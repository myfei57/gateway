// Copyright Envoy Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package runner

import (
	"context"
	"crypto/tls"
	"fmt"
	"math/rand"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/service/cluster/v3"
	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	endpointv3 "github.com/envoyproxy/go-control-plane/envoy/service/endpoint/v3"
	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/service/listener/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/service/route/v3"
	runtimev3 "github.com/envoyproxy/go-control-plane/envoy/service/runtime/v3"
	secretv3 "github.com/envoyproxy/go-control-plane/envoy/service/secret/v3"
	serverv3 "github.com/envoyproxy/go-control-plane/pkg/server/v3"
	"github.com/telepresenceio/watchable"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	ktypes "k8s.io/apimachinery/pkg/types"

	egv1a1 "github.com/envoyproxy/gateway/api/v1alpha1"
	"github.com/envoyproxy/gateway/internal/crypto"
	"github.com/envoyproxy/gateway/internal/envoygateway/config"
	extension "github.com/envoyproxy/gateway/internal/extension/types"
	"github.com/envoyproxy/gateway/internal/infrastructure/host"
	"github.com/envoyproxy/gateway/internal/infrastructure/kubernetes/ratelimit"
	"github.com/envoyproxy/gateway/internal/ir"
	"github.com/envoyproxy/gateway/internal/logging"
	"github.com/envoyproxy/gateway/internal/message"
	"github.com/envoyproxy/gateway/internal/xds/bootstrap"
	xdsbudget "github.com/envoyproxy/gateway/internal/xds/budget"
	"github.com/envoyproxy/gateway/internal/xds/cache"
	"github.com/envoyproxy/gateway/internal/xds/server/kubejwt"
	"github.com/envoyproxy/gateway/internal/xds/translator"
	xtypes "github.com/envoyproxy/gateway/internal/xds/types"
)

const (
	// XdsServerAddress is the listening address of the xds-server.
	XdsServerAddress = "0.0.0.0"

	// Default certificates path for envoy-gateway with Kubernetes provider.
	// xdsTLSCertFilepath is the fully qualified path of the file containing the
	// xDS server TLS certificate.
	xdsTLSCertFilepath = "/certs/tls.crt"
	// xdsTLSKeyFilepath is the fully qualified path of the file containing the
	// xDS server TLS key.
	xdsTLSKeyFilepath = "/certs/tls.key"
	// xdsTLSCaFilepath is the fully qualified path of the file containing the
	// xDS server trusted CA certificate.
	xdsTLSCaFilepath = "/certs/ca.crt"

	// defaultKubernetesIssuer is the default issuer URL for Kubernetes.
	// This is used for validating Service Account JWT tokens.
	defaultKubernetesIssuer = "https://kubernetes.default.svc.cluster.local"

	defaultMaxConnectionAgeGrace = 2 * time.Minute
)

var tracer = otel.Tracer("envoy-gateway/xds")

var maxConnectionAgeValues = []time.Duration{
	10 * time.Hour,
	11 * time.Hour,
	12 * time.Hour,
}

type Config struct {
	config.Server
	grpc              *grpc.Server
	cache             cache.SnapshotCacheWithCallbacks
	XdsIR             *message.XdsIR
	ExtensionManager  extension.Manager
	ProviderResources *message.ProviderResources
	RunnerErrors      *message.RunnerErrors
	// Test-configurable TLS paths
	TLSCertPath string
	TLSKeyPath  string
	TLSCaPath   string
}

type Runner struct {
	Config

	// done tracks goroutines started by Start so that Close can block until
	// they have all exited, ensuring shared state they write to is not
	// closed out from under them during shutdown.
	done sync.WaitGroup

	// resourceBudget optionally gates candidate snapshots before they reach the
	// cache. Nil disables the gate and preserves the original publish path. The
	// pointer is captured once at Start; every later candidate is re-evaluated
	// against it, so a configuration change takes effect with the next candidate.
	resourceBudget *egv1a1.XdsResourceBudget

	// budgetState tracks the candidate generation identity per IR key. It is
	// only touched by the single subscription goroutine in translateFromSubscription.
	budgetState map[string]*budgetKeyState
}

// budgetKeyState distinguishes candidate generations from the last generation
// that was actually published for one IR key.
type budgetKeyState struct {
	// generation increments for every evaluated candidate, including rejects.
	generation int64
	// lastGood is the generation of the snapshot currently held by the cache.
	// Zero means no compliant snapshot has been published for the key yet.
	lastGood int64
}

// nextGeneration returns the identity of the candidate currently being gated.
func (s *budgetKeyState) nextGeneration() int64 {
	s.generation++
	return s.generation
}

func New(cfg *Config) *Runner {
	return &Runner{Config: *cfg}
}

// proxyInfraNameAndNamespace returns the ProxyInfra name and namespace for the xDS IR with the
// given key.
func proxyInfraNameAndNamespace(irKey, controllerNamespace string, gatewayNamespaceMode bool) (string, string) {
	if gatewayNamespaceMode {
		if namespace, name, ok := strings.Cut(irKey, "/"); ok {
			return name, namespace
		}
	}
	return irKey, controllerNamespace
}

func (r *Runner) Name() string {
	return string(egv1a1.LogComponentXdsRunner)
}

func (r *Runner) serverKeepaliveParams() (keepalive.ServerParameters, error) {
	params := keepalive.ServerParameters{
		MaxConnectionAge:      getRandomMaxConnectionAge(),
		MaxConnectionAgeGrace: defaultMaxConnectionAgeGrace,
	}

	if r.EnvoyGateway == nil || r.EnvoyGateway.XDSServer == nil {
		return params, nil
	}

	cfg := r.EnvoyGateway.XDSServer

	if cfg.MaxConnectionAge != nil {
		d, err := time.ParseDuration(string(*cfg.MaxConnectionAge))
		if err != nil {
			return keepalive.ServerParameters{}, fmt.Errorf("invalid xdsServer.maxConnectionAge: %w", err)
		}
		if d <= 0 {
			return keepalive.ServerParameters{}, fmt.Errorf("xdsServer.maxConnectionAge must be greater than zero")
		}
		params.MaxConnectionAge = d
	}

	if cfg.MaxConnectionAgeGrace != nil {
		d, err := time.ParseDuration(string(*cfg.MaxConnectionAgeGrace))
		if err != nil {
			return keepalive.ServerParameters{}, fmt.Errorf("invalid xdsServer.maxConnectionAgeGrace: %w", err)
		}
		if d <= 0 {
			return keepalive.ServerParameters{}, fmt.Errorf("xdsServer.maxConnectionAgeGrace must be greater than zero")
		}
		params.MaxConnectionAgeGrace = d
	}

	return params, nil
}

// getRandomMaxConnectionAge picks a random maxConnectionAge value
// to spread out envoy proxy connections over multiple envoy gateway replicas
func getRandomMaxConnectionAge() time.Duration {
	rnd := rand.New(rand.NewSource(time.Now().UnixNano())) //nolint:gosec
	return maxConnectionAgeValues[rnd.Intn(len(maxConnectionAgeValues))]
}

// Close implements Runner interface.
func (r *Runner) Close() error {
	r.done.Wait()
	return nil
}

// Start starts the xds-server runner
func (r *Runner) Start(ctx context.Context) error {
	r.Logger = r.Logger.WithName(r.Name()).WithValues("runner", r.Name())
	r.cache = cache.NewSnapshotCache(true, r.Logger)

	// Capture the optional resource budget once. A nil budget keeps the original
	// unconditional publish path; when set, every later candidate is metered and
	// only fully compliant tables reach the snapshot cache.
	r.budgetState = make(map[string]*budgetKeyState)
	if r.EnvoyGateway != nil && r.EnvoyGateway.XDSServer != nil {
		r.resourceBudget = r.EnvoyGateway.XDSServer.ResourceBudget
	}

	// Set up the gRPC server and register the xDS handler.
	// Create SnapshotCache before start subscribeAndTranslate,
	// prevent panics in case cache is nil.
	tlsConfig, err := r.loadTLSConfig()
	if err != nil {
		return fmt.Errorf("failed to load TLS config: %w", err)
	}
	r.Logger.Info("loaded TLS certificate and key")

	keepaliveParams, err := r.serverKeepaliveParams()
	if err != nil {
		return err
	}
	r.Logger.Info("configured gRPC keepalive", "maxConnectionAge", keepaliveParams.MaxConnectionAge, "maxConnectionAgeGrace", keepaliveParams.MaxConnectionAgeGrace)

	enforcementPolicy := keepalive.EnforcementPolicy{
		MinTime:             15 * time.Second,
		PermitWithoutStream: true,
	}

	// Default to 32MiB
	maxReceiveMessageSize := int64(32 * 1024 * 1024)
	if r.EnvoyGateway.XDSServer != nil && r.EnvoyGateway.XDSServer.MaxReceiveMessageSize != nil {
		maxReceiveMessageSize, _ = r.EnvoyGateway.XDSServer.MaxReceiveMessageSize.AsInt64()
	}
	baseKeepaliveOptions := []grpc.ServerOption{
		grpc.KeepaliveEnforcementPolicy(enforcementPolicy),
		grpc.KeepaliveParams(keepaliveParams),
		grpc.MaxRecvMsgSize(int(maxReceiveMessageSize)),
	}
	r.Logger.Info("configured gRPC max receive message size", "maxReceiveMessageSize", maxReceiveMessageSize)

	grpcOpts := append([]grpc.ServerOption{}, baseKeepaliveOptions...)
	grpcOpts = append(grpcOpts, grpc.Creds(credentials.NewTLS(tlsConfig)))

	// When GatewayNamespaceMode is enabled, we will use sTLS and Service Account JWT tokens to authenticate envoy proxy infra and xds server.
	if r.EnvoyGateway.GatewayNamespaceMode() {
		r.Logger.Info("gatewayNamespaceMode is enabled, setting up JWTAuthInterceptor and sTLS server")
		clientset, err := kubejwt.GetKubernetesClient()
		if err != nil {
			return fmt.Errorf("failed to create Kubernetes client: %w", err)
		}
		saAudience := fmt.Sprintf("%s.%s.svc.%s", config.EnvoyGatewayServiceName, r.ControllerNamespace, r.DNSDomain)
		jwtInterceptor := kubejwt.NewJWTAuthInterceptor(
			r.Logger,
			clientset,
			defaultKubernetesIssuer,
			saAudience,
		)

		// Re-read the cert from disk on every handshake, mirroring the default mode above.
		serverTLSConfig, err := r.loadServerTLSConfig()
		if err != nil {
			return fmt.Errorf("failed to load server TLS config: %w", err)
		}

		grpcOpts = append([]grpc.ServerOption{}, baseKeepaliveOptions...)
		grpcOpts = append(grpcOpts,
			grpc.Creds(credentials.NewTLS(serverTLSConfig)),
			grpc.StreamInterceptor(jwtInterceptor.Stream()),
			grpc.UnaryInterceptor(jwtInterceptor.Unary()),
		)
	}

	r.grpc = grpc.NewServer(grpcOpts...)
	registerServer(serverv3.NewServer(ctx, r.cache, r.cache), r.grpc)

	// Start and listen xDS gRPC Server.
	r.done.Go(func() {
		r.serveXdsServer(ctx)
	})

	// Do not call .Subscribe() inside Goroutine since it is supposed to be called from the same
	// Goroutine where Close() is called.
	sub := r.XdsIR.Subscribe(ctx)
	r.done.Go(func() {
		r.translateFromSubscription(sub)
	})
	r.Logger.Info("started")
	return err
}

func (r *Runner) serveXdsServer(ctx context.Context) {
	addr := net.JoinHostPort(XdsServerAddress, strconv.Itoa(bootstrap.DefaultXdsServerPort))
	l, err := net.Listen("tcp", addr)
	if err != nil {
		r.Logger.Error(err, "failed to listen on address", "address", addr)
		return
	}

	go func() {
		<-ctx.Done()
		r.Logger.Info("grpc server shutting down")
		// We don't use GracefulStop here because envoy
		// has long-lived hanging xDS requests. There's no
		// mechanism to make those pending requests fail,
		// so we forcibly terminate the TCP sessions.
		r.grpc.Stop()
	}()

	if err = r.grpc.Serve(l); err != nil {
		r.Logger.Error(err, "failed to start grpc based xds server")
	}
}

// registerServer registers the given xDS protocol Server with the gRPC
// runtime.
func registerServer(srv serverv3.Server, g *grpc.Server) {
	// register services
	discoveryv3.RegisterAggregatedDiscoveryServiceServer(g, srv)
	secretv3.RegisterSecretDiscoveryServiceServer(g, srv)
	clusterv3.RegisterClusterDiscoveryServiceServer(g, srv)
	endpointv3.RegisterEndpointDiscoveryServiceServer(g, srv)
	listenerv3.RegisterListenerDiscoveryServiceServer(g, srv)
	routev3.RegisterRouteDiscoveryServiceServer(g, srv)
	runtimev3.RegisterRuntimeDiscoveryServiceServer(g, srv)
}

func (r *Runner) translateFromSubscription(sub <-chan watchable.Snapshot[string, *message.XdsIRWithContext]) {
	// Subscribe to resources
	message.HandleSubscription(
		r.Logger,
		message.Metadata{Runner: r.Name(), Message: message.XDSIRMessageName}, sub,
		func(update message.Update[string, *message.XdsIRWithContext], errChan chan error) {
			message.PublishRunnerEventMetric(r.Name(), update.Delete)

			parentCtx := update.Value.ParentContext(context.Background())
			var startOpts []trace.SpanStartOption
			if !update.Delete && !update.Initial {
				parentCtx, startOpts = message.RecordQueueWait(parentCtx, tracer, r.Name(), update.Value.StoredAtTime())
			}

			traceCtx, span := tracer.Start(parentCtx, "XdsRunner.subscribeAndTranslate", startOpts...)
			defer span.End()
			traceLogger := r.Logger.WithTrace(traceCtx)
			traceLogger.Info("received an update")

			key := update.Key
			val := update.Value

			// Add span attributes for observability
			span.SetAttributes(
				attribute.String("xds-ir.key", update.Key),
				attribute.Bool("update.delete", update.Delete),
			)

			if update.Delete {
				// Drop the generation tracking and rejection report so a later
				// re-created key starts from generation one again.
				r.deleteBudgetState(key)
				if err := r.cache.GenerateNewSnapshot(key, nil, traceCtx); err != nil {
					traceLogger.Error(err, "failed to delete the snapshot")
					errChan <- err
				}
			} else {
				// Translate to xds resources
				proxyInfraName, proxyInfraNamespace := proxyInfraNameAndNamespace(key, r.ControllerNamespace, r.EnvoyGateway.GatewayNamespaceMode())
				t := &translator.Translator{
					ControllerNamespace: r.ControllerNamespace,
					ProxyInfraName:      proxyInfraName,
					ProxyInfraNamespace: proxyInfraNamespace,
					FilterOrder:         val.XdsIR.FilterOrder,
					RuntimeFlags:        r.EnvoyGateway.RuntimeFlags,
					Logger:              traceLogger,
				}

				// Set the extension manager if an extension is loaded
				if r.ExtensionManager != nil {
					t.ExtensionManager = &r.ExtensionManager
				}

				// Set the rate limit service URL if global rate limiting is enabled.
				if r.EnvoyGateway.RateLimit != nil {
					t.GlobalRateLimit = &translator.GlobalRateLimitSettings{
						ServiceURL: ratelimit.GetServiceURL(r.ControllerNamespace, r.DNSDomain),
						FailClosed: r.EnvoyGateway.RateLimit.FailClosed,
					}
					if r.EnvoyGateway.RateLimit.Timeout != nil {
						d, err := time.ParseDuration(string(*r.EnvoyGateway.RateLimit.Timeout))
						if err != nil {
							traceLogger.Error(err, "invalid rateLimit timeout")
							errChan <- err
						} else {
							t.GlobalRateLimit.Timeout = d
						}
					}
				}

				// The span is ended by a deferred call inside the closure: the translator
				// panics on some inputs and HandleSubscription recovers from it, and an
				// unended span is never exported, so a plain End() here would drop the
				// stage span and the input sizes recorded on it.
				result, err := func() (*xtypes.ResourceVersionTable, error) {
					translateCtx, translateSpan := tracer.Start(traceCtx, "Translator.Translate")
					defer translateSpan.End()
					return t.Translate(translateCtx, val.XdsIR)
				}()
				if err != nil {
					traceLogger.Error(err, "skipped publishing xds resources: failed to translate xds ir")
					errChan <- err
				}

				// xDS translation is done in a best-effort manner, so the result
				// may contain partial resources even if there are errors.
				if result == nil {
					traceLogger.Info("no xds resources to publish")
					return
				}

				// Only update the snapshot cache when there are no system-level errors, to avoid publishing partial resources.
				// This allows Envoy to continue using the previous known-good snapshot until the next successful translation.
				// Note: invalid EnvoyPatchPolicies are considered user-level errors and will not prevent the snapshot from being updated.
				if err == nil {
					if result.XdsResources != nil {
						if r.cache == nil {
							r.Logger.Error(err, "failed to init snapshot cache")
							errChan <- err
						} else if !r.applyResourceBudget(key, val.XdsIR, result, traceLogger) {
							// The candidate exceeded the resource budget. The cache is
							// intentionally left untouched, so Envoy keeps serving the
							// last good snapshot. This is a stable rejection rather than
							// a retryable error: nothing is written to errChan and no
							// message is re-stored, so the runner does not reconcile in a loop.
							traceLogger.Info("skipped publishing xds resources: resource budget exceeded, retaining the last good snapshot",
								"key", key)
						} else {
							// Update snapshot cache
							if err := r.cache.GenerateNewSnapshot(key, result.XdsResources, traceCtx); err != nil {
								r.Logger.Error(err, "failed to generate a snapshot")
								errChan <- err
							}
						}
					} else {
						r.Logger.Error(err, "skipped publishing xds resources")
					}
				}

				// Get all status keys from watchable and save them in the map statusesToDelete.
				// Iterating through result.EnvoyPatchPolicyStatuses, any valid keys will be removed from statusesToDelete.
				// Remaining keys will be deleted from watchable before we exit this function.
				statusesToDelete := make(map[ktypes.NamespacedName]bool)
				for key := range r.ProviderResources.EnvoyPatchPolicyStatuses.LoadAll() {
					statusesToDelete[key] = true
				}

				// Publish EnvoyPatchPolicyStatus
				for _, e := range result.EnvoyPatchPolicyStatuses {
					key := ktypes.NamespacedName{
						Name:      e.Name,
						Namespace: e.Namespace,
					}
					// Skip updating status for policies with empty status
					// They may have been skipped in this translation because
					// their target is not found (not relevant)
					if len(e.Status.Ancestors) > 0 {
						r.ProviderResources.EnvoyPatchPolicyStatuses.Store(key, e.Status)
					}
					delete(statusesToDelete, key)
				}
				// Discard the EnvoyPatchPolicyStatuses to reduce memory footprint
				result.EnvoyPatchPolicyStatuses = nil

				// Delete all the deletable status keys
				for key := range statusesToDelete {
					r.ProviderResources.EnvoyPatchPolicyStatuses.Delete(key)
				}
			}
		},
	)
	r.Logger.Info("subscriber shutting down")
}

// applyResourceBudget meters the final, fully-built candidate table (including
// resources appended by extension hooks) and reports whether it may be
// published. When the budget is disabled it always returns true. On rejection
// the evaluation report is published into ProviderResources with the
// candidate generation and Published=false, while the cache is left serving
// the previous last good snapshot.
func (r *Runner) applyResourceBudget(
	key string,
	xdsIR *ir.Xds,
	table *xtypes.ResourceVersionTable,
	logger logging.Logger,
) bool {
	if r.resourceBudget == nil {
		return true
	}

	state, ok := r.budgetState[key]
	if !ok {
		state = &budgetKeyState{}
		r.budgetState[key] = state
	}
	generation := state.nextGeneration()

	// Meter the final table right before the cache boundary, after every
	// translator phase and extension hook, so no incrementally added resource
	// can bypass the gate.
	usage, meterErr := xdsbudget.Meter(table.XdsResources)
	report := xdsbudget.Evaluate(
		r.resourceBudget,
		key,
		generation,
		state.lastGood,
		usage,
		xdsbudget.CollectSources(xdsIR),
		meterErr,
	)
	xdsbudget.RecordEvaluation(report.Published)

	if report.Published {
		state.lastGood = generation
		// The published candidate is itself the new last good snapshot.
		report.LastGoodGeneration = generation
		// Keep the successful evaluation visible so consumers can correlate the
		// published generation with the last good snapshot. Only IR deletion
		// removes the entry (see deleteBudgetState).
		r.ProviderResources.XdsBudgetStatuses.Store(key, report)
		return true
	}

	for _, violation := range report.Violations {
		xdsbudget.RecordViolation(violation)
	}
	logger.Info("resource budget rejected candidate snapshot",
		"key", key,
		"generation", generation,
		"lastGoodGeneration", state.lastGood,
		"violations", len(report.Violations),
	)
	r.ProviderResources.XdsBudgetStatuses.Store(key, report)
	return false
}

// deleteBudgetState resets the generation tracking and rejection report for an
// IR key, used when the key's IR is deleted.
func (r *Runner) deleteBudgetState(key string) {
	delete(r.budgetState, key)
	if r.ProviderResources != nil {
		r.ProviderResources.XdsBudgetStatuses.Delete(key)
	}
}

func (r *Runner) loadTLSConfig() (*tls.Config, error) {
	var certPath, keyPath, caPath string

	// Use test-configurable paths if provided
	if r.TLSCertPath != "" && r.TLSKeyPath != "" && r.TLSCaPath != "" {
		certPath = r.TLSCertPath
		keyPath = r.TLSKeyPath
		caPath = r.TLSCaPath
	} else {
		// Use default paths based on provider type
		switch {
		case r.EnvoyGateway.Provider.IsRunningOnKubernetes():
			certPath = xdsTLSCertFilepath
			keyPath = xdsTLSKeyFilepath
			caPath = xdsTLSCaFilepath
		case r.EnvoyGateway.Provider.IsRunningOnHost():
			// Get config
			var hostCfg *egv1a1.EnvoyGatewayHostInfrastructureProvider
			if p := r.EnvoyGateway.Provider; p != nil && p.Custom != nil &&
				p.Custom.Infrastructure != nil && p.Custom.Infrastructure.Host != nil {
				hostCfg = p.Custom.Infrastructure.Host
			}

			paths, err := host.GetPaths(hostCfg)
			if err != nil {
				return nil, fmt.Errorf("failed to determine paths: %w", err)
			}

			certDir := paths.CertDir("envoy-gateway")
			certPath = filepath.Join(certDir, "tls.crt")
			keyPath = filepath.Join(certDir, "tls.key")
			caPath = filepath.Join(certDir, "ca.crt")
		default:
			return nil, fmt.Errorf("no valid tls certificates")
		}
	}

	tlsConfig, err := crypto.LoadTLSConfig(certPath, keyPath, caPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create tls config: %w", err)
	}
	return tlsConfig, err
}

// loadServerTLSConfig returns a server-only TLS config used by the
// GatewayNamespaceMode xDS server, where peers are authenticated via JWT.
func (r *Runner) loadServerTLSConfig() (*tls.Config, error) {
	certPath := xdsTLSCertFilepath
	keyPath := xdsTLSKeyFilepath

	if r.TLSCertPath != "" && r.TLSKeyPath != "" {
		certPath = r.TLSCertPath
		keyPath = r.TLSKeyPath
	}

	tlsConfig, err := crypto.LoadServerTLSConfig(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create server tls config: %w", err)
	}
	return tlsConfig, nil
}
