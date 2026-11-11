// Copyright Envoy Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package budget

import (
	"encoding/json"
	"math"
	"testing"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	endpointv3 "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	hcmv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	cachetypes "github.com/envoyproxy/go-control-plane/pkg/cache/types"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"github.com/envoyproxy/go-control-plane/pkg/wellknown"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protowire"
	protobuf "google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	egv1a1 "github.com/envoyproxy/gateway/api/v1alpha1"
	"github.com/envoyproxy/gateway/internal/ir"
	xtypes "github.com/envoyproxy/gateway/internal/xds/types"
)

func p(v int64) *int64 { return &v }

func marshalAny(t *testing.T, msg protobuf.Message) *anypb.Any {
	t.Helper()
	any, err := anypb.New(msg)
	require.NoError(t, err)
	return any
}

// buildEdgeTable builds a deterministic snapshot exercising every edge kind:
// Listener -> RouteConfiguration, Listener -> Secret, RouteConfiguration ->
// Cluster (simple and weighted), EDS Cluster -> ClusterLoadAssignment and
// Cluster -> Secret. It also includes dangling references that must not count.
func buildEdgeTable(t *testing.T) xtypes.XdsResources {
	t.Helper()

	hcm := marshalAny(t, &hcmv3.HttpConnectionManager{
		RouteSpecifier: &hcmv3.HttpConnectionManager_Rds{
			Rds: &hcmv3.Rds{RouteConfigName: "rc"},
		},
	})
	downstreamTLS := marshalAny(t, &tlsv3.DownstreamTlsContext{
		CommonTlsContext: &tlsv3.CommonTlsContext{
			TlsCertificateSdsSecretConfigs: []*tlsv3.SdsSecretConfig{{Name: "listener-secret"}},
		},
	})
	listener := &listenerv3.Listener{
		Name: "l",
		FilterChains: []*listenerv3.FilterChain{{
			Filters: []*listenerv3.Filter{{
				Name:       wellknown.HTTPConnectionManager,
				ConfigType: &listenerv3.Filter_TypedConfig{TypedConfig: hcm},
			}},
			TransportSocket: coreTransportSocket(downstreamTLS),
		}},
	}
	// A second RDS name and route action pointing at absent resources: dangling
	// references must not produce edges.
	danglingHCM := marshalAny(t, &hcmv3.HttpConnectionManager{
		RouteSpecifier: &hcmv3.HttpConnectionManager_Rds{
			Rds: &hcmv3.Rds{RouteConfigName: "missing-rc"},
		},
	})
	danglingListener := &listenerv3.Listener{
		Name: "l-dangling",
		FilterChains: []*listenerv3.FilterChain{{
			Filters: []*listenerv3.Filter{{
				Name:       wellknown.HTTPConnectionManager,
				ConfigType: &listenerv3.Filter_TypedConfig{TypedConfig: danglingHCM},
			}},
		}},
	}

	rc := &routev3.RouteConfiguration{
		Name: "rc",
		VirtualHosts: []*routev3.VirtualHost{{
			Name: "vhost",
			Routes: []*routev3.Route{
				{
					Name: "simple",
					Action: &routev3.Route_Route{Route: &routev3.RouteAction{
						ClusterSpecifier: &routev3.RouteAction_Cluster{Cluster: "c-static"},
					}},
				},
				{
					Name: "weighted",
					Action: &routev3.Route_Route{Route: &routev3.RouteAction{
						// c-static repeats across routes: the edge must be counted once.
						ClusterSpecifier: &routev3.RouteAction_WeightedClusters{WeightedClusters: &routev3.WeightedCluster{
							Clusters: []*routev3.WeightedCluster_ClusterWeight{
								{Name: "c-static", Weight: gogoUint32(70)},
								{Name: "c-eds", Weight: gogoUint32(30)},
								{Name: "missing-cluster", Weight: gogoUint32(1)},
							},
						}},
					}},
				},
			},
		}},
	}

	upstreamTLS := marshalAny(t, &tlsv3.UpstreamTlsContext{
		CommonTlsContext: &tlsv3.CommonTlsContext{
			TlsCertificateSdsSecretConfigs: []*tlsv3.SdsSecretConfig{{Name: "cluster-secret"}},
		},
	})
	staticCluster := &clusterv3.Cluster{
		Name:                 "c-static",
		ClusterDiscoveryType: &clusterv3.Cluster_Type{Type: clusterv3.Cluster_STATIC},
		TransportSocket:      coreTransportSocket(upstreamTLS),
	}
	edsCluster := &clusterv3.Cluster{
		Name:                 "c-eds",
		ClusterDiscoveryType: &clusterv3.Cluster_Type{Type: clusterv3.Cluster_EDS},
		EdsClusterConfig:     &clusterv3.Cluster_EdsClusterConfig{},
	}
	endpoint := &endpointv3.ClusterLoadAssignment{ClusterName: "c-eds"}

	secret := &tlsv3.Secret{Name: "listener-secret"}
	clusterSecret := &tlsv3.Secret{Name: "cluster-secret"}

	return xtypes.XdsResources{
		resourcev3.ListenerType: {listener, danglingListener},
		resourcev3.RouteType:    {rc},
		resourcev3.ClusterType:  {staticCluster, edsCluster},
		resourcev3.EndpointType: {endpoint},
		resourcev3.SecretType:   {secret, clusterSecret},
	}
}

func TestMeterReferenceEdges(t *testing.T) {
	usage, err := Meter(buildEdgeTable(t))
	require.NoError(t, err)

	// l->rc, l->listener-secret, rc->c-static (deduped across two routes),
	// rc->c-eds, c-eds->endpoint, c-static->cluster-secret.
	require.Equal(t, int64(6), usage.ReferenceEdges)
	// 2 listeners + 1 route config + 2 clusters + 1 endpoint + 2 secrets.
	require.Equal(t, int64(8), usage.TotalResources)
}

func TestMeterDeduplicatesSharedResources(t *testing.T) {
	cluster := &clusterv3.Cluster{
		Name:                 "shared-cluster",
		ClusterDiscoveryType: &clusterv3.Cluster_Type{Type: clusterv3.Cluster_STATIC},
	}
	secret := &tlsv3.Secret{Name: "shared-secret"}
	resources := xtypes.XdsResources{
		// The same cluster is emitted for every route that targets it, but the
		// budget must meter it once.
		resourcev3.ClusterType: {cluster, cluster, cluster},
		resourcev3.SecretType:  {secret, secret},
	}

	usage, err := Meter(resources)
	require.NoError(t, err)

	clusterUsage := usage.ByType[resourcev3.ClusterType]
	require.Equal(t, int64(1), clusterUsage.Resources)
	require.Equal(t, int64(2), clusterUsage.DuplicateResources)

	clusterBytes := int64(len(mustMarshal(t, cluster)))
	require.Equal(t, clusterBytes, clusterUsage.SerializedBytes)
	require.Equal(t, clusterBytes, clusterUsage.MaxResourceBytes)
	require.Equal(t, "shared-cluster", clusterUsage.LargestResource)

	secretUsage := usage.ByType[resourcev3.SecretType]
	require.Equal(t, int64(1), secretUsage.Resources)
	require.Equal(t, int64(1), secretUsage.DuplicateResources)
	// Secret names must not surface even in the metered usage summary.
	require.Equal(t, redactedResourceName, secretUsage.LargestResource)

	require.Equal(t, int64(2), usage.TotalResources)
	require.Equal(t, clusterBytes+int64(len(mustMarshal(t, secret))), usage.TotalSerializedBytes)
}

func TestMeterCountsUnknownBytesAndOrderedFields(t *testing.T) {
	cluster := &clusterv3.Cluster{
		Name:                 "unknown-bytes-cluster",
		ClusterDiscoveryType: &clusterv3.Cluster_Type{Type: clusterv3.Cluster_STATIC},
	}
	original := mustMarshal(t, cluster)

	// Append an unknown field (field number 1000, wire type 2) carrying payload.
	unknownPayload := []byte("unknown-payload-ordered-bytes")
	withUnknown := protowire.AppendTag(original, 1000, protowire.BytesType)
	withUnknown = protowire.AppendBytes(withUnknown, unknownPayload)
	require.NotEqual(t, len(original), len(withUnknown))

	// Re-decode: protobuf preserves the unknown bytes, so metering the final
	// in-memory resource still accounts for them.
	roundTripped := &clusterv3.Cluster{}
	require.NoError(t, protobuf.Unmarshal(withUnknown, roundTripped))

	usage, err := Meter(xtypes.XdsResources{resourcev3.ClusterType: {roundTripped}})
	require.NoError(t, err)
	tu := usage.ByType[resourcev3.ClusterType]
	require.Equal(t, int64(len(withUnknown)), tu.SerializedBytes)
	require.Equal(t, int64(len(withUnknown)), tu.MaxResourceBytes)

	// Ordered repeated fields contribute in order: serialized bytes are exactly
	// the sum of the per-resource wire sizes, nothing is estimated.
	second := &clusterv3.Cluster{
		Name:                 "second-cluster",
		ClusterDiscoveryType: &clusterv3.Cluster_Type{Type: clusterv3.Cluster_STATIC},
	}
	usage, err = Meter(xtypes.XdsResources{resourcev3.ClusterType: {roundTripped, second}})
	require.NoError(t, err)
	expected := int64(len(withUnknown)) + int64(len(mustMarshal(t, second)))
	require.Equal(t, expected, usage.ByType[resourcev3.ClusterType].SerializedBytes)
}

func TestMeterHugeRouteExpansion(t *testing.T) {
	// One Kubernetes HTTPRoute with many hostnames x matches expands into many
	// virtual hosts and routes inside a single RouteConfiguration. The budget is
	// based on this final protobuf size, not on object counts.
	const expandedRoutes = 500
	routes := make([]*routev3.Route, 0, expandedRoutes)
	for i := 0; i < expandedRoutes; i++ {
		routes = append(routes, &routev3.Route{
			Name: "expanded-route",
			Action: &routev3.Route_Route{Route: &routev3.RouteAction{
				ClusterSpecifier: &routev3.RouteAction_Cluster{Cluster: "c"},
			}},
		})
	}
	rc := &routev3.RouteConfiguration{
		Name:         "huge-rc",
		VirtualHosts: []*routev3.VirtualHost{{Name: "vhost", Routes: routes}},
	}
	cluster := &clusterv3.Cluster{
		Name:                 "c",
		ClusterDiscoveryType: &clusterv3.Cluster_Type{Type: clusterv3.Cluster_STATIC},
	}

	usage, err := Meter(xtypes.XdsResources{
		resourcev3.RouteType:   {rc},
		resourcev3.ClusterType: {cluster},
	})
	require.NoError(t, err)

	routeUsage := usage.ByType[resourcev3.RouteType]
	rawSize := int64(len(mustMarshal(t, rc)))
	require.Equal(t, rawSize, routeUsage.SerializedBytes)
	require.Greater(t, routeUsage.SerializedBytes, int64(expandedRoutes*10))

	loose := &egv1a1.XdsResourceBudget{PerTypeURL: []egv1a1.XdsResourceTypeBudget{{
		TypeURL:            resourcev3.RouteType,
		MaxSerializedBytes: p(rawSize + 1),
	}}}
	tight := &egv1a1.XdsResourceBudget{PerTypeURL: []egv1a1.XdsResourceTypeBudget{{
		TypeURL:            resourcev3.RouteType,
		MaxSerializedBytes: p(rawSize - 1),
	}}}

	looseReport := Evaluate(loose, "key", 1, 0, usage, Sources{}, nil)
	require.True(t, looseReport.Published)
	tightReport := Evaluate(tight, "key", 2, 1, usage, Sources{}, nil)
	require.False(t, tightReport.Published)
	require.Equal(t, int64(2), tightReport.Generation)
	require.Equal(t, int64(1), tightReport.LastGoodGeneration)
	require.Len(t, tightReport.Violations, 1)
	require.Equal(t, ViolationSerializedBytes, tightReport.Violations[0].Kind)
	require.Equal(t, rawSize, tightReport.Violations[0].Observed)
}

func TestEvaluateResourceAndSingleResourceLimits(t *testing.T) {
	clusters := []cachetypes.Resource{
		&clusterv3.Cluster{Name: "c1", ClusterDiscoveryType: &clusterv3.Cluster_Type{Type: clusterv3.Cluster_STATIC}},
		&clusterv3.Cluster{Name: "c2", ClusterDiscoveryType: &clusterv3.Cluster_Type{Type: clusterv3.Cluster_STATIC}},
	}
	usage, err := Meter(xtypes.XdsResources{resourcev3.ClusterType: clusters})
	require.NoError(t, err)

	t.Run("resource count limit", func(t *testing.T) {
		budget := &egv1a1.XdsResourceBudget{PerTypeURL: []egv1a1.XdsResourceTypeBudget{{
			TypeURL:      resourcev3.ClusterType,
			MaxResources: p(1),
		}}}
		report := Evaluate(budget, "key", 1, 0, usage, Sources{}, nil)
		require.False(t, report.Published)
		require.Len(t, report.Violations, 1)
		require.Equal(t, ViolationResources, report.Violations[0].Kind)
		require.Equal(t, int64(2), report.Violations[0].Observed)
	})

	t.Run("single resource byte limit names the offender", func(t *testing.T) {
		budget := &egv1a1.XdsResourceBudget{PerTypeURL: []egv1a1.XdsResourceTypeBudget{{
			TypeURL:          resourcev3.ClusterType,
			MaxResourceBytes: p(1),
		}}}
		report := Evaluate(budget, "key", 1, 0, usage, Sources{}, nil)
		require.False(t, report.Published)
		var found bool
		for _, v := range report.Violations {
			if v.Kind == ViolationResourceBytes {
				found = true
				require.NotEmpty(t, v.OffendingResources)
			}
		}
		require.True(t, found)
	})

	t.Run("missing type URL entry means unbounded", func(t *testing.T) {
		budget := &egv1a1.XdsResourceBudget{PerTypeURL: []egv1a1.XdsResourceTypeBudget{{
			TypeURL:      resourcev3.RouteType,
			MaxResources: p(0),
		}}}
		// Zero is rejected at API validation, but Evaluate only enforces set bounds:
		// route type is absent from usage, so no violation; clusters are unbounded.
		report := Evaluate(budget, "key", 1, 0, usage, Sources{}, nil)
		require.True(t, report.Published)
	})
}

func TestEvaluateReferenceEdgeLimit(t *testing.T) {
	usage, err := Meter(buildEdgeTable(t))
	require.NoError(t, err)

	reject := Evaluate(&egv1a1.XdsResourceBudget{MaxReferenceEdges: p(5)}, "key", 1, 0, usage, Sources{}, nil)
	require.False(t, reject.Published)
	require.Equal(t, ViolationReferenceEdges, reject.Violations[0].Kind)
	require.Equal(t, int64(6), reject.Violations[0].Observed)

	accept := Evaluate(&egv1a1.XdsResourceBudget{MaxReferenceEdges: p(6)}, "key", 1, 0, usage, Sources{}, nil)
	require.True(t, accept.Published)
}

func TestEvaluateExtensionResourcesAreMetered(t *testing.T) {
	// Simulate a post-translation extension hook appending a resource of a type
	// the translator itself never emits: the final-table gate must still meter it.
	extensionResource := coreTypedExtensionConfig(t, "ext-added")
	table := xtypes.XdsResources{
		resourcev3.ExtensionConfigType: {extensionResource, extensionResource},
	}

	usage, err := Meter(table)
	require.NoError(t, err)
	extUsage := usage.ByType[resourcev3.ExtensionConfigType]
	require.NotNil(t, extUsage)
	require.Equal(t, int64(1), extUsage.Resources)
	require.Equal(t, int64(1), extUsage.DuplicateResources)
	require.Greater(t, extUsage.SerializedBytes, int64(0))

	budget := &egv1a1.XdsResourceBudget{PerTypeURL: []egv1a1.XdsResourceTypeBudget{{
		TypeURL:      resourcev3.ExtensionConfigType,
		MaxResources: p(0),
	}}}
	report := Evaluate(budget, "key", 1, 0, usage, Sources{}, nil)
	require.False(t, report.Published)
}

func TestEvaluateSecretReportNeverLeaksSecretContent(t *testing.T) {
	const secretName = "top-secret-cert"
	const secretPayload = "super-secret-certificate-bytes"
	secret := &tlsv3.Secret{
		Name: secretName,
		Type: &tlsv3.Secret_TlsCertificate{
			TlsCertificate: &tlsv3.TlsCertificate{
				CertificateChain: coreDataSource(secretPayload),
			},
		},
	}
	usage, err := Meter(xtypes.XdsResources{resourcev3.SecretType: {secret}})
	require.NoError(t, err)

	budget := &egv1a1.XdsResourceBudget{PerTypeURL: []egv1a1.XdsResourceTypeBudget{{
		TypeURL:          resourcev3.SecretType,
		MaxResourceBytes: p(1),
		MaxResources:     p(0),
	}}}
	report := Evaluate(budget, "key", 1, 0, usage, Sources{}, nil)
	require.False(t, report.Published)

	raw, err := json.Marshal(report)
	require.NoError(t, err)
	rendered := string(raw)
	require.NotContains(t, rendered, secretName)
	require.NotContains(t, rendered, secretPayload)

	for _, v := range report.Violations {
		if v.Kind == ViolationResourceBytes {
			require.True(t, v.ResourcesRedacted)
			require.Empty(t, v.OffendingResources)
		}
	}
	// Aggregate sizes are still reported so operators can size the budget.
	require.Greater(t, report.Usage.ByType[resourcev3.SecretType].SerializedBytes, int64(0))
}

func TestEvaluateDisabledBudgetPublishes(t *testing.T) {
	usage, err := Meter(buildEdgeTable(t))
	require.NoError(t, err)
	report := Evaluate(nil, "key", 1, 0, usage, Sources{}, nil)
	require.True(t, report.Published)
	require.Empty(t, report.Violations)
}

func TestEvaluateMeteringErrorIsRejection(t *testing.T) {
	usage := &Usage{ByType: map[string]*TypeUsage{}}
	report := Evaluate(
		&egv1a1.XdsResourceBudget{MaxReferenceEdges: p(1)},
		"key", 1, 0, usage, Sources{}, errOverflow,
	)
	require.False(t, report.Published)
	require.Len(t, report.Violations, 1)
	require.Equal(t, ViolationMetering, report.Violations[0].Kind)
}

func TestAddInt64Overflow(t *testing.T) {
	_, err := addInt64(math.MaxInt64, 1)
	require.ErrorIs(t, err, errOverflow)
	_, err = addInt64(math.MinInt64, -1)
	require.ErrorIs(t, err, errOverflow)

	sum, err := addInt64(math.MaxInt64-1, 1)
	require.NoError(t, err)
	require.Equal(t, int64(math.MaxInt64), sum)
}

func TestCollectSources(t *testing.T) {
	xdsIR := &ir.Xds{
		HTTP: []*ir.HTTPListener{
			{
				CoreListenerDetails: ir.CoreListenerDetails{
					Name:     "default/eg/http",
					Address:  "0.0.0.0",
					Port:     80,
					Metadata: &ir.ResourceMetadata{Kind: "Gateway", Namespace: "default", Name: "eg", SectionName: "http"},
				},
				Routes: []*ir.HTTPRoute{
					{Name: "default/route-a/rule/0/match/0", Metadata: &ir.ResourceMetadata{Kind: "HTTPRoute", Namespace: "default", Name: "route-a"}},
					{Name: "default/route-b/rule/0/match/0", Metadata: &ir.ResourceMetadata{Kind: "HTTPRoute", Namespace: "default", Name: "route-b"}},
					// Duplicate expansion of the same route: sources are deduplicated.
					{Name: "default/route-b/rule/0/match/1", Metadata: &ir.ResourceMetadata{Kind: "HTTPRoute", Namespace: "default", Name: "route-b"}},
				},
			},
		},
		TCP: []*ir.TCPListener{
			{
				CoreListenerDetails: ir.CoreListenerDetails{
					Name:     "default/eg/tcp",
					Address:  "0.0.0.0",
					Port:     9000,
					Metadata: &ir.ResourceMetadata{Kind: "Gateway", Namespace: "default", Name: "eg", SectionName: "tcp"},
				},
				Routes: []*ir.TCPRoute{
					{Name: "default/tcp-route", Metadata: &ir.ResourceMetadata{Kind: "TCPRoute", Namespace: "default", Name: "tcp-route"}},
				},
			},
		},
		UDP: []*ir.UDPListener{
			{
				CoreListenerDetails: ir.CoreListenerDetails{
					Name:     "default/eg/udp",
					Address:  "0.0.0.0",
					Port:     9001,
					Metadata: &ir.ResourceMetadata{Kind: "Gateway", Namespace: "default", Name: "eg", SectionName: "udp"},
				},
				Route: &ir.UDPRoute{Name: "default/udp-route"},
			},
		},
	}

	sources := CollectSources(xdsIR)
	require.Len(t, sources.Gateways, 3)
	require.Equal(t, "Gateway", sources.Gateways[0].Kind)
	require.Len(t, sources.Routes, 4)

	var kinds []string
	for _, ref := range sources.Routes {
		kinds = append(kinds, ref.Kind)
	}
	require.Contains(t, kinds, "HTTPRoute")
	require.Contains(t, kinds, "TCPRoute")
	require.Contains(t, kinds, "UDPRoute")

	// Sources are sorted and deterministic, and carry identity only.
	require.Equal(t, "HTTPRoute", sources.Routes[0].Kind)
	require.Equal(t, "route-a", sources.Routes[0].Name)
}

func TestReportDeepCopy(t *testing.T) {
	usage, err := Meter(buildEdgeTable(t))
	require.NoError(t, err)
	report := Evaluate(
		&egv1a1.XdsResourceBudget{MaxReferenceEdges: p(1)},
		"key", 3, 2, usage,
		Sources{Gateways: []ResourceRef{{Kind: "Gateway", Name: "eg"}}, Routes: []ResourceRef{{Kind: "HTTPRoute", Name: "r"}}},
		nil,
	)
	require.False(t, report.Published)

	cp := report.DeepCopy()
	require.Equal(t, report, cp)

	cp.Violations[0].Observed = 999
	cp.Sources.Gateways[0].Name = "changed"
	require.NotEqual(t, report.Violations[0].Observed, cp.Violations[0].Observed)
	require.NotEqual(t, report.Sources.Gateways[0].Name, cp.Sources.Gateways[0].Name)
	require.Nil(t, (*Report)(nil).DeepCopy())
}

func mustMarshal(t *testing.T, msg protobuf.Message) []byte {
	t.Helper()
	data, err := protobuf.Marshal(msg)
	require.NoError(t, err)
	return data
}

func gogoUint32(v uint32) *wrapperspb.UInt32Value {
	return wrapperspb.UInt32(v)
}

func coreTransportSocket(typedConfig *anypb.Any) *corev3.TransportSocket {
	return &corev3.TransportSocket{
		Name: wellknown.TransportSocketTLS,
		ConfigType: &corev3.TransportSocket_TypedConfig{
			TypedConfig: typedConfig,
		},
	}
}

func coreTypedExtensionConfig(t *testing.T, name string) *corev3.TypedExtensionConfig {
	t.Helper()
	return &corev3.TypedExtensionConfig{
		Name: name,
		TypedConfig: marshalAny(t, &hcmv3.HttpConnectionManager{
			StatPrefix: name,
		}),
	}
}

func coreDataSource(inline string) *corev3.DataSource {
	return &corev3.DataSource{
		Specifier: &corev3.DataSource_InlineString{InlineString: inline},
	}
}
