// Copyright Envoy Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package runner

import (
	"context"
	"fmt"
	"io"
	"testing"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	cachev3 "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"github.com/stretchr/testify/require"
	protobuf "google.golang.org/protobuf/proto"

	egv1a1 "github.com/envoyproxy/gateway/api/v1alpha1"
	"github.com/envoyproxy/gateway/internal/envoygateway/config"
	"github.com/envoyproxy/gateway/internal/ir"
	"github.com/envoyproxy/gateway/internal/message"
	xdsbudget "github.com/envoyproxy/gateway/internal/xds/budget"
)

// budgetTestIR builds an IR with listenerCount distinct HTTP listeners, each
// exposing one route. Every listener maps to one xDS Listener resource, so the
// translated listener count is predictable instead of being estimated from
// Kubernetes object counts.
func budgetTestIR(listenerCount int) *ir.Xds {
	listeners := make([]*ir.HTTPListener, 0, listenerCount)
	for i := 0; i < listenerCount; i++ {
		port := 8000 + uint32(i)
		path := fmt.Sprintf("/path-%d", i)
		listeners = append(listeners, &ir.HTTPListener{
			CoreListenerDetails: ir.CoreListenerDetails{
				Name:    fmt.Sprintf("default/eg/http-%d", i),
				Address: "0.0.0.0",
				Port:    port,
				Metadata: &ir.ResourceMetadata{
					Kind:        "Gateway",
					Namespace:   "default",
					Name:        "eg",
					SectionName: fmt.Sprintf("http-%d", i),
				},
			},
			Hostnames: []string{fmt.Sprintf("host-%d.example.com", i)},
			Routes: []*ir.HTTPRoute{{
				Name: fmt.Sprintf("default/route-%d/rule/0/match/0", i),
				Metadata: &ir.ResourceMetadata{
					Kind:      "HTTPRoute",
					Namespace: "default",
					Name:      fmt.Sprintf("route-%d", i),
				},
				PathMatch: &ir.StringMatch{Exact: &path},
				Destination: &ir.RouteDestination{
					Name: fmt.Sprintf("dest-%d", i),
					Settings: []*ir.DestinationSetting{{
						Endpoints: []*ir.DestinationEndpoint{{Host: "10.0.0.1", Port: 8080}},
					}},
				},
			}},
		})
	}
	return &ir.Xds{HTTP: listeners}
}

func newBudgetRunner(t *testing.T, budget *egv1a1.XdsResourceBudget) (*Runner, *message.XdsIR, *message.ProviderResources, context.CancelFunc) {
	t.Helper()
	caFile, certFile, keyFile, cleanup := setupTLSCerts(t)

	xdsIR := new(message.XdsIR)
	pResource := new(message.ProviderResources)
	cfg, err := config.New(io.Discard, io.Discard)
	require.NoError(t, err)
	cfg.EnvoyGateway.XDSServer = &egv1a1.XDSServer{ResourceBudget: budget}

	r := New(&Config{
		Server:            *cfg,
		ProviderResources: pResource,
		XdsIR:             xdsIR,
		TLSCertPath:       certFile,
		TLSKeyPath:        keyFile,
		TLSCaPath:         caFile,
	})

	ctx, cancel := context.WithCancel(newTestTraceContext())
	require.NoError(t, r.Start(ctx))
	t.Cleanup(func() {
		cancel()
		require.NoError(t, r.Close())
		cleanup()
	})
	return r, xdsIR, pResource, cancel
}

func storeBudgetIR(t *testing.T, xdsIR *message.XdsIR, key string, x *ir.Xds) {
	t.Helper()
	xdsIR.Store(key, &message.XdsIRWithContext{XdsIR: x, Context: newTestTraceContext()})
}

// snapshotByteSize registers a node for irKey and returns the total protobuf
// size of the snapshot currently served to it. It lets tests prove that a
// rejected candidate never changes the last good bytes.
func snapshotByteSize(t *testing.T, r *Runner, irKey, nodeID string, streamID int64) int64 {
	t.Helper()
	require.NoError(t, r.cache.OnStreamOpen(context.Background(), streamID, ""))
	require.NoError(t, r.cache.OnStreamRequest(streamID, &discoveryv3.DiscoveryRequest{
		Node: &corev3.Node{Id: nodeID, Cluster: irKey},
	}))

	snap, err := r.cache.GetSnapshot(nodeID)
	require.NoError(t, err)
	typed, ok := snap.(*cachev3.Snapshot)
	require.True(t, ok)

	var total int64
	for _, resources := range typed.Resources {
		for _, item := range resources.Items {
			data, err := protobuf.Marshal(item.Resource)
			require.NoError(t, err)
			total += int64(len(data))
		}
	}
	require.Greater(t, total, int64(0))
	return total
}

// TestRunnerResourceBudgetGate verifies the end-to-end gate: compliant
// candidates reach the snapshot cache, over-budget ones are rejected while the
// last good snapshot keeps being served, rejection carries the generation
// identity and Gateway/Route sources, and other IR keys publish independently.
func TestRunnerResourceBudgetGate(t *testing.T) {
	// At most five listeners per candidate snapshot.
	budget := &egv1a1.XdsResourceBudget{
		PerTypeURL: []egv1a1.XdsResourceTypeBudget{{
			TypeURL:      resourcev3.ListenerType,
			MaxResources: int64Ptr(5),
		}},
	}
	r, xdsIR, pResource, _ := newBudgetRunner(t, budget)

	// Phase 1: a small, compliant candidate is published as generation one.
	storeBudgetIR(t, xdsIR, "gate", budgetTestIR(1))
	require.Eventually(t, func() bool { return r.cache.SnapshotHasIrKey("gate") }, 5*time.Second, 50*time.Millisecond)
	lastGoodBytes := snapshotByteSize(t, r, "gate", "node-gate", 1)

	require.Eventually(t, func() bool {
		report, ok := pResource.XdsBudgetStatuses.Load("gate")
		return ok && report.Published && report.Generation == 1 && report.LastGoodGeneration == 1
	}, 5*time.Second, 50*time.Millisecond)

	// Phase 2: a large candidate (six listeners) exceeds the budget. It must not
	// reach the cache; Envoy keeps the phase-one snapshot byte for byte.
	storeBudgetIR(t, xdsIR, "gate", budgetTestIR(6))
	var rejected *xdsbudget.Report
	require.Eventually(t, func() bool {
		report, ok := pResource.XdsBudgetStatuses.Load("gate")
		if ok && !report.Published {
			rejected = report
			return true
		}
		return false
	}, 5*time.Second, 50*time.Millisecond)

	require.Equal(t, int64(2), rejected.Generation)
	require.Equal(t, int64(1), rejected.LastGoodGeneration)
	require.Len(t, rejected.Violations, 1)
	require.Equal(t, xdsbudget.ViolationResources, rejected.Violations[0].Kind)
	require.Equal(t, int64(6), rejected.Violations[0].Observed)
	require.NotEmpty(t, rejected.Sources.Gateways)
	require.Equal(t, "Gateway", rejected.Sources.Gateways[0].Kind)
	require.Len(t, rejected.Sources.Routes, 6)

	// The publish entry only ever received the compliant table: the snapshot
	// bytes and listener count are unchanged.
	require.Equal(t, lastGoodBytes, snapshotByteSize(t, r, "gate", "node-gate", 1))

	// Rejection is a stable state, not a retryable error: nothing re-stores the
	// IR and the runner must not reconcile in a loop.
	time.Sleep(500 * time.Millisecond)
	report, ok := pResource.XdsBudgetStatuses.Load("gate")
	require.True(t, ok)
	require.False(t, report.Published)
	require.Equal(t, int64(2), report.Generation)
	require.Equal(t, 1, pResource.XdsBudgetStatuses.Len())

	// Phase 3: another IR key is bounded independently and still publishes.
	storeBudgetIR(t, xdsIR, "other", budgetTestIR(2))
	require.Eventually(t, func() bool { return r.cache.SnapshotHasIrKey("other") }, 5*time.Second, 50*time.Millisecond)
	otherReport, ok := pResource.XdsBudgetStatuses.Load("other")
	require.True(t, ok)
	require.True(t, otherReport.Published)

	// Phase 4: a compliant candidate for the rejected key publishes, advances the
	// last good generation and clears the rejection report.
	storeBudgetIR(t, xdsIR, "gate", budgetTestIR(2))
	require.Eventually(t, func() bool {
		report, ok := pResource.XdsBudgetStatuses.Load("gate")
		return ok && report.Published && report.Generation == 3 && report.LastGoodGeneration == 3
	}, 5*time.Second, 50*time.Millisecond)
	// The rejection is replaced by the successful evaluation, not silently dropped.
	report, ok = pResource.XdsBudgetStatuses.Load("gate")
	require.True(t, ok)
	require.True(t, report.Published)
	require.Empty(t, report.Violations)
}

// TestRunnerResourceBudgetRejectsFirstCandidate checks that when no compliant
// snapshot exists yet, a rejected candidate reports generation one with a zero
// last good generation and no snapshot is ever created for the key.
func TestRunnerResourceBudgetRejectsFirstCandidate(t *testing.T) {
	// One serialized byte can never hold a RouteConfiguration, so every
	// candidate fails on its route configuration size.
	budget := &egv1a1.XdsResourceBudget{
		PerTypeURL: []egv1a1.XdsResourceTypeBudget{{
			TypeURL:            resourcev3.RouteType,
			MaxSerializedBytes: int64Ptr(1),
		}},
	}
	r, xdsIR, pResource, _ := newBudgetRunner(t, budget)

	storeBudgetIR(t, xdsIR, "never-published", budgetTestIR(1))
	require.Eventually(t, func() bool {
		report, ok := pResource.XdsBudgetStatuses.Load("never-published")
		return ok && !report.Published
	}, 5*time.Second, 50*time.Millisecond)

	report, _ := pResource.XdsBudgetStatuses.Load("never-published")
	require.Equal(t, int64(1), report.Generation)
	require.Equal(t, int64(0), report.LastGoodGeneration)
	require.Never(t, func() bool { return r.cache.SnapshotHasIrKey("never-published") }, time.Second, 50*time.Millisecond)

	// Deleting the IR drops the rejection state as well.
	xdsIR.Delete("never-published")
	require.Eventually(t, func() bool { return pResource.XdsBudgetStatuses.Len() == 0 }, 5*time.Second, 50*time.Millisecond)
}

// TestRunnerResourceBudgetDisabled confirms the original publish path is
// unchanged when no budget is configured.
func TestRunnerResourceBudgetDisabled(t *testing.T) {
	caFile, certFile, keyFile, cleanup := setupTLSCerts(t)
	defer cleanup()

	xdsIR := new(message.XdsIR)
	pResource := new(message.ProviderResources)
	cfg, err := config.New(io.Discard, io.Discard)
	require.NoError(t, err)

	r := New(&Config{
		Server:            *cfg,
		ProviderResources: pResource,
		XdsIR:             xdsIR,
		TLSCertPath:       certFile,
		TLSKeyPath:        keyFile,
		TLSCaPath:         caFile,
	})
	ctx, cancel := context.WithCancel(newTestTraceContext())
	require.NoError(t, r.Start(ctx))
	defer func() {
		cancel()
		require.NoError(t, r.Close())
	}()

	storeBudgetIR(t, xdsIR, "no-budget", budgetTestIR(3))
	require.Eventually(t, func() bool { return r.cache.SnapshotHasIrKey("no-budget") }, 5*time.Second, 50*time.Millisecond)
	require.Equal(t, 0, pResource.XdsBudgetStatuses.Len())
}

func int64Ptr(v int64) *int64 { return &v }
