// Copyright Envoy Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package runner

import (
	"io"
	"testing"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"github.com/stretchr/testify/require"

	egv1a1 "github.com/envoyproxy/gateway/api/v1alpha1"
	"github.com/envoyproxy/gateway/internal/envoygateway/config"
	"github.com/envoyproxy/gateway/internal/ir"
	"github.com/envoyproxy/gateway/internal/message"
	xtypes "github.com/envoyproxy/gateway/internal/xds/types"
)

func TestApplyResourceBudgetDirect(t *testing.T) {
	cfg, err := config.New(io.Discard, io.Discard)
	require.NoError(t, err)
	cfg.EnvoyGateway.XDSServer = &egv1a1.XDSServer{
		ResourceBudget: &egv1a1.XdsResourceBudget{
			PerTypeURL: []egv1a1.XdsResourceTypeBudget{{
				TypeURL:      resourcev3.ClusterType,
				MaxResources: int64Ptr(1),
			}},
		},
	}
	r := New(&Config{Server: *cfg, ProviderResources: new(message.ProviderResources)})
	r.Logger = r.Logger.WithName(r.Name())
	r.budgetState = map[string]*budgetKeyState{}
	r.resourceBudget = cfg.EnvoyGateway.XDSServer.ResourceBudget

	table := &xtypes.ResourceVersionTable{
		XdsResources: xtypes.XdsResources{
			resourcev3.ClusterType: {
				&clusterv3.Cluster{Name: "c1", ClusterDiscoveryType: &clusterv3.Cluster_Type{Type: clusterv3.Cluster_STATIC}},
				&clusterv3.Cluster{Name: "c2", ClusterDiscoveryType: &clusterv3.Cluster_Type{Type: clusterv3.Cluster_STATIC}},
			},
		},
	}

	allow := r.applyResourceBudget("k", &ir.Xds{}, table, r.Logger)
	require.False(t, allow)
	report, ok := r.ProviderResources.XdsBudgetStatuses.Load("k")
	require.True(t, ok, "rejection report must be stored")
	require.False(t, report.Published)
	require.Equal(t, int64(1), report.Generation)
	require.Equal(t, int64(0), report.LastGoodGeneration)
}
