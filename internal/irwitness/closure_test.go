// Copyright Envoy Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package irwitness

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/envoyproxy/gateway/internal/ir"
)

// TestCACertificateClosure verifies CA registration entries are retained while
// referenced and reclaimed once their last referrer disappears.
func TestCACertificateClosure(t *testing.T) {
	const (
		clusterName = "cluster-with-ca"
		caDigest    = "sha256:ca-bundle-digest"
	)
	cluster := backendCluster(clusterName, "7.7.7.7", 8080)
	cluster.Setting.TLS = &ir.TLSUpstreamConfig{
		CACertificate: &ir.TLSCACertificate{Digest: caDigest},
	}
	route := clusterRefRoute("tls-route", "/tls", clusterName)
	x := &ir.Xds{
		HTTP:            []*ir.HTTPListener{baseListener("gw/http", route)},
		BackendClusters: []*ir.BackendCluster{cluster},
		CACertificates: []*ir.CACertificateEntry{{
			Digest:      caDigest,
			Certificate: []byte("ca-bundle-bytes"),
		}},
	}
	require.NoError(t, x.Validate())
	require.True(t, secretBearing(x))

	// Index counts the digest reference exactly once.
	idx := buildReferenceIndex(x)
	require.Equal(t, 1, idx.caDigests[caDigest])

	// Removing the sole route reclaims the cluster and then the CA entry.
	candidate, op, err := removeRoute(x, "gw/http", "tls-route")
	require.NoError(t, err)
	require.NoError(t, candidate.Validate())
	require.Contains(t, op.Reclaimed, string(DeletionBackendCluster)+":"+clusterName)
	require.Contains(t, op.Reclaimed, string(DeletionCACertificate)+":"+caDigest)
	require.Empty(t, candidate.CACertificates)
	require.Empty(t, candidate.BackendClusters)

	// The original IR keeps its CA registration.
	require.Len(t, x.CACertificates, 1)
}

// TestExtensionBackendClosure verifies ExtensionBackend registry entries are
// reference counted through EnvoyExtensions.Backends aliases.
func TestExtensionBackendClosure(t *testing.T) {
	const extName = "envoyextensionpolicy/default/policy/backend/0"
	route := settingsRoute("ext-route", "/ext", "ext-dest", "10.0.0.1", 8080)
	route.EnvoyExtensions = &ir.EnvoyExtensionFeatures{
		Backends: map[string]string{"resolver": extName},
	}
	x := &ir.Xds{
		HTTP: []*ir.HTTPListener{baseListener("gw/http", route)},
		ExtensionBackends: []*ir.ExtensionBackend{{
			RouteDestination: ir.RouteDestination{
				Name: extName,
				Settings: []*ir.DestinationSetting{{
					Name:        extName + "/0",
					Protocol:    ir.HTTP,
					AddressType: ptrIP(),
					Weight:      u32Ptr(1),
					Endpoints:   []*ir.DestinationEndpoint{{Host: "10.0.0.2", Port: 8080}},
				}},
			},
		}},
	}
	require.NoError(t, x.Validate())

	idx := buildReferenceIndex(x)
	require.Equal(t, 1, idx.extBackends[extName])

	candidate, op, err := removeRoute(x, "gw/http", "ext-route")
	require.NoError(t, err)
	require.NoError(t, candidate.Validate())
	require.Contains(t, op.Reclaimed, string(DeletionExtensionBackend)+":"+extName)
	require.Empty(t, candidate.ExtensionBackends)
}

// TestSharedExtensionBackendKept proves an ExtensionBackend referenced by two
// routes survives the deletion of either one.
func TestSharedExtensionBackendKept(t *testing.T) {
	const (
		extName     = "shared-ext-backend"
		mainCluster = "main-cluster"
	)
	makeRoute := func(name string) *ir.HTTPRoute {
		route := clusterRefRoute(name, "/"+name, mainCluster)
		route.EnvoyExtensions = &ir.EnvoyExtensionFeatures{
			Backends: map[string]string{"resolver": extName},
		}
		return route
	}
	x := &ir.Xds{
		HTTP: []*ir.HTTPListener{baseListener("gw/http", makeRoute("route-1"), makeRoute("route-2"))},
		BackendClusters: []*ir.BackendCluster{
			backendCluster(mainCluster, "10.0.0.9", 8080),
		},
		ExtensionBackends: []*ir.ExtensionBackend{{
			RouteDestination: ir.RouteDestination{
				Name: extName,
				Settings: []*ir.DestinationSetting{{
					Name:        extName + "/0",
					Protocol:    ir.HTTP,
					AddressType: ptrIP(),
					Weight:      u32Ptr(1),
					Endpoints:   []*ir.DestinationEndpoint{{Host: "10.0.0.2", Port: 8080}},
				}},
			},
		}},
	}
	require.NoError(t, x.Validate())

	candidate, op, err := removeRoute(x, "gw/http", "route-1")
	require.NoError(t, err)
	require.NoError(t, candidate.Validate())
	for _, reclaimed := range op.Reclaimed {
		require.NotContains(t, reclaimed, extName)
	}
	require.Len(t, candidate.ExtensionBackends, 1)

	// The reducer keeps the shared extension backend while any alias survives.
	pred := mustCompile(t, resourceExistsSpec("cluster", mainCluster))
	result, err := Reduce(context.Background(), x, pred, testOptions())
	require.NoError(t, err)
	require.Equal(t, StatusOneMinimal, result.Status)
	require.Len(t, result.BestKnown.ExtensionBackends, 1)
}

func ptrIP() *ir.DestinationAddressType {
	v := ir.IP
	return &v
}

func u32Ptr(v uint32) *uint32 {
	return &v
}
