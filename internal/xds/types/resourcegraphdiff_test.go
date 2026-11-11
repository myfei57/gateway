// Copyright Envoy Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package types

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
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
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// ---------------------------------------------------------------------------
// Test fixtures
// ---------------------------------------------------------------------------

func newTable(resources map[resourcev3.Type][]cachetypes.Resource) *ResourceVersionTable {
	return &ResourceVersionTable{XdsResources: XdsResources(resources)}
}

func mustAny(t *testing.T, msg proto.Message) *anypb.Any {
	t.Helper()
	a, err := anypb.New(msg)
	require.NoError(t, err)
	return a
}

func adsConfigSource() *corev3.ConfigSource {
	return &corev3.ConfigSource{ConfigSourceSpecifier: &corev3.ConfigSource_Ads{Ads: &corev3.AggregatedConfigSource{}}}
}

func grpcConfigSource() *corev3.ConfigSource {
	return &corev3.ConfigSource{ConfigSourceSpecifier: &corev3.ConfigSource_ApiConfigSource{
		ApiConfigSource: &corev3.ApiConfigSource{
			ApiType: corev3.ApiConfigSource_GRPC,
			GrpcServices: []*corev3.GrpcService{{
				TargetSpecifier: &corev3.GrpcService_EnvoyGrpc_{
					EnvoyGrpc: &corev3.GrpcService_EnvoyGrpc{ClusterName: "external-sds-cluster"},
				},
			}},
		},
	}}
}

func hcmListener(t *testing.T, name, routeConfigName string, transportSocket *corev3.TransportSocket) *listenerv3.Listener {
	t.Helper()
	hcm := &hcmv3.HttpConnectionManager{
		StatPrefix: name,
		RouteSpecifier: &hcmv3.HttpConnectionManager_Rds{
			Rds: &hcmv3.Rds{ConfigSource: adsConfigSource(), RouteConfigName: routeConfigName},
		},
	}
	chain := &listenerv3.FilterChain{
		Filters: []*listenerv3.Filter{{
			Name: wellknown.HTTPConnectionManager,
			ConfigType: &listenerv3.Filter_TypedConfig{
				TypedConfig: mustAny(t, hcm),
			},
		}},
	}
	if transportSocket != nil {
		chain.TransportSocket = transportSocket
	}
	return &listenerv3.Listener{
		Name:         name,
		FilterChains: []*listenerv3.FilterChain{chain},
	}
}

type routeSpec struct {
	prefix  string
	cluster string
}

func routeConfig(name string, specs ...routeSpec) *routev3.RouteConfiguration {
	rc := &routev3.RouteConfiguration{Name: name}
	for _, spec := range specs {
		rc.VirtualHosts = append(rc.VirtualHosts, &routev3.VirtualHost{
			Name:    name + "/" + spec.prefix,
			Domains: []string{"*"},
			Routes: []*routev3.Route{{
				Match: &routev3.RouteMatch{PathSpecifier: &routev3.RouteMatch_Prefix{Prefix: spec.prefix}},
				Action: &routev3.Route_Route{Route: &routev3.RouteAction{
					ClusterSpecifier: &routev3.RouteAction_Cluster{Cluster: spec.cluster},
				}},
			}},
		})
	}
	return rc
}

func edsCluster(name, serviceName string, edsConfig *corev3.ConfigSource) *clusterv3.Cluster {
	c := &clusterv3.Cluster{
		Name:                 name,
		ClusterDiscoveryType: &clusterv3.Cluster_Type{Type: clusterv3.Cluster_EDS},
		EdsClusterConfig: &clusterv3.Cluster_EdsClusterConfig{
			ServiceName: serviceName,
			EdsConfig:   edsConfig,
		},
	}
	return c
}

func endpoint(clusterName, host string, port uint32) *endpointv3.ClusterLoadAssignment {
	return &endpointv3.ClusterLoadAssignment{
		ClusterName: clusterName,
		Endpoints: []*endpointv3.LocalityLbEndpoints{{
			LbEndpoints: []*endpointv3.LbEndpoint{{
				HostIdentifier: &endpointv3.LbEndpoint_Endpoint{
					Endpoint: &endpointv3.Endpoint{Address: &corev3.Address{
						Address: &corev3.Address_SocketAddress{SocketAddress: &corev3.SocketAddress{
							Address:       host,
							PortSpecifier: &corev3.SocketAddress_PortValue{PortValue: port},
						}},
					}},
				},
			}},
		}},
	}
}

func tlsSecret(name, certPEM, keyPEM string) *tlsv3.Secret {
	return &tlsv3.Secret{
		Name: name,
		Type: &tlsv3.Secret_TlsCertificate{TlsCertificate: &tlsv3.TlsCertificate{
			CertificateChain: &corev3.DataSource{Specifier: &corev3.DataSource_InlineBytes{InlineBytes: []byte(certPEM)}},
			PrivateKey:       &corev3.DataSource{Specifier: &corev3.DataSource_InlineBytes{InlineBytes: []byte(keyPEM)}},
		}},
	}
}

func tlsTransportSocket(t *testing.T, sdsConfigs ...*tlsv3.SdsSecretConfig) *corev3.TransportSocket {
	t.Helper()
	downstream := &tlsv3.DownstreamTlsContext{
		CommonTlsContext: &tlsv3.CommonTlsContext{TlsCertificateSdsSecretConfigs: sdsConfigs},
	}
	return &corev3.TransportSocket{
		Name:       wellknown.TransportSocketTLS,
		ConfigType: &corev3.TransportSocket_TypedConfig{TypedConfig: mustAny(t, downstream)},
	}
}

func sdsSecretConfig(name string, cs *corev3.ConfigSource) *tlsv3.SdsSecretConfig {
	return &tlsv3.SdsSecretConfig{Name: name, SdsConfig: cs}
}

// fullChainTable builds a complete listener -> route -> cluster -> endpoint chain.
func fullChainTable(t *testing.T, listenerName, routeName, clusterName, endpointHost string) *ResourceVersionTable {
	t.Helper()
	l := hcmListener(t, listenerName, routeName, nil)
	rc := routeConfig(routeName, routeSpec{prefix: "/", cluster: clusterName})
	c := edsCluster(clusterName, clusterName, adsConfigSource())
	e := endpoint(clusterName, endpointHost, 8080)
	return newTable(map[resourcev3.Type][]cachetypes.Resource{
		resourcev3.ListenerType: {l},
		resourcev3.RouteType:    {rc},
		resourcev3.ClusterType:  {c},
		resourcev3.EndpointType: {e},
	})
}

func findChange(t *testing.T, report *GraphDiffReport, id ResourceID) ResourceChange {
	t.Helper()
	for _, c := range append(append(report.Added, report.Removed...), report.Modified...) {
		if idEqual(c.ID, id) {
			return c
		}
	}
	require.Failf(t, "change not found", "resource %s", id)
	return ResourceChange{}
}

func hasChange(report *GraphDiffReport, id ResourceID) bool {
	for _, c := range append(append(report.Added, report.Removed...), report.Modified...) {
		if idEqual(c.ID, id) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestDiffEmptyAndNil(t *testing.T) {
	report := DiffResourceGraphs(nil, nil)
	require.Empty(t, report.Added)
	require.Empty(t, report.Removed)
	require.Empty(t, report.Modified)
	require.NotEmpty(t, report.StructuralOnlyStatement)
	require.False(t, report.Truncated)

	report = DiffResourceGraphs(newTable(nil), newTable(XdsResources{}))
	require.Equal(t, 0, report.Counts.Added+report.Counts.Removed+report.Counts.Modified)
}

func TestDiffMapOrderIndependence(t *testing.T) {
	// Repeatedly build equivalent tables whose map fields are populated in
	// different Go insertion orders, including a map nested inside an Any.
	for iteration := 0; iteration < 20; iteration++ {
		build := func() *ResourceVersionTable {
			rc := routeConfig("rc", routeSpec{prefix: "/", cluster: "c"})
			rc.Metadata = &corev3.Metadata{FilterMetadata: map[string]*structpb.Struct{
				"zeta":  {Fields: map[string]*structpb.Value{"k": structpb.NewStringValue("v")}},
				"alpha": {Fields: map[string]*structpb.Value{"k": structpb.NewStringValue("v")}},
				"mu":    {Fields: map[string]*structpb.Value{"k": structpb.NewStringValue("v")}},
			}}
			// A map nested inside an Any: per-filter config wrapping a structpb.Struct.
			rc.VirtualHosts[0].Routes[0].TypedPerFilterConfig = map[string]*anypb.Any{
				"filter-z": mustAny(t, &structpb.Struct{Fields: map[string]*structpb.Value{
					"z-field": structpb.NewStringValue("z"),
					"a-field": structpb.NewStringValue("a"),
					"m-field": structpb.NewStringValue("m"),
				}}),
			}
			return newTable(map[resourcev3.Type][]cachetypes.Resource{
				resourcev3.RouteType: {rc},
			})
		}
		report := DiffResourceGraphs(build(), build())
		require.Empty(t, report.Modified, "iteration %d: map ordering must not produce a modification", iteration)
		require.Empty(t, report.Added)
		require.Empty(t, report.Removed)
		require.Equal(t, 1, report.Counts.Unchanged)
	}
}

func TestDiffRouteOrderChangeIsSignificant(t *testing.T) {
	rcA := routeConfig("rc",
		routeSpec{prefix: "/a", cluster: "c-a"},
		routeSpec{prefix: "/b", cluster: "c-b"},
	)
	// Same routes and references, only the ordered repeated field is reordered.
	rcB := routeConfig("rc",
		routeSpec{prefix: "/b", cluster: "c-b"},
		routeSpec{prefix: "/a", cluster: "c-a"},
	)
	tableA := newTable(map[resourcev3.Type][]cachetypes.Resource{resourcev3.RouteType: {rcA}})
	tableB := newTable(map[resourcev3.Type][]cachetypes.Resource{resourcev3.RouteType: {rcB}})

	report := DiffResourceGraphs(tableA, tableB)
	require.Len(t, report.Modified, 1, "route order changes must not be sorted away")
	require.Equal(t, ResourceID{TypeURL: resourcev3.RouteType, Name: "rc"}, report.Modified[0].ID)

	// The edge set is unchanged: both tables still reference the same clusters.
	require.Empty(t, report.ReferenceChanges)
}

func TestDiffSharedClusterSingleNodeAndImpact(t *testing.T) {
	l1, l2 := "listener-1", "listener-2"
	rc1, rc2 := "route-1", "route-2"
	clusterName, endpointName := "shared-cluster", "shared-cluster"

	build := func(endpointHost string, lbPolicy clusterv3.Cluster_LbPolicy) *ResourceVersionTable {
		c := edsCluster(clusterName, clusterName, adsConfigSource())
		c.LbPolicy = lbPolicy
		return newTable(map[resourcev3.Type][]cachetypes.Resource{
			resourcev3.ListenerType: {
				hcmListener(t, l1, rc1, nil),
				hcmListener(t, l2, rc2, nil),
			},
			resourcev3.RouteType: {
				routeConfig(rc1, routeSpec{prefix: "/", cluster: clusterName}),
				routeConfig(rc2, routeSpec{prefix: "/", cluster: clusterName}),
			},
			resourcev3.ClusterType:  {c},
			resourcev3.EndpointType: {endpoint(endpointName, endpointHost, 8080)},
		})
	}

	d := NewXdsResourceGraphDiff()
	newGraph := d.buildGraph(build("10.0.0.2", clusterv3.Cluster_ROUND_ROBIN), SideNew)
	// A shared resource is stored as exactly one node keyed by type URL + name.
	require.Len(t, newGraph.nodes, 6, "two listeners, two route configs, one shared cluster, one endpoint")
	require.Contains(t, newGraph.nodes, ResourceID{TypeURL: resourcev3.ClusterType, Name: clusterName})

	report := d.Diff(
		build("10.0.0.1", clusterv3.Cluster_LEAST_REQUEST),
		build("10.0.0.2", clusterv3.Cluster_ROUND_ROBIN),
	)
	clusterChange := findChange(t, report, ResourceID{TypeURL: resourcev3.ClusterType, Name: clusterName})
	require.Equal(t, ChangeModified, clusterChange.Kind)
	require.ElementsMatch(t,
		[]ResourceID{{TypeURL: resourcev3.ListenerType, Name: l1}, {TypeURL: resourcev3.ListenerType, Name: l2}},
		clusterChange.AffectedListeners, "both listener entries reach the shared cluster")

	endpointChange := findChange(t, report, ResourceID{TypeURL: resourcev3.EndpointType, Name: endpointName})
	require.Equal(t, ChangeModified, endpointChange.Kind)
	require.ElementsMatch(t,
		[]ResourceID{{TypeURL: resourcev3.ListenerType, Name: l1}, {TypeURL: resourcev3.ListenerType, Name: l2}},
		endpointChange.AffectedListeners, "both listener entries reach the shared endpoint closure")
	require.Equal(t, []ResourceID{
		{TypeURL: resourcev3.ListenerType, Name: l1},
		{TypeURL: resourcev3.RouteType, Name: rc1},
		{TypeURL: resourcev3.ClusterType, Name: clusterName},
		{TypeURL: resourcev3.EndpointType, Name: endpointName},
	}, endpointChange.ExplainPath, "shortest explanation path follows the full reference closure")
}

func TestDiffSecretRotationDigestOnly(t *testing.T) {
	const secretName = "cert-secret"
	build := func(cert, key string) *ResourceVersionTable {
		socket := tlsTransportSocket(t, sdsSecretConfig(secretName, adsConfigSource()))
		l := hcmListener(t, "listener-1", "route-1", socket)
		return newTable(map[resourcev3.Type][]cachetypes.Resource{
			resourcev3.ListenerType: {l},
			resourcev3.SecretType:   {tlsSecret(secretName, cert, key)},
		})
	}

	oldTable := build("cert-version-1", "secret-key-payload-alpha")
	newTable := build("cert-version-2", "secret-key-payload-beta")

	report := DiffResourceGraphs(oldTable, newTable)
	require.Len(t, report.Modified, 1)
	change := report.Modified[0]
	require.True(t, change.Secret)
	require.Equal(t, ResourceID{TypeURL: resourcev3.SecretType, Name: secretName}, change.ID)
	require.NotEmpty(t, change.OldDigest)
	require.NotEmpty(t, change.NewDigest)
	require.NotEqual(t, change.OldDigest, change.NewDigest, "secret rotation must be detected, not ignored")

	// The digest is the SHA-256 of the canonical secret bytes.
	raw, _, _, err := canonicalFingerprint(tlsSecret(secretName, "cert-version-2", "secret-key-payload-beta"))
	require.NoError(t, err)
	sum := sha256.Sum256(raw)
	require.Equal(t, hex.EncodeToString(sum[:]), change.NewDigest)

	// No secret material may appear anywhere in the report.
	rendered := fmt.Sprintf("%+v", report)
	require.NotContains(t, rendered, "secret-key-payload-alpha")
	require.NotContains(t, rendered, "secret-key-payload-beta")
	require.NotContains(t, rendered, "cert-version-1")
	require.NotContains(t, rendered, "cert-version-2")

	// Identical secrets must not be reported as changed.
	stable := DiffResourceGraphs(build("same", "same"), build("same", "same"))
	require.Empty(t, stable.Modified)
	require.Equal(t, 2, stable.Counts.Unchanged, "listener and secret are both unchanged")
}

func TestDiffDanglingReferenceAndExternalSDS(t *testing.T) {
	// Route references a cluster that does not exist in either table.
	l := hcmListener(t, "listener-1", "route-1", nil)
	rc := routeConfig("route-1", routeSpec{prefix: "/", cluster: "missing-cluster"})
	// Listener also fetches a secret through an explicit gRPC SDS server.
	socket := tlsTransportSocket(t, sdsSecretConfig("external-secret", grpcConfigSource()))
	l.FilterChains[0].TransportSocket = socket
	table := newTable(map[resourcev3.Type][]cachetypes.Resource{
		resourcev3.ListenerType: {l},
		resourcev3.RouteType:    {rc},
	})

	report := DiffResourceGraphs(newTable(nil), table)
	var dangling *DanglingReference
	for i := range report.DanglingReferences {
		if report.DanglingReferences[i].Side == SideNew {
			dangling = &report.DanglingReferences[i]
			break
		}
	}
	require.NotNil(t, dangling)
	require.Equal(t, DanglingNew, dangling.Class)
	require.Equal(t, ResourceID{TypeURL: resourcev3.ClusterType, Name: "missing-cluster"}, dangling.Edge.To)
	require.Equal(t, ReferenceInternal, dangling.Edge.Kind)
	require.Equal(t,
		[]ResourceID{{TypeURL: resourcev3.ListenerType, Name: "listener-1"}, {TypeURL: resourcev3.RouteType, Name: "route-1"}},
		dangling.ExplainPath)
	require.Equal(t, []ResourceID{{TypeURL: resourcev3.ListenerType, Name: "listener-1"}}, dangling.AffectedListeners)

	// The external SDS secret must be marked External and must not be dangling.
	var external *ExternalReference
	for i := range report.ExternalReferences {
		if report.ExternalReferences[i].Edge.To.Name == "external-secret" {
			external = &report.ExternalReferences[i]
			break
		}
	}
	require.NotNil(t, external)
	require.Equal(t, ReferenceExternal, external.Edge.Kind)
	require.Equal(t, "config_source.api_config_source", external.Edge.ExternalReason)
	for _, d := range report.DanglingReferences {
		require.NotEqual(t, "external-secret", d.Edge.To.Name, "external references must not be reported as dangling")
	}
}

func TestDiffExternalEDSNotDangling(t *testing.T) {
	// An EDS cluster whose endpoint is fetched through a non-ADS source is external.
	c := edsCluster("external-eds-cluster", "external-endpoint", grpcConfigSource())
	table := newTable(map[resourcev3.Type][]cachetypes.Resource{
		resourcev3.ClusterType: {c},
	})
	report := DiffResourceGraphs(newTable(nil), table)
	require.Empty(t, report.DanglingReferences)
	require.Len(t, report.ExternalReferences, 1)
	require.Equal(t, ResourceID{TypeURL: resourcev3.EndpointType, Name: "external-endpoint"}, report.ExternalReferences[0].Edge.To)
	require.Equal(t, ReferenceExternal, report.ExternalReferences[0].Edge.Kind)
}

func TestDiffRemovedResourceStillReferenced(t *testing.T) {
	oldTable := fullChainTable(t, "listener-1", "route-1", "cluster-1", "10.0.0.1")
	// New table keeps the listener and route configuration but drops the cluster
	// and endpoint while the route still points at the removed cluster.
	newTable := newTable(map[resourcev3.Type][]cachetypes.Resource{
		resourcev3.ListenerType: oldTable.XdsResources[resourcev3.ListenerType],
		resourcev3.RouteType:    oldTable.XdsResources[resourcev3.RouteType],
	})

	report := DiffResourceGraphs(oldTable, newTable)
	require.True(t, hasChange(report, ResourceID{TypeURL: resourcev3.ClusterType, Name: "cluster-1"}))
	require.True(t, hasChange(report, ResourceID{TypeURL: resourcev3.EndpointType, Name: "cluster-1"}))

	var removedRef *DanglingReference
	for i := range report.DanglingReferences {
		if report.DanglingReferences[i].Class == DanglingRemovedStillReferenced {
			removedRef = &report.DanglingReferences[i]
			break
		}
	}
	require.NotNil(t, removedRef)
	require.Equal(t, SideNew, removedRef.Side)
	require.Equal(t, ResourceID{TypeURL: resourcev3.ClusterType, Name: "cluster-1"}, removedRef.Edge.To)
	require.Contains(t, removedRef.Reason, "removed")
}

func TestDiffIdentityConflict(t *testing.T) {
	table := newTable(map[resourcev3.Type][]cachetypes.Resource{
		resourcev3.ClusterType: {
			&clusterv3.Cluster{Name: "duplicate"},
			&clusterv3.Cluster{Name: "duplicate", ConnectTimeout: nil},
		},
	})
	report := DiffResourceGraphs(newTable(nil), table)
	require.Len(t, report.IdentityConflicts, 1)
	require.Equal(t, ResourceID{TypeURL: resourcev3.ClusterType, Name: "duplicate"}, report.IdentityConflicts[0].ID)
	require.Equal(t, 2, report.IdentityConflicts[0].Occurrences)
	// Only one node is stored for the duplicated identity.
	require.Equal(t, 1, report.Counts.ResourcesByType[resourcev3.ClusterType].New)
}

func TestDiffSwapInputsFlipsDirection(t *testing.T) {
	oldTable := fullChainTable(t, "listener-1", "route-1", "cluster-old", "10.0.0.1")
	// New table: same listener/route, different cluster + endpoint, and a fresh
	// dangling reference introduced by a second route entry.
	newRC := routeConfig("route-1",
		routeSpec{prefix: "/", cluster: "cluster-new"},
		routeSpec{prefix: "/ghost", cluster: "ghost-cluster"},
	)
	newTable := newTable(map[resourcev3.Type][]cachetypes.Resource{
		resourcev3.ListenerType: oldTable.XdsResources[resourcev3.ListenerType],
		resourcev3.RouteType:    {newRC},
		resourcev3.ClusterType:  {edsCluster("cluster-new", "cluster-new", adsConfigSource())},
		resourcev3.EndpointType: {endpoint("cluster-new", "10.0.0.9", 8080)},
	})

	d := NewXdsResourceGraphDiff()
	forward := d.Diff(oldTable, newTable)
	reverse := d.Diff(newTable, oldTable)

	forwardAdded := ids(forward.Added)
	reverseRemoved := ids(reverse.Removed)
	require.ElementsMatch(t, forwardAdded, reverseRemoved, "swapping inputs must turn added into removed")

	forwardRemoved := ids(forward.Removed)
	reverseAdded := ids(reverse.Added)
	require.ElementsMatch(t, forwardRemoved, reverseAdded, "swapping inputs must turn removed into added")

	require.ElementsMatch(t, ids(forward.Modified), ids(reverse.Modified), "modified identities stay modified under swap")

	// Edge-level changes flip direction and keep their dependency reason side.
	var forwardAddedEdges, reverseRemovedEdges []Edge
	for _, c := range forward.ReferenceChanges {
		if c.Kind == ReferenceAdded {
			forwardAddedEdges = append(forwardAddedEdges, c.Edge)
			require.Equal(t, SideNew, c.Side)
		}
	}
	for _, c := range reverse.ReferenceChanges {
		if c.Kind == ReferenceRemoved {
			reverseRemovedEdges = append(reverseRemovedEdges, c.Edge)
			require.Equal(t, SideOld, c.Side)
		}
	}
	require.Equal(t, edgeKeys(forwardAddedEdges), edgeKeys(reverseRemovedEdges))

	// The fresh dangling reference is NewDangling in the forward diff. After the
	// swap it is an old-side pre-existing dangling reference because its target
	// exists on neither side.
	var forwardDanglingClass, reverseDanglingClass DanglingClass
	for _, d := range forward.DanglingReferences {
		if d.Edge.To.Name == "ghost-cluster" {
			forwardDanglingClass = d.Class
		}
	}
	for _, d := range reverse.DanglingReferences {
		if d.Edge.To.Name == "ghost-cluster" {
			reverseDanglingClass = d.Class
		}
	}
	require.Equal(t, DanglingNew, forwardDanglingClass)
	require.Equal(t, DanglingPreExisting, reverseDanglingClass)
}

func TestDiffUnknownFieldsPreservedOrMarkedIncomparable(t *testing.T) {
	base := func() *clusterv3.Cluster {
		return edsCluster("cluster-1", "cluster-1", adsConfigSource())
	}
	withUnknown := func(value string) *clusterv3.Cluster {
		raw, err := proto.Marshal(base())
		require.NoError(t, err)
		raw = protowire.AppendTag(raw, 9999, protowire.BytesType)
		raw = protowire.AppendString(raw, value)
		out := &clusterv3.Cluster{}
		require.NoError(t, proto.Unmarshal(raw, out))
		return out
	}

	// Identical unknown bytes are preserved per the wire protocol: equal.
	stable := DiffResourceGraphs(
		newTable(map[resourcev3.Type][]cachetypes.Resource{resourcev3.ClusterType: {withUnknown("same-unknown")}}),
		newTable(map[resourcev3.Type][]cachetypes.Resource{resourcev3.ClusterType: {withUnknown("same-unknown")}}),
	)
	require.Empty(t, stable.Modified)
	require.Equal(t, 1, stable.Counts.Unchanged)

	// Different unknown bytes: modification reported and marked incomparable.
	report := DiffResourceGraphs(
		newTable(map[resourcev3.Type][]cachetypes.Resource{resourcev3.ClusterType: {withUnknown("unknown-a")}}),
		newTable(map[resourcev3.Type][]cachetypes.Resource{resourcev3.ClusterType: {withUnknown("unknown-b")}}),
	)
	require.Len(t, report.Modified, 1)
	change := report.Modified[0]
	require.True(t, change.UnknownFields)
	require.True(t, change.Incomparable)
	require.NotEmpty(t, change.IncomparableReason)
}

func TestCycleProtectionAndTraversalBudget(t *testing.T) {
	// Hand-built cyclic graph: listener -> route -> cluster -> route ...
	g := newResourceGraph(SideNew, DefaultGraphBudget(), DefaultOutputLimits().MaxWarnings)
	listenerID := ResourceID{TypeURL: resourcev3.ListenerType, Name: "l"}
	routeID := ResourceID{TypeURL: resourcev3.RouteType, Name: "r"}
	clusterID := ResourceID{TypeURL: resourcev3.ClusterType, Name: "c"}
	for _, id := range []ResourceID{listenerID, routeID, clusterID} {
		g.nodes[id] = &resourceNode{id: id}
	}
	g.nodeOrder = []ResourceID{listenerID, routeID, clusterID}
	g.listenerIDs = []ResourceID{listenerID}
	g.addEdge(listenerID, resourcev3.RouteType, "r", "rds", ReferenceInternal, "")
	g.addEdge(routeID, resourcev3.ClusterType, "c", "cluster", ReferenceInternal, "")
	g.addEdge(clusterID, resourcev3.RouteType, "r", "synthetic-cycle", ReferenceInternal, "")
	g.buildAdjacency()

	// BFS terminates despite the cycle and returns the shortest acyclic path.
	path, reached, visits, limitHit := g.bfs(listenerID, clusterID, DefaultGraphBudget().MaxPathLength, DefaultGraphBudget().MaxTraversalVisits)
	require.True(t, reached)
	require.False(t, limitHit)
	require.Equal(t, []ResourceID{listenerID, routeID, clusterID}, path)
	require.LessOrEqual(t, visits, 3, "each node is visited at most once")

	// A one-visit budget must surface an explicit limit hit.
	_, _, _, limitHit = g.bfs(listenerID, clusterID, DefaultGraphBudget().MaxPathLength, 1)
	require.True(t, limitHit)

	// The depth cap prevents paths longer than MaxPathLength.
	_, reachedDeep, _, _ := g.bfs(listenerID, ResourceID{TypeURL: resourcev3.EndpointType, Name: "never"}, 1, 10)
	require.False(t, reachedDeep)
}

func TestGraphBudgetTruncationIsSignaled(t *testing.T) {
	d := NewXdsResourceGraphDiff()
	d.Budget.MaxResources = 1
	table := fullChainTable(t, "listener-1", "route-1", "cluster-1", "10.0.0.1")
	report := d.Diff(newTable(nil), table)
	require.True(t, report.Truncated, "hitting the resource budget must be surfaced explicitly")
	require.NotEmpty(t, report.Warnings)
}

func TestInputTablesAreNotMutated(t *testing.T) {
	oldTable := fullChainTable(t, "listener-1", "route-1", "cluster-1", "10.0.0.1")
	newTable := fullChainTable(t, "listener-1", "route-1", "cluster-1", "10.0.0.2")
	oldSnapshot := proto.Clone(oldTable.XdsResources[resourcev3.EndpointType][0])
	_ = DiffResourceGraphs(oldTable, newTable)
	require.True(t, proto.Equal(oldSnapshot, oldTable.XdsResources[resourcev3.EndpointType][0]),
		"the diff must not mutate its inputs")
}

func TestDiffRouteReferenceExtractionVariants(t *testing.T) {
	// One route config exercising weighted clusters, mirror policies and a
	// dynamic cluster header: only concrete cluster names become edges.
	rc := &routev3.RouteConfiguration{
		Name: "rc",
		VirtualHosts: []*routev3.VirtualHost{{
			Name:    "vh",
			Domains: []string{"*"},
			Routes: []*routev3.Route{
				{
					Match: &routev3.RouteMatch{PathSpecifier: &routev3.RouteMatch_Prefix{Prefix: "/weighted"}},
					Action: &routev3.Route_Route{Route: &routev3.RouteAction{
						ClusterSpecifier: &routev3.RouteAction_WeightedClusters{WeightedClusters: &routev3.WeightedCluster{
							Clusters: []*routev3.WeightedCluster_ClusterWeight{
								{Name: "wc-a", Weight: wrapperspb.UInt32(70)},
								{Name: "wc-b", Weight: wrapperspb.UInt32(30)},
							},
						}},
						RequestMirrorPolicies: []*routev3.RouteAction_RequestMirrorPolicy{
							{Cluster: "mirror-cluster"},
						},
					}},
				},
				{
					Match: &routev3.RouteMatch{PathSpecifier: &routev3.RouteMatch_Prefix{Prefix: "/dynamic"}},
					Action: &routev3.Route_Route{Route: &routev3.RouteAction{
						// Header-selected cluster names are resolved at request time
						// and must not produce a concrete resource edge.
						ClusterSpecifier: &routev3.RouteAction_ClusterHeader{ClusterHeader: "x-cluster"},
					}},
				},
			},
		}},
	}
	// A present cluster resolves one of the weighted references; the other two
	// concrete names are intentionally missing to prove dangling detection.
	table := newTable(map[resourcev3.Type][]cachetypes.Resource{
		resourcev3.RouteType:   {rc},
		resourcev3.ClusterType: {&clusterv3.Cluster{Name: "wc-a"}},
	})

	d := NewXdsResourceGraphDiff()
	graph := d.buildGraph(table, SideNew)
	routeID := ResourceID{TypeURL: resourcev3.RouteType, Name: "rc"}

	targets := map[string]bool{}
	for _, e := range graph.edges {
		if idEqual(e.From, routeID) && e.To.TypeURL == resourcev3.ClusterType {
			targets[e.To.Name] = true
		}
	}
	require.True(t, targets["wc-a"])
	require.True(t, targets["wc-b"])
	require.True(t, targets["mirror-cluster"])
	require.False(t, targets["x-cluster"], "dynamic header cluster selection is not a concrete xDS reference")

	report := d.Diff(newTable(nil), table)
	danglingNames := map[string]bool{}
	for _, dangling := range report.DanglingReferences {
		danglingNames[dangling.Edge.To.Name] = true
	}
	require.True(t, danglingNames["wc-b"])
	require.True(t, danglingNames["mirror-cluster"])
	require.False(t, danglingNames["wc-a"], "an existing cluster must not be dangling")
}

// ---------------------------------------------------------------------------
// Small assertion helpers
// ---------------------------------------------------------------------------

func ids(changes []ResourceChange) []ResourceID {
	out := make([]ResourceID, 0, len(changes))
	for _, c := range changes {
		out = append(out, c.ID)
	}
	return out
}

func edgeKeys(edges []Edge) []edgeKey {
	out := make([]edgeKey, 0, len(edges))
	for _, e := range edges {
		out = append(out, edgeKey{
			fromType: e.From.TypeURL, fromName: e.From.Name,
			toType: e.To.TypeURL, toName: e.To.Name,
			kind: e.Kind,
		})
	}
	return out
}
