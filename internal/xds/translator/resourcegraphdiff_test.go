// Copyright Envoy Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package translator

import (
	"fmt"
	"slices"
	"testing"

	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	cachetypes "github.com/envoyproxy/go-control-plane/pkg/cache/types"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"k8s.io/utils/ptr"

	"github.com/envoyproxy/gateway/internal/ir"
	xtypes "github.com/envoyproxy/gateway/internal/xds/types"
)

// These integration tests exercise XdsResourceGraphDiff against two
// independently translated, real protobuf resource graphs produced by the
// production xDS translator (rather than hand-built fixtures).

func translateIR(t *testing.T, x *ir.Xds) *xtypes.ResourceVersionTable {
	t.Helper()
	table, err := (&Translator{}).Translate(t.Context(), x)
	require.NoError(t, err)
	require.NotNil(t, table)
	return table
}

func loadGraphIR(t *testing.T, name string) *ir.Xds {
	t.Helper()
	return requireXdsIRFromInputTestData(t, name)
}

func changeIDs(changes []xtypes.ResourceChange) []xtypes.ResourceID {
	out := make([]xtypes.ResourceID, 0, len(changes))
	for _, c := range changes {
		out = append(out, c.ID)
	}
	return out
}

// cloneTable deep-copies every resource so tests can mutate the copy without
// touching the original translated table.
func cloneTable(t *testing.T, table *xtypes.ResourceVersionTable) *xtypes.ResourceVersionTable {
	t.Helper()
	clone := &xtypes.ResourceVersionTable{XdsResources: xtypes.XdsResources{}}
	for typeURL, resources := range table.XdsResources {
		for _, r := range resources {
			clone.XdsResources[typeURL] = append(clone.XdsResources[typeURL], proto.Clone(r).(cachetypes.Resource))
		}
	}
	return clone
}

func TestResourceGraphDiffRealTranslatorDeterministic(t *testing.T) {
	// Two independent translations of the same fixed input must be structurally
	// identical, regardless of Go map iteration order during translation.
	x := loadGraphIR(t, "testdata/in/xds-ir/http-route.yaml")
	first := translateIR(t, x.DeepCopy())
	second := translateIR(t, x.DeepCopy())

	report := xtypes.DiffResourceGraphs(first, second)
	require.Empty(t, report.Added)
	require.Empty(t, report.Removed)
	require.Empty(t, report.Modified)
	require.Empty(t, report.DanglingReferences)
	require.NotEmpty(t, report.StructuralOnlyStatement)
}

func TestResourceGraphDiffRealTranslatorEndpointChangeAndSwap(t *testing.T) {
	x := loadGraphIR(t, "testdata/in/xds-ir/http-route.yaml")
	oldTable := translateIR(t, x.DeepCopy())

	newIR := x.DeepCopy()
	newIR.HTTP[0].Routes[0].Destination.Settings[0].Endpoints[0].Host = "1.2.3.9"
	newTable := translateIR(t, newIR)

	forward := xtypes.DiffResourceGraphs(oldTable, newTable)
	require.Empty(t, forward.Added)
	require.Empty(t, forward.Removed)
	require.Len(t, forward.Modified, 1, "only the endpoint ClusterLoadAssignment changes")
	modified := forward.Modified[0]
	require.Equal(t, resourcev3.EndpointType, modified.ID.TypeURL)
	require.NotEmpty(t, modified.ExplainPath, "the changed endpoint carries an entry path")
	require.Equal(t, resourcev3.ListenerType, modified.ExplainPath[0].TypeURL)
	require.Equal(t, resourcev3.EndpointType, modified.ExplainPath[len(modified.ExplainPath)-1].TypeURL)
	require.Len(t, modified.AffectedListeners, 1)
	require.Empty(t, forward.DanglingReferences)

	// Swapping the inputs must not turn a content modification into an add/remove.
	reverse := xtypes.DiffResourceGraphs(newTable, oldTable)
	require.Empty(t, reverse.Added)
	require.Empty(t, reverse.Removed)
	require.Equal(t, changeIDs(forward.Modified), changeIDs(reverse.Modified))
	require.Equal(t, modified.NewDigest, reverse.Modified[0].OldDigest, "digest direction must follow the input direction")
}

func TestResourceGraphDiffRealTranslatorRouteReorder(t *testing.T) {
	x := loadGraphIR(t, "testdata/in/xds-ir/http-route-multiple-matches.yaml")
	oldTable := translateIR(t, x.DeepCopy())

	newIR := x.DeepCopy()
	// Swap two routes that target different clusters: ordered repeated fields
	// must remain order-sensitive.
	routes := newIR.HTTP[0].Routes
	routes[0], routes[1] = routes[1], routes[0]
	newTable := translateIR(t, newIR)

	report := xtypes.DiffResourceGraphs(oldTable, newTable)
	// The route configuration content changes; every cluster and endpoint stays
	// identical and the reference closure is unchanged.
	var routeModified bool
	for _, change := range report.Modified {
		if change.ID.TypeURL == resourcev3.RouteType {
			routeModified = true
		}
		require.NotEqual(t, resourcev3.ClusterType, change.ID.TypeURL)
		require.NotEqual(t, resourcev3.EndpointType, change.ID.TypeURL)
	}
	require.True(t, routeModified)
	require.Empty(t, report.Added)
	require.Empty(t, report.Removed)
	require.Empty(t, report.ReferenceChanges, "reordering routes must not change the reference relationships")
	require.Empty(t, report.DanglingReferences)
}

func TestResourceGraphDiffRealTranslatorSharedCluster(t *testing.T) {
	x := loadGraphIR(t, "testdata/in/xds-ir/http-route.yaml")
	sharedName := x.HTTP[0].Routes[0].Destination.Name

	newIR := x.DeepCopy()
	extraRoute := newIR.HTTP[0].Routes[0].DeepCopy()
	extraRoute.Name = "extra-route"
	extraRoute.PathMatch = &ir.StringMatch{Prefix: ptr.To("/extra")}
	newIR.HTTP[0].Routes = append(newIR.HTTP[0].Routes, extraRoute)

	oldTable := translateIR(t, x.DeepCopy())
	newTable := translateIR(t, newIR)
	report := xtypes.DiffResourceGraphs(oldTable, newTable)

	// The shared destination still produces a single cluster node; the extra
	// route only modifies the route configuration.
	require.Equal(t, 1, report.Counts.ResourcesByType[resourcev3.ClusterType].New)
	for _, change := range report.Modified {
		require.NotEqual(t, resourcev3.ClusterType, change.ID.TypeURL, "shared cluster content is untouched")
	}
	require.Empty(t, report.Added, "no new cluster is created for the shared destination")
	require.Empty(t, report.DanglingReferences)
	require.NotEmpty(t, sharedName)
}

func TestResourceGraphDiffRealTranslatorSecretRotation(t *testing.T) {
	x := loadGraphIR(t, "testdata/in/xds-ir/simple-tls.yaml")
	oldTable := translateIR(t, x.DeepCopy())

	newIR := x.DeepCopy()
	newIR.HTTP[0].TLS.Certificates[0].PrivateKey = ir.PrivateBytes([]byte("rotated-private-key-material"))
	newTable := translateIR(t, newIR)

	report := xtypes.DiffResourceGraphs(oldTable, newTable)
	var secretChanges []xtypes.ResourceChange
	for _, change := range report.Modified {
		if change.ID.TypeURL == resourcev3.SecretType {
			secretChanges = append(secretChanges, change)
		}
	}
	require.NotEmpty(t, secretChanges, "secret rotation must be detected from content, not version strings")
	for _, change := range secretChanges {
		require.True(t, change.Secret)
		require.NotEqual(t, change.OldDigest, change.NewDigest)
		require.NotEmpty(t, change.NewDigest)
	}
	// Secret material must never be rendered into the report.
	require.NotContains(t, fmt.Sprintf("%+v", report), "rotated-private-key-material")

	reverse := xtypes.DiffResourceGraphs(newTable, oldTable)
	require.ElementsMatch(t, changeIDs(report.Modified), changeIDs(reverse.Modified))
}

func TestResourceGraphDiffRealTranslatorDanglingReference(t *testing.T) {
	x := loadGraphIR(t, "testdata/in/xds-ir/http-route.yaml")
	oldTable := translateIR(t, x)
	newTable := cloneTable(t, oldTable)

	// Repoint the translated route at a cluster that does not exist in the table.
	const ghostCluster = "ghost-cluster-does-not-exist"
	routes := newTable.XdsResources[resourcev3.RouteType]
	require.NotEmpty(t, routes)
	rc := routes[0].(*routev3.RouteConfiguration)
	action := rc.VirtualHosts[0].Routes[0].GetRoute()
	action.ClusterSpecifier = &routev3.RouteAction_Cluster{Cluster: ghostCluster}

	report := xtypes.DiffResourceGraphs(oldTable, newTable)
	var dangling *xtypes.DanglingReference
	for i := range report.DanglingReferences {
		if report.DanglingReferences[i].Edge.To.Name == ghostCluster {
			dangling = &report.DanglingReferences[i]
			break
		}
	}
	require.NotNil(t, dangling, "a reference to a missing cluster must be reported as dangling")
	require.Equal(t, xtypes.DanglingNew, dangling.Class)
	require.Equal(t, xtypes.ReferenceInternal, dangling.Edge.Kind)
	require.NotEmpty(t, dangling.ExplainPath)
	require.Equal(t, resourcev3.ListenerType, dangling.ExplainPath[0].TypeURL)

	// The edge-level changes explain the dependency direction explicitly.
	var addedGhost, removedReal bool
	for _, change := range report.ReferenceChanges {
		if change.Kind == xtypes.ReferenceAdded && change.Edge.To.Name == ghostCluster {
			addedGhost = true
			require.Equal(t, xtypes.SideNew, change.Side)
		}
		if change.Kind == xtypes.ReferenceRemoved {
			removedReal = true
			require.Equal(t, xtypes.SideOld, change.Side)
		}
	}
	require.True(t, addedGhost && removedReal)

	// After swapping inputs the dangling classification flips to the old side.
	reverse := xtypes.DiffResourceGraphs(newTable, oldTable)
	var reverseDangling *xtypes.DanglingReference
	for i := range reverse.DanglingReferences {
		if reverse.DanglingReferences[i].Edge.To.Name == ghostCluster {
			reverseDangling = &reverse.DanglingReferences[i]
			break
		}
	}
	require.NotNil(t, reverseDangling)
	require.Equal(t, xtypes.SideOld, reverseDangling.Side)
}

func TestResourceGraphDiffRealTranslatorExternalSDSNotDangling(t *testing.T) {
	// sds.yaml configures upstream TLS through an explicit gRPC SDS server
	// (unix socket), so the secret names are external references, not table
	// resources, and must not produce dangling references.
	x := loadGraphIR(t, "testdata/in/xds-ir/sds.yaml")
	table := translateIR(t, x)

	report := xtypes.DiffResourceGraphs(&xtypes.ResourceVersionTable{}, table)
	require.Empty(t, report.DanglingReferences, "external SDS references must not be flagged as dangling")
	require.NotEmpty(t, report.ExternalReferences)
	for _, external := range report.ExternalReferences {
		require.Equal(t, xtypes.ReferenceExternal, external.Edge.Kind)
		require.NotEmpty(t, external.Edge.ExternalReason)
		require.Equal(t, resourcev3.SecretType, external.Edge.To.TypeURL)
	}
}

func TestResourceGraphDiffRealTranslatorAddedRemovedSwap(t *testing.T) {
	x := loadGraphIR(t, "testdata/in/xds-ir/http-route.yaml")
	oldTable := translateIR(t, x.DeepCopy())

	newIR := x.DeepCopy()
	addedRoute := newIR.HTTP[0].Routes[0].DeepCopy()
	addedRoute.Name = "added-route"
	addedRoute.PathMatch = &ir.StringMatch{Prefix: ptr.To("/added")}
	addedRoute.Destination = &ir.RouteDestination{
		Name: "brand-new-destination",
		Settings: []*ir.DestinationSetting{{
			Name:      "brand-new-destination/backend/0",
			Endpoints: []*ir.DestinationEndpoint{{Host: "192.0.2.10", Port: 8080}},
		}},
	}
	newIR.HTTP[0].Routes = append(newIR.HTTP[0].Routes, addedRoute)
	newTable := translateIR(t, newIR)

	forward := xtypes.DiffResourceGraphs(oldTable, newTable)
	reverse := xtypes.DiffResourceGraphs(newTable, oldTable)

	// Every forward Added identity is a reverse Removed identity and vice versa.
	require.ElementsMatch(t, changeIDs(forward.Added), changeIDs(reverse.Removed))
	require.ElementsMatch(t, changeIDs(forward.Removed), changeIDs(reverse.Added))
	require.Empty(t, forward.Removed)
	require.Empty(t, reverse.Added)

	// The new cluster and endpoint are among the forward additions.
	addedNames := map[xtypes.ResourceID]bool{}
	for _, id := range changeIDs(forward.Added) {
		addedNames[id] = true
	}
	require.True(t, addedNames[xtypes.ResourceID{TypeURL: resourcev3.ClusterType, Name: "brand-new-destination"}])
	require.True(t, addedNames[xtypes.ResourceID{TypeURL: resourcev3.EndpointType, Name: "brand-new-destination"}])

	// Reference change directions and side annotations flip consistently.
	var forwardAddedEdges, reverseRemovedEdges []xtypes.Edge
	for _, c := range forward.ReferenceChanges {
		if c.Kind == xtypes.ReferenceAdded {
			forwardAddedEdges = append(forwardAddedEdges, c.Edge)
		}
	}
	for _, c := range reverse.ReferenceChanges {
		if c.Kind == xtypes.ReferenceRemoved {
			reverseRemovedEdges = append(reverseRemovedEdges, c.Edge)
		}
	}
	require.Equal(t, len(forwardAddedEdges), len(reverseRemovedEdges))
	require.Positive(t, len(forwardAddedEdges))
	for _, e := range forwardAddedEdges {
		require.True(t, slices.ContainsFunc(reverseRemovedEdges, func(re xtypes.Edge) bool {
			return re.From.String() == e.From.String() && re.To.String() == e.To.String() && re.Kind == e.Kind
		}))
	}
}
