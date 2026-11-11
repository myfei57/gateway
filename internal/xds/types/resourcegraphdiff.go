// Copyright Envoy Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package types

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

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
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/dynamicpb"
	"google.golang.org/protobuf/types/known/anypb"
)

// StructuralOnlyStatement is attached to every GraphDiffReport. A graph diff only
// describes structural differences between two translated xDS resource tables. It
// must never be interpreted as a proof that two arbitrary Envoy configurations are
// semantically equivalent, or as a claim that a reported change carries no traffic
// impact risk.
const StructuralOnlyStatement = "structural xDS resource graph diff only: does not establish semantic equivalence of arbitrary Envoy configurations or absence of traffic-impact risk"

// DiffSide identifies which of the two independently translated input tables a
// graph-level finding belongs to.
type DiffSide string

const (
	SideOld DiffSide = "Old"
	SideNew DiffSide = "New"
)

// ResourceChangeKind is the direct, node-level change classification.
type ResourceChangeKind string

const (
	ChangeAdded    ResourceChangeKind = "Added"
	ChangeRemoved  ResourceChangeKind = "Removed"
	ChangeModified ResourceChangeKind = "Modified"
)

// ReferenceChangeKind classifies an edge-level change.
type ReferenceChangeKind string

const (
	ReferenceAdded   ReferenceChangeKind = "ReferenceAdded"
	ReferenceRemoved ReferenceChangeKind = "ReferenceRemoved"
)

// ReferenceKind distinguishes references that must resolve inside the same ADS
// resource table from references explicitly served by an external/dynamic source.
type ReferenceKind string

const (
	// ReferenceInternal points at a resource expected to be present in the same
	// ResourceVersionTable (ADS-delivered). A missing target is a dangling reference.
	ReferenceInternal ReferenceKind = "Internal"
	// ReferenceExternal points at a resource fetched through an explicit non-ADS
	// config source (for example a gRPC SDS server). It is intentionally never
	// reported as a dangling reference, because the target lives outside the table.
	ReferenceExternal ReferenceKind = "External"
)

// DanglingClass explains why an internal reference cannot be resolved within a
// table, relative to the other side of the diff.
type DanglingClass string

const (
	// DanglingNew: the target does not exist on either side, so the reference was
	// newly introduced and already broken.
	DanglingNew DanglingClass = "NewDangling"
	// DanglingRemovedStillReferenced: the target exists on the other side but was
	// removed from this side while references to it remain.
	DanglingRemovedStillReferenced DanglingClass = "RemovedStillReferenced"
	// DanglingResolved: an old-side dangling reference whose target exists on the
	// new side.
	DanglingResolved DanglingClass = "Resolved"
	// DanglingPreExisting: the target is missing on both sides.
	DanglingPreExisting DanglingClass = "PreExisting"
)

// ResourceID is the identity of an xDS resource inside a table: its type URL plus
// its resource name. A version string is deliberately not part of the identity,
// and the diff never compares version strings in place of content.
//
// The same name under different type URLs is a distinct identity (for example an
// EDS ClusterLoadAssignment shares the cluster name with its Cluster).
type ResourceID struct {
	TypeURL string
	Name    string
}

// String renders an identity as "typeURL/name".
func (id ResourceID) String() string {
	return id.TypeURL + "/" + id.Name
}

// Edge is one extracted resource reference. Its identity is the triple
// (From, To, Kind): a reference relationship, independent of where in the
// source resource it appears. Reordering ordered repeated fields (for example
// swapping two routes) therefore changes resource content but never produces
// spurious reference changes.
type Edge struct {
	From ResourceID
	To   ResourceID
	Kind ReferenceKind
	// References pinpoints every stable locator within the source resource where
	// the same relationship appears (for example the two routes of a weighted
	// cluster reference). The slice is deduplicated and sorted.
	References []string
	// ExternalReason is set only when Kind is ReferenceExternal and records the
	// explicit protocol mechanism that makes the reference external.
	ExternalReason string
}

// GraphBudget bounds graph construction and graph traversal explicitly. The
// listener->route->cluster->endpoint/secret closure is normally shallow, but the
// budget guarantees termination and predictable cost on malformed or cyclic input.
type GraphBudget struct {
	// MaxResources is the maximum number of resource nodes accepted per graph.
	MaxResources int
	// MaxEdges is the maximum number of deduplicated reference edges per graph.
	MaxEdges int
	// MaxTraversalVisits bounds how many nodes all impact BFS traversals on one
	// graph may visit in total.
	MaxTraversalVisits int
	// MaxPathLength caps the length of an explanation path.
	MaxPathLength int
}

// DefaultGraphBudget returns the documented default budget.
func DefaultGraphBudget() GraphBudget {
	return GraphBudget{
		MaxResources:       10_000,
		MaxEdges:           50_000,
		MaxTraversalVisits: 10_000,
		MaxPathLength:      32,
	}
}

// OutputLimits bounds the size of the rendered report. Full counts are always
// reported even when the detailed slices are truncated.
type OutputLimits struct {
	MaxChangesPerKind     int
	MaxReferenceChanges   int
	MaxDanglingReferences int
	MaxIdentityConflicts  int
	MaxExternalReferences int
	MaxAffectedListeners  int
	MaxWarnings           int
}

// DefaultOutputLimits returns the documented default output limits.
func DefaultOutputLimits() OutputLimits {
	return OutputLimits{
		MaxChangesPerKind:     500,
		MaxReferenceChanges:   1_000,
		MaxDanglingReferences: 500,
		MaxIdentityConflicts:  100,
		MaxExternalReferences: 500,
		MaxAffectedListeners:  100,
		MaxWarnings:           50,
	}
}

// ResourceChange describes one direct node-level change.
//
// The struct never carries resource payloads: for every resource type only a
// SHA-256 digest of canonicalized content is exposed. This is what allows secret
// changes to be detected without leaking key or certificate material.
type ResourceChange struct {
	ID   ResourceID
	Kind ResourceChangeKind
	// OldDigest and NewDigest are hex SHA-256 digests of the canonicalized
	// resource bytes. The missing side is the empty string.
	OldDigest string
	NewDigest string
	// Secret is true for envoy...tls.v3.Secret resources. When true, the digest
	// pair is the entire content information emitted by the diff.
	Secret bool
	// UnknownFields is true when at least one side carries unknown protobuf
	// fields.
	UnknownFields bool
	// Incomparable is true when unknown fields prevent the change from being
	// attributed solely to known fields. The modification is still reported
	// (content bytes differ), but consumers must not treat it as a fully
	// normalized comparison.
	Incomparable bool
	// IncomparableReason explains why Incomparable is set.
	IncomparableReason string
	// ExplainPath is the shortest listener-entry -> ... -> this-resource path on
	// the side where the resource exists. It is nil when no listener reaches the
	// resource (for example an orphaned resource).
	ExplainPath []ResourceID
	// AffectedListeners is the bounded set of listener entries whose reference
	// closure reaches this resource. A shared resource is stored as a single node
	// and reports every listener that reaches it through this set.
	AffectedListeners []ResourceID
}

// ReferenceChange describes one edge-level change.
type ReferenceChange struct {
	Kind ReferenceChangeKind
	// Side is the graph on which the edge exists: SideNew for an added edge,
	// SideOld for a removed edge.
	Side DiffSide
	Edge Edge
	// ExplainPath is the shortest listener-entry -> ... -> edge-source path on
	// Side; the Edge itself records the final hop.
	ExplainPath []ResourceID
	// AffectedListeners is the bounded set of listener entries reaching the edge
	// source on Side.
	AffectedListeners []ResourceID
}

// DanglingReference reports an internal reference whose target is absent from the
// table that contains the reference.
type DanglingReference struct {
	Side   DiffSide
	Class  DanglingClass
	Edge   Edge
	Reason string
	// ExplainPath is the shortest listener-entry -> ... -> referencing-resource
	// path on Side; the Edge records the unresolved final hop.
	ExplainPath []ResourceID
	// AffectedListeners is the bounded set of listener entries whose closure
	// contains the dangling reference.
	AffectedListeners []ResourceID
}

// IdentityConflict reports the same type URL + name appearing more than once in a
// single table. The first occurrence wins as the graph node; every extra
// occurrence is counted here.
type IdentityConflict struct {
	Side        DiffSide
	ID          ResourceID
	Occurrences int
}

// ExternalReference summarizes a reference that is explicitly resolved outside
// the table. It is informational and is never a dangling reference.
type ExternalReference struct {
	Side DiffSide
	Edge Edge
}

// TypeCount holds per-type resource counts on both input sides.
type TypeCount struct {
	Old int
	New int
}

// DiffCounts carries the full, pre-truncation numbers behind a report.
type DiffCounts struct {
	ResourcesByType  map[string]TypeCount
	Added            int
	Removed          int
	Modified         int
	Unchanged        int
	ReferenceAdded   int
	ReferenceRemoved int
	Dangling         map[DanglingClass]int
	// ConflictCount and ExternalCount are the totals across both sides.
	ConflictCount int
	ExternalCount int
}

// GraphDiffReport is the bounded, read-only result of a graph diff.
type GraphDiffReport struct {
	Added    []ResourceChange
	Removed  []ResourceChange
	Modified []ResourceChange

	ReferenceChanges   []ReferenceChange
	DanglingReferences []DanglingReference
	IdentityConflicts  []IdentityConflict
	ExternalReferences []ExternalReference

	Counts DiffCounts
	// Truncated is true when at least one budget or output limit was hit.
	Truncated bool
	// Warnings records budget events and skipped malformed inputs.
	Warnings []string

	// StructuralOnlyStatement carries the fixed structural-only disclaimer.
	StructuralOnlyStatement string
}

// XdsResourceGraphDiff compares two independently translated ResourceVersionTables.
//
// It is strictly read-only: it never publishes xDS resources, never mutates the
// input tables and never touches an active snapshot. Input messages are cloned
// before canonicalization. The output describes structural changes only and does
// not claim semantic equivalence of arbitrary Envoy configurations or absence of
// traffic risk (see StructuralOnlyStatement).
type XdsResourceGraphDiff struct {
	Budget GraphBudget
	Limits OutputLimits
}

// NewXdsResourceGraphDiff returns a differ with the default budget and limits.
func NewXdsResourceGraphDiff() *XdsResourceGraphDiff {
	return &XdsResourceGraphDiff{
		Budget: DefaultGraphBudget(),
		Limits: DefaultOutputLimits(),
	}
}

// DiffResourceGraphs diffs two tables with default settings.
func DiffResourceGraphs(oldTable, newTable *ResourceVersionTable) *GraphDiffReport {
	return NewXdsResourceGraphDiff().Diff(oldTable, newTable)
}

func (d *XdsResourceGraphDiff) normalize() {
	defaultBudget := DefaultGraphBudget()
	if d.Budget.MaxResources <= 0 {
		d.Budget.MaxResources = defaultBudget.MaxResources
	}
	if d.Budget.MaxEdges <= 0 {
		d.Budget.MaxEdges = defaultBudget.MaxEdges
	}
	if d.Budget.MaxTraversalVisits <= 0 {
		d.Budget.MaxTraversalVisits = defaultBudget.MaxTraversalVisits
	}
	if d.Budget.MaxPathLength <= 0 {
		d.Budget.MaxPathLength = defaultBudget.MaxPathLength
	}
	defaultLimits := DefaultOutputLimits()
	if d.Limits.MaxChangesPerKind <= 0 {
		d.Limits.MaxChangesPerKind = defaultLimits.MaxChangesPerKind
	}
	if d.Limits.MaxReferenceChanges <= 0 {
		d.Limits.MaxReferenceChanges = defaultLimits.MaxReferenceChanges
	}
	if d.Limits.MaxDanglingReferences <= 0 {
		d.Limits.MaxDanglingReferences = defaultLimits.MaxDanglingReferences
	}
	if d.Limits.MaxIdentityConflicts <= 0 {
		d.Limits.MaxIdentityConflicts = defaultLimits.MaxIdentityConflicts
	}
	if d.Limits.MaxExternalReferences <= 0 {
		d.Limits.MaxExternalReferences = defaultLimits.MaxExternalReferences
	}
	if d.Limits.MaxAffectedListeners <= 0 {
		d.Limits.MaxAffectedListeners = defaultLimits.MaxAffectedListeners
	}
	if d.Limits.MaxWarnings <= 0 {
		d.Limits.MaxWarnings = defaultLimits.MaxWarnings
	}
}

// ---------------------------------------------------------------------------
// Internal graph model
// ---------------------------------------------------------------------------

type resourceNode struct {
	id      ResourceID
	raw     []byte
	digest  string
	secret  bool
	unknown bool
}

type edgeKey struct {
	fromType string
	fromName string
	toType   string
	toName   string
	kind     ReferenceKind
}

type resourceGraph struct {
	side      DiffSide
	nodes     map[ResourceID]*resourceNode
	nodeOrder []ResourceID
	edges     map[edgeKey]Edge
	conflicts []IdentityConflict
	dangling  []Edge
	external  []Edge
	warnings  []string
	truncated bool
	// adjacency is built lazily from internal edges for impact traversals.
	adjacency   map[ResourceID][]Edge
	listenerIDs []ResourceID
	budget      GraphBudget
	maxWarnings int
}

func newResourceGraph(side DiffSide, budget GraphBudget, maxWarnings int) *resourceGraph {
	return &resourceGraph{
		side:        side,
		nodes:       make(map[ResourceID]*resourceNode),
		edges:       make(map[edgeKey]Edge),
		adjacency:   make(map[ResourceID][]Edge),
		budget:      budget,
		maxWarnings: maxWarnings,
	}
}

func (g *resourceGraph) warn(format string, args ...any) {
	if len(g.warnings) >= g.maxWarnings {
		g.truncated = true
		return
	}
	g.warnings = append(g.warnings, fmt.Sprintf(format, args...))
}

// buildGraph indexes a table into identity-keyed nodes and extracts the
// listener -> route -> cluster -> endpoint/secret reference closure. The table
// itself is never modified.
func (d *XdsResourceGraphDiff) buildGraph(table *ResourceVersionTable, side DiffSide) *resourceGraph {
	g := newResourceGraph(side, d.Budget, d.Limits.MaxWarnings)
	if table == nil {
		return g
	}

	// Stable type URL iteration keeps node order independent of map iteration.
	typeURLs := make([]string, 0, len(table.XdsResources))
	for typeURL := range table.XdsResources {
		typeURLs = append(typeURLs, typeURL)
	}
	sort.Strings(typeURLs)

	for _, typeURL := range typeURLs {
		resources := table.XdsResources[typeURL]
		for _, r := range resources {
			if r == nil {
				g.warn("%s: skipped nil resource of type %q", side, typeURL)
				continue
			}
			name := resourceName(typeURL, r)
			if name == "" {
				g.warn("%s: skipped resource of type %q without a name", side, typeURL)
				continue
			}
			id := ResourceID{TypeURL: typeURL, Name: name}

			raw, digest, unknown, err := canonicalFingerprint(r)
			if err != nil {
				g.warn("%s: canonicalization failed for %s: %v", side, id, err)
				continue
			}

			if len(g.nodes) >= d.Budget.MaxResources {
				g.truncated = true
				g.warn("%s: resource budget %d reached, dropping %s", side, d.Budget.MaxResources, id)
				continue
			}

			if _, ok := g.nodes[id]; ok {
				// Same type URL + name twice in one table is an identity conflict.
				// The first occurrence remains the graph node; duplicate payloads are
				// surfaced through the conflict report rather than silently merged.
				g.recordConflict(side, id)
				continue
			}

			node := &resourceNode{
				id:      id,
				raw:     raw,
				digest:  digest,
				secret:  typeURL == resourcev3.SecretType,
				unknown: unknown,
			}
			g.nodes[id] = node
			g.nodeOrder = append(g.nodeOrder, id)
			if typeURL == resourcev3.ListenerType {
				g.listenerIDs = append(g.listenerIDs, id)
			}
			g.extractReferences(id, typeURL, r)
		}
	}

	g.resolveDangling()
	return g
}

// recordConflict bumps the occurrence count for a duplicated identity, or
// registers the first conflict for it.
func (g *resourceGraph) recordConflict(side DiffSide, id ResourceID) {
	for i := range g.conflicts {
		if g.conflicts[i].ID == id {
			g.conflicts[i].Occurrences++
			return
		}
	}
	g.conflicts = append(g.conflicts, IdentityConflict{Side: side, ID: id, Occurrences: 2})
}

// resolveDangling splits internal edges whose target is missing from the table
// into the dangling list. External edges are never dangling.
func (g *resourceGraph) resolveDangling() {
	for _, e := range g.edges {
		if e.Kind == ReferenceExternal {
			continue
		}
		if _, ok := g.nodes[e.To]; !ok {
			g.dangling = append(g.dangling, e)
		}
	}
	sort.Slice(g.dangling, func(i, j int) bool { return edgeLess(g.dangling[i], g.dangling[j]) })
	sort.Slice(g.external, func(i, j int) bool { return edgeLess(g.external[i], g.external[j]) })
}

// addEdge records a deduplicated reference relationship while enforcing the
// edge budget. Multiple locators sharing the same (From, To, Kind) identity are
// accumulated on a single edge.
func (g *resourceGraph) addEdge(from ResourceID, toTypeURL, toName, locator string, kind ReferenceKind, externalReason string) {
	if toName == "" {
		return
	}
	key := edgeKey{
		fromType: from.TypeURL,
		fromName: from.Name,
		toType:   toTypeURL,
		toName:   toName,
		kind:     kind,
	}
	if existing, ok := g.edges[key]; ok {
		for _, ref := range existing.References {
			if ref == locator {
				return
			}
		}
		existing.References = append(existing.References, locator)
		sort.Strings(existing.References)
		g.edges[key] = existing
		return
	}
	if len(g.edges) >= g.budget.MaxEdges {
		g.truncated = true
		return
	}
	e := Edge{
		From:           from,
		To:             ResourceID{TypeURL: toTypeURL, Name: toName},
		Kind:           kind,
		References:     []string{locator},
		ExternalReason: externalReason,
	}
	g.edges[key] = e
	if kind == ReferenceExternal {
		g.external = append(g.external, e)
	}
}

// resourceName returns the xDS resource name for the known Envoy resource types.
// ClusterLoadAssignment is named by its cluster name; every other supported type
// carries an explicit name field.
func resourceName(typeURL string, r cachetypes.Resource) string {
	switch v := r.(type) {
	case *endpointv3.ClusterLoadAssignment:
		return v.GetClusterName()
	case *clusterv3.Cluster:
		return v.GetName()
	case *routev3.RouteConfiguration:
		return v.GetName()
	case *listenerv3.Listener:
		return v.GetName()
	case *tlsv3.Secret:
		return v.GetName()
	default:
		if named, ok := r.(interface{ GetName() string }); ok {
			return named.GetName()
		}
		return ""
	}
}

// ---------------------------------------------------------------------------
// Reference extraction
// ---------------------------------------------------------------------------

func (g *resourceGraph) extractReferences(id ResourceID, typeURL string, r cachetypes.Resource) {
	switch v := r.(type) {
	case *listenerv3.Listener:
		g.addListenerEdges(v, id)
	case *routev3.RouteConfiguration:
		g.addRouteConfigEdges(v, id)
	case *clusterv3.Cluster:
		g.addClusterEdges(v, id)
	case *endpointv3.ClusterLoadAssignment, *tlsv3.Secret:
		// Leaf resources: no outgoing xDS resource references.
	default:
		// Unknown resource types are still indexed and content-compared, but no
		// protocol-specific reference extraction is attempted.
	}
}

func (g *resourceGraph) addListenerEdges(l *listenerv3.Listener, from ResourceID) {
	for i, chain := range l.GetFilterChains() {
		g.addFilterChainEdges(chain, from, fmt.Sprintf("filter_chains[%d]", i))
	}
	if dfc := l.GetDefaultFilterChain(); dfc != nil {
		g.addFilterChainEdges(dfc, from, "default_filter_chain")
	}
}

func (g *resourceGraph) addFilterChainEdges(chain *listenerv3.FilterChain, from ResourceID, chainLocator string) {
	for i, filter := range chain.GetFilters() {
		hcm := unmarshalHCM(filter)
		if hcm == nil {
			continue
		}
		locator := fmt.Sprintf("%s.filters[%d].rds.route_config_name", chainLocator, i)
		if rds := hcm.GetRds(); rds != nil {
			if name := rds.GetRouteConfigName(); name != "" {
				kind, reason := classifyConfigSource(rds.GetConfigSource())
				g.addEdge(from, resourcev3.RouteType, name, locator, kind, reason)
			}
		}
		// An inline RouteConfiguration is embedded payload rather than an xDS
		// reference, so it produces no edge.
	}

	if ts := chain.GetTransportSocket(); ts != nil && ts.GetName() == wellknown.TransportSocketTLS {
		downstream := &tlsv3.DownstreamTlsContext{}
		if err := unmarshalAny(ts.GetTypedConfig(), downstream); err != nil {
			g.warn("%s: failed to unmarshal downstream TLS context on %s: %v", g.side, from, err)
			return
		}
		g.addCommonTlsSecretEdges(downstream.GetCommonTlsContext(), from, chainLocator+".transport_socket.tls")
	}
}

func (g *resourceGraph) addRouteConfigEdges(rc *routev3.RouteConfiguration, from ResourceID) {
	for i, vh := range rc.GetVirtualHosts() {
		for j, route := range vh.GetRoutes() {
			action := route.GetRoute()
			if action == nil {
				// Redirect, direct response and filter actions have no cluster.
				continue
			}
			baseLocator := fmt.Sprintf("virtual_hosts[%d].routes[%d].route", i, j)
			switch spec := action.GetClusterSpecifier().(type) {
			case *routev3.RouteAction_Cluster:
				g.addEdge(from, resourcev3.ClusterType, spec.Cluster,
					baseLocator+".cluster", ReferenceInternal, "")
			case *routev3.RouteAction_WeightedClusters:
				for k, weight := range spec.WeightedClusters.GetClusters() {
					g.addEdge(from, resourcev3.ClusterType, weight.GetName(),
						fmt.Sprintf("%s.weighted_clusters.cluster_weights[%d]", baseLocator, k),
						ReferenceInternal, "")
				}
			case *routev3.RouteAction_ClusterHeader, *routev3.RouteAction_ClusterSpecifierPlugin,
				*routev3.RouteAction_InlineClusterSpecifierPlugin:
				// The concrete target cluster is chosen dynamically at request time;
				// there is no concrete resource name to resolve within the table.
			}
			for k, mirror := range action.GetRequestMirrorPolicies() {
				g.addEdge(from, resourcev3.ClusterType, mirror.GetCluster(),
					fmt.Sprintf("%s.request_mirror_policies[%d].cluster", baseLocator, k),
					ReferenceInternal, "")
			}
		}
	}
}

func (g *resourceGraph) addClusterEdges(c *clusterv3.Cluster, from ResourceID) {
	// EDS clusters reference a ClusterLoadAssignment resource. STATIC/LOGICAL_DNS
	// and other inline discovery types carry an embedded LoadAssignment and
	// therefore produce no endpoint edge.
	if discovery, ok := c.GetClusterDiscoveryType().(*clusterv3.Cluster_Type); ok && discovery.Type == clusterv3.Cluster_EDS {
		var configSource *corev3.ConfigSource
		name := c.GetName()
		if eds := c.GetEdsClusterConfig(); eds != nil {
			if serviceName := eds.GetServiceName(); serviceName != "" {
				name = serviceName
			}
			configSource = eds.GetEdsConfig()
		}
		kind, reason := classifyConfigSource(configSource)
		g.addEdge(from, resourcev3.EndpointType, name,
			"eds_cluster_config.service_name", kind, reason)
	}

	if ts := c.GetTransportSocket(); ts != nil && ts.GetName() == wellknown.TransportSocketTLS {
		upstream := &tlsv3.UpstreamTlsContext{}
		if err := unmarshalAny(ts.GetTypedConfig(), upstream); err != nil {
			g.warn("%s: failed to unmarshal upstream TLS context on %s: %v", g.side, from, err)
		} else {
			g.addCommonTlsSecretEdges(upstream.GetCommonTlsContext(), from, "transport_socket.tls")
		}
	}
	for i, match := range c.GetTransportSocketMatches() {
		ts := match.GetTransportSocket()
		if ts == nil || ts.GetName() != wellknown.TransportSocketTLS {
			continue
		}
		upstream := &tlsv3.UpstreamTlsContext{}
		if err := unmarshalAny(ts.GetTypedConfig(), upstream); err != nil {
			g.warn("%s: failed to unmarshal upstream TLS context on %s transport_socket_matches[%d]: %v", g.side, from, i, err)
			continue
		}
		g.addCommonTlsSecretEdges(upstream.GetCommonTlsContext(), from,
			fmt.Sprintf("transport_socket_matches[%d].transport_socket.tls", i))
	}
}

// addCommonTlsSecretEdges extracts every SDS secret reference from a
// CommonTlsContext. An ADS config source makes the secret an internal table
// resource; any other config source makes the reference explicitly external.
func (g *resourceGraph) addCommonTlsSecretEdges(ctc *tlsv3.CommonTlsContext, from ResourceID, locator string) {
	if ctc == nil {
		return
	}
	for i, sds := range ctc.GetTlsCertificateSdsSecretConfigs() {
		g.addSdsSecretEdge(sds, from, fmt.Sprintf("%s.tls_certificate_sds_secret_configs[%d]", locator, i))
	}
	switch validation := ctc.GetValidationContextType().(type) {
	case *tlsv3.CommonTlsContext_ValidationContextSdsSecretConfig:
		g.addSdsSecretEdge(validation.ValidationContextSdsSecretConfig, from,
			locator+".validation_context_sds_secret_config")
	case *tlsv3.CommonTlsContext_CombinedValidationContext:
		g.addSdsSecretEdge(validation.CombinedValidationContext.GetValidationContextSdsSecretConfig(),
			from, locator+".combined_validation_context.validation_context_sds_secret_config")
	}
}

func (g *resourceGraph) addSdsSecretEdge(sds *tlsv3.SdsSecretConfig, from ResourceID, locator string) {
	if sds == nil || sds.GetName() == "" {
		return
	}
	kind, reason := classifyConfigSource(sds.GetSdsConfig())
	g.addEdge(from, resourcev3.SecretType, sds.GetName(), locator, kind, reason)
}

// classifyConfigSource maps an xDS ConfigSource to an internal/external reference
// classification. ADS and Self are served within the same xDS stream/table; every
// other explicit mechanism is external and must not trigger dangling reports.
func classifyConfigSource(cs *corev3.ConfigSource) (ReferenceKind, string) {
	if cs == nil {
		return ReferenceInternal, ""
	}
	switch cs.GetConfigSourceSpecifier().(type) {
	case *corev3.ConfigSource_Ads, *corev3.ConfigSource_Self:
		return ReferenceInternal, ""
	case *corev3.ConfigSource_ApiConfigSource:
		return ReferenceExternal, "config_source.api_config_source"
	case *corev3.ConfigSource_Path:
		return ReferenceExternal, "config_source.path"
	case *corev3.ConfigSource_PathConfigSource:
		return ReferenceExternal, "config_source.path_config_source"
	default:
		return ReferenceExternal, "config_source.unspecified"
	}
}

func unmarshalHCM(filter *listenerv3.Filter) *hcmv3.HttpConnectionManager {
	if filter == nil || filter.GetTypedConfig() == nil {
		return nil
	}
	hcm := &hcmv3.HttpConnectionManager{}
	if err := unmarshalAny(filter.GetTypedConfig(), hcm); err != nil {
		return nil
	}
	return hcm
}

func unmarshalAny(a *anypb.Any, out proto.Message) error {
	if a == nil {
		return fmt.Errorf("any is nil")
	}
	return anypb.UnmarshalTo(a, out, proto.UnmarshalOptions{})
}

// ---------------------------------------------------------------------------
// Canonicalization and content comparison
// ---------------------------------------------------------------------------

var deterministicMarshal = proto.MarshalOptions{Deterministic: true}

// canonicalFingerprint returns the canonical wire bytes of a resource, their
// SHA-256 digest and whether unknown protobuf fields are present.
//
// Canonicalization rules:
//   - protobuf map fields are serialized in sorted key order (deterministic
//     marshal), including maps nested inside anypb.Any values, which are
//     unmarshaled, recursively normalized and re-marshaled;
//   - ordered repeated fields (virtual hosts, routes, HTTP filters, network
//     filters ...) keep their declared order, so an order change is a real
//     content change and is never sorted away;
//   - unknown fields are preserved per the protobuf wire protocol and compared
//     as raw bytes; callers additionally receive the unknown flag so resources
//     whose difference involves unknown fields can be marked incomparable.
//
// The input message is cloned first, so canonicalization never mutates the
// input tables.
func canonicalFingerprint(msg proto.Message) (raw []byte, digest string, unknown bool, err error) {
	clone := proto.Clone(msg)
	unknown = messageHasUnknown(clone.ProtoReflect(), map[protoreflect.Message]struct{}{})
	normalizeAnyFields(clone.ProtoReflect(), map[protoreflect.Message]struct{}{})
	raw, err = deterministicMarshal.Marshal(clone)
	if err != nil {
		return nil, "", unknown, err
	}
	sum := sha256.Sum256(raw)
	return raw, hex.EncodeToString(sum[:]), unknown, nil
}

// normalizeAnyFields recursively rewrites every google.protobuf.Any field so its
// embedded value is deterministically marshaled. Top-level deterministic marshal
// already sorts maps, but bytes stored inside an Any would otherwise bypass that
// normalization.
func normalizeAnyFields(md protoreflect.Message, seen map[protoreflect.Message]struct{}) {
	if md == nil {
		return
	}
	if _, ok := seen[md]; ok {
		return
	}
	seen[md] = struct{}{}

	if md.Descriptor().FullName() == "google.protobuf.Any" {
		if inner, err := unmarshalAnyMessage(md); err == nil {
			normalizeAnyFields(inner.ProtoReflect(), seen)
			if bytes, err := deterministicMarshal.Marshal(inner); err == nil {
				valueField := md.Descriptor().Fields().ByName("value")
				md.Set(valueField, protoreflect.ValueOfBytes(bytes))
			}
		}
	}

	md.Range(func(fd protoreflect.FieldDescriptor, value protoreflect.Value) bool {
		switch {
		case fd.IsMap():
			if fd.MapValue().Kind() == protoreflect.MessageKind {
				value.Map().Range(func(_ protoreflect.MapKey, entry protoreflect.Value) bool {
					normalizeAnyFields(entry.Message(), seen)
					return true
				})
			}
		case fd.IsList():
			if fd.Kind() == protoreflect.MessageKind {
				list := value.List()
				for i := 0; i < list.Len(); i++ {
					normalizeAnyFields(list.Get(i).Message(), seen)
				}
			}
		case fd.Kind() == protoreflect.MessageKind:
			normalizeAnyFields(value.Message(), seen)
		}
		return true
	})
}

// messageHasUnknown reports whether the message or any nested message (including
// the payload of an Any) carries unknown protobuf fields.
func messageHasUnknown(md protoreflect.Message, seen map[protoreflect.Message]struct{}) bool {
	if md == nil {
		return false
	}
	if _, ok := seen[md]; ok {
		return false
	}
	seen[md] = struct{}{}

	if len(md.GetUnknown()) > 0 {
		return true
	}
	if md.Descriptor().FullName() == "google.protobuf.Any" {
		if inner, err := unmarshalAnyMessage(md); err == nil && messageHasUnknown(inner.ProtoReflect(), seen) {
			return true
		}
	}
	found := false
	md.Range(func(fd protoreflect.FieldDescriptor, value protoreflect.Value) bool {
		switch {
		case fd.IsMap():
			if fd.MapValue().Kind() == protoreflect.MessageKind {
				value.Map().Range(func(_ protoreflect.MapKey, entry protoreflect.Value) bool {
					if messageHasUnknown(entry.Message(), seen) {
						found = true
						return false
					}
					return true
				})
			}
		case fd.IsList():
			if fd.Kind() == protoreflect.MessageKind {
				list := value.List()
				for i := 0; i < list.Len(); i++ {
					if messageHasUnknown(list.Get(i).Message(), seen) {
						found = true
						break
					}
				}
			}
		case fd.Kind() == protoreflect.MessageKind:
			found = messageHasUnknown(value.Message(), seen)
		}
		return !found
	})
	return found
}

// unmarshalAnyMessage resolves an Any field reached through protoreflect into a
// concrete message when its type is registered, falling back to a dynamic
// message for unknown-but-decodable types.
func unmarshalAnyMessage(md protoreflect.Message) (proto.Message, error) {
	anyMsg, ok := md.Interface().(*anypb.Any)
	if !ok {
		return nil, fmt.Errorf("field is not google.protobuf.Any")
	}
	msg, err := anypb.UnmarshalNew(anyMsg, proto.UnmarshalOptions{})
	if err == nil {
		return msg, nil
	}
	msgType, err := protoregistry.GlobalTypes.FindMessageByName(protoreflect.FullName(anyMsg.MessageName()))
	if err != nil {
		return nil, err
	}
	dynamic := dynamicpb.NewMessage(msgType.Descriptor())
	if err := anypb.UnmarshalTo(anyMsg, dynamic, proto.UnmarshalOptions{}); err != nil {
		return nil, err
	}
	return dynamic, nil
}

// ---------------------------------------------------------------------------
// Impact traversal (cycle-protected, budgeted BFS)
// ---------------------------------------------------------------------------

// buildAdjacency materializes sorted internal-edge adjacency. External edges
// leave the table and are not part of the in-table reference closure.
func (g *resourceGraph) buildAdjacency() {
	for _, e := range g.edges {
		if e.Kind != ReferenceInternal {
			continue
		}
		if _, ok := g.nodes[e.From]; !ok {
			continue
		}
		g.adjacency[e.From] = append(g.adjacency[e.From], e)
	}
	for from := range g.adjacency {
		sort.Slice(g.adjacency[from], func(i, j int) bool { return edgeLess(g.adjacency[from][i], g.adjacency[from][j]) })
	}
	sort.Slice(g.listenerIDs, func(i, j int) bool { return idLess(g.listenerIDs[i], g.listenerIDs[j]) })
}

// impact computes the shortest listener-entry -> target explanation path and the
// bounded set of listener entries whose closure reaches target. Traversal is BFS
// (visited-set cycle protection, explicit depth and visit budgets) over internal
// edges only.
func (g *resourceGraph) impact(target ResourceID, maxListeners, maxPathLength, maxVisits int) (explainPath []ResourceID, listeners []ResourceID, visitLimitHit bool) {
	g.buildAdjacency()
	visits := 0
	for _, entry := range g.listenerIDs {
		if len(listeners) >= maxListeners {
			break
		}
		path, reached, used, limit := g.bfs(entry, target, maxPathLength, maxVisits-visits)
		visits += used
		if limit {
			visitLimitHit = true
		}
		if reached {
			listeners = append(listeners, entry)
			if explainPath == nil || len(path) < len(explainPath) {
				explainPath = path
			}
		}
		if visits >= maxVisits {
			visitLimitHit = true
			break
		}
	}
	return explainPath, listeners, visitLimitHit
}

// bfs runs one bounded breadth-first search from start. The visited set
// guarantees termination even if the extracted graph contains a cycle.
func (g *resourceGraph) bfs(start, target ResourceID, maxPathLength, visitBudget int) (path []ResourceID, reached bool, visits int, limitHit bool) {
	type step struct {
		id   ResourceID
		path []ResourceID
	}
	visited := map[ResourceID]struct{}{start: {}}
	queue := []step{{id: start, path: []ResourceID{start}}}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		visits++
		if visits > visitBudget {
			return nil, false, visits, true
		}
		if current.id == target {
			return current.path, true, visits, false
		}
		if len(current.path) >= maxPathLength {
			continue
		}
		for _, e := range g.adjacency[current.id] {
			if _, ok := visited[e.To]; ok {
				continue
			}
			visited[e.To] = struct{}{}
			nextPath := make([]ResourceID, 0, len(current.path)+1)
			nextPath = append(nextPath, current.path...)
			nextPath = append(nextPath, e.To)
			queue = append(queue, step{id: e.To, path: nextPath})
		}
	}
	return nil, false, visits, false
}

// ---------------------------------------------------------------------------
// Diff assembly
// ---------------------------------------------------------------------------

// Diff computes the structural graph diff between two independently translated
// resource tables. Both arguments are read-only and remain unmodified.
func (d *XdsResourceGraphDiff) Diff(oldTable, newTable *ResourceVersionTable) *GraphDiffReport {
	d.normalize()
	oldGraph := d.buildGraph(oldTable, SideOld)
	newGraph := d.buildGraph(newTable, SideNew)

	report := &GraphDiffReport{
		Counts: DiffCounts{
			ResourcesByType: make(map[string]TypeCount),
			Dangling:        make(map[DanglingClass]int),
		},
		StructuralOnlyStatement: StructuralOnlyStatement,
	}

	d.diffNodes(oldGraph, newGraph, report)
	d.diffEdges(oldGraph, newGraph, report)
	d.diffDangling(oldGraph, newGraph, report)
	d.collectConflictsAndExternal(oldGraph, newGraph, report)
	d.collectWarnings(oldGraph, newGraph, report)
	d.fillCounts(oldGraph, newGraph, report)

	return report
}

func (d *XdsResourceGraphDiff) diffNodes(oldGraph, newGraph *resourceGraph, report *GraphDiffReport) {
	var added, removed, modified []ResourceChange

	for _, id := range newGraph.nodeOrder {
		newNode := newGraph.nodes[id]
		oldNode, ok := oldGraph.nodes[id]
		if !ok {
			added = append(added, ResourceChange{
				ID:            id,
				Kind:          ChangeAdded,
				NewDigest:     newNode.digest,
				Secret:        newNode.secret,
				UnknownFields: newNode.unknown,
			})
			continue
		}
		if string(oldNode.raw) == string(newNode.raw) {
			report.Counts.Unchanged++
			continue
		}
		change := ResourceChange{
			ID:        id,
			Kind:      ChangeModified,
			OldDigest: oldNode.digest,
			NewDigest: newNode.digest,
			Secret:    newNode.secret,
		}
		change.UnknownFields = oldNode.unknown || newNode.unknown
		if change.UnknownFields {
			// Unknown bytes are preserved by canonicalization, so identical bytes
			// still compare equal. Once bytes differ and unknown fields are
			// involved, the difference cannot be attributed solely to known
			// fields and is explicitly marked incomparable.
			change.Incomparable = true
			change.IncomparableReason = "unknown protobuf fields are present on at least one side; the difference cannot be attributed solely to known fields"
		}
		modified = append(modified, change)
	}

	for _, id := range oldGraph.nodeOrder {
		oldNode := oldGraph.nodes[id]
		if _, ok := newGraph.nodes[id]; !ok {
			removed = append(removed, ResourceChange{
				ID:            id,
				Kind:          ChangeRemoved,
				OldDigest:     oldNode.digest,
				Secret:        oldNode.secret,
				UnknownFields: oldNode.unknown,
			})
		}
	}

	sortChanges(added)
	sortChanges(removed)
	sortChanges(modified)
	report.Counts.Added = len(added)
	report.Counts.Removed = len(removed)
	report.Counts.Modified = len(modified)

	report.Added = d.enrichChanges(added, newGraph)
	report.Removed = d.enrichChanges(removed, oldGraph)
	report.Modified = d.enrichChanges(modified, newGraph)
}

// enrichChanges applies the per-kind output limit and attaches shortest
// explanation paths and bounded affected-listener sets.
func (d *XdsResourceGraphDiff) enrichChanges(changes []ResourceChange, g *resourceGraph) []ResourceChange {
	if len(changes) == 0 {
		return changes
	}
	out := changes
	if len(out) > d.Limits.MaxChangesPerKind {
		out = out[:d.Limits.MaxChangesPerKind]
	}
	for i := range out {
		path, listeners, limitHit := g.impact(changes[i].ID,
			d.Limits.MaxAffectedListeners, d.Budget.MaxPathLength, d.Budget.MaxTraversalVisits)
		out[i].ExplainPath = path
		out[i].AffectedListeners = listeners
		if limitHit {
			g.truncated = true
		}
	}
	return out
}

func (d *XdsResourceGraphDiff) diffEdges(oldGraph, newGraph *resourceGraph, report *GraphDiffReport) {
	var changes []ReferenceChange

	for key, newEdge := range newGraph.edges {
		if _, ok := oldGraph.edges[key]; ok {
			continue
		}
		changes = append(changes, ReferenceChange{Kind: ReferenceAdded, Side: SideNew, Edge: newEdge})
		report.Counts.ReferenceAdded++
	}
	for key, oldEdge := range oldGraph.edges {
		if _, ok := newGraph.edges[key]; ok {
			continue
		}
		changes = append(changes, ReferenceChange{Kind: ReferenceRemoved, Side: SideOld, Edge: oldEdge})
		report.Counts.ReferenceRemoved++
	}

	sort.Slice(changes, func(i, j int) bool {
		if changes[i].Kind != changes[j].Kind {
			return changes[i].Kind < changes[j].Kind
		}
		return edgeLess(changes[i].Edge, changes[j].Edge)
	})

	if len(changes) > d.Limits.MaxReferenceChanges {
		changes = changes[:d.Limits.MaxReferenceChanges]
	}
	for i := range changes {
		g := newGraph
		if changes[i].Side == SideOld {
			g = oldGraph
		}
		path, listeners, limitHit := g.impact(changes[i].Edge.From,
			d.Limits.MaxAffectedListeners, d.Budget.MaxPathLength, d.Budget.MaxTraversalVisits)
		changes[i].ExplainPath = path
		changes[i].AffectedListeners = listeners
		if limitHit {
			g.truncated = true
		}
	}
	report.ReferenceChanges = changes
}

func (d *XdsResourceGraphDiff) diffDangling(oldGraph, newGraph *resourceGraph, report *GraphDiffReport) {
	var dangling []DanglingReference

	for _, e := range newGraph.dangling {
		class := DanglingNew
		reason := "reference target is absent from both input tables"
		if _, existed := oldGraph.nodes[e.To]; existed {
			class = DanglingRemovedStillReferenced
			reason = "referenced resource was removed but the reference remains"
		}
		dangling = append(dangling, DanglingReference{Side: SideNew, Class: class, Edge: e, Reason: reason})
		report.Counts.Dangling[class]++
	}
	for _, e := range oldGraph.dangling {
		if _, resolved := newGraph.nodes[e.To]; resolved {
			dangling = append(dangling, DanglingReference{
				Side: SideOld, Class: DanglingResolved, Edge: e,
				Reason: "previously dangling reference target now exists",
			})
			report.Counts.Dangling[DanglingResolved]++
			continue
		}
		// Missing on both sides: only count it once against the new side, unless
		// the edge itself changed. Old-side pre-existing entries stay informational.
		dangling = append(dangling, DanglingReference{
			Side: SideOld, Class: DanglingPreExisting, Edge: e,
			Reason: "reference target is absent from both input tables",
		})
		report.Counts.Dangling[DanglingPreExisting]++
	}

	sort.Slice(dangling, func(i, j int) bool {
		if dangling[i].Side != dangling[j].Side {
			return dangling[i].Side < dangling[j].Side
		}
		if dangling[i].Class != dangling[j].Class {
			return dangling[i].Class < dangling[j].Class
		}
		return edgeLess(dangling[i].Edge, dangling[j].Edge)
	})

	if len(dangling) > d.Limits.MaxDanglingReferences {
		dangling = dangling[:d.Limits.MaxDanglingReferences]
	}
	for i := range dangling {
		g := newGraph
		if dangling[i].Side == SideOld {
			g = oldGraph
		}
		path, listeners, limitHit := g.impact(dangling[i].Edge.From,
			d.Limits.MaxAffectedListeners, d.Budget.MaxPathLength, d.Budget.MaxTraversalVisits)
		dangling[i].ExplainPath = path
		dangling[i].AffectedListeners = listeners
		if limitHit {
			g.truncated = true
		}
	}
	report.DanglingReferences = dangling
}

func (d *XdsResourceGraphDiff) collectConflictsAndExternal(oldGraph, newGraph *resourceGraph, report *GraphDiffReport) {
	conflicts := make([]IdentityConflict, 0, len(oldGraph.conflicts)+len(newGraph.conflicts))
	conflicts = append(conflicts, oldGraph.conflicts...)
	conflicts = append(conflicts, newGraph.conflicts...)
	sort.Slice(conflicts, func(i, j int) bool {
		if conflicts[i].Side != conflicts[j].Side {
			return conflicts[i].Side < conflicts[j].Side
		}
		return idLess(conflicts[i].ID, conflicts[j].ID)
	})
	report.Counts.ConflictCount = len(conflicts)
	if len(conflicts) > d.Limits.MaxIdentityConflicts {
		conflicts = conflicts[:d.Limits.MaxIdentityConflicts]
	}
	report.IdentityConflicts = conflicts

	var external []ExternalReference
	for _, e := range oldGraph.external {
		external = append(external, ExternalReference{Side: SideOld, Edge: e})
	}
	for _, e := range newGraph.external {
		external = append(external, ExternalReference{Side: SideNew, Edge: e})
	}
	sort.Slice(external, func(i, j int) bool {
		if external[i].Side != external[j].Side {
			return external[i].Side < external[j].Side
		}
		return edgeLess(external[i].Edge, external[j].Edge)
	})
	report.Counts.ExternalCount = len(external)
	if len(external) > d.Limits.MaxExternalReferences {
		external = external[:d.Limits.MaxExternalReferences]
	}
	report.ExternalReferences = external
}

func (d *XdsResourceGraphDiff) collectWarnings(oldGraph, newGraph *resourceGraph, report *GraphDiffReport) {
	report.Truncated = oldGraph.truncated || newGraph.truncated
	warnings := make([]string, 0, len(oldGraph.warnings)+len(newGraph.warnings))
	warnings = append(warnings, oldGraph.warnings...)
	warnings = append(warnings, newGraph.warnings...)
	if len(warnings) > d.Limits.MaxWarnings {
		warnings = warnings[:d.Limits.MaxWarnings]
		report.Truncated = true
	}
	report.Warnings = warnings
}

func (d *XdsResourceGraphDiff) fillCounts(oldGraph, newGraph *resourceGraph, report *GraphDiffReport) {
	for id := range oldGraph.nodes {
		count := report.Counts.ResourcesByType[id.TypeURL]
		count.Old++
		report.Counts.ResourcesByType[id.TypeURL] = count
	}
	for id := range newGraph.nodes {
		count := report.Counts.ResourcesByType[id.TypeURL]
		count.New++
		report.Counts.ResourcesByType[id.TypeURL] = count
	}
}

// ---------------------------------------------------------------------------
// Sorting helpers (deterministic reports)
// ---------------------------------------------------------------------------

func idLess(a, b ResourceID) bool {
	if a.TypeURL != b.TypeURL {
		return a.TypeURL < b.TypeURL
	}
	return a.Name < b.Name
}

func edgeLess(a, b Edge) bool {
	if !idEqual(a.From, b.From) {
		return idLess(a.From, b.From)
	}
	if !idEqual(a.To, b.To) {
		return idLess(a.To, b.To)
	}
	if a.Kind != b.Kind {
		return a.Kind < b.Kind
	}
	return strings.Join(a.References, ",") < strings.Join(b.References, ",")
}

func idEqual(a, b ResourceID) bool {
	return a.TypeURL == b.TypeURL && a.Name == b.Name
}

func sortChanges(changes []ResourceChange) {
	sort.Slice(changes, func(i, j int) bool { return idLess(changes[i].ID, changes[j].ID) })
}
