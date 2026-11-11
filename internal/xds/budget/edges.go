// Copyright Envoy Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package budget

import (
	"errors"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	hcmv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	cachetypes "github.com/envoyproxy/go-control-plane/pkg/cache/types"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"github.com/envoyproxy/go-control-plane/pkg/wellknown"
	protobuf "google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

var errNilAny = errors.New("nil typed config")

// edgeKey identifies one directed reference between two in-table resources.
type edgeKey struct {
	fromType string
	fromName string
	toType   string
	toName   string
}

// countReferenceEdges walks the resources that can reference other resources
// and counts the directed edges whose target is also present in the table.
// Dangling references are ignored: the budget bounds the graph that is
// actually published, not unresolved names. Repeated references between the
// same two resources collapse into one edge.
func countReferenceEdges(
	resources map[resourcev3.Type][]cachetypes.Resource,
	nameSets map[string]map[string]struct{},
	sortedTypeURLs []string,
) (int64, error) {
	edges := make(map[edgeKey]struct{})

	addEdge := func(fromType, fromName, toType, toName string) {
		if toName == "" {
			return
		}
		if _, ok := nameSets[toType][toName]; !ok {
			return
		}
		edges[edgeKey{fromType: fromType, fromName: fromName, toType: toType, toName: toName}] = struct{}{}
	}

	for _, typeURL := range sortedTypeURLs {
		for _, resource := range resources[typeURL] {
			switch r := resource.(type) {
			case *listenerv3.Listener:
				listenerEdges(r, addEdge)
			case *routev3.RouteConfiguration:
				routeConfigEdges(r, addEdge)
			case *clusterv3.Cluster:
				clusterEdges(r, addEdge)
			default:
				// Endpoints, secrets, runtime resources and extension types do
				// not reference other table resources through name fields the
				// snapshot resolves, so they have no outgoing edges here.
			}
		}
	}

	return addInt64(0, int64(len(edges)))
}

// listenerEdges extracts Listener -> RouteConfiguration (HCM RDS) and
// Listener -> Secret (downstream TLS SDS) edges.
func listenerEdges(l *listenerv3.Listener, addEdge func(fromType, fromName, toType, toName string)) {
	fromName := l.GetName()
	chains := make([]*listenerv3.FilterChain, 0, len(l.GetFilterChains())+1)
	chains = append(chains, l.GetFilterChains()...)
	if l.GetDefaultFilterChain() != nil {
		chains = append(chains, l.GetDefaultFilterChain())
	}

	for _, chain := range chains {
		if chain == nil {
			continue
		}
		for _, filter := range chain.GetFilters() {
			if filter.GetName() != wellknown.HTTPConnectionManager {
				continue
			}
			hcm := &hcmv3.HttpConnectionManager{}
			if err := unmarshalAny(filter.GetTypedConfig(), hcm); err != nil {
				continue
			}
			if rds := hcm.GetRds(); rds != nil {
				addEdge(resourcev3.ListenerType, fromName, resourcev3.RouteType, rds.GetRouteConfigName())
			}
		}
		commonTLS := downstreamCommonTLS(chain.GetTransportSocket())
		for _, secretName := range commonTLSSecretNames(commonTLS) {
			addEdge(resourcev3.ListenerType, fromName, resourcev3.SecretType, secretName)
		}
	}
}

// routeConfigEdges extracts RouteConfiguration -> Cluster edges from route
// actions and weighted clusters.
func routeConfigEdges(rc *routev3.RouteConfiguration, addEdge func(fromType, fromName, toType, toName string)) {
	fromName := rc.GetName()
	for _, vhost := range rc.GetVirtualHosts() {
		for _, route := range vhost.GetRoutes() {
			action := route.GetRoute()
			if action == nil {
				continue
			}
			if cluster := action.GetCluster(); cluster != "" {
				addEdge(resourcev3.RouteType, fromName, resourcev3.ClusterType, cluster)
			}
			if weighted := action.GetWeightedClusters(); weighted != nil {
				for _, weightedCluster := range weighted.GetClusters() {
					addEdge(resourcev3.RouteType, fromName, resourcev3.ClusterType, weightedCluster.GetName())
				}
			}
		}
	}
}

// clusterEdges extracts EDS Cluster -> ClusterLoadAssignment and
// Cluster -> Secret (upstream TLS SDS) edges.
func clusterEdges(c *clusterv3.Cluster, addEdge func(fromType, fromName, toType, toName string)) {
	fromName := c.GetName()

	if t, ok := c.GetClusterDiscoveryType().(*clusterv3.Cluster_Type); ok && t.Type == clusterv3.Cluster_EDS {
		endpointName := c.GetName()
		if eds := c.GetEdsClusterConfig(); eds != nil && eds.GetServiceName() != "" {
			endpointName = eds.GetServiceName()
		}
		addEdge(resourcev3.ClusterType, fromName, resourcev3.EndpointType, endpointName)
	}

	commonTLS := upstreamCommonTLS(c.GetTransportSocket())
	for _, secretName := range commonTLSSecretNames(commonTLS) {
		addEdge(resourcev3.ClusterType, fromName, resourcev3.SecretType, secretName)
	}
}

func downstreamCommonTLS(socket *corev3.TransportSocket) *tlsv3.CommonTlsContext {
	if socket == nil || socket.GetTypedConfig() == nil {
		return nil
	}
	ctx := &tlsv3.DownstreamTlsContext{}
	if err := unmarshalAny(socket.GetTypedConfig(), ctx); err != nil {
		return nil
	}
	return ctx.GetCommonTlsContext()
}

func upstreamCommonTLS(socket *corev3.TransportSocket) *tlsv3.CommonTlsContext {
	if socket == nil || socket.GetTypedConfig() == nil {
		return nil
	}
	ctx := &tlsv3.UpstreamTlsContext{}
	if err := unmarshalAny(socket.GetTypedConfig(), ctx); err != nil {
		return nil
	}
	return ctx.GetCommonTlsContext()
}

// commonTLSSecretNames returns the SDS secret names referenced by a
// CommonTlsContext: the TLS certificate secrets and either the standalone
// validation-context secret or the one carried by a combined validation
// context.
func commonTLSSecretNames(common *tlsv3.CommonTlsContext) []string {
	if common == nil {
		return nil
	}
	var names []string
	for _, sds := range common.GetTlsCertificateSdsSecretConfigs() {
		if sds != nil && sds.GetName() != "" {
			names = append(names, sds.GetName())
		}
	}
	if sds := common.GetValidationContextSdsSecretConfig(); sds != nil && sds.GetName() != "" {
		names = append(names, sds.GetName())
	}
	if combined := common.GetCombinedValidationContext(); combined != nil {
		if sds := combined.GetValidationContextSdsSecretConfig(); sds != nil && sds.GetName() != "" {
			names = append(names, sds.GetName())
		}
	}
	return names
}

// unmarshalAny decodes an Any payload into the given message. Unknown
// extension types fail the unmarshal and callers simply skip them.
func unmarshalAny(any *anypb.Any, msg protobuf.Message) error {
	if any == nil {
		return errNilAny
	}
	return any.UnmarshalTo(msg)
}
