// Copyright Envoy Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package irwitness

import (
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/utils/ptr"

	"github.com/envoyproxy/gateway/internal/ir"
)

func testOptions() Options {
	return Options{
		ControllerNamespace:       "envoy-gateway-system",
		GlobalRateLimitServiceURL: "grpc://envoy-gateway-ratelimit.envoy-gateway-system.svc.cluster.local:8081",
		MaxEvaluations:            200,
		EvalTimeout:               30_000_000_000,
	}
}

func baseListener(name string, routes ...*ir.HTTPRoute) *ir.HTTPListener {
	return &ir.HTTPListener{
		CoreListenerDetails: ir.CoreListenerDetails{
			Name:    name,
			Address: "0.0.0.0",
			Port:    10080,
		},
		Hostnames: []string{"*"},
		Routes:    routes,
	}
}

func clusterRefRoute(routeName, prefix, clusterName string) *ir.HTTPRoute {
	return &ir.HTTPRoute{
		Name:     routeName,
		Hostname: "*",
		PathMatch: &ir.StringMatch{
			Prefix: ptr.To(prefix),
		},
		Destination: destWithClusterRefs("dest-"+routeName, clusterName),
	}
}

func destWithClusterRefs(name string, clusterNames ...string) *ir.RouteDestination {
	dest := &ir.RouteDestination{Name: name}
	for _, clusterName := range clusterNames {
		dest.BackendClusterRefs = append(dest.BackendClusterRefs, &ir.BackendClusterRef{
			Name:   clusterName,
			Weight: ptr.To(uint32(1)),
		})
	}
	return dest
}

func settingsRoute(routeName, prefix, destName, host string, port uint32) *ir.HTTPRoute {
	return &ir.HTTPRoute{
		Name:      routeName,
		Hostname:  "*",
		PathMatch: &ir.StringMatch{Prefix: ptr.To(prefix)},
		Destination: &ir.RouteDestination{
			Name: destName,
			Settings: []*ir.DestinationSetting{{
				Name:        destName + "/0",
				Protocol:    ir.HTTP,
				AddressType: ptr.To(ir.IP),
				Weight:      ptr.To(uint32(1)),
				Endpoints:   []*ir.DestinationEndpoint{{Host: host, Port: port}},
			}},
		},
	}
}

func backendCluster(name, host string, port uint32) *ir.BackendCluster {
	return &ir.BackendCluster{
		Name: name,
		Setting: &ir.DestinationSetting{
			Name:        name + "/setting",
			Protocol:    ir.HTTP,
			AddressType: ptr.To(ir.IP),
			Weight:      ptr.To(uint32(1)),
			Endpoints:   []*ir.DestinationEndpoint{{Host: host, Port: port}},
		},
	}
}

func mirrorRoute(routeName, primaryCluster, mirrorCluster string) *ir.HTTPRoute {
	return &ir.HTTPRoute{
		Name:        routeName,
		Hostname:    "*",
		PathMatch:   &ir.StringMatch{Prefix: ptr.To("/" + routeName)},
		Destination: destWithClusterRefs("dest-"+routeName, primaryCluster),
		Mirrors: []*ir.MirrorPolicy{{
			Destination: destWithClusterRefs("mirror-dest-"+routeName, mirrorCluster),
		}},
	}
}

func wasmFilter(name, wasmName string) ir.Wasm {
	return ir.Wasm{
		Name:     name,
		WasmName: wasmName,
		Config:   &apiextensionsv1.JSON{Raw: []byte(`{"plugin":"` + wasmName + `"}`)},
		Code: &ir.HTTPWasmCode{
			ServingURL: "http://envoy-gateway.envoy-gateway-system:18002/" + wasmName + ".wasm",
			SHA256:     "a1f0b78b8c1320690327800e3a5de10e7dbba7b6c752e702193a395a52c727b6",
		},
	}
}

func twoFilterRoute() *ir.HTTPRoute {
	route := settingsRoute("filter-route", "/filters", "filter-dest", "10.1.1.1", 8080)
	route.EnvoyExtensions = &ir.EnvoyExtensionFeatures{
		Wasms: []ir.Wasm{
			wasmFilter("policy/wasm/0", "callout-a"),
			wasmFilter("policy/wasm/1", "callout-b"),
		},
	}
	return route
}

func resourceExistsSpec(rType, name string) *PredicateSpec {
	return &PredicateSpec{ResourceExists: &ResourceRef{Type: rType, Name: name}}
}
