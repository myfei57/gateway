// Copyright Envoy Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package gatewayapi

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"math/rand/v2"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"
	gwapiv1b1 "sigs.k8s.io/gateway-api/apis/v1beta1"

	egv1a1 "github.com/envoyproxy/gateway/api/v1alpha1"
	"github.com/envoyproxy/gateway/internal/gatewayapi/resource"
	"github.com/envoyproxy/gateway/internal/logging"
)

const (
	auditInfraNS      = "infra"
	auditBackendA     = "backend-a"
	auditBackendB     = "backend-b"
	auditCertNS       = "certs"
	auditSecretMarker = "SUPER-SECRET-PAYLOAD-MUST-NEVER-LEAK"
)

// auditGrant builds a ReferenceGrant in targetNS with a single from/to pair.
func auditGrant(name, targetNS, fromKind string, toGroup, toKind string, toName *gwapiv1.ObjectName) *gwapiv1b1.ReferenceGrant {
	return &gwapiv1b1.ReferenceGrant{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: targetNS,
			Name:      name,
			UID:       types.UID("uid-" + name),
		},
		Spec: gwapiv1b1.ReferenceGrantSpec{
			From: []gwapiv1b1.ReferenceGrantFrom{{
				Group:     gwapiv1.GroupName,
				Kind:      gwapiv1.Kind(fromKind),
				Namespace: gwapiv1.Namespace(auditInfraNS),
			}},
			To: []gwapiv1b1.ReferenceGrantTo{{
				Group: gwapiv1.Group(toGroup),
				Kind:  gwapiv1.Kind(toKind),
				Name:  toName,
			}},
		},
	}
}

func auditService(namespace, name string) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
			UID:       types.UID("uid-" + namespace + "-" + name),
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{{Name: "http", Port: 8080, Protocol: corev1.ProtocolTCP}},
		},
	}
}

func auditSecret(namespace, name string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
			UID:       types.UID("uid-secret-" + namespace + "-" + name),
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			"tls.crt": []byte(auditSecretMarker + "-crt"),
			"tls.key": []byte(auditSecretMarker + "-key"),
		},
	}
}

// auditFixtureResources builds the shared comprehensive fixture. It deliberately
// contains a same-named Service in two namespaces, name-scoped and unscoped grants,
// defaulted group/kind refs and multiple alternative grants.
func auditFixtureResources() *resource.Resources {
	mode := gwapiv1.TLSModeTerminate
	gateway := &gwapiv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: auditInfraNS, Name: "gw", UID: "uid-gw", Generation: 2},
		Spec: gwapiv1.GatewaySpec{
			GatewayClassName: "envoy-gateway-class",
			Listeners: []gwapiv1.Listener{{
				Name:     "https",
				Port:     443,
				Protocol: gwapiv1.HTTPSProtocolType,
				TLS: &gwapiv1.ListenerTLSConfig{
					Mode: &mode,
					CertificateRefs: []gwapiv1.SecretObjectReference{
						{Name: "tls-ok", Namespace: NamespacePtr(auditCertNS)},
						{Name: "tls-denied", Namespace: NamespacePtr(auditCertNS)},
					},
				},
			}},
			TLS: &gwapiv1.GatewayTLSConfig{
				Backend: &gwapiv1.GatewayBackendTLS{
					ClientCertificateRef: &gwapiv1.SecretObjectReference{
						Name: "client-ok", Namespace: NamespacePtr(auditCertNS),
					},
				},
			},
		},
	}

	httpRoute := &gwapiv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Namespace: auditInfraNS, Name: "hr", UID: "uid-hr", Generation: 3},
		Spec: gwapiv1.HTTPRouteSpec{
			CommonRouteSpec: gwapiv1.CommonRouteSpec{
				ParentRefs: []gwapiv1.ParentReference{{Name: "gw"}},
			},
			Rules: []gwapiv1.HTTPRouteRule{
				{
					Name: SectionNamePtr("same-name-cross-ns"),
					BackendRefs: []gwapiv1.HTTPBackendRef{
						{BackendRef: gwapiv1.BackendRef{BackendObjectReference: gwapiv1.BackendObjectReference{
							Name: "svc", Namespace: NamespacePtr(auditBackendA), Port: PortNumPtr(8080),
						}}},
						{BackendRef: gwapiv1.BackendRef{BackendObjectReference: gwapiv1.BackendObjectReference{
							Name: "svc", Namespace: NamespacePtr(auditBackendB), Port: PortNumPtr(8080),
						}}},
					},
				},
				{
					Name: SectionNamePtr("same-namespace"),
					BackendRefs: []gwapiv1.HTTPBackendRef{
						{BackendRef: gwapiv1.BackendRef{BackendObjectReference: gwapiv1.BackendObjectReference{
							Name: "svc-local", Port: PortNumPtr(8080),
						}}},
					},
				},
				{
					Name: SectionNamePtr("unscoped-grant"),
					BackendRefs: []gwapiv1.HTTPBackendRef{
						{BackendRef: gwapiv1.BackendRef{BackendObjectReference: gwapiv1.BackendObjectReference{
							Name: "unscoped-svc", Namespace: NamespacePtr(auditBackendA), Port: PortNumPtr(8080),
						}}},
					},
				},
				{
					Name: SectionNamePtr("missing-target"),
					BackendRefs: []gwapiv1.HTTPBackendRef{
						{BackendRef: gwapiv1.BackendRef{BackendObjectReference: gwapiv1.BackendObjectReference{
							Name: "missing-svc", Namespace: NamespacePtr(auditBackendA), Port: PortNumPtr(8080),
						}}},
					},
				},
				{
					Name: SectionNamePtr("request-mirror"),
					Filters: []gwapiv1.HTTPRouteFilter{{
						Type: gwapiv1.HTTPRouteFilterRequestMirror,
						RequestMirror: &gwapiv1.HTTPRequestMirrorFilter{
							BackendRef: gwapiv1.BackendObjectReference{
								Name: "mirror-svc", Namespace: NamespacePtr(auditBackendA), Port: PortNumPtr(8080),
							},
						},
					}},
				},
				{
					Name: SectionNamePtr("alternative-grants"),
					BackendRefs: []gwapiv1.HTTPBackendRef{
						{BackendRef: gwapiv1.BackendRef{BackendObjectReference: gwapiv1.BackendObjectReference{
							Name: "alt-svc", Namespace: NamespacePtr(auditBackendA), Port: PortNumPtr(8080),
						}}},
					},
				},
			},
		},
	}

	// Group and kind are intentionally omitted: defaulting to core/Service must be
	// audited exactly as the translator defaults them.
	tlsRoute := &gwapiv1.TLSRoute{
		ObjectMeta: metav1.ObjectMeta{Namespace: auditInfraNS, Name: "tlsr", UID: "uid-tlsr", Generation: 1},
		Spec: gwapiv1.TLSRouteSpec{
			CommonRouteSpec: gwapiv1.CommonRouteSpec{
				ParentRefs: []gwapiv1.ParentReference{{Name: "gw"}},
			},
			Rules: []gwapiv1.TLSRouteRule{{
				BackendRefs: []gwapiv1.BackendRef{{
					BackendObjectReference: gwapiv1.BackendObjectReference{
						Name: "svc", Namespace: NamespacePtr(auditBackendA), Port: PortNumPtr(443),
					},
				}},
			}},
		},
	}

	resources := &resource.Resources{
		Gateways:   []*gwapiv1.Gateway{gateway},
		HTTPRoutes: []*gwapiv1.HTTPRoute{httpRoute},
		TLSRoutes:  []*gwapiv1.TLSRoute{tlsRoute},
		Services: []*corev1.Service{
			auditService(auditBackendA, "svc"),
			auditService(auditBackendB, "svc"),
			auditService(auditInfraNS, "svc-local"),
			auditService(auditBackendA, "unscoped-svc"),
			auditService(auditBackendA, "mirror-svc"),
			auditService(auditBackendA, "alt-svc"),
		},
		Secrets: []*corev1.Secret{
			auditSecret(auditCertNS, "tls-ok"),
			auditSecret(auditCertNS, "client-ok"),
		},
		ReferenceGrants: []*gwapiv1b1.ReferenceGrant{
			// Name-scoped grant for backend-a/svc from HTTPRoute.
			auditGrant("grant-http-name", auditBackendA, "HTTPRoute", "", resource.KindService, ObjectNamePtr("svc")),
			// Unscoped grant covering every Service in backend-a for HTTPRoute.
			auditGrant("grant-http-all", auditBackendA, "HTTPRoute", "", resource.KindService, nil),
			// Unscoped grant for TLSRoute, exercising from-kind matching and default groups.
			auditGrant("grant-tls-all", auditBackendA, "TLSRoute", "", resource.KindService, nil),
			// Name-scoped grant whose name never matches an audited target.
			auditGrant("grant-bad-name", auditBackendA, "HTTPRoute", "", resource.KindService, ObjectNamePtr("does-not-exist")),
			// Two independent grants covering alt-svc.
			auditGrant("grant-alt-1", auditBackendA, "HTTPRoute", "", resource.KindService, ObjectNamePtr("alt-svc")),
			auditGrant("grant-alt-2", auditBackendA, "HTTPRoute", "", resource.KindService, ObjectNamePtr("alt-svc")),
			// Certificate grant for the existing, name-scoped listener secret.
			auditGrant("grant-cert-name", auditCertNS, "Gateway", "", resource.KindSecret, ObjectNamePtr("tls-ok")),
			// Certificate grant for the backend client certificate secret.
			auditGrant("grant-cert-client", auditCertNS, "Gateway", "", resource.KindSecret, ObjectNamePtr("client-ok")),
			// Grant sitting in the wrong namespace: it must never authorize certs/*,
			// regardless of the matching name.
			auditGrant("grant-wrong-namespace", auditInfraNS, "Gateway", "", resource.KindSecret, ObjectNamePtr("tls-denied")),
		},
	}
	return resources
}

func findAuditEdge(t *testing.T, report *ReferenceGrantAuditReport, sourceName, section string) AuditEdge {
	t.Helper()
	for _, edge := range report.Edges {
		if edge.Source.Name == sourceName && edge.Section.Description == section {
			return edge
		}
	}
	require.Failf(t, "audit edge not found", "source=%q section=%q", sourceName, section)
	return AuditEdge{}
}

func grantNames(evidence []GrantEvidence) []string {
	names := make([]string, 0, len(evidence))
	for _, item := range evidence {
		names = append(names, item.Namespace+"/"+item.Name)
	}
	return names
}

func explanationBranch(edge AuditEdge, grantName string) GrantMatchBranch {
	for _, explanation := range edge.ConsideredGrants {
		if explanation.Grant.Name == grantName {
			return explanation.Branch
		}
	}
	return ""
}

// TestReferenceGrantAuditEdges verifies every edge verdict, the actual hit grants, the
// testable explanation branches and the bounded removal dependency analysis.
func TestReferenceGrantAuditEdges(t *testing.T) {
	resources := auditFixtureResources()
	report := (&ReferenceGrantAudit{}).Audit(resources)

	require.Equal(t, 11, len(report.Edges), "the fixture declares eleven finite references")

	t.Run("name scoped and unscoped grants both match the exact backend", func(t *testing.T) {
		edge := findAuditEdge(t, report, "hr", "rule[0].backendRef[0]")
		require.Equal(t, AuditEdgeBackend, edge.Kind)
		require.True(t, edge.CrossNamespace)
		require.Equal(t, AuditVerdictAllowed, edge.Verdict)
		require.Equal(t, AuditReasonGranted, edge.Reason)
		require.Equal(t,
			[]string{"backend-a/grant-http-all", "backend-a/grant-http-name"},
			grantNames(edge.GrantEvidence))
		nameScoped := map[string]bool{}
		for _, evidence := range edge.GrantEvidence {
			nameScoped[evidence.Name] = evidence.NameScoped
		}
		require.True(t, nameScoped["grant-http-name"])
		require.False(t, nameScoped["grant-http-all"])
		require.True(t, edge.Target.Found)
		require.Equal(t, types.UID("uid-backend-a-svc"), edge.Target.UID)
		require.Equal(t, types.UID("uid-hr"), edge.Source.UID)
		require.Equal(t, int64(3), edge.Source.Generation)
		require.Equal(t, 0, edge.Section.RuleIndex)
		require.Equal(t, 0, edge.Section.BackendRefIndex)
		require.Equal(t, "same-name-cross-ns", edge.Section.RuleName)
		// Either grant alone keeps the edge permitted, so both are redundant.
		require.Len(t, edge.Dependencies, 2)
		for _, dependency := range edge.Dependencies {
			require.Equal(t, GrantRemovalRedundant, dependency.Effect)
		}
		// The bad-name grant is considered but fails the to-name comparison.
		require.Equal(t, GrantBranchToNotMatched, explanationBranch(edge, "grant-bad-name"))
	})

	t.Run("same named service in another namespace does not get authorized", func(t *testing.T) {
		edge := findAuditEdge(t, report, "hr", "rule[0].backendRef[1]")
		require.Equal(t, AuditVerdictDenied, edge.Verdict)
		require.Equal(t, AuditReasonRefNotPermitted, edge.Reason)
		require.Empty(t, edge.GrantEvidence)
		require.Empty(t, edge.Dependencies)
		require.Equal(t, auditBackendB, edge.Target.Namespace)
		require.Equal(t, "svc", edge.Target.Name)
		// Every backend-a grant lives outside the target namespace and therefore
		// cannot authorize the reference to backend-b.
		for _, explanation := range edge.ConsideredGrants {
			if explanation.Grant.Namespace == auditBackendA {
				require.Equal(t, GrantBranchInOtherNamespace, explanation.Branch,
					"grant %s must not authorize a target in another namespace", explanation.Grant.Name)
			}
		}
	})

	t.Run("same namespace reference needs no grant", func(t *testing.T) {
		edge := findAuditEdge(t, report, "hr", "rule[1].backendRef[0]")
		require.False(t, edge.CrossNamespace)
		require.Equal(t, AuditVerdictAllowed, edge.Verdict)
		require.Equal(t, AuditReasonSameNamespace, edge.Reason)
		require.Empty(t, edge.GrantEvidence, "no grant may be fabricated for a same-namespace reference")
		require.Empty(t, edge.ConsideredGrants)
		require.Empty(t, edge.Dependencies)
		require.True(t, edge.Target.Found)
	})

	t.Run("unscoped grant covers all resources of a kind", func(t *testing.T) {
		edge := findAuditEdge(t, report, "hr", "rule[2].backendRef[0]")
		require.Equal(t, AuditVerdictAllowed, edge.Verdict)
		// The name-scoped "svc" grant cannot cover "unscoped-svc"; only the unscoped
		// grant matches, making it the single load-bearing grant.
		require.Equal(t, []string{"backend-a/grant-http-all"}, grantNames(edge.GrantEvidence))
		require.False(t, edge.GrantEvidence[0].NameScoped, "a grant without a to.name is not name scoped")
		require.Len(t, edge.Dependencies, 1)
		require.Equal(t, GrantRemovalRequired, edge.Dependencies[0].Effect)
	})

	t.Run("missing target is Unknown while inventory completeness is unproven", func(t *testing.T) {
		edge := findAuditEdge(t, report, "hr", "rule[3].backendRef[0]")
		require.Equal(t, AuditVerdictUnknown, edge.Verdict)
		require.Equal(t, AuditReasonTargetNotInInventory, edge.Reason)
		require.False(t, edge.Target.Found)
		// The grant itself still matches; uncertainty only concerns target existence.
		require.Equal(t, []string{"backend-a/grant-http-all"}, grantNames(edge.GrantEvidence))
	})

	t.Run("request mirror backend uses the same predicate", func(t *testing.T) {
		edge := findAuditEdge(t, report, "hr", "rule[4].filter[0].requestMirror.backendRef")
		require.Equal(t, AuditVerdictAllowed, edge.Verdict)
		require.Equal(t, 4, edge.Section.RuleIndex)
		require.Equal(t, 0, edge.Section.FilterIndex)
		require.Equal(t, -1, edge.Section.BackendRefIndex)
		require.Equal(t, []string{"backend-a/grant-http-all"}, grantNames(edge.GrantEvidence))
	})

	t.Run("multiple alternative grants form a redundant set", func(t *testing.T) {
		edge := findAuditEdge(t, report, "hr", "rule[5].backendRef[0]")
		require.Equal(t, AuditVerdictAllowed, edge.Verdict)
		// Both dedicated alternative grants and the unscoped grant authorize alt-svc.
		require.Equal(t,
			[]string{"backend-a/grant-alt-1", "backend-a/grant-alt-2", "backend-a/grant-http-all"},
			grantNames(edge.GrantEvidence))
		for _, evidence := range edge.GrantEvidence {
			if evidence.Name == "grant-http-all" {
				require.False(t, evidence.NameScoped)
				continue
			}
			require.True(t, evidence.NameScoped)
		}
		require.Len(t, edge.Dependencies, 3)
		for _, dependency := range edge.Dependencies {
			require.Equal(t, GrantRemovalRedundant, dependency.Effect,
				"removing one alternative grant must leave the edge permitted")
		}
		// The hypothetical analysis never mutates the input grant list.
		require.Len(t, resources.ReferenceGrants, 9)
	})

	t.Run("defaulted group and kind on the route side", func(t *testing.T) {
		edge := findAuditEdge(t, report, "tlsr", "rule[0].backendRef[0]")
		require.Equal(t, AuditVerdictAllowed, edge.Verdict)
		require.Equal(t, "", edge.Target.Group, "omitted group defaults to the core group")
		require.Equal(t, resource.KindService, edge.Target.Kind, "omitted kind defaults to Service")
		require.Equal(t, []string{"backend-a/grant-tls-all"}, grantNames(edge.GrantEvidence))
		// The HTTPRoute grant cannot serve a TLSRoute referrer.
		require.Equal(t, GrantBranchFromNotMatched, explanationBranch(edge, "grant-http-name"))
	})

	t.Run("listener certificate grants and the wrong-namespace trap", func(t *testing.T) {
		allowed := findAuditEdge(t, report, "gw", "listener[https].certificateRef[0]")
		require.Equal(t, AuditEdgeCertificate, allowed.Kind)
		require.Equal(t, AuditVerdictAllowed, allowed.Verdict)
		require.Equal(t, []string{"certs/grant-cert-name"}, grantNames(allowed.GrantEvidence))
		require.Equal(t, types.UID("uid-secret-certs-tls-ok"), allowed.Target.UID)
		require.Equal(t, "https", allowed.Section.ListenerName)

		denied := findAuditEdge(t, report, "gw", "listener[https].certificateRef[1]")
		require.Equal(t, AuditVerdictDenied, denied.Verdict)
		require.Equal(t, AuditReasonRefNotPermitted, denied.Reason)
		require.Empty(t, denied.GrantEvidence)
		require.Equal(t, GrantBranchInOtherNamespace, explanationBranch(denied, "grant-wrong-namespace"))
		require.Equal(t, GrantBranchToNotMatched, explanationBranch(denied, "grant-cert-name"))
	})

	t.Run("gateway backend client certificate reference", func(t *testing.T) {
		edge := findAuditEdge(t, report, "gw", "tls.backend.clientCertificateRef")
		require.Equal(t, AuditVerdictAllowed, edge.Verdict)
		require.Equal(t, []string{"certs/grant-cert-client"}, grantNames(edge.GrantEvidence))
		require.Equal(t, -1, edge.Section.CertificateRefIndex)
	})
}

// TestReferenceGrantAuditInventoryCompleteness toggles the completeness flag and checks
// that only a provably complete inventory turns a missing target into a hard denial.
func TestReferenceGrantAuditInventoryCompleteness(t *testing.T) {
	resources := auditFixtureResources()

	incomplete := (&ReferenceGrantAudit{InventoryComplete: false}).Audit(resources)
	edge := findAuditEdge(t, incomplete, "hr", "rule[3].backendRef[0]")
	require.Equal(t, AuditVerdictUnknown, edge.Verdict)

	complete := (&ReferenceGrantAudit{InventoryComplete: true}).Audit(resources)
	edge = findAuditEdge(t, complete, "hr", "rule[3].backendRef[0]")
	require.Equal(t, AuditVerdictDenied, edge.Verdict)
	require.Equal(t, AuditReasonTargetNotFound, edge.Reason)

	// A denied grant decision stays denied under either completeness mode.
	denied := findAuditEdge(t, complete, "hr", "rule[0].backendRef[1]")
	require.Equal(t, AuditVerdictDenied, denied.Verdict)
	require.Equal(t, AuditReasonRefNotPermitted, denied.Reason)
}

// TestReferenceGrantAuditReusesTranslatorPredicate asserts the audit verdict for every
// cross-namespace edge equals the real translator predicate evaluated directly.
func TestReferenceGrantAuditReusesTranslatorPredicate(t *testing.T) {
	resources := auditFixtureResources()
	report := (&ReferenceGrantAudit{}).Audit(resources)

	for _, edge := range report.Edges {
		if !edge.CrossNamespace {
			require.Empty(t, edge.GrantEvidence)
			continue
		}
		permitted := isCrossNamespaceReferencePermitted(
			crossNamespaceFrom{
				group:     edge.Source.Group,
				kind:      edge.Source.Kind,
				namespace: edge.Source.Namespace,
			},
			crossNamespaceTo{
				group:     edge.Target.Group,
				kind:      edge.Target.Kind,
				namespace: edge.Target.Namespace,
				name:      edge.Target.Name,
			},
			resources.ReferenceGrants,
		)
		if permitted {
			require.NotEqual(t, AuditVerdictDenied, edge.Verdict, "edge %s must not be denied while the predicate permits it", edge.Section.Description)
			require.NotEmpty(t, edge.GrantEvidence, "permitted edge %s must carry grant evidence", edge.Section.Description)
		} else {
			require.Equal(t, AuditVerdictDenied, edge.Verdict)
			require.Equal(t, AuditReasonRefNotPermitted, edge.Reason)
			require.Empty(t, edge.GrantEvidence)
		}

		// Explanation consistency: a Matched branch exists if and only if the
		// predicate permits the edge.
		hasMatch := false
		for _, explanation := range edge.ConsideredGrants {
			if explanation.Branch == GrantBranchMatched {
				hasMatch = true
			}
		}
		require.Equal(t, permitted, hasMatch, "explanation branches disagree with the predicate for %s", edge.Section.Description)
	}
}

// TestReferenceGrantAuditPermutationInvariant shuffles every input slice and proves the
// normalized evidence and conclusions do not depend on input ordering.
func TestReferenceGrantAuditPermutationInvariant(t *testing.T) {
	baseline := (&ReferenceGrantAudit{}).Audit(auditFixtureResources())

	for seed := int64(1); seed <= 8; seed++ {
		resources := auditFixtureResources()
		rng := rand.New(rand.NewPCG(uint64(seed), uint64(seed*7)))
		rng.Shuffle(len(resources.ReferenceGrants), func(i, j int) {
			resources.ReferenceGrants[i], resources.ReferenceGrants[j] = resources.ReferenceGrants[j], resources.ReferenceGrants[i]
		})
		rng.Shuffle(len(resources.Services), func(i, j int) {
			resources.Services[i], resources.Services[j] = resources.Services[j], resources.Services[i]
		})
		rng.Shuffle(len(resources.Secrets), func(i, j int) {
			resources.Secrets[i], resources.Secrets[j] = resources.Secrets[j], resources.Secrets[i]
		})
		rng.Shuffle(len(resources.HTTPRoutes), func(i, j int) {
			resources.HTTPRoutes[i], resources.HTTPRoutes[j] = resources.HTTPRoutes[j], resources.HTTPRoutes[i]
		})
		rng.Shuffle(len(resources.Gateways), func(i, j int) {
			resources.Gateways[i], resources.Gateways[j] = resources.Gateways[j], resources.Gateways[i]
		})
		// Note: refs inside a rule keep their position because the section path is
		// positional; shuffling them would change the declared reference rather than
		// its ordering.

		shuffled := (&ReferenceGrantAudit{}).Audit(resources)
		require.True(t, reflect.DeepEqual(baseline, shuffled),
			"audit output changed under input permutation with seed %d", seed)
	}
}

// TestReferenceGrantAuditDoesNotMutateInput guarantees the audit performs zero writes:
// the full input tree, including statuses, is byte-for-byte unchanged afterwards.
func TestReferenceGrantAuditDoesNotMutateInput(t *testing.T) {
	resources := auditFixtureResources()
	snapshot := resources.DeepCopy()

	report := (&ReferenceGrantAudit{InventoryComplete: true}).Audit(resources)
	require.NotEmpty(t, report.Edges)

	require.True(t, reflect.DeepEqual(snapshot, resources), "the audit must not mutate any input object or status")
}

// TestReferenceGrantAuditNeverExposesSecretData marshals the whole report and ensures no
// Secret payload can leak through it.
func TestReferenceGrantAuditNeverExposesSecretData(t *testing.T) {
	report := (&ReferenceGrantAudit{}).Audit(auditFixtureResources())
	payload, err := json.Marshal(report)
	require.NoError(t, err)
	require.NotContains(t, string(payload), auditSecretMarker)
}

// TestReferenceGrantAuditNilAndEmpty covers defensive handling of empty inputs.
func TestReferenceGrantAuditNilAndEmpty(t *testing.T) {
	require.NotNil(t, (&ReferenceGrantAudit{}).Audit(nil))
	require.Empty(t, (&ReferenceGrantAudit{}).Audit(nil).Edges)

	report := (&ReferenceGrantAudit{}).Audit(resource.NewResources())
	require.Empty(t, report.Edges)
	require.False(t, report.InventoryComplete)
}

// translatorAuditResources builds a minimal fixture for the end-to-end cross-check with
// the real Translator. Every denied outcome must be caused exclusively by a missing
// ReferenceGrant because all referenced objects exist.
func translatorAuditResources() *resource.Resources {
	mode := gwapiv1.TLSModeTerminate
	resources := &resource.Resources{
		GatewayClass: &gwapiv1.GatewayClass{
			ObjectMeta: metav1.ObjectMeta{Name: "envoy-gateway-class"},
			Spec:       gwapiv1.GatewayClassSpec{ControllerName: gwapiv1.GatewayController(egv1a1.GatewayControllerName)},
		},
		Gateways: []*gwapiv1.Gateway{{
			ObjectMeta: metav1.ObjectMeta{Namespace: auditInfraNS, Name: "gw", UID: "uid-gw-e2e"},
			Spec: gwapiv1.GatewaySpec{
				GatewayClassName: "envoy-gateway-class",
				Listeners: []gwapiv1.Listener{
					{
						Name:     "http",
						Port:     80,
						Protocol: gwapiv1.HTTPProtocolType,
					},
					{
						Name:     "https",
						Port:     443,
						Protocol: gwapiv1.HTTPSProtocolType,
						TLS: &gwapiv1.ListenerTLSConfig{
							Mode: &mode,
							CertificateRefs: []gwapiv1.SecretObjectReference{
								{Name: "tls-ok", Namespace: NamespacePtr(auditCertNS)},
								{Name: "tls-denied", Namespace: NamespacePtr(auditCertNS)},
							},
						},
					},
				},
			},
		}},
		HTTPRoutes: []*gwapiv1.HTTPRoute{
			{
				ObjectMeta: metav1.ObjectMeta{Namespace: auditInfraNS, Name: "route-allowed"},
				Spec: gwapiv1.HTTPRouteSpec{
					CommonRouteSpec: gwapiv1.CommonRouteSpec{
						ParentRefs: []gwapiv1.ParentReference{{Name: "gw", SectionName: SectionNamePtr("http")}},
					},
					Rules: []gwapiv1.HTTPRouteRule{{
						BackendRefs: []gwapiv1.HTTPBackendRef{{
							BackendRef: gwapiv1.BackendRef{BackendObjectReference: gwapiv1.BackendObjectReference{
								Name: "svc", Namespace: NamespacePtr(auditBackendA), Port: PortNumPtr(8080),
							}},
						}},
					}},
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{Namespace: auditInfraNS, Name: "route-denied"},
				Spec: gwapiv1.HTTPRouteSpec{
					CommonRouteSpec: gwapiv1.CommonRouteSpec{
						ParentRefs: []gwapiv1.ParentReference{{Name: "gw", SectionName: SectionNamePtr("http")}},
					},
					Rules: []gwapiv1.HTTPRouteRule{{
						BackendRefs: []gwapiv1.HTTPBackendRef{{
							BackendRef: gwapiv1.BackendRef{BackendObjectReference: gwapiv1.BackendObjectReference{
								Name: "svc", Namespace: NamespacePtr(auditBackendB), Port: PortNumPtr(8080),
							}},
						}},
					}},
				},
			},
		},
		Services: []*corev1.Service{
			auditService(auditBackendA, "svc"),
			auditService(auditBackendB, "svc"),
		},
		EndpointSlices: []*discoveryv1.EndpointSlice{
			{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: auditBackendA,
					Name:      "endpointslice-a",
					Labels:    map[string]string{discoveryv1.LabelServiceName: "svc"},
				},
				AddressType: discoveryv1.AddressTypeIPv4,
				Ports:       []discoveryv1.EndpointPort{{Name: strPtr("http"), Port: port32Ptr(8080), Protocol: protocolTCPPtr()}},
				Endpoints:   []discoveryv1.Endpoint{{Addresses: []string{"10.0.0.1"}, Conditions: discoveryv1.EndpointConditions{Ready: boolPtr(true)}}},
			},
			{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: auditBackendB,
					Name:      "endpointslice-b",
					Labels:    map[string]string{discoveryv1.LabelServiceName: "svc"},
				},
				AddressType: discoveryv1.AddressTypeIPv4,
				Ports:       []discoveryv1.EndpointPort{{Name: strPtr("http"), Port: port32Ptr(8080), Protocol: protocolTCPPtr()}},
				Endpoints:   []discoveryv1.Endpoint{{Addresses: []string{"10.0.0.2"}, Conditions: discoveryv1.EndpointConditions{Ready: boolPtr(true)}}},
			},
		},
		Secrets: []*corev1.Secret{},
		ReferenceGrants: []*gwapiv1b1.ReferenceGrant{
			auditGrant("grant-backend-a", auditBackendA, "HTTPRoute", "", resource.KindService, ObjectNamePtr("svc")),
			auditGrant("grant-cert", auditCertNS, "Gateway", "", resource.KindSecret, ObjectNamePtr("tls-ok")),
		},
	}
	return resources
}

func strPtr(s string) *string  { return &s }
func port32Ptr(p int32) *int32 { return &p }
func boolPtr(b bool) *bool     { return &b }
func protocolTCPPtr() *corev1.Protocol {
	p := corev1.ProtocolTCP
	return &p
}

// validTLSSecret builds a kubernetes.io/tls Secret from the known-valid certificate and
// key pair already exercised by the translator testdata fixtures.
func validTLSSecret(t *testing.T, namespace, name string) *corev1.Secret {
	t.Helper()
	crt, err := base64.StdEncoding.DecodeString(validTLSCrtB64)
	require.NoError(t, err)
	key, err := base64.StdEncoding.DecodeString(validTLSKeyB64)
	require.NoError(t, err)
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
			UID:       types.UID("uid-secret-" + namespace + "-" + name),
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{"tls.crt": crt, "tls.key": key},
	}
}

const (
	validTLSCrtB64 = "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUREVENDQWZXZ0F3SUJBZ0lVRUZNaFA5ZUo5WEFCV3NRNVptNmJSazJjTE5Rd0RRWUpLb1pJaHZjTkFRRUwKQlFBd0ZqRVVNQklHQTFVRUF3d0xabTl2TG1KaGNpNWpiMjB3SGhjTk1qUXdNakk1TURrek1ERXdXaGNOTXpRdwpNakkyTURrek1ERXdXakFXTVJRd0VnWURWUVFEREF0bWIyOHVZbUZ5TG1OdmJUQ0NBU0l3RFFZSktvWklodmNOCkFRRUJCUUFEZ2dFUEFEQ0NBUW9DZ2dFQkFKbEk2WXhFOVprQ1BzNnBDUXhickNtZWl4OVA1RGZ4OVJ1NUxENFQKSm1kVzdJS2R0UVYvd2ZMbXRzdTc2QithVGRDaldlMEJUZmVPT1JCYlIzY1BBRzZFbFFMaWNsUVVydW4zcStncwpKcEsrSTdjSStqNXc4STY4WEg1V1E3clZVdGJ3SHBxYncrY1ZuQnFJVU9MaUlhdGpJZjdLWDUxTTF1RjljZkVICkU0RG5jSDZyYnI1OS9SRlpCc2toeHM1T3p3Sklmb2hreXZGd2V1VHd4Sy9WcGpJKzdPYzQ4QUJDWHBOTzlEL3EKRWgrck9hdWpBTWNYZ0hRSVRrQ2lpVVRjVW82TFNIOXZMWlB0YXFmem9acTZuaE1xcFc2NUUxcEF3RjNqeVRUeAphNUk4SmNmU0Zqa2llWjIwTFVRTW43TThVNHhIamFvL2d2SDBDQWZkQjdSTFUyc0NBd0VBQWFOVE1GRXdIUVlEClZSME9CQllFRk9SQ0U4dS8xRERXN2loWnA3Y3g5dFNtUG02T01COEdBMVVkSXdRWU1CYUFGT1JDRTh1LzFERFcKN2loWnA3Y3g5dFNtUG02T01BOEdBMVVkRXdFQi93UUZNQU1CQWY4d0RRWUpLb1pJaHZjTkFRRUxCUUFEZ2dFQgpBRnQ1M3pqc3FUYUg1YThFMmNodm1XQWdDcnhSSzhiVkxNeGl3TkdqYm1FUFJ6K3c2TngrazBBOEtFY0lEc0tjClNYY2k1OHU0b1didFZKQmx6YS9adWpIUjZQMUJuT3BsK2FveTc4NGJiZDRQMzl3VExvWGZNZmJCQ20xdmV2aDkKQUpLbncyWnRxcjRta2JMY3hFcWxxM3NCTEZBUzlzUUxuS05DZTJjR0xkVHAyYm9HK3FjZ3lRZ0NJTTZmOEVNdgpXUGlmQ01NR3V6Sy9HUkY0YlBPL1lGNDhld0R1M1VlaWgwWFhkVUFPRTlDdFVhOE5JaGMxVVBhT3pQcnRZVnFyClpPR2t2L0t1K0I3OGg4U0VzTzlYclFjdXdiT25KeDZLdFIrYWV5a3ZBcFhDUTNmWkMvYllLQUFSK1A4QUpvUVoKYndJVW1YaTRnajVtK2JLUGhlK2lyK0U9Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0="
	validTLSKeyB64 = "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JSUV1Z0lCQURBTkJna3Foa2lHOXcwQkFRRUZBQVNDQktRd2dnU2dBZ0VBQW9JQkFRQ1pTT21NUlBXWkFqN08KcVFrTVc2d3Bub3NmVCtRMzhmVWJ1U3crRXlablZ1eUNuYlVGZjhIeTVyYkx1K2dmbWszUW8xbnRBVTMzamprUQpXMGQzRHdCdWhKVUM0bkpVRks3cDk2dm9MQ2FTdmlPM0NQbytjUENPdkZ4K1ZrTzYxVkxXOEI2YW04UG5GWndhCmlGRGk0aUdyWXlIK3lsK2RUTmJoZlhIeEJ4T0E1M0IrcTI2K2ZmMFJXUWJKSWNiT1RzOENTSDZJWk1yeGNIcmsKOE1TdjFhWXlQdXpuT1BBQVFsNlRUdlEvNmhJZnF6bXJvd0RIRjRCMENFNUFvb2xFM0ZLT2kwaC9ieTJUN1dxbgo4NkdhdXA0VEtxVnV1Uk5hUU1CZDQ4azA4V3VTUENYSDBoWTVJbm1kdEMxRURKK3pQRk9NUjQycVA0THg5QWdICjNRZTBTMU5yQWdNQkFBRUNnZjk2Zy9QWXh2YVp5NEJuMU5ySkJkOExaT2djYlpjMmdueDZJa3YvVVhaME5obHgKRVlpS2plRmpWNkhXNW9FWHJaKy9tUGY0ZHVzVmFMNzRVOVZvanVQSmNlQWVScmpMM2VPaGJIdGN4KzBnY0dMZwpYeEY5VFJhcDY1VHVVZDFhaTA0aEd3WWY3NXNiUDdSS2JQaXZ3WmdVQWUwQ3BWdWZjaG5YcXJzWXI4cEpZNTFPCldWa1NxejRSWTlXbTBrNUcxSkZ5SXlFQzl1bURsdWpjSE50UlZtYWZrTmZBdENsaVByRktjL245bkpmTzZSRlAKN2c3Vi9JdnFudUlyN1BFM0duNlBhVCtCZ2c0NDh0ZDVKelBwVEE1WkJjQm8yb3J6L2t4WVBGcHIvZ1BVQnFRZApvNm5XcXc3Nlp4d1BsZHdMaEorWFlOWDdvdWN0VVNDTDl1NzdmeUVDZ1lFQXl2N0RseGYrS1FsZkR3bW8vcjFUCjBMMVpuSDQ3MmhpSWVkU2hleVZCSGJFVlRTbXI0MkJSbGpXNERiUmNRTTRWY3h4RGtHclI3NlJHZTlvZzZtemMKUnY4K1ZsQ1gyK3F5OXA1bTZaWHJiQXczMHpDLzVtUGtSV3ViaFVoaSs5ZUNNWmEvaEFJL1JGdjI2OURyQkQyLwo2a2cwRjhYME8vNndJK1dwYXRLM1cwY0NnWUVBd1U5QTZiSnBmYVhLS1hQR21PRy9uVXhUeXp5cVlqS05aSmQvCjlHaEVudUdqSzVDQUVWUEphOGtadmZRemxXbXdaYWZxMERocUk4dkxhRkNEZjhZOEU5OU1hbjNHV2hVYjNWL0oKcU5RUVMzNTZOQ2ZadzdseG9LS0JJdlQ2Y3dpaFRuc0UvUjRIQ3NhbDJ3d040Wmw5SFdOQmdhbVM3VExrejFMaApmd1JEa0wwQ2dZQlo0OWorNW53QTlncG5JVkw1Z3lORGN5WGtlNjNMVlVQU0YwdHV1YitOQTJhNFpiU2RHb0RtCmNHRlJpRVcxMk14OHpjNUpmRlA4dDVVU3NUUVVPeUtNT2VrRDFlcDVVd1B1MjVRYzZldDNUQzNJVW5VWDg3SVkKMzU3ZHRZRkhubFlqMldwemJYOVFxUnk5cmlUMEd0Z0tTZkR2ZWhRK0lQa2szRVZhYlhjT2J3S0JnR0d4QzcwTwp6UUVTcC9nSzZuS1lvNTE2MVY0QWFwcjFzVDhFMFVWUzdGcmU3UGMzTDRHU05saWlhTC8yaVpzWXJteXhUNW1xCjZQanVKUDJ5c3NJQURKeCtYTC8wa0NrMlFiNitpY3NvWUpQR2R6dWthQWpoenVxL05VUFZTanlZUCt6SmZ0dnMKTU9MaFFUQlNCekhidjc3NlNrQ2MwZ1BObEpTeDdnT2l4QUtCQW9HQUpCR1VuM2U1QWZDb21BMUUxRHhSeUxaagpUMFBrQUNlUGpEK3hrRkpod0RoQ2dzd2htNFVKZzFmQW8xaEJRUkZ0dHBWQy91QkxjazE4TUVBSTF2ZGZTeVB2CmtTZzVrVnFQanUzc2czOVRNZ09WZXdqUDNFM0FNUUd1ZzFQNzFZazJ6WUpQbGg5NWRMVTVISlZubzZvdkIrUG0KTHF5K016eDN3a0YwZDhlUFhRND0KLS0tLS1FTkQgUFJJVkFURSBLRVktLS0tLQo="
)

// routeHasRefNotPermitted reports whether the translator rejected the reference on
// grant grounds. The aggregate reason may vary (e.g. partial invalidity), but the
// predicate's "not permitted by any ReferenceGrant" message and the target identity are
// stable signals.
func routeHasRefNotPermitted(t *testing.T, route *gwapiv1.HTTPRoute, targetNS, targetName string) bool {
	t.Helper()
	for _, parent := range route.Status.Parents {
		for _, condition := range parent.Conditions {
			if condition.Type == string(gwapiv1.RouteConditionResolvedRefs) &&
				condition.Status == metav1.ConditionFalse &&
				strings.Contains(condition.Message, "not permitted by any ReferenceGrant") &&
				containsAll(condition.Message, targetNS, targetName) {
				return true
			}
		}
	}
	return false
}

func containsAll(message string, fragments ...string) bool {
	for _, fragment := range fragments {
		if !strings.Contains(message, fragment) {
			return false
		}
	}
	return true
}

// listenerHasRefNotPermitted mirrors routeHasRefNotPermitted for Gateway listener
// certificate refs, where mixed valid/invalid refs surface as
// PartiallyInvalidCertificateRef instead of RefNotPermitted.
func listenerHasRefNotPermitted(t *testing.T, gateway *gwapiv1.Gateway, listenerName, targetName string) bool {
	t.Helper()
	for _, listenerStatus := range gateway.Status.Listeners {
		if listenerStatus.Name != gwapiv1.SectionName(listenerName) {
			continue
		}
		for _, condition := range listenerStatus.Conditions {
			if condition.Type == string(gwapiv1.ListenerConditionResolvedRefs) &&
				condition.Status == metav1.ConditionFalse &&
				strings.Contains(condition.Message, "not permitted by any ReferenceGrant") &&
				strings.Contains(condition.Message, targetName) {
				return true
			}
		}
	}
	return false
}

// TestReferenceGrantAuditMatchesTranslator runs the real translator and compares every
// audit edge with the translator's actual RefNotPermitted acceptance decisions.
func TestReferenceGrantAuditMatchesTranslator(t *testing.T) {
	resources := translatorAuditResources()

	// The translator expects the shared bootstrap secret used by the standard fixtures.
	base, err := os.ReadFile("testdata/base/base.yaml")
	require.NoError(t, err)
	baseResources := &resource.Resources{}
	mustUnmarshal(t, base, baseResources)
	resources.Secrets = append(resources.Secrets, baseResources.Secrets...)

	// Reuse a known-valid key pair (the same material as the
	// gateway-with-listener-with-tls-secret-in-other-namespace fixture) so that the
	// only failure on the second certificate ref is the missing ReferenceGrant.
	validCert := validTLSSecret(t, auditCertNS, "tls-ok")
	resources.Secrets = append(resources.Secrets, validCert)

	translator := &Translator{
		GatewayControllerName: egv1a1.GatewayControllerName,
		GatewayClassName:      "envoy-gateway-class",
		BackendEnabled:        true,
		ControllerNamespace:   "envoy-gateway-system",
		Logger:                logging.DefaultLogger(io.Discard, egv1a1.LogLevelInfo),
	}
	result, err := translator.Translate(t.Context(), resources)
	require.NoError(t, err)
	require.NotNil(t, result)

	report := (&ReferenceGrantAudit{InventoryComplete: true}).Audit(resources)

	translatedRoute := func(name string) *gwapiv1.HTTPRoute {
		for _, route := range result.HTTPRoutes {
			if route.Name == name {
				return route
			}
		}
		return nil
	}

	for _, edge := range report.Edges {
		switch edge.Kind {
		case AuditEdgeBackend:
			route := translatedRoute(edge.Source.Name)
			require.NotNil(t, route, "translated route %s missing", edge.Source.Name)
			translatorDenied := routeHasRefNotPermitted(t, route, edge.Target.Namespace, edge.Target.Name)
			auditDenied := edge.Verdict == AuditVerdictDenied && edge.Reason == AuditReasonRefNotPermitted
			require.Equal(t, translatorDenied, auditDenied,
				"audit/translator disagreement on %s %s", edge.Source.Name, edge.Section.Description)
		case AuditEdgeCertificate:
			gateway := result.Gateways[0]
			translatorDenied := listenerHasRefNotPermitted(t, gateway, edge.Section.ListenerName, edge.Target.Name)
			auditDenied := edge.Verdict == AuditVerdictDenied && edge.Reason == AuditReasonRefNotPermitted
			require.Equal(t, translatorDenied, auditDenied,
				"audit/translator disagreement on certificate %s", edge.Section.Description)
		}
	}

	// Explicit per-edge assertions on top of the loop invariant.
	allowedRoute := findAuditEdge(t, report, "route-allowed", "rule[0].backendRef[0]")
	require.Equal(t, AuditVerdictAllowed, allowedRoute.Verdict)
	deniedRoute := findAuditEdge(t, report, "route-denied", "rule[0].backendRef[0]")
	require.Equal(t, AuditVerdictDenied, deniedRoute.Verdict)
	require.Equal(t, AuditReasonRefNotPermitted, deniedRoute.Reason)

	allowedCert := findAuditEdge(t, report, "gw", "listener[https].certificateRef[0]")
	require.Equal(t, AuditVerdictAllowed, allowedCert.Verdict)
	deniedCert := findAuditEdge(t, report, "gw", "listener[https].certificateRef[1]")
	require.Equal(t, AuditVerdictDenied, deniedCert.Verdict)
	require.Equal(t, AuditReasonRefNotPermitted, deniedCert.Reason)
}
