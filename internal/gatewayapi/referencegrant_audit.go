// Copyright Envoy Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package gatewayapi

import (
	"cmp"
	"fmt"
	"slices"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"
	gwapiv1b1 "sigs.k8s.io/gateway-api/apis/v1beta1"

	egv1a1 "github.com/envoyproxy/gateway/api/v1alpha1"
	"github.com/envoyproxy/gateway/internal/gatewayapi/resource"
)

// AuditEdgeKind classifies a reference audited by ReferenceGrantAudit.
type AuditEdgeKind string

const (
	// AuditEdgeBackend is a backend reference (Service, ServiceImport, Backend or an
	// extension backend) used by a Route.
	AuditEdgeBackend AuditEdgeKind = "Backend"
	// AuditEdgeCertificate is a certificate reference (Secret or an extension secret
	// kind) used by a Gateway listener, a ListenerSet listener or a Gateway backend TLS
	// client certificate.
	AuditEdgeCertificate AuditEdgeKind = "Certificate"
)

// AuditVerdict is the per-edge authorization verdict.
type AuditVerdict string

const (
	// AuditVerdictAllowed means the reference is permitted and the target object is
	// present in the supplied inventory.
	AuditVerdictAllowed AuditVerdict = "Allowed"
	// AuditVerdictDenied means the reference is rejected, either because no
	// ReferenceGrant permits it or because the target of an otherwise permitted
	// reference is provably absent from a complete inventory.
	AuditVerdictDenied AuditVerdict = "Denied"
	// AuditVerdictUnknown means the grant decision is settled but the target cannot be
	// proven present or absent from an inventory that is not known to be complete.
	AuditVerdictUnknown AuditVerdict = "Unknown"
)

// AuditReason is the machine-readable explanation of an AuditVerdict.
type AuditReason string

const (
	// AuditReasonSameNamespace marks same-namespace references, which need no
	// ReferenceGrant by the Gateway API protocol.
	AuditReasonSameNamespace AuditReason = "SameNamespace"
	// AuditReasonGranted marks a cross-namespace reference permitted by at least one
	// ReferenceGrant.
	AuditReasonGranted AuditReason = "Granted"
	// AuditReasonRefNotPermitted mirrors the translator's RefNotPermitted failure: no
	// ReferenceGrant authorizes the cross-namespace reference.
	AuditReasonRefNotPermitted AuditReason = "RefNotPermitted"
	// AuditReasonTargetNotFound marks a permitted reference whose target object is
	// absent from a provably complete inventory.
	AuditReasonTargetNotFound AuditReason = "TargetNotFound"
	// AuditReasonTargetNotInInventory marks a permitted reference whose target cannot
	// be located in an inventory that is not proven complete.
	AuditReasonTargetNotInInventory AuditReason = "TargetNotInInventory"
)

// GrantMatchBranch is the testable per-grant explanation branch. The branches use the
// same field comparisons as isCrossNamespaceReferencePermitted, which remains the single
// source of truth for the allow/deny decision.
type GrantMatchBranch string

const (
	// GrantBranchMatched means the grant's spec.from and spec.to both match the edge.
	GrantBranchMatched GrantMatchBranch = "Matched"
	// GrantBranchInOtherNamespace means the grant lives in a different namespace than
	// the target and therefore can never authorize the edge, regardless of its name.
	GrantBranchInOtherNamespace GrantMatchBranch = "GrantInOtherNamespace"
	// GrantBranchFromNotMatched means the grant is in the target namespace but none of
	// its spec.from entries matches the referrer identity.
	GrantBranchFromNotMatched GrantMatchBranch = "FromNotMatched"
	// GrantBranchToNotMatched means a spec.from entry matches but no spec.to entry
	// matches the target group/kind/name.
	GrantBranchToNotMatched GrantMatchBranch = "ToNotMatched"
)

// GrantRemovalEffect is the limited, in-memory result of hypothetically removing one
// matching grant. No grant is ever deleted.
type GrantRemovalEffect string

const (
	// GrantRemovalRequired means the edge would be denied without the grant.
	GrantRemovalRequired GrantRemovalEffect = "Required"
	// GrantRemovalRedundant means alternative grants keep the edge permitted without
	// the grant.
	GrantRemovalRedundant GrantRemovalEffect = "Redundant"
)

// AuditObjectIdentity identifies a Kubernetes object without carrying its payload.
// Secret data is never included in an audit report.
type AuditObjectIdentity struct {
	Group      string    `json:"group" yaml:"group"`
	Kind       string    `json:"kind" yaml:"kind"`
	Namespace  string    `json:"namespace" yaml:"namespace"`
	Name       string    `json:"name" yaml:"name"`
	UID        types.UID `json:"uid,omitempty" yaml:"uid,omitempty"`
	Generation int64     `json:"generation,omitempty" yaml:"generation,omitempty"`
}

// AuditSection pinpoints where a reference is declared inside its source object.
// Negative sentinel indexes mean the field does not apply to the edge.
type AuditSection struct {
	// Description is the stable textual path of the reference, e.g.
	// "rule[0].backendRef[1]" or "listener[https].certificateRef[0]".
	Description string `json:"description" yaml:"description"`
	// RuleIndex is the route rule index, -1 when not a route rule reference.
	RuleIndex int `json:"ruleIndex" yaml:"ruleIndex"`
	// RuleName is the optional route rule name.
	RuleName string `json:"ruleName,omitempty" yaml:"ruleName,omitempty"`
	// BackendRefIndex is the backendRef index within a route rule, -1 when N/A.
	BackendRefIndex int `json:"backendRefIndex" yaml:"backendRefIndex"`
	// FilterIndex is the route rule filter index of a RequestMirror backendRef, -1
	// when N/A.
	FilterIndex int `json:"filterIndex" yaml:"filterIndex"`
	// ListenerName is the Gateway listener or ListenerSet listener entry name.
	ListenerName string `json:"listenerName,omitempty" yaml:"listenerName,omitempty"`
	// CertificateRefIndex is the tls.certificateRefs index, -1 when N/A.
	CertificateRefIndex int `json:"certificateRefIndex" yaml:"certificateRefIndex"`
}

// AuditTarget is the fully resolved identity of the referenced object. Only metadata is
// exposed; Secret contents are never read.
type AuditTarget struct {
	AuditObjectIdentity `json:",inline" yaml:",inline"`
	// Found reports whether the target object exists in the supplied inventory.
	Found bool `json:"found" yaml:"found"`
}

// GrantEvidence is one entry of the normalized minimal set of ReferenceGrants that
// actually authorize an edge. Non-matching grants never appear here.
type GrantEvidence struct {
	Namespace string    `json:"namespace" yaml:"namespace"`
	Name      string    `json:"name" yaml:"name"`
	UID       types.UID `json:"uid,omitempty" yaml:"uid,omitempty"`
	// FromEntries holds the matched 0-based spec.from entry indexes.
	FromEntries []int `json:"fromEntries" yaml:"fromEntries"`
	// ToEntries holds the matched 0-based spec.to entry indexes.
	ToEntries []int `json:"toEntries" yaml:"toEntries"`
	// NameScoped is true when every matching spec.to entry pins a concrete name rather
	// than covering all resources of the group/kind.
	NameScoped bool `json:"nameScoped" yaml:"nameScoped"`
}

// GrantExplanation records why a single input ReferenceGrant does or does not match an
// edge, giving every explanation branch a deterministic, testable outcome.
type GrantExplanation struct {
	Grant  AuditObjectIdentity `json:"grant" yaml:"grant"`
	Branch GrantMatchBranch    `json:"branch" yaml:"branch"`
	// Detail carries a stable explanation of the branch.
	Detail string `json:"detail,omitempty" yaml:"detail,omitempty"`
	// FromEntries and ToEntries are populated only for GrantBranchMatched and
	// GrantBranchToNotMatched (which still has a matched spec.from side).
	FromEntries []int `json:"fromEntries,omitempty" yaml:"fromEntries,omitempty"`
	ToEntries   []int `json:"toEntries,omitempty" yaml:"toEntries,omitempty"`
	// NameScoped is populated only for GrantBranchMatched.
	NameScoped bool `json:"nameScoped,omitempty" yaml:"nameScoped,omitempty"`
}

// GrantDependency describes what happens to an edge if one matching grant is
// hypothetically removed from the in-memory input.
type GrantDependency struct {
	Grant  AuditObjectIdentity `json:"grant" yaml:"grant"`
	Effect GrantRemovalEffect  `json:"effect" yaml:"effect"`
}

// AuditEdge is one audited reference with its verdict, evidence and bounded dependency
// analysis.
type AuditEdge struct {
	// Kind is Backend or Certificate.
	Kind AuditEdgeKind `json:"kind" yaml:"kind"`
	// Source is the referrer object, including UID and generation.
	Source AuditObjectIdentity `json:"source" yaml:"source"`
	// Section pinpoints the reference inside the source object.
	Section AuditSection `json:"section" yaml:"section"`
	// Target is the referenced object identity.
	Target AuditTarget `json:"target" yaml:"target"`
	// CrossNamespace is true when source and target namespaces differ.
	CrossNamespace bool `json:"crossNamespace" yaml:"crossNamespace"`
	// Verdict is Allowed, Denied or Unknown.
	Verdict AuditVerdict `json:"verdict" yaml:"verdict"`
	// Reason is the machine-readable explanation of the verdict.
	Reason AuditReason `json:"reason" yaml:"reason"`
	// Message is a stable human-readable description.
	Message string `json:"message,omitempty" yaml:"message,omitempty"`
	// GrantEvidence is the normalized minimal set of grants actually matching the edge.
	// It is empty for same-namespace references, which need no grant.
	GrantEvidence []GrantEvidence `json:"grantEvidence,omitempty" yaml:"grantEvidence,omitempty"`
	// ConsideredGrants explains every input grant against this edge, including grants
	// in other namespaces that must not authorize it.
	ConsideredGrants []GrantExplanation `json:"consideredGrants,omitempty" yaml:"consideredGrants,omitempty"`
	// Dependencies is the bounded removal analysis for the matching grants.
	Dependencies []GrantDependency `json:"dependencies,omitempty" yaml:"dependencies,omitempty"`
}

// ReferenceGrantAuditReport is the deterministic result of a ReferenceGrantAudit run.
type ReferenceGrantAuditReport struct {
	// InventoryComplete mirrors the audit configuration used to produce this report.
	InventoryComplete bool `json:"inventoryComplete" yaml:"inventoryComplete"`
	// Edges is the sorted, finite set of audited references.
	Edges []AuditEdge `json:"edges" yaml:"edges"`
}

// ReferenceGrantAudit enumerates the finite set of backend and certificate references
// used by the Gateways and Routes in a fixed *resource.Resources snapshot and audits
// each reference against the snapshot's ReferenceGrants.
//
// The audit is strictly read-only: it performs no Kubernetes writes, changes no object
// status and never reads Secret payloads. The allow/deny decision is always taken from
// the translator's real predicate, isCrossNamespaceReferencePermitted.
type ReferenceGrantAudit struct {
	// InventoryComplete declares that the input *resource.Resources is a complete
	// snapshot of every object of the kinds the translator watches. When false (the
	// safe default), a permitted reference whose target is absent is reported Unknown
	// instead of a definitive TargetNotFound denial.
	InventoryComplete bool
}

// auditedBackendRef is the flattened shape of every route backend reference, including
// RequestMirror filter backends, which converge on the same grant predicate.
type auditedBackendRef struct {
	ruleIndex    int
	ruleName     string
	backendIndex int
	filterIndex  int
	ref          gwapiv1.BackendObjectReference
}

// Audit runs the read-only reference grant audit over the supplied resources.
func (a *ReferenceGrantAudit) Audit(resources *resource.Resources) *ReferenceGrantAuditReport {
	report := &ReferenceGrantAuditReport{
		InventoryComplete: a.InventoryComplete,
		Edges:             []AuditEdge{},
	}
	if resources == nil {
		return report
	}

	edges := make([]AuditEdge, 0)

	// Certificate references declared on Gateways: listener TLS certificate refs and
	// the backend TLS client certificate ref.
	for _, gateway := range resources.Gateways {
		if gateway == nil {
			continue
		}
		source := objectIdentity(gwapiv1.GroupName, resource.KindGateway, gateway)
		a.appendGatewayListenerCertificateEdges(&edges, source, gateway.Spec.Listeners, gateway.GetNamespace())
		a.appendGatewayClientCertificateEdge(&edges, source, gateway)
	}

	// Certificate references declared on ListenerSets, whose from-identity is the
	// ListenerSet rather than the Gateway.
	for _, listenerSet := range resources.ListenerSets {
		if listenerSet == nil {
			continue
		}
		source := objectIdentity(gwapiv1.GroupVersion.Group, resource.KindListenerSet, listenerSet)
		for _, listener := range listenerSet.Spec.Listeners {
			if listener.TLS == nil {
				continue
			}
			for certIndex, certRef := range listener.TLS.CertificateRefs {
				group, kind := secretRefGroupKind(certRef)
				edges = append(edges, a.newEdge(
					AuditEdgeCertificate, source,
					AuditSection{
						Description:         fmt.Sprintf("listenerSet[%s].listener[%s].certificateRef[%d]", listenerSet.Name, listener.Name, certIndex),
						RuleIndex:           -1,
						BackendRefIndex:     -1,
						FilterIndex:         -1,
						CertificateRefIndex: certIndex,
						ListenerName:        string(listener.Name),
					},
					group, kind, certRef.Namespace, string(certRef.Name), listenerSet.GetNamespace(),
				))
			}
		}
	}

	// Backend references declared on every route kind.
	for _, route := range resources.HTTPRoutes {
		if route == nil {
			continue
		}
		source := objectIdentity(gwapiv1.GroupName, resource.KindHTTPRoute, route)
		a.appendRouteBackendEdges(&edges, source, httpRouteBackendRefs(route), route.GetNamespace())
	}
	for _, route := range resources.GRPCRoutes {
		if route == nil {
			continue
		}
		source := objectIdentity(gwapiv1.GroupName, resource.KindGRPCRoute, route)
		a.appendRouteBackendEdges(&edges, source, grpcRouteBackendRefs(route), route.GetNamespace())
	}
	for _, route := range resources.TLSRoutes {
		if route == nil {
			continue
		}
		source := objectIdentity(gwapiv1.GroupName, resource.KindTLSRoute, route)
		a.appendRouteBackendEdges(&edges, source, tlsRouteBackendRefs(route.Spec.Rules), route.GetNamespace())
	}
	for _, route := range resources.TCPRoutes {
		if route == nil {
			continue
		}
		source := objectIdentity(gwapiv1.GroupName, resource.KindTCPRoute, route)
		a.appendRouteBackendEdges(&edges, source, tcpRouteBackendRefs(route.Spec.Rules), route.GetNamespace())
	}
	for _, route := range resources.UDPRoutes {
		if route == nil {
			continue
		}
		source := objectIdentity(gwapiv1.GroupName, resource.KindUDPRoute, route)
		a.appendRouteBackendEdges(&edges, source, udpRouteBackendRefs(route.Spec.Rules), route.GetNamespace())
	}

	for index := range edges {
		edges[index] = a.evaluateEdge(edges[index], resources)
	}

	slices.SortFunc(edges, compareAuditEdge)
	report.Edges = edges
	return report
}

// appendGatewayListenerCertificateEdges enumerates a Gateway listener's TLS
// certificateRefs using the same group/kind defaulting as the translator.
func (a *ReferenceGrantAudit) appendGatewayListenerCertificateEdges(
	edges *[]AuditEdge, source AuditObjectIdentity, listeners []gwapiv1.Listener, gatewayNamespace string,
) {
	for _, listener := range listeners {
		if listener.TLS == nil {
			continue
		}
		for certIndex, certRef := range listener.TLS.CertificateRefs {
			group, kind := secretRefGroupKind(certRef)
			*edges = append(*edges, a.newEdge(
				AuditEdgeCertificate, source,
				AuditSection{
					Description:         fmt.Sprintf("listener[%s].certificateRef[%d]", listener.Name, certIndex),
					RuleIndex:           -1,
					BackendRefIndex:     -1,
					FilterIndex:         -1,
					CertificateRefIndex: certIndex,
					ListenerName:        string(listener.Name),
				},
				group, kind, certRef.Namespace, string(certRef.Name), gatewayNamespace,
			))
		}
	}
}

// appendGatewayClientCertificateEdge enumerates the optional backend TLS
// clientCertificateRef, which is checked with the same predicate in listener
// translation.
func (a *ReferenceGrantAudit) appendGatewayClientCertificateEdge(edges *[]AuditEdge, source AuditObjectIdentity, gateway *gwapiv1.Gateway) {
	if gateway.Spec.TLS == nil || gateway.Spec.TLS.Backend == nil || gateway.Spec.TLS.Backend.ClientCertificateRef == nil {
		return
	}
	ref := gateway.Spec.TLS.Backend.ClientCertificateRef
	group := GroupDerefOr(ref.Group, "")
	kind := KindDerefOr(ref.Kind, resource.KindSecret)
	*edges = append(*edges, a.newEdge(
		AuditEdgeCertificate, source,
		AuditSection{
			Description:         "tls.backend.clientCertificateRef",
			RuleIndex:           -1,
			BackendRefIndex:     -1,
			FilterIndex:         -1,
			CertificateRefIndex: -1,
		},
		group, kind, ref.Namespace, string(ref.Name), gateway.GetNamespace(),
	))
}

// appendRouteBackendEdges turns flattened route backend refs into audit edges,
// preserving the exact to group/kind/namespace defaulting of validateBackendNamespace.
func (a *ReferenceGrantAudit) appendRouteBackendEdges(
	edges *[]AuditEdge, source AuditObjectIdentity, refs []auditedBackendRef, routeNamespace string,
) {
	for _, backendRef := range refs {
		group := GroupDerefOr(backendRef.ref.Group, "")
		kind := KindDerefOr(backendRef.ref.Kind, resource.KindService)

		description := fmt.Sprintf("rule[%d].backendRef[%d]", backendRef.ruleIndex, backendRef.backendIndex)
		if backendRef.filterIndex >= 0 {
			description = fmt.Sprintf("rule[%d].filter[%d].requestMirror.backendRef", backendRef.ruleIndex, backendRef.filterIndex)
		}

		*edges = append(*edges, a.newEdge(
			AuditEdgeBackend, source,
			AuditSection{
				Description:         description,
				RuleIndex:           backendRef.ruleIndex,
				RuleName:            backendRef.ruleName,
				BackendRefIndex:     backendRef.backendIndex,
				FilterIndex:         backendRef.filterIndex,
				CertificateRefIndex: -1,
			},
			group, kind, backendRef.ref.Namespace, string(backendRef.ref.Name), routeNamespace,
		))
	}
}

// newEdge constructs an edge and resolves whether it crosses a namespace.
func (a *ReferenceGrantAudit) newEdge(
	kind AuditEdgeKind, source AuditObjectIdentity, section AuditSection,
	group, targetKind string, namespace *gwapiv1.Namespace, name, sourceNamespace string,
) AuditEdge {
	targetNamespace := NamespaceDerefOr(namespace, sourceNamespace)
	return AuditEdge{
		Kind:    kind,
		Source:  source,
		Section: section,
		Target: AuditTarget{
			AuditObjectIdentity: AuditObjectIdentity{
				Group:     group,
				Kind:      targetKind,
				Namespace: targetNamespace,
				Name:      name,
			},
		},
		CrossNamespace: targetNamespace != sourceNamespace,
	}
}

// evaluateEdge resolves the verdict for one edge. The cross-namespace allow/deny boolean
// is always read from isCrossNamespaceReferencePermitted; the explanation machinery only
// describes that decision and never widens it.
func (a *ReferenceGrantAudit) evaluateEdge(edge AuditEdge, resources *resource.Resources) AuditEdge {
	from := crossNamespaceFrom{
		group:     edge.Source.Group,
		kind:      edge.Source.Kind,
		namespace: edge.Source.Namespace,
	}
	to := crossNamespaceTo{
		group:     edge.Target.Group,
		kind:      edge.Target.Kind,
		namespace: edge.Target.Namespace,
		name:      edge.Target.Name,
	}

	if !edge.CrossNamespace {
		// Same-namespace references are permitted by the protocol itself; no grant is
		// required and none is fabricated.
		edge.Reason = AuditReasonSameNamespace
		edge.Message = "reference is within the same namespace and needs no ReferenceGrant"
		a.resolveTarget(&edge, resources)
		return edge
	}

	edge.ConsideredGrants = explainReferenceGrants(from, to, resources.ReferenceGrants)
	edge.GrantEvidence = matchingGrantEvidence(edge.ConsideredGrants)

	permitted := isCrossNamespaceReferencePermitted(from, to, resources.ReferenceGrants)
	if !permitted {
		edge.Verdict = AuditVerdictDenied
		edge.Reason = AuditReasonRefNotPermitted
		edge.Message = fmt.Sprintf(
			"cross-namespace reference from %s %s/%s to %s %s/%s is not permitted by any ReferenceGrant",
			edge.Source.Kind, edge.Source.Namespace, edge.Source.Name,
			edge.Target.Kind, edge.Target.Namespace, edge.Target.Name,
		)
		return edge
	}

	edge.Reason = AuditReasonGranted
	edge.Message = "cross-namespace reference is permitted by a ReferenceGrant"
	edge.Dependencies = analyzeGrantDependencies(from, to, resources.ReferenceGrants, edge.GrantEvidence)
	a.resolveTarget(&edge, resources)
	return edge
}

// resolveTarget checks target presence using only object metadata and applies the
// inventory-completeness semantics. Secret payloads are never accessed.
func (a *ReferenceGrantAudit) resolveTarget(edge *AuditEdge, resources *resource.Resources) {
	uid, found, authoritative := a.lookupTarget(edge.Target.Group, edge.Target.Kind, edge.Target.Namespace, edge.Target.Name, resources)
	edge.Target.Found = found
	edge.Target.UID = uid

	if found {
		edge.Verdict = AuditVerdictAllowed
		return
	}

	if a.InventoryComplete && authoritative {
		edge.Verdict = AuditVerdictDenied
		edge.Reason = AuditReasonTargetNotFound
		edge.Message = fmt.Sprintf(
			"target %s %s/%s is absent from the complete resource inventory",
			edge.Target.Kind, edge.Target.Namespace, edge.Target.Name,
		)
		return
	}

	edge.Verdict = AuditVerdictUnknown
	edge.Reason = AuditReasonTargetNotInInventory
	edge.Message = fmt.Sprintf(
		"target %s %s/%s cannot be proven present or absent from the supplied resource inventory",
		edge.Target.Kind, edge.Target.Namespace, edge.Target.Name,
	)
}

// lookupTarget returns the target UID, presence and whether the inventory can answer
// authoritatively for this group/kind. A non-authoritative answer never turns into a
// hard NotFound denial.
func (a *ReferenceGrantAudit) lookupTarget(
	group, kind, namespace, name string, resources *resource.Resources,
) (types.UID, bool, bool) {
	switch kind {
	case resource.KindService:
		for _, service := range resources.Services {
			if service != nil && service.Namespace == namespace && service.Name == name {
				return service.UID, true, true
			}
		}
		return "", false, true
	case resource.KindServiceImport:
		for _, serviceImport := range resources.ServiceImports {
			if serviceImport != nil && serviceImport.Namespace == namespace && serviceImport.Name == name {
				return serviceImport.UID, true, true
			}
		}
		return "", false, true
	case egv1a1.KindBackend:
		for _, backend := range resources.Backends {
			if backend != nil && backend.Namespace == namespace && backend.Name == name {
				return backend.UID, true, true
			}
		}
		return "", false, true
	case resource.KindSecret:
		// Only metadata is inspected; the Secret data is never exposed.
		for _, secret := range resources.Secrets {
			if secret != nil && secret.Namespace == namespace && secret.Name == name {
				return secret.UID, true, true
			}
		}
		return "", false, true
	default:
		return lookupExtensionTarget(group, kind, namespace, name, resources)
	}
}

// lookupExtensionTarget covers extension-registered secret and backend kinds. The
// inventory is authoritative for a group/kind only when it demonstrably tracks at least
// one object of that group/kind.
func lookupExtensionTarget(
	group, kind, namespace, name string, resources *resource.Resources,
) (types.UID, bool, bool) {
	tracked := false

	for index := range resources.ExtensionSecrets {
		obj := &resources.ExtensionSecrets[index]
		gvk := obj.GroupVersionKind()
		if gvk.Group != group || gvk.Kind != kind {
			continue
		}
		tracked = true
		if obj.GetNamespace() == namespace && obj.GetName() == name {
			return obj.GetUID(), true, true
		}
	}
	for index := range resources.ExtensionRefFilters {
		obj := &resources.ExtensionRefFilters[index]
		gvk := obj.GroupVersionKind()
		if gvk.Group != group || gvk.Kind != kind {
			continue
		}
		tracked = true
		if obj.GetNamespace() == namespace && obj.GetName() == name {
			return obj.GetUID(), true, true
		}
	}

	return "", false, tracked
}

// explainReferenceGrants classifies every input grant for one edge using the exact
// comparison rules of isCrossNamespaceReferencePermitted.
func explainReferenceGrants(
	from crossNamespaceFrom, to crossNamespaceTo, grants []*gwapiv1b1.ReferenceGrant,
) []GrantExplanation {
	explanations := make([]GrantExplanation, 0, len(grants))
	for _, grant := range grants {
		if grant == nil {
			continue
		}
		identity := objectIdentity(gwapiv1b1.GroupName, resource.KindReferenceGrant, grant)

		if grant.Namespace != to.namespace {
			explanations = append(explanations, GrantExplanation{
				Grant:  identity,
				Branch: GrantBranchInOtherNamespace,
				Detail: fmt.Sprintf(
					"grant is in namespace %q but only a grant in the target namespace %q can authorize the reference",
					grant.Namespace, to.namespace,
				),
			})
			continue
		}

		fromEntries := matchingFromEntries(from, grant.Spec.From)
		if len(fromEntries) == 0 {
			explanations = append(explanations, GrantExplanation{
				Grant:  identity,
				Branch: GrantBranchFromNotMatched,
				Detail: fmt.Sprintf(
					"no spec.from entry matches group=%q kind=%q namespace=%q",
					from.group, from.kind, from.namespace,
				),
			})
			continue
		}

		toEntries, nameScoped := matchingToEntries(to, grant.Spec.To)
		if len(toEntries) == 0 {
			explanations = append(explanations, GrantExplanation{
				Grant:       identity,
				Branch:      GrantBranchToNotMatched,
				FromEntries: slices.Clone(fromEntries),
				Detail: fmt.Sprintf(
					"spec.from matches but no spec.to entry matches group=%q kind=%q name=%q",
					to.group, to.kind, to.name,
				),
			})
			continue
		}

		explanations = append(explanations, GrantExplanation{
			Grant:       identity,
			Branch:      GrantBranchMatched,
			FromEntries: slices.Clone(fromEntries),
			ToEntries:   slices.Clone(toEntries),
			NameScoped:  nameScoped,
			Detail:      "spec.from and spec.to both match the reference",
		})
	}

	slices.SortFunc(explanations, func(a, b GrantExplanation) int {
		return cmp.Or(
			cmp.Compare(a.Grant.Namespace, b.Grant.Namespace),
			cmp.Compare(a.Grant.Name, b.Grant.Name),
		)
	})
	return explanations
}

// matchingFromEntries mirrors the from-side comparison of the translator predicate.
func matchingFromEntries(from crossNamespaceFrom, entries []gwapiv1b1.ReferenceGrantFrom) []int {
	matched := make([]int, 0)
	for index, entry := range entries {
		if string(entry.Namespace) == from.namespace &&
			string(entry.Group) == from.group &&
			string(entry.Kind) == from.kind {
			matched = append(matched, index)
		}
	}
	return matched
}

// matchingToEntries mirrors the to-side comparison of the translator predicate,
// including the optional name scoping.
func matchingToEntries(to crossNamespaceTo, entries []gwapiv1b1.ReferenceGrantTo) ([]int, bool) {
	matched := make([]int, 0)
	allNameScoped := true
	for index, entry := range entries {
		if string(entry.Group) != to.group || string(entry.Kind) != to.kind {
			continue
		}
		if entry.Name != nil && *entry.Name != "" && string(*entry.Name) != to.name {
			continue
		}
		matched = append(matched, index)
		if entry.Name == nil || *entry.Name == "" {
			allNameScoped = false
		}
	}
	return matched, len(matched) > 0 && allNameScoped
}

// matchingGrantEvidence reduces the per-grant explanations to the normalized minimal
// evidence set: each matching grant appears once, with sorted entry indexes, regardless
// of input ordering or duplicate grant entries.
func matchingGrantEvidence(explanations []GrantExplanation) []GrantEvidence {
	seen := make(map[string]struct{})
	evidence := make([]GrantEvidence, 0)
	for _, explanation := range explanations {
		if explanation.Branch != GrantBranchMatched {
			continue
		}
		key := explanation.Grant.Namespace + "/" + explanation.Grant.Name
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		evidence = append(evidence, GrantEvidence{
			Namespace:   explanation.Grant.Namespace,
			Name:        explanation.Grant.Name,
			UID:         explanation.Grant.UID,
			FromEntries: slices.Clone(explanation.FromEntries),
			ToEntries:   slices.Clone(explanation.ToEntries),
			NameScoped:  explanation.NameScoped,
		})
	}
	slices.SortFunc(evidence, func(a, b GrantEvidence) int {
		return cmp.Or(
			cmp.Compare(a.Namespace, b.Namespace),
			cmp.Compare(a.Name, b.Name),
		)
	})
	return evidence
}

// analyzeGrantDependencies computes, for each matching grant, whether the edge stays
// permitted when that grant is omitted from the in-memory list. No grant is deleted and
// no object outside the supplied Resources slice is inspected.
func analyzeGrantDependencies(
	from crossNamespaceFrom, to crossNamespaceTo,
	grants []*gwapiv1b1.ReferenceGrant, evidence []GrantEvidence,
) []GrantDependency {
	dependencies := make([]GrantDependency, 0, len(evidence))
	for _, item := range evidence {
		withoutGrant := make([]*gwapiv1b1.ReferenceGrant, 0, len(grants))
		for _, grant := range grants {
			if grant == nil {
				continue
			}
			if grant.Namespace == item.Namespace && grant.Name == item.Name {
				continue
			}
			withoutGrant = append(withoutGrant, grant)
		}

		effect := GrantRemovalRequired
		if isCrossNamespaceReferencePermitted(from, to, withoutGrant) {
			effect = GrantRemovalRedundant
		}
		dependencies = append(dependencies, GrantDependency{
			Grant: AuditObjectIdentity{
				Group:     gwapiv1b1.GroupName,
				Kind:      resource.KindReferenceGrant,
				Namespace: item.Namespace,
				Name:      item.Name,
				UID:       item.UID,
			},
			Effect: effect,
		})
	}
	return dependencies
}

// compareAuditEdge gives every report a canonical ordering independent of the input
// slice ordering.
func compareAuditEdge(a, b AuditEdge) int {
	return cmp.Or(
		cmp.Compare(a.Source.Namespace, b.Source.Namespace),
		cmp.Compare(a.Source.Kind, b.Source.Kind),
		cmp.Compare(a.Source.Name, b.Source.Name),
		cmp.Compare(string(a.Kind), string(b.Kind)),
		cmp.Compare(a.Section.Description, b.Section.Description),
		cmp.Compare(a.Target.Namespace, b.Target.Namespace),
		cmp.Compare(a.Target.Name, b.Target.Name),
	)
}

// objectIdentity builds an AuditObjectIdentity from object metadata.
func objectIdentity(group, kind string, obj metav1.Object) AuditObjectIdentity {
	return AuditObjectIdentity{
		Group:      group,
		Kind:       kind,
		Namespace:  obj.GetNamespace(),
		Name:       obj.GetName(),
		UID:        obj.GetUID(),
		Generation: obj.GetGeneration(),
	}
}

// secretRefGroupKind reproduces the translator's group/kind defaulting for a
// SecretObjectReference exactly.
func secretRefGroupKind(ref gwapiv1.SecretObjectReference) (group, kind string) {
	group, kind = "", resource.KindSecret
	if ref.Group != nil {
		group = string(*ref.Group)
	}
	if ref.Kind != nil && string(*ref.Kind) != "" {
		kind = string(*ref.Kind)
	}
	return group, kind
}

func sectionNameDeref(name *gwapiv1.SectionName) string {
	if name == nil {
		return ""
	}
	return string(*name)
}

// httpRouteBackendRefs flattens an HTTPRoute's rule backendRefs and RequestMirror
// filter backendRefs, both of which the translator authorizes through
// validateBackendNamespace.
func httpRouteBackendRefs(route *gwapiv1.HTTPRoute) []auditedBackendRef {
	refs := make([]auditedBackendRef, 0)
	for ruleIndex, rule := range route.Spec.Rules {
		for backendIndex, backendRef := range rule.BackendRefs {
			refs = append(refs, auditedBackendRef{
				ruleIndex:    ruleIndex,
				ruleName:     sectionNameDeref(rule.Name),
				backendIndex: backendIndex,
				filterIndex:  -1,
				ref:          backendRef.BackendObjectReference,
			})
		}
		for filterIndex, filter := range rule.Filters {
			if filter.Type != gwapiv1.HTTPRouteFilterRequestMirror || filter.RequestMirror == nil {
				continue
			}
			refs = append(refs, auditedBackendRef{
				ruleIndex:    ruleIndex,
				ruleName:     sectionNameDeref(rule.Name),
				backendIndex: -1,
				filterIndex:  filterIndex,
				ref:          filter.RequestMirror.BackendRef,
			})
		}
	}
	return refs
}

// grpcRouteBackendRefs flattens a GRPCRoute's rule backendRefs and RequestMirror filter
// backendRefs.
func grpcRouteBackendRefs(route *gwapiv1.GRPCRoute) []auditedBackendRef {
	refs := make([]auditedBackendRef, 0)
	for ruleIndex, rule := range route.Spec.Rules {
		for backendIndex, backendRef := range rule.BackendRefs {
			refs = append(refs, auditedBackendRef{
				ruleIndex:    ruleIndex,
				ruleName:     sectionNameDeref(rule.Name),
				backendIndex: backendIndex,
				filterIndex:  -1,
				ref:          backendRef.BackendObjectReference,
			})
		}
		for filterIndex, filter := range rule.Filters {
			if filter.Type != gwapiv1.GRPCRouteFilterRequestMirror || filter.RequestMirror == nil {
				continue
			}
			refs = append(refs, auditedBackendRef{
				ruleIndex:    ruleIndex,
				ruleName:     sectionNameDeref(rule.Name),
				backendIndex: -1,
				filterIndex:  filterIndex,
				ref:          filter.RequestMirror.BackendRef,
			})
		}
	}
	return refs
}

// tlsRouteBackendRefs flattens a TLSRoute's rule backendRefs.
func tlsRouteBackendRefs(rules []gwapiv1.TLSRouteRule) []auditedBackendRef {
	refs := make([]auditedBackendRef, 0)
	for ruleIndex, rule := range rules {
		appendL4BackendRefs(&refs, ruleIndex, sectionNameDeref(rule.Name), rule.BackendRefs)
	}
	return refs
}

// tcpRouteBackendRefs flattens a TCPRoute's rule backendRefs.
func tcpRouteBackendRefs(rules []gwapiv1.TCPRouteRule) []auditedBackendRef {
	refs := make([]auditedBackendRef, 0)
	for ruleIndex, rule := range rules {
		appendL4BackendRefs(&refs, ruleIndex, sectionNameDeref(rule.Name), rule.BackendRefs)
	}
	return refs
}

// udpRouteBackendRefs flattens a UDPRoute's rule backendRefs.
func udpRouteBackendRefs(rules []gwapiv1.UDPRouteRule) []auditedBackendRef {
	refs := make([]auditedBackendRef, 0)
	for ruleIndex, rule := range rules {
		appendL4BackendRefs(&refs, ruleIndex, sectionNameDeref(rule.Name), rule.BackendRefs)
	}
	return refs
}

func appendL4BackendRefs(refs *[]auditedBackendRef, ruleIndex int, ruleName string, backendRefs []gwapiv1.BackendRef) {
	for backendIndex, backendRef := range backendRefs {
		*refs = append(*refs, auditedBackendRef{
			ruleIndex:    ruleIndex,
			ruleName:     ruleName,
			backendIndex: backendIndex,
			filterIndex:  -1,
			ref:          backendRef.BackendObjectReference,
		})
	}
}
