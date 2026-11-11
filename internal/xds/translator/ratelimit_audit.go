// Copyright Envoy Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package translator

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"sort"
	"strings"

	xdscorev3 "github.com/cncf/xds/go/xds/core/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	matcherv3 "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	rlsconfv3 "github.com/envoyproxy/go-control-plane/ratelimit/config/ratelimit/v3"

	"github.com/envoyproxy/gateway/internal/ir"
)

// Bounds applied by RateLimitDescriptorAudit unless overridden. The audit is an
// offline, in-memory tool: the bounds keep both computation and serialized output
// finite regardless of the IR size or corpus length.
const (
	defaultAuditMaxRequests      = 64
	defaultAuditMaxRateLimits    = 256
	defaultAuditMaxActionEntries = 32
	defaultAuditMaxOutputBytes   = 1 << 20 // 1 MiB

	auditPhaseRequest  = "request"
	auditPhaseResponse = "response"
)

// AuditEntryStatus describes what a single Envoy rate-limit action contributes to
// the descriptor for one request.
type AuditEntryStatus string

const (
	// AuditEntryAppended means the action produced a descriptor entry.
	AuditEntryAppended AuditEntryStatus = "Appended"
	// AuditEntrySkipped means the action matched negatively and appended no entry,
	// while the remaining actions of the rate-limit configuration are still evaluated.
	AuditEntrySkipped AuditEntryStatus = "Skipped"
	// AuditEntryAborted means a required request value (header or query parameter) was
	// absent: Envoy skips the whole rate-limit configuration and makes no RLS call for it.
	AuditEntryAborted AuditEntryStatus = "Aborted"
	// AuditEntryUnknown means the action cannot be modeled statically (dynamic metadata,
	// filter state, an unsupported regex/format specifier, ...). The branch is neither
	// treated as a hit nor as a miss.
	AuditEntryUnknown AuditEntryStatus = "Unknown"
)

// AuditDescriptorStatus describes the descriptor produced by one Envoy rate-limit
// configuration (one entry of routev3.RateLimit) for one request.
type AuditDescriptorStatus string

const (
	// AuditDescriptorGenerated means all modeled actions were evaluated and a descriptor
	// entry sequence was produced (it may still resolve to NoMatch against the RLS tree).
	AuditDescriptorGenerated AuditDescriptorStatus = "Generated"
	// AuditDescriptorAborted means an action aborted the configuration, so Envoy would not
	// call the RLS at all for it.
	AuditDescriptorAborted AuditDescriptorStatus = "Aborted"
	// AuditDescriptorUnknown means at least one action is unmodeled; no hit/miss verdict is
	// emitted for this configuration.
	AuditDescriptorUnknown AuditDescriptorStatus = "Unknown"
)

// AuditResolutionStatus describes how a generated descriptor resolves against the
// real RLS descriptor tree.
type AuditResolutionStatus string

const (
	// AuditResolutionMatched means the descriptor walked the RLS tree to a leaf carrying a
	// rate-limit policy.
	AuditResolutionMatched AuditResolutionStatus = "Matched"
	// AuditResolutionNoMatch means the tree walk stopped without reaching a policy at the
	// final descriptor entry; no RLS policy bounds the request. It is a statement about the
	// supplied corpus, not about reachability in the general request language.
	AuditResolutionNoMatch AuditResolutionStatus = "NoMatch"
	// AuditResolutionUnknown means the RLS tree uses features the audit does not model
	// (e.g. wildcard descriptors), so the outcome cannot be determined.
	AuditResolutionUnknown AuditResolutionStatus = "Unknown"
	// AuditResolutionNotInvoked means no descriptor was generated in the first place.
	AuditResolutionNotInvoked AuditResolutionStatus = "NotInvoked"
)

// AuditCoverageStatus states whether a rule's enforcing descriptor was exercised by
// the supplied corpus. Unexercised rules are never reported as unreachable.
type AuditCoverageStatus string

const (
	AuditRuleExercised   AuditCoverageStatus = "Exercised"
	AuditRuleUnexercised AuditCoverageStatus = "Unexercised"
)

// AuditRequest is one element of the explicit, finite request corpus. The corpus is
// the only source of request values: the audit performs no network I/O and never
// reconstructs the client address from X-Forwarded-For or any other header. Header
// and query values are consumed in memory but never echoed in the report.
type AuditRequest struct {
	// ID identifies the request in the report.
	ID string
	// Method is the :method pseudo-header value, compared case-sensitively.
	Method string
	// Path is the :path pseudo-header value including the query string.
	Path string
	// Headers holds request header values keyed by header name. Names are matched
	// case-insensitively; values are matched case-sensitively unless the Envoy matcher
	// explicitly sets ignore_case.
	Headers map[string]string
	// TrustedClientIP is the already-trusted downstream remote address (host only, no
	// port), as established by the surrounding deployment. It is the sole input used by
	// remote-address actions; X-Forwarded-For strings in Headers are never parsed for it.
	TrustedClientIP string
}

// AuditActionEvidence is bounded, value-free evidence about one evaluated action.
type AuditActionEvidence struct {
	// Index is the zero-based position of the action within the rate-limit configuration.
	Index int `json:"index"`
	// Kind is the Envoy action kind, e.g. "GenericKey", "HeaderValueMatch".
	Kind string `json:"kind"`
	// DescriptorKey is the descriptor key the action would use.
	DescriptorKey string `json:"descriptorKey"`
	// Status is the per-action evaluation status.
	Status AuditEntryStatus `json:"status"`
	// ValueSource identifies where the descriptor value is taken from without exposing it:
	// "static", "header:<name>", "query:<name>" or "trusted-client-ip".
	ValueSource string `json:"valueSource,omitempty"`
	// Reason is a short, static explanation (no request values).
	Reason string `json:"reason,omitempty"`
}

// AuditDescriptorNode identifies one node of a matched RLS descriptor tree. Values
// are configuration values only; request-derived values never appear here.
type AuditDescriptorNode struct {
	Key        string `json:"key"`
	Value      string `json:"value"`
	ShadowMode bool   `json:"shadowMode"`
}

// AuditMatchedPolicy describes the RLS policy a descriptor resolved to.
type AuditMatchedPolicy struct {
	// DescriptorPath is the matched root-to-leaf RLS descriptor path.
	DescriptorPath []AuditDescriptorNode `json:"descriptorPath"`
	// RequestsPerUnit is the static policy quota.
	RequestsPerUnit uint32 `json:"requestsPerUnit"`
	// Unit is the RLS policy unit, e.g. "SECOND".
	Unit string `json:"unit"`
	// Unlimited mirrors the RLS policy unlimited flag.
	Unlimited bool `json:"unlimited"`
	// ShadowMode is the shadow attribute of the matched leaf descriptor.
	ShadowMode bool `json:"shadowMode"`
}

// AuditOverride records the source of the per-route limit override.
type AuditOverride struct {
	// Source is "none" or "dynamic-metadata".
	Source string `json:"source"`
	// Namespace and Key locate the dynamic metadata value. They are configuration data.
	Namespace string `json:"namespace,omitempty"`
	Key       string `json:"key,omitempty"`
	// EffectiveLimitKnown is false when the effective limit is resolved per request from
	// dynamic metadata and cannot be determined by the audit.
	EffectiveLimitKnown bool `json:"effectiveLimitKnown"`
}

// AuditHitsAddend records the hits_addend attached to the rate-limit configuration.
type AuditHitsAddend struct {
	// Source is "default" (Envoy implicit addend of 1), "static-number" or "format".
	Source string `json:"source"`
	// Number is the static addend when Source is "static-number".
	Number *uint64 `json:"number,omitempty"`
	// RuntimeResolved is true when the addend is computed at runtime from a format
	// specifier and its value cannot be known offline.
	RuntimeResolved bool `json:"runtimeResolved,omitempty"`
}

// AuditRateLimitResult is the audit outcome for one request and one Envoy
// rate-limit configuration.
type AuditRateLimitResult struct {
	RequestID string `json:"requestId"`
	// ListenerName and RouteName identify the owning xDS entities.
	ListenerName string `json:"listenerName"`
	RouteName    string `json:"routeName"`
	// Domain is the RLS/HCM filter domain the configuration belongs to.
	Domain string `json:"domain"`
	// RuleName, GlobalRuleIndex and DomainRuleIndex identify the IR rate-limit rule.
	// They are empty when the audit is fed anonymous final-Envoy configurations.
	RuleName        string `json:"ruleName,omitempty"`
	GlobalRuleIndex int    `json:"globalRuleIndex,omitempty"`
	DomainRuleIndex int    `json:"domainRuleIndex,omitempty"`
	// Shared and ShadowMode mirror the IR rule attributes under audit.
	Shared     bool `json:"shared"`
	ShadowMode bool `json:"shadowMode"`
	// Phase is "request" or "response" (ApplyOnStreamDone, never enforced on the request path).
	Phase string `json:"phase"`
	// XRatelimitOption is the per-configuration X-RateLimit header option name.
	XRatelimitOption string `json:"xRatelimitOption,omitempty"`

	DescriptorStatus AuditDescriptorStatus `json:"descriptorStatus"`
	// Actions holds bounded per-action evidence.
	Actions []AuditActionEvidence `json:"actions"`
	// DescriptorKeys lists the keys of appended entries in order. It never contains
	// request-derived values.
	DescriptorKeys []string `json:"descriptorKeys,omitempty"`

	Resolution    AuditResolutionStatus `json:"resolution"`
	MatchedPolicy *AuditMatchedPolicy   `json:"matchedPolicy,omitempty"`
	// UnknownReasons lists why an outcome cannot be determined statically.
	UnknownReasons []string `json:"unknownReasons,omitempty"`
	// Findings lists cross-check discrepancies between the route configuration, IR rule
	// attributes and RLS tree (bounded, static messages).
	Findings []string `json:"findings,omitempty"`

	HitsAddend AuditHitsAddend `json:"hitsAddend"`
	Override   AuditOverride   `json:"override"`

	// Enforcing is true only when a request-phase descriptor resolves to an enforcing
	// (non-shadow) RLS policy whose effective limit is statically known. It means the
	// descriptor is a candidate for enforcement; the audit performs no counter evaluation
	// and never emits an allow/over-limit verdict. Shadow and stream-done configurations
	// are never enforcing.
	Enforcing bool `json:"enforcing"`
}

// AuditRuleCoverage states whether each rule was exercised by the corpus.
type AuditRuleCoverage struct {
	ListenerName    string              `json:"listenerName"`
	RouteName       string              `json:"routeName"`
	RuleName        string              `json:"ruleName"`
	Domain          string              `json:"domain"`
	GlobalRuleIndex int                 `json:"globalRuleIndex"`
	DomainRuleIndex int                 `json:"domainRuleIndex"`
	Shared          bool                `json:"shared"`
	Shadow          bool                `json:"shadow"`
	Status          AuditCoverageStatus `json:"status"`
	// ExercisedBy lists request IDs that matched the rule descriptor, bounded in size.
	ExercisedBy []string `json:"exercisedBy,omitempty"`
}

// AuditReport is the bounded, value-redacted audit output.
type AuditReport struct {
	// Results contains one entry per (request, rate-limit configuration) pair that fit
	// within the configured bounds.
	Results []AuditRateLimitResult `json:"results"`
	// RuleCoverage covers every rule seen by the audit; corpus-uncovered rules are
	// reported as Unexercised, never as unreachable.
	RuleCoverage []AuditRuleCoverage `json:"ruleCoverage"`
	// Truncated is true when result entries had to be dropped to honor MaxOutputBytes.
	Truncated bool `json:"truncated,omitempty"`
}

// AuditOption customizes RateLimitDescriptorAudit bounds.
type AuditOption func(*RateLimitDescriptorAudit)

// AuditWithMaxRequests overrides the maximum corpus size.
func AuditWithMaxRequests(n int) AuditOption {
	return func(a *RateLimitDescriptorAudit) { a.maxRequests = n }
}

// AuditWithMaxRateLimits overrides the maximum number of rate-limit configurations
// evaluated per request across all routes and domains.
func AuditWithMaxRateLimits(n int) AuditOption {
	return func(a *RateLimitDescriptorAudit) { a.maxRateLimits = n }
}

// AuditWithMaxActionEntries overrides the maximum number of actions accepted per
// rate-limit configuration.
func AuditWithMaxActionEntries(n int) AuditOption {
	return func(a *RateLimitDescriptorAudit) { a.maxActionEntries = n }
}

// AuditWithMaxOutputBytes overrides the maximum serialized report size.
func AuditWithMaxOutputBytes(n int) AuditOption {
	return func(a *RateLimitDescriptorAudit) { a.maxOutputBytes = n }
}

// RateLimitDescriptorAudit generates rate-limit descriptor sequences for an explicit
// finite request corpus and checks them against the real RLS descriptor
// configuration. It reuses the production builders (BuildRateLimitServiceConfig and
// buildRouteRateLimits) and implements the semantics of the Envoy rate-limit actions
// EG emits. It is purely in-memory: no HTTP calls are made and no rate-limit counters
// are read or written.
type RateLimitDescriptorAudit struct {
	maxRequests      int
	maxRateLimits    int
	maxActionEntries int
	maxOutputBytes   int
}

// NewRateLimitDescriptorAudit builds an auditor with the given bound overrides.
func NewRateLimitDescriptorAudit(opts ...AuditOption) *RateLimitDescriptorAudit {
	a := &RateLimitDescriptorAudit{
		maxRequests:      defaultAuditMaxRequests,
		maxRateLimits:    defaultAuditMaxRateLimits,
		maxActionEntries: defaultAuditMaxActionEntries,
		maxOutputBytes:   defaultAuditMaxOutputBytes,
	}
	for _, opt := range opts {
		opt(a)
	}
	return a
}

func (a *RateLimitDescriptorAudit) normalize() {
	if a.maxRequests <= 0 {
		a.maxRequests = defaultAuditMaxRequests
	}
	if a.maxRateLimits <= 0 {
		a.maxRateLimits = defaultAuditMaxRateLimits
	}
	if a.maxActionEntries <= 0 {
		a.maxActionEntries = defaultAuditMaxActionEntries
	}
	if a.maxOutputBytes <= 0 {
		a.maxOutputBytes = defaultAuditMaxOutputBytes
	}
}

// AuditRuleIdentity annotates one final-Envoy rate-limit configuration with the IR
// rule it was translated from. Entries must line up 1:1 with the RateLimits slice.
type AuditRuleIdentity struct {
	RuleName        string
	GlobalRuleIndex int
	DomainRuleIndex int
	Shared          bool
	ShadowMode      bool
}

// AuditDomainRateLimits groups the final Envoy rate-limit configurations of one
// route for one RLS domain, optionally annotated with their rule identities.
type AuditDomainRateLimits struct {
	Domain     string
	RateLimits []*routev3.RateLimit
	Identities []AuditRuleIdentity
}

// AuditRouteInput is the final-Envoy representation of one audited route.
type AuditRouteInput struct {
	ListenerName string
	RouteName    string
	Domains      []AuditDomainRateLimits
}

// Run audits fixed IR listeners. The route actions and RLS configuration are produced
// by the real production builders, so route matching results are never assumed to be
// existing descriptors: descriptors are recomputed per corpus request.
func (a *RateLimitDescriptorAudit) Run(
	listeners []*ir.HTTPListener, requests []*AuditRequest,
) (*AuditReport, error) {
	a.normalize()

	views, err := a.buildRequestViews(requests)
	if err != nil {
		return nil, err
	}

	// Real RLS configuration produced by the production builder.
	rlsConfigs := BuildRateLimitServiceConfig(listeners)

	inputs := make([]AuditRouteInput, 0)
	var coverage []AuditRuleCoverage
	for _, listener := range listeners {
		if listener == nil {
			continue
		}
		for _, route := range listener.Routes {
			if !isValidGlobalRateLimit(route) {
				continue
			}
			// Real per-route Envoy rate-limit actions produced by the production builder.
			routeLimits := buildRouteRateLimits(listener.Name, route)
			input, routeCoverage, err := buildAuditRouteInput(listener.Name, route, routeLimits)
			if err != nil {
				return nil, err
			}
			inputs = append(inputs, input)
			coverage = append(coverage, routeCoverage...)
		}
	}

	if err := a.validateRouteInputs(inputs); err != nil {
		return nil, err
	}
	return a.runInputs(inputs, rlsConfigs, views, coverage), nil
}

// RunActions audits final Envoy per-route rate-limit configurations and RLS
// configuration protos directly. Use it when the IR is no longer available; rule
// identity and coverage are only populated where AuditRuleIdentity is supplied.
func (a *RateLimitDescriptorAudit) RunActions(
	inputs []AuditRouteInput,
	rlsConfigs []*rlsconfv3.RateLimitConfig,
	requests []*AuditRequest,
) (*AuditReport, error) {
	a.normalize()

	views, err := a.buildRequestViews(requests)
	if err != nil {
		return nil, err
	}
	if err := a.validateRouteInputs(inputs); err != nil {
		return nil, err
	}

	coverage := make([]AuditRuleCoverage, 0)
	for _, input := range inputs {
		for _, d := range input.Domains {
			for i, identity := range d.Identities {
				if i >= len(d.RateLimits) || identity.RuleName == "" {
					continue
				}
				coverage = append(coverage, AuditRuleCoverage{
					ListenerName:    input.ListenerName,
					RouteName:       input.RouteName,
					RuleName:        identity.RuleName,
					Domain:          d.Domain,
					GlobalRuleIndex: identity.GlobalRuleIndex,
					DomainRuleIndex: identity.DomainRuleIndex,
					Shared:          identity.Shared,
					Shadow:          identity.ShadowMode,
					Status:          AuditRuleUnexercised,
				})
			}
		}
	}
	sortCoverage(coverage)
	return a.runInputs(inputs, rlsConfigs, views, coverage), nil
}

// buildAuditRouteInput pairs the production builder output of one route with the
// rule identities derived independently from the IR rule ordering.
func buildAuditRouteInput(
	listenerName string, route *ir.HTTPRoute,
	routeLimits map[string][]*routev3.RateLimit,
) (AuditRouteInput, []AuditRuleCoverage, error) {
	rules := route.Traffic.RateLimit.Global.Rules
	input := AuditRouteInput{ListenerName: listenerName, RouteName: route.Name}
	coverage := make([]AuditRuleCoverage, 0, len(rules))

	// Deterministic domain order.
	domains := make([]string, 0, len(routeLimits))
	for domain := range routeLimits {
		domains = append(domains, domain)
	}
	sort.Strings(domains)

	for _, domain := range domains {
		rateLimits := routeLimits[domain]
		identities := make([]AuditRuleIdentity, 0, len(rateLimits))

		// Re-derive the identity sequence from IR, mirroring the iteration order of
		// buildRouteRateLimits (rule order, one RateLimit per method match, plus a
		// stream-done twin when a response cost is set).
		for rIdx, rule := range rules {
			ruleDomain := listenerName
			shared := isRuleShared(rule)
			if shared {
				ruleDomain = stripRuleIndexSuffix(rule.Name)
			}
			if ruleDomain != domain {
				continue
			}
			methodMatches := rule.MethodMatches
			if len(methodMatches) == 0 {
				methodMatches = []*ir.StringMatch{nil}
			}
			domainRuleIdx := getDomainRuleIndex(rules, rIdx, shared)
			for range methodMatches {
				identities = append(identities, AuditRuleIdentity{
					RuleName:        rule.Name,
					GlobalRuleIndex: rIdx,
					DomainRuleIndex: domainRuleIdx,
					Shared:          shared,
					ShadowMode:      isRuleShadowMode(rule),
				})
				if rule.ResponseCost != nil {
					identities = append(identities, AuditRuleIdentity{
						RuleName:        rule.Name,
						GlobalRuleIndex: rIdx,
						DomainRuleIndex: domainRuleIdx,
						Shared:          shared,
						ShadowMode:      isRuleShadowMode(rule),
					})
				}
			}
			coverage = append(coverage, AuditRuleCoverage{
				ListenerName:    listenerName,
				RouteName:       route.Name,
				RuleName:        rule.Name,
				Domain:          domain,
				GlobalRuleIndex: rIdx,
				DomainRuleIndex: domainRuleIdx,
				Shared:          shared,
				Shadow:          isRuleShadowMode(rule),
				Status:          AuditRuleUnexercised,
			})
		}

		// Defensive guard: identity alignment relies on the builder iteration order; a
		// mismatch must fail loudly instead of mislabeling results.
		if len(identities) != len(rateLimits) {
			return AuditRouteInput{}, nil, fmt.Errorf(
				"rate-limit audit identity mismatch for route %q domain %q: %d identities vs %d rate limits",
				route.Name, domain, len(identities), len(rateLimits))
		}

		input.Domains = append(input.Domains, AuditDomainRateLimits{
			Domain:     domain,
			RateLimits: rateLimits,
			Identities: identities,
		})
	}
	sortCoverage(coverage)
	return input, coverage, nil
}

func (a *RateLimitDescriptorAudit) validateRouteInputs(inputs []AuditRouteInput) error {
	total := 0
	for _, input := range inputs {
		for _, d := range input.Domains {
			total += len(d.RateLimits)
			for _, rl := range d.RateLimits {
				if rl == nil {
					return errors.New("rate-limit audit: nil rate-limit configuration")
				}
				if len(rl.Actions) > a.maxActionEntries {
					return fmt.Errorf(
						"rate-limit audit: rate-limit configuration on route %q has %d actions, exceeding MaxActionEntries %d",
						input.RouteName, len(rl.Actions), a.maxActionEntries)
				}
			}
			if len(d.Identities) > 0 && len(d.Identities) != len(d.RateLimits) {
				return fmt.Errorf(
					"rate-limit audit: %d identities supplied for %d rate limits on route %q",
					len(d.Identities), len(d.RateLimits), input.RouteName)
			}
		}
	}
	if total > a.maxRateLimits {
		return fmt.Errorf(
			"rate-limit audit: %d rate-limit configurations per request exceed MaxRateLimits %d",
			total, a.maxRateLimits)
	}
	return nil
}

// auditRequestView is the in-memory request representation. Request-derived values
// live here only and are never copied into the report.
type auditRequestView struct {
	id       string
	method   string
	path     string
	headers  map[string]string
	query    url.Values
	queryErr error
	ip       netip.Addr
	hasIP    bool
}

func (a *RateLimitDescriptorAudit) buildRequestViews(requests []*AuditRequest) ([]auditRequestView, error) {
	if len(requests) > a.maxRequests {
		return nil, fmt.Errorf(
			"rate-limit audit: corpus size %d exceeds MaxRequests %d", len(requests), a.maxRequests)
	}
	views := make([]auditRequestView, 0, len(requests))
	seenIDs := make(map[string]struct{}, len(requests))
	for _, req := range requests {
		if req == nil {
			return nil, errors.New("rate-limit audit: nil corpus request")
		}
		if req.ID == "" {
			return nil, errors.New("rate-limit audit: corpus request without ID")
		}
		if _, dup := seenIDs[req.ID]; dup {
			return nil, fmt.Errorf("rate-limit audit: duplicate corpus request ID %q", req.ID)
		}
		seenIDs[req.ID] = struct{}{}

		view := auditRequestView{
			id:      req.ID,
			method:  req.Method,
			path:    req.Path,
			headers: make(map[string]string, len(req.Headers)),
		}
		for name, value := range req.Headers {
			// Envoy treats header names case-insensitively (lowercased internally).
			view.headers[strings.ToLower(name)] = value
		}
		if req.TrustedClientIP != "" {
			addr, err := netip.ParseAddr(req.TrustedClientIP)
			if err != nil {
				return nil, fmt.Errorf(
					"rate-limit audit: request %q carries an invalid trusted client IP: %w",
					req.ID, err)
			}
			view.ip = addr
			view.hasIP = true
		}
		u, err := url.Parse(req.Path)
		if err != nil {
			view.queryErr = err
		} else {
			view.query = u.Query()
		}
		views = append(views, view)
	}
	return views, nil
}

// headerValue returns the first value of a request header. Pseudo-headers :method
// and :path are served from the dedicated corpus fields.
func (v *auditRequestView) headerValue(name string) (string, bool) {
	switch name {
	case ":method":
		return v.method, v.method != ""
	case ":path":
		return v.path, v.path != ""
	default:
		value, ok := v.headers[strings.ToLower(name)]
		return value, ok
	}
}

// queryValues returns all values of a query parameter.
func (v *auditRequestView) queryValues(name string) ([]string, bool) {
	if v.queryErr != nil || v.query == nil {
		return nil, false
	}
	values, ok := v.query[name]
	return values, ok
}

func (a *RateLimitDescriptorAudit) runInputs(
	inputs []AuditRouteInput,
	rlsConfigs []*rlsconfv3.RateLimitConfig,
	views []auditRequestView,
	coverage []AuditRuleCoverage,
) *AuditReport {
	report := &AuditReport{RuleCoverage: coverage}
	coverageIndex := make(map[string]int, len(coverage))
	for i, c := range report.RuleCoverage {
		coverageIndex[coverageKey(c.ListenerName, c.RouteName, c.GlobalRuleIndex)] = i
	}

	for _, view := range views {
		for _, input := range inputs {
			for _, d := range input.Domains {
				for idx, rl := range d.RateLimits {
					result := a.evaluateRateLimit(input, d.Domain, idx, rl, view, rlsConfigs)
					report.Results = append(report.Results, result)

					if result.Resolution == AuditResolutionMatched {
						if ci, ok := coverageIndex[coverageKey(
							result.ListenerName, result.RouteName, result.GlobalRuleIndex)]; ok {
							c := &report.RuleCoverage[ci]
							c.Status = AuditRuleExercised
							// Bound the evidence per rule; request/response-phase twins
							// share a request ID and must not duplicate it.
							if len(c.ExercisedBy) < a.maxRequests && !containsString(c.ExercisedBy, view.id) {
								c.ExercisedBy = append(c.ExercisedBy, view.id)
							}
						}
					}
				}
			}
		}
	}

	a.enforceOutputBound(report)
	return report
}

func coverageKey(listener, route string, globalRuleIndex int) string {
	return listener + "\x00" + route + "\x00" + fmt.Sprintf("%d", globalRuleIndex)
}

func containsString(items []string, target string) bool {
	for _, item := range items {
		if item == target {
			return true
		}
	}
	return false
}

// enforceOutputBound trims tail results when the serialized report would exceed the
// configured byte budget. Coverage data is retained because it is small and required
// for the Unexercised guarantee.
func (a *RateLimitDescriptorAudit) enforceOutputBound(report *AuditReport) {
	for report.approxBytes() > a.maxOutputBytes && len(report.Results) > 0 {
		report.Results = report.Results[:len(report.Results)-1]
		report.Truncated = true
	}
}

// approxBytes estimates the serialized size of the report.
func (r *AuditReport) approxBytes() int {
	b, err := json.Marshal(r)
	if err != nil {
		// Falling back to a structural upper bound keeps the audit total under any
		// circumstances.
		return len(r.Results) * aResultSizeEstimate
	}
	return len(b)
}

const aResultSizeEstimate = 512

// evaluateRateLimit evaluates one final Envoy rate-limit configuration against one
// request and then resolves the generated descriptor against the RLS tree.
func (a *RateLimitDescriptorAudit) evaluateRateLimit(
	input AuditRouteInput, domain string, idx int, rl *routev3.RateLimit,
	view auditRequestView, rlsConfigs []*rlsconfv3.RateLimitConfig,
) AuditRateLimitResult {
	result := AuditRateLimitResult{
		RequestID:        view.id,
		ListenerName:     input.ListenerName,
		RouteName:        input.RouteName,
		Domain:           domain,
		Phase:            auditPhaseRequest,
		DescriptorStatus: AuditDescriptorGenerated,
		Resolution:       AuditResolutionNotInvoked,
		XRatelimitOption: rl.GetXRatelimitOption().String(),
		HitsAddend:       auditHitsAddend(rl),
		Override:         auditOverride(rl),
	}
	if rl.GetApplyOnStreamDone() {
		result.Phase = auditPhaseResponse
	}
	if idx < len(identityOf(input, domain)) {
		identity := identityOf(input, domain)[idx]
		result.RuleName = identity.RuleName
		result.GlobalRuleIndex = identity.GlobalRuleIndex
		result.DomainRuleIndex = identity.DomainRuleIndex
		result.Shared = identity.Shared
		result.ShadowMode = identity.ShadowMode
	}

	entries := make([]auditDescriptorEntry, 0, len(rl.Actions))
	for actionIdx, action := range rl.Actions {
		evidence, entry, status := a.evaluateAction(actionIdx, action, view)
		result.Actions = append(result.Actions, evidence)
		switch status {
		case AuditEntryAppended:
			entries = append(entries, *entry)
		case AuditEntrySkipped:
			// Continue with the remaining actions.
		case AuditEntryAborted:
			result.DescriptorStatus = AuditDescriptorAborted
			result.Resolution = AuditResolutionNotInvoked
			result.UnknownReasons = append(result.UnknownReasons, evidence.Reason)
			return result
		case AuditEntryUnknown:
			result.DescriptorStatus = AuditDescriptorUnknown
			result.Resolution = AuditResolutionNotInvoked
			result.UnknownReasons = append(result.UnknownReasons, evidence.Reason)
			return result
		}
	}

	for _, entry := range entries {
		result.DescriptorKeys = append(result.DescriptorKeys, entry.key)
	}

	tree := a.resolveDescriptor(rlsConfigs, domain, entries)
	result.Resolution = tree.status
	result.UnknownReasons = append(result.UnknownReasons, tree.unknownReasons...)
	result.Findings = append(result.Findings, tree.findings...)
	if tree.policy != nil {
		result.MatchedPolicy = tree.policy
		if result.ShadowMode != tree.policy.ShadowMode {
			result.Findings = append(result.Findings, fmt.Sprintf(
				"shadow-attribute-mismatch: rule=%v rls-descriptor=%v",
				result.ShadowMode, tree.policy.ShadowMode))
		}
	}
	// A dynamic-metadata override may change (or disable) the effective limit per
	// request; this cannot be resolved offline, so it must not be reported as a
	// statically known enforcement outcome.
	if result.Resolution == AuditResolutionMatched &&
		result.Override.Source == "dynamic-metadata" {
		result.UnknownReasons = append(result.UnknownReasons,
			"effective-limit-override-sourced-from-dynamic-metadata")
	}

	result.Enforcing = a.isEnforcing(result)
	return result
}

func identityOf(input AuditRouteInput, domain string) []AuditRuleIdentity {
	for _, d := range input.Domains {
		if d.Domain == domain {
			return d.Identities
		}
	}
	return nil
}

// isEnforcing implements the rule that only request-phase, non-shadow, statically
// known matches can be enforced. Shadow and stream-done hits never count as enforced
// rejections, and the audit never evaluates counters anyway.
func (a *RateLimitDescriptorAudit) isEnforcing(result AuditRateLimitResult) bool {
	if result.Phase != auditPhaseRequest {
		return false
	}
	if result.Resolution != AuditResolutionMatched || result.MatchedPolicy == nil {
		return false
	}
	if result.MatchedPolicy.ShadowMode || result.MatchedPolicy.Unlimited {
		return false
	}
	if !result.Override.EffectiveLimitKnown {
		return false
	}
	return true
}

// auditDescriptorEntry is the internal descriptor entry. Its value may contain
// request data and must never be copied into report types.
type auditDescriptorEntry struct {
	key         string
	value       string
	valueSource string
}

// evaluateAction implements the supported Envoy rate-limit action semantics. It
// returns per-action evidence, an optional descriptor entry and the entry status.
func (a *RateLimitDescriptorAudit) evaluateAction(
	idx int, action *routev3.RateLimit_Action, view auditRequestView,
) (AuditActionEvidence, *auditDescriptorEntry, AuditEntryStatus) {
	switch {
	case action.GetGenericKey() != nil:
		gk := action.GetGenericKey()
		key := gk.GetDescriptorKey()
		if key == "" {
			key = "generic_key"
		}
		ev := AuditActionEvidence{Index: idx, Kind: "GenericKey", DescriptorKey: key, ValueSource: "static"}
		if strings.Contains(gk.GetDescriptorValue(), "%") {
			ev.Status = AuditEntryUnknown
			ev.Reason = "generic-key-format-specifier-unsupported"
			return ev, nil, AuditEntryUnknown
		}
		ev.Status = AuditEntryAppended
		return ev, &auditDescriptorEntry{key: key, value: gk.GetDescriptorValue(), valueSource: "static"}, AuditEntryAppended

	case action.GetRequestHeaders() != nil:
		rh := action.GetRequestHeaders()
		ev := AuditActionEvidence{
			Index: idx, Kind: "RequestHeaders", DescriptorKey: rh.GetDescriptorKey(),
			ValueSource: "header:" + rh.GetHeaderName(),
		}
		value, ok := view.headerValue(rh.GetHeaderName())
		if !ok {
			if rh.GetSkipIfAbsent() {
				ev.Status = AuditEntrySkipped
				ev.Reason = "header-absent-skip-if-absent"
				return ev, nil, AuditEntrySkipped
			}
			ev.Status = AuditEntryAborted
			ev.Reason = "required-request-header-absent"
			return ev, nil, AuditEntryAborted
		}
		ev.Status = AuditEntryAppended
		return ev, &auditDescriptorEntry{
			key: rh.GetDescriptorKey(), value: value, valueSource: ev.ValueSource,
		}, AuditEntryAppended

	case action.GetQueryParameters() != nil:
		qp := action.GetQueryParameters()
		ev := AuditActionEvidence{
			Index: idx, Kind: "QueryParameters", DescriptorKey: qp.GetDescriptorKey(),
			ValueSource: "query:" + qp.GetQueryParameterName(),
		}
		values, ok := view.queryValues(qp.GetQueryParameterName())
		if !ok || len(values) == 0 {
			if qp.GetSkipIfAbsent() {
				ev.Status = AuditEntrySkipped
				ev.Reason = "query-parameter-absent-skip-if-absent"
				return ev, nil, AuditEntrySkipped
			}
			ev.Status = AuditEntryAborted
			ev.Reason = "required-query-parameter-absent"
			return ev, nil, AuditEntryAborted
		}
		ev.Status = AuditEntryAppended
		// Envoy populates the entry with the first parameter value.
		return ev, &auditDescriptorEntry{
			key: qp.GetDescriptorKey(), value: values[0], valueSource: ev.ValueSource,
		}, AuditEntryAppended

	case action.GetHeaderValueMatch() != nil:
		hvm := action.GetHeaderValueMatch()
		ev := AuditActionEvidence{
			Index: idx, Kind: "HeaderValueMatch", DescriptorKey: hvm.GetDescriptorKey(),
			ValueSource: "static",
		}
		matched, unknown, reason := evalHeaderMatchers(hvm.GetHeaders(), view)
		if unknown {
			ev.Status = AuditEntryUnknown
			ev.Reason = reason
			return ev, nil, AuditEntryUnknown
		}
		expect := true
		if hvm.GetExpectMatch() != nil {
			expect = hvm.GetExpectMatch().GetValue()
		}
		if matched != expect {
			ev.Status = AuditEntrySkipped
			ev.Reason = "header-expectation-not-met"
			return ev, nil, AuditEntrySkipped
		}
		if strings.Contains(hvm.GetDescriptorValue(), "%") {
			ev.Status = AuditEntryUnknown
			ev.Reason = "header-value-match-format-specifier-unsupported"
			return ev, nil, AuditEntryUnknown
		}
		ev.Status = AuditEntryAppended
		return ev, &auditDescriptorEntry{
			key: hvm.GetDescriptorKey(), value: hvm.GetDescriptorValue(), valueSource: "static",
		}, AuditEntryAppended

	case action.GetQueryParameterValueMatch() != nil:
		qvm := action.GetQueryParameterValueMatch()
		ev := AuditActionEvidence{
			Index: idx, Kind: "QueryParameterValueMatch", DescriptorKey: qvm.GetDescriptorKey(),
			ValueSource: "static",
		}
		matched, unknown, reason := evalQueryParameterMatchers(qvm.GetQueryParameters(), view)
		if unknown {
			ev.Status = AuditEntryUnknown
			ev.Reason = reason
			return ev, nil, AuditEntryUnknown
		}
		expect := true
		if qvm.GetExpectMatch() != nil {
			expect = qvm.GetExpectMatch().GetValue()
		}
		if matched != expect {
			ev.Status = AuditEntrySkipped
			ev.Reason = "query-parameter-expectation-not-met"
			return ev, nil, AuditEntrySkipped
		}
		if strings.Contains(qvm.GetDescriptorValue(), "%") {
			ev.Status = AuditEntryUnknown
			ev.Reason = "query-parameter-value-match-format-specifier-unsupported"
			return ev, nil, AuditEntryUnknown
		}
		ev.Status = AuditEntryAppended
		return ev, &auditDescriptorEntry{
			key: qvm.GetDescriptorKey(), value: qvm.GetDescriptorValue(), valueSource: "static",
		}, AuditEntryAppended

	case action.GetRemoteAddressMatch() != nil:
		ram := action.GetRemoteAddressMatch()
		ev := AuditActionEvidence{
			Index: idx, Kind: "RemoteAddressMatch", DescriptorKey: ram.GetDescriptorKey(),
		}
		matched, unknown, reason := evalAddressMatcher(ram.GetAddressMatcher(), view)
		if unknown {
			ev.Status = AuditEntryUnknown
			ev.Reason = reason
			return ev, nil, AuditEntryUnknown
		}
		if !matched {
			ev.Status = AuditEntrySkipped
			ev.Reason = "remote-address-matcher-not-met"
			ev.ValueSource = "trusted-client-ip"
			return ev, nil, AuditEntrySkipped
		}
		value, source, unknown, reason := remoteAddressDescriptorValue(ram.GetDescriptorValue(), view)
		if unknown {
			ev.Status = AuditEntryUnknown
			ev.Reason = reason
			ev.ValueSource = source
			return ev, nil, AuditEntryUnknown
		}
		ev.Status = AuditEntryAppended
		ev.ValueSource = source
		return ev, &auditDescriptorEntry{
			key: ram.GetDescriptorKey(), value: value, valueSource: source,
		}, AuditEntryAppended

	case action.GetRemoteAddress() != nil:
		ev := AuditActionEvidence{
			Index: idx, Kind: "RemoteAddress", DescriptorKey: "remote_address",
			ValueSource: "trusted-client-ip",
		}
		if !view.hasIP {
			ev.Status = AuditEntryUnknown
			ev.Reason = "trusted-client-ip-unavailable"
			return ev, nil, AuditEntryUnknown
		}
		ev.Status = AuditEntryAppended
		return ev, &auditDescriptorEntry{
			key: "remote_address", value: view.ip.String(), valueSource: "trusted-client-ip",
		}, AuditEntryAppended

	case action.GetMaskedRemoteAddress() != nil:
		mra := action.GetMaskedRemoteAddress()
		ev := AuditActionEvidence{
			Index: idx, Kind: "MaskedRemoteAddress", DescriptorKey: "masked_remote_address",
			ValueSource: "trusted-client-ip",
		}
		value, ok := maskedRemoteAddressValue(mra, view)
		if !ok {
			ev.Status = AuditEntryUnknown
			ev.Reason = "trusted-client-ip-unavailable"
			return ev, nil, AuditEntryUnknown
		}
		ev.Status = AuditEntryAppended
		return ev, &auditDescriptorEntry{
			key: "masked_remote_address", value: value, valueSource: "trusted-client-ip",
		}, AuditEntryAppended

	case action.GetDynamicMetadata() != nil,
		action.GetMetadata() != nil,
		action.GetExtension() != nil,
		action.GetSourceCluster() != nil,
		action.GetDestinationCluster() != nil:
		ev := AuditActionEvidence{Index: idx, Kind: unsupportedActionKind(action), Status: AuditEntryUnknown}
		ev.Reason = "action-requires-dynamic-metadata-filter-state-or-unmodeled-source"
		return ev, nil, AuditEntryUnknown

	default:
		ev := AuditActionEvidence{Index: idx, Kind: "Unknown", Status: AuditEntryUnknown}
		ev.Reason = "unsupported-rate-limit-action"
		return ev, nil, AuditEntryUnknown
	}
}

func unsupportedActionKind(action *routev3.RateLimit_Action) string {
	switch {
	case action.GetDynamicMetadata() != nil:
		return "DynamicMetadata"
	case action.GetMetadata() != nil:
		return "Metadata"
	case action.GetExtension() != nil:
		return "Extension"
	case action.GetSourceCluster() != nil:
		return "SourceCluster"
	case action.GetDestinationCluster() != nil:
		return "DestinationCluster"
	default:
		return "Unknown"
	}
}

// remoteAddressDescriptorValue resolves a RemoteAddressMatch descriptor value. The
// only substitution EG emits is the trusted downstream address formatter; any other
// format specifier is Unknown.
func remoteAddressDescriptorValue(format string, view auditRequestView) (value, source string, unknown bool, reason string) {
	if format == downstreamRemoteAddressWithoutPortCelFormatter {
		if !view.hasIP {
			return "", "trusted-client-ip", true, "trusted-client-ip-unavailable"
		}
		return view.ip.String(), "trusted-client-ip", false, ""
	}
	if strings.Contains(format, "%") {
		return "", "static", true, "remote-address-format-specifier-unsupported"
	}
	return format, "static", false, ""
}

// maskedRemoteAddressValue reproduces the MaskedRemoteAddress action value from the
// trusted client IP, e.g. "192.168.1.0/24".
func maskedRemoteAddressValue(
	mra *routev3.RateLimit_Action_MaskedRemoteAddress, view auditRequestView,
) (string, bool) {
	if !view.hasIP {
		return "", false
	}
	maskLen := uint32(32)
	if view.ip.Is6() {
		maskLen = 128
		if mra.GetV6PrefixMaskLen() != nil {
			maskLen = mra.GetV6PrefixMaskLen().GetValue()
		}
	} else if mra.GetV4PrefixMaskLen() != nil {
		maskLen = mra.GetV4PrefixMaskLen().GetValue()
	}
	prefix, err := view.ip.Prefix(int(maskLen))
	if err != nil {
		return "", false
	}
	return prefix.Masked().String(), true
}

// evalStringMatcher evaluates an Envoy StringMatcher against one concrete value.
// SafeRegex and custom matchers are reported as Unknown rather than guessed.
func evalStringMatcher(matcher *matcherv3.StringMatcher, value string) (matched, unknown bool) {
	if matcher == nil {
		return false, false
	}
	caseInsensitive := matcher.GetIgnoreCase()
	switch mp := matcher.MatchPattern.(type) {
	case *matcherv3.StringMatcher_Exact:
		if caseInsensitive {
			return strings.EqualFold(mp.Exact, value), false
		}
		return mp.Exact == value, false
	case *matcherv3.StringMatcher_Prefix:
		if caseInsensitive {
			return strings.HasPrefix(strings.ToLower(value), strings.ToLower(mp.Prefix)), false
		}
		return strings.HasPrefix(value, mp.Prefix), false
	case *matcherv3.StringMatcher_Suffix:
		if caseInsensitive {
			return strings.HasSuffix(strings.ToLower(value), strings.ToLower(mp.Suffix)), false
		}
		return strings.HasSuffix(value, mp.Suffix), false
	case *matcherv3.StringMatcher_Contains:
		if caseInsensitive {
			return strings.Contains(strings.ToLower(value), strings.ToLower(mp.Contains)), false
		}
		return strings.Contains(value, mp.Contains), false
	case *matcherv3.StringMatcher_SafeRegex:
		_ = mp
		return false, true
	case *matcherv3.StringMatcher_Custom:
		return false, true
	default:
		return false, false
	}
}

// evalHeaderMatchers implements AND semantics over the action's HeaderMatcher list.
func evalHeaderMatchers(headers []*routev3.HeaderMatcher, view auditRequestView) (
	matched, unknown bool, reason string,
) {
	for _, header := range headers {
		ok, unknown, reason := evalOneHeaderMatcher(header, view)
		if unknown {
			return false, true, reason
		}
		if !ok {
			return false, false, ""
		}
	}
	return true, false, ""
}

func evalOneHeaderMatcher(header *routev3.HeaderMatcher, view auditRequestView) (
	matched, unknown bool, reason string,
) {
	value, present := view.headerValue(header.GetName())
	if !present && !header.GetTreatMissingHeaderAsEmpty() {
		// A missing header cannot satisfy any value matcher; presence matchers handle
		// absence explicitly below.
		switch header.HeaderMatchSpecifier.(type) {
		case *routev3.HeaderMatcher_PresentMatch:
			return applyHeaderInversion(header.GetPresentMatch(), header.GetInvertMatch()), false, ""
		default:
			return applyHeaderInversion(false, header.GetInvertMatch()), false, ""
		}
	}

	var baseMatch bool
	switch spec := header.HeaderMatchSpecifier.(type) {
	case *routev3.HeaderMatcher_StringMatch:
		baseMatch, unknown = evalStringMatcher(spec.StringMatch, value)
		if unknown {
			return false, true, "header-safe-regex-or-custom-matcher-unsupported"
		}
	case *routev3.HeaderMatcher_PresentMatch:
		baseMatch = present
	case *routev3.HeaderMatcher_ExactMatch:
		baseMatch = spec.ExactMatch == value
	case *routev3.HeaderMatcher_PrefixMatch:
		baseMatch = strings.HasPrefix(value, spec.PrefixMatch)
	case *routev3.HeaderMatcher_SuffixMatch:
		baseMatch = strings.HasSuffix(value, spec.SuffixMatch)
	case *routev3.HeaderMatcher_ContainsMatch:
		baseMatch = strings.Contains(value, spec.ContainsMatch)
	case *routev3.HeaderMatcher_SafeRegexMatch:
		return false, true, "header-safe-regex-matcher-unsupported"
	case *routev3.HeaderMatcher_RangeMatch:
		return false, true, "header-range-matcher-unsupported"
	default:
		return false, true, "unsupported-header-matcher"
	}
	return applyHeaderInversion(baseMatch, header.GetInvertMatch()), false, ""
}

func applyHeaderInversion(matched, invert bool) bool {
	if invert {
		return !matched
	}
	return matched
}

// evalQueryParameterMatchers implements AND semantics over QueryParameterMatcher list.
func evalQueryParameterMatchers(
	params []*routev3.QueryParameterMatcher, view auditRequestView,
) (matched, unknown bool, reason string) {
	for _, param := range params {
		ok, unknown, reason := evalOneQueryParameterMatcher(param, view)
		if unknown {
			return false, true, reason
		}
		if !ok {
			return false, false, ""
		}
	}
	return true, false, ""
}

func evalOneQueryParameterMatcher(
	param *routev3.QueryParameterMatcher, view auditRequestView,
) (matched, unknown bool, reason string) {
	values, present := view.queryValues(param.GetName())
	switch spec := param.QueryParameterMatchSpecifier.(type) {
	case *routev3.QueryParameterMatcher_StringMatch:
		if !present {
			return false, false, ""
		}
		// Envoy matches when any of the repeated parameter values satisfies the matcher.
		for _, value := range values {
			baseMatch, unk := evalStringMatcher(spec.StringMatch, value)
			if unk {
				return false, true, "query-parameter-safe-regex-or-custom-matcher-unsupported"
			}
			if baseMatch {
				return true, false, ""
			}
		}
		return false, false, ""
	case *routev3.QueryParameterMatcher_PresentMatch:
		return present && spec.PresentMatch, false, ""
	default:
		return false, true, "unsupported-query-parameter-matcher"
	}
}

// evalAddressMatcher evaluates an AddressMatcher against the explicit trusted client
// IP only. X-Forwarded-For is never consulted.
func evalAddressMatcher(
	matcher *matcherv3.AddressMatcher, view auditRequestView,
) (matched, unknown bool, reason string) {
	if matcher == nil {
		return false, true, "remote-address-matcher-missing"
	}
	if !view.hasIP {
		return false, true, "trusted-client-ip-unavailable"
	}
	inRange := false
	for _, cidr := range matcher.GetRanges() {
		prefix, err := parseCidrRange(cidr)
		if err != nil {
			return false, true, "address-matcher-cidr-invalid"
		}
		if prefix.Contains(view.ip) {
			inRange = true
			break
		}
	}
	if matcher.GetInvertMatch() {
		return !inRange, false, ""
	}
	return inRange, false, ""
}

func parseCidrRange(cidr *xdscorev3.CidrRange) (netip.Prefix, error) {
	if cidr == nil {
		return netip.Prefix{}, errors.New("nil cidr range")
	}
	addr, err := netip.ParseAddr(cidr.GetAddressPrefix())
	if err != nil {
		return netip.Prefix{}, err
	}
	bits := uint32(0)
	if cidr.GetPrefixLen() != nil {
		bits = cidr.GetPrefixLen().GetValue()
	}
	prefix, err := addr.Prefix(int(bits))
	if err != nil {
		return netip.Prefix{}, err
	}
	return prefix.Masked(), nil
}

// auditTreeResult is the internal RLS tree resolution outcome.
type auditTreeResult struct {
	status         AuditResolutionStatus
	policy         *AuditMatchedPolicy
	unknownReasons []string
	findings       []string
}

// resolveDescriptor walks the real RLS descriptor tree using the same lookup order as
// envoyproxy/ratelimit: entries are consumed in order, each level first trying an
// explicit key/value child then a key-only (distinct) child, and traversal stops at
// the first miss. A policy is only applied when attached to the node matching the
// final descriptor entry.
func (a *RateLimitDescriptorAudit) resolveDescriptor(
	configs []*rlsconfv3.RateLimitConfig, domain string, entries []auditDescriptorEntry,
) auditTreeResult {
	var cfg *rlsconfv3.RateLimitConfig
	for _, candidate := range configs {
		if candidate.GetDomain() == domain {
			cfg = candidate
			break
		}
	}
	if cfg == nil {
		// Unknown domain: the RLS records not-found and applies no policy.
		return auditTreeResult{
			status:   AuditResolutionNoMatch,
			findings: []string{"rls-domain-not-configured:" + domain},
		}
	}

	children := cfg.GetDescriptors()
	path := make([]AuditDescriptorNode, 0, len(entries))
	var policy *rlsconfv3.RateLimitPolicy
	var policyPath []AuditDescriptorNode

	for i, entry := range entries {
		node := findDescriptorChild(children, entry.key, entry.value)
		if node == nil {
			if levelHasWildcard(children) {
				return auditTreeResult{
					status:         AuditResolutionUnknown,
					unknownReasons: []string{"rls-wildcard-descriptor-unsupported"},
				}
			}
			return auditTreeResult{status: AuditResolutionNoMatch}
		}
		path = append(path, AuditDescriptorNode{
			Key: node.GetKey(), Value: node.GetValue(), ShadowMode: node.GetShadowMode(),
		})

		// Mirror RLS semantics: a limit only counts at the final entry.
		if i == len(entries)-1 && node.GetRateLimit() != nil {
			policy = node.GetRateLimit()
			policyPath = append([]AuditDescriptorNode(nil), path...)
		}

		if len(node.GetDescriptors()) == 0 {
			break
		}
		children = node.GetDescriptors()
	}

	if policy == nil {
		return auditTreeResult{status: AuditResolutionNoMatch}
	}
	return auditTreeResult{
		status: AuditResolutionMatched,
		policy: &AuditMatchedPolicy{
			DescriptorPath:  policyPath,
			RequestsPerUnit: policy.GetRequestsPerUnit(),
			Unit:            policy.GetUnit().String(),
			Unlimited:       policy.GetUnlimited(),
			ShadowMode:      leafShadowMode(policyPath),
		},
	}
}

// leafShadowMode returns the shadow attribute of the matched leaf node.
func leafShadowMode(path []AuditDescriptorNode) bool {
	if len(path) == 0 {
		return false
	}
	return path[len(path)-1].ShadowMode
}

// findDescriptorChild reproduces the RLS map lookup: explicit key/value first, then a
// key-only child for distinct descriptors.
func findDescriptorChild(
	descriptors []*rlsconfv3.RateLimitDescriptor, key, value string,
) *rlsconfv3.RateLimitDescriptor {
	for _, d := range descriptors {
		if d.GetKey() == key && d.GetValue() == value {
			return d
		}
	}
	for _, d := range descriptors {
		if d.GetKey() == key && d.GetValue() == "" {
			return d
		}
	}
	return nil
}

// levelHasWildcard detects RLS wildcard descriptors ("key*"), which EG does not emit
// but final-Envoy/RLS inputs might contain.
func levelHasWildcard(descriptors []*rlsconfv3.RateLimitDescriptor) bool {
	for _, d := range descriptors {
		if strings.HasSuffix(d.GetKey(), "*") {
			return true
		}
	}
	return false
}

// auditHitsAddend extracts the hits_addend of a rate-limit configuration.
func auditHitsAddend(rl *routev3.RateLimit) AuditHitsAddend {
	addend := rl.GetHitsAddend()
	if addend == nil {
		// Envoy applies an implicit addend of 1 when unset.
		return AuditHitsAddend{Source: "default"}
	}
	if addend.GetNumber() != nil {
		number := addend.GetNumber().GetValue()
		return AuditHitsAddend{Source: "static-number", Number: &number}
	}
	if addend.GetFormat() != "" {
		return AuditHitsAddend{Source: "format", RuntimeResolved: true}
	}
	return AuditHitsAddend{Source: "default"}
}

// auditOverride records the limit override source. Dynamic-metadata overrides cannot
// be resolved offline, so the effective limit is marked unknown.
func auditOverride(rl *routev3.RateLimit) AuditOverride {
	override := rl.GetLimit()
	if override == nil {
		return AuditOverride{Source: "none", EffectiveLimitKnown: true}
	}
	if dm := override.GetDynamicMetadata(); dm != nil {
		namespace, key := "", ""
		if mk := dm.GetMetadataKey(); mk != nil {
			namespace = mk.GetKey()
			if segments := mk.GetPath(); len(segments) > 0 && segments[0].GetKey() != "" {
				key = segments[0].GetKey()
			}
		}
		return AuditOverride{
			Source:              "dynamic-metadata",
			Namespace:           namespace,
			Key:                 key,
			EffectiveLimitKnown: false,
		}
	}
	if rlOverride := override.GetRateLimit(); rlOverride != nil {
		return AuditOverride{Source: "static-override", EffectiveLimitKnown: true}
	}
	return AuditOverride{Source: "unknown", EffectiveLimitKnown: false}
}

func sortCoverage(coverage []AuditRuleCoverage) {
	sort.Slice(coverage, func(i, j int) bool {
		if coverage[i].ListenerName != coverage[j].ListenerName {
			return coverage[i].ListenerName < coverage[j].ListenerName
		}
		if coverage[i].RouteName != coverage[j].RouteName {
			return coverage[i].RouteName < coverage[j].RouteName
		}
		return coverage[i].GlobalRuleIndex < coverage[j].GlobalRuleIndex
	})
}
