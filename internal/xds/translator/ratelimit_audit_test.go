// Copyright Envoy Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package translator

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	rlsconfv3 "github.com/envoyproxy/go-control-plane/ratelimit/config/ratelimit/v3"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	egv1a1 "github.com/envoyproxy/gateway/api/v1alpha1"
	"github.com/envoyproxy/gateway/internal/ir"
)

const (
	auditTestListener = "first-listener"
	auditTestRoute    = "first-route"
)

func auditBool(b bool) *bool { return &b }

func auditUint64(v uint64) *uint64 { return &v }

func auditStr(s string) *string { return &s }

func auditTestRouteWithRules(rules ...*ir.RateLimitRule) *ir.HTTPRoute {
	return &ir.HTTPRoute{
		Name: auditTestRoute,
		Traffic: &ir.TrafficFeatures{
			RateLimit: &ir.RateLimit{
				Global: &ir.GlobalRateLimit{Rules: rules},
			},
		},
	}
}

func auditTestListenerWith(routes ...*ir.HTTPRoute) *ir.HTTPListener {
	return &ir.HTTPListener{Name: auditTestListener, Routes: routes}
}

func auditRule(name string, limit ir.RateLimitValue) *ir.RateLimitRule {
	return &ir.RateLimitRule{Name: name, Limit: limit}
}

func auditLimit(requests uint32, unit egv1a1.RateLimitUnit) ir.RateLimitValue {
	return ir.RateLimitValue{Requests: requests, Unit: ir.RateLimitUnit(unit)}
}

func auditRequest(id, method, path, trustedIP string, headers map[string]string) *AuditRequest {
	return &AuditRequest{
		ID:              id,
		Method:          method,
		Path:            path,
		Headers:         headers,
		TrustedClientIP: trustedIP,
	}
}

// resultFor returns the request-phase audit results for one request and rule.
func resultsFor(t *testing.T, report *AuditReport, requestID, ruleName string) []AuditRateLimitResult {
	t.Helper()
	var out []AuditRateLimitResult
	for _, r := range report.Results {
		if r.RequestID == requestID && r.RuleName == ruleName && r.Phase == auditPhaseRequest {
			out = append(out, r)
		}
	}
	require.NotEmpty(t, out, "no audit result for request %q rule %q", requestID, ruleName)
	return out
}

func coverageFor(report *AuditReport, ruleName string) AuditRuleCoverage {
	for _, c := range report.RuleCoverage {
		if c.RuleName == ruleName {
			return c
		}
	}
	return AuditRuleCoverage{}
}

func TestRateLimitAuditSharedAndNonShared(t *testing.T) {
	sharedRule := auditRule("ns/shared-policy/rule/0", auditLimit(5, egv1a1.RateLimitUnitSecond))
	sharedRule.Shared = auditBool(true)
	sharedRule.HeaderMatches = []*ir.StringMatch{{Name: "x-user-id", Exact: auditStr("one")}}

	localRule := auditRule("ns/local-policy/rule/0", auditLimit(7, egv1a1.RateLimitUnitMinute))
	localRule.HeaderMatches = []*ir.StringMatch{{Name: "x-org-id", Exact: auditStr("two")}}

	listener := auditTestListenerWith(auditTestRouteWithRules(sharedRule, localRule))
	requests := []*AuditRequest{
		auditRequest("both", "GET", "/foo", "", map[string]string{
			"x-user-id": "one", "x-org-id": "two",
		}),
		auditRequest("shared-only", "GET", "/foo", "", map[string]string{"x-user-id": "one"}),
		auditRequest("none", "GET", "/foo", "", map[string]string{"x-user-id": "miss"}),
	}

	report, err := NewRateLimitDescriptorAudit().Run([]*ir.HTTPListener{listener}, requests)
	require.NoError(t, err)

	// Shared rule resolves in the policy domain; non-shared in the listener domain.
	sharedResults := resultsFor(t, report, "both", sharedRule.Name)
	require.Len(t, sharedResults, 1)
	shared := sharedResults[0]
	require.Equal(t, "ns/shared-policy", shared.Domain)
	require.True(t, shared.Shared)
	require.Equal(t, sharedRule.Name, shared.DescriptorKeys[0])
	require.Equal(t, AuditResolutionMatched, shared.Resolution)
	require.True(t, shared.Enforcing)

	localResults := resultsFor(t, report, "both", localRule.Name)
	require.Len(t, localResults, 1)
	local := localResults[0]
	require.Equal(t, auditTestListener, local.Domain)
	require.False(t, local.Shared)
	require.Equal(t, auditTestRoute, local.DescriptorKeys[0])
	require.Equal(t, AuditResolutionMatched, local.Resolution)

	// The shared rule still matches; the local rule's value-match action skips its
	// entry, so the shortened descriptor cannot resolve in the RLS tree.
	sharedOnly := resultsFor(t, report, "shared-only", sharedRule.Name)[0]
	require.Equal(t, AuditResolutionMatched, sharedOnly.Resolution)
	localMiss := resultsFor(t, report, "shared-only", localRule.Name)[0]
	require.Equal(t, AuditResolutionNoMatch, localMiss.Resolution)
	require.Equal(t, AuditEntrySkipped, localMiss.Actions[1].Status)

	noneShared := resultsFor(t, report, "none", sharedRule.Name)[0]
	require.Equal(t, AuditResolutionNoMatch, noneShared.Resolution)

	// Coverage reflects the corpus only; nothing is declared unreachable.
	require.Equal(t, AuditRuleExercised, coverageFor(report, sharedRule.Name).Status)
	require.Equal(t, AuditRuleExercised, coverageFor(report, localRule.Name).Status)

	// A corpus that matches nothing leaves every rule Unexercised.
	emptyReport, err := NewRateLimitDescriptorAudit().Run(
		[]*ir.HTTPListener{listener},
		[]*AuditRequest{auditRequest("none-2", "GET", "/foo", "", map[string]string{"x-user-id": "miss"})})
	require.NoError(t, err)
	for _, c := range emptyReport.RuleCoverage {
		require.Equal(t, AuditRuleUnexercised, c.Status)
		require.Empty(t, c.ExercisedBy)
	}
}

func TestRateLimitAuditShadowMode(t *testing.T) {
	shadowRule := auditRule("ns/shadow-policy/rule/0", auditLimit(5, egv1a1.RateLimitUnitSecond))
	shadowRule.ShadowMode = auditBool(true)
	shadowRule.HeaderMatches = []*ir.StringMatch{{Name: "x-user-id", Exact: auditStr("one")}}

	enforceRule := auditRule("ns/enforce-policy/rule/0", auditLimit(5, egv1a1.RateLimitUnitSecond))
	enforceRule.HeaderMatches = []*ir.StringMatch{{Name: "x-user-id", Exact: auditStr("one")}}

	listener := auditTestListenerWith(auditTestRouteWithRules(shadowRule, enforceRule))
	req := auditRequest("r1", "GET", "/foo", "", map[string]string{"x-user-id": "one"})
	report, err := NewRateLimitDescriptorAudit().Run([]*ir.HTTPListener{listener}, []*AuditRequest{req})
	require.NoError(t, err)

	shadow := resultsFor(t, report, "r1", shadowRule.Name)[0]
	require.Equal(t, AuditResolutionMatched, shadow.Resolution)
	require.NotNil(t, shadow.MatchedPolicy)
	require.True(t, shadow.MatchedPolicy.ShadowMode)
	require.True(t, shadow.ShadowMode)
	// Shadow hits must never be reported as enforcing.
	require.False(t, shadow.Enforcing)

	enforce := resultsFor(t, report, "r1", enforceRule.Name)[0]
	require.Equal(t, AuditResolutionMatched, enforce.Resolution)
	require.False(t, enforce.MatchedPolicy.ShadowMode)
	require.True(t, enforce.Enforcing)

	// Cross-check the real RLS builder output carries shadow_mode on the chain.
	rlsConfigs := BuildRateLimitServiceConfig([]*ir.HTTPListener{listener})
	require.Len(t, rlsConfigs, 1)
	var sawShadow bool
	for _, d := range rlsConfigs[0].GetDescriptors() {
		for _, child := range d.GetDescriptors() {
			if child.GetShadowMode() {
				sawShadow = true
			}
		}
	}
	require.True(t, sawShadow)
}

func TestRateLimitAuditCIDR(t *testing.T) {
	exactRule := auditRule("ns/exact/rule/0", auditLimit(5, egv1a1.RateLimitUnitSecond))
	exactRule.CIDRMatch = &ir.CIDRMatch{CIDR: "192.168.0.0/24", MaskLen: 24}

	distinctRule := auditRule("ns/distinct/rule/0", auditLimit(6, egv1a1.RateLimitUnitSecond))
	distinctRule.CIDRMatch = &ir.CIDRMatch{CIDR: "10.0.0.0/8", MaskLen: 8, Distinct: true}

	invertRule := auditRule("ns/invert/rule/0", auditLimit(7, egv1a1.RateLimitUnitSecond))
	invertRule.CIDRMatch = &ir.CIDRMatch{CIDR: "172.16.0.0/12", MaskLen: 12, Invert: true}

	listener := auditTestListenerWith(auditTestRouteWithRules(exactRule, distinctRule, invertRule))
	requests := []*AuditRequest{
		auditRequest("in-exact", "GET", "/a", "192.168.0.5", nil),
		auditRequest("in-distinct", "GET", "/a", "10.1.2.3", nil),
		auditRequest("in-invert", "GET", "/a", "172.16.5.5", nil),
		auditRequest("outside-all", "GET", "/a", "8.8.8.8", nil),
		// Decoy XFF must never be used as the client address.
		auditRequest("no-trusted-ip", "GET", "/a", "", map[string]string{
			"x-forwarded-for": "192.168.0.5, 10.1.2.3",
		}),
	}

	report, err := NewRateLimitDescriptorAudit().Run([]*ir.HTTPListener{listener}, requests)
	require.NoError(t, err)

	inExact := resultsFor(t, report, "in-exact", exactRule.Name)[0]
	require.Equal(t, AuditResolutionMatched, inExact.Resolution)
	require.Equal(t, []string{auditTestRoute, descriptorKeyMaskedRemoteAddress}, inExact.DescriptorKeys)
	require.Equal(t, AuditEntryAppended, inExact.Actions[1].Status)
	require.Equal(t, "192.168.0.0/24", inExact.MatchedPolicy.DescriptorPath[1].Value)

	inDistinct := resultsFor(t, report, "in-distinct", distinctRule.Name)[0]
	require.Equal(t, AuditResolutionMatched, inDistinct.Resolution)
	require.Equal(t,
		[]string{auditTestRoute, descriptorKeyMaskedRemoteAddress, descriptorKeyRemoteAddress},
		inDistinct.DescriptorKeys)
	// The distinct leaf is a key-only descriptor in the RLS tree.
	leaf := inDistinct.MatchedPolicy.DescriptorPath[2]
	require.Equal(t, descriptorKeyRemoteAddress, leaf.Key)
	require.Empty(t, leaf.Value)

	// Invert only fires outside the range.
	inInvert := resultsFor(t, report, "in-invert", invertRule.Name)[0]
	require.Equal(t, AuditResolutionNoMatch, inInvert.Resolution)
	require.Equal(t, AuditEntrySkipped, inInvert.Actions[1].Status)
	outsideInvert := resultsFor(t, report, "outside-all", invertRule.Name)[0]
	require.Equal(t, AuditResolutionMatched, outsideInvert.Resolution)
	require.Equal(t, "invert:172.16.0.0/12", outsideInvert.MatchedPolicy.DescriptorPath[1].Value)

	// Without an explicit trusted IP every CIDR action is Unknown, never a miss, and
	// the XFF header is not consulted.
	for _, rule := range []*ir.RateLimitRule{exactRule, distinctRule, invertRule} {
		r := resultsFor(t, report, "no-trusted-ip", rule.Name)[0]
		require.Equal(t, AuditDescriptorUnknown, r.DescriptorStatus)
		require.Equal(t, AuditResolutionNotInvoked, r.Resolution)
		require.Contains(t, r.UnknownReasons[0], "trusted-client-ip-unavailable")
	}
}

func TestRateLimitAuditMissingHeaderAndCase(t *testing.T) {
	distinctRule := auditRule("ns/distinct-header/rule/0", auditLimit(5, egv1a1.RateLimitUnitSecond))
	distinctRule.HeaderMatches = []*ir.StringMatch{{Name: "x-user-id", Distinct: true}}

	exactRule := auditRule("ns/exact-header/rule/0", auditLimit(5, egv1a1.RateLimitUnitSecond))
	exactRule.HeaderMatches = []*ir.StringMatch{{Name: "x-org-id", Exact: auditStr("Two")}}

	methodRule := auditRule("ns/method/rule/0", auditLimit(5, egv1a1.RateLimitUnitSecond))
	methodRule.MethodMatches = []*ir.StringMatch{{Exact: auditStr("GET")}}

	listener := auditTestListenerWith(auditTestRouteWithRules(distinctRule, exactRule, methodRule))
	requests := []*AuditRequest{
		auditRequest("ok", "GET", "/a", "", map[string]string{"x-user-id": "alice", "x-org-id": "Two"}),
		auditRequest("missing-distinct", "GET", "/a", "", map[string]string{"x-org-id": "Two"}),
		auditRequest("wrong-case", "GET", "/a", "", map[string]string{"x-user-id": "alice", "x-org-id": "two"}),
		auditRequest("lower-method", "get", "/a", "", map[string]string{"x-user-id": "alice", "x-org-id": "Two"}),
	}

	report, err := NewRateLimitDescriptorAudit().Run([]*ir.HTTPListener{listener}, requests)
	require.NoError(t, err)

	okDistinct := resultsFor(t, report, "ok", distinctRule.Name)[0]
	require.Equal(t, AuditResolutionMatched, okDistinct.Resolution)
	require.Equal(t, "rule-0-match-0", okDistinct.DescriptorKeys[1])

	// A missing distinct header aborts the whole configuration: no RLS call.
	missing := resultsFor(t, report, "missing-distinct", distinctRule.Name)[0]
	require.Equal(t, AuditDescriptorAborted, missing.DescriptorStatus)
	require.Equal(t, AuditResolutionNotInvoked, missing.Resolution)
	require.Equal(t, AuditEntryAborted, missing.Actions[1].Status)
	require.Contains(t, missing.UnknownReasons[0], "required-request-header-absent")

	// Exact value matching is case-sensitive.
	wrongCase := resultsFor(t, report, "wrong-case", exactRule.Name)[0]
	require.Equal(t, AuditResolutionNoMatch, wrongCase.Resolution)
	require.Equal(t, AuditEntrySkipped, wrongCase.Actions[1].Status)

	// :method matching is case-sensitive too.
	upperMethod := resultsFor(t, report, "ok", methodRule.Name)[0]
	require.Equal(t, AuditResolutionMatched, upperMethod.Resolution)
	lowerMethod := resultsFor(t, report, "lower-method", methodRule.Name)[0]
	require.Equal(t, AuditResolutionNoMatch, lowerMethod.Resolution)
}

func TestRateLimitAuditCosts(t *testing.T) {
	requestCost := auditUint64(3)
	responseCost := auditUint64(5)
	rule := auditRule("ns/cost/rule/0", auditLimit(5, egv1a1.RateLimitUnitSecond))
	rule.HeaderMatches = []*ir.StringMatch{{Name: "x-user-id", Exact: auditStr("alice")}}
	rule.RequestCost = &ir.RateLimitCost{Number: requestCost}
	rule.ResponseCost = &ir.RateLimitCost{Number: responseCost}

	formatRule := auditRule("ns/cost-format/rule/0", auditLimit(5, egv1a1.RateLimitUnitSecond))
	formatRule.HeaderMatches = []*ir.StringMatch{{Name: "x-user-id", Exact: auditStr("alice")}}
	formatRule.RequestCost = &ir.RateLimitCost{Format: auditStr("%BYTES_RECEIVED%")}

	listener := auditTestListenerWith(auditTestRouteWithRules(rule, formatRule))
	req := auditRequest("r1", "GET", "/a", "", map[string]string{"x-user-id": "alice"})
	report, err := NewRateLimitDescriptorAudit().Run([]*ir.HTTPListener{listener}, []*AuditRequest{req})
	require.NoError(t, err)

	var requestPhase, responsePhase *AuditRateLimitResult
	for i := range report.Results {
		r := &report.Results[i]
		if r.RuleName != rule.Name {
			continue
		}
		switch r.Phase {
		case auditPhaseRequest:
			requestPhase = r
		case auditPhaseResponse:
			responsePhase = r
		}
	}
	require.NotNil(t, requestPhase)
	require.NotNil(t, responsePhase)

	require.Equal(t, "static-number", requestPhase.HitsAddend.Source)
	require.Equal(t, uint64(3), *requestPhase.HitsAddend.Number)
	require.True(t, requestPhase.Enforcing)

	// The stream-done twin shares the descriptor but can never enforce.
	require.Equal(t, requestPhase.DescriptorKeys, responsePhase.DescriptorKeys)
	require.Equal(t, "static-number", responsePhase.HitsAddend.Source)
	require.Equal(t, uint64(5), *responsePhase.HitsAddend.Number)
	require.False(t, responsePhase.Enforcing)

	formatResult := resultsFor(t, report, "r1", formatRule.Name)[0]
	require.Equal(t, "format", formatResult.HitsAddend.Source)
	require.True(t, formatResult.HitsAddend.RuntimeResolved)
	require.Nil(t, formatResult.HitsAddend.Number)

	// The request/response-phase twins share a request ID: coverage evidence is deduplicated.
	require.Equal(t, []string{"r1"}, coverageFor(report, rule.Name).ExercisedBy)
}

func TestRateLimitAuditMultiActionAndMethodOR(t *testing.T) {
	rule := auditRule("ns/multi/rule/0", auditLimit(9, egv1a1.RateLimitUnitSecond))
	rule.HeaderMatches = []*ir.StringMatch{{Name: "x-user-id", Exact: auditStr("alice")}}
	rule.MethodMatches = []*ir.StringMatch{
		{Exact: auditStr("GET")},
		{Exact: auditStr("POST")},
	}
	rule.PathMatch = &ir.StringMatch{Prefix: auditStr("/api/")}
	rule.QueryParamMatches = []*ir.QueryParamMatch{{
		StringMatch: ir.StringMatch{Name: "team", Exact: auditStr("core")},
	}}

	listener := auditTestListenerWith(auditTestRouteWithRules(rule))
	requests := []*AuditRequest{
		auditRequest("full-get", "GET", "/api/x?team=core", "", map[string]string{"x-user-id": "alice"}),
		auditRequest("full-post", "POST", "/api/x?team=core", "", map[string]string{"x-user-id": "alice"}),
		auditRequest("wrong-query", "GET", "/api/x?team=other", "", map[string]string{"x-user-id": "alice"}),
		auditRequest("wrong-method", "DELETE", "/api/x?team=core", "", map[string]string{"x-user-id": "alice"}),
	}

	report, err := NewRateLimitDescriptorAudit().Run([]*ir.HTTPListener{listener}, requests)
	require.NoError(t, err)

	// One RateLimit per method expansion: exactly one of the two matches per request.
	fullGet := resultsFor(t, report, "full-get", rule.Name)
	require.Len(t, fullGet, 2)
	var matched, missed *AuditRateLimitResult
	for i := range fullGet {
		if fullGet[i].Resolution == AuditResolutionMatched {
			matched = &fullGet[i]
		} else {
			missed = &fullGet[i]
		}
	}
	require.NotNil(t, matched)
	require.NotNil(t, missed)
	require.Equal(t,
		[]string{auditTestRoute, "rule-0-match-0", "rule-0-method", "rule-0-path", "rule-0-match-1"},
		matched.DescriptorKeys)
	require.Equal(t, AuditEntrySkipped, missed.Actions[2].Status)

	fullPost := resultsFor(t, report, "full-post", rule.Name)
	postMatched := 0
	for _, r := range fullPost {
		if r.Resolution == AuditResolutionMatched {
			postMatched++
		}
	}
	require.Equal(t, 1, postMatched)

	wrongQuery := resultsFor(t, report, "wrong-query", rule.Name)
	for _, r := range wrongQuery {
		require.Equal(t, AuditResolutionNoMatch, r.Resolution)
	}
	wrongMethod := resultsFor(t, report, "wrong-method", rule.Name)
	for _, r := range wrongMethod {
		require.Equal(t, AuditResolutionNoMatch, r.Resolution)
		require.Equal(t, AuditEntrySkipped, r.Actions[2].Status)
	}
}

func TestRateLimitAuditRegexUnknown(t *testing.T) {
	headerRegexRule := auditRule("ns/regex-header/rule/0", auditLimit(5, egv1a1.RateLimitUnitSecond))
	headerRegexRule.HeaderMatches = []*ir.StringMatch{{Name: "x-user-id", SafeRegex: auditStr(".*")}}

	pathRegexRule := auditRule("ns/regex-path/rule/0", auditLimit(5, egv1a1.RateLimitUnitSecond))
	pathRegexRule.PathMatch = &ir.StringMatch{SafeRegex: auditStr("^/api/.*")}

	listener := auditTestListenerWith(auditTestRouteWithRules(headerRegexRule, pathRegexRule))
	req := auditRequest("r1", "GET", "/api/x", "", map[string]string{"x-user-id": "alice"})
	report, err := NewRateLimitDescriptorAudit().Run([]*ir.HTTPListener{listener}, []*AuditRequest{req})
	require.NoError(t, err)

	for _, ruleName := range []string{headerRegexRule.Name, pathRegexRule.Name} {
		r := resultsFor(t, report, "r1", ruleName)[0]
		require.Equal(t, AuditDescriptorUnknown, r.DescriptorStatus)
		require.Equal(t, AuditResolutionNotInvoked, r.Resolution)
		require.NotEmpty(t, r.UnknownReasons)
		// An unmodeled branch must never be downgraded to a miss.
		require.NotEqual(t, AuditResolutionNoMatch, r.Resolution)
	}
}

func TestRateLimitAuditMetadataOverride(t *testing.T) {
	rule := auditRule("ns/metadata/rule/0", auditLimit(5, egv1a1.RateLimitUnitSecond))
	rule.HeaderMatches = []*ir.StringMatch{{Name: "x-user-id", Exact: auditStr("alice")}}
	rule.Limit.FromMetadata = &ir.RateLimitValueMetadata{Namespace: "io.envoyproxy.eg", Key: "per-user-limit"}

	listener := auditTestListenerWith(auditTestRouteWithRules(rule))
	req := auditRequest("r1", "GET", "/a", "", map[string]string{"x-user-id": "alice"})
	report, err := NewRateLimitDescriptorAudit().Run([]*ir.HTTPListener{listener}, []*AuditRequest{req})
	require.NoError(t, err)

	r := resultsFor(t, report, "r1", rule.Name)[0]
	require.Equal(t, AuditResolutionMatched, r.Resolution)
	require.Equal(t, "dynamic-metadata", r.Override.Source)
	require.Equal(t, "io.envoyproxy.eg", r.Override.Namespace)
	require.Equal(t, "per-user-limit", r.Override.Key)
	require.False(t, r.Override.EffectiveLimitKnown)
	require.Contains(t, strings.Join(r.UnknownReasons, ","), "dynamic-metadata")
	// The effective limit is per-request: no static enforcement verdict.
	require.False(t, r.Enforcing)
}

func TestRateLimitAuditCatchAllRule(t *testing.T) {
	rule := auditRule("ns/catch-all/rule/0", auditLimit(5, egv1a1.RateLimitUnitSecond))
	listener := auditTestListenerWith(auditTestRouteWithRules(rule))

	report, err := NewRateLimitDescriptorAudit().Run(
		[]*ir.HTTPListener{listener},
		[]*AuditRequest{auditRequest("any", "GET", "/whatever", "192.0.2.1", nil)})
	require.NoError(t, err)

	r := resultsFor(t, report, "any", rule.Name)[0]
	require.Equal(t, AuditResolutionMatched, r.Resolution)
	require.Equal(t, []string{auditTestRoute, "rule-0-match--1"}, r.DescriptorKeys)
	require.True(t, r.Enforcing)
}

func TestRateLimitAuditBoundsAndRedaction(t *testing.T) {
	rule := auditRule("ns/redact/rule/0", auditLimit(5, egv1a1.RateLimitUnitSecond))
	rule.HeaderMatches = []*ir.StringMatch{{Name: "authorization", Distinct: true}}
	rule.QueryParamMatches = []*ir.QueryParamMatch{{
		StringMatch: ir.StringMatch{Name: "token", Distinct: true},
	}}
	rule.CIDRMatch = &ir.CIDRMatch{CIDR: "203.0.113.0/24", MaskLen: 24, Distinct: true}
	listener := auditTestListenerWith(auditTestRouteWithRules(rule))

	secretHeader := "s3cr3t-auth-value"
	secretQuery := "qp-secret-99"
	secretIP := "203.0.113.9"
	req := auditRequest("r1", "GET", "/a?token="+secretQuery, secretIP,
		map[string]string{"authorization": secretHeader})

	report, err := NewRateLimitDescriptorAudit().Run([]*ir.HTTPListener{listener}, []*AuditRequest{req})
	require.NoError(t, err)
	raw, err := json.Marshal(report)
	require.NoError(t, err)
	serialized := string(raw)
	require.NotContains(t, serialized, secretHeader)
	require.NotContains(t, serialized, secretQuery)
	require.NotContains(t, serialized, secretIP)
	require.Contains(t, serialized, "header:authorization")
	require.Contains(t, serialized, "query:token")
	require.Contains(t, serialized, "trusted-client-ip")

	// Corpus bound.
	_, err = NewRateLimitDescriptorAudit(AuditWithMaxRequests(1)).Run(
		[]*ir.HTTPListener{listener}, []*AuditRequest{req, req})
	require.Error(t, err)
	require.Contains(t, err.Error(), "MaxRequests")

	// Action bound.
	bigRule := auditRule("ns/big/rule/0", auditLimit(5, egv1a1.RateLimitUnitSecond))
	bigRule.HeaderMatches = []*ir.StringMatch{
		{Name: "a", Exact: auditStr("1")},
		{Name: "b", Exact: auditStr("2")},
	}
	bigListener := auditTestListenerWith(auditTestRouteWithRules(bigRule))
	_, err = NewRateLimitDescriptorAudit(AuditWithMaxActionEntries(1)).Run(
		[]*ir.HTTPListener{bigListener}, []*AuditRequest{req})
	require.Error(t, err)
	require.Contains(t, err.Error(), "MaxActionEntries")

	// Output bound.
	tiny, err := NewRateLimitDescriptorAudit(AuditWithMaxOutputBytes(64)).Run(
		[]*ir.HTTPListener{listener}, []*AuditRequest{req})
	require.NoError(t, err)
	require.True(t, tiny.Truncated)
}

func TestRateLimitAuditRunActionsParity(t *testing.T) {
	rule := auditRule("ns/parity/rule/0", auditLimit(5, egv1a1.RateLimitUnitSecond))
	rule.Shared = auditBool(true)
	rule.HeaderMatches = []*ir.StringMatch{{Name: "x-user-id", Exact: auditStr("alice")}}
	listener := auditTestListenerWith(auditTestRouteWithRules(rule))
	requests := []*AuditRequest{
		auditRequest("hit", "GET", "/a", "", map[string]string{"x-user-id": "alice"}),
		auditRequest("miss", "GET", "/a", "", map[string]string{"x-user-id": "bob"}),
	}

	auditor := NewRateLimitDescriptorAudit()
	irReport, err := auditor.Run([]*ir.HTTPListener{listener}, requests)
	require.NoError(t, err)

	// Feed the final Envoy/RLS protos produced by the real builders through the
	// proto-driven entry point.
	rlsConfigs := BuildRateLimitServiceConfig([]*ir.HTTPListener{listener})
	routeLimits := buildRouteRateLimits(listener.Name, listener.Routes[0])
	input, _, err := buildAuditRouteInput(listener.Name, listener.Routes[0], routeLimits)
	require.NoError(t, err)
	protoReport, err := auditor.RunActions([]AuditRouteInput{input}, rlsConfigs, requests)
	require.NoError(t, err)

	require.Empty(t, cmp.Diff(irReport, protoReport))
}

func TestRateLimitAuditCoverageNeverUnreachable(t *testing.T) {
	rule := auditRule("ns/covered/rule/0", auditLimit(5, egv1a1.RateLimitUnitSecond))
	rule.HeaderMatches = []*ir.StringMatch{{Name: "x-user-id", Exact: auditStr("alice")}}
	listener := auditTestListenerWith(auditTestRouteWithRules(rule))

	report, err := NewRateLimitDescriptorAudit().Run(
		[]*ir.HTTPListener{listener},
		[]*AuditRequest{auditRequest("miss", "GET", "/a", "", map[string]string{"x-user-id": "bob"})})
	require.NoError(t, err)

	raw, err := json.Marshal(report)
	require.NoError(t, err)
	require.NotContains(t, string(raw), "reachable")
	require.Equal(t, AuditRuleUnexercised, coverageFor(report, rule.Name).Status)
}

// ---- Independent matching reference ---------------------------------------
//
// The oracle below re-derives descriptor entries and RLS tree outcomes directly
// from the IR rules (not from the generated protos), providing an independent
// cross-check of the proto-driven auditor. Only exact/prefix/suffix semantics are
// modeled; regex rules are excluded and covered separately by Unknown tests.

type oracleEntry struct {
	key   string
	value string
}

type oracleVerdict struct {
	aborted bool
	unknown bool
	reason  string
	entries []oracleEntry
}

func oracleHeaderValue(req *AuditRequest, name string) (string, bool) {
	switch name {
	case ":method":
		return req.Method, req.Method != ""
	case ":path":
		return req.Path, req.Path != ""
	default:
		v, ok := req.Headers[name]
		return v, ok
	}
}

// oracleStringMatch returns (matched, unknown).
func oracleStringMatch(m *ir.StringMatch, value string) (bool, bool) {
	switch {
	case m.Exact != nil:
		return *m.Exact == value, false
	case m.Prefix != nil:
		return strings.HasPrefix(value, *m.Prefix), false
	case m.Suffix != nil:
		return strings.HasSuffix(value, *m.Suffix), false
	case m.SafeRegex != nil:
		return false, true
	default:
		return false, false
	}
}

func oracleExpect(matched bool, invert *bool) bool {
	if invert != nil && *invert {
		return !matched
	}
	return matched
}

func oracleDomainRuleIndex(allRules []*ir.RateLimitRule, globalIdx int, shared bool) int {
	count := 0
	for i := 0; i < globalIdx; i++ {
		ruleShared := allRules[i].Shared != nil && *allRules[i].Shared
		if shared == ruleShared {
			count++
		}
	}
	return count
}

func oracleEvaluate(
	routeName string, allRules []*ir.RateLimitRule, globalIdx int,
	rule *ir.RateLimitRule, methodMatch *ir.StringMatch, req *AuditRequest,
) oracleVerdict {
	v := oracleVerdict{}
	appendEntry := func(key, value string) {
		v.entries = append(v.entries, oracleEntry{key: key, value: value})
	}

	shared := rule.Shared != nil && *rule.Shared
	rootKey := routeName
	if shared {
		rootKey = rule.Name
	}
	appendEntry(rootKey, rootKey)

	// Re-derive the domain-specific rule index independently from the IR rule list.
	ruleIdx := oracleDomainRuleIndex(allRules, globalIdx, shared)
	for mIdx, hm := range rule.HeaderMatches {
		key := fmt.Sprintf("rule-%d-match-%d", ruleIdx, mIdx)
		value, present := oracleHeaderValue(req, hm.Name)
		if hm.Distinct {
			if !present {
				v.aborted = true
				v.reason = "missing-distinct-header"
				return v
			}
			appendEntry(key, value)
			continue
		}
		if hm.SafeRegex != nil {
			v.unknown = true
			v.reason = "regex"
			return v
		}
		matched, unknown := oracleStringMatch(hm, value)
		if unknown {
			v.unknown = true
			v.reason = "regex"
			return v
		}
		if oracleExpect(matched, hm.Invert) {
			appendEntry(key, key)
		}
	}

	if methodMatch != nil {
		key := fmt.Sprintf("rule-%d-method", ruleIdx)
		if methodMatch.SafeRegex != nil {
			v.unknown = true
			v.reason = "regex"
			return v
		}
		matched, unknown := oracleStringMatch(methodMatch, req.Method)
		if unknown {
			v.unknown = true
			v.reason = "regex"
			return v
		}
		if oracleExpect(matched, methodMatch.Invert) {
			appendEntry(key, key)
		}
	}

	if rule.PathMatch != nil {
		key := fmt.Sprintf("rule-%d-path", ruleIdx)
		if rule.PathMatch.SafeRegex != nil {
			v.unknown = true
			v.reason = "regex"
			return v
		}
		matched, unknown := oracleStringMatch(rule.PathMatch, req.Path)
		if unknown {
			v.unknown = true
			v.reason = "regex"
			return v
		}
		if oracleExpect(matched, rule.PathMatch.Invert) {
			appendEntry(key, key)
		}
	}

	if rule.CIDRMatch != nil {
		if req.TrustedClientIP == "" {
			v.unknown = true
			v.reason = "no-trusted-ip"
			return v
		}
		ip, err := netip.ParseAddr(req.TrustedClientIP)
		if err != nil {
			v.unknown = true
			v.reason = "bad-ip"
			return v
		}
		prefix, err := netip.ParsePrefix(rule.CIDRMatch.CIDR)
		if err != nil {
			v.unknown = true
			v.reason = "bad-cidr"
			return v
		}
		inRange := prefix.Contains(ip)
		fires := inRange
		if rule.CIDRMatch.Invert {
			fires = !inRange
		}
		if fires {
			value := rule.CIDRMatch.CIDR
			if rule.CIDRMatch.Invert {
				value = descriptorValueInvertPrefix + value
			}
			appendEntry(descriptorKeyMaskedRemoteAddress, value)
			if rule.CIDRMatch.Distinct {
				appendEntry(descriptorKeyRemoteAddress, ip.String())
			}
		}
	}

	queryOffset := len(rule.HeaderMatches)
	for mIdx, qp := range rule.QueryParamMatches {
		key := fmt.Sprintf("rule-%d-match-%d", ruleIdx, queryOffset+mIdx)
		// Query parameters are parsed from :path in both the auditor and the oracle.
		parsed, err := parseOracleQuery(req.Path)
		if err != nil {
			v.unknown = true
			v.reason = "bad-query"
			return v
		}
		qv, ok := parsed[qp.Name]
		present := ok && len(qv) > 0
		if qp.Distinct {
			if !present {
				v.aborted = true
				v.reason = "missing-distinct-query"
				return v
			}
			appendEntry(key, qv[0])
			continue
		}
		if qp.SafeRegex != nil {
			v.unknown = true
			v.reason = "regex"
			return v
		}
		matchedAny := false
		if present {
			for _, candidate := range qv {
				matched, unknown := oracleStringMatch(&qp.StringMatch, candidate)
				if unknown {
					v.unknown = true
					v.reason = "regex"
					return v
				}
				if oracleExpect(matched, qp.Invert) {
					matchedAny = true
					break
				}
			}
		}
		if matchedAny {
			appendEntry(key, key)
		}
	}

	if !rule.IsMatchSet() {
		key := fmt.Sprintf("rule-%d-match--1", ruleIdx)
		appendEntry(key, key)
	}

	return v
}

func parseOracleQuery(path string) (map[string][]string, error) {
	idx := strings.Index(path, "?")
	if idx < 0 {
		return map[string][]string{}, nil
	}
	out := map[string][]string{}
	for _, pair := range strings.Split(path[idx+1:], "&") {
		kv := strings.SplitN(pair, "=", 2)
		if len(kv) != 2 {
			continue
		}
		out[kv[0]] = append(out[kv[0]], kv[1])
	}
	return out, nil
}

// oracleResolve is an independent RLS tree walk mirroring key/value then key-only
// lookup and final-entry policy semantics.
func oracleResolve(
	configs []*rlsconfv3.RateLimitConfig, domain string, entries []oracleEntry,
) (matched, shadow bool) {
	var cfg *rlsconfv3.RateLimitConfig
	for _, c := range configs {
		if c.GetDomain() == domain {
			cfg = c
			break
		}
	}
	if cfg == nil {
		return false, false
	}
	children := cfg.GetDescriptors()
	var policy *rlsconfv3.RateLimitPolicy
	var policyNode *rlsconfv3.RateLimitDescriptor
	for i, entry := range entries {
		var next *rlsconfv3.RateLimitDescriptor
		for _, d := range children {
			if d.GetKey() == entry.key && d.GetValue() == entry.value {
				next = d
				break
			}
		}
		if next == nil {
			for _, d := range children {
				if d.GetKey() == entry.key && d.GetValue() == "" {
					next = d
					break
				}
			}
		}
		if next == nil {
			return false, false
		}
		if i == len(entries)-1 && next.GetRateLimit() != nil {
			policy = next.GetRateLimit()
			policyNode = next
		}
		if len(next.GetDescriptors()) == 0 {
			break
		}
		children = next.GetDescriptors()
	}
	if policy == nil {
		return false, false
	}
	_ = policy
	return true, policyNode.GetShadowMode()
}

func TestRateLimitAuditIndependentOracle(t *testing.T) {
	headerCIDRRule := auditRule("ns/mix-a/rule/0", auditLimit(5, egv1a1.RateLimitUnitSecond))
	headerCIDRRule.HeaderMatches = []*ir.StringMatch{{Name: "x-user-id", Exact: auditStr("alice")}}
	headerCIDRRule.QueryParamMatches = []*ir.QueryParamMatch{{
		StringMatch: ir.StringMatch{Name: "team", Distinct: true},
	}}
	headerCIDRRule.CIDRMatch = &ir.CIDRMatch{CIDR: "10.0.0.0/8", MaskLen: 8, Distinct: true}

	methodPathRule := auditRule("ns/mix-b/rule/0", auditLimit(8, egv1a1.RateLimitUnitHour))
	methodPathRule.Shared = auditBool(true)
	methodPathRule.MethodMatches = []*ir.StringMatch{
		{Exact: auditStr("GET")},
		{Exact: auditStr("POST")},
	}
	methodPathRule.PathMatch = &ir.StringMatch{Prefix: auditStr("/api/")}

	catchAllRule := auditRule("ns/mix-c/rule/0", auditLimit(3, egv1a1.RateLimitUnitDay))

	listener := auditTestListenerWith(auditTestRouteWithRules(headerCIDRRule, methodPathRule, catchAllRule))
	rlsConfigs := BuildRateLimitServiceConfig([]*ir.HTTPListener{listener})
	requests := []*AuditRequest{
		auditRequest("full", "GET", "/api/x?team=core", "10.0.0.9",
			map[string]string{"x-user-id": "alice"}),
		auditRequest("missing-header", "GET", "/api/x?team=core", "10.0.0.9", nil),
		auditRequest("missing-query", "POST", "/api/x", "10.0.0.9",
			map[string]string{"x-user-id": "alice"}),
		auditRequest("outside-cidr", "GET", "/api/x?team=core", "18.0.0.1",
			map[string]string{"x-user-id": "alice"}),
		auditRequest("no-ip", "GET", "/api/x?team=core", "",
			map[string]string{"x-user-id": "alice"}),
		auditRequest("path-miss", "POST", "/web?team=core", "10.0.0.9",
			map[string]string{"x-user-id": "alice"}),
	}

	report, err := NewRateLimitDescriptorAudit().Run([]*ir.HTTPListener{listener}, requests)
	require.NoError(t, err)

	rules := []*ir.RateLimitRule{headerCIDRRule, methodPathRule, catchAllRule}
	evaluated := 0
	for _, req := range requests {
		for rIdx, rule := range rules {
			methods := rule.MethodMatches
			if len(methods) == 0 {
				methods = []*ir.StringMatch{nil}
			}
			domain := auditTestListener
			if rule.Shared != nil && *rule.Shared {
				domain = stripRuleIndexSuffix(rule.Name)
			}
			matches := resultsFor(t, report, req.ID, rule.Name)
			for methodIdx, methodMatch := range methods {
				verdict := oracleEvaluate(auditTestRoute, rules, rIdx, rule, methodMatch, req)

				// One request-phase RateLimit per method expansion, in builder order.
				require.Less(t, methodIdx, len(matches))
				got := &matches[methodIdx]
				require.Equal(t, domain, got.Domain)

				switch {
				case verdict.aborted:
					require.Equal(t, AuditDescriptorAborted, got.DescriptorStatus,
						"%s/%s", req.ID, rule.Name)
				case verdict.unknown:
					require.Equal(t, AuditDescriptorUnknown, got.DescriptorStatus,
						"%s/%s: %s", req.ID, rule.Name, verdict.reason)
				default:
					require.Equal(t, AuditDescriptorGenerated, got.DescriptorStatus,
						"%s/%s", req.ID, rule.Name)
					wantKeys := make([]string, 0, len(verdict.entries))
					for _, e := range verdict.entries {
						wantKeys = append(wantKeys, e.key)
					}
					require.Equal(t, wantKeys, got.DescriptorKeys,
						"%s/%s descriptor keys", req.ID, rule.Name)

					wantMatched, wantShadow := oracleResolve(rlsConfigs, domain, verdict.entries)
					if wantMatched {
						require.Equal(t, AuditResolutionMatched, got.Resolution,
							"%s/%s resolution", req.ID, rule.Name)
						require.Equal(t, wantShadow, got.MatchedPolicy.ShadowMode)
						require.Equal(t, wantShadow == false, got.Enforcing,
							"%s/%s enforcing", req.ID, rule.Name)
					} else {
						require.Equal(t, AuditResolutionNoMatch, got.Resolution,
							"%s/%s resolution", req.ID, rule.Name)
						require.False(t, got.Enforcing)
					}
				}
				evaluated++
			}
		}
	}

	// Every request-phase RateLimit produced by the real builder must have been
	// cross-checked against the oracle.
	requestPhaseResults := 0
	for _, r := range report.Results {
		if r.Phase == auditPhaseRequest {
			requestPhaseResults++
		}
	}
	require.Equal(t, evaluated, requestPhaseResults)
}

// TestRateLimitAuditReusesBuilders ensures the audit runs on real builder outputs
// and never on assumed descriptors: route protos built here come straight from
// buildRouteRateLimits, and RLS configs from BuildRateLimitServiceConfig.
func TestRateLimitAuditReusesBuilders(t *testing.T) {
	rule := auditRule("ns/builder/rule/0", auditLimit(5, egv1a1.RateLimitUnitSecond))
	rule.HeaderMatches = []*ir.StringMatch{{Name: "x-user-id", Exact: auditStr("alice")}}
	route := auditTestRouteWithRules(rule)
	listener := auditTestListenerWith(route)

	routeLimits := buildRouteRateLimits(listener.Name, route)
	require.NotNil(t, routeLimits[auditTestListener])
	require.IsType(t, &routev3.RateLimit{}, routeLimits[auditTestListener][0])

	rlsConfigs := BuildRateLimitServiceConfig([]*ir.HTTPListener{listener})
	require.Len(t, rlsConfigs, 1)
	require.NotEmpty(t, rlsConfigs[0].GetDescriptors())

	report, err := NewRateLimitDescriptorAudit().Run(
		[]*ir.HTTPListener{listener},
		[]*AuditRequest{auditRequest("r1", "GET", "/a", "", map[string]string{"x-user-id": "alice"})})
	require.NoError(t, err)
	require.NotEmpty(t, report.Results)
}
