// Copyright Envoy Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package irwitness

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/envoyproxy/gateway/internal/ir"
	xds_types "github.com/envoyproxy/gateway/internal/xds/types"
)

// mustCompile compiles a spec or fails the test.
func mustCompile(t *testing.T, spec *PredicateSpec) Predicate {
	t.Helper()
	pred, err := CompilePredicate(spec)
	require.NoError(t, err)
	return pred
}

// TestReduceTwoRoutesSharedBackend verifies that a BackendCluster referenced
// by two routes is retained while both routes live, is never reclaimed while
// one route still references it, and is only removed together with the last
// referencing route (which then fails the target).
func TestReduceTwoRoutesSharedBackend(t *testing.T) {
	sharedCluster := "service/default/shared/8080/http"
	x := &ir.Xds{
		HTTP: []*ir.HTTPListener{baseListener("gw/http",
			clusterRefRoute("route-1", "/r1", sharedCluster),
			clusterRefRoute("route-2", "/r2", sharedCluster),
		)},
		BackendClusters: []*ir.BackendCluster{backendCluster(sharedCluster, "7.7.7.7", 8080)},
	}
	require.NoError(t, x.Validate())

	pred := mustCompile(t, resourceExistsSpec("cluster", sharedCluster))
	before := canonicalDigest(x)

	result, err := Reduce(context.Background(), x, pred, testOptions())
	require.NoError(t, err)
	require.Equal(t, StatusOneMinimal, result.Status)

	// Original IR is untouched.
	require.Equal(t, before, canonicalDigest(x))
	require.Len(t, x.HTTP[0].Routes, 2)
	require.Len(t, x.BackendClusters, 1)

	// Exactly one route is removed; the shared cluster survives because the
	// remaining route still references it.
	require.Len(t, result.BestKnown.HTTP[0].Routes, 1)
	require.Len(t, result.BestKnown.BackendClusters, 1)
	require.Equal(t, sharedCluster, result.BestKnown.BackendClusters[0].Name)

	// No accepted deletion may have reclaimed the shared cluster while a
	// referrer remained.
	for _, op := range result.Deletions {
		for _, reclaimed := range op.Reclaimed {
			require.NotContains(t, reclaimed, sharedCluster)
		}
	}

	// Every recorded verdict is real: true verdicts only after validate +
	// translate + predicate, and no failure class masquerades as true.
	for _, record := range result.Log {
		if record.Verdict == VerdictTrue {
			require.Empty(t, record.Reason)
		} else {
			require.NotEmpty(t, record.Reason)
		}
	}
}

// TestReduceMirrorUniqueDependency covers a mirror destination that is the
// sole referrer of a standalone BackendCluster.
func TestReduceMirrorUniqueDependency(t *testing.T) {
	primaryCluster := "cluster-primary"
	mirrorCluster := "cluster-mirror-only"
	otherCluster := "cluster-other"

	mirrorRT := mirrorRoute("mirror-route", primaryCluster, mirrorCluster)
	// The primary cluster is shared with a second route, so deleting the mirror
	// route must only reclaim the mirror-only dependency.
	sharedRT := clusterRefRoute("shared-route", "/shared", primaryCluster)
	otherRT := clusterRefRoute("other-route", "/other", otherCluster)
	x := &ir.Xds{
		HTTP: []*ir.HTTPListener{baseListener("gw/http", mirrorRT, sharedRT, otherRT)},
		BackendClusters: []*ir.BackendCluster{
			backendCluster(primaryCluster, "7.7.7.7", 8080),
			backendCluster(mirrorCluster, "8.8.8.8", 8080),
			backendCluster(otherCluster, "9.9.9.9", 8080),
		},
	}
	require.NoError(t, x.Validate())

	// Structural check first: deleting the mirror route reclaims the
	// mirror-only cluster but keeps the shared primary cluster.
	candidate, op, err := removeRoute(x, "gw/http", "mirror-route")
	require.NoError(t, err)
	require.Contains(t, op.Reclaimed, string(DeletionBackendCluster)+":"+mirrorCluster)
	for _, reclaimed := range op.Reclaimed {
		require.NotContains(t, reclaimed, primaryCluster)
	}
	require.NoError(t, candidate.Validate())

	pred := mustCompile(t, resourceExistsSpec("cluster", mirrorCluster))
	result, err := Reduce(context.Background(), x, pred, testOptions())
	require.NoError(t, err)
	require.Equal(t, StatusOneMinimal, result.Status)

	// The unrelated routes can be removed, but the mirror route (with its
	// unique mirror dependency) must survive.
	var routeNames []string
	for _, route := range result.BestKnown.HTTP[0].Routes {
		routeNames = append(routeNames, route.Name)
	}
	require.Contains(t, routeNames, "mirror-route")
	require.NotContains(t, routeNames, "other-route")
	require.NotNil(t, result.BestKnown.GetHTTPListener("gw/http").Routes[0].Mirrors)
	clusterNames := map[string]bool{}
	for _, cluster := range result.BestKnown.BackendClusters {
		clusterNames[cluster.Name] = true
	}
	require.True(t, clusterNames[mirrorCluster])
	require.True(t, clusterNames[primaryCluster])
	require.False(t, clusterNames[otherCluster])
}

// TestTwoFilterCoexistence uses a predicate that only holds while both Wasm
// HTTP filters exist in the translated HCM.
func TestTwoFilterCoexistence(t *testing.T) {
	listenerName := "gw/http"
	x := &ir.Xds{
		HTTP: []*ir.HTTPListener{baseListener(listenerName, twoFilterRoute())},
	}
	require.NoError(t, x.Validate())

	hcmPath := func(wasmName string) string {
		return "defaultFilterChain.filters[name=envoy.filters.network.http_connection_manager]" +
			".typedConfig.httpFilters[name=envoy.filters.http.wasm/" + wasmName + "]"
	}
	spec := &PredicateSpec{And: []*PredicateSpec{
		{FieldExists: &FieldProbe{Type: "listener", Name: listenerName, Field: hcmPath("policy/wasm/0")}},
		{FieldExists: &FieldProbe{Type: "listener", Name: listenerName, Field: hcmPath("policy/wasm/1")}},
	}}
	pred := mustCompile(t, spec)

	// Sanity: the original translation really carries both filters.
	ev := newEvaluator(testOptions(), pred, 100)
	rvt, err := ev.newTranslator().Translate(context.Background(), x)
	require.NoError(t, err)
	require.True(t, pred.Eval(rvt))

	opts := testOptions()
	opts.EnableFilterGroupDeletions = true
	result, err := Reduce(context.Background(), x, pred, opts)
	require.NoError(t, err)
	require.Equal(t, StatusOneMinimal, result.Status)

	// Both filters survive: deleting either one flips the conjunction false.
	remaining := result.BestKnown.HTTP[0].Routes[0].EnvoyExtensions.Wasms
	require.Len(t, remaining, 2)

	// With filter deletions disabled, no filter-entry operation is ever
	// attempted.
	plainResult, err := Reduce(context.Background(), x, pred, testOptions())
	require.NoError(t, err)
	for _, record := range plainResult.Log {
		require.NotEqual(t, DeletionFilterEntry, record.Operation.Kind)
	}
}

// TestCacheKeySeparationAndReuse proves the cache cannot be polluted across
// different source digests and that identical inputs hit the cache.
func TestCacheKeySeparationAndReuse(t *testing.T) {
	clusterA := "cluster-a"
	x1 := &ir.Xds{
		HTTP:            []*ir.HTTPListener{baseListener("gw/http", clusterRefRoute("route-a", "/a", clusterA))},
		BackendClusters: []*ir.BackendCluster{backendCluster(clusterA, "7.7.7.7", 8080)},
	}
	x2 := &ir.Xds{
		HTTP:            []*ir.HTTPListener{baseListener("gw/http", clusterRefRoute("route-b", "/b", "cluster-b"))},
		BackendClusters: []*ir.BackendCluster{backendCluster("cluster-b", "8.8.8.8", 8080)},
	}
	pred := mustCompile(t, resourceExistsSpec("cluster", clusterA))
	ev := newEvaluator(testOptions(), pred, 100)

	verdict, _, hit, exhausted := ev.evaluate(context.Background(), x1, DeletionOp{Kind: DeletionInitial})
	require.False(t, hit)
	require.False(t, exhausted)
	require.Equal(t, VerdictTrue, verdict)

	// Same content, independent copy: cache hit with the same verdict.
	verdict, _, hit, _ = ev.evaluate(context.Background(), x1.DeepCopy(), DeletionOp{Kind: DeletionRoute, Target: "dup"})
	require.True(t, hit)
	require.Equal(t, VerdictTrue, verdict)

	// Different source digest: no polluted hit, and the predicate is false on
	// the second IR because cluster-a does not exist there.
	verdict, _, hit, _ = ev.evaluate(context.Background(), x2, DeletionOp{Kind: DeletionRoute, Target: "other"})
	require.False(t, hit)
	require.Equal(t, VerdictFalse, verdict)

	// Low-level key check: the three key components all participate.
	base := cacheKey{optionsDigest: optionsDigest(testOptions()), predicateDigest: pred.Digest(), sourceDigest: canonicalDigest(x1)}
	require.NotEqual(t, base.String(), cacheKey{base.optionsDigest, base.predicateDigest, canonicalDigest(x2)}.String())
	require.NotEqual(t, base.String(), cacheKey{base.optionsDigest, "other-predicate", base.sourceDigest}.String())
	require.NotEqual(t, base.String(), cacheKey{"other-opts", base.predicateDigest, base.sourceDigest}.String())
}

// TestCancellationReturnsBestKnown verifies a mid-run cancellation returns the
// last artifact re-verified true with the Incomplete marker.
func TestCancellationReturnsBestKnown(t *testing.T) {
	clusterKeep := "cluster-keep"
	x := &ir.Xds{
		HTTP: []*ir.HTTPListener{
			baseListener("gw/http",
				clusterRefRoute("keep-route", "/keep", clusterKeep),
				clusterRefRoute("drop-route", "/drop", "cluster-drop"),
			),
		},
		BackendClusters: []*ir.BackendCluster{
			backendCluster(clusterKeep, "7.7.7.7", 8080),
			backendCluster("cluster-drop", "8.8.8.8", 8080),
		},
	}
	require.NoError(t, x.Validate())

	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	inner := mustCompile(t, resourceExistsSpec("cluster", clusterKeep))
	realPred := &GoPredicate{
		Deterministic: true,
		CallBudget:    100,
		ID:            "cancel-after-two",
		Description:   "cancels after the first couple of evaluations",
		Fn: func(table *xds_types.ResourceVersionTable) bool {
			calls++
			if calls >= 2 {
				cancel()
			}
			return inner.Eval(table)
		},
	}

	result, err := Reduce(ctx, x, realPred, testOptions())
	require.NoError(t, err)
	require.Equal(t, StatusIncomplete, result.Status)
	require.NotEmpty(t, result.IncompleteReason)
	require.NotNil(t, result.BestKnown)
	require.NotEmpty(t, result.BestKnownDigest)

	// The BestKnown artifact must itself re-verify true on a fresh context.
	fresh := newEvaluator(testOptions(), realPred, 100)
	rvt, err := fresh.newTranslator().Translate(context.Background(), result.BestKnown)
	require.NoError(t, err)
	require.True(t, realPred.Eval(rvt))
}

// TestBudgetBoundary verifies a one-evaluation budget stops after the mandatory
// initial verification and reports Incomplete with the original as BestKnown.
func TestBudgetBoundary(t *testing.T) {
	x := &ir.Xds{
		HTTP: []*ir.HTTPListener{
			baseListener("gw/http",
				clusterRefRoute("route-1", "/r1", "cluster-1"),
				clusterRefRoute("route-2", "/r2", "cluster-2"),
			),
		},
		BackendClusters: []*ir.BackendCluster{
			backendCluster("cluster-1", "7.7.7.7", 8080),
			backendCluster("cluster-2", "8.8.8.8", 8080),
		},
	}
	require.NoError(t, x.Validate())

	opts := testOptions()
	opts.MaxEvaluations = 1
	pred := mustCompile(t, resourceExistsSpec("cluster", "cluster-1"))
	result, err := Reduce(context.Background(), x, pred, opts)
	require.NoError(t, err)
	require.Equal(t, StatusIncomplete, result.Status)
	require.Equal(t, 1, result.Evaluations)
	require.Equal(t, result.OriginalDigest, result.BestKnownDigest)
	require.Len(t, result.BestKnown.HTTP[0].Routes, 2)
}

// TestExhaustiveSingleStepMinimality independently verifies the 1-Minimal
// claim on a small IR by applying every legal single-step deletion and
// evaluating each candidate through a real translator.
func TestExhaustiveSingleStepMinimality(t *testing.T) {
	clusterKeep := "cluster-keep"
	x := &ir.Xds{
		HTTP: []*ir.HTTPListener{baseListener("gw/http",
			clusterRefRoute("keep-route", "/keep", clusterKeep),
			clusterRefRoute("drop-route", "/drop", "cluster-drop"),
		)},
		BackendClusters: []*ir.BackendCluster{
			backendCluster(clusterKeep, "7.7.7.7", 8080),
			backendCluster("cluster-drop", "8.8.8.8", 8080),
		},
	}
	pred := mustCompile(t, resourceExistsSpec("cluster", clusterKeep))
	result, err := Reduce(context.Background(), x, pred, testOptions())
	require.NoError(t, err)
	require.Equal(t, StatusOneMinimal, result.Status)

	ev := newEvaluator(testOptions(), pred, 100)
	check := func(candidate *ir.Xds, op DeletionOp) {
		verdict, _, _, exhausted := ev.evaluate(context.Background(), candidate, op)
		require.False(t, exhausted)
		require.False(t, verdict.IsTrue(), "single-step deletion %s unexpectedly preserves target: %s", op.Target, verdict)
	}

	// Every surviving listener deletion.
	for _, name := range listenerNames(result.BestKnown) {
		candidate, op, err := removeHTTPListener(result.BestKnown, name)
		require.NoError(t, err)
		check(candidate, op)
	}
	// Every surviving route deletion (with its reclamation closure).
	for _, key := range routeKeys(result.BestKnown) {
		candidate, op, err := removeRoute(result.BestKnown, key.listener, key.route)
		require.NoError(t, err)
		check(candidate, op)
	}
	// No orphaned definitions may remain on a fixed-point artifact.
	sweepCopy := result.BestKnown.DeepCopy()
	require.Empty(t, sweepOrphans(sweepCopy))
}

// TestArtifactReloadAndTranslate reparses every emitted artifact and proves the
// target still holds through the real translator.
func TestArtifactReloadAndTranslate(t *testing.T) {
	clusterKeep := "cluster-keep"
	x := &ir.Xds{
		HTTP: []*ir.HTTPListener{baseListener("gw/http",
			clusterRefRoute("keep-route", "/keep", clusterKeep),
			settingsRoute("inline-route", "/inline", "inline-dest", "6.6.6.6", 8080),
		)},
		BackendClusters: []*ir.BackendCluster{backendCluster(clusterKeep, "7.7.7.7", 8080)},
	}
	pred := mustCompile(t, resourceExistsSpec("cluster", clusterKeep))
	result, err := Reduce(context.Background(), x, pred, testOptions())
	require.NoError(t, err)

	for _, format := range []string{FormatYAML, FormatJSON} {
		data, err := MarshalArtifact(result.BestKnown, format)
		require.NoError(t, err)
		reloaded, err := LoadArtifact(data, format)
		require.NoError(t, err)
		require.NoError(t, reloaded.Validate())

		ev := newEvaluator(testOptions(), pred, 100)
		rvt, err := ev.newTranslator().Translate(context.Background(), reloaded)
		require.NoError(t, err)
		require.True(t, pred.Eval(rvt), "reloaded %s artifact lost the target property", format)

		// The reloaded artifact must be structurally equal to the result.
		require.Empty(t, cmp.Diff(result.BestKnown, reloaded))
	}
}

// TestOriginalIRRemainsImmutable proves the caller's object graph is not
// mutated, including slice lengths and registry contents.
func TestOriginalIRRemainsImmutable(t *testing.T) {
	clusterA, clusterB := "cluster-a", "cluster-b"
	original := &ir.Xds{
		HTTP: []*ir.HTTPListener{baseListener("gw/http",
			clusterRefRoute("route-1", "/r1", clusterA),
			clusterRefRoute("route-2", "/r2", clusterB),
		)},
		BackendClusters: []*ir.BackendCluster{
			backendCluster(clusterA, "7.7.7.7", 8080),
			backendCluster(clusterB, "8.8.8.8", 8080),
		},
	}
	snapshot := original.DeepCopy()

	pred := mustCompile(t, resourceExistsSpec("cluster", clusterA))
	_, err := Reduce(context.Background(), original, pred, testOptions())
	require.NoError(t, err)
	require.Empty(t, cmp.Diff(snapshot, original))
}

// TestUnsupportedInputs verifies live-extension dependencies are rejected
// explicitly instead of being contacted online.
func TestUnsupportedInputs(t *testing.T) {
	x := &ir.Xds{
		HTTP: []*ir.HTTPListener{baseListener("gw/http", clusterRefRoute("route-1", "/r1", "cluster-1"))},
		BackendClusters: []*ir.BackendCluster{
			backendCluster("cluster-1", "7.7.7.7", 8080),
		},
		ExtensionServerPolicies: []*ir.UnstructuredRef{{Name: "foo/bar/ext"}},
	}
	pred := mustCompile(t, resourceExistsSpec("cluster", "cluster-1"))
	result, err := Reduce(context.Background(), x, pred, testOptions())
	require.NoError(t, err)
	require.Equal(t, StatusUnsupported, result.Status)
	require.NotEmpty(t, result.UnsupportedReason)
	require.Nil(t, result.BestKnown)
}

// TestInitialTargetFalseRejected verifies a false target on the original input
// aborts the run instead of producing a misleading artifact.
func TestInitialTargetFalseRejected(t *testing.T) {
	x := &ir.Xds{
		HTTP:            []*ir.HTTPListener{baseListener("gw/http", clusterRefRoute("route-1", "/r1", "cluster-1"))},
		BackendClusters: []*ir.BackendCluster{backendCluster("cluster-1", "7.7.7.7", 8080)},
	}
	pred := mustCompile(t, resourceExistsSpec("cluster", "does-not-exist"))
	result, err := Reduce(context.Background(), x, pred, testOptions())
	require.Error(t, err)
	require.Nil(t, result)
}

// TestPredicateCompileBounds exercises the bounded CLI predicate surface.
func TestPredicateCompileBounds(t *testing.T) {
	_, err := CompilePredicate(nil)
	require.Error(t, err)

	// Two operators on one node.
	_, err = CompilePredicate(&PredicateSpec{
		And:            []*PredicateSpec{{ResourceExists: &ResourceRef{Type: "cluster", Name: "a"}}, {ResourceExists: &ResourceRef{Type: "cluster", Name: "b"}}},
		ResourceExists: &ResourceRef{Type: "cluster", Name: "c"},
	})
	require.Error(t, err)

	// Unknown resource type.
	_, err = CompilePredicate(&PredicateSpec{ResourceExists: &ResourceRef{Type: "nope", Name: "x"}})
	require.Error(t, err)

	// Bad field path.
	_, err = CompilePredicate(&PredicateSpec{FieldExists: &FieldProbe{Type: "cluster", Name: "x", Field: "a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q"}})
	require.Error(t, err)

	// Valid predicate gets a stable digest and description.
	p1 := mustCompile(t, &PredicateSpec{Not: &PredicateSpec{ResourceExists: &ResourceRef{Type: "route", Name: "r"}}})
	p2 := mustCompile(t, &PredicateSpec{Not: &PredicateSpec{ResourceExists: &ResourceRef{Type: "route", Name: "r"}}})
	require.Equal(t, p1.Digest(), p2.Digest())
	require.NotEmpty(t, p1.Describe())
}

// TestCanonicalDigestSemantics verifies ordering, nil/empty distinction and
// sharing are all represented in the source digest.
func TestCanonicalDigestSemantics(t *testing.T) {
	base := func() *ir.Xds {
		return &ir.Xds{
			HTTP: []*ir.HTTPListener{
				baseListener("l1", clusterRefRoute("r1", "/r1", "c1")),
				baseListener("l2", clusterRefRoute("r2", "/r2", "c2")),
			},
		}
	}

	first := base()
	second := base()
	require.Equal(t, canonicalDigest(first), canonicalDigest(second))

	// Slice order matters.
	reordered := base()
	reordered.HTTP[0], reordered.HTTP[1] = reordered.HTTP[1], reordered.HTTP[0]
	require.NotEqual(t, canonicalDigest(first), canonicalDigest(reordered))

	// Nil vs explicit empty slice differ.
	withEmpty := base()
	withEmpty.HTTP[0].Routes = []*ir.HTTPRoute{}
	nilRoutes := base()
	nilRoutes.HTTP[0].Routes = nil
	require.NotEqual(t, canonicalDigest(withEmpty), canonicalDigest(nilRoutes))

	// Shared pointer identity is encoded: the same digest is stable and a
	// content change to the shared object changes it.
	cluster := backendCluster("shared", "7.7.7.7", 8080)
	sharedGraph := &ir.Xds{BackendClusters: []*ir.BackendCluster{cluster}}
	require.Equal(t, canonicalDigest(sharedGraph), canonicalDigest(sharedGraph.DeepCopy()))
	cluster.Setting.Endpoints[0].Port = 9090
	require.NotEqual(t, canonicalDigest(sharedGraph), canonicalDigest(base()))

	// Secret bytes never appear in canonical text, but change the digest.
	secretIR := &ir.Xds{
		HTTP: []*ir.HTTPListener{func() *ir.HTTPListener {
			l := baseListener("tls", settingsRoute("r", "/r", "d", "1.1.1.1", 8080))
			return l
		}()},
	}
	d1 := canonicalDigest(secretIR)
	secretIR.HTTP[0].Routes[0].CredentialInjection = &ir.CredentialInjection{
		Name:       "cred",
		Credential: ir.PrivateBytes("super-secret-token"),
	}
	d2 := canonicalDigest(secretIR)
	require.NotEqual(t, d1, d2)
	require.True(t, secretBearing(secretIR))
}

// TestGoPredicateDeclarations verifies the determinism and call-budget
// declarations are enforced.
func TestGoPredicateDeclarations(t *testing.T) {
	baseIR := &ir.Xds{
		HTTP:            []*ir.HTTPListener{baseListener("gw", clusterRefRoute("r", "/r", "c"))},
		BackendClusters: []*ir.BackendCluster{backendCluster("c", "7.7.7.7", 8080)},
	}

	_, err := Reduce(context.Background(), baseIR, &GoPredicate{
		Fn: func(_ *xds_types.ResourceVersionTable) bool { return true },
	}, testOptions())
	require.Error(t, err)

	_, err = Reduce(context.Background(), baseIR, &GoPredicate{
		Deterministic: true,
		Fn:            func(_ *xds_types.ResourceVersionTable) bool { return true },
	}, testOptions())
	require.Error(t, err)

	// A properly declared predicate whose function returns false on the real
	// table is treated like any false target.
	pred := &GoPredicate{
		Deterministic: true,
		CallBudget:    10,
		ID:            "always-false",
		Fn:            func(_ *xds_types.ResourceVersionTable) bool { return false },
	}
	_, err = Reduce(context.Background(), baseIR, pred, testOptions())
	require.Error(t, err)
}

// TestEvalTimeoutIsNotTrue ensures a timeout/cancellation verdict can never
// count as the target holding.
func TestEvalTimeoutIsNotTrue(t *testing.T) {
	x := &ir.Xds{
		HTTP:            []*ir.HTTPListener{baseListener("gw/http", clusterRefRoute("route-1", "/r1", "cluster-1"))},
		BackendClusters: []*ir.BackendCluster{backendCluster("cluster-1", "7.7.7.7", 8080)},
	}
	// A pre-cancelled parent context deterministically aborts the evaluation
	// before translation, independent of scheduler timing.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	pred := mustCompile(t, resourceExistsSpec("cluster", "cluster-1"))
	ev := newEvaluator(testOptions(), pred, 10)
	verdict, _, _, exhausted := ev.evaluate(ctx, x, DeletionOp{Kind: DeletionInitial})
	require.False(t, exhausted)
	require.Equal(t, VerdictCancelled, verdict)
	require.False(t, verdict.IsTrue())
}
