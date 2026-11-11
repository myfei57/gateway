// Copyright Envoy Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package irwitness

import (
	"context"
	"errors"
	"fmt"
	"strings"

	egv1a1 "github.com/envoyproxy/gateway/api/v1alpha1"
	"github.com/envoyproxy/gateway/internal/ir"
)

// routeKey locates one route within the current IR.
type routeKey struct {
	listener string
	route    string
}

// filterKey locates one extension filter entry within the current IR.
type filterKey struct {
	listener string
	route    string
	group    FilterGroup
	index    int
}

type reducer struct {
	original *ir.Xds
	pred     Predicate
	opts     Options
	ev       *evaluator

	best       *ir.Xds
	bestDigest string
	accepted   []DeletionOp

	stopped    bool
	stopReason string
}

// Reduce shrinks original while keeping the target predicate reproducible by
// real Translator.Translate calls. The original IR is never mutated and never
// embedded in the returned artifacts.
func Reduce(ctx context.Context, original *ir.Xds, pred Predicate, opts Options) (*Result, error) {
	if original == nil {
		return nil, errors.New("input ir.Xds must not be nil")
	}
	if pred == nil {
		return nil, errors.New("target predicate must not be nil")
	}
	if goPred, ok := pred.(*GoPredicate); ok {
		if !goPred.Deterministic {
			return nil, errors.New("Go predicates must declare Deterministic=true")
		}
		if goPred.CallBudget <= 0 {
			return nil, errors.New("Go predicates must declare a positive CallBudget")
		}
		if goPred.ID == "" {
			return nil, errors.New("Go predicates must declare a stable ID for the cache key")
		}
		if opts.MaxEvaluations == 0 || goPred.CallBudget < opts.MaxEvaluations {
			// Honor the smaller of the translator budget and the predicate's
			// own declared call budget.
			if opts.MaxEvaluations == 0 {
				opts.MaxEvaluations = goPred.CallBudget
			} else {
				opts.MaxEvaluations = minInt(opts.MaxEvaluations, goPred.CallBudget)
			}
		}
	}
	if opts.MaxEvaluations <= 0 {
		opts.MaxEvaluations = DefaultMaxEvaluations
	}
	// FilterOrder is part of the fixed translation options; snapshot it from
	// the input once so every evaluation uses identical options.
	opts.FilterOrder = append([]egv1a1.FilterPosition(nil), original.FilterOrder...)

	result := &Result{
		SecretBearing: secretBearing(original),
	}
	if reasons := unsupportedReasons(original); len(reasons) > 0 {
		result.Status = StatusUnsupported
		result.UnsupportedReason = joinReasons(reasons)
		result.OriginalDigest = canonicalDigest(original)
		return result, nil
	}

	ev := newEvaluator(opts, pred, opts.MaxEvaluations)
	r := &reducer{
		original: original,
		pred:     pred,
		opts:     opts,
		ev:       ev,
	}

	// Step 1: the unmodified input must validate, translate and satisfy the
	// target. Nothing is reduced if this does not hold.
	initialVerdict, reason, _, budgetExhausted := ev.evaluate(ctx, original.DeepCopy(), DeletionOp{
		Kind:   DeletionInitial,
		Target: "original",
	})
	if budgetExhausted {
		return nil, errors.New("evaluation budget exhausted before the original input could be verified")
	}
	if !initialVerdict.IsTrue() {
		return nil, fmt.Errorf("target predicate does not hold on the original input: %s: %s", initialVerdict, reason)
	}

	r.best = original.DeepCopy()
	r.bestDigest = canonicalDigest(r.best)

	// Step 2: layered reduction. Every layer greedily tries single units and
	// then bounded group deletions (delta debugging) on the survivors.
	r.runLayers(ctx)

	// Step 3: prove the fixed point over every legal single-step deletion. A
	// surviving deletion means the layered loop missed an interaction, so the
	// accepted candidate is fed back through the layers before trying again.
	// Only a fully enumerated, all-failing fixed point earns 1-Minimal.
	status := StatusIncomplete
	for !r.stopped {
		if r.proveFixedPoint(ctx) {
			status = StatusOneMinimal
			break
		}
		if r.stopped {
			break
		}
		r.runLayers(ctx)
	}

	r.fillResult(result, status)
	return result, nil
}

// runLayers executes one full pass over the declared deletion layers.
func (r *reducer) runLayers(ctx context.Context) {
	for {
		if err := ctx.Err(); err != nil {
			r.markStopped("context cancelled: " + err.Error())
			return
		}
		progress := false
		if r.layerListeners(ctx) {
			progress = true
		}
		if r.stopped {
			return
		}
		if r.layerRoutes(ctx) {
			progress = true
		}
		if r.stopped {
			return
		}
		if r.layerOrphans(ctx) {
			progress = true
		}
		if r.stopped {
			return
		}
		if r.opts.EnableFilterGroupDeletions && r.layerFilters(ctx) {
			progress = true
		}
		if r.stopped || !progress {
			return
		}
	}
}

func (r *reducer) markStopped(reason string) {
	if !r.stopped {
		r.stopped = true
		r.stopReason = reason
	}
}

// try evaluates candidate and, when the verdict proves the target still
// holds, promotes the candidate to best.
func (r *reducer) try(ctx context.Context, candidate *ir.Xds, op DeletionOp) bool {
	verdict, _, _, budgetExhausted := r.ev.evaluate(ctx, candidate, op)
	if budgetExhausted {
		r.markStopped(fmt.Sprintf("evaluation budget of %d real translations exhausted", r.opts.MaxEvaluations))
		return false
	}
	if verdict == VerdictCancelled || verdict == VerdictTimeout {
		r.markStopped("evaluation stopped: " + string(verdict))
		return false
	}
	if !verdict.IsTrue() {
		return false
	}
	r.best = candidate
	r.bestDigest = r.ev.log[len(r.ev.log)-1].CandidateDigest
	r.accepted = append(r.accepted, op)
	return true
}

// layerListeners removes whole HTTP listeners, first one by one and then via
// bounded group deletion.
func (r *reducer) layerListeners(ctx context.Context) bool {
	progress := false
	for {
		names := listenerNames(r.best)
		if len(names) == 0 {
			break
		}
		changed := false
		for _, name := range names {
			candidate, op, err := removeHTTPListener(r.best, name)
			if err != nil {
				continue
			}
			if r.try(ctx, candidate, op) {
				changed = true
				progress = true
				break
			}
			if r.stopped {
				return progress
			}
		}
		if !changed {
			break
		}
	}
	if r.stopped {
		return progress
	}
	progress = r.ddmin(len(listenerNames(r.best)), func(indices []int) (*ir.Xds, DeletionOp, error) {
		names := listenerNames(r.best)
		chosen := pickStrings(names, indices)
		return r.removeListenerBatch(chosen)
	}, ctx) || progress
	return progress
}

func (r *reducer) removeListenerBatch(names []string) (*ir.Xds, DeletionOp, error) {
	if len(names) == 0 {
		return nil, DeletionOp{}, errors.New("empty listener batch")
	}
	out := r.best.DeepCopy()
	drop := make(map[string]struct{}, len(names))
	for _, name := range names {
		drop[name] = struct{}{}
	}
	kept := out.HTTP[:0]
	for _, listener := range out.HTTP {
		if _, ok := drop[listener.Name]; ok {
			continue
		}
		kept = append(kept, listener)
	}
	out.HTTP = kept
	reclaimed := sweepOrphans(out)
	return out, DeletionOp{
		Kind:      DeletionHTTPListener,
		Target:    strings.Join(names, ","),
		Reclaimed: reclaimed,
	}, nil
}

// layerRoutes removes individual routes across all surviving listeners and
// then applies bounded group deletion to each listener's route list.
func (r *reducer) layerRoutes(ctx context.Context) bool {
	progress := false
	for {
		keys := routeKeys(r.best)
		if len(keys) == 0 {
			break
		}
		changed := false
		for _, key := range keys {
			candidate, op, err := removeRoute(r.best, key.listener, key.route)
			if err != nil {
				continue
			}
			if r.try(ctx, candidate, op) {
				changed = true
				progress = true
				break
			}
			if r.stopped {
				return progress
			}
		}
		if !changed {
			break
		}
	}
	if r.stopped {
		return progress
	}
	for _, listenerName := range listenerNames(r.best) {
		routes := routesOf(r.best, listenerName)
		if len(routes) < 2 {
			continue
		}
		progress = r.ddmin(len(routes), func(indices []int) (*ir.Xds, DeletionOp, error) {
			chosen := make([]routeKey, 0, len(indices))
			current := routeKeysOfListener(r.best, listenerName)
			for _, idx := range indices {
				if idx < len(current) {
					chosen = append(chosen, current[idx])
				}
			}
			return r.removeRouteBatch(chosen)
		}, ctx) || progress
		if r.stopped {
			return progress
		}
	}
	return progress
}

func (r *reducer) removeRouteBatch(keys []routeKey) (*ir.Xds, DeletionOp, error) {
	if len(keys) == 0 {
		return nil, DeletionOp{}, errors.New("empty route batch")
	}
	out := r.best.DeepCopy()
	drop := make(map[routeKey]struct{}, len(keys))
	for _, key := range keys {
		drop[key] = struct{}{}
	}
	targets := make([]string, 0, len(keys))
	for _, key := range keys {
		targets = append(targets, key.listener+"/"+key.route)
	}
	for _, listener := range out.HTTP {
		kept := listener.Routes[:0]
		for _, route := range listener.Routes {
			if _, ok := drop[routeKey{listener.Name, route.Name}]; ok {
				continue
			}
			kept = append(kept, route)
		}
		listener.Routes = kept
	}
	reclaimed := sweepOrphans(out)
	return out, DeletionOp{
		Kind:      DeletionRoute,
		Target:    strings.Join(targets, ","),
		Reclaimed: reclaimed,
	}, nil
}

// layerOrphans removes standalone registry definitions that nothing
// references anymore. Each sweep is really evaluated before being accepted.
func (r *reducer) layerOrphans(ctx context.Context) bool {
	progress := false
	for {
		candidate := r.best.DeepCopy()
		reclaimed := sweepOrphans(candidate)
		if len(reclaimed) == 0 {
			return progress
		}
		op := DeletionOp{
			Kind:      DeletionBackendCluster,
			Target:    "orphan-sweep",
			Reclaimed: reclaimed,
		}
		if !r.try(ctx, candidate, op) {
			return progress
		}
		progress = true
		if r.stopped {
			return progress
		}
	}
}

// layerFilters removes per-route extension filter entries, singly and in
// bounded groups.
func (r *reducer) layerFilters(ctx context.Context) bool {
	progress := false
	for {
		keys := filterKeys(r.best)
		if len(keys) == 0 {
			break
		}
		changed := false
		for _, key := range keys {
			candidate, op, err := removeFilterEntry(r.best, key.listener, key.route, key.group, key.index)
			if err != nil {
				continue
			}
			if r.try(ctx, candidate, op) {
				changed = true
				progress = true
				break
			}
			if r.stopped {
				return progress
			}
		}
		if !changed {
			break
		}
	}
	return progress
}

// proveFixedPoint really evaluates every legal single-step deletion on the
// current best. It returns true only when all of them fail the target. On
// budget/cancel it marks the run stopped and returns false.
func (r *reducer) proveFixedPoint(ctx context.Context) bool {
	// Listener deletions.
	for _, name := range listenerNames(r.best) {
		candidate, op, err := removeHTTPListener(r.best, name)
		if err != nil {
			continue
		}
		if r.try(ctx, candidate, op) {
			return false
		}
		if r.stopped {
			return false
		}
	}
	// Route deletions.
	for _, key := range routeKeys(r.best) {
		candidate, op, err := removeRoute(r.best, key.listener, key.route)
		if err != nil {
			continue
		}
		if r.try(ctx, candidate, op) {
			return false
		}
		if r.stopped {
			return false
		}
	}
	// Orphaned standalone definitions, if any remain.
	candidate := r.best.DeepCopy()
	if reclaimed := sweepOrphans(candidate); len(reclaimed) > 0 {
		op := DeletionOp{Kind: DeletionBackendCluster, Target: "orphan-sweep", Reclaimed: reclaimed}
		if r.try(ctx, candidate, op) {
			return false
		}
		if r.stopped {
			return false
		}
	}
	// Filter entry deletions.
	if r.opts.EnableFilterGroupDeletions {
		for _, key := range filterKeys(r.best) {
			candidate, op, err := removeFilterEntry(r.best, key.listener, key.route, key.group, key.index)
			if err != nil {
				continue
			}
			if r.try(ctx, candidate, op) {
				return false
			}
			if r.stopped {
				return false
			}
		}
	}
	return true
}

// ddmin implements one bounded delta-debugging pass over n ordered units.
// apply receives the subset of positional indices to remove, resolved against
// the current best each time. The function returns as soon as one chunk (or
// its complement) is accepted because the unit set changes on acceptance; the
// outer layer loop re-invokes ddmin with a fresh list. When nothing can be
// removed at any granularity it returns false having exhausted the groups.
func (r *reducer) ddmin(n int, apply func(indices []int) (*ir.Xds, DeletionOp, error), ctx context.Context) bool {
	if n < 2 || r.stopped {
		return false
	}
	granularity := 2
	for granularity <= n {
		chunkSize := (n + granularity - 1) / granularity
		for start := 0; start < n; start += chunkSize {
			end := start + chunkSize
			if end > n {
				end = n
			}
			chunk := indicesRange(start, end)
			candidate, op, err := apply(chunk)
			if err == nil && r.try(ctx, candidate, op) {
				return true
			}
			if r.stopped {
				return false
			}
			complement := complementIndices(n, chunk)
			if len(complement) == 0 {
				continue
			}
			candidate, op, err = apply(complement)
			if err == nil && r.try(ctx, candidate, op) {
				return true
			}
			if r.stopped {
				return false
			}
		}
		if granularity >= n {
			break
		}
		granularity = minInt(granularity*2, n)
	}
	return false
}

func (r *reducer) fillResult(result *Result, status Status) {
	result.Status = status
	result.OriginalDigest = canonicalDigest(r.original)
	result.BestKnownDigest = r.bestDigest
	result.BestKnown = r.best
	result.Evaluations = r.ev.realEvals
	result.CacheHits = r.ev.cache.hitCount()
	result.Deletions = r.accepted
	result.Log = r.ev.log
	if r.stopped {
		result.Status = StatusIncomplete
		result.IncompleteReason = r.stopReason
	}
}

// --- small IR list helpers ---

func listenerNames(x *ir.Xds) []string {
	names := make([]string, 0, len(x.HTTP))
	for _, listener := range x.HTTP {
		if listener != nil {
			names = append(names, listener.Name)
		}
	}
	return names
}

func routesOf(x *ir.Xds, listenerName string) []string {
	listener := x.GetHTTPListener(listenerName)
	if listener == nil {
		return nil
	}
	names := make([]string, 0, len(listener.Routes))
	for _, route := range listener.Routes {
		if route != nil {
			names = append(names, route.Name)
		}
	}
	return names
}

func routeKeys(x *ir.Xds) []routeKey {
	var keys []routeKey
	for _, listenerName := range listenerNames(x) {
		keys = append(keys, routeKeysOfListener(x, listenerName)...)
	}
	return keys
}

func routeKeysOfListener(x *ir.Xds, listenerName string) []routeKey {
	keys := make([]routeKey, 0)
	for _, routeName := range routesOf(x, listenerName) {
		keys = append(keys, routeKey{listener: listenerName, route: routeName})
	}
	return keys
}

func filterKeys(x *ir.Xds) []filterKey {
	var keys []filterKey
	for _, listener := range x.HTTP {
		if listener == nil {
			continue
		}
		for _, route := range listener.Routes {
			if route == nil || route.EnvoyExtensions == nil {
				continue
			}
			ext := route.EnvoyExtensions
			for i := range ext.ExtProcs {
				keys = append(keys, filterKey{listener.Name, route.Name, FilterGroupExtProcs, i})
			}
			for i := range ext.Wasms {
				keys = append(keys, filterKey{listener.Name, route.Name, FilterGroupWasms, i})
			}
			for i := range ext.Luas {
				keys = append(keys, filterKey{listener.Name, route.Name, FilterGroupLuas, i})
			}
			for i := range ext.DynamicModules {
				keys = append(keys, filterKey{listener.Name, route.Name, FilterGroupDynamicModules, i})
			}
		}
	}
	return keys
}

func indicesRange(start, end int) []int {
	out := make([]int, 0, end-start)
	for i := start; i < end; i++ {
		out = append(out, i)
	}
	return out
}

func complementIndices(n int, removed []int) []int {
	drop := make(map[int]struct{}, len(removed))
	for _, idx := range removed {
		drop[idx] = struct{}{}
	}
	out := make([]int, 0, n-len(removed))
	for i := 0; i < n; i++ {
		if _, ok := drop[i]; !ok {
			out = append(out, i)
		}
	}
	return out
}

func pickStrings(values []string, indices []int) []string {
	out := make([]string, 0, len(indices))
	for _, idx := range indices {
		if idx >= 0 && idx < len(values) {
			out = append(out, values[idx])
		}
	}
	return out
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
