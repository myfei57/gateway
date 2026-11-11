// Copyright Envoy Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package irwitness

import (
	"context"
	"errors"
	"io"
	"time"

	egv1a1 "github.com/envoyproxy/gateway/api/v1alpha1"
	"github.com/envoyproxy/gateway/internal/ir"
	"github.com/envoyproxy/gateway/internal/logging"
	"github.com/envoyproxy/gateway/internal/xds/translator"
	xds_types "github.com/envoyproxy/gateway/internal/xds/types"
)

// evaluator runs the real validate/translate/predicate pipeline for one
// candidate at a time and maintains the verdict cache and deletion log.
type evaluator struct {
	opts          Options
	pred          Predicate
	cache         *evalCache
	log           []EvaluationRecord
	realEvals     int
	maxRealEvals  int
	optionsDigest string
}

func newEvaluator(opts Options, pred Predicate, maxRealEvals int) *evaluator {
	return &evaluator{
		opts:          opts,
		pred:          pred,
		cache:         newEvalCache(),
		maxRealEvals:  maxRealEvals,
		optionsDigest: optionsDigest(opts),
	}
}

func (e *evaluator) remaining() int {
	return e.maxRealEvals - e.realEvals
}

// evaluate runs the full pipeline for candidate. budgetExhausted is reported
// separately from a verdict so the reducer can never mistake it for a target
// result: no evaluation happens when the budget has been spent.
func (e *evaluator) evaluate(ctx context.Context, candidate *ir.Xds, op DeletionOp) (verdict Verdict, reason string, cacheHit, budgetExhausted bool) {
	sourceDigest := canonicalDigest(candidate)
	summary := summarize(candidate)
	key := cacheKey{
		optionsDigest:   e.optionsDigest,
		predicateDigest: e.pred.Digest(),
		sourceDigest:    sourceDigest,
	}
	if entry, ok := e.cache.get(key); ok {
		e.appendRecord(op, sourceDigest, summary, entry.verdict, entry.reason, true, 0)
		return entry.verdict, entry.reason, true, false
	}

	if e.remaining() <= 0 {
		return "", "", false, true
	}

	started := time.Now()
	verdict, reason = e.runPipeline(ctx, candidate)
	elapsed := time.Since(started)

	e.realEvals++
	e.cache.put(key, cacheEntry{verdict: verdict, reason: reason})
	e.appendRecord(op, sourceDigest, summary, verdict, reason, false, elapsed.Milliseconds())
	return verdict, reason, false, false
}

func (e *evaluator) appendRecord(op DeletionOp, digest string, summary CandidateSummary, verdict Verdict, reason string, cacheHit bool, elapsedMS int64) {
	e.log = append(e.log, EvaluationRecord{
		Sequence:        len(e.log) + 1,
		Operation:       op,
		CandidateDigest: digest,
		Summary:         summary,
		Verdict:         verdict,
		Reason:          reason,
		CacheHit:        cacheHit,
		ElapsedMS:       elapsedMS,
	})
}

// runPipeline enforces the mandatory ordering: validation first, then a real
// translation, then the predicate over the produced table. Any failure class
// becomes an explicit non-true verdict.
func (e *evaluator) runPipeline(ctx context.Context, candidate *ir.Xds) (Verdict, string) {
	if err := ctx.Err(); err != nil {
		if errors.Is(err, context.Canceled) {
			return VerdictCancelled, "context cancelled before evaluation"
		}
		return VerdictCancelled, err.Error()
	}

	if err := candidate.Validate(); err != nil {
		return VerdictInvalid, err.Error()
	}

	rvt, err := e.translate(ctx, candidate)
	if err != nil {
		switch {
		case errors.Is(err, context.DeadlineExceeded):
			return VerdictTimeout, "translation exceeded evaluation timeout"
		case errors.Is(err, context.Canceled):
			return VerdictCancelled, "context cancelled during translation"
		default:
			return VerdictTranslateError, err.Error()
		}
	}

	if e.pred.Eval(rvt) {
		return VerdictTrue, ""
	}
	return VerdictFalse, "target predicate evaluated false on translated ResourceVersionTable"
}

// translate invokes the real Translator.Translate under the run context and
// the optional per-evaluation timeout. The translator's context does not
// interrupt an in-flight translation, so the call is abandoned on timeout
// rather than killed; offline translation performs no network I/O.
func (e *evaluator) translate(ctx context.Context, candidate *ir.Xds) (*xds_types.ResourceVersionTable, error) {
	evalCtx := ctx
	var cancel context.CancelFunc
	if e.opts.EvalTimeout > 0 {
		evalCtx, cancel = context.WithTimeout(ctx, e.opts.EvalTimeout)
		defer cancel()
	}

	tr := e.newTranslator()
	type translateOut struct {
		rvt *xds_types.ResourceVersionTable
		err error
	}
	ch := make(chan translateOut, 1)
	go func() {
		rvt, err := tr.Translate(evalCtx, candidate)
		ch <- translateOut{rvt: rvt, err: err}
	}()

	select {
	case out := <-ch:
		return out.rvt, out.err
	case <-evalCtx.Done():
		return nil, evalCtx.Err()
	}
}

func (e *evaluator) newTranslator() *translator.Translator {
	return &translator.Translator{
		ControllerNamespace: e.opts.ControllerNamespace,
		ProxyInfraName:      e.opts.ProxyInfraName,
		ProxyInfraNamespace: e.opts.ProxyInfraNamespace,
		GlobalRateLimit: &translator.GlobalRateLimitSettings{
			ServiceURL: e.opts.GlobalRateLimitServiceURL,
			Timeout:    e.opts.GlobalRateLimitTimeout,
			FailClosed: e.opts.GlobalRateLimitFailClosed,
		},
		// ExtensionManager is intentionally never set: this reducer never
		// performs extension callouts or other network activity.
		FilterOrder:  e.opts.FilterOrder,
		RuntimeFlags: e.opts.RuntimeFlags,
		Logger:       logging.DefaultLogger(io.Discard, egv1a1.LogLevelInfo),
	}
}
