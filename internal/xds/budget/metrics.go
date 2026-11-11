// Copyright Envoy Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package budget

import "github.com/envoyproxy/gateway/internal/metrics"

var (
	// xdsBudgetEvaluationTotal counts candidate snapshots evaluated against the
	// resource budget, labeled by the decision (published or rejected).
	xdsBudgetEvaluationTotal = metrics.NewCounter(
		"xds_budget_evaluation_total",
		"Total number of candidate xDS snapshots evaluated against the resource budget.",
	)

	// xdsBudgetViolationTotal counts individual budget violations, labeled by
	// type URL and violation kind. Secret payloads are never attached.
	xdsBudgetViolationTotal = metrics.NewCounter(
		"xds_budget_violation_total",
		"Total number of xDS resource budget violations by type URL and kind.",
	)

	resultLabel     = metrics.NewLabel("result")
	typeURLLabel    = metrics.NewLabel("typeURL")
	kindLabel       = metrics.NewLabel("kind")
	resultPublished = "published"
	resultRejected  = "rejected"
)

// RecordEvaluation increments the evaluation counter with the decision label.
func RecordEvaluation(published bool) {
	result := resultPublished
	if !published {
		result = resultRejected
	}
	xdsBudgetEvaluationTotal.With(resultLabel.Value(result)).Increment()
}

// RecordViolation increments the violation counter for one violation.
func RecordViolation(v Violation) {
	xdsBudgetViolationTotal.With(
		typeURLLabel.Value(v.TypeURL),
		kindLabel.Value(v.Kind),
	).Increment()
}
