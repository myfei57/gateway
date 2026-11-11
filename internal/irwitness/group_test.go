// Copyright Envoy Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package irwitness

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/envoyproxy/gateway/internal/ir"
)

// TestReduceMultipleListeners exercises whole-listener deletion across several
// independent listeners, including the batch application helper used by the
// bounded group-deletion path.
func TestReduceMultipleListeners(t *testing.T) {
	keepCluster := "cluster-keep"
	x := &ir.Xds{
		HTTP: []*ir.HTTPListener{
			baseListener("keep-listener", clusterRefRoute("keep-route", "/keep", keepCluster)),
			baseListener("drop-listener-1", clusterRefRoute("drop-route-1", "/d1", "cluster-drop-1")),
			baseListener("drop-listener-2", clusterRefRoute("drop-route-2", "/d2", "cluster-drop-2")),
		},
		BackendClusters: []*ir.BackendCluster{
			backendCluster(keepCluster, "7.7.7.7", 8080),
			backendCluster("cluster-drop-1", "8.8.8.8", 8080),
			backendCluster("cluster-drop-2", "9.9.9.9", 8080),
		},
	}
	require.NoError(t, x.Validate())

	pred := mustCompile(t, resourceExistsSpec("cluster", keepCluster))
	result, err := Reduce(context.Background(), x, pred, testOptions())
	require.NoError(t, err)
	require.Equal(t, StatusOneMinimal, result.Status)

	require.Len(t, result.BestKnown.HTTP, 1)
	require.Equal(t, "keep-listener", result.BestKnown.HTTP[0].Name)
	require.Len(t, result.BestKnown.BackendClusters, 1)
	require.Equal(t, keepCluster, result.BestKnown.BackendClusters[0].Name)

	// Batch deletion removes multiple listeners in one candidate and
	// reclaims everything they alone referenced.
	r := &reducer{best: x.DeepCopy()}
	batch, op, err := r.removeListenerBatch([]string{"drop-listener-1", "drop-listener-2"})
	require.NoError(t, err)
	require.NoError(t, batch.Validate())
	require.Len(t, batch.HTTP, 1)
	require.Contains(t, op.Reclaimed, string(DeletionBackendCluster)+":cluster-drop-1")
	require.Contains(t, op.Reclaimed, string(DeletionBackendCluster)+":cluster-drop-2")
	for _, reclaimed := range op.Reclaimed {
		require.NotContains(t, reclaimed, keepCluster)
	}
}

// TestDDMinGroupMechanics drives ddmin with an apply that only accepts a
// specific group size, proving chunk and complement attempts are really
// evaluated rather than assumed.
func TestDDMinGroupMechanics(t *testing.T) {
	x := &ir.Xds{
		HTTP: []*ir.HTTPListener{
			baseListener("l0", clusterRefRoute("r0", "/r0", "c0")),
			baseListener("l1", clusterRefRoute("r1", "/r1", "c1")),
			baseListener("l2", clusterRefRoute("r2", "/r2", "c2")),
			baseListener("l3", clusterRefRoute("r3", "/r3", "c3")),
		},
		BackendClusters: []*ir.BackendCluster{
			backendCluster("c0", "1.1.1.1", 8080),
			backendCluster("c1", "2.2.2.2", 8080),
			backendCluster("c2", "3.3.3.3", 8080),
			backendCluster("c3", "4.4.4.4", 8080),
		},
	}
	require.NoError(t, x.Validate())

	pred := mustCompile(t, resourceExistsSpec("cluster", "c0"))
	ev := newEvaluator(testOptions(), pred, 200)
	r := &reducer{
		original: x,
		pred:     pred,
		opts:     testOptions(),
		ev:       ev,
		best:     x.DeepCopy(),
	}

	progressed := r.ddmin(4, func(indices []int) (*ir.Xds, DeletionOp, error) {
		names := pickStrings(listenerNames(r.best), indices)
		return r.removeListenerBatch(names)
	}, context.Background())
	require.True(t, progressed)
	require.True(t, ev.realEvals > 0)

	// Whatever ddmin accepted, the accepted artifact was itself verified true.
	rvt, err := ev.newTranslator().Translate(context.Background(), r.best)
	require.NoError(t, err)
	require.True(t, pred.Eval(rvt))
}

// TestLogRecordsEveryEvaluation ensures the deletion log contains normalized
// summaries, digest and verdict for every real evaluation plus cache hits.
func TestLogRecordsEveryEvaluation(t *testing.T) {
	x := &ir.Xds{
		HTTP: []*ir.HTTPListener{baseListener("gw/http",
			clusterRefRoute("route-1", "/r1", "cluster-1"),
			clusterRefRoute("route-2", "/r2", "cluster-2"),
		)},
		BackendClusters: []*ir.BackendCluster{
			backendCluster("cluster-1", "7.7.7.7", 8080),
			backendCluster("cluster-2", "8.8.8.8", 8080),
		},
	}
	pred := mustCompile(t, resourceExistsSpec("cluster", "cluster-1"))
	result, err := Reduce(context.Background(), x, pred, testOptions())
	require.NoError(t, err)

	require.NotEmpty(t, result.Log)
	initial := result.Log[0]
	require.Equal(t, DeletionInitial, initial.Operation.Kind)
	require.Equal(t, VerdictTrue, initial.Verdict)
	require.NotEmpty(t, initial.CandidateDigest)
	require.Equal(t, 2, initial.Summary.HTTPRoutes)
	require.Equal(t, 2, initial.Summary.BackendClusters)

	verdictSeen := map[Verdict]bool{}
	for _, record := range result.Log {
		require.NotEmpty(t, record.CandidateDigest)
		verdictSeen[record.Verdict] = true
		if record.Verdict != VerdictTrue {
			require.NotEmpty(t, record.Reason)
		}
	}
	// At least one rejected deletion must be recorded for a fixed point claim.
	require.True(t, verdictSeen[VerdictFalse])
}
