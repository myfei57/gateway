// Copyright Envoy Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

// Package irwitness implements IRWitnessReducer: a deterministic, read-only
// reducer that shrinks a fixed ir.Xds input while keeping a declared target
// property reproducible through the real xds Translator.
//
// # Guarantees
//
// The reducer never mutates the input IR, never writes to Kubernetes and never
// publishes xDS resources. Every candidate produced during a run is, in order:
//
//  1. a deep copy of the last verified artifact (object identity is never
//     shared with the caller's input);
//  2. checked with ir.Xds.Validate;
//  3. translated with a freshly constructed translator.Translator using the
//     fixed translation options;
//  4. tested against the target predicate evaluated on the actual
//     types.ResourceVersionTable produced by that translation.
//
// A validation failure, a translation error, a per-evaluation timeout or a
// context cancellation are all recorded as explicit non-true verdicts. None
// of them can ever be interpreted as "the target still holds".
//
// Deletions are restricted to a fixed, auditable operation set: whole HTTP
// listeners, individual HTTP routes (with reclamation of the standalone
// definitions that become unreferenced), standalone BackendCluster /
// ExtensionBackend / CACertificate registry entries, and — only when
// explicitly enabled — per-route extension filter entries. Reference
// counting covers BackendClusterRefs (including mirror destinations),
// EnvoyExtensionFeatures.Backends aliases and TLSCACertificate digest
// registrations, so shared definitions are retained and a target property is
// never turned into a dangling-reference failure.
//
// The 1-Minimal marker is only emitted after a fixed point is proven on the
// declared deletion operation set, i.e. every legal single-step deletion on
// the final artifact has been really evaluated and fails the target. It does
// not claim a global minimum. When the evaluation budget is exhausted or the
// context is cancelled first, the last artifact that was re-verified true is
// returned together with the Incomplete marker.
//
// # Unsupported inputs
//
// Inputs whose faithful translation would require an extension manager or
// other live, unfixed dependencies are rejected up front with the Unsupported
// marker instead of being silently translated against an online service.
package irwitness
