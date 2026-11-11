// Copyright Envoy Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package irwitness

import (
	"time"

	egv1a1 "github.com/envoyproxy/gateway/api/v1alpha1"
	"github.com/envoyproxy/gateway/internal/ir"
	xds_types "github.com/envoyproxy/gateway/internal/xds/types"
)

// Status classifies the outcome of a reduction run.
type Status string

const (
	// StatusOneMinimal means a fixed point was proven on the declared deletion
	// operation set: every legal single-step deletion on the final artifact was
	// really evaluated and the target predicate failed on each result. It is a
	// 1-step minimality claim, never a global-minimum claim.
	StatusOneMinimal Status = "1-Minimal"

	// StatusIncomplete means the run stopped because the evaluation budget was
	// exhausted or the context was cancelled. BestKnown is the last artifact
	// re-verified to satisfy the target predicate.
	StatusIncomplete Status = "Incomplete"

	// StatusUnsupported means the fixed input depends on facilities this
	// reducer never invokes (extension servers, live resolution or other
	// unfixed inputs). No reduction is performed.
	StatusUnsupported Status = "Unsupported"
)

// Verdict classifies a single real evaluation of a candidate artifact.
// Every value other than VerdictTrue means the target property does not
// demonstrably hold on that candidate.
type Verdict string

const (
	VerdictTrue           Verdict = "true"
	VerdictFalse          Verdict = "false"
	VerdictInvalid        Verdict = "invalid"
	VerdictTranslateError Verdict = "translate-error"
	VerdictTimeout        Verdict = "timeout"
	VerdictCancelled      Verdict = "cancelled"
)

// IsTrue reports whether the verdict proves the target still holds. Only an
// evaluation that passed ir validation, translation and the predicate itself
// counts.
func (v Verdict) IsTrue() bool { return v == VerdictTrue }

// DeletionKind enumerates the declared, auditable deletion operation set.
type DeletionKind string

const (
	DeletionHTTPListener     DeletionKind = "http-listener"
	DeletionRoute            DeletionKind = "route"
	DeletionBackendCluster   DeletionKind = "backend-cluster"
	DeletionExtensionBackend DeletionKind = "extension-backend"
	DeletionCACertificate    DeletionKind = "ca-certificate"
	DeletionFilterEntry      DeletionKind = "filter-entry"
	// DeletionInitial marks the mandatory verification of the unmodified input.
	DeletionInitial DeletionKind = "initial"
)

// DeletionOp records one structural deletion applied to produce a candidate.
// Reclaimed lists the standalone registry definitions removed together with
// the primary target because the deletion left them unreferenced.
type DeletionOp struct {
	Kind      DeletionKind `json:"kind" yaml:"kind"`
	Target    string       `json:"target" yaml:"target"`
	Reclaimed []string     `json:"reclaimed,omitempty" yaml:"reclaimed,omitempty"`
}

// CandidateSummary is the normalized structural summary of a candidate. It
// only contains counts, never resource bytes.
type CandidateSummary struct {
	HTTPListeners     int `json:"httpListeners" yaml:"httpListeners"`
	HTTPRoutes        int `json:"httpRoutes" yaml:"httpRoutes"`
	TCPListeners      int `json:"tcpListeners" yaml:"tcpListeners"`
	UDPListeners      int `json:"udpListeners" yaml:"udpListeners"`
	BackendClusters   int `json:"backendClusters" yaml:"backendClusters"`
	ExtensionBackends int `json:"extensionBackends" yaml:"extensionBackends"`
	CACertificates    int `json:"caCertificates" yaml:"caCertificates"`
	FilterEntries     int `json:"filterEntries" yaml:"filterEntries"`
}

// EvaluationRecord is one entry of the verifiable deletion log.
type EvaluationRecord struct {
	Sequence        int              `json:"sequence" yaml:"sequence"`
	Operation       DeletionOp       `json:"operation" yaml:"operation"`
	CandidateDigest string           `json:"candidateDigest" yaml:"candidateDigest"`
	Summary         CandidateSummary `json:"summary" yaml:"summary"`
	Verdict         Verdict          `json:"verdict" yaml:"verdict"`
	Reason          string           `json:"reason,omitempty" yaml:"reason,omitempty"`
	CacheHit        bool             `json:"cacheHit,omitempty" yaml:"cacheHit,omitempty"`
	ElapsedMS       int64            `json:"elapsedMs" yaml:"elapsedMs"`
}

// Options fixes every input that may influence an evaluation. The same
// Options value must produce the same verdict for the same IR and predicate.
type Options struct {
	// Translator settings, fixed for the whole run.
	ControllerNamespace       string
	ProxyInfraName            string
	ProxyInfraNamespace       string
	GlobalRateLimitServiceURL string
	GlobalRateLimitTimeout    time.Duration
	GlobalRateLimitFailClosed bool
	FilterOrder               []egv1a1.FilterPosition
	RuntimeFlags              *egv1a1.RuntimeFlags

	// EnableFilterGroupDeletions opts in per-route extension filter entry
	// deletions. It defaults to false because filter groups frequently encode
	// the target property itself.
	EnableFilterGroupDeletions bool

	// MaxEvaluations caps the number of real (non-cached) translations. Zero
	// selects DefaultMaxEvaluations.
	MaxEvaluations int

	// EvalTimeout bounds a single Translator.Translate call. Zero means only
	// the run context bounds evaluation.
	EvalTimeout time.Duration
}

// DefaultMaxEvaluations is the default call budget applied when
// Options.MaxEvaluations is zero.
const DefaultMaxEvaluations = 500

// Result is the reducer output. BestKnown always points at an independent
// deep copy; the caller-owned input IR is never returned or mutated.
type Result struct {
	Status            Status             `json:"status" yaml:"status"`
	OriginalDigest    string             `json:"originalDigest" yaml:"originalDigest"`
	BestKnownDigest   string             `json:"bestKnownDigest,omitempty" yaml:"bestKnownDigest,omitempty"`
	BestKnown         *ir.Xds            `json:"-" yaml:"-"`
	Evaluations       int                `json:"evaluations" yaml:"evaluations"`
	CacheHits         int                `json:"cacheHits" yaml:"cacheHits"`
	Deletions         []DeletionOp       `json:"deletions,omitempty" yaml:"deletions,omitempty"`
	Log               []EvaluationRecord `json:"log,omitempty" yaml:"log,omitempty"`
	IncompleteReason  string             `json:"incompleteReason,omitempty" yaml:"incompleteReason,omitempty"`
	UnsupportedReason string             `json:"unsupportedReason,omitempty" yaml:"unsupportedReason,omitempty"`
	Warnings          []string           `json:"warnings,omitempty" yaml:"warnings,omitempty"`
	// SecretBearing reports that the IR carries secret material (PrivateBytes
	// or CA bundles). Artifacts must then only be written to an explicit local
	// restricted output location.
	SecretBearing bool `json:"secretBearing" yaml:"secretBearing"`
}

// Predicate is a deterministic, side-effect-free test over the translated
// ResourceVersionTable. Implementations must not perform I/O, spawn
// goroutines that outlive Eval or reach into live services.
type Predicate interface {
	// Eval reports whether the target property holds on the translated
	// resources. It is only invoked after a successful translation.
	Eval(table *xds_types.ResourceVersionTable) bool
	// Digest is a stable identifier of the predicate semantics and is part of
	// the evaluation cache key.
	Digest() string
	// Describe returns a stable, human-readable description used in logs.
	Describe() string
}
