// Copyright Envoy Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package egctl

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
	"sigs.k8s.io/yaml"

	"github.com/envoyproxy/gateway/internal/infrastructure/kubernetes/ratelimit"
	"github.com/envoyproxy/gateway/internal/ir"
	"github.com/envoyproxy/gateway/internal/irwitness"
)

const (
	witnessIRArtifactName   = "reduced-ir"
	witnessLogArtifactName  = "witness-log"
	defaultEvalTimeout      = 30 * time.Second
	defaultWitnessNamespace = "envoy-gateway-system"
	defaultWitnessDNSDomain = "cluster.local"
)

// newWitnessCommand builds the read-only IR witness reduction subcommand. It
// only reads local files and writes artifacts into an explicit local
// directory: no Kubernetes client is constructed and no xDS is published.
func newWitnessCommand() *cobra.Command {
	var (
		irFile            string
		predicateFile     string
		outputDir         string
		format            string
		allowFilterGroups bool
		maxEvaluations    int
		evalTimeout       time.Duration
		controllerNS      string
		dnsDomain         string
	)

	cmd := &cobra.Command{
		Use:   "witness",
		Short: "Reduce a fixed ir.Xds while preserving a target xDS property (read-only)",
		Long: `Witness reduction takes a fixed ir.Xds artifact, translation options and a bounded
target predicate and deletes irrelevant IR content while proving, through real
Translator.Translate calls, that the target property still holds on the reduced
input. The command never writes to Kubernetes and never publishes xDS.

Predicates are limited to resource type/name existence and protobuf field
presence, absence and exact scalar value combined with finite AND/OR/NOT
expressions. There is no shell, import or network callback surface.`,
		Example: `  # Reduce an IR while keeping a named cluster present in the translated xDS.
  egctl experimental witness \
    --ir input-ir.yaml \
    --predicate predicate.yaml \
    --output-dir ./witness-out \
    --max-evaluations 200
`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runWitness(cmd.Context(), witnessConfig{
				irFile:            irFile,
				predicateFile:     predicateFile,
				outputDir:         outputDir,
				format:            format,
				allowFilterGroups: allowFilterGroups,
				maxEvaluations:    maxEvaluations,
				evalTimeout:       evalTimeout,
				controllerNS:      controllerNS,
				dnsDomain:         dnsDomain,
				out:               cmd.OutOrStdout(),
			})
		},
	}

	cmd.Flags().StringVar(&irFile, "ir", "", "Path to the fixed ir.Xds artifact (YAML or JSON).")
	cmd.Flags().StringVar(&predicateFile, "predicate", "", "Path to the bounded predicate spec (YAML or JSON).")
	cmd.Flags().StringVar(&outputDir, "output-dir", "", "Explicit local directory for the reduced artifact and deletion log.")
	cmd.Flags().StringVarP(&format, "output", "o", yamlOutput, "One of 'yaml' or 'json'.")
	cmd.Flags().BoolVar(&allowFilterGroups, "allow-filter-groups", false, "Opt in to per-route extension filter entry deletions.")
	cmd.Flags().IntVar(&maxEvaluations, "max-evaluations", irwitness.DefaultMaxEvaluations, "Maximum number of real translations.")
	cmd.Flags().DurationVar(&evalTimeout, "eval-timeout", defaultEvalTimeout, "Per-translation timeout.")
	cmd.Flags().StringVar(&controllerNS, "controller-namespace", defaultWitnessNamespace, "Controller namespace used by translation options.")
	cmd.Flags().StringVar(&dnsDomain, "dns-domain", defaultWitnessDNSDomain, "DNS domain used by translation options.")

	_ = cmd.MarkFlagRequired("ir")
	_ = cmd.MarkFlagRequired("predicate")
	_ = cmd.MarkFlagRequired("output-dir")
	return cmd
}

type witnessConfig struct {
	irFile            string
	predicateFile     string
	outputDir         string
	format            string
	allowFilterGroups bool
	maxEvaluations    int
	evalTimeout       time.Duration
	controllerNS      string
	dnsDomain         string
	out               interface{ Write(p []byte) (int, error) }
}

func runWitness(ctx context.Context, cfg witnessConfig) error {
	if cfg.format != yamlOutput && cfg.format != jsonOutput {
		return fmt.Errorf("--output must be one of %q or %q", yamlOutput, jsonOutput)
	}
	if cfg.maxEvaluations <= 0 {
		return fmt.Errorf("--max-evaluations must be positive")
	}
	if cfg.evalTimeout <= 0 {
		return fmt.Errorf("--eval-timeout must be positive")
	}

	irBytes, err := os.ReadFile(cfg.irFile)
	if err != nil {
		return fmt.Errorf("reading IR artifact: %w", err)
	}
	inputIR := &ir.Xds{}
	if err := yaml.Unmarshal(irBytes, inputIR, yaml.DisallowUnknownFields); err != nil {
		return fmt.Errorf("parsing IR artifact: %w", err)
	}

	predBytes, err := os.ReadFile(cfg.predicateFile)
	if err != nil {
		return fmt.Errorf("reading predicate spec: %w", err)
	}
	spec := &irwitness.PredicateSpec{}
	if err := yaml.Unmarshal(predBytes, spec, yaml.DisallowUnknownFields); err != nil {
		return fmt.Errorf("parsing predicate spec: %w", err)
	}
	predicate, err := irwitness.CompilePredicate(spec)
	if err != nil {
		return fmt.Errorf("compiling predicate: %w", err)
	}

	opts := irwitness.Options{
		ControllerNamespace:        cfg.controllerNS,
		GlobalRateLimitServiceURL:  ratelimit.GetServiceURL(cfg.controllerNS, cfg.dnsDomain),
		EnableFilterGroupDeletions: cfg.allowFilterGroups,
		MaxEvaluations:             cfg.maxEvaluations,
		EvalTimeout:                cfg.evalTimeout,
	}

	result, err := irwitness.Reduce(ctx, inputIR, predicate, opts)
	if err != nil {
		return err
	}
	if result.Status == irwitness.StatusUnsupported {
		return fmt.Errorf("witness reduction unsupported for this input: %s", result.UnsupportedReason)
	}

	ext := ".yaml"
	if cfg.format == jsonOutput {
		ext = ".json"
	}
	irPath := filepath.Join(cfg.outputDir, witnessIRArtifactName+ext)
	logPath := filepath.Join(cfg.outputDir, witnessLogArtifactName+ext)

	artifactBytes, err := irwitness.MarshalArtifact(result.BestKnown, cfg.format)
	if err != nil {
		return fmt.Errorf("marshaling reduced artifact: %w", err)
	}
	if err := irwitness.WriteRestricted(irPath, artifactBytes); err != nil {
		return err
	}
	logBytes, err := irwitness.MarshalLog(result, cfg.format)
	if err != nil {
		return fmt.Errorf("marshaling deletion log: %w", err)
	}
	if err := irwitness.WriteRestricted(logPath, logBytes); err != nil {
		return err
	}

	secretNote := ""
	if result.SecretBearing {
		secretNote = " (input contains secret material; artifacts written with owner-only permissions)"
	}
	fmt.Fprintf(cfg.out, "witness reduction complete: status=%s evaluations=%d cacheHits=%d%s\n",
		result.Status, result.Evaluations, result.CacheHits, secretNote)
	fmt.Fprintf(cfg.out, "original digest: %s\n", result.OriginalDigest)
	fmt.Fprintf(cfg.out, "reduced digest:  %s\n", result.BestKnownDigest)
	fmt.Fprintf(cfg.out, "reduced IR:      %s\n", irPath)
	fmt.Fprintf(cfg.out, "deletion log:    %s\n", logPath)
	if result.Status == irwitness.StatusIncomplete {
		fmt.Fprintf(cfg.out, "incomplete:      %s\n", result.IncompleteReason)
	}
	return nil
}
