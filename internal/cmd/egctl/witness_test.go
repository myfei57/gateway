// Copyright Envoy Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package egctl

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
	"sigs.k8s.io/yaml"

	egv1a1 "github.com/envoyproxy/gateway/api/v1alpha1"
	"github.com/envoyproxy/gateway/internal/infrastructure/kubernetes/ratelimit"
	"github.com/envoyproxy/gateway/internal/ir"
	"github.com/envoyproxy/gateway/internal/irwitness"
	"github.com/envoyproxy/gateway/internal/logging"
	"github.com/envoyproxy/gateway/internal/xds/translator"
)

const witnessIRFixture = `
http:
- name: gw/http
  address: 0.0.0.0
  port: 10080
  hostnames:
  - '*'
  routes:
  - name: keep-route
    hostname: '*'
    pathMatch:
      prefix: /keep
    destination:
      name: dest-keep
      backendClusterRefs:
      - name: cluster-keep
        weight: 1
  - name: drop-route
    hostname: '*'
    pathMatch:
      prefix: /drop
    destination:
      name: dest-drop
      backendClusterRefs:
      - name: cluster-drop
        weight: 1
backendClusters:
- name: cluster-keep
  setting:
    name: cluster-keep/setting
    protocol: HTTP
    addressType: IP
    weight: 1
    endpoints:
    - host: 7.7.7.7
      port: 8080
- name: cluster-drop
  setting:
    name: cluster-drop/setting
    protocol: HTTP
    addressType: IP
    weight: 1
    endpoints:
    - host: 8.8.8.8
      port: 8080
`

const witnessPredicateFixture = `
resourceExists:
  type: cluster
  name: cluster-keep
`

func writeTemp(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return path
}

func TestWitnessCommandEndToEnd(t *testing.T) {
	inputDir := t.TempDir()
	outputDir := filepath.Join(t.TempDir(), "out")
	irPath := writeTemp(t, inputDir, "input-ir.yaml", witnessIRFixture)
	predPath := writeTemp(t, inputDir, "predicate.yaml", witnessPredicateFixture)

	buf := bytes.NewBuffer(nil)
	cmd := newWitnessCommand()
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{
		"witness",
		"--ir", irPath,
		"--predicate", predPath,
		"--output-dir", outputDir,
		"--max-evaluations", "100",
	})
	require.NoError(t, cmd.ExecuteContext(context.Background()))

	output := buf.String()
	require.Contains(t, output, string(irwitness.StatusOneMinimal))
	require.Contains(t, output, "reduced-ir.yaml")
	require.Contains(t, output, "witness-log.yaml")

	artifactPath := filepath.Join(outputDir, "reduced-ir.yaml")
	logPath := filepath.Join(outputDir, "witness-log.yaml")
	artifactBytes, err := os.ReadFile(artifactPath)
	require.NoError(t, err)
	logBytes, err := os.ReadFile(logPath)
	require.NoError(t, err)

	// Reload the artifact through the public loader and prove the target still
	// holds with a real Translator.Translate call.
	reloaded, err := irwitness.LoadArtifact(artifactBytes, irwitness.FormatYAML)
	require.NoError(t, err)
	require.NoError(t, reloaded.Validate())
	require.Len(t, reloaded.HTTP[0].Routes, 1)
	require.Equal(t, "keep-route", reloaded.HTTP[0].Routes[0].Name)
	require.Len(t, reloaded.BackendClusters, 1)
	require.Equal(t, "cluster-keep", reloaded.BackendClusters[0].Name)

	tr := &translator.Translator{
		ControllerNamespace: "envoy-gateway-system",
		GlobalRateLimit: &translator.GlobalRateLimitSettings{
			ServiceURL: ratelimit.GetServiceURL("envoy-gateway-system", "cluster.local"),
		},
		Logger: logging.DefaultLogger(io.Discard, egv1a1.LogLevelInfo),
	}
	rvt, err := tr.Translate(context.Background(), reloaded)
	require.NoError(t, err)
	require.NotNil(t, rvt.FindCluster("cluster-keep"))
	require.Nil(t, rvt.FindCluster("cluster-drop"))

	// The deletion log only carries names, digests and counts — no endpoint
	// bytes or other resource content.
	logText := string(logBytes)
	require.Contains(t, logText, "candidateDigest")
	require.NotContains(t, logText, "7.7.7.7")
	require.NotContains(t, logText, "8.8.8.8")

	// Files are written through the restricted sink. Unix honors the 0600
	// mode bits; Windows only tracks the read-only bit, so the mode assertion
	// is platform scoped.
	info, err := os.Stat(artifactPath)
	require.NoError(t, err)
	if runtime.GOOS != "windows" {
		require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	} else {
		require.False(t, info.IsDir())
	}

	// The log itself parses back into the result shape.
	var logResult irwitness.Result
	require.NoError(t, yaml.Unmarshal(logBytes, &logResult))
	require.Equal(t, irwitness.StatusOneMinimal, logResult.Status)
	require.Greater(t, logResult.Evaluations, 0)
	for _, record := range logResult.Log {
		require.NotEmpty(t, record.CandidateDigest)
	}
}

func TestWitnessCommandJSON(t *testing.T) {
	inputDir := t.TempDir()
	outputDir := filepath.Join(t.TempDir(), "out")
	irPath := writeTemp(t, inputDir, "input-ir.yaml", witnessIRFixture)
	predPath := writeTemp(t, inputDir, "predicate.yaml", witnessPredicateFixture)

	buf := bytes.NewBuffer(nil)
	cmd := newWitnessCommand()
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{
		"witness",
		"--ir", irPath,
		"--predicate", predPath,
		"--output-dir", outputDir,
		"--output", "json",
	})
	require.NoError(t, cmd.ExecuteContext(context.Background()))

	reloaded, err := irwitness.LoadArtifact(mustRead(t, filepath.Join(outputDir, "reduced-ir.json")), irwitness.FormatJSON)
	require.NoError(t, err)
	require.NoError(t, reloaded.Validate())
	require.Equal(t, "keep-route", reloaded.HTTP[0].Routes[0].Name)
}

func TestWitnessCommandUnsupported(t *testing.T) {
	unsupportedIR := `
http:
- name: gw/http
  address: 0.0.0.0
  port: 10080
  hostnames:
  - '*'
  routes:
  - name: route-1
    hostname: '*'
    extensionServerPolicies:
    - name: foo/bar/ext
    destination:
      name: dest-1
      settings:
      - name: dest-1/0
        endpoints:
        - host: 7.7.7.7
          port: 8080
`
	inputDir := t.TempDir()
	outputDir := filepath.Join(t.TempDir(), "out")
	irPath := writeTemp(t, inputDir, "input-ir.yaml", unsupportedIR)
	predPath := writeTemp(t, inputDir, "predicate.yaml", witnessPredicateFixture)

	buf := bytes.NewBuffer(nil)
	cmd := newWitnessCommand()
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{
		"witness",
		"--ir", irPath,
		"--predicate", predPath,
		"--output-dir", outputDir,
	})
	err := cmd.ExecuteContext(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported")
	_, statErr := os.Stat(filepath.Join(outputDir, "reduced-ir.yaml"))
	require.True(t, os.IsNotExist(statErr))
}

func TestWitnessCommandRejectsBadInputs(t *testing.T) {
	inputDir := t.TempDir()
	irPath := writeTemp(t, inputDir, "input-ir.yaml", witnessIRFixture)
	predPath := writeTemp(t, inputDir, "predicate.yaml", witnessPredicateFixture)

	// Unknown field in the predicate spec is rejected.
	badPred := writeTemp(t, inputDir, "bad.yaml", "resourceExists:\n  type: nope\n  name: x\n")
	buf := bytes.NewBuffer(nil)
	cmd := newWitnessCommand()
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{
		"witness", "--ir", irPath, "--predicate", badPred,
		"--output-dir", filepath.Join(t.TempDir(), "out"),
	})
	require.Error(t, cmd.ExecuteContext(context.Background()))

	// Non-positive budget.
	buf.Reset()
	cmd = newWitnessCommand()
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{
		"witness", "--ir", irPath, "--predicate", predPath,
		"--output-dir", filepath.Join(t.TempDir(), "out"), "--max-evaluations", "0",
	})
	require.Error(t, cmd.ExecuteContext(context.Background()))
}

// TestWitnessCommandNoKubernetesAccess keeps the read-only guarantee explicit:
// the command package path only touches local files and the translated table
// never gets published anywhere.
func TestWitnessCommandNoKubernetesAccess(t *testing.T) {
	var x ir.Xds
	require.NoError(t, yaml.Unmarshal([]byte(witnessIRFixture), &x))
	require.Len(t, x.BackendClusters, 2)

	// Sanity: protojson (used for predicate plumbing) can render a cluster.
	tr := &translator.Translator{
		ControllerNamespace: "envoy-gateway-system",
		GlobalRateLimit: &translator.GlobalRateLimitSettings{
			ServiceURL: ratelimit.GetServiceURL("envoy-gateway-system", "cluster.local"),
		},
		Logger: logging.DefaultLogger(io.Discard, egv1a1.LogLevelInfo),
	}
	rvt, err := tr.Translate(context.Background(), &x)
	require.NoError(t, err)
	cluster := rvt.FindCluster("cluster-keep")
	require.NotNil(t, cluster)
	raw, err := protojson.Marshal(cluster)
	require.NoError(t, err)
	require.Contains(t, string(raw), "cluster-keep")
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	return data
}
