// Copyright Envoy Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package irwitness

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"sigs.k8s.io/yaml"

	"github.com/envoyproxy/gateway/internal/ir"
)

const (
	// FormatYAML serializes artifacts as YAML, matching the IR test data
	// contract used across the repository.
	FormatYAML = "yaml"
	// FormatJSON serializes artifacts as JSON.
	FormatJSON = "json"
)

// MarshalArtifact serializes an IR artifact using the same encoder the rest
// of the repository uses for ir.Xds. It never rewrites defaults or strips
// fields beyond the struct tags that define the IR contract itself.
func MarshalArtifact(x *ir.Xds, format string) ([]byte, error) {
	switch format {
	case FormatYAML, "":
		return yaml.Marshal(x)
	case FormatJSON:
		return json.MarshalIndent(x, "", "  ")
	default:
		return nil, fmt.Errorf("unsupported artifact format %q", format)
	}
}

// LoadArtifact reparses a serialized artifact into a fresh ir.Xds, rejecting
// unknown fields so a tampered or incompatible file cannot silently change
// semantics.
func LoadArtifact(data []byte, format string) (*ir.Xds, error) {
	x := &ir.Xds{}
	switch format {
	case FormatYAML, "":
		if err := yaml.Unmarshal(data, x, yaml.DisallowUnknownFields); err != nil {
			return nil, err
		}
	case FormatJSON:
		if err := json.Unmarshal(data, x); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported artifact format %q", format)
	}
	return x, nil
}

// WriteRestricted writes data to an explicit local path with owner-only
// permissions. It is the only supported sink for secret-bearing artifacts;
// the directory is created with 0700 and files with 0600.
func WriteRestricted(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("creating restricted output directory %s: %w", dir, err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("writing restricted artifact %s: %w", path, err)
	}
	return nil
}

// MarshalLog serializes the verifiable deletion log. Log entries only contain
// digests, names and structural counts, never resource bytes.
func MarshalLog(result *Result, format string) ([]byte, error) {
	switch format {
	case FormatYAML, "":
		return yaml.Marshal(result)
	case FormatJSON:
		return json.MarshalIndent(result, "", "  ")
	default:
		return nil, fmt.Errorf("unsupported log format %q", format)
	}
}
