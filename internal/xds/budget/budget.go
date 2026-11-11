// Copyright Envoy Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

// Package budget meters the final protobuf resources of a candidate
// ResourceVersionTable and enforces the optional XdsResourceBudget before the
// candidate is published to the xDS snapshot cache.
package budget

import (
	"errors"
	"fmt"
	"math"
	"sort"

	cachev3 "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	protobuf "google.golang.org/protobuf/proto"

	egv1a1 "github.com/envoyproxy/gateway/api/v1alpha1"
	"github.com/envoyproxy/gateway/internal/ir"
	xtypes "github.com/envoyproxy/gateway/internal/xds/types"
)

// Violation kinds reported by Evaluate.
const (
	// ViolationResources means a type URL holds more unique resources than allowed.
	ViolationResources = "Resources"
	// ViolationSerializedBytes means the summed protobuf size of a type URL is too large.
	ViolationSerializedBytes = "SerializedBytes"
	// ViolationResourceBytes means a single resource exceeds the per-resource byte limit.
	ViolationResourceBytes = "ResourceBytes"
	// ViolationReferenceEdges means the snapshot holds more reference edges than allowed.
	ViolationReferenceEdges = "ReferenceEdges"
	// ViolationMetering means the candidate could not be metered, for example because
	// an overflow was detected while accumulating sizes.
	ViolationMetering = "Metering"
)

// redactedResourceName replaces resource names that must never leave the
// control plane, currently Secret names. Only the name is sensitive in the
// report; aggregate counts and sizes are still reported.
const redactedResourceName = "<redacted>"

// errOverflow is returned when accumulating metered values would wrap int64.
var errOverflow = errors.New("xds resource budget metering overflow")

// ResourceRef points at the Gateway API object (Gateway or route) a candidate
// snapshot was built from. It carries object identities only, never payloads.
type ResourceRef struct {
	Kind        string `json:"kind"`
	Namespace   string `json:"namespace,omitempty"`
	Name        string `json:"name"`
	SectionName string `json:"sectionName,omitempty"`
}

// Sources collects the Gateway and route objects attached to a candidate.
type Sources struct {
	Gateways []ResourceRef `json:"gateways,omitempty"`
	Routes   []ResourceRef `json:"routes,omitempty"`
}

// TypeUsage is the metered footprint of one xDS type URL.
type TypeUsage struct {
	TypeURL string `json:"typeURL"`
	// Resources is the number of unique resources after name-based deduplication.
	Resources int64 `json:"resources"`
	// DuplicateResources is the number of additional resource entries collapsed
	// because a resource with the same name was already present.
	DuplicateResources int64 `json:"duplicateResources,omitempty"`
	// SerializedBytes is the sum of the protobuf wire sizes of the unique resources.
	SerializedBytes int64 `json:"serializedBytes"`
	// MaxResourceBytes is the largest protobuf wire size of a single resource.
	MaxResourceBytes int64 `json:"maxResourceBytes"`
	// LargestResource names the resource reaching MaxResourceBytes. Secret names
	// are redacted. It is empty when the type URL holds no resources.
	LargestResource string `json:"largestResource,omitempty"`
}

// Usage is the metered footprint of a whole candidate snapshot.
type Usage struct {
	// ByType holds the usage per type URL, keyed by the type URL.
	ByType map[string]*TypeUsage `json:"byType"`
	// TotalResources is the number of unique resources across all type URLs.
	TotalResources int64 `json:"totalResources"`
	// TotalSerializedBytes is the sum of the protobuf wire sizes of every unique resource.
	TotalSerializedBytes int64 `json:"totalSerializedBytes"`
	// ReferenceEdges is the number of name-based reference edges between resources
	// that are both present in the candidate.
	ReferenceEdges int64 `json:"referenceEdges"`
}

// Violation describes one budget dimension a candidate failed, together with
// the observed and limiting values.
type Violation struct {
	// TypeURL is empty for snapshot-wide violations such as ReferenceEdges.
	TypeURL string `json:"typeURL,omitempty"`
	Kind    string `json:"kind"`
	// Observed is the metered value.
	Observed int64 `json:"observed"`
	// Limit is the configured bound. It is zero for ViolationMetering.
	Limit int64 `json:"limit"`
	// OffendingResources names the resources responsible, deterministically ordered.
	// Names are redacted (and the slice may be empty) for Secret resources.
	OffendingResources []string `json:"offendingResources,omitempty"`
	// ResourcesRedacted is true when OffendingResources was withheld because the
	// type URL's resource names must not appear in reports.
	ResourcesRedacted bool `json:"resourcesRedacted,omitempty"`
}

// Report is the budget evaluation outcome for one candidate snapshot.
type Report struct {
	// IRKey identifies the proxy infrastructure the candidate belongs to. The
	// budget gate is applied per key, so rejecting one key never blocks another.
	IRKey string `json:"irKey"`
	// Generation identifies the candidate within the IR key. It increments for
	// every evaluated candidate, including rejected ones.
	Generation int64 `json:"generation"`
	// LastGoodGeneration is the generation of the snapshot still served by Envoy.
	// It is zero when no compliant snapshot has been published yet.
	LastGoodGeneration int64 `json:"lastGoodGeneration,omitempty"`
	// Published is true only when the candidate was fully compliant and handed to
	// the snapshot cache. A rejected candidate must never be reported as published.
	Published bool `json:"published"`
	// Violations is empty when Published is true.
	Violations []Violation `json:"violations,omitempty"`
	// Sources attributes the candidate to the Gateways and routes it was built from.
	Sources Sources `json:"sources"`
	// Usage is the metered footprint behind the decision. It never contains
	// resource payloads, only aggregate sizes and counts.
	Usage *Usage `json:"usage"`
}

// DeepCopy returns an independent copy of the report so it can be stored in a
// watchable map without sharing mutable slices.
func (r *Report) DeepCopy() *Report {
	if r == nil {
		return nil
	}
	out := *r
	out.Violations = cloneViolations(r.Violations)
	out.Sources.Gateways = append([]ResourceRef(nil), r.Sources.Gateways...)
	out.Sources.Routes = append([]ResourceRef(nil), r.Sources.Routes...)
	if r.Usage != nil {
		u := &Usage{
			ByType:               make(map[string]*TypeUsage, len(r.Usage.ByType)),
			TotalResources:       r.Usage.TotalResources,
			TotalSerializedBytes: r.Usage.TotalSerializedBytes,
			ReferenceEdges:       r.Usage.ReferenceEdges,
		}
		for k, v := range r.Usage.ByType {
			cp := *v
			u.ByType[k] = &cp
		}
		out.Usage = u
	}
	return &out
}

func cloneViolations(in []Violation) []Violation {
	if in == nil {
		return nil
	}
	out := make([]Violation, len(in))
	for i := range in {
		out[i] = in[i]
		if in[i].OffendingResources != nil {
			out[i].OffendingResources = append([]string(nil), in[i].OffendingResources...)
		}
	}
	return out
}

// addInt64 returns a+b or errOverflow when the addition would wrap.
func addInt64(a, b int64) (int64, error) {
	if b > 0 && a > math.MaxInt64-b {
		return 0, errOverflow
	}
	if b < 0 && a < math.MinInt64-b {
		return 0, errOverflow
	}
	return a + b, nil
}

// Meter measures the final resources of a candidate snapshot. Resources are
// deduplicated by name within each type URL, every unique resource is
// serialized with protobuf so that ordered fields and unknown bytes are
// included, and all accumulations are overflow-checked.
func Meter(resources xtypes.XdsResources) (*Usage, error) {
	usage := &Usage{ByType: make(map[string]*TypeUsage, len(resources))}

	// Stable type URL ordering keeps reports and the largest-resource tie break
	// deterministic regardless of map iteration.
	typeURLs := make([]string, 0, len(resources))
	for typeURL := range resources {
		typeURLs = append(typeURLs, typeURL)
	}
	sort.Strings(typeURLs)

	nameSets := make(map[string]map[string]struct{}, len(typeURLs))
	var meterErr error

	for _, typeURL := range typeURLs {
		entries := resources[typeURL]
		tu := &TypeUsage{TypeURL: typeURL}
		seenNames := make(map[string]struct{}, len(entries))
		nameSets[typeURL] = seenNames

		for idx, resource := range entries {
			if resource == nil {
				continue
			}
			name := cachev3.GetResourceName(resource)
			if name == "" {
				// Extension types unknown to go-control-plane have no extracted
				// name; fall back to a stable per-slice identity so distinct
				// resources are still metered instead of collapsing into one.
				name = fmt.Sprintf("__unnamed_%s_%d", typeURL, idx)
			}
			if _, exists := seenNames[name]; exists {
				// Shared resources (for example a Cluster or Secret referenced by
				// many routes) are counted and serialized exactly once.
				var err error
				tu.DuplicateResources, err = addInt64(tu.DuplicateResources, 1)
				if err != nil {
					meterErr = errors.Join(meterErr, err)
				}
				continue
			}
			seenNames[name] = struct{}{}

			// Marshal the actual protobuf message: the wire output includes
			// repeated field order and unknown fields preserved on unmarshal.
			data, err := protobuf.Marshal(resource)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal xds resource %s/%s: %w", typeURL, name, err)
			}
			size := int64(len(data))

			tu.Resources, err = addInt64(tu.Resources, 1)
			if err != nil {
				meterErr = errors.Join(meterErr, err)
			}
			tu.SerializedBytes, err = addInt64(tu.SerializedBytes, size)
			if err != nil {
				meterErr = errors.Join(meterErr, err)
			}
			if size > tu.MaxResourceBytes {
				tu.MaxResourceBytes = size
				if typeURL == resourcev3.SecretType {
					tu.LargestResource = redactedResourceName
				} else {
					tu.LargestResource = name
				}
			}
		}

		usage.ByType[typeURL] = tu
		var err error
		usage.TotalResources, err = addInt64(usage.TotalResources, tu.Resources)
		if err != nil {
			meterErr = errors.Join(meterErr, err)
		}
		usage.TotalSerializedBytes, err = addInt64(usage.TotalSerializedBytes, tu.SerializedBytes)
		if err != nil {
			meterErr = errors.Join(meterErr, err)
		}
	}

	edges, err := countReferenceEdges(resources, nameSets, typeURLs)
	if err != nil {
		meterErr = errors.Join(meterErr, err)
	}
	usage.ReferenceEdges = edges

	if meterErr != nil {
		return usage, meterErr
	}
	return usage, nil
}

// Evaluate checks a metered candidate against the budget and builds the
// decision report. A nil budget means the feature is disabled: callers must
// keep the original publish path and skip the gate entirely.
func Evaluate(
	budget *egv1a1.XdsResourceBudget,
	irKey string,
	generation, lastGoodGeneration int64,
	usage *Usage,
	sources Sources,
	meterErr error,
) *Report {
	report := &Report{
		IRKey:              irKey,
		Generation:         generation,
		LastGoodGeneration: lastGoodGeneration,
		Sources:            sources,
		Usage:              usage,
	}
	if budget == nil {
		report.Published = true
		return report
	}

	if meterErr != nil {
		report.Published = false
		report.Violations = append(report.Violations, Violation{
			Kind:     ViolationMetering,
			Observed: 0,
		})
		return report
	}

	for _, perType := range budget.PerTypeURL {
		tu := usage.ByType[perType.TypeURL]
		if tu == nil {
			tu = &TypeUsage{TypeURL: perType.TypeURL}
		}

		if perType.MaxResources != nil && tu.Resources > *perType.MaxResources {
			report.Violations = append(report.Violations, Violation{
				TypeURL:  perType.TypeURL,
				Kind:     ViolationResources,
				Observed: tu.Resources,
				Limit:    *perType.MaxResources,
			})
		}
		if perType.MaxSerializedBytes != nil && tu.SerializedBytes > *perType.MaxSerializedBytes {
			report.Violations = append(report.Violations, Violation{
				TypeURL:  perType.TypeURL,
				Kind:     ViolationSerializedBytes,
				Observed: tu.SerializedBytes,
				Limit:    *perType.MaxSerializedBytes,
			})
		}
		if perType.MaxResourceBytes != nil && tu.MaxResourceBytes > *perType.MaxResourceBytes {
			v := Violation{
				TypeURL:  perType.TypeURL,
				Kind:     ViolationResourceBytes,
				Observed: tu.MaxResourceBytes,
				Limit:    *perType.MaxResourceBytes,
			}
			if perType.TypeURL == resourcev3.SecretType {
				v.ResourcesRedacted = true
			} else if tu.LargestResource != "" {
				v.OffendingResources = []string{tu.LargestResource}
			}
			report.Violations = append(report.Violations, v)
		}
	}

	if budget.MaxReferenceEdges != nil && usage.ReferenceEdges > *budget.MaxReferenceEdges {
		report.Violations = append(report.Violations, Violation{
			Kind:     ViolationReferenceEdges,
			Observed: usage.ReferenceEdges,
			Limit:    *budget.MaxReferenceEdges,
		})
	}

	report.Published = len(report.Violations) == 0
	return report
}

// CollectSources extracts the Gateway and route identities attached to an IR.
// It reads source metadata only, so the resulting refs never contain payloads.
func CollectSources(xdsIR *ir.Xds) Sources {
	var sources Sources
	if xdsIR == nil {
		return sources
	}

	gatewaySeen := make(map[ResourceRef]struct{})
	routeSeen := make(map[ResourceRef]struct{})
	addGateway := func(md *ir.ResourceMetadata) {
		if md == nil || md.Kind == "" {
			return
		}
		ref := ResourceRef{Kind: md.Kind, Namespace: md.Namespace, Name: md.Name, SectionName: md.SectionName}
		if _, ok := gatewaySeen[ref]; !ok {
			gatewaySeen[ref] = struct{}{}
			sources.Gateways = append(sources.Gateways, ref)
		}
	}
	addRoute := func(md *ir.ResourceMetadata) {
		if md == nil || md.Kind == "" || md.Name == "" {
			return
		}
		ref := ResourceRef{Kind: md.Kind, Namespace: md.Namespace, Name: md.Name, SectionName: md.SectionName}
		if _, ok := routeSeen[ref]; !ok {
			routeSeen[ref] = struct{}{}
			sources.Routes = append(sources.Routes, ref)
		}
	}

	for _, l := range xdsIR.HTTP {
		if l == nil {
			continue
		}
		addGateway(l.Metadata)
		for _, route := range l.Routes {
			if route != nil {
				addRoute(route.Metadata)
			}
		}
	}
	for _, l := range xdsIR.TCP {
		if l == nil {
			continue
		}
		addGateway(l.Metadata)
		for _, route := range l.Routes {
			if route != nil {
				addRoute(route.Metadata)
			}
		}
	}
	for _, l := range xdsIR.UDP {
		if l == nil {
			continue
		}
		addGateway(l.Metadata)
		if l.Route != nil && l.Route.Name != "" {
			ref := ResourceRef{Kind: "UDPRoute", Name: l.Route.Name}
			if _, ok := routeSeen[ref]; !ok {
				routeSeen[ref] = struct{}{}
				sources.Routes = append(sources.Routes, ref)
			}
		}
	}

	sortRefs(sources.Gateways)
	sortRefs(sources.Routes)
	return sources
}

func sortRefs(refs []ResourceRef) {
	sort.Slice(refs, func(i, j int) bool {
		if refs[i].Kind != refs[j].Kind {
			return refs[i].Kind < refs[j].Kind
		}
		if refs[i].Namespace != refs[j].Namespace {
			return refs[i].Namespace < refs[j].Namespace
		}
		if refs[i].Name != refs[j].Name {
			return refs[i].Name < refs[j].Name
		}
		return refs[i].SectionName < refs[j].SectionName
	})
}
