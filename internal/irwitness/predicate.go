// Copyright Envoy Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package irwitness

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/anypb"

	xds_types "github.com/envoyproxy/gateway/internal/xds/types"
)

// Bounds keep the CLI predicate surface finite and cheap to evaluate.
const (
	MaxPredicateDepth    = 8
	MaxPredicateAtoms    = 32
	MaxFieldPathSegments = 16
	MaxFieldSelectorLen  = 256
	MaxPredicateValueLen = 4096
)

// PredicateSpec is the serializable, bounded predicate accepted by the CLI.
// Exactly one of the fields may be set on each node. It only expresses:
//
//   - existence of an xDS resource of a fixed type/name;
//   - presence, absence or exact scalar value of a protobuf field reached by a
//     bounded path;
//   - finite AND/OR/NOT combinations of the above.
//
// It has no expression evaluation, no imports, no shell and no network hooks.
type PredicateSpec struct {
	And            []*PredicateSpec `json:"and,omitempty" yaml:"and,omitempty"`
	Or             []*PredicateSpec `json:"or,omitempty" yaml:"or,omitempty"`
	Not            *PredicateSpec   `json:"not,omitempty" yaml:"not,omitempty"`
	ResourceExists *ResourceRef     `json:"resourceExists,omitempty" yaml:"resourceExists,omitempty"`
	FieldExists    *FieldProbe      `json:"fieldExists,omitempty" yaml:"fieldExists,omitempty"`
	FieldAbsent    *FieldProbe      `json:"fieldAbsent,omitempty" yaml:"fieldAbsent,omitempty"`
	FieldEquals    *FieldEqualsSpec `json:"fieldEquals,omitempty" yaml:"fieldEquals,omitempty"`
}

// ResourceRef selects one xDS resource by type and name.
type ResourceRef struct {
	// Type is one of listener, route, cluster, endpoint, secret.
	Type string `json:"type" yaml:"type"`
	Name string `json:"name" yaml:"name"`
}

// FieldProbe addresses a protobuf field inside a named xDS resource.
type FieldProbe struct {
	// Type is one of listener, route, cluster, endpoint, secret.
	Type string `json:"type" yaml:"type"`
	Name string `json:"name" yaml:"name"`
	// Field is a bounded dot-separated protobuf path, e.g.
	// filterChains[0].filters[name=foo].typedConfig.httpFilters[name=bar].
	Field string `json:"field" yaml:"field"`
}

// FieldEqualsSpec is a FieldProbe together with the exact expected value.
type FieldEqualsSpec struct {
	FieldProbe `json:",inline" yaml:",inline"`
	// Value must be a scalar (string, bool, int or float).
	Value any `json:"value" yaml:"value"`
}

var resourceTypeMap = map[string]resourcev3.Type{
	"listener": resourcev3.ListenerType,
	"route":    resourcev3.RouteType,
	"cluster":  resourcev3.ClusterType,
	"endpoint": resourcev3.EndpointType,
	"secret":   resourcev3.SecretType,
}

// CompilePredicate validates the spec against the declared bounds and returns
// an executable Predicate.
func CompilePredicate(spec *PredicateSpec) (Predicate, error) {
	if spec == nil {
		return nil, errors.New("predicate spec must not be nil")
	}
	atoms, err := spec.validate(0)
	if err != nil {
		return nil, err
	}
	if atoms == 0 {
		return nil, errors.New("predicate must contain at least one atomic check")
	}
	p := &specPredicate{spec: spec, atoms: atoms}
	p.digest = canonicalDigest(spec)
	p.description = renderSpec(spec)
	return p, nil
}

func (s *PredicateSpec) validate(depth int) (int, error) {
	if depth > MaxPredicateDepth {
		return 0, fmt.Errorf("predicate nesting exceeds max depth %d", MaxPredicateDepth)
	}
	set := 0
	if len(s.And) > 0 {
		set++
	}
	if len(s.Or) > 0 {
		set++
	}
	if s.Not != nil {
		set++
	}
	if s.ResourceExists != nil {
		set++
	}
	if s.FieldExists != nil {
		set++
	}
	if s.FieldAbsent != nil {
		set++
	}
	if s.FieldEquals != nil {
		set++
	}
	if set != 1 {
		return 0, fmt.Errorf("predicate node must set exactly one operator, got %d", set)
	}

	atoms := 0
	switch {
	case len(s.And) > 0:
		if len(s.And) < 2 {
			return 0, errors.New("and requires at least two operands")
		}
		for _, child := range s.And {
			n, err := child.validate(depth + 1)
			if err != nil {
				return 0, err
			}
			atoms += n
		}
	case len(s.Or) > 0:
		if len(s.Or) < 2 {
			return 0, errors.New("or requires at least two operands")
		}
		for _, child := range s.Or {
			n, err := child.validate(depth + 1)
			if err != nil {
				return 0, err
			}
			atoms += n
		}
	case s.Not != nil:
		n, err := s.Not.validate(depth + 1)
		if err != nil {
			return 0, err
		}
		atoms += n
	case s.ResourceExists != nil:
		if err := s.ResourceExists.validate(); err != nil {
			return 0, err
		}
		atoms = 1
	case s.FieldExists != nil:
		if err := s.FieldExists.validate(); err != nil {
			return 0, err
		}
		atoms = 1
	case s.FieldAbsent != nil:
		if err := s.FieldAbsent.validate(); err != nil {
			return 0, err
		}
		atoms = 1
	case s.FieldEquals != nil:
		if err := s.FieldEquals.validate(); err != nil {
			return 0, err
		}
		switch s.FieldEquals.Value.(type) {
		case string, bool, int, int64, float64, float32:
		default:
			return 0, fmt.Errorf("fieldEquals value must be a scalar, got %T", s.FieldEquals.Value)
		}
		atoms = 1
	}
	if atoms > MaxPredicateAtoms {
		return 0, fmt.Errorf("predicate uses %d atomic checks, max is %d", atoms, MaxPredicateAtoms)
	}
	return atoms, nil
}

func (r *ResourceRef) validate() error {
	if _, ok := resourceTypeMap[r.Type]; !ok {
		return fmt.Errorf("unknown resource type %q", r.Type)
	}
	if r.Name == "" {
		return errors.New("resource name must not be empty")
	}
	return nil
}

func (p *FieldProbe) validate() error {
	if _, ok := resourceTypeMap[p.Type]; !ok {
		return fmt.Errorf("unknown resource type %q", p.Type)
	}
	if p.Name == "" {
		return errors.New("resource name must not be empty")
	}
	if p.Field == "" {
		return errors.New("field path must not be empty")
	}
	if len(p.Field) > MaxFieldSelectorLen*MaxFieldPathSegments {
		return errors.New("field path too long")
	}
	segments := strings.Split(p.Field, ".")
	if len(segments) > MaxFieldPathSegments {
		return fmt.Errorf("field path has %d segments, max is %d", len(segments), MaxFieldPathSegments)
	}
	for _, segment := range segments {
		if segment == "" || len(segment) > MaxFieldSelectorLen {
			return fmt.Errorf("invalid field path segment %q", segment)
		}
	}
	return nil
}

type specPredicate struct {
	spec        *PredicateSpec
	atoms       int
	digest      string
	description string
}

func (p *specPredicate) Digest() string   { return p.digest }
func (p *specPredicate) Describe() string { return p.description }

func (p *specPredicate) Eval(table *xds_types.ResourceVersionTable) bool {
	return evalSpec(p.spec, table)
}

func evalSpec(s *PredicateSpec, table *xds_types.ResourceVersionTable) bool {
	switch {
	case len(s.And) > 0:
		for _, child := range s.And {
			if !evalSpec(child, table) {
				return false
			}
		}
		return true
	case len(s.Or) > 0:
		for _, child := range s.Or {
			if evalSpec(child, table) {
				return true
			}
		}
		return false
	case s.Not != nil:
		return !evalSpec(s.Not, table)
	case s.ResourceExists != nil:
		_, ok := findResource(table, resourceTypeMap[s.ResourceExists.Type], s.ResourceExists.Name)
		return ok
	case s.FieldExists != nil:
		_, _, present, err := resolveProbe(table, s.FieldExists)
		return err == nil && present
	case s.FieldAbsent != nil:
		_, _, present, err := resolveProbe(table, s.FieldAbsent)
		return err == nil && !present
	case s.FieldEquals != nil:
		value, fd, present, err := resolveProbe(table, &s.FieldEquals.FieldProbe)
		if err != nil || !present || fd == nil {
			return false
		}
		return scalarEquals(value, fd, s.FieldEquals.Value)
	}
	return false
}

// GoPredicate wraps an explicit caller-supplied Go function for library use.
// Callers must declare that the function is deterministic and side-effect
// free and state its call budget; Reduce rejects an undeclared predicate.
type GoPredicate struct {
	// Fn is the predicate over the real translated table.
	Fn func(*xds_types.ResourceVersionTable) bool
	// Deterministic must be explicitly true.
	Deterministic bool
	// CallBudget is the declared maximum number of predicate invocations the
	// caller authorizes for one run; it must be positive.
	CallBudget int
	// ID is a caller-chosen stable identifier folded into the cache key. It
	// must uniquely distinguish this closure's semantics.
	ID string
	// Description is used in deletion logs.
	Description string
}

func (g *GoPredicate) Eval(table *xds_types.ResourceVersionTable) bool { return g.Fn(table) }
func (g *GoPredicate) Digest() string {
	return canonicalDigest(struct {
		Kind          string `json:"kind"`
		ID            string `json:"id"`
		Deterministic bool   `json:"deterministic"`
		CallBudget    int    `json:"callBudget"`
	}{Kind: "go-predicate", ID: g.ID, Deterministic: g.Deterministic, CallBudget: g.CallBudget})
}
func (g *GoPredicate) Describe() string {
	if g.Description != "" {
		return g.Description
	}
	return "go-predicate:" + g.ID
}

func renderSpec(s *PredicateSpec) string {
	switch {
	case len(s.And) > 0:
		parts := make([]string, len(s.And))
		for i, c := range s.And {
			parts[i] = renderSpec(c)
		}
		return "and(" + strings.Join(parts, ",") + ")"
	case len(s.Or) > 0:
		parts := make([]string, len(s.Or))
		for i, c := range s.Or {
			parts[i] = renderSpec(c)
		}
		return "or(" + strings.Join(parts, ",") + ")"
	case s.Not != nil:
		return "not(" + renderSpec(s.Not) + ")"
	case s.ResourceExists != nil:
		return fmt.Sprintf("resourceExists(%s/%s)", s.ResourceExists.Type, s.ResourceExists.Name)
	case s.FieldExists != nil:
		return fmt.Sprintf("fieldExists(%s/%s:%s)", s.FieldExists.Type, s.FieldExists.Name, s.FieldExists.Field)
	case s.FieldAbsent != nil:
		return fmt.Sprintf("fieldAbsent(%s/%s:%s)", s.FieldAbsent.Type, s.FieldAbsent.Name, s.FieldAbsent.Field)
	case s.FieldEquals != nil:
		return fmt.Sprintf("fieldEquals(%s/%s:%s=%v)", s.FieldEquals.Type, s.FieldEquals.Name, s.FieldEquals.Field, s.FieldEquals.Value)
	}
	return "<empty>"
}

// findResource locates a named resource of the given type in the table.
func findResource(table *xds_types.ResourceVersionTable, rType resourcev3.Type, name string) (protoreflect.Message, bool) {
	if table == nil {
		return nil, false
	}
	for _, resource := range table.XdsResources[rType] {
		msg, ok := resource.(protoreflect.ProtoMessage)
		if !ok {
			continue
		}
		rm := msg.ProtoReflect()
		fd := rm.Descriptor().Fields().ByName("name")
		if fd == nil {
			continue
		}
		if rm.Get(fd).String() == name {
			return rm, true
		}
	}
	return nil, false
}

func resolveProbe(table *xds_types.ResourceVersionTable, probe *FieldProbe) (protoreflect.Value, protoreflect.FieldDescriptor, bool, error) {
	msg, ok := findResource(table, resourceTypeMap[probe.Type], probe.Name)
	if !ok {
		return protoreflect.Value{}, nil, false, nil
	}
	return resolveFieldPath(msg, probe.Field)
}

// pathSegment is one parsed field path element with an optional selector.
type pathSegment struct {
	field        string
	index        int
	hasIndex     bool
	keyField     string
	keyValue     string
	hasKeySelect bool
}

// parseFieldPath splits a path on dots at bracket depth zero, so selector
// values such as filter names may themselves contain dots.
func parseFieldPath(path string) ([]pathSegment, error) {
	var raw []string
	depth := 0
	start := 0
	for i, r := range path {
		switch r {
		case '[':
			depth++
		case ']':
			depth--
			if depth < 0 {
				return nil, fmt.Errorf("unbalanced brackets in %q", path)
			}
		case '.':
			if depth == 0 {
				raw = append(raw, path[start:i])
				start = i + 1
			}
		}
	}
	if depth != 0 {
		return nil, fmt.Errorf("unbalanced brackets in %q", path)
	}
	raw = append(raw, path[start:])

	segments := make([]pathSegment, 0, len(raw))
	for _, part := range raw {
		open := strings.Index(part, "[")
		seg := pathSegment{}
		if open < 0 {
			seg.field = part
			segments = append(segments, seg)
			continue
		}
		if !strings.HasSuffix(part, "]") {
			return nil, fmt.Errorf("malformed selector in %q", part)
		}
		seg.field = part[:open]
		selector := part[open+1 : len(part)-1]
		if selector == "" {
			return nil, fmt.Errorf("empty selector in %q", part)
		}
		if n, err := strconv.Atoi(selector); err == nil {
			if n < 0 {
				return nil, fmt.Errorf("negative index in %q", part)
			}
			seg.index = n
			seg.hasIndex = true
		} else {
			eq := strings.Index(selector, "=")
			if eq <= 0 || eq == len(selector)-1 {
				return nil, fmt.Errorf("selector must be [index] or [field=value], got %q", part)
			}
			seg.keyField = selector[:eq]
			seg.keyValue = selector[eq+1:]
			seg.hasKeySelect = true
		}
		segments = append(segments, seg)
	}
	return segments, nil
}

// resolveFieldPath walks a protobuf message. google.protobuf.Any fields are
// unwrapped transparently; repeated message fields support numeric index and
// name-based [field=value] selection. The returned descriptor is nil only for
// a bare repeated/map field, in which case presence means non-empty.
func resolveFieldPath(root protoreflect.Message, path string) (protoreflect.Value, protoreflect.FieldDescriptor, bool, error) {
	segments, err := parseFieldPath(path)
	if err != nil {
		return protoreflect.Value{}, nil, false, err
	}

	msg := root
	for i, seg := range segments {
		last := i == len(segments)-1

		// Unwrap Any-typed current message before resolving the next field.
		if msg.Descriptor().FullName() == "google.protobuf.Any" {
			anyMsg, ok := msg.Interface().(*anypb.Any)
			if !ok {
				return protoreflect.Value{}, nil, false, errors.New("field is google.protobuf.Any but not an anypb.Any")
			}
			inner, err := anyMsg.UnmarshalNew()
			if err != nil {
				return protoreflect.Value{}, nil, false, fmt.Errorf("unwrapping Any: %w", err)
			}
			msg = inner.ProtoReflect()
		}

		fd := msg.Descriptor().Fields().ByName(protoreflect.Name(seg.field))
		if fd == nil {
			fd = msg.Descriptor().Fields().ByJSONName(seg.field)
		}
		if fd == nil {
			return protoreflect.Value{}, nil, false, fmt.Errorf("unknown protobuf field %q", seg.field)
		}

		value := msg.Get(fd)

		if fd.IsMap() {
			if seg.hasIndex || seg.hasKeySelect {
				return protoreflect.Value{}, nil, false, fmt.Errorf("selectors are not supported on map field %q", seg.field)
			}
			if !last {
				return protoreflect.Value{}, nil, false, fmt.Errorf("cannot descend into map field %q", seg.field)
			}
			return value, nil, value.Map().Len() > 0, nil
		}

		if fd.IsList() {
			list := value.List()
			if !seg.hasIndex && !seg.hasKeySelect {
				if !last {
					return protoreflect.Value{}, nil, false, fmt.Errorf("cannot descend through unindexed repeated field %q", seg.field)
				}
				return value, nil, list.Len() > 0, nil
			}
			if seg.hasIndex && seg.hasKeySelect {
				return protoreflect.Value{}, nil, false, fmt.Errorf("invalid selector on %q", seg.field)
			}

			var elem protoreflect.Value
			if seg.hasIndex {
				if seg.index >= list.Len() {
					return protoreflect.Value{}, fd, false, nil
				}
				elem = list.Get(seg.index)
			} else {
				if fd.Kind() != protoreflect.MessageKind {
					return protoreflect.Value{}, nil, false, fmt.Errorf("key selector requires a repeated message field %q", seg.field)
				}
				matched := false
				for j := 0; j < list.Len(); j++ {
					candidate := list.Get(j)
					em := candidate.Message()
					kfd := em.Descriptor().Fields().ByName(protoreflect.Name(seg.keyField))
					if kfd == nil {
						kfd = em.Descriptor().Fields().ByJSONName(seg.keyField)
					}
					if kfd == nil {
						continue
					}
					if em.Get(kfd).String() == seg.keyValue {
						elem = candidate
						matched = true
						break
					}
				}
				if !matched {
					return protoreflect.Value{}, fd, false, nil
				}
			}

			if fd.Kind() != protoreflect.MessageKind {
				if !last {
					return protoreflect.Value{}, nil, false, fmt.Errorf("cannot descend into scalar element of %q", seg.field)
				}
				return elem, fd, scalarPresent(fd, elem), nil
			}
			if last {
				return elem, fd, elem.Message().IsValid(), nil
			}
			msg = elem.Message()
			continue
		}

		if seg.hasIndex || seg.hasKeySelect {
			return protoreflect.Value{}, nil, false, fmt.Errorf("selector used on non-repeated field %q", seg.field)
		}
		if fd.HasPresence() && !msg.Has(fd) {
			return protoreflect.Value{}, fd, false, nil
		}

		if fd.Kind() == protoreflect.MessageKind {
			if last {
				return value, fd, value.Message().IsValid(), nil
			}
			msg = value.Message()
			continue
		}
		if !last {
			return protoreflect.Value{}, nil, false, fmt.Errorf("cannot descend into scalar field %q", seg.field)
		}
		return value, fd, scalarPresent(fd, value), nil
	}

	return protoreflect.Value{}, nil, false, errors.New("empty field path")
}

// scalarPresent reports whether a scalar value is populated. Fields with
// explicit presence are already checked via Message.Has before this helper;
// for synthetic-presence scalars a non-default value counts as present.
func scalarPresent(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
	switch fd.Kind() {
	case protoreflect.BoolKind:
		return v.Bool() != fd.Default().Bool()
	case protoreflect.Int32Kind, protoreflect.Int64Kind,
		protoreflect.Sint32Kind, protoreflect.Sint64Kind,
		protoreflect.Sfixed32Kind, protoreflect.Sfixed64Kind:
		return v.Int() != fd.Default().Int()
	case protoreflect.Uint32Kind, protoreflect.Uint64Kind,
		protoreflect.Fixed32Kind, protoreflect.Fixed64Kind:
		return v.Uint() != fd.Default().Uint()
	case protoreflect.FloatKind, protoreflect.DoubleKind:
		return v.Float() != fd.Default().Float()
	case protoreflect.StringKind:
		return v.String() != fd.Default().String()
	case protoreflect.BytesKind:
		return len(v.Bytes()) != len(fd.Default().Bytes())
	case protoreflect.EnumKind:
		return v.Enum() != fd.Default().Enum()
	}
	return true
}

func scalarEquals(actual protoreflect.Value, fd protoreflect.FieldDescriptor, expected any) bool {
	switch want := expected.(type) {
	case string:
		if fd.Kind() == protoreflect.EnumKind {
			// Allow matching enums by their value name.
			enumValue := fd.Enum().Values().ByNumber(actual.Enum())
			return enumValue != nil && string(enumValue.Name()) == want
		}
		return fd.Kind() == protoreflect.StringKind && actual.String() == want
	case bool:
		return fd.Kind() == protoreflect.BoolKind && actual.Bool() == want
	case int:
		return scalarIntEquals(actual, fd, int64(want))
	case int64:
		return scalarIntEquals(actual, fd, want)
	case float64:
		switch fd.Kind() {
		case protoreflect.FloatKind, protoreflect.DoubleKind:
			return actual.Float() == want
		case protoreflect.Int32Kind, protoreflect.Int64Kind,
			protoreflect.Sint32Kind, protoreflect.Sint64Kind,
			protoreflect.Sfixed32Kind, protoreflect.Sfixed64Kind:
			return float64(actual.Int()) == want
		case protoreflect.Uint32Kind, protoreflect.Uint64Kind,
			protoreflect.Fixed32Kind, protoreflect.Fixed64Kind:
			return float64(actual.Uint()) == want
		}
	case float32:
		return scalarEquals(actual, fd, float64(want))
	}
	return false
}

func scalarIntEquals(actual protoreflect.Value, fd protoreflect.FieldDescriptor, want int64) bool {
	switch fd.Kind() {
	case protoreflect.Int32Kind, protoreflect.Int64Kind,
		protoreflect.Sint32Kind, protoreflect.Sint64Kind,
		protoreflect.Sfixed32Kind, protoreflect.Sfixed64Kind:
		return actual.Int() == want
	case protoreflect.Uint32Kind, protoreflect.Uint64Kind,
		protoreflect.Fixed32Kind, protoreflect.Fixed64Kind:
		return int64(actual.Uint()) == want
	case protoreflect.EnumKind:
		return int64(actual.Enum()) == want
	}
	return false
}
