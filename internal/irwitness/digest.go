// Copyright Envoy Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package irwitness

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"reflect"
	"sort"
)

// canonicalDigest builds a content digest directly from the Go object graph
// instead of going through JSON tag semantics. This deliberately preserves:
//
//   - ordered slices (elements are walked in order, prefixed by length);
//   - the nil/empty distinction (a nil slice, an empty non-nil slice and a
//     nil pointer all encode differently);
//   - explicit zero values (every struct field is visited regardless of
//     omitempty tags);
//   - shared object semantics (pointer values are identity-tracked: the
//     first visit emits the content, later visits emit a stable reference).
//
// Byte slices are folded through SHA-256 inline so secret material never
// appears in canonical text, while any content change still changes the
// digest.
func canonicalDigest(v any) string {
	w := &canonicalWalker{
		identities: make(map[reflect.Value]int),
	}
	w.value(reflect.ValueOf(v))
	sum := sha256.Sum256(w.out)
	return hex.EncodeToString(sum[:])
}

type canonicalWalker struct {
	out        []byte
	identities map[reflect.Value]int
	nextID     int
}

func (w *canonicalWalker) writef(format string, args ...any) {
	w.out = append(w.out, []byte(fmt.Sprintf(format, args...))...)
}

func (w *canonicalWalker) value(v reflect.Value) {
	if !v.IsValid() {
		w.writef("<invalid>")
		return
	}

	switch v.Kind() {
	case reflect.Pointer:
		if v.IsNil() {
			w.writef("P:nil:%s", v.Type().String())
			return
		}
		// Pointer identity is only meaningful for the same concrete type.
		if id, ok := w.identities[v]; ok {
			w.writef("P:ref@%d", id)
			return
		}
		id := w.nextID
		w.nextID++
		w.identities[v] = id
		w.writef("P:id@%d:%s:", id, v.Type().String())
		w.value(v.Elem())

	case reflect.Interface:
		if v.IsNil() {
			w.writef("I:nil:%s", v.Type().String())
			return
		}
		w.writef("I:%s:", v.Elem().Type().String())
		w.value(v.Elem())

	case reflect.Struct:
		t := v.Type()
		w.writef("S:%s:%d{", t.String(), t.NumField())
		for i := 0; i < t.NumField(); i++ {
			field := t.Field(i)
			if field.PkgPath != "" {
				// Unexported fields do not participate in the IR contract.
				continue
			}
			w.writef("F:%s:", field.Name)
			w.value(v.Field(i))
		}
		w.writef("}")

	case reflect.Slice:
		if v.IsNil() {
			w.writef("SL:nil:%s", v.Type().String())
			return
		}
		// []byte gets hashed so raw bytes (including PrivateBytes secrets)
		// never appear in canonical text.
		if v.Type().Elem().Kind() == reflect.Uint8 {
			raw := v.Bytes()
			h := sha256.Sum256(raw)
			w.writef("BYTES:%d:%s", len(raw), hex.EncodeToString(h[:]))
			return
		}
		w.writef("SL:%s:%d[", v.Type().String(), v.Len())
		for i := 0; i < v.Len(); i++ {
			w.writef("%d:", i)
			w.value(v.Index(i))
		}
		w.writef("]")

	case reflect.Array:
		w.writef("AR:%s:%d[", v.Type().String(), v.Len())
		for i := 0; i < v.Len(); i++ {
			w.writef("%d:", i)
			w.value(v.Index(i))
		}
		w.writef("]")

	case reflect.Map:
		if v.IsNil() {
			w.writef("M:nil:%s", v.Type().String())
			return
		}
		keys := v.MapKeys()
		// Map iteration order is randomized; sort by canonical key text.
		keyTexts := make([]string, 0, len(keys))
		byText := make(map[string]reflect.Value, len(keys))
		for _, k := range keys {
			kw := &canonicalWalker{identities: make(map[reflect.Value]int)}
			kw.value(k)
			text := string(kw.out)
			keyTexts = append(keyTexts, text)
			byText[text] = k
		}
		sort.Strings(keyTexts)
		w.writef("M:%s:%d{", v.Type().String(), len(keys))
		for _, text := range keyTexts {
			w.writef("K:%s:", text)
			w.value(v.MapIndex(byText[text]))
		}
		w.writef("}")

	case reflect.String:
		w.writef("STR:%q", v.String())
	case reflect.Bool:
		w.writef("BOOL:%t", v.Bool())
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		w.writef("INT:%s:%d", v.Kind().String(), v.Int())
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		w.writef("UINT:%s:%d", v.Kind().String(), v.Uint())
	case reflect.Float32, reflect.Float64:
		w.writef("FLT:%s:%g", v.Kind().String(), v.Float())
	case reflect.Complex64, reflect.Complex128:
		w.writef("CPX:%s:%v", v.Kind().String(), v.Complex())
	default:
		// Channels, functions and unsafe pointers are not part of the IR
		// contract; record their kind so two different values cannot collide.
		w.writef("UNSUPPORTED:%s:%s", v.Kind().String(), v.Type().String())
	}
}
