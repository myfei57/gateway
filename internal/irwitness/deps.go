// Copyright Envoy Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package irwitness

import (
	"fmt"
	"reflect"

	"github.com/envoyproxy/gateway/internal/ir"
)

// FilterGroup identifies one of the per-route extension filter collections
// that may be deleted when filter group deletions are enabled.
type FilterGroup string

const (
	FilterGroupExtProcs       FilterGroup = "extProcs"
	FilterGroupWasms          FilterGroup = "wasms"
	FilterGroupLuas           FilterGroup = "luas"
	FilterGroupDynamicModules FilterGroup = "dynamicModules"
)

// referenceIndex counts every live reference to the standalone registries.
// It is rebuilt from a whole IR so sharing across listeners, routes and
// mirrors is counted correctly.
type referenceIndex struct {
	backendClusters map[string]int
	extBackends     map[string]int
	caDigests       map[string]int
}

func buildReferenceIndex(x *ir.Xds) *referenceIndex {
	idx := &referenceIndex{
		backendClusters: make(map[string]int),
		extBackends:     make(map[string]int),
		caDigests:       make(map[string]int),
	}
	if x == nil {
		return idx
	}

	for _, listener := range x.HTTP {
		idx.addTLS(listener.TLS)
		if listener == nil {
			continue
		}
		for _, route := range listener.Routes {
			if route == nil {
				continue
			}
			idx.addDestination(route.Destination)
			for _, mirror := range route.Mirrors {
				if mirror != nil {
					idx.addDestination(mirror.Destination)
				}
			}
			if route.EnvoyExtensions != nil {
				for _, backendName := range route.EnvoyExtensions.Backends {
					idx.extBackends[backendName]++
				}
			}
		}
	}
	for _, listener := range x.TCP {
		if listener == nil {
			continue
		}
		idx.addTLS(listener.TLS)
		for _, route := range listener.Routes {
			if route != nil {
				idx.addDestination(route.Destination)
			}
		}
	}
	for _, listener := range x.UDP {
		if listener == nil {
			continue
		}
		if listener.Route != nil {
			idx.addDestination(listener.Route.Destination)
		}
	}
	for _, cluster := range x.BackendClusters {
		if cluster != nil && cluster.Setting != nil {
			idx.addSettingTLS(cluster.Setting)
		}
	}
	for _, backend := range x.ExtensionBackends {
		if backend == nil {
			continue
		}
		idx.addDestination(&backend.RouteDestination)
	}
	return idx
}

func (idx *referenceIndex) addDestination(dest *ir.RouteDestination) {
	if dest == nil {
		return
	}
	for _, ref := range dest.BackendClusterRefs {
		if ref != nil && ref.Name != "" {
			idx.backendClusters[ref.Name]++
		}
	}
	for _, setting := range dest.Settings {
		idx.addSettingTLS(setting)
	}
}

func (idx *referenceIndex) addSettingTLS(setting *ir.DestinationSetting) {
	if setting == nil || setting.TLS == nil {
		return
	}
	idx.addCA(setting.TLS.CACertificate)
	for _, cert := range setting.TLS.ClientCertificates {
		idx.addTLSRefs(&cert)
	}
}

func (idx *referenceIndex) addTLS(tls *ir.TLSConfig) {
	if tls == nil {
		return
	}
	idx.addCA(tls.CACertificate)
	for i := range tls.Certificates {
		idx.addTLSRefs(&tls.Certificates[i])
	}
	for i := range tls.ClientCertificates {
		idx.addTLSRefs(&tls.ClientCertificates[i])
	}
}

func (idx *referenceIndex) addTLSRefs(cert *ir.TLSCertificate) {
	if cert != nil && cert.ExtensionRef != nil && cert.ExtensionRef.Name != "" {
		// Extension refs are covered by the unsupported scan; nothing to count.
	}
}

func (idx *referenceIndex) addCA(ca *ir.TLSCACertificate) {
	if ca != nil && ca.Digest != "" {
		idx.caDigests[ca.Digest]++
	}
}

// sweepOrphans removes standalone registry entries that have no live
// reference in x. It is the single reclamation entry point: a definition is
// only ever removed here, and only after a whole-IR reference count proves it
// is unreferenced, so dangling references cannot be introduced. The sweep
// iterates to a fixed point because removing one registry entry (for example
// a BackendCluster carrying a TLS CA digest) can make another entry (the CA
// bundle) orphan in turn.
func sweepOrphans(x *ir.Xds) []string {
	var reclaimed []string
	for {
		idx := buildReferenceIndex(x)
		removed := false

		if len(x.BackendClusters) > 0 {
			kept := x.BackendClusters[:0]
			for _, cluster := range x.BackendClusters {
				if cluster == nil {
					continue
				}
				if idx.backendClusters[cluster.Name] > 0 {
					kept = append(kept, cluster)
				} else {
					reclaimed = append(reclaimed, string(DeletionBackendCluster)+":"+cluster.Name)
					removed = true
				}
			}
			x.BackendClusters = kept
		}

		if len(x.ExtensionBackends) > 0 {
			kept := x.ExtensionBackends[:0]
			for _, backend := range x.ExtensionBackends {
				if backend == nil {
					continue
				}
				if idx.extBackends[backend.Name] > 0 {
					kept = append(kept, backend)
				} else {
					reclaimed = append(reclaimed, string(DeletionExtensionBackend)+":"+backend.Name)
					removed = true
				}
			}
			x.ExtensionBackends = kept
		}

		if len(x.CACertificates) > 0 {
			kept := x.CACertificates[:0]
			for _, entry := range x.CACertificates {
				if entry == nil {
					continue
				}
				if idx.caDigests[entry.Digest] > 0 {
					kept = append(kept, entry)
				} else {
					reclaimed = append(reclaimed, string(DeletionCACertificate)+":"+entry.Digest)
					removed = true
				}
			}
			x.CACertificates = kept
		}

		if !removed {
			return reclaimed
		}
	}
}

// removeHTTPListener returns an independent deep copy without the named
// listener and with its orphaned definitions reclaimed.
func removeHTTPListener(x *ir.Xds, listenerName string) (*ir.Xds, DeletionOp, error) {
	out := x.DeepCopy()
	found := false
	kept := out.HTTP[:0]
	for _, listener := range out.HTTP {
		if listener != nil && listener.Name == listenerName {
			found = true
			continue
		}
		kept = append(kept, listener)
	}
	if !found {
		return nil, DeletionOp{}, fmt.Errorf("http listener %q not found", listenerName)
	}
	out.HTTP = kept
	reclaimed := sweepOrphans(out)
	return out, DeletionOp{Kind: DeletionHTTPListener, Target: listenerName, Reclaimed: reclaimed}, nil
}

// removeRoute returns an independent deep copy without the named route.
// Standalone definitions referenced only by that route (including its mirror
// destinations) become unreferenced and are reclaimed in the same step;
// definitions still referenced elsewhere are retained.
func removeRoute(x *ir.Xds, listenerName, routeName string) (*ir.Xds, DeletionOp, error) {
	out := x.DeepCopy()
	listener := out.GetHTTPListener(listenerName)
	if listener == nil {
		return nil, DeletionOp{}, fmt.Errorf("http listener %q not found", listenerName)
	}
	found := false
	kept := listener.Routes[:0]
	for _, route := range listener.Routes {
		if route != nil && route.Name == routeName {
			found = true
			continue
		}
		kept = append(kept, route)
	}
	if !found {
		return nil, DeletionOp{}, fmt.Errorf("route %q not found in listener %q", routeName, listenerName)
	}
	listener.Routes = kept
	reclaimed := sweepOrphans(out)
	return out, DeletionOp{
		Kind:      DeletionRoute,
		Target:    listenerName + "/" + routeName,
		Reclaimed: reclaimed,
	}, nil
}

// removeFilterEntry removes one extension filter entry from a route. The
// filter groups are the four EnvoyExtensionFeatures slices.
func removeFilterEntry(x *ir.Xds, listenerName, routeName string, group FilterGroup, index int) (*ir.Xds, DeletionOp, error) {
	out := x.DeepCopy()
	listener := out.GetHTTPListener(listenerName)
	if listener == nil {
		return nil, DeletionOp{}, fmt.Errorf("http listener %q not found", listenerName)
	}
	var route *ir.HTTPRoute
	for _, candidate := range listener.Routes {
		if candidate != nil && candidate.Name == routeName {
			route = candidate
			break
		}
	}
	if route == nil || route.EnvoyExtensions == nil {
		return nil, DeletionOp{}, fmt.Errorf("route %q/%q has no extension filters", listenerName, routeName)
	}

	target := ""
	ext := route.EnvoyExtensions
	switch group {
	case FilterGroupExtProcs:
		if index < 0 || index >= len(ext.ExtProcs) {
			return nil, DeletionOp{}, fmt.Errorf("filter index %d out of range for %s", index, group)
		}
		target = ext.ExtProcs[index].Name
		ext.ExtProcs = append(ext.ExtProcs[:index], ext.ExtProcs[index+1:]...)
	case FilterGroupWasms:
		if index < 0 || index >= len(ext.Wasms) {
			return nil, DeletionOp{}, fmt.Errorf("filter index %d out of range for %s", index, group)
		}
		target = ext.Wasms[index].Name
		ext.Wasms = append(ext.Wasms[:index], ext.Wasms[index+1:]...)
	case FilterGroupLuas:
		if index < 0 || index >= len(ext.Luas) {
			return nil, DeletionOp{}, fmt.Errorf("filter index %d out of range for %s", index, group)
		}
		target = ext.Luas[index].Name
		ext.Luas = append(ext.Luas[:index], ext.Luas[index+1:]...)
	case FilterGroupDynamicModules:
		if index < 0 || index >= len(ext.DynamicModules) {
			return nil, DeletionOp{}, fmt.Errorf("filter index %d out of range for %s", index, group)
		}
		target = ext.DynamicModules[index].Name
		ext.DynamicModules = append(ext.DynamicModules[:index], ext.DynamicModules[index+1:]...)
	default:
		return nil, DeletionOp{}, fmt.Errorf("unknown filter group %q", group)
	}
	return out, DeletionOp{
		Kind:   DeletionFilterEntry,
		Target: fmt.Sprintf("%s/%s/%s[%d](%s)", listenerName, routeName, group, index, target),
	}, nil
}

// summarize counts the structural objects participating in the deletion set.
func summarize(x *ir.Xds) CandidateSummary {
	s := CandidateSummary{}
	if x == nil {
		return s
	}
	s.HTTPListeners = len(x.HTTP)
	s.TCPListeners = len(x.TCP)
	s.UDPListeners = len(x.UDP)
	s.BackendClusters = len(x.BackendClusters)
	s.ExtensionBackends = len(x.ExtensionBackends)
	s.CACertificates = len(x.CACertificates)
	for _, listener := range x.HTTP {
		if listener == nil {
			continue
		}
		s.HTTPRoutes += len(listener.Routes)
		for _, route := range listener.Routes {
			if route == nil || route.EnvoyExtensions == nil {
				continue
			}
			s.FilterEntries += len(route.EnvoyExtensions.ExtProcs) +
				len(route.EnvoyExtensions.Wasms) +
				len(route.EnvoyExtensions.Luas) +
				len(route.EnvoyExtensions.DynamicModules)
		}
	}
	return s
}

// unsupportedReasons reports fixed-input dependencies this reducer never
// services offline. A non-empty result means the run must end Unsupported.
func unsupportedReasons(x *ir.Xds) []string {
	var reasons []string
	if x == nil {
		return reasons
	}
	if len(x.ExtensionServerPolicies) > 0 {
		reasons = append(reasons, fmt.Sprintf("extensionServerPolicies (%d entries) require a live extension manager", len(x.ExtensionServerPolicies)))
	}
	if len(x.ExtensionResources) > 0 {
		reasons = append(reasons, fmt.Sprintf("extensionResources registry (%d entries) requires a live extension manager", len(x.ExtensionResources)))
	}
	for _, listener := range x.HTTP {
		if listener == nil {
			continue
		}
		if len(listener.ExtensionRefs) > 0 {
			reasons = append(reasons, fmt.Sprintf("listener %q carries extensionRefs", listener.Name))
		}
		for _, route := range listener.Routes {
			if route == nil {
				continue
			}
			if len(route.ExtensionRefs) > 0 {
				reasons = append(reasons, fmt.Sprintf("route %q carries extensionRefs", route.Name))
			}
			if len(route.ExtensionServerPolicies) > 0 {
				reasons = append(reasons, fmt.Sprintf("route %q carries extensionServerPolicies", route.Name))
			}
		}
	}
	return reasons
}

// secretBearing reports whether the IR contains PrivateBytes secret material
// or CA bundles. It walks the object graph by reflection so newly added
// containers are covered automatically.
func secretBearing(x *ir.Xds) bool {
	if x == nil {
		return false
	}
	seen := make(map[reflect.Value]struct{})
	return walkForSecrets(reflect.ValueOf(x), seen)
}

func walkForSecrets(v reflect.Value, seen map[reflect.Value]struct{}) bool {
	if !v.IsValid() {
		return false
	}
	switch v.Kind() {
	case reflect.Pointer:
		if v.IsNil() {
			return false
		}
		if _, ok := seen[v]; ok {
			return false
		}
		seen[v] = struct{}{}
		return walkForSecrets(v.Elem(), seen)
	case reflect.Interface:
		if v.IsNil() {
			return false
		}
		return walkForSecrets(v.Elem(), seen)
	case reflect.Struct:
		t := v.Type()
		if t.Name() == "CACertificateEntry" || t.Name() == "TLSCACertificate" {
			if field := v.FieldByName("Certificate"); field.IsValid() && field.Len() > 0 {
				return true
			}
		}
		for i := 0; i < t.NumField(); i++ {
			if t.Field(i).PkgPath != "" {
				continue
			}
			if walkForSecrets(v.Field(i), seen) {
				return true
			}
		}
	case reflect.Slice, reflect.Array:
		// PrivateBytes is a named []byte type carrying secret material.
		if v.Type().Elem().Kind() == reflect.Uint8 {
			if v.Type().Name() == "PrivateBytes" && v.Len() > 0 {
				return true
			}
			// Other raw byte slices are only sensitive under the typed
			// containers handled above; plain endpoint bytes are not secrets.
			return false
		}
		for i := 0; i < v.Len(); i++ {
			if walkForSecrets(v.Index(i), seen) {
				return true
			}
		}
	case reflect.Map:
		iter := v.MapRange()
		for iter.Next() {
			if walkForSecrets(iter.Value(), seen) {
				return true
			}
		}
	}
	return false
}
