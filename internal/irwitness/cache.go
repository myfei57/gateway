// Copyright Envoy Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package irwitness

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"sync"
)

// cacheEntry stores one real evaluation outcome. Only verdicts and reasons are
// cached; translated tables and IR bytes never enter the cache.
type cacheEntry struct {
	verdict Verdict
	reason  string
}

// cacheKey binds the three inputs that determine an evaluation result: the
// fixed translation options, the predicate semantics and the canonical source
// digest. Different IR content always yields a different source digest
// because the canonical walker preserves order, nil/empty and sharing.
type cacheKey struct {
	optionsDigest   string
	predicateDigest string
	sourceDigest    string
}

func (k cacheKey) String() string {
	h := sha256.New()
	h.Write([]byte("opts="))
	h.Write([]byte(k.optionsDigest))
	h.Write([]byte("|pred="))
	h.Write([]byte(k.predicateDigest))
	h.Write([]byte("|src="))
	h.Write([]byte(k.sourceDigest))
	return hex.EncodeToString(h.Sum(nil))
}

// evalCache is a per-run verdict cache. It is safe for concurrent use although
// the reducer itself drives evaluations sequentially.
type evalCache struct {
	mu      sync.Mutex
	entries map[string]cacheEntry
	hits    int
}

func newEvalCache() *evalCache {
	return &evalCache{entries: make(map[string]cacheEntry)}
}

func (c *evalCache) get(key cacheKey) (cacheEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[key.String()]
	if ok {
		c.hits++
	}
	return entry, ok
}

func (c *evalCache) put(key cacheKey, entry cacheEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[key.String()] = entry
}

func (c *evalCache) hitCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.hits
}

// optionsDigest canonicalizes exactly the translation-relevant option fields.
// It deliberately excludes run-control fields (budgets, timeouts, feature
// toggles for deletion scope) which do not change Translate output.
func optionsDigest(opts Options) string {
	type translatable struct {
		ControllerNamespace       string
		ProxyInfraName            string
		ProxyInfraNamespace       string
		GlobalRateLimitServiceURL string
		GlobalRateLimitTimeout    int64
		GlobalRateLimitFailClosed bool
		FilterOrder               any
		RuntimeFlags              any
	}
	return canonicalDigest(translatable{
		ControllerNamespace:       opts.ControllerNamespace,
		ProxyInfraName:            opts.ProxyInfraName,
		ProxyInfraNamespace:       opts.ProxyInfraNamespace,
		GlobalRateLimitServiceURL: opts.GlobalRateLimitServiceURL,
		GlobalRateLimitTimeout:    int64(opts.GlobalRateLimitTimeout),
		GlobalRateLimitFailClosed: opts.GlobalRateLimitFailClosed,
		FilterOrder:               opts.FilterOrder,
		RuntimeFlags:              opts.RuntimeFlags,
	})
}

// joinReasons renders a stable, secret-free reason string.
func joinReasons(reasons []string) string {
	return strings.Join(reasons, "; ")
}
