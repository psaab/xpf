// #5250 (A9 F3): the route-mask cache was built per EXPORTER, and both
// production call sites (NewExporter / newIPFIXExporter) run on the
// flow-export reconcile path — i.e. once per commit. Each generation
// therefore spawned its own background RTM_GETROUTE goroutines with its own
// in-flight ceiling, which outlived the exporter that scheduled them (the
// cache type has no Stop hook and netlink offers no cancellation), and each
// generation restarted from a cold cache, re-paying lookups the previous one
// had already made. The default-TTL cache is now a process singleton, so the
// background work is bounded process-wide and survives a reconcile.
//
// FAIL-ON-REVERT: go back to constructing a fresh cache per call and the
// pointer-identity assertion goes RED.
package flowexport

import (
	"testing"
	"time"
)

func TestRouteMaskCacheIsProcessSingleton_5250(t *testing.T) {
	a := routeMaskCacheFor(0)
	b := routeMaskCacheFor(0)
	if a == nil || b == nil {
		t.Fatal("routeMaskCacheFor returned nil")
	}
	if a != b {
		t.Fatal("two default-TTL resolvers use DIFFERENT cache instances — each exporter generation re-spawns its own uncancellable background lookups and starts cold")
	}
	if a.ttl != defaultRouteMaskTTL {
		t.Fatalf("shared cache ttl = %v, want %v", a.ttl, defaultRouteMaskTTL)
	}
	// The explicit default TTL resolves to the same instance as ttl<=0.
	if c := routeMaskCacheFor(defaultRouteMaskTTL); c != a {
		t.Fatal("an explicit default TTL must reuse the shared instance")
	}
	// A caller asking for different freshness still gets its own instance.
	other := routeMaskCacheFor(2 * time.Second)
	if other == a {
		t.Fatal("a non-default TTL must NOT alias the shared default-TTL cache")
	}
	if other.ttl != 2*time.Second {
		t.Fatalf("dedicated cache ttl = %v, want 2s", other.ttl)
	}
	// The public constructor is wired to the same instance.
	if got := NewRouteMaskResolver(0); got == nil {
		t.Fatal("NewRouteMaskResolver(0) = nil")
	}
	// Sanity: the shared cache is usable (maps initialized, no nil-map panic).
	if _, ok := a.resolve(nil, 0); ok {
		t.Fatal("resolve(nil, 0) reported a resolved mask")
	}
}
