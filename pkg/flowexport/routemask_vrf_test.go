package flowexport

import (
	"net"
	"testing"
	"time"
)

// #3744 fail-on-revert pins: the route-mask lookup must be scoped to the flow's
// routing table by the INGRESS ifindex (the l3mdev VRF the flow was forwarded
// in), and an UNRESOLVED lookup must be counted rather than silently exported as
// a bogus /0. Before #3744 the resolver was VRF/table-blind (a global-table
// lookup) and discarded the ok bit, so a multi-VRF flow's mask resolved in the
// wrong table and an unresolved lookup was indistinguishable from a real
// default-route /0.

// warmKey resolves key (ip, ifindex) once (cold miss → schedules the background
// populate), waits for the populate to land, and returns the warm result. The
// cache's afterPopulate seam signals completion deterministically without
// depending on wall-clock timing.
func warmKey(t *testing.T, c *routeMaskCache, done <-chan struct{}, ip net.IP, ifindex int) (uint8, bool) {
	t.Helper()
	if m, ok := c.resolve(ip, ifindex); m != 0 || ok {
		t.Fatalf("cold resolve(%v,%d) = %d,%v want 0,false (miss default)", ip, ifindex, m, ok)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("background lookup for (%v,%d) never populated the cache", ip, ifindex)
	}
	return c.resolve(ip, ifindex)
}

// TestRouteMaskLookupScopedByIfindex pins Option A: the SAME destination IP
// resolves to DIFFERENT prefix lengths in different VRF tables (selected by
// ingress ifindex), and the cache keys on (ifindex, IP) so a VRF-A result is
// never served to a VRF-B flow. Reverting to the pre-#3744 IP-only key (or a
// lookup that ignores ifindex) serves VRF-A's mask to the VRF-B resolve → RED.
func TestRouteMaskLookupScopedByIfindex(t *testing.T) {
	const (
		ifVRFA         = 11
		ifVRFB         = 22
		maskVRFA uint8 = 24
		maskVRFB uint8 = 30
	)
	done := make(chan struct{}, 8)
	c := &routeMaskCache{
		ttl:         time.Hour,
		maxInflight: 8,
		entries:     make(map[routeMaskKey]routeMaskEntry),
		pending:     make(map[routeMaskKey]struct{}),
	}
	// Same dst IP, different matched-route prefix length per VRF table. A
	// table-blind lookup (revert) cannot distinguish these.
	c.lookup = func(_ net.IP, ifindex int) (uint8, bool) {
		switch ifindex {
		case ifVRFA:
			return maskVRFA, true
		case ifVRFB:
			return maskVRFB, true
		default:
			return 0, false
		}
	}
	c.afterPopulate = func() { done <- struct{}{} }

	dst := net.IPv4(203, 0, 113, 5)

	if m, ok := warmKey(t, c, done, dst, ifVRFA); m != maskVRFA || !ok {
		t.Fatalf("VRF-A warm resolve = %d,%v want %d,true (ifindex scope dropped)", m, ok, maskVRFA)
	}
	if m, ok := warmKey(t, c, done, dst, ifVRFB); m != maskVRFB || !ok {
		t.Fatalf("VRF-B warm resolve = %d,%v want %d,true (cache key collision across VRFs)", m, ok, maskVRFB)
	}
	// Re-resolving VRF-A must still return VRF-A's mask — the VRF-B populate
	// must not have clobbered it (proves the key includes ifindex).
	if m, ok := c.resolve(dst, ifVRFA); m != maskVRFA || !ok {
		t.Fatalf("VRF-A re-resolve = %d,%v want %d,true (VRF-B populate collided onto VRF-A key)", m, ok, maskVRFA)
	}
}

// TestResolveMasksScopesByIngressInstance pins that resolveMasks scopes BOTH the
// src and dst lookup by the ingress ifindex (inIf), with outIf as the fallback
// only when inIf is 0. Reverting to a table-blind resolveMasks (no ifindex
// argument, or scoping by the wrong interface) changes the ifindex the resolver
// observes → RED.
func TestResolveMasksScopesByIngressInstance(t *testing.T) {
	var seen []int
	r := func(_ net.IP, ifindex int) (uint8, bool) {
		seen = append(seen, ifindex)
		return 24, true
	}
	src := net.IPv4(10, 0, 0, 1)
	dst := net.IPv4(10, 0, 0, 2)

	// inIf set: both halves scoped by inIf, never outIf.
	seen = nil
	resolveMasks(r, src, dst, 7, 9)
	if len(seen) != 2 || seen[0] != 7 || seen[1] != 7 {
		t.Fatalf("with inIf=7 outIf=9, resolver saw ifindexes %v, want [7 7] (ingress-instance scope)", seen)
	}

	// inIf==0: fall back to outIf for both halves (better than the global table).
	seen = nil
	resolveMasks(r, src, dst, 0, 9)
	if len(seen) != 2 || seen[0] != 9 || seen[1] != 9 {
		t.Fatalf("with inIf=0 outIf=9, resolver saw ifindexes %v, want [9 9] (egress fallback)", seen)
	}

	// inIf==0 && outIf==0: unscoped global-table lookup (single-VRF/default).
	seen = nil
	resolveMasks(r, src, dst, 0, 0)
	if len(seen) != 2 || seen[0] != 0 || seen[1] != 0 {
		t.Fatalf("with inIf=0 outIf=0, resolver saw ifindexes %v, want [0 0] (global fallback)", seen)
	}
}

// TestResolveMasksMissCount pins Option B at the helper layer: resolveMasks
// returns the number of halves (0, 1, 2) that did NOT resolve. A revert that
// discards the ok bit reports 0 misses on an unresolved lookup → RED.
func TestResolveMasksMissCount(t *testing.T) {
	src := net.IPv4(10, 0, 0, 1)
	dst := net.IPv4(10, 0, 0, 2)

	// Both resolve → 0 misses (a default-route /0 with ok=true is NOT a miss).
	both := func(_ net.IP, _ int) (uint8, bool) { return 0, true }
	if _, _, m := resolveMasks(both, src, dst, 0, 0); m != 0 {
		t.Fatalf("both-resolve misses = %d, want 0 (default-route /0 is a real resolve)", m)
	}

	// Dst misses only → 1.
	srcOnly := func(ip net.IP, _ int) (uint8, bool) {
		if ip.Equal(src) {
			return 24, true
		}
		return 0, false
	}
	if _, _, m := resolveMasks(srcOnly, src, dst, 0, 0); m != 1 {
		t.Fatalf("one-miss misses = %d, want 1", m)
	}

	// Both miss → 2.
	none := func(_ net.IP, _ int) (uint8, bool) { return 0, false }
	if _, _, m := resolveMasks(none, src, dst, 0, 0); m != 2 {
		t.Fatalf("both-miss misses = %d, want 2", m)
	}
}

// TestExporterRouteMaskUnresolvedCounter pins Option B end-to-end: an unresolved
// lookup increments the exporter's RouteMaskUnresolved counter (the only signal
// that an exported mask-0 is unresolved, not a real default route) while the
// wire field is still exported as 0 (the u8 IE has no sentinel room). Reverting
// the counter leaves RouteMaskUnresolved at 0 for a genuinely unresolved flow.
func TestExporterRouteMaskUnresolvedCounter(t *testing.T) {
	rec, sd := closeRecordForMask(false)

	// Resolver: src resolves (/24), dst is unresolved (no route). One miss.
	partial := func(ip net.IP, _ int) (uint8, bool) {
		if ip.Equal(sd.SrcIP) {
			return testSrcMask, true
		}
		return 0, false
	}

	t.Run("netflow", func(t *testing.T) {
		e := Exporter{exporterCore: exporterCore{MaskResolver: partial}}
		e.ExportSessionClose(rec, sd)
		if got := e.RouteMaskUnresolved(); got != 1 {
			t.Fatalf("RouteMaskUnresolved = %d, want 1 (dst unresolved not counted)", got)
		}
		recs, _ := e.batch.drain()
		if len(recs) != 1 {
			t.Fatalf("drained %d records, want 1", len(recs))
		}
		if recs[0].SrcMask != testSrcMask {
			t.Fatalf("srcMask = %d, want %d (resolved half lost)", recs[0].SrcMask, testSrcMask)
		}
		if recs[0].DstMask != 0 {
			t.Fatalf("dstMask = %d, want 0 (unresolved half must export 0, not a sentinel)", recs[0].DstMask)
		}
	})

	t.Run("ipfix", func(t *testing.T) {
		e := IPFIXExporter{exporterCore: exporterCore{MaskResolver: partial}}
		e.ExportSessionClose(rec, sd)
		if got := e.RouteMaskUnresolved(); got != 1 {
			t.Fatalf("RouteMaskUnresolved = %d, want 1 (dst unresolved not counted)", got)
		}
	})

	t.Run("both-resolved-no-miss", func(t *testing.T) {
		e := Exporter{exporterCore: exporterCore{MaskResolver: maskResolverFor(sd.SrcIP, sd.DstIP)}}
		e.ExportSessionClose(rec, sd)
		if got := e.RouteMaskUnresolved(); got != 0 {
			t.Fatalf("RouteMaskUnresolved = %d, want 0 (both halves resolved)", got)
		}
	})
}
