package flowexport

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/logging"
)

// #2866 fail-on-revert pins: NetFlow v9 srcMask (IE 9) / dstMask (IE 13) and
// the IPFIX sourceIPv4PrefixLength (IE 9) / destinationIPv4PrefixLength (IE 13)
// — plus the IPv6 variants IE 29 / IE 30 — must carry the FIB longest-prefix-
// match prefix length of the flow's source/destination route, NOT the
// always-zero value they had before this change.
//
// Before #2866 the templates advertised (NetFlow) / never advertised (IPFIX)
// the mask fields and the encoder wrote FlowRecord.SrcMask/DstMask, but those
// members were never assigned in ExportSessionClose, so every flow exported a
// /0 mask. These tests inject a deterministic MaskResolver (no kernel FIB
// dependency) and assert:
//   - the FlowRecord built by ExportSessionClose carries the resolved masks;
//   - the encoded record carries the masks at the template's field offset.
// Reverting the SessionCloseData->FlowRecord mask population, the template
// field, or the encoder write flips one of these RED.

// Sentinel non-default prefix lengths so a reverted (always-0) population is
// detectable — a real /0 default route would falsely pass an "is it non-zero"
// check, so the resolver returns distinct non-zero values keyed by address.
const (
	testSrcMask uint8 = 24
	testDstMask uint8 = 30
)

// maskResolverFor returns a MaskResolver that maps the test src IP -> testSrcMask
// and the test dst IP -> testDstMask, mirroring a FIB that has a /24 covering
// the source and a /30 covering the destination.
func maskResolverFor(srcIP, dstIP net.IP) MaskResolver {
	return func(ip net.IP, _ int) (uint8, bool) {
		switch {
		case ip.Equal(srcIP):
			return testSrcMask, true
		case ip.Equal(dstIP):
			return testDstMask, true
		default:
			return 0, false
		}
	}
}

func closeRecordForMask(v6 bool) (logging.EventRecord, SessionCloseData) {
	rec := logging.EventRecord{
		Type:         "SESSION_CLOSE",
		Time:         time.Unix(1_700_000_100, 0),
		Created:      1_700_000_000,
		SessionPkts:  0x1122334455667788,
		SessionBytes: 0x99AABBCCDDEEFF00,
	}
	sd := SessionCloseData{SrcPort: 40000, DstPort: 80, Protocol: 6, IsIPv6: v6}
	if v6 {
		sd.SrcIP = net.ParseIP("fd00::1")
		sd.DstIP = net.ParseIP("2001:db8::200")
	} else {
		sd.SrcIP = net.IPv4(10, 0, 1, 100)
		sd.DstIP = net.IPv4(172, 16, 80, 200)
	}
	return rec, sd
}

// TestNetflowSrcDstMaskPopulated pins the NetFlow v9 mask fields.
func TestNetflowSrcDstMaskPopulated(t *testing.T) {
	boot := time.Unix(1_700_000_000, 0)
	opts := DefaultV9TemplateOptions()
	for _, tc := range []struct {
		name         string
		v6           bool
		fields       []templateField
		srcIE, dstIE uint16
	}{
		{"v4", false, netflowTemplateFieldsV4, fieldSrcMask, fieldDstMask},
		{"v6", true, netflowTemplateFieldsV6, fieldIPv6SrcMask, fieldIPv6DstMask},
	} {
		rec, sd := closeRecordForMask(tc.v6)

		srcOff, ok := netflowFieldBodyOffset(tc.fields, tc.srcIE)
		if !ok {
			t.Fatalf("%s: template missing srcMask IE %d", tc.name, tc.srcIE)
		}
		dstOff, ok := netflowFieldBodyOffset(tc.fields, tc.dstIE)
		if !ok {
			t.Fatalf("%s: template missing dstMask IE %d", tc.name, tc.dstIE)
		}

		e := Exporter{exporterCore: exporterCore{MaskResolver: maskResolverFor(sd.SrcIP, sd.DstIP)}}
		e.ExportSessionClose(rec, sd)
		v4recs, v6recs := e.batch.drain()
		recs := v4recs
		if tc.v6 {
			recs = v6recs
		}
		if len(recs) != 1 {
			t.Fatalf("%s: drained %d records, want 1", tc.name, len(recs))
		}
		if recs[0].SrcMask != testSrcMask || recs[0].DstMask != testDstMask {
			t.Fatalf("%s: FlowRecord masks = src %d/dst %d, want %d/%d (population reverted)",
				tc.name, recs[0].SrcMask, recs[0].DstMask, testSrcMask, testDstMask)
		}

		fs := encodeDataFlowSet(recs, boot, opts)
		// 4-byte set header precedes the record body.
		if got := fs[4+srcOff]; got != testSrcMask {
			t.Fatalf("%s: encoded srcMask = %d, want %d (encoder write reverted)", tc.name, got, testSrcMask)
		}
		if got := fs[4+dstOff]; got != testDstMask {
			t.Fatalf("%s: encoded dstMask = %d, want %d (encoder write reverted)", tc.name, got, testDstMask)
		}
	}
}

// TestIPFIXSrcDstMaskPopulated mirrors the check for IPFIX.
func TestIPFIXSrcDstMaskPopulated(t *testing.T) {
	for _, tc := range []struct {
		name         string
		v6           bool
		fields       []ipfixField
		srcIE, dstIE uint16
	}{
		{"v4", false, ipfixTemplateV4, ipfixSourceIPv4PrefixLength, ipfixDestIPv4PrefixLength},
		{"v6", true, ipfixTemplateV6, ipfixSourceIPv6PrefixLength, ipfixDestIPv6PrefixLength},
	} {
		rec, sd := closeRecordForMask(tc.v6)

		srcOff, ok := ipfixFieldBodyOffset(tc.fields, tc.srcIE)
		if !ok {
			t.Fatalf("%s: template missing srcMask IE %d", tc.name, tc.srcIE)
		}
		dstOff, ok := ipfixFieldBodyOffset(tc.fields, tc.dstIE)
		if !ok {
			t.Fatalf("%s: template missing dstMask IE %d", tc.name, tc.dstIE)
		}

		e := IPFIXExporter{exporterCore: exporterCore{MaskResolver: maskResolverFor(sd.SrcIP, sd.DstIP)}}
		e.ExportSessionClose(rec, sd)
		v4recs, v6recs := e.batch.drain()
		recs := v4recs
		if tc.v6 {
			recs = v6recs
		}
		if len(recs) != 1 {
			t.Fatalf("%s: drained %d records, want 1", tc.name, len(recs))
		}
		if recs[0].SrcMask != testSrcMask || recs[0].DstMask != testDstMask {
			t.Fatalf("%s: FlowRecord masks = src %d/dst %d, want %d/%d (population reverted)",
				tc.name, recs[0].SrcMask, recs[0].DstMask, testSrcMask, testDstMask)
		}

		ds := encodeIPFIXDataSet(recs)
		if got := ds[4+srcOff]; got != testSrcMask {
			t.Fatalf("%s: encoded srcMask = %d, want %d (encoder write reverted)", tc.name, got, testSrcMask)
		}
		if got := ds[4+dstOff]; got != testDstMask {
			t.Fatalf("%s: encoded dstMask = %d, want %d (encoder write reverted)", tc.name, got, testDstMask)
		}
	}
}

// TestRouteMaskResolveMissDoesNotLookupSynchronously is the #3743 fail-on-
// revert pin at the cache layer: resolve() runs inside the EventReader
// session-close callback, so a cache MISS must NOT perform the netlink FIB
// lookup on the caller's goroutine. The injected lookup blocks until the test
// releases it; resolve() must still return the default (0,false) immediately.
// Reverting to the pre-#3743 synchronous "lookup inside resolve" makes resolve()
// block on the channel and return the lookup's sentinel (24,true) instead —
// flipping this RED (and, end-to-end, blocking the whole callback path, which
// TestExportSessionCloseDoesNotBlockOnFIBLookup pins).
func TestRouteMaskResolveMissDoesNotLookupSynchronously(t *testing.T) {
	release := make(chan struct{})
	c := &routeMaskCache{
		ttl:         time.Hour,
		maxInflight: 4,
		entries:     make(map[routeMaskKey]routeMaskEntry),
		pending:     make(map[routeMaskKey]struct{}),
	}
	c.lookup = func(net.IP, int) (uint8, bool) {
		<-release // a synchronous caller would block here
		return 24, true
	}
	got, ok := c.resolve(net.IPv4(192, 0, 2, 1), 0)
	if got != 0 || ok {
		t.Fatalf("cache-miss resolve = %d,%v want 0,false (synchronous netlink on the callback path)", got, ok)
	}
	close(release) // let the scheduled background lookup finish and exit
}

// TestRouteMaskCacheAsyncPopulateAndHit checks the two-phase #3743 behaviour:
// the first resolve to a new prefix misses (returns the default) and schedules
// a background lookup; once that lookup completes, a subsequent resolve HITS
// with the real mask without issuing another syscall. It also verifies a
// default-route /0 is cached as a successful resolve (ok=true), distinct from a
// miss (ok=false).
func TestRouteMaskCacheAsyncPopulateAndHit(t *testing.T) {
	done := make(chan struct{}, 1)
	var mu sync.Mutex
	calls := 0
	c := &routeMaskCache{
		ttl:         time.Hour,
		maxInflight: 4,
		entries:     make(map[routeMaskKey]routeMaskEntry),
		pending:     make(map[routeMaskKey]struct{}),
	}
	c.lookup = func(net.IP, int) (uint8, bool) {
		mu.Lock()
		calls++
		mu.Unlock()
		return 16, true
	}
	c.afterPopulate = func() { done <- struct{}{} }

	ip := net.IPv4(192, 0, 2, 1)
	if m, ok := c.resolve(ip, 0); m != 0 || ok {
		t.Fatalf("first resolve = %d,%v want 0,false (miss default)", m, ok)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("background lookup never populated the cache")
	}
	// Swap the lookup to a sentinel: a genuine cache HIT must not call it.
	c.lookup = func(net.IP, int) (uint8, bool) { mu.Lock(); calls++; mu.Unlock(); return 99, true }
	if m, ok := c.resolve(ip, 0); m != 16 || !ok {
		t.Fatalf("warm resolve = %d,%v want 16,true (cache not populated / hit path broken)", m, ok)
	}
	mu.Lock()
	got := calls
	mu.Unlock()
	if got != 1 {
		t.Fatalf("lookup called %d times, want 1 (hit path issued a syscall)", got)
	}

	// A default-route match (/0) caches as a successful resolve (ok=true).
	c.lookup = func(net.IP, int) (uint8, bool) { return 0, true }
	dip := net.IPv4(203, 0, 113, 1)
	if m, ok := c.resolve(dip, 0); m != 0 || ok {
		t.Fatalf("default-route first resolve = %d,%v want 0,false (miss default)", m, ok)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("default-route background lookup never populated the cache")
	}
	if m, ok := c.resolve(dip, 0); m != 0 || !ok {
		t.Fatalf("default-route warm resolve = %d,%v want 0,true (default route not cached as a hit)", m, ok)
	}

	// nil IP -> miss without scheduling a lookup.
	if m, ok := c.resolve(nil, 0); m != 0 || ok {
		t.Fatalf("nil IP resolve = %d,%v want 0,false", m, ok)
	}
}

// TestExportSessionCloseDoesNotBlockOnFIBLookup is the #3743 end-to-end pin:
// ExportSessionClose is invoked from the EventReader session-close callback, so
// it must never block on the route-mask FIB lookup. The exporter is wired to a
// routeMaskCache whose FIB lookup blocks until released; ExportSessionClose must
// return promptly regardless. Reverting resolve() to a synchronous lookup makes
// ExportSessionClose block on the netlink round-trip -> this test times out RED.
func TestExportSessionCloseDoesNotBlockOnFIBLookup(t *testing.T) {
	release := make(chan struct{})
	c := &routeMaskCache{
		ttl:         time.Hour,
		maxInflight: 8,
		entries:     make(map[routeMaskKey]routeMaskEntry),
		pending:     make(map[routeMaskKey]struct{}),
	}
	c.lookup = func(net.IP, int) (uint8, bool) {
		<-release
		return 24, true
	}
	e := Exporter{exporterCore: exporterCore{MaskResolver: c.resolve}}
	rec, sd := closeRecordForMask(false)

	done := make(chan struct{})
	go func() {
		e.ExportSessionClose(rec, sd)
		close(done)
	}()
	select {
	case <-done:
		// good: returned without waiting for the blocked FIB lookup.
	case <-time.After(2 * time.Second):
		close(release)
		t.Fatal("ExportSessionClose blocked on the synchronous FIB lookup (netlink on the callback path)")
	}
	close(release) // let the background lookups finish and exit
}

// TestRouteMaskCacheBounded is a fail-on-revert pin for the cache size bound.
// Inserting many more distinct keys than the cap must NOT grow the map without
// bound — len(entries) stays <= maxSize. Reverting evictLocked (the unbounded
// map[key]=val of the original #2866 implementation) lets the map grow to the
// full insert count and flips this RED. A within-TTL repeated key still hits
// the cache (no extra lookup), so the bound does not break the hit path.
func TestRouteMaskCacheBounded(t *testing.T) {
	const maxSize = 64
	c := &routeMaskCache{
		ttl:     time.Hour, // long TTL: entries never expire during the test,
		maxSize: maxSize,   // so the bound is enforced purely by the size cap.
		entries: make(map[routeMaskKey]routeMaskEntry),
	}
	// storeLocked is the map-insert path the background populate goroutine uses
	// (#3743). Drive it directly so the size bound is exercised deterministically
	// without goroutines/timing.
	insert := func(ip net.IP) {
		c.mu.Lock()
		c.storeLocked(routeMaskKey{ip: string(ip.To16())}, 24, true, time.Now())
		c.mu.Unlock()
	}

	// Insert far more distinct keys than the cap. Each is a fresh IPv4 address.
	const inserts = maxSize * 10
	for i := 0; i < inserts; i++ {
		ip := net.IPv4(10, byte(i>>16), byte(i>>8), byte(i))
		insert(ip)
		if got := len(c.entries); got > maxSize {
			t.Fatalf("after %d inserts len(entries) = %d, want <= %d (cache unbounded — leak)",
				i+1, got, maxSize)
		}
	}

	// A freshly inserted key within TTL must still resolve from the cache (the
	// hit path returns it without a lookup), even after the churn above.
	ip := net.IPv4(192, 0, 2, 7)
	insert(ip)
	if m, ok := c.resolve(ip, 0); m != 24 || !ok {
		t.Fatalf("warm resolve = %d,%v want 24,true (hit path broken)", m, ok)
	}
	if len(c.entries) > maxSize {
		t.Fatalf("final len(entries) = %d, want <= %d", len(c.entries), maxSize)
	}
}

// TestRouteMaskCacheEvictsExpiredFirst checks that at the cap the bound first
// drops expired entries (recovering headroom) before resorting to a full clear,
// so a steady cache of live entries below the cap is not needlessly wiped.
func TestRouteMaskCacheEvictsExpiredFirst(t *testing.T) {
	const maxSize = 4
	c := &routeMaskCache{
		ttl:     time.Hour,
		maxSize: maxSize,
		entries: make(map[routeMaskKey]routeMaskEntry),
	}
	c.lookup = func(net.IP, int) (uint8, bool) { return 16, true }

	past := time.Now().Add(-time.Hour)
	// Fill to the cap: 1 live entry + (maxSize-1) already-expired entries.
	live := net.IPv4(10, 0, 0, 1)
	c.entries[routeMaskKey{ip: string(live.To16())}] = routeMaskEntry{mask: 16, ok: true, expires: time.Now().Add(time.Hour)}
	for i := 0; i < maxSize-1; i++ {
		ip := net.IPv4(10, 0, 1, byte(i))
		c.entries[routeMaskKey{ip: string(ip.To16())}] = routeMaskEntry{mask: 16, ok: true, expires: past}
	}
	if len(c.entries) != maxSize {
		t.Fatalf("setup len = %d, want %d", len(c.entries), maxSize)
	}

	// A new key at the cap should purge the expired entries (not clear the
	// whole map), leaving the live entry + the newcomer. Drive storeLocked
	// directly — the background populate path (#3743) that would call it.
	newIP := net.IPv4(203, 0, 113, 9)
	c.mu.Lock()
	c.storeLocked(routeMaskKey{ip: string(newIP.To16())}, 16, true, time.Now())
	c.mu.Unlock()
	if _, ok := c.entries[routeMaskKey{ip: string(live.To16())}]; !ok {
		t.Fatalf("live entry was wiped — expired-first purge did not run")
	}
	if len(c.entries) > maxSize {
		t.Fatalf("len after purge = %d, want <= %d", len(c.entries), maxSize)
	}
}

// TestResolveMasksNilResolver pins the pre-#2866 fallback: a zero-value
// exporter (nil resolver) leaves both masks 0 and reports 0 misses — the
// feature is simply off, not "unresolved".
func TestResolveMasksNilResolver(t *testing.T) {
	s, d, misses := resolveMasks(nil, net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 2), 0, 0)
	if s != 0 || d != 0 {
		t.Fatalf("nil resolver masks = %d/%d, want 0/0", s, d)
	}
	if misses != 0 {
		t.Fatalf("nil resolver misses = %d, want 0 (feature off, not a miss)", misses)
	}
}
