package userspace

// #16172 allocation guard for the collapsed session-sync builders.
//
// Baselines measured on the pre-collapse twins at 24f2c40e5e with the
// benchmark harness below (key+value hoisted outside the loop, request
// consumed via a package-level sink — see "Harness shape"):
//
//	BenchmarkBuildSessionSyncRequestV4Upsert16172          80 B/op  6 allocs/op
//	BenchmarkBuildSessionSyncRequestV6Upsert16172          64 B/op  4 allocs/op
//	BenchmarkBuildSessionSyncRequestV4ScopedDelete16172    16 B/op  2 allocs/op
//	BenchmarkBuildSessionSyncRequestV6ScopedDelete16172    32 B/op  2 allocs/op
//
// The borrowed-view head reproduces all four numbers exactly. The first
// collapsed shape (682c6337, a view RETURNED BY VALUE holding net.IP
// slices into the caller's key/value) measured 352/432 B/op and 8/6
// allocs/op on the upserts under a caller-local harness — it moved
// both keys, and the caller's V6 value, to the heap. That is the shape
// this guard exists to keep out: do not raise the ceilings to fit a
// regression.
//
// Two production-shape notes the guard encodes:
//   - The upsert benchmarks call buildSessionSyncRequest{V4,V6}, the
//     exact entry points syncSessionV{4,6}Locked calls.
//   - The scoped-delete benchmarks call
//     buildSessionSyncScopedDelete{V4,V6} with a raw domain — the exact
//     form manager_sessions.go's delete paths now take. (The twins'
//     delete path went through buildSessionSyncRequest{V4,V6} with a
//     domain-only value; the scoped wrappers reproduce its cost and
//     bytes exactly, without the view's key escape.)
//
// Harness shape: production callers receive key BY VALUE from their
// own callers and pass &val onward; neither is born inside the builder
// call. Hoisting key+value out of the loop reproduces that escape
// environment. Creating them INSIDE the loop additionally charges the
// builder for the caller's stack-to-result copies (~256 B for
// SessionValue{V6}), which the twins pay too — it is not a builder
// cost, and it masks the view's escapes, so it is not used.

import (
	"runtime"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

var benchSink16172 SessionSyncRequest

func benchV4Key16172() dataplane.SessionKey {
	return dataplane.SessionKey{SrcIP: [4]byte{10, 0, 0, 1}, DstIP: [4]byte{10, 0, 0, 2}, SrcPort: hostToNetwork16(1234), DstPort: hostToNetwork16(80), Protocol: 6}
}

func benchV6Key16172() dataplane.SessionKeyV6 {
	return dataplane.SessionKeyV6{SrcIP: ip16("2001:db8::1"), DstIP: ip16("2001:db8::2"), SrcPort: hostToNetwork16(1234), DstPort: hostToNetwork16(80), Protocol: 6}
}

func benchV4Val16172() dataplane.SessionValue {
	return dataplane.SessionValue{IngressZone: 1, EgressZone: 2, FibIfindex: 6, FibVlanID: 80, Flags: dataplane.SessFlagSNAT | dataplane.SessFlagDNAT, NATSrcIP: natU32("10.0.61.1"), NATDstIP: natU32("10.0.61.102"), NATSrcPort: hostToNetwork16(40000), NATDstPort: hostToNetwork16(8443)}
}

func benchV6Val16172() dataplane.SessionValueV6 {
	return dataplane.SessionValueV6{IngressZone: 1, EgressZone: 2, FibIfindex: 6, FibVlanID: 80, Flags: dataplane.SessFlagSNAT | dataplane.SessFlagDNAT, NATSrcIP: ip16("2001:db8:61::1"), NATDstIP: ip16("2001:db8:61::102"), NATSrcPort: hostToNetwork16(40000), NATDstPort: hostToNetwork16(8443)}
}

func BenchmarkBuildSessionSyncRequestV4Upsert16172(b *testing.B) {
	m := goldenManager16172()
	key := benchV4Key16172()
	val := benchV4Val16172()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchSink16172 = m.buildSessionSyncRequestV4("upsert", key, &val)
	}
}

func BenchmarkBuildSessionSyncRequestV6Upsert16172(b *testing.B) {
	m := goldenManager16172()
	key := benchV6Key16172()
	val := benchV6Val16172()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchSink16172 = m.buildSessionSyncRequestV6("upsert", key, &val)
	}
}

func BenchmarkBuildSessionSyncRequestV4ScopedDelete16172(b *testing.B) {
	m := goldenManager16172()
	key := benchV4Key16172()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchSink16172 = m.buildSessionSyncScopedDeleteV4("mirror_delete", key, 100007)
	}
}

func BenchmarkBuildSessionSyncRequestV6ScopedDelete16172(b *testing.B) {
	m := goldenManager16172()
	key := benchV6Key16172()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchSink16172 = m.buildSessionSyncScopedDeleteV6("mirror_delete", key, 100008)
	}
}

// allocBytes16172 measures allocs and allocated BYTES for n calls with
// a MemStats delta (testing.AllocsPerRun reports counts only). The GC
// is forced before and after so live-object noise cannot hide bytes.
func allocBytes16172(n int, run func()) (allocsPerOp, bytesPerOp uint64) {
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for i := 0; i < n; i++ {
		run()
	}
	runtime.ReadMemStats(&after)
	return (after.Mallocs - before.Mallocs) / uint64(n), (after.TotalAlloc - before.TotalAlloc) / uint64(n)
}

// TestSessionSyncAllocations16172 is the in-suite guard: both families,
// upsert AND scoped delete, count AND bytes, against the pre-collapse
// twin baselines in the header. The previous V4-only count guard
// (<=8 against a 6 baseline) passed the heap-owning view; this one
// would have caught it on every row.
func TestSessionSyncAllocations16172(t *testing.T) {
	m := goldenManager16172()
	// Inputs are built ONCE, outside the measured closure — the same
	// hoisting the benchmarks use. Building them inside would charge
	// the builder for the caller's stack-to-result copies.
	key4, val4 := benchV4Key16172(), benchV4Val16172()
	key6, val6 := benchV6Key16172(), benchV6Val16172()
	cases := []struct {
		name      string
		maxAllocs uint64
		maxBytes  uint64
		run       func()
	}{
		{"v4_upsert", 6, 80, func() {
			benchSink16172 = m.buildSessionSyncRequestV4("upsert", key4, &val4)
		}},
		{"v6_upsert", 4, 64, func() {
			benchSink16172 = m.buildSessionSyncRequestV6("upsert", key6, &val6)
		}},
		{"v4_scoped_delete", 2, 16, func() {
			benchSink16172 = m.buildSessionSyncScopedDeleteV4("mirror_delete", key4, 100007)
		}},
		{"v6_scoped_delete", 2, 32, func() {
			benchSink16172 = m.buildSessionSyncScopedDeleteV6("mirror_delete", key6, 100008)
		}},
	}
	for _, tc := range cases {
		allocs, bytes := allocBytes16172(200, tc.run)
		if allocs > tc.maxAllocs || bytes > tc.maxBytes {
			t.Fatalf("%s: %d allocs/op, %d B/op; want <= %d allocs/op, <= %d B/op (pre-collapse twin baseline — a heap-owning view regresses both; see file header)",
				tc.name, allocs, bytes, tc.maxAllocs, tc.maxBytes)
		}
	}
}
