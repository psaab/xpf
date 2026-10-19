package cluster

import (
	"fmt"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/dataplane"
)

// #15039: a bare delete names no domain, so it must reach every scoped
// entry for its tuple (#14358) — previously by scanning the whole scoped
// generation map, which on the receiver is pinned near its cap by
// tombstones. The tuple index must keep that cost independent of how
// many unrelated entries are held, at both ends, v4 and v6.

func scopedIndexKeyV4(i int) dataplane.SessionKey {
	key := scopedGenKeyV4(uint16(10000 + i%60000))
	key.SrcIP[2] = byte(i >> 16)
	key.SrcIP[3] = byte(i >> 8)
	return key
}

func assertScopedIndexConsistent[K comparable, SK comparable](t *testing.T, name string, m map[SK]uint64, ix *scopedTupleIndex[K, SK], tupleOf func(SK) K) {
	t.Helper()
	indexed := 0
	for tuple, set := range ix.byTuple {
		if len(set) == 0 {
			t.Fatalf("%s index holds an empty set for a tuple", name)
		}
		for skey := range set {
			indexed++
			if _, ok := m[skey]; !ok {
				t.Fatalf("%s index names %v, absent from the scoped map", name, skey)
			}
			if tupleOf(skey) != tuple {
				t.Fatalf("%s index files %v under the wrong tuple", name, skey)
			}
		}
	}
	if indexed != len(m) {
		t.Fatalf("%s index names %d entries, scoped map holds %d", name, indexed, len(m))
	}
}

// Per-delete cost must not grow with held scoped entries. The fills use
// unrelated tuples; the timed bare deletes touch none of them. Pre-fix
// the sender scan alone took ~150us at 1k held entries and ~5ms at 50k
// (measured on the campaign host), so the 2ms budget at 50k fails only
// on the scanning implementation.
func TestBareDeleteCostFlatWithHeldScopedEntries15039(t *testing.T) {
	if testing.Short() {
		t.Skip("timing probe; skipped in -short")
	}
	const (
		fill    = 50000
		deletes = 200
		budget  = 2 * time.Millisecond
	)
	sender := &SessionSync{}
	recv := &SessionSync{}
	recv.sessions = &scopedRecorderStore10512{}
	for i := range fill {
		key := scopedIndexKeyV4(i)
		val := dataplane.SessionValue{RoutingDomain: uint32(7 + i%3)}
		sender.stampInstallGenV4(key, &val)
		if !recv.installClusterSyncedV4(key, dataplane.SessionValue{RoutingDomain: uint32(7 + i%3), Generation: 100}) {
			t.Fatalf("FIXTURE: fill install %d refused", i)
		}
	}
	target := scopedGenKeyV4(1)

	start := time.Now()
	for range deletes {
		_ = sender.takeDeleteGenV4(target)
	}
	if per := time.Since(start) / deletes; per > budget {
		t.Fatalf("sender bare delete = %v at %d held scoped entries, want < %v (full-map scan?)", per, fill, budget)
	}

	start = time.Now()
	for range deletes {
		recv.deleteClusterSyncedV4(target, 150, false)
	}
	if per := time.Since(start) / deletes; per > budget {
		t.Fatalf("receiver bare delete = %v at %d held scoped entries, want < %v (full-map scan?)", per, fill, budget)
	}

	sender.genSentMu.Lock()
	assertScopedIndexConsistent(t, "genSentScopedV4", sender.genSentScopedV4, &sender.genSentScopedByTupleV4, func(sk scopedDeleteKeyV4) dataplane.SessionKey { return sk.Key })
	sender.genSentMu.Unlock()
	recv.recvGenMu.Lock()
	assertScopedIndexConsistent(t, "recvGenScopedV4", recv.recvGenScopedV4, &recv.recvGenScopedByTupleV4, func(sk scopedDeleteKeyV4) dataplane.SessionKey { return sk.Key })
	recv.recvGenMu.Unlock()
}

// The index must track every scoped lifecycle: installs in several
// domains, cap eviction of the oldest tombstone, reclaim-preserving and
// namespace resets, gen-0 eviction, and bare deletes — never naming an
// entry the map no longer holds, and never missing one it does.
func TestScopedTupleIndexTracksLifecycle15039(t *testing.T) {
	// Receiver cap eviction: the evicted oldest tombstone leaves the index.
	s := &SessionSync{}
	s.recvGenGuardCap = 2
	s.genGuardMapCeilingOverride = 2
	k1, k2, k3 := scopedGenKeyV4(5011), scopedGenKeyV4(5012), scopedGenKeyV4(5013)
	s.deleteGenGuardScopedV4(7, k1, 10)
	s.deleteGenGuardScopedV4(7, k2, 20)
	s.deleteGenGuardScopedV4(7, k3, 30)
	s.recvGenMu.Lock()
	assertScopedIndexConsistent(t, "recvGenScopedV4", s.recvGenScopedV4, &s.recvGenScopedByTupleV4, func(sk scopedDeleteKeyV4) dataplane.SessionKey { return sk.Key })
	if _, ok := s.recvGenScopedByTupleV4.byTuple[k1]; ok {
		t.Fatal("cap-evicted tombstone must leave the tuple index")
	}
	s.recvGenMu.Unlock()

	// Reclaim keeps tombstones (and their index entries); a namespace
	// reset drops both. Multi-domain entries for one tuple stay grouped.
	r := &SessionSync{}
	key := scopedGenKeyV4(5020)
	r.recordInstalledGenScopedV4(7, key, 100)
	r.recordInstalledGenScopedV4(8, key, 100)
	if !r.deleteGenGuardV4(key, 150) {
		t.Fatal("FIXTURE: bare delete must apply")
	}
	r.reclaimRecvLiveGen()
	r.recvGenMu.Lock()
	assertScopedIndexConsistent(t, "recvGenScopedV4", r.recvGenScopedV4, &r.recvGenScopedByTupleV4, func(sk scopedDeleteKeyV4) dataplane.SessionKey { return sk.Key })
	if got := len(r.recvGenScopedByTupleV4.byTuple[key]); got != 2 {
		t.Fatalf("reclaim must retain both scoped tombstones in the index, got %d", got)
	}
	r.recvGenMu.Unlock()
	r.resetRecvGen()
	r.recvGenMu.Lock()
	if len(r.recvGenScopedByTupleV4.byTuple) != 0 {
		t.Fatal("namespace reset must clear the tuple index")
	}
	r.recvGenMu.Unlock()

	// Gen-0 bare delete evicts the tuple's scoped entries and index set.
	g := &SessionSync{}
	g.recordInstalledGenScopedV4(7, key, 100)
	g.recordInstalledGenScopedV4(8, key, 100)
	if !g.deleteGenGuardV4(key, 0) {
		t.Fatal("FIXTURE: gen-0 bare delete must apply")
	}
	g.recvGenMu.Lock()
	assertScopedIndexConsistent(t, "recvGenScopedV4", g.recvGenScopedV4, &g.recvGenScopedByTupleV4, func(sk scopedDeleteKeyV4) dataplane.SessionKey { return sk.Key })
	if len(g.recvGenScopedByTupleV4.byTuple) != 0 {
		t.Fatal("gen-0 bare delete must prune the tuple index")
	}
	g.recvGenMu.Unlock()

	// Sender: bare close reclaims only its tuple across domains; scoped
	// take evicts exactly its (domain, tuple); v6 twins likewise.
	snd := &SessionSync{}
	other := scopedGenKeyV4(5030)
	for _, tc := range []struct {
		k dataplane.SessionKey
		d uint32
	}{{key, 7}, {key, 8}, {other, 7}} {
		val := dataplane.SessionValue{RoutingDomain: tc.d}
		snd.stampInstallGenV4(tc.k, &val)
	}
	_ = snd.takeDeleteGenV4(key)
	snd.genSentMu.Lock()
	assertScopedIndexConsistent(t, "genSentScopedV4", snd.genSentScopedV4, &snd.genSentScopedByTupleV4, func(sk scopedDeleteKeyV4) dataplane.SessionKey { return sk.Key })
	if _, ok := snd.genSentScopedByTupleV4.byTuple[key]; ok {
		t.Fatal("bare close must prune its tuple from the sender index")
	}
	snd.genSentMu.Unlock()
	if got := snd.takeDeleteGenScopedV4(7, other); got == 0 {
		t.Fatal("scoped take for the surviving tuple must draw fresh")
	}
	snd.genSentMu.Lock()
	assertScopedIndexConsistent(t, "genSentScopedV4", snd.genSentScopedV4, &snd.genSentScopedByTupleV4, func(sk scopedDeleteKeyV4) dataplane.SessionKey { return sk.Key })
	snd.genSentMu.Unlock()

	snd6 := &SessionSync{}
	key6 := scopedGenKeyV6(5040)
	val6 := dataplane.SessionValueV6{RoutingDomain: 7}
	snd6.stampInstallGenV6(key6, &val6)
	_ = snd6.takeDeleteGenV6(key6)
	snd6.genSentMu.Lock()
	assertScopedIndexConsistent(t, "genSentScopedV6", snd6.genSentScopedV6, &snd6.genSentScopedByTupleV6, func(sk scopedDeleteKeyV6) dataplane.SessionKeyV6 { return sk.Key })
	snd6.genSentMu.Unlock()

	r6 := &SessionSync{}
	r6.recordInstalledGenScopedV6(7, key6, 100)
	if !r6.deleteGenGuardV6(key6, 150) {
		t.Fatal("FIXTURE: v6 bare delete must apply")
	}
	r6.recvGenMu.Lock()
	assertScopedIndexConsistent(t, "recvGenScopedV6", r6.recvGenScopedV6, &r6.recvGenScopedByTupleV6, func(sk scopedDeleteKeyV6) dataplane.SessionKeyV6 { return sk.Key })
	r6.recvGenMu.Unlock()
}

// Benchmark companion to the flat-cost test: per-op cost at increasing
// held-entry counts (report-only; the test above is the gate).
func BenchmarkBareDeleteScopedIndex15039(b *testing.B) {
	for _, n := range []int{1000, 10000, 50000} {
		b.Run(fmt.Sprintf("held=%d", n), func(b *testing.B) {
			sender := &SessionSync{}
			for i := range n {
				val := dataplane.SessionValue{RoutingDomain: uint32(7 + i%3)}
				sender.stampInstallGenV4(scopedIndexKeyV4(i), &val)
			}
			target := scopedGenKeyV4(1)
			b.ResetTimer()
			for range b.N {
				_ = sender.takeDeleteGenV4(target)
			}
		})
	}
}
