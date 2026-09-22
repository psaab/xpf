package cluster

import (
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

func scopedGenKeyV4(port uint16) dataplane.SessionKey {
	return dataplane.SessionKey{
		SrcIP: [4]byte{10, 0, 0, 1}, DstIP: [4]byte{10, 0, 0, 2},
		Protocol: 6, SrcPort: port, DstPort: 80,
	}
}

func scopedGenKeyV6(port uint16) dataplane.SessionKeyV6 {
	k := dataplane.SessionKeyV6{Protocol: 6, SrcPort: port, DstPort: 80}
	k.SrcIP[15] = 1
	k.DstIP[15] = 2
	return k
}

// Scoped takes draw fresh from the global counter (always out-ranks) and
// never touch bare sender stamps.
func TestTakeDeleteGenScopedDrawsFresh10512(t *testing.T) {
	s := &SessionSync{}
	key := scopedGenKeyV4(5001)
	g1 := s.takeDeleteGenScopedV4(7, key)
	g2 := s.takeDeleteGenScopedV4(8, key)
	g3 := s.takeDeleteGenScopedV6(7, scopedGenKeyV6(5001))
	if g1 == 0 || g2 <= g1 || g3 <= g2 {
		t.Fatalf("scoped takes must draw fresh monotonic gens, got %d %d %d", g1, g2, g3)
	}
	s.genSentMu.Lock()
	defer s.genSentMu.Unlock()
	if len(s.genSentV4) != 0 || len(s.genSentV6) != 0 {
		t.Fatal("scoped takes must not disturb bare sender stamps")
	}
}

// Scoped guard ordering: refuse older, accept newer, tombstone; domains
// Sharing a tuple order independently (the colliding-tenants property).
func TestDeleteGenGuardScopedOrdersPerDomain10512(t *testing.T) {
	s := &SessionSync{}
	key := scopedGenKeyV4(5002)
	if !s.deleteGenGuardScopedV4(7, key, 100) {
		t.Fatal("first scoped delete must apply")
	}
	if s.deleteGenGuardScopedV4(7, key, 50) {
		t.Fatal("older scoped delete must be refused")
	}
	if !s.deleteGenGuardScopedV4(7, key, 150) {
		t.Fatal("newer scoped delete must apply")
	}
	if !s.deleteGenGuardScopedV4(8, key, 50) {
		t.Fatal("a colliding domain must order independently of domain 7's tombstone")
	}
	s.recvGenMu.Lock()
	defer s.recvGenMu.Unlock()
	if got := s.recvGenScopedV4[scopedDeleteKeyV4{Domain: 7, Key: key}]; got != 150 {
		t.Fatalf("scoped tombstone = %d, want 150", got)
	}
	if got := s.recvGenScopedV4[scopedDeleteKeyV4{Domain: 8, Key: key}]; got != 50 {
		t.Fatalf("colliding tombstone = %d, want 50", got)
	}
}

// Gen-0 scoped delete evicts (mirror of #9719 bare semantics).
func TestDeleteGenGuardScopedZeroEvicts10512(t *testing.T) {
	s := &SessionSync{}
	key := scopedGenKeyV4(5003)
	if !s.deleteGenGuardScopedV4(7, key, 100) {
		t.Fatal("FIXTURE: scoped delete must apply")
	}
	if !s.deleteGenGuardScopedV4(7, key, 0) {
		t.Fatal("gen-0 scoped delete must apply")
	}
	s.recvGenMu.Lock()
	defer s.recvGenMu.Unlock()
	if _, ok := s.recvGenScopedV4[scopedDeleteKeyV4{Domain: 7, Key: key}]; ok {
		t.Fatal("gen-0 scoped delete must evict the entry")
	}
}

// Migration pin (plan §1.2): bare and scoped spaces are fully separate
// in BOTH directions — neither is ever authoritative for the other.
func TestScopedGenSpaceIndependentFromBare10512(t *testing.T) {
	key := scopedGenKeyV4(5004)
	s := &SessionSync{}
	if !s.deleteGenGuardV4(key, 100) {
		t.Fatal("FIXTURE: bare delete must apply")
	}
	if !s.deleteGenGuardScopedV4(7, key, 50) {
		t.Fatal("a bare tombstone must never gate a scoped delete")
	}
	s2 := &SessionSync{}
	if !s2.deleteGenGuardScopedV4(7, key, 200) {
		t.Fatal("FIXTURE: scoped delete must apply")
	}
	if !s2.deleteGenGuardV4(key, 50) {
		t.Fatal("a scoped tombstone must never gate a bare delete (legacy preserved)")
	}
}

// Reset inclusion: reclaim preserves scoped tombstones; namespace reset
// clears them.
func TestScopedGenResetPreserveAndClear10512(t *testing.T) {
	s := &SessionSync{}
	key := scopedGenKeyV4(5005)
	skey := scopedDeleteKeyV4{Domain: 7, Key: key}
	if !s.deleteGenGuardScopedV4(7, key, 100) {
		t.Fatal("FIXTURE: scoped delete must apply")
	}
	s.reclaimRecvLiveGen()
	s.recvGenMu.Lock()
	_, kept := s.recvGenScopedV4[skey]
	s.recvGenMu.Unlock()
	if !kept {
		t.Fatal("reclaim must retain scoped tombstones")
	}
	s.resetRecvGen()
	s.recvGenMu.Lock()
	_, kept = s.recvGenScopedV4[skey]
	s.recvGenMu.Unlock()
	if kept {
		t.Fatal("namespace reset must clear scoped tombstones")
	}
}

// Cap bound: a new scoped key at the cap evicts the oldest scoped
// tombstone (same #9719 machinery as the bare spaces).
func TestScopedGenCapEvictsOldestTombstone10512(t *testing.T) {
	s := &SessionSync{}
	s.recvGenGuardCap = 2
	s.genGuardMapCeilingOverride = 2
	k1, k2, k3 := scopedGenKeyV4(5011), scopedGenKeyV4(5012), scopedGenKeyV4(5013)
	s.deleteGenGuardScopedV4(7, k1, 10)
	s.deleteGenGuardScopedV4(7, k2, 20)
	s.deleteGenGuardScopedV4(7, k3, 30)
	s.recvGenMu.Lock()
	_, k1kept := s.recvGenScopedV4[scopedDeleteKeyV4{Domain: 7, Key: k1}]
	n := len(s.recvGenScopedV4)
	s.recvGenMu.Unlock()
	if k1kept || n != 2 {
		t.Fatalf("oldest scoped tombstone must evict at cap (k1 kept=%v size=%d)", k1kept, n)
	}
	if got := s.stats.GenTombstonesEvicted.Load(); got != 1 {
		t.Fatalf("GenTombstonesEvicted = %d, want 1", got)
	}
}

// V6 twin: fresh takes + guard ordering on the scoped v6 space.
func TestDeleteGenScopedV6Orders10512(t *testing.T) {
	s := &SessionSync{}
	key := scopedGenKeyV6(5006)
	if s.takeDeleteGenScopedV6(7, key) == 0 {
		t.Fatal("scoped v6 take must draw fresh")
	}
	if !s.deleteGenGuardScopedV6(7, key, 100) {
		t.Fatal("first scoped v6 delete must apply")
	}
	if s.deleteGenGuardScopedV6(7, key, 50) {
		t.Fatal("older scoped v6 delete must be refused")
	}
	if !s.deleteGenGuardScopedV6(8, key, 50) {
		t.Fatal("a colliding v6 domain must order independently")
	}
}

// A delayed pre-delete install cannot land after the scoped tombstone;
// a newer install can — per domain.
func TestScopedInstallRefusedAfterDeleteTombstone10512(t *testing.T) {
	s := &SessionSync{}
	key := scopedGenKeyV4(5010)
	if !s.deleteGenGuardScopedV4(7, key, 100) {
		t.Fatal("FIXTURE: scoped delete must apply")
	}
	if _, apply := s.installGenGuardScopedV4(7, key, 50); apply {
		t.Fatal("pre-delete install must be refused after the scoped tombstone")
	}
	if _, apply := s.installGenGuardScopedV4(7, key, 150); !apply {
		t.Fatal("newer install must be accepted")
	}
	if _, apply := s.installGenGuardScopedV4(8, key, 50); !apply {
		t.Fatal("a colliding domain must not see domain 7's tombstone")
	}
}

// A newer replacement transitions the scoped entry back to live: the
// tombstone is forgotten, the high-water advances, and a later scoped
// delete orders against the install instead of the stale tombstone.
func TestScopedInstallTransitionsEntryLive10512(t *testing.T) {
	s := &SessionSync{}
	key := scopedGenKeyV4(5011)
	skey := scopedDeleteKeyV4{Domain: 7, Key: key}
	if !s.deleteGenGuardScopedV4(7, key, 100) {
		t.Fatal("FIXTURE: scoped delete must apply")
	}
	s.recordInstalledGenScopedV4(7, key, 150)
	s.recvGenMu.Lock()
	got := s.recvGenScopedV4[skey]
	tombs := s.recvTombScopedV4.size()
	s.recvGenMu.Unlock()
	if got != 150 {
		t.Fatalf("scoped high-water = %d, want 150", got)
	}
	if tombs != 0 {
		t.Fatalf("install must forget the scoped tombstone, %d remain", tombs)
	}
	if s.deleteGenGuardScopedV4(7, key, 120) {
		t.Fatal("scoped delete older than the live install must be refused")
	}
}

// V6 twin: install refused after the scoped tombstone.
func TestScopedInstallRefusedAfterDeleteTombstoneV610512(t *testing.T) {
	s := &SessionSync{}
	key := scopedGenKeyV6(5010)
	if !s.deleteGenGuardScopedV6(7, key, 100) {
		t.Fatal("FIXTURE: scoped v6 delete must apply")
	}
	if _, apply := s.installGenGuardScopedV6(7, key, 50); apply {
		t.Fatal("pre-delete v6 install must be refused after the scoped tombstone")
	}
	if _, apply := s.installGenGuardScopedV6(7, key, 150); !apply {
		t.Fatal("newer v6 install must be accepted")
	}
}
