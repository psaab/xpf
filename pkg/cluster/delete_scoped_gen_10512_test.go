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

// Scoped takes draw fresh strictly greater than the install they cancel
// (evicting the stamp); unstamped draws 0 legacy fallback (fresh on
// overflow). Bare sender stamps never disturbed.
func TestTakeDeleteGenScopedKeyed10512(t *testing.T) {
	s := &SessionSync{}
	key := scopedGenKeyV4(5001)
	val := dataplane.SessionValue{RoutingDomain: 7}
	s.stampInstallGenV4(key, &val)
	installGen := val.Generation
	if installGen == 0 {
		t.Fatal("FIXTURE: install stamp must be nonzero")
	}
	g1 := s.takeDeleteGenScopedV4(7, key)
	if g1 <= installGen {
		t.Fatalf("scoped take %d must out-rank its install %d", g1, installGen)
	}
	if again := s.takeDeleteGenScopedV4(7, key); again != 0 {
		t.Fatalf("take after eviction returned %d, want 0", again)
	}
	if got := s.takeDeleteGenScopedV4(7, scopedGenKeyV4(5009)); got != 0 {
		t.Fatalf("unstamped scoped take = %d, want 0", got)
	}
	if got := s.takeDeleteGenScopedV4(8, key); got != 0 {
		t.Fatalf("other-domain scoped take = %d, want 0 (per-domain stamps)", got)
	}
	s.genSentMu.Lock()
	s.genSentOverflowScopedV4 = true
	s.genSentMu.Unlock()
	if got := s.takeDeleteGenScopedV4(7, scopedGenKeyV4(5010)); got == 0 {
		t.Fatal("overflow-latched scoped take must draw fresh, got 0")
	}
	s.genSentMu.Lock()
	bareStamps := len(s.genSentV4)
	s.genSentMu.Unlock()
	if bareStamps != 1 {
		t.Fatalf("bare stamps = %d, want exactly the install's 1", bareStamps)
	}
	key6 := scopedGenKeyV6(5001)
	val6 := dataplane.SessionValueV6{RoutingDomain: 7}
	s.stampInstallGenV6(key6, &val6)
	if g := s.takeDeleteGenScopedV6(7, key6); g <= val6.Generation {
		t.Fatalf("scoped v6 take %d must out-rank its install %d", g, val6.Generation)
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

// V6 twin: keyed takes + guard ordering on the scoped v6 space.
func TestDeleteGenScopedV6Orders10512(t *testing.T) {
	s := &SessionSync{}
	key := scopedGenKeyV6(5006)
	val := dataplane.SessionValueV6{RoutingDomain: 7}
	s.stampInstallGenV6(key, &val)
	if val.Generation == 0 {
		t.Fatal("FIXTURE: install stamp must be nonzero")
	}
	if s.takeDeleteGenScopedV6(7, key) <= val.Generation {
		t.Fatal("scoped v6 take must out-rank its install")
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

// Default-domain normalization: a wire-marker-1 install stamps the
// logical-0 scoped space, so a logical-0 take draws fresh (not 0).
func TestScopedStampTakeDefaultDomain10512(t *testing.T) {
	s := &SessionSync{}
	key := scopedGenKeyV4(5020)
	val := dataplane.SessionValue{RoutingDomain: 1} // WIRE_DEFAULT_INSTANCE, stated.
	s.stampInstallGenV4(key, &val)
	if g := s.takeDeleteGenScopedV4(0, key); g <= val.Generation {
		t.Fatalf("default-domain take %d must out-rank its install %d", g, val.Generation)
	}
}

// Sender-side lifecycle: scoped stamps are bounded by sentCap like the
// bare maps (ordinary bare-path closes do not remove them; the cap +
// overflow latch is the reclamation discipline, #9719-shaped). Past the
// cap, installs skip stamping, the overflow latches, and takes for
// unstamped keys draw fresh (safe: fresh out-ranks every install).
func TestScopedSenderStampsBoundedAtCap10512(t *testing.T) {
	s := &SessionSync{}
	const wantCap = 8
	s.sentGenGuardCap = wantCap
	s.genGuardMapCeilingOverride = wantCap
	for i := uint16(0); i < 2*uint16(wantCap); i++ {
		key := scopedGenKeyV4(6000 + i)
		val := dataplane.SessionValue{RoutingDomain: 7}
		s.stampInstallGenV4(key, &val)
	}
	s.genSentMu.Lock()
	n := len(s.genSentScopedV4)
	latched := s.genSentOverflowScopedV4
	s.genSentMu.Unlock()
	if n > wantCap {
		t.Fatalf("scoped sender stamps = %d, want <= cap %d", n, wantCap)
	}
	if !latched {
		t.Fatal("scoped sender overflow must latch past the cap")
	}
	// Unstamped key (skipped past the cap) draws fresh, never 0.
	fresh := scopedGenKeyV4(7000)
	fval := dataplane.SessionValue{RoutingDomain: 7}
	s.stampInstallGenV4(fresh, &fval) // skipped: at cap
	if g := s.takeDeleteGenScopedV4(7, fresh); g == 0 {
		t.Fatal("overflow-latched take must draw fresh, got 0")
	}
}

// Receive-path normalization: a logical-0 scoped tombstone refuses a
// wire-marker-1 install with an older generation — no store write.
// Pins the normalization at BOTH the guard and record call sites.
func TestScopedInstallDefaultDomainRefusedAtReceive10512(t *testing.T) {
	s := &SessionSync{}
	fake := &scopedRecorderStore10512{}
	s.sessions = fake
	key := scopedGenKeyV4(5030)
	if !s.deleteGenGuardScopedV4(0, key, 100) {
		t.Fatal("FIXTURE: logical-0 scoped delete must apply")
	}
	val := dataplane.SessionValue{RoutingDomain: 1, Generation: 50}
	if s.installClusterSyncedV4(key, val) {
		t.Fatal("pre-delete wire-default install must be refused at receive")
	}
	if got := fake.putsV4; got != 0 {
		t.Fatalf("refused install wrote the store %d times, want 0", got)
	}
	// Newer wire-default install lands (normalization is not a block).
	val.Generation = 150
	if !s.installClusterSyncedV4(key, val) {
		t.Fatal("newer wire-default install must land")
	}
	if got := fake.putsV4; got != 1 {
		t.Fatalf("landed install wrote the store %d times, want 1", got)
	}
}

// V6 twin of the receive-path normalization cell.
func TestScopedInstallDefaultDomainRefusedAtReceiveV610512(t *testing.T) {
	s := &SessionSync{}
	fake := &scopedRecorderStore10512{}
	s.sessions = fake
	key := scopedGenKeyV6(5030)
	if !s.deleteGenGuardScopedV6(0, key, 100) {
		t.Fatal("FIXTURE: logical-0 scoped v6 delete must apply")
	}
	val := dataplane.SessionValueV6{RoutingDomain: 1, Generation: 50}
	if s.installClusterSyncedV6(key, val) {
		t.Fatal("pre-delete wire-default v6 install must be refused at receive")
	}
	if got := fake.putsV6; got != 0 {
		t.Fatalf("refused v6 install wrote the store %d times, want 0", got)
	}
}
