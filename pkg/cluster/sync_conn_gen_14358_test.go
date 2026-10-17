package cluster

import (
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// #14358 (a): normal closes must not leak scoped generation entries.
// Sender takeDeleteGen* and receiver deleteClusterSynced* both need to
// reclaim the scoped live entry (bare key carries no domain, so every
// scoped entry naming the tuple), while receiver tombstones are retained.
func TestNormalCloseReclaimsScopedGen14358(t *testing.T) {
	const wantCap = 8
	sender := &SessionSync{}
	sender.sentGenGuardCap = wantCap
	sender.genGuardMapCeilingOverride = wantCap
	for i := uint16(0); i < 2*uint16(wantCap); i++ {
		key := scopedGenKeyV4(8000 + i)
		val := dataplane.SessionValue{RoutingDomain: 7}
		sender.stampInstallGenV4(key, &val)
		_ = sender.takeDeleteGenV4(key)
	}
	sender.genSentMu.Lock()
	sentScoped := len(sender.genSentScopedV4)
	sentBare := len(sender.genSentV4)
	overflowScoped := sender.genSentOverflowScopedV4
	sender.genSentMu.Unlock()
	if sentScoped != 0 {
		t.Fatalf("genSentScopedV4 holds %d live entries after normal closes, want 0", sentScoped)
	}
	if sentBare != 0 {
		t.Fatalf("genSentV4 holds %d entries after normal closes, want 0", sentBare)
	}
	if overflowScoped {
		t.Fatal("scoped sender overflow latched despite normal-close reclamation")
	}
	// V6 twin (sender).
	sender6 := &SessionSync{}
	sender6.sentGenGuardCap = wantCap
	sender6.genGuardMapCeilingOverride = wantCap
	for i := uint16(0); i < 2*uint16(wantCap); i++ {
		key := scopedGenKeyV6(8000 + i)
		val := dataplane.SessionValueV6{RoutingDomain: 7}
		sender6.stampInstallGenV6(key, &val)
		_ = sender6.takeDeleteGenV6(key)
	}
	sender6.genSentMu.Lock()
	sentScoped6 := len(sender6.genSentScopedV6)
	sender6.genSentMu.Unlock()
	if sentScoped6 != 0 {
		t.Fatalf("genSentScopedV6 holds %d live entries after normal closes, want 0", sentScoped6)
	}
	dp := &mockSweepDP{v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{}, v6sessions: map[dataplane.SessionKeyV6]dataplane.SessionValueV6{}}
	recv := NewSessionSync(":0", "10.0.0.2:4785", dp)
	recv.recvGenGuardCap = wantCap
	recv.genGuardMapCeilingOverride = wantCap
	for i := uint16(0); i < 2*uint16(wantCap); i++ {
		key := scopedGenKeyV4(9000 + i)
		val := dataplane.SessionValue{RoutingDomain: 7, Generation: uint64(100 + i)}
		if !recv.installClusterSyncedV4(key, val) {
			t.Fatalf("install %d refused", i)
		}
		recv.deleteClusterSyncedV4(key, uint64(200+i), false)
	}
	recv.recvGenMu.Lock()
	liveScoped := 0
	for skey, gen := range recv.recvGenScopedV4 {
		if recv.recvTombScopedV4.elems[skey] == nil {
			_ = gen
			liveScoped++
		}
	}
	totalScoped := len(recv.recvGenScopedV4)
	tombScoped := recv.recvTombScopedV4.size()
	recv.recvGenMu.Unlock()
	if liveScoped != 0 {
		t.Fatalf("recvGenScopedV4 holds %d live entries after normal deletes, want 0 (total=%d tombs=%d)", liveScoped, totalScoped, tombScoped)
	}
}

// #14358 (b): scoped policy delete must also tombstone the bare space and
// evict received memos, so a same-generation install replay is refused by
// the bare guard even when the scoped tombstone was evicted at cap. Also
// checks receiver bare delete tombstones the scoped space, and that a
// genuinely newer bare incarnation is not gated by a stale scoped delete.
func TestScopedDeleteCrossTombstonesBare14358(t *testing.T) {
	// V4.
	s := &SessionSync{}
	store := &scopedRecorderStore10512{}
	s.sessions = store
	key := scopedGenKeyV4(9100)
	const genInstall = uint64(100)
	val := dataplane.SessionValue{RoutingDomain: 7, Generation: genInstall, SessionID: 42, InstallTableDomain: 99, InstallTableCheck: 7}
	if !s.installClusterSyncedV4(key, val) {
		t.Fatal("install must land")
	}
	s.deleteClusterSyncedScopedV4(7, key, 150, 42)
	s.recvGenMu.Lock()
	bareGen, bareOK := s.recvGenV4[key]
	bareTomb := s.recvTombV4.elems[key] != nil
	_, installMemo := s.installTableRecvV4[key]
	s.recvGenMu.Unlock()
	if !bareOK || bareGen != 150 || !bareTomb {
		t.Fatalf("scoped delete must bare-tombstone at 150, got gen=%d ok=%v tomb=%v", bareGen, bareOK, bareTomb)
	}
	if installMemo {
		t.Fatal("scoped delete must evict installTableRecvV4")
	}
	// Replay at same generation must be refused.
	replay := dataplane.SessionValue{RoutingDomain: 7, Generation: genInstall}
	if s.installClusterSyncedV4(key, replay) {
		t.Fatal("same-generation replay after scoped delete must be refused")
	}
	// Genuinely newer bare incarnation must still land (scoped delete of a
	// different tenant / domain-0 bare session at same tuple).
	bareVal := dataplane.SessionValue{RoutingDomain: 0, Generation: 200}
	if !s.installClusterSyncedV4(key, bareVal) {
		t.Fatal("newer bare install must land despite scoped tombstone")
	}
	// A stale scoped delete (older than live bare gen 200) must be refused
	// now that spaces are coupled on delete.
	s.deleteClusterSyncedScopedV4(7, key, 150, 42)
	if got := s.stats.DeletesStaleIgnored.Load(); got == 0 {
		t.Fatal("stale scoped delete after newer bare install must be ignored")
	}

	// Capacity case: scoped tombstone evicted, bare tombstone still refuses.
	s2 := &SessionSync{}
	s2.sessions = &scopedRecorderStore10512{}
	const cap2 = 2
	s2.recvGenGuardCap = cap2
	s2.genGuardMapCeilingOverride = cap2
	key2 := scopedGenKeyV4(9200)
	if !s2.installClusterSyncedV4(key2, dataplane.SessionValue{RoutingDomain: 7, Generation: 100}) {
		t.Fatal("cap install must land")
	}
	s2.deleteClusterSyncedScopedV4(7, key2, 150, 1)
	// Fill both spaces with other tombstones to evict key2's tombstones.
	for i := uint16(0); i < 4; i++ {
		s2.deleteGenGuardScopedV4(7, scopedGenKeyV4(9300+i), uint64(300+i))
		s2.deleteGenGuardV4(scopedGenKeyV4(9300+i), uint64(300+i))
	}
	s2.recvGenMu.Lock()
	_, scopedTombKept2 := s2.recvTombScopedV4.elems[scopedDeleteKeyV4{Domain: 7, Key: key2}]
	_, bareTombKept2 := s2.recvTombV4.elems[key2]
	s2.recvGenMu.Unlock()
	if scopedTombKept2 || bareTombKept2 {
		t.Fatalf("FIXTURE: both tombstones should have been evicted at cap (scoped=%v bare=%v)", scopedTombKept2, bareTombKept2)
	}
	s2.deleteGenGuardV4(key2, 150)
	if s2.installClusterSyncedV4(key2, dataplane.SessionValue{RoutingDomain: 7, Generation: 100}) {
		t.Fatal("same-generation replay must be refused by bare tombstone alone")
	}

	// Reverse direction: bare delete tombstones scoped space per domain.
	s3 := &SessionSync{}
	s3.sessions = &scopedRecorderStore10512{}
	key3 := scopedGenKeyV4(9400)
	if !s3.installClusterSyncedV4(key3, dataplane.SessionValue{RoutingDomain: 7, Generation: 100}) {
		t.Fatal("install must land")
	}
	s3.deleteClusterSyncedV4(key3, 150, false)
	s3.recvGenMu.Lock()
	scopedGen, scopedOK := s3.recvGenScopedV4[scopedDeleteKeyV4{Domain: 7, Key: key3}]
	scopedTomb := s3.recvTombScopedV4.elems[scopedDeleteKeyV4{Domain: 7, Key: key3}] != nil
	s3.recvGenMu.Unlock()
	if !scopedOK || scopedGen != 150 || !scopedTomb {
		t.Fatalf("bare delete must scoped-tombstone at 150, got gen=%d ok=%v tomb=%v", scopedGen, scopedOK, scopedTomb)
	}
	// Scoped delete older than that must be refused; newer same-domain scoped
	// delete still applies.
	before := s3.stats.DeletesStaleIgnored.Load()
	s3.deleteClusterSyncedScopedV4(7, key3, 120, 1)
	if s3.stats.DeletesStaleIgnored.Load() == before {
		t.Fatal("scoped delete older than bare-delete scoped tombstone must be ignored")
	}

	// V6 smoke for scoped->bare.
	s6 := &SessionSync{}
	s6.sessions = &scopedRecorderStore10512{}
	key6 := scopedGenKeyV6(9100)
	if !s6.installClusterSyncedV6(key6, dataplane.SessionValueV6{RoutingDomain: 7, Generation: 100}) {
		t.Fatal("v6 install must land")
	}
	s6.deleteClusterSyncedScopedV6(7, key6, 150, 1)
	if s6.installClusterSyncedV6(key6, dataplane.SessionValueV6{RoutingDomain: 7, Generation: 100}) {
		t.Fatal("v6 same-generation replay after scoped delete must be refused")
	}
	// V6 bare->scoped.
	s6b := &SessionSync{}
	s6b.sessions = &scopedRecorderStore10512{}
	if !s6b.installClusterSyncedV6(key6, dataplane.SessionValueV6{RoutingDomain: 7, Generation: 100}) {
		t.Fatal("v6 install must land")
	}
	s6b.deleteClusterSyncedV6(key6, 150, false)
	s6b.recvGenMu.Lock()
	sg6, ok6 := s6b.recvGenScopedV6[scopedDeleteKeyV6{Domain: 7, Key: key6}]
	s6b.recvGenMu.Unlock()
	if !ok6 || sg6 != 150 {
		t.Fatalf("v6 bare delete must scoped-tombstone at 150, got %d ok=%v", sg6, ok6)
	}
}
