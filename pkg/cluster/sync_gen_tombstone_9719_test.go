package cluster

import (
	"encoding/binary"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// #9719: a tombstone never freed its generation-map entry, so a long-lived connection churning closed
// sessions filled the receiver map. Then every NEW key was skip-recorded, and the #2170/#2221 ordering
// guards were off for every new session until the next bulk.
//
// On the sender, a key stamped above the cap carried generation 0 on its delete, which the receiver
// applies unconditionally.

// churnInstallDeleteV4_9719 runs n install+delete cycles over distinct keys through the receiver's
// generation bookkeeping, as a long-lived connection with no BulkStart would. It returns the next
// unused generation.
//
// It drives the guard and record functions rather than the dataplane apply, because the defect is in
// the generation state, and 200k dataplane round trips under -race would dwarf the cell.
func churnInstallDeleteV4_9719(ss *SessionSync, n int) uint64 {
	gen := uint64(1)
	for i := 0; i < n; i++ {
		key := synthKeyV4(i)
		if rec, apply := ss.installGenGuardV4(key, gen); apply {
			ss.recordInstalledGenV4(key, rec)
		}
		ss.deleteGenGuardV4(key, gen+1)
		gen += 2
	}
	return gen
}

// THE DEFECT, as the acceptance states it: churn more than genGuardMapCap install+close cycles with no
// BulkStart, install a new key, then deliver an OLDER delete. The delete must be refused.
func TestTombstoneChurnDoesNotStarveANewLiveKey_9719(t *testing.T) {
	dp := &mockSweepDP{v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{}}
	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)

	next := churnInstallDeleteV4_9719(ss, genGuardMapCap+1000)

	// The new session is installed through the real apply path at a generation newer than every churn.
	newKey := dataplane.SessionKey{Protocol: 6, SrcPort: 0x9719, DstPort: 5201}
	newKey.SrcIP = [4]byte{192, 0, 2, 97}
	installWithGenV4(ss, newKey, next+10)
	if _, ok := dp.v4sessions[newKey]; !ok {
		t.Fatal("FIXTURE: the new session was not installed")
	}

	// A delete older than that install, reordered in, must be refused.
	ss.deleteClusterSyncedV4(newKey, next+5)
	if _, ok := dp.v4sessions[newKey]; !ok {
		t.Fatalf("#9719: after %d closed sessions with no bulk, a delete OLDER than the new key's install "+
			"removed it. The generation map was full of tombstones, so the new key's generation was never "+
			"recorded and the delete guard saw stored=0", genGuardMapCap+1000)
	}
	if got := ss.stats.DeletesStaleIgnored.Load(); got != 1 {
		t.Errorf("DeletesStaleIgnored = %d, want 1", got)
	}
	if got := ss.stats.GenTombstonesEvicted.Load(); got == 0 {
		t.Error("GenTombstonesEvicted = 0: churn past the cap must have evicted tombstones to make room")
	}
	ss.recvGenMu.Lock()
	size, tombs := len(ss.recvGenV4), ss.recvTombV4.size()
	ss.recvGenMu.Unlock()
	if size > genGuardMapCap || tombs > size {
		t.Errorf("the map grew past the cap or the tombstone order outgrew the map: map=%d tombstones=%d cap=%d",
			size, tombs, genGuardMapCap)
	}
}

// Eviction is OLDEST first. The newest tombstone still refuses its own reordered older install, while
// the oldest was evicted to make room, and its reordered install now applies.
func TestTombstonesAreEvictedOldestFirst_9719(t *testing.T) {
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	const n = genGuardMapCap + 10
	churnInstallDeleteV4_9719(ss, n)
	// The map is full of tombstones. Make room for one more new key, which evicts exactly one.
	extra := dataplane.SessionKey{Protocol: 17, SrcPort: 1, DstPort: 1}
	binary.LittleEndian.PutUint32(extra.SrcIP[:], 0xC0000201)
	ss.recordInstalledGenV4(extra, 1<<40)

	// Newest churned key: install generation 2(n-1)+1, delete generation 2(n-1)+2.
	newestInstallGen := uint64(2*(n-1) + 1)
	if _, apply := ss.installGenGuardV4(synthKeyV4(n-1), newestInstallGen); apply {
		t.Error("the NEWEST tombstone was evicted: its reordered older install was admitted, resurrecting a " +
			"session closed moments ago")
	}
	// Oldest churned key: install generation 1. Its tombstone went first.
	if _, apply := ss.installGenGuardV4(synthKeyV4(0), 1); !apply {
		t.Error("the OLDEST tombstone was kept while newer ones were evicted: eviction must be oldest-first")
	}
}

// A re-install supersedes the key's tombstone, and a gen-0 delete removes it. Neither may leave the key
// in the tombstone order, or a later eviction would delete a LIVE entry.
func TestReinstallAndLegacyDeleteForgetTheTombstone_9719(t *testing.T) {
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	key := gen2170KeyV4()

	ss.recordInstalledGenV4(key, 5)
	ss.deleteGenGuardV4(key, 6)
	if got := ss.recvTombV4.size(); got != 1 {
		t.Fatalf("FIXTURE: an applied non-zero delete must register one tombstone, got %d", got)
	}
	ss.recordInstalledGenV4(key, 7)
	if got := ss.recvTombV4.size(); got != 0 {
		t.Errorf("a re-install left the key in the tombstone order (%d); a later eviction would delete its "+
			"LIVE generation", got)
	}

	ss.deleteGenGuardV4(key, 8)
	ss.deleteGenGuardV4(key, 0)
	ss.recvGenMu.Lock()
	_, present := ss.recvGenV4[key]
	ss.recvGenMu.Unlock()
	if present {
		t.Fatal("FIXTURE: a gen-0 delete must evict the entry, as before")
	}
	if got := ss.recvTombV4.size(); got != 0 {
		t.Errorf("a gen-0 delete left the key in the tombstone order (%d), out of step with the map", got)
	}
}

// The sender half: above the stamp cap, a delete for a live key whose stamp was skipped must still
// carry a generation. Before any overflow, the legacy 0 for a never-stamped key is unchanged.
func TestUnstampedDeleteAfterStampOverflowCarriesAGenerationV4_9719(t *testing.T) {
	control := NewSessionSync(":0", "10.0.0.2:4785", nil)
	if got := control.takeDeleteGenV4(gen2170KeyV4()); got != 0 {
		t.Fatalf("CONTROL: before any overflow a never-stamped key must keep the legacy generation 0, got %d", got)
	}

	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	ss.genSentMu.Lock()
	ss.genSentV4 = make(map[dataplane.SessionKey]uint64, genGuardMapCap)
	for i := 0; len(ss.genSentV4) < genGuardMapCap; i++ {
		ss.genSentV4[synthKeyV4(i)] = uint64(i + 1)
	}
	ss.genSentMu.Unlock()

	live := gen2170KeyV4()
	val := dataplane.SessionValue{}
	ss.stampInstallGenV4(live, &val)
	ss.genSentMu.Lock()
	_, stamped := ss.genSentV4[live]
	ss.genSentMu.Unlock()
	if stamped {
		t.Fatal("FIXTURE: the stamp map was not at the cap, so nothing was skipped")
	}

	if got := ss.takeDeleteGenV4(live); got == 0 {
		t.Error("#9719: a live session whose stamp was skipped at the cap was deleted with generation 0, which " +
			"the receiver applies unconditionally")
	}
}

func TestUnstampedDeleteAfterStampOverflowCarriesAGenerationV6_9719(t *testing.T) {
	control := NewSessionSync(":0", "10.0.0.2:4785", nil)
	if got := control.takeDeleteGenV6(gen2170KeyV6()); got != 0 {
		t.Fatalf("CONTROL: before any overflow a never-stamped v6 key must keep generation 0, got %d", got)
	}

	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	ss.genSentMu.Lock()
	ss.genSentV6 = make(map[dataplane.SessionKeyV6]uint64, genGuardMapCap)
	for i := 0; len(ss.genSentV6) < genGuardMapCap; i++ {
		var k dataplane.SessionKeyV6
		k.Protocol = 17
		binary.LittleEndian.PutUint32(k.SrcIP[:4], uint32(i))
		ss.genSentV6[k] = uint64(i + 1)
	}
	ss.genSentMu.Unlock()

	live := gen2170KeyV6()
	val := dataplane.SessionValueV6{}
	ss.stampInstallGenV6(live, &val)

	if got := ss.takeDeleteGenV6(live); got == 0 {
		t.Error("#9719: a live v6 session whose stamp was skipped at the cap was deleted with generation 0")
	}
}
