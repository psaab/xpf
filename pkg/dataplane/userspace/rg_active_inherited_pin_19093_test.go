package userspace

import (
	"errors"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/psaab/xpf/pkg/dataplane"
)

// #19093: the PINNED rg_active map (/sys/fs/bpf/xpf/rg_active) outlives an
// unclean xpfd exit. The restarted process's first apply imported it into the
// helper-facing HA inventory (refreshHAStateFromMapsLocked ->
// mergeHAStateFromMaps: Active = rgVal != 0) and published it to the new
// helper, so a node that came back SECONDARY told its helper it owned RG0-2.
// Nothing wrote the correcting 0, XSK idle liveness never proved, and failback
// was refused for 8m49s on loss.
//
// The barrier sits at that import: a slot is BASE ownership only if THIS
// process's UpdateRGActive landed a write to it (Manager.rgActiveWritten). The
// #18559 transfer pre-activation is a separate in-memory overlay of this
// process, applied per publish; these cells check the two layers together.
//
// Every cell observes the publication boundary — the update_ha_state
// inventories a helper receives, in order — and drives the production paths:
// the first-apply HA tail (refresh then publish, manager_compile.go), the
// replay, the helper-departure reset shared by stop and crash
// (resetAfterHelperGoneLocked), UpdateRGActive, and the pre-activation API.
//
// The maps are REAL kernel arrays shaped like the shim's (Array,
// MaxRedundancyGroups entries): a fixed array is what makes an unconfigured
// slot exist, and Freeze() is the only honest way to make a userspace write
// fail. They need the privilege to create a BPF map; unprivileged each cell
// SKIPs, and a skip prints `ok` like a pass, so each is registered in
// pkg/memlockcensus and the privileged leg (make test-memlock-guards) is the
// one that counts. The pure merge core is ALSO covered unprivileged, in
// rg_active_mask_19093_test.go.
//
// This file compiles against master's API on purpose, so the same cells show
// RED at master and GREEN with the fix.

// rgActivePublish19093 records every update_ha_state inventory sent to the
// helper, in order, and can fail them on demand.
type rgActivePublish19093 struct {
	reqs    [][]HAGroupStatus
	failNow bool
}

func (p *rgActivePublish19093) at(i int) map[int]HAGroupStatus {
	out := make(map[int]HAGroupStatus)
	for _, g := range p.reqs[i] {
		out[g.RGID] = g
	}
	return out
}

func (p *rgActivePublish19093) last(t *testing.T) map[int]HAGroupStatus {
	t.Helper()
	if len(p.reqs) == 0 {
		t.Fatal("no update_ha_state reached the helper; the cell cannot judge what it was told")
	}
	return p.at(len(p.reqs) - 1)
}

// everActive reports the index of the first request that told the helper rg
// was active, or -1.
func (p *rgActivePublish19093) everActive(rg int) int {
	for i := range p.reqs {
		if p.at(i)[rg].Active {
			return i
		}
	}
	return -1
}

func newRGActiveArrays19093(t *testing.T, stale map[uint32]uint8) (rg, wd *ebpf.Map) {
	t.Helper()
	var err error
	rg, err = ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Array,
		KeySize:    4,
		ValueSize:  1,
		MaxEntries: dataplane.MaxRedundancyGroups,
	})
	if err != nil {
		skipIfBPFMapUnavailable(t, "new rg_active array", err)
	}
	t.Cleanup(func() { rg.Close() })
	wd, err = ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Array,
		KeySize:    4,
		ValueSize:  8,
		MaxEntries: dataplane.MaxRedundancyGroups,
	})
	if err != nil {
		skipIfBPFMapUnavailable(t, "new ha_watchdog array", err)
	}
	t.Cleanup(func() { wd.Close() })
	for k, v := range stale {
		if err := rg.Update(k, v, ebpf.UpdateAny); err != nil {
			t.Fatalf("seed inherited rg_active[%d]=%d: %v", k, v, err)
		}
	}
	return rg, wd
}

// newRGActiveImportManager19093 is a fresh process's userspace Manager over the
// given maps, with the configured redundancy groups seeded inactive (what
// seedHAGroupInventoryLocked produces on a fresh process).
func newRGActiveImportManager19093(t *testing.T, rg, wd *ebpf.Map, groups ...int) *Manager {
	t.Helper()
	m := New()
	m.clusterHA = true
	m.bpfShim.SelectUserspaceXDPShimEntryProgram()
	// applyHelperStatusLocked (the tail of every publish) re-syncs classifier
	// maps this fixture does not load; the established seam (#7468/#9337).
	m.syncClassifierMapsHook = func(*ConfigSnapshot) error { return nil }
	injectCtrlAndBindingMaps(t, m)
	injectShimMap(t, m.bpfShim, "rg_active", rg)
	injectShimMap(t, m.bpfShim, "ha_watchdog", wd)
	m.haGroups = make(map[int]HAGroupStatus, len(groups))
	for _, g := range groups {
		m.haGroups[g] = HAGroupStatus{RGID: g}
	}
	return m
}

// attachHelper19093 models a spawned helper: a live process and a control
// channel whose update_ha_state requests are recorded (and ACKed unless
// failNow is set). Re-attaching after a helper departure models the respawn.
func attachHelper19093(m *Manager, p *rgActivePublish19093) *rgActivePublish19093 {
	if p == nil {
		p = &rgActivePublish19093{}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.proc = &exec.Cmd{Process: &os.Process{Pid: 1}}
	m.controlRequestHook = func(req ControlRequest, _ *ProcessStatus) error {
		if req.Type == "update_ha_state" && req.HAState != nil {
			if p.failNow {
				return errors.New("synthetic helper IPC failure (#19093)")
			}
			p.reqs = append(p.reqs, append([]HAGroupStatus(nil), req.HAState.Groups...))
		}
		return nil
	}
	return p
}

// helperGone19093 runs the real helper-departure reset that stopLocked and the
// crash path share, and drops the process, as both do.
func helperGone19093(m *Manager) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.resetAfterHelperGoneLocked()
	m.proc = nil
	m.controlRequestHook = nil
}

// firstApplyHA19093 runs the clustered HA tail of the first apply exactly as
// applyCompiledSnapshot orders it: refresh from the maps, then publish.
func firstApplyHA19093(t *testing.T, m *Manager) {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.refreshHAStateFromMapsLocked(); err != nil {
		t.Fatalf("refreshHAStateFromMapsLocked: %v", err)
	}
	if err := m.syncHAStateLocked(); err != nil {
		// The inventory was already handed to the helper (captured);
		// later steps of the tail are not under test here.
		t.Logf("syncHAStateLocked tail after the publish: %v", err)
	}
}

// replayHA19093 runs the production replay (helper respawn / debt
// convergence): refresh from the maps, then a full-inventory publish.
func replayHA19093(t *testing.T, m *Manager) {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pendingHAStateReplay = true
	if err := m.retryPendingHAStateReplayLocked(); err != nil {
		t.Logf("replay tail after the publish: %v", err)
	}
}

func rgActiveSlot19093(t *testing.T, rg *ebpf.Map, k uint32) uint8 {
	t.Helper()
	var v uint8
	if err := rg.Lookup(k, &v); err != nil {
		t.Fatalf("lookup rg_active[%d]: %v", k, err)
	}
	return v
}

// M1: the issue's shape. The previous process owned RG0-2 and left them 1; the
// unconfigured last slot is 1 as well. The restarted node is secondary for
// every RG. No request may tell the helper any of them is active, and the
// inherited slots — including the unconfigured one — must be cleared.
//
// RED at master: the first publish carries RG0-2 Active=true and no slot is
// cleared.
func TestRGActiveInheritedPinNotPublished19093(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("creating a BPF map needs privilege (memlock rlimit / CAP_BPF): %v", err)
	}
	last := uint32(dataplane.MaxRedundancyGroups - 1)
	rg, wd := newRGActiveArrays19093(t, map[uint32]uint8{0: 1, 1: 1, 2: 1, last: 1})
	m := newRGActiveImportManager19093(t, rg, wd, 0, 1, 2)
	pub := attachHelper19093(m, nil)

	firstApplyHA19093(t, m)

	_ = pub.last(t)
	for _, g := range []int{0, 1, 2} {
		if i := pub.everActive(g); i >= 0 {
			t.Errorf("update_ha_state #%d told the new helper RG%d is ACTIVE from a pin the "+
				"previous process left; this process never decided it owns RG%d (#19093)", i, g, g)
		}
	}
	for _, k := range []uint32{0, 1, 2, last} {
		if v := rgActiveSlot19093(t, rg, k); v != 0 {
			t.Errorf("inherited rg_active[%d] = %d after the first apply, want it cleared "+
				"(configured=%v)", k, v, k <= 2)
		}
	}
}

// M2: an inherited 1 in a slot that is NOT configured now must not become
// authority when that RG is configured later — even when clearing the pin is
// impossible (the map is frozen, so every userspace write fails), so only the
// import can refuse it.
//
// RED at master: the later refresh imports the inherited 1.
func TestRGActiveInheritedUnconfiguredSlotStaysInactiveWhenAdded19093(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("creating a BPF map needs privilege (memlock rlimit / CAP_BPF): %v", err)
	}
	last := int(dataplane.MaxRedundancyGroups - 1)
	rg, wd := newRGActiveArrays19093(t, map[uint32]uint8{uint32(last): 1})
	if err := rg.Freeze(); err != nil {
		t.Fatalf("freeze rg_active: %v", err)
	}
	m := newRGActiveImportManager19093(t, rg, wd, 0, 1, 2)
	pub := attachHelper19093(m, nil)
	firstApplyHA19093(t, m)

	// A later commit adds the RG whose slot the previous process left at 1.
	m.mu.Lock()
	m.haGroups[last] = HAGroupStatus{RGID: last}
	m.mu.Unlock()
	firstApplyHA19093(t, m)

	if i := pub.everActive(last); i >= 0 {
		t.Errorf("RG%d, configured after the restart, was published ACTIVE (request #%d) from "+
			"the previous process's pin while its clear was impossible (#19093)", last, i)
	}
}

// M3: THIS process's ownership survives the real helper departure (the reset
// stop and crash share) and the respawn's replay. A barrier that is reset with
// the helper hides the process's own writes and blackholes an owned RG.
//
// GREEN at master; red for a mask cleared on helper departure, for a mask that
// hides everything, and for a clear that also zeroes written slots.
func TestRGActiveOwnWriteSurvivesHelperDepartureAndReplay19093(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("creating a BPF map needs privilege (memlock rlimit / CAP_BPF): %v", err)
	}
	rg, wd := newRGActiveArrays19093(t, nil)
	m := newRGActiveImportManager19093(t, rg, wd, 0, 1, 2)
	pub := attachHelper19093(m, nil)

	if err := m.UpdateRGActive(1, true); err != nil {
		t.Logf("UpdateRGActive tail after the publish: %v", err)
	}
	if v := rgActiveSlot19093(t, rg, 1); v != 1 {
		t.Fatalf("fixture: UpdateRGActive(1,true) left rg_active[1]=%d", v)
	}

	helperGone19093(m)
	attachHelper19093(m, pub) // respawned helper
	before := len(pub.reqs)
	replayHA19093(t, m)

	if len(pub.reqs) == before {
		t.Fatal("the replay after the helper respawn published nothing")
	}
	if !pub.last(t)[1].Active {
		t.Error("the replay after a helper departure and respawn published RG1 INACTIVE although " +
			"THIS process wrote it active: the restart barrier must not be reset with the helper")
	}
	if v := rgActiveSlot19093(t, rg, 1); v != 1 {
		t.Errorf("rg_active[1] = %d after the replay; this process wrote 1", v)
	}
}

// M4: the publication race. A cluster event lands THIS process's true write
// after Start published the registry and before the first apply's publish,
// with a helper already reachable, so UpdateRGActive's own direct publish
// ({1:true,2:false} even at master) is captured first. The full sequence must
// carry RG1 true and must NEVER carry the inherited RG2.
//
// RED at master (the post-refresh publish carries RG2 inherited). Red for an
// implementation that zeroes every slot at the first refresh (RG1 lost).
func TestRGActiveWriteBeforeFirstPublishIsKeptInheritedIsNot19093(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("creating a BPF map needs privilege (memlock rlimit / CAP_BPF): %v", err)
	}
	rg, wd := newRGActiveArrays19093(t, map[uint32]uint8{2: 1})
	m := newRGActiveImportManager19093(t, rg, wd, 0, 1, 2)
	pub := attachHelper19093(m, nil)

	if err := m.UpdateRGActive(1, true); err != nil {
		t.Logf("UpdateRGActive tail after the publish: %v", err)
	}
	direct := len(pub.reqs)
	firstApplyHA19093(t, m)
	if len(pub.reqs) <= direct {
		t.Fatalf("fixture: the first apply published nothing after the direct publish (%d requests)", len(pub.reqs))
	}

	if i := pub.everActive(2); i >= 0 {
		t.Errorf("update_ha_state #%d of %d carried RG2 ACTIVE from the previous process's pin "+
			"(#19093)", i, len(pub.reqs))
	}
	if !pub.last(t)[1].Active {
		t.Error("the post-refresh publish dropped RG1, which THIS process wrote active before the " +
			"first apply; a true first seed is legitimate when this process authorized it")
	}
	if v := rgActiveSlot19093(t, rg, 1); v != 1 {
		t.Errorf("rg_active[1] = %d after the first apply; this process wrote 1", v)
	}
}

// M5: clearing an inherited slot fails (the map is frozen). Every publish must
// still say inactive, across retries.
//
// RED at master.
func TestRGActiveInheritedSlotMaskedWhenClearFails19093(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("creating a BPF map needs privilege (memlock rlimit / CAP_BPF): %v", err)
	}
	rg, wd := newRGActiveArrays19093(t, map[uint32]uint8{1: 1})
	if err := rg.Freeze(); err != nil {
		t.Fatalf("freeze rg_active: %v", err)
	}
	m := newRGActiveImportManager19093(t, rg, wd, 0, 1, 2)
	pub := attachHelper19093(m, nil)

	firstApplyHA19093(t, m)
	firstApplyHA19093(t, m)
	if i := pub.everActive(1); i >= 0 {
		t.Errorf("update_ha_state #%d published RG1 ACTIVE from an inherited pin whose clear "+
			"failed; a failed clear must change nothing the helper is told (#19093)", i)
	}
	if v := rgActiveSlot19093(t, rg, 1); v != 1 {
		t.Fatalf("fixture: the frozen slot changed to %d; the cell needs the clear to fail", v)
	}
}

// M6: authority follows the PROCESS. The same Manager keeps its write across a
// helper stop and a re-opened handle to the same pin (the retained-Manager
// re-Start); a NEW Manager over that pin — the next process after an unclean
// exit — gets none of it.
//
// RED at master (B imports the 1). Red for a mask keyed to the map handle, or
// reset with the helper (A).
func TestRGActiveAuthorityIsPerProcessNotPerHandle19093(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("creating a BPF map needs privilege (memlock rlimit / CAP_BPF): %v", err)
	}
	rg, wd := newRGActiveArrays19093(t, nil)

	a := newRGActiveImportManager19093(t, rg, wd, 0, 1, 2)
	pubA := attachHelper19093(a, nil)
	if err := a.UpdateRGActive(1, true); err != nil {
		t.Logf("A: UpdateRGActive tail after the publish: %v", err)
	}
	helperGone19093(a)
	reopened, err := rg.Clone()
	if err != nil {
		t.Fatalf("clone rg_active handle: %v", err)
	}
	t.Cleanup(func() { reopened.Close() })
	injectShimMap(t, a.bpfShim, "rg_active", reopened)
	attachHelper19093(a, pubA)
	firstApplyHA19093(t, a)
	if !pubA.last(t)[1].Active {
		t.Error("process A lost its own RG1=active across a helper stop and a re-opened pin " +
			"handle; authority must follow the process, not the helper or the handle")
	}

	// A dies uncleanly; process B starts over the pin A left.
	b := newRGActiveImportManager19093(t, rg, wd, 0, 1, 2)
	pubB := attachHelper19093(b, nil)
	firstApplyHA19093(t, b)
	if i := pubB.everActive(1); i >= 0 {
		t.Errorf("a new process published RG1 ACTIVE (request #%d) from the pin a dead process "+
			"left (#19093)", i)
	}
}

// M7: only a LANDED write is ownership, and the last landed value wins.
func TestRGActiveOwnershipFollowsLandedWritesOnly19093(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("creating a BPF map needs privilege (memlock rlimit / CAP_BPF): %v", err)
	}

	// M7a/M7b: the map is frozen, so this process's write fails at the map;
	// the inherited 1 must stay unpublished whichever value it tried.
	// RED at master. M7a is red for "mark on an attempted true write".
	for _, tc := range []struct {
		name   string
		active bool
	}{{"failed true write", true}, {"failed false write", false}} {
		t.Run(tc.name, func(t *testing.T) {
			rg, wd := newRGActiveArrays19093(t, map[uint32]uint8{1: 1})
			if err := rg.Freeze(); err != nil {
				t.Fatalf("freeze rg_active: %v", err)
			}
			m := newRGActiveImportManager19093(t, rg, wd, 0, 1, 2)
			if err := m.UpdateRGActive(1, tc.active); err == nil {
				t.Fatalf("fixture: UpdateRGActive(1,%v) on a frozen rg_active succeeded; the cell "+
					"needs the map write to fail", tc.active)
			}
			pub := attachHelper19093(m, nil)
			firstApplyHA19093(t, m)
			if i := pub.everActive(1); i >= 0 {
				t.Errorf("RG1 was published ACTIVE (request #%d) from the inherited pin after this "+
					"process's own %s FAILED; only a landed write is ownership (#19093)", i, tc.name)
			}
		})
	}

	// M7c: the map write lands but the helper IPC fails, so UpdateRGActive
	// returns an error. The value IS this process's: the next replay must
	// publish it. GREEN at master; red for "mark only when the whole call
	// succeeds".
	t.Run("landed write, failed helper IPC", func(t *testing.T) {
		rg, wd := newRGActiveArrays19093(t, nil)
		m := newRGActiveImportManager19093(t, rg, wd, 0, 1, 2)
		pub := attachHelper19093(m, nil)
		pub.failNow = true
		if err := m.UpdateRGActive(1, true); err == nil {
			t.Fatal("fixture: UpdateRGActive succeeded; the cell needs the helper IPC to fail")
		}
		if v := rgActiveSlot19093(t, rg, 1); v != 1 {
			t.Fatalf("fixture: the map write did not land (rg_active[1]=%d)", v)
		}
		pub.failNow = false
		replayHA19093(t, m)
		if !pub.last(t)[1].Active {
			t.Error("a landed rg_active=1 whose helper publish failed was not republished on the " +
				"replay: the write is this process's ownership even though the call returned an error")
		}
	})

	// M7d: true then false both land; the replay publishes the LAST value.
	// GREEN at master.
	t.Run("last landed value", func(t *testing.T) {
		rg, wd := newRGActiveArrays19093(t, nil)
		m := newRGActiveImportManager19093(t, rg, wd, 0, 1, 2)
		pub := attachHelper19093(m, nil)
		for _, v := range []bool{true, false} {
			if err := m.UpdateRGActive(1, v); err != nil {
				t.Logf("UpdateRGActive(1,%v) tail: %v", v, err)
			}
		}
		replayHA19093(t, m)
		if pub.last(t)[1].Active {
			t.Error("the replay published RG1 active after this process's last landed write was false")
		}
		if v := rgActiveSlot19093(t, rg, 1); v != 0 {
			t.Errorf("rg_active[1] = %d, want this process's last write (0)", v)
		}
	})
}

// M8: the #18559 make-before-break pre-activation is an overlay of THIS process
// on top of BASE ownership. Over an inherited pin it must behave exactly as it
// does with no pin: open RG1 for the transfer, and on release fall back to
// BASE — which is inactive, not the dead process's 1.
func TestRGActiveInheritedPinUnderTransferPreActivation19093(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("creating a BPF map needs privilege (memlock rlimit / CAP_BPF): %v", err)
	}

	// M8a: begin, publish, release. RED at master: BASE imported the inherited
	// 1, so End reports "unchanged", publishes nothing, and the helper keeps
	// RG1 active after the transfer was abandoned.
	t.Run("release falls back to base, not the pin", func(t *testing.T) {
		rg, wd := newRGActiveArrays19093(t, map[uint32]uint8{1: 1})
		m := newRGActiveImportManager19093(t, rg, wd, 0, 1, 2)
		pub := attachHelper19093(m, nil)
		firstApplyHA19093(t, m)

		m.BeginTransferPreActivation([]int{1}, time.Now().Add(time.Minute))
		if err := m.PublishTransferPreActivation(); err != nil {
			t.Logf("pre-activation publish tail: %v", err)
		}
		if !pub.last(t)[1].Active {
			t.Fatal("the pre-activation did not open RG1 for the transfer; the overlay must keep working over an inherited pin")
		}
		changed, err := m.EndTransferPreActivation([]int{1})
		if err != nil {
			t.Logf("release publish tail: %v", err)
		}
		if !changed {
			t.Error("releasing the pre-activation reported no change: BASE still says RG1 is active, " +
				"which only the previous process's pin could have made true (#19093)")
		}
		if pub.last(t)[1].Active {
			t.Error("after the abandoned transfer was released, the helper's last inventory still " +
				"has RG1 ACTIVE — it was never told to stop (#19093)")
		}
	})

	// M8b: the real promotion supersedes the overlay and becomes BASE.
	t.Run("promotion supersedes and is kept", func(t *testing.T) {
		rg, wd := newRGActiveArrays19093(t, map[uint32]uint8{1: 1})
		m := newRGActiveImportManager19093(t, rg, wd, 0, 1, 2)
		pub := attachHelper19093(m, nil)
		firstApplyHA19093(t, m)
		m.BeginTransferPreActivation([]int{1}, time.Now().Add(time.Minute))
		if err := m.UpdateRGActive(1, true); err != nil {
			t.Logf("promotion tail: %v", err)
		}
		if got := m.TransferPreActiveRGs(); len(got) != 0 {
			t.Errorf("the promotion did not supersede the pre-activation: still pre-active %v", got)
		}
		replayHA19093(t, m)
		if !pub.last(t)[1].Active {
			t.Error("after the real promotion landed, the replay published RG1 inactive")
		}
	})

	// M8c: a pre-activation whose deadline has passed no longer counts in the
	// refresh+sync publish, which shows BASE: inactive, not the inherited 1.
	// The deadline is set in the past, so nothing sleeps. SCOPE: this drives
	// the refresh+sync publish only. It does not cover the degraded watchdog's
	// cached snapshot or the status poll's all-inactive skip; deadline
	// enforcement on those senders predates #19093 and is #19103.
	t.Run("lapsed pre-activation shows base", func(t *testing.T) {
		rg, wd := newRGActiveArrays19093(t, map[uint32]uint8{1: 1})
		m := newRGActiveImportManager19093(t, rg, wd, 0, 1, 2)
		pub := attachHelper19093(m, nil)
		m.BeginTransferPreActivation([]int{1}, time.Now().Add(-time.Second))
		firstApplyHA19093(t, m)
		if pub.last(t)[1].Active {
			t.Error("with the pre-activation lapsed, the publish showed RG1 ACTIVE: BASE came from " +
				"the previous process's pin (#19093)")
		}
	})
}
