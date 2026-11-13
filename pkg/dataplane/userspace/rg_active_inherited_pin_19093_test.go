package userspace

import (
	"errors"
	"os"
	"os/exec"
	"runtime"
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
// Every operation must produce a NEW request, and the verdict is read from
// the requests that operation produced (code review: an assertion of the form
// "no request said active" passes vacuously when nothing was published, which
// is exactly what a change that suppresses publication would do).
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

// published runs op and returns the inventory of the LAST request op produced.
// It fails the cell when op produced none: a verdict about what the helper was
// told needs the helper to have been told something.
func (p *rgActivePublish19093) published(t *testing.T, what string, op func()) map[int]HAGroupStatus {
	t.Helper()
	before := len(p.reqs)
	op()
	if len(p.reqs) <= before {
		t.Fatalf("%s published no update_ha_state (requests %d -> %d); the cell cannot judge what the helper was told",
			what, before, len(p.reqs))
	}
	return p.at(len(p.reqs) - 1)
}

// activeSince reports the index of the first request at or after from that
// told the helper rg was active, or -1.
func (p *rgActivePublish19093) activeSince(from, rg int) int {
	for i := from; i < len(p.reqs); i++ {
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
// applyCompiledSnapshot orders it — refresh from the maps, then publish — and
// returns the inventory that publish handed the helper.
func firstApplyHA19093(t *testing.T, m *Manager, p *rgActivePublish19093) map[int]HAGroupStatus {
	t.Helper()
	return p.published(t, "the first-apply HA tail", func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		if err := m.refreshHAStateFromMapsLocked(); err != nil {
			t.Fatalf("refreshHAStateFromMapsLocked: %v", err)
		}
		if err := m.syncHAStateLocked(); err != nil {
			// Steps of the tail AFTER the request are not under test; the
			// request itself is required by published().
			t.Logf("syncHAStateLocked tail: %v", err)
		}
	})
}

// replayHA19093 runs the production replay (helper respawn / debt
// convergence): refresh from the maps, then a full-inventory publish.
func replayHA19093(t *testing.T, m *Manager, p *rgActivePublish19093) map[int]HAGroupStatus {
	t.Helper()
	return p.published(t, "the HA replay", func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		m.pendingHAStateReplay = true
		if err := m.retryPendingHAStateReplayLocked(); err != nil {
			t.Logf("replay tail: %v", err)
		}
	})
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
// every RG. The first publish must tell the helper none of them is active, and
// the inherited slots — including the unconfigured one — must be cleared.
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

	got := firstApplyHA19093(t, m, pub)

	for _, g := range []int{0, 1, 2} {
		if _, ok := got[g]; !ok {
			t.Errorf("the first publish omitted configured RG%d", g)
		}
		if i := pub.activeSince(0, g); i >= 0 {
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
// import can refuse it. Both publishes must happen.
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
	firstApplyHA19093(t, m, pub)

	// A later commit adds the RG whose slot the previous process left at 1.
	m.mu.Lock()
	m.haGroups[last] = HAGroupStatus{RGID: last}
	m.mu.Unlock()
	from := len(pub.reqs)
	got := firstApplyHA19093(t, m, pub)

	if g, ok := got[last]; !ok {
		t.Errorf("the publish after configuring RG%d omitted it", last)
	} else if g.Active {
		t.Errorf("RG%d, configured after the restart, was published ACTIVE from the previous "+
			"process's pin while its clear was impossible (#19093)", last)
	}
	if i := pub.activeSince(from, last); i >= 0 {
		t.Errorf("request #%d after configuring RG%d carried it ACTIVE (#19093)", i, last)
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

	direct := pub.published(t, "UpdateRGActive(1,true)", func() {
		if err := m.UpdateRGActive(1, true); err != nil {
			t.Logf("UpdateRGActive tail: %v", err)
		}
	})
	if !direct[1].Active {
		t.Fatal("fixture: UpdateRGActive(1,true)'s own publish did not carry RG1 active")
	}
	if v := rgActiveSlot19093(t, rg, 1); v != 1 {
		t.Fatalf("fixture: UpdateRGActive(1,true) left rg_active[1]=%d", v)
	}

	helperGone19093(m)
	attachHelper19093(m, pub) // respawned helper
	got := replayHA19093(t, m, pub)

	if !got[1].Active {
		t.Error("the replay after a helper departure and respawn published RG1 INACTIVE although " +
			"THIS process wrote it active: the restart barrier must not be reset with the helper")
	}
	if v := rgActiveSlot19093(t, rg, 1); v != 1 {
		t.Errorf("rg_active[1] = %d after the replay; this process wrote 1", v)
	}
}

// M4: the publication race, in two shapes.
func TestRGActiveWriteBeforeFirstPublishIsKeptInheritedIsNot19093(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("creating a BPF map needs privilege (memlock rlimit / CAP_BPF): %v", err)
	}

	// M4a: a cluster event lands THIS process's true write after Start
	// published the registry and before the first apply's publish. With a
	// helper reachable, UpdateRGActive's own direct publish ({1:true,2:false}
	// even at master) comes first; the full sequence must carry RG1 true and
	// must NEVER carry the inherited RG2. RED at master (the post-refresh
	// publish carries RG2). Red for an implementation that zeroes every slot
	// at the first refresh (RG1 lost).
	t.Run("write before the first publish", func(t *testing.T) {
		rg, wd := newRGActiveArrays19093(t, map[uint32]uint8{2: 1})
		m := newRGActiveImportManager19093(t, rg, wd, 0, 1, 2)
		pub := attachHelper19093(m, nil)

		pub.published(t, "UpdateRGActive(1,true)", func() {
			if err := m.UpdateRGActive(1, true); err != nil {
				t.Logf("UpdateRGActive tail: %v", err)
			}
		})
		got := firstApplyHA19093(t, m, pub)

		if i := pub.activeSince(0, 2); i >= 0 {
			t.Errorf("update_ha_state #%d of %d carried RG2 ACTIVE from the previous process's pin "+
				"(#19093)", i, len(pub.reqs))
		}
		if !got[1].Active {
			t.Error("the post-refresh publish dropped RG1, which THIS process wrote active before " +
				"the first apply; a true first seed is legitimate when this process authorized it")
		}
		if v := rgActiveSlot19093(t, rg, 1); v != 1 {
			t.Errorf("rg_active[1] = %d after the first apply; this process wrote 1", v)
		}
	})

	// M4c: a PRODUCTION refresh (import + clear) races UpdateRGActive. The
	// writer is parked inside its m.mu+sessionMu hold, before the map write;
	// the refresher must be seen to contend for m.mu (a failed TryLock) while
	// the writer is parked, and only then is the writer released. The refresh
	// can only run after the write and its bit land, so it must import RG1 as
	// this process's ownership and must not clear the slot as inherited.
	t.Run("production refresh racing the write", func(t *testing.T) {
		rg, wd := newRGActiveArrays19093(t, map[uint32]uint8{2: 1})
		m := newRGActiveImportManager19093(t, rg, wd, 0, 1, 2)
		attachHelper19093(m, nil)

		parked := make(chan struct{})
		release := make(chan struct{})
		m.haRGActiveSessionHoldHook = func() {
			close(parked)
			<-release
		}
		writerDone := make(chan struct{})
		go func() {
			defer close(writerDone)
			_ = m.UpdateRGActive(1, true)
		}()
		<-parked

		contended := make(chan struct{})
		refreshDone := make(chan error, 1)
		go func() {
			signalled := false
			for !m.mu.TryLock() {
				if !signalled {
					close(contended)
					signalled = true
				}
				runtime.Gosched()
			}
			if !signalled {
				close(contended)
			}
			err := m.refreshHAStateFromMapsLocked()
			m.mu.Unlock()
			refreshDone <- err
		}()
		<-contended
		select {
		case err := <-refreshDone:
			t.Fatalf("the refresh completed while UpdateRGActive was parked holding m.mu (err=%v): "+
				"m.mu does not serialize the refresh with the write", err)
		default:
		}
		close(release)
		<-writerDone
		if err := <-refreshDone; err != nil {
			t.Fatalf("refreshHAStateFromMapsLocked: %v", err)
		}

		m.mu.Lock()
		rg1 := m.haGroups[1].Active
		rg2 := m.haGroups[2].Active
		m.mu.Unlock()
		if !rg1 {
			t.Error("the racing refresh imported RG1 inactive after this process's write landed: " +
				"it saw the 1 without its written bit")
		}
		if rg2 {
			t.Error("the racing refresh imported the inherited RG2 as ACTIVE (#19093)")
		}
		if v := rgActiveSlot19093(t, rg, 1); v != 1 {
			t.Errorf("rg_active[1] = %d after the racing refresh: this process's fresh 1 was cleared as inherited", v)
		}
		if v := rgActiveSlot19093(t, rg, 2); v != 0 {
			t.Errorf("inherited rg_active[2] = %d after the racing refresh, want it cleared", v)
		}
	})
}

// M5: clearing an inherited slot fails (the map is frozen). Each refresh must
// still PUBLISH, and say inactive.
//
// RED at master. Red for an implementation that suppresses publication after
// a failed clear.
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

	for pass := 1; pass <= 2; pass++ {
		got := firstApplyHA19093(t, m, pub)
		if g, ok := got[1]; !ok || g.Active {
			t.Errorf("refresh %d published RG1 %+v (present=%v): an inherited pin whose clear "+
				"failed must be published inactive (#19093)", pass, g, ok)
		}
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
	pubA.published(t, "A: UpdateRGActive(1,true)", func() {
		if err := a.UpdateRGActive(1, true); err != nil {
			t.Logf("A: UpdateRGActive tail: %v", err)
		}
	})
	helperGone19093(a)
	reopened, err := rg.Clone()
	if err != nil {
		t.Fatalf("clone rg_active handle: %v", err)
	}
	t.Cleanup(func() { reopened.Close() })
	injectShimMap(t, a.bpfShim, "rg_active", reopened)
	attachHelper19093(a, pubA)
	if gotA := firstApplyHA19093(t, a, pubA); !gotA[1].Active {
		t.Error("process A lost its own RG1=active across a helper stop and a re-opened pin " +
			"handle; authority must follow the process, not the helper or the handle")
	}

	// A dies uncleanly; process B starts over the pin A left.
	b := newRGActiveImportManager19093(t, rg, wd, 0, 1, 2)
	pubB := attachHelper19093(b, nil)
	if gotB := firstApplyHA19093(t, b, pubB); gotB[1].Active {
		t.Error("a new process published RG1 ACTIVE from the pin a dead process left (#19093)")
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
			if got := firstApplyHA19093(t, m, pub); got[1].Active {
				t.Errorf("RG1 was published ACTIVE from the inherited pin after this process's own "+
					"%s FAILED; only a landed write is ownership (#19093)", tc.name)
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
		if got := replayHA19093(t, m, pub); !got[1].Active {
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
		if got := replayHA19093(t, m, pub); got[1].Active {
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
		firstApplyHA19093(t, m, pub)

		m.BeginTransferPreActivation([]int{1}, time.Now().Add(time.Minute))
		opened := pub.published(t, "PublishTransferPreActivation", func() {
			if err := m.PublishTransferPreActivation(); err != nil {
				t.Logf("pre-activation publish tail: %v", err)
			}
		})
		if !opened[1].Active {
			t.Fatal("the pre-activation did not open RG1 for the transfer; the overlay must keep working over an inherited pin")
		}
		var changed bool
		released := pub.published(t, "EndTransferPreActivation (a reverted transfer must republish)", func() {
			var err error
			changed, err = m.EndTransferPreActivation([]int{1})
			if err != nil {
				t.Logf("release publish tail: %v", err)
			}
		})
		if !changed {
			t.Error("releasing the pre-activation reported no change: BASE still says RG1 is active, " +
				"which only the previous process's pin could have made true (#19093)")
		}
		if released[1].Active {
			t.Error("the publish after the abandoned transfer was released still has RG1 ACTIVE (#19093)")
		}
	})

	// M8b: the real promotion supersedes the overlay and becomes BASE.
	t.Run("promotion supersedes and is kept", func(t *testing.T) {
		rg, wd := newRGActiveArrays19093(t, map[uint32]uint8{1: 1})
		m := newRGActiveImportManager19093(t, rg, wd, 0, 1, 2)
		pub := attachHelper19093(m, nil)
		firstApplyHA19093(t, m, pub)
		m.BeginTransferPreActivation([]int{1}, time.Now().Add(time.Minute))
		if err := m.UpdateRGActive(1, true); err != nil {
			t.Logf("promotion tail: %v", err)
		}
		if got := m.TransferPreActiveRGs(); len(got) != 0 {
			t.Errorf("the promotion did not supersede the pre-activation: still pre-active %v", got)
		}
		if got := replayHA19093(t, m, pub); !got[1].Active {
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
		if got := firstApplyHA19093(t, m, pub); got[1].Active {
			t.Error("with the pre-activation lapsed, the publish showed RG1 ACTIVE: BASE came from " +
				"the previous process's pin (#19093)")
		}
	})
}
