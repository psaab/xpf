package userspace

import (
	"errors"
	"os"
	"os/exec"
	"reflect"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// #19093, the unprivileged half. rg_active_inherited_pin_19093_test.go drives
// the real map paths and needs the privilege to create a BPF map; these cells
// pin the same barrier where no privilege is needed, so they run on every
// ordinary `make test` (the census's preferred remedy, pkg/memlockcensus).

// U1: the pure merge core. A slot's value is BASE ownership only if this
// process wrote it; every non-zero slot it did not write is reported
// inherited, configured or not, and never added to the inventory.
func TestMergeHAStateMasksSlotsThisProcessNeverWrote19093(t *testing.T) {
	var written [dataplane.MaxRedundancyGroups]bool
	written[0] = true // this process wrote 1
	written[3] = true // this process wrote 0
	last := dataplane.MaxRedundancyGroups - 1
	rgVals := map[int]uint8{
		0:    1, // written 1        -> active
		1:    1, // inherited 1      -> inactive, inherited
		2:    0, // never written 0  -> inactive, not inherited
		3:    0, // written 0        -> inactive
		last: 1, // inherited, unconfigured -> inherited, not added
		99:   1, // outside the array -> never written, never added
	}
	existing := map[int]HAGroupStatus{0: {RGID: 0}, 1: {RGID: 1}, 2: {RGID: 2}, 3: {RGID: 3}}

	merged, inherited := mergeHAState(rgVals, map[int]uint64{1: 77}, existing, &written)

	if !merged[0].Active {
		t.Error("RG0: a slot this process wrote 1 was not imported as active")
	}
	for _, rg := range []int{1, 2, 3} {
		if merged[rg].Active {
			t.Errorf("RG%d imported ACTIVE; only a slot this process wrote 1 is ownership", rg)
		}
	}
	if merged[1].WatchdogTimestamp != 77 {
		t.Errorf("RG1 watchdog = %d, want 77: masking ownership must not drop the watchdog", merged[1].WatchdogTimestamp)
	}
	if _, ok := merged[last]; ok {
		t.Errorf("unconfigured slot %d was added to the inventory", last)
	}
	if _, ok := merged[99]; ok {
		t.Error("an out-of-array key was added to the inventory")
	}
	if want := []int{1, last, 99}; !reflect.DeepEqual(inherited, want) {
		t.Errorf("inherited = %v, want %v (every non-zero slot this process did not write, sorted)", inherited, want)
	}
}

// U2: no mask at all is the most defensive reading: nothing is ownership.
func TestMergeHAStateNilMaskOwnsNothing19093(t *testing.T) {
	merged, inherited := mergeHAState(map[int]uint8{1: 1}, nil,
		map[int]HAGroupStatus{1: {RGID: 1}}, nil)
	if merged[1].Active {
		t.Error("with no write mask, an rg_active 1 was imported as ownership")
	}
	if !reflect.DeepEqual(inherited, []int{1}) {
		t.Errorf("inherited = %v, want [1]", inherited)
	}
}

// M4b: the bit and the write are published together. Inside UpdateRGActive's
// m.mu+sessionMu hold, right after the map write lands, the bit must already
// be set and m.mu must still be held — every refresh takes m.mu, so no
// refresh can observe the landed 1 without its bit. Map-free: the write goes
// through the haRGActiveMapWrite seam, so this runs unprivileged on every
// `make test`. The racing PRODUCTION refresh/clear (with demonstrated m.mu
// contention and post-refresh pin and ownership assertions) is the privileged
// M4c subtest in rg_active_inherited_pin_19093_test.go.
func TestRGActiveWrittenBitIsAtomicWithTheMapWrite19093(t *testing.T) {
	var pin [dataplane.MaxRedundancyGroups]uint8

	m := New()
	m.clusterHA = true
	m.haGroups = map[int]HAGroupStatus{0: {RGID: 0}, 1: {RGID: 1}}
	m.haRGActiveMapWrite = func(rgID int, active bool) error {
		if active {
			pin[rgID] = 1
		} else {
			pin[rgID] = 0
		}
		return nil
	}
	// Stop UpdateRGActive right after its publish attempt: the property under
	// test is complete by then, and the status tail needs maps this cell does
	// not load.
	m.proc = &exec.Cmd{Process: &os.Process{Pid: 1}}
	m.controlRequestHook = func(ControlRequest, *ProcessStatus) error {
		return errors.New("stop after publish (#19093 cell)")
	}

	var hookRan, bitSetInHook, muHeldInHook bool
	var pinInHook uint8
	m.haRGActiveAfterMapWriteHook = func() {
		hookRan = true
		pinInHook = pin[1]
		bitSetInHook = m.rgActiveWritten[1]
		if m.mu.TryLock() {
			m.mu.Unlock()
		} else {
			muHeldInHook = true
		}
	}

	_ = m.UpdateRGActive(1, true)

	if !hookRan {
		t.Fatal("haRGActiveAfterMapWriteHook never ran: the write did not land, so the cell judged nothing")
	}
	if pinInHook != 1 {
		t.Fatalf("fixture: the hook ran before the map write landed (rg_active[1]=%d)", pinInHook)
	}
	if !bitSetInHook {
		t.Error("right after the rg_active write landed, inside UpdateRGActive's lock hold, the " +
			"written bit was still unset: a refresh between the two would clear this process's " +
			"own 1 as inherited (#19093)")
	}
	if !muHeldInHook {
		t.Error("m.mu was not held when the rg_active write landed; the write and its bit are not " +
			"serialized with refresh")
	}
	m.mu.Lock()
	written := m.rgActiveWritten[1]
	m.mu.Unlock()
	if !written {
		t.Error("after UpdateRGActive returned (its helper publish failed), the written bit was unset: " +
			"a landed map write is this process's ownership whatever the IPC did")
	}
}

// U3: the array's BOUNDARY slots (0 and MaxRedundancyGroups-1) that this
// process wrote are ownership like any other. R20 review: a bound mutant
// (`rgID < len(written)-1`) passed every other cell, yet it would mask this
// process's own RG15 and then clear its pin about a second after takeover — a
// self-blackhole of the last RG.
func TestMergeHAStateOwnsBoundarySlotsThisProcessWrote19093(t *testing.T) {
	last := dataplane.MaxRedundancyGroups - 1
	var written [dataplane.MaxRedundancyGroups]bool
	written[0], written[last] = true, true
	merged, inherited := mergeHAState(
		map[int]uint8{0: 1, 1: 1, last: 1}, nil,
		map[int]HAGroupStatus{0: {RGID: 0}, 1: {RGID: 1}, last: {RGID: last}}, &written)
	if !merged[0].Active {
		t.Error("slot 0, written 1 by this process, was not imported as ownership")
	}
	if !merged[last].Active {
		t.Errorf("slot %d (the last), written 1 by this process, was not imported as ownership", last)
	}
	if merged[1].Active {
		t.Error("inherited slot 1 was imported as ownership")
	}
	if !reflect.DeepEqual(inherited, []int{1}) {
		t.Errorf("inherited = %v, want [1]: a boundary slot this process wrote must never be "+
			"reported inherited (and so cleared)", inherited)
	}
}

// U4: UpdateRGActive marks the boundary slots too (the write side of U3).
func TestUpdateRGActiveMarksBoundarySlots19093(t *testing.T) {
	last := dataplane.MaxRedundancyGroups - 1
	m := New()
	m.clusterHA = true
	m.haGroups = map[int]HAGroupStatus{0: {RGID: 0}, last: {RGID: last}}
	m.haRGActiveMapWrite = func(int, bool) error { return nil }
	m.proc = &exec.Cmd{Process: &os.Process{Pid: 1}}
	m.controlRequestHook = func(ControlRequest, *ProcessStatus) error {
		return errors.New("stop after publish (#19093 cell)")
	}
	for _, rg := range []int{0, last} {
		_ = m.UpdateRGActive(rg, true)
	}
	m.mu.Lock()
	w0, wl := m.rgActiveWritten[0], m.rgActiveWritten[last]
	m.mu.Unlock()
	if !w0 {
		t.Error("UpdateRGActive(0, true) landed but slot 0 was not marked as this process's write")
	}
	if !wl {
		t.Errorf("UpdateRGActive(%d, true) landed but the last slot was not marked as this process's write", last)
	}
}
