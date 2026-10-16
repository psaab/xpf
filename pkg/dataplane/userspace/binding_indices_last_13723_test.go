package userspace

import (
	"errors"
	"os"
	"os/exec"
	"slices"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/psaab/xpf/pkg/dataplane"
)

type recordingBindingsMap13723 struct {
	writes    map[uint32]userspaceBindingValue
	updateErr map[uint32]error
}

func newRecordingBindingsMap13723() *recordingBindingsMap13723 {
	return &recordingBindingsMap13723{writes: make(map[uint32]userspaceBindingValue)}
}

func (f *recordingBindingsMap13723) Lookup(key, valueOut interface{}) error {
	k, ok := key.(uint32)
	if !ok {
		return errors.New("unexpected lookup key")
	}
	vp, ok := valueOut.(*userspaceBindingValue)
	if !ok {
		return errors.New("unexpected lookup value")
	}
	*vp = f.writes[k]
	return nil
}

func (f *recordingBindingsMap13723) Update(key, value interface{}, _ ebpf.MapUpdateFlags) error {
	k, ok := key.(uint32)
	if !ok {
		return errors.New("unexpected update key")
	}
	if err := f.updateErr[k]; err != nil {
		return err
	}
	v, ok := value.(userspaceBindingValue)
	if !ok {
		return errors.New("unexpected update value")
	}
	f.writes[k] = v
	return nil
}

func TestLastBindingIndicesPartialError13723(t *testing.T) {
	const liveIfindex = 7
	const badIfindex = int(dataplane.MaxInterfaces) + 42
	liveIdx := uint32(liveIfindex) * bindingQueuesPerIface

	t.Run("primary_bad_ifindex", func(t *testing.T) {
		m, _ := seamedManager(t)
		bindingsMap := newRecordingBindingsMap13723()
		m.helperStatusBindingsMapHook = bindingsMap
		m.lastBindingIndices = []uint32{999}

		status := readyHelperStatus()
		status.Bindings = append(status.Bindings, BindingStatus{
			Slot: 1, QueueID: 0, WorkerID: 1, Ifindex: badIfindex, Registered: true, Armed: true, Ready: true, Bound: true,
		})
		if err := m.applyHelperStatusLocked(status); err == nil {
			t.Fatal("want error")
		}
		if have, want := slices.Clone(m.lastBindingIndices), []uint32{999, liveIdx}; !slices.Equal(have, want) {
			t.Fatalf("partial-error m.lastBindingIndices = %v, want merged durable rows %v (old indices preserved + written rows)", have, want)
		}
	})

	t.Run("primary_bad_ifindex_preserves_old", func(t *testing.T) {
		m, _ := seamedManager(t)
		m.helperStatusBindingsMapHook = newRecordingBindingsMap13723()
		m.lastBindingIndices = []uint32{999}
		status := &ProcessStatus{Enabled: true, Workers: 1, NeighborGeneration: 1, Bindings: []BindingStatus{{Slot: 1, QueueID: 0, WorkerID: 1, Ifindex: badIfindex, Registered: true, Armed: true, Ready: true, Bound: true}}}
		if err := m.applyHelperStatusLocked(status); err == nil {
			t.Fatal("want error")
		}
		if !slices.Contains(m.lastBindingIndices, 999) {
			t.Fatalf("old index dropped on partial error: %v", m.lastBindingIndices)
		}
	})

	t.Run("primary_update_failure", func(t *testing.T) {
		m, _ := seamedManager(t)
		bindingsMap := newRecordingBindingsMap13723()
		bindingsMap.updateErr = map[uint32]error{liveIdx + 1: errors.New("boom")}
		m.helperStatusBindingsMapHook = bindingsMap
		m.lastBindingIndices = []uint32{999}
		status := readyHelperStatus()
		status.Bindings = append(status.Bindings, BindingStatus{Slot: 1, QueueID: 1, WorkerID: 1, Ifindex: liveIfindex, Registered: true, Armed: true, Ready: true, Bound: true})
		if err := m.applyHelperStatusLocked(status); err == nil {
			t.Fatal("want error")
		}
		if !slices.Contains(m.lastBindingIndices, liveIdx) || !slices.Contains(m.lastBindingIndices, 999) {
			t.Fatalf("successful first row not merged: %v", m.lastBindingIndices)
		}
	})

	t.Run("alias_update_failure", func(t *testing.T) {
		m, _ := seamedManager(t)
		bindingsMap := newRecordingBindingsMap13723()
		aliasIdx := uint32(99) * bindingQueuesPerIface
		bindingsMap.updateErr = map[uint32]error{aliasIdx: errors.New("alias boom")}
		m.helperStatusBindingsMapHook = bindingsMap
		m.lastBindingIndices = []uint32{999}
		m.lastSnapshot = &ConfigSnapshot{Interfaces: []InterfaceSnapshot{{
			Name: "ge-0/0/1.80", Zone: "wan", Ifindex: 99, ParentIfindex: liveIfindex, VLANID: 80,
		}}}
		if err := m.applyHelperStatusLocked(readyHelperStatus()); err == nil {
			t.Fatal("want alias update error")
		}
		if !slices.Contains(m.lastBindingIndices, liveIdx) || slices.Contains(m.lastBindingIndices, aliasIdx) || !slices.Contains(m.lastBindingIndices, 999) {
			t.Fatalf("alias partial-error inventory=%v, want old + primary row but not failed alias", m.lastBindingIndices)
		}
	})
}

func TestVerifyBindingsWatchdogRepairTracksIndex13723(t *testing.T) {
	m := New()
	bindingsMap := newRecordingBindingsMap13723()
	m.helperStatusBindingsMapHook = bindingsMap
	m.ctrlWasEnabled = true
	m.proc = &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
	m.lastStatus.Bindings = []BindingStatus{{Slot: 5, QueueID: 0, Ifindex: 7, Registered: true, Armed: true, Ready: true, Bound: true}}
	m.lastSnapshot = &ConfigSnapshot{Interfaces: []InterfaceSnapshot{{
		Name: "ge-0/0/1.80", Zone: "wan", Ifindex: 99, ParentIfindex: 7, VLANID: 80,
	}}}
	idx := uint32(7) * bindingQueuesPerIface
	aliasIdx := uint32(99) * bindingQueuesPerIface
	if repaired := m.verifyBindingsMapLocked(); !repaired {
		t.Fatalf("watchdog did not repair stale row idx=%d", idx)
	}
	if !slices.Contains(m.lastBindingIndices, idx) {
		t.Fatalf("watchdog repair not merged into m.lastBindingIndices=%v, want idx %d", m.lastBindingIndices, idx)
	}
	if !slices.Contains(m.lastBindingIndices, aliasIdx) {
		t.Fatalf("watchdog alias repair not merged into m.lastBindingIndices=%v, want idx %d", m.lastBindingIndices, aliasIdx)
	}
	var val userspaceBindingValue
	if err := bindingsMap.Lookup(idx, &val); err != nil || val.Slot != 5 {
		t.Fatalf("repaired row lookup err=%v val=%+v", err, val)
	}
	var aliasVal userspaceBindingValue
	if err := bindingsMap.Lookup(aliasIdx, &aliasVal); err != nil || aliasVal.Slot != 5 {
		t.Fatalf("repaired alias lookup err=%v val=%+v", err, aliasVal)
	}
	if repaired := m.verifyBindingsMapLocked(); repaired {
		t.Fatal("second watchdog pass should not repair populated row")
	}
	if n := countOccurrences13723(m.lastBindingIndices, idx); n != 1 {
		t.Fatalf("duplicate watchdog index count=%d inventory=%v", n, m.lastBindingIndices)
	}
	if n := countOccurrences13723(m.lastBindingIndices, aliasIdx); n != 1 {
		t.Fatalf("duplicate watchdog alias index count=%d inventory=%v", n, m.lastBindingIndices)
	}
}

func countOccurrences13723(xs []uint32, want uint32) int {
	n := 0
	for _, x := range xs {
		if x == want {
			n++
		}
	}
	return n
}
