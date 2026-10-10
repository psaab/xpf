package userspace

import (
	"errors"
	"os"
	"os/exec"
	"reflect"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

func withRevalidationSample12213(t *testing.T, ifindex int) {
	t.Helper()
	previousBuild := buildLinkSnapshot
	previousLookup := linkByNameFn
	t.Cleanup(func() {
		buildLinkSnapshot = previousBuild
		linkByNameFn = previousLookup
	})
	buildLinkSnapshot = func(string) (int, int, string, []InterfaceAddressSnapshot) {
		return ifindex, 1500, "", nil
	}
	linkByNameFn = func(string) (netlink.Link, error) { return nil, errors.New("test link lookup") }
}

func retainedInterfaceRows12213() []InterfaceSnapshot {
	linkUp := true
	return []InterfaceSnapshot{
		{Name: "ge-0/0/0", Zone: "blue", LinuxName: "eth12213", Ifindex: 23, RXQueues: 4, LinkUp: &linkUp},
	}
}

func TestFailedPartialPublishPreservesRetainedInterfacesAndHash12213(t *testing.T) {
	withRevalidationSample12213(t, 0) // the interface disappears at the send boundary
	m := New()
	m.proc = &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
	m.lastStatus.ConfigSnapshotProtocolVersion = ProtocolVersion
	m.helperStatusObserved = true
	rows := retainedInterfaceRows12213()
	linkUp := false
	rows = append(rows, InterfaceSnapshot{Name: "lo0", Ifindex: 1, LinkUp: &linkUp})
	rows = append(rows, InterfaceSnapshot{Name: "tail-sentinel"})
	m.lastSnapshot = &ConfigSnapshot{
		Version: ProtocolVersion, Generation: 7,
		Config: &config.Config{}, Interfaces: rows[:2],
	}
	// Reserve spare capacity so the assertion also observes the compacted tail,
	// not only the retained slice's current length.
	beforeBacking := append([]InterfaceSnapshot(nil), m.lastSnapshot.Interfaces[:cap(m.lastSnapshot.Interfaces)]...)
	retainedLinkUp := m.lastSnapshot.Interfaces[1].LinkUp
	beforeHash, ok := snapshotContentHash(m.lastSnapshot)
	if !ok {
		t.Fatal("could not hash retained snapshot")
	}
	m.lastSnapshotHash = beforeHash
	m.generation = m.lastSnapshot.Generation
	var sentLinkUp *bool
	m.controlRequestHook = func(req ControlRequest, _ *ProcessStatus) error {
		if req.Type == "apply_snapshot" {
			if len(req.Snapshot.Interfaces) > 0 {
				sentLinkUp = req.Snapshot.Interfaces[0].LinkUp
			}
			return errors.New("scripted partial-publish failure")
		}
		return nil
	}
	err := m.UpdatePolicyScheduleStateWithLatch(m.lastSnapshot.Config, map[string]bool{}, false)
	if err == nil {
		t.Fatal("expected scripted publish failure")
	}
	if sentLinkUp == nil || sentLinkUp == retainedLinkUp {
		t.Errorf("send snapshot did not receive an independently copied LinkUp pointer")
	}
	if got := m.lastSnapshot.Interfaces[:cap(m.lastSnapshot.Interfaces)]; !reflect.DeepEqual(got, beforeBacking) {
		t.Errorf("failed partial publish mutated retained interface backing array:\n got=%+v\nwant=%+v", got, beforeBacking)
	}
	if got, ok := snapshotContentHash(m.lastSnapshot); !ok || got != beforeHash {
		t.Errorf("failed partial publish changed retained content hash: got=%x ok=%v want=%x", got, ok, beforeHash)
	}
	if m.lastSnapshotHash != beforeHash {
		t.Errorf("stored retained hash changed: got=%x want=%x", m.lastSnapshotHash, beforeHash)
	}
}

func TestCompileStoresSentPlanKeyAfterInterfaceRevalidation12213(t *testing.T) {
	withRevalidationSample12213(t, 99)
	f := newFixture9824(t)
	snap := f.snap9824(9, nil, nil, nil)
	f.m.programBootstrapMapsHook = func(*ConfigSnapshot, config.UserspaceConfig) error { return nil }
	snap.Interfaces = retainedInterfaceRows12213()
	var sentPlanKey string
	f.m.controlRequestHook = func(req ControlRequest, status *ProcessStatus) error {
		if req.Type == "apply_snapshot" {
			sentPlanKey = snapshotBindingPlanKey(req.Snapshot)
		}
		return f.model.hook(req, status)
	}
	if _, err := f.apply(t, snap); err != nil && f.m.publishedSnapshot == 0 {
		t.Fatalf("applyCompiledSnapshot failed before publication: %v", err)
	}
	if sentPlanKey == "" || sentPlanKey == snapshotBindingPlanKey(&ConfigSnapshot{Interfaces: retainedInterfaceRows12213()}) {
		t.Fatalf("test did not observe a changed sent plan key: %q", sentPlanKey)
	}
	if f.m.publishedPlanKey != sentPlanKey {
		t.Fatalf("stored plan key does not match exact sent snapshot: stored=%q sent=%q", f.m.publishedPlanKey, sentPlanKey)
	}
	if f.m.lastSnapshot.Interfaces[0].Ifindex != 99 {
		t.Fatalf("retained Compile snapshot does not match sent interface row: %+v", f.m.lastSnapshot.Interfaces)
	}
}

func TestDeferredPublishStoresSentPlanKeyAfterInterfaceRevalidation12213(t *testing.T) {
	withRevalidationSample12213(t, 99)
	f := newFixture9824(t)
	snap := f.snap9824(9, nil, nil, nil)
	snap.Interfaces = retainedInterfaceRows12213()
	f.m.mu.Lock()
	f.m.lastSnapshot = snap
	f.m.generation = snap.Generation
	f.m.publishedSnapshot = 0
	f.m.publishedPlanKey = ""
	f.m.mu.Unlock()
	var sentPlanKey string
	f.m.controlRequestHook = func(req ControlRequest, status *ProcessStatus) error {
		if req.Type == "apply_snapshot" {
			sentPlanKey = snapshotBindingPlanKey(req.Snapshot)
		}
		return f.model.hook(req, status)
	}
	if err := f.tick(t); err != nil {
		t.Fatalf("syncSnapshotLocked: %v", err)
	}
	if sentPlanKey == "" {
		t.Fatal("deferred path did not send an apply_snapshot")
	}
	if f.m.publishedPlanKey != sentPlanKey {
		t.Fatalf("stored deferred plan key does not match exact sent snapshot: stored=%q sent=%q", f.m.publishedPlanKey, sentPlanKey)
	}
	if f.m.lastSnapshot.Interfaces[0].Ifindex != 99 {
		t.Fatalf("retained deferred snapshot does not match sent interface row: %+v", f.m.lastSnapshot.Interfaces)
	}
}
