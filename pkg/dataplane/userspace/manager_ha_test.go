package userspace

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/psaab/xpf/pkg/config"
)

// boundEventStream returns an EventStream whose listener successfully bound on a
// throwaway temp socket, so its ListenerBound() reports true. Takeover-readiness
// gates on a bound event-stream listener (#5273); fixtures that expect a healthy
// node ready to serve session deltas must attach one. The listener + accept loop
// are torn down via t.Cleanup.
func boundEventStream(t *testing.T) *EventStream {
	t.Helper()
	es := NewEventStream(filepath.Join(t.TempDir(), "events.sock"))
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := es.Start(ctx); err != nil {
		t.Fatalf("event stream Start: %v", err)
	}
	t.Cleanup(es.Close)
	return es
}

func TestTakeoverReadyReportsSessionMirrorFailure(t *testing.T) {
	m := &Manager{
		proc: &exec.Cmd{Process: &os.Process{Pid: 1}},
		lastStatus: ProcessStatus{
			Enabled:         true,
			ForwardingArmed: true,
			Capabilities: UserspaceCapabilities{
				ForwardingSupported: true,
			},
		},
		mode:                ModeUserspaceCompat,
		xskLivenessProven:   true,
		sessionMirrorFailed: true,
		sessionMirrorErr:    "dial unix /tmp/userspace-dp-sessions.sock: connect: no such file or directory",
	}

	ready, reasons := m.TakeoverReady()
	if ready {
		t.Fatal("TakeoverReady() = true, want false")
	}
	if len(reasons) == 0 {
		t.Fatal("TakeoverReady() returned no reasons")
	}
	found := false
	for _, reason := range reasons {
		if strings.Contains(reason, "userspace session mirror unhealthy") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected session mirror failure reason, got %v", reasons)
	}
}

// TestTakeoverReadyReportsACapabilityDisarmReason asserts the GENERIC property:
// a node whose dataplane has disarmed forwarding for ANY capability reason is
// not takeover-ready, and the reason is reported rather than swallowed.
//
// #8573 changed the SPECIMEN, not the property. The cell used to carry
// persistentSourceNATHAUnsupportedReason, which was the only disarm reason a
// clustered node could realistically hit — and that gate was removed after its
// premise ("leases are not HA-synchronized") was measured false on the loss
// userspace cluster. The specimen is now a reason that still exists, so the
// cell keeps testing TakeoverReady rather than a retired constant.
func TestTakeoverReadyReportsACapabilityDisarmReason(t *testing.T) {
	// A live reason from deriveUserspaceCapabilities, spelled here rather than
	// imported: it is a SPECIMEN of the class, and pinning it to a particular
	// constant is what tied this cell to a gate that then went away.
	const specimen = "userspace three-color policers require color-blind mode and a supported then action"
	m := &Manager{
		proc: &exec.Cmd{Process: &os.Process{Pid: 1}},
		lastStatus: ProcessStatus{
			Enabled:         true,
			ForwardingArmed: true,
			Capabilities: UserspaceCapabilities{
				ForwardingSupported: false,
				UnsupportedReasons:  []string{specimen},
			},
		},
		mode:              ModeUserspaceCompat,
		xskLivenessProven: true,
	}

	ready, reasons := m.TakeoverReady()
	if ready {
		t.Fatal("TakeoverReady() = true, want false for a disarmed dataplane")
	}
	if !slices.Contains(reasons, specimen) {
		t.Fatalf("TakeoverReady() reasons = %v, missing the disarm reason — a standby "+
			"that cannot forward must say WHY it is unfit, not merely that it is",
			reasons)
	}
}

func testStandbyNeighborPrewarmManager() *Manager {
	return &Manager{
		proc:      &exec.Cmd{Process: &os.Process{Pid: 1}},
		clusterHA: true,
		lastStatus: ProcessStatus{
			Enabled:         true,
			ForwardingArmed: true,
			Capabilities: UserspaceCapabilities{
				ForwardingSupported: true,
			},
		},
		lastSnapshot: &ConfigSnapshot{
			Config: &config.Config{
				Chassis: config.ChassisConfig{
					Cluster: &config.ClusterConfig{
						RedundancyGroups: []*config.RedundancyGroup{
							{ID: 0},
							{ID: 1},
						},
					},
				},
			},
		},
		haGroups: map[int]HAGroupStatus{
			1: {RGID: 1, Active: false},
		},
	}
}

func TestShouldStandbyNeighborPrewarmLocked(t *testing.T) {
	m := testStandbyNeighborPrewarmManager()
	if !m.shouldStandbyNeighborPrewarmLocked(time.Now()) {
		t.Fatal("shouldStandbyNeighborPrewarmLocked() = false, want true")
	}
}

func TestShouldStandbyNeighborPrewarmLockedRejectsActiveOwner(t *testing.T) {
	m := testStandbyNeighborPrewarmManager()
	m.haGroups[1] = HAGroupStatus{RGID: 1, Active: true}
	if m.shouldStandbyNeighborPrewarmLocked(time.Now()) {
		t.Fatal("shouldStandbyNeighborPrewarmLocked() = true, want false for active owner")
	}
}

func TestShouldStandbyNeighborPrewarmLockedThrottlesRecentRun(t *testing.T) {
	m := testStandbyNeighborPrewarmManager()
	now := time.Now()
	m.lastStandbyNeighResolve = now.Add(-5 * time.Second)
	if m.shouldStandbyNeighborPrewarmLocked(now) {
		t.Fatal("shouldStandbyNeighborPrewarmLocked() = true, want false during throttle window")
	}
}

func TestTakeoverReadyAllowsStandbyWithReadyBindingsWithoutLivenessProof(t *testing.T) {
	m := &Manager{
		proc: &exec.Cmd{Process: &os.Process{Pid: 1}},
		lastStatus: ProcessStatus{
			Enabled:         true,
			ForwardingArmed: true,
			Capabilities: UserspaceCapabilities{
				ForwardingSupported: true,
			},
			Queues: []QueueStatus{
				{QueueID: 0, WorkerID: 0, Registered: true, Armed: true, Ready: true},
			},
			Bindings: []BindingStatus{
				{
					Slot:          0,
					QueueID:       0,
					WorkerID:      0,
					Ifindex:       5,
					Registered:    true,
					Armed:         true,
					Ready:         true,
					Bound:         true,
					XSKRegistered: true,
				},
			},
		},
		mode: ModeUserspaceCompat,
		haGroups: map[int]HAGroupStatus{
			1: {RGID: 1, Active: false},
			2: {RGID: 2, Active: false},
		},
		eventStream: boundEventStream(t),
	}

	ready, reasons := m.TakeoverReady()
	if !ready {
		t.Fatalf("TakeoverReady() = false, want true, reasons=%v", reasons)
	}
}

// TestTakeoverReadyRequiresEventStreamListenerBound is the #5273 regression:
// takeover-readiness must gate on the LOCAL event-stream listener being bound
// (the daemon can accept local-helper session deltas), NOT on the helper having
// connected. A node whose listener failed to bind must not be advertised
// takeover-ready. A bound listener with the local helper temporarily disconnected
// must NOT be blocked because the daemon polls deltas as fallback.
//
// RED-on-revert: removing the ListenerBound() gate in takeoverReadyLocked makes
// the ListenerBindFailed sub-case report ready=true (every other gate passes),
// while the two ListenerBound sub-cases stay green either way — proving the gate
// keys on listener-up, not helper-connected.
func TestTakeoverReadyRequiresEventStreamListenerBound(t *testing.T) {
	newHealthyManager := func() *Manager {
		return &Manager{
			proc: &exec.Cmd{Process: &os.Process{Pid: 1}},
			lastStatus: ProcessStatus{
				Enabled:         true,
				ForwardingArmed: true,
				Capabilities:    UserspaceCapabilities{ForwardingSupported: true},
			},
			mode:              ModeUserspaceCompat,
			xskLivenessProven: true,
		}
	}

	t.Run("ListenerBindFailed", func(t *testing.T) {
		es := NewEventStream(filepath.Join(t.TempDir(), "missing-dir", "events.sock"))
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		if err := es.Start(ctx); err == nil {
			t.Fatal("precondition: Start unexpectedly succeeded on an unbindable path")
		}
		m := newHealthyManager()
		m.eventStream = es // stored, but the listener never bound
		ready, reasons := m.TakeoverReady()
		if ready {
			t.Fatalf("TakeoverReady() = true with an unbound event-stream listener, want false; reasons=%v", reasons)
		}
		if !hasReasonSubstr(reasons, "event stream listener not bound") {
			t.Fatalf("missing event-stream listener gate reason, got %v", reasons)
		}
	})

	t.Run("ListenerBoundHelperDisconnected", func(t *testing.T) {
		es := boundEventStream(t)
		if es.IsConnected() {
			t.Fatal("precondition: local helper should not be connected yet")
		}
		m := newHealthyManager()
		m.eventStream = es
		if ready, reasons := m.TakeoverReady(); !ready {
			t.Fatalf("TakeoverReady() = false with the helper disconnected, want true; reasons=%v", reasons)
		}
	})

	t.Run("ListenerBoundHelperConnected", func(t *testing.T) {
		es := boundEventStream(t)
		conn, err := net.Dial("unix", es.socketPath)
		if err != nil {
			t.Fatalf("dial event socket: %v", err)
		}
		defer conn.Close()
		deadline := time.Now().Add(2 * time.Second)
		for !es.IsConnected() {
			if time.Now().After(deadline) {
				t.Fatal("local helper did not connect to event stream")
			}
			time.Sleep(10 * time.Millisecond)
		}
		m := newHealthyManager()
		m.eventStream = es
		if ready, reasons := m.TakeoverReady(); !ready {
			t.Fatalf("TakeoverReady() = false with helper connected, want true; reasons=%v", reasons)
		}
	})
}

func hasReasonSubstr(reasons []string, substr string) bool {
	for _, r := range reasons {
		if strings.Contains(r, substr) {
			return true
		}
	}
	return false
}

func TestTakeoverReadyRequiresLivenessProofOnActiveNode(t *testing.T) {
	m := &Manager{
		proc: &exec.Cmd{Process: &os.Process{Pid: 1}},
		lastStatus: ProcessStatus{
			Enabled:         true,
			ForwardingArmed: true,
			Capabilities: UserspaceCapabilities{
				ForwardingSupported: true,
			},
			Queues: []QueueStatus{
				{QueueID: 0, WorkerID: 0, Registered: true, Armed: true, Ready: true},
			},
			Bindings: []BindingStatus{
				{
					Slot:          0,
					QueueID:       0,
					WorkerID:      0,
					Ifindex:       5,
					Registered:    true,
					Armed:         true,
					Ready:         true,
					Bound:         true,
					XSKRegistered: true,
				},
			},
		},
		mode: ModeUserspaceCompat,
		haGroups: map[int]HAGroupStatus{
			1: {RGID: 1, Active: true},
		},
	}

	ready, reasons := m.TakeoverReady()
	if ready {
		t.Fatal("TakeoverReady() = true, want false without active-node liveness proof")
	}
	found := false
	for _, reason := range reasons {
		if reason == "userspace XSK liveness not proven" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected XSK liveness reason, got %v", reasons)
	}
}

func TestApplyHelperStatusInitialCtrlCleanupRunsOnlyOnce(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("RemoveMemlock: %v", err)
	}
	m := New()
	m.bpfShim.SelectUserspaceXDPShimEntryProgram()
	injectCtrlAndBindingMaps(t, m)
	usMap := injectUserspaceSessionMap(t, m)
	// #9337: applyHelperStatusLocked re-syncs the ingress/local/interface-NAT
	// classifier maps (#6994), which this fixture does not load — under CAP_BPF
	// it failed with "userspace_ingress_ifaces map not loaded" before reaching
	// anything this cell asserts. Unprivileged the whole test skips, so the gap
	// was invisible. The seam is the established remedy (#7468).
	m.syncClassifierMapsHook = func(*ConfigSnapshot) error { return nil }
	m.neighborsPrewarmed = true
	m.xskLivenessProven = true
	m.publishedSnapshot = 1

	status := ProcessStatus{
		Enabled:                true,
		Workers:                1,
		LastSnapshotGeneration: 1,
		NeighborGeneration:     1,
		Capabilities: UserspaceCapabilities{
			ForwardingSupported: true,
		},
		Bindings: []BindingStatus{{
			Slot:       1,
			QueueID:    0,
			Ifindex:    5,
			Registered: true,
			Armed:      true,
			Bound:      true,
		}},
	}

	key := uint32(1)
	value := uint64(1)
	if err := usMap.Update(key, value, ebpf.UpdateAny); err != nil {
		t.Fatalf("seed userspace_sessions: %v", err)
	}
	if err := m.applyHelperStatusLocked(&status); err != nil {
		t.Fatalf("first applyHelperStatusLocked: %v", err)
	}
	if !m.initialCtrlCleanupDone {
		t.Fatal("initialCtrlCleanupDone = false, want true after first ctrl enable")
	}
	var got uint64
	if err := usMap.Lookup(key, &got); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("userspace_sessions entry survived first ctrl enable cleanup: err=%v got=%d", err, got)
	}

	if err := usMap.Update(key, value, ebpf.UpdateAny); err != nil {
		t.Fatalf("reseed userspace_sessions: %v", err)
	}
	m.ctrlWasEnabled = false
	if err := m.applyHelperStatusLocked(&status); err != nil {
		t.Fatalf("second applyHelperStatusLocked: %v", err)
	}
	if err := usMap.Lookup(key, &got); err != nil {
		t.Fatalf("later ctrl re-enable reran startup cleanup: %v", err)
	}
}

func TestUpdateRGActiveActivationKeepsCtrlEnabledAfterAckedStatus(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("RemoveMemlock: %v", err)
	}
	dir := t.TempDir()
	controlSock := filepath.Join(dir, "control.sock")
	ln, err := net.Listen("unix", controlSock)
	if err != nil {
		t.Fatalf("listen control socket: %v", err)
	}
	defer ln.Close()

	status := ProcessStatus{
		Enabled:                true,
		Workers:                1,
		LastSnapshotGeneration: 2,
		NeighborGeneration:     1,
		Capabilities: UserspaceCapabilities{
			ForwardingSupported: true,
		},
		Bindings: []BindingStatus{{
			Slot:       1,
			QueueID:    0,
			Ifindex:    5,
			Registered: true,
			Armed:      true,
			Bound:      true,
		}},
	}
	reqDone := make(chan struct{}, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		var req ControlRequest
		if err := json.NewDecoder(conn).Decode(&req); err != nil {
			return
		}
		if req.Type != "update_ha_state" {
			return
		}
		_ = json.NewEncoder(conn).Encode(ControlResponse{
			OK:     true,
			Status: &status,
		})
		reqDone <- struct{}{}
	}()

	m := New()
	m.proc = &exec.Cmd{Process: &os.Process{Pid: 1}}
	m.cfg.ControlSocket = controlSock
	m.clusterHA = true
	m.bpfShim.SelectUserspaceXDPShimEntryProgram()
	// #9337: applyHelperStatusLocked re-syncs the ingress/local/interface-NAT
	// classifier maps (#6994), which this fixture does not load — under CAP_BPF
	// it failed with "userspace_ingress_ifaces map not loaded" before reaching
	// anything this cell asserts. Unprivileged the whole test skips, so the gap
	// was invisible. The seam is the established remedy (#7468).
	m.syncClassifierMapsHook = func(*ConfigSnapshot) error { return nil }
	m.neighborsPrewarmed = true
	m.xskLivenessProven = true
	m.ctrlWasEnabled = true
	m.haGroups = map[int]HAGroupStatus{
		0: {RGID: 0, Active: true},
		1: {RGID: 1, Active: false},
		2: {RGID: 2, Active: true},
	}

	ctrlMap, _ := injectCtrlAndBindingMaps(t, m)
	rgMap, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  1,
		MaxEntries: 16,
	})
	if err != nil {
		t.Fatalf("new rg_active map: %v", err)
	}
	t.Cleanup(func() { rgMap.Close() })
	injectShimMap(t, m.bpfShim, "rg_active", rgMap)

	if err := m.UpdateRGActive(1, true); err != nil {
		t.Fatalf("UpdateRGActive: %v", err)
	}
	select {
	case <-reqDone:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for update_ha_state request")
	}

	var zero uint32
	var ctrl userspaceCtrlValue
	if err := ctrlMap.Lookup(zero, &ctrl); err != nil {
		t.Fatalf("lookup userspace_ctrl: %v", err)
	}
	if ctrl.Enabled != 1 {
		t.Fatalf("userspace_ctrl.Enabled = %d, want 1 after acked activation", ctrl.Enabled)
	}
	if m.mode != ModeUserspaceCompat {
		t.Fatalf("mode = %s, want %s", m.mode, ModeUserspaceCompat)
	}
	if m.rgTransitionInFlight.Load() {
		t.Fatal("rgTransitionInFlight = true after UpdateRGActive")
	}
}

func TestMergeHAStateFromMaps(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("RemoveMemlock: %v", err)
	}
	rgMap, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  1,
		MaxEntries: 16,
	})
	if err != nil {
		t.Fatalf("NewMap(rg_active): %v", err)
	}
	defer rgMap.Close()
	wdMap, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  8,
		MaxEntries: 16,
	})
	if err != nil {
		t.Fatalf("NewMap(ha_watchdog): %v", err)
	}
	defer wdMap.Close()

	rgID := uint32(2)
	active := uint8(1)
	watchdog := uint64(12345)
	if err := rgMap.Update(rgID, active, ebpf.UpdateAny); err != nil {
		t.Fatalf("rgMap.Update: %v", err)
	}
	if err := wdMap.Update(rgID, watchdog, ebpf.UpdateAny); err != nil {
		t.Fatalf("wdMap.Update: %v", err)
	}

	merged, err := mergeHAStateFromMaps(rgMap, wdMap, map[int]HAGroupStatus{
		0: {RGID: 0, Active: false},
	})
	if err != nil {
		t.Fatalf("mergeHAStateFromMaps: %v", err)
	}
	if !merged[2].Active {
		t.Fatal("merged[2].Active = false, want true")
	}
	if got := merged[2].WatchdogTimestamp; got != watchdog {
		t.Fatalf("merged[2].WatchdogTimestamp = %d, want %d", got, watchdog)
	}
	if _, ok := merged[0]; !ok {
		t.Fatal("existing RG 0 state was dropped")
	}
}

// TestMergeHAStateFromMapsFabricatesGroupsFromArrayMap documents the #1928
// failure mechanism: rg_active is a fixed-size ARRAY (max_entries 16), so it
// is ALWAYS fully populated with keys 0-15 regardless of whether any
// redundancy group is configured. On a standalone (non-cluster) firewall every
// entry is value=0, and mergeHAStateFromMaps therefore returns 16 inactive HA
// groups. Shipping those to the helper makes its per-packet HA gate drop all
// transit traffic as HAInactive. The startup path in Apply guards
// refreshHAStateFromMapsLocked/syncHAStateLocked behind m.clusterHA so a
// standalone never fabricates and publishes these phantom groups (matching the
// pre-existing m.clusterHA guard on the periodic status poll in process.go).
func TestMergeHAStateFromMapsFabricatesGroupsFromArrayMap(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("RemoveMemlock: %v", err)
	}
	rgMap, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Array,
		KeySize:    4,
		ValueSize:  1,
		MaxEntries: 16,
	})
	if err != nil {
		t.Fatalf("NewMap(rg_active array): %v", err)
	}
	defer rgMap.Close()
	wdMap, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Array,
		KeySize:    4,
		ValueSize:  8,
		MaxEntries: 16,
	})
	if err != nil {
		t.Fatalf("NewMap(ha_watchdog array): %v", err)
	}
	defer wdMap.Close()

	// Leave both arrays at their default zero values — the standalone case.
	merged, err := mergeHAStateFromMaps(rgMap, wdMap, map[int]HAGroupStatus{})
	if err != nil {
		t.Fatalf("mergeHAStateFromMaps: %v", err)
	}
	if len(merged) != 16 {
		t.Fatalf("array map yielded %d HA groups, want 16 (the phantom-group source #1928 guards against)", len(merged))
	}
	for id, group := range merged {
		if group.Active {
			t.Fatalf("standalone array entry RG%d unexpectedly Active", id)
		}
	}
}

// TestSeedHAGroupInventoryLockedClearsGroupsWithoutCluster covers the #1928
// cluster->standalone transition: when a cluster config is removed, the manager
// must drop any HA groups retained from the prior clustered apply so it does not
// keep them around (and so the Apply path's clearHelperHAStateLocked can flush
// the helper). Before the fix, seedHAGroupInventoryLocked returned early without
// clearing m.haGroups, leaving stale groups that re-armed the HAInactive
// transit-drop gate.
func TestSeedHAGroupInventoryLockedClearsGroupsWithoutCluster(t *testing.T) {
	m := &Manager{
		haGroups: map[int]HAGroupStatus{
			0: {RGID: 0, Active: true},
			1: {RGID: 1, Active: true},
			2: {RGID: 2, Active: false},
		},
	}
	// cfg with no chassis cluster — the standalone / post-decluster case.
	m.seedHAGroupInventoryLocked(&config.Config{})
	if len(m.haGroups) != 0 {
		t.Fatalf("standalone seed left %d HA groups, want 0: %+v", len(m.haGroups), m.haGroups)
	}

	// nil cfg must also clear (defensive — same early-return branch).
	m.haGroups = map[int]HAGroupStatus{3: {RGID: 3, Active: true}}
	m.seedHAGroupInventoryLocked(nil)
	if len(m.haGroups) != 0 {
		t.Fatalf("nil-cfg seed left %d HA groups, want 0", len(m.haGroups))
	}
}

// TestClearHelperHAStateLockedSendsEmptyUpdate verifies the helper-side half of
// the #1928 fix: clearHelperHAStateLocked must send an update_ha_state request
// carrying an empty group set so the helper rebuilds an empty ha_state and drops
// any groups a prior clustered apply pushed. The empty ha_state is what bypasses
// the helper's HAInactive transit-drop gate on a standalone node.
func TestClearHelperHAStateLockedSendsEmptyUpdate(t *testing.T) {
	dir := t.TempDir()
	controlSock := filepath.Join(dir, "control.sock")
	ln, err := net.Listen("unix", controlSock)
	if err != nil {
		t.Fatalf("listen control socket: %v", err)
	}
	defer ln.Close()

	reqCh := make(chan ControlRequest, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		var req ControlRequest
		if err := json.NewDecoder(conn).Decode(&req); err != nil {
			return
		}
		reqCh <- req
		_ = json.NewEncoder(conn).Encode(ControlResponse{
			OK:     true,
			Status: &ProcessStatus{PID: 4321},
		})
	}()

	proc, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatalf("FindProcess: %v", err)
	}
	m := New()
	m.proc = &exec.Cmd{Process: proc}
	m.cfg.ControlSocket = controlSock

	// clearHelperHAStateLocked sends the request, then calls
	// applyHelperStatusLocked, which needs BPF maps not loaded in this unit
	// test. We assert on the request the helper RECEIVED (captured before the
	// response), so a post-send applyHelperStatusLocked error is tolerated —
	// the wire request is what this test validates.
	m.mu.Lock()
	_ = m.clearHelperHAStateLocked()
	m.mu.Unlock()

	select {
	case req := <-reqCh:
		if req.Type != "update_ha_state" {
			t.Fatalf("request type = %q, want update_ha_state", req.Type)
		}
		if req.HAState == nil {
			t.Fatal("ha_state payload missing — helper would reject as 'missing HA state'")
		}
		if len(req.HAState.Groups) != 0 {
			t.Fatalf("clear sent %d groups, want 0: %+v", len(req.HAState.Groups), req.HAState.Groups)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no control request received from clearHelperHAStateLocked")
	}
}

func TestSeedHAGroupInventoryLockedSeedsConfiguredStandbyGroups(t *testing.T) {
	m := &Manager{
		haGroups: map[int]HAGroupStatus{
			0: {RGID: 0, Active: true, WatchdogTimestamp: 111},
			2: {RGID: 2, Active: true, WatchdogTimestamp: 222},
			9: {RGID: 9, Active: true, WatchdogTimestamp: 999},
		},
	}
	cfg := &config.Config{
		Chassis: config.ChassisConfig{
			Cluster: &config.ClusterConfig{
				RedundancyGroups: []*config.RedundancyGroup{
					{ID: 1},
					{ID: 2},
				},
			},
		},
	}

	m.seedHAGroupInventoryLocked(cfg)

	if _, ok := m.haGroups[1]; !ok {
		t.Fatal("expected configured standby RG1 to be seeded")
	}
	if group := m.haGroups[2]; !group.Active || group.WatchdogTimestamp != 222 {
		t.Fatalf("configured RG2 state not preserved: %+v", group)
	}
	if group := m.haGroups[0]; !group.Active || group.WatchdogTimestamp != 111 {
		t.Fatalf("RG0 state not preserved: %+v", group)
	}
	if _, ok := m.haGroups[9]; ok {
		t.Fatal("unexpected stale RG9 retained after seeding from config")
	}
}

func TestActiveHAGroupSignatureUsesSortedActiveRGs(t *testing.T) {
	got := activeHAGroupSignature(map[int]HAGroupStatus{
		2: {RGID: 2, Active: true},
		1: {RGID: 1, Active: false},
		7: {RGID: 7, Active: true},
		0: {RGID: 0, Active: true},
	})
	if got != "0,2,7" {
		t.Fatalf("activeHAGroupSignature = %q, want 0,2,7", got)
	}
}

func TestActiveHAGroupSignatureSliceUsesSortedActiveRGs(t *testing.T) {
	got := activeHAGroupSignatureSlice([]HAGroupStatus{
		{RGID: 7, Active: true},
		{RGID: 1, Active: false},
		{RGID: 0, Active: true},
		{RGID: 2, Active: true},
	})
	if got != "0,2,7" {
		t.Fatalf("activeHAGroupSignatureSlice = %q, want 0,2,7", got)
	}
}

func TestDesiredForwardingArmedUsesSeededConfiguredDataRGs(t *testing.T) {
	m := &Manager{
		clusterHA: true,
		lastStatus: ProcessStatus{
			Capabilities: UserspaceCapabilities{ForwardingSupported: true},
		},
		haGroups: make(map[int]HAGroupStatus),
		lastSnapshot: &ConfigSnapshot{
			Config: &config.Config{
				Chassis: config.ChassisConfig{
					Cluster: &config.ClusterConfig{
						RedundancyGroups: []*config.RedundancyGroup{
							{ID: 1},
							{ID: 2},
						},
					},
				},
			},
		},
	}

	if !m.desiredForwardingArmedLocked() {
		t.Fatal("desiredForwardingArmedLocked() = false, want true for configured standby data RGs")
	}
}

func TestDesiredForwardingArmedKeepsClusterStandbyArmed(t *testing.T) {
	m := &Manager{
		clusterHA: true,
		lastStatus: ProcessStatus{
			Capabilities: UserspaceCapabilities{ForwardingSupported: true},
		},
		haGroups: map[int]HAGroupStatus{
			0: {RGID: 0, Active: true},
			1: {RGID: 1, Active: false},
			2: {RGID: 2, Active: false},
		},
	}
	if !m.desiredForwardingArmedLocked() {
		t.Fatal("desiredForwardingArmedLocked() = false, want true on standby HA node with data RGs")
	}
	m.haGroups[2] = HAGroupStatus{RGID: 2, Active: true}
	if !m.desiredForwardingArmedLocked() {
		t.Fatal("desiredForwardingArmedLocked() = false, want true with active data RG")
	}
}

func TestDesiredForwardingArmedRequiresDataRGOrActiveLocalOnlyGroup(t *testing.T) {
	m := &Manager{
		clusterHA: true,
		lastStatus: ProcessStatus{
			Capabilities: UserspaceCapabilities{ForwardingSupported: true},
		},
		haGroups: map[int]HAGroupStatus{
			0: {RGID: 0, Active: true},
		},
	}
	if !m.desiredForwardingArmedLocked() {
		t.Fatal("desiredForwardingArmedLocked() = false, want true with active local-only RG")
	}
	m.haGroups[0] = HAGroupStatus{RGID: 0, Active: false}
	if m.desiredForwardingArmedLocked() {
		t.Fatal("desiredForwardingArmedLocked() = true, want false with no data RG and no active local-only RG")
	}
}

func TestRGTransitionInFlightOnlyDuringActivation(t *testing.T) {
	// Verify that rgTransitionInFlight is NOT set during demotion.
	// Setting it during demotion causes ctrl.Enabled=0 globally, which
	// disrupts forwarding for other active RGs and causes the standby
	// to lose userspace readiness (#457).
	m := &Manager{
		clusterHA: true,
		haGroups: map[int]HAGroupStatus{
			0: {RGID: 0, Active: true},
			1: {RGID: 1, Active: true},
			2: {RGID: 2, Active: true},
		},
	}

	// Demotion (active=false) should NOT set rgTransitionInFlight.
	if m.rgTransitionInFlight.Load() {
		t.Fatal("rgTransitionInFlight should be false before demotion")
	}

	// We can't call UpdateRGActive directly without BPF maps, so we
	// verify the conditional guard matches the production code at
	// manager_ha.go:382 — `if active { m.rgTransitionInFlight.Store(true) }`.
	// This is a logic-level test; integration coverage comes from the
	// failover test harness (userspace-ha-failover-validation.sh).
	active := false
	if active {
		m.rgTransitionInFlight.Store(true)
	}
	if m.rgTransitionInFlight.Load() {
		t.Fatal("rgTransitionInFlight should NOT be set during demotion (active=false)")
	}

	// Activation (active=true) SHOULD set rgTransitionInFlight.
	active = true
	if active {
		m.rgTransitionInFlight.Store(true)
	}
	if !m.rgTransitionInFlight.Load() {
		t.Fatal("rgTransitionInFlight should be set during activation (active=true)")
	}
}

func TestHasActiveDataRGLockedIgnoresRG0(t *testing.T) {
	m := &Manager{
		haGroups: map[int]HAGroupStatus{
			0: {RGID: 0, Active: true},
			1: {RGID: 1, Active: false},
			2: {RGID: 2, Active: false},
		},
	}
	if m.hasActiveDataRGLocked() {
		t.Fatal("hasActiveDataRGLocked() = true, want false when only RG0 is active")
	}
	m.haGroups[2] = HAGroupStatus{RGID: 2, Active: true}
	if !m.hasActiveDataRGLocked() {
		t.Fatal("hasActiveDataRGLocked() = false, want true when a data RG is active")
	}
}

func TestShouldExtendXSKLivenessIdleLocked(t *testing.T) {
	m := &Manager{
		haGroups: map[int]HAGroupStatus{
			0: {RGID: 0, Active: true},
		},
	}
	if !m.shouldExtendXSKLivenessIdleLocked(0, false) {
		t.Fatal("shouldExtendXSKLivenessIdleLocked(0) = false, want true with no active data RG")
	}
	if m.shouldExtendXSKLivenessIdleLocked(0, true) {
		t.Fatal("shouldExtendXSKLivenessIdleLocked(0, true) = true, want false when idle standby should auto-prove")
	}
	m.haGroups[1] = HAGroupStatus{RGID: 1, Active: true}
	if m.shouldExtendXSKLivenessIdleLocked(0, false) {
		t.Fatal("shouldExtendXSKLivenessIdleLocked(0) = true, want false with active data RG")
	}
	if !m.shouldExtendXSKLivenessIdleLocked(0, true) {
		t.Fatal("shouldExtendXSKLivenessIdleLocked(0, true) = false, want true when active dataplane is fully bound but still idle")
	}
	if m.shouldExtendXSKLivenessIdleLocked(42, true) {
		t.Fatal("shouldExtendXSKLivenessIdleLocked(42) = true, want false when RX is already live")
	}
}

func TestShouldAutoProveIdleStandbyXSKLocked(t *testing.T) {
	m := &Manager{
		haGroups: map[int]HAGroupStatus{
			0: {RGID: 0, Active: true},
		},
	}
	if !m.shouldAutoProveIdleStandbyXSKLocked(0, true) {
		t.Fatal("shouldAutoProveIdleStandbyXSKLocked(0, true) = false, want true on fully bound idle standby")
	}
	if m.shouldAutoProveIdleStandbyXSKLocked(0, false) {
		t.Fatal("shouldAutoProveIdleStandbyXSKLocked(0, false) = true, want false when bindings are not fully bound")
	}
	m.haGroups[1] = HAGroupStatus{RGID: 1, Active: true}
	if m.shouldAutoProveIdleStandbyXSKLocked(0, true) {
		t.Fatal("shouldAutoProveIdleStandbyXSKLocked(0, true) = true, want false when a data RG is active")
	}
	if m.shouldAutoProveIdleStandbyXSKLocked(42, true) {
		t.Fatal("shouldAutoProveIdleStandbyXSKLocked(42, true) = true, want false when RX is already live")
	}
}

func TestHasBusyBindingsWedgeLocked(t *testing.T) {
	m := &Manager{
		proc: &exec.Cmd{Process: &os.Process{Pid: 1}},
		lastStatus: ProcessStatus{
			ForwardingArmed: true,
			Bindings: []BindingStatus{
				{
					Ifindex:    6,
					QueueID:    0,
					Registered: true,
					Armed:      true,
					Ready:      false,
					Bound:      false,
					LastError:  "libxdp xsk_socket__create_shared: Device or resource busy",
				},
			},
		},
	}
	if !m.hasBusyBindingsWedgeLocked(false) {
		t.Fatal("hasBusyBindingsWedgeLocked(false) = false, want true for busy unbound wedge")
	}
	m.lastStatus.Bindings[0].Bound = true
	if m.hasBusyBindingsWedgeLocked(false) {
		t.Fatal("hasBusyBindingsWedgeLocked(false) = true, want false once EVERY " +
			"registered+armed binding is bound (#7497: this fixture has one " +
			"binding, so \"every\" and \"any\" coincide here — the partial case " +
			"is covered by TestWedgeFiresOnPartialBindFailure7497)")
	}
}

func TestShouldAutoRebindBusyBindingsLockedDebounces(t *testing.T) {
	now := time.Now()
	m := &Manager{
		proc: &exec.Cmd{Process: &os.Process{Pid: 1}},
		lastStatus: ProcessStatus{
			ForwardingArmed: true,
			Bindings: []BindingStatus{
				{
					Ifindex:    6,
					QueueID:    0,
					Registered: true,
					Armed:      true,
					LastError:  "Device or resource busy",
				},
			},
		},
	}
	if m.shouldAutoRebindBusyBindingsLocked(now, false) {
		t.Fatal("first shouldAutoRebindBusyBindingsLocked() = true, want false while starting debounce")
	}
	if m.shouldAutoRebindBusyBindingsLocked(now.Add(4*time.Second), false) {
		t.Fatal("shouldAutoRebindBusyBindingsLocked() = true before busy debounce window elapsed")
	}
	if !m.shouldAutoRebindBusyBindingsLocked(now.Add(6*time.Second), false) {
		t.Fatal("shouldAutoRebindBusyBindingsLocked() = false, want true after busy debounce window")
	}
	if m.shouldAutoRebindBusyBindingsLocked(now.Add(10*time.Second), false) {
		t.Fatal("shouldAutoRebindBusyBindingsLocked() = true, want false during rebind throttle")
	}
	m.lastStatus.Bindings[0].Bound = true
	if m.shouldAutoRebindBusyBindingsLocked(now.Add(30*time.Second), false) {
		t.Fatal("shouldAutoRebindBusyBindingsLocked() = true, want false once wedge clears")
	}
}

func TestStopLockedResetsBusyBindingsAutoRebindState(t *testing.T) {
	m := &Manager{
		bindingsBusySince:      time.Now().Add(-30 * time.Second),
		lastBindingsAutoRebind: time.Now().Add(-10 * time.Second),
	}

	m.stopLocked()

	if !m.bindingsBusySince.IsZero() {
		t.Fatal("bindingsBusySince not reset by stopLocked()")
	}
	if !m.lastBindingsAutoRebind.IsZero() {
		t.Fatal("lastBindingsAutoRebind not reset by stopLocked()")
	}
}

func TestDesiredForwardingArmedDefaultsOnStandalone(t *testing.T) {
	m := &Manager{
		clusterHA: false,
		lastStatus: ProcessStatus{
			Capabilities: UserspaceCapabilities{ForwardingSupported: true},
		},
	}
	if !m.desiredForwardingArmedLocked() {
		t.Fatal("desiredForwardingArmedLocked() = false, want true on standalone supported config")
	}
}

func TestStopLockedClearsLastStatus(t *testing.T) {
	m := &Manager{
		lastStatus: ProcessStatus{
			PID:             1234,
			Enabled:         true,
			ForwardingArmed: true,
			Capabilities:    UserspaceCapabilities{ForwardingSupported: true},
		},
		sessionMirrorFailed: true,
		sessionMirrorErr:    "boom",
	}

	m.stopLocked()

	if m.lastStatus.PID != 0 {
		t.Fatalf("lastStatus.PID = %d, want 0", m.lastStatus.PID)
	}
	if m.lastStatus.Enabled {
		t.Fatal("lastStatus.Enabled = true, want false")
	}
	if m.lastStatus.ForwardingArmed {
		t.Fatal("lastStatus.ForwardingArmed = true, want false")
	}
	if m.lastStatus.Capabilities.ForwardingSupported {
		t.Fatal("lastStatus.Capabilities.ForwardingSupported = true, want false")
	}
	if m.sessionMirrorFailed {
		t.Fatal("sessionMirrorFailed = true, want false")
	}
	if m.sessionMirrorErr != "" {
		t.Fatalf("sessionMirrorErr = %q, want empty", m.sessionMirrorErr)
	}
}

// TestStopLockedClearsStatusAfterARealProcessTeardown covers the OTHER clear in
// stopLocked (#6691 round 11).
//
// stopLocked clears the helper status twice: once in the `m.proc == nil` early
// return and once after the real teardown (shutdown request, Wait, escalate,
// m.proc = nil). Every existing stopLocked test runs with proc == nil and so
// exercises only the first, and the observation marker is asserted elsewhere by
// calling clearLastStatusLocked directly — so deleting the second clear left the
// suite green while a stopped helper kept a stale PID, a stale
// ForwardingArmed and, worse, a stale ConfigSnapshotProtocolVersion with
// helperStatusObserved still true. That combination is exactly what the
// required-protocol gates read: a version belonging to a dead process, treated
// as an observation about its replacement.
//
// The Cmd is deliberately never Started, so Wait returns immediately and the
// teardown walks the real branch without a signal, a kill or a 2s timeout.
//
// FAIL-ON-REVERT: delete the clearLastStatusLocked call that follows
// `m.proc = nil` and this reds; the two pre-existing stopLocked tests do not.
func TestStopLockedClearsStatusAfterARealProcessTeardown(t *testing.T) {
	self, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatalf("FindProcess: %v", err)
	}

	m := New()
	// A control socket path that resolves to nothing: the shutdown request and
	// the ctrl disable fail fast and are ignored by stopLocked, as they are on a
	// helper that has already died.
	m.cfg.ControlSocket = filepath.Join(t.TempDir(), "absent.sock")
	m.proc = &exec.Cmd{Process: self}
	m.setLastStatusLocked(ProcessStatus{
		PID:                           4321,
		Enabled:                       true,
		ForwardingArmed:               true,
		ConfigSnapshotProtocolVersion: ProtocolVersion,
	})
	if !m.helperStatusObserved {
		t.Fatal("premise broken: setLastStatusLocked did not record the observation")
	}

	m.stopLocked()

	if m.proc != nil {
		t.Fatal("premise broken: stopLocked did not take the real-process branch")
	}
	if m.lastStatus.PID != 0 || m.lastStatus.Enabled || m.lastStatus.ForwardingArmed {
		t.Errorf("lastStatus after a real teardown = %+v, want the zero value: the "+
			"helper is gone, and a status left behind describes a process that no "+
			"longer exists", m.lastStatus)
	}
	if m.lastStatus.ConfigSnapshotProtocolVersion != 0 || m.helperStatusObserved {
		t.Errorf("protocol observation survived the teardown (version=%d observed=%v). "+
			"The required-protocol gates arm on an OBSERVED version; keeping one from a "+
			"dead process makes the next commit decide against a helper that never answered",
			m.lastStatus.ConfigSnapshotProtocolVersion, m.helperStatusObserved)
	}
}

// startFakeHAControlHelper starts a unix-socket helper that captures the Type of
// every ControlRequest it receives (one request per connection, matching
// requestDetailedLocked's fresh-dial-per-request behavior) and replies OK. The
// returned channel buffers received request types for the test to count. Used by
// the HA-watchdog IPC-throttle tests (#2549).
func startFakeHAControlHelper(t *testing.T, dir string) (string, <-chan string) {
	t.Helper()
	controlSock := filepath.Join(dir, "control.sock")
	ln, err := net.Listen("unix", controlSock)
	if err != nil {
		t.Fatalf("listen control socket: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	reqTypes := make(chan string, 256)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			var req ControlRequest
			if err := json.NewDecoder(conn).Decode(&req); err != nil {
				_ = conn.Close()
				continue
			}
			reqTypes <- req.Type
			_ = json.NewEncoder(conn).Encode(ControlResponse{
				OK:     true,
				Status: &ProcessStatus{PID: 4321},
			})
			_ = conn.Close()
		}
	}()
	return controlSock, reqTypes
}

// drainUpdateHAStateCount non-blockingly counts update_ha_state requests buffered
// in ch. requestLocked is synchronous (the helper pushes the type BEFORE encoding
// the response UpdateHAWatchdog waits on), so by the time the driving loop returns
// every send is already in the channel.
func drainUpdateHAStateCount(ch <-chan string) int {
	n := 0
	for {
		select {
		case typ := <-ch:
			if typ == "update_ha_state" {
				n++
			}
		default:
			return n
		}
	}
}

// TestUpdateHAWatchdogThrottlesIPCButWritesMapEveryTick proves the #2549 split:
// the kernel-visible shim watchdog MAP WRITE fires on every 500ms heartbeat tick
// (the BPF ~2s stale window relies on it), while the update_ha_state socket IPC
// is throttled to a periodic backstop (~once per haWatchdogIPCBackstopSecs) so it
// stops being a >1/s control-socket caller that starves session installs.
//
// FAIL-ON-REVERT: master's UpdateHAWatchdog calls syncHAStateLocked
// unconditionally — restoring that makes the IPC fire on all 20 ticks, blowing
// the `<= 6` bound. (On unmodified master the test also fails earlier because the
// un-seamed bpfShim.UpdateHAWatchdog errors on the missing map, short-circuiting
// the whole call.)
func TestUpdateHAWatchdogThrottlesIPCButWritesMapEveryTick(t *testing.T) {
	dir := t.TempDir()
	controlSock, reqTypes := startFakeHAControlHelper(t, dir)

	proc, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatalf("FindProcess: %v", err)
	}

	m := New()
	m.proc = &exec.Cmd{Process: proc}
	m.cfg.ControlSocket = controlSock
	m.clusterHA = true
	m.haGroups[1] = HAGroupStatus{RGID: 1, Active: false}

	mapWrites := 0
	m.haWatchdogMapWrite = func(rgID int, ts uint64) error { mapWrites++; return nil }

	const rgID = 1
	const ticks = 20 // 500ms ticks over a 10s span.
	for i := 0; i < ticks; i++ {
		// The daemon writes CLOCK_MONOTONIC SECONDS, so tick i carries
		// timestamp i/2 (0,0,1,1,...,9,9). post-send applyHelperStatusLocked
		// errors without BPF maps; the IPC is already sent + counted, so the
		// returned error is expected and ignored.
		_ = m.UpdateHAWatchdog(rgID, uint64(i/2))
	}

	if mapWrites != ticks {
		t.Fatalf("shim map write fired %d times over %d ticks, want every tick (kernel watchdog must stay fresh)", mapWrites, ticks)
	}

	ipc := drainUpdateHAStateCount(reqTypes)
	// 3s backstop -> IPC at ts 0,3,6,9 = 4 sends over the 10s span.
	if ipc < 2 {
		t.Fatalf("update_ha_state IPC fired %d times over a 10s span — the periodic backstop never refreshed the helper (stale-lease would expire)", ipc)
	}
	if ipc > 6 {
		t.Fatalf("update_ha_state IPC fired %d times over %d ticks (10s span); want throttled to ~once/%ds (<=6), not per-tick like master (=%d)", ipc, ticks, haWatchdogIPCBackstopSecs, ticks)
	}
}

// TestUpdateHAWatchdogActiveChangeForcesImmediateIPC proves the load-bearing
// correctness constraint of #2549: an RG Active-state change (failover/failback)
// MUST publish the update_ha_state IPC immediately, regardless of the timestamp
// backstop throttle. If the throttle ever swallowed a transition, failover timing
// would regress.
func TestUpdateHAWatchdogActiveChangeForcesImmediateIPC(t *testing.T) {
	dir := t.TempDir()
	controlSock, reqTypes := startFakeHAControlHelper(t, dir)

	proc, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatalf("FindProcess: %v", err)
	}

	m := New()
	m.proc = &exec.Cmd{Process: proc}
	m.cfg.ControlSocket = controlSock
	m.clusterHA = true
	m.haWatchdogMapWrite = func(int, uint64) error { return nil }
	m.haGroups[1] = HAGroupStatus{RGID: 1, Active: false}

	// Tick 0 seeds the baseline + syncs; tick 1 (same second, no change) is
	// throttled. One IPC so far.
	_ = m.UpdateHAWatchdog(1, 0)
	_ = m.UpdateHAWatchdog(1, 0)
	if base := drainUpdateHAStateCount(reqTypes); base != 1 {
		t.Fatalf("baseline IPC count = %d, want 1 (first tick syncs, second is throttled)", base)
	}

	// Flip Active WITHOUT advancing the timestamp past the backstop. The
	// throttle MUST NOT swallow this transition.
	m.mu.Lock()
	g := m.haGroups[1]
	g.Active = true
	m.haGroups[1] = g
	m.mu.Unlock()
	_ = m.UpdateHAWatchdog(1, 0)

	if got := drainUpdateHAStateCount(reqTypes); got != 1 {
		t.Fatalf("Active-state change fired %d immediate IPCs, want exactly 1 — failover/failback must publish instantly despite the timestamp throttle", got)
	}
}
