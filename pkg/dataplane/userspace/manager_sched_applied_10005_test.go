package userspace

import (
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// TestConfigSnapshot10005_SchedulerStampIsLocalOnly proves the deferred
// scheduler-state stamp is not part of either representation sent to the
// helper. Unexported fields are omitted by encoding/json (the same mechanism
// used by the existing zoneIDCollisions and partialUpdateEpoch fields), and
// snapshotContentHash hashes that JSON encoding; this pins both contracts.
func TestConfigSnapshot10005_SchedulerStampIsLocalOnly(t *testing.T) {
	snap := &ConfigSnapshot{
		Version:                 ProtocolVersion,
		Generation:              7,
		schedulerActiveState:    map[string]bool{"workhours": true},
		schedulerActiveStateSet: true,
	}
	beforeHash, ok := snapshotContentHash(snap)
	if !ok {
		t.Fatal("snapshotContentHash rejected baseline snapshot")
	}
	beforeWire, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("marshal baseline snapshot: %v", err)
	}
	snap.schedulerActiveState = map[string]bool{"workhours": false}
	afterHash, ok := snapshotContentHash(snap)
	if !ok {
		t.Fatal("snapshotContentHash rejected stamped snapshot")
	}
	afterWire, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("marshal stamped snapshot: %v", err)
	}
	if beforeHash != afterHash {
		t.Fatalf("scheduler stamp changed snapshot hash: before=%x after=%x", beforeHash, afterHash)
	}
	if string(beforeWire) != string(afterWire) {
		t.Fatalf("scheduler stamp changed wire JSON:\nbefore=%s\nafter=%s", beforeWire, afterWire)
	}
	if strings.Contains(string(afterWire), "schedulerActiveState") ||
		strings.Contains(string(afterWire), "scheduler_active_state") {
		t.Fatalf("scheduler stamp leaked onto the wire: %s", afterWire)
	}
}

// #10005: the policy-scheduler applied/show cache (m.policySchedulerActive,
// surfaced via PolicySchedulerActiveState) must track ENFORCEMENT, not intent.
// Every republish error path must leave it at the last applied state; only a
// landed publish may advance it.
//
// FAIL-ON-REVERT: each cell drives the real daemon sequence —
// SetPolicySchedulerActiveState (seed) then UpdatePolicyScheduleState — with a
// forced failure, and asserts the applied cache still reads the pre-call
// (enforced) state. A same-field fix (merely moving the Update assignment)
// fails RED at the after-seed assertion, because the seed already advanced the
// single field; the pre-fix code additionally fails at the after-update
// assertion.
// The cache failure cells themselves use only pre-existing identifiers, so
// they remain valid as a fail-on-revert test independent of the new metadata
// carrier tested above.

// schedCfg10005 is the minimal scheduled-policy config shared by the #10005
// cells: one scheduled permit behind scheduler "workhours".
func schedCfg10005() *config.Config {
	cfg := &config.Config{}
	cfg.Security.Policies = []*config.ZonePairPolicies{{
		FromZone: "trust",
		ToZone:   "untrust",
		Policies: []*config.Policy{{
			Name:          "scheduled-allow",
			SchedulerName: "workhours",
			Match: config.PolicyMatch{
				SourceAddresses:      []string{"any"},
				DestinationAddresses: []string{"any"},
				Applications:         []string{"any"},
			},
			Action: config.PolicyPermit,
		}},
	}}
	cfg.Schedulers = map[string]*config.SchedulerConfig{
		"workhours": {Name: "workhours"},
	}
	return cfg
}

// shortSockDir10005 returns a short control-socket path: t.TempDir under these
// long test names would push the AF_UNIX path past sun_path limits (4959
// pattern).
func shortSockDir10005(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "x10005")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "control.sock")
}

// assertApplied10005 checks BOTH applied views agree with want: the cached
// field (what the next enforcement decision would compare against) and the
// show surface (what operators read). Non-fatal so a RED run reports every
// diverged view in one pass.
func assertApplied10005(t *testing.T, m *Manager, where string, want bool) {
	t.Helper()
	m.mu.Lock()
	got, ok := m.policySchedulerActive["workhours"]
	m.mu.Unlock()
	if !ok || got != want {
		t.Errorf("%s: applied cache workhours = %t, present=%t; want %t and present",
			where, got, ok, want)
	}
	show := m.PolicySchedulerActiveState()
	if show == nil {
		t.Errorf("%s: show surface returned nil; want workhours=%t", where, want)
		return
	}
	if got, ok := show["workhours"]; !ok || got != want {
		t.Errorf("%s: show surface workhours = %t, present=%t; want %t and present",
			where, got, ok, want)
	}
}

// assertEnforcedOpen10005 pins the test premise that the helper still enforces
// the OPEN window: lastSnapshot carries the permit ACTIVE.
func assertEnforcedOpen10005(t *testing.T, m *Manager, where string) {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.lastSnapshot == nil || len(m.lastSnapshot.Policies) != 1 {
		t.Fatalf("%s: premise broken: lastSnapshot = %+v, want 1 policy", where, m.lastSnapshot)
	}
	if m.lastSnapshot.Policies[0].Inactive {
		t.Errorf("%s: lastSnapshot permit Inactive=true; want ACTIVE (enforcement must be retained)", where)
	}
}

// seedOpenBaseline10005 installs a coherent OPEN-window baseline: the helper
// enforces the active permit (lastSnapshot bits) and the applied cache agrees.
func seedOpenBaseline10005(t *testing.T, m *Manager, cfg *config.Config, controlSock string, generation uint64) {
	t.Helper()
	m.proc = &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
	m.cfg.ControlSocket = controlSock
	m.generation = generation
	m.lastSnapshot = mustBuildSnapshot(t, cfg, config.UserspaceConfig{ControlSocket: controlSock}, generation, 0)
	m.lastSnapshot.Policies[0].Inactive = false
	m.lastStatus.ConfigSnapshotProtocolVersion = ProtocolVersion
	m.mu.Lock()
	m.policySchedulerActive = map[string]bool{"workhours": true}
	m.mu.Unlock()
}

// TestUpdatePolicyScheduleState10005_ProtocolMismatchRetainsAppliedCache:
// refusing a publish to an incompatible helper must not advance the applied
// cache past what the helper enforces.
func TestUpdatePolicyScheduleState10005_ProtocolMismatchRetainsAppliedCache(t *testing.T) {
	controlSock := shortSockDir10005(t)
	ln, err := net.Listen("unix", controlSock)
	if err != nil {
		t.Fatalf("listen control socket: %v", err)
	}
	defer ln.Close()

	reqCh := make(chan ControlRequest, 2)
	done := make(chan struct{}, 1)
	go func() {
		for i := 0; i < 2; i++ {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			var req ControlRequest
			if err := json.NewDecoder(conn).Decode(&req); err != nil {
				conn.Close()
				return
			}
			reqCh <- req
			status := &ProcessStatus{
				PID:             1234,
				ForwardingArmed: true,
			}
			if req.Type == "set_forwarding_state" {
				status.ForwardingArmed = false
			}
			_ = json.NewEncoder(conn).Encode(ControlResponse{
				OK:     true,
				Status: status,
			})
			conn.Close()
		}
		done <- struct{}{}
	}()

	cfg := schedCfg10005()
	m := New()
	// Old-helper fixture (mirrors RefusesOldHelperForScheduledPolicies): zero
	// protocol version in lastStatus, so the status probe reports version 0
	// and the scheduler protocol gate refuses.
	m.proc = &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
	m.cfg.ControlSocket = controlSock
	m.generation = 7
	m.lastSnapshot = mustBuildSnapshot(t, cfg, config.UserspaceConfig{ControlSocket: controlSock}, 7, 0)
	m.lastSnapshot.Policies[0].Inactive = false
	m.mu.Lock()
	m.policySchedulerActive = map[string]bool{"workhours": true}
	m.mu.Unlock()

	// Daemon sequence: seed, then republish into the CLOSED window.
	m.SetPolicySchedulerActiveState(map[string]bool{"workhours": false})
	assertApplied10005(t, m, "after seed (protocol-mismatch)", true)

	err = m.UpdatePolicyScheduleState(cfg, map[string]bool{"workhours": false})
	if err == nil {
		t.Fatal("UpdatePolicyScheduleState must refuse the publish to an incompatible helper")
	}
	if !strings.Contains(err.Error(), "refusing snapshot publish to incompatible helper") {
		t.Fatalf("error = %q, want the protocol-refusal site (proves the intended path failed)", err)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for status probe + disarm")
	}
	assertApplied10005(t, m, "after refused publish (protocol-mismatch)", true)
	assertEnforcedOpen10005(t, m, "after refused publish (protocol-mismatch)")
	if m.generation != 7 {
		t.Errorf("generation = %d, want 7 retained after refusal", m.generation)
	}
}

// TestUpdatePolicyScheduleState10005_RebuildSkewRetainsAppliedCache: the #6480
// config-skew refusal happens before any publish, so the applied cache must
// stay at the enforced OPEN state.
func TestUpdatePolicyScheduleState10005_RebuildSkewRetainsAppliedCache(t *testing.T) {
	stubRuleListHermetic(t)
	dir := t.TempDir()
	controlSock := filepath.Join(dir, "no-listener.sock")

	cfgA := skewCfgA6480(t)
	cfgB := skewCfgB6480(t)

	m := New()
	m.proc = &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
	m.cfg.ControlSocket = controlSock
	m.generation = 5
	m.lastStatus.ConfigSnapshotProtocolVersion = ProtocolVersion

	var err error
	m.lastSnapshot, err = buildSnapshotWithSchedulerState(
		cfgA, config.UserspaceConfig{ControlSocket: controlSock}, 5, 0,
		map[string]bool{"workhours": true}, nil, nil)
	if err != nil {
		t.Fatalf("build lastSnapshot: %v", err)
	}
	if m.lastSnapshot.Config != cfgA {
		t.Fatal("precondition: seeded snapshot must carry cfgA by pointer")
	}
	m.mu.Lock()
	m.policySchedulerActive = map[string]bool{"workhours": true}
	m.mu.Unlock()

	m.SetPolicySchedulerActiveState(map[string]bool{"workhours": false})
	assertApplied10005(t, m, "after seed (rebuild-skew)", true)

	skewErr := m.UpdatePolicyScheduleState(cfgB, map[string]bool{"workhours": false})
	if skewErr == nil {
		t.Fatal("UpdatePolicyScheduleState must refuse the config-skew republish (#6480)")
	}
	if !strings.Contains(skewErr.Error(), "refusing scheduled-policy republish") {
		t.Fatalf("error = %q, want the #6480 skew-refusal site", skewErr)
	}
	assertApplied10005(t, m, "after refused skew republish", true)
	if m.generation != 5 {
		t.Errorf("generation = %d, want 5 retained after refusal", m.generation)
	}
	if m.lastSnapshot == nil || m.lastSnapshot.Config != cfgA {
		t.Error("refused skew republish advanced lastSnapshot past the applied config A")
	}
}

// TestUpdatePolicyScheduleState10005_RebuildFailureRetainsAppliedCache drives
// the actual policy/address-book rebuild error (not the separate #6480 config
// skew guard): a forced address-book content-ID collision makes
// buildPolicySnapshotsWithSchedulerStateAndFeeds fail before any publish.
func TestUpdatePolicyScheduleState10005_RebuildFailureRetainsAppliedCache(t *testing.T) {
	cfg := collidingBookCfg(3)
	cfg.Security.Policies = []*config.ZonePairPolicies{{
		FromZone: "trust",
		ToZone:   "untrust",
		Policies: []*config.Policy{{
			Name:          "scheduled-allow",
			SchedulerName: "workhours",
			Match: config.PolicyMatch{
				SourceAddresses:      []string{"aa"},
				DestinationAddresses: []string{"any"},
				Applications:         []string{"any"},
			},
			Action: config.PolicyPermit,
		}},
	}}
	cfg.Schedulers = map[string]*config.SchedulerConfig{
		"workhours": {Name: "workhours"},
	}
	controlSock := shortSockDir10005(t)

	m := New()
	m.proc = &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
	m.cfg.ControlSocket = controlSock
	m.generation = 7
	m.lastStatus.ConfigSnapshotProtocolVersion = ProtocolVersion
	// Build the applied baseline before injecting the collision. Keeping the
	// exact cfg pointer proves the rebuild reaches its builder rather than the
	// #6480 cfg-skew refusal.
	m.lastSnapshot = mustBuildSnapshotWithSchedulerState(t, cfg,
		config.UserspaceConfig{ControlSocket: controlSock}, 7, 0,
		map[string]bool{"workhours": true}, nil, nil)
	m.lastSnapshot.Policies[0].Inactive = false
	m.mu.Lock()
	m.policySchedulerActive = map[string]bool{"workhours": true}
	m.mu.Unlock()

	restore := forceAddressBookCollision(t)
	defer restore()
	m.SetPolicySchedulerActiveState(map[string]bool{"workhours": false})
	assertApplied10005(t, m, "after seed (rebuild failure)", true)

	err := m.UpdatePolicyScheduleState(cfg, map[string]bool{"workhours": false})
	if err == nil {
		t.Fatal("UpdatePolicyScheduleState must report the policy rebuild failure")
	}
	if !strings.Contains(err.Error(), "policy snapshot rebuild for scheduler republish") {
		t.Fatalf("error = %q, want wrapped policy snapshot rebuild failure", err)
	}
	assertApplied10005(t, m, "after policy rebuild failure", true)
	assertEnforcedOpen10005(t, m, "after policy rebuild failure")
	if m.generation != 7 {
		t.Errorf("generation = %d, want 7 retained after rebuild failure", m.generation)
	}
}

// TestUpdatePolicyScheduleState10005_DisarmFailureRetainsAppliedCache: when the
// pre-publish disarm fails, the new snapshot never lands, so the applied cache
// must stay at the enforced OPEN state.
func TestUpdatePolicyScheduleState10005_DisarmFailureRetainsAppliedCache(t *testing.T) {
	controlSock := shortSockDir10005(t)
	// The disarm's set_forwarding_state is the only control call before the
	// failure return; reject it.
	startArmControlServerReject(t, controlSock, 1)

	cfg := schedCfg10005()
	m := New()
	seedOpenBaseline10005(t, m, cfg, controlSock, 7)
	// Unsupported-config fixture: the inherited capabilities flag forces the
	// disarm gate, and the helper reports armed so the disarm is issued.
	m.lastSnapshot.Capabilities.ForwardingSupported = false
	m.lastStatus.ForwardingArmed = true

	m.SetPolicySchedulerActiveState(map[string]bool{"workhours": false})
	assertApplied10005(t, m, "after seed (disarm-failure)", true)

	err := m.UpdatePolicyScheduleState(cfg, map[string]bool{"workhours": false})
	if err == nil {
		t.Fatal("UpdatePolicyScheduleState must report the disarm failure")
	}
	if !strings.Contains(err.Error(), "disarm before unsupported-config") {
		t.Fatalf("error = %q, want the disarm-failure site (proves disarm was attempted)", err)
	}
	assertApplied10005(t, m, "after disarm failure", true)
	assertEnforcedOpen10005(t, m, "after disarm failure")
	if m.generation != 7 {
		t.Errorf("generation = %d, want 7 retained after disarm failure", m.generation)
	}
}

// TestUpdatePolicyScheduleState10005_ApplyFailureRetainsAppliedCache: when
// apply_snapshot itself fails, the helper keeps the old bits, so the applied
// cache must stay at the enforced OPEN state.
func TestUpdatePolicyScheduleState10005_ApplyFailureRetainsAppliedCache(t *testing.T) {
	dir := t.TempDir()
	controlSock := filepath.Join(dir, "no-listener.sock")

	cfg := schedCfg10005()
	m := New()
	seedOpenBaseline10005(t, m, cfg, controlSock, 7)

	m.SetPolicySchedulerActiveState(map[string]bool{"workhours": false})
	assertApplied10005(t, m, "after seed (apply-failure)", true)

	err := m.UpdatePolicyScheduleState(cfg, map[string]bool{"workhours": false})
	if err == nil {
		t.Fatal("UpdatePolicyScheduleState must return an error when apply_snapshot fails")
	}
	if !strings.Contains(err.Error(), "publish policy scheduler snapshot") {
		t.Fatalf("error = %q, want the requestApply-failure site", err)
	}
	assertApplied10005(t, m, "after apply failure", true)
	assertEnforcedOpen10005(t, m, "after apply failure")
	if m.generation != 7 {
		t.Errorf("generation = %d, want 7 retained after a failed publish", m.generation)
	}
}

// TestPublishRouteOverlaySnapshot10005_ApplyFailureRetainsAppliedCache covers
// the second scheduler-state publisher. A failed route-overlay apply must not
// advance the applied/show cache even though it stages the desired map before
// rebuilding the overlay snapshot.
func TestPublishRouteOverlaySnapshot10005_ApplyFailureRetainsAppliedCache(t *testing.T) {
	stubRuleListHermetic(t)
	cfg := schedCfg10005()
	controlSock := shortSockDir10005(t)
	m := New()
	m.proc = &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
	m.cfg.ControlSocket = controlSock
	m.generation = 7
	m.lastStatus.ConfigSnapshotProtocolVersion = ProtocolVersion
	m.lastSnapshot = mustBuildSnapshot(t, cfg,
		config.UserspaceConfig{ControlSocket: controlSock}, 7, 0)
	m.lastSnapshot.Policies[0].Inactive = false
	m.mu.Lock()
	m.policySchedulerActive = map[string]bool{"workhours": true}
	m.mu.Unlock()

	m.SetPolicySchedulerActiveState(map[string]bool{"workhours": false})
	assertApplied10005(t, m, "after seed (overlay apply failure)", true)

	_, err := m.PublishRouteOverlaySnapshot(cfg, nil, map[string]bool{"workhours": false})
	if err == nil {
		t.Fatal("PublishRouteOverlaySnapshot must return the apply failure")
	}
	if !strings.Contains(err.Error(), "publish route overlay snapshot") {
		t.Fatalf("error = %q, want the overlay requestApply failure", err)
	}
	assertApplied10005(t, m, "after overlay apply failure", true)
	assertEnforcedOpen10005(t, m, "after overlay apply failure")
	if m.generation != 7 {
		t.Errorf("generation = %d, want 7 retained after overlay apply failure", m.generation)
	}
}

// TestUpdatePolicyScheduleState10005_SuccessCommitsAppliedCache is the control:
// a LANDED closing-window republish must advance the applied cache to CLOSED.
// Guards the degenerate fix that never commits (this cell passes pre-fix and
// must keep passing).
func TestUpdatePolicyScheduleState10005_SuccessCommitsAppliedCache(t *testing.T) {
	controlSock := shortSockDir10005(t)
	ln, err := net.Listen("unix", controlSock)
	if err != nil {
		t.Fatalf("listen control socket: %v", err)
	}
	defer ln.Close()

	done := make(chan struct{}, 1)
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
		_ = json.NewEncoder(conn).Encode(ControlResponse{
			OK: true,
			Status: &ProcessStatus{
				Enabled:                true,
				LastSnapshotGeneration: req.Snapshot.Generation,
				LastFIBGeneration:      req.Snapshot.FIBGeneration,
			},
		})
		done <- struct{}{}
	}()

	cfg := schedCfg10005()
	m := New()
	seedOpenBaseline10005(t, m, cfg, controlSock, 7)

	m.SetPolicySchedulerActiveState(map[string]bool{"workhours": false})
	if err := m.UpdatePolicyScheduleState(cfg, map[string]bool{"workhours": false}); err != nil {
		t.Fatalf("closing-window republish must converge: %v", err)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for apply_snapshot publish")
	}
	assertApplied10005(t, m, "after successful republish", false)
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.lastSnapshot == nil || len(m.lastSnapshot.Policies) != 1 || !m.lastSnapshot.Policies[0].Inactive {
		t.Fatalf("lastSnapshot must carry the CLOSED window after success: %+v", m.lastSnapshot)
	}
	if m.generation != 8 {
		t.Errorf("generation = %d, want 8 after a landed publish", m.generation)
	}
}

// TestApplyCompiledSnapshot10005_DeferredCommitWaitsForPublish proves that a
// pending-XSK startup apply does not publish yet and therefore does not advance
// the applied/show cache. The same snapshot's scheduler metadata is committed
// only when syncSnapshotLocked later lands it in the helper.
func TestApplyCompiledSnapshot10005_DeferredCommitWaitsForPublish(t *testing.T) {
	f := newFixture9824(t)
	retained := f.seedPublished(t, 7, nil, nil, nil)
	retained.schedulerActiveState = map[string]bool{"workhours": true}
	retained.schedulerActiveStateSet = true
	f.m.mu.Lock()
	f.m.policySchedulerActive = map[string]bool{"workhours": true}
	f.m.mu.Unlock()

	next := *retained
	next.Generation = 8
	next.schedulerActiveState = map[string]bool{"workhours": false}
	next.schedulerActiveStateSet = true
	f.forcePendingXSK()

	f.m.SetPolicySchedulerActiveState(map[string]bool{"workhours": false})
	assertApplied10005(t, f.m, "after seed (deferred apply)", true)
	if _, err := f.apply(t, &next); err != nil {
		t.Fatalf("pending-XSK full apply must defer without error: %v", err)
	}
	assertApplied10005(t, f.m, "after deferred apply (before publish)", true)
	f.m.mu.Lock()
	published := f.m.publishedSnapshot
	f.m.mu.Unlock()
	if published != 7 {
		t.Fatalf("publishedSnapshot = %d, want retained 7 before deferred publish", published)
	}

	f.endXSKWindow()
	if err := f.tick(t); err != nil {
		t.Fatalf("deferred publish must converge: %v", err)
	}
	assertApplied10005(t, f.m, "after deferred publish", false)
}

// TestRetryDeferredWorkerArm10005_CommitsAppliedSchedulerState covers the
// worker-arm publisher's success boundary. A workerless snapshot that was
// deferred before publication carries scheduler metadata; when the retry lands
// it must advance the applied/show cache even if the later status sync reports
// the fixture's absent BPF maps.
func TestRetryDeferredWorkerArm10005_CommitsAppliedSchedulerState(t *testing.T) {
	controlSock := filepath.Join(t.TempDir(), "control.sock")
	cfg := &config.Config{}
	m := New()
	m.proc = &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
	m.cfg.ControlSocket = controlSock
	m.lastStatus.ConfigSnapshotProtocolVersion = ProtocolVersion

	snap := mustBuildSnapshotWithSchedulerState(t, cfg,
		config.UserspaceConfig{ControlSocket: controlSock}, 7, 0,
		map[string]bool{"workhours": true}, nil, nil)
	snap.DeferWorkers = true
	m.lastSnapshot = snap
	m.generation = 7
	m.publishedSnapshot = 7
	m.mu.Lock()
	m.policySchedulerActive = map[string]bool{"workhours": false}
	m.policySchedulerDesired = map[string]bool{"workhours": true}
	m.policySchedulerDesiredSet = true
	m.pendingWorkerArm = true
	m.mu.Unlock()
	assertApplied10005(t, m, "before worker-arm retry", false)

	reqs := startArmControlServer(t, controlSock, 1)
	m.mu.Lock()
	retryErr := m.retryDeferredWorkerArmLocked()
	m.mu.Unlock()

	var req ControlRequest
	select {
	case req = <-reqs:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for deferred-worker arm apply_snapshot")
	}
	if req.Type != "apply_snapshot" || req.Snapshot == nil {
		t.Fatalf("worker-arm request = %#v, want apply_snapshot with snapshot", req)
	}
	if req.Snapshot.DeferWorkers {
		t.Fatal("worker-arm retry must publish DeferWorkers=false")
	}
	if retryErr != nil && !strings.Contains(retryErr.Error(), "sync helper status after deferred-worker arm") {
		t.Fatalf("worker-arm retry failed before the expected post-publish status sync: %v", retryErr)
	}

	assertApplied10005(t, m, "after worker-arm retry", true)
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.pendingWorkerArm {
		t.Fatal("worker-arm debt must clear after the publish succeeds")
	}
	if m.lastSnapshot == nil || m.lastSnapshot.DeferWorkers ||
		!m.lastSnapshot.schedulerActiveStateSet ||
		!m.lastSnapshot.schedulerActiveState["workhours"] {
		t.Fatalf("landed worker-arm snapshot = %+v, want workers armed and scheduler state true", m.lastSnapshot)
	}
}

// TestApplyCompiledSnapshot10005_SuccessCommitsAppliedCache verifies the
// ordinary full-apply success boundary, including the daemon's seed-before-
// apply sequence. The successful apply must advance the applied/show cache,
// while the pending-XSK path below intentionally does not commit until
// syncSnapshotLocked publishes the deferred snapshot.
func TestApplyCompiledSnapshot10005_SuccessCommitsAppliedCache(t *testing.T) {
	f := newFixture9824(t)
	retained := f.seedPublished(t, 7, nil, nil, nil)
	retained.schedulerActiveState = map[string]bool{"workhours": true}
	retained.schedulerActiveStateSet = true
	f.m.mu.Lock()
	f.m.policySchedulerActive = map[string]bool{"workhours": true}
	f.m.mu.Unlock()

	next := *retained
	next.Generation = 8
	next.schedulerActiveState = map[string]bool{"workhours": false}
	next.schedulerActiveStateSet = true
	f.endXSKWindow()

	f.m.SetPolicySchedulerActiveState(map[string]bool{"workhours": false})
	assertApplied10005(t, f.m, "after seed (full-apply success)", true)
	if _, err := f.apply(t, &next); err != nil {
		t.Fatalf("full apply must converge: %v", err)
	}
	assertApplied10005(t, f.m, "after successful full apply", false)
	f.m.mu.Lock()
	defer f.m.mu.Unlock()
	if f.m.lastSnapshot == nil || !f.m.lastSnapshot.schedulerActiveStateSet ||
		f.m.lastSnapshot.schedulerActiveState["workhours"] {
		t.Fatalf("lastSnapshot scheduler state = %+v, want CLOSED", f.m.lastSnapshot.schedulerActiveState)
	}
}

// TestApplyCompiledSnapshot10005_BootstrapFailureRetainsAppliedCache: a full
// apply that fails before apply_snapshot must leave the applied cache at the
// last enforced state. Failure injection is the 5485 premise (classifier maps
// not loaded in an unprivileged harness), which needs no BPF fixture.
func TestApplyCompiledSnapshot10005_BootstrapFailureRetainsAppliedCache(t *testing.T) {
	cfg := schedCfg10005()
	ucfg := deriveUserspaceConfig(cfg)
	caps := deriveUserspaceCapabilities(cfg)

	m := New()
	retained := mustBuildSnapshotWithSchedulerState(t, cfg, ucfg, 7, 0,
		map[string]bool{"workhours": true}, nil, nil)
	if len(retained.Policies) != 1 || retained.Policies[0].Inactive {
		t.Fatal("premise broken: OPEN seed must render the permit active")
	}
	next := mustBuildSnapshotWithSchedulerState(t, cfg, ucfg, 8, 0,
		map[string]bool{"workhours": false}, nil, nil)
	m.lastSnapshot = retained
	m.generation = 7
	m.mu.Lock()
	m.policySchedulerActive = map[string]bool{"workhours": true}
	m.mu.Unlock()

	// Daemon full-apply sequence: seed, then apply.
	m.SetPolicySchedulerActiveState(map[string]bool{"workhours": false})
	assertApplied10005(t, m, "after seed (full-apply failure)", true)

	_, err := m.applyCompiledSnapshot(cfg, &dataplane.CompileResult{}, next, ucfg, caps)
	if err == nil {
		t.Fatal("premise broken: the apply must FAIL before apply_snapshot — " +
			"with no BPF maps injected programBootstrapMapsLocked cannot succeed")
	}
	if !strings.Contains(err.Error(), "userspace_ctrl map not loaded") {
		t.Fatalf("premise broken: apply failed with %v, want the pre-publish "+
			"programBootstrapMapsLocked failure", err)
	}
	assertApplied10005(t, m, "after failed full apply", true)
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.lastSnapshot != retained {
		t.Error("failed full apply advanced lastSnapshot past the retained snapshot")
	}
	if m.publishedSnapshot != 0 {
		t.Errorf("publishedSnapshot = %d, want 0 — nothing was published", m.publishedSnapshot)
	}
}
