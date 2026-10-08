package upgrade

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
)

// #12175: RunRolling calls ForceSecondary (drain start) and then invokes the
// single-node cut. If the cut REFUSES before STOP (verifier REJECT, envelope
// refusal, no restorable rollback target), the error returned at
// rolling.go:374-377 WITHOUT ResetFailover — unlike the drain-timeout path
// (:328-361), which fails back and reads the result back. The rollback twin
// (runRollingRollbackWith) runs its refusal checks BEFORE demoting
// (:149-160). The node was left held at weight 0 with a healthy daemon while
// the doc (docs/in-place-upgrade.md:61-65) says PREFLIGHT/COPY/VERIFY
// failures leave things untouched.
//
// These cells drive runRollingWith against a REAL two-node cluster.Manager
// pair (loopback heartbeats, RG configured on both) behind a thin
// RollingCluster bridge, so the assertion is on the Manager's authoritative
// RG state (ManualFailover / weight / State) — not on fake forced/reset
// booleans. Each case starts from a genuinely PRIMARY local node, stages a
// refusal, and asserts (a) no pre-STOP refusal returns with a residual
// ManualFailover/weight-zero hold, and (b) the error still names the refusal.

// twoNodeManagers12175 builds a primary local node (node 0) and a secondary
// peer (node 1) on loopback heartbeats, and waits until both see the peer
// alive. The caller stops both heartbeats via cleanup.
func twoNodeManagers12175(t *testing.T) (local, peer *cluster.Manager) {
	t.Helper()
	local = cluster.NewManager(0, 1)
	peer = cluster.NewManager(1, 1)
	mkCfg := func(node int) *config.ClusterConfig {
		return &config.ClusterConfig{
			ClusterID: 1,
			NodeID:    node,
			RedundancyGroups: []*config.RedundancyGroup{
				{ID: 0, Preempt: true, NodePriorities: map[int]int{0: 200, 1: 100}},
				{ID: 1, Preempt: true, NodePriorities: map[int]int{0: 200, 1: 100}},
			},
		}
	}
	local.UpdateConfig(mkCfg(0))
	peer.UpdateConfig(mkCfg(1))
	// Loopback heartbeats: node 0 <-> node 1 use distinct IPv4 loopback
	// addresses and the fixed HeartbeatPort, so both real receivers can bind.
	if err := local.StartHeartbeat("127.0.0.1", "127.0.0.2", "", "lo"); err != nil {
		t.Fatalf("local StartHeartbeat: %v", err)
	}
	t.Cleanup(local.StopHeartbeat)
	if err := peer.StartHeartbeat("127.0.0.2", "127.0.0.1", "", "lo"); err != nil {
		t.Fatalf("peer StartHeartbeat: %v", err)
	}
	t.Cleanup(peer.StopHeartbeat)
	deadline := time.Now().Add(10 * time.Second)
	for {
		if local.PeerAlive() && peer.PeerAlive() {
			// The state seam establishes the specified starting ownership while
			// both Managers have a live peer and configured priority ordering.
			for _, rgID := range []int{0, 1} {
				local.SetGroupStateForTesting(rgID, cluster.StatePrimary)
				peer.SetGroupStateForTesting(rgID, cluster.StateSecondary)
			}
			return local, peer
		}
		if time.Now().After(deadline) {
			t.Fatalf("two-node pair never converged (local peerAlive=%v peer peerAlive=%v)",
				local.PeerAlive(), peer.PeerAlive())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// managerBridge12175 is a RollingCluster over a real local Manager. The sync
// predicates are healthy-test constants (session-sync has no loopback
// fixture here); ForceSecondary/ResetFailover and the RG readbacks hit the
// real Manager, which is the state under test.
type managerBridge12175 struct {
	m            *cluster.Manager
	synced       bool
	peerReady    bool
	drainPolls   int
	drainAfter   int
	resetCalls   int
	rejoinChecks int
}

func (b *managerBridge12175) PeerAlive() (bool, error) { return b.m.PeerAlive(), nil }
func (b *managerBridge12175) SyncEstablished() (bool, error) {
	return b.synced, nil
}
func (b *managerBridge12175) SessionSyncBulkPrimed() (bool, error) { return b.synced, nil }
func (b *managerBridge12175) HAProtocolCompatible() (bool, error)  { return true, nil }
func (b *managerBridge12175) SessionSyncWireCompatible() (bool, string, error) {
	return true, "test pair wire-compatible", nil
}
func (b *managerBridge12175) PeerTakeoverReady() (bool, error) { return b.peerReady, nil }
func (b *managerBridge12175) ForceSecondary() error            { return b.m.ForceSecondary() }
func (b *managerBridge12175) DrainComplete() (bool, error) {
	b.drainPolls++
	return b.drainPolls >= b.drainAfter, nil
}
func (b *managerBridge12175) ResetFailover() error {
	b.resetCalls++
	for _, st := range b.m.GroupStates() {
		if err := b.m.ResetFailover(st.GroupID); err != nil {
			return err
		}
	}
	return nil
}
func (b *managerBridge12175) LocalPrimary() (bool, error) { return b.m.IsLocalPrimaryAny(), nil }
func (b *managerBridge12175) LocalRejoinComplete() (bool, error) {
	b.rejoinChecks++
	for _, st := range b.m.GroupStates() {
		if st.ManualFailover || st.Weight == 0 {
			return false, nil
		}
	}
	return true, nil
}

// assertNoResidualHold12175 fails the test if any RG on m still carries the
// ForceSecondary hold (ManualFailover set or weight pinned at 0).
func assertNoResidualHold12175(t *testing.T, m *cluster.Manager) {
	t.Helper()
	for _, st := range m.GroupStates() {
		if st.ManualFailover {
			t.Errorf("RG %d still carries ManualFailover after a pre-STOP refusal (state=%v weight=%d)",
				st.GroupID, st.State, st.Weight)
		}
		if st.Weight == 0 {
			t.Errorf("RG %d still weight-0 after a pre-STOP refusal (state=%v manual=%v)",
				st.GroupID, st.State, st.ManualFailover)
		}
	}
}

func TestRolling_PreStopRefusalLeavesNoHold_12175(t *testing.T) {
	t.Run("verifier REJECT fails back with readback", func(t *testing.T) {
		local, _ := twoNodeManagers12175(t)
		if !local.IsLocalPrimary(1) {
			t.Fatalf("precondition: local node is not primary for data RG 1 (state=%v)", local.GroupState(1).State)
		}
		fs := newFakeSystem(t, "2.0.0")
		fs.verifyPass = false // staged dataplane rejected at VERIFY
		r, cfg := testEnv(t, fs)
		seedInitialCurrent(t, r, cfg, "1.0.0")
		br := &managerBridge12175{m: local, synced: true, peerReady: true, drainAfter: 1}

		err := runRollingWith(r, br, fastRC())
		if err == nil {
			t.Fatal("expected the verifier REJECT to abort the rolling cut, got nil")
		}
		if !strings.Contains(err.Error(), "REJECT") && !strings.Contains(err.Error(), "verify") {
			t.Fatalf("error does not name the verifier refusal: %v", err)
		}
		if fs.dropinContent != "" {
			t.Error("cut proceeded past a verifier REJECT (drop-in written)")
		}
		if !fs.unitRunning {
			t.Error("daemon stopped despite a pre-STOP verifier refusal")
		}
		if br.resetCalls == 0 {
			t.Error("ResetFailover never ran on the refusal path — the demotion was not failed back")
		}
		if br.rejoinChecks == 0 {
			t.Error("ResetFailover acknowledgement was not followed by per-RG rejoin readback")
		}
		assertNoResidualHold12175(t, local)
	})

	t.Run("envelope refusal fails back with readback", func(t *testing.T) {
		local, _ := twoNodeManagers12175(t)
		if !local.IsLocalPrimary(1) {
			t.Fatalf("precondition: local node is not primary for data RG 1 (state=%v)", local.GroupState(1).State)
		}
		fs := newFakeSystem(t, "2.0.0")
		fs.readerVersion = 1 // target reader below the live envelope floor
		r, cfg := testEnv(t, fs)
		seedInitialCurrent(t, r, cfg, "1.0.0")
		mkfile(t, cfg.ConfigDBDir+"/active.json",
			"#xpf-config-envelope v=1 writer=2.0.0 ast=1 min-reader=2 rollback-fmt=1 committed=1\n{}")
		br := &managerBridge12175{m: local, synced: true, peerReady: true, drainAfter: 1}

		err := runRollingWith(r, br, fastRC())
		if err == nil {
			t.Fatal("expected the envelope refusal to abort the rolling cut, got nil")
		}
		if !strings.Contains(err.Error(), "min-reader=2") {
			t.Fatalf("error does not name the envelope refusal: %v", err)
		}
		if fs.dropinContent != "" {
			t.Error("cut proceeded past an envelope refusal (drop-in written)")
		}
		if br.resetCalls == 0 {
			t.Error("ResetFailover never ran on the refusal path — the demotion was not failed back")
		}
		if br.rejoinChecks == 0 {
			t.Error("ResetFailover acknowledgement was not followed by per-RG rejoin readback")
		}
		assertNoResidualHold12175(t, local)
	})
}

type stopFailureSystem12175 struct {
	System
	err error
}

func (s stopFailureSystem12175) StopUnit(string) error { return s.err }

func TestRolling_StopAttemptFailureKeepsDrain_12175(t *testing.T) {
	local, _ := twoNodeManagers12175(t)
	fs := newFakeSystem(t, "2.0.0")
	r, cfg := testEnv(t, fs)
	seedInitialCurrent(t, r, cfg, "1.0.0")
	stopErr := errors.New("injected StopUnit failure")
	r.cfg.Sys = stopFailureSystem12175{System: fs, err: stopErr}
	br := &managerBridge12175{m: local, synced: true, peerReady: true, drainAfter: 1}

	err := runRollingWith(r, br, fastRC())
	if !errors.Is(err, stopErr) {
		t.Fatalf("rolling error = %v, want the StopUnit failure", err)
	}
	if br.resetCalls != 0 {
		t.Fatalf("ResetFailover called %d times after STOP was attempted; leave the drained node passive", br.resetCalls)
	}
	for _, st := range local.GroupStates() {
		if !st.ManualFailover || st.Weight != 0 {
			t.Errorf("RG %d lost its drain hold after StopUnit failure (manual=%v weight=%d)",
				st.GroupID, st.ManualFailover, st.Weight)
		}
	}
}
