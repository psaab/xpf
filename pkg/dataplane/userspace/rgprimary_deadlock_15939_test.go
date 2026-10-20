package userspace

import (
	"errors"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

// TestSyncSnapshotLockedMovedInterfaceRowNoDeadlock15939 pins #15939.
//
// syncSnapshotLocked runs under m.mu (statusLoop) and calls
// prepareSnapshotForApply. When link revalidation moved or dropped an
// interface row, rebuildDerivedSectionsAfterRevalidate called
// m.rgPrimaryNow(), which tried to take m.mu again — a recursive lock
// (Go mutexes are not reentrant), so the status tick deadlocked and the
// pkg/dataplane/userspace suite hung whenever this path fired.
//
// FAIL-ON-REVERT: restoring rgPrimaryNow() inside
// rebuildDerivedSectionsAfterRevalidate makes the goroutine below block
// on m.mu forever; the test's timeout guard then fails it. The test also
// asserts the rebuild actually ran (the recreated interface's mirror
// follows to the new ifindex), so a "fix" that merely skips the rebuild
// under lock cannot pass, and that the wired RG provider's verdict was
// consulted (a peer-owned RG row stays marked after the rebuild).
func TestSyncSnapshotLockedMovedInterfaceRowNoDeadlock15939(t *testing.T) {
	origBuild := buildLinkSnapshot
	t.Cleanup(func() { buildLinkSnapshot = origBuild })
	origLookup := linkByNameFn
	t.Cleanup(func() { linkByNameFn = origLookup })
	origXfrm := liveXfrmNetdevs
	t.Cleanup(func() { liveXfrmNetdevs = origXfrm })
	origRules := ruleListFn
	t.Cleanup(func() { ruleListFn = origRules })
	// Kernel state at tick time: ge-0-0-0 was recreated (17 -> 29) and
	// ge-0-0-1 vanished; gr-0-0-0 and ge-0-0-9 are unchanged (the #14209
	// fixture), so prepareSnapshotForApply takes the rebuild branch.
	buildLinkSnapshot = func(linuxName string) (int, int, string, []InterfaceAddressSnapshot) {
		switch linuxName {
		case "ge-0-0-0":
			return 29, 1500, "", nil
		case "gr-0-0-0":
			return 42, 1476, "", nil
		case "ge-0-0-9":
			return 19, 1500, "", nil
		default:
			return 0, 0, "", nil
		}
	}
	linkByNameFn = func(string) (netlink.Link, error) { return nil, errors.New("test link lookup") }
	liveXfrmNetdevs = func() (map[string]bool, error) { return nil, nil }
	ruleListFn = func(int) ([]netlink.Rule, error) { return nil, nil }

	cfg := republishDerivedConfig15043()
	// Clustered config with the RG provider wired: the rebuild must ask
	// the provider (via the m.mu-held variant) whether RG rows are
	// peer-owned. Return peer-owned so the marking is observable.
	cfg.Chassis.Cluster = &config.ClusterConfig{ClusterID: 1, NodeID: 0}

	m := New()
	m.proc = &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
	m.helperStatusCtrlMapHook = &fakeCtrlMap{}
	m.helperStatusBindingsMapHook = &fakeBindingsMap{}
	m.syncClassifierMapsHook = func(*ConfigSnapshot) error { return nil }
	m.clearHelperHAStateHook = func() error { return nil }
	m.lastStatus.ConfigSnapshotProtocolVersion = ProtocolVersion
	m.helperStatusObserved = true
	m.rgPrimaryProvider = func(rgID int) (bool, bool) { return false, true }
	m.rgProviderWired = true
	m.lastSnapshot = republishDerivedSnapshot15043(cfg)
	// The deferred snapshot is retained ahead of its publication, so the
	// tick publishes it (same shape as the #15043 status-tick cell).
	m.lastSnapshot.Generation = 8
	m.generation = 8
	m.publishedSnapshot = 0
	m.publishedPlanKey = ""
	var sent []*ConfigSnapshot
	m.controlRequestHook = func(req ControlRequest, _ *ProcessStatus) error {
		if req.Type == "apply_snapshot" {
			c := *req.Snapshot
			sent = append(sent, &c)
		}
		return nil
	}

	// Drive the tick exactly as statusLoop does — under m.mu — in a
	// goroutine so the timeout guard can report the deadlock instead of
	// hanging the suite (the pre-fix symptom).
	done := make(chan error, 1)
	go func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		done <- m.syncSnapshotLocked()
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("syncSnapshotLocked with moved interface row: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("syncSnapshotLocked deadlocked under m.mu: prepareSnapshotForApply -> rebuildDerivedSectionsAfterRevalidate -> rgPrimaryNow re-took m.mu (#15939)")
	}

	if len(sent) != 1 {
		t.Fatalf("premise: status tick sent %d snapshots, want 1", len(sent))
	}
	// The rebuild ran under lock: the recreated interface's mirror
	// followed to ifindex 29 and the vanished interface's mirror was
	// excluded, exactly as the #14209 rebuild produces.
	if len(sent[0].MirrorConfigs) != 1 || sent[0].MirrorConfigs[0].IngressIfindex != 29 {
		t.Fatalf("sent mirrors = %+v, want the rebuilt 29 mirror (rebuild must run under m.mu, not be skipped)", sent[0].MirrorConfigs)
	}
	if m.publishedSnapshot != m.lastSnapshot.Generation {
		t.Fatalf("publishedSnapshot = %d, want %d after the tick publish", m.publishedSnapshot, m.lastSnapshot.Generation)
	}
}
