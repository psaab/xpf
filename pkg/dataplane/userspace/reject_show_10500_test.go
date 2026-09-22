package userspace

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func seededRejectRepublishManager10500(t *testing.T, cfg *config.Config, feed map[string][]string) (*Manager, string) {
	t.Helper()
	dir, err := os.MkdirTemp("", "x10500")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	controlSock := filepath.Join(dir, "control.sock")
	m := New()
	m.proc = &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
	m.cfg.ControlSocket = controlSock
	m.generation = 5
	m.feedOverlay = cloneFeedOverlay(feed)
	var errBuild error
	m.lastSnapshot, errBuild = buildSnapshotWithSchedulerState(
		cfg, config.UserspaceConfig{ControlSocket: controlSock}, 5, 0, nil, nil, feed,
	)
	if errBuild != nil {
		t.Fatalf("build seed snapshot: %v", errBuild)
	}
	if len(m.lastSnapshot.Capabilities.PolicyContentRejected) != 0 {
		t.Fatalf("seed snapshot unexpectedly rejected policy content: %v", m.lastSnapshot.Capabilities.PolicyContentRejected)
	}
	m.lastStatus.ConfigSnapshotProtocolVersion = ProtocolVersion
	return m, controlSock
}

func assertRejectReasonsEqual10500(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("rejection reasons = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("rejection reason %d = %q, want %q; got=%v want=%v", i, got[i], want[i], got, want)
		}
	}
}

func TestUpdatePolicyScheduleStateRecordsRejectReasons10500(t *testing.T) {
	cfg := feedPolicyCfg("bad-actors", "any")
	feed := map[string][]string{"bad-actors": {"198.51.100.0/24"}}
	m, controlSock := seededRejectRepublishManager10500(t, cfg, feed)
	m.feedOverlay = nil
	reqs := startArmControlServer(t, controlSock, 1)

	if err := m.UpdatePolicyScheduleState(cfg, map[string]bool{}); err != nil {
		t.Fatalf("UpdatePolicyScheduleState: %v", err)
	}
	req := <-reqs
	if req.Snapshot == nil {
		t.Fatal("scheduler republish sent no snapshot")
	}
	if len(req.Snapshot.Capabilities.PolicyContentRejected) == 0 {
		t.Fatal("fixture did not flip to rejected")
	}
	assertRejectReasonsEqual10500(t, m.lastSnapshotRejectReasons,
		req.Snapshot.Capabilities.PolicyContentRejected)
}

func TestPublishRouteOverlaySnapshotRecordsRejectReasons10500(t *testing.T) {
	stubRuleListHermetic(t)
	cfg := feedPolicyCfg("bad-actors", "any")
	feed := map[string][]string{"bad-actors": {"198.51.100.0/24"}}
	m, controlSock := seededRejectRepublishManager10500(t, cfg, feed)
	m.feedOverlay = nil
	reqs := startArmControlServer(t, controlSock, 1)

	published, err := m.PublishRouteOverlaySnapshot(cfg, nil, map[string]bool{})
	if err != nil {
		t.Fatalf("PublishRouteOverlaySnapshot: %v", err)
	}
	if !published {
		t.Fatal("route-overlay republish was skipped; expected a content-rejection transition")
	}
	req := <-reqs
	if req.Snapshot == nil {
		t.Fatal("route-overlay republish sent no snapshot")
	}
	if len(req.Snapshot.Capabilities.PolicyContentRejected) == 0 {
		t.Fatal("fixture did not flip to rejected")
	}
	assertRejectReasonsEqual10500(t, m.lastSnapshotRejectReasons,
		req.Snapshot.Capabilities.PolicyContentRejected)
}

func TestRecordHelperStatusStampsIndependentRejectReasons10500(t *testing.T) {
	snap, err := buildSnapshot(goodAndBadPolicyCfg(), config.UserspaceConfig{}, 1, 0)
	if err != nil {
		t.Fatalf("buildSnapshot: %v", err)
	}
	m := New()
	m.recordPolicyContentRejectionLocked(snap.Capabilities.PolicyContentRejected)
	var status ProcessStatus
	m.recordHelperStatusLocked(&status)
	if len(status.LastSnapshotRejectReasons) != 1 {
		t.Fatalf("status.LastSnapshotRejectReasons = %v, want one reason", status.LastSnapshotRejectReasons)
	}
	status.LastSnapshotRejectReasons[0] = "mutated status copy"
	if m.lastSnapshotRejectReasons[0] == "mutated status copy" {
		t.Fatal("recordHelperStatusLocked exposed manager-owned rejection slice")
	}
}
