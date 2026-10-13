package userspace

import (
	"os"
	"os/exec"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func installPMechIdentityTunnelRoute9506(t *testing.T) {
	t.Helper()
	setPMechRouteDump9506(t, []netlink.Route{v96MainRoute(t, "10.0.0.0/24", unix.RTN_UNICAST, 10)}, nil)
}

func pmechIdentityCapture9506(uint64, uint32) (uint64, []QueueEpochSnapshot, uint64, []IpsecTunnelRowSnapshot) {
	return 41, []QueueEpochSnapshot{{Queue: 1000, Epoch: 9}}, 17,
		[]IpsecTunnelRowSnapshot{{STN: "st0", IfID: 9, LogicalIfindex: 10}}
}

func pmechIdentityConfig9506() *config.Config {
	cfg := scheduledPolicyConfig9520()
	cfg.Security.IPsec.VPNs = map[string]*config.IPsecVPN{
		"vpn": {BindInterface: "st0", LocalID: "192.0.2.0/24", RemoteID: "10.0.0.0/24"},
	}
	return cfg
}

func pmechIdentityManager9506(t *testing.T) (*Manager, *config.Config, *[]ConfigSnapshot) {
	t.Helper()
	stubRuleListHermetic(t)
	installPMechIdentityTunnelRoute9506(t)

	cfg := pmechIdentityConfig9506()
	m := New()
	m.proc = &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
	m.generation = 7
	m.lastStatus.ConfigSnapshotProtocolVersion = ProtocolVersion
	m.helperStatusObserved = true
	m.SetCaptureEpochProvider(pmechIdentityCapture9506)
	m.lastSnapshot = mustBuildSnapshotWithSchedulerState(
		t, cfg, config.UserspaceConfig{}, 7, 0, map[string]bool{"workhours": true}, nil, nil)
	stampCaptureAuthority(m.lastSnapshot, pmechIdentityCapture9506)
	if schedPolicyInactive5328(t, m.lastSnapshot.Policies, "scheduled-allow") {
		t.Fatal("precondition: seeded workhours policy must be active")
	}
	m.lastSnapshotHash, _ = snapshotContentHash(m.lastSnapshot)
	m.publishedSnapshot = 7
	m.publishedPlanKey = snapshotBindingPlanKey(m.lastSnapshot)
	m.xskLivenessProven = true

	published := make([]ConfigSnapshot, 0, 1)
	m.controlRequestHook = func(req ControlRequest, status *ProcessStatus) error {
		if req.Type == "apply_snapshot" && req.Snapshot != nil {
			published = append(published, *req.Snapshot)
			if status != nil {
				*status = ProcessStatus{
					Enabled:                       true,
					ConfigSnapshotProtocolVersion: ProtocolVersion,
					LastSnapshotGeneration:        req.Snapshot.Generation,
					LastFIBGeneration:             req.Snapshot.FIBGeneration,
				}
			}
		}
		return nil
	}
	return m, cfg, &published
}

func assertPMechIdentitySnapshot9506(t *testing.T, where string, snap *ConfigSnapshot) {
	t.Helper()
	if snap == nil || snap.PMechInventory == nil {
		t.Fatalf("%s: snapshot has no P-MECH inventory", where)
	}
	if len(snap.IpsecTunnelRows) != 1 || snap.IpsecTunnelRows[0].STN != "st0" ||
		len(snap.PMechInventory.TunnelRows) != 1 || snap.PMechInventory.TunnelRows[0].STN != "st0" {
		t.Fatalf("%s: active tunnel fixture missing: authority=%+v inventory=%+v",
			where, snap.IpsecTunnelRows, snap.PMechInventory.TunnelRows)
	}
	if !snap.PMechInventory.Complete || !snap.PMechInventory.TunnelRows[0].InventoryValid {
		t.Fatalf("%s: route-backed tunnel authority is not active: %+v", where, snap.PMechInventory)
	}
	got, want := snap.PMechInventory.PolicyIdentity, pmechPolicyIdentity(snap)
	if got == "" || got != want {
		t.Fatalf("%s: published policy identity %q does not describe exact snapshot identity %q",
			where, got, want)
	}
}

func assertPMechIdentityPublishedAndStored9506(t *testing.T, m *Manager, published []ConfigSnapshot) {
	t.Helper()
	if len(published) != 1 {
		t.Fatalf("apply_snapshot count = %d, want one scheduled-policy publication", len(published))
	}
	for i := range published {
		assertPMechIdentitySnapshot9506(t, "published snapshot", &published[i])
	}
	m.mu.Lock()
	var stored *ConfigSnapshot
	if m.lastSnapshot != nil {
		copy := *m.lastSnapshot
		stored = &copy
	}
	m.mu.Unlock()
	assertPMechIdentitySnapshot9506(t, "stored snapshot", stored)
}

func TestPMechIdentityStampedAfterOverlayRebuild9506(t *testing.T) {
	m, cfg, published := pmechIdentityManager9506(t)
	ok, err := m.PublishRouteOverlaySnapshot(cfg, nil, map[string]bool{"workhours": false})
	if err != nil {
		t.Fatalf("PublishRouteOverlaySnapshot: %v", err)
	}
	if !ok {
		t.Fatal("scheduler flip was deduplicated instead of published")
	}
	if !schedPolicyInactive5328(t, (*published)[0].Policies, "scheduled-allow") {
		t.Fatal("published workhours=false policy is not inactive")
	}
	assertPMechIdentityPublishedAndStored9506(t, m, *published)
}

func TestPMechIdentityStampedAfterScheduleRebuild9506(t *testing.T) {
	m, cfg, published := pmechIdentityManager9506(t)
	if err := m.UpdatePolicyScheduleState(cfg, map[string]bool{"workhours": false}); err != nil {
		t.Fatalf("UpdatePolicyScheduleState: %v", err)
	}
	if len(*published) != 1 || !schedPolicyInactive5328(t, (*published)[0].Policies, "scheduled-allow") {
		t.Fatal("scheduled publication did not carry the workhours=false policy")
	}
	assertPMechIdentityPublishedAndStored9506(t, m, *published)
}

func TestCaptureAuthorityCommitterRunsOnReconciledSnapshot9506(t *testing.T) {
	m := New()
	snap := &ConfigSnapshot{Generation: 19, IpsecTunnelSnapshotGeneration: 23}
	m.lastSnapshot = snap
	var calls int
	var gotGeneration uint64
	var gotSnapshot *ConfigSnapshot
	m.SetCaptureAuthorityCommitter(func(generation uint64, snapshot *ConfigSnapshot) {
		calls++
		gotGeneration = generation
		gotSnapshot = snapshot
	})

	m.mu.Lock()
	m.markAppliedSnapshotLocked()
	m.mu.Unlock()
	if calls != 1 || gotGeneration != 19 || gotSnapshot != snap {
		t.Fatalf("capture authority commit = calls:%d generation:%d snapshot:%p; want 1/19/%p",
			calls, gotGeneration, gotSnapshot, snap)
	}
}
