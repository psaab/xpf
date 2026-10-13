package userspace

import (
	"errors"
	"os"
	"os/exec"
	"reflect"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func installPMechRouteDump9506(t *testing.T) {
	t.Helper()
	setPMechRouteDump9506(t, []netlink.Route{v96MainRoute(t, "10.99.0.0/24", unix.RTN_UNICAST, 3)}, nil)
	previousSource := pmechMainRouteSourceSelectorFn
	t.Cleanup(func() { pmechMainRouteSourceSelectorFn = previousSource })
	pmechMainRouteSourceSelectorFn = func() (bool, error) { return false, nil }
}

func pmechDedupCapture9506(uint64, uint32) (uint64, []QueueEpochSnapshot, uint64, []IpsecTunnelRowSnapshot) {
	return 1, []QueueEpochSnapshot{{Queue: 1000, Epoch: 2}}, 3,
		[]IpsecTunnelRowSnapshot{{STN: "st0", IfID: 9, LogicalIfindex: 3}}
}

func TestPMechContentHashIgnoresInventoryGenerations9506(t *testing.T) {
	installPMechRouteDump9506(t)
	cfg := overlayTestConfig()
	first := mustBuildSnapshot(t, cfg, config.UserspaceConfig{}, 7, 3)
	second := mustBuildSnapshot(t, cfg, config.UserspaceConfig{}, 8, 4)
	stampCaptureAuthority(first, pmechDedupCapture9506)
	stampCaptureAuthority(second, pmechDedupCapture9506)
	before := *second.PMechInventory
	before.TunnelRows = append([]IpsecPMechTunnelRowSnapshot(nil), before.TunnelRows...)
	a, aOK := snapshotContentHash(first)
	b, bOK := snapshotContentHash(second)
	if !aOK || !bOK || a != b {
		t.Fatal("inventory generations must not defeat the content hash")
	}
	if !reflect.DeepEqual(before, *second.PMechInventory) {
		t.Fatal("hashing mutated wire authority generations")
	}
	second.PMechInventory.TunnelRows[0].EffectivePrefixes = []string{"10.99.0.0/25"}
	changed, ok := snapshotContentHash(second)
	if !ok || changed == b {
		t.Fatal("semantic inventory change must still change the content hash")
	}
}

func pmechDedupManager9506(t *testing.T) (*Manager, *config.Config, map[string]int) {
	t.Helper()
	installPMechRouteDump9506(t)
	cfg := overlayTestConfig()
	m := New()
	m.proc = &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
	m.generation = 7
	m.lastSnapshot = mustBuildSnapshot(t, cfg, config.UserspaceConfig{}, 7, 0)
	m.SetCaptureEpochProvider(pmechDedupCapture9506)
	stampCaptureAuthority(m.lastSnapshot, m.captureEpochProvider)
	m.lastSnapshotHash, _ = snapshotContentHash(m.lastSnapshot)
	m.publishedSnapshot = 7
	m.publishedPlanKey = snapshotBindingPlanKey(m.lastSnapshot)
	m.xskLivenessProven = true
	m.lastStatus.ConfigSnapshotProtocolVersion = ProtocolVersion
	requests := make(map[string]int)
	m.controlRequestHook = func(req ControlRequest, status *ProcessStatus) error {
		requests[req.Type]++
		if status != nil && req.Snapshot != nil {
			*status = ProcessStatus{Enabled: true, ConfigSnapshotProtocolVersion: ProtocolVersion,
				LastSnapshotGeneration: req.Snapshot.Generation, LastFIBGeneration: req.Snapshot.FIBGeneration}
		}
		return nil
	}
	return m, cfg, requests
}

func TestPMechDuplicateOverlayPublishIsSkipped9506(t *testing.T) {
	m, cfg, requests := pmechDedupManager9506(t)
	overlay := []config.RouteOverlayEntry{{Destination: "0.0.0.0/0", NextHop: "172.16.80.1", Policy: "wan-failover"}}
	if published, err := m.PublishRouteOverlaySnapshot(cfg, overlay, nil); err != nil || !published {
		t.Fatalf("first overlay publish = %v, %v", published, err)
	}
	before := requests["apply_snapshot"]
	if published, err := m.PublishRouteOverlaySnapshot(cfg, overlay, nil); err != nil || published {
		t.Fatalf("provider-wired duplicate = %v, %v; want skipped", published, err)
	}
	if requests["apply_snapshot"] != before {
		t.Fatal("duplicate overlay sent apply_snapshot")
	}
	if published, err := m.RepublishCurrentCaptureAuthority(); err != nil || published {
		t.Fatalf("unchanged capture authority = %v, %v; want skipped", published, err)
	}
}

func TestPMechFIBBumpStaysBumpOnly9506(t *testing.T) {
	m, _, requests := pmechDedupManager9506(t)
	_, bumpErr := m.BumpFIBGeneration()
	if bumpErr != nil && !errors.Is(bumpErr, dataplane.ErrDataplaneNotArmed) {
		t.Fatalf("BumpFIBGeneration = %v, want successful control bump and no other failure", bumpErr)
	}
	m.mu.Lock()
	err := m.syncSnapshotLocked()
	m.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if requests["bump_fib_generation"] != 1 || requests["apply_snapshot"] != 0 {
		t.Fatalf("FIB bump must remain bump-only through the status tick: %v", requests)
	}
}
