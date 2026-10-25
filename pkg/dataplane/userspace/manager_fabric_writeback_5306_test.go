package userspace

import (
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

// TestSyncFabricStatePersistsResolvedFabricsIntoLastSnapshot is the #5306
// fail-on-revert guard.
//
// SyncFabricState resolves a late fabric peer MAC (normal HA startup) and pushes
// it to the helper via update_fabrics; it MUST ALSO write that resolved set back
// into m.lastSnapshot.Fabrics. Otherwise the very next partial-rebuild publish
// (PublishRouteOverlaySnapshot here — but the policy-scheduler republish and the
// #5134 worker-arm re-apply share the `next := *m.lastSnapshot` shape) rebuilds
// ONLY Routes and re-publishes the STALE, unresolved-MAC fabrics verbatim,
// silently reverting the helper to the unresolved fabric MAC during the exact HA
// window fabric cross-chassis forwarding exists to preserve.
//
// Removing the persistResolvedFabricsLocked writeback fails BOTH assertions:
// the direct lastSnapshot check and the end-to-end apply_snapshot check.
func TestSyncFabricStatePersistsResolvedFabricsIntoLastSnapshot(t *testing.T) {
	const resolvedMAC = "02:aa:bb:cc:dd:ee"

	// The ip-monitoring overlay rebuild enumerates ip rules via netlink; stub it
	// so the route rebuild is hermetic and deterministic in a unit test.
	origRuleList := ruleListFn
	t.Cleanup(func() { ruleListFn = origRuleList })
	ruleListFn = func(int) ([]netlink.Rule, error) { return nil, nil }

	dir := shortSockDir9322(t)
	controlSock := filepath.Join(dir, "control.sock")
	ln, err := net.Listen("unix", controlSock)
	if err != nil {
		t.Fatalf("listen control socket: %v", err)
	}
	defer ln.Close()

	var (
		mu       sync.Mutex
		requests []ControlRequest
	)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			var req ControlRequest
			if err := json.NewDecoder(conn).Decode(&req); err != nil {
				conn.Close()
				continue
			}
			mu.Lock()
			requests = append(requests, req)
			mu.Unlock()
			// Reply with a minimal OK status. The post-publish
			// applyHelperStatusLocked needs BPF maps not loaded here and returns
			// an error, but the overlay path only logs it — the wire requests are
			// what this test validates.
			_ = json.NewEncoder(conn).Encode(ControlResponse{
				OK:     true,
				Status: &ProcessStatus{PID: 4321},
			})
			conn.Close()
		}
	}()

	proc, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatalf("FindProcess: %v", err)
	}

	cfg := &config.Config{}
	cfg.Chassis.Cluster = &config.ClusterConfig{
		FabricInterface:   "fab0",
		FabricPeerAddress: "10.99.1.2",
	}

	m := New()
	m.proc = &exec.Cmd{Process: proc}
	m.cfg.ControlSocket = controlSock
	// #16843: cfg is clustered, so wire the RG provider (as the daemon
	// does) or the #15919 send-site gate refuses the overlay publish
	// this cell asserts on.
	m.SetRGPrimaryProvider(func(int) (bool, bool) { return true, true })

	// Baseline published snapshot: the fabric peer MAC is UNRESOLVED (empty), as
	// it would be at the first full apply during HA startup before neighbor
	// resolution completes.
	staleFabric := FabricSnapshot{
		Name:            "fab0",
		ParentInterface: "ge-0/0/0",
		ParentLinuxName: "ge-0-0-0",
		PeerAddress:     "10.99.1.2",
		PeerMAC:         "", // unresolved
		Up:              true,
	}
	m.lastSnapshot = &ConfigSnapshot{
		Version:    ProtocolVersion,
		Generation: 1,
		Config:     cfg,
		Fabrics:    []FabricSnapshot{staleFabric},
	}
	m.generation = 1
	m.publishedSnapshot = 1
	if h, ok := snapshotContentHash(m.lastSnapshot); ok {
		m.lastSnapshotHash = h
	}

	// SyncFabricState now resolves the peer MAC. Inject the resolved set (no real
	// netlink neighbor state exists in a unit test) so the resolution is
	// deterministic and distinguishable from the stale baseline.
	resolvedFabric := staleFabric
	resolvedFabric.PeerMAC = resolvedMAC
	m.fabricSnapshotBuilder = func(*config.Config) []FabricSnapshot {
		return []FabricSnapshot{resolvedFabric}
	}

	m.SyncFabricState()

	// Assertion 1 (direct writeback): the resolved MAC landed in lastSnapshot so
	// a subsequent `next := *m.lastSnapshot` carries it forward.
	m.mu.Lock()
	got := append([]FabricSnapshot(nil), m.lastSnapshot.Fabrics...)
	m.mu.Unlock()
	if len(got) != 1 || got[0].PeerMAC != resolvedMAC {
		t.Fatalf("lastSnapshot.Fabrics after SyncFabricState = %+v, want one entry with PeerMAC %q "+
			"(resolved MAC was not written back — #5306 revert)", got, resolvedMAC)
	}

	// Assertion 2 (end-to-end): a subsequent route-overlay publish must carry the
	// RESOLVED fabric MAC in its apply_snapshot, not the stale unresolved one.
	overlay := []config.RouteOverlayEntry{{Destination: "10.9.9.0/24", NextHop: "10.0.0.1"}}
	published, err := m.PublishRouteOverlaySnapshot(cfg, overlay, nil)
	if err != nil {
		t.Fatalf("PublishRouteOverlaySnapshot: %v", err)
	}
	if !published {
		t.Fatal("route overlay publish was skipped; expected a real apply_snapshot carrying the resolved fabrics")
	}

	mu.Lock()
	defer mu.Unlock()
	var applied *ConfigSnapshot
	sawUpdateFabrics := false
	for i := range requests {
		switch requests[i].Type {
		case "update_fabrics":
			sawUpdateFabrics = true
			if len(requests[i].Fabrics) != 1 || requests[i].Fabrics[0].PeerMAC != resolvedMAC {
				t.Fatalf("update_fabrics sent %+v, want one entry with PeerMAC %q",
					requests[i].Fabrics, resolvedMAC)
			}
		case "apply_snapshot":
			applied = requests[i].Snapshot
		}
	}
	if !sawUpdateFabrics {
		t.Fatal("SyncFabricState never sent update_fabrics")
	}
	if applied == nil {
		t.Fatal("route overlay publish did not send an apply_snapshot")
	}
	if len(applied.Fabrics) != 1 || applied.Fabrics[0].PeerMAC != resolvedMAC {
		t.Fatalf("apply_snapshot carried Fabrics %+v, want one entry with PeerMAC %q "+
			"(overlay re-published the STALE fabric MAC — #5306 revert)", applied.Fabrics, resolvedMAC)
	}
}

// TestPersistResolvedFabricsLockedNoOpOnUnchanged asserts the writeback does not
// churn the snapshot generation when SyncFabricState re-resolves the SAME fabric
// set (the daemon calls it after every refreshFabricFwd). A per-call generation
// bump would make the status reconcile loop treat each steady-state fabric sync
// as an unpublished generation.
func TestPersistResolvedFabricsLockedNoOpOnUnchanged(t *testing.T) {
	m := New()
	fabrics := []FabricSnapshot{{Name: "fab0", PeerMAC: "02:aa:bb:cc:dd:ee", Up: true}}
	m.lastSnapshot = &ConfigSnapshot{Version: ProtocolVersion, Generation: 7, Fabrics: fabrics}
	m.generation = 7
	m.publishedSnapshot = 7

	m.mu.Lock()
	// A distinct-but-equal slice (same content) must be a no-op.
	m.persistResolvedFabricsLocked(append([]FabricSnapshot(nil), fabrics...))
	gen := m.generation
	snapGen := m.lastSnapshot.Generation
	m.mu.Unlock()

	if gen != 7 || snapGen != 7 {
		t.Fatalf("unchanged fabrics bumped generation: m.generation=%d snapshot.Generation=%d, want 7/7",
			gen, snapGen)
	}
}
