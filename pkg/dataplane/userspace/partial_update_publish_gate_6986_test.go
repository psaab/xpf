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
)

// #6986: a PARTIAL update (update_neighbors / update_fabrics) must never claim
// that a Compile-DEFERRED full snapshot has been published.
//
// The two writebacks — RegenerateNeighborSnapshot and
// persistResolvedFabricsLocked — advance the generation so the partial-rebuild
// publish paths carry their mutation forward. Neither sends an apply_snapshot.
// When they also advanced publishedSnapshot unconditionally, they closed the
// level-triggered gate the status tick uses (publishedSnapshot <
// lastSnapshot.Generation), and the full snapshot Compile had deferred —
// policies, routes, interfaces, NAT — was never sent while the bookkeeping said
// it had been.
//
// These tests assert the END property, not the bookkeeping: the deferred
// content REACHES THE HELPER. That matters because the swallow has TWO
// independent kills. Fixing only publishedSnapshot leaves lastSnapshotHash
// refreshed from a snapshot that was never sent, and syncSnapshotLocked's
// content-dedup then returns without publishing anyway. A test that asserted
// only "publishedSnapshot is still behind" would pass against that half-fix.

// partialUpdateHarness6986 is the #5306 fabric-writeback harness, reused: a
// real Manager over a unix control socket that records every ControlRequest.
type partialUpdateHarness6986 struct {
	m        *Manager
	cfg      *config.Config
	mu       *sync.Mutex
	requests *[]ControlRequest
}

func (h *partialUpdateHarness6986) sent(t *testing.T, kind string) []ControlRequest {
	t.Helper()
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []ControlRequest
	for i := range *h.requests {
		if (*h.requests)[i].Type == kind {
			out = append(out, (*h.requests)[i])
		}
	}
	return out
}

func newPartialUpdateHarness6986(t *testing.T) *partialUpdateHarness6986 {
	t.Helper()
	dir := shortSockDir9322(t)
	controlSock := filepath.Join(dir, "control.sock")
	ln, err := net.Listen("unix", controlSock)
	if err != nil {
		t.Fatalf("listen control socket: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

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
	// #16843: cfg is clustered (Chassis.Cluster), so the #15919 send-site
	// gate refuses every apply_snapshot until the RG provider is wired.
	// These cells exercise the #6986 deferred-publish property, not the
	// unwired refusal (covered by routes_connected_nil_provider_15919_test.go),
	// so wire a provider as the daemon does before publishing.
	m.SetRGPrimaryProvider(func(int) (bool, bool) { return true, true })
	return &partialUpdateHarness6986{m: m, cfg: cfg, mu: &mu, requests: &requests}
}

// deferredMarkerZone6986 is content that exists ONLY in the deferred snapshot.
// The end-to-end assertions look for it in the apply_snapshot the status tick
// eventually sends: its presence is what says the DEFERRED generation reached
// the helper, as opposed to some later snapshot that happened to be published.
const deferredMarkerZone6986 = "deferred-only-zone-6986"

// seedDeferredPublish6986 models the manager immediately after Compile took its
// pendingXSKStartup branch: lastSnapshot holds generation 10 and was NEVER sent,
// publishedSnapshot is still 1, and lastSnapshotHash describes the generation-1
// content the helper actually has.
func (h *partialUpdateHarness6986) seedDeferredPublish(t *testing.T) {
	t.Helper()
	published := &ConfigSnapshot{
		Version:    ProtocolVersion,
		Generation: 1,
		Config:     h.cfg,
		Fabrics: []FabricSnapshot{{
			Name: "fab0", ParentInterface: "ge-0/0/0", ParentLinuxName: "ge-0-0-0",
			PeerAddress: "10.99.1.2", PeerMAC: "", Up: true,
		}},
	}
	hash, ok := snapshotContentHash(published)
	if !ok {
		t.Fatal("fixture: the published snapshot must hash")
	}

	deferred := *published
	deferred.Generation = 10
	deferred.Zones = []ZoneSnapshot{{Name: deferredMarkerZone6986, ID: 77}}
	// #16843: the deferred snapshot now carries one zone, so its Summary
	// must declare it or the #16056 send-site section gate refuses it.
	deferred.Summary.ZoneCount = len(deferred.Zones)

	h.m.mu.Lock()
	h.m.lastSnapshot = &deferred
	h.m.generation = 10
	h.m.publishedSnapshot = 1
	h.m.publishedPlanKey = snapshotBindingPlanKey(&deferred)
	h.m.lastSnapshotHash = hash
	// The XSK-startup window has ENDED — this is the state in which the status
	// tick is supposed to service the deferred publish. Without it
	// syncSnapshotLocked defers again and the test would prove nothing.
	h.m.xskLivenessProven = true
	h.m.mu.Unlock()

	if h.m.publishedSnapshot >= h.m.lastSnapshot.Generation {
		t.Fatalf("fixture: the swallow window must be OPEN before the partial update "+
			"(published=%d lastSnapshot.Generation=%d)",
			h.m.publishedSnapshot, h.m.lastSnapshot.Generation)
	}
}

// assertDeferredSnapshotReachesHelper drives the status tick's publish and
// asserts the deferred generation actually went out, carrying BOTH its own
// marker content and the partial update that landed on top of it.
func (h *partialUpdateHarness6986) assertDeferredSnapshotReachesHelper(t *testing.T, what string) *ConfigSnapshot {
	t.Helper()
	h.m.mu.Lock()
	gate := h.m.publishedSnapshot < h.m.lastSnapshot.Generation
	published, lastGen := h.m.publishedSnapshot, h.m.lastSnapshot.Generation
	h.m.mu.Unlock()
	if !gate {
		t.Fatalf("%s advanced publishedSnapshot over a DEFERRED full snapshot "+
			"(published=%d lastSnapshot.Generation=%d). The status tick's gate is now "+
			"false, so the deferred generation's policies/routes/interfaces/NAT will "+
			"never be apply_snapshot'd, while the bookkeeping says they were (#6986)",
			what, published, lastGen)
	}

	h.m.mu.Lock()
	syncErr := h.m.syncSnapshotLocked()
	h.m.mu.Unlock()
	// syncErr is NOT the assertion, and is deliberately not fatal. The publish
	// itself lands on the wire; what fails afterwards is the post-publish
	// applyHelperStatusLocked, which needs BPF maps this unit test does not load
	// ("userspace_ctrl map not loaded"). The #5306 harness this reuses notes the
	// same thing. Asserting on the RECORDED REQUEST rather than on the error is
	// also the stronger check: a publish that genuinely never happened records
	// nothing, so the assertion below cannot be satisfied by swallowing an error.
	applied := h.sent(t, "apply_snapshot")
	if len(applied) == 0 {
		t.Fatalf("%s: the status tick sent NO apply_snapshot (syncSnapshotLocked err=%v). "+
			"The generation gate was open, so this is the CONTENT-HASH half of the "+
			"swallow: the writeback refreshed lastSnapshotHash from a snapshot that was "+
			"never published, and syncSnapshotLocked's dedup then suppressed the publish "+
			"(#6986)", what, syncErr)
	}
	snap := applied[len(applied)-1].Snapshot
	if snap == nil {
		t.Fatalf("%s: apply_snapshot carried no snapshot", what)
	}
	foundMarker := false
	for _, z := range snap.Zones {
		if z.Name == deferredMarkerZone6986 {
			foundMarker = true
		}
	}
	if !foundMarker {
		t.Fatalf("%s: the published apply_snapshot does not carry the DEFERRED "+
			"generation's content (zone %q). Zones=%+v", what, deferredMarkerZone6986, snap.Zones)
	}
	return snap
}

// #6986 fail-on-revert, FABRIC arm.
func TestFabricWritebackDoesNotSwallowADeferredSnapshot6986(t *testing.T) {
	const resolvedMAC = "02:aa:bb:cc:dd:ee"
	h := newPartialUpdateHarness6986(t)
	h.seedDeferredPublish(t)

	resolved := FabricSnapshot{
		Name: "fab0", ParentInterface: "ge-0/0/0", ParentLinuxName: "ge-0-0-0",
		PeerAddress: "10.99.1.2", PeerMAC: resolvedMAC, Up: true,
	}
	h.m.fabricSnapshotBuilder = func(*config.Config) []FabricSnapshot {
		return []FabricSnapshot{resolved}
	}

	h.m.SyncFabricState()

	if got := h.sent(t, "update_fabrics"); len(got) == 0 {
		t.Fatal("fixture: SyncFabricState must have pushed update_fabrics, or the " +
			"writeback under test never ran")
	}

	snap := h.assertDeferredSnapshotReachesHelper(t, "SyncFabricState")
	// …and the partial update rides along, so the fix does not trade the
	// swallow for a stale-fabric republish (the #5306 property).
	if len(snap.Fabrics) != 1 || snap.Fabrics[0].PeerMAC != resolvedMAC {
		t.Fatalf("the deferred publish carried Fabrics %+v, want the RESOLVED MAC %q — "+
			"the #6986 fix must not cost the #5306 writeback", snap.Fabrics, resolvedMAC)
	}
}

// #6986 fail-on-revert, NEIGHBOR arm.
func TestNeighborWritebackDoesNotSwallowADeferredSnapshot6986(t *testing.T) {
	h := newPartialUpdateHarness6986(t)
	h.seedDeferredPublish(t)

	// Deterministic diff with no netlink dependence: `buildNeighborSnapshots`
	// returns nil for a config with no interfaces (neighbors.go), so seeding one
	// cached entry makes `neighborsEqualForwarding` false and the regeneration
	// proceeds to its `update_neighbors` push and the writeback under test.
	h.m.mu.Lock()
	h.m.lastSnapshot.Neighbors = []NeighborSnapshot{{
		Ifindex: 3, IP: "10.0.0.9", MAC: "02:00:00:00:00:09",
	}}
	h.m.mu.Unlock()

	h.m.RegenerateNeighborSnapshot()

	if got := h.sent(t, "update_neighbors"); len(got) == 0 {
		t.Fatal("fixture: RegenerateNeighborSnapshot must have pushed update_neighbors, " +
			"or the writeback under test never ran")
	}

	h.assertDeferredSnapshotReachesHelper(t, "RegenerateNeighborSnapshot")
}

// #6986 ANTI-OVER-FIX: when the full snapshot IS published, both writebacks must
// still advance publishedSnapshot and refresh lastSnapshotHash.
//
// Without this the fix could be "never advance", which reintroduces exactly what
// the original Copilot-review writeback prevented: the status loop would see
// every neighbor or fabric bump as an unpublished generation and force a
// redundant full apply_snapshot on each one — on the neighbor path that is every
// RTM_NEWNEIGH burst.
func TestPartialUpdateStillPublishesWhenNothingIsDeferred6986(t *testing.T) {
	h := newPartialUpdateHarness6986(t)
	snap := &ConfigSnapshot{
		Version:    ProtocolVersion,
		Generation: 4,
		Config:     h.cfg,
		Fabrics: []FabricSnapshot{{
			Name: "fab0", ParentInterface: "ge-0/0/0", ParentLinuxName: "ge-0-0-0",
			PeerAddress: "10.99.1.2", PeerMAC: "", Up: true,
		}},
	}
	hash, ok := snapshotContentHash(snap)
	if !ok {
		t.Fatal("fixture: snapshot must hash")
	}
	h.m.mu.Lock()
	h.m.lastSnapshot = snap
	h.m.generation = 4
	h.m.publishedSnapshot = 4 // fully published: no deferral outstanding
	h.m.lastSnapshotHash = hash
	h.m.mu.Unlock()

	resolved := snap.Fabrics[0]
	resolved.PeerMAC = "02:aa:bb:cc:dd:ee"
	h.m.fabricSnapshotBuilder = func(*config.Config) []FabricSnapshot {
		return []FabricSnapshot{resolved}
	}
	h.m.SyncFabricState()

	h.m.mu.Lock()
	defer h.m.mu.Unlock()
	if h.m.publishedSnapshot != h.m.lastSnapshot.Generation {
		t.Fatalf("publishedSnapshot = %d, want %d: with nothing deferred the writeback "+
			"must keep advancing it, or every neighbor/fabric bump forces a redundant "+
			"full apply_snapshot",
			h.m.publishedSnapshot, h.m.lastSnapshot.Generation)
	}
	newHash, ok := snapshotContentHash(h.m.lastSnapshot)
	if !ok {
		t.Fatal("post-writeback snapshot must hash")
	}
	if h.m.lastSnapshotHash != newHash {
		t.Fatal("lastSnapshotHash was not refreshed although the full snapshot was " +
			"published; churn in filtered-out rows could then leak through hash-dedup")
	}
}
