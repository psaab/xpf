package userspace

import (
	"errors"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

// #15919: a clustered snapshot built before the daemon wires the RG
// provider (boot window: early applies, link-refresh / overlay publishes
// racing the first wiring in applyDataplaneAndHACore) must NOT suppress
// the node's own RG>0 connected prefixes. Before the fix the nil
// provider failed closed (peer-owned), so a clustered PRIMARY blackholed
// its own transit until wiring plus an ownership edge / commit
// republished. The wired-but-unknown-RG case keeps failing closed
// (pinned by TestConnectedPrefixesFilterUnknownClusteredRG15742).
func TestConnectedNilProviderKeepsOwnPrefixes15919(t *testing.T) {
	origRules := ruleListFn
	t.Cleanup(func() { ruleListFn = origRules })
	ruleListFn = func(int) ([]netlink.Rule, error) { return nil, nil }
	withLearnedRoutes(t, fixedLearned())

	cfg := clusteredConfig15742()
	interfaces := connectedRGInterfaces15742()

	if connectedRowPeerOwned(cfg, interfaces[0], nil) {
		t.Fatal("nil provider on clustered RG1 row = peer-owned; want not peer-owned (fail open until wired)")
	}
	if connectedRowPeerOwned(cfg, interfaces[1], nil) {
		t.Fatal("nil provider on clustered RG2 row = peer-owned; want not peer-owned (fail open until wired)")
	}

	routes, _, err := buildRouteSnapshotsWithRGPrimary(cfg, interfaces, nil, nil)
	if err != nil {
		t.Fatalf("buildRouteSnapshotsWithRGPrimary(nil provider): %v", err)
	}
	if !hasConnectedRoute15742(routes, "172.16.80.0/24") || !hasConnectedRoute15742(routes, "2001:559:8585:80::/64") {
		t.Fatalf("nil-provider build suppressed RG1 connected prefixes: %+v", routes)
	}
	if !hasConnectedRoute15742(routes, "10.0.61.0/24") {
		t.Fatalf("nil-provider build suppressed RG2 connected prefix: %+v", routes)
	}

	marked := markConnectedRGPeerOwned(cfg, interfaces, nil)
	for i, row := range marked {
		if row.ConnectedRGPeerOwned {
			t.Fatalf("nil-provider marking flagged row %d (%s) peer-owned", i, row.Name)
		}
	}
}

// The daemon-facing gate: a Manager whose provider was never wired must
// report the nil-provider window for clustered configs, and
// SetRGPrimaryProvider must close it (even when every RG verdict is
// unknown — wired-unknown still fails closed per-row). Standalone
// configs never require wiring. Clearing re-opens the window.
func TestManagerRGProviderWiredGate15919(t *testing.T) {
	m := &Manager{}
	if m.RGProviderWiredFor(clusteredConfig15742()) {
		t.Fatal("unwired manager reports provider wired for clustered config")
	}
	if !m.RGProviderWiredFor(&config.Config{}) {
		t.Fatal("standalone config must not require a wired provider")
	}
	m.SetRGPrimaryProvider(func(int) (bool, bool) { return false, false })
	if !m.RGProviderWiredFor(clusteredConfig15742()) {
		t.Fatal("wired manager must report provider wired even when every RG is unknown")
	}
	m.SetRGPrimaryProvider(nil)
	if m.RGProviderWiredFor(clusteredConfig15742()) {
		t.Fatal("cleared provider must report unwired again")
	}
	var nilMgr *Manager
	if !nilMgr.RGProviderWiredFor(clusteredConfig15742()) {
		t.Fatal("nil manager must not block snapshot builds")
	}
}

// Publisher-level gate (#15924 Codex P2): the Compile-only refusal left
// the partial publishers open — after SetRGPrimaryProvider(nil), an
// overlay or link-refresh publish cloned the retained clustered
// snapshot, rebuilt routes with the nil (fail-open) provider, and sent
// a peer-owned RG prefix unmarked to the helper. The single
// apply_snapshot send site now refuses clustered sends while unwired.
// This drives the REAL Compile, PublishRouteOverlaySnapshot, and
// RefreshInterfaceRowsForLink APIs against the fake-helper fixtures
// with the provider cleared, and asserts no apply_snapshot is sent.
// Re-wiring restores the overlay publish (positive control), and the
// wired peer-owned rebuild still suppresses the RG1 prefix.
func TestUnwiredPublishersRefuseClearedProvider15919(t *testing.T) {
	origRules := ruleListFn
	t.Cleanup(func() { ruleListFn = origRules })
	ruleListFn = func(int) ([]netlink.Rule, error) { return nil, nil }
	withLearnedRoutes(t, fixedLearned())

	cfg := clusteredConfig15742()
	// RG1 peer-owned, RG2 local: the baseline helper state is the
	// non-owner's, with the RG1 connected prefix suppressed.
	peerRG1 := RGPrimaryProvider(func(rgID int) (bool, bool) { return rgID != 1, true })
	snap := mustBuildSnapshot(t, cfg, config.UserspaceConfig{}, 7, 0)
	snap.Interfaces = markConnectedRGPeerOwned(cfg, connectedRGInterfaces15742(), peerRG1)
	var err error
	snap.Routes, _, err = buildRouteSnapshotsWithRGPrimary(cfg, snap.Interfaces, nil, peerRG1)
	if err != nil {
		t.Fatalf("baseline routes: %v", err)
	}
	if hasConnectedRoute15742(snap.Routes, "172.16.80.0/24") || !snap.Interfaces[0].ConnectedRGPeerOwned {
		t.Fatal("premise: baseline must suppress peer-owned RG1 (route absent, row marked)")
	}

	rec := &applyRecorder9520{}
	m := newRepublishManager9520(snap, rec)
	m.SetRGPrimaryProvider(peerRG1)

	// Real Compile gate: unwired clustered build is refused.
	unwired := New()
	if _, err := unwired.Compile(cfg); !errors.Is(err, errRGProviderNotWired) {
		t.Fatalf("Compile unwired = %v, want errRGProviderNotWired", err)
	}

	m.SetRGPrimaryProvider(nil)
	if m.RGProviderWiredFor(cfg) {
		t.Fatal("premise: cleared provider must report unwired")
	}

	// Overlay publish: refused, nothing sent, retry debt unarmed.
	published, err := m.PublishRouteOverlaySnapshot(cfg, nil, nil)
	if published || !errors.Is(err, errRGProviderNotWired) {
		t.Fatalf("overlay publish unwired = (%t, %v), want (false, errRGProviderNotWired)", published, err)
	}
	if len(rec.sent) != 0 {
		t.Fatalf("overlay publish sent %d snapshots while unwired, want 0", len(rec.sent))
	}
	if m.applySnapshotOutcomeUnknown {
		t.Fatal("refused (unsent) publish adopted retry debt; want untouched outcome state")
	}

	// Link-refresh publish: refused by the same send-site gate, after
	// its rebuild — assert the error, not the early-return no-op.
	linkPublished, linkErr := refreshForGate15919(t, m, cfg)
	if linkPublished || !errors.Is(linkErr, errRGProviderNotWired) {
		t.Fatalf("link refresh unwired = (%t, %v), want (false, errRGProviderNotWired)", linkPublished, linkErr)
	}
	if len(rec.sent) != 0 {
		t.Fatalf("link refresh sent %d snapshots while unwired, want 0", len(rec.sent))
	}

	// Positive control: re-wiring lifts the gate. The rebuilt content is
	// identical to what the helper already holds, so the publish
	// dedups to a no-op (false, nil) and sends nothing — the peer-owned
	// RG1 prefix stays suppressed either way; nothing unmarked can
	// reach the helper while wired with the peer-owned verdict.
	m.SetRGPrimaryProvider(peerRG1)
	published, err = m.PublishRouteOverlaySnapshot(cfg, nil, nil)
	if err != nil || published {
		t.Fatalf("overlay publish rewired = (%t, %v), want dedup no-op (false, nil)", published, err)
	}
	if len(rec.sent) != 0 {
		t.Fatalf("rewired dedup sent %d snapshots, want 0", len(rec.sent))
	}
	if hasConnectedRoute15742(m.lastSnapshot.Routes, "172.16.80.0/24") || !m.lastSnapshot.Interfaces[0].ConnectedRGPeerOwned {
		t.Fatal("retained snapshot lost the peer-owned RG1 suppression after rewired publish")
	}

	// Wired actual-send control (#15924 GLM2): the dedup above proves
	// the gate lifts, but not that a clustered snapshot can still be
	// SENT through the gated site — an always-refuse regression would
	// pass everything so far. Publish with a non-empty overlay so the
	// content changes and the fake helper must record a real
	// apply_snapshot; assert it carries the peer-owned suppression
	// (route absent, row marked), i.e. the gate admits wired sends
	// without weakening the marking.
	published, err = m.PublishRouteOverlaySnapshot(cfg, []config.RouteOverlayEntry{
		{Destination: "198.51.100.0/24", NextHop: "10.0.61.254", Policy: "gate-15919"},
	}, nil)
	if err != nil || !published {
		t.Fatalf("overlay publish wired with overlay = (%t, %v), want (true, nil)", published, err)
	}
	if len(rec.sent) != 1 {
		t.Fatalf("wired publish sent %d snapshots, want 1 (always-refuse gate would send 0)", len(rec.sent))
	}
	sent := rec.sent[0]
	if hasConnectedRoute15742(sent.Routes, "172.16.80.0/24") || !sent.Interfaces[0].ConnectedRGPeerOwned {
		t.Fatalf("wired send leaked peer-owned RG1: route present=%t marked=%t",
			hasConnectedRoute15742(sent.Routes, "172.16.80.0/24"), sent.Interfaces[0].ConnectedRGPeerOwned)
	}
	foundOverlay := false
	for _, route := range sent.Routes {
		if route.Destination == "198.51.100.0/24" {
			foundOverlay = true
		}
	}
	if !foundOverlay {
		t.Fatalf("wired send missing overlay route: %+v", sent.Routes)
	}
}

// refreshForGate15919 drives RefreshInterfaceRowsForLink on m with a
// link name present in the retained config. clusteredConfig15742 has
// no interface rows, so it grafts one configured interface (reth0,
// RG1) onto a copy of the config and re-points the retained snapshot
// at it; buildLinkSnapshot is stubbed so the rebuilt row differs from
// the retained one and the publish path (not the dedup skip) runs.
func refreshForGate15919(t *testing.T, m *Manager, cfg *config.Config) (published bool, err error) {
	t.Helper()
	linkCfg := *cfg
	linkCfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"reth0": {RedundancyGroup: 1, Units: map[int]*config.InterfaceUnit{80: {}}},
	}
	m.mu.Lock()
	m.lastSnapshot.Config = &linkCfg
	m.mu.Unlock()
	// Restore the exact retained-config pointer before returning (not via
	// t.Cleanup, which runs too late): the route-only publish's hybrid
	// guard (#5680) content-compares cfg against lastSnapshot.Config,
	// and the positive control below publishes with the original cfg.
	defer func() {
		m.mu.Lock()
		m.lastSnapshot.Config = cfg
		m.mu.Unlock()
	}()
	oldBuild := buildLinkSnapshot
	t.Cleanup(func() { buildLinkSnapshot = oldBuild })
	buildLinkSnapshot = func(name string) (int, int, string, []InterfaceAddressSnapshot) {
		if name == "reth0" {
			return 12, 9000, "02:00:00:00:15:19", nil
		}
		return 0, 0, "", nil
	}
	return m.RefreshInterfaceRowsForLink(&linkCfg, "reth0")
}
