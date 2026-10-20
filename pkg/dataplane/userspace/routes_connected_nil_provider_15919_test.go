package userspace

import (
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
