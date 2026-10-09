package configstore

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestLoadOverrideCommitKeepsSplitBlockPreference_12084(t *testing.T) {
	store := newTestStore(t)
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	defer store.ExitConfigure()
	const text = `routing-options { static {
		route 10.0.0.0/8 { next-hop 192.0.2.1; preference 10; }
		route 10.0.0.0/8 { next-hop 192.0.2.2; }
	} }`
	if err := store.LoadOverride(text); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	committed, err := store.Commit()
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if committed != store.ActiveConfig() {
		t.Fatal("Commit returned config different from ActiveConfig")
	}
	if len(committed.RoutingOptions.StaticRoutes) != 1 {
		t.Fatalf("committed static routes = %+v, want one split-block route", committed.RoutingOptions.StaticRoutes)
	}
	route := committed.RoutingOptions.StaticRoutes[0]
	tiers := config.StaticRouteNextHopTiers(route)
	if route.Preference != 10 || len(tiers) != 1 || tiers[0].Preference != 10 ||
		len(tiers[0].NextHops) != 2 || tiers[0].NextHops[0].Address != "192.0.2.1" ||
		tiers[0].NextHops[1].Address != "192.0.2.2" {
		t.Fatalf("committed split-block tiers = %+v (route %+v), want both paths at base preference 10", tiers, route)
	}
}

func TestSyncApplyKeepsSplitBlockNoInstallExcluded_12084(t *testing.T) {
	store := newTestStore(t)
	const text = `routing-options { static {
		route 10.0.0.0/8 { next-hop 192.0.2.1; }
		route 10.0.0.0/8 { no-install; }
	} }`
	cfg, err := store.SyncApply(text, nil)
	if err != nil {
		t.Fatalf("SyncApply: %v", err)
	}
	if cfg != store.ActiveConfig() {
		t.Fatal("SyncApply returned config different from ActiveConfig")
	}
	if len(cfg.RoutingOptions.StaticRoutes) != 1 {
		t.Fatalf("synced static routes = %+v, want one split-block route", cfg.RoutingOptions.StaticRoutes)
	}
	route := cfg.RoutingOptions.StaticRoutes[0]
	if !route.NoInstall {
		t.Fatalf("SyncApply lost no-install: %+v", route)
	}
	if reason := config.StaticRouteExclusions(cfg)[route]; reason != "route has the `no-install` option set" {
		t.Fatalf("SyncApply exclusion reason = %q, want no-install", reason)
	}
	for _, warning := range cfg.Warnings {
		if strings.Contains(warning, "install and no-install") {
			t.Fatalf("same-spelling SyncApply emitted install conflict warning: %v", cfg.Warnings)
		}
	}
}
