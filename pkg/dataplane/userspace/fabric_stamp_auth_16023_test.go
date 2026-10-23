package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16023: builder carries the attestation and the requirement onto the wire.

func fabricAuthCfg16023(t *testing.T) *config.Config {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, cmd := range []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster node 0",
		"set chassis cluster authentication-key aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"set chassis cluster fabric-interface fab0",
		"set chassis cluster fabric-interface-authenticated",
		"set security flow require-authenticated-fabric-stamps",
		"set interfaces fab0 fabric-options member-interfaces ge-0/0/0",
	} {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("parse %q: %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("set %q: %v", cmd, err)
		}
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return cfg
}

func TestFabricSnapshotCarriesLinkAuthenticated16023(t *testing.T) {
	cfg := fabricAuthCfg16023(t)
	fabrics := buildFabricSnapshots(cfg)
	if len(fabrics) != 1 {
		t.Fatalf("want 1 fabric, got %d (%v)", len(fabrics), fabrics)
	}
	if !fabrics[0].LinkAuthenticated {
		t.Fatal("attested fabric must carry link_authenticated=true")
	}
	if got := buildFlowSnapshot(cfg); !got.RequireAuthenticatedFabricStamps {
		t.Fatal("flow snapshot must carry require_authenticated_fabric_stamps=true")
	}
}

func TestFabricSnapshotUnauthenticatedByDefault16023(t *testing.T) {
	cfg := fabricAuthCfg16023(t)
	cfg.Chassis.Cluster.FabricLinkAuthenticated = false
	cfg.Security.Flow.RequireAuthenticatedFabricStamps = false
	fabrics := buildFabricSnapshots(cfg)
	if len(fabrics) != 1 || fabrics[0].LinkAuthenticated {
		t.Fatalf("unattested fabric must carry link_authenticated=false; got %v", fabrics)
	}
	if got := buildFlowSnapshot(cfg); got.RequireAuthenticatedFabricStamps {
		t.Fatal("flow snapshot must default require=false")
	}
}
