package configstore

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestCommitCheckRejectsUnsupportedTunnelRITarget12520(t *testing.T) {
	cases := []struct {
		name         string
		target       string
		instanceType string
		wantReason   string
	}{
		{name: "reserved management", target: "mgmt", wantReason: "reserved for the management VRF"},
		{name: "undefined", target: "missing", wantReason: "undefined"},
		{name: "forwarding", target: "fwd", instanceType: "forwarding", wantReason: "forwarding instance"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestStore(t)
			if err := s.EnterConfigure(); err != nil {
				t.Fatalf("EnterConfigure: %v", err)
			}
			lines := []string{
				"set interfaces gr-0/0/0 tunnel source 192.0.2.1",
				"set interfaces gr-0/0/0 tunnel destination 192.0.2.2",
				"set interfaces gr-0/0/0 unit 0 family inet address 10.10.10.1/30",
				"set interfaces gr-0/0/0 tunnel routing-instance destination " + tc.target,
			}
			if tc.instanceType != "" {
				lines = append(lines, "set routing-instances "+tc.target+" instance-type "+tc.instanceType)
			}
			if _, err := s.LoadSet(strings.Join(lines, "\n")); err != nil {
				t.Fatalf("LoadSet: %v", err)
			}
			if _, err := s.CommitCheck(); err == nil {
				t.Fatalf("CommitCheck accepted unsupported tunnel target %q", tc.target)
			} else if !strings.Contains(err.Error(), "#12520") || !strings.Contains(err.Error(), tc.wantReason) {
				t.Fatalf("CommitCheck error %q does not identify %q and %q", err, tc.target, tc.wantReason)
			}
		})
	}
}

func assertQuarantinedTunnelTargets12520(t *testing.T, cfg *config.Config) {
	t.Helper()
	if cfg == nil {
		t.Fatal("compiled config is nil")
	}
	var warnings []string
	for _, warning := range cfg.Warnings {
		if strings.Contains(warning, "#12520") {
			warnings = append(warnings, warning)
		}
	}
	if len(warnings) != 2 {
		t.Fatalf("got %d #12520 warnings, want one per invalid tunnel claim: %v",
			len(warnings), warnings)
	}
	for _, tc := range []struct {
		ifName string
		target string
	}{
		{ifName: "gr-0/0/0", target: "missing"},
		{ifName: "gr-0/0/1", target: "mgmt"},
	} {
		ifName, target := tc.ifName, tc.target
		ifc := cfg.Interfaces.Interfaces[ifName]
		if ifc == nil {
			t.Fatalf("%s interface missing from compiled config", ifName)
		}
		if ifc.Tunnel != nil {
			t.Errorf("%s tunnel survived bad-target removal: %+v, want removed (#14390)", ifName, ifc.Tunnel)
		}
		found := false
		for _, warning := range warnings {
			if strings.Contains(warning, ifName) && strings.Contains(warning, target) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("warnings omit %s target %q: %v", ifName, target, warnings)
		}
	}
}

func TestLoadAndSyncApplyQuarantineUnsupportedTunnelTargets12520(t *testing.T) {
	const legacy = `interfaces {
  gr-0/0/0 {
    unit 0 { family inet { address 10.0.0.1/30; } }
    tunnel {
      source 192.0.2.1;
      destination 192.0.2.2;
      routing-instance { destination missing; }
    }
  }
  gr-0/0/1 {
    unit 0 { family inet { address 10.0.1.1/30; } }
    tunnel {
      source 192.0.2.3;
      destination 192.0.2.4;
      routing-instance { destination mgmt; }
    }
  }
}`
	path := filepath.Join(t.TempDir(), "config")
	s := newTestStoreAt(t, path)
	synced, err := s.SyncApply(legacy, nil)
	if err != nil {
		t.Fatalf("SyncApply rejected legacy tunnel targets: %v", err)
	}
	assertQuarantinedTunnelTargets12520(t, synced)

	loaded := newTestStoreAt(t, path)
	if err := loaded.Load(); err != nil {
		t.Fatalf("Load rejected persisted legacy tunnel targets: %v", err)
	}
	assertQuarantinedTunnelTargets12520(t, loaded.ActiveConfig())
}

func assertQuarantinedGRECollision12520(t *testing.T, cfg *config.Config, path string) {
	t.Helper()
	if cfg == nil {
		t.Fatalf("%s config is nil", path)
	}
	if ifc := cfg.Interfaces.Interfaces["gr-0/0/0"]; ifc == nil || ifc.Tunnel != nil {
		t.Errorf("%s quarantined collider remains active: %+v", path, ifc)
	}
	valid := cfg.Interfaces.Interfaces["gr-0/0/1"]
	if valid == nil || valid.Tunnel == nil {
		t.Errorf("%s valid GRE tunnel was removed", path)
	} else if valid.Tunnel.RoutingInstance != "" {
		t.Errorf("%s valid tunnel target = %q, want default routing domain", path,
			valid.Tunnel.RoutingInstance)
	}
	var targetWarning, duplicateWarning bool
	for _, warning := range cfg.Warnings {
		if strings.Contains(warning, "#12520") && strings.Contains(warning, "missing") {
			targetWarning = true
		}
		if strings.Contains(warning, "is skipped on tolerant load") &&
			strings.Contains(warning, "#12520") && strings.Contains(warning, "#10654") &&
			strings.Contains(warning, `"gr-0/0/0.0"`) &&
			strings.Contains(warning, `"gr-0/0/1.0"`) {
			duplicateWarning = true
		}
	}
	if !targetWarning {
		t.Errorf("%s warnings omit the quarantined target: %v", path, cfg.Warnings)
	}
	if !duplicateWarning {
		t.Errorf("%s warnings omit the post-quarantine GRE collision: %v", path,
			cfg.Warnings)
	}
}

// TestLoadAndSyncApplySkipQuarantinedGRECollision12520: a persisted tunnel
// whose bad target would land on another tunnel's GRE outer identity is
// removed on both tolerant paths (#14390), and the valid tunnel keeps it.
func TestLoadAndSyncApplySkipQuarantinedGRECollision12520(t *testing.T) {
	const legacy = `interfaces {
  gr-0/0/0 {
    tunnel {
      source 192.0.2.1;
      destination 192.0.2.2;
      routing-instance { destination missing; }
    }
    unit 0 { family inet { address 10.0.0.1/30; } }
  }
  gr-0/0/1 {
    tunnel { source 192.0.2.1; destination 192.0.2.2; }
    unit 0 { family inet { address 10.0.1.1/30; } }
  }
}`
	path := filepath.Join(t.TempDir(), "config")
	store := newTestStoreAt(t, path)
	synced, err := store.SyncApply(legacy, nil)
	if err != nil {
		t.Fatalf("SyncApply rejected legacy GRE collision: %v", err)
	}
	assertQuarantinedGRECollision12520(t, synced, "SyncApply")

	loaded := newTestStoreAt(t, path)
	if err := loaded.Load(); err != nil {
		t.Fatalf("Load rejected persisted GRE collision: %v", err)
	}
	assertQuarantinedGRECollision12520(t, loaded.ActiveConfig(), "Load")
}
