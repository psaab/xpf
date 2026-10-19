package config

import (
	"strings"
	"testing"
)

// #15048 (A25-01): a vrrp-group `track-interface` naming no configured
// interface or unit committed clean. CollectInstances then stored a name
// resolving to no netdev, seedTrackState held the group at reduced
// priority for the life of the config, and real link events (matched by
// exact kernel name) were never seen — HA ownership wrong forever, the
// intended tracking disabled.
//
// FAIL-ON-REVERT: drop the validateVRRPTrackInterfaceRefStrict dispatch
// (compiler_uniformgates_cluster_zone.go) or its unresolvedInterfaceRef
// check and the strict-reject cells below go green on the BAD config.
// The declared controls (bare, unit, VLAN unit, reth, dash spelling)
// must stay green — no behaviour change outside the cited mechanism.

func trackRefCfg15048(t *testing.T, track string) *ConfigTree {
	t.Helper()
	return buildTree(t, []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24 vrrp-group 1 virtual-address 10.0.0.3/24",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24 vrrp-group 1 priority 200",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24 vrrp-group 1 track-interface " + track + " priority-cost 20",
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.1.1/24",
		"set interfaces ge-0/0/1 vlan-tagging",
		"set interfaces ge-0/0/1 unit 100 vlan-id 100 family inet address 10.0.100.1/24",
		"set interfaces ge-0/0/2 gigether-options redundant-parent reth1",
		"set interfaces reth1 redundant-ether-options redundancy-group 1",
		"set interfaces reth1 unit 0 family inet address 10.0.2.1/24",
	})
}

func TestVRRPTrackInterfaceRefStrict15048(t *testing.T) {
	cases := []struct {
		name    string
		track   string
		wantErr string // "" = must commit
	}{
		{"declared bare", "ge-0/0/1", ""},
		{"declared unit zero", "ge-0/0/1.0", ""},
		{"declared vlan unit", "ge-0/0/1.100", ""},
		{"declared reth", "reth1", ""},
		{"declared reth unit", "reth1.0", ""},
		{"dash spelling", "ge-0-0-1", ""},
		{"undeclared interface", "ge-0/0/9", "names no configured interface"},
		{"undeclared unit", "ge-0/0/1.7", "names no configured unit on ge-0/0/1"},
		{"malformed unit", "ge-0/0/1.foo", "has an unparseable unit"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(trackRefCfg15048(t, tc.track))
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("track-interface %q must commit, got: %v", tc.track, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("track-interface %q must fail strict commit (%s), got nil", tc.track, tc.wantErr)
			}
			if !strings.Contains(err.Error(), "track-interface "+tc.track) || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q must name the track-interface %q and %q", err, tc.track, tc.wantErr)
			}
		})
	}
}

func TestVRRPTrackInterfaceRefLenientWarns15048(t *testing.T) {
	for _, track := range []string{"ge-0/0/9", "ge-0/0/1.7"} {
		cfg, err := CompileConfigLenient(trackRefCfg15048(t, track))
		if err != nil {
			t.Fatalf("lenient compile of track-interface %q must not reject (no-brick): %v", track, err)
		}
		if !hasWarningContaining(cfg.Warnings, "track-interface "+track) {
			t.Errorf("lenient compile of track-interface %q must warn naming it; warnings=%v", track, cfg.Warnings)
		}
	}
	// Control: a declared track target warns about nothing track-related.
	cfg, err := CompileConfigLenient(trackRefCfg15048(t, "ge-0/0/1.100"))
	if err != nil {
		t.Fatalf("lenient compile of declared track-interface: %v", err)
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "track-interface ge-0/0/1.100") && strings.Contains(w, "names no configured") {
			t.Errorf("declared VLAN-unit track-interface must not warn as unresolved: %v", cfg.Warnings)
		}
	}
}
