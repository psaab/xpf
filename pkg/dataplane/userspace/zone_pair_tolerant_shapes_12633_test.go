package userspace

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestTolerantZonePairShapesSnapshotRefused12633(t *testing.T) {
	deny := `policy p1 {
        match { source-address any; destination-address any; application any; }
        then { deny; }
    }`
	for _, tc := range []struct {
		name     string
		fromZone string
		setCmds  []string
	}{
		{"S9-direct-nested", `from-zone A { to-zone B { ` + deny + ` } }`, nil},
		{"S10-mixed-child-keyed-to-zone", `from-zone { A { to-zone B { ` + deny + ` } } }`, nil},
		{"S18-container-to-zone-policy", `from-zone { A { to-zone { ` + deny + ` } } }`, nil},
		{"SET1-set-command-phantom", "", []string{
			"set security policies from-zone A policy p1 match source-address any",
			"set security policies from-zone A policy p1 match destination-address any",
			"set security policies from-zone A policy p1 match application any",
			"set security policies from-zone A policy p1 then deny",
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var cfg *config.Config
			var err error
			if tc.setCmds != nil {
				tree := &config.ConfigTree{}
				cmds := []string{"set security zones security-zone A", "set security zones security-zone B",
					"set security policies global policy g-permit match source-address any",
					"set security policies global policy g-permit match destination-address any",
					"set security policies global policy g-permit match application any",
					"set security policies global policy g-permit then permit",
					"set security policies default-policy permit-all"}
				cmds = append(cmds[:2:2], append(tc.setCmds, cmds[2:]...)...)
				for _, c := range cmds {
					path, perr := config.ParseSetCommand(c)
					if perr != nil {
						t.Fatalf("ParseSetCommand(%q): %v", c, perr)
					}
					if err := tree.SetPath(path); err != nil {
						t.Fatalf("SetPath(%q): %v", c, err)
					}
				}
				cfg, err = config.CompileConfigLenient(tree)
			} else {
				cfg, _ = mixedZonePairSnapshot12231(t, tc.fromZone)
				// mixedZonePairSnapshot12231 returns cfg+snap; re-check snap below via cfg
				_ = err
				snap, serr := buildSnapshot(cfg, config.UserspaceConfig{}, 1, 0)
				if serr != nil {
					t.Fatalf("buildSnapshot: %v", serr)
				}
				assertSnapshotRefused12633(t, cfg, snap)
				return
			}
			if err != nil {
				t.Fatalf("CompileConfigLenient: %v", err)
			}
			snap, serr := buildSnapshot(cfg, config.UserspaceConfig{}, 1, 0)
			if serr != nil {
				t.Fatalf("buildSnapshot: %v", serr)
			}
			assertSnapshotRefused12633(t, cfg, snap)
		})
	}
}

func assertSnapshotRefused12633(t *testing.T, cfg *config.Config, snap *ConfigSnapshot) {
	t.Helper()
	if len(cfg.Security.MalformedZonePairs) == 0 {
		t.Fatalf("shape recorded nothing in MalformedZonePairs; warnings=%q", strings.Join(cfg.Warnings, " | "))
	}
	if len(snap.Capabilities.PolicyContentRejected) == 0 {
		t.Fatalf("snapshot has no whole-snapshot refusal; dropped deny falls through to permit fallback; policies=%+v", snap.Policies)
	}
	sawSentinel := false
	for _, rule := range snap.Policies {
		for _, term := range rule.ApplicationTerms {
			if term.Name == unsupportedApplicationSentinel || term.Protocol == unsupportedApplicationSentinel {
				sawSentinel = true
			}
		}
	}
	if !sawSentinel {
		t.Fatal("snapshot carries rejection reason but no __unsupported__ wire sentinel")
	}
	if reasons := PolicyContentRejectionReasons(cfg, nil); len(reasons) == 0 {
		t.Fatal("config-level simulator does not refuse the malformed snapshot")
	}
}
