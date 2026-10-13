package config

import (
	"strings"
	"testing"
)

// #12633: S9/S10/S18/SET1 warn on the tolerant path without recording
// MalformedZonePairs, so the snapshot poison carrier never engages and
// the dropped deny fails open under permit-all.

func zonePairShape12633(t *testing.T, fromZone string) *ConfigTree {
	t.Helper()
	text := `security {
    zones { security-zone A; security-zone B; }
    policies {
        ` + fromZone + `
        global {
            policy g-permit {
                match { source-address any; destination-address any; application any; }
                then { permit; }
            }
        }
        default-policy permit-all;
    }
}`
	tree, errs := NewParser(text).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse #12633 shape: %v", errs)
	}
	return tree
}

func zonePairSetTree12633(t *testing.T) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	for _, l := range []string{
		"set security zones security-zone A",
		"set security zones security-zone B",
		"set security policies from-zone A policy p1 match source-address any",
		"set security policies from-zone A policy p1 match destination-address any",
		"set security policies from-zone A policy p1 match application any",
		"set security policies from-zone A policy p1 then deny",
		"set security policies global policy g-permit match source-address any",
		"set security policies global policy g-permit match destination-address any",
		"set security policies global policy g-permit match application any",
		"set security policies global policy g-permit then permit",
		"set security policies default-policy permit-all",
	} {
		path, err := ParseSetCommand(l)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", l, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", l, err)
		}
	}
	return tree
}

func TestTolerantZonePairShapesPoison12633(t *testing.T) {
	deny := `policy p1 { match { source-address any; destination-address any; application any; } then { deny; } }`
	for _, tc := range []struct {
		name       string
		fromZone   string
		wantRecord string // substring naming the intended pair
	}{
		{"S9-direct-nested", `from-zone A { to-zone B { ` + deny + ` } }`, `from-zone "A"`},
		{"S10-mixed-child-keyed-to-zone", `from-zone { A { to-zone B { ` + deny + ` } } }`, `to-zone B`},
		{"S18-container-to-zone-policy", `from-zone { A { to-zone { ` + deny + ` } } }`, "`policy policy`"},
		{"S18-keyed-to-zone-policy", `from-zone A { to-zone { ` + deny + ` } }`, "#12633"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := zonePairShape12633(t, tc.fromZone)
			if _, err := CompileConfig(tree); err == nil {
				t.Fatal("strict CompileConfig accepted the malformed zone-pair shape")
			}
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("tolerant compile must remain bootable: %v", err)
			}
			if len(cfg.Security.MalformedZonePairs) == 0 {
				t.Fatalf("shape recorded nothing in MalformedZonePairs; dropped deny would fail open (pairs=%v)", cfg.Security.Policies)
			}
			joined := strings.Join(cfg.Security.MalformedZonePairs, "\n")
			if !strings.Contains(joined, tc.wantRecord) {
				t.Fatalf("MalformedZonePairs %q does not name intended pair via %q", joined, tc.wantRecord)
			}
			if got := LenientDroppedPolicyLocator(cfg); got == "" {
				t.Fatal("tolerant compile did not add the snapshot poison carrier")
			}
		})
	}
}

func TestSetCommandPhantomZonePairPoisons12633(t *testing.T) {
	tree := zonePairSetTree12633(t)
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("strict CompileConfig accepted `from-zone A policy p1` (phantom A->p1 pair)")
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("tolerant compile must remain bootable: %v", err)
	}
	if len(cfg.Security.MalformedZonePairs) == 0 {
		t.Fatalf("set-command phantom pair recorded nothing in MalformedZonePairs (pairs=%v)", cfg.Security.Policies)
	}
	joined := strings.Join(cfg.Security.MalformedZonePairs, "\n")
	if !strings.Contains(joined, "#12633") || !strings.Contains(joined, `"A"`) || !strings.Contains(joined, "`policy p1`") {
		t.Fatalf("MalformedZonePairs %q does not name phantom pair A->p1", joined)
	}
	if got := LenientDroppedPolicyLocator(cfg); got == "" {
		t.Fatal("tolerant compile did not add the snapshot poison carrier for SET1 phantom pair")
	}
}
