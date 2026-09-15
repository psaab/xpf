package userspace

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// Unknown NAT `match` leaves — #9877 builder cells.
//
// End to end through the TOLERANT load (CompileConfigLenient): a rule whose
// match lost unknown leaves must not install as the surviving dimensions
// only. Non-exemption rules skip (fail-closed); keyable exemptions install
// (warned). The compile-side record/gate is pinned in pkg/config
// (nat_match_unknown_9877_test.go); this file pins the snapshot verdict.

// lenientNATCfg9877 compiles set-lines on the tolerant load / peer-sync path.
func lenientNATCfg9877(t *testing.T, cmds []string) *config.Config {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, cmd := range cmds {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	return cfg
}

func warnNames9877(t *testing.T, cfg *config.Config, leaf string) {
	t.Helper()
	for _, w := range cfg.Warnings {
		if strings.Contains(w, leaf) {
			return
		}
	}
	t.Fatalf("no lenient warning names %q; warnings: %q", leaf, cfg.Warnings)
}

// TestBuildSourceNATSkipsPartialLoss9877: the marked rule installs nothing;
// the healthy sibling still emits (fall-through pinned — skipping removes the
// rule from first-match evaluation, so a later rule may translate traffic the
// broken rule would have shadowed; warned at load).
func TestBuildSourceNATSkipsPartialLoss9877(t *testing.T) {
	cfg := lenientNATCfg9877(t, []string{
		"set security nat source pool p1 address 198.51.100.1/32",
		"set security nat source pool p2 address 198.51.100.2/32",
		"set security nat source rule-set rs1 from zone trust",
		"set security nat source rule-set rs1 to zone untrust",
		"set security nat source rule-set rs1 rule r1 match source-address 10.0.0.0/8",
		"set security nat source rule-set rs1 rule r1 match soruce-address 192.168.0.0/16",
		"set security nat source rule-set rs1 rule r1 then source-nat pool p1",
		"set security nat source rule-set rs1 rule r2 match source-address 10.0.0.0/8",
		"set security nat source rule-set rs1 rule r2 then source-nat pool p2",
	})
	warnNames9877(t, cfg, "soruce-address")
	snaps := buildSourceNATSnapshots(cfg, nil)
	if len(snaps) != 1 {
		t.Fatalf("len(snaps) = %d, want 1 (r1 skipped, r2 emits)", len(snaps))
	}
	if snaps[0].Name != "r2" {
		t.Fatalf("surviving snapshot is %q, want r2 (the marked rule installed)", snaps[0].Name)
	}
	if snaps[0].PoolName != "p2" {
		t.Fatalf("surviving snapshot pool is %q, want p2", snaps[0].PoolName)
	}
}

// TestBuildSourceNATTypoOnlyShipsTombstone9877: disarm-wins (parent ruling).
// A typo-only rule carries both markers; it ships as the #9874 fail-closed
// drop tombstone — unknown intent denies (drop + stop) rather than falling
// through to subsequent rules. The oracle is the tombstone marker on the row,
// not mere row presence.
func TestBuildSourceNATTypoOnlyShipsTombstone9877(t *testing.T) {
	cfg := lenientNATCfg9877(t, []string{
		"set security nat source pool p1 address 198.51.100.1/32",
		"set security nat source rule-set rs1 from zone trust",
		"set security nat source rule-set rs1 to zone untrust",
		"set security nat source rule-set rs1 rule r1 match soruce-address 192.168.0.0/16",
		"set security nat source rule-set rs1 rule r1 then source-nat pool p1",
	})
	warnNames9877(t, cfg, "soruce-address")
	snaps := buildSourceNATSnapshots(cfg, nil)
	if len(snaps) != 1 {
		t.Fatalf("len(snaps) = %d, want 1 (the tombstone row)", len(snaps))
	}
	if !snaps[0].LenientMatchDropped {
		t.Fatalf("snapshot %+v lacks the tombstone marker — it would translate", snaps[0])
	}
}

// TestBuildSourceNATSkipsInterfaceMode9877: the skip is not pool-gated — an
// interface-mode rule with dropped leaves installs nothing either.
func TestBuildSourceNATSkipsInterfaceMode9877(t *testing.T) {
	cfg := lenientNATCfg9877(t, []string{
		"set security nat source rule-set rs1 from zone trust",
		"set security nat source rule-set rs1 to zone untrust",
		"set security nat source rule-set rs1 rule r1 match source-address 10.0.0.0/8",
		"set security nat source rule-set rs1 rule r1 match soruce-address 192.168.0.0/16",
		"set security nat source rule-set rs1 rule r1 then source-nat interface",
	})
	warnNames9877(t, cfg, "soruce-address")
	if snaps := buildSourceNATSnapshots(cfg, nil); len(snaps) != 0 {
		t.Fatalf("len(snaps) = %d, want 0 (marked interface rule installed)", len(snaps))
	}
}

// TestBuildSourceNATInstallsExemption9877: keyable exemptions install, warned
// — skipping one would translate traffic the operator said not to translate.
func TestBuildSourceNATInstallsExemption9877(t *testing.T) {
	t.Run("partial", func(t *testing.T) {
		cfg := lenientNATCfg9877(t, []string{
			"set security nat source rule-set rs1 from zone trust",
			"set security nat source rule-set rs1 to zone untrust",
			"set security nat source rule-set rs1 rule r1 match source-address 10.0.0.0/8",
			"set security nat source rule-set rs1 rule r1 match soruce-address 192.168.0.0/16",
			"set security nat source rule-set rs1 rule r1 then source-nat off",
		})
		warnNames9877(t, cfg, "soruce-address")
		snaps := buildSourceNATSnapshots(cfg, nil)
		if len(snaps) != 1 {
			t.Fatalf("len(snaps) = %d, want 1 (keyable exemption must install)", len(snaps))
		}
		if !snaps[0].Off {
			t.Fatal("installed exemption row lost its Off flag")
		}
		if snaps[0].LenientMatchDropped {
			t.Fatalf("partial-loss exemption row %+v carries the tombstone marker — it would drop instead of exempting", snaps[0])
		}
	})
	t.Run("total ships drop tombstone warned", func(t *testing.T) {
		cfg := lenientNATCfg9877(t, []string{
			"set security nat source rule-set rs1 from zone trust",
			"set security nat source rule-set rs1 to zone untrust",
			"set security nat source rule-set rs1 rule r1 match soruce-address 192.168.0.0/16",
			"set security nat source rule-set rs1 rule r1 then source-nat off",
		})
		warnNames9877(t, cfg, "soruce-address")
		snaps := buildSourceNATSnapshots(cfg, nil)
		if len(snaps) != 1 {
			t.Fatalf("len(snaps) = %d, want 1 (the tombstone row)", len(snaps))
		}
		if !snaps[0].Off {
			t.Fatal("tombstone row lost its Off flag")
		}
		// The oracle is the marker, not Off: Rust checks lenient_match_dropped
		// BEFORE off, so this row DROPS (never exempts). An Off-only check
		// would pass for a scope-wide exemption too.
		if !snaps[0].LenientMatchDropped {
			t.Fatalf("total-loss exemption row %+v lacks the tombstone marker — it would exempt scope-wide", snaps[0])
		}
		all := strings.Join(cfg.Warnings, "\n")
		if !strings.Contains(all, "fail-closed drop") || !strings.Contains(all, "NOT exempted") {
			t.Fatalf("total-loss exemption warning %q must report the drop disposition, not an exemption", cfg.Warnings)
		}
	})
}

// TestBuildDestinationNATUnknownLeaves9877: partial-loss translate rules skip;
// a keyable exemption installs; an unkeyable one (destination was the dropped
// dimension) skips AND reports so the renderer agrees.
func TestBuildDestinationNATUnknownLeaves9877(t *testing.T) {
	t.Run("partial skips", func(t *testing.T) {
		cfg := lenientNATCfg9877(t, []string{
			"set security nat destination pool p1 address 192.0.2.5",
			"set security nat destination rule-set rs1 from zone trust",
			"set security nat destination rule-set rs1 rule r1 match destination-address 203.0.113.0/24",
			"set security nat destination rule-set rs1 rule r1 match soruce-address 10.0.0.0/8",
			"set security nat destination rule-set rs1 rule r1 then destination-nat pool p1",
		})
		warnNames9877(t, cfg, "soruce-address")
		if snaps := buildDestinationNATSnapshots(cfg, nil); len(snaps) != 0 {
			t.Fatalf("len(snaps) = %d, want 0 (marked DNAT rule installed)", len(snaps))
		}
	})
	t.Run("keyable exemption installs", func(t *testing.T) {
		cfg := lenientNATCfg9877(t, []string{
			"set security nat destination pool p1 address 192.0.2.5",
			"set security nat destination rule-set rs1 from zone trust",
			"set security nat destination rule-set rs1 rule r1 match destination-address 203.0.113.0/24",
			"set security nat destination rule-set rs1 rule r1 match soruce-address 10.0.0.0/8",
			"set security nat destination rule-set rs1 rule r1 then destination-nat off",
		})
		warnNames9877(t, cfg, "soruce-address")
		snaps := buildDestinationNATSnapshots(cfg, nil)
		if len(snaps) == 0 {
			t.Fatal("no snapshot for a keyable exemption (it must install)")
		}
		for _, s := range snaps {
			if !s.Off {
				t.Fatalf("exemption snapshot %+v lost its Off flag", s)
			}
		}
	})
	t.Run("unkeyable exemption skips and reports", func(t *testing.T) {
		cfg := lenientNATCfg9877(t, []string{
			"set security nat destination pool p1 address 192.0.2.5",
			"set security nat destination rule-set rs1 from zone trust",
			"set security nat destination rule-set rs1 rule r1 match source-address 10.0.0.0/8",
			"set security nat destination rule-set rs1 rule r1 match destination-addres 203.0.113.0/24",
			"set security nat destination rule-set rs1 rule r1 then destination-nat off",
		})
		warnNames9877(t, cfg, "destination-addres")
		if snaps := buildDestinationNATSnapshots(cfg, nil); len(snaps) != 0 {
			t.Fatalf("len(snaps) = %d, want 0 (unkeyable exemption installed)", len(snaps))
		}
		// Builder-to-renderer agreement: the skip must report, not render armed.
		var rule *config.NATRule
		for _, rs := range cfg.Security.NAT.Destination.RuleSets {
			for _, r := range rs.Rules {
				if r.Name == "r1" {
					rule = r
				}
			}
		}
		if rule == nil {
			t.Fatal("rule r1 missing after compile")
		}
		if got := config.DestinationNATRuleNotInstalledReason(cfg, rule); !strings.Contains(got, "no destination key") {
			t.Fatalf("unkeyable exemption reports %q; want the missing-key verdict", got)
		}
	})
}

// TestBuildStaticNATSkipsPartialLoss9877: a marked static rule installs no
// 1:1 mapping.
func TestBuildStaticNATSkipsPartialLoss9877(t *testing.T) {
	cfg := lenientNATCfg9877(t, []string{
		"set security nat static rule-set rs1 from zone untrust",
		"set security nat static rule-set rs1 rule r1 match destination-address 198.51.100.10/32",
		"set security nat static rule-set rs1 rule r1 match soruce-address 10.0.0.0/8",
		"set security nat static rule-set rs1 rule r1 then static-nat prefix 10.0.0.5/32",
	})
	warnNames9877(t, cfg, "soruce-address")
	if snaps := buildStaticNATSnapshots(cfg, nil); len(snaps) != 0 {
		t.Fatalf("len(snaps) = %d, want 0 (marked static rule installed %+v)", len(snaps), snaps)
	}
}

// TestBuildNPTv6SkipsUnknownLeaves9877: a typo'd scope leaf on an NPTv6 rule
// must not evade the #5818 drop and install a zone-wide rewrite.
func TestBuildNPTv6SkipsUnknownLeaves9877(t *testing.T) {
	cfg := lenientNATCfg9877(t, []string{
		"set security nat static rule-set rs1 from zone trust",
		"set security nat static rule-set rs1 rule r1 match destination-address 2001:db8:1::/48",
		"set security nat static rule-set rs1 rule r1 match soruce-address 2001:db8:9::/48",
		"set security nat static rule-set rs1 rule r1 then static-nat nptv6-prefix fd00:1::/48",
	})
	warnNames9877(t, cfg, "soruce-address")
	if snaps := buildNptv6Snapshots(cfg); len(snaps) != 0 {
		t.Fatalf("len(snaps) = %d, want 0 (marked NPTv6 rule installed zone-wide)", len(snaps))
	}
}

// TestBuildSourceNATBothMarkersDisarms9874_9877 pins disarm-wins-over-skip
// (second-lander cell, parent ruling): a typo-only rule carries both markers,
// and the #9874 tombstone wins — one row ships WITH the marker. Unknown intent
// denies rather than falling through.
func TestBuildSourceNATBothMarkersDisarms9874_9877(t *testing.T) {
	cfg := lenientNATCfg9877(t, []string{
		"set security nat source pool p1 address 198.51.100.1/32",
		"set security nat source rule-set rs1 from zone trust",
		"set security nat source rule-set rs1 to zone untrust",
		"set security nat source rule-set rs1 rule r1 match soruce-address 192.168.0.0/16",
		"set security nat source rule-set rs1 rule r1 then source-nat pool p1",
	})
	var rule *config.NATRule
	for _, rs := range cfg.Security.NAT.Source {
		for _, r := range rs.Rules {
			if r.Name == "r1" {
				rule = r
			}
		}
	}
	if rule == nil {
		t.Fatal("rule r1 missing after compile")
	}
	if !rule.LenientMatchDropped || len(rule.UnknownMatchLeaves) == 0 {
		t.Fatalf("premise broken: LenientMatchDropped=%v UnknownMatchLeaves=%v; want both markers",
			rule.LenientMatchDropped, rule.UnknownMatchLeaves)
	}
	snaps := buildSourceNATSnapshots(cfg, nil)
	if len(snaps) != 1 {
		t.Fatalf("len(snaps) = %d, want 1 (the tombstone row — disarm must win over skip)", len(snaps))
	}
	if !snaps[0].LenientMatchDropped {
		t.Fatalf("both-markers snapshot %+v lacks the tombstone marker", snaps[0])
	}
}

// TestBuildSourceNATCompactTypoSkips9877: end-to-end for the compact spelling —
// a brace-elided typo beside a surviving valid block records, warns and skips
// exactly like the braced spelling (which silently compiled before the compact
// capture).
func TestBuildSourceNATCompactTypoSkips9877(t *testing.T) {
	cfgText := `
security {
    zones {
        security-zone trust;
        security-zone untrust;
    }
    nat {
        source {
            pool p1 { address 198.51.100.1/32; }
            rule-set rs1 {
                from zone trust;
                to zone untrust;
                rule r1 {
                    match { source-address 10.0.0.0/8; }
                    match soruce-address 192.168.0.0/16;
                    then { source-nat pool p1; }
                }
            }
        }
    }
}
`
	tree, perrs := config.NewParser(cfgText).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	warnNames9877(t, cfg, "soruce-address")
	if snaps := buildSourceNATSnapshots(cfg, nil); len(snaps) != 0 {
		t.Fatalf("len(snaps) = %d, want 0 (compact-typo rule installed)", len(snaps))
	}
}
