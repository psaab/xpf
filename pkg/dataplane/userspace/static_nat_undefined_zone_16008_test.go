package userspace

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16008: on the tolerant path a static-NAT rule-set with an undefined
// from-zone must be DROPPED by the snapshot builders, not shipped with
// the undefined name verbatim (Rust matches FromZone by exact equality,
// so the verbatim row is a silent never-match). The deciding record is
// cfg.LenientNATUndefinedZoneRuleSets{Kind:"static"} populated by the
// tolerant config compile; hand-built configs without the record keep
// the legacy verbatim behavior (pinned by the control below), and
// healthy siblings in the same config still ship.
//
// RED on revert: removing the drop in buildStaticNATSnapshots /
// buildNptv6Snapshots makes the bad rule-set ship and these tests fail.

func tolerantStaticCfg16008(t *testing.T) *config.Config {
	t.Helper()
	tree := &config.ConfigTree{}
	cmds := []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security nat static rule-set static-bad from zone untrsut",
		"set security nat static rule-set static-bad rule R1 match destination-address 203.0.113.5/32",
		"set security nat static rule-set static-bad rule R1 then static-nat prefix 10.0.0.5/32",
		"set security nat static rule-set static-good from zone untrust",
		"set security nat static rule-set static-good rule R1 match destination-address 203.0.113.6/32",
		"set security nat static rule-set static-good rule R1 then static-nat prefix 10.0.0.6/32",
	}
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
	if !cfg.LenientNATUndefinedZoneRuleSets[config.NATRuleSetRef{Kind: "static", Name: "static-bad"}] {
		t.Fatalf("precondition: tolerant record missing {{static static-bad}}; record=%v warnings=%v",
			cfg.LenientNATUndefinedZoneRuleSets, cfg.Warnings)
	}
	return cfg
}

func TestBuildStaticNATSnapshotsDropsUndefinedZone16008(t *testing.T) {
	cfg := tolerantStaticCfg16008(t)
	snaps := buildStaticNATSnapshots(cfg, nil)
	if len(snaps) != 1 {
		t.Fatalf("expected exactly the healthy sibling to ship (1 snapshot), got %d: %+v", len(snaps), snaps)
	}
	if snaps[0].Name != "R1" || snaps[0].FromZone != "untrust" || snaps[0].ExternalIP != "203.0.113.6/32" {
		t.Fatalf("surviving snapshot is not static-good/R1: %+v", snaps[0])
	}
	for _, s := range snaps {
		if s.FromZone == "untrsut" {
			t.Fatalf("verbatim never-match row shipped: %+v", s)
		}
	}
}

func TestBuildNptv6SnapshotsDropsUndefinedZone16008(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{"untrust": {Name: "untrust"}}
	cfg.LenientNATUndefinedZoneRuleSets = map[config.NATRuleSetRef]bool{
		{Kind: "static", Name: "npt-bad"}: true,
	}
	cfg.Security.NAT.Static = []*config.StaticNATRuleSet{
		{Name: "npt-bad", FromZone: "untrsut", Rules: []*config.StaticNATRule{
			{Name: "n1", IsNPTv6: true, Match: "2001:db8:1::/48", Then: "fd00:1::/48"},
		}},
		{Name: "npt-good", FromZone: "untrust", Rules: []*config.StaticNATRule{
			{Name: "n2", IsNPTv6: true, Match: "2001:db8:2::/48", Then: "fd00:2::/48"},
		}},
	}
	snaps := buildNptv6Snapshots(cfg)
	if len(snaps) != 1 || snaps[0].Name != "n2" {
		t.Fatalf("expected only the healthy NPTv6 rule to ship, got %+v", snaps)
	}
}

func TestBuildStaticNATSnapshotsNoRecordShipsVerbatim16008(t *testing.T) {
	// Control: a hand-built config that never went through tolerant
	// compile carries no record, so the builder's legacy verbatim
	// behavior is unchanged — the drop is keyed to the record, not to
	// re-deriving zone membership in the builder.
	cfg := &config.Config{}
	cfg.Security.NAT.Static = []*config.StaticNATRuleSet{
		{Name: "hand", FromZone: "untrsut", Rules: []*config.StaticNATRule{
			{Name: "r1", Match: "203.0.113.5/32", Then: "10.0.0.5/32"},
		}},
	}
	snaps := buildStaticNATSnapshots(cfg, nil)
	if len(snaps) != 1 || snaps[0].FromZone != "untrsut" {
		t.Fatalf("hand-built config without the tolerant record must ship verbatim, got %+v", snaps)
	}
	if !strings.Contains(snaps[0].ExternalIP, "203.0.113.5") {
		t.Fatalf("control snapshot malformed: %+v", snaps[0])
	}
}
