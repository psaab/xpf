package config

import (
	"strings"
	"testing"
)

// #15706: compileSNMP dropped two-level containers
// (`client-list { <L> { ... } }`, and the 2nd+ children of
// `community { <c> { ... } }`, `trap-group { <g> { ... } }`, and
// `v3 ... user { <u> { ... } }`) — only the first instance (or none)
// was read — and it did not merge same-name trap-group blocks formed
// outside the #9023 tree fold (direct compileSNMP callers).
//
// RED on pre-fix: client-list two-level lists compile to map[] (the
// referencing community then hard-rejects as unresolved), community /
// trap-group / v3 two-level containers keep only their first instance,
// and a same-name trap-group pair whose first block has no targets
// wrongly rejected (per-block zero-target check) instead of merging.

func compileHier15706(t *testing.T, src string) (*Config, error) {
	t.Helper()
	tree, errs := NewParser(src).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs[0])
	}
	return CompileConfig(tree)
}

func TestSNMPClientListTwoLevel15706(t *testing.T) {
	cfg, err := compileHier15706(t, `snmp {
		client-list { L1 { 10.0.0.0/8; } L2 { 192.168.0.0/16; } }
		community c { client-list-name L1; }
		community d { client-list-name L2; }
	}`)
	if err != nil {
		t.Fatalf("two-level client-list must compile: %v", err)
	}
	lists := cfg.System.SNMP.ClientLists
	if len(lists["L1"]) != 1 || lists["L1"][0].Prefix != "10.0.0.0/8" {
		t.Fatalf("L1 = %+v, want [10.0.0.0/8]", lists["L1"])
	}
	if len(lists["L2"]) != 1 || lists["L2"][0].Prefix != "192.168.0.0/16" {
		t.Fatalf("L2 (2nd two-level instance) = %+v, want [192.168.0.0/16]", lists["L2"])
	}
	// The referencing communities resolve to the list prefixes (not allow-all).
	if c := cfg.System.SNMP.Communities["c"]; c == nil || len(c.Clients) != 1 || c.Clients[0].Prefix != "10.0.0.0/8" {
		t.Fatalf("community c clients = %+v, want resolved L1", c)
	}
	if d := cfg.System.SNMP.Communities["d"]; d == nil || len(d.Clients) != 1 || d.Clients[0].Prefix != "192.168.0.0/16" {
		t.Fatalf("community d clients = %+v, want resolved L2", d)
	}
}

func TestSNMPCommunityTwoLevelSecondInstance15706(t *testing.T) {
	cfg, err := compileHier15706(t, `snmp {
		community { c1 { authorization read-only; clients { 10.0.0.0/8; } } c2 { authorization read-write; clients { 192.168.0.0/16; } } }
	}`)
	if err != nil {
		t.Fatalf("two-level community must compile: %v", err)
	}
	c1 := cfg.System.SNMP.Communities["c1"]
	c2 := cfg.System.SNMP.Communities["c2"]
	if c1 == nil || c2 == nil {
		t.Fatalf("communities = %v, want both c1 and c2 (2nd instance dropped pre-fix)", cfg.System.SNMP.Communities)
	}
	if len(c2.Clients) != 1 || c2.Clients[0].Prefix != "192.168.0.0/16" || c2.Authorization != "read-write" {
		t.Fatalf("c2 = %+v, want read-write + 192.168.0.0/16", c2)
	}
	if len(c1.Clients) != 1 || c1.Clients[0].Prefix != "10.0.0.0/8" {
		t.Fatalf("c1 = %+v, want 10.0.0.0/8", c1)
	}
}

func TestSNMPTrapGroupTwoLevelSecondInstance15706(t *testing.T) {
	cfg, err := compileHier15706(t, `snmp {
		trap-group { g1 { targets 192.0.2.1; } g2 { targets 192.0.2.2; version v1; } }
	}`)
	if err != nil {
		t.Fatalf("two-level trap-group must compile: %v", err)
	}
	g1 := cfg.System.SNMP.TrapGroups["g1"]
	g2 := cfg.System.SNMP.TrapGroups["g2"]
	if g1 == nil || g2 == nil {
		t.Fatalf("trap groups = %v, want both g1 and g2 (2nd instance dropped pre-fix)", cfg.System.SNMP.TrapGroups)
	}
	if len(g2.Targets) != 1 || g2.Targets[0] != "192.0.2.2" || g2.Version != "v1" {
		t.Fatalf("g2 = %+v, want target 192.0.2.2 version v1", g2)
	}
	if len(g1.Targets) != 1 || g1.Targets[0] != "192.0.2.1" {
		t.Fatalf("g1 = %+v, want target 192.0.2.1", g1)
	}
}

func TestSNMPv3UserTwoLevelSecondInstance15706(t *testing.T) {
	cfg, err := compileHier15706(t, `snmp { v3 { usm { local-engine { user { u1 { authentication-sha { authentication-password p1pass; } } u2 { authentication-sha { authentication-password p2pass; } } } } } } }`)
	if err != nil {
		t.Fatalf("two-level v3 user must compile: %v", err)
	}
	u1 := cfg.System.SNMP.V3Users["u1"]
	u2 := cfg.System.SNMP.V3Users["u2"]
	if u1 == nil || u2 == nil {
		t.Fatalf("v3 users = %v, want both u1 and u2 (2nd instance dropped pre-fix)", cfg.System.SNMP.V3Users)
	}
	if u2.AuthProtocol != "sha" || string(u2.AuthPassword) != "p2pass" {
		t.Fatalf("u2 = auth %q pw set %v, want sha/p2pass", u2.AuthProtocol, string(u2.AuthPassword) != "")
	}
	if u1.AuthProtocol != "sha" || string(u1.AuthPassword) != "p1pass" {
		t.Fatalf("u1 = auth %q, want sha/p1pass", u1.AuthProtocol)
	}
}

// Same-name trap-group blocks whose targets are split across blocks must
// merge (not reject the target-less first block, not overwrite). Exercised
// through direct compileSNMP so the #9023 tree fold cannot mask an
// unmerged compiler.
func TestSNMPTrapGroupSameNameMergeDeferredZeroTarget15706(t *testing.T) {
	sys := &SystemConfig{}
	cfg := &Config{}
	node := &Node{Keys: []string{"snmp"}, Children: []*Node{
		{Keys: []string{"trap-group", "g1"}, Children: []*Node{{Keys: []string{"version", "v1"}}}},
		{Keys: []string{"trap-group", "g1"}, Children: []*Node{
			{Keys: []string{"targets", "192.0.2.1"}},
			{Keys: []string{"categories", "link"}},
		}},
		{Keys: []string{"trap-group", "g1"}, Children: []*Node{{Keys: []string{"targets", "192.0.2.2"}}}},
	}}
	if err := compileSNMP(node, sys, cfg, false); err != nil {
		t.Fatalf("merged same-name trap-group must not reject on the first block's zero targets: %v", err)
	}
	tg := sys.SNMP.TrapGroups["g1"]
	if tg == nil {
		t.Fatal("g1 missing")
	}
	if len(tg.Targets) != 2 || tg.Version != "v1" || len(tg.Categories) != 1 || tg.Categories[0] != "link" {
		t.Fatalf("merged g1 = %+v, want targets [192.0.2.1 192.0.2.2] version v1 categories [link]", tg)
	}
	// A genuinely target-less merged group still rejects strict.
	sys2 := &SystemConfig{}
	node2 := &Node{Keys: []string{"snmp"}, Children: []*Node{
		{Keys: []string{"trap-group", "g9"}, Children: []*Node{{Keys: []string{"version", "v1"}}}},
	}}
	if err := compileSNMP(node2, sys2, &Config{}, false); err == nil || !strings.Contains(err.Error(), "no targets") {
		t.Fatalf("target-less merged group must reject, got %v", err)
	}
	// Version from an empty later block must not clear an earlier version.
	sys3 := &SystemConfig{}
	node3 := &Node{Keys: []string{"snmp"}, Children: []*Node{
		{Keys: []string{"trap-group", "g2"}, Children: []*Node{
			{Keys: []string{"targets", "192.0.2.9"}},
			{Keys: []string{"version", "v1"}},
		}},
		{Keys: []string{"trap-group", "g2"}, Children: []*Node{
			{Keys: []string{"targets", "192.0.2.10"}},
		}},
	}}
	if err := compileSNMP(node3, sys3, &Config{}, false); err != nil {
		t.Fatalf("compile: %v", err)
	}
	if tg := sys3.SNMP.TrapGroups["g2"]; tg == nil || tg.Version != "v1" || len(tg.Targets) != 2 {
		t.Fatalf("g2 = %+v, want version v1 kept and 2 targets", tg)
	}
}

// Neighbouring valid spellings must not regress: named forms still compile.
func TestSNMPNamedFormsUnaffected15706(t *testing.T) {
	cfg, err := compileHier15706(t, `snmp {
		client-list L1 { 10.0.0.0/8; }
		community c { client-list-name L1; authorization read-only; }
		trap-group g1 { targets 192.0.2.1; version v2; categories link; }
		v3 { usm { local-engine { user u1 { authentication-sha { authentication-password p1pass; } } } } }
	}`)
	if err != nil {
		t.Fatalf("named forms must compile: %v", err)
	}
	if len(cfg.System.SNMP.ClientLists["L1"]) != 1 {
		t.Fatalf("named client-list regressed: %v", cfg.System.SNMP.ClientLists)
	}
	if cfg.System.SNMP.TrapGroups["g1"] == nil || cfg.System.SNMP.V3Users["u1"] == nil {
		t.Fatalf("named trap-group/v3 regressed: traps=%v users=%v", cfg.System.SNMP.TrapGroups, cfg.System.SNMP.V3Users)
	}
}
