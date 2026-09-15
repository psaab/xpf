package config

import (
	"fmt"
	"sort"
	"testing"
)

// #9862 — `apply-groups-except H` was honoured for a group applied directly and
// IGNORED for one inherited through another group: expandGroupsRecursive
// pre-merged H into G's cloned body, the outer mergeNodes carried group "G",
// and both except checks matched that single outer name only. The fix tags
// each clone with leaf provenance (Node.fromGroups) and filters nested
// contributors per node, while the outer group keeps its veto exactly.
//
// Reuses parseTree9422/compile9422 (strict CompileConfig): the issue notes
// strict commit accepts every row, so strict is the stronger signal here.

func zoneNames9862(t *testing.T, cfg *Config) []string {
	t.Helper()
	var names []string
	for n := range cfg.Security.Zones {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

func contains9862(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}

func equalStrs9862(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// The issue's table, in both inline spellings and both application shapes,
// each with its no-except control. Before the fix the nested rows compiled
// [trust zgh]; the direct rows are pinned so the fix cannot move them.
func TestApplyGroupsExceptNestedZone9862(t *testing.T) {
	nested := `groups { H { security { zones { security-zone zgh; } } } G { apply-groups H; } }
apply-groups G;
security { zones { %s security-zone %s } }`
	direct := `groups { H { security { zones { security-zone zgh; } } } }
apply-groups H;
security { zones { %s security-zone %s } }`
	rows := []struct {
		name string
		tmpl string
		zone string
	}{
		{"nested braced", nested, "trust { }"},
		{"nested leaf", nested, "trust;"},
		{"direct braced", direct, "trust { }"},
		{"direct leaf", direct, "trust;"},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			ctrl := compile9422(t, parseTree9422(t, fmt.Sprintf(r.tmpl, "", r.zone)))
			if got := zoneNames9862(t, ctrl); !equalStrs9862(got, []string{"trust", "zgh"}) {
				t.Fatalf("POSITIVE CONTROL broken: without the exclusion want [trust zgh], got %v", got)
			}
			cfg := compile9422(t, parseTree9422(t, fmt.Sprintf(r.tmpl, "apply-groups-except H;", r.zone)))
			if got := zoneNames9862(t, cfg); !equalStrs9862(got, []string{"trust"}) {
				t.Fatalf("apply-groups-except H did not exclude nested H: zones=%v, want [trust]", got)
			}
		})
	}
}

// Excluding the nested group must not take the outer group's own content with
// it: G's own zone survives except-H. The over-exclusion guard.
func TestApplyGroupsExceptNestedKeepsOuterOwnZone9862(t *testing.T) {
	const control = `groups {
  H { security { zones { security-zone zgh; } } }
  G { security { zones { security-zone zg1; } } apply-groups H; }
}
apply-groups G;
security { zones { security-zone trust { } } }`
	const excepted = `groups {
  H { security { zones { security-zone zgh; } } }
  G { security { zones { security-zone zg1; } } apply-groups H; }
}
apply-groups G;
security { zones { apply-groups-except H; security-zone trust { } } }`
	ctrl := compile9422(t, parseTree9422(t, control))
	if got := zoneNames9862(t, ctrl); !equalStrs9862(got, []string{"trust", "zg1", "zgh"}) {
		t.Fatalf("POSITIVE CONTROL broken: want [trust zg1 zgh], got %v", got)
	}
	cfg := compile9422(t, parseTree9422(t, excepted))
	if got := zoneNames9862(t, cfg); !equalStrs9862(got, []string{"trust", "zg1"}) {
		t.Fatalf("except-H over-excluded G's own zone (or kept H's): zones=%v, want [trust zg1]", got)
	}
}

// The outer (merged) group keeps its veto EXACTLY: except-G drops the whole
// application, nested content included. This is today's behavior (the plan
// review's kill counterexample) and must not move.
func TestApplyGroupsExceptOuterVetoesNested9862(t *testing.T) {
	const control = `groups {
  H { system { host-name FROM-H; } }
  G { system { domain-name FROM-G; } apply-groups H; }
}
apply-groups G;
system { time-zone UTC; }`
	const excepted = `groups {
  H { system { host-name FROM-H; } }
  G { system { domain-name FROM-G; } apply-groups H; }
}
apply-groups G;
system { apply-groups-except G; time-zone UTC; }`
	ctrl := compile9422(t, parseTree9422(t, control))
	if ctrl.System.HostName != "FROM-H" || ctrl.System.DomainName != "FROM-G" {
		t.Fatalf("POSITIVE CONTROL broken: HostName=%q DomainName=%q", ctrl.System.HostName, ctrl.System.DomainName)
	}
	cfg := compile9422(t, parseTree9422(t, excepted))
	if cfg.System.HostName != "" || cfg.System.DomainName != "" {
		t.Fatalf("except-G stopped vetoing nested content: HostName=%q DomainName=%q",
			cfg.System.HostName, cfg.System.DomainName)
	}
	if cfg.System.TimeZone != "UTC" {
		t.Fatalf("inline stanza lost: TimeZone=%q", cfg.System.TimeZone)
	}
}

// The issue's consequence: H's reserved `any` zone, inherited through G,
// refused strict commit with no documented suppression. With except-H the
// commit goes through; without it the control still refuses.
func TestApplyGroupsExceptNestedAnyZoneCommittable9862(t *testing.T) {
	const control = `groups {
  H { security { zones { security-zone any; } } }
  G { apply-groups H; }
}
apply-groups G;
security { zones { security-zone trust { } } }`
	const excepted = `groups {
  H { security { zones { security-zone any; } } }
  G { apply-groups H; }
}
apply-groups G;
security { zones { apply-groups-except H; security-zone trust { } } }`
	if _, err := CompileConfig(parseTree9422(t, control)); err == nil {
		t.Fatalf("POSITIVE CONTROL broken: the unsuppressed `any` zone must still refuse strict commit")
	}
	cfg, err := CompileConfig(parseTree9422(t, excepted))
	if err != nil {
		t.Fatalf("except-H did not suppress the nested reserved zone: strict refused: %v", err)
	}
	if got := zoneNames9862(t, cfg); !equalStrs9862(got, []string{"trust"}) {
		t.Fatalf("zones=%v, want [trust]", got)
	}
}

// Cross-group leaf-list unions clear provenance as uncertain, so filtering
// falls back to keep: a surviving group's members are NEVER dropped by the
// union. Superset assertions, deliberately follow-up-compatible: member-level
// provenance (which would also drop the excluded group's members) is a
// follow-up, and these cells must stay green when it lands.
func TestApplyGroupsExceptNestedLeafListUnionKeepsSurvivor9862(t *testing.T) {
	const tmpl = `groups {
  H1 { system { name-server { 1.1.1.1; } } }
  H2 { system { name-server { 2.2.2.2; } } }
  G { apply-groups [ H1 H2 ]; }
}
apply-groups G;
system { %s }`
	ctrl := compile9422(t, parseTree9422(t, fmt.Sprintf(tmpl, "domain-name example.com;")))
	if got := ctrl.System.NameServers; !contains9862(got, "1.1.1.1") || !contains9862(got, "2.2.2.2") {
		t.Fatalf("POSITIVE CONTROL broken: NameServers=%v, want both members", got)
	}
	got1 := compile9422(t, parseTree9422(t, fmt.Sprintf(tmpl, "apply-groups-except H1;"))).System.NameServers
	if !contains9862(got1, "2.2.2.2") {
		t.Fatalf("except-H1 over-excluded H2's unioned member: NameServers=%v", got1)
	}
	got2 := compile9422(t, parseTree9422(t, fmt.Sprintf(tmpl, "apply-groups-except H2;"))).System.NameServers
	if !contains9862(got2, "1.1.1.1") {
		t.Fatalf("except-H2 over-excluded H1's unioned member: NameServers=%v", got2)
	}
	// Contrast: applied directly (no union collapse), the same exclusion is
	// per-group exact.
	direct := compile9422(t, parseTree9422(t, `groups {
  H1 { system { name-server { 1.1.1.1; } } }
  H2 { system { name-server { 2.2.2.2; } } }
}
apply-groups [ H1 H2 ];
system { apply-groups-except H2; }`))
	if got := direct.System.NameServers; !equalStrs9862(got, []string{"1.1.1.1"}) {
		t.Fatalf("direct per-group union filtering moved: NameServers=%v, want [1.1.1.1]", got)
	}
}

// Per-destination filtering through nesting: H names both interfaces
// concretely, G carries H, and only ge-0/0/1 excludes H — the description
// lands on ge-0/0/0 alone. (A `<*>` template cannot serve here: nested
// wildcards are consumed by the inner wholesale adopt on base too, an
// independent pre-existing hole with its own follow-up.)
func TestApplyGroupsExceptNestedPerDestination9862(t *testing.T) {
	cfg := compile9422(t, parseTree9422(t, `groups {
  H { interfaces {
    ge-0/0/0 { description FROM-H; }
    ge-0/0/1 { description FROM-H; }
  } }
  G { apply-groups H; }
}
apply-groups G;
interfaces {
  ge-0/0/0 { unit 0 { family inet { address 10.0.0.1/24; } } }
  ge-0/0/1 { apply-groups-except H; unit 0 { family inet { address 10.0.1.1/24; } } }
}`))
	applied := cfg.Interfaces.Interfaces["ge-0/0/0"]
	excluded := cfg.Interfaces.Interfaces["ge-0/0/1"]
	if applied == nil || excluded == nil {
		t.Fatalf("fixture broken: interfaces = %d", len(cfg.Interfaces.Interfaces))
	}
	if applied.Description != "FROM-H" {
		t.Fatalf("POSITIVE CONTROL broken: description=%q", applied.Description)
	}
	if excluded.Description != "" {
		t.Fatalf("the excluding interface inherited nested H anyway: description=%q", excluded.Description)
	}
}

// One logical level spread over two blocks: the except in the second block
// excludes nested H from the level, while G's own content lands.
func TestApplyGroupsExceptNestedAcrossDuplicateBlocks9862(t *testing.T) {
	const control = `system { host-name p; }
groups {
  H { system { domain-name FROM-H; } }
  G { system { time-zone FROM-G; } apply-groups H; }
}
apply-groups G;
system { time-zone UTC; }`
	const excepted = `system { host-name p; }
groups {
  H { system { domain-name FROM-H; } }
  G { system { time-zone FROM-G; } apply-groups H; }
}
apply-groups G;
system { apply-groups-except H; }`
	ctrl := compile9422(t, parseTree9422(t, control))
	if ctrl.System.DomainName != "FROM-H" || ctrl.System.TimeZone != "UTC" {
		t.Fatalf("POSITIVE CONTROL broken: DomainName=%q TimeZone=%q", ctrl.System.DomainName, ctrl.System.TimeZone)
	}
	cfg := compile9422(t, parseTree9422(t, excepted))
	if cfg.System.DomainName != "" {
		t.Fatalf("except-H ignored across duplicate blocks: DomainName=%q", cfg.System.DomainName)
	}
	if cfg.System.TimeZone != "FROM-G" {
		t.Fatalf("G's own content lost across duplicate blocks: TimeZone=%q", cfg.System.TimeZone)
	}
	if cfg.System.HostName != "p" {
		t.Fatalf("authored block lost: HostName=%q", cfg.System.HostName)
	}
}

// Top-level exclusion with no inline peer: the wholesale-adopted subtree is
// filtered recursively — H's content drops, G's own content lands.
func TestApplyGroupsExceptNestedAtTopLevel9862(t *testing.T) {
	const control = `groups {
  H { system { host-name FROM-H; } }
  G { system { domain-name FROM-G; } apply-groups H; }
}
apply-groups G;`
	const excepted = `groups {
  H { system { host-name FROM-H; } }
  G { system { domain-name FROM-G; } apply-groups H; }
}
apply-groups G;
apply-groups-except H;`
	ctrl := compile9422(t, parseTree9422(t, control))
	if ctrl.System.HostName != "FROM-H" || ctrl.System.DomainName != "FROM-G" {
		t.Fatalf("POSITIVE CONTROL broken: HostName=%q DomainName=%q", ctrl.System.HostName, ctrl.System.DomainName)
	}
	cfg := compile9422(t, parseTree9422(t, excepted))
	if cfg.System.HostName != "" {
		t.Fatalf("top-level except-H ignored through nesting: HostName=%q", cfg.System.HostName)
	}
	if cfg.System.DomainName != "FROM-G" {
		t.Fatalf("G's own content lost to a nested exclusion: DomainName=%q", cfg.System.DomainName)
	}
}

// DOCUMENTED SEMANTIC, pinned: except names a group's own statements. B's own
// statements drop wherever B is applied, but statements authored in groups
// nested inside B (applied through B) are still inherited — Junos' own
// nested-except-middle behavior is undocumented, and this preserves today's
// outcome for the deeper group while fixing the named one.
func TestApplyGroupsExceptMiddleKeepsDeeperNested9862(t *testing.T) {
	const control = `groups {
  C { system { host-name FROM-C; } }
  B { system { domain-name FROM-B; } apply-groups C; }
  A { apply-groups B; }
}
apply-groups A;
system { time-zone UTC; }`
	const excepted = `groups {
  C { system { host-name FROM-C; } }
  B { system { domain-name FROM-B; } apply-groups C; }
  A { apply-groups B; }
}
apply-groups A;
system { apply-groups-except B; time-zone UTC; }`
	ctrl := compile9422(t, parseTree9422(t, control))
	if ctrl.System.HostName != "FROM-C" || ctrl.System.DomainName != "FROM-B" {
		t.Fatalf("POSITIVE CONTROL broken: HostName=%q DomainName=%q", ctrl.System.HostName, ctrl.System.DomainName)
	}
	cfg := compile9422(t, parseTree9422(t, excepted))
	if cfg.System.DomainName != "" {
		t.Fatalf("except-B did not drop B's own statements: DomainName=%q", cfg.System.DomainName)
	}
	if cfg.System.HostName != "FROM-C" {
		t.Fatalf("documented semantic moved: C-through-B no longer inherited: HostName=%q", cfg.System.HostName)
	}
	if cfg.System.TimeZone != "UTC" {
		t.Fatalf("inline stanza lost: TimeZone=%q", cfg.System.TimeZone)
	}
}

// An exclusion authored inside a group definition filters that group's nested
// merges (inner veto), exactly as before the fix.
func TestApplyGroupsExceptInGroupDef9862(t *testing.T) {
	const control = `groups {
  H { system { host-name FROM-H; } }
  G { system { domain-name FROM-G; } apply-groups H; }
}
apply-groups G;`
	const excepted = `groups {
  H { system { host-name FROM-H; } }
  G { system { apply-groups-except H; domain-name FROM-G; } apply-groups H; }
}
apply-groups G;`
	ctrl := compile9422(t, parseTree9422(t, control))
	if ctrl.System.HostName != "FROM-H" || ctrl.System.DomainName != "FROM-G" {
		t.Fatalf("POSITIVE CONTROL broken: HostName=%q DomainName=%q", ctrl.System.HostName, ctrl.System.DomainName)
	}
	cfg := compile9422(t, parseTree9422(t, excepted))
	if cfg.System.HostName != "" {
		t.Fatalf("exclusion inside G's definition no longer filters H: HostName=%q", cfg.System.HostName)
	}
	if cfg.System.DomainName != "FROM-G" {
		t.Fatalf("G's own content lost: DomainName=%q", cfg.System.DomainName)
	}
}

// Same-instance merge: G authors the EMPTY zone zg and inherits its only
// child (tcp-rst) from H. Excluding H must drop H's child but PRESERVE G's
// authored zone — an empty zone is a real object, not a shell to garbage-
// collect. The different-names cell above misses this: it never empties a
// surviving container.
func TestApplyGroupsExceptNestedKeepsEmptiedOwnZone9862(t *testing.T) {
	const control = `groups {
  H { security { zones { security-zone zg { tcp-rst; } } } }
  G { security { zones { security-zone zg { } } } apply-groups H; }
}
apply-groups G;
security { zones { security-zone trust { } } }`
	const excepted = `groups {
  H { security { zones { security-zone zg { tcp-rst; } } } }
  G { security { zones { security-zone zg { } } } apply-groups H; }
}
apply-groups G;
security { zones { apply-groups-except H; security-zone trust { } } }`
	ctrl := compile9422(t, parseTree9422(t, control))
	if got := zoneNames9862(t, ctrl); !equalStrs9862(got, []string{"trust", "zg"}) {
		t.Fatalf("POSITIVE CONTROL broken: zones=%v", got)
	}
	if !ctrl.Security.Zones["zg"].TCPRst {
		t.Fatalf("POSITIVE CONTROL broken: H's tcp-rst did not land without the exclusion")
	}
	cfg := compile9422(t, parseTree9422(t, excepted))
	if got := zoneNames9862(t, cfg); !equalStrs9862(got, []string{"trust", "zg"}) {
		t.Fatalf("except-H deleted G's authored zone with H's child: zones=%v, want [trust zg]", got)
	}
	if cfg.Security.Zones["zg"].TCPRst {
		t.Fatalf("except-H did not drop H's zone child: TCPRst still set")
	}
}

// Same member through two nested groups, excluded one, no inline peer: H1 and
// H2 contribute the IDENTICAL block-form member via G, the top level excludes
// H1, and there is no inline system (wholesale route). The duplicate-merged
// ownership must keep the member for surviving H2; excluding BOTH drops it.
// The different-members cell above misses this: distinct members never dedup.
func TestApplyGroupsExceptNestedSameMemberWholesale9862(t *testing.T) {
	const tmpl = `groups {
  H1 { system { name-server { 1.1.1.1; } } }
  H2 { system { name-server { 1.1.1.1; } } }
  G { apply-groups [ H1 H2 ]; }
}
apply-groups G;
%s`
	ctrl := compile9422(t, parseTree9422(t, fmt.Sprintf(tmpl, ""))).System.NameServers
	if !equalStrs9862(ctrl, []string{"1.1.1.1"}) {
		t.Fatalf("POSITIVE CONTROL broken: NameServers=%v, want exactly [1.1.1.1]", ctrl)
	}
	got1 := compile9422(t, parseTree9422(t, fmt.Sprintf(tmpl, "apply-groups-except H1;"))).System.NameServers
	if !equalStrs9862(got1, []string{"1.1.1.1"}) {
		t.Fatalf("except-H1 dropped H2's same member (over-exclusion): NameServers=%v", got1)
	}
	gotBoth := compile9422(t, parseTree9422(t, fmt.Sprintf(tmpl, "apply-groups-except [ H1 H2 ];"))).System.NameServers
	if len(gotBoth) != 0 {
		t.Fatalf("excluding both owners must drop the member: NameServers=%v", gotBoth)
	}
}

// A packed group leaf (`target apply-groups-except H;`) carries the exclusion
// on its Keys tail with Name()=="target", so a statement-only pre-scan misses
// it — but #7648 synthesis materializes the real exclusion node into the
// destination DURING G's merge. A subsequently applied direct H must still be
// vetoed there, exactly as the unconditional #9422 checks. Tree-level: this
// is the expansion contract (synthesis ran AND the veto fired).
func TestApplyGroupsExceptPackedTailVetoesDirect9862(t *testing.T) {
	findTarget9862 := func(t *testing.T, tree *ConfigTree) *Node {
		t.Helper()
		var walk func(nodes []*Node) *Node
		walk = func(nodes []*Node) *Node {
			for _, n := range nodes {
				if n == nil {
					continue
				}
				if len(n.Keys) == 1 && n.Keys[0] == "target" && !n.IsLeaf {
					return n
				}
				if found := walk(n.Children); found != nil {
					return found
				}
			}
			return nil
		}
		target := walk(tree.Children)
		if target == nil {
			t.Fatalf("fixture broken: no target container after expansion")
		}
		return target
	}
	hasChild9862 := func(n *Node, key string) bool {
		for _, c := range n.Children {
			if c != nil && len(c.Keys) > 0 && c.Keys[0] == key {
				return true
			}
		}
		return false
	}
	exceptNames9862 := func(n *Node) []string {
		var out []string
		for _, c := range n.Children {
			if c != nil && c.Name() == "apply-groups-except" {
				out = append(out, c.Keys[1:]...)
			}
		}
		return out
	}
	expand9862 := func(t *testing.T, text string) *ConfigTree {
		t.Helper()
		tree := parseTree9422(t, text)
		if err := tree.ExpandGroups(); err != nil {
			t.Fatalf("ExpandGroups: %v", err)
		}
		return tree
	}
	const inlineTarget = `services { rpm { probe P { test T { target { url http://x/; } } } } }`
	packed := `groups {
  G { services { rpm { probe P { test T { target apply-groups-except H; } } } } }
  H { services { rpm { probe P { test T { target { address 10.9.9.9; } } } } } }
}
apply-groups [ G H ];
` + inlineTarget
	target := findTarget9862(t, expand9862(t, packed))
	if names := exceptNames9862(target); !contains9862(names, "H") {
		t.Fatalf("synthesis proof broken: no except-H under target (names=%v) — the cell is vacuous", names)
	}
	if hasChild9862(target, "address") {
		t.Fatalf("packed except-H did not veto subsequently applied direct H: address landed")
	}
	if !hasChild9862(target, "url") {
		t.Fatalf("inline target content lost: url missing")
	}
	// Control: the same packed leaf WITHOUT the except tail synthesizes no
	// exclusion, so H's address lands.
	unpacked := `groups {
  G { services { rpm { probe P { test T { target url http://g/; } } } } }
  H { services { rpm { probe P { test T { target { address 10.9.9.9; } } } } } }
}
apply-groups [ G H ];
` + inlineTarget
	ctarget := findTarget9862(t, expand9862(t, unpacked))
	if !hasChild9862(ctarget, "address") {
		t.Fatalf("POSITIVE CONTROL broken: without the packed except, H's address must land")
	}
}
