package config

import (
	"strings"
	"testing"
)

// #9422 — `apply-groups-except` was accepted by every config channel and
// consulted by NONE, so a stanza that explicitly excluded a group inherited it
// anyway on a commit that reported success. `docs/feature-gaps.md` claimed the
// statement was Done.
//
// The measurement that makes these cells about the EXCLUSION rather than about
// the fixture is the CONTROL: the identical config with the `-except` line
// removed. Before the fix the two were byte-identical in their compiled output,
// which is the whole finding — removing the statement changed nothing.

func flatTree9422(t *testing.T, lines ...string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	for _, l := range lines {
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

func compile9422(t *testing.T, tree *ConfigTree) *Config {
	t.Helper()
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	return cfg
}

// The core cell, in BOTH AST shapes: the same config with and without the
// `-except` line, asserting the group's leaf is ABSENT in one and PRESENT in
// the other. Both halves are required — a fix that dropped the group's content
// unconditionally would pass the first half alone.
func TestApplyGroupsExceptSuppressesInheritance9422(t *testing.T) {
	const withExcept = `groups { G { system { host-name FROM-GROUP; } } }
apply-groups G;
system { apply-groups-except G; domain-name example.com; }`
	const control = `groups { G { system { host-name FROM-GROUP; } } }
apply-groups G;
system { domain-name example.com; }`

	shapes := []struct {
		name        string
		excepted    *ConfigTree
		controlTree *ConfigTree
	}{
		{
			name:        "hierarchical",
			excepted:    parseHierText(t, withExcept),
			controlTree: parseHierText(t, control),
		},
		{
			name: "flat set",
			excepted: flatTree9422(t,
				"set groups G system host-name FROM-GROUP",
				"set apply-groups G",
				"set system apply-groups-except G",
				"set system domain-name example.com"),
			controlTree: flatTree9422(t,
				"set groups G system host-name FROM-GROUP",
				"set apply-groups G",
				"set system domain-name example.com"),
		},
	}
	for _, sh := range shapes {
		t.Run(sh.name, func(t *testing.T) {
			ctrl := compile9422(t, sh.controlTree)
			if ctrl.System.HostName != "FROM-GROUP" {
				t.Fatalf("POSITIVE CONTROL broken: without `apply-groups-except` the "+
					"group must be inherited, got HostName=%q — this cell would then be "+
					"measuring the fixture, not the exclusion", ctrl.System.HostName)
			}
			got := compile9422(t, sh.excepted)
			if got.System.HostName != "" {
				t.Fatalf("`apply-groups-except G` did not suppress the inheritance: "+
					"HostName=%q — the operator got configuration they explicitly "+
					"excluded (#9422)", got.System.HostName)
			}
			// The excluding stanza's OWN statements must survive. An exclusion
			// that also dropped the inline leaves would satisfy the assertion
			// above while breaking the stanza.
			if got.System.DomainName != "example.com" {
				t.Fatalf("the excluding stanza lost its own inline statement: DomainName=%q",
					got.System.DomainName)
			}
		})
	}
}

// The exclusion at the TOP level, where the group is also applied. This is the
// one shape the container-descent scan cannot see — the statement is a sibling
// of `apply-groups`, not a child of any container the group contributes to — so
// it is the cell that binds the entry-level check.
func TestApplyGroupsExceptAtTopLevel9422(t *testing.T) {
	cfg := compile9422(t, parseHierText(t, `groups { G { system { host-name FROM-GROUP; } } }
apply-groups G;
apply-groups-except G;
system { domain-name example.com; }`))
	if cfg.System.HostName != "" {
		t.Fatalf("a top-level `apply-groups-except` was ignored: HostName=%q", cfg.System.HostName)
	}
	if cfg.System.DomainName != "example.com" {
		t.Fatalf("authored config lost: DomainName=%q", cfg.System.DomainName)
	}
	ctrl := compile9422(t, parseHierText(t, `groups { G { system { host-name FROM-GROUP; } } }
apply-groups G;
system { domain-name example.com; }`))
	if ctrl.System.HostName != "FROM-GROUP" {
		t.Fatalf("POSITIVE CONTROL broken: %q", ctrl.System.HostName)
	}
}

// The exclusion is per-GROUP, not "stop inheriting". A sibling group applied by
// the same `apply-groups` statement must still be inherited.
func TestApplyGroupsExceptIsPerGroup9422(t *testing.T) {
	cfg := compile9422(t, parseHierText(t, `groups {
  G { system { host-name FROM-G; } }
  H { system { time-zone UTC; } }
}
apply-groups [ G H ];
system { apply-groups-except G; domain-name example.com; }`))
	if cfg.System.HostName != "" {
		t.Errorf("G was not excluded: HostName=%q", cfg.System.HostName)
	}
	if cfg.System.TimeZone != "UTC" {
		t.Errorf("H was excluded too — the statement named only G: TimeZone=%q", cfg.System.TimeZone)
	}
}

// A bracketed list of excluded groups collapses onto one node's Keys (#2419
// class), so every key past the keyword is a group name.
func TestApplyGroupsExceptBracketList9422(t *testing.T) {
	cfg := compile9422(t, parseHierText(t, `groups {
  G { system { host-name FROM-G; } }
  H { system { time-zone UTC; } }
}
apply-groups [ G H ];
system { apply-groups-except [ G H ]; domain-name example.com; }`))
	if cfg.System.HostName != "" || cfg.System.TimeZone != "" {
		t.Errorf("a bracketed exclusion list kept only its first name: HostName=%q TimeZone=%q",
			cfg.System.HostName, cfg.System.TimeZone)
	}
	if cfg.System.DomainName != "example.com" {
		t.Errorf("inline statement lost: DomainName=%q", cfg.System.DomainName)
	}
}

// PER-DESTINATION, and this is why the check lives in mergeNodes rather than in
// a pre-prune of the group body: one `<*>` group key fans out into every
// matching destination container, and two of those containers can disagree
// about whether they exclude the group. A decision taken once against the group
// body cannot express that.
func TestApplyGroupsExceptIsPerDestination9422(t *testing.T) {
	cfg := compile9422(t, parseHierText(t, `groups { G { interfaces { <*> { description FROM-GROUP; } } } }
apply-groups G;
interfaces {
  ge-0/0/0 { unit 0 { family inet { address 10.0.0.1/24; } } }
  ge-0/0/1 { apply-groups-except G; unit 0 { family inet { address 10.0.1.1/24; } } }
}`))
	applied := cfg.Interfaces.Interfaces["ge-0/0/0"]
	excluded := cfg.Interfaces.Interfaces["ge-0/0/1"]
	if applied == nil || excluded == nil {
		t.Fatalf("fixture broken: interfaces = %d", len(cfg.Interfaces.Interfaces))
	}
	if applied.Description != "FROM-GROUP" {
		t.Fatalf("POSITIVE CONTROL broken: the wildcard group did not reach the "+
			"non-excluding interface (description=%q)", applied.Description)
	}
	if excluded.Description != "" {
		t.Fatalf("the excluding interface inherited the wildcard group anyway: description=%q",
			excluded.Description)
	}
}

// ONE hierarchy level can be spread across several AST nodes, and mergeNodes
// merges a group's contribution into the FIRST matching container only. This
// cell was written because the configstore fixture hit it by accident: the same
// config honoured the statement with one `system` block and IGNORED it with two,
// which is the defect this issue is about wearing a different shape.
func TestApplyGroupsExceptAcrossDuplicateBlocks9422(t *testing.T) {
	cfg := compile9422(t, parseHierText(t, `system { host-name p; }
groups { G { system { domain-name FROM-GROUP; } } }
apply-groups G;
system { apply-groups-except G; time-zone UTC; }`))
	if cfg.System.DomainName != "" {
		t.Fatalf("the exclusion was ignored because it sat in the SECOND `system` "+
			"block: DomainName=%q", cfg.System.DomainName)
	}
	if cfg.System.HostName != "p" || cfg.System.TimeZone != "UTC" {
		t.Fatalf("both authored blocks must survive: HostName=%q TimeZone=%q",
			cfg.System.HostName, cfg.System.TimeZone)
	}
	// Control: with the statement removed, the group reaches the merged level.
	ctrl := compile9422(t, parseHierText(t, `system { host-name p; }
groups { G { system { domain-name FROM-GROUP; } } }
apply-groups G;
system { time-zone UTC; }`))
	if ctrl.System.DomainName != "FROM-GROUP" {
		t.Fatalf("POSITIVE CONTROL broken: %q", ctrl.System.DomainName)
	}
}

// The exclusion is scoped to the stanza that carries it and everything BELOW,
// which is how the Junos statement reads. A sibling stanza keeps inheriting.
func TestApplyGroupsExceptScopedToItsSubtree9422(t *testing.T) {
	cfg := compile9422(t, parseHierText(t, `groups { G {
  system { host-name FROM-GROUP; }
  snmp { description FROM-GROUP; }
} }
apply-groups G;
system { apply-groups-except G; domain-name example.com; }
snmp { location LAB; }`))
	if cfg.System.HostName != "" {
		t.Errorf("system did not exclude G: HostName=%q", cfg.System.HostName)
	}
	if cfg.System.SNMP == nil || cfg.System.SNMP.Description != "FROM-GROUP" {
		t.Errorf("the exclusion leaked into a SIBLING stanza that did not carry it: %+v", cfg.System.SNMP)
	}
}

// An exclusion naming a group that is not defined is a NO-OP, deliberately:
// unlike `apply-groups`, which fails to ADD configuration and therefore has to
// say so, an exclusion that matches nothing removes nothing — and rejecting it
// would break a shared cluster config that excludes a `${node}` group defined
// only in the peer's view.
func TestApplyGroupsExceptUndefinedGroupIsNoOp9422(t *testing.T) {
	cfg := compile9422(t, parseHierText(t, `groups { G { system { host-name FROM-GROUP; } } }
apply-groups G;
system { apply-groups-except NOPE; domain-name example.com; }`))
	if cfg.System.HostName != "FROM-GROUP" {
		t.Errorf("an exclusion naming an undefined group suppressed an unrelated group: HostName=%q",
			cfg.System.HostName)
	}
}

// `${node}` resolves in an exclusion the same way it resolves in `apply-groups`,
// so a per-node cluster config can exclude the peer-shaped group by variable.
func TestApplyGroupsExceptResolvesNodeVar9422(t *testing.T) {
	const src = `groups { node0 { system { host-name FROM-NODE0; } } }
apply-groups "${node}";
system { apply-groups-except "${node}"; domain-name example.com; }`
	cfg, err := CompileConfigForNode(parseHierText(t, src), 0)
	if err != nil {
		t.Fatalf("CompileConfigForNode: %v", err)
	}
	if cfg.System.HostName != "" {
		t.Errorf(`apply-groups-except "${node}" did not resolve: HostName=%q`, cfg.System.HostName)
	}
	// Control: without the exclusion the same node compile inherits it.
	ctrl, err := CompileConfigForNode(parseHierText(t, `groups { node0 { system { host-name FROM-NODE0; } } }
apply-groups "${node}";
system { domain-name example.com; }`), 0)
	if err != nil {
		t.Fatalf("control CompileConfigForNode: %v", err)
	}
	if ctrl.System.HostName != "FROM-NODE0" {
		t.Fatalf("POSITIVE CONTROL broken: %q", ctrl.System.HostName)
	}
}

// The statement stays ACCEPTED on every channel — this issue's remedy is that it
// is now CONSULTED, not that it is refused. A commit carrying it must not start
// erroring.
func TestApplyGroupsExceptStillAcceptedOnEveryChannel9422(t *testing.T) {
	tree := parseHierText(t, `groups { G { system { host-name FROM-GROUP; } } }
apply-groups G;
system { apply-groups-except G; domain-name example.com; }`)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("strict CompileConfig rejected: %v", err)
	}
	if len(cfg.Warnings) != 0 {
		t.Errorf("unexpected warnings: %v", cfg.Warnings)
	}
	if _, err := CompileConfigLenient(tree); err != nil {
		t.Fatalf("CompileConfigLenient rejected: %v", err)
	}
	if err := SchemaValidate(tree); err != nil {
		t.Fatalf("SchemaValidate rejected: %v", err)
	}
	if strings.Contains(cfg.System.HostName, "FROM-GROUP") {
		t.Fatalf("still inheriting the excluded group")
	}
}
