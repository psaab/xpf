package config

import (
	"strings"
	"testing"
)

// #16580: Junos relay-level `active-server-group` is the DHCPv4
// default for groups without their own. Before the fix the #9552
// closed-world gate rejected it at strict commit with a message
// describing the silent-drop outcome, and the tolerant path dropped
// it so groups relayed nowhere. The v6 compiler (#9553) already
// implements exactly this inheritance.
//
// FAIL-ON-REVERT: removing the schema declaration reds every strict
// cell (gate refusal); removing the compiler read leaves
// relay.ActiveServerGroup empty and groups without an effective
// server group (strict #11693 rejection / wrong group value).

func relay16580(t *testing.T, tree *ConfigTree) *DHCPRelayConfig {
	t.Helper()
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("#16580: relay-level active-server-group config rejected: %v", err)
	}
	if cfg.ForwardingOptions.DHCPRelay == nil {
		t.Fatalf("#16580: no DHCP relay compiled: %+v", cfg)
	}
	return cfg.ForwardingOptions.DHCPRelay
}

func TestDHCPRelayV4RelayLevelActiveServerGroup16580(t *testing.T) {
	for _, sp := range []spelling9414{
		{label: "braced", braced: "forwarding-options { dhcp-relay { server-group sg { 10.0.0.5; } " +
			"active-server-group sg; group rg { interface ge-0/0/1.0; } } }"},
		{label: "flat-set", flat: []string{
			"set forwarding-options dhcp-relay server-group sg 10.0.0.5",
			"set forwarding-options dhcp-relay active-server-group sg",
			"set forwarding-options dhcp-relay group rg interface ge-0/0/1.0",
		}},
		{label: "singly-elided", braced: "forwarding-options { dhcp-relay active-server-group sg; }"},
		{label: "fully-packed", braced: "forwarding-options dhcp-relay active-server-group sg server-group sg 10.0.0.5 group rg interface ge-0/0/1.0;"},
		{label: "packed-in-brace", braced: "forwarding-options { dhcp-relay active-server-group sg server-group sg 10.0.0.5 group rg interface ge-0/0/1.0; }"},
	} {
		t.Run(sp.label, func(t *testing.T) {
			var tree *ConfigTree
			if sp.label == "singly-elided" {
				// The elided leaf alone has no group to inherit into;
				// combine with a braced sibling relay block via two
				// forwarding-options statements is not one tree, so
				// assert the leaf-only shape separately below.
				tree = sp.tree(t)
				cfg, err := CompileConfig(tree)
				// A relay with only a default and no group/server-group
				// is not required to commit; only that the #9552 gate
				// no longer refuses the token itself.
				if err != nil && strings.Contains(err.Error(), "(#9552)") {
					t.Fatalf("#16580: singly-elided relay-level token still refused by #9552 gate: %v", err)
				}
				_ = cfg
				return
			}
			relay := relay16580(t, sp.tree(t))
			if relay.ActiveServerGroup != "sg" {
				t.Fatalf("#16580: relay-level ActiveServerGroup = %q, want sg", relay.ActiveServerGroup)
			}
			g := relay.Groups["rg"]
			if g == nil {
				t.Fatalf("#16580: group rg missing: %+v", relay.Groups)
			}
			// Acceptance: the compiled group carries sg.
			if g.ActiveServerGroup != "sg" {
				t.Fatalf("#16580: compiled group ActiveServerGroup = %q, want inherited sg", g.ActiveServerGroup)
			}
			if len(g.Interfaces) != 1 || g.Interfaces[0] != "ge-0/0/1.0" {
				t.Fatalf("#16580: group interfaces = %v, want [ge-0/0/1.0]", g.Interfaces)
			}
			if sg := relay.ServerGroups["sg"]; sg == nil || len(sg.Servers) != 1 || sg.Servers[0] != "10.0.0.5" {
				t.Fatalf("#16580: server-group = %+v, want sg=[10.0.0.5]", relay.ServerGroups)
			}
			// No #9552 warning on either path.
			lenient, err := CompileConfigLenient(sp.tree(t))
			if err != nil {
				t.Fatalf("#16580: lenient compile failed: %v", err)
			}
			for _, w := range lenient.Warnings {
				if strings.Contains(w, "(#9552)") {
					t.Fatalf("#16580: valid relay-level default raised #9552 warning: %q", w)
				}
			}
		})
	}
}

func TestDHCPRelayV4RelayLevelOverrideWins16580(t *testing.T) {
	// Issue's decisive check: global default + group override.
	// The override group keeps its own; the inheriting group gets sg.
	tree := parseHierText(t, "forwarding-options { dhcp-relay { "+
		"server-group sg { 10.0.0.5; } server-group other { 10.0.0.6; } "+
		"active-server-group sg; "+
		"group inherit { interface ge-0/0/1.0; } "+
		"group override { active-server-group other; interface ge-0/0/2.0; } } }")
	relay := relay16580(t, tree)
	if relay.ActiveServerGroup != "sg" {
		t.Fatalf("relay default = %q, want sg", relay.ActiveServerGroup)
	}
	if got := relay.Groups["inherit"].ActiveServerGroup; got != "sg" {
		t.Fatalf("inheriting group = %q, want sg", got)
	}
	if got := relay.Groups["override"].ActiveServerGroup; got != "other" {
		t.Fatalf("overriding group = %q, want other (group wins over relay default)", got)
	}
}

func TestDHCPRelayV4RelayLevelEffectiveValidation16580(t *testing.T) {
	// #11693 validation on the EFFECTIVE value: an undefined relay
	// default must refuse strict and warn lenient, naming the group.
	tree := parseHierText(t, "forwarding-options { dhcp-relay { "+
		"server-group sg { 10.0.0.5; } active-server-group missing; "+
		"group rg { interface ge-0/0/1.0; } } }")
	if _, err := CompileConfig(tree); err == nil ||
		!strings.Contains(err.Error(), "#11693") || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("#16580: undefined relay default must fail #11693 on the effective value: %v", err)
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("#16580: lenient must not brick (#1960): %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#11693") && strings.Contains(w, "missing") {
			found = true
		}
	}
	if !found {
		t.Fatalf("#16580: lenient warnings lack #11693 effective-value warning: %v", cfg.Warnings)
	}
	// The lenient compiled group still carries the effective value,
	// so the operator can see what was attempted.
	if cfg.ForwardingOptions.DHCPRelay == nil ||
		cfg.ForwardingOptions.DHCPRelay.Groups["rg"] == nil ||
		cfg.ForwardingOptions.DHCPRelay.Groups["rg"].ActiveServerGroup != "missing" {
		t.Fatalf("#16580: lenient group does not carry effective default: %+v", cfg.ForwardingOptions.DHCPRelay)
	}

	// A group with neither its own nor a relay default still refuses.
	tree2 := parseHierText(t, "forwarding-options { dhcp-relay { "+
		"server-group sg { 10.0.0.5; } group rg { interface ge-0/0/1.0; } } }")
	if _, err := CompileConfig(tree2); err == nil || !strings.Contains(err.Error(), "#11693") {
		t.Fatalf("#16580: group with no server group anywhere must still refuse: %v", err)
	}

	// A valueless relay-level leaf contributes no default: the
	// group then has no effective value and strict refuses (the
	// v6 bare-family fallback shape, mirrored).
	tree3 := parseHierText(t, "forwarding-options { dhcp-relay { "+
		"active-server-group; server-group sg { 10.0.0.5; } "+
		"group rg { interface ge-0/0/1.0; } } }")
	if _, err := CompileConfig(tree3); err == nil || !strings.Contains(err.Error(), "#11693") {
		t.Fatalf("#16580: valueless relay-level leaf must not invent a default: %v", err)
	}
}

func TestDHCPRelayV4RelayLevelTolerantInherits16580(t *testing.T) {
	// The inferred tolerant leg, now executed: on the tolerant path
	// the global default is NOT dropped — the group inherits it and
	// relays via sg.
	tree := parseHierText(t, "forwarding-options { dhcp-relay { "+
		"server-group sg { 10.0.0.5; } active-server-group sg; "+
		"group rg { interface ge-0/0/1.0; } } }")
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("#16580: lenient compile failed: %v", err)
	}
	relay := cfg.ForwardingOptions.DHCPRelay
	if relay == nil || relay.Groups["rg"] == nil || relay.Groups["rg"].ActiveServerGroup != "sg" {
		t.Fatalf("#16580: tolerant path dropped the relay default: %+v", relay)
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "active-server-group") {
			t.Fatalf("#16580: tolerant path warned about the valid default: %q", w)
		}
	}
}

func TestDHCPRelay9552StrictMessageDescribesRejection16580(t *testing.T) {
	// Unknown children still refuse strict, but the message must
	// describe the rejection — not claim the config "commits clean".
	tree := parseHierText(t, "forwarding-options { dhcp-relay { xpfbogus16580 { foo 1; } } }")
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("#16580: unknown dhcp-relay child must still refuse strict")
	}
	if !strings.Contains(err.Error(), "xpfbogus16580") || !strings.Contains(err.Error(), "(#9552)") {
		t.Fatalf("#16580: strict refusal must name token and #9552: %v", err)
	}
	if strings.Contains(err.Error(), "it commits clean") {
		t.Fatalf("#16580: strict message still claims the rejected config commits clean: %v", err)
	}
	if !strings.Contains(err.Error(), "rejected") {
		t.Fatalf("#16580: strict message must describe the rejection: %v", err)
	}
	// The known list now includes the relay-level default.
	if !strings.Contains(err.Error(), "active-server-group") {
		t.Fatalf("#16580: strict message known list must include active-server-group: %v", err)
	}
	// Tolerant path keeps the compiles-to-NOTHING wording (true there).
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("#16580: lenient must not fail (#1960): %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "xpfbogus16580") && strings.Contains(w, "compiles to NOTHING") {
			found = true
		}
	}
	if !found {
		t.Fatalf("#16580: lenient warning must keep compiles-to-NOTHING wording: %v", cfg.Warnings)
	}
}
