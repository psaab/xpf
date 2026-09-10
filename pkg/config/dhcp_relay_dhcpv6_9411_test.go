package config

import (
	"strings"
	"testing"
)

// #9411 — `forwarding-options dhcp-relay dhcpv6` must be LOUD, not discarded.
//
// CHANNELS. This file drives config.CompileConfig (the strict compiler, where
// the gate is fatal) and config.CompileConfigLenient (the tolerant Store.Load /
// Store.SyncApply ingress, where it is a warning). configstore.CheckText — the
// operator commit path — is asserted in
// pkg/configstore/dhcp_relay_dhcpv6_checktext_9411_test.go. SchemaValidate still
// ACCEPTS the stanza: the refusal lives in the compiler's pre-walk, because the
// stanza compiles to nothing and the schema walk is open-world under dhcp-relay.

func bracedTree9411(t *testing.T, txt string) *ConfigTree {
	t.Helper()
	tree, errs := NewParser(txt).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse %q: %v", txt, errs[0])
	}
	return tree
}

func flatTree9411(t *testing.T, lines ...string) *ConfigTree {
	t.Helper()
	tr := &ConfigTree{}
	for _, l := range lines {
		p, err := ParseSetCommand(l)
		if err != nil {
			t.Fatalf("parse %q: %v", l, err)
		}
		if err := tr.SetPath(p); err != nil {
			t.Fatalf("setpath %q: %v", l, err)
		}
	}
	return tr
}

func relayCounts9411(cfg *Config) (sg, g int) {
	if cfg == nil || cfg.ForwardingOptions.DHCPRelay == nil {
		return 0, 0
	}
	r := cfg.ForwardingOptions.DHCPRelay
	return len(r.ServerGroups), len(r.Groups)
}

func mentions9411(warnings []string) bool {
	for _, w := range warnings {
		if strings.Contains(w, "#9411") {
			return true
		}
	}
	return false
}

// TestDHCPRelayDHCPv6IsRefusedInEveryShape9411 is the fix, in every measured AST
// shape. A gate that checked one shape would pass its own fixture and miss the
// other four.
func TestDHCPRelayDHCPv6IsRefusedInEveryShape9411(t *testing.T) {
	for _, tc := range []struct {
		name                string
		tree                func(*testing.T) *ConfigTree
		lenientSG, lenientG int
	}{
		{"braced nested", func(t *testing.T) *ConfigTree {
			return bracedTree9411(t, "forwarding-options { dhcp-relay { dhcpv6 { server-group isp6 { 2001:db8::5; } group g6 { active-server-group isp6; interface ge-0/0/0.0; } } } }")
		}, 0, 0},
		{"bare dhcpv6 leaf", func(t *testing.T) *ConfigTree {
			return bracedTree9411(t, "forwarding-options { dhcp-relay { dhcpv6; } }")
		}, 0, 0},
		{"relay elided onto dhcpv6 (the relay node's own Keys[1])", func(t *testing.T) *ConfigTree {
			return bracedTree9411(t, "forwarding-options { dhcp-relay dhcpv6 { group g6 { interface ge-0/0/0.0; } } }")
		}, 0, 0},
		{"fully elided (forwarding-options' own Keys)", func(t *testing.T) *ConfigTree {
			return bracedTree9411(t, "forwarding-options dhcp-relay dhcpv6 group g6 interface ge-0/0/0.0;")
		}, 0, 0},
		{"flat-set (one child per set line)", func(t *testing.T) *ConfigTree {
			return flatTree9411(t,
				"set forwarding-options dhcp-relay dhcpv6 server-group isp6 2001:db8::5",
				"set forwarding-options dhcp-relay dhcpv6 group g6 active-server-group isp6",
				"set forwarding-options dhcp-relay dhcpv6 group g6 interface ge-0/0/0.0")
		}, 0, 0},
		{
			// On the tolerant path the v4 relay beside the stanza must still
			// compile: the warning replaces a silent discard, it does not add a
			// new one.
			"BESIDE a working v4 relay", func(t *testing.T) *ConfigTree {
				return bracedTree9411(t, "forwarding-options { dhcp-relay { group g1 { interface ge-0/0/0.0; } dhcpv6 { group g6 { interface ge-0/0/1.0; } } } }")
			}, 0, 1},
		{
			// The dhcpv6-elided block FIRST. Before the fix FindChild returned it,
			// so g6 compiled as a DHCPv4 relay AND the real DHCPv4 block after it
			// was never compiled. The tolerant path must compile g1, not g6.
			"relay-elided dhcpv6 BEFORE a v4 relay block", func(t *testing.T) *ConfigTree {
				return bracedTree9411(t, "forwarding-options { dhcp-relay dhcpv6 { group g6 { interface ge-0/0/1.0; } } dhcp-relay { server-group isp { 10.0.0.5; } group g1 { active-server-group isp; interface ge-0/0/0.0; } } }")
			}, 1, 1},
		{
			"relay-elided dhcpv6 AFTER a v4 relay block", func(t *testing.T) *ConfigTree {
				return bracedTree9411(t, "forwarding-options { dhcp-relay { server-group isp { 10.0.0.5; } group g1 { active-server-group isp; interface ge-0/0/0.0; } } dhcp-relay dhcpv6 { group g6 { interface ge-0/0/1.0; } } }")
			}, 1, 1},
		{
			// Measured: the pre-walk runs on the GROUP-EXPANDED tree, so a stanza
			// injected through apply-groups is caught too.
			"injected via apply-groups", func(t *testing.T) *ConfigTree {
				return bracedTree9411(t, "groups { g1 { forwarding-options { dhcp-relay { dhcpv6 { group g6 { interface ge-0/0/0.0; } } } } } } apply-groups g1;")
			}, 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := tc.tree(t)
			if _, err := CompileConfig(tree); err == nil || !strings.Contains(err.Error(), "#9411") {
				t.Fatalf("#9411: strict CompileConfig did not refuse the dhcpv6 relay stanza; err = %v\n"+
					"It compiles to NOTHING — there is no DHCPv6 relay agent — so a clean commit "+
					"is the defect: the operator gets no relay and no complaint.", err)
			}
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("#9411 NO-BRICK: the tolerant compile REFUSED the config (%v). "+
					"Store.Load and Store.SyncApply use this path, so refusing here blackouts "+
					"a node booting a persisted config or receiving one from its HA peer (#1960).", err)
			}
			if !mentions9411(cfg.Warnings) {
				t.Errorf("#9411: the tolerant path emitted no #9411 warning, so the stanza is still "+
					"silently discarded wherever the strict gate does not run. warnings: %v", cfg.Warnings)
			}
			if sg, g := relayCounts9411(cfg); sg != tc.lenientSG || g != tc.lenientG {
				t.Errorf("#9411: tolerant relay = %d server-groups / %d groups, want %d / %d",
					sg, g, tc.lenientSG, tc.lenientG)
			}
			// THE MIS-COMPILE, pinned directly: no DHCPv6 group may ever surface as a
			// DHCPv4 relay group. Before the fix `dhcp-relay dhcpv6 { group g6 … }`
			// compiled to v4-groups=[g6] on every channel.
			if r := cfg.ForwardingOptions.DHCPRelay; r != nil {
				if _, ok := r.Groups["g6"]; ok {
					t.Errorf("#9411 MIS-COMPILE: the DHCPv6 group g6 was compiled as a DHCPv4 relay "+
						"group, so a DHCPv4 relay is installed on the interface the operator named for "+
						"DHCPv6. groups: %v", r.Groups)
				}
			}
		})
	}
}

// TestDHCPRelayDHCPv6GateDoesNotRefuseAWorkingV4Relay9411 carries the rows that
// matter most, because "the stanza is refused" is satisfiable by refusing every
// relay config — which would take down DHCPv4 relay for everyone on their next
// commit, a far worse defect than the silent discard being fixed (#4191).
//
// The sharpest rows are a DHCPv4 relay GROUP or SERVER-GROUP that is merely NAMED
// `dhcpv6`. They are why the gate matches by token POSITION: a gate that looked
// for the token anywhere under dhcp-relay would refuse them.
func TestDHCPRelayDHCPv6GateDoesNotRefuseAWorkingV4Relay9411(t *testing.T) {
	for _, tc := range []struct {
		name             string
		tree             func(*testing.T) *ConfigTree
		strictMustCommit bool
		wantSG, wantG    int // -1 = not asserted
	}{
		{"CONTROL braced v4 relay", func(t *testing.T) *ConfigTree {
			return bracedTree9411(t, "forwarding-options { dhcp-relay { server-group isp { 10.0.0.5; } group g1 { active-server-group isp; interface ge-0/0/0.0; } } }")
		}, true, 1, 1},
		{"CONTROL flat-set v4 relay", func(t *testing.T) *ConfigTree {
			return flatTree9411(t,
				"set forwarding-options dhcp-relay server-group isp 10.0.0.5",
				"set forwarding-options dhcp-relay group g1 active-server-group isp",
				"set forwarding-options dhcp-relay group g1 interface ge-0/0/0.0")
		}, true, 1, 1},
		{"v4 GROUP named dhcpv6, braced", func(t *testing.T) *ConfigTree {
			return bracedTree9411(t, "forwarding-options { dhcp-relay { server-group isp { 10.0.0.5; } group dhcpv6 { active-server-group isp; interface ge-0/0/0.0; } } }")
		}, true, 1, 1},
		{"v4 GROUP named dhcpv6, flat-set", func(t *testing.T) *ConfigTree {
			return flatTree9411(t,
				"set forwarding-options dhcp-relay server-group isp 10.0.0.5",
				"set forwarding-options dhcp-relay group dhcpv6 active-server-group isp",
				"set forwarding-options dhcp-relay group dhcpv6 interface ge-0/0/0.0")
		}, true, 1, 1},
		{"v4 SERVER-GROUP named dhcpv6, flat-set", func(t *testing.T) *ConfigTree {
			return flatTree9411(t,
				"set forwarding-options dhcp-relay server-group dhcpv6 10.0.0.5",
				"set forwarding-options dhcp-relay group g1 active-server-group dhcpv6",
				"set forwarding-options dhcp-relay group g1 interface ge-0/0/0.0")
		}, true, 1, 1},
		{
			// Elided spelling of the named group: the assertion is only that THIS
			// gate does not fire, since the elided grammar is not this fix's subject.
			"v4 GROUP named dhcpv6, fully elided", func(t *testing.T) *ConfigTree {
				return bracedTree9411(t, "forwarding-options dhcp-relay group dhcpv6 interface ge-0/0/0.0;")
			}, false, -1, -1},
		{
			// A DEACTIVATED dhcpv6 stanza is inert by design and is pruned before the
			// gate runs (measured). Refusing it would stop an operator committing a
			// deactivated migration artefact they have deliberately set aside.
			"inactive: dhcpv6 is NOT refused", func(t *testing.T) *ConfigTree {
				return bracedTree9411(t, "forwarding-options { dhcp-relay { inactive: dhcpv6 { group g6 { interface ge-0/0/0.0; } } } }")
			}, true, 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := tc.tree(t)
			cfg, err := CompileConfig(tree)
			if err != nil && strings.Contains(err.Error(), "#9411") {
				t.Fatalf("#9411 OVER-REJECTION: a DHCPv4 relay was refused as a DHCPv6 stanza: %v\n"+
					"The gate must match `dhcpv6` by POSITION — immediately after `dhcp-relay`, or "+
					"as a child's own name — not anywhere it appears as a token.", err)
			}
			if tc.strictMustCommit && err != nil {
				t.Fatalf("#9411: a DHCPv4 relay control no longer commits: %v", err)
			}
			if tc.wantSG >= 0 {
				if sg, g := relayCounts9411(cfg); sg != tc.wantSG || g != tc.wantG {
					t.Errorf("#9411: v4 relay = %d server-groups / %d groups, want %d / %d",
						sg, g, tc.wantSG, tc.wantG)
				}
			}
			if lc, lerr := CompileConfigLenient(tree); lerr == nil && mentions9411(lc.Warnings) {
				t.Errorf("#9411 OVER-REJECTION (tolerant path): a DHCPv4 relay drew a DHCPv6 warning: %v",
					lc.Warnings)
			}
		})
	}
}

// TestDHCPRelayDHCPv6GateSeesTheRawElidedShape9411 keeps the
// forwarding-options-Keys clause of validateDHCPRelayDHCPv6AST exercisable.
//
// On every compile channel the normalizer folds `forwarding-options dhcp-relay
// dhcpv6 …;` into the relay-node-Keys[1] shape before the pre-walk runs, so no
// end-to-end cell can reach that clause — measured: removing it survived every
// other #9411 cell. This cell drives the gate on the RAW parser tree, where that
// clause is the only one that can fire, so a future normalizer change that stopped
// folding the spelling cannot silently re-open it.
func TestDHCPRelayDHCPv6GateSeesTheRawElidedShape9411(t *testing.T) {
	tree := bracedTree9411(t, "forwarding-options dhcp-relay dhcpv6 group g6 interface ge-0/0/0.0;")

	// POSITIVE CONTROLS: the raw tree must carry the token in forwarding-options'
	// own Keys and have NO children, or the other clauses could fire and this cell
	// would not isolate the one it exists for.
	var fo *Node
	for _, n := range tree.Children {
		if n != nil && n.Name() == "forwarding-options" {
			fo = n
		}
	}
	if fo == nil || len(fo.Keys) < 3 || fo.Keys[1] != "dhcp-relay" || fo.Keys[2] != "dhcpv6" {
		t.Fatalf("POSITIVE CONTROL: the raw parser tree no longer carries dhcpv6 in "+
			"forwarding-options' own Keys (%+v); this cell cannot reach the clause it exists for", fo)
	}
	if len(fo.Children) != 0 {
		t.Fatalf("POSITIVE CONTROL: the raw fully-elided node has %d children, so another "+
			"clause could fire and this cell would not isolate the Keys clause", len(fo.Children))
	}

	if _, err := validateDHCPRelayDHCPv6AST(tree.Children, false); err == nil || !strings.Contains(err.Error(), "#9411") {
		t.Fatalf("#9411: the gate did not refuse the RAW fully-elided spelling; err = %v. The "+
			"normalizer happens to fold it today, but this clause is what refuses it if that stops.", err)
	}
	warns, err := validateDHCPRelayDHCPv6AST(tree.Children, true)
	if err != nil || !mentions9411(warns) {
		t.Fatalf("#9411: tolerant mode did not warn on the RAW fully-elided spelling (err=%v warns=%v)", err, warns)
	}
}
