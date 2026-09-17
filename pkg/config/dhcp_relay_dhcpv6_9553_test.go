package config

import (
	"strings"
	"testing"
)

// #9553 STEP-0 repro: `forwarding-options dhcp-relay dhcpv6` must compile to a
// DHCPv6 relay. On the base this is RED — strict CompileConfig refuses the
// stanza (#9411) because there is no agent to hand it to. When the RFC 8415
// relay agent lands, the refusal is retired in the same change and this cell
// goes GREEN. It then grows the typed assertions on the compiled v6 relay.
func TestDHCPRelayDHCPv6CompilesToV6Relay9553(t *testing.T) {
	tree := bracedTree9411(t, "forwarding-options { dhcp-relay { dhcpv6 { "+
		"relay-agent-interface-id global-iid; "+
		"server-group isp6 { 2001:db8::5; } "+
		"group g6 { active-server-group isp6; interface ge-0/0/0.0; } } } }")
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("#9553: strict CompileConfig refused the supported dhcpv6 relay stanza: %v", err)
	}
	if mentions9411(cfg.Warnings) {
		t.Fatalf("#9553: strict compile carried an obsolete #9411 warning: %v", cfg.Warnings)
	}
	relay := cfg.ForwardingOptions.DHCPRelay
	if relay == nil || relay.V6 == nil {
		t.Fatalf("#9553: dhcpv6 stanza did not compile to a typed v6 relay: %+v", relay)
	}
	sg := relay.V6.ServerGroups["isp6"]
	if sg == nil || len(sg.Servers) != 1 || sg.Servers[0] != "2001:db8::5" {
		t.Fatalf("#9553: v6 server-group compiled incorrectly: %+v", relay.V6.ServerGroups)
	}
	if relay.V6.InterfaceIDOverride != "global-iid" {
		t.Fatalf("#9553: global relay-agent-interface-id was discarded: %+v", relay.V6)
	}
	group := relay.V6.Groups["g6"]
	if group == nil || group.ActiveServerGroup != "isp6" || len(group.Interfaces) != 1 || group.Interfaces[0] != "ge-0/0/0.0" {
		t.Fatalf("#9553: v6 group compiled incorrectly: %+v", relay.V6.Groups)
	}
}
func TestDHCPRelayDHCPv6BareInterfaceIDDefaults9553(t *testing.T) {
	for _, tc := range []struct {
		name  string
		tree  *ConfigTree
		group bool
	}{
		{
			name: "family",
			tree: bracedTree9411(t, "forwarding-options { dhcp-relay { dhcpv6 { "+
				"relay-agent-interface-id; "+
				"server-group isp6 { 2001:db8::5; } "+
				"group g6 { active-server-group isp6; interface ge-0/0/0.0; } } } }"),
		},
		{
			name: "family-flat",
			tree: flatTree9411(t,
				"set forwarding-options dhcp-relay dhcpv6 relay-agent-interface-id",
				"set forwarding-options dhcp-relay dhcpv6 server-group isp6 2001:db8::5",
				"set forwarding-options dhcp-relay dhcpv6 group g6 active-server-group isp6",
				"set forwarding-options dhcp-relay dhcpv6 group g6 interface ge-0/0/0.0"),
		},
		{
			name: "group",
			tree: bracedTree9411(t, "forwarding-options { dhcp-relay { dhcpv6 { "+
				"server-group isp6 { 2001:db8::5; } "+
				"group g6 { active-server-group isp6; interface ge-0/0/0.0; "+
				"relay-agent-interface-id; } } } }"),
			group: true,
		},
		{
			name: "group-flat",
			tree: flatTree9411(t,
				"set forwarding-options dhcp-relay dhcpv6 server-group isp6 2001:db8::5",
				"set forwarding-options dhcp-relay dhcpv6 group g6 active-server-group isp6",
				"set forwarding-options dhcp-relay dhcpv6 group g6 interface ge-0/0/0.0",
				"set forwarding-options dhcp-relay dhcpv6 group g6 relay-agent-interface-id"),
			group: true,
		},
		{
			name: "family-fully-elided-before-sibling",
			tree: bracedTree9411(t, "forwarding-options dhcp-relay dhcpv6 relay-agent-interface-id server-group isp6 2001:db8::5 group g6 active-server-group isp6 interface ge-0/0/0.0;"),
		},
		{
			name:  "group-fully-elided-before-sibling",
			tree:  bracedTree9411(t, "forwarding-options dhcp-relay dhcpv6 server-group isp6 2001:db8::5 group g6 relay-agent-interface-id interface ge-0/0/0.0 active-server-group isp6;"),
			group: true,
		},
		{
			name: "family-singly-elided-before-sibling",
			tree: bracedTree9411(t, "forwarding-options { dhcp-relay { dhcpv6 relay-agent-interface-id server-group isp6 2001:db8::5 group g6 active-server-group isp6 interface ge-0/0/0.0; } }"),
		},
		{
			name:  "group-singly-elided-before-sibling",
			tree:  bracedTree9411(t, "forwarding-options { dhcp-relay { dhcpv6 server-group isp6 2001:db8::5 group g6 relay-agent-interface-id interface ge-0/0/0.0 active-server-group isp6; } }"),
			group: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CompileConfig(tc.tree)
			if err != nil {
				t.Fatalf("bare %s relay-agent-interface-id flag was rejected: %v", tc.name, err)
			}
			v6 := cfg.ForwardingOptions.DHCPRelay.V6
			if v6 == nil {
				t.Fatalf("bare %s flag did not compile a DHCPv6 relay: %+v", tc.name, cfg)
			}
			if tc.group {
				if got := v6.Groups["g6"].InterfaceIDOverride; got != "" {
					t.Fatalf("bare group flag installed a non-default IID %q", got)
				}
			} else if got := v6.InterfaceIDOverride; got != "" {
				t.Fatalf("bare family flag installed a non-default IID %q", got)
			}
		})
	}
}

func TestDHCPRelayDHCPv6BareGroupSuppressesFamilyOverride9553(t *testing.T) {
	tree := bracedTree9411(t, "forwarding-options { dhcp-relay { dhcpv6 { "+
		"relay-agent-interface-id family-iid; "+
		"server-group isp6 { 2001:db8::5; } "+
		"group g6 { active-server-group isp6; interface ge-0/0/0.0; "+
		"relay-agent-interface-id; } } } }")
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("family scalar plus bare group flag was rejected: %v", err)
	}
	v6 := cfg.ForwardingOptions.DHCPRelay.V6
	if v6 == nil || v6.InterfaceIDOverride != "family-iid" {
		t.Fatalf("family Interface-ID override = %+v, want family-iid", v6)
	}
	group := v6.Groups["g6"]
	if group == nil || group.InterfaceIDOverride != "" || !group.InterfaceIDOverrideSet {
		t.Fatalf("bare group Interface-ID state = %+v, want explicit empty override", group)
	}
}

func TestDHCPRelayDHCPv6BracedAndPackedScalarResults9553(t *testing.T) {
	const braced = "forwarding-options { dhcp-relay { dhcpv6 { " +
		"active-server-group sg6; relay-agent-interface-id family-iid; " +
		"server-group sg6 { 2001:db8::5; } " +
		"group g6 { active-server-group sg6; interface ge-0/0/0.0; " +
		"relay-agent-interface-id group-iid; } } } }"
	const packed = "forwarding-options dhcp-relay dhcpv6 " +
		"active-server-group sg6 relay-agent-interface-id family-iid " +
		"server-group sg6 2001:db8::5 group g6 active-server-group sg6 " +
		"interface ge-0/0/0.0 relay-agent-interface-id group-iid;"
	const singly = "forwarding-options { dhcp-relay { dhcpv6 " +
		"active-server-group sg6 relay-agent-interface-id family-iid " +
		"server-group sg6 2001:db8::5 group g6 active-server-group sg6 " +
		"interface ge-0/0/0.0 relay-agent-interface-id group-iid; } }"
	for _, tc := range []struct {
		name string
		tree *ConfigTree
	}{
		{"braced", bracedTree9411(t, braced)},
		{"packed", bracedTree9411(t, packed)},
		{"singly-elided", bracedTree9411(t, singly)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CompileConfig(tc.tree)
			if err != nil {
				t.Fatalf("%s DHCPv6 spelling rejected: %v", tc.name, err)
			}
			if cfg.ForwardingOptions.DHCPRelay == nil || cfg.ForwardingOptions.DHCPRelay.V6 == nil {
				t.Fatalf("%s did not compile a DHCPv6 relay: %+v", tc.name, cfg)
			}
			v6 := cfg.ForwardingOptions.DHCPRelay.V6
			if v6.ActiveServerGroup != "sg6" || v6.InterfaceIDOverride != "family-iid" {
				t.Fatalf("%s family scalars = active %q IID %q", tc.name, v6.ActiveServerGroup, v6.InterfaceIDOverride)
			}
			sg := v6.ServerGroups["sg6"]
			if sg == nil || len(sg.Servers) != 1 || sg.Servers[0] != "2001:db8::5" {
				t.Fatalf("%s server-group result = %+v", tc.name, sg)
			}
			group := v6.Groups["g6"]
			if group == nil || group.ActiveServerGroup != "sg6" || group.InterfaceIDOverride != "group-iid" ||
				len(group.Interfaces) != 1 || group.Interfaces[0] != "ge-0/0/0.0" {
				t.Fatalf("%s group result = %+v", tc.name, group)
			}
		})
	}
}
func TestDHCPRelayDHCPv6BracketedInterfaceList9553(t *testing.T) {
	tree := bracedTree9411(t, "forwarding-options { dhcp-relay { dhcpv6 { server-group isp6 { 2001:db8::5; } group g6 { active-server-group isp6; interface [ ge-0/0/0.0 ge-0/0/1.0 ]; } } } }")
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("bracketed DHCPv6 interface list rejected: %v", err)
	}
	group := cfg.ForwardingOptions.DHCPRelay.V6.Groups["g6"]
	if group == nil || len(group.Interfaces) != 2 ||
		group.Interfaces[0] != "ge-0/0/0.0" || group.Interfaces[1] != "ge-0/0/1.0" {
		t.Fatalf("bracketed DHCPv6 interface list = %+v", group)
	}
}

func TestDHCPRelayDHCPv6MetaStatementsRemainLegal9553(t *testing.T) {
	for _, tc := range []struct {
		name string
		text string
	}{
		{
			"family",
			"forwarding-options { dhcp-relay { dhcpv6 { apply-groups foo; apply-groups-except bar; apply-macro baz { inherited; } server-group isp6 { 2001:db8::5; } group g6 { active-server-group isp6; interface ge-0/0/0.0; } } } }",
		},
		{
			"group",
			"forwarding-options { dhcp-relay { dhcpv6 { server-group isp6 { 2001:db8::5; } group g6 { apply-groups foo; apply-groups-except bar; apply-macro baz { inherited; } active-server-group isp6; interface ge-0/0/0.0; } } } }",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := bracedTree9411(t, tc.text)
			if _, err := validateDHCPRelayDHCPv6AST(tree.Children, false); err != nil {
				t.Fatalf("legal %s-scope meta statements were rejected by v6 gate: %v", tc.name, err)
			}
		})
	}
}

// TestDHCPRelayDHCPv6FullyElidedPackedRemainder9553 pins the raw parser shape
// that is normalized before the ordinary pre-walk. Supported packed tokens must
// still compile as DHCPv6, while an unknown token in the same packed tail must
// remain visible to the strict #9553 remainder gate.
func TestDHCPRelayDHCPv6FullyElidedPackedRemainder9553(t *testing.T) {
	valid := bracedTree9411(t, "forwarding-options dhcp-relay dhcpv6 server-group isp6 2001:db8::5 group g6 active-server-group isp6 interface ge-0/0/0.0;")
	cfg, err := CompileConfig(valid)
	if err != nil {
		t.Fatalf("#9553: supported fully-elided DHCPv6 relay was rejected: %v", err)
	}
	if cfg.ForwardingOptions.DHCPRelay == nil || cfg.ForwardingOptions.DHCPRelay.V6 == nil {
		t.Fatalf("#9553: supported fully-elided relay did not compile to V6: %+v", cfg)
	}

	for _, tc := range []struct {
		name string
		text string
	}{
		{"unknown direct token", "forwarding-options dhcp-relay dhcpv6 unsupported-knob foo;"},
		{"unknown group token", "forwarding-options dhcp-relay dhcpv6 server-group isp6 2001:db8::5 group g6 active-server-group isp6 unsupported-knob foo interface ge-0/0/0.0;"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			unsupported := bracedTree9411(t, tc.text)
			if _, err := CompileConfig(unsupported); err == nil || !strings.Contains(err.Error(), "#9553") {
				t.Fatalf("#9553: unknown packed DHCPv6 token committed clean: %v", err)
			}
			lenient, err := CompileConfigLenient(unsupported)
			if err != nil {
				t.Fatalf("#9553 no-brick: tolerant packed remainder was rejected: %v", err)
			}
			foundWarning := false
			for _, warning := range lenient.Warnings {
				if strings.Contains(warning, "#9553") {
					foundWarning = true
					break
				}
			}
			if !foundWarning {
				t.Fatalf("#9553 no-brick: tolerant packed remainder emitted no scoped warning: %v", lenient.Warnings)
			}
		})
	}
}

// TestDHCPRelayDHCPv6GateSeesRawElidedShape9411 is the raw-shape regression
// cell. The pre-#9553 gate was accidentally tested only after normalization,
// which allowed a fully elided AST to bypass the refusal boundary. Keep this
// cell on the raw parser tree: supported tokens pass, while an unsupported
func TestDHCPRelayDHCPv6GateSeesRawElidedShape9411(t *testing.T) {
	supported := bracedTree9411(t, "forwarding-options dhcp-relay dhcpv6 server-group isp6 2001:db8::5 group g6 active-server-group isp6 interface ge-0/0/0.0;")
	family := dhcpRelayV6Nodes9553(supported.Children[0])
	if len(family) != 1 || family[0] == nil {
		t.Fatalf("raw elided DHCPv6 family disappeared before gate: %+v", supported)
	}
	if _, err := validateDHCPRelayDHCPv6AST(supported.Children, false); err != nil {
		t.Fatalf("supported raw elided shape was refused: %v", err)
	}
	unsupported := bracedTree9411(t, "forwarding-options dhcp-relay dhcpv6 server-group isp6 2001:db8::5 unsupported-knob foo;")
	if _, err := CompileConfig(unsupported); err == nil || !strings.Contains(err.Error(), "#9553") {
		t.Fatalf("unsupported raw elided shape bypassed the strict gate: %v", err)
	}
}

// TestDHCPRelayDHCPv6RejectsNestedLeafChildren9553 protects the scalar
// boundary. A Junos leaf followed by a brace or packed tail must not be
// absorbed into the interface list or Interface-ID value.
func TestDHCPRelayDHCPv6RejectsNestedLeafChildren9553(t *testing.T) {
	cases := []struct {
		name string
		tree *ConfigTree
	}{
		{
			"braced interface child",
			bracedTree9411(t, "forwarding-options { dhcp-relay { dhcpv6 { server-group isp6 { 2001:db8::5; } group g6 { active-server-group isp6; interface ge-0/0/0.0 { disable; } } } } }"),
		},
		{
			"braced interface member child",
			bracedTree9411(t, "forwarding-options { dhcp-relay { dhcpv6 { server-group isp6 { 2001:db8::5; } group g6 { active-server-group isp6; interface { ge-0/0/0.0 { disable; } } } } } }"),
		},
		{
			"braced server-group member child",
			bracedTree9411(t, "forwarding-options { dhcp-relay { dhcpv6 { server-group isp6 { 2001:db8::5 { bogus; } } group g6 { active-server-group isp6; interface ge-0/0/0.0; } } } }"),
		},
		{
			"braced Interface-ID child",
			bracedTree9411(t, "forwarding-options { dhcp-relay { dhcpv6 { server-group isp6 { 2001:db8::5; } group g6 { active-server-group isp6; interface ge-0/0/0.0; relay-agent-interface-id { use-option-82; } } } } }"),
		},
		{
			"braced family active-server-group child",
			bracedTree9411(t, "forwarding-options { dhcp-relay { dhcpv6 { active-server-group isp6 { unsupported; } server-group isp6 { 2001:db8::5; } group g6 { active-server-group isp6; interface ge-0/0/0.0; } } } }"),
		},
		{
			"braced group active-server-group child",
			bracedTree9411(t, "forwarding-options { dhcp-relay { dhcpv6 { server-group isp6 { 2001:db8::5; } group g6 { active-server-group isp6 { unsupported; } interface ge-0/0/0.0; } } } }"),
		},
		{
			"flat interface packed tail",
			flatTree9411(t,
				"set forwarding-options dhcp-relay dhcpv6 server-group isp6 2001:db8::5",
				"set forwarding-options dhcp-relay dhcpv6 group g6 active-server-group isp6",
				"set forwarding-options dhcp-relay dhcpv6 group g6 interface ge-0/0/0.0 disable"),
		},
		{
			"flat active-server-group packed tail",
			flatTree9411(t,
				"set forwarding-options dhcp-relay dhcpv6 server-group isp6 2001:db8::5",
				"set forwarding-options dhcp-relay dhcpv6 group g6 active-server-group isp6 unsupported",
				"set forwarding-options dhcp-relay dhcpv6 group g6 interface ge-0/0/0.0"),
		},
		{
			"flat Interface-ID use-option-82",
			flatTree9411(t,
				"set forwarding-options dhcp-relay dhcpv6 server-group isp6 2001:db8::5",
				"set forwarding-options dhcp-relay dhcpv6 group g6 active-server-group isp6",
				"set forwarding-options dhcp-relay dhcpv6 group g6 interface ge-0/0/0.0",
				"set forwarding-options dhcp-relay dhcpv6 group g6 relay-agent-interface-id use-option-82"),
		},
		{
			"valueless family active-server-group with group fallback",
			bracedTree9411(t, "forwarding-options { dhcp-relay { dhcpv6 { active-server-group; server-group isp6 { 2001:db8::5; } group g6 { active-server-group isp6; interface ge-0/0/0.0; } } } }"),
		},
		{
			"valueless group active-server-group with family fallback",
			bracedTree9411(t, "forwarding-options { dhcp-relay { dhcpv6 { active-server-group isp6; server-group isp6 { 2001:db8::5; } group g6 { active-server-group; interface ge-0/0/0.0; } } } }"),
		},
		{
			"valueless interface with another valid interface",
			bracedTree9411(t, "forwarding-options { dhcp-relay { dhcpv6 { server-group isp6 { 2001:db8::5; } group g6 { active-server-group isp6; interface; interface ge-0/0/0.0; } } } }"),
		},
	}
	wantMessages := map[string]string{
		"valueless family active-server-group with group fallback": "active-server-group requires a value",
		"valueless group active-server-group with family fallback": "active-server-group requires a value",
		"valueless interface with another valid interface":         "interface requires a value",
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(tc.tree)
			if err == nil || !strings.Contains(err.Error(), "#9553") {
				t.Fatalf("malformed DHCPv6 leaf committed without #9553 refusal: %v", err)
			}
			if want := wantMessages[tc.name]; want != "" && !strings.Contains(err.Error(), want) {
				t.Fatalf("malformed %s refusal = %v, want message fragment %q", tc.name, err, want)
			}
			lenient, err := CompileConfigLenient(tc.tree)
			if err != nil {
				t.Fatalf("tolerant malformed leaf bricked config: %v", err)
			}
			if !mentions9553(lenient.Warnings) {
				t.Fatalf("tolerant malformed leaf emitted no #9553 warning: %v", lenient.Warnings)
			}
			if want := wantMessages[tc.name]; want != "" && !strings.Contains(strings.Join(lenient.Warnings, "\n"), want) {
				t.Fatalf("tolerant %s warning = %v, want message fragment %q", tc.name, lenient.Warnings, want)
			}
		})
	}
}

func mentions9553(warnings []string) bool {
	for _, warning := range warnings {
		if strings.Contains(warning, "#9553") {
			return true
		}
	}
	return false
}

// TestDHCPRelayDHCPv6RejectsDocumentedInterfaceIDSuboptions9553 keeps the
// Junos Interface-ID sub-option forms explicit. These keywords are valid Junos
// syntax under forwarding-options dhcp-relay dhcpv6
// relay-agent-interface-id, but are outside xpf's byte-valued Interface-ID
// implementation, so both family and group forms must refuse strictly and warn
// tolerantly.
func TestDHCPRelayDHCPv6RejectsDocumentedInterfaceIDSuboptions9553(t *testing.T) {
	suboptions := []string{
		"use-option-82",
		"prefix",
		"host-name",
		"routing-instance-name",
		"logical-system-name",
		"use-interface-description",
		"include-irb-and-l2",
		"keep-incoming-interface-id",
		"no-vlan-interface-name",
		"use-vlan-id",
	}
	for _, form := range []string{"flat", "braced"} {
		for _, scope := range []string{"family", "group"} {
			for _, suboption := range suboptions {
				form, scope, suboption := form, scope, suboption
				t.Run(form+"-"+scope+"-"+suboption, func(t *testing.T) {
					var tree *ConfigTree
					if form == "flat" {
						lines := []string{
							"set forwarding-options dhcp-relay dhcpv6 server-group isp6 2001:db8::5",
							"set forwarding-options dhcp-relay dhcpv6 group g6 active-server-group isp6",
							"set forwarding-options dhcp-relay dhcpv6 group g6 interface ge-0/0/0.0",
						}
						if scope == "family" {
							lines = append(lines, "set forwarding-options dhcp-relay dhcpv6 relay-agent-interface-id "+suboption)
						} else {
							lines = append(lines, "set forwarding-options dhcp-relay dhcpv6 group g6 relay-agent-interface-id "+suboption)
						}
						tree = flatTree9411(t, lines...)
					} else if scope == "family" {
						tree = bracedTree9411(t, "forwarding-options { dhcp-relay { dhcpv6 { "+
							"relay-agent-interface-id { "+suboption+"; } "+
							"server-group isp6 { 2001:db8::5; } "+
							"group g6 { active-server-group isp6; interface ge-0/0/0.0; } } } }")
					} else {
						tree = bracedTree9411(t, "forwarding-options { dhcp-relay { dhcpv6 { "+
							"server-group isp6 { 2001:db8::5; } "+
							"group g6 { active-server-group isp6; interface ge-0/0/0.0; "+
							"relay-agent-interface-id { "+suboption+"; } } } } }")
					}
					if _, err := CompileConfig(tree); err == nil ||
						!strings.Contains(err.Error(), "#9553") ||
						!strings.Contains(err.Error(), suboption) {
						t.Fatalf("strict %s compile accepted unsupported %s Interface-ID sub-option %q: %v", form, scope, suboption, err)
					}
					cfg, err := CompileConfigLenient(tree)
					if err != nil {
						t.Fatalf("tolerant %s compile bricked unsupported %s Interface-ID sub-option %q: %v", form, scope, suboption, err)
					}
					found := false
					for _, warning := range cfg.Warnings {
						if strings.Contains(warning, "#9553") && strings.Contains(warning, suboption) {
							found = true
							break
						}
					}
					if !found {
						t.Fatalf("tolerant %s compile did not warn for unsupported %s Interface-ID sub-option %q: %v", form, scope, suboption, cfg.Warnings)
					}
					relay := cfg.ForwardingOptions.DHCPRelay
					if relay == nil || relay.V6 == nil {
						t.Fatalf("tolerant %s compile dropped the DHCPv6 relay while warning: %+v", form, cfg)
					}
					if scope == "family" {
						if got := relay.V6.InterfaceIDOverride; got != "" {
							t.Fatalf("tolerant %s compile installed unsupported family IID %q", form, got)
						}
					} else {
						group := relay.V6.Groups["g6"]
						if group == nil {
							t.Fatalf("tolerant %s compile dropped group while warning: %+v", form, relay.V6)
						}
						if got := group.InterfaceIDOverride; got != "" {
							t.Fatalf("tolerant %s compile installed unsupported group IID %q", form, got)
						}
					}
				})
			}
		}
	}
}

func TestDHCPRelayDHCPv6LenientChildDoesNotInstallInterfaceID9553(t *testing.T) {
	tree := bracedTree9411(t, "forwarding-options { dhcp-relay { dhcpv6 { "+
		"server-group isp6 { 2001:db8::5; } "+
		"group g6 { active-server-group isp6; interface ge-0/0/0.0; "+
		"relay-agent-interface-id { unimplemented-modifier; } } } } }")
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("tolerant compile bricked a warned Interface-ID child: %v", err)
	}
	if !mentions9553(cfg.Warnings) {
		t.Fatalf("tolerant compile emitted no #9553 warning for Interface-ID child: %v", cfg.Warnings)
	}
	relay := cfg.ForwardingOptions.DHCPRelay
	if relay == nil || relay.V6 == nil {
		t.Fatalf("tolerant compile dropped the DHCPv6 relay while warning: %+v", cfg)
	}
	group := relay.V6.Groups["g6"]
	if group == nil {
		t.Fatalf("tolerant compile dropped the group while warning: %+v", relay.V6)
	}
	if group.InterfaceIDOverride != "" {
		t.Fatalf("tolerant compile installed child name as Interface-ID %q", group.InterfaceIDOverride)
	}
}
