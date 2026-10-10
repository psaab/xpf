package config

import (
	"fmt"
	"strings"
	"testing"
)

type silentFilterSite12090 struct {
	name       string
	section    string
	placement  string
	family     string
	keyword    string
	direction  string
	isConsumer bool
}

func silentFilterSites12090() []silentFilterSite12090 {
	var sites []silentFilterSite12090
	add := func(section, placement, family string, consumer bool) {
		for _, keyword := range []string{"filter", "simple-filter"} {
			for _, direction := range []string{"input", "output"} {
				parts := []string{section, placement}
				if family != "" {
					parts = append(parts, family)
				}
				parts = append(parts, keyword, direction)
				sites = append(sites, silentFilterSite12090{
					name: strings.Join(parts, "/"), section: section, placement: placement,
					family: family, keyword: keyword, direction: direction,
					isConsumer: consumer && keyword == "filter",
				})
			}
		}
	}
	add("interfaces", "interface", "", false)
	add("interfaces", "unit", "", false)
	add("interfaces", "physical-family", "inet", false)
	for _, family := range []string{"inet", "inet6"} {
		add("interfaces", "family", family, true)
		add("interfaces", "split-family", family, true)
	}
	for _, family := range []string{"mpls", "ccc"} {
		add("interfaces", "family", family, false)
	}
	add("forwarding-options", "root", "", false)
	for _, family := range []string{"inet", "inet6", "mpls", "ccc"} {
		add("forwarding-options", "family", family, false)
	}
	return sites
}

func silentFilterTree12090(t *testing.T, site silentFilterSite12090, hierarchical bool) *ConfigTree {
	t.Helper()
	var setPath, body string
	switch site.section {
	case "interfaces":
		switch site.placement {
		case "interface":
			setPath = fmt.Sprintf("interfaces ge-0/0/0 %s %s f", site.keyword, site.direction)
			body = fmt.Sprintf("interfaces { ge-0/0/0 { %s { %s f; } } }", site.keyword, site.direction)
		case "unit":
			setPath = fmt.Sprintf("interfaces ge-0/0/0 unit 0 %s %s f", site.keyword, site.direction)
			body = fmt.Sprintf("interfaces { ge-0/0/0 { unit 0 { %s { %s f; } } } }", site.keyword, site.direction)
		case "physical-family":
			setPath = fmt.Sprintf("interfaces ge-0/0/0 family %s %s %s f", site.family, site.keyword, site.direction)
			body = fmt.Sprintf("interfaces { ge-0/0/0 { family %s { %s { %s f; } } } }", site.family, site.keyword, site.direction)
		case "family":
			setPath = fmt.Sprintf("interfaces ge-0/0/0 unit 0 family %s %s %s f", site.family, site.keyword, site.direction)
			body = fmt.Sprintf("interfaces { ge-0/0/0 { unit 0 { family %s { %s { %s f; } } } } }", site.family, site.keyword, site.direction)
		case "split-family":
			setPath = fmt.Sprintf("interfaces ge-0/0/0 unit 0 family %s %s %s f", site.family, site.keyword, site.direction)
			body = fmt.Sprintf("interfaces { ge-0/0/0 { unit 0 { family { %s { %s { %s f; } } } } } }", site.family, site.keyword, site.direction)
		}
	case "forwarding-options":
		switch site.placement {
		case "root":
			setPath = fmt.Sprintf("forwarding-options %s %s f", site.keyword, site.direction)
			body = fmt.Sprintf("forwarding-options { %s { %s f; } }", site.keyword, site.direction)
		case "family":
			setPath = fmt.Sprintf("forwarding-options family %s %s %s f", site.family, site.keyword, site.direction)
			body = fmt.Sprintf("forwarding-options { family %s { %s { %s f; } } }", site.family, site.keyword, site.direction)
		}
	default:
		t.Fatalf("unknown filter section %q", site.section)
	}
	if hierarchical {
		return hierTree(t, body)
	}
	tree := flatTreeFromSets(t, "set "+setPath)
	if site.placement == "split-family" {
		// Older flat-set parsing persisted family as a bare parent with
		// the AF child below it. Recreate that legacy AST explicitly; the
		// current SetPath compoundKey shape alone would miss the regression.
		iface := tree.FindChild("interfaces").FindChild("ge-0/0/0")
		unit := iface.FindChild("unit")
		family := unit.FindChild("family")
		children := family.Children
		family.Keys = []string{"family"}
		family.IsLeaf = false
		family.Children = []*Node{{Keys: []string{site.family}, Children: children}}
	}
	return tree
}

func silentFilterCompactTree12090(t *testing.T, site silentFilterSite12090) *ConfigTree {
	t.Helper()
	var body string
	switch site.section {
	case "interfaces":
		switch site.placement {
		case "interface":
			body = fmt.Sprintf("interfaces { ge-0/0/0 %s %s f; }", site.keyword, site.direction)
		case "unit":
			body = fmt.Sprintf("interfaces { ge-0/0/0 { unit 0 %s %s f; } }", site.keyword, site.direction)
		case "physical-family":
			body = fmt.Sprintf("interfaces { ge-0/0/0 { family %s %s %s f; } }", site.family, site.keyword, site.direction)
		case "family":
			body = fmt.Sprintf("interfaces { ge-0/0/0 { unit 0 { family %s %s %s f; } } }", site.family, site.keyword, site.direction)
		case "split-family":
			body = fmt.Sprintf("interfaces { ge-0/0/0 { unit 0 { family { %s %s %s f; } } } }", site.family, site.keyword, site.direction)
		}
	case "forwarding-options":
		switch site.placement {
		case "root":
			body = fmt.Sprintf("forwarding-options %s %s f;", site.keyword, site.direction)
		case "family":
			body = fmt.Sprintf("forwarding-options { family %s %s %s f; }", site.family, site.keyword, site.direction)
		}
	default:
		t.Fatalf("unknown compact filter section %q", site.section)
	}
	return hierTree(t, body)
}

func TestFilterKeywordPopulationCannotCommitUnbound12090(t *testing.T) {
	for _, site := range silentFilterSites12090() {
		t.Run(site.name, func(t *testing.T) {
			for _, shape := range []struct {
				name         string
				hierarchical bool
				compact      bool
			}{
				{name: "flat-set"},
				{name: "hierarchical", hierarchical: true},
				{name: "compact", compact: true},
			} {
				t.Run(shape.name, func(t *testing.T) {
					tree := silentFilterTree12090(t, site, shape.hierarchical)
					if shape.compact {
						tree = silentFilterCompactTree12090(t, site)
					}
					if site.isConsumer {
						filterDefinition := fmt.Sprintf("set firewall family %s filter f term t then accept", site.family)
						base := flatTreeFromSets(t, filterDefinition)
						base.Children = append(base.Children, tree.Children...)
						cfg, err := CompileConfig(base)
						if err != nil {
							t.Fatalf("supported interface family filter binding must commit: %v", err)
						}
						unit := cfg.Interfaces.Interfaces["ge-0/0/0"].Units[0]
						got := unit.FilterInputV4
						if site.direction == "output" {
							got = unit.FilterOutputV4
						}
						if site.family == "inet6" {
							got = unit.FilterInputV6
							if site.direction == "output" {
								got = unit.FilterOutputV6
							}
						}
						if got != "f" {
							t.Fatalf("supported filter binding = %q, want f", got)
						}
						return
					}
					_, err := CompileConfig(tree)
					if err == nil {
						t.Fatalf("%s %s committed cleanly in %s shape without a consumer", site.keyword, site.direction, shape.name)
					}
					if !strings.Contains(err.Error(), site.keyword) || !strings.Contains(err.Error(), site.direction) ||
						(!strings.Contains(err.Error(), "#10293") && !strings.Contains(err.Error(), "#12090")) {
						t.Fatalf("reject error %q must identify the unsupported %s %s binding and its gate", err, site.keyword, site.direction)
					}
				})
			}
		})
	}
	// Keyword-looking values and apply statements are outside this gate's
	// keyword-head population and must keep their Junos value semantics.
	testFilterKeywordValueCases12090(t)

}

func TestCompactFilterHeadsRejectAndWarn12090(t *testing.T) {
	for _, tc := range []struct {
		name string
		text string
	}{
		{"unit-filter", "interfaces { ge-0/0/0 { unit 1 filter input protect; } }"},
		{"unit-simple-filter", "interfaces { ge-0/0/0 { unit 0 simple-filter output protect; } }"},
		{"forwarding-root-filter", "forwarding-options filter input protect;"},
		{"forwarding-root-simple-filter", "forwarding-options simple-filter input protect;"},
		{"forwarding-sampling-filter", "forwarding-options { sampling filter input f; }"},
		{"apply-group-unit-filter", "groups { g { interfaces { ge-0/0/0 { unit 0 filter input f; } } } } apply-groups g;"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := hierTree(t, tc.text)
			_, err := CompileConfig(tree)
			if err == nil || !strings.Contains(err.Error(), "#12090") {
				t.Fatalf("packed unsupported filter head must reject with #12090; got %v", err)
			}
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("lenient load must keep booting through a packed unsupported filter: %v", err)
			}
			for _, warning := range cfg.Warnings {
				if strings.Contains(warning, "#12090") {
					return
				}
			}
			t.Fatalf("lenient packed filter load must warn with #12090, got %q", cfg.Warnings)
		})
	}
}

func TestApplyGroupInlinePeerOverrideDropTracked12090(t *testing.T) {
	tree := hierTree(t, `groups {
		g { interfaces { ge-0/0/0 { unit 0 filter input f; } } }
	}
	apply-groups g;
	interfaces { ge-0/0/0 { unit 0 { family inet { address 10.0.0.1/24; } } } }`)
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("the existing inline-peer expansion gap is tracked by #12530: %v", err)
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile through the tracked #12530 gap: %v", err)
	}
	for _, warning := range cfg.Warnings {
		if strings.Contains(warning, "#12090") {
			t.Fatalf("the inline-peer override currently removes the packed tail before #12090: %q", warning)
		}
	}
}

func TestDHCPRelayNamedGroupFilterRejects12090(t *testing.T) {
	for _, keyword := range []string{"filter", "simple-filter"} {
		t.Run(keyword, func(t *testing.T) {
			tree := hierTree(t, `forwarding-options {
				dhcp-relay {
					server-group sg { 10.0.0.1; }
					group lan {
						active-server-group sg;
						interface ge-0/0/0.0;
						`+keyword+` { input f; }
					}
				}
			}`)
			_, err := CompileConfig(tree)
			if err == nil || !strings.Contains(err.Error(), "#12090") {
				t.Fatalf("filter keyword under named relay group must reject with #12090; got %v", err)
			}
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("lenient named relay group must continue booting: %v", err)
			}
			if !strings.Contains(strings.Join(cfg.Warnings, "\n"), "#12090") {
				t.Fatalf("lenient named relay group must warn with #12090; got %q", cfg.Warnings)
			}
		})
	}
}

func TestDHCPRelayBracedFilterGroupNameRemainsAccepted12090(t *testing.T) {
	tree := hierTree(t, `forwarding-options {
		dhcp-relay {
			server-group sg { 10.0.0.1; }
			group { filter { active-server-group sg; interface ge-0/0/0.0; } }
		}
	}`)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("braced group instance named filter must remain accepted: %v", err)
	}
	if cfg.ForwardingOptions.DHCPRelay == nil ||
		cfg.ForwardingOptions.DHCPRelay.Groups["filter"] == nil {
		t.Fatalf("braced group instance name filter was not compiled: %+v", cfg.ForwardingOptions.DHCPRelay)
	}
}

func TestDHCPRelayServerGroupNamedFilterRemainsAccepted12090(t *testing.T) {
	tree := hierTree(t, `forwarding-options {
		dhcp-relay {
			server-group { filter { 10.0.0.1; } }
			group lan { active-server-group filter; interface ge-0/0/0.0; }
		}
	}`)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("Junos-native DHCP relay server-group named filter must be accepted: %v", err)
	}
	lenient, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient load of filter-named DHCP relay group must be accepted: %v", err)
	}
	if strings.Contains(strings.Join(lenient.Warnings, "\n"), "#12090") {
		t.Fatalf("server-group instance name must not produce a false #12090 warning: %v", lenient.Warnings)
	}
	relay := cfg.ForwardingOptions.DHCPRelay
	if relay == nil || relay.ServerGroups["filter"] == nil ||
		len(relay.ServerGroups["filter"].Servers) != 1 ||
		relay.ServerGroups["filter"].Servers[0] != "10.0.0.1" ||
		relay.Groups["lan"] == nil ||
		relay.Groups["lan"].ActiveServerGroup != "filter" {
		t.Fatalf("DHCP relay filter-named server-group was not compiled: %+v", relay)
	}
}

func TestFilterKeywordValuesRemainAccepted12090(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  string
	}{
		{"memberless-range-description", "set interfaces interface-range r description filter"},
		{"memberless-range-unit-description", "set interfaces interface-range r unit 0 description simple-filter"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := CompileConfig(flatTreeFromSets(t, tc.set)); err != nil {
				t.Fatalf("keyword used as a value must remain accepted: %v", err)
			}
		})
	}
	testFilterKeywordValueCases12090(t)
}

func testFilterKeywordValueCases12090(t *testing.T) {
	t.Helper()
	for _, tc := range []struct {
		name string
		set  string
		hier string
	}{
		{
			name: "vlan-member-braced",
			set:  "set interfaces ge-0/0/0 unit 0 family ethernet-switching vlan members filter",
			hier: "interfaces { ge-0/0/0 { unit 0 { family ethernet-switching { vlan { members filter; } } } } }",
		},
		{
			name: "vlan-member-list-braced",
			set:  "set interfaces ge-0/0/0 unit 0 family ethernet-switching vlan members [ filter v20 ]",
			hier: "interfaces { ge-0/0/0 { unit 0 { family ethernet-switching { vlan { members [ filter v20 ]; } } } } }",
		},
		{
			name: "vlan-member-singleton-list",
			set:  "set interfaces ge-0/0/0 unit 0 family ethernet-switching vlan members [ filter ]",
			hier: "interfaces { ge-0/0/0 { unit 0 { family ethernet-switching { vlan { members [ filter ]; } } } } }",
		},
		{
			name: "vlan-member-simple-filter",
			set:  "set interfaces ge-0/0/0 unit 0 family ethernet-switching vlan members simple-filter",
			hier: "interfaces { ge-0/0/0 { unit 0 { family ethernet-switching { vlan { members simple-filter; } } } } }",
		},
		{
			name: "memberless-vlan-members",
			set:  "set interfaces interface-range r vlan members filter",
			hier: "interfaces { interface-range r { vlan { members filter; } } }",
		},
		{
			name: "apply-macro-interface-value",
			set:  "set interfaces ge-0/0/0 apply-macro filter k v",
			hier: "interfaces { ge-0/0/0 { apply-macro filter { k v; } } }",
		},
		{
			name: "apply-macro-unit-value",
			set:  "set interfaces ge-0/0/0 unit 0 apply-macro filter k v",
			hier: "interfaces { ge-0/0/0 { unit 0 { apply-macro filter { k v; } } } }",
		},
		{
			name: "apply-macro-family-value",
			set:  "set interfaces ge-0/0/0 unit 0 family inet apply-macro simple-filter k v",
			hier: "interfaces { ge-0/0/0 { unit 0 { family inet { apply-macro simple-filter { k v; } } } } }",
		},
		{
			name: "apply-groups-except-interface-value",
			set:  "set interfaces ge-0/0/0 apply-groups-except filter",
			hier: "interfaces { ge-0/0/0 { apply-groups-except filter; } }",
		},
		{
			name: "apply-macro-forwarding-value",
			set:  "set forwarding-options apply-macro filter k v",
			hier: "forwarding-options { apply-macro filter { k v; } }",
		},
		{
			name: "apply-groups-except-forwarding-value",
			set:  "set forwarding-options apply-groups-except filter",
			hier: "forwarding-options { apply-groups-except filter; }",
		},
		{
			name: "analyzer-name-filter",
			set:  "set forwarding-options analyzer filter x",
			hier: "forwarding-options { analyzer filter { x; } }",
		},
		{
			name: "memberless-range-apply-macro-value",
			set:  "set interfaces interface-range r apply-macro filter k v",
			hier: "interfaces { interface-range r { apply-macro filter { k v; } } }",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, shape := range []struct {
				name string
				tree *ConfigTree
			}{
				{name: "flat-set", tree: flatTreeFromSets(t, tc.set)},
				{name: "hierarchical", tree: hierTree(t, tc.hier)},
			} {
				t.Run(shape.name, func(t *testing.T) {
					if _, err := CompileConfig(shape.tree); err != nil {
						t.Fatalf("keyword-looking value must remain accepted: %v", err)
					}
					cfg, err := CompileConfigLenient(shape.tree)
					if err != nil {
						t.Fatalf("lenient keyword-looking value must remain loadable: %v", err)
					}
					for _, warning := range cfg.Warnings {
						if strings.Contains(warning, "#12090") {
							t.Fatalf("value must not produce a false #12090 warning: %q", warning)
						}
					}
				})
			}
		})
	}
}
func TestForwardingOptionsFilterLenientWarns12090(t *testing.T) {
	for _, hierarchical := range []bool{false, true} {
		name := "flat-set"
		if hierarchical {
			name = "hierarchical"
		}
		t.Run(name, func(t *testing.T) {
			site := silentFilterSite12090{
				section: "forwarding-options", placement: "family",
				family: "inet", keyword: "filter", direction: "input",
			}
			cfg, err := CompileConfigLenient(silentFilterTree12090(t, site, hierarchical))
			if err != nil {
				t.Fatalf("lenient load must keep booting through an unsupported filter binding: %v", err)
			}
			for _, warning := range cfg.Warnings {
				if strings.Contains(warning, "#12090") &&
					strings.Contains(warning, "filter input") {
					return
				}
			}
			t.Fatalf("lenient load must warn about forwarding-options filter input, got %q", cfg.Warnings)
		})
	}
}
func TestPhysicalFamilyFilterInterfaceRangeShapes12090(t *testing.T) {
	shapes := []struct {
		name string
		tree func(*testing.T) *ConfigTree
	}{
		{
			name: "flat-member",
			tree: func(t *testing.T) *ConfigTree {
				return flatTreeFromSets(t,
					"set interfaces interface-range uplinks member ge-0/0/1",
					"set interfaces interface-range uplinks family inet filter input f")
			},
		},
		{
			name: "hierarchical-member",
			tree: func(t *testing.T) *ConfigTree {
				return hierTree(t, "interfaces { interface-range uplinks { member ge-0/0/1; family inet { filter { input f; } } } }")
			},
		},
		{
			name: "flat-memberless",
			tree: func(t *testing.T) *ConfigTree {
				return flatTreeFromSets(t,
					"set interfaces interface-range uplinks family inet filter input f")
			},
		},
		{
			name: "hierarchical-memberless",
			tree: func(t *testing.T) *ConfigTree {
				return hierTree(t, "interfaces { interface-range uplinks { family inet { filter { input f; } } } }")
			},
		},
	}
	for _, shape := range shapes {
		t.Run(shape.name, func(t *testing.T) {
			_, err := CompileConfig(shape.tree(t))
			if err == nil || !strings.Contains(err.Error(), "filter input") ||
				!strings.Contains(err.Error(), "#12090") {
				t.Fatalf("physical family filter must be rejected with #12090; got %v", err)
			}

			cfg, err := CompileConfigLenient(shape.tree(t))
			if err != nil {
				t.Fatalf("lenient load must keep booting through an unsupported range filter: %v", err)
			}
			for _, warning := range cfg.Warnings {
				if strings.Contains(warning, "#12090") && strings.Contains(warning, "filter input") {
					if strings.Contains(shape.name, "member") && !strings.Contains(shape.name, "memberless") {
						ifc := cfg.Interfaces.Interfaces["ge-0/0/1"]
						if ifc == nil || len(ifc.Units) != 0 {
							t.Fatalf("physical range filter should not synthesize units; got %#v", ifc)
						}
					}
					return
				}
			}
			t.Fatalf("lenient load must warn about physical family filter, got %q", cfg.Warnings)
		})
	}
}

func TestMemberlessRangeKeepsSupportedUnitFilter12090(t *testing.T) {
	shapes := []struct {
		name string
		tree func(*testing.T) *ConfigTree
	}{
		{
			name: "flat-set",
			tree: func(t *testing.T) *ConfigTree {
				return flatTreeFromSets(t,
					"set interfaces interface-range uplinks unit 0 family inet filter input f")
			},
		},
		{
			name: "hierarchical",
			tree: func(t *testing.T) *ConfigTree {
				return hierTree(t, "interfaces { interface-range uplinks { unit 0 { family inet { filter { input f; } } } } }")
			},
		},
	}
	for _, shape := range shapes {
		t.Run(shape.name, func(t *testing.T) {
			if _, err := CompileConfig(shape.tree(t)); err != nil {
				t.Fatalf("memberless range with supported unit-family filter must remain accepted: %v", err)
			}
		})
	}
}

func TestForwardingOptionsFamilyNodePackedFilterKeys12090(t *testing.T) {
	nodes := []*Node{{
		Keys: []string{"forwarding-options"},
		Children: []*Node{{
			Keys: []string{"family", "mpls", "filter", "input", "f"},
		}},
	}}
	_, err := validateUnsupportedForwardingOptionsFiltersAST(nodes, false)
	if err == nil || !strings.Contains(err.Error(), "filter input") ||
		!strings.Contains(err.Error(), "#12090") {
		t.Fatalf("packed family-node filter keys must be rejected with #12090; got %v", err)
	}
}

func TestSplitFamilyPackedFilterConsumerRemainsAccepted12090(t *testing.T) {
	nodes := []*Node{{
		Keys: []string{"interfaces"},
		Children: []*Node{{
			Keys: []string{"ge-0/0/0"},
			Children: []*Node{{
				Keys: []string{"unit", "0"},
				Children: []*Node{{
					Keys:     []string{"family"},
					Children: []*Node{{Keys: []string{"inet", "filter", "input", "f"}, IsLeaf: true}},
				}},
			}},
		}},
	}}
	if _, err := validateUnsupportedInterfaceStanzasAST(nodes, false); err != nil {
		t.Fatalf("packed filter under the inet child of a bare family is the supported split-family consumer: %v", err)
	}
}

func TestNonAFChildOfBareFamilyIsNotInspectedAsPackedHead12090(t *testing.T) {
	nodes := []*Node{{
		Keys: []string{"interfaces"},
		Children: []*Node{{
			Keys: []string{"ge-0/0/0"},
			Children: []*Node{{
				Keys: []string{"unit", "0"},
				Children: []*Node{{
					Keys:     []string{"family"},
					Children: []*Node{{Keys: []string{"description", "filter"}, IsLeaf: true}},
				}},
			}},
		}},
	}}
	if _, err := validateUnsupportedInterfaceStanzasAST(nodes, false); err != nil {
		t.Fatalf("a non-AF value under bare family must not be scanned as a packed keyword: %v", err)
	}
}
func TestNonInetFamilyWithoutFilterRemainsAccepted12090(t *testing.T) {
	for _, family := range []string{"mpls", "ccc"} {
		t.Run(family, func(t *testing.T) {
			for _, set := range []string{
				fmt.Sprintf("set interfaces ge-0/0/0 unit 0 family %s", family),
				fmt.Sprintf("set forwarding-options family %s", family),
			} {
				if _, err := CompileConfig(flatTreeFromSets(t, set)); err != nil {
					t.Errorf("bare non-inet family %q must remain accepted: %v", set, err)
				}
			}
		})
	}
}

func TestFilterWordAsFamilyValueDoesNotTrigger12090(t *testing.T) {
	if _, err := CompileConfig(flatTreeFromSets(t,
		"set interfaces ge-0/0/0 unit 0 family inet unnumbered-address filter")); err != nil {
		t.Fatalf("family child value `filter` is not a filter keyword and must remain accepted: %v", err)
	}
}

func TestNonInetFamilyFilterInterfaceRangeMember12090(t *testing.T) {
	for _, site := range []struct {
		name      string
		family    string
		keyword   string
		direction string
	}{
		{name: "mpls-filter", family: "mpls", keyword: "filter", direction: "input"},
		{name: "ccc-simple-filter", family: "ccc", keyword: "simple-filter", direction: "output"},
	} {
		t.Run(site.name, func(t *testing.T) {
			tree := flatTreeFromSets(t,
				"set interfaces interface-range uplinks member ge-0/0/1",
				fmt.Sprintf("set interfaces interface-range uplinks unit 0 family %s %s %s f",
					site.family, site.keyword, site.direction))
			_, err := CompileConfig(tree)
			if err == nil || !strings.Contains(err.Error(), site.keyword+" "+site.direction) ||
				!strings.Contains(err.Error(), "#12090") {
				t.Fatalf("range member non-inet filter must be rejected with #12090; got %v", err)
			}
		})
	}
}
