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
	return flatTreeFromSets(t, "set "+setPath)
}

func TestFilterKeywordPopulationCannotCommitUnbound12090(t *testing.T) {
	for _, site := range silentFilterSites12090() {
		t.Run(site.name, func(t *testing.T) {
			for _, shape := range []struct {
				name         string
				hierarchical bool
			}{
				{name: "flat-set"},
				{name: "hierarchical", hierarchical: true},
			} {
				t.Run(shape.name, func(t *testing.T) {
					tree := silentFilterTree12090(t, site, shape.hierarchical)
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
