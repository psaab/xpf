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
	for _, family := range []string{"inet", "inet6"} {
		add("interfaces", "family", family, true)
	}
	add("forwarding-options", "root", "", false)
	for _, family := range []string{"inet", "inet6"} {
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
