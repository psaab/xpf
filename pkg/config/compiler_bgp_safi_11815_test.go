package config

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestBGPFamilySAFI11815StrictRejectsLabeledUnicast(t *testing.T) {
	for _, tc := range []struct {
		name string
		sets []string
	}{
		{
			name: "group inet",
			sets: []string{
				"set protocols bgp local-as 65001",
				"set protocols bgp group external peer-as 65002",
				"set protocols bgp group external family inet labeled-unicast",
				"set protocols bgp group external neighbor 192.0.2.1",
			},
		},
		{
			name: "group inet6",
			sets: []string{
				"set protocols bgp local-as 65001",
				"set protocols bgp group external peer-as 65002",
				"set protocols bgp group external family inet6 labeled-unicast",
				"set protocols bgp group external neighbor 2001:db8::1",
			},
		},
		{
			name: "neighbor override",
			sets: []string{
				"set protocols bgp local-as 65001",
				"set protocols bgp group external peer-as 65002",
				"set protocols bgp group external neighbor 192.0.2.1 family inet labeled-unicast",
			},
		},
		{
			name: "routing-instance group",
			sets: []string{
				"set routing-instances VRF-A instance-type virtual-router",
				"set routing-instances VRF-A protocols bgp local-as 65001",
				"set routing-instances VRF-A protocols bgp group external peer-as 65002",
				"set routing-instances VRF-A protocols bgp group external family inet labeled-unicast",
				"set routing-instances VRF-A protocols bgp group external neighbor 192.0.2.1",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(buildTree(t, tc.sets))
			if err == nil {
				t.Fatal("strict compilation accepted labeled-unicast as unicast")
			}
			if !strings.Contains(err.Error(), "labeled-unicast") || !strings.Contains(err.Error(), "#11815") {
				t.Fatalf("diagnostic %q does not name unsupported SAFI and issue", err)
			}
		})
	}
}

func TestBGPFamilySAFI11815UnicastAndBareFamilyRemainSupported(t *testing.T) {
	for _, tc := range []struct {
		name string
		safi string
	}{
		{name: "explicit unicast", safi: " unicast"},
		{name: "Junos bare-family unicast default", safi: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CompileConfig(buildTree(t, []string{
				"set protocols bgp local-as 65001",
				"set protocols bgp group external peer-as 65002",
				"set protocols bgp group external family inet" + tc.safi,
				"set protocols bgp group external neighbor 192.0.2.1",
			}))
			if err != nil {
				t.Fatalf("compile supported family: %v", err)
			}
			if cfg.Protocols.BGP == nil || len(cfg.Protocols.BGP.Neighbors) != 1 {
				t.Fatalf("compiled BGP neighbor missing: %+v", cfg.Protocols.BGP)
			}
			n := cfg.Protocols.BGP.Neighbors[0]
			if !n.FamilyInet || n.UnsupportedInetSAFI {
				t.Fatalf("family inet state = unicast %v, unsupported %v; want unicast only", n.FamilyInet, n.UnsupportedInetSAFI)
			}
		})
	}
}

func TestBGPFamilySAFI11815LenientLabeledUnicastIsNotUnicast(t *testing.T) {
	cfg, err := CompileConfigLenient(buildTree(t, []string{
		"set protocols bgp local-as 65001",
		"set protocols bgp group external peer-as 65002",
		"set protocols bgp group external family inet labeled-unicast",
		"set protocols bgp group external loops 2",
		"set protocols bgp group external neighbor 192.0.2.1",
	}))
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}
	if cfg.Protocols.BGP == nil || len(cfg.Protocols.BGP.Neighbors) != 1 {
		t.Fatalf("compiled BGP neighbor missing: %+v", cfg.Protocols.BGP)
	}
	n := cfg.Protocols.BGP.Neighbors[0]
	if n.FamilyInet || !n.UnsupportedInetSAFI {
		t.Fatalf("labeled-unicast compiled as inet=%v unsupported=%v, want inet=false unsupported=true", n.FamilyInet, n.UnsupportedInetSAFI)
	}
	warnings := bgpSAFIWarnings11815(cfg)
	if len(warnings) != 1 || !strings.Contains(warnings[0], "labeled-unicast") {
		t.Fatalf("SAFI warning = %v, want one labeled-unicast warning", warnings)
	}
	wire, err := json.Marshal(n)
	if err != nil {
		t.Fatalf("marshal compiled neighbor: %v", err)
	}
	if strings.Contains(string(wire), "UnsupportedInet") {
		t.Fatalf("compiler-only SAFI evidence leaked on wire: %s", wire)
	}
}

func TestBGPFamilySAFI11815LenientUnionRetainsSupportedUnicast(t *testing.T) {
	cfg, err := CompileConfigLenient(buildTree(t, []string{
		"set protocols bgp local-as 65001",
		"set protocols bgp group external peer-as 65002",
		"set protocols bgp group external family inet unicast",
		"set protocols bgp group external family inet labeled-unicast",
		"set protocols bgp group external neighbor 192.0.2.1",
	}))
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}
	n := cfg.Protocols.BGP.Neighbors[0]
	if !n.FamilyInet || !n.UnsupportedInetSAFI {
		t.Fatalf("mixed SAFIs lost a supported/unhandled family: inet=%v unsupported=%v", n.FamilyInet, n.UnsupportedInetSAFI)
	}
	warnings := bgpSAFIWarnings11815(cfg)
	if len(warnings) != 1 ||
		!strings.Contains(warnings[0], "labeled-unicast") ||
		!strings.Contains(warnings[0], "skipped") ||
		!strings.Contains(warnings[0], "unicast remains activated") ||
		strings.Contains(warnings[0], "this family is not activated") {
		t.Fatalf("mixed SAFI warning = %v, want unsupported SAFI skipped with unicast still activated", warnings)
	}
}

func TestBGPFamilySAFI11815LenientHierarchicalOneLinerWarns(t *testing.T) {
	tree := hierTree(t, `protocols {
    bgp {
        local-as 65001;
        group external {
            peer-as 65002;
            family inet labeled-unicast;
            neighbor 192.0.2.1;
        }
    }
}`)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}
	if cfg.Protocols.BGP == nil || len(cfg.Protocols.BGP.Neighbors) != 1 {
		t.Fatalf("compiled BGP neighbor missing: %+v", cfg.Protocols.BGP)
	}
	n := cfg.Protocols.BGP.Neighbors[0]
	if n.FamilyInet || !n.UnsupportedInetSAFI {
		t.Fatalf("packed labeled-unicast compiled as inet=%v unsupported=%v, want inert", n.FamilyInet, n.UnsupportedInetSAFI)
	}
	warnings := bgpSAFIWarnings11815(cfg)
	if len(warnings) != 1 ||
		!strings.Contains(warnings[0], "labeled-unicast") ||
		!strings.Contains(warnings[0], "this family is not activated") {
		t.Fatalf("packed hierarchical SAFI warnings = %v, want one inactive labeled-unicast diagnostic", warnings)
	}
}

func bgpSAFIWarnings11815(cfg *Config) []string {
	var warnings []string
	for _, warning := range cfg.Warnings {
		if strings.Contains(warning, "#11815") {
			warnings = append(warnings, warning)
		}
	}
	return warnings
}

func TestBGPFamilySAFI11815SplitHierarchicalShapeRejects(t *testing.T) {
	tree := hierTree(t, `protocols {
    bgp {
        local-as 65001;
        group external {
            peer-as 65002;
            family {
                inet {
                    labeled-unicast;
                }
            }
            neighbor 192.0.2.1;
        }
    }
}`)
	_, err := CompileConfig(tree)
	if err == nil || !strings.Contains(err.Error(), "labeled-unicast") {
		t.Fatalf("split hierarchical SAFI was not rejected with a named diagnostic: %v", err)
	}
}

func TestBGPFamilySAFI12112LenientNamesEveryUnsupportedSAFI(t *testing.T) {
	tests := []struct {
		name        string
		tree        *ConfigTree
		unsupported []string
	}{
		{
			name: "flat siblings",
			tree: buildTree(t, []string{
				"set protocols bgp local-as 65001",
				"set protocols bgp group external peer-as 65002",
				"set protocols bgp group external family inet labeled-unicast",
				"set protocols bgp group external family inet bogus-safi",
				"set protocols bgp group external neighbor 192.0.2.1",
			}),
			unsupported: []string{"labeled-unicast", "bogus-safi"},
		},
		{
			name: "hierarchical children",
			tree: hierTree(t, `protocols {
    bgp {
        local-as 65001;
        group external {
            peer-as 65002;
            family {
                inet {
                    labeled-unicast;
                    bogus-leaf;
                }
            }
            neighbor 192.0.2.1;
        }
    }
}`),
			unsupported: []string{"labeled-unicast", "bogus-leaf"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CompileConfigLenient(tc.tree)
			if err != nil {
				t.Fatalf("lenient compile: %v", err)
			}
			warnings := bgpSAFIWarnings11815(cfg)
			joined := strings.Join(warnings, "\n")
			if len(warnings) != len(tc.unsupported) {
				t.Fatalf("SAFI warnings = %v, want one per unsupported SAFI", warnings)
			}
			for _, name := range tc.unsupported {
				if !strings.Contains(joined, name) {
					t.Errorf("SAFI warnings = %v, missing %q", warnings, name)
				}
			}
		})
	}
}

func TestBGPFamilySAFI12112LenientWordingUsesMergedActivation(t *testing.T) {
	tests := []struct {
		name string
		tree *ConfigTree
	}{
		{
			name: "group sibling activation",
			tree: hierTree(t, `protocols {
    bgp {
        local-as 65001;
        group external {
            peer-as 65002;
            family inet labeled-unicast;
            family inet unicast;
            neighbor 192.0.2.1;
        }
    }
}`),
		},
		{
			name: "inherited group activation",
			tree: buildTree(t, []string{
				"set protocols bgp local-as 65001",
				"set protocols bgp group external peer-as 65002",
				"set protocols bgp group external family inet unicast",
				"set protocols bgp group external neighbor 192.0.2.1 family inet labeled-unicast",
			}),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CompileConfigLenient(tc.tree)
			if err != nil {
				t.Fatalf("lenient compile: %v", err)
			}
			if cfg.Protocols.BGP == nil || len(cfg.Protocols.BGP.Neighbors) != 1 ||
				!cfg.Protocols.BGP.Neighbors[0].FamilyInet {
				t.Fatalf("merged group/neighbor activation missing: %+v", cfg.Protocols.BGP)
			}
			warnings := bgpSAFIWarnings11815(cfg)
			if len(warnings) == 0 {
				t.Fatal("missing unsupported-SAFI warning")
			}
			for _, warning := range warnings {
				if !strings.Contains(warning, "unicast remains activated in the merged configuration") ||
					strings.Contains(warning, "this family is not activated") {
					t.Fatalf("warning does not reflect merged unicast activation: %q", warning)
				}
			}
		})
	}
}

func TestBGPFamilySAFI12112StrictMixedFamilyStatesRejection(t *testing.T) {
	_, err := CompileConfig(buildTree(t, []string{
		"set protocols bgp local-as 65001",
		"set protocols bgp group external peer-as 65002",
		"set protocols bgp group external family inet unicast",
		"set protocols bgp group external family inet labeled-unicast",
		"set protocols bgp group external neighbor 192.0.2.1",
	}))
	if err == nil {
		t.Fatal("strict compilation accepted a mixed family with unsupported SAFI")
	}
	if !strings.Contains(err.Error(), "labeled-unicast") ||
		!strings.Contains(err.Error(), "rejected on strict compilation") ||
		strings.Contains(err.Error(), "remains activated") {
		t.Fatalf("strict mixed-family diagnostic does not state rejection: %q", err)
	}
}

func TestBGPFamilySAFI12112StrictNamesEveryUnsupportedSAFI(t *testing.T) {
	_, err := CompileConfig(buildTree(t, []string{
		"set protocols bgp local-as 65001",
		"set protocols bgp group external peer-as 65002",
		"set protocols bgp group external family inet labeled-unicast",
		"set protocols bgp group external family inet bogus-safi",
		"set protocols bgp group external neighbor 192.0.2.1",
	}))
	if err == nil || !strings.Contains(err.Error(), "labeled-unicast") ||
		!strings.Contains(err.Error(), "bogus-safi") ||
		!strings.Contains(err.Error(), "rejected on strict compilation") {
		t.Fatalf("strict SAFI diagnostic = %v, want all names and rejection", err)
	}
}

func TestBGPFamilySAFI12112LenientWordingAcrossDuplicateGroupBlocks(t *testing.T) {
	const input = `protocols {
    bgp {
        local-as 65001;
        group external {
            peer-as 65002;
            neighbor 192.0.2.1 {
                family inet labeled-unicast;
            }
        }
        group external {
            neighbor 192.0.2.1 {
                family inet unicast;
            }
        }
    }
}`
	tree := hierTree(t, input)
	if _, err := CompileConfig(tree); err == nil || !strings.Contains(err.Error(), "#5180") {
		t.Fatalf("strict compilation did not reject duplicate group blocks: %v", err)
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}
	if cfg.Protocols.BGP == nil || len(cfg.Protocols.BGP.Neighbors) != 1 ||
		!cfg.Protocols.BGP.Neighbors[0].FamilyInet {
		t.Fatalf("duplicate blocks did not merge the neighbor's inet activation: %+v", cfg.Protocols.BGP)
	}
	warnings := bgpSAFIWarnings11815(cfg)
	if len(warnings) != 1 ||
		!strings.Contains(warnings[0], "unicast remains activated in the merged configuration") ||
		strings.Contains(warnings[0], "this family is not activated") {
		t.Fatalf("duplicate-block SAFI warning = %v, want merged inet activation", warnings)
	}
}

func TestBGPFamilySAFI12112LenientWarningMetadataIsNotParsedFromText(t *testing.T) {
	t.Run("SAFI containing diagnostic phrase", func(t *testing.T) {
		cfg, err := CompileConfigLenient(hierTree(t, `protocols {
    bgp {
        local-as 65001;
        group external {
            peer-as 65002;
            family inet "x is unsupported";
            neighbor 192.0.2.1;
        }
    }
}`))
		if err != nil {
			t.Fatalf("lenient compile: %v", err)
		}
		warnings := bgpSAFIWarnings11815(cfg)
		if len(warnings) != 1 ||
			!strings.Contains(warnings[0], `SAFI "x is unsupported" is unsupported;`) {
			t.Fatalf("SAFI warning = %v, want complete quoted SAFI name", warnings)
		}
	})

	t.Run("group name contains another AFI marker", func(t *testing.T) {
		cfg, err := CompileConfigLenient(hierTree(t, `protocols {
    bgp {
        local-as 65001;
        group "ext family inet6:" {
            peer-as 65002;
            family inet labeled-unicast;
            family inet6 unicast;
            neighbor 192.0.2.1;
        }
    }
}`))
		if err != nil {
			t.Fatalf("lenient compile: %v", err)
		}
		if cfg.Protocols.BGP == nil || len(cfg.Protocols.BGP.Neighbors) != 1 ||
			cfg.Protocols.BGP.Neighbors[0].FamilyInet {
			t.Fatalf("contrived group activated neighbor inet: %+v", cfg.Protocols.BGP)
		}
		warnings := bgpSAFIWarnings11815(cfg)
		if len(warnings) != 1 ||
			!strings.Contains(warnings[0], ` family inet: BGP address-family SAFI "labeled-unicast" is unsupported; only unicast is compiled, so this family is not activated`) {
			t.Fatalf("inet SAFI warning = %v, want inactive inet despite the group name", warnings)
		}
	})
}

func TestBGPFamilySAFI12112LenientInet6FinalizationCells(t *testing.T) {
	tests := []struct {
		name       string
		tree       *ConfigTree
		wantInet   bool
		wantInet6  bool
		wantActive bool
	}{
		{
			name: "group sibling inet6 must stay inactive for IPv6 peer",
			tree: hierTree(t, `protocols {
    bgp {
        local-as 65001;
        group external {
            peer-as 65002;
            family inet unicast;
            family inet6 labeled-unicast;
            neighbor 2001:db8::1;
        }
    }
}`),
			wantActive: false,
		},
		{
			name: "W1 neighbor inet6 warning uses inet6 activation",
			tree: hierTree(t, `protocols {
    bgp {
        local-as 65001;
        group external {
            peer-as 65002;
            family inet unicast;
            neighbor 192.0.2.1 {
                family inet6 labeled-unicast;
            }
        }
    }
}`),
			wantInet: true,
		},
		{
			name: "inherited inet6 activation survives neighbor SAFI",
			tree: hierTree(t, `protocols {
    bgp {
        local-as 65001;
        group external {
            peer-as 65002;
            family inet6 unicast;
            neighbor 2001:db8::1 {
                family inet6 labeled-unicast;
            }
        }
    }
}`),
			wantInet6:  true,
			wantActive: true,
		},
		{
			name: "IPv6 peer does not inherit explicit inet unicast",
			tree: hierTree(t, `protocols {
    bgp {
        local-as 65001;
        group external {
            peer-as 65002;
            family inet unicast;
            neighbor 2001:db8::1 {
                family inet labeled-unicast;
            }
        }
    }
}`),
			wantActive: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CompileConfigLenient(tc.tree)
			if err != nil {
				t.Fatalf("lenient compile: %v", err)
			}
			if cfg.Protocols.BGP == nil || len(cfg.Protocols.BGP.Neighbors) != 1 {
				t.Fatalf("compiled neighbor missing: %+v", cfg.Protocols.BGP)
			}
			neighbor := cfg.Protocols.BGP.Neighbors[0]
			if neighbor.FamilyInet != tc.wantInet || neighbor.FamilyInet6 != tc.wantInet6 {
				t.Fatalf("neighbor family inet=%v inet6=%v, want inet=%v inet6=%v",
					neighbor.FamilyInet, neighbor.FamilyInet6, tc.wantInet, tc.wantInet6)
			}
			warnings := bgpSAFIWarnings11815(cfg)
			if len(warnings) != 1 {
				t.Fatalf("SAFI warnings = %v, want exactly one", warnings)
			}
			if active := strings.Contains(warnings[0], "unicast remains activated in the merged configuration"); active != tc.wantActive {
				t.Fatalf("SAFI warning active=%v, want %v: %q", active, tc.wantActive, warnings[0])
			}
			if !tc.wantActive && !strings.Contains(warnings[0], "this family is not activated") {
				t.Fatalf("inactive SAFI warning has wrong wording: %q", warnings[0])
			}
		})
	}
}

func TestBGPFamilySAFI12112StrictSiblingAndInheritedShapesReject(t *testing.T) {
	tests := []struct {
		name string
		tree *ConfigTree
	}{
		{
			name: "sibling families",
			tree: hierTree(t, `protocols {
    bgp {
        local-as 65001;
        group external {
            peer-as 65002;
            family inet labeled-unicast;
            family inet unicast;
            neighbor 2001:db8::1;
        }
    }
}`),
		},
		{
			name: "inherited neighbor family",
			tree: hierTree(t, `protocols {
    bgp {
        local-as 65001;
        group external {
            peer-as 65002;
            family inet6 unicast;
            neighbor 2001:db8::1 {
                family inet6 labeled-unicast;
            }
        }
    }
}`),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(tc.tree)
			if err == nil ||
				!strings.Contains(err.Error(), "labeled-unicast") ||
				!strings.Contains(err.Error(), "rejected on strict compilation") {
				t.Fatalf("strict SAFI diagnostic = %v, want named rejection", err)
			}
		})
	}
}

func TestBGPFamilySAFI12112LenientGroupWarningsStayInTheirGroup(t *testing.T) {
	tree := hierTree(t, `protocols {
    bgp {
        local-as 65001;
        group A {
            peer-as 65002;
            family inet labeled-unicast;
            neighbor 192.0.2.1;
        }
        group B {
            peer-as 65003;
            family inet unicast;
            neighbor 192.0.2.2;
        }
    }
}`)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}
	if cfg.Protocols.BGP == nil || len(cfg.Protocols.BGP.Neighbors) != 2 {
		t.Fatalf("compiled BGP neighbors = %+v, want both groups", cfg.Protocols.BGP)
	}
	neighbors := make(map[string]*BGPNeighbor, len(cfg.Protocols.BGP.Neighbors))
	for _, neighbor := range cfg.Protocols.BGP.Neighbors {
		neighbors[neighbor.Address] = neighbor
	}
	if neighbors["192.0.2.1"] == nil || neighbors["192.0.2.1"].FamilyInet {
		t.Fatalf("group A neighbor activation = %+v, want inet inactive", neighbors["192.0.2.1"])
	}
	if neighbors["192.0.2.2"] == nil || !neighbors["192.0.2.2"].FamilyInet {
		t.Fatalf("group B neighbor activation = %+v, want inet active", neighbors["192.0.2.2"])
	}
	warnings := bgpSAFIWarnings11815(cfg)
	if len(warnings) != 1 ||
		!strings.Contains(warnings[0], `BGP group "A" family inet:`) ||
		!strings.Contains(warnings[0], "this family is not activated") ||
		strings.Contains(warnings[0], "unicast remains activated") {
		t.Fatalf("group A SAFI warning = %v, want its own inactive activation", warnings)
	}
}

func TestBGPFamilySAFI12112DeduplicatesUnsupportedSAFI(t *testing.T) {
	tree := hierTree(t, `protocols {
    bgp {
        local-as 65001;
        group external {
            peer-as 65002;
            family inet {
                labeled-unicast;
                labeled-unicast;
            }
            neighbor 192.0.2.1;
        }
    }
}`)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}
	warnings := bgpSAFIWarnings11815(cfg)
	if len(warnings) != 1 || strings.Count(warnings[0], "labeled-unicast") != 1 {
		t.Fatalf("duplicate SAFI warnings = %v, want one name in one warning", warnings)
	}
	_, err = CompileConfig(tree)
	if err == nil || strings.Count(err.Error(), "labeled-unicast") != 1 {
		t.Fatalf("strict duplicate SAFI error = %v, want one name", err)
	}
}
