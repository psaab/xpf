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
