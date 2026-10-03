package config

import (
	"fmt"
	"strings"
	"testing"
)

func bgpLoopsTree11795(t *testing.T, scope, value string) *ConfigTree {
	t.Helper()
	base := []string{
		"set protocols bgp local-as 65001",
		"set protocols bgp group G peer-as 65002",
	}
	if scope == "group" {
		base = append(base,
			"set protocols bgp group G loops "+value,
			"set protocols bgp group G neighbor 192.0.2.1")
	} else {
		base = append(base,
			"set protocols bgp group G neighbor 192.0.2.1 loops "+value)
	}
	return flatTreeFromSets(t, base...)
}

func bgpLoopsHierarchical11795(t *testing.T, scope, value string) *ConfigTree {
	t.Helper()
	leaf := fmt.Sprintf("loops %s;", value)
	if scope == "group" {
		leaf += " neighbor 192.0.2.1;"
	} else {
		leaf = fmt.Sprintf("neighbor 192.0.2.1 { loops %s; }", value)
	}
	src := "protocols { bgp { local-as 65001; group G { peer-as 65002; " + leaf + " } } }"
	tree, errs := NewParser(src).Parse()
	if len(errs) != 0 {
		t.Fatalf("parse hierarchical BGP loops fixture: %v", errs)
	}
	return tree
}

// Both BGP group `loops` and neighbor `loops` feed FRR's allowas-in integer
// argument. Their schemas were bare args:1 leaves, so garbage/negative/zero
// silently disabled the control and a large value rendered as an invalid FRR
// command. Junos `loops` and FRR `allowas-in` both accept 1..10.
func TestBGPLoopsSchemaGate11795(t *testing.T) {
	bad := []string{"banana", "default", "0", "-1", "11", "99999999999999999999"}
	for _, scope := range []string{"group", "neighbor"} {
		for _, tok := range bad {
			t.Run(scope+"/reject-"+tok, func(t *testing.T) {
				for _, tree := range []*ConfigTree{
					bgpLoopsTree11795(t, scope, tok),
					bgpLoopsHierarchical11795(t, scope, tok),
				} {
					if err := SchemaValidate(tree, nil); err == nil {
						t.Fatalf("SchemaValidate accepted %s loops %q; want commit rejection", scope, tok)
					} else if !strings.Contains(err.Error(), "loops") {
						t.Fatalf("%s loops rejection must name the leaf: %v", scope, err)
					}
				}
			})
		}
		for _, tok := range []string{"1", "3", "10"} {
			t.Run(scope+"/accept-"+tok, func(t *testing.T) {
				if err := SchemaValidate(bgpLoopsTree11795(t, scope, tok), nil); err != nil {
					t.Fatalf("SchemaValidate rejected valid %s loops %q: %v", scope, tok, err)
				}
			})
		}
	}
}

// Direct compiler callers bypass SchemaValidate. Preserve invalid group and
// neighbor values so the compiled strict/tolerant gate can reject or warn
// instead of allowing Atoi failures to become the disabled zero sentinel.
func TestBGPLoopsStrictCompileRejects11795(t *testing.T) {
	for _, scope := range []string{"group", "neighbor"} {
		for _, tok := range []string{"banana", "0", "-1", "11", "99999999999999999999"} {
			t.Run(scope+"/reject-"+tok, func(t *testing.T) {
				_, err := CompileConfig(bgpLoopsTree11795(t, scope, tok))
				if err == nil {
					t.Fatalf("CompileConfig accepted invalid %s loops %q; want strict rejection", scope, tok)
				}
				if !strings.Contains(err.Error(), "loops") || !strings.Contains(err.Error(), "192.0.2.1") {
					t.Fatalf("strict diagnostic must identify loops and the affected neighbor: %v", err)
				}
			})
		}
	}
}

func TestBGPLoopsValidValuesBind11795(t *testing.T) {
	for _, scope := range []string{"group", "neighbor"} {
		for _, tc := range []struct {
			token string
			want  int
		}{{"1", 1}, {"3", 3}, {"10", 10}} {
			t.Run(scope+"/"+tc.token, func(t *testing.T) {
				cfg, err := CompileConfig(bgpLoopsTree11795(t, scope, tc.token))
				if err != nil {
					t.Fatalf("CompileConfig rejected valid %s loops %q: %v", scope, tc.token, err)
				}
				if cfg.Protocols.BGP == nil || len(cfg.Protocols.BGP.Neighbors) == 0 {
					t.Fatalf("expected an effective compiled BGP neighbor, got %+v", cfg.Protocols.BGP)
				}
				if got := cfg.Protocols.BGP.Neighbors[0].AllowASIn; got != tc.want {
					t.Fatalf("AllowASIn = %d, want %d", got, tc.want)
				}
			})
		}
	}
}

func TestBGPLoopsLenientCompileWarns11795(t *testing.T) {
	for _, scope := range []string{"group", "neighbor"} {
		for _, value := range []string{"banana", "0", "999999"} {
			t.Run(scope+"/"+value, func(t *testing.T) {
				cfg, err := CompileConfigLenient(bgpLoopsTree11795(t, scope, value))
				if err != nil {
					t.Fatalf("CompileConfigLenient rejected legacy %s loops %q (want warning): %v", scope, value, err)
				}
				found := false
				for _, warning := range cfg.Warnings {
					if strings.Contains(warning, "loops") && strings.Contains(warning, "192.0.2.1") {
						found = true
						break
					}
				}
				if !found {
					t.Fatalf("lenient compile produced no loops warning naming the neighbor: %v", cfg.Warnings)
				}
			})
		}
	}
}

func bgpLoopsRoutingInstanceTree11795(t *testing.T, value string) *ConfigTree {
	t.Helper()
	return flatTreeFromSets(t,
		"set routing-instances VR1 instance-type virtual-router",
		"set routing-instances VR1 protocols bgp local-as 65010",
		"set routing-instances VR1 protocols bgp group G peer-as 65011",
		"set routing-instances VR1 protocols bgp group G neighbor 192.0.2.1 loops "+value,
	)
}

func TestBGPLoopsRoutingInstanceGate11795(t *testing.T) {
	invalid := bgpLoopsRoutingInstanceTree11795(t, "11")
	if err := SchemaValidate(invalid, nil); err == nil || !strings.Contains(err.Error(), "loops") {
		t.Fatalf("routing-instance schema accepted loops 11 or omitted leaf diagnostic: %v", err)
	}
	if _, err := CompileConfig(invalid); err == nil {
		t.Fatal("CompileConfig accepted routing-instance loops 11")
	} else {
		for _, want := range []string{"routing-instance", "VR1", "192.0.2.1", "loops"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("routing-instance loops error %q missing %q", err, want)
			}
		}
	}
	cfg, err := CompileConfig(bgpLoopsRoutingInstanceTree11795(t, "10"))
	if err != nil {
		t.Fatalf("CompileConfig rejected valid routing-instance loops 10: %v", err)
	}
	if len(cfg.RoutingInstances) != 1 || cfg.RoutingInstances[0] == nil ||
		cfg.RoutingInstances[0].BGP == nil || len(cfg.RoutingInstances[0].BGP.Neighbors) != 1 {
		t.Fatalf("expected one compiled BGP neighbor in VR1, got %+v", cfg.RoutingInstances)
	}
	if got := cfg.RoutingInstances[0].BGP.Neighbors[0].AllowASIn; got != 10 {
		t.Fatalf("routing-instance AllowASIn = %d, want 10", got)
	}
}
