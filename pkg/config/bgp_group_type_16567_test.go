package config

import (
	"strings"
	"testing"
)

// #16567: BGP group `type internal|external` was unmodelled — no schema
// child, no compiler case — so `type internal` without peer-as was
// strict-rejected as "missing peer-as", and a contradicting or typo'd
// type committed with only the generic advisory while FRR followed
// peer-as. These tests drive CompileConfig (strict), CompileConfigLenient
// and SchemaValidate.

func bgpGroupTypeNeighbor16567(t *testing.T, cfg *Config) *BGPNeighbor {
	t.Helper()
	if cfg == nil || cfg.Protocols.BGP == nil || len(cfg.Protocols.BGP.Neighbors) != 1 {
		t.Fatalf("expected exactly one BGP neighbor, got %+v", cfg)
	}
	return cfg.Protocols.BGP.Neighbors[0]
}

// Acceptance row 1: type internal without peer-as commits and derives
// PeerAS from the effective local AS (routing-options autonomous-system).
// FAIL-ON-REVERT: without resolveBGPGroupType16567 the strict peer-as
// gate rejects this config.
func TestBGPGroupTypeInternalNoPeerASDerivesLocalAS16567(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set routing-options autonomous-system 65000",
		"set protocols bgp group ibgp type internal",
		"set protocols bgp group ibgp neighbor 10.0.2.3",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("type internal without peer-as must commit: %v", err)
	}
	n := bgpGroupTypeNeighbor16567(t, cfg)
	if n.PeerAS != 65000 {
		t.Fatalf("PeerAS = %d, want 65000 (derived local AS; renders remote-as 65000)", n.PeerAS)
	}
}

// Same derivation via protocols bgp local-as (not autonomous-system).
func TestBGPGroupTypeInternalLocalASOverride16567(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set routing-options autonomous-system 65000",
		"set protocols bgp local-as 65001",
		"set protocols bgp group ibgp type internal",
		"set protocols bgp group ibgp neighbor 10.0.2.3",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("strict compile: %v", err)
	}
	if got := bgpGroupTypeNeighbor16567(t, cfg).PeerAS; got != 65001 {
		t.Fatalf("PeerAS = %d, want 65001 (protocols bgp local-as wins)", got)
	}
}

// Hierarchical spelling of the same acceptance row.
func TestBGPGroupTypeInternalHierarchical16567(t *testing.T) {
	tree, errs := NewParser("routing-options { autonomous-system 65000; }\nprotocols { bgp { group ibgp { type internal; neighbor 10.0.2.3; } } }").Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs[0])
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("hierarchical type internal without peer-as must commit: %v", err)
	}
	if got := bgpGroupTypeNeighbor16567(t, cfg).PeerAS; got != 65000 {
		t.Fatalf("PeerAS = %d, want 65000", got)
	}
}

// Consistent explicit peer-as under type internal is accepted.
func TestBGPGroupTypeInternalMatchingPeerASAccepted16567(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set routing-options autonomous-system 65000",
		"set protocols bgp group ibgp type internal",
		"set protocols bgp group ibgp peer-as 65000",
		"set protocols bgp group ibgp neighbor 10.0.2.3",
	})
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("type internal with peer-as == local AS must commit: %v", err)
	}
}

// Acceptance row 2a: type internal with a foreign peer-as is rejected.
// FAIL-ON-REVERT: without validateBGPGroupTypeStrict this commits.
func TestBGPGroupTypeInternalForeignPeerASRejected16567(t *testing.T) {
	for _, cmds := range [][]string{
		{ // group peer-as
			"set routing-options autonomous-system 65000",
			"set protocols bgp group ibgp type internal",
			"set protocols bgp group ibgp peer-as 65002",
			"set protocols bgp group ibgp neighbor 10.0.2.3",
		},
		{ // per-neighbor peer-as
			"set routing-options autonomous-system 65000",
			"set protocols bgp group ibgp type internal",
			"set protocols bgp group ibgp neighbor 10.0.2.3 peer-as 65002",
		},
	} {
		_, err := CompileConfig(buildTreeFromSet(t, cmds))
		if err == nil {
			t.Fatalf("type internal with foreign peer-as must be rejected: %v", cmds)
		}
		for _, want := range []string{"type internal", "peer-as", "65000"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error %q missing %q", err.Error(), want)
			}
		}
	}
}

// Acceptance row 2b: type external with the own AS is rejected.
func TestBGPGroupTypeExternalOwnASRejected16567(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set routing-options autonomous-system 65000",
		"set protocols bgp group ebgp type external",
		"set protocols bgp group ebgp peer-as 65000",
		"set protocols bgp group ebgp neighbor 10.0.2.3",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("type external with peer-as == local AS must be rejected")
	}
	for _, want := range []string{"type external", "peer-as"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q missing %q", err.Error(), want)
		}
	}
}

// type external with a foreign peer-as is the normal eBGP shape: accepted.
func TestBGPGroupTypeExternalForeignAccepted16567(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set routing-options autonomous-system 65000",
		"set protocols bgp group ebgp type external",
		"set protocols bgp group ebgp peer-as 65002",
		"set protocols bgp group ebgp neighbor 10.0.2.3",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("type external with foreign peer-as must commit: %v", err)
	}
	if got := bgpGroupTypeNeighbor16567(t, cfg).PeerAS; got != 65002 {
		t.Fatalf("PeerAS = %d, want 65002", got)
	}
}

// Acceptance row 3: a typo'd type is rejected — both at SchemaValidate
// (closed enum) and at strict compile (compiler gate, for configs that
// bypass SchemaValidate).
func TestBGPGroupTypeTypoRejected16567(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set routing-options autonomous-system 65000",
		"set protocols bgp group ibgp type internl",
		"set protocols bgp group ibgp neighbor 10.0.2.3",
	})
	if err := SchemaValidate(tree); err == nil {
		t.Fatal("SchemaValidate accepted typo'd group type internl")
	} else if !strings.Contains(err.Error(), "internl") {
		t.Errorf("SchemaValidate error %q should name the bad value", err)
	}
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("CompileConfig accepted typo'd group type internl")
	} else if !strings.Contains(err.Error(), "internl") {
		t.Errorf("CompileConfig error %q should name the bad value", err)
	}
}

// No type at all: unchanged behavior — peer-as still required.
func TestBGPGroupNoTypeStillRequiresPeerAS16567(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set routing-options autonomous-system 65000",
		"set protocols bgp group g neighbor 10.0.2.3",
	})
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("neighbor without type or peer-as must still be rejected")
	}
}

// Routing-instance scope: derivation and contradiction both fire.
func TestBGPGroupTypeRoutingInstance16567(t *testing.T) {
	okTree := buildTreeFromSet(t, []string{
		"set routing-options autonomous-system 65000",
		"set routing-instances VR1 instance-type virtual-router",
		"set routing-instances VR1 protocols bgp group ibgp type internal",
		"set routing-instances VR1 protocols bgp group ibgp neighbor 10.0.2.3",
	})
	cfg, err := CompileConfig(okTree)
	if err != nil {
		t.Fatalf("RI type internal without peer-as must commit: %v", err)
	}
	var ri *RoutingInstanceConfig
	for _, r := range cfg.RoutingInstances {
		if r.Name == "VR1" {
			ri = r
		}
	}
	if ri == nil || ri.BGP == nil || len(ri.BGP.Neighbors) != 1 {
		t.Fatalf("RI BGP neighbor missing: %+v", cfg.RoutingInstances)
	}
	if got := ri.BGP.Neighbors[0].PeerAS; got != 65000 {
		t.Fatalf("RI PeerAS = %d, want 65000", got)
	}

	badTree := buildTreeFromSet(t, []string{
		"set routing-options autonomous-system 65000",
		"set routing-instances VR1 instance-type virtual-router",
		"set routing-instances VR1 protocols bgp group ebgp type external",
		"set routing-instances VR1 protocols bgp group ebgp peer-as 65000",
		"set routing-instances VR1 protocols bgp group ebgp neighbor 10.0.2.3",
	})
	if _, err := CompileConfig(badTree); err == nil {
		t.Fatal("RI type external with own AS must be rejected")
	}
}

// Per-neighbor local-as is the effective local AS for the cross-check:
// internal with peer-as == neighbor local-as is consistent even when it
// differs from the router AS.
func TestBGPGroupTypeInternalNeighborLocalAS16567(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set routing-options autonomous-system 65000",
		"set protocols bgp group ibgp type internal",
		"set protocols bgp group ibgp neighbor 10.0.2.3 local-as 65001 peer-as 65001",
	})
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("type internal with peer-as == neighbor local-as must commit: %v", err)
	}
}

// Lenient path: a persisted contradiction warns, does not brick boot.
func TestBGPGroupTypeContradictionLenientWarns16567(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set routing-options autonomous-system 65000",
		"set protocols bgp group ibgp type internal",
		"set protocols bgp group ibgp peer-as 65002",
		"set protocols bgp group ibgp neighbor 10.0.2.3",
	})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile must boot a persisted contradiction: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "type internal") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a group-type warning, got %v", cfg.Warnings)
	}
}

// The compiler must validate the statement itself, including empty groups.
// A peer-only validator misses these; schema validation is a separate gate.
func TestBGPGroupTypeInvalidStatement16567(t *testing.T) {
	for _, scope := range []string{"global", "instance"} {
		for _, statement := range []string{
			"type;", `type "";`, "type internl;", "type INTERNAL;",
			"type [ internal external ];", "type internal garbage;",
		} {
			for _, neighbor := range []string{"", "neighbor 10.0.2.3;"} {
				t.Run(scope+"/"+statement+"/"+neighbor, func(t *testing.T) {
					body := "protocols { bgp { local-as 65000; group G { peer-as 65001; " + statement + neighbor + " } } }"
					if scope == "instance" {
						body = "routing-instances { VR1 { instance-type virtual-router; " + body + " } }"
					}
					parse := func() *ConfigTree {
						tree, errs := NewParser(body).Parse()
						if len(errs) != 0 {
							t.Fatalf("parse: %v", errs)
						}
						return tree
					}
					if _, err := CompileConfig(parse()); err == nil || !strings.Contains(err.Error(), "type") {
						t.Fatalf("strict must reject invalid type even with no neighbors: %v", err)
					}
					cfg, err := CompileConfigLenient(parse())
					if err != nil {
						t.Fatalf("lenient compile: %v", err)
					}
					if !strings.Contains(strings.Join(cfg.Warnings, "\n"), "type") {
						t.Fatalf("missing type warning: %v", cfg.Warnings)
					}
				})
			}
		}
	}
}

func TestBGPGroupTypeEmptyValidGroup16567(t *testing.T) {
	for _, typ := range []string{"internal", "external"} {
		t.Run(typ, func(t *testing.T) {
			tree := buildTreeFromSet(t, []string{
				"set routing-options autonomous-system 65000",
				"set protocols bgp group empty type " + typ,
			})
			if err := SchemaValidate(tree); err != nil {
				t.Fatalf("schema rejected valid empty group: %v", err)
			}
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("compile rejected valid empty group: %v", err)
			}
			if cfg.Protocols.BGP == nil || len(cfg.Protocols.BGP.Neighbors) != 0 {
				t.Fatalf("empty group must not create a peer: %+v", cfg.Protocols.BGP)
			}
		})
	}
}

func TestBGPGroupTypeDerivationAfterOverrides16567(t *testing.T) {
	for _, tc := range []struct {
		name string
		cmds []string
		want uint32
	}{
		{"group local AS", []string{"neighbor 10.0.2.3", "type internal", "local-as 65001"}, 65001},
		{"neighbor overrides group", []string{"neighbor 10.0.2.3", "type internal", "local-as 65001", "neighbor 10.0.2.3 local-as 65002"}, 65002},
		{"packed type before peer", []string{"type internal neighbor 10.0.2.3"}, 65000},
		{"explicit matching peer", []string{"type internal", "peer-as 65001", "local-as 65001", "neighbor 10.0.2.3"}, 65001},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmds := []string{"set routing-options autonomous-system 65000"}
			for _, cmd := range tc.cmds {
				cmds = append(cmds, "set protocols bgp group G "+cmd)
			}
			for _, lenient := range []bool{false, true} {
				tree := buildTreeFromSet(t, cmds)
				compile := CompileConfig
				if lenient {
					compile = CompileConfigLenient
				}
				cfg, err := compile(tree)
				if err != nil {
					t.Fatalf("lenient=%v: %v", lenient, err)
				}
				if got := bgpGroupTypeNeighbor16567(t, cfg).PeerAS; got != tc.want {
					t.Fatalf("lenient=%v: peer-as=%d, want %d", lenient, got, tc.want)
				}
			}
		})
	}
}

func TestBGPGroupTypeDoesNotRepairInvalidPeerAS16567(t *testing.T) {
	for _, scope := range []string{"", "neighbor 10.0.2.3 "} {
		for _, value := range []string{"0", "-1", "4294967296", "invalid"} {
			t.Run(scope+value, func(t *testing.T) {
				tree := buildTreeFromSet(t, []string{
					"set routing-options autonomous-system 65000",
					"set protocols bgp group G type internal",
					"set protocols bgp group G neighbor 10.0.2.3",
					"set protocols bgp group G " + scope + "peer-as " + value,
				})
				if _, err := CompileConfig(tree); err == nil {
					t.Fatal("an authored invalid peer-as must not be defaulted")
				}
				cfg, err := CompileConfigLenient(tree)
				if err != nil {
					t.Fatalf("lenient: %v", err)
				}
				if got := bgpGroupTypeNeighbor16567(t, cfg).PeerAS; got != 0 {
					t.Fatalf("invalid peer-as became %d, want zero (not rendered)", got)
				}
			})
		}
	}
}

func TestBGPGroupTypeEffectiveLocalASContradictions16567(t *testing.T) {
	for _, tc := range []struct{ typ, peerAS string }{
		{"internal", "65000"}, {"external", "65002"},
	} {
		t.Run(tc.typ, func(t *testing.T) {
			tree := buildTreeFromSet(t, []string{
				"set routing-options autonomous-system 65000",
				"set protocols bgp group G type " + tc.typ,
				"set protocols bgp group G local-as 65001",
				"set protocols bgp group G neighbor 10.0.2.3 local-as 65002",
				"set protocols bgp group G neighbor 10.0.2.3 peer-as " + tc.peerAS,
			})
			if _, err := CompileConfig(tree); err == nil || !strings.Contains(err.Error(), "type "+tc.typ) {
				t.Fatalf("type must be checked against neighbor local-as 65002, not router or group AS: %v", err)
			}
		})
	}
}

func TestBGPGroupTypeInstanceASOverride16567(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set routing-options autonomous-system 65000",
		"set routing-instances VR1 instance-type virtual-router",
		"set routing-instances VR1 routing-options autonomous-system 65010",
		"set routing-instances VR1 protocols bgp group G type internal",
		"set routing-instances VR1 protocols bgp group G neighbor 2001:db8::1",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.RoutingInstances) != 1 || cfg.RoutingInstances[0].BGP == nil ||
		len(cfg.RoutingInstances[0].BGP.Neighbors) != 1 ||
		cfg.RoutingInstances[0].BGP.Neighbors[0].PeerAS != 65010 {
		t.Fatalf("expected the instance's AS, not the global AS: %+v", cfg.RoutingInstances)
	}
}

func TestBGPGroupTypeApplyGroups16567(t *testing.T) {
	tree, errs := NewParser(`
groups { defaults { protocols { bgp { group <*> { type internal; } } } } }
apply-groups defaults;
routing-options { autonomous-system 65000; }
protocols { bgp { group G { neighbor 10.0.2.3; } } }
`).Parse()
	if len(errs) != 0 {
		t.Fatal(errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}
	if got := bgpGroupTypeNeighbor16567(t, cfg).PeerAS; got != 65000 {
		t.Fatalf("inherited type internal did not derive peer-as: got %d", got)
	}
}
