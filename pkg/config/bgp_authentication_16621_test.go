package config

import (
	"strings"
	"testing"
)

// #16621: BGP authentication spellings xpf cannot render committed with
// only the generic #10707 advisory and the peer rendered without
// TCP-MD5. Acceptance: each probe row either renders
// `neighbor 10.0.0.2 password ...` or is strict-rejected naming the
// statement; control rows unchanged.
//
// Fix: top-level `authentication-key` is implemented with Junos
// inheritance (neighbor > group > bgp); `authentication-key-chain` and
// `authentication-algorithm` are refusal stubs at bgp/group/neighbor
// level in both the default instance and routing instances, with a
// specific warning on the tolerant path.

func bgpAuthTree16621(t *testing.T, lines ...string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	for _, l := range lines {
		p, err := ParseSetCommand(l)
		if err != nil {
			t.Fatalf("parse %q: %v", l, err)
		}
		if err := tree.SetPath(p); err != nil {
			t.Fatalf("setpath %q: %v", l, err)
		}
	}
	return tree
}

func bgpAuthHier16621(t *testing.T, src string) *ConfigTree {
	t.Helper()
	tree, perrs := NewParser(src).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	return tree
}

func bgpNeighbors16621(t *testing.T, tree *ConfigTree) []*BGPNeighbor {
	t.Helper()
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("strict compile: %v", err)
	}
	if cfg.Protocols.BGP == nil {
		t.Fatal("no BGP compiled")
	}
	return cfg.Protocols.BGP.Neighbors
}

func bgpAuthKey16621(t *testing.T, ns []*BGPNeighbor, addr string) string {
	t.Helper()
	for _, n := range ns {
		if n.Address == addr {
			return n.AuthPassword.Reveal()
		}
	}
	t.Fatalf("neighbor %s not compiled: %+v", addr, ns)
	return ""
}

// --- Top-level inheritance (implemented half) ---

func TestBGPTopLevelAuthKeyInherited16621(t *testing.T) {
	ns := bgpNeighbors16621(t, bgpAuthTree16621(t,
		"set protocols bgp local-as 65001",
		"set protocols bgp authentication-key topsecret",
		"set protocols bgp group G peer-as 65002",
		"set protocols bgp group G neighbor 10.0.0.2",
	))
	if got := bgpAuthKey16621(t, ns, "10.0.0.2"); got != "topsecret" {
		t.Errorf("top-level key: AuthPassword = %q, want %q (inherited)", got, "topsecret")
	}
}

func TestBGPTopLevelAuthKeyHierarchical16621(t *testing.T) {
	ns := bgpNeighbors16621(t, bgpAuthHier16621(t,
		`protocols { bgp { local-as 65001; authentication-key topsecret; group G { peer-as 65002; neighbor 10.0.0.2; } } }`))
	if got := bgpAuthKey16621(t, ns, "10.0.0.2"); got != "topsecret" {
		t.Errorf("hier top-level key: AuthPassword = %q, want %q", got, "topsecret")
	}
}

func TestBGPAuthKeyMostSpecificWins16621(t *testing.T) {
	ns := bgpNeighbors16621(t, bgpAuthTree16621(t,
		"set protocols bgp local-as 65001",
		"set protocols bgp authentication-key topsecret",
		"set protocols bgp group G peer-as 65002",
		"set protocols bgp group G authentication-key groupsecret",
		"set protocols bgp group G neighbor 10.0.0.2",
		"set protocols bgp group G neighbor 10.0.0.3 authentication-key neighborsecret",
		"set protocols bgp group H peer-as 65003",
		"set protocols bgp group H neighbor 10.0.0.4",
	))
	if got := bgpAuthKey16621(t, ns, "10.0.0.2"); got != "groupsecret" {
		t.Errorf("group overrides top: = %q, want groupsecret", got)
	}
	if got := bgpAuthKey16621(t, ns, "10.0.0.3"); got != "neighborsecret" {
		t.Errorf("neighbor overrides group+top: = %q, want neighborsecret", got)
	}
	if got := bgpAuthKey16621(t, ns, "10.0.0.4"); got != "topsecret" {
		t.Errorf("other group inherits top: = %q, want topsecret", got)
	}
}

// Neighbor authored BEFORE the top-level/group keys (order independence,
// same doctrine as #5270 group inheritance).
func TestBGPAuthKeyOrderIndependent16621(t *testing.T) {
	ns := bgpNeighbors16621(t, bgpAuthHier16621(t,
		`protocols { bgp { group G { neighbor 10.0.0.2; peer-as 65002; authentication-key groupsecret; } local-as 65001; authentication-key topsecret; } }`))
	if got := bgpAuthKey16621(t, ns, "10.0.0.2"); got != "groupsecret" {
		t.Errorf("order-independent group key: = %q, want groupsecret", got)
	}
}

func TestBGPTopLevelAuthKeyRoutingInstance16621(t *testing.T) {
	tree := bgpAuthTree16621(t,
		"set routing-instances VR1 instance-type virtual-router",
		"set routing-instances VR1 protocols bgp local-as 65010",
		"set routing-instances VR1 protocols bgp authentication-key vrfsecret",
		"set routing-instances VR1 protocols bgp group G peer-as 65011",
		"set routing-instances VR1 protocols bgp group G neighbor 10.0.0.2",
	)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("strict compile RI: %v", err)
	}
	if len(cfg.RoutingInstances) != 1 || cfg.RoutingInstances[0].BGP == nil {
		t.Fatalf("RI BGP not compiled: %+v", cfg.RoutingInstances)
	}
	ns := cfg.RoutingInstances[0].BGP.Neighbors
	if got := bgpAuthKey16621(t, ns, "10.0.0.2"); got != "vrfsecret" {
		t.Errorf("RI top-level key: = %q, want vrfsecret", got)
	}
}

// Control: no key anywhere stays empty (unchanged); group-only and
// neighbor-only keys behave as before.
func TestBGPAuthKeyControls16621(t *testing.T) {
	ns := bgpNeighbors16621(t, bgpAuthTree16621(t,
		"set protocols bgp local-as 65001",
		"set protocols bgp group G peer-as 65002",
		"set protocols bgp group G neighbor 10.0.0.2",
	))
	if got := bgpAuthKey16621(t, ns, "10.0.0.2"); got != "" {
		t.Errorf("no-key control: = %q, want empty", got)
	}
	ns = bgpNeighbors16621(t, bgpAuthTree16621(t,
		"set protocols bgp local-as 65001",
		"set protocols bgp group G peer-as 65002",
		"set protocols bgp group G authentication-key groupsecret",
		"set protocols bgp group G neighbor 10.0.0.2",
	))
	if got := bgpAuthKey16621(t, ns, "10.0.0.2"); got != "groupsecret" {
		t.Errorf("group-only control: = %q, want groupsecret", got)
	}
}

// --- Refused half: keychain / algorithm at every level ---

var bgpAuthRefusedRows16621 = []struct {
	name  string
	lines []string
	want  string
}{
	{"top keychain", []string{
		"set protocols bgp local-as 65001",
		"set protocols bgp authentication-key-chain KC1",
		"set protocols bgp group G peer-as 65002",
		"set protocols bgp group G neighbor 10.0.0.2"}, "authentication-key-chain"},
	{"top algorithm", []string{
		"set protocols bgp local-as 65001",
		"set protocols bgp authentication-algorithm md5",
		"set protocols bgp group G peer-as 65002",
		"set protocols bgp group G neighbor 10.0.0.2"}, "authentication-algorithm"},
	{"group keychain", []string{
		"set protocols bgp local-as 65001",
		"set protocols bgp group G peer-as 65002",
		"set protocols bgp group G authentication-key-chain KC1",
		"set protocols bgp group G neighbor 10.0.0.2"}, "authentication-key-chain"},
	{"group algorithm", []string{
		"set protocols bgp local-as 65001",
		"set protocols bgp group G peer-as 65002",
		"set protocols bgp group G authentication-algorithm sha-1",
		"set protocols bgp group G neighbor 10.0.0.2"}, "authentication-algorithm"},
	{"neighbor keychain", []string{
		"set protocols bgp local-as 65001",
		"set protocols bgp group G peer-as 65002",
		"set protocols bgp group G neighbor 10.0.0.2 authentication-key-chain KC1"}, "authentication-key-chain"},
	{"neighbor algorithm", []string{
		"set protocols bgp local-as 65001",
		"set protocols bgp group G peer-as 65002",
		"set protocols bgp group G neighbor 10.0.0.2 authentication-algorithm md5"}, "authentication-algorithm"},
	{"ri top keychain", []string{
		"set routing-instances VR1 instance-type virtual-router",
		"set routing-instances VR1 protocols bgp local-as 65010",
		"set routing-instances VR1 protocols bgp authentication-key-chain KC1",
		"set routing-instances VR1 protocols bgp group G peer-as 65011",
		"set routing-instances VR1 protocols bgp group G neighbor 10.0.0.2"}, "authentication-key-chain"},
	{"ri group algorithm", []string{
		"set routing-instances VR1 instance-type virtual-router",
		"set routing-instances VR1 protocols bgp local-as 65010",
		"set routing-instances VR1 protocols bgp group G peer-as 65011",
		"set routing-instances VR1 protocols bgp group G authentication-algorithm md5",
		"set routing-instances VR1 protocols bgp group G neighbor 10.0.0.2"}, "authentication-algorithm"},
	{"ri neighbor keychain", []string{
		"set routing-instances VR1 instance-type virtual-router",
		"set routing-instances VR1 protocols bgp local-as 65010",
		"set routing-instances VR1 protocols bgp group G peer-as 65011",
		"set routing-instances VR1 protocols bgp group G neighbor 10.0.0.2 authentication-key-chain KC1"}, "authentication-key-chain"},
}

func TestBGPAuthRefusedStrict16621(t *testing.T) {
	for _, row := range bgpAuthRefusedRows16621 {
		t.Run(row.name, func(t *testing.T) {
			tree := bgpAuthTree16621(t, row.lines...)
			err := SchemaValidate(tree)
			if err == nil {
				t.Fatalf("SchemaValidate accepted %s; want strict rejection naming it", row.want)
			}
			if !strings.Contains(err.Error(), row.want) {
				t.Errorf("rejection must name %q: %v", row.want, err)
			}
			// Chain/algorithm names are not secrets, but no authored
			// key value may leak through this diagnostic either.
			if strings.Contains(err.Error(), "topsecret") {
				t.Errorf("error leaks key: %v", err)
			}
		})
	}
}

func TestBGPAuthRefusedHierarchical16621(t *testing.T) {
	for _, inner := range []string{
		`authentication-key-chain KC1;`,
		`authentication-algorithm md5;`,
	} {
		src := `protocols { bgp { local-as 65001; ` + inner + ` group G { peer-as 65002; neighbor 10.0.0.2; } } }`
		tree := bgpAuthHier16621(t, src)
		if err := SchemaValidate(tree); err == nil {
			t.Errorf("hier %q must be refused", inner)
		}
		src = `protocols { bgp { local-as 65001; group G { peer-as 65002; ` + inner + ` neighbor 10.0.0.2; } } }`
		tree = bgpAuthHier16621(t, src)
		if err := SchemaValidate(tree); err == nil {
			t.Errorf("hier group %q must be refused", inner)
		}
		src = `protocols { bgp { local-as 65001; group G { peer-as 65002; neighbor 10.0.0.2 { ` + inner + ` } } } }`
		tree = bgpAuthHier16621(t, src)
		if err := SchemaValidate(tree); err == nil {
			t.Errorf("hier neighbor %q must be refused", inner)
		}
		src = `routing-instances { VR1 { instance-type virtual-router; protocols { bgp { local-as 65010; ` + inner + ` group G { peer-as 65011; neighbor 10.0.0.2; } } } } }`
		tree = bgpAuthHier16621(t, src)
		if err := SchemaValidate(tree); err == nil {
			t.Errorf("hier RI %q must be refused", inner)
		}
	}
}

// Tolerant path: lenient compile must boot (#1960) and carry a SPECIFIC
// warning naming the refused statement (not only generic #10707).
func TestBGPAuthRefusedTolerantWarning16621(t *testing.T) {
	for _, row := range bgpAuthRefusedRows16621 {
		t.Run(row.name, func(t *testing.T) {
			tree := bgpAuthTree16621(t, row.lines...)
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("lenient must boot: %v", err)
			}
			found := false
			for _, w := range cfg.Warnings {
				if strings.Contains(w, row.want) && strings.Contains(w, "#16621") {
					found = true
				}
				if strings.Contains(w, "topsecret") {
					t.Errorf("warning leaks key: %q", w)
				}
			}
			if !found {
				t.Errorf("tolerant warnings must name %q specifically (#16621), got %v", row.want, cfg.Warnings)
			}
		})
	}
	// Strict compile (no SchemaValidate) must also surface the specific
	// warning so a direct CompileConfig caller sees the drop.
	tree := bgpAuthTree16621(t, bgpAuthRefusedRows16621[0].lines...)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("strict compile: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "authentication-key-chain") && strings.Contains(w, "#16621") {
			found = true
		}
	}
	if !found {
		t.Errorf("strict compile warnings must name authentication-key-chain (#16621), got %v", cfg.Warnings)
	}
}

// Controls: legitimate BGP leaves still commit strict, and an unrelated
// protocol's keychain spelling is untouched by this gate.
func TestBGPAuthControlsStillCommit16621(t *testing.T) {
	tree := bgpAuthTree16621(t,
		"set protocols bgp local-as 65001",
		"set protocols bgp authentication-key topsecret",
		"set protocols bgp group G peer-as 65002",
		"set protocols bgp group G neighbor 10.0.0.2 authentication-key neighborsecret",
	)
	if err := SchemaValidate(tree); err != nil {
		t.Fatalf("valid BGP auth config must commit: %v", err)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#16621") {
			t.Errorf("valid config must not draw #16621 warning: %q", w)
		}
	}
}
