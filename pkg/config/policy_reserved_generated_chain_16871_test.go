package config

import (
	"strings"
	"testing"
)

// #16871 (R3-B08-03): the strict suffix gate forbids NAMING a policy-statement
// `xpf-default-export-xpf-chain`, but the members `xpf` and `default-export`
// are individually legal and their BGP chain JOINS into that reserved
// generated name. Strict commit must reject the join; the tolerant path warns
// (#1960) and pkg/frr's bgpComposedChainCollision fails the apply closed.
//
// These tests drive the real CompileConfig / CompileConfigLenient paths. The
// defect cells FAIL pre-fix (the forge compiles clean) and pass post-fix.

func reservedChainTree16871(chain []string) []string {
	cmds := []string{
		"set routing-options autonomous-system 65000",
		"set protocols bgp group g type external",
		"set protocols bgp group g peer-as 65001",
	}
	for _, name := range chain {
		cmds = append(cmds,
			"set policy-options policy-statement "+name+" term t1 from protocol static",
			"set policy-options policy-statement "+name+" term t1 then accept",
			"set protocols bgp group g neighbor 10.0.0.2 export "+name,
		)
	}
	// Controls: ordinary members used by the negative control.
	for _, name := range []string{"LOCAL", "TRANSIT"} {
		cmds = append(cmds,
			"set policy-options policy-statement "+name+" term t1 then accept")
	}
	return cmds
}

// TestForgedDefaultExportChainRejectedStrict16871 is the defect cell.
func TestForgedDefaultExportChainRejectedStrict16871(t *testing.T) {
	tree := buildTreeFromSet(t, reservedChainTree16871([]string{"xpf", "default-export"}))
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig accepted chain [xpf default-export] which composes into " +
			"the reserved xpf-default-export-xpf-chain; expected rejection (#16871)")
	}
	for _, want := range []string{"xpf-default-export-xpf-chain", "xpf", "default-export", "reserved"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q missing %q", err.Error(), want)
		}
	}
}

// TestForgedEmptiedChainRejectedStrict16871 is the sibling control: the #7625
// forge joins the same way and must also be rejected at commit.
func TestForgedEmptiedChainRejectedStrict16871(t *testing.T) {
	tree := buildTreeFromSet(t, reservedChainTree16871([]string{"xpf", "emptied", "chain"}))
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig accepted chain [xpf emptied chain] which composes into " +
			"the reserved xpf-emptied-chain-xpf-chain; expected rejection (#16871)")
	}
	if !strings.Contains(err.Error(), "xpf-emptied-chain-xpf-chain") {
		t.Errorf("error %q does not name the reserved map", err.Error())
	}
}

// TestForgedDefaultExportChainLenientWarns16871 pins the #1960 doctrine: the
// tolerant path boots with a warning, and the render belt fails the apply.
func TestForgedDefaultExportChainLenientWarns16871(t *testing.T) {
	tree := buildTreeFromSet(t, reservedChainTree16871([]string{"xpf", "default-export"}))
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient must not hard-fail on a forged reserved chain; must warn: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "xpf-default-export-xpf-chain") && strings.Contains(w, "reserved") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected a downgraded reserved-chain warning naming the map; warnings=%v", cfg.Warnings)
	}
}

// TestOrdinaryChainAcceptedStrict16871 is the negative control: [LOCAL
// TRANSIT] composes to an ordinary name and must still compile.
func TestOrdinaryChainAcceptedStrict16871(t *testing.T) {
	cmds := []string{
		"set routing-options autonomous-system 65000",
		"set policy-options policy-statement LOCAL term t1 then accept",
		"set policy-options policy-statement TRANSIT term t1 then accept",
		"set protocols bgp group g type external",
		"set protocols bgp group g peer-as 65001",
		"set protocols bgp group g neighbor 10.0.0.2 export LOCAL",
		"set protocols bgp group g neighbor 10.0.0.2 export TRANSIT",
	}
	tree := buildTreeFromSet(t, cmds)
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("CompileConfig rejected ordinary chain [LOCAL TRANSIT]: %v", err)
	}
}
