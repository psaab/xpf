package configstore

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #5876: the strict commit gate (compileTreeStrict) must reject a chassis-cluster
// candidate whose SOURCE-NAT is representable on the SUBMITTING node but not on
// the PEER — a green commit would strand the standby's SNAT. This test locks the
// STORE wiring: compileTreeStrict compiles the local node clean, then the
// peer-effective SNAT gate rejects.
//
// FAIL-ON-REVERT: drop the config.ValidatePeerEffectiveStrict call from
// compileTreeStrict (leaving the local compile) and compileTreeStrict(tree, 0)
// returns nil — this test goes RED.

func peerDivergentSNATTree(t *testing.T) *config.ConfigTree {
	t.Helper()
	tree := &config.ConfigTree{}
	cmds := []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security nat source rule-set RS from zone trust",
		"set security nat source rule-set RS to zone untrust",
		"set security nat source rule-set RS rule R1 match source-address 10.0.0.0/24",
		"set security nat source rule-set RS rule R1 then source-nat pool P",
		"set groups node0 security nat source pool P address 203.0.113.5/32",
		"set groups node0 security nat source pool P port range 1024 to 2048",
		"set groups node1 security nat source pool P address 203.0.113.5/32",
		"set groups node1 security nat source pool P port range 5000 to 100",
		`set apply-groups "${node}"`,
	}
	for _, cmd := range cmds {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	return tree
}

// TestCompileTreeStrict_RejectsPeerOnlySNAT_5876 drives the store-level strict
// commit gate for a node0 commit: the peer (node1) view has a reversed
// source-pool port range, so the gate must reject naming the peer node.
func TestCompileTreeStrict_RejectsPeerOnlySNAT_5876(t *testing.T) {
	tree := peerDivergentSNATTree(t)

	// node0 (the submitting node) strict-compiles cleanly on its own view.
	if _, err := config.CompileConfigForNode(tree, 0); err != nil {
		t.Fatalf("node0 local compile must be clean: %v", err)
	}

	// The strict commit gate for node0 must reject the peer-only SNAT error.
	_, err := compileTreeStrict(tree, 0)
	if err == nil {
		t.Fatal("compileTreeStrict(node0) ACCEPTED a peer-only source-NAT reversed port range — #5876 fail-open")
	}
	for _, want := range []string{"node1", "source-nat pool"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("compileTreeStrict reject missing %q: %v", want, err)
		}
	}
}

// TestCompileTreeStrict_StandalonePeerNoOp_5876 pins that standalone commits
// (nodeID -1) skip the peer gate — a lone reversed range is still rejected by the
// local strict gate, but no peer machinery runs and no false-reject occurs for a
// clean standalone config.
func TestCompileTreeStrict_StandaloneCleanSNAT_5876(t *testing.T) {
	tree := &config.ConfigTree{}
	for _, cmd := range []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security nat source rule-set RS from zone trust",
		"set security nat source rule-set RS to zone untrust",
		"set security nat source rule-set RS rule R1 match source-address 10.0.0.0/24",
		"set security nat source rule-set RS rule R1 then source-nat pool P",
		"set security nat source pool P address 203.0.113.5/32",
		"set security nat source pool P port range 1024 to 2048",
	} {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	if _, err := compileTreeStrict(tree, -1); err != nil {
		t.Fatalf("standalone clean SNAT config must compile: %v", err)
	}
}
