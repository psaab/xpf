package config

import (
	"strings"
	"testing"
)

// buildTreeFromSet builds a ConfigTree from a list of `set ...` commands
// using the flat-set path (ParseSetCommand + SetPath), per the project's
// set-syntax testing rule. NewParser must NOT be used for multi-line set
// input — it merges all lines into one node.
func buildTreeFromSet(t *testing.T, cmds []string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	return tree
}

// TestIPsecPolicyDanglingExplicitProposalRejected covers the #2073 core:
// an IPsec policy with an explicit `proposals` reference that does not
// resolve must be hard-rejected at commit/commit-check, instead of
// silently dropping the configured PFS group to the strongSwan default.
func TestIPsecPolicyDanglingExplicitProposalRejected(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set security ipsec policy ipsec-pol perfect-forward-secrecy keys group14",
		"set security ipsec policy ipsec-pol proposals does-not-exist",
		"set security ipsec vpn tun1 ike gateway gw1",
		"set security ipsec vpn tun1 bind-interface st0",
		"set security ipsec vpn tun1 ike ipsec-policy ipsec-pol",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig accepted an IPsec policy with a dangling proposal reference; expected rejection")
	}
	// Must name the policy and the dangling proposal, and explain the
	// silent-drop consequence.
	for _, want := range []string{"ipsec-pol", "does-not-exist", "perfect-forward-secrecy"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q missing %q", err.Error(), want)
		}
	}
}

// TestIPsecPolicyNoProposalLeafRejected covers the R1 finding: a policy
// that configures PFS but gives no `proposals` leaf at all (so the
// policy-name fallback also dangles) must be rejected with a message that
// does NOT blame a phantom proposal named after the policy.
func TestIPsecPolicyNoProposalLeafRejected(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set security ipsec policy ipsec-pol perfect-forward-secrecy keys group14",
		"set security ipsec vpn tun1 ike gateway gw1",
		"set security ipsec vpn tun1 bind-interface st0",
		"set security ipsec vpn tun1 ike ipsec-policy ipsec-pol",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig accepted a PFS policy with no resolvable proposal; expected rejection")
	}
	if !strings.Contains(err.Error(), "ipsec-pol") {
		t.Errorf("error %q missing policy name", err.Error())
	}
	if !strings.Contains(err.Error(), "no `proposals` reference") {
		t.Errorf("error %q should describe the missing proposals reference, not blame a phantom proposal: %v", err.Error(), err)
	}
}

// TestIPsecPolicyResolvableProposalAccepted is the (A) regression: a
// policy whose proposal reference resolves must compile cleanly.
func TestIPsecPolicyResolvableProposalAccepted(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set security ike gateway gw1 address 192.0.2.1",
		"set security ipsec proposal esp-p2 protocol esp",
		"set security ipsec proposal esp-p2 encryption-algorithm aes-256-cbc",
		"set security ipsec proposal esp-p2 authentication-algorithm hmac-sha-256-128",
		"set security ipsec policy ipsec-pol perfect-forward-secrecy keys group14",
		"set security ipsec policy ipsec-pol proposals esp-p2",
		"set security ipsec vpn tun1 ike gateway gw1",
		"set security ipsec vpn tun1 bind-interface st0",
		"set security ipsec vpn tun1 ike ipsec-policy ipsec-pol",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig rejected a resolvable IPsec policy proposal: %v", err)
	}
	pol, ok := cfg.Security.IPsec.Policies["ipsec-pol"]
	if !ok {
		t.Fatal("ipsec policy ipsec-pol not compiled")
	}
	if pol.PFSGroup != 14 {
		t.Errorf("PFSGroup = %d, want 14", pol.PFSGroup)
	}
	if len(pol.Proposals) != 1 || pol.Proposals[0] != "esp-p2" {
		t.Errorf("Proposals = %q, want esp-p2", pol.Proposals)
	}
}

// TestIPsecPolicyNameEqualsProposalAccepted is the (C) regression: the
// Junos idiom of an IPsec policy whose `proposals` leaf is omitted but a
// proposal of the same name exists must compile (policy-name fallback
// resolves) and must NOT trip the validator.
func TestIPsecPolicyNameEqualsProposalAccepted(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set security ike gateway gw1 address 192.0.2.1",
		"set security ipsec proposal ipsec-pol protocol esp",
		"set security ipsec proposal ipsec-pol encryption-algorithm aes-256-cbc",
		"set security ipsec proposal ipsec-pol authentication-algorithm hmac-sha-256-128",
		"set security ipsec policy ipsec-pol perfect-forward-secrecy keys group14",
		"set security ipsec vpn tun1 ike gateway gw1",
		"set security ipsec vpn tun1 bind-interface st0",
		"set security ipsec vpn tun1 ike ipsec-policy ipsec-pol",
	})
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("CompileConfig rejected the policy-name == proposal-name idiom: %v", err)
	}
}

// TestIPsecNoPolicyAccepted is the (D) regression: a VPN with no IPsec
// policy at all (and thus no PFS) must compile cleanly — nothing is
// weakened.
func TestIPsecNoPolicyAccepted(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set security ike gateway gw1 address 192.0.2.1",
		"set security ipsec vpn tun1 ike gateway gw1",
		"set security ipsec vpn tun1 bind-interface st0",
	})
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("CompileConfig rejected a VPN with no IPsec policy: %v", err)
	}
}

// TestIPsecPolicyDanglingProposalLenientDowngrade verifies the tolerant
// load / peer-sync paths (CompileConfigLenient and
// CompileConfigForNodeLenient) downgrade the dangling-reference error to
// a warning so an already-persisted or peer-synced config still boots.
func TestIPsecPolicyDanglingProposalLenientDowngrade(t *testing.T) {
	cmds := []string{
		"set security ipsec policy ipsec-pol perfect-forward-secrecy keys group14",
		"set security ipsec policy ipsec-pol proposals does-not-exist",
		"set security ipsec vpn tun1 ike gateway gw1",
		"set security ipsec vpn tun1 ike ipsec-policy ipsec-pol",
	}

	hasIPsecWarning := func(cfg *Config) bool {
		for _, w := range cfg.Warnings {
			if strings.Contains(w, "ipsec policy proposal reference") {
				return true
			}
		}
		return false
	}

	t.Run("standalone", func(t *testing.T) {
		cfg, err := CompileConfigLenient(buildTreeFromSet(t, cmds))
		if err != nil {
			t.Fatalf("CompileConfigLenient hard-failed a dangling proposal ref; must downgrade to warning: %v", err)
		}
		if !hasIPsecWarning(cfg) {
			t.Errorf("expected an ipsec policy proposal reference warning, got %v", cfg.Warnings)
		}
	})

	t.Run("node-aware", func(t *testing.T) {
		cfg, err := CompileConfigForNodeLenient(buildTreeFromSet(t, cmds), 0)
		if err != nil {
			t.Fatalf("CompileConfigForNodeLenient hard-failed a dangling proposal ref; must downgrade to warning (HA peer-sync): %v", err)
		}
		if !hasIPsecWarning(cfg) {
			t.Errorf("expected an ipsec policy proposal reference warning, got %v", cfg.Warnings)
		}
	})
}
