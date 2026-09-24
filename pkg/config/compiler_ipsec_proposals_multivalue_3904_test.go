package config

import (
	"reflect"
	"strings"
	"testing"
)

// #3904 (fable-161 F-040/F-161): an IKE/IPsec policy `proposals [ p1 p2 ]`
// bracket list used to compile to a single scalar reference — the compiler
// read only nodeVal(p) (the first token) and IKEPolicy.Proposals /
// IPsecPolicyDef.Proposals were plain strings. The schema now marks the
// leaves multi: true (so the flat-set path keeps every reference) and the
// compiler accumulates EVERY value via firewallMatchValues into the []string
// fields, in BOTH the flat-set and hierarchical AST shapes (#2419).
//
// fail-on-revert: restoring the scalar read leaves the slice with one element
// (or fails to compile), so the two-element assertions below go RED.

func multiProposalsFlat(t *testing.T) *Config {
	t.Helper()
	tree := buildTree(t, []string{
		"set security ike proposal ike-a authentication-method pre-shared-keys",
		"set security ike proposal ike-a encryption-algorithm aes-256-cbc",
		"set security ike proposal ike-b authentication-method pre-shared-keys",
		"set security ike proposal ike-b encryption-algorithm aes-128-cbc",
		"set security ike policy ike-pol proposals [ ike-a ike-b ]",
		"set security ipsec proposal esp-a protocol esp",
		"set security ipsec proposal esp-a encryption-algorithm aes-256-cbc",
		"set security ipsec proposal esp-a authentication-algorithm hmac-sha-256-128",
		"set security ipsec proposal esp-b protocol esp",
		"set security ipsec proposal esp-b encryption-algorithm aes-128-cbc",
		"set security ipsec proposal esp-b authentication-algorithm hmac-sha-256-128",
		"set security ipsec policy esp-pol proposals [ esp-a esp-b ]",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig (flat multi-proposal): %v", err)
	}
	return cfg
}

func TestIKEIPsecProposalsMultiValueFlat(t *testing.T) {
	cfg := multiProposalsFlat(t)
	ikePol := cfg.Security.IPsec.IKEPolicies["ike-pol"]
	if ikePol == nil {
		t.Fatal("ike-policy ike-pol missing after compile")
	}
	if got, want := ikePol.Proposals, []string{"ike-a", "ike-b"}; !reflect.DeepEqual(got, want) {
		t.Errorf("IKE policy Proposals = %v, want %v (bracket list truncated)", got, want)
	}
	espPol := cfg.Security.IPsec.Policies["esp-pol"]
	if espPol == nil {
		t.Fatal("ipsec-policy esp-pol missing after compile")
	}
	if got, want := espPol.Proposals, []string{"esp-a", "esp-b"}; !reflect.DeepEqual(got, want) {
		t.Errorf("IPsec policy Proposals = %v, want %v (bracket list truncated)", got, want)
	}
}

func TestIKEIPsecProposalsMultiValueHierarchical(t *testing.T) {
	tree := mustParse(t, `security {
    ike {
        proposal ike-a {
            authentication-method pre-shared-keys;
            encryption-algorithm aes-256-cbc;
        }
        proposal ike-b {
            authentication-method pre-shared-keys;
            encryption-algorithm aes-128-cbc;
        }
        policy ike-pol {
            proposals [ ike-a ike-b ];
        }
    }
    ipsec {
        proposal esp-a {
            protocol esp;
            encryption-algorithm aes-256-cbc;
            authentication-algorithm hmac-sha-256-128;
        }
        proposal esp-b {
            protocol esp;
            encryption-algorithm aes-128-cbc;
            authentication-algorithm hmac-sha-256-128;
        }
        policy esp-pol {
            proposals [ esp-a esp-b ];
        }
    }
}`)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig (hierarchical multi-proposal): %v", err)
	}
	if got, want := cfg.Security.IPsec.IKEPolicies["ike-pol"].Proposals, []string{"ike-a", "ike-b"}; !reflect.DeepEqual(got, want) {
		t.Errorf("hierarchical IKE Proposals = %v, want %v", got, want)
	}
	if got, want := cfg.Security.IPsec.Policies["esp-pol"].Proposals, []string{"esp-a", "esp-b"}; !reflect.DeepEqual(got, want) {
		t.Errorf("hierarchical IPsec Proposals = %v, want %v", got, want)
	}
}

// TestIPsecPolicyProposalsDanglingSecondRejected pins the strict-commit gate:
// a bracket list whose SECOND reference dangles must be rejected at commit
// (mirror the NAT bracket-list H05 precedent). Pre-#3904 the truncation hid
// the second reference entirely, so a typo committed silently.
func TestIPsecPolicyProposalsDanglingSecondRejected(t *testing.T) {
	tree := buildTree(t, []string{
		"set security zones security-zone untrust",
		"set security ipsec proposal esp-a authentication-algorithm hmac-sha-256-128",
		"set security ipsec proposal esp-a protocol esp",
		"set security ipsec proposal esp-a encryption-algorithm aes-256-cbc",
		"set security ipsec policy esp-pol proposals [ esp-a esp-typo ]",
		"set security ike proposal ike-a authentication-method pre-shared-keys",
		"set security ike policy ike-pol proposals ike-a",
		"set security ike gateway gw1 address 172.16.0.1",
		"set security ike gateway gw1 ike-policy ike-pol",
		"set security ipsec vpn tun1 ike gateway gw1",
		"set security ipsec vpn tun1 bind-interface st0",
		"set security ipsec vpn tun1 ike ipsec-policy esp-pol",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("an ipsec policy proposals list with a dangling second reference must be rejected at commit")
	}
	if !strings.Contains(err.Error(), "esp-typo") {
		t.Errorf("error should name the dangling reference esp-typo, got: %v", err)
	}
}

// TestIKEPolicyProposalsDanglingSecondRejected is the phase-1 mirror: a
// dangling SECOND ike-proposal reference must be rejected at commit.
func TestIKEPolicyProposalsDanglingSecondRejected(t *testing.T) {
	tree := buildTree(t, []string{
		"set security zones security-zone untrust",
		"set security ike proposal ike-a authentication-method pre-shared-keys",
		"set security ike policy ike-pol proposals [ ike-a ike-typo ]",
		"set security ike gateway gw1 address 172.16.0.1",
		"set security ike gateway gw1 ike-policy ike-pol",
		"set security ipsec proposal esp-a protocol esp",
		"set security ipsec proposal esp-a encryption-algorithm aes-256-cbc",
		"set security ipsec policy esp-pol proposals esp-a",
		"set security ipsec vpn tun1 ike gateway gw1",
		"set security ipsec vpn tun1 bind-interface st0",
		"set security ipsec vpn tun1 ike ipsec-policy esp-pol",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("an ike policy proposals list with a dangling second reference must be rejected at commit")
	}
	if !strings.Contains(err.Error(), "ike-typo") {
		t.Errorf("error should name the dangling reference ike-typo, got: %v", err)
	}
}
