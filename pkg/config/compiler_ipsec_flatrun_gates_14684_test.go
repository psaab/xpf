package config

import (
	"strings"
	"testing"
)

// #14684 (D9-04): a chained flat `set` run under `security ipsec vpn <name>`
// is expanded by compileIPsec via expandIPsecVPNRun9088, so every leaf in
// the chain is compiled -- Gateway, IPsecPolicy, BindInterface, LocalID and
// RemoteID all land on the typed VPN. But two sibling gates read only
// DIRECT children:
//
//   - validateIPsecTrafficSelectorsStrict used vpnInst.node.FindChildren
//     for local-identity / remote-identity (#8003/#12507, and the #4098
//     value rules behind them). Chained after gateway/ipsec-policy/
//     bind-interface, those leaves are nested inside the run, so the gate
//     saw nothing and an FQDN (corp.example.com, which strongSwan
//     discards the whole connection for as local_ts) or a helper-refused
//     /008 mask committed clean.
//   - warnSecureTunnelPlaintextUnadjudicatedAST used
//     inst.node.FindChild("bind-interface") (#5619/#12507 plaintext
//     advisory). Chained after gateway, bind-interface is likewise
//     invisible, so no plaintext warning fired.
//
// The bind-interface gate already reads the run via
// findChildInRun9088/findChildrenInRun9088. These tests require the two
// sibling gates to see the same leaves the compiler installs, in both
// strict and lenient modes, for set and braced spellings alike, without
// over-rejecting valid selector-shaped identities.
//
// Named fixture from the issue: TestIPsecVPNFlatRunTrafficSelectorAndPlaintextWarn9088.

const chained14684 = "set security ipsec vpn v1 gateway gw1 ipsec-policy epol1 bind-interface st0.0 local-identity corp.example.com remote-identity 10.0.0.0/008"

// preamble14684 defines gw1 and epol1 so strict compiles reach the
// selector/plaintext gates instead of failing earlier on undefined
// gateway/policy references. VPN v1 itself is authored per subtest.
var preamble14684 = []string{
	"set security ike proposal p1 authentication-method pre-shared-keys",
	"set security ike proposal p1 encryption-algorithm aes-256-cbc",
	"set security ike proposal p1 authentication-algorithm sha-256",
	"set security ike proposal p1 dh-group group14",
	"set security ike policy ike-pol proposals p1",
	"set security ike policy ike-pol pre-shared-key ascii-text secret123",
	"set security ike gateway gw1 ike-policy ike-pol",
	"set security ike gateway gw1 address 192.0.2.1",
	"set security ipsec proposal esp1 protocol esp",
	"set security ipsec proposal esp1 encryption-algorithm aes-256-gcm",
	"set security ipsec policy epol1 proposals esp1",
}

func buildTree14684(t *testing.T, cmds ...string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	for _, cmd := range append(append([]string{}, preamble14684...), cmds...) {
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

// buildBraced14684 parses a self-contained braced config.
func buildBraced14684(t *testing.T, text string) *ConfigTree {
	t.Helper()
	tree, perrs := NewParser(text).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse braced control: %v", perrs)
	}
	return tree
}

// TestIPsecVPNFlatRunTrafficSelectorAndPlaintextWarn9088 is the decisive
// regression: the chained flat form must match the braced/split verdict
// for the SAME values.
//
//   - strict: the FQDN local-identity must be rejected naming #8003 (and
//     the /008 remote-identity naming #12507 when it is the offending
//     leaf), and
//   - lenient: the same values must warn (not error, #1960), and
//   - the plaintext advisory must fire for the chained bind-interface.
//
// On unfixed origin/master the chained form compiles with
// SchemaErr=<nil> CompileErr=<nil> Warnings=[] while
// BindInterface/LocalID/RemoteID are all populated -- this test is RED.
func TestIPsecVPNFlatRunTrafficSelectorAndPlaintextWarn9088(t *testing.T) {
	t.Run("strict chained FQDN local-identity rejected like braced", func(t *testing.T) {
		// Braced control: same values in split/braced form already reject.
		control := buildTree14684(t,
			"set security ipsec vpn v1 gateway gw1",
			"set security ipsec vpn v1 ipsec-policy epol1",
			"set security ipsec vpn v1 bind-interface st0.0",
			"set security ipsec vpn v1 local-identity corp.example.com",
		)
		if _, err := CompileConfig(control); err == nil {
			t.Fatal("control (split) form unexpectedly accepted FQDN local-identity; test premise broken")
		} else if !strings.Contains(err.Error(), "#8003") || !strings.Contains(err.Error(), "local-identity") {
			t.Fatalf("control reject %q should name local-identity and #8003", err.Error())
		}

		chained := buildTree14684(t, chained14684)
		_, err := CompileConfig(chained)
		if err == nil {
			t.Fatal("CompileConfig accepted chained flat run with FQDN local-identity corp.example.com; " +
				"want strict #8003 reject matching the braced form (#14684)")
		}
		// First offending leaf in run order is local-identity.
		if !strings.Contains(err.Error(), "#8003") || !strings.Contains(err.Error(), "local-identity") ||
			!strings.Contains(err.Error(), "corp.example.com") {
			t.Fatalf("chained reject %q should name local-identity corp.example.com and #8003", err.Error())
		}
	})

	t.Run("strict chained helper-refused mask rejected like braced", func(t *testing.T) {
		// Remote-only offence so the /008 arm is the deciding leaf.
		chained := buildTree14684(t,
			"set security ipsec vpn v1 gateway gw1 ipsec-policy epol1 bind-interface st0.0 remote-identity 10.0.0.0/008")
		_, err := CompileConfig(chained)
		if err == nil {
			t.Fatal("CompileConfig accepted chained flat run with helper-refused remote-identity 10.0.0.0/008; " +
				"want strict #12507 reject (#14684)")
		}
		if !strings.Contains(err.Error(), "#12507") || !strings.Contains(err.Error(), "remote-identity") ||
			!strings.Contains(err.Error(), "10.0.0.0/008") {
			t.Fatalf("chained reject %q should name remote-identity 10.0.0.0/008 and #12507", err.Error())
		}
	})

	t.Run("lenient chained warns not errors and still compiles values", func(t *testing.T) {
		chained := buildTree14684(t, chained14684)
		cfg, err := CompileConfigLenient(chained)
		if err != nil {
			t.Fatalf("CompileConfigLenient must not fail on persisted chained config (#1960): %v", err)
		}
		// The compiler must still see the chained leaves (premise check).
		vpn := cfg.Security.IPsec.VPNs["v1"]
		if vpn == nil {
			t.Fatal("chained run produced no vpn v1")
		}
		if vpn.BindInterface != "st0.0" || vpn.LocalID != "corp.example.com" || vpn.RemoteID != "10.0.0.0/008" {
			t.Fatalf("chained compile = Bind=%q Local=%q Remote=%q, want st0.0/corp.example.com/10.0.0.0/008 (premise)",
				vpn.BindInterface, vpn.LocalID, vpn.RemoteID)
		}
		var saw8003, saw12507 bool
		for _, w := range cfg.Warnings {
			if strings.Contains(w, "#8003") && strings.Contains(w, "local-identity") {
				saw8003 = true
			}
			if strings.Contains(w, "#12507") && strings.Contains(w, "remote-identity") {
				saw12507 = true
			}
		}
		if !saw8003 {
			t.Fatalf("lenient chained compile did not warn #8003 for FQDN local-identity; warnings=%v", cfg.Warnings)
		}
		if !saw12507 {
			t.Fatalf("lenient chained compile did not warn #12507 for /008 remote-identity; warnings=%v", cfg.Warnings)
		}
	})

	t.Run("plaintext advisory fires for chained bind-interface", func(t *testing.T) {
		// Valid selector identities so only the #5619 advisory is in play.
		chained := buildTree14684(t,
			"set security ipsec vpn v1 gateway gw1 ipsec-policy epol1 bind-interface st0.0 local-identity 10.0.0.0/24 remote-identity 10.1.0.0/24")
		cfg, err := CompileConfig(chained)
		if err != nil {
			t.Fatalf("CompileConfig rejected valid chained selectors: %v", err)
		}
		found := false
		for _, w := range cfg.Warnings {
			if strings.Contains(w, "#5619") && strings.Contains(w, "v1") && strings.Contains(w, "st0.0") {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("chained bind-interface st0.0 produced no #5619 plaintext advisory; warnings=%v (#14684)", cfg.Warnings)
		}
	})

	t.Run("plaintext advisory fires when bind-interface is not first in chain", func(t *testing.T) {
		// bind-interface buried mid-chain (after gateway, before df-bit).
		chained := buildTree14684(t,
			"set security ipsec vpn v1 gateway gw1 bind-interface st0.1 df-bit clear")
		cfg, err := CompileConfig(chained)
		if err != nil {
			t.Fatalf("CompileConfig: %v", err)
		}
		found := false
		for _, w := range cfg.Warnings {
			if strings.Contains(w, "#5619") && strings.Contains(w, "st0.1") {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("mid-chain bind-interface st0.1 produced no #5619 advisory; warnings=%v", cfg.Warnings)
		}
	})

	t.Run("braced valid selectors stay clean and still warn plaintext", func(t *testing.T) {
		// Over-reject / over-warn control: valid CIDR identities in a
		// braced block must commit with no #8003/#12507 warning, and the
		// #5619 advisory must still fire exactly as before the fix.
		tree := buildBraced14684(t, `security {
  ike {
    proposal p1 { authentication-method pre-shared-keys; encryption-algorithm aes-256-cbc; authentication-algorithm sha-256; dh-group group14; }
    policy ike-pol { proposals p1; pre-shared-key ascii-text secret123; }
    gateway gw1 { ike-policy ike-pol; address 192.0.2.1; }
  }
  ipsec {
    proposal esp1 { protocol esp; encryption-algorithm aes-256-gcm; }
    policy epol1 { proposals esp1; }
    vpn v1 {
      gateway gw1;
      ipsec-policy epol1;
      bind-interface st0.0;
      local-identity 10.0.0.0/24;
      remote-identity 10.1.0.0/24;
    }
  }
}`)
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("braced valid selectors rejected: %v", err)
		}
		for _, w := range cfg.Warnings {
			if strings.Contains(w, "#8003") || strings.Contains(w, "#12507") {
				t.Fatalf("braced valid selectors produced selector warning: %q", w)
			}
		}
		found := false
		for _, w := range cfg.Warnings {
			if strings.Contains(w, "#5619") {
				found = true
			}
		}
		if !found {
			t.Fatalf("braced bind-interface lost #5619 advisory; warnings=%v", cfg.Warnings)
		}
	})

	t.Run("chained valid selectors stay clean", func(t *testing.T) {
		chained := buildTree14684(t,
			"set security ipsec vpn v1 gateway gw1 ipsec-policy epol1 bind-interface st0.0 local-identity 10.0.0.0/24 remote-identity 2001:db8::/48")
		cfg, err := CompileConfig(chained)
		if err != nil {
			t.Fatalf("chained valid selectors rejected: %v", err)
		}
		for _, w := range cfg.Warnings {
			if strings.Contains(w, "#8003") || strings.Contains(w, "#12507") {
				t.Fatalf("chained valid selectors produced selector warning: %q", w)
			}
		}
	})

	t.Run("repeated chained identity last value is gated", func(t *testing.T) {
		// Compiler installs the LAST occurrence; gate must see every
		// occurrence in the expanded run (mirrors #14451 bind semantics).
		chained := buildTree14684(t,
			"set security ipsec vpn v1 bind-interface st0.0 local-identity 10.0.0.0/24 gateway gw1 local-identity corp.example.com")
		if _, err := CompileConfig(chained); err == nil {
			t.Fatal("CompileConfig accepted chained run whose last local-identity is an FQDN (#14684)")
		}
	})
}
