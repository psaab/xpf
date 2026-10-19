package config

import (
	"strings"
	"testing"
)

// #15027 (A16-04): `pre-shared-key hexadecimal <hex>` must compile to
// a hex-flagged PSK (rendered by pkg/ipsec as `secret = 0x<hex>`), an
// unknown qualifier or malformed hex must be refused at strict commit
// (warned on the tolerant path), and `ascii-text` / the bare VPN-level
// form must keep today's ASCII behaviour. The block spelling
// `pre-shared-key { hexadecimal ...; }`, previously dropped entirely,
// must carry the key.
//
// FAIL-ON-REVERT: on pre-fix code the qualifier (Keys[1]) was never
// read — hexadecimal committed as the ASCII string "6162...", bogus
// committed identically, and the block form compiled to an empty PSK
// (then #14139-refused) — so every assertion below goes RED.

func pskHexBase(t *testing.T, pskLine string) []string {
	t.Helper()
	return []string{
		"set security ike proposal p1 authentication-method pre-shared-keys",
		"set security ike proposal p1 encryption-algorithm aes-256-cbc",
		"set security ike proposal p1 authentication-algorithm sha-256",
		"set security ike proposal p1 dh-group group14",
		"set security ike policy pol proposals p1",
		pskLine,
		"set security ike gateway gw1 ike-policy pol",
		"set security ike gateway gw1 address 192.0.2.1",
		"set security ipsec proposal esp1 protocol esp",
		"set security ipsec proposal esp1 encryption-algorithm aes-256-cbc",
		"set security ipsec proposal esp1 authentication-algorithm hmac-sha-256-128",
		"set security ipsec policy ipol proposals esp1",
		"set security ipsec vpn v1 ike gateway gw1",
		"set security ipsec vpn v1 ike ipsec-policy ipol",
		"set security ipsec vpn v1 bind-interface st0.0",
	}
}

func TestIPsecPSKHexadecimal15027(t *testing.T) {
	// Acceptance probe from the issue: hexadecimal 6162636431323334
	// is "abcd1234" as raw bytes.
	t.Run("hexadecimal compiles hex-flagged", func(t *testing.T) {
		cfg, err := CompileConfig(buildTree(t, pskHexBase(t,
			"set security ike policy pol pre-shared-key hexadecimal 6162636431323334")))
		if err != nil {
			t.Fatalf("hexadecimal PSK must commit: %v", err)
		}
		pol := cfg.Security.IPsec.IKEPolicies["pol"]
		if pol == nil {
			t.Fatal("ike policy pol missing")
		}
		if pol.PSK.Reveal() != "6162636431323334" || !pol.PSKHex {
			t.Fatalf("pol PSK=%q hex=%v, want 6162636431323334 hex=true",
				pol.PSK.Reveal(), pol.PSKHex)
		}
		if pol.PSKQualifierInvalidSpec != "" {
			t.Fatalf("valid hex must not record an invalid spec, got %q", pol.PSKQualifierInvalidSpec)
		}
	})

	t.Run("ascii-text control stays ASCII", func(t *testing.T) {
		cfg, err := CompileConfig(buildTree(t, pskHexBase(t,
			"set security ike policy pol pre-shared-key ascii-text secret123")))
		if err != nil {
			t.Fatalf("ascii-text PSK must commit: %v", err)
		}
		pol := cfg.Security.IPsec.IKEPolicies["pol"]
		if pol.PSK.Reveal() != "secret123" || pol.PSKHex {
			t.Fatalf("pol PSK=%q hex=%v, want secret123 hex=false", pol.PSK.Reveal(), pol.PSKHex)
		}
	})

	t.Run("bogus qualifier refused at commit, warned on tolerant path", func(t *testing.T) {
		cmds := pskHexBase(t, "set security ike policy pol pre-shared-key bogus 6162636431323334")
		if _, err := CompileConfig(buildTree(t, cmds)); err == nil ||
			!strings.Contains(err.Error(), "unsupported pre-shared-key qualifier") ||
			!strings.Contains(err.Error(), "bogus") {
			t.Fatalf("bogus qualifier must be refused at commit, got %v", err)
		}
		lenient, err := CompileConfigLenient(buildTree(t, cmds))
		if err != nil {
			t.Fatalf("tolerant path must not refuse: %v", err)
		}
		warned := false
		for _, w := range lenient.Warnings {
			if strings.Contains(w, "pre-shared-key qualifier") {
				warned = true
			}
		}
		if !warned {
			t.Fatalf("tolerant path must warn about the qualifier, warnings=%v", lenient.Warnings)
		}
		if lenient.Security.IPsec.IKEPolicies["pol"] == nil {
			t.Fatal("tolerant path must keep the policy (render belt fences the value)")
		}
	})

	t.Run("malformed hex refused at commit without echoing the key", func(t *testing.T) {
		for _, val := range []string{"616", "zz11", "0x6162"} {
			cmds := pskHexBase(t, "set security ike policy pol pre-shared-key hexadecimal "+val)
			_, err := CompileConfig(buildTree(t, cmds))
			if err == nil || !strings.Contains(err.Error(), "hexadecimal value is not valid hexadecimal") {
				t.Fatalf("hex %q must be refused, got %v", val, err)
			}
			if strings.Contains(err.Error(), val) && val == "zz11" {
				t.Fatalf("error must not echo key material %q: %v", val, err)
			}
		}
	})

	t.Run("block hexadecimal carries the key", func(t *testing.T) {
		tree := hierTree(t, `security {
  ike {
    proposal p1 { authentication-method pre-shared-keys; encryption-algorithm aes-256-cbc; authentication-algorithm sha-256; dh-group group14; }
    policy pol { proposals p1; pre-shared-key { hexadecimal 6162636431323334; } }
    gateway gw1 { ike-policy pol; address 192.0.2.1; }
  }
  ipsec {
    proposal esp1 { protocol esp; encryption-algorithm aes-256-cbc; authentication-algorithm hmac-sha-256-128; }
    policy ipol { proposals esp1; }
    vpn v1 { bind-interface st0.0; ike { gateway gw1; ipsec-policy ipol; } }
  }
}`)
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("block hexadecimal PSK must commit: %v", err)
		}
		pol := cfg.Security.IPsec.IKEPolicies["pol"]
		if pol == nil || pol.PSK.Reveal() != "6162636431323334" || !pol.PSKHex {
			t.Fatalf("block pol = %+v, want PSK 6162636431323334 hex=true", pol)
		}
	})

	t.Run("block bogus qualifier refused", func(t *testing.T) {
		tree := hierTree(t, `security {
  ike {
    proposal p1 { authentication-method pre-shared-keys; encryption-algorithm aes-256-cbc; authentication-algorithm sha-256; dh-group group14; }
    policy pol { proposals p1; pre-shared-key { bogus deadbeef; } }
    gateway gw1 { ike-policy pol; address 192.0.2.1; }
  }
  ipsec {
    proposal esp1 { protocol esp; encryption-algorithm aes-256-cbc; authentication-algorithm hmac-sha-256-128; }
    policy ipol { proposals esp1; }
    vpn v1 { bind-interface st0.0; ike { gateway gw1; ipsec-policy ipol; } }
  }
}`)
		if _, err := CompileConfig(tree); err == nil ||
			!strings.Contains(err.Error(), "unsupported pre-shared-key qualifier") {
			t.Fatalf("block bogus qualifier must be refused, got %v", err)
		}
	})

	t.Run("vpn-level hexadecimal and bare controls", func(t *testing.T) {
		hexCmds := []string{
			"set security ipsec vpn v1 gateway 192.0.2.1",
			"set security ipsec vpn v1 bind-interface st0.0",
			"set security ipsec vpn v1 pre-shared-key hexadecimal deadbeef01",
		}
		cfg, err := CompileConfigLenient(buildTree(t, hexCmds))
		// Lenient: the default-auth VPN passes the qualifier gate; the
		// strict PSK-presence gate is satisfied by the vpn key itself.
		if err != nil {
			t.Fatalf("lenient vpn hex compile: %v", err)
		}
		vpn := cfg.Security.IPsec.VPNs["v1"]
		if vpn == nil || vpn.PSK.Reveal() != "deadbeef01" || !vpn.PSKHex {
			t.Fatalf("vpn = %+v, want PSK deadbeef01 hex=true", vpn)
		}
		bareCmds := []string{
			"set security ipsec vpn v1 gateway 192.0.2.1",
			"set security ipsec vpn v1 bind-interface st0.0",
			"set security ipsec vpn v1 pre-shared-key fixture-secret",
		}
		cfg2, err := CompileConfigLenient(buildTree(t, bareCmds))
		if err != nil {
			t.Fatalf("lenient vpn bare compile: %v", err)
		}
		vpn2 := cfg2.Security.IPsec.VPNs["v1"]
		if vpn2 == nil || vpn2.PSK.Reveal() != "fixture-secret" || vpn2.PSKHex {
			t.Fatalf("bare vpn = %+v, want PSK fixture-secret hex=false", vpn2)
		}
	})
}
