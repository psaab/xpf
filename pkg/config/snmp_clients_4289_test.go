package config

import (
	"testing"
)

// #4289 (fable-review-167 S-3): the SNMP community `clients` source-IP
// restriction was silently ignored (parsed nothing, served every source). The
// compiler now captures the allowlist and SNMPCommunity.AllowsSource enforces
// it. These tests pin the parse (both AST shapes + the `restrict` modifier) and
// the longest-prefix-match / default-deny / allow-all semantics.

func communityFrom(t *testing.T, tree *ConfigTree, name string) *SNMPCommunity {
	t.Helper()
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if cfg.System.SNMP == nil {
		t.Fatal("no SNMP config compiled")
	}
	c := cfg.System.SNMP.Communities[name]
	if c == nil {
		t.Fatalf("community %q not compiled", name)
	}
	return c
}

// Flat-set parse of `clients` (with a trailing `restrict`) plus the AllowsSource
// semantics. RED-on-revert: without the compileSNMP clients parse, Clients is
// empty → AllowsSource returns allow-all → the 8.8.8.8 assertion (deny) flips.
func TestSNMPClientsFlatSetParseAndEnforce(t *testing.T) {
	c := communityFrom(t, buildTreeFromSet(t, []string{
		"set snmp community public authorization read-only",
		"set snmp community public clients 10.0.0.0/24",
		"set snmp community public clients 192.168.1.5",
		"set snmp community public clients 0.0.0.0/0 restrict",
	}), "public")

	if len(c.Clients) != 3 {
		t.Fatalf("expected 3 client entries, got %+v", c.Clients)
	}
	cases := map[string]bool{
		"10.0.0.5":    true,  // in 10.0.0.0/24
		"192.168.1.5": true,  // /32 host
		"8.8.8.8":     false, // only 0.0.0.0/0 restrict matches → deny
	}
	for src, want := range cases {
		if got := c.AllowsSource(snmpClientTestSource10687(src)); got != want {
			t.Errorf("AllowsSource(%s) = %v, want %v", src, got, want)
		}
	}
}

// Hierarchical parse with longest-prefix-match: a /24 restrict inside a /16
// allow denies the /24 while the rest of the /16 is allowed. A source matching
// no entry is denied (clients configured = default-deny for the unlisted).
func TestSNMPClientsHierLongestPrefix(t *testing.T) {
	c := communityFrom(t, parseHier(t, `
snmp {
    community mgmt {
        authorization read-only;
        clients {
            10.1.0.0/16;
            10.1.2.0/24 restrict;
        }
    }
}
`), "mgmt")

	cases := map[string]bool{
		"10.1.5.1":  true,  // allowed by /16
		"10.1.2.9":  false, // denied by /24 restrict (longest match)
		"192.0.2.1": false, // no match → default-deny
	}
	for src, want := range cases {
		if got := c.AllowsSource(snmpClientTestSource10687(src)); got != want {
			t.Errorf("AllowsSource(%s) = %v, want %v", src, got, want)
		}
	}
}

// A community without `clients` is allow-all (Junos default) — the enforcement
// must not change the common unscoped case.
func TestSNMPClientsAbsentIsAllowAll(t *testing.T) {
	c := communityFrom(t, parseHier(t, `snmp { community open { authorization read-only; } }`), "open")
	if len(c.Clients) != 0 {
		t.Fatalf("expected no clients, got %+v", c.Clients)
	}
	for _, src := range []string{"10.0.0.1", "8.8.8.8", "2001:db8::1"} {
		if !c.AllowsSource(snmpClientTestSource10687(src)) {
			t.Errorf("AllowsSource(%s) = false on an unscoped community, want allow-all", src)
		}
	}
}

// IPv6 prefixes are honored too.
func TestSNMPClientsIPv6(t *testing.T) {
	c := communityFrom(t, parseHier(t, `
snmp {
    community v6 {
        authorization read-only;
        clients {
            2001:db8::/32;
        }
    }
}
`), "v6")
	if got := c.AllowsSource(snmpClientTestSource10687("2001:db8::1")); !got {
		t.Error("AllowsSource(2001:db8::1) = false, want true (in 2001:db8::/32)")
	}
	if got := c.AllowsSource(snmpClientTestSource10687("2001:dead::1")); got {
		t.Error("AllowsSource(2001:dead::1) = true, want false (outside 2001:db8::/32)")
	}
}
