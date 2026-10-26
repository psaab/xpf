package config

import (
	"strings"
	"testing"
)

// #2691 P2 Surface A config-model tests: the `system services dynamic-dns`
// provider catalog + the per-interface per-family `dynamic-dns` binding compile
// from BOTH the flat-set spelling (ParseSetCommand + SetPath, per CLAUDE.md) AND
// the hierarchical brace form, and the dual-AST shapes compile identically.
// Fail-on-revert: if the compiler/schema wiring is removed these go red.

func TestSurfaceADDNSFlatSetCompiles(t *testing.T) {
	tree := buildTree(t, []string{
		// Provider catalog.
		"set system services dynamic-dns provider corp-2136 backend rfc2136",
		"set system services dynamic-dns provider corp-2136 update-server 192.0.2.53",
		"set system services dynamic-dns provider corp-2136 tsig-key k1",
		"set system services dynamic-dns provider corp-2136 tsig-algorithm hmac-sha256",
		"set system services dynamic-dns provider corp-2136 tsig-secret c2VjcmV0",
		"set system services dynamic-dns forced-refresh 24h",
		"set system services dynamic-dns error-backoff-max 1h",
		"set interfaces ge-0-0-2 vlan-tagging",
		"set interfaces ge-0-0-2 unit 50 vlan-id 50",
		"set interfaces ge-0-0-2 unit 50 family inet dynamic-dns provider corp-2136",
		"set interfaces ge-0-0-2 unit 50 family inet dynamic-dns hostname wan.example.net",
		"set interfaces ge-0-0-2 unit 50 family inet dynamic-dns address-source dhcp",
		"set interfaces ge-0-0-2 unit 50 family inet dynamic-dns ttl 300",
		"set interfaces ge-0-0-2 unit 50 family inet6 dynamic-dns provider corp-2136",
		"set interfaces ge-0-0-2 unit 50 family inet6 dynamic-dns hostname wan6.example.net",
		"set interfaces ge-0-0-2 unit 50 family inet6 dynamic-dns source-address 2001:db8::8",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}

	// Provider catalog.
	if cfg.System.Services == nil || cfg.System.Services.DynamicDNS == nil {
		t.Fatal("system services dynamic-dns did not compile")
	}
	cat := cfg.System.Services.DynamicDNS
	if cat.ForcedRefreshSeconds != 86400 {
		t.Fatalf("forced-refresh 24h => %ds, want 86400", cat.ForcedRefreshSeconds)
	}
	if cat.ErrorBackoffMaxSeconds != 3600 {
		t.Fatalf("error-backoff-max 1h => %ds, want 3600", cat.ErrorBackoffMaxSeconds)
	}
	p := cat.Providers["corp-2136"]
	if p == nil {
		t.Fatal("provider corp-2136 not compiled")
	}
	if p.Backend != "rfc2136" || p.UpdateServer != "192.0.2.53" ||
		p.TSIGKeyName != "k1" || p.TSIGAlgorithm != "hmac-sha256" || p.TSIGSecret.Reveal() != "c2VjcmV0" {
		t.Fatalf("provider corp-2136 mismatch: %+v", p)
	}
	// The secret must be redacted in String() (logging hygiene).
	if strings.Contains(p.String(), "c2VjcmV0") {
		t.Fatalf("provider String() leaked the TSIG secret: %s", p.String())
	}

	// Per-interface bindings.
	unit := cfg.Interfaces.Interfaces["ge-0-0-2"].Units[50]
	if unit == nil {
		t.Fatal("unit 50 not compiled")
	}
	if unit.DynamicDNSInet == nil {
		t.Fatal("family inet dynamic-dns binding not compiled")
	}
	if unit.DynamicDNSInet.Provider != "corp-2136" ||
		unit.DynamicDNSInet.Hostname != "wan.example.net" ||
		unit.DynamicDNSInet.AddressSource != "dhcp" ||
		unit.DynamicDNSInet.TTLSeconds != 300 {
		t.Fatalf("inet binding mismatch: %+v", unit.DynamicDNSInet)
	}
	if unit.DynamicDNSInet6 == nil {
		t.Fatal("family inet6 dynamic-dns binding not compiled")
	}
	if unit.DynamicDNSInet6.Provider != "corp-2136" ||
		unit.DynamicDNSInet6.Hostname != "wan6.example.net" ||
		unit.DynamicDNSInet6.SourceAddress != "2001:db8::8" {
		t.Fatalf("inet6 binding mismatch: %+v", unit.DynamicDNSInet6)
	}
	// The two families are INDEPENDENT (distinct fields, not field-merged).
	if unit.DynamicDNSInet.Hostname == unit.DynamicDNSInet6.Hostname {
		t.Fatal("inet and inet6 bindings must be independent")
	}
}

func TestSurfaceADDNSHierarchicalCompilesIdentically(t *testing.T) {
	src := `system {
  services {
    dynamic-dns {
      provider corp-2136 {
        backend rfc2136;
        update-server 192.0.2.53;
        tsig-key k1;
        tsig-algorithm hmac-sha256;
        tsig-secret c2VjcmV0;
      }
      forced-refresh 24h;
    }
  }
}
interfaces {
  ge-0-0-2 {
    vlan-tagging;
    unit 50 {
      vlan-id 50;
      family inet {
        dynamic-dns {
          provider corp-2136;
          hostname wan.example.net;
          address-source dhcp;
          ttl 300;
        }
      }
    }
  }
}
`
	hp := NewParser(src)
	tree, perrs := hp.Parse()
	if len(perrs) != 0 {
		t.Fatalf("Parse(hier): %v", perrs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig(hier): %v", err)
	}
	cat := cfg.System.Services.DynamicDNS
	if cat == nil || cat.Providers["corp-2136"] == nil {
		t.Fatal("hierarchical provider catalog did not compile")
	}
	if cat.ForcedRefreshSeconds != 86400 {
		t.Fatalf("hier forced-refresh => %d, want 86400", cat.ForcedRefreshSeconds)
	}
	unit := cfg.Interfaces.Interfaces["ge-0-0-2"].Units[50]
	if unit == nil || unit.DynamicDNSInet == nil {
		t.Fatal("hierarchical inet binding did not compile")
	}
	if unit.DynamicDNSInet.Provider != "corp-2136" ||
		unit.DynamicDNSInet.Hostname != "wan.example.net" ||
		unit.DynamicDNSInet.AddressSource != "dhcp" ||
		unit.DynamicDNSInet.TTLSeconds != 300 {
		t.Fatalf("hier inet binding mismatch: %+v", unit.DynamicDNSInet)
	}
}

func TestSurfaceADDNSAbsentCompilesToNil(t *testing.T) {
	tree := buildTree(t, []string{
		"set interfaces ge-0-0-0 unit 0 family inet address 10.0.1.10/24",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if cfg.System.Services != nil && cfg.System.Services.DynamicDNS != nil {
		t.Fatal("absent system services dynamic-dns must compile to nil")
	}
	if u := cfg.Interfaces.Interfaces["ge-0-0-0"].Units[0]; u != nil && u.DynamicDNSInet != nil {
		t.Fatal("absent per-interface dynamic-dns must compile to nil")
	}
}

func TestSurfaceADDNSWarnsOnUndefinedProviderAndMissingHostname(t *testing.T) {
	tree := buildTree(t, []string{
		// Binding referencing a provider that is not in the catalog, and a
		"set interfaces ge-0-0-2 vlan-tagging",
		"set interfaces ge-0-0-2 unit 50 vlan-id 50",
		"set interfaces ge-0-0-2 unit 50 family inet dynamic-dns provider ghost",
		"set interfaces ge-0-0-2 unit 50 family inet dynamic-dns hostname wan.example.net",
		"set interfaces ge-0-0-3 unit 0 family inet dynamic-dns provider corp-2136",
		"set system services dynamic-dns provider corp-2136 backend rfc2136",
		// rfc2136 provider with no update-server → warn.
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	warnings := validateSurfaceADDNSWarnings(cfg)
	joined := strings.Join(warnings, "\n")
	if !strings.Contains(joined, "undefined provider \"ghost\"") {
		t.Fatalf("expected undefined-provider warning, got:\n%s", joined)
	}
	if !strings.Contains(joined, "no hostname is set") {
		t.Fatalf("expected missing-hostname warning, got:\n%s", joined)
	}
	if !strings.Contains(joined, "no update-server") {
		t.Fatalf("expected provider-no-update-server warning, got:\n%s", joined)
	}
}

// TestSurfaceADDNSWarnsCheckIPSourceWithoutURL is the #4423 H08 commit-warning
// gate: a binding that selects `address-source checkip` while its provider
// carries NO checkip-url must be flagged at commit — the runtime fails closed
// and publishes nothing for the scope (it must NOT fall back to the interface
// address). A binding whose provider DOES carry a checkip-url is not flagged.
// RED-on-revert: drop the H08 warn block in compiler_validate_warn.go and the
// urlless binding is no longer flagged.
func TestSurfaceADDNSWarnsCheckIPSourceWithoutURL(t *testing.T) {
	tree := buildTree(t, []string{
		"set interfaces ge-0-0-2 vlan-tagging",
		"set interfaces ge-0-0-2 unit 50 vlan-id 50",
		"set interfaces ge-0-0-2 unit 50 family inet dynamic-dns provider nourl",
		"set interfaces ge-0-0-2 unit 50 family inet dynamic-dns hostname wan.example.net",
		"set interfaces ge-0-0-2 unit 50 family inet dynamic-dns address-source checkip",
		// Provider WITHOUT a checkip-url; a binding selects address-source checkip.
		"set system services dynamic-dns provider nourl backend rfc2136",
		"set system services dynamic-dns provider nourl update-server 192.0.2.53",
		"set system services dynamic-dns provider withurl backend rfc2136",
		"set system services dynamic-dns provider withurl update-server 192.0.2.53",
		"set system services dynamic-dns provider withurl checkip-url https://ip.example.net",
		"set interfaces ge-0-0-3 unit 0 family inet dynamic-dns provider withurl",
		"set interfaces ge-0-0-3 unit 0 family inet dynamic-dns hostname ok.example.net",
		"set interfaces ge-0-0-3 unit 0 family inet dynamic-dns address-source checkip",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	warnings := validateSurfaceADDNSWarnings(cfg)
	joined := strings.Join(warnings, "\n")
	if !strings.Contains(joined, "address-source checkip but provider \"nourl\" has no checkip-url") {
		t.Fatalf("expected checkip-without-url warning for provider nourl, got:\n%s", joined)
	}
	if strings.Contains(joined, "provider \"withurl\" has no checkip-url") {
		t.Fatalf("a provider WITH a checkip-url must not be flagged, got:\n%s", joined)
	}
}

// TestSurfaceADDNSWarnsNoTSIG is the #4483 commit-warn fail-on-revert proof for
// the Surface A provider catalog: an rfc2136 provider with an update-server but
// NO tsig-key must warn that UPDATEs are sent unsigned and the response rcode is
// forgeable. A provider with a complete TSIG tuple must NOT emit that warning.
func TestSurfaceADDNSWarnsNoTSIG(t *testing.T) {
	tree := buildTree(t, []string{
		"set interfaces ge-0-0-2 vlan-tagging",
		"set interfaces ge-0-0-2 unit 50 vlan-id 50",
		"set interfaces ge-0-0-2 unit 50 family inet dynamic-dns provider nokey",
		"set interfaces ge-0-0-2 unit 50 family inet dynamic-dns hostname wan.example.net",
		// rfc2136 provider WITH update-server but no tsig-key → unsigned warn.
		"set system services dynamic-dns provider nokey backend rfc2136",
		"set system services dynamic-dns provider nokey update-server 192.0.2.53",
		"set system services dynamic-dns provider withkey backend rfc2136",
		"set system services dynamic-dns provider withkey update-server 192.0.2.53",
		"set system services dynamic-dns provider withkey tsig-key k1",
		"set system services dynamic-dns provider withkey tsig-algorithm hmac-sha256",
		"set system services dynamic-dns provider withkey tsig-secret c2VjcmV0",
		"set interfaces ge-0-0-3 unit 0 family inet dynamic-dns provider withkey",
		"set interfaces ge-0-0-3 unit 0 family inet dynamic-dns hostname wan2.example.net",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	joined := strings.Join(validateSurfaceADDNSWarnings(cfg), "\n")
	if !strings.Contains(joined, "provider \"nokey\"") ||
		!strings.Contains(joined, "no tsig-key") || !strings.Contains(joined, "forgeable") {
		t.Fatalf("provider nokey (update-server, no tsig-key) must warn unsigned/forgeable, got:\n%s", joined)
	}
	// The complete-tuple provider must not be dragged into the unsigned warning.
	if strings.Contains(joined, "provider \"withkey\"") && strings.Contains(joined, "no tsig-key") {
		t.Fatalf("a provider WITH a tsig-key must not warn about unsigned updates, got:\n%s", joined)
	}
}
