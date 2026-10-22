package config

import (
	"strings"
	"testing"
)

// #1387 DHCP dynamic-dns config-model tests. All use the production
// ParseSetCommand + SetPath path (buildTree), never NewParser (the
// flat-set merge gotcha in CLAUDE.md). They prove the dual-AST compile,
// the empty-block-is-absent guard, TSIG redaction, and the schema typed
// leaves (enum + ttl validators) at commit check.

func ddnsOf(t *testing.T, cfg *Config) *DHCPDynamicDNSConfig {
	t.Helper()
	return cfg.System.DHCPServer.DynamicDNS
}

// ddnsV6Of returns the IPv6-family DDNS policy (#2691 P1b / #2663: v4 and v6
// now compile to independent fields instead of one field-merged struct).
func ddnsV6Of(t *testing.T, cfg *Config) *DHCPDynamicDNSConfig {
	t.Helper()
	return cfg.System.DHCPServer.DynamicDNSv6
}

func TestDHCPDDNSHierarchicalAndFlatSetCompileEqually(t *testing.T) {
	// Dual-AST equality: the hierarchical block and the flat-set spelling
	// must compile to the same typed DHCPDynamicDNSConfig (plan §5 inv 5).
	flat := buildTree(t, []string{
		"set system services dhcp-local-server dynamic-dns enable",
		"set system services dhcp-local-server dynamic-dns domain corp.example.com",
		"set system services dhcp-local-server dynamic-dns ttl 600",
		"set system services dhcp-local-server dynamic-dns hostname-source fqdn",
		"set system services dhcp-local-server dynamic-dns conflict-policy strict-fail",
		"set system services dhcp-local-server dynamic-dns backend rfc2136",
		"set system services dhcp-local-server dynamic-dns update-server 192.0.2.53",
		"set system services dhcp-local-server dynamic-dns tsig-key xpf-key",
		"set system services dhcp-local-server dynamic-dns tsig-algorithm hmac-sha256",
		"set system services dhcp-local-server dynamic-dns tsig-secret c2VjcmV0",
	})
	cflat, err := CompileConfig(flat)
	if err != nil {
		t.Fatalf("CompileConfig(flat): %v", err)
	}
	df := ddnsOf(t, cflat)
	if df == nil {
		t.Fatal("flat-set DDNS compiled to nil")
	}

	want := &DHCPDynamicDNSConfig{
		Enabled:        true,
		Domain:         "corp.example.com",
		TTLSeconds:     600,
		HostnameSource: "fqdn",
		ConflictPolicy: "strict-fail",
		Backend:        "rfc2136",
		UpdateServer:   "192.0.2.53",
		TSIGKeyName:    "xpf-key",
		TSIGAlgorithm:  "hmac-sha256",
		TSIGSecret:     NewSecret("c2VjcmV0"),
	}
	if *df != *want {
		t.Fatalf("flat-set DDNS mismatch:\n got %+v\nwant %+v", *df, *want)
	}

	// Hierarchical NewParser path: build the same content through the
	// real parser to prove the hierarchical AST compiles identically.
	hierSrc := `system {
  services {
    dhcp-local-server {
      dynamic-dns {
        enable;
        domain corp.example.com;
        ttl 600;
        hostname-source fqdn;
        conflict-policy strict-fail;
        backend rfc2136;
        update-server 192.0.2.53;
        tsig-key xpf-key;
        tsig-algorithm hmac-sha256;
        tsig-secret c2VjcmV0;
      }
    }
  }
}`
	hp := NewParser(hierSrc)
	htree, perrs := hp.Parse()
	if len(perrs) > 0 {
		t.Fatalf("hierarchical Parse: %v", perrs)
	}
	chier, err := CompileConfig(htree)
	if err != nil {
		t.Fatalf("CompileConfig(hier): %v", err)
	}
	dh := ddnsOf(t, chier)
	if dh == nil {
		t.Fatal("hierarchical DDNS compiled to nil")
	}
	if *dh != *df {
		t.Fatalf("hierarchical vs flat-set DDNS differ:\n hier %+v\n flat %+v", *dh, *df)
	}
}

func TestDHCPDDNSAbsentByDefault(t *testing.T) {
	// No dynamic-dns stanza => nil block => zero behaviour change.
	cfg, err := CompileConfig(buildTree(t, []string{
		"set system services dhcp-local-server group g0 interface ge-0/0/0",
		"set system services dhcp-local-server group g0 pool p0 subnet 10.0.1.0/24",
	}))
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if ddnsOf(t, cfg) != nil {
		t.Fatal("absent dynamic-dns must compile to nil DynamicDNS")
	}
}

func TestDHCPDDNSV6BlockCompiles(t *testing.T) {
	cfg, err := CompileConfig(buildTree(t, []string{
		"set system services dhcpv6-local-server dynamic-dns enable",
		"set system services dhcpv6-local-server dynamic-dns domain v6.example.com",
	}))
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	// #2691 P1b / #2663: a v6-only block now compiles to the INDEPENDENT
	// DynamicDNSv6 field (not field-merged into DynamicDNS). The v4 field stays
	// nil (no v4 DDNS configured).
	d := ddnsV6Of(t, cfg)
	if d == nil || !d.Enabled || d.Domain != "v6.example.com" {
		t.Fatalf("v6 dynamic-dns not compiled into DynamicDNSv6: %+v", d)
	}
	if ddnsOf(t, cfg) != nil {
		t.Fatalf("v6-only block must leave the v4 DynamicDNS field nil, got %+v", ddnsOf(t, cfg))
	}
}

// TestDHCPDDNSDualFamilyIndependentPolicy proves the #2691 P1b / #2663 fix:
// when BOTH dhcp-local-server AND dhcpv6-local-server carry a dynamic-dns
// block, the two families compile to INDEPENDENT policies (DynamicDNS vs
// DynamicDNSv6) — NOT one field-merged struct. A v4 block and a v6 block keep
// their OWN domain / server / ttl, so an operator can direct v4 leases to one
// zone/server and v6 leases to another. This is the deliberate behaviour change
// from the pre-P1b field-merge (under which a v6 `domain` silently filled an
// empty v4 field and a single struct could not represent two servers).
func TestDHCPDDNSDualFamilyIndependentPolicy(t *testing.T) {
	cfg, err := CompileConfig(buildTree(t, []string{
		"set system services dhcp-local-server dynamic-dns enable",
		"set system services dhcp-local-server dynamic-dns domain v4.example.com",
		"set system services dhcp-local-server dynamic-dns update-server 192.0.2.53",
		"set system services dhcp-local-server dynamic-dns ttl 600",
		"set system services dhcpv6-local-server dynamic-dns enable",
		"set system services dhcpv6-local-server dynamic-dns domain v6.example.com",
		"set system services dhcpv6-local-server dynamic-dns update-server 2001:db8::53",
		"set system services dhcpv6-local-server dynamic-dns ttl 1200",
	}))
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	v4 := ddnsOf(t, cfg)
	v6 := ddnsV6Of(t, cfg)
	if v4 == nil || v6 == nil {
		t.Fatalf("both families must compile to a policy: v4=%+v v6=%+v", v4, v6)
	}
	// v4 keeps ITS settings; v6 keeps ITS settings — independent, never merged.
	if v4.Domain != "v4.example.com" || v4.UpdateServer != "192.0.2.53" || v4.TTLSeconds != 600 {
		t.Fatalf("v4 policy not independent: %+v", v4)
	}
	if v6.Domain != "v6.example.com" || v6.UpdateServer != "2001:db8::53" || v6.TTLSeconds != 1200 {
		t.Fatalf("v6 policy not independent: %+v", v6)
	}
	// The cardinal #2663 assertion: a v6 field never bled into the v4 struct.
	if v4.Domain == v6.Domain || v4.UpdateServer == v6.UpdateServer {
		t.Fatalf("v4 and v6 policies were merged (not independent): v4=%+v v6=%+v", v4, v6)
	}
}

// TestDHCPDDNSSingleFamilyAppliesToBoth proves backward compatibility (#2691
// P1b / plan §5.9): a pre-P1b config that set the dynamic-dns block under only
// ONE family still works — the engine inherits that single policy for the other
// family at reconcile time (ReconcileScoped). At the COMPILE layer the v4 block
// lands in DynamicDNS and DynamicDNSv6 stays nil; the inheritance is a runtime
// (engine) concern, asserted in pkg/ddns. Here we only prove the v4 block
// compiles into the v4 field and the v6 field is nil (no silent v6 struct).
func TestDHCPDDNSSingleFamilyAppliesToBoth(t *testing.T) {
	cfg, err := CompileConfig(buildTree(t, []string{
		"set system services dhcp-local-server dynamic-dns enable",
		"set system services dhcp-local-server dynamic-dns domain corp.example.com",
		"set system services dhcp-local-server dynamic-dns update-server 192.0.2.53",
	}))
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	v4 := ddnsOf(t, cfg)
	if v4 == nil || !v4.Enabled || v4.Domain != "corp.example.com" {
		t.Fatalf("v4 block not compiled: %+v", v4)
	}
	if ddnsV6Of(t, cfg) != nil {
		t.Fatalf("v4-only block must leave DynamicDNSv6 nil (engine inherits at reconcile), got %+v", ddnsV6Of(t, cfg))
	}
}

func TestDHCPDDNSStringRedactsTSIGSecret(t *testing.T) {
	d := &DHCPDynamicDNSConfig{
		Enabled:       true,
		TSIGKeyName:   "k",
		TSIGAlgorithm: "hmac-sha256",
		TSIGSecret:    NewSecret("TOPSECRET-base64=="),
	}
	s := d.String()
	if strings.Contains(s, "TOPSECRET") {
		t.Fatalf("String() leaked TSIG secret: %q", s)
	}
	if !strings.Contains(s, "<redacted>") {
		t.Fatalf("String() did not redact a set secret: %q", s)
	}
	// An unset secret renders empty, not <redacted>.
	d.TSIGSecret = NewSecret("")
	if strings.Contains(d.String(), "<redacted>") {
		t.Fatalf("String() redacted an empty secret: %q", d.String())
	}
}

func TestDHCPDDNSSchemaAcceptsValidLeaves(t *testing.T) {
	tree := buildTree(t, []string{
		"set system services dhcp-local-server dynamic-dns enable",
		"set system services dhcp-local-server dynamic-dns ttl 300",
		"set system services dhcp-local-server dynamic-dns hostname-source client-hostname",
		"set system services dhcp-local-server dynamic-dns conflict-policy replace-owned",
		"set system services dhcp-local-server dynamic-dns backend rfc2136",
	})
	if err := SchemaValidate(tree); err != nil {
		t.Fatalf("SchemaValidate rejected valid DDNS leaves: %v", err)
	}
}

// TestDHCPDDNSSourceBindingLeaves proves the #2691 P1b / #2665 source-binding
// leaves (source-address / destination-interface / routing-instance) pass
// schema validation AND compile onto the typed policy.
func TestDHCPDDNSSourceBindingLeaves(t *testing.T) {
	lines := []string{
		"set system services dhcp-local-server dynamic-dns enable",
		"set system services dhcp-local-server dynamic-dns domain example.com",
		"set system services dhcp-local-server dynamic-dns update-server 192.0.2.53",
		"set system services dhcp-local-server dynamic-dns source-address 10.0.0.9",
		"set system services dhcp-local-server dynamic-dns destination-interface ge-0/0/2.50",
		"set system services dhcp-local-server dynamic-dns routing-instance VRF-WAN",
	}
	tree := buildTree(t, lines)
	if err := SchemaValidate(tree); err != nil {
		t.Fatalf("SchemaValidate rejected source-binding leaves: %v", err)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	d := ddnsOf(t, cfg)
	if d == nil {
		t.Fatal("source-binding block compiled to nil")
	}
	if d.SourceAddress != "10.0.0.9" {
		t.Fatalf("source-address not compiled: %q", d.SourceAddress)
	}
	if d.DestinationInterface != "ge-0/0/2.50" {
		t.Fatalf("destination-interface not compiled: %q", d.DestinationInterface)
	}
	if d.RoutingInstance != "VRF-WAN" {
		t.Fatalf("routing-instance not compiled: %q", d.RoutingInstance)
	}
}

// TestDHCPDDNSBackendWarnings proves the #1387 inc-2 commit warnings: the
// increment-1 "backend deferred / no records published" warning is RETIRED
// (the live RFC 2136 backend is now wired). The warnings here flag a config
// the now-live path cannot act on, all WARN-only (never an error) so a
// previously-inert malformed value cannot brick a boot (plan §4.5 / §7 Q-C).
func TestDHCPDDNSBackendWarnings(t *testing.T) {
	hasDDNSWarn := func(ws []string, substr string) (string, bool) {
		for _, w := range ws {
			if strings.Contains(w, "dhcp dynamic-dns") && strings.Contains(w, substr) {
				return w, true
			}
		}
		return "", false
	}
	anyDeferred := func(ws []string) bool {
		for _, w := range ws {
			if strings.Contains(w, "deferred") || strings.Contains(w, "no records are published") {
				return true
			}
		}
		return false
	}

	t.Run("retired deferred warning when rfc2136 + update-server set", func(t *testing.T) {
		cfg, err := CompileConfig(buildTree(t, []string{
			"set system services dhcp-local-server dynamic-dns enable",
			"set system services dhcp-local-server dynamic-dns domain corp.example.com",
			"set system services dhcp-local-server dynamic-dns update-server 192.0.2.53",
		}))
		if err != nil {
			t.Fatalf("CompileConfig: %v", err)
		}
		ws := ValidateConfig(cfg)
		if anyDeferred(ws) {
			t.Fatalf("the inc-1 deferred-backend warning must be retired in inc-2: %v", ws)
		}
		if _, ok := hasDDNSWarn(ws, "no update-server"); ok {
			t.Fatalf("a configured update-server must not warn about a missing one: %v", ws)
		}
	})

	t.Run("enabled rfc2136 with no update-server warns", func(t *testing.T) {
		cfg, err := CompileConfig(buildTree(t, []string{
			"set system services dhcp-local-server dynamic-dns enable",
			"set system services dhcp-local-server dynamic-dns domain corp.example.com",
		}))
		if err != nil {
			t.Fatalf("CompileConfig: %v", err)
		}
		if _, ok := hasDDNSWarn(ValidateConfig(cfg), "no update-server"); !ok {
			t.Fatal("enabled rfc2136 without an update-server must warn")
		}
	})

	t.Run("kea-d2 still deferred", func(t *testing.T) {
		cfg, err := CompileConfig(buildTree(t, []string{
			"set system services dhcp-local-server dynamic-dns enable",
			"set system services dhcp-local-server dynamic-dns backend kea-d2",
		}))
		if err != nil {
			t.Fatalf("CompileConfig: %v", err)
		}
		if _, ok := hasDDNSWarn(ValidateConfig(cfg), "kea-d2"); !ok {
			t.Fatal("kea-d2 backend must warn that it is not implemented")
		}
	})

	t.Run("malformed update-server warns (WARN-only, no error)", func(t *testing.T) {
		cfg, err := CompileConfig(buildTree(t, []string{
			"set system services dhcp-local-server dynamic-dns enable",
			// A quoted value with embedded whitespace is not a usable host.
			`set system services dhcp-local-server dynamic-dns update-server "bad host"`,
		}))
		if err != nil {
			t.Fatalf("CompileConfig must NOT error on a malformed update-server (Q-C): %v", err)
		}
		if _, ok := hasDDNSWarn(ValidateConfig(cfg), "not a valid host"); !ok {
			t.Fatal("a malformed update-server must warn")
		}
	})

	t.Run("bad tsig-algorithm warns", func(t *testing.T) {
		cfg, err := CompileConfig(buildTree(t, []string{
			"set system services dhcp-local-server dynamic-dns enable",
			"set system services dhcp-local-server dynamic-dns update-server 192.0.2.53",
			"set system services dhcp-local-server dynamic-dns tsig-key k1",
			"set system services dhcp-local-server dynamic-dns tsig-algorithm hmac-md5",
		}))
		if err != nil {
			t.Fatalf("CompileConfig: %v", err)
		}
		if _, ok := hasDDNSWarn(ValidateConfig(cfg), "tsig-algorithm"); !ok {
			t.Fatal("hmac-md5 (insecure) tsig-algorithm must warn")
		}
	})

	t.Run("valid hmac-sha256 default is silent", func(t *testing.T) {
		cfg, err := CompileConfig(buildTree(t, []string{
			"set system services dhcp-local-server dynamic-dns enable",
			"set system services dhcp-local-server dynamic-dns update-server 192.0.2.53",
			"set system services dhcp-local-server dynamic-dns tsig-key k1",
			"set system services dhcp-local-server dynamic-dns tsig-secret c2VjcmV0",
		}))
		if err != nil {
			t.Fatalf("CompileConfig: %v", err)
		}
		ws := ValidateConfig(cfg)
		if _, ok := hasDDNSWarn(ws, "tsig-algorithm"); ok {
			t.Fatalf("default hmac-sha256 must not warn: %v", ws)
		}
		if _, ok := hasDDNSWarn(ws, "no update-server"); ok {
			t.Fatalf("a configured update-server must not warn: %v", ws)
		}
	})

	// #2666 / #2691 P0: TSIG tuple completeness. RFC 8945 needs the full
	// {key name, algorithm, secret} triple. An incomplete tuple commits today
	// and fails only at runtime (BADKEY/BADSIG); warn at commit instead.
	// fail-on-revert: removing the keySet/secretSet switch in
	// validateDDNSBackendWarnings makes both "warns" subtests go red (no
	// tsig-secret / no tsig-key warning is emitted).
	t.Run("tsig-key without tsig-secret warns (#2666)", func(t *testing.T) {
		cfg, err := CompileConfig(buildTree(t, []string{
			"set system services dhcp-local-server dynamic-dns enable",
			"set system services dhcp-local-server dynamic-dns update-server 192.0.2.53",
			"set system services dhcp-local-server dynamic-dns tsig-key k1",
			"set system services dhcp-local-server dynamic-dns tsig-algorithm hmac-sha256",
		}))
		if err != nil {
			t.Fatalf("CompileConfig must NOT error on an incomplete TSIG tuple (Q-C): %v", err)
		}
		ws := ValidateConfig(cfg)
		w, ok := hasDDNSWarn(ws, "tsig-secret is empty")
		if !ok {
			t.Fatalf("tsig-key without tsig-secret must warn: %v", ws)
		}
		if !strings.Contains(w, "tsig-key is set") {
			t.Errorf("the warn must name the incomplete side: %q", w)
		}
	})

	t.Run("tsig-secret without tsig-key warns (#2666)", func(t *testing.T) {
		cfg, err := CompileConfig(buildTree(t, []string{
			"set system services dhcp-local-server dynamic-dns enable",
			"set system services dhcp-local-server dynamic-dns update-server 192.0.2.53",
			"set system services dhcp-local-server dynamic-dns tsig-secret c2VjcmV0",
		}))
		if err != nil {
			t.Fatalf("CompileConfig must NOT error on an incomplete TSIG tuple (Q-C): %v", err)
		}
		ws := ValidateConfig(cfg)
		if _, ok := hasDDNSWarn(ws, "tsig-secret is set but"); !ok {
			t.Fatalf("tsig-secret without tsig-key must warn (ignored): %v", ws)
		}
	})

	t.Run("complete TSIG tuple is silent (#2666)", func(t *testing.T) {
		cfg, err := CompileConfig(buildTree(t, []string{
			"set system services dhcp-local-server dynamic-dns enable",
			"set system services dhcp-local-server dynamic-dns update-server 192.0.2.53",
			"set system services dhcp-local-server dynamic-dns tsig-key k1",
			"set system services dhcp-local-server dynamic-dns tsig-algorithm hmac-sha256",
			"set system services dhcp-local-server dynamic-dns tsig-secret c2VjcmV0",
		}))
		if err != nil {
			t.Fatalf("CompileConfig: %v", err)
		}
		ws := ValidateConfig(cfg)
		if _, ok := hasDDNSWarn(ws, "tsig-secret is empty"); ok {
			t.Fatalf("a complete TSIG tuple must not warn key-without-secret: %v", ws)
		}
		if _, ok := hasDDNSWarn(ws, "tsig-secret is set but"); ok {
			t.Fatalf("a complete TSIG tuple must not warn secret-without-key: %v", ws)
		}
	})

	t.Run("incomplete TSIG tuple does not hard-fail the commit (#2666)", func(t *testing.T) {
		// The whole point of the WARN-only posture: a previously-inert
		// incomplete TSIG config must still COMMIT (CompileConfig succeeds and
		// ValidateConfig returns warnings, never an error/panic).
		cfg, err := CompileConfig(buildTree(t, []string{
			"set system services dhcp-local-server dynamic-dns enable",
			"set system services dhcp-local-server dynamic-dns update-server 192.0.2.53",
			"set system services dhcp-local-server dynamic-dns tsig-key k1",
		}))
		if err != nil {
			t.Fatalf("an incomplete TSIG tuple must NOT brick the commit: %v", err)
		}
		if _, ok := hasDDNSWarn(ValidateConfig(cfg), "tsig-secret is empty"); !ok {
			t.Fatal("the incomplete tuple must still warn")
		}
	})

	t.Run("absent or disabled is silent", func(t *testing.T) {
		cfgAbsent, err := CompileConfig(buildTree(t, []string{
			"set system services dhcp-local-server group g0 interface ge-0/0/0",
		}))
		if err != nil {
			t.Fatalf("CompileConfig(absent): %v", err)
		}
		for _, w := range ValidateConfig(cfgAbsent) {
			if strings.Contains(w, "dhcp dynamic-dns") {
				t.Fatalf("absent DDNS must emit no warnings: %q", w)
			}
		}
		cfgDisabled, err := CompileConfig(buildTree(t, []string{
			"set system services dhcp-local-server dynamic-dns domain corp.example.com",
		}))
		if err != nil {
			t.Fatalf("CompileConfig(disabled): %v", err)
		}
		for _, w := range ValidateConfig(cfgDisabled) {
			if strings.Contains(w, "dhcp dynamic-dns") {
				t.Fatalf("disabled DDNS must emit no warnings: %q", w)
			}
		}
	})
}

func TestDHCPDDNSSchemaRejectsBadEnumAndTTL(t *testing.T) {
	cases := []struct {
		name string
		line string
	}{
		{"bad hostname-source", "set system services dhcp-local-server dynamic-dns hostname-source bogus"},
		{"bad conflict-policy", "set system services dhcp-local-server dynamic-dns conflict-policy maybe"},
		{"bad backend", "set system services dhcp-local-server dynamic-dns backend windows-dns"},
		{"zero ttl", "set system services dhcp-local-server dynamic-dns ttl 0"},
		{"garbage ttl", "set system services dhcp-local-server dynamic-dns ttl notanumber"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildTree(t, []string{tc.line})
			if err := SchemaValidate(tree); err == nil {
				t.Fatalf("SchemaValidate accepted invalid leaf %q", tc.line)
			}
		})
	}
}

// TestDHCPDDNSNoTSIGUnsignedWarning is the #4483 commit-warn fail-on-revert
// proof: a DHCP dynamic-dns update-server configured with NO tsig-key must
// warn that DNS UPDATEs are sent unsigned and the response rcode is forgeable.
// A config WITH a complete TSIG tuple must NOT emit that warning. Reverting the
// no-tsig branch in validateDDNSBackendWarnings makes the first subtest go red.
func TestDHCPDDNSNoTSIGUnsignedWarning(t *testing.T) {
	hasWarn := func(ws []string, substr string) bool {
		for _, w := range ws {
			if strings.Contains(w, "dhcp dynamic-dns") && strings.Contains(w, substr) {
				return true
			}
		}
		return false
	}

	t.Run("update-server without tsig-key warns unsigned/forgeable", func(t *testing.T) {
		cfg, err := CompileConfig(buildTree(t, []string{
			"set system services dhcp-local-server dynamic-dns enable",
			"set system services dhcp-local-server dynamic-dns domain corp.example.com",
			"set system services dhcp-local-server dynamic-dns update-server 192.0.2.53",
		}))
		if err != nil {
			t.Fatalf("CompileConfig must NOT error on a no-TSIG update-server: %v", err)
		}
		ws := ValidateConfig(cfg)
		if !hasWarn(ws, "unsigned") {
			t.Fatalf("an update-server with no tsig-key must warn that updates are unsigned: %v", ws)
		}
		if !hasWarn(ws, "forgeable") {
			t.Fatalf("the warn must name the forgeable-response consequence: %v", ws)
		}
	})

	t.Run("complete TSIG tuple emits no unsigned warning", func(t *testing.T) {
		cfg, err := CompileConfig(buildTree(t, []string{
			"set system services dhcp-local-server dynamic-dns enable",
			"set system services dhcp-local-server dynamic-dns domain corp.example.com",
			"set system services dhcp-local-server dynamic-dns update-server 192.0.2.53",
			"set system services dhcp-local-server dynamic-dns tsig-key k1",
			"set system services dhcp-local-server dynamic-dns tsig-algorithm hmac-sha256",
			"set system services dhcp-local-server dynamic-dns tsig-secret c2VjcmV0",
		}))
		if err != nil {
			t.Fatalf("CompileConfig: %v", err)
		}
		ws := ValidateConfig(cfg)
		if hasWarn(ws, "unsigned") {
			t.Fatalf("a configured tsig-key must NOT warn about unsigned updates: %v", ws)
		}
	})

	t.Run("no update-server does not emit the unsigned warning", func(t *testing.T) {
		// The "no update-server" warning already covers this config; the
		// unsigned-posture warning is scoped to a SET update-server so the two
		// do not double-fire on an incomplete config.
		cfg, err := CompileConfig(buildTree(t, []string{
			"set system services dhcp-local-server dynamic-dns enable",
			"set system services dhcp-local-server dynamic-dns domain corp.example.com",
		}))
		if err != nil {
			t.Fatalf("CompileConfig: %v", err)
		}
		if hasWarn(ValidateConfig(cfg), "unsigned") {
			t.Fatal("with no update-server the unsigned-posture warning must not fire")
		}
	})
}
