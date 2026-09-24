package config

import (
	"testing"
)

// #4711: the `clients` source-IP allowlist is parsed ONCE at compile time into
// SNMPCommunity.clientNets, and AllowsSource matches against that precomputed
// set instead of re-parsing every prefix on every incoming v2c packet. These
// tests pin (a) the cache is populated by the compiler, (b) the compiled fast
// path and the directly-constructed on-the-fly fallback return identical
// allow/deny decisions (semantics preserved), and (c) malformed / empty
// allowlist handling matches the former per-call convention.

// The compiler must pre-parse the prefixes: after CompileConfig, clientNets is
// populated (one entry per parseable prefix) so AllowsSource never re-parses.
func TestSNMPClientsCompiledCachePopulated(t *testing.T) {
	c := communityFrom(t, buildTreeFromSet(t, []string{
		"set snmp community public authorization read-only",
		"set snmp community public clients 10.0.0.0/24",
		"set snmp community public clients 192.168.1.5",
		"set snmp community public clients 0.0.0.0/0 restrict",
	}), "public")

	if len(c.Clients) != 3 {
		t.Fatalf("expected 3 client entries, got %+v", c.Clients)
	}
	if len(c.clientNets) != 3 {
		t.Fatalf("expected 3 pre-parsed clientNets after compile, got %d (%+v)", len(c.clientNets), c.clientNets)
	}
	// The bare IP became a /32 host route; the restrict flag rode along.
	byPrefix := map[string]compiledSNMPClient{}
	for _, cn := range c.clientNets {
		byPrefix[cn.net.String()] = cn
	}
	if cn, ok := byPrefix["192.168.1.5/32"]; !ok || cn.ones != 32 || cn.restrict {
		t.Errorf("bare IP 192.168.1.5 not cached as an allow /32: %+v (ok=%v)", cn, ok)
	}
	if cn, ok := byPrefix["0.0.0.0/0"]; !ok || cn.ones != 0 || !cn.restrict {
		t.Errorf("0.0.0.0/0 restrict not cached as a deny /0: %+v (ok=%v)", cn, ok)
	}
}

// An unscoped community (no `clients`) leaves clientNets nil and stays allow-all
// — the empty-list default must be untouched by the caching.
func TestSNMPClientsCompiledCacheEmptyIsAllowAll(t *testing.T) {
	c := communityFrom(t, parseHier(t, `snmp { community open { authorization read-only; } }`), "open")
	if c.clientNets != nil {
		t.Errorf("unscoped community should have nil clientNets, got %+v", c.clientNets)
	}
	for _, src := range []string{"10.0.0.1", "8.8.8.8", "2001:db8::1"} {
		if !c.AllowsSource(snmpClientTestSource10687(src)) {
			t.Errorf("AllowsSource(%s) = false on an unscoped community, want allow-all", src)
		}
	}
}

// Semantics preserved: for a representative allowlist (CIDR + bare IP + a
// restrict entry, IPv4 and IPv6), the compiled fast path and the
// directly-constructed on-the-fly fallback must return the SAME decision for
// sources inside and outside each entry. A directly-built community (clientNets
// nil) exercises the fallback; the compiled one exercises the cache.
func TestSNMPClientsCompiledVsFallbackParity(t *testing.T) {
	clients := []SNMPClient{
		{Prefix: "10.1.0.0/16"},
		{Prefix: "10.1.2.0/24", Restrict: true},
		{Prefix: "192.168.1.5"}, // bare IPv4 → /32
		{Prefix: "2001:db8::/32"},
		{Prefix: "2001:db8:dead::/48", Restrict: true},
	}

	// Directly constructed: clientNets stays nil → AllowsSource parses on the
	// fly (the fallback path).
	direct := &SNMPCommunity{Name: "d", Clients: clients}
	if direct.clientNets != nil {
		t.Fatal("directly-constructed community should not have a pre-built cache")
	}

	// Compiled: clientNets is pre-parsed → AllowsSource uses the cache.
	compiled := &SNMPCommunity{Name: "c", Clients: clients}
	compiled.clientNets = compileClientNets(compiled.Clients)
	if len(compiled.clientNets) != len(clients) {
		t.Fatalf("expected %d cached nets, got %d", len(clients), len(compiled.clientNets))
	}

	cases := map[string]bool{
		"10.1.5.1":         true,  // 10.1.0.0/16 allow
		"10.1.2.9":         false, // 10.1.2.0/24 restrict (longest match)
		"192.168.1.5":      true,  // bare /32 allow
		"192.168.1.6":      false, // no match → default-deny
		"8.8.8.8":          false, // no match → default-deny
		"2001:db8::1":      true,  // 2001:db8::/32 allow
		"2001:db8:dead::1": false, // 2001:db8:dead::/48 restrict (longest)
		"2001:dead::1":     false, // no match → default-deny
	}
	for src, want := range cases {
		ip := snmpClientTestSource10687(src)
		gd := direct.AllowsSource(ip)
		gc := compiled.AllowsSource(ip)
		if gd != gc {
			t.Errorf("AllowsSource(%s): fallback=%v compiled=%v — decisions diverge", src, gd, gc)
		}
		if gc != want {
			t.Errorf("AllowsSource(%s) = %v, want %v", src, gc, want)
		}
	}
}

// Malformed-CIDR convention preserved: an unparseable prefix is skipped (inert)
// — never a silent allow-all — both when compiled and on the fallback path. A
// list of ONLY malformed entries still default-denies (non-nil empty cache),
// distinguishable from an unscoped (nil-cache) allow-all community.
func TestSNMPClientsMalformedSkippedInert(t *testing.T) {
	clients := []SNMPClient{
		{Prefix: "not-an-ip"},
		{Prefix: "10.5.0.0/24"},
	}
	// Compiled: the bad entry is dropped from the cache, the good one kept.
	nets := compileClientNets(clients)
	if len(nets) != 1 || nets[0].net.String() != "10.5.0.0/24" {
		t.Fatalf("malformed entry should be skipped, kept %+v", nets)
	}

	c := &SNMPCommunity{Name: "m", Clients: clients, clientNets: nets}
	if !c.AllowsSource(snmpClientTestSource10687("10.5.0.9")) {
		t.Error("10.5.0.9 should be allowed by 10.5.0.0/24 despite a malformed sibling")
	}
	if c.AllowsSource(snmpClientTestSource10687("8.8.8.8")) {
		t.Error("8.8.8.8 should be denied — a malformed entry must not become allow-all")
	}

	// All-malformed list: non-nil empty cache, and default-deny (NOT allow-all).
	badOnly := compileClientNets([]SNMPClient{{Prefix: "bad"}, {Prefix: "10.0.0.0/99"}})
	if badOnly == nil || len(badOnly) != 0 {
		t.Fatalf("all-malformed list should compile to a non-nil empty cache, got %+v", badOnly)
	}
	deny := &SNMPCommunity{Name: "b", Clients: []SNMPClient{{Prefix: "bad"}}, clientNets: badOnly}
	if deny.AllowsSource(snmpClientTestSource10687("10.0.0.1")) {
		t.Error("a community whose clients are all malformed must default-deny, not allow-all")
	}
}
