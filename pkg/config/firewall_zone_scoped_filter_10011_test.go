package config

import (
	"strings"
	"testing"
)

// #10011: a `%zone`-scoped filter address literal (`fe80::1%eth0`) was ACCEPTED
// by classifyFilterAddrFamily (bare netip.ParsePrefix/ParseAddr honor a zone)
// but is UNREPRESENTABLE in the dataplane: the Rust matcher parses each token
// as std::net::Ipv6Addr / IpNet (no zone model), so parse_address hits its Err
// arm and pushes nothing — a silent per-token drop. Because
// recordFilterAddrTokens keys on the same classifier, the scoped token was
// never recorded on term.UnknownAddresses, so the #6463
// address_unrepresentable fail-closed marker never fired and a partially-scoped
// list on a `then discard`/`reject` term silently enforced only the surviving
// prefixes (fail-open via fall-through to the implicit accept). #5875 closed
// the identical divergence for SNAT pools; filters still had it.
//
// The fix rejects `%` in the classifier (the single source of truth shared by
// the strict gate and the record path) and gives the strict gate a precise
// zone/scope diagnostic mirroring the #5875 NAT message. Strict refuses; the
// tolerant path downgrades to a warning (#1960 no-brick) while the recorded
// token sets the wire marker so the Rust preflight fails the snapshot CLOSED.
//
// FAIL-ON-REVERT: restore the bare netip classifier (or drop the `%` arm) and
// the strict table accepts, the lenient warning/record vanishes, and the
// marker e2e (pkg/dataplane/userspace) goes RED.

// TestFilterZoneScopedAddressRejectedStrict_10011: every `%zone`-scoped filter
// address shape the Rust parse_address cannot represent must be REFUSED at
// strict commit, naming the offending filter, term, AND address with a
// zone/scope cause. The reject assertions FAIL against the unpatched
// classifier (the fail-on-revert proof).
func TestFilterZoneScopedAddressRejectedStrict_10011(t *testing.T) {
	cases := []struct {
		name   string
		cmds   []string
		filter string
		term   string
		addr   string
	}{
		{
			name: "link-local-named-scope-source",
			cmds: []string{
				"set firewall family inet6 filter f6 term t from source-address fe80::1%eth0",
				"set firewall family inet6 filter f6 term t then accept",
			},
			filter: "f6",
			term:   "t",
			addr:   "fe80::1%eth0",
		},
		{
			name: "link-local-numeric-scope-source",
			cmds: []string{
				"set firewall family inet6 filter f6 term t from source-address fe80::1%2",
				"set firewall family inet6 filter f6 term t then accept",
			},
			filter: "f6",
			term:   "t",
			addr:   "fe80::1%2",
		},
		{
			name: "global-scoped-destination",
			cmds: []string{
				"set firewall family inet6 filter f6 term t from destination-address 2001:db8::1%eth0",
				"set firewall family inet6 filter f6 term t then accept",
			},
			filter: "f6",
			term:   "t",
			addr:   "2001:db8::1%eth0",
		},
		{
			name: "scoped-cidr",
			cmds: []string{
				"set firewall family inet6 filter f6 term t from source-address fe80::1%eth0/64",
				"set firewall family inet6 filter f6 term t then accept",
			},
			filter: "f6",
			term:   "t",
			addr:   "fe80::1%eth0/64",
		},
		{
			name: "mixed-valid-scoped-discard",
			cmds: []string{
				"set firewall family inet6 filter f6 term t from source-address [ 2001:db8::/32 fe80::1%eth0 ]",
				"set firewall family inet6 filter f6 term t then discard",
			},
			filter: "f6",
			term:   "t",
			addr:   "fe80::1%eth0",
		},
		{
			name: "v4-scoped-inet",
			cmds: []string{
				"set firewall family inet filter f term t from source-address 10.0.0.1%eth0",
				"set firewall family inet filter f term t then accept",
			},
			filter: "f",
			term:   "t",
			addr:   "10.0.0.1%eth0",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(buildFilterTree(t, tc.cmds...))
			if err == nil {
				t.Fatalf("expected strict commit to reject zone-scoped filter address %q", tc.addr)
			}
			msg := err.Error()
			if !strings.Contains(msg, `filter "`+tc.filter+`"`) ||
				!strings.Contains(msg, `term "`+tc.term+`"`) {
				t.Fatalf("error %q must name filter %q and term %q", msg, tc.filter, tc.term)
			}
			if !strings.Contains(msg, tc.addr) {
				t.Fatalf("error %q must name the offending address %q", msg, tc.addr)
			}
			if !strings.Contains(msg, "zone/scope") {
				t.Fatalf("error %q must explain the zone/scope cause", msg)
			}
		})
	}
}

// TestFilterZoneScopedAddressLenientWarnsAndRecords_10011: the tolerant load /
// peer-sync path (#1960 no-brick) must NOT hard-fail on a scoped filter
// address — it records a warning AND records the token on
// term.UnknownAddresses (kept verbatim in the address list) so the snapshot
// builder sets the AddressUnrepresentable wire marker. RED-on-revert: with the
// bare classifier, no warning is recorded and UnknownAddresses stays empty.
func TestFilterZoneScopedAddressLenientWarnsAndRecords_10011(t *testing.T) {
	tree := buildFilterTree(t,
		"set firewall family inet6 filter f6 term t from source-address [ 2001:db8::/32 fe80::1%eth0 ]",
		"set firewall family inet6 filter f6 term t then discard",
	)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile must not brick on a zone-scoped filter address: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "firewall filter address literal") &&
			strings.Contains(w, "zone/scope") &&
			strings.Contains(w, "fe80::1%eth0") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("lenient compile must record a zone-scoped address warning; warnings = %v", cfg.Warnings)
	}
	term := firstInet6Term(t, cfg, "f6")
	if len(term.UnknownAddresses) != 1 || term.UnknownAddresses[0] != "fe80::1%eth0" {
		t.Fatalf("the zone-scoped literal must be recorded on UnknownAddresses, got %v "+
			"(an empty record means the wire marker can never fire — the #10011 silent drop)",
			term.UnknownAddresses)
	}
	// The token is kept VERBATIM in the address list (never stripped), so the
	// term still carries the surviving prefix alongside it.
	if len(term.SourceAddresses) != 2 ||
		term.SourceAddresses[0] != "2001:db8::/32" ||
		term.SourceAddresses[1] != "fe80::1%eth0" {
		t.Fatalf("source addresses must keep both tokens verbatim, got %v", term.SourceAddresses)
	}
}

// TestClassifyFilterAddrFamilyZoneScope_10011 is a focused unit test of the
// classifier so the strict gate and the record path agree on what a
// zone-scoped literal is: any `%` rejects, every unscoped form still parses
// with the right family.
func TestClassifyFilterAddrFamilyZoneScope_10011(t *testing.T) {
	scoped := []string{
		"fe80::1%eth0",
		"fe80::1%2",
		"2001:db8::1%eth0",
		"fe80::1%eth0/64",
		"10.0.0.1%eth0",
	}
	for _, a := range scoped {
		if _, ok := classifyFilterAddrFamily(a); ok {
			t.Errorf("classifyFilterAddrFamily(%q) = accept, want reject (the dataplane cannot represent %%zone)", a)
		}
	}
	unscoped := []struct {
		addr   string
		wantV6 bool
	}{
		{"fe80::1", true},
		{"::1", true},
		{"2001:db8::1", true},
		{"2001:db8::/32", true},
		{"10.0.0.1", false},
		{"10.0.0.0/8", false},
	}
	for _, tc := range unscoped {
		isV6, ok := classifyFilterAddrFamily(tc.addr)
		if !ok {
			t.Errorf("classifyFilterAddrFamily(%q) = reject, want accept", tc.addr)
		} else if isV6 != tc.wantV6 {
			t.Errorf("classifyFilterAddrFamily(%q) isV6 = %v, want %v", tc.addr, isV6, tc.wantV6)
		}
	}
}

// TestFilterUnscopedLinkLocalCompiles_10011: an UNSCOPED link-local (and the
// surrounding unscoped shapes) must still compile clean on the strict path.
// Regression guard against a false-reject — the fix targets ONLY the `%zone`
// suffix, not any legitimate v6 literal.
func TestFilterUnscopedLinkLocalCompiles_10011(t *testing.T) {
	tree := buildFilterTree(t,
		"set firewall family inet6 filter f6 term t from source-address [ fe80::1 2001:db8::/32 ]",
		"set firewall family inet6 filter f6 term t from destination-address 2001:db8::1",
		"set firewall family inet6 filter f6 term t then accept",
	)
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("unscoped link-local / global literals must compile: %v", err)
	}
}
