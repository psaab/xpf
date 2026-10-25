package config

import (
	"strings"
	"testing"
)

// #16550: the NAT64 `match source-address-name` strict gate checked only
// that the name exists. An IPv4-only address or address-set committed
// clean and shipped a source constraint the Rust NAT64 matcher (which
// parses only IPv6 prefixes) can never satisfy, while the same prefix
// as a literal `match source-address` was rejected (#15678). The gate
// now resolves the static closure and rejects it when it yields no
// IPv6 prefix; a mixed v4+v6 set still commits. The tolerant path
// warns instead of bricking (#1960).

func TestNAT64SourceAddressNameIPv4OnlyRejected16550(t *testing.T) {
	for _, tc := range []struct {
		name  string
		extra []string
	}{
		{"v4-address", []string{
			"set security address-book global address v4-only 10.0.0.0/8",
			"set security nat nat64 rule-set rs1 match source-address-name v4-only",
		}},
		{"v4-set", []string{
			"set security address-book global address v4-a 10.0.0.0/8",
			"set security address-book global address v4-b 192.168.0.0/16",
			"set security address-book global address-set all-v4 address v4-a",
			"set security address-book global address-set all-v4 address v4-b",
			"set security nat nat64 rule-set rs1 match source-address-name all-v4",
		}},
		{"v4-nested-set", []string{
			"set security address-book global address v4-a 10.0.0.0/8",
			"set security address-book global address-set inner-v4 address v4-a",
			"set security address-book global address-set outer address-set inner-v4",
			"set security nat nat64 rule-set rs1 match source-address-name outer",
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := compileNAT64Scope(t, nat64ScopeLines(tc.extra...))
			if err == nil {
				t.Fatalf("%s: IPv4-only source-address-name must be rejected at strict commit", tc.name)
			}
			if !strings.Contains(err.Error(), "does not resolve to any IPv6 address") {
				t.Fatalf("%s: error = %v, want the #16550 no-IPv6 diagnostic", tc.name, err)
			}
			// Lenient path warns, never bricks (#1960).
			if _, lerr := CompileConfigLenient(buildTree(t, nat64ScopeLines(tc.extra...))); lerr != nil {
				t.Fatalf("%s: lenient path must not brick: %v", tc.name, lerr)
			}
		})
	}
}

func TestNAT64SourceAddressNameMixedSetCommits16550(t *testing.T) {
	cfg, err := compileNAT64Scope(t, nat64ScopeLines(
		"set security address-book global address v4-a 10.0.0.0/8",
		"set security address-book global address v6-a 2001:db8:2::/48",
		"set security address-book global address-set mixed address v4-a",
		"set security address-book global address-set mixed address v6-a",
		"set security nat nat64 rule-set rs1 match source-address-name mixed",
	))
	if err != nil {
		t.Fatalf("mixed v4+v6 set must still commit: %v", err)
	}
	rs := cfg.Security.NAT.NAT64[0]
	if len(rs.SourceAddressNames) != 1 || rs.SourceAddressNames[0] != "mixed" {
		t.Fatalf("SourceAddressNames = %v, want [mixed]", rs.SourceAddressNames)
	}

	// A pure IPv6 name remains admitted (control).
	if _, err := compileNAT64Scope(t, nat64ScopeLines(
		"set security nat nat64 rule-set rs1 match source-address-name clients-v6",
	)); err != nil {
		t.Fatalf("IPv6 source-address-name must commit: %v", err)
	}
}

// TestNAT64SourceAddressNameFeedBindingAdmitted16550: a direct
// dynamic-address feed binding has no static closure; its prefixes
// arrive via the live overlay, so the family gate must not reject it.
func TestNAT64SourceAddressNameFeedBindingAdmitted16550(t *testing.T) {
	_, err := compileNAT64Scope(t, nat64ScopeLines(
		"set security dynamic-address feed-server threat url https://feeds.example/list.txt",
		"set security dynamic-address feed-server threat feed-name malware path /malware.txt",
		"set security dynamic-address address-name feed-clients profile feed-name malware",
		"set security nat nat64 rule-set rs1 match source-address-name feed-clients",
	))
	if err != nil {
		t.Fatalf("direct feed binding must compile (runtime-resolved): %v", err)
	}
}

// TestNAT64NameClosureNoIPv6Unit16550 pins the helper directly: the
// verdict is "proven IPv4-only" over the resolved closure, not the
// authored name. Anything not statically decidable (dns-name with no
// snapshot, an undefined name) is not proven IPv4-only.
func TestNAT64NameClosureNoIPv6Unit16550(t *testing.T) {
	ab := &AddressBook{
		Addresses: map[string]*Address{
			"v4":  {Name: "v4", Value: "10.0.0.0/8"},
			"v6":  {Name: "v6", Value: "2001:db8::/32"},
			"dns": {Name: "dns", DNSName: "clients.example.net"},
		},
		AddressSets: map[string]*AddressSet{
			"mixed": {Name: "mixed", Addresses: []string{"v4", "v6"}},
			"allv4": {Name: "allv4", Addresses: []string{"v4"}},
		},
	}
	for name, want := range map[string]bool{
		"v4": true, "v6": false, "mixed": false, "allv4": true,
		// Not statically decidable: no usable snapshot yet.
		"dns": false, "nosuch": false,
	} {
		if got := nat64NameClosureNoIPv6(ab, name); got != want {
			t.Fatalf("nat64NameClosureNoIPv6(%q) = %v, want %v", name, got, want)
		}
	}
}
