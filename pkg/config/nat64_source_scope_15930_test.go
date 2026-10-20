package config

import (
	"testing"
)

// #15930: strict admission of the NAT64 source spellings whose meaning the
// snapshot builder now preserves: `any` (match-any), the IPv6 family
// wildcards, `::/0`, and a dns-name backed source-address-name (defined
// name, zero answers at compile time — resolution is runtime state and
// must fail closed at the dataplane, not reject the commit).

func TestNAT64SourceAnyStrictAdmitted15930(t *testing.T) {
	for _, spelling := range []string{"any", "any6", "any-ipv6", "::/0"} {
		cfg, err := compileNAT64Scope(t, nat64ScopeLines(
			"set security nat nat64 rule-set rs1 match source-address "+spelling,
		))
		if err != nil {
			t.Fatalf("source-address %s must be admitted at strict commit: %v", spelling, err)
		}
		rs := cfg.Security.NAT.NAT64[0]
		if len(rs.SourceAddresses) != 1 || rs.SourceAddresses[0] != spelling {
			t.Fatalf("source-address %s compiled to %v, want [%s]", spelling, rs.SourceAddresses, spelling)
		}
	}
}

func TestNAT64SourceNameDNSDefinedAdmitted15930(t *testing.T) {
	// A dns-name entry is a DEFINED address-book name; a zero-answer
	// resolution at snapshot time poisons the NAT64 closure (fail-closed
	// sentinel), it does not make the name undefined at commit.
	cfg, err := compileNAT64Scope(t, nat64ScopeLines(
		"set security address-book global address dns-clients dns-name clients.example.net",
		"set security nat nat64 rule-set rs1 match source-address-name dns-clients",
	))
	if err != nil {
		t.Fatalf("dns-name source-address-name must compile: %v", err)
	}
	rs := cfg.Security.NAT.NAT64[0]
	if len(rs.SourceAddressNames) != 1 || rs.SourceAddressNames[0] != "dns-clients" {
		t.Fatalf("SourceAddressNames = %v, want [dns-clients]", rs.SourceAddressNames)
	}
	if ab := cfg.Security.AddressBook; ab == nil || ab.Addresses["dns-clients"] == nil || ab.Addresses["dns-clients"].DNSName == "" {
		t.Fatalf("dns-clients must compile to a dns-name entry: %+v", ab)
	}
}

func TestNAT64SourceAddressNameAnyAdmitted15930(t *testing.T) {
	// The strict gate exempts `source-address-name any` as a wildcard
	// (validateNAT64ScopeStrict); the compiled rule-set must carry the
	// name verbatim so the builder can lower it to ::/0. Family
	// variants are admitted by the same gate.
	for _, spelling := range []string{"any", "any6", "any-ipv6", "any4", "any-ipv4"} {
		cfg, err := compileNAT64Scope(t, nat64ScopeLines(
			"set security nat nat64 rule-set rs1 match source-address-name "+spelling,
		))
		if err != nil {
			t.Fatalf("source-address-name %s must be admitted at strict commit: %v", spelling, err)
		}
		rs := cfg.Security.NAT.NAT64[0]
		if len(rs.SourceAddressNames) != 1 || rs.SourceAddressNames[0] != spelling {
			t.Fatalf("source-address-name %s compiled to %v, want [%s]", spelling, rs.SourceAddressNames, spelling)
		}
	}
}
