package config

import (
	"strings"
	"testing"
)

// Regression tests for #3332: trailing tokens on a SUPPORTED fixed-arity
// scalar value leaf were silently consumed at commit. `set interfaces
// ge-0-0-0 description hello bogus` parses (flat-set) as a `description`
// leaf carrying its single value `hello` with a trailing CHILD node
// `bogus` that the compiler never reads — so the typo committed cleanly
// and the operator's garbage token was dropped without warning.
//
// The #3411 screen subset closed only the screen subtree (compileScreen
// recordKeyExtras). This is the general schema-walk value-arity gate
// (SchemaValidate via isScalarValueLeaf): any fixed-arity scalar value
// leaf (args > 0, children == nil, non-multi, untyped) now rejects a
// trailing token its declared arity does not expect, while multi /
// bracketed-list (#2419) and named-instance leaves stay accepted.
//
// All tests build the tree through the production ParseSetCommand +
// SetPath loop (never NewParser — see CLAUDE.md "Testing flat set
// syntax").

func buildSetTree3332(t *testing.T, cmds ...string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	for _, cmd := range cmds {
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

// TestSchema3332_TrailingTokenOnScalarLeaf_Rejected is the RED-on-revert
// guard: a scalar value leaf carrying a trailing junk token must fail the
// commit-time schema gate. Reverting the isScalarValueLeaf gate makes the
// token silently accepted and this test goes RED.
func TestSchema3332_TrailingTokenOnScalarLeaf_Rejected(t *testing.T) {
	tree := buildSetTree3332(t,
		"set interfaces ge-0-0-0 description hello bogus",
	)
	err := SchemaValidate(tree)
	if err == nil {
		t.Fatal("expected commit error for trailing token on `description` scalar leaf, got nil (token silently dropped)")
	}
	if !strings.Contains(err.Error(), "description") || !strings.Contains(err.Error(), "bogus") {
		t.Fatalf("error should reference the leaf + the offending token: %v", err)
	}
}

// TestSchema3332_ValidScalarLeaf_Accepted guards against a false-reject of
// the legitimate single-value spelling.
func TestSchema3332_ValidScalarLeaf_Accepted(t *testing.T) {
	tree := buildSetTree3332(t,
		"set interfaces ge-0-0-0 description hello",
	)
	if err := SchemaValidate(tree); err != nil {
		t.Fatalf("unexpected error for valid scalar leaf: %v", err)
	}
}

// TestSchema3332_MultiValueLeaf_Accepted guards the #2419 exemption: a
// multi-value leaf legitimately carries multiple trailing values and must
// NOT be rejected by the arity gate.
func TestSchema3332_MultiValueLeaf_Accepted(t *testing.T) {
	tree := buildSetTree3332(t,
		"set system name-server 8.8.8.8",
		"set system name-server 9.9.9.9",
	)
	if err := SchemaValidate(tree); err != nil {
		t.Fatalf("unexpected error for multi-value leaf: %v", err)
	}
	// And a REAL #2419 bracketed-list collapse: one set line whose
	// `[ ... ]` list collapses every value onto a single multi leaf's Keys
	// (ParseSetCommand strips the brackets, SetPath absorbs the tail —
	// Keys=[name-server 8.8.8.8 9.9.9.9 2001:4860:4860::8888]). The arity
	// gate must NOT trip on the trailing list values of a multi leaf.
	tree2 := buildSetTree3332(t,
		"set system name-server [ 8.8.8.8 9.9.9.9 2001:4860:4860::8888 ]",
	)
	if err := SchemaValidate(tree2); err != nil {
		t.Fatalf("unexpected error for bracketed multi-value list: %v", err)
	}
}

// TestSchema3332_OpaqueContainerBody_Accepted guards the design decision
// behind the explicit `scalar` opt-in: `application-set` is `args:1,
// children:nil` (structurally identical to a scalar value leaf) but is an
// OPAQUE CONTAINER whose `application <member>` body the compiler reads off
// the node's AST children. A structural-only gate would false-reject the
// legitimate body; the gate must stay out unless the leaf is tagged
// `scalar: true`. If someone tags application-set scalar (or drops the
// children==nil guard), this test goes RED.
func TestSchema3332_OpaqueContainerBody_Accepted(t *testing.T) {
	tree := buildSetTree3332(t,
		"set applications application-set my-set application junos-http",
		"set applications application-set my-set application junos-https",
	)
	if err := SchemaValidate(tree); err != nil {
		t.Fatalf("unexpected error for opaque application-set body: %v", err)
	}
}

// TestSchema3332_NamedInstanceLeaf_Accepted guards the named-instance
// exemption: a container leaf whose trailing tokens are real sub-structure
// (here the `address <cidr> { ... }` identity arg) must not trip the gate.
func TestSchema3332_NamedInstanceLeaf_Accepted(t *testing.T) {
	tree := buildSetTree3332(t,
		"set interfaces ge-0-0-0 unit 0 family inet address 10.0.1.1/24",
	)
	if err := SchemaValidate(tree); err != nil {
		t.Fatalf("unexpected error for named-instance address leaf: %v", err)
	}
}

// --- address-book `address` (multi:true) trailing tokens (#3332 fold) -------
//
// The `address` schema node is multi:true (it absorbs the `description`
// sub-token onto its Keys to keep the #2419 dual-AST shape), so the generic
// scalar-leaf gate cannot reach the description / prefix slot. The
// compiler-side validateTrailingTokensStrict gate catches the leak. These
// run the STRICT CompileConfig path (the commit / commit-check path).

func TestSchema3332_AddressBookDescriptionTrailing_Rejected(t *testing.T) {
	tree := buildSetTree3332(t,
		"set security address-book global address h2 description web-server bogus",
	)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("expected commit error for trailing token after address description, got nil (token silently dropped)")
	}
	if !strings.Contains(err.Error(), "h2") || !strings.Contains(err.Error(), "bogus") {
		t.Fatalf("error should reference the address + offending token: %v", err)
	}
}

func TestSchema3332_AddressBookPrefixTrailing_Rejected(t *testing.T) {
	tree := buildSetTree3332(t,
		"set security address-book global address h2 1.2.3.4/32 bogus",
	)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("expected commit error for trailing token after address prefix, got nil")
	}
	if !strings.Contains(err.Error(), "h2") || !strings.Contains(err.Error(), "bogus") {
		t.Fatalf("error should reference the address + offending token: %v", err)
	}
}

// TestSchema3332_AddressBookZoneLocalTrailing_Rejected covers the zone-local
// address book (#3061): the trailing token rides on the zone-local original
// Address struct, which resolveZoneLocalAddressBooks does not copy into the
// qualified global entry — the gate must walk the zone book too.
func TestSchema3332_AddressBookZoneLocalTrailing_Rejected(t *testing.T) {
	tree := buildSetTree3332(t,
		"set security zones security-zone trust address-book address h2 description web-server bogus",
	)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("expected commit error for trailing token on zone-local address description, got nil")
	}
	if !strings.Contains(err.Error(), "h2") || !strings.Contains(err.Error(), "bogus") {
		t.Fatalf("error should reference the address + offending token: %v", err)
	}
}

func TestSchema3332_AddressBookValidForms_Accepted(t *testing.T) {
	// Bare prefix, and a quoted multi-word description (one token) — neither
	// carries a trailing token.
	tree := buildSetTree3332(t,
		"set security address-book global address h2 1.2.3.4/32",
		"set security address-book global address h3 description \"web server frontend\"",
	)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("unexpected error for valid address-book forms: %v", err)
	}
	// And confirm the legitimate value/description still compiled through.
	h2 := cfg.Security.AddressBook.Addresses["h2"]
	h3 := cfg.Security.AddressBook.Addresses["h3"]
	if h2 == nil || h2.Value != "1.2.3.4/32" {
		t.Fatalf("h2 prefix not compiled: %+v", h2)
	}
	if h3 == nil || h3.Description != "web server frontend" {
		t.Fatalf("h3 quoted description not compiled: %+v", h3)
	}
}

// --- IKE gateway compact-hierarchical `dynamic hostname` (#3332 fold) -------
//
// The compact-hierarchical `dynamic hostname <fqdn> <extra>` collapses the
// tokens onto the parent `dynamic` node's Keys (NOT a scalar child), so the
// generic gate cannot see it; the compiler reads only Keys[2] and drops the
// rest. Built with the hierarchical parser (NewParser is correct for a
// hierarchical block — the flat-set caveat is about `set` lines).

func TestSchema3332_DynamicHostnameCompactTrailing_Rejected(t *testing.T) {
	tree := parseHierText(t, `security {
    ike {
        gateway dyn-gw {
            ike-policy pol1;
            external-interface ge-0-0-0;
            dynamic hostname peer.example.com bogus;
        }
    }
}`)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("expected commit error for trailing token after dynamic hostname, got nil (token silently dropped)")
	}
	if !strings.Contains(err.Error(), "dyn-gw") || !strings.Contains(err.Error(), "bogus") {
		t.Fatalf("error should reference the gateway + offending token: %v", err)
	}
}

func TestSchema3332_DynamicHostnameCompactValid_Accepted(t *testing.T) {
	tree := parseHierText(t, `security {
    ike {
        gateway dyn-gw {
            ike-policy pol1;
            external-interface ge-0-0-0;
            dynamic hostname peer.example.com;
        }
    }
}`)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("unexpected error for valid compact dynamic hostname: %v", err)
	}
	if gw := cfg.Security.IPsec.Gateways["dyn-gw"]; gw == nil || gw.DynamicHostname != "peer.example.com" {
		t.Fatalf("dynamic hostname not compiled: %+v", cfg.Security.IPsec.Gateways["dyn-gw"])
	}
}
