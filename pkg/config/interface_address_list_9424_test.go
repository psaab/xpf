package config

import (
	"strings"
	"testing"
)

// #9424 — a bracketed interface address list kept only the FIRST address,
// silently, in both AST shapes, on both families and through all four config
// channels. `namedInstances` reads slot 0 only (`Keys[1]` and nothing else),
// which is the canonical #2419 shape; #6662 and #7653 both swept
// `namedInstances` callers and did not reach this one.
//
// The two-separate-stanzas spelling is the POSITIVE CONTROL: it compiles
// exactly the configuration the bracket asks for, which is what makes these
// cells a measurement of the bracket handling rather than of the fixture — and
// what makes ACCUMULATE the right remedy here where the sibling members of this
// class (#8794 / #9246 / #8810) were REFUSED. Those refused because expanding
// would have invented a semantics the platform lacks; a unit with two addresses
// is ordinary.

func addrTreeHier9424(t *testing.T, family, body string) *ConfigTree {
	t.Helper()
	src := `interfaces { ge-0/0/0 { unit 0 { family ` + family + ` { ` + body + ` } } } }`
	tree, errs := NewParser(src).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse %q: %v", src, errs)
	}
	return tree
}

func addrTreeFlat9424(t *testing.T, lines ...string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	for _, l := range lines {
		path, err := ParseSetCommand(l)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", l, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", l, err)
		}
	}
	return tree
}

func addrUnit9424(t *testing.T, tree *ConfigTree) *InterfaceUnit {
	t.Helper()
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	iface := cfg.Interfaces.Interfaces["ge-0/0/0"]
	if iface == nil || iface.Units[0] == nil {
		t.Fatalf("fixture broken: no ge-0/0/0 unit 0")
	}
	return iface.Units[0]
}

func TestBracketedInterfaceAddressListBothShapes9424(t *testing.T) {
	cases := []struct {
		name   string
		family string
		hier   string
		flat   []string
		want   []string
	}{
		{
			name: "inet bracketed pair", family: "inet",
			hier: `address [ 10.0.0.1/24 10.0.0.2/24 ];`,
			flat: []string{"set interfaces ge-0/0/0 unit 0 family inet address [ 10.0.0.1/24 10.0.0.2/24 ]"},
			want: []string{"10.0.0.1/24", "10.0.0.2/24"},
		},
		{
			name: "inet two separate stanzas (POSITIVE CONTROL)", family: "inet",
			hier: `address 10.0.0.1/24; address 10.0.0.2/24;`,
			flat: []string{
				"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
				"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.2/24",
			},
			want: []string{"10.0.0.1/24", "10.0.0.2/24"},
		},
		{
			name: "inet bracketed triple", family: "inet",
			hier: `address [ 10.0.0.1/24 10.0.0.2/24 10.0.0.3/24 ];`,
			flat: []string{"set interfaces ge-0/0/0 unit 0 family inet address [ 10.0.0.1/24 10.0.0.2/24 10.0.0.3/24 ]"},
			want: []string{"10.0.0.1/24", "10.0.0.2/24", "10.0.0.3/24"},
		},
		{
			name: "inet6 bracketed pair", family: "inet6",
			hier: `address [ 2001:db8::1/64 2001:db8::2/64 ];`,
			flat: []string{"set interfaces ge-0/0/0 unit 0 family inet6 address [ 2001:db8::1/64 2001:db8::2/64 ]"},
			want: []string{"2001:db8::1/64", "2001:db8::2/64"},
		},
		{
			name: "inet6 two separate stanzas (POSITIVE CONTROL)", family: "inet6",
			hier: `address 2001:db8::1/64; address 2001:db8::2/64;`,
			flat: []string{
				"set interfaces ge-0/0/0 unit 0 family inet6 address 2001:db8::1/64",
				"set interfaces ge-0/0/0 unit 0 family inet6 address 2001:db8::2/64",
			},
			want: []string{"2001:db8::1/64", "2001:db8::2/64"},
		},
		{
			name: "inet single address is unchanged", family: "inet",
			hier: `address 10.0.0.1/24;`,
			flat: []string{"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24"},
			want: []string{"10.0.0.1/24"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hier := addrUnit9424(t, addrTreeHier9424(t, tc.family, tc.hier))
			flat := addrUnit9424(t, addrTreeFlat9424(t, tc.flat...))
			for shape, unit := range map[string]*InterfaceUnit{"hierarchical": hier, "flat set": flat} {
				if len(unit.Addresses) != len(tc.want) {
					t.Fatalf("%s: Addresses=%v, want %v — the bracketed list lost "+
						"everything past the first address (#9424)", shape, unit.Addresses, tc.want)
				}
				for i, w := range tc.want {
					if unit.Addresses[i] != w {
						t.Fatalf("%s: Addresses[%d]=%q, want %q (all=%v)", shape, i, unit.Addresses[i], w, unit.Addresses)
					}
				}
			}
			if strings.Join(hier.Addresses, ",") != strings.Join(flat.Addresses, ",") {
				t.Fatalf("the two AST shapes DISAGREE: hierarchical=%v flat=%v", hier.Addresses, flat.Addresses)
			}
		})
	}
}

// A bracketed list must not become a way to smuggle an unvalidated value past
// the typed-leaf gate, which validates only the FIRST key slot of an `address`
// leaf. Turning "silently dropped" into "silently compiled" would be a worse
// outcome than the defect, so a token that is neither an address for the family
// nor a declared sub-statement is REFUSED.
func TestBracketedInterfaceAddressListRefusesGarbage9424(t *testing.T) {
	cases := []struct {
		name   string
		family string
		hier   string
		flat   []string
		bad    string
	}{
		{
			name: "not an address", family: "inet",
			hier: `address [ 10.0.0.1/24 not-an-address ];`,
			flat: []string{"set interfaces ge-0/0/0 unit 0 family inet address [ 10.0.0.1/24 not-an-address ]"},
			bad:  "not-an-address",
		},
		{
			name: "an IPv6 address under family inet", family: "inet",
			hier: `address [ 10.0.0.1/24 2001:db8::1/64 ];`,
			flat: []string{"set interfaces ge-0/0/0 unit 0 family inet address [ 10.0.0.1/24 2001:db8::1/64 ]"},
			bad:  "2001:db8::1/64",
		},
		{
			name: "an IPv4 address under family inet6", family: "inet6",
			hier: `address [ 2001:db8::1/64 10.0.0.1/24 ];`,
			flat: []string{"set interfaces ge-0/0/0 unit 0 family inet6 address [ 2001:db8::1/64 10.0.0.1/24 ]"},
			bad:  "10.0.0.1/24",
		},
		{
			name: "an address with no prefix length", family: "inet",
			hier: `address [ 10.0.0.1/24 10.0.0.2 ];`,
			flat: []string{"set interfaces ge-0/0/0 unit 0 family inet address [ 10.0.0.1/24 10.0.0.2 ]"},
			bad:  "10.0.0.2",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for shape, tree := range map[string]*ConfigTree{
				"hierarchical": addrTreeHier9424(t, tc.family, tc.hier),
				"flat set":     addrTreeFlat9424(t, tc.flat...),
			} {
				_, err := CompileConfig(tree)
				if err == nil {
					t.Fatalf("%s: accepted a bracketed list carrying %q — the token is "+
						"silently dropped and the operator is not told (#9424)", shape, tc.bad)
				}
				if !strings.Contains(err.Error(), tc.bad) {
					t.Fatalf("%s: rejected, but the message does not name the token %q: %v",
						shape, tc.bad, err)
				}
				if !strings.Contains(err.Error(), "interface address list") {
					t.Fatalf("%s: rejected by a DIFFERENT gate, so this cell is not "+
						"measuring the #9424 refusal: %v", shape, err)
				}
			}
			// The tolerant load / peer-sync path must WARN rather than reject, so
			// an already-persisted config still boots (#1960) — carrying the
			// addresses that did parse, which is strictly more than the
			// pre-#9424 first-address-only behaviour.
			cfg, err := CompileConfigLenient(addrTreeHier9424(t, tc.family, tc.hier))
			if err != nil {
				t.Fatalf("tolerant path must not reject: %v", err)
			}
			var found bool
			for _, w := range cfg.Warnings {
				if strings.Contains(w, "interface address list") && strings.Contains(w, tc.bad) {
					found = true
				}
			}
			if !found {
				t.Fatalf("tolerant path dropped the diagnostic entirely: warnings=%v", cfg.Warnings)
			}
		})
	}
}

// A sub-statement written in the BRACED spelling still binds to the address it
// is written under, and the bracket accumulation must not reassign it. This is
// the failure mode of reusing the named instance's node for every extra
// address: `primary` would spread to all of them.
func TestBracketedInterfaceAddressSubStatementsStayBound9424(t *testing.T) {
	unit := addrUnit9424(t, addrTreeHier9424(t, "inet",
		`address 10.0.0.1/24 { primary; } address 10.0.0.2/24 { preferred; }`))
	if len(unit.Addresses) != 2 {
		t.Fatalf("Addresses=%v", unit.Addresses)
	}
	if unit.PrimaryAddress != "10.0.0.1/24" {
		t.Errorf("PrimaryAddress=%q, want 10.0.0.1/24", unit.PrimaryAddress)
	}
	if unit.PreferredAddress != "10.0.0.2/24" {
		t.Errorf("PreferredAddress=%q, want 10.0.0.2/24", unit.PreferredAddress)
	}

	// A bracketed pair carries NO sub-statements, so neither flag may be set.
	// If the extra address reused the named instance's node, `primary` written
	// on the first would silently apply to the second as well.
	braced := addrUnit9424(t, addrTreeHier9424(t, "inet",
		`address 10.0.0.1/24 { primary; } address 10.0.0.2/24;`))
	if braced.PrimaryAddress != "10.0.0.1/24" {
		t.Errorf("PrimaryAddress=%q", braced.PrimaryAddress)
	}

	// The discriminating shape: ONE `address` leaf carrying a bracketed pair AND
	// a braced body. The body belongs to the address the operator NAMED, and the
	// packed extra must not inherit it — which is why each packed extra gets a
	// fresh childless placeholder node rather than a reference to the named
	// instance's node. Sharing the node compiles PrimaryAddress = the LAST
	// address in the list, silently promoting a secondary address to primary.
	shared := addrUnit9424(t, addrTreeHier9424(t, "inet",
		`address [ 10.0.0.1/24 10.0.0.2/24 ] { primary; }`))
	if len(shared.Addresses) != 2 {
		t.Fatalf("Addresses=%v", shared.Addresses)
	}
	if shared.PrimaryAddress != "10.0.0.1/24" {
		t.Fatalf("the braced body was applied to a PACKED extra: PrimaryAddress=%q, "+
			"want 10.0.0.1/24 — the sub-statement belongs to the named address only",
			shared.PrimaryAddress)
	}
	sharedPref := addrUnit9424(t, addrTreeHier9424(t, "inet",
		`address [ 10.0.0.1/24 10.0.0.2/24 ] { preferred; }`))
	if sharedPref.PreferredAddress != "10.0.0.1/24" {
		t.Fatalf("PreferredAddress=%q, want 10.0.0.1/24", sharedPref.PreferredAddress)
	}
}

// VRRP hangs off the address node, so a group on a SEPARATE second address must
// still be found — the accumulation must not perturb the existing binding.
func TestBracketedInterfaceAddressVRRPStillBinds9424(t *testing.T) {
	unit := addrUnit9424(t, addrTreeHier9424(t, "inet",
		`address 10.0.0.1/24; address 10.0.0.2/24 { vrrp-group 1 { virtual-address 10.0.0.100/24; priority 200; } }`))
	if len(unit.Addresses) != 2 {
		t.Fatalf("Addresses=%v", unit.Addresses)
	}
	if len(unit.VRRPGroups) != 1 {
		t.Fatalf("VRRPGroups=%d, want 1", len(unit.VRRPGroups))
	}
}

// PINNED, NOT FIXED. The brace-elided sub-statement spelling
// `address 10.0.0.1/24 primary;` parses to the SAME shape as a bracketed pair —
// Keys=["address","10.0.0.1/24","primary"] — and still loses `primary` in the
// hierarchical shape while the flat spelling applies it. That is the
// brace-elision class #9056 owns (its remedy is an admission into
// compactNormalizeInScope), a different mechanism from this one.
//
// It is pinned rather than left unmentioned for two reasons: it is the exact
// false-positive a "the node carries extra Keys" detector would have refused,
// so the cell records why the discriminator is schema-driven instead; and a
// divergence measured and pinned is visible, while one merely known is not.
func TestElidedAddressSubStatementDivergenceStillOpen9424(t *testing.T) {
	hier := addrUnit9424(t, addrTreeHier9424(t, "inet", `address 10.0.0.1/24 primary;`))
	flat := addrUnit9424(t, addrTreeFlat9424(t,
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24 primary"))
	if len(hier.Addresses) != 1 || hier.Addresses[0] != "10.0.0.1/24" {
		t.Fatalf("the elided sub-statement must NOT be read as an address: %v", hier.Addresses)
	}
	if len(flat.Addresses) != 1 {
		t.Fatalf("flat: %v", flat.Addresses)
	}
	if hier.PrimaryAddress != "" {
		t.Fatalf("the hierarchical elided `primary` now compiles (%q). That is a FIX, "+
			"not a regression — but it belongs to #9056 and this cell pins the "+
			"boundary, so update it deliberately rather than deleting it",
			hier.PrimaryAddress)
	}
	if flat.PrimaryAddress != "10.0.0.1/24" {
		t.Fatalf("flat lost `primary` too: %q", flat.PrimaryAddress)
	}
}

// The FALSE POSITIVE the repo's own #8662/#2419 census caught, and the reason
// scanAddressTail9424 stops at the first sub-statement keyword.
//
// `address 10.0.0.1/24 vrrp-group 1 virtual-address 10.0.0.100/24;` is the
// fully brace-elided spelling of a VRRP stanza. Its packed tail is
// indistinguishable, token by token, from a bracketed list: without the stop,
// `1` and `virtual-address` classify as malformed — so a config an earlier
// binary ACCEPTED begins failing at commit — and `10.0.0.100/24` classifies as
// an ADDRESS, which would install the VIP on the interface as a real address on
// the tolerant path.
//
// Neither of those was predicted. The first version of this walk flipped two
// `family inet[6] address <a> vrrp-group` sites in
// testdata/compact_block_divergences_2419.txt from drop-shape "empty" to
// "partial", which is a repo-wide guard scanning by CONTENT reporting a defect
// none of the cells above could see.
func TestElidedAddressSubStatementBodyIsNotAnAddressList9424(t *testing.T) {
	cases := []struct {
		name   string
		family string
		hier   string
		want   []string
	}{
		{
			name: "inet elided vrrp-group", family: "inet",
			hier: `address 10.0.0.1/24 vrrp-group 1 virtual-address 10.0.0.100/24;`,
			want: []string{"10.0.0.1/24"},
		},
		{
			name: "inet6 elided vrrp-group", family: "inet6",
			hier: `address 2001:db8::1/64 vrrp-group 1 virtual-address 2001:db8::100/64;`,
			want: []string{"2001:db8::1/64"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := addrTreeHier9424(t, tc.family, tc.hier)
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("a brace-elided vrrp-group stanza is now REJECTED at commit; it "+
					"was accepted before and its tokens are not a bracketed address "+
					"list: %v", err)
			}
			unit := cfg.Interfaces.Interfaces["ge-0/0/0"].Units[0]
			if len(unit.Addresses) != len(tc.want) || unit.Addresses[0] != tc.want[0] {
				t.Fatalf("Addresses=%v, want %v — a sub-statement's VALUE was read as an "+
					"address, which would install the VIP on the interface",
					unit.Addresses, tc.want)
			}
			if len(cfg.Interfaces.MalformedAddresses) != 0 {
				t.Fatalf("a sub-statement body was recorded as malformed: %v",
					cfg.Interfaces.MalformedAddresses)
			}
		})
	}

	// The flat spelling of the same statement compiles the VRRP group and must
	// keep doing so — it is the POSITIVE CONTROL that the stop rule did not
	// simply make the walk blind.
	flat := addrUnit9424(t, addrTreeFlat9424(t,
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24 vrrp-group 1 virtual-address 10.0.0.100/24"))
	if len(flat.Addresses) != 1 || flat.Addresses[0] != "10.0.0.1/24" {
		t.Fatalf("flat: Addresses=%v", flat.Addresses)
	}
	if len(flat.VRRPGroups) != 1 {
		t.Fatalf("flat: the VRRP group stopped compiling: %d groups", len(flat.VRRPGroups))
	}
}

// The discriminator reads the SCHEMA, so it cannot drift from what the grammar
// declares. If a sub-statement is added to `address` and this list is not
// updated, the compiler would start recording it as a malformed address and
// refuse a legal config — so the schema IS the list.
func TestInterfaceAddressSchemaDiscriminator9424(t *testing.T) {
	for _, family := range []string{"inet", "inet6"} {
		schema := interfaceAddressSchema(family)
		if schema == nil {
			t.Fatalf("%s: address schema not resolvable — the discriminator falls back "+
				"to pre-#9424 behaviour and the fix is inert", family)
		}
		if schema.keyValidator == nil {
			t.Fatalf("%s: address schema has no keyValidator, so no token can be "+
				"classified as an address", family)
		}
		for _, want := range []string{"primary", "preferred", "vrrp-group"} {
			if _, ok := schema.children[want]; !ok {
				t.Errorf("%s: `address` no longer declares %q; a config using it would "+
					"now be REFUSED as a malformed address", family, want)
			}
		}
	}
	if err := interfaceAddressSchema("inet").keyValidator("10.0.0.1/24"); err != nil {
		t.Errorf("inet validator rejects a valid IPv4 CIDR: %v", err)
	}
	if err := interfaceAddressSchema("inet").keyValidator("2001:db8::1/64"); err == nil {
		t.Error("inet validator accepts an IPv6 address; the family discriminator is not family-aware")
	}
}
