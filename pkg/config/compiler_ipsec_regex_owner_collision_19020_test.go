package config

import "testing"

// #19020: strongSwan parses anchored FQDN/RFC822/DN selectors in PSK owner
// lists as regular expressions. Unknown language intersections must refuse
// rather than leave a second credential owner selectable.
func TestIPsecRegexOwnerCollision19020(t *testing.T) {
	t.Run("match-all FQDN regex collides in either gateway order", func(t *testing.T) {
		for _, pair := range [][4]string{
			{"inet", "fqdn:^.*$", "hostname", "vpn.example"},
			{"hostname", "vpn.example", "inet", "fqdn:^.*$"},
		} {
			requireCollision17772(t, identityPair17772(pair[0], pair[1], pair[2], pair[3]))
		}
	})

	t.Run("match-all regex intersects raw nonprintable owner encoding", func(t *testing.T) {
		for _, pair := range [][4]string{
			{"inet", "fqdn:^.*$", "inet", "fqdn:#780a79"},
			{"inet", "fqdn:#780a79", "inet", "fqdn:^.*$"},
		} {
			requireCollision17772(t, identityPair17772(pair[0], pair[1], pair[2], pair[3]))
		}
	})

	t.Run("literal and prefix regexes retain their language", func(t *testing.T) {
		requireCollision17772(t, identityPair17772("inet", "fqdn:^vpn$", "hostname", "vpn"))
		requireNoCollision17772(t, identityPair17772("inet", "fqdn:^vpn$", "hostname", "other"))
		requireCollision17772(t, identityPair17772("inet", "fqdn:^vpn.*$", "hostname", "vpn.example"))
		requireNoCollision17772(t, identityPair17772("inet", "fqdn:^vpn.*$", "hostname", "xvpn.example"))
	})
	t.Run("mixed-case regex prefix overlaps in either gateway order", func(t *testing.T) {
		requireCollision17772(t, identityPair17772("inet", "fqdn:^VPN.*$", "hostname", "vpn.example"))
		requireCollision17772(t, identityPair17772("hostname", "vpn.example", "inet", "fqdn:^VPN.*$"))
		requireCollision17772(t, identityPair17772("inet", "fqdn:^VPN.*$", "inet", "fqdn:^vpna.*$"))
		requireNoCollision17772(t, identityPair17772("inet", "fqdn:^VPN.*$", "hostname", "bar.example"))
	})

	t.Run("mixed-case prefix selects local identity in either gateway placement", func(t *testing.T) {
		for _, localOnGatewayA := range []bool{false, true} {
			requireCollision17772(t, localIdentityPair17772(
				"inet", "fqdn:^VPN.*$", "hostname", "vpn.example", localOnGatewayA))
		}
	})

	t.Run("disjoint anchored prefix languages are a positive control", func(t *testing.T) {
		requireNoCollision17772(t, identityPair17772("inet", "fqdn:^foo.*$", "inet", "fqdn:^bar.*$"))
	})

	t.Run("complex regex shapes fail closed", func(t *testing.T) {
		for _, tc := range []struct {
			pattern, disjointIdentity string
		}{
			{"^vpn[0-9]+$", "host.example"},
			{"^[a-z]+\\.example$", "9.example"},
			{"^(foo|bar)\\.example$", "other.example"},
			{"^(ab){2}\\.example$", "ab.example"},
		} {
			requireCollision17772(t, identityPair17772(
				"inet", "fqdn:"+tc.pattern, "hostname", tc.disjointIdentity))
		}
	})

	t.Run("only owner parsing enables regex semantics", func(t *testing.T) {
		lookup, _ := ipsecIKEIdentityKey("inet", "fqdn:^.*$")
		owner, _ := ipsecIKEIdentityOwnerKey("inet", "fqdn:^.*$")
		if lookup.isRegex || !owner.isRegex {
			t.Fatalf("plain lookup regex flag=%v owner regex flag=%v, want false/true", lookup.isRegex, owner.isRegex)
		}
	})
}

// FAIL-ON-REVERT: deleting the owner regex branch from either
// ipsecIdentitiesCollide or ipsecLookupSelectsOwner makes the match-all,
// exact, prefix, or undecidable-language cells below fail.
func TestIPsecRegexOwnerLookupSelectsOwner19020(t *testing.T) {
	for _, tc := range []struct {
		name       string
		pattern    string
		lookupType string
		lookup     string
		wantSelect bool
	}{
		{"match all", "^.*$", "hostname", "vpn.example", true},
		{"match all matches raw nonprintable FQDN bytes", "^.*$", "inet", "fqdn:#780a79", true},
		{"mixed-case prefix match", "^VPN.*$", "hostname", "vpn.example", true},
		{"mixed-case prefix mismatch", "^VPN.*$", "hostname", "bar.example", false},
		{"exact match", "^vpn$", "hostname", "vpn", true},
		{"exact mismatch", "^vpn$", "hostname", "other", false},
		{"prefix match", "^vpn.*$", "hostname", "vpn.example", true},
		{"prefix mismatch", "^vpn.*$", "hostname", "xvpn.example", false},
		{"undecidable pattern fails closed", "^vpn[0-9]+$", "hostname", "host.example", true},
		{"empty lookup cannot match regex", "^.*$", "inet", "fqdn:", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lookup, _ := ipsecIKEIdentityKey(tc.lookupType, tc.lookup)
			owner, _ := ipsecIKEIdentityOwnerKey("inet", "fqdn:"+tc.pattern)
			_, selected := ipsecLookupSelectsOwner(lookup, owner)
			if selected != tc.wantSelect {
				t.Errorf("ipsecLookupSelectsOwner(%q, %q) = %v, want %v", tc.lookup, tc.pattern, selected, tc.wantSelect)
			}
		})
	}

	regexOwner, _ := ipsecIKEIdentityOwnerKey("inet", "fqdn:^.*$")
	rfc822Lookup, _ := ipsecIKEIdentityKey("user-at-hostname", "user@example.com")
	if _, selected := ipsecLookupSelectsOwner(rfc822Lookup, regexOwner); selected {
		t.Fatal("an FQDN regex owner must not select an RFC822 lookup")
	}

	literalOwner, _ := ipsecIKEIdentityKey("hostname", "vpn.example")
	regexLookup, _ := ipsecIKEIdentityKey("inet", "fqdn:^VPN.*$")
	if _, selected := ipsecLookupSelectsOwner(regexLookup, literalOwner); selected {
		t.Fatal("a regex-looking local identity is an ordinary lookup, not a regex owner")
	}
}
