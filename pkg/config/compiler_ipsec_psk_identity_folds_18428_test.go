package config

import (
	"strings"
	"testing"
)

// #18428 review folds. A PSK owner collision is a presented identity that can
// select both secrets. strongSwan selects through has_owner() (mem_cred.c),
// lookup->matches(owner), and every matches_* is type-strict except that an
// ID_ANY owner matches anything (round 3, verified in identification.c and
// with the libstrongswan 6.1.0-2 oracle). So a DN and a KEY_ID with the same
// DER bytes never collide, whichever gateway sorts first, while two selectors
// that strongSwan parses as the SAME type and compares equal always do.
// ID_ANY spellings, diagnostics, the case-insensitive type prefix and the
// empty-last-RDN quirk are oracle-checked too (docs/log/18428.md).

func TestPSKIdentityCollisionTypeStrict18428(t *testing.T) {
	crossType := []struct{ name, aType, a, bType, b string }{
		{"textual DN versus rendered KEY_ID", "distinguished-name", "CN=peer", "key-id", "300f310d300b0603550403130470656572"},
		{"textual DN versus KEY_ID case variant", "distinguished-name", "CN=peer", "key-id", "300f310d300b0603550403130450454552"},
		{"asn1dn versus keyid prefix", "inet", "asn1dn:#300f310d300b0603550403130470656572", "inet", "keyid:#300f310d300b0603550403130470656572"},
		{"numeric type-9 versus FQDN raw bytes", "inet", "{9}:#300f310d300b0603550403130470656572", "inet", "{2}:#300f310d300b0603550403130450454552"},
	}
	for _, pair := range crossType {
		t.Run(pair.name+" commits (DN on gw-a)", func(t *testing.T) {
			requireNoCollision17772(t, identityPair17772(pair.aType, pair.a, pair.bType, pair.b))
		})
		t.Run(pair.name+" commits (DN on gw-b)", func(t *testing.T) {
			requireNoCollision17772(t, identityPair17772(pair.bType, pair.b, pair.aType, pair.a))
		})
	}

	// Peer selector against the OTHER gateway's local identity, in both
	// gateway orders: still cross-type, still no collision.
	localOnA := twoVPN17772([]string{
		"set security ike gateway gw-a ike-policy ike-pol",
		"set security ike gateway gw-a address 203.0.113.1",
		"set security ike gateway gw-a remote-identity hostname gw-a-peer.example.com",
		"set security ike gateway gw-a local-identity distinguished-name CN=peer",
	}, []string{
		"set security ike gateway gw-b ike-policy ike-pol",
		"set security ike gateway gw-b address 203.0.113.2",
		"set security ike gateway gw-b remote-identity key-id 300f310d300b0603550403130450454552",
	}, "secret-a", "secret-b")
	t.Run("local DN on gw-a versus KEY_ID peer selector on gw-b commits", func(t *testing.T) {
		requireNoCollision17772(t, localOnA)
	})
	t.Run("local DN on gw-b versus KEY_ID peer selector on gw-a commits", func(t *testing.T) {
		requireNoCollision17772(t, identityPair17772("key-id", "300f310d300b0603550403130450454552", "hostname", "gw-b-peer.example.com",
			"set security ike gateway gw-b local-identity distinguished-name CN=peer"))
	})

	// Same strongSwan type and equal: the original #18428 defect. A
	// user-at-hostname or inet value with DN syntax renders unadorned and
	// parses as the same DN.
	sameType := []struct{ name, aType, a, bType, b string }{
		{"DN versus user-at-hostname of the same text", "distinguished-name", "CN=peer", "user-at-hostname", "CN=peer"},
		{"DN versus inet of the same text", "distinguished-name", "CN=peer", "inet", "CN=peer"},
		{"DN versus user-at-hostname case and attribute variant", "distinguished-name", "CN=Peer,O=Corp", "user-at-hostname", "cn=peer,o=corp"},
	}
	for _, pair := range sameType {
		t.Run(pair.name+" collides (gw-a order)", func(t *testing.T) {
			requireCollision17772(t, identityPair17772(pair.aType, pair.a, pair.bType, pair.b))
		})
		t.Run(pair.name+" collides (gw-b order)", func(t *testing.T) {
			requireCollision17772(t, identityPair17772(pair.bType, pair.b, pair.aType, pair.a))
		})
	}

	// An ID_ANY OWNER matches every lookup, so two owners collide when
	// either is ID_ANY. Remote identities with an ID_ANY spelling never
	// become owners (they fall back to the gateway address), so this clause
	// guards the owner set rather than a reachable config shape.
	t.Run("an ID_ANY owner collides with every identity in both operand orders", func(t *testing.T) {
		wildcard, _ := ipsecIKEIdentityKey("distinguished-name", "0.0.0.0")
		dn, _ := ipsecIKEIdentityKey("distinguished-name", "CN=peer")
		if _, ok := ipsecIdentitiesCollide(wildcard, dn); !ok {
			t.Errorf("ID_ANY versus DN must collide")
		}
		if _, ok := ipsecIdentitiesCollide(dn, wildcard); !ok {
			t.Errorf("DN versus ID_ANY must collide")
		}
		if _, ok := ipsecLookupSelectsOwner(dn, wildcard); !ok {
			t.Errorf("a DN lookup selects an ID_ANY owner")
		}
	})
	// The effective local identity is the `me` LOOKUP of has_owner(), and
	// matches_any() makes an ID_ANY lookup match only an ID_ANY owner.
	// Master committed these shapes; the local wildcard selects no peer
	// selector, so they still commit.
	t.Run("an ID_ANY lookup selects no concrete owner", func(t *testing.T) {
		wildcard, _ := ipsecIKEIdentityKey("inet", "0.0.0.0")
		fqdn, _ := ipsecIKEIdentityKey("hostname", "a.example.com")
		if _, ok := ipsecLookupSelectsOwner(wildcard, fqdn); ok {
			t.Errorf("an ID_ANY lookup must not select an FQDN owner")
		}
	})
	t.Run("ID_ANY local identity commits", func(t *testing.T) {
		requireNoCollision17772(t, identityPair17772("hostname", "a.example.com", "hostname", "b.example.com",
			`set security ike gateway gw-b local-identity distinguished-name "0.0.0.0"`))
	})
	t.Run("unspecified local address commits", func(t *testing.T) {
		requireNoCollision17772(t, identityPair17772("hostname", "a.example.com", "hostname", "b.example.com",
			"set security ike gateway gw-b local-address 0.0.0.0"))
		requireNoCollision17772(t, identityPair17772("hostname", "a.example.com", "hostname", "b.example.com",
			"set security ike gateway gw-b local-address ::"))
	})
}

// strongSwan's identification_create_from_string maps "", "%any", "%any6",
// "0.0.0.0", "*", "::" and "0::0" to ID_ANY whenever the string reaches it
// unprefixed and without '@', so the declared xpf type does not matter for the
// types that render their value as-is. Before the fold only inet/inet6 were
// screened, so `remote-identity distinguished-name 0.0.0.0` versus
// `email ::` committed two wildcard PSK owners and bypassed #16845.
func TestPSKIdentityAnySelectors18428(t *testing.T) {
	anyTypes := []string{"inet", "inet6", "distinguished-name", "user-at-hostname", "email"}
	anyValues := []string{"%any", "%any6", "0.0.0.0", "*", "::", "0::0"}
	for _, idType := range anyTypes {
		for _, value := range anyValues {
			identity, selector := ipsecIKEIdentityKey(idType, value)
			if identity.typeID != 0 || identity.encoding != "" {
				t.Errorf("%s %q renders %q: type %d encoding %x, want ID_ANY (type 0, no encoding)",
					idType, value, selector, identity.typeID, identity.encoding)
			}
			if !IsAnyIPsecRemoteIdentity(idType, value) {
				t.Errorf("IsAnyIPsecRemoteIdentity(%s, %q) = false; strongSwan parses it as ID_ANY", idType, value)
			}
		}
	}
	if !IsAnyIPsecRemoteIdentity("inet", "{0}:peer") {
		t.Errorf("a numeric {0}: prefix is ID_ANY and must not discriminate a peer")
	}
	// Oracle-confirmed near misses: an IPv6 address, an FQDN, a KEY_ID.
	notAny := []struct{ idType, value string }{
		{"distinguished-name", "::0"},
		{"distinguished-name", "0:0::0"},
		{"distinguished-name", "0.0.0.0/0"},
		{"user-at-hostname", "%ANY"},
		{"hostname", "0.0.0.0"},
		{"hostname", "::"},
		{"key-id", "00"},
		{"distinguished-name", "[::]"},
	}
	for _, c := range notAny {
		identity, selector := ipsecIKEIdentityKey(c.idType, c.value)
		if identity.typeID == 0 {
			t.Errorf("%s %q renders %q as ID_ANY; strongSwan does not", c.idType, c.value, selector)
		}
		if IsAnyIPsecRemoteIdentity(c.idType, c.value) {
			t.Errorf("IsAnyIPsecRemoteIdentity(%s, %q) = true for a discriminating identity", c.idType, c.value)
		}
	}
	if IsAnyIPsecRemoteIdentity("distinguished-name", "") {
		t.Errorf("an empty value means no remote-identity, not ID_ANY")
	}

	wildcardPair := func(addrA, addrB string) []string {
		gwA := []string{
			"set security ike gateway gw-a ike-policy ike-pol",
			"set security ike gateway gw-a address " + addrA,
			`set security ike gateway gw-a remote-identity distinguished-name "0.0.0.0"`,
		}
		gwB := []string{
			"set security ike gateway gw-b ike-policy ike-pol",
			"set security ike gateway gw-b address " + addrB,
			`set security ike gateway gw-b remote-identity email "::"`,
		}
		return twoVPN17772(gwA, gwB, "secret-a", "secret-b")
	}
	t.Run("wildcard remote identities on hostname-addressed gateways are refused by #16845", func(t *testing.T) {
		_, err := CompileConfig(buildTree17772(t, wildcardPair("peer-a.example.com", "peer-b.example.com")))
		if err == nil || !strings.Contains(err.Error(), "#16845") {
			t.Fatalf("ID_ANY remote-identity under a non-inet type must be refused like inet 0.0.0.0, got %v", err)
		}
	})
	t.Run("wildcard remote identities scope the secret by gateway address", func(t *testing.T) {
		requireNoCollision17772(t, wildcardPair("203.0.113.1", "203.0.113.2"))
		gw := &IPsecGateway{Address: "203.0.113.1", RemoteIDType: "distinguished-name", RemoteIDValue: "0.0.0.0"}
		if got := IPsecPSKPeerSelectors(gw.Address, gw); len(got) != 1 || got[0] != "203.0.113.1" {
			t.Fatalf("an ID_ANY remote-identity must not become a PSK owner; selectors = %q, want the gateway IP", got)
		}
	})
	t.Run("wildcard remote identities sharing a gateway address collide on the address", func(t *testing.T) {
		requireCollision17772(t, wildcardPair("203.0.113.1", "203.0.113.1"))
	})
}

func TestPSKIdentityCollisionDiagnostics18428(t *testing.T) {
	cases := []struct {
		name, aType, a, bType, b string
		want                     []string
	}{
		{"FQDN case", "hostname", "VPN.example.com", "hostname", "vpn.example.com",
			[]string{`"@VPN.example.com"`, `"@vpn.example.com"`, "FQDN case-insensitive"}},
		{"RFC822 local-part case", "user-at-hostname", "Alice@corp.example", "user-at-hostname", "alice@corp.example",
			[]string{`"Alice@corp.example"`, `"alice@corp.example"`, "RFC822 case-insensitive"}},
		{"DN versus user-at-hostname of the same text", "user-at-hostname", "CN=peer", "distinguished-name", "CN=peer",
			[]string{`selector "CN=peer" on ike gateway "gw-a"`, `selector "CN=peer" on ike gateway "gw-b"`, "identical DN encoding"}},
		{"DN structural case fold", "distinguished-name", "CN=Peer,O=Corp", "distinguished-name", "CN=peer,O=corp",
			[]string{`"CN=Peer,O=Corp"`, `"CN=peer,O=corp"`, "DN equality"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := CompileConfig(buildTree17772(t, identityPair17772(c.aType, c.a, c.bType, c.b)))
			if err == nil {
				t.Fatal("expected a #17772 collision")
			}
			for _, want := range c.want {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("refusal must name both rendered selectors and the equality rule; missing %s in:\n%v", want, err)
				}
			}
		})
	}
	t.Run("local identity refusal names the local selector and the rule", func(t *testing.T) {
		cmds := identityPair17772("hostname", "shared.example.com", "hostname", "gw-b-peer.example.com",
			"set security ike gateway gw-b local-identity hostname SHARED.example.com")
		_, err := CompileConfig(buildTree17772(t, cmds))
		if err == nil {
			t.Fatal("expected a #17772 collision")
		}
		for _, want := range []string{`"@shared.example.com"`, `local identity "@SHARED.example.com"`, "FQDN case-insensitive"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("missing %s in:\n%v", want, err)
			}
		}
	})
}

func TestPSKIdentityPrefixCaseAndEmptyLastRDN18428(t *testing.T) {
	t.Run("type prefix is case-insensitive", func(t *testing.T) {
		requireCollision17772(t, identityPair17772("inet", "FQDN:peer.example", "hostname", "peer.example"))
		requireCollision17772(t, identityPair17772("inet", "DnS:peer.example", "hostname", "PEER.example"))
	})
	// compare_dn() finishes only when both RDN enumerators end at the DN end;
	// an empty LAST value unwraps to a NULL chunk, so such DNs match only
	// byte-identically (libstrongswan 6.1.0-2: `CN=Peer, O=` != `CN=peer, O=`).
	t.Run("empty last RDN value disables DN case folding", func(t *testing.T) {
		requireNoCollision17772(t, identityPair17772("distinguished-name", "CN=Peer, O=", "distinguished-name", "CN=peer, O="))
		requireNoCollision17772(t, identityPair17772("distinguished-name", "CN=Peer,OU=,O=", "distinguished-name", "CN=peer,OU=,O="))
	})
	t.Run("empty last RDN value still matches byte-identically", func(t *testing.T) {
		requireCollision17772(t, identityPair17772("distinguished-name", "CN=peer, O=", "inet", "asn1dn:#301a310d300b060355040313047065657231093007060355040a1300"))
	})
	t.Run("an empty value that is not last still folds", func(t *testing.T) {
		requireCollision17772(t, identityPair17772("distinguished-name", "O=, CN=Peer", "distinguished-name", "O=, CN=peer"))
		requireCollision17772(t, identityPair17772("distinguished-name", "CN=Peer, O=x", "distinguished-name", "CN=peer, O=x"))
	})
	// atodn() parses at most 20 RDNs; a longer DN is not a DN to strongSwan
	// but a literal KEY_ID, compared byte for byte (oracle-confirmed).
	t.Run("more than 20 RDNs is a literal KEY_ID", func(t *testing.T) {
		rdns := func(n int, upper bool) string {
			parts := make([]string, n)
			for i := range parts {
				value := "u" + string(rune('a'+i))
				if upper {
					value = strings.ToUpper(value)
				}
				parts[i] = "OU=" + value
			}
			return strings.Join(parts, ",")
		}
		twenty, _ := ipsecIKEIdentityKey("distinguished-name", rdns(20, false))
		twentyOne, _ := ipsecIKEIdentityKey("distinguished-name", rdns(21, false))
		if twenty.typeID != 9 || twentyOne.typeID != 11 {
			t.Fatalf("20 RDNs must parse as a DN and 21 as KEY_ID: types %d/%d", twenty.typeID, twentyOne.typeID)
		}
		requireCollision17772(t, identityPair17772("distinguished-name", rdns(20, false), "distinguished-name", rdns(20, true)))
		requireNoCollision17772(t, identityPair17772("distinguished-name", rdns(21, false), "distinguished-name", rdns(21, true)))
	})
}
