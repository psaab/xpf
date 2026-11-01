package config

import (
	"strings"
	"testing"
)

// #18428 review folds. strongSwan's equals() is directional (a type-9 LEFT
// operand compares as a DN against the right operand's raw bytes), but which
// identity is the lookup key depends on the exchange, not on gateway names, so
// collision DETECTION treats a match in either direction as a collision. These
// cells run every directional pair with the gateway names swapped: before the
// fold `distinguished-name CN=peer` vs `key-id 300f...` was refused only when
// the DN sorted first. ID_ANY spellings, diagnostics, the case-insensitive
// type prefix and the empty-last-RDN quirk are oracle-checked against
// libstrongswan 6.1.0-2 (docs/log/18428.md).

func TestPSKIdentityCollisionEitherDirection18428(t *testing.T) {
	pairs := []struct{ name, aType, a, bType, b string }{
		{"textual DN versus rendered KEY_ID", "distinguished-name", "CN=peer", "key-id", "300f310d300b0603550403130470656572"},
		{"textual DN versus KEY_ID case variant", "distinguished-name", "CN=peer", "key-id", "300f310d300b0603550403130450454552"},
		{"asn1dn versus keyid prefix", "inet", "asn1dn:#300f310d300b0603550403130470656572", "inet", "keyid:#300f310d300b0603550403130470656572"},
		{"numeric type-9 versus FQDN raw bytes", "inet", "{9}:#300f310d300b0603550403130470656572", "inet", "{2}:#300f310d300b0603550403130450454552"},
	}
	for _, pair := range pairs {
		t.Run(pair.name+" (DN on gw-a)", func(t *testing.T) {
			requireCollision17772(t, identityPair17772(pair.aType, pair.a, pair.bType, pair.b))
		})
		t.Run(pair.name+" (DN on gw-b)", func(t *testing.T) {
			requireCollision17772(t, identityPair17772(pair.bType, pair.b, pair.aType, pair.a))
		})
	}

	// Peer selector against the OTHER gateway's local identity, in both
	// gateway orders: the local DN is the type-9 left operand either way.
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
	t.Run("local DN on gw-a versus KEY_ID peer selector on gw-b", func(t *testing.T) {
		requireCollision17772(t, localOnA)
	})
	t.Run("local DN on gw-b versus KEY_ID peer selector on gw-a", func(t *testing.T) {
		requireCollision17772(t, identityPair17772("key-id", "300f310d300b0603550403130450454552", "hostname", "gw-b-peer.example.com",
			"set security ike gateway gw-b local-identity distinguished-name CN=peer"))
	})

	t.Run("DN versus a padded KEY_ID of a different length stays distinct both ways", func(t *testing.T) {
		requireNoCollision17772(t, identityPair17772("inet", "asn1dn:#300f310d300b0603550403130470656572", "inet", "keyid:#3082000f310d300b0603550403130470656572"))
		requireNoCollision17772(t, identityPair17772("inet", "keyid:#3082000f310d300b0603550403130470656572", "inet", "asn1dn:#300f310d300b0603550403130470656572"))
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
		{"DN versus KEY_ID bytes, KEY_ID on gw-a", "key-id", "300f310d300b0603550403130470656572", "distinguished-name", "CN=peer",
			[]string{`"@#300f310d300b0603550403130470656572"`, `"CN=peer"`, "DN encoding equals KEY_ID bytes"}},
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
		cmds := identityPair17772("key-id", "300f310d300b0603550403130450454552", "hostname", "gw-b-peer.example.com",
			"set security ike gateway gw-b local-identity distinguished-name CN=peer")
		_, err := CompileConfig(buildTree17772(t, cmds))
		if err == nil {
			t.Fatal("expected a #17772 collision")
		}
		for _, want := range []string{`"@#300f310d300b0603550403130450454552"`, `local identity "CN=peer"`,
			"DN compared against KEY_ID bytes as a DN"} {
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
