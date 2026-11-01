package ipsec

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestPSKIdentityCollisionRender17772(t *testing.T) {
	manager := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
	build := func(gateways map[string]*config.IPsecGateway, vpns map[string]*config.IPsecVPN) *config.IPsecConfig {
		return &config.IPsecConfig{
			Gateways:  gateways,
			VPNs:      vpns,
			Proposals: map[string]*config.IPsecProposal{},
		}
	}
	assertSkipped := func(t *testing.T, cfg *config.IPsecConfig, names ...string) (string, map[string]bool) {
		t.Helper()
		text, rendered, err := manager.renderConfig(cfg)
		if err != nil {
			t.Fatalf("renderConfig: %v", err)
		}
		blocks := parseSecretBlocks(t, text)
		for _, name := range names {
			if rendered[name] {
				t.Errorf("colliding connection %q must not render: %s", name, text)
			}
			if _, ok := blocks["ike-"+name]; ok {
				t.Errorf("colliding connection %q emitted a PSK secret: %s", name, text)
			}
		}
		return text, rendered
	}

	t.Run("shared remote identity skips both colliding connections but keeps unrelated VPN", func(t *testing.T) {
		cfg := build(map[string]*config.IPsecGateway{
			"gw-a": {Name: "gw-a", Address: "203.0.113.1", RemoteIDType: "hostname", RemoteIDValue: "shared.example.com"},
			"gw-b": {Name: "gw-b", Address: "203.0.113.2", RemoteIDType: "fqdn", RemoteIDValue: "SHARED.EXAMPLE.COM"},
			"gw-c": {Name: "gw-c", Address: "203.0.113.3"},
		}, map[string]*config.IPsecVPN{
			"a": {Gateway: "gw-a", PSK: config.NewSecret("secret-a")},
			"b": {Gateway: "gw-b", PSK: config.NewSecret("secret-b")},
			"c": {Gateway: "gw-c", PSK: config.NewSecret("secret-c")},
		})
		text, rendered := assertSkipped(t, cfg, "gw-a", "gw-b")
		if !rendered["gw-c"] {
			t.Fatalf("unrelated connection must render alongside skips:\n%s", text)
		}
	})

	t.Run("distinct remote identities render both connections", func(t *testing.T) {
		cfg := build(map[string]*config.IPsecGateway{
			"gw-a": {Name: "gw-a", Address: "203.0.113.1", RemoteIDType: "hostname", RemoteIDValue: "a.example.com"},
			"gw-b": {Name: "gw-b", Address: "203.0.113.2", RemoteIDType: "hostname", RemoteIDValue: "b.example.com"},
		}, map[string]*config.IPsecVPN{
			"a": {Gateway: "gw-a", PSK: config.NewSecret("secret-a")},
			"b": {Gateway: "gw-b", PSK: config.NewSecret("secret-b")},
		})
		text, rendered, err := manager.renderConfig(cfg)
		if err != nil {
			t.Fatalf("renderConfig: %v", err)
		}
		if !rendered["gw-a"] || !rendered["gw-b"] {
			t.Fatalf("distinct peer identities must render both connections: rendered=%v\n%s", rendered, text)
		}
	})

	t.Run("remote identity equal to another connection local identity skips both", func(t *testing.T) {
		cfg := build(map[string]*config.IPsecGateway{
			"gw-a": {Name: "gw-a", Address: "203.0.113.1", RemoteIDType: "hostname", RemoteIDValue: "shared.example.com"},
			"gw-b": {Name: "gw-b", Address: "203.0.113.2", LocalIDType: "fqdn", LocalIDValue: "SHARED.EXAMPLE.COM"},
		}, map[string]*config.IPsecVPN{
			"a": {Gateway: "gw-a", PSK: config.NewSecret("secret-a")},
			"b": {Gateway: "gw-b", PSK: config.NewSecret("secret-b")},
		})
		assertSkipped(t, cfg, "gw-a", "gw-b")
	})

	t.Run("mixed hostname and IP without remote identity skips connection", func(t *testing.T) {
		cfg := build(map[string]*config.IPsecGateway{
			"gw": {Name: "gw", Address: "peer.example.test, 203.0.113.1"},
		}, map[string]*config.IPsecVPN{
			"site": {Gateway: "gw", PSK: config.NewSecret("site-secret")},
		})
		assertSkipped(t, cfg, "gw")
	})

	t.Run("explicit remote identity scopes mixed hostname and IP connection", func(t *testing.T) {
		cfg := build(map[string]*config.IPsecGateway{
			"gw": {Name: "gw", Address: "peer.example.test, 203.0.113.1", RemoteIDType: "hostname", RemoteIDValue: "peer.example.test"},
		}, map[string]*config.IPsecVPN{
			"site": {Gateway: "gw", PSK: config.NewSecret("site-secret")},
		})
		text, rendered, err := manager.renderConfig(cfg)
		if err != nil {
			t.Fatalf("renderConfig: %v", err)
		}
		if !rendered["gw"] {
			t.Fatalf("explicit remote-identity must preserve mixed gateway render:\n%s", text)
		}
		block := parseSecretBlocks(t, text)["ike-gw"]
		if len(block.ids) != 1 || block.ids[0] != "@peer.example.test" {
			t.Fatalf("mixed gateway selectors = %v, want exactly [@peer.example.test]", block.ids)
		}
	})

	t.Run("same remote identity with same PSK remains renderable", func(t *testing.T) {
		cfg := build(map[string]*config.IPsecGateway{
			"gw-a": {Name: "gw-a", Address: "203.0.113.1", RemoteIDType: "hostname", RemoteIDValue: "shared.example.com"},
			"gw-b": {Name: "gw-b", Address: "203.0.113.2", RemoteIDType: "fqdn", RemoteIDValue: "shared.example.com"},
		}, map[string]*config.IPsecVPN{
			"a": {Gateway: "gw-a", PSK: config.NewSecret("same-secret")},
			"b": {Gateway: "gw-b", PSK: config.NewSecret("same-secret")},
		})
		text, rendered, err := manager.renderConfig(cfg)
		if err != nil {
			t.Fatalf("renderConfig: %v", err)
		}
		if !rendered["gw-a"] || !rendered["gw-b"] {
			t.Fatalf("identical shared credentials may render: rendered=%v\n%s", rendered, text)
		}
	})

	t.Run("cross-type rendered-identical owner with the same PSK renders both", func(t *testing.T) {
		cfg := build(map[string]*config.IPsecGateway{
			"gw-a": {Name: "gw-a", Address: "203.0.113.1", RemoteIDType: "inet", RemoteIDValue: "peer@corp.example"},
			"gw-b": {Name: "gw-b", Address: "203.0.113.2", RemoteIDType: "email", RemoteIDValue: "peer@corp.example"},
		}, map[string]*config.IPsecVPN{
			"a": {Gateway: "gw-a", PSK: config.NewSecret("same-secret")},
			"b": {Gateway: "gw-b", PSK: config.NewSecret("same-secret")},
		})
		text, rendered, err := manager.renderConfig(cfg)
		if err != nil || !rendered["gw-a"] || !rendered["gw-b"] {
			t.Fatalf("same PSK may share an identical rendered owner: rendered=%v err=%v\n%s", rendered, err, text)
		}
		blocks := parseSecretBlocks(t, text)
		for _, name := range []string{"gw-a", "gw-b"} {
			block, ok := blocks["ike-"+name]
			if !ok || len(block.ids) != 1 || block.ids[0] != "peer@corp.example" {
				t.Fatalf("%s secret selectors = %+v, want [peer@corp.example]\n%s", name, block, text)
			}
		}
	})

	t.Run("RFC822 aliases collide and retain unrelated VPN", func(t *testing.T) {
		pairs := []struct{ aType, a, bType, b string }{
			{"rfc822", "peer@corp.example", "user-at-hostname", "peer@CORP.EXAMPLE"},
			{"email", "peer@corp.example", "user-at-hostname", "Peer@Corp.Example"},
			{"email", "peer@corp.example", "rfc822", "PEER@CORP.EXAMPLE"},
		}
		for _, pair := range pairs {
			pair := pair
			t.Run(pair.aType+"_"+pair.bType, func(t *testing.T) {
				cfg := build(map[string]*config.IPsecGateway{
					"gw-a": {Name: "gw-a", Address: "203.0.113.1", RemoteIDType: pair.aType, RemoteIDValue: pair.a},
					"gw-b": {Name: "gw-b", Address: "203.0.113.2", RemoteIDType: pair.bType, RemoteIDValue: pair.b},
					"gw-c": {Name: "gw-c", Address: "203.0.113.3"},
				}, map[string]*config.IPsecVPN{
					"a": {Gateway: "gw-a", PSK: config.NewSecret("secret-a")},
					"b": {Gateway: "gw-b", PSK: config.NewSecret("secret-b")},
					"c": {Gateway: "gw-c", PSK: config.NewSecret("secret-c")},
				})
				text, rendered := assertSkipped(t, cfg, "gw-a", "gw-b")
				if !rendered["gw-c"] {
					t.Fatalf("unrelated VPN must render alongside RFC822 skips:\n%s", text)
				}
			})
		}
	})

	t.Run("canonical atodn spellings skip both secrets", func(t *testing.T) {
		pairs := []struct{ name, a, b string }{
			{"separator spacing and case", "CN=peer, O=Org", "cn=PEER,o=ORG"},
			{"slash separator", "/CN=peer/O=Org", "CN=PEER,O=ORG"},
			{"leading whitespace still selects slash delimiter", " /CN=peer/O=Org", "/CN=PEER/O=ORG"},
			{"trailing delimiter with whitespace", "CN=peer,O=Org, ", "CN=PEER,O=ORG"},
			{"space terminates attribute token", "CN=peer,O other=thing", "CN=PEER,O=other=thing"},
			{"PrintableString case", "SN=Smith", "sn=SMITH"},
			{"email attribute aliases", "E=Peer@corp.example,O=Org", "emailAddress=PEER@CORP.EXAMPLE,o=ORG"},
			{"employeeNumber aliases", "EN=12345", "employeeNumber=12345"},
		}
		for _, pair := range pairs {
			pair := pair
			t.Run(pair.name, func(t *testing.T) {
				cfg := build(map[string]*config.IPsecGateway{
					"gw-a": {Name: "gw-a", Address: "203.0.113.1", RemoteIDType: "distinguished-name", RemoteIDValue: pair.a},
					"gw-b": {Name: "gw-b", Address: "203.0.113.2", RemoteIDType: "distinguished-name", RemoteIDValue: pair.b},
				}, map[string]*config.IPsecVPN{
					"a": {Gateway: "gw-a", PSK: config.NewSecret("secret-a")},
					"b": {Gateway: "gw-b", PSK: config.NewSecret("secret-b")},
				})
				assertSkipped(t, cfg, "gw-a", "gw-b")
			})
		}
	})

	t.Run("key-id spellings compare chunk_from_hex bytes", func(t *testing.T) {
		pairs := []struct{ name, a, b string }{
			{"invalid nibble maps to zero", "zz", "00"},
			{"hex case", "7a7a", "7A7A"},
			{"0x prefix and colon separators", "0x7a7a", "7a:7a"},
			{"single separator skip per low nibble", "7a::7a", "a07a"},
			{"odd nibble is left padded", "7a7", "07A7"},
			{"two zero bytes with separators", "0000", "00:00"},
		}
		for _, pair := range pairs {
			pair := pair
			t.Run(pair.name, func(t *testing.T) {
				cfg := build(map[string]*config.IPsecGateway{
					"gw-a": {Name: "gw-a", Address: "203.0.113.1", RemoteIDType: "key-id", RemoteIDValue: pair.a},
					"gw-b": {Name: "gw-b", Address: "203.0.113.2", RemoteIDType: "key-id", RemoteIDValue: pair.b},
				}, map[string]*config.IPsecVPN{
					"a": {Gateway: "gw-a", PSK: config.NewSecret("secret-a")},
					"b": {Gateway: "gw-b", PSK: config.NewSecret("secret-b")},
				})
				assertSkipped(t, cfg, "gw-a", "gw-b")
			})
		}
	})

	t.Run("typed DER identities and syntax fallbacks collide", func(t *testing.T) {
		pairs := []struct{ name, aType, a, bType, b string }{
			{"hostname selector falls back to literal KEY_ID", "hostname", "CN=peer", "key-id", "40434e3d70656572"},
			{"unsupported DN falls back to literal KEY_ID", "distinguished-name", "broken=peer", "key-id", "62726f6b656e3d70656572"},
			{"textual DN equals asn1dn DER", "distinguished-name", "CN=peer", "inet", "asn1dn:#300f310d300b0603550403130470656572"},
			{"textual DN equals numeric type-9 DER", "distinguished-name", "CN=peer", "inet", "{9}:#300f310d300b0603550403130470656572"},
			{"cross-tag exact DN value equals", "distinguished-name", "CN=Peer", "inet", "asn1dn:#300f310d300b06035504030c0450656572"},
			{"xmppaddr wraps into asn1gn DER", "inet", "xmppaddr:peer", "inet", "asn1gn:#a01206082b06010505070805a0060c0470656572"},
			{"untyped subnet masks host bits", "inet", "198.51.100.0/24", "inet", "198.51.100.1/24"},
			{"untyped subnet equals ipv4net bytes", "inet", "198.51.100.0/24", "inet", "ipv4net:#c6336400ffffff00"},
			{"URI prefix is type 201", "inet", "uri:Peer", "inet", "{201}:Peer"},
			{"positive numeric type prefix", "inet", "{+2}:peer", "inet", "fqdn:peer"},
			{"space-prefixed numeric type", "inet", "{ 2}:peer", "inet", "fqdn:peer"},
			{"numeric type truncates to 32 bits", "inet", "{4294967298}:peer", "inet", "fqdn:peer"},
			{"wide type truncates to ID_IPV4", "inet", "{4294967297}:peer", "inet", "{1}:peer"},
			{"hexadecimal base-0 numeric type", "inet", "{0x2}:peer", "inet", "fqdn:peer"},
			{"negative type wraps to uint32", "inet", "{-1}:peer", "inet", "{4294967295}:peer"},
			{"negative type truncates to type 2", "inet", "{-4294967294}:peer", "inet", "fqdn:peer"},
			{"octal invalid digit falls back to literal KEY_ID", "inet", "{08}:peer", "key-id", "7b30387d3a70656572"},
			{"overflowing type falls back to literal KEY_ID", "inet", "{18446744073709551617}:peer", "key-id", "7b31383434363734343037333730393535313631377d3a70656572"},
			{"identical malformed DN bytes compare equal", "inet", "asn1dn:#3000", "inet", "{9}:#3000"},
			{"organizationIdentifier PrintableString case folding", "distinguished-name", "organizationIdentifier=Peer", "distinguished-name", "organizationIdentifier=peer"},
			{"organizationIdentifier equals asn1dn", "distinguished-name", "organizationIdentifier=Peer", "inet", "asn1dn:#300f310d300b0603550461130450656572"},
			{"IPv4 range equals type-7 DER", "inet", "198.51.100.1-198.51.100.2", "inet", "ipv4range:#c6336401c6336402"},
			{"IPv6 range equals type-8 DER", "inet", "2001:db8::1-2001:db8::2", "inet", "ipv6range:#20010db800000000000000000000000120010db8000000000000000000000002"},
			{"hyphenated FQDN remains type 2", "inet", "host-a-host-b", "inet", "fqdn:host-a-host-b"},
			{"IPv4 prefix suffix ignores trailing text", "inet", "198.51.100.1/24junk", "inet", "198.51.100.1/24"},
			{"IPv4 prefix accepts leading zero", "inet", "198.51.100.1/024", "inet", "198.51.100.1/24"},
			{"IPv4 prefix accepts leading plus", "inet", "198.51.100.1/+24", "inet", "198.51.100.1/24"},
			{"IPv4 prefix skips leading whitespace", "inet", "198.51.100.1/ 24", "inet", "198.51.100.1/24"},
			{"empty IPv4 prefix defaults to zero", "inet", "198.51.100.1/", "inet", "198.51.100.1/0"},
			{"IPv6 prefix suffix ignores trailing text", "inet", "2001:db8::1/64junk", "inet", "2001:db8::1/64"},
			{"IPv4 positive int32 subnet wrap", "inet", "198.51.100.1/4294967320", "inet", "198.51.100.1/24"},
			{"IPv4 negative int32 subnet wrap", "inet", "198.51.100.1/-4294967272", "inet", "198.51.100.1/24"},
			{"IPv4 subnet wrap to one", "inet", "198.51.100.1/4294967297", "inet", "198.51.100.1/1"},
			{"IPv4 subnet wrap to zero", "inet", "198.51.100.1/8589934592", "inet", "198.51.100.1/0"},
			{"IPv6 positive int32 subnet wrap", "inet", "2001:db8::1/4294967360", "inet", "2001:db8::1/64"},
			{"IPv6 negative int32 subnet wrap", "inet", "2001:db8::1/-4294967232", "inet", "2001:db8::1/64"},
			{"IPv6 subnet wrap to 128", "inet", "2001:db8::1/4294967424", "inet", "2001:db8::1/128"},
			{"negative strtol overflow narrows to zero", "inet", "198.51.100.1/-99999999999999999999999999", "inet", "198.51.100.1/0"},
			{"PrintableString compares through NUL only", "inet", "asn1dn:#300e310c300a06035504031303410042", "inet", "asn1dn:#300e310c300a06035504031303610043"},
			{"emailAddress compares through NUL only", "inet", "asn1dn:#30143112301006092a864886f70d0109011603410042", "inet", "asn1dn:#30143112301006092a864886f70d0109011603610043"},
			{"identical primitive outer sequence equals exact bytes", "inet", "asn1dn:#100f310d300b0603550403130470656572", "inet", "asn1dn:#100f310d300b0603550403130470656572"},
			{"identical primitive SET equals exact bytes", "inet", "asn1dn:#300f110d300b0603550403130470656572", "inet", "asn1dn:#300f110d300b0603550403130470656572"},
			{"identical primitive inner sequence equals exact bytes", "inet", "asn1dn:#300f310d100b0603550403130470656572", "inet", "asn1dn:#300f310d100b0603550403130470656572"},
			{"nonminimal outer length compares DN values", "inet", "asn1dn:#30810f310d300b0603550403130470656572", "inet", "asn1dn:#30810f310d300b0603550403130450454552"},
			{"nonminimal SET length compares DN values", "inet", "asn1dn:#301031810d300b0603550403130470656572", "inet", "asn1dn:#301031810d300b0603550403130450454552"},
			{"nonminimal attribute SEQUENCE length compares DN values", "inet", "asn1dn:#3010310e30810b0603550403130470656572", "inet", "asn1dn:#3010310e30810b0603550403130450454552"},
			{"nonminimal OID length compares DN values", "inet", "asn1dn:#3010310e300c068103550403130470656572", "inet", "asn1dn:#3010310e300c068103550403130450454552"},
			{"nonminimal value length compares DN values", "inet", "asn1dn:#3010310e300c060355040313810470656572", "inet", "asn1dn:#3010310e300c060355040313810450454552"},
			{"nonminimal two-octet outer length compares DN values", "inet", "asn1dn:#3082000f310d300b0603550403130470656572", "inet", "asn1dn:#3082000f310d300b0603550403130450454552"},
			{"nonminimal two-octet SET length compares DN values", "inet", "asn1dn:#30113182000d300b0603550403130470656572", "inet", "asn1dn:#30113182000d300b0603550403130450454552"},
			{"nonminimal two-octet attribute SEQUENCE length compares DN values", "inet", "asn1dn:#3011310f3082000b0603550403130470656572", "inet", "asn1dn:#3011310f3082000b0603550403130450454552"},
			{"nonminimal two-octet OID length compares DN values", "inet", "asn1dn:#3011310f300d06820003550403130470656572", "inet", "asn1dn:#3011310f300d06820003550403130450454552"},
			{"nonminimal two-octet value length compares DN values", "inet", "asn1dn:#3011310f300d06035504031382000470656572", "inet", "asn1dn:#3011310f300d06035504031382000450454552"},
			{"maximum eight-octet outer length compares DN values", "inet", "asn1dn:#3088000000000000000f310d300b0603550403130470656572", "inet", "asn1dn:#3088000000000000000f310d300b0603550403130450454552"},
			{"identical malformed total length remains exact-equal", "inet", "asn1dn:#3010310d300b0603550403130470656572", "inet", "asn1dn:#3010310d300b0603550403130470656572"},
			{"identical constructed OID remains exact-byte equal", "inet", "asn1dn:#300f310d300b2603550403130470656572", "inet", "asn1dn:#300f310d300b2603550403130470656572"},
			{"identical leading empty SET equals exact bytes", "inet", "asn1dn:#30113100310d300b0603550403130470656572", "inet", "asn1dn:#30113100310d300b0603550403130470656572"},
			{"identical trailing empty SET equals exact bytes", "inet", "asn1dn:#3011310d300b06035504031304706565723100", "inet", "asn1dn:#3011310d300b06035504031304706565723100"},
			{"identical malformed DN bytes equal KEY_ID bytes", "inet", "asn1dn:#3000", "inet", "keyid:#3000"},
			{"DN left compares KEY_ID DER bytes", "inet", "asn1dn:#300f310d300b0603550403130470656572", "inet", "keyid:#300f310d300b0603550403130470656572"},
			{"DN left folds KEY_ID DER case", "inet", "asn1dn:#300f310d300b0603550403130470656572", "inet", "keyid:#300f310d300b0603550403130450454552"},
			{"textual DN left compares KEY_ID DER bytes", "distinguished-name", "CN=peer", "inet", "keyid:#300f310d300b0603550403130470656572"},
			{"numeric type-9 DN left compares KEY_ID DER bytes", "inet", "{9}:#300f310d300b0603550403130470656572", "inet", "keyid:#300f310d300b0603550403130470656572"},
			{"DN left compares KEY_ID padded DER case", "inet", "asn1dn:#3082000f310d300b0603550403130470656572", "inet", "keyid:#3082000f310d300b0603550403130450454552"},
			{"DN left compares exact FQDN type DER bytes", "inet", "asn1dn:#300f310d300b0603550403130470656572", "inet", "{2}:#300f310d300b0603550403130470656572"},
			{"DN left folds rendered KEY_ID DER case", "distinguished-name", "CN=peer", "key-id", "300f310d300b0603550403130450454552"},
			{"DN left folds FQDN type raw DER case", "inet", "asn1dn:#300f310d300b0603550403130470656572", "inet", "{2}:#300f310d300b0603550403130450454552"},
			{"raw high-tag value equals same PrintableString bytes", "inet", "asn1dn:#300f310d300b06035504031f0470656572", "inet", "asn1dn:#300f310d300b0603550403130470656572"},
			{"raw high-tag DN left compares canonical KEY_ID bytes", "inet", "asn1dn:#300f310d300b06035504031f0470656572", "inet", "keyid:#300f310d300b0603550403130470656572"},
			{"raw high-tag equals other raw tag with same content", "inet", "asn1dn:#300f310d300b06035504031f0470656572", "inet", "asn1dn:#300f310d300b0603550403040470656572"},
			{"raw tags 1f and 0c compare same content", "inet", "asn1dn:#300f310d300b06035504031f0470656572", "inet", "asn1dn:#300f310d300b06035504030c0470656572"},
			{"raw tags 1f and 16 compare same content", "inet", "asn1dn:#300f310d300b06035504031f0470656572", "inet", "asn1dn:#300f310d300b0603550403160470656572"},
			{"OCTET STRING and UTF8String compare exact content", "inet", "asn1dn:#300f310d300b0603550403040470656572", "inet", "asn1dn:#300f310d300b06035504030c0470656572"},
			{"OCTET STRING and IA5String compare exact content", "inet", "asn1dn:#300f310d300b0603550403040470656572", "inet", "asn1dn:#300f310d300b0603550403160470656572"},
			{"UTF8String and IA5String compare exact content", "inet", "asn1dn:#300f310d300b06035504030c0470656572", "inet", "asn1dn:#300f310d300b0603550403160470656572"},
			{"emailAddress IA5 and raw tag compare identical NUL bytes", "inet", "asn1dn:#30143112301006092a864886f70d0109011603410042", "inet", "asn1dn:#30143112301006092a864886f70d0109011f03410042"},
			{"identical raw high-tag value compares exact bytes", "inet", "asn1dn:#300e310c300a06035504031f026100", "inet", "asn1dn:#300e310c300a06035504031f026100"},
			{"reverse operand order: KEY_ID DER versus DN collides (#18428)", "inet", "keyid:#300f310d300b0603550403130470656572", "inet", "asn1dn:#300f310d300b0603550403130470656572"},
			{"reverse operand order: FQDN raw DER versus DN collides (#18428)", "inet", "{2}:#300f310d300b0603550403130470656572", "inet", "asn1dn:#300f310d300b0603550403130470656572"},
			{"reverse operand order: rendered KEY_ID case versus DN collides (#18428)", "key-id", "300f310d300b0603550403130450454552", "inet", "asn1dn:#300f310d300b0603550403130470656572"},
			{"reverse operand order: FQDN raw DER case versus DN collides (#18428)", "inet", "{2}:#300f310d300b0603550403130450454552", "inet", "asn1dn:#300f310d300b0603550403130470656572"},
			{"reverse operand order: KEY_ID versus DN case variant collides (#18428)", "inet", "keyid:#300f310d300b0603550403130470656572", "inet", "asn1dn:#300f310d300b0603550403130450454552"},
			{"reverse operand order: KEY_ID raw high-tag versus DN collides (#18428)", "inet", "keyid:#300f310d300b06035504031f0470656572", "inet", "asn1dn:#300f310d300b0603550403130470656572"},
		}
		for _, pair := range pairs {
			pair := pair
			t.Run(pair.name, func(t *testing.T) {
				cfg := build(map[string]*config.IPsecGateway{
					"gw-a": {Name: "gw-a", Address: "203.0.113.1", RemoteIDType: pair.aType, RemoteIDValue: pair.a},
					"gw-b": {Name: "gw-b", Address: "203.0.113.2", RemoteIDType: pair.bType, RemoteIDValue: pair.b},
				}, map[string]*config.IPsecVPN{
					"a": {Gateway: "gw-a", PSK: config.NewSecret("secret-a")},
					"b": {Gateway: "gw-b", PSK: config.NewSecret("secret-b")},
				})
				assertSkipped(t, cfg, "gw-a", "gw-b")
			})
		}
	})

	t.Run("distinct strongSwan identities render both secrets", func(t *testing.T) {
		pairs := []struct{ name, aType, a, bType, b string }{
			{"one zero byte versus two", "key-id", "zz", "key-id", "0000"},
			{"FQDN non-ASCII bytes remain distinct", "hostname", "é.example", "hostname", "ê.example"},
			{"RFC822 non-ASCII bytes remain distinct", "rfc822", "user@é.example", "rfc822", "user@ê.example"},
			{"odd padded bytes versus ASCII hex text", "key-id", "7a7", "key-id", "376137"},
			{"unknown DN attribute case", "distinguished-name", "broken=peer", "distinguished-name", "BROKEN=PEER"},
			{"double separator differs from plain hex", "key-id", "7a::7a", "key-id", "7a7a"},
			{"URI and numeric ID 12 are distinct", "inet", "uri:Peer", "inet", "{12}:Peer"},
			{"subnet differs from host IP", "inet", "198.51.100.0/24", "inet", "198.51.100.0"},
			{"UTF8 DN differs from uppercase bytes", "distinguished-name", "CN=Peer", "inet", "asn1dn:#300f310d300b06035504030c0450454552"},
			{"backslash DN is not raw KEY_ID", "distinguished-name", "CN=peer\\", "key-id", "434e3d706565725c"},
			{"non-Printable DN keeps case", "distinguished-name", "CN=peer\\", "distinguished-name", "CN=PEER\\"},
			{"RDN order is significant", "distinguished-name", "CN=peer,O=Org", "distinguished-name", "O=ORG,CN=PEER"},
			{"internal DN whitespace", "distinguished-name", "CN=Peer   Name", "distinguished-name", "CN=peer name"},
			{"UTF8 DN sharp-s", "distinguished-name", "CN=Straße", "distinguished-name", "CN=STRASSE"},
			{"plus remains in DN value", "distinguished-name", "CN=peer+OU=VPN", "distinguished-name", "OU=vpn+CN=PEER"},
			{"numeric OID is not an atodn attribute", "distinguished-name", "CN=peer,2.5.4.4=Smith", "distinguished-name", "CN=peer,SN=Smith"},
			{"different malformed DN bytes remain distinct", "inet", "asn1dn:#3000", "inet", "asn1dn:#3001"},
			{"octal invalid digit remains literal KEY_ID", "inet", "{08}:peer", "inet", "fqdn:peer"},
			{"overflowing numeric type remains literal KEY_ID", "inet", "{18446744073709551617}:peer", "inet", "18446744073709551617"},
			{"reversed IPv4 range is not type 7", "inet", "198.51.100.2-198.51.100.1", "inet", "ipv4range:#c6336402c6336401"},
			{"ID_ANY remains distinct from FQDN", "inet", "{0}:any", "inet", "fqdn:any"},
			{"empty numeric type remains distinct from whitespace", "inet", "{}:a", "inet", "{ }:a"},
			{"negative subnet length remains literal", "inet", "198.51.100.1/-24", "inet", "ipv4net:#c6336400ffffff00"},
			{"out-of-range IPv4 prefix remains literal", "inet", "198.51.100.1/33", "inet", "ipv4net:#c6336400ffffff00"},
			{"out-of-range IPv6 prefix remains literal", "inet", "2001:db8::1/129", "inet", "ipv6net:#20010db80000000000000000000000ffffffffffffffffffffffffffffffff"},
			{"positive int32 overflow remains invalid", "inet", "198.51.100.1/2147483648", "inet", "198.51.100.1/24"},
			{"int32 minus one remains invalid", "inet", "198.51.100.1/4294967295", "inet", "198.51.100.1/24"},
			{"positive strtol overflow remains invalid", "inet", "198.51.100.1/99999999999999999999999999", "inet", "198.51.100.1/24"},
			{"primitive outer sequence does not normalize as constructed", "inet", "asn1dn:#100f310d300b0603550403130470656572", "inet", "asn1dn:#300f310d300b0603550403130470656572"},
			{"primitive SET does not normalize as constructed", "inet", "asn1dn:#300f110d300b0603550403130470656572", "inet", "asn1dn:#300f310d300b0603550403130470656572"},
			{"primitive inner sequence does not normalize as constructed", "inet", "asn1dn:#300f310d100b0603550403130470656572", "inet", "asn1dn:#300f310d300b0603550403130470656572"},
			{"primitive outer sequence does not case-fold", "inet", "asn1dn:#100f310d300b0603550403130470656572", "inet", "asn1dn:#100f310d300b0603550403130450454552"},
			{"primitive SET does not case-fold", "inet", "asn1dn:#300f110d300b0603550403130470656572", "inet", "asn1dn:#300f110d300b0603550403130450454552"},
			{"primitive inner sequence does not case-fold", "inet", "asn1dn:#300f310d100b0603550403130470656572", "inet", "asn1dn:#300f310d100b0603550403130450454552"},
			{"constructed OID does not match canonical OID", "inet", "asn1dn:#300f310d300b2603550403130470656572", "inet", "asn1dn:#300f310d300b0603550403130470656572"},
			{"constructed OID does not fold against canonical DN", "inet", "asn1dn:#300f310d300b2603550403130470656572", "inet", "asn1dn:#300f310d300b0603550403130450454552"},
			{"constructed OID case variant stays distinct", "inet", "asn1dn:#300f310d300b2603550403130470656572", "inet", "asn1dn:#300f310d300b2603550403130450454552"},
			{"leading empty SET does not compare padded valid DN", "inet", "asn1dn:#30113100310d300b0603550403130470656572", "inet", "asn1dn:#3082000f310d300b0603550403130470656572"},
			{"leading empty SET case variant remains distinct", "inet", "asn1dn:#30113100310d300b0603550403130470656572", "inet", "asn1dn:#30113100310d300b0603550403130450454552"},
			{"leading empty SET does not compare uppercase padded DN", "inet", "asn1dn:#30113100310d300b0603550403130470656572", "inet", "asn1dn:#3082000f310d300b0603550403130450454552"},
			{"trailing empty SET does not compare padded valid DN", "inet", "asn1dn:#3011310d300b06035504031304706565723100", "inet", "asn1dn:#3082000f310d300b0603550403130470656572"},
			{"trailing empty SET case variant remains distinct", "inet", "asn1dn:#3011310d300b06035504031304706565723100", "inet", "asn1dn:#3011310d300b06035504031304504545523100"},
			{"trailing empty SET does not compare uppercase padded DN", "inet", "asn1dn:#3011310d300b06035504031304706565723100", "inet", "asn1dn:#3082000f310d300b0603550403130450454552"},
			{"leading and trailing empty SET forms remain distinct", "inet", "asn1dn:#30113100310d300b0603550403130470656572", "inet", "asn1dn:#3011310d300b06035504031304706565723100"},
			{"KEY_ID does not fold peer case", "inet", "keyid:#300f310d300b0603550403130470656572", "inet", "keyid:#300f310d300b0603550403130450454552"},
			{"DN canonical keyid padded stays distinct", "inet", "asn1dn:#300f310d300b0603550403130470656572", "inet", "keyid:#3082000f310d300b0603550403130470656572"},
			{"DN padded keyid canonical stays distinct", "inet", "asn1dn:#3082000f310d300b0603550403130470656572", "inet", "keyid:#300f310d300b0603550403130470656572"},
			{"DN against KEY_ID ASCII stays distinct", "inet", "asn1dn:#300f310d300b0603550403130470656572", "inet", "keyid:#434e3d706565725c"},
			{"textual backslash DN against KEY_ID ASCII stays distinct", "distinguished-name", "CN=peer\\", "inet", "keyid:#434e3d706565725c"},
			{"DN left against KEY_ID constructed OID stays distinct", "inet", "asn1dn:#300f310d300b0603550403130470656572", "inet", "keyid:#300f310d300b2603550403130470656572"},
			{"DN left against KEY_ID leading empty SET stays distinct", "inet", "asn1dn:#300f310d300b0603550403130470656572", "inet", "keyid:#30113100310d300b0603550403130470656572"},
			{"DN left against KEY_ID trailing empty SET stays distinct", "inet", "asn1dn:#300f310d300b0603550403130470656572", "inet", "keyid:#3011310d300b06035504031304706565723100"},
			{"DN left against KEY_ID malformed stays distinct", "inet", "asn1dn:#300f310d300b0603550403130470656572", "inet", "keyid:#3000"},
			{"different malformed DN and KEY_ID bytes stay distinct", "inet", "asn1dn:#3000", "inet", "keyid:#3001"},
			{"constructed OID left against KEY_ID canonical stays distinct", "inet", "asn1dn:#300f310d300b2603550403130470656572", "inet", "keyid:#300f310d300b0603550403130470656572"},
			{"leading empty SET left against KEY_ID canonical stays distinct", "inet", "asn1dn:#30113100310d300b0603550403130470656572", "inet", "keyid:#300f310d300b0603550403130470656572"},
			{"zero-length OID with leftover bytes remains malformed", "inet", "asn1dn:#3011310f300d0682000003550403130470656572", "inet", "asn1dn:#3011310f300d0682000003550403130450454552"},
			{"zero-length value with extra TLV remains malformed", "inet", "asn1dn:#3011310f300d0603550403138200000470656572", "inet", "asn1dn:#3011310f300d0603550403138200000450454552"},
			{"mismatched declared total length remains distinct", "inet", "asn1dn:#3010310d300b0603550403130470656572", "inet", "asn1dn:#3010310d300b0603550403130450454552"},
			{"trailing bytes remain outside DN total length", "inet", "asn1dn:#300f310d300b060355040313047065657200", "inet", "asn1dn:#300f310d300b060355040313045045455200"},
			{"nonminimal outer length differs from canonical under total-length gate", "inet", "asn1dn:#30810f310d300b0603550403130470656572", "inet", "asn1dn:#300f310d300b0603550403130470656572"},
			{"padded two-octet outer length differs from canonical under total-length gate", "inet", "asn1dn:#3082000f310d300b0603550403130470656572", "inet", "asn1dn:#300f310d300b0603550403130450454552"},
			{"nine-octet outer length remains malformed", "inet", "asn1dn:#308900000000000000000f310d300b0603550403130470656572", "inet", "asn1dn:#308900000000000000000f310d300b0603550403130450454552"},
			{"embedded NUL prevents type-2 comparison", "inet", "{2}:#410062", "inet", "{2}:#410062"},
			{"embedded NUL prevents type-3 comparison", "inet", "{3}:#410062", "inet", "{3}:#410062"},
			{"embedded NUL differing type-2 values do not compare", "inet", "{2}:#410062", "inet", "{2}:#610062"},
			{"embedded NUL differing type-3 values do not compare", "inet", "{3}:#410062", "inet", "{3}:#610062"},
			{"PrintableString differing before NUL stays distinct", "inet", "asn1dn:#300e310c300a06035504031303410042", "inet", "asn1dn:#300e310c300a06035504031303420043"},
			{"emailAddress differing before NUL stays distinct", "inet", "asn1dn:#30143112301006092a864886f70d0109011603410042", "inet", "asn1dn:#30143112301006092a864886f70d0109011603420043"},
			{"high tag 275 case variants remain distinct", "inet", "asn1dn:#3011310f300d06035504031f82130470656572", "inet", "asn1dn:#3011310f300d06035504031f82130450454552"},
			{"high tag 275 differs from canonical PrintableString", "inet", "asn1dn:#3011310f300d06035504031f82130470656572", "inet", "asn1dn:#300f310d300b0603550403130470656572"},
			{"raw high-tag case variant remains distinct", "inet", "asn1dn:#300f310d300b06035504031f0470656572", "inet", "asn1dn:#300f310d300b06035504031f0450454552"},
			{"raw high-tag does not fold with PrintableString", "inet", "asn1dn:#300f310d300b06035504031f0470656572", "inet", "asn1dn:#300f310d300b0603550403130450454552"},
			{"raw high-tag does not fold with OCTET STRING", "inet", "asn1dn:#300f310d300b06035504031f0470656572", "inet", "asn1dn:#300f310d300b0603550403040450454552"},
			{"raw high-tag does not fold with UTF8String", "inet", "asn1dn:#300f310d300b06035504031f0470656572", "inet", "asn1dn:#300f310d300b06035504030c0450454552"},
			{"raw high-tag does not fold with IA5String", "inet", "asn1dn:#300f310d300b06035504031f0470656572", "inet", "asn1dn:#300f310d300b0603550403160450454552"},
			{"OCTET STRING case variant remains distinct", "inet", "asn1dn:#300f310d300b0603550403040470656572", "inet", "asn1dn:#300f310d300b0603550403040450454552"},
			{"UTF8String case variant remains distinct", "inet", "asn1dn:#300f310d300b06035504030c0470656572", "inet", "asn1dn:#300f310d300b06035504030c0450454552"},
			{"IA5String non-email case variant remains distinct", "inet", "asn1dn:#300f310d300b0603550403160470656572", "inet", "asn1dn:#300f310d300b0603550403160450454552"},
			{"PrintableString does not fold against raw high-tag", "inet", "asn1dn:#300f310d300b0603550403130470656572", "inet", "asn1dn:#300f310d300b06035504031f0450454552"},
			{"emailAddress does not fold against raw high-tag", "inet", "asn1dn:#30143112301006092a864886f70d010901160350656572", "inet", "asn1dn:#30143112301006092a864886f70d0109011f0350454552"},
			{"emailAddress raw-tag content differs after NUL", "inet", "asn1dn:#30143112301006092a864886f70d0109011603410042", "inet", "asn1dn:#30143112301006092a864886f70d0109011f03410043"},
		}
		for _, pair := range pairs {
			pair := pair
			t.Run(pair.name, func(t *testing.T) {
				cfg := build(map[string]*config.IPsecGateway{
					"gw-a": {Name: "gw-a", Address: "203.0.113.1", RemoteIDType: pair.aType, RemoteIDValue: pair.a},
					"gw-b": {Name: "gw-b", Address: "203.0.113.2", RemoteIDType: pair.bType, RemoteIDValue: pair.b},
				}, map[string]*config.IPsecVPN{
					"a": {Gateway: "gw-a", PSK: config.NewSecret("secret-a")},
					"b": {Gateway: "gw-b", PSK: config.NewSecret("secret-b")},
				})
				text, rendered, err := manager.renderConfig(cfg)
				if err != nil || !rendered["gw-a"] || !rendered["gw-b"] {
					t.Fatalf("distinct strongSwan identities must both render: rendered=%v err=%v\n%s", rendered, err, text)
				}
			})
		}
	})
	t.Run("type-9 peer identity matches another gateway KEY_ID local identity", func(t *testing.T) {
		cfg := build(map[string]*config.IPsecGateway{
			"gw-a": {Name: "gw-a", Address: "203.0.113.1", RemoteIDType: "distinguished-name", RemoteIDValue: "CN=peer"},
			"gw-b": {Name: "gw-b", Address: "203.0.113.2", RemoteIDType: "hostname", RemoteIDValue: "gw-b.example.com", LocalIDType: "key-id", LocalIDValue: "300f310d300b0603550403130450454552"},
		}, map[string]*config.IPsecVPN{
			"a": {Gateway: "gw-a", PSK: config.NewSecret("secret-a")},
			"b": {Gateway: "gw-b", PSK: config.NewSecret("secret-b")},
		})
		assertSkipped(t, cfg, "gw-a", "gw-b")
	})

	// #18428: a match in either direction is a collision (the local DN is
	// the type-9 left operand here), so both connections are skipped.
	t.Run("KEY_ID peer identity collides with another gateway type-9 local identity", func(t *testing.T) {
		cfg := build(map[string]*config.IPsecGateway{
			"gw-a": {Name: "gw-a", Address: "203.0.113.1", RemoteIDType: "key-id", RemoteIDValue: "300f310d300b0603550403130450454552"},
			"gw-b": {Name: "gw-b", Address: "203.0.113.2", RemoteIDType: "hostname", RemoteIDValue: "gw-b.example.com", LocalIDType: "distinguished-name", LocalIDValue: "CN=peer"},
		}, map[string]*config.IPsecVPN{
			"a": {Gateway: "gw-a", PSK: config.NewSecret("secret-a")},
			"b": {Gateway: "gw-b", PSK: config.NewSecret("secret-b")},
		})
		assertSkipped(t, cfg, "gw-a", "gw-b")
	})

	t.Run("remote peer identity equal to default local address skips both", func(t *testing.T) {
		cfg := build(map[string]*config.IPsecGateway{
			"gw-a": {Name: "gw-a", Address: "203.0.113.1", RemoteIDType: "inet", RemoteIDValue: "198.51.100.7"},
			"gw-b": {Name: "gw-b", Address: "203.0.113.2", LocalAddress: "198.51.100.7", RemoteIDType: "hostname", RemoteIDValue: "gw-b.example.com"},
		}, map[string]*config.IPsecVPN{
			"a": {Gateway: "gw-a", PSK: config.NewSecret("secret-a")},
			"b": {Gateway: "gw-b", PSK: config.NewSecret("secret-b")},
		})
		assertSkipped(t, cfg, "gw-a", "gw-b")
	})

	t.Run("VPN local-address override participates in default identity collision", func(t *testing.T) {
		cfg := build(map[string]*config.IPsecGateway{
			"gw-a": {Name: "gw-a", Address: "203.0.113.1", RemoteIDType: "inet", RemoteIDValue: "198.51.100.7"},
			"gw-b": {Name: "gw-b", Address: "203.0.113.2", RemoteIDType: "hostname", RemoteIDValue: "gw-b.example.com"},
		}, map[string]*config.IPsecVPN{
			"a": {Gateway: "gw-a", PSK: config.NewSecret("secret-a")},
			"b": {Gateway: "gw-b", LocalAddr: "198.51.100.7", PSK: config.NewSecret("secret-b")},
		})
		assertSkipped(t, cfg, "gw-a", "gw-b")
	})

	t.Run("different default local address renders both", func(t *testing.T) {
		cfg := build(map[string]*config.IPsecGateway{
			"gw-a": {Name: "gw-a", Address: "203.0.113.1", RemoteIDType: "inet", RemoteIDValue: "198.51.100.7"},
			"gw-b": {Name: "gw-b", Address: "203.0.113.2", LocalAddress: "198.51.100.8", RemoteIDType: "hostname", RemoteIDValue: "gw-b.example.com"},
		}, map[string]*config.IPsecVPN{
			"a": {Gateway: "gw-a", PSK: config.NewSecret("secret-a")},
			"b": {Gateway: "gw-b", PSK: config.NewSecret("secret-b")},
		})
		text, rendered, err := manager.renderConfig(cfg)
		if err != nil || !rendered["gw-a"] || !rendered["gw-b"] {
			t.Fatalf("different local address must preserve both connections: rendered=%v err=%v\n%s", rendered, err, text)
		}
	})

	t.Run("RFC822 and FQDN remain distinct in rendered owners", func(t *testing.T) {
		cfg := build(map[string]*config.IPsecGateway{
			"gw-a": {Name: "gw-a", Address: "203.0.113.1", RemoteIDType: "email", RemoteIDValue: "peer@corp.example"},
			"gw-b": {Name: "gw-b", Address: "203.0.113.2", RemoteIDType: "hostname", RemoteIDValue: "peer@corp.example"},
		}, map[string]*config.IPsecVPN{
			"a": {Gateway: "gw-a", PSK: config.NewSecret("secret-a")},
			"b": {Gateway: "gw-b", PSK: config.NewSecret("secret-b")},
		})
		text, rendered, err := manager.renderConfig(cfg)
		if err != nil || !rendered["gw-a"] || !rendered["gw-b"] {
			t.Fatalf("RFC822 and FQDN are distinct identity namespaces: rendered=%v err=%v\n%s", rendered, err, text)
		}
	})

	t.Run("cross-type rendered-identical owners skip both secrets", func(t *testing.T) {
		pairs := []struct{ name, aType, a, bType, b string }{
			{"inet and inet6 same value", "inet", "198.51.100.7", "inet6", "198.51.100.7"},
			{"inet and email same user-at-host", "inet", "peer@corp.example", "email", "peer@corp.example"},
			{"inet and DN same string", "inet", "CN=peer", "distinguished-name", "CN=peer"},
			{"email and DN same string", "email", "CN=peer", "distinguished-name", "CN=peer"},
			{"inet and email same IP string", "inet", "198.51.100.7", "email", "198.51.100.7"},
			{"hostname adorned equals inet literal @fqdn", "hostname", "peer.example", "inet", "@peer.example"},
			{"key-id rendered equals inet literal @#zz", "key-id", "zz", "inet", "@#zz"},
			{"hostname starting hash equals key-id rendered", "hostname", "#zz", "key-id", "zz"},
			{"hostname containing DN syntax falls back to matching key-id bytes", "hostname", "CN=peer", "key-id", "40434e3d70656572"},
			{"explicit FQDN prefix matches untyped FQDN", "inet", "fqdn:peer.example", "inet", "peer.example"},
			{"explicit keyid prefix decodes chunk bytes", "inet", "keyid:#7a7a", "key-id", "7a7a"},
			{"invalid IPv6-like value falls back to literal KEY_ID", "inet", "7a:7a", "key-id", "37613a3761"},
			{"numeric FQDN prefix matches untyped FQDN", "inet", "{2}:peer.example", "inet", "peer.example"},
		}
		for _, pair := range pairs {
			pair := pair
			t.Run(pair.name, func(t *testing.T) {
				cfg := build(map[string]*config.IPsecGateway{
					"gw-a": {Name: "gw-a", Address: "203.0.113.1", RemoteIDType: pair.aType, RemoteIDValue: pair.a},
					"gw-b": {Name: "gw-b", Address: "203.0.113.2", RemoteIDType: pair.bType, RemoteIDValue: pair.b},
					"gw-c": {Name: "gw-c", Address: "203.0.113.3"},
				}, map[string]*config.IPsecVPN{
					"a": {Gateway: "gw-a", PSK: config.NewSecret("secret-a")},
					"b": {Gateway: "gw-b", PSK: config.NewSecret("secret-b")},
					"c": {Gateway: "gw-c", PSK: config.NewSecret("secret-c")},
				})
				text, rendered := assertSkipped(t, cfg, "gw-a", "gw-b")
				if !rendered["gw-c"] {
					t.Fatalf("unrelated VPN must render alongside rendered-form skips:\n%s", text)
				}
			})
		}
	})

	t.Run("cross-type distinct rendered owners render both", func(t *testing.T) {
		pairs := []struct{ name, aType, a, bType, b string }{
			{"email and hostname render differently", "email", "peer@corp.example", "hostname", "peer@corp.example"},
			{"hostname and key-id render differently", "hostname", "zz", "key-id", "zz"},
		}
		for _, pair := range pairs {
			pair := pair
			t.Run(pair.name, func(t *testing.T) {
				cfg := build(map[string]*config.IPsecGateway{
					"gw-a": {Name: "gw-a", Address: "203.0.113.1", RemoteIDType: pair.aType, RemoteIDValue: pair.a},
					"gw-b": {Name: "gw-b", Address: "203.0.113.2", RemoteIDType: pair.bType, RemoteIDValue: pair.b},
				}, map[string]*config.IPsecVPN{
					"a": {Gateway: "gw-a", PSK: config.NewSecret("secret-a")},
					"b": {Gateway: "gw-b", PSK: config.NewSecret("secret-b")},
				})
				text, rendered, err := manager.renderConfig(cfg)
				if err != nil || !rendered["gw-a"] || !rendered["gw-b"] {
					t.Fatalf("distinct rendered owners must both render: rendered=%v err=%v\n%s", rendered, err, text)
				}
			})
		}
	})

	t.Run("DN and FQDN remain distinct in rendered owners", func(t *testing.T) {
		cfg := build(map[string]*config.IPsecGateway{
			"gw-a": {Name: "gw-a", Address: "203.0.113.1", RemoteIDType: "distinguished-name", RemoteIDValue: "CN=peer.example.com"},
			"gw-b": {Name: "gw-b", Address: "203.0.113.2", RemoteIDType: "hostname", RemoteIDValue: "peer.example.com"},
		}, map[string]*config.IPsecVPN{
			"a": {Gateway: "gw-a", PSK: config.NewSecret("secret-a")},
			"b": {Gateway: "gw-b", PSK: config.NewSecret("secret-b")},
		})
		text, rendered, err := manager.renderConfig(cfg)
		if err != nil || !rendered["gw-a"] || !rendered["gw-b"] {
			t.Fatalf("DN and FQDN are distinct identity namespaces: rendered=%v err=%v\n%s", rendered, err, text)
		}
	})

}
