package config

import (
	"strings"
	"testing"
)

// #9899 F102 local tree builder. Independent of every other _test.go helper
// (no shared dependency between concurrent slices): ParseSetCommand + SetPath
// is the production flat-set path.
func buildTree9899(t *testing.T, lines []string) *ConfigTree {
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

// #9899 F102: every config-side numeric protocol reader takes canonical raw
// ASCII decimal 0..255 only. Signed ("+6"/"-1"), whitespace-padded (" 6"),
// overflow and malformed tokens must reject; "0"/"6"/"255" and named
// case/trim/aliases are preserved. Absolute verdicts (not mirror equality) so
// the pre-fix Atoi readers go RED.
func TestProtocolCanonicalNumeric9899(t *testing.T) {
	t.Run("validateProtocol", func(t *testing.T) {
		for _, tok := range []string{"0", "6", "255", "47", "006", "tcp", "TCP", "junos-ping", "junos-foobar"} {
			if err := validateProtocol(tok); err != nil {
				t.Errorf("validateProtocol(%q) = %v, want nil", tok, err)
			}
		}
		for _, tok := range []string{"+6", "+0", "-1", "256", "99999999999999999999999", "0x6", "bogus", " 6"} {
			if err := validateProtocol(tok); err == nil {
				t.Errorf("validateProtocol(%q) = nil, want error (non-canonical/unrepresentable)", tok)
			}
		}
	})

	t.Run("filterProtocolResolvable", func(t *testing.T) {
		for _, tok := range []string{"0", "6", "255", "47", "006", "tcp", "TCP", " tcp ", "junos-ping", "JUNOS-TCP-ANY", "ipv6", "IPV6"} {
			if !filterProtocolResolvable(tok) {
				t.Errorf("filterProtocolResolvable(%q) = false, want true", tok)
			}
		}
		for _, tok := range []string{"+6", "+0", "-1", " 6", "6 ", " 6 ", "\t6", "256", "99999999999999999999999", "0x6", "bogus", "", "junos-foobar"} {
			if filterProtocolResolvable(tok) {
				t.Errorf("filterProtocolResolvable(%q) = true, want false", tok)
			}
		}
	})

	t.Run("protocolIsPortBearing", func(t *testing.T) {
		for _, tok := range []string{"6", "17", "006", "017", "tcp", "TCP", " udp ", "junos-tcp-any", "junos-udp-any"} {
			if !protocolIsPortBearing(tok) {
				t.Errorf("protocolIsPortBearing(%q) = false, want true", tok)
			}
		}
		for _, tok := range []string{"+6", "+17", " 6", "6 ", " 17", "0", "1", "47", "132", "icmp", "sctp", "256", "-1", "bogus", ""} {
			if protocolIsPortBearing(tok) {
				t.Errorf("protocolIsPortBearing(%q) = true, want false", tok)
			}
		}
	})

	t.Run("protocolIsTCP", func(t *testing.T) {
		for _, tok := range []string{"6", "006", "tcp", "TCP", " tcp ", "junos-tcp-any"} {
			if !protocolIsTCP(tok) {
				t.Errorf("protocolIsTCP(%q) = false, want true", tok)
			}
		}
		for _, tok := range []string{"+6", " 6", "6 ", "17", "udp", "1", "47", "256", "-1", "bogus", ""} {
			if protocolIsTCP(tok) {
				t.Errorf("protocolIsTCP(%q) = true, want false", tok)
			}
		}
	})

	t.Run("protocolIsICMPFamily", func(t *testing.T) {
		for _, tok := range []string{"1", "58", "001", "058", "icmp", "ICMP", " icmp ", "icmpv6", "icmp6", "ICMP6", "junos-ping", "junos-pingv6"} {
			if !protocolIsICMPFamily(tok) {
				t.Errorf("protocolIsICMPFamily(%q) = false, want true", tok)
			}
		}
		for _, tok := range []string{"+1", "+58", " 1", "1 ", "58 ", "6", "tcp", "47", "256", "-1", "bogus", ""} {
			if protocolIsICMPFamily(tok) {
				t.Errorf("protocolIsICMPFamily(%q) = true, want false", tok)
			}
		}
	})

	t.Run("dnatProtocolResolvable", func(t *testing.T) {
		// Empty wildcard preserved; junos-* and "ipv6" exclusions preserved.
		for _, tok := range []string{"", "0", "6", "255", "47", "006", "tcp", "TCP", " udp "} {
			if !dnatProtocolResolvable(tok) {
				t.Errorf("dnatProtocolResolvable(%q) = false, want true", tok)
			}
		}
		for _, tok := range []string{"+6", " 6", "6 ", "-1", "256", "99999999999999999999999", "bogus", "0x6", "junos-tcp-any", "junos-ping", "ipv6", "IPV6"} {
			if dnatProtocolResolvable(tok) {
				t.Errorf("dnatProtocolResolvable(%q) = true, want false", tok)
			}
		}
	})
}

// #9899 F102: junos-host application reduction uses the same canonical numeric
// discipline on its raw app.Protocol token. Named case/trim preserved; the
// numeric arm must reject sign/whitespace/overflow while "0"/"6"/"255" still
// reduce.
func TestProtocolCanonicalHostAppNumeric9899(t *testing.T) {
	t.Run("appProtoNumber", func(t *testing.T) {
		for _, tc := range []struct {
			tok  string
			want uint8
		}{
			{"tcp", HostInboundProtoTCP}, {"TCP", HostInboundProtoTCP}, {" tcp ", HostInboundProtoTCP},
			{"udp", HostInboundProtoUDP}, {"icmp", HostInboundProtoICMP}, {"icmp6", HostInboundProtoICMPv6}, {"icmpv6", HostInboundProtoICMPv6},
			{"6", 6}, {"17", 17}, {"1", 1}, {"58", 58}, {"47", 47}, {"0", 0}, {"255", 255}, {"006", 6},
		} {
			got, ok := appProtoNumber(tc.tok)
			if !ok || got != tc.want {
				t.Errorf("appProtoNumber(%q) = (%d, %v), want (%d, true)", tc.tok, got, ok, tc.want)
			}
		}
		for _, tok := range []string{"+6", "-1", " 6", "6 ", " 6 ", "\t6", "256", "99999999999999999999999", "0x6", "bogus", "", " "} {
			if n, ok := appProtoNumber(tok); ok {
				t.Errorf("appProtoNumber(%q) = (%d, true), want ok=false", tok, n)
			}
		}
	})

	t.Run("junosHostReduceApp", func(t *testing.T) {
		reduce := func(proto string) (uint8, bool) {
			cfg := &Config{}
			// Concrete non-exempt destination port: a port-less TCP/UDP
			// fragment claims all ports, colliding with the IPsec/ident
			// exempt-tuple guard (tcp 113, udp 500/4500) and failing for
			// reasons unrelated to the protocol token. Port 80 is
			// non-exempt for both TCP and UDP and is ignored for
			// non-TCP/UDP protocols, so the verdict isolates the token.
			cfg.Applications.Applications = map[string]*Application{"a": {Name: "a", Protocol: proto, DestinationPort: "80"}}
			frags, ok := junosHostReduceApp(cfg, "a")
			if !ok || len(frags) != 1 {
				return 0, ok && len(frags) == 1
			}
			return frags[0].Proto, true
		}
		for _, tc := range []struct {
			proto string
			want  uint8
		}{
			{"tcp", HostInboundProtoTCP}, {"TCP", HostInboundProtoTCP}, {" tcp ", HostInboundProtoTCP},
			{"udp", HostInboundProtoUDP}, {"icmp", HostInboundProtoICMP}, {"icmpv6", HostInboundProtoICMPv6},
			{"6", 6}, {"17", 17}, {"47", 47}, {"0", 0}, {"255", 255}, {"006", 6},
		} {
			got, ok := reduce(tc.proto)
			if !ok || got != tc.want {
				t.Errorf("junosHostReduceApp(%q) = (%d, %v), want (%d, true)", tc.proto, got, ok, tc.want)
			}
		}
		for _, proto := range []string{"+6", "+0", "-1", " 6", "6 ", " 6 ", "256", "99999999999999999999999", "0x6", "bogus", "", " "} {
			if n, ok := reduce(proto); ok {
				t.Errorf("junosHostReduceApp(%q) = (%d, true), want ok=false", proto, n)
			}
		}
	})
}

// #9899 F102: a policy-referenced DIRECT application with a non-canonical
// numeric protocol must refuse strict commit; canonical numerics and names
// still commit. "+6" is the RED token on base (filterProtocolResolvable
// accepts it via Atoi); the parser cannot carry whitespace-padded tokens, so
// those are pinned at the helper boundary above.
func TestProtocolCanonicalDirectAppCompile9899(t *testing.T) {
	direct := func(proto string) []string {
		return []string{
			"set applications application BAD protocol " + proto,
			"set security zones security-zone trust",
			"set security zones security-zone untrust",
			"set security policies from-zone trust to-zone untrust policy p match source-address any",
			"set security policies from-zone trust to-zone untrust policy p match destination-address any",
			"set security policies from-zone trust to-zone untrust policy p match application BAD",
			"set security policies from-zone trust to-zone untrust policy p then deny",
		}
	}
	for _, proto := range []string{"0", "6", "255", "47", "tcp", "TCP", "junos-ping"} {
		if _, err := CompileConfig(buildTree9899(t, direct(proto))); err != nil {
			t.Errorf("direct app protocol %q must commit, got: %v", proto, err)
		}
	}
	for _, proto := range []string{"+6", "+0", "-1", "256", "bogus"} {
		tree := buildTree9899(t, direct(proto))
		_, err := CompileConfig(tree)
		if err == nil {
			t.Errorf("direct app protocol %q must be REJECTED at strict commit (non-canonical/unrepresentable)", proto)
			continue
		}
		if !strings.Contains(err.Error(), "BAD") || !strings.Contains(err.Error(), proto) {
			t.Errorf("direct app protocol %q error %q must name application BAD and the token", proto, err.Error())
		}
	}
}

// #9899 F102: same strict refusal through the inline-TERM application path
// ("term t1 protocol <tok>"), which normalizes then resolves through the same
// filterProtocolResolvable gate.
func TestProtocolCanonicalTermAppCompile9899(t *testing.T) {
	term := func(proto string) []string {
		return []string{
			"set applications application BAD term t1 protocol " + proto,
			"set security zones security-zone trust",
			"set security zones security-zone untrust",
			"set security policies from-zone trust to-zone untrust policy p match source-address any",
			"set security policies from-zone trust to-zone untrust policy p match destination-address any",
			"set security policies from-zone trust to-zone untrust policy p match application BAD",
			"set security policies from-zone trust to-zone untrust policy p then deny",
		}
	}
	for _, proto := range []string{"0", "6", "255", "tcp", "junos-ping"} {
		if _, err := CompileConfig(buildTree9899(t, term(proto))); err != nil {
			t.Errorf("term app protocol %q must commit, got: %v", proto, err)
		}
	}
	for _, proto := range []string{"+6", "-1", "256", "bogus"} {
		tree := buildTree9899(t, term(proto))
		if _, err := CompileConfig(tree); err == nil {
			t.Errorf("term app protocol %q must be REJECTED at strict commit (non-canonical/unrepresentable)", proto)
		}
	}
}

// #9899 F102: firewall-filter `from protocol` strict refusal for non-canonical
// numerics; canonical numerics/names still commit.
func TestProtocolCanonicalFilterCompile9899(t *testing.T) {
	filter := func(proto string) []string {
		return []string{
			"set firewall family inet filter f1 term t1 from protocol " + proto,
			"set firewall family inet filter f1 term t1 then accept",
		}
	}
	for _, proto := range []string{"0", "6", "255", "47", "tcp", "TCP", "junos-ping", "ipv6"} {
		if _, err := CompileConfig(buildTree9899(t, filter(proto))); err != nil {
			t.Errorf("filter protocol %q must commit, got: %v", proto, err)
		}
	}
	for _, proto := range []string{"+6", "+0", "-1", "256", "bogus", "junos-foobar"} {
		tree := buildTree9899(t, filter(proto))
		if _, err := CompileConfig(tree); err == nil {
			t.Errorf("filter protocol %q must be REJECTED at strict commit (non-canonical/unrepresentable)", proto)
		}
	}
}

// #9899 F102: DNAT `match protocol` strict refusal for non-canonical numerics.
// Preserves the deliberate tighter set: junos-* and "ipv6" stay rejected,
// canonical numerics/names commit.
func TestProtocolCanonicalDNATCompile9899(t *testing.T) {
	dnat := func(proto string) []string {
		return []string{
			"set security zones security-zone untrust",
			"set security nat destination pool dp address 10.0.0.5",
			"set security nat destination rule-set rs1 from zone untrust",
			"set security nat destination rule-set rs1 rule r1 match destination-address 203.0.113.10",
			"set security nat destination rule-set rs1 rule r1 match protocol " + proto,
			"set security nat destination rule-set rs1 rule r1 then destination-nat pool dp",
		}
	}
	for _, proto := range []string{"0", "6", "47", "255", "tcp", "TCP"} {
		if _, err := CompileConfig(buildTree9899(t, dnat(proto))); err != nil {
			t.Errorf("DNAT match protocol %q must commit, got: %v", proto, err)
		}
	}
	for _, proto := range []string{"+6", "-1", "256", "bogus", "junos-tcp-any", "ipv6"} {
		tree := buildTree9899(t, dnat(proto))
		if _, err := CompileConfig(tree); err == nil {
			t.Errorf("DNAT match protocol %q must be REJECTED at strict commit", proto)
		}
	}
}
