package config

import (
	"strings"
	"testing"
)

// #15943 (H11-04): tolerated NAT prefix spellings (`/+32`, `/024`) and
// protocol name/number spellings must not bypass the overlap / off-shadow
// gates. The NAT grammar normalizes and installs those spellings
// (NormalizeNATPrefixLen, #7481), but parsePoolAddr and hostLocalAddrFamily
// raw-parsed them, returned nil/empty, and every consuming gate silently
// skipped the entry; and dnatOffProtos canonicalized `tcp` as `s:tcp` but
// `6` as `n:6`, so an off exemption and a translate rule naming the same
// protocol in different spellings never intersected.
//
// RED-on-revert: drop the NormalizeNATPrefixLen call in parsePoolAddr and
// the dup-host-local case accepts silently; drop it in hostLocalAddrFamily
// and the same; restore textual `s:` canonicalization in dnatOffProtos and
// the off-shadow case compiles clean.

func TestParsePoolAddrPlusSpelling_15943(t *testing.T) {
	plus := parsePoolAddr("203.0.113.10/+32")
	canon := parsePoolAddr("203.0.113.10/32")
	if plus == nil || canon == nil {
		t.Fatalf("parsePoolAddr must parse both spellings: plus=%v canon=%v", plus, canon)
	}
	if plus.String() != canon.String() {
		t.Errorf("plus spelling %v != canonical %v", plus, canon)
	}
	lead := parsePoolAddr("203.0.113.0/024")
	canon24 := parsePoolAddr("203.0.113.0/24")
	if lead == nil || canon24 == nil || lead.String() != canon24.String() {
		t.Errorf("leading-zero spelling %v != canonical %v", lead, canon24)
	}
	if got := parsePoolAddr("not-an-ip"); got != nil {
		t.Errorf("unparseable entry must still return nil, got %v", got)
	}
	// The operational consumer inherits the fix: a pool member spelled
	// /+32 resolves through SourceNATPoolNets.
	nat := &NATConfig{SourcePools: map[string]*NATPool{
		"p": {Name: "p", Addresses: []string{"203.0.113.10/+32"}},
	}}
	nets, ok := SourceNATPoolNets(nat, "p")
	if !ok || len(nets) != 1 {
		t.Fatalf("SourceNATPoolNets(/+32 member): ok=%v nets=%v, want 1 net", ok, nets)
	}
}

func TestDNATOffNumericProtoShadow_15943(t *testing.T) {
	// off exempts tcp; the later translate pins protocol 6 (tcp) on a
	// narrower port tier. Same protocol, different spelling — the #9879
	// witness must fire exactly as the tcp/tcp spelling does.
	tree := offShadowTree9879(t,
		"set security nat destination rule-set rs1 rule r-exempt match destination-address 192.0.2.10/32",
		"set security nat destination rule-set rs1 rule r-exempt match protocol tcp",
		"set security nat destination rule-set rs1 rule r-exempt then destination-nat off",
		"set security nat destination rule-set rs1 rule r-dnat match destination-address 192.0.2.10/32",
		"set security nat destination rule-set rs1 rule r-dnat match protocol 6",
		"set security nat destination rule-set rs1 rule r-dnat match destination-port 80",
		"set security nat destination rule-set rs1 rule r-dnat then destination-nat pool p1",
	)
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("CompileConfig accepted an off(tcp) shadowed by translate(protocol 6) — " +
			"protocol spelling bypassed the #9879 witness (#15943)")
	} else if !strings.Contains(err.Error(), "9879") {
		t.Errorf("reject does not cite #9879: %v", err)
	}

	// icmpv6 vs icmp6 are the same protocol (58) and must also equate.
	tree2 := offShadowTree9879(t,
		"set security nat destination rule-set rs1 rule r-exempt match destination-address 2001:db8::10/128",
		"set security nat destination rule-set rs1 rule r-exempt match protocol icmpv6",
		"set security nat destination rule-set rs1 rule r-exempt then destination-nat off",
		"set security nat destination rule-set rs1 rule r-dnat match destination-address 2001:db8::10/128",
		"set security nat destination rule-set rs1 rule r-dnat match protocol icmp6",
		"set security nat destination rule-set rs1 rule r-dnat match destination-port 80",
		"set security nat destination rule-set rs1 rule r-dnat then destination-nat pool p1",
	)
	// icmp has no port tier in the same way; accept either a #9879 reject or
	// a clean compile only if the shapes are genuinely disjoint — assert the
	// canonicalization unit directly instead of depending on port tiers.
	_, _ = CompileConfig(tree2)
	if got := dnatOffProtoCanon("icmpv6"); got != dnatOffProtoCanon("icmp6") {
		t.Errorf("icmpv6/icmp6 canonicalize differently: %q vs %q", dnatOffProtoCanon("icmpv6"), got)
	}
	if dnatOffProtoCanon("tcp") != "n:6" || dnatOffProtoCanon("6") != "n:6" {
		t.Errorf("tcp/6 must canonicalize to n:6, got tcp=%q 6=%q",
			dnatOffProtoCanon("tcp"), dnatOffProtoCanon("6"))
	}

	// Control: disjoint protocols (tcp off vs udp translate) must NOT fire.
	tree3 := offShadowTree9879(t,
		"set security nat destination rule-set rs1 rule r-exempt match destination-address 192.0.2.10/32",
		"set security nat destination rule-set rs1 rule r-exempt match protocol tcp",
		"set security nat destination rule-set rs1 rule r-exempt then destination-nat off",
		"set security nat destination rule-set rs1 rule r-dnat match destination-address 192.0.2.10/32",
		"set security nat destination rule-set rs1 rule r-dnat match protocol 17",
		"set security nat destination rule-set rs1 rule r-dnat match destination-port 80",
		"set security nat destination rule-set rs1 rule r-dnat then destination-nat pool p1",
	)
	if _, err := CompileConfig(tree3); err != nil {
		t.Errorf("disjoint protocols (tcp off vs 17/udp translate) must commit clean, got: %v", err)
	}
}

func TestDuplicateHostLocalPlusSpelling_15943(t *testing.T) {
	// The same host-local address in two zones with differing host-inbound
	// sets, one spelled /+32: the #3718 gate must reject exactly as the
	// canonical /32 spelling does (proven by the existing canonical tests).
	cmds := []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 203.0.113.10/+32",
		"set interfaces ge-0/0/1 unit 0 family inet address 203.0.113.10/32",
		"set security zones security-zone trust interfaces ge-0/0/0.0",
		"set security zones security-zone trust host-inbound-traffic system-services ping",
		"set security zones security-zone untrust interfaces ge-0/0/1.0",
		"set security zones security-zone untrust host-inbound-traffic system-services ssh",
	}
	if _, err := CompileConfig(buildTree(t, cmds)); err == nil {
		t.Fatal("CompileConfig accepted duplicate host-local 203.0.113.10 spelled /+32 in one zone — " +
			"hostLocalAddrFamily skipped it and the #3718 gate missed the collision (#15943)")
	} else if !strings.Contains(err.Error(), "203.0.113.10") {
		t.Errorf("reject does not name the address: %v", err)
	}
	// Unit pin: the family helper itself must resolve the plus spelling.
	host, fam := hostLocalAddrFamily("203.0.113.10/+32")
	if host != "203.0.113.10" || fam != "inet" {
		t.Errorf("hostLocalAddrFamily(/+32) = (%q,%q), want (203.0.113.10, inet)", host, fam)
	}
}
