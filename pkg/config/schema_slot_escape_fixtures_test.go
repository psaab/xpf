package config

// schema_slot_escape_fixtures_test.go — the hand-authored half of the slot-1
// validation-escape gate (see schema_slot_escape_gate_test.go for the property
// and the calibration).
//
// A row exists for exactly one reason: its site does NOT commit clean under the
// synthetic parent path the automatic sweep builds, so the sweep can produce no
// control and therefore no verdict. Each row supplies a real prerequisite
// config instead. `site` must be the setSchema site key the row covers —
// TestSlotEscapeCoverage matches on it, and a row whose site no longer exists
// is a hard failure rather than a silently inert fixture.

import "strings"

// ---------------------------------------------------------------------------
// Shared prerequisite configs.
// ---------------------------------------------------------------------------

const (
	slotEscWGKeyA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	slotEscWGKeyB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	slotEscWGKeyC = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
)

var slotEscIfaces = []string{
	"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
	"set interfaces ge-0/0/1 unit 0 family inet address 10.0.2.1/24",
}

var slotEscZones = append(append([]string{}, slotEscIfaces...),
	"set security zones security-zone trust interfaces ge-0/0/0.0",
	"set security zones security-zone untrust interfaces ge-0/0/1.0",
)

var slotEscAddrBook = append(append([]string{}, slotEscZones...),
	"set security address-book global address a1 10.5.0.0/24",
)

var slotEscApp = []string{
	"set applications application app1 protocol tcp",
	"set applications application app1 destination-port 80",
}

// A zone-pair policy is only valid with all three match criteria present, so
// each policy row supplies the OTHER two and varies only the leaf under test.
func slotEscPolicyBase(omit string) []string {
	out := append([]string{}, slotEscAddrBook...)
	out = append(out, slotEscApp...)
	const p = "set security policies from-zone trust to-zone untrust policy p1 "
	for _, c := range []string{"match source-address any", "match destination-address any", "match application any"} {
		if omit != "" && strings.HasPrefix(c, omit) {
			continue
		}
		out = append(out, p+c)
	}
	return append(out, p+"then permit")
}

func slotEscGlobalPolicyBase(omit string) []string {
	out := append([]string{}, slotEscAddrBook...)
	out = append(out, slotEscApp...)
	const p = "set security policies global policy g1 "
	for _, c := range []string{"match source-address any", "match destination-address any", "match application any"} {
		if omit != "" && strings.HasPrefix(c, omit) {
			continue
		}
		out = append(out, p+c)
	}
	return append(out, p+"then permit")
}

var slotEscNatSrc = append(append([]string{}, slotEscZones...),
	"set security nat source rule-set RS from zone trust",
	"set security nat source rule-set RS to zone untrust",
	"set security nat source rule-set RS rule R1 then source-nat interface",
)

var slotEscNatDst = append(append([]string{}, slotEscZones...),
	"set security nat destination rule-set RD from zone untrust",
	"set security nat destination rule-set RD rule R1 then destination-nat off",
)

var slotEscNatStatic = append(append([]string{}, slotEscZones...),
	"set security nat static rule-set RT from zone untrust",
	"set security nat static rule-set RT rule R1 then static-nat prefix 10.0.9.5/32",
)

var slotEscPolicyOptions = []string{
	"set policy-options policy-statement PS term t1 then accept",
	"set policy-options community C1 members 65000:1",
}

var slotEscBGP = append(append([]string{}, slotEscPolicyOptions...),
	"set routing-options autonomous-system 65000",
	"set protocols bgp group G type external",
	"set protocols bgp group G peer-as 65001",
	"set protocols bgp group G neighbor 10.0.2.2",
)

var slotEscIPsec = []string{
	"set security ipsec proposal esp-a protocol esp",
	"set security ipsec proposal esp-a encryption-algorithm aes-256-cbc",
	"set security ipsec proposal esp-a authentication-algorithm hmac-sha-256-128",
	"set security ipsec policy pol1 perfect-forward-secrecy keys group14",
}

var slotEscWG = []string{
	"set system dataplane-type userspace",
	"set interfaces wg0 tunnel mode wireguard",
	"set interfaces wg0 tunnel wireguard listen-port 51820",
	"set interfaces wg0 tunnel wireguard private-key " + slotEscWGKeyA,
}

var slotEscCoS = []string{
	"set class-of-service forwarding-classes queue 0 best-effort",
	"set class-of-service forwarding-classes queue 1 expedited-forwarding",
}

var slotEscFilter4 = []string{"set firewall family inet filter F term t1 then accept"}
var slotEscFilter6 = []string{"set firewall family inet6 filter F6 term t1 then accept"}

var slotEscRibGroup = []string{
	"set routing-instances blue instance-type virtual-router",
	"set routing-instances blue interface ge-0/0/1.0",
	"set interfaces ge-0/0/1 unit 0 family inet address 10.0.2.1/24",
}

// ---------------------------------------------------------------------------
// Sites whose leaf has NO check to escape.
//
// A row here is NOT a statement that the leaf is correct — only that this gate
// has nothing to compare, because the probe value it offers is accepted in slot
// 0 as readily as in slot 1. TestSlotEscapeTable fails if such a site LATER
// starts rejecting the probe value, which is the direction that matters: the
// day someone adds the missing check, the row must gain a real verdict rather
// than stay skipped.
//
// Every entry below was measured, not assumed.
// ---------------------------------------------------------------------------
// #7145 CLOSED the four NAT match-address rows this map used to carry:
//
//	security nat source      rule-set <*> rule <*> match source-address
//	security nat source      rule-set <*> rule <*> match destination-address
//	security nat destination rule-set <*> rule <*> match source-address
//	security nat static      rule-set <*> rule <*> match source-address
//
// They were recorded here because a malformed CIDR (999.1.1.1/24) committed
// clean in slot 0, while the destination-NAT and static-NAT `match
// destination-address` siblings rejected the identical value — the asymmetry
// this scout's inventory surfaced. validateNATMatchAddressLiteralsStrict now
// gates all four, so their rows carry a REAL verdict and run the full slot-1
// escape comparison instead of skipping. Removed rather than annotated: an
// entry here means "this gate has nothing to compare", which is no longer true.
var slotEscapeUngated = map[string]string{
	"snmp trap-group <*> categories": "" +
		"trap categories are an open token set at commit; no domain check exists to escape",
}

// slotEscapeHistorical pins the instances that motivated this gate. They are
// listed separately from the coverage rows because their value is different: a
// coverage row exists so a SITE carries a verdict, whereas these exist so a
// specific historical defect can never come back unnoticed. Each was measured
// ESCAPED at 22e17c2de and rejected at the commit that introduced this file.
func slotEscapeHistoricalRows() []slotEscapeRow {
	return []slotEscapeRow{
		{"#6687 bridge-domain vlan-id-list", "bridge-domains <*> vlan-id-list",
			[]string{"set bridge-domains bd1 domain-type bridge"},
			"set bridge-domains bd1 vlan-id-list", "10", "99999"},
		// site is empty: `port range <lo> to <hi>` is an args>1 leaf, which the
		// shared enumerator excludes by construction (a two-element list is not
		// meaningful for a compound leaf), so there is no site key to bind to.
		// The row is a regression pin, not a coverage row.
		{"#6688 source-NAT pool port range", "",
			append(append([]string{}, slotEscZones...),
				"set security nat source pool P1 address 10.9.0.1/32",
				"set security nat source rule-set RS from zone trust",
				"set security nat source rule-set RS to zone untrust",
				"set security nat source rule-set RS rule R1 then source-nat pool P1"),
			"set security nat source pool P1 port range", "1024", "99999"},
		{"#6692 archival archive-sites", "system archival configuration archive-sites",
			[]string{"set system archival configuration transfer-interval 60"},
			"set system archival configuration archive-sites", `"scp://a/cfg"`, `"-oProxyCommand=id"`},
		// setSchema models the rewrite-rule leaf as the SINGULAR `code-point`;
		// `code-points` is an alias the compiler also reads, and it is the
		// spelling the #6697 escape was authored in. The row probes the alias
		// and binds to the modeled leaf.
		{"#6697 cos rewrite-rules dscp code-points", "class-of-service rewrite-rules dscp <*> forwarding-class <*> loss-priority <*> code-point",
			slotEscCoS,
			"set class-of-service rewrite-rules dscp r1 forwarding-class best-effort loss-priority low code-points", "ef", "zzbogus"},
		{"#6697 cos rewrite-rules ieee-802.1 code-points", "class-of-service rewrite-rules ieee-802.1 <*> forwarding-class <*> loss-priority <*> code-point",
			slotEscCoS,
			"set class-of-service rewrite-rules ieee-802.1 r2 forwarding-class best-effort loss-priority low code-points", "3", "zzbogus"},
		{"#7126 rib-group import-rib", "routing-options rib-groups <*> import-rib", slotEscRibGroup,
			"set routing-options rib-groups RG import-rib", "inet.0", "zz.does-not-exist.inet.0"},
	}
}

// ---------------------------------------------------------------------------
// The rows.
// ---------------------------------------------------------------------------

func slotEscapeRows() []slotEscapeRow {
	return []slotEscapeRow{
		// -- security policies ------------------------------------------------
		{"policies from-zone then log", "security policies from-zone <*> <*> <*> policy <*> then log",
			slotEscPolicyBase(""),
			"set security policies from-zone trust to-zone untrust policy p1 then log", "session-init", "zzbogus"},
		{"policies from-zone then deny log", "security policies from-zone <*> <*> <*> policy <*> then deny log",
			append(append([]string{}, slotEscAddrBook...),
				"set security policies from-zone trust to-zone untrust policy p1 match source-address any",
				"set security policies from-zone trust to-zone untrust policy p1 match destination-address any",
				"set security policies from-zone trust to-zone untrust policy p1 match application any",
				"set security policies from-zone trust to-zone untrust policy p1 then deny"),
			"set security policies from-zone trust to-zone untrust policy p1 then deny log", "session-init", "zzbogus"},
		{"policies from-zone match source-address", "security policies from-zone <*> <*> <*> policy <*> match source-address",
			slotEscPolicyBase("match source-address"),
			"set security policies from-zone trust to-zone untrust policy p1 match source-address", "a1", "zznotdefined"},
		{"policies from-zone match destination-address", "security policies from-zone <*> <*> <*> policy <*> match destination-address",
			slotEscPolicyBase("match destination-address"),
			"set security policies from-zone trust to-zone untrust policy p1 match destination-address", "a1", "zznotdefined"},
		{"policies from-zone match application", "security policies from-zone <*> <*> <*> policy <*> match application",
			slotEscPolicyBase("match application"),
			"set security policies from-zone trust to-zone untrust policy p1 match application", "app1", "zznotdefined"},
		{"policies global then log", "security policies global policy <*> then log",
			slotEscGlobalPolicyBase(""),
			"set security policies global policy g1 then log", "session-init", "zzbogus"},
		{"policies global then deny log", "security policies global policy <*> then deny log",
			append(append([]string{}, slotEscAddrBook...),
				"set security policies global policy g1 match source-address any",
				"set security policies global policy g1 match destination-address any",
				"set security policies global policy g1 match application any",
				"set security policies global policy g1 then deny"),
			"set security policies global policy g1 then deny log", "session-init", "zzbogus"},
		{"policies global match source-address", "security policies global policy <*> match source-address",
			slotEscGlobalPolicyBase("match source-address"),
			"set security policies global policy g1 match source-address", "a1", "zznotdefined"},
		{"policies global match destination-address", "security policies global policy <*> match destination-address",
			slotEscGlobalPolicyBase("match destination-address"),
			"set security policies global policy g1 match destination-address", "a1", "zznotdefined"},
		{"policies global match application", "security policies global policy <*> match application",
			slotEscGlobalPolicyBase("match application"),
			"set security policies global policy g1 match application", "app1", "zznotdefined"},
		{"policies global match from-zone", "security policies global policy <*> match from-zone",
			slotEscGlobalPolicyBase(""),
			"set security policies global policy g1 match from-zone", "trust", "zznotazone"},
		{"policies global match to-zone", "security policies global policy <*> match to-zone",
			slotEscGlobalPolicyBase(""),
			"set security policies global policy g1 match to-zone", "untrust", "zznotazone"},

		// -- security zones ----------------------------------------------------
		{"zone iface host-inbound system-services", "security zones security-zone <*> interfaces <*> host-inbound-traffic system-services",
			slotEscZones,
			"set security zones security-zone trust interfaces ge-0/0/0.0 host-inbound-traffic system-services", "ssh", "zzbogus"},
		{"zone iface host-inbound protocols", "security zones security-zone <*> interfaces <*> host-inbound-traffic protocols",
			slotEscZones,
			"set security zones security-zone trust interfaces ge-0/0/0.0 host-inbound-traffic protocols", "ospf", "zzbogus"},

		// -- NAT source --------------------------------------------------------
		{"nat src match source-address", "security nat source rule-set <*> rule <*> match source-address",
			slotEscNatSrc,
			"set security nat source rule-set RS rule R1 match source-address", "10.5.0.0/24", "999.1.1.1/24"},
		{"nat src match destination-address", "security nat source rule-set <*> rule <*> match destination-address",
			slotEscNatSrc,
			"set security nat source rule-set RS rule R1 match destination-address", "10.6.0.0/24", "999.1.1.1/24"},
		{"nat src match source-address-name", "security nat source rule-set <*> rule <*> match source-address-name",
			append(append([]string{}, slotEscNatSrc...), "set security address-book global address a1 10.5.0.0/24"),
			"set security nat source rule-set RS rule R1 match source-address-name", "a1", "zznotdefined"},
		{"nat src match destination-address-name", "security nat source rule-set <*> rule <*> match destination-address-name",
			append(append([]string{}, slotEscNatSrc...), "set security address-book global address a1 10.5.0.0/24"),
			"set security nat source rule-set RS rule R1 match destination-address-name", "a1", "zznotdefined"},
		{"nat src match destination-port", "security nat source rule-set <*> rule <*> match destination-port",
			slotEscNatSrc,
			"set security nat source rule-set RS rule R1 match destination-port", "80", "99999"},
		{"nat src match application", "security nat source rule-set <*> rule <*> match application",
			append(append([]string{}, slotEscNatSrc...), slotEscApp...),
			"set security nat source rule-set RS rule R1 match application", "app1", "zznotdefined"},

		// -- NAT destination ----------------------------------------------------
		{"nat dst match destination-address", "security nat destination rule-set <*> rule <*> match destination-address",
			slotEscNatDst,
			"set security nat destination rule-set RD rule R1 match destination-address", "10.6.0.1/32", "999.1.1.1/24"},
		{"nat dst match source-address", "security nat destination rule-set <*> rule <*> match source-address",
			slotEscNatDst,
			"set security nat destination rule-set RD rule R1 match source-address", "10.5.0.0/24", "999.1.1.1/24"},
		{"nat dst match protocol", "security nat destination rule-set <*> rule <*> match protocol",
			slotEscNatDst,
			"set security nat destination rule-set RD rule R1 match protocol", "tcp", "zzbogus"},
		{"nat dst match destination-port", "security nat destination rule-set <*> rule <*> match destination-port",
			slotEscNatDst,
			"set security nat destination rule-set RD rule R1 match destination-port", "80", "99999"},
		{"nat dst match application", "security nat destination rule-set <*> rule <*> match application",
			append(append([]string{}, slotEscNatDst...), slotEscApp...),
			"set security nat destination rule-set RD rule R1 match application", "app1", "zznotdefined"},
		{"nat dst match source-address-name", "security nat destination rule-set <*> rule <*> match source-address-name",
			append(append([]string{}, slotEscNatDst...), "set security address-book global address a1 10.5.0.0/24"),
			"set security nat destination rule-set RD rule R1 match source-address-name", "a1", "zznotdefined"},
		{"nat dst match destination-address-name", "security nat destination rule-set <*> rule <*> match destination-address-name",
			append(append([]string{}, slotEscNatDst...), "set security address-book global address a1 10.5.0.0/24"),
			"set security nat destination rule-set RD rule R1 match destination-address-name", "a1", "zznotdefined"},

		// -- NAT static ----------------------------------------------------------
		{"nat static match destination-address", "security nat static rule-set <*> rule <*> match destination-address",
			slotEscNatStatic,
			"set security nat static rule-set RT rule R1 match destination-address", "10.6.0.1/32", "999.1.1.1/24"},
		{"nat static match source-address", "security nat static rule-set <*> rule <*> match source-address",
			slotEscNatStatic,
			"set security nat static rule-set RT rule R1 match source-address", "10.5.0.0/24", "999.1.1.1/24"},

		// -- routing policy -------------------------------------------------------
		{"policy-statement from community", "policy-options policy-statement <*> term <*> from community",
			slotEscPolicyOptions,
			"set policy-options policy-statement PS term t1 from community", "C1", "zznotdefined"},
		{"bgp import", "protocols bgp import", slotEscBGP,
			"set protocols bgp import", "PS", "zznotdefined"},
		{"bgp group neighbor import", "protocols bgp group <*> neighbor <*> import", slotEscBGP,
			"set protocols bgp group G neighbor 10.0.2.2 import", "PS", "zznotdefined"},
		{"bgp group neighbor export", "protocols bgp group <*> neighbor <*> export", slotEscBGP,
			"set protocols bgp group G neighbor 10.0.2.2 export", "PS", "zznotdefined"},
		{"forwarding-table export", "routing-options forwarding-table export", slotEscPolicyOptions,
			"set routing-options forwarding-table export", "PS", "zznotdefined"},

		// -- ipsec ------------------------------------------------------------------
		{"ipsec policy proposals", "security ipsec policy <*> proposals", slotEscIPsec,
			"set security ipsec policy pol1 proposals", "esp-a", "zznotdefined"},

		// -- wireguard ---------------------------------------------------------------
		{"wireguard allowed-ips", "interfaces <*> tunnel wireguard peer <*> allowed-ips",
			append(append([]string{}, slotEscWG...),
				"set interfaces wg0 tunnel wireguard peer "+slotEscWGKeyB+" endpoint 10.0.2.2:51820"),
			"set interfaces wg0 tunnel wireguard peer " + slotEscWGKeyB + " allowed-ips", "10.1.0.0/24", "10.1.0.0/999"},
		{"wireguard allowed-ips (unit form)", "interfaces <*> unit <*> tunnel wireguard peer <*> allowed-ips",
			append(append([]string{}, slotEscWG...),
				"set interfaces wg0 tunnel wireguard peer "+slotEscWGKeyB+" endpoint 10.0.2.2:51820",
				"set interfaces wg0 tunnel wireguard peer "+slotEscWGKeyB+" allowed-ips 10.1.0.0/24",
				"set interfaces wg0 unit 0 tunnel wireguard peer "+slotEscWGKeyC+" endpoint 10.0.3.3:51820"),
			"set interfaces wg0 unit 0 tunnel wireguard peer " + slotEscWGKeyC + " allowed-ips", "10.2.0.0/24", "10.2.0.0/999"},

		// -- CoS -----------------------------------------------------------------------
		{"cos classifiers dscp code-points", "class-of-service classifiers dscp <*> forwarding-class <*> loss-priority <*> code-points",
			slotEscCoS,
			"set class-of-service classifiers dscp c1 forwarding-class best-effort loss-priority low code-points", "ef", "zzbogus"},
		{"cos classifiers ieee-802.1 code-points", "class-of-service classifiers ieee-802.1 <*> forwarding-class <*> loss-priority <*> code-points",
			slotEscCoS,
			"set class-of-service classifiers ieee-802.1 c2 forwarding-class best-effort loss-priority low code-points", "3", "zzbogus"},
		{"cos classifiers inet-precedence code-points", "class-of-service classifiers inet-precedence <*> forwarding-class <*> loss-priority <*> code-points",
			slotEscCoS,
			"set class-of-service classifiers inet-precedence c3 forwarding-class best-effort loss-priority low code-points", "3", "zzbogus"},

		// -- firewall filters -------------------------------------------------------------
		{"filter inet from icmp-code", "firewall family inet filter <*> term <*> from icmp-code",
			append(append([]string{}, slotEscFilter4...),
				"set firewall family inet filter F term t1 from protocol icmp",
				"set firewall family inet filter F term t1 from icmp-type 3"),
			"set firewall family inet filter F term t1 from icmp-code", "1", "999"},
		{"filter inet6 from icmp-code", "firewall family inet6 filter <*> term <*> from icmp-code",
			append(append([]string{}, slotEscFilter6...),
				"set firewall family inet6 filter F6 term t1 from next-header icmp6",
				"set firewall family inet6 filter F6 term t1 from icmp-type 1"),
			"set firewall family inet6 filter F6 term t1 from icmp-code", "1", "999"},

		// -- VRRP --------------------------------------------------------------------------
		{"vrrp virtual-address inet", "interfaces <*> unit <*> family inet address <*> vrrp-group <*> virtual-address",
			[]string{"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24 vrrp-group 1 priority 100"},
			"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24 vrrp-group 1 virtual-address", "10.0.1.254/24", "999.1.1.1/24"},
		{"vrrp virtual-address inet6", "interfaces <*> unit <*> family inet6 address <*> vrrp-group <*> virtual-address",
			[]string{"set interfaces ge-0/0/0 unit 0 family inet6 address 2001:db8::1/64 vrrp-group 1 priority 100"},
			"set interfaces ge-0/0/0 unit 0 family inet6 address 2001:db8::1/64 vrrp-group 1 virtual-address", "2001:db8::254/64", "2001:db8::zzz/64"},

		// -- misc ----------------------------------------------------------------------------
		{"apply-groups", "apply-groups", []string{"set groups g1 system host-name h1"},
			"set apply-groups", "g1", "zznotdefined"},
		{"snmp trap-group categories", "snmp trap-group <*> categories",
			[]string{"set snmp trap-group tg1 targets 10.0.0.1"},
			"set snmp trap-group tg1 categories", "link", "zzbogus"},
	}
}
