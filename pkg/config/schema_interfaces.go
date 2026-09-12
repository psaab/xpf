package config

// schema_interfaces.go carries the `interfaces` subtree of the
// config-mode grammar SSOT (#1891 domain split), plus the shared
// tunnel/wireguard subtree constructors it composes. The root
// composition, the schemaNode type, and the split rationale live in
// schema.go.

// #1319 PR 3 typed leaves (interfaces subsystem). Same fields-only
// discipline as the chassis PR 2 block: no children/args/multi
// changes, ranges derived from what the runtime actually consumes
// (cited per leaf). The `address` nodes use the typed-KEY-slot
// feature (keyValidator) because their value is a named-instance
// identity token, not a leaf value. The `unit <n>` instance key is
// ALSO typed now (keyValidator ValidateLogicalUnit, #5829): a
// non-numeric / negative / overflow / out-of-range unit id made the
// compiler SILENTLY DROP the whole unit — including its firewall
// filters (a security fail-open) — so it is rejected at commit here
// plus defense-in-depth in the compiler. Deliberately still NOT typed:
// `vrrp-group <id>` instance ids (same deferral class as the chassis
// PR-2 redundancy-group/node ids: garbage ids make the compiler
// silently coerce/drop the instance, but these ids are cross-referenced
// from other subsystems and their range is backstopped by a semantic
// commit gate — see below). NOTE (#4573): the SCHEMA
// deferral above is only safe for NON-numeric garbage; an
// OUT-OF-RANGE NUMERIC `vrrp-group <id>` is bounded by a semantic
// commit gate on the compiled *Config — `validateVRRPGroupIDStrict`
// (`compiler_validate_strict_vrrp.go`), the RFC 5798 VRID-range 1..255
// analog of the chassis `validateChassisClusterStrict` (#4434) — NOT
// through this schema walker. `track-interface priority-cost`
// (already strict-rejected by the #1814 AST pre-walk in the
// compiler — typing here would shadow those curated errors), the
// dhcp/dhcpv6 client knobs and tunnel keepalives (deferred:
// low-risk pass-through integers), `speed`/`duplex`/`encapsulation`
// (free-form pass-through strings).
// The interfaces wildcard identity token is TYPED (keyValidator
// ValidateInterfaceName, #6834). The name is interpolated into four sites in
// the generated systemd units, one of which — `[Match] Name=` in the .network
// file — systemd reads as a WHITESPACE-SEPARATED LIST OF SHELL-STYLE GLOBS. An
// unvalidated name containing a space or a glob metacharacter therefore does
// not corrupt the file; it makes one .network claim SEVERAL interfaces. Gating
// the identity here closes all four render sites at once and reports the
// problem at commit rather than as a rename that silently fails at next boot.
// See validate_interface_name.go for why escaping at the render site would be
// worse than doing nothing.
var schemaInterfaces = &schemaNode{desc: "Interface configuration", wildcard: &schemaNode{desc: "Interface name", valueHint: ValueHintInterfaceName, placeholder: "<interface-name>", keyValidator: ValidateInterfaceName, children: map[string]*schemaNode{
	"description": {desc: "Text description of interface", args: 1, scalar: true, children: nil},
	// Compiled verbatim (compiler_interfaces.go:44, Atoi with the
	// error swallowed → garbage silently means "MTU not set", the
	// zero-value sentinel) and passed through to networkd MTUBytes=
	// and the dataplane interface snapshot. Min-only per the
	// no-schema-only-caps doctrine: the kernel/driver owns the real
	// ceiling and rejects loudly.
	"mtu": {
		desc:          "Maximum transmit packet size",
		args:          1,
		valueType:     ValueInteger,
		valueDesc:     "MTU in bytes (>= 1; kernel/driver enforces its own ceiling)",
		valueExamples: []string{"1500", "9000"},
		validator:     ValidateIntegerMin(1),
		children:      nil,
	},
	"speed":                 {desc: "Link speed", args: 1, children: nil},
	"duplex":                {desc: "Link duplex mode", args: 1, children: nil},
	"bandwidth":             {desc: "Interface bandwidth", args: 1, children: nil},
	"disable":               {desc: "Disable this interface", children: nil},
	"vlan-tagging":          {desc: "Enable 802.1Q VLAN tagging", children: nil},
	"flexible-vlan-tagging": {desc: "Enable flexible 802.1Q VLAN tagging (QinQ)", children: nil},
	// #4308 (fable-review-167 I-3): typed + compiled so they stop silently
	// vanishing, but ACCEPTED-ONLY today (a commit-time advisory warns each
	// is not enforced). native-vlan-id folds into the QinQ tagging pipeline
	// (#2354); the gratuitous-ARP knobs map to per-interface sysctls the
	// apply path does not yet write. See validateInterfaceParityWarnings.
	"native-vlan-id": {desc: "VLAN ID for untagged frames on a trunk (accepted-only, not yet enforced — #4308)", args: 1, placeholder: "<number>",
		valueType: ValueInteger, valueDesc: "802.1Q native VLAN ID (1..4094)",
		valueExamples: []string{"1", "100"}, validator: ValidateInteger(1, 4094), children: nil},
	"gratuitous-arp-reply":      {desc: "Reply to gratuitous ARP requests (accepted-only, not yet enforced — #4308)", children: nil},
	"no-gratuitous-arp-request": {desc: "Suppress sending gratuitous ARP requests (accepted-only, not yet enforced — #4308)", children: nil},
	"encapsulation":             {desc: "Physical link-layer encapsulation", args: 1, children: nil},
	"gigether-options": {desc: "Gigabit Ethernet interface options", children: map[string]*schemaNode{
		"redundant-parent": {desc: "Parent of this redundant interface", args: 1, children: nil},
		"802.3ad":          {desc: "Link aggregation group", args: 1, children: nil},
	}},
	"aggregated-ether-options": {desc: "Aggregated Ethernet interface options", children: map[string]*schemaNode{
		"lacp": {desc: "LACP parameters", children: map[string]*schemaNode{
			"active":   {desc: "Active LACP mode", children: nil},
			"passive":  {desc: "Passive LACP mode", children: nil},
			"periodic": {desc: "LACP timer period", args: 1, children: nil},
		}},
		"link-speed": {desc: "Member link speed", args: 1, children: nil},
		"minimum-links": {
			desc:          "Minimum active member links",
			args:          1,
			placeholder:   "<number>",
			valueType:     ValueInteger,
			valueDesc:     "Minimum active member links before the bundle goes down (>= 1)",
			valueExamples: []string{"1", "2"},
			// #6940: the leaf carried no validator, so a malformed value reached
			// compileInterfaces and `Atoi`'s discarded error made it 0. Bounded at
			// >= 1 because 0 members is not a floor an operator can mean.
			validator: ValidateIntegerMin(1),
			children:  nil,
		},
	}},
	"redundant-ether-options": {desc: "Redundant Ethernet interface options", children: map[string]*schemaNode{
		"redundancy-group": {desc: "Redundancy group for this RETH", args: 1, children: nil},
	}},
	"fabric-options": {desc: "Fabric interface options", children: map[string]*schemaNode{
		"member-interfaces": {desc: "Member interfaces", children: nil},
	}},
	"tunnel": {desc: "Tunnel parameters", packedStatements: true, children: tunnelSchemaChildren()},
	// #5829: the unit instance key is a NUMERIC identity token — type it so
	// `commit`/`commit check` reject a non-numeric / negative / overflow /
	// out-of-range `unit <n>` naming the bad value, instead of the compiler
	// silently discarding the unit (and its firewall filters) later. keyValidator
	// alone gates the identity arg (schema_walk validateKeySlot); valueHint stays
	// for dynamic unit-number completion.
	// #9620 (M6): packedStatements splits `unit 0 vlan-id 10 inner-vlan-id 20;`.
	// Without it `inner-vlan-id` stayed on the vlan-id leaf: strict refused it as
	// an unknown modifier and the lenient load dropped the inner tag.
	"unit": {desc: "Logical unit number", args: 1, valueHint: ValueHintUnitNumber, placeholder: "<unit-number>", keyValidator: ValidateLogicalUnit, packedStatements: true, children: map[string]*schemaNode{
		"description":    {desc: "Text description", args: 1, scalar: true, placeholder: "<text>", children: nil},
		"point-to-point": {desc: "Point-to-point interface", children: nil},
		// 802.1Q VID is a 12-bit wire field: 0 is the compiler's
		// "untagged" zero-value sentinel and 4095 is reserved, so
		// 1..4094 is exactly the usable range — the runtime creates
		// the sub-interface via netlink.Vlan{VlanId} (pkg/dataplane/
		// compiler_iface.go:96) and the kernel 8021q layer rejects
		// anything outside it. Compiled with the Atoi error
		// swallowed (compiler_interfaces.go:293/:302) — garbage
		// silently meant "no VLAN" before this gate.
		"vlan-id": {
			desc:          "VLAN ID",
			args:          1,
			placeholder:   "<number>",
			valueType:     ValueInteger,
			valueDesc:     "802.1Q VLAN ID (1..4094)",
			valueExamples: []string{"50", "80"},
			validator:     ValidateInteger(1, 4094),
			children:      nil,
		},
		// inner-vlan-id stays typed (range-validated) so a malformed value
		// still reports a clean error, but a well-formed inner tag is
		// HARD-REJECTED at commit by the #5879 canonical per-physical-
		// interface QinQ gate (validateQinQVLANStackAST, compiler_interfaces_
		// qinq.go — the #2354 honest-posture gate, generalized to the
		// aggregate stack across every spelling and both cluster-node views):
		// the AF_XDP dataplane does not enforce QinQ / stacked-VLAN transit,
		// so committing an inner tag would be a false promise. The modern
		// `vlan-tags outer/inner` spelling is intentionally NOT a setSchema
		// leaf (advertising an unsupported feature would mislead) — the same
		// gate rejects it. Single 802.1Q tagging via vlan-id is supported.
		//
		// input-vlan-map / output-vlan-map (per-unit VLAN push/pop/swap
		// rewrite) are likewise intentionally NOT setSchema leaves: xpf has
		// no vlan-map consumer, so the rewrite never happens. They are
		// HARD-REJECTED at commit by the #6178 honesty gate
		// (validateVLANMapAST, compiler_interfaces_vlanmap.go) rather than
		// advertised and silently dropped.
		"inner-vlan-id": {
			desc:          "Inner VLAN ID (QinQ; NOT enforced — rejected at commit, #2354)",
			args:          1,
			placeholder:   "<number>",
			valueType:     ValueInteger,
			valueDesc:     "Inner (QinQ) 802.1Q VLAN ID (1..4094) — stacked-VLAN transit not enforced (#2354)",
			valueExamples: []string{"100"},
			validator:     ValidateInteger(1, 4094),
			children:      nil,
		},
		"tunnel": {desc: "Tunnel parameters", packedStatements: true, children: tunnelSchemaChildren()},
		"family": {desc: "Protocol family", compoundKey: true, children: map[string]*schemaNode{
			"inet": {desc: "IPv4 protocol", packedStatements: true, children: map[string]*schemaNode{
				// #4308 (fable-review-167 I-3): typed + compiled so they stop
				// silently vanishing, but ACCEPTED-ONLY today (commit-time
				// advisory). unnumbered-address needs a networkd
				// borrow-address implementation; targeted-broadcast needs
				// dataplane directed-broadcast forwarding. See
				// validateInterfaceParityWarnings.
				"unnumbered-address": {desc: "Borrow another interface's address (accepted-only, not yet enforced — #4308)", args: 1, placeholder: "<interface>",
					valueHint: ValueHintInterfaceName, children: nil},
				"targeted-broadcast": {desc: "Forward directed broadcasts to the subnet (accepted-only, not yet enforced — #4308)", children: nil},
				// Compiled verbatim (compiler_interfaces.go:539); same
				// pass-through contract as the interface-level mtu.
				"mtu": {
					desc:          "Maximum transmit packet size",
					args:          1,
					placeholder:   "<size>",
					valueType:     ValueInteger,
					valueDesc:     "MTU in bytes (>= 1; kernel/driver enforces its own ceiling)",
					valueExamples: []string{"1500"},
					validator:     ValidateIntegerMin(1),
					children:      nil,
				},
				// Typed KEY slot: the address value is this container's
				// identity token. Every runtime consumer net.ParseCIDRs
				// configured addresses and SILENTLY SKIPS unparseable
				// ones (dataplane snapshot interfaces.go:391-394,
				// networkd Address= lines, RETH/VIP/RA walks), so a
				// bare IP or typo committed fine and then didn't exist.
				// Family rule mirrors the runtime ip.To4() split.
				"address": {
					desc:             "IPv4 address",
					args:             1,
					placeholder:      "<address>",
					keyValueType:     ValueCIDR,
					keyValueDesc:     "IPv4 address with prefix length (e.g. 10.0.1.10/24)",
					keyValueExamples: []string{"10.0.1.10/24"},
					keyValidator:     ValidateIPv4CIDR,
					children: map[string]*schemaNode{
						"primary":    {desc: "Primary address", children: nil},
						"preferred":  {desc: "Preferred address", children: nil},
						"vrrp-group": vrrpGroupSchemaNode(false),
					},
				},
				"dhcp": {desc: "DHCP client", children: map[string]*schemaNode{
					"lease-time": {desc: "Lease time", args: 1, placeholder: "<seconds>",
						valueType: ValueInteger, valueDesc: "DHCP lease time in seconds (>= 1; 0 means 'use the default' and cannot be requested)",
						valueExamples: []string{"3600", "86400"},
						// #6940: 0 is this leaf's DOCUMENTED sentinel for "default", so a
						// silently-zeroed malformed value was indistinguishable from an
						// unconfigured leaf. Bounded at >= 1 so the sentinel can only be
						// reached by omitting the leaf, which is what it means.
						validator: ValidateIntegerMin(1), children: nil},
					"retransmission-attempt": {desc: "Retransmission attempts", args: 1, placeholder: "<number>",
						valueType: ValueInteger, valueDesc: "DHCP retransmission attempts (>= 1)",
						valueExamples: []string{"4"}, validator: ValidateIntegerMin(1), children: nil},
					"retransmission-interval": {desc: "Retransmission interval", args: 1, placeholder: "<seconds>",
						valueType: ValueInteger, valueDesc: "Seconds between DHCP retransmissions (>= 1)",
						valueExamples: []string{"2"}, validator: ValidateIntegerMin(1), children: nil},
					"force-discover": {desc: "Force DHCP discover", children: nil},
				}},
				"sampling": {desc: "Traffic sampling", children: map[string]*schemaNode{
					"input":  {desc: "Sample input traffic", children: nil},
					"output": {desc: "Sample output traffic", children: nil},
				}},
				"filter": {desc: "Firewall filter", children: map[string]*schemaNode{
					"input":  {desc: "Input filter", args: 1, placeholder: "<filter-name>", children: nil},
					"output": {desc: "Output filter", args: 1, placeholder: "<filter-name>", children: nil},
				}},
				"dynamic-dns": interfaceDynamicDNSSchema(),
			}},
			"inet6": {desc: "IPv6 protocol", packedStatements: true, children: map[string]*schemaNode{
				// Compiled at compiler_interfaces.go:578 (the lower of
				// the per-family values wins); same pass-through
				// contract as the interface-level mtu.
				"mtu": {
					desc:          "Maximum transmit packet size",
					args:          1,
					placeholder:   "<size>",
					valueType:     ValueInteger,
					valueDesc:     "MTU in bytes (>= 1; kernel/driver enforces its own ceiling)",
					valueExamples: []string{"1500"},
					validator:     ValidateIntegerMin(1),
					children:      nil,
				},
				"dad-disable": {desc: "Disable duplicate address detection", children: nil},
				// Typed KEY slot — see the family inet address comment.
				"address": {
					desc:             "IPv6 address",
					args:             1,
					placeholder:      "<address>",
					keyValueType:     ValueCIDR,
					keyValueDesc:     "IPv6 address with prefix length (e.g. 2001:db8::1/64)",
					keyValueExamples: []string{"2001:db8::1/64"},
					keyValidator:     ValidateIPv6CIDR,
					children: map[string]*schemaNode{
						"primary":    {desc: "Primary address", children: nil},
						"preferred":  {desc: "Preferred address", children: nil},
						"vrrp-group": vrrpGroupSchemaNode(true),
					},
				},
				"sampling": {desc: "Traffic sampling", children: map[string]*schemaNode{
					"input":  {desc: "Sample input traffic", children: nil},
					"output": {desc: "Sample output traffic", children: nil},
				}},
				"filter": {desc: "Firewall filter", children: map[string]*schemaNode{
					"input":  {desc: "Input filter", args: 1, placeholder: "<filter-name>", children: nil},
					"output": {desc: "Output filter", args: 1, placeholder: "<filter-name>", children: nil},
				}},
				"dynamic-dns": interfaceDynamicDNSSchema(),
				"dhcpv6-client": {desc: "DHCPv6 client", children: map[string]*schemaNode{
					"client-type":    {desc: "Client type", args: 1, placeholder: "<type>", children: nil},
					"client-ia-type": {desc: "Client IA type", args: 1, placeholder: "<type>", children: nil},
					"prefix-delegating": {desc: "Prefix delegation", children: map[string]*schemaNode{
						// #6587: both leaves were untyped `<length>` placeholders
						// parsed with an unbounded strconv.Atoi whose error is
						// DISCARDED, so `abc` and `999` both silently became a
						// value the operator never typed.
						//
						// sub-prefix-length was incidentally fail-closed —
						// netip.PrefixFrom(addr, >128) yields an invalid Prefix
						// that daemon_ra.go's IsValid() check rejects — but the
						// operator got no commit error, just a silently absent
						// delegation. preferred-prefix-length is NOT even that:
						// net.CIDRMask(999, 128) returns nil, and the IA_PD hint
						// then EGRESSES to the upstream server with wire
						// prefix-length 0.
						//
						// 0..128 is the IPv6 prefix-length domain; 0 is retained
						// as the documented "not set" sentinel both fields
						// already use.
						"preferred-prefix-length": {
							desc:          "Preferred prefix length",
							args:          1,
							placeholder:   "<0..128>",
							valueType:     ValueInteger,
							valueDesc:     "Requested IA_PD prefix length (0..128; 0 = not set, send no length hint)",
							valueExamples: []string{"48", "56", "60"},
							validator:     ValidateInteger(0, 128),
							children:      nil,
						},
						"sub-prefix-length": {
							desc:          "Sub-prefix length",
							args:          1,
							placeholder:   "<0..128>",
							valueType:     ValueInteger,
							valueDesc:     "Length of the sub-prefix derived from the delegation for RA (0..128; 0 = advertise the delegated prefix as-is)",
							valueExamples: []string{"64"},
							validator:     ValidateInteger(0, 128),
							children:      nil,
						},
					}},
					"client-identifier": {desc: "Client identifier", children: map[string]*schemaNode{
						"duid-type": {desc: "DUID type", args: 1, placeholder: "<type>", children: nil},
					}},
					"req-option": {desc: "Request option", args: 1, placeholder: "<option>", children: nil},
					"update-router-advertisement": {desc: "Update router advertisement", children: map[string]*schemaNode{
						"interface": {desc: "Interface", args: 1, placeholder: "<interface>", children: nil},
					}},
				}},
			}},
		}},
	}},
}}}

// vrrpGroupSchemaNode returns the config-mode schema subtree for a
// `vrrp-group <id> { ... }` block under a family inet/inet6 address.
// Both families share an identical leaf set — only the virtual-address
// validator and its value description differ by family (#2384). The
// native VRRP engine already family-detects each VIP by parse
// (pkg/vrrp/instance.go ip.To4()==nil), so the inet6 path needed only a
// config surface, not a runtime change. Keeping the two trees identical
// except for the VIP validator means completion and commit validation
// behave the same across families.
func vrrpGroupSchemaNode(v6 bool) *schemaNode {
	// xpf-DIVERGENT from Junos (bare IP): the VIP string is
	// netlink.ParseAddr'd verbatim when the group masters
	// (pkg/vrrp/instance.go:1076) and that parser REQUIRES a /prefix — a
	// bare Junos-style virtual-address still gets advertised (sendAdvert
	// strips an optional prefix, instance.go:897) but the address is
	// never installed on the interface: a silent half-working group.
	// VRRPConfig documents the CIDR contract (pkg/vrrp/vrrp.go:20).
	vaDesc := "Virtual IPv4 address with prefix length (e.g. 10.0.1.1/24; xpf requires the prefix, unlike Junos)"
	vaExamples := []string{"10.0.1.1/24"}
	vaValidator := ValidateIPv4CIDR
	if v6 {
		vaDesc = "Virtual IPv6 address with prefix length (e.g. 2001:db8::1/64; xpf requires the prefix, unlike Junos)"
		vaExamples = []string{"2001:db8::1/64"}
		vaValidator = ValidateIPv6CIDR
	}
	// #8839: keyValidator on the IDENTITY slot. Without it a non-numeric id is
	// accepted at commit and the group silently vanishes -- parseVRRPGroups does
	// strconv.Atoi(name) and `continue`s on error. Range and sign are already
	// caught by an existing strict gate; this closes only the silent case.
	return &schemaNode{desc: "VRRP group", args: 1, placeholder: "<group-id>", keyValidator: ValidateVRRPGroupID, children: map[string]*schemaNode{
		"virtual-address": {
			desc:          "Virtual IP address",
			args:          1,
			multi:         true,
			placeholder:   "<address>",
			valueType:     ValueCIDR,
			valueDesc:     vaDesc,
			valueExamples: vaExamples,
			validator:     vaValidator,
			children:      nil,
		},
		// VRRP priority is one wire byte (pkg/vrrp/instance.go:918
		// uint8); 0 is the "unset → default 100" compiler sentinel and
		// also the RFC 5798 resignation value, 255 is the valid IP-owner
		// priority (instance.go:256). Junos: 1..255 — identical.
		// NOTE (#5184): this leaf validator gates only the STRUCTURED
		// spellings (flat-set / braced). The hierarchical PACKED one-liner
		// `vrrp-group 1 priority 256;` packs the priority onto the instance
		// node's Keys, which walkInstanceChildren consumes as an
		// unvalidated identity token (same residual as the vrrp-group <id>
		// slot) — it is backstopped by the semantic commit gate
		// validateVRRPGroupPriorityStrict on the compiled *Config
		// (compiler_validate_strict_vrrp_priority.go), the analog of
		// validateVRRPGroupIDStrict (#4573).
		"priority": {
			desc:          "VRRP priority",
			args:          1,
			placeholder:   "<1..255>",
			valueType:     ValueInteger,
			valueDesc:     "VRRP priority (1..255; 255 = address owner)",
			valueExamples: []string{"100", "200", "255"},
			validator:     ValidateInteger(1, 255),
			children:      nil,
		},
		// Junos `preempt { hold-time <seconds>; }`: a higher-priority
		// backup that comes back up waits hold-time seconds before
		// preempting a still-live lower-priority master, so failback is
		// deferred until dynamic routing converges (avoids a transient
		// blackhole). 0/unset hold-time = immediate preemption (today's
		// behavior). Bare `preempt` (no hold-time) is still valid.
		"preempt": {desc: "Allow preemption", children: map[string]*schemaNode{
			"hold-time": {
				desc:          "Seconds to wait before preempting a live lower-priority master",
				args:          1,
				placeholder:   "<seconds>",
				valueType:     ValueInteger,
				valueDesc:     "Preempt hold-time in seconds (1..3600; 0/unset = immediate)",
				valueExamples: []string{"30", "60", "120"},
				validator:     ValidateInteger(1, 3600),
				children:      nil,
			},
		}},
		"accept-data": {desc: "Accept packets sent to the virtual address", children: nil},
		// Seconds. xpf-DIVERGENT from Junos (1..255 s): the value is
		// converted seconds→ms (pkg/vrrp/vrrp.go:58) then ms→centiseconds
		// (instance.go:915) into the 12-bit VRRPv3 Max Advert Int field,
		// so 40 s (4000 cs) is the last whole-second value that encodes;
		// 41 s (4100 cs) overflows the 0x0FFF wire mask and aliases. 0 =
		// unset → default 1 s (vrrp.go:55).
		"advertise-interval": {
			desc:          "Advertisement interval",
			args:          1,
			placeholder:   "<seconds>",
			valueType:     ValueInteger,
			valueDesc:     "Advertisement interval in seconds (1..40; VRRPv3 12-bit centisecond wire field — Junos allows up to 255)",
			valueExamples: []string{"1", "5"},
			validator:     ValidateInteger(1, 40),
			children:      nil,
		},
		"authentication-type": {desc: "Authentication type", args: 1, placeholder: "<type>", children: nil},
		"authentication-key":  {desc: "Authentication key", args: 1, placeholder: "<key>", children: nil},
		// priority-cost stays untyped: the #1814 AST pre-walk in the
		// compiler already strict-rejects out-of-range costs with curated
		// errors (validateVRRPTrackInterfaceAST / parseTrackCost,
		// compiler_interfaces.go:791); typing it here would shadow them.
		"track-interface": {desc: "Interface to track", args: 1, placeholder: "<interface>", closedWorld: true, children: map[string]*schemaNode{
			"priority-cost": {desc: "Priority cost subtracted while the tracked interface is down", args: 1, placeholder: "<1..254>", children: nil},
		}},
		"track-priority-cost": {desc: "Priority cost when tracked interface fails", args: 1, placeholder: "<cost>", children: nil},
	}}
}

// tunnelSchemaChildren returns the config-mode schema children for the
// `tunnel { ... }` stanza, shared between the physical-interface and
// unit-level positions (the compiler parses both with the same property
// switch, compiler_interfaces.go:153 / :241). #1319 PR 3 typed leaves:
//
//   - source / destination: the runtime net.ParseIPs both families
//     (pkg/routing/tunnel.go:194-195; Gretun auto-selects gre vs ip6gre)
//     and an unparseable address silently skips tunnel creation.
//   - ttl: stored verbatim by the compiler, then truncated to the
//     netlink uint8 Ttl field (tunnel.go:218/:226/:235) — 256 would
//     silently wrap to 0. 0 = unset; the runtime substitutes its
//     default of 64 (tunnel.go:202-205), not the kernel inherit
//     behaviour (AGY r1 Low on PR #1886).
//   - key: compiled via uint32(Atoi) (compiler_interfaces.go:168/:262),
//     so negatives and values past 2^32-1 silently wrap; the GRE key
//     wire field (IKey/OKey, tunnel.go:238-239) is exactly 32 bits.
//   - keepalive: typed 0..32767 seconds (0 = disabled). An unbounded
//     value overflowed time.Duration(sec)*time.Second (int64 ns) at the
//     runtime probe/ticker multiply and could wrap non-positive →
//     time.NewTicker panic → xpfd crash (#5705). 32767 s matches the
//     de-facto GRE keepalive ceiling and is far under the int64-ns
//     overflow; the runtime also clamps (pkg/routing/tunnel.go
//     clampKeepaliveIntervalSec) as defense-in-depth.
//   - keepalive-retry: typed 1..255 (#9157). It WAS deliberately untyped, on
//     the rationale that it is "a pass-through count consumed by the keepalive
//     prober only when > 0; never a Duration multiply". That rationale is
//     accurate and it answers a DIFFERENT question: it rules out the #5705
//     OVERFLOW, and the harm here is REACHABILITY. `keepaliveTick` transitions
//     the tunnel down at `state.Failures >= state.MaxRetries`
//     (pkg/routing/tunnel_keepalive_runner.go), Failures increments once per
//     probe tick, and the runner normalizes only `<= 0 -> 3`
//     (startKeepalive) — so `keepalive-retry 99999999999` committed clean and
//     left dead-peer detection permanently unreachable: the tunnel is never
//     declared down and traffic keeps being handed to a dead peer, with the
//     configured value rendered back by `show configuration`. The `abc` row is
//     the other half: a typo'd value became the silent default 3 rather than a
//     commit error, because compiler_interfaces.go discards the strconv error.
//     1..255 is Junos's own range for this leaf; 0 is rejected rather than
//     silently meaning "the default 3".
func tunnelSchemaChildren() map[string]*schemaNode {
	return map[string]*schemaNode{
		"source": {
			desc:          "Tunnel source address",
			args:          1,
			placeholder:   "<address>",
			valueType:     ValueIPAddress,
			valueDesc:     "Tunnel source IP address (IPv4 or IPv6)",
			valueExamples: []string{"10.0.2.10", "2001:db8::1"},
			validator:     ValidateIPAddress,
			children:      nil,
		},
		"destination": {
			desc:          "Tunnel destination address",
			args:          1,
			placeholder:   "<address>",
			valueType:     ValueIPAddress,
			valueDesc:     "Tunnel destination IP address (IPv4 or IPv6)",
			valueExamples: []string{"192.0.2.1", "2001:db8::2"},
			validator:     ValidateIPAddress,
			children:      nil,
		},
		"mode": {
			desc:        "Tunnel mode",
			args:        1,
			placeholder: "<mode>",
			valueType:   ValueEnumOf,
			valueDesc:   "Tunnel encapsulation mode",
			// "ip6gre" FIRST, deliberately. The #2419 compact/block census
			// synthesises its probe values from valueExamples[0] and [1], and
			// the compact spelling of this site is compact-BLIND: the value is
			// dropped and Mode falls back to the parser's default, which is
			// "gre". An examples list starting with "gre" makes the dropped
			// value and the fallback identical, so the divergence reads as
			// EQUIVALENT and the inventory entry looks stale — a fixture that
			// uses the value the bug falls back to (#2419 stays open here).
			valueExamples: []string{"ip6gre", "gre"},
			validator:     ValidateEnum(TunnelModeNames),
			children:      nil,
		},
		"key": {
			desc:          "Tunnel key",
			args:          1,
			placeholder:   "<key>",
			valueType:     ValueInteger,
			valueDesc:     "GRE key (0..4294967295; 32-bit wire field)",
			valueExamples: []string{"100"},
			validator:     ValidateInteger(0, 4294967295),
			children:      nil,
		},
		"ttl": {
			desc:          "Time to live",
			args:          1,
			placeholder:   "<number>",
			valueType:     ValueInteger,
			valueDesc:     "Tunnel TTL (0..255; 0 = use the default 64, one wire byte)",
			valueExamples: []string{"64"},
			validator:     ValidateInteger(0, 255),
			children:      nil,
		},
		"keepalive": {
			desc:          "Keepalive interval",
			args:          1,
			placeholder:   "<seconds>",
			valueType:     ValueInteger,
			valueDesc:     "Keepalive interval in seconds (0..32767; 0 = disabled). Bounded to keep time.Duration(sec)*time.Second from overflowing int64 ns (#5705)",
			valueExamples: []string{"0", "10", "30"},
			validator:     ValidateInteger(0, 32767),
			children:      nil,
		},
		"keepalive-retry": {
			desc:        "Keepalive retry count",
			args:        1,
			placeholder: "<number>",
			valueType:   ValueInteger,
			valueDesc: "Consecutive failed keepalive probes before the tunnel is declared " +
				"down (1..255, Junos range; default 3). Bounded so `Failures >= MaxRetries` " +
				"stays REACHABLE — an unbounded count makes the dead-peer check in " +
				"pkg/routing/tunnel_keepalive_runner.go never fire (#9157)",
			valueExamples: []string{"3", "5"},
			validator:     ValidateInteger(1, 255),
			children:      nil,
		},
		// packedTail (#9172 V044): the compiler reads the packed tail
		// (packedTunnelRoutingInstance8936), so the commit gate validates it:
		// a packed `routing-instance destination;` with no name is refused
		// exactly as the braced `routing-instance { destination; }` is.
		"routing-instance": {desc: "Routing instance", packedTail: true, children: map[string]*schemaNode{
			"destination": {desc: "Destination routing instance", args: 1, placeholder: "<name>", children: nil},
		}},
		"wireguard": wireguardSchemaNode(),
	}
}

// wireguardSchemaNode returns the config-mode schema subtree for the
// `tunnel wireguard { ... }` stanza (#1432 S2a). Minimal generic
// surface — listen-port / private-key / peer{public-key, allowed-ips,
// endpoint, persistent-keepalive}. See parseTunnelWireguard in
// compiler_interfaces.go for the matching parse.
//
// #1319 PR 3: listen-port and persistent-keepalive carry exactly the
// bounds the compiler enforces SILENTLY today — parseTunnelWireguard
// accepts only 1..65535 (compiler_interfaces.go:689) and
// parseTunnelWireguardPeer only 0..65535 (:720), dropping anything else
// without a trace. The typed leaves turn that silent drop into a commit
// rejection.
func wireguardSchemaNode() *schemaNode {
	return &schemaNode{
		desc: "WireGuard tunnel parameters",
		children: map[string]*schemaNode{
			"listen-port": {
				desc:          "UDP listen port",
				args:          1,
				placeholder:   "<port>",
				valueType:     ValueInteger,
				valueDesc:     "UDP listen port (1..65535)",
				valueExamples: []string{"51820"},
				validator:     ValidateInteger(1, 65535),
				children:      nil,
			},
			"private-key": {desc: "Local static private key (hex)", args: 1, placeholder: "<hex-key>", children: nil},
			// peer is a NAMED-INSTANCE container keyed by the peer's
			// public key (#1434 multi-peer): `peer <public-key> { ... }`.
			// Modeled on vrrp-group (args:1 with a child block). A WG
			// tunnel may carry N peers; the identity IS the pubkey, so
			// it moves to the instance arg (no separate public-key
			// child). The compiler hard-rejects duplicate pubkeys at
			// commit (schema_walk.go validateWireguardPeers).
			"peer": {desc: "WireGuard peer (keyed by public key)", args: 1, placeholder: "<public-key>", children: map[string]*schemaNode{
				"allowed-ips": {desc: "Peer allowed IPs (CIDR)", args: 1, multi: true, placeholder: "<prefix>", children: nil},
				"endpoint":    {desc: "Peer endpoint (ip:port)", args: 1, placeholder: "<ip:port>", children: nil},
				"persistent-keepalive": {
					desc:          "Persistent keepalive seconds",
					args:          1,
					placeholder:   "<seconds>",
					valueType:     ValueInteger,
					valueDesc:     "Persistent keepalive interval in seconds (0..65535; 0 = disabled)",
					valueExamples: []string{"25"},
					validator:     ValidateInteger(0, 65535),
					children:      nil,
				},
				"preshared-key": {desc: "Per-peer preshared key (hex)", args: 1, placeholder: "<hex-key>", children: nil},
			}},
		},
	}
}

// interfaceDynamicDNSSchema returns the config-mode schema for a per-family
// Surface A router/interface-address DDNS binding (#2691 P2, plan §5.9):
// `interfaces <if> unit <n> family <af> dynamic-dns { provider X; hostname Y;
// address-source dhcp; ttl 300; }`. A fresh tree per call so the inet and inet6
// parents do not share a mutable map. The provider name stays untyped so a
// valid value is not rejected at commit; the engine warn-validates the provider
// reference + binding at commit (validateSurfaceADDNSWarnings) and is fail-open
// at runtime. The hostname leaf IS typed (#2779): the publish path silently
// rewrites a non-LDH / empty-label name to a DIFFERENT public DNS name, so a
// name that would be structurally transformed is rejected at commit via
// ValidateDDNSHostname rather than published wrong with no error.
func interfaceDynamicDNSSchema() *schemaNode {
	return &schemaNode{desc: "Publish this interface address via Dynamic DNS (Surface A, #2691)", children: map[string]*schemaNode{
		"provider": {desc: "system services dynamic-dns provider to publish through", args: 1, placeholder: "<provider-name>", children: nil},
		"hostname": {
			desc:        "FQDN to publish for this interface address",
			args:        1,
			placeholder: "<fqdn>",
			// #2779: the publish path (surfaceAName -> sanitizeFQDN) silently
			// rewrites a hostname containing non-LDH characters / empty labels
			// to a DIFFERENT public DNS name. For router-owned Surface A the
			// hostname is operator intent, so reject a name that would be
			// structurally transformed at commit instead of publishing the
			// wrong name with no error. Case + a single trailing dot are
			// accepted (benign canonicalization).
			valueType: ValueHostname,
			valueDesc: "FQDN to publish (LDH labels only: letters, digits, hyphens)",
			validator: ValidateDDNSHostname,
			children:  nil,
		},
		"address-source": {
			desc:          "Where this interface's current address is observed",
			args:          1,
			valueType:     ValueEnumOf,
			valueDesc:     "Address source (interface | dhcp | checkip)",
			valueExamples: []string{"interface", "dhcp", "checkip"},
			validator:     ValidateEnum([]string{"interface", "dhcp", "checkip"}),
			children:      nil,
		},
		"ttl": {
			desc:          "TTL (seconds) for the published A/AAAA record (default 300)",
			args:          1,
			valueType:     ValueInteger,
			valueDesc:     "Record TTL in seconds (>= 1; default 300 when unset)",
			valueExamples: []string{"300", "3600"},
			validator:     ValidateIntegerMin(1),
			children:      nil,
		},
		"source-address": {
			desc: "Source address to bind the UPDATE socket to (overrides the provider's)",
			args: 1,
			// #2780: the runtime feeds source-address to netip.ParseAddr
			// (pkg/ddns/backend_bind.go resolveBindConfig). A free-form value
			// that does not parse is a hard error there, so the backend falls
			// back to a no-op for that scope and the binding silently stops
			// emitting UPDATEs. Reject a non-IP literal at commit (reusing the
			// GRE/tunnel ValidateIPAddress) instead of committing garbage that
			// disables the scope at runtime. A bare IP only — no prefix length.
			valueType: ValueIPAddress,
			valueDesc: "Source IP literal to bind the UPDATE socket to (v4 or v6, no prefix)",
			validator: ValidateIPAddress,
			children:  nil,
		},
	}}
}
