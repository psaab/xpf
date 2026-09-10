package config

import (
	"fmt"
	"sort"
	"strings"
)

// compiler_wireguard_plaintext_warn.go carries the #5618 commit-time WARNING
// that a WireGuard tunnel's decapsulated plaintext is not zone-adjudicated on
// every path.
//
// WHAT IS TRUE NOW (#8274, #9521; restated by #9251). Inbound WireGuard
// transport reaches one of two paths:
//
//	dataplane path  The XDP shim hands a transport-data record for the steered
//	                listen port to the AF_XDP worker (wg_worker_claims_record,
//	                #8274). The worker decapsulates it
//	                (userspace-dp/src/afxdp/wg/decap.rs), rebinds the inner
//	                packet to the tunnel's logical ifindex and zone
//	                (logical_ingress::build_logical_ingress_packet) and runs
//	                screen, session, policy and NAT on it. A tunnel in no zone
//	                resolves to zone id 0 there, and #6682 DENIES transit from
//	                an unzoned ingress.
//	kernel path     A record that reaches the firewall through the Linux kernel
//	                instead — on an ingress interface the shim does not attach
//	                to (#8274's stated residual), or while the dataplane is
//	                degraded and the shim passes local-destination traffic to
//	                the kernel (helper start, redundancy-group transition, reth
//	                link cycle, missing binding, stale heartbeat; #9594) — lands
//	                on the helper's WireGuard control thread socket. For the
//	                STEERED listen port that thread writes the plaintext to the
//	                wgN TUN (`write_packet_nonblocking` in
//	                userspace-dp/src/afxdp/coordinator/wg_control/dispatch.rs)
//	                and the kernel forwards it with no zone policy, no session,
//	                no NAT and no screen. For every OTHER listen port the thread
//	                drops it (#9521).
//
// So the zone an operator gives a WireGuard tunnel IS enforced on the dataplane
// path and is NOT enforced on the kernel path. This advisory used to say the
// zone was not enforced at all — "ASSIGNED A ZONE THAT IS NOT ENFORCED — this
// reads as protected and is not" — which described the pre-#8274 dataplane and
// became false when #8274 landed (#9251). It now states both halves.
//
// Why it still fires for EVERY WireGuard tunnel rather than only the steered
// one. The kernel-path write belongs to the tunnel on the steered listen port,
// and the steered port has exactly one derivation, SteeredWireGuardListenPort,
// which reads the TYPED Config. This advisory runs in the AST pre-walk, before
// that Config exists, and a second, AST-level derivation of the steered port is
// the divergence #9521 removed. With one listen port — the case the shim steers
// completely until #9587 — every tunnel is on it. With several, the multi-port
// warning (validateWireguardSingleSteeredPort) names the steered tunnel and the
// refused ones from the derivation the dataplane uses, and the mechanism
// sentence below scopes the residual to the steered port.
//
// xpf keeps ip_forward at 1 while the dataplane is armed and installs only
// nftables `hook input` chains, so nothing between the TUN write and the
// kernel's forwarding decision consults a zone.
//
// `allowed-ips` is not a substitute. It is a cryptographic peer/source
// ownership gate — it answers "may this peer claim this inner source address",
// not "may this source reach this destination". It has no destination, no
// zone-pair, no application and no direction.
//
// This is NOT the same as GRE. Native GRE decap happens ONLY inside the worker
// pipeline (userspace-dp/src/afxdp/gre.rs): it rebinds `ingress_ifindex` to the
// tunnel's `logical_ifindex`, derives `ingress_zone` from
// `ForwardingState.ifindex_to_zone_id`, reparses the inner flow, and continues
// through screen, session, route, filters and zone-pair policy. WireGuard's
// dataplane path now does the same; what GRE lacks is a second, kernel-side
// decap path, and WireGuard has one. That is why this advisory keys on the MODE
// and not merely on "is a tunnel".
//
// Coupling to the dataplane exclusion, which is also why the kernel path is
// unadjudicated: the wgN TUN the control thread writes to is never AF_XDP-bound,
// so a packet written to it is seen only by the kernel. The row that carries a
// WireGuard tunnel
// is `Tunnel=true` in its InterfaceSnapshot (buildInterfaceSnapshotsFrom sets
// `Tunnel: iface.Tunnel != nil` on the base row and `iface.Tunnel != nil ||
// unit.Tunnel != nil` on the unit row, pkg/dataplane/userspace/interfaces.go).
// The `Tunnel` arm of netdevExclusionClasses matches exactly that flag, so
// userspaceUnbindableNetdev — and therefore userspaceSkipsIngressInterface —
// excludes the row from the ingress-adjudication map
// (buildUserspaceIngressIfindexes) and from the AF_XDP binding plan. Measured
// on this tree for `set interfaces wg0 unit 0 tunnel mode wireguard` plus
// `set interfaces wg1 tunnel mode wireguard`:
//
//	row     Tunnel   exclusion class   skips ingress
//	wg0.0   true     "Tunnel"          true
//	wg1     true     "Tunnel"          true
//	wg1.0   true     "Tunnel"          true
//
// The exclusion predicate is therefore `Tunnel`, and this advisory's predicate
// is `Tunnel AND mode == wireguard` — a strict SUBSET, not the identical test,
// and the doc above says why the rest of the class (GRE/IPIP) is excluded from
// the advisory while still excluded from ingress binding. The two are joined at
// the `tunnel` stanza: an interface stops matching this advisory at exactly the
// moment it stops setting `Tunnel=true`, so the warning cannot outlive the
// exclusion it describes. `astTunnelModeWireguard` is the SAME `mode wireguard`
// extraction the tunnel-endpoint collision gate uses (tunnelid.go), which is in
// turn the extraction the compiler uses for TunnelConfig.Mode — so "is this a
// WireGuard tunnel" has one answer here, in the compiler, and in the snapshot.
//
// Keyed on the tunnel MODE, never on the `wg` name shape. Nothing reserves the
// `wg` prefix — schema_interfaces.go accepts a wildcard interface name — so a
// lexical `wg*` predicate would both miss a WireGuard tunnel on an
// unconventionally-named interface and fire on an ordinary NIC that happens to
// be called `wg5`. That is the #6691 lesson applied ahead of the bug.
//
// Why a warning and not a rejection. WireGuard is a supported, shipped feature
// (#1432 S2a); a box may already be running a WireGuard tunnel that carries
// production traffic. Rejecting it would not be a guard, it would be a feature
// removal, and it would leave that operator unable to commit an UNRELATED
// change. This is the #1960 no-brick posture: strict enough to tell the truth,
// never strict enough to brick a config the box already accepts and runs.
//
// This function CANNOT reject. It has no error return and takes no `lenient`
// flag — the no-brick property is structural, not a convention a later edit
// could quietly invert. If a future change genuinely needs to reject one of
// these, that belongs in a separate gate with its own justification, not here.
//
// ONE aggregated advisory per commit, not one per tunnel — see
// renderPlaintextUnadjudicatedAdvisory.
//
// It fires whenever a WireGuard tunnel is configured, NOT only when one carries
// a zone. Leaving the tunnel out of a zone does not close the kernel path: the
// control thread's TUN write consults no zone, so zoning or not zoning the
// interface does not change it. On the dataplane path the two DO differ, and
// the advisory says how: a zoned tunnel's traffic is adjudicated under its
// zone, and an unzoned tunnel's transit is DENIED — build_logical_ingress_packet
// resolves it to zone id 0 and #6682 refuses it before the implicit default
// policy, pinned end to end through the poll loop by
// poll_loop_denies_unzoned_wg_tunnel_transit_under_permit_all_9251.
//
// #6682: this comment used to add that an unzoned interface resolves to zone id
// 0 and could be "affirmatively PERMITTED by a wildcard rule". That was never
// true — #3110 has fenced every rule tier, wildcard tiers included, against
// zone 0 since before the claim was written — and #6682 made an unzoned INGRESS
// an explicit deny on top of that.
//
// The two groups are worded differently on purpose, and neither is an
// escalation any more. Before #8274 a zoned tunnel was the acute case: the zone
// committed cleanly and governed nothing, so the heading said "this reads as
// protected and is not". Since #8274 the zone governs the dataplane path, so
// that heading would itself be the untrue statement. The zoned group now says
// where the zone applies and where it does not, and the unzoned caveat says
// what the absence of a zone does on each path (#9251).
//
// An AST pre-walk (like warnSecureTunnelPlaintextUnadjudicatedAST) rather than
// a typed-Config pass, so it runs on the group-expanded, inactive-pruned tree
// in compileExpanded: an apply-groups-inherited `tunnel mode wireguard` is
// covered and an `inactive:` interface is ignored for free.
func warnWireGuardPlaintextUnadjudicatedAST(nodes []*Node) []string {
	zones := collectWireGuardZoneRefsAST(nodes)

	var findings []plaintextTunnelFinding
	seen := map[string]struct{}{}
	add := func(ref, detail string) {
		if ref == "" {
			return
		}
		if _, dup := seen[ref]; dup {
			return
		}
		seen[ref] = struct{}{}
		findings = append(findings, plaintextTunnelFinding{
			ref:    ref,
			detail: detail,
			zone:   zones.zoneFor(ref),
		})
	}

	// #3562 shape: iterate EVERY top-level `interfaces` node with forEachChild.
	// parseStatements APPENDS a repeated top-level block rather than merging it
	// and the compiler compiles every one (#5691), so a WireGuard tunnel living
	// in a second `interfaces {}` stanza must not be missed here either.
	_ = forEachChild(nodes, "interfaces", func(interfaces *Node) error {
		for _, iface := range interfaces.Children {
			name := iface.Name()
			if name == "" {
				continue
			}
			// Interface-level `tunnel mode wireguard`. This is ONE persistent
			// wgN TUN shared by every unit of the interface (Config.TunnelNameMap:
			// "the persistent wgN TUN is one shared device"), so it is reported
			// once against the interface reference, not once per unit.
			_ = forEachChild(iface.Children, "tunnel", func(tunnel *Node) error {
				if astTunnelModeWireguard(tunnel) {
					add(name, fmt.Sprintf("interfaces %s tunnel mode wireguard", name))
				}
				return nil
			})
			// Per-unit `tunnel mode wireguard`. A unit that carries its own
			// tunnel stanza gets its own device, so it is its own finding.
			for _, unit := range namedInstances(iface.FindChildren("unit")) {
				if unit.name == "" {
					continue
				}
				ref := CanonicalInterfaceUnitRef(name + "." + unit.name)
				_ = forEachChild(unit.node.Children, "tunnel", func(tunnel *Node) error {
					if astTunnelModeWireguard(tunnel) {
						add(ref, fmt.Sprintf("interfaces %s unit %s tunnel mode wireguard",
							name, unit.name))
					}
					return nil
				})
			}
		}
		return nil
	})

	return renderPlaintextUnadjudicatedAdvisory(findings, wireGuardPlaintextAdvisoryWording())
}

// WireGuard's group headings and unzoned caveat (#9251). They are not IPsec's:
// see plaintextAdvisoryWording for why those stopped being shared.
const (
	// wgPlaintextZonedHeading introduces tunnels that ARE in a zone. It is not
	// an escalation: the zone is enforced on the dataplane path, and the
	// heading says where it is not.
	wgPlaintextZonedHeading = "IN A SECURITY ZONE — enforced on the dataplane path, NOT on the kernel path:"

	// wgPlaintextUnzonedHeading introduces tunnels that are in no zone.
	wgPlaintextUnzonedHeading = "IN NO SECURITY ZONE:"

	// wgPlaintextUnzonedCaveat is emitted only when at least one tunnel is
	// unzoned. It carries both halves because each alone misleads: the
	// dataplane half is a DENY rather than a gap (#6682), so "unzoning is no
	// different from zoning" is false; and the kernel half is unchanged by
	// zoning, so "unzoning is safe" is false too.
	wgPlaintextUnzonedCaveat = "An UNZONED WireGuard tunnel's decapsulated transit is DENIED on " +
		"the dataplane path (#6682), but leaving it out of a zone does not close the kernel " +
		"path, which consults no zone at all."
)

// wireGuardPlaintextAdvisoryWording is the #5618 advisory's text.
//
// The lead and the zoned suffix state the SPLIT: evaluated on the dataplane
// path, not on the kernel path. The mechanism names both ways onto the kernel
// path — ingress the dataplane does not attach to (#8274's residual) and a
// degraded dataplane (#9594) — scopes the TUN write to the steered listen port,
// and says every other port is dropped there (#9521), so an operator with
// several ports is not told that a refused tunnel leaks.
func wireGuardPlaintextAdvisoryWording() plaintextAdvisoryWording {
	return plaintextAdvisoryWording{
		lead: "interfaces: decapsulated traffic on WireGuard tunnels is evaluated against " +
			"xpf security policies on the dataplane path only, NOT on the kernel path (#5618).",
		zonedHeading:   wgPlaintextZonedHeading,
		zonedSuffix:    "which governs its traffic on the dataplane path but NOT on the kernel path",
		unzonedHeading: wgPlaintextUnzonedHeading,
		mechanism: "The AF_XDP dataplane decapsulates WireGuard transport records in its " +
			"worker and evaluates the inner packet under the tunnel's security zone (#8274). " +
			"A record for the steered listen port that reaches the firewall through the Linux " +
			"kernel instead — on an ingress interface the dataplane does not attach to, or " +
			"while the dataplane is degraded (helper start, a redundancy-group transition, a " +
			"reth link cycle, a stale helper heartbeat; #9594) — is decrypted by the helper's " +
			"WireGuard control thread and written straight to the wgN TUN, where the kernel " +
			"routes and forwards it: no zone policy, no session, no NAT and no screen are " +
			"applied to it. A record for any other listen port is dropped on that path " +
			"(#9521). A peer's `allowed-ips` is a cryptographic check on the inner SOURCE " +
			"address, not a security policy — it has no destination, zone-pair or " +
			"application scope.",
		unzonedCaveat: wgPlaintextUnzonedCaveat,
		remedy: "On the kernel path, restrict what the tunnel can reach with routing, with " +
			"the peer's `allowed-ips`, or with the peer's own policy.",
	}
}

// wgZoneRefIndex maps a zone-member interface reference to its zone name, and
// resolves a WireGuard tunnel reference against it.
//
// Keyed by the LITERAL (canonicalized) reference the operator wrote rather than
// by a derived device identity, because a WireGuard interface has no
// config-visible device id to join on the way an xfrmi has an if_id
// (collectZoneInterfaceRefsAST, #5619). The fan-out that makes the two
// spellings meet is done at LOOKUP time by zoneFor, which mirrors — deliberately
// and no more widely than — the fan buildInterfaceZoneMap performs
// (pkg/dataplane/userspace/zones.go).
type wgZoneRefIndex struct {
	byRef map[string]string
	// refs is byRef's key set in sorted order, so the unit scan in zoneFor is
	// deterministic when an interface-level tunnel has several zoned units.
	refs []string
}

// collectWireGuardZoneRefsAST builds the zone-membership index from
// `security zones security-zone <z> interfaces <ref>`.
//
// Membership is read through the shared forEachZoneInterfaceMemberAST walker,
// so a bracketed `interfaces [ wg0.0 wg1.0 ]` list is fully seen: the lexer
// strips the brackets and the tail arrives NESTED under the first member
// (#2419/#5248), so reading only the first member would report every tunnel
// after it as UNZONED — dropping the escalation in exactly the case that earns
// it.
//
// References are canonicalized with CanonicalInterfaceUnitRef so `wg0.00` and
// `wg0.0` are one key, matching how buildInterfaceZoneMap keys the runtime map.
// First zone wins; a duplicate assignment is a separate concern with its own
// gate.
func collectWireGuardZoneRefsAST(nodes []*Node) wgZoneRefIndex {
	idx := wgZoneRefIndex{byRef: map[string]string{}}
	forEachZoneInterfaceMemberAST(nodes, func(zone, member string) {
		ref := CanonicalInterfaceUnitRef(member)
		if _, exists := idx.byRef[ref]; !exists {
			idx.byRef[ref] = zone
		}
	})
	idx.refs = make([]string, 0, len(idx.byRef))
	for ref := range idx.byRef {
		idx.refs = append(idx.refs, ref)
	}
	sort.Strings(idx.refs)
	return idx
}

// zoneFor resolves the zone governing a WireGuard tunnel reference.
//
// Three arms, each with a distinct reason, and deliberately no more fan-out
// than buildInterfaceZoneMap performs:
//
//  1. The literal reference. `bind` and zone written the same way.
//
//  2. A UNIT reference falling back to its BASE. A bare zone member
//     (`interfaces wg0`) means "every unit of wg0" — buildInterfaceZoneMap
//     fans a bare reference DOWN onto the interface's units, so `wg0.1` is
//     governed by a zone written on `wg0`.
//
//  3. An INTERFACE reference falling back to any zoned unit beneath it. An
//     interface-level `tunnel mode wireguard` is ONE shared wgN TUN
//     (Config.TunnelNameMap), so a zone on `wg1.0` governs that same TUN — and
//     reporting it as unzoned would drop the escalation for the most common
//     spelling of all, since operators zone units, not bare interfaces.
//
// What it deliberately does NOT do is fan a UNIT zone SIDEWAYS to a SIBLING
// unit's own tunnel. Under per-unit tunnels, unit 0 takes the base Linux device
// and unit N>0 takes a `uN` device (compiler_interfaces.go), so `wg0.1` is a
// different device from `wg0.0` and a zone on one says nothing about the other.
// Claiming otherwise would report a tunnel as zoned that is not.
func (z wgZoneRefIndex) zoneFor(ref string) string {
	if zone := z.byRef[ref]; zone != "" {
		return zone
	}
	base, _, hasUnit := strings.Cut(ref, ".")
	if hasUnit {
		return z.byRef[base]
	}
	prefix := ref + "."
	for _, member := range z.refs {
		if strings.HasPrefix(member, prefix) {
			return z.byRef[member]
		}
	}
	return ""
}
