package config

import (
	"fmt"
	"sort"
	"strings"
)

// compiler_tunnel_plaintext_advisory.go holds the pieces the #5619 IPsec and
// #5618 WireGuard plaintext advisories SHARE.
//
// The two advisories describe the same operator-visible fact about two
// different protocols: a tunnel's decapsulated inner traffic leaves the xpf
// dataplane's adjudication and is forwarded by the Linux kernel, so the zone
// the operator put the tunnel interface in does not govern it.
//
// WHAT IS SHARED HERE and what is deliberately NOT:
//
// Shared, because a divergence would ALWAYS be a bug:
//
//   - forEachZoneInterfaceMemberAST — the zone-membership enumeration. Both
//     advisories must see EXACTLY the members compileZones sees, including a
//     bracketed `interfaces [ a b ]` list, whose tail arrives NESTED under the
//     first member because the lexer strips the brackets (#2419/#5248). Two
//     independent readers of that shape is precisely how the #5248 defect
//     class arises, so there is one reader and it is the compiler's own
//     (zoneInterfaceStanzaMembers).
//
//   - renderPlaintextUnadjudicatedAdvisory — the AGGREGATION SHAPE. Exactly
//     ONE advisory per commit however many tunnels are affected; a stable sort
//     so both HA nodes render the identical string; the zoned/unzoned
//     partition; and the #6682 unzoned caveat emitted only when there IS an
//     unzoned tunnel. If one advisory fired per tunnel while the other
//     aggregated, or one dropped the #6682 caveat, the operator would read two
//     contradictory accounts of one mechanism.
//
//   - The group HEADINGS and the #6682 caveat sentence. They are statements
//     about zone id 0 and about what "zoned" means, not about IPsec or
//     WireGuard. Two spellings of one fact is a bug.
//
// NOT shared, because a divergence is LEGITIMATE:
//
//   - The finding-collection walk. IPsec findings come from
//     `security ipsec vpn <v> bind-interface` and are joined to zones by XFRM
//     if_id; WireGuard findings come from `interfaces <if> [unit <n>] tunnel
//     mode wireguard` and are joined by interface reference. Different
//     hierarchies, different identity, different join key.
//
//   - Every protocol-specific SENTENCE (plaintextAdvisoryWording). The
//     mechanism differs (kernel XFRM stack vs the userspace helper's WireGuard
//     control thread writing to a TUN), and so does the remedy an operator can
//     reach for. Forcing one wording would make at least one of them false.
//
// NEITHER advisory can reject. Both entry points return only []string — no
// error, no `lenient` flag — so the #1960 no-brick property is STRUCTURAL
// rather than a convention a later edit could quietly invert.

// plaintextTunnelFinding is one tunnel whose decapsulated inner traffic is not
// zone-adjudicated.
//
//   - ref is the operator-facing interface reference (`st0.0`, `wg0.0`).
//   - detail is the config path that DECLARED the tunnel, rendered in the
//     parenthetical so the operator can find the stanza to edit.
//   - zone is the security zone the interface is a member of, or "" when it is
//     in none. "" is not a mitigation — see plaintextAdvisoryUnzonedCaveat.
type plaintextTunnelFinding struct {
	ref    string
	detail string
	zone   string
}

// plaintextAdvisoryWording carries the protocol-specific sentences.
// Everything not in here is structure, and structure is shared.
type plaintextAdvisoryWording struct {
	// lead is the first sentence, and it must carry the issue number the
	// operator (and the tests) grep for.
	lead string
	// zonedSuffix completes `<ref> (<detail>) is assigned to security-zone
	// "<zone>", <zonedSuffix>`.
	zonedSuffix string
	// mechanism states HOW the plaintext escapes adjudication.
	mechanism string
	// remedy states what the operator can do until enforcement lands.
	remedy string
}

const (
	// plaintextAdvisoryZonedHeading introduces the ACUTE group. A zoned tunnel
	// is worse than an unimplemented feature: the zone assignment commits
	// cleanly and nothing distinguishes it from a zone that is enforced, so the
	// operator has been told something specific and untrue.
	plaintextAdvisoryZonedHeading = "ASSIGNED A ZONE THAT IS NOT ENFORCED — this reads as protected and is not:"

	// plaintextAdvisoryUnzonedHeading introduces the plain-statement group.
	plaintextAdvisoryUnzonedHeading = "NOT ZONE-ADJUDICATED:"

	// plaintextAdvisoryUnzonedCaveat is emitted only when at least one tunnel
	// is unzoned. Leaving a tunnel out of a zone is NOT a mitigation, and an
	// operator reading only the zoned paragraph could conclude that it is.
	// #6682: this sentence used to say an unzoned interface resolves to zone id
	// 0 "which a `from-zone any to-zone any permit` rule matches". That was
	// never true -- the #3110 guard has fenced every rule tier, wildcard tiers
	// included, against zone 0 since before the claim was written -- and #6682
	// went further and made an unzoned INGRESS an explicit deny. The conclusion
	// survives; only the mechanism was wrong, and it is the mechanism an
	// operator would act on.
	plaintextAdvisoryUnzonedCaveat = "An UNZONED tunnel is not safer: leaving it out of a zone does " +
		"not bring its plaintext under policy, it only leaves it unadjudicated by a different route " +
		"(#6682)."
)

// renderPlaintextUnadjudicatedAdvisory folds every finding into ONE advisory.
//
// ONE aggregated advisory per commit, not one per tunnel. An advisory that
// fires N times on every commit is filtered out, and then it protects nobody —
// the same reason compiler_system.go folds several inert knobs into a single
// message. The affected tunnels are named inside it.
//
// The two groups are worded differently on purpose: see the heading constants.
//
// The sort is stable and total over (ref, detail) so the rendered string is a
// pure function of the config — both HA nodes emit byte-identical text, and a
// map-iteration order upstream cannot make the advisory flap between commits.
//
// Returns nil (not an empty slice) when there is nothing to report, so callers
// can append unconditionally.
func renderPlaintextUnadjudicatedAdvisory(findings []plaintextTunnelFinding, w plaintextAdvisoryWording) []string {
	if len(findings) == 0 {
		return nil
	}
	sorted := make([]plaintextTunnelFinding, len(findings))
	copy(sorted, findings)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].ref != sorted[j].ref {
			return sorted[i].ref < sorted[j].ref
		}
		return sorted[i].detail < sorted[j].detail
	})

	var zoned, unzoned []plaintextTunnelFinding
	for _, f := range sorted {
		if f.zone != "" {
			zoned = append(zoned, f)
		} else {
			unzoned = append(unzoned, f)
		}
	}

	var b strings.Builder
	b.WriteString(w.lead)
	if len(zoned) > 0 {
		b.WriteString("\n  " + plaintextAdvisoryZonedHeading)
		for _, f := range zoned {
			fmt.Fprintf(&b, "\n    %s (%s) is assigned to security-zone %q, %s",
				f.ref, f.detail, f.zone, w.zonedSuffix)
		}
	}
	if len(unzoned) > 0 {
		b.WriteString("\n  " + plaintextAdvisoryUnzonedHeading)
		for _, f := range unzoned {
			fmt.Fprintf(&b, "\n    %s (%s)", f.ref, f.detail)
		}
	}
	b.WriteString("\n  " + w.mechanism)
	if len(unzoned) > 0 {
		b.WriteString(" " + plaintextAdvisoryUnzonedCaveat)
	}
	b.WriteString(" " + w.remedy)

	return []string{b.String()}
}

// forEachZoneInterfaceMemberAST calls fn(zoneName, memberRef) for every
// interface reference named by a `security zones security-zone <z> interfaces
// ...` stanza, across every AST shape.
//
// Membership is read through zoneInterfaceStanzaMembers — the flattener
// compileZones itself uses — for the reason stated at the top of this file: a
// bracketed `interfaces [ a b ]` list arrives bracket-stripped with the tail
// NESTED under the first member (#2419/#5248), and a second, independent
// reader of that shape is exactly how a member gets silently dropped. Reading
// only `iface.Name()` would see the FIRST member and miss every one after it.
//
// It iterates EVERY top-level `security` node and EVERY `zones` sibling with
// forEachChild rather than FindChild (#3562): parseStatements APPENDS a
// repeated top-level block rather than merging it, and the compiler compiles
// every one, so a zone living in a duplicate block must not be missed here
// either.
//
// The callback is invoked once per (zone, member) pair in AST order. Ordering
// is deterministic for a given tree; callers that need a total order over their
// own findings impose it themselves (renderPlaintextUnadjudicatedAdvisory does).
func forEachZoneInterfaceMemberAST(nodes []*Node, fn func(zone, member string)) {
	_ = forEachChild(nodes, "security", func(security *Node) error {
		return forEachChild(security.Children, "zones", func(zones *Node) error {
			for _, inst := range zoneGroupInstances8794(zones.FindChildren("security-zone")) {
				if inst.name == "" {
					continue
				}
				for _, prop := range inst.node.Children {
					if prop.Name() != "interfaces" {
						continue
					}
					for _, member := range zoneInterfaceStanzaMembers(prop) {
						if member == "" {
							continue
						}
						fn(inst.name, member)
					}
				}
			}
			return nil
		})
	})
}
