package config

import (
	"fmt"
	"sort"
	"strings"
)

// compiler_tunnel_plaintext_advisory.go holds the pieces the #5619 IPsec and
// #5618 WireGuard plaintext advisories SHARE.
//
// The two advisories used to describe ONE fact about two protocols: a tunnel's
// decapsulated inner traffic leaves the xpf dataplane's adjudication and is
// forwarded by the Linux kernel, so the zone the operator put the tunnel
// interface in does not govern it. It is still exactly that for route-based
// IPsec. For WireGuard, #8274 moved transport decapsulation into the AF_XDP
// worker, which adjudicates the inner packet under the tunnel's zone, and left
// a kernel-path residual (docs/log/8274.md "The residual, stated rather than
// closed"; #9594). So since #9251 the two advisories render DIFFERENT facts
// through one shared shape.
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
//     partition; and the unzoned caveat emitted only when there IS an unzoned
//     tunnel. If one advisory fired per tunnel while the other aggregated, or
//     one dropped its unzoned caveat, the operator would read two
//     differently-shaped accounts of tunnel plaintext on one commit.
//
// NOT shared, because a divergence is LEGITIMATE:
//
//   - The finding-collection walk. IPsec findings come from
//     `security ipsec vpn <v> bind-interface` and are joined to zones by XFRM
//     if_id; WireGuard findings come from `interfaces <if> [unit <n>] tunnel
//     mode wireguard` and are joined by interface reference. Different
//     hierarchies, different identity, different join key.
//
//   - Every SENTENCE (plaintextAdvisoryWording), the group HEADINGS and the
//     unzoned caveat included. The mechanism differs (the kernel XFRM stack
//     vs the AF_XDP worker, with a kernel-path residual through the helper's
//     WireGuard control thread), and so does the remedy an operator can reach
//     for. Forcing one wording would make at least one of them false.
//
//     The headings and the caveat were SHARED until #9251, on the argument
//     that they were "statements about zone id 0 and about what 'zoned'
//     means, not about IPsec or WireGuard". #8274 hollowed that premise: what
//     a zone means for a tunnel's plaintext depends on WHERE the protocol
//     decapsulates. An IPsec tunnel's zone is not enforced on its plaintext at
//     all. A WireGuard tunnel's zone IS enforced on the dataplane path and not
//     on the kernel path, and an unzoned WireGuard tunnel's transit is DENIED
//     on the dataplane path (#6682) rather than "unadjudicated by a different
//     route". The shared heading rendered IPsec's account for WireGuard —
//     "ASSIGNED A ZONE THAT IS NOT ENFORCED" for a zone the dataplane
//     enforces — which is the defect #9251 reports.
//
// NEITHER advisory can reject. Both entry points return only []string — no
// error, no `lenient` flag — so the #1960 no-brick property is STRUCTURAL
// rather than a convention a later edit could quietly invert.

// plaintextTunnelFinding is one tunnel whose decapsulated inner traffic is not
// zone-adjudicated: on any path (IPsec), or on the kernel path (WireGuard).
//
//   - ref is the operator-facing interface reference (`st0.0`, `wg0.0`).
//   - detail is the config path that DECLARED the tunnel, rendered in the
//     parenthetical so the operator can find the stanza to edit.
//   - zone is the security zone the interface is a member of, or "" when it is
//     in none. What "" means is protocol-specific — see each advisory's
//     unzonedCaveat.
type plaintextTunnelFinding struct {
	ref    string
	detail string
	zone   string
}

// plaintextAdvisoryWording carries every protocol-specific sentence, the group
// headings and the unzoned caveat included (#9251). Everything not in here is
// structure, and structure is shared.
//
// EVERY field is required, and there is deliberately no default. A default
// heading or caveat would be ONE protocol's account of its own decapsulation
// path, and an advisory that left the field empty would render that account as
// its own — which is the #9251 defect exactly: WireGuard rendering IPsec's
// "ASSIGNED A ZONE THAT IS NOT ENFORCED" for a zone the dataplane enforces.
// TestPlaintextAdvisoryWordingsAreCompleteAndDistinct is the guard.
type plaintextAdvisoryWording struct {
	// lead is the first sentence, and it must carry the issue number the
	// operator (and the tests) grep for.
	lead string
	// zonedHeading introduces the group of tunnels that ARE in a zone.
	zonedHeading string
	// zonedSuffix completes `<ref> (<detail>) is assigned to security-zone
	// "<zone>", <zonedSuffix>`.
	zonedSuffix string
	// unzonedHeading introduces the group of tunnels that are in no zone.
	unzonedHeading string
	// mechanism states where the plaintext is, and is not, adjudicated.
	mechanism string
	// unzonedCaveat follows the mechanism when at least one tunnel is unzoned:
	// what leaving THIS protocol's tunnel out of a zone does and does not
	// change, so an operator reading only the zoned group cannot conclude
	// something false about the unzoned one.
	unzonedCaveat string
	// remedy states what the operator can do about the unadjudicated path.
	remedy string
}

// renderPlaintextUnadjudicatedAdvisory folds every finding into ONE advisory.
//
// ONE aggregated advisory per commit, not one per tunnel. An advisory that
// fires N times on every commit is filtered out, and then it protects nobody —
// the same reason compiler_system.go folds several inert knobs into a single
// message. The affected tunnels are named inside it.
//
// The two groups are worded differently on purpose, and differently per
// protocol: see plaintextAdvisoryWording.
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
		b.WriteString("\n  " + w.zonedHeading)
		for _, f := range zoned {
			fmt.Fprintf(&b, "\n    %s (%s) is assigned to security-zone %q, %s",
				f.ref, f.detail, f.zone, w.zonedSuffix)
		}
	}
	if len(unzoned) > 0 {
		b.WriteString("\n  " + w.unzonedHeading)
		for _, f := range unzoned {
			fmt.Fprintf(&b, "\n    %s (%s)", f.ref, f.detail)
		}
	}
	b.WriteString("\n  " + w.mechanism)
	if len(unzoned) > 0 {
		b.WriteString(" " + w.unzonedCaveat)
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
			for _, inst := range bracketedGroupInstances8794(zones.FindChildren("security-zone")) {
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
