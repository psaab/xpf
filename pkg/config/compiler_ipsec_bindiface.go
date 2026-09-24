package config

import (
	"fmt"
	"sort"
	"strings"
)

// compiler_ipsec_bindiface.go carries the #2933 reject-at-commit gate for two
// distinct secure-tunnel `bind-interface` aliases that derive the SAME Linux
// XFRM if_id.
//
// The defect: `security ipsec vpn <name> bind-interface` is a free-form 1-arg
// string (schema_security.go) stored verbatim on the typed VPN
// (compiler_ipsec.go). The runtime resolves it to a Linux xfrmi device name
// and a stable XFRM if_id via XFRMIfNameAndID (xfrmi.go):
//
//	if_id = stIndex<<16 | (unit+1)        (unit defaults to 0)
//
// so `bind-interface st0` and `bind-interface st0.0` BOTH derive if_id 1 — a
// bare `st0` is the same xfrmi device as `st0.0`. Two VPNs that bind these two
// distinct strings committed cleanly, but at apply time only one xfrm device
// can carry that if_id. Before #2929 this silently leaked one VPN's SA onto the
// other's tunnel; #2929 added a pkg/routing last-line-of-defense guard that
// refuses to create EITHER device and logs an ERROR — correct, but the operator
// experience is "both tunnels silently down with a journal ERROR" rather than a
// config-commit error.
//
// This gate turns that apply-time both-down into a Junos-style commit-check
// error (candidate rejected, live config untouched). The #2929 routing guard
// stays as the runtime backstop.
//
// Scope — surgical: the if_id-collision arm fires ONLY when two DISTINCT
// bind-interface strings derive the SAME non-zero if_id. It does NOT fire when
// the same bind-interface string is shared by multiple VPNs (that is one
// device, one if_id — not the ambiguous-alias case #2929 named).
//
// An unambiguous map (st0.0 + st0.1, or st0 + st1) commits cleanly.
//
// #5297 invalid-name arm: a NON-EMPTY bind-interface that XFRMIfNameAndID
// cannot parse as `st<N>[.unit]` resolves to if_id 0 — it creates NO XFRM
// device at reconciliation, so the route-based VPN commits but silently
// carries no traffic. This is a DISTINCT failure from the #2933 collision
// (which needs two VALID, non-zero if_ids): the gate now rejects such a name on
// the strict path (naming the canonical st<N>[.unit] requirement) and warns on
// the tolerant path, mirroring the same strict/lenient split. A missing or
// empty bind-interface (none configured) is rejected on the strict path and
// warned on the tolerant path (#10638): without a bind-interface the runtime
// capture plan marks the VPN IFIDUnderivable and every apply installs a
// box-wide quarantine guard dropping all non-loopback traffic.
//
// This is an AST pre-walk (like validateUnsupportedInterfaceStanzasAST / the other
// reject-at-commit gates) rather than a typed-Config validator so it runs on
// the group-expanded, inactive-pruned tree in compileExpanded: an
// apply-groups-inherited bind-interface is covered and an `inactive:` VPN is
// ignored for free.
//
// Strict path (commit / commit-check, lenient=false): the first colliding
// if_id is a hard compile error naming every offending bind-interface string,
// its VPN(s), and the shared if_id.
//
// Lenient path (load / peer-sync, lenient=true): every collision is returned as
// a warning and compilation continues — an already-persisted or peer-synced
// config that an older binary silently accepted still BOOTS (#1960
// fail-closed-on-load class). Mirrors the other lenient gates' no-prune
// handling; the runtime #2929 routing guard still refuses the colliding
// devices.
func validateSecureTunnelBindInterfaceAST(nodes []*Node, lenient bool) ([]string, error) {
	// bindRef tracks the VPN(s) that configured one distinct bind-interface
	// string (a single string may legitimately be shared by several VPNs).
	type bindRef struct {
		vpns []string
	}
	// if_id -> distinct bind-interface string -> the VPN(s) that bound it.
	byID := map[uint32]map[string]*bindRef{}
	order := []uint32{} // first-seen if_id order for deterministic errors

	// #5297: a NON-EMPTY bind-interface that XFRMIfNameAndID resolves to
	// if_id 0 is not a canonical st<N>[.unit] secure-tunnel name. It commits
	// but creates no XFRM device at reconciliation (pkg/routing logs "invalid
	// bind-interface name"), so the route-based VPN is silently DOWN. Collect
	// these here and reject (strict) / warn (lenient) after the walk, in
	// deterministic order. Distinct from the #2933 if_id-collision gate below
	// (two VALID aliases sharing one non-zero if_id).
	type invalidBind struct{ vpn, iface string }
	var invalid []invalidBind

	// #10638: union of VPN names carrying at least one bind-bearing
	// instance. The typed compiler MERGES duplicate VPN stanzas across
	// blocks (compiler_ipsec.go: vpn := sec.IPsec.VPNs[inst.name]), so a
	// bind-interface in ANY instance satisfies the VPN and missing is
	// decided after the walk (vpnNames minus hasBind), not per instance.
	hasBind := map[string]bool{}
	var vpnNames []string
	seenVPN := map[string]bool{}

	// #3562: iterate EVERY top-level `security` node and EVERY `ipsec` sibling,
	// not the first match at any level. parseStatements APPENDS a repeated
	// top-level block instead of merging it (parser.go) and compileExpanded /
	// compileSecurity compile every `security` root and every `ipsec` sibling,
	// so two VPNs that derive a colliding XFRM if_id from distinct
	// bind-interface aliases could be split across duplicate `security {}` (or
	// duplicate `ipsec {}`) blocks and bypass a first-`security`/first-`ipsec`
	// walk while the compiler still compiled both. Aggregating the if_id map
	// across every block via forEachChild catches the collision wherever the
	// two distinct bind-interface strings live (the multi-level duplicate-block
	// class). The inner per-VPN if_id derivation + distinct-string collision
	// check below is unchanged.
	collect := forEachChild(nodes, "security", func(security *Node) error {
		return forEachChild(security.Children, "ipsec", func(ipsec *Node) error {
			for _, inst := range namedInstances(ipsec.FindChildren("vpn")) {
				// #10638: record every VPN instance; missing is decided after
				// the walk (vpnNames minus hasBind) because the typed compiler
				// merges duplicate VPN stanzas across blocks.
				if !seenVPN[inst.name] {
					seenVPN[inst.name] = true
					vpnNames = append(vpnNames, inst.name)
				}
				// #9088: expand a packed flat run before looking for the leaf.
				// This gate walks the AST, and a one-liner such as
				//
				//	set security ipsec vpn v1 gateway G ipsec-policy P \
				//	    bind-interface ge-0/0/0
				//
				// buries `bind-interface` inside a SIBLING node's Keys, so a
				// bare FindChild returns nil and this VPN is skipped entirely.
				// The gate then never sees a value to reject and the config
				// commits -- with no XFRM device at all, which is the exact
				// condition this gate exists to prevent.
				//
				// So the packed spelling did not merely lose a value; it
				// removed this gate's SUBJECT. Fixing the compiler alone is not
				// enough for the same reason ipsecTrafficSelectorSchema8939
				// gives one file over, pointed the other way: the admission
				// gate walks the same children and needs the same segmentation.
				biNode := findChildInRun9088(inst.node, "bind-interface")
				if biNode == nil {
					continue
				}
				bindIface := nodeVal(biNode)
				if bindIface == "" {
					continue
				}
				// #10638: presence (even an invalid name) satisfies "has a
				// bind-interface"; a bad value is the #5297 arm's subject, not
				// the missing arm's.
				hasBind[inst.name] = true
				_, ifID := XFRMIfNameAndID(bindIface)
				if ifID == 0 {
					// #5297: not a recognizable st<N>[.unit] secure-tunnel
					// binding — it creates no XFRM device (empty name / zero
					// id), so the VPN silently carries no traffic. Record for a
					// fail-closed reject (strict) / warn (lenient) after the
					// walk. NOT the #2933 collision case (that needs a valid,
					// non-zero if_id).
					invalid = append(invalid, invalidBind{vpn: inst.name, iface: bindIface})
					continue
				}
				group, ok := byID[ifID]
				if !ok {
					group = map[string]*bindRef{}
					byID[ifID] = group
					order = append(order, ifID)
				}
				ref, ok := group[bindIface]
				if !ok {
					ref = &bindRef{}
					group[bindIface] = ref
				}
				ref.vpns = append(ref.vpns, inst.name)
			}
			return nil
		})
	})
	if collect != nil {
		// The collection closures never return an error; this is defensive.
		return nil, collect
	}

	var warnings []string
	emit := func(format string, args ...any) error {
		msg := fmt.Sprintf(format, args...)
		if !lenient {
			return fmt.Errorf("%s", msg)
		}
		warnings = append(warnings, msg)
		return nil
	}

	// #5297: fail closed on any bind-interface that resolves to no XFRM
	// device. Strict (commit / commit-check) hard-rejects with an actionable
	// message naming the canonical st<N>[.unit] requirement; lenient (load /
	// peer-sync) warns and skips so an already-persisted or peer-synced config
	// an older binary silently accepted still BOOTS (#1960) — the pkg/routing
	// reconciler stays the runtime backstop (logs the invalid name, no device).
	// Sorted for deterministic output.
	sort.Slice(invalid, func(i, j int) bool {
		if invalid[i].iface != invalid[j].iface {
			return invalid[i].iface < invalid[j].iface
		}
		return invalid[i].vpn < invalid[j].vpn
	})
	for _, bad := range invalid {
		if err := emit(
			"secure-tunnel bind-interface %q (security ipsec vpn %s) is not a "+
				"valid secure-tunnel interface: it must be st<N> or st<N>.<unit> "+
				"(e.g. st0 or st0.1). Any other name resolves to no XFRM "+
				"interface, so the route-based VPN commits successfully but "+
				"carries no traffic (silent tunnel down) (#5297)",
			bad.iface, bad.vpn); err != nil {
			return nil, err
		}
	}

	// #10638: fail closed on a VPN with no bind-interface at all (or an
	// empty value). Without a usable bind-interface the runtime capture
	// plan marks the VPN IFIDUnderivable and stageIpsecCapture installs a
	// box-wide quarantine guard on every apply, dropping management, IKE,
	// BGP and cluster heartbeat until the config changes. Strict (commit /
	// commit-check) hard-rejects; lenient (load / peer-sync) warns so an
	// already-persisted config an older binary silently accepted still
	// BOOTS (#1960). vpnNames is first-seen order: deterministic output.
	for _, name := range vpnNames {
		if hasBind[name] {
			continue
		}
		if err := emit(
			"security ipsec vpn %s has no bind-interface: route-based IPsec "+
				"requires bind-interface st<N> or st<N>.<unit> (e.g. st0 or "+
				"st0.1); without one every apply installs a box-wide capture "+
				"quarantine dropping all non-loopback traffic (#10638)",
			name); err != nil {
			return nil, err
		}
	}

	for _, ifID := range order {
		group := byID[ifID]
		if len(group) < 2 {
			// One distinct bind-interface string for this if_id (possibly
			// shared by several VPNs) — not the ambiguous-alias case.
			continue
		}
		// Two or more DISTINCT bind-interface strings collide on this if_id.
		names := make([]string, 0, len(group))
		for name := range group {
			names = append(names, name)
		}
		sort.Strings(names)
		descs := make([]string, 0, len(names))
		for _, name := range names {
			vpns := append([]string(nil), group[name].vpns...)
			sort.Strings(vpns)
			descs = append(descs, fmt.Sprintf(
				"bind-interface %q (security ipsec vpn %s)",
				name, strings.Join(vpns, ", ")))
		}
		if err := emit(
			"secure-tunnel bind-interface alias collision: %s all derive the "+
				"same XFRM if_id %d (a bare st<N> is unit 0, so st<N> and "+
				"st<N>.0 are the same xfrm device); only one device can carry "+
				"that if_id, so the others are dropped at apply time (both "+
				"tunnels down / cross-VPN SA leak). Bind each VPN to a distinct "+
				"secure-tunnel unit, e.g. st0.0 and st0.1 (#2933)",
			strings.Join(descs, " and "), ifID,
		); err != nil {
			return nil, err
		}
	}
	return warnings, nil
}

// findChildInRun9088 finds a named leaf among a vpn node's children, expanding
// any packed flat run first.
//
// Split out rather than inlined so the two readers of this container -- this
// admission gate and the compiler -- segment identically by construction. A
// gate and a compiler that disagree about where a run ends is how a value
// reaches one and not the other, which is #9088.
func findChildInRun9088(vpn *Node, name string) *Node {
	if vpn == nil {
		return nil
	}
	for _, c := range expandIPsecVPNRun9088(vpn) {
		if c != nil && c.Name() == name {
			return c
		}
	}
	return nil
}
