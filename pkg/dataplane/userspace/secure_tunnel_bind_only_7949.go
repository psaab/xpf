package userspace

import (
	"sort"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

// #7949 Shape B: a secure tunnel named ONLY through `bind-interface`.
//
// THE SHAPE. #4515 accepts
//
//	set security ipsec vpn v bind-interface st0.0
//	set security zones security-zone vpn interfaces st0.0
//
// with no `set interfaces st0` stanza at all. The zone assignment commits
// cleanly and reads as enforced. But buildInterfaceSnapshotsFrom iterates
// `cfg.Interfaces.Interfaces` — the config map this shape is absent from by
// definition — so the snapshot carries NO row for the tunnel, and the Rust
// forwarding build never learns the netdev.
//
// WHAT THAT COSTS, measured in #7167 and re-read here. populate_interfaces
// (userspace-dp/src/afxdp/forwarding_build/interfaces.rs:222) populates
// name_to_ifindex / linux_to_ifindex only for rows with ifindex > 0, so with no
// row `resolve_ifindex` (fib.rs:446) misses on both maps, the interface-only
// next hop `@st0.0` collapses to ifindex 0 (fib.rs:379), and the lookup returns
// NoRoute (forwarding/fib.rs:583). NoRoute is slow-path eligible
// (types/forwarding.rs:1359), so on a `default-policy permit-all` box the frame
// is reinjected and the KERNEL forwards it: no session, no NAT, no screen, no
// egress zone policy. #7480's noroute_policy_denial closes this on a deny-all
// default — it evaluates with to-zone 0, which falls through to the default
// action — but not on permit-all. That residue is what this closes.
//
// WHY THE FIX IS A CONVERGENCE, NOT A NEW STATE. The very same tunnel written
// WITH a stanza (Shape A) already produces this row and has since #5619, which
// landed the identical transition for the other naming bug in this area and
// recorded it in snapshotLinuxName as
//
//	bind-interface st0.0  : NoRoute before -> MissingNeighbor after
//
// So every consumer's disposition toward a zoned secure-tunnel row is already
// decided, shipped, and reviewed — by Shape A. This appends a row that is
// FIELD-IDENTICAL to the one Shape A produces for the same tunnel, which makes
// the per-consumer question "should the two spellings of one tunnel behave the
// same?" rather than five independent judgements. #7949's acceptance criteria
// are met as a parity assertion (secure_tunnel_bind_only_7949_test.go), which
// cannot drift the way five hand-written expectations can.
//
// THE THREE REQUIREMENTS THE ISSUE PLACES ON ANY IMPLEMENTATION.
//
// R1 — the zone must be authored in the same change. Honoured STRUCTURALLY:
// this iterates `authored` (authoredZoneRefs), so a tunnel the operator never
// zoned gets no row and keeps today's behaviour exactly. It is not a
// convention a later edit could drop without deleting the loop's input.
//
//	Note on R1's stated reason, which is stale. The issue says a row with no
//	zone "denies under every policy measured, including a `from-zone any
//	to-zone any permit` wildcard — the tunnel goes dark". The first half is
//	right: policy.rs:2776 gates EVERY rule tier, both-any included, behind
//	`from_id != 0 && to_id != 0`. The conclusion is not. Only a zero INGRESS
//	zone is hard-denied (policy.rs:2988, #6682); a zero EGRESS zone falls
//	through to `state.default_action`, and that block says why in as many
//	words — "#6713: an xfrmi tunnel egress resolved to 0 ... denying on
//	`to_id` would risk black-holing a correctly-configured path". So an
//	unzoned row would land on the default action, which is exactly where
//	today's NoRoute path already lands (noroute_policy_denial also evaluates
//	with to-zone 0). The measurement was taken on a box whose default action
//	was deny; "goes dark" is a property of that default, not of zone 0. The
//	gate is kept anyway — an unzoned row buys no adjudication (zone 0 skips
//	every tier) and could not claim an egress zone regardless (R3 note below)
//	— but it is kept as a scope decision, not as an outage guard.
//
// R3 — SecureTunnel must be stamped, never defaulted. The issue's sharpest
// requirement: a row appended OUTSIDE the builder loop defaults `Tunnel` and
// `SecureTunnel` to false, escaping BOTH netdevExclusionClasses entries, and
// then the consumers documented as "skipped" do not skip it. Here the flag
// comes from snapshotSecureTunnel with THE REF THAT NAMES THE ROW, per the
// interfaces.go rule. It is true by construction — the same oracle
// (SecureTunnelNetdevForRef) both admits the row and sets the flag — and that
// coupling is the point: if the admission rule is ever widened, the flag
// follows it instead of silently disagreeing.
//
// FAIL-CLOSED INHERITANCE. SecureTunnelNetdevForRef returns false for an if_id
// COLLISION, because pkg/routing/xfrm.go then creates NEITHER device. Gating
// on it means a colliding config gets no row rather than a row naming a device
// that does not exist — the same answer the resolver already gives every other
// caller, reached by calling it rather than by re-deriving it.
//
// ONE ROW PER DEVICE. Both `st0` and `st0.0` can be authored as zone
// references for one tunnel, and under `bind-interface st0` both refs resolve
// to the netdev `st0`. Two rows on one ifindex would be an egress-zone claim
// CONFLICT in the helper (forwarding_build/interfaces.rs:155 merges per
// ifindex and any mismatch is sticky-Conflicting), which unzones the egress for
// the whole ifindex. The device dedup below makes that unreachable.
func appendBindInterfaceOnlySecureTunnelRows(
	cfg *config.Config,
	out []InterfaceSnapshot,
	idents []egressRowIdentity,
	authored map[string]string,
	zoneByInterface map[string]string,
	ifaceRoutingInstance map[string]string,
	quarantinedKeys map[string]struct{},
	liveXfrm map[string]bool,
) ([]InterfaceSnapshot, []egressRowIdentity) {
	if cfg == nil || len(authored) == 0 {
		return out, idents
	}
	haveName := make(map[string]bool, len(out))
	haveDev := make(map[string]bool, len(out))
	for i := range out {
		haveName[out[i].Name] = true
		if out[i].LinuxName != "" {
			haveDev[out[i].LinuxName] = true
		}
	}
	refs := make([]string, 0, len(authored))
	for ref := range authored {
		refs = append(refs, ref)
	}
	sort.Strings(refs)
	for _, ref := range refs {
		// A ref the builder loop already emitted is Shape A — the operator
		// wrote the stanza — and its row is authoritative. Never a second one.
		//
		// MEASURED SURVIVOR. Deleting this leaves the whole Go suite green, and
		// the reason is structural rather than a missing fixture: for the
		// synthesis to reach a ref at all, SecureTunnelNetdevForRef must name a
		// device for it, and snapshotLinuxName's FIRST arm resolves that same
		// ref through SecureTunnelUnitNetdev — the same
		// secureTunnelBindingForRef core — so a Shape A row for this ref
		// already carries that device in LinuxName and the haveDev check below
		// catches it one line later. There is no config where the two
		// disagree.
		//
		// Kept because the two guards are about DIFFERENT things and only one
		// of them is currently redundant. haveDev prevents two rows contending
		// for one ifindex; haveName prevents two rows with one NAME, which is a
		// broken snapshot rather than a contested one. If snapshotLinuxName's
		// arm ordering ever changes — round 5 of #6691 already moved it once —
		// this is the guard that keeps a duplicate name out, and it would be
		// reintroduced under worse conditions than it is kept under here.
		if haveName[ref] {
			continue
		}
		dev, ok := cfg.SecureTunnelNetdevForRef(ref)
		if !ok || dev == "" {
			continue
		}
		if haveDev[dev] {
			continue
		}
		zone := zoneByInterface[ref]
		if zone == "" {
			// Unreachable from `authored` (every entry names a zone) but
			// asserted rather than assumed: an unzoned row is the one shape
			// R1 exists to keep out, so the gate is stated where the row is
			// built rather than inferred from the input's provenance.
			continue
		}
		ifindex, mtu, hardwareAddr, addresses := buildLinkSnapshot(dev)
		base, unit, dotted := strings.Cut(ref, ".")
		// The parent netdev, resolved the way the builder loop resolves it for
		// a unit row whose interface has no stanza: snapshotLinuxName returns
		// config.LinuxIfName(ifName) when iface is nil. Not inventing a parent
		// and not omitting one — both would be a difference from the Shape A
		// row for the same tunnel, and the parity assertion is the whole basis
		// on which the consumer dispositions are decided. A BASE ref has no
		// parent, exactly as a base row does not.
		var parentLinux string
		var parentIfindex int
		if dotted && unit != "" {
			parentLinux = config.LinuxIfName(base)
			parentIfindex, _, _, _ = buildLinkSnapshot(parentLinux)
		}
		out = append(out, InterfaceSnapshot{
			Name: ref,
			// #9821 #22: same rule as the idents entry below — a dotted
			// ref with a unit part is a unit row (st-family-correct: a
			// bare `st0` bind stays a base row).
			IsUnit:          dotted && unit != "",
			Zone:            zone,
			RoutingInstance: ifaceRoutingInstance[ref],
			RoutingDomain:   routingDomainForInterfaceKey(ref, ifaceRoutingInstance, quarantinedKeys),
			LinuxName:       dev,
			ParentLinuxName: parentLinux,
			Ifindex:         ifindex,
			ParentIfindex:   parentIfindex,
			RXQueues:        userspaceRXQueueCount(dev),
			// Tunnel is the STANZA-derived flag (`iface.Tunnel != nil ||
			// unit.Tunnel != nil`) and this shape has no stanza, so false is
			// the honest value — matching what Shape A stamps on the same
			// row, whose stanza carries no `tunnel` block either. SecureTunnel
			// is the flag that classifies this row, and it is derived.
			Tunnel:       false,
			SecureTunnel: snapshotSecureTunnel(cfg, ref, dev, liveXfrm),
			MTU:          mtu,
			HardwareAddr: hardwareAddr,
			Addresses:    addresses,
			// RedundancyGroup stays 0: a stanza-less tunnel authors no
			// `redundancy-group` and has no RETH parent, so it cannot win
			// resolveOwnerRGFromZone's `RedundancyGroup > 0` race. That is a
			// DECISION — the tunnel does not own its zone's RG — and
			// TestBindOnlyTunnelDoesNotOwnTheZoneRG7949 pins it.
		})
		idents = append(idents, egressRowIdentity{
			owner:    base,
			identity: ref,
			isUnit:   dotted && unit != "",
		})
		haveName[ref] = true
		haveDev[dev] = true
	}
	return out, idents
}

// snapshotHasInterfaceRows reports whether this config can produce any
// interface row at all.
//
// It exists because the check is asked at TWO entry points — this wrapper and
// buildInterfaceSnapshotsFrom, which buildSnapshot calls directly — and #7949
// widened it. Widening one copy and not the other produced exactly the split
// this function prevents: the inner builder admitted a config whose only
// interface is a `bind-interface`-only tunnel while the wrapper still returned
// nil for it, so the fix worked through one door and not the other.
// TestBothInterfaceSnapshotEntryPointsAgree7949 asserts the two agree rather
// than pinning either to a literal.
func snapshotHasInterfaceRows(cfg *config.Config) bool {
	if cfg == nil {
		return false
	}
	// A `bind-interface`-only secure tunnel is absent from
	// cfg.Interfaces.Interfaces by definition, so a config whose only interface
	// is one would be refused here before the #7949 synthesis could run. Every
	// config with neither interface stanzas nor such a tunnel still returns
	// false, unchanged.
	return len(cfg.Interfaces.Interfaces) > 0 || bindInterfaceOnlySecureTunnelRefs(cfg)
}

// bindInterfaceOnlySecureTunnelRefs reports whether any authored zone reference
// names a secure tunnel that has no interface stanza.
//
// It exists for ONE reason: buildInterfaceSnapshotsFrom returns nil early when
// `cfg.Interfaces.Interfaces` is empty, and a config whose ONLY interface is a
// `bind-interface`-only tunnel has an empty map. Without this the fix would be
// correct everywhere except the one config shape that consists of nothing but
// the shape it is about. Every config that has neither interface stanzas nor
// such a tunnel still returns nil, byte-identically.
func bindInterfaceOnlySecureTunnelRefs(cfg *config.Config) bool {
	if cfg == nil {
		return false
	}
	for ref := range authoredZoneRefs(cfg) {
		if _, ok := cfg.SecureTunnelNetdevForRef(ref); ok {
			base, _, _ := strings.Cut(ref, ".")
			if cfg.Interfaces.Interfaces[base] == nil {
				return true
			}
		}
	}
	return false
}
