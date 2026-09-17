package userspace

import "strings"

// Which interfaces the userspace dataplane does NOT adjudicate.
//
// Split out of maps_sync.go in #6691 round 8. The predicate is ~20 lines of
// code carrying ~180 lines of rationale — five exclusion classes, each with a
// documented reason and a documented cost — and keeping it inline pushed
// maps_sync.go past the 2000-line refactor threshold on comment alone.
//
// The FILE CREATION (be8aec13e) was a pure move: same body, same signature, no
// caller changes. What the file holds now is NOT — an earlier revision of this
// header said "pure move: no signature, no behaviour and no caller changes" and
// kept saying it after that stopped being true. Since the move, round 8 split
// the predicate in two (userspaceUnbindableNetdev / userspaceSkipsIngressInterface),
// added the refused-netdev index below, and changed behaviour at three call
// sites; round 9 then re-founded that index on ownership. Describe what is here,
// not how it got here.

// userspaceUnbindableNetdev reports whether a row's OWN netdev is one the
// userspace dataplane must never bind an AF_XDP socket to.
//
// #6691 round 8 SPLIT THE EXCLUSION IN TWO, and the split is the fix, not a
// tidy-up. The classes below are properties of the DEVICE — "whatever row asks,
// this netdev may not be bound" — so they are INHERITED by any row that
// redirects its binding onto the device. The classes left in
// userspaceSkipsIngressInterface (a mgmt/control ZONE, a local-fabric ROLE) are
// properties of the ROW, and a sibling row must NOT inherit them.
//
// The distinction is load-bearing in both directions:
//
//   - INHERITED. Under `bind-interface st10` plus a zoned sibling unit
//     (`st10 unit 5 vlan-id 100`, zone trust), the base row `st10` is excluded
//     — it IS the xfrmi — while the unit derives a DIFFERENT if_id
//     (`stIndex<<16 | unit+1`), is correctly SecureTunnel=false, and carries
//     ParentIfindex/ParentLinuxName pointing straight at the live xfrmi. Before
//     this split the child re-admitted its own excluded parent: measured at
//     head, the ingress set was [10 11] with 11 the xfrmi, the RSS allowlist
//     contained "st10", and the Rust planner re-keyed the orphan child onto
//     "st10" and dropped the LAN from 4 planned queues to 1 — the #3091
//     single-worker regression the exclusion exists to prevent, arriving
//     through the child.
//   - NOT INHERITED. A base row in the mgmt zone with a data-zoned VLAN unit
//     (reachable: buildInterfaceZoneMap keys the base off whichever zone entry
//     sorts first, so `security-zone mgmt interfaces ge-0/0/3.0` +
//     `security-zone trust interfaces ge-0/0/3.100` gives base=mgmt,
//     unit=trust) is the ORDINARY case the parent redirect exists for. The
//     trust VLAN's tagged frames arrive on the parent's hardware queues, so
//     the parent's ifindex MUST enter the ingress set or the unit carries no
//     traffic. Inheriting the mgmt exclusion there would be a forwarding
//     regression, not a fix. TestParentRedirectKeepsAMgmtZonedParent is the
//     negative control.
//
// Whether a class can actually DISAGREE between a base row and its unit row is
// a separate question from where the class belongs, and it has to be asked in
// BOTH directions. Round 8 asked only one of them and got the enumeration
// wrong:
//
//   - BASE excluded, UNIT not. SecureTunnel is the only class that reaches
//     this — it is keyed on the if_id, which a base and a non-zero unit
//     necessarily derive differently. This is the F1 direction, and it is what
//     the refused-netdev index below exists for.
//   - UNIT excluded, BASE not. TUNNEL reaches this, and round 8 said it could
//     not: "Tunnel and LocalFabric are read off the same InterfaceConfig by
//     both the base and the unit row" is FALSE of Tunnel, because
//     buildInterfaceSnapshots sets a unit row's flag to
//     `iface.Tunnel != nil || unit.Tunnel != nil` (interfaces.go). A
//     unit-level `tunnel` stanza on a base with no interface-level tunnel —
//     `set interfaces wgN unit 0 tunnel mode wireguard` is the canonical
//     spelling — gives Tunnel=true on the unit and false on the base. That
//     direction is the #6691 round 9 blocker; see userspaceRefusedNetdevs.
//     LocalFabric really is one field copied to both rows, and the fxp/em/lo0
//     arms really do test the BASE name a unit shares. The fab arm is the
//     deliberate exception: configured unresolved fabric bonds carry
//     InterfaceSnapshot.FabricBond and bind through their rows instead.

// TestExclusionClassesAgreeAcrossParentAndChild pins both directions for every
// class, so a new class cannot be added on the wrong side unnoticed and a
// direction cannot go unmeasured again.
func userspaceUnbindableNetdev(iface InterfaceSnapshot) bool {
	return userspaceNetdevExclusionClass(iface) != ""
}

// userspaceNetdevExclusionClass returns the NAME of the first class that
// refuses this row's netdev, or "" when none does.
//
// #6691 round 9 turned the predicate's switch into a NAMED TABLE, and the
// reason is a review finding rather than taste. The enumeration guard that was
// supposed to stop a new class being added on the wrong side —
// TestExclusionClassesAgreeAcrossParentAndChild's coverage assertion — compared
// six hard-coded strings against a hard-coded 6. Adding a production arm could
// not change either value, so the assertion could not fire, and the
// fail-on-revert contract stated in that test's own doc comment was false. A
// count of literals is not a coverage check.
//
// With production enumerating its own classes, the test asserts against THIS
// slice: a new arm that no case names fails, and a case that names a class it
// does not actually trigger fails too. Returning the NAME rather than a bool is
// what makes the second half possible — a positive control can assert WHICH
// class fired, not merely that something did.
func userspaceNetdevExclusionClass(iface InterfaceSnapshot) string {
	for _, class := range netdevExclusionClasses {
		if class.match(iface) {
			return class.name
		}
	}
	return ""
}

// netdevExclusionClass is one reason the userspace dataplane must never bind an
// AF_XDP socket to a row's own netdev. The name is part of the contract: the
// enumeration guard reads it.
type netdevExclusionClass struct {
	name  string
	match func(InterfaceSnapshot) bool
}

// exclusionBaseName is the interface name with any unit suffix removed — the
// string the name-shaped arms test. A unit row SHARES it with its base, which
// is why those classes cannot disagree between the two rows in either
// direction.
func exclusionBaseName(iface InterfaceSnapshot) string {
	base := iface.Name
	if idx := strings.IndexByte(base, '.'); idx >= 0 {
		base = base[:idx]
	}
	return base
}

// netdevExclusionClasses is evaluated in order. Order affects only WHICH name is
// reported, never the boolean, so it is free to read as the switch did.
var netdevExclusionClasses = []netdevExclusionClass{
	{name: "Tunnel", match: func(iface InterfaceSnapshot) bool { return iface.Tunnel }},
	{name: "fxp name", match: func(iface InterfaceSnapshot) bool {
		return strings.HasPrefix(exclusionBaseName(iface), "fxp")
	}},
	{name: "em name", match: func(iface InterfaceSnapshot) bool {
		return strings.HasPrefix(exclusionBaseName(iface), "em")
	}},
	{name: "fab name", match: func(iface InterfaceSnapshot) bool {
		return strings.HasPrefix(exclusionBaseName(iface), "fab") && !iface.FabricBond
	}},
	{name: "lo0 name", match: func(iface InterfaceSnapshot) bool {
		return exclusionBaseName(iface) == "lo0"
	}},
	{name: "SecureTunnel", match: matchesSecureTunnelClass},
}

// matchesSecureTunnelClass is the SecureTunnel class of
// netdevExclusionClasses.
//
// #5619: an IPsec secure tunnel is NOT adjudicated by the userspace
// dataplane, and this arm says so out loud.
//
// KEYED ON OWNERSHIP OR DEVICE KIND, NEVER ON NAME SHAPE (#6691
// rounds 5 and 8). The row's SecureTunnel flag is set by the snapshot
// builder from snapshotSecureTunnel, which is the union of two facts:
// some `security ipsec vpn <name> bind-interface` NAMES this row's
// device (Config.SecureTunnelNetdevForRef), OR the netdev this row
// resolves to has kernel link kind `xfrm` (liveXfrmNetdevs, round 8 —
// the half that sees a live xfrmi the config no longer describes). So
// this arm excludes exactly the interfaces that ARE route-based IPsec
// tunnel devices, by configuration or by kernel fact.
//
// It used to test config.IsSecureTunnelIfName(base), which is a
// LEXICAL predicate: `st` followed by an index in [0, 65536). Nothing
// reserves the `st` prefix — schema_interfaces.go accepts a wildcard
// interface name — so
//
//	set interfaces st5 unit 0 family inet address 192.0.2.1/24
//	set security zones security-zone trust interfaces st5.0
//
// is a valid config naming a real physical NIC with no VPN anywhere,
// and the lexical arm dropped it out of adjudication, out of the
// AF_XDP binding plan and out of the RSS allowlist. That is the
// traffic outage the previous revision of this comment named while
// causing it. TestUnownedStNameKeepsItsDataplaneRole pins both
// directions of the ownership rule — the unowned `st5` keeps its role,
// and an `st5` a VPN binds still loses it.
//
// The lexical predicate is still right for LEXICAL questions —
// SecureTunnelUnitNetdev uses it to resolve `st<N>.<unit>` to a netdev
// name — and remains the classifier the constructor-agreement guard
// pins. It is only wrong as an OWNERSHIP test, which is what this arm
// asks.
//
// Route-based IPsec decrypts in the KERNEL XFRM stack, which delivers
// the plaintext on the xfrmi netdev (xfrmi_rcv_cb sets skb->dev, then
// xfrm_input -> gro_cells_receive -> __netif_receive_skb_core). The
// userspace dataplane has no path to hand a plaintext frame back INTO
// an xfrmi for the egress direction, so it cannot own this interface
// end-to-end yet.
//
// Until it can, the xfrmi must stay out of the dataplane sets THIS
// PREDICATE GATES — and only those. There are FOUR call sites, not
// three (#6691 round 8 corrected the count; the earlier text listed
// the three that CHANGE an installed set and silently dropped the
// other two consumers):
//
//  1. buildUserspaceIngressIfindexes  — the ingress-adjudication map.
//  2. UserspaceBoundLinuxInterfaces   — the RSS/AF_XDP allowlist
//     (interfaces.go), name-keyed.
//  3. snapshotBindingPlanKey          — the plan-key HASH. Excluding
//     the row here is what keeps the
//     key from churning when a
//     tunnel appears or moves.
//  4. buildUserspaceIngressBindingAliases — INERT for the xfrmi's own
//     row (an xfrmi has no parent
//     ifindex, so the ParentIfindex
//     guard skips it first). It is
//     NOT inert for the redirect
//     that names the xfrmi as a
//     PARENT, which is why it now
//     consults the refused-netdev
//     index like the other two
//     set-changing sites.
//
// Each of the three set-changing sites can be handed this netdev by a
// row that is NOT this row — a zoned sibling unit redirecting onto its
// parent. userspaceRefusedNetdevs (below) is what makes the refusal
// travel with the NETDEV instead of stopping at the row.
//
// THE CALLER LIST IS NOT AN ENUMERATION OF THE SETS. Round 8 wrote
// that "the sites enumerated above cannot be re-entered sideways" and
// bounded its own work by "a redirect can only launder within the sets
// the predicate gates, so the sites are the predicate's callers per
// plane". Both sentences are false, and the counter-example is the
// FABRIC loop: buildUserspaceIngressIfindexes and
// UserspaceBoundLinuxInterfaces each finish with a `snapshot.Fabrics`
// pass that pushes fab.ParentIfindex / fab.ParentLinuxName
// UNCONDITIONALLY — it asks neither this predicate nor the index — and
// Rust replan_queues' fabric loop did the same. Measured with
// `set interfaces fab0 fabric-options member-interfaces gr-0/0/3` and an
// interface-level tunnel on gr-0/0/3: the refused netdev was in the
// ingress set AND in the RSS allowlist.
//
// Round 9 CLOSED all four of those loops (#6998) rather than deferring
// them, because round 8 also made the gap REACHABLE: the kernel-kind half
// refuses a device for what it IS, so a slot-shaped `ge-0/0/0` created out
// of band is both refused and a legal fabric member. The pre-round-8
// "not reachable" reasoning — LocalFabricMember resolves only for
// slot-shaped names, so an `st*` member yields no fabric row — answered a
// question about the NAME-keyed exclusion and did not survive the change
// that keyed it on device kind. The correction that matters for a future
// reader: to bound a laundering question, enumerate every CONTRIBUTOR to
// the set, not every caller of the predicate.
//
// AND ROUND 9 CLOSED THEM WITH THE WRONG INSTRUMENT, which is worth
// keeping visible because the loops READ correct after that round and
// were not. Each loop asked userspaceRefusedNetdevs about the parent
// netdev — but that index was built from interface ROWS, and the very
// example above (`fabric-options member-interfaces ge-0/0/0`) names a
// member that needs no interface stanza. Asking a row-derived index
// about an ownerless netdev returns "not refused", so all four loops
// asked the right question of an oracle that could not answer it, and
// an unbindable ownerless parent went through unchanged. Round 10 fixed
// the ORACLE (fabricParentUnbindable, tallied by
// buildUserspaceRefusedNetdevs) rather than the loops, which are
// unchanged and now correct. Enumerating the contributors is necessary;
// it is not sufficient unless each contributor also gets a VOTE.
//
// The AF_XDP binding PLAN itself is gated on the Rust side by the
// mirrored include_userspace_binding_interface (userspace-dp), off the
// secure_tunnel flag this row carries — not by a fifth Go call site.
// Its own orphan-VLAN redirect is closed the same way, by
// snapshot_refuses_parent_netdev (server/helpers/planning.rs).
//
// SCOPE, stated because the narrower truth matters: this predicate does
// NOT make the xfrmi invisible to the dataplane generally. Once #5619
// made its ifindex resolve, the tunnel DOES enter the Rust
// forwarding-state maps gated on `ifindex > 0` rather than on this
// predicate — `populate_interfaces`
// (userspace-dp/src/afxdp/forwarding_build/interfaces.rs), hence
// `name_to_ifindex` and the zone map.
//
// It does NOT enter the EGRESS map: `populate_egress` needs a source
// MAC (own, parent's, or the tunnel flag), and an xfrmi is ARPHRD_NONE
// with no parent and no tunnel flag, so the row hits `None => continue`
// and no EgressInterface is built. Nor does an authored `next-hop
// st0.0` resolve: it reaches `parse_route_next_hop` as the bare string
// `"st0.0"`, which returns `(None, None)` and leaves the target at
// `(0, 0)` on both revisions — an earlier version of this comment
// claimed both of those, and both were wrong.
//
// AND IT MOVES A TX DISPOSITION — an earlier version of this comment
// claimed otherwise ("the TX dispatcher drops it as
// missing_egress_binding either way"). That was WRONG: a LAN->tunnel
// packet never reaches the TX dispatcher, because the FIB claims it
// first. Measured end to end, real Go wire snapshot -> real Rust FIB,
// `next-hop <gw-in-tunnel-subnet>`:
//
//	bind-interface st0    : MissingNeighbor before AND after
//	bind-interface st0.0  : NoRoute before -> MissingNeighbor after
//
// Both spellings are ONE tunnel (same if_id, same unit ref `st0.0`),
// so this is a CONVERGENCE onto what the canonical bare spelling
// already did — the divergence WAS the name bug. It is still
// operator-visible, because the two arms differ: `NoRoute` reinjects
// to the kernel unconditionally, while `MissingNeighbor` resolves zone
// ids and evaluates policy first, and a DENY exits before the reinject
// gate.
//
// A PERMIT does NOT currently rescue it, and saying otherwise was the
// review finding: with no EgressInterface (above) the to-zone reads 0,
// and `evaluate_policy_result_l3_aware` refuses to match any rule —
// exact, wildcard OR junos-global — when either zone id is 0, so the
// flow takes the default action. That MAC-less-egress zone resolution
// is a PRE-EXISTING defect (#6713) fixed by #6722; only once #6722
// lands does a matching `from-zone <lan> to-zone <tunnel-zone> permit`
// preserve delivery here. Until then the dotted spelling converges onto
// the bare spelling's disposition — which is the point, the bare
// spelling being what master already did — but it converges onto a
// currently-denying one.
// TestSecureTunnelSpellingsAgreeOnForwardingInputs pins the
// convergence.
//
// Widening this exclusion to cover those maps would ALSO drop the
// zone-map entry, and an interface absent from the zone map resolves
// to zone_id 0 — which, per the guard just cited, matches nothing and
// falls to the default action, so it would trade an adjudicated
// disposition for an unadjudicable one.
//
// WHY ADMITTING IT IS WORSE, in the order the reasons can actually be
// ESTABLISHED (#6691 round 8). An earlier revision of this comment led
// with a claim it could not support, and a review leg was right to
// refuse it.
//
//  1. IT BINDS A NETDEV THE DATAPLANE CANNOT TRANSMIT INTO. An xfrm
//     interface has exactly ONE RX queue: `ip -d link` reports
//     `numrxqueues 1` and `/sys/class/net/<if>/queues` holds a single
//     `rx-0` (measured in a netns). That single queue is what
//     userspaceRXQueueCount reads and ships. Admitting it mints an
//     AF_XDP binding on a netdev with no egress path back from this
//     dataplane, and spends a slot against MAX_BINDING_SLOTS.
//
//     BEFORE #7497 the harm was GLOBAL: the Rust planner took the
//     MINIMUM queue count across every candidate
//     (replan_bindings_from_candidates, planning.rs), so ONE zoned
//     xfrmi dragged every physical interface on the box down to one
//     queue and one worker — the #3091 ~6 Gbps single-worker regression
//     by a different route. #7497 gave each interface its own
//     min(rx_queues, 16), so the tunnel now costs one binding and no
//     other interface's queue count moves. The guard named
//     secure_tunnel_would_collapse_the_global_queue_count was retired
//     with that change (it had become true with the exclusion deleted);
//     secure_tunnel_adds_nothing_to_the_binding_plan and
//     binding_candidate_excludes_secure_tunnel are the live
//     fail-on-revert guards (userspace-dp/src/main_tests.rs).
//
//  2. AND IT CANNOT BE HALF-ADMITTED. "Adjudicate but do not bind" is
//     not available: an ifindex in the shim's ingress map with no READY
//     binding takes drop_degraded_transit
//     (userspace-xdp/src/lib.rs, BINDING_MISSING). The ingress map and
//     the binding plan move together or transit dies, which is why this
//     one predicate gates both.
//
// NOT CLAIMED, deliberately: that an XSK cannot come up on an xfrmi at
// all. ZERO-COPY plainly cannot (no ndo_bpf / ndo_xsk_wakeup), but
// zero-copy is not required for every socket role — XskSocketRole::
// Private returns false from requires_zerocopy, a generic-XDP interface
// is offered COPY_ONLY_BIND_FLAGS, and a failed shared-UMEM group falls
// back to a private socket automatically. A copy-mode binding is
// REACHABLE in that code; whether it succeeds on an ARPHRD_NONE netdev
// needs a live NIC and is untested. Reason 1 does not depend on it.
//
// THE COST IS REAL AND IS NOT A DROP. Decrypted plaintext traverses
// Linux routing with NO xpf zone policy — see "What actually changes"
// in the PR and #6700. That gap is what this arm buys the throughput
// with; it is not what it prevents.
//
// Before #5619 this exclusion was an ACCIDENT for ONE spelling ONLY.
// snapshotLinuxName collapsed unit 0, so `bind-interface st0.0`
// resolved to the nonexistent netdev `st0`, carried ifindex 0 and fell
// out of these sets on the `Ifindex <= 0` guard. `bind-interface st0`,
// `st10.5` and `st0.7` all resolved to REAL ifindexes and were fully
// adjudicated and RSS-bound — measured, not inferred. So this arm is
// NEW behaviour for three of the four spellings, not a preserved
// accident: it is what stops a route-based tunnel from collapsing the
// AF_XDP binding plan onto a single XSK on a virtual netdev. Do not
// delete it as inert.
//
// The consequence is real and operator-visible: decrypted IPsec
// plaintext traverses Linux routing with NO xpf zone policy. That is
// #5619's open half. Deleting this arm without building the egress
// path re-opens the drop described above.
func matchesSecureTunnelClass(iface InterfaceSnapshot) bool {
	return iface.SecureTunnel
}

func userspaceSkipsIngressInterface(iface InterfaceSnapshot) bool {
	// The DEVICE half — inherited by any row that redirects onto this netdev.
	if userspaceUnbindableNetdev(iface) {
		return true
	}
	// The ROW half. Both classes below describe what THIS row is for, not what
	// its netdev is, so a sibling row on the same netdev does not inherit them.
	switch iface.Zone {
	case "mgmt", "control":
		return true
	}
	if iface.LocalFabric != "" {
		return true
	}
	return false
}

// userspaceOwnsItsNetdev reports whether a row's AF_XDP binding would land on
// its OWN netdev — i.e. the row is not a VLAN child redirecting onto a parent.
//
// It is the "which rows speak for this netdev" relation behind
// userspaceRefusedNetdevs, and it is deliberately expressed through
// userspaceBindTargetNetdev (the #2917 SSOT) rather than restating the VLAN
// test: a VLAN child's LinuxName is the CHILD netdev, so the child says nothing
// about whether the PARENT netdev may be bound. Rust's
// snapshot_refuses_parent_netdev carries the identical qualifier
// (`vlan_child_parent_netdev(p, &p_linux).is_none()`), so the two planes select
// the same rows by the same sentence.
//
// A LogicalOnly row is a bondless RETH VLAN unit, so it is a VLAN child by
// construction (shouldUseLogicalOnlyParentBoundRethVLAN requires unit.VlanID > 0
// and a parent netdev whose name differs) and this relation already excludes it.
// Round 8 carried a separate `!iface.LogicalOnly` clause for the same reason and
// a review round was right that nothing could distinguish it: it was not merely
// unbound, it was redundant with the rule above it.
// TestLogicalOnlyRowNeverOwnsANetdev pins that, so the redundancy is a measured
// fact and not this comment's assertion.
func userspaceOwnsItsNetdev(iface InterfaceSnapshot) bool {
	return userspaceBindTargetNetdev(iface) == iface.LinuxName
}

// userspaceRefusedNetdevs indexes — by ifindex AND by Linux name — every netdev
// that the userspace dataplane must never bind an AF_XDP socket to, judged
// across ALL the rows that own it.
//
// #6691 round 8. It exists because three of the four sets the exclusion gates
// let a row contribute a netdev that is NOT its own: a VLAN child binds its
// physical parent (#2917), so it emits the parent's ifindex into the ingress
// map, the parent's NAME into the RSS allowlist, and a child→parent entry into
// the binding aliases. Each of those is a way for a row to hand the dataplane a
// netdev a DIFFERENT row already failed the predicate for. Asking the row-level
// predicate again at each site cannot catch it — the child passes it. The
// question at a redirect is about the TARGET netdev, so the answer has to be
// indexed by netdev.
//
// EVERY OWNER, NOT ANY OWNER (#6691 round 9, and this is the correctness half).
// Round 8 refused a netdev as soon as ANY row was unbindable for it, which reads
// a DISAGREEMENT between two rows as a refusal. Rows do disagree — a unit row's
// Tunnel flag is `iface.Tunnel != nil || unit.Tunnel != nil`, and a unit-0 row
// with no vlan-id resolves to the BASE netdev — so
//
//	set interfaces wg1408 unit 0 tunnel mode wireguard
//
// (the canonical WireGuard spelling: verbatim in pkg/config/tunnelid_test.go and
// in an operator config in docs/issues/issue-history.md) puts an unbindable
// `wg1408.0` row and a bindable `wg1408` base row on ONE netdev. Round 8 refused
// it, and the base row's own name being in the index took the base row out of
// the RSS allowlist — measured, head vs master: allowlist `[ge-0-0-0]` where
// master had `[ge-0-0-0 wg1408]`. The same shape on a `ge-*` NIC additionally
// dropped its VLAN unit out of the ingress-adjudication map (`[10 30]` vs
// `[10 30 31]`) and its child→parent alias, and an ifindex absent from
// userspace_ingress_ifaces leaves the adjudicated path entirely
// (cpumap_or_pass, userspace-xdp/src/lib.rs) with syncInterfaceAttachments
// detaching XDP/TC from it.
//
// The question this index answers is "is this netdev, AS A DEVICE, one we must
// never bind?" — and a device cannot be both. When the owners disagree, at least
// one of them is an ordinary data interface, and that one will contribute the
// netdev to the binding plan on its own account whatever the redirect does.
// Refusing on a disagreement therefore cannot prevent the binding; it can only
// strip traffic from rows that were entitled to it. So the rule is: refuse only
// when every owner agrees.
//
// WHICH MAKES THE OWNER SET THE WHOLE CORRECTNESS ARGUMENT (#6691 round 10). A
// unanimity rule over an EMPTY bucket answers "not refused", which is right when
// it means "nothing emits this netdev" and catastrophic when it means "something
// emits it and I did not count that something". Round 9 built the tally from
// interface rows only, and a FABRIC MEMBER NEEDS NO INTERFACE STANZA:
//
//	set interfaces fab0 fabric-options member-interfaces ge-0/0/0
//
// emits ge-0-0-0's ifindex into the ingress-adjudication map and its name into
// the RSS allowlist with zero rows owning it, so an ownerless unbindable parent
// — a live xfrmi under a slot-shaped name, the reachable case — passed both
// loops on both planes. Measured at 4cf507638 with that config plus a live-xfrm
// ge-0-0-0: `rows OWNING ge-0-0-0: 0`, `refusesName = false`, and the netdev in
// both sets.
//
// The fix is NOT a fourth conjunct. It is that the owner set was wrong: an
// emitted fabric parent IS an owner, so it is tallied like one, carrying the
// verdict fabricParentUnbindable computed for it. Every contributor to the sets
// is now a voter in the unanimity, which is the property that makes "refuse only
// when every owner agrees" safe rather than merely conservative.
//
// ONE DEVICE, ONE VERDICT (#6691 round 11). Round 10 made the fabric parent an
// owner UNCONDITIONALLY, which is right where the bucket was empty and wrong
// where it was not: on a member that also has an interface stanza it put two
// owners on one device, computing their verdicts from different evidence, and
// every way of making those two disagree became a fail-open (a canonical alias
// and a re-sampled kernel were both reachable). The fabric now votes only where
// no row does — see snapshotNetdevVotes, which is also where the owner set and
// the protocol gate's scope are settled together.
//
// F1 IS PRESERVED EXACTLY, and it survives on the ownership half rather than on
// a special case. Under `bind-interface st10` with a zoned sibling
// `st10 unit 5 vlan-id 100`, the only row whose LinuxName is `st10` is the base
// xfrmi row — the sibling resolves to `st10.100` — so the bucket is a single
// unbindable owner and `st10` stays refused. Under `bind-interface st10` with a
// unit-0 sibling, BOTH rows resolve to `st10` and BOTH are SecureTunnel (the
// unit inherits the ownership through Config.SecureTunnelNetdevForRef, and the
// live-xfrmi half sees the same device), so the bucket is unanimous and the
// netdev stays refused there too. Measured in
// TestRefusedNetdevNeedsEveryOwnerToAgree.
//
// A COROLLARY WORTH KNOWING: for a row that owns its own netdev the refusal is
// now structurally unreachable. Such a row only reaches a refusal check after
// passing userspaceSkipsIngressInterface, and unbindable ⇒ skipped, so the row
// is a bindable owner of its own bucket and the bucket cannot be unanimous.
// The index can therefore only ever fire through a REDIRECT — which is the
// property round 8 claimed and did not have. It also puts the Go rule in the
// same shape as Rust's binding_target_is_refused, whose non-VLAN arm is the
// literal constant `false`.
//
// BOTH keys are needed, and neither is redundant: the ingress map and the
// aliases are ifindex-keyed, while the RSS allowlist is name-keyed and is
// derived (UserspaceBoundLinuxInterfaces) without resolving ifindexes at all.
//
// WHICH CONSUMERS THE INDEX CAN ACTUALLY FIRE FOR. Two of the three
// set-changing sites are live on reachable configs; the binding-alias table
// (buildUserspaceIngressBindingAliases, maps_sync.go) is INERT — and round 8
// said so having checked only ONE of the six exclusion classes, which a review
// round was right to reject. It was in fact LIVE at that revision: on
// `set interfaces ge-0/0/5 unit 0 tunnel ...` with a zoned
// `unit 100 vlan-id 100`, severing that guard alone changed the alias table
// from map[] to map[31:30] (measured). That reachability was the round-9
// blocker, not a feature, and it is gone with it — the netdev there has a
// bindable owner and is no longer refused at all. Re-checked per class, since
// one class is not an enumeration:
//
//   - Tunnel, fxp/em/fab/lo0 name. A VLAN child INHERITS the parent's exclusion
//     (the name arms read the shared base name; the Tunnel flag ORs the
//     parent's), so the child is dropped by userspaceSkipsIngressInterface
//     before that loop consults the index.
//   - LocalFabric, mgmt/control. Not device-level at all, so the parent never
//     enters this index and there is nothing to ask.
//   - SecureTunnel. The child does NOT inherit — that is the F1 mechanism — but
//     its own netdev is `st<N>.<vlan>`, which the xfrmi reconciler never creates
//     and which the kernel cannot create as a VLAN on an ARPHRD_NONE parent. It
//     reports ifindex 0 and the `Ifindex <= 0` guard drops it first.
//
// That guard is retained because the invariant is about the SITE, not about
// today's reachability: if a child netdev ever does resolve there — which is
// exactly what #5619 did for three of the four secure-tunnel spellings — the
// alias table must not become the one place the refusal is not asked.
// TestAliasTableRefusesEvenWhenTheChildNetdevResolves constructs that state
// directly and is the fail-on-revert guard.
//
// Scope: built from the CONTRIBUTORS to the gated sets, which snapshotNetdevVotes
// enumerates ONCE for every consumer. For the VLAN redirect the coverage is
// automatic: every unit row's parent netdev is the base row's netdev, and a unit
// exists only under a base in cfg.Interfaces.Interfaces, so a redirect target
// always has a row. For the FABRIC loops it took round 10 to become true; see
// fabricParentUnbindable. A THIRD contributor added later joins by joining that
// enumeration — which is also what puts it in the protocol gate's scope, so the
// two cannot drift the way they did in round 10.
type userspaceRefusedNetdevs struct {
	ifindex map[int]struct{}
	name    map[string]struct{}
}

// netdevOwnerTally counts, for one netdev key, how many contributors speak for
// it and how many of those call it unbindable.
//
// A key is refused only when the two are EQUAL AND NON-ZERO. The zero-owner case
// falls through to "not refused" deliberately, and that is safe only because
// every contributor registers as an OWNER before it can call a netdev
// unbindable — so a key present in this map always has owners >= 1. Round 10
// made that true for the fabric parent (fabricParentUnbindable); before it, a
// fabric member named with no interface stanza reached here with owners == 0 and
// fell through fail-OPEN. A future contributor that records unbindable WITHOUT
// recording ownership reopens exactly that hole, which is why the ownership and
// the verdict are declared together in snapshotNetdevVotes rather than at the
// call sites.
type netdevOwnerTally struct {
	owners     int
	unbindable int
}

func (t netdevOwnerTally) refused() bool {
	return t.owners > 0 && t.owners == t.unbindable
}

// netdevVoteRole says how a contributor's verdict is counted.
type netdevVoteRole uint8

const (
	// netdevVoteAbstains — this contributor hands the dataplane the netdev (or
	// speaks about it) but casts no verdict on it. A VLAN child abstains about
	// its PARENT: it binds the parent, so it says nothing about whether the
	// parent may be bound.
	netdevVoteAbstains netdevVoteRole = iota
	// netdevVoteOwner — speaks for the netdev on its own account.
	netdevVoteOwner
	// netdevVoteFallback — speaks only where no owner does.
	netdevVoteFallback
)

// netdevVote is one contributor's evidence about one netdev: who speaks for it,
// what they say, and whether saying it needs a protocol version.
//
// #6691 round 11. It exists because round 10 added a SECOND producer of netdev
// verdicts (the fabric parent) and had to remember to teach every consumer about
// it — the tally learned, the required-protocol gate did not, and the gate that
// exists to stop an under-version helper staying armed was silent for exactly
// the verdict the version bump was for. A hand-maintained second list is the
// defect, not the omission: the repair is that ONE enumeration answers "who
// contributes a netdev verdict", and both the tally and the gate read it.
type netdevVote struct {
	name    string
	ifindex int
	role    netdevVoteRole
	// unbindable is this contributor's device-level verdict.
	unbindable bool
	// verdictNeedsProtocol is true when this contributor's unbindable verdict
	// reaches the helper ONLY as a snapshot field introduced by a protocol
	// bump, so a helper that predates the field cannot reproduce the decision
	// from the bytes it does read. It is what scopes
	// ensureSecureTunnelProtocolLocked, and each contributor declares it for
	// itself — a contributor that ships a new verdict field and leaves this
	// false is the round-10 regression again.
	verdictNeedsProtocol bool
}

// counted reports whether this vote lands in a netdevOwnerTally — i.e. whether
// its unbindable verdict participates in the unanimity that decides refusal.
//
// It exists so the ROLE axis of that filter has exactly one definition. The
// tally applies it and the #6691 enumeration guard reads it, so a change to
// which roles count moves the guard with it instead of leaving the guard
// asserting a rule the tally no longer follows — the hand-maintained second
// list this type's doc names as the defect. It single-sources the role test
// ONLY: the per-key `name != ""` and `ifindex > 0` guards in
// buildUserspaceRefusedNetdevs are separate and stay separate.
func (v netdevVote) counted() bool { return v.role != netdevVoteAbstains }

// snapshotNetdevVotes enumerates every contributor to the sets the binding
// exclusion gates, with the verdict each one casts.
//
// THE FABRIC IS A FALLBACK VOTER, NOT A CO-VOTER (#6691 round 11), and that is
// the correctness half. Round 10 made the fabric parent an owner unconditionally,
// which puts TWO owners on one device whenever the member also has an interface
// stanza — and those two owners compute their verdicts from different evidence,
// so they can DISAGREE about one device. The unanimity rule reads a disagreement
// as an admission, so every way of making them disagree is a fail-OPEN:
//
//   - CANONICAL ALIASES. `fabric-options member-interfaces gr-0/0/3` with the
//     stanza authored `gr-0-0-3` is one netdev under two authored names, both
//     legal (the member MUST be slash-spelled for InterfaceSlot to resolve it;
//     the stanza name is a wildcard). The row voted unbindable on its `tunnel`
//     stanza and the fabric's exact map lookup missed it and voted bindable, so
//     the GRE device was admitted. Round 9, with no fabric vote at all, refused
//     it correctly.
//   - SAMPLING. The fabric rows and the interface rows are judged against one
//     kernel xfrm sample at build time, but SyncFabricState rebuilt the fabric
//     rows alone; see alignFabricVerdicts (fabric.go).
//
// Both were fixed at their source, and neither fix is what makes this safe: a
// third way for one device's two owners to disagree would be a third fail-open.
// The invariant is that A DEVICE HAS ONE VERDICT, so where a row already speaks
// for the netdev the fabric does not vote at all, and where none does the
// fabric's vote is the only one and unanimity is over a bucket of one. That
// preserves round 9's rule exactly for row-owned netdevs and round 10's fix
// exactly for ownerless ones, and it is never less refusing than either:
// suppressing a bindable fabric vote can only turn "not refused" into "refused".
//
// The same walk answers the PROTOCOL question, which is what stops the two
// scopes drifting again: a fabric verdict needs the wire only where it is
// load-bearing, and a row's secure-tunnel flag needs it always — Rust's
// include_userspace_binding_interface reads that flag PER ROW, so it changes the
// row's own admission whether or not the row owns a netdev anyone else contests.
func snapshotNetdevVotes(snap *ConfigSnapshot) []netdevVote {
	if snap == nil {
		return nil
	}
	owned := make(map[string]struct{}, len(snap.Interfaces))
	votes := make([]netdevVote, 0, len(snap.Interfaces)+len(snap.Fabrics))
	for _, iface := range snap.Interfaces {
		role := netdevVoteAbstains
		if userspaceOwnsItsNetdev(iface) {
			role = netdevVoteOwner
			if iface.LinuxName != "" {
				owned[iface.LinuxName] = struct{}{}
			}
		}
		votes = append(votes, netdevVote{
			name:       iface.LinuxName,
			ifindex:    iface.Ifindex,
			role:       role,
			unbindable: userspaceUnbindableNetdev(iface),
			// The v5 field. Present on the row => an older helper plans a
			// binding this control plane refuses, independently of any tally.
			verdictNeedsProtocol: iface.SecureTunnel,
		})
	}
	// The rows are walked first so `owned` is complete before any fabric vote is
	// classified.
	for _, fab := range snap.Fabrics {
		if fab.ParentLinuxName == "" {
			// Nothing is emitted for a parent with no netdev (both fabric loops
			// guard on the name/ifindex), so there is nothing to judge.
			continue
		}
		_, hasOwner := owned[fab.ParentLinuxName]
		role := netdevVoteFallback
		if hasOwner {
			role = netdevVoteAbstains
		}
		votes = append(votes, netdevVote{
			name:       fab.ParentLinuxName,
			ifindex:    fab.ParentIfindex,
			role:       role,
			unbindable: fab.ParentUnbindable,
			// The v7 field, and only where it decides something: with an owning
			// row present the helper reaches the same verdict from the row's own
			// pre-v7 fields, so arming there would abort a commit over a
			// difference that does not exist.
			verdictNeedsProtocol: fab.ParentUnbindable && !hasOwner,
		})
	}
	return votes
}

// snapshotRequiresRefusalProtocol reports whether this snapshot carries an
// unbindable verdict that a helper predating the current protocol cannot
// reproduce — the scope of ensureSecureTunnelProtocolLocked.
//
// Derived from snapshotNetdevVotes rather than from its own walk of the
// snapshot: the enumeration that decides which contributors have a verdict is
// the enumeration that decides which verdicts need the wire, so a contributor
// cannot be in one and out of the other.
func snapshotRequiresRefusalProtocol(snap *ConfigSnapshot) bool {
	for _, vote := range snapshotNetdevVotes(snap) {
		if vote.verdictNeedsProtocol {
			return true
		}
	}
	return false
}

// snapshotRequiresFabricBondProtocol reports whether the snapshot carries the
// positive bond-fabric admission bit. Helpers below its feature floor retain
// the old fab-name exclusion and cannot reproduce the bond-master target.
func snapshotRequiresFabricBondProtocol(snap *ConfigSnapshot) bool {
	if snap == nil {
		return false
	}
	for _, iface := range snap.Interfaces {
		if iface.FabricBond {
			return true
		}
	}
	return false
}

func buildUserspaceRefusedNetdevs(snap *ConfigSnapshot) userspaceRefusedNetdevs {
	byName := make(map[string]netdevOwnerTally)
	byIfindex := make(map[int]netdevOwnerTally)
	for _, vote := range snapshotNetdevVotes(snap) {
		if !vote.counted() {
			continue
		}
		if vote.name != "" {
			tally := byName[vote.name]
			tally.owners++
			if vote.unbindable {
				tally.unbindable++
			}
			byName[vote.name] = tally
		}
		if vote.ifindex > 0 {
			tally := byIfindex[vote.ifindex]
			tally.owners++
			if vote.unbindable {
				tally.unbindable++
			}
			byIfindex[vote.ifindex] = tally
		}
	}
	out := userspaceRefusedNetdevs{
		ifindex: make(map[int]struct{}),
		name:    make(map[string]struct{}),
	}
	for name, tally := range byName {
		if tally.refused() {
			out.name[name] = struct{}{}
		}
	}
	for ifindex, tally := range byIfindex {
		if tally.refused() {
			out.ifindex[ifindex] = struct{}{}
		}
	}
	return out
}

func (r userspaceRefusedNetdevs) refusesIfindex(ifindex int) bool {
	if ifindex <= 0 {
		return false
	}
	_, refused := r.ifindex[ifindex]
	return refused
}

// refusesNetdev answers the refusal question for a netdev a caller knows BOTH
// identities of, and it is the form every such caller must use (#6691 round 16).
//
// THE TWO KEYS ARE NOT POPULATED FROM THE SAME EVIDENCE. buildUserspaceRefusedNetdevs
// gives a netdev a NAME bucket from any counted vote that carries a name, but an
// IFINDEX bucket only from a vote whose own `buildLinkSnapshot` resolved
// (`vote.ifindex > 0`, snapshotNetdevVotes). A snapshot is not one netlink
// sample: buildInterfaceSnapshots takes one per base row AND a second per unit
// row for that unit's parent (interfaces.go), buildFabricSnapshotsFrom takes its
// own (fabric.go), and SyncFabricState refreshes the fabric rows ALONE and
// persists them back into m.lastSnapshot beside interface rows that were never
// re-sampled (persistResolvedFabricsLocked, manager_ha.go). So one netdev can be
// named by a row whose lookup MISSED — no ifindex bucket — while a sibling row
// or fabric row carries its LIVE ifindex.
//
// A DIVERGENCE BETWEEN THE TWO KEYS IS ALWAYS A BUG, which is why this is one
// predicate and not a convention. The refusal decides two things that must
// agree: whether a netdev enters the ingress-adjudication map (Go) and whether
// the AF_XDP planner binds it (Rust). The Rust side asks by NAME with no ifindex
// filter — snapshot_refuses_parent_netdev walks owning rows on the name, and
// binding_target_is_refused routes a VLAN child's bind target through it
// (server/helpers/planning.rs) — and so does UserspaceBoundLinuxInterfaces, the
// RSS allowlist. An ifindex-only reader therefore admitted a netdev to
// adjudication that every name-keyed reader had refused, and an ifindex in the
// ingress map with NO READY binding is drop_degraded_transit (BINDING_MISSING):
// transit on that netdev drops.
//
// Measured at 76045dfae, before this round, on a snapshot whose fabric row had
// been refreshed past its interface row:
//
//	rows  : {gr-0-0-3, ifindex 0, tunnel}  fabric: {gr-0-0-3, parent ifindex 20}
//	Go    : ingress [20]        Rust: planned bindings {}
//
// and on one whose VLAN child's parent lookup outran its base row's:
//
//	rows  : {ge-0-0-5, ifindex 0, tunnel}, {ge-0-0-5.100, ifindex 12, parent 11}
//	Go    : ingress [11 12], alias 12->11   Rust: planned bindings {}
//
// Adding the name key is a strict tightening AT THESE SITES: it can only stop a
// loop from ADDING a key, never remove one another reader put there, and what it
// stops adding is exactly the set the binding planner already refuses.
//
// A caller holding only a name (UserspaceBoundLinuxInterfaces' bind-target arm,
// which is name-keyed by contract because `ethtool` consumes names) still asks
// refusesName directly — there is no ifindex to bring.
func (r userspaceRefusedNetdevs) refusesNetdev(name string, ifindex int) bool {
	return r.refusesIfindex(ifindex) || r.refusesName(name)
}

func (r userspaceRefusedNetdevs) refusesName(name string) bool {
	if name == "" {
		return false
	}
	_, refused := r.name[name]
	return refused
}
