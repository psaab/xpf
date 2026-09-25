package userspace

import (
	"time"

	"github.com/psaab/xpf/pkg/config"
)

const (
	// ProtocolVersion is the config-snapshot wire contract version. It is
	// the Go mirror of CONFIG_SNAPSHOT_PROTOCOL_VERSION
	// (userspace-dp/src/protocol/control.rs) and the two MUST be bumped in
	// lockstep: both apply_snapshot and bump_fib_generation gate on EXACT
	// equality, so a helper at a different version refuses the snapshot
	// outright rather than decoding it under the wrong contract.
	//
	// v4 (#5488): a scoped GLOBAL policy carries its zone SCOPE as a zone
	// SET in the plural match_from_zones/match_to_zones fields, and those
	// fields are AUTHORITATIVE. The singular match_from_zone/match_to_zone
	// fields carry only the FIRST element (config.ScopeSingular).
	//
	// #4626 added the plural fields as purely ADDITIVE JSON without bumping
	// this constant, which made the version handshake lie: a pre-#4626
	// helper advertising the same version 3 ignores fields it does not know
	// and reads ONLY the singular field, so a global `deny` scoped
	// `[dmz trust] -> untrust` silently NARROWS to `dmz -> untrust` and the
	// trust-sourced traffic the operator denied is evaluated by lower
	// precedence rules instead — a rolling-upgrade fail-OPEN. A
	// compatibility extension that changes deny/reject COVERAGE must not be
	// silently ignorable under an unchanged protocol version.
	//
	// The bump alone only makes an old helper REFUSE the snapshot (it keeps
	// forwarding its previous-good image), so it is paired with the
	// ensureScopedGlobalZoneSetProtocolLocked required-protocol gate in
	// manager_compile.go, which DISARMS the helper and aborts the commit
	// when the running helper is too old to represent a multi-zone scope.
	//
	// v5 (#6722): the per-interface EGRESS zone is decided by the Go builder
	// and carried in InterfaceSnapshot.EgressZone; the reth_projection field
	// that the previous contract carried is GONE. This is a field DELETION
	// paired with an addition, so unlike an additive field it cannot ride an
	// unchanged version: at v4 two binaries built either side of this change
	// both advertise 4 and interpret the same bytes differently, and nothing
	// on the wire distinguishes them.
	//
	// The mixed pairing is not merely "not yet fixed", which is why the bump
	// is not optional. MEASURED, feeding the v4 Go builder's rows to the v5
	// helper on the reference cluster (docs/ha-cluster-userspace.conf, node
	// 0): egress zone of ifindex 24 = 0 and ifindex 25 = 0, where BOTH
	// origin/master and the v5 pair resolve `lan` and `wan`. Ifindex 25 is the
	// telling one — it loses a zone that even the pre-#6722 helper resolved —
	// so the pairing is strictly worse than either endpoint, not an
	// intermediate state. Under `default-policy deny-all` that is a silent
	// transit outage whose only signature is a version both sides agree on.
	//
	// Paired with ensureEgressZoneProtocolLocked (manager_compile.go), which
	// gates on EQUALITY rather than `>=`: the helper's own apply_snapshot and
	// bump_fib_generation gates are exact-equality, so a helper at ANY other
	// version refuses the snapshot, and a `>=` gate would stay green at
	// exactly the value that collides.
	// v5 (#5619 / #6691): InterfaceSnapshot.SecureTunnel became AUTHORITATIVE
	// over AF_XDP binding admission — the helper's
	// include_userspace_binding_interface refuses a candidate on it. A helper
	// that predates the field leaves it false and plans the xfrmi anyway, and
	// since the helper's queue count is the GLOBAL MINIMUM across candidates
	// and an xfrm interface has exactly ONE RX queue, that re-plans EVERY
	// physical interface onto one queue and one worker — the #3091
	// single-worker regression, silently, on a config this control plane
	// believes is safe. The same-version equality check cannot see it, which
	// is why the field needed the version and not just a new JSON tag.
	// Paired with ensureSecureTunnelProtocolLocked (manager_compile.go).
	//
	// v6 (#6691 round 9): the REFUSAL RULE over that same field changed from
	// "any owning row calls this netdev unbindable" to "every owning row
	// does" (userspaceRefusedNetdevs, mirrored by
	// snapshot_refuses_parent_netdev). No field moved — the SEMANTICS of the
	// existing rows did, which is precisely the case an unchanged version
	// number cannot express: a v5 helper and a v6 control plane both say "5"
	// and disagree about which netdevs may be bound, so a netdev one plane
	// admits the other refuses and the two produce different binding plans
	// from one snapshot. A wire change with no new field still needs the
	// version.
	//
	// v7 (#6691 round 10): FabricSnapshot.ParentUnbindable is AUTHORITATIVE
	// over whether a fabric parent netdev may be bound. A fabric member needs
	// no interface stanza, so the parent commonly has no row to carry the
	// device-level flags, and a v6 helper — which decodes the absent field to
	// false — plans an AF_XDP binding on a netdev this control plane refused.
	// The reachable shape is a live xfrmi under a slot-shaped name used as a
	// fabric member: one RX queue, global-minimum queue planning, #3091 again.
	// Paired with ensureSecureTunnelProtocolLocked, which gates the whole
	// secure-tunnel contract on the helper being at ProtocolVersion.
	// v8 (integration of #6722 and #6691): both branches independently bumped
	// this constant for DIFFERENT wire changes — #6722 to 5 for the
	// EgressZone-for-reth_projection swap, #6691 to 7 for the secure-tunnel
	// refusal contract. The merged wire carries BOTH contracts and therefore
	// matches NEITHER 5 nor 7. Leaving it at either value is exactly the
	// collision the two comments above describe: a helper built from one branch
	// alone advertises the same number as this control plane and reads the rows
	// differently. 8 was never shipped by either side, so no mixed pairing can
	// agree on it by accident. BOTH gates stay armed and both are dispatched
	// from ensureRequiredSnapshotProtocolLocked. The per-branch prose above
	// still says "4 -> 5" and "moved to 6"; those describe each branch's own
	// history, not this constant's current value.
	// v9 (issue 8892): `RoutingDomain` was added to the snapshot in 9472a66fd
	// WITHOUT bumping this constant, so a helper built before it advertises the
	// same 8, passes the exact-equality gate, ignores the field, and resolves
	// every interface to domain 0.
	//
	// The compatibility note left on the field was true and pointed one step
	// the wrong way: the field IS additive, and an old helper DOES degrade to
	// pre-#7160 behaviour. What does not hold is treating pre-#7160 behaviour
	// as an acceptable fallback -- #7160 exists because that behaviour is the
	// cross-tenant session aliasing defect, and the project's own regression
	// test (afxdp/tests_routing_domain_7160.rs) asserts that exact state is a
	// defect while the wire note called it a safe degradation.
	//
	// ADDITIVE-AND-DEGRADES-TO-OLD-BEHAVIOUR IS SOUND FOR A FEATURE AND UNSOUND
	// WHEN THE OLD BEHAVIOUR IS THE DEFECT THE FIELD WAS ADDED TO FIX. For
	// those, the version bump IS the mechanism that refuses the pairing, and
	// skipping it removes the only signal.
	// v10 (issue 9054) introduced `learned_route_import_capped`. #8355's cap
	// declines the whole learned-route import above ~65k routes. #7480 had
	// already made a NoRoute frame drop on a default-deny box, so #9054 made
	// the flag restore delegation to avoid a silent dynamic-FIB blackhole.
	// #9522 re-owns that tradeoff in the fail-closed direction: the helper
	// adjudicates capped NoRoute frames exactly as uncapped ones, and only a
	// policy Permit result keeps the normal slow-path delegation. The field's
	// meaning changed while its JSON bytes stayed the same, so v27 fences old
	// helpers that would still delegate.
	//
	// BUMPED, per the rule the v9 note above records: an old helper that
	// ignores the field keeps the pre-#9054 behaviour, and the pre-#9054
	// behaviour IS the defect. So the answer to "is what it enforced before
	// acceptable?" is no, and the bump is the only mechanism that refuses the
	// mismatched pairing — the acceptance gate is exact equality, so an
	// unbumped field is silently ignored rather than refused.
	// v11 (issue 9425): `ScreenMissingProfileRef.alarm_without_drop`. A zone
	// whose screen profile is DEFINED but enables no check is INERT: it gets no
	// `screens` entry, so the helper's resolved `alarm_without_drop` lookup
	// missed and the #7888 substituted conservative default HARD-DROPPED. The
	// canonical way into that state is `set security screen ids-option p
	// alarm-without-drop` and nothing else — an explicit request for audit mode
	// producing its exact inverse. The flag now rides on the inert reference so
	// the substituted checks alarm instead of dropping.
	//
	// BUMPED, by the same test the v10 note applies: an old helper that ignores
	// the field decodes false and keeps hard-dropping, and hard-dropping IS the
	// defect. "Purely additive needs no bump" is a true rule that would license
	// exactly this regression — the acceptance gate is exact equality, so an
	// unbumped field is silently ignored rather than refused, and the operator
	// would see audit mode configured, committed clean, and inverted.
	//
	// v12 (issue 9546): the on-map conntrack value gained `routing_domain`
	// (session_value 144 -> 152, session_value_v6 192 -> 200). No snapshot field
	// changed, so snapshot_shape_version_8892_test's digest did NOT move; this
	// bump is on the merits, by the test the v10/v11 notes apply. The helper
	// WRITES that struct, so a mismatched pair is not a benign degradation: a new
	// daemon creates the map at 152 bytes, an old helper hands
	// bpf_map_update_elem a 144-byte buffer, and the kernel copies value_size
	// bytes -- 8 past the helper's struct, into the very routing_domain slot a
	// new reader trusts. A garbage domain on a delete can name ANOTHER TENANT's
	// row. Exact equality refuses that pairing: an old helper receives no
	// snapshot, so it installs no session and never reaches publish_conntrack.
	//
	// v13 (issue 9412): the TCP close class now crosses the HA session-sync
	// path. It rides SessionDeltaInfo and SessionSyncRequest `tcp_close_class`,
	// the open-frame trailing byte, and the new close-state UPDATE frame.
	// Every hop is additive, and an old peer degrades to 0. By the v9 rule that
	// is still not enough, because the old behaviour IS the defect: a v12 helper
	// under a v13 daemon would never emit a close-state update, and would import
	// every closing session on the established window, while this daemon
	// believes close state crosses. The session-sync messages are not snapshot
	// structs, so the #8892 digest did not move; like v12, this bump is on the
	// merits.
	//
	// v14 (issue 9521): `ConfigSnapshot.WgSteeredListenPort`, the ONE WireGuard
	// listen port the shim steers, derived from the configuration. The helper
	// reads it to decide which WireGuard control threads may write kernel-path
	// transport plaintext to their wgN TUN: only the steered port's may, and
	// every other port's is dropped, because the kernel would otherwise forward
	// that plaintext with no zone policy.
	//
	// BUMPED, by the test the v10/v11 notes apply. An old helper ignores the
	// field and keeps writing every port's plaintext to its TUN, and that IS the
	// defect the field closes, so "is what it enforced before acceptable?" is
	// no. The reverse pairing fails the other way: a new helper under an old
	// daemon reads 0 and refuses kernel-path transport for every WireGuard
	// endpoint, the steered one included. Exact equality refuses both.
	//
	// #9521 was written against v12 and claimed 13; #9412 landed v13 first for a
	// different wire change. The v8 rule applies: the merged wire carries BOTH
	// contracts, so it cannot reuse either branch's number — a v13 helper built
	// from #9412 alone would accept this daemon's snapshots and ignore the field.
	// 14 was never shipped by either side.
	//
	// v15 (issue 9520): `ConfigSnapshot.ContentDigest`, which the helper compares
	// when an apply reuses its installed generation. BUMPED, by the test the
	// v10/v11 notes apply: an old helper ignores the field and keeps admitting a
	// reused generation content-blind, and that IS the defect the field closes.
	// A new helper under an old daemon sees an empty digest on both sides and
	// admits as v14 did, while that daemon cannot react to a conflict refusal.
	// Exact equality refuses both pairings.
	//
	// v16 (issue 9714): `SessionSyncRequest.PeerDelete`, which marks a delete sent
	// on behalf of the peer so the helper can refuse one that would tear down a
	// live LOCAL session whose owner RG is locally active (a dual-primary split).
	// BUMPED on the merits, like v13: an old helper ignores the field and keeps
	// deleting the live local session, and that IS the defect the field closes.
	// The session-sync messages are not snapshot structs, so the #8892 digest did
	// not move.
	//
	// v17 (issue 9587): `ConfigSnapshot.WgSteeredListenPorts`, the bounded SET
	// of WireGuard listen ports the shim steers (at most
	// config.MaxSteeredWireGuardPorts), replacing the v14 singular
	// `WgSteeredListenPort`. BUMPED on the merits under the v9 rule: an old
	// helper ignores the new key and steers by the ABSENT singular key, which
	// decodes to 0 and delivers kernel-path transport for NO endpoint — a
	// total loss of kernel-path inbound delivery (worker-path decap matches
	// endpoints independently of the steered set, so "total outage" would
	// overstate), which is the gap this field closes, not an acceptable
	// degradation. The bump does not cover ctrl-layout skew: a Go/Rust
	// userspaceCtrlValue size mismatch is refused separately by the
	// pinned-map pre-flight (fail-closed deploy, never a post-stop brick).
	// The reverse pairing fails the other way:
	// new helper under an old daemon reads an empty set and refuses
	// kernel-path transport for every WireGuard endpoint, the steered ones
	// included. Exact equality refuses both.
	//
	// v18 (issue 9637): NO wire change — the dual-outlet behavioral contract.
	// A pre-narrowing helper satisfies the handshake but funnels every
	// reinject (adjudicated AND delegated) through `xpf-usp0`, which a v18
	// kernel exempts from destination judgment; the daemon installs that
	// exemption on publication freshness, which cannot see outlet semantics.
	// BUMPED on the merits under the v9 rule even with the digest unmoved:
	// an old helper under a new daemon would admit unadjudicated traffic,
	// and that IS the defect the fence closes.
	// Refusal fails closed in both directions. A helper wire refusal is
	// ordinary-class (mixed_version_matrix_6691_test.go): the #5679 deferred
	// path fails the commit while the helper stays armed on its
	// previous-good snapshot, and the tail still runs with the D1 gate
	// clear so it renders accept-less. A daemon-side version-gate refusal
	// is an abort sentinel, so the tail is skipped, the commit fails, and
	// the helper is disarmed (fail-closed, deliberate) while the retained
	// kernel table stands. Exact equality refuses both pairings.
	//
	// v19 (issue 9874): `SourceNATRuleSnapshot.LenientMatchDropped`, the
	// fail-closed poison for a rule whose AUTHORED `match` constrains
	// nothing. The #8430 strict gate rejects such a rule at commit, but the
	// tolerant load / peer-sync path downgrades to a warning and used to
	// ship it with an empty match set — which the helper reads as
	// UNCONSTRAINED (`source_constrained = false` → match-any), installing
	// a catch-all translator for every flow in scope. BUMPED, by the test
	// the v10/v11 notes apply: an old helper ignores the marker and keeps
	// installing the catch-all, and that IS the defect the field closes.
	// Exact equality refuses the mismatched pairing instead of degrading
	// silently, in both directions. (The typed-config
	// `NATRule.LenientMatchDropped` diagnostic that feeds it is `json:"-"`
	// and rides along invisibly — the #9246 STANDS arm, folded into this
	// bump rather than a separate entry.)
	//
	// v20 (issue 9875): `FirewallTermSnapshot.FromUnrepresentable`, set when
	// the term's `from` carried a match leaf the dataplane does not enforce
	// (term.UnknownFrom, #3307) or a value-bearing leaf written with no
	// operand (term.ValuelessFrom, #8480). BUMPED on the merits under the
	// v9 rule: an old helper ignores the new key and enforces the SURVIVING
	// match set — byte-identical to a term authored without the leaf — so
	// an accept term over-permits and a discard/reject term over-drops,
	// which IS the defect the marker closes (the #3406/#6459/#6463 family
	// rode without bumps only because all of them predate the #8892 cell;
	// the v4 rule above — "a compatibility extension that changes
	// deny/reject COVERAGE must not be silently ignorable" — governs now).
	// A new helper under an old daemon reads the key absent (false) and
	// enforces the widened term exactly as before — the pre-fix window,
	// closed on upgrade. Exact equality refuses both pairings; the #8892
	// digest moves with it (a real, transmitted field).
	//
	// v21 (issue 9821): `InterfaceSnapshot.IsUnit`, the STRUCTURAL row
	// identity (true = logical-unit row, false = interface row), emitted
	// unconditionally. BUMPED on the merits under the v9 rule: an old helper
	// parses every row by NAME SHAPE ("contains a dot"), so a v20 helper
	// reads a dotted base row (`ge-0/0/5.0`) as a UNIT row — admitting its
	// zone claim into the unit agreement (#7509) and its netdev into the
	// ingress identity (#9637) — and that misread IS the defect the field
	// closes, not an acceptable degradation. The reverse pairing degrades by
	// construction instead of refusing: a new helper reads `None` (absent
	// key) as "parse the name", which is old-Go behavior exactly — but exact
	// equality refuses the pairing anyway, because a mixed window would
	// silently lose the fix on the old side. The #8892 digest moves with it
	// (a real, transmitted field).
	//
	// #9875 claimed 20 first for a different wire change. The v8 rule
	// applies: the merged wire carries BOTH contracts, so it cannot reuse
	// 20 — a v20 helper built from #9875 alone would accept this daemon's
	// snapshots and misread every dotted base row. 21 was never shipped by
	// either side.
	//
	// v22 (issue 9752): the session's installing-table identity
	// (`SessionDecision` domain+check) now crosses the HA session-sync path:
	// the open-frame trailing pair, both `SessionDeltaInfo` legs, the
	// cluster wire tails, and `SessionSyncRequest.install_table_*`.
	// BUMPED on the merits, like v13/v16: an old helper ignores the fields
	// and imports every PBR-steered session stamp-less, re-resolving it in
	// `inet.0` — and that IS the defect the fields close. The session-sync
	// messages are not snapshot structs, so the #8892 digest did not move.
	//
	// v23 -> v24 BUMPED (#9955): RouteSnapshot.RulePriority is a real
	// transmitted field added on top of the v23 DHCPv6 relay contract (#9553).
	// An old helper silently retains the one-list prefix-length leak model and
	// cannot fall through a target-table miss. Exact equality refuses the mixed
	// pairing.
	// v24 -> v25 (#10018): persistent-NAT lease identity gained RoutingScope.
	// The manager gates both lease-control verbs on an observed v25 helper;
	// without that gate an old helper would ignore the field and merge two VRFs.
	// v25 -> v26 (#10196): a named WireGuard transport table now means the
	// outer UDP socket is bound to `vrf-<instance>` via SO_BINDTODEVICE. An
	// old Rust helper would accept the same snapshot but keep that socket in
	// the main table, reopening #9909's containment escape.
	// v26 -> v27 (#9522): `learned_route_import_capped` keeps the same JSON
	// field, but its disposition changed. A v26 helper still restores kernel
	// delegation for capped NoRoute frames; v27 adjudicates them and drops a
	// policy denial. Exact equality must refuse the mixed pairing or an old
	// helper preserves the #9054 security bypass.
	// v27 -> v28 (#9506 S5): `permit_epoch` and `queue_epochs` carry
	// the epoch-scoped q0 capture authority. An older helper would ignore those
	// fields and admit/reject against stale queue ownership.
	// v28 -> v29 (#9506 P-MECH): IPsec tunnel-row identity carries the
	// authoritative `{stn, if_id, logical_ifindex}` D14 fence. An older helper
	// would omit the row contract and let the Rust worker pair a claimed
	// tunnel with an untrusted or stale snapshot.
	// v29 -> v30 (#10485): the capture-generation stamp paired with
	// `ipsec_tunnel_rows` fences rows against same-key config/FIB publishes.
	// A v29 helper can decode the rows but cannot prove that the packet's
	// admitted handle generation is the one in the RuntimeView.
	// v30 -> v31 (#10510): `zone_set_validated` authenticates the populated,
	// collision-free zone identity set before Rust derives removed-zone ids.
	// A v30 helper cannot distinguish a quarantined/legacy partial map from a
	// real zone disappearance and can retain stale peer sessions; exact
	// equality refuses the mixed pair.
	// v32 (#10683): bind-less VPNs publish their rendered selector pairs to
	// the dataplane, which drops matching AF_XDP transit without relying on SA
	// state. An older helper ignores these rows and continues sending matching
	// cleartext because AF_XDP TX bypasses kernel XFRM.
	// v32 -> v33 (#10702): post-teardown apply refusals now carry a
	// machine-readable kind. A v32 manager interprets the old free-text refusal
	// as proof that the prior snapshot is retained and can leave ctrl enabled
	// after workers are gone; exact equality refuses that unsafe mixed pairing
	// before teardown.
	ProtocolVersion = 33

	// MinProtocolMultiZoneScopedPolicy is the FIRST snapshot protocol version
	// that can represent a multi-zone scoped global policy — the plural
	// MatchFromZones/MatchToZones fields landed in the v4 bump (#6644/#5488).
	// A reader below it sees only the singular MatchFromZone/MatchToZone and
	// NARROWS the policy to its first zone.
	//
	// It is a per-feature IMMUTABLE floor, deliberately not `ProtocolVersion`.
	// The cross-chassis gate (#6650) asks "can the PEER represent this shape?",
	// and that answer does not change when an unrelated wire field is added --
	// pinning it to the shared constant would make every future bump
	// retroactively refuse multi-zone commits across a version skew, which is
	// exactly the defect open #6648 describes in the LOCAL gates. This is the
	// first per-feature floor in the tree; #6648 tracks giving the local gates
	// the same treatment. Never renumber it: it names a historical wire fact.
	MinProtocolMultiZoneScopedPolicy = 4

	// The remaining per-feature floors (#6648). Each names the FIRST snapshot
	// protocol version whose wire representation carries that feature, and each
	// is IMMUTABLE: it is a historical fact about the wire, not a tracking
	// alias for ProtocolVersion. Never renumber one; a new floor is added when
	// a new feature's representation lands.
	//
	// Before #6648 the four gates in manager_compile.go all compared against
	// ProtocolVersion, so every bump for an unrelated feature retroactively
	// raised the bar for all of them and reported a misleading reason: a helper
	// running a scheduled-policy config was told "policy scheduler snapshots"
	// required version 8, when policy-scheduler snapshots have been
	// representable since version 2.
	//
	// These floors answer ONLY "can this helper represent this feature?". The
	// separate question "will this helper accept our snapshot at all?" is
	// answered in exactly ONE place — ensureEgressZoneProtocolLocked's
	// unconditional equality check — because the helper's own contract is exact
	// equality (userspace-dp/src/server/handlers/snapshot.rs). Keeping the two
	// questions apart is what stops the per-feature gates from being a second,
	// divergent copy of the acceptance rule (#6649).

	// MinProtocolPolicyScheduler: the policy-scheduler inactive-state fields
	// landed in the v2 bump (f7c4b125c, #1396).
	MinProtocolPolicyScheduler = 2

	// MinProtocolPersistentSourceNAT: persistent SNAT pool leases landed in the
	// v3 bump (c0a047ea2, #1377).
	MinProtocolPersistentSourceNAT = 3
	// MinProtocolPersistentNatLeaseScope is the FIRST protocol version whose
	// control-socket lease records carry a routing domain. Unlike the historical
	// persistent-SNAT feature floor above, this gate is used at runtime by both
	// lease-control verbs: an unobserved or older helper is not allowed to
	// ignore the scope and import a lease as domain 0.
	MinProtocolPersistentNatLeaseScope = 25

	// MinProtocolSecureTunnelRefusal: the device-level AF_XDP binding refusal
	// contract spans THREE bumps on the #5619/#6691 branch — v5 added
	// InterfaceSnapshot.SecureTunnel (be8aec13e), v6 the every-owner refusal
	// rule (8d0e09fb8), v7 the fabric parent's verdict
	// (FabricSnapshot.ParentUnbindable, 8c011681c). The floor is the LAST of
	// them: a helper below 7 misreads at least one part of the contract, so 7
	// is the first version that reads all of it. (The subsequent 7 -> 8 bump
	// was collision resolution against #6722's parallel v5, not a fourth change
	// to this contract — see the ProtocolVersion comment above.)

	MinProtocolSecureTunnelRefusal   = 7
	InjectPacketTupleProtocolVersion = 1
	TypeUserspace                    = "userspace"

	// MaxInjectPacketLength bounds the operator/API-supplied packet
	// length for the `request inject-packet` control RPC (#2443). An
	// injected packet is always emitted as a single unfragmented frame
	// that must fit in one AF_XDP UMEM frame on the TX path
	// (UMEM_FRAME_SIZE = 4096 in userspace-dp), and 4096 is also well
	// within the u16 range of the IPv4 total-length / IPv6 payload-length
	// wire fields, so the on-wire length can never wrap. The bound is the
	// smaller of "u16-representable" and "max single egress frame"; the
	// UMEM frame ceiling is the binding constraint. A length above this is
	// REJECTED (not clamped) so an API misuse / DoS attempt surfaces as an
	// error rather than being silently masked.
	MaxInjectPacketLength = 4096
)

// IdleLeaseWire is one idle persistent-NAT lease crossing the helper control
// socket and, in the same shape, the cluster sync channel (#8121).
//
// RoutingScope is a pointer deliberately: nil means a pre-v25 helper omitted
// the field, while a non-nil pointer to 0 is the real default routing domain.
// Callers must reject nil rather than silently converting it to domain 0.
// Three fields are deliberately NOT what the helper holds internally, and each
// for the same reason — the internal form is node-local and means something
// different on the peer:
//
//   - RemainingNs is a LIFETIME, not a deadline. The helper's expires_at_ns is
//     CLOCK_MONOTONIC and boot-relative, so a node up ten days would read a
//     value from a node up one hour as long expired.
//   - TranslatedIP is an address, not a pool index. An index means the same
//     address only while both sides agree on the pool ordering.
//   - Pool is a name, not a rule index, for that same reason one level up.
//
// Go never interprets these beyond carrying them; the meanings live in the
// helper (userspace-dp nat/idle_lease_sync_8121.rs).
type IdleLeaseWire struct {
	Pool           string  `json:"pool"`
	Protocol       uint8   `json:"protocol"`
	SrcIP          string  `json:"src_ip"`
	SrcPort        uint16  `json:"src_port"`
	RoutingScope   *uint32 `json:"routing_scope"`
	RemoteIP       string  `json:"remote_ip,omitempty"`
	RemotePort     uint16  `json:"remote_port,omitempty"`
	TranslatedIP   string  `json:"translated_ip"`
	TranslatedPort uint16  `json:"translated_port"`
	AddressOnly    bool    `json:"address_only,omitempty"`
	RemainingNs    uint64  `json:"remaining_ns"`
	TimeoutNs      uint64  `json:"timeout_ns"`
}

// DisplayLeaseWire is the export_persistent_lease_display result (#8615): one
// persistent-NAT lease as the SHOW table needs it, INCLUDING bindings that
// still have live flows.
//
// A separate type from IdleLeaseWire on purpose. IdleLeaseWire is the record a
// peer IMPORTS, and userspace-dp/src/nat/idle_lease_sync_8121.rs's first design
// rule forbids carrying ActiveFlows on it — a standby installs a strict subset,
// so a carried count credits a lease for sessions that node does not hold, it
// never reaches zero, and no GC path reclaims it. Keeping the display record
// distinct means that rule cannot be undone by a later edit to a shared struct.
type DisplayLeaseWire struct {
	Pool           string  `json:"pool"`
	Protocol       uint8   `json:"protocol"`
	SrcIP          string  `json:"src_ip"`
	SrcPort        uint16  `json:"src_port"`
	RoutingScope   *uint32 `json:"routing_scope"`
	RemoteIP       string  `json:"remote_ip,omitempty"`
	RemotePort     uint16  `json:"remote_port,omitempty"`
	TranslatedIP   string  `json:"translated_ip"`
	TranslatedPort uint16  `json:"translated_port"`
	AddressOnly    bool    `json:"address_only,omitempty"`
	// RemainingNs is RAW and is meaningful only when ActiveFlows == 0. While
	// flows are live the allocator does not refresh the deadline (it is
	// rewritten when the last flow closes), so this is routinely 0 for a
	// perfectly healthy binding. Interpreting it is the renderer's job.
	RemainingNs uint64 `json:"remaining_ns"`
	TimeoutNs   uint64 `json:"timeout_ns"`
	ActiveFlows uint32 `json:"active_flows,omitempty"`
}

type ControlRequest struct {
	Type           string                    `json:"type"`
	SuppressStatus bool                      `json:"suppress_status,omitempty"`
	Snapshot       *ConfigSnapshot           `json:"snapshot,omitempty"`
	Forwarding     *ForwardingControlRequest `json:"forwarding,omitempty"`
	HAState        *HAStateUpdateRequest     `json:"ha_state,omitempty"`
	Queue          *QueueControlRequest      `json:"queue,omitempty"`
	Binding        *BindingControlRequest    `json:"binding,omitempty"`
	Packet         *InjectPacketRequest      `json:"packet,omitempty"`
	SessionSync    *SessionSyncRequest       `json:"session_sync,omitempty"`
	SessionPolicyList *SessionPolicyListRequest `json:"session_policy_list,omitempty"`
	SessionDeltas  *SessionDeltaDrainRequest `json:"session_deltas,omitempty"`
	SessionExport  *SessionExportRequest     `json:"session_export,omitempty"`
	// #7919: the 5-tuple for the read-only `session_counters` verb. An ADDED
	// field, never a redefinition — an old helper ignores it, and this control
	// plane never sends it to one twice (the first refusal is sticky per call).
	SessionCounterQuery *SessionCounterQuery `json:"session_counter_query,omitempty"`
	// IdleLeases carries idle persistent-NAT leases for the import_idle_leases
	// verb (#8121). omitempty so every other request is byte-identical to
	// before — the control socket is shared with the 1/s status poll and with
	// session installs, and an empty array on every request is waste there.
	IdleLeases []IdleLeaseWire `json:"idle_leases,omitempty"`
	// Neighbors carries the manager-neighbor set for an update_neighbors
	// request. It deliberately does NOT use omitempty (#5864): when the
	// authoritative publishable set transitions to EMPTY, the send path
	// still passes a present-but-empty slice with NeighborReplace=true to
	// CLEAR the helper table. omitempty drops both nil and empty slices,
	// which erased that clear on the wire (the helper decoded neighbors as
	// absent and returned before applying the replacement, leaving stale
	// dynamic neighbors installed → blackhole after kernel neighbor
	// deletion). Without omitempty a present-empty replace encodes as
	// "neighbors":[] — distinct from an absent field — so the helper
	// applies the clear. A nil slice on non-neighbor requests encodes as
	// "neighbors":null, which the Rust Option<Vec<..>> decodes back to
	// None (harmless; those requests ignore the field).
	Neighbors          []NeighborSnapshot `json:"neighbors"`
	NeighborGeneration uint64             `json:"neighbor_generation,omitempty"`
	NeighborReplace    bool               `json:"neighbor_replace,omitempty"`
	Fabrics            []FabricSnapshot   `json:"fabrics,omitempty"`
}

type ControlResponse struct {
	OK            bool               `json:"ok"`
	Error         string             `json:"error,omitempty"`
	Status        *ProcessStatus     `json:"status,omitempty"`
	SessionPolicyMatches []SessionPolicyMatch `json:"session_policy_matches,omitempty"`
	SessionPolicyComplete bool `json:"session_policy_complete,omitempty"`
	SessionPolicyContinuation string `json:"session_policy_continuation,omitempty"`
	SessionPolicyPerWorkerErrors []string `json:"session_policy_per_worker_errors,omitempty"`
	SessionDeltas []SessionDeltaInfo `json:"session_deltas,omitempty"`
	// SessionExportMore reports that an export_owner_rg_sessions answer was
	// CAPPED by the request's Max and the helper still holds deltas from the
	// same window (#9344).
	//
	// The bit is not new information — the helper's drain_session_deltas_fair
	// has always computed it; the owner-RG call site discarded it into
	// `_overflow`, which is why paging was not expressible and the only usable
	// request was Max=0. Max=0 asks for the UNBOUNDED owner-RG set, which
	// crosses MaxControlResponseBytes at roughly 7.8k sessions/worker on a
	// six-worker box and makes the HA cold prime fail permanently.
	//
	// Additive and omitempty (#1961 skew-safe): an older helper omits it and an
	// older caller ignores it, so both read false — the pre-#9344 single-shot
	// behaviour. A caller must therefore NOT read false as proof the helper
	// supports paging; ExportOwnerRGSessionsPaged handles that by asking for
	// the unbounded set on the first page when it has no evidence either way.
	SessionExportMore bool `json:"session_export_more,omitempty"`
	// #9856: v2 export completeness metadata. The helper emits these on
	// every owner-RG export page; a nonzero dropped count is never
	// publishable by the authoritative FullResync caller.
	SessionExportDropped     uint64 `json:"session_export_dropped,omitempty"`
	SessionExportIncarnation uint64 `json:"session_export_incarnation,omitempty"`
	SessionExportSeq         uint64 `json:"session_export_seq,omitempty"`
	// IdleLeases is the export_idle_leases result (#8121).
	IdleLeases []IdleLeaseWire `json:"idle_leases,omitempty"`

	// DisplayLeases is the export_persistent_lease_display result (#8615).
	DisplayLeases []DisplayLeaseWire `json:"display_leases,omitempty"`
	// SessionCounters is the session_counters result (#7919), one row per
	// worker. Empty for every other verb — callers must NOT read emptiness as
	// "no worker holds this session": an unimplemented verb is reported by the
	// helper's `unknown request type` error and surfaces as
	// ErrSessionCountersUnsupported, never as an empty answer.
	SessionCounters []SessionCounterRow `json:"session_counters,omitempty"`
	// #10512: helper-owned clear transaction metadata.
	SessionMirrorV4Count          uint64 `json:"session_mirror_v4_count,omitempty"`
	SessionMirrorV6Count          uint64 `json:"session_mirror_v6_count,omitempty"`
	SessionMirrorComplete         bool   `json:"session_mirror_complete,omitempty"`
	SessionMirrorFenceID          uint64 `json:"session_mirror_fence_id,omitempty"`
	SessionMirrorContinuation     string `json:"session_mirror_continuation,omitempty"`
	// PolicyDeleteOutcomes is the per-match outcome vector for one
	// mirror_delete_policy_batch micro-batch (#10512, plan §2.4), positional
	// against the request's PolicyMatches: applied | stale_forward |
	// partial_companion | refused_identity. Valid only when
	// PolicyDeleteComplete is true; any other shape is a batch failure the
	// caller surfaces as a persistent gap, never partial success.
	PolicyDeleteOutcomes []string `json:"policy_delete_outcomes,omitempty"`
	PolicyDeleteComplete bool     `json:"policy_delete_complete,omitempty"`
	PolicyDeleteErrors   []string `json:"policy_delete_errors,omitempty"`
}

// QueueEpochSnapshot is one queue-number/epoch pair. It is a list rather than
// a map so the wire order remains deterministic across Go and Rust.
type QueueEpochSnapshot struct {
	Queue uint16 `json:"queue"`
	Epoch uint64 `json:"epoch"`
}

// Rename operation. It is additive wire state; absent ancestry means the
// helper retains the historical teardown behavior.
type PolicyRenameAncestry struct {
	SourceRuleID        string `json:"source_rule_id"`
	DestinationRuleID   string `json:"destination_rule_id"`
	SourceFromZone      string `json:"source_from_zone,omitempty"`
	SourceToZone        string `json:"source_to_zone,omitempty"`
	DestinationFromZone string `json:"destination_from_zone,omitempty"`
	DestinationToZone   string `json:"destination_to_zone,omitempty"`
	// Numeric ids are captured from the validated old/new snapshots. Rust
	// checks them against the session's recorded zones and the destination
	// forwarding map; names alone are not an identity proof across snapshots.
	SourceFromZoneID       uint16 `json:"source_from_zone_id,omitempty"`
	SourceToZoneID         uint16 `json:"source_to_zone_id,omitempty"`
	DestinationFromZoneID  uint16 `json:"destination_from_zone_id,omitempty"`
	DestinationToZoneID    uint16 `json:"destination_to_zone_id,omitempty"`
	SourceFromZoneAny      bool   `json:"source_from_zone_any,omitempty"`
	SourceToZoneAny        bool   `json:"source_to_zone_any,omitempty"`
	DestinationFromZoneAny bool   `json:"destination_from_zone_any,omitempty"`
	DestinationToZoneAny   bool   `json:"destination_to_zone_any,omitempty"`
}

// PolicySessionRebind is a pre-publication Go verdict joined to a canonical
// forward tuple. Rust consumes it during rotation to restamp both pair halves.
//
// TunnelDiscriminator is trailing-additive JSON metadata. It is the opaque
// TunnelDiscriminator value already carried by SessionValue and used to build
// the Rust SessionKey. Older readers omit/ignore this field; Rust treats a
// missing or invalid value as non-retainable and deletes the pair.
type PolicySessionRebind struct {
	Family              string `json:"family"`
	SrcIP               string `json:"src_ip"`
	DstIP               string `json:"dst_ip"`
	SrcPort             uint16 `json:"src_port,omitempty"`
	DstPort             uint16 `json:"dst_port,omitempty"`
	Protocol            uint8  `json:"protocol"`
	RoutingDomain       uint32 `json:"routing_domain,omitempty"`
	PolicyID            uint32 `json:"policy_id"`
	RuleID              string `json:"rule_id"`
	IngressZone         uint16 `json:"ingress_zone"`
	EgressZone          uint16 `json:"egress_zone"`
	TunnelDiscriminator uint64 `json:"tunnel_discriminator,omitempty"`
}

// IpsecTunnelRowSnapshot is one per-admitted-tunnel P-MECH identity row (#10485,
// design section 1.1 D1). The daemon publishes one row per admitted tunnel:
// STN is always the authored vpn.BindInterface, IfID is the ownership-checked
// config.XFRMIfNameAndID derivation, and LogicalIfindex is the staged live
// ifindex frozen for the snapshot generation (D1c). Rust D14 derives the
// authoritative if_id by EXACT STN match and an unknown STN is doubt and
// DROPs. There is deliberately no Rust-side if_id re-derivation (a second
// parser is a second alias bug, #6691).
type IpsecTunnelRowSnapshot struct {
	STN            string `json:"stn"`
	IfID           uint32 `json:"if_id"`
	LogicalIfindex int32  `json:"logical_ifindex"`
}
// IpsecBindlessSelectorSnapshot is one complete pair of IPsec traffic-selector
// sides for a policy-based VPN with no bind-interface. Empty sides are not
// published: they resolve to dynamic endpoints rather than a shape the helper
// can classify precisely.
type IpsecBindlessSelectorSnapshot struct {
	LocalTS  string `json:"local_ts"`
	RemoteTS string `json:"remote_ts"`
}

type ConfigSnapshot struct {
	Version       int       `json:"version"`
	Generation    uint64    `json:"generation"`
	FIBGeneration uint32    `json:"fib_generation,omitempty"`
	GeneratedAt   time.Time `json:"generated_at"`
	// PermitEpoch and QueueEpochs are additive S4 authority feed fields.
	// Zero/nil means no active #9506 pipeline authority.
	PermitEpoch uint64               `json:"permit_epoch,omitempty"`
	QueueEpochs []QueueEpochSnapshot `json:"queue_epochs,omitempty"`
	// IpsecTunnelRows is the immutable per-admitted-tunnel P-MECH identity
	// set (#10485, design section 1.1 D1). Nil/empty is deliberate deny-only
	// state: Rust binds an empty set to generation 0, so every D14 submit
	// remains E28-denied exactly as before the publisher exists.
	IpsecTunnelRows []IpsecTunnelRowSnapshot `json:"ipsec_tunnel_rows,omitempty"`
	// BindlessSelectorFenceEnabled gates shape-based cleartext fencing for
	// policy-based IPsec selector pairs. The helper drops matching transit even
	// while no SA is present: AF_XDP TX bypasses kernel XFRM and SA state is not
	// a safe authorization oracle.
	BindlessSelectorFenceEnabled bool `json:"bindless_selector_fence_enabled,omitempty"`
	BindlessSelectorRows         []IpsecBindlessSelectorSnapshot `json:"bindless_selector_rows,omitempty"`
	// IpsecTunnelSnapshotGeneration is the daemon capture-generation stamp
	// paired with IpsecTunnelRows. It is distinct from ConfigSnapshot.Generation:
	// the latter advances for ordinary config/FIB publishes, while the former
	// advances only when admitted NFQUEUE handles rotate. Rust D14 compares its
	// packet snapshot-generation advisory against this exact capture authority.
	IpsecTunnelSnapshotGeneration uint64                `json:"ipsec_tunnel_snapshot_generation,omitempty"`
	Summary                       SnapshotSummary       `json:"summary"`
	Capabilities                  UserspaceCapabilities `json:"capabilities"`
	MapPins                       UserspaceMapPins      `json:"map_pins"`
	Zones                         []ZoneSnapshot        `json:"zones,omitempty"`
	// ZoneSetValidated is true only when the producer supplied a populated
	// zone set and completed duplicate/collision validation without
	// quarantining a zone. Rust uses it to derive removed-zone ids; absent or
	// false is a fail-closed no-op for old/ambiguous producers.
	ZoneSetValidated bool                     `json:"zone_set_validated,omitempty"`
	Interfaces       []InterfaceSnapshot      `json:"interfaces,omitempty"`
	Fabrics          []FabricSnapshot         `json:"fabrics,omitempty"`
	TunnelEndpoints  []TunnelEndpointSnapshot `json:"tunnel_endpoints,omitempty"`
	Neighbors        []NeighborSnapshot       `json:"neighbors,omitempty"`
	Routes           []RouteSnapshot          `json:"routes,omitempty"`
	Flow             FlowSnapshot             `json:"flow,omitempty"`
	DefaultPolicy    string                   `json:"default_policy,omitempty"`
	// WgSteeredListenPorts (#9587) is the bounded SET of WireGuard listen
	// ports the shim steers onto its AF_XDP WireGuard path (at most
	// config.MaxSteeredWireGuardPorts, selected by config.SplitSteeredPorts):
	// derived from the configuration rather than from TunnelEndpoints (which
	// are intersected with the live interface rows), so it is the set the
	// commit warning names even when a tunnel's netdev is absent. Two
	// readers: the ctrl-block programmer encodes it into the shim's
	// count+array, and the helper lets every listed port's WireGuard control
	// thread write kernel-path transport plaintext to its wgN TUN; any other
	// port's is dropped, because the kernel would forward it with no zone
	// policy. Empty/nil = no WireGuard tunnel.
	WgSteeredListenPorts []uint16 `json:"wg_steered_listen_ports,omitempty"`
	// DefaultLogSessionInit / DefaultLogSessionClose carry
	// `security policies default-policy-log session-init|session-close` (#3534).
	// They request RT_FLOW session logging for the IMPLICIT default-policy
	// verdict (the result returned when a flow matches no zone-pair, wildcard,
	// or global policy), mirroring a named policy's `then log` selection. The
	// Rust default-verdict result stamps these onto the metadata of a
	// default-PERMIT session so it emits RT_FLOW_SESSION_CREATE/CLOSE; a
	// default-DENY/REJECT verdict installs no session (already logged via the
	// policy-deny record), so they are inert there. Additive/skew-tolerant:
	// omitempty on the Go side + #[serde(default)] on the Rust side, so an old
	// helper decodes a missing field as false and an old Go binary that does not
	// emit it leaves the Rust flag false.
	// LearnedRouteImportCapped says the #8355 learned-route cap DECLINED this
	// build's kernel-route import (#9054). It is diagnostic state, not a
	// disposition override: #9522 makes the NoRoute policy predicate identical
	// above and below the cap. A denied result becomes PolicyDenied and is
	// dropped/counts as a policy denial; only a policy Permit result keeps the
	// ordinary slow-path delegation.
	//
	// WHY IT STAYS ON THE WIRE. The helper status and Prometheus gauge need to
	// report the published capped state, and the NoRoute diagnostics need to
	// explain why the helper route set is incomplete. The flag is also the
	// explicit input to the v26 -> v27 mixed-version fence: a v26 helper would
	// still restore delegation while a v27 helper adjudicates, even though the
	// JSON bytes are identical.
	//
	// The v27 learned-route contract is therefore NOT skew-tolerant. The
	// current ProtocolVersion 28 also fences the additive #9506 authority
	// fields rather than silently preserving either stale-ownership behavior.
	LearnedRouteImportCapped bool `json:"learned_route_import_capped,omitempty"`

	DefaultLogSessionInit  bool                 `json:"default_log_session_init,omitempty"`
	DefaultLogSessionClose bool                 `json:"default_log_session_close,omitempty"`
	Policies               []PolicyRuleSnapshot `json:"policies,omitempty"`
	// PolicyRematchExtensive enables the conditional retain/rebind rotation arm.
	PolicyRematchExtensive bool                         `json:"policy_rematch_extensive,omitempty"`
	PolicyRenameAncestry   []PolicyRenameAncestry       `json:"policy_rename_ancestry,omitempty"`
	PolicySessionRebinds   []PolicySessionRebind        `json:"policy_session_rebinds,omitempty"`
	DestinationNAT         []DestinationNATRuleSnapshot `json:"destination_nat_rules,omitempty"`
	SourceNAT              []SourceNATRuleSnapshot      `json:"source_nat_rules,omitempty"`
	StaticNAT              []StaticNATRuleSnapshot      `json:"static_nat_rules,omitempty"`
	NAT64                  []NAT64RuleSnapshot          `json:"nat64_rules,omitempty"`
	Nptv6                  []Nptv6RuleSnapshot          `json:"nptv6_rules,omitempty"`
	Screens                []ScreenProfileSnapshot      `json:"screens,omitempty"`
	// ScreenMissingProfiles records zones that REFERENCE a screen profile
	// which was NOT defined at snapshot-build time (#3082). On the
	// lenient/HA-sync path (#1960 — older-binary-persisted active.json on
	// upgrade, or an HA sync from an un-upgraded primary) a zone can
	// reference an undefined screen profile and boot with an apply-time
	// warning, yet the dataplane would have no `screens` entry for that zone
	// and so silently PASS all screen checks. Both "zone has no screen
	// configured" and "zone references a MISSING screen" otherwise produce
	// no entry. This additive field carries the missing references so the
	// dataplane can distinguish the two and emit a rate-limited runtime WARN
	// (the verdict stays Pass — the fail-closed-vs-pass posture is deferred).
	// Additive/skew-tolerant: an old helper without the field decodes it as
	// empty (all-Pass, no warn); an old Go binary that does not emit it
	// leaves the Rust set empty.
	ScreenMissingProfiles []ScreenMissingProfileRef `json:"screen_missing_profile_zones,omitempty"`
	// ScreenInertProfiles records zones that resolve to a screen profile
	// which IS DEFINED but enables no check (#7888, the #7059 third state).
	// buildScreenSnapshots emits no `screens` entry for such a zone, exactly
	// as it emits none for an undefined reference, so without this field the
	// helper cannot tell the two apart -- and it cannot tell either of them
	// from a zone with no screen configured at all, which is a LEGITIMATE
	// silent Pass.
	//
	// Carried as a SIBLING of ScreenMissingProfiles rather than folded into
	// it. The two sets are disjoint by construction (each builder skips the
	// other's case) and must stay separately addressable on the wire: the
	// helper branches its runtime WARN text on which set a zone is in, and
	// merging them would make that text undecidable at the point it is
	// emitted -- reintroducing the very defect #7888 exists to fix, one
	// layer down.
	//
	// Additive/skew-tolerant in BOTH directions, which is what makes this
	// safe to land without a flag day: an old helper without the field
	// ignores it (inert zones Pass, exactly as today); an old Go binary that
	// does not emit it leaves the Rust set empty (inert zones Pass, exactly
	// as today). Neither direction is worse than the status quo, and no
	// existing field changes meaning -- the rolling-upgrade rule is ADD a
	// field, never redefine one, because the two HA nodes run different
	// binaries against one wire and `serde(default)` cannot help when the
	// OLDER binary is the sender.
	ScreenInertProfiles []ScreenMissingProfileRef `json:"screen_inert_profile_zones,omitempty"`
	SYNCookieMasterKey  string                    `json:"syn_cookie_master_key,omitempty"`
	// #9173: the SYN-cookie key bases, ADDED beside SYNCookieMasterKey rather
	// than redefining it. SYNCookieMasterKey keeps its meaning (the key to mint
	// and validate with, now the key of the period the snapshot was built in), so
	// an older helper that ignores this field still works. A newer helper derives
	// every period's key from the ring and picks one by each cookie's own epoch.
	// Only a newer helper that receives NO ring falls back to SYNCookieMasterKey;
	// a ring it receives is authoritative, and one with no usable base fails
	// closed. See buildSYNCookieKeys.
	SYNCookieKeyRing   *SYNCookieKeyRingSnapshot   `json:"syn_cookie_key_ring,omitempty"`
	Filters            []FirewallFilterSnapshot    `json:"filters,omitempty"`
	Policers           []PolicerSnapshot           `json:"policers,omitempty"`
	ThreeColorPolicers []ThreeColorPolicerSnapshot `json:"three_color_policers,omitempty"`
	ClassOfService     *ClassOfServiceSnapshot     `json:"class_of_service,omitempty"`
	FlowExport         *FlowExportSnapshot         `json:"flow_export,omitempty"`
	MirrorConfigs      []MirrorConfigSnapshot      `json:"mirror_configs,omitempty"`
	// MirrorExclusions records the port-mirroring entries this snapshot's
	// build REFUSED to install for a runtime reason (#7357 §2). Carried on
	// the snapshot so a show surface renders the verdict that was actually
	// applied rather than re-deriving one from a live interface table that
	// may have moved since.
	MirrorExclusions []MirrorExclusion     `json:"mirror_exclusions,omitempty"`
	AddressBooks     []AddressBookSnapshot `json:"address_books,omitempty"`
	// AppCatalog is the L3/L4 application-identification catalog (#2008 M5):
	// the ordered (protocol, port-range) -> app_id classification table the
	// dataplane uses to stamp app_id on a new session. Additive field — an
	// old Rust helper that does not know it simply ignores it (serde does not
	// require it), and an old Go binary that does not emit it leaves Rust's
	// catalog empty (every session keeps app_id 0, the existing default). The
	// app_id values match CompileResult.AppNames so `show security flow
	// session` resolves them back to names.
	AppCatalog   []AppCatalogEntrySnapshot `json:"app_catalog,omitempty"`
	Config       *config.Config            `json:"config,omitempty"`
	Userspace    config.UserspaceConfig    `json:"userspace"`
	DeferWorkers bool                      `json:"defer_workers,omitempty"`
	// NodeID is the chassis-cluster node id this daemon runs as (0 or 1; 0 when
	// standalone). #6311: the helper folds it into the high bit of every
	// worker's session-id namespace (SessionTable::set_session_id_namespace), so
	// a peer session id the standby adopts verbatim on import (#5212) can never
	// collide with an id this node mints — both nodes otherwise run the same
	// worker set (queue indices 0..N) with counters that both start at 1.
	//
	// ADDITIVE with omitempty and a Rust-side #[serde(default)], deliberately
	// WITHOUT a ProtocolVersion bump. The snapshot handler gates on EXACT
	// version equality, so a bump would make a mixed-base pair refuse to apply a
	// snapshot at all; whereas an older helper that ignores this field simply
	// keeps the pre-#6311 layout, which is exactly today's behaviour. The pairing
	// is monotone in both directions: new-daemon/old-helper is no worse than
	// today, and old-daemon/new-helper leaves node 1 in the un-bitted low half —
	// still today's behaviour, never a NEW collision.
	NodeID uint8 `json:"node_id,omitempty"`
	// #1620: cold-path latency histogram sample mask. *uint64 with
	// omitempty so a nil pointer omits the field entirely from the
	// wire (matching the Rust Option<u64>::None behavior). Default
	// at the Rust receiver: unwrap_or(0xff) = 1-in-256 sampling.
	// Powers-of-two-minus-one only (validated in cmd/xpfd/main.go).
	// Setting to a non-nil pointer to 0 explicitly enables 1-in-1
	// sampling (256× CPU cost) — operator must pass both
	// --cold-path-sample-mask 0 and --enable-cold-path-1-in-1-sampling.
	ColdPathSampleMask *uint64 `json:"cold_path_sample_mask,omitempty"`
	// ContentDigest (#9520) is hex SHA-256 over this snapshot's content, from
	// snapshotContentHash: Generation, FIBGeneration, GeneratedAt, Config and
	// ContentDigest itself are excluded, and neighbours count only if
	// publishable. requestApplySnapshotLocked stamps it immediately before
	// every apply_snapshot. The helper refuses an apply that reuses its
	// installed generation with a different digest: a retried republish
	// rebuilds its content, and installing new content under a generation
	// whose flow-cache and session-policy decisions were made for the old
	// content leaves those decisions fresh.
	ContentDigest string `json:"content_digest,omitempty"`
	// zoneIDCollisions is the manager-facing (#3719) record of every security
	// zone the snapshot builder QUARANTINED because its StableZoneID collided
	// with an earlier-sorting zone. It is unexported so it never rides the wire
	// or perturbs the snapshot hash (JSON ignores unexported fields), yet it
	// carries the diagnostic from the pure builder up to ApplyConfig, which
	// stamps it onto ProcessStatus.ZoneIDCollisions and fires the one-shot
	// operator alarm. Empty means no collision (the common case).
	zoneIDCollisions []ZoneIDCollision
	// partialUpdateEpoch (#9684) is Manager.partialUpdateEpoch as Compile read it
	// before building this snapshot (resampleForCompileLocked). Unexported, so it
	// never reaches the wire or the content hash.
	partialUpdateEpoch uint64
	// schedulerActiveState is manager-local metadata carried by a snapshot
	// between the build/defer and publish boundaries. It records the scheduler
	// state whose policy bits this snapshot contains so the applied/show cache
	// can advance only after the helper accepts the snapshot. It is
	// intentionally unexported, like zoneIDCollisions and partialUpdateEpoch:
	// encoding/json omits it from the wire, and snapshotContentHash (which
	// hashes the JSON encoding) therefore excludes it as well.
	schedulerActiveState    map[string]bool
	schedulerActiveStateSet bool
}

// AddressBookSnapshot is #1606: one row of the deduplicated address-book
// table. Multiple Junos-declared names whose canonical CIDR sets are
// identical share one row + one ID. Name is diagnostic-only
// (lexicographically smallest declaring name).
type AddressBookSnapshot struct {
	ID         uint32   `json:"id"`
	Name       string   `json:"name,omitempty"`
	PrefixesV4 []string `json:"prefixes_v4,omitempty"`
	PrefixesV6 []string `json:"prefixes_v6,omitempty"`
}

type FlowSnapshot struct {
	AllowDNSReply     bool `json:"allow_dns_reply,omitempty"`
	AllowEmbeddedICMP bool `json:"allow_embedded_icmp,omitempty"`
	TCPMSSAllTCP      int  `json:"tcp_mss_all_tcp,omitempty"`
	TCPMSSIPsecVPN    int  `json:"tcp_mss_ipsec_vpn,omitempty"`
	TCPMSSGreIn       int  `json:"tcp_mss_gre_in,omitempty"`
	TCPMSSGreOut      int  `json:"tcp_mss_gre_out,omitempty"`
	TCPSessionTimeout int  `json:"tcp_session_timeout,omitempty"` // seconds, 0=default
	// #7342: the three `security flow tcp-session` windows #6539 recorded as
	// having no wire carrier. Seconds, 0=unset (the helper keeps its default).
	// `omitempty` + Rust `serde(default)` is the repo's skew-tolerant additive
	// pattern (#1961): a helper that predates #7342 ignores them, and a Go
	// binary that predates it omits them, and in both directions every window
	// stays where it was.
	TCPInitialTimeout  int `json:"tcp_initial_timeout,omitempty"`
	TCPClosingTimeout  int `json:"tcp_closing_timeout,omitempty"`
	TCPTimeWaitTimeout int `json:"tcp_time_wait_timeout,omitempty"`
	UDPSessionTimeout  int `json:"udp_session_timeout,omitempty"`  // seconds, 0=default
	ICMPSessionTimeout int `json:"icmp_session_timeout,omitempty"` // seconds, 0=default
	// GREAcceleration carries `security flow gre-performance-acceleration`
	// (#3360). On vSRX this extracts the GRE key/call-id into the session tuple
	// so multiple GRE tunnels between the same endpoints map to distinct
	// sessions. The userspace dataplane keys GRE flows on the 5-tuple only, so
	// this threads the operator's intent into the Rust ForwardingState
	// (mirroring the PowerModeDisable plumbing) for config truth/parity; the bit
	// is NOT yet read by any forwarding path. The consumer (GRE key/call-id
	// extraction) is a deferred feature.
	GREAcceleration bool `json:"gre_acceleration,omitempty"`
	// PowerModeDisable carries `security flow power-mode-disable` (#2008 H14).
	// On vSRX power-mode is an express datapath; disabling it forces the
	// regular flow path. The userspace dataplane has a single forwarding path,
	// so this threads the operator's intent into ForwardingState (mirroring the
	// GREAcceleration plumbing) and is read on the Rust side for parity; it does
	// not currently alter packet handling (there is no express/regular split to
	// switch between).
	PowerModeDisable bool   `json:"power_mode_disable,omitempty"`
	Lo0FilterInputV4 string `json:"lo0_filter_input_v4,omitempty"` // lo0 inet input filter name
	Lo0FilterInputV6 string `json:"lo0_filter_input_v6,omitempty"` // lo0 inet6 input filter name
	// ALGDisableFlags carries the `security alg <proto> disable` bitfield
	// (bit 0: DNS, bit 1: FTP, bit 2: SIP, bit 3: TFTP — same layout as the
	// legacy flow_config_map FlowConfigValue.ALGFlags). The userspace
	// dataplane reads this to suppress ALG-type tagging for disabled ALGs
	// (#2008 H3/H4). Junos `alg disable` turns the ALG off; it does NOT drop
	// traffic, so the only enforced effect is that a session matching a
	// disabled ALG is no longer tagged with that ALG type.
	ALGDisableFlags uint8 `json:"alg_disable_flags,omitempty"`
}

type SnapshotSummary struct {
	HostName       string `json:"host_name"`
	DataplaneType  string `json:"dataplane_type"`
	InterfaceCount int    `json:"interface_count"`
	ZoneCount      int    `json:"zone_count"`
	PolicyCount    int    `json:"policy_count"`
	SchedulerCount int    `json:"scheduler_count"`
	HAEnabled      bool   `json:"ha_enabled"`
}

type InterfaceSnapshot struct {
	Name string `json:"name"`
	Zone string `json:"zone,omitempty"`
	// RoutingInstance is the bare routing-instance name this interface
	// belongs to ("" = the default instance). The Rust dataplane derives
	// the connected-route table (<ri>.inet.0 / <ri>.inet6.0, or
	// inet.0/inet6.0 for the default instance) from it so connected routes
	// rebuilt from interface addresses are table-scoped and do not leak
	// across VRF boundaries (#2388). Additive: an old Rust helper that does
	// not know the field treats every interface as the default instance
	// (the pre-#2388 global behavior); an old Go binary omits it.
	RoutingInstance string `json:"routing_instance,omitempty"`
	// RoutingDomain is the #7160 (#2387) ROUTING DOMAIN id for
	// RoutingInstance: `config.StableRoutingInstanceTableID(RoutingInstance)`
	// for a named instance, 0 for the default instance — except an interface
	// no surviving instance claims but a quarantined one does, which ships
	// QuarantinedRoutingInstanceDomain (2, #9956 F-032): nonzero so it never
	// shares the default session space, outside the stable band so it never
	// collides with a tenant, HA-refused on import. It is the discriminator
	// the Rust dataplane folds into `SessionKey.routing_domain` so two
	// routing instances that share a 5-tuple do not collapse to one
	// conntrack entry.
	//
	// It is computed HERE, in Go, rather than hashed independently on the
	// Rust side, because the number also has to survive a trip across the
	// HA session-sync wire: a value both nodes derive from the same config by
	// the same code cannot drift, whereas two implementations of one hash in
	// two languages is exactly the "when two spellings must agree" trap. The
	// band is [100000, 999999] (RoutingInstanceTableIDBase/Span), so a named
	// instance can never collide with the 0 that means "default instance",
	// and pkg/config's commit-time gate already refuses a name collision
	// inside the band.
	//
	// Additive: an old Rust helper that does not know the field treats every
	// interface as domain 0, which is the pre-#7160 behaviour exactly.
	RoutingDomain   uint32 `json:"routing_domain,omitempty"`
	LinuxName       string `json:"linux_name,omitempty"`
	ParentLinuxName string `json:"parent_linux_name,omitempty"`
	Ifindex         int    `json:"ifindex,omitempty"`
	ParentIfindex   int    `json:"parent_ifindex,omitempty"`
	LogicalOnly     bool   `json:"logical_only,omitempty"`
	RXQueues        int    `json:"rx_queues,omitempty"`
	VLANID          int    `json:"vlan_id,omitempty"`
	LocalFabric     string `json:"local_fabric_member,omitempty"`
	RedundancyGroup int    `json:"redundancy_group,omitempty"`
	// EgressZone is the security zone this row's IFINDEX egresses into, or "" for
	// none (#6722). It is the ANSWER, decided in stampEgressZones (interfaces.go)
	// where the operator's authored `security-zone ... interfaces <ref>` bindings
	// and snapshotLinuxName's aliasing are both in hand. Every row sharing an
	// ifindex carries the SAME value.
	//
	// It is NOT Zone with a different name. Zone is this row's own zone as
	// buildInterfaceZoneMap derived it, and is what the INGRESS half attributes an
	// arriving packet to (#921/#3618, unchanged). EgressZone answers the different
	// question the egress half must ask — "does this ifindex identify exactly one
	// zone" — for a netdev that several configured identities may share.
	//
	// The Rust helper honours it only when some row on the ifindex literally
	// carries that zone NAME (forwarding_build::interfaces::populate_interfaces),
	// so a drifted or hostile snapshot can never conjure a zone no row on the
	// ifindex named. That is the whole of the helper-side check: there is no row
	// classification left for a config shape to disagree with.
	//
	// Emitted UNCONDITIONALLY (no omitempty), so a "" answer is on the wire as a
	// DECISION — this Go binary determined the ifindex identifies no zone — and
	// resolves the 0 sentinel. There is no "the field was absent" arm to fall
	// back to; the compatibility arm that used to exist was deleted with the
	// row-unanimity rule it restored.
	//
	// THAT IS A DESIGN STATEMENT, NOT A BEHAVIOURAL GUARD, and the difference is
	// worth stating because it reads like one. The Rust side declares
	// `#[serde(rename = "egress_zone", default)]` (snapshot.rs), so an ABSENT
	// key and an emitted "" decode identically: both give `String::new()`, which
	// `EgressZoneClaim::Decided("")` resolves to `None` and the 0 sentinel.
	// Adding `omitempty` here would therefore change no answer the helper gives,
	// and no test can red on it — the one Go wire pin,
	// TestEgressZoneCrossesTheWireAndTheQuarantine_6722, asserts the NONEMPTY
	// case, which omitempty does not touch. The tag is kept because "the builder
	// always states its answer" is the property this field is FOR, and because a
	// future `deny_unknown_fields` or a non-defaulting decoder would make the
	// two spellings diverge; it is not kept because something would catch its
	// removal today.
	//
	// MIXED VERSION IS REFUSED, NOT TOLERATED. ProtocolVersion moved 4 -> 5 in
	// this change (see the constant above), and ensureEgressZoneProtocolLocked
	// (manager_compile.go) refuses to commit against a helper whose observed
	// version is anything else. That is a departure from the sibling gates: this
	// repo has previously bumped only when an old reader MISREADS a snapshot
	// into a wrong answer (#5488's ErrScopedGlobalZoneSetProtocolIncompatible —
	// an old helper reads only the singular match_from_zone and NARROWS a global
	// deny, a fail-OPEN). Neither direction here misreads, so the bump is not
	// forced by that rule; it is taken because a mixed window silently loses the
	// fix, and losing it silently is what this PR exists to stop:
	//
	//	new Go -> OLD helper: the wire shape this builder emits deserializes on
	//	  a v4 helper (there is no deny_unknown_fields anywhere in
	//	  userspace-dp/src/protocol, at c9b020695 or here) — it reads
	//	  reth_projection=false from serde's default and answers ledger[24]=None,
	//	  to_zone=0, action=Deny. Measured by running that helper against this
	//	  builder's output.
	//	old Go -> NEW helper: the retired `reth_projection` key is ignored and
	//	  `egress_zone` is absent, which serde fills with the empty String —
	//	  the fail-closed 0 sentinel. Pinned by
	//	  retired_wire_key_decodes_and_absent_egress_zone_fails_closed_6722
	//	  (userspace-dp/src/afxdp/forwarding/tests.rs).
	//
	// Neither direction invents a zone; both would blackhole a bondless-RETH
	// cluster exactly as the pre-#6722 tree did. What the gate changes is that
	// the commit ABORTS with a named sentinel and DISARMS the helper instead of
	// promoting an image the dataplane cannot honour — see
	// TestEgressZoneProtocolAbortDisarmsAndPublishesNothing_6722 for the
	// measured wire behaviour, including that no apply_snapshot is sent.
	EgressZone string `json:"egress_zone"`
	UnitCount  int    `json:"unit_count"`
	Tunnel     bool   `json:"tunnel"`
	// SecureTunnel reports that this row's netdev is a route-based IPsec
	// tunnel device, so the dataplane must neither adjudicate nor bind it.
	//
	// TWO ORACLES, ONE CLAIM (#6691 round 8, snapshotSecureTunnel):
	//
	//   - CONFIG. Some `security ipsec vpn <name> bind-interface` NAMES this
	//     row's xfrmi device (Config.SecureTunnelNetdevForRef).
	//   - KERNEL. The netdev this row resolves to has link kind `xfrm`
	//     (liveXfrmNetdevs). This half exists because every config-keyed
	//     predicate is blind to a device the config no longer describes: a
	//     failed LinkDel retains the xfrmi (pkg/routing, #4901) while the
	//     apply proceeds on a deferred error, and a daemon restart leaves an
	//     untracked one that no sweep enumerates. Only the kernel knows.
	//
	// The two cover different instants, so the flag is their union and neither
	// is redundant. The instant that matters is narrower than "the commit that
	// creates a tunnel", though: on the NORMAL apply path the daemon's
	// interface/xfrmi reconcile runs BEFORE snapshot construction, so the
	// device usually exists by the time the builder samples and the kernel half
	// sees it. The config half is load-bearing where reconciliation has not run
	// or did not succeed — a build that precedes it, or an xfrmi routing failed
	// to create — not for every creation commit.
	//
	// It is OWNERSHIP or DEVICE KIND, never name shape: nothing reserves the
	// `st` prefix, so a wildcard-authored `st5` with no VPN is an ordinary
	// data interface, is not an xfrm device, and this stays false (#6691).
	//
	// The field's MEANING, type and JSON tag are unchanged by the kernel half;
	// what changed is the evidence the control plane accepts for the same
	// claim. The version still moved to 6 in #6691 round 9, for a different
	// reason: the REFUSAL RULE this flag feeds changed within the PR (ANY
	// owner -> EVERY owner), so two helpers at the same number would plan
	// different bindings for identical bytes.
	//
	// It is NOT read by one consumer. include_userspace_binding_interface was
	// the only one when round 8 wrote that; userspace_unbindable_netdev and,
	// through it, snapshot_refuses_parent_netdev / binding_target_is_refused
	// read it too (planning.rs), which is how a VLAN child's redirect is
	// refused.
	//
	// "Names the device", not "derives the if_id" — the two differ, and the
	// difference was a defect (#6691 round 6). strconv.Atoi erases a leading
	// `+` and leading zeros, so `bind-interface st05` derives the SAME if_id
	// as `st5` under a DIFFERENT device name; keying on the if_id alone set
	// this flag on a NIC no VPN names, taking it out of the dataplane.
	//
	// "THIS ROW's device", and the row decides which name that is (#6691
	// round 7). A UNIT row's netdev comes from the authored bind-interface,
	// so `st5.0` is the xfrmi under either spelling. A BASE row's netdev is
	// `LinuxIfName(ifName)` — literally `st5` — so it is the xfrmi only under
	// a bare `bind-interface st5`. Round 6 compared only the base part of
	// each name, which set this flag on the `st5` row for a VPN whose device
	// is `st5.0`, and a live NIC lost its AF_XDP/RSS binding to it.
	//
	// Additive: an old Rust helper that does not know the field treats every
	// interface as not-a-secure-tunnel, so an xfrmi would get an AF_XDP
	// binding it cannot use — the #5619 GAP, which both planes' comments
	// already rank as less bad than the outage over-matching causes. An old
	// Go binary omits it.
	SecureTunnel              bool                       `json:"secure_tunnel,omitempty"`
	MTU                       int                        `json:"mtu,omitempty"`
	HardwareAddr              string                     `json:"hardware_addr,omitempty"`
	Addresses                 []InterfaceAddressSnapshot `json:"addresses,omitempty"`
	FilterInputV4             string                     `json:"filter_input_v4,omitempty"`
	FilterOutputV4            string                     `json:"filter_output_v4,omitempty"`
	FilterInputV6             string                     `json:"filter_input_v6,omitempty"`
	FilterOutputV6            string                     `json:"filter_output_v6,omitempty"`
	CoSShapingRateBytesPerSec uint64                     `json:"cos_shaping_rate_bytes_per_sec,omitempty"`
	CoSBurstSize              uint64                     `json:"cos_shaping_burst_bytes,omitempty"`
	CoSSchedulerMap           string                     `json:"cos_scheduler_map,omitempty"`
	CoSDSCPClassifier         string                     `json:"cos_dscp_classifier,omitempty"`
	CoSIEEE8021Classifier     string                     `json:"cos_ieee8021_classifier,omitempty"`
	// CoSINetPrecedenceClassifier (#6847) is the unit's `classifiers
	// inet-precedence <name>` binding. Mutually exclusive with
	// CoSDSCPClassifier — both classify the same DS field, so the commit gate
	// rejects binding both; on the tolerant load path (warn) the dataplane
	// consults DSCP first, so DSCP wins.
	CoSINetPrecedenceClassifier string `json:"cos_inet_precedence_classifier,omitempty"`
	CoSDSCPRewriteRule          string `json:"cos_dscp_rewrite_rule,omitempty"`
	// #1614 A1: operator-selectable oversubscription policy. "" or
	// "proportional" (default) preserves current scheduler bit-for-
	// bit (when CoSPriorityLowMinShareBytes is also 0). "guarantee-
	// rate" activates the two-phase waterfill allocator using
	// CoSOversubscriptionGuaranteeFraction.
	CoSOversubscriptionPolicy string `json:"cos_oversubscription_policy,omitempty"`
	// #1614 A1: Phase 1 budget fraction (0.0..1.0). Only meaningful
	// when CoSOversubscriptionPolicy == "guarantee-rate". 0.0 makes
	// the allocator a no-op even if the policy string is set.
	CoSOversubscriptionGuaranteeFraction float64 `json:"cos_oversubscription_guarantee_fraction,omitempty"`
	// #1614 A2: priority-low minimum share in bytes per second.
	// WIRE SURFACE ONLY in PR #1618 — the per-pass cap_eff
	// subtraction in the Rust selector is deferred to a focused
	// follow-up. Default 0 (no min-share); no hot-path effect
	// today.
	CoSPriorityLowMinShareBytes uint64 `json:"cos_priority_low_min_share_bytes,omitempty"`
	// HostInbound* carry the per-interface host-inbound-traffic OVERRIDE
	// (#3362). Junos models host-inbound at both the zone level (ZoneSnapshot
	// above) and the interface level; an interface that declares an
	// interface-level stanza is described ENTIRELY by it — the zone-level set is
	// REPLACED, not unioned (#6515). These fields carry that already-resolved
	// effective set and are
	// populated ONLY for an interface that declared an interface-level stanza
	// (and is not a management/cluster-control lifeline). When present the Rust
	// dataplane keys the host-inbound admission check by ingress interface
	// (ifindex) instead of the from-zone, so a service exposed on one interface
	// of a zone is admitted there while the zone-default set governs the rest.
	// Additive: an old Rust helper without the fields ignores them and falls
	// back to the zone-keyed check (pre-#3362 behaviour); an old Go binary omits
	// them (omitempty). HostInboundConfigured distinguishes a present-but-empty
	// override (enforcing, deny-all) from an absent one (zone-keyed fallback).
	HostInboundConfigured     bool     `json:"host_inbound_configured,omitempty"`
	HostInboundSystemServices []string `json:"host_inbound_system_services,omitempty"`
	HostInboundProtocols      []string `json:"host_inbound_protocols,omitempty"`
	// IsUnit is the STRUCTURAL row identity: true when this row was emitted
	// for a logical unit, false for an interface (base) row (#9821 #22).
	// Name shape cannot answer this — a declared interface may itself
	// contain a dot (`ge-0/0/5.0`), so "contains a dot" reads a dotted base
	// row as a unit row. The builder knows which loop emitted the row and
	// states it here instead of making every consumer re-derive it.
	//
	// Emitted UNCONDITIONALLY (no omitempty): false is the base-row answer,
	// not an absence. The Rust side reads `Option<bool>` — `Some` is
	// structural, `None` (old Go, tests, fixtures) falls back to the legacy
	// name parse, which is old-Go behavior exactly.
	//
	// BUMPED 20 -> 21 with this field, by the v9 rule: an old helper parses
	// every row by name shape, so a v20 helper would read a dotted base row
	// as a unit row — and that misread IS the defect the field closes, not
	// an acceptable degradation. Exact equality refuses the pairing both
	// ways (see the v21 note on ProtocolVersion).
	IsUnit bool `json:"is_unit"`
}

type FabricSnapshot struct {
	Name            string `json:"name"`
	ParentInterface string `json:"parent_interface,omitempty"`
	ParentLinuxName string `json:"parent_linux_name,omitempty"`
	ParentIfindex   int    `json:"parent_ifindex,omitempty"`
	// ParentUnbindable is the device-level verdict for the parent netdev: the
	// userspace dataplane must never bind an AF_XDP socket to it (#6691 round
	// 10, fabricParentUnbindable).
	//
	// It rides on the wire because a fabric MEMBER NEEDS NO INTERFACE STANZA,
	// so the parent netdev routinely has no InterfaceSnapshot to carry the
	// flags — and the Rust plane, which runs the mirror of the Go unanimity
	// tally, cannot recompute the verdict from what it has: the kernel-kind
	// half of the secure-tunnel evidence is a Go-side RTM_GETLINK dump.
	//
	// NOT omitempty, for the same reason as Up below: this field decides
	// whether a netdev enters the ingress-adjudication map and the AF_XDP
	// binding plan, and an operator reading a snapshot dump is entitled to see
	// the verdict rather than infer it from an absence. An absent field decodes
	// to false (bindable) in Rust, which is the pre-round-10 behaviour, and is
	// why the protocol version moved to 7 — a v6 reader silently plans the
	// binding this flag exists to refuse.
	ParentUnbindable bool   `json:"parent_unbindable"`
	OverlayLinux     string `json:"overlay_linux_name,omitempty"`
	OverlayIfindex   int    `json:"overlay_ifindex,omitempty"`
	RXQueues         int    `json:"rx_queues,omitempty"`
	PeerAddress      string `json:"peer_address,omitempty"`
	LocalMAC         string `json:"local_mac,omitempty"`
	PeerMAC          string `json:"peer_mac,omitempty"`
	// Up is the local fabric parent link's carrier/oper state (#4082). The
	// Rust dataplane prefers an UP fabric when resolving the cross-chassis
	// redirect, so a dual-fabric cluster fails over to the secondary when the
	// primary parent drops. This field MUST NOT be omitempty: a genuinely-down
	// fabric has to serialize "up":false, not drop the field — the Rust decoder
	// defaults an absent field to true (fail-open), so dropping it on down
	// would defeat the failover.
	Up bool `json:"up"`
}

// FlowExportSnapshot captures flow monitoring/export configuration for the
// userspace dataplane.
type FlowExportSnapshot struct {
	CollectorAddress string `json:"collector_address"`
	CollectorPort    int    `json:"collector_port"`
	SamplingRate     int    `json:"sampling_rate"`
	ActiveTimeout    int    `json:"active_timeout,omitempty"`   // seconds, 0=default 60
	InactiveTimeout  int    `json:"inactive_timeout,omitempty"` // seconds, 0=default 15
}

// MirrorConfigSnapshot captures one ingress SPAN mapping for userspace-dp.
// It is snapshot/admission state only until the userspace runtime clone path is
// wired. Runtime delivery must use full-L2 cross-binding inject; the L3 TUN
// slow-path is not a valid mirror sink because it strips Ethernet framing.
type MirrorConfigSnapshot struct {
	IngressIfindex int    `json:"ingress_ifindex"`
	OutputIfindex  int    `json:"output_ifindex"`
	Rate           uint32 `json:"rate"`
}

type InterfaceAddressSnapshot struct {
	Family  string `json:"family"`
	Address string `json:"address"`
	Scope   int    `json:"scope,omitempty"`
}

type UserspaceMapPins struct {
	Ctrl        string `json:"ctrl,omitempty"`
	Bindings    string `json:"bindings,omitempty"`
	Heartbeat   string `json:"heartbeat,omitempty"`
	XSK         string `json:"xsk,omitempty"`
	LocalV4     string `json:"local_v4,omitempty"`
	LocalV6     string `json:"local_v6,omitempty"`
	Sessions    string `json:"sessions,omitempty"`
	ConntrackV4 string `json:"conntrack_v4,omitempty"`
	ConntrackV6 string `json:"conntrack_v6,omitempty"`
	DnatTable   string `json:"dnat_table,omitempty"`
	DnatTableV6 string `json:"dnat_table_v6,omitempty"`
	Trace       string `json:"trace,omitempty"`
}

type UserspaceCapabilities struct {
	ForwardingSupported bool     `json:"forwarding_supported"`
	UnsupportedReasons  []string `json:"unsupported_reasons,omitempty"`
	// PolicyContentRejected lists the reasons the published snapshot carries
	// the reserved __unsupported__ sentinel term and will be REJECTED by the
	// helper's non-mutating integrity preflight (the #2124 fail-closed family).
	// UNLIKE UnsupportedReasons, these entries do NOT disarm the helper
	// (#3261): the snapshot still publishes, the current helper rejects it via
	// SnapshotIntegrityError and KEEPS the previous-good PolicyState (running
	// node) or leaves the default-deny PolicyState (fresh boot) — it never
	// fails open to the kernel. Setting ForwardingSupported=false for this
	// class instead DISARMS the helper, so the XDP shim XDP_PASSes transit to
	// the kernel and bypasses the integrity reject — the system-level
	// fail-OPEN #3261 closes. Go-side diagnostic only; omitempty so
	// representable configs keep their exact wire shape (and snapshot hash).
	// The Rust helper has no field for this and (lacking deny_unknown_fields)
	// silently ignores it on decode.
	PolicyContentRejected []string `json:"policy_content_rejected,omitempty"`
}

// SYNCookieKeyRingSnapshot is the #9173 SYN-cookie key ring; see
// ConfigSnapshot.SYNCookieKeyRing and buildSYNCookieKeys.
type SYNCookieKeyRingSnapshot struct {
	// PeriodSecs is the rotation period. It must be a whole number of 64-second
	// cookie epochs, or the helper fails the ring closed.
	PeriodSecs uint64                     `json:"period_secs"`
	Bases      []SYNCookieKeyBaseSnapshot `json:"bases"`
}

// SYNCookieKeyBaseSnapshot is one ring base: 64 hex characters for the 32-byte
// HMAC key every period's key derives from, and whether those keys are only
// accepted and never minted with (a #6630 additional-authentication-key base).
type SYNCookieKeyBaseSnapshot struct {
	Base       string `json:"base"`
	AcceptOnly bool   `json:"accept_only,omitempty"`
}
