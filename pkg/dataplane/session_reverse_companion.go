package dataplane

// The reverse companion's "not yet observed" reset (#7917).
//
// When a forward session is installed, a REVERSE companion is synthesized for
// it so the reply direction is already present before it is needed. The
// companion is built by copying the forward value and adjusting the parts that
// are direction-dependent — the zone pair is swapped, `IsReverse` is set, and
// `ReverseKey` points back.
//
// Some fields must additionally be CLEARED, because they record an OBSERVATION
// the reverse direction has not made yet:
//
//   - the cached FIB result. It is the forward direction's resolved egress; the
//     reply's egress is a different lookup and must be re-resolved locally.
//   - the #4983 ingress identity. `pkg/dataplane/types.go` names the reverse
//     companion as the first legitimate-`0` population and gives the reason:
//     "its own ingress has not been OBSERVED yet ... the forward flow's egress
//     IS known at install — it is the wrong datum, being a PREDICTION of where
//     the reply will arrive rather than an OBSERVATION of where it did, and
//     routing may be asymmetric."
//
// WHY THIS IS NOT `ScrubNodeLocal` (#7097), THE OTHER RESET OVER THESE FIELDS.
// The two overlap but are different rules, and as of #7095 they no longer even
// cover the same fields:
//
//   - `ScrubNodeLocal` strips values that BELONG TO ANOTHER NODE. It must NOT
//     touch `IngressIfaceFold`, whose entire purpose is to be cluster-stable and
//     cross the wire so the #4983 identity survives a failover.
//   - this reset strips values the reverse direction HAS NOT OBSERVED. It MUST
//     clear `IngressIfaceFold`, because "where the first packet arrived" is
//     exactly as unobserved for the reply as the node-local ifindex is — and the
//     helper wire request derives its ingress identity FROM the fold
//     (`buildSessionSyncRequestV4` -> `resolveIngressFold`), so leaving it set
//     stamps the FORWARD direction's ingress binding onto the companion.
//
// Folding the two would make every future node-local field automatically a
// reverse-companion reset, and every future companion reset automatically a
// cross-node scrub. Neither implication holds.
// `TestCompanionResetAndNodeLocalScrubAreDifferentRules7917` pins the divergence.

// NO CALLER IN TREE SINCE #8015, AND THAT IS THE POINT. #8015 deleted the Go
// control plane's explicitly built reverse companion (`mirrorSessionPairV4` /
// `...V6`): the session mirror sends the forward alone and the Rust helper
// synthesizes the companion itself, at import, against live node-local state.
// The RULE this file states did not go with it — it moved to
// `synthesized_synced_reverse_entry` (`userspace-dp/src/afxdp/shared_ops.rs`),
// which sets `ingress_ifindex: 0` / `ingress_vlan_id: 0` for the same reason
// and is pinned by
// `synthesized_synced_reverse_entry_carries_no_ingress_identity_7917`.
//
// This declaration stays because the rule is the part worth keeping: the census
// test below pins its divergence from `ScrubNodeLocal`, so a future node-local
// field cannot silently become a companion reset or vice versa, and anything in
// `pkg/dataplane` that builds a companion again has one correct answer to reach
// for instead of a fresh hand-written list. That is exactly the failure #7097
// documents.

// FibGen IS CONDITIONALLY UNOBSERVED (#8612), and the conditional below is
// written out in each twin rather than shared, exactly as ScrubNodeLocal writes
// its list out twice: the two structs are separate declarations and the census
// reaches both.
//
// THIS RESET SWEPT FibGen UP BY NAME, WHICH IS THE MISTAKE #8612 HAD TO UNDO
// ONE FILE OVER. `LogFlagUserspaceTunnelEndpoint` says FibGen is not a FIB
// generation at all: it is `config.StableTunnelEndpointID(ifName)`, an FNV-1a
// fold of the interface NAME, which pkg/config/tunnelid.go documents as
// crossing the cluster in this exact field, identical on both nodes by
// construction. A name-derived identity is not an OBSERVATION, so the rule this
// function states — "clear what the reverse direction has not observed yet" —
// does not reach it. The reply direction of a tunnelled session traverses the
// same tunnel; that is config, not a measurement of the first packet.
//
// #8612 corrected ScrubNodeLocal for exactly this reason. It did not correct
// THIS function, and the reason is stated at the top of the file: since #8015
// there has been no caller, so nothing could make the staleness observable.
// K74 (#8597) adds the first callers back, which is precisely when the claim
// has to be re-checked — an unfalsifiable claim in inert code is not a
// verified one.
//
// What zeroing it would have cost is on the record in session_node_local.go:
// "sessionSyncEgressLocked(0) and sessionSyncTunnelEndpointIDLocked(0) both
// seed from a scrubbed ifindex and return 0 ... so a peer-imported tunnel
// session was resolved as if it were not a tunnel session at all". FibGen is
// carried in the on-map ABI (bpf_session_value.go), unlike IngressIfaceFold, so
// this one is not merely theoretical at the install sites.

// ResetUnobservedForReverseCompanion clears every field that records something
// the REVERSE direction has not observed yet. Call it on the copy destined to
// become a forward session's reverse companion, after the zone swap.
func (v *SessionValue) ResetUnobservedForReverseCompanion() {
	// Forward egress — the reply's egress is a separate lookup.
	v.FibIfindex = 0
	v.FibVlanID = 0
	v.FibDmac = [6]byte{}
	v.FibSmac = [6]byte{}
	// #8612: NOT unconditionally — see the note above this function.
	if v.LogFlags&LogFlagUserspaceTunnelEndpoint == 0 {
		v.FibGen = 0
	}
	// Forward ingress — where the reply will arrive is a prediction, not an
	// observation, and routing may be asymmetric.
	v.IngressIfindex = 0
	v.IngressVlanID = 0
	v.IngressIfaceFold = 0
	// #9752 round 5: the installing-table identity is the FORWARD steer
	// outcome. A reverse companion resolving by it would re-resolve in a
	// table chosen for the other direction — companions stamp (0,0) (R1).
	v.InstallTableDomain = 0
	v.InstallTableCheck = 0
}

// ResetUnobservedForReverseCompanion is the IPv6 twin.
func (v *SessionValueV6) ResetUnobservedForReverseCompanion() {
	v.FibIfindex = 0
	v.FibVlanID = 0
	v.FibDmac = [6]byte{}
	v.FibSmac = [6]byte{}
	// #8612: see the v4 twin and the note above it.
	if v.LogFlags&LogFlagUserspaceTunnelEndpoint == 0 {
		v.FibGen = 0
	}
	v.IngressIfindex = 0
	v.IngressVlanID = 0
	v.IngressIfaceFold = 0
	// #9752 round 5: v6 twin — see above.
	v.InstallTableDomain = 0
	v.InstallTableCheck = 0
}
