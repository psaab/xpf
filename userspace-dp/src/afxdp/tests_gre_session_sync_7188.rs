// #7188: two RFC 2890 GRE tunnels between ONE pair of outer endpoints must
// survive HA session sync as TWO sessions.
//
// THE FIXTURE IS THE WHOLE TEST. A test that syncs ONE keyed tunnel passes
// whether or not the discriminator crosses the wire, because a single session
// has nothing to alias with. The defect only exists when two records share a
// 5-tuple — GRE is protocol 47 and has no L4 ports, so two tunnels between the
// same outer endpoints ARE one 5-tuple — and `install.rs` opens with an
// unconditional `remove_entry`, so the second install lands on the first.
//
// Before this change `build_synced_session_key` hardcoded
// `discriminator: Default::default()`, and `Default` for `TunnelDiscriminator`
// is `None` — the "no discriminator concept for this protocol" class, not even
// `Unkeyed`. Both records therefore rebuilt to the SAME key: one session for
// two tunnels, so after a failover they shared one policy decision, one NAT
// state, one counter set and one timeout.

use super::*;
use crate::ip_proto::{PROTO_GRE, PROTO_TCP};
use crate::server::helpers::{build_synced_session_entry, build_synced_session_key, SyncedKeyIntent};
use crate::session::TunnelDiscriminator;
use crate::test_zone_ids::*;
use crate::SessionSyncRequest;

/// One peer sync record for a transit session between a fixed pair of outer
/// endpoints. Everything except `protocol` and the discriminator is held
/// constant on purpose: the whole point is that two calls differing ONLY in the
/// discriminator must not collapse.
fn gre_sync_req(protocol: u8, discriminator: u64) -> SessionSyncRequest {
    SessionSyncRequest {
        operation: "upsert".to_string(),
        addr_family: libc::AF_INET as u8,
        protocol,
        src_ip: "198.51.100.7".to_string(),
        dst_ip: "203.0.113.9".to_string(),
        // Protocol 47 has no L4 ports. These zeros are exactly what the shim's
        // `parse_l4` catch-all stamps, and they are why the 5-tuple cannot tell
        // two tunnels apart on its own.
        src_port: 0,
        dst_port: 0,
        ingress_zone_id: TEST_TRUST_ZONE_ID,
        egress_zone_id: TEST_UNTRUST_ZONE_ID,
        tunnel_discriminator: discriminator,
        ..SessionSyncRequest::default()
    }
}

/// THE fixture. Two keyed tunnels, keys 100 and 200, identical outer endpoints.
///
/// FAIL-ON-REVERT: restore `discriminator: Default::default()` in
/// `build_synced_session_key` and both records rebuild to one key, so the
/// synced map holds ONE entry and this asserts 2.
#[test]
fn two_keyed_gre_tunnels_sharing_a_5_tuple_sync_as_two_sessions_7188() {
    let coordinator = Coordinator::new();
    let zones = rustc_hash::FxHashMap::default();

    for key in [100u32, 200u32] {
        let req = gre_sync_req(PROTO_GRE, TunnelDiscriminator::Keyed(key).to_wire());
        let entry = build_synced_session_entry(&req, &zones, 0)
            .unwrap_or_else(|e| panic!("keyed-GRE tunnel {key} must import: {e}"));
        assert_eq!(
            entry.key.discriminator,
            TunnelDiscriminator::Keyed(key),
            "the rebuilt key must carry the RFC 2890 key the peer sent, not the \
             `Default::default()` (`None`) class every synced session used to land in"
        );
        assert!(matches!(
            coordinator.upsert_synced_session(entry),
            SyncedImportOutcome::Applied
        ));
    }

    let synced = coordinator
        .sessions
        .synced
        .lock()
        .expect("shared synced sessions");
    let forward: Vec<_> = synced
        .iter()
        .filter(|(key, _)| key.protocol == PROTO_GRE && !synced[key].metadata.is_reverse)
        .map(|(key, _)| key.discriminator)
        .collect();
    assert_eq!(
        forward.len(),
        2,
        "two RFC 2890 tunnels between the same outer endpoints must be TWO synced \
         sessions. One means the standby aliased them onto a single key, so after a \
         failover both tunnels share one policy decision, one NAT state, one counter \
         set and one timeout — the exact collapse #7188 exists to prevent, restored \
         silently by the failover. Discriminators present: {forward:?}"
    );
    assert!(forward.contains(&TunnelDiscriminator::Keyed(100)));
    assert!(forward.contains(&TunnelDiscriminator::Keyed(200)));

    // #8103 FIXED, and this is where it is measured. The REVERSE companions
    // used to be ONE shared entry: all five `SessionKey` transforms in
    // `session/key.rs` built their output with `discriminator:
    // Default::default()`, preserving the sibling `routing_domain` and dropping
    // this field, so two tunnels' reverse keys differed in nothing (protocol 47
    // has no L4 ports) and the second publish evicted the first. The map held
    // THREE rows, not four.
    //
    // It now holds four. Asserted rather than described, because the previous
    // version of this block stated the row count in prose and prose does not
    // fail when the behaviour changes — in either direction.
    let reverse: Vec<_> = synced
        .iter()
        .filter(|(key, _)| key.protocol == PROTO_GRE && synced[key].metadata.is_reverse)
        .map(|(key, _)| key.discriminator)
        .collect();
    assert_eq!(
        reverse.len(),
        2,
        "each keyed tunnel must have its OWN reverse companion (#8103). One \
         means they still share it, so a reply resolves whichever tunnel \
         published last — and with `gre-performance-acceleration` on, a reply \
         may match no session at all, because it is parsed as `Keyed(k)` while \
         the stored companion is keyed `None`. Discriminators present: \
         {reverse:?}"
    );
    assert!(reverse.contains(&TunnelDiscriminator::Keyed(100)));
    assert!(reverse.contains(&TunnelDiscriminator::Keyed(200)));
}

/// #7188 decision 2, the fail-closed half: a peer that does NOT carry the
/// discriminator has its keyed-GRE sessions WITHHELD, not downgraded to a
/// 5-tuple record. Withholding is the conservative direction — the peer misses
/// the session and re-learns it, rather than installing a record that aliases
/// two tunnels.
///
/// The refusal is reported with the machine-readable refusal prefix, not as a
/// bare error, because it is the CORRECT answer from a HEALTHY helper: Go
/// discriminates on that token and a transport-class failure would gate
/// takeover-readiness (#5247) on a node that is working.
#[test]
fn a_peer_that_cannot_express_the_discriminator_has_its_gre_session_withheld_7188() {
    let zones = rustc_hash::FxHashMap::default();
    // Tag 0 is what `#[serde(default)]` and a short length-gated record both
    // produce, i.e. exactly what an older daemon sends.
    let req = gre_sync_req(PROTO_GRE, 0);
    let err = build_synced_session_entry(&req, &zones, 0).expect_err(
        "a protocol-47 record whose peer could not state the discriminator must be \
         WITHHELD; importing it guesses which of two tunnels it names, and the \
         install's unconditional remove_entry makes that guess EVICT the other",
    );
    assert!(
        err.starts_with(SYNCED_IMPORT_REFUSED_PREFIX),
        "the withhold is a semantic refusal from a healthy helper, so it must carry \
         the refusal prefix Go matches on rather than reading as a transport \
         failure that gates takeover-readiness (#5247): {err}"
    );
}

/// The CONTROL for the test above, and the reason the gate keys on ABSENCE
/// rather than on "protocol 47".
///
/// With `gre-performance-acceleration` off a GRE session's identity would be
/// `None`, and a NEW peer states that explicitly. (Today #6837 leaves such a
/// session flowless so none is created — the gate deliberately does not depend
/// on that staying true.) An explicit `None` is a statement; tag 0 is the
/// absence of one, and only the absence may be refused.
#[test]
fn an_explicitly_stated_none_on_protocol_47_still_imports_7188() {
    let zones = rustc_hash::FxHashMap::default();
    let req = gre_sync_req(PROTO_GRE, TunnelDiscriminator::None.to_wire());
    let entry = build_synced_session_entry(&req, &zones, 0).expect(
        "an explicit `None` from a peer that CAN express the discriminator is a \
         statement about the session, not an inability to make one",
    );
    assert_eq!(entry.key.discriminator, TunnelDiscriminator::None);
}

/// Every non-tunnel protocol is untouched by the fail-closed gate, including
/// from a peer that carries nothing. `None` is what those sessions have always
/// been keyed on, so this arm is bit-identical to the pre-#7188 import.
#[test]
fn a_legacy_peers_non_gre_session_still_imports_as_none_7188() {
    let zones = rustc_hash::FxHashMap::default();
    let mut req = gre_sync_req(PROTO_TCP, 0);
    req.src_port = 5001;
    req.dst_port = 443;
    let entry = build_synced_session_entry(&req, &zones, 0)
        .expect("a legacy peer's TCP session must still import unchanged");
    assert_eq!(entry.key.discriminator, TunnelDiscriminator::None);
}

/// A DELETE reconstructs the same key but wants the opposite answer when the
/// peer could not state the discriminator.
///
/// The cluster delete message carries the key and the #2170 delete generation
/// only — there is no value to hang a discriminator on — so every delete
/// arrives with tag 0. Refusing them would turn a legacy peer's ordinary GRE
/// close into an error response for no gain: a key rebuilt without a
/// discriminator names the `None` class alone, so a delete can only
/// UNDER-match. Under-matching never merges two identities, which is exactly
/// why the install arm fails closed and this one does not.
#[test]
fn a_delete_without_a_discriminator_is_not_refused_7188() {
    let key = build_synced_session_key(
        &gre_sync_req(PROTO_GRE, 0),
        0,
        SyncedKeyIntent::Delete,
    )
    .expect("a delete for a protocol-47 key must not be refused");
    assert_eq!(
        key.discriminator,
        TunnelDiscriminator::None,
        "a delete with no stated discriminator must name the `None` class only, so \
         it under-matches instead of retracting a keyed tunnel it cannot name"
    );
}

/// The four classes are disjoint locally (decision 6); they must stay disjoint
/// after a round trip through the sync path. Asserted over the whole set at the
/// KEY level — where the aliasing actually happens — rather than only over the
/// wire codec, so a key builder that dropped or coerced a class would be caught
/// here even if the codec round-tripped.
#[test]
fn every_discriminator_class_survives_the_sync_path_distinctly_7188() {
    let classes = [
        TunnelDiscriminator::None,
        TunnelDiscriminator::Unkeyed,
        TunnelDiscriminator::Unparseable,
        TunnelDiscriminator::Keyed(0),
        TunnelDiscriminator::Keyed(1),
        TunnelDiscriminator::Keyed(u32::MAX),
    ];
    let mut keys = std::collections::HashSet::new();
    for class in classes {
        let key = build_synced_session_key(
            &gre_sync_req(PROTO_GRE, class.to_wire()),
            0,
            SyncedKeyIntent::Install,
        )
        .unwrap_or_else(|e| panic!("{class:?} must rebuild: {e}"));
        assert_eq!(key.discriminator, class);
        assert!(
            keys.insert(key),
            "{class:?} rebuilt to a key equal to another class's. `Unkeyed` is not \
             `Keyed(0)` and `Unparseable` is not `Unkeyed` (#7188 decision 6): a \
             malformed header must not merge into a legitimate session, and an \
             unkeyed tunnel must not join a keyed-zero one"
        );
    }
}

#[test]
fn ipsec_if_id_sync_tag_round_trips_and_unknown_tags_refuse_import_9506() {
    let if_id = 0x1234_5678;
    let mut req = gre_sync_req(
        PROTO_TCP,
        TunnelDiscriminator::Ipsec(if_id).to_wire(),
    );
    req.src_port = 50_123;
    req.dst_port = 443;
    let key = build_synced_session_key(&req, 0, SyncedKeyIntent::Install)
        .expect("a known nonzero IPsec if_id must import");
    assert_eq!(key.discriminator, TunnelDiscriminator::Ipsec(if_id));

    let zero_if_id = 3u64 << 32;
    assert_eq!(
        TunnelDiscriminator::from_wire(zero_if_id),
        crate::session::WireDiscriminator::Unrecognized,
        "if_id zero cannot create an unscoped IPsec session"
    );
    let unknown_tag = (4u64 << 32) | u64::from(if_id);
    let mut unknown = gre_sync_req(PROTO_TCP, unknown_tag);
    unknown.src_port = 50_123;
    unknown.dst_port = 443;
    let err = build_synced_session_key(&unknown, 0, SyncedKeyIntent::Install)
        .expect_err("a future discriminator must not be coerced to a known class");
    assert!(err.contains("tunnel-discriminator-unrecognized"));
}

/// #7699: a PPTP record whose call-id pair was not carried is WITHHELD.
///
/// The handle in the discriminator is derived from the pair, so a record with
/// the handle and no pair is one this node can never match a packet against: it
/// cannot build the association its workers resolve through. Importing it would
/// leave a session in the table while every packet for that call resolves
/// unassociated — present-and-unusable, which is worse than absent.
///
/// Same discipline as
/// `a_peer_that_cannot_express_the_discriminator_has_its_gre_session_withheld_7188`,
/// and the refusal carries the same machine-readable prefix because it is the
/// CORRECT answer from a healthy helper, not a transport failure.
#[test]
fn a_pptp_record_without_its_call_id_pair_is_withheld_7699() {
    use crate::session::pptp::PptpCall;

    let (a, b): (std::net::IpAddr, std::net::IpAddr) = (
        "198.51.100.7".parse().unwrap(),
        "203.0.113.9".parse().unwrap(),
    );
    let call = PptpCall::new(a, 0x1111, b, 0x2222);
    let zones = rustc_hash::FxHashMap::default();

    // The peer states the handle but carries no pair — an older daemon, or one
    // that lost the association.
    let mut req = gre_sync_req(PROTO_GRE, TunnelDiscriminator::Pptp(call.handle()).to_wire());
    req.src_ip = a.to_string();
    req.dst_ip = b.to_string();
    req.pptp_call_ids = crate::session::pptp::PPTP_CALL_IDS_ABSENT;
    let err = build_synced_session_entry(&req, &zones, 0)
        .expect_err("a PPTP record with no call-id pair must be withheld");
    assert!(
        err.contains("pptp-call-ids-not-carried"),
        "the refusal must name the reason so Go can discriminate it from a \
         transport failure (#5247); got {err}"
    );

    // POSITIVE CONTROL: the SAME record with the pair carried imports cleanly.
    // Without this the assertion above is satisfied by a build that withholds
    // every PPTP record, which would be indistinguishable from not supporting
    // the class at all.
    req.pptp_call_ids = call.to_wire_call_ids();
    let entry = build_synced_session_entry(&req, &zones, 0)
        .expect("a PPTP record carrying its pair must import");
    assert_eq!(entry.key.discriminator, TunnelDiscriminator::Pptp(call.handle()));
}

/// #7699: a handle that does not match the carried pair is WITHHELD, not
/// repaired.
///
/// Both nodes derive the handle with the same pure function, so a mismatch
/// means they disagree about the derivation — version skew or a corrupted
/// record. Recomputing it locally and importing under the local value would
/// make the two tables disagree SILENTLY, which is the failure this check
/// exists to catch rather than paper over.
#[test]
fn a_pptp_handle_that_disagrees_with_its_pair_is_withheld_7699() {
    use crate::session::pptp::PptpCall;

    let (a, b): (std::net::IpAddr, std::net::IpAddr) = (
        "198.51.100.7".parse().unwrap(),
        "203.0.113.9".parse().unwrap(),
    );
    let call = PptpCall::new(a, 0x1111, b, 0x2222);
    let other = PptpCall::new(a, 0x3333, b, 0x4444);
    assert_ne!(call.handle(), other.handle(), "fixture: the two must differ");

    let zones = rustc_hash::FxHashMap::default();
    let mut req = gre_sync_req(PROTO_GRE, TunnelDiscriminator::Pptp(other.handle()).to_wire());
    req.src_ip = a.to_string();
    req.dst_ip = b.to_string();
    // The pair belongs to `call`; the handle claims `other`.
    req.pptp_call_ids = call.to_wire_call_ids();

    let err = build_synced_session_entry(&req, &zones, 0)
        .expect_err("a handle that disagrees with its pair must be withheld");
    assert!(
        err.contains("pptp-handle-mismatch"),
        "the refusal must name the disagreement rather than silently importing \
         under a locally recomputed handle; got {err}"
    );
}
