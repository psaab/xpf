// #6312: the JSON leg of the session-delta wire must carry the #5212 stable
// RT_FLOW session id, at parity with the binary event-stream open frame.
//
// The JSON `SessionDeltaInfo` is what the `drain_session_deltas` polling
// fallback (used whenever the binary event stream is down) and the owner-RG
// resync export put on the control-plane RPC. Before this it had no session-id
// field at all, so every session recovered through that leg imported id 0 and
// the peer minted a fresh local one — the originating node's SESSION_CREATE and
// the peer's post-failover SESSION_CLOSE no longer shared an id.
//
// Sibling `#[path]` test module loaded from afxdp/mod.rs, mirroring the #4840
// split.
#![allow(unused_imports)]

use super::session_delta::session_delta_info;
use super::*;
use crate::nat::NatDecision;
use crate::session::{
    SessionCounters, SessionDecision, SessionDelta, SessionDeltaKind, SessionKey, SessionMetadata,
    SessionOrigin,
};
use std::net::{IpAddr, Ipv4Addr};

fn delta_with_session_id(session_id: u64) -> SessionDelta {
    SessionDelta {
        kind: SessionDeltaKind::Open,
        key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: 6,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            src_port: 12345,
            dst_port: 5201,
                    discriminator: Default::default(),
                    routing_domain: 0,
        },
        decision: SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 2,
                egress_ifindex: 3,
                tx_ifindex: 3,
                tunnel_endpoint_id: 0,
                next_hop: None,
                neighbor_mac: None,
                src_mac: None,
                tx_vlan_id: 0,
            },
            nat: NatDecision::default(),
        },
        metadata: SessionMetadata {
            ingress_zone: 1,
            egress_zone: 2,
            ingress_ifindex: 0,
            ingress_vlan_id: 0,
            owner_rg_id: 1,
            fabric_ingress: false,
            is_reverse: false,
            nat64_reverse: None,
            log_session_init: false,
            log_session_close: false,
            policy_id: 0,
            inactivity_timeout_ns: None,
            policy_counter_idx: 0,
            policy_counter: None,
        },
        origin: SessionOrigin::ForwardFlow,
        fabric_redirect_sync: false,
        created_ns: 0,
        last_seen_ns: 0,
        counters: SessionCounters::default(),
        observed_tos: 0,
        observed_tcp_flags: 0,
        session_id,
        bulk_resync: false,
        tcp_close_class: 0,
    }
}

fn test_binding_identity() -> BindingIdentity {
    BindingIdentity {
        slot: 0,
        queue_id: 0,
        worker_id: 7,
        interface: Arc::from("ge-0-0-1"),
        ifindex: 12,
    }
}

fn zone_names() -> FastMap<u16, String> {
    let mut m: FastMap<u16, String> = FastMap::default();
    m.insert(1, "lan".to_string());
    m.insert(2, "wan".to_string());
    m
}

/// Fail-on-revert: drop `rt_flow_session_id: delta.session_id` from
/// `session_delta_info` and the id arrives as 0, so the peer allocates a fresh
/// local id and the cross-node correlation is lost.
#[test]
fn session_delta_info_carries_rt_flow_session_id_6312() {
    let want = 7u64 << 48 | 0x1234_5678;
    let info = session_delta_info(
        &test_binding_identity(),
        &delta_with_session_id(want),
        &zone_names(),
    );
    assert_eq!(
        info.rt_flow_session_id, want,
        "the JSON resync leg must carry the originating node's stable RT_FLOW \
         session id, like the binary open frame does (#6312)"
    );
    // Positive control: this really is the delta -> JSON conversion, so a
    // mismatch above cannot be a wrongly-built fixture.
    assert_eq!(info.src_port, 12345, "conversion produced the delta's tuple");
    assert_eq!(info.ingress_zone, "lan", "conversion resolved zone names");
}

/// The wire KEY is the cross-language contract: the Go consumer decodes this
/// field as `SessionDeltaInfo.RTFlowSessionID` with `json:"rt_flow_session_id"`
/// (pkg/dataplane/userspace/protocol_ha.go). A rename on this side would ship a
/// key the Go decoder ignores — the field would be present and the id still
/// silently lost, which the struct-level assertion above cannot see.
#[test]
fn session_delta_info_rt_flow_session_id_wire_key_6312() {
    let want = 0x0BAD_F00D_u64;
    let info = session_delta_info(
        &test_binding_identity(),
        &delta_with_session_id(want),
        &zone_names(),
    );
    let v: serde_json::Value = serde_json::to_value(&info).expect("serialize SessionDeltaInfo");
    let on_wire = v
        .get("rt_flow_session_id")
        .unwrap_or_else(|| panic!("no `rt_flow_session_id` key on the wire: {v}"));
    assert_eq!(
        on_wire.as_u64(),
        Some(want),
        "`rt_flow_session_id` must carry the id verbatim: {v}"
    );
}

/// A delta with no backing entry (`session_id == 0`) must still emit the key
/// carrying 0 — the pre-existing "no id" sentinel the peer maps to a fresh local
/// allocation. This is the rolling-upgrade fallback, so it must not become an
/// absent key or a synthesized non-zero value.
#[test]
fn session_delta_info_zero_session_id_is_the_no_id_sentinel_6312() {
    let info = session_delta_info(
        &test_binding_identity(),
        &delta_with_session_id(0),
        &zone_names(),
    );
    assert_eq!(info.rt_flow_session_id, 0);
    let v: serde_json::Value = serde_json::to_value(&info).expect("serialize SessionDeltaInfo");
    assert_eq!(
        v.get("rt_flow_session_id").and_then(|x| x.as_u64()),
        Some(0),
        "the zero sentinel must still ride the wire: {v}"
    );
}

// ---------------------------------------------------------------------------
// #6949: the JSON leg must carry the SAME policy attribution as the binary
// event-stream open frame.
//
// The binary MSG_SESSION_OPEN frame has carried policy_id (#3056/#3301),
// policy_counter_idx (#3073), the per-application inactivity timeout (#3227)
// and the NAT64 pool source (#4565) as trailing fields. The JSON
// `SessionDeltaInfo` carried NONE of them, while the Go consumer
// (`pkg/dataplane/userspace/protocol_ha.go`) declared and read all of them, so
// every session recovered through this leg imported policy 0 / counter 0 / the
// global idle timeout / no reverse-BIB pool source.
//
// The tests below assert on the SERIALIZED JSON rather than on struct fields
// wherever they are the red-at-master proof: at master those fields do not
// exist, and a struct-field assertion would be a BUILD BREAK rather than a
// named failing test.
// ---------------------------------------------------------------------------

use crate::event_stream::codec::{EventFrame, FLAG_NAT64, FRAME_HEADER_SIZE};

/// One session carrying a DISTINCTIVE, non-zero attribution on every field.
///
/// `policy_id` is deliberately NOT 0. A rendered 0 displays as `unattributed`
/// (#6851) and is also what a dropped field decodes to, so a fixture whose
/// correct `policy_id` is 0 cannot tell "attributed to policy 0" from
/// "attribution lost" — the exact confusion that hid this defect. It is a
/// NAT64 v6 session so `nat64` / `nat64_snat_v4` carry real values too.
fn delta_with_attribution() -> SessionDelta {
    use std::net::Ipv6Addr;
    let mut delta = delta_with_session_id(0x5EED_5EED);
    delta.key = SessionKey {
        addr_family: libc::AF_INET6 as u8,
        protocol: 6,
        src_ip: IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap()),
        dst_ip: IpAddr::V6("64:ff9b::c0a8:101".parse::<Ipv6Addr>().unwrap()),
        src_port: 5001,
        dst_port: 80,
            discriminator: Default::default(),
            routing_domain: 0,
    };
    // #7239: a NON-DEFAULT domain, so the two legs have something to disagree
    // ABOUT. With 0 here both legs would emit the same encoded default marker
    // and a leg that dropped the field entirely would still look equal.
    delta.key.routing_domain = 100_007;
    delta.metadata.policy_id = 4242;
    delta.metadata.policy_counter_idx = 9;
    // 1800 s, expressed in ns: exercises the ns -> s conversion rather than a
    // value that survives either rounding.
    delta.metadata.inactivity_timeout_ns = Some(1_800 * 1_000_000_000);
    delta.decision.nat.nat64 = true;
    delta.decision.nat.rewrite_src = Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)));
    delta
}

/// The attribution as the BINARY open frame actually puts it on the wire.
///
/// Parsed from the frame bytes, not from the encoder's inputs: this is the leg
/// the JSON leg has to agree WITH, so it must be read the way the Go decoder
/// reads it (`pkg/dataplane/userspace/eventstream.go`). The #3301 block is the
/// last thing on the frame apart from the #4565 snat_v4, the #5212 session id
/// and the #7188 tunnel discriminator, so it is addressed from the END.
struct BinaryAttribution {
    policy_id: u32,
    policy_counter_idx: u32,
    app_timeout: u32,
    nat64: bool,
    nat64_snat_v4: String,
    /// #7188: the tunnel session-identity discriminator, the frame's last
    /// field. It joins this struct because it is the newest thing BOTH legs
    /// carry, and because it is the one field here that is part of session
    /// IDENTITY rather than attribution — a divergence between the legs would
    /// not mis-label a session, it would merge two.
    tunnel_discriminator: u64,
}

fn binary_attribution(delta: &SessionDelta) -> BinaryAttribution {
    let zones: FxHashMap<String, u16> = FxHashMap::default();
    let frame = EventFrame::encode_session_open(
        1,
        &delta.key,
        &delta.decision,
        &delta.metadata,
        &zones,
        delta.fabric_redirect_sync,
        delta.session_id,
        0, // #9412: tcp_close_class
    );
    let payload = &frame.as_bytes()[FRAME_HEADER_SIZE..];
    // #9412: discount the trailing close-class byte. The fields below are read
    // end-relative, and the open frame now ends one byte after the routing domain.
    let n = payload.len() - 1;
    let u32_at = |off: usize| -> u32 {
        u32::from_le_bytes(payload[off..off + 4].try_into().expect("4 bytes"))
    };
    // [n-32..n-28] policy_id, [n-28..n-24] policy_counter_idx,
    // [n-24..n-20] inactivity secs, [n-20..n-16] snat_v4,
    // [n-16..n-8] session id, [n-8..n] #7188 tunnel discriminator.
    let snat = &payload[n - 24..n - 20];
    BinaryAttribution {
        policy_id: u32_at(n - 36),
        policy_counter_idx: u32_at(n - 32),
        app_timeout: u32_at(n - 28),
        nat64: payload[26] & FLAG_NAT64 != 0,
        nat64_snat_v4: if snat == [0, 0, 0, 0] {
            String::new()
        } else {
            format!("{}.{}.{}.{}", snat[0], snat[1], snat[2], snat[3])
        },
        tunnel_discriminator: u64::from_le_bytes(
            payload[n - 12..n - 4].try_into().expect("8 bytes"),
        ),
    }
}

/// CROSS-PRODUCER AGREEMENT (#6949). One session, both wires, same attribution.
///
/// Neither side is pinned to a literal here on purpose. A test that asserted
/// `policy_id == 4242` on the JSON leg alone would encode a belief that the
/// binary leg is the correct one; this asserts only that the two legs DESCRIBE
/// THE SAME SESSION, which is the actual contract — the Go control plane reads
/// whichever leg delivered the delta and cannot tell them apart afterwards.
///
/// RED AT MASTER: at master `session_delta_info` emits none of these keys, so
/// every `.get()` below is `None` and the JSON side reads as 0/""/false against
/// a binary side carrying 4242/9/1800/true/203.0.113.5.
///
/// NOTE on what an agreement assertion can and cannot see. A mutation INSIDE
/// the shared derivation (return `policy_id: 0` from
/// `SessionSyncAttribution::from_session`) moves BOTH legs together, so the
/// five equality assertions below all still hold — two legs can agree on a
/// wrong value. Measured as cell M6 of the #6949 matrix: what actually reds is
/// the POSITIVE CONTROL at the end (`want.policy_id == 4242`), alongside the
/// pre-existing binary-side `test_encode_session_open_carries_policy_fields_3301`.
/// That is why the controls are assertions and not a comment, and why the
/// #3301/#4565 codec tests that pin the binary leg's own values are the other
/// half of this guard and must not be deleted.
#[test]
fn session_delta_json_and_binary_agree_on_policy_attribution_6949() {
    let delta = delta_with_attribution();
    let want = binary_attribution(&delta);
    let info = session_delta_info(&test_binding_identity(), &delta, &zone_names());
    let v: serde_json::Value = serde_json::to_value(&info).expect("serialize SessionDeltaInfo");

    let u32_key = |k: &str| -> u32 {
        v.get(k)
            .unwrap_or_else(|| {
                panic!(
                    "the JSON session-delta leg carries no `{k}` key at all, so every session \
                     recovered through the drain fallback or a FullResync export imports 0 for \
                     it while the binary open frame carries a real value (#6949): {v}"
                )
            })
            .as_u64()
            .unwrap_or_else(|| panic!("`{k}` is not a number: {v}")) as u32
    };

    assert_eq!(
        u32_key("policy_id"),
        want.policy_id,
        "the two session-delta legs disagree on the admitting policy id. A session learned \
         through the JSON leg would render `unattributed` (#6851 renders 0 that way) and be \
         skipped by the commit-time deletion-clear and the #4234 policy-rematch, both of which \
         exclude id 0"
    );
    assert_eq!(
        u32_key("policy_counter_idx"),
        want.policy_counter_idx,
        "the two legs disagree on the per-rule hit-counter handle (#3073): no rule counter is \
         attributed after a failover promotion"
    );
    assert_eq!(
        u32_key("app_timeout"),
        want.app_timeout,
        "the two legs disagree on the per-application inactivity timeout (#3227): the session \
         ages on the global per-protocol timeout instead"
    );
    assert_eq!(
        v.get("nat64").and_then(|x| x.as_bool()).unwrap_or(false),
        want.nat64,
        "the two legs disagree on the NAT64 cross-family marker (#4565): {v}"
    );
    assert_eq!(
        v.get("nat64_snat_v4")
            .and_then(|x| x.as_str())
            .unwrap_or_default(),
        want.nat64_snat_v4,
        "the two legs disagree on the NAT64 translated pool SOURCE. This one is not a \
         mis-attribution: it is the ONE datum the standby cannot reconstruct from the synced \
         forward v6 key, so without it a NAT64 session promoted from this leg cannot rebuild \
         its reverse v4->v6 BIB at all (#4565): {v}"
    );

    assert_eq!(
        v.get("tunnel_discriminator").and_then(|x| x.as_u64()),
        Some(want.tunnel_discriminator),
        "the two legs disagree on the #7188 tunnel session-identity discriminator. \
         This one does not mis-label a session, it MERGES two: a keyed-GRE session \
         recovered through the JSON leg would carry a different identity from the \
         same session recovered through the binary leg, and for protocol 47 the \
         5-tuples are equal so the peer cannot tell them apart afterwards: {v}"
    );

    // Positive controls: the binary side really did carry the fixture, so an
    // equality above cannot be two legs agreeing on nothing.
    assert_eq!(want.policy_id, 4242, "binary leg carried the fixture policy");
    assert_ne!(
        want.tunnel_discriminator, 0,
        "binary leg must STATE a discriminator class; 0 is the reserved \
         `not carried` tag and would make this agreement vacuous (#7188)"
    );
    assert_eq!(want.app_timeout, 1800, "binary leg converted ns -> s");
    assert_eq!(want.nat64_snat_v4, "203.0.113.5", "binary leg carried snat");
    // ...and this really is the delta -> JSON conversion of THAT session.
    assert_eq!(info.src_port, 5001, "conversion produced the delta's tuple");
}

/// THREE STATES, NOT TWO (#6949 / #6851). A session genuinely admitted by
/// policy 0 must emit the keys carrying 0 — present-and-zero — so that
/// "attributed to policy 0" stays distinguishable from "the producer dropped
/// the field". An absent key is the pre-#6949 defect, and it decodes to the
/// same 0 on the Go side, which is exactly why the defect survived four
/// releases without an operator noticing.
///
/// RED AT MASTER: the keys are absent, so `get()` returns `None`.
#[test]
fn session_delta_info_zero_attribution_is_present_not_absent_6949() {
    // delta_with_session_id leaves policy_id / policy_counter_idx 0,
    // inactivity_timeout_ns None and the NatDecision default (no NAT64).
    let info = session_delta_info(
        &test_binding_identity(),
        &delta_with_session_id(1),
        &zone_names(),
    );
    let v: serde_json::Value = serde_json::to_value(&info).expect("serialize SessionDeltaInfo");
    // #7188 is deliberately NOT in this list: its `0` is the RESERVED
    // "not carried" tag, not a legitimate value, so it is asserted NON-zero by
    // `session_delta_info_states_none_explicitly_for_non_tunnel_protocols_7188`
    // instead. Same three-state discipline, opposite sentinel.
    for key in ["policy_id", "policy_counter_idx", "app_timeout"] {
        assert_eq!(
            v.get(key).and_then(|x| x.as_u64()),
            Some(0),
            "`{key}` must ride the wire as an explicit 0 for an unattributed session, not be \
             absent — absent is indistinguishable from the dropped-field defect: {v}"
        );
    }
    assert_eq!(
        v.get("nat64").and_then(|x| x.as_bool()),
        Some(false),
        "`nat64` must ride the wire as an explicit false for a non-NAT64 session: {v}"
    );
    assert_eq!(
        v.get("nat64_snat_v4").and_then(|x| x.as_str()),
        Some(""),
        "`nat64_snat_v4` must ride the wire as an explicit empty string when there is no pool \
         source — the Go consumer's `net.ParseIP(...).To4() != nil` test treats it as not-NAT64: \
         {v}"
    );
}

/// The single-source seam is only load-bearing while BOTH producers destructure
/// `SessionSyncAttribution` EXHAUSTIVELY. A `..` in either destructure restores
/// the pre-#6949 escape hatch: a field added to the struct would then be
/// carried by whichever producer happened to be updated, and nothing would fail
/// to compile — which is precisely how policy_id, policy_counter_idx,
/// app_timeout, nat64 and nat64_snat_v4 came to ride only one of the two legs.
///
/// Textual because the property is about the ABSENCE of a token; there is no
/// value to observe at runtime. Comment lines are stripped before matching so
/// this gate cannot be satisfied by prose that quotes the pattern it looks for.
#[test]
fn sync_attribution_exhaustive_destructure_6949() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let read_code = |rel: &str| -> String {
        let p = root.join(rel);
        let src = std::fs::read_to_string(&p)
            .unwrap_or_else(|e| panic!("read {}: {e} (the #6949 seam guard cannot run)", p.display()));
        src.lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
    };

    // The field set is read from the definition, never restated here: a
    // constant written down twice is two constants.
    let def = read_code("src/session/sync_attribution.rs");
    let body = def
        .split_once("pub(crate) struct SessionSyncAttribution {")
        .expect("SessionSyncAttribution definition")
        .1
        .split_once("\n}")
        .expect("end of the struct definition")
        .0;
    let mut want: Vec<String> = body
        .lines()
        .filter_map(|l| l.trim().strip_suffix(','))
        .filter_map(|l| l.strip_prefix("pub(crate) "))
        .map(|l| l.split(':').next().unwrap_or_default().trim().to_string())
        .filter(|n| !n.is_empty())
        .collect();
    want.sort();
    assert_eq!(
        want.len(),
        5,
        "expected the 5 HA-carried attribution fields, parsed {want:?}"
    );

    for producer in [
        "src/afxdp/session_delta.rs",
        "src/event_stream/codec/session_sync.rs",
    ] {
        let src = read_code(producer);
        let block = src
            .split_once("let SessionSyncAttribution {")
            .unwrap_or_else(|| {
                panic!(
                    "{producer} no longer destructures SessionSyncAttribution. If this producer \
                     stopped deriving its attribution from the shared helper, the two \
                     session-delta legs can silently diverge again (#6949) — restore the \
                     destructure or UPDATE this guard, do not delete it"
                )
            })
            .1
            .split_once('}')
            .expect("end of the destructure")
            .0;
        assert!(
            !block.contains(".."),
            "{producer} destructures SessionSyncAttribution with `..`, so a field added to the \
             struct would be carried by only one of the two session-delta legs and still \
             compile — the #6949 defect, restored silently: {block}"
        );
        let mut got: Vec<String> = block
            .split(',')
            .map(|f| f.trim().to_string())
            .filter(|f| !f.is_empty())
            .collect();
        got.sort();
        assert_eq!(
            got, want,
            "{producer} binds {got:?} of SessionSyncAttribution's {want:?}"
        );
    }
}

// --- #7188: the JSON leg carries the tunnel session-identity discriminator ---

/// A keyed-GRE delta: protocol 47, no L4 ports, and a discriminator that is the
/// only thing distinguishing it from another tunnel between the same endpoints.
fn keyed_gre_delta(key: u32) -> SessionDelta {
    let mut delta = delta_with_session_id(0);
    delta.key.protocol = crate::ip_proto::PROTO_GRE;
    delta.key.src_port = 0;
    delta.key.dst_port = 0;
    delta.key.discriminator = crate::session::TunnelDiscriminator::Keyed(key);
    delta
}

/// Fail-on-revert: drop `tunnel_discriminator: delta.key.discriminator.to_wire()`
/// from `session_delta_info` and the JSON leg emits the reserved 0 tag, so the
/// peer reads a fully capable node as one that cannot express the identity and
/// WITHHOLDS every keyed-GRE session it sends.
///
/// The pair is the point: two tunnels between one pair of outer endpoints have
/// identical tuples on this leg, so a single-tunnel assertion would pass with
/// the field hardcoded to any constant.
#[test]
fn session_delta_info_carries_distinct_tunnel_discriminators_7188() {
    let first = session_delta_info(
        &test_binding_identity(),
        &keyed_gre_delta(100),
        &zone_names(),
    );
    let second = session_delta_info(
        &test_binding_identity(),
        &keyed_gre_delta(200),
        &zone_names(),
    );
    assert_eq!(
        first.tunnel_discriminator,
        crate::session::TunnelDiscriminator::Keyed(100).to_wire()
    );
    assert_ne!(
        first.tunnel_discriminator, second.tunnel_discriminator,
        "two RFC 2890 tunnels between the same outer endpoints are one 5-tuple on \
         this leg — protocol 47 has no ports — so a shared discriminator makes the \
         two deltas indistinguishable and the standby holds one session for both"
    );
    // Positive control: this really is the delta -> JSON conversion.
    assert_eq!(first.protocol, crate::ip_proto::PROTO_GRE);
    assert_eq!(first.src_port, 0, "protocol 47 carries no ports");
}

/// The wire KEY is the cross-language contract: the Go consumer decodes this as
/// `SessionDeltaInfo.TunnelDiscriminator` with `json:"tunnel_discriminator"`
/// (pkg/dataplane/userspace/protocol_ha.go). A rename here ships a key Go
/// ignores — present on the wire and still silently lost, which the struct-level
/// assertion above cannot see.
#[test]
fn session_delta_info_tunnel_discriminator_wire_key_7188() {
    let info = session_delta_info(
        &test_binding_identity(),
        &keyed_gre_delta(0x0BAD_F00D),
        &zone_names(),
    );
    let v: serde_json::Value = serde_json::to_value(&info).expect("serialize SessionDeltaInfo");
    let on_wire = v
        .get("tunnel_discriminator")
        .unwrap_or_else(|| panic!("no `tunnel_discriminator` key on the wire: {v}"));
    assert_eq!(
        on_wire.as_u64(),
        Some(crate::session::TunnelDiscriminator::Keyed(0x0BAD_F00D).to_wire()),
        "`tunnel_discriminator` must carry the encoded class verbatim: {v}"
    );
}

/// A non-GRE session emits an EXPLICIT `None`, never the reserved absent tag.
/// That is what tells the receiver this producer can express the identity, and
/// it is the whole reason a peer that omits the field can be told apart from one
/// that says "this protocol has no discriminator".
#[test]
fn session_delta_info_states_none_explicitly_for_non_tunnel_protocols_7188() {
    let info = session_delta_info(
        &test_binding_identity(),
        &delta_with_session_id(0),
        &zone_names(),
    );
    assert_ne!(
        info.tunnel_discriminator, 0,
        "0 is RESERVED for `the peer did not carry this field`; a TCP session must \
         still STATE its `None` class, otherwise every record this helper sends is \
         indistinguishable from one sent by a build that predates the field"
    );
    assert_eq!(
        info.tunnel_discriminator,
        crate::session::TunnelDiscriminator::None.to_wire()
    );
}


/// #7239: the two delta legs must agree on the ROUTING DOMAIN, for the reason
/// #6949 exists on this same struct — a field carried by the binary leg and not
/// the JSON one is not an error anywhere, it is a 0 at the consumer, and 0 here
/// is a legal encoded value rather than an obvious absence.
///
/// The mutation matrix caught this gap: dropping `routing_domain` from the JSON
/// producer left the whole suite green, because the #6949 parity cell compares
/// policy attribution and nothing compared this field.
///
/// FAIL-ON-REVERT: stop populating `routing_domain` in
/// `afxdp::session_delta_info` and this reds.
#[test]
fn session_delta_json_and_binary_agree_on_the_routing_domain_7239() {
    let delta = delta_with_attribution();
    let frame = EventFrame::encode_session_open(
        1,
        &delta.key,
        &delta.decision,
        &delta.metadata,
        &FxHashMap::default(),
        delta.fabric_redirect_sync,
        delta.session_id,
        0, // #9412: tcp_close_class
    );
    let payload = &frame.as_bytes()[FRAME_HEADER_SIZE..];
    // #9412: discount the trailing close-class byte. The fields below are read
    // end-relative, and the open frame now ends one byte after the routing domain.
    let n = payload.len() - 1;
    let binary = u32::from_le_bytes(payload[n - 4..n].try_into().expect("4 bytes"));

    let info = session_delta_info(&test_binding_identity(), &delta, &zone_names());
    let json = serde_json::to_value(info).expect("delta serializes");
    let json_domain = json
        .get("routing_domain")
        .unwrap_or_else(|| {
            panic!(
                "the JSON session-delta leg carries no `routing_domain` key at all, so every \
                 session recovered through the drain fallback or a FullResync export imports \
                 the encoded ABSENT value while the binary open frame carries a real domain: {json}"
            )
        })
        .as_u64()
        .expect("routing_domain is a number") as u32;

    assert_eq!(
        json_domain, binary,
        "the two session-delta legs disagree on the routing domain. The JSON leg's \
         value decodes to a DIFFERENT routing instance than the binary leg's, so a \
         session recovered through the fallback is keyed in the wrong tenant's \
         identity space — which is the #7239 defect arriving by the other transport."
    );
    assert_ne!(
        binary,
        crate::session::routing_domain_to_wire(0),
        "fixture check: the domain must be non-default, or a leg that dropped the \
         field entirely would still compare equal"
    );
}

// --- #9412: the JSON leg carries the close class and names an update ---

/// Fail-on-revert: drop `tcp_close_class: delta.tcp_close_class` from
/// `session_delta_info` and every session recovered through the JSON resync leg
/// reads as open. A close-state Update then never reaches the peer as closing
/// on that leg, even though the binary frame carries it.
///
/// The Update must also be NAMED `"update"`, the event the Go walker syncs like
/// an open. Any other string falls through the walker's switch silently.
#[test]
fn session_delta_info_carries_the_close_class_and_names_an_update_9412() {
    let mut delta = delta_with_session_id(1);
    delta.kind = crate::session::SessionDeltaKind::Update;
    delta.tcp_close_class = 2;
    let info = session_delta_info(&test_binding_identity(), &delta, &zone_names());
    assert_eq!(info.tcp_close_class, 2, "the JSON leg must carry the close class (#9412)");
    assert_eq!(info.event, "update", "a close-state Update must be named \"update\" on the JSON leg (#9412)");
    // Positive control: this really is the delta -> JSON conversion.
    assert_eq!(info.src_port, 12345, "conversion produced the delta's tuple");
}
