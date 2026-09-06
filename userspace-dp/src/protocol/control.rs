//! Control socket request/response wire shapes, `ProcessStatus`
//! (the per-tick status aggregate), and session-sync wire shapes.
//! Deepest module in the `protocol/` DAG: depends on every leaf
//! plus `snapshot` because `ProcessStatus` and `ControlRequest`
//! aggregate them.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// #7160: `ProcessStatus` now lives in the sibling `status` module (split out
// to keep this file under the modularity floor). `ControlResponse` still
// embeds it, so name it directly rather than through the crate re-export.
use super::status::ProcessStatus;

use super::binding::{
    BindingCountersSnapshot, BindingStatus, ExceptionStatus, HAGroupStatus, QueueStatus,
    SessionDeltaInfo, WorkerRuntimeStatus,
};
use super::cos::{CoSActiveFlowCountStatus, CoSInterfaceStatus};
use super::nat::{NatRuleCounterStatus, SourceNatPoolStatus};
use super::resolution::{FlowWorkerStatus, PacketResolution};
use super::security::{
    FirewallFilterTermCounterStatus, PolicyRuleCounterStatus, ThreeColorPolicerStatus,
};
use super::snapshot::{ConfigSnapshot, FabricSnapshot, NeighborSnapshot, UserspaceCapabilities};

/// The config-snapshot wire contract version, mirrored on the Go side by
/// `userspace.ProtocolVersion` (pkg/dataplane/userspace/protocol.go). The two
/// MUST be bumped in lockstep: both `apply_snapshot` and `bump_fib_generation`
/// gate on EXACT equality, so a peer at a different version refuses the
/// snapshot outright instead of decoding it under the wrong contract.
///
/// v4 (#5488): a scoped GLOBAL policy carries its zone SCOPE as a zone SET in
/// the plural `match_from_zones`/`match_to_zones` fields, and those fields are
/// AUTHORITATIVE (`effective_match_zones` prefers them). The singular
/// `match_from_zone`/`match_to_zone` fields carry only the FIRST element.
///
/// #4626 added the plural fields as purely ADDITIVE JSON without bumping this
/// constant, which made the version handshake lie: a pre-#4626 helper
/// advertising the same version 3 ignores fields it does not know and reads
/// ONLY the singular field, so a global `deny` scoped `[dmz trust] -> untrust`
/// silently NARROWS to `dmz -> untrust` — a rolling-upgrade fail-OPEN for the
/// zones dropped from the scope. A compatibility extension that changes
/// deny/reject COVERAGE must not be silently ignorable under an unchanged
/// protocol version.
///
/// v5 (#6722): the per-interface EGRESS zone is decided by the Go builder and
/// carried in `InterfaceSnapshot::egress_zone`; the `reth_projection` field the
/// v4 contract carried is GONE. A DELETION cannot ride an unchanged version the
/// way an additive field can: at v4 two binaries built either side of the change
/// both advertise 4 and read the same bytes differently.
///
/// MEASURED rather than argued — the v4 Go builder's rows fed to the v5 helper
/// on the reference cluster (`docs/ha-cluster-userspace.conf`, node 0) resolve
/// egress zone 0 for BOTH ifindex 24 and ifindex 25, where origin/master and the
/// v5 pair resolve `lan` and `wan`. Ifindex 25 loses a zone even the pre-#6722
/// helper resolved, so the mixed pairing is strictly worse than either endpoint.
/// Under `default-policy deny-all` that is a silent transit outage carrying a
/// version number both sides agree on.
/// v5 (#5619 / #6691): `InterfaceSnapshot.secure_tunnel` is AUTHORITATIVE over
/// AF_XDP binding admission — `include_userspace_binding_interface` refuses a
/// candidate on it (server/helpers/planning.rs). A helper that predates the
/// field leaves it `false` and plans the xfrmi anyway, and because
/// `replan_bindings_from_candidates` takes the GLOBAL MINIMUM queue count and
/// an xfrm interface has exactly ONE RX queue, that re-plans EVERY physical
/// interface on the box onto one queue and one worker — the #3091
/// single-worker regression, on a config the new control plane believes is
/// safe. Additive-and-ignorable is exactly the shape #5488 was: a new field
/// that changes how existing bytes behave needs the version, not just the tag.
///
/// The bump alone only makes the old helper REFUSE the snapshot and keep
/// forwarding its previous-good image, so it is paired with
/// `ensureSecureTunnelProtocolLocked` (pkg/dataplane/userspace/
/// manager_compile.go), which disarms that helper and aborts the commit.
///
/// v6 (#6691 round 9): the REFUSAL RULE over that same field changed from "any
/// owning row calls this netdev unbindable" to "every owning row does"
/// (`snapshot_refuses_parent_netdev`). No field moved — the SEMANTICS of the
/// existing rows did, which is the case an unchanged version number cannot
/// express: a v5 helper and a v6 control plane both say "5" and disagree about
/// which netdevs may be bound.
///
/// v7 (#6691 round 10): `FabricSnapshot.parent_unbindable` is AUTHORITATIVE
/// over whether a fabric parent netdev may be bound. A fabric member needs no
/// interface stanza, so the parent commonly has no row to carry the
/// device-level flags; a v6 helper decodes the absent field to `false` and
/// plans an AF_XDP binding on a netdev the control plane refused. The reachable
/// shape is a live xfrmi under a slot-shaped name used as a fabric member: one
/// RX queue, global-minimum queue planning, #3091 again.
/// v8 (integration of #6722 and #6691): both branches independently bumped this
/// constant for DIFFERENT wire changes — #6722 to 5, #6691 to 7. The merged wire
/// carries BOTH contracts and so matches NEITHER value. Leaving it at either is
/// precisely the collision both comments below describe: a helper built from one
/// branch alone advertises the same number and reads the rows differently. 8 was
/// never shipped by either side, so no mixed pairing can agree on it by accident.
/// v9 (issue 8892): `routing_domain` was added to the snapshot without bumping
/// this constant, so a helper built before it advertises the same 8, passes the
/// exact-equality gate, ignores the field, and resolves every interface to
/// domain 0 -- the cross-tenant session aliasing that #7160 exists to close and
/// that `afxdp/tests_routing_domain_7160.rs` asserts is a defect. Additive and
/// degrading to the old behaviour is a sound argument for a FEATURE; it is not
/// sound when the old behaviour IS the defect the field was added to fix, and
/// for those the bump is the only mechanism that refuses the pairing.
pub(crate) const CONFIG_SNAPSHOT_PROTOCOL_VERSION: i32 = 10;
pub(crate) const INJECT_PACKET_TUPLE_PROTOCOL_VERSION: i32 = 1;

/// #3651: one per-zone traffic-volume row inside the `ProcessStatus`-level
/// `zone_traffic_counters` sparse block. `zone_id` is the stable name-hash
/// zone id (`StableZoneID`, matching `ZoneSnapshot.id`); ingress totals count
/// packets/bytes that entered the firewall through an interface in the zone,
/// egress totals count packets/bytes that left through one. Totals are
/// cumulative since helper start (or the last `clear_zone_counters` IPC). The
/// Go mirror is `ZoneTrafficCounterStatus` with json tags
/// `zone_id`/`ingress_packets`/`ingress_bytes`/`egress_packets`/`egress_bytes`.
#[derive(Clone, Debug, Serialize, Deserialize, Default, PartialEq, Eq)]
pub(crate) struct ZoneTrafficCounterStatus {
    #[serde(rename = "zone_id", default)]
    pub zone_id: u16,
    #[serde(rename = "ingress_packets", default)]
    pub ingress_packets: u64,
    #[serde(rename = "ingress_bytes", default)]
    pub ingress_bytes: u64,
    #[serde(rename = "egress_packets", default)]
    pub egress_packets: u64,
    #[serde(rename = "egress_bytes", default)]
    pub egress_bytes: u64,
}

/// #3651: one per-zone flood-EVENT row inside the `ProcessStatus`-level
/// `zone_flood_counters` sparse block — the sibling of
/// [`ZoneTrafficCounterStatus`] for the other dead per-zone counter family.
/// `zone_id` is the stable name-hash zone id (`StableZoneID`, matching
/// `ZoneSnapshot.id`); the three counts are cumulative screen DROPS attributed
/// to that zone for the `syn-flood`, `icmp-flood`, and `udp-flood` checks,
/// since helper start (or the last `clear_flood_counters` IPC). The Go mirror
/// is `ZoneFloodCounterStatus` with json tags
/// `zone_id`/`syn_flood_events`/`icmp_flood_events`/`udp_flood_events`, which
/// `syncBPFCountersLocked` maps onto `dataplane.FloodState`
/// `SynCount`/`ICMPCount`/`UDPCount`.
#[derive(Clone, Debug, Serialize, Deserialize, Default, PartialEq, Eq)]
pub(crate) struct ZoneFloodCounterStatus {
    #[serde(rename = "zone_id", default)]
    pub zone_id: u16,
    #[serde(rename = "syn_flood_events", default)]
    pub syn_flood_events: u64,
    #[serde(rename = "icmp_flood_events", default)]
    pub icmp_flood_events: u64,
    #[serde(rename = "udp_flood_events", default)]
    pub udp_flood_events: u64,
}

/// Maximum accepted size, in bytes, of a single newline-delimited
/// control-socket request body before it is decoded (#2523).
///
/// The control socket reads one JSON request per connection via a
/// bounded `read_until`. Without a cap, a malformed or compromised local
/// caller can stream a very large unterminated line and force the helper
/// to grow its read buffer unbounded (bounded in time only by the 5 s
/// read timeout, not in allocation). The accept loop reads the whole body
/// into memory before any schema validation can run, so the cap must be
/// enforced at the read, not at decode.
///
/// Sizing (#2744): the largest legitimate request is `apply_snapshot`,
/// which carries the entire compiled config (every zone, policy,
/// address-book entry, NAT rule, filter, route, etc.). A hand-authored
/// production config serializes to a few MB of JSON, but the DOMINANT
/// scaling dimension is NOT policy count — it is dynamic-feed-backed
/// address books: `AddressBookSnapshot.prefixes_v4/v6` carry feed
/// prefixes inline as CIDR text (see `buildAddressBookTableWithFeeds`,
/// `pkg/dataplane/userspace/policies.go`), and feeds are bounded only by
/// a per-line scanner cap, not a total-entry cap.
///
/// The original #2523 ceiling was 16 MiB, sized off the policy/NAT/route
/// dimension. A large threat-intel feed (hundreds of thousands of CIDRs;
/// an IPv6 CIDR serializes to ~45 B of JSON each, so ~500K prefixes ≈
/// 20+ MiB) can push a *legitimate* `apply_snapshot` past 16 MiB and be
/// rejected at the control socket — fail-closed, but it silently drops a
/// committed config on the floor. #2744 raises the ceiling to 64 MiB,
/// sized to the feed dimension: 64 MiB / ~45 B per IPv6 CIDR ≈ 1.4M
/// prefixes, comfortably above realistic large-feed deployments while
/// still bounding a single request's read allocation to a fixed ceiling.
/// A request larger than this is rejected before allocating its body,
/// keeping the daemon alive (fail-closed: stale config retained, one log
/// line, no crash).
///
/// LOCKSTEP: this MUST equal the Go sender's pre-flight ceiling
/// `MaxControlRequestBytes` in `pkg/dataplane/userspace/process.go`. A
/// sender that emits a request larger than the receiver's cap still gets
/// rejected at the read, so the two caps must move together. The Go side
/// pins the relationship in `TestControlRequestCapLockstepWithRust`.
pub(crate) const MAX_CONTROL_REQUEST_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct ControlRequest {
    #[serde(rename = "type")]
    pub request_type: String,
    #[serde(rename = "suppress_status", default)]
    pub suppress_status: bool,
    #[serde(default)]
    pub snapshot: Option<ConfigSnapshot>,
    #[serde(default)]
    pub forwarding: Option<ForwardingControlRequest>,
    #[serde(rename = "ha_state", default)]
    pub ha_state: Option<HAStateUpdateRequest>,
    #[serde(default)]
    pub queue: Option<QueueControlRequest>,
    #[serde(default)]
    pub binding: Option<BindingControlRequest>,
    #[serde(default)]
    pub packet: Option<InjectPacketRequest>,
    #[serde(rename = "session_sync", default)]
    pub session_sync: Option<SessionSyncRequest>,
    #[serde(rename = "session_deltas", default)]
    pub session_deltas: Option<SessionDeltaDrainRequest>,
    #[serde(rename = "session_export", default)]
    pub session_export: Option<SessionExportRequest>,
    /// #7919: the 5-tuple to report per-worker counters for (`session_counters`
    /// verb). Absent for every other verb — an ADDED field, never a
    /// redefinition of one, so an old helper ignores it and an old control
    /// plane never sends it.
    #[serde(rename = "session_counter_query", default)]
    pub session_counter_query: Option<SessionCounterQueryRequest>,
    /// #8121: idle persistent-NAT leases to install (the `import_idle_leases`
    /// verb). Absent for every other verb.
    #[serde(rename = "idle_leases", default, skip_serializing_if = "Vec::is_empty")]
    pub idle_leases: Vec<IdleLeaseWire>,
    #[serde(default)]
    pub neighbors: Option<Vec<NeighborSnapshot>>,
    #[serde(rename = "neighbor_generation", default)]
    pub neighbor_generation: u64,
    #[serde(rename = "neighbor_replace", default)]
    pub neighbor_replace: bool,
    #[serde(default)]
    pub fabrics: Option<Vec<FabricSnapshot>>,
}


#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct SlowPathStatus {
    #[serde(default)]
    pub active: bool,
    /// #2471: active but the live TUN MTU is below the configured MTU because
    /// the MTU-programming ioctl failed. Jumbo reinjection is refused.
    #[serde(rename = "degraded", default)]
    pub degraded: bool,
    /// #2471: the live TUN MTU (1500 fallback when programming failed).
    #[serde(rename = "live_mtu", default)]
    pub live_mtu: i32,
    #[serde(rename = "device_name", default)]
    pub device_name: String,
    #[serde(default)]
    pub mode: String,
    #[serde(rename = "last_error", default)]
    pub last_error: String,
    #[serde(rename = "queued_packets", default)]
    pub queued_packets: u64,
    #[serde(rename = "injected_packets", default)]
    pub injected_packets: u64,
    #[serde(rename = "injected_bytes", default)]
    pub injected_bytes: u64,
    #[serde(rename = "dropped_packets", default)]
    pub dropped_packets: u64,
    #[serde(rename = "dropped_bytes", default)]
    pub dropped_bytes: u64,
    #[serde(rename = "rate_limited_packets", default)]
    pub rate_limited_packets: u64,
    #[serde(rename = "queue_full_packets", default)]
    pub queue_full_packets: u64,
    #[serde(rename = "write_errors", default)]
    pub write_errors: u64,
    /// #2471: frames refused at enqueue because they exceed the live TUN MTU.
    #[serde(rename = "mtu_dropped_packets", default)]
    pub mtu_dropped_packets: u64,
}

impl From<crate::slowpath::SlowPathStatus> for SlowPathStatus {
    fn from(value: crate::slowpath::SlowPathStatus) -> Self {
        Self {
            active: value.active,
            degraded: value.degraded,
            live_mtu: value.live_mtu,
            device_name: value.device_name,
            mode: value.mode,
            last_error: value.last_error,
            queued_packets: value.queued_packets,
            injected_packets: value.injected_packets,
            injected_bytes: value.injected_bytes,
            dropped_packets: value.dropped_packets,
            dropped_bytes: value.dropped_bytes,
            rate_limited_packets: value.rate_limited_packets,
            queue_full_packets: value.queue_full_packets,
            write_errors: value.write_errors,
            mtu_dropped_packets: value.mtu_dropped_packets,
        }
    }
}

/// #1434: one WG PEER's telemetry row inside a `WgTunnelStatus`. The
/// Go mirror is `WgPeerStatus` in `pkg/dataplane/userspace/protocol.go`
/// — keep json tags identical on both sides. Fields are serde-defaulted
/// for mixed-version compat.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct WgPeerStatus {
    /// Peer static public key, 64-char lowercase hex (same rendering as
    /// the config-side `wg_peer_pubkey_hex`). Public by definition.
    /// NOTE: `wg show` renders base64; xpf surfaces are uniformly hex.
    #[serde(rename = "peer_pubkey_hex", default)]
    pub peer_pubkey_hex: String,
    /// Configured-or-learned peer endpoint (empty for a responder-only
    /// peer with no learned endpoint yet).
    #[serde(rename = "peer_endpoint", default)]
    pub peer_endpoint: String,
    /// Whether this peer currently holds a CONFIRMED (egress-usable)
    /// transport session.
    #[serde(rename = "session_confirmed", default)]
    pub session_confirmed: bool,
}

/// #1865: one WG tunnel's telemetry row inside `ProcessStatus`.
/// Counter semantics, lifetime, and the reserved-reason list live in
/// `afxdp/wg/counters.rs` (the single source of truth this mirrors);
/// the Go mirror is `WgTunnelStatus` in
/// `pkg/dataplane/userspace/protocol.go` — keep json tags identical
/// on BOTH sides (feedback_wire_protocol_both_sides). All fields are
/// serde-defaulted; rows are additive for mixed-version compat.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct WgTunnelStatus {
    /// Tunnel interface name (e.g. "wg0") — the PRIMARY key and the
    /// only Prometheus label. Falls back to `wg-endpoint-<id>` when
    /// the ifindex has no resolved name (a row is never dropped).
    #[serde(default)]
    pub tunnel: String,
    /// Positional endpoint id — informational cross-ref ONLY (#1873:
    /// renumbers when tunnels are added/removed; never a join key).
    #[serde(rename = "tunnel_endpoint_id", default)]
    pub tunnel_endpoint_id: u16,
    #[serde(rename = "listen_port", default)]
    pub listen_port: u16,
    /// Our LOCAL static public key, 64-char lowercase hex (#1434
    /// Increment 1). This is the key an operator must hand to the peer
    /// to configure us — derived once from the local private key at
    /// engine construction (`WgEngine::local_public_key`). Travels as a
    /// hex STRING (never a `Vec<u8>`, to avoid the Go↔Rust base64 wire
    /// trap, MEMORY #1961); operator surfaces re-render it as
    /// WireGuard-canonical base64. `#[serde(default)]` keeps a pre-#1434
    /// payload (key absent) decoding to "".
    #[serde(rename = "local_pubkey_hex", default)]
    pub local_pubkey_hex: String,
    /// Per-peer rows (#1434 multi-peer). Replaces the scalar
    /// peer_pubkey_hex / peer_endpoint / session_confirmed fields with
    /// one row per configured peer. The COUNTERS below remain
    /// tunnel-level (per-engine), as they were pre-#1434.
    #[serde(rename = "peers", default)]
    pub peers: Vec<WgPeerStatus>,
    /// Wall-clock epoch seconds of the most recent handshake
    /// completion (either role). 0 = never (epoch 0 is unreachable, so
    /// the sentinel is unambiguous without Option plumbing). Converted
    /// from the engine's monotonic stamp at snapshot time; an NTP step
    /// skews the display, never the stored stamp.
    #[serde(rename = "last_handshake_unix_secs", default)]
    pub last_handshake_unix_secs: u64,
    // --- handshake counters ---
    #[serde(rename = "hs_initiations_created", default)]
    pub hs_initiations_created: u64,
    #[serde(rename = "hs_initiation_build_failures", default)]
    pub hs_initiation_build_failures: u64,
    #[serde(rename = "hs_responses_created", default)]
    pub hs_responses_created: u64,
    #[serde(rename = "hs_completions_initiator", default)]
    pub hs_completions_initiator: u64,
    #[serde(rename = "hs_rx_drops_mac1_mismatch", default)]
    pub hs_rx_drops_mac1_mismatch: u64,
    #[serde(rename = "hs_rx_drops_malformed", default)]
    pub hs_rx_drops_malformed: u64,
    #[serde(rename = "hs_rx_drops_crypto", default)]
    pub hs_rx_drops_crypto: u64,
    #[serde(rename = "hs_rx_drops_unknown_peer", default)]
    pub hs_rx_drops_unknown_peer: u64,
    #[serde(rename = "hs_rx_drops_stale_response", default)]
    pub hs_rx_drops_stale_response: u64,
    #[serde(rename = "hs_rx_drops_index_exhausted", default)]
    pub hs_rx_drops_index_exhausted: u64,
    /// #4092 responder handshake anti-replay rejects (TAI64N `<=`
    /// greatest accepted from the peer). Distinct from the transport
    /// `decap_drops_replay` counter.
    #[serde(rename = "hs_rx_drops_replayed_init", default)]
    pub hs_rx_drops_replayed_init: u64,
    #[serde(rename = "hs_rx_cookie_unsupported", default)]
    pub hs_rx_cookie_unsupported: u64,
    /// #4094 PR-B initiator-side cookie-replies successfully consumed
    /// (decrypted + stored, arming a valid MAC2 on the next initiation).
    #[serde(rename = "hs_rx_cookie_consumed", default)]
    pub hs_rx_cookie_consumed: u64,
    /// #4094 PR-A responder cookie-reply / MAC2 under-load DoS-mitigation
    /// accounting: cookie replies emitted, under-load initiations dropped
    /// for a missing/bad MAC2 (challenged), under-load initiations that
    /// carried a valid MAC2 and proceeded, and cookie replies suppressed by
    /// the per-window emission budget (`hs_cookie_reply_budget_drops` also
    /// folds in the #4332 per-source token-bucket throttle drops).
    #[serde(rename = "hs_cookie_replies_sent", default)]
    pub hs_cookie_replies_sent: u64,
    #[serde(rename = "hs_rx_under_load_no_mac2", default)]
    pub hs_rx_under_load_no_mac2: u64,
    #[serde(rename = "hs_rx_under_load_mac2_ok", default)]
    pub hs_rx_under_load_mac2_ok: u64,
    #[serde(rename = "hs_cookie_reply_budget_drops", default)]
    pub hs_cookie_reply_budget_drops: u64,
    #[serde(rename = "rx_unknown_type", default)]
    pub rx_unknown_type: u64,
    #[serde(rename = "hs_send_errors", default)]
    pub hs_send_errors: u64,
    #[serde(rename = "hs_requests_armed", default)]
    pub hs_requests_armed: u64,
    // --- transport decap ---
    #[serde(rename = "decap_packets", default)]
    pub decap_packets: u64,
    #[serde(rename = "decap_bytes", default)]
    pub decap_bytes: u64,
    #[serde(rename = "decap_keepalives", default)]
    pub decap_keepalives: u64,
    #[serde(rename = "decap_drops_malformed_header", default)]
    pub decap_drops_malformed_header: u64,
    #[serde(rename = "decap_drops_unknown_session", default)]
    pub decap_drops_unknown_session: u64,
    #[serde(rename = "decap_drops_counter_ceiling", default)]
    pub decap_drops_counter_ceiling: u64,
    #[serde(rename = "decap_drops_crypto", default)]
    pub decap_drops_crypto: u64,
    #[serde(rename = "decap_drops_replay", default)]
    pub decap_drops_replay: u64,
    #[serde(rename = "decap_drops_allowed_ips", default)]
    pub decap_drops_allowed_ips: u64,
    #[serde(rename = "decap_drops_malformed_inner", default)]
    pub decap_drops_malformed_inner: u64,
    #[serde(rename = "decap_drops_buffer", default)]
    pub decap_drops_buffer: u64,
    // --- transport encap ---
    #[serde(rename = "encap_packets", default)]
    pub encap_packets: u64,
    #[serde(rename = "encap_bytes", default)]
    pub encap_bytes: u64,
    #[serde(rename = "encap_drops_no_session", default)]
    pub encap_drops_no_session: u64,
    #[serde(rename = "encap_drops_unconfirmed", default)]
    pub encap_drops_unconfirmed: u64,
    #[serde(rename = "encap_drops_rekey_required", default)]
    pub encap_drops_rekey_required: u64,
    #[serde(rename = "encap_drops_other", default)]
    pub encap_drops_other: u64,
    #[serde(rename = "encap_mtu_drops", default)]
    pub encap_mtu_drops: u64,
    #[serde(rename = "transport_send_errors", default)]
    pub transport_send_errors: u64,
    #[serde(rename = "tun_write_errors", default)]
    pub tun_write_errors: u64,
    #[serde(rename = "tun_rx_drops_no_endpoint", default)]
    pub tun_rx_drops_no_endpoint: u64,
    // --- #1888 S5 timers ---
    #[serde(rename = "encap_drops_expired", default)]
    pub encap_drops_expired: u64,
    #[serde(rename = "decap_drops_expired", default)]
    pub decap_drops_expired: u64,
    #[serde(rename = "sessions_expired", default)]
    pub sessions_expired: u64,
    #[serde(rename = "rekeys_initiated_age", default)]
    pub rekeys_initiated_age: u64,
    #[serde(rename = "rekeys_initiated_dead_peer", default)]
    pub rekeys_initiated_dead_peer: u64,
    #[serde(rename = "rekeys_initiated_keepalive_no_session", default)]
    pub rekeys_initiated_keepalive_no_session: u64,
    #[serde(rename = "keepalives_tx_passive", default)]
    pub keepalives_tx_passive: u64,
    #[serde(rename = "keepalives_tx_persistent", default)]
    pub keepalives_tx_persistent: u64,
    #[serde(rename = "pending_aborted_attempt_window", default)]
    pub pending_aborted_attempt_window: u64,
    // --- endpoint resolver (#7158 counters, put on the wire by #7936) ---
    //
    // Present only for a tunnel with at least one DNS-hostname peer endpoint;
    // a literal-only tunnel starts no resolver and reports zeros, which is
    // indistinguishable from a resolver that has not run yet AND correct for
    // both — there is nothing to resolve either way.
    #[serde(rename = "endpoint_resolve_ok", default)]
    pub endpoint_resolve_ok: u64,
    #[serde(rename = "endpoint_resolve_fail", default)]
    pub endpoint_resolve_fail: u64,
    /// The name resolved, but to no address of the family this interface's
    /// single UDP socket can send from. THE counter this row exists for: it is
    /// a configuration error that otherwise presents as a peer that simply
    /// never initiates, which is indistinguishable from a dozen other causes.
    #[serde(rename = "endpoint_family_mismatch", default)]
    pub endpoint_family_mismatch: u64,
    #[serde(rename = "endpoint_changed", default)]
    pub endpoint_changed: u64,
    /// Most recent resolver failure text. Carried as a STRING because it is the
    /// half a counter cannot express: `endpoint_family_mismatch` says how often,
    /// and this says which name and which family — and only the pair makes the
    /// condition actionable. It has no Prometheus home (a label of unbounded
    /// cardinality would be worse than useless), so it is rendered on the
    /// `show security wireguard detail` line instead.
    #[serde(rename = "endpoint_last_error", default)]
    pub endpoint_last_error: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct ControlResponse {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub error: String,
    /// #7919: one row per worker for the `session_counters` verb. Empty for
    /// every other verb, and empty from a helper that does not implement it —
    /// the Go caller distinguishes those by the `unknown request type` error,
    /// never by emptiness, because an unimplemented verb and a genuinely empty
    /// answer must not read alike.
    #[serde(
        rename = "session_counters",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub session_counters: Vec<SessionCounterRowWire>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<ProcessStatus>,
    #[serde(
        rename = "session_deltas",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub session_deltas: Vec<SessionDeltaInfo>,
    /// #8121: the `export_idle_leases` result.
    #[serde(rename = "idle_leases", default, skip_serializing_if = "Vec::is_empty")]
    pub idle_leases: Vec<IdleLeaseWire>,
    /// #8615: the `export_persistent_lease_display` result — the SHOW-table
    /// population, which unlike `idle_leases` includes bindings with LIVE flows.
    #[serde(
        rename = "display_leases",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub display_leases: Vec<DisplayLeaseWire>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct ForwardingControlRequest {
    #[serde(default)]
    pub armed: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct HAStateUpdateRequest {
    #[serde(default)]
    pub groups: Vec<HAGroupStatus>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct QueueControlRequest {
    #[serde(rename = "queue_id")]
    pub queue_id: u32,
    #[serde(default)]
    pub registered: bool,
    #[serde(default)]
    pub armed: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct BindingControlRequest {
    pub slot: u32,
    #[serde(default)]
    pub registered: bool,
    #[serde(default)]
    pub armed: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct InjectPacketRequest {
    pub slot: u32,
    #[serde(rename = "packet_length", default)]
    pub packet_length: u32,
    #[serde(rename = "addr_family", default)]
    pub addr_family: u8,
    #[serde(default)]
    pub protocol: u8,
    #[serde(rename = "config_generation", default)]
    pub config_generation: u64,
    #[serde(rename = "fib_generation", default)]
    pub fib_generation: u32,
    #[serde(rename = "metadata_valid", default)]
    pub metadata_valid: bool,
    #[serde(rename = "destination_ip", default)]
    pub destination_ip: String,
    #[serde(rename = "emit_on_wire", default)]
    pub emit_on_wire: bool,
    #[serde(rename = "tuple_metadata_version", default)]
    pub tuple_metadata_version: i32,
    #[serde(rename = "source_ip", default)]
    pub source_ip: String,
    #[serde(rename = "source_port", default)]
    pub source_port: Option<u16>,
    #[serde(rename = "destination_port", default)]
    pub destination_port: Option<u16>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct SessionSyncRequest {
    #[serde(default)]
    pub operation: String,
    #[serde(rename = "addr_family", default)]
    pub addr_family: u8,
    #[serde(default)]
    pub protocol: u8,
    #[serde(rename = "src_ip", default)]
    pub src_ip: String,
    #[serde(rename = "dst_ip", default)]
    pub dst_ip: String,
    #[serde(rename = "src_port", default)]
    pub src_port: u16,
    #[serde(rename = "dst_port", default)]
    pub dst_port: u16,
    /// Legacy zone-name field. New peers populate `ingress_zone_id`
    /// instead and may leave this empty; preserved for one-release
    /// peer-compat window.
    #[serde(rename = "ingress_zone", default)]
    pub ingress_zone: String,
    #[serde(rename = "egress_zone", default)]
    pub egress_zone: String,
    /// #919: zone IDs preferred over names. Receiving side prefers
    /// these when nonzero; falls back to name lookup via
    /// `zone_name_to_id` otherwise.
    #[serde(rename = "ingress_zone_id", default)]
    pub ingress_zone_id: u16,
    #[serde(rename = "egress_zone_id", default)]
    pub egress_zone_id: u16,
    /// #7095: the LOCAL ingress identity a peer-imported session should carry.
    ///
    /// The originating node could not send its own `ingress_ifindex` — an
    /// ifindex is node-local and would name a different NIC here, which is why
    /// #6928 imported 0 — so it sent a fold of the RETH-RELATIVE name both
    /// chassis agree on, and the Go side resolved that fold to THIS node's own
    /// numbers before building this request. They are therefore safe to store.
    ///
    /// `default` keeps an older daemon's request decoding to 0, which is the
    /// pre-#7095 behaviour: no ingress identity, zone approximation on display.
    #[serde(rename = "ingress_ifindex", default)]
    pub ingress_ifindex: i32,
    /// #7239 (#7160/#2387): the session's ROUTING DOMAIN as the SENDER stamped
    /// it at install, from the interface the flow actually arrived on.
    ///
    /// Preferred over deriving one from `ingress_ifindex` above, because that
    /// ifindex is resolved from the #7095 fold, and the fold is computed on the
    /// sender's SEND path against its CURRENT config — so an ifindex recycled
    /// onto a sibling between install and sync resolves to the sibling, and a
    /// derived domain files the session in the sibling's routing instance. A
    /// carried value cannot drift that way.
    ///
    /// 0 is NOT a sentinel here: it is the default routing instance, and it is
    /// also what a peer predating this field sends. The handler therefore
    /// prefers a NON-ZERO carried value and otherwise falls back to the
    /// derivation, which keeps the pre-#7239 behaviour — including #8116's
    /// unresolvable-domain refusal — for an old peer. The residual is a
    /// legitimately-default-instance session from a NEW peer during a recycle,
    /// which still derives; that is strictly narrower than deriving every
    /// session, and closing it needs a carried "domain is stated" bit rather
    /// than a magic value.
    #[serde(rename = "routing_domain", default)]
    pub routing_domain: u32,
    #[serde(rename = "ingress_vlan_id", default)]
    pub ingress_vlan_id: u16,
    #[serde(rename = "owner_rg_id", default)]
    pub owner_rg_id: i32,
    #[serde(rename = "egress_ifindex", default)]
    pub egress_ifindex: i32,
    #[serde(rename = "tx_ifindex", default)]
    pub tx_ifindex: i32,
    #[serde(rename = "tunnel_endpoint_id", default)]
    pub tunnel_endpoint_id: u16,
    #[serde(rename = "tx_vlan_id", default)]
    pub tx_vlan_id: u16,
    #[serde(rename = "next_hop", default)]
    pub next_hop: String,
    #[serde(rename = "neighbor_mac", default)]
    pub neighbor_mac: String,
    #[serde(rename = "src_mac", default)]
    pub src_mac: String,
    #[serde(rename = "nat_src_ip", default)]
    pub nat_src_ip: String,
    #[serde(rename = "nat_dst_ip", default)]
    pub nat_dst_ip: String,
    #[serde(rename = "nat_src_port", default)]
    pub nat_src_port: u16,
    #[serde(rename = "nat_dst_port", default)]
    pub nat_dst_port: u16,
    #[serde(rename = "fabric_ingress", default)]
    pub fabric_ingress: bool,
    #[serde(rename = "is_reverse", default)]
    pub is_reverse: bool,
    /// #2785: the admitting policy's per-policy `then log` selection,
    /// carried so a session synced to this node logs the same RT_FLOW
    /// SESSION_CREATE/CLOSE records after failover. `serde(default)` =>
    /// false on an old peer that omits the field (no per-policy log),
    /// which is bit-identical to pre-#2785 behavior (rolling-upgrade safe).
    #[serde(rename = "log_session_init", default)]
    pub log_session_init: bool,
    #[serde(rename = "log_session_close", default)]
    pub log_session_close: bool,
    /// #2170 HA install generation. Mirrors the Go cluster apply layer's
    /// per-(sender,key) monotonic generation so the helper's in-memory
    /// SyncedSessionEntry can enforce the same guard (belt-and-suspenders
    /// for helper-originated deletes and the delayed-stale-install
    /// variant). `serde(default)` => 0 on an old peer that omits the field,
    /// which falls back to unconditional behavior (rolling-upgrade safe).
    #[serde(default)]
    pub generation: u64,
    /// #3301: the admitting policy's ID (#3056 namespace), carried so a
    /// peer-PROMOTED session resolves the admitting policy on its live-session
    /// rows / RT_FLOW records instead of the `0` sentinel (which the Go side
    /// renders as the FIRST configured policy — a wrong attribution). The local
    /// helper stamps this in-process at install; this field carries it across
    /// the cross-node HA wire (#1961 both-sides discipline). `serde(default)`
    /// => 0 on an old peer that omits the field, which is the legitimate
    /// "unattributed / non-policy-forwarded" value, bit-identical to the
    /// pre-#3301 synced-session behavior (rolling-upgrade safe).
    #[serde(rename = "policy_id", default)]
    pub policy_id: u32,
    /// #3301: a 1-based handle to the admitting rule's per-rule hit counter
    /// (#3073 `PolicyState::hit_counter_by_idx`). Carried so a peer-promoted
    /// session increments the correct policy hit counter on EVERY forwarded
    /// packet after failover (the established fast path uses this idx) instead
    /// of leaving the rule uncounted until a local re-evaluation re-stamps it.
    /// HA requires identical config on both nodes, so the same policy snapshot
    /// resolves the same idx on the peer. `serde(default)` => 0 ("no per-rule
    /// counter") on an old peer, the pre-#3301 behavior (rolling-upgrade safe).
    #[serde(rename = "policy_counter_idx", default)]
    pub policy_counter_idx: u32,
    /// #3301: the admitting application term's per-application inactivity (idle)
    /// timeout in SECONDS (#3227). Carried so a peer-promoted short-timeout
    /// session ages out on the app's value rather than the global per-protocol
    /// timeout until a real-traffic refresh re-stamps it. The receiver converts
    /// seconds -> ns via `app_inactivity_timeout_ns`. `serde(default)` => 0 on
    /// an old peer, which maps to `None` (use the global timeout — pre-#3301
    /// behavior, rolling-upgrade safe).
    #[serde(rename = "inactivity_timeout", default)]
    pub inactivity_timeout: u32,
    /// #4565: the NAT64 translated pool SOURCE (dotted-quad IPv4 string). A
    /// non-empty value is the SIGNAL that this synced forward session is a NAT64
    /// cross-family translation: the receiver sets `nat.nat64`, rewrites the
    /// forward source to this v4 pool address, reconstructs the forward v4
    /// destination from the /96-embedded low 32 bits of the (v6) `dst_ip`, and
    /// rebuilds the RFC 6146 reverse (v4->v6) BIB — the original v6 src/dst are
    /// the synced forward `src_ip`/`dst_ip` themselves, so only this pool source
    /// (chosen by the active node's `allocate_source`, not embedded in the key)
    /// must ride the wire. Enables a peer-PROMOTED NAT64 session to reverse-
    /// translate its replies after failover, and arms #4564's standby port
    /// reservation (which gates on `nat.nat64`). `serde(default)` => "" on an
    /// old peer that omits it, decoding to "not NAT64" (rolling-upgrade safe).
    #[serde(rename = "nat64_snat_v4", default)]
    pub nat64_snat_v4: String,
    /// #5212: the ORIGINATING node's stable RT_FLOW session id
    /// (`SessionTable::alloc_session_id` namespace: worker id in the high 16
    /// bits + a per-worker monotonic counter). Carried across the cross-node HA
    /// wire so a peer-synced session ADOPTS the originating node's id rather than
    /// minting a fresh node-local one on import — the standby's SESSION_CLOSE
    /// RT_FLOW record then correlates with the primary's SESSION_CREATE across
    /// both HA nodes (an operator or a collector merging both streams sees one
    /// id per logical session). The receiver stamps this onto the imported entry
    /// (`build_synced_session_entry` -> `SessionInstall::session_id` ->
    /// `upsert_synced_with_origin`) when non-zero, else falls back to a fresh
    /// local id. `serde(default)` => 0 on an old peer that omits the field,
    /// which is the "no id carried" sentinel (a real id is never 0 — the
    /// allocator's counter starts at 1), bit-identical to the pre-#5212
    /// fresh-local-id import (rolling-upgrade safe).
    #[serde(rename = "session_id", default)]
    pub session_id: u64,
    /// #7188: the forward session key's `TunnelDiscriminator`, encoded by
    /// `TunnelDiscriminator::to_wire` (`session/discriminator.rs`). GRE is
    /// protocol 47 and carries no L4 ports, so two RFC 2890 tunnels between one
    /// pair of outer endpoints share a 5-tuple; without this field both records
    /// rebuilt to the same key and the second install evicted the first.
    ///
    /// `0` is RESERVED for "the peer did not carry this field" and is NOT the
    /// encoding of `None` (see `WireDiscriminator`), so a `serde(default)` 0
    /// from an older daemon has its protocol-47 sessions WITHHELD rather than
    /// imported aliased; every other protocol decodes to `None`, bit-identical
    /// to pre-#7188. Plain `u64` with NO `skip_serializing_if`, matching the
    /// `generation` discipline above: 0 must serialize explicitly.
    /// Full contract: `docs/session-sync-architecture.md`.
    #[serde(rename = "tunnel_discriminator", default)]
    pub tunnel_discriminator: u64,

    /// #7699: the learned PPTP call-id pair, for a session whose discriminator
    /// is `Pptp(handle)`.
    ///
    /// The handle in the discriminator is DERIVED from this pair, so a peer
    /// that sends the handle without the pair sends a session the receiver can
    /// never match a packet against: the receiver resolves an incoming PPTP
    /// packet by looking its call id up in the association table, and without
    /// the pair it cannot build that entry. Such a record is WITHHELD rather
    /// than imported — the #7188 withhold-not-downgrade discipline, for the
    /// same reason: a downgraded record is worse than an absent one, because
    /// the peer believes it has state it cannot use.
    ///
    /// `0` is RESERVED for "not carried", exactly as `tunnel_discriminator`
    /// reserves it, and is NOT the encoding of the call-id pair `(0, 0)`. PPTP
    /// call id 0 is not obviously illegal, so a raw pair of u16s would make an
    /// older peer's `serde(default)` zeros indistinguishable from a real call —
    /// which is the absent-vs-zero collapse #7188 exists to avoid. The present
    /// form is `PPTP_CALL_IDS_PRESENT | (lo << 16) | hi`, where `lo`/`hi` are
    /// the call ids of the canonically-lower and -higher peer address.
    #[serde(rename = "pptp_call_ids", default)]
    pub pptp_call_ids: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct SessionDeltaDrainRequest {
    #[serde(default)]
    pub max: u32,
}

/// #8121: one idle persistent-NAT lease on the wire.
///
/// Addresses are strings and the lifetime is REMAINING, not a deadline —
/// `expires_at_ns` is `CLOCK_MONOTONIC` and boot-relative, so carrying it
/// verbatim would read as long-expired on a node with a different uptime. The
/// pool is named rather than indexed for the same reason an address is carried
/// rather than a pool index: a position means the same thing only while both
/// sides agree on the list.
#[derive(Clone, Debug, Serialize, Deserialize, Default, PartialEq, Eq)]
pub(crate) struct IdleLeaseWire {
    #[serde(rename = "pool", default)]
    pub pool_name: String,
    #[serde(default)]
    pub protocol: u8,
    #[serde(rename = "src_ip", default)]
    pub src_ip: String,
    #[serde(rename = "src_port", default)]
    pub src_port: u16,
    /// Empty => `permit-any-remote-host`.
    #[serde(
        rename = "remote_ip",
        default,
        skip_serializing_if = "String::is_empty"
    )]
    pub remote_ip: String,
    #[serde(rename = "remote_port", default, skip_serializing_if = "is_zero_u16")]
    pub remote_port: u16,
    #[serde(rename = "translated_ip", default)]
    pub translated_ip: String,
    #[serde(rename = "translated_port", default)]
    pub translated_port: u16,
    #[serde(rename = "address_only", default, skip_serializing_if = "is_false")]
    pub address_only: bool,
    #[serde(rename = "remaining_ns", default)]
    pub remaining_ns: u64,
    #[serde(rename = "timeout_ns", default)]
    pub timeout_ns: u64,
}

/// #8615: one persistent-NAT lease as the SHOW table needs it.
///
/// A SEPARATE struct from `IdleLeaseWire`, not a widened one, and that is the
/// design rather than a stylistic choice. `IdleLeaseWire` is the record a peer
/// IMPORTS, and `nat/idle_lease_sync_8121.rs`'s first design rule forbids
/// carrying `active_flows` on it: the standby installs a strict subset, so a
/// carried count credits a lease for sessions that node does not hold, it never
/// reaches zero, never enters `lease_expirations`, and no GC path reclaims it.
///
/// Keeping the display record distinct means that rule cannot be undone by a
/// later edit to a shared struct — the import handler deserialises
/// `IdleLeaseWire`, which has no such field to populate.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct DisplayLeaseWire {
    #[serde(rename = "pool", default)]
    pub pool_name: String,
    #[serde(default)]
    pub protocol: u8,
    #[serde(rename = "src_ip", default)]
    pub src_ip: String,
    #[serde(rename = "src_port", default)]
    pub src_port: u16,
    /// Empty => `permit-any-remote-host`.
    #[serde(
        rename = "remote_ip",
        default,
        skip_serializing_if = "String::is_empty"
    )]
    pub remote_ip: String,
    #[serde(rename = "remote_port", default, skip_serializing_if = "is_zero_u16")]
    pub remote_port: u16,
    #[serde(rename = "translated_ip", default)]
    pub translated_ip: String,
    #[serde(rename = "translated_port", default)]
    pub translated_port: u16,
    #[serde(rename = "address_only", default, skip_serializing_if = "is_false")]
    pub address_only: bool,
    /// RAW remaining lifetime. Meaningful only when `active_flows == 0` — while
    /// flows are live the allocator does not refresh the deadline, so this is
    /// routinely 0. The presentation layer interprets it.
    #[serde(rename = "remaining_ns", default)]
    pub remaining_ns: u64,
    #[serde(rename = "timeout_ns", default)]
    pub timeout_ns: u64,
    /// The field that is the whole point of this record, and the one that must
    /// never appear on `IdleLeaseWire`.
    #[serde(rename = "active_flows", default)]
    pub active_flows: u32,
}

fn is_zero_u16(v: &u16) -> bool {
    *v == 0
}

fn is_false(v: &bool) -> bool {
    !*v
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct SessionExportRequest {
    #[serde(rename = "owner_rgs", default)]
    pub owner_rgs: Vec<i32>,
    #[serde(default)]
    pub max: u32,
}

/// #7919: the 5-tuple a `session_counters` query names.
///
/// Addresses are strings for the same reason the rest of this protocol uses
/// them: a numeric form would have to agree about byte order across two
/// languages, and every place this protocol has done that has needed a comment
/// explaining which endianness won.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct SessionCounterQueryRequest {
    #[serde(default)]
    pub src_ip: String,
    #[serde(default)]
    pub dst_ip: String,
    #[serde(default)]
    pub src_port: u16,
    #[serde(default)]
    pub dst_port: u16,
    #[serde(default)]
    pub protocol: u8,
}

/// #7919: what ONE worker's own session table holds for the queried 5-tuple.
///
/// Three states are deliberately distinct and none may be collapsed:
///   - `answered = false` — the worker did not reply before the deadline. Not
///     an answer at all.
///   - `answered, !found`  — it replied: it does not hold this session.
///   - `answered, found`   — it holds it; the counters are what its copy says,
///     and `replica` says whether that copy is a peer-synced/replica origin.
///
/// A reading that flattened these into "counters or zero" would answer neither
/// of the two questions the query exists to separate.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct SessionCounterRowWire {
    #[serde(default)]
    pub worker_id: u32,
    #[serde(default)]
    pub answered: bool,
    #[serde(default)]
    pub found: bool,
    #[serde(default)]
    pub replica: bool,
    #[serde(default)]
    pub fwd_packets: u64,
    #[serde(default)]
    pub fwd_bytes: u64,
    #[serde(default)]
    pub rev_packets: u64,
    #[serde(default)]
    pub rev_bytes: u64,
}
