//! The HA-carried policy attribution of a session, derived ONCE (#6949).
//!
//! A session delta leaves this helper on two wires, and both must describe the
//! same session identically:
//!
//! * the BINARY event-stream `MSG_SESSION_OPEN` frame
//!   (`event_stream::codec::session_sync::encode_session_open`) — the primary
//!   HA path; and
//! * the JSON RPC-fallback `SessionDeltaInfo`
//!   (`afxdp::session_delta::session_delta_info`) — what
//!   `drain_session_deltas` puts on the control-plane RPC while the binary
//!   stream is down (drained every 100 ms then), what it puts there every 5 s
//!   even while the stream is up, and what a helper-requested FullResync
//!   exports through `ExportOwnerRGSessions`.
//!
//! Until #6949 those two spellings had diverged: the binary frame carried
//! `policy_id` (#3056), `policy_counter_idx` (#3073), the per-application
//! inactivity timeout (#3227) and the NAT64 pool source (#4565), and the JSON
//! leg carried NONE of them. The Go consumer declared all of them on
//! `SessionDeltaInfo` and read them unconditionally, so every session learned
//! through the JSON leg imported `PolicyID = 0`, `PolicyCounterIdx = 0`, no
//! application timeout and no reverse-BIB pool source. A rendered id of 0
//! displays as `unattributed` (#6851) — indistinguishable from a session an
//! operator really did admit under policy 0 — which is why the divergence was
//! invisible for four releases.
//!
//! A divergence between the two producers is ALWAYS a bug: they describe one
//! session for one peer. So the derivation is single-sourced here rather than
//! written twice and held in agreement by a test. Both producers destructure
//! `SessionSyncAttribution` EXHAUSTIVELY (no `..`), which makes "a new field
//! carried by only one of the two legs" a COMPILE error rather than another
//! silent four-release drift. `sync_attribution_exhaustive_destructure_6949`
//! pins the absence of `..` at both sites, since a `..` would quietly restore
//! the escape hatch.

use std::net::{IpAddr, Ipv4Addr};

use super::entry::{SessionDecision, SessionMetadata};

/// The per-session policy metadata both HA session-delta producers carry.
///
/// Built by [`SessionSyncAttribution::from_session`]; every field here is a
/// value the Go control plane reads off BOTH legs
/// (`pkg/dataplane/userspace/protocol_ha.go`, `SessionDeltaInfo`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SessionSyncAttribution<'a> {
    /// #3056: the admitting policy's id. `0` is the legitimate "unattributed"
    /// value (no policy resolved), NOT a "field absent" marker — which is
    /// exactly why a dropped field was undetectable downstream.
    pub(crate) policy_id: u32,
    /// #11070: stable identity of the admitting rule. An empty value means
    /// the receiver must leave the hit counter unattributed rather than
    /// resolving a stale positional index.
    pub(crate) policy_rule_id: &'a str,
    /// #3073: the 1-based per-rule hit-counter handle. HA carries it for
    /// legacy metadata, but receivers bind by `policy_rule_id`.
    pub(crate) policy_counter_idx: u32,
    /// #3227: the per-application idle timeout in WHOLE SECONDS, saturating.
    /// The metadata carries nanoseconds; both cross-node wires (Go
    /// `SessionValue.AppTimeout`, `SessionSyncRequest.inactivity_timeout`)
    /// carry seconds. `0` = "use the global per-protocol timeout".
    pub(crate) inactivity_timeout_secs: u32,
    /// #4565: this is a NAT64 cross-family session. The binary frame encodes
    /// it as `FLAG_NAT64` (1<<5); the JSON leg as the `nat64` key.
    pub(crate) nat64: bool,
    /// #4565: the NAT64 translated pool SOURCE. `Some` only for a NAT64
    /// session that actually rewrote its source to a v4 pool address — the one
    /// datum the standby cannot reconstruct from the synced forward v6 key,
    /// because `allocate_source` chooses it and it is not embedded in the key.
    pub(crate) nat64_snat_v4: Option<Ipv4Addr>,
    /// The active ICMP query identity for source-NAT rule reconstruction.
    /// `Some` only when an ICMP packet installed a source-NAT translation.
    pub(crate) source_nat_icmp: Option<(u8, u8)>,
}

impl<'a> SessionSyncAttribution<'a> {
    /// Derive the HA-carried attribution from a session's decision + metadata.
    ///
    /// This is the ONLY place the ns -> s timeout conversion and the
    /// `(nat64, rewrite_src)` pool-source selection are written. Both were
    /// non-trivial enough that duplicating them per producer would have been a
    /// second divergence waiting to happen even after the fields were added.
    pub(crate) fn from_session(decision: &SessionDecision, metadata: &'a SessionMetadata) -> Self {
        Self {
            policy_id: metadata.policy_id,
            policy_rule_id: metadata
                .policy_counter
                .as_ref()
                .map_or("", |counter| counter.rule_id()),
            policy_counter_idx: metadata.policy_counter_idx,
            inactivity_timeout_secs: match metadata.inactivity_timeout_ns {
                Some(ns) => u32::try_from(ns / 1_000_000_000).unwrap_or(u32::MAX),
                None => 0,
            },
            nat64: decision.nat.nat64,
            nat64_snat_v4: match (decision.nat.nat64, decision.nat.rewrite_src) {
                (true, Some(IpAddr::V4(v4))) => Some(v4),
                _ => None,
            },
            source_nat_icmp: decision.nat.source_nat_icmp,
        }
    }
}

/// The 4 raw IPv4 octets the binary open frame's trailing `snat_v4` slot
/// carries. `0.0.0.0` when there is no NAT64 pool source, which is the
/// pre-#4565 wire value and what `FLAG_NAT64` disambiguates.
pub(crate) fn nat64_snat_v4_octets(snat: Option<Ipv4Addr>) -> [u8; 4] {
    snat.map(|v4| v4.octets()).unwrap_or([0u8; 4])
}

/// The dotted-quad the JSON leg's `nat64_snat_v4` key carries. Empty string
/// when there is no NAT64 pool source: the Go consumer tests
/// `net.ParseIP(delta.Nat64SnatV4).To4() != nil`, so "" is its "not NAT64"
/// value (`daemon_ha_userspace_convert.go`).
pub(crate) fn nat64_snat_v4_string(snat: Option<Ipv4Addr>) -> String {
    snat.map(|v4| v4.to_string()).unwrap_or_default()
}
