//! Zone-table population for `build_forwarding_state`.
//!
//! Populates `state.zone_name_to_id` and `state.zone_id_to_name`
//! from `snapshot.zones`. Rejects reserved-range zone IDs
//! (>= ZONE_ID_RESERVED_MIN). #3075 widened the event-stream zone
//! field to u16, so ids up to ZONE_ID_RESERVED_MIN-1 are addressable
//! (the former >u8::MAX skip is retired).

use super::super::*;

/// #3719 (H03): reject a snapshot in which two DIFFERENT security zones share
/// the same nonzero, non-reserved numeric zone id, BEFORE `populate_zones`
/// touches any id-keyed map. Two zone names can fold to the same
/// `config.StableZoneID`; publishing both would let the later zone silently
/// overwrite the earlier's `zone_id_to_name` / `zone_host_inbound` /
/// `zone_tcp_rst` entries below — merging two security zones under one id (a
/// zone-isolation failure). The Go control plane already QUARANTINES the
/// later-sorting colliding zone before it reaches the wire
/// (`config.QuarantinedZoneNames` -> `quarantineCollidingZones`,
/// pkg/dataplane/userspace/zones.go), so a clean snapshot never trips this; this
/// is the helper-boundary backstop for a corrupt / hand-built / version-drifted
/// snapshot, consistent with the #3402 / #3771 fail-closed family. Rejecting the
/// whole snapshot keeps the previous good forwarding state (a fresh boot keeps
/// the default-deny), never merging two zones.
///
/// The skip set mirrors `populate_zones`: an id of 0, an empty name, or an id in
/// the reserved range (`>= ZONE_ID_RESERVED_MIN`) is never installed, so it is
/// not a collision. Duplicate entries with the SAME name are the same zone, not
/// a collision. The first differing-name duplicate wins the error, naming both.
pub(super) fn reject_duplicate_zone_ids(
    snapshot: &ConfigSnapshot,
) -> Result<(), crate::policy::SnapshotIntegrityError> {
    let mut owner: std::collections::HashMap<u16, &str> =
        std::collections::HashMap::with_capacity(snapshot.zones.len());
    for zone in &snapshot.zones {
        if zone.id == 0 || zone.name.is_empty() || zone.id >= crate::policy::ZONE_ID_RESERVED_MIN {
            continue;
        }
        match owner.get(&zone.id) {
            Some(&first) if first != zone.name.as_str() => {
                return Err(crate::policy::SnapshotIntegrityError::DuplicateZoneId {
                    id: zone.id,
                    first: first.to_string(),
                    second: zone.name.clone(),
                });
            }
            Some(_) => {}
            None => {
                owner.insert(zone.id, zone.name.as_str());
            }
        }
    }
    Ok(())
}

/// Populate `state.zone_name_to_id` / `state.zone_id_to_name`.
/// Must run before any other pass that resolves zone names
/// (interfaces addresses pass, interfaces egress pass,
/// `parse_policy_state_with_counters`). Callers MUST run
/// `reject_duplicate_zone_ids` first so no two zones share an id.
pub(super) fn populate_zones(snapshot: &ConfigSnapshot, state: &mut ForwardingState) {
    // #3402: build the name→id map from the shared SSOT so the apply-time
    // integrity preflight (which has no live forwarding state yet) resolves
    // policy zones against the IDENTICAL validated map this build path uses.
    // The loop below only fills the id-keyed maps (zone_id_to_name /
    // host-inbound / tcp-rst) and emits the #919/#922 skip diagnostics.
    state.zone_name_to_id = crate::policy::zone_name_to_id_from_snapshot(&snapshot.zones);
    for zone in &snapshot.zones {
        if zone.id == 0 || zone.name.is_empty() {
            continue;
        }
        // #919/#922: reserve the top of the u16 space for the
        // `JUNOS_GLOBAL_ZONE_ID` sentinel. Reject any snapshot that
        // would collide.
        if zone.id >= crate::policy::ZONE_ID_RESERVED_MIN {
            eprintln!(
                "xpf-userspace-dp: zone {:?} has reserved id {}; skipping (max usable id is {})",
                zone.name,
                zone.id,
                crate::policy::ZONE_ID_RESERVED_MIN - 1
            );
            continue;
        }
        // #3075: the event-stream codec now writes zone IDs as u16, so the
        // former >u8::MAX skip is retired — a stable name-hash zone id in
        // [1, ZONE_ID_RESERVED_MIN-1] = [1, 65533] is fully addressable. The
        // reserved-range reject above (>= ZONE_ID_RESERVED_MIN) remains the only
        // out-of-range guard.
        // zone_name_to_id is populated above by the shared SSOT helper.
        state.zone_id_to_name.insert(zone.id, zone.name.clone());
        // #3070/#3405/#3705: build the host-inbound admission set keyed by the
        // SAME validated id for EVERY KNOWN zone (a zone present in the snapshot
        // with a valid, addressable id). Post-#3405 the Go control plane sends
        // HostInboundConfigured=true for every configured zone (security.go:70,
        // zones.go), so a configured zone with NO `host-inbound-traffic` stanza is
        // NOT left absent — it ships an EMPTY token set that inserts a default
        // `ZoneHostInbound` here (`admits()` -> false for every service/protocol
        // => default-DENY, Junos parity).
        //
        // #3705: the insert is NO LONGER gated on `host_inbound_configured`. A
        // KNOWN zone whose snapshot carries `host_inbound_configured == false` —
        // the tolerant / HA nil-zone shape (Security.Zones[name] == nil ships a
        // valid name+id but configured=false; #3493), or an old pre-#3405 Go
        // control plane that omits the field — would otherwise be left ABSENT from
        // this table and hit the `None => true` admit-all arm in
        // `host_inbound_admits`, making that known configured zone admit ALL
        // host-bound traffic (reopening the #3405 default-deny on the nil shape).
        // A configured=false zone carries empty token vecs, so it inserts an empty
        // `ZoneHostInbound` -> default-DENY, identical to a no-stanza zone. The
        // Go builder now also ships configured=true for a nil zone; this insert is
        // the fail-closed backstop for a mismatched-version control plane. The
        // `None => true` arm consequently fires ONLY for a genuinely unknown /
        // global ingress zone (id 0, never in this table — skipped above).
        // Lifeline interfaces (fxp0/em0/fab*) are exempt because they never reach
        // the AF_XDP local-delivery classifier (#3682). SSOT:
        // docs/host-inbound-service-matrix.md.
        state
            .zone_host_inbound
            .insert(zone.id, zone_host_inbound_from_snapshot(zone));
        // #3618: one per-zone `reject`-reply rate-limit bucket per KNOWN zone,
        // keyed by the SAME validated zone id. Before #3618 a single
        // process-global bucket rate-limited every generated reject, so a
        // rejected-flow flood ingressing one zone drained it and starved
        // legitimate reject-generation in another zone. Building one bucket per
        // CONFIGURED zone here (not per-packet) bounds cardinality to the
        // configured zone set and gives each ingress zone an independent budget.
        // An unzoned / unknown from-zone (id 0, never in this table) falls back
        // to the shared `REJECT_FALLBACK_LIMITER` at the gate. Fresh limiters on
        // every build = reset-on-commit, accepted for a diagnostic limiter.
        state.reject_buckets.insert(
            zone.id,
            std::sync::Arc::new(crate::afxdp::icmp_ratelimit::ZoneLimiter::new()),
        );
        // #5856: one per-zone Time-Exceeded and one per-zone Packet-Too-Big
        // bucket per KNOWN zone, keyed by the SAME validated zone id, built
        // identically to the reject bucket above. Before #5856 these two
        // reasons shared a SINGLE process-global bucket, so a TTL=1/hop-limit=1
        // (Time-Exceeded) or oversized-DF (Packet-Too-Big) flood ingressing one
        // zone drained it and starved legitimate traceroute / PMTUD replies in
        // every OTHER zone. Building one bucket per CONFIGURED zone here (not
        // per-packet) bounds cardinality to the configured zone set and gives
        // each ingress zone an independent budget. An unzoned / unknown
        // from-zone (id 0, never in this table) falls back to the shared
        // per-reason `*_FALLBACK_LIMITER` at the gate. Fresh limiters on every
        // build = reset-on-commit, accepted for a diagnostic limiter.
        state.time_exceeded_buckets.insert(
            zone.id,
            std::sync::Arc::new(crate::afxdp::icmp_ratelimit::ZoneLimiter::new()),
        );
        state.packet_too_big_buckets.insert(
            zone.id,
            std::sync::Arc::new(crate::afxdp::icmp_ratelimit::ZoneLimiter::new()),
        );
        // #3071: record the per-zone Junos `tcp-rst` knob keyed by zone id so
        // the policy-deny hot path can answer a denied TCP flow whose ingress
        // (from) zone has tcp-rst with a RST instead of a silent drop. Only
        // tcp-rst-enabled zones are inserted; the absence of a key is "off".
        if zone.tcp_rst {
            state.zone_tcp_rst.insert(zone.id, true);
        }
    }
}
