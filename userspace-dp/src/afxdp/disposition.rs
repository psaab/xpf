// Disposition / telemetry recording extracted from afxdp.rs (Issue 67.3).
//
// `record_exception` (52 LOC) — emits an ExceptionStatus to the
// per-binding live counters when a packet hits an exception path
// (drop, kernel handoff, fabric redirect).
//
// `record_disposition` (68 LOC) — feeds the per-disposition
// PacketDisposition counters used by status queries.
//
// `record_forwarding_disposition` (99 LOC) — overlay used when
// the forwarding outcome itself (ForwardCandidate / FabricRedirect /
// LocalDelivery / etc.) is the dimension being recorded.
//
// `update_last_resolution` (~30 LOC) — caches the most recent
// ForwardingResolution / disposition per session for the inspect
// CLI / gRPC.
//
// Pure relocation. `use super::*;` brings every type and helper
// from afxdp.rs into scope.

use super::*;

pub(super) fn record_exception(
    recent_exceptions: &Arc<Mutex<VecDeque<ExceptionStatus>>>,
    binding: &BindingIdentity,
    reason: &str,
    packet_length: u32,
    meta: Option<UserspaceDpMeta>,
    debug: Option<&ResolutionDebug>,
    forwarding: &ForwardingState,
) {
    // #919: zone IDs render as zone names through `zone_id_to_name`;
    // unknown IDs render as the empty string (was the original
    // behaviour for unknown zone names too).
    let zone_name_for = |id: u16| -> String {
        forwarding
            .zone_id_to_name
            .get(&id)
            .cloned()
            .unwrap_or_default()
    };
    if let Ok(mut recent) = recent_exceptions.lock() {
        push_recent_exception(
            &mut recent,
            ExceptionStatus {
                timestamp: Utc::now(),
                slot: binding.slot,
                queue_id: binding.queue_id,
                worker_id: binding.worker_id,
                interface: binding.interface.to_string(),
                ifindex: binding.ifindex,
                ingress_ifindex: debug.map(|d| d.ingress_ifindex).unwrap_or_default(),
                reason: reason.to_string(),
                packet_length,
                addr_family: meta.map(|m| m.addr_family).unwrap_or(0),
                protocol: meta.map(|m| m.protocol).unwrap_or(0),
                config_generation: meta.map(|m| m.config_generation).unwrap_or(0),
                fib_generation: meta.map(|m| m.fib_generation).unwrap_or(0),
                src_ip: debug
                    .and_then(|d| d.src_ip)
                    .map(|ip| ip.to_string())
                    .unwrap_or_default(),
                dst_ip: debug
                    .and_then(|d| d.dst_ip)
                    .map(|ip| ip.to_string())
                    .unwrap_or_default(),
                src_port: debug.map(|d| d.src_port).unwrap_or_default(),
                dst_port: debug.map(|d| d.dst_port).unwrap_or_default(),
                from_zone: debug.and_then(|d| d.from_zone).map(zone_name_for).unwrap_or_default(),
                to_zone: debug.and_then(|d| d.to_zone).map(zone_name_for).unwrap_or_default(),
            },
        );
    }
}

/// #1187: counter sink for `record_disposition` /
/// `record_forwarding_disposition`. Hot callers (worker poll path)
/// pass `Hot(&mut BatchCounters)` so per-packet increments land in
/// the per-poll-tick batch and flush via `BatchCounters::flush()`.
/// Cold callers (coordinator/inject.rs RPC injection) pass
/// `Cold(&BindingLiveState)` and write directly to atomics — they're
/// not on the worker per-packet hot path so MESI thrash is not a
/// concern there.
pub(super) enum DispositionCounters<'a> {
    Hot(&'a mut BatchCounters),
    Cold(&'a BindingLiveState),
}

impl DispositionCounters<'_> {
    fn bump_validated(&mut self, packet_length: u32) {
        match self {
            Self::Hot(c) => {
                c.touched = true;
                c.validated_packets += 1;
                c.validated_bytes += packet_length as u64;
            }
            Self::Cold(live) => {
                live.validated_packets.fetch_add(1, Ordering::Relaxed);
                live.validated_bytes
                    .fetch_add(packet_length as u64, Ordering::Relaxed);
            }
        }
    }
    fn bump_exception(&mut self) {
        match self {
            Self::Hot(c) => {
                c.touched = true;
                c.exception_packets += 1;
            }
            Self::Cold(live) => {
                live.exception_packets.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    fn bump_local_delivery(&mut self) {
        match self {
            Self::Hot(c) => {
                c.touched = true;
                c.local_delivery_packets += 1;
            }
            Self::Cold(live) => {
                live.local_delivery_packets.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    fn bump_forward_candidate(&mut self) {
        match self {
            Self::Hot(c) => {
                c.touched = true;
                c.forward_candidate_packets += 1;
            }
            Self::Cold(live) => {
                live.forward_candidate_packets
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    fn bump_policy_denied(&mut self) {
        match self {
            Self::Hot(c) => {
                c.touched = true;
                c.policy_denied_packets += 1;
            }
            Self::Cold(live) => {
                live.policy_denied_packets.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    fn bump_route_miss(&mut self) {
        match self {
            Self::Hot(c) => {
                c.touched = true;
                c.route_miss_packets += 1;
            }
            Self::Cold(live) => {
                live.route_miss_packets.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    fn bump_neighbor_miss(&mut self) {
        match self {
            Self::Hot(c) => {
                c.touched = true;
                c.neighbor_miss_packets += 1;
            }
            Self::Cold(live) => {
                live.neighbor_miss_packets.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    fn bump_discard_route(&mut self) {
        match self {
            Self::Hot(c) => {
                c.touched = true;
                c.discard_route_packets += 1;
            }
            Self::Cold(live) => {
                live.discard_route_packets.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    fn bump_next_table(&mut self) {
        match self {
            Self::Hot(c) => {
                c.touched = true;
                c.next_table_packets += 1;
            }
            Self::Cold(live) => {
                live.next_table_packets.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

pub(super) fn record_disposition(
    binding: &BindingIdentity,
    live: &BindingLiveState,
    mut counters: DispositionCounters<'_>,
    disposition: PacketDisposition,
    packet_length: u32,
    meta: Option<UserspaceDpMeta>,
    recent_exceptions: &Arc<Mutex<VecDeque<ExceptionStatus>>>,
    forwarding: &ForwardingState,
) {
    match disposition {
        PacketDisposition::Valid => {
            counters.bump_validated(packet_length);
        }
        PacketDisposition::NoSnapshot => {
            counters.bump_exception();
            record_exception(
                recent_exceptions,
                binding,
                "no_snapshot",
                packet_length,
                meta,
                None,
                forwarding,
            );
        }
        PacketDisposition::ConfigGenerationMismatch => {
            counters.bump_exception();
            // config_gen_mismatches is reconcile-only; deferred from
            // batch per plan §2. Direct atomic on `live`.
            live.config_gen_mismatches.fetch_add(1, Ordering::Relaxed);
            record_exception(
                recent_exceptions,
                binding,
                "config_generation_mismatch",
                packet_length,
                meta,
                None,
                forwarding,
            );
        }
        PacketDisposition::FibGenerationMismatch => {
            counters.bump_exception();
            // fib_gen_mismatches is reconcile-only; deferred per plan §2.
            live.fib_gen_mismatches.fetch_add(1, Ordering::Relaxed);
            record_exception(
                recent_exceptions,
                binding,
                "fib_generation_mismatch",
                packet_length,
                meta,
                None,
                forwarding,
            );
        }
        PacketDisposition::UnsupportedPacket => {
            counters.bump_exception();
            // unsupported_packets is reconcile-/upgrade-window only;
            // deferred per plan §2.
            live.unsupported_packets.fetch_add(1, Ordering::Relaxed);
            record_exception(
                recent_exceptions,
                binding,
                "unsupported_packet",
                packet_length,
                meta,
                None,
                forwarding,
            );
        }
    }
}

pub(super) fn record_forwarding_disposition(
    binding: &BindingIdentity,
    mut counters: DispositionCounters<'_>,
    resolution: ForwardingResolution,
    packet_length: u32,
    meta: Option<UserspaceDpMeta>,
    debug: Option<&ResolutionDebug>,
    recent_exceptions: &Arc<Mutex<VecDeque<ExceptionStatus>>>,
    last_resolution: &Arc<Mutex<Option<PacketResolution>>>,
    forwarding: &ForwardingState,
) {
    match resolution.disposition {
        ForwardingDisposition::LocalDelivery => {
            counters.bump_local_delivery();
        }
        ForwardingDisposition::ForwardCandidate | ForwardingDisposition::FabricRedirect => {
            counters.bump_forward_candidate();
        }
        ForwardingDisposition::HAInactive => {
            update_last_resolution(last_resolution, resolution, debug, forwarding);
            counters.bump_exception();
            record_exception(
                recent_exceptions,
                binding,
                "ha_inactive",
                packet_length,
                meta,
                debug,
                forwarding,
            );
        }
        ForwardingDisposition::PolicyDenied => {
            update_last_resolution(last_resolution, resolution, debug, forwarding);
            counters.bump_policy_denied();
            record_exception(
                recent_exceptions,
                binding,
                "policy_denied",
                packet_length,
                meta,
                debug,
                forwarding,
            );
        }
        ForwardingDisposition::NoRoute => {
            update_last_resolution(last_resolution, resolution, debug, forwarding);
            counters.bump_route_miss();
            record_exception(
                recent_exceptions,
                binding,
                "no_route",
                packet_length,
                meta,
                debug,
                forwarding,
            );
        }
        ForwardingDisposition::MissingNeighbor => {
            update_last_resolution(last_resolution, resolution, debug, forwarding);
            counters.bump_neighbor_miss();
            record_exception(
                recent_exceptions,
                binding,
                "missing_neighbor",
                packet_length,
                meta,
                debug,
                forwarding,
            );
        }
        ForwardingDisposition::DiscardRoute => {
            update_last_resolution(last_resolution, resolution, debug, forwarding);
            counters.bump_discard_route();
            record_exception(
                recent_exceptions,
                binding,
                "discard_route",
                packet_length,
                meta,
                debug,
                forwarding,
            );
        }
        ForwardingDisposition::NextTableUnsupported => {
            update_last_resolution(last_resolution, resolution, debug, forwarding);
            counters.bump_next_table();
            record_exception(
                recent_exceptions,
                binding,
                "next_table_unsupported",
                packet_length,
                meta,
                debug,
                forwarding,
            );
        }
    }
}

pub(super) fn update_last_resolution(
    last_resolution: &Arc<Mutex<Option<PacketResolution>>>,
    resolution: ForwardingResolution,
    debug: Option<&ResolutionDebug>,
    forwarding: &ForwardingState,
) {
    if let Ok(mut last) = last_resolution.lock() {
        *last = Some(resolution.status(debug, forwarding));
    }
}
