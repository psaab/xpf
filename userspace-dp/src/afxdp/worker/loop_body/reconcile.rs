// #13075 (D4-12) — cold snapshot-rotation session-reconciliation helpers,
// extracted from loop_body/mod.rs (pure code motion).
//
// The rebind/rematch walkers run only when `refresh_runtime_view`
// observes a control-plane forwarding-snapshot rotation; they never run
// on the per-packet path (`poll_binding` lives in lifecycle.rs). Those
// walkers were already ordinary out-of-line functions in mod.rs, so this
// extraction adds no call boundary or runtime work to the hot loop.
// `refresh_runtime_view` itself runs each worker-loop pass and remains
// `#[inline]`; its production `between` callback carries the #15151
// IPsec-inner pending-work drain.
//
// Contents: the #10509 rebind discriminator (+ its unit tests), the
// zone-ancestry matchers, the bound-first-policy rematch / snapshot rebind
// walkers, the #18693 forwarding-snapshot adoption orchestration, the
// SINGLE-load (validation, forwarding) refresh seam (#6291/#6592 —
// `#[inline]`, carrying the per-tick #15151 drain), and the #9856 resumable
// owner-RG export state. `use super::*;` chains through loop_body/mod.rs to
// worker/mod.rs, exactly as setup.rs/idle_poll.rs do.

use super::*;

/// Run P2 descriptor work only while its Go-stamped absolute deadline is live.
/// Generic closures inline into the worker loop; expiry posts a definitive
/// refusal without entering D13/D14 or touching q0.
#[inline(always)]
pub(super) fn run_before_pmech_deadline<T>(
    deadline_mono_ns: u64,
    now_ns: u64,
    on_expired: impl FnOnce(),
    adjudicate: impl FnOnce() -> T,
) -> Option<T> {
    if now_ns == 0 || deadline_mono_ns <= now_ns {
        on_expired();
        None
    } else {
        Some(adjudicate())
    }
}

/// Decode the trailing #10509 discriminator without ever turning an absent
/// value into a GRE `None` class. Go captures from the BPF conntrack mirror,
/// whose ABI omits this sync-only field, so a production GRE row arrives as
/// zero and is torn down by the Go capture path. Non-GRE rows legitimately use
/// the `None` class (including WireGuard's UDP inner flow); zero is accepted
/// there for compatibility with that ABI.
pub(super) fn policy_rebind_discriminator(
    protocol: u8,
    wire: u64,
) -> Option<crate::session::TunnelDiscriminator> {
    if protocol == 47 {
        return match crate::session::TunnelDiscriminator::from_wire(wire) {
            crate::session::WireDiscriminator::Present(discriminator)
                if !discriminator.is_none() =>
            {
                Some(discriminator)
            }
            _ => None,
        };
    }
    if wire == 0 || wire == crate::session::TunnelDiscriminator::None.to_wire() {
        return Some(crate::session::TunnelDiscriminator::None);
    }
    None
}

#[cfg(test)]
mod policy_rebind_discriminator_tests {
    use super::*;

    #[test]
    fn gre_requires_an_explicit_non_none_discriminator() {
        assert_eq!(
            policy_rebind_discriminator(47, 0),
            None,
            "BPF-mirrored GRE rows cannot be retained without their sync-only identity"
        );
        assert_eq!(
            policy_rebind_discriminator(47, crate::session::TunnelDiscriminator::Unkeyed.to_wire(),),
            Some(crate::session::TunnelDiscriminator::Unkeyed)
        );
    }

    #[test]
    fn non_gre_zero_discriminator_is_the_legacy_none_class() {
        assert_eq!(
            policy_rebind_discriminator(17, 0),
            Some(crate::session::TunnelDiscriminator::None)
        );
        assert_eq!(
            policy_rebind_discriminator(17, crate::session::TunnelDiscriminator::None.to_wire()),
            Some(crate::session::TunnelDiscriminator::None)
        );
    }
}
pub(super) fn ancestry_source_zone_matches(
    forwarding: &crate::afxdp::ForwardingState,
    name: &str,
    id: u32,
    any: bool,
    actual_id: u32,
) -> bool {
    if actual_id == 0 {
        return false;
    }
    if any {
        return name == "any" && id == 0;
    }
    if name == "junos-global" {
        return id == crate::policy::JUNOS_GLOBAL_ZONE_ID;
    }
    if name == "junos-host" {
        return id == crate::policy::ZONE_ID_RESERVED_MIN
            && actual_id == crate::policy::ZONE_ID_RESERVED_MIN;
    }
    id == actual_id
        && forwarding
            .zone_id_to_name
            .get(&actual_id)
            .map(String::as_str)
            == Some(name)
}

pub(super) fn ancestry_destination_zone_id(
    forwarding: &crate::afxdp::ForwardingState,
    name: &str,
    id: u32,
    any: bool,
    fallback_id: u32,
    require_fallback: bool,
) -> Option<u32> {
    if fallback_id == 0 {
        return None;
    }
    if any {
        return (name == "any" && id == 0 && forwarding.zone_id_to_name.contains_key(&fallback_id))
            .then_some(fallback_id);
    }
    if name == "junos-global" {
        return (id == crate::policy::JUNOS_GLOBAL_ZONE_ID
            && forwarding.zone_id_to_name.contains_key(&fallback_id))
        .then_some(fallback_id);
    }
    if name == "junos-host" {
        return (id == crate::policy::ZONE_ID_RESERVED_MIN
            && fallback_id == crate::policy::ZONE_ID_RESERVED_MIN)
            .then_some(fallback_id);
    }
    let mapped = forwarding.zone_name_to_id.get(name).copied()?;
    if mapped != id || (require_fallback && mapped != fallback_id) {
        return None;
    }
    Some(mapped)
}

#[expect(clippy::too_many_arguments, reason = "#17200: wide dataplane signature; census in docs/log/17200.md")]
pub(super) fn rematch_bound_first_policy_sessions(
    old_forwarding: &crate::afxdp::ForwardingState,
    new_forwarding: &crate::afxdp::ForwardingState,
    sessions: &mut crate::session::SessionTable,
    session_map: &crate::afxdp::bpf_map::SteeringMapRef,
    conntrack_v4_fd: libc::c_int,
    conntrack_v6_fd: libc::c_int,
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: &SharedSessionOwnerRgIndexes,
    peer_worker_commands: &[Arc<Mutex<VecDeque<WorkerCommand>>>],
    worker_commands_by_id: &WorkerCommandQueues,
    worker_id: u32,
    now_ns: u64,
) -> (usize, usize) {
    if !new_forwarding.policy_rematch_extensive {
        return (0, 0);
    }
    let Some(old_first) = old_forwarding.policy.rule_for_policy_id(0) else {
        return (0, 0);
    };
    if old_first.rule_id.is_empty() {
        return (0, 0);
    }
    let ancestry: Vec<_> = new_forwarding
        .policy_rename_ancestry
        .iter()
        .filter(|candidate| candidate.source_rule_id == old_first.rule_id)
        .collect();
    // An unchanged first rule needs no special handling. A changed first rule
    // without exactly one validated ancestry descriptor is fail-closed below.
    if ancestry.is_empty()
        && new_forwarding
            .policy
            .rules
            .iter()
            .any(|rule| rule.rule_id == old_first.rule_id)
    {
        return (0, 0);
    }

    let mut candidates = Vec::new();
    sessions.iter_with_origin(|key, decision, metadata, origin| {
        if metadata.is_reverse
            || !metadata
                .policy_counter
                .as_ref()
                .is_some_and(|counter| counter.rule_id() == old_first.rule_id)
        {
            return;
        }
        candidates.push((key.clone(), decision, metadata.clone(), origin));
    });

    let mut rebound = 0;
    let mut purged = 0;
    let mut rematch_declined = 0;
    for (key, decision, mut metadata, origin) in candidates {
        let mut retained = false;
        let mut declined = false;
        let local_delivery =
            decision.resolution.disposition == crate::afxdp::ForwardingDisposition::LocalDelivery;
        if let Some(descriptor) = ancestry.iter().copied().find(|descriptor| {
            ancestry_source_zone_matches(
                old_forwarding,
                &descriptor.source_from_zone,
                descriptor.source_from_zone_id,
                descriptor.source_from_zone_any,
                metadata.ingress_zone,
            ) && if local_delivery {
                descriptor.source_to_zone == "junos-host"
                    && descriptor.source_to_zone_id == crate::policy::ZONE_ID_RESERVED_MIN
                    && metadata.egress_zone != 0
            } else {
                ancestry_source_zone_matches(
                    old_forwarding,
                    &descriptor.source_to_zone,
                    descriptor.source_to_zone_id,
                    descriptor.source_to_zone_any,
                    metadata.egress_zone,
                )
            }
        }) {
            if ancestry_source_zone_matches(
                old_forwarding,
                &descriptor.source_from_zone,
                descriptor.source_from_zone_id,
                descriptor.source_from_zone_any,
                metadata.ingress_zone,
            )
                // #12858: the LocalDelivery classifier stamps its interface
                // zone as `metadata.egress_zone`; the admitting policy's
                // destination is nevertheless the reserved junos-host zone.
                // Only explicit host ancestry can prove this is the same
                // policy domain. Transit rows continue to use their real
                // stamped egress zone and cannot use this exception.
                && (if local_delivery {
                    descriptor.source_to_zone == "junos-host"
                        && descriptor.source_to_zone_id == crate::policy::ZONE_ID_RESERVED_MIN
                        && metadata.egress_zone != 0
                } else {
                    ancestry_source_zone_matches(
                        old_forwarding,
                        &descriptor.source_to_zone,
                        descriptor.source_to_zone_id,
                        descriptor.source_to_zone_any,
                        metadata.egress_zone,
                    )
                })
                && let Ok(ifindex) = i32::try_from(metadata.ingress_ifindex)
                // Untagged physical ports carry no (parent, vlan) entry; fall
                // back to the physical ifindex exactly like the flow-cache
                // classifier. A tagged miss on any bind must fail closed
                // before a fallback zone can match.
                && !crate::afxdp::forwarding::unknown_ingress_vlan(
                    new_forwarding,
                    ifindex,
                    metadata.ingress_vlan_id,
                )
                && let logical_ifindex = resolve_ingress_logical_ifindex(
                    new_forwarding,
                    ifindex,
                    metadata.ingress_vlan_id,
                )
                .unwrap_or(ifindex)
                && let Some(&from_id) = new_forwarding.ifindex_to_zone_id.get(&logical_ifindex)
                && from_id != 0
                // The interface-derived ingress zone must be the ancestry
                // pair's destination-from zone: without this, a broad/global
                // destination rule could permit the same flow from an unrelated
                // current zone and falsely prove continuity.
                && ancestry_destination_zone_id(
                    new_forwarding,
                    &descriptor.destination_from_zone,
                    descriptor.destination_from_zone_id,
                    descriptor.destination_from_zone_any,
                    from_id,
                    true,
                )
                .is_some()
                && let Some(to_id) = if local_delivery {
                    ancestry_destination_zone_id(
                        new_forwarding,
                        &descriptor.destination_to_zone,
                        descriptor.destination_to_zone_id,
                        descriptor.destination_to_zone_any,
                        crate::policy::JUNOS_HOST_ZONE_ID,
                        true,
                    )
                } else {
                    ancestry_destination_zone_id(
                        new_forwarding,
                        &descriptor.destination_to_zone,
                        descriptor.destination_to_zone_id,
                        descriptor.destination_to_zone_any,
                        metadata.egress_zone,
                        false,
                    )
                }
                && to_id != 0
                && let Some(_destination_rule) = new_forwarding
                    .policy
                    .rule_for_stable_id(&descriptor.destination_rule_id)
            {
                // #12859/#13655: preserve packet-scoped adjudication for
                // type-dependent ICMP, but carry validated zone identity
                // forward now. The later packet hit needs the current zones
                // even though its policy identity remains the admitting rule.
                if new_forwarding
                    .policy
                    .icmp_packet_verdict_may_depend_on_type(key.protocol)
                {
                    declined = true;
                    let zone_egress = if local_delivery {
                        metadata.egress_zone
                    } else {
                        to_id
                    };
                    retained = sessions.rebind_zones_pair(
                        &key,
                        from_id,
                        crate::session::zone_vintage_check_for_id(
                            &new_forwarding.zone_id_to_name,
                            from_id,
                        ),
                        zone_egress,
                        crate::session::zone_vintage_check_for_id(
                            &new_forwarding.zone_id_to_name,
                            zone_egress,
                        ),
                    );
                    if retained {
                        metadata.ingress_zone = from_id;
                        metadata.ingress_zone_check = crate::session::zone_vintage_check_for_id(
                            &new_forwarding.zone_id_to_name,
                            from_id,
                        );
                        metadata.egress_zone = zone_egress;
                        metadata.egress_zone_check = crate::session::zone_vintage_check_for_id(
                            &new_forwarding.zone_id_to_name,
                            zone_egress,
                        );
                    }
                    if retained {
                        let entries = sessions.policy_rebind_pair_entries(&key);
                        if let Some(entries) = entries {
                            let bpf_ok = entries.iter().all(|entry| {
                                restamp_bpf_conntrack_policy(
                                    conntrack_v4_fd,
                                    conntrack_v6_fd,
                                    &entry.key,
                                    &entry.metadata,
                                )
                            });
                            if bpf_ok {
                                crate::afxdp::shared_ops::restamp_shared_policy_entries(
                                    shared_sessions,
                                    shared_nat_sessions,
                                    shared_forward_wire_sessions,
                                    &entries,
                                );
                                for entry in entries {
                                    publish_worker_session_map_entry(
                                        session_map.handle(),
                                        new_forwarding,
                                        &entry.key,
                                        entry.decision,
                                        &entry.metadata,
                                        entry.origin,
                                        true,
                                    );
                                }
                            } else {
                                retained = false;
                            }
                        } else {
                            retained = false;
                        }
                    }
                }
                let policy_dst_ip = decision.nat.rewrite_dst.unwrap_or(key.dst_ip);
                let policy_dst_port = decision.nat.rewrite_dst_port.unwrap_or(key.dst_port);
                let result = if declined {
                    None
                } else if local_delivery {
                    crate::policy::evaluate_junos_host_policy_l3_aware_without_counting(
                        &new_forwarding.policy,
                        from_id,
                        key.src_ip,
                        policy_dst_ip,
                        key.protocol,
                        key.src_port,
                        policy_dst_port,
                        None,
                        true,
                    )
                } else {
                    Some(crate::policy::evaluate_policy_result_without_counting_at(
                        &new_forwarding.policy,
                        from_id,
                        to_id,
                        key.src_ip,
                        policy_dst_ip,
                        key.protocol,
                        key.src_port,
                        policy_dst_port,
                        None,
                        now_ns,
                    ))
                };
                if !declined
                    && let Some(result) = result
                    && result.action == crate::policy::PolicyAction::Permit
                    && result.policy_counter_idx != 0
                    && let Some(matched_rule) = result
                        .policy_counter_idx
                        .checked_sub(1)
                        .and_then(|idx| usize::try_from(idx).ok())
                        .and_then(|idx| new_forwarding.policy.rules.get(idx))
                    && matched_rule.policy_id == result.policy_id
                {
                    let record = crate::protocol::PolicySessionRebind {
                        family: if key.addr_family == libc::AF_INET as u8 {
                            "v4".to_string()
                        } else {
                            "v6".to_string()
                        },
                        src_ip: key.src_ip.to_string(),
                        dst_ip: key.dst_ip.to_string(),
                        src_port: key.src_port,
                        dst_port: key.dst_port,
                        protocol: key.protocol,
                        routing_domain: key.routing_domain,
                        policy_id: result.policy_id,
                        rule_id: matched_rule.rule_id.clone(),
                        ingress_zone: from_id,
                        // Preserve the LocalDelivery metadata contract: its
                        // egress zone is the local interface's real zone, not
                        // the reserved zone used to evaluate junos-host policy.
                        egress_zone: if local_delivery {
                            metadata.egress_zone
                        } else {
                            to_id
                        },
                        tunnel_discriminator: key.discriminator.to_wire(),
                    };
                    retained = rebind_policy_sessions_from_snapshot(
                        sessions,
                        new_forwarding,
                        &[record],
                        session_map,
                        conntrack_v4_fd,
                        conntrack_v6_fd,
                        shared_sessions,
                        shared_nat_sessions,
                        shared_forward_wire_sessions,
                        shared_owner_rg_indexes,
                        peer_worker_commands,
                        worker_commands_by_id,
                        worker_id,
                        now_ns,
                    ) != 0;
                }
            }
        }
        if !retained {
            // Teardown context is the new state, same rule as the
            // rotation-purge note below: live reservations live in the new
            // allocator objects.
            delete_terminal_filtered_session(
                sessions,
                session_map.handle(),
                SharedSessionRefs {
                    sessions: shared_sessions,
                    nat_sessions: shared_nat_sessions,
                    forward_wire_sessions: shared_forward_wire_sessions,
                    owner_rg_indexes: shared_owner_rg_indexes,
                    peer_worker_commands: peer_worker_commands,
                    worker_commands_by_id: worker_commands_by_id,
                    conntrack: ConntrackFds { v4: conntrack_v4_fd, v6: conntrack_v6_fd },
                    tick: Tick::from_ns(now_ns),
                },
                new_forwarding,
                &key,
                decision,
                &metadata,
                origin,
                worker_id,
            );
            purged += 1;
        } else if declined {
            rematch_declined += 1;
        } else {
            rebound += 1;
        }
    }
    if rematch_declined > 0 {
        debug_log!(
            "RENAMED_FIRST_POLICY_REMAP_DECLINED: worker={} declined={}",
            worker_id,
            rematch_declined
        );
    }
    (rebound, purged)
}
#[expect(clippy::too_many_arguments, reason = "#17200: wide dataplane signature; census in docs/log/17200.md")]
pub(super) fn rebind_policy_sessions_from_snapshot(
    sessions: &mut crate::session::SessionTable,
    forwarding: &crate::afxdp::ForwardingState,
    records: &[crate::protocol::PolicySessionRebind],
    session_map: &crate::afxdp::bpf_map::SteeringMapRef,
    conntrack_v4_fd: libc::c_int,
    conntrack_v6_fd: libc::c_int,
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: &SharedSessionOwnerRgIndexes,
    peer_worker_commands: &[Arc<Mutex<VecDeque<WorkerCommand>>>],
    worker_commands_by_id: &WorkerCommandQueues,
    worker_id: u32,
    now_ns: u64,
) -> usize {
    let mut rebound = 0usize;
    if !forwarding.policy_rematch_extensive {
        return 0;
    }
    for record in records {
        let (addr_family, src_ip, dst_ip) = match record.family.as_str() {
            "v4" => (
                libc::AF_INET as u8,
                match record.src_ip.parse::<std::net::Ipv4Addr>() {
                    Ok(ip) => std::net::IpAddr::V4(ip),
                    Err(_) => continue,
                },
                match record.dst_ip.parse::<std::net::Ipv4Addr>() {
                    Ok(ip) => std::net::IpAddr::V4(ip),
                    Err(_) => continue,
                },
            ),
            "v6" => (
                libc::AF_INET6 as u8,
                match record.src_ip.parse::<std::net::Ipv6Addr>() {
                    Ok(ip) => std::net::IpAddr::V6(ip),
                    Err(_) => continue,
                },
                match record.dst_ip.parse::<std::net::Ipv6Addr>() {
                    Ok(ip) => std::net::IpAddr::V6(ip),
                    Err(_) => continue,
                },
            ),
            _ => continue,
        };
        let Some(discriminator) =
            policy_rebind_discriminator(record.protocol, record.tunnel_discriminator)
        else {
            // Missing/unrecognized tunnel identity is fail-closed. The
            // production Go capture deletes BPF GRE rows before this wire
            // record is built; this guard protects mixed-version/manual
            // records from aliasing a live tunnel under `None`.
            continue;
        };
        if record.rule_id.is_empty() {
            continue;
        }
        let Some((policy_counter_idx, rule)) =
            forwarding.policy.rule_binding_by_stable_id(&record.rule_id)
        else {
            continue;
        };
        if rule.policy_id != record.policy_id {
            continue;
        }
        let key = crate::session::SessionKey {
            addr_family,
            protocol: record.protocol,
            src_ip,
            dst_ip,
            src_port: record.src_port,
            dst_port: record.dst_port,
            discriminator,
            routing_domain: record.routing_domain,
        };
        if sessions.rebind_policy_pair(
            &key,
            record.policy_id,
            policy_counter_idx,
            rule.hit_counter.clone(),
            record.ingress_zone,
            crate::session::zone_vintage_check_for_id(
                &forwarding.zone_id_to_name,
                record.ingress_zone,
            ),
            record.egress_zone,
            crate::session::zone_vintage_check_for_id(
                &forwarding.zone_id_to_name,
                record.egress_zone,
            ),
        ) {
            let Some(entries) = sessions.policy_rebind_pair_entries(&key) else {
                continue;
            };
            // Restamp both map rows before publishing any shared alias. If a
            // live BPF row cannot be read or updated, tear down the newly
            // rebound pair rather than exposing a split policy identity.
            let bpf_ok = entries.iter().all(|entry| {
                restamp_bpf_conntrack_policy(
                    conntrack_v4_fd,
                    conntrack_v6_fd,
                    &entry.key,
                    &entry.metadata,
                )
            });
            if !bpf_ok {
                if let Some(entry) = entries.first() {
                    delete_terminal_filtered_session(
                        sessions,
                        session_map.handle(),
                        SharedSessionRefs {
                            sessions: shared_sessions,
                            nat_sessions: shared_nat_sessions,
                            forward_wire_sessions: shared_forward_wire_sessions,
                            owner_rg_indexes: shared_owner_rg_indexes,
                            peer_worker_commands: peer_worker_commands,
                            worker_commands_by_id: worker_commands_by_id,
                            conntrack: ConntrackFds { v4: conntrack_v4_fd, v6: conntrack_v6_fd },
                            tick: Tick::from_ns(now_ns),
                        },
                        forwarding,
                        &entry.key,
                        entry.decision,
                        &entry.metadata,
                        entry.origin,
                        worker_id,
                    );
                }
                continue;
            }
            crate::afxdp::shared_ops::restamp_shared_policy_entries(
                shared_sessions,
                shared_nat_sessions,
                shared_forward_wire_sessions,
                &entries,
            );
            for entry in entries {
                publish_worker_session_map_entry(
                    session_map.handle(),
                    forwarding,
                    &entry.key,
                    entry.decision,
                    &entry.metadata,
                    entry.origin,
                    true,
                );
            }
            rebound += 1;
        }
    }
    rebound
}

/// #6592: refresh the worker's per-tick `(validation, forwarding)` view from
/// ONE `ArcSwap` load, so the two halves can never come from different
/// generations.
///
/// # What went wrong with two loads
///
/// Validation and forwarding used to live in two independent `ArcSwap`s, and
/// this refresh performed two separate acquire-loads. A coordinator publish
/// landing between them left the worker holding one half from generation N and
/// the other from N-1 — a torn pair, unsafe in BOTH orientations:
/// - `(old validation, new forwarding)` — a packet stamped at the OLD
///   generation matches the worker's old validation, classifies `Valid`
///   (`classify_metadata`, `forwarding/fib.rs`), and is then forwarded under
///   the NEW tables. This is what #6291 named.
/// - `(new validation, old forwarding)` — the mirror. While the shim is still
///   stamping the OLD generation this pair only drops
///   (`ConfigGenerationMismatch`, or `FibGenerationMismatch` when only the FIB
///   generation moved). But once the new generation reaches `userspace_ctrl`
///   (written by the coordinator right after the view store since #18560, or
///   by Go from the reply), the shim stamps NEW; those
///   packets match the worker's new validation, classify `Valid`, and are
///   forwarded under the STALE tables — a withdrawn route still resolves, a
///   newly added deny is not applied. Nothing orders the Go control-map update
///   after every worker's next forwarding load. This is #6592.
///
/// Reordering the two loads cannot fix this. Producer and consumer must run in
/// OPPOSITE orders for an acquire/release pair, which excludes exactly one of
/// the two orientations and widens the other. #6291's reorder closed the first
/// and left the second — and the second is the COMMON one: it needs only the
/// forwarding load to land anywhere inside the publish window, whereas the
/// closed orientation needed the whole window (a full `ForwardingState` clone —
/// 69 fields, ~20 heap-owning collections including the FIB) to nest inside the
/// nanosecond-scale gap between two adjacent loads, i.e. a stalled worker.
///
/// # What one load buys
///
/// The coordinator publishes a single [`RuntimeView`] holding both halves
/// (`Coordinator::publish_runtime_view`). Whichever view this load observes,
/// its `validation` and `forwarding` were published together, so the returned
/// pair is coherent by construction. Neither orientation is reachable; there is
/// no pair to tear and no ordering discipline to get wrong.
///
/// Observing an OLD view is still possible and still SAFE: new-stamped packets
/// mismatch the old validation and DROP, the intended fail-closed behaviour.
/// This closes INCOHERENT pairs, not stale coherent ones — nothing here forces
/// a refresh.
///
/// # Cost
///
/// One `ArcSwap` load per tick where there used to be two, and the #1188
/// short-circuit is preserved exactly: `Arc::ptr_eq` against the caller's
/// cached forwarding returns `None` when the published forwarding `Arc` did not
/// rotate, so the caller's expensive rotation branch is skipped. A
/// validation-only publish (`bump_fib_generation`) rotates the view but reuses
/// the inner forwarding `Arc`, so it still short-circuits — see
/// `Coordinator::republish_runtime_validation`. The #5166 CoS pair is unchanged:
/// the caller still reads this view before the CoS map Arcs.
///
/// `between` is a deterministic test seam fired between reading the two halves
/// OUT of the loaded view. Under this implementation both reads come from the
/// same already-loaded `Arc`, so a coordinator publish injected there is
/// invisible and the returned pair stays coherent. Splitting the refresh back
/// into two `ArcSwap` loads — in EITHER order — makes an injected publish tear
/// the pair, which is exactly what
/// `snapshot_refresh_runtime_view_pair_is_atomic_6592` asserts against.
/// In `worker_loop`, the production callback captures the #15151
/// IPsec-inner transport and worker state to drain pending work and
/// verdict completions. It is not a ZST/no-op: this `#[inline]` generic
/// seam carries that work in the per-tick refresh path.
///
/// The callback receives the loaded `RuntimeView`. Unit tests inject a
/// publish from the callback after the load and assert that the returned
/// validation/forwarding pair remains coherent.
///
/// LIMIT, stated rather than left implicit: this seam pins the ordering INSIDE
/// this function, and the test drives this function rather than the real
/// `worker_loop`. A SECOND `shared_runtime.load()` added elsewhere in the tick
/// would pair halves across generations without tripping the test. That hole is
/// covered mechanically instead, by the reader-load count in
/// `tests/runtime_view_publish_canary.rs`.
#[inline]
pub(super) fn refresh_runtime_view(
    forwarding: &Arc<ForwardingState>,
    shared_runtime: &RuntimeViewReader,
    between: impl FnOnce(&crate::afxdp::types::RuntimeView),
) -> (Option<Arc<ForwardingState>>, ValidationState) {
    // ONE acquire-load. Everything below reads out of `view`, so the two
    // halves are from the same publish no matter what runs concurrently.
    let view = shared_runtime.load();
    let validation = view.validation();
    between(&view);
    // #1188: adopt the forwarding Arc only when it actually rotated.
    let new_forwarding = if Arc::ptr_eq(forwarding, view.forwarding()) {
        None
    } else {
        Some(view.forwarding().clone())
    };
    (new_forwarding, validation)
}

/// #18693: adopt one rotated forwarding snapshot — the cold
/// rotation-adoption orchestration, extracted verbatim from `worker_loop`
/// in loop_body/mod.rs (pure code motion into the #13075 reconcile sibling;
/// the walkers it drives already live here).
///
/// Runs ONLY when `refresh_runtime_view` observed a forwarding-snapshot
/// rotation, never on the per-packet path. Ordinary out-of-line fn like
/// the walkers it calls; the caller in `worker_loop` is a single
/// `if let Some(new_forwarding)` invocation, so execution order and
/// side-effect sequence are unchanged. `new_forwarding` is assigned into
/// `forwarding` exactly where the inline block assigned it, and the
/// #15188 generation guard is carried in `last_rebind_generation`.
/// Returns the cosine-changed flag (`cos_changed`) so the caller's
/// `rebuild_cos_fast_interfaces` handling is untouched.
#[expect(clippy::too_many_arguments, reason = "#17200: wide dataplane signature; census in docs/log/17200.md")]
#[inline(never)]
pub(super) fn adopt_rotated_forwarding(
    new_forwarding: Arc<ForwardingState>,
    cos_changed: bool,
    forwarding: &mut Arc<ForwardingState>,
    screen_state: &mut ScreenState,
    mut sessions: &mut crate::session::SessionTable,
    bindings: &mut [BindingWorker],
    binding_lookup: &WorkerBindingLookup,
    shared_recycles: &mut Vec<(u32, u64)>,
    last_rebind_generation: &mut u64,
    ha_state: &Arc<ArcSwap<BTreeMap<i32, HAGroupRuntime>>>,
    session_map: &crate::afxdp::bpf_map::SteeringMapRef,
    conntrack_v4_fd: c_int,
    conntrack_v6_fd: c_int,
    worker_id: u32,
    loop_now_ns: u64,
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: &SharedSessionOwnerRgIndexes,
    peer_worker_commands: &[Arc<Mutex<VecDeque<WorkerCommand>>>],
    worker_commands_by_id: &WorkerCommandQueues,
) -> bool {
    let (mut purge_input_filter_v4, mut purge_input_filter_v6) =
        crate::filter::input_dscp_filter_ifindexes_changed(
            &forwarding.filter_state,
            &new_forwarding.filter_state,
        );
    // #11330: lo0 republish scans the full session table. Compare
    // semantic filter content before assignment so unchanged rotations
    // can skip that walk; positional filter ids are not semantics.
    let (lo0_filter_changed_v4, lo0_filter_changed_v6) =
        crate::filter::lo0_filter_families_changed(
            &forwarding.filter_state,
            &new_forwarding.filter_state,
        );
    let lo0_filter_changed = lo0_filter_changed_v4 || lo0_filter_changed_v6;
    // #2362: per-packet-L4 filters share the DSCP session-hit
    // re-evaluation path. Merge the per-family sets of interfaces
    // whose cached route/action semantics changed; ordinary term,
    // counter, and log edits are handled by the next session hit.
    let (per_packet_changed_v4, per_packet_changed_v6) =
        crate::filter::input_per_packet_l4_filter_ifindexes_changed(
            &forwarding.filter_state,
            &new_forwarding.filter_state,
        );
    purge_input_filter_v4.extend(per_packet_changed_v4);
    purge_input_filter_v6.extend(per_packet_changed_v6);
    // #9526: compare BEFORE assignment. The Go commit sweep cannot clear
    // the literal first policy's sessions (policy_id 0 is overloaded on
    // the wire), so when this rotation removes the old snapshot's
    // policy_id-0 rule, the sessions bound to it are purged below.
    // Worker-local old vs new, like the cold-path slot compare: a worker
    // that skipped intermediate generations still sees the rule vanish.
    let deleted_first_policy =
        deleted_first_policy_rule_id(&forwarding.policy, &new_forwarding.policy);
    // #10510: derive actual old-minus-new zone disappearance before
    // assigning the new snapshot. Empty producer maps are a safe no-op.
    let removed_zone_ids = removed_zone_ids_for_rotation(&forwarding, &new_forwarding);
    // #16026 fold: single→multi-zone transition. Existing PASS
    // rows in the pinned map were published under the old
    // single-zone state and stay zoneless until their session
    // ends; capture the transition BEFORE assignment (worker-
    // local old vs new, like the removed-zone compare above —
    // a worker that skipped generations still sees it). The
    // demotion sweep itself runs after `forwarding` is rotated
    // below, beside the lo0 republish.
    let became_multi_zone =
        !forwarding.has_multiple_zones && new_forwarding.has_multiple_zones;
    let extensive_rematch = new_forwarding.policy_rematch_extensive;

    // Use NEW values for dependent state updates (forwarding-site
    // ordering — old `forwarding` is stale once rotated).
    screen_state.update_profiles(new_forwarding.screen_profiles.clone());
    // #3082: re-thread the references-missing-profile set on every
    // runtime forwarding-snapshot rotation so a newly-introduced
    // dangling screen reference starts WARNing (and a fixed one stops).
    screen_state.update_missing_profiles(new_forwarding.screen_missing_profiles.clone());
    screen_state.update_inert_profiles(new_forwarding.screen_inert_profiles.clone());
    screen_state.update_syn_cookie_keys(
        new_forwarding.syn_cookie_master_key.0,
        new_forwarding.syn_cookie_key_ring.clone(),
    );
    sessions.set_timeouts(new_forwarding.session_timeouts);
    // #3527: re-apply the per-screened-zone half-open overrides on every
    // runtime forwarding-snapshot rotation. `set_opening_overrides` is a
    // full replace, so a zone whose `syn-flood timeout` was removed
    // drops out and reverts to the global default on the next install.
    sessions.set_opening_overrides(new_forwarding.session_opening_overrides.clone());
    // #2134/#11057: re-derive optional destination accounting on every
    // runtime forwarding-snapshot rotation. An ON->OFF transition
    // clears only the destination map; source counts remain current
    // for the always-enforced default per-source quota.
    sessions.set_session_limit_active(screen_state.any_session_limit_dst_configured());

    // #1635 (plan §2.4): a config apply may have reassigned
    // cold-path histogram slots to new zone-pairs. Zero those
    // slots in every binding's worker-local accumulator BEFORE
    // any record_sample into the reused slot, so a reused slot
    // never carries the previous zone-pair's counts.
    //
    // Copilot code-r2: derive the zero-set from THIS WORKER's
    // OWN old map vs the new map, NOT from the coordinator's
    // `slots_to_zero` list. A worker can skip intermediate
    // ForwardingState generations (ArcSwap only ever delivers
    // the latest), and the coordinator computes `slots_to_zero`
    // relative to its immediately-previous map — so a slot
    // reassigned in a skipped generation would be absent from
    // the latest list (it now looks "retained"). Comparing the
    // worker's actual old slot-map inverse against the new one
    // is generation-independent: any slot whose mapping changed
    // since the worker last observed it gets zeroed. The
    // sibling atomics are overwritten at the next publish merge
    // from the freshly-zeroed local accumulator.
    {
        let old_inverse = &forwarding.cold_path_slot_map.inverse;
        let new_inverse = &new_forwarding.cold_path_slot_map.inverse;
        for slot in 0..crate::afxdp::cold_path_hist::POLICY_COLD_PATH_ZONE_PAIR_SLOTS {
            let new_pair = new_inverse.get(slot).copied().flatten();
            // Zero when the slot now maps to a pair that differs
            // from what the worker last saw there. A freed slot
            // (new == None) keeps its stale local data harmlessly
            // — it is unmapped, never sampled, and gets zeroed
            // when next reassigned.
            if new_pair.is_some() && new_pair != old_inverse.get(slot).copied().flatten() {
                for binding in bindings.iter_mut() {
                    binding.cold_path.zero_slot(slot);
                }
            }
        }
    }

    // Teardown runs against the NEW state deliberately: interface-NAT
    // identity is Arc-shared across the rotation, pool/NAT64
    // allocators are reused-or-reseeded into the new objects
    // (parse_source_nat_rules_with_previous + carry), and old-only
    // allocator objects die with the old ForwardingState — so only
    // the new tables can free the live (possibly carried)
    // reservation. Releasing against the old state would miss carried
    // copies and strand them in the new allocators.
    let (rematched_rebound, rematched_purged) = rematch_bound_first_policy_sessions(
        &forwarding,
        &new_forwarding,
        &mut sessions,
        &session_map,
        conntrack_v4_fd,
        conntrack_v6_fd,
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &peer_worker_commands,
        &worker_commands_by_id,
        worker_id,
        loop_now_ns,
    );
    if rematched_rebound + rematched_purged > 0 {
        debug_log!(
            "RENAMED_FIRST_POLICY_REMAP: worker={} rebound={} purged={}",
            worker_id,
            rematched_rebound,
            rematched_purged,
        );
    }
    // Keep the old interface/VLAN mapping for session filter identity
    // resolution; teardown itself must use the rotated forwarding
    // state so carried NAT reservations are released there.
    let old_forwarding_for_filter_purge = (*forwarding).clone();

    *forwarding = new_forwarding;
    // #15188 (C08-02): consume this generation's single-use rebinds
    // exactly once. The coordinator strips the retained metadata
    // after a full apply publishes it, so helper-internal republishes
    // (neighbor push, HA fabric refresh) already arrive with
    // `rebinds=0`; this generation guard is the worker-side half of
    // the same invariant — a republished forwarding Arc that still
    // carries rebinds for the config generation this worker already
    // consumed must not re-run the per-record restamp walk. The
    // record is applied exactly once per generation.
    let rebind_generation = forwarding.config_generation;
    let rebind_records: &[crate::protocol::PolicySessionRebind] =
        if rebind_generation == *last_rebind_generation {
            &[]
        } else {
            *last_rebind_generation = rebind_generation;
            &forwarding.policy_session_rebinds
        };
    let rebound_policy_sessions = rebind_policy_sessions_from_snapshot(
        &mut sessions,
        &forwarding,
        rebind_records,
        &session_map,
        conntrack_v4_fd,
        conntrack_v6_fd,
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &peer_worker_commands,
        &worker_commands_by_id,
        worker_id,
        loop_now_ns,
    );
    if rebound_policy_sessions > 0 {
        debug_log!(
            "RENAMED_POLICY_REBIND: worker={} sessions={}",
            worker_id,
            rebound_policy_sessions,
        );
    }

    let purged_removed_zone_sessions = purge_sessions_with_removed_zone_ids(
        &mut sessions,
        session_map.handle(),
        SharedSessionRefs {
            sessions: &shared_sessions,
            nat_sessions: &shared_nat_sessions,
            forward_wire_sessions: &shared_forward_wire_sessions,
            owner_rg_indexes: &shared_owner_rg_indexes,
            peer_worker_commands: &peer_worker_commands,
            worker_commands_by_id: &worker_commands_by_id,
            conntrack: ConntrackFds {
                v4: conntrack_v4_fd,
                v6: conntrack_v6_fd,
            },
            tick: Tick::from_ns(loop_now_ns),
        },
        &forwarding,
        &removed_zone_ids,
        worker_id,
    );
    if purged_removed_zone_sessions > 0 {
        debug_log!(
            "REMOVED_ZONE_SYNC_PURGE: worker={} zones={} sessions={}",
            worker_id,
            removed_zone_ids.len(),
            purged_removed_zone_sessions,
        );
    }
    let purged_input_filter = purge_sessions_for_changed_input_filter_cached_semantics(
        &mut sessions,
        session_map.handle(),
        SharedSessionRefs {
            sessions: &shared_sessions,
            nat_sessions: &shared_nat_sessions,
            forward_wire_sessions: &shared_forward_wire_sessions,
            owner_rg_indexes: &shared_owner_rg_indexes,
            peer_worker_commands: &peer_worker_commands,
            worker_commands_by_id: &worker_commands_by_id,
            conntrack: ConntrackFds {
                v4: conntrack_v4_fd,
                v6: conntrack_v6_fd,
            },
            tick: Tick::from_ns(loop_now_ns),
        },
        &old_forwarding_for_filter_purge,
        &forwarding,
        &purge_input_filter_v4,
        &purge_input_filter_v6,
        worker_id,
    );
    if purged_input_filter > 0 {
        debug_log!(
            "INPUT_FILTER_CACHE_REVALIDATION_PURGE: worker={} sessions={}",
            worker_id,
            purged_input_filter,
        );
    }
    if !extensive_rematch {
        if let Some(rule_id) = deleted_first_policy.as_deref() {
            let purged_first_policy = purge_sessions_bound_to_deleted_first_policy(
                &mut sessions,
                session_map.handle(),
                SharedSessionRefs {
                    sessions: &shared_sessions,
                    nat_sessions: &shared_nat_sessions,
                    forward_wire_sessions: &shared_forward_wire_sessions,
                    owner_rg_indexes: &shared_owner_rg_indexes,
                    peer_worker_commands: &peer_worker_commands,
                    worker_commands_by_id: &worker_commands_by_id,
                    conntrack: ConntrackFds {
                        v4: conntrack_v4_fd,
                        v6: conntrack_v6_fd,
                    },
                    tick: Tick::from_ns(loop_now_ns),
                },
                &forwarding,
                rule_id,
                worker_id,
            );
            if purged_first_policy > 0 {
                debug_log!(
                    "DELETED_FIRST_POLICY_PURGE: worker={} rule={} sessions={}",
                    worker_id,
                    rule_id,
                    purged_first_policy,
                );
            }
        }
    }
    let republished = republish_local_delivery_sessions_for_lo0_filter(
        &sessions,
        session_map.handle(),
        &forwarding,
        lo0_filter_changed,
    );
    if republished > 0 {
        debug_log!(
            "LO0_FILTER_REPUBLISH: worker={} local_delivery_sessions={}",
            worker_id,
            republished,
        );
    }
    // #16026 fold: demote already-published PASS rows on the
    // single→multi-zone transition captured above. Runs with
    // the NEW forwarding state (has_multiple_zones set), so the
    // republish writes REDIRECT and `publish_session_rows`
    // migrates each entry's claims without a no-row window.
    // `ha_state` is sampled here (not the later per-tick load)
    // so `allow_replace_local` matches this rotation.
    if became_multi_zone {
        let demoted = demote_kernel_local_sessions_for_multiple_zones(
            &sessions,
            session_map.handle(),
            &forwarding,
            ha_state.load().as_ref(),
            loop_now_ns / 1_000_000_000,
            became_multi_zone,
        );
        if demoted > 0 {
            debug_log!(
                "MULTI_ZONE_STEERING_DEMOTE: worker={} sessions={}",
                worker_id,
                demoted,
            );
        }
    }

    if cos_changed {
        reset_worker_cos_runtimes(bindings, shared_recycles);
        apply_shared_recycles_to_bindings(bindings, binding_lookup, shared_recycles);
    }
    cos_changed
}

/// #9856: one worker's resumable owner-RG export. Lives in the worker-loop
/// locals (persists across passes); `None` = idle. Adopted from
/// `WorkerCommandResults` when Export commands arrive; cleared on completion
/// (after acking). Single slot: a timeout-then-rekick overwrites (with
/// purge-foreign); concurrent kicks never reach here (coordinator BUSY).
pub(in crate::afxdp) struct WorkerExportState {
    /// Resume cursor (slab slot) for `iter_export_budgeted`.
    pub(in crate::afxdp) cursor: usize,
    /// Epoch predicate bound, captured at command accept.
    pub(in crate::afxdp) kick_epoch: u64,
    /// Requested owner RGs (union for the tick-batch).
    pub(in crate::afxdp) owner_rgs: Vec<i32>,
    /// Command sequences this export satisfies (acked on completion).
    pub(in crate::afxdp) sequences: Vec<u64>,
    /// Window token tagging every push (M2c: the kicked command sequence;
    /// M3: the opaque continuation token). Pinned at adopt; purge + push +
    /// collect all key on it.
    pub(in crate::afxdp) token: u64,
}
