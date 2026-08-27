// decapsulated missing-neighbor handling, replay filtering, and DNAT-table publish/delete.
//
// Split out of afxdp/tests.rs (#4840) as a sibling `#[path]` test module
// loaded from afxdp/mod.rs. Pure code motion: every #[test] fn is moved
// verbatim; shared test-support helpers live in afxdp/tests_support.rs.
#![allow(unused_imports)]

use super::test_fixtures::*;
use super::worker::WorkerTxPipeline;
use super::*;
use crate::test_zone_ids::*;
use crate::xsk_ffi::IfInfo;
use crate::{
    ClassOfServiceSnapshot, CoSDSCPClassifierEntrySnapshot, CoSDSCPClassifierSnapshot,
    CoSForwardingClassSnapshot, CoSIEEE8021ClassifierEntrySnapshot, CoSIEEE8021ClassifierSnapshot,
    CoSSchedulerMapEntrySnapshot, CoSSchedulerMapSnapshot, CoSSchedulerSnapshot,
    DestinationNATRuleSnapshot, FirewallFilterSnapshot, FirewallTermSnapshot,
    InterfaceAddressSnapshot, NeighborSnapshot, PolicyRuleSnapshot, RouteSnapshot,
    SourceNATRuleSnapshot, StaticNATRuleSnapshot, ThreeColorPolicerSnapshot, ZoneSnapshot,
};
use super::tests_support::*;

/// #1902: VLAN-tagged underlay (the live reth0.80 shape, #1885
/// parity) — the buffered outer frame's L3 sits at 18 while the inner
/// meta says 14, so the pre-fix retry rewrote the dot1q tail.
#[test]
fn txn_decapped_missing_neighbor_not_buffered_tagged() {
    assert_decapped_missing_neighbor_never_buffered_or_retried(80);
}


/// #1902: untagged underlay — `outer_frame[14..]` IS the outer L3
/// header (valid version nibble), so the pre-fix retry TXed the
/// still-encapsulated OUTER GRE packet toward the INNER next-hop.
/// Byte-indistinguishable from a valid frame at retry time, which is
/// why the fix gates ADMISSION rather than detecting at retry.
#[test]
fn txn_decapped_missing_neighbor_not_buffered_untagged() {
    assert_decapped_missing_neighbor_never_buffered_or_retried(0);
}


/// #1902 regression pin for the UNCHANGED path: a NON-decapped packet
/// (desc and meta describe the same UMEM frame) with a cold neighbor
/// must still buffer in pending_neigh, and after resolution the retry
/// must TX the correctly rewritten ORIGINAL packet (resolved dst MAC,
/// egress src MAC, TTL-1, IP/L4 bytes otherwise identical).
#[test]
fn txn_non_decap_missing_neighbor_buffers_and_retries_correctly() {
    let mut forwarding = build_forwarding_state(&gre_to_self_snapshot());
    let ha_state = txn_ha_state();
    let mut bindings = vec![BindingWorker::new_for_mirror_test(0, 0, 24, 0)];
    bindings[0].interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();

    // LAN hairpin: 10.0.61.102 -> 10.0.61.50, directly connected on
    // reth1.0 (egress == ingress binding), neighbor cold.
    let dst = Ipv4Addr::new(10, 0, 61, 50);
    let frame =
        build_txn_tcp_syn_frame_v4(Ipv4Addr::new(10, 0, 61, 102), dst, 12345, 443, TCP_FLAG_SYN);
    let meta = txn_meta_v4(24, TCP_FLAG_SYN, frame.len() as u16);
    let (_batch, dbg) = txn_run_descriptor(
        &mut bindings[0],
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
    );
    assert_eq!(dbg.missing_neigh, 1, "cold neighbor -> MissingNeighbor arm");
    assert_eq!(
        bindings[0].pending_neigh.len(),
        1,
        "a non-decapped cold-neighbor packet must still buffer"
    );
    assert_eq!(
        bindings[0]
            .live
            .pending_neigh_decap_drops
            .load(Ordering::Relaxed),
        0,
        "the decap gate must not touch UMEM-paired packets"
    );

    let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
    forwarding
        .neighbors
        .insert((24, IpAddr::V4(dst)), NeighborEntry { mac });
    let lookup = WorkerBindingLookup::from_bindings(&bindings);
    let mirror_targets = MirrorTargetMap::default();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let mut shared_recycles = Vec::new();
    let area = bindings[0].umem.area() as *const MmapArea;
    let (left, rest) = bindings.split_at_mut(0);
    let (binding, right) = rest.split_first_mut().expect("ingress binding");
    retry_pending_neigh(
        binding,
        left,
        0,
        right,
        &lookup,
        &mirror_targets,
        &forwarding,
        &dynamic_neighbors,
        None,
        123_000_000_100,
        // SAFETY: same single-threaded umem-area contract as above.
        unsafe { &*area },
        &mut shared_recycles,
    );
    assert!(
        bindings[0].pending_neigh.is_empty(),
        "entry consumed by retry"
    );
    let req = bindings[0]
        .tx_pipeline
        .pending_tx_prepared
        .front()
        .expect("resolved retry must produce a prepared TX");
    let rewritten = bindings[0]
        .umem
        .area()
        .slice(req.offset as usize, req.len as usize)
        .expect("rewritten frame")
        .to_vec();
    assert_eq!(
        &rewritten[0..6],
        &mac,
        "dst MAC must be the resolved neighbor"
    );
    assert_eq!(
        &rewritten[6..12],
        &[0x02, 0xbf, 0x72, 0x01, 0x00, 0x01],
        "src MAC must be the reth1.0 egress interface MAC"
    );
    assert_eq!(
        rewritten.len(),
        frame.len(),
        "no length change on a plain forward"
    );
    assert_eq!(rewritten[22], 63, "TTL decremented exactly once (64 -> 63)");
    assert_eq!(
        &rewritten[26..34],
        &frame[26..34],
        "IP src+dst must be byte-identical to the original packet"
    );
    assert_eq!(
        &rewritten[34..],
        &frame[34..],
        "L4 segment must be byte-identical to the original packet"
    );
}


/// #1873 replay-filter companion pin (AGY code r4 HIGH): filtering the
/// preserved synced-session replay list by purged tunnel ids must
/// mirror delete_synced_session's companion semantics — the derived
/// reverse companion (tunnel_endpoint_id == 0) of a dropped forward
/// entry is dropped too, never resurrected as a half-dead pair; a
/// reverse-marked entry drops standalone; unrelated entries survive.
#[test]
fn replay_filter_drops_purged_forward_and_derived_reverse_companion() {
    use crate::afxdp::coordinator::filter_replayed_synced_sessions;

    let nat = NatDecision {
        rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
        ..NatDecision::default()
    };
    let forward_key = SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        src_port: 12345,
        dst_port: 5201,
    };
    let reverse_key = crate::session::reverse_session_key(&forward_key, nat);
    let tunnel_resolution = ForwardingResolution {
        disposition: ForwardingDisposition::ForwardCandidate,
        local_ifindex: 0,
        egress_ifindex: 41,
        tx_ifindex: 3,
        tunnel_endpoint_id: 824,
        next_hop: None,
        neighbor_mac: Some([2, 0, 0, 0, 0, 9]),
        src_mac: Some([2, 0, 0, 0, 0, 1]),
        tx_vlan_id: 0,
    };
    let plain_resolution = ForwardingResolution {
        tunnel_endpoint_id: 0,
        ..tunnel_resolution
    };
    let make =
        |key: &SessionKey, resolution: ForwardingResolution, is_reverse: bool| SyncedSessionEntry {
            key: key.clone(),
            decision: SessionDecision { resolution, nat },
            metadata: SessionMetadata {
                ingress_zone: 1,
                egress_zone: 2,
                ingress_ifindex: 0,
                ingress_vlan_id: 0,
                owner_rg_id: 1,
                fabric_ingress: false,
                is_reverse,
                nat64_reverse: None,
                log_session_init: false,
                log_session_close: false,
                policy_id: 0,
                inactivity_timeout_ns: None,
                policy_counter_idx: 0,
                policy_counter: None,
            },
            origin: SessionOrigin::SyncImport,
            protocol: PROTO_TCP,
            tcp_flags: 0,
            // #2170 test fixture: no peer install generation.
            generation: 0,
            session_id: 0,
        };
    let unrelated_key = SessionKey {
        src_port: 23456,
        ..forward_key.clone()
    };

    // Case 1: tunnel-marked forward + unmarked derived reverse
    // companion + unrelated unmarked entry.
    let mut entries = vec![
        make(&forward_key, tunnel_resolution, false),
        make(&reverse_key, plain_resolution, true),
        make(&unrelated_key, plain_resolution, false),
    ];
    filter_replayed_synced_sessions(&mut entries, &[824]);
    assert_eq!(entries.len(), 1, "forward + derived reverse both dropped");
    assert_eq!(entries[0].key, unrelated_key);

    // Case 2: reverse-marked tunnel entry drops standalone; its
    // unmarked forward keeps forwarding (matches live purge
    // semantics: delete_synced_session on a reverse key derives no
    // companion).
    let mut entries = vec![
        make(&forward_key, plain_resolution, false),
        make(&reverse_key, tunnel_resolution, true),
    ];
    filter_replayed_synced_sessions(&mut entries, &[824]);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].key, forward_key);

    // Case 3: no purged ids — untouched.
    let mut entries = vec![make(&forward_key, tunnel_resolution, false)];
    filter_replayed_synced_sessions(&mut entries, &[7]);
    assert_eq!(entries.len(), 1);
}

/// #4975 membership-index pin: the drop set is a HashSet, but the retain
/// must stay behavior-identical to the prior `Vec::contains` scan — it
/// tests membership only, never reorders or over-drops. This exercises a
/// many-drop-keys set interleaved with survivors so a broken membership
/// index (wrong key type, a collision-prone hashable projection that
/// collapses distinct keys, or a survivor accidentally swept) is caught:
///   * survivors are returned in ORIGINAL order (retain is in-place);
///   * a survivor that shares src_ip/dst_ip/proto/family with a dropped
///     forward key and differs ONLY in src_port MUST survive — a
///     projection keyed on anything less than the whole SessionKey would
///     wrongly drop it;
///   * a derived reverse companion entry (present in the fixture with
///     tunnel-id 0, so NOT purged on its own) is swept because its parent
///     forward's purge inserts the derived reverse key, and a
///     reverse-marked purged entry drops standalone (asymmetry preserved).
/// INVARIANT PIN (not a diff-revert failure — Vec<->HashSet is
/// behavior-identical, so reverting THIS commit leaves the test green): a
/// lossy membership projection that collapses distinct keys, or a retain
/// that reorders, fails the ordered-survivor assertion. Validated against
/// the real optimization by manual fail-injection into the retain
/// predicate (see _Log.md), which goes RED here.
#[test]
fn replay_filter_preserves_order_and_survivors_across_many_drops() {
    use crate::afxdp::coordinator::filter_replayed_synced_sessions;

    let nat = NatDecision {
        rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
        ..NatDecision::default()
    };
    let base = SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        src_port: 10000,
        dst_port: 5201,
    };
    let key_at = |src_port: u16| SessionKey {
        src_port,
        ..base.clone()
    };
    let tunnel_resolution = |id: u16| ForwardingResolution {
        disposition: ForwardingDisposition::ForwardCandidate,
        local_ifindex: 0,
        egress_ifindex: 41,
        tx_ifindex: 3,
        tunnel_endpoint_id: id,
        next_hop: None,
        neighbor_mac: Some([2, 0, 0, 0, 0, 9]),
        src_mac: Some([2, 0, 0, 0, 0, 1]),
        tx_vlan_id: 0,
    };
    let make = |key: &SessionKey, resolution: ForwardingResolution, is_reverse: bool| {
        SyncedSessionEntry {
            key: key.clone(),
            decision: SessionDecision { resolution, nat },
            metadata: SessionMetadata {
                ingress_zone: 1,
                egress_zone: 2,
                ingress_ifindex: 0,
                ingress_vlan_id: 0,
                owner_rg_id: 1,
                fabric_ingress: false,
                is_reverse,
                nat64_reverse: None,
                log_session_init: false,
                log_session_close: false,
                policy_id: 0,
                inactivity_timeout_ns: None,
                policy_counter_idx: 0,
                policy_counter: None,
            },
            origin: SessionOrigin::SyncImport,
            protocol: PROTO_TCP,
            tcp_flags: 0,
            generation: 0,
            session_id: 0,
        }
    };

    // Purge ids 100..=131 (a large drop set). Build many purged forward
    // entries interleaved with survivors. One survivor (`survivor_shares_ip`)
    // shares every field of a purged forward except src_port — a lossy index
    // would wrongly sweep it. A derived reverse companion entry (below) that
    // is NOT itself purged must still drop, swept by its forward's purge.
    let purge_ids: Vec<u16> = (100u16..=131).collect();
    // The derived reverse companion of the FIRST purged forward
    // (src_port 40000). It carries tunnel-id 0, so it is never purged on its
    // own — it must drop ONLY because the forward's purge inserts this
    // reverse key into the drop set (the companion-derivation semantic the
    // sibling test pins at unit scale; here it must hold amid many drops).
    let derived_companion = crate::session::reverse_session_key(&key_at(40000), nat);
    let survivor_shares_ip = key_at(20000); // distinct src_port, not purged
    let survivor_other = SessionKey {
        src_port: 30000,
        dst_port: 443,
        ..base.clone()
    };

    let mut entries: Vec<SyncedSessionEntry> = Vec::new();
    let mut expected_survivors: Vec<SessionKey> = Vec::new();

    // A leading survivor to pin that position 0 is retained.
    entries.push(make(&survivor_other, tunnel_resolution(0), false));
    expected_survivors.push(survivor_other.clone());

    for (i, &id) in purge_ids.iter().enumerate() {
        // Each purged forward uses a unique src_port so its derived
        // reverse companion is unique too.
        let fk = key_at(40000 + i as u16);
        entries.push(make(&fk, tunnel_resolution(id), false));
        // Interleave the derived reverse companion of the first purged
        // forward early. tunnel-id 0 → not purged on its own; it must drop
        // solely via the forward's inserted reverse key. NOT a survivor.
        if i == 1 {
            entries.push(make(&derived_companion, tunnel_resolution(0), true));
        }
        // Interleave the shared-IP survivor exactly once, mid-stream.
        if i == purge_ids.len() / 2 {
            entries.push(make(&survivor_shares_ip, tunnel_resolution(0), false));
            expected_survivors.push(survivor_shares_ip.clone());
        }
    }

    // A reverse-marked purged entry (drops standalone; no companion added).
    let reverse_only = SessionKey {
        src_port: 55000,
        ..base.clone()
    };
    entries.push(make(&reverse_only, tunnel_resolution(131), true));

    // A trailing survivor to pin the last position is retained.
    let survivor_tail = SessionKey {
        src_port: 60000,
        ..base.clone()
    };
    entries.push(make(&survivor_tail, tunnel_resolution(0), false));
    expected_survivors.push(survivor_tail.clone());

    filter_replayed_synced_sessions(&mut entries, &purge_ids);

    let got: Vec<SessionKey> = entries.iter().map(|e| e.key.clone()).collect();
    assert_eq!(
        got, expected_survivors,
        "survivors must be exactly the non-purged entries, in original order"
    );
    // The shared-IP survivor differs from purged forwards only in src_port
    // — an index keyed on less than the whole SessionKey would drop it.
    assert!(
        got.contains(&survivor_shares_ip),
        "survivor sharing src_ip/dst_ip/proto with purged keys must not be swept"
    );
    // The derived reverse companion (tunnel-id 0, never purged on its own)
    // must be swept by its forward's purge — the companion-derivation
    // semantic, exercised amid many drops.
    assert!(
        !got.contains(&derived_companion),
        "derived reverse companion of a purged forward must be dropped"
    );
}

// ---------------------------------------------------------------------------
// #2244: publish_dnat_table_entry must surface bpf_map_update_elem failures.
//
// Before #2244 the syscall return was discarded with `unsafe { ... };`, so a
// failed reverse-SNAT dnat_table publish (map at capacity / EINVAL / bad fd)
// was completely silent — no counter, no log. The embedded-ICMP NAT path then
// cannot reverse-NAT an inbound ICMP error (PMTUD / traceroute) back to the
// original source. These tests pin the new contract:
//   * the function returns `true` for the no-op / nothing-to-publish paths,
//   * it returns `false` when the syscall actually fails, and
//   * the worker call-site increment logic bumps `dnat_publish_errors` on
//     `false` and leaves it at 0 otherwise.
//
// FAIL-ON-REVERT: if the syscall return is discarded again (function reverts
// to `-> ()` / ignores `rc`), `publish_dnat_table_entry` can no longer report
// the failure, the `false` assertion and the counter-increment assertion both
// regress, and these tests fail.
// ---------------------------------------------------------------------------


#[test]
fn publish_dnat_table_entry_noops_return_true() {
    // No SNAT rewrite → nothing to publish, treated as success.
    let no_snat = NatDecision::default();
    assert!(publish_dnat_table_entry(
        &DnatTableFds { v4: Some(-1), v6: None },
        &dnat_v4_key(),
        no_snat,
    ));

    // SNAT present but no v4 table fd → nothing to publish, success.
    assert!(publish_dnat_table_entry(
        &DnatTableFds::default(),
        &dnat_v4_key(),
        dnat_snat_decision(),
    ));

    // SNAT present but the key is not AF_INET → unsupported family, success.
    let mut v6_key = dnat_v4_key();
    v6_key.addr_family = libc::AF_INET6 as u8;
    assert!(publish_dnat_table_entry(
        &DnatTableFds { v4: Some(-1), v6: None },
        &v6_key,
        dnat_snat_decision(),
    ));
}


#[test]
fn publish_dnat_table_entry_reports_syscall_failure() {
    // An invalid map fd forces bpf_map_update_elem to fail (EBADF). The
    // function must now report that failure instead of swallowing it.
    let fds = DnatTableFds { v4: Some(-1), v6: None };
    let ok = publish_dnat_table_entry(&fds, &dnat_v4_key(), dnat_snat_decision());
    assert!(
        !ok,
        "publish_dnat_table_entry must return false when bpf_map_update_elem fails"
    );
}

// ---------------------------------------------------------------------------
// #2979: the close-handler dnat_table delete MUST key on the exact same bytes
// the install-path publish wrote, or the delete misses and the entry leaks.
// These tests pin the v4/v6 key encoding (the SSOT used by both publish and
// delete) and the no-op contracts of delete_dnat_table_entry.
//
// FAIL-ON-REVERT: change either key helper's byte layout (or let publish and
// delete diverge) and the byte-equality assertions go red.
// ---------------------------------------------------------------------------


#[test]
fn dnat_v4_key_bytes_matches_publish_encoding() {
    // protocol, snat_ip = 172.16.80.8, snat_port = 54321 (host-order native).
    let dk = dnat_v4_key_bytes(&dnat_v4_key(), dnat_snat_decision())
        .expect("SNAT v4 flow must yield a key");
    let mut want = [0u8; 12];
    want[0] = PROTO_TCP;
    want[4..8].copy_from_slice(&Ipv4Addr::new(172, 16, 80, 8).octets());
    want[8..10].copy_from_slice(&54321u16.to_ne_bytes());
    assert_eq!(dk, want, "v4 dnat_table key encoding drifted from the publish path");

    // No SNAT -> no key (close is a no-op for plain flows).
    assert!(dnat_v4_key_bytes(&dnat_v4_key(), NatDecision::default()).is_none());
    // Wrong family -> no v4 key.
    let mut v6_key = dnat_v4_key();
    v6_key.addr_family = libc::AF_INET6 as u8;
    assert!(dnat_v4_key_bytes(&v6_key, dnat_snat_decision()).is_none());
}


#[test]
fn dnat_v6_key_bytes_matches_entry_bytes_key_half() {
    let snat_v6: std::net::Ipv6Addr = "2001:559:8585:80::8".parse().unwrap();
    let orig_v6: std::net::Ipv6Addr = "2001:559:8585:61::100".parse().unwrap();
    let key = SessionKey {
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V6(orig_v6),
        dst_ip: IpAddr::V6("2001:559:8585:80::200".parse().unwrap()),
        src_port: 12345,
        dst_port: 443,
    };
    let nat = NatDecision {
        rewrite_src: Some(IpAddr::V6(snat_v6)),
        rewrite_src_port: Some(54321),
        ..NatDecision::default()
    };
    let dk = dnat_v6_key_bytes(&key, nat).expect("SNAT66 flow must yield a key");
    // The delete key MUST byte-match the KEY half of the publish-path encoder.
    let (entry_key, _entry_val) =
        dnat_v6_entry_bytes(PROTO_TCP, snat_v6, 54321, orig_v6, 12345);
    assert_eq!(
        dk, entry_key,
        "v6 dnat_table_v6 delete key drifted from publish (dnat_v6_entry_bytes)"
    );
}


#[test]
fn delete_dnat_table_entry_noops_without_snat_or_fd() {
    use crate::afxdp::checksum::DNAT_DELETE_ATTEMPTS;
    // #6872: this file had THREE readers of the process-global counter,
    // TWO function-local `static GUARD`s that serialized nothing, and no
    // shared guard. The issue named one unguarded reader and neither local
    // guard here — an enumeration is a floor, not a census.
    let _g = crate::afxdp::checksum::dnat_counter_guard();
    use std::sync::atomic::Ordering;
    let before = DNAT_DELETE_ATTEMPTS.load(Ordering::Relaxed);
    // No SNAT decision -> nothing was published -> no delete attempt.
    delete_dnat_table_entry(
        &DnatTableFds { v4: Some(-1), v6: None },
        &dnat_v4_key(),
        NatDecision::default(),
    );
    // SNAT present but no table fd -> no delete attempt.
    delete_dnat_table_entry(&DnatTableFds::default(), &dnat_v4_key(), dnat_snat_decision());
    assert_eq!(
        DNAT_DELETE_ATTEMPTS.load(Ordering::Relaxed),
        before,
        "delete_dnat_table_entry must be a no-op for non-SNAT flows and absent fds"
    );
}


#[test]
fn publish_dnat_table_entry_failure_increments_counter() {
    // Mirror the worker poll call-site increment logic against a real
    // BindingLiveState. Pre-#2244 the counter did not exist and the syscall
    // result was discarded, so this increment was impossible.
    let live = BindingLiveState::new();
    assert_eq!(live.dnat_publish_errors.load(Ordering::Relaxed), 0);

    // Success / no-op path: no increment.
    if !publish_dnat_table_entry(&DnatTableFds::default(), &dnat_v4_key(), dnat_snat_decision()) {
        live.dnat_publish_errors.fetch_add(1, Ordering::Relaxed);
    }
    assert_eq!(
        live.dnat_publish_errors.load(Ordering::Relaxed),
        0,
        "no-op publish must not bump the error counter"
    );

    // Failing publish (bad fd): increment fires.
    let fds = DnatTableFds { v4: Some(-1), v6: None };
    if !publish_dnat_table_entry(&fds, &dnat_v4_key(), dnat_snat_decision()) {
        live.dnat_publish_errors.fetch_add(1, Ordering::Relaxed);
    }
    assert_eq!(
        live.dnat_publish_errors.load(Ordering::Relaxed),
        1,
        "failed dnat_table publish must increment dnat_publish_errors"
    );

    // A second failure accumulates.
    if !publish_dnat_table_entry(&fds, &dnat_v4_key(), dnat_snat_decision()) {
        live.dnat_publish_errors.fetch_add(1, Ordering::Relaxed);
    }
    assert_eq!(live.dnat_publish_errors.load(Ordering::Relaxed), 2);
}

// ---------------------------------------------------------------------------
// #2406: IPv6 SNAT66-return reverse-NAT must be published to dnat_table_v6.
//
// Before #2406 publish_dnat_table_entry had ONLY a (AF_INET, V4) arm; an
// AF_INET6 SNAT'd flow fell through `_ => true` and NOTHING was written to
// dnat_table_v6. The shim's GRE-inner v6 classify therefore never saw the
// reverse mapping, so an inbound ICMPv6 error (PMTUD Packet-Too-Big /
// traceroute Time-Exceeded) carried over a native-GRE tunnel whose inner
// destination is the SNAT66 pool address was not steered to the helper —
// silent IPv6 PMTUD/traceroute blackhole behind pool-mode SNAT66.
//
// FAIL-ON-REVERT: drop the (AF_INET6, V6) arm in publish_dnat_table_entry
// and both tests below regress — `dnat_v6_entry_bytes` disappears
// (compile error) and the publish-attempt test sees the AF_INET6 key
// return `true` (no syscall) instead of `false` (EBADF on the forced-bad
// v6 fd).
// ---------------------------------------------------------------------------


#[test]
fn dnat_v6_entry_bytes_matches_struct_layout() {
    // Reverse mapping: inbound return packet carries dst = SNAT addr/port;
    // the value steers it back to the original pre-NAT source.
    let snat: Ipv6Addr = "2001:559:8585:80::8".parse().unwrap();
    let orig: Ipv6Addr = "2001:559:8585:61::100".parse().unwrap();
    let (dk, dv) = dnat_v6_entry_bytes(PROTO_TCP, snat, 54321, orig, 12345);

    // struct dnat_key_v6 (24B): protocol, 3B pad, 16B dst_ip, dst_port, from_zone.
    assert_eq!(dk[0], PROTO_TCP, "key protocol");
    assert_eq!(&dk[1..4], &[0u8; 3], "key pad must be zero");
    assert_eq!(&dk[4..20], &snat.octets(), "key dst_ip = SNAT address");
    // #2406 FAIL-ON-REVERT: the KEY port is HOST-ORDER numeric serialized
    // natively (to_ne_bytes), matching the AF_XDP shim reader. The pre-fix
    // code wrote to_be_bytes (network order); on little-endian x86 those byte
    // arrays differ ([0x31,0xd4] host vs [0xd4,0x31] network for 54321), so
    // reverting dnat_v6_entry_bytes to to_be_bytes makes this assertion RED.
    assert_eq!(
        &dk[20..22],
        &54321u16.to_ne_bytes(),
        "key dst_port = SNAT port HOST-ORDER (native) to match shim from_be_bytes reader"
    );
    assert_eq!(&dk[22..24], &[0u8; 2], "key from_zone = 0");

    // struct dnat_value_v6 (20B): 16B new_dst_ip, new_dst_port, flags, pad.
    // VALUE is never read by the shim; encoding is inert (kept network-order).
    assert_eq!(&dv[0..16], &orig.octets(), "value new_dst_ip = original source");
    assert_eq!(&dv[16..18], &12345u16.to_be_bytes(), "value new_dst_port (inert)");
    assert_eq!(dv[18], 0, "value flags = 0 (dynamic SNAT-return)");
    assert_eq!(dv[19], 0, "value pad = 0");
}


// #2406 Go<->Rust dnat-key PARITY: the bytes the Rust publisher writes for
// the dnat_table_v6 KEY (port field) must EXACTLY equal what the AF_XDP shim
// reader builds for the same (proto, snat_ip, snat_port) tuple. The shim
// reader builds its key port via u16::from_be_bytes(wire) (host-order
// numeric) and stores it natively. The Go publisher (DNATKeyForSessionV6 /
// dnat_v6_entry_bytes here) must produce the SAME native bytes. This is the
// regression guard that would have caught the 3c network-order bug: the only
// correct encoding for a host-order numeric port P, stored natively, is
// P.to_ne_bytes(). Mirror the shim's reader construction here as golden bytes.
#[test]
fn dnat_v6_key_port_parity_with_shim_reader() {
    // Wire bytes for port 443 on the packet: network order [0x01, 0xbb].
    // The shim reads them as u16::from_be_bytes([0x01,0xbb]) = 443 (host),
    // then stores the key struct natively => key port bytes = 443.to_ne_bytes().
    let wire_port_bytes = [0x01u8, 0xbb]; // network-order 443 on the wire
    let shim_host_numeric = u16::from_be_bytes(wire_port_bytes); // == 443
    let shim_key_port_bytes = shim_host_numeric.to_ne_bytes(); // native store

    // The publisher is handed snat_port as a HOST-ORDER numeric (443).
    let snat: Ipv6Addr = "2001:559:8585:80::8".parse().unwrap();
    let orig: Ipv6Addr = "2001:559:8585:61::100".parse().unwrap();
    let (dk, _dv) = dnat_v6_entry_bytes(PROTO_TCP, snat, 443, orig, 12345);

    assert_eq!(
        &dk[20..22],
        &shim_key_port_bytes,
        "Rust dnat_table_v6 KEY port bytes must equal the shim reader's key port bytes for port 443"
    );
    // Numeric sanity: 443 host-order on LE x86 is [0xbb,0x01]; the OLD network
    // encoding (to_be_bytes) would be [0x01,0xbb] and FAIL this parity check.
    assert_eq!(shim_host_numeric, 443, "from_be_bytes of network wire yields host numeric");
}


#[test]
fn publish_dnat_table_entry_v6_attempts_publish() {
    // Pre-#2406 an AF_INET6 SNAT'd flow returned `true` via the `_ => true`
    // fall-through WITHOUT touching dnat_table_v6. With the v6 arm wired, a
    // present-but-invalid v6 fd forces bpf_map_update_elem to fail (EBADF),
    // which the function reports as `false` — proving the arm runs and the
    // syscall is attempted for v6.
    let fds = DnatTableFds { v4: None, v6: Some(-1) };
    let ok = publish_dnat_table_entry(&fds, &dnat_v6_key(), dnat_snat_decision_v6());
    assert!(
        !ok,
        "v6 SNAT'd flow with a bad v6 fd must attempt the publish and return false (revert => returns true, no syscall)"
    );

    // No v6 fd → nothing to publish, success (the noops contract still holds).
    let no_fd = DnatTableFds { v4: None, v6: None };
    assert!(publish_dnat_table_entry(&no_fd, &dnat_v6_key(), dnat_snat_decision_v6()));

    // v6 SNAT decision present but no v6 fd, with a v4 fd set, must NOT use
    // the v4 fd for a v6 flow (no cross-family publish).
    let v4_only = DnatTableFds { v4: Some(-1), v6: None };
    assert!(publish_dnat_table_entry(&v4_only, &dnat_v6_key(), dnat_snat_decision_v6()));
}

// =====================================================================
// #2345: inbound destination-translation policy is evaluated on the
// POST-translation destination tuple (Junos parity).
//
// For the SAME-FAMILY inbound destination translations that happen BEFORE
// the route/zone lookup — DNAT, static-DNAT, and inbound NPTv6 — the
// security policy must match on the TRANSLATED (real/internal) destination
// address + port, in the zone derived from that translated destination.
// These tests are fail-on-revert: each builds a config where the ORIGINAL
// (public/virtual) destination and the TRANSLATED (internal) destination
// would draw DIFFERENT policy verdicts, so the observed forward/deny
// outcome can only be produced if the match ran on the translated tuple.
// If the policy lookup reverts to the pre-translation tuple/zone these
// tests flip and fail.
//
// NAT64 (#2358): the PRIMARY (ForwardCandidate) path now ALSO matches on
// the POST-translation destination — the EXTRACTED real IPv4 host the
// synthetic NAT64 address decodes to, NOT the synthetic IPv6 dst. NAT64 is
// a cross-family translation (IPv6 source, IPv4 destination), so the
// forwarding path feeds a mixed (V6 src, V4 dst) tuple and
// `policy.rs::try_match_rule` carries a dedicated (V6 src, V4 dst) arm that
// matches the source against the rule's IPv6 source set and the destination
// against the rule's IPv4 destination set. The permit/deny tests below use
// whole-prefix `64:ff9b::/96` destination rules that still PERMIT/DENY the
// flow — but via the extracted IPv4 dst: a v6-only destination set (no v4
// prefix) compiles to IPv4-match-any under the legacy address-set
// convention, so it matches the extracted v4 dst on the match-any path, NOT
// via any synthetic-IPv6 match. The MissingNeighbor cold-path arm is the
// one exception — it does NOT re-classify NAT64, so it retains a synthetic
// IPv6 fallback (see that test's comment below). The test function names
// still say `synthetic_v6`, a pre-#2358 misnomer. See
// `docs/next-features/twice-nat.md`.
// =====================================================================


// #6745: the reverse-NAT steering row is SHARED and the close was not.
//
// `dnat_v4_key_bytes` builds the key from (protocol, SNAT source address, SNAT
// source port) and nothing else — no remote endpoint. Under address-only SNAT
// (`port no-translation`) and plain static SNAT, two flows from one internal
// source to DIFFERENT remotes therefore land on ONE row, and the allocator
// admits both deliberately: `AddressOnlyReverseKey` enforces uniqueness on a
// key that DOES include dst_ip/dst_port. A per-session close then deleted that
// row unconditionally.

/// The two colliding sessions: one internal source, one SNAT identity, two
/// different remotes. This is the shape the allocator admits on purpose.
fn colliding_pair_6745() -> (crate::session::SessionKey, crate::session::SessionKey) {
    let a = dnat_v4_key();
    let mut b = a.clone();
    b.dst_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 25));
    (a, b)
}

#[test]
fn colliding_sessions_share_one_steering_key_6745() {
    // The premise. If this ever stops holding — because the key gained the
    // remote endpoint — the holder set is no longer load-bearing and the
    // tests below are measuring nothing, so it is asserted rather than
    // assumed.
    let (a, b) = colliding_pair_6745();
    assert_ne!(a.dst_ip, b.dst_ip, "the fixtures must differ in the remote");
    assert_eq!(
        dnat_steering_key(&a, dnat_snat_decision()),
        dnat_steering_key(&b, dnat_snat_decision()),
        "two flows differing only in the remote must share one steering key -- \
         that sharing is what #6745 is about"
    );
    // And the VALUES are identical too, which is why a read-before-delete
    // value comparison cannot separate them: the value encodes the ORIGINAL
    // source, and these two flows share it.
    assert_eq!(a.src_ip, b.src_ip);
    assert_eq!(a.src_port, b.src_port);
}

#[test]
fn a_shared_steering_row_survives_the_first_close_6745() {
    // OBSERVED THROUGH delete_dnat_table_entry, not through the accounting
    // helper it calls. An earlier revision asserted on
    // release_dnat_steering_holder directly and stayed GREEN under the
    // mutation that matters — restoring the UNCONDITIONAL delete, i.e. calling
    // the helper and ignoring its answer. A refcount nothing consults is not a
    // refcount, so the map delete itself is what this watches, via the
    // test-only DNAT_DELETE_ATTEMPTS counter that the family arms bump only
    // once the gate has let them through. The fd is -1: the syscall returns
    // EBADF, which is benign — the contract under test is whether the keyed
    // delete is ATTEMPTED.
    use crate::afxdp::checksum::DNAT_DELETE_ATTEMPTS;
    // #6872: this file had THREE readers of the process-global counter,
    // TWO function-local `static GUARD`s that serialized nothing, and no
    // shared guard. The issue named one unguarded reader and neither local
    // guard here — an enumeration is a floor, not a census.
    let _g = crate::afxdp::checksum::dnat_counter_guard();
    use std::sync::atomic::Ordering;


    reset_dnat_steering_holders();
    let (a, b) = colliding_pair_6745();
    let nat = dnat_snat_decision();
    let fds = DnatTableFds {
        v4: Some(-1),
        v6: None,
    };

    publish_dnat_table_entry(&fds, &a, nat);
    publish_dnat_table_entry(&fds, &b, nat);
    assert_eq!(dnat_steering_holder_count(&a, nat), 2, "both sessions must hold the row");

    // A closes. The row is still B's only steering path, so NO map delete.
    let before = DNAT_DELETE_ATTEMPTS.load(Ordering::Relaxed);
    delete_dnat_table_entry(&fds, &a, nat);
    assert_eq!(
        DNAT_DELETE_ATTEMPTS.load(Ordering::Relaxed),
        before,
        "closing the FIRST of two sessions sharing a steering row issued the map delete -- \
         that blackholes the survivor's return traffic until it republishes (#6745)"
    );
    assert_eq!(dnat_steering_holder_count(&a, nat), 1);

    // B closes. Now it is nobody's, and leaving it would leak a map row.
    delete_dnat_table_entry(&fds, &b, nat);
    assert_eq!(
        DNAT_DELETE_ATTEMPTS.load(Ordering::Relaxed),
        before + 1,
        "closing the LAST holder must issue the map delete -- otherwise the fix trades a \
         blackhole for an unbounded map leak"
    );
    assert_eq!(dnat_steering_holder_count(&b, nat), 0);
}

#[test]
fn republishing_one_session_does_not_add_a_second_hold_6745() {
    // Re-sync, reconcile replay and a second worker seeing the same flow all
    // re-publish. If each added a hold, the row would outlive its last real
    // user by however many times it was republished -- a leak that only shows
    // up under map pressure.
    reset_dnat_steering_holders();
    let key = dnat_v4_key();
    let nat = dnat_snat_decision();
    let fds = DnatTableFds::default();

    publish_dnat_table_entry(&fds, &key, nat);
    publish_dnat_table_entry(&fds, &key, nat);
    publish_dnat_table_entry(&fds, &key, nat);
    assert_eq!(dnat_steering_holder_count(&key, nat), 1, "holds must be per SESSION, not per publish");

    assert!(release_dnat_steering_holder(&key, nat), "one close must release a singly-held row");
}

#[test]
fn an_unaccounted_row_is_still_deleted_6745() {
    // The failure direction of an accounting gap. A row published by a path
    // that did not account -- or by an older build across a helper restart --
    // must delete exactly as it did before #6745, never leak. "Unchanged" is
    // the right answer here; "the map fills up" is not.
    use crate::afxdp::checksum::DNAT_DELETE_ATTEMPTS;
    // #6872: this file had THREE readers of the process-global counter,
    // TWO function-local `static GUARD`s that serialized nothing, and no
    // shared guard. The issue named one unguarded reader and neither local
    // guard here — an enumeration is a floor, not a census.
    let _g = crate::afxdp::checksum::dnat_counter_guard();
    use std::sync::atomic::Ordering;

    reset_dnat_steering_holders();
    let key = dnat_v4_key();
    let fds = DnatTableFds {
        v4: Some(-1),
        v6: None,
    };
    let before = DNAT_DELETE_ATTEMPTS.load(Ordering::Relaxed);
    delete_dnat_table_entry(&fds, &key, dnat_snat_decision());
    assert_eq!(
        DNAT_DELETE_ATTEMPTS.load(Ordering::Relaxed),
        before + 1,
        "a row with no recorded holder must still be deleted -- the failure direction of an \
         accounting gap has to be `unchanged`, never `the map fills up`"
    );
}

#[test]
fn the_v6_steering_row_is_held_independently_6745() {
    // The v6 key is a different width and a different map. A holder set that
    // collapsed the two families would let a v4 close release a v6 row.
    reset_dnat_steering_holders();
    let v4 = dnat_v4_key();
    let v6 = dnat_v6_key();
    let fds = DnatTableFds::default();

    publish_dnat_table_entry(&fds, &v4, dnat_snat_decision());
    publish_dnat_table_entry(&fds, &v6, dnat_snat_decision_v6());
    assert_eq!(dnat_steering_holder_count(&v4, dnat_snat_decision()), 1);
    assert_eq!(dnat_steering_holder_count(&v6, dnat_snat_decision_v6()), 1);

    assert!(release_dnat_steering_holder(&v4, dnat_snat_decision()));
    assert_eq!(
        dnat_steering_holder_count(&v6, dnat_snat_decision_v6()),
        1,
        "releasing the v4 row must not touch the v6 row"
    );
}

#[test]
fn every_publisher_accounts_because_the_callee_does_6745() {
    // THE ASYMMETRY IS 3 PUBLISH SITES AND 2 DELETE SITES:
    //   publish - poll_descriptor/mod.rs (x2, both worker poll paths) and
    //             ha/session_import.rs (the synced install).
    //   delete  - session_delta.rs (the Close arm) and ha/session_import.rs
    //             (delete_synced_session_gen's teardown).
    //
    // A design that accounted at each CALL SITE would need five correct edits
    // and would regress silently if one were missed -- and a test exercising
    // one site would pass while another leaked or blackholed. The accounting
    // lives in publish_dnat_table_entry / delete_dnat_table_entry instead, so
    // every site inherits it by construction and there is no per-site variant
    // to get wrong. This test pins that the FUNCTIONS account, which is the
    // property the call sites rely on.
    reset_dnat_steering_holders();
    let key = dnat_v4_key();
    let nat = dnat_snat_decision();
    assert_eq!(dnat_steering_holder_count(&key, nat), 0);
    publish_dnat_table_entry(&DnatTableFds::default(), &key, nat);
    assert_eq!(
        dnat_steering_holder_count(&key, nat),
        1,
        "publish_dnat_table_entry must record the hold itself -- if it does not, each of the \
         three publish sites has to, and one of them will eventually not"
    );
}

#[test]
fn a_non_snat_session_holds_nothing_6745() {
    // No source rewrite means no row was ever published, so nothing may be
    // recorded and a close must stay the no-op it already was.
    reset_dnat_steering_holders();
    let key = dnat_v4_key();
    let no_nat = NatDecision::default();
    publish_dnat_table_entry(&DnatTableFds::default(), &key, no_nat);
    assert_eq!(dnat_steering_holder_count(&key, no_nat), 0);
    assert!(release_dnat_steering_holder(&key, no_nat));
}
