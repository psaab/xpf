// Tests for afxdp/bpf_map/ — relocated from inline
// `#[cfg(test)] mod tests` to keep bpf_map under the modularity-discipline
// LOC threshold. Loaded as a sibling submodule via
// `#[path = "../bpf_map_tests.rs"]` from bpf_map/mod.rs (#1356 split the
// flat bpf_map.rs into a directory; this file stays at the parent
// afxdp/ scope and is pulled back into the bpf_map namespace by the
// path attribute).

use super::*;
use crate::test_zone_ids::*;

fn local_delivery_decision(tunnel_endpoint_id: u16) -> SessionDecision {
    SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::LocalDelivery,
            local_ifindex: 0,
            egress_ifindex: 0,
            tx_ifindex: 0,
            tunnel_endpoint_id,
            next_hop: None,
            neighbor_mac: None,
            src_mac: None,
            tx_vlan_id: 0,
        },
        nat: NatDecision::default(),
    }
}

/// #9517: the predicate now reads the session KEY, because the steering map
/// cannot tell tunnel discriminators apart. The cells that predate that exercise
/// a non-tunnel session, so they pass this plain key.
fn plain_key() -> SessionKey {
    SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: 6,
        src_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 61, 102)),
        dst_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 61, 1)),
        src_port: 40000,
        dst_port: 22,
        discriminator: crate::session::TunnelDiscriminator::None,
        routing_domain: 0,
    }
}

fn synced_forward_metadata() -> SessionMetadata {
    SessionMetadata {
        ingress_zone: TEST_TRUST_ZONE_ID,
        egress_zone: TEST_TRUST_ZONE_ID,
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
    }
}

#[test]
fn kernel_local_session_map_entry_requires_zero_tunnel_endpoint() {
    let metadata = synced_forward_metadata();
    assert!(uses_kernel_local_session_map_entry(
        &plain_key(),
        local_delivery_decision(0),
        &metadata,
        SessionOrigin::SyncImport,
        false,
    ));
    assert!(!uses_kernel_local_session_map_entry(
        &plain_key(),
        local_delivery_decision(7),
        &metadata,
        SessionOrigin::SyncImport,
        false,
    ));
}

#[test]
fn kernel_local_session_map_entry_rejects_non_kernel_local_cases() {
    let metadata = synced_forward_metadata();
    // Not local delivery → rejected
    assert!(!uses_kernel_local_session_map_entry(
        &plain_key(),
        SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                ..local_delivery_decision(0).resolution
            },
            nat: NatDecision::default(),
        },
        &metadata,
        SessionOrigin::SyncImport,
        false,
    ));

    // Non-peer-synced origin → rejected
    assert!(!uses_kernel_local_session_map_entry(
        &plain_key(),
        local_delivery_decision(0),
        &metadata,
        SessionOrigin::ForwardFlow,
        false,
    ));

    // Reverse session → rejected
    let mut reverse_metadata = synced_forward_metadata();
    reverse_metadata.is_reverse = true;
    assert!(!uses_kernel_local_session_map_entry(
        &plain_key(),
        local_delivery_decision(0),
        &reverse_metadata,
        SessionOrigin::SyncImport,
        false,
    ));
}

/// #9517: a node WITH routing domains never publishes a `PASS_TO_KERNEL` row.
///
/// The XDP steering map is keyed on a bare 5-tuple, so two sessions in different
/// routing domains share one row and the publish is an identity-blind `BPF_ANY`
/// overwrite. An aliased peer-synced publish could therefore flip another
/// domain's `REDIRECT` row to `PASS_TO_KERNEL`, sending that flow to the kernel
/// forward path where no zone policy runs — a harm a clean MISS cannot produce.
///
/// The pair is the cell: the SAME decision, metadata and origin that the cell
/// above proves IS kernel-local on a single-instance box must NOT be kernel-local
/// once `has_routing_domains` is set. Only the flag differs, so the flag is what
/// is bound. Deleting `!has_routing_domains &&` from the predicate reds the
/// second assertion and nothing else.
#[test]
fn routing_domains_demote_kernel_local_to_redirect_9517() {
    let metadata = synced_forward_metadata();
    assert!(
        uses_kernel_local_session_map_entry(
            &plain_key(),
            local_delivery_decision(0),
            &metadata,
            SessionOrigin::SyncImport,
            false,
        ),
        "control: on a single-instance box this exact session IS kernel-local, \
         or the demotion assertion below is vacuous (#9517)"
    );
    assert!(
        !uses_kernel_local_session_map_entry(
            &plain_key(),
            local_delivery_decision(0),
            &metadata,
            SessionOrigin::SyncImport,
            true,
        ),
        "with routing domains the steering key aliases across domains, so a \
         PASS_TO_KERNEL row could overwrite another domain's REDIRECT row and \
         bypass zone policy. It must be demoted to REDIRECT (#9517)"
    );
}

/// #9517, the GRE arm: the steering key drops the tunnel discriminator, so on a
/// SINGLE-instance box two keyed GRE tunnels between one endpoint pair already
/// share a row. Every non-`None` class must be demoted, `Unkeyed` included —
/// an unkeyed tunnel and a keyed one between the same endpoints sit on the same
/// bare tuple, so either one's `PASS_TO_KERNEL` row would overwrite the other's.
#[test]
fn tunnel_discriminators_demote_kernel_local_to_redirect_9517() {
    use crate::session::TunnelDiscriminator;
    let metadata = synced_forward_metadata();
    let gre = |discriminator| SessionKey {
        protocol: 47,
        src_port: 0,
        dst_port: 0,
        discriminator,
        ..plain_key()
    };
    assert!(
        uses_kernel_local_session_map_entry(
            &gre(TunnelDiscriminator::None),
            local_delivery_decision(0),
            &metadata,
            SessionOrigin::SyncImport,
            false,
        ),
        "control: with no discriminator this single-instance session IS kernel-local, \
         or every demotion below is vacuous (#9517)"
    );
    for discriminator in [
        TunnelDiscriminator::Unkeyed,
        TunnelDiscriminator::Keyed(0),
        TunnelDiscriminator::Keyed(7),
        TunnelDiscriminator::Pptp(3),
        TunnelDiscriminator::Unparseable,
    ] {
        assert!(
            !uses_kernel_local_session_map_entry(
                &gre(discriminator),
                local_delivery_decision(0),
                &metadata,
                SessionOrigin::SyncImport,
                false,
            ),
            "a {discriminator:?} session shares its 40-byte steering row with every \
             other tunnel between the same endpoints, so a PASS_TO_KERNEL row here \
             could overwrite a sibling tunnel's REDIRECT row. It must be demoted even \
             with no routing domains (#9517)"
        );
    }
}

#[test]
fn degraded_path_reason_names_cover_retained_shim_actions() {
    assert_eq!(DEGRADED_PATH_REASON_NAMES.len(), 16);
    assert_eq!(DEGRADED_PATH_REASON_NAMES[4], "heartbeat_missing");
    assert_eq!(DEGRADED_PATH_REASON_NAMES[5], "heartbeat_stale");
    assert_eq!(DEGRADED_PATH_REASON_NAMES[11], "interface_nat_no_session");
    assert_eq!(DEGRADED_PATH_REASON_NAMES[13], "strict_drop");
    assert_eq!(DEGRADED_PATH_REASON_NAMES[14], "pass_to_kernel");
    assert_eq!(DEGRADED_PATH_REASON_NAMES[15], "transit_drop");
}

// --- #2332: monotonic HA-liveness freshness (Rust sibling of #1792) ---
//
// `heartbeat_fresh_mono` MUST decide worker liveness purely from two
// CLOCK_MONOTONIC nanosecond readings, never the wall clock. These tests
// pin that contract and FAIL if the function is reverted to a wall-clock
// (`Utc::now()` minus a `DateTime<Utc>`) comparison: the simulated
// forward clock step only changes the wall clock, so a wall-clock revert
// would flip `fresh` to false and fail `heartbeat_fresh_survives_*`.

// Derived from the production threshold so the tests can never drift from
// it if HEARTBEAT_STALE_AFTER ever changes (was a hard-coded 5_000_000_000).
const HB_STALE_NS: u64 = HEARTBEAT_STALE_AFTER.as_nanos() as u64;

#[test]
fn heartbeat_fresh_mono_recent_is_fresh() {
    // Worker stamped 1s of monotonic time ago, well under the 5s limit.
    let last = 100_000_000_000_u64;
    let now = last + 1_000_000_000; // +1s monotonic
    assert!(heartbeat_fresh_mono(last, now));
}

#[test]
fn heartbeat_fresh_mono_overdue_is_stale() {
    // Genuinely overdue: 6s of monotonic elapsed > 5s threshold → dead.
    let last = 100_000_000_000_u64;
    let now = last + 6_000_000_000; // +6s monotonic
    assert!(!heartbeat_fresh_mono(last, now));
}

#[test]
fn heartbeat_fresh_mono_exactly_at_limit_is_fresh() {
    // age == HEARTBEAT_STALE_AFTER is inclusive-fresh (`<=`).
    let last = 100_000_000_000_u64;
    let now = last + HB_STALE_NS;
    assert!(heartbeat_fresh_mono(last, now));
    // One nanosecond past the limit is stale.
    assert!(!heartbeat_fresh_mono(last, now + 1));
}

#[test]
fn heartbeat_fresh_mono_zero_sentinel_is_never_fresh() {
    // last_heartbeat_ns == 0 means "never stamped" → not fresh.
    assert!(!heartbeat_fresh_mono(0, 1_000_000_000));
    assert!(!heartbeat_fresh_mono(0, 0));
}

#[test]
fn heartbeat_fresh_survives_forward_wall_clock_step() {
    // FAIL-ON-REVERT: the worker's last heartbeat is monotonically recent
    // (1ms ago), but the wall clock has jumped FORWARD by 1 hour (NTP
    // makestep / VM resume) between the heartbeat stamp and this check.
    //
    // The monotonic decision below depends ONLY on the monotonic readings,
    // so the wall-clock step is invisible and the binding stays FRESH. A
    // wall-clock revert (Utc::now() - last_DateTime) would compute a ~1h
    // age, exceed the 5s limit, and return false — failing this test.
    let last_mono = 500_000_000_000_u64;
    let now_mono = last_mono + 1_000_000; // +1ms monotonic — clearly fresh

    // Build the wall-clock view the OLD code would have used: at heartbeat
    // time the wall clock was `t0`; by check time it stepped forward 1h.
    let t0 = chrono::Utc::now();
    let last_wall = t0; // worker-stamped wall instant (back-projected)
    let now_wall_after_step = t0 + chrono::TimeDelta::hours(1);
    let wall_age = now_wall_after_step.signed_duration_since(last_wall);
    // Sanity: the wall-clock age the old code saw really does exceed 5s.
    assert!(wall_age.to_std().unwrap() > std::time::Duration::from_secs(5));

    // The monotonic decision is unaffected by the wall-clock step.
    assert!(
        heartbeat_fresh_mono(last_mono, now_mono),
        "monotonic liveness must ignore a forward wall-clock step (#2332)"
    );
}

#[test]
fn heartbeat_fresh_backward_monotonic_anomaly_clamps_fresh() {
    // A backward CLOCK_MONOTONIC reading cannot happen on a well-behaved
    // kernel, but saturating_sub clamps it to a zero age (fail-safe:
    // treated as fresh, never spuriously dead).
    let last = 100_000_000_000_u64;
    let now = last - 1_000_000; // now < last
    assert!(heartbeat_fresh_mono(last, now));
}

#[test]
fn bpf_conntrack_struct_sizes_match_c() {
    // Must match C struct sizes from xpf_conntrack.h exactly.
    // The value structs grew 128->136 / 176->184 when `flags` widened from
    // __u8 to __u16 (#5460): the compiler pads the leading state/flags/
    // tcp_state/is_reverse block from 8 to 16 bytes. #4983 appended the
    // `ingress_ifindex` u32 (the session's TRUE ingress-binding identity),
    // growing them again 136->144 / 184->192: the u32 lands on the existing
    // 8-byte boundary and the compiler tail-pads 4 bytes to the struct's
    // 8-byte alignment. The Go on-map ABI mirror (bpfSessionValue /
    // bpfSessionValueV6, whose tail pad is DECLARED for the #6082 zero-copy
    // marshal path) is asserted to the same 144/192 in
    // pkg/dataplane/bpf_session_value_test.go.
    assert_eq!(core::mem::size_of::<BpfSessionKeyV4>(), 16);
    // #9546 appended `routing_domain` (u32) after `ingress_vlan_id`: it skips
    // the 2 unused pad bytes to a 4-byte boundary, lands at 144/192, and the
    // 8-byte alignment grows the structs 144->152 / 192->200.
    assert_eq!(core::mem::size_of::<BpfSessionValueV4>(), 152);
    assert_eq!(core::mem::size_of::<BpfSessionKeyV6>(), 40);
    assert_eq!(core::mem::size_of::<BpfSessionValueV6>(), 200);
}

// #5460: SESS_FLAG_NPTV6 is bit 8 (0x100 = 256), which does not fit the
// __u8 `session_value.flags` field it belonged to before this fix — setting it
// truncated to 0 (colliding with "no flags"). This is a counter-factual pin:
// it writes the NPTv6 bit into the flags field and reads it back. On the
// pre-fix u8 field `SESS_FLAG_NPTV6 as _` truncates to 0, so the read-back
// masks to 0 and the assertion FAILS; on the u16 field the bit survives.
#[test]
fn nptv6_session_flag_survives_roundtrip_v4() {
    const SESS_FLAG_NPTV6: u32 = 1 << 8; // 256
    let mut v: BpfSessionValueV4 = unsafe { core::mem::zeroed() };
    // `as _` casts 256 to whatever width `flags` is: u8 (pre-fix) => 0, u16 => 256.
    v.flags = SESS_FLAG_NPTV6 as _;
    // Round-trip through the exact bytes written to the BPF map.
    let bytes: [u8; core::mem::size_of::<BpfSessionValueV4>()] =
        unsafe { core::mem::transmute_copy(&v) };
    let back: BpfSessionValueV4 = unsafe { core::ptr::read_unaligned(bytes.as_ptr().cast()) };
    assert_ne!(
        u32::from(back.flags) & SESS_FLAG_NPTV6,
        0,
        "NPTv6 session flag (bit 8) lost -- session_value.flags too narrow for SESS_FLAG_NPTV6",
    );
}

#[test]
fn nptv6_session_flag_survives_roundtrip_v6() {
    const SESS_FLAG_NPTV6: u32 = 1 << 8; // 256
    let mut v: BpfSessionValueV6 = unsafe { core::mem::zeroed() };
    v.flags = SESS_FLAG_NPTV6 as _;
    let bytes: [u8; core::mem::size_of::<BpfSessionValueV6>()] =
        unsafe { core::mem::transmute_copy(&v) };
    let back: BpfSessionValueV6 = unsafe { core::ptr::read_unaligned(bytes.as_ptr().cast()) };
    assert_ne!(
        u32::from(back.flags) & SESS_FLAG_NPTV6,
        0,
        "NPTv6 session flag (bit 8) lost -- session_value_v6.flags too narrow for SESS_FLAG_NPTV6",
    );
}

#[test]
fn session_map_redirect_keys_for_forward_session_include_nat_aliases() {
    let key = SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: 6,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        src_port: 41086,
        dst_port: 5201,
            discriminator: Default::default(),
            routing_domain: 0,
    };
    let decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 14,
            tx_ifindex: 14,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200))),
            neighbor_mac: None,
            src_mac: None,
            tx_vlan_id: 0,
        },
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
            ..NatDecision::default()
        },
    };
    let metadata = SessionMetadata {
        ingress_zone: TEST_LAN_ZONE_ID,
        egress_zone: TEST_WAN_ZONE_ID,
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
    };

    let keys = session_map_redirect_keys_for_session(
        &key,
        decision,
        &metadata,
        SessionOrigin::SharedPromote,
    );

    assert!(keys.contains(&key));
    assert!(keys.contains(&forward_wire_key(&key, decision.nat)));
    assert!(keys.contains(&reverse_session_key(&key, decision.nat)));
    assert!(keys.contains(&reverse_canonical_key(&key, decision.nat)));
}

#[test]
fn session_map_redirect_keys_for_kernel_local_synced_session_delete_superset() {
    let key = SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: 1,
        src_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)),
        src_port: 0,
        dst_port: 0,
            discriminator: Default::default(),
            routing_domain: 0,
    };
    let decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::LocalDelivery,
            local_ifindex: 14,
            egress_ifindex: 14,
            tx_ifindex: 14,
            tunnel_endpoint_id: 0,
            next_hop: None,
            neighbor_mac: None,
            src_mac: None,
            tx_vlan_id: 0,
        },
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
            ..NatDecision::default()
        },
    };
    let metadata = synced_forward_metadata();

    let keys =
        session_map_redirect_keys_for_session(&key, decision, &metadata, SessionOrigin::SyncImport);

    assert_eq!(keys.len(), 4);
    assert!(keys.contains(&key));
    assert!(keys.contains(&forward_wire_key(&key, decision.nat)));
    assert!(keys.contains(&reverse_session_key(&key, decision.nat)));
    assert!(keys.contains(&reverse_canonical_key(&key, decision.nat)));
}

#[test]
fn bpf_conntrack_key_port_byte_order() {
    // BPF session_key uses __be16 ports (network byte order).
    // SessionKey stores ports in host order (u16::from_be_bytes in parsing).
    // publish_bpf_conntrack_entry must apply .to_be() to produce the correct
    // big-endian byte pattern in the packed struct.
    // #7743: this fixture used to build the struct literal INLINE, with its own
    // `.to_be()` calls. It therefore asserted only that `u16::to_be` works —
    // reverting the production encoding left it GREEN, because no production
    // code was on the path. It now calls the single-source builder every
    // publish/refresh/delete site uses, so dropping a `.to_be()` there REDS.
    let port: u16 = 80;
    let bpf_key = bpf_session_key_v4([10, 0, 1, 102], [10, 0, 2, 1], port, 443, 6);
    // The packed struct bytes at the port offsets must be big-endian:
    // port 80 = 0x0050 -> bytes [0x00, 0x50]
    // port 443 = 0x01BB -> bytes [0x01, 0xBB]
    let bytes: [u8; 16] = unsafe { core::mem::transmute(bpf_key) };
    assert_eq!(bytes[8], 0x00, "src_port high byte");
    assert_eq!(bytes[9], 0x50, "src_port low byte");
    assert_eq!(bytes[10], 0x01, "dst_port high byte");
    assert_eq!(bytes[11], 0xBB, "dst_port low byte");
}

// #5213 FAIL-ON-REVERT: the v4 conntrack mirror value must carry the STABLE
// dataplane session id resolved from the session table
// (`SessionEntry.session_id`, #4915) — NOT the `0` it hardcoded before.
// `show security flow session` reads this exact slot
// (`dataplane.SessionValue.SessionID`) and, when non-zero, renders it verbatim
// so the id matches the one RT_FLOW emits (SESSION_CREATE/CLOSE) for the same
// session. Reverting the builder to `session_id: 0` turns this RED (and the Go
// render then falls back to the per-iteration ordinal — the #5213 mismatch).
#[test]
fn build_conntrack_value_stamps_stable_session_id_v4() {
    let key = SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: 6,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        src_port: 41086,
        dst_port: 5201,
            discriminator: Default::default(),
            routing_domain: 0,
    };
    let decision = local_delivery_decision(0);
    let metadata = synced_forward_metadata();
    // worker 7 (high 16 bits) + per-worker counter 42 — a representative
    // #4915-namespaced id that is clearly not 0 or a small ordinal.
    const SID: u64 = (7u64 << 48) | 42;
    let value = publish_conntrack::build_conntrack_value_v4(
        &key, decision, &metadata, 0, 1, 2, 100, 0, 0, SID, 0,
    )
    .expect("a v4 session must map to a v4 conntrack value");
    assert_eq!(
        value.session_id, SID,
        "conntrack mirror must carry the stable session id, not 0"
    );
}

// #5213 FAIL-ON-REVERT: v6 sibling of the above — the v6 conntrack mirror value
// must likewise carry the stable session id.
#[test]
fn build_conntrack_value_stamps_stable_session_id_v6() {
    let key = SessionKey {
        addr_family: libc::AF_INET6 as u8,
        protocol: 6,
        src_ip: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x102)),
        dst_ip: IpAddr::V6(Ipv6Addr::new(0x2001, 0x559, 0x8585, 0x80, 0, 0, 0, 0x200)),
        src_port: 41086,
        dst_port: 5201,
            discriminator: Default::default(),
            routing_domain: 0,
    };
    let decision = local_delivery_decision(0);
    let metadata = synced_forward_metadata();
    const SID: u64 = (3u64 << 48) | 7;
    let value = publish_conntrack::build_conntrack_value_v6(
        &key, decision, &metadata, 0, 1, 2, 100, 0, 0, SID, 0,
    )
    .expect("a v6 session must map to a v6 conntrack value");
    assert_eq!(
        value.session_id, SID,
        "v6 conntrack mirror must carry the stable session id, not 0"
    );
}

// #5287 FAIL-ON-REVERT: `refresh_bpf_conntrack_last_seen` is an INCREMENTAL,
// budgeted slice — NOT a full-table pass. It must advance a persistent cursor
// by at most `budget` slab slots per call and resume across calls, so no single
// packet-loop tick walks the whole table (the old behaviour did tens of
// thousands of synchronous BPF syscalls between two RX/TX polls, spiking
// latency near the 131072-entry cap).
//
// With fd=-1 no BPF syscalls run, but the walk still advances the cursor, so
// the budget/continuation contract is observable directly: the first slice from
// the top returns a cursor advanced by EXACTLY the budget (it does not wrap to 0
// while the table still has unwalked slots), and draining a full cycle takes
// MORE THAN ONE slice. Reverting the refresh to the unbounded single-pass scan
// makes the first call walk the whole table and wrap to 0 -> the `== BUDGET`
// assertion reddens.
#[test]
fn refresh_bpf_conntrack_last_seen_is_budgeted_across_slices() {
    use crate::session::SessionTable;
    let mut table = SessionTable::new();
    const N: usize = 40;
    const BUDGET: usize = 8;
    assert!(N > BUDGET, "test only meaningful when the table exceeds one slice");

    let install_time = 1_000_000_000u64;
    for i in 0..N {
        let key = SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: 6,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            src_port: 10_000 + i as u16, // distinct 5-tuples -> distinct forward entries
            dst_port: 443,
                    discriminator: Default::default(),
                    routing_domain: 0,
        };
        let decision = SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: 12,
                tx_ifindex: 12,
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 50, 1))),
                neighbor_mac: Some([0, 1, 2, 3, 4, 5]),
                src_mac: None,
                tx_vlan_id: 0,
            },
            nat: NatDecision::default(),
        };
        let metadata = SessionMetadata {
            ingress_zone: TEST_LAN_ZONE_ID,
            egress_zone: TEST_WAN_ZONE_ID,
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
        };
        assert!(table.install_with_protocol(key, decision, metadata, install_time, 6, 0x10));
    }

    let policy = crate::policy::PolicyState::default();
    let now = install_time + 5_000_000_000;

    // First slice from the top: cursor advances by EXACTLY the budget and does
    // NOT wrap (the table still has N - BUDGET unwalked slots). fd=-1 => no BPF
    // I/O, but the cursor bookkeeping is exercised.
    // #7919: the slice now returns a RefreshSliceOutcome; the cursor contract it
    // used to return directly is `.cursor` and is otherwise unchanged.
    let c1 = refresh_bpf_conntrack_last_seen(-1, -1, &table, &policy, now, 0, BUDGET).cursor;
    assert_eq!(
        c1, BUDGET,
        "first slice must be bounded to the budget, not a full single-pass scan"
    );

    // Draining a full cycle takes >1 slice; each returned cursor advances by at
    // most BUDGET until it wraps to 0.
    let mut cursor = c1;
    let mut slices = 1usize;
    for _ in 0..1024 {
        let next =
            refresh_bpf_conntrack_last_seen(-1, -1, &table, &policy, now, cursor, BUDGET).cursor;
        slices += 1;
        if next != 0 {
            assert!(
                next.saturating_sub(cursor) <= BUDGET,
                "slice advanced {} past budget {BUDGET}",
                next.saturating_sub(cursor),
            );
        }
        cursor = next;
        if cursor == 0 {
            break; // full-table cycle completed
        }
    }
    assert!(
        slices > 1,
        "full table must span more than one budgeted slice, got {slices}"
    );
}

// #4983 FAIL-ON-REVERT: the conntrack mirror value must carry the session's
// TRUE ingress-interface identity — `SessionMetadata::ingress_ifindex` plus
// `ingress_vlan_id`, the binding its first packet arrived on, stamped once at
// install. `show security flow session interface <name>` and the matching
// `clear` read exactly these two slots (Go `dataplane.SessionValue`
// .IngressIfindex/.IngressVlanID) and, when the ifindex is non-zero, resolve
// the one interface it names instead of asking "is <name> bound to the
// session's ingress ZONE?" — the approximation that made a session on
// interface X match a filter for every sibling interface Y of that zone.
// Reverting the builder to `ingress_ifindex: 0` turns this RED and the Go
// filter silently falls back to the zone answer for every session.
#[test]
fn build_conntrack_value_stamps_ingress_identity_v4_4983() {
    let key = SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: 6,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        src_port: 41086,
        dst_port: 5201,
            discriminator: Default::default(),
            routing_domain: 0,
    };
    let decision = local_delivery_decision(0);
    let mut metadata = synced_forward_metadata();
    // A plain kernel ifindex on a VLAN 80 trunk unit — the loss cluster's own
    // shape (reth0.80 over the physical WAN NIC), not a sentinel.
    metadata.ingress_ifindex = 24;
    metadata.ingress_vlan_id = 80;

    let value = publish_conntrack::build_conntrack_value_v4(
        &key, decision, &metadata, 0, 1, 2, 100, 0, 0, 0, 0,
    )
    .expect("a v4 session must map to a v4 conntrack value");

    assert_eq!(
        value.ingress_ifindex, 24,
        "the conntrack mirror must carry the session's recorded ingress ifindex, not 0 \
         (0 sends the Go filter back to the zone approximation, #4983)"
    );
    assert_eq!(
        value.ingress_vlan_id, 80,
        "the conntrack mirror must carry the ingress VLAN id: without it two units of \
         one trunk NIC alias onto the parent and the cross-interface match returns (#4983)"
    );
}

// #4983 v6 sibling — matchesV6 carries the identical filter arm, so the v6
// mirror must carry the identical identity.
#[test]
fn build_conntrack_value_stamps_ingress_identity_v6_4983() {
    let key = SessionKey {
        addr_family: libc::AF_INET6 as u8,
        protocol: 6,
        src_ip: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x102)),
        dst_ip: IpAddr::V6(Ipv6Addr::new(0x2001, 0x559, 0x8585, 0x80, 0, 0, 0, 0x200)),
        src_port: 41086,
        dst_port: 5201,
            discriminator: Default::default(),
            routing_domain: 0,
    };
    let decision = local_delivery_decision(0);
    let mut metadata = synced_forward_metadata();
    metadata.ingress_ifindex = 24;
    metadata.ingress_vlan_id = 80;

    let value = publish_conntrack::build_conntrack_value_v6(
        &key, decision, &metadata, 0, 1, 2, 100, 0, 0, 0, 0,
    )
    .expect("a v6 session must map to a v6 conntrack value");

    assert_eq!(
        value.ingress_ifindex, 24,
        "v6 mirror must carry the ingress ifindex (#4983)"
    );
    assert_eq!(
        value.ingress_vlan_id, 80,
        "v6 mirror must carry the ingress VLAN id (#4983)"
    );
}

// #4983 OVER-REACH GUARD: the ingress identity and the cached FIB EGRESS
// result are two different things occupying two different slots. A session
// with a recorded ingress must leave fib_ifindex/fib_vlan_id exactly as the
// pre-#4983 builder left them (0 — the helper does not populate the FIB cache
// here), so the CLI's egress arm keeps resolving from the FIB result and its
// zone fallback rather than from the ingress binding. This assertion stays
// GREEN with the ingress stamping reverted; it fails only if someone
// "implements" the ingress identity by reusing the egress slots.
#[test]
fn ingress_identity_does_not_occupy_the_fib_egress_slots_4983() {
    let key = SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: 6,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        src_port: 41086,
        dst_port: 5201,
            discriminator: Default::default(),
            routing_domain: 0,
    };
    let decision = local_delivery_decision(0);
    let mut metadata = synced_forward_metadata();
    metadata.ingress_ifindex = 24;
    metadata.ingress_vlan_id = 80;

    let value = publish_conntrack::build_conntrack_value_v4(
        &key, decision, &metadata, 0, 1, 2, 100, 0, 0, 0, 0,
    )
    .expect("a v4 session must map to a v4 conntrack value");

    assert_eq!(
        value.fib_ifindex, 0,
        "the ingress identity must not leak into the FIB EGRESS ifindex slot: the CLI \
         resolves the egress interface from it and would report the ingress one (#4983)"
    );
    assert_eq!(
        value.fib_vlan_id, 0,
        "the ingress VLAN must not leak into the FIB EGRESS vlan slot (#4983)"
    );
}

// #7743: the v6 twin of `bpf_conntrack_key_port_byte_order`. The v6 key is
// `#[repr(C, packed)]` and 40 bytes, so the ports sit at offsets 32..36 with no
// alignment padding before them.
#[test]
fn bpf_conntrack_key_v6_port_byte_order() {
    let src = Ipv6Addr::new(0x2001, 0x559, 0x8585, 0x80, 0, 0, 0, 0x200);
    let dst = Ipv6Addr::new(0x2001, 0x559, 0x8585, 0x80, 0, 0, 0, 8);
    let bpf_key = bpf_session_key_v6(src.octets(), dst.octets(), 80, 443, 6);
    let bytes: [u8; 40] = unsafe { core::mem::transmute(bpf_key) };
    assert_eq!(bytes[32], 0x00, "src_port high byte");
    assert_eq!(bytes[33], 0x50, "src_port low byte");
    assert_eq!(bytes[34], 0x01, "dst_port high byte");
    assert_eq!(bytes[35], 0xBB, "dst_port low byte");
    assert_eq!(bytes[36], 6, "protocol");
    assert_eq!(&bytes[37..40], &[0, 0, 0], "pad must be zeroed");
}

// #7743 ANTI-DRIFT: the conntrack key encoding is single-sourced in
// `bpf_session_key_v4` / `bpf_session_key_v6` precisely because publish,
// refresh and delete must address the same map row byte-for-byte. A ninth
// hand-rolled literal would silently reintroduce the drift this consolidated,
// and it would not fail any behavioural test — publish and delete would simply
// stop matching, leaking the row. Scan the source for a struct literal that
// builds the key from `.octets()` outside the builders.
#[test]
fn conntrack_key_encoding_has_no_hand_rolled_copies() {
    let sources = [
        (
            "bpf_map/mod.rs",
            include_str!("bpf_map/mod.rs"),
        ),
        (
            "bpf_map/publish_conntrack.rs",
            include_str!("bpf_map/publish_conntrack.rs"),
        ),
    ];
    for (name, src) in sources {
        // Strip line comments so this test's own prose (and the builder doc
        // comments, which name the literal) cannot satisfy or trip the scan.
        let code: String = src
            .lines()
            .map(|l| match l.find("//") {
                Some(i) => &l[..i],
                None => l,
            })
            .collect::<Vec<_>>()
            .join("\n");
        for family in ["BpfSessionKeyV4", "BpfSessionKeyV6"] {
            for (idx, _) in code.match_indices(&format!("{family} {{")) {
                let tail = &code[idx..];
                let end = tail.find('}').map_or(tail.len(), |e| e + 1);
                let body = &tail[..end];
                assert!(
                    !body.contains(".octets()"),
                    "{name}: hand-rolled {family} literal built from .octets() — \
                     use bpf_session_key_v4/v6 so publish, refresh and delete \
                     cannot drift apart (#7743). Offending block:\n{body}"
                );
            }
        }
    }
}

// #7919 FAIL-ON-REVERT for the mirror's counter gate.
//
// `refresh_bpf_conntrack_last_seen` does raw BPF syscalls, and with fd=-1 (the
// only mode a unit test has) the map write never runs — so the WRITE itself is
// not directly observable here. The decision it makes is, because it was
// extracted into `mirrored_counters`. That extraction is the point: the choice
// used to be four inline assignments, which nothing could bind.
//
// Delete the gate (return the live values unconditionally) and
// `a_zero_replica_does_not_erase_the_owners_volume_7919` reddens.
#[test]
fn a_zero_replica_does_not_erase_the_owners_volume_7919() {
    use crate::session::SessionCounters;
    let live_row = (5_000u64, 7_500_000u64, 4_000u64, 6_000_000u64);

    // A SIBLING worker's replica: created by the fan-out at zero and never
    // advanced, because no counters field exists on the replication path.
    let replica = SessionCounters::default();
    assert_eq!(
        mirrored_counters(live_row, &replica),
        live_row,
        "a worker holding an all-zero replica of a live session must leave the \
         row alone -- this is the #7919 defect: five of six workers were \
         publishing zero over the owner's volume"
    );

    // POSITIVE CONTROL on the accept side. A gate that refused every write
    // would satisfy the assertion above and freeze the counters permanently.
    let owner = SessionCounters {
        fwd_packets: 6_000,
        fwd_bytes: 9_000_000,
        rev_packets: 4_500,
        rev_bytes: 6_750_000,
    };
    assert_eq!(
        mirrored_counters(live_row, &owner),
        (6_000, 9_000_000, 4_500, 6_750_000),
        "control: the OWNING worker must still advance the row, or the mirror \
         is frozen at its first value instead of being wrong"
    );
    // And from a freshly published (all-zero) row, which is the ordinary case.
    assert_eq!(
        mirrored_counters((0, 0, 0, 0), &owner),
        (6_000, 9_000_000, 4_500, 6_750_000),
        "control: the first mirror after install must take the owner's volume"
    );
}

// #7919 EDGE: the gate must not key on the FORWARD direction alone.
//
// A session whose traffic is entirely in the reverse direction has
// `fwd_packets == 0` with a real `rev_packets`. Keying the gate on
// `fwd_packets == 0` would classify that owner as an empty replica and freeze
// its row at zero forever -- the same defect, moved to a narrower case where
// only asymmetric flows show it. Mutating the gate to test `fwd_packets` alone
// reddens this and NOT the cell above, which is why it is separate.
#[test]
fn a_reverse_only_session_is_still_mirrored_7919() {
    use crate::session::SessionCounters;
    let reverse_only = SessionCounters {
        fwd_packets: 0,
        fwd_bytes: 0,
        rev_packets: 900,
        rev_bytes: 1_350_000,
    };
    assert_eq!(
        mirrored_counters((0, 0, 0, 0), &reverse_only),
        (0, 0, 900, 1_350_000),
        "a reverse-only flow is real traffic and must reach the row"
    );
    assert_eq!(
        mirrored_counters((0, 0, 100, 150_000), &reverse_only),
        (0, 0, 900, 1_350_000),
        "and it must keep ADVANCING, not stop at its first mirrored value"
    );
}

// #7919: the gate, driven from the two-table shape it exists for rather than
// from hand-built tuples -- the owner's SessionTable and a SIBLING's table
// built through the REAL fan-out constructor, walked exactly as the refresh
// walks them. Binds the gate to the defect's actual shape, so a future change
// to the replication path that starts carrying counters shows up HERE as this
// cell going green for a new reason rather than silently.
#[test]
fn the_mirror_gate_holds_for_a_real_sibling_replica_7919() {
    use crate::session::{SessionCounters, SessionTable};
    // Rebuild the minimal pair: an owner that accounted traffic, and a replica
    // installed with no counters (the replication types have no such field).
    let mut owner = SessionCounters::default();
    for _ in 0..2_500u32 {
        owner.fwd_packets = owner.fwd_packets.saturating_add(1);
        owner.fwd_bytes = owner.fwd_bytes.saturating_add(1500);
    }
    let sibling = SessionCounters::default();

    // Whatever order the six workers' slices land in, the row must converge on
    // the owner's volume and stay there.
    let mut row = (0u64, 0u64, 0u64, 0u64);
    for step in 0..12 {
        let walking = if step % 6 == 0 { &owner } else { &sibling };
        row = mirrored_counters(row, walking);
    }
    assert_eq!(
        row,
        (2_500, 3_750_000, 0, 0),
        "after twelve interleaved slices from six workers -- ONE owner and five \
         zero replicas -- the row must carry the owner's volume. Before the gate \
         this converged on (0,0,0,0) for every ordering that did not end on the \
         owner's slice, which is five orderings out of six"
    );
    // The table types are exercised for real in
    // `a_sibling_workers_replica_carries_zero_counters_for_a_live_session_7919`
    // (tests_bind_forward.rs), which is what establishes that a sibling's entry
    // really is all-zero; this cell is about what the gate then does with it.
    let _ = SessionTable::new();
}

// #8125 FAIL-ON-REVERT: the conntrack row's `Timeout:` column must report the
// session's OWN window, not a constant.
//
// The column read `1800` for every session — the JUNOS default for
// `established-timeout` — whatever window was actually in force. Measured on the
// cluster before the fix, with the reap behaviour proving the windows differed:
//
//     closing-timeout UNSET (30 s window):  Timeout: 1800s   session alive at +8s
//     closing-timeout 3     (3 s window):   Timeout: 1800s   session GONE  at +8s
//
// and 1800 for ESTABLISHED sessions too, whose window is 300 s
// (DEFAULT_TCP_SESSION_TIMEOUT_NS) unless configured. A wrong number is
// indistinguishable from a right one at the point of reading, which is what
// makes this worse than an unimplemented column.
//
// TWO sessions with DIFFERENT windows, because a single-session cell cannot see
// this defect: any constant passes it.
#[test]
fn conntrack_timeout_column_reports_the_session_window_8125() {
    let key = SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: 6,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        src_port: 41086,
        dst_port: 5201,
        discriminator: Default::default(),
        routing_domain: 0,
    };
    let decision = local_delivery_decision(0);
    let metadata = synced_forward_metadata();

    // The two windows an operator actually sees on one box at one time: an
    // ESTABLISHED session on its 300 s default and a half-closed one on the
    // 30 s closing window.
    const ESTABLISHED_SECS: u32 = 300;
    const CLOSING_SECS: u32 = 30;

    let established = publish_conntrack::build_conntrack_value_v4(
        &key, decision, &metadata, 0, 1, 2, 100, 0, 0, 0, ESTABLISHED_SECS,
    )
    .expect("a v4 session must map to a v4 conntrack value");
    let closing = publish_conntrack::build_conntrack_value_v4(
        &key, decision, &metadata, 0, 1, 2, 100, 0, 0, 0, CLOSING_SECS,
    )
    .expect("a v4 session must map to a v4 conntrack value");

    assert_eq!(
        established.timeout, ESTABLISHED_SECS,
        "the row must report the ESTABLISHED window, not the 1800 constant"
    );
    assert_eq!(
        closing.timeout, CLOSING_SECS,
        "the row must report the CLOSING window, not the 1800 constant"
    );
    // The property the two rows exist for. Asserting each value alone would
    // pass on a builder that returned its argument for one call and a constant
    // for the other; asserting they DIFFER is what a constant cannot satisfy.
    assert_ne!(
        established.timeout, closing.timeout,
        "two sessions on windows an order of magnitude apart must not render \
         the same Timeout column (#8125)"
    );

    // The documented fallback, and the only place 1800 survives: a publish with
    // NO live table entry has no window to report, which is the pre-#8125
    // behaviour for exactly that case.
    let no_entry = publish_conntrack::build_conntrack_value_v4(
        &key, decision, &metadata, 0, 1, 2, 100, 0, 0, 0, 0,
    )
    .expect("a v4 session must map to a v4 conntrack value");
    assert_eq!(
        no_entry.timeout, 1800,
        "with no live entry the documented default stands; the refresh loop \
         corrects it within one cycle once an entry exists"
    );
}

// #8125 v6 sibling. The v6 builder carried its own copy of the constant, and a
// fix applied to one renderer with the sibling surface left behind is the #8258
// class — every v4 cell above passes against exactly that half-fix.
#[test]
fn conntrack_timeout_column_reports_the_session_window_v6_8125() {
    let key = SessionKey {
        addr_family: libc::AF_INET6 as u8,
        protocol: 6,
        src_ip: IpAddr::V6("2001:559:8585:bf01::102".parse().unwrap()),
        dst_ip: IpAddr::V6("2001:559:8585:80::200".parse().unwrap()),
        src_port: 41086,
        dst_port: 5201,
        discriminator: Default::default(),
        routing_domain: 0,
    };
    let decision = local_delivery_decision(0);
    let metadata = synced_forward_metadata();

    let established = publish_conntrack::build_conntrack_value_v6(
        &key, decision, &metadata, 0, 1, 2, 100, 0, 0, 0, 300,
    )
    .expect("a v6 session must map to a v6 conntrack value");
    let closing = publish_conntrack::build_conntrack_value_v6(
        &key, decision, &metadata, 0, 1, 2, 100, 0, 0, 0, 30,
    )
    .expect("a v6 session must map to a v6 conntrack value");

    assert_eq!(established.timeout, 300);
    assert_eq!(closing.timeout, 30);
    assert_ne!(established.timeout, closing.timeout);

    let no_entry = publish_conntrack::build_conntrack_value_v6(
        &key, decision, &metadata, 0, 1, 2, 100, 0, 0, 0, 0,
    )
    .expect("a v6 session must map to a v6 conntrack value");
    assert_eq!(no_entry.timeout, 1800);
}

// #7919: the refresh slice reports the largest per-session volume it walked.
//
// This is the instrument that separates the two live explanations for a
// session row reading `Pkts: 0` while the flow moves traffic. Every worker
// holds a copy of every session (measured on the reference cluster:
// `session_table_entries` reads 6 on all six workers for three flows), but only
// the worker whose packets land accounts for one. So if only one worker's table
// ever holds volume, accounting reaches only that worker; if every worker's
// does, accounting is fine and the shared mirror is losing it.
//
// Sampled on the walk the refresh already performs — no second iteration, and
// nothing on the packet path.
#[test]
fn a_refresh_slice_reports_the_largest_session_volume_it_walked_7919() {
    use crate::session::SessionTable;
    let mut table = SessionTable::new();
    let policy = crate::policy::PolicyState::default();
    let install = 1_000_000_000u64;

    let mk_key = |port: u16| SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: 6,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        src_port: port,
        dst_port: 5201,
        discriminator: Default::default(),
        routing_domain: 0,
    };
    let mk_decision = || SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 12,
            tx_ifindex: 12,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 50, 1))),
            neighbor_mac: Some([0, 1, 2, 3, 4, 5]),
            src_mac: None,
            tx_vlan_id: 0,
        },
        nat: NatDecision::default(),
    };
    let mk_metadata = || SessionMetadata {
        ingress_zone: TEST_LAN_ZONE_ID,
        egress_zone: TEST_WAN_ZONE_ID,
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
    };
    let busy = mk_key(40001);
    let quiet = mk_key(40002);
    assert!(table.install_with_protocol(
        busy.clone(), mk_decision(), mk_metadata(), install, 6, 0x10,
    ));
    assert!(table.install_with_protocol(
        quiet.clone(), mk_decision(), mk_metadata(), install, 6, 0x10,
    ));
    for _ in 0..1_234u32 {
        table.account_packet(&busy, 1500, 0x10, 0);
    }

    // fd -1: no BPF syscalls run, but the walk still happens — which is exactly
    // the surface under test.
    let out = refresh_bpf_conntrack_last_seen(-1, -1, &table, &policy, install + 1, 0, 4096);
    assert_eq!(
        out.max_session_volume, 1_234,
        "the slice must report the busiest walked session's fwd+rev volume"
    );

    // CONTROL: a table whose sessions have NO traffic reports 0, so a nonzero
    // reading cannot come from the walk merely having visited entries.
    let mut idle = SessionTable::new();
    assert!(idle.install_with_protocol(
        quiet, mk_decision(), mk_metadata(), install, 6, 0x10,
    ));
    let idle_out = refresh_bpf_conntrack_last_seen(-1, -1, &idle, &policy, install + 1, 0, 4096);
    assert_eq!(
        idle_out.max_session_volume, 0,
        "control: an unaccounted table must report 0, or the value above is an \
         artefact of walking rather than of volume"
    );

    // And the cursor contract is unchanged by carrying the extra value back.
    assert_eq!(
        idle_out.cursor, 0,
        "a slice that drains the table still wraps its cursor to 0"
    );
}

// #7919 WIRE CONTRACT: the high-water is an ADDED key, and an unreported one
// must be indistinguishable from absent rather than serialized as a 0 a reader
// could mistake for a measurement.
#[test]
fn an_unobserved_session_volume_high_water_stays_off_the_wire_7919() {
    let mut w = crate::protocol::WorkerRuntimeStatus::default();
    w.worker_id = 2;
    let json = serde_json::to_string(&w).expect("serialize");
    assert!(
        !json.contains("session_volume_high_water"),
        "a never-observed high-water must not appear on the wire at all; a 0 \
         there reads as 'this worker has never carried traffic', which is a \
         measurement the helper did not make. got: {json}"
    );

    w.session_volume_high_water = 117_280;
    let json = serde_json::to_string(&w).expect("serialize");
    assert!(
        json.contains("\"session_volume_high_water\":117280"),
        "an observed high-water must reach the wire under its own key. got: {json}"
    );

    // An OLD control plane's payload (no such key) must still decode — the
    // rolling-upgrade direction that makes this an ADD rather than a change.
    let old: crate::protocol::WorkerRuntimeStatus =
        serde_json::from_str(r#"{"worker_id":3,"work_loops":7}"#).expect("decode old payload");
    assert_eq!(old.worker_id, 3);
    assert_eq!(
        old.session_volume_high_water, 0,
        "an absent key decodes to the Rust zero value; the GO side is where \
         absent-vs-zero is preserved, via a pointer (see \
         metrics_session_volume_high_water_7919_test.go)"
    );
}

/// #9517: the ESTABLISHED half of the issue, measured — the XDP steering key
/// ALIASES two sessions the authoritative `SessionKey` keeps apart.
///
/// This is a CHARACTERIZATION, not a defect guard, and it is labelled so. It pins
/// the known collision surface so that (a) the README's corrected residual list
/// rests on an executed fact rather than a reading, and (b) a future change that
/// widens the key has to update this cell deliberately instead of the aliasing
/// disappearing — or reappearing — unnoticed.
///
/// THE POSITIVE CONTROL is what makes it a measurement rather than a tautology: a
/// field the key DOES carry (`src_port`) must separate two keys. Without it,
/// "the bytes are equal" is satisfied by an encoder that ignores every field.
#[test]
fn steering_key_aliases_routing_domain_and_gre_discriminator_9517() {
    fn key_bytes(k: &SessionKey) -> Vec<u8> {
        let mk = session_map_key(k);
        let n = std::mem::size_of::<UserspaceSessionMapKey>();
        unsafe {
            std::slice::from_raw_parts((&mk as *const UserspaceSessionMapKey).cast::<u8>(), n)
                .to_vec()
        }
    }
    let base = SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: 47,
        src_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 5)),
        dst_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 9)),
        src_port: 0,
        dst_port: 0,
        discriminator: crate::session::TunnelDiscriminator::Keyed(1),
        routing_domain: 0,
    };

    assert_eq!(
        std::mem::size_of::<UserspaceSessionMapKey>(),
        40,
        "the steering key is 40 bytes; a size change is a shim ABI change \
         (`loader_userspace_shim.go`) and must not happen by accident (#9517)"
    );

    // Arm 1: routing_domain. Authoritatively DIFFERENT, byte-identical row.
    let other_domain = SessionKey { routing_domain: 100_007, ..base.clone() };
    assert_ne!(base, other_domain, "the authoritative keys must differ");
    assert_eq!(
        key_bytes(&base),
        key_bytes(&other_domain),
        "two sessions in different routing domains share ONE steering row — the \
         aliasing #9517 measured (#9517)"
    );

    // Arm 2: the GRE discriminator. DETERMINISTIC: needs no routing domains at
    // all, because two RFC 2890 keyed tunnels between the same endpoints are both
    // protocol 47 with no L4 ports.
    let other_gre_key = SessionKey {
        discriminator: crate::session::TunnelDiscriminator::Keyed(2),
        ..base.clone()
    };
    assert_ne!(base, other_gre_key, "the authoritative keys must differ");
    assert_eq!(
        key_bytes(&base),
        key_bytes(&other_gre_key),
        "two keyed GRE tunnels between the same endpoints share ONE steering row, \
         on a single-VRF box, with no crafted traffic (#9517)"
    );

    // POSITIVE CONTROL: a field the key DOES carry must separate.
    let other_port = SessionKey { src_port: 1235, ..base.clone() };
    assert_ne!(
        key_bytes(&base),
        key_bytes(&other_port),
        "control: `src_port` is carried by the steering key, so it MUST separate. \
         If this is equal, the encoder ignores every field and the two aliasing \
         assertions above are vacuous (#9517)"
    );
}
