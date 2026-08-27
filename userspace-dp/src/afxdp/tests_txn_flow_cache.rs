// transactional flow-cache admission, hit reclassification, and pool/reply-repair.
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

// I1/I2/I3: at cap, a NAT'd new flow is REFUSED — trigger packet dropped
// (not forwarded), nothing installed (forward NOR reverse), nothing
// flow-cached, refusal counted.
#[test]
fn txn_admission_refusal_at_cap_drops_and_leaks_nothing() {
    let forwarding = build_forwarding_state(&nat_snapshot());
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();
    sessions.set_max_sessions_for_test(0);

    let frame = build_txn_tcp_syn_frame_v4(
        Ipv4Addr::new(10, 0, 61, 102),
        Ipv4Addr::new(8, 8, 8, 8),
        12345,
        443,
        TCP_FLAG_SYN,
    );
    let meta = txn_meta_v4(24, TCP_FLAG_SYN, frame.len() as u16);
    let (batch, dbg) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
    );

    assert_eq!(
        dbg.tx, 0,
        "refused flow's trigger packet must NOT be forwarded"
    );
    assert!(
        binding.scratch.scratch_recycle.contains(&128),
        "refused flow's trigger frame must be recycled"
    );
    assert_eq!(sessions.len(), 0, "no forward or reverse entry may leak");
    assert_eq!(sessions.admission_refused(), 1);
    assert_eq!(sessions.install_partial(), 0);
    assert_eq!(
        txn_flow_cache_entries(&binding),
        0,
        "a refused flow's (rolled-back) NAT decision must never be cached"
    );
    assert_eq!(batch.session_creates, 0);
    // #4800: a REFUSED flow is not an install. This is the over-reach half of
    // the per-binding new-flow counter — see
    // `txn_new_flow_install_counts_on_the_binding_4800` below for the positive
    // cell. It stays GREEN under that cell's revert (deleting the poll-path
    // `fetch_add` pins the counter at 0, and 0 is what this asserts).
    assert_eq!(
        binding.live.new_flow_installs.load(Ordering::Relaxed),
        0,
        "an admission-refused flow must not be counted as a new-flow install \
         — folding refusals in would inflate the very rate the ceiling \
         analysis divides by"
    );
}


/// #4800 RED-on-revert: the per-binding `new_flow_installs` counter must be
/// bumped by the REAL transit-install path, not merely carried by the
/// worker-level plumbing above it.
///
/// The counter is the only input to both cross-worker gates the ceiling
/// analyzer runs (`active_workers < 3` and `max_worker_share > 0.60`), so an
/// increment that never fires reads as "one worker does all the work" — the
/// exact verdict those gates exist to raise — with no way to tell that from a
/// real skew.
///
/// Drives a genuine LAN->WAN TCP SYN through `poll_binding_process_descriptor`
/// (not a synthetic leaf call), so the assertion sits downstream of every
/// rollback door: ICMP-TE bounce, admission refusal, and install-partial all
/// `continue` before reaching the increment.
///
/// RED on revert: deleting the `binding.live.new_flow_installs.fetch_add(1, ..)`
/// in `poll_descriptor/mod.rs` leaves the counter at 0 and this fails on its
/// message while `batch.session_creates` still reports 2 — an assertion
/// failure, not a build or behaviour break.
#[test]
fn txn_new_flow_install_counts_on_the_binding_4800() {
    let forwarding = build_forwarding_state(&nat_snapshot());
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();

    assert_eq!(
        binding.live.new_flow_installs.load(Ordering::Relaxed),
        0,
        "fixture must start from zero for the delta below to mean anything"
    );

    let frame = build_txn_tcp_syn_frame_v4(
        Ipv4Addr::new(10, 0, 61, 102),
        Ipv4Addr::new(8, 8, 8, 8),
        12345,
        443,
        TCP_FLAG_SYN,
    );
    let meta = txn_meta_v4(24, TCP_FLAG_SYN, frame.len() as u16);
    let (batch, dbg) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
    );

    // Control: the flow really did install and forward. Without this, a
    // fixture that silently stopped installing would make the counter
    // assertion below vacuous rather than red. Two session CREATES for one
    // flow is the dual forward+reverse entry the session table always
    // installs as a pair.
    assert_eq!(dbg.tx, 1, "the SYN must forward");
    assert_eq!(
        batch.session_creates, 2,
        "the SYN must install the forward session and its reverse companion"
    );
    // ...and exactly ONE new-flow install. The counter is a FLOW rate, not a
    // session-entry rate: it sits on the forward-install site alone, so the
    // reverse companion must not double it. A per-entry count would report
    // twice the connection rate the ceiling analysis is trying to bound.
    assert_eq!(
        binding.live.new_flow_installs.load(Ordering::Relaxed),
        1,
        "a committed transit forward install must count exactly once on the \
         OWNING binding — this is the per-worker skew signal, and a zero here \
         is indistinguishable from a worker that never took any work"
    );
}


/// #3777 RED-on-revert: an interface INPUT filter `then count` must count EVERY
/// packet of a cacheable flow, not just the seed. Packet 1 (SYN) counts on the
/// cold path and seeds the flow cache; packet 2 (same 5-tuple) hits the flow
/// cache and MUST replay the input `then count` — mirroring the output-counter
/// replay (#2573). Reverting the input replay leaves the counter at 1 for a
/// 2-packet flow (the under-count this fixes).
#[test]
fn txn_flow_cache_hit_replays_input_filter_then_count_3777() {
    use std::sync::atomic::Ordering;

    let mut snapshot = nat_snapshot();
    // A count-only accept term on the LAN ingress interface (ifindex 24). No
    // forwarding-class / dscp, so it is NOT tx-selection-affecting and is NOT
    // folded into tx_selection.filter_counters — exactly the #3777 gap.
    snapshot.interfaces[0].filter_input_v4 = "count-in".to_string();
    snapshot.filters = vec![FirewallFilterSnapshot {
        name: "count-in".to_string(),
        family: "inet".to_string(),
        terms: vec![FirewallTermSnapshot {
            name: "count-all".to_string(),
            action: "accept".to_string(),
            count: "c-all".to_string(),
            ..Default::default()
        }],
    }];

    let forwarding = build_forwarding_state(&snapshot);
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();

    let input_counter = forwarding
        .filter_state
        .iface_filter_v4_fast
        .get(&24)
        .expect("input filter compiled for ifindex 24")
        .terms
        .first()
        .expect("one term")
        .counter
        .clone();
    assert_eq!(input_counter.packets.load(Ordering::Relaxed), 0);

    // Packet 1 (pure ACK = established TCP, so it is flow-cache-eligible per
    // #2363 — a SYN is not cached): cold path counts the input filter, installs
    // the session, and seeds the flow cache.
    let frame1 = build_txn_tcp_syn_frame_v4(
        Ipv4Addr::new(10, 0, 61, 102),
        Ipv4Addr::new(8, 8, 8, 8),
        12345,
        443,
        0x10_u8,
    );
    let meta1 = txn_meta_v4(24, 0x10_u8, (frame1.len() - 14) as u16);
    txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame1,
        meta1,
    );
    assert_eq!(
        input_counter.packets.load(Ordering::Relaxed),
        1,
        "the seed packet must count on the cold path"
    );
    assert_eq!(
        txn_flow_cache_entries(&binding),
        1,
        "the forwarded SYN must seed the flow cache"
    );

    // Packet 2 (same 5-tuple, ACK): MUST hit the flow cache and replay the
    // input count.
    let frame2 = build_txn_tcp_syn_frame_v4(
        Ipv4Addr::new(10, 0, 61, 102),
        Ipv4Addr::new(8, 8, 8, 8),
        12345,
        443,
        0x10_u8,
    );
    let meta2 = txn_meta_v4(24, 0x10_u8, (frame2.len() - 14) as u16);
    let (_, dbg2) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame2,
        meta2,
    );
    assert!(
        dbg2.tx >= 1,
        "packet 2 must be forwarded from the flow-cache fast path"
    );
    assert_eq!(
        input_counter.packets.load(Ordering::Relaxed),
        2,
        "the flow-cache hit MUST replay the interface input `then count` (#3777)"
    );
}


/// #3778 RED-on-revert: a CoS behavior-aggregate (DSCP) classifier is
/// per-packet in vSRX, but the cached TX-selection froze the SEED packet's
/// queue (the flow-cache key excludes DSCP). Packet 1 (DSCP 0) seeds the cache
/// on the default queue; packet 2 (same 5-tuple, DSCP 46 = EF) hits the flow
/// cache and MUST re-classify to the EF queue. Reverting the per-packet
/// re-classify replays the frozen default queue (queue 0), which this asserts
/// against (expects queue 1).
#[test]
fn txn_flow_cache_hit_reclassifies_ba_dscp_per_packet_3778() {
    let mut snapshot = nat_snapshot();
    // CoS on the WAN egress (reth0.80, ifindex 12): a DSCP BA classifier maps
    // DSCP 46 (EF) -> expedited-forwarding (queue 1); DSCP 0 is unmapped and
    // falls to the default best-effort queue (0).
    snapshot.interfaces[1].cos_shaping_rate_bytes_per_sec = 10_000_000;
    snapshot.interfaces[1].cos_shaping_burst_bytes = 256_000;
    snapshot.interfaces[1].cos_scheduler_map = "wan-map".to_string();
    snapshot.interfaces[1].cos_dscp_classifier = "cls".to_string();
    snapshot.class_of_service = Some(ClassOfServiceSnapshot {
        forwarding_classes: vec![
            CoSForwardingClassSnapshot {
                name: "best-effort".into(),
                queue: 0,
            },
            CoSForwardingClassSnapshot {
                name: "expedited-forwarding".into(),
                queue: 1,
            },
        ],
        dscp_classifiers: vec![CoSDSCPClassifierSnapshot {
            name: "cls".into(),
            entries: vec![CoSDSCPClassifierEntrySnapshot {
                forwarding_class: "expedited-forwarding".into(),
                loss_priority: "low".into(),
                dscp_values: vec![46],
            }],
        }],
        ieee8021_classifiers: vec![],
        dscp_rewrite_rules: vec![],
        schedulers: vec![
            CoSSchedulerSnapshot {
                name: "be-sched".into(),
                transmit_rate_bytes: 4_000_000,
                transmit_rate_percent: 0.0,
                transmit_rate_exact: false,
                priority: "low".into(),
                buffer_size_bytes: 128_000,
                buffer_size_percent: 0.0,
                surplus_sharing: false,
                equal_flow_enforcement: false,
                equal_flow_target_policy: String::new(),
                codel_target_ns: 0,
                ..Default::default()
            },
            CoSSchedulerSnapshot {
                name: "ef-sched".into(),
                transmit_rate_bytes: 6_000_000,
                transmit_rate_percent: 0.0,
                transmit_rate_exact: false,
                priority: "strict-high".into(),
                buffer_size_bytes: 64_000,
                buffer_size_percent: 0.0,
                surplus_sharing: false,
                equal_flow_enforcement: false,
                equal_flow_target_policy: String::new(),
                codel_target_ns: 0,
                ..Default::default()
            },
        ],
        scheduler_maps: vec![CoSSchedulerMapSnapshot {
            name: "wan-map".into(),
            entries: vec![
                CoSSchedulerMapEntrySnapshot {
                    forwarding_class: "best-effort".into(),
                    scheduler: "be-sched".into(),
                },
                CoSSchedulerMapEntrySnapshot {
                    forwarding_class: "expedited-forwarding".into(),
                    scheduler: "ef-sched".into(),
                },
            ],
        }],
        inet_precedence_classifiers: vec![],
    });

    let forwarding = build_forwarding_state(&snapshot);
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();

    // Packet 1 (pure ACK = established, cache-eligible; DSCP 0): seeds the
    // cache on the default queue.
    let frame1 = build_txn_tcp_syn_frame_v4(
        Ipv4Addr::new(10, 0, 61, 102),
        Ipv4Addr::new(8, 8, 8, 8),
        12345,
        443,
        0x10_u8,
    );
    let mut meta1 = txn_meta_v4(24, 0x10_u8, (frame1.len() - 14) as u16);
    meta1.dscp = 0;
    txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame1,
        meta1,
    );
    assert_eq!(
        txn_flow_cache_entries(&binding),
        1,
        "the forwarded established ACK must seed the flow cache"
    );
    let seed_q = binding
        .scratch
        .scratch_forwards
        .last()
        .and_then(|r| r.cos_queue_id);
    assert_eq!(
        seed_q,
        Some(0),
        "DSCP-0 seed packet must land on the default (best-effort) queue"
    );

    // Packet 2 (same 5-tuple, DSCP 46 = EF): flow-cache HIT. The BA classifier
    // MUST re-classify per packet to the EF queue instead of replaying the
    // frozen default.
    let frame2 = build_txn_tcp_syn_frame_v4(
        Ipv4Addr::new(10, 0, 61, 102),
        Ipv4Addr::new(8, 8, 8, 8),
        12345,
        443,
        0x10_u8,
    );
    let mut meta2 = txn_meta_v4(24, 0x10_u8, (frame2.len() - 14) as u16);
    meta2.dscp = 46;
    txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame2,
        meta2,
    );
    let hit_q = binding
        .scratch
        .scratch_forwards
        .last()
        .and_then(|r| r.cos_queue_id);
    assert_eq!(
        hit_q,
        Some(1),
        "the flow-cache hit MUST re-classify DSCP 46 to the EF queue (#3778), \
         not replay the seed's frozen default queue"
    );
}


/// #3779 RED-on-revert: on the flow-cache hit path the TTL/hop-limit check (and
/// its ICMP Time Exceeded) MUST run BEFORE the egress side effects (output
/// `then count` replay, policy hit counter, policers, filter logs, terminal
/// drop). Packet 1 (TTL 64) seeds the cache and charges the output filter count
/// once; packet 2 (same 5-tuple, TTL 1) hits the cache and must be handled as a
/// TTL-exceeded packet — enqueuing ICMP Time Exceeded — WITHOUT charging the
/// output filter count a second time. Reverting the hoist replays the output
/// count for the expired packet (it reaches 2) and, on a dropping flow, would
/// drop it before the TE is built.
#[test]
fn txn_flow_cache_hit_ttl_check_precedes_egress_accounting_3779() {
    use std::sync::atomic::Ordering;

    let mut snapshot = nat_snapshot();
    // Output `then count accept` on the WAN egress (reth0.80, ifindex 12): its
    // counter is captured into the cached tx_selection and replayed on hits.
    snapshot.interfaces[1].filter_output_v4 = "count-out".to_string();
    snapshot.filters = vec![FirewallFilterSnapshot {
        name: "count-out".to_string(),
        family: "inet".to_string(),
        terms: vec![FirewallTermSnapshot {
            name: "count-all".to_string(),
            action: "accept".to_string(),
            count: "c-out".to_string(),
            ..Default::default()
        }],
    }];

    let forwarding = build_forwarding_state(&snapshot);
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();

    let out_counter = forwarding
        .filter_state
        .iface_filter_out_v4_fast
        .get(&12)
        .expect("output filter compiled for ifindex 12")
        .terms
        .first()
        .expect("one term")
        .counter
        .clone();

    // Packet 1 (pure ACK, TTL 64): seeds the cache and charges the output count.
    let frame1 = build_txn_tcp_syn_frame_v4(
        Ipv4Addr::new(10, 0, 61, 102),
        Ipv4Addr::new(8, 8, 8, 8),
        12345,
        443,
        0x10_u8,
    );
    let meta1 = txn_meta_v4(24, 0x10_u8, (frame1.len() - 14) as u16);
    txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame1,
        meta1,
    );
    assert_eq!(
        txn_flow_cache_entries(&binding),
        1,
        "the forwarded established ACK must seed the flow cache"
    );
    assert_eq!(
        out_counter.packets.load(Ordering::Relaxed),
        1,
        "the seed packet charges the output `then count` once"
    );
    let forwards_after_seed = binding.scratch.scratch_forwards.len();

    // Packet 2 (same 5-tuple, TTL 1): TTL check must precede egress accounting.
    let mut frame2 = build_txn_tcp_syn_frame_v4(
        Ipv4Addr::new(10, 0, 61, 102),
        Ipv4Addr::new(8, 8, 8, 8),
        12345,
        443,
        0x10_u8,
    );
    // IPv4 TTL byte: eth(14) + IP header offset 8 = frame index 22. Rewrite to
    // 1 and repair the IPv4 header checksum (frame[24..26]).
    frame2[22] = 1;
    frame2[24] = 0;
    frame2[25] = 0;
    let ip_sum = checksum16(&frame2[14..34]);
    frame2[24] = (ip_sum >> 8) as u8;
    frame2[25] = ip_sum as u8;
    let meta2 = txn_meta_v4(24, 0x10_u8, (frame2.len() - 14) as u16);
    txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame2,
        meta2,
    );
    assert_eq!(
        out_counter.packets.load(Ordering::Relaxed),
        1,
        "a TTL=1 cache-hit packet MUST NOT charge egress counters — the TTL \
         check runs before egress accounting (#3779)"
    );
    // The expired packet is handled on the TTL path (ICMP Time Exceeded when
    // the per-reason token bucket admits it, otherwise a silent drop) — in BOTH
    // cases BEFORE egress accounting, which the count==1 pin above proves. When
    // a reply IS enqueued it must be a prebuilt Time Exceeded frame, not the
    // transit packet; the global per-reason rate-limiter bucket is shared across
    // the test binary, so gate that stronger check on the reply being produced
    // rather than asserting it unconditionally (which would flake).
    if binding.scratch.scratch_forwards.len() > forwards_after_seed {
        let te = binding
            .scratch
            .scratch_forwards
            .last()
            .expect("a forward request for the TTL=1 packet");
        assert!(
            matches!(te.frame, PendingForwardFrame::Prebuilt(_)),
            "an enqueued forward for a TTL=1 cache-hit packet must be a prebuilt \
             ICMP Time Exceeded reply, not the transit packet"
        );
    }
}


/// #4422 RED-on-revert: the CoS behavior-aggregate re-classify on a flow-cache
/// HIT (#3778) must also cover the IEEE 802.1p (PCP) classifier branch, not just
/// DSCP. PCP — like DSCP — is a per-packet field excluded from the 5-tuple
/// flow-cache key (`reclassify_cached_ba_queue` reads `meta.ingress_pcp`), so a
/// mixed-priority flow must not be pinned to the SEED packet's queue.
///
/// A priority-tagged (802.1p, VID 0) packet 1 with PCP 0 seeds the cache on the
/// default (best-effort) queue; packet 2 (same 5-tuple, PCP 5) hits the flow
/// cache and MUST re-classify to the EF queue via the 802.1p branch of
/// `reclassify_cached_ba_queue`. The interface carries ONLY an 802.1p classifier
/// (no DSCP classifier), so the PCP branch is the sole path to the EF queue.
/// Reverting the per-packet re-classify (or dropping the 802.1p arm) replays the
/// frozen default queue (0), which this asserts against (expects queue 1).
#[test]
fn txn_flow_cache_hit_reclassifies_ba_pcp_per_packet_4422() {
    // Splice an 802.1p priority tag (TPID 0x8100, VID 0, PCP in the top 3 TCI
    // bits) after the 12-byte MAC header of an otherwise-untagged frame.
    // Inserting 4 bytes at offset 12 leaves the IP/TCP content — and its
    // checksum — byte-identical; only the L3 offset shifts 14 -> 18, which the
    // paired meta below reflects (ingress_vlan_present = 1).
    fn priority_tag(frame: &[u8], pcp: u8) -> Vec<u8> {
        let mut tagged = Vec::with_capacity(frame.len() + 4);
        tagged.extend_from_slice(&frame[..12]);
        tagged.extend_from_slice(&0x8100u16.to_be_bytes());
        tagged.extend_from_slice(&(u16::from(pcp) << 13).to_be_bytes());
        tagged.extend_from_slice(&frame[12..]);
        tagged
    }
    // Meta for a priority-tagged (VID 0) frame: L3 at 18, tag present, PCP set.
    // Everything else mirrors the untagged `txn_meta_v4`.
    fn pcp_meta(pcp: u8, l3_len: u16) -> UserspaceDpMeta {
        UserspaceDpMeta {
            l3_offset: 18,
            l4_offset: 38,
            payload_offset: 58,
            ingress_vlan_present: 1,
            ingress_vlan_id: 0,
            ingress_pcp: pcp,
            ..txn_meta_v4(24, 0x10_u8, l3_len)
        }
    }

    let mut snapshot = nat_snapshot();
    // CoS on the WAN egress (reth0.80, ifindex 12): an 802.1p (PCP) BA
    // classifier maps PCP 5 -> expedited-forwarding (queue 1); PCP 0 is unmapped
    // and falls to the default best-effort queue (0). Deliberately NO DSCP
    // classifier, so the 802.1p branch of reclassify_cached_ba_queue is the only
    // path that can select the EF queue.
    snapshot.interfaces[1].cos_shaping_rate_bytes_per_sec = 10_000_000;
    snapshot.interfaces[1].cos_shaping_burst_bytes = 256_000;
    snapshot.interfaces[1].cos_scheduler_map = "wan-map".to_string();
    snapshot.interfaces[1].cos_ieee8021_classifier = "pcp-cls".to_string();
    snapshot.class_of_service = Some(ClassOfServiceSnapshot {
        forwarding_classes: vec![
            CoSForwardingClassSnapshot {
                name: "best-effort".into(),
                queue: 0,
            },
            CoSForwardingClassSnapshot {
                name: "expedited-forwarding".into(),
                queue: 1,
            },
        ],
        dscp_classifiers: vec![],
        ieee8021_classifiers: vec![CoSIEEE8021ClassifierSnapshot {
            name: "pcp-cls".into(),
            entries: vec![CoSIEEE8021ClassifierEntrySnapshot {
                forwarding_class: "expedited-forwarding".into(),
                loss_priority: "low".into(),
                code_points: vec![5],
            }],
        }],
        dscp_rewrite_rules: vec![],
        schedulers: vec![
            CoSSchedulerSnapshot {
                name: "be-sched".into(),
                transmit_rate_bytes: 4_000_000,
                transmit_rate_percent: 0.0,
                transmit_rate_exact: false,
                priority: "low".into(),
                buffer_size_bytes: 128_000,
                buffer_size_percent: 0.0,
                surplus_sharing: false,
                equal_flow_enforcement: false,
                equal_flow_target_policy: String::new(),
                codel_target_ns: 0,
                ..Default::default()
            },
            CoSSchedulerSnapshot {
                name: "ef-sched".into(),
                transmit_rate_bytes: 6_000_000,
                transmit_rate_percent: 0.0,
                transmit_rate_exact: false,
                priority: "strict-high".into(),
                buffer_size_bytes: 64_000,
                buffer_size_percent: 0.0,
                surplus_sharing: false,
                equal_flow_enforcement: false,
                equal_flow_target_policy: String::new(),
                codel_target_ns: 0,
                ..Default::default()
            },
        ],
        scheduler_maps: vec![CoSSchedulerMapSnapshot {
            name: "wan-map".into(),
            entries: vec![
                CoSSchedulerMapEntrySnapshot {
                    forwarding_class: "best-effort".into(),
                    scheduler: "be-sched".into(),
                },
                CoSSchedulerMapEntrySnapshot {
                    forwarding_class: "expedited-forwarding".into(),
                    scheduler: "ef-sched".into(),
                },
            ],
        }],
        inet_precedence_classifiers: vec![],
    });

    let forwarding = build_forwarding_state(&snapshot);
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();

    // Packet 1 (pure ACK = established, cache-eligible; priority tag PCP 0):
    // seeds the cache on the default queue.
    let base1 = build_txn_tcp_syn_frame_v4(
        Ipv4Addr::new(10, 0, 61, 102),
        Ipv4Addr::new(8, 8, 8, 8),
        12345,
        443,
        0x10_u8,
    );
    let frame1 = priority_tag(&base1, 0);
    let meta1 = pcp_meta(0, (frame1.len() - 18) as u16);
    txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame1,
        meta1,
    );
    assert_eq!(
        txn_flow_cache_entries(&binding),
        1,
        "the forwarded established ACK must seed the flow cache"
    );
    let seed_q = binding
        .scratch
        .scratch_forwards
        .last()
        .and_then(|r| r.cos_queue_id);
    assert_eq!(
        seed_q,
        Some(0),
        "PCP-0 seed packet must land on the default (best-effort) queue"
    );

    // Packet 2 (same 5-tuple, priority tag PCP 5): flow-cache HIT. The 802.1p BA
    // classifier MUST re-classify per packet to the EF queue instead of
    // replaying the frozen default.
    let base2 = build_txn_tcp_syn_frame_v4(
        Ipv4Addr::new(10, 0, 61, 102),
        Ipv4Addr::new(8, 8, 8, 8),
        12345,
        443,
        0x10_u8,
    );
    let frame2 = priority_tag(&base2, 5);
    let meta2 = pcp_meta(5, (frame2.len() - 18) as u16);
    txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame2,
        meta2,
    );
    let hit_q = binding
        .scratch
        .scratch_forwards
        .last()
        .and_then(|r| r.cos_queue_id);
    assert_eq!(
        hit_q,
        Some(1),
        "the flow-cache hit MUST re-classify PCP 5 to the EF queue via the \
         802.1p branch (#4422), not replay the seed's frozen default queue"
    );
}


/// #4422 RED-on-revert: a TTL-expired packet on a cached flow whose egress
/// output filter carries a THREE-COLOR POLICER must NOT consume policer credits.
/// The #3779 hoist runs the TTL/hop-limit check BEFORE
/// `apply_cached_three_color_policers`, so an expired cache-hit packet — which
/// never egresses — must not meter the policer (which would drain a token bucket
/// meant for real traffic and skew it toward red for packets that were dropped).
///
/// #3779 pinned the ordering for an output `then count` counter; this pins the
/// POLICER interaction — the "TTL-expired-with-policer" item #4422 calls out.
/// Packet 1 (TTL 64) seeds the cache; packet 2 (TTL 1) hits and must leave the
/// policer's green count unchanged; packet 3 (TTL 64) hits and DOES meter the
/// policer once — proving packet 2's non-metering is the TTL guard, not a dead
/// policer. Reverting the hoist meters the expired packet 2 (green += 1) and
/// fails the packet-2 assertion.
#[test]
fn txn_flow_cache_hit_ttl_expired_does_not_charge_three_color_policer_4422() {
    let mut snapshot = nat_snapshot();
    // Output filter on the WAN egress (reth0.80, ifindex 12): accept + a
    // generous single-rate policer so every forwarded packet is GREEN (the
    // assertion is about whether the packet is METERED at all, not about drops).
    snapshot.interfaces[1].filter_output_v4 = "policed-out".to_string();
    snapshot.filters = vec![FirewallFilterSnapshot {
        name: "policed-out".to_string(),
        family: "inet".to_string(),
        terms: vec![FirewallTermSnapshot {
            name: "accept-policed".to_string(),
            action: "accept".to_string(),
            policer: "p-out".to_string(),
            ..Default::default()
        }],
    }];
    snapshot.three_color_policers = vec![ThreeColorPolicerSnapshot {
        name: "p-out".to_string(),
        mode: "single-rate".to_string(),
        color_blind: true,
        committed_rate_bytes_per_sec: 1,
        committed_burst_bytes: 10_000,
        peak_or_excess_burst_bytes: 5_000,
        then_action: "discard".to_string(),
        ..Default::default()
    }];

    let forwarding = build_forwarding_state(&snapshot);
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();

    let green_packets = || {
        forwarding
            .filter_state
            .three_color_policer_statuses()
            .into_iter()
            .find(|s| s.name == "p-out")
            .expect("policer p-out present in status")
            .green_packets
    };

    // Packet 1 (pure ACK, TTL 64): seeds the cache and forwards.
    let frame1 = build_txn_tcp_syn_frame_v4(
        Ipv4Addr::new(10, 0, 61, 102),
        Ipv4Addr::new(8, 8, 8, 8),
        12345,
        443,
        0x10_u8,
    );
    let meta1 = txn_meta_v4(24, 0x10_u8, (frame1.len() - 14) as u16);
    txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame1,
        meta1,
    );
    assert_eq!(
        txn_flow_cache_entries(&binding),
        1,
        "the forwarded established ACK must seed the flow cache"
    );
    let green_after_seed = green_packets();

    // Packet 2 (same 5-tuple, TTL 1): flow-cache HIT, TTL expired. The TTL check
    // precedes the policer, so this packet must NOT meter it.
    let mut frame2 = build_txn_tcp_syn_frame_v4(
        Ipv4Addr::new(10, 0, 61, 102),
        Ipv4Addr::new(8, 8, 8, 8),
        12345,
        443,
        0x10_u8,
    );
    // IPv4 TTL byte: eth(14) + IP header offset 8 = frame index 22. Rewrite to 1
    // and repair the IPv4 header checksum (frame[24..26]).
    frame2[22] = 1;
    frame2[24] = 0;
    frame2[25] = 0;
    let ip_sum = checksum16(&frame2[14..34]);
    frame2[24] = (ip_sum >> 8) as u8;
    frame2[25] = ip_sum as u8;
    let meta2 = txn_meta_v4(24, 0x10_u8, (frame2.len() - 14) as u16);
    txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame2,
        meta2,
    );
    assert_eq!(
        green_packets(),
        green_after_seed,
        "a TTL=1 cache-hit packet MUST NOT meter the three-color policer — the \
         TTL check runs before apply_cached_three_color_policers (#4422 / #3779)"
    );

    // Packet 3 (same 5-tuple, TTL 64): a LIVE flow-cache hit. This DOES meter the
    // policer once on the cached replay path — proving the policer is live and
    // that packet 2's non-metering is specifically the TTL guard.
    let frame3 = build_txn_tcp_syn_frame_v4(
        Ipv4Addr::new(10, 0, 61, 102),
        Ipv4Addr::new(8, 8, 8, 8),
        12345,
        443,
        0x10_u8,
    );
    let meta3 = txn_meta_v4(24, 0x10_u8, (frame3.len() - 14) as u16);
    txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame3,
        meta3,
    );
    assert_eq!(
        green_packets(),
        green_after_seed + 1,
        "a live cache-hit packet meters the three-color policer exactly once — \
         confirms the policer is live, so packet 2's unchanged count is the TTL \
         guard, not a dead policer"
    );
}


// I4 boundary: a forward+reverse pair is admitted while 2 slots remain
// and refused at cap-1 (1 slot remaining). The admitted phase also pins
// that a passing preflight makes both installs succeed.
#[test]
fn txn_pair_admitted_at_cap_minus_two_refused_at_cap_minus_one() {
    let forwarding = build_forwarding_state(&nat_snapshot());
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();
    sessions.set_max_sessions_for_test(2);

    // Phase 1: len 0, cap 2 — exactly the pair fits.
    let frame = build_txn_tcp_syn_frame_v4(
        Ipv4Addr::new(10, 0, 61, 102),
        Ipv4Addr::new(8, 8, 8, 8),
        12345,
        443,
        TCP_FLAG_SYN,
    );
    let meta = txn_meta_v4(24, TCP_FLAG_SYN, frame.len() as u16);
    let (_b1, d1) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
    );
    assert_eq!(
        sessions.len(),
        2,
        "forward + reverse must both install when the pair fits"
    );
    assert_eq!(d1.tx, 1, "admitted flow forwards its trigger packet");
    assert_eq!(sessions.admission_refused(), 0);

    // Phase 2: len 2, cap 3 — one free slot, a pair needs two: refuse.
    sessions.set_max_sessions_for_test(3);
    let frame2 = build_txn_tcp_syn_frame_v4(
        Ipv4Addr::new(10, 0, 61, 102),
        Ipv4Addr::new(8, 8, 8, 8),
        12346,
        443,
        TCP_FLAG_SYN,
    );
    let meta2 = txn_meta_v4(24, TCP_FLAG_SYN, (frame2.len() - 14) as u16);
    let (_b2, d2) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame2,
        meta2,
    );
    assert_eq!(
        sessions.len(),
        2,
        "cap-1 must refuse the pair — no one-sided forward install"
    );
    assert_eq!(sessions.admission_refused(), 1);
    assert_eq!(
        d2.tx, 0,
        "refused flow at cap-1 must not forward its trigger packet"
    );
    assert_eq!(sessions.install_partial(), 0);
}


// I2 (pool-mode): the refusal arm releases the pool-SNAT allocation AND
// the flow cache stays empty — the pre-fix behavior cached the
// rolled-back tuple, persisting an unreserved translated (ip,port) on
// the wire (cross-flow aliasing, plan §2).
#[test]
fn txn_pool_snat_refusal_rolls_back_allocation_and_caches_nothing() {
    let mut snapshot = nat_snapshot();
    snapshot.source_nat_rules = vec![SourceNATRuleSnapshot {
        name: "snat-pool".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        pool_name: "pool-a".to_string(),
        pool_addresses: vec!["172.16.80.100".to_string()],
        port_low: 20000,
        port_high: 20999,
        ..Default::default()
    }];
    let forwarding = build_forwarding_state(&snapshot);
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();
    sessions.set_max_sessions_for_test(0);

    let frame = build_txn_tcp_syn_frame_v4(
        Ipv4Addr::new(10, 0, 61, 102),
        Ipv4Addr::new(8, 8, 8, 8),
        12345,
        443,
        TCP_FLAG_SYN,
    );
    let meta = txn_meta_v4(24, TCP_FLAG_SYN, frame.len() as u16);
    let (_b, dbg) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
    );

    assert_eq!(dbg.tx, 0, "refused pool-SNAT flow must not forward");
    assert_eq!(sessions.len(), 0);
    assert_eq!(sessions.admission_refused(), 1);
    let pools = crate::nat::source_nat_pool_statuses(&forwarding.source_nat_rules);
    assert_eq!(pools.len(), 1);
    assert_eq!(
        pools[0].live_flows, 0,
        "refused flow's pool-SNAT allocation must be rolled back"
    );
    assert_eq!(
        txn_flow_cache_entries(&binding),
        0,
        "the rolled-back pool tuple must NOT persist in the flow cache"
    );
}


// I5: a reply whose reverse-session repair install fails at cap is still
// forwarded but NOT flow-cached, so the repair re-fires per packet and
// installs the reverse session on the first reply after capacity frees
// (plan §5.4, Codex r1 C1). Also pins created==install outcome (AGY r1
// F1): a failed repair must not count a session create.
#[test]
fn txn_failed_reply_repair_forwards_uncached_then_self_heals_below_cap() {
    let mut snapshot = nat_snapshot();
    // The repair resolves the reply toward the LAN host; give it a
    // neighbor so the rebuilt reverse decision is a ForwardCandidate.
    snapshot.neighbors.push(NeighborSnapshot {
        interface: "ge-0-0-1".to_string(),
        ifindex: 24,
        family: "inet".to_string(),
        ip: "10.0.61.102".to_string(),
        mac: "0a:0b:0c:0d:0e:0f".to_string(),
        state: "reachable".to_string(),
        router: false,
        link_local: false,
    });
    let forwarding = build_forwarding_state(&snapshot);
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 12, 0);
    binding.interface = Arc::<str>::from("reth0.80");
    let mut sessions = SessionTable::new();

    // Forward session: 10.0.61.102:12345 -> 8.8.8.8:443, interface SNAT
    // to 172.16.80.8 (no port rewrite). Installed below cap, then the
    // table is pinned at cap so the repair's reverse install must fail.
    let forward_key = SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        src_port: 12345,
        dst_port: 443,
    };
    let forward_decision = SessionDecision {
        resolution: lookup_forwarding_resolution(
            &forwarding,
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        ),
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
            ..NatDecision::default()
        },
    };
    assert!(sessions.install_with_protocol_with_origin(
        forward_key,
        forward_decision,
        SessionMetadata {
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
        },
        SessionOrigin::ForwardFlow,
        122_000_000_000,
        PROTO_TCP,
        TCP_FLAG_SYN,
    ));
    sessions.set_max_sessions_for_test(1);

    // Reply: 8.8.8.8:443 -> 172.16.80.8:12345 (pure ACK) from the WAN.
    let reply = build_txn_tcp_syn_frame_v4(
        Ipv4Addr::new(8, 8, 8, 8),
        Ipv4Addr::new(172, 16, 80, 8),
        443,
        12345,
        0x10,
    );
    let meta = txn_meta_v4(12, 0x10, (reply.len() - 14) as u16);
    let (batch, dbg) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &reply,
        meta,
    );
    assert_eq!(
        dbg.tx, 1,
        "reply must still forward when the repair install fails at cap"
    );
    assert_eq!(sessions.len(), 1, "repair install refused at cap");
    assert_eq!(
        batch.session_creates, 0,
        "a failed repair install must not count a session create (created flag)"
    );
    assert_eq!(
        txn_flow_cache_entries(&binding),
        0,
        "a failed repair's sessionless decision must NOT be flow-cached"
    );

    // Below cap, the next reply re-fires the repair and installs the
    // reverse session — the self-heal property the cache gate restores.
    sessions.set_max_sessions_for_test(16);
    let meta2 = txn_meta_v4(12, 0x10, (reply.len() - 14) as u16);
    let (batch2, dbg2) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &reply,
        meta2,
    );
    assert_eq!(
        sessions.len(),
        2,
        "below cap the repair must install the reverse session"
    );
    assert_eq!(batch2.session_creates, 1);
    assert_eq!(dbg2.tx, 1, "self-healed reply forwards as well");
}


// ── #6075 (#5147 / #6074 follow-up): the poll_descriptor PRE-RESOLVE
// `neighbor_mac_epoch` SNAPSHOT site must key on the OUTER transport neighbor
// ifindex, not the logical tunnel `egress_ifindex` ──
//
// The #6074 fold routed BOTH neighbor-MAC-epoch key sites through
// `outer_neighbor_ifindex(state, None, &resolution)`:
//   (1) `flow_cache.rs` — the `neighbor_shard` STAMP on the cached entry.
//   (2) `poll_descriptor/mod.rs` — the pre-resolve `neighbor_mac_epoch`
//       SNAPSHOT (`epoch_for(&(outer_neighbor_ifindex(..), nh))`).
// The existing `tunnel_flow_cache_keys_mac_change_shard_on_outer_neighbor_not_
// logical_ifindex` (flow_cache_tests.rs) pins ONLY site (1): it calls
// `from_forward_decision` directly with an INJECTED `neighbor_mac_epoch = 0`,
// bypassing poll_descriptor entirely. Reverting ONLY site (2) to the logical
// `egress_ifindex` would NOT fail that test — the pre-resolve snapshot site is
// unbound. That desync (stamp keyed on outer, snapshot keyed on logical) causes
// spurious eviction (a perf regression, not a blackhole), and #6075 asks for an
// independent fail-on-revert test that isolates site (2).
//
// This test drives the REAL poll_descriptor path (`poll_binding_process_
// descriptor` via `txn_run_descriptor_with_neighbors`) for a native-GRE transit
// forward, with the OUTER transport neighbor's shard MAC-change epoch pre-bumped
// in the caller-owned dynamic-neighbor map BEFORE the poll takes its pre-resolve
// snapshot. It then reads the flow-cache entry the poll seeded and asserts the
// stamped `neighbor_mac_epoch` equals the OUTER neighbor shard's snapshot epoch
// (non-zero) and NOT the logical tunnel shard's epoch (zero).
//
// RED-ON-REVERT / ISOLATION: reverting site (2)'s
// `epoch_for(&(outer_neighbor_ifindex(..), nh))` to
// `epoch_for(&(decision.resolution.egress_ifindex, nh))` makes the poll snapshot
// the LOGICAL (362) shard's epoch (0) instead of the OUTER (12) shard's epoch
// (bumped), so `entry.neighbor_mac_epoch` becomes 0 and the primary assert
// fails. The assertion is on `neighbor_mac_epoch` (site 2's output), NOT
// `neighbor_shard` (site 1's output), so it fails on a site-(2)-only revert
// while the site-(1) test stays green — genuinely isolating the snapshot site.
//
// WireGuard is intentionally NOT covered here: the build ZEROES a WG endpoint's
// outer transport destination (the peer carries the hop, see
// frame/wg_tests.rs::wg_resolver_stores_zero_tx_ifindex_so_no_tx_fallback_is_
// possible), so a WG transit resolution NoRoutes at admit time and never seeds a
// ForwardCandidate flow-cache entry — the site-(2) stamp path is only reached by
// tunnels that resolve a static/dynamic outer neighbor at admit time (native
// GRE). WG shares the identical `outer_neighbor_ifindex` helper, which is
// covered at the resolution layer in frame/wg_tests.rs.
#[test]
fn poll_descriptor_stamps_neighbor_mac_epoch_from_outer_neighbor_shard_not_logical_6075() {
    use crate::afxdp::sharded_neighbor::ShardedNeighborMap;
    use crate::afxdp::types::NeighborEntry;

    // native_gre_snapshot(true): GRE tunnel endpoint 1 -> logical ifindex 362
    // (gr-0-0-0); the OUTER transport neighbor (2001:559:8585:80::1) lives on
    // reth0.80, ifindex 12. The PBR variant adds a LAN ingress (reth1.0, ifindex
    // 5) whose input filter steers 10.255.192.40/30 into sfmix.inet.0. Add an
    // explicit lan->sfmix permit so the transit forward is admitted (the fixture
    // is otherwise default-deny with no policies).
    let mut snapshot = native_gre_pbr_snapshot(true);
    snapshot.default_policy = "deny".to_string();
    snapshot.policies = vec![PolicyRuleSnapshot {
        name: "lan-sfmix".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "sfmix".to_string(),
        source_addresses: vec!["any".to_string()],
        destination_addresses: vec!["any".to_string()],
        applications: vec!["any".to_string()],
        application_terms: Vec::new(),
        action: "permit".to_string(),
        ..Default::default()
    }];
    let forwarding = build_forwarding_state(&snapshot);
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 5, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();

    // The OUTER transport next-hop the GRE outer packet resolves to (reth0.80,
    // ifindex 12). Seed the caller-owned dynamic-neighbor map and REPLACE the MAC
    // once so ONLY this outer shard's MAC-change epoch advances (a first insert
    // does not bump; a genuine MAC change does). The poll takes its pre-resolve
    // shard-epoch snapshot from THIS map, so the snapshot's outer shard is
    // non-zero while the logical (362) shard stays at the baseline 0.
    let outer_nh = IpAddr::V6("2001:559:8585:80::1".parse().unwrap());
    let outer_if = 12_i32;
    let logical_if = 362_i32;
    let neighbors = Arc::new(ShardedNeighborMap::new());
    neighbors.insert_if_changed((outer_if, outer_nh), NeighborEntry { mac: [0xaa; 6] });
    neighbors.insert_if_changed((outer_if, outer_nh), NeighborEntry { mac: [0xbb; 6] });

    let outer_epoch = neighbors.mac_change_epoch_for(&(outer_if, outer_nh));
    let logical_epoch = neighbors.mac_change_epoch_for(&(logical_if, outer_nh));
    // Preconditions: the outer bump advanced the outer shard's epoch, and the
    // outer and logical ifindexes hash to DIFFERENT shards for this next-hop
    // (else the test cannot distinguish the outer key from the logical key).
    assert_ne!(
        outer_epoch, logical_epoch,
        "test precondition: the outer-neighbor bump must advance the OUTER shard's \
         epoch above the untouched logical (362) shard's epoch"
    );
    assert_ne!(
        ShardedNeighborMap::shard_index(&(outer_if, outer_nh)),
        ShardedNeighborMap::shard_index(&(logical_if, outer_nh)),
        "test precondition: the outer (12) and logical (362) ifindexes must hash to \
         DIFFERENT shards for this next-hop"
    );

    // A cache-eligible ESTABLISHED (pure-ACK) TCP flow ingressing the LAN (ifindex
    // 5), destined into the GRE tunnel's connected /30 (10.255.192.41). PBR steers
    // it into sfmix.inet.0 -> tunnel endpoint 1 (ForwardCandidate; the outer
    // neighbor resolves from the static NeighborSnapshot), which the poll installs
    // and seeds into the flow cache.
    let frame = build_txn_tcp_syn_frame_v4(
        Ipv4Addr::new(10, 0, 61, 100),
        Ipv4Addr::new(10, 255, 192, 41),
        12345,
        443,
        0x10_u8,
    );
    let meta = txn_meta_v4(5, 0x10_u8, frame.len() as u16);
    let (_batch, dbg) = txn_run_descriptor_with_neighbors(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
        &neighbors,
    );
    assert_eq!(dbg.tx, 1, "the GRE transit forward must forward its trigger packet");
    assert_eq!(
        txn_flow_cache_entries(&binding),
        1,
        "the forwarded established tunnel flow must seed exactly one flow-cache entry"
    );

    let entry = binding
        .flow
        .flow_cache
        .entries
        .iter()
        .flatten()
        .next()
        .expect("the tunnel forward seeded a flow-cache entry");
    // The seeded entry is the tunnel forward (logical egress 362, endpoint 1),
    // resolving the outer transport next-hop.
    assert_eq!(entry.decision.resolution.tunnel_endpoint_id, 1);
    assert_eq!(entry.decision.resolution.egress_ifindex, logical_if);
    assert_eq!(entry.decision.resolution.next_hop, Some(outer_nh));

    // PRIMARY (site-2 isolation): the poll_descriptor pre-resolve snapshot stamped
    // the OUTER neighbor shard's epoch, NOT the logical tunnel shard's epoch.
    // Reverting site (2) to `decision.resolution.egress_ifindex` snapshots the
    // logical (362) shard (epoch 0) and this assert fails — independently of the
    // `neighbor_shard` STAMP (site 1), which this does not touch.
    assert_eq!(
        entry.neighbor_mac_epoch, outer_epoch,
        "the poll_descriptor pre-resolve snapshot MUST stamp the OUTER transport \
         neighbor's shard epoch (ifindex {outer_if}); keying the snapshot on the \
         logical tunnel egress ifindex (362) stamps the wrong shard's epoch and \
         spuriously evicts the tunnel flow on every hit (#6075 / #5147 site 2)"
    );
    assert_ne!(
        entry.neighbor_mac_epoch, logical_epoch,
        "the stamped epoch must NOT be the logical tunnel shard's (362) epoch"
    );

    // BEHAVIORAL: because the stamped epoch matches the live OUTER shard epoch,
    // the freshly-seeded entry is NOT spuriously MAC-stale. Reverting site (2)
    // stamps the logical epoch (0) while `neighbor_shard` (site 1) still reads the
    // live OUTER shard epoch (non-zero) -> a spurious eviction on the next hit.
    assert!(
        !entry.neighbor_mac_epoch_stale(&neighbors),
        "a tunnel flow seeded from the correct OUTER-neighbor snapshot must not be \
         spuriously stale against the same map"
    );
}


// I6: a MissingNeighborSeed install refused at cap must NOT buffer the
// frame for neighbor-resolution replay (the replay would forward on the
// rolled-back SNAT tuple with no session). Below cap the seed installs
// and the frame buffers as before.
#[test]
fn txn_refused_seed_recycles_instead_of_buffering() {
    let mut snapshot = nat_snapshot();
    // Remove the gateway neighbor: 8.8.8.8 routes via 172.16.80.1 whose
    // MAC is now unknown -> MissingNeighbor seed path.
    snapshot.neighbors.clear();
    let forwarding = build_forwarding_state(&snapshot);
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();
    sessions.set_max_sessions_for_test(0);

    let frame = build_txn_tcp_syn_frame_v4(
        Ipv4Addr::new(10, 0, 61, 102),
        Ipv4Addr::new(8, 8, 8, 8),
        12345,
        443,
        TCP_FLAG_SYN,
    );
    let meta = txn_meta_v4(24, TCP_FLAG_SYN, frame.len() as u16);
    txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
    );
    assert_eq!(sessions.len(), 0, "seed install refused at cap");
    assert!(
        binding.pending_neigh.is_empty(),
        "a refused seed's frame must be recycled, not buffered for replay"
    );

    // Below cap: the seed installs and the representative frame buffers.
    sessions.set_max_sessions_for_test(16);
    let meta2 = txn_meta_v4(24, TCP_FLAG_SYN, frame.len() as u16);
    txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta2,
    );
    assert_eq!(sessions.len(), 1, "seed installs below cap");
    assert_eq!(
        binding.pending_neigh.len(),
        1,
        "below cap the representative frame buffers as before"
    );
}

/// #6432 recycle-exactly-once pin for the MissingNeighbor arm — the pilot
/// conversion of the arm's five hand-maintained
/// `scratch_recycle.push + continue` pairs onto the
/// `poll_stages::StageOutcome` ownership enum (one outcome per terminal
/// path, one push + continue at the consumer). Every terminal path of the
/// arm must account for the trigger frame EXACTLY ONCE: a leak (never
/// recycled, never buffered) strands the UMEM frame forever, and a
/// double-push hands the same addr back to the fill ring twice (UMEM
/// aliasing — the #2208/#4041 class). Invariant pin: it also passes on
/// the pre-refactor code — the refactor must leave it green.
#[test]
fn missing_neighbor_recycle_exactly_once_pin() {
    // txn_run_descriptor* parks the frame at this UMEM offset, so the
    // descriptor addr is known.
    let frame_offset = 128u64;

    // ── Phase 1: permitted + unresolved → the arm BUFFERS the frame
    // (Continue outcome, recycle_now = false). scratch_recycle stays
    // empty; pending_neigh takes ownership of the addr exactly once.
    let mut snapshot = nat_snapshot();
    snapshot.neighbors.clear();
    let forwarding = build_forwarding_state(&snapshot);
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();

    let frame = build_txn_tcp_syn_frame_v4(
        Ipv4Addr::new(10, 0, 61, 102),
        Ipv4Addr::new(8, 8, 8, 8),
        12345,
        443,
        TCP_FLAG_SYN,
    );
    let meta = txn_meta_v4(24, TCP_FLAG_SYN, frame.len() as u16);
    let (_batch, dbg) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
    );
    assert!(
        dbg.missing_neigh >= 1,
        "phase 1 must take the MissingNeighbor arm"
    );
    assert_eq!(sessions.len(), 1, "permitted flow seeds a session");
    assert!(
        binding.scratch.scratch_recycle.is_empty(),
        "a buffered frame must NOT also be recycled (double-push once the \
         fill ring hands the addr out again)"
    );
    assert_eq!(binding.pending_neigh.len(), 1);
    assert_eq!(
        binding.pending_neigh.values().next().unwrap().addr,
        frame_offset,
        "pending_neigh owns the trigger frame's addr exactly once"
    );

    // ── Phase 2: a NEW flow (different 5-tuple) to the SAME unresolved
    // next-hop is a duplicate-hop drop (Continue outcome, recycle_now
    // stays true): the seed installs, but the frame is NOT buffered and
    // the finalizer recycles it EXACTLY ONCE.
    let frame2 = build_txn_tcp_syn_frame_v4(
        Ipv4Addr::new(10, 0, 61, 102),
        Ipv4Addr::new(8, 8, 8, 8),
        12346,
        444,
        TCP_FLAG_SYN,
    );
    let meta2 = txn_meta_v4(24, TCP_FLAG_SYN, (frame2.len() - 14) as u16);
    let (_batch2, dbg2) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame2,
        meta2,
    );
    assert!(
        dbg2.missing_neigh >= 1,
        "phase 2 must re-enter the MissingNeighbor arm"
    );
    assert_eq!(binding.pending_neigh.len(), 1, "buffer holds only the first hop representative");
    assert_eq!(
        binding
            .scratch
            .scratch_recycle
            .iter()
            .filter(|&&a| a == frame_offset)
            .count(),
        1,
        "duplicate-hop frame recycled exactly once (no leak, no double-push)"
    );

    // ── Phase 3: policy-DENY inside the arm → the RecycleAndContinue
    // outcome; the frame is recycled EXACTLY ONCE by the single consumer,
    // nothing seeds, nothing buffers.
    let mut deny_snapshot = nat_snapshot();
    deny_snapshot.neighbors.clear();
    deny_snapshot.policies.clear(); // default_policy = deny
    let deny_forwarding = build_forwarding_state(&deny_snapshot);
    let mut deny_binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    deny_binding.interface = Arc::<str>::from("reth1.0");
    let mut deny_sessions = SessionTable::new();
    let meta3 = txn_meta_v4(24, TCP_FLAG_SYN, frame.len() as u16);
    let (_batch3, dbg3) = txn_run_descriptor(
        &mut deny_binding,
        &mut deny_sessions,
        &deny_forwarding,
        &ha_state,
        &frame,
        meta3,
    );
    assert!(
        dbg3.missing_neigh >= 1,
        "phase 3 must take the MissingNeighbor arm"
    );
    assert!(
        dbg3.policy_deny >= 1,
        "default-deny must fire in the arm's #1913 policy gate"
    );
    assert_eq!(
        deny_binding
            .scratch
            .scratch_recycle
            .iter()
            .filter(|&&a| a == frame_offset)
            .count(),
        1,
        "denied frame recycled exactly once via the arm's single outcome consumer"
    );
    assert!(
        deny_binding.pending_neigh.is_empty(),
        "a denied flow never buffers"
    );
    assert_eq!(deny_sessions.len(), 0, "a denied flow seeds no session");
}

