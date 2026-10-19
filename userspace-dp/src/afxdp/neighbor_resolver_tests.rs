use super::*;
use std::sync::atomic::Ordering;

const NUD_INCOMPLETE: u16 = 0x01;
const NUD_REACHABLE: u16 = 0x02;
const NUD_STALE: u16 = 0x04;
const NUD_DELAY: u16 = 0x08;
const NUD_PROBE: u16 = 0x10;
const NUD_FAILED: u16 = 0x20;
const NUD_PERMANENT: u16 = 0x80;

fn mac() -> [u8; 6] {
    [0xea, 0xde, 0x15, 0xf5, 0x66, 0x70]
}

#[test]
fn classify_reachable_and_permanent_are_confirmed() {
    assert_eq!(
        classify_nud(NUD_REACHABLE, Some(mac())),
        GetOutcome::Confirmed(mac())
    );
    assert_eq!(
        classify_nud(NUD_PERMANENT, Some(mac())),
        GetOutcome::Confirmed(mac())
    );
}

#[test]
fn classify_stale_delay_probe_are_unconfirmed_with_mac() {
    // This is the LIVE #1769 bug state: kernel HAS the lladdr in
    // DELAY/STALE but we must probe, not cache.
    for st in [NUD_STALE, NUD_DELAY, NUD_PROBE] {
        assert_eq!(
            classify_nud(st, Some(mac())),
            GetOutcome::Unconfirmed,
            "state {st:#x} with a MAC must be Unconfirmed (probe, do not cache)",
        );
    }
}

#[test]
fn classify_failed_incomplete_are_failed_others_no_reply() {
    // Kernel authoritatively dead → Failed (revoke).
    assert_eq!(classify_nud(NUD_FAILED, Some(mac())), GetOutcome::Failed);
    assert_eq!(
        classify_nud(NUD_INCOMPLETE, Some(mac())),
        GetOutcome::Failed
    );
    assert_eq!(classify_nud(NUD_FAILED, None), GetOutcome::Failed);
    // REACHABLE/STALE but no lladdr → not an authoritative FAILED, so
    // NoReply (probe, do NOT revoke a possibly-good entry — Copilot).
    assert_eq!(classify_nud(NUD_REACHABLE, None), GetOutcome::NoReply);
    assert_eq!(classify_nud(NUD_STALE, None), GetOutcome::NoReply);
}

/// Build a synthetic RTM_NEWNEIGH body (the bytes after the 16-byte
/// nlmsghdr) for `(ifindex, ip)` with `state` and an optional MAC, so
/// the parser + classifier can be tested without a real socket.
fn neigh_body(ifindex: i32, ip: IpAddr, state: u16, mac: Option<[u8; 6]>) -> Vec<u8> {
    let (family, ip_bytes): (u8, Vec<u8>) = match ip {
        IpAddr::V4(v4) => (libc::AF_INET as u8, v4.octets().to_vec()),
        IpAddr::V6(v6) => (libc::AF_INET6 as u8, v6.octets().to_vec()),
    };
    let mut body = vec![0u8; 12];
    body[0] = family;
    body[4..8].copy_from_slice(&ifindex.to_ne_bytes());
    body[8..10].copy_from_slice(&state.to_ne_bytes());
    // NDA_DST
    let ip_attr_len = 4 + ip_bytes.len();
    body.extend_from_slice(&(ip_attr_len as u16).to_ne_bytes());
    body.extend_from_slice(&1u16.to_ne_bytes());
    body.extend_from_slice(&ip_bytes);
    while body.len() % 4 != 0 {
        body.push(0);
    }
    if let Some(m) = mac {
        body.extend_from_slice(&10u16.to_ne_bytes());
        body.extend_from_slice(&2u16.to_ne_bytes());
        body.extend_from_slice(&m);
        while body.len() % 4 != 0 {
            body.push(0);
        }
    }
    body
}

#[test]
fn parse_get_reply_matches_key_and_classifies() {
    let ip = IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200));
    let body = neigh_body(14, ip, NUD_DELAY, Some(mac()));
    // Correct key → Unconfirmed (DELAY+MAC).
    assert_eq!(
        parse_get_reply_body(&body, 14, ip),
        Some(GetOutcome::Unconfirmed)
    );
    // Wrong ifindex → no match (keep scanning).
    assert_eq!(parse_get_reply_body(&body, 99, ip), None);
    // Wrong IP → no match.
    let other = IpAddr::V4(Ipv4Addr::new(172, 16, 80, 201));
    assert_eq!(parse_get_reply_body(&body, 14, other), None);
}

#[test]
fn parse_get_reply_reachable_is_confirmed() {
    let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 61, 5));
    let body = neigh_body(8, ip, NUD_REACHABLE, Some(mac()));
    assert_eq!(
        parse_get_reply_body(&body, 8, ip),
        Some(GetOutcome::Confirmed(mac()))
    );
}

#[test]
fn resolver_counters_default_zero() {
    let c = ResolverCounters::default();
    assert_eq!(c.queue_depth.load(Ordering::Relaxed), 0);
    assert_eq!(c.enqueue_drops.load(Ordering::Relaxed), 0);
    assert_eq!(c.get_attempts.load(Ordering::Relaxed), 0);
}

#[test]
fn enqueue_full_queue_counts_drop_not_block() {
    // Depth-1 queue: the second enqueue (without a consumer) must
    // count an enqueue_drop and NOT block.
    let (tx, _rx) = mpsc::sync_channel::<ResolveItem>(1);
    let counters = Arc::new(ResolverCounters::default());
    let resolver = NeighborResolver::new(
        tx,
        counters.clone(),
        Arc::new(AtomicU64::new(0)),
        Arc::new(super::super::neighbor_latency::NeighborLatencyHist::default()),
        Arc::new(AtomicU64::new(0)),
        Arc::new(AtomicU64::new(0)),
    );
    let hop = IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200));
    resolver.enqueue(14, hop, "ge-0-0-2.80".to_string());
    resolver.enqueue(14, hop, "ge-0-0-2.80".to_string());
    assert_eq!(counters.queue_depth.load(Ordering::Relaxed), 1);
    assert_eq!(counters.enqueue_drops.load(Ordering::Relaxed), 1);
}

#[test]
fn enqueue_snapshots_current_epoch() {
    // The enqueued item must carry the global neighbor epoch at
    // enqueue time so the resolver's epoch guard can detect a later
    // monitor event.
    let (tx, rx) = mpsc::sync_channel::<ResolveItem>(1);
    let counters = Arc::new(ResolverCounters::default());
    let epoch_gen = Arc::new(AtomicU64::new(7));
    let resolver = NeighborResolver::new(
        tx,
        counters,
        epoch_gen.clone(),
        Arc::new(super::super::neighbor_latency::NeighborLatencyHist::default()),
        Arc::new(AtomicU64::new(0)),
        Arc::new(AtomicU64::new(0)),
    );
    epoch_gen.store(42, Ordering::Release);
    resolver.enqueue(
        14,
        IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        "ge-0-0-2.80".to_string(),
    );
    let item = rx.try_recv().expect("item enqueued");
    assert_eq!(item.epoch, 42, "enqueue must snapshot the current epoch");
}

#[test]
fn enqueue_disconnected_counts_disconnected() {
    let (tx, rx) = mpsc::sync_channel::<ResolveItem>(1);
    let counters = Arc::new(ResolverCounters::default());
    let resolver = NeighborResolver::new(
        tx,
        counters.clone(),
        Arc::new(AtomicU64::new(0)),
        Arc::new(super::super::neighbor_latency::NeighborLatencyHist::default()),
        Arc::new(AtomicU64::new(0)),
        Arc::new(AtomicU64::new(0)),
    );
    drop(rx);
    resolver.enqueue(
        14,
        IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        "ge-0-0-2.80".to_string(),
    );
    assert_eq!(counters.disconnected.load(Ordering::Relaxed), 1);
    assert_eq!(counters.queue_depth.load(Ordering::Relaxed), 0);
}

// ---- decide_action: outcome → action mapping + epoch guard ----

#[test]
fn decide_confirmed_same_epoch_caches() {
    assert_eq!(
        decide_action(GetOutcome::Confirmed(mac()), 5, 5),
        ResolveAction::Cache(mac()),
    );
}

/// AGY F1 out-of-order race: a confirmed GET reply that arrives after
/// a concurrent monitor event (epoch advanced) must NOT be cached —
/// it could resurrect a MAC the monitor just removed via DELNEIGH.
#[test]
fn decide_confirmed_advanced_epoch_rejects() {
    assert_eq!(
        decide_action(GetOutcome::Confirmed(mac()), 5, 6),
        ResolveAction::EpochReject,
        "a confirmed insert racing a newer monitor event must be rejected",
    );
}

#[test]
fn decide_unconfirmed_probes_regardless_of_epoch() {
    // DELAY/STALE → probe, epoch-independent (never writes a MAC).
    assert_eq!(
        decide_action(GetOutcome::Unconfirmed, 5, 5),
        ResolveAction::ProbeOnStale,
    );
    assert_eq!(
        decide_action(GetOutcome::Unconfirmed, 5, 9),
        ResolveAction::ProbeOnStale,
    );
}

#[test]
fn decide_failed_revokes_but_no_reply_only_probes() {
    // Authoritative kernel FAILED → revoke + probe.
    assert_eq!(
        decide_action(GetOutcome::Failed, 5, 5),
        ResolveAction::RevokeAndProbe,
    );
    // No authoritative answer → probe ONLY, never revoke (a transient
    // GET loss must not evict a still-good entry — Copilot).
    assert_eq!(
        decide_action(GetOutcome::NoReply, 5, 5),
        ResolveAction::ProbeOnly,
    );
    assert_eq!(
        decide_action(GetOutcome::NoReply, 5, 9),
        ResolveAction::ProbeOnly,
    );
}

/// AUTHORITATIVE in-lock epoch gate (the Codex F1 fix). Reconstructs
/// the exact counterexample Codex raised: a confirmed GET reply whose
/// pre-GET epoch snapshot is stale because a monitor event (which
/// bumps the generation under bump-first ordering) has since landed.
/// `insert_confirmed_if_unchanged` must reject the insert even though
/// the lock-free `decide_action(epoch_before, epoch_after)` fast-path
/// would have been bypassed (simulating the bump landing AFTER the
/// post-GET `epoch_after` load but the in-lock re-read catching it).
#[test]
fn in_lock_epoch_gate_rejects_stale_insert() {
    let map = ShardedNeighborMap::new();
    let epoch_gen = AtomicU64::new(5);
    let key = (14, IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)));
    // Resolver snapshotted epoch_before = 5 before its GET.
    let epoch_before = 5u64;
    // A monitor DELNEIGH batch lands: bump-first advances the gen,
    // then it removes the key (here: key already absent — the exact
    // case the old `if changed` post-bump MISSED, but bump-first now
    // always advances).
    epoch_gen.fetch_add(1, Ordering::Release); // now 6
    map.remove(&key);
    // The late confirmed insert must be rejected by the in-lock gate.
    let stale = mac();
    let inserted = map.insert_confirmed_if_unchanged(
        key,
        NeighborEntry { mac: stale },
        &epoch_gen,
        epoch_before,
    );
    assert!(
        !inserted,
        "stale insert under advanced epoch must be rejected"
    );
    assert!(
        map.get(&key).is_none(),
        "the removed key must NOT be resurrected by a late stale GET",
    );
}

/// The happy path of the in-lock gate: no monitor event raced in
/// (generation unchanged since the snapshot), so the confirmed insert
/// is applied.
#[test]
fn in_lock_epoch_gate_accepts_unchanged() {
    let map = ShardedNeighborMap::new();
    let epoch_gen = AtomicU64::new(5);
    let key = (14, IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)));
    let m = mac();
    let inserted = map.insert_confirmed_if_unchanged(key, NeighborEntry { mac: m }, &epoch_gen, 5);
    assert!(inserted, "unchanged-epoch confirmed insert must apply");
    assert_eq!(map.get(&key).map(|e| e.mac), Some(m));
}

/// The epoch-guard race end-to-end on the real ShardedNeighborMap: a
/// newer good entry is present; a late confirmed GET reply (issued
/// under an older epoch) must NOT overwrite it once the epoch has
/// advanced. Applying the rejected action leaves the newer entry
/// intact.
#[test]
fn epoch_guard_does_not_overwrite_newer_good_entry() {
    let map = ShardedNeighborMap::new();
    let key = (14, IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)));
    let newer = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
    // Monitor installed a NEWER good entry (and bumped the epoch).
    map.insert(key, NeighborEntry { mac: newer });
    // A late confirmed GET reply derived from a STALE-era read tries
    // to write a DIFFERENT (older) MAC, but it was issued under an
    // older epoch (epoch_before=5) and the epoch has since advanced
    // (epoch_after=6).
    let action = decide_action(GetOutcome::Confirmed(mac()), 5, 6);
    assert_eq!(action, ResolveAction::EpochReject);
    // Apply only the non-rejected actions; EpochReject is a no-op on
    // the map. The newer entry must survive.
    if let ResolveAction::Cache(m) = action {
        map.insert(key, NeighborEntry { mac: m });
    }
    assert_eq!(
        map.get(&key).map(|e| e.mac),
        Some(newer),
        "epoch-rejected stale insert must not overwrite the newer good MAC",
    );
}

// ---- rate_limit_decide: no probe storm ----

#[test]
fn rate_limit_admits_first_then_coalesces_within_window() {
    let mut last: FastMap<(i32, IpAddr), u64> = FastMap::default();
    let key = (14, IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)));
    // First miss at t=0 → admit (one GET fires).
    assert_eq!(
        rate_limit_decide(&mut last, key, 0),
        RateLimitDecision::AdmitFirst
    );
    // 50 storm misses within the 1s window → all coalesced (no GET).
    for t in (1..=50).map(|i| i * 10_000_000u64) {
        assert_eq!(
            rate_limit_decide(&mut last, key, t),
            RateLimitDecision::Coalesce,
            "within-window repeat must be coalesced (no probe storm)",
        );
    }
    // After the window lapses → admit again (one fresh GET), now as
    // a backoff RETRY for the still-unresolved key.
    assert_eq!(
        rate_limit_decide(&mut last, key, RESOLVER_PER_KEY_RATE_LIMIT_NS + 1),
        RateLimitDecision::AdmitRetry
    );
}

/// #1771 §2.6: the decision split must classify the SAME admissions
/// the boolean helper grants — first attempt vs backoff retry — so
/// `resolver_get_backoff_attempts` counts exactly the re-admitted
/// keys (subset of `get_attempts`).
#[test]
fn rate_limit_decide_classifies_first_retry_coalesce() {
    let mut last: FastMap<(i32, IpAddr), u64> = FastMap::default();
    let key = (14, IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)));
    // First attempt for an unseen key.
    assert_eq!(
        rate_limit_decide(&mut last, key, 0),
        RateLimitDecision::AdmitFirst
    );
    // Within the window → coalesced, and the recorded timestamp is
    // NOT refreshed (the retry clock keeps running from t=0).
    assert_eq!(
        rate_limit_decide(&mut last, key, 10),
        RateLimitDecision::Coalesce
    );
    assert_eq!(last.get(&key), Some(&0));
    // Past the window → a backoff RETRY (counted), timestamp moves.
    let t_retry = RESOLVER_PER_KEY_RATE_LIMIT_NS + 1;
    assert_eq!(
        rate_limit_decide(&mut last, key, t_retry),
        RateLimitDecision::AdmitRetry
    );
    assert_eq!(last.get(&key), Some(&t_retry));
    // A different key is still a FIRST attempt.
    let other = (14, IpAddr::V4(Ipv4Addr::new(172, 16, 80, 201)));
    assert_eq!(
        rate_limit_decide(&mut last, other, t_retry),
        RateLimitDecision::AdmitFirst
    );
}

#[test]
fn rate_limit_is_per_key() {
    let mut last: FastMap<(i32, IpAddr), u64> = FastMap::default();
    let k1 = (14, IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)));
    let k2 = (14, IpAddr::V4(Ipv4Addr::new(172, 16, 80, 201)));
    assert_eq!(
        rate_limit_decide(&mut last, k1, 0),
        RateLimitDecision::AdmitFirst
    );
    // A different key in the same instant is independently admitted.
    assert_eq!(
        rate_limit_decide(&mut last, k2, 0),
        RateLimitDecision::AdmitFirst
    );
    // ...but the first key is still coalesced.
    assert_eq!(
        rate_limit_decide(&mut last, k1, 1),
        RateLimitDecision::Coalesce
    );
}

// ---- differential repro: the #1769 stuck state is now resolvable ----

/// Reconstructs the stuck state and proves the fix resolves it.
///
/// 1. The dst's `(egress_ifindex, next_hop)` is negatively cached
///    (the `retry_pending_neigh` timeout armed a 3 s entry) AND its
///    dynamic entry is gone (transient FAILED/DELNEIGH or a dropped
///    good RTM_NEWNEIGH). With the OLD code the negative gate would
///    fast-fail every new SYN with nothing nudging resolution → 3 s
///    blackout cycles.
/// 2. The gate still fast-fails (dead-host storm defense preserved),
///    but now routes the dst through the resolver.
/// 3. The resolver's single-key GET returns the kernel's CONFIRMED
///    lladdr (REACHABLE); under an unchanged epoch the action caches
///    it into `dynamic_neighbors`.
/// 4. The next SYN's resolved-wins check now finds the dynamic entry,
///    so `neg_neigh_gate` evicts the negative entry and proceeds —
///    the flow forwards instead of blackholing.
#[test]
fn stuck_state_is_resolved_via_get_instead_of_blackholing() {
    use crate::afxdp::neg_neigh::{NegNeighCache, neg_neigh_gate, neg_neigh_record};

    let egress_ifindex = 14i32;
    let next_hop = IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200));
    let key = (egress_ifindex, next_hop);

    // Per-binding negative cache + the shared dynamic map.
    let mut neg = NegNeighCache::default();
    let dynamic = ShardedNeighborMap::new();

    // (1) Arm the stuck state: negative entry recorded at t=1s, no
    //     dynamic entry for the dst.
    neg_neigh_record(&mut neg, key, 1_000_000_000);
    assert!(
        dynamic.get(&key).is_none(),
        "precondition: dst has no dynamic entry"
    );

    // (2) A new SYN at t=1.5s: the gate fast-fails (still within the
    //     3 s TTL, still unresolved). is_resolved checks the dynamic
    //     map (the production closure also checks static neighbors).
    let resolved_check = |dynamic: &ShardedNeighborMap| dynamic.get(&key).is_some();
    assert!(
        neg_neigh_gate(&mut neg, &key, 1_500_000_000, || resolved_check(&dynamic)),
        "stuck dst must still fast-fail (dead-host storm defense preserved)",
    );

    // (3) The resolver's single-key GET returns the kernel's
    //     CONFIRMED lladdr (the kernel HAD it the whole time — the
    //     dataplane just lacked it). Epoch unchanged → cache it. This
    //     is exactly what neighbor_resolver_loop does on a
    //     GetOutcome::Confirmed.
    let kernel_mac = mac();
    let action = decide_action(GetOutcome::Confirmed(kernel_mac), 0, 0);
    assert_eq!(action, ResolveAction::Cache(kernel_mac));
    if let ResolveAction::Cache(m) = action {
        dynamic.insert(key, NeighborEntry { mac: m });
    }

    // (4) The NEXT SYN at t=1.6s: resolved-wins now finds the dynamic
    //     entry, so the gate evicts the negative entry and PROCEEDS
    //     (returns false) — the flow forwards instead of blackholing
    //     for the rest of the 3 s window.
    assert!(
        !neg_neigh_gate(&mut neg, &key, 1_600_000_000, || resolved_check(&dynamic)),
        "after the resolver cached the kernel lladdr, a new flow must \
             resolve and proceed (NOT blackhole for 3s)",
    );
    // The negative entry was evicted by resolved-wins.
    assert!(
        !neg_neigh_gate(&mut neg, &key, 1_700_000_000, || resolved_check(&dynamic)),
        "the negative entry must be gone after resolution",
    );
}

/// The DELAY/STALE variant of the wedge: the kernel has the lladdr
/// but only in DELAY (the EXACT live #1769 signature). The resolver
/// must NOT cache the unconfirmed MAC; it probes to force kernel
/// revalidation. The dst stays unresolved until the confirmed
/// RTM_NEWNEIGH arrives — never forwarding to an unconfirmed MAC.
#[test]
fn delay_state_probes_does_not_cache_unconfirmed_mac() {
    let dynamic = ShardedNeighborMap::new();
    let key = (14, IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)));
    // GET reply says DELAY+MAC → Unconfirmed → ProbeOnStale.
    let action = decide_action(GetOutcome::Unconfirmed, 0, 0);
    assert_eq!(action, ResolveAction::ProbeOnStale);
    // The resolver fires a probe but writes nothing to the map.
    assert!(
        dynamic.get(&key).is_none(),
        "DELAY/STALE lladdr must NOT be cached (forward only on confirmed)",
    );
}

// ---- §2.4 invariant N1: negative cache does not stop resolution ----

/// Invariant N1 (#1771 §2.4): while a key is negatively cached
/// (`neg_neigh_gate` true), the resolver continues to issue
/// GET/backoff probes for that key; only *duplicate buffered packets*
/// are dropped, not resolution.
///
/// Both halves are pinned, the resolution half against the REAL
/// resolver thread (live `neighbor_resolver_loop` on a real netlink
/// socket — no socket seam exists, and a mock would not prove the
/// loop fires):
/// - resolution half: the key is enqueued twice across the per-key
///   backoff window; `get_attempts` increments BOTH times (the second
///   counted as a backoff retry) while `neg_neigh_gate` fast-fails
///   packets for the key the whole time. The window-vs-TTL overlap
///   this depends on is also pinned at compile time
///   (`NEG_NEIGH_TTL_NS > RESOLVER_PER_KEY_RATE_LIMIT_NS`).
/// - buffering half: the production admission decision
///   (`pending_neigh_admission`, the exact helper `poll_descriptor`
///   calls) admits ONE buffered packet per key and drops siblings.
///
/// The key targets a nonexistent ifindex so the kernel answers the
/// GET promptly (no entry → NoReply → probe-only) and the ARP-probe
/// helper no-ops without CAP_NET_RAW — the asserted effect is the
/// counter movement, mirroring `warmer_tests`.
#[test]
fn invariant_n1_negative_cache_does_not_stop_resolution() {
    use crate::afxdp::neg_neigh::{NegNeighCache, neg_neigh_gate, neg_neigh_record};
    use crate::afxdp::neighbor_dispatch::{PendingNeighAdmission, pending_neigh_admission};
    use std::sync::atomic::AtomicBool;
    use std::time::Duration;

    // Codex review on PR #1833: the resolver thread exits silently
    // when its netlink socket cannot be opened (sandboxes deny
    // AF_NETLINK), which would turn this test into a timeout
    // failure. Probe availability and skip gracefully — the
    // invariant itself is environment-independent; only this
    // live-thread harness needs the socket.
    let probe_fd = open_resolver_socket();
    if probe_fd < 0 {
        eprintln!(
            "skipping invariant_n1: AF_NETLINK/NETLINK_ROUTE unavailable in this environment"
        );
        return;
    }
    unsafe { libc::close(probe_fd) };

    fn wait_for<F: Fn() -> bool>(pred: F) -> bool {
        for _ in 0..400 {
            if pred() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        false
    }

    let ifindex = 999i32;
    let hop = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 77));
    let key = (ifindex, hop);

    // Arm the negative cache for K with REAL monotonic time (the
    // resolver thread runs on the same clock).
    let mut neg = NegNeighCache::default();
    neg_neigh_record(&mut neg, key, monotonic_nanos());
    assert!(
        neg_neigh_gate(&mut neg, &key, monotonic_nanos(), || false),
        "precondition: K negatively cached → duplicate packets fast-fail",
    );

    // Buffering half: pending_neigh admits AT MOST ONE packet for K.
    assert_eq!(
        pending_neigh_admission(false, 0, crate::afxdp::MAX_PENDING_NEIGH),
        PendingNeighAdmission::Buffer,
        "the first packet for K is buffered (the per-key representative)",
    );
    assert_eq!(
        pending_neigh_admission(true, 1, crate::afxdp::MAX_PENDING_NEIGH),
        PendingNeighAdmission::DuplicateDrop,
        "a sibling for the already-pending K is dropped, not buffered",
    );

    // Resolution half: live resolver thread on a real netlink socket.
    let (tx, rx) = mpsc::sync_channel::<ResolveItem>(8);
    let counters = Arc::new(ResolverCounters::default());
    let dynamic = Arc::new(ShardedNeighborMap::new());
    let generation = Arc::new(AtomicU64::new(1));
    let get_rtt_hist = Arc::new(super::super::neighbor_latency::NeighborLatencyHist::default());
    let stop = Arc::new(AtomicBool::new(false));
    let handle = {
        let (d, g, c, h, s) = (
            dynamic.clone(),
            generation.clone(),
            counters.clone(),
            get_rtt_hist.clone(),
            stop.clone(),
        );
        std::thread::spawn(move || neighbor_resolver_loop(rx, d, g, c, h, s))
    };
    let resolver = NeighborResolver::new(
        tx,
        counters.clone(),
        generation,
        Arc::new(super::super::neighbor_latency::NeighborLatencyHist::default()),
        Arc::new(AtomicU64::new(0)),
        Arc::new(AtomicU64::new(0)),
    );

    // First fast-fail routes K through the resolver: one GET fires
    // WHILE K is negatively cached.
    resolver.enqueue(ifindex, hop, "xpf-n1-nodev".to_string());
    assert!(
        wait_for(|| counters.get_attempts.load(Ordering::Relaxed) == 1),
        "first GET must fire while K is negatively cached",
    );

    // Advance the backoff clock past the per-key window. Refresh the
    // negative entry first so a slow scheduler cannot expire the 3 s
    // TTL under the test (production re-records on every timeout
    // drop, so a refresh is semantics-preserving); then verify the
    // gate is STILL fast-failing when the retry GET is admitted.
    neg_neigh_record(&mut neg, key, monotonic_nanos());
    std::thread::sleep(Duration::from_nanos(
        RESOLVER_PER_KEY_RATE_LIMIT_NS + 100_000_000,
    ));
    assert!(
        neg_neigh_gate(&mut neg, &key, monotonic_nanos(), || dynamic
            .get(&key)
            .is_some()),
        "K must still be negatively cached when the backoff GET fires",
    );
    resolver.enqueue(ifindex, hop, "xpf-n1-nodev".to_string());
    assert!(
        wait_for(|| counters.get_attempts.load(Ordering::Relaxed) == 2),
        "the backoff GET must fire for the still-negatively-cached K",
    );
    assert_eq!(
        counters.get_backoff_attempts.load(Ordering::Relaxed),
        1,
        "the second GET is a counted backoff RETRY (§2.6 counter ties to N1)",
    );
    // Resolution continued the whole time the gate was dropping
    // duplicates — the invariant. (The dst is genuinely unresolvable
    // here, so the gate stays armed.)
    assert!(
        neg_neigh_gate(&mut neg, &key, monotonic_nanos(), || dynamic
            .get(&key)
            .is_some()),
        "K still negatively cached after both GETs — duplicates were \
             dropped, resolution was not",
    );

    stop.store(true, Ordering::Relaxed);
    drop(resolver); // drops the producer → recv disconnects promptly
    handle.join().expect("resolver join");
}

// #1912: the MissingNeighbor arm enqueues the resolver keyed by
// outer_neighbor_ifindex(...) for a tunnel-marked decision. Pin that
// keying contract: the ResolveItem the arm enqueues for a GRE tunnel
// resolution must carry the OUTER L3 egress ifindex (the VLAN subif
// where the outer neighbor lives), NOT the tunnel logical ifindex.
// Drives the same enqueue(neigh_if, hop, name) call the arm makes.
#[test]
fn tunnel_marked_resolver_enqueue_keys_outer_l3_egress() {
    use crate::afxdp::forwarding::{outer_neighbor_ifindex, resolve_tunnel_forwarding_resolution};
    use crate::afxdp::forwarding_build::build_forwarding_state;
    use crate::afxdp::test_fixtures::native_gre_snapshot;

    let state = build_forwarding_state(&native_gre_snapshot(false));
    let resolution = resolve_tunnel_forwarding_resolution(&state, None, 1, 0);
    assert_eq!(resolution.egress_ifindex, 362, "tunnel logical ifindex");
    let next_hop = resolution.next_hop.expect("outer next hop");

    // The arm computes neigh_if exactly this way before enqueueing.
    let neigh_if = outer_neighbor_ifindex(&state, None, &resolution);
    assert_eq!(neigh_if, 12, "outer L3 egress (reth0.80 subif)");

    let (tx, rx) = mpsc::sync_channel::<ResolveItem>(1);
    let counters = Arc::new(ResolverCounters::default());
    let resolver = NeighborResolver::new(
        tx,
        counters,
        Arc::new(AtomicU64::new(0)),
        Arc::new(super::super::neighbor_latency::NeighborLatencyHist::default()),
        Arc::new(AtomicU64::new(0)),
        Arc::new(AtomicU64::new(0)),
    );
    let name = state
        .ifindex_to_name
        .get(&neigh_if)
        .cloned()
        .expect("outer egress has a name");
    resolver.enqueue(neigh_if, next_hop, name);

    let item = rx.try_recv().expect("item enqueued");
    assert_eq!(
        item.ifindex, 12,
        "resolver must be keyed on the outer L3 egress, not the tunnel logical (362)"
    );
    assert_eq!(item.hop, next_hop);
}
