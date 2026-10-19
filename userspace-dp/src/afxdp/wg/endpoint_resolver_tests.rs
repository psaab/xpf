//! #7158, #13666 and #15101 endpoint-resolver tests.
//!
//! Existing resolution fixtures use IP literals or syntactically invalid
//! targets, so they do not depend on DNS, `/etc/hosts`, or external network.
//! The injected lookup tests exercise concurrency and worker failure without
//! invoking a real resolver.

use super::*;

const PK_A: [u8; 32] = [0xAA; 32];
const PK_B: [u8; 32] = [0xBB; 32];

/// A target `to_socket_addrs` rejects immediately, with no network involved.
const UNRESOLVABLE: &str = "this-target-has-no-port";

fn shared() -> ResolverShared {
    ResolverShared {
        resolved: Mutex::new(HashMap::new()),
        telemetry: std::sync::Arc::new(WgEndpointResolverTelemetry::default()),
        stop: AtomicBool::new(false),
    }
}

/// #7158 acceptance 4: a failed lookup must retain the last-good address and
/// leave the session alone.
///
/// The policy this pins is not obvious and is the one a future reader is most
/// likely to "simplify": clearing the entry on failure looks like correct
/// cache hygiene. It would tear down a working tunnel because a DNS server
/// blinked, making the tunnel strictly less reliable than the name service in
/// front of it.
///
/// FAIL-ON-REVERT: add a `map.remove(pubkey)` to the `Err` arm of
/// `resolve_once` and the retained-address assertion goes RED.
#[test]
fn a_failed_lookup_retains_the_last_good_endpoint_7158() {
    let sh = shared();

    // Pass 1: resolves.
    let good = vec![(PK_A, "203.0.113.7:51820".to_string())];
    assert_eq!(resolve_once(&sh, &good, false, None), 1);
    let first = sh.resolved.lock().unwrap().get(&PK_A).copied();
    assert_eq!(
        first,
        Some("203.0.113.7:51820".parse().unwrap()),
        "precondition: the address must be held before failure can retain it"
    );

    // Pass 2: the SAME peer, now unresolvable.
    let bad = vec![(PK_A, UNRESOLVABLE.to_string())];
    assert_eq!(
        resolve_once(&sh, &bad, false, None),
        1,
        "the peer still HOLDS an address after a failed lookup, so it is not \
         counted as awaiting one — a peer with a stale address must not put \
         the thread into its fast bring-up cadence"
    );

    assert_eq!(
        sh.resolved.lock().unwrap().get(&PK_A).copied(),
        first,
        "a failed lookup must leave the last-good endpoint in place. Clearing \
         it here drops a working peer to responder-only because DNS blinked \
         (#7158)"
    );
    assert_eq!(
        sh.telemetry.counters.resolve_fail.load(Ordering::Relaxed),
        1,
        "the failure must be COUNTED — an operator whose tunnel is stale \
         because DNS is broken has to be able to see that from the box"
    );
    assert!(
        sh.telemetry.last_error.lock().unwrap().is_some(),
        "the failure text must be retained for the operator surface"
    );
}

/// #15101 (was #7158's premise): a dual-stack (`socket_is_v6 == true`) socket
/// can send to EITHER family — `wg_send_to` maps an IPv4 target to its
/// v4-mapped form — so the resolver must ADOPT an A-only answer on it. The
/// pre-#15101 filter required `is_ipv6() == socket_is_v6` and dropped every
/// A record on the (normal) dual-stack socket, so an IPv4-only DDNS peer
/// could never be initiated to. Only the v4-fallback socket
/// (`socket_is_v6 == false`) rejects the family it cannot send: AAAA.
///
/// This is what replaces the commit-time family gate for hostnames: the family
/// is unknowable at commit, so it is enforced here, where it is known.
///
/// FAIL-ON-REVERT: restore `find(|a| a.is_ipv6() == socket_is_v6)` and the
/// dual-stack A-only assertions below go RED (held == 0, empty map,
/// family_mismatch == 1).
#[test]
fn only_addresses_of_the_socket_family_are_adopted_7158() {
    // #15101 acceptance: an A-only answer on the dual-stack socket IS adopted
    // as its canonical V4 form (the send path maps it; see
    // `wg_send_to_maps_v4_target_on_v6_socket`).
    let sh = shared();
    let v4_target = vec![(PK_A, "203.0.113.7:51820".to_string())];
    assert_eq!(
        resolve_once_with(&sh, &v4_target, true, None, |_| {
            Ok(vec!["203.0.113.7:51820".parse().unwrap()])
        }),
        1,
        "dual-stack socket must adopt the A record: it can send to IPv4 \
         peers via the v4-mapped form"
    );
    assert_eq!(
        sh.resolved.lock().unwrap().get(&PK_A).copied(),
        Some("203.0.113.7:51820".parse().unwrap()),
        "the adopted address stays canonical V4 so MTU/overhead math and \
         configured-endpoint comparisons see the real family"
    );
    assert_eq!(
        sh.telemetry
            .counters
            .family_mismatch
            .load(Ordering::Relaxed),
        0,
        "an A answer on a dual-stack socket is usable, not a mismatch"
    );
    assert_eq!(
        sh.telemetry.counters.resolve_fail.load(Ordering::Relaxed),
        0
    );

    // The v4-fallback socket still rejects AAAA: it has no way to send to an
    // IPv6 peer, so adopting it would present as a peer that initiates and
    // never connects. The mismatch is COUNTED and named, not silent.
    let sh4 = shared();
    let v6_target = vec![(PK_A, "[2001:db8::7]:51820".to_string())];
    assert_eq!(
        resolve_once(&sh4, &v6_target, false, None),
        0,
        "no address is held: the v4-fallback socket cannot send to IPv6"
    );
    assert!(
        sh4.resolved.lock().unwrap().is_empty(),
        "an AAAA answer must not be adopted by the v4-fallback socket"
    );
    assert_eq!(
        sh4.telemetry
            .counters
            .family_mismatch
            .load(Ordering::Relaxed),
        1,
        "counted separately from resolve_fail: the name WORKS and the record \
         (or the tunnel's family) is wrong, which is a different operator action"
    );
    assert_eq!(
        sh4.telemetry.counters.resolve_fail.load(Ordering::Relaxed),
        0,
        "a successful lookup of the wrong family is not a lookup failure"
    );

    // Positive control: the same v4 target on a v4 socket IS adopted, so the
    // emptiness above is the family filter and not a broken fixture.
    let sh4b = shared();
    assert_eq!(resolve_once(&sh4b, &v4_target, false, None), 1);
    assert_eq!(
        sh4b.resolved.lock().unwrap().get(&PK_A).copied(),
        Some("203.0.113.7:51820".parse().unwrap())
    );
    assert_eq!(
        sh4b.telemetry
            .counters
            .family_mismatch
            .load(Ordering::Relaxed),
        0
    );
}

/// #15101: preference among a dual answer set. When the interface already
/// carries literal endpoints their family wins (the operator pinned the
/// outer family at commit — the Go mixed-literal gate guarantees they
/// agree); with no literals, AAAA is preferred and A is the fallback.
///
/// FAIL-ON-REVERT: drop `preferred_v6` (always prefer AAAA) and the
/// v4-pinned case goes RED; always prefer A and the other two go RED.
#[test]
fn dual_stack_answers_prefer_the_literal_family_then_aaaa_15101() {
    let targets = vec![(PK_A, "dual.example:51820".to_string())];
    // Lookup order is deliberately A-first: selection must not be
    // "whichever answer happened to sort first".
    let lookup = |_: &str| {
        Ok(vec![
            "203.0.113.7:51820".parse().unwrap(),
            "[2001:db8::7]:51820".parse().unwrap(),
        ])
    };

    // No literal endpoints on the interface: AAAA wins.
    let sh = shared();
    assert_eq!(resolve_once_with(&sh, &targets, true, None, lookup), 1);
    assert_eq!(
        sh.resolved.lock().unwrap().get(&PK_A).copied(),
        Some("[2001:db8::7]:51820".parse().unwrap()),
        "no literal pins the family: prefer AAAA"
    );

    // A v4 literal peer pins the outer family to IPv4.
    let sh = shared();
    assert_eq!(
        resolve_once_with(&sh, &targets, true, Some(false), lookup),
        1
    );
    assert_eq!(
        sh.resolved.lock().unwrap().get(&PK_A).copied(),
        Some("203.0.113.7:51820".parse().unwrap()),
        "a v4 literal endpoint on the interface makes A win"
    );

    // A v6 literal peer pins the outer family to IPv6.
    let sh = shared();
    assert_eq!(
        resolve_once_with(&sh, &targets, true, Some(true), lookup),
        1
    );
    assert_eq!(
        sh.resolved.lock().unwrap().get(&PK_A).copied(),
        Some("[2001:db8::7]:51820".parse().unwrap()),
        "a v6 literal endpoint on the interface makes AAAA win"
    );
}

/// #15101: the v4-fallback socket keeps the pre-#15101 A-over-AAAA
/// behaviour: from a dual answer set it takes the A record, and an
/// AAAA-only answer is the counted family mismatch (covered above).
#[test]
fn v4_fallback_socket_still_prefers_a_15101() {
    let sh = shared();
    let targets = vec![(PK_A, "dual.example:51820".to_string())];
    let held = resolve_once_with(&sh, &targets, false, None, |_| {
        Ok(vec![
            "[2001:db8::7]:51820".parse().unwrap(),
            "203.0.113.7:51820".parse().unwrap(),
        ])
    });
    assert_eq!(held, 1);
    assert_eq!(
        sh.resolved.lock().unwrap().get(&PK_A).copied(),
        Some("203.0.113.7:51820".parse().unwrap()),
        "the v4-fallback socket takes the A record from a dual answer"
    );
    assert_eq!(
        sh.telemetry
            .counters
            .family_mismatch
            .load(Ordering::Relaxed),
        0
    );
}

/// #7158: `endpoint_changed` must count actual CHANGES, not lookups.
///
/// It is the operator's evidence that re-resolution is doing something. If it
/// ticked once per pass it would read as a DDNS change every 30 s on a
/// perfectly static name, which is worse than not having the counter.
#[test]
fn endpoint_changed_counts_changes_not_lookups_7158() {
    let sh = shared();
    let t1 = vec![(PK_A, "203.0.113.7:51820".to_string())];
    resolve_once(&sh, &t1, false, None);
    resolve_once(&sh, &t1, false, None);
    resolve_once(&sh, &t1, false, None);
    assert_eq!(
        sh.telemetry
            .counters
            .endpoint_changed
            .load(Ordering::Relaxed),
        1,
        "three lookups of an unchanged name are ONE change (the first, from \
         nothing to an address)"
    );
    assert_eq!(sh.telemetry.counters.resolve_ok.load(Ordering::Relaxed), 3);

    // The DDNS move.
    let t2 = vec![(PK_A, "198.51.100.9:51820".to_string())];
    resolve_once(&sh, &t2, false, None);
    assert_eq!(
        sh.telemetry
            .counters
            .endpoint_changed
            .load(Ordering::Relaxed),
        2,
        "an address change at the name must be counted"
    );
    assert_eq!(
        sh.resolved.lock().unwrap().get(&PK_A).copied(),
        Some("198.51.100.9:51820".parse().unwrap()),
        "and adopted — acceptance 3 is that a DDNS move is picked up with no \
         commit and no daemon restart"
    );
}

/// #7158 acceptance 6: a tunnel whose peers are all IP literals must be
/// bit-identical to its pre-#7158 behaviour, which starts with not existing.
#[test]
fn a_tunnel_with_no_hostname_peers_starts_no_resolver_7158() {
    assert!(
        WgEndpointResolver::spawn("wg0", Vec::new(), false, None, Default::default()).is_none(),
        "no hostname peers means no thread: every tunnel that existed before \
         #7158 must not acquire one"
    );
}

/// #7158: per-peer isolation — one peer's failure must not disturb another's
/// held address, since they share the resolver pass.
#[test]
fn one_peers_failure_does_not_disturb_another_7158() {
    let sh = shared();
    let targets = vec![
        (PK_A, "203.0.113.7:51820".to_string()),
        (PK_B, UNRESOLVABLE.to_string()),
    ];
    let held = resolve_once(&sh, &targets, false, None);
    assert_eq!(held, 1, "only PK_A holds an address");
    assert_eq!(
        sh.resolved.lock().unwrap().get(&PK_A).copied(),
        Some("203.0.113.7:51820".parse().unwrap()),
        "PK_A resolved before PK_B failed in the same pass; the failure must \
         not abort the pass or discard earlier work"
    );
    assert!(sh.resolved.lock().unwrap().get(&PK_B).is_none());
}

/// #13666: multiple peers' blocking DNS lookups run concurrently, but the
/// resolver thread alone folds outcomes into the shared state. The peak bound
/// also prevents a large peer set from creating unbounded worker threads.
#[test]
fn peer_endpoint_lookups_are_bounded_and_concurrent_13666() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    let sh = shared();
    let targets: Vec<_> = (0..10)
        .map(|n| {
            let mut pubkey = [0u8; 32];
            pubkey[0] = n;
            (pubkey, format!("peer-{n}"))
        })
        .collect();
    let active = AtomicUsize::new(0);
    let peak = AtomicUsize::new(0);
    let held = resolve_once_with(&sh, &targets, false, None, |_| {
        let now = active.fetch_add(1, Ordering::SeqCst) + 1;
        peak.fetch_max(now, Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(30));
        active.fetch_sub(1, Ordering::SeqCst);
        Ok(vec!["203.0.113.7:51820".parse().unwrap()])
    });

    assert_eq!(held, targets.len());
    assert!(
        peak.load(Ordering::SeqCst) > 1,
        "peer lookups were serialized instead of concurrent"
    );
    assert!(
        peak.load(Ordering::SeqCst) <= 8,
        "lookup fan-out exceeded its configured bound"
    );
    assert_eq!(
        sh.telemetry.counters.resolve_ok.load(Ordering::Relaxed),
        targets.len() as u64
    );
}

/// #13666: a panicking lookup is isolated to its peer and does not prevent
/// later results from being applied.
#[test]
fn panicking_endpoint_lookup_does_not_stop_sibling_updates_13666() {
    let sh = shared();
    let targets = vec![
        (PK_A, "panic-peer".to_string()),
        (PK_B, "healthy-peer".to_string()),
    ];
    let held = resolve_once_with(&sh, &targets, false, None, |host| {
        if host == "panic-peer" {
            panic!("injected resolver panic");
        }
        Ok(vec!["203.0.113.8:51820".parse().unwrap()])
    });

    assert_eq!(held, 1);
    assert_eq!(
        sh.resolved.lock().unwrap().get(&PK_B).copied(),
        Some("203.0.113.8:51820".parse().unwrap())
    );
    assert_eq!(
        sh.telemetry.counters.resolve_fail.load(Ordering::Relaxed),
        1
    );
}

/// #13666: a slow peer must not block later lookups or adoption of their answers,
/// including peers beyond the concurrent-worker limit.
#[test]
fn slow_endpoint_does_not_block_later_peers_13666() {
    use std::sync::{Arc, mpsc};
    use std::time::{Duration, Instant};

    let sh = Arc::new(shared());
    let resolver_sh = Arc::clone(&sh);
    let targets: Vec<_> = (0..9)
        .map(|n| {
            let mut pubkey = [0u8; 32];
            pubkey[0] = n;
            (pubkey, format!("peer-{n}"))
        })
        .collect();
    let mut peer_8 = [0u8; 32];
    peer_8[0] = 8;
    let (started_tx, started_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let release_rx = Mutex::new(release_rx);
    let resolver = std::thread::spawn(move || {
        resolve_once_with(&resolver_sh, &targets, false, None, |host| {
            if host == "peer-0" {
                release_rx.lock().unwrap().recv().unwrap();
            } else if host == "peer-8" {
                started_tx.send(()).unwrap();
            }
            Ok(vec!["203.0.113.9:51820".parse().unwrap()])
        })
    });

    let later_peer_started = started_rx.recv_timeout(Duration::from_secs(1)).is_ok();
    let deadline = Instant::now() + Duration::from_secs(1);
    let later_peer_applied = loop {
        if sh.resolved.lock().unwrap().contains_key(&peer_8) {
            break true;
        }
        if Instant::now() >= deadline {
            break false;
        }
        std::thread::yield_now();
    };
    release_tx.send(()).unwrap();
    assert_eq!(resolver.join().unwrap(), 9);
    assert!(later_peer_started, "the ninth peer lookup did not start");
    assert!(
        later_peer_applied,
        "the ninth peer answer was not applied before releasing the slow first lookup"
    );
}

/// #13666: dropping the resolver is nonblocking even when DNS is in flight,
/// and workers do not schedule more peers after shutdown begins.
#[test]
fn dropping_resolver_does_not_wait_for_inflight_lookup_13666() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Barrier, mpsc};
    use std::time::Duration;

    let shared = Arc::new(shared());
    let worker_shared = Arc::clone(&shared);
    let all_workers_started = Arc::new(Barrier::new(9));
    let worker_started_barrier = Arc::clone(&all_workers_started);
    let release_workers = Arc::new(Barrier::new(9));
    let worker_release_barrier = Arc::clone(&release_workers);
    let late_peer_scheduled = Arc::new(AtomicBool::new(false));
    let late_peer_probe = Arc::clone(&late_peer_scheduled);
    let (finished_tx, finished_rx) = mpsc::channel();
    let targets: Vec<_> = (0..9)
        .map(|n| {
            let mut pubkey = [0u8; 32];
            pubkey[0] = n;
            (pubkey, format!("peer-{n}"))
        })
        .collect();
    let handle = std::thread::spawn(move || {
        let _ = resolve_once_with(&worker_shared, &targets, false, None, |host| {
            let n: usize = host.strip_prefix("peer-").unwrap().parse().unwrap();
            if n < 8 {
                worker_started_barrier.wait();
                worker_release_barrier.wait();
            } else {
                late_peer_probe.store(true, Ordering::Relaxed);
            }
            Ok(vec!["203.0.113.10:51820".parse().unwrap()])
        });
        finished_tx.send(()).unwrap();
    });
    let resolver = WgEndpointResolver {
        shared: Arc::clone(&shared),
        join: Some(handle),
    };

    // All eight workers are inside their injected lookup; peer 8 is still
    // unscheduled.
    all_workers_started.wait();
    let (dropped_tx, dropped_rx) = mpsc::channel();
    let dropper = std::thread::spawn(move || {
        drop(resolver);
        dropped_tx.send(()).unwrap();
    });
    let dropped_without_wait = dropped_rx.recv_timeout(Duration::from_millis(500)).is_ok();
    release_workers.wait();
    dropper.join().unwrap();
    finished_rx.recv_timeout(Duration::from_secs(1)).unwrap();

    assert!(
        dropped_without_wait,
        "resolver Drop waited for an in-flight DNS lookup"
    );
    assert!(
        !late_peer_scheduled.load(Ordering::Relaxed),
        "a worker scheduled another peer after stop was set"
    );
    assert!(
        shared.resolved.lock().unwrap().is_empty(),
        "shutdown must not apply results after the resolver is dropped"
    );
}
