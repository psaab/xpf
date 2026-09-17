use super::*;
use crate::afxdp::wg::handshake::{self, MSG_INIT_NOISE_LEN};

fn src(port: u16) -> SocketAddr {
    format!("203.0.113.7:{port}").parse().unwrap()
}

fn valid_mac1_init(our_pub: &[u8; 32], sender_index: u32) -> [u8; WG_MSG_INIT_LEN] {
    let noise = [0x5Au8; MSG_INIT_NOISE_LEN];
    let mut buf = [0u8; WG_MSG_INIT_LEN];
    handshake::build_initiation(&mut buf, sender_index, &noise, our_pub).unwrap();
    buf
}

#[test]
fn cookie_reply_length_and_type() {
    assert_eq!(WG_MSG_COOKIE_LEN, 64);
    let our_pub = [0x11u8; 32];
    let cc = CookieChecker::new(&our_pub);
    let init = valid_mac1_init(&our_pub, 0xABCD);
    let mut out = [0u8; 128];
    let len = cc
        .build_cookie_reply(&init, src(51820), 10_000_000_000, &mut out)
        .unwrap();
    assert_eq!(len, WG_MSG_COOKIE_LEN);
    assert_eq!(out[0], WG_TYPE_COOKIE);
    assert_eq!(&out[1..4], &[0, 0, 0], "reserved zero");
    // receiver_index echoes the initiator's sender_index.
    assert_eq!(&out[M3_RECEIVER..M3_RECEIVER + 4], &init[4..8]);
}

/// End-to-end: a cookie reply decrypts (PR-B mirror) to the cookie the
/// responder would recompute, and a MAC2 stamped from that cookie
/// verifies. A DIFFERENT source (spoofed) does NOT verify.
#[test]
fn cookie_reply_roundtrip_and_source_binding() {
    let our_pub = [0x22u8; 32];
    let cc = CookieChecker::new(&our_pub);
    let now = 10_000_000_000;
    let real = src(51820);
    let init = valid_mac1_init(&our_pub, 7);
    let mut reply = [0u8; 64];
    cc.build_cookie_reply(&init, real, now, &mut reply).unwrap();

    // Initiator (PR-B) decrypts using the responder pubkey + the
    // initiation's MAC1 as AAD.
    let aad = &init[M1_MAC1..M1_MAC2];
    let cookie = CookieChecker::decrypt_cookie_reply(&reply, &our_pub, aad).expect("decrypts");

    // Stamp MAC2 and verify from the SAME source → accepted.
    let mut init2 = init;
    stamp_initiation_mac2(&mut init2, &cookie);
    assert!(
        cc.verify_initiation_mac2(&init2, real, now),
        "same-source MAC2 verifies"
    );

    // The same MAC2 replayed from a DIFFERENT source → rejected (the
    // cookie is bound to the source that received the reply).
    let spoof = src(51821);
    assert!(
        !cc.verify_initiation_mac2(&init2, spoof, now),
        "MAC2 must not verify from a different source"
    );

    // Wrong AAD MAC1 fails the AEAD entirely.
    let bad_aad = [0u8; WG_MAC_LEN];
    assert!(CookieChecker::decrypt_cookie_reply(&reply, &our_pub, &bad_aad).is_none());
}

/// A zero / absent MAC2 (a normal not-yet-challenged initiation) never
/// verifies — the cookie is non-zero.
#[test]
fn zero_mac2_never_verifies() {
    let our_pub = [0x33u8; 32];
    let cc = CookieChecker::new(&our_pub);
    let init = valid_mac1_init(&our_pub, 1); // build_initiation zeroes MAC2
    assert_eq!(&init[M1_MAC2..], &[0u8; 16]);
    assert!(!cc.verify_initiation_mac2(&init, src(1), 10_000_000_000));
}

/// Secret rotation with the one-window previous-secret carry: a cookie
/// issued under the original secret still validates after ONE rotation
/// (previous window) but NOT after two (secret aged out).
#[test]
fn secret_rotation_previous_window() {
    let our_pub = [0x44u8; 32];
    let cc = CookieChecker::new(&our_pub);
    let peer = src(51820);
    let t0 = 10_000_000_000; // 10 s (nonzero → lazy init stamps here)

    // Cookie + MAC2 minted under the original secret at t0.
    let cookie0 = cc.cookie_for_test(peer, t0);
    let mut init = valid_mac1_init(&our_pub, 9);
    stamp_initiation_mac2(&mut init, &cookie0);
    assert!(
        cc.verify_initiation_mac2(&init, peer, t0),
        "current secret validates"
    );

    // One rotation later (t0 + 130 s > 120 s): current rotates, the
    // original becomes `previous` → the old MAC2 STILL validates.
    let t1 = t0 + 130 * 1_000_000_000;
    assert!(
        cc.verify_initiation_mac2(&init, peer, t1),
        "previous-secret window keeps a just-challenged peer valid across a rotation"
    );

    // A second rotation later (another +130 s): the original has aged
    // out of both slots → the old MAC2 no longer validates.
    let t2 = t1 + 130 * 1_000_000_000;
    assert!(
        !cc.verify_initiation_mac2(&init, peer, t2),
        "secret aged past the previous window no longer validates"
    );
}

#[test]
fn load_gate_trips_over_threshold_and_grace_holds() {
    let our_pub = [0x55u8; 32];
    let cc = CookieChecker::new(&our_pub);
    let base = 10_000_000_000;
    // First arrival: not under load.
    assert!(!cc.note_initiation(base));
    // Drive past the threshold within the same 1 s window.
    let mut under = false;
    for _ in 0..(INITIATIONS_UNDER_LOAD_THRESHOLD + 2) {
        under = cc.note_initiation(base);
    }
    assert!(
        under,
        "crossing the per-window threshold declares under-load"
    );
    // Grace holds for ~1 s even with no further arrivals accounted.
    assert!(
        cc.note_initiation(base + 500_000_000),
        "grace still under load"
    );
    // Well past the grace window with a fresh (low-rate) window → clear.
    assert!(!cc.note_initiation(base + 3_000_000_000));
}

#[test]
fn reply_budget_caps_per_window() {
    let our_pub = [0x66u8; 32];
    let cc = CookieChecker::new(&our_pub);
    let base = 10_000_000_000;
    let mut granted = 0u64;
    for _ in 0..(COOKIE_REPLY_BUDGET_PER_WINDOW + 10) {
        if cc.reply_budget_available(base) {
            granted += 1;
        }
    }
    assert_eq!(
        granted, COOKIE_REPLY_BUDGET_PER_WINDOW,
        "budget caps emission per window"
    );
    // A new window refills.
    assert!(cc.reply_budget_available(base + UNDER_LOAD_WINDOW_NS));
}

/// #4094 Copilot BUG-1: `now_ns == 0` is a LEGITIMATE timestamp (very
/// early CLOCK_MONOTONIC, or a failed clock read that returns 0), not
/// "uninitialized". With the old `window_start_ns == 0` sentinel the
/// load window reset on every call → `count` never accumulated → the
/// under-load gate NEVER tripped, disabling the mitigation exactly when
/// it matters. With `Option`, the first call at t=0 arms the window and
/// the gate trips as the flood accumulates. RED on the 0-sentinel.
#[test]
fn load_gate_trips_at_now_zero() {
    let our_pub = [0x77u8; 32];
    let cc = CookieChecker::new(&our_pub);
    // Every call at now_ns == 0 (clock stuck/early). The count must
    // accumulate across calls, not reset.
    let mut under = false;
    for _ in 0..(INITIATIONS_UNDER_LOAD_THRESHOLD + 2) {
        under = cc.note_initiation(0);
    }
    assert!(
        under,
        "the under-load gate must trip even when now_ns is 0 \
             (0 is a valid window start, not 'uninitialized')"
    );
}

/// #4094 BUG-1 companion: the reply budget also must not reset every
/// call at now_ns == 0 (else it would grant unlimited replies).
#[test]
fn reply_budget_caps_at_now_zero() {
    let our_pub = [0x78u8; 32];
    let cc = CookieChecker::new(&our_pub);
    let mut granted = 0u64;
    for _ in 0..(COOKIE_REPLY_BUDGET_PER_WINDOW + 10) {
        if cc.reply_budget_available(0) {
            granted += 1;
        }
    }
    assert_eq!(
        granted, COOKIE_REPLY_BUDGET_PER_WINDOW,
        "the budget must cap per window even at now_ns == 0"
    );
}

/// #4094 BUG-1 companion: secret rotation must treat now_ns == 0 as a
/// real generation time, not "uninitialized" (else it would re-stamp
/// every call and the rotation clock would never advance). A cookie
/// minted at t=0 still validates one window later.
#[test]
fn secret_rotation_from_now_zero() {
    let our_pub = [0x79u8; 32];
    let cc = CookieChecker::new(&our_pub);
    let peer = src(51820);
    let cookie0 = cc.cookie_for_test(peer, 0);
    let mut init = valid_mac1_init(&our_pub, 3);
    stamp_initiation_mac2(&mut init, &cookie0);
    assert!(
        cc.verify_initiation_mac2(&init, peer, 0),
        "t=0 mint validates at t=0"
    );
    // 130 s later: current rotates, t=0 secret becomes previous → still
    // valid. If t=0 were treated as "uninitialized", generated_at would
    // keep re-stamping to `now` and the rotation would never fire.
    let t1 = 130 * 1_000_000_000;
    assert!(
        cc.verify_initiation_mac2(&init, peer, t1),
        "t=0-minted cookie still validates one rotation later"
    );
}

/// #4094 Copilot BUG-2: a `getrandom` failure must FAIL CLOSED, never
/// fall back to a predictable secret/nonce. With the CSPRNG simulated as
/// unavailable: no secret is produced (`verify` cannot validate, `build`
/// refuses to emit a reply), and once randomness returns the mechanism
/// recovers. RED on the old time-seeded xorshift fallback (which would
/// have produced a usable-but-predictable secret and a successful
/// reply).
#[test]
fn getrandom_failure_fails_closed_no_weak_secret() {
    let our_pub = [0x7Au8; 32];
    let cc = CookieChecker::new(&our_pub);
    let peer = src(51820);
    let now = 10_000_000_000;

    // Mint a cookie + MAC2 while randomness is healthy.
    let cookie = cc.cookie_for_test(peer, now);
    let mut init = valid_mac1_init(&our_pub, 9);
    stamp_initiation_mac2(&mut init, &cookie);
    assert!(cc.verify_initiation_mac2(&init, peer, now));

    // Simulate a persistent getrandom failure.
    cc.set_rng_fail_for_test(true);

    // No secure secret → cannot verify (fail closed, NOT accept).
    assert!(
        !cc.verify_initiation_mac2(&init, peer, now),
        "with no secure secret, MAC2 verification must fail closed"
    );
    // Cannot build a cookie reply → RandUnavailable, NOT a weak-nonce
    // reply.
    let mut out = [0u8; 128];
    assert_eq!(
        cc.build_cookie_reply(&init, peer, now, &mut out),
        Err(CookieError::RandUnavailable),
        "with no secure randomness, no cookie reply is emitted"
    );

    // Randomness returns → the mechanism recovers (lazy re-acquire).
    cc.set_rng_fail_for_test(false);
    let cookie2 = cc.cookie_for_test(peer, now);
    let mut init2 = valid_mac1_init(&our_pub, 10);
    stamp_initiation_mac2(&mut init2, &cookie2);
    assert!(
        cc.verify_initiation_mac2(&init2, peer, now),
        "the mechanism recovers once secure randomness is available"
    );
}

/// `fill_random` reports success and yields non-constant output for a
/// healthy CSPRNG (and there is no weak-PRNG fallback path).
#[test]
fn fill_random_reports_success_and_fills() {
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    assert!(fill_random(&mut a));
    assert!(fill_random(&mut b));
    assert_ne!(a, [0u8; 32], "a healthy CSPRNG does not yield all-zero");
    assert_ne!(a, b, "two draws differ");
}

// ===================================================================
// #4332 per-SOURCE cookie-reply token bucket.
// ===================================================================

fn ipv4(a: u8) -> IpAddr {
    IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, a))
}

/// A fresh source draws exactly [`SOURCE_REPLY_BURST`] replies back-to-back
/// (same instant, no refill) and is then throttled; one [`PACKET_COST_NS`]
/// of accrued time refills exactly one token.
#[test]
fn source_bucket_burst_then_throttle() {
    let cc = CookieChecker::new(&[0x81u8; 32]);
    let now = 10_000_000_000u64;
    let s = ipv4(1);
    let mut granted = 0u64;
    for _ in 0..(SOURCE_REPLY_BURST + 10) {
        if cc.source_reply_allowed(s, now) {
            granted += 1;
        }
    }
    assert_eq!(
        granted, SOURCE_REPLY_BURST,
        "a source may burst exactly SOURCE_REPLY_BURST replies, then throttles"
    );
    // One packet-cost of accrued time → exactly one more token, then dry.
    assert!(cc.source_reply_allowed(s, now + PACKET_COST_NS));
    assert!(!cc.source_reply_allowed(s, now + PACKET_COST_NS));
}

/// The isolation #4332 buys over the global-only budget: a source that has
/// exhausted its bucket does NOT starve a DIFFERENT source, which still
/// draws its full burst. RED on revert (no per-source layer, the direct
/// method disappears; and at the engine level A's flood drains the shared
/// budget — see `classify_initiation_per_source_budget_isolation`).
#[test]
fn source_bucket_isolates_sources() {
    let cc = CookieChecker::new(&[0x82u8; 32]);
    let now = 10_000_000_000u64;
    let a = ipv4(1);
    let b = ipv4(2);
    for _ in 0..(SOURCE_REPLY_BURST + 5) {
        cc.source_reply_allowed(a, now);
    }
    assert!(
        !cc.source_reply_allowed(a, now),
        "source A is throttled after exhausting its own bucket"
    );
    let mut granted_b = 0u64;
    for _ in 0..(SOURCE_REPLY_BURST + 5) {
        if cc.source_reply_allowed(b, now) {
            granted_b += 1;
        }
    }
    assert_eq!(
        granted_b, SOURCE_REPLY_BURST,
        "a different source is unaffected by A's flood (per-source isolation)"
    );
}

/// The table is hard-capped at [`SOURCE_TABLE_MAX`]: a spoofed-source-IP
/// flood cannot grow the map without bound. A NEW source over the cap fails
/// CLOSED (no reply, not inserted); an already-tracked source is still
/// served.
#[test]
fn source_table_cap_fails_closed() {
    let cc = CookieChecker::new(&[0x83u8; 32]);
    let now = 10_000_000_000u64;
    // Fill to the cap with distinct sources, all within one GC interval
    // (same `now`) so none are reclaimed.
    for i in 0..SOURCE_TABLE_MAX {
        let ip = IpAddr::V4(std::net::Ipv4Addr::from(0x0A00_0000u32 + i as u32));
        assert!(
            cc.source_reply_allowed(ip, now),
            "a fresh source under the cap is admitted"
        );
    }
    assert_eq!(cc.source_table_len_for_test(), SOURCE_TABLE_MAX);
    // A NEW source over the cap is DENIED and NOT inserted — fail closed
    // against the memory-amplification vector.
    let overflow = IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, 1));
    assert!(
        !cc.source_reply_allowed(overflow, now),
        "a new source over the table cap fails closed (denied, no reply)"
    );
    assert!(!cc.source_contains_for_test(overflow));
    assert_eq!(
        cc.source_table_len_for_test(),
        SOURCE_TABLE_MAX,
        "the table never grows past its cap under a spoofed-IP flood"
    );
    // An already-tracked source (drew 1 of its burst) is still served.
    let tracked = IpAddr::V4(std::net::Ipv4Addr::from(0x0A00_0000u32));
    assert!(
        cc.source_reply_allowed(tracked, now),
        "an already-tracked source is not refused by the cap"
    );
}

/// #9908: valid-MAC2 admission has its own bounded source table and
/// token bucket. The reply table's cap must not be the only bound: a
/// spoofed-IP flood that reaches the admission seam cannot grow the new
/// map without limit.
#[test]
fn handshake_source_bucket_burst_and_table_cap() {
    let cc = CookieChecker::new(&[0x86u8; 32]);
    let source = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1));
    let now = 10_000_000_000u64;
    let mut granted = 0u64;
    for _ in 0..(SOURCE_HANDSHAKE_BURST + 5) {
        if cc.source_handshake_allowed(source, now) {
            granted += 1;
        }
    }
    assert_eq!(
        granted, SOURCE_HANDSHAKE_BURST,
        "one source gets exactly the bounded handshake burst"
    );
    assert!(cc.source_handshake_allowed(
        source,
        now + HANDSHAKE_PACKET_COST_NS
    ));
    assert!(!cc.source_handshake_allowed(
        source,
        now + HANDSHAKE_PACKET_COST_NS
    ));

    for i in 0..(SOURCE_TABLE_MAX - 1) {
        let ip = IpAddr::V6(std::net::Ipv6Addr::from(i as u128));
        assert!(cc.source_handshake_allowed(ip, now));
    }
    assert_eq!(
        cc.handshake_source_table_len_for_test(),
        SOURCE_TABLE_MAX,
        "the handshake source table reaches, but does not exceed, its cap"
    );
    let overflow = IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, 2));
    assert!(!cc.source_handshake_allowed(overflow, now));
    assert_eq!(
        cc.handshake_source_table_len_for_test(),
        SOURCE_TABLE_MAX,
        "a new over-cap source is denied without map growth"
    );
}

/// GC reclaims buckets idle for a full [`SOURCE_GC_INTERVAL_NS`]: as
/// spoofed sources come and go the table shrinks back, so a burst of
/// short-lived sources does not permanently pin the map at its cap.
#[test]
fn source_gc_reclaims_idle_buckets() {
    let cc = CookieChecker::new(&[0x84u8; 32]);
    let base = 10_000_000_000u64;
    let idle = ipv4(1);
    let active = ipv4(2);
    assert!(cc.source_reply_allowed(idle, base));
    assert_eq!(cc.source_table_len_for_test(), 1);
    // A full GC interval later a DIFFERENT source sends: the sweep drops
    // the idle bucket before admitting the active one.
    let later = base + SOURCE_GC_INTERVAL_NS + 1;
    assert!(cc.source_reply_allowed(active, later));
    assert_eq!(
        cc.source_table_len_for_test(),
        1,
        "the idle source was GC-reclaimed; only the active source remains"
    );
    assert!(!cc.source_contains_for_test(idle));
    assert!(cc.source_contains_for_test(active));
}

/// Monotonic-clock discipline (#4330/#4321): a backwards `now_ns` credits
/// nothing and never lowers the bucket's `last_ns` high-water mark, so the
/// glitch cannot be replayed into an over-credit on the next forward step.
#[test]
fn source_bucket_ignores_backwards_clock() {
    let cc = CookieChecker::new(&[0x85u8; 32]);
    let s = ipv4(1);
    let t_hi = 10_000_000_000u64;
    // Drain the burst at t_hi.
    for _ in 0..SOURCE_REPLY_BURST {
        assert!(cc.source_reply_allowed(s, t_hi));
    }
    assert!(!cc.source_reply_allowed(s, t_hi), "burst exhausted at t_hi");
    // A backwards step must NOT credit (saturating_sub → 0 elapsed) and must
    // NOT lower last_ns — else the following forward jump back to t_hi would
    // credit the whole (t_hi - t_lo) span and refill to the ceiling.
    let t_lo = t_hi - 5 * SOURCE_GC_INTERVAL_NS;
    assert!(
        !cc.source_reply_allowed(s, t_lo),
        "a backwards clock step credits nothing"
    );
    assert!(
        !cc.source_reply_allowed(s, t_hi),
        "the forward jump after a backwards step is not replayed into an over-credit"
    );
}

// ===================================================================
// #4094 PR-B initiator-side cookie-reply consume + MAC2 stamping.
// ===================================================================

/// Full cookie handshake round-trip across BOTH halves: the responder
/// (PR-A [`CookieChecker`]) issues a cookie-reply; the initiator (PR-B
/// [`InitiatorCookie`]) consumes it and stamps a MAC2 on its RETRIED
/// initiation that the responder's [`CookieChecker::verify_initiation_mac2`]
/// accepts. RED on revert: without the consume+stamp the retried MAC2
/// stays zero and the responder rejects it (re-challenging forever — the
/// handshake never completes under load).
#[test]
fn initiator_cookie_roundtrip_stamps_accepted_mac2() {
    let responder_pub = [0x91u8; 32];
    let cc = CookieChecker::new(&responder_pub);
    let now = 10_000_000_000u64;
    let from = src(51820); // the initiator's source as the responder sees it

    // 1. Initiator sends its FIRST initiation (MAC2 zero) and records its
    //    MAC1 via add_macs.
    let mut ic = InitiatorCookie::new();
    let mut first = valid_mac1_init(&responder_pub, 0x1111);
    assert!(
        !ic.add_macs(&mut first, now),
        "no cookie yet → MAC2 stays zero"
    );
    assert_eq!(&first[M1_MAC2..], &[0u8; 16]);

    // 2. Responder issues a cookie-reply for that initiation from `from`.
    let mut reply = [0u8; WG_MSG_COOKIE_LEN];
    cc.build_cookie_reply(&first, from, now, &mut reply)
        .unwrap();

    // 3. Initiator consumes the reply → stores the cookie.
    assert!(ic.consume_reply(&reply, &responder_pub, now));
    assert!(ic.has_cookie_for_test());

    // 4. Initiator retries — add_macs now stamps a NON-ZERO MAC2.
    let mut retry = valid_mac1_init(&responder_pub, 0x2222);
    assert!(ic.add_macs(&mut retry, now), "a fresh cookie stamps MAC2");
    assert_ne!(&retry[M1_MAC2..], &[0u8; 16]);

    // 5. The responder's MAC2 verifier accepts the retried initiation
    //    from the SAME source (RED on revert: zero MAC2 is rejected).
    assert!(
        cc.verify_initiation_mac2(&retry, from, now),
        "responder must accept the initiator's cookie-derived MAC2"
    );
    // A DIFFERENT source is still rejected — the cookie binds the source.
    assert!(
        !cc.verify_initiation_mac2(&retry, src(51821), now),
        "a cookie-derived MAC2 must not verify from a different source"
    );
}

/// A cookie-reply that fails AEAD authentication (tampered ciphertext or
/// wrong responder key) is DROPPED: no cookie is stored, no panic, and a
/// subsequent retry still carries a zero MAC2 (fail-closed).
#[test]
fn initiator_drops_undecryptable_cookie_reply() {
    let responder_pub = [0x92u8; 32];
    let cc = CookieChecker::new(&responder_pub);
    let now = 10_000_000_000u64;
    let from = src(51820);

    let mut ic = InitiatorCookie::new();
    let mut first = valid_mac1_init(&responder_pub, 7);
    ic.add_macs(&mut first, now);
    let mut reply = [0u8; WG_MSG_COOKIE_LEN];
    cc.build_cookie_reply(&first, from, now, &mut reply)
        .unwrap();

    // (a) Tampered ciphertext → AEAD tag mismatch → not consumed.
    let mut tampered = reply;
    tampered[M3_COOKIE] ^= 0xFF;
    assert!(!ic.consume_reply(&tampered, &responder_pub, now));
    assert!(!ic.has_cookie_for_test());

    // (b) Wrong responder key → wrong AEAD key → not consumed.
    let wrong_pub = [0x93u8; 32];
    assert!(!ic.consume_reply(&reply, &wrong_pub, now));
    assert!(!ic.has_cookie_for_test());

    // Sanity: the untampered reply with the RIGHT key DOES consume — the
    // failures above were the tamper/key, not a broken reply. (`last_mac1`
    // is still the first initiation's MAC1 — we have not sent another —
    // so the AAD still matches.)
    assert!(ic.consume_reply(&reply, &responder_pub, now));
    assert!(ic.has_cookie_for_test());
}

/// An EXPIRED cookie (older than [`COOKIE_ROTATION_TIME_NS`], 120 s) is
/// NOT used: add_macs leaves MAC2 zero rather than stamping a stale
/// cookie. Just inside the window it is still stamped.
#[test]
fn initiator_expired_cookie_yields_zero_mac2() {
    let responder_pub = [0x94u8; 32];
    let cc = CookieChecker::new(&responder_pub);
    let t0 = 10_000_000_000u64;
    let from = src(51820);

    let mut ic = InitiatorCookie::new();
    let mut first = valid_mac1_init(&responder_pub, 1);
    ic.add_macs(&mut first, t0);
    let mut reply = [0u8; WG_MSG_COOKIE_LEN];
    cc.build_cookie_reply(&first, from, t0, &mut reply).unwrap();
    assert!(ic.consume_reply(&reply, &responder_pub, t0));

    // Just within the TTL → MAC2 stamped.
    let mut in_window = valid_mac1_init(&responder_pub, 2);
    assert!(ic.add_macs(&mut in_window, t0 + COOKIE_ROTATION_TIME_NS - 1));
    assert_ne!(&in_window[M1_MAC2..], &[0u8; 16]);

    // Past the TTL (> 120 s) → MAC2 zero (a stale cookie is not used).
    let mut expired = valid_mac1_init(&responder_pub, 3);
    assert!(!ic.add_macs(&mut expired, t0 + COOKIE_ROTATION_TIME_NS + 1));
    assert_eq!(&expired[M1_MAC2..], &[0u8; 16]);
}

/// A cookie-reply that arrives before the initiator ever sent an
/// initiation (no stored MAC1 to use as the AEAD AAD) is ignored — the
/// reply cannot be attributed, so it is dropped fail-closed.
#[test]
fn initiator_ignores_cookie_reply_before_any_initiation() {
    let responder_pub = [0x95u8; 32];
    let cc = CookieChecker::new(&responder_pub);
    let now = 10_000_000_000u64;
    let from = src(51820);

    let first = valid_mac1_init(&responder_pub, 9);
    let mut reply = [0u8; WG_MSG_COOKIE_LEN];
    cc.build_cookie_reply(&first, from, now, &mut reply)
        .unwrap();

    let mut ic = InitiatorCookie::new();
    assert!(
        !ic.consume_reply(&reply, &responder_pub, now),
        "a reply with no prior sent initiation cannot be attributed"
    );
    assert!(!ic.has_cookie_for_test());
}

/// #6422: the responder's under-load detector is consulted on EVERY
/// inbound initiation. `.lock().unwrap()` on `load` meant one poisoning
/// panic turned the cookie/DoS gate itself into the denial of service —
/// every later initiation panicked the thread that classified it.
/// Recovery is safe: `LoadState` is a fixed-window counter mutated by
/// infallible integer arithmetic, so the recovered value is always a
/// real committed window.
#[test]
fn note_initiation_recovers_poisoned_load_lock_6422() {
    use crate::afxdp::wg::poison_tests::poison_mutex;
    let cc = CookieChecker::new(&[0x11u8; 32]);
    // Seed a window so recovery has committed state to preserve.
    for _ in 0..3 {
        assert!(!cc.note_initiation(1_000));
    }
    let counted_before = cc.load.lock().unwrap().count;
    assert_eq!(counted_before, 3, "precondition: three arrivals recorded");

    poison_mutex(&cc.load);

    assert!(
        !cc.note_initiation(1_000),
        "the load gate must still answer after poison recovery"
    );
    assert_eq!(
        cc.load.lock().unwrap_or_else(|e| e.into_inner()).count,
        4,
        "recovery must extend the COMMITTED window, not restart it"
    );
}

/// #6422: the rotating cookie secret. `with_secrets()` is on the path of
/// every cookie-reply build and every MAC2 verification; panicking there
/// forever would disable MAC2 for the tunnel. Recovery cannot weaken the
/// #4094 BUG-2 fail-closed posture, because `secure` is only ever set to
/// `true` AFTER a fresh secret has been written. #9918 F-145: the secrets
/// no longer escape as bare copies, so this pins the SAME-secret property
/// via the derived cookie (same secret → same cookie for same src/now).
#[test]
fn secrets_recovers_poisoned_secret_lock_6422() {
    use crate::afxdp::wg::poison_tests::poison_mutex;
    let our_pub = [0x22u8; 32];
    let cc = CookieChecker::new(&our_pub);
    let peer = src(51820);
    let first = cc.cookie_for_test(peer, 10_000);

    poison_mutex(&cc.secret);

    let after = cc.cookie_for_test(peer, 10_000);
    assert_eq!(
        first, after,
        "recovery must return the SAME committed secret — a fresh one \
         would invalidate every cookie already handed out"
    );
    let init = valid_mac1_init(&our_pub, 0x1234);
    let mut out = [0u8; 128];
    assert!(
        cc.build_cookie_reply(&init, src(51820), 10_000, &mut out)
            .is_ok(),
        "the cookie-reply path must still function after recovery"
    );
}

/// #5191 (A1-b9-F5): a CookieReply whose RESERVED bytes are nonzero is NOT
/// canonical. WG transmits `message_type` as a little-endian u32 and kernel
/// WG / wireguard-go compare all four bytes, so accepting a reply on the low
/// byte alone was a parser differential: xpf would consume (and act on) a
/// cookie challenge that every other implementation drops. The type-word check
/// is shared with the handshake parser (`handshake::is_canonical_type`), so
/// the two cannot drift.
///
/// FAIL-ON-REVERT: compare `reply[0] != WG_TYPE_COOKIE` again and each
/// nonzero-reserved variant below decrypts successfully.
#[test]
fn cookie_reply_rejects_noncanonical_type_word_5191() {
    let our_pub = [0x55u8; 32];
    let cc = CookieChecker::new(&our_pub);
    let now = 10_000_000_000;
    let peer = src(51820);
    let init = valid_mac1_init(&our_pub, 11);
    let mut reply = [0u8; 64];
    cc.build_cookie_reply(&init, peer, now, &mut reply).unwrap();
    let aad = &init[M1_MAC1..M1_MAC2];

    assert!(
        CookieChecker::decrypt_cookie_reply(&reply, &our_pub, aad).is_some(),
        "the canonical reply must still decrypt"
    );

    for byte in 1..4usize {
        let mut tampered = reply;
        tampered[byte] = 0x01;
        assert!(
            CookieChecker::decrypt_cookie_reply(&tampered, &our_pub, aad).is_none(),
            "reserved byte {byte} = 0x01 was accepted — the type word is not compared as a full u32"
        );
    }

    // The low byte still gates on its own.
    let mut wrong_type = reply;
    wrong_type[0] = WG_TYPE_COOKIE + 1;
    assert!(CookieChecker::decrypt_cookie_reply(&wrong_type, &our_pub, aad).is_none());
}
