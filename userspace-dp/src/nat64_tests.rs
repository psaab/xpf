// Tests for nat64.rs — relocated from inline
// `#[cfg(test)] mod tests` to keep nat64.rs under the modularity-discipline
// LOC threshold. Loaded as a sibling submodule via
// `#[path = "nat64_tests.rs"]` from nat64.rs.

use super::*;
// #7899: the fragment-association cache moved to `crate::fragment_assoc`. The
// 55 frag tests in this file were NOT moved with it -- they are interleaved with
// 119 non-frag NAT64 tests across 7000 lines, and extracting them is a separate
// change with its own risk (a mis-placed insertion between a doc comment and its
// `fn` silently steals the `#[test]` attribute). Imported here instead so the
// move stays motion-only and no guard changes.
use crate::fragment_assoc::{
    FragAuthority, FRAG_CAP_PER_SHARD, NAT64_FRAG_CROSS_DOMAIN_MISSES,
    NAT64_FRAG_PROTOCOL_ALIAS_MISSES, FRAG_SHARDS, FRAG_TTL_NS, FragAssoc,
    FragKey, frag_shard_index, first_fragment_key,
    nonfirst_fragment_key,
};

/// #5798: a fixed ingress authority for fragment-key tests that are not ABOUT
/// the authority. `frag_other_authority` mints a DIFFERENT domain so a test can
/// assert the cross-domain miss.
fn frag_test_authority() -> FragAuthority {
    FragAuthority {
        ingress_ifindex: 11,
        ingress_vlan_id: 0,
        ingress_zone: 3,
        routing_table: 0,
    }
}

/// #5798: an authority for a DIFFERENT ingress domain (a second logical
/// interface in a second zone) — the neighbouring domain's view.
fn frag_other_authority() -> FragAuthority {
    FragAuthority {
        ingress_ifindex: 22,
        ingress_vlan_id: 0,
        ingress_zone: 9,
        routing_table: 0,
    }
}

fn well_known_prefix() -> NAT64RuleSnapshot {
    NAT64RuleSnapshot {
        name: "nat64-wkp".to_string(),
        prefix: "64:ff9b::/96".to_string(),
        pool_addresses: vec!["198.51.100.1".to_string(), "198.51.100.2".to_string()],
        no_v6_frag_header: false,
        ..Default::default()
    }
}

#[test]
fn parse_well_known_prefix() {
    let state = Nat64State::from_snapshots(&[well_known_prefix()]);
    assert!(state.is_active());
    assert_eq!(state.prefixes.len(), 1);
    assert_eq!(
        state.prefixes[0].prefix_bytes,
        [0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0],
    );
    assert_eq!(state.prefixes[0].pool_v4.len(), 2);
}

#[test]
fn match_ipv6_dest_extracts_v4() {
    let state = Nat64State::from_snapshots(&[well_known_prefix()]);
    // 64:ff9b::198.51.100.50 = 64:ff9b::c633:6432
    let dst: Ipv6Addr = "64:ff9b::c633:6432".parse().unwrap();
    let (idx, v4) = state.match_ipv6_dest(dst).expect("should match");
    assert_eq!(idx, 0);
    assert_eq!(v4, Ipv4Addr::new(198, 51, 100, 50));
}

#[test]
fn match_ipv6_dest_no_match() {
    let state = Nat64State::from_snapshots(&[well_known_prefix()]);
    let dst: Ipv6Addr = "2001:db8::1".parse().unwrap();
    assert!(state.match_ipv6_dest(dst).is_none());
}

#[test]
fn pool_allocation_round_robin() {
    let state = Nat64State::from_snapshots(&[well_known_prefix()]);
    let a1 = state.allocate_v4_source(0).expect("alloc1");
    let a2 = state.allocate_v4_source(0).expect("alloc2");
    let a3 = state.allocate_v4_source(0).expect("alloc3");
    assert_eq!(a1, Ipv4Addr::new(198, 51, 100, 1));
    assert_eq!(a2, Ipv4Addr::new(198, 51, 100, 2));
    assert_eq!(a3, Ipv4Addr::new(198, 51, 100, 1)); // wraps
}

#[test]
fn empty_pool_returns_none() {
    let state = Nat64State::from_snapshots(&[NAT64RuleSnapshot {
        name: "no-pool".to_string(),
        prefix: "64:ff9b::/96".to_string(),
        pool_addresses: vec![],
        no_v6_frag_header: false,
            ..Default::default()
    }]);
    assert!(state.allocate_v4_source(0).is_none());
}

// #4559 mode-2 (NAPT64) RED-on-revert: a NAT64 rule whose source pool carries
// `port deterministic` with an enforced IPv6 host builds a deterministic prefix
// and `allocate_source` maps each IPv6 subscriber to its FIXED external IPv4 +
// port block — NOT round-robin. Neutralizing the `deterministic_v6` gate in
// `allocate_source` (falling back to `allocate_nat64_pool_port`) turns this RED:
// the first flow would round-robin to a cursor-start port (1024), outside the
// subscriber's computed block [3584,4095], and subscriber B would not land on
// its own computed pool IP.
#[test]
fn napt64_deterministic_v6_routes_through_block_allocator() {
    let det_snap = NAT64RuleSnapshot {
        name: "napt64-cgn".to_string(),
        prefix: "64:ff9b::/96".to_string(),
        pool_addresses: vec![
            "198.51.100.1".to_string(),
            "198.51.100.2".to_string(),
            "198.51.100.3".to_string(),
            "198.51.100.4".to_string(),
        ],
        no_v6_frag_header: false,
        // NAT64 fixed range 1024..=65535 => 64512 ports; block 512 => bpi 126.
        deterministic_block_size: 512,
        deterministic_blocks_per_ip: 126,
        deterministic_host_prefix_len: 32,
        deterministic_host_base_v6: "2001:db8::".to_string(),
    };
    let state = Nat64State::from_snapshots(&[det_snap]);
    assert!(
        state.prefixes[0].deterministic_v6.is_some(),
        "an enforced IPv6-host deterministic NAT64 snapshot must build a deterministic prefix"
    );

    let dst_v4 = Ipv4Addr::new(203, 0, 113, 9);
    let alloc = |src: &str, sport: u16| -> (Ipv4Addr, u16) {
        state
            .allocate_source(0, PROTO_TCP, src.parse().expect("src"), dst_v4, sport, 443, 0)
            .expect("deterministic NAPT64 allocation")
    };

    // Subscriber A = 2001:db8:0:5:: -> word 5 -> ip_idx 0, block_idx 5,
    // block [3584,4095], pool[0] (198.51.100.1).
    let (a_ip, a_port) = alloc("2001:db8:0:5::", 40001);
    assert_eq!(a_ip, Ipv4Addr::new(198, 51, 100, 1), "subscriber A -> deterministic pool IP");
    assert!(
        (3584..=4095).contains(&a_port),
        "subscriber A port {a_port} must fall in its deterministic block [3584,4095] (RED under round-robin)"
    );

    // Same subscriber, a distinct flow -> same IP + block, distinct port.
    let (a2_ip, a2_port) = alloc("2001:db8:0:5::", 40002);
    assert_eq!(a2_ip, a_ip, "same subscriber keeps its deterministic pool IP");
    assert!((3584..=4095).contains(&a2_port), "second flow stays in block");
    assert_ne!(a_port, a2_port, "two flows in one block get distinct ports");

    // Subscriber B = 2001:db8:0:100:: -> word 256 -> ip_idx 2, block_idx 4,
    // block [3072,3583], pool[2] (198.51.100.3).
    let (b_ip, b_port) = alloc("2001:db8:0:100::", 50001);
    assert_eq!(b_ip, Ipv4Addr::new(198, 51, 100, 3), "subscriber B -> a DIFFERENT deterministic pool IP");
    assert!(
        (3072..=3583).contains(&b_port),
        "subscriber B port {b_port} must fall in its deterministic block [3072,3583]"
    );
}

// #4559 companion: a NAT64 rule whose source pool has NO `port deterministic`
// stanza builds a NON-deterministic prefix (`deterministic_v6 == None`) and
// round-robins as before — guards the gate so mode 2 never engages for a plain
// NAT64 pool.
#[test]
fn napt64_without_deterministic_stays_round_robin() {
    let state = Nat64State::from_snapshots(&[well_known_prefix()]);
    assert!(
        state.prefixes[0].deterministic_v6.is_none(),
        "a NAT64 pool without `port deterministic` must not build a deterministic prefix"
    );
    // Round-robin allocate_source hands out a pool member at the cursor-start
    // port (the pool address is hash-selected from the subscriber, so assert
    // membership + the port, not a fixed index).
    let (ip, port) = state
        .allocate_source(0, PROTO_TCP, "2001:db8::1".parse().unwrap(), Ipv4Addr::new(203, 0, 113, 9), 40001, 443, 0)
        .expect("round-robin allocation");
    assert!(
        [Ipv4Addr::new(198, 51, 100, 1), Ipv4Addr::new(198, 51, 100, 2)].contains(&ip),
        "round-robin picks a pool member"
    );
    assert_eq!(port, 1024, "round-robin allocates from the cursor start (port_low)");
}

/// #7413: serialises the two tests that assert on `DETERMINISTIC_V6_DOWNGRADE_COUNT`.
///
/// That counter is PRODUCTION state (`nat64.rs`, bumped on the real
/// downgrade path), not test-only, so the `thread_local!` pattern
/// `docs/engineering-style.md` gives for test-only globals does NOT apply here
/// — making it thread-local would break the product, because the increment
/// happens on whichever thread compiles the snapshot and a status reader on
/// another thread would see zero. The settled pattern for a genuinely shared
/// global is this: a poison-tolerant serial guard held for the whole body by
/// every test that touches it.
///
/// Both tests already read a RELATIVE delta (`before + 1`), which is correct in
/// isolation and still wrong concurrently: each sees the other's increment and
/// asserts `left: 2, right: 1`. Reproduced 6 of 6 runs at `--test-threads=2`.
///
/// EXACTLY TWO tests bump the counter, established by running all 4549 tests in
/// the binary alone and watching for the paired operator warning rather than by
/// reading call sites — so this guard covers the whole population, not the part
/// that was easy to find.
fn deterministic_v6_downgrade_test_lock() -> std::sync::MutexGuard<'static, ()> {
    use std::sync::Mutex;
    static LOCK: Mutex<()> = Mutex::new(());
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

// #4559: an IPv6-host deterministic NAT64 snapshot with an UNSUPPORTED prefix
// length (only /32 and /64 map to a 32-bit subscriber word) does NOT build a
// deterministic prefix — it round-robins (the commit-time advisory covers it).
#[test]
fn napt64_deterministic_v6_unsupported_prefix_len_falls_back() {
    let _downgrade_serial = deterministic_v6_downgrade_test_lock();
    let before = DETERMINISTIC_V6_DOWNGRADE_COUNT.load(Ordering::Relaxed);
    let state = Nat64State::from_snapshots(&[NAT64RuleSnapshot {
        name: "napt64-bad-prefix".to_string(),
        prefix: "64:ff9b::/96".to_string(),
        pool_addresses: vec!["198.51.100.1".to_string()],
        no_v6_frag_header: false,
        deterministic_block_size: 512,
        deterministic_blocks_per_ip: 126,
        deterministic_host_prefix_len: 48, // unsupported
        deterministic_host_base_v6: "2001:db8::".to_string(),
    }]);
    assert!(
        state.prefixes[0].deterministic_v6.is_none(),
        "an unsupported subscriber-prefix length must not build a deterministic prefix"
    );
    assert_eq!(
        DETERMINISTIC_V6_DOWNGRADE_COUNT.load(Ordering::Relaxed),
        before + 1,
        "#6227 item 1: a requested-but-failed deterministic build must bump the \
         downgrade counter, not silently round-robin"
    );
}

// #6227 item 1, RED-on-revert: `build_deterministic_v6`'s `host_count =
// num_pool_ips.checked_mul(blocks_per_ip)` overflows `u32` when the pool is
// large enough relative to the per-IP block count, returning `None` exactly
// like every other "not deterministic" case — a subscriber's mapping silently
// stops being deterministic. Before the #6227 fix this was unobservable
// (silent round-robin fallback, no signal at all); the fix bumps
// `DETERMINISTIC_V6_DOWNGRADE_COUNT` (and emits a paired `eprintln!`) whenever
// the rule DID request deterministic mapping but the build failed. Reverting
// just the new `if deterministic_v6.is_none() && ...` guard in
// `from_snapshots_with_previous` turns this RED: the prefix still round-robins
// (silently), but the counter no longer moves.
#[test]
fn napt64_deterministic_v6_host_count_overflow_warns_operator() {
    let _downgrade_serial = deterministic_v6_downgrade_test_lock();
    let before = DETERMINISTIC_V6_DOWNGRADE_COUNT.load(Ordering::Relaxed);
    // blocks_per_ip at its u16 max; a 70_000-entry pool makes
    // `num_pool_ips * blocks_per_ip` (70_000 * 65_535 ≈ 4.59e9) exceed
    // `u32::MAX` (≈4.29e9) — `checked_mul` returns `None`.
    let pool_addresses = vec!["203.0.113.1".to_string(); 70_000];
    let state = Nat64State::from_snapshots(&[NAT64RuleSnapshot {
        name: "napt64-overflow".to_string(),
        prefix: "64:ff9b::/96".to_string(),
        pool_addresses,
        no_v6_frag_header: false,
        deterministic_block_size: 512,
        deterministic_blocks_per_ip: u16::MAX,
        deterministic_host_prefix_len: 32,
        deterministic_host_base_v6: "2001:db8::".to_string(),
    }]);
    assert!(
        state.prefixes[0].deterministic_v6.is_none(),
        "a host_count u32 overflow must not build a deterministic prefix"
    );
    assert_eq!(
        DETERMINISTIC_V6_DOWNGRADE_COUNT.load(Ordering::Relaxed),
        before + 1,
        "#6227 item 1: a checked_mul overflow must be counted/warned, not silent"
    );
}

#[test]
fn nat64_pool_with_cidr_mask_yields_nonempty_pool() {
    // #2123: a range-form source pool (`address A to B`) is expanded by the
    // Go compiler into per-IP /32 entries. Ipv4Addr::from_str rejects the
    // mask, so pre-fix the filter_map discarded every entry, leaving pool_v4
    // empty and allocate_v4_source returning None. The parse must strip the
    // /32 mask. This test FAILS on the unfixed code.
    let state = Nat64State::from_snapshots(&[NAT64RuleSnapshot {
        name: "nat64-range".to_string(),
        prefix: "64:ff9b::/96".to_string(),
        pool_addresses: vec![
            "100.64.0.1/32".to_string(),
            "100.64.0.2/32".to_string(),
        ],
        no_v6_frag_header: false,
            ..Default::default()
    }]);
    assert!(state.is_active());
    assert_eq!(
        state.prefixes[0].pool_v4.len(),
        2,
        "range-expanded /32 pool addresses must parse, not be dropped"
    );
    // Round-robin allocation must now succeed (was None pre-fix).
    let a1 = state.allocate_v4_source(0).expect("alloc1");
    let a2 = state.allocate_v4_source(0).expect("alloc2");
    let a3 = state.allocate_v4_source(0).expect("alloc3 wraps");
    assert_eq!(a1, Ipv4Addr::new(100, 64, 0, 1));
    assert_eq!(a2, Ipv4Addr::new(100, 64, 0, 2));
    assert_eq!(a3, Ipv4Addr::new(100, 64, 0, 1));
}

#[test]
fn nat64_pool_mixed_bare_and_masked() {
    // Discrete bare-IP `address` lines and range-expanded /32 entries must
    // coexist: stripping the mask must not break the bare-IP parse.
    let state = Nat64State::from_snapshots(&[NAT64RuleSnapshot {
        name: "nat64-mixed".to_string(),
        prefix: "64:ff9b::/96".to_string(),
        pool_addresses: vec![
            "198.51.100.1".to_string(),
            "198.51.100.5/32".to_string(),
        ],
        no_v6_frag_header: false,
            ..Default::default()
    }]);
    assert_eq!(state.prefixes[0].pool_v4.len(), 2);
    assert!(state.prefixes[0].pool_v4.contains(&Ipv4Addr::new(198, 51, 100, 1)));
    assert!(state.prefixes[0].pool_v4.contains(&Ipv4Addr::new(198, 51, 100, 5)));
}

#[test]
fn nat64_pool_genuinely_invalid_skips_rule() {
    // #2212/#3888: a genuinely-malformed pool address SKIPS the WHOLE rule
    // (all-or-nothing), NOT narrowing the pool to just the good entries and NOT
    // aborting the whole forwarding rebuild. Skipping the whole rule preserves
    // #2212's anti-silent-narrowing intent — the surviving `100.64.0.7` must
    // NOT install a pool-of-one — while #3888 scopes the blast radius to this
    // one rule.
    //
    // FAIL-ON-REVERT: reverting #3888 restores the fallible
    // `try_from_snapshots -> Result` that returns `Err(Nat64UnparseableRule)`;
    // the infallible `from_snapshots` wrapper then `.expect()`-PANICS on this
    // bad rule, so this test PANICS (RED). Reverting further to the pre-#2212
    // `filter_map` would install pool_v4 == [100.64.0.7] (pool-of-one) — the
    // `prefixes.is_empty()` assert FAILS.
    let state = Nat64State::from_snapshots(&[NAT64RuleSnapshot {
        name: "nat64-bad".to_string(),
        prefix: "64:ff9b::/96".to_string(),
        pool_addresses: vec![
            "not-an-ip".to_string(),
            "100.64.0.7/32".to_string(),
        ],
        no_v6_frag_header: false,
            ..Default::default()
    }]);
    assert!(
        !state.is_active() && state.prefixes.is_empty(),
        "a malformed pool address must skip the WHOLE rule, not narrow the pool"
    );
}

#[test]
fn nat64_pool_non_host_mask_skips_rule() {
    // #2212/#3888: a non-host mask or garbage suffix on a pool address SKIPS
    // the WHOLE rule (fail-scoped), not narrowing it to the valid /32 alongside
    // and not aborting the rebuild. Each malformed form independently skips.
    for bad in [
        "100.64.0.1/24",      // non-host prefix
        "100.64.0.2/notanum", // non-numeric mask
        "100.64.0.3/",        // empty mask
        "100.64.0.4//32",     // double slash
    ] {
        let state = Nat64State::from_snapshots(&[NAT64RuleSnapshot {
            name: "nat64-bad-mask".to_string(),
            prefix: "64:ff9b::/96".to_string(),
            pool_addresses: vec![bad.to_string(), "100.64.0.9/32".to_string()],
            no_v6_frag_header: false,
                    ..Default::default()
        }]);
        assert!(
            !state.is_active() && state.prefixes.is_empty(),
            "malformed pool entry {bad:?} must skip the whole rule, got {} prefixes",
            state.prefixes.len()
        );
    }
    // Verify the canonical /32-only pool DOES install (the good path still works).
    let ok = Nat64State::from_snapshots(&[NAT64RuleSnapshot {
        name: "nat64-good-mask".to_string(),
        prefix: "64:ff9b::/96".to_string(),
        pool_addresses: vec!["100.64.0.9/32".to_string()],
        no_v6_frag_header: false,
            ..Default::default()
    }]);
    assert_eq!(ok.prefixes[0].pool_v4, vec![Ipv4Addr::new(100, 64, 0, 9)]);
}

#[test]
fn invalid_prefix_length_skips_rule() {
    // #2212/#3888: a non-/96 prefix length SKIPS the rule (fail-scoped),
    // leaving it absent at the dataplane WITHOUT aborting the whole rebuild.
    let state = Nat64State::from_snapshots(&[NAT64RuleSnapshot {
        name: "bad".to_string(),
        prefix: "64:ff9b::/64".to_string(),
        pool_addresses: vec!["1.2.3.4".to_string()],
        no_v6_frag_header: false,
            ..Default::default()
    }]);
    assert!(
        !state.is_active() && state.prefixes.is_empty(),
        "a non-/96 prefix must skip the rule, got {} prefixes",
        state.prefixes.len()
    );
}

#[test]
fn empty_prefix_skips_rule() {
    // #2212/#3888: an empty prefix is anomalous (the Go side never emits one)
    // and SKIPS the rule rather than aborting the whole rebuild.
    let state = Nat64State::from_snapshots(&[NAT64RuleSnapshot {
        name: "empty-prefix".to_string(),
        prefix: String::new(),
        pool_addresses: vec!["198.51.100.1".to_string()],
        no_v6_frag_header: false,
            ..Default::default()
    }]);
    assert!(
        !state.is_active() && state.prefixes.is_empty(),
        "an empty prefix must skip the rule, got {} prefixes",
        state.prefixes.len()
    );
}

#[test]
fn malformed_prefix_address_skips_rule() {
    // #2212/#3888: a /96-masked but unparseable prefix address SKIPS the rule
    // (was silently `continue`d pre-#2212, aborted the rebuild #2212..#3888).
    let state = Nat64State::from_snapshots(&[NAT64RuleSnapshot {
        name: "bad-addr".to_string(),
        prefix: "not:an:ipv6::garbage::x/96".to_string(),
        pool_addresses: vec!["198.51.100.1".to_string()],
        no_v6_frag_header: false,
            ..Default::default()
    }]);
    assert!(!state.is_active() && state.prefixes.is_empty());
}

#[test]
fn extra_slash_prefix_skips_rule() {
    // #3888 backstop hardening (Copilot): the corrupt/lenient-snapshot parse
    // must require EXACTLY `<ipv6>/96`. A prefix with an EXTRA slash —
    // "64:ff9b::/96/garbage" → split('/') = ["64:ff9b::", "96", "garbage"] —
    // must be SKIPPED as malformed, NOT accepted with the trailing garbage
    // silently ignored (parts[1]=="96" parses fine, parts[0]=="64:ff9b::"
    // parses fine).
    //
    // FAIL-ON-REVERT: reverting the `parts.len() != 2` check makes the old
    // `parts.get(1)`-only match accept this as a valid /96 → 1 published
    // prefix, so `prefixes.is_empty()` FAILS (RED).
    let state = Nat64State::from_snapshots(&[NAT64RuleSnapshot {
        name: "extra-slash".to_string(),
        prefix: "64:ff9b::/96/garbage".to_string(),
        pool_addresses: vec!["198.51.100.1".to_string()],
        no_v6_frag_header: false,
            ..Default::default()
    }]);
    assert!(
        !state.is_active() && state.prefixes.is_empty(),
        "an extra-slash prefix must skip the rule, got {} prefixes",
        state.prefixes.len()
    );
    // Control: the well-formed exact-2-parts prefix still publishes.
    let ok = Nat64State::from_snapshots(&[NAT64RuleSnapshot {
        name: "good".to_string(),
        prefix: "64:ff9b::/96".to_string(),
        pool_addresses: vec!["198.51.100.1".to_string()],
        no_v6_frag_header: false,
            ..Default::default()
    }]);
    assert!(ok.is_active() && ok.prefixes.len() == 1);
}

#[test]
fn valid_nat64_rule_still_applies() {
    // #2212/#3888 companion: a wholly valid NAT64 config must still apply
    // cleanly through the infallible path (the fail-scoped skip does not
    // over-drop a valid rule).
    let state = Nat64State::from_snapshots(&[well_known_prefix()]);
    assert!(state.is_active());
    assert_eq!(state.prefixes.len(), 1);
    assert_eq!(state.prefixes[0].pool_v4.len(), 2);
    // And it translates a forward packet (proves the rule reached the
    // translator, not just parsed).
    let src_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::c633:6432".parse().unwrap();
    let (idx, dst_v4) = state.match_ipv6_dest(dst_v6).expect("dst must match prefix");
    let snat = state.allocate_v4_source(idx).expect("pool must allocate");
    let pkt = make_ipv6_tcp_packet(src_v6, dst_v6, 12345, 80, b"ok");
    let v4 = translate_v6_to_v4(&pkt, snat, dst_v4, false).expect("forward translate");
    assert_eq!(v4[0], 0x45);
    assert_eq!(checksum16(&v4[..20]), 0, "header checksum must verify");
}

#[test]
fn nat64_mixed_good_bad_good_publishes_good_rules() {
    // #3888 RED-ON-REVERT GUARD: a snapshot of [good, BAD, good] NAT64 rules
    // must build the TWO good rules and SKIP the one bad rule — a bad NAT64
    // rule is a NAT64-only degradation, not a total forwarding freeze. The bad
    // rule leaves no gap: the survivors keep their relative order.
    //
    // FAIL-ON-REVERT: reverting #3888 restores the fallible
    // `try_from_snapshots -> Result` returning `Err(Nat64UnparseableRule)` on
    // the bad rule; the infallible `from_snapshots` wrapper then
    // `.expect()`-PANICS, so this test PANICS (RED) instead of observing the
    // two published prefixes. This is the direct analogue of the whole-rebuild
    // abort the fix removes (`Nat64State::from_snapshots` is called
    // unconditionally inside `build_reconcile_forwarding`; a returned Err there
    // froze every other rule type and every later commit).
    let good_a = NAT64RuleSnapshot {
        name: "good-a".to_string(),
        prefix: "64:ff9b::/96".to_string(),
        pool_addresses: vec!["198.51.100.1".to_string()],
        no_v6_frag_header: false,
            ..Default::default()
    };
    let bad = NAT64RuleSnapshot {
        name: "bad".to_string(),
        prefix: "64:ff9b:1::/64".to_string(), // non-/96 => skipped
        pool_addresses: vec!["198.51.100.2".to_string()],
        no_v6_frag_header: false,
            ..Default::default()
    };
    let good_b = NAT64RuleSnapshot {
        name: "good-b".to_string(),
        prefix: "2001:db8:64::/96".to_string(),
        pool_addresses: vec!["203.0.113.9".to_string()],
        no_v6_frag_header: false,
            ..Default::default()
    };
    let state = Nat64State::from_snapshots(&[good_a, bad, good_b]);
    assert!(state.is_active());
    assert_eq!(
        state.prefixes.len(),
        2,
        "the two good NAT64 rules must publish; the bad one is skipped"
    );
    // The survivors are the two good rules, in order — the bad rule left no gap.
    assert_eq!(
        state.prefixes[0].prefix_bytes,
        [0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0],
    );
    assert_eq!(
        state.prefixes[0].pool_v4,
        vec![Ipv4Addr::new(198, 51, 100, 1)]
    );
    assert_eq!(
        state.prefixes[1].pool_v4,
        vec![Ipv4Addr::new(203, 0, 113, 9)]
    );
}

// --- Packet translation tests ---

fn make_ipv6_tcp_packet(
    src: Ipv6Addr,
    dst: Ipv6Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let tcp_len = 20 + payload.len();
    let mut pkt = vec![0u8; 40 + tcp_len];
    // IPv6 header
    pkt[0] = 0x60;
    pkt[4..6].copy_from_slice(&(tcp_len as u16).to_be_bytes());
    pkt[6] = PROTO_TCP;
    pkt[7] = 64; // hop limit
    pkt[8..24].copy_from_slice(&src.octets());
    pkt[24..40].copy_from_slice(&dst.octets());
    // TCP header (minimal)
    pkt[40..42].copy_from_slice(&src_port.to_be_bytes());
    pkt[42..44].copy_from_slice(&dst_port.to_be_bytes());
    pkt[52] = 0x50; // data offset = 5 (20 bytes)
    pkt[53] = 0x02; // SYN
    pkt[54..56].copy_from_slice(&1024u16.to_be_bytes()); // window
                                                         // Copy payload
    pkt[60..60 + payload.len()].copy_from_slice(payload);
    // Compute TCP checksum
    pkt[56..58].copy_from_slice(&[0, 0]);
    let sum = checksum16_ipv6_pseudo(src, dst, PROTO_TCP, &pkt[40..]);
    pkt[56..58].copy_from_slice(&sum.to_be_bytes());
    pkt
}

fn make_ipv4_tcp_packet(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let tcp_len = 20 + payload.len();
    let total_len = 20 + tcp_len;
    let mut pkt = vec![0u8; total_len];
    // IPv4 header
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    pkt[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // DF
    pkt[8] = 64; // TTL
    pkt[9] = PROTO_TCP;
    pkt[12..16].copy_from_slice(&src.octets());
    pkt[16..20].copy_from_slice(&dst.octets());
    // TCP header
    pkt[20..22].copy_from_slice(&src_port.to_be_bytes());
    pkt[22..24].copy_from_slice(&dst_port.to_be_bytes());
    pkt[32] = 0x50; // data offset = 5
    pkt[33] = 0x12; // SYN+ACK
    pkt[34..36].copy_from_slice(&1024u16.to_be_bytes());
    pkt[40..40 + payload.len()].copy_from_slice(payload);
    // Compute checksums
    pkt[10..12].copy_from_slice(&[0, 0]);
    let ip_sum = checksum16(&pkt[..20]);
    pkt[10..12].copy_from_slice(&ip_sum.to_be_bytes());
    pkt[36..38].copy_from_slice(&[0, 0]);
    let tcp_sum = checksum16_ipv4_pseudo(src, dst, PROTO_TCP, &pkt[20..]);
    pkt[36..38].copy_from_slice(&tcp_sum.to_be_bytes());
    pkt
}

#[test]
fn translate_v6_to_v4_tcp() {
    let src_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::c633:6432".parse().unwrap();
    let snat_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let dst_v4 = Ipv4Addr::new(198, 51, 100, 50);

    let ipv6_pkt = make_ipv6_tcp_packet(src_v6, dst_v6, 12345, 80, b"hello");
    let ipv4_pkt = translate_v6_to_v4(&ipv6_pkt, snat_v4, dst_v4, false).expect("translate");

    // Verify IPv4 header.
    assert_eq!(ipv4_pkt[0], 0x45);
    assert_eq!(ipv4_pkt[8], 63); // TTL = 64-1
    assert_eq!(ipv4_pkt[9], PROTO_TCP);
    assert_eq!(&ipv4_pkt[12..16], &snat_v4.octets());
    assert_eq!(&ipv4_pkt[16..20], &dst_v4.octets());

    // Verify size: IPv6 was 40+25=65, IPv4 should be 20+25=45.
    assert_eq!(ipv4_pkt.len(), 45);

    // Verify TCP ports preserved.
    assert_eq!(u16::from_be_bytes([ipv4_pkt[20], ipv4_pkt[21]]), 12345);
    assert_eq!(u16::from_be_bytes([ipv4_pkt[22], ipv4_pkt[23]]), 80);

    // Verify IPv4 header checksum.
    assert_eq!(checksum16(&ipv4_pkt[..20]), 0);

    // Verify TCP checksum.
    let tcp_payload = &ipv4_pkt[20..];
    let src = Ipv4Addr::new(ipv4_pkt[12], ipv4_pkt[13], ipv4_pkt[14], ipv4_pkt[15]);
    let dst = Ipv4Addr::new(ipv4_pkt[16], ipv4_pkt[17], ipv4_pkt[18], ipv4_pkt[19]);
    assert_eq!(checksum16_ipv4_pseudo(src, dst, PROTO_TCP, tcp_payload), 0);
}

// ---------------------------------------------------------------------------
// #5625: RFC 7915 §5.1 translation-eligibility gate. A v6→v4 NAT64 forward
// translation MUST NOT silently strip/translate an Authentication Header (AH),
// an ACTIVE Routing header (Segments Left > 0), or a Mobility / HIP / Shim6
// header. These tests pin the fail-closed reject (and, as the over-reject
// guard, that Hop-by-Hop / Destination Options / Routing-SL0 / plain packets
// STILL translate). They go RED if the gate in `write_v6_to_v4_into` is removed
// (the walker would then resolve the inner L4 and translation would proceed).
// ---------------------------------------------------------------------------

/// Build an L3 IPv6 packet: fixed header (Next Header = `first_ext`) followed by
/// one extension-header block `ext` (whose own byte[0] Next Header MUST point at
/// the TCP that follows) and then a minimal TCP segment. Used by the #5625
/// eligibility tests.
fn make_ipv6_ext_then_tcp(
    src: Ipv6Addr,
    dst: Ipv6Addr,
    first_ext: u8,
    ext: &[u8],
) -> Vec<u8> {
    let payload = b"hi";
    let tcp_len = 20 + payload.len();
    let total = 40 + ext.len() + tcp_len;
    let mut pkt = vec![0u8; total];
    pkt[0] = 0x60;
    pkt[4..6].copy_from_slice(&((ext.len() + tcp_len) as u16).to_be_bytes());
    pkt[6] = first_ext;
    pkt[7] = 64; // hop limit
    pkt[8..24].copy_from_slice(&src.octets());
    pkt[24..40].copy_from_slice(&dst.octets());
    // Extension-header block (its byte[0] chains to TCP).
    pkt[40..40 + ext.len()].copy_from_slice(ext);
    // Minimal TCP header + payload.
    let t = 40 + ext.len();
    pkt[t..t + 2].copy_from_slice(&12345u16.to_be_bytes());
    pkt[t + 2..t + 4].copy_from_slice(&80u16.to_be_bytes());
    pkt[t + 12] = 0x50; // data offset = 5
    pkt[t + 13] = 0x02; // SYN
    pkt[t + 14..t + 16].copy_from_slice(&1024u16.to_be_bytes());
    pkt[t + 20..t + 20 + payload.len()].copy_from_slice(payload);
    // Valid TCP checksum over the TCP region (IPv6 pseudo-header).
    pkt[t + 16..t + 18].copy_from_slice(&[0, 0]);
    let sum = checksum16_ipv6_pseudo(src, dst, PROTO_TCP, &pkt[t..]);
    pkt[t + 16..t + 18].copy_from_slice(&sum.to_be_bytes());
    pkt
}

fn nat64_test_addrs() -> (Ipv6Addr, Ipv6Addr, Ipv4Addr, Ipv4Addr) {
    let src_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::c633:6432".parse().unwrap();
    let snat_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let dst_v4 = Ipv4Addr::new(198, 51, 100, 50);
    (src_v6, dst_v6, snat_v4, dst_v4)
}

/// (a) An AH-bearing v6 packet to a NAT64 prefix is DROPPED (not translated).
/// RFC 7915 §5.1.1: a packet whose header chain includes AH "SHOULD be dropped
/// and logged" — AH's ICV covers IP fields NAT64 rewrites, so a translated
/// packet carries a broken ICV. RED if the gate is removed (the walker skips
/// AH per RFC 4302 length math and resolves the inner TCP → translated).
#[test]
fn nat64_5625_ah_bearing_v6_is_dropped_not_translated() {
    let (src_v6, dst_v6, snat_v4, dst_v4) = nat64_test_addrs();
    // AH (proto 51): [next=TCP, payload_len=1, resv, SPI(4), Seq(4)] = 12 bytes.
    let ah: [u8; 12] = [PROTO_TCP, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0];
    let pkt = make_ipv6_ext_then_tcp(src_v6, dst_v6, 51, &ah);
    assert!(
        translate_v6_to_v4(&pkt, snat_v4, dst_v4, false).is_none(),
        "AH-bearing v6 packet must be dropped, not translated (RFC 7915 §5.1.1)"
    );
    assert!(
        nat64_v6_translation_ineligible(&pkt),
        "AH chain must be classified translation-ineligible"
    );
}

/// (b) A Routing header with Segments Left > 0 (an active, not-yet-delivered
/// source route) is DROPPED. RFC 7915 §5.1: "If a Routing header with a
/// non-zero Segments Left field is present, then the packet MUST NOT be
/// translated". RED if the gate is removed.
#[test]
fn nat64_5625_active_routing_header_is_dropped() {
    let (src_v6, dst_v6, snat_v4, dst_v4) = nat64_test_addrs();
    // Routing (43): [next=TCP, hdr_ext_len=0, routing_type=0, segments_left=1, ...].
    let rh: [u8; 8] = [PROTO_TCP, 0, 0, 1, 0, 0, 0, 0];
    let pkt = make_ipv6_ext_then_tcp(src_v6, dst_v6, 43, &rh);
    assert!(
        translate_v6_to_v4(&pkt, snat_v4, dst_v4, false).is_none(),
        "active Routing header (SL>0) must be dropped, not translated (RFC 7915 §5.1)"
    );
    assert!(nat64_v6_translation_ineligible(&pkt));
}

/// (c) Mobility (135) / HIP (139) / Shim6 (140) headers — active end-to-end
/// extension semantics with NO IPv4 equivalent — are DROPPED, not translated
/// (which would silently strip them). RED if the gate is removed (the #4517
/// parity walker skips them and resolves the inner TCP).
#[test]
fn nat64_5625_active_extension_headers_are_dropped() {
    let (src_v6, dst_v6, snat_v4, dst_v4) = nat64_test_addrs();
    for proto in [135u8, 139u8, 140u8] {
        // 8-byte generic ext block chaining to TCP.
        let ext: [u8; 8] = [PROTO_TCP, 0, 0, 0, 0, 0, 0, 0];
        let pkt = make_ipv6_ext_then_tcp(src_v6, dst_v6, proto, &ext);
        assert!(
            translate_v6_to_v4(&pkt, snat_v4, dst_v4, false).is_none(),
            "ext header {proto} (Mobility/HIP/Shim6) must be dropped, not translated"
        );
        assert!(
            nat64_v6_translation_ineligible(&pkt),
            "ext header {proto} must be classified translation-ineligible"
        );
    }
}

/// (d) A Routing header with Segments Left == 0 is INERT (reached its final
/// destination) and STILL translates. RFC 7915 §5.1: such a header "MUST be
/// ignored ... and the packet translated normally." Guards against over-reject.
#[test]
fn nat64_5625_routing_header_sl0_still_translates() {
    let (src_v6, dst_v6, snat_v4, dst_v4) = nat64_test_addrs();
    // Routing (43) with segments_left = 0.
    let rh: [u8; 8] = [PROTO_TCP, 0, 0, 0, 0, 0, 0, 0];
    let pkt = make_ipv6_ext_then_tcp(src_v6, dst_v6, 43, &rh);
    assert!(
        !nat64_v6_translation_ineligible(&pkt),
        "Routing SL==0 is inert — must not be flagged ineligible"
    );
    let v4 = translate_v6_to_v4(&pkt, snat_v4, dst_v4, false)
        .expect("Routing SL==0 must still translate (RFC 7915 §5.1)");
    assert_eq!(v4[9], PROTO_TCP, "translated protocol must be the inner TCP");
}

/// (e) Hop-by-Hop (0) and Destination Options (60) headers STILL translate.
/// RFC 7915 §5.1: they "MUST be ignored ... and the packet translated
/// normally." Guards against over-reject.
#[test]
fn nat64_5625_hopbyhop_and_destopts_still_translate() {
    let (src_v6, dst_v6, snat_v4, dst_v4) = nat64_test_addrs();
    for proto in [0u8, 60u8] {
        let ext: [u8; 8] = [PROTO_TCP, 0, 0, 0, 0, 0, 0, 0];
        let pkt = make_ipv6_ext_then_tcp(src_v6, dst_v6, proto, &ext);
        assert!(
            !nat64_v6_translation_ineligible(&pkt),
            "ext header {proto} (HBH/Dest-Opts) must not be flagged ineligible"
        );
        let v4 = translate_v6_to_v4(&pkt, snat_v4, dst_v4, false)
            .unwrap_or_else(|| panic!("ext header {proto} must still translate"));
        assert_eq!(v4[9], PROTO_TCP);
    }
}

/// (f) A plain no-extension-header v6 TCP packet STILL translates (the common
/// fast path is unchanged by the eligibility gate).
#[test]
fn nat64_5625_plain_no_exthdr_still_translates() {
    let (src_v6, dst_v6, snat_v4, dst_v4) = nat64_test_addrs();
    let pkt = make_ipv6_tcp_packet(src_v6, dst_v6, 12345, 80, b"hello");
    assert!(!nat64_v6_translation_ineligible(&pkt));
    let v4 = translate_v6_to_v4(&pkt, snat_v4, dst_v4, false).expect("plain packet must translate");
    assert_eq!(v4[9], PROTO_TCP);
}

/// The TX-dispatcher SSOT predicate `frame_is_nat64_exthdr_ineligible` mirrors
/// the translator guard: an AH-bearing L2 frame on the forward (`AF_INET6`)
/// path is attributed, an eligible plain frame is not, and the reverse
/// (`AF_INET`) path never attributes (IPv4 has no extension headers).
#[test]
fn nat64_5625_frame_predicate_attributes_exthdr_drop() {
    let (src_v6, dst_v6, _snat, _dst) = nat64_test_addrs();
    let ah: [u8; 12] = [PROTO_TCP, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0];
    let l3_ah = make_ipv6_ext_then_tcp(src_v6, dst_v6, 51, &ah);
    let l3_plain = make_ipv6_tcp_packet(src_v6, dst_v6, 12345, 80, b"hello");
    // Prepend a 14-byte Ethernet header (EtherType 0x86DD = IPv6) so the
    // predicate's `frame_l3_offset` resolves the L3 start like a real frame.
    let mut frame_ah = vec![0u8; 14];
    frame_ah[12..14].copy_from_slice(&0x86DDu16.to_be_bytes());
    frame_ah.extend_from_slice(&l3_ah);
    let mut frame_plain = vec![0u8; 14];
    frame_plain[12..14].copy_from_slice(&0x86DDu16.to_be_bytes());
    frame_plain.extend_from_slice(&l3_plain);

    assert!(
        frame_is_nat64_exthdr_ineligible(&frame_ah, libc::AF_INET6),
        "AH frame on the forward path must be attributed to the ext-header counter"
    );
    assert!(
        !frame_is_nat64_exthdr_ineligible(&frame_plain, libc::AF_INET6),
        "an eligible plain frame must not be attributed"
    );
    assert!(
        !frame_is_nat64_exthdr_ineligible(&frame_ah, libc::AF_INET),
        "reverse v4→v6 path has no IPv6 extension headers — never attribute"
    );
}

/// #4499 A5: NAT64 translation preserves the L4 ports, so the `AppCatalog`
/// application resolution — which keys ONLY on (protocol, src_port, dst_port)
/// and is deliberately address-agnostic — yields the SAME application for the
/// original IPv6 flow and its NAT64-translated IPv4 flow. A v6 SYN to tcp/80
/// (an `junos-http`-shaped catalog entry) is translated to v4; the destination
/// service port is read back FROM the translated packet bytes and fed to
/// `AppCatalog::lookup_forward`, which must still resolve `junos-http`.
///
/// This composes `nat64::translate_v6_to_v4` (the port-copy) with
/// `policy::AppCatalog::lookup_forward` (the port-keyed resolution) as the A5
/// finding asks. Because the service port is read out of the translated frame
/// rather than hard-coded, a regression that corrupted the L4 port during
/// translation would make the lookup miss (app_id 0 / UNKNOWN) and turn this
/// RED — the exact "port not preserved across translation" failure. A no-match
/// control (a non-80 dst) and the pre-translation v6 lookup (same app, proving
/// address-independence) round out the pin.
#[test]
fn nat64_translation_preserves_port_for_appcatalog_lookup_4499() {
    const HTTP_APP_ID: u16 = 42;
    // A `junos-http`-shaped catalog: tcp, destination port 80 only.
    let catalog = crate::policy::AppCatalog::from_snapshot(&[crate::AppCatalogEntry {
        app_id: HTTP_APP_ID,
        protocol: PROTO_TCP,
        dst_port_low: 80,
        dst_port_high: 80,
        src_port_low: 0,
        src_port_high: 0,
    }]);

    let src_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::c633:6432".parse().unwrap();
    let snat_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let dst_v4 = Ipv4Addr::new(198, 51, 100, 50);
    let client_port = 12345u16;
    let http_port = 80u16;

    // Pre-translation: the IPv6 flow resolves to junos-http purely by port
    // (the catalog never sees an address), establishing the baseline.
    assert_eq!(
        catalog.lookup_forward(PROTO_TCP, client_port, http_port),
        HTTP_APP_ID,
        "the original v6 flow to tcp/80 resolves junos-http"
    );

    let ipv6_pkt = make_ipv6_tcp_packet(src_v6, dst_v6, client_port, http_port, b"GET /");
    let ipv4_pkt = translate_v6_to_v4(&ipv6_pkt, snat_v4, dst_v4, false).expect("translate");

    // Read the L4 ports back out of the TRANSLATED v4 frame (TCP header at
    // offset 20): src at 20..22, dst at 22..24. If translation corrupted them
    // the lookup below misses.
    let xlated_src_port = u16::from_be_bytes([ipv4_pkt[20], ipv4_pkt[21]]);
    let xlated_dst_port = u16::from_be_bytes([ipv4_pkt[22], ipv4_pkt[23]]);
    assert_eq!(xlated_src_port, client_port, "NAT64 preserves the source port");
    assert_eq!(xlated_dst_port, http_port, "NAT64 preserves the dst service port");

    // Post-translation: the SAME application resolves from the translated
    // ports — the NAT64'd IPv4 flow is still classified junos-http.
    assert_eq!(
        catalog.lookup_forward(PROTO_TCP, xlated_src_port, xlated_dst_port),
        HTTP_APP_ID,
        "#4499 A5: the NAT64-translated v4 flow resolves the same app (port preserved)"
    );

    // Control: a translated flow to a NON-80 port must NOT resolve junos-http
    // (proves the assertion above is port-sensitive, not a constant pass).
    assert_eq!(
        catalog.lookup_forward(PROTO_TCP, xlated_src_port, 8080),
        0,
        "a non-80 translated dst must not spuriously resolve junos-http"
    );
}

#[test]
fn translate_v4_to_v6_tcp() {
    let src_v4 = Ipv4Addr::new(198, 51, 100, 50);
    let dst_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let src_v6: Ipv6Addr = "64:ff9b::c633:6432".parse().unwrap(); // server→client reply
    let dst_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();

    let ipv4_pkt = make_ipv4_tcp_packet(src_v4, dst_v4, 80, 12345, b"world");
    let ipv6_pkt = translate_v4_to_v6(&ipv4_pkt, src_v6, dst_v6).expect("translate");

    // Verify IPv6 header.
    assert_eq!(ipv6_pkt[0] >> 4, 6);
    assert_eq!(ipv6_pkt[6], PROTO_TCP);
    assert_eq!(ipv6_pkt[7], 63); // hop limit = 64-1
    assert_eq!(&ipv6_pkt[8..24], &src_v6.octets());
    assert_eq!(&ipv6_pkt[24..40], &dst_v6.octets());

    // Verify size: IPv4 was 20+25=45, IPv6 should be 40+25=65.
    assert_eq!(ipv6_pkt.len(), 65);

    // Verify TCP ports preserved.
    assert_eq!(u16::from_be_bytes([ipv6_pkt[40], ipv6_pkt[41]]), 80);
    assert_eq!(u16::from_be_bytes([ipv6_pkt[42], ipv6_pkt[43]]), 12345);

    // Verify TCP checksum.
    let src6 = Ipv6Addr::from(<[u8; 16]>::try_from(&ipv6_pkt[8..24]).unwrap());
    let dst6 = Ipv6Addr::from(<[u8; 16]>::try_from(&ipv6_pkt[24..40]).unwrap());
    assert_eq!(
        checksum16_ipv6_pseudo(src6, dst6, PROTO_TCP, &ipv6_pkt[40..]),
        0
    );
}

#[test]
fn translate_v6_to_v4_udp() {
    let src_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::0808:0808".parse().unwrap();
    let snat_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let dst_v4 = Ipv4Addr::new(8, 8, 8, 8);

    // Build IPv6 + UDP.
    let dns_query = b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00";
    let udp_len = 8 + dns_query.len();
    let mut pkt = vec![0u8; 40 + udp_len];
    pkt[0] = 0x60;
    pkt[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    pkt[6] = PROTO_UDP;
    pkt[7] = 64;
    pkt[8..24].copy_from_slice(&src_v6.octets());
    pkt[24..40].copy_from_slice(&dst_v6.octets());
    pkt[40..42].copy_from_slice(&12345u16.to_be_bytes());
    pkt[42..44].copy_from_slice(&53u16.to_be_bytes());
    pkt[44..46].copy_from_slice(&(udp_len as u16).to_be_bytes());
    pkt[48..48 + dns_query.len()].copy_from_slice(dns_query);
    // UDP checksum
    pkt[46..48].copy_from_slice(&[0, 0]);
    let sum = checksum16_ipv6_pseudo(src_v6, dst_v6, PROTO_UDP, &pkt[40..]);
    pkt[46..48].copy_from_slice(&sum.to_be_bytes());

    let v4 = translate_v6_to_v4(&pkt, snat_v4, dst_v4, false).expect("translate");
    assert_eq!(v4[9], PROTO_UDP);
    assert_eq!(checksum16(&v4[..20]), 0);
}

#[test]
fn translate_v6_to_v4_icmp_echo() {
    let src_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::0808:0808".parse().unwrap();
    let snat_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let dst_v4 = Ipv4Addr::new(8, 8, 8, 8);

    // Build ICMPv6 Echo Request.
    let icmp_len = 8; // type(1) + code(1) + checksum(2) + id(2) + seq(2)
    let mut pkt = vec![0u8; 40 + icmp_len];
    pkt[0] = 0x60;
    pkt[4..6].copy_from_slice(&(icmp_len as u16).to_be_bytes());
    pkt[6] = PROTO_ICMPV6;
    pkt[7] = 64;
    pkt[8..24].copy_from_slice(&src_v6.octets());
    pkt[24..40].copy_from_slice(&dst_v6.octets());
    pkt[40] = ICMPV6_ECHO_REQUEST;
    pkt[41] = 0; // code
    pkt[44..46].copy_from_slice(&0x1234u16.to_be_bytes()); // id
    pkt[46..48].copy_from_slice(&0x0001u16.to_be_bytes()); // seq
                                                           // ICMPv6 checksum
    pkt[42..44].copy_from_slice(&[0, 0]);
    let sum = checksum16_ipv6_pseudo(src_v6, dst_v6, PROTO_ICMPV6, &pkt[40..]);
    pkt[42..44].copy_from_slice(&sum.to_be_bytes());

    let v4 = translate_v6_to_v4(&pkt, snat_v4, dst_v4, false).expect("translate");
    assert_eq!(v4[9], PROTO_ICMP);
    assert_eq!(v4[20], ICMP_ECHO_REQUEST); // type mapped
    assert_eq!(checksum16(&v4[..20]), 0);
    // ICMPv4 checksum: no pseudo-header.
    assert_eq!(checksum16(&v4[20..]), 0);
}

#[test]
fn translate_v4_to_v6_icmp_echo_reply() {
    let src_v4 = Ipv4Addr::new(8, 8, 8, 8);
    let dst_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let src_v6: Ipv6Addr = "64:ff9b::0808:0808".parse().unwrap();
    let dst_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();

    // Build ICMPv4 Echo Reply.
    let icmp_len = 8;
    let total = 20 + icmp_len;
    let mut pkt = vec![0u8; total];
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    pkt[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
    pkt[8] = 64;
    pkt[9] = PROTO_ICMP;
    pkt[12..16].copy_from_slice(&src_v4.octets());
    pkt[16..20].copy_from_slice(&dst_v4.octets());
    pkt[10..12].copy_from_slice(&[0, 0]);
    let ip_sum = checksum16(&pkt[..20]);
    pkt[10..12].copy_from_slice(&ip_sum.to_be_bytes());
    pkt[20] = ICMP_ECHO_REPLY;
    pkt[21] = 0;
    pkt[24..26].copy_from_slice(&0x1234u16.to_be_bytes());
    pkt[26..28].copy_from_slice(&0x0001u16.to_be_bytes());
    pkt[22..24].copy_from_slice(&[0, 0]);
    let icmp_sum = checksum16(&pkt[20..]);
    pkt[22..24].copy_from_slice(&icmp_sum.to_be_bytes());

    let v6 = translate_v4_to_v6(&pkt, src_v6, dst_v6).expect("translate");
    assert_eq!(v6[6], PROTO_ICMPV6);
    assert_eq!(v6[40], ICMPV6_ECHO_REPLY); // type mapped
                                           // ICMPv6 checksum verification.
    let s6 = Ipv6Addr::from(<[u8; 16]>::try_from(&v6[8..24]).unwrap());
    let d6 = Ipv6Addr::from(<[u8; 16]>::try_from(&v6[24..40]).unwrap());
    assert_eq!(checksum16_ipv6_pseudo(s6, d6, PROTO_ICMPV6, &v6[40..]), 0);
}

#[test]
fn packet_size_delta() {
    // IPv6 packet: 40 header + 20 TCP header + 5 payload = 65 bytes
    let src_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::c633:6432".parse().unwrap();
    let pkt = make_ipv6_tcp_packet(src_v6, dst_v6, 1025, 80, b"hello");
    assert_eq!(pkt.len(), 65); // 40 + 20 + 5

    let v4 = translate_v6_to_v4(
        &pkt,
        Ipv4Addr::new(198, 51, 100, 1),
        Ipv4Addr::new(198, 51, 100, 50),
        false,
    )
    .expect("translate");
    assert_eq!(v4.len(), 45); // 20 + 20 + 5
    assert_eq!(pkt.len() - v4.len(), 20); // IPv6→IPv4 shrinks by 20 bytes
}

#[test]
fn forward_decision_sets_nat64_flag() {
    // #4381: forward_decision now carries the unique translated source port in
    // rewrite_src_port.
    let d = Nat64State::forward_decision(
        Ipv4Addr::new(198, 51, 100, 1),
        Ipv4Addr::new(8, 8, 8, 8),
        40000,
    );
    assert!(d.nat64);
    assert_eq!(
        d.rewrite_src,
        Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)))
    );
    assert_eq!(d.rewrite_dst, Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
    assert_eq!(d.rewrite_src_port, Some(40000));
    assert_eq!(d.rewrite_dst_port, None);
}

#[test]
fn frame_building_v6_to_v4() {
    let src_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::c633:6432".parse().unwrap();

    // Build Ethernet + IPv6 frame.
    let pkt = make_ipv6_tcp_packet(src_v6, dst_v6, 12345, 80, b"test");
    let mut frame = Vec::new();
    frame.extend_from_slice(&[0xaa; 6]); // dst mac
    frame.extend_from_slice(&[0xbb; 6]); // src mac
    frame.extend_from_slice(&0x86ddu16.to_be_bytes());
    frame.extend_from_slice(&pkt);

    let result = build_nat64_v6_to_v4_frame(
        &frame,
        Ipv4Addr::new(198, 51, 100, 1),
        Ipv4Addr::new(198, 51, 100, 50),
        [0x11; 6],
        [0x22; 6],
        0,
        false,
    )
    .expect("build");

    // Should be 14 (eth) + 44 (20 ipv4 + 20 tcp + 4 payload)
    assert_eq!(result.len(), 14 + 44);
    // Check Ethernet type is IPv4.
    assert_eq!(u16::from_be_bytes([result[12], result[13]]), 0x0800);
}

#[test]
fn frame_building_v4_to_v6() {
    let src_v4 = Ipv4Addr::new(198, 51, 100, 50);
    let dst_v4 = Ipv4Addr::new(198, 51, 100, 1);

    let pkt = make_ipv4_tcp_packet(src_v4, dst_v4, 80, 12345, b"resp");
    let mut frame = Vec::new();
    frame.extend_from_slice(&[0xaa; 6]);
    frame.extend_from_slice(&[0xbb; 6]);
    frame.extend_from_slice(&0x0800u16.to_be_bytes());
    frame.extend_from_slice(&pkt);

    let src_v6: Ipv6Addr = "64:ff9b::c633:6432".parse().unwrap();
    let dst_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();

    let result =
        build_nat64_v4_to_v6_frame(&frame, src_v6, dst_v6, [0x11; 6], [0x22; 6], 0).expect("build");

    // Should be 14 (eth) + 64 (40 ipv6 + 20 tcp + 4 payload)
    assert_eq!(result.len(), 14 + 64);
    // Check Ethernet type is IPv6.
    assert_eq!(u16::from_be_bytes([result[12], result[13]]), 0x86dd);
}

#[test]
fn ttl_expired_returns_none() {
    let src_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::c633:6432".parse().unwrap();
    let mut pkt = make_ipv6_tcp_packet(src_v6, dst_v6, 1025, 80, b"x");
    pkt[7] = 1; // hop limit = 1
                // Need to recompute TCP checksum after modifying hop limit
                // (hop limit isn't in pseudo-header so checksum is still valid).
    assert!(
        translate_v6_to_v4(&pkt, Ipv4Addr::new(1, 2, 3, 4), Ipv4Addr::new(5, 6, 7, 8), false).is_none()
    );
}

#[test]
fn frame_building_v6_to_v4_with_vlan() {
    let src_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::c633:6432".parse().unwrap();

    let pkt = make_ipv6_tcp_packet(src_v6, dst_v6, 12345, 80, b"vlan");
    let mut frame = Vec::new();
    frame.extend_from_slice(&[0xaa; 6]);
    frame.extend_from_slice(&[0xbb; 6]);
    frame.extend_from_slice(&0x86ddu16.to_be_bytes());
    frame.extend_from_slice(&pkt);

    let result = build_nat64_v6_to_v4_frame(
        &frame,
        Ipv4Addr::new(198, 51, 100, 1),
        Ipv4Addr::new(198, 51, 100, 50),
        [0x11; 6],
        [0x22; 6],
        100, // VLAN 100
        false,
    )
    .expect("build");

    // 18 (eth+vlan) + 44 (20 ipv4 + 20 tcp + 4 payload)
    assert_eq!(result.len(), 18 + 44);
    // VLAN tag
    assert_eq!(u16::from_be_bytes([result[12], result[13]]), 0x8100);
    assert_eq!(u16::from_be_bytes([result[16], result[17]]), 0x0800);
}

// #2844: SSOT eth-header fail-on-revert.
//
// The NAT64 frame builders must emit their Ethernet header through the
// shared `crate::afxdp::write_eth_header_slice`, not a private
// hardcoded copy. These tests pin the EXACT L2 header bytes the SSOT
// writer produces for both translation directions, tagged and
// untagged, so the assertions are byte-identical to the intended
// frame. They go RED if the builder reverts to a private writer that
// emits the wrong ethertype (e.g. 0x86dd on the v6→v4 IPv4 frame),
// the wrong TPID, or the wrong dst/src MAC / VLAN placement.
#[test]
fn nat64_eth_header_is_ssot_byte_identical() {
    let src_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::c633:6432".parse().unwrap();
    let eth_dst = [0x11u8, 0x22, 0x33, 0x44, 0x55, 0x66];
    let eth_src = [0xaau8, 0xbb, 0xcc, 0xdd, 0xee, 0xff];

    // --- v6→v4, untagged: ethertype must be IPv4 (0x0800). ---
    let pkt = make_ipv6_tcp_packet(src_v6, dst_v6, 12345, 80, b"ssot");
    let mut frame = Vec::new();
    frame.extend_from_slice(&[0x01; 6]);
    frame.extend_from_slice(&[0x02; 6]);
    frame.extend_from_slice(&0x86ddu16.to_be_bytes());
    frame.extend_from_slice(&pkt);
    let out = build_nat64_v6_to_v4_frame(
        &frame,
        Ipv4Addr::new(198, 51, 100, 1),
        Ipv4Addr::new(198, 51, 100, 50),
        eth_dst,
        eth_src,
        0, // untagged
        false,
    )
    .expect("build v6->v4 untagged");
    // Reference: the SSOT writer applied to a fresh buffer.
    let mut want = [0u8; 14];
    crate::afxdp::write_eth_header_slice(&mut want, eth_dst, eth_src, 0, 0x0800)
        .expect("ssot ref");
    assert_eq!(&out[..14], &want, "v6->v4 untagged L2 header must match SSOT");
    // Explicit field pins so the intent is RED-obvious on revert.
    assert_eq!(&out[0..6], &eth_dst, "dst MAC");
    assert_eq!(&out[6..12], &eth_src, "src MAC");
    assert_eq!(u16::from_be_bytes([out[12], out[13]]), 0x0800, "ethertype IPv4");

    // --- v6→v4, tagged VLAN 100: TPID 0x8100, then VID, then 0x0800. ---
    let out_t = build_nat64_v6_to_v4_frame(
        &frame,
        Ipv4Addr::new(198, 51, 100, 1),
        Ipv4Addr::new(198, 51, 100, 50),
        eth_dst,
        eth_src,
        100,
        false,
    )
    .expect("build v6->v4 tagged");
    let mut want_t = [0u8; 18];
    crate::afxdp::write_eth_header_slice(&mut want_t, eth_dst, eth_src, 100, 0x0800)
        .expect("ssot ref tagged");
    assert_eq!(&out_t[..18], &want_t, "v6->v4 tagged L2 header must match SSOT");
    assert_eq!(u16::from_be_bytes([out_t[12], out_t[13]]), 0x8100, "TPID");
    assert_eq!(u16::from_be_bytes([out_t[14], out_t[15]]), 100, "VID");
    assert_eq!(u16::from_be_bytes([out_t[16], out_t[17]]), 0x0800, "ethertype IPv4");

    // --- v4→v6, untagged: ethertype must be IPv6 (0x86dd). ---
    let v4src = Ipv4Addr::new(198, 51, 100, 50);
    let v4dst = Ipv4Addr::new(198, 51, 100, 1);
    let v4pkt = make_ipv4_tcp_packet(v4src, v4dst, 80, 12345, b"ssot");
    let mut frame4 = Vec::new();
    frame4.extend_from_slice(&[0x03; 6]);
    frame4.extend_from_slice(&[0x04; 6]);
    frame4.extend_from_slice(&0x0800u16.to_be_bytes());
    frame4.extend_from_slice(&v4pkt);
    let out4 = build_nat64_v4_to_v6_frame(&frame4, src_v6, dst_v6, eth_dst, eth_src, 0)
        .expect("build v4->v6 untagged");
    let mut want4 = [0u8; 14];
    crate::afxdp::write_eth_header_slice(&mut want4, eth_dst, eth_src, 0, 0x86dd)
        .expect("ssot ref v4->v6");
    assert_eq!(&out4[..14], &want4, "v4->v6 untagged L2 header must match SSOT");
    assert_eq!(u16::from_be_bytes([out4[12], out4[13]]), 0x86dd, "ethertype IPv6");
}

// ---------------------------------------------------------------------------
// Regression tests for #1641: translate_v4_to_v6 must trim the L4 payload to
// the IPv4 Total Length field, not the end of the input slice. The caller
// passes the whole L3-onward frame, which can carry Ethernet padding when the
// reply is shorter than the 60/64-byte minimum frame size. Before the fix the
// padding was copied into the IPv6 packet, inflating payload_len and poisoning
// the L4 checksum so the receiver dropped the reply.
// ---------------------------------------------------------------------------

#[test]
fn translate_v4_to_v6_trims_ethernet_padding_tcp() {
    let src_v4 = Ipv4Addr::new(198, 51, 100, 50);
    let dst_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let src_v6: Ipv6Addr = "64:ff9b::c633:6432".parse().unwrap();
    let dst_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();

    // A minimal TCP segment with no L4 payload: 20B IP + 20B TCP = 40B on the
    // wire (make_ipv4_tcp_packet sets SYN+ACK flags; the exact flag bits are
    // irrelevant to the padding bug). The NIC/driver pads the frame to the
    // 60-byte L2 minimum, so the L3-onward slice the caller hands us is 46
    // bytes (40B real + 6B zero padding).
    let mut packet = make_ipv4_tcp_packet(src_v4, dst_v4, 80, 12345, b"");
    assert_eq!(packet.len(), 40, "unpadded segment should be 40 bytes");
    let real_len = packet.len();
    packet.extend_from_slice(&[0u8; 6]); // simulate trailing Ethernet padding
    assert_eq!(packet.len(), 46);

    let ipv6_pkt = translate_v4_to_v6(&packet, src_v6, dst_v6).expect("translate");

    // payload_len must reflect the real L4 length (20B TCP), NOT the padded
    // slice length. Before the fix this was 26 (20 + 6 padding bytes).
    let payload_len = u16::from_be_bytes([ipv6_pkt[4], ipv6_pkt[5]]) as usize;
    assert_eq!(payload_len, 20, "payload_len must exclude Ethernet padding");
    // Total translated length = 40B IPv6 header + 20B TCP, with no padding.
    assert_eq!(ipv6_pkt.len(), 40 + (real_len - 20));
    assert_eq!(ipv6_pkt.len(), 60);

    // The L4 checksum must verify over the trimmed payload. A padding-poisoned
    // checksum (the pre-fix bug) leaves a non-zero residual here.
    let src6 = Ipv6Addr::from(<[u8; 16]>::try_from(&ipv6_pkt[8..24]).unwrap());
    let dst6 = Ipv6Addr::from(<[u8; 16]>::try_from(&ipv6_pkt[24..40]).unwrap());
    assert_eq!(
        checksum16_ipv6_pseudo(src6, dst6, PROTO_TCP, &ipv6_pkt[40..]),
        0,
        "TCP checksum must verify over the unpadded payload"
    );
}

#[test]
fn translate_v4_to_v6_trims_ethernet_padding_udp_dns() {
    // Short UDP/DNS reply (the canonical Ethernet-padded case). Build a 12B
    // DNS-ish payload: 20B IP + 8B UDP + 12B = 40B real, padded to 46B.
    let src_v4 = Ipv4Addr::new(8, 8, 8, 8);
    let dst_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let src_v6: Ipv6Addr = "64:ff9b::0808:0808".parse().unwrap();
    let dst_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();

    let dns = b"\x00\x01\x81\x80\x00\x01\x00\x00\x00\x00\x00\x00";
    let udp_len = 8 + dns.len();
    let total_len = 20 + udp_len;
    let mut packet = vec![0u8; total_len];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    packet[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = PROTO_UDP;
    packet[12..16].copy_from_slice(&src_v4.octets());
    packet[16..20].copy_from_slice(&dst_v4.octets());
    packet[10..12].copy_from_slice(&[0, 0]);
    let ip_sum = checksum16(&packet[..20]);
    packet[10..12].copy_from_slice(&ip_sum.to_be_bytes());
    packet[20..22].copy_from_slice(&53u16.to_be_bytes()); // src port
    packet[22..24].copy_from_slice(&12345u16.to_be_bytes()); // dst port
    packet[24..26].copy_from_slice(&(udp_len as u16).to_be_bytes());
    packet[28..28 + dns.len()].copy_from_slice(dns);
    packet[26..28].copy_from_slice(&[0, 0]);
    let udp_sum = checksum16_ipv4_pseudo(src_v4, dst_v4, PROTO_UDP, &packet[20..]);
    packet[26..28].copy_from_slice(&udp_sum.to_be_bytes());

    assert_eq!(packet.len(), 40);
    packet.extend_from_slice(&[0u8; 6]); // Ethernet padding to 46B L3 slice

    let v6 = translate_v4_to_v6(&packet, src_v6, dst_v6).expect("translate");
    let payload_len = u16::from_be_bytes([v6[4], v6[5]]) as usize;
    assert_eq!(payload_len, udp_len, "payload_len must exclude padding");
    assert_eq!(v6.len(), 40 + udp_len);

    let s6 = Ipv6Addr::from(<[u8; 16]>::try_from(&v6[8..24]).unwrap());
    let d6 = Ipv6Addr::from(<[u8; 16]>::try_from(&v6[24..40]).unwrap());
    assert_eq!(
        checksum16_ipv6_pseudo(s6, d6, PROTO_UDP, &v6[40..]),
        0,
        "UDP checksum must verify over the unpadded payload"
    );
}

#[test]
fn translate_v4_to_v6_total_len_larger_than_slice_returns_none() {
    // Malformed Total Length advertising more bytes than we received: must be
    // rejected safely (no panic, no out-of-bounds), not trusted.
    let src_v6: Ipv6Addr = "64:ff9b::c633:6432".parse().unwrap();
    let dst_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let mut packet = make_ipv4_tcp_packet(
        Ipv4Addr::new(198, 51, 100, 50),
        Ipv4Addr::new(198, 51, 100, 1),
        80,
        12345,
        b"hi",
    );
    // Advertise a Total Length 100 bytes beyond the actual slice.
    let bogus = (packet.len() + 100) as u16;
    packet[2..4].copy_from_slice(&bogus.to_be_bytes());
    assert!(
        translate_v4_to_v6(&packet, src_v6, dst_v6).is_none(),
        "oversized total_len must be rejected"
    );
}

// ---------------------------------------------------------------------------
// #1662: NAT64 must copy the IP traffic class (DSCP + ECN) across translation
// in BOTH directions. Before the fix the IPv4 TOS byte / IPv6 traffic class was
// hard-zeroed, so DiffServ marking and end-to-end ECN were lost across the
// translator. RFC 7915 §4/§5 default is a verbatim full-byte copy (DSCP copied,
// ECN copied verbatim) — NAT64 is stateless translation, not RFC 6040 tunnel
// encapsulation.
//
// All cases use TOS/TC = 0xBA = (DSCP 46 EF << 2) | ECN 0b10 (ECT(0)). The
// non-zero ECN nibble means a DSCP-only implementation that dropped ECN would
// also fail these assertions.
// ---------------------------------------------------------------------------

/// DSCP 46 (EF) in bits 7:2, ECN 0b10 (ECT(0)) in bits 1:0 → 0xBA.
const TC_EF_ECT0: u8 = (46u8 << 2) | 0b10;

#[test]
fn translate_v6_to_v4_copies_traffic_class() {
    let src_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::c633:6432".parse().unwrap();
    let snat_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let dst_v4 = Ipv4Addr::new(198, 51, 100, 50);

    let mut ipv6_pkt = make_ipv6_tcp_packet(src_v6, dst_v6, 12345, 80, b"qos");
    // Set the IPv6 traffic class to 0xBA across bytes 0-1 (preserving version
    // nibble and flow label). TC[7:4] in byte0 low nibble, TC[3:0] in byte1
    // high nibble. (TCP checksum does not cover the TC byte, so no recompute.)
    ipv6_pkt[0] = (ipv6_pkt[0] & 0xf0) | (TC_EF_ECT0 >> 4);
    ipv6_pkt[1] = (ipv6_pkt[1] & 0x0f) | ((TC_EF_ECT0 & 0x0f) << 4);
    // Sanity: reconstruct and confirm the input really carries 0xBA.
    let in_tc = ((ipv6_pkt[0] & 0x0f) << 4) | (ipv6_pkt[1] >> 4);
    assert_eq!(in_tc, TC_EF_ECT0);

    let v4 = translate_v6_to_v4(&ipv6_pkt, snat_v4, dst_v4, false).expect("translate");

    // IPv4 TOS byte must equal the source traffic class exactly (DSCP+ECN).
    assert_eq!(v4[1], TC_EF_ECT0, "IPv4 TOS must copy the IPv6 traffic class");
    // IPv4 header checksum must still verify with the non-zero TOS byte.
    assert_eq!(checksum16(&v4[..20]), 0, "IPv4 header checksum must verify");
}

#[test]
fn translate_v4_to_v6_copies_traffic_class() {
    let src_v4 = Ipv4Addr::new(198, 51, 100, 50);
    let dst_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let src_v6: Ipv6Addr = "64:ff9b::c633:6432".parse().unwrap();
    let dst_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();

    let mut ipv4_pkt = make_ipv4_tcp_packet(src_v4, dst_v4, 80, 12345, b"qos");
    // Set the IPv4 TOS byte to 0xBA and recompute the IPv4 header checksum
    // (the header checksum DOES cover the TOS byte).
    ipv4_pkt[1] = TC_EF_ECT0;
    ipv4_pkt[10..12].copy_from_slice(&[0, 0]);
    let ip_sum = checksum16(&ipv4_pkt[..20]);
    ipv4_pkt[10..12].copy_from_slice(&ip_sum.to_be_bytes());

    let v6 = translate_v4_to_v6(&ipv4_pkt, src_v6, dst_v6).expect("translate");

    // Reconstruct the IPv6 traffic class from bytes 0-1 and compare exactly.
    let out_tc = ((v6[0] & 0x0f) << 4) | (v6[1] >> 4);
    assert_eq!(
        out_tc, TC_EF_ECT0,
        "IPv6 traffic class must copy the IPv4 TOS byte"
    );
    // Version nibble must remain 6.
    assert_eq!(v6[0] >> 4, 6, "IPv6 version nibble must be preserved");
    // Flow label (low nibble of byte 1 + bytes 2-3) must stay 0.
    assert_eq!(v6[1] & 0x0f, 0, "flow-label high nibble must be 0");
    assert_eq!(v6[2], 0, "flow label must be 0");
    assert_eq!(v6[3], 0, "flow label must be 0");
}

#[test]
fn nat64_traffic_class_round_trips() {
    // v6 → v4 → v6: the traffic class survives a full round trip.
    let client_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::c633:6432".parse().unwrap();
    let snat_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let dst_v4 = Ipv4Addr::new(198, 51, 100, 50);

    let mut ipv6_pkt = make_ipv6_tcp_packet(client_v6, dst_v6, 12345, 80, b"rt");
    ipv6_pkt[0] = (ipv6_pkt[0] & 0xf0) | (TC_EF_ECT0 >> 4);
    ipv6_pkt[1] = (ipv6_pkt[1] & 0x0f) | ((TC_EF_ECT0 & 0x0f) << 4);

    let v4 = translate_v6_to_v4(&ipv6_pkt, snat_v4, dst_v4, false).expect("v6->v4");
    assert_eq!(v4[1], TC_EF_ECT0);

    // Translate the IPv4 packet back to IPv6 (reply direction reuses the same
    // helper). The TOS byte carried by v4 must reappear in the IPv6 TC.
    let v6 = translate_v4_to_v6(&v4, dst_v6, client_v6).expect("v4->v6");
    let rt_tc = ((v6[0] & 0x0f) << 4) | (v6[1] >> 4);
    assert_eq!(rt_tc, TC_EF_ECT0, "traffic class must survive round trip");
    assert_eq!(v6[0] >> 4, 6);

    // v4 → v6 → v4: the traffic class also survives the opposite round trip.
    let server_v4 = Ipv4Addr::new(198, 51, 100, 50);
    let client_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let server_v6: Ipv6Addr = "64:ff9b::c633:6432".parse().unwrap();
    let client_v6_reverse: Ipv6Addr = "2001:db8::1".parse().unwrap();

    let mut ipv4_pkt = make_ipv4_tcp_packet(server_v4, client_v4, 80, 12345, b"rt2");
    ipv4_pkt[1] = TC_EF_ECT0;
    ipv4_pkt[10..12].copy_from_slice(&[0, 0]);
    let ip_sum = checksum16(&ipv4_pkt[..20]);
    ipv4_pkt[10..12].copy_from_slice(&ip_sum.to_be_bytes());

    let v6_reverse = translate_v4_to_v6(&ipv4_pkt, server_v6, client_v6_reverse).expect("v4->v6");
    let v6_reverse_tc = ((v6_reverse[0] & 0x0f) << 4) | (v6_reverse[1] >> 4);
    assert_eq!(v6_reverse_tc, TC_EF_ECT0);

    let v4_reverse = translate_v6_to_v4(&v6_reverse, server_v4, client_v4, false).expect("v6->v4");
    assert_eq!(
        v4_reverse[1], TC_EF_ECT0,
        "traffic class must survive v4->v6->v4 round trip"
    );
    assert_eq!(
        checksum16(&v4_reverse[..20]),
        0,
        "IPv4 header checksum must verify"
    );
}

#[test]
fn translate_v4_to_v6_total_len_below_ihl_returns_none() {
    // Total Length shorter than the IPv4 header is nonsensical: reject it.
    let src_v6: Ipv6Addr = "64:ff9b::c633:6432".parse().unwrap();
    let dst_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let mut packet = make_ipv4_tcp_packet(
        Ipv4Addr::new(198, 51, 100, 50),
        Ipv4Addr::new(198, 51, 100, 1),
        80,
        12345,
        b"hi",
    );
    packet[2..4].copy_from_slice(&10u16.to_be_bytes()); // < 20B IHL
    assert!(
        translate_v4_to_v6(&packet, src_v6, dst_v6).is_none(),
        "total_len below the IPv4 header length must be rejected"
    );
}

// ---------------------------------------------------------------------------
// #2008 H16: `security nat natv6v4 no-v6-frag-header` must be honored by the
// IPv6->IPv4 translator. Before the fix the option parsed, compiled into typed
// config, and rode the snapshot wire but had NO runtime consumer: the global
// flag never reached the dataplane snapshot and translate_v6_to_v4 always set
// the Don't-Fragment (DF) bit. These tests pin the runtime enforcement: the
// flags+frag-offset word (IPv4 header bytes 6-7) must be DF=1 (0x4000) by
// default and DF=0 (0x0000) when the option is set. The DF clearing is an
// option-gated LOCAL policy, not the size-driven RFC 7915 5.1 selection.
//
// They also pin the DF/Identification consistency the Copilot review on #2014
// flagged: a DF=1 atomic datagram keeps Identification=0 (legal per RFC 6864
// 4.1), while a DF=0 fragmentable datagram MUST carry a non-zero, non-repeating
// Identification drawn from the per-translator generator (RFC 7915 5.1 / RFC
// 6864 4.1) — pinning ID=0 while clearing DF was the original bug.
// ---------------------------------------------------------------------------

/// Helper: read the IPv4 flags + fragment-offset word from a translated L3
/// packet (bytes 6-7).
fn ipv4_frag_word(pkt: &[u8]) -> u16 {
    u16::from_be_bytes([pkt[6], pkt[7]])
}

/// Helper: read the IPv4 Identification field (bytes 4-5) from a translated L3
/// packet.
fn ipv4_identification(pkt: &[u8]) -> u16 {
    u16::from_be_bytes([pkt[4], pkt[5]])
}

#[test]
fn translate_v6_to_v4_default_sets_df_bit() {
    let src_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::c633:6432".parse().unwrap();
    let snat_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let dst_v4 = Ipv4Addr::new(198, 51, 100, 50);

    let ipv6_pkt = make_ipv6_tcp_packet(src_v6, dst_v6, 12345, 80, b"df");
    let v4 = translate_v6_to_v4(&ipv6_pkt, snat_v4, dst_v4, false).expect("translate");

    // Default (no-v6-frag-header NOT set): DF=1, no fragment offset.
    assert_eq!(
        ipv4_frag_word(&v4),
        0x4000,
        "default translation must set the DF bit (atomic, non-fragmentable)"
    );
    // ID=0 is legal for an ATOMIC datagram (DF=1) per RFC 6864 4.1.
    assert_eq!(
        ipv4_identification(&v4),
        0,
        "atomic (DF=1) translation keeps Identification=0"
    );
    // Header checksum must still verify.
    assert_eq!(checksum16(&v4[..20]), 0, "IPv4 header checksum must verify");
}

#[test]
fn translate_v6_to_v4_no_v6_frag_header_clears_df_bit() {
    let src_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::c633:6432".parse().unwrap();
    let snat_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let dst_v4 = Ipv4Addr::new(198, 51, 100, 50);

    let ipv6_pkt = make_ipv6_tcp_packet(src_v6, dst_v6, 12345, 80, b"nofrag");
    let v4 = translate_v6_to_v4(&ipv6_pkt, snat_v4, dst_v4, true).expect("translate");

    // With no-v6-frag-header set: DF cleared so the packet stays fragmentable.
    assert_eq!(
        ipv4_frag_word(&v4),
        0x0000,
        "no-v6-frag-header must clear the DF bit (fragmentable, per RFC 7915 5.1)"
    );
    // A fragmentable (DF=0) datagram is NON-ATOMIC. RFC 7915 5.1 sets the
    // Identification from a per-translator generator, and RFC 6864 4.1 forbids
    // a constant/repeated ID for non-atomic datagrams. A pinned ID=0 (the
    // pre-fix bug) would mis-reassemble distinct datagrams when a downstream
    // router fragments them, so the ID MUST be non-zero here.
    assert_ne!(
        ipv4_identification(&v4),
        0,
        "fragmentable (DF=0) translation MUST carry a non-zero Identification \
         (RFC 7915 5.1 / RFC 6864 4.1)"
    );
    // The change must not break the IPv4 header checksum.
    assert_eq!(checksum16(&v4[..20]), 0, "IPv4 header checksum must verify");

    // Everything else (TTL, protocol, addresses, payload) must be unchanged
    // relative to the default translation — only the DF bit (bytes 6-7), the
    // Identification (bytes 4-5), and the resulting header checksum (bytes
    // 10-11) differ.
    let v4_default = translate_v6_to_v4(&ipv6_pkt, snat_v4, dst_v4, false).expect("translate");
    assert_eq!(v4.len(), v4_default.len());
    assert_eq!(v4[8], v4_default[8], "TTL unchanged");
    assert_eq!(v4[9], v4_default[9], "protocol unchanged");
    assert_eq!(&v4[12..20], &v4_default[12..20], "src/dst addresses unchanged");
    assert_eq!(&v4[20..], &v4_default[20..], "L4 payload unchanged");
    // The frag word is one header field that must differ.
    assert_ne!(
        ipv4_frag_word(&v4),
        ipv4_frag_word(&v4_default),
        "frag word must differ between the two modes"
    );
}

#[test]
fn translate_v6_to_v4_no_v6_frag_header_identification_is_unique() {
    // RFC 6864 4.1: a source emitting non-atomic (DF=0) datagrams MUST NOT
    // repeat the Identification for a given src/dst/proto tuple within one MDL.
    // The per-translator generator advances on every fragmentable translation,
    // so successive DF=0 translations must carry DISTINCT non-zero IDs.
    //
    // This test is DETERMINISTIC and robust to the process-global counter's
    // start value (it does not assume the generator begins at any particular
    // raw value): it exercises the pure mapping `map_frag_id` over a CONTROLLED
    // consecutive sequence that crosses the 0/1 boundary AND a full 16-bit wrap,
    // and asserts the cycle invariants directly. The old test passed only by
    // accident — other tests advanced the shared atomic before it ran, so it
    // FAILED in isolation (`cargo test <name> -- --exact`).
    //
    // Mutation check: the pre-fix mapping `if raw==0 {1} else {raw as u16}`
    // maps BOTH raw=0 and raw=1 to 1, so the raw=0->raw=1 step below produces a
    // consecutive duplicate and the no-repeat assertion fails.
    let mut prev: Option<u16> = None;
    // 0..=65536 covers the first two values (raw=0,1 — the boundary that the
    // pre-fix remap collided), the top of the cycle (raw=65534 -> 65535), and
    // the wrap (raw=65535 -> 1, raw=65536 -> 2). Iterating one full period plus
    // a step proves there is no consecutive duplicate ANYWHERE, including the
    // 65535 -> 1 jump.
    for raw in 0u32..=65536 {
        let id = map_frag_id(raw);
        assert_ne!(id, 0, "Identification must be non-zero (raw={raw})");
        assert!(
            (1..=65535).contains(&id),
            "Identification must lie in 1..=65535 (raw={raw}, id={id})"
        );
        if let Some(p) = prev {
            assert_ne!(
                p, id,
                "successive Identifications must differ (RFC 6864 4.1 no-repeat): \
                 raw={raw} produced {id} == previous {p}"
            );
        }
        prev = Some(id);
    }
    // Spot-check the boundary and wrap values the pre-fix mapping got wrong.
    assert_eq!(map_frag_id(0), 1);
    assert_eq!(map_frag_id(1), 2, "raw=1 must NOT collide with raw=0 (the bug)");
    assert_eq!(map_frag_id(65534), 65535, "top of the cycle");
    assert_eq!(map_frag_id(65535), 1, "wrap is a jump 65535 -> 1, not a repeat");
    assert_eq!(map_frag_id(65536), 2);

    // End-to-end smoke: two back-to-back fragmentable translations both carry
    // non-zero IDs and stay DF=0 with valid checksums. (The no-consecutive-dup
    // proof lives in the deterministic loop above; this only confirms the
    // generator is actually wired into the DF=0 translation path.)
    let src_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::c633:6432".parse().unwrap();
    let snat_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let dst_v4 = Ipv4Addr::new(198, 51, 100, 50);
    let ipv6_pkt = make_ipv6_tcp_packet(src_v6, dst_v6, 12345, 80, b"uniq");
    let a = translate_v6_to_v4(&ipv6_pkt, snat_v4, dst_v4, true).expect("translate a");
    let b = translate_v6_to_v4(&ipv6_pkt, snat_v4, dst_v4, true).expect("translate b");
    assert_ne!(ipv4_identification(&a), 0, "first fragmentable ID must be non-zero");
    assert_ne!(ipv4_identification(&b), 0, "second fragmentable ID must be non-zero");
    assert_ne!(
        ipv4_identification(&a),
        ipv4_identification(&b),
        "two back-to-back fragmentable translations must use distinct IDs"
    );
    assert_eq!(ipv4_frag_word(&a), 0x0000);
    assert_eq!(ipv4_frag_word(&b), 0x0000);
    assert_eq!(checksum16(&a[..20]), 0, "header checksum must verify (a)");
    assert_eq!(checksum16(&b[..20]), 0, "header checksum must verify (b)");
}

#[test]
fn build_nat64_v6_to_v4_frame_honors_no_v6_frag_header() {
    let src_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::c633:6432".parse().unwrap();

    let pkt = make_ipv6_tcp_packet(src_v6, dst_v6, 12345, 80, b"frame");
    let mut frame = Vec::new();
    frame.extend_from_slice(&[0xaa; 6]);
    frame.extend_from_slice(&[0xbb; 6]);
    frame.extend_from_slice(&0x86ddu16.to_be_bytes());
    frame.extend_from_slice(&pkt);

    // no_v6_frag_header = true: the inner IPv4 header (after the 14B Ethernet
    // header) must carry DF=0.
    let result = build_nat64_v6_to_v4_frame(
        &frame,
        Ipv4Addr::new(198, 51, 100, 1),
        Ipv4Addr::new(198, 51, 100, 50),
        [0x11; 6],
        [0x22; 6],
        0,
        true,
    )
    .expect("build");
    let ipv4 = &result[14..];
    assert_eq!(
        ipv4_frag_word(ipv4),
        0x0000,
        "frame builder must thread no-v6-frag-header into the IPv4 framing"
    );
}

#[test]
fn nat64_state_threads_no_v6_frag_header_from_snapshot() {
    // The flag rides on the per-rule snapshot (the Go side stamps the global
    // natv6v4 option onto every rule). from_snapshots must surface it.
    let mut snap = well_known_prefix();
    assert!(
        !Nat64State::from_snapshots(&[snap.clone()]).no_v6_frag_header,
        "default snapshot must leave no_v6_frag_header unset"
    );
    snap.no_v6_frag_header = true;
    assert!(
        Nat64State::from_snapshots(&[snap]).no_v6_frag_header,
        "from_snapshots must surface the no_v6_frag_header flag"
    );
}

// ---------------------------------------------------------------------------
// #2150: NAT64 L2 offset must agree with the canonical contract on a single
// 0x88a8 (802.1ad) tag. Pre-fix `frame_l3_offset` matched only 0x8100, so a
// 0x88a8-tagged frame was treated as untagged (l3=14) and the IP header was
// read 4 bytes into the VLAN tag → corrupted translation. This canary FAILS on
// pre-fix code (l3=14) and passes after (l3=18).
// ---------------------------------------------------------------------------

#[test]
fn nat64_l2_offset_canary() {
    // dst+src MAC, then the outer ethertype slot.
    let mut frame = vec![0u8; 14];
    frame[12] = 0x88;
    frame[13] = 0xa8; // 802.1ad
    frame.extend_from_slice(&0x0064u16.to_be_bytes()); // TCI VID 100
    frame.extend_from_slice(&0x86ddu16.to_be_bytes()); // inner ethertype
    frame.extend_from_slice(&[0u8; 64]); // body

    // Single 0x88a8 tag → l3 at 18, matching frame/inspect::frame_l3_offset.
    assert_eq!(frame_l3_offset(&frame), Some(18));

    // 0x8100 still maps to 18.
    frame[12] = 0x81;
    frame[13] = 0x00;
    assert_eq!(frame_l3_offset(&frame), Some(18));

    // Untagged (inner ethertype directly at 12..14) → l3 at 14.
    let untagged = {
        let mut f = vec![0u8; 14];
        f[12] = 0x86;
        f[13] = 0xdd;
        f.extend_from_slice(&[0u8; 64]);
        f
    };
    assert_eq!(frame_l3_offset(&untagged), Some(14));
}

#[test]
fn nat64_v4_to_v6_frame_reads_ip_at_offset_18_under_8021ad() {
    // End-to-end proof: a 0x88a8-tagged IPv4 frame fed to the reverse NAT64
    // builder reads the IPv4 header at offset 18 (not 14). Pre-fix the
    // builder offset the IP read into the VLAN tag and translate_v4_to_v6
    // would see a corrupted (version != 4) header.
    let src_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::c633:6432".parse().unwrap();
    let inner = make_ipv4_tcp_packet(
        Ipv4Addr::new(198, 51, 100, 50),
        Ipv4Addr::new(198, 51, 100, 1),
        80,
        12345,
        b"x",
    );

    let mut frame = Vec::new();
    frame.extend_from_slice(&[0xaa; 6]); // dst
    frame.extend_from_slice(&[0xbb; 6]); // src
    frame.extend_from_slice(&0x88a8u16.to_be_bytes()); // 802.1ad TPID
    frame.extend_from_slice(&0x0064u16.to_be_bytes()); // TCI VID 100
    frame.extend_from_slice(&0x0800u16.to_be_bytes()); // inner: IPv4
    frame.extend_from_slice(&inner);

    let out = build_nat64_v4_to_v6_frame(
        &frame,
        src_v6,
        dst_v6,
        [0x11; 6],
        [0x22; 6],
        100, // emit a VLAN-tagged output
    )
    .expect("v4->v6 build must succeed for an 0x88a8-tagged input");

    // The output IPv6 header (after the rebuilt eth+vlan = 18 bytes) must be
    // a valid IPv6 header (version nibble 6), proving the inner IPv4 was read
    // from offset 18, not from inside the VLAN tag.
    assert_eq!(u16::from_be_bytes([out[12], out[13]]), 0x8100);
    assert_eq!(u16::from_be_bytes([out[16], out[17]]), 0x86dd);
    assert_eq!(out[18] >> 4, 6, "translated payload must be a valid IPv6 header");
}

// ---------------------------------------------------------------------------
// #2211: the NAT64 transit translate path must NOT heap-allocate per packet.
// The old path allocated an intermediate L3 `Vec`, a pseudo-header `Vec` per
// checksum, and a second full output `Vec` — copying the L4 payload at least
// twice. The `write_*_into` cores now translate directly into a caller-provided
// buffer with the pseudo-header checksum STREAMED (no Vec). These tests assert:
//   1. zero heap allocations across many translations into a reused buffer; and
//   2. the `_into` output is BYTE-IDENTICAL to the legacy Vec translator, so
//      the optimization is on-the-wire equivalent (correctness preserved).
// ---------------------------------------------------------------------------

#[test]
fn write_v6_to_v4_into_writes_caller_buffer_without_realloc() {
    // #2211: the `_into` core translates straight into a caller-provided buffer.
    // Translating thousands of packets into ONE reused buffer must NOT
    // reallocate it: the buffer's backing pointer and capacity stay fixed,
    // proving the translator does not grow/replace the caller's allocation
    // (the same hot-path-discipline proof the WG scratch-buffer test uses).
    // It cannot internally `vec![]` an L3 packet either, because that
    // intermediate buffer no longer exists — translation writes header bytes,
    // the L4 payload (one copy), and a streamed checksum directly into `out`.
    let src_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::c633:6432".parse().unwrap();
    let snat_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let dst_v4 = Ipv4Addr::new(198, 51, 100, 50);
    let ipv6_tcp = make_ipv6_tcp_packet(src_v6, dst_v6, 12345, 80, b"hello-nat64-payload");

    let mut out = vec![0u8; 2048];
    let initial_ptr = out.as_ptr();
    let initial_cap = out.capacity();
    let mut written = 0usize;
    for i in 0..4096 {
        let no_frag = i % 2 == 0;
        written = write_v6_to_v4_into(&mut out, &ipv6_tcp, snat_v4, dst_v4, no_frag)
            .expect("translate into reused buffer");
    }
    assert_eq!(written, 20 + 20 + b"hello-nat64-payload".len());
    assert_eq!(
        out.as_ptr(),
        initial_ptr,
        "v6->v4 translate-into must not reallocate the caller buffer (#2211)"
    );
    assert_eq!(
        out.capacity(),
        initial_cap,
        "v6->v4 translate-into must not change the caller buffer capacity (#2211)"
    );
}

#[test]
fn write_v4_to_v6_into_writes_caller_buffer_without_realloc() {
    // #2211 reverse-direction twin of the above.
    let src_v4 = Ipv4Addr::new(198, 51, 100, 50);
    let dst_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let src_v6: Ipv6Addr = "64:ff9b::c633:6432".parse().unwrap();
    let dst_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let ipv4_tcp = make_ipv4_tcp_packet(src_v4, dst_v4, 80, 12345, b"reverse-nat64-payload");

    let mut out = vec![0u8; 2048];
    let initial_ptr = out.as_ptr();
    let initial_cap = out.capacity();
    let mut written = 0usize;
    for _ in 0..4096 {
        written = write_v4_to_v6_into(&mut out, &ipv4_tcp, src_v6, dst_v6)
            .expect("translate into reused buffer");
    }
    assert_eq!(written, 40 + 20 + b"reverse-nat64-payload".len());
    assert_eq!(
        out.as_ptr(),
        initial_ptr,
        "v4->v6 translate-into must not reallocate the caller buffer (#2211)"
    );
    assert_eq!(
        out.capacity(),
        initial_cap,
        "v4->v6 translate-into must not change the caller buffer capacity (#2211)"
    );
}

// Source guard for the streamed pseudo-header checksum (#2211): the two
// `checksum16_*_pseudo` helpers must NOT build an intermediate `Vec` per call
// (the old code did, allocating 12+payload / 40+payload bytes on every L4
// checksum). The bodies are uniquely delimited, so a precise body scan FAILS if
// a future edit reintroduces a per-checksum buffer.
#[test]
fn pseudo_header_checksum_helpers_have_no_per_packet_vec() {
    let src = include_str!("nat64.rs");
    for fn_name in ["fn checksum16_ipv4_pseudo", "fn checksum16_ipv6_pseudo"] {
        let start = src.find(fn_name).unwrap_or_else(|| panic!("{fn_name} must exist"));
        // The body ends at the function's column-0 closing brace `\n}`. Each
        // helper is a short free function, so the FIRST `\n}` after the opener
        // is its terminator.
        let after = &src[start + fn_name.len()..];
        let body_end = after.find("\n}").unwrap_or(after.len());
        let body = &after[..body_end];
        for needle in ["vec![", "Vec::with_capacity", "Vec::new(", "extend_from_slice"] {
            assert!(
                !body.contains(needle),
                "{fn_name} must stream the checksum with NO per-packet {needle:?} (#2211)"
            );
        }
    }
}

#[test]
fn write_v6_to_v4_into_byte_identical_to_vec_translator() {
    // Differential: the allocation-free `_into` core must produce EXACTLY the
    // same L3 bytes as the legacy Vec translator across protocols, DF modes,
    // and traffic-class settings. (DF=0 draws a fresh Identification from the
    // process-global generator each call, so compare those two runs with the
    // Identification field masked out; everything else must match byte-for-byte
    // and the DF=1 runs match in full.)
    let src_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let snat_v4 = Ipv4Addr::new(198, 51, 100, 1);

    let cases: Vec<(Ipv6Addr, Vec<u8>, Ipv4Addr)> = vec![
        (
            "64:ff9b::c633:6432".parse().unwrap(),
            make_ipv6_tcp_packet(src_v6, "64:ff9b::c633:6432".parse().unwrap(), 12345, 80, b"abc"),
            Ipv4Addr::new(198, 51, 100, 50),
        ),
    ];
    for (_dst6, pkt, dst_v4) in cases {
        // DF=1 (atomic): full byte-identity, including Identification (=0).
        let mut buf = vec![0u8; 2048];
        let n = write_v6_to_v4_into(&mut buf, &pkt, snat_v4, dst_v4, false).expect("into");
        let vec_out = translate_v6_to_v4(&pkt, snat_v4, dst_v4, false).expect("vec");
        assert_eq!(
            &buf[..n],
            vec_out.as_slice(),
            "DF=1 translate-into must be byte-identical to the Vec translator"
        );
        assert_eq!(checksum16(&vec_out[..20]), 0, "vec header checksum verifies");
        assert_eq!(checksum16(&buf[..20]), 0, "into header checksum verifies");

        // DF=0 (fragmentable): everything EXCEPT the Identification (bytes 4-5)
        // and the header checksum (bytes 10-11, which covers the ID) must match.
        let mut buf2 = vec![0u8; 2048];
        let n2 = write_v6_to_v4_into(&mut buf2, &pkt, snat_v4, dst_v4, true).expect("into df0");
        let vec_out2 = translate_v6_to_v4(&pkt, snat_v4, dst_v4, true).expect("vec df0");
        assert_eq!(n2, vec_out2.len());
        // Mask Identification + header checksum before comparing.
        let mut a = buf2[..n2].to_vec();
        let mut b = vec_out2.clone();
        for p in [&mut a, &mut b] {
            p[4] = 0;
            p[5] = 0;
            p[10] = 0;
            p[11] = 0;
        }
        assert_eq!(
            a, b,
            "DF=0 translate-into must match the Vec translator outside the per-call ID"
        );
        // Both still carry a non-zero ID and a verifying header checksum.
        assert_ne!(u16::from_be_bytes([buf2[4], buf2[5]]), 0);
        assert_eq!(checksum16(&buf2[..20]), 0);
    }
}

#[test]
fn write_v4_to_v6_into_byte_identical_to_vec_translator() {
    let src_v6: Ipv6Addr = "64:ff9b::c633:6432".parse().unwrap();
    let dst_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    // Cover TCP, UDP-with-padding, and ICMP plus a non-zero traffic class.
    let mut tcp = make_ipv4_tcp_packet(
        Ipv4Addr::new(198, 51, 100, 50),
        Ipv4Addr::new(198, 51, 100, 1),
        80,
        12345,
        b"world",
    );
    // Set a non-zero TOS and refresh the header checksum so the TC-copy path is
    // exercised in the differential.
    tcp[1] = (46u8 << 2) | 0b10;
    tcp[10..12].copy_from_slice(&[0, 0]);
    let s = checksum16(&tcp[..20]);
    tcp[10..12].copy_from_slice(&s.to_be_bytes());

    // A padded short reply (the #1641 trim path).
    let mut padded = make_ipv4_tcp_packet(
        Ipv4Addr::new(198, 51, 100, 50),
        Ipv4Addr::new(198, 51, 100, 1),
        80,
        12345,
        b"",
    );
    padded.extend_from_slice(&[0u8; 8]); // simulate Ethernet padding

    for pkt in [tcp, padded] {
        let mut buf = vec![0u8; 2048];
        let n = write_v4_to_v6_into(&mut buf, &pkt, src_v6, dst_v6).expect("into");
        let vec_out = translate_v4_to_v6(&pkt, src_v6, dst_v6).expect("vec");
        assert_eq!(
            &buf[..n],
            vec_out.as_slice(),
            "translate-into must be byte-identical to the Vec translator"
        );
        // L4 checksum must verify over the trimmed payload in BOTH outputs.
        let s6 = Ipv6Addr::from(<[u8; 16]>::try_from(&buf[8..24]).unwrap());
        let d6 = Ipv6Addr::from(<[u8; 16]>::try_from(&buf[24..40]).unwrap());
        assert_eq!(
            checksum16_ipv6_pseudo(s6, d6, PROTO_TCP, &buf[40..n]),
            0,
            "translated L4 checksum must verify"
        );
    }
}

#[test]
fn streamed_pseudo_header_checksum_matches_contiguous_buffer() {
    // The pseudo-header checksum is now STREAMED (no per-packet Vec). Prove the
    // streamed result equals the historical "build a contiguous pseudo+payload
    // buffer then checksum16" computation, so no checksum drift was introduced.
    let src4 = Ipv4Addr::new(198, 51, 100, 7);
    let dst4 = Ipv4Addr::new(8, 8, 8, 8);
    let src6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst6: Ipv6Addr = "64:ff9b::0808:0808".parse().unwrap();
    for payload_len in [0usize, 1, 7, 8, 15, 16, 40, 1500] {
        let payload: Vec<u8> = (0..payload_len).map(|i| ((i * 37 + 11) & 0xff) as u8).collect();

        // IPv4 reference: contiguous pseudo-header + payload.
        let mut buf4 = Vec::with_capacity(12 + payload.len());
        buf4.extend_from_slice(&src4.octets());
        buf4.extend_from_slice(&dst4.octets());
        buf4.push(0);
        buf4.push(PROTO_UDP);
        buf4.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        buf4.extend_from_slice(&payload);
        assert_eq!(
            checksum16_ipv4_pseudo(src4, dst4, PROTO_UDP, &payload),
            checksum16(&buf4),
            "streamed IPv4 pseudo-header checksum must match the contiguous buffer (len={payload_len})"
        );

        // IPv6 reference: contiguous pseudo-header + payload.
        let mut buf6 = Vec::with_capacity(40 + payload.len());
        buf6.extend_from_slice(&src6.octets());
        buf6.extend_from_slice(&dst6.octets());
        buf6.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        buf6.extend_from_slice(&[0, 0, 0, PROTO_TCP]);
        buf6.extend_from_slice(&payload);
        assert_eq!(
            checksum16_ipv6_pseudo(src6, dst6, PROTO_TCP, &payload),
            checksum16(&buf6),
            "streamed IPv6 pseudo-header checksum must match the contiguous buffer (len={payload_len})"
        );
    }
}

// ---------------------------------------------------------------------------
// #2219: ICMP ERROR-message translation (Dest-Unreachable, Time-Exceeded,
// Packet-Too-Big <-> Fragmentation-Needed, Parameter-Problem) across NAT64.
//
// Pre-fix the ICMP type translators handled ONLY echo (128/129, 8/0) and
// returned None for every error type, which aborted the whole frame build
// (`?` on the translator) — so PMTUD and traceroute were blackholed. These
// tests are FAIL-ON-REVERT: each asserts the outer ICMP type/code/checksum AND
// the EMBEDDED translated IP header (addresses NAT64-mapped, lengths/checksums
// correct), with an independent oracle for both checksums. Reverting the fix
// (translators return None for errors) drops the packet -> `expect("translate")`
// panics, failing the test.
//
// ICMP error message layout: type(1) code(1) checksum(2) rest-of-header(4) then
// the quoted original packet (IP header + leading L4 bytes).
// ---------------------------------------------------------------------------

const PROTO_ICMP_C: u8 = 1;
const PROTO_ICMPV6_C: u8 = 58;

/// Build an IPv4 packet (header + given L4 bytes) with a valid header checksum.
/// Used to construct the embedded/quoted original packet inside an ICMP error.
fn build_v4_with_l4(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, ttl: u8, l4: &[u8]) -> Vec<u8> {
    let total = 20 + l4.len();
    let mut p = vec![0u8; total];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    p[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
    p[8] = ttl;
    p[9] = proto;
    p[12..16].copy_from_slice(&src.octets());
    p[16..20].copy_from_slice(&dst.octets());
    let s = checksum16(&p[..20]);
    p[10..12].copy_from_slice(&s.to_be_bytes());
    p[20..].copy_from_slice(l4);
    p
}

/// Build an IPv6 packet (header + given L4 bytes).
fn build_v6_with_l4(src: Ipv6Addr, dst: Ipv6Addr, nh: u8, hl: u8, l4: &[u8]) -> Vec<u8> {
    let mut p = vec![0u8; 40 + l4.len()];
    p[0] = 0x60;
    p[4..6].copy_from_slice(&(l4.len() as u16).to_be_bytes());
    p[6] = nh;
    p[7] = hl;
    p[8..24].copy_from_slice(&src.octets());
    p[24..40].copy_from_slice(&dst.octets());
    p[40..].copy_from_slice(l4);
    p
}

/// Wrap a quoted packet as an ICMPv4 error message: type/code/rest + quote.
/// Computes a correct ICMPv4 checksum so the input is well-formed.
fn build_icmpv4_error(typ: u8, code: u8, rest: [u8; 4], quote: &[u8]) -> Vec<u8> {
    let mut m = vec![0u8; 8 + quote.len()];
    m[0] = typ;
    m[1] = code;
    m[4..8].copy_from_slice(&rest);
    m[8..].copy_from_slice(quote);
    let s = checksum16(&m);
    m[2..4].copy_from_slice(&s.to_be_bytes());
    m
}

/// Wrap a quoted packet as an ICMPv6 error message (checksum filled by caller
/// via the IPv6 pseudo-header).
fn build_icmpv6_error(typ: u8, code: u8, rest: [u8; 4], quote: &[u8]) -> Vec<u8> {
    let mut m = vec![0u8; 8 + quote.len()];
    m[0] = typ;
    m[1] = code;
    m[4..8].copy_from_slice(&rest);
    m[8..].copy_from_slice(quote);
    m
}

// === v4 -> v6 reverse direction (the PMTUD / traceroute return path) =========

#[test]
fn nat64_v4_to_v6_time_exceeded_translates_outer_and_embedded() {
    // Topology: v6 client 2001:db8::1 reached v4 server 192.0.2.5 via the WKP.
    // SNAT pool source 198.51.100.1. A v4 hop (203.0.113.9) returns ICMPv4
    // Time Exceeded quoting the original forward v4 packet
    // (198.51.100.1 -> 192.0.2.5). The reverse translation rewrites the outer
    // addresses from the session reverse-info (src_v6 = prefix::server,
    // dst_v6 = client).
    let client_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let server_v4 = Ipv4Addr::new(192, 0, 2, 5);
    let server_v6: Ipv6Addr = "64:ff9b::c000:0205".parse().unwrap(); // prefix::192.0.2.5
    let pool_v4 = Ipv4Addr::new(198, 51, 100, 1);

    // Embedded = original forward v4 packet, quoting IP header + 8 L4 bytes.
    let inner_l4 = [0x30u8, 0x39, 0x00, 0x50, 0xaa, 0xbb, 0xcc, 0xdd]; // src/dst ports + seq
    let embedded = build_v4_with_l4(pool_v4, server_v4, PROTO_TCP, 1, &inner_l4);
    let icmp = build_icmpv4_error(11, 0, [0, 0, 0, 0], &embedded);
    let v4_pkt = build_v4_with_l4(
        Ipv4Addr::new(203, 0, 113, 9),
        pool_v4,
        PROTO_ICMP_C,
        64,
        &icmp,
    );

    // Reverse builder args: src_v6 = orig_dst (prefix::server), dst_v6 = client.
    let v6 = translate_v4_to_v6(&v4_pkt, server_v6, client_v6)
        .expect("ICMPv4 Time-Exceeded must translate, not drop");

    // Outer IPv6 header.
    assert_eq!(v6[6], PROTO_ICMPV6_C, "outer next-header must be ICMPv6");
    assert_eq!(&v6[8..24], &server_v6.octets(), "outer src = prefix::server");
    assert_eq!(&v6[24..40], &client_v6.octets(), "outer dst = client");
    // Outer ICMPv6 type/code: Time Exceeded (3), code preserved (0).
    assert_eq!(v6[40], 3, "ICMPv6 Time Exceeded type");
    assert_eq!(v6[41], 0, "code preserved");
    // Outer ICMPv6 checksum valid (independent oracle: pseudo-header sum == 0).
    let s6 = Ipv6Addr::from(<[u8; 16]>::try_from(&v6[8..24]).unwrap());
    let d6 = Ipv6Addr::from(<[u8; 16]>::try_from(&v6[24..40]).unwrap());
    assert_eq!(
        checksum16_ipv6_pseudo(s6, d6, PROTO_ICMPV6_C, &v6[40..]),
        0,
        "outer ICMPv6 checksum must verify"
    );

    // EMBEDDED translated IPv6 header begins at v6[48] (40 outer IP + 8 ICMP).
    let emb = &v6[48..];
    assert_eq!(emb[0] >> 4, 6, "embedded must be IPv6");
    assert_eq!(emb[6], PROTO_TCP, "embedded protocol preserved");
    // Embedded src (was pool_v4) -> original v6 client.
    assert_eq!(&emb[8..24], &client_v6.octets(), "embedded src = client");
    // Embedded dst (was server_v4) -> prefix::server.
    assert_eq!(&emb[24..40], &server_v6.octets(), "embedded dst = prefix::server");
    // Embedded TTL copied verbatim (NOT decremented — it's a quote).
    assert_eq!(emb[7], 1, "embedded hop limit copied verbatim");
    // Embedded quoted L4 bytes preserved.
    assert_eq!(&emb[40..48], &inner_l4, "embedded quoted L4 preserved");
    // Embedded payload length consistent.
    assert_eq!(
        u16::from_be_bytes([emb[4], emb[5]]) as usize,
        inner_l4.len(),
        "embedded payload length"
    );
}

#[test]
fn nat64_v4_to_v6_frag_needed_becomes_packet_too_big_with_mtu() {
    // ICMPv4 Dest-Unreachable / Fragmentation-Needed (3/4) carrying Next-Hop
    // MTU 1400 in bytes 6-7 -> ICMPv6 Packet-Too-Big (2/0) with MTU 1420
    // (1400 + 20, the NAT64 header delta), clamped to the v6 minimum (1280).
    let client_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let server_v4 = Ipv4Addr::new(192, 0, 2, 5);
    let server_v6: Ipv6Addr = "64:ff9b::c000:0205".parse().unwrap();
    let pool_v4 = Ipv4Addr::new(198, 51, 100, 1);

    let inner_l4 = [0x30u8, 0x39, 0x00, 0x50, 0x11, 0x22, 0x33, 0x44];
    let embedded = build_v4_with_l4(pool_v4, server_v4, PROTO_TCP, 60, &inner_l4);
    // RFC 1191: Frag-Needed rest-of-header = [unused(2)][next-hop MTU(2)].
    let rest = [0u8, 0, (1400u16 >> 8) as u8, 1400u16 as u8];
    let icmp = build_icmpv4_error(3, 4, rest, &embedded);
    let v4_pkt = build_v4_with_l4(server_v4, pool_v4, PROTO_ICMP_C, 64, &icmp);

    let v6 = translate_v4_to_v6(&v4_pkt, server_v6, client_v6)
        .expect("ICMPv4 Frag-Needed must translate to Packet-Too-Big, not drop");

    assert_eq!(v6[40], 2, "ICMPv6 Packet Too Big type");
    assert_eq!(v6[41], 0, "PTB code 0");
    // MTU is the full 32-bit rest-of-header word (bytes 4-7 of the ICMPv6 msg).
    let mtu = u32::from_be_bytes([v6[44], v6[45], v6[46], v6[47]]);
    assert_eq!(mtu, 1420, "PTB MTU must be v4 next-hop MTU + 20");
    // Checksum oracle.
    let s6 = Ipv6Addr::from(<[u8; 16]>::try_from(&v6[8..24]).unwrap());
    let d6 = Ipv6Addr::from(<[u8; 16]>::try_from(&v6[24..40]).unwrap());
    assert_eq!(checksum16_ipv6_pseudo(s6, d6, PROTO_ICMPV6_C, &v6[40..]), 0);

    // Embedded check: addresses mapped.
    let emb = &v6[48..];
    assert_eq!(&emb[8..24], &client_v6.octets(), "embedded src = client");
    assert_eq!(&emb[24..40], &server_v6.octets(), "embedded dst = prefix::server");
}

#[test]
fn nat64_v4_to_v6_frag_needed_mtu_clamped_to_v6_minimum() {
    // A tiny advertised v4 MTU (e.g. 1000) + 20 = 1020 < 1280; clamp to 1280
    // so the v6 client is never told to go below the IPv6 minimum link MTU.
    let client_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let server_v6: Ipv6Addr = "64:ff9b::c000:0205".parse().unwrap();
    let pool_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let server_v4 = Ipv4Addr::new(192, 0, 2, 5);

    let embedded = build_v4_with_l4(pool_v4, server_v4, PROTO_UDP, 60, &[0u8; 8]);
    let rest = [0u8, 0, (1000u16 >> 8) as u8, 1000u16 as u8];
    let icmp = build_icmpv4_error(3, 4, rest, &embedded);
    let v4_pkt = build_v4_with_l4(server_v4, pool_v4, PROTO_ICMP_C, 64, &icmp);

    let v6 = translate_v4_to_v6(&v4_pkt, server_v6, client_v6).expect("translate");
    let mtu = u32::from_be_bytes([v6[44], v6[45], v6[46], v6[47]]);
    assert_eq!(mtu, 1280, "MTU must clamp to the IPv6 minimum link MTU");
}

#[test]
fn nat64_v4_to_v6_dest_unreachable_port_maps() {
    // ICMPv4 Dest-Unreachable / Port-Unreachable (3/3) -> ICMPv6
    // Dest-Unreachable / Port-Unreachable (1/4).
    let client_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let server_v6: Ipv6Addr = "64:ff9b::c000:0205".parse().unwrap();
    let pool_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let server_v4 = Ipv4Addr::new(192, 0, 2, 5);

    let inner_l4 = [0x00u8, 0x35, 0x12, 0x34, 0xde, 0xad, 0xbe, 0xef];
    let embedded = build_v4_with_l4(pool_v4, server_v4, PROTO_UDP, 60, &inner_l4);
    let icmp = build_icmpv4_error(3, 3, [0, 0, 0, 0], &embedded);
    let v4_pkt = build_v4_with_l4(server_v4, pool_v4, PROTO_ICMP_C, 64, &icmp);

    let v6 = translate_v4_to_v6(&v4_pkt, server_v6, client_v6)
        .expect("ICMPv4 Port-Unreachable must translate, not drop");
    assert_eq!(v6[40], 1, "ICMPv6 Destination Unreachable type");
    assert_eq!(v6[41], 4, "ICMPv6 Port Unreachable code");
    let s6 = Ipv6Addr::from(<[u8; 16]>::try_from(&v6[8..24]).unwrap());
    let d6 = Ipv6Addr::from(<[u8; 16]>::try_from(&v6[24..40]).unwrap());
    assert_eq!(checksum16_ipv6_pseudo(s6, d6, PROTO_ICMPV6_C, &v6[40..]), 0);
    let emb = &v6[48..];
    assert_eq!(&emb[8..24], &client_v6.octets());
    assert_eq!(&emb[24..40], &server_v6.octets());
    assert_eq!(emb[6], PROTO_UDP, "embedded protocol preserved");
    assert_eq!(&emb[40..48], &inner_l4, "embedded quoted L4 preserved");
}

// === v6 -> v4 forward direction =============================================

#[test]
fn nat64_v6_to_v4_packet_too_big_becomes_frag_needed_with_mtu() {
    // ICMPv6 Packet-Too-Big (type 2) MTU 1500 -> ICMPv4 Dest-Unreachable /
    // Fragmentation-Needed (3/4), next-hop MTU 1480 (1500 - 20).
    let client_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::0808:0808".parse().unwrap(); // prefix::8.8.8.8
    let snat_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let dst_v4 = Ipv4Addr::new(8, 8, 8, 8);

    // Embedded = original v6 forward packet (client -> prefix::8.8.8.8).
    let inner_l4 = [0x30u8, 0x39, 0x00, 0x50, 0x01, 0x02, 0x03, 0x04];
    let embedded = build_v6_with_l4(client_v6, dst_v6, PROTO_TCP, 1, &inner_l4);
    // ICMPv6 PTB rest-of-header = the 32-bit MTU.
    let icmp = build_icmpv6_error(2, 0, 1500u32.to_be_bytes(), &embedded);
    // Wrap as a v6 packet from a v6 hop back toward dst_v6 with valid checksum.
    let hop_v6: Ipv6Addr = "2001:db8:ffff::1".parse().unwrap();
    let mut v6_pkt = build_v6_with_l4(hop_v6, client_v6, PROTO_ICMPV6_C, 64, &icmp);
    // Fix the outer ICMPv6 checksum for the input.
    let icmp_off = 40;
    v6_pkt[icmp_off + 2..icmp_off + 4].copy_from_slice(&[0, 0]);
    let s = checksum16_ipv6_pseudo(hop_v6, client_v6, PROTO_ICMPV6_C, &v6_pkt[icmp_off..]);
    v6_pkt[icmp_off + 2..icmp_off + 4].copy_from_slice(&s.to_be_bytes());

    let v4 = translate_v6_to_v4(&v6_pkt, snat_v4, dst_v4, false)
        .expect("ICMPv6 Packet-Too-Big must translate to Frag-Needed, not drop");

    assert_eq!(v4[9], PROTO_ICMP_C, "outer protocol ICMPv4");
    assert_eq!(v4[20], 3, "ICMPv4 Destination Unreachable type");
    assert_eq!(v4[21], 4, "ICMPv4 Fragmentation Needed code");
    // Next-hop MTU in bytes 26-27 (ICMP rest-of-header word, low 16 bits).
    let mtu = u16::from_be_bytes([v4[26], v4[27]]);
    assert_eq!(mtu, 1480, "next-hop MTU = v6 MTU - 20");
    // Outer IPv4 + ICMPv4 checksums valid (oracle).
    assert_eq!(checksum16(&v4[..20]), 0, "outer IPv4 header checksum");
    assert_eq!(checksum16(&v4[20..]), 0, "outer ICMPv4 checksum");

    // EMBEDDED translated IPv4 header begins at v4[28] (20 IP + 8 ICMP).
    let emb = &v4[28..];
    assert_eq!(emb[0], 0x45, "embedded IPv4 header");
    assert_eq!(emb[9], PROTO_TCP, "embedded protocol preserved");
    // Embedded src (was client_v6) -> dst_v4 (the mapped embedded src).
    assert_eq!(&emb[12..16], &dst_v4.octets(), "embedded src mapped to dst_v4");
    // Embedded dst (was prefix::8.8.8.8) -> snat_v4 (mapped embedded dst).
    assert_eq!(&emb[16..20], &snat_v4.octets(), "embedded dst mapped to snat_v4");
    // Embedded IPv4 header checksum valid (oracle).
    assert_eq!(checksum16(&emb[..20]), 0, "embedded IPv4 header checksum");
    assert_eq!(&emb[20..28], &inner_l4, "embedded quoted L4 preserved");
}

#[test]
fn nat64_v6_to_v4_time_exceeded_translates() {
    // ICMPv6 Time Exceeded (3) -> ICMPv4 Time Exceeded (11), code preserved.
    let client_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::0808:0808".parse().unwrap();
    let snat_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let dst_v4 = Ipv4Addr::new(8, 8, 8, 8);

    let inner_l4 = [0x30u8, 0x39, 0x00, 0x50, 0x09, 0x08, 0x07, 0x06];
    let embedded = build_v6_with_l4(client_v6, dst_v6, PROTO_UDP, 1, &inner_l4);
    let icmp = build_icmpv6_error(3, 0, [0, 0, 0, 0], &embedded);
    let hop_v6: Ipv6Addr = "2001:db8:ffff::1".parse().unwrap();
    let mut v6_pkt = build_v6_with_l4(hop_v6, client_v6, PROTO_ICMPV6_C, 64, &icmp);
    v6_pkt[42..44].copy_from_slice(&[0, 0]);
    let s = checksum16_ipv6_pseudo(hop_v6, client_v6, PROTO_ICMPV6_C, &v6_pkt[40..]);
    v6_pkt[42..44].copy_from_slice(&s.to_be_bytes());

    let v4 = translate_v6_to_v4(&v6_pkt, snat_v4, dst_v4, false)
        .expect("ICMPv6 Time-Exceeded must translate, not drop");
    assert_eq!(v4[20], 11, "ICMPv4 Time Exceeded type");
    assert_eq!(v4[21], 0, "code preserved");
    assert_eq!(checksum16(&v4[..20]), 0);
    assert_eq!(checksum16(&v4[20..]), 0);
    let emb = &v4[28..];
    assert_eq!(&emb[12..16], &dst_v4.octets());
    assert_eq!(&emb[16..20], &snat_v4.octets());
    assert_eq!(checksum16(&emb[..20]), 0);
}

#[test]
fn nat64_v6_to_v4_dest_unreachable_admin_maps() {
    // ICMPv6 Dest-Unreachable / admin-prohibited (1/1) -> ICMPv4
    // Dest-Unreachable / comm-administratively-prohibited (3/10).
    let client_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::0808:0808".parse().unwrap();
    let snat_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let dst_v4 = Ipv4Addr::new(8, 8, 8, 8);

    let embedded = build_v6_with_l4(client_v6, dst_v6, PROTO_TCP, 1, &[0u8; 8]);
    let icmp = build_icmpv6_error(1, 1, [0, 0, 0, 0], &embedded);
    let hop_v6: Ipv6Addr = "2001:db8:ffff::1".parse().unwrap();
    let mut v6_pkt = build_v6_with_l4(hop_v6, client_v6, PROTO_ICMPV6_C, 64, &icmp);
    v6_pkt[42..44].copy_from_slice(&[0, 0]);
    let s = checksum16_ipv6_pseudo(hop_v6, client_v6, PROTO_ICMPV6_C, &v6_pkt[40..]);
    v6_pkt[42..44].copy_from_slice(&s.to_be_bytes());

    let v4 = translate_v6_to_v4(&v6_pkt, snat_v4, dst_v4, false)
        .expect("ICMPv6 admin-prohibited must translate, not drop");
    assert_eq!(v4[20], 3, "ICMPv4 Destination Unreachable type");
    assert_eq!(v4[21], 10, "ICMPv4 comm admin prohibited code");
    assert_eq!(checksum16(&v4[20..]), 0);
}

// === regression: echo still works (no behavior change) ======================

#[test]
fn nat64_icmp_echo_unaffected_by_error_path() {
    // The echo path must remain byte-correct after the error-path refactor.
    let src_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::0808:0808".parse().unwrap();
    let snat_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let dst_v4 = Ipv4Addr::new(8, 8, 8, 8);
    let mut icmp = vec![0u8; 8];
    icmp[0] = ICMPV6_ECHO_REQUEST;
    icmp[4..6].copy_from_slice(&0x1234u16.to_be_bytes());
    icmp[6..8].copy_from_slice(&0x0001u16.to_be_bytes());
    let mut pkt = build_v6_with_l4(src_v6, dst_v6, PROTO_ICMPV6_C, 64, &icmp);
    let s = checksum16_ipv6_pseudo(src_v6, dst_v6, PROTO_ICMPV6_C, &pkt[40..]);
    pkt[42..44].copy_from_slice(&s.to_be_bytes());

    let v4 = translate_v6_to_v4(&pkt, snat_v4, dst_v4, false).expect("echo translate");
    assert_eq!(v4[20], ICMP_ECHO_REQUEST);
    assert_eq!(v4.len(), 20 + 8, "echo length unchanged");
    assert_eq!(checksum16(&v4[20..]), 0);
}

#[test]
fn nat64_truncated_icmp_error_header_dropped_not_panicked() {
    // A Packet-Too-Big / Frag-Needed message with a truncated rest-of-header
    // (< 8 ICMP bytes) must be dropped, never panic on an out-of-bounds index
    // of the attacker-controlled MTU word.
    let src_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::0808:0808".parse().unwrap();
    let snat_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let dst_v4 = Ipv4Addr::new(8, 8, 8, 8);
    // ICMPv6 PTB header truncated to 6 bytes (no full MTU word).
    let icmp = vec![2u8, 0, 0, 0, 0, 0];
    let mut pkt = build_v6_with_l4(src_v6, dst_v6, PROTO_ICMPV6_C, 64, &icmp);
    let s = checksum16_ipv6_pseudo(src_v6, dst_v6, PROTO_ICMPV6_C, &pkt[40..]);
    pkt[42..44].copy_from_slice(&s.to_be_bytes());
    assert!(
        translate_v6_to_v4(&pkt, snat_v4, dst_v4, false).is_none(),
        "truncated ICMPv6 PTB must be dropped"
    );

    // ICMPv4 Frag-Needed header truncated to 6 bytes.
    let server_v4 = Ipv4Addr::new(192, 0, 2, 5);
    let server_v6: Ipv6Addr = "64:ff9b::c000:0205".parse().unwrap();
    let client_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let pool_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let icmp4 = vec![3u8, 4, 0, 0, 0, 0]; // 6 bytes, no next-hop MTU word
    let mut p4 = build_v4_with_l4(server_v4, pool_v4, PROTO_ICMP_C, 64, &icmp4);
    let s4 = checksum16(&p4[20..]);
    p4[22..24].copy_from_slice(&s4.to_be_bytes());
    assert!(
        translate_v4_to_v6(&p4, server_v6, client_v6).is_none(),
        "truncated ICMPv4 Frag-Needed must be dropped"
    );
}

#[test]
fn nat64_unsupported_icmpv6_type_still_dropped() {
    // A link-local-only ICMPv6 type (e.g. Neighbor Solicitation 135) has no
    // IPv4 mapping and must still be dropped (None), not mistranslated.
    let src_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::0808:0808".parse().unwrap();
    let snat_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let dst_v4 = Ipv4Addr::new(8, 8, 8, 8);
    let icmp = vec![135u8, 0, 0, 0, 0, 0, 0, 0]; // Neighbor Solicitation
    let mut pkt = build_v6_with_l4(src_v6, dst_v6, PROTO_ICMPV6_C, 64, &icmp);
    let s = checksum16_ipv6_pseudo(src_v6, dst_v6, PROTO_ICMPV6_C, &pkt[40..]);
    pkt[42..44].copy_from_slice(&s.to_be_bytes());
    assert!(
        translate_v6_to_v4(&pkt, snat_v4, dst_v4, false).is_none(),
        "unmappable ICMPv6 type must be dropped"
    );
}

// ===========================================================================
// #6472: flowless NAT64 ICMP-error translation — embedded-quote L4
// port/identifier restoration. The quote must read back as the tuple the
// ERROR RECEIVER carries for the flow: v4→v6 the ORIGINAL v6 client
// source port/echo id (the wire quote holds the translated pool value);
// v6→v4 the TRANSLATED pool destination port/echo id (the wire quote holds
// the original client value). Without the restore the error is delivered
// but unassociable — PMTUD dead, the exact defect class of the issue.
// ===========================================================================

#[test]
fn nat64_v4_to_v6_icmp_error_restores_embedded_src_port_6472() {
    // v6 client 2001:db8::1 :12345 -> 64:ff9b::c000:0205 :443, translated on
    // the v4 wire to pool 198.51.100.1 :40000. A v4 hop (203.0.113.9) sends
    // Time-Exceeded quoting the FORWARD wire packet (pool:40000 -> server:443).
    let client_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let server_v4 = Ipv4Addr::new(192, 0, 2, 5);
    let server_v6: Ipv6Addr = "64:ff9b::c000:0205".parse().unwrap();
    let pool_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let router_v4 = Ipv4Addr::new(203, 0, 113, 9);
    // The translated error's outer src = Pref64 :: router (RFC 7915 §6
    // stateless mapping of the error's sender).
    let router_v6: Ipv6Addr = "64:ff9b::cb00:7109".parse().unwrap();

    let inner_l4 = [0x9Cu8, 0x40, 0x01, 0xBB, 0xaa, 0xbb, 0xcc, 0xdd]; // 40000 -> 443
    let embedded = build_v4_with_l4(pool_v4, server_v4, PROTO_TCP, 1, &inner_l4);
    let icmp = build_icmpv4_error(11, 0, [0, 0, 0, 0], &embedded);
    let v4_pkt = build_v4_with_l4(router_v4, pool_v4, PROTO_ICMP_C, 64, &icmp);

    let mut buf = vec![0u8; v4_pkt.len() + 64];
    let written = write_v4_to_v6_icmp_error_into(
        &mut buf,
        &v4_pkt,
        router_v6,
        client_v6,
        Some(12345),
    )
    .expect("ICMPv4 Time-Exceeded must translate");
    let v6 = &buf[..written];

    assert_eq!(&v6[8..24], &router_v6.octets(), "outer src = Pref64::router");
    assert_eq!(&v6[24..40], &client_v6.octets(), "outer dst = v6 client");
    assert_eq!(v6[40], 3, "ICMPv6 Time Exceeded type");
    // Embedded quote (v6 header at v6[48..88], L4 at 88..): reads back as the
    // ORIGINAL client tuple — the source port is RESTORED to 12345.
    let emb = &v6[48..];
    assert_eq!(&emb[8..24], &client_v6.octets(), "embedded src = client");
    assert_eq!(&emb[24..40], &server_v6.octets(), "embedded dst = Pref64::server");
    assert_eq!(
        &emb[40..42],
        &12345u16.to_be_bytes(),
        "quote src port must be restored to the ORIGINAL client port"
    );
    assert_eq!(
        &emb[42..44],
        &443u16.to_be_bytes(),
        "quote dst port untouched"
    );
    // The outer ICMPv6 checksum covers the restored bytes (pseudo-header oracle).
    let s6 = Ipv6Addr::from(<[u8; 16]>::try_from(&v6[8..24]).unwrap());
    let d6 = Ipv6Addr::from(<[u8; 16]>::try_from(&v6[24..40]).unwrap());
    assert_eq!(
        checksum16_ipv6_pseudo(s6, d6, PROTO_ICMPV6_C, &v6[40..]),
        0,
        "outer ICMPv6 checksum must verify over the restored quote"
    );

    // RED-on-revert pin: the None / data-packet entry leaves the TRANSLATED
    // pool port verbatim (the pre-#6472, unassociable behavior).
    let mut buf2 = vec![0u8; v4_pkt.len() + 64];
    let w2 = write_v4_to_v6_into(&mut buf2, &v4_pkt, router_v6, client_v6)
        .expect("data-packet entry translates");
    assert_eq!(
        &buf2[48 + 40..48 + 42],
        &40000u16.to_be_bytes(),
        "None port map must leave the translated pool port (revert of #6472 keeps this RED)"
    );
    // ... and the icmp_error entry with None is byte-identical to it.
    let mut buf3 = vec![0u8; v4_pkt.len() + 64];
    let w3 = write_v4_to_v6_icmp_error_into(&mut buf3, &v4_pkt, router_v6, client_v6, None)
        .expect("icmp-error entry with None translates");
    assert_eq!(&buf2[..w2], &buf3[..w3], "None == data-packet entry, byte-for-byte");
}

#[test]
fn nat64_v4_to_v6_icmp_error_restores_embedded_echo_id_6472() {
    // Same topology as the TCP case, but the quoted packet is an ICMPv4 echo
    // request (pool:xlated_id -> server). The client's echo identifier is
    // restored at the L4 identifier offset (bytes 4-6 of the quoted L4).
    let client_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let server_v4 = Ipv4Addr::new(192, 0, 2, 5);
    let pool_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let router_v4 = Ipv4Addr::new(203, 0, 113, 9);
    let router_v6: Ipv6Addr = "64:ff9b::cb00:7109".parse().unwrap();

    let inner_l4 = [8u8, 0, 0xAA, 0xBB, 0x9C, 0x40, 0x00, 0x01]; // echo req, csum, id 40000, seq
    let embedded = build_v4_with_l4(pool_v4, server_v4, PROTO_ICMP_C, 1, &inner_l4);
    let icmp = build_icmpv4_error(11, 0, [0, 0, 0, 0], &embedded);
    let v4_pkt = build_v4_with_l4(router_v4, pool_v4, PROTO_ICMP_C, 64, &icmp);

    let mut buf = vec![0u8; v4_pkt.len() + 64];
    let written =
        write_v4_to_v6_icmp_error_into(&mut buf, &v4_pkt, router_v6, client_v6, Some(12345))
            .expect("echo-quoting error must translate");
    let v6 = &buf[..written];
    let emb = &v6[48..];
    assert_eq!(emb[6], PROTO_ICMPV6_C, "embedded proto maps ICMP -> ICMPv6");
    assert_eq!(emb[40], 128, "embedded echo request maps to ICMPv6 echo request");
    assert_eq!(
        &emb[44..46],
        &12345u16.to_be_bytes(),
        "embedded echo id must be restored to the ORIGINAL client id"
    );
    let s6 = Ipv6Addr::from(<[u8; 16]>::try_from(&v6[8..24]).unwrap());
    let d6 = Ipv6Addr::from(<[u8; 16]>::try_from(&v6[24..40]).unwrap());
    assert_eq!(checksum16_ipv6_pseudo(s6, d6, PROTO_ICMPV6_C, &v6[40..]), 0);
}

#[test]
fn nat64_v6_to_v4_icmp_error_restores_embedded_dst_port_6472() {
    // The session's translated REPLY (64:ff9b::808:808:443 -> client:12345)
    // dies at a v6 hop (2001:db8:ffff::1), which returns Time-Exceeded
    // addressed to the synthetic source. The translated ICMPv4 error must
    // quote (8.8.8.8:443 -> pool:40000) — the DESTINATION port restored to
    // the TRANSLATED value the v4 server replied to — or the server cannot
    // associate the error with its socket.
    let client_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::0808:0808".parse().unwrap(); // Pref64::8.8.8.8
    let pool_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let server_v4 = Ipv4Addr::new(8, 8, 8, 8);

    let inner_l4 = [0x01u8, 0xBB, 0x30, 0x39, 0x01, 0x02, 0x03, 0x04]; // 443 -> 12345
    let embedded = build_v6_with_l4(dst_v6, client_v6, PROTO_TCP, 1, &inner_l4);
    let icmp = build_icmpv6_error(3, 0, [0, 0, 0, 0], &embedded);
    let hop_v6: Ipv6Addr = "2001:db8:ffff::1".parse().unwrap();
    let mut v6_pkt = build_v6_with_l4(hop_v6, dst_v6, PROTO_ICMPV6_C, 64, &icmp);
    v6_pkt[42..44].copy_from_slice(&[0, 0]);
    let s = checksum16_ipv6_pseudo(hop_v6, dst_v6, PROTO_ICMPV6_C, &v6_pkt[40..]);
    v6_pkt[42..44].copy_from_slice(&s.to_be_bytes());

    let mut buf = vec![0u8; v6_pkt.len() + 64];
    let written = write_v6_to_v4_icmp_error_into(
        &mut buf,
        &v6_pkt,
        pool_v4,
        server_v4,
        false,
        Some(40000),
    )
    .expect("ICMPv6 Time-Exceeded must translate");
    let v4 = &buf[..written];

    assert_eq!(&v4[12..16], &pool_v4.octets(), "outer src = translator pool address");
    assert_eq!(&v4[16..20], &server_v4.octets(), "outer dst = v4 server");
    assert_eq!(v4[20], 11, "ICMPv4 Time Exceeded type");
    // Embedded quote (v4 header at v4[28..48], L4 at 48..): reads back as the
    // v4 reply the server sent — dst port RESTORED to the translated value.
    let emb = &v4[28..];
    assert_eq!(&emb[12..16], &server_v4.octets(), "embedded src = server");
    assert_eq!(&emb[16..20], &pool_v4.octets(), "embedded dst = pool");
    assert_eq!(
        &emb[20..22],
        &443u16.to_be_bytes(),
        "quote src port untouched"
    );
    assert_eq!(
        &emb[22..24],
        &40000u16.to_be_bytes(),
        "quote dst port must be restored to the TRANSLATED pool port"
    );
    // Checksum oracles cover the restored bytes.
    assert_eq!(checksum16(&v4[..20]), 0, "outer IPv4 header checksum");
    assert_eq!(checksum16(&v4[20..]), 0, "outer ICMPv4 checksum");
    assert_eq!(checksum16(&emb[..20]), 0, "embedded IPv4 header checksum");

    // RED-on-revert pin: the data-packet entry leaves the ORIGINAL client
    // port verbatim (unassociable — the pre-#6472 behavior).
    let mut buf2 = vec![0u8; v6_pkt.len() + 64];
    let w2 = write_v6_to_v4_into(&mut buf2, &v6_pkt, pool_v4, server_v4, false)
        .expect("data-packet entry translates");
    assert_eq!(
        &buf2[28 + 22..28 + 24],
        &12345u16.to_be_bytes(),
        "None port map must leave the original client port (revert of #6472 keeps this RED)"
    );
}

#[test]
fn nat64_v6_to_v4_icmp_error_restores_embedded_echo_id_6472() {
    // The quoted reply is an ICMPv6 echo REPLY (Pref64::server -> client) —
    // its identifier is the ORIGINAL client id on the v6 side; the v4 server
    // only associates the TRANSLATED id it echoed back. Restore at the L4
    // identifier offset.
    let client_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::0808:0808".parse().unwrap();
    let pool_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let server_v4 = Ipv4Addr::new(8, 8, 8, 8);

    let inner_l4 = [129u8, 0, 0xAA, 0xBB, 0x30, 0x39, 0x00, 0x01]; // echo reply, csum, id 12345, seq
    let embedded = build_v6_with_l4(dst_v6, client_v6, PROTO_ICMPV6_C, 1, &inner_l4);
    let icmp = build_icmpv6_error(3, 0, [0, 0, 0, 0], &embedded);
    let hop_v6: Ipv6Addr = "2001:db8:ffff::1".parse().unwrap();
    let mut v6_pkt = build_v6_with_l4(hop_v6, dst_v6, PROTO_ICMPV6_C, 64, &icmp);
    v6_pkt[42..44].copy_from_slice(&[0, 0]);
    let s = checksum16_ipv6_pseudo(hop_v6, dst_v6, PROTO_ICMPV6_C, &v6_pkt[40..]);
    v6_pkt[42..44].copy_from_slice(&s.to_be_bytes());

    let mut buf = vec![0u8; v6_pkt.len() + 64];
    let written = write_v6_to_v4_icmp_error_into(
        &mut buf,
        &v6_pkt,
        pool_v4,
        server_v4,
        false,
        Some(40000),
    )
    .expect("echo-reply-quoting error must translate");
    let v4 = &buf[..written];
    let emb = &v4[28..];
    assert_eq!(emb[9], PROTO_ICMP_C, "embedded proto maps ICMPv6 -> ICMP");
    assert_eq!(emb[20], 0, "embedded echo reply maps to ICMPv4 echo reply");
    assert_eq!(
        &emb[24..26],
        &40000u16.to_be_bytes(),
        "embedded echo id must be restored to the TRANSLATED id"
    );
    assert_eq!(checksum16(&v4[20..]), 0);
}

// ===========================================================================
// #2290: IPv6 extension-header walk in the v6->v4 translator.
//
// Pre-fix the translator read packet[6] as the L4 protocol and assumed L4 at
// byte 40, so any packet carrying a Hop-by-Hop / Routing / Dest-Opts / AH /
// Fragment header before its transport header was dropped as "unsupported
// protocol". These tests are FAIL-ON-REVERT: each builds a valid v6 packet
// with an extension header before TCP/UDP and asserts it TRANSLATES (not
// dropped). Reverting the fix (fixed offset 40 + raw next-header) reads the
// ext-header type as the L4 protocol -> `expect("translate")` panics.
// ===========================================================================

/// Build an IPv6 packet carrying ONE extension header (`ext_type`, given
/// option bytes) before the terminal L4 (`l4_proto`, `l4` bytes). The ext
/// header is `Type-Length-Optiondata` per RFC 8200: byte 0 = next-header
/// (the L4 proto), byte 1 = Hdr Ext Len in 8-octet units NOT counting the
/// first 8 octets. `ext_payload` is the option data AFTER the 2-byte
/// type/len; its length must make the ext header a multiple of 8 octets.
fn build_v6_with_ext_then_l4(
    src: Ipv6Addr,
    dst: Ipv6Addr,
    ext_type: u8,
    ext_payload: &[u8],
    l4_proto: u8,
    hl: u8,
    l4: &[u8],
) -> Vec<u8> {
    // ext header = [next_header, hdr_ext_len, ext_payload...]
    let ext_len_bytes = 2 + ext_payload.len();
    assert_eq!(ext_len_bytes % 8, 0, "ext header must be a multiple of 8");
    let hdr_ext_len = (ext_len_bytes / 8 - 1) as u8;
    let mut p = vec![0u8; 40 + ext_len_bytes + l4.len()];
    p[0] = 0x60;
    // IPv6 payload_len covers ext header + L4.
    p[4..6].copy_from_slice(&((ext_len_bytes + l4.len()) as u16).to_be_bytes());
    p[6] = ext_type; // first next-header points at the ext header
    p[7] = hl;
    p[8..24].copy_from_slice(&src.octets());
    p[24..40].copy_from_slice(&dst.octets());
    // Extension header.
    p[40] = l4_proto; // ext's next-header = terminal L4
    p[41] = hdr_ext_len;
    p[42..42 + ext_payload.len()].copy_from_slice(ext_payload);
    // L4.
    let l4_off = 40 + ext_len_bytes;
    p[l4_off..l4_off + l4.len()].copy_from_slice(l4);
    p
}

#[test]
fn ipv6_l4_offset_walks_dest_opts_then_tcp() {
    // Dest-Opts (60) 8 bytes, then TCP at offset 48.
    let src: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst: Ipv6Addr = "64:ff9b::0808:0808".parse().unwrap();
    let pkt = build_v6_with_ext_then_l4(src, dst, 60, &[0u8; 6], PROTO_TCP, 64, &[0u8; 20]);
    let (off, proto) = ipv6_l4_offset_and_protocol(&pkt).expect("walk must find L4");
    assert_eq!(off, 48, "TCP starts after the 8-byte Dest-Opts header");
    assert_eq!(proto, PROTO_TCP);
}

#[test]
fn ipv6_l4_offset_walks_hop_by_hop_then_udp() {
    let src: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst: Ipv6Addr = "64:ff9b::0808:0808".parse().unwrap();
    let pkt = build_v6_with_ext_then_l4(src, dst, 0, &[0u8; 6], PROTO_UDP, 64, &[0u8; 8]);
    let (off, proto) = ipv6_l4_offset_and_protocol(&pkt).expect("walk must find L4");
    assert_eq!(off, 48);
    assert_eq!(proto, PROTO_UDP);
}

#[test]
fn translate_v6_to_v4_tcp_behind_dest_opts() {
    // FAIL-ON-REVERT: a Dest-Opts header before TCP. Pre-fix this read
    // next_header=60 (Dest-Opts) as the protocol -> `_ => return None` drop.
    let src_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::c633:6432".parse().unwrap();
    let snat_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let dst_v4 = Ipv4Addr::new(198, 51, 100, 50);

    // Minimal TCP header (20 bytes) + 5-byte payload, ports 12345 -> 80.
    let mut tcp = vec![0u8; 25];
    tcp[0..2].copy_from_slice(&12345u16.to_be_bytes());
    tcp[2..4].copy_from_slice(&80u16.to_be_bytes());
    tcp[12] = 0x50; // data offset 5
    tcp[13] = 0x02; // SYN
    tcp[20..25].copy_from_slice(b"hello");

    let ipv6_pkt =
        build_v6_with_ext_then_l4(src_v6, dst_v6, 60, &[0u8; 6], PROTO_TCP, 64, &tcp);
    let v4 = translate_v6_to_v4(&ipv6_pkt, snat_v4, dst_v4, false)
        .expect("TCP behind Dest-Opts must translate, not drop");

    assert_eq!(v4[0], 0x45);
    assert_eq!(v4[9], PROTO_TCP, "protocol must be the terminal L4, not 60");
    assert_eq!(&v4[12..16], &snat_v4.octets());
    assert_eq!(&v4[16..20], &dst_v4.octets());
    // The ext header is stripped: IPv4 length = 20 + 25 (NOT 20 + 8 + 25).
    assert_eq!(v4.len(), 20 + 25, "Dest-Opts header stripped from output");
    // TCP ports preserved at the IPv4 L4 offset.
    assert_eq!(u16::from_be_bytes([v4[20], v4[21]]), 12345);
    assert_eq!(u16::from_be_bytes([v4[22], v4[23]]), 80);
    assert_eq!(checksum16(&v4[..20]), 0, "IPv4 header checksum valid");
}

#[test]
fn translate_v6_to_v4_udp_behind_hop_by_hop() {
    // FAIL-ON-REVERT: UDP behind a Hop-by-Hop (0) header.
    let src_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::0808:0808".parse().unwrap();
    let snat_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let dst_v4 = Ipv4Addr::new(8, 8, 8, 8);

    let mut udp = vec![0u8; 8 + 4];
    udp[0..2].copy_from_slice(&5353u16.to_be_bytes());
    udp[2..4].copy_from_slice(&53u16.to_be_bytes());
    udp[4..6].copy_from_slice(&(12u16).to_be_bytes()); // UDP length
    udp[8..12].copy_from_slice(b"data");

    let ipv6_pkt = build_v6_with_ext_then_l4(src_v6, dst_v6, 0, &[0u8; 6], PROTO_UDP, 64, &udp);
    let v4 = translate_v6_to_v4(&ipv6_pkt, snat_v4, dst_v4, false)
        .expect("UDP behind Hop-by-Hop must translate, not drop");

    assert_eq!(v4[9], PROTO_UDP, "protocol must be the terminal L4, not 0");
    assert_eq!(v4.len(), 20 + 12, "Hop-by-Hop header stripped");
    assert_eq!(u16::from_be_bytes([v4[20], v4[21]]), 5353);
    assert_eq!(u16::from_be_bytes([v4[22], v4[23]]), 53);
}

#[test]
fn translate_v6_to_v4_udp_behind_mobility_header() {
    // #4517 kept the NAT64 walker in PARITY with the canonical afxdp walkers so
    // it RESOLVES the terminal L4 past a Mobility (135) header. #5625 preserves
    // that L4-resolution parity for the forwarding/screen paths but ADDS a
    // NAT64 translate-path RFC 7915 §5.1 eligibility reject: Mobility has no
    // IPv4 equivalent, so translating would silently strip it. The walker still
    // resolves the inner UDP (parity intact), but the TRANSLATOR now DROPS the
    // packet instead of emitting a stripped IPv4 datagram. This test therefore
    // pins BOTH invariants and goes RED if either regresses (walker stops
    // resolving, or the translate-path reject is removed).
    let src_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::0808:0808".parse().unwrap();
    let snat_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let dst_v4 = Ipv4Addr::new(8, 8, 8, 8);

    let mut udp = vec![0u8; 8 + 4];
    udp[0..2].copy_from_slice(&5353u16.to_be_bytes());
    udp[2..4].copy_from_slice(&53u16.to_be_bytes());
    udp[4..6].copy_from_slice(&(12u16).to_be_bytes()); // UDP length
    udp[8..12].copy_from_slice(b"data");

    let ipv6_pkt = build_v6_with_ext_then_l4(src_v6, dst_v6, 135, &[0u8; 6], PROTO_UDP, 64, &udp);

    // #4517 parity preserved: the shared L4-resolution walker STILL traverses
    // the 8-byte Mobility header to the terminal UDP (unchanged behavior the
    // forwarding/screen paths depend on).
    assert_eq!(
        ipv6_l4_offset_and_protocol(&ipv6_pkt),
        Some((40 + 8, PROTO_UDP)),
        "walker must still resolve the terminal UDP past Mobility (parity intact)"
    );

    // #5625: the NAT64 translate path now REJECTS it (fail-closed drop) — a
    // Mobility header cannot be represented in IPv4 (RFC 7915 §5.1).
    assert!(
        translate_v6_to_v4(&ipv6_pkt, snat_v4, dst_v4, false).is_none(),
        "Mobility-header packet must be dropped by NAT64 translation (RFC 7915 §5.1)"
    );
    assert!(
        nat64_v6_translation_ineligible(&ipv6_pkt),
        "Mobility chain must be classified translation-ineligible"
    );
}

#[test]
fn translate_v6_to_v4_non_first_fragment_dropped() {
    // A non-first fragment carries no L4 header. The walker must NOT read its
    // payload bytes as a transport header — fail closed (drop).
    let src_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::0808:0808".parse().unwrap();
    let snat_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let dst_v4 = Ipv4Addr::new(8, 8, 8, 8);

    // Fragment header (44), 8 bytes: next-header=TCP, frag-offset != 0.
    // bytes: [nh, reserved, frag_off_hi, frag_off_lo|flags, id(4)].
    // Set fragment offset to 0x0010 (>0) in the upper 13 bits.
    let mut frag = vec![0u8; 8 + 16]; // frag header + 16 "payload" bytes
    frag[0] = PROTO_TCP; // next-header
    frag[2..4].copy_from_slice(&0x0010u16.to_be_bytes()); // frag offset != 0
    let mut pkt = vec![0u8; 40 + frag.len()];
    pkt[0] = 0x60;
    pkt[4..6].copy_from_slice(&(frag.len() as u16).to_be_bytes());
    pkt[6] = 44; // first next-header = Fragment
    pkt[7] = 64;
    pkt[8..24].copy_from_slice(&src_v6.octets());
    pkt[24..40].copy_from_slice(&dst_v6.octets());
    pkt[40..].copy_from_slice(&frag);

    assert!(
        ipv6_is_non_first_fragment(&pkt),
        "predicate must flag the non-first fragment"
    );
    assert!(
        translate_v6_to_v4(&pkt, snat_v4, dst_v4, false).is_none(),
        "non-first fragment must be dropped, not translated from payload bytes"
    );
}

// ===========================================================================
// #4435: the NAT64 private ext-header walkers must share the canonical
// forwarding/screen bound `MAX_IPV6_EXT_HEADERS` (8), not a stale 6. Before
// #4435 a valid 7-ext-header packet to a NAT64 prefix was DROPPED here while
// the forwarding path accepted it. These are FAIL-ON-REVERT: reverting the
// bound to 6 makes the 7-header packet surrender (`ipv6_l4_offset_and_protocol`
// returns the non-terminal ext-header type -> the translator's `_ => None`),
// so the walk assertion / `expect("translate")` below panics.
// ===========================================================================

/// Build an IPv6 packet carrying `n` back-to-back 8-byte Destination-Options
/// (60) extension headers before the terminal L4 (`l4_proto` / `l4` bytes).
/// Each Dest-Opts header is the minimum 8 octets (Hdr Ext Len = 0). Used to
/// drive the walk bound: the walkers resolve up to `MAX_IPV6_EXT_HEADERS`
/// headers and fail closed beyond it.
fn build_v6_with_n_ext_then_l4(
    src: Ipv6Addr,
    dst: Ipv6Addr,
    n: usize,
    l4_proto: u8,
    hl: u8,
    l4: &[u8],
) -> Vec<u8> {
    let ext_total = n * 8;
    let mut p = vec![0u8; 40 + ext_total + l4.len()];
    p[0] = 0x60;
    // IPv6 payload_len covers the whole ext-header chain + L4.
    p[4..6].copy_from_slice(&((ext_total + l4.len()) as u16).to_be_bytes());
    p[6] = if n == 0 { l4_proto } else { 60 }; // base next-header
    p[7] = hl;
    p[8..24].copy_from_slice(&src.octets());
    p[24..40].copy_from_slice(&dst.octets());
    // Chain of Dest-Opts headers; each next-header points at the following
    // ext header, and the LAST points at the terminal L4.
    for i in 0..n {
        let off = 40 + i * 8;
        p[off] = if i + 1 == n { l4_proto } else { 60 }; // next-header
        p[off + 1] = 0; // Hdr Ext Len = 0 -> minimal 8-byte header
        // off+2..off+8 are option/padding bytes (left zero).
    }
    let l4_off = 40 + ext_total;
    p[l4_off..l4_off + l4.len()].copy_from_slice(l4);
    p
}

fn nat64_probe_udp() -> Vec<u8> {
    let mut udp = vec![0u8; 8 + 4];
    udp[0..2].copy_from_slice(&5353u16.to_be_bytes());
    udp[2..4].copy_from_slice(&53u16.to_be_bytes());
    udp[4..6].copy_from_slice(&12u16.to_be_bytes()); // UDP length
    udp[8..12].copy_from_slice(b"data");
    udp
}

#[test]
fn nat64_v6_to_v4_seven_ext_headers_translates() {
    // #4435 FAIL-ON-REVERT: a chain of 7 resolvable ext headers before UDP.
    // The canonical bound MAX_IPV6_EXT_HEADERS (8) resolves 7 ext headers +
    // the terminal L4 (the 8th loop iteration consumes the terminal). On the
    // stale 6-bound the walk surrenders after 6 headers -> protocol=60 (the
    // 7th, unconsumed) -> `_ => return None` drop.
    assert!(
        MAX_IPV6_EXT_HEADERS >= 8,
        "canonical bound must resolve a 7-ext-header chain"
    );
    let src_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::0808:0808".parse().unwrap();
    let snat_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let dst_v4 = Ipv4Addr::new(8, 8, 8, 8);
    let udp = nat64_probe_udp();

    let pkt = build_v6_with_n_ext_then_l4(src_v6, dst_v6, 7, PROTO_UDP, 64, &udp);

    // The walk resolves the terminal UDP after 7 8-byte ext headers.
    let (off, proto) = ipv6_l4_offset_and_protocol(&pkt).expect("walk must find L4");
    assert_eq!(off, 40 + 7 * 8, "UDP starts after 7 8-byte ext headers");
    assert_eq!(proto, PROTO_UDP);

    let v4 = translate_v6_to_v4(&pkt, snat_v4, dst_v4, false)
        .expect("UDP behind 7 ext headers must translate, not drop (#4435)");
    assert_eq!(v4[9], PROTO_UDP, "protocol must be the terminal L4");
    assert_eq!(
        v4.len(),
        20 + udp.len(),
        "all 7 ext headers stripped from output"
    );
    assert_eq!(u16::from_be_bytes([v4[20], v4[21]]), 5353);
    assert_eq!(u16::from_be_bytes([v4[22], v4[23]]), 53);
    assert_eq!(checksum16(&v4[..20]), 0, "IPv4 header checksum valid");
}

#[test]
fn nat64_v6_to_v4_oversized_ext_chain_fails_closed() {
    // #4435: a chain LONGER than MAX_IPV6_EXT_HEADERS must still fail closed
    // (drop), matching the canonical parser's cap. After the bound the walk is
    // still on an ext header, so it fails closed at the post-loop (`None`) —
    // the fix widens the accepted chain to 8, it does not remove the cap.
    let src_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::0808:0808".parse().unwrap();
    let snat_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let dst_v4 = Ipv4Addr::new(8, 8, 8, 8);
    let udp = nat64_probe_udp();

    let pkt = build_v6_with_n_ext_then_l4(
        src_v6,
        dst_v6,
        MAX_IPV6_EXT_HEADERS + 1,
        PROTO_UDP,
        64,
        &udp,
    );

    // The walk fails closed at the bound — it never returns an L4 tuple.
    assert!(
        ipv6_l4_offset_and_protocol(&pkt).is_none(),
        "oversized chain must fail closed at the walk (None), never resolve an L4"
    );
    assert!(
        translate_v6_to_v4(&pkt, snat_v4, dst_v4, false).is_none(),
        "oversized ext-header chain must fail closed (drop), matching the canonical cap"
    );
}

#[test]
fn nat64_v6_to_v4_exactly_max_ext_headers_parity_both_drop() {
    // #4435 cap parity (locks the residual the const-share alone left): a chain
    // of EXACTLY MAX_IPV6_EXT_HEADERS ext headers must fail closed on BOTH the
    // NAT64 private walker AND the canonical forwarding walker. Before the
    // post-loop `None` change, nat64 RESOLVED this (post-loop `Some`) while the
    // canonical walker (inspect.rs, #2292) DROPPED it — a one-header skew at the
    // bound, merely moved from the old 6-bound to the 8-bound. The 9-header
    // `oversized` test does not exercise this exact boundary.
    let src_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::0808:0808".parse().unwrap();
    let snat_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let dst_v4 = Ipv4Addr::new(8, 8, 8, 8);
    let udp = nat64_probe_udp();

    let pkt =
        build_v6_with_n_ext_then_l4(src_v6, dst_v6, MAX_IPV6_EXT_HEADERS, PROTO_UDP, 64, &udp);

    // NAT64 private walker: fail closed at the bound (post-loop `None`).
    assert!(
        ipv6_l4_offset_and_protocol(&pkt).is_none(),
        "nat64 walker must drop an exactly-MAX_IPV6_EXT_HEADERS chain"
    );
    // Canonical forwarding walker: SAME verdict — the parity this test locks.
    assert!(
        crate::afxdp::packet_rel_l4_offset_and_protocol_for_test(&pkt, libc::AF_INET6 as u8)
            .is_none(),
        "canonical walker must ALSO drop it — true cap parity, no m=8 skew"
    );
    // End to end: the translator drops the datagram.
    assert!(
        translate_v6_to_v4(&pkt, snat_v4, dst_v4, false).is_none(),
        "exactly-MAX_IPV6_EXT_HEADERS chain must be NAT64-dropped"
    );
}

#[test]
fn nat64_v6_to_v4_two_ext_headers_unaffected() {
    // #4435 sanity: a normal short chain (2 ext headers) resolves identically
    // under the 6- and 8-bound — the fix must not perturb the common case.
    let src_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::0808:0808".parse().unwrap();
    let snat_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let dst_v4 = Ipv4Addr::new(8, 8, 8, 8);
    let udp = nat64_probe_udp();

    let pkt = build_v6_with_n_ext_then_l4(src_v6, dst_v6, 2, PROTO_UDP, 64, &udp);
    let (off, proto) = ipv6_l4_offset_and_protocol(&pkt).expect("walk finds L4");
    assert_eq!(off, 40 + 2 * 8);
    assert_eq!(proto, PROTO_UDP);
    let v4 = translate_v6_to_v4(&pkt, snat_v4, dst_v4, false).expect("2-ext-header UDP translates");
    assert_eq!(v4[9], PROTO_UDP);
    assert_eq!(v4.len(), 20 + udp.len());
}

#[test]
fn nat64_v6_to_v4_embedded_icmp_seven_ext_headers_translates() {
    // #4435 FAIL-ON-REVERT (embedded-ICMP path): an ICMPv6 Time-Exceeded whose
    // quoted original packet carries 7 ext headers before TCP. The embedded
    // translator reuses `ipv6_l4_offset_and_protocol`; on the stale 6-bound it
    // surrenders at the 7th header and drops the whole error (traceroute/PMTUD
    // blackhole). With the shared bound the quoted packet is translated.
    let client_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::0808:0808".parse().unwrap();
    let snat_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let dst_v4 = Ipv4Addr::new(8, 8, 8, 8);

    // Quoted original = v6 packet with 7 ext headers then 8 bytes of TCP.
    let inner_l4 = [0x30u8, 0x39, 0x00, 0x50, 0x09, 0x08, 0x07, 0x06];
    let embedded = build_v6_with_n_ext_then_l4(client_v6, dst_v6, 7, PROTO_TCP, 1, &inner_l4);
    let icmp = build_icmpv6_error(3, 0, [0, 0, 0, 0], &embedded);
    let hop_v6: Ipv6Addr = "2001:db8:ffff::1".parse().unwrap();
    let mut v6_pkt = build_v6_with_l4(hop_v6, client_v6, PROTO_ICMPV6_C, 64, &icmp);
    v6_pkt[42..44].copy_from_slice(&[0, 0]);
    let s = checksum16_ipv6_pseudo(hop_v6, client_v6, PROTO_ICMPV6_C, &v6_pkt[40..]);
    v6_pkt[42..44].copy_from_slice(&s.to_be_bytes());

    let v4 = translate_v6_to_v4(&v6_pkt, snat_v4, dst_v4, false)
        .expect("ICMPv6 error quoting 7-ext-header TCP must translate, not drop (#4435)");
    assert_eq!(v4[20], 11, "outer ICMPv4 Time Exceeded type");
    assert_eq!(checksum16(&v4[..20]), 0);
    // Embedded translated IPv4 header starts at v4[28] (20 outer IP + 8 ICMP).
    let emb = &v4[28..];
    assert_eq!(emb[9], PROTO_TCP, "embedded protocol = TCP, ext headers stripped");
    assert_eq!(&emb[12..16], &dst_v4.octets(), "embedded src mapped to dst_v4");
    assert_eq!(&emb[16..20], &snat_v4.octets(), "embedded dst mapped to snat_v4");
    assert_eq!(checksum16(&emb[..20]), 0, "embedded IPv4 header checksum valid");
}

#[test]
fn translate_v6_to_v4_first_fragment_still_translates() {
    // A FIRST fragment (offset 0) carries the real L4 header and must still
    // translate — the non-first-fragment guard must not over-reject.
    let src_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::0808:0808".parse().unwrap();
    let snat_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let dst_v4 = Ipv4Addr::new(8, 8, 8, 8);

    let mut udp = vec![0u8; 8];
    udp[0..2].copy_from_slice(&1111u16.to_be_bytes());
    udp[2..4].copy_from_slice(&2222u16.to_be_bytes());
    udp[4..6].copy_from_slice(&8u16.to_be_bytes());

    // Fragment header with offset 0 (first fragment), MF can be set.
    let mut frag = vec![0u8; 8 + udp.len()];
    frag[0] = PROTO_UDP;
    frag[2..4].copy_from_slice(&0x0001u16.to_be_bytes()); // offset 0, MF=1
    frag[8..].copy_from_slice(&udp);
    let mut pkt = vec![0u8; 40 + frag.len()];
    pkt[0] = 0x60;
    pkt[4..6].copy_from_slice(&(frag.len() as u16).to_be_bytes());
    pkt[6] = 44;
    pkt[7] = 64;
    pkt[8..24].copy_from_slice(&src_v6.octets());
    pkt[24..40].copy_from_slice(&dst_v6.octets());
    pkt[40..].copy_from_slice(&frag);

    assert!(!ipv6_is_non_first_fragment(&pkt), "first fragment is not non-first");
    let v4 = translate_v6_to_v4(&pkt, snat_v4, dst_v4, false)
        .expect("first fragment must translate");
    assert_eq!(v4[9], PROTO_UDP);
    assert_eq!(u16::from_be_bytes([v4[20], v4[21]]), 1111);
    // #2488 FAIL-ON-REVERT: a real first fragment (IPv6 Fragment Header offset
    // 0, M=1) must translate to IPv4 with MF=1 and offset 0 — derived from THE
    // PACKET (RFC 7915 §5), NOT the no-v6-frag-header config. Master emits the
    // atomic 0x4000 (DF=1, MF=0) here, which delivers a truncated first
    // fragment as if it were a complete datagram.
    assert_eq!(
        ipv4_frag_word(&v4),
        0x2000,
        "first fragment must set MF=1, DF=0, offset=0 (RFC 7915 §5), not atomic"
    );
    // Identification = low 16 bits of the IPv6 Fragment Header id (0 here).
    assert_eq!(ipv4_identification(&v4), 0, "ID = low16 of the v6 Fragment id");
    assert_eq!(checksum16(&v4[..20]), 0, "IPv4 header checksum must verify");
}

// ---------------------------------------------------------------------------
// #2488: RFC 7915 fragment translation. The IPv4 fragmentation fields (and, in
// the v4->v6 direction, the presence of an IPv6 Fragment Header) must be
// derived from THE PACKET, not the no-v6-frag-header config. Non-first
// fragments are dropped both directions (the round-robin SNAT pool and
// port-keyed sessions cannot consistently map a port-less fragment to its
// datagram) — only first/atomic fragments translate.
// ---------------------------------------------------------------------------

/// Build a v6 packet carrying a Fragment Header (next-header 44) wrapping a
/// complete UDP datagram (valid v6 UDP checksum), with the given fragment
/// offset (8-byte units), M flag and 32-bit Identification.
fn make_ipv6_frag_udp(
    src: Ipv6Addr,
    dst: Ipv6Addr,
    sport: u16,
    dport: u16,
    data: &[u8],
    offset_units: u16,
    more: bool,
    frag_id: u32,
) -> Vec<u8> {
    let udp_len = 8 + data.len();
    let mut udp = vec![0u8; udp_len];
    udp[0..2].copy_from_slice(&sport.to_be_bytes());
    udp[2..4].copy_from_slice(&dport.to_be_bytes());
    udp[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    udp[8..].copy_from_slice(data);
    let csum = checksum16_ipv6_pseudo(src, dst, PROTO_UDP, &udp);
    let csum = if csum == 0 { 0xFFFF } else { csum };
    udp[6..8].copy_from_slice(&csum.to_be_bytes());

    let mut frag = vec![0u8; 8 + udp_len];
    frag[0] = PROTO_UDP;
    let word = (offset_units << 3) | u16::from(more);
    frag[2..4].copy_from_slice(&word.to_be_bytes());
    frag[4..8].copy_from_slice(&frag_id.to_be_bytes());
    frag[8..].copy_from_slice(&udp);

    let mut pkt = vec![0u8; 40 + frag.len()];
    pkt[0] = 0x60;
    pkt[4..6].copy_from_slice(&(frag.len() as u16).to_be_bytes());
    pkt[6] = 44;
    pkt[7] = 64;
    pkt[8..24].copy_from_slice(&src.octets());
    pkt[24..40].copy_from_slice(&dst.octets());
    pkt[40..].copy_from_slice(&frag);
    pkt
}

/// Build a v4 UDP packet with explicit fragmentation fields (MF flag, 13-bit
/// offset in 8-byte units, 16-bit Identification), valid checksums.
fn make_ipv4_frag_udp(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    sport: u16,
    dport: u16,
    data: &[u8],
    offset_units: u16,
    more: bool,
    ident: u16,
) -> Vec<u8> {
    let udp_len = 8 + data.len();
    let total = 20 + udp_len;
    let mut pkt = vec![0u8; total];
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    pkt[4..6].copy_from_slice(&ident.to_be_bytes());
    let word = (offset_units & 0x1FFF) | if more { 0x2000 } else { 0 };
    pkt[6..8].copy_from_slice(&word.to_be_bytes());
    pkt[8] = 64;
    pkt[9] = PROTO_UDP;
    pkt[12..16].copy_from_slice(&src.octets());
    pkt[16..20].copy_from_slice(&dst.octets());
    pkt[20..22].copy_from_slice(&sport.to_be_bytes());
    pkt[22..24].copy_from_slice(&dport.to_be_bytes());
    pkt[24..26].copy_from_slice(&(udp_len as u16).to_be_bytes());
    pkt[28..28 + data.len()].copy_from_slice(data);
    let csum = checksum16_ipv4_pseudo(src, dst, PROTO_UDP, &pkt[20..]);
    let csum = if csum == 0 { 0xFFFF } else { csum };
    pkt[26..28].copy_from_slice(&csum.to_be_bytes());
    let ip = checksum16(&pkt[..20]);
    pkt[10..12].copy_from_slice(&ip.to_be_bytes());
    pkt
}

// ---------------------------------------------------------------------------
// #2562: fail-closed ICMP/ICMPv6 fragment drop. A REAL fragment (Fragment
// Header present with MF=1 OR offset>0) carrying ICMP/ICMPv6 cannot be
// translated — the ICMP checksum covers the WHOLE datagram, so translating a
// single fragment's bytes emits a first fragment with a WRONG checksum the
// receiver discards. An ATOMIC fragment (MF=0, offset 0) carries the complete
// message and still translates; a non-fragmented ICMP is unchanged. The
// stateful frag-association cache (#3291 stage 4) is the deferred principled
// fix.
// ---------------------------------------------------------------------------

/// Build a v6 packet carrying a Fragment Header (next-header 44) wrapping an
/// ICMPv6 Echo Request, with the given fragment offset (8-byte units), M flag
/// and 32-bit Identification.
fn make_ipv6_frag_icmpv6(
    src: Ipv6Addr,
    dst: Ipv6Addr,
    offset_units: u16,
    more: bool,
    frag_id: u32,
) -> Vec<u8> {
    let mut icmp = vec![0u8; 8];
    icmp[0] = ICMPV6_ECHO_REQUEST;
    icmp[1] = 0; // code
    icmp[4..6].copy_from_slice(&0x1234u16.to_be_bytes()); // id
    icmp[6..8].copy_from_slice(&0x0001u16.to_be_bytes()); // seq
    let csum = checksum16_ipv6_pseudo(src, dst, PROTO_ICMPV6, &icmp);
    icmp[2..4].copy_from_slice(&csum.to_be_bytes());

    let mut frag = vec![0u8; 8 + icmp.len()];
    frag[0] = PROTO_ICMPV6;
    let word = (offset_units << 3) | u16::from(more);
    frag[2..4].copy_from_slice(&word.to_be_bytes());
    frag[4..8].copy_from_slice(&frag_id.to_be_bytes());
    frag[8..].copy_from_slice(&icmp);

    let mut pkt = vec![0u8; 40 + frag.len()];
    pkt[0] = 0x60;
    pkt[4..6].copy_from_slice(&(frag.len() as u16).to_be_bytes());
    pkt[6] = 44;
    pkt[7] = 64;
    pkt[8..24].copy_from_slice(&src.octets());
    pkt[24..40].copy_from_slice(&dst.octets());
    pkt[40..].copy_from_slice(&frag);
    pkt
}

/// Build a v4 ICMP Echo Reply with explicit fragmentation fields.
fn make_ipv4_frag_icmp(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    offset_units: u16,
    more: bool,
    ident: u16,
) -> Vec<u8> {
    let icmp_len = 8usize;
    let total = 20 + icmp_len;
    let mut pkt = vec![0u8; total];
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    pkt[4..6].copy_from_slice(&ident.to_be_bytes());
    let word = (offset_units & 0x1FFF) | if more { 0x2000 } else { 0 };
    pkt[6..8].copy_from_slice(&word.to_be_bytes());
    pkt[8] = 64;
    pkt[9] = PROTO_ICMP;
    pkt[12..16].copy_from_slice(&src.octets());
    pkt[16..20].copy_from_slice(&dst.octets());
    pkt[20] = ICMP_ECHO_REPLY;
    pkt[21] = 0;
    pkt[24..26].copy_from_slice(&0x1234u16.to_be_bytes());
    pkt[26..28].copy_from_slice(&0x0001u16.to_be_bytes());
    let icmp_sum = checksum16(&pkt[20..]);
    pkt[22..24].copy_from_slice(&icmp_sum.to_be_bytes());
    let ip = checksum16(&pkt[..20]);
    pkt[10..12].copy_from_slice(&ip.to_be_bytes());
    pkt
}

/// Prepend a bare (non-VLAN) Ethernet header so an L3 packet becomes an L2
/// frame for the frame-level predicate. `frame_l3_offset` only special-cases
/// VLAN TPIDs, so any other ethertype yields l3=14.
fn l2_frame(l3: &[u8], ethertype: u16) -> Vec<u8> {
    let mut f = vec![0u8; 14 + l3.len()];
    f[12..14].copy_from_slice(&ethertype.to_be_bytes());
    f[14..].copy_from_slice(l3);
    f
}

#[test]
fn nat64_v6_to_v4_real_fragment_icmpv6_dropped() {
    // FAIL-ON-REVERT: a REAL v6 fragment (Fragment Header, MF=1, offset 0)
    // carrying ICMPv6 must be DROPPED. On revert (no guard) the first fragment
    // translates to Some(_) with an ICMPv4 checksum computed over only this
    // fragment's bytes — a wrong checksum the receiver discards.
    let src_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::c000:0201".parse().unwrap();
    let snat_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let dst_v4 = Ipv4Addr::new(192, 0, 2, 1);

    // First fragment (MF=1, offset 0).
    let first = make_ipv6_frag_icmpv6(src_v6, dst_v6, 0, true, 0xDEAD_BEEF);
    assert!(
        translate_v6_to_v4(&first, snat_v4, dst_v4, false).is_none(),
        "a real first ICMPv6 fragment must be dropped, not forwarded with a wrong checksum"
    );
    // Non-first fragment (offset > 0) — dropped by the pre-existing non-first
    // guard, and also flagged by the fragment predicate.
    let nonfirst = make_ipv6_frag_icmpv6(src_v6, dst_v6, 2, false, 0xDEAD_BEEF);
    assert!(
        translate_v6_to_v4(&nonfirst, snat_v4, dst_v4, false).is_none(),
        "a non-first ICMPv6 fragment must be dropped"
    );
}

#[test]
fn nat64_v6_to_v4_atomic_fragment_icmpv6_translates() {
    // NO-OVER-DROP: an ATOMIC fragment (Fragment Header, MF=0, offset 0)
    // carries the complete ICMPv6 message and MUST still translate.
    let src_v6: Ipv6Addr = "2001:db8::2".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::c000:0202".parse().unwrap();
    let snat_v4 = Ipv4Addr::new(198, 51, 100, 2);
    let dst_v4 = Ipv4Addr::new(192, 0, 2, 2);

    let atomic = make_ipv6_frag_icmpv6(src_v6, dst_v6, 0, false, 0x0000_1234);
    let v4 = translate_v6_to_v4(&atomic, snat_v4, dst_v4, false)
        .expect("atomic ICMPv6 fragment must still translate");
    assert_eq!(v4[9], PROTO_ICMP, "translated to ICMPv4");
    assert_eq!(v4[20], ICMP_ECHO_REQUEST, "type mapped");
    assert_eq!(checksum16(&v4[..20]), 0, "IPv4 header checksum verifies");
    assert_eq!(checksum16(&v4[20..]), 0, "ICMPv4 checksum verifies (complete message)");
}

#[test]
fn nat64_v4_to_v6_real_fragment_icmp_dropped() {
    // FAIL-ON-REVERT (reverse direction): a REAL v4 fragment (MF=1, offset 0)
    // carrying ICMP must be DROPPED. On revert the first fragment translates
    // with an ICMPv6 checksum over only this fragment's bytes.
    let src_v4 = Ipv4Addr::new(8, 8, 8, 8);
    let dst_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let src_v6: Ipv6Addr = "64:ff9b::0808:0808".parse().unwrap();
    let dst_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();

    let first = make_ipv4_frag_icmp(src_v4, dst_v4, 0, true, 0x4321);
    assert!(
        translate_v4_to_v6(&first, src_v6, dst_v6).is_none(),
        "a real first ICMP fragment must be dropped, not forwarded with a wrong checksum"
    );
    let nonfirst = make_ipv4_frag_icmp(src_v4, dst_v4, 2, false, 0x4321);
    assert!(
        translate_v4_to_v6(&nonfirst, src_v6, dst_v6).is_none(),
        "a non-first ICMP fragment must be dropped"
    );
}

#[test]
fn nat64_v4_to_v6_atomic_fragment_icmp_translates() {
    // NO-OVER-DROP: an atomic v4 fragment (MF=0, offset 0) carrying a complete
    // ICMP message MUST still translate.
    let src_v4 = Ipv4Addr::new(8, 8, 8, 8);
    let dst_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let src_v6: Ipv6Addr = "64:ff9b::0808:0808".parse().unwrap();
    let dst_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();

    let atomic = make_ipv4_frag_icmp(src_v4, dst_v4, 0, false, 0x4321);
    let v6 = translate_v4_to_v6(&atomic, src_v6, dst_v6)
        .expect("atomic ICMP fragment must still translate");
    assert_eq!(v6[6], PROTO_ICMPV6, "translated to ICMPv6");
    assert_eq!(v6[40], ICMPV6_ECHO_REPLY, "type mapped");
    let s6 = Ipv6Addr::from(<[u8; 16]>::try_from(&v6[8..24]).unwrap());
    let d6 = Ipv6Addr::from(<[u8; 16]>::try_from(&v6[24..40]).unwrap());
    assert_eq!(
        checksum16_ipv6_pseudo(s6, d6, PROTO_ICMPV6, &v6[40..]),
        0,
        "ICMPv6 checksum verifies (complete message)"
    );
}

#[test]
fn nat64_non_fragmented_icmp_unchanged_by_frag_guard() {
    // NO-REGRESSION: a non-fragmented ICMP echo still translates both
    // directions (the fragment guard only fires when a Fragment Header / MF /
    // offset says the datagram is a real fragment).
    let src_v6: Ipv6Addr = "2001:db8::9".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::0808:0808".parse().unwrap();
    let snat_v4 = Ipv4Addr::new(198, 51, 100, 9);
    let dst_v4 = Ipv4Addr::new(8, 8, 8, 8);
    // v6→v4 (no Fragment Header at all).
    let mut v6 = vec![0u8; 48];
    v6[0] = 0x60;
    v6[4..6].copy_from_slice(&8u16.to_be_bytes());
    v6[6] = PROTO_ICMPV6;
    v6[7] = 64;
    v6[8..24].copy_from_slice(&src_v6.octets());
    v6[24..40].copy_from_slice(&dst_v6.octets());
    v6[40] = ICMPV6_ECHO_REQUEST;
    v6[44..46].copy_from_slice(&0x1234u16.to_be_bytes());
    v6[46..48].copy_from_slice(&0x0001u16.to_be_bytes());
    let s = checksum16_ipv6_pseudo(src_v6, dst_v6, PROTO_ICMPV6, &v6[40..]);
    v6[42..44].copy_from_slice(&s.to_be_bytes());
    assert!(
        translate_v6_to_v4(&v6, snat_v4, dst_v4, false).is_some(),
        "non-fragmented ICMPv6 must translate"
    );
    // v4→v6 (atomic, DF, no MF/offset).
    let v4 = make_ipv4_frag_icmp(dst_v4, snat_v4, 0, false, 0);
    assert!(
        translate_v4_to_v6(&v4, dst_v6, src_v6).is_some(),
        "non-fragmented ICMP must translate"
    );
}

#[test]
fn nat64_fragment_drop_predicates_match_guards() {
    let src_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::c000:0201".parse().unwrap();
    let src_v4 = Ipv4Addr::new(8, 8, 8, 8);
    let dst_v4 = Ipv4Addr::new(198, 51, 100, 1);

    // v6→v4 predicate.
    let icmp_first = make_ipv6_frag_icmpv6(src_v6, dst_v6, 0, true, 1);
    let icmp_nonfirst = make_ipv6_frag_icmpv6(src_v6, dst_v6, 3, false, 1);
    let icmp_atomic = make_ipv6_frag_icmpv6(src_v6, dst_v6, 0, false, 1);
    let udp_first = make_ipv6_frag_udp(src_v6, dst_v6, 5, 6, b"x", 0, true, 1);
    let udp_nonfirst = make_ipv6_frag_udp(src_v6, dst_v6, 5, 6, b"x", 3, false, 1);
    assert!(v6_to_v4_is_fragment_drop(&icmp_first), "real ICMPv6 first fragment drops");
    assert!(v6_to_v4_is_fragment_drop(&icmp_nonfirst), "ICMPv6 non-first drops");
    assert!(!v6_to_v4_is_fragment_drop(&icmp_atomic), "atomic ICMPv6 keeps");
    assert!(!v6_to_v4_is_fragment_drop(&udp_first), "UDP first fragment translates (keep)");
    assert!(v6_to_v4_is_fragment_drop(&udp_nonfirst), "UDP non-first drops (any protocol)");

    // v4→v6 predicate.
    let v4_icmp_first = make_ipv4_frag_icmp(src_v4, dst_v4, 0, true, 1);
    let v4_icmp_atomic = make_ipv4_frag_icmp(src_v4, dst_v4, 0, false, 1);
    let v4_udp_first = make_ipv4_frag_udp(src_v4, dst_v4, 5, 6, b"x", 0, true, 1);
    let v4_udp_nonfirst = make_ipv4_frag_udp(src_v4, dst_v4, 5, 6, b"x", 3, false, 1);
    assert!(v4_to_v6_is_fragment_drop(&v4_icmp_first), "real ICMP first fragment drops");
    assert!(!v4_to_v6_is_fragment_drop(&v4_icmp_atomic), "atomic ICMP keeps");
    assert!(!v4_to_v6_is_fragment_drop(&v4_udp_first), "UDP first fragment translates (keep)");
    assert!(v4_to_v6_is_fragment_drop(&v4_udp_nonfirst), "UDP non-first drops (any protocol)");

    // Frame-level predicate (with an Ethernet header) — the attribution point.
    assert!(frame_is_nat64_fragment_drop(
        &l2_frame(&icmp_first, 0x86dd),
        libc::AF_INET6
    ));
    assert!(!frame_is_nat64_fragment_drop(
        &l2_frame(&icmp_atomic, 0x86dd),
        libc::AF_INET6
    ));
    assert!(frame_is_nat64_fragment_drop(
        &l2_frame(&v4_icmp_first, 0x0800),
        libc::AF_INET
    ));
    assert!(!frame_is_nat64_fragment_drop(
        &l2_frame(&v4_icmp_atomic, 0x0800),
        libc::AF_INET
    ));
    // Wrong/unknown family → not attributed.
    assert!(!frame_is_nat64_fragment_drop(&l2_frame(&icmp_first, 0x86dd), 0));
}

#[test]
fn nat64_v6_to_v4_first_fragment_mf_and_id_from_packet() {
    // FAIL-ON-REVERT: a v6 first fragment (Fragment Header offset 0, M=1) must
    // become IPv4 MF=1, offset 0, DF=0, Identification = low16 of the v6
    // Fragment id — derived from THE PACKET (RFC 7915 §5), NOT no-v6-frag-header.
    let src_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::c000:0201".parse().unwrap();
    let snat_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let dst_v4 = Ipv4Addr::new(192, 0, 2, 1);

    let pkt = make_ipv6_frag_udp(src_v6, dst_v6, 5000, 6000, b"hello-frag", 0, true, 0xDEAD_BEEF);

    // The config value MUST be ignored for a real fragment: try both.
    for cfg in [false, true] {
        let v4 = translate_v6_to_v4(&pkt, snat_v4, dst_v4, cfg)
            .unwrap_or_else(|| panic!("first fragment must translate (cfg={cfg})"));
        assert_eq!(
            ipv4_frag_word(&v4),
            0x2000,
            "MF=1, DF=0, offset=0 from the packet (cfg={cfg}); master emits atomic 0x4000"
        );
        assert_eq!(
            ipv4_identification(&v4),
            0xBEEF,
            "ID = low 16 bits of the v6 Fragment id (cfg={cfg})"
        );
        assert_eq!(v4[9], PROTO_UDP, "protocol UDP (cfg={cfg})");
        assert_eq!(checksum16(&v4[..20]), 0, "IPv4 header checksum verifies (cfg={cfg})");
        // L4 fully present here -> incremental adjust must equal a from-scratch
        // v4 UDP checksum (verify == 0 over pseudo + L4 incl. checksum field).
        assert_eq!(
            checksum16_ipv4_pseudo(snat_v4, dst_v4, PROTO_UDP, &v4[20..]),
            0,
            "translated v4 UDP fragment checksum verifies (cfg={cfg})"
        );
    }
}

#[test]
fn nat64_v6_to_v4_atomic_fragment_header_df_clear_id_from_packet() {
    // An IPv6 atomic fragment (Fragment Header present, offset 0, M=0) is whole
    // but fragmentable: RFC 7915 §5.1.1 -> IPv4 DF=0, MF=0, offset 0, and the
    // Identification copied from the Fragment Header (low 16 bits), regardless
    // of the no-v6-frag-header config.
    let src_v6: Ipv6Addr = "2001:db8::2".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::c000:0202".parse().unwrap();
    let snat_v4 = Ipv4Addr::new(198, 51, 100, 2);
    let dst_v4 = Ipv4Addr::new(192, 0, 2, 2);

    let pkt = make_ipv6_frag_udp(src_v6, dst_v6, 7000, 8000, b"atomic", 0, false, 0x0000_1234);
    let v4 = translate_v6_to_v4(&pkt, snat_v4, dst_v4, false).expect("translate");
    assert_eq!(ipv4_frag_word(&v4), 0x0000, "atomic fragment -> DF=0, MF=0, offset=0");
    assert_eq!(ipv4_identification(&v4), 0x1234, "ID from the Fragment Header");
    assert_eq!(checksum16(&v4[..20]), 0);
}

#[test]
fn nat64_v6_to_v4_unfragmented_keeps_config_df_policy() {
    // NO-REGRESSION: a packet with NO Fragment Header keeps the option-gated
    // atomic DF policy (DF=1 default, DF=0 + generated id with the option).
    let src_v6: Ipv6Addr = "2001:db8::3".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::c000:0203".parse().unwrap();
    let snat_v4 = Ipv4Addr::new(198, 51, 100, 3);
    let dst_v4 = Ipv4Addr::new(192, 0, 2, 3);
    let pkt = make_ipv6_tcp_packet(src_v6, dst_v6, 1234, 80, b"plain");

    let df = translate_v6_to_v4(&pkt, snat_v4, dst_v4, false).expect("translate");
    assert_eq!(ipv4_frag_word(&df), 0x4000, "default atomic DF=1");
    assert_eq!(ipv4_identification(&df), 0, "atomic id=0");

    let nodf = translate_v6_to_v4(&pkt, snat_v4, dst_v4, true).expect("translate");
    assert_eq!(ipv4_frag_word(&nodf), 0x0000, "no-v6-frag-header clears DF");
    assert_ne!(ipv4_identification(&nodf), 0, "fragmentable -> non-zero generated id");
}

#[test]
fn nat64_v4_to_v6_first_fragment_inserts_fragment_header() {
    // FAIL-ON-REVERT: a v4 first fragment (MF=1, offset 0) must become an IPv6
    // packet WITH a Fragment Header (next-header 44): offset copied, M mapped,
    // Identification = v4 id zero-extended, payload-length += 8. Master emits a
    // plain 40-byte IPv6 header with NO Fragment Header.
    let src_v6: Ipv6Addr = "64:ff9b::c000:0204".parse().unwrap();
    let dst_v6: Ipv6Addr = "2001:db8::4".parse().unwrap();
    let v4_src = Ipv4Addr::new(192, 0, 2, 4);
    let v4_dst = Ipv4Addr::new(198, 51, 100, 4);

    let data = b"v4-frag-payload";
    let pkt = make_ipv4_frag_udp(v4_src, v4_dst, 4444, 5555, data, 0, true, 0x4321);
    let v6 = translate_v4_to_v6(&pkt, src_v6, dst_v6).expect("translate");

    assert_eq!(v6[6], 44, "base IPv6 next-header must point at the Fragment Header");
    assert_eq!(v6[40], PROTO_UDP, "Fragment Header next-header = UDP");
    let frag_word = u16::from_be_bytes([v6[42], v6[43]]);
    assert_eq!(frag_word & 0x0001, 0x0001, "M flag mapped from IPv4 MF");
    assert_eq!(frag_word >> 3, 0, "fragment offset 0 copied");
    assert_eq!(
        u32::from_be_bytes([v6[44], v6[45], v6[46], v6[47]]),
        0x0000_4321,
        "Identification = v4 id zero-extended to 32 bits"
    );
    let udp_len = 8 + data.len();
    assert_eq!(
        u16::from_be_bytes([v6[4], v6[5]]) as usize,
        8 + udp_len,
        "payload-length includes the 8-byte Fragment Header"
    );
    assert_eq!(u16::from_be_bytes([v6[48], v6[49]]), 4444, "UDP src port at L4 offset 48");
    // L4 fully present -> incremental adjust equals a from-scratch v6 recompute.
    assert_eq!(
        checksum16_ipv6_pseudo(src_v6, dst_v6, PROTO_UDP, &v6[48..]),
        0,
        "translated v6 UDP fragment checksum verifies"
    );
}

#[test]
fn nat64_v4_to_v6_unfragmented_has_no_fragment_header() {
    // NO-REGRESSION: an unfragmented v4 packet (MF=0, offset 0) stays a plain
    // IPv6 packet with NO Fragment Header — byte-identical to pre-#2488.
    let src_v6: Ipv6Addr = "64:ff9b::c000:0205".parse().unwrap();
    let dst_v6: Ipv6Addr = "2001:db8::5".parse().unwrap();
    let v4_src = Ipv4Addr::new(192, 0, 2, 5);
    let v4_dst = Ipv4Addr::new(198, 51, 100, 5);

    let pkt = make_ipv4_frag_udp(v4_src, v4_dst, 4000, 5000, b"plain-reply", 0, false, 0x9999);
    let v6 = translate_v4_to_v6(&pkt, src_v6, dst_v6).expect("translate");
    assert_eq!(v6[6], PROTO_UDP, "base next-header = UDP, no Fragment Header");
    assert_eq!(u16::from_be_bytes([v6[48 - 8], v6[48 - 7]]), 4000, "UDP at L4 offset 40");
    assert_eq!(checksum16_ipv6_pseudo(src_v6, dst_v6, PROTO_UDP, &v6[40..]), 0);
}

#[test]
fn nat64_v4_to_v6_non_first_fragment_dropped() {
    // A non-first v4 fragment (offset > 0) carries no L4 header and is dropped,
    // symmetric with the v6->v4 non-first-fragment drop.
    let src_v6: Ipv6Addr = "64:ff9b::c000:0206".parse().unwrap();
    let dst_v6: Ipv6Addr = "2001:db8::6".parse().unwrap();
    let v4_src = Ipv4Addr::new(192, 0, 2, 6);
    let v4_dst = Ipv4Addr::new(198, 51, 100, 6);
    let pkt = make_ipv4_frag_udp(v4_src, v4_dst, 1, 2, &[0u8; 16], 0x0002, true, 0x1111);
    assert!(
        translate_v4_to_v6(&pkt, src_v6, dst_v6).is_none(),
        "non-first v4 fragment must be dropped"
    );
}

#[test]
fn nat64_v4_to_v6_udp_fragment_zero_checksum_dropped() {
    // RFC 7915 §4.5: a v4 UDP fragment with checksum 0 cannot be translated
    // (the mandatory v6 UDP checksum cannot be computed from one fragment).
    let src_v6: Ipv6Addr = "64:ff9b::c000:0207".parse().unwrap();
    let dst_v6: Ipv6Addr = "2001:db8::7".parse().unwrap();
    let v4_src = Ipv4Addr::new(192, 0, 2, 7);
    let v4_dst = Ipv4Addr::new(198, 51, 100, 7);
    let mut pkt = make_ipv4_frag_udp(v4_src, v4_dst, 3, 4, b"data", 0, true, 0x2222);
    pkt[26..28].copy_from_slice(&[0, 0]); // zero the UDP checksum
    let ip = checksum16(&pkt[..20]);
    pkt[10..12].copy_from_slice(&ip.to_be_bytes());
    assert!(
        translate_v4_to_v6(&pkt, src_v6, dst_v6).is_none(),
        "v4 UDP fragment with zero checksum must be dropped"
    );
}

#[test]
fn nat64_v6_to_v4_non_first_fragment_still_dropped() {
    // NO-REGRESSION of the #2290 drop: a v6 non-first fragment is still dropped
    // (offset > 0, no L4 header).
    let src_v6: Ipv6Addr = "2001:db8::8".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::c000:0208".parse().unwrap();
    let snat_v4 = Ipv4Addr::new(198, 51, 100, 8);
    let dst_v4 = Ipv4Addr::new(192, 0, 2, 8);
    let pkt = make_ipv6_frag_udp(src_v6, dst_v6, 9, 10, &[0u8; 16], 0x0040, false, 0x3333);
    assert!(
        translate_v6_to_v4(&pkt, snat_v4, dst_v4, false).is_none(),
        "v6 non-first fragment must be dropped"
    );
}

#[test]
fn nat64_v6_to_v4_time_exceeded_quoting_ext_headered_tcp_translates() {
    // FAIL-ON-REVERT (#2290 embedded path): an ICMPv6 Time-Exceeded whose
    // quoted original packet carries a Dest-Opts header before TCP. Pre-fix
    // the embedded translator read quote[6]=60 as the protocol and dropped
    // the whole error -> PMTUD/traceroute blackhole. Now it walks the quoted
    // ext-header chain and translates the embedded packet.
    let client_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::0808:0808".parse().unwrap();
    let snat_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let dst_v4 = Ipv4Addr::new(8, 8, 8, 8);

    // Quoted original = v6 packet with Dest-Opts then 8 bytes of TCP.
    let inner_l4 = [0x30u8, 0x39, 0x00, 0x50, 0x09, 0x08, 0x07, 0x06];
    let embedded =
        build_v6_with_ext_then_l4(client_v6, dst_v6, 60, &[0u8; 6], PROTO_TCP, 1, &inner_l4);
    let icmp = build_icmpv6_error(3, 0, [0, 0, 0, 0], &embedded);
    let hop_v6: Ipv6Addr = "2001:db8:ffff::1".parse().unwrap();
    let mut v6_pkt = build_v6_with_l4(hop_v6, client_v6, PROTO_ICMPV6_C, 64, &icmp);
    v6_pkt[42..44].copy_from_slice(&[0, 0]);
    let s = checksum16_ipv6_pseudo(hop_v6, client_v6, PROTO_ICMPV6_C, &v6_pkt[40..]);
    v6_pkt[42..44].copy_from_slice(&s.to_be_bytes());

    let v4 = translate_v6_to_v4(&v6_pkt, snat_v4, dst_v4, false)
        .expect("ICMPv6 error quoting ext-headered TCP must translate, not drop");
    assert_eq!(v4[20], 11, "outer ICMPv4 Time Exceeded type");
    assert_eq!(checksum16(&v4[..20]), 0);
    // Embedded translated IPv4 header starts at v4[28] (20 outer IP + 8 ICMP).
    let emb = &v4[28..];
    assert_eq!(emb[9], PROTO_TCP, "embedded protocol = TCP, ext header stripped");
    assert_eq!(&emb[12..16], &dst_v4.octets(), "embedded src mapped to dst_v4");
    assert_eq!(&emb[16..20], &snat_v4.octets(), "embedded dst mapped to snat_v4");
    assert_eq!(checksum16(&emb[..20]), 0, "embedded IPv4 header checksum valid");
}

#[test]
fn nat64_v6_to_v4_ext_header_path_unaffects_plain_tcp() {
    // Regression: a PLAIN TCP packet (no ext header) must still translate
    // byte-identically after the walk was added — the walk returns offset 40
    // for a packet whose first next-header is already the L4.
    let src_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::c633:6432".parse().unwrap();
    let pkt = make_ipv6_tcp_packet(src_v6, dst_v6, 12345, 80, b"hello");
    let (off, proto) = ipv6_l4_offset_and_protocol(&pkt).expect("plain walk");
    assert_eq!(off, 40, "no ext header -> L4 at byte 40");
    assert_eq!(proto, PROTO_TCP);
    let v4 = translate_v6_to_v4(
        &pkt,
        Ipv4Addr::new(198, 51, 100, 1),
        Ipv4Addr::new(198, 51, 100, 50),
        false,
    )
    .expect("plain TCP translate");
    assert_eq!(v4.len(), 45, "plain TCP length unchanged (20 + 25)");
    assert_eq!(v4[9], PROTO_TCP);
}

// ===========================================================================
// #2291: fail-closed tri-state NAT64 lookup. A matched prefix with no usable
// source pool must drop, not fall through to IPv6 routing on the synthetic
// destination.
// ===========================================================================

#[test]
fn classify_no_prefix_match_continues_ipv6_routing() {
    let state = Nat64State::from_snapshots(&[well_known_prefix()]);
    let dst: Ipv6Addr = "2001:db8::1".parse().unwrap(); // not the NAT64 prefix
    assert_eq!(state.classify_ipv6_dest(dst), Nat64Match::NoPrefixMatch);
}

#[test]
fn classify_match_ready_when_pool_has_source() {
    let state = Nat64State::from_snapshots(&[well_known_prefix()]);
    let dst: Ipv6Addr = "64:ff9b::c633:6432".parse().unwrap(); // ::198.51.100.50
    match state.classify_ipv6_dest(dst) {
        // #4381: MatchReady no longer pre-allocates a source; it just confirms
        // the prefix matched and a pool exists. The `(snat_v4, port)` is
        // allocated per-flow at the Permit branch via `allocate_source`.
        Nat64Match::MatchReady {
            prefix_idx,
            dst_v4,
            dst_v6,
        } => {
            assert_eq!(prefix_idx, 0);
            assert_eq!(dst_v4, Ipv4Addr::new(198, 51, 100, 50));
            assert_eq!(dst_v6, dst);
        }
        other => panic!("expected MatchReady, got {other:?}"),
    }
}

#[test]
fn classify_match_unavailable_on_empty_pool_fails_closed() {
    // The exact #2291 wire state: a configured NAT64 prefix with an empty
    // (no-source) pool. The lookup MUST report MatchUnavailable so the caller
    // drops, NOT NoPrefixMatch (which would continue IPv6 routing on the
    // synthetic destination — the pre-fix fail-open).
    let state = Nat64State::from_snapshots(&[NAT64RuleSnapshot {
        name: "no-pool".to_string(),
        prefix: "64:ff9b::/96".to_string(),
        pool_addresses: vec![],
        no_v6_frag_header: false,
            ..Default::default()
    }]);
    let dst: Ipv6Addr = "64:ff9b::0808:0808".parse().unwrap();

    // Sanity: the prefix DOES match, and the source allocation DOES fail.
    assert!(state.match_ipv6_dest(dst).is_some(), "prefix must match");
    assert!(state.allocate_v4_source(0).is_none(), "empty pool yields no source");

    let result = state.classify_ipv6_dest(dst);
    assert_eq!(
        result,
        Nat64Match::MatchUnavailable,
        "empty-pool match must fail closed (drop), not fall through to IPv6 routing"
    );
    // Counter-factual: the pre-fix chain collapsed this to None ==
    // NoPrefixMatch, which the caller treats as "route as IPv6". Assert the
    // new result is NOT that fail-open value.
    assert_ne!(
        result,
        Nat64Match::NoPrefixMatch,
        "must NOT be treated as no-match (would IPv6-route the synthetic dest)"
    );
}

// ===========================================================================
// #4381: RFC 6146 BIB — NAT64 allocates a UNIQUE translated source port / ICMP
// identifier per flow, reusing the pool-mode SNAT PortAllocator, so two v6
// clients hidden behind ONE pool v4 address never collide on the reverse
// (v4->v6) tuple. Pre-#4381 `forward_decision` set `rewrite_src_port = None`
// and the source was a bare round-robin over the pool with no (addr, port)
// uniqueness, so two clients sharing a source port produced an identical
// reverse tuple and the second install collided.
// ===========================================================================

fn single_addr_prefix() -> NAT64RuleSnapshot {
    NAT64RuleSnapshot {
        name: "nat64-single".to_string(),
        prefix: "64:ff9b::/96".to_string(),
        // A one-address pool is the sharpest collision case: every client maps
        // to the SAME snat_v4, so ONLY the translated port can disambiguate.
        pool_addresses: vec!["198.51.100.1".to_string()],
        no_v6_frag_header: false,
        ..Default::default()
    }
}

// FAIL-ON-REVERT: reverting the per-flow port allocation (forward_decision
// carrying no translated port) lets two clients that share a source port map to
// the SAME (snat_v4, port), producing an identical reverse tuple — the
// distinct-port assertion goes RED.
#[test]
fn nat64_4381_shared_src_port_gets_distinct_translated_ports() {
    let state = Nat64State::from_snapshots(&[single_addr_prefix()]);
    let dst_v4 = Ipv4Addr::new(8, 8, 8, 8);
    let c1: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let c2: Ipv6Addr = "2001:db8::2".parse().unwrap();
    // Both clients: source port 5000 -> server 443. One-address pool, so the
    // snat_v4 is identical and the translated PORTS must differ.
    let (s1, p1) = state
        .allocate_source(0, crate::ip_proto::PROTO_TCP, c1, dst_v4, 5000, 443, 1)
        .expect("alloc c1");
    let (s2, p2) = state
        .allocate_source(0, crate::ip_proto::PROTO_TCP, c2, dst_v4, 5000, 443, 1)
        .expect("alloc c2");
    assert_eq!(s1, Ipv4Addr::new(198, 51, 100, 1));
    assert_eq!(s2, s1, "single-address pool => same snat_v4");
    assert_ne!(
        p1, p2,
        "#4381: two clients sharing a source port MUST get distinct translated ports"
    );
    // The reverse tuples (server, snat_v4, server_port, translated_port) differ.
    assert_ne!((s1, 443u16, p1), (s2, 443u16, p2));
    // Translated ports come from the configured 1024..=65535 range.
    assert!(p1 >= 1024 && p2 >= 1024, "translated ports in ephemeral range");
}

// Idempotency: re-allocating the SAME forward flow returns the SAME mapping (a
// retransmit before the session installs must not consume a second port).
#[test]
fn nat64_4381_same_flow_reuses_mapping() {
    let state = Nat64State::from_snapshots(&[single_addr_prefix()]);
    let dst_v4 = Ipv4Addr::new(8, 8, 8, 8);
    let c: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let a = state
        .allocate_source(0, crate::ip_proto::PROTO_TCP, c, dst_v4, 5000, 443, 1)
        .unwrap();
    let b = state
        .allocate_source(0, crate::ip_proto::PROTO_TCP, c, dst_v4, 5000, 443, 1)
        .unwrap();
    assert_eq!(a, b, "same flow reuses its translated mapping");
}

// Release un-tracks the flow so its port returns to the pool. Before release a
// re-allocation is idempotent (returns the live mapping); after release the
// live entry is gone, so a fresh allocation is issued.
#[test]
fn nat64_4381_release_untracks_flow() {
    let state = Nat64State::from_snapshots(&[single_addr_prefix()]);
    let dst_v4 = Ipv4Addr::new(8, 8, 8, 8);
    let c: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let (snat, pa) = state
        .allocate_source(0, crate::ip_proto::PROTO_TCP, c, dst_v4, 5000, 443, 1)
        .unwrap();
    // Idempotent while live.
    assert_eq!(
        state
            .allocate_source(0, crate::ip_proto::PROTO_TCP, c, dst_v4, 5000, 443, 1)
            .unwrap(),
        (snat, pa)
    );
    // The forward session key + decision the teardown release path reconstructs.
    let key = crate::session::SessionKey {
        addr_family: libc::AF_INET6 as u8,
        protocol: crate::ip_proto::PROTO_TCP,
        src_ip: IpAddr::V6(c),
        dst_ip: IpAddr::V6("64:ff9b::0808:0808".parse().unwrap()),
        src_port: 5000,
        dst_port: 443,
            discriminator: Default::default(),
            routing_domain: 0,
    };
    release_nat64_allocation(
        &state,
        &key,
        Nat64State::forward_decision(snat, dst_v4, pa),
        false,
        2,
    );
    // Flow no longer live: a fresh allocation is issued (NOT the cached live
    // entry), proving the release removed the tracking.
    let (snat2, pb) = state
        .allocate_source(0, crate::ip_proto::PROTO_TCP, c, dst_v4, 5000, 443, 3)
        .unwrap();
    assert_eq!(snat2, snat);
    assert_ne!(
        pb, pa,
        "post-release allocation is fresh, not the released live entry"
    );
}

// A NAT64 forward flow's reverse entry (is_reverse == true) must NOT trigger a
// release — only the forward entry owns the allocation.
#[test]
fn nat64_4381_reverse_entry_release_is_noop() {
    let state = Nat64State::from_snapshots(&[single_addr_prefix()]);
    let dst_v4 = Ipv4Addr::new(8, 8, 8, 8);
    let c: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let (snat, pa) = state
        .allocate_source(0, crate::ip_proto::PROTO_TCP, c, dst_v4, 5000, 443, 1)
        .unwrap();
    let key = crate::session::SessionKey {
        addr_family: libc::AF_INET6 as u8,
        protocol: crate::ip_proto::PROTO_TCP,
        src_ip: IpAddr::V6(c),
        dst_ip: IpAddr::V6("64:ff9b::0808:0808".parse().unwrap()),
        src_port: 5000,
        dst_port: 443,
            discriminator: Default::default(),
            routing_domain: 0,
    };
    // is_reverse == true: no-op, so the mapping stays live and idempotent.
    release_nat64_allocation(
        &state,
        &key,
        Nat64State::forward_decision(snat, dst_v4, pa),
        true,
        2,
    );
    assert_eq!(
        state
            .allocate_source(0, crate::ip_proto::PROTO_TCP, c, dst_v4, 5000, 443, 3)
            .unwrap(),
        (snat, pa),
        "reverse-entry release must not free the forward flow's port"
    );
}

// === #4512: cross-node HA-failover port-reservation sync ===
//
// The synthetic v6 destination the forward NAT64 session key carries; the
// reserve/allocate flow key uses the TRANSLATED v4 destination
// (`nat.rewrite_dst`) instead, so this exact value is not load-bearing.
fn nat64_synced_key(client: &str) -> crate::session::SessionKey {
    crate::session::SessionKey {
        addr_family: libc::AF_INET6 as u8,
        protocol: crate::ip_proto::PROTO_TCP,
        src_ip: IpAddr::V6(client.parse().unwrap()),
        dst_ip: IpAddr::V6("64:ff9b::0808:0808".parse().unwrap()),
        src_port: 5000,
        dst_port: 443,
            discriminator: Default::default(),
            routing_domain: 0,
    }
}

// A fresh local NAT64 flow from a distinct client to 8.8.8.8, used to probe
// whether a prior reservation forced the sequential allocator to skip a port.
fn nat64_probe_alloc(state: &Nat64State) -> (Ipv4Addr, u16) {
    state
        .allocate_source(
            0,
            crate::ip_proto::PROTO_TCP,
            "2001:db8::2".parse().unwrap(),
            Ipv4Addr::new(8, 8, 8, 8),
            5000,
            443,
            1,
        )
        .expect("probe flow allocates")
}

// #4512 FAIL-ON-REVERT: a peer-synced NAT64 forward flow's translated pool port
// must be RESERVED in the standby's LOCAL NAT64 allocator, so a post-failover
// local `allocate_source` cannot hand the SAME (snat_v4, port) to a new flow —
// two forward flows colliding on one translated source, the RFC 6146 BIB
// violation (#4381) reappearing across a cross-node failover.
//
// The standby imports the active node's pre-computed NAT64 decision but never
// runs `allocate_source`, so before the fix its allocator had no record that
// (snat_v4, port) was in use and a fresh local flow reused it. Reverting
// `reserve_synced_nat64_allocation` (or its call site at `handle_upsert_synced`)
// makes the "new flow must NOT get the synced port" assertion RED.
#[test]
fn nat64_4512_synced_session_reserves_translated_port() {
    let state = Nat64State::from_snapshots(&[single_addr_prefix()]);
    let snat = Ipv4Addr::new(198, 51, 100, 1);
    let dst_v4 = Ipv4Addr::new(8, 8, 8, 8);

    // The active node translated a synced flow to (198.51.100.1, 1024) — 1024 is
    // the FIRST sequential NAT64 port, the sharpest collision case: a fresh
    // allocation's cursor picks it first unless the reservation forces a skip.
    let key = nat64_synced_key("2001:db8::1");
    let synced = Nat64State::forward_decision(snat, dst_v4, 1024);
    reserve_synced_nat64_allocation(&state, &key, synced, false, 0);

    // A NEW local flow (different client) allocates from the same one-address
    // pool: it MUST skip the reserved 1024 and hand out 1025. On revert (no
    // reservation) it returns 1024 — a collision with the still-live synced
    // session.
    let (snat2, port2) = nat64_probe_alloc(&state);
    assert_eq!(snat2, snat, "single-address pool => same snat_v4");
    assert_eq!(
        port2, 1025,
        "a post-failover local flow must NOT reuse the synced session's \
         reserved port 1024 (#4512 collision)"
    );
}

// #4512: a peer-synced REVERSE entry carries the destination rewrite, not the
// translated source port, and must reserve nothing (mirrors the is_reverse
// guard on the release path). A fresh flow then gets the first port 1024.
#[test]
fn nat64_4512_reverse_entry_reserves_nothing() {
    let state = Nat64State::from_snapshots(&[single_addr_prefix()]);
    let snat = Ipv4Addr::new(198, 51, 100, 1);
    let dst_v4 = Ipv4Addr::new(8, 8, 8, 8);
    let key = nat64_synced_key("2001:db8::1");
    // is_reverse = true: the reserve is a no-op.
    let synced = Nat64State::forward_decision(snat, dst_v4, 1024);
    reserve_synced_nat64_allocation(&state, &key, synced, true, 0);
    let (_, port) = nat64_probe_alloc(&state);
    assert_eq!(port, 1024, "a reverse synced entry must not reserve a port");
}

// #4512: a non-NAT64 synced decision (e.g. a pool-mode source-NAT session,
// whose port is reserved via `reserve_synced_source_nat_allocation`) must NOT
// touch the NAT64 allocator — the `nat.nat64` guard keeps the two allocators
// disjoint even when the source-NAT pool address happens to match a NAT64 pool.
#[test]
fn nat64_4512_non_nat64_decision_reserves_nothing() {
    let state = Nat64State::from_snapshots(&[single_addr_prefix()]);
    let snat = Ipv4Addr::new(198, 51, 100, 1);
    let dst_v4 = Ipv4Addr::new(8, 8, 8, 8);
    let key = nat64_synced_key("2001:db8::1");
    // A source-NAT-shaped decision: nat64 == false, but it carries the same
    // translated (snat, port). The NAT64 reserve must ignore it.
    let source_nat = NatDecision {
        rewrite_src: Some(IpAddr::V4(snat)),
        rewrite_dst: Some(IpAddr::V4(dst_v4)),
        rewrite_src_port: Some(1024),
        rewrite_dst_port: None,
        nat64: false,
        nptv6: false,
    };
    reserve_synced_nat64_allocation(&state, &key, source_nat, false, 0);
    let (_, port) = nat64_probe_alloc(&state);
    assert_eq!(
        port, 1024,
        "a non-NAT64 decision must not reserve on the NAT64 allocator"
    );
}

// #4512: if the synced pool address is not a member of ANY local NAT64 pool
// (config drift between HA nodes), the reserve is skipped gracefully — no panic,
// nothing reserved, so a fresh flow gets the first port on the real pool.
#[test]
fn nat64_4512_foreign_pool_addr_skips_reserve() {
    let state = Nat64State::from_snapshots(&[single_addr_prefix()]);
    let dst_v4 = Ipv4Addr::new(8, 8, 8, 8);
    let key = nat64_synced_key("2001:db8::1");
    // 203.0.113.9 is NOT in the local pool [198.51.100.1] (config drift).
    let foreign = Nat64State::forward_decision(Ipv4Addr::new(203, 0, 113, 9), dst_v4, 1024);
    reserve_synced_nat64_allocation(&state, &key, foreign, false, 0);
    let (snat, port) = nat64_probe_alloc(&state);
    assert_eq!(snat, Ipv4Addr::new(198, 51, 100, 1));
    assert_eq!(
        port, 1024,
        "a foreign pool address must reserve nothing on the local pool"
    );
}

// #4512: the low-level reserve/release wrappers are a symmetric pair. A reserve
// marks (snat, port) owned for a flow; a SECOND reserve for a DIFFERENT flow on
// the same port refuses to steal it (returns false); the standard teardown
// release frees it so a later flow can re-own it. This pins the standby-side
// reserve/release contract the session-sync install/delete paths depend on.
#[test]
fn nat64_4512_reserve_release_wrapper_symmetry() {
    let state = Nat64State::from_snapshots(&[single_addr_prefix()]);
    let alloc = &state.prefixes[0].port_allocator;
    let snat = Ipv4Addr::new(198, 51, 100, 1);
    let flow1 = SourceNatFlowKey {
        protocol: crate::ip_proto::PROTO_TCP,
        src_ip: "2001:db8::1".parse().unwrap(),
        dst_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        src_port: 5000,
        dst_port: 443,
        routing_scope: 0,
    };
    let flow2 = SourceNatFlowKey {
        src_ip: "2001:db8::2".parse().unwrap(),
        ..flow1
    };
    assert!(
        reserve_nat64_pool_port(
            alloc,
            flow1,
            snat,
            1024,
            0,
            false,
            0,
            crate::nat::NatHolder::Untracked
        ),
        "first reserve of an unowned port must take"
    );
    assert!(
        !reserve_nat64_pool_port(
            alloc,
            flow2,
            snat,
            1024,
            0,
            false,
            0,
            crate::nat::NatHolder::Untracked
        ),
        "a second flow must NOT steal a port owned by a live reservation"
    );
    assert!(
        release_nat64_pool_port(alloc, flow1, snat, 1024, 1, false, crate::nat::NatHolder::Untracked),
        "release must free the reservation for the owning flow"
    );
    assert!(
        reserve_nat64_pool_port(
            alloc,
            flow2,
            snat,
            1024,
            0,
            false,
            0,
            crate::nat::NatHolder::Untracked
        ),
        "after release the port is free and a later flow can re-own it"
    );
}

// ICMP echo identifiers are translated uniquely too: two clients pinging the
// same target with the same echo id, behind one pool address, get distinct
// translated identifiers so their reverse (v4->v6) tuples never collide.
#[test]
fn nat64_4381_shared_icmp_identifier_gets_distinct_translated_ids() {
    let state = Nat64State::from_snapshots(&[single_addr_prefix()]);
    let dst_v4 = Ipv4Addr::new(8, 8, 8, 8);
    let c1: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let c2: Ipv6Addr = "2001:db8::2".parse().unwrap();
    // ICMP echo: `parse_flow_ports` lifts the identifier into `src_port` with
    // `dst_port == 0`.
    let id = 0x1234u16;
    let (_, t1) = state
        .allocate_source(0, crate::ip_proto::PROTO_ICMPV6, c1, dst_v4, id, 0, 1)
        .expect("alloc icmp c1");
    let (_, t2) = state
        .allocate_source(0, crate::ip_proto::PROTO_ICMPV6, c2, dst_v4, id, 0, 1)
        .expect("alloc icmp c2");
    assert_ne!(
        t1, t2,
        "#4381: shared ICMP echo id must map to distinct translated ids"
    );
}

// ===========================================================================
// #4518: NAT64 port-allocator durability across a same-node config reload.
//
// A config commit rebuilds the forwarding state. Pre-#4518 the NAT64
// PortAllocator was rebuilt FRESH at port-offset 0, so the first post-commit
// flow reclaimed the LOW translated port still owned by a live pre-reload
// session — the (1:N) reverse index bucket then held two handles and v4->v6
// replies mis-demuxed until the old session aged out.
// `from_snapshots_with_previous` REUSES the previous prefix's Arc-backed
// allocator when the pool is unchanged, so live reservations survive; a
// changed pool resets to a fresh allocator.
// ===========================================================================

// A DIFFERENT single-address pool, same prefix, used to prove that a pool
// CHANGE does NOT reuse the previous allocator (fresh start is correct).
fn single_addr_prefix_alt_pool() -> NAT64RuleSnapshot {
    NAT64RuleSnapshot {
        name: "nat64-single".to_string(),
        prefix: "64:ff9b::/96".to_string(),
        pool_addresses: vec!["203.0.113.9".to_string()],
        no_v6_frag_header: false,
        ..Default::default()
    }
}

// FAIL-ON-REVERT: with the allocator rebuilt fresh (revert of the reuse), the
// post-reload flow reclaims the SAME low port the live pre-reload flow still
// owns, so `assert_ne!(pb, pa)` goes RED. The same-flow idempotency assertion
// also proves the live reservation carried across the reload.
#[test]
fn nat64_4518_allocator_survives_config_reload() {
    let state1 = Nat64State::from_snapshots(&[single_addr_prefix()]);
    let dst_v4 = Ipv4Addr::new(8, 8, 8, 8);
    let c1: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let c2: Ipv6Addr = "2001:db8::2".parse().unwrap();
    // Live pre-reload flow A claims the first (lowest) translated port.
    let (sa, pa) = state1
        .allocate_source(0, crate::ip_proto::PROTO_TCP, c1, dst_v4, 5000, 443, 1)
        .expect("alloc A");
    assert_eq!(sa, Ipv4Addr::new(198, 51, 100, 1));

    // Config reload with the SAME pool: the allocator (and its live tuple
    // ownership + monotonic cursor) must carry over.
    let state2 =
        Nat64State::from_snapshots_with_previous(&[single_addr_prefix()], Some(&state1), 1, 0);

    // No-collision proof FIRST (before any flow-A touch, so a reverted fresh
    // allocator cannot be masked by flow A re-consuming the low port): a NEW
    // flow B on the reloaded state must NOT reclaim flow A's still-owned
    // translated port. With the reuse it gets the NEXT port; on a reverted
    // (fresh) allocator B is the first allocation and deterministically
    // reclaims the low port `pa` — the collision this fix prevents.
    let (sb, pb) = state2
        .allocate_source(0, crate::ip_proto::PROTO_TCP, c2, dst_v4, 5000, 443, 2)
        .expect("alloc B after reload");
    assert_eq!(sb, sa, "single-address pool => same snat_v4");
    assert_ne!(
        pb, pa,
        "#4518: post-reload flow must not collide with a live pre-reload port"
    );

    // Direct durability proof: re-allocating flow A on the RELOADED state
    // returns its ORIGINAL live mapping idempotently (the reservation survived).
    // On a reverted fresh allocator flow A is no longer live and would be
    // issued a different port here.
    assert_eq!(
        state2
            .allocate_source(0, crate::ip_proto::PROTO_TCP, c1, dst_v4, 5000, 443, 2)
            .expect("re-alloc A after reload"),
        (sa, pa),
        "#4518: live pre-reload reservation must survive the config reload"
    );
}

// A pool CHANGE (addresses added/removed/reordered) must NOT reuse the old
// allocator — the round-robin counters are pool-position indexed, so stale
// reservations against a different pool must not be replayed. The new flow
// therefore starts fresh at the low port on the new pool address.
#[test]
fn nat64_4518_pool_change_resets_allocator() {
    let state1 = Nat64State::from_snapshots(&[single_addr_prefix()]);
    let dst_v4 = Ipv4Addr::new(8, 8, 8, 8);
    let c1: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let c2: Ipv6Addr = "2001:db8::2".parse().unwrap();
    let (_sa, pa) = state1
        .allocate_source(0, crate::ip_proto::PROTO_TCP, c1, dst_v4, 5000, 443, 1)
        .expect("alloc A");

    // Reload with a DIFFERENT pool address: pool differs => fresh allocator.
    let state3 = Nat64State::from_snapshots_with_previous(
        &[single_addr_prefix_alt_pool()],
        Some(&state1),
        1,
        0,
    );
    let (sb, pb) = state3
        .allocate_source(0, crate::ip_proto::PROTO_TCP, c2, dst_v4, 5000, 443, 2)
        .expect("alloc B on changed pool");
    assert_eq!(
        sb,
        Ipv4Addr::new(203, 0, 113, 9),
        "#4518: changed pool must translate to the NEW pool address"
    );
    assert_eq!(
        pb, pa,
        "#4518: a changed pool starts a fresh allocator at the low port"
    );

    // And flow A's original mapping is NOT resurrected on the changed pool.
    assert_ne!(
        state3
            .allocate_source(0, crate::ip_proto::PROTO_TCP, c1, dst_v4, 5000, 443, 2)
            .expect("re-alloc A on changed pool")
            .0,
        Ipv4Addr::new(198, 51, 100, 1),
        "#4518: the old pool address is gone after a pool change"
    );
}

// A NEW NAT64 rule with no previous counterpart (previous state present but no
// matching prefix) builds a fresh allocator, exactly as a cold start would.
#[test]
fn nat64_4518_new_rule_has_no_previous_to_reuse() {
    let empty = Nat64State::default();
    let state =
        Nat64State::from_snapshots_with_previous(&[single_addr_prefix()], Some(&empty), 1, 0);
    let dst_v4 = Ipv4Addr::new(8, 8, 8, 8);
    let c: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let (snat, port) = state
        .allocate_source(0, crate::ip_proto::PROTO_TCP, c, dst_v4, 5000, 443, 1)
        .expect("alloc on fresh rule");
    assert_eq!(snat, Ipv4Addr::new(198, 51, 100, 1));
    assert_eq!(port, 1024, "a rule with no previous match starts fresh");
}

// ---------------------------------------------------------------------------
// #2333: NAT64 v6->v4 UDP checksum 0x0000 -> 0xFFFF mapping (RFC 768/1624).
//
// In IPv4 UDP, a checksum field of 0x0000 is the reserved "no checksum
// present" sentinel; the receiver skips validation. A genuinely COMPUTED
// checksum of zero MUST be transmitted as 0xFFFF (all-ones). The v6->v4
// translation arm previously wrote the raw fold, so a datagram whose computed
// checksum folds to 0 was emitted as 0x0000 -> silent integrity loss. These
// tests fail if the 0->0xFFFF map is reverted.
// ---------------------------------------------------------------------------

/// Build a minimal IPv4 + UDP packet (no Ethernet) suitable for feeding to
/// `recompute_l4_checksum_after_nat64_v6_to_v4`. The 20-byte IPv4 header
/// carries only the fields the recompute path reads (src/dst at 12..20); the
/// UDP body is `payload`. The UDP checksum field (l4[6..8]) is left zeroed.
fn build_v4_udp_for_recompute(src: Ipv4Addr, dst: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let mut pkt = vec![0u8; 20 + udp_len];
    pkt[0] = 0x45;
    pkt[9] = PROTO_UDP;
    pkt[12..16].copy_from_slice(&src.octets());
    pkt[16..20].copy_from_slice(&dst.octets());
    // UDP header: src port, dst port, length, checksum(=0).
    pkt[20..22].copy_from_slice(&1234u16.to_be_bytes());
    pkt[22..24].copy_from_slice(&53u16.to_be_bytes());
    pkt[24..26].copy_from_slice(&(udp_len as u16).to_be_bytes());
    pkt[28..28 + payload.len()].copy_from_slice(payload);
    pkt
}

#[test]
fn v6_to_v4_udp_computed_zero_checksum_written_as_0xffff() {
    let src = Ipv4Addr::new(198, 51, 100, 1);
    let dst = Ipv4Addr::new(8, 8, 8, 8);

    // Search for a 2-byte payload whose recomputed IPv4 UDP checksum folds to
    // exactly 0x0000. The translated datagram must NOT be written as 0x0000;
    // it must become the all-ones sentinel 0xFFFF.
    let mut found = None;
    for b in 0u16..=0xffff {
        let payload = b.to_be_bytes();
        let mut pkt = build_v4_udp_for_recompute(src, dst, &payload);
        let l4 = &pkt[20..];
        let raw = checksum16_ipv4_pseudo(src, dst, PROTO_UDP, l4);
        if raw == 0 {
            // Now run the production recompute path and assert the wire value.
            recompute_l4_checksum_after_nat64_v6_to_v4(&mut pkt, PROTO_UDP)
                .expect("recompute");
            let on_wire = u16::from_be_bytes([pkt[26], pkt[27]]);
            assert_eq!(
                on_wire, 0xFFFF,
                "computed UDP checksum of 0x0000 must be transmitted as 0xFFFF \
                 (RFC 768/1624), not 0x0000"
            );
            found = Some(b);
            break;
        }
    }
    assert!(
        found.is_some(),
        "expected to find a payload yielding a zero-folding UDP checksum"
    );
}

#[test]
fn v6_to_v4_udp_nonzero_checksum_written_unchanged() {
    let src = Ipv4Addr::new(198, 51, 100, 1);
    let dst = Ipv4Addr::new(8, 8, 8, 8);
    let payload = b"\x01\x02\x03\x04";
    let mut pkt = build_v4_udp_for_recompute(src, dst, payload);

    let expected = checksum16_ipv4_pseudo(src, dst, PROTO_UDP, &pkt[20..]);
    assert_ne!(expected, 0, "test payload must not fold to zero");

    recompute_l4_checksum_after_nat64_v6_to_v4(&mut pkt, PROTO_UDP).expect("recompute");
    let on_wire = u16::from_be_bytes([pkt[26], pkt[27]]);
    assert_eq!(
        on_wire, expected,
        "a normal non-zero UDP checksum must be written verbatim (no remap)"
    );
}

#[test]
fn v6_to_v4_tcp_checksum_not_remapped() {
    // TCP checksum 0 is a normal valid value and MUST NOT be remapped to
    // 0xFFFF. Build an IPv4 + TCP packet and confirm the recompute path writes
    // the raw fold even if it is 0x0000.
    let src = Ipv4Addr::new(198, 51, 100, 1);
    let dst = Ipv4Addr::new(8, 8, 8, 8);

    // 20-byte minimal TCP header; search for a sequence number that folds the
    // computed TCP checksum to 0x0000 so we exercise the "0 stays 0" path.
    let mut found = None;
    for seq in 0u32..=0x000f_ffff {
        let mut tcp = vec![0u8; 20];
        tcp[0..2].copy_from_slice(&1234u16.to_be_bytes());
        tcp[2..4].copy_from_slice(&80u16.to_be_bytes());
        tcp[4..8].copy_from_slice(&seq.to_be_bytes());
        tcp[12] = 0x50; // data offset = 5 (20 bytes), no flags
        let raw = checksum16_ipv4_pseudo(src, dst, PROTO_TCP, &tcp);
        if raw == 0 {
            let mut pkt = vec![0u8; 20 + tcp.len()];
            pkt[0] = 0x45;
            pkt[9] = PROTO_TCP;
            pkt[12..16].copy_from_slice(&src.octets());
            pkt[16..20].copy_from_slice(&dst.octets());
            pkt[20..].copy_from_slice(&tcp);
            recompute_l4_checksum_after_nat64_v6_to_v4(&mut pkt, PROTO_TCP)
                .expect("recompute");
            // TCP checksum field is at l4[16..18] -> pkt[36..38].
            let on_wire = u16::from_be_bytes([pkt[36], pkt[37]]);
            assert_eq!(
                on_wire, 0x0000,
                "TCP checksum of 0x0000 is valid and must be written as 0x0000, \
                 not remapped to 0xFFFF (the UDP-only RFC 768 rule must not leak)"
            );
            found = Some(seq);
            break;
        }
    }
    assert!(
        found.is_some(),
        "expected to find a TCP header that folds the checksum to zero"
    );
}

// ---------------------------------------------------------------------------
// #3025: non-fragmented NAT64 packets adjust the L4 checksum INCREMENTALLY
// (RFC 1624) for the pseudo-header address change instead of recomputing the
// full L4 checksum over the whole payload. The incremental result is BYTE-
// IDENTICAL to a full recompute (one's-complement addition is exact), so the
// translated packet must always validate AND match the value a full recompute
// would write. The "uses incremental, not recompute" tests are the fail-on-
// revert seam: a deliberately-corrupted INPUT checksum is preserved (adjusted)
// by the incremental path but would be SILENTLY REPAIRED by a full recompute,
// so reverting to recompute flips those assertions RED.
// ---------------------------------------------------------------------------

/// Build an IPv6 + UDP packet (no Ethernet) with a correct mandatory checksum.
fn make_ipv6_udp_packet(
    src: Ipv6Addr,
    dst: Ipv6Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let mut pkt = vec![0u8; 40 + udp_len];
    pkt[0] = 0x60;
    pkt[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    pkt[6] = PROTO_UDP;
    pkt[7] = 64;
    pkt[8..24].copy_from_slice(&src.octets());
    pkt[24..40].copy_from_slice(&dst.octets());
    pkt[40..42].copy_from_slice(&src_port.to_be_bytes());
    pkt[42..44].copy_from_slice(&dst_port.to_be_bytes());
    pkt[44..46].copy_from_slice(&(udp_len as u16).to_be_bytes());
    pkt[48..48 + payload.len()].copy_from_slice(payload);
    pkt[46..48].copy_from_slice(&[0, 0]);
    let sum = checksum16_ipv6_pseudo(src, dst, PROTO_UDP, &pkt[40..]);
    let final_sum = if sum == 0 { 0xFFFF } else { sum };
    pkt[46..48].copy_from_slice(&final_sum.to_be_bytes());
    pkt
}

/// Build an IPv4 + UDP packet (no Ethernet). When `with_checksum` is false the
/// UDP checksum field is left 0x0000 = "no checksum present" (legal in IPv4).
fn make_ipv4_udp_packet(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
    with_checksum: bool,
) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let total_len = 20 + udp_len;
    let mut pkt = vec![0u8; total_len];
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    pkt[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // DF, non-fragmented
    pkt[8] = 64;
    pkt[9] = PROTO_UDP;
    pkt[12..16].copy_from_slice(&src.octets());
    pkt[16..20].copy_from_slice(&dst.octets());
    pkt[20..22].copy_from_slice(&src_port.to_be_bytes());
    pkt[22..24].copy_from_slice(&dst_port.to_be_bytes());
    pkt[24..26].copy_from_slice(&(udp_len as u16).to_be_bytes());
    pkt[28..28 + payload.len()].copy_from_slice(payload);
    pkt[10..12].copy_from_slice(&[0, 0]);
    let ip_sum = checksum16(&pkt[..20]);
    pkt[10..12].copy_from_slice(&ip_sum.to_be_bytes());
    pkt[26..28].copy_from_slice(&[0, 0]);
    if with_checksum {
        let sum = checksum16_ipv4_pseudo(src, dst, PROTO_UDP, &pkt[20..]);
        let final_sum = if sum == 0 { 0xFFFF } else { sum };
        pkt[26..28].copy_from_slice(&final_sum.to_be_bytes());
    }
    pkt
}

#[test]
fn nat64_3025_v6_to_v4_tcp_incremental_equals_recompute() {
    let src_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::c633:6432".parse().unwrap();
    let snat_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let dst_v4 = Ipv4Addr::new(198, 51, 100, 50);

    let v6 = make_ipv6_tcp_packet(src_v6, dst_v6, 12345, 80, b"incremental");
    let v4 = translate_v6_to_v4(&v6, snat_v4, dst_v4, false).expect("translate");

    // Translated TCP checksum must validate.
    assert_eq!(
        checksum16_ipv4_pseudo(snat_v4, dst_v4, PROTO_TCP, &v4[20..]),
        0,
        "incrementally adjusted v6->v4 TCP checksum must validate"
    );
    // ...and be bit-identical to an independent full recompute.
    let on_wire = u16::from_be_bytes([v4[36], v4[37]]);
    let mut ref_l4 = v4[20..].to_vec();
    ref_l4[16..18].copy_from_slice(&[0, 0]);
    let full = checksum16_ipv4_pseudo(snat_v4, dst_v4, PROTO_TCP, &ref_l4);
    assert_eq!(on_wire, full, "incremental result must equal full recompute");
}

#[test]
fn nat64_3025_v6_to_v4_udp_incremental_equals_recompute() {
    let src_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::0808:0808".parse().unwrap();
    let snat_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let dst_v4 = Ipv4Addr::new(8, 8, 8, 8);

    let v6 = make_ipv6_udp_packet(src_v6, dst_v6, 12345, 53, b"\x00\x01\x02\x03\x04");
    let v4 = translate_v6_to_v4(&v6, snat_v4, dst_v4, false).expect("translate");

    assert_eq!(
        checksum16_ipv4_pseudo(snat_v4, dst_v4, PROTO_UDP, &v4[20..]),
        0,
        "incrementally adjusted v6->v4 UDP checksum must validate"
    );
    let on_wire = u16::from_be_bytes([v4[26], v4[27]]);
    let mut ref_l4 = v4[20..].to_vec();
    ref_l4[6..8].copy_from_slice(&[0, 0]);
    let raw = checksum16_ipv4_pseudo(snat_v4, dst_v4, PROTO_UDP, &ref_l4);
    let full = if raw == 0 { 0xFFFF } else { raw };
    assert_eq!(on_wire, full, "incremental result must equal full recompute");
}

#[test]
fn nat64_3025_v4_to_v6_tcp_incremental_equals_recompute() {
    let src_v4 = Ipv4Addr::new(198, 51, 100, 50);
    let dst_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let src_v6: Ipv6Addr = "64:ff9b::c633:6432".parse().unwrap();
    let dst_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();

    let v4 = make_ipv4_tcp_packet(src_v4, dst_v4, 80, 12345, b"incremental");
    let v6 = translate_v4_to_v6(&v4, src_v6, dst_v6).expect("translate");

    assert_eq!(
        checksum16_ipv6_pseudo(src_v6, dst_v6, PROTO_TCP, &v6[40..]),
        0,
        "incrementally adjusted v4->v6 TCP checksum must validate"
    );
    let on_wire = u16::from_be_bytes([v6[56], v6[57]]);
    let mut ref_l4 = v6[40..].to_vec();
    ref_l4[16..18].copy_from_slice(&[0, 0]);
    let full = checksum16_ipv6_pseudo(src_v6, dst_v6, PROTO_TCP, &ref_l4);
    assert_eq!(on_wire, full, "incremental result must equal full recompute");
}

#[test]
fn nat64_3025_v4_to_v6_udp_incremental_equals_recompute() {
    let src_v4 = Ipv4Addr::new(8, 8, 8, 8);
    let dst_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let src_v6: Ipv6Addr = "64:ff9b::0808:0808".parse().unwrap();
    let dst_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();

    let v4 = make_ipv4_udp_packet(src_v4, dst_v4, 53, 12345, b"\x10\x20\x30\x40\x50", true);
    let v6 = translate_v4_to_v6(&v4, src_v6, dst_v6).expect("translate");

    // UDP checksum field at v6[40+6..40+8] = v6[46..48].
    assert_eq!(
        checksum16_ipv6_pseudo(src_v6, dst_v6, PROTO_UDP, &v6[40..]),
        0,
        "incrementally adjusted v4->v6 UDP checksum must validate"
    );
    let on_wire = u16::from_be_bytes([v6[46], v6[47]]);
    let mut ref_l4 = v6[40..].to_vec();
    ref_l4[6..8].copy_from_slice(&[0, 0]);
    let raw = checksum16_ipv6_pseudo(src_v6, dst_v6, PROTO_UDP, &ref_l4);
    let full = if raw == 0 { 0xFFFF } else { raw };
    assert_eq!(on_wire, full, "incremental result must equal full recompute");
}

#[test]
fn nat64_3025_v4_to_v6_udp_zero_checksum_generates_fresh() {
    // An IPv4 UDP datagram with checksum 0 = "no checksum present". IPv6 UDP
    // mandates a checksum, so the non-fragment path must take the full recompute
    // to GENERATE one (no baseline to adjust). The output must be a valid,
    // non-zero IPv6 UDP checksum.
    let src_v4 = Ipv4Addr::new(8, 8, 8, 8);
    let dst_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let src_v6: Ipv6Addr = "64:ff9b::0808:0808".parse().unwrap();
    let dst_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();

    let v4 = make_ipv4_udp_packet(src_v4, dst_v4, 53, 12345, b"query-bytes", false);
    assert_eq!(&v4[26..28], &[0, 0], "input v4 UDP checksum must be zero");

    let v6 = translate_v4_to_v6(&v4, src_v6, dst_v6).expect("translate");
    let on_wire = u16::from_be_bytes([v6[46], v6[47]]);
    assert_ne!(on_wire, 0, "IPv6 UDP checksum is mandatory; must be generated");
    assert_eq!(
        checksum16_ipv6_pseudo(src_v6, dst_v6, PROTO_UDP, &v6[40..]),
        0,
        "generated IPv6 UDP checksum must validate"
    );
}

#[test]
fn nat64_3025_v6_to_v4_uses_incremental_not_recompute() {
    // FAIL-ON-REVERT seam. Corrupt the INPUT v6 TCP checksum. The incremental
    // path adjusts that (wrong) baseline by the address delta, so the output is
    // ALSO wrong and does NOT validate. A full recompute would IGNORE the input
    // and produce a correct, validating checksum — so reverting flips this RED.
    let src_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::c633:6432".parse().unwrap();
    let snat_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let dst_v4 = Ipv4Addr::new(198, 51, 100, 50);

    let mut v6 = make_ipv6_tcp_packet(src_v6, dst_v6, 12345, 80, b"corrupt");
    // TCP checksum field is at v6[56..58]; flip a bit to corrupt the baseline.
    let bad = u16::from_be_bytes([v6[56], v6[57]]) ^ 0x0001;
    v6[56..58].copy_from_slice(&bad.to_be_bytes());

    let v4 = translate_v6_to_v4(&v6, snat_v4, dst_v4, false).expect("translate");
    assert_ne!(
        checksum16_ipv4_pseudo(snat_v4, dst_v4, PROTO_TCP, &v4[20..]),
        0,
        "incremental path must PRESERVE the corrupted baseline (would validate if \
         reverted to a full recompute)"
    );
}

#[test]
fn nat64_3025_v4_to_v6_uses_incremental_not_recompute() {
    // FAIL-ON-REVERT seam for the reverse direction.
    let src_v4 = Ipv4Addr::new(198, 51, 100, 50);
    let dst_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let src_v6: Ipv6Addr = "64:ff9b::c633:6432".parse().unwrap();
    let dst_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();

    let mut v4 = make_ipv4_tcp_packet(src_v4, dst_v4, 80, 12345, b"corrupt");
    // TCP checksum field is at v4[36..38]; flip a bit to corrupt the baseline.
    let bad = u16::from_be_bytes([v4[36], v4[37]]) ^ 0x0001;
    v4[36..38].copy_from_slice(&bad.to_be_bytes());

    let v6 = translate_v4_to_v6(&v4, src_v6, dst_v6).expect("translate");
    assert_ne!(
        checksum16_ipv6_pseudo(src_v6, dst_v6, PROTO_TCP, &v6[40..]),
        0,
        "incremental path must PRESERVE the corrupted baseline (would validate if \
         reverted to a full recompute)"
    );
}

#[test]
fn nat64_3025_incremental_helper_wrong_delta_breaks() {
    // Pin the delta math: applying the CORRECT pseudo-header address delta makes
    // the translated checksum validate; a WRONG delta does not. RED if the
    // incremental address-fold math is wrong.
    let src_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::c633:6432".parse().unwrap();
    let v6 = make_ipv6_tcp_packet(src_v6, dst_v6, 1111, 2222, b"abcde");

    let snat_v4 = Ipv4Addr::new(192, 0, 2, 1);
    let dst_v4 = Ipv4Addr::new(203, 0, 113, 9);

    // Build a v4-shaped buffer: 20-byte v4 header + the verbatim v6 L4 (still
    // carrying the original IPv6-pseudo-header checksum), exactly as the
    // translator does before adjusting the L4 checksum.
    let v6_l4 = &v6[40..];
    let mut out = vec![0u8; 20 + v6_l4.len()];
    out[0] = 0x45;
    out[9] = PROTO_TCP;
    out[12..16].copy_from_slice(&snat_v4.octets());
    out[16..20].copy_from_slice(&dst_v4.octets());
    out[20..].copy_from_slice(v6_l4);
    let mut v6_addrs = [0u8; 32];
    v6_addrs.copy_from_slice(&v6[8..40]);

    let mut good = out.clone();
    adjust_l4_checksum_v6_to_v4_incremental(&mut good, PROTO_TCP, &v6_addrs, snat_v4, dst_v4)
        .expect("adjust");
    assert_eq!(
        checksum16_ipv4_pseudo(snat_v4, dst_v4, PROTO_TCP, &good[20..]),
        0,
        "correct delta must validate against the real v4 addresses"
    );

    let mut bad = out.clone();
    let wrong_dst = Ipv4Addr::new(203, 0, 113, 10);
    adjust_l4_checksum_v6_to_v4_incremental(&mut bad, PROTO_TCP, &v6_addrs, snat_v4, wrong_dst)
        .expect("adjust");
    assert_ne!(
        checksum16_ipv4_pseudo(snat_v4, dst_v4, PROTO_TCP, &bad[20..]),
        0,
        "a wrong address delta must NOT validate against the real v4 addresses"
    );
}

// ===========================================================================
// #2562: stateful cross-family fragment-association cache. A non-first NAT64
// fragment inherits the FIRST fragment's translation (via the cache) and
// translates L3-only instead of dropping fail-closed (#4617). RED-on-revert:
// reverting the non-first translators to `return None`, dropping the cache LRU
// cap, or dropping the TTL prune makes these tests fail.
// ===========================================================================

/// Minimal `SessionDecision` with a forwardable resolution for cache tests.
fn frag_test_decision(nat: NatDecision) -> SessionDecision {
    SessionDecision {
        resolution: crate::afxdp::ForwardingResolution {
            disposition: crate::afxdp::ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 2,
            tx_ifindex: 2,
            tunnel_endpoint_id: 0,
            next_hop: None,
            neighbor_mac: Some([2, 0, 0, 0, 0, 2]),
            src_mac: Some([2, 0, 0, 0, 0, 1]),
            tx_vlan_id: 0,
        },
        nat,
    }
}

#[test]
fn nat64_frag_assoc_v6_to_v4_nonfirst_inherits_and_translates() {
    let src_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::0808:0808".parse().unwrap();
    let snat_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let dst_v4 = Ipv4Addr::new(8, 8, 8, 8);
    let ident: u32 = 0x0000_ABCD;

    // Payload lengths are multiples of 8 so the fragment offsets are sane.
    let first = make_ipv6_frag_udp(src_v6, dst_v6, 1000, 53, &[0xAAu8; 16], 0, true, ident);
    let nonfirst = make_ipv6_frag_udp(src_v6, dst_v6, 0, 0, &[0xBBu8; 24], 185, false, ident);

    // Port-free key co-location: first and non-first share ONE key so the
    // non-first fragment finds the first fragment's association.
    let kf = first_fragment_key(&first, libc::AF_INET6, frag_test_authority()).expect("first-fragment key");
    let kn =
        nonfirst_fragment_key(&nonfirst, libc::AF_INET6, frag_test_authority()).expect("non-first-fragment key");
    assert_eq!(
        kf, kn,
        "first and non-first fragments must share the port-free key"
    );
    // DoS property: a non-first fragment can NEVER produce a first-fragment key
    // (so it can never INSTALL into the cache).
    assert!(first_fragment_key(&nonfirst, libc::AF_INET6, frag_test_authority()).is_none());
    // An atomic fragment (MF=0, offset 0) is not a first fragment either.
    let atomic = make_ipv6_frag_udp(src_v6, dst_v6, 1, 2, &[0u8; 8], 0, false, ident);
    assert!(first_fragment_key(&atomic, libc::AF_INET6, frag_test_authority()).is_none());

    // Install the first fragment's decision; the non-first fragment inherits it.
    let cache = FragAssoc::new();
    let decision = frag_test_decision(Nat64State::forward_decision(snat_v4, dst_v4, 5000));
    cache.install(kf, decision, None, 1_000, 1, 0);
    let (hit, reverse) = cache
        .lookup(&kn, 1_500, 1, |_| true)
        .expect("non-first inherits association");
    assert!(
        reverse.is_none(),
        "forward association carries no reverse info"
    );
    assert_eq!(hit.nat.rewrite_src, Some(IpAddr::V4(snat_v4)));
    assert_eq!(hit.nat.rewrite_dst, Some(IpAddr::V4(dst_v4)));
    assert!(hit.nat.nat64);

    // Translate the non-first fragment L3-only using the inherited snat/dst.
    // RED-on-revert: forcing `write_v6_to_v4_nonfirst_into` back to `None` fails.
    let mut out = vec![0u8; nonfirst.len()];
    let n = write_v6_to_v4_nonfirst_into(&mut out, &nonfirst, snat_v4, dst_v4)
        .expect("non-first v6 fragment translates (inherited)");
    let v4 = &out[..n];
    assert_eq!(v4[0] >> 4, 4, "output is IPv4");
    assert_eq!(&v4[12..16], &snat_v4.octets(), "inherited SNAT source");
    assert_eq!(&v4[16..20], &dst_v4.octets(), "inherited v4 destination");
    // frag word: offset preserved (185, 8-byte units), MF=0, DF=0.
    let fw = u16::from_be_bytes([v4[6], v4[7]]);
    assert_eq!(fw & 0x1FFF, 185, "fragment offset preserved verbatim");
    assert_eq!(fw & 0x2000, 0, "MF copied (last fragment)");
    assert_eq!(fw & 0x4000, 0, "DF cleared for a real fragment");
    // Payload copied verbatim (everything after the v6 base(40)+Fragment(8)).
    assert_eq!(
        &v4[20..n],
        &nonfirst[48..],
        "payload copied verbatim, no L4 touch"
    );

    // Ident-equality invariant: the FIRST fragment's translated v4 ident equals
    // the non-first fragment's (both are the low 16 bits of the v6 32-bit ident).
    // Without this, the fragments never reassemble at the receiver.
    let first_v4 =
        translate_v6_to_v4(&first, snat_v4, dst_v4, false).expect("first fragment translates");
    assert_eq!(
        u16::from_be_bytes([first_v4[4], first_v4[5]]),
        u16::from_be_bytes([v4[4], v4[5]]),
        "first and non-first translated v4 idents must match"
    );
    assert_eq!(
        u16::from_be_bytes([v4[4], v4[5]]),
        (ident & 0xFFFF) as u16,
        "v4 ident = low 16 bits of the v6 32-bit ident",
    );
}

#[test]
fn nat64_frag_assoc_v4_to_v6_nonfirst_inherits_and_translates() {
    let orig_client_v6: Ipv6Addr = "2001:db8::9".parse().unwrap();
    let orig_dst_v6: Ipv6Addr = "64:ff9b::c000:0209".parse().unwrap(); // prefix::server
    let server_v4 = Ipv4Addr::new(192, 0, 2, 9);
    let snat_v4 = Ipv4Addr::new(198, 51, 100, 9);
    let ident: u16 = 0x4242;

    // Reply datagram: src = server, dst = the pool SNAT address.
    let first = make_ipv4_frag_udp(server_v4, snat_v4, 53, 1000, &[0xCCu8; 16], 0, true, ident);
    let nonfirst = make_ipv4_frag_udp(server_v4, snat_v4, 0, 0, &[0xDDu8; 24], 120, false, ident);

    let kf = first_fragment_key(&first, libc::AF_INET, frag_test_authority()).expect("first key");
    let kn = nonfirst_fragment_key(&nonfirst, libc::AF_INET, frag_test_authority()).expect("non-first key");
    assert_eq!(kf, kn, "reverse fragments share the port-free key");
    assert_eq!(
        kf.ident,
        u32::from(ident),
        "v4 ident zero-extended into the key"
    );

    // Reverse association carries the original v6 addresses (the frame builder's
    // v4->v6 branch reads these; `decision.nat` value is not consulted here).
    let cache = FragAssoc::new();
    let reverse = Nat64ReverseInfo {
        orig_src_v6: orig_client_v6,
        orig_dst_v6,
    };
    let decision = frag_test_decision(Nat64State::forward_decision(snat_v4, server_v4, 5000));
    cache.install(kf, decision, Some(reverse), 2_000, 1, 0);
    let (_hit, rev) = cache
        .lookup(&kn, 2_400, 1, |_| true)
        .expect("reverse non-first inherits");
    assert_eq!(
        rev,
        Some(reverse),
        "non-first reply fragment inherits reverse info"
    );

    // Translate the non-first reply fragment L3-only. RED-on-revert: forcing
    // `write_v4_to_v6_nonfirst_into` back to `None` fails this.
    let mut out = vec![0u8; nonfirst.len() + 64];
    let n = write_v4_to_v6_nonfirst_into(&mut out, &nonfirst, orig_dst_v6, orig_client_v6)
        .expect("non-first v4 fragment translates (inherited)");
    let v6 = &out[..n];
    assert_eq!(v6[0] >> 4, 6, "output is IPv6");
    assert_eq!(
        &v6[8..24],
        &orig_dst_v6.octets(),
        "reply src = prefix::server"
    );
    assert_eq!(
        &v6[24..40],
        &orig_client_v6.octets(),
        "reply dst = original client"
    );
    assert_eq!(v6[6], 44, "Fragment Header inserted");
    assert_eq!(
        u32::from_be_bytes([v6[44], v6[45], v6[46], v6[47]]),
        u32::from(ident),
        "v6 ident = v4 16-bit ident zero-extended",
    );
    let fw = u16::from_be_bytes([v6[42], v6[43]]);
    assert_eq!(fw >> 3, 120, "offset preserved verbatim");
    assert_eq!(fw & 1, 0, "MF copied (last fragment)");
    // Payload copied verbatim (everything after the v4 20-byte header).
    assert_eq!(
        &v6[48..n],
        &nonfirst[20..],
        "payload copied verbatim, no L4 touch"
    );
}

#[test]
fn nat64_frag_assoc_nonfirst_without_first_misses_and_drops() {
    // A non-first fragment with NO installed first fragment MISSES -> the caller
    // drops it fail-closed (#4617). The existing first-path translator also
    // still drops a non-first fragment (no association => never L3-translated).
    let cache = FragAssoc::new();
    let src_v6: Ipv6Addr = "2001:db8::5".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::c000:0205".parse().unwrap();
    let nonfirst = make_ipv6_frag_udp(src_v6, dst_v6, 0, 0, &[0u8; 16], 100, false, 0x9999);
    let kn = nonfirst_fragment_key(&nonfirst, libc::AF_INET6, frag_test_authority()).expect("key");
    assert!(
        cache.lookup(&kn, 10, 1, |_| true).is_none(),
        "orphan non-first fragment misses"
    );
    let snat = Ipv4Addr::new(198, 51, 100, 5);
    let dst = Ipv4Addr::new(192, 0, 2, 5);
    assert!(
        translate_v6_to_v4(&nonfirst, snat, dst, false).is_none(),
        "an unassociated non-first fragment is still dropped by the first-path translator",
    );
}

#[test]
fn nat64_frag_assoc_cache_is_bounded() {
    // No unbounded growth: inserting far more distinct keys than the fixed
    // ceiling must NOT exceed it (LRU eviction). RED-on-revert: dropping the
    // `if shard.len() >= CAP { remove(0) }` eviction lets the cache grow without
    // bound.
    let cache = FragAssoc::new();
    let src_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::0808:0808".parse().unwrap();
    let decision = frag_test_decision(Nat64State::forward_decision(
        Ipv4Addr::new(198, 51, 100, 1),
        Ipv4Addr::new(8, 8, 8, 8),
        5000,
    ));
    let ceiling = FRAG_SHARDS * FRAG_CAP_PER_SHARD;
    for i in 0..(ceiling * 4) as u32 {
        let key = FragKey {
            addr_family: libc::AF_INET6 as u8,
            src: IpAddr::V6(src_v6),
            dst: IpAddr::V6(dst_v6),
            ident: i,
            protocol: PROTO_UDP,
            authority: frag_test_authority(),
        };
        cache.install(key, decision, None, 1_000, 1, 0);
    }
    assert!(
        cache.len() <= ceiling,
        "cache must be bounded to {} entries; got {}",
        ceiling,
        cache.len(),
    );
}

#[test]
fn nat64_frag_assoc_ttl_evicts() {
    // The association expires after the short TTL and is pruned on the next
    // consult. RED-on-revert: dropping the `retain(deadline > now)` prune (or the
    // deadline field) makes the expired entry still hit.
    let cache = FragAssoc::new();
    let key = FragKey {
        addr_family: libc::AF_INET6 as u8,
        src: IpAddr::V6("2001:db8::1".parse().unwrap()),
        dst: IpAddr::V6("64:ff9b::0808:0808".parse().unwrap()),
        ident: 7,
        protocol: PROTO_UDP,
        authority: frag_test_authority(),
    };
    let decision = frag_test_decision(Nat64State::forward_decision(
        Ipv4Addr::new(198, 51, 100, 1),
        Ipv4Addr::new(8, 8, 8, 8),
        5000,
    ));
    cache.install(key, decision, None, 1_000, 1, 0);
    assert_eq!(cache.len(), 1);
    // Still within the TTL window: hit.
    assert!(
        cache
            .lookup(&key, 1_000 + FRAG_TTL_NS - 1, 1, |_| true)
            .is_some()
    );
    // Past the (refreshed) TTL with no intervening hit: pruned + miss.
    cache.install(key, decision, None, 1_000, 1, 0);
    assert!(
        cache
            .lookup(&key, 1_000 + FRAG_TTL_NS + 1, 1, |_| true)
            .is_none(),
        "expired association must miss",
    );
    assert_eq!(cache.len(), 0, "expired entry pruned");
}

/// Collect `count` distinct idents that all hash to the SAME shard for a fixed
/// (family, src, dst). Lets the cap-eviction path be exercised deterministically
/// on a single shard instead of relying on the statistical spread of the shared
/// cache. Panics if not enough colliding idents are found in the scan window
/// (16 shards -> ~1/16 of idents land in any one shard, so the window is ample).
fn frag_idents_in_one_shard(
    src: IpAddr,
    dst: IpAddr,
    family: u8,
    count: usize,
) -> Vec<u32> {
    let mut out = Vec::with_capacity(count);
    let target = frag_shard_index(&FragKey {
        addr_family: family,
        src,
        dst,
        ident: 0,
        protocol: PROTO_UDP,
        authority: frag_test_authority(),
    });
    let mut ident: u32 = 0;
    while out.len() < count && ident < 1_000_000 {
        let key = FragKey {
            addr_family: family,
            src,
            dst,
            ident,
            protocol: PROTO_UDP,
            authority: frag_test_authority(),
        };
        if frag_shard_index(&key) == target {
            out.push(ident);
        }
        ident += 1;
    }
    assert!(
        out.len() == count,
        "wanted {count} colliding idents, found {}",
        out.len(),
    );
    out
}

#[test]
fn nat64_frag_assoc_install_prunes_expired_before_evicting_live() {
    // #5447: under a first-fragment flood the shard fills with entries, some
    // already EXPIRED. `install` on a full shard must reclaim an EXPIRED slot
    // before it evicts the OLDEST (front) LIVE entry -- otherwise a live
    // association whose non-first fragments have not yet arrived is dropped and
    // those fragments fail closed.
    //
    // RED-on-revert: replace the prune-then-evict body with a bare
    // `shard.remove(0)` and the LIVE association (installed FIRST, so it is the
    // front/oldest) is evicted -> the final lookup for it misses.
    let src = IpAddr::V6("2001:db8::1".parse().unwrap());
    let dst = IpAddr::V6("64:ff9b::0808:0808".parse().unwrap());
    let family = libc::AF_INET6 as u8;
    let decision = frag_test_decision(Nat64State::forward_decision(
        Ipv4Addr::new(198, 51, 100, 1),
        Ipv4Addr::new(8, 8, 8, 8),
        5000,
    ));

    // Need CAP idents to fill one shard, plus one more for the flood install.
    let idents = frag_idents_in_one_shard(src, dst, family, FRAG_CAP_PER_SHARD + 1);
    let mk = |ident: u32| FragKey {
        addr_family: family,
        src,
        dst,
        ident,
        protocol: PROTO_UDP,
        authority: frag_test_authority(),
    };

    let cache = FragAssoc::new();

    // The LIVE association: installed FIRST so it sits at the front (oldest by
    // insertion order). Its deadline is FAR in the future.
    let live_key = mk(idents[0]);
    let live_now = 2 * FRAG_TTL_NS; // deadline = 4*TTL
    cache.install(live_key, decision, None, live_now, 1, 0);

    // Fill the rest of the shard to cap with EXPIRED entries: installed at
    // now=0 so their deadline is TTL, which the flood/lookup times below exceed.
    for &ident in &idents[1..FRAG_CAP_PER_SHARD] {
        cache.install(mk(ident), decision, None, 0, 1, 0);
    }
    assert_eq!(
        cache.len(),
        FRAG_CAP_PER_SHARD,
        "shard filled to cap (1 live front + CAP-1 expired)",
    );

    // The flood: a NEW first fragment installs at a time past the expired
    // deadlines but well within the LIVE entry's window.
    let flood_now = FRAG_TTL_NS + 1; // > TTL (expired) but < 4*TTL (live alive)
    let new_key = mk(idents[FRAG_CAP_PER_SHARD]);
    cache.install(new_key, decision, None, flood_now, 1, 0);

    // The LIVE association survived (expired slots were reclaimed first)...
    assert!(
        cache.lookup(&live_key, flood_now + 1, 1, |_| true).is_some(),
        "#5447: live association must survive a first-fragment flood",
    );
    // ...and the NEW association was installed into a reclaimed slot.
    assert!(
        cache.lookup(&new_key, flood_now + 1, 1, |_| true).is_some(),
        "new association installed into a reclaimed expired slot",
    );
}

#[test]
fn nat64_frag_assoc_install_reports_only_live_evictions_7054() {
    // #7054: the shard-cap eviction of a still-LIVE association was SILENT. The
    // eviction itself is correct — a fixed ceiling has to sacrifice something —
    // but the victim's non-first fragments then miss and are dropped
    // fail-closed, and the only trace was a `nat64_frag_dropped` bump
    // indistinguishable from an ordinary reorder/orphan. `install` now reports
    // it so the caller can count it.
    //
    // REACHABILITY IS ALREADY PROVEN and is not re-proven here:
    // `nat64_frag_assoc_install_all_live_still_evicts_oldest` below drives an
    // all-live shard at cap and shows the front entry evicted. What this cell
    // adds is the SIGNAL.
    //
    // THE FALSE CASES ARE THE POINT. `assert!(evicted)` alone passes against a
    // function that returns `true` unconditionally — and a counter that fires on
    // every install is worse than no counter, because it reads as constant
    // capacity pressure. So the three ordinary paths are asserted false: a plain
    // install into a shard with room, a REFRESH of an existing key, and an
    // install that reclaimed an EXPIRED slot (the #5447 prune, which must not be
    // reported as a live eviction).
    let src = IpAddr::V6("2001:db8::7054".parse().unwrap());
    let dst = IpAddr::V6("64:ff9b::0707:0707".parse().unwrap());
    let family = libc::AF_INET6 as u8;
    let decision = frag_test_decision(Nat64State::forward_decision(
        Ipv4Addr::new(198, 51, 100, 7),
        Ipv4Addr::new(7, 7, 7, 7),
        5007,
    ));
    let idents = frag_idents_in_one_shard(src, dst, family, FRAG_CAP_PER_SHARD + 2);
    let mk = |ident: u32| FragKey {
        addr_family: family,
        src,
        dst,
        ident,
        protocol: PROTO_UDP,
        authority: frag_test_authority(),
    };

    let cache = FragAssoc::new();

    // FALSE 1 — a plain install with room in the shard.
    assert!(
        !cache.install(mk(idents[0]), decision, None, 1_000, 1, 0),
        "an install into a shard with room evicted nothing and must report false"
    );
    // FALSE 2 — a REFRESH of the same key. It takes the early return and cannot
    // evict; reporting true here would count every retransmitted first fragment.
    assert!(
        !cache.install(mk(idents[0]), decision, None, 2_000, 1, 0),
        "a same-key refresh evicts nothing and must report false"
    );

    for &ident in &idents[1..FRAG_CAP_PER_SHARD] {
        assert!(
            !cache.install(mk(ident), decision, None, 1_000, 1, 0),
            "filling the shard must not report an eviction until it is full"
        );
    }
    assert_eq!(
        cache.len(),
        FRAG_CAP_PER_SHARD,
        "fixture: the shard must be exactly at cap, or the cell below is not \
         exercising the eviction branch at all"
    );

    // TRUE — every entry live, shard at cap: the oldest live entry is sacrificed.
    assert!(
        cache.install(mk(idents[FRAG_CAP_PER_SHARD]), decision, None, 1_000, 1, 0),
        "an install that evicted a still-LIVE association must report it — this \
         is the condition #7054 exists to make observable"
    );
    assert!(
        cache
            .lookup(&mk(idents[0]), 1_000, 1, |_| true)
            .is_none(),
        "control: the reported eviction really did remove the front entry"
    );

    // FALSE 3 — the #5447 prune path. Advance past the TTL so every entry is
    // expired; the install then reclaims a dead slot and must NOT be reported as
    // a live eviction.
    let past_ttl = 1_000 + FRAG_TTL_NS + 1;
    assert!(
        !cache.install(
            mk(idents[FRAG_CAP_PER_SHARD + 1]),
            decision,
            None,
            past_ttl,
            1,
            0
        ),
        "an install that reclaimed EXPIRED slots sacrificed no live association \
         and must report false — otherwise the counter fires on ordinary TTL \
         turnover and tells an operator nothing (#5447/#7054)"
    );
}

#[test]
fn nat64_frag_assoc_install_all_live_still_evicts_oldest() {
    // Control / capacity-bound preservation: when EVERY entry in a full shard is
    // LIVE, pruning reclaims nothing, so `install` still evicts the OLDEST
    // (front) entry -- the hard fixed ceiling is unchanged. This holds BOTH with
    // and without the #5447 prune (the prune is a no-op when nothing is expired).
    let src = IpAddr::V6("2001:db8::2".parse().unwrap());
    let dst = IpAddr::V6("64:ff9b::0909:0909".parse().unwrap());
    let family = libc::AF_INET6 as u8;
    let decision = frag_test_decision(Nat64State::forward_decision(
        Ipv4Addr::new(198, 51, 100, 2),
        Ipv4Addr::new(9, 9, 9, 9),
        5001,
    ));

    let idents = frag_idents_in_one_shard(src, dst, family, FRAG_CAP_PER_SHARD + 1);
    let mk = |ident: u32| FragKey {
        addr_family: family,
        src,
        dst,
        ident,
        protocol: PROTO_UDP,
        authority: frag_test_authority(),
    };

    let cache = FragAssoc::new();
    // Fill the shard to cap with entries that are ALL live at the times below.
    for &ident in &idents[..FRAG_CAP_PER_SHARD] {
        cache.install(mk(ident), decision, None, 1_000, 1, 0);
    }
    assert_eq!(cache.len(), FRAG_CAP_PER_SHARD, "shard filled to cap");

    let oldest_key = mk(idents[0]);
    let new_key = mk(idents[FRAG_CAP_PER_SHARD]);
    // Install a NEW key while every existing entry is still live.
    cache.install(new_key, decision, None, 1_000, 1, 0);

    // The oldest (front) live entry is evicted -- capacity bound preserved.
    assert!(
        cache.lookup(&oldest_key, 1_000, 1, |_| true).is_none(),
        "capacity bound: oldest live entry evicted when the shard is all-live",
    );
    assert!(
        cache.lookup(&new_key, 1_000, 1, |_| true).is_some(),
        "new entry installed",
    );
    assert!(
        cache.len() <= FRAG_CAP_PER_SHARD,
        "shard never exceeds cap",
    );
}

#[test]
fn nat64_frag_assoc_generation_change_invalidates_stale_association() {
    // #5624: a fragment association is a per-flow deny/NAT64 verdict resolved
    // under ONE config-snapshot generation. The Arc-shared cache survives a
    // config reload (so in-flight datagrams keep translating), but a commit
    // that changes deny/NAT64 rules bumps the generation, and an association
    // minted under the PRIOR generation must NOT keep being hit-refreshed and
    // used to forward fragments the new config might drop. `lookup` REJECTS
    // (treats as a miss + EVICTS) an entry whose stamped generation != the
    // current generation, while a same-generation replay still hits.
    //
    // RED-on-revert: neutralize the generation guard in `FragAssoc::lookup`
    // (e.g. change `if shard[pos].generation != generation` to `if false`) and
    // the post-commit lookup HITS -> the `is_none()` assertion below fails.
    let cache = FragAssoc::new();
    let key = FragKey {
        addr_family: libc::AF_INET6 as u8,
        src: IpAddr::V6("2001:db8::1".parse().unwrap()),
        dst: IpAddr::V6("64:ff9b::0808:0808".parse().unwrap()),
        ident: 0x5624,
        protocol: PROTO_UDP,
        authority: frag_test_authority(),
    };
    let decision = frag_test_decision(Nat64State::forward_decision(
        Ipv4Addr::new(198, 51, 100, 1),
        Ipv4Addr::new(8, 8, 8, 8),
        5000,
    ));

    // A first fragment installs the association under generation 7.
    let gen0: u64 = 7;
    cache.install(key, decision, None, 1_000, gen0, 0);

    // A same-generation non-first fragment still inherits it (valid same-config
    // reassembly is NOT broken by the guard).
    assert!(
        cache.lookup(&key, 1_100, gen0, |_| true).is_some(),
        "same-generation replay must still hit",
    );

    // A config commit bumps the generation. The stale association (gen 7) must
    // MISS under generation 8 -- the fix.
    let gen1: u64 = 8;
    assert!(
        cache.lookup(&key, 1_200, gen1, |_| true).is_none(),
        "#5624: association from a prior config generation must miss",
    );
    // ...and it was EVICTED, not merely skipped, so it cannot linger to be
    // refreshed by a later same-old-generation consult.
    assert_eq!(
        cache.len(),
        0,
        "stale association evicted on the mismatched lookup",
    );
    assert!(
        cache.lookup(&key, 1_300, gen0, |_| true).is_none(),
        "stale association was evicted, not merely skipped",
    );

    // A NEW first fragment re-admitted under the current config re-establishes
    // the association, and it hits again under the current generation.
    cache.install(key, decision, None, 1_400, gen1, 0);
    assert!(
        cache.lookup(&key, 1_500, gen1, |_| true).is_some(),
        "re-established association under the new generation hits",
    );
}

// ===========================================================================
// #5623: NAT64 SOURCE-eligibility rejection (RFC 6146 §3.5).
//
// A NAT64 translator MUST drop an incoming IPv6 packet whose SOURCE lies within
// a configured Pref64 — a looping/synthesized "already-translated" source (the
// §5 hairpin construction). `classify_ipv6_packet` folds this check ahead of the
// destination match, returning the distinct fail-closed `IneligibleSource`
// BEFORE any allocation/translation. These are the fail-on-revert guards: each
// reject test uses a VALID Pref64 destination, so WITHOUT the source gate the
// classifier would return `MatchReady` (translate) — removing the gate flips the
// assertion RED. The eligible-source test stays green, guarding against
// over-reject of legitimate global-unicast sources.
// ===========================================================================

#[test]
fn nat64_5623_source_lower_pref64_boundary_rejected() {
    let state = Nat64State::from_snapshots(&[well_known_prefix()]);
    // Lower boundary: <prefix>:: — the embedded v4 is 0.0.0.0.
    let src: Ipv6Addr = "64:ff9b::".parse().unwrap();
    // A destination that WOULD translate (MatchReady) if the source were eligible.
    let dst: Ipv6Addr = "64:ff9b::c633:6432".parse().unwrap(); // ::198.51.100.50
    assert_eq!(
        state.classify_ipv6_packet(src, dst),
        Nat64Match::IneligibleSource,
        "a lower-boundary Pref64 source (<prefix>::) must be rejected before translation"
    );
    // Counterfactual: without the source gate this destination is MatchReady.
    assert!(
        matches!(state.classify_ipv6_dest(dst), Nat64Match::MatchReady { .. }),
        "the destination alone must be a translate candidate — proves the reject is source-driven"
    );
}

#[test]
fn nat64_5623_source_upper_pref64_boundary_rejected() {
    let state = Nat64State::from_snapshots(&[well_known_prefix()]);
    // Upper boundary: <prefix>::ffff:ffff — the embedded v4 is 255.255.255.255.
    let src: Ipv6Addr = "64:ff9b::ffff:ffff".parse().unwrap();
    let dst: Ipv6Addr = "64:ff9b::c633:6432".parse().unwrap();
    assert_eq!(
        state.classify_ipv6_packet(src, dst),
        Nat64Match::IneligibleSource,
        "an upper-boundary Pref64 source (<prefix>::ffff:ffff) must be rejected before translation"
    );
}

#[test]
fn nat64_5623_source_looping_synthesized_rejected() {
    let state = Nat64State::from_snapshots(&[well_known_prefix()]);
    // Looping/synthesized: a source that already claims to be a translated
    // Pref64 address (embedded v4 192.0.2.1). RFC 6146 §5 hairpin-loop input.
    let src: Ipv6Addr = "64:ff9b::c000:0201".parse().unwrap(); // ::192.0.2.1
    let dst: Ipv6Addr = "64:ff9b::c633:6432".parse().unwrap();
    assert_eq!(
        state.classify_ipv6_packet(src, dst),
        Nat64Match::IneligibleSource,
        "a looping/synthesized Pref64 source must be rejected before translation"
    );
    // The primitive the caller drops on is also directly asserted, so a gate
    // neutralization that leaves `source_within_pref64` returning false is RED.
    assert!(
        state.source_within_pref64(src),
        "a source inside the configured Pref64 must be flagged ineligible"
    );
}

#[test]
fn nat64_5623_eligible_global_unicast_source_translates() {
    // Over-reject guard: a legitimate global-unicast source OUTSIDE every Pref64
    // must still translate exactly as before — the gate rejects only Pref64
    // sources, never eligible traffic.
    let state = Nat64State::from_snapshots(&[well_known_prefix()]);
    let src: Ipv6Addr = "2001:db8::1".parse().unwrap(); // outside 64:ff9b::/96
    let dst: Ipv6Addr = "64:ff9b::c633:6432".parse().unwrap(); // ::198.51.100.50
    match state.classify_ipv6_packet(src, dst) {
        Nat64Match::MatchReady {
            prefix_idx,
            dst_v4,
            dst_v6,
        } => {
            assert_eq!(prefix_idx, 0);
            assert_eq!(dst_v4, Ipv4Addr::new(198, 51, 100, 50));
            assert_eq!(dst_v6, dst);
        }
        other => panic!("expected MatchReady for an eligible source, got {other:?}"),
    }
    assert!(
        !state.source_within_pref64(src),
        "a global-unicast source outside every Pref64 must NOT be flagged ineligible"
    );
}

#[test]
fn nat64_5623_eligible_source_non_nat64_dest_still_routes() {
    // A legitimate source with a NON-NAT64 destination continues ordinary IPv6
    // routing — the source gate does not perturb the no-match path.
    let state = Nat64State::from_snapshots(&[well_known_prefix()]);
    let src: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst: Ipv6Addr = "2001:db8::2".parse().unwrap(); // not the NAT64 prefix
    assert_eq!(
        state.classify_ipv6_packet(src, dst),
        Nat64Match::NoPrefixMatch
    );
}

// ===========================================================================
// #6475: NAT64 DESTINATION-eligibility rejection (RFC 6052 §3.1).
//
// A NAT64 prefix MUST NOT translate an embedded IPv4 destination that is not
// globally routable. Pre-gate, `match_ipv6_dest` extracted the low 32 bits
// unconditionally, so `64:ff9b::127.0.0.1` classified `MatchReady(127.0.0.1)`
// and — with lo0 configured, whose addresses land in `state.local_v4` —
// resolved LocalDelivery to the localhost-only control plane (gRPC 50051 /
// REST 8080), reachable bidirectionally from any NAT64 client through a minted
// session. `classify_ipv6_dest` now returns the distinct fail-closed
// `IneligibleDestination` BEFORE the pool check, route lookup, policy, or
// `allocate_source`.
//
// These are the fail-on-revert guards: every reject case below is a VALID
// Pref64 destination whose extracted v4 is in a screened class, so WITHOUT the
// gate the classifier returns `MatchReady` (translate) — reverting the gate
// flips each assertion RED. The global-control test stays green, guarding
// against over-reject of a legitimate embedded destination.
// ===========================================================================

/// #6475 helper: assert BOTH classify entry points (the production
/// `classify_ipv6_packet` with an eligible source, and the dest-only
/// `classify_ipv6_dest` used by the degenerate V4-src arm and the #5174
/// MissingNeighbor re-classify) reject the destination as
/// `IneligibleDestination`.
fn assert_dst_ineligible_6475(state: &Nat64State, dst: Ipv6Addr, what: &str) {
    let src: Ipv6Addr = "2001:db8::1".parse().unwrap(); // eligible, outside Pref64
    assert_eq!(
        state.classify_ipv6_packet(src, dst),
        Nat64Match::IneligibleDestination,
        "#6475: {what} embedded in a NAT64 destination must be rejected before translation"
    );
    assert_eq!(
        state.classify_ipv6_dest(dst),
        Nat64Match::IneligibleDestination,
        "#6475: {what} must also be rejected by the dest-only classify"
    );
    // Counterfactual pin: the prefix DOES match and the v4 WOULD have been
    // extracted — the reject is the gate, not a no-match. Without the gate the
    // extracted v4 reaches `MatchReady`, so this assertion pair flips RED.
    assert!(
        state.match_ipv6_dest(dst).is_some(),
        "#6475: {what} still prefix-matches — the gate, not the prefix scan, rejects it"
    );
}

#[test]
fn nat64_6475_dst_this_host_on_this_network_rejected() {
    let state = Nat64State::from_snapshots(&[well_known_prefix()]);
    // 0.0.0.0/8 "this host on this network" (RFC 1122 §3.2.1.3). `<prefix>::`
    // is the embedded-v4 lower boundary (0.0.0.0).
    assert_dst_ineligible_6475(&state, "64:ff9b::".parse().unwrap(), "0.0.0.0 (lower boundary)");
    assert_dst_ineligible_6475(&state, "64:ff9b::1".parse().unwrap(), "0.0.0.1");
    assert_dst_ineligible_6475(
        &state,
        "64:ff9b::ff:ffff".parse().unwrap(),
        "0.255.255.255 (top of 0.0.0.0/8)",
    );
}

#[test]
fn nat64_6475_dst_loopback_rejected() {
    let state = Nat64State::from_snapshots(&[well_known_prefix()]);
    // 127.0.0.0/8 loopback (RFC 1122 §3.2.1.3) — the issue's headline case:
    // `64:ff9b::127.0.0.1` would otherwise LocalDeliver to the localhost-only
    // control plane once lo0 lands in `state.local_v4`.
    assert_dst_ineligible_6475(&state, "64:ff9b::127.0.0.1".parse().unwrap(), "127.0.0.1 loopback");
    assert_dst_ineligible_6475(
        &state,
        "64:ff9b::7fff:ffff".parse().unwrap(),
        "127.255.255.255 (top of 127.0.0.0/8)",
    );
}

#[test]
fn nat64_6475_dst_link_local_rejected() {
    let state = Nat64State::from_snapshots(&[well_known_prefix()]);
    // 169.254.0.0/16 link-local (RFC 3927).
    assert_dst_ineligible_6475(
        &state,
        "64:ff9b::a9fe:0001".parse().unwrap(),
        "169.254.0.1 link-local",
    );
    assert_dst_ineligible_6475(
        &state,
        "64:ff9b::a9fe:fffe".parse().unwrap(),
        "169.254.255.254 link-local",
    );
}

#[test]
fn nat64_6475_dst_multicast_rejected() {
    let state = Nat64State::from_snapshots(&[well_known_prefix()]);
    // 224.0.0.0/4 multicast (RFC 5771) — a translated multicast destination has
    // no unicast FIB/BIB semantics.
    assert_dst_ineligible_6475(&state, "64:ff9b::e000:0001".parse().unwrap(), "224.0.0.1 multicast");
    assert_dst_ineligible_6475(
        &state,
        "64:ff9b::efff:ffff".parse().unwrap(),
        "239.255.255.255 (top of 224.0.0.0/4)",
    );
}

#[test]
fn nat64_6475_dst_reserved_and_limited_broadcast_rejected() {
    let state = Nat64State::from_snapshots(&[well_known_prefix()]);
    // 240.0.0.0/4 reserved (RFC 1112 §4) — subsumes 255.255.255.255/32 limited
    // broadcast; `<prefix>::ffff:ffff` is the embedded-v4 upper boundary.
    assert_dst_ineligible_6475(&state, "64:ff9b::f000:0001".parse().unwrap(), "240.0.0.1 reserved");
    assert_dst_ineligible_6475(
        &state,
        "64:ff9b::ffff:ffff".parse().unwrap(),
        "255.255.255.255 limited broadcast (upper boundary)",
    );
}

#[test]
fn nat64_6475_global_dst_still_translates() {
    // Over-reject guard: a legitimate embedded IPv4 destination must still
    // translate exactly as before. 198.51.100.50 is TEST-NET-2 — RFC 6052 §3.1
    // also names RFC 1918 / RFC 5735 special-use space, but the issue scopes
    // that screening to OPTIONAL (an NSP deployment may legitimately translate
    // to internal v4), so only the listed classes are rejected and TEST-NET /
    // RFC 1918 embedded destinations still classify MatchReady.
    let state = Nat64State::from_snapshots(&[well_known_prefix()]);
    let src: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst: Ipv6Addr = "64:ff9b::c633:6432".parse().unwrap(); // ::198.51.100.50
    match state.classify_ipv6_packet(src, dst) {
        Nat64Match::MatchReady {
            prefix_idx,
            dst_v4,
            dst_v6,
        } => {
            assert_eq!(prefix_idx, 0);
            assert_eq!(dst_v4, Ipv4Addr::new(198, 51, 100, 50));
            assert_eq!(dst_v6, dst);
        }
        other => panic!("expected MatchReady for a global embedded dst, got {other:?}"),
    }
    // 8.8.8.8 — unambiguously global — translates too.
    let dst2: Ipv6Addr = "64:ff9b::808:0808".parse().unwrap();
    assert!(
        matches!(
            state.classify_ipv6_packet(src, dst2),
            Nat64Match::MatchReady { .. }
        ),
        "a global embedded destination (8.8.8.8) must still translate"
    );
    // A non-NAT64 destination is untouched by the gate (still routes as IPv6).
    let plain: Ipv6Addr = "2001:db8::2".parse().unwrap();
    assert_eq!(
        state.classify_ipv6_packet(src, plain),
        Nat64Match::NoPrefixMatch,
        "a non-Pref64 destination must still fall through to IPv6 routing"
    );
}

#[test]
fn nat64_6475_nonglobal_dst_rejected_before_pool_check() {
    // Ordering pin: input validation precedes the capacity/config report — a
    // non-global embedded destination on a prefix with an EMPTY pool reports
    // the distinct `IneligibleDestination`, not `MatchUnavailable`, so the
    // operator counter attributes the reject to the malformed destination.
    let state = Nat64State::from_snapshots(&[NAT64RuleSnapshot {
        name: "no-pool".to_string(),
        prefix: "64:ff9b::/96".to_string(),
        pool_addresses: vec![],
        no_v6_frag_header: false,
        ..Default::default()
    }]);
    let dst: Ipv6Addr = "64:ff9b::127.0.0.1".parse().unwrap();
    assert_eq!(
        state.classify_ipv6_dest(dst),
        Nat64Match::IneligibleDestination,
        "a non-global embedded dst must reject before the empty-pool check"
    );
    // The eligible-dst empty-pool behavior is unchanged (still MatchUnavailable).
    let global_dst: Ipv6Addr = "64:ff9b::808:0808".parse().unwrap();
    assert_eq!(
        state.classify_ipv6_dest(global_dst),
        Nat64Match::MatchUnavailable,
        "a global embedded dst on an empty pool still reports MatchUnavailable"
    );
}

#[test]
fn nat64_6475_embedded_v4_predicate_range_boundaries() {
    // Pin the exact screened ranges at their edges so a mask/range drift (a
    // widened or narrowed class) is RED. Each `true` case sits inside a
    // screened class; each `false` case is the nearest global address outside
    // it.
    let non_global = [
        Ipv4Addr::new(0, 0, 0, 0),          // 0.0.0.0/8 floor
        Ipv4Addr::new(0, 255, 255, 255),    // 0.0.0.0/8 ceiling
        Ipv4Addr::new(127, 0, 0, 0),        // 127.0.0.0/8 floor
        Ipv4Addr::new(127, 255, 255, 255),  // 127.0.0.0/8 ceiling
        Ipv4Addr::new(169, 254, 0, 0),      // 169.254.0.0/16 floor
        Ipv4Addr::new(169, 254, 255, 255),  // 169.254.0.0/16 ceiling
        Ipv4Addr::new(224, 0, 0, 0),        // 224.0.0.0/4 floor
        Ipv4Addr::new(239, 255, 255, 255),  // 224.0.0.0/4 ceiling
        Ipv4Addr::new(240, 0, 0, 0),        // 240.0.0.0/4 floor
        Ipv4Addr::new(255, 255, 255, 255),  // limited broadcast
    ];
    for v4 in non_global {
        assert!(
            Nat64State::embedded_v4_is_non_global(v4),
            "{v4} must be screened as non-global"
        );
    }
    let global = [
        Ipv4Addr::new(1, 0, 0, 0),          // just above 0.0.0.0/8
        Ipv4Addr::new(126, 255, 255, 255),  // just below 127.0.0.0/8
        Ipv4Addr::new(128, 0, 0, 0),        // just above 127.0.0.0/8
        Ipv4Addr::new(169, 253, 255, 255),  // just below 169.254.0.0/16
        Ipv4Addr::new(169, 255, 0, 0),      // just above 169.254.0.0/16
        Ipv4Addr::new(223, 255, 255, 255),  // just below 224.0.0.0/4
        Ipv4Addr::new(8, 8, 8, 8),          // ordinary global unicast
        Ipv4Addr::new(198, 51, 100, 50),    // TEST-NET-2 (not screened, see issue)
        Ipv4Addr::new(192, 168, 0, 1),      // RFC 1918 (not screened, see issue)
        Ipv4Addr::new(10, 0, 0, 1),         // RFC 1918 (not screened, see issue)
    ];
    for v4 in global {
        assert!(
            !Nat64State::embedded_v4_is_non_global(v4),
            "{v4} must NOT be screened as non-global"
        );
    }
}

// === #6876: the NAT64 release must free EVERY prefix holding the flow ===
//
// `release_nat64_allocation_with_mode` sweeps the prefixes but `break`s on the
// first allocator that frees the flow. That is the SAME first-hit break this
// PR REMOVED from the source-NAT release (`release_source_nat_allocation_with_mode`
// in nat/source.rs), where the accompanying comment explains at length that one
// flow can come to be held in TWO allocators and that stopping at the first
// leaves the other holding its `(pool_addr, port)` FOREVER — nothing else
// removes a `live_by_flow` entry (`release_flow` / `rollback_flow` / the
// stale-tuple replace in `reserve_flow` are the only removers, and
// `gc_expired_chunked` sweeps persistent LEASES, not live flows). The NAT64
// twin was left contradicting that reasoning.
//
// Two prefixes come to hold ONE flow with no config edit at all, because the
// reserve is OCCUPANCY-dependent: `reserve_synced_nat64_allocation` takes the
// first prefix whose allocator ACCEPTS. If prefix A's port is transiently held
// by an unrelated local flow, the synced reservation lands in B; when A frees
// and the synced session REFRESHES — every HA session-sync reconnect and every
// periodic re-upsert re-runs the reserve — A now accepts, and the same flow is
// held in A *and* B. One release then frees A and strands B.
//
// The observable is `reserve_nat64_pool_port`'s bool: it returns false when the
// port is still owned by a DIFFERENT live allocation, so a post-release probe
// with a fresh flow answers "is this port still held here" directly, rather
// than inferring it from which port a fresh `allocate_source` happens to hand
// out (a freed port goes on the recycle queue and is NOT reissued immediately —
// see `nat64_4381_release_frees_the_port`'s `assert_ne!`).
//
// FAIL-ON-REVERT: restore the `break` and prefix B's assertion goes RED.
fn shared_pool_prefix(name: &str, pref64: &str) -> NAT64RuleSnapshot {
    NAT64RuleSnapshot {
        name: name.to_string(),
        prefix: pref64.to_string(),
        // BOTH prefixes publish the SAME one-address pool, so a synced
        // `(snat_v4, port)` is a member of both and either allocator can hold
        // it — the precondition for a two-prefix reservation.
        pool_addresses: vec!["198.51.100.1".to_string()],
        no_v6_frag_header: false,
        ..Default::default()
    }
}

#[test]
fn nat64_6876_release_frees_every_prefix_holding_the_flow() {
    let state = Nat64State::from_snapshots(&[
        shared_pool_prefix("nat64-a", "64:ff9b::/96"),
        shared_pool_prefix("nat64-b", "64:ff9b:1::/96"),
    ]);
    let snat = Ipv4Addr::new(198, 51, 100, 1);
    let dst_v4 = Ipv4Addr::new(8, 8, 8, 8);
    let synced_key = nat64_synced_key("2001:db8::1");
    let synced = Nat64State::forward_decision(snat, dst_v4, 1024);

    // A local flow takes port 1024 in prefix A (1024 is the first sequential
    // NAT64 port), so A cannot accept the synced reservation.
    let squatter_key = nat64_synced_key("2001:db8::9");
    let squatter = state
        .allocate_source(
            0,
            crate::ip_proto::PROTO_TCP,
            "2001:db8::9".parse().unwrap(),
            dst_v4,
            5000,
            443,
            1,
        )
        .expect("prefix A allocates for the squatting flow");
    assert_eq!(
        squatter,
        (snat, 1024),
        "fixture precondition: the squatting flow must hold prefix A's port 1024"
    );

    // The synced flow arrives. A REFUSES (1024 is the squatter's), so the
    // reservation lands in B.
    reserve_synced_nat64_allocation(&state, &synced_key, synced, false, 0);

    // The squatter retires, freeing 1024 in A. It is held only in A, so the
    // break under test cannot affect this release.
    release_nat64_allocation(
        &state,
        &squatter_key,
        Nat64State::forward_decision(snat, dst_v4, 1024),
        false,
        2,
    );

    // The synced session refreshes (HA reconnect / periodic re-upsert). A now
    // accepts, so the SAME flow is held in BOTH prefixes.
    reserve_synced_nat64_allocation(&state, &synced_key, synced, false, 0);

    // ONE release, exactly as the teardown path issues it.
    release_nat64_allocation(&state, &synced_key, synced, false, 3);

    // Both allocators must have given the port back. Probe each with a fresh,
    // unrelated flow: `reserve_nat64_pool_port` returns false while a different
    // live allocation still owns the port.
    let probe = |client: &str| crate::nat::SourceNatFlowKey {
        protocol: crate::ip_proto::PROTO_TCP,
        src_ip: IpAddr::V6(client.parse().unwrap()),
        dst_ip: IpAddr::V4(dst_v4),
        src_port: 6000,
        dst_port: 443,
        routing_scope: 0,
    };
    assert!(
        crate::nat::reserve_nat64_pool_port(
            &state.prefixes[0].port_allocator,
            probe("2001:db8::a"),
            snat,
            1024,
            0,
            false,
            0,
            crate::nat::NatHolder::Untracked,
        ),
        "prefix A must have freed the released flow's port"
    );
    assert!(
        crate::nat::reserve_nat64_pool_port(
            &state.prefixes[1].port_allocator,
            probe("2001:db8::b"),
            snat,
            1024,
            0,
            false,
            0,
            crate::nat::NatHolder::Untracked,
        ),
        "prefix B still owns the released flow's port: the NAT64 release stopped \
         at the FIRST prefix that freed it, stranding every other holder \
         permanently — nothing else removes a live_by_flow entry. This is the \
         exact first-hit break this PR removed from the source-NAT release \
         (#6876)"
    );
}

// ---------------------------------------------------------------------------
// #5798: ingress-authority + protocol scoping of the shared fragment cache.
//
// A fragment-association HIT short-circuits the flowless enforcement arm and
// returns the FIRST fragment's whole SessionDecision (permit + egress + NAT).
// Before #5798 the key was only (family, src, dst, ident), so a non-first
// fragment from ANY security domain that reproduced that tuple inherited the
// first domain's authority — bypassing its own input filter, PBR, zone
// derivation and zone security policy. These are FAIL-ON-REVERT guards: drop a
// field from FragKey (or stop threading it through fragment_fields)
// and the corresponding "must NOT inherit" assertion fires.
// ---------------------------------------------------------------------------

/// Build the (first, non-first) IPv6 UDP fragment pair every #5798 case uses.
fn frag_pair_v6() -> (Vec<u8>, Vec<u8>) {
    let src_v6: Ipv6Addr = "2001:db8::7".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::0808:0808".parse().unwrap();
    let ident: u32 = 0x5798_0001;
    let first = make_ipv6_frag_udp(src_v6, dst_v6, 1000, 53, &[0xAAu8; 16], 0, true, ident);
    let nonfirst = make_ipv6_frag_udp(src_v6, dst_v6, 0, 0, &[0xBBu8; 24], 185, false, ident);
    (first, nonfirst)
}

fn frag_v6_decision() -> SessionDecision {
    frag_test_decision(Nat64State::forward_decision(
        Ipv4Addr::new(198, 51, 100, 1),
        Ipv4Addr::new(8, 8, 8, 8),
        5000,
    ))
}

/// A permitted first fragment from domain A must NOT authorize a non-first
/// fragment arriving from domain B. This is the #5798 root: the cross-domain
/// permit-inheritance bypass.
///
/// RED on revert: remove `authority` from `FragKey` (or stop stamping it in
/// `fragment_fields`) and the domain-B lookup HITS — the cross-domain
/// assertion below fails.
#[test]
fn frag_assoc_cross_domain_nonfirst_fragment_does_not_inherit_permit() {
    let (first, nonfirst) = frag_pair_v6();
    let cache = FragAssoc::new();
    let decision = frag_v6_decision();

    // Domain A: the permitted first fragment installs its decision.
    let ka = first_fragment_key(&first, libc::AF_INET6, frag_test_authority())
        .expect("domain-A first-fragment key");
    cache.install(ka, decision, None, 1_000, 1, 0);

    // Domain B: a non-first fragment with the SAME (family, src, dst, ident) —
    // an attacker only has to reproduce a 32-bit fragment ID, which is not an
    // authorization mechanism.
    let kb = nonfirst_fragment_key(&nonfirst, libc::AF_INET6, frag_other_authority())
        .expect("domain-B non-first-fragment key");
    assert_ne!(
        ka, kb,
        "a different ingress domain must build a DIFFERENT key (fail-closed by construction)"
    );
    assert!(
        cache.lookup(&kb, 1_100, 1, |_| true).is_none(),
        "a non-first fragment from another security domain must NOT inherit domain A's permit"
    );

    // Control: the SAME domain still inherits — the fix must not blackhole
    // legitimate fragmented traffic. The cache is Arc-shared across workers, so
    // this also covers "same domain, different worker".
    let ka_nonfirst = nonfirst_fragment_key(&nonfirst, libc::AF_INET6, frag_test_authority())
        .expect("domain-A non-first-fragment key");
    assert_eq!(ka, ka_nonfirst, "same-domain first/non-first share one key");
    assert!(
        cache.lookup(&ka_nonfirst, 1_100, 1, |_| true).is_some(),
        "a same-domain non-first fragment must still inherit (no over-blocking)"
    );
}

/// Each authority DIMENSION must bind on its own. A test that only varied the
/// whole struct could pass while three of the four fields were ignored, so this
/// perturbs one field at a time against a fixed baseline.
///
/// Every iteration carries a POSITIVE CONTROL: the same-authority non-first
/// fragment must HIT the very entry the perturbed one missed. Without it the
/// whole test is satisfied by a cache that never returns a hit — "no
/// association" is the correct answer here often enough that a totally broken
/// lookup would look identical to a correctly discriminating one.
///
/// RED on revert: delete any single field from `FragAuthority` (or from the
/// key's `PartialEq`) and that field's iteration hits.
#[test]
fn frag_assoc_every_authority_dimension_is_load_bearing() {
    let (first, nonfirst) = frag_pair_v6();
    let base = frag_test_authority();
    let decision = frag_v6_decision();

    let perturbations: [(&str, FragAuthority); 4] = [
        (
            "logical ingress interface",
            FragAuthority { ingress_ifindex: base.ingress_ifindex + 1, ..base },
        ),
        (
            "ingress VLAN (two VLAN siblings on one physical port)",
            FragAuthority { ingress_vlan_id: base.ingress_vlan_id + 100, ..base },
        ),
        (
            "ingress security zone",
            FragAuthority { ingress_zone: base.ingress_zone + 1, ..base },
        ),
        (
            "routing instance / VRF (duplicate address space across VRFs)",
            FragAuthority { routing_table: base.routing_table + 1, ..base },
        ),
    ];

    for (dimension, other) in perturbations {
        // Exactly ONE field differs from the baseline — assert that here rather
        // than trusting the struct-update literals above, so a future edit that
        // accidentally perturbs two fields cannot make a weaker test look like
        // this one.
        let differing = [
            other.ingress_ifindex != base.ingress_ifindex,
            other.ingress_vlan_id != base.ingress_vlan_id,
            other.ingress_zone != base.ingress_zone,
            other.routing_table != base.routing_table,
        ]
        .into_iter()
        .filter(|d| *d)
        .count();
        assert_eq!(
            differing, 1,
            "{dimension}: the perturbation must vary exactly one dimension"
        );

        let cache = FragAssoc::new();
        let kf = first_fragment_key(&first, libc::AF_INET6, base).expect("first key");
        cache.install(kf, decision, None, 1_000, 1, 0);

        // POSITIVE CONTROL FIRST: the baseline non-first fragment HITS. Ordered
        // before the negative assertion so a lookup that never returns anything
        // fails here rather than passing the "must not inherit" check for free.
        let kn_base =
            nonfirst_fragment_key(&nonfirst, libc::AF_INET6, base).expect("baseline key");
        assert!(
            cache.lookup(&kn_base, 1_100, 1, |_| true).is_some(),
            "{dimension} control: the SAME-authority non-first fragment must inherit — without \
             this the negative assertion below is also satisfied by a cache that never hits"
        );

        let kn =
            nonfirst_fragment_key(&nonfirst, libc::AF_INET6, other).expect("non-first key");
        assert!(
            cache.lookup(&kn, 1_100, 1, |_| true).is_none(),
            "{dimension} must be part of the association authority; a fragment differing only \
             in it inherited the permit"
        );
        // And the entry the perturbed fragment failed to match is still LIVE —
        // it MISSED, rather than the lookup above having consumed or expired it.
        assert!(
            cache.lookup(&kn_base, 1_200, 1, |_| true).is_some(),
            "{dimension}: the baseline association must survive the cross-authority miss"
        );
    }
}

/// Two datagrams that collide on (src, dst, ident) but carry DIFFERENT
/// upper-layer protocols must not alias — required-fix #2's protocol-in-key.
/// The protocol is read from L3 only (the IPv6 Fragment Header's Next Header /
/// the IPv4 Protocol byte), both of which every fragment carries, so a non-first
/// fragment never has to have its payload interpreted as L4.
///
/// RED on revert: drop `protocol` from `FragKey` and the TCP-labelled
/// non-first fragment inherits the UDP datagram's decision.
#[test]
fn frag_assoc_protocol_collision_does_not_alias() {
    let (first, nonfirst) = frag_pair_v6();
    let cache = FragAssoc::new();
    let decision = frag_v6_decision();

    let kf =
        first_fragment_key(&first, libc::AF_INET6, frag_test_authority()).expect("first key");
    // The builder emits UDP, so the key's protocol must come from the packet —
    // not be defaulted or zeroed.
    assert_eq!(
        kf.protocol, PROTO_UDP,
        "the key's protocol must be parsed from the IPv6 Fragment Header's Next Header"
    );
    cache.install(kf, decision, None, 1_000, 1, 0);

    let kn = nonfirst_fragment_key(&nonfirst, libc::AF_INET6, frag_test_authority())
        .expect("non-first key");
    let collided = FragKey { protocol: PROTO_TCP, ..kn };
    assert!(
        cache.lookup(&collided, 1_100, 1, |_| true).is_none(),
        "a TCP fragment must not inherit a UDP datagram's decision on an ident collision"
    );
    assert!(
        cache.lookup(&kn, 1_100, 1, |_| true).is_some(),
        "the matching-protocol fragment must still inherit"
    );
}

/// The IPv4 side reads its protocol from the header's Protocol byte, which is
/// present in EVERY fragment (unlike the L4 header, which only the first
/// carries). Guards the v4 arm of the same SSOT builder.
///
/// The key comparisons alone would all hold against a cache that never serves a
/// hit, so the second half drives the SAME keys through a real `FragAssoc`
/// — same-domain HIT (the positive control) then cross-domain MISS.
#[test]
fn frag_assoc_v4_key_carries_protocol_and_authority() {
    let server_v4 = Ipv4Addr::new(192, 0, 2, 9);
    let snat_v4 = Ipv4Addr::new(198, 51, 100, 9);
    let ident: u16 = 0x5798;
    let first = make_ipv4_frag_udp(server_v4, snat_v4, 53, 1000, &[0xCCu8; 16], 0, true, ident);
    let nonfirst = make_ipv4_frag_udp(server_v4, snat_v4, 0, 0, &[0xDDu8; 24], 120, false, ident);

    let kf =
        first_fragment_key(&first, libc::AF_INET, frag_test_authority()).expect("v4 first key");
    let kn = nonfirst_fragment_key(&nonfirst, libc::AF_INET, frag_test_authority())
        .expect("v4 non-first key");
    assert_eq!(
        kf.protocol, PROTO_UDP,
        "the v4 key's protocol must come from IPv4 header byte 9"
    );
    assert_eq!(
        kn.protocol, PROTO_UDP,
        "a v4 NON-first fragment carries the same Protocol byte"
    );
    assert_eq!(kf.authority, frag_test_authority(), "authority is stamped");
    assert_eq!(kf, kn, "same domain + protocol still co-locates the datagram");

    // Cross-domain on the v4 arm too.
    let kn_other = nonfirst_fragment_key(&nonfirst, libc::AF_INET, frag_other_authority())
        .expect("v4 non-first key, other domain");
    assert_ne!(
        kf, kn_other,
        "a v4 fragment from another domain must build a different key"
    );

    // Drive the same keys through a real cache. Everything above compares keys
    // and would hold verbatim against a `FragAssoc` that never returns a
    // hit, so the discrimination below needs a positive control to mean
    // anything: same-domain HITS, other-domain MISSES, and the entry the
    // other-domain fragment failed to match is still live afterwards.
    let cache = FragAssoc::new();
    cache.install(kf, frag_v6_decision(), None, 1_000, 1, 0);
    assert!(
        cache.lookup(&kn, 1_100, 1, |_| true).is_some(),
        "control: the same-domain v4 non-first fragment must inherit"
    );
    assert!(
        cache.lookup(&kn_other, 1_100, 1, |_| true).is_none(),
        "a v4 non-first fragment from another domain must NOT inherit"
    );
    assert!(
        cache.lookup(&kn, 1_200, 1, |_| true).is_some(),
        "the v4 association must survive the cross-domain miss (it missed, it did not vanish)"
    );
}

// ---------------------------------------------------------------------------
// #6857: the RUNTIME-ownership fence on the fragment association.
//
// The config-generation fence (#5624) invalidates an association when a commit
// changes deny/NAT64 rules. An RG transition is runtime HA state: it changes no
// config and bumps no snapshot generation, so that fence cannot see it. Without
// a runtime fence a non-first fragment keeps HITTING an association minted while
// this node was forwarding-active, inheriting the earlier permit + egress + NAT
// on a node no longer entitled to grant it — exactly what the #6458 owner-RG
// gate prevents on the enforcement path.
// ---------------------------------------------------------------------------

fn frag_rg_fixture() -> (FragAssoc, FragKey, FragKey, SessionDecision) {
    let src_v6: Ipv6Addr = "2001:db8::1".parse().expect("src");
    let dst_v6: Ipv6Addr = "64:ff9b::808:808".parse().expect("dst");
    let snat_v4 = Ipv4Addr::new(172, 16, 80, 8);
    let dst_v4 = Ipv4Addr::new(8, 8, 8, 8);
    let ident: u32 = 0x0000_BEEF;
    let first = make_ipv6_frag_udp(src_v6, dst_v6, 1000, 53, &[0xAAu8; 16], 0, true, ident);
    let nonfirst = make_ipv6_frag_udp(src_v6, dst_v6, 0, 0, &[0xBBu8; 24], 185, false, ident);
    let kf = first_fragment_key(&first, libc::AF_INET6, frag_test_authority())
        .expect("first-fragment key");
    let kn = nonfirst_fragment_key(&nonfirst, libc::AF_INET6, frag_test_authority())
        .expect("non-first-fragment key");
    assert_eq!(
        kf, kn,
        "#6857 premise: the two fragments must share one key"
    );
    let decision = frag_test_decision(Nat64State::forward_decision(snat_v4, dst_v4, 5000));
    (FragAssoc::new(), kf, kn, decision)
}

/// The property: an association minted under owner RG 3 must MISS once RG 3 is
/// no longer forwarding-active locally.
#[test]
fn frag_assoc_refuses_a_hit_once_the_owner_rg_stops_forwarding_6857() {
    let (cache, kf, kn, decision) = frag_rg_fixture();
    cache.install(kf, decision, None, 1_000, 1, 3);

    assert!(
        cache.lookup(&kn, 1_500, 1, |_| false).is_none(),
        "#6857: a non-first fragment must NOT inherit a permit this node is no \
         longer entitled to grant. The association was minted while owner RG 3 \
         was forwarding-active; it is not any more, and the config-generation \
         fence cannot see that because an RG transition bumps no generation"
    );
}

/// The POSITIVE control, without which the cell above is satisfied by a lookup
/// that refuses everything.
#[test]
fn frag_assoc_still_inherits_while_the_owner_rg_is_forwarding_6857() {
    let (cache, kf, kn, decision) = frag_rg_fixture();
    cache.install(kf, decision, None, 1_000, 1, 3);

    assert!(
        cache.lookup(&kn, 1_500, 1, |rg| rg == 3).is_some(),
        "#6857 CONTROL: an unchanged RG must still inherit — over-blocking here \
         is a fragment blackhole, not a safety improvement"
    );
}

/// owner_rg == 0 means NOT RG-dependent and must NEVER be fenced.
///
/// This is the cell that stops the fix becoming a regression: on a STANDALONE
/// box (no chassis cluster) every resolution has owner RG 0, so a fence that
/// treated 0 as "not entitled" would evict every association on every consult
/// and disable fragment association for the entire non-HA deployment. The
/// predicate below refuses everything, exactly as it would on a box with no HA
/// state at all.
#[test]
fn frag_assoc_with_no_owner_rg_is_not_fenced_6857() {
    let (cache, kf, kn, decision) = frag_rg_fixture();
    cache.install(kf, decision, None, 1_000, 1, 0);

    assert!(
        cache.lookup(&kn, 1_500, 1, |_| false).is_some(),
        "#6857: owner RG 0 is NOT RG-dependent and must not be fenced. A \
         standalone box has no redundancy groups, so fencing on 0 would disable \
         fragment association entirely for every non-HA deployment"
    );
}

/// A refused hit must also EVICT, so the fence is not re-evaluated on every
/// later fragment of a datagram that can never be inherited again.
#[test]
fn frag_assoc_evicts_the_entry_it_refuses_6857() {
    let (cache, kf, kn, decision) = frag_rg_fixture();
    cache.install(kf, decision, None, 1_000, 1, 3);
    assert_eq!(cache.len(), 1, "#6857 premise: the install must be present");

    assert!(cache.lookup(&kn, 1_500, 1, |_| false).is_none());
    assert_eq!(
        cache.len(),
        0,
        "#6857: a refused association must be evicted, not left to be re-judged \
         by every subsequent fragment"
    );
}

/// The two fences are INDEPENDENT: a stale generation must still refuse even
/// while the owner RG is perfectly healthy.
///
/// Without this, a fix that replaced the config fence with the runtime one —
/// rather than adding beside it — would pass every cell above.
#[test]
fn frag_assoc_config_fence_survives_the_rg_fence_6857() {
    let (cache, kf, kn, decision) = frag_rg_fixture();
    cache.install(kf, decision, None, 1_000, 1, 3);

    assert!(
        cache.lookup(&kn, 1_500, 2, |rg| rg == 3).is_none(),
        "#6857: the #5624 config-generation fence must still refuse a \
         stale-generation entry even when the owner RG is forwarding-active. \
         The runtime fence is added BESIDE the config one, not instead of it"
    );
}

// ---------------------------------------------------------------------------
// #6892: the synced NAT64 reserve must pick the prefix by the SAME
// discriminator the ACTIVE node used.
// ---------------------------------------------------------------------------

// TWO prefixes that SHARE one pool address and differ only in prefix_bytes.
//
// This shape is the whole test, and a single-prefix fixture cannot exercise it
// at all: with one prefix, "first prefix whose pool_v4 contains snat_v4" and
// "the prefix whose prefix_bytes match the v6 destination" are the same answer,
// so the defect is invisible. Sharing the pool address is what makes the pool
// scan ambiguous; differing prefix_bytes is what makes the v6 destination
// decisive.
fn shared_pool_prefixes_6892() -> Vec<NAT64RuleSnapshot> {
    vec![
        NAT64RuleSnapshot {
            name: "nat64-a".to_string(),
            prefix: "64:ff9b::/96".to_string(),
            pool_addresses: vec!["198.51.100.1".to_string()],
            no_v6_frag_header: false,
            ..Default::default()
        },
        NAT64RuleSnapshot {
            name: "nat64-b".to_string(),
            // A DIFFERENT Pref64 with the SAME pool address.
            prefix: "2001:db8:64::/96".to_string(),
            pool_addresses: vec!["198.51.100.1".to_string()],
            no_v6_frag_header: false,
            ..Default::default()
        },
    ]
}

fn synced_key_for_dst_6892(client: &str, dst_v6: &str) -> crate::session::SessionKey {
    crate::session::SessionKey {
        addr_family: libc::AF_INET6 as u8,
        protocol: crate::ip_proto::PROTO_TCP,
        src_ip: IpAddr::V6(client.parse().unwrap()),
        dst_ip: IpAddr::V6(dst_v6.parse().unwrap()),
        src_port: 5000,
        dst_port: 443,
            discriminator: Default::default(),
            routing_domain: 0,
    }
}

// FAIL-ON-REVERT: drop the #6892 match_ipv6_dest narrowing and the reserve falls
// back to "first prefix whose pool_v4 contains snat_v4", which is prefix 0 for
// BOTH destinations. The prefix-1 assertion below then goes RED.
//
// This asserts WHICH ALLOCATOR holds the reservation, not merely that a
// reservation happened — the defect is a reservation in the wrong allocator, so
// "it reserved" is satisfied by the buggy path too.
#[test]
fn nat64_6892_synced_reserve_picks_the_prefix_the_active_used() {
    let state = Nat64State::from_snapshots(&shared_pool_prefixes_6892());
    assert_eq!(state.prefixes.len(), 2, "fixture must have two prefixes");
    let snat = Ipv4Addr::new(198, 51, 100, 1);
    let dst_v4 = Ipv4Addr::new(8, 8, 8, 8);

    // The active translated a flow whose v6 destination lies in prefix B, so it
    // selected prefix 1 via match_ipv6_dest and reserved in prefix 1's
    // allocator. The standby must land in the SAME one.
    let key = synced_key_for_dst_6892("2001:db8::1", "2001:db8:64::0808:0808");
    let synced = Nat64State::forward_decision(snat, dst_v4, 1024);
    assert!(
        reserve_synced_nat64_allocation(&state, &key, synced, false, 0),
        "the synced reserve must succeed"
    );

    // Prefix 1 (the one the ACTIVE used) must now refuse a DIFFERENT flow on the
    // same (snat, port) — that is what "the reservation lives here" means.
    let other_flow = SourceNatFlowKey {
        protocol: crate::ip_proto::PROTO_TCP,
        src_ip: "2001:db8::99".parse().unwrap(),
        dst_ip: IpAddr::V4(dst_v4),
        src_port: 6000,
        dst_port: 443,
        routing_scope: 0,
    };
    assert!(
        !reserve_nat64_pool_port(
            &state.prefixes[1].port_allocator,
            other_flow,
            snat,
            1024,
            0,
            false,
            0,
            crate::nat::NatHolder::Untracked,
        ),
        "prefix 1's allocator does NOT hold the synced reservation — the standby \
         reserved in a different allocator than the active used, so the translated \
         (pool v4, port) is still free where it matters and a post-failover local \
         flow can be handed it (#6892)"
    );

    // And prefix 0 must be UNTOUCHED: a reservation there is the bug's signature.
    assert!(
        reserve_nat64_pool_port(
            &state.prefixes[0].port_allocator,
            other_flow,
            snat,
            1024,
            0,
            false,
            0,
            crate::nat::NatHolder::Untracked,
        ),
        "prefix 0's allocator holds a reservation it should never have taken — the \
         synced path selected by pool_v4 membership instead of the v6 destination (#6892)"
    );
}

// The MIRROR case, and it is what stops the fix being "always pick prefix 1".
// Same fixture, same pool address, destination in prefix A: the reservation must
// land in prefix 0. Without this cell, hard-coding either index passes.
#[test]
fn nat64_6892_synced_reserve_follows_the_destination_prefix_both_ways() {
    let state = Nat64State::from_snapshots(&shared_pool_prefixes_6892());
    let snat = Ipv4Addr::new(198, 51, 100, 1);
    let dst_v4 = Ipv4Addr::new(8, 8, 8, 8);

    let key = synced_key_for_dst_6892("2001:db8::1", "64:ff9b::0808:0808");
    let synced = Nat64State::forward_decision(snat, dst_v4, 2048);
    assert!(reserve_synced_nat64_allocation(&state, &key, synced, false, 0));

    let other_flow = SourceNatFlowKey {
        protocol: crate::ip_proto::PROTO_TCP,
        src_ip: "2001:db8::99".parse().unwrap(),
        dst_ip: IpAddr::V4(dst_v4),
        src_port: 6000,
        dst_port: 443,
        routing_scope: 0,
    };
    assert!(
        !reserve_nat64_pool_port(
            &state.prefixes[0].port_allocator,
            other_flow,
            snat,
            2048,
            0,
            false,
            0,
            crate::nat::NatHolder::Untracked,
        ),
        "a destination in prefix A did not reserve in prefix 0's allocator (#6892)"
    );
    assert!(
        reserve_nat64_pool_port(
            &state.prefixes[1].port_allocator,
            other_flow,
            snat,
            2048,
            0,
            false,
            0,
            crate::nat::NatHolder::Untracked,
        ),
        "prefix 1 took a reservation for a destination in prefix A (#6892)"
    );
}

// The FALLBACK must survive. A key whose destination matches NO configured
// prefix (config drift between nodes, or an old peer that synced a v4-keyed
// tuple) must still reach the pool scan rather than silently reserving nothing —
// narrowing is an added discriminator, not a replacement gate.
#[test]
fn nat64_6892_unmatched_destination_still_falls_back_to_the_pool_scan() {
    let state = Nat64State::from_snapshots(&shared_pool_prefixes_6892());
    let snat = Ipv4Addr::new(198, 51, 100, 1);
    let dst_v4 = Ipv4Addr::new(8, 8, 8, 8);

    // A destination in NEITHER Pref64.
    let key = synced_key_for_dst_6892("2001:db8::1", "2001:dead:beef::0808:0808");
    assert!(
        state
            .match_ipv6_dest("2001:dead:beef::0808:0808".parse().unwrap())
            .is_none(),
        "fixture precondition: this destination must match no prefix, or the cell \
         is not exercising the fallback"
    );

    let synced = Nat64State::forward_decision(snat, dst_v4, 4096);
    assert!(
        reserve_synced_nat64_allocation(&state, &key, synced, false, 0),
        "an unmatched destination must still reserve via the pool scan — dropping \
         the fallback would leave the translated port free on the standby (#6892)"
    );

    // The scan takes the first pool owner, which is prefix 0.
    let other_flow = SourceNatFlowKey {
        protocol: crate::ip_proto::PROTO_TCP,
        src_ip: "2001:db8::99".parse().unwrap(),
        dst_ip: IpAddr::V4(dst_v4),
        src_port: 6000,
        dst_port: 443,
        routing_scope: 0,
    };
    assert!(
        !reserve_nat64_pool_port(
            &state.prefixes[0].port_allocator,
            other_flow,
            snat,
            4096,
            0,
            false,
            0,
            crate::nat::NatHolder::Untracked,
        ),
        "the fallback scan did not reserve anywhere (#6892)"
    );
}

// ---------------------------------------------------------------------------
// #6982: the NAT64 allocator aggregate budget.
//
// There are exactly TWO production `PortAllocator::new` call sites in the tree.
// #6812 gated the SNAT one at its apply boundary; this one was gated by
// nothing. A NAT64 prefix costs `pool_v4.len() * 64512` occupancy bits, and
// because the port range is a FIXED CONSTANT every pool address costs the
// MAXIMUM — there is no narrow-range case, unlike SNAT. So the ~1.48 GiB
// allocation #6812 exists to prevent was reachable here with #6812 fully in
// place.
//
// TWO THINGS THESE TESTS DO DELIBERATELY, both learned from #6815's own review:
//
//  1. THEY DRIVE THE REAL ENTRY POINT UNDER THE REAL BUDGET. #6815's cap
//     arithmetic was fully tested while its production wiring was not —
//     substituting an infinite budget into the production call left that suite
//     at 273 passed / 0 failed. A test that injects a scaled-down budget binds
//     the injection, not the shipped constant. Every test below calls
//     `Nat64State::from_snapshots{,_with_previous}` and crosses
//     `NAT64_AGGREGATE_BUDGET` itself.
//
//  2. THEY CROSS BY PREFIX COUNT, NOT PORT CAPACITY. Materialising 2^33 port
//     slots is a test that gets deleted for being slow, and a deleted guard is
//     no guard. `max_prefixes` is 1024, so 1025 prefixes of ONE address each
//     cross the real budget while allocating ~66M bits total — and the refused
//     one allocates nothing at all, which is the property under test.
// ---------------------------------------------------------------------------

/// Build `n` distinct single-address NAT64 prefixes.
fn budget_snaps(n: usize) -> Vec<NAT64RuleSnapshot> {
    (0..n)
        .map(|i| NAT64RuleSnapshot {
            name: format!("r{i}"),
            // Distinct /96 prefixes: 2001:db8:<i>::/96.
            prefix: format!("2001:db8:{:x}::/96", i),
            pool_addresses: vec![format!("198.51.100.{}", (i % 250) + 1)],
            no_v6_frag_header: false,
            ..Default::default()
        })
        .collect()
}

/// THE BINDING (#6982). The real entry point, the real constant: a snapshot one
/// prefix past `max_prefixes` gets that prefix REFUSED, and the refusal builds
/// no bitmap.
///
/// Fail-on-revert: delete the `admitted_with` gate in
/// `from_snapshots_with_previous` and the 1025th prefix installs its pool and
/// its allocator, so both assertions below fail.
#[test]
fn nat64_6982_aggregate_budget_refuses_past_the_prefix_cap() {
    let n = NAT64_AGGREGATE_BUDGET.max_prefixes as usize;
    let state = Nat64State::from_snapshots(&budget_snaps(n + 1));

    // Every prefix is INSTALLED — a refused one is not dropped, or its traffic
    // would fall through to NoPrefixMatch and route as ordinary IPv6.
    assert_eq!(
        state.prefixes.len(),
        n + 1,
        "a refused prefix must still be installed, or its traffic routes UNTRANSLATED \
         instead of dropping fail-closed (#6982)"
    );

    let refused: Vec<usize> = state
        .prefixes
        .iter()
        .enumerate()
        .filter(|(_, p)| p.over_budget)
        .map(|(i, _)| i)
        .collect();
    assert_eq!(
        refused,
        vec![n],
        "exactly the one prefix past the cap must be refused, and it must be the LAST \
         (first-fit: earlier prefixes fit and are admitted)"
    );
    assert!(
        state.prefixes[n].pool_v4.is_empty(),
        "a refused prefix must carry an EMPTY pool — the whole point is that no occupancy \
         bitmap is materialised for it"
    );
    // ...and the admitted ones are untouched.
    assert_eq!(state.prefixes[0].pool_v4.len(), 1);
    assert!(!state.prefixes[0].over_budget);
}

/// THREE STATES, NOT TWO (#6982), asserted at the CONSUMPTION boundary.
///
/// A refused prefix carries an empty pool, which makes it classify exactly like
/// the legitimate no-source-pool rule the Go side emits — both are
/// `MatchUnavailable`. That collapse is the trap: the two have OPPOSITE
/// remedies (raise the budget / split the config, versus add a source pool), so
/// an operator who cannot tell them apart is sent to the wrong one.
///
/// This asserts all three states where they are CONSUMED — through
/// `classify_ipv6_dest`, not at the point the budget is computed — because a
/// distinction that exists only inside the resolver is not a distinction the
/// dataplane can act on.
#[test]
fn nat64_6982_over_budget_is_distinguishable_from_empty_pool() {
    // (a) healthy, (b) empty-by-config — both under budget.
    let healthy = NAT64RuleSnapshot {
        name: "healthy".to_string(),
        prefix: "2001:db8:aaaa::/96".to_string(),
        pool_addresses: vec!["198.51.100.1".to_string()],
        ..Default::default()
    };
    let empty = NAT64RuleSnapshot {
        name: "empty-by-config".to_string(),
        prefix: "2001:db8:bbbb::/96".to_string(),
        pool_addresses: vec![],
        ..Default::default()
    };
    let state = Nat64State::from_snapshots(&[healthy.clone(), empty.clone()]);
    assert!(!state.prefixes[0].over_budget, "healthy is not over budget");
    assert!(
        !state.prefixes[1].over_budget,
        "an empty-by-config pool is NOT a budget refusal — collapsing the two is the defect"
    );
    assert!(state.prefixes[1].pool_v4.is_empty());

    // Consumption boundary: healthy translates, empty-by-config is unavailable.
    let dst_healthy: Ipv6Addr = "2001:db8:aaaa::c633:6401".parse().unwrap();
    let dst_empty: Ipv6Addr = "2001:db8:bbbb::c633:6401".parse().unwrap();
    assert!(
        matches!(state.classify_ipv6_dest(dst_healthy), Nat64Match::MatchReady { .. }),
        "a healthy prefix must translate"
    );
    assert_eq!(
        state.classify_ipv6_dest(dst_empty),
        Nat64Match::MatchUnavailable,
        "an empty-by-config pool drops fail-closed"
    );

    // (c) refused-by-budget. Same classification, DIFFERENT state.
    let mut snaps = budget_snaps(NAT64_AGGREGATE_BUDGET.max_prefixes as usize);
    snaps.push(NAT64RuleSnapshot {
        name: "refused".to_string(),
        prefix: "2001:db8:cccc::/96".to_string(),
        pool_addresses: vec!["198.51.100.9".to_string()],
        ..Default::default()
    });
    let over = Nat64State::from_snapshots(&snaps);
    let last = over.prefixes.last().expect("the refused prefix is installed");
    assert!(last.over_budget, "the past-cap prefix must be marked over-budget");

    let dst_refused: Ipv6Addr = "2001:db8:cccc::c633:6401".parse().unwrap();
    assert_eq!(
        over.classify_ipv6_dest(dst_refused),
        Nat64Match::MatchUnavailable,
        "a refused prefix must DROP fail-closed, never route as untranslated IPv6"
    );

    // The three states are pairwise distinguishable. Classification alone is
    // NOT enough — (b) and (c) share it — which is exactly why `over_budget`
    // has to be carried rather than inferred from `pool_v4.is_empty()`.
    let healthy_p = &state.prefixes[0];
    let empty_p = &state.prefixes[1];
    assert_ne!(
        (empty_p.pool_v4.is_empty(), empty_p.over_budget),
        (last.pool_v4.is_empty(), last.over_budget),
        "empty-by-config and refused-by-budget must not be the same observable state; \
         both classify MatchUnavailable, so the flag is the only thing separating them"
    );
    assert_ne!(
        (healthy_p.pool_v4.is_empty(), healthy_p.over_budget),
        (empty_p.pool_v4.is_empty(), empty_p.over_budget),
    );
}

/// #6982: a REUSED allocator is charged in phase 1, BEFORE any new prefix is
/// admitted — so admission does not depend on snapshot ORDER.
///
/// This is the #6812 F2-round-4 invariant. Charging reuse where it is met lets
/// a NEW prefix be admitted against a total that does not yet include reused
/// prefixes appearing LATER in the slice; those are then accepted
/// unconditionally and the live set ends up over the cap, one extra prefix per
/// apply.
///
/// Fail-on-revert: move the phase-1 loop inline (charge reuse at the point it
/// is met) and the reversed order admits the new prefix.
#[test]
fn nat64_6982_reuse_is_charged_before_new_prefixes_regardless_of_order() {
    let n = NAT64_AGGREGATE_BUDGET.max_prefixes as usize;
    // A full generation at exactly the cap.
    let first = Nat64State::from_snapshots(&budget_snaps(n));
    assert!(first.prefixes.iter().all(|p| !p.over_budget), "generation 1 fits exactly");

    let newcomer = NAT64RuleSnapshot {
        name: "newcomer".to_string(),
        prefix: "2001:db8:ffff::/96".to_string(),
        pool_addresses: vec!["198.51.100.200".to_string()],
        ..Default::default()
    };

    for (label, snaps) in [
        ("reused-first", {
            let mut v = budget_snaps(n);
            v.push(newcomer.clone());
            v
        }),
        ("newcomer-first", {
            let mut v = vec![newcomer.clone()];
            v.extend(budget_snaps(n));
            v
        }),
    ] {
        let next = Nat64State::from_snapshots_with_previous(&snaps, Some(&first), 0, 1);
        let refused = next.prefixes.iter().filter(|p| p.over_budget).count();
        assert_eq!(
            refused, 1,
            "{label}: exactly one prefix must be refused. If this is 0 the newcomer was \
             admitted against a total that did not yet include the reused prefixes later in \
             the slice — the live set is then over the cap, and it repeats one prefix per \
             apply (#6982 / #6812 F2 r4)"
        );
        let newcomer_prefix = next
            .prefixes
            .iter()
            .find(|p| p.prefix_bytes[..6] == [0x20, 0x01, 0x0d, 0xb8, 0xff, 0xff])
            .expect("the newcomer is installed either way");
        assert!(
            newcomer_prefix.over_budget,
            "{label}: the REFUSED one must be the newcomer, not a reused prefix — a reused \
             allocator carries live translations and must be accepted unconditionally"
        );
    }
}

/// #6982: a no-op re-apply must not refuse anything.
///
/// Every prefix reuses, so phase 1 charges the whole live set and phase 2
/// admits nothing new. If reuse were charged through `admitted_with` instead of
/// unconditionally, a generation sitting exactly AT the cap would refuse its own
/// prefixes on re-apply and kill live translations.
#[test]
fn nat64_6982_noop_reapply_refuses_nothing_at_the_cap() {
    let n = NAT64_AGGREGATE_BUDGET.max_prefixes as usize;
    let snaps = budget_snaps(n);
    let first = Nat64State::from_snapshots(&snaps);
    let again = Nat64State::from_snapshots_with_previous(&snaps, Some(&first), 0, 1);
    assert_eq!(
        again.prefixes.iter().filter(|p| p.over_budget).count(),
        0,
        "a no-op re-apply at exactly the cap must refuse nothing — a reused allocator holds \
         live translated-port ownership and refusing it would strand those flows"
    );
    assert!(again.prefixes.iter().all(|p| p.pool_v4.len() == 1));
}

/// #6982: the silent phase-1 identity parser must accept exactly the rules the
/// build loop accepts.
///
/// The two parses are separate code (the loop's logs loudly and skips
/// all-or-nothing per #3888; phase 1 must not double-log). If phase 1 were
/// STRICTER, a rule the loop installs would be invisible to the budget and its
/// reuse uncharged — reopening the ordering hole. If it were LOOSER, a skipped
/// rule would consume budget that nothing uses.
#[test]
fn nat64_6982_identity_parser_matches_the_build_loop() {
    let cases = vec![
        // accepted
        NAT64RuleSnapshot {
            name: "ok".into(),
            prefix: "64:ff9b::/96".into(),
            pool_addresses: vec!["198.51.100.1".into(), "198.51.100.2/32".into()],
            ..Default::default()
        },
        NAT64RuleSnapshot {
            name: "ok-empty-pool".into(),
            prefix: "64:ff9b::/96".into(),
            pool_addresses: vec![],
            ..Default::default()
        },
        // skipped by the loop
        NAT64RuleSnapshot { name: "empty-prefix".into(), prefix: String::new(), ..Default::default() },
        NAT64RuleSnapshot { name: "no-mask".into(), prefix: "64:ff9b::".into(), ..Default::default() },
        NAT64RuleSnapshot { name: "bad-mask".into(), prefix: "64:ff9b::/64".into(), ..Default::default() },
        NAT64RuleSnapshot { name: "extra-slash".into(), prefix: "64:ff9b::/96/x".into(), ..Default::default() },
        NAT64RuleSnapshot { name: "bad-addr".into(), prefix: "zzz/96".into(), ..Default::default() },
        NAT64RuleSnapshot {
            name: "bad-pool".into(),
            prefix: "64:ff9b::/96".into(),
            pool_addresses: vec!["198.51.100.0/24".into()],
            ..Default::default()
        },
    ];
    for snap in &cases {
        // The loop's verdict: does a single-rule snapshot install a prefix?
        let installed = !Nat64State::from_snapshots(std::slice::from_ref(snap))
            .prefixes
            .is_empty();
        let identified = nat64_rule_identity(snap).is_some();
        assert_eq!(
            identified, installed,
            "rule {:?}: phase-1 identity parser says {identified}, the build loop says \
             {installed}. They must agree, or a rule's reuse is either uncharged (budget \
             hole) or charged while nothing uses it (#6982)",
            snap.name
        );
    }
}

/// #6982: the charge arithmetic saturates rather than wrapping.
///
/// A hand-crafted or HA-peer-synced snapshot can claim an absurd pool
/// cardinality. Wrapping would make a colossal charge look SMALL and be
/// admitted — the over-budget verdict has to be fail-closed.
#[test]
fn nat64_6982_charge_saturates_and_fails_closed() {
    let huge = Nat64AggregateUse {
        prefixes: u64::MAX,
        addresses: u64::MAX,
        port_capacity: u64::MAX,
    };
    let sum = huge.saturating_with(huge);
    assert_eq!(sum.port_capacity, u64::MAX, "must saturate, never wrap");
    assert!(
        Nat64AggregateUse::default()
            .admitted_with(huge, &NAT64_AGGREGATE_BUDGET)
            .is_none(),
        "an absurd charge must be REFUSED, not wrapped into a small one"
    );
    // A single pool address costs the FIXED full port range — there is no
    // narrow-range case on this path, which is what makes NAT64 costlier per
    // address than SNAT.
    assert_eq!(
        nat64_prefix_charge(1).port_capacity,
        (NAT64_PORT_HIGH as u64 - NAT64_PORT_LOW as u64) + 1
    );
    assert_eq!(nat64_prefix_charge(0).port_capacity, 0);
}

/// #6982: the budget's charge and the allocator's own sizing must be ONE
/// formula.
///
/// The SNAT sibling charges through `nat::allocator_capacity`, the same helper
/// `PortAllocator::new` sizes itself with. An open-coded `len * 64512` here
/// would be a second copy of the allocation arithmetic, and a charge that
/// drifts from what is actually allocated is a budget that does not bind — it
/// would admit a prefix whose real bitmap is larger than the slots it was
/// charged for. Asserting the AGREEMENT rather than pinning either side to a
/// literal: a literal here would just be a third copy.
#[test]
fn nat64_6982_charge_uses_the_allocators_own_capacity_formula() {
    for len in [0usize, 1, 2, 7, 250, 65536] {
        assert_eq!(
            nat64_prefix_charge(len).port_capacity,
            crate::nat::allocator_capacity(len, NAT64_PORT_LOW, NAT64_PORT_HIGH) as u64,
            "charge and allocation disagree at pool_len={len}; the budget would not bind"
        );
    }
    // The values are non-trivial, so the agreement above is not two zeros.
    assert!(nat64_prefix_charge(1).port_capacity > 60_000);
}

// --- #7094: the NAT64 rollback path's holder semantics --------------------
//
// `rollback_nat64_allocation_for_worker` had FOUR production call sites
// (install-failure, admission-refusal and two ICMP-error-bounce paths) and not
// one test caller. Its `#[cfg(test)]` `Untracked` twin had no caller either,
// which is what surfaced as a dead-code warning — and the twin's existence made
// the family look covered when the path production actually takes was not
// exercised at all. Deleting the twin without adding this would have closed the
// warning and left that hole exactly where it was.
//
// The property is the one the #6211 F2 guard exists to protect: a rollback
// releases only THIS worker's hold. Every worker that forwarded the flow holds
// the same reservation, so a single-holder release would free a `(pool_v4,
// port)` the siblings are still using — the tuple would then be handed to a
// fresh flow while the original is live, and the 1:N reverse index mis-demuxes
// the replies.

#[test]
fn nat64_7094_rollback_for_worker_frees_only_that_holder() {
    // MULTI-HOLDER STATE COMES FROM THE SYNCED RESERVE, not from two local
    // allocations, and that distinction is why the first version of this cell
    // failed. Two `allocate_source_for_worker` calls for one flow do NOT create
    // two holders: the live-hit path returns the existing translation and gives
    // back the port it just claimed WITHOUT OR-ing in the second worker's bit
    // (allocator.rs, "Idempotent re-entry for an already-allocated flow"). So
    // that fixture had a single holder, the first rollback freeing it was
    // CORRECT, and the assertion was wrong rather than the code.
    //
    // `reserve_flow` is where workers 2..N land — `slot.holders |= holder.bit()`,
    // commented as exactly that — so the HA-synced reservation is the state in
    // which "release only THIS worker's hold" is observable at all.
    let state = Nat64State::from_snapshots(&[single_addr_prefix()]);
    let snat = Ipv4Addr::new(198, 51, 100, 1);
    let dst_v4 = Ipv4Addr::new(8, 8, 8, 8);
    let synced_key = nat64_synced_key("2001:db8::1");
    let synced = Nat64State::forward_decision(snat, dst_v4, 1024);

    assert!(
        reserve_synced_nat64_allocation_for_worker(&state, &synced_key, synced, false, 0, 0),
        "precondition: worker 0 must reserve the synced flow"
    );
    assert!(
        reserve_synced_nat64_allocation_for_worker(&state, &synced_key, synced, false, 0, 1),
        "precondition: worker 1 must join the SAME reservation — this is the \
         early-return path that ORs its holder bit in, and without it there is \
         only one holder and nothing below discriminates"
    );

    // Worker 0 rolls back. Worker 1 still holds it, so the port stays claimed:
    // a fresh, unrelated local flow must NOT be handed 1024.
    rollback_nat64_allocation_for_worker(&state, &synced_key, synced, false, 2, 0);
    let after_first = state
        .allocate_source_for_worker(
            0,
            crate::ip_proto::PROTO_TCP,
            "2001:db8::77".parse().unwrap(),
            dst_v4,
            6000,
            443,
            3,
            0,
            &[],
        )
        .expect("a fresh flow still allocates");
    assert_ne!(
        after_first,
        (snat, 1024),
        "worker 0's rollback freed a reservation worker 1 still holds: {:?} was \
         handed to a fresh flow while the synced one is live. The 1:N reverse \
         index then mis-demuxes the server's replies — the collision #6211 F2 \
         exists to prevent (#7094)",
        after_first
    );

    // The LAST holder lets go. Now the port must come back to the pool.
    rollback_nat64_allocation_for_worker(&state, &synced_key, synced, false, 4, 1);
    assert!(
        reserve_synced_nat64_allocation_for_worker(&state, &synced_key, synced, false, 5, 0),
        "after the last holder rolled back, the same tuple must be reservable \
         again; if this fails the rollback path never frees and the pool leaks a \
         port per rolled-back synced flow"
    );
}

#[test]
fn nat64_7094_rollback_is_a_noop_on_the_reverse_entry() {
    // Mirrors nat64_4381_reverse_entry_release_is_noop for the rollback path:
    // only the FORWARD entry owns the allocation, so a reverse-entry rollback
    // must not release it. Without this, the is_reverse guard could be deleted
    // and the test above would still pass — it only ever passes is_reverse=false.
    let state = Nat64State::from_snapshots(&[single_addr_prefix()]);
    let dst_v4 = Ipv4Addr::new(8, 8, 8, 8);
    let c: Ipv6Addr = "2001:db8::2".parse().unwrap();
    let (snat, pa) = state
        .allocate_source_for_worker(
            0,
            crate::ip_proto::PROTO_TCP,
            c,
            dst_v4,
            6000,
            443,
            1,
            0,
            &[],
        )
        .unwrap();
    let key = crate::session::SessionKey {
        addr_family: libc::AF_INET6 as u8,
        protocol: crate::ip_proto::PROTO_TCP,
        src_ip: IpAddr::V6(c),
        dst_ip: IpAddr::V6("64:ff9b::0808:0808".parse().unwrap()),
        src_port: 6000,
        dst_port: 443,
            discriminator: Default::default(),
            routing_domain: 0,
    };
    rollback_nat64_allocation_for_worker(
        &state,
        &key,
        Nat64State::forward_decision(snat, dst_v4, pa),
        true, // is_reverse
        2,
        0,
    );
    let again = state
        .allocate_source_for_worker(
            0,
            crate::ip_proto::PROTO_TCP,
            c,
            dst_v4,
            6000,
            443,
            3,
            0,
            &[],
        )
        .unwrap();
    assert_eq!(
        again,
        (snat, pa),
        "a REVERSE-entry rollback released the forward entry's allocation; only \
         the forward entry owns it"
    );
}

// ---- #7056 (#5798 required-fix #5): the distinct refused-alias counters ----

fn frag_alias_counts_7056() -> (u64, u64) {
    (
        NAT64_FRAG_CROSS_DOMAIN_MISSES.load(std::sync::atomic::Ordering::Relaxed),
        NAT64_FRAG_PROTOCOL_ALIAS_MISSES.load(std::sync::atomic::Ordering::Relaxed),
    )
}

fn frag_key_7056(protocol: u8, authority: FragAuthority) -> FragKey {
    FragKey {
        addr_family: libc::AF_INET6 as u8,
        src: IpAddr::V6("2001:db8::1".parse().unwrap()),
        dst: IpAddr::V6("64:ff9b::0808:0808".parse().unwrap()),
        ident: 0xfeed,
        protocol,
        authority,
    }
}

/// #7056: a fragment-association miss has several causes with very different
/// meanings, and before this they all landed on the same drop counter. This is
/// the table that separates them, and the MIDDLE ROW is what makes it a test
/// rather than a demonstration: an ordinary miss — no entry at all — must count
/// as NEITHER. A classifier that simply counted every miss would satisfy the two
/// interesting rows and fail this one.
#[test]
fn refused_alias_misses_are_counted_distinctly_7056() {
    let decision = frag_test_decision(Nat64State::forward_decision(
        Ipv4Addr::new(198, 51, 100, 1),
        Ipv4Addr::new(8, 8, 8, 8),
        5000,
    ));

    // (1) CROSS-DOMAIN: installed under one authority, consulted under another.
    let cache = FragAssoc::new();
    cache.install(
        frag_key_7056(PROTO_UDP, frag_test_authority()),
        decision,
        None,
        1_000,
        1,
        0,
    );
    let (x0, p0) = frag_alias_counts_7056();
    let hit = cache.lookup(
        &frag_key_7056(PROTO_UDP, frag_other_authority()),
        2_000,
        1,
        |_| true,
    );
    let (x1, p1) = frag_alias_counts_7056();
    assert!(
        hit.is_none(),
        "precondition: a cross-domain consult must MISS (the #5798 fail-closed \
         behaviour); if it hits, this test is measuring the wrong thing"
    );
    assert_eq!(
        (x1 - x0, p1 - p0),
        (1, 0),
        "a cross-domain refusal must advance the CROSS-DOMAIN counter and only \
         that one — it is the one miss cause that describes the traffic rather \
         than cache pressure (#7056)"
    );

    // (2) PROTOCOL ALIAS: same authority, TCP vs UDP on one (src, dst, ident).
    let cache = FragAssoc::new();
    cache.install(
        frag_key_7056(PROTO_UDP, frag_test_authority()),
        decision,
        None,
        1_000,
        1,
        0,
    );
    let (x0, p0) = frag_alias_counts_7056();
    let hit = cache.lookup(
        &frag_key_7056(PROTO_TCP, frag_test_authority()),
        2_000,
        1,
        |_| true,
    );
    let (x1, p1) = frag_alias_counts_7056();
    assert!(hit.is_none(), "precondition: a protocol-aliased consult must MISS");
    assert_eq!(
        (x1 - x0, p1 - p0),
        (0, 1),
        "a protocol-alias refusal must advance the PROTOCOL counter and only that \
         one. Folding the two into a single \"alias refused\" total would answer \
         neither operator question: cross-domain means another security domain's \
         association was probed, protocol-alias means TCP and UDP collided on \
         (src, dst, ident) (#7056)"
    );

    // (3) THE MIDDLE ROW — an ordinary miss, no entry at all. Neither counter.
    let cache = FragAssoc::new();
    let (x0, p0) = frag_alias_counts_7056();
    let hit = cache.lookup(
        &frag_key_7056(PROTO_UDP, frag_test_authority()),
        2_000,
        1,
        |_| true,
    );
    let (x1, p1) = frag_alias_counts_7056();
    assert!(hit.is_none(), "precondition: an empty cache must miss");
    assert_eq!(
        (x1 - x0, p1 - p0),
        (0, 0),
        "an ORDINARY miss — reorder, TTL straddle, eviction, cold cache — must \
         advance NEITHER counter. This is the row that distinguishes a real \
         classifier from one that counts every miss, and counting every miss is \
         exactly the lumping #7056 exists to undo"
    );

    // (4) A HIT must not count either, or the counters measure consult volume.
    let cache = FragAssoc::new();
    let key = frag_key_7056(PROTO_UDP, frag_test_authority());
    cache.install(key, decision, None, 1_000, 1, 0);
    let (x0, p0) = frag_alias_counts_7056();
    let hit = cache.lookup(&key, 2_000, 1, |_| true);
    let (x1, p1) = frag_alias_counts_7056();
    assert!(hit.is_some(), "precondition: the matching consult must HIT");
    assert_eq!(
        (x1 - x0, p1 - p0),
        (0, 0),
        "a HIT must advance neither counter"
    );
}

/// #7056: the classification must survive the entry it is classifying against
/// being evicted for an unrelated reason. A config-generation bump evicts the
/// entry and returns a miss BEFORE the alias scan would run, so that miss is a
/// generation miss — not a refused alias — even though the stale entry differed
/// in authority too.
///
/// Without this, the classifier could attribute every generation-fenced miss to
/// cross-domain aliasing on a box that had simply committed a config change,
/// which is the false-positive direction: it would make the one counter that is
/// supposed to mean "something is probing another domain" fire on an ordinary
/// commit.
#[test]
fn a_generation_fenced_miss_is_not_reported_as_an_alias_7056() {
    let decision = frag_test_decision(Nat64State::forward_decision(
        Ipv4Addr::new(198, 51, 100, 1),
        Ipv4Addr::new(8, 8, 8, 8),
        5000,
    ));
    let cache = FragAssoc::new();
    cache.install(
        frag_key_7056(PROTO_UDP, frag_test_authority()),
        decision,
        None,
        1_000,
        1, // generation 1
        0,
    );
    let (x0, p0) = frag_alias_counts_7056();
    // SAME key, but the config generation moved on.
    let hit = cache.lookup(
        &frag_key_7056(PROTO_UDP, frag_test_authority()),
        2_000,
        2, // generation 2
        |_| true,
    );
    let (x1, p1) = frag_alias_counts_7056();
    assert!(hit.is_none(), "precondition: a stale-generation entry must miss");
    assert_eq!(
        (x1 - x0, p1 - p0),
        (0, 0),
        "a CONFIG-GENERATION miss must not be reported as a refused alias — it is \
         an ordinary commit invalidating the cache, and attributing it to \
         cross-domain probing would make that counter fire on every config \
         change (#7056)"
    );
}

// ---------------------------------------------------------------------------
// #9128 / #9129: an ICMP error's QUOTED packet must keep its fragmentation
// fields across the embedded translation.
//
// Both directions had the same defect from opposite ends. v6->v4 wrote
// `ID=0, DF=1` over whatever the quote said; v4->v6 never emitted an IPv6
// Fragment Header at all, so the translated quote described an unfragmented
// datagram that was never sent.
//
// Scope, stated because it is what makes these Low rather than High: a
// non-first fragment is refused upstream in BOTH directions -- by
// `ipv6_is_non_first_fragment` (#2290) going v6->v4, and by `parse_embedded_v4`
// (#1852) going v4->v6. Those guards filter on OFFSET, so an `MF=1, offset=0`
// FIRST fragment passes and is the reachable case. The fix copies the offset
// anyway so neither arm is correct only by virtue of a guard somewhere else.
// ---------------------------------------------------------------------------

/// A quoted IPv6 packet with an optional Fragment Header, carrying a UDP header.
fn quoted_v6_9128(frag: Option<(u32, u16, bool)>) -> Vec<u8> {
    let mut q = vec![0u8; 40];
    q[0] = 0x60;
    q[7] = 64; // hop limit
    q[8..24].copy_from_slice(&Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).octets());
    q[24..40].copy_from_slice(&Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, 0x0a00, 0x0001).octets());
    let udp = [0x30u8, 0x39, 0x00, 0x50, 0x00, 0x08, 0x00, 0x00];
    match frag {
        Some((ident, offset_units, more)) => {
            q[6] = 44; // next header = Fragment
            let mut fh = vec![0u8; 8];
            fh[0] = PROTO_UDP;
            let w = (offset_units << 3) | u16::from(more);
            fh[2..4].copy_from_slice(&w.to_be_bytes());
            fh[4..8].copy_from_slice(&ident.to_be_bytes());
            q.extend_from_slice(&fh);
            q.extend_from_slice(&udp);
            let plen = (8 + udp.len()) as u16;
            q[4..6].copy_from_slice(&plen.to_be_bytes());
        }
        None => {
            q[6] = PROTO_UDP;
            q.extend_from_slice(&udp);
            q[4..6].copy_from_slice(&(udp.len() as u16).to_be_bytes());
        }
    }
    q
}

fn embed_map_v6_to_v4_9128() -> EmbeddedV6ToV4 {
    EmbeddedV6ToV4 {
        mapped_embedded_src: Ipv4Addr::new(192, 0, 2, 1),
        mapped_embedded_dst: Ipv4Addr::new(10, 0, 0, 1),
        mapped_embedded_dst_port: None,
    }
}

#[test]
fn embedded_v6_to_v4_carries_the_quoted_fragmentation_9128() {
    let mut out = [0u8; MAX_EMBEDDED_LEN];

    // REFERENCE ARM. An UNFRAGMENTED quote must stay byte-identical to the
    // pre-fix behaviour: ID 0, DF set. Without this the fragmented assertion
    // below could pass against a translator that simply copies garbage.
    let plain = quoted_v6_9128(None);
    let n = translate_embedded_v6_to_v4(&mut out, &plain, &embed_map_v6_to_v4_9128())
        .expect("unfragmented quote must translate");
    assert_eq!(&out[4..6], &[0, 0], "unfragmented quote must keep ID 0");
    assert_eq!(
        u16::from_be_bytes([out[6], out[7]]),
        0x4000,
        "unfragmented quote must keep DF=1, MF=0, offset=0"
    );
    assert!(n >= 20);

    // THE DEFECT: a FIRST fragment (offset 0, M=1). ID and MF were discarded.
    let frag = quoted_v6_9128(Some((0xDEAD_BEEF, 0, true)));
    translate_embedded_v6_to_v4(&mut out, &frag, &embed_map_v6_to_v4_9128())
        .expect("first-fragment quote must translate");
    assert_eq!(
        u16::from_be_bytes([out[4], out[5]]),
        0xBEEF,
        "RFC 7915 5.1: Identification comes from the low 16 bits of the Fragment Header"
    );
    let w = u16::from_be_bytes([out[6], out[7]]);
    assert_eq!(w & 0x4000, 0, "DF must be CLEARED for a fragmented quote");
    assert_eq!(w & 0x2000, 0x2000, "M flag must be copied to MF");
    assert_eq!(w & 0x1FFF, 0, "a first fragment's offset is 0");

    // NARROWNESS: the offset is copied, not synthesized. A guard upstream keeps
    // offset != 0 from reaching here; this arm must not DEPEND on that.
    let deep = quoted_v6_9128(Some((1, 5, false)));
    if translate_embedded_v6_to_v4(&mut out, &deep, &embed_map_v6_to_v4_9128()).is_some() {
        assert_eq!(
            u16::from_be_bytes([out[6], out[7]]) & 0x1FFF,
            5,
            "if a non-first quote ever reaches this arm its offset must be copied"
        );
    }
}

/// A quoted IPv4 packet with the given fragmentation word, carrying a UDP header.
fn quoted_v4_9129(ident: u16, offset_units: u16, more: bool) -> Vec<u8> {
    let udp = [0x30u8, 0x39, 0x00, 0x50, 0x00, 0x08, 0x00, 0x00];
    let mut q = vec![0u8; 20];
    q[0] = 0x45;
    q[2..4].copy_from_slice(&((20 + udp.len()) as u16).to_be_bytes());
    q[4..6].copy_from_slice(&ident.to_be_bytes());
    let w = (offset_units & 0x1FFF) | if more { 0x2000 } else { 0 };
    q[6..8].copy_from_slice(&w.to_be_bytes());
    q[8] = 64;
    q[9] = PROTO_UDP;
    q[12..16].copy_from_slice(&Ipv4Addr::new(192, 0, 2, 1).octets());
    q[16..20].copy_from_slice(&Ipv4Addr::new(10, 0, 0, 1).octets());
    q.extend_from_slice(&udp);
    q
}

fn embed_map_v4_to_v6_9129() -> EmbeddedV4ToV6 {
    let mut prefix_bytes = [0u8; 12];
    prefix_bytes[..4].copy_from_slice(&[0x00, 0x64, 0xff, 0x9b]);
    EmbeddedV4ToV6 {
        mapped_embedded_src: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
        prefix_bytes,
        mapped_embedded_src_port: None,
    }
}

#[test]
fn embedded_v4_to_v6_emits_a_fragment_header_9129() {
    let mut out = [0u8; MAX_EMBEDDED_LEN];

    // REFERENCE ARM. An UNFRAGMENTED quote must be byte-identical to before:
    // no Fragment Header, next-header is the real protocol, L4 at offset 40.
    let plain = quoted_v4_9129(0x1234, 0, false);
    let n = translate_embedded_v4_to_v6(&mut out, &plain, &embed_map_v4_to_v6_9129())
        .expect("unfragmented quote must translate");
    assert_eq!(out[6], PROTO_UDP, "no Fragment Header for an unfragmented quote");
    assert_eq!(n, 48, "40-byte IPv6 header + 8-byte UDP header");
    assert_eq!(&out[40..42], &[0x30, 0x39], "L4 must still start at offset 40");

    // THE DEFECT: a FIRST fragment (MF=1, offset=0) passed the upstream offset
    // filter and lost its ID and M flag entirely, because no Fragment Header
    // was emitted.
    let frag = quoted_v4_9129(0x1234, 0, true);
    let n = translate_embedded_v4_to_v6(&mut out, &frag, &embed_map_v4_to_v6_9129())
        .expect("first-fragment quote must translate");
    assert_eq!(out[6], 44, "base next-header must chain the Fragment Header");
    assert_eq!(out[40], PROTO_UDP, "Fragment Header carries the real protocol");
    let w = u16::from_be_bytes([out[42], out[43]]);
    assert_eq!(w & 0x0001, 1, "M flag must mirror IPv4 MF");
    assert_eq!(w >> 3, 0, "a first fragment's offset is 0");
    assert_eq!(
        u32::from_be_bytes([out[44], out[45], out[46], out[47]]),
        0x1234,
        "RFC 7915 4: the IPv4 16-bit ID is zero-extended to 32 bits"
    );
    assert_eq!(n, 56, "the Fragment Header adds 8 bytes");
    assert_eq!(
        u16::from_be_bytes([out[4], out[5]]) as usize,
        8 + 8,
        "payload length must count the Fragment Header"
    );
    assert_eq!(&out[48..50], &[0x30, 0x39], "L4 must shift past the Fragment Header");
}

#[test]
fn embedded_v4_to_v6_fragment_header_shortens_rather_than_drops_9129() {
    // The Fragment Header costs 8 bytes the scratch was not sized for: a
    // maximal quote already lands exactly on MAX_EMBEDDED_LEN. Growing past it
    // would make the bounds check fail and DROP the ICMP error, turning an
    // unfaithful translation into a missing one -- a worse outcome than the
    // defect being fixed. The quote must be shortened instead.
    let mut q = quoted_v4_9129(0x4321, 0, true);
    let pad = MAX_EMBEDDED_LEN; // far past any budget
    q.extend(std::iter::repeat(0xAA).take(pad));
    let total = q.len() as u16;
    q[2..4].copy_from_slice(&total.to_be_bytes());

    let mut out = [0u8; MAX_EMBEDDED_LEN];
    let n = translate_embedded_v4_to_v6(&mut out, &q, &embed_map_v4_to_v6_9129())
        .expect("an oversized fragmented quote must still translate, shortened");
    assert!(n <= MAX_EMBEDDED_LEN, "must fit the scratch, got {n}");
    assert_eq!(out[6], 44, "and must still carry the Fragment Header");
    assert_eq!(
        u32::from_be_bytes([out[44], out[45], out[46], out[47]]),
        0x4321,
        "the identification survives the shortening"
    );
}

/// #9555 PREMISE for the Go #5144 NAT64 owner model (`nat64ShadowedRuleSets`).
///
/// Go now treats a later NAT64 rule-set under the same /96 as unreachable and not
/// an allocator owner. That is sound ONLY while the dataplane (1) selects the FIRST
/// built rule-set in SNAPSHOT order and (2) skips a rule-set whole when a pool
/// member fails `parse_pool_v4`, so a skipped rule-set shadows nothing. If either
/// changes, the Go gate's reasoning is stale, and this is where that shows up.
#[test]
fn nat64_selects_the_first_built_rule_set_for_a_shared_prefix_9555() {
    let first = NAT64RuleSnapshot {
        name: "Z".to_string(),
        prefix: "64:ff9b::/96".to_string(),
        pool_addresses: vec!["100.64.0.7".to_string()],
        no_v6_frag_header: false,
        ..Default::default()
    };
    let second = NAT64RuleSnapshot {
        name: "A".to_string(),
        pool_addresses: vec!["100.64.0.8".to_string()],
        ..first.clone()
    };
    let dst: std::net::Ipv6Addr = "64:ff9b::808:808".parse().unwrap();

    let state = Nat64State::from_snapshots(&[first.clone(), second.clone()]);
    assert_eq!(state.prefixes.len(), 2, "both same-prefix rule-sets are built");
    let (idx, _) = state.match_ipv6_dest(dst).expect("the shared prefix matches");
    assert_eq!(
        state.prefixes[idx].pool_v4,
        vec![std::net::Ipv4Addr::new(100, 64, 0, 7)],
        "#9555 premise (1): the FIRST rule-set in snapshot order is selected -- not the one \
         that sorts first by name (\"A\")"
    );

    let skipped = NAT64RuleSnapshot {
        pool_addresses: vec!["100.65.0.0/24".to_string()],
        ..first
    };
    let state2 = Nat64State::from_snapshots(&[skipped, second]);
    assert_eq!(
        state2.prefixes.len(),
        1,
        "#9555 premise (2): a rule-set with a non-host pool member is skipped WHOLE (#3888)"
    );
    let (idx2, _) = state2.match_ipv6_dest(dst).expect("the later rule-set now matches");
    assert_eq!(
        state2.prefixes[idx2].pool_v4,
        vec![std::net::Ipv4Addr::new(100, 64, 0, 8)],
        "#9555 premise (2): a skipped earlier rule-set shadows nothing"
    );
}
