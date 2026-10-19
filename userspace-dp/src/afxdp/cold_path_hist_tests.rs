use super::*;

// #1620 plan v4: pin the cacheline-0 layout of
// WorkerColdPathCounters so a future field reorder is caught
// by the test suite, not by a regression in the cold-path-flooder
// microbench. v4 absorbs AGY r3 [HIGH-1] (sample_phase published)
// + AXIS-6 diagnostic (wrapper_underflow_count).
#[test]
fn worker_cold_path_counters_hot_fields_fit_in_cacheline_0() {
    use std::mem::offset_of;
    // Hot fields declared first; ClockSource is #[repr(u8)] so
    // its size is 1 byte and the offset math is deterministic.
    assert_eq!(offset_of!(WorkerColdPathCounters, sample_phase), 0);
    assert_eq!(offset_of!(WorkerColdPathCounters, ns_per_tsc_q32), 8);
    assert_eq!(offset_of!(WorkerColdPathCounters, wrapper_ns_baseline), 16);
    assert_eq!(
        offset_of!(WorkerColdPathCounters, wrapper_underflow_count),
        24
    );
    assert_eq!(offset_of!(WorkerColdPathCounters, clock_source), 32);
    // #1635: builder_collision [bool; 256] alignment 1: lives at
    // [33..289], no padding. All hot reads (sample_phase ..
    // clock_source) still land in cacheline 0 ([0..63]).
    assert_eq!(offset_of!(WorkerColdPathCounters, builder_collision), 33);
    // first_key [u64; 256] alignment 8: padded from 33+256=289 to 296.
    assert_eq!(offset_of!(WorkerColdPathCounters, first_key), 296);
}

#[test]
fn worker_cold_path_atomics_hot_fields_at_top() {
    use std::mem::{align_of, offset_of};
    // align(64) preserved from #1619.
    assert_eq!(align_of::<WorkerColdPathAtomics>(), 64);
    // Hot fields at top — cacheline 0. v2 (#1621) inserts the
    // snapshot_failed counter at offset 8 between cold_window_gen
    // and sample_phase so the reader-thread Counter sits in
    // cacheline 0 alongside the seqlock gen it accompanies.
    assert_eq!(offset_of!(WorkerColdPathAtomics, cold_window_gen), 0);
    assert_eq!(offset_of!(WorkerColdPathAtomics, snapshot_failed), 8);
    assert_eq!(offset_of!(WorkerColdPathAtomics, sample_phase), 16);
    assert_eq!(offset_of!(WorkerColdPathAtomics, ns_per_tsc_q32), 24);
    assert_eq!(offset_of!(WorkerColdPathAtomics, wrapper_ns_baseline), 32);
    assert_eq!(
        offset_of!(WorkerColdPathAtomics, wrapper_underflow_count),
        40
    );
    assert_eq!(offset_of!(WorkerColdPathAtomics, clock_source), 48);
}

/// #1620 plan v4 (AGY r3 [HIGH-1]): publish_from_local /
/// snapshot must round-trip sample_phase + wrapper_underflow_count.
#[test]
fn sample_phase_and_underflow_round_trip_through_publish_snapshot() {
    let atomics = WorkerColdPathAtomics::new();
    let mut local = WorkerColdPathCounters::default();
    local.sample_phase = 12345;
    local.wrapper_underflow_count = 7;
    atomics.publish_from_local(&local);
    let snap = atomics.snapshot().expect("snapshot must succeed");
    assert_eq!(snap.sample_phase, 12345);
    assert_eq!(snap.wrapper_underflow_count, 7);
}

// === #1635 log-linear 48-bucket layout ===

#[test]
fn bucket_index_for_ns_48_linear_band() {
    // Linear band: 16-ns stride, indices [0, 32).
    assert_eq!(bucket_index_for_ns_48(0), 0);
    assert_eq!(bucket_index_for_ns_48(15), 0);
    assert_eq!(bucket_index_for_ns_48(16), 1);
    assert_eq!(bucket_index_for_ns_48(31), 1);
    assert_eq!(bucket_index_for_ns_48(100), 6); // 100/16 = 6
    assert_eq!(bucket_index_for_ns_48(496), 31);
    assert_eq!(bucket_index_for_ns_48(511), 31);
}

#[test]
fn bucket_index_for_ns_48_pivots_at_512() {
    assert_eq!(bucket_index_for_ns_48(511), 31, "last linear bucket");
    assert_eq!(bucket_index_for_ns_48(512), 32, "first exponential bucket");
}

#[test]
fn bucket_index_for_ns_48_exponential_band() {
    // bucket 32 covers [512, 1024); 33 covers [1024, 2048); ...
    assert_eq!(bucket_index_for_ns_48(512), 32);
    assert_eq!(bucket_index_for_ns_48(1023), 32);
    assert_eq!(bucket_index_for_ns_48(1024), 33);
    assert_eq!(bucket_index_for_ns_48(2047), 33);
    assert_eq!(bucket_index_for_ns_48(2048), 34);
    // i=14 → bucket 46 covers [2^23, 2^24).
    assert_eq!(bucket_index_for_ns_48(1u64 << 23), 46);
    assert_eq!(bucket_index_for_ns_48((1u64 << 24) - 1), 46);
}

#[test]
fn bucket_index_for_ns_48_saturates() {
    // ns ≥ 2^24 lands in bucket 47.
    assert_eq!(bucket_index_for_ns_48(1u64 << 24), 47);
    assert_eq!(bucket_index_for_ns_48(1u64 << 33), 47);
    assert_eq!(bucket_index_for_ns_48(u64::MAX), 47);
}

#[test]
fn bucket_upper_bound_ns_48_matches_layout() {
    // Linear band inclusive upper boundaries.
    assert_eq!(bucket_upper_bound_ns_48(0), 15);
    assert_eq!(bucket_upper_bound_ns_48(1), 31);
    assert_eq!(bucket_upper_bound_ns_48(31), 511);
    // Exponential band.
    assert_eq!(bucket_upper_bound_ns_48(32), 1023);
    assert_eq!(bucket_upper_bound_ns_48(33), 2047);
    assert_eq!(bucket_upper_bound_ns_48(46), (1u64 << 24) - 1);
    // Saturate bucket.
    assert_eq!(bucket_upper_bound_ns_48(47), u64::MAX);
}

/// Consumer criterion (#1622 F1 / plan §X): a 10-rule cold-path
/// distribution centered at ~50-150 ns must read back a p50 within
/// 2× of truth, NOT collapsed to the old bucket-0 512-ns midpoint.
/// This test FAILS on the old 24-bucket pow-2-from-0 layout (which
/// puts all of [0,1024) ns into one bucket whose midpoint is 512)
/// and PASSES on the new log-linear layout.
#[test]
fn bucket_layout_resolves_low_end_within_2x() {
    // For each true latency, the bucket's INCLUSIVE upper bound is
    // the worst-case reported value for a histogram_quantile read
    // landing in that bucket. Assert it is within 2× of truth (and
    // that the lower edge is ≥ truth/2), i.e. relative error ≤ 1.0.
    for truth in [50u64, 75, 100, 125, 150, 1000, 5000, 50000] {
        let idx = bucket_index_for_ns_48(truth);
        let upper = bucket_upper_bound_ns_48(idx);
        let lower = if idx == 0 {
            0
        } else {
            bucket_upper_bound_ns_48(idx - 1) + 1
        };
        // Reported value (bucket boundary) within 2× of truth.
        assert!(
            upper <= truth.saturating_mul(2),
            "truth={truth} upper={upper} exceeds 2x (idx={idx})"
        );
        assert!(
            lower <= truth,
            "truth={truth} lower={lower} above truth (idx={idx})"
        );
    }
}

/// Adversarial demonstration that the OLD pow-2-from-0 layout
/// FAILS the consumer criterion the new layout passes: a true
/// 100 ns p50 reads as 1023 ns (>10× error) under the old bucket-0.
#[test]
fn old_pow2_layout_would_fail_low_end_resolution() {
    // Re-implement the retired 24-bucket formula inline to prove
    // the regression it caused.
    fn old_bucket_index_for_ns_24(ns: u64) -> usize {
        let clz = (ns | 1).leading_zeros() as i32;
        let b = (54 - clz).max(0) as usize;
        b.min(23)
    }
    // 50, 100, 150 ns all collapse into old bucket 0 = [0, 1024).
    assert_eq!(old_bucket_index_for_ns_24(50), 0);
    assert_eq!(old_bucket_index_for_ns_24(100), 0);
    assert_eq!(old_bucket_index_for_ns_24(150), 0);
    // Old bucket-0 upper bound is 1023 ns ⇒ a true 100 ns p50
    // reads up to 1023 ns: > 10× error. The new layout keeps it
    // ≤ 2× (covered by bucket_layout_resolves_low_end_within_2x).
    let old_upper = 1023u64;
    assert!(old_upper > 100 * 2, "old layout error must exceed 2x");
    // New layout: 100 ns → bucket 6 → upper 111 ns ⇒ 1.11×.
    assert_eq!(bucket_index_for_ns_48(100), 6);
    assert_eq!(bucket_upper_bound_ns_48(6), 111);
}

// === #1635 direct slot map ===

#[test]
fn direct_slot_map_assigns_sequential() {
    let pairs = [(1u16, 2u16), (3, 4), (5, 6), (7, 8), (9, 10)];
    let (map, zeroed) = ColdPathSlotMap::build(None, &pairs);
    assert!(zeroed.is_empty(), "fresh build zeroes nothing");
    // Sorted/dedup input ⇒ slots assigned 0..5 in pair order.
    for (i, &(from, to)) in pairs.iter().enumerate() {
        assert_eq!(
            lookup_slot(&map, from, to),
            Some(i as u8),
            "pair {from}->{to}"
        );
        assert_eq!(map.inverse[i], Some((from, to)));
    }
    assert!(!map.overflow_active);
}

#[test]
fn direct_slot_map_no_collisions_at_capacity() {
    // 255 distinct in-range pairs ⇒ unique slots [0,255), no
    // overflow. (Slot 255 is reserved as the u8::MAX sentinel.)
    let mut pairs = Vec::new();
    'outer: for from in 0u16..8 {
        for to in 0u16..32 {
            pairs.push((from, to));
            if pairs.len() == COLD_PATH_ASSIGNABLE_SLOTS {
                break 'outer;
            }
        }
    }
    assert_eq!(pairs.len(), 255);
    let (map, _) = ColdPathSlotMap::build(None, &pairs);
    assert!(!map.overflow_active);
    let mut seen = std::collections::HashSet::new();
    for &(from, to) in &pairs {
        let s = lookup_slot(&map, from, to).expect("all 255 pairs assigned");
        assert!(s != u8::MAX, "slot 255 sentinel must never be handed out");
        assert!(seen.insert(s), "slot {s} assigned twice");
    }
    assert_eq!(seen.len(), 255);
}

#[test]
fn direct_slot_map_overflow_past_capacity() {
    // 256 in-range pairs: one more than the 255 assignable slots.
    let mut pairs = Vec::new();
    'outer: for from in 0u16..16 {
        for to in 0u16..17 {
            pairs.push((from, to));
            if pairs.len() == 256 {
                break 'outer;
            }
        }
    }
    assert_eq!(pairs.len(), 256);
    let (map, _) = ColdPathSlotMap::build(None, &pairs);
    assert!(
        map.overflow_active,
        "the 256th pair must overflow the 255-slot capacity"
    );
    // Exactly 255 slots occupied.
    let occupied = map.inverse.iter().filter(|s| s.is_some()).count();
    assert_eq!(occupied, 255);
}

#[test]
fn direct_slot_map_immediate_reuse_after_removal_zeros_atomics() {
    // Build A with {(1,2),(3,4)}; record into both.
    let pairs_a = [(1u16, 2u16), (3, 4)];
    let (map_a, _) = ColdPathSlotMap::build(None, &pairs_a);
    let slot_34 = lookup_slot(&map_a, 3, 4).unwrap();
    // Build B with {(1,2),(5,6)} — drop (3,4), add (5,6).
    let pairs_b = [(1u16, 2u16), (5, 6)];
    let (map_b, zeroed) = ColdPathSlotMap::build(Some(&map_a), &pairs_b);
    // (1,2) retains its slot; (5,6) takes the freed (3,4) slot.
    assert_eq!(lookup_slot(&map_b, 1, 2), lookup_slot(&map_a, 1, 2));
    let slot_56 = lookup_slot(&map_b, 5, 6).unwrap();
    assert_eq!(slot_56, slot_34, "reused freed slot");
    assert_eq!(lookup_slot(&map_b, 3, 4), None, "(3,4) no longer mapped");
    // The reused slot is queued for zero-out.
    assert!(zeroed.contains(&slot_56), "reused slot must be zeroed");

    // Verify zero_slot actually clears local + atomic accumulators.
    let mut local = WorkerColdPathCounters::default();
    local.record_sample(slot_34, 3, 4, 5000);
    assert_eq!(local.samples[slot_34 as usize], 1);
    local.zero_slot(slot_34 as usize);
    assert_eq!(local.samples[slot_34 as usize], 0);
    assert_eq!(local.sum_ns[slot_34 as usize], 0);
    assert_eq!(local.first_key[slot_34 as usize], 0);

    let atomics = WorkerColdPathAtomics::new();
    let mut l2 = WorkerColdPathCounters::default();
    l2.record_sample(slot_34, 3, 4, 5000);
    atomics.publish_from_local(&l2);
    atomics.zero_slot(slot_34 as usize);
    let snap = atomics.snapshot().expect("snapshot");
    assert_eq!(snap.samples[slot_34 as usize], 0);
}

#[test]
fn direct_slot_map_retains_assignment_for_surviving_pairs() {
    let pairs_a = [(1u16, 2u16), (3, 4), (5, 6)];
    let (map_a, _) = ColdPathSlotMap::build(None, &pairs_a);
    // Add a new pair; all original pairs survive.
    let pairs_b = [(1u16, 2u16), (3, 4), (5, 6), (7, 8)];
    let (map_b, zeroed) = ColdPathSlotMap::build(Some(&map_a), &pairs_b);
    for &(from, to) in &pairs_a {
        assert_eq!(
            lookup_slot(&map_b, from, to),
            lookup_slot(&map_a, from, to),
            "surviving pair {from}->{to} kept its slot"
        );
        // Retained pairs must NOT be zeroed (keep their histogram).
        let s = lookup_slot(&map_b, from, to).unwrap();
        assert!(
            !zeroed.contains(&s),
            "retained pair {from}->{to} (slot {s}) must NOT be zeroed"
        );
    }
    // (7,8) is a NEW pair ⇒ its slot IS queued for zero-out (every
    // newly-assigned slot is zeroed per Codex finding 1).
    let slot_78 = lookup_slot(&map_b, 7, 8).expect("(7,8) assigned");
    assert!(
        zeroed.contains(&slot_78),
        "new pair (7,8) slot {slot_78} must be zeroed; zeroed={zeroed:?}"
    );
}

#[test]
fn build_assigns_slots_for_wide_stable_hash_zone_ids() {
    // #3075: zone ids are stable name-hashes spanning [1,65533], NOT
    // the old sequential 1..=64. A pair with an id >= 65 (e.g. 300,
    // 40000) MUST get a slot — the old 65×65 flat table dropped every
    // such pair, silently dark-ing the #1635 cold-path histogram for
    // every real config. RED-on-revert: against the fixed-65 table
    // these lookups return None and overflow_active is true.
    let pairs = [(300u16, 400u16), (40000, 1), (1, 65533), (65533, 65533)];
    let (map, _) = ColdPathSlotMap::build(None, &pairs);
    for &(from, to) in &pairs {
        assert!(
            lookup_slot(&map, from, to).is_some(),
            "wide stable-hash pair {from}->{to} must get a slot"
        );
    }
    assert!(
        !map.overflow_active,
        "wide ids must NOT trip overflow (overflow is now slot-capacity only)"
    );
    // Distinct wide pairs get distinct slots.
    assert_ne!(lookup_slot(&map, 300, 400), lookup_slot(&map, 40000, 1));
    // An unmapped wide pair still misses.
    assert_eq!(lookup_slot(&map, 12345, 54321), None);
}

#[test]
fn build_assigns_slots_for_zone_ids_up_to_64() {
    // Regression for Codex code-r1 finding 2 (ids 32-63 dropped at
    // ceiling 32) AND Copilot code-r2 (id 64 dropped at exclusive
    // ceiling 64). The 1-based MAX_ZONES=64 means the 64th zone has
    // id 64; it MUST get a slot.
    let pairs = [(32u16, 33u16), (63, 1), (1, 63), (64, 64), (1, 64), (64, 1)];
    let (map, _) = ColdPathSlotMap::build(None, &pairs);
    for &(from, to) in &pairs {
        assert!(
            lookup_slot(&map, from, to).is_some(),
            "in-range pair {from}->{to} must get a slot"
        );
    }
    assert!(!map.overflow_active);
    // (64,64) and (1,2)-style pairs must not collide.
    assert_ne!(lookup_slot(&map, 64, 64), lookup_slot(&map, 1, 64));
    assert_ne!(lookup_slot(&map, 1, 64), lookup_slot(&map, 64, 1));
}

#[test]
fn lookup_slot_returns_none_for_unmapped_pair() {
    let (map, _) = ColdPathSlotMap::build(None, &[(1u16, 2u16)]);
    assert_eq!(lookup_slot(&map, 9, 9), None);
}

// === #3783: wildcard / global-only policy histogram slot coverage ===

/// A deployment whose ONLY policies are `from-zone any to-zone <z>` and a
/// `security policies global` rule produces ZERO exact zone-pair entries.
/// The cold-path recorder keys on the CONCRETE ingress/egress zone-ids a
/// packet traverses (`poll_descriptor::lookup_slot`), so before #3783 the
/// slot map had no slot for `(trust, untrust)` and the first-packet
/// latency sample was silently dropped. This drives the real pipeline
/// (`parse_policy_state` → `configured_zone_pairs` → `ColdPathSlotMap`) and
/// asserts the concrete pairs the wildcard/global tiers match DO resolve a
/// slot. RED on revert: the pre-#3783 `configured_zone_pairs` returns the
/// empty exact set, so every `lookup_slot` below returns `None`.
#[test]
fn cold_path_slot_assigned_for_wildcard_and_global_only_policy() {
    use crate::protocol::PolicyRuleSnapshot;
    use rustc_hash::FxHashMap;

    const TRUST: u16 = crate::test_zone_ids::TEST_TRUST_ZONE_ID;
    const UNTRUST: u16 = crate::test_zone_ids::TEST_UNTRUST_ZONE_ID;
    const DMZ: u16 = crate::test_zone_ids::TEST_DMZ_ZONE_ID;

    let mut zone_name_to_id: FxHashMap<String, u16> = FxHashMap::default();
    zone_name_to_id.insert("trust".to_string(), TRUST);
    zone_name_to_id.insert("untrust".to_string(), UNTRUST);
    zone_name_to_id.insert("dmz".to_string(), DMZ);

    let rules = vec![
        // from-zone any to-zone untrust — single-wildcard tier, no exact pair.
        PolicyRuleSnapshot {
            name: "wild-out".to_string(),
            from_zone: "any".to_string(),
            to_zone: "untrust".to_string(),
            source_addresses: vec!["any".to_string()],
            destination_addresses: vec!["any".to_string()],
            applications: vec!["any".to_string()],
            action: "permit".to_string(),
            ..Default::default()
        },
        // Unscoped junos-global permit — matches every concrete pair.
        PolicyRuleSnapshot {
            name: "glob".to_string(),
            from_zone: "junos-global".to_string(),
            to_zone: "junos-global".to_string(),
            source_addresses: vec!["any".to_string()],
            destination_addresses: vec!["any".to_string()],
            applications: vec!["any".to_string()],
            action: "permit".to_string(),
            ..Default::default()
        },
    ];

    let state = crate::policy::parse_policy_state("deny", &rules, &zone_name_to_id);
    let pairs = state.configured_zone_pairs();
    let (map, zeroed) = ColdPathSlotMap::build(None, &pairs);
    assert!(zeroed.is_empty(), "fresh build zeroes nothing");

    // trust->untrust: matched by BOTH the from-any and the global rule.
    assert!(
        lookup_slot(&map, TRUST, UNTRUST).is_some(),
        "trust->untrust (wildcard + global) must have a cold-path slot"
    );
    // dmz->trust: matched ONLY by the unscoped global.
    assert!(
        lookup_slot(&map, DMZ, TRUST).is_some(),
        "dmz->trust (global-only) must have a cold-path slot"
    );
    // untrust->untrust intrazone: covered by from-any to-zone untrust.
    assert!(
        lookup_slot(&map, UNTRUST, UNTRUST).is_some(),
        "untrust->untrust (from-any to-zone untrust) must have a cold-path slot"
    );
}

/// A `security policies global match { from-zone trust; to-zone untrust; }`
/// rule (#3148 scoped global) must expand to EXACTLY its pinned pair — not
/// the full concrete cross-product — so it gets a slot without needlessly
/// broadening the slot map. A pair outside the scope stays unmapped.
#[test]
fn cold_path_slot_scoped_global_pins_single_pair() {
    use crate::protocol::PolicyRuleSnapshot;
    use rustc_hash::FxHashMap;

    const TRUST: u16 = crate::test_zone_ids::TEST_TRUST_ZONE_ID;
    const UNTRUST: u16 = crate::test_zone_ids::TEST_UNTRUST_ZONE_ID;
    const DMZ: u16 = crate::test_zone_ids::TEST_DMZ_ZONE_ID;

    let mut zone_name_to_id: FxHashMap<String, u16> = FxHashMap::default();
    zone_name_to_id.insert("trust".to_string(), TRUST);
    zone_name_to_id.insert("untrust".to_string(), UNTRUST);
    zone_name_to_id.insert("dmz".to_string(), DMZ);

    let rules = vec![PolicyRuleSnapshot {
        name: "scoped-glob".to_string(),
        from_zone: "junos-global".to_string(),
        to_zone: "junos-global".to_string(),
        match_from_zone: "trust".to_string(),
        match_to_zone: "untrust".to_string(),
        source_addresses: vec!["any".to_string()],
        destination_addresses: vec!["any".to_string()],
        applications: vec!["any".to_string()],
        action: "permit".to_string(),
        ..Default::default()
    }];

    let state = crate::policy::parse_policy_state("deny", &rules, &zone_name_to_id);
    let pairs = state.configured_zone_pairs();
    let (map, _z) = ColdPathSlotMap::build(None, &pairs);

    assert!(
        lookup_slot(&map, TRUST, UNTRUST).is_some(),
        "scoped global's pinned pair must have a slot"
    );
    // Not in scope — must stay unmapped (no over-broadening).
    assert_eq!(
        lookup_slot(&map, DMZ, TRUST),
        None,
        "a pair outside the scoped global's match context must NOT get a slot"
    );
}

#[test]
fn build_flags_overflow_only_on_slot_capacity_exhaustion() {
    // #3075: overflow_active is set when the slot CAPACITY
    // (COLD_PATH_ASSIGNABLE_SLOTS) is exhausted, NOT by zone-id
    // magnitude — wide stable-hash ids are first-class now. A wide id
    // within capacity is assigned, not dropped.
    let pairs = [(1u16, 2u16), (200, 5), (3, 4)];
    let (map, _) = ColdPathSlotMap::build(None, &pairs);
    assert!(
        lookup_slot(&map, 200, 5).is_some(),
        "a wide id (200) within capacity must be assigned, not dropped"
    );
    assert!(!map.overflow_active, "no capacity pressure ⇒ no overflow");
    let occupied = map.inverse.iter().filter(|s| s.is_some()).count();
    assert_eq!(occupied, 3);

    // Exceed the slot capacity with distinct wide pairs ⇒ overflow.
    let mut many: Vec<(u16, u16)> = Vec::new();
    for i in 0..(COLD_PATH_ASSIGNABLE_SLOTS as u16 + 1) {
        many.push((1000 + i, 2000 + i));
    }
    let (full, _) = ColdPathSlotMap::build(None, &many);
    assert!(
        full.overflow_active,
        "exceeding the {COLD_PATH_ASSIGNABLE_SLOTS}-slot capacity must trip overflow_active"
    );
    let occupied_full = full.inverse.iter().filter(|s| s.is_some()).count();
    assert_eq!(
        occupied_full, COLD_PATH_ASSIGNABLE_SLOTS,
        "exactly the capacity is assigned; the surplus pair is dropped"
    );
}

/// #15092: the production build path (`configured_zone_pairs_bounded` →
/// `ColdPathSlotMap`) must keep `overflow_active` set when the wildcard
/// expansion exceeds capacity BEFORE the capped input reaches `build`.
/// Feeding `build` only the 255 capped pairs would otherwise look like
/// an exact fit and the starvation flag would never fire. This mirrors
/// the `|=` wiring in `forwarding_build`.
#[test]
fn bounded_pairs_overflow_reaches_slot_map_15092() {
    use crate::protocol::PolicyRuleSnapshot;
    use rustc_hash::FxHashMap;

    // 20 zones ⇒ 400 both-any pairs ≫ 255 slots.
    let mut zone_name_to_id: FxHashMap<String, u16> = FxHashMap::default();
    for id in 1..=20u16 {
        zone_name_to_id.insert(format!("z{id}"), id);
    }
    let rules = vec![PolicyRuleSnapshot {
        name: "catch-all".to_string(),
        from_zone: "any".to_string(),
        to_zone: "any".to_string(),
        source_addresses: vec!["any".to_string()],
        destination_addresses: vec!["any".to_string()],
        applications: vec!["any".to_string()],
        action: "permit".to_string(),
        ..Default::default()
    }];
    let state = crate::policy::parse_policy_state("deny", &rules, &zone_name_to_id);
    let configured = state.configured_zone_pairs_bounded(COLD_PATH_ASSIGNABLE_SLOTS);
    assert_eq!(configured.pairs.len(), COLD_PATH_ASSIGNABLE_SLOTS);
    assert!(configured.overflow);
    let (mut map, _) = ColdPathSlotMap::build(None, &configured.pairs);
    map.overflow_active |= configured.overflow;
    assert!(
        map.overflow_active,
        "capped wildcard expansion must surface overflow to operators"
    );
    let occupied = map.inverse.iter().filter(|s| s.is_some()).count();
    assert_eq!(occupied, COLD_PATH_ASSIGNABLE_SLOTS);
    assert!(lookup_slot(&map, 1, 1).is_some());
}

/// Codex code-r1 finding 1: A assigns slot 0; B frees it (no reuse);
/// C reassigns slot 0 to a NEW pair. C's `previous` (= B) shows
/// slot 0 free, but the worker-local accumulator may still carry
/// A's counts — so C MUST queue slot 0 for zero-out.
#[test]
fn build_zeros_slot_reassigned_after_intermediate_free() {
    // A: slot 0 = (1,2), slot 1 = (3,4).
    let (map_a, za) = ColdPathSlotMap::build(None, &[(1u16, 2u16), (3, 4)]);
    assert!(za.is_empty());
    let slot_12 = lookup_slot(&map_a, 1, 2).unwrap();
    // B: drop (1,2); keep (3,4). Slot for (1,2) is now free.
    let (map_b, _zb) = ColdPathSlotMap::build(Some(&map_a), &[(3u16, 4u16)]);
    assert_eq!(lookup_slot(&map_b, 1, 2), None);
    // C: keep (3,4); add NEW (5,6). It takes the lowest free slot,
    // which is the slot A used for (1,2).
    let (map_c, zc) = ColdPathSlotMap::build(Some(&map_b), &[(3u16, 4u16), (5, 6)]);
    let slot_56 = lookup_slot(&map_c, 5, 6).unwrap();
    assert_eq!(slot_56, slot_12, "(5,6) reuses the slot A gave (1,2)");
    assert!(
        zc.contains(&slot_56),
        "reassigned slot must be queued for zero-out even though B showed it free \
             (Codex finding 1) — slots_to_zero={zc:?}"
    );
}

#[test]
fn zone_pair_packed_key_nonzero_for_zero_inputs() {
    // (0, 0) must not collapse to zero per plan §3.4 first_key/
    // alias_seen collision detection (zero is the "no sample"
    // sentinel).
    assert_ne!(zone_pair_packed_key(0, 0), 0);
    assert_eq!(zone_pair_packed_key(0, 0), 1);
}

#[test]
fn zone_pair_packed_key_distinguishes_from_to() {
    assert_ne!(
        zone_pair_packed_key(1, 2),
        zone_pair_packed_key(2, 1),
        "(1,2) and (2,1) must hash to distinct packed keys"
    );
}

/// Codex r3 finding 1: `| 1` collapsed (1,2) and (1,3) to the
/// same packed key, breaking injectivity. v3 fix uses `+ 1`
/// instead. This test pins the injective semantics by exhaustively
/// checking the small (8x8) zone-id box for distinct keys per
/// distinct pair.
#[test]
fn zone_pair_packed_key_is_injective_over_small_box() {
    use std::collections::HashSet;
    let mut keys = HashSet::new();
    for f in 0..8u16 {
        for t in 0..8u16 {
            let k = zone_pair_packed_key(f, t);
            assert!(keys.insert(k), "duplicate packed key for ({f},{t}) -> {k}");
        }
    }
    assert_eq!(keys.len(), 8 * 8);
}

/// Codex r3 finding 1 explicit counter-example: (1,2) and (1,3)
/// MUST have distinct packed keys; the v1/v2 `| 1` form collapsed
/// them both to 65539.
#[test]
fn zone_pair_packed_key_distinguishes_adjacent_to_zone_ids() {
    let k12 = zone_pair_packed_key(1, 2);
    let k13 = zone_pair_packed_key(1, 3);
    assert_ne!(
        k12, k13,
        "(1,2)={k12} (1,3)={k13} — must be distinct (Codex r3 finding 1)"
    );
}

#[test]
fn clock_source_round_trip_u8() {
    for src in [
        ClockSource::Tsc,
        ClockSource::ClockGettime,
        ClockSource::Unset,
    ] {
        assert_eq!(ClockSource::from_u8(src.as_u8()), src);
    }
}

#[test]
fn clock_source_as_str_stable_wire_contract() {
    assert_eq!(ClockSource::Tsc.as_str(), "tsc");
    assert_eq!(ClockSource::ClockGettime.as_str(), "clock_gettime");
    assert_eq!(ClockSource::Unset.as_str(), "");
}

#[test]
fn record_sample_updates_all_fields() {
    let mut c = WorkerColdPathCounters::default();
    let slot = 0u8;
    c.record_sample(slot, 1, 2, 1500);
    let bucket = bucket_index_for_ns_48(1500);
    assert_eq!(c.buckets[slot as usize][bucket], 1);
    assert_eq!(c.sum_ns[slot as usize], 1500);
    assert_eq!(c.samples[slot as usize], 1);
    // First sample sets first_key, builder_collision stays false.
    assert_eq!(c.first_key[slot as usize], zone_pair_packed_key(1, 2));
    assert!(!c.builder_collision[slot as usize]);
}

#[test]
fn record_sample_same_key_twice_no_collision() {
    let mut c = WorkerColdPathCounters::default();
    let slot = 0u8;
    c.record_sample(slot, 1, 2, 100);
    c.record_sample(slot, 1, 2, 100);
    assert_eq!(c.first_key[slot as usize], zone_pair_packed_key(1, 2));
    assert!(!c.builder_collision[slot as usize]);
    assert_eq!(c.samples[slot as usize], 2);
}

#[test]
fn record_sample_detects_builder_collision() {
    // With the direct slot map a slot should only ever see one
    // zone-pair. If the builder mistakenly maps two pairs to the
    // same slot, builder_collision must fire — this is a builder
    // bug detector, not an aliasing gate.
    let mut c = WorkerColdPathCounters::default();
    let slot = 4u8;
    c.record_sample(slot, 1, 2, 100);
    assert!(!c.builder_collision[slot as usize]);
    c.record_sample(slot, 3, 4, 200); // different key, same slot
    assert!(
        c.builder_collision[slot as usize],
        "builder_collision must fire when two distinct keys share a slot"
    );
}

#[test]
fn snapshot_roundtrip() {
    let atomics = WorkerColdPathAtomics::new();
    let mut local = WorkerColdPathCounters::default();
    let slot = 9u8;
    local.record_sample(slot, 3, 5, 4000);
    local.record_sample(slot, 3, 5, 8000);
    atomics.install_calibration(42, 30, ClockSource::Tsc);
    atomics.publish_from_local(&local);
    let snap = atomics
        .snapshot()
        .expect("single-thread snapshot must succeed");
    assert_eq!(snap.samples[slot as usize], 2);
    assert_eq!(snap.sum_ns[slot as usize], 12000);
    assert_eq!(snap.ns_per_tsc_q32, 42);
    assert_eq!(snap.wrapper_ns_baseline, 30);
    assert_eq!(snap.clock_source, ClockSource::Tsc);
}

/// Single-thread sequential publish + snapshot test. Verifies
/// the seqlock writes/reads coherently across two consecutive
/// publish-snapshot cycles on the same thread.
///
/// Copilot code-r1: the prior test was named
/// `snapshot_concurrent_publish_does_not_tear` but actually
/// performed no concurrent writes. Renamed to reflect what it
/// truly exercises. A separate `snapshot_under_concurrent_writer_*`
/// test below covers the real cross-thread tear regime.
#[test]
fn snapshot_sequential_publish_roundtrip() {
    let atomics = std::sync::Arc::new(WorkerColdPathAtomics::new());
    let mut local = WorkerColdPathCounters::default();
    let slot = 11u8;
    local.record_sample(slot, 7, 11, 12345);
    atomics.publish_from_local(&local);
    let snap1 = atomics.snapshot().expect("seq snapshot 1 must succeed");
    local.record_sample(slot, 7, 11, 67890);
    atomics.publish_from_local(&local);
    let snap2 = atomics.snapshot().expect("seq snapshot 2 must succeed");
    assert_eq!(snap1.samples[slot as usize], 1);
    assert_eq!(snap2.samples[slot as usize], 2);
}

/// AGY code-r2 finding 2: snapshot() now returns Option. Verify
/// that an in-flight publish (odd cold_window_gen) is detected
/// and the snapshot returns None on retry exhaustion — NOT a
/// silently-zero result that the harness would mistake for an
/// empty worker.
#[test]
fn snapshot_returns_none_on_perpetually_odd_gen() {
    use std::sync::atomic::Ordering as AOrd;
    let atomics = WorkerColdPathAtomics::new();
    // Pin the seqlock at an odd generation. The snapshot retry
    // loop should exhaust its budget and return None.
    atomics.cold_window_gen.fetch_add(1, AOrd::AcqRel);
    let snap = atomics.snapshot();
    assert!(
        snap.is_none(),
        "snapshot must return None when cold_window_gen is perpetually odd"
    );
}

/// Cross-thread tear test: spawn a writer thread that publishes
/// in a tight loop while the main thread snapshots. Verifies the
/// seqlock provably never returns a torn payload (samples[slot]
/// must monotonically increase across snapshots, never decrease
/// or wrap).
///
/// Copilot code-r1: replaces the prior misnamed test that only
/// did back-to-back same-thread publishes.
/// Size the concurrent writer's inter-publish sleep from the MEASURED cost of
/// one uncontended snapshot pass (#7650).
///
/// The seqlock's even-window is exactly this sleep. A reader can only return
/// `Some` if a whole `snapshot()` pass — `COLD_PATH_PUBLISH_ATOMIC_OPS` atomic
/// loads over a ~100 KiB working set — fits inside one even-window. Retries do
/// not help: every attempt needs a fresh uninterrupted window, so a budget of
/// 8192 buys nothing once the pass is wider than the window. The gate is the
/// WINDOW, not the budget.
///
/// It has to scale rather than be a literal. The 100 µs literal this replaced
/// was sized when the payload was 16×24 (~450 atomics); #1635 grew it 30× to
/// 256×48 (~13.3k) and the throttle was never resized, leaving roughly 2.5×
/// margin on an idle machine and none at all on a machine under memory
/// pressure — where the pass faults instead of hitting cache and coherence
/// collapses. That is the regime #7650 was reported from.
///
/// The floor keeps a fast machine from spinning the writer into a busy loop;
/// the multiplier is what guarantees the margin on a slow or loaded one.
/// Minimum coherent snapshots out of 1000 for the concurrency test to mean
/// anything (#7650). This is an ANTI-VACUITY floor, not a tuning knob: without
/// it the test would pass having observed nothing, because every snapshot can
/// legitimately return `None` under retry exhaustion. Lowering it is how the
/// test gets "fixed" into uselessness, so it is pinned by
/// `coherence_floor_is_pinned_7650` rather than left as a bare literal.
const COHERENCE_FLOOR: u64 = 100;

fn writer_throttle_for_read_cost(read_cost: std::time::Duration) -> std::time::Duration {
    /// How many reader passes must fit inside one even-window.
    const WINDOW_MARGIN: u32 = 8;
    const FLOOR: std::time::Duration = std::time::Duration::from_micros(100);
    std::cmp::max(FLOOR, read_cost * WINDOW_MARGIN)
}

/// #7650: the publish/snapshot surface is what makes a reader pass expensive,
/// and it has grown silently before. #1635 took it from 16×24 to 256×48 — a
/// 30× increase — updating one doc comment while a second comment in the same
/// function kept claiming ~450 atomics and the concurrency test kept a writer
/// throttle sized for the old shape.
///
/// This pins the DERIVED constant against the two dimensions, so the constant
/// cannot drift from the arrays it describes. It deliberately does NOT pin a
/// literal 13314: pinning the number would just be a third place to forget.
#[test]
fn publish_atomic_ops_tracks_the_actual_surface_7650() {
    assert_eq!(
        COLD_PATH_PUBLISH_ATOMIC_OPS,
        POLICY_COLD_PATH_ZONE_PAIR_SLOTS * POLICY_COLD_PATH_HIST_BUCKETS
            + POLICY_COLD_PATH_ZONE_PAIR_SLOTS * 4
            + 2,
        "the derived publish/snapshot cost must track the arrays it describes"
    );
    // A reader pass this wide is the whole reason the even-window has to be
    // measured rather than assumed. If this ever shrinks back to the old dense
    // shape the throttle maths should be revisited deliberately, not silently.
    assert!(
        COLD_PATH_PUBLISH_ATOMIC_OPS > 10_000,
        "one publish/snapshot pass is {COLD_PATH_PUBLISH_ATOMIC_OPS} atomics; \
         if that has fallen back under 10k the surface changed shape and the \
         seqlock even-window sizing in this file needs re-deriving (#7650)"
    );
}

#[test]
fn coherence_floor_is_pinned_7650() {
    // 10% of the 1000 snapshots the reader takes. The number is the CLAIM that
    // the test saw enough to mean something; the correct response to it failing
    // is to widen the seqlock's even-window, never to lower this.
    assert_eq!(
        COHERENCE_FLOOR, 100,
        "the anti-vacuity floor was changed. If the concurrency test is failing \
         here, the reader could not complete a snapshot pass inside the writer's \
         even-window often enough — widen the window \
         (writer_throttle_for_read_cost) or explain why a reader pass became so \
         expensive. Lowering the floor leaves a test that runs, passes, and \
         measures nothing (#7650)"
    );
}

/// The helper tests above prove `writer_throttle_for_read_cost` computes the
/// right window, and prove nothing about whether the concurrency test USES it.
/// Every one of them stays green against a fixture that measures nothing and
/// sleeps a hardcoded 100 µs — which is exactly the pre-#7650 code.
///
/// So scan the fixture's own source for the three wirings. Comments are
/// stripped first: this file's prose names all three identifiers, and a gate
/// satisfiable by its own documentation proves nothing.
#[test]
fn concurrency_fixture_is_wired_to_the_measured_window_7650() {
    let src = include_str!("cold_path_hist_tests.rs");
    // Scan ONLY the fixture's body. Scanning the whole file is self-satisfying:
    // the needle table below contains every string it greps for, so the gate
    // passes against a fixture that no longer contains any of them. Stripping
    // comments does not fix that — these needles are code, not prose. The
    // matrix caught this: three cells stayed green against the whole-file scan.
    // Anchor on a REAL newline before the fn header. The obvious
    // `find("fn snapshot_...()")` matches this function's own argument to
    // `find` — a string literal that necessarily contains the name — so the
    // slice became the SCANNER's body, which holds every needle. That is the
    // third depth of the same self-satisfaction trap in this one gate, and the
    // matrix caught each one. A Rust string literal on a single line cannot
    // contain a raw newline, so this marker can only match the definition.
    let marker = "\nfn snapshot_under_concurrent_writer_never_tears() {\n";
    let start = src.find(marker).expect("concurrency fixture not found");
    let rest = &src[start..];
    let end = rest.find("\n#[test]").unwrap_or(rest.len());
    let body: String = rest[..end]
        .lines()
        .map(|l| {
            if l.trim_start().starts_with("//") {
                ""
            } else {
                l
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    let code = body;

    for (needle, why) in [
        (
            "std::thread::sleep(writer_sleep)",
            "the writer must sleep the MEASURED window; a hardcoded literal is \
             the #1635 drift that made the coherence floor unreachable",
        ),
        (
            "writer_throttle_for_read_cost(read_cost)",
            "the window must be derived from the measured pass cost, not from a \
             constant — otherwise the helper is dead code and the fixture is \
             back to assuming",
        ),
        (
            "let read_cost = probe_start.elapsed() / PROBE_ITERS",
            "the read cost must actually be MEASURED on this machine; a fixed \
             stand-in re-introduces the assumption the measurement replaces",
        ),
        (
            "atomics.snapshot().is_some()",
            "the uncontended precondition must remain: if a snapshot cannot be \
             coherent with NO writer running, the seqlock is broken and the \
             concurrency result below is uninterpretable",
        ),
    ] {
        assert!(
            code.contains(needle),
            "concurrency fixture no longer contains `{needle}` — {why} (#7650)"
        );
    }
}

#[test]
fn writer_throttle_scales_with_the_measured_read_cost_7650() {
    use std::time::Duration;
    // A fast machine is clamped by the floor, so the writer never becomes a
    // busy loop that starves the reader outright.
    assert_eq!(
        writer_throttle_for_read_cost(Duration::from_micros(1)),
        Duration::from_micros(100),
        "a very cheap read must still leave the 100 µs floor in place"
    );
    // The load-bearing case, and the one a hardcoded literal fails: when a
    // reader pass is EXPENSIVE the window must grow with it. This is the
    // regression #1635 introduced silently — the payload grew 30× and the
    // window did not move, so the margin quietly went to nothing.
    assert_eq!(
        writer_throttle_for_read_cost(Duration::from_micros(500)),
        Duration::from_micros(4000),
        "an expensive read pass must widen the even-window proportionally; a \
         fixed throttle is what let #1635's 30× payload growth silently erase \
         the reader's margin (#7650)"
    );
    assert!(
        writer_throttle_for_read_cost(Duration::from_millis(2)) >= Duration::from_millis(16),
        "the margin must hold for a slow/loaded machine too, or the coherence \
         floor becomes unreachable exactly when the machine is busy"
    );
}

#[test]
fn snapshot_under_concurrent_writer_never_tears() {
    use std::sync::atomic::{AtomicBool, Ordering as AOrd};
    let atomics = std::sync::Arc::new(WorkerColdPathAtomics::new());

    // Measure one uncontended snapshot pass BEFORE the writer starts, so the
    // writer's even-window can be sized from what a reader actually costs on
    // THIS machine rather than from a literal that was correct for a payload
    // 30× smaller (#7650).
    const PROBE_ITERS: u32 = 32;
    let probe_start = std::time::Instant::now();
    for _ in 0..PROBE_ITERS {
        assert!(
            atomics.snapshot().is_some(),
            "an UNCONTENDED snapshot must be coherent; if this fails the \
             seqlock is broken independently of any concurrency"
        );
    }
    let read_cost = probe_start.elapsed() / PROBE_ITERS;
    let writer_sleep = writer_throttle_for_read_cost(read_cost);

    let stop = std::sync::Arc::new(AtomicBool::new(false));
    let writer_atomics = atomics.clone();
    let writer_stop = stop.clone();
    let writer = std::thread::spawn(move || {
        let mut local = WorkerColdPathCounters::default();
        let mut count = 0u64;
        while !writer_stop.load(AOrd::Relaxed) {
            local.record_sample(5, 3, 5, 1000 + (count & 0xff));
            writer_atomics.publish_from_local(&local);
            count += 1;
            // The production writer publishes at ~1 Hz (see
            // worker_runtime.rs::publish); the test writer is far faster on
            // purpose, but it must still leave an even-window wide enough for
            // a whole reader pass — see writer_throttle_for_read_cost. Without
            // that the seqlock is odd nearly always, every snapshot exhausts
            // its retry budget and returns None, and the test fails its
            // coherence floor having observed nothing (Codex code-r3 NIT: the
            // weaker oracle would have falsely passed by accepting all zeros).
            std::thread::sleep(writer_sleep);
        }
        count
    });
    let slot = 5usize;

    // #8139: WAIT for the writer's first publish instead of sleeping a fixed
    // 20ms and hoping it happened.
    //
    // The 20ms literal was a bet on the scheduler. This box routinely sits at
    // load 40+ with several agents running --release gates at once, and under
    // that the writer thread can be starved through the whole spin-up AND the
    // reader loop. The reader then takes 1000 perfectly coherent all-zero
    // snapshots and the old `max_samples > 0` assertion fired with "reader
    // observed only zero samples across 1000 coherent and 0 retry-exhausted
    // snapshots".
    //
    // That message named the tell without acting on it: 0 retry-exhausted
    // means the seqlock behaved flawlessly. The test was asserting that the
    // WRITER MADE PROGRESS, which is a property of the scheduler, not of the
    // histogram. Because `cargo test` aborts at the first failing binary, that
    // scheduler accident took the whole `make test-rust` gate down with it.
    //
    // This is the same distinction #7650 already drew for the coherence floor
    // below, so it gets the same treatment: an explicit, generously bounded
    // observability precondition that fails with a message saying what it is.
    // 10s is ~500x the old literal; a writer that cannot publish once in that
    // window is a real problem worth failing on.
    const WRITER_SPINUP_DEADLINE: std::time::Duration = std::time::Duration::from_secs(10);
    let spinup_start = std::time::Instant::now();
    let mut writer_published = false;
    while spinup_start.elapsed() < WRITER_SPINUP_DEADLINE {
        if let Some(snap) = atomics.snapshot() {
            if snap.samples[slot] > 0 {
                writer_published = true;
                break;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    assert!(
        writer_published,
        "OBSERVABILITY PRECONDITION FAILED, NOT A TEAR: the writer published \
         nothing in {WRITER_SPINUP_DEADLINE:?}, so the reader window would \
         have opened on an idle writer and measured the scheduler rather than \
         the seqlock. Nothing here indicts the histogram."
    );
    // Reader: take 1000 snapshots, assert monotonic samples per
    // slot AND cross-field invariants (Codex code-r3 NIT: the
    // weaker oracle would pass even if every snapshot returned
    // default zero after retry-exhaustion).
    let mut last_samples = 0u64;
    let mut at_least_one_observed_increase = false;
    let mut coherent_snapshots = 0u64;
    let mut retry_exhausted_snapshots = 0u64;
    for _ in 0..1000 {
        // AGY code-r2 finding 2: snapshot() returns Option<_>.
        // None means retry budget exhausted — NOT a tear. The
        // earlier oracle conflated these two regimes by checking
        // `samples` against a zero-default that retry-exhaustion
        // returned, producing false "seqlock tore" panics under
        // heavy contention. The correct oracle skips None
        // snapshots; tear detection runs only on coherent
        // (Some) snapshots.
        let Some(snap) = atomics.snapshot() else {
            retry_exhausted_snapshots += 1;
            continue;
        };
        coherent_snapshots += 1;
        let s = snap.samples[slot];
        // Tear-1: samples must be monotonic non-decreasing if the
        // seqlock is honoring epoch boundaries. We compare only
        // against the LAST COHERENT snapshot's samples; None
        // snapshots in between don't reset the monotonicity check.
        assert!(
            s >= last_samples,
            "samples regressed: {s} < {last_samples} — seqlock tore"
        );
        if s > last_samples {
            at_least_one_observed_increase = true;
        }
        // Tear-2: cross-field invariant — total bucket counts in
        // this slot MUST equal samples count. If the seqlock tore
        // and we observed samples from one epoch + buckets from
        // another, this invariant would fail.
        let bucket_sum: u64 = snap.buckets[slot].iter().sum();
        assert_eq!(
            bucket_sum, s,
            "torn epoch: samples={s} != bucket_sum={bucket_sum} for slot {slot}"
        );
        last_samples = s;
    }
    stop.store(true, AOrd::Relaxed);
    let writer_iters = writer.join().expect("writer thread panicked");
    // #8139: the former Sanity-1 ("at least one coherent snapshot was nonzero")
    // is deleted, not rewritten. The spin-up gate above now establishes that
    // the writer published BEFORE the reader window opened, and `samples` is
    // asserted monotonic non-decreasing below, so a nonzero first observation
    // is guaranteed by construction. Keeping the assertion would leave a cell
    // that can no longer fail — and a vacuous assertion is worse than no
    // assertion, because the next reader counts it as coverage.
    // Sanity-2: at least one snapshot must show an INCREASE over
    // the prior one, proving we actually observed publishes
    // arriving during the reader loop.
    assert!(
        at_least_one_observed_increase,
        "reader observed only the same samples value — seqlock contention may have masked all writes"
    );
    // Sanity-3: the writer did actually publish (proves we exercised
    // the concurrent path, not just an idle reader).
    assert!(
        writer_iters > 10,
        "writer only published {writer_iters} times — test did not exercise concurrency"
    );
    // Sanity-4: at least 10% of snapshots must have been coherent;
    // if EVERY snapshot exhausted retries the test is meaningless.
    //
    // #7650: the message names what this is and is not. Reaching here means
    // BOTH tear detections above already PASSED — the seqlock did not tear —
    // so a reader who starts by auditing the seqlock is auditing the wrong
    // thing. This is an observability precondition: the reader could not win
    // the race often enough to see anything, which is a property of the
    // even-window versus the reader's pass cost (and of how loaded the machine
    // is), not of the lock.
    assert!(
        coherent_snapshots >= COHERENCE_FLOOR,
        "OBSERVABILITY PRECONDITION FAILED, NOT A TEAR: only \
         {coherent_snapshots}/1000 snapshots were coherent \
         ({retry_exhausted_snapshots} exhausted their retry budget). The \
         seqlock did NOT tear — both tear detections above passed on every \
         coherent snapshot. The reader simply could not complete a \
         {read_cost:?} pass inside the writer's {writer_sleep:?} even-window \
         often enough. Raising the retry budget will NOT help: each attempt \
         needs its own uninterrupted window. Widen the window \
         (writer_throttle_for_read_cost) or find out why this machine made a \
         reader pass so expensive — do not lower this floor, it is the claim \
         that the test saw enough to mean something (#7650)"
    );
}

#[test]
fn sample_tsc_monotonic_within_thread() {
    // On x86_64 with constant_tsc, back-to-back rdtscp must be
    // monotonic non-decreasing. Gate on `probe_clock_source` per
    // Codex code-r2 NIT/portability: x86_64 does not imply
    // RDTSCP — a probe-fallback host would #UD on these
    // invocations.
    #[cfg(target_arch = "x86_64")]
    {
        if probe_clock_source() != ClockSource::Tsc {
            eprintln!(
                "skipping sample_tsc_monotonic_within_thread: host lacks RDTSCP or invariant TSC"
            );
            return;
        }
        let a = sample_tsc_start();
        let b = sample_tsc_end();
        let c = sample_tsc_start();
        let d = sample_tsc_end();
        assert!(
            b >= a && c >= b && d >= c,
            "tsc not monotonic: a={a} b={b} c={c} d={d}"
        );
    }
}

/// AGY code-r1 NIT 2: probe_clock_source must parse the `flags`
/// line as tokens to avoid false-positives from CPU model names
/// that contain the substring. We exercise the tokenizer in
/// isolation here because probe_clock_source itself reads
/// /proc/cpuinfo which is host-state-dependent.
#[test]
fn cpuinfo_tokenization_rejects_substring_false_positives() {
    // A pathological "model name" line that contains all three
    // tokens as substrings of the model name should NOT yield a
    // positive match if the actual flags line lacks them.
    let pathological = "\
model name\t: AMD constant_tsc-nonstop_tsc-rdtscp Special Edition\n\
flags\t\t: fpu vme de pse\n";
    let block = pathological.split("\n\n").next().unwrap();
    let flags_line = block
        .lines()
        .find(|l| {
            let t = l.trim_start();
            t.starts_with("flags") || t.starts_with("Features")
        })
        .and_then(|l| l.split(':').nth(1));
    let flags = flags_line.expect("flags line must exist in fixture");
    let tokens: std::collections::HashSet<&str> = flags.split_ascii_whitespace().collect();
    assert!(!tokens.contains("constant_tsc"));
    assert!(!tokens.contains("nonstop_tsc"));
    assert!(!tokens.contains("rdtscp"));
}

/// AGY code-r1 NIT 2: the positive case — a realistic flags line
/// with all three tokens must be detected.
#[test]
fn cpuinfo_tokenization_accepts_realistic_flags_line() {
    let realistic = "\
processor\t: 0\n\
flags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov constant_tsc rep_good nopl nonstop_tsc cpuid pni rdtscp\n";
    let block = realistic.split("\n\n").next().unwrap();
    let flags_line = block
        .lines()
        .find(|l| {
            let t = l.trim_start();
            t.starts_with("flags") || t.starts_with("Features")
        })
        .and_then(|l| l.split(':').nth(1))
        .expect("flags line must exist");
    let tokens: std::collections::HashSet<&str> = flags_line.split_ascii_whitespace().collect();
    assert!(tokens.contains("constant_tsc"));
    assert!(tokens.contains("nonstop_tsc"));
    assert!(tokens.contains("rdtscp"));
}

/// Codex code-r1 finding 1: verify the start/end split exists and
/// each variant returns a monotonic non-decreasing pair, matching
/// the Intel SDM §17.17 measurement-window recipe.
///
/// Gate on `probe_clock_source` per Codex code-r2 NIT/portability.
#[test]
fn sample_tsc_start_end_split_monotonic() {
    #[cfg(target_arch = "x86_64")]
    {
        if probe_clock_source() != ClockSource::Tsc {
            eprintln!(
                "skipping sample_tsc_start_end_split_monotonic: host lacks RDTSCP or invariant TSC"
            );
            return;
        }
        let a = sample_tsc_start();
        let b = sample_tsc_end();
        assert!(b >= a, "start={a} end={b} — not monotonic");
        // Two consecutive measurement windows; ensure each
        // start/end pair is monotonic and that the second start
        // is >= the first end (TSC is monotonic across the
        // intervening cycles).
        let c = sample_tsc_start();
        let d = sample_tsc_end();
        assert!(
            c >= b,
            "second_start={c} after first_end={b} — not monotonic"
        );
        assert!(d >= c, "second start={c} end={d} — not monotonic");
    }
}
