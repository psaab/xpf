// Tests for prefix_set.rs — relocated from inline
// `#[cfg(test)] mod tests` to keep prefix_set.rs under the modularity-discipline
// LOC threshold. Loaded as a sibling submodule via
// `#[path = "prefix_set_tests.rs"]` from prefix_set.rs.

use super::*;
use ipnet::{Ipv4Net, Ipv6Net};

/// Tiny deterministic LCG for seeded test inputs. We don't pull
/// in `rand` as a dev-dependency just for this.
struct Lcg(u64);
impl Lcg {
    fn new(seed: u64) -> Self {
        Self(seed)
    }
    fn next_u32(&mut self) -> u32 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (self.0 >> 32) as u32
    }
    fn next_u128(&mut self) -> u128 {
        let hi = self.next_u32() as u128;
        let mid = self.next_u32() as u128;
        let lo_a = self.next_u32() as u128;
        let lo_b = self.next_u32() as u128;
        (hi << 96) | (mid << 64) | (lo_a << 32) | lo_b
    }
}

fn p4(s: &str) -> PrefixV4 {
    PrefixV4::from_net(s.parse::<Ipv4Net>().expect("parse v4"))
}

fn p6(s: &str) -> PrefixV6 {
    PrefixV6::from_net(s.parse::<Ipv6Net>().expect("parse v6"))
}

#[test]
fn empty_input_yields_match_any() {
    let set = PrefixSetV4::from_prefixes(Vec::new());
    assert!(matches!(set, PrefixSetV4::MatchAny));
    assert!(set.contains("1.2.3.4".parse().expect("ip")));
    assert_eq!(set.prefix_count(), 0);
}

#[test]
fn match_any_set_matches_arbitrary_ips() {
    // 0.0.0.0/0 is funneled to MatchAny by the constructor.
    let set = PrefixSetV4::from_prefixes(vec![p4("0.0.0.0/0")]);
    assert!(matches!(set, PrefixSetV4::MatchAny));
    assert!(set.contains("172.16.80.5".parse().expect("ip")));
    assert!(set.contains("0.0.0.0".parse().expect("ip")));
}

#[test]
fn linear_set_matches_covered_ip() {
    let set = PrefixSetV4::from_prefixes(vec![
        p4("10.0.0.0/8"),
        p4("192.168.1.0/24"),
        p4("172.16.0.0/12"),
    ]);
    assert!(matches!(set, PrefixSetV4::Linear(_)));
    assert!(set.contains("10.0.61.102".parse().expect("ip")));
    assert!(set.contains("192.168.1.42".parse().expect("ip")));
    assert!(set.contains("172.16.80.5".parse().expect("ip")));
    assert!(!set.contains("8.8.8.8".parse().expect("ip")));
    assert!(!set.contains("192.168.2.1".parse().expect("ip")));
}

#[test]
fn linear_variant_chosen_when_count_eq_threshold() {
    let prefixes: Vec<PrefixV4> = (0..16).map(|i| p4(&format!("10.{i}.0.0/16"))).collect();
    let set = PrefixSetV4::from_prefixes(prefixes);
    assert!(matches!(set, PrefixSetV4::Linear(_)));
    assert_eq!(set.prefix_count(), 16);
}

#[test]
fn ranges_variant_chosen_when_count_gt_threshold() {
    let prefixes: Vec<PrefixV4> = (0..17).map(|i| p4(&format!("10.{i}.0.0/16"))).collect();
    let set = PrefixSetV4::from_prefixes(prefixes);
    assert!(matches!(set, PrefixSetV4::Ranges(..)));
    assert_eq!(set.prefix_count(), 17);
}

#[test]
fn ranges_lookup_matches_linear_lookup_random_v4() {
    let mut rng = Lcg::new(0xCAFE_BABE_DEAD_BEEF);
    // Build 256 prefixes with random length 8..=32 — wider than
    // /32 only would hit the worst-case node count; we use a
    // mix to exercise both shared-prefix and unique-prefix paths.
    let mut prefixes: Vec<PrefixV4> = Vec::with_capacity(256);
    for _ in 0..256 {
        let len = 8 + (rng.next_u32() % 25) as u8; // 8..=32
        let addr = rng.next_u32();
        let net = Ipv4Net::new(Ipv4Addr::from(addr), len).expect("net");
        prefixes.push(PrefixV4::from_net(net));
    }
    // Force a Linear set by truncating to 16 vs a Trie set with
    // the full 256.
    let linear = PrefixSetV4::from_prefixes(prefixes.iter().take(16).copied().collect());
    let trie = PrefixSetV4::from_prefixes(prefixes.clone());
    assert!(matches!(linear, PrefixSetV4::Linear(_)));
    assert!(matches!(trie, PrefixSetV4::Ranges(..)));
    // Boolean equivalence: against a fresh linear scan on the
    // same input, the trie must produce the same answer for
    // every probe IP.
    let reference: Vec<PrefixV4> = prefixes.clone();
    for _ in 0..4096 {
        let ip = Ipv4Addr::from(rng.next_u32());
        let want = reference.iter().any(|p| p.contains(ip));
        let got = trie.contains(ip);
        assert_eq!(want, got, "trie disagreed with linear at ip {}", ip);
    }
}

#[test]
fn ranges_lookup_matches_linear_lookup_random_v6() {
    let mut rng = Lcg::new(0xFACE_FEED_C0DE_BEEF);
    let mut prefixes: Vec<PrefixV6> = Vec::with_capacity(256);
    for _ in 0..256 {
        let len = 32 + (rng.next_u32() % 97) as u8; // 32..=128
        let addr = rng.next_u128();
        let net = Ipv6Net::new(Ipv6Addr::from(addr), len).expect("net");
        prefixes.push(PrefixV6::from_net(net));
    }
    let trie = PrefixSetV6::from_prefixes(prefixes.clone());
    assert!(matches!(trie, PrefixSetV6::Ranges(..)));
    let reference: Vec<PrefixV6> = prefixes;
    for _ in 0..4096 {
        let ip = Ipv6Addr::from(rng.next_u128());
        let want = reference.iter().any(|p| p.contains(ip));
        let got = trie.contains(ip);
        assert_eq!(want, got, "trie v6 disagreed with linear at ip {}", ip);
    }
}

#[test]
fn ranges_short_circuits_on_covering_ancestor() {
    // /16 + /24 nested: the /16 is a strict superset of /24.
    // Any IP within the /16 should match because of the /16
    // covers flag at depth 16, regardless of /24 membership.
    let prefixes: Vec<PrefixV4> = (0..17)
        .map(|i| p4(&format!("10.{i}.0.0/24")))
        .chain(std::iter::once(p4("10.0.0.0/16")))
        .collect();
    let set = PrefixSetV4::from_prefixes(prefixes);
    assert!(matches!(set, PrefixSetV4::Ranges(..)));
    // 10.0.99.42: second octet 0 → in 10.0.0.0/16 (depth-16
    // covers short-circuits before we ever check the /24 layer
    // for 10.0.99/24, which wasn't inserted).
    assert!(set.contains("10.0.99.42".parse().expect("ip")));
    // 10.1.0.42: in 10.1.0.0/24 (depth-24 covers). NOT in
    // 10.0.0.0/16 because second octet is 1 not 0.
    assert!(set.contains("10.1.0.42".parse().expect("ip")));
    // 10.1.5.10: NOT in 10.1.0.0/24 (third octet 5 not 0) and
    // NOT in 10.0.0.0/16 (second octet 1 not 0).
    assert!(!set.contains("10.1.5.10".parse().expect("ip")));
    // 10.20.0.5: outside every inserted /24 (only 10.0..10.16
    // were inserted) and outside 10.0.0.0/16.
    assert!(!set.contains("10.20.0.5".parse().expect("ip")));
}

#[test]
fn ranges_handles_zero_prefix_via_match_any_shortcut() {
    // /0 must be filtered to MatchAny by the constructor —
    // even when mixed with other prefixes.
    let prefixes = vec![p4("10.0.0.0/24"), p4("0.0.0.0/0"), p4("192.168.1.0/24")];
    let set = PrefixSetV4::from_prefixes(prefixes);
    assert!(matches!(set, PrefixSetV4::MatchAny));
    assert!(set.contains("8.8.8.8".parse().expect("ip")));
}

#[test]
fn ranges_handles_full_host_prefix() {
    // A single /32 — only the exact host matches.
    let prefixes: Vec<PrefixV4> = (0..17).map(|i| p4(&format!("10.0.0.{i}/32"))).collect();
    let set = PrefixSetV4::from_prefixes(prefixes);
    assert!(matches!(set, PrefixSetV4::Ranges(..)));
    assert!(set.contains("10.0.0.5".parse().expect("ip")));
    assert!(!set.contains("10.0.0.20".parse().expect("ip")));
    assert!(!set.contains("10.0.0.100".parse().expect("ip")));
}

#[test]
fn duplicate_prefixes_dont_corrupt_the_set() {
    // Insert the same /24 three times. prefix_count should be
    // 1 (de-duplication via covers-already-set check), and the
    // lookup must still return true for IPs in that /24.
    let prefixes: Vec<PrefixV4> = (0..17)
        .map(|i| p4(&format!("5.5.{i}.0/24")))
        .chain(std::iter::repeat_with(|| p4("10.0.0.0/24")).take(3))
        .collect();
    let set = PrefixSetV4::from_prefixes(prefixes);
    match &set {
        PrefixSetV4::Ranges(r, n) => {
            // 17 unique /24s + 1 deduped (10.0.0.0/24): 18 distinct
            // prefixes. The /24s are adjacent (5.5.0..5.5.16) so
            // they merge into fewer disjoint ranges.
            assert_eq!(
                *n, 18,
                "distinct prefix count should dedupe exact duplicates"
            );
            assert!(r.len() < 18, "adjacent /24s must merge: {} ranges", r.len());
        }
        _ => panic!("expected ranges variant"),
    }
    assert!(set.contains("10.0.0.42".parse().expect("ip")));
    assert!(set.contains("5.5.16.1".parse().expect("ip")));
}

#[test]
fn unsorted_input_works() {
    // Bit-walk insertion order shouldn't affect the result.
    let prefixes: Vec<PrefixV4> = vec![
        p4("192.168.1.0/24"),
        p4("10.0.0.0/8"),
        p4("172.16.0.0/12"),
        p4("8.8.8.8/32"),
        p4("203.0.113.0/24"),
    ];
    // Build twice with different orders; both must agree.
    let a = PrefixSetV4::from_prefixes(prefixes.clone());
    let mut shuffled = prefixes;
    shuffled.reverse();
    let b = PrefixSetV4::from_prefixes(shuffled);
    for ip_str in [
        "10.0.0.1",
        "192.168.1.42",
        "172.16.80.5",
        "8.8.8.8",
        "203.0.113.99",
        "8.8.4.4", // not in any prefix
        "1.1.1.1", // not in any prefix
    ] {
        let ip: Ipv4Addr = ip_str.parse().expect("ip");
        assert_eq!(a.contains(ip), b.contains(ip), "disagree at {}", ip);
    }
}

// -----------------------------------------------------------------
// #15091: range representation memory + budget regression cells.
// These fail on origin/master: the old variant is `Trie` (one
// Box per bit), so the `Ranges` shape, the <64 MiB heap bound for
// 850k random /128s, and the typed budget error do not exist.
// -----------------------------------------------------------------

fn v6_15091(i: u64) -> PrefixV6 {
    // Deterministic splitmix64 spread of /128 host prefixes.
    let mut z = i.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^= z >> 31;
    let hi = z as u128;
    let lo = (z ^ 0xA076_1D64_78BD_642F) as u128;
    let addr = (hi << 64) | lo;
    p6(&format!("{}/128", Ipv6Addr::from(addr)))
}

#[test]
fn ranges_memory_bound_850k_random_v6_15091() {
    let prefixes: Vec<PrefixV6> = (0..850_000u64).map(v6_15091).collect();
    let set = PrefixSetV6::from_v3_literals(prefixes);
    assert!(
        matches!(set, PrefixSetV6::Ranges(..)),
        "850k prefixes must compile to Ranges, got a non-Ranges variant"
    );
    let heap = set.heap_bytes();
    assert!(
        heap < 64 * 1024 * 1024,
        "850k random /128 heap {heap} bytes must stay under 64 MiB (#15091 acceptance)"
    );
    // Membership spot-checks against the retained ranges.
    assert!(set.contains(Ipv6Addr::from({
        let p = v6_15091(42);
        u128::from(p.addr())
    })));
    assert!(!set.contains(Ipv6Addr::UNSPECIFIED));
}

#[test]
fn ranges_budget_exceeded_is_typed_15091() {
    // MAX+1 disjoint /128s cannot merge, so the merged count
    // exceeds the budget and the fallible factory must refuse.
    let n = MAX_PREFIX_SET_RANGES + 1;
    let prefixes: Vec<PrefixV6> = (0..n as u64).map(v6_15091).collect();
    match PrefixSetV6::try_from_v3_literals(prefixes) {
        Err(e) => {
            assert_eq!(e.limit, MAX_PREFIX_SET_RANGES);
            assert!(e.ranges > MAX_PREFIX_SET_RANGES);
        }
        Ok(_) => panic!("over-budget set must return PrefixSetBudgetExceeded"),
    }
    // The infallible wrapper must fail closed to MatchNone,
    // never widen to MatchAny.
    let prefixes: Vec<PrefixV6> = (0..n as u64).map(v6_15091).collect();
    let set = PrefixSetV6::from_v3_literals(prefixes);
    assert!(set.is_match_none(), "over-budget wrapper must be MatchNone");
    assert!(!set.contains(Ipv6Addr::LOCALHOST));
}

#[test]
fn ranges_at_budget_still_compiles_15091() {
    // Control: exactly at the merged-range budget compiles and
    // matches. Adjacent /128s merge, so use spaced addresses
    // (step 3) to keep ranges disjoint without exceeding it.
    let prefixes: Vec<PrefixV6> = (0..MAX_PREFIX_SET_RANGES as u128)
        .map(|i| {
            let addr = 0x2001_0db8_0000_0000_0000_0000_0000_0000u128 + i * 3;
            p6(&format!("{}/128", Ipv6Addr::from(addr)))
        })
        .collect();
    let set = PrefixSetV6::try_from_v3_literals(prefixes).expect("at-budget set must compile");
    assert_eq!(set.prefix_count(), MAX_PREFIX_SET_RANGES);
    assert!(set.contains(Ipv6Addr::from(
        0x2001_0db8_0000_0000_0000_0000_0000_0000u128
    )));
    assert!(!set.contains(Ipv6Addr::from(
        0x2001_0db8_0000_0000_0000_0000_0000_0001u128
    )));
}

#[test]
fn ranges_merge_covered_and_adjacent_15091() {
    // A covering /32 plus nested and adjacent prefixes collapse
    // to one range; a disjoint /32 stays separate.
    let mut prefixes: Vec<PrefixV6> = vec![
        p6("2001:db8::/32"),
        p6("2001:db8:1::/48"),
        p6("2001:db8::1/128"),
        p6("2001:db9::/32"),
    ];
    // Pad past the Linear threshold with prefixes inside the /32.
    for i in 0..20u32 {
        prefixes.push(p6(&format!("2001:db8:{i:x}::/48")));
    }
    let set = PrefixSetV6::from_v3_literals(prefixes);
    match &set {
        PrefixSetV6::Ranges(r, _) => assert_eq!(
            r.len(),
            1,
            "all inputs lie in 2001:db8::/32 or the adjacent 2001:db9::/32 which merges adjacently"
        ),
        other => panic!("expected Ranges, got {other:?}"),
    }
    assert!(set.contains("2001:db8:ffff::1".parse().expect("ip")));
    assert!(set.contains("2001:db9::1".parse().expect("ip")));
    assert!(!set.contains("2001:dba::1".parse().expect("ip")));
}

// -----------------------------------------------------------------
// #16189: generic family machinery. The `host_mask` guard is an
// IMPL-LEVEL contract, and this must be stated plainly:
// `merged_ranges` has NO observable bypass shape. Constructors
// funnel len==0 to MatchAny before the builder runs, and
// PrefixV4/PrefixV6 lengths cannot exceed BITS, so the builder
// only ever sees len in 1..=BITS — where the raw
// `(1 << (BITS - len)) - 1` shifts by 0..BITS-1 and yields
// exactly the guarded result. No test through the builder can
// distinguish `F::host_mask(..)` from an unguarded inline shift.
// What the required trait method buys is that the guards live
// with each family impl (verified directly by
// `host_mask_guards_boundaries_16189`, including the
// out-of-range lens the builder never passes), not that a
// call-site bypass would be caught here.
// `builder_ranges_at_boundary_lens_16189` below is therefore a
// RANGE-CORRECTNESS cell only: it pins the builder's exact
// retained ranges at len==BITS and BITS-1 for both families.
// -----------------------------------------------------------------

#[test]
fn host_mask_guards_boundaries_16189() {
    // v4: /0 covers everything, /32 is a single host.
    assert_eq!(PrefixV4Family::BITS, 32);
    assert_eq!(PrefixV6Family::BITS, 128);
    assert_eq!(PrefixV4Family::host_mask(0), u32::MAX);
    assert_eq!(PrefixV4Family::host_mask(1), 0x7fff_ffff);
    assert_eq!(PrefixV4Family::host_mask(24), 0xff);
    assert_eq!(PrefixV4Family::host_mask(31), 1);
    assert_eq!(PrefixV4Family::host_mask(32), 0);
    // Out-of-range lengths stay guarded (no shift overflow/panic).
    assert_eq!(PrefixV4Family::host_mask(33), 0);
    assert_eq!(PrefixV4Family::host_mask(255), 0);
    // v6: ::/0 covers everything, /128 is a single host.
    assert_eq!(PrefixV6Family::host_mask(0), u128::MAX);
    assert_eq!(PrefixV6Family::host_mask(1), (1u128 << 127) - 1);
    assert_eq!(PrefixV6Family::host_mask(64), (1u128 << 64) - 1);
    assert_eq!(PrefixV6Family::host_mask(127), 1);
    assert_eq!(PrefixV6Family::host_mask(128), 0);
    assert_eq!(PrefixV6Family::host_mask(129), 0);
    assert_eq!(PrefixV6Family::host_mask(255), 0);
}

#[test]
fn merged_ranges_byte_identical_per_family_16189() {
    // Corpus hitting len 0-adjacent (no /0 — constructor funnels it
    // to MatchAny), len==BITS (/32, /128), covered, adjacent and
    // disjoint inputs. Assert the retained ranges themselves, not
    // just `contains`, so a generic/host_mask drift that happens to
    // preserve membership on the probed IPs still fails.
    let v4_in: Vec<PrefixV4> = vec![
        p4("10.0.0.0/24"),
        p4("10.0.1.0/24"),    // adjacent → merges with previous
        p4("10.0.0.128/25"),  // covered by the /24
        p4("10.0.0.7/32"),    // covered, len==BITS
        p4("192.168.0.0/16"), // disjoint
        p4("192.168.255.255/32"),
    ];
    let mut v4_pad: Vec<PrefixV4> = v4_in.clone();
    // Pad past the Linear threshold with prefixes inside 10.0.0.0/23.
    for i in 0..16u32 {
        v4_pad.push(p4(&format!("10.0.0.{i}/32")));
    }
    let set = PrefixSetV4::try_from_v3_literals(v4_pad).expect("v4 set");
    match &set {
        PrefixSetV4::Ranges(r, n) => {
            let expected: Vec<(u32, u32)> = vec![
                (
                    u32::from(Ipv4Addr::new(10, 0, 0, 0)),
                    u32::from(Ipv4Addr::new(10, 0, 1, 255)),
                ),
                (
                    u32::from(Ipv4Addr::new(192, 168, 0, 0)),
                    u32::from(Ipv4Addr::new(192, 168, 255, 255)),
                ),
            ];
            assert_eq!(*r, expected, "v4 merged ranges must be byte-identical");
            // 6 named + 16 padded, minus exact dup 10.0.0.7/32 = 21.
            assert_eq!(*n, 21);
        }
        other => panic!("expected Ranges, got {other:?}"),
    }

    let mut v6_pad: Vec<PrefixV6> = vec![
        p6("2001:db8::/48"),
        p6("2001:db8:1::/48"), // adjacent → merges
        p6("2001:db8::1/128"), // covered, len==BITS
        p6("2001:db9::/48"),   // disjoint
    ];
    for i in 0..16u32 {
        v6_pad.push(p6(&format!("2001:db8::{i:x}/128")));
    }
    let set = PrefixSetV6::try_from_v3_literals(v6_pad).expect("v6 set");
    match &set {
        PrefixSetV6::Ranges(r, n) => {
            let base = u128::from("2001:db8::".parse::<Ipv6Addr>().expect("ip"));
            let expected: Vec<(u128, u128)> = vec![
                (base, base + (1u128 << 81) - 1), // 2001:db8::/47 span
                (
                    u128::from("2001:db9::".parse::<Ipv6Addr>().expect("ip")),
                    u128::from("2001:db9::".parse::<Ipv6Addr>().expect("ip")) + (1u128 << 80) - 1,
                ),
            ];
            assert_eq!(*r, expected, "v6 merged ranges must be byte-identical");
            // 4 named + 16 padded, minus exact dup 2001:db8::1/128 = 19.
            assert_eq!(*n, 19);
        }
        other => panic!("expected Ranges, got {other:?}"),
    }
}

#[test]
fn generic_set_boundary_membership_16189() {
    // len==BITS host prefixes at the address-space edges, built
    // through the generic Ranges path (>16 inputs).
    let mut v4: Vec<PrefixV4> = (0..17).map(|i| p4(&format!("0.0.0.{i}/32"))).collect();
    v4.push(p4("255.255.255.255/32"));
    let set = PrefixSetV4::from_prefixes(v4);
    assert!(matches!(set, PrefixSetV4::Ranges(..)));
    assert!(set.contains("0.0.0.0".parse().expect("ip")));
    assert!(set.contains("0.0.0.16".parse().expect("ip")));
    assert!(!set.contains("0.0.0.17".parse().expect("ip")));
    assert!(set.contains("255.255.255.255".parse().expect("ip")));
    assert!(!set.contains("255.255.255.254".parse().expect("ip")));

    let mut v6: Vec<PrefixV6> = (0..17).map(|i| p6(&format!("::1:{i:x}/128"))).collect();
    v6.push(p6("ffff::ffff/128"));
    let set = PrefixSetV6::from_prefixes(v6);
    assert!(matches!(set, PrefixSetV6::Ranges(..)));
    assert!(set.contains("::1:0".parse().expect("ip")));
    assert!(!set.contains("::1:11".parse().expect("ip")));
    assert!(set.contains("ffff::ffff".parse().expect("ip")));
    // Fail-open defaults unchanged per family.
    assert!(PrefixSetV4::default().is_match_any());
    assert!(PrefixSetV6::default().is_match_any());
    assert!(PrefixSetV4::default().contains("203.0.113.1".parse().expect("ip")));
    assert!(PrefixSetV6::default().contains("2001:db8::1".parse().expect("ip")));
}

#[test]
fn builder_ranges_at_boundary_lens_16189() {
    // Range-correctness ONLY (see header): pins the builder's exact
    // retained ranges at len==BITS (/32, /128) and BITS-1 (/31, /127)
    // for both families. It cannot — and does not claim to — detect
    // a builder that bypasses `F::host_mask`, because for every len
    // the builder can actually receive (1..=BITS; len==0 is funneled
    // to MatchAny by the constructors and prefix lens cannot exceed
    // BITS) the raw `(1 << (BITS - len)) - 1` shifts by 0..BITS-1 and
    // yields the same mask as the guarded method.
    // v4: sixteen /32 hosts inside 10.0.0.0/24 plus the /24 itself
    // and a disjoint /31 (len == BITS-1) at the top of the space.
    let mut v4: Vec<PrefixV4> = (0..16).map(|i| p4(&format!("10.0.0.{i}/32"))).collect();
    v4.push(p4("10.0.0.0/24"));
    v4.push(p4("255.255.255.254/31"));
    let set = PrefixSetV4::try_from_v3_literals(v4).expect("v4 set");
    match &set {
        PrefixSetV4::Ranges(r, n) => {
            let expected: Vec<(u32, u32)> = vec![
                (
                    u32::from(Ipv4Addr::new(10, 0, 0, 0)),
                    u32::from(Ipv4Addr::new(10, 0, 0, 255)),
                ),
                (
                    u32::from(Ipv4Addr::new(255, 255, 255, 254)),
                    u32::from(Ipv4Addr::new(255, 255, 255, 255)),
                ),
            ];
            assert_eq!(*r, expected, "builder ranges at boundary lens (v4)");
            assert_eq!(*n, 18);
        }
        other => panic!("expected Ranges, got {other:?}"),
    }
    // v6: sixteen /128 hosts inside 2001:db8::/112 plus the /112
    // itself and a disjoint /127 (len == BITS-1).
    let mut v6: Vec<PrefixV6> = (0..16)
        .map(|i| p6(&format!("2001:db8::{i:x}/128")))
        .collect();
    v6.push(p6("2001:db8::/112"));
    v6.push(p6("2001:db8:ffff::fffe/127"));
    let set = PrefixSetV6::try_from_v3_literals(v6).expect("v6 set");
    match &set {
        PrefixSetV6::Ranges(r, n) => {
            let lo112 = u128::from("2001:db8::".parse::<Ipv6Addr>().expect("ip"));
            let lo127 = u128::from("2001:db8:ffff::fffe".parse::<Ipv6Addr>().expect("ip"));
            let expected: Vec<(u128, u128)> =
                vec![(lo112, lo112 + (1u128 << 16) - 1), (lo127, lo127 + 1)];
            assert_eq!(*r, expected, "builder ranges at boundary lens (v6)");
            assert_eq!(*n, 18);
        }
        other => panic!("expected Ranges, got {other:?}"),
    }
}
