// #923 acceptance gate #3, updated by #15091: config-commit latency
// on the large-set build. #15091 replaced the one-Box-per-bit trie
// (256 random /32 prefixes → ~8K Box<TrieNode> allocations, and
// ~2.9 GB for an in-cap 850k-/128 feed book) with sorted, merged
// inclusive ranges. This bench re-implements that build shape —
// sort (lo, hi) pairs and coalesce — at the same 256-prefix scale
// and retains the <1.5 ms p95 gate, which now bounds a sort+merge
// that runs in tens of microseconds.
//
// Like `tx_kick_latency`, the daemon code lives in a bin crate
// (`xpf-userspace-dp` is a binary target with `pub(crate)`-only
// items), so this bench re-implements the equivalent shape. The
// test suite in `prefix_set.rs::tests` exercises the real types
// for correctness; this bench only gates the build cost.

use std::hint::black_box;
use std::time::Instant;

fn build_ranges(prefixes: &[(u32, u8)]) -> Vec<(u32, u32)> {
    let mut ranges: Vec<(u32, u32)> = prefixes
        .iter()
        .map(|&(ip, len)| {
            let host = if len == 0 {
                u32::MAX
            } else if len >= 32 {
                0
            } else {
                (1u32 << (32 - len)) - 1
            };
            let lo = ip & !host;
            (lo, lo.wrapping_add(host))
        })
        .collect();
    ranges.sort_unstable();
    let mut out: Vec<(u32, u32)> = Vec::with_capacity(ranges.len());
    for (lo, hi) in ranges {
        match out.last_mut() {
            Some((_, prev_hi)) if lo <= prev_hi.saturating_add(1) => {
                if hi > *prev_hi {
                    *prev_hi = hi;
                }
            }
            _ => out.push((lo, hi)),
        }
    }
    out
}

/// Tiny deterministic LCG matching the one in `prefix_set.rs::tests`.
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
}

fn build_256_random_v4_ranges() -> Vec<(u32, u32)> {
    let mut rng = Lcg::new(0xCAFE_BABE_DEAD_BEEF);
    let prefixes: Vec<(u32, u8)> = (0..256).map(|_| (rng.next_u32(), 32)).collect();
    build_ranges(&prefixes)
}

fn main() {
    const ITERATIONS: usize = 100;
    let mut samples_ns: Vec<u128> = Vec::with_capacity(ITERATIONS);
    for _ in 0..ITERATIONS {
        let t0 = Instant::now();
        let ranges = build_256_random_v4_ranges();
        let elapsed = t0.elapsed();
        black_box(&ranges);
        samples_ns.push(elapsed.as_nanos());
    }
    samples_ns.sort_unstable();
    let mean_ns: u128 = samples_ns.iter().sum::<u128>() / (ITERATIONS as u128);
    let p50_ns = samples_ns[ITERATIONS / 2];
    let p95_ns = samples_ns[(ITERATIONS * 95) / 100];
    let p99_ns = samples_ns[(ITERATIONS * 99) / 100];
    println!(
        "#923/#15091 prefix_set_lookup bench (256 /32 prefixes → merged ranges):"
    );
    println!("  mean: {} µs", mean_ns / 1_000);
    println!("  p50:  {} µs", p50_ns / 1_000);
    println!("  p95:  {} µs", p95_ns / 1_000);
    println!("  p99:  {} µs", p99_ns / 1_000);
    // Acceptance gate: p95 ≤ 1.5 ms = 1_500_000 ns.
    let p95_threshold_ns: u128 = 1_500_000;
    if p95_ns > p95_threshold_ns {
        eprintln!(
            "FAIL: p95 {} ns > {} ns threshold",
            p95_ns, p95_threshold_ns
        );
        std::process::exit(1);
    }
    println!("PASS: p95 under 1.5 ms threshold");
}
