// #12989: SipHash-2-4 vs keyed multiply-mix cost. Bin-crate internals are
// pub(crate), so both hashers are re-implemented verbatim here (same pattern
// as session_table.rs). Workload: the placements that profiled hot —
// 40-byte steering row, v6 5-tuple bytes, single u64 shard key.
use criterion::{Criterion, criterion_group, criterion_main, Throughput};
use std::collections::hash_map::DefaultHasher;
use std::hash::{BuildHasher, Hasher};
use std::hint::black_box;

fn splitmix64(mut x: u64) -> u64 {
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^ (x >> 31)
}
const KEYED_FX_K: u64 = 0x9e37_79b9_7f4a_7c15;
#[derive(Clone)]
struct KeyedState(u64);
struct KeyedHasher(u64);
impl Hasher for KeyedHasher {
    #[inline]
    fn finish(&self) -> u64 { splitmix64(self.0) }
    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        let mut chunks = bytes.chunks_exact(8);
        for c in &mut chunks {
            self.0 = splitmix64(self.0 ^ u64::from_le_bytes(c.try_into().unwrap()) ^ KEYED_FX_K);
        }
        let rem = chunks.remainder();
        if !rem.is_empty() {
            let mut t = [0u8; 8];
            t[..rem.len()].copy_from_slice(rem);
            self.0 = splitmix64(self.0 ^ (u64::from_le_bytes(t) ^ rem.len() as u64) ^ KEYED_FX_K);
        }
    }
}
impl BuildHasher for KeyedState {
    type Hasher = KeyedHasher;
    fn build_hasher(&self) -> Self::Hasher { KeyedHasher(splitmix64(self.0 ^ 0xa076_1d64_78bd_642f)) }
}

fn bench_hot_hash(c: &mut Criterion) {
    let row = [0xA5u8; 40];
    let tuple = [0x5Au8; 37];
    let mut g = c.benchmark_group("hot_hash");
    g.throughput(Throughput::Elements(1));
    g.bench_function("siphash_row40", |b| b.iter(|| {
        let mut h = DefaultHasher::new();
        h.write(black_box(&row));
        black_box(h.finish())
    }));
    g.bench_function("keyedfx_row40", |b| b.iter(|| {
        black_box(KeyedState(42).hash_one(black_box(&row)))
    }));
    g.bench_function("siphash_tuple37", |b| b.iter(|| {
        let mut h = DefaultHasher::new();
        h.write(black_box(&tuple));
        black_box(h.finish())
    }));
    g.bench_function("keyedfx_tuple37", |b| b.iter(|| {
        black_box(KeyedState(42).hash_one(black_box(&tuple)))
    }));
    g.bench_function("siphash_u64", |b| b.iter(|| {
        let mut h = DefaultHasher::new();
        h.write_u64(black_box(0xdead_beef));
        black_box(h.finish())
    }));
    g.bench_function("keyedfx_u64", |b| b.iter(|| {
        black_box(KeyedState(42).hash_one(black_box(0xdead_beefu64)))
    }));
    g.finish();
}
criterion_group!(benches, bench_hot_hash);
criterion_main!(benches);
