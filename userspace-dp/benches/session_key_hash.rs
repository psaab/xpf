// Perf #14300: SessionKey hash cost — derived (typed write_* sequence)
// vs manual (single write over a fixed image), under BOTH the std
// SipHash hasher and the production KeyedFxHasher (splitmix64 per fold).
// Re-implements both hash bodies verbatim because SessionKey /
// KeyedFxHasher are pub(crate) in the bin crate (same pattern as
// hot_hash.rs / session_table.rs).
//
// Read the printed ns/op: the manual image must beat the derived
// sequence under KeyedFxHasher (the production hasher, where every
// typed write is a full splitmix64 fold). Exploratory — prints only,
// never gates (see session_table.rs #5190 banner).
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use std::hash::{BuildHasher, Hasher};
use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

fn splitmix64(mut x: u64) -> u64 {
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^ (x >> 31)
}
const KEYED_FX_K: u64 = 0x9e37_79b9_7f4a_7c15;
#[derive(Clone, Copy)]
struct KeyedState(u64);
struct KeyedHasher(u64);
impl Hasher for KeyedHasher {
    #[inline]
    fn finish(&self) -> u64 {
        splitmix64(self.0)
    }
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
    #[inline]
    fn write_u8(&mut self, n: u8) {
        self.0 = splitmix64(self.0 ^ n as u64 ^ KEYED_FX_K);
    }
    #[inline]
    fn write_u16(&mut self, n: u16) {
        self.0 = splitmix64(self.0 ^ n as u64 ^ KEYED_FX_K);
    }
    #[inline]
    fn write_u32(&mut self, n: u32) {
        self.0 = splitmix64(self.0 ^ n as u64 ^ KEYED_FX_K);
    }
    #[inline]
    fn write_u64(&mut self, n: u64) {
        self.0 = splitmix64(self.0 ^ n ^ KEYED_FX_K);
    }
    #[inline]
    fn write_usize(&mut self, n: usize) {
        self.0 = splitmix64(self.0 ^ n as u64 ^ KEYED_FX_K);
    }
}
impl BuildHasher for KeyedState {
    type Hasher = KeyedHasher;
    fn build_hasher(&self) -> KeyedHasher {
        KeyedHasher(splitmix64(self.0 ^ 0xa076_1d64_78bd_642f))
    }
}

// IpAddr's std Hash: V4 = write_u8(4?) — std hashes the discriminant via
// write_u8 then octets via write(&[..]). Reproduced faithfully from the
// derived SessionKey sequence: af, proto, IpAddr, IpAddr, sport, dport,
// discriminator (discriminant write_isize in std for enums — one fold),
// routing_domain.
fn hash_derived<H: Hasher>(state: &mut H, v6: bool) {
    state.write_u8(10); // addr_family AF_INET
    state.write_u8(6); // protocol TCP
    if v6 {
        state.write_u8(1); // IpAddr::V6 discriminant (Hash for IpAddr: variant index via write_u8 in std? uses write_length_prefix-free direct)
        state.write(&Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).octets());
        state.write_u8(1);
        state.write(&Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2).octets());
    } else {
        state.write_u8(0);
        state.write(&Ipv4Addr::new(10, 0, 0, 1).octets());
        state.write_u8(0);
        state.write(&Ipv4Addr::new(10, 0, 0, 2).octets());
    }
    state.write_u16(1234);
    state.write_u16(80);
    // TunnelDiscriminator::None — derived enum hash writes the variant
    // discriminant (write_isize on modern std Hash for enums).
    state.write_isize(0);
    state.write_u32(0); // routing_domain
}

fn hash_manual<H: Hasher>(state: &mut H, v6: bool) {
    let mut img = [0u8; 49];
    img[0] = 10;
    img[1] = 6;
    let (s, d): (IpAddr, IpAddr) = if v6 {
        (
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2)),
        )
    } else {
        (
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        )
    };
    let put = |slot: &mut [u8], ip: &IpAddr| match ip {
        IpAddr::V4(a) => {
            slot[0] = 4;
            slot[1..5].copy_from_slice(&a.octets());
        }
        IpAddr::V6(a) => {
            slot[0] = 6;
            slot[1..17].copy_from_slice(&a.octets());
        }
    };
    put(&mut img[2..19], &s);
    put(&mut img[19..36], &d);
    img[36..38].copy_from_slice(&1234u16.to_le_bytes());
    img[38..40].copy_from_slice(&80u16.to_le_bytes());
    state.write(&img);
}

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("session_key_hash");
    g.throughput(Throughput::Elements(1));
    for v6 in [false, true] {
        let fam = if v6 { "v6" } else { "v4" };
        g.bench_function(format!("derived_keyedfx_{fam}"), |b| {
            b.iter(|| {
                let mut h = KeyedState(42).build_hasher();
                hash_derived(&mut h, v6);
                black_box(h.finish())
            })
        });
        g.bench_function(format!("manual_keyedfx_{fam}"), |b| {
            b.iter(|| {
                let mut h = KeyedState(42).build_hasher();
                hash_manual(&mut h, v6);
                black_box(h.finish())
            })
        });
        g.bench_function(format!("derived_siphash_{fam}"), |b| {
            b.iter(|| {
                let mut h = std::collections::hash_map::DefaultHasher::new();
                hash_derived(&mut h, v6);
                black_box(h.finish())
            })
        });
        g.bench_function(format!("manual_siphash_{fam}"), |b| {
            b.iter(|| {
                let mut h = std::collections::hash_map::DefaultHasher::new();
                hash_manual(&mut h, v6);
                black_box(h.finish())
            })
        });
    }
    g.finish();
}
criterion_group!(benches, bench);
criterion_main!(benches);
