//! #17124 (R4-Q47-08): shared deterministic-NAT golden vectors.
//!
//! Loads `userspace-dp/tests/fixtures/deterministic_nat_vectors_v1.json`
//! from `tests/fixtures/` — the SAME file the Go test
//! `TestDeterministicNATVectorsSharedFixture17124` in
//! `pkg/nat/deterministic_vectors_17124_test.go` loads. Neither side keeps
//! a copied table, so mutating any expected value in the fixture turns
//! BOTH the cargo test and the `go test` RED.
//!
//! This test drives the pure allocator functions in
//! `nat/allocator/deterministic.rs` (`deterministic_indices_v4/v6`,
//! `reverse_deterministic_v4/v6`, `build_pool_reverse_index`) plus the
//! pool-expansion semantics the Go `expandPoolV4` mirrors: mode-1
//! first-occurrence dedupe (`nat/source/expand.rs` `expand_pool_address`
//! with its production seen-set) and mode-2 NAT64 `parse_pool_v4`
//! first-occurrence dedupe (`nat64/state.rs`, #14624).
//!
//! The fixture rows include the three historical Go/Rust divergences:
//! #9498 (reverse index wrap), #14623/#14624 (duplicate pool members),
//! and #15283 (narrowed pool port range).

use super::super::source::expand_pool_address;
use super::deterministic::{
    build_pool_reverse_index, deterministic_indices_v4, deterministic_indices_v6,
    reverse_deterministic_v4, reverse_deterministic_v6, DeterministicV4, DeterministicV6,
};
use serde_json::Value;
use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr};

/// Mode-2 pool-member parse, mirroring `nat64/state.rs` `parse_pool_v4`:
/// a bare IPv4 address or an explicit `/32` only; anything else is not a
/// NAT64 allocator member. Kept local so this test adds no production
/// visibility widening; the member shapes are also pinned end-to-end by
/// the Go mode-2 expansion checks on the same fixture.
fn parse_pool_v4_nat64(s: &str) -> Option<Ipv4Addr> {
    let mut parts = s.splitn(2, '/');
    let addr: Ipv4Addr = parts.next()?.parse().ok()?;
    match parts.next() {
        None => Some(addr),
        Some("32") => Some(addr),
        Some(_) => None,
    }
}

fn load_fixture() -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("deterministic_nat_vectors_v1.json");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {}", path.display(), e))
}

fn v4(s: &str) -> Ipv4Addr {
    s.parse().unwrap_or_else(|_| panic!("bad ipv4 {s}"))
}
fn v6(s: &str) -> Ipv6Addr {
    s.parse().unwrap_or_else(|_| panic!("bad ipv6 {s}"))
}
fn u32f(v: &Value, k: &str) -> u32 {
    v.get(k)
        .and_then(Value::as_u64)
        .unwrap_or_else(|| panic!("missing numeric field {k} in {v}")) as u32
}
fn u16f(v: &Value, k: &str) -> u16 {
    u32f(v, k) as u16
}
fn opt_str(v: &Value, k: &str) -> Option<String> {
    match v.get(k) {
        Some(Value::Null) | None => None,
        Some(Value::String(s)) => Some(s.clone()),
        other => panic!("field {k} must be string or null, got {other:?}"),
    }
}

/// Expand one vector's `pool_spec` into the ordered allocator pool using
/// the mode-correct production semantics.
fn expand_pool(vec: &Value) -> Vec<Ipv4Addr> {
    let mode = u32f(vec, "mode");
    let spec: Vec<String> = vec["pool_spec"]
        .as_array()
        .expect("pool_spec array")
        .iter()
        .map(|m| m.as_str().expect("pool member string").to_string())
        .collect();
    match mode {
        1 => {
            // Mode 1: production caller threads seen-sets through
            // expand_pool_address (first occurrence wins, #14623).
            let mut out4 = Vec::new();
            let mut out6 = Vec::new();
            let mut seen4 = rustc_hash::FxHashSet::default();
            let mut seen6 = rustc_hash::FxHashSet::default();
            for m in &spec {
                assert!(
                    expand_pool_address(m, &mut out4, &mut out6, &mut seen4, &mut seen6),
                    "mode-1 pool member {m:?} must expand (vector {})",
                    vec["id"]
                );
            }
            assert!(out6.is_empty(), "mode-1 pool must be IPv4-only");
            out4
        }
        2 => {
            // Mode 2: NAT64 parse_pool_v4 accepts bare hosts and /32s
            // only, first occurrence wins (#14624).
            let mut seen = HashSet::new();
            let mut out = Vec::new();
            for m in &spec {
                let a = parse_pool_v4_nat64(m).unwrap_or_else(|| {
                    panic!("mode-2 pool member {m:?} must parse (vector {})", vec["id"])
                });
                if seen.insert(a) {
                    out.push(a);
                }
            }
            out
        }
        other => panic!("unknown mode {other}"),
    }
}

struct Ctx {
    mode: u32,
    pool: Vec<Ipv4Addr>,
    port_low: u16,
    det4: Option<DeterministicV4>,
    det6: Option<DeterministicV6>,
}

fn ctx(vec: &Value) -> Ctx {
    let mode = u32f(vec, "mode");
    let pool = expand_pool(vec);
    // pool_expanded / pool_len pins.
    if let Some(exp) = vec.get("pool_expanded") {
        let want: Vec<Ipv4Addr> = exp
            .as_array()
            .expect("pool_expanded array")
            .iter()
            .map(|a| v4(a.as_str().expect("pool addr string")))
            .collect();
        assert_eq!(pool, want, "pool expansion drift (vector {})", vec["id"]);
    }
    if let Some(len) = vec.get("pool_len") {
        assert_eq!(
            pool.len() as u64,
            len.as_u64().expect("pool_len number"),
            "pool_len drift (vector {})",
            vec["id"]
        );
    }
    let port_low = u16f(vec, "port_low");
    let port_high = u16f(vec, "port_high");
    let block_size = u16f(vec, "block_size");
    let bpi = ((port_high as u32 - port_low as u32 + 1) / block_size as u32) as u16;
    assert!(bpi > 0, "degenerate blocks_per_ip (vector {})", vec["id"]);
    let host_prefix = vec["host_prefix"].as_str().expect("host_prefix string");
    match mode {
        1 => {
            let (addr, plen) = host_prefix
                .split_once('/')
                .expect("v4 host_prefix must be CIDR");
            let plen: u32 = plen.parse().expect("v4 prefix len");
            assert!(plen <= 32);
            let host_count = 1u32 << (32 - plen);
            // Mask the base exactly as a CIDR network base.
            let base_raw = u32::from(v4(addr));
            let base = if plen == 0 {
                0
            } else {
                base_raw & (!0u32 << (32 - plen))
            };
            Ctx {
                mode,
                pool,
                port_low,
                det4: Some(DeterministicV4 {
                    block_size,
                    blocks_per_ip: bpi,
                    host_base: base,
                    host_count,
                }),
                det6: None,
            }
        }
        2 => {
            let (addr, plen) = host_prefix
                .split_once('/')
                .expect("v6 host_prefix must be CIDR");
            let plen: u8 = plen.parse().expect("v6 prefix len");
            assert!(plen == 32 || plen == 64, "v6 prefix must be /32 or /64");
            let host_count = (pool.len() as u32)
                .checked_mul(bpi as u32)
                .expect("mode-2 host_count overflow");
            Ctx {
                mode,
                pool,
                port_low,
                det4: None,
                det6: Some(DeterministicV6 {
                    block_size,
                    blocks_per_ip: bpi,
                    host_prefix_len: plen,
                    host_base: v6(addr).octets(),
                    host_count,
                }),
            }
        }
        other => panic!("unknown mode {other}"),
    }
}

#[test]
fn deterministic_nat_vectors_fixture_17124() {
    let raw = load_fixture();
    let doc: Value = serde_json::from_str(&raw).expect("fixture parses");
    let vectors = doc["vectors"].as_array().expect("vectors array");
    assert!(
        vectors.len() >= 8,
        "fixture must carry at least 8 vectors, got {}",
        vectors.len()
    );
    let mut ids = HashSet::new();
    let (mut fwd_checked, mut rev_checked) = (0usize, 0usize);
    for vec in vectors {
        let id = vec["id"].as_str().expect("vector id");
        assert!(ids.insert(id.to_string()), "duplicate vector id {id}");
        let c = ctx(vec);
        let index = build_pool_reverse_index(&c.pool);

        for row in vec["forward"].as_array().expect("forward array") {
            fwd_checked += 1;
            let sub = row["subscriber"].as_str().expect("subscriber string");
            let want_ext = opt_str(row, "external_ip");
            // Index-level expectation (when the fixture pins it).
            let want_idx = match (row.get("sub_idx"), row.get("ip_idx")) {
                (Some(Value::Null), _) | (_, Some(Value::Null)) => None,
                (Some(_), Some(_)) => Some((u32f(row, "ip_idx") as usize, u32f(row, "block_idx"))),
                _ => None,
            };
            match c.mode {
                1 => {
                    let det = c.det4.unwrap();
                    let got = deterministic_indices_v4(&det, v4(sub));
                    assert_eq!(got, want_idx, "v4 forward indices for {sub} (vector {id})");
                    match (got, &want_ext) {
                        (Some((ip_idx, _)), Some(ext)) => {
                            assert!(ip_idx < c.pool.len(), "ip_idx in pool (vector {id})");
                            assert_eq!(
                                c.pool[ip_idx],
                                v4(ext),
                                "v4 forward external for {sub} (vector {id})"
                            );
                        }
                        (Some(_), None) => {
                            // Indices exist but name no pool address: the
                            // caller fails closed (Go: out-of-range).
                        }
                        (None, Some(ext)) => {
                            panic!("v4 forward for {sub} returned None, want {ext} (vector {id})")
                        }
                        (None, None) => {}
                    }
                }
                2 => {
                    let det = c.det6.unwrap();
                    let got = deterministic_indices_v6(&det, v6(sub));
                    assert_eq!(got, want_idx, "v6 forward indices for {sub} (vector {id})");
                    match (got, &want_ext) {
                        (Some((ip_idx, _)), Some(ext)) => {
                            assert!(ip_idx < c.pool.len(), "ip_idx in pool (vector {id})");
                            assert_eq!(
                                c.pool[ip_idx],
                                v4(ext),
                                "v6 forward external for {sub} (vector {id})"
                            );
                        }
                        (Some(_), None) => {}
                        (None, Some(ext)) => {
                            panic!("v6 forward for {sub} returned None, want {ext} (vector {id})")
                        }
                        (None, None) => {}
                    }
                }
                _ => unreachable!(),
            }
            if let Some(ext) = &want_ext {
                assert_eq!(
                    row["port_low"].as_u64().expect("port_low"),
                    c.port_low as u64
                        + u32f(row, "block_idx") as u64 * vec["block_size"].as_u64().unwrap(),
                    "forward block low for {sub} (vector {id}); external {ext}"
                );
            }
        }

        for row in vec["reverse"].as_array().expect("reverse array") {
            rev_checked += 1;
            let ext = v4(row["external_ip"].as_str().expect("external_ip string"));
            let port = u16f(row, "port");
            let want = opt_str(row, "subscriber");
            match c.mode {
                1 => {
                    let got =
                        reverse_deterministic_v4(&c.det4.unwrap(), &index, c.port_low, ext, port);
                    assert_eq!(
                        got.map(|a| a.to_string()),
                        want,
                        "v4 reverse for {ext}:{port} (vector {id})"
                    );
                }
                2 => {
                    let got =
                        reverse_deterministic_v6(&c.det6.unwrap(), &index, c.port_low, ext, port);
                    assert_eq!(
                        got.map(|a| a.to_string()),
                        want,
                        "v6 reverse for {ext}:{port} (vector {id})"
                    );
                }
                _ => unreachable!(),
            }
        }
    }
    assert!(fwd_checked >= 20, "too few forward rows: {fwd_checked}");
    assert!(rev_checked >= 15, "too few reverse rows: {rev_checked}");
    // The three historical divergences must stay represented.
    for needle in ["9498", "14623", "15283", "14624"] {
        assert!(
            ids.iter().any(|i| i.contains(needle)),
            "fixture lost the #{needle} vector"
        );
    }
}
