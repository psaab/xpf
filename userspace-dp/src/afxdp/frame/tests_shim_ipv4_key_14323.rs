// #14323: the IPv4 BPF map-key encoding, EXECUTED across all three sites.
//
// `classify_native_gre_inner_ipv4` (userspace-xdp/src/lib.rs) and
// `parse_ipv4` both derive the `dnat_table` / `userspace_interface_nat_v4`
// / `userspace_local_v4` probe key from the inner/header destination
// octets; `shim_v4_key` (wg_control/kernel_path.rs) derives the same key
// from an `Ipv4Addr` for the WG kernel path. Go writes those maps with
// `binary.BigEndian.Uint32`. Two of the three sites used
// `u32::from_ne_bytes`, byte-reversing every non-palindromic address on
// little-endian hosts: real local destinations missed, and transit
// destinations whose reversal was local were falsely claimed.
//
// WHY THIS FILE INCLUDES THE SHIM'S SOURCE AND RUNS IT: same shape as
// `tests_shim_early_filter_10640.rs` — the shim is `no_std` for
// `bpfel-unknown-none` and cannot be executed by a host test, and modeled
// tests leak to ordinary edits. The encoding lives in the `core`-only
// `ipv4_key` module the shim calls (both `parse_ipv4` and the GRE-inner
// classifier route through it); this file pulls that file in by source
// and runs it against the production `shim_v4_key` and the Go writer's
// encoding. The module's fns are `pub`-in-private-module, so unwiring
// them from lib.rs trips `dead_code`, exactly as the early_filter host
// test relies on.
//
// RED on revert: restore `from_ne_bytes` in `ipv4_key.rs` (or in
// `shim_v4_key`) and the non-palindromic cells below fail —
// 172.16.80.8 encodes as 0x0850_10ac instead of 0xac10_5008.
#[path = "../../../../userspace-xdp/src/ipv4_key.rs"]
mod shim_ipv4_key;
use crate::afxdp::coordinator::shim_v4_key;
use shim_ipv4_key::ipv4_map_key;
use std::net::Ipv4Addr;

/// The Go writer's encoding (`binary.BigEndian.Uint32` in maps_sync.go),
/// restated as bytes so the fixture does not trust either Rust site.
fn go_writer_key(octets: [u8; 4]) -> u32 {
    u32::from_be_bytes(octets)
}

#[test]
fn ipv4_map_key_matches_go_writer_and_shim_v4_key_14323() {
    // Non-palindromic fixtures: byte reversal changes the key, so a
    // native-endian regression cannot pass. Includes the issue's
    // decisive address and the WG inner fixture's destination.
    for octets in [
        [172, 16, 80, 8],
        [10, 95, 21, 1],
        [203, 0, 113, 9],
        [192, 0, 2, 1],
        [8, 80, 16, 172], // byte-reversal of the first fixture
    ] {
        let want = go_writer_key(octets);
        assert_eq!(
            ipv4_map_key(octets),
            want,
            "ipv4_key (parse_ipv4 / GRE-inner) disagrees with Go BigEndian writer for {octets:?}"
        );
        assert_eq!(
            shim_v4_key(Ipv4Addr::from(octets)),
            want,
            "shim_v4_key (WG kernel path) disagrees with Go BigEndian writer for {octets:?}"
        );
        assert_eq!(
            ipv4_map_key(octets),
            shim_v4_key(Ipv4Addr::from(octets)),
            "parse_ipv4/GRE-inner and WG kernel-path keys disagree for {octets:?}"
        );
    }
    // The issue's decisive literal.
    assert_eq!(ipv4_map_key([172, 16, 80, 8]), 0xac10_5008);
    assert_eq!(shim_v4_key(Ipv4Addr::new(172, 16, 80, 8)), 0xac10_5008);
}

#[test]
fn ipv4_map_key_palindromic_controls_14323() {
    // Byte-reversal-invariant addresses pass under either encoding; they
    // pin that the fix did not disturb the already-correct cases.
    for octets in [[0, 0, 0, 0], [255, 255, 255, 255], [10, 1, 1, 10]] {
        assert_eq!(ipv4_map_key(octets), go_writer_key(octets));
        assert_eq!(shim_v4_key(Ipv4Addr::from(octets)), go_writer_key(octets));
    }
}

#[test]
fn byte_reversed_transit_is_not_the_local_key_14323() {
    // The false-admission half: a transit destination d.c.b.a must not
    // produce the key Go wrote for the local address a.b.c.d.
    let local = go_writer_key([172, 16, 80, 8]);
    assert_ne!(ipv4_map_key([8, 80, 16, 172]), local);
    assert_ne!(shim_v4_key(Ipv4Addr::new(8, 80, 16, 172)), local);
}
