// #13953: execute the shim's LAND predicate on the host.
//
// #11087 put the unconditional LAND drop only on the healthy shim's
// established PASS_TO_KERNEL arm, because a live PASS row is terminal there
// and never reaches worker screen stage 10. Every other shim arm that hands
// a packet to the kernel has the same property: the healthy session-miss
// local-destination and ICMP-to-interface-NAT-local arms, the WireGuard
// steer fallthrough, the early-filter pass, and the whole degraded
// (control-disabled / binding / heartbeat) path, whose local/control
// predicate has no session dimension at all. The Linux stack has no IPv6
// LAND backstop: a src == dst IPv6 packet to a firewall-local address was
// delivered to local sockets on every one of those arms.
//
// The verdict lives in the `core`-only `land` module the shim calls before
// every kernel pass (healthy gate after the tagged-only VID-0 drop, plus
// the ctrl-disabled path); this file pulls that file in by source and runs
// it on the exact 16-byte address fields `ParsedPacket` carries, so the
// comparison executed here is the comparison the shim performs.
#[path = "../../../../userspace-xdp/src/land.rs"]
mod shim_land;

use shim_land::{
    LAND_SCREEN_ALARM, LAND_SCREEN_DROP, LAND_SCREEN_PASS, LandDisposition, is_land,
    land_disposition,
};

fn v4(a: u8, b: u8, c: u8, d: u8) -> [u8; 16] {
    let mut buf = [0u8; 16];
    buf[..4].copy_from_slice(&[a, b, c, d]);
    buf
}

fn v6(bytes: [u8; 16]) -> [u8; 16] {
    bytes
}

/// #13953 fail-on-revert: equal source/destination, both families, is LAND.
/// Deleting the shim's gate (or reverting `is_land` to `false`) makes every
/// equal-address row below RED: on master those packets pass to the kernel.
#[test]
fn equal_source_destination_is_land_13953() {
    // IPv6 src == dst to a firewall-local (non-NAT) address — the
    // demonstrated H13-03 consequence.
    let local6 = v6([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    assert!(is_land(&local6, &local6), "IPv6 src==dst must be LAND");

    // IPv6 link-local equal pair.
    let link6 = v6([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    assert!(is_land(&link6, &link6), "IPv6 link-local src==dst must be LAND");

    // IPv4 equal pair in the first-four-bytes encoding.
    assert!(is_land(&v4(192, 0, 2, 1), &v4(192, 0, 2, 1)), "IPv4 src==dst must be LAND");

    // IPv4 0.0.0.0 == 0.0.0.0.
    assert!(is_land(&v4(0, 0, 0, 0), &v4(0, 0, 0, 0)), "IPv4 unspecified src==dst must be LAND");
}

/// The preserved half: distinct addresses are never LAND, including the
/// near-miss shapes that must keep reaching local sockets.
#[test]
fn distinct_addresses_are_not_land_13953() {
    let local6 = v6([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    let peer6 = v6([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    assert!(!is_land(&peer6, &local6), "ordinary IPv6 host-bound traffic must pass");
    assert!(!is_land(&local6, &peer6), "reversed IPv6 pair must pass");

    assert!(!is_land(&v4(192, 0, 2, 2), &v4(192, 0, 2, 1)), "ordinary IPv4 host-bound traffic must pass");
    // One-byte-different IPv4 must not be caught by a prefix compare.
    assert!(!is_land(&v4(192, 0, 2, 1), &v4(192, 0, 2, 2)), "last-octet difference must pass");
    // An IPv4 address and its IPv6-mapped spelling differ in the full
    // 16-byte field and are not LAND.
    let mapped = v6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 0, 2, 1]);
    assert!(!is_land(&v4(192, 0, 2, 1), &mapped), "cross-family spellings must pass");
}

/// #15789 fail-on-revert: the published disposition byte decides the
/// shim's LAND verdict for a resolved zone. Reverting
/// `land_disposition` to always-Drop (the #13953 unconditional
/// behaviour) makes the PASS and ALARM rows RED; dropping the
/// unresolved-zone fail-closed arm makes the last rows RED.
#[test]
fn land_disposition_follows_published_screen_byte_15789() {
    assert_eq!(
        land_disposition(true, LAND_SCREEN_DROP),
        LandDisposition::Drop,
        "LAND enabled without audit mode must drop at the shim"
    );
    assert_eq!(
        land_disposition(true, LAND_SCREEN_ALARM),
        LandDisposition::AlarmPass,
        "LAND enabled under alarm-without-drop must alarm and pass"
    );
    assert_eq!(
        land_disposition(true, LAND_SCREEN_PASS),
        LandDisposition::Pass,
        "LAND disabled must pass unscreened at the shim"
    );
    // Unresolved zone: no WG ingress-zone row named a zone, so no
    // published byte may admit the packet — fail closed to Drop
    // (#13953 posture for unscreened zones and version skew).
    assert_eq!(
        land_disposition(false, LAND_SCREEN_PASS),
        LandDisposition::Drop,
        "unresolved zone must fail closed even with a PASS byte"
    );
    assert_eq!(
        land_disposition(false, LAND_SCREEN_ALARM),
        LandDisposition::Drop,
        "unresolved zone must fail closed even with an ALARM byte"
    );
    // Unrecognised bytes fail closed too: a corrupt/future value must
    // never turn the shim fail-open.
    assert_eq!(
        land_disposition(true, 0xff),
        LandDisposition::Drop,
        "unknown disposition byte must fail closed to drop"
    );
}
