// #10640: the shim's early kernel-pass destination filter, EXECUTED.
//
// `should_fallback_early` hands a packet to the kernel BEFORE any session
// lookup, so its predicate is a security boundary. It used to name two
// classes that bypassed the userspace policy engine entirely: IPv4
// 169.254/16 unicast with no destination-locality test, and ICMPv6 NDP
// types 133-137 on a TYPE-ONLY test with no destination predicate at all.
// A SYN to a routable non-local 169.254 address (executed: 169.254.7.9)
// or NDP to a transit destination rode the kernel forward path plus the
// armed fence's ingress-name pinhole with no zone policy.
//
// WHY THIS FILE INCLUDES THE SHIM'S SOURCE AND RUNS IT: same shape as
// `tests_shim_wg_classify_8274.rs` — the shim is `no_std` for
// `bpfel-unknown-none` and cannot be executed by a host test, and the
// ext-parity record shows modeled tests leaking to ordinary edits. The
// verdict lives in the `core`-only `early_filter` module the shim calls;
// this file pulls that file in by source and runs it on real values.
//
// The wiring (lib.rs calls the module) is pinned by the dead-code
// eliminator: the module's fns are `pub`-in-private-module, so unwiring
// them trips `dead_code`. The NDP half holds by signature — the module
// takes no ICMP type at all, so no type-only arm can exist on the path.
#[path = "../../../../userspace-xdp/src/early_filter.rs"]
mod shim_early;

use shim_early::{
    ipv4_early_pass_to_kernel, ipv6_early_pass_to_kernel, is_ipv4_link_local,
    is_ipv4_multicast, is_ipv6_link_local, is_ipv6_multicast,
};

/// The issue's executed repro, both families' bypass shapes: link-local
/// unicast and transit-destination NDP must NOT pass early. Every fixture
/// is validity-pinned through the module's own classifiers rather than
/// trusting hand hex.
#[test]
fn link_local_unicast_and_transit_ndp_do_not_pass_early_10640() {
    // IPv4 169.254/16 unicast: the SYN-to-169.254.7.9 repro plus the range
    // edges. All link-local, none passed.
    for dst in [0xa9fe_0709u32, 0xa9fe_0001, 0xa9fe_ffff, 0xa9fe_8000] {
        assert!(
            is_ipv4_link_local(dst),
            "fixture {dst:#010x} must really be link-local, or the verdict below is vacuous"
        );
        assert!(
            !is_ipv4_multicast(dst),
            "fixture {dst:#010x} must not be multicast, or the verdict below passes for the wrong reason"
        );
        assert!(
            !ipv4_early_pass_to_kernel(dst),
            "link-local unicast {dst:#010x} must fall through to the session-miss path, \
             never pass early with no locality test (#10640)"
        );
    }
    // Ordinary unicast is not passed either (control: the fix did not
    // become a blanket pass by deleting the arm).
    for dst in [0x0a00_0001u32, 0xc0a8_0001, 0xac10_50c8] {
        assert!(
            !is_ipv4_link_local(dst) && !is_ipv4_multicast(dst),
            "fixture {dst:#010x} must be ordinary unicast"
        );
        assert!(
            !ipv4_early_pass_to_kernel(dst),
            "ordinary unicast {dst:#010x} must not pass early"
        );
    }
    // IPv6 transit/global: NDP takes no type on this path, so a global
    // destination is the whole decision — it must not pass.
    for dst in [
        [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0x61, 0, 0, 0, 0, 0, 0, 0x01, 0x02],
    ] {
        assert!(
            !is_ipv6_multicast(dst) && !is_ipv6_link_local(dst),
            "fixture {dst:?} must be global/transit"
        );
        assert!(
            !ipv6_early_pass_to_kernel(dst),
            "a transit IPv6 destination must continue to the AF_XDP redirect \
             for adjudication, never pass early (#10640)"
        );
    }
}

/// THE PRESERVED HALF: limited broadcast, multicast, and IPv6
/// link-local still pass early. Without this, deleting the verdict
/// function (fail-everything-closed) would satisfy the cell above while
/// breaking DHCP, multicast NDP, and link-local control plane.
#[test]
fn broadcast_multicast_and_v6_link_local_still_pass_early_10640() {
    assert!(
        ipv4_early_pass_to_kernel(0xffff_ffff),
        "limited broadcast must still pass early"
    );
    for dst in [0xe000_0001u32, 0xe000_00fb, 0xef01_0203] {
        assert!(
            is_ipv4_multicast(dst),
            "fixture {dst:#010x} must really be multicast"
        );
        assert!(
            ipv4_early_pass_to_kernel(dst),
            "IPv4 multicast {dst:#010x} must still pass early"
        );
    }
    // Multicast NDP (solicited-node, all-nodes, all-routers): the arm that
    // still delivers NDP now that the type-only arm is deleted.
    for dst in [
        [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff, 0x00, 0x00, 0x01],
        [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01],
        [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02],
    ] {
        assert!(
            is_ipv6_multicast(dst),
            "fixture {dst:?} must really be multicast"
        );
        assert!(
            ipv6_early_pass_to_kernel(dst),
            "multicast NDP must still pass early"
        );
    }
    for dst in [
        [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        [0xfe, 0xb0, 0, 0, 0, 0, 0, 0, 0x02, 0xbf, 0x72, 0x01, 0x00, 0x01, 0x00, 0x01],
    ] {
        assert!(
            is_ipv6_link_local(dst),
            "fixture {dst:?} must really be link-local"
        );
        assert!(
            ipv6_early_pass_to_kernel(dst),
            "IPv6 link-local must still pass early"
        );
    }
    // fe80::/10 boundary: febf:: is link-local, fec0:: is not (site-local
    // range, must fall through).
    assert!(
        ipv6_early_pass_to_kernel([0xfe, 0xbf, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
        "febf::/10 edge must still pass early"
    );
    assert!(
        !ipv6_early_pass_to_kernel([0xfe, 0xc0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
        "fec0:: is outside fe80::/10 and must fall through"
    );
}
