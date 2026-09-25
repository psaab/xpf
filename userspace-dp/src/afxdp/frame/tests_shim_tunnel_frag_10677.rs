// #10677: fragmented ESP/GRE to interface-NAT keeps every fragment on the
// endpoint's selected kernel/helper path. Execute the exact core-only
// predicates called by the shim; do not model the decision here.
#[path = "../../../../userspace-xdp/src/tunnel_frag.rs"]
mod shim_tunnel_frag;
#[path = "../../../../userspace-xdp/src/ipv6_ext_walk.rs"]
mod shim_ipv6_ext_walk;

use shim_tunnel_frag::{
    IP_PROTO_ESP, IP_PROTO_GRE, IP_PROTO_NO_L4, degraded_interface_nat_esp_passes_to_kernel,
    interface_nat_tunnel_passes_to_kernel,
};

/// #10677 fail-on-revert: the #304 head goes to the kernel, and a #7494 tail
/// whose parsed protocol is 255 must follow it for ESP and non-native GRE.
/// Restoring the old parsed-protocol-only arm makes the tail rows RED. Native
/// GRE and non-tunnel fragments remain on the helper path.
#[test]
fn interface_nat_tunnel_fragments_follow_head_disposition_10677() {
    assert_eq!(IP_PROTO_GRE, crate::ip_proto::PROTO_GRE);
    assert_eq!(IP_PROTO_ESP, crate::ip_proto::PROTO_ESP);
    assert_eq!(IP_PROTO_NO_L4, shim_ipv6_ext_walk::PROTO_FRAGMENT_NO_L4);
    let cases = [
        // Parsed protocol, real wire protocol, native GRE armed, kernel.
        (
            IP_PROTO_ESP,
            IP_PROTO_ESP,
            false,
            true,
            "whole ESP goes to XFRM",
        ),
        (
            IP_PROTO_ESP,
            IP_PROTO_ESP,
            true,
            true,
            "ESP is kernel-terminated even with native GRE",
        ),
        (
            IP_PROTO_NO_L4,
            IP_PROTO_ESP,
            false,
            true,
            "ESP tail follows its kernel-bound head",
        ),
        (
            IP_PROTO_NO_L4,
            IP_PROTO_ESP,
            true,
            true,
            "ESP tail remains kernel-bound",
        ),
        (
            IP_PROTO_GRE,
            IP_PROTO_GRE,
            false,
            true,
            "non-native GRE head goes to kernel",
        ),
        (
            IP_PROTO_NO_L4,
            IP_PROTO_GRE,
            false,
            true,
            "non-native GRE tail follows its head",
        ),
        (
            IP_PROTO_NO_L4,
            IP_PROTO_GRE,
            true,
            false,
            "native GRE tail follows helper-bound head",
        ),
        (IP_PROTO_NO_L4, 6, false, false, "TCP tail remains on helper path"),
        (
            IP_PROTO_NO_L4,
            IP_PROTO_NO_L4,
            false,
            false,
            "wire 255 is not a tunnel protocol",
        ),
        (6, 6, false, false, "whole TCP is unaffected"),
    ];
    for (parsed, wire, native_gre, kernel, why) in cases {
        assert_eq!(
            interface_nat_tunnel_passes_to_kernel(parsed, wire, native_gre),
            kernel,
            "{why}: parsed={parsed} wire={wire} native_gre={native_gre}",
        );
    }
}

/// #10677 fail-on-revert on the degraded twin: ESP interface-NAT fragments
/// must not be dropped when the healthy shim is unavailable. GRE remains
/// governed by the existing degraded-path policy (both head and tails drop).
#[test]
fn degraded_interface_nat_esp_fragment_follows_kernel_head_10677() {
    let cases = [
        (IP_PROTO_ESP, IP_PROTO_ESP, true),
        (IP_PROTO_NO_L4, IP_PROTO_ESP, true),
        (IP_PROTO_NO_L4, IP_PROTO_GRE, false),
        (IP_PROTO_NO_L4, 6, false),
    ];
    for (parsed, wire, kernel) in cases {
        assert_eq!(
            degraded_interface_nat_esp_passes_to_kernel(parsed, wire),
            kernel,
            "parsed={parsed} wire={wire}",
        );
    }
}
