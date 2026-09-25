//! #10677: fragmented tunnel traffic to interface-NAT follows the head.
//!
//! The #304 arm shunts ESP and non-native GRE addressed to an interface-NAT
//! address to the kernel (XFRM / a kernel GRE device), keyed on the parsed
//! protocol. But #7494 substitutes the no-L4 sentinel (255) for the protocol
//! of every NON-FIRST fragment — the bytes at the resolved offset are payload,
//! not a header — so a fragmented tunnel datagram splits: the whole datagram
//! or first fragment rides the arm to the kernel while every tail misses it,
//! falls through to the AF_XDP redirect, and is refused by the helper as
//! protocol 255. The datagram never reassembles anywhere: an availability
//! hole for every tunnel endpoint sitting on an interface-NAT address (the
//! common WAN case `is_local_destination` deliberately reports false for).
//!
//! The fix is tails-follow-head, decided here on the WIRE protocol — the real
//! upper-layer protocol the parse captured before the substitution — rather
//! than on the post-substitution one:
//!
//! * an ESP tail to interface-NAT passes to the kernel, exactly as its head
//!   does, on both the healthy path and the degraded path;
//! * a GRE tail passes when native GRE is OFF, exactly as its head does. When
//!   native GRE is ON the head takes the inner-classifier branch (never the
//!   #304 arm) and lands in the helper, so the tail follows it there —
//!   the pre-#10677 behaviour, unchanged;
//! * every other tail (TCP/UDP/ICMP/..., and the wire-255 curiosity) still
//!   falls through to the helper, and the session lookup still sees the
//!   sentinel with zeroed ports — the #7494 guaranteed-miss contract is
//!   untouched. Only these two arms read the wire protocol; nothing else may.
//!
//! # Why this is a module and not two conditions at the call sites
//!
//! The shim cannot be executed by a host test: it is `no_std`, built for
//! `bpfel-unknown-none`. `tests_shim_ext_parity.rs` records what happens when
//! a shim property is guarded by a test that MODELS the shim from source text
//! instead — five successive models, each leaking to a more ordinary edit
//! than the last, including one that accepted the deletion of a security
//! property. Its resolution was to move the walk into a `core`-only module
//! (`ipv6_ext_walk.rs`) that the shim calls and a host test pulls in BY SOURCE
//! PATH and RUNS. (Described, not spelled: the #5173 confinement refusal walks
//! this directory for the attribute token itself, and prose that spells it is
//! a false red — the convention this file follows is the one stated at the top
//! of `ipv6_ext_walk.rs`.)
//!
//! This module is that shape, for the same reason. The decision below is what
//! decides whether a fragmented tunnel datagram reassembles at all, so it is
//! executed by the host test on real argument tuples rather than asserted
//! about.
//!
//! Nothing in here may take a dependency on `aya`, on a BPF map, or on `std` —
//! that is what keeps it host-compilable, and it is the whole point.

/// IANA protocol numbers this decision keys on.
///
/// Mirrored from the shim root's `PROTO_*` rather than imported: importing
/// would couple this host-compiled module to the `no_std` crate root it must
/// stay independent of. Pinned equal to userspace-dp's `ip_proto` SSOT by the
/// host test, so the mirror cannot drift silently.
pub const IP_PROTO_GRE: u8 = 47;
/// See [`IP_PROTO_GRE`].
pub const IP_PROTO_ESP: u8 = 50;
/// The #7494 no-L4 sentinel, mirrored from `PROTO_FRAGMENT_NO_L4` for the
/// same reason. 255 is IANA-Reserved and a member of neither the IPv6
/// traversable set nor any protocol the shim branches on — see
/// `ipv6_ext_walk.rs` for why that membership test is the one that matters.
pub const IP_PROTO_NO_L4: u8 = 255;

/// Healthy path (#304 arm): does tunnel traffic to an interface-NAT address
/// pass to the kernel?
///
/// `parsed_protocol` is the post-#7494 protocol (the sentinel when no L4
/// header is present, else the wire value); `wire_protocol` is the real
/// upper-layer protocol the parse captured before the substitution;
/// `native_gre_armed` is the `USERSPACE_CTRL_FLAG_NATIVE_GRE` state.
///
/// The truth table, and what each row preserves:
///
/// * `(ESP, ESP, _)` → kernel. Unchanged: the #304 head behaviour.
/// * `(255, ESP, _)` → kernel. THE ESP FIX: the tail follows its head.
/// * `(GRE, GRE, off)` → kernel. Unchanged: the #304 head behaviour. GRE
///   reaches this arm only with native GRE off (native GRE takes the
///   inner-classifier branch), so spelling the off-case keeps today's
///   behaviour exactly; the on-case below is unreachable-today
///   defence in depth, not a behaviour change.
/// * `(255, GRE, off)` → kernel. THE GRE FIX: the tail follows its head.
/// * `(255, GRE, on)` → helper. UNCHANGED: a native-GRE head lands in the
///   helper via inner classification, so the tail follows it there.
/// * `(255, anything-else, _)` → helper. UNCHANGED: the #7494 disposition
///   for every non-tunnel tail, and the wire-255 curiosity with it.
/// * anything else → helper. UNCHANGED: ordinary non-tunnel traffic.
#[inline(always)]
pub fn interface_nat_tunnel_passes_to_kernel(
    parsed_protocol: u8,
    wire_protocol: u8,
    native_gre_armed: bool,
) -> bool {
    // ESP terminates on the kernel (XFRM) unconditionally: head by the
    // parsed protocol, tail by the wire protocol it lost to the sentinel.
    if parsed_protocol == IP_PROTO_ESP
        || (parsed_protocol == IP_PROTO_NO_L4 && wire_protocol == IP_PROTO_ESP)
    {
        return true;
    }
    // GRE terminates on the kernel only when it is NOT native: native GRE
    // is userspace-terminated, and a native head never reaches this arm.
    if native_gre_armed {
        return false;
    }
    parsed_protocol == IP_PROTO_GRE
        || (parsed_protocol == IP_PROTO_NO_L4 && wire_protocol == IP_PROTO_GRE)
}

/// Degraded path (`is_degraded_local_or_control`): does ESP to an
/// interface-NAT address pass to the kernel instead of dropping?
///
/// The degraded path is fail-closed transit with destination-qualified
/// exceptions, and ESP-to-interface-NAT is one of them — for the head. The
/// tail took the drop. Same hole, same fix: the tail follows its head.
///
/// GRE is deliberately ABSENT here, and that is tails-follow-head too: on
/// the degraded path a non-native GRE HEAD is dropped by design (the GRE
/// arm requires the native flag plus an inner PASS_TO_KERNEL), so a GRE
/// tail dropping beside it is the consistent disposition, not a second
/// hole. A native-GRE tail cannot be inner-classified — there is no inner
/// header in a tail — so it keeps today's drop; closing that needs
/// head-disposition state the shim does not keep, and is out of scope.
#[inline(always)]
pub fn degraded_interface_nat_esp_passes_to_kernel(
    parsed_protocol: u8,
    wire_protocol: u8,
) -> bool {
    parsed_protocol == IP_PROTO_ESP
        || (parsed_protocol == IP_PROTO_NO_L4 && wire_protocol == IP_PROTO_ESP)
}
