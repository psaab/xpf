//! #10640: the shim's early kernel-pass destination filter.
//!
//! `should_fallback_early` hands a packet to the kernel BEFORE any session
//! lookup, so its predicate is a security boundary: every address class it
//! names bypasses the userspace policy engine entirely. Two of the classes
//! the early path used to name did not survive review:
//!
//! * IPv4 169.254/16 unicast, matched with no destination-locality test, so
//!   a SYN to a routable NON-local 169.254 address on a tracked-XDP ingress
//!   rode the kernel forward path plus the armed fence's ingress-name
//!   pinhole with no zone policy — the same shape #304 closed for ESP and
//!   non-native GRE. Genuinely local 169.254 destinations are unaffected:
//!   an assigned link-local address is a member of `userspace_local_v4`
//!   (the Go sync enumerates every kernel address with no link-local
//!   exclusion), so the session-miss path's `is_local_destination` arm
//!   still delivers it to the kernel.
//! * ICMPv6 NDP types 133-137, matched on TYPE alone with no destination
//!   predicate at all. That arm is deleted, not moved here. What remains
//!   for NDP is exactly the destination predicate below: multicast NDP
//!   (solicited-node, all-nodes, all-routers) still passes early, unicast
//!   NDP to a firewall-local address passes via `is_local_destination`,
//!   and NDP to a transit destination continues to the AF_XDP redirect
//!   for adjudication by the worker.
//!
//! # Why this is a module and not two arms inside `should_fallback_early`
//!
//! Same reason as `wg_classify` and `ipv6_ext_walk`: the shim is `no_std`
//! for `bpfel-unknown-none` and cannot be executed by a host test, and a
//! test that MODELS the predicate from source text leaks to ordinary edits
//! (the ext-parity file records five such leaks, the worst accepting the
//! deletion of a security property). Everything the decision needs is in
//! this file, it depends only on `core`, and the userspace-dp regression
//! test pulls THIS FILE in by source and RUNS it on real address values.
//! (Wording, here and at the `lib.rs` call site, steers around the
//! confinement token pair #5173 refuses under this directory — see the top
//! of `ipv6_ext_walk.rs` for the rule this file follows.)
//!
//! Nothing in here may take a dependency on `aya`, on a BPF map, or on
//! `std` — that is what keeps it host-compilable, and it is the whole
//! point. `is_local_destination` stays at the call site for exactly that
//! reason: it reads BPF maps this module cannot see. What this module owns
//! is that the link-local answer is no longer CONSULTED for IPv4 at all,
//! and that no ICMPv6 type test exists anywhere on the early path.

/// Is this big-endian IPv4 destination a multicast address (224.0.0.0/4)?
///
/// Byte order is load-bearing: `parse_ipv4` stores `dst_v4` big-endian
/// (`u32::from_be_bytes` of the header octets, the same encoding Go uses
/// for the `userspace_local_v4` keys), so the mask below reads the wire
/// order. A native-endian fixture on a little-endian host would void every
/// cell below it — the host test pins each fixture through these same
/// predicates rather than trusting its own hex.
#[inline(always)]
pub fn is_ipv4_multicast(ip: u32) -> bool {
    (ip & 0xf000_0000) == 0xe000_0000
}

/// Is this big-endian IPv4 destination link-local (169.254.0.0/16)?
///
/// Moved verbatim; the #10640 change is that the early filter no longer
/// CALLS it. It stays `pub` for the host test's fixture-validity asserts —
/// proving the "not passed" fixtures really are link-local — in the same
/// way `wg_classify` keeps its message-type consts for its own test.
#[inline(always)]
// Test-only by design (see doc above): the shim must NOT call this, so the
// dead-code lint would fire on every shim build without the allow.
#[allow(dead_code)]
pub fn is_ipv4_link_local(ip: u32) -> bool {
    (ip & 0xffff_0000) == 0xa9fe_0000
}

/// Is this IPv6 destination a multicast address (ff00::/8)?
#[inline(always)]
pub fn is_ipv6_multicast(ip: [u8; 16]) -> bool {
    ip[0] == 0xff
}

/// Is this IPv6 destination link-local (fe80::/10)?
#[inline(always)]
pub fn is_ipv6_link_local(ip: [u8; 16]) -> bool {
    ip[0] == 0xfe && (ip[1] & 0xc0) == 0x80
}

/// #10640: the IPv4 early kernel-pass verdict.
///
/// Limited broadcast and multicast pass. EVERYTHING else — including the
/// whole 169.254.0.0/16 — falls through to the session-miss path, where
/// `is_local_destination` still delivers genuinely local destinations to
/// the kernel and the remainder continues to the AF_XDP redirect for
/// adjudication. There is deliberately no link-local arm here any more:
/// scope alone never made a destination local to THIS box.
#[inline(always)]
pub fn ipv4_early_pass_to_kernel(dst_v4: u32) -> bool {
    dst_v4 == 0xffff_ffff || is_ipv4_multicast(dst_v4)
}

/// The IPv6 early kernel-pass verdict, UNCHANGED by #10640.
///
/// Multicast and link-local destinations pass early — that is the arm that
/// still delivers multicast NDP now that the type-only NDP arm is deleted.
/// A global/transit destination answers false here, which for an NDP packet
/// is the whole early decision: it continues to the AF_XDP redirect.
#[inline(always)]
pub fn ipv6_early_pass_to_kernel(dst: [u8; 16]) -> bool {
    is_ipv6_multicast(dst) || is_ipv6_link_local(dst)
}
