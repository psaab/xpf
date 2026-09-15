//! #8274 step 2: the shim's WireGuard record classification.
//!
//! WireGuard's two directions are asymmetric. ENCAP already runs inside the
//! AF_XDP worker, on a packet that has been through screen, session, route,
//! policy and NAT. DECAP does not: the shim steers every UDP datagram on the
//! WireGuard listen port to the kernel, the control thread's socket reads it,
//! `try_decap` authenticates it, and the plaintext is written straight to the
//! `wgN` TUN for the kernel to route. Nothing between `try_decap` and that
//! write is a security policy — a peer's `allowed-ips` is a cryptographic check
//! on the inner SOURCE address, with no destination, no zone pair, no
//! application and no direction.
//!
//! The fix is to claim WireGuard TRANSPORT-DATA records in the worker and decap
//! them there. This module is the first half of it: the shim must keep steering
//! handshake and cookie records (types 1, 2, 3) to the kernel — the control
//! thread owns the handshake state machine and there is nothing for the
//! dataplane to adjudicate in them — and stop steering transport-data records
//! (type 4), which are the ones carrying inner IP packets.
//!
//! # Why this is a module and not four lines inside `wg_steer_to_kernel`
//!
//! The shim cannot be executed by a host test: it is `no_std`, built for
//! `bpfel-unknown-none`. `tests_shim_ext_parity.rs` records what happens when a
//! shim property is guarded by a test that MODELS the shim from source text
//! instead — five successive models, each leaking to a more ordinary edit than
//! the last, including one that accepted the deletion of a security property.
//! Its resolution was to move the walk into a `core`-only module
//! (`ipv6_ext_walk.rs`) that the shim calls and a host test pulls in BY SOURCE
//! PATH and RUNS. (Described, not spelled: the #5173 confinement refusal walks
//! this directory for the attribute token itself, and prose that spells it is a
//! false red — the convention this file follows is the one stated at the top of
//! `ipv6_ext_walk.rs`.)
//!
//! This module is that shape, for the same reason. The decision below is the
//! security boundary of #8274 — it is what decides whether a packet's inner
//! plaintext will be adjudicated at all — so it is executed by the host test,
//! on real byte buffers, rather than asserted about.

/// WireGuard message types (the protocol's first header byte).
pub const WG_TYPE_INITIATION: u8 = 1;
pub const WG_TYPE_RESPONSE: u8 = 2;
pub const WG_TYPE_COOKIE: u8 = 3;
pub const WG_TYPE_DATA: u8 = 4;

/// Is this datagram a WireGuard TRANSPORT-DATA record?
///
/// Takes the first byte of the UDP payload, which for every WireGuard message
/// is the message type — `None` when the datagram has no readable payload byte.
///
/// The RESULT, a single bool, is what rides in `ParsedPacket`; the byte itself
/// does not. That is a verifier constraint, not a taste: `ParsedPacket` is a
/// `Copy` struct threaded through the shim's whole parse chain, and widening it
/// by a `u16` pushed an UNRELATED packet read out of line into a BPF subprogram
/// where the verifier lost the pointer's range —
/// `invalid access to packet, off=0 size=1, R4(id=343,r=0)` at a 1-byte load
/// dominated by a 4-byte check, in `frame1`, with the offset reloaded from the
/// stack. The failing site was not this read at all. A `bool` lands in the
/// struct's existing padding and leaves the layout alone.
///
/// WHY THE READ IS DONE IN `parse_l4` AND NOT HERE, measured twice. This
/// classifier first did the packet read itself at `pkt.payload_offset`, and the
/// kernel verifier REJECTED the object: `invalid access to packet, off=0 size=1,
/// R8 offset is outside of the packet`. `payload_offset` reaches a downstream
/// call site through a `ParsedPacket` field, so its provenance is gone and its
/// `var_off` spans the whole `u16` range — the hazard CLAUDE.md records for
/// `meta->l3_offset` packet math. It was rejected identically with a hand-rolled
/// deref and with the shim's own `read_bytes`, so it is the OFFSET, not the read.
/// A narrowing mask (the documented remedy) did not fix it either, and a mask
/// small enough to help would have been a correctness hazard in its own right:
/// a WireGuard payload offset is 42 over IPv4 and 62 over IPv6, 46/66 with a
/// VLAN tag, and deeper with IPv6 extension headers, so a mask can wrap a large
/// offset onto a small one and read the wrong byte — which for this classifier
/// means possibly reading a 4 out of a handshake record.
///
/// So the byte is captured in `parse_l4`'s UDP arm, at the same
/// freshly-validated `l4_offset` the mandatory 8-byte UDP header read just used.
/// That read shape already verifies; a 9-byte read at the same offset is the
/// same shape.
///
/// ABSENT IS NOT TRANSPORT DATA, and that direction is deliberate. A truncated
/// or zero-length payload keeps the pre-#8274 behaviour (steered to the kernel):
/// claiming it for a worker decap stage that will only reject it would move the
/// kernel path's existing malformed-record accounting to a stage without it.
///
/// Every type OTHER than 4 is likewise not transport data, including the
/// reserved 0 and everything above 4. The control thread's dispatch has an
/// explicit arm for a type byte outside {1,2,3,4} that drops and counts it
/// (#1865); leaving those on the kernel path preserves that counting rather than
/// silently relocating it.
#[inline(always)]
pub fn wg_record_is_transport_data(first_payload_byte: Option<u8>) -> bool {
    matches!(first_payload_byte, Some(WG_TYPE_DATA))
}

/// Given that the datagram already matched the WireGuard listen port on UDP,
/// must it be steered to the KERNEL?
///
/// Two conditions, and both are load-bearing:
///
/// * `local_destination` is MANDATORY and unchanged by #8274. A port-only match
///   would shunt TRANSIT or DNAT UDP that merely happens to use the WireGuard
///   port to the kernel, bypassing the userspace policy engine entirely — a
///   separate and worse bug than the one #8274 fixes. It is passed in rather
///   than computed here because the shim's own predicate reads BPF maps this
///   module cannot see; what this function owns is that the answer is REQUIRED.
/// * a transport-data record is NOT steered. That is the #8274 change, and the
///   only behaviour this module alters.
#[inline(always)]
pub fn wg_steer_to_kernel_on_port_match(local_destination: bool, is_transport_data: bool) -> bool {
    local_destination && !is_transport_data
}

/// #8274 step 3: does the WORKER claim this datagram for decap?
///
/// Step 2 stopped the WireGuard arm from steering transport-data records to the
/// kernel, and that was deliberately INERT: the record then fell through to the
/// session-miss path and was matched by `is_local_destination` a few arms down,
/// which returns the same `cpumap_or_pass` — so it still reached the kernel and
/// the tunnel kept working with no worker-side decap to receive it.
///
/// Step 3 is where that changes. The worker now HAS a decap stage, so a
/// transport-data record must reach it instead: `is_local_destination` must not
/// claim it, and the packet continues to the AF_XDP redirect like any other
/// transit traffic.
///
/// The two callers are the same predicate read in opposite directions, which is
/// why they share one function: the WireGuard arm steers to the kernel when
/// this is FALSE, and the local-destination arm declines to steer when it is
/// TRUE. Spelling that twice is how the two drift apart.
///
/// `local_destination` is still required. A transport-data record to a
/// destination that is not ours is transit traffic that merely happens to use
/// the listen port, and it must take the ordinary policy path rather than being
/// handed to a decap stage that would not find a session for it anyway.
#[inline(always)]
pub fn wg_worker_claims_record(
    wg_rx_enabled: bool,
    port_matches: bool,
    local_destination: bool,
    is_transport_data: bool,
) -> bool {
    wg_rx_enabled && port_matches && local_destination && is_transport_data
}

/// #9587: the bound on the steered WireGuard listen-port set. Shared by the
/// shim ctrl block (`UserspaceCtrl.wg_ports`), the helper forwarding state
/// and the snapshot decode (each crate carries its own copy; the Go
/// cross-plane test pins all three equal to `config.MaxSteeredWireGuardPorts`).
pub const WG_STEERED_PORT_SET_MAX: usize = 8;

/// Given a UDP datagram's destination port, is it a member of the steered
/// set? `ports` is the fixed ctrl array, `count` the valid prefix length
/// (clamped defensively — the Go programmer guarantees count <= MAX).
///
/// The loop bound is the CONST, not the count, so the verifier sees a fixed
/// trip count; the count only gates matching. Zero never matches, so a
/// zero-filled tail and a corrupt over-count alike match nothing.
#[inline(always)]
pub fn wg_port_is_steered(port: u16, ports: &[u16; WG_STEERED_PORT_SET_MAX], count: u32) -> bool {
    if port == 0 {
        return false;
    }
    let mut matched = false;
    let mut i = 0usize;
    while i < WG_STEERED_PORT_SET_MAX {
        if (i as u32) < count && ports[i] == port {
            matched = true;
            break;
        }
        i += 1;
    }
    matched
}
