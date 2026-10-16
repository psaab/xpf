//! LAND (equal source/destination) disposition for the XDP shim.
//!
//! #11087 put the unconditional LAND drop on the healthy shim's established
//! `USERSPACE_SESSION_ACTION_PASS_TO_KERNEL` arm only, because a live PASS row
//! is terminal there and never reaches worker screen stage 10. #13953: every
//! other shim arm that hands a packet to the kernel has the same property —
//! the arm is terminal, the worker never sees the packet, and no other screen
//! runs. That covers the healthy session-miss local-destination arm and the
//! ICMP-to-interface-NAT-local arm, the WireGuard steer fallthrough, and the
//! whole degraded (control-disabled / binding / heartbeat) path, whose
//! local/control predicate has no session dimension at all. The Linux stack
//! has no IPv6 LAND backstop: a `src == dst` IPv6 packet to a firewall-local
//! address was delivered to local sockets on every one of those arms.
//!
//! The verdict therefore lives here, in a `core`-only module, stated once:
//! any packet the shim is about to hand to the kernel whose source and
//! destination addresses are equal is a LAND packet and is dropped, whatever
//! arm classified it as local. Callers gate on their own "about to pass to
//! the kernel" condition; this predicate owns the address test so the host
//! regression executes the exact comparison the shim performs.
//!
//! The check is unconditional and identical for both families, like the
//! #11087 arm it generalises: `ParsedPacket` stores IPv4 addresses in the first
//! four bytes of a zeroed 16-byte field, so one byte-array comparison is
//! family-correct. Loopback never traverses this XDP hook, so no legitimate
//! equal-address traffic exists here.

/// Is this packet a LAND packet — source address equal to destination
/// address — on either address family?
#[inline(always)]
pub fn is_land(src_addr: &[u8; 16], dst_addr: &[u8; 16]) -> bool {
    src_addr == dst_addr
}
