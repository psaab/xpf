//! LAND (equal source/destination) disposition for the XDP shim.
//!
//! #11087 put an unconditional LAND drop on the healthy shim's established
//! `USERSPACE_SESSION_ACTION_PASS_TO_KERNEL` arm only, because a live PASS row
//! is terminal there and never reaches worker screen stage 10. #13953
//! generalised it to every other shim arm that hands a packet to the kernel.
//!
//! #15789: that unconditional drop made the worker's profile-gated
//! `check_land` unreachable on every kernel-pass arm and bypassed the
//! ingress zone's `ScreenProfile.land` / `alarm-without-drop` contract:
//! a zone with LAND disabled, or in audit mode, still lost the packet at
//! the shim with no alarm accounting. The disposition therefore follows
//! the ingress zone's resolved screen profile, published per zone into
//! `userspace_land_screen` by the Go control plane:
//!
//! * `LAND_SCREEN_DROP` (1) — drop at the shim (`land_drop` counter).
//! * `LAND_SCREEN_ALARM` (2) — count `land_alarm` and let the caller's
//!   normal kernel-pass arm proceed (audit mode: alarm without drop).
//! * absent / 0 — the zone has no resolved screen profile with the LAND
//!   posture decided (no screen configured, or a pre-#15789 control
//!   plane that never publishes the map). The shim stays fail-closed
//!   and drops, preserving the #13953 guarantee on version skew: an
//!   old Go binary leaves every zone absent, so the shim behaves
//!   exactly as #13953 shipped until the new sync runs.
//!
//! The address test itself is unchanged and identical for both families:
//! `ParsedPacket` stores IPv4 addresses in the first four bytes of a
//! zeroed 16-byte field, so one byte-array comparison is family-correct.
//! Loopback never traverses this XDP hook, so no legitimate
//! equal-address traffic exists here.

/// Shim LAND disposition for one ingress zone, as published in
/// `userspace_land_screen`. Mirrors the Go constants of the same name in
/// `pkg/dataplane/userspace/land_screen.go`.
pub const LAND_SCREEN_PASS: u8 = 0;
/// LAND enabled, drop-enforcing.
pub const LAND_SCREEN_DROP: u8 = 1;
/// Audit mode: count the alarm and pass to the kernel.
pub const LAND_SCREEN_ALARM: u8 = 2;

/// Is this packet a LAND packet — source address equal to destination
/// address — on either address family?
#[inline(always)]
pub fn is_land(src_addr: &[u8; 16], dst_addr: &[u8; 16]) -> bool {
    src_addr == dst_addr
}

/// What the shim does with a LAND packet for one ingress zone.
///
/// `zone_known` says the ingress zone resolved (a WG ingress-zone row
/// named a non-zero zone). Only then does a published byte decide:
/// PASS (LAND disabled) and ALARM both let the packet proceed — ALARM
/// additionally counts `land_alarm` — and DROP drops. An unresolved
/// zone ignores the byte and fails closed to Drop, so a stale
/// land_screen row for another zone can never admit a packet whose
/// own zone is unknown, and a pre-#15789 control plane (no rows at
/// all) keeps the #13953 unconditional-drop behaviour.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LandDisposition {
    /// Pass to the kernel unscreened (LAND disabled for this zone).
    Pass,
    /// Drop at the shim.
    Drop,
    /// Count an alarm and pass to the kernel.
    AlarmPass,
}

#[inline(always)]
pub fn land_disposition(zone_known: bool, screen_byte: u8) -> LandDisposition {
    if !zone_known {
        return LandDisposition::Drop;
    }
    match screen_byte {
        LAND_SCREEN_PASS => LandDisposition::Pass,
        LAND_SCREEN_ALARM => LandDisposition::AlarmPass,
        _ => LandDisposition::Drop,
    }
}
