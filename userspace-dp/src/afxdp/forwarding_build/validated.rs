//! #2410: validated narrowing newtypes for the forwarding-build trust
//! boundary.
//!
//! The Go control plane is the primary validator, but the Rust
//! forwarding-build conversion is the SECOND trust boundary: it must not
//! silently build a DIFFERENT config from a bad / mixed-version snapshot.
//! These newtypes decode a control-plane integer ONCE, with a checked
//! `try_*` conversion that returns a typed
//! [`crate::policy::SnapshotIntegrityError`] on an out-of-range value —
//! instead of the pre-fix unchecked `as` cast that silently WRAPPED
//! (`vlan 65537 → 1`, `ttl 256 → 0`) or the `filter_map` range check that
//! silently DROPPED an out-of-range CoS queue id.
//!
//! The valid path is byte-identical to the old cast: an in-range value
//! produces the same `u16`/`u8`. Only the out-of-range case changes — it
//! now fails the snapshot closed (the apply preflight keeps the previous
//! live forwarding state) rather than installing a wrapped/partial config.

use crate::policy::SnapshotIntegrityError;

/// A validated 802.1Q VLAN id (0..=65535). 0 is the legitimate
/// "untagged" sentinel the egress/ingress paths already use.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(in crate::afxdp) struct VlanId(u16);

impl VlanId {
    /// Decode an interface snapshot `vlan_id` (an `i32`). A NEGATIVE
    /// value is the legitimate "no VLAN" sentinel the pre-fix `.max(0)`
    /// collapsed to 0, so it maps to `VlanId(0)` (untagged) — preserving
    /// the old valid-path behavior. A value > `u16::MAX` is REJECTED
    /// (the pre-fix cast wrapped it to a different VLAN).
    /// #8597 K39: the bound is **4095**, not `u16::MAX`.
    ///
    /// A VLAN id is a 12-bit field, and the emitter masks it:
    /// `TxVlanTag::from` (`frame/headers.rs`) computes `vid & 0x0fff` and then
    /// `present: vid > 0`. So accepting the full `u16` range here does not
    /// produce a large VLAN downstream, it produces a DIFFERENT one, silently:
    ///
    /// * 4097 masks to 1 — the frame is emitted on VLAN 1, a live L2 domain the
    ///   operator did not name.
    /// * 4096 masks to 0, which makes `present` FALSE, so `header_len()` returns
    ///   14 and the frame is emitted with **no tag at all** on an interface
    ///   configured as tagged. That is not a wrong-VLAN delivery; the frame
    ///   lands in the native VLAN or is dropped by the switch, and neither is
    ///   the configured behaviour.
    ///
    /// Rejecting at the snapshot boundary is what the existing
    /// `InterfaceVlanOutOfRange` variant is for, and it fails CLOSED: a
    /// snapshot naming an unrepresentable VLAN is refused rather than
    /// silently re-pointed at a domain that exists.
    ///
    /// 4095 rather than 4094 deliberately. The commit gate is
    /// `ValidateInteger(1, 4094)` (`pkg/config/schema_interfaces.go`), so no
    /// committed config can reach either bound — this guards the TOLERANT load
    /// path and any future non-config producer. The invariant being restored is
    /// "the boundary admits exactly the wire-representable range" (#6773), and
    /// 4095 is representable; rejecting it here would make this stricter than
    /// the wire rather than equal to it, which is a different claim from the
    /// one this fixes.
    ///
    /// Negative stays `Self(0)` (untagged), unchanged.
    pub(in crate::afxdp) fn try_from_snapshot(
        vlan_id: i32,
        interface: &str,
    ) -> Result<Self, SnapshotIntegrityError> {
        if vlan_id < 0 {
            return Ok(Self(0));
        }
        if vlan_id > 0x0fff {
            return Err(SnapshotIntegrityError::InterfaceVlanOutOfRange {
                interface: interface.to_string(),
                vlan_id,
            });
        }
        u16::try_from(vlan_id).map(Self).map_err(|_| {
            SnapshotIntegrityError::InterfaceVlanOutOfRange {
                interface: interface.to_string(),
                vlan_id,
            }
        })
    }

    #[inline]
    pub(in crate::afxdp) fn get(self) -> u16 {
        self.0
    }
}

/// A validated outer-IP tunnel TTL / hop-limit (0..=255).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(in crate::afxdp) struct TunnelTtl(u8);

impl TunnelTtl {
    /// The documented default outer TTL when a tunnel carries no explicit
    /// value. Mirrors the Go contract (`0` = "use the default 64",
    /// `pkg/config/schema_interfaces.go` / `types_routing.go`) and the
    /// netlink path (`pkg/routing/tunnel.go: if ttl == 0 { ttl = 64 }`).
    pub(in crate::afxdp) const DEFAULT_TTL: u8 = 64;

    /// Decode a tunnel-endpoint snapshot `ttl` (an `i32`). A value > `u8::MAX`
    /// is REJECTED (the pre-fix cast wrapped it, 256→0). A NEGATIVE value is a
    /// corrupt / mixed-version snapshot field — map it to the documented
    /// default `DEFAULT_TTL` rather than `0` (#2703): coercing to 0 would write
    /// outer TTL 0 and blackhole the tunnel, the exact failure the Go-side
    /// 0→64 default in `pkg/dataplane/userspace/tunnels.go` exists to prevent.
    /// The well-behaved Go emitter never sends 0 (it applies the default
    /// before the snapshot), so this is a fail-closed backstop only.
    pub(in crate::afxdp) fn try_from_snapshot(
        ttl: i32,
        tunnel_id: u16,
    ) -> Result<Self, SnapshotIntegrityError> {
        if ttl < 0 {
            return Ok(Self(Self::DEFAULT_TTL));
        }
        u8::try_from(ttl)
            .map(Self)
            .map_err(|_| SnapshotIntegrityError::TunnelTtlOutOfRange { tunnel_id, ttl })
    }

    #[inline]
    pub(in crate::afxdp) fn get(self) -> u8 {
        self.0
    }
}

/// A validated CoS queue id (0..=255).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(in crate::afxdp) struct QueueId(u8);

impl QueueId {
    /// Decode a CoS forwarding-class snapshot `queue` (an `i32`). Unlike
    /// VLAN/TTL there is NO negative sentinel — a negative or > `u8::MAX`
    /// queue id is REJECTED (the pre-fix `filter_map` silently DROPPED
    /// the whole class, unmapping every classifier/scheduler entry that
    /// referenced it).
    pub(in crate::afxdp) fn try_from_snapshot(
        queue: i32,
        forwarding_class: &str,
    ) -> Result<Self, SnapshotIntegrityError> {
        u8::try_from(queue).map(Self).map_err(|_| {
            SnapshotIntegrityError::CosQueueIdOutOfRange {
                forwarding_class: forwarding_class.to_string(),
                queue,
            }
        })
    }

    #[inline]
    pub(in crate::afxdp) fn get(self) -> u8 {
        self.0
    }
}

/// A validated egress interface MTU.
///
/// #2706: the pre-fix code narrowed the snapshot `mtu` with
/// `iface.mtu.max(0) as usize`, so a NEGATIVE (malformed / version-drifted)
/// value silently collapsed to `0`. The egress MTU guard
/// (`forwarded_egress_mtu_decision`) treats `mtu == 0` as "unknown; forward"
/// (fail-open: never invent an MTU smaller than the link), so a negative MTU
/// silently DISABLED PTB / drop enforcement instead of failing the snapshot.
///
/// `0` is the LEGITIMATE "unknown MTU" sentinel the Go control plane emits
/// (an interface whose link could not be resolved — `buildLinkSnapshot`
/// returns mtu 0, dropped on the wire by `json:"mtu,omitempty"` and decoded
/// back to 0). That permissive case is preserved unchanged: `0` maps to
/// `InterfaceMtu(0)`. Only a NEGATIVE value (which a healthy Go path never
/// produces — netlink MTUs are non-negative) is REJECTED, consistent with the
/// #2410/#2696 fail-closed boundary: rejecting the whole snapshot keeps the
/// previous live forwarding state rather than installing an interface with MTU
/// enforcement silently switched off.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(in crate::afxdp) struct InterfaceMtu(usize);

impl InterfaceMtu {
    /// Decode an interface snapshot `mtu` (an `i32`). `0` (and only 0) is the
    /// legitimate "unknown, forward permissively" sentinel and maps to
    /// `InterfaceMtu(0)`. A NEGATIVE value is REJECTED (the pre-fix `.max(0)`
    /// silently turned it into the permissive 0, disabling egress MTU
    /// enforcement). A positive value passes through unchanged.
    pub(in crate::afxdp) fn try_from_snapshot(
        mtu: i32,
        interface: &str,
    ) -> Result<Self, SnapshotIntegrityError> {
        usize::try_from(mtu).map(Self).map_err(|_| {
            SnapshotIntegrityError::InterfaceMtuInvalid {
                interface: interface.to_string(),
                mtu,
            }
        })
    }

    #[inline]
    pub(in crate::afxdp) fn get(self) -> usize {
        self.0
    }
}

/// A validated tunnel-endpoint logical MTU (#16514).
///
/// Same contract as `InterfaceMtu` (#2706): `0` is the legitimate
/// "unknown" sentinel (non-limiting for `native_gre_inner_mtu`), a
/// positive value passes through, and a NEGATIVE value is REJECTED
/// rather than collapsed to 0 — collapsing would silently disable the
/// gr- MTU cap the operator configured. Reuses the
/// `InterfaceMtuInvalid` error (keyed by the endpoint's interface
/// name) so no new wire/error variant is needed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(in crate::afxdp) struct TunnelMtu(usize);

impl TunnelMtu {
    pub(in crate::afxdp) fn try_from_snapshot(
        mtu: i32,
        interface: &str,
    ) -> Result<Self, SnapshotIntegrityError> {
        usize::try_from(mtu).map(Self).map_err(|_| {
            SnapshotIntegrityError::InterfaceMtuInvalid {
                interface: interface.to_string(),
                mtu,
            }
        })
    }

    #[inline]
    pub(in crate::afxdp) fn get(self) -> usize {
        self.0
    }
}
