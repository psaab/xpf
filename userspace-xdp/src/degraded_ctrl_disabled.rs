//! #13632 ctrl-disabled degraded disposition, in a module that compiles
//! for the HOST as well as for `bpfel-unknown-none`.
//!
//! The disabled path must test ingress authority before parsing bytes,
//! then decide whether a parsed frame is eligible for the local/control
//! kernel-pass exemption. Keeping that decision here lets the same code
//! execute in unprivileged host tests, rather than relying only on a BPF
//! collection load that skips when `RemoveMemlock` is denied.
//!
//! The caller still owns packet reads, parse failures, S-tag/QinQ
//! handling, and non-IP L2 disposition, whose reasons differ by parse
//! shape. This module has no packet reads, BPF map, `aya`, or `std`.

/// ADJUDICATED bit of the ingress-interface flag word.
pub const INGRESS_IFACE_FLAG_ADJUDICATED: u8 = 1;

/// Post-parse disposition while control is disabled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DegradedCtrlDisabledDisposition {
    /// Take the local/control kernel-pass arm.
    PassLocalControl,
    /// Fail closed with transit DROP.
    DropTransit,
}

/// #13632 authority gate: raw-L3 ingress must not be parsed if the
/// interface is not adjudicated, because source octets could be mistaken
/// for an Ethernet ethertype and influence the local/control exemption.
#[inline(always)]
pub fn ingress_adjudicated(ingress_iface_flags: u8) -> bool {
    ingress_iface_flags & INGRESS_IFACE_FLAG_ADJUDICATED != 0
}

/// Post-parse disposition over the fact already computed from a parsed
/// frame that reached the end of `degraded_ctrl_disabled_action`.
///
/// This is *not* the complete #13632 decision. Production reaches this
/// helper only after the caller has already returned for: unadjudicated
/// ingress (see `ingress_adjudicated`), parse failures, S-tag/QinQ and
/// non-IP shapes, tagged-only VID-0 local destinations, and the LAND
/// gate — each under its own reason counter. This helper therefore takes
/// no interface flags and no tagged-only input: those facts are decided
/// by the caller and can never be passed here. Local/control frames
/// pass, all other (transit) frames drop.
#[inline(always)]
pub fn local_control_or_drop(local_or_control: bool) -> DegradedCtrlDisabledDisposition {
    if local_or_control {
        return DegradedCtrlDisabledDisposition::PassLocalControl;
    }
    DegradedCtrlDisabledDisposition::DropTransit
}
