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

/// Post-parse disposition over facts already computed from a parsed frame.
/// `tagged_only_vid0_local` retains its higher-priority drop; all other
/// local/control frames pass, and all transit frames drop.
#[inline(always)]
pub fn ctrl_disabled_disposition(
    tagged_only_vid0_local: bool,
    local_or_control: bool,
) -> DegradedCtrlDisabledDisposition {
    if tagged_only_vid0_local {
        return DegradedCtrlDisabledDisposition::DropTransit;
    }
    if local_or_control {
        return DegradedCtrlDisabledDisposition::PassLocalControl;
    }
    DegradedCtrlDisabledDisposition::DropTransit
}

/// Complete #13632 behavioral decision. The flags gate is evaluated
/// before either post-parse fact may grant a pass.
#[inline(always)]
pub fn ctrl_disabled_action(
    ingress_iface_flags: u8,
    tagged_only_vid0_local: bool,
    local_or_control: bool,
) -> DegradedCtrlDisabledDisposition {
    if !ingress_adjudicated(ingress_iface_flags) {
        return DegradedCtrlDisabledDisposition::DropTransit;
    }
    ctrl_disabled_disposition(tagged_only_vid0_local, local_or_control)
}
