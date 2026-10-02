use std::sync::atomic::AtomicU64;

/// #9901 (F-074): forwarded frames whose egress-MTU decision ran with no
/// known MTU and took the documented fail-open `Forward` arm.
pub(in crate::afxdp) static EGRESS_MTU_UNKNOWN_FORWARD_TOTAL: AtomicU64 = AtomicU64::new(0);

/// PTB builders that could not produce an ICMP reply, so the oversized
/// original packet had to be dropped without a PMTU signal.
pub(in crate::afxdp) static PTB_UNBUILDABLE_TOTAL: AtomicU64 = AtomicU64::new(0);
