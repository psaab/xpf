// TX-request types extracted from afxdp/types/mod.rs (Issue 68.3).
// 8 items / ~80 LOC of transmit-side request descriptors used by
// tx/dispatch.rs and the per-binding pending-forward queues.
//
// Pure relocation. Original `pub(super)` widened to `pub(in crate::afxdp)`
// in this file; types/mod.rs re-exports via `pub(in crate::afxdp) use
// tx::*;` so external call sites resolve unchanged.

use super::*;

#[derive(Clone, Debug)]
pub(in crate::afxdp) struct TxRequest {
    pub(in crate::afxdp) bytes: Vec<u8>,
    #[allow(dead_code)]
    pub(in crate::afxdp) expected_ports: Option<(u16, u16)>,
    #[allow(dead_code)]
    pub(in crate::afxdp) expected_addr_family: u8,
    #[allow(dead_code)]
    pub(in crate::afxdp) expected_protocol: u8,
    pub(in crate::afxdp) flow_key: Option<SessionKey>,
    pub(in crate::afxdp) egress_ifindex: i32,
    pub(in crate::afxdp) cos_queue_id: Option<u8>,
    pub(in crate::afxdp) dscp_rewrite: Option<u8>,
    pub(in crate::afxdp) mirror_clone: bool,
}

pub(in crate::afxdp) enum PendingForwardFrame {
    Live,
    Owned(Vec<u8>),
    Prebuilt(Vec<u8>),
}

impl Default for PendingForwardFrame {
    fn default() -> Self {
        Self::Live
    }
}

pub(in crate::afxdp) struct PendingForwardRequest {
    pub(in crate::afxdp) target_ifindex: i32,
    pub(in crate::afxdp) target_binding_index: Option<usize>,
    pub(in crate::afxdp) ingress_queue_id: u32,
    pub(in crate::afxdp) desc: XdpDesc,
    pub(in crate::afxdp) frame: PendingForwardFrame,
    pub(in crate::afxdp) meta: ForwardPacketMeta,
    pub(in crate::afxdp) decision: SessionDecision,
    pub(in crate::afxdp) apply_nat_on_fabric: bool,
    pub(in crate::afxdp) expected_ports: Option<(u16, u16)>,
    pub(in crate::afxdp) flow_key: Option<SessionKey>,
    pub(in crate::afxdp) nat64_reverse: Option<Nat64ReverseInfo>,
    pub(in crate::afxdp) cos_queue_id: Option<u8>,
    pub(in crate::afxdp) dscp_rewrite: Option<u8>,
}

pub(in crate::afxdp) struct PreparedTxRequest {
    pub(in crate::afxdp) offset: u64,
    pub(in crate::afxdp) len: u32,
    pub(in crate::afxdp) recycle: PreparedTxRecycle,
    #[allow(dead_code)]
    pub(in crate::afxdp) expected_ports: Option<(u16, u16)>,
    #[allow(dead_code)]
    pub(in crate::afxdp) expected_addr_family: u8,
    #[allow(dead_code)]
    pub(in crate::afxdp) expected_protocol: u8,
    pub(in crate::afxdp) flow_key: Option<SessionKey>,
    pub(in crate::afxdp) egress_ifindex: i32,
    pub(in crate::afxdp) cos_queue_id: Option<u8>,
    pub(in crate::afxdp) dscp_rewrite: Option<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::afxdp) enum InPlaceL2Rewrite {
    SameLength,
    VlanPushDescriptor,
    VlanPopDescriptor,
    VlanPushMemmoveNoHeadroom,
    UnsupportedMemmove,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::afxdp) struct InPlaceRewriteResult {
    pub(in crate::afxdp) offset: u64,
    pub(in crate::afxdp) len: u32,
    pub(in crate::afxdp) l2_rewrite: InPlaceL2Rewrite,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::afxdp) struct ExactLocalScratchTxRequest {
    pub(in crate::afxdp) offset: u64,
    pub(in crate::afxdp) len: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::afxdp) struct ExactPreparedScratchTxRequest {
    pub(in crate::afxdp) offset: u64,
    pub(in crate::afxdp) len: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::afxdp) enum PreparedTxRecycle {
    FreeTxFrame,
    FillOnSlot(u32),
    FillOnSlotWithOffset { slot: u32, offset: u64 },
}

impl PreparedTxRecycle {
    #[inline]
    pub(in crate::afxdp) fn recycle_offset(self, tx_offset: u64) -> u64 {
        match self {
            Self::FreeTxFrame | Self::FillOnSlot(_) => tx_offset,
            Self::FillOnSlotWithOffset { offset, .. } => offset,
        }
    }

    #[inline]
    pub(in crate::afxdp) fn fill_slot(self) -> Option<u32> {
        match self {
            Self::FreeTxFrame => None,
            Self::FillOnSlot(slot) | Self::FillOnSlotWithOffset { slot, .. } => Some(slot),
        }
    }

    #[inline]
    pub(in crate::afxdp) fn fill_on_slot(slot: u32, tx_offset: u64, recycle_offset: u64) -> Self {
        if tx_offset == recycle_offset {
            Self::FillOnSlot(slot)
        } else {
            Self::FillOnSlotWithOffset {
                slot,
                offset: recycle_offset,
            }
        }
    }
}

#[derive(Debug)]
pub(in crate::afxdp) struct LocalTunnelTxPlan {
    pub(in crate::afxdp) tx_ifindex: i32,
    pub(in crate::afxdp) tx_request: TxRequest,
    pub(in crate::afxdp) session_entry: SyncedSessionEntry,
    pub(in crate::afxdp) reverse_session_entry: Option<SyncedSessionEntry>,
}
