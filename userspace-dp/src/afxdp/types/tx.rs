// TX-request types extracted from afxdp/types/mod.rs (Issue 68.3).
// 8 items / ~80 LOC of transmit-side request descriptors used by
// tx/dispatch.rs and the per-binding pending-forward queues.
//
// Pure relocation. Original `pub(super)` widened to `pub(in crate::afxdp)`
// in this file; types/mod.rs re-exports via `pub(in crate::afxdp) use
// tx::*;` so external call sites resolve unchanged.

use super::*;
#[derive(Debug)]
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
    /// Fragment-overlap admission ownership. This is moved through every
    /// local/CoS/prepared queue until the TX ring accepts or drops it.
    pub(in crate::afxdp) overlap_admissions:
        Option<crate::fragment_overlap::OverlapAdmissionTokens>,
    /// #1829 Phase 1: CoS enqueue timestamp (pass-level `now_ns`),
    /// stamped ONCE at the single CoS admission choke point
    /// (`enqueue_cos_item`). 0 means "never CoS-enqueued" (direct TX
    /// paths, test constructors, pre-upgrade items) and the sojourn
    /// recorder treats 0 as "no data" — a zero timestamp can never
    /// produce a bogus huge sojourn. Preserved across
    /// `into_prepared_request` / `to_local_request` conversions and
    /// across pop→push_front rollbacks, so retried items keep their
    /// ORIGINAL enqueue time (correct for sojourn measurement).
    pub(in crate::afxdp) enqueue_ns: u64,
}
impl Clone for TxRequest {
    fn clone(&self) -> Self {
        assert!(
            self.overlap_admissions.is_none(),
            "admission-bearing TX requests must move, not clone"
        );
        Self {
            bytes: self.bytes.clone(),
            expected_ports: self.expected_ports,
            expected_addr_family: self.expected_addr_family,
            expected_protocol: self.expected_protocol,
            flow_key: self.flow_key.clone(),
            egress_ifindex: self.egress_ifindex,
            cos_queue_id: self.cos_queue_id,
            dscp_rewrite: self.dscp_rewrite,
            mirror_clone: self.mirror_clone,
            overlap_admissions: None,
            enqueue_ns: self.enqueue_ns,
        }
    }
}
impl TxRequest {
    #[inline]
    pub(in crate::afxdp) fn into_prepared_request(
        self,
        offset: u64,
        recycle: PreparedTxRecycle,
    ) -> PreparedTxRequest {
        PreparedTxRequest {
            offset,
            len: self.bytes.len() as u32,
            recycle,
            expected_ports: self.expected_ports,
            expected_addr_family: self.expected_addr_family,
            expected_protocol: self.expected_protocol,
            flow_key: self.flow_key,
            egress_ifindex: self.egress_ifindex,
            cos_queue_id: self.cos_queue_id,
            dscp_rewrite: self.dscp_rewrite,
            mirror_clone: self.mirror_clone,
            overlap_admissions: self.overlap_admissions,
            enqueue_ns: self.enqueue_ns,
        }
    }
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
    /// #5606: the NAT64 flow's original IPv6 src/dst, threaded from the matched
    /// reverse-companion session's `SessionMetadata` by
    /// `build_live_forward_request_from_frame`. The TX dispatcher hands this to
    /// `build_nat64_forwarded_frame`; its AF_INET (v4->v6) reverse branch
    /// hard-requires it to translate a server's IPv4 reply back to IPv6 — with
    /// `None` the branch returns `None` and the reply is dropped. `None` for
    /// every non-NAT64 flow, and inert for PREBUILT-frame requests (embedded-ICMP
    /// / generated-time-exceeded) whose non-NAT64 decision routes them past the
    /// frame builder entirely.
    pub(in crate::afxdp) nat64_reverse: Option<Nat64ReverseInfo>,
    /// Fragment-overlap admission ownership transferred to TX queues.
    pub(in crate::afxdp) overlap_admissions:
        Option<crate::fragment_overlap::OverlapAdmissionTokens>,
    pub(in crate::afxdp) cos_queue_id: Option<u8>,
    pub(in crate::afxdp) dscp_rewrite: Option<u8>,
    pub(in crate::afxdp) cos_tx_selection_resolved: bool,
    // #hb166 T-7: the `filter_match_extra` snapshot field was removed. Its
    // sole reader was the deferred TX-selection / CoS dispatch path
    // (`resolve_pending_forward_cos_tx_selection`), which was deleted as
    // dead code — every request is built with `cos_tx_selection_resolved =
    // true`, so CoS TX selection is always resolved upstream at build time
    // (via `resolve_cos_tx_selection_at`, which reads the LIVE frame). With
    // no reader, the field was write-only and its per-request
    // `term_match_extra_from_frame(..).to_static()` snapshot was wasted
    // work on every forwarded packet.
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
    /// Fragment-overlap admission ownership transferred to TX queues.
    pub(in crate::afxdp) overlap_admissions:
        Option<crate::fragment_overlap::OverlapAdmissionTokens>,
    pub(in crate::afxdp) egress_ifindex: i32,
    pub(in crate::afxdp) cos_queue_id: Option<u8>,
    pub(in crate::afxdp) dscp_rewrite: Option<u8>,
    pub(in crate::afxdp) mirror_clone: bool,
    /// #1829 Phase 1: CoS enqueue timestamp. Same contract as
    /// `TxRequest::enqueue_ns` (0 = never CoS-enqueued / no data);
    /// see the field doc there.
    pub(in crate::afxdp) enqueue_ns: u64,
}

impl PreparedTxRequest {
    #[inline]
    pub(in crate::afxdp) fn into_local_request(&mut self, bytes: Vec<u8>) -> TxRequest {
        TxRequest {
            bytes,
            expected_ports: self.expected_ports,
            expected_addr_family: self.expected_addr_family,
            expected_protocol: self.expected_protocol,
            flow_key: self.flow_key.clone(),
            egress_ifindex: self.egress_ifindex,
            cos_queue_id: self.cos_queue_id,
            dscp_rewrite: self.dscp_rewrite,
            mirror_clone: self.mirror_clone,
            overlap_admissions: self.overlap_admissions.take(),
            enqueue_ns: self.enqueue_ns,
        }
    }
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
    /// #10518: `None` for non-firewall-local inner src (encap-only, never
    /// published as TunOrigin — the WG `parse_wg_tun_origin_flow` twin).
    /// `Some` only when provenance is proven; the loop still TXes either way.
    pub(in crate::afxdp) session_entry: Option<SyncedSessionEntry>,
    pub(in crate::afxdp) reverse_session_entry: Option<SyncedSessionEntry>,
}
