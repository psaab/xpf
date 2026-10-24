// Fabric-link descriptors split from forwarding.rs (#16209):
// FabricLink, the skip-reason enum, and the named skip row. Pure
// code motion behind `forwarding/mod.rs`'s `use forwarding::*`
// glob; zero layout or access-site change.
// Visibility bill: no widening.

use super::super::*;

#[derive(Clone, Copy, Debug, PartialEq)]
pub(in crate::afxdp) struct FabricLink {
    pub(in crate::afxdp) parent_ifindex: i32,
    pub(in crate::afxdp) overlay_ifindex: i32,
    pub(in crate::afxdp) peer_addr: IpAddr,
    pub(in crate::afxdp) peer_mac: [u8; 6],
    pub(in crate::afxdp) local_mac: [u8; 6],
    /// #4082: the local fabric parent link's carrier/oper state, threaded from
    /// `FabricSnapshot.up`. `resolve_fabric_redirect_from_list` prefers a fabric
    /// with `up == true` so a dual-fabric cluster fails the cross-chassis
    /// redirect over to the secondary when the primary parent carrier drops.
    pub(in crate::afxdp) up: bool,
    /// #16023: operator attestation (FabricSnapshot.link_authenticated)
    /// that this link is link-authenticated (MACsec/802.1X). Consulted
    /// only when ForwardingState.require_authenticated_fabric_stamps.
    pub(in crate::afxdp) link_authenticated: bool,
}

/// #3773 (M13): why a configured fabric link was skipped during a forwarding
/// build/refresh pass. `is_malformed()` partitions the reasons into the two
/// cumulative counters: a MALFORMED value (an unusable parent ifindex, an
/// unparseable peer address, or a NON-EMPTY MAC string that fails to parse) vs
/// an UNRESOLVED peer/local MAC (an EMPTY MAC field still awaiting neighbor /
/// interface resolution — the expected transient the late-resolution
/// `SyncFabricState` path fills in). A persistently non-zero UNRESOLVED count
/// is a distinct, benign-until-persistent state; a non-zero MALFORMED count is
/// a config/environment fault an operator must fix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::afxdp) enum FabricSkipReason {
    /// `parent_ifindex <= 0` — the fabric parent netdev index is unusable.
    InvalidParentIfindex,
    /// `peer_address` does not parse as an IP address.
    UnparseablePeerAddress,
    /// A NON-EMPTY `local_mac` string failed to parse (and no parent-ifindex
    /// MAC fallback was available).
    MalformedLocalMac,
    /// An EMPTY `local_mac` with no resolvable parent-ifindex MAC — awaiting
    /// interface MAC resolution.
    UnresolvedLocalMac,
    /// A NON-EMPTY `peer_mac` string failed to parse (and no neighbor entry
    /// resolved it).
    MalformedPeerMac,
    /// An EMPTY `peer_mac` with no resolved neighbor — awaiting ARP/NDP
    /// resolution (the common startup transient).
    UnresolvedPeerMac,
}

impl FabricSkipReason {
    /// True for a malformed value (a config/environment fault that will not
    /// self-heal), false for an unresolved-but-well-formed peer/local MAC (the
    /// expected late-resolution transient).
    pub(in crate::afxdp) fn is_malformed(self) -> bool {
        matches!(
            self,
            FabricSkipReason::InvalidParentIfindex
                | FabricSkipReason::UnparseablePeerAddress
                | FabricSkipReason::MalformedLocalMac
                | FabricSkipReason::MalformedPeerMac
        )
    }

    pub(in crate::afxdp) fn as_str(self) -> &'static str {
        match self {
            FabricSkipReason::InvalidParentIfindex => "invalid-parent-ifindex",
            FabricSkipReason::UnparseablePeerAddress => "unparseable-peer-address",
            FabricSkipReason::MalformedLocalMac => "malformed-local-mac",
            FabricSkipReason::UnresolvedLocalMac => "unresolved-local-mac",
            FabricSkipReason::MalformedPeerMac => "malformed-peer-mac",
            FabricSkipReason::UnresolvedPeerMac => "unresolved-peer-mac",
        }
    }
}

/// #3773 (M13): a skipped fabric link, named for operator diagnostics.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::afxdp) struct FabricLinkSkip {
    /// The configured fabric name (`FabricSnapshot.name`, e.g. `fab0`).
    pub(in crate::afxdp) name: String,
    /// The parent netdev ifindex the skip pertained to (`<= 0` for an
    /// `InvalidParentIfindex` skip). Used by the preserved-fabric merge to
    /// prune a skip whose parent was re-added from the prior resolved set.
    pub(in crate::afxdp) parent_ifindex: i32,
    pub(in crate::afxdp) reason: FabricSkipReason,
}
