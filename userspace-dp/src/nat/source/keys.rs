//! #9062: the two source-NAT identity keys, split out of `source/mod.rs`.
//!
//! They are here together because they answer the same question at two scopes
//! and had the same bug: `SourceNatFlowKey` is one flow's identity, and
//! `SourceNatPoolAllocatorKey` selects which `PortAllocator` a rule-set draws
//! from. Both omitted the routing domain, so two rule-sets scoped to different
//! routing instances that named the SAME pool shared one identity space AND one
//! allocator -- and an identical 5-tuple in two VRFs collided.
//!
//! Moved rather than left in place because adding the domain to both pushed
//! `source/mod.rs` past the 1500-LOC modularity floor. Splitting on the KEYS is
//! the natural seam rather than the convenient one: everything here is
//! identity, and everything that stayed behind is behaviour.

use super::*;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub(crate) struct SourceNatFlowKey {
    pub(crate) protocol: u8,
    pub(crate) src_ip: IpAddr,
    pub(crate) dst_ip: IpAddr,
    pub(crate) src_port: u16,
    pub(crate) dst_port: u16,
    /// #9062: the ROUTING DOMAIN this flow's identity belongs to.
    ///
    /// Without it, two rule-sets scoped to DIFFERENT routing instances that
    /// reference the SAME pool shared one flow-identity space, and
    /// `live_by_flow.get(&flow)` handed the second tenant's flow the first's
    /// translated tuple on an identical 5-tuple. #7160 cannot recover it: the
    /// reverse index is inserted and probed with `routing_domain: 0`, and the
    /// two-pass domain PREFERENCE it uses has nothing to prefer once both
    /// forward sessions carry the same reverse identity.
    ///
    /// THIS IS `SessionKey.routing_domain`, NOT A SECOND NOTION OF DOMAIN, and
    /// that is a correctness requirement rather than tidiness. Three of the
    /// four sites that build this key -- the release path, the HA-synced
    /// reserve, and the NAT64 arms -- build it FROM a SessionKey, and
    /// `synced.rs` states outright that its flow must be "byte-identical to the
    /// active's SNAT-match tuple". A scope derived some other way at the match
    /// site (a hash of the instance NAME, say) would disagree with the value
    /// those three compute, and the standby would fail to reserve the flow the
    /// active reserved -- turning a cross-tenant collision into a sync defect.
    ///
    /// 0 is the default/unscoped instance, so a deployment with no routing
    /// instances keys exactly as it did before this change.
    pub(crate) routing_scope: u32,
}

impl SourceNatFlowKey {
    /// #2397: build the persistent-NAT lease key for this flow.
    ///
    /// #2823: the scope is selected by the three-way `permit` enum:
    ///   - `AnyRemoteHost`   -> `remote = None`: source-tuple-only key, any
    ///     remote host reuses the mapping.
    ///   - `TargetHost`      -> `remote = Some((dst_ip, 0))`: the destination
    ///     IP is folded in but the port is dropped, so a second flow from the
    ///     same source to a NEW port on the SAME remote host keys to the same
    ///     lease and reuses the mapping.
    ///   - `TargetHostPort`  -> `remote = Some((dst_ip, dst_port))`: the full
    ///     remote endpoint is folded in, so a different remote port keys to a
    ///     distinct lease and gets a fresh mapping (the pre-#2823 behavior).
    pub(in crate::nat) fn persistent_source_key(self, permit: PersistentNatPermit) -> PersistentSourceKey {
        PersistentSourceKey {
            protocol: self.protocol,
            src_ip: self.src_ip,
            src_port: self.src_port,
            // #10018: retain the exact routing domain that already
            // distinguishes `SourceNatFlowKey`. The allocator remains shared
            // for wire-identity occupancy (#9389); lease reuse alone is
            // partitioned so overlapping subscribers in different VRFs cannot
            // receive one another's persistent translation.
            routing_scope: self.routing_scope,
            remote: match permit {
                PersistentNatPermit::AnyRemoteHost => None,
                PersistentNatPermit::TargetHost => Some((self.dst_ip, 0)),
                PersistentNatPermit::TargetHostPort => Some((self.dst_ip, self.dst_port)),
            },
        }
    }
}
