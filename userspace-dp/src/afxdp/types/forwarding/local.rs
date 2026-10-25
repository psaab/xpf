// Local/egress interface descriptor split from forwarding.rs
// (#16209). Pure code motion behind `forwarding/mod.rs`'s
// `use forwarding::*` glob; zero layout or access-site change.
// Visibility bill: no widening.

use super::super::*;

#[derive(Clone, Debug)]
pub(in crate::afxdp) struct EgressInterface {
    pub(in crate::afxdp) bind_ifindex: i32,
    pub(in crate::afxdp) vlan_id: u16,
    pub(in crate::afxdp) mtu: usize,
    pub(in crate::afxdp) src_mac: [u8; 6],
    /// #921: u32 zone ID (was `zone: String`). `0` means "unknown".
    ///
    /// #7025: THIS IS A DEBUG-ONLY MIRROR OF
    /// [`ForwardingState::ifindex_unambiguous_zone_id`], NOT a second opinion on
    /// the egress zone. Do not reach for it when you want the egress zone —
    /// call [`ForwardingState::egress_zone_id`], which reads the ledger.
    ///
    /// Before #6722 this field WAS the answer: `egress_zone_id` was
    /// `state.egress.get(&ifx).map(|i| i.zone_id)`. #6722 moved the answer into
    /// the ledger and pointed both `egress_zone_id` and `populate_egress` at it,
    /// so the two are equal by construction — `populate_egress` writes this
    /// field with the identical `ifindex_unambiguous_zone_id.get(..).unwrap_or(0)`
    /// expression `egress_zone_id` evaluates.
    ///
    /// The reader census is the COMPILER's, not a grep's: deleting this field
    /// and building the crate yields, in a DEFAULT build, seven `E0609` field
    /// reads and every one of them is in a test file — zero production readers.
    /// Building `--features debug-log` adds exactly one,
    /// `forwarding_build/mod.rs`'s `FWD_STATE: egress[..]` dump, which is
    /// compiled out of a normal build. That is why the field is retained with
    /// this note rather than dropped: the only thing it does is make one debug
    /// line self-describing, and removing it would rewrite 66 struct literals,
    /// 63 of them in unrelated test fixtures, to delete a value that cannot
    /// currently be wrong.
    ///
    /// "Cannot currently be wrong" is enforced, not asserted:
    /// `egress_zone_id_mirrors_the_unambiguous_ledger_7025` fails if the two
    /// ever diverge, so the drift this note warns a reader about cannot be
    /// introduced silently. That cell pins the INVARIANT over every egress row;
    /// specific expected zone values for specific shapes are pinned separately
    /// by the #6713/#6722 cells, and its own doc records which mutations each
    /// of them catches rather than assuming the new one is the only guard.
    pub(in crate::afxdp) zone_id: u32,
    pub(in crate::afxdp) redundancy_group: i32,
    pub(in crate::afxdp) primary_v4: Option<Ipv4Addr>,
    pub(in crate::afxdp) primary_v6: Option<Ipv6Addr>,
}
