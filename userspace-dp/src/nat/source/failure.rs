//! Per-rule failure taxonomy.
//!
//! The `SourceNatLookup` / `SourceNatFailure` / `SourceNatFailureReason` triple and
//! the snapshot-verdict mapper. Zero private dependencies on the rest of
//! `source`; it reads `SourceNatRule` only through that type's `pub(crate)`
//! fields.
//!
//! #6988 PURE CODE MOTION: every line below was moved verbatim from
//! `nat/source.rs` lines 59-215. The only edits are the visibility
//! widenings enumerated in `source/mod.rs`; no logic, no ordering and no
//! signature changed.

use super::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum SourceNatLookup {
    NoMatch,
    Matched(NatDecision),
    Unavailable(SourceNatFailure),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SourceNatFailure {
    pub(crate) rule_name: String,
    pub(crate) pool_name: String,
    pub(crate) reason: SourceNatFailureReason,
}

impl SourceNatFailure {
    pub(super) fn for_rule(rule: &SourceNatRule, reason: SourceNatFailureReason) -> Self {
        Self {
            rule_name: rule.name.clone(),
            pool_name: rule.pool_name.clone(),
            reason,
        }
    }

    pub(crate) fn exception_reason(&self) -> &'static str {
        self.reason.exception_reason()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SourceNatFailureReason {
    MissingPool,
    EmptyPool,
    InvalidPool,
    InvalidPortRange,
    WrongAddressFamily,
    AllocatorExhausted,
    /// #1852: a non-first IP fragment reached a port-translating
    /// (pool-mode) source-NAT rule. It has no L4 ports — allocating a
    /// mapping from its garbage payload "ports" would leak a pool port
    /// per fragment and corrupt payload. Without datapath reassembly the
    /// fragment cannot be correctly port-mapped, so it is dropped.
    NonFirstFragment,
    /// #4559: a deterministic CGNAT pool matched a flow whose subscriber IPv4 is
    /// outside the configured `host address` range (or the pool's parameters are
    /// degenerate). Deterministic NAT reserves a fixed block per in-range
    /// subscriber; an out-of-range source has no reserved block, so the
    /// allocation fails closed rather than silently round-robining it.
    DeterministicSubscriberOutOfRange,
    /// #5688: an interface-mode source-NAT rule matched, but the egress interface
    /// has NO address of the packet's family (a v4 packet on an egress interface
    /// with only v6 addresses, or vice versa). Interface SNAT translates the
    /// source to the egress interface's OWN same-family address; with none to
    /// use there is nothing to translate to, so the flow fails CLOSED (drop +
    /// count) rather than forwarding the private/internal source UNTRANSLATED
    /// onto the egress — the leak this closes.
    InterfaceNoEgressAddress,
    /// #6812: the pool's allocator key did not fit within the source-NAT
    /// AGGREGATE cardinality budget (pool count / total addresses / total port
    /// capacity — the same budgets the Go #5877 strict commit gate enforces)
    /// at the apply boundary, so no allocator was built for it. Reached only
    /// from a tolerated (lenient-load / peer-synced) config or a hand-crafted
    /// snapshot: a strict commit rejects the over-budget config before apply.
    /// Fail-closed exactly like the other pool-unusable reasons — the flow
    /// gets `Unavailable` (drop + count), never an untranslated forward.
    OverBudget,
    /// #6751: an interface-mode source-NAT admission found NO free translated
    /// identity for its `(egress address, remote endpoint)` — the preserved
    /// source port was owned by another flow AND every PAT candidate in
    /// 1024-65535 was too (or, for a port-less protocol, the single
    /// address-only identity was owned). Fails CLOSED: admitting an unowned
    /// duplicate is exactly the misdelivery this closes, so the flow is
    /// dropped and counted rather than sharing a reverse tuple.
    InterfaceIdentityExhausted,
    /// #6751: an interface-mode source-NAT admission could not create the
    /// REGISTRY state it needs — the retained-allocator cap with nothing
    /// reclaimable, or the per-address tracked-flow cap. Distinct from
    /// `InterfaceIdentityExhausted` because the remedy differs: this says
    /// "no more bookkeeping capacity", not "this identity space is full".
    InterfaceRegistryCap,
    /// #7717: the egress address this interface-mode admission would mint on
    /// still carries LIVE allocations from a quarantined source-NAT pool that
    /// is draining. The two domains keep independent occupancy, so minting
    /// here can hand out an identity the draining pool still owns — the
    /// collision `defect_pin_pool_and_interface_snat_mint_one_identity_7717`
    /// demonstrates.
    ///
    /// Deliberately NOT folded into `InterfaceIdentityExhausted`: the remedy
    /// differs and so does the expected duration. Exhaustion says "this
    /// identity space is full"; this says "someone else is still holding part
    /// of it and will let go". The quarantine lifts on its own when the last
    /// draining flow closes, so an operator seeing this counter climb should
    /// look at the overlap, not at pool sizing.
    InterfaceOverlapDraining,
    /// #7717: this POOL is quarantined because one of its addresses is also an
    /// interface-mode SNAT egress address, which the snapshot builder can only
    /// see for a runtime-resolved (DHCP/netlink) address. New pool mints are
    /// refused; its existing allocator is RETAINED so live flows drain.
    ///
    /// A distinct variant rather than reusing an existing failure because it is
    /// the ONLY one whose allocator is retained. Folding it into, say,
    /// `EmptyPool` would silently extend drain retention to every pool failure
    /// — a wider behaviour change than the demonstrated defect needs, and one
    /// that perturbs the #6812 budget walk for pools that have nothing to
    /// drain.
    PoolIfaceEgressOverlap,
    /// #6979 F6: this pool-mode allocation was rolled back because the
    /// `(pool address, port)` it landed on is already OWNED by a PEER pool —
    /// a different allocator key whose pool covers the same address.
    ///
    /// Two pools over one address are two independent occupancy bitmaps, each
    /// blind to the other, so without this check both mint the same translated
    /// identity for two live flows and the reverse index cannot attribute their
    /// replies. Measured on master, with and without the rule edit F6's text
    /// attributes it to.
    ///
    /// Fails CLOSED rather than retrying elsewhere: this allocator cannot
    /// enumerate the peer's held ports, so "pick another" is a guess, and the
    /// config that reaches this state is one the Go #5144 strict gate already
    /// rejects at commit (on ADDRESS overlap alone — it does not consult port
    /// ranges). Reached only from a tolerated lenient load, a peer sync, an
    /// older control plane, or a handcrafted snapshot: the same population
    /// `OverBudget` exists for (#6812).
    PoolPeerAddressOverlap,
}

impl SourceNatFailureReason {
    fn exception_reason(self) -> &'static str {
        match self {
            Self::MissingPool => "source_nat_pool_missing",
            Self::EmptyPool => "source_nat_pool_empty",
            Self::InvalidPool => "source_nat_pool_invalid",
            Self::InvalidPortRange => "source_nat_pool_invalid_port_range",
            Self::WrongAddressFamily => "source_nat_pool_wrong_family",
            Self::AllocatorExhausted => "source_nat_pool_exhausted",
            Self::NonFirstFragment => "source_nat_non_first_fragment",
            Self::DeterministicSubscriberOutOfRange => {
                "source_nat_deterministic_subscriber_out_of_range"
            }
            Self::InterfaceNoEgressAddress => "source_nat_interface_no_egress_address",
            Self::OverBudget => "source_nat_pool_over_budget",
            Self::InterfaceIdentityExhausted => "source_nat_interface_identity_exhausted",
            Self::InterfaceRegistryCap => "source_nat_interface_registry_cap",
            Self::InterfaceOverlapDraining => "source_nat_interface_overlap_draining",
            Self::PoolIfaceEgressOverlap => "source_nat_pool_iface_egress_overlap",
            Self::PoolPeerAddressOverlap => "source_nat_pool_peer_address_overlap",
        }
    }
}

pub(super) fn source_nat_failure_reason_from_snapshot(reason: &str) -> SourceNatFailureReason {
    match reason {
        "missing_pool" => SourceNatFailureReason::MissingPool,
        "empty_pool" => SourceNatFailureReason::EmptyPool,
        "invalid_port_range" => SourceNatFailureReason::InvalidPortRange,
        // #6812 F1 round 2: the Go snapshot builder now emits this for a pool
        // with ANY member `expand_pool_address` would refuse — an unparseable
        // token, a malformed mask, or an over-capacity prefix. It decodes to the
        // SAME variant the parse loop below assigns from its own
        // `invalid_pool_address` flag, so the disposition of such a pool is
        // unchanged; deciding it Go-side is what lets the aggregate budget walk
        // exclude the pool it knows builds no allocator.
        "invalid_pool" => SourceNatFailureReason::InvalidPool,
        "wrong_address_family" => SourceNatFailureReason::WrongAddressFamily,
        // #7717: emitted by the Go snapshot builder when a pool address is also
        // an interface-SNAT egress address. The ONLY reason whose allocator is
        // retained for draining.
        "iface_snat_egress_overlap" => SourceNatFailureReason::PoolIfaceEgressOverlap,
        "allocator_exhausted" => SourceNatFailureReason::AllocatorExhausted,
        // #6812: the Go tolerant snapshot poison for a pool that does not fit
        // the #5877 aggregate cardinality budget. Wire-skew safe: an older
        // helper maps the unknown string to InvalidPool via the catch-all —
        // still fail-closed, just a less specific diagnostic.
        "aggregate_over_budget" => SourceNatFailureReason::OverBudget,
        _ => SourceNatFailureReason::InvalidPool,
    }
}
