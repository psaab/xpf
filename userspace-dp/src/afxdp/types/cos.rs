// Class-of-Service types extracted from afxdp/types/mod.rs (Issue 68.1).
// 28 items / ~700 LOC of CoS shaper / queue / flow-fair-RR / fast-path /
// runtime types and constants.
//
// Pure relocation. The original `pub(super)` visibility (super=afxdp) is
// translated to `pub(in crate::afxdp)` so the types remain reachable from
// any afxdp/* sibling. types/mod.rs re-exports them via `pub(in crate::afxdp)
// use cos::*;` so external call sites that use `crate::afxdp::types::CoSState`
// (etc.) continue to resolve through the same import path.

use super::*;

// #1614: f64 in CoSInterfaceConfig (oversubscription_guarantee_fraction)
// precludes Eq; drop Eq on the container type. PartialEq still permits
// the existing reconcile diff path (which only needs `!=`).
#[derive(Clone, Debug, Default, PartialEq)]
pub(in crate::afxdp) struct CoSState {
    pub(in crate::afxdp) interfaces: FastMap<i32, CoSInterfaceConfig>,
    /// Ingress classifier ids are retained independently of `interfaces`: the
    /// egress CoS admission gate may omit an ingress-only unit, while those
    /// ids still select transit packets' BA queue and loss-priority.
    pub(in crate::afxdp) ingress_classifier_bindings: FastMap<i32, CoSIngressClassifierBindings>,
    /// Globally compiled classifier tables. Ingress-unit bindings store
    /// integer indexes into these vectors so TX classification does not hash
    /// classifier names on the packet path.
    pub(in crate::afxdp) dscp_classifier_tables: Vec<CoSDSCPClassifierConfig>,
    pub(in crate::afxdp) ieee8021_classifier_tables: Vec<CoSIEEE8021ClassifierConfig>,
    pub(in crate::afxdp) inet_precedence_classifier_tables: Vec<CoSINetPrecedenceClassifierConfig>,
    pub(in crate::afxdp) dscp_rewrite_rules: FastMap<String, CoSDSCPRewriteRuleConfig>,
    /// Per-egress-interface loss-priority/rewrite tables, keyed by ifindex.
    /// The queue/rewrite matrix is egress-owned; classifier LP tables are
    /// retained for locally generated packets that have no wire ingress.
    pub(in crate::afxdp) lp_rewrite: FastMap<i32, CoSLossPriorityRewrite>,
}

/// Integer-indexed classifier bindings on a logical ingress unit, independent
/// of its egress shaping / scheduler state. `None` means that classifier type
/// is not bound on this ingress unit.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(in crate::afxdp) struct CoSIngressClassifierBindings {
    pub(in crate::afxdp) dscp: Option<usize>,
    pub(in crate::afxdp) inet_precedence: Option<usize>,
    pub(in crate::afxdp) ieee8021: Option<usize>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub(in crate::afxdp) enum CoSOversubscriptionPolicy {
    /// #1614 default: current scheduler unchanged bit-for-bit (when
    /// `priority_low_min_share_bytes == 0`).
    #[default]
    Proportional,
    /// #1614 A1: two-phase waterfill allocator using
    /// `guarantee_fraction` Pass 1 budget fraction.
    GuaranteeRate,
}

#[derive(Clone, Debug, PartialEq)]
pub(in crate::afxdp) struct CoSInterfaceConfig {
    pub(in crate::afxdp) shaping_rate_bytes: u64,
    pub(in crate::afxdp) burst_bytes: u64,
    pub(in crate::afxdp) default_queue: u8,
    /// Egress-unit classifier refs/tables are retained for locally generated
    /// packets, which have no wire ingress. Transit TX resolves BA classifiers
    /// from the logical ingress unit's indexed bindings in `CoSState`.
    pub(in crate::afxdp) dscp_classifier: String,
    pub(in crate::afxdp) ieee8021_classifier: String,
    /// #6847: the egress unit's bound `inet-precedence` classifier name, or
    /// empty. Used for local-generated TX and egress CoS admission.
    pub(in crate::afxdp) inet_precedence_classifier: String,
    pub(in crate::afxdp) dscp_queue_by_dscp: [u8; 64],
    pub(in crate::afxdp) ieee8021_queue_by_pcp: [u8; 8],
    /// #6847: IP-precedence code-point (0..=7) → queue id, `u8::MAX` for an
    /// unclassified code-point. Indexed by the top 3 bits of the DS field
    /// (`(dscp >> 3) & 0x7`), which is the same byte `dscp_queue_by_dscp`
    /// indexes on — hence the commit-time mutual exclusion between the two
    /// bindings.
    pub(in crate::afxdp) inet_precedence_queue_by_prec: [u8; 8],
    pub(in crate::afxdp) queue_by_forwarding_class: FastMap<String, u8>,
    pub(in crate::afxdp) queues: Vec<CoSQueueConfig>,
    /// #1614 A1: operator-selectable oversubscription policy.
    /// Default `Proportional` preserves current behaviour bit-for-
    /// bit (when `priority_low_min_share_bytes == 0`).
    pub(in crate::afxdp) oversubscription_policy: CoSOversubscriptionPolicy,
    /// #1614 A1: Phase 1 budget fraction (0.0..1.0). Only meaningful
    /// when `oversubscription_policy == GuaranteeRate`. 0.0 makes
    /// the allocator a no-op even if the policy enum is set.
    pub(in crate::afxdp) oversubscription_guarantee_fraction: f64,
    /// #1614 A2: priority-low minimum share in bytes per second.
    /// WIRE SURFACE ONLY in PR #1618 — the per-pass cap_eff
    /// subtraction in the selector is deferred to a focused
    /// follow-up. Default 0; no hot-path effect today.
    pub(in crate::afxdp) priority_low_min_share_bytes: u64,
}

/// Number of Junos loss-priority levels: low, medium-low, medium-high, high.
/// Indexed 0..=3 by `cos_loss_priority_index` in `forwarding_build/cos.rs`
/// (low=0 .. high=3). The classifier assigns one per code-point; the rewrite
/// rule keys on (forwarding-class, loss-priority).
pub(in crate::afxdp) const COS_LOSS_PRIORITY_LEVELS: u8 = 4;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(in crate::afxdp) struct CoSDSCPClassifierConfig {
    pub(in crate::afxdp) queue_by_dscp: FastMap<u8, u8>,
    /// #3995: behavior-aggregate loss-priority assigned per DSCP code-point
    /// (index 0=low .. 3=high). Parallel to `queue_by_dscp` — the same
    /// classifier entry that maps a DSCP to a forwarding-class (→ queue) also
    /// maps it to a loss-priority, which the egress rewrite-rule keys on.
    pub(in crate::afxdp) lp_by_dscp: FastMap<u8, u8>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(in crate::afxdp) struct CoSIEEE8021ClassifierConfig {
    pub(in crate::afxdp) queue_by_pcp: FastMap<u8, u8>,
    /// #3995: loss-priority assigned per 802.1p code-point (index 0=low ..
    /// 3=high). Parallel to `queue_by_pcp`.
    pub(in crate::afxdp) lp_by_pcp: FastMap<u8, u8>,
}

/// #6847: an IP-precedence behavior-aggregate classifier, resolved from
/// `CoSINetPrecedenceClassifierSnapshot`. Mirrors `CoSIEEE8021ClassifierConfig`
/// (same 3-bit code-point domain) but reads the DS field rather than the
/// 802.1Q tag, so it applies to untagged frames too.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(in crate::afxdp) struct CoSINetPrecedenceClassifierConfig {
    pub(in crate::afxdp) queue_by_prec: FastMap<u8, u8>,
    /// Loss-priority assigned per IP-precedence code-point (index 0=low ..
    /// 3=high). Parallel to `queue_by_prec` — without it a classifier entry's
    /// `loss-priority` would be accepted at commit and silently ignored on
    /// egress rewrite, the same accepted-but-inert failure #6847 removes from
    /// the queue side.
    pub(in crate::afxdp) lp_by_prec: FastMap<u8, u8>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(in crate::afxdp) struct CoSDSCPRewriteRuleConfig {
    /// #3995: egress DSCP rewrite keyed on `(forwarding_class, loss_priority)`.
    /// Junos rewrite-rules match a (forwarding-class, loss-priority) pair to a
    /// code-point, so a rule that rewrites `voice low` and `voice high` to
    /// different DSCPs must NOT collapse to forwarding-class only (the pre-fix
    /// `.or_insert` on a `FastMap<String, u8>` silently dropped every entry but
    /// the first). A rule with no explicit loss-priority is a wildcard: it
    /// fills all four loss-priority slots (backward-compat).
    pub(in crate::afxdp) dscp_by_fc_lp: FastMap<(String, u8), u8>,
}

/// #3995/#11679: per-egress loss-priority/rewrite tables, stored on
/// `CoSState::lp_rewrite` keyed by egress ifindex. The `(queue_id,
/// loss_priority)` rewrite matrix always belongs to egress. Transit LP is
/// selected from the logical ingress unit's indexed classifier tables; the
/// per-egress classifier tables below preserve the legacy behavior for locally
/// generated packets, which have no wire ingress.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::afxdp) struct CoSLossPriorityRewrite {
    /// Flattened DSCP → loss-priority (0..3) for local replies classified on
    /// the egress interface. `u8::MAX` = unclassified (default LOW).
    pub(in crate::afxdp) dscp_lp_by_dscp: [u8; 64],
    /// Flattened 802.1p PCP → loss-priority (0..3) for local replies.
    /// `u8::MAX` = unclassified.
    pub(in crate::afxdp) ieee8021_lp_by_pcp: [u8; 8],
    /// #6847: IP-precedence LP for local replies, following DSCP and preceding
    /// 802.1p. `u8::MAX` = unclassified.
    pub(in crate::afxdp) inet_precedence_lp_by_prec: [u8; 8],
    /// `(queue_id, loss_priority)` → egress DSCP code-point. Populated for the
    /// interface's materialized queues from the interface's rewrite-rule. The
    /// full loss-priority matrix (not just LOW) so a differentiated rule is
    /// applied per-flow.
    pub(in crate::afxdp) dscp_rewrite_by_queue_lp: FastMap<(u8, u8), u8>,
}

/// #1746: operator-selectable equal-flow target policy. Decides the
/// reduction applied over the sampled per-worker
/// `(prev_grant, active_flows)` pairs when
/// `publish_equal_flow_epoch_v8` computes the per-flow target. Only
/// meaningful when `equal_flow_enforcement` is on (the lease is in
/// `V8RateMode::EqualFlowSuppress`); the default `Slowest` preserves
/// the pre-#1746 `candidate_target.min(per_flow)` math byte-for-byte,
/// so unset configs and the named `slowest` value never diverge.
///
/// NONE of these policies can lift slow flows: the published cap is
/// one-directional (`my_share.min(cap)` in `acquire_v8`), and the
/// capacity freed by clipping a fast worker cannot reach a starved
/// worker on a different queue/CPU. Work-conserving cross-worker
/// rebalance is #1748, not this knob.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(in crate::afxdp) enum EqualFlowTargetPolicy {
    /// Clip every flow to the SLOWEST sampled achieved per-flow rate
    /// (`min` over the sampled set). Pre-#1746 behavior and the
    /// byte-unchanged default; the empty wire string decodes here.
    /// Maximum evenness, maximum aggregate cost (non-work-conserving).
    #[default]
    Slowest,
    /// Clip toward the aggregate-weighted mean achieved per-flow rate
    /// (`Σ prev_grants / Σ active_flows` over the sampled set). Clips
    /// only the lucky outliers; keeps more aggregate than `Slowest`.
    Mean,
    /// Literal nominal equal share (`scheduler_rate /
    /// total_active_flows`). Documented no-op in capacity-limited
    /// regimes — every flow already runs below the nominal share, so
    /// the cap never binds (#1745 live A/B).
    IdealShare,
}

impl EqualFlowTargetPolicy {
    /// Parse the wire string from `CoSSchedulerSnapshot`.
    ///
    /// #2458: the EMPTY string is the legitimate legacy/unset default and
    /// decodes to `Slowest` (byte-for-byte the pre-#1746 math). A NON-EMPTY
    /// UNKNOWN string (a typo or a version-drifted/mixed-version snapshot)
    /// is REJECTED rather than silently mapped to `Slowest` — silently
    /// collapsing an unrecognized value to the default would change queue
    /// fairness with no failure surfaced. The Go commit-time gate
    /// (`compiler_validate_strict.go`, #1746) is the primary defense; this
    /// fallible parse is the helper-boundary backstop, consistent with the
    /// #2447 CoS fail-closed family. Returns the offending value to the
    /// caller so the snapshot integrity error can name it.
    pub(in crate::afxdp) fn parse(value: &str) -> Result<Self, &str> {
        match value {
            "" | "slowest" => Ok(Self::Slowest),
            "mean" => Ok(Self::Mean),
            "ideal-share" => Ok(Self::IdealShare),
            other => Err(other),
        }
    }

    pub(in crate::afxdp) fn as_str(self) -> &'static str {
        match self {
            Self::Slowest => "slowest",
            Self::Mean => "mean",
            Self::IdealShare => "ideal-share",
        }
    }
}

#[cfg(test)]
mod equal_flow_target_policy_tests {
    use super::EqualFlowTargetPolicy;

    /// #2458: the empty (legacy/unset) wire string decodes to the
    /// byte-unchanged default `Slowest` — NOT an error.
    #[test]
    fn empty_decodes_to_slowest_default() {
        assert_eq!(
            EqualFlowTargetPolicy::parse(""),
            Ok(EqualFlowTargetPolicy::Slowest)
        );
        // The empty-string default and the explicit `slowest` value must be
        // indistinguishable (the empty-string contract documented on the
        // variant).
        assert_eq!(
            EqualFlowTargetPolicy::parse(""),
            EqualFlowTargetPolicy::parse("slowest")
        );
    }

    /// All three known wire strings round-trip through `parse`/`as_str`.
    #[test]
    fn known_values_decode_and_round_trip() {
        assert_eq!(
            EqualFlowTargetPolicy::parse("slowest"),
            Ok(EqualFlowTargetPolicy::Slowest)
        );
        assert_eq!(
            EqualFlowTargetPolicy::parse("mean"),
            Ok(EqualFlowTargetPolicy::Mean)
        );
        assert_eq!(
            EqualFlowTargetPolicy::parse("ideal-share"),
            Ok(EqualFlowTargetPolicy::IdealShare)
        );
        for p in [
            EqualFlowTargetPolicy::Slowest,
            EqualFlowTargetPolicy::Mean,
            EqualFlowTargetPolicy::IdealShare,
        ] {
            assert_eq!(EqualFlowTargetPolicy::parse(p.as_str()), Ok(p));
        }
    }

    /// #2458: a non-empty UNKNOWN value (a typo or version-drifted snapshot)
    /// is REJECTED — not silently mapped to `Slowest` — and the error names
    /// the offending value so the snapshot integrity error can surface it.
    #[test]
    fn unknown_non_empty_value_is_rejected() {
        assert_eq!(EqualFlowTargetPolicy::parse("typo"), Err("typo"));
        assert_eq!(
            EqualFlowTargetPolicy::parse("Slowest"),
            Err("Slowest"),
            "case-sensitive: the Go gate normalizes to lowercase before this point"
        );
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::afxdp) struct CoSQueueConfig {
    pub(in crate::afxdp) queue_id: u8,
    pub(in crate::afxdp) forwarding_class: String,
    pub(in crate::afxdp) priority: u8,
    pub(in crate::afxdp) transmit_rate_bytes: u64,
    /// True when this queue has an explicit scheduler transmit-rate and
    /// therefore participates in guarantee service. Scheduler-map entries
    /// without an explicit rate still keep an effective rate for burst sizing
    /// and surplus weighting, but are residual/surplus-only under the root
    /// shaper.
    pub(in crate::afxdp) guarantee_enabled: bool,
    pub(in crate::afxdp) exact: bool,
    /// #915: opt-in for exact queues to draw from root surplus
    /// tokens once their own bucket is empty. See the
    /// `CoSQueueConfigState.surplus_sharing` doc-comment for runtime
    /// semantics. Only meaningful when `exact == true` (the Go
    /// control plane warn-and-strips otherwise so the runtime
    /// never sees it set on a non-exact queue).
    pub(in crate::afxdp) surplus_sharing: bool,
    /// Explicit opt-in for shared equal-flow enforcement on positive
    /// exact queues. The coordinator turns this into
    /// `V8RateMode::EqualFlowSuppress` for shared v8 leases.
    pub(in crate::afxdp) equal_flow_enforcement: bool,
    /// #1746: target policy applied by the equal-flow publisher. Only
    /// meaningful when `equal_flow_enforcement == true`;
    /// forwarding_build gates it identically, so non-equal-flow
    /// queues always carry the default `Slowest`.
    pub(in crate::afxdp) equal_flow_target_policy: EqualFlowTargetPolicy,
    pub(in crate::afxdp) surplus_weight: u32,
    pub(in crate::afxdp) buffer_bytes: u64,
    /// #3995: loss-priority-INDEPENDENT egress DSCP rewrite applied at drain as
    /// a fallback. `Some` ONLY when the forwarding-class rewrites EVERY
    /// loss-priority to the SAME code-point (a single-value / wildcard rule),
    /// so applying it regardless of a packet's loss-priority is always correct.
    /// Loss-priority-DIFFERENTIATED rewrites resolve per-flow at CoS TX
    /// classification via `CoSLossPriorityRewrite.dscp_rewrite_by_queue_lp` and
    /// are cached in the flow's `dscp_rewrite`; this stays `None` for them so
    /// the drain fallback never misapplies one loss-priority's code-point to a
    /// packet of another (the #3995 collapse bug).
    pub(in crate::afxdp) dscp_rewrite: Option<u8>,
    /// #1614 A3: per-queue CoDel target in nanoseconds. WIRE
    /// SURFACE ONLY in PR #1618 — dequeue-time sojourn check
    /// deferred to a focused follow-up. 0 disables CoDel for the
    /// queue (current default and the only behaviour-affecting
    /// value today).
    pub(in crate::afxdp) codel_target_ns: u64,
}

impl CoSQueueConfig {
    /// A non-exact GUARANTEED queue whose configured rate trips
    /// `COS_SHARED_EXACT_MIN_RATE_BYTES` runs the sharded `shared_exact`
    /// execution policy: it drains locally on EVERY worker rather than
    /// being funnelled to one owner. The coordinator therefore attaches a
    /// shared legacy `SharedCoSQueueLease` so the class-wide guarantee
    /// admission is metered to the configured rate instead of admitting at
    /// `N_workers × rate` (#4265).
    ///
    /// This predicate is the SINGLE source of truth for "is this non-exact
    /// queue lease-metered?". Two sites must agree on it, and they used to
    /// diverge (the #5156 asymmetry): the coordinator uses it to decide
    /// whether to build the lease
    /// (`build_shared_cos_queue_leases_reusing_existing`), and the runtime
    /// builder uses it to start such a queue's token bucket at 0 (metered
    /// via the lease at runtime) instead of pre-filling `buffer_bytes`
    /// un-metered. Keeping both sites on one predicate is what makes the
    /// lease's init charge and teardown give-back symmetric: every byte the
    /// queue's `hot.tokens` ever holds is acquired through — and returned
    /// to — the shared lease.
    ///
    /// Returns false for exact queues (their lease is a v8 lease built on
    /// a separate branch and their bucket already starts at 0) and for
    /// single-owner low-rate non-exact queues (no lease; a private
    /// per-worker bucket is correct and must keep pre-filling its burst).
    pub(in crate::afxdp) fn is_shared_lease_metered(&self) -> bool {
        !self.exact
            && self.guarantee_enabled
            && self.transmit_rate_bytes
                >= crate::afxdp::worker::COS_SHARED_EXACT_MIN_RATE_BYTES
    }
}

pub(in crate::afxdp) const COS_FAST_QUEUE_INDEX_MISS: u16 = u16::MAX;

/// Number of SFQ flow buckets per flow-fair CoS queue.
///
/// GEMINI-NEXT.md Section 2 fairness: bumped 1024 → 4096. The metric
/// below is *per-flow* collision probability — i.e. the chance that any
/// given flow ends up sharing a bucket with at least one of the other
/// active flows in the queue, computed as `1 - (1 - 1/N)^(flows - 1)`
/// where N is `COS_FLOW_FAIR_BUCKETS`. Per-flow probability is what
/// directly governs that flow's fairness: colliding flows compete for
/// one SFQ dequeue slot and one admission-cap slice (#705).
///
/// Under typical 100E100M (Elephant + Mouse) workloads with ~200
/// concurrent flows per queue, 1024 buckets gave each flow ~17.7%
/// chance of sharing — a fairness leak even when MQFQ ordering was
/// correct. At 4096 buckets the same flow count drops the per-flow
/// probability to ~4.7%; at 64 flows it falls to ~1.5%. See #711 for
/// the original sizing analysis.
///
/// (The probability of *at least one* collision anywhere in the queue
/// — the canonical birthday-paradox metric — is much higher and stays
/// near 100% at 200 flows even at 4096 buckets. That metric is
/// fairness-irrelevant: a single colliding pair somewhere doesn't hurt
/// the other 198 flows.)
///
/// Per-queue memory overhead at 4096 buckets:
///   `flow_bucket_bytes: [u64; N]`    = 32 KB
///   `flow_bucket_head_finish_bytes: [u64; N]` = 32 KB
///   `flow_bucket_tail_finish_bytes: [u64; N]` = 32 KB
///   `flow_bucket_items: [VecDeque; N]` = 128 KB inline headers
///   `flow_rr_buckets: FlowRrRing` (`[u16; N] + head + len`) = 8 KB
/// = ~232 KB per flow-fair queue (was ~58 KB at 1024). Post-#1206 these
/// arrays live on `FlowFairState`, behind an `Option<Box<...>>` on
/// `CoSQueueRuntime`, so non-flow-fair queues no longer pay the inline
/// footprint at all — the field is `None` on those queues. Flow-fair
/// queues at 8 workers × 8 queues × 2 ifaces ≈ 30 MB total when fully
/// populated; non-flow-fair queues hold a pointer plus 0 bytes.
pub(in crate::afxdp) const COS_FLOW_FAIR_BUCKETS: usize = 4096;

/// Pre-computed mask for `COS_FLOW_FAIR_BUCKETS`-modulo on the hot
/// path. Using a mask (rather than `%`) gives deterministic codegen
/// independent of the optimizer proving the power-of-two property at
/// each call site.
pub(in crate::afxdp) const COS_FLOW_FAIR_BUCKET_MASK: usize = COS_FLOW_FAIR_BUCKETS - 1;

/// #694: Fixed-capacity ring buffer holding the set of currently-active
/// flow bucket IDs, driving SFQ round-robin dequeue.
///
/// Storage is exactly `COS_FLOW_FAIR_BUCKETS` u16 slots — no heap
/// allocation. Replaces a prior `VecDeque<u8>` which paid allocator
/// cost per queue and capped bucket IDs at 256 (incompatible with the
/// #711 bucket-count grow). The ring is accessed exclusively through
/// the associated methods, which are all O(1).
///
/// Invariant: the ring contains no duplicate bucket IDs. The callers
/// in `cos_queue_push_*` / `cos_queue_pop_front` already gate on
/// "bucket transitioned empty → non-empty" before pushing and on
/// "bucket still non-empty" before re-enqueueing the RR cursor, so the
/// ring itself does not revalidate on the hot path.
#[derive(Debug)]
pub(in crate::afxdp) struct FlowRrRing {
    buf: [u16; COS_FLOW_FAIR_BUCKETS],
    head: u16,
    len: u16,
}

impl Default for FlowRrRing {
    fn default() -> Self {
        Self {
            buf: [0; COS_FLOW_FAIR_BUCKETS],
            head: 0,
            len: 0,
        }
    }
}

impl FlowRrRing {
    #[inline]
    pub(in crate::afxdp) fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[inline]
    pub(in crate::afxdp) fn len(&self) -> usize {
        usize::from(self.len)
    }

    #[inline]
    pub(in crate::afxdp) fn front(&self) -> Option<u16> {
        if self.len == 0 {
            None
        } else {
            Some(self.buf[usize::from(self.head)])
        }
    }

    /// Iterate active bucket IDs in service order (head first).
    pub(in crate::afxdp) fn iter(&self) -> FlowRrRingIter<'_> {
        FlowRrRingIter {
            ring: self,
            offset: 0,
        }
    }

    // Hot-path invariant: the caller in `cos_queue_push_*` gates every
    // push on "bucket transitioned empty → non-empty", so a bucket ID
    // is in the ring at most once. The ring therefore never holds more
    // than `COS_FLOW_FAIR_BUCKETS` entries, and `len < CAP` is a
    // structural invariant — not a runtime bound we need to defend
    // against. `debug_assert!` enforces it in tests; release uses a
    // plain `+= 1` rather than `saturating_add` because a silent
    // saturation on a violated invariant would hide a real bug (the
    // push would succeed at the wrapped-buffer index and the ring
    // would lose either the new entry or an older one, depending on
    // head placement — very hard to triage).
    #[inline]
    pub(in crate::afxdp) fn push_back(&mut self, bucket: u16) {
        debug_assert!(
            usize::from(self.len) < COS_FLOW_FAIR_BUCKETS,
            "FlowRrRing overflow: len={} cap={}",
            self.len,
            COS_FLOW_FAIR_BUCKETS
        );
        let tail = (usize::from(self.head) + usize::from(self.len)) & COS_FLOW_FAIR_BUCKET_MASK;
        self.buf[tail] = bucket;
        self.len += 1;
    }

    #[inline]
    pub(in crate::afxdp) fn push_front(&mut self, bucket: u16) {
        debug_assert!(
            usize::from(self.len) < COS_FLOW_FAIR_BUCKETS,
            "FlowRrRing overflow: len={} cap={}",
            self.len,
            COS_FLOW_FAIR_BUCKETS
        );
        // head := (head + CAP - 1) mod CAP, with CAP a power of two
        // so this is a mask-only op. Avoids the `if head == 0` branch
        // on the hot path.
        self.head = ((usize::from(self.head) + COS_FLOW_FAIR_BUCKETS - 1)
            & COS_FLOW_FAIR_BUCKET_MASK) as u16;
        self.buf[usize::from(self.head)] = bucket;
        self.len += 1;
    }

    #[inline]
    pub(in crate::afxdp) fn pop_front(&mut self) -> Option<u16> {
        if self.len == 0 {
            return None;
        }
        let bucket = self.buf[usize::from(self.head)];
        self.head = ((usize::from(self.head) + 1) & COS_FLOW_FAIR_BUCKET_MASK) as u16;
        self.len -= 1;
        Some(bucket)
    }

    /// #785 Phase 3 — remove a specific bucket ID from the active
    /// set wherever it sits in the ring. Used by the MQFQ dequeue
    /// path when the bucket with the minimum virtual-finish-time
    /// (which may not be at `head`) drains to empty and must
    /// de-register from the active set.
    ///
    /// O(len) — scans the ring. `len` is bounded by the number of
    /// concurrently active flow buckets, typically 2-16 on
    /// iperf3-style workloads, up to `COS_FLOW_FAIR_BUCKETS = 4096`
    /// worst case. Returns `true` if the bucket was found and
    /// removed.
    ///
    /// Implementation: find the position via linear scan, then
    /// shift subsequent entries left (preserving head-relative
    /// order). Head stays fixed; `len` decrements. Avoids the
    /// alternative of "swap with tail then decrement" which would
    /// reorder the active set — acceptable for membership-only
    /// semantics but noisy for any future debug invariants that
    /// assume insertion-order preservation.
    pub(in crate::afxdp) fn remove(&mut self, bucket: u16) -> bool {
        if self.len == 0 {
            return false;
        }
        let head = usize::from(self.head);
        let len = usize::from(self.len);
        for i in 0..len {
            let idx = (head + i) & COS_FLOW_FAIR_BUCKET_MASK;
            if self.buf[idx] == bucket {
                // Shift subsequent entries left by one.
                for j in i..len - 1 {
                    let src = (head + j + 1) & COS_FLOW_FAIR_BUCKET_MASK;
                    let dst = (head + j) & COS_FLOW_FAIR_BUCKET_MASK;
                    self.buf[dst] = self.buf[src];
                }
                self.len -= 1;
                return true;
            }
        }
        false
    }
}

pub(in crate::afxdp) struct FlowRrRingIter<'a> {
    ring: &'a FlowRrRing,
    offset: usize,
}

#[derive(Clone)]
pub(in crate::afxdp) struct WorkerCoSQueueFastPath {
    pub(in crate::afxdp) shared_exact: bool,
    pub(in crate::afxdp) owner_worker_id: u32,
    pub(in crate::afxdp) owner_live: Option<Arc<BindingLiveState>>,
    pub(in crate::afxdp) shared_queue_lease: Option<Arc<SharedCoSQueueLease>>,
    /// #917 — cross-worker MQFQ V_min coordination structure.
    /// Allocated lazily on `shared_exact` promotion (one per
    /// shared queue, not per worker). All workers servicing the
    /// same shared queue receive the same `Arc`. `None` on
    /// non-shared queues (V_min sync only applies to
    /// `shared_exact`).
    pub(in crate::afxdp) vtime_floor: Option<Arc<SharedCoSQueueVtimeFloor>>,
}

#[derive(Clone)]
pub(in crate::afxdp) struct WorkerCoSInterfaceFastPath {
    pub(in crate::afxdp) tx_ifindex: i32,
    pub(in crate::afxdp) default_queue_index: usize,
    pub(in crate::afxdp) queue_index_by_id: [u16; 256],
    pub(in crate::afxdp) tx_owner_live: Option<Arc<BindingLiveState>>,
    pub(in crate::afxdp) shared_root_lease: Option<Arc<SharedCoSRootLease>>,
    pub(in crate::afxdp) shared_exact_backlog: Option<Arc<SharedCoSExactBacklog>>,
    pub(in crate::afxdp) queue_fast_path: Vec<WorkerCoSQueueFastPath>,
}

impl WorkerCoSInterfaceFastPath {
    #[inline]
    pub(in crate::afxdp) fn effective_queue_index(
        &self,
        requested_queue_id: Option<u8>,
    ) -> Option<usize> {
        if let Some(queue_id) = requested_queue_id {
            let idx = self.queue_index_by_id[usize::from(queue_id)];
            if idx != COS_FAST_QUEUE_INDEX_MISS {
                return Some(idx as usize);
            }
            return None;
        }
        (!self.queue_fast_path.is_empty()).then_some(
            self.default_queue_index
                .min(self.queue_fast_path.len().saturating_sub(1)),
        )
    }

    #[inline]
    pub(in crate::afxdp) fn queue_fast_path(
        &self,
        requested_queue_id: Option<u8>,
    ) -> Option<&WorkerCoSQueueFastPath> {
        self.effective_queue_index(requested_queue_id)
            .and_then(|idx| self.queue_fast_path.get(idx))
    }
}

pub(in crate::afxdp) struct CoSInterfaceRuntime {
    pub(in crate::afxdp) shaping_rate_bytes: u64,
    pub(in crate::afxdp) burst_bytes: u64,
    pub(in crate::afxdp) tokens: u64,
    pub(in crate::afxdp) nonexact_surplus_under_exact_tokens: u64,
    pub(in crate::afxdp) nonexact_surplus_under_exact_last_refill_ns: u64,
    pub(in crate::afxdp) default_queue: u8,
    pub(in crate::afxdp) nonempty_queues: usize,
    pub(in crate::afxdp) runnable_queues: usize,
    /// #1614 A1: copied from `CoSInterfaceConfig.oversubscription_policy`
    /// at `build_cos_interface_runtime` time. Controls whether the
    /// hot-path selector runs the legacy round-robin (`Proportional`)
    /// or the v5 two-phase waterfill allocator (`GuaranteeRate`).
    pub(in crate::afxdp) oversubscription_policy: CoSOversubscriptionPolicy,
    /// #1614 A1: Phase 1 budget fraction (0.0..1.0). Honored only when
    /// `oversubscription_policy == GuaranteeRate`.
    pub(in crate::afxdp) oversubscription_guarantee_fraction: f64,
    /// #1614 A2: priority-low minimum share in bytes per second.
    /// WIRE SURFACE ONLY in PR #1618. The intended semantic
    /// (cap_eff = root.tokens.saturating_sub(min_share_pass)
    /// applied before the A1 selector) is deferred to a focused
    /// follow-up issue. Today no hot-path code consults this
    /// field; default 0 and any other value behave identically.
    pub(in crate::afxdp) priority_low_min_share_bytes: u64,
    /// #1614 A2 helper (reserved for the deferred cap_eff
    /// mechanism): per-pass priority-low min-share bytes that
    /// will be reserved before the A1 selector runs once the
    /// follow-up issue ships. Currently UNUSED.
    pub(in crate::afxdp) priority_low_reserved_tokens: u64,
    /// #1614 A2 helper (reserved for the deferred cap_eff
    /// mechanism): last-refill timestamp companion to
    /// `priority_low_reserved_tokens`. Currently UNUSED.
    pub(in crate::afxdp) priority_low_last_refill_ns: u64,
    /// #1614 A1: pre-sorted queue indices ordered ascending by
    /// `transmit_rate_bytes`. Built at `build_cos_interface_runtime`
    /// time; runtime is read-only. Used by the GuaranteeRate
    /// waterfill phase 1 greedy honor loop.
    pub(in crate::afxdp) exact_queues_by_rate_ascending: Vec<usize>,
    /// #1614 A1: Phase 1 byte budget remaining in the current
    /// service epoch. #1743: an epoch ends on EITHER a Phase-2 wrap
    /// (full RR cycle through the sorted vec) OR a 200µs time tick —
    /// it is no longer strictly one RR cycle, so `waterfill_epochs`
    /// counts budget refreshes (either trigger), not RR completions.
    /// #1743: refilled to `(shaping_rate_bytes × COS_GUARANTEE_VISIT_NS
    /// / 1e9 × guarantee_fraction)` for a SHAPED root (the documented
    /// "fraction × cap" contract) or the legacy `(quantum_sum ×
    /// guarantee_fraction)` for a transparent root, clamped to ≥ one
    /// min-quantum. Decremented per successful Phase 1 honor by the
    /// chosen queue's STABLE configured quantum (`phase1_cost`, NOT the
    /// token-clamped send budget). When it drops below the next queue's
    /// quantum, the selector switches to Phase 2 residual distribution.
    pub(in crate::afxdp) waterfill_pass1_remaining_bytes: u64,
    /// #1614 A1: descending-rate cursor into the sorted vec for
    /// Phase 2 residual distribution. Tracks where in the
    /// descending walk (largest-rate-first) the last Phase 2
    /// service event landed.
    pub(in crate::afxdp) waterfill_phase2_cursor: usize,
    /// #1732: persistent Phase-1 honored bitset for the current waterfill
    /// epoch. Bit `j` set ⇔ the exact queue at ORDINAL position `j` in
    /// `exact_queues_by_rate_ascending` was honored in Phase 1 this epoch.
    /// Keyed by ASCENDING-VEC ORDINAL, NOT by `queue_idx` (the `queues`
    /// index): both phases iterate this same sorted vec, so ordinal `j`
    /// unambiguously identifies one queue.
    ///
    /// The word vector is sized once when the interface runtime is built,
    /// with one `u64` per 64 exact guarantee queues. This supports every
    /// ordinal without per-selector allocation or a fixed queue-count cap.
    /// The set is CLEARED only on a genuine epoch boundary — the 200µs time
    /// tick OR a Phase-2 WRAP (`waterfill_epoch_wrap_pending`) — NOT on every
    /// Phase-1 budget refill (`waterfill_epochs` still bumps on every refill,
    /// but a bare mid-walk `pass1 == 0` refill must keep the bits so an
    /// exact-fit honor does not re-honor the same queue forever).
    /// Single-writer owner worker.
    pub(in crate::afxdp) waterfill_honored_epoch_bits: Vec<u64>,
    /// #1628: completed waterfill epochs (Phase-1 budget refills) on this
    /// interface, THIS WORKER's view. Bumped at the lazy Phase-1 refill
    /// site. NOT a per-queue normalizer (the cross-worker SUM would be
    /// diluted by worker count); used as a cluster event counter (SUM)
    /// plus the coordinator's per-worker MIN (`waterfill_min_epochs_per_
    /// worker` on `CoSInterfaceStatus`), which flags a single worker
    /// frozen in Phase-2 lock-in. Single-writer owner worker, plain `u64`.
    pub(in crate::afxdp) waterfill_epochs: u64,
    /// #1628: times Phase 1 broke into Phase 2 because the next ascending
    /// queue's rate-scaled cost exceeded the remaining Phase-1 budget.
    /// Per-INTERFACE not per-queue: the break only ever sees the first
    /// queue that crosses the boundary, so a per-queue attribution would
    /// silently miss the larger queues never reached. A high
    /// breaks-per-epoch ratio means Phase 1 routinely exhausts its budget
    /// mid-walk. Single-writer owner worker, plain `u64`.
    pub(in crate::afxdp) waterfill_phase1_budget_breaks: u64,
    /// #1743: monotonic nanosecond timestamp of the most recent waterfill
    /// Phase-1 epoch refill. The selector refreshes the Phase-1 budget when
    /// `now_ns - waterfill_epoch_start_ns >= COS_GUARANTEE_VISIT_NS` (200µs)
    /// in addition to the `pass1 == 0` budget-spent path. Without the
    /// time-based refresh, Phase-2 selections (which do NOT decrement the
    /// Phase-1 budget) let the budget freeze at a small non-zero value under
    /// saturation, so small classes stop being honored after a few epochs.
    /// Worker-local runtime; NOT HA-synced (same class as the other
    /// waterfill_* fields above). Single-writer owner worker, plain `u64`.
    pub(in crate::afxdp) waterfill_epoch_start_ns: u64,
    /// #1743 (Codex code-r3): true when a genuine epoch boundary is pending
    /// — set ONLY by the end-of-function Phase-2 WRAP (`None`) path, which
    /// also zeroes `waterfill_pass1_remaining_bytes` and the cursor. The
    /// distinction matters because `pass1` can also reach 0 mid-walk when a
    /// Phase-1 exact-fit honor subtracts the last bytes; that is NOT an epoch
    /// boundary. The honored-bitset is cleared (allowing queues to be
    /// re-honored) ONLY on the time tick OR when this flag is set — NOT on
    /// every `pass1 == 0` refill. Clearing on a bare mid-walk `pass1 == 0`
    /// re-enabled a degenerate all-min-quantum livelock (q0 honored → pass1=0
    /// → clear bits → q0 re-honored → … with Phase 2 never reached). A bare
    /// `pass1 == 0` still REFILLS the budget so Phase 1 can resume, but with
    /// the honored bits intact the already-honored small queue is skipped and
    /// the walk advances / breaks to Phase 2. Single-writer owner worker.
    pub(in crate::afxdp) waterfill_epoch_wrap_pending: bool,
    // Round-robin cursors for the two guarantee service classes. Exact and
    // non-exact guarantee queues rotate independently — the scheduler gives
    // exact queues strict priority over non-exact guarantee service (the
    // exact path runs first in `drain_shaped_tx`; non-exact only runs when
    // the exact path returns None), and within each class RR ordering is
    // preserved across calls without coupling to the other class's service
    // events. Prior to #689 both passes shared a single `guarantee_rr`
    // cursor; that had neither pure unified-RR semantics (because the exact
    // path always wins at a shared rr position) nor clean class-independent
    // semantics (because service events in one class advanced the cursor
    // seen by the other), and in pathological backlog mixes could produce
    // non-obvious skips in the non-exact rotation.
    pub(in crate::afxdp) exact_guarantee_rr: usize,
    pub(in crate::afxdp) nonexact_guarantee_rr: usize,
    // Unified-walk cursor used only by the test-only legacy selector
    // `select_cos_guarantee_batch_with_fast_path`. Gated on `cfg(test)`
    // so non-test builds of the hot CoS fast-path runtime do not pay
    // field footprint or init churn for compatibility scaffolding.
    // Separate from the production cursors above so test harnesses that
    // exercise the legacy walk do not disturb production rotation state
    // and vice versa — see the
    // `legacy_guarantee_rr_does_not_advance_class_cursors` regression
    // that pins that isolation contract.
    #[cfg(test)]
    pub(in crate::afxdp) legacy_guarantee_rr: usize,
    pub(in crate::afxdp) queues: Vec<CoSQueueRuntime>,
    pub(in crate::afxdp) queue_indices_by_priority: [Vec<usize>; COS_PRIORITY_LEVELS],
    pub(in crate::afxdp) rr_index_by_priority: [usize; COS_PRIORITY_LEVELS],
    pub(in crate::afxdp) timer_wheel: CoSTimerWheelRuntime,
}

/// #785 Phase 3 — Codex round-3 HIGH: pop→push_front round-trip
/// snapshot. Captured by `cos_queue_pop_front` immediately before
/// advancing `queue_vtime`, consumed by `cos_queue_push_front` to
/// restore pre-pop head/tail when the popped item rolls back onto
/// the queue (TX-ring-full retry path).
///
/// Without this snapshot, a push_front onto a drained bucket
/// (Rust reviewer MEDIUM #1) re-anchors head/tail to
/// `max(0, queue_vtime) + bytes`. Even if `queue_vtime` is rewound
/// symmetrically, that formula overshoots the pre-pop head by one
/// packet when the item was freshly enqueued at the pre-pop vtime:
/// the pre-pop head was `V + X`, the post-pop+rewind anchor would
/// be `V + X` (correct only by coincidence), but in the general
/// case where the item was enqueued long before pop (so head
/// trailed vtime) the rewound-anchor overshoots. Restoring the
/// snapshot exactly is the only path to true round-trip neutrality.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(in crate::afxdp) struct CoSQueuePopSnapshot {
    /// The bucket that was popped from. Used by
    /// `cos_queue_push_front` to verify it is restoring the SAME
    /// bucket the snapshot was captured for.
    ///
    /// **#913 contract**: a bucket mismatch on push_front is a
    /// HARD INVARIANT VIOLATION and panics via `assert!(false)`
    /// (see `cos_queue_push_front`). Stale-snapshot prevention is
    /// the responsibility of the surrounding helpers, NOT a
    /// runtime fallback:
    ///   - Batch-start clears in
    ///     `drain_exact_local_items_to_scratch_flow_fair` and
    ///     `drain_exact_prepared_items_to_scratch_flow_fair`
    ///     (the hot-path scratch builders) and in
    ///     `cos_queue_push_back` (any new enqueue invalidates
    ///     all outstanding pop snapshots).
    ///   - Drain-start clear in `cos_queue_drain_all` (#913).
    ///   - Orphan-drop cleanup at the four scratch-builder Drop
    ///     sites via `cos_queue_clear_orphan_snapshot_after_drop`
    ///     (#913 §3.4).
    /// With those in place, mismatch is believed unreachable in
    /// current code; the assert is a defensive tripwire for any
    /// future caller that introduces a new pop+drop site without
    /// the cleanup.
    pub(in crate::afxdp) bucket: u16,
    /// Bucket's HEAD finish time BEFORE the pop-time advance.
    pub(in crate::afxdp) pre_pop_head_finish: u64,
    /// Bucket's TAIL finish time BEFORE the pop-time advance.
    pub(in crate::afxdp) pre_pop_tail_finish: u64,
    /// #913 — flow-fair `queue_vtime` BEFORE the pop-time advance.
    /// Captured so push_front can exactly restore vtime under the
    /// new MQFQ served-finish semantics, where the advance is
    /// `max(vtime, served_finish)` (no fixed delta — symmetric
    /// rewind by `item_len` is wrong).
    pub(in crate::afxdp) pre_pop_queue_vtime: u64,
}

pub(in crate::afxdp) struct CoSQueueRuntime {
    pub(in crate::afxdp) config: CoSQueueConfigState,
    pub(in crate::afxdp) hot: CoSQueueHotState,
    pub(in crate::afxdp) flow_fair_state: Option<Box<FlowFairState>>,
    pub(in crate::afxdp) v_min: VMinQueueState,
    pub(in crate::afxdp) telemetry: CoSQueueTelemetry,
    /// #1229 Phase 6 v8: per-worker fair-share lease back-reference.
    /// `Some` for guarantee-phase exact queues bound to a v8 lease.
    /// Active-bucket helpers (`cos/queue_ops/active_buckets.rs`) read
    /// this to delta-update the lease's per-worker counter on
    /// transitions. `None` for non-flow-fair, non-exact, transparent,
    /// surplus-sharing-only, or root-only queues — those don't
    /// participate in v8 fair scheduling and incur zero overhead from
    /// the helpers' optional path.
    pub(in crate::afxdp) queue_lease_v8: Option<Arc<SharedCoSQueueLease>>,
}

impl CoSQueueRuntime {
    #[inline]
    pub(in crate::afxdp) fn queue_id(&self) -> u8 {
        self.config.queue_id
    }

    /// #1735: the flow-fair gate is now `flow_fair_state.is_some()`,
    /// NOT `config.flow_fair`. This makes the invariant
    /// `flow_fair() == flow_fair_state.is_some()` structurally
    /// unbreakable: a queue with `None` state always dispatches through
    /// the cheap FIFO branch, and allocation (eager for exact, lazy for
    /// non-exact promoted) is the ONLY thing that flips the gate. Every
    /// `if queue.flow_fair() { ...flow_fair_state.expect()... }` site
    /// is now provably unreachable on the `None` side. `config.exact`
    /// (eager promotion) and `config.flow_fair_eligible` (may EVER
    /// promote) are decoupled from this runtime gate.
    #[inline]
    pub(in crate::afxdp) fn flow_fair(&self) -> bool {
        self.flow_fair_state.is_some()
    }

    #[inline]
    pub(in crate::afxdp) fn shared_exact(&self) -> bool {
        self.config.shared_exact
    }

    #[inline]
    pub(in crate::afxdp) fn transmit_rate_bytes(&self) -> u64 {
        self.config.transmit_rate_bytes
    }
}

/// Immutable-after-build config bits. Written during queue construction and
/// promotion; steady-state hot-path mutation lives in the sibling state
/// structs.
pub(in crate::afxdp) struct CoSQueueConfigState {
    pub(in crate::afxdp) queue_id: u8,
    pub(in crate::afxdp) priority: u8,
    pub(in crate::afxdp) transmit_rate_bytes: u64,
    /// Immutable guarantee eligibility bit copied from `CoSQueueConfig`.
    /// Do not infer this from `transmit_rate_bytes == 0`: transparent
    /// zero-rate queues use that value to mean "unshaped/full bucket", while
    /// residual-only queues under a shaped root may carry a positive effective
    /// rate for sizing and accounting.
    pub(in crate::afxdp) guarantee_enabled: bool,
    pub(in crate::afxdp) exact: bool,
    /// #915: only meaningful when `exact == true`. When set, the
    /// queue (1) is NOT parked on `queue.hot.tokens < head_len` in
    /// the exact-guarantee selector, and
    /// (2) participates in `select_cos_surplus_batch` as if it
    /// were non-exact. The combined effect is that the queue
    /// retains its strict-priority guarantee but can also draw
    /// from root surplus tokens once its own bucket is empty.
    /// `tx_completion::apply_cos_*_result` phase-gates the
    /// `shared_queue_lease` consumption to Guarantee phase only,
    /// so surplus draws don't debit the per-queue rate cap.
    pub(in crate::afxdp) surplus_sharing: bool,
    /// Explicit opt-in for shared equal-flow enforcement on positive
    /// exact queues. The coordinator turns this into
    /// `V8RateMode::EqualFlowSuppress` for shared v8 leases.
    pub(in crate::afxdp) equal_flow_enforcement: bool,
    /// #1735: renamed from `flow_fair`. Decoupled from the runtime
    /// `flow_fair()` gate (now `flow_fair_state.is_some()`). This bit
    /// means "this queue MAY ever run flow-fair MQFQ" — set for every
    /// shaped CoS queue that reaches `promote_cos_queue_flow_fair`
    /// (exact AND non-exact). Exact queues additionally promote
    /// EAGERLY at build (allocate `flow_fair_state` immediately);
    /// non-exact eligible queues stay `None` until the lazy
    /// front-key contention probe in `cos_queue_push_back` promotes
    /// them on the first differing flow. Forwarding-only / transparent
    /// interfaces never build a `CoSInterfaceRuntime` (the #1183
    /// "useful CoS state" gate), so their queues never reach promotion
    /// and stay ineligible — preserving the #1183 best-effort
    /// fast-path boundary.
    pub(in crate::afxdp) flow_fair_eligible: bool,
    /// #785: cached shadow of `WorkerCoSQueueFastPath.shared_exact`
    /// populated by `promote_cos_queue_flow_fair`. Under the current
    /// promotion policy (`flow_fair = queue.exact`), shared_exact
    /// queues ARE on the flow-fair MQFQ path with cross-worker V_min
    /// sync via `vtime_floor: Arc<...>` (#917). The cached
    /// `shared_exact` flag remains on `CoSQueueRuntime` so admission
    /// paths can apply rate-aware caps differently from owner-local
    /// exact queues — see `cos_queue_flow_share_limit` (#914), which
    /// returns `max(fair_share*2, bdp_floor).clamp(MIN, buffer_limit)`
    /// on shared_exact instead of the legacy MIN-floor cap.
    ///
    /// Keeping the field on the queue runtime makes the policy bit
    /// available to hot-path helpers directly from
    /// `&CoSQueueRuntime`, so current and future branching does not
    /// have to thread extra interface state through admission-path
    /// call sites or add an iface_fast lookup there.
    pub(in crate::afxdp) shared_exact: bool,
    pub(in crate::afxdp) surplus_weight: u32,
    pub(in crate::afxdp) buffer_bytes: u64,
    pub(in crate::afxdp) dscp_rewrite: Option<u8>,
    /// #1614 A3: per-queue CoDel target in nanoseconds. WIRE
    /// SURFACE ONLY in PR #1618 — the dequeue-time sojourn check
    /// (intended to drop or CE-mark when packet sojourn > target)
    /// is deferred to a focused follow-up. 0 disables CoDel for
    /// the queue (current default and the only behaviour-affecting
    /// value today).
    pub(in crate::afxdp) codel_target_ns: u64,
}

/// Hot per-pop / per-push state: token bucket, FIFO storage, runnable
/// bookkeeping, and queue-local counters that are not flow-fair-specific.
pub(in crate::afxdp) struct CoSQueueHotState {
    pub(in crate::afxdp) surplus_deficit: u64,
    pub(in crate::afxdp) tokens: u64,
    pub(in crate::afxdp) last_refill_ns: u64,
    pub(in crate::afxdp) queued_bytes: u64,
    pub(in crate::afxdp) runnable: bool,
    pub(in crate::afxdp) parked: bool,
    pub(in crate::afxdp) next_wakeup_tick: u64,
    pub(in crate::afxdp) wheel_level: u8,
    pub(in crate::afxdp) wheel_slot: usize,
    pub(in crate::afxdp) items: VecDeque<CoSPendingTxItem>,
    /// #774 optimization: cached count of `Local` items currently
    /// resident in `items` + `flow_bucket_items`. Incremented /
    /// decremented at every `cos_queue_push_*` and
    /// `cos_queue_pop_front` site. Replaces an O(n) scan in
    /// `cos_queue_accepts_prepared` that profiled at 3.25% CPU on
    /// the hot path at line rate. Owner-only writes; no atomic
    /// needed (same discipline as `queued_bytes`).
    pub(in crate::afxdp) local_item_count: u32,
    /// #1735: consecutive quiescent batch-settle observations on a
    /// lazily-promoted NON-exact flow-fair queue. Incremented by
    /// `maybe_demote_drained_best_effort` when the queue settles fully
    /// drained; reset to 0 on any non-quiescent settle. When it reaches
    /// `COS_DEMOTE_EMPTY_SETTLE_HYSTERESIS` the queue demotes
    /// (`flow_fair_state = None`, dropping the ~232 KB box). Hysteresis
    /// prevents a queue oscillating 1<->2 flows from thrashing the
    /// alloc/free of `FlowFairState`. Always 0 on exact queues (they
    /// never demote) and on non-eligible queues.
    pub(in crate::afxdp) cos_demote_empty_settles: u8,
}

/// Flow-fair MQFQ state. Only allocated when `queue.flow_fair() == true`.
/// This struct is the only boxed flow-fair allocation; per-bucket arrays are
/// inline here and are not double-boxed.
pub(in crate::afxdp) struct FlowFairState {
    /// #785 Phase 3 — MQFQ queue virtual time. Updated on every
    /// dequeue to `finish[bucket]` of the drained bucket. Serves
    /// as the "catch-up anchor" in the enqueue formula:
    /// `finish[b] = max(finish[b], queue_vtime) + bytes`. A newly
    /// arriving flow bucket that's been idle re-anchors to
    /// `queue_vtime` so it starts competing at the current frontier
    /// rather than from 0 (which would let it sweep past all
    /// established flows in bounded rounds).
    ///
    /// Read by `cos_queue_min_finish_bucket` (as the `max(tail, vtime)`
    /// anchor source on idle-bucket re-entry).
    ///
    /// Hot-path advance (#913 served-finish semantics): on a snapshotting
    /// `cos_queue_pop_front`, `vtime = max(vtime, served_finish)` where
    /// served_finish is the popped bucket's pre-pop head_finish. The
    /// paired `cos_queue_push_front` restores from the snapshot stack
    /// (LIFO, per-pop) so rollback is exact. The legacy aggregate-bytes
    /// advance (`vtime += bytes`) is retained only on
    /// `cos_queue_pop_front_no_snapshot` (drain_all + worker teardown),
    /// which clears the snapshot stack so the paired empty-stack
    /// `push_front` rewinds with `vtime -= item_len`.
    ///
    /// Meaningful only on `flow_fair` queues; only reachable through
    /// `queue.flow_fair_state.as_mut().unwrap().queue_vtime` once the
    /// queue is promoted.
    pub(in crate::afxdp) queue_vtime: u64,
    // Per-queue hash salt mixed into `exact_cos_flow_bucket()` so the SFQ
    // bucket mapping is not an externally-probeable pure function of the
    // 5-tuple. Drawn from getrandom(2) exactly when a queue is promoted
    // onto the flow-fair path (see `ensure_cos_interface_runtime`), never
    // rotated for the lifetime of this runtime — within one instance the
    // mapping stays deterministic (required for correct enqueue/dequeue
    // bucket accounting), but is unpredictable across restarts and nodes.
    pub(in crate::afxdp) flow_hash_seed: u64,
    pub(in crate::afxdp) active_flow_buckets: u16,
    /// #784 diagnostic: runtime-lifetime peak of
    /// `active_flow_buckets` on this queue. Monotonically
    /// non-decreasing; resets only on daemon restart (queue
    /// runtime re-creation). Lets operators detect SFQ hash-
    /// collision regressions empirically — at steady state an
    /// iperf3 -P N workload should show
    /// `active_flow_buckets_peak >= N` if the hash is spreading
    /// correctly. Owner-only writes; the snapshot reader reads
    /// without resetting (Codex review: do NOT reset on
    /// snapshot, the doc here is the contract).
    pub(in crate::afxdp) active_flow_buckets_peak: u16,
    pub(in crate::afxdp) flow_bucket_bytes: [u64; COS_FLOW_FAIR_BUCKETS],
    /// #785 Phase 3 — MQFQ virtual-finish-time ordering: per-bucket
    /// HEAD-packet finish time.
    ///
    /// Selection keys off this (the packet that's next to drain
    /// on this bucket), not the tail-finish, so equal-depth
    /// backlogged flows interleave `A,B,A,B` rather than burst
    /// `A,A,B,B`. Codex adversarial review of the first Phase 3
    /// revision flagged the tail-keyed selection as a correctness
    /// bug that collapsed MQFQ back to packet-count-fair for
    /// equal-byte flows.
    ///
    /// Invariants maintained by the enqueue/dequeue accounting:
    ///
    ///   * On enqueue to a previously-IDLE bucket (pre-enqueue
    ///     `flow_bucket_bytes[b] == 0`): head[b] = tail[b] =
    ///     `max(tail[b], queue.vtime) + bytes`.
    ///   * On enqueue to an ACTIVE bucket: tail[b] += bytes;
    ///     head[b] unchanged (the head packet is still the same
    ///     packet).
    ///   * On pop from a bucket that still has packets: head[b]
    ///     advances by the NEW head packet's bytes (the packet
    ///     that's now at front after pop).
    ///   * On pop that drains the bucket: head[b] = tail[b] = 0
    ///     so the next re-enqueue re-anchors at `queue.vtime`.
    ///
    /// Overflow: at 100 Gbps sustained, u64 wraps at ~46 years of
    /// uptime. No normalisation needed.
    ///
    /// Meaningful only on `flow_fair` queues.
    ///
    /// Read by `cos_queue_min_finish_bucket` as the selection key
    /// for MQFQ dequeue ordering.
    pub(in crate::afxdp) flow_bucket_head_finish_bytes: [u64; COS_FLOW_FAIR_BUCKETS],
    /// #785 Phase 3 — MQFQ per-bucket TAIL finish: the finish
    /// time of the LAST-enqueued packet on this bucket. Used by
    /// enqueue to compute the next packet's finish (tail + bytes)
    /// and by empty-bucket detection to decide whether to
    /// re-anchor at `queue.vtime`. Distinct from head-finish —
    /// see above. Invariants: `head[b] <= tail[b]` when bucket
    /// is active; both 0 when bucket is idle.
    pub(in crate::afxdp) flow_bucket_tail_finish_bytes: [u64; COS_FLOW_FAIR_BUCKETS],
    pub(in crate::afxdp) flow_bucket_items: [VecDeque<CoSPendingTxItem>; COS_FLOW_FAIR_BUCKETS],
    /// #785 Phase 3 — active-set tracking for flow-fair MQFQ.
    /// Still populated on bucket 0→>0 / >0→0 transitions so that
    /// `cos_queue_front`/`cos_queue_pop_front` can scan just the
    /// small active set rather than all 4096 SFQ buckets to find
    /// the minimum finish time. Semantically a set (membership),
    /// not a DRR ring — the ordering is governed by
    /// `flow_bucket_finish_bytes`, not ring position.
    pub(in crate::afxdp) flow_rr_buckets: FlowRrRing,
    /// #785 Phase 3 — Codex round-3 HIGH + NEW-1: LIFO stack of
    /// bucket-state snapshots captured at each `cos_queue_pop_front`.
    /// `cos_queue_push_front` pops from the back of the stack on
    /// rollback so every item in a batched multi-pop restore can
    /// restore its own pre-pop head/tail exactly — not just the most
    /// recent pop.
    ///
    /// Stack ordering:
    ///   * `cos_queue_pop_front` pushes onto the back (most recent).
    ///   * `cos_queue_push_front` pops from the back (LIFO).
    ///   * `cos_queue_push_back` clears the stack (any new enqueue
    ///     can invalidate earlier snapshots — bucket state under
    ///     those snapshots has changed).
    ///   * Flow-fair drain helpers (`drain_exact_*_flow_fair`) clear
    ///     the stack at batch start (not end) so successful-commit
    ///     chains from prior batches do not leak into the current
    ///     batch — and so the bound below holds even when a
    ///     committed submission never called push_front.
    ///   * Teardown paths (`cos_queue_drain_all` and
    ///     `reset_binding_cos_runtime`) call
    ///     `cos_queue_pop_front_no_snapshot` so that drains of
    ///     >TX_BATCH_SIZE items never grow the stack.
    ///
    /// Size bound: at most `TX_BATCH_SIZE` entries alive at once —
    /// enforced by the batch-start clear above. The hot-path drain
    /// helpers cap scratch depth at `TX_BATCH_SIZE` and push onto
    /// the stack once per pop, so ≤ `TX_BATCH_SIZE` snapshots
    /// accumulate between a drain and its paired push_front /
    /// commit. `cos_queue_pop_front` contains a `debug_assert!` to
    /// catch regressions in dev/test. Preallocated to that capacity
    /// so no hot-path realloc occurs. Each entry is 24 bytes
    /// (`CoSQueuePopSnapshot`), so the worst-case footprint is
    /// `TX_BATCH_SIZE × 24` bytes per queue — on top of the
    /// 4096-bucket bookkeeping arrays already resident in
    /// `CoSQueueRuntime`. Lowered from 256 → 64 in #920 (worst-case
    /// stack ~1.5 KB).
    ///
    /// Why a stack and not a single `Option`: earlier drained
    /// buckets in a batched rollback (e.g. N pops across M buckets,
    /// all ring-full-retried) need their exact pre-pop head/tail,
    /// not the `max(tail, queue_vtime) + bytes` re-anchor, which
    /// can overshoot when `queue_vtime` has already advanced past
    /// the earlier bucket's original head. Per-pop snapshots make
    /// every rollback item round-trip neutral.
    pub(in crate::afxdp) pop_snapshot_stack: Vec<CoSQueuePopSnapshot>,
    /// #1229 v7 per-bucket monotonic TX byte counter. Updated at all
    /// settle/commit paths (apply_cos_send_result, apply_cos_prepared_result,
    /// and the settle_exact_*_scratch_submission_flow_fair direct paths).
    /// Never updated on speculative pop or restore. Single-writer per
    /// FlowFairState (the owning worker for this queue runtime). u64
    /// wraps in ~1.5e9 seconds (~47 years) at 100 Gbps — practically
    /// unreachable.
    pub(in crate::afxdp) flow_bucket_tx_bytes: [u64; COS_FLOW_FAIR_BUCKETS],
    /// #1229 v7 per-bucket EWMA-smoothed observed rate in bits/sec. u64
    /// to avoid the v4-era u32 truncation above 4.29 Gbps. Updated by
    /// `account_flow_bucket_tx` at settle. Read by the cap-aware MQFQ
    /// selector when comparing against the per-class target rate
    /// (also in bits/sec). Note: the field name `*_bps` and the selector
    /// comparison (`observed_bps <= target_bps`) are both in bits/sec.
    pub(in crate::afxdp) flow_bucket_observed_bps: [u64; COS_FLOW_FAIR_BUCKETS],
    /// #1229 v7 per-bucket last-commit timestamp (CLOCK_MONOTONIC ns,
    /// sampled once per batch commit at the apply_cos_*_result call
    /// site, NOT inside the per-packet loop — Gemini round-6 fix).
    /// Used as the EWMA dt reference: dt_ns = now_ns - last_tx_ns.
    /// 0 sentinel = "never committed"; first commit initializes
    /// observed_bps directly from inst (skip-ramp).
    pub(in crate::afxdp) flow_bucket_last_tx_ns: [u64; COS_FLOW_FAIR_BUCKETS],
    /// #1229 v7 sub-threshold byte accumulator. When dt_ns since the
    /// last EWMA roll is below `EWMA_MIN_DT_NS` (100 µs), bytes
    /// accumulate here and the EWMA defers. When dt finally crosses
    /// the threshold the accumulated total is divided by the elapsed
    /// dt for a true average rate, neutralizing the back-to-back
    /// packet "100+ Gbps over 100 ns" microspike Gemini round-4
    /// flagged.
    pub(in crate::afxdp) flow_bucket_pending_bytes: [u32; COS_FLOW_FAIR_BUCKETS],
}

impl FlowFairState {
    /// Owned-value constructor. Retained for tests that genuinely need an
    /// owned `FlowFairState` on the stack (`fairness.rs`/`worker/cos/tests.rs`).
    ///
    /// **Do not call this on any production/hot path.** `FlowFairState` is
    /// ~352 KB; returning it by value forces the caller's frame to reserve
    /// and `__rust_probestack`-touch the whole 352 KB (#1755). Production
    /// promotion sites (`promote_to_flow_fair`, `admission.rs`,
    /// `test_support.rs`) must use `new_boxed`, which builds directly into a
    /// heap allocation so the giant temporary never lands on any stack frame.
    pub(in crate::afxdp) fn new(flow_hash_seed: u64) -> Self {
        Self {
            queue_vtime: 0,
            flow_hash_seed,
            active_flow_buckets: 0,
            active_flow_buckets_peak: 0,
            flow_bucket_bytes: [0; COS_FLOW_FAIR_BUCKETS],
            flow_bucket_head_finish_bytes: [0; COS_FLOW_FAIR_BUCKETS],
            flow_bucket_tail_finish_bytes: [0; COS_FLOW_FAIR_BUCKETS],
            flow_bucket_items: std::array::from_fn(|_| VecDeque::new()),
            flow_rr_buckets: FlowRrRing::default(),
            pop_snapshot_stack: Vec::with_capacity(TX_BATCH_SIZE),
            flow_bucket_tx_bytes: [0; COS_FLOW_FAIR_BUCKETS],
            flow_bucket_observed_bps: [0; COS_FLOW_FAIR_BUCKETS],
            flow_bucket_last_tx_ns: [0; COS_FLOW_FAIR_BUCKETS],
            flow_bucket_pending_bytes: [0; COS_FLOW_FAIR_BUCKETS],
        }
    }

    /// #1755 — heap constructor that builds `FlowFairState` directly into a
    /// `Box` without ever materialising the ~352 KB struct on the stack.
    ///
    /// Rust has no guaranteed placement-new into `Box`, so the by-value
    /// `new()` return slot is the actual 352 KB temporary that forces the
    /// `__rust_probestack` 352 KB-frame loop in `cos_queue_push_back` /
    /// `promote_to_flow_fair`. This constructor allocates an uninitialised
    /// `Box<MaybeUninit<Self>>` and writes every field exactly once through
    /// raw pointers, then `assume_init`s it. No giant temporary is ever
    /// created.
    ///
    /// SAFETY contract (verified by the `flow_fair_state_tests` field-
    /// equivalence test and `cargo +nightly miri`):
    ///   * Every one of the 14 fields is written exactly once below — keep
    ///     this in lockstep with the struct definition and with `new()`.
    ///   * `flow_bucket_items` (`[VecDeque; N]`) and `pop_snapshot_stack`
    ///     (`Vec`) are NON-trivial types: a zeroed `Vec`/`VecDeque` is NOT a
    ///     valid initialised representation, so they MUST be written with a
    ///     real value (`VecDeque::new()` / `Vec::with_capacity`), never left
    ///     to `write_bytes(0)`. `Box::new_zeroed().assume_init()` /
    ///     transmute-from-zeroed would be UB for exactly this reason and is
    ///     deliberately not used.
    ///   * `flow_rr_buckets: FlowRrRing` is POD (`[u16; N]` + two `u16`)
    ///     whose `Default` is all-zero; its bytes are zeroed in place
    ///     (`write_bytes(0)`) rather than materialising an 8 KB `Default`
    ///     temporary on the stack.
    ///   * The POD `[u64; N]` / `[u32; N]` arrays and scalars are zeroed via
    ///     `write_bytes`/`write(0)` to match `new()`'s `[0; N]` values.
    ///   * Drop-safety: the body is panic-free. The two heap-allocating
    ///     writes (`Box::new_uninit` for the struct, `Vec::with_capacity`
    ///     for `pop_snapshot_stack`) abort on OOM rather than unwinding, and
    ///     `Vec::with_capacity(TX_BATCH_SIZE)` cannot capacity-overflow
    ///     (`TX_BATCH_SIZE` is a small fixed constant). Every other write is
    ///     infallible. So no path unwinds through partially-initialised
    ///     memory, and no field is ever both initialised and then dropped on
    ///     unwind — no drop-on-unwind scaffold is required.
    pub(in crate::afxdp) fn new_boxed(flow_hash_seed: u64) -> Box<Self> {
        use std::ptr::addr_of_mut;

        let mut uninit: Box<std::mem::MaybeUninit<Self>> = Box::new_uninit();
        // SAFETY: `ptr` points at a freshly-allocated, properly-aligned,
        // uninitialised `FlowFairState`. Each `addr_of_mut!` derives a raw
        // pointer to a distinct field without forming a reference to the
        // uninitialised whole, and every field is written exactly once
        // before `assume_init`. See the SAFETY contract above.
        unsafe {
            let ptr = uninit.as_mut_ptr();

            // Scalars / small POD fields.
            addr_of_mut!((*ptr).queue_vtime).write(0);
            addr_of_mut!((*ptr).flow_hash_seed).write(flow_hash_seed);
            addr_of_mut!((*ptr).active_flow_buckets).write(0);
            addr_of_mut!((*ptr).active_flow_buckets_peak).write(0);

            // POD bucket arrays — zeroed in place, matching `[0; N]`.
            addr_of_mut!((*ptr).flow_bucket_bytes).write_bytes(0, 1);
            addr_of_mut!((*ptr).flow_bucket_head_finish_bytes).write_bytes(0, 1);
            addr_of_mut!((*ptr).flow_bucket_tail_finish_bytes).write_bytes(0, 1);
            addr_of_mut!((*ptr).flow_bucket_tx_bytes).write_bytes(0, 1);
            addr_of_mut!((*ptr).flow_bucket_observed_bps).write_bytes(0, 1);
            addr_of_mut!((*ptr).flow_bucket_last_tx_ns).write_bytes(0, 1);
            addr_of_mut!((*ptr).flow_bucket_pending_bytes).write_bytes(0, 1);

            // POD ring (`[u16; N]` + two `u16`); `Default` == all-zero, so
            // zero in place to avoid an 8 KB stack temporary.
            addr_of_mut!((*ptr).flow_rr_buckets).write_bytes(0, 1);

            // NON-trivial collection fields — MUST be written with real
            // initialised values; a zeroed Vec/VecDeque is invalid.
            //
            // Write each `VecDeque` directly into its slot rather than via
            // `array::from_fn`, which would materialise the full 128 KB
            // `[VecDeque; N]` array as a stack temporary first — exactly the
            // large-frame footgun this constructor exists to avoid.
            let items = addr_of_mut!((*ptr).flow_bucket_items) as *mut VecDeque<CoSPendingTxItem>;
            for i in 0..COS_FLOW_FAIR_BUCKETS {
                items.add(i).write(VecDeque::new());
            }
            addr_of_mut!((*ptr).pop_snapshot_stack).write(Vec::with_capacity(TX_BATCH_SIZE));

            uninit.assume_init()
        }
    }
}

pub(in crate::afxdp) struct VMinQueueState {
    /// #917 — V_min cross-worker coordination. Set by
    /// `promote_cos_queue_flow_fair` when the queue is shared_exact
    /// (matches the queue.shared_exact policy). Each worker
    /// servicing this shared queue holds its own `CoSQueueRuntime`
    /// instance; all instances point to the same
    /// `SharedCoSQueueVtimeFloor` Arc but read/write their own slot
    /// indexed by `worker_id`.
    ///
    /// `None` for owner-local-exact and best-effort queues — V_min
    /// sync only applies to shared_exact.
    pub(in crate::afxdp) vtime_floor: Option<Arc<SharedCoSQueueVtimeFloor>>,
    /// Worker id of the local thread holding this `CoSQueueRuntime`
    /// instance. Used to index into `vtime_floor.slots` for publish
    /// (this worker's own slot) and to skip self in V_min reads.
    pub(in crate::afxdp) worker_id: u32,
    /// #941 Work item D: counts back-to-back V_min throttle decisions
    /// (cos_queue_v_min_continue returning false → caller breaks).
    /// Resets on a successful pop (V_min check returns true). When
    /// it reaches `V_MIN_CONSECUTIVE_SKIP_HARD_CAP`, hard-cap fires:
    /// `v_min_suspended_remaining` is set to
    /// `V_MIN_SUSPENSION_BATCHES`, suspending V_min checks for that
    /// many drain calls so the worker can drain at full rate.
    pub(in crate::afxdp) consecutive_v_min_skips: u32,
    /// #941 Work item D: countdown of drain calls during which the
    /// V_min check is suspended. Decremented once per drain call
    /// after the `free_tx_frames.is_empty()` preflight passes (so a
    /// no-progress drain doesn't burn a suspension slot). When 0,
    /// V_min checks resume normally.
    pub(in crate::afxdp) v_min_suspended_remaining: u32,
    /// #941 Work item D: per-queue scratch counter for hard-cap
    /// activations. Flushed to
    /// `BindingLiveState::v_min_throttle_hard_cap_overrides` in
    /// `update_binding_debug_state` (mirrors flow_cache_collision_evictions
    /// pattern at umem.rs:2603-2607).
    pub(in crate::afxdp) v_min_hard_cap_overrides_scratch: u32,
    /// #943: per-queue scratch counter for V_min throttle decisions
    /// (i.e. `cos_queue_v_min_continue` returned `false` and the
    /// caller broke out of the drain loop without hard-cap firing).
    /// Flushed to `BindingLiveState::v_min_throttles` in
    /// `update_binding_debug_state` alongside the hard-cap counter.
    /// Together with `v_min_throttle_hard_cap_overrides` this gives
    /// operators visibility into both the regular throttle
    /// (working-as-designed fairness brake) and the hard-cap
    /// override path (escape hatch when the brake is too tight).
    pub(in crate::afxdp) v_min_throttles_scratch: u32,
    /// #hb166 T-6(a): per-queue scratch counter for V_min *suspended*
    /// drain batches — every batch where `cos_queue_v_min_consume_suspension`
    /// burned a suspension slot (the fairness brake was OFF because a
    /// prior hard-cap armed suspension). Pre-fix these were UNCOUNTED, so
    /// telemetry read "brake idle" while it was suppressed. Flushed to
    /// `BindingLiveState::v_min_suspended_batches` in
    /// `update_binding_debug_state` alongside the throttle/hard-cap
    /// counters. `v_min_suspended_batches / v_min_throttle_hard_cap_overrides`
    /// is the "how long is the brake staying off per activation" diagnostic.
    pub(in crate::afxdp) v_min_suspended_batches_scratch: u32,
    /// #hb166 T-6(a): current decaying re-arm window for the V_min
    /// suspension. Initialized to `V_MIN_SUSPENSION_BATCHES`; each
    /// consecutive hard-cap activation (no intervening passing V_min
    /// check) halves it toward `V_MIN_SUSPENSION_MIN_BATCHES`, and a
    /// clean V_min check resets it to `V_MIN_SUSPENSION_BATCHES`. This
    /// makes a persistently-skewed queue re-engage the brake sooner.
    pub(in crate::afxdp) v_min_suspension_window: u32,
    /// #2624: persistent V_min cadence pop counter. The cross-worker
    /// V_min sync (`cos_queue_v_min_continue` → the expensive
    /// `participating_v_min_snapshot` Acquire-load scan of every peer
    /// worker's slot) is rate-limited to the first pop and every
    /// `V_MIN_READ_CADENCE`-th pop thereafter. This counter MUST persist
    /// across `drain_exact_*_to_scratch_flow_fair` invocations: under
    /// low/medium load the queue is drained in many small batches, so a
    /// per-call `let mut = 0` re-armed the mandatory `pop_count == 1`
    /// first-pop snapshot on EVERY drain call, defeating the cadence and
    /// generating continuous cross-core coherency traffic.
    ///
    /// Single-writer, no atomics: each `CoSQueueRuntime` instance is
    /// owned and drained by exactly one worker thread (`worker_id`), the
    /// same single-writer model the sibling `consecutive_v_min_skips` /
    /// `v_min_suspended_remaining` fields already rely on. Both
    /// flow-fair drain fns (Local + Prepared) for a given queue run on
    /// that one owner worker and share this counter, so the cadence is
    /// counted across BOTH drain entry points for the queue.
    ///
    /// Incremented with `wrapping_add` so the cadence stays live even
    /// after ~4 billion pops (saturating would freeze at a value that is
    /// neither 1 nor a multiple of the cadence and silently disable all
    /// further sync); a single wrap-to-0 just re-runs the snapshot once
    /// (0 is a multiple of the cadence), which is harmless.
    pub(in crate::afxdp) v_min_pop_count: u32,
}

pub(in crate::afxdp) struct CoSQueueTelemetry {
    // #710: per-queue drop-reason counters. Single-writer (the owner
    // worker is the only code path that mutates this queue's runtime),
    // so plain `u64` is sufficient — no atomics needed on the hot path.
    // Snapshot reads happen through the `build_worker_cos_statuses`
    // path which copies the whole runtime into a status struct published
    // via `ArcSwap`, so reads are consistent without ordering discipline
    // here.
    pub(in crate::afxdp) drop_counters: CoSQueueDropCounters,
    // #1628: per-class waterfill-selector trace counters. Kept SEPARATE
    // from `drop_counters` (which is reserved for packet drops / ECN
    // marks / token-starvation parks) so scheduler-selection telemetry
    // does not pollute the drop-reason struct (r1 review). Plain `u64`,
    // single-writer: the owner worker bumps these on its drain path and
    // `build_worker_cos_statuses` reads them ON THE SAME WORKER THREAD
    // before publishing the snapshot via ArcSwap — there is no live
    // cross-thread read of these fields, so no atomics are needed (same
    // reasoning as the `drop_counters` park counters, NOT a
    // tearing-tolerance argument).
    pub(in crate::afxdp) waterfill_counters: CoSQueueWaterfillCounters,
    // #751: per-queue owner-side drain telemetry. Lives inline on the
    // queue runtime so each queue's drain_latency + drain_invocations
    // are genuinely per-queue rather than a binding-wide rollup
    // surfaced under every queue row (#732). Single-writer on the
    // owner worker thread; atomic because the snapshot path reads
    // from a different thread.
    //
    // Cross-core ping-pong: this lives on the owner worker's hot
    // data, so it shares cache lines with the surrounding queue
    // state (tokens, queued_bytes, etc.). Owner-only writes to all
    // of them, so false-sharing risk is internal to the worker and
    // already accepted by the design. The #709 cache-pad isolation
    // on BindingLiveState was specifically for owner/peer split;
    // here both are owner-side so no separate pad is needed.
    pub(in crate::afxdp) owner_profile: CoSQueueOwnerProfile,
    // #1829 Phase 1: per-queue dequeue-time sojourn telemetry. Plain
    // u64 fields, single-writer (owner worker, at the committed-prefix
    // TX settle sites — see `CoSQueueSojourn::record` for why NOT at
    // pop time), read by `build_worker_cos_statuses` ON
    // THE SAME WORKER THREAD before publishing via ArcSwap — same
    // no-atomics reasoning as `waterfill_counters` above.
    pub(in crate::afxdp) sojourn: CoSQueueSojourn,
}

/// #1829 Phase 1: windowed sojourn measurement window. 100 ms matches
/// the standard CoDel interval (RFC 8289) so the Phase-1 gate evidence
/// ("does any queue sustain standing sojourn above target for ≥ one
/// interval?") is measured on exactly the timescale the Phase-2
/// control law would act on.
pub(in crate::afxdp) const COS_SOJOURN_WINDOW_NS: u64 = 100_000_000;

/// #1829 Phase 1: per-queue dequeue-time sojourn telemetry state.
///
/// All updates are O(1), allocation-free, and use the pass-level
/// `now_ns` (no clock syscalls on the hot path — #1734 kill
/// rationale). The windowed MINIMUM is the Phase-2 gate metric (AGY
/// r2 F2 on the #1829 plan): EWMA and peak are biased high by
/// transient scheduler service gaps (a single 10 ms gap inflates them
/// while the true standing queue is zero); only a minimum that stays
/// elevated across a whole window is evidence of a standing queue.
///
/// Window bookkeeping is the classic two-bucket flip-flop: a running
/// minimum for the current 100 ms window plus the previous completed
/// window's minimum. Flips happen lazily at pop time off the pass
/// `now_ns`; an idle gap of ≥ 2 windows discards both buckets (the
/// data is stale), and the snapshot-side export
/// (`windowed_min_export`) additionally reports 0 once the queue has
/// gone ≥ 2 windows without a pop, so a stale standing-queue reading
/// can never outlive the backlog that produced it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::afxdp) struct CoSQueueSojourn {
    /// Shift-add EWMA (α = 1/8) of per-pop sojourn, ns. Truncating
    /// integer arithmetic: converges to within 8 ns of the true mean,
    /// warm-up from 0 over ~8 pops. Supporting context only — NOT the
    /// gate metric (biased high by service gaps).
    pub(in crate::afxdp) ewma_ns: u64,
    /// Lifetime maximum per-pop sojourn, ns. Same lifetime contract
    /// as `active_flow_buckets_peak`.
    pub(in crate::afxdp) peak_ns: u64,
    /// Running minimum of the CURRENT window. `u64::MAX` = no pops
    /// recorded in this window yet.
    pub(in crate::afxdp) win_cur_min_ns: u64,
    /// Minimum of the PREVIOUS completed window. `u64::MAX` = none.
    pub(in crate::afxdp) win_prev_min_ns: u64,
    /// Pass-`now_ns` at which the current window started. 0 = never
    /// recorded.
    pub(in crate::afxdp) win_flip_ns: u64,
}

impl Default for CoSQueueSojourn {
    fn default() -> Self {
        Self {
            ewma_ns: 0,
            peak_ns: 0,
            win_cur_min_ns: u64::MAX,
            win_prev_min_ns: u64::MAX,
            win_flip_ns: 0,
        }
    }
}

impl CoSQueueSojourn {
    /// Record one sojourn sample for a packet whose TX insert has
    /// been settled as COMMITTED. Called at the accepted-prefix
    /// settle sites (exact flow-fair settle fns; submit_local /
    /// submit_prepared enq sidecars) with the item's `enqueue_ns`
    /// and the drain pass's `now_ns` — NEVER at pop/scratch-build
    /// time, because partial/zero TX inserts push the retry suffix
    /// back with its original stamp and pop-time sampling would
    /// count a rolled-back item once per attempt (Codex review on
    /// PR #1846).
    ///
    /// `enqueue_ns == 0` means "never CoS-stamped" (direct-TX
    /// constructions, pre-upgrade items) and is skipped entirely —
    /// plan invariant 10: a zero timestamp must never turn into a
    /// huge bogus sojourn. Cost on the common path: one compare, one
    /// subtract, two shifts/adds, two compares.
    #[inline]
    pub(in crate::afxdp) fn record(&mut self, enqueue_ns: u64, now_ns: u64) {
        if enqueue_ns == 0 {
            return;
        }
        let sojourn = now_ns.saturating_sub(enqueue_ns);
        self.ewma_ns = self.ewma_ns - (self.ewma_ns >> 3) + (sojourn >> 3);
        if sojourn > self.peak_ns {
            self.peak_ns = sojourn;
        }
        let since_flip = now_ns.saturating_sub(self.win_flip_ns);
        if since_flip >= COS_SOJOURN_WINDOW_NS {
            // Lazy flip. If we idled for ≥ 2 windows the current
            // bucket's data is older than one full window — discard
            // rather than promote (stale minima must not survive an
            // idle gap).
            self.win_prev_min_ns = if since_flip >= 2 * COS_SOJOURN_WINDOW_NS {
                u64::MAX
            } else {
                self.win_cur_min_ns
            };
            self.win_cur_min_ns = u64::MAX;
            self.win_flip_ns = now_ns;
        }
        if sojourn < self.win_cur_min_ns {
            self.win_cur_min_ns = sojourn;
        }
    }

    /// Snapshot-side export of the windowed minimum: the smallest
    /// sojourn observed over the last 1-2 windows (current running
    /// bucket + previous completed bucket), or 0 when there is no
    /// fresh data (never recorded, or last pop ≥ 2 windows before the
    /// snapshot's `now_ns`). Runs on the worker thread at snapshot
    /// cadence (~1/s), not on the per-pop hot path.
    #[inline]
    pub(in crate::afxdp) fn windowed_min_export(&self, now_ns: u64) -> u64 {
        if self.win_flip_ns == 0
            || now_ns.saturating_sub(self.win_flip_ns) >= 2 * COS_SOJOURN_WINDOW_NS
        {
            return 0;
        }
        let min = self.win_prev_min_ns.min(self.win_cur_min_ns);
        if min == u64::MAX { 0 } else { min }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(in crate::afxdp) struct CoSQueueDropCounters {
    /// Flow-share admission cap exceeded; packet tail-dropped at
    /// `enqueue_cos_item`. Indicates SFQ bucket collision or a single
    /// flow attempting to occupy more than its fair share of the
    /// buffer. See #705, #711.
    pub(in crate::afxdp) admission_flow_share_drops: u64,
    /// Physical queue buffer exceeded; packet tail-dropped at
    /// `enqueue_cos_item`. Indicates buffer undersizing relative to
    /// the offered-load × RTT product. See #707.
    pub(in crate::afxdp) admission_buffer_drops: u64,
    /// Packet ECN CE-marked at admission (not dropped). Incremented
    /// when queue depth crosses the ECN threshold derived from
    /// `buffer_limit` AND the packet was already ECT(0) or ECT(1).
    /// Non-ECT packets above the threshold fall through to the drop
    /// path and are counted under the respective drop-reason field.
    /// See #718.
    pub(in crate::afxdp) admission_ecn_marked: u64,
    /// Queue parked because the interface shaping-rate token bucket is
    /// empty. Not a drop — the queue will be woken on timer-wheel tick.
    /// High count relative to serviced-batches indicates the root
    /// shaper is the limiter.
    pub(in crate::afxdp) root_token_starvation_parks: u64,
    /// Queue parked because the per-queue (exact) token bucket is
    /// empty. Not a drop — the queue will be woken when its own tokens
    /// refill. High count indicates the per-queue rate cap is the
    /// limiter for this queue.
    pub(in crate::afxdp) queue_token_starvation_parks: u64,
    /// Counts `writer.insert` returning zero on the exact-drain path —
    /// i.e. the TX ring refused the batch. NOT a packet-loss event on
    /// the exact path: FIFO variants leave items in `queue.hot.items` and
    /// flow-fair variants explicitly restore them via
    /// `restore_exact_*_scratch_to_queue_head_flow_fair`. Frames copied
    /// into UMEM are released back to `free_tx_frames` by the caller;
    /// the packets themselves are retried on the next drain cycle.
    /// Elevated values indicate TX ring / completion reap pressure, not
    /// packet loss. See #706 / #709 for the downstream causes operators
    /// typically chase when this fires.
    pub(in crate::afxdp) tx_ring_full_submit_stalls: u64,
}

/// #1628: per-class trace counters for the `guarantee-rate` waterfill
/// selector (`cos/queue_service/mod.rs`
/// `select_exact_cos_guarantee_queue_waterfill`). These exist to make
/// the #1630-verified root cause (multi-worker queue-ownership
/// fragmentation + Phase-1/Phase-2 split) empirically observable; they
/// do NOT change any scheduling decision. Zero on the Proportional
/// (legacy RR) selector path, which has no phases — a non-zero value on
/// a queue is itself a "this interface is in guarantee-rate mode" signal.
///
/// Single-writer (owner worker) plain `u64`; read on the same thread by
/// `build_worker_cos_statuses` and published via ArcSwap (see the field
/// comment on `CoSQueueTelemetry.waterfill_counters`).
///
/// INTERPRETATION (not a single-counter fingerprint — r1 review): a
/// Phase-2 lock-in is identified only by COMBINING `phase2_admissions`
/// (climbing) + `phase1_admissions` (flat) with `queued_bytes > 0` and
/// the `*_starvation_parks` drop counters on the SAME queue row, AND
/// only for a small class whose configured rate fits the Phase-1 budget;
/// the same shape on a large above-cutoff class is healthy rate-limiting.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(in crate::afxdp) struct CoSQueueWaterfillCounters {
    /// Times this queue was admitted via the Phase-1 (small-first
    /// honored) ascending walk. Bumped at the Phase-1 honor `return`.
    pub(in crate::afxdp) phase1_admissions: u64,
    /// Times this queue was admitted via the Phase-2 (descending
    /// residual) walk. See the struct-level INTERPRETATION note — this
    /// is evidence, not a standalone fingerprint.
    pub(in crate::afxdp) phase2_admissions: u64,
    /// Times the waterfill selector reached this queue, found it eligible
    /// (nonempty + runnable + guarantee + exact) and head-present, and
    /// evaluated it — counted in BOTH phases, BEFORE the root/queue token
    /// gate (so a token-starved-but-eligible queue is still a visit). A
    /// backlogged queue PARKED on token starvation is `!runnable` and
    /// skipped at the eligibility gate, so it shows LOW eligible_visits;
    /// pair with `*_starvation_parks` to tell "backlogged but parked"
    /// (low visits + high parks) from "genuinely idle on this owner"
    /// (low visits + low parks + zero queued_bytes).
    pub(in crate::afxdp) eligible_visits: u64,
    /// hb166 T-2: times this queue was selected via the Phase-1 honored
    /// walk but the subsequent service call transmitted zero bytes (TX
    /// ring full / no free UMEM frame / frame-build Drop). On such a
    /// no-progress visit the Phase-1 budget debit and honored-epoch bit
    /// are REFUNDED (the class keeps its guarantee for a retry), so
    /// `phase1_admissions` counts only visits that actually made TX
    /// progress. A climbing `phase1_selected_no_progress` with flat
    /// `phase1_admissions` on a backlogged small class is the fingerprint
    /// of sustained TX-ring / completion-reap pressure eating the
    /// guarantee pass (previously invisible: the pre-hb166 code counted
    /// the failed selection as an admission and burned the epoch).
    pub(in crate::afxdp) phase1_selected_no_progress: u64,
}

pub(in crate::afxdp) struct CoSTimerWheelRuntime {
    pub(in crate::afxdp) current_tick: u64,
    pub(in crate::afxdp) level0: [Vec<usize>; COS_TIMER_WHEEL_L0_SLOTS],
    pub(in crate::afxdp) level1: [Vec<usize>; COS_TIMER_WHEEL_L1_SLOTS],
    /// #4270 (R-9): persistent per-drain scratch buffers reused across
    /// every `cascade_cos_timer_wheel_level1` / `wake_due_cos_timer_slot`
    /// call so the per-tick catch-up loop performs no allocator ops. The
    /// slot being processed is *swapped* with `drain` (preserving the
    /// slot's own capacity for the next park), and the rearm/wake decision
    /// lists reuse the persistent vectors instead of `Vec::with_capacity`
    /// temporaries. See the two functions in cos/tx_completion.rs.
    pub(in crate::afxdp) scratch: CoSTimerWheelScratch,
}

/// #4270 (R-9): reusable scratch for the timer-wheel drain path. All
/// three vectors retain capacity across calls; the two consumers
/// (`cascade_cos_timer_wheel_level1`, `wake_due_cos_timer_slot`) run
/// sequentially on the owner thread and never nest, so sharing is safe.
#[derive(Default)]
pub(in crate::afxdp) struct CoSTimerWheelScratch {
    /// Swapped with the slot Vec being processed so the slot keeps a
    /// capacity-retaining buffer (never a fresh 0-capacity Vec).
    pub(in crate::afxdp) drain: Vec<usize>,
    /// Reused list of `(queue_idx, wake_tick)` to re-park after the scan.
    pub(in crate::afxdp) rearm: Vec<(usize, u64)>,
    /// Reused list of queue indices to wake after the scan.
    pub(in crate::afxdp) wake: Vec<usize>,
}

/// #751: per-queue owner-side drain telemetry. Written by the owner
/// worker when a drain cycle services this specific queue (see
/// `drain_shaped_tx`'s per-queue return signal in cos/queue_service/mod.rs); read via
/// the snapshot path published through ArcSwap to Prometheus and to
/// `show class-of-service interface`.
///
/// Buckets sum to `drain_invocations` modulo the reader's scrape
/// window, pinned in
/// `queue_owner_profile_buckets_sum_to_drain_invocations`.
///
/// Single-writer. Relaxed is sufficient:
///   - The snapshot reader tolerates monotonic counter tearing
///     across the bucket array (same tolerance the BindingLiveState
///     owner_profile_owner already assumed).
///   - Prometheus scrape semantics are "best effort at scrape time".
///   - No happens-before requirement between the buckets themselves
///     or between `drain_latency_hist` and `drain_invocations` —
///     readers compute percentiles independently and a brief skew
///     just rounds the p50/p99 into an adjacent bucket.
pub(in crate::afxdp) struct CoSQueueOwnerProfile {
    pub(in crate::afxdp) drain_latency_hist: [AtomicU64; super::binding_state::DRAIN_HIST_BUCKETS],
    pub(in crate::afxdp) drain_invocations: AtomicU64,
    /// #760 instrumentation. Bytes the shaped drain actually
    /// submitted on behalf of this queue. Divide by a scrape window
    /// to get an observed drain rate and compare against
    /// `queue.transmit_rate_bytes()`. Writer = owner worker on the
    /// single site that also decrements `queue.hot.tokens` after a send
    /// (apply_direct_exact_send_result for exact-owner-local,
    /// apply_cos_send_result for the non-exact / shared-exact paths).
    pub(in crate::afxdp) drain_sent_bytes: AtomicU64,
    /// Bytes sent while the queue was serviced in Guarantee phase.
    /// This is a phase split of `drain_sent_bytes`, not a distinct
    /// packet path. Exact-owner-local sends are always Guarantee
    /// phase; shared/non-exact paths write this from the
    /// `CoSServicePhase` observed at TX completion.
    pub(in crate::afxdp) drain_guarantee_sent_bytes: AtomicU64,
    /// Bytes sent while the queue was serviced in Surplus phase.
    /// A non-zero value on a best-effort / uncapped queue proves it
    /// used residual root service; a high `drain_sent_bytes` with a
    /// zero surplus split means the queue is consuming guarantee
    /// service instead.
    pub(in crate::afxdp) drain_surplus_sent_bytes: AtomicU64,
    /// Non-exact bytes sent while at least one exact queue on the same
    /// CoS interface still had backlog. This is the direct diagnostic
    /// for best-effort or uncapped traffic stealing service from exact
    /// queues; it is written only on non-exact queue apply paths.
    pub(in crate::afxdp) drain_nonexact_sent_bytes_while_exact_backlogged: AtomicU64,
    /// #760 instrumentation. Count of drain iterations where the
    /// root token gate fired (root.tokens < head_len) and the queue
    /// got parked waiting for the interface shaper to refill.
    pub(in crate::afxdp) drain_park_root_tokens: AtomicU64,
    /// #760 instrumentation. Count of drain iterations where the
    /// per-queue token gate fired (queue.hot.tokens < head_len) and
    /// the queue got parked waiting for its own refill. A queue that
    /// sustains throughput above its configured rate with this near
    /// zero is a direct signal the gate never fired.
    pub(in crate::afxdp) drain_park_queue_tokens: AtomicU64,
}

impl CoSQueueOwnerProfile {
    pub(in crate::afxdp) fn new() -> Self {
        Self {
            drain_latency_hist: std::array::from_fn(|_| AtomicU64::new(0)),
            drain_invocations: AtomicU64::new(0),
            drain_sent_bytes: AtomicU64::new(0),
            drain_guarantee_sent_bytes: AtomicU64::new(0),
            drain_surplus_sent_bytes: AtomicU64::new(0),
            drain_nonexact_sent_bytes_while_exact_backlogged: AtomicU64::new(0),
            drain_park_root_tokens: AtomicU64::new(0),
            drain_park_queue_tokens: AtomicU64::new(0),
        }
    }
}

impl Default for CoSQueueOwnerProfile {
    fn default() -> Self {
        Self::new()
    }
}

pub(in crate::afxdp) enum CoSPendingTxItem {
    Local(TxRequest),
    Prepared(PreparedTxRequest),
}

/// Size of every per-priority array, INDEXED BY RANK.
///
/// Six, not five, and that is correct rather than off by one (#6849).
/// Junos has five scheduler priorities, but `cos_priority_rank` assigns
/// them ranks 0, 1, 2, 4, 5 — rank 3 is deliberately vacant since the dead
/// `medium` arm was removed, and the ranks were not renumbered because a
/// large number of CoS tests hardcode `priority: 5` meaning "low" and
/// would silently mean something else. The highest live rank is therefore
/// still 5, so these arrays need six slots; slot 3 is allocated and never
/// populated. See `cos_priority_rank` for the full reasoning.
pub(in crate::afxdp) const COS_PRIORITY_LEVELS: usize = 6;

pub(in crate::afxdp) const COS_TIMER_WHEEL_L0_SLOTS: usize = 256;

pub(in crate::afxdp) const COS_TIMER_WHEEL_L1_SLOTS: usize = 256;

impl<'a> Iterator for FlowRrRingIter<'a> {
    type Item = u16;
    #[inline]
    fn next(&mut self) -> Option<u16> {
        if self.offset >= usize::from(self.ring.len) {
            return None;
        }
        let idx = (usize::from(self.ring.head) + self.offset) & COS_FLOW_FAIR_BUCKET_MASK;
        self.offset += 1;
        Some(self.ring.buf[idx])
    }
}

// Compile-time invariants for COS_FLOW_FAIR_BUCKETS — the #711 design
// depends on both and a future refactor that changes the constant
// without checking these must fail at build time, not at runtime:
//
// 1. Power of two — `cos_flow_bucket_index` masks with
//    `COS_FLOW_FAIR_BUCKETS - 1` instead of modulo, and `FlowRrRing`
//    uses mask-based wrap math on the hot push/pop path. Without
//    power-of-two sizing that math silently indexes off the end.
// 2. Fits in `u16` — `FlowRrRing` stores bucket IDs as `u16`. A
//    larger constant would silently truncate.
const _: () = assert!(COS_FLOW_FAIR_BUCKETS.is_power_of_two());
const _: () = assert!(COS_FLOW_FAIR_BUCKETS <= u16::MAX as usize);

#[cfg(test)]
mod flow_fair_state_tests {
    use super::*;

    /// #1755: `new_boxed` must initialise every field to byte-for-byte the
    /// same value as the by-value `new()` constructor. This is the
    /// field-equivalence guard for the unsafe `MaybeUninit` builder — if a
    /// field is added to `FlowFairState` and not written in `new_boxed`,
    /// `assume_init` would read uninitialised memory; this test (run under
    /// `cargo +nightly miri`) catches that as UB, and even without miri it
    /// catches a value mismatch.
    #[test]
    fn new_boxed_matches_new_field_for_field() {
        let seed = 0x1234_5678_9abc_def0_u64;
        let owned = FlowFairState::new(seed);
        let boxed = FlowFairState::new_boxed(seed);

        assert_eq!(boxed.queue_vtime, owned.queue_vtime);
        assert_eq!(boxed.flow_hash_seed, owned.flow_hash_seed);
        assert_eq!(boxed.flow_hash_seed, seed);
        assert_eq!(boxed.active_flow_buckets, owned.active_flow_buckets);
        assert_eq!(boxed.active_flow_buckets_peak, owned.active_flow_buckets_peak);
        assert_eq!(boxed.flow_bucket_bytes, owned.flow_bucket_bytes);
        assert_eq!(
            boxed.flow_bucket_head_finish_bytes,
            owned.flow_bucket_head_finish_bytes
        );
        assert_eq!(
            boxed.flow_bucket_tail_finish_bytes,
            owned.flow_bucket_tail_finish_bytes
        );
        assert_eq!(boxed.flow_bucket_tx_bytes, owned.flow_bucket_tx_bytes);
        assert_eq!(boxed.flow_bucket_observed_bps, owned.flow_bucket_observed_bps);
        assert_eq!(boxed.flow_bucket_last_tx_ns, owned.flow_bucket_last_tx_ns);
        assert_eq!(boxed.flow_bucket_pending_bytes, owned.flow_bucket_pending_bytes);

        // Collection fields: every bucket queue is a real, empty VecDeque;
        // the pop-snapshot stack is empty with the preallocated capacity.
        assert_eq!(boxed.flow_bucket_items.len(), COS_FLOW_FAIR_BUCKETS);
        assert!(boxed.flow_bucket_items.iter().all(|q| q.is_empty()));
        assert!(boxed.pop_snapshot_stack.is_empty());
        // `with_capacity` guarantees AT LEAST the requested capacity; match
        // the same `>=` contract `owned` (via `new()`) satisfies rather than
        // pinning an exact value the allocator is free to round up.
        assert!(boxed.pop_snapshot_stack.capacity() >= TX_BATCH_SIZE);
        assert!(owned.pop_snapshot_stack.capacity() >= TX_BATCH_SIZE);

        // FlowRrRing zero-init equivalence (POD).
        assert!(boxed.flow_rr_buckets.is_empty());
        assert_eq!(boxed.flow_rr_buckets.len(), owned.flow_rr_buckets.len());
        assert_eq!(boxed.flow_rr_buckets.front(), owned.flow_rr_buckets.front());
    }

    /// Exercise the collection fields enough to prove they are genuinely
    /// initialised (a zeroed VecDeque would UB/abort here, not silently
    /// pass) — reserve/push on a couple of buckets and the snapshot stack.
    #[test]
    fn new_boxed_collections_are_usable() {
        let mut boxed = FlowFairState::new_boxed(7);
        // Reserving + reading capacity touches the VecDeque's internal
        // raw-vec pointer/cap; a zeroed VecDeque would be invalid here.
        boxed.flow_bucket_items[0].reserve(4);
        boxed.flow_bucket_items[COS_FLOW_FAIR_BUCKETS - 1].reserve(4);
        assert!(boxed.flow_bucket_items[0].capacity() >= 4);
        assert!(boxed.flow_bucket_items[COS_FLOW_FAIR_BUCKETS - 1].capacity() >= 4);
        assert_eq!(boxed.flow_bucket_items[0].len(), 0);

        boxed.pop_snapshot_stack.push(CoSQueuePopSnapshot {
            bucket: 3,
            pre_pop_head_finish: 10,
            pre_pop_tail_finish: 20,
            pre_pop_queue_vtime: 30,
        });
        assert_eq!(boxed.pop_snapshot_stack.len(), 1);
        assert_eq!(boxed.pop_snapshot_stack[0].bucket, 3);
        // Dropping `boxed` here drops all 4096 VecDeques + the Vec; under
        // miri this proves every collection field is a valid drop target.
    }
}

#[cfg(test)]
#[path = "cos_sojourn_tests.rs"]
mod cos_sojourn_tests;
