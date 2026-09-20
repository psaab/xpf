//! #6592: the atomically-paired worker-visible runtime view.
//!
//! # Why this type exists
//!
//! Validation (`config_generation` / `fib_generation`, the values
//! `classify_metadata` matches a packet's shim stamp against) and the
//! `ForwardingState` (the policy/FIB/NAT tables a `Valid` packet is then
//! forwarded under) used to be published through TWO independent `ArcSwap`s.
//! A worker refreshing its per-tick view performed two separate acquire-loads,
//! so a coordinator publish landing between them left the worker holding one
//! half from generation N and the other from N-1 — a TORN pair. Both
//! orientations were reachable and both are unsafe:
//!
//! - `(old validation, new forwarding)` — a packet stamped at the OLD
//!   generation matches the worker's old validation, classifies `Valid`, and
//!   is then forwarded under the NEW tables. (#6291.)
//! - `(new validation, old forwarding)` — once the coordinator's reply reaches
//!   Go and Go writes the new generation into `userspace_ctrl`, the shim stamps
//!   NEW. Those packets match the worker's new validation, classify `Valid`,
//!   and are forwarded under the STALE tables — a withdrawn route still
//!   resolves, a newly added deny is not applied. (#6592, the mirror.)
//!
//! Reordering the two loads can only ever exclude ONE orientation (the
//! producer and consumer must run in opposite orders for an acquire/release
//! pair, which is exactly one of the two). Closing BOTH needs the two values to
//! travel in ONE `Arc`, which is this type: a worker's refresh is a single
//! `ArcSwap` load, and whichever `RuntimeView` it observes, `validation` and
//! `forwarding` came from the same publish. There is no pair to tear.
//!
//! Holding an OLD view is still possible and is still SAFE — that is the
//! intended fail-closed behaviour. A worker that has not refreshed matches
//! new-stamped packets against old validation, they mismatch, and they DROP.
//! The defect this type closes is specifically an INCOHERENT pair, not a stale
//! coherent one; nothing here forces a refresh.
//!
//! # Why `forwarding` is a nested `Arc`, not an inlined field
//!
//! The obvious alternative — make `ValidationState` a field of
//! `ForwardingState` — is structurally simpler but breaks the #1188 worker
//! short-circuit. `Coordinator::bump_fib_generation` advances validation with
//! NO forwarding rebuild (that is its entire purpose: Go's
//! `Manager.BumpFIBGeneration` fires repeatedly during route convergence
//! precisely to avoid the full `buildSnapshot()` + `apply_snapshot` round
//! trip). Inlining would force a full `ForwardingState` clone — 69 fields, ~20
//! heap-owning collections including the FIB — per bump on the coordinator,
//! and on every worker would rotate the forwarding `Arc`, taking the expensive
//! rotation branch (screen-profile + opening-override clones, cold-path slot
//! rescan, input-filter session purges, CoS runtime reset) for a change that
//! touched neither policy nor FIB tables.
//!
//! With the nested `Arc`, a validation-only publish allocates one small
//! `RuntimeView` and REUSES the inner forwarding `Arc`. The worker's
//! `Arc::ptr_eq` short-circuit still hits, so #1188 is preserved exactly.
//!
//! # Publish ordering is unchanged
//!
//! The `RuntimeView` store sits exactly where the `ha.forwarding` store sat: it
//! is still THE single worker-visible release gate, and #5166 still holds —
//! the CoS owner/live/lease/backlog/vtime maps and `ha.fabrics` are stored
//! BEFORE it, and the worker reads them AFTER its view load.
use super::*;

/// The worker-visible `(validation, forwarding)` pair, published as ONE
/// `Arc` so the two can never be observed from different generations.
///
/// # Immutable and non-`Clone` on purpose
///
/// The fields are PRIVATE to this module and the type deliberately does NOT
/// implement `Clone`. That is the language-level half of the invariant, and it
/// exists because a review probe defeated the earlier source-canary version:
///
/// ```ignore
/// let mut torn = channel.load_full().as_ref().clone();
/// torn.validation.fib_generation = torn.validation.fib_generation.wrapping_add(1);
/// channel.store(Arc::new(torn));      // published a torn pair
/// ```
///
/// That compiled, published exactly the `(new validation, old forwarding)`
/// tear, and every textual canary rule passed — the store was not the choke
/// point's literal spelling, and the value came from a CLONE rather than a
/// construction, so "a publish needs a constructed view" was simply false.
///
/// With private fields the mutation line does not compile, and without `Clone`
/// the clone line does not compile. [`RuntimeView::new`] becomes the only way
/// to obtain a view value anywhere in the tree, which is what makes the
/// canary's construction rule a true statement rather than an enumeration of
/// the spellings someone happened to think of.
///
/// Cheap to publish: `ValidationState` is `Copy` and `forwarding` is an `Arc`
/// refcount bump, so a view reusing the current forwarding costs one small
/// allocation and no table copying.
/// A per-generation P-MECH tunnel row. It is stored inside the immutable
/// `RuntimeView`, not beside it, so a D13 worker cannot accidentally pair
/// generation-N tunnel identity with generation-(N+1) forwarding/zone maps.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::afxdp) struct IpsecTunnelRow {
    pub(in crate::afxdp) stn: String,
    pub(in crate::afxdp) if_id: u32,
    pub(in crate::afxdp) logical_ifindex: i32,
}

/// Immutable exact-STN tunnel-row set published as part of one RuntimeView.
/// Duplicate STNs and duplicate if_id claims are tracked per claimant:
/// unrelated rows remain usable while every ambiguous claimant resolves to
/// `None` at D14.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(in crate::afxdp) struct IpsecTunnelRows {
    rows: BTreeMap<String, IpsecTunnelRow>,
    duplicate_stns: BTreeSet<String>,
    ambiguous_if_ids: BTreeSet<u32>,
}

impl IpsecTunnelRows {
    pub(in crate::afxdp) fn new(rows: impl IntoIterator<Item = IpsecTunnelRow>) -> Self {
        let mut out = Self::default();
        let mut if_id_claims: BTreeMap<u32, usize> = BTreeMap::new();
        for row in rows {
            if row.stn.is_empty() || row.if_id == 0 || row.logical_ifindex == 0 {
                continue;
            }
            *if_id_claims.entry(row.if_id).or_default() += 1;
            let stn = row.stn.clone();
            if out.rows.insert(stn.clone(), row).is_some() {
                out.duplicate_stns.insert(stn);
            }
        }
        for (if_id, count) in if_id_claims {
            if count > 1 {
                out.ambiguous_if_ids.insert(if_id);
            }
        }
        out
    }

    #[inline]
    pub(in crate::afxdp) fn exact(&self, stn: &str) -> Option<&IpsecTunnelRow> {
        let row = self.rows.get(stn)?;
        if self.duplicate_stns.contains(stn) || self.ambiguous_if_ids.contains(&row.if_id) {
            None
        } else {
            Some(row)
        }
    }

    pub(in crate::afxdp) fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    pub(in crate::afxdp) fn len(&self) -> usize {
        self.rows.len()
    }

    /// Rows are immutable after construction; this accessor is only for
    /// snapshot/control tests that need to inspect the published set.
    pub(in crate::afxdp) fn duplicate(&self) -> bool {
        !self.duplicate_stns.is_empty() || !self.ambiguous_if_ids.is_empty()
    }
}

/// Number of admitted P-MECH tunnels and exact rows are part of the same
/// immutable runtime binding as `ForwardingState`.
///
/// The normal two-argument `RuntimeView::new` keeps existing non-P-MECH
/// consumers compatible by publishing an empty row set; P-MECH control
/// publication uses `new_with_ipsec_tunnel_rows` below.
#[derive(Debug)]
pub(in crate::afxdp) struct IpsecRuntimeBinding {
    rows: Arc<IpsecTunnelRows>,
    /// Authoritative generation of the tunnel-row/admit contract. It is
    /// published with the same RuntimeView as forwarding + validation; zero is
    /// unavailable and therefore E28, never "current".
    snapshot_generation: u64,
}

impl Default for IpsecRuntimeBinding {
    fn default() -> Self {
        Self {
            rows: Arc::new(IpsecTunnelRows::default()),
            snapshot_generation: 0,
        }
    }
}

impl IpsecRuntimeBinding {
    pub(in crate::afxdp) fn new(rows: Arc<IpsecTunnelRows>, snapshot_generation: u64) -> Self {
        Self {
            rows,
            snapshot_generation,
        }
    }

    #[inline]
    pub(in crate::afxdp) fn rows(&self) -> &IpsecTunnelRows {
        &self.rows
    }

    #[inline]
    pub(in crate::afxdp) fn snapshot_generation(&self) -> u64 {
        self.snapshot_generation
    }
}

#[derive(Debug)]
pub(in crate::afxdp) struct RuntimeView {
    /// Generation stamps a packet's shim metadata is matched against
    /// (`classify_metadata`).
    validation: ValidationState,
    /// The policy / FIB / NAT tables a `Valid` packet is forwarded under.
    forwarding: Arc<ForwardingState>,
    /// P-MECH tunnel identity rows are atomically paired with the forwarding
    /// maps and validation generations. D13 receives this through the same
    /// immutable view binding and never accepts a caller-supplied side table.
    ipsec: IpsecRuntimeBinding,
}

impl Default for RuntimeView {
    fn default() -> Self {
        Self {
            validation: ValidationState::default(),
            forwarding: Arc::new(ForwardingState::default()),
            ipsec: IpsecRuntimeBinding::default(),
        }
    }
}

impl RuntimeView {
    /// Build a view pairing `validation` with an already-published forwarding
    /// `Arc` (refcount bump, no table copy). Non-P-MECH callers publish the
    /// empty row set; P-MECH uses the explicit constructor below.
    pub(in crate::afxdp) fn new(
        validation: ValidationState,
        forwarding: Arc<ForwardingState>,
    ) -> Self {
        Self {
            validation,
            forwarding,
            ipsec: IpsecRuntimeBinding::default(),
        }
    }

    /// Build a P-MECH view with tunnel rows as part of the SAME immutable
    /// binding. There is no API to construct a D13 invocation from two
    /// independently loaded views.
    pub(in crate::afxdp) fn new_with_ipsec_tunnel_rows(
        validation: ValidationState,
        forwarding: Arc<ForwardingState>,
        rows: Arc<IpsecTunnelRows>,
        snapshot_generation: u64,
    ) -> Self {
        Self {
            validation,
            forwarding,
            ipsec: IpsecRuntimeBinding::new(rows, snapshot_generation),
        }
    }
    /// The generation stamps half. `Copy`, so a caller gets a value it cannot
    /// write back.
    #[inline]
    pub(in crate::afxdp) fn validation(&self) -> ValidationState {
        self.validation
    }

    /// The forwarding half, by reference. A caller may clone the `Arc` (that is
    /// how a worker adopts it) but cannot swap this view's field.
    #[inline]
    pub(in crate::afxdp) fn forwarding(&self) -> &Arc<ForwardingState> {
        &self.forwarding
    }

    /// The exact tunnel-row set paired with this view.
    #[inline]
    pub(in crate::afxdp) fn ipsec_tunnel_rows(&self) -> &IpsecTunnelRows {
        self.ipsec.rows()
    }
    /// Authoritative tunnel-row generation paired with this view.
    #[inline]
    pub(in crate::afxdp) fn ipsec_snapshot_generation(&self) -> u64 {
        self.ipsec.snapshot_generation()
    }

    #[inline]
    pub(in crate::afxdp) fn ipsec_tunnel_rows_arc(&self) -> Arc<IpsecTunnelRows> {
        self.ipsec.rows.clone()
    }
}


/// The WRITE side of the runtime-view channel — the coordinator's handle.
///
/// Wraps the `ArcSwap` with a PRIVATE field and exposes exactly three
/// operations. Nothing hands out the `ArcSwap` itself, so `swap`, `rcu`,
/// `compare_and_swap`, `Deref` and every other mutation route `ArcSwap`
/// provides are simply not reachable — [`RuntimeViewChannel::publish`] is the
/// only way to change what workers see. That closes the "enumerate the
/// mutation spellings" failure mode a textual canary cannot.
pub(in crate::afxdp) struct RuntimeViewChannel {
    inner: Arc<ArcSwap<RuntimeView>>,
}

impl Default for RuntimeViewChannel {
    fn default() -> Self {
        Self {
            inner: Arc::new(ArcSwap::from_pointee(RuntimeView::default())),
        }
    }
}

impl RuntimeViewChannel {
    /// Hand a READ-ONLY handle to a worker or aux thread. The returned type
    /// cannot publish, so no consumer can become a writer by aliasing.
    pub(in crate::afxdp) fn reader(&self) -> RuntimeViewReader {
        RuntimeViewReader {
            inner: self.inner.clone(),
        }
    }

    /// Acquire-load the current view (coordinator side).
    #[inline]
    pub(in crate::afxdp) fn load(&self) -> arc_swap::Guard<Arc<RuntimeView>> {
        self.inner.load()
    }

    /// Acquire-load and retain the current view (the `#[cfg(test)]` publish
    /// seam keeps the previous view alive with this, so `Arc::ptr_eq` cannot be
    /// fooled by a freed allocation being reused).
    pub(in crate::afxdp) fn load_full(&self) -> Arc<RuntimeView> {
        self.inner.load_full()
    }

    /// Make `view` worker-visible. THE single mutation on this channel; the
    /// coordinator funnels every publish through
    /// `Coordinator::store_runtime_view` so the view is always built from
    /// `self.validation` at the store.
    pub(in crate::afxdp) fn publish(&self, view: Arc<RuntimeView>) {
        self.inner.store(view);
    }
}

/// The READ side of the runtime-view channel — what workers, the GRE
/// local-origin threads, and every other consumer hold.
///
/// The `ArcSwap` is a private field and the only method is [`load`]. There is
/// no `Deref`, no accessor returning the `ArcSwap`, and no publish method, so a
/// consumer cannot obtain a writer at all — the earlier
/// `runtime_reader() -> Arc<ArcSwap<RuntimeView>>` handed one out and a review
/// probe used exactly that to publish a torn pair from `refresh_fabric_links`.
///
/// [`load`]: RuntimeViewReader::load
#[derive(Clone)]
pub(in crate::afxdp) struct RuntimeViewReader {
    inner: Arc<ArcSwap<RuntimeView>>,
}

impl RuntimeViewReader {
    /// THE single-load primitive. Both halves of the pair must come out of one
    /// call: two loads in a tick can observe two different views and pair
    /// halves across generations, which is the defect #6592 closed.
    #[inline]
    pub(in crate::afxdp) fn load(&self) -> arc_swap::Guard<Arc<RuntimeView>> {
        self.inner.load()
    }

    /// Do two handles address the SAME channel? For the launch-wiring test
    /// only — it replaces an `Arc::ptr_eq` on the formerly-exposed `ArcSwap`.
    pub(in crate::afxdp) fn same_channel(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }
}

/// #1188 short-circuit over a [`RuntimeViewReader`] for readers that need ONLY
/// the forwarding half (the GRE local-origin / WG control threads).
///
/// Returns `Some(new_arc)` when the published forwarding `Arc` differs from
/// `cached`, `None` when it is the same allocation. A validation-only publish
/// rotates the view but NOT the inner forwarding `Arc`, so such readers
/// correctly see no change.
#[inline]
pub(in crate::afxdp) fn load_forwarding_if_changed(
    cached: &Arc<ForwardingState>,
    shared_runtime: &RuntimeViewReader,
) -> Option<Arc<ForwardingState>> {
    let view = shared_runtime.load();
    if Arc::ptr_eq(cached, view.forwarding()) {
        None
    } else {
        Some(view.forwarding().clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation_only_view_reuses_published_ipsec_rows() {
        let rows = Arc::new(IpsecTunnelRows::new([IpsecTunnelRow {
            stn: "st0".into(),
            if_id: 9,
            logical_ifindex: 10,
        }]));
        let forwarding = Arc::new(ForwardingState::default());
        let first = RuntimeView::new_with_ipsec_tunnel_rows( // runtime-view-canary: test-local
            ValidationState {
                snapshot_installed: true,
                config_generation: 7,
                fib_generation: 3,
            },
            forwarding,
            rows,
            7,
        );
        let second = RuntimeView::new_with_ipsec_tunnel_rows( // runtime-view-canary: test-local
            ValidationState {
                snapshot_installed: true,
                config_generation: 7,
                fib_generation: 4,
            },
            first.forwarding().clone(),
            first.ipsec_tunnel_rows_arc(),
            first.ipsec_snapshot_generation(),
        );
        assert_eq!(second.ipsec_snapshot_generation(), 7);
        assert_eq!(second.ipsec_tunnel_rows().exact("st0").map(|r| r.if_id), Some(9));
    }
}
