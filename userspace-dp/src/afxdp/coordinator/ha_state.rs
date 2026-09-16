use super::*;

/// Cross-thread HA reconciliation state shared between the coordinator,
/// HA worker, and packet workers via `Arc<ArcSwap<…>>`.
///
/// The 3 fields land here together because they're all written by the
/// same reconciliation pass (RG demote/activate, fabric refresh,
/// forwarding rebuild) and read by the worker hot path. Splitting them
/// further would create artificial cross-struct coupling on the
/// reconcile call sites.
pub(in crate::afxdp) struct HaState {
    pub(in crate::afxdp) rg_runtime: Arc<ArcSwap<BTreeMap<i32, HAGroupRuntime>>>,
    /// #9629: leaf mutex serializing the HA load→diff→store section across
    /// the locked path (`Coordinator::update_ha_state`) and the session
    /// fast path (`SessionDomain::try_refresh_ha_leases`). Guards no data —
    /// the section holds only ArcSwap/atomics/local builds — so poison is
    /// recovered (`lock_ha_recover`), never quarantined. Lock order is
    /// `ServerState → ha` (leaf, acyclic); hold is µs (no slow ops, no
    /// logging inside).
    pub(in crate::afxdp) ha_mutex: Arc<Mutex<()>>,
    pub(in crate::afxdp) fabrics: Arc<ArcSwap<Vec<FabricLink>>>,
    /// #6592: the single worker-visible runtime gate — validation AND
    /// forwarding in ONE `Arc`, so a reader can never pair them across
    /// generations. Replaces the former `forwarding: Arc<ArcSwap<
    /// ForwardingState>>` + the sibling `Coordinator::shared_validation`;
    /// see `types/runtime_view.rs` for why the forwarding half stays a
    /// nested `Arc` (the #1188 short-circuit).
    ///
    /// **Narrower than its two siblings on purpose.** `pub(super)` — the
    /// `coordinator` module tree only — not `pub(in crate::afxdp)`. Publishing
    /// a view pairs `Coordinator::validation` with a forwarding state, and that
    /// pairing is the whole point of #6592; every publish must therefore go
    /// through `Coordinator::store_runtime_view`, which builds the view from
    /// `self.validation` AT the store.
    ///
    /// The type is [`RuntimeViewChannel`], not a bare `Arc<ArcSwap<..>>`: its
    /// `ArcSwap` is a private field, so `publish` is the only mutation
    /// reachable anywhere and `swap` / `rcu` / `compare_and_swap` / `Deref` are
    /// not. Readers outside the coordinator take a [`RuntimeViewReader`] via
    /// [`HaState::runtime_reader`], which cannot publish at all.
    pub(super) runtime: RuntimeViewChannel,
}

impl HaState {
    pub(super) fn new() -> Self {
        Self {
            rg_runtime: Arc::new(ArcSwap::from_pointee(BTreeMap::new())),
            ha_mutex: Arc::new(Mutex::new(())),
            fabrics: Arc::new(ArcSwap::from_pointee(Vec::new())),
            runtime: RuntimeViewChannel::default(),
        }
    }
}

/// #9629: recover the HA leaf mutex, never propagate poison.
///
/// `worker_queue::lock_recover` is type-bound to
/// `Mutex<VecDeque<WorkerCommand>>` and cannot serve `Mutex<()>`; this is
/// the same committed-prefix + clear-poison policy for the HA leaf. No
/// quarantine (unlike `ServerState` poison): the mutex guards no data, the
/// section contains only ArcSwap loads, atomic bumps and local map builds,
#[inline]
pub(in crate::afxdp) fn lock_ha_recover(m: &Mutex<()>) -> std::sync::MutexGuard<'_, ()> {
    match m.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            // Clear (not just recover): `into_inner()` alone leaves the poison
            // bit set, so every later `lock()` would re-enter this arm
            // forever. Same committed-prefix + clear policy as
            // `worker_queue::lock_recover`, minus its queue-specific counter
            // and log (this mutex guards no data; nothing to count).
            m.clear_poison();
            poisoned.into_inner()
        }
    }
}

impl HaState {
    /// #6592: a READ-ONLY handle on the published runtime view, for the worker
    /// launch bundle and the GRE/WG aux threads.
    ///
    /// It returns a [`RuntimeViewReader`], not the `ArcSwap`. The earlier
    /// version returned `Arc<ArcSwap<RuntimeView>>` and a review probe used
    /// exactly that to alias the writer and publish a torn pair from
    /// `refresh_fabric_links` — every textual canary rule passed. A consumer
    /// now has no way to reach a writer, so that bypass is a COMPILE error
    /// rather than something a canary has to notice.
    pub(in crate::afxdp) fn runtime_reader(&self) -> RuntimeViewReader {
        self.runtime.reader()
    }
}
