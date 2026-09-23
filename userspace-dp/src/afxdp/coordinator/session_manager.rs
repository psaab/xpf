use super::*;

/// Cross-thread session-table state shared between the coordinator,
/// HA worker, and packet workers via `Arc<Mutex<...>>`.
///
/// The 3 session tables (synced + nat + forward-wire) plus the
/// owner-RG index live here together because they're written and
/// queried as a unit by the HA bulk-sync, incremental-sync, and
/// session-resolution paths. The `export_seq` counter is the
/// per-RG ack sequence number that pairs with the export ack
/// broadcast in HA `export_owner_rg_sessions`.
///
/// The three sync-import refusal counters below are PER-INSTANCE
/// (`AtomicU64` fields, not process-global statics) for the same reason
/// `Coordinator::last_quiesce_ms` and the `force_worker_*` seams are: a
/// process-global counter is observable by every other `Coordinator` in the
/// process. Production builds exactly one `Coordinator` (`server::lifecycle`),
/// so the exported Prometheus value (`import_cap_drops`, via
/// `server/helpers/status.rs` -> `protocol::control` -> the Go collector) is
/// unchanged; the other two have no surface outside this binary at all — their
/// accessors are called only from `ha_tests.rs`. (None of the three is in
/// `proto/`: this crate has no gRPC dependency.) The change is observable only
/// to tests, which build one `Coordinator` per `#[test]` and run them
/// concurrently in a single process — as globals, every assertion about these
/// counters depended on what every other test happened to do (#6819).
/// #9856: open-window idle expiry. A window with no `wait_and_collect`
/// activity this long is abandoned (Go side died mid-window — healthy paged
/// exports refresh every call) and the next kick clears + proceeds instead
/// of BUSY-looping. Generous vs the 15 s per-call bound; M3 replaces with
/// explicit expiry errors + measured sizing.
const EXPORT_WINDOW_IDLE_EXPIRY_NS: u64 = 60_000_000_000;

/// #9856: the currently-open owner-RG export window. Private to this module:
/// all access goes through the `open_export_*` methods so the BUSY / adopt /
/// refresh / clear-if-ours protocol has exactly one implementation. Kick-time
/// buffer+ack Arcs ride here so every continuation of the window drains the
/// EXACT worker set the kick saw (a reconcile between pages can neither drop
/// torn-down workers' buffers nor add a new worker into this window).
pub(in crate::afxdp) struct OpenExportWindow {
    sequence: u64,
    incarnation: u64,
    since_ns: u64,
    buffers: Vec<Arc<crate::afxdp::binding_state::ExportBufferState>>,
    acks: Vec<Arc<AtomicU64>>,
    dropped_at_begin: Vec<u64>,
    shed: u32,
}

pub(in crate::afxdp) struct SessionManager {
    pub(in crate::afxdp) synced: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    pub(in crate::afxdp) nat: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    pub(in crate::afxdp) forward_wire: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    pub(in crate::afxdp) owner_rg_indexes: SharedSessionOwnerRgIndexes,
    pub(in crate::afxdp) export_seq: AtomicU64,
    /// #9856: random per-helper incarnation. It is emitted with every
    /// export page so a restarted helper cannot reuse a sequence number
    /// and accidentally resume an old window.
    pub(in crate::afxdp) export_incarnation: u64,
    /// #9856: the currently-open owner-RG export window (`None` = idle).
    /// Shared with in-flight `OwnerRgExportWait` handles, which refresh
    /// activity per page and clear-if-ours on terminal pages and error
    /// paths. See `OpenExportWindow` + the `open_export_*` methods.
    pub(in crate::afxdp) open_export: Arc<Mutex<Option<OpenExportWindow>>>,
    /// #2170 HA deferred-delete generation guard observability. These count how
    /// often the helper's in-memory SyncedSessionEntry generation guard refused
    /// a stale-generation install (`upsert_synced_session`, the
    /// delayed-stale-install variant) or a stale-generation delete
    /// (`delete_synced_session_gen`, belt-and-suspenders for any helper-side
    /// generation-aware delete). The authoritative guard lives in the Go
    /// cluster apply layer; these helper-side counters report any
    /// divergence/back-stop activity. Surfaced via
    /// `Coordinator::session_install_stale_ignored_total()` /
    /// `session_delete_stale_ignored_total()`.
    pub(in crate::afxdp) install_stale_ignored: AtomicU64,
    pub(in crate::afxdp) delete_stale_ignored: AtomicU64,
    /// #10512 scoped HA deletes refused on identity mismatch (the under-lock
    /// entry carries a different RT_FLOW id than captured — a replacement
    /// installed after capture). Surfaced via
    /// `Coordinator::session_delete_refused_identity_total()`.
    pub(in crate::afxdp) delete_refused_identity: AtomicU64,
    /// #10512: policy-delete micro-batch gate-lease holds: count, total hold
    /// nanoseconds, and max single hold. The average (total/count) is the
    /// empirical leg of the tree-consistent timing position (ms-typical
    /// holds); the max bounds the pathological case. Surfaced via
    /// `Coordinator::policy_batch_{count,hold_ns,hold_max_ns}_total()`.
    pub(in crate::afxdp) policy_batch_count: AtomicU64,
    pub(in crate::afxdp) policy_batch_hold_ns: AtomicU64,
    pub(in crate::afxdp) policy_batch_hold_max_ns: AtomicU64,
    /// #6979 F4: `DeleteSynced` commands dropped by a full worker command queue
    /// whose NAT reservation this coordinator released on the worker's behalf.
    ///
    /// Nonzero means a worker command queue hit
    /// `MAX_PENDING_WORKER_COMMANDS` during a synced-session delete. The
    /// reservation is NOT leaked — that is what this counter counts — but the
    /// same dropped command also cost that worker its local session-table and
    /// BPF map teardown for the key, so a climbing value is a real backpressure
    /// signal and not merely bookkeeping. Pair it with
    /// `WORKER_COMMAND_QUEUE_DROPS`, which counts every dropped command of any
    /// kind.
    pub(in crate::afxdp) delete_dropped_released: AtomicU64,
    /// #8138: import-time `Untracked` reservations released by the tunnel-remap
    /// purge. Incremented ONLY when the release actually freed a record — a
    /// counter that also counted attempts would report the leak as handled
    /// while the port stayed held.
    pub(in crate::afxdp) tunnel_purge_reservations_released: AtomicU64,
    /// #7209: peer-synced imports whose `(from_zone, to_zone)` pair could not
    /// be resolved locally, so the source-NAT reservation was booked WITHOUT
    /// #6211's zone narrowing.
    ///
    /// What the operator loses, which is what makes this worth a counter: the
    /// session is installed with the ACTIVE node's exact translated address and
    /// port — those come off the HA wire and are never recomputed, so nothing
    /// is mistranslated. What is lost is the narrowing that picks WHICH rule's
    /// allocator holds the reservation. With a single pool-mode rule owning the
    /// translated address the two paths agree and this is purely informational.
    /// It only diverges where two pool-mode rules' pools BOTH contain that
    /// address in separate allocators, and there the booking may sit in a
    /// different allocator than the active's — with a second booking taken if a
    /// later re-upsert does resolve, both live until teardown frees them and
    /// both counting against `max_tracked_flows`.
    ///
    /// Nonzero is not by itself a fault: it is expected while a config apply is
    /// in flight (`sync_session` reads the PUBLISHED forwarding view, which lags
    /// the pending one by design — #7209) and on an HA standby's first sync
    /// before any snapshot has been applied. Sustained growth on a settled
    /// config means the nodes' zone configuration has drifted.
    ///
    /// Surfaced via `Coordinator::synced_import_zone_unresolved_total()`.
    pub(in crate::afxdp) synced_import_zone_unresolved: AtomicU64,
    /// #7209: peer-synced imports this node was ALLOWED to publish (the local
    /// replace guard passed) but could not, because `bpf_maps.session_map_fd`
    /// was `None` — there was no kernel session map to write into.
    ///
    /// Counts the GAP only, never the ownership decision it used to share an
    /// `&&` with. Declining to publish because the PEER owns the redundancy
    /// group is correct and is not counted; a counter folding the two together
    /// would sit permanently nonzero on a healthy node and report nothing.
    ///
    /// Nonzero is EXPECTED, not a fault, on the ordinary paths where the map
    /// does not exist yet: an HA standby taking bulk sync before its first
    /// snapshot apply, and the interval between `stop_inner` and the next
    /// `reconcile::bringup`. Those imports are not lost — every reconcile opens
    /// by capturing the whole shared synced map and replays it once the new map
    /// is up.
    ///
    /// What it is FOR is #7209. Once `sync_session` is taken off the
    /// snapshot-wide `ServerState` mutex, an import landing between that
    /// capture and the replay would be recorded, answered to Go as installed,
    /// never published and never replayed. This is the instrument that makes
    /// that window observable, so the deferred-and-replay design can be SHOWN
    /// to drive it to zero rather than asserted from the lock graph.
    ///
    /// Surfaced via `Coordinator::synced_import_unpublished_total()`.
    pub(in crate::afxdp) synced_import_unpublished: AtomicU64,
    /// #7209: reverse companions RE-DERIVED at reconcile replay because the
    /// stored one no longer matched what the live forwarding table resolves.
    ///
    /// The companion is synthesized at IMPORT time from `Coordinator.forwarding`
    /// (`synthesized_synced_reverse_entry`, whose only early return is on
    /// `is_reverse` — there is no forwarding-dependent `None` arm), so an import
    /// taken while that table cannot resolve the reply path publishes a
    /// companion carrying `NoRoute`, ifindex 0 and owner RG 0. Nothing
    /// downstream re-derived it: the replay republished `entry.decision`
    /// verbatim, and the only repair was the RG-activation prewarm, which a
    /// mid-life `apply_snapshot` on an already-ACTIVE node never reaches.
    ///
    /// The replay now re-derives under the live table, which is the same shape
    /// #8171 established for the entries themselves. This counts the repairs so
    /// the window is MEASURED rather than asserted from the lock graph — a
    /// nonzero value means an import was taken while the table could not answer,
    /// which is expected on a standby taking bulk sync before its first apply
    /// and is the thing to watch once `sync_session` runs off the ServerState
    /// mutex.
    ///
    /// Surfaced via `Coordinator::synced_reverse_rederived_total()`.
    pub(in crate::afxdp) synced_reverse_rederived: AtomicU64,
    /// #5674: peer-synced session imports REJECTED by the coordinator's
    /// aggregate admission bound (`upsert_synced_session`). Locally-created
    /// sessions are capped per worker at `DEFAULT_MAX_SESSIONS`
    /// (`install_with_protocol_with_origin`), but peer-synced sessions were
    /// imported with NO cap and fanned out to EVERY worker command queue +
    /// table, so a peer under session-table pressure — or a
    /// malicious/compromised peer — could drive this node past its own
    /// aggregate session ceiling and multiply that state across all workers
    /// (the availability/DoS root of #5674). `upsert_synced_session` now bounds
    /// the shared synced map (the single fan-out choke point) at this
    /// appliance's OWN aggregate ENTRY ceiling (`2 * worker_count *
    /// DEFAULT_MAX_SESSIONS` — 2× the logical ceiling because each admitted
    /// forward logical session publishes a forward AND a synthesized reverse
    /// companion into the map) and drop-newest-rejects a NEW over-ceiling
    /// FORWARD key here (a REPLACE of an existing key, and a lone reverse
    /// import, never trip the bound — neither grows the forward-keyed count).
    /// Surfaced via `Coordinator::synced_import_cap_drops_total()` and the
    /// Prometheus counter `xpf_userspace_synced_import_cap_drops_total`. A
    /// nonzero value means a peer exceeded its own LOGICAL session ceiling (a
    /// malicious/compromised peer); a legitimate symmetric-pair failover — the
    /// peer's full logical set (N logical → 2N entries) EXACTLY fits the 2N cap
    /// — never trips it, at any peer load.
    pub(in crate::afxdp) import_cap_drops: AtomicU64,
    /// #7160 (#2387): peer-synced imports REFUSED because this node runs
    /// routing instances and the request named no ingress identity to resolve
    /// the session's routing DOMAIN from.
    ///
    /// Always 0 on a node with no routing-instance interface membership — the
    /// resolver returns the default domain there and nothing is refused — so a
    /// nonzero value means specifically: a VRF deployment received a synced
    /// session whose cluster-stable ingress name the sender could not supply
    /// (#7096 fabric-redirected, or a session with no such name). Those
    /// sessions are not taken over; their flows re-adjudicate through policy
    /// after a failover.
    ///
    /// Surfaced via `Coordinator::synced_import_unknown_routing_domain_total()`
    /// and the Prometheus counter
    /// `xpf_userspace_synced_import_unknown_routing_domain_total`, on the same
    /// route as every sibling refusal counter. It was briefly written as
    /// "deliberately not surfaced"; the #6641 status-wiring audit rejected
    /// that, correctly — its `UNSURFACED` allowlist is deliberately EMPTY
    /// since #7398, and this counter is the only signal that a VRF cluster is
    /// silently not taking over a subset of its peer's sessions.
    pub(in crate::afxdp) import_unknown_routing_domain: AtomicU64,
    /// #6600: peer-synced imports REFUSED because this node could not reserve
    /// the translated NAT port the session names.
    ///
    /// The import path published the shared session entry BEFORE any worker
    /// reserved that port, and the reservation — which happens only inside the
    /// worker-local upsert — REFUSES to steal a port a different live
    /// allocation already holds. The refusal was returned by nothing, counted
    /// by nothing and logged by nothing, so in the window between publish and
    /// worker-apply a local flow could claim the port and the imported session
    /// went on advertising a translation this node did not own. Any packet
    /// forwarded on that shared-backed decision used it.
    ///
    /// The reservation now happens at the coordinator BEFORE the publish, and a
    /// refusal drops the import instead. That is the safe direction — no
    /// session beats a session naming someone else's port, and the peer re-syncs
    /// — but it is still a DROPPED failover session, so it must be visible: a
    /// silent drop would trade one invisible failure for another. A nonzero
    /// value means a local flow held the translated port at import time, which
    /// on a healthy standby (owning RG passive) should not happen and points at
    /// overlapping pools, an active-active RG pair sharing one SNAT pool, or
    /// genuine NAT config drift between the nodes.
    pub(in crate::afxdp) import_reserve_refused: AtomicU64,
}

impl SessionManager {
    pub(super) fn new() -> Self {
        Self {
            synced: Arc::new(Mutex::new(FastMap::default())),
            nat: Arc::new(Mutex::new(FastMap::default())),
            forward_wire: Arc::new(Mutex::new(FastMap::default())),
            owner_rg_indexes: SharedSessionOwnerRgIndexes::default(),
            export_seq: AtomicU64::new(0),
            export_incarnation: crate::protocol::session_export_incarnation(),
            open_export: Arc::new(Mutex::new(None)),
            install_stale_ignored: AtomicU64::new(0),
            synced_import_zone_unresolved: AtomicU64::new(0),
            synced_import_unpublished: AtomicU64::new(0),
            synced_reverse_rederived: AtomicU64::new(0),
            delete_stale_ignored: AtomicU64::new(0),
            delete_refused_identity: AtomicU64::new(0),
            delete_dropped_released: AtomicU64::new(0),
            tunnel_purge_reservations_released: AtomicU64::new(0),
            import_cap_drops: AtomicU64::new(0),
            policy_batch_count: AtomicU64::new(0),
            policy_batch_hold_ns: AtomicU64::new(0),
            policy_batch_hold_max_ns: AtomicU64::new(0),
            import_unknown_routing_domain: AtomicU64::new(0),
            import_reserve_refused: AtomicU64::new(0),
        }
    }
    /// #9856: BUSY check for a fresh kick. `Some(open_seq)` when a non-idle
    /// window is open (caller fails WITHOUT consuming a sequence); `None`
    /// when kick may proceed (no window, or idle-expired — the subsequent
    /// `begin` overwrites). MUST be called under the `ServerState` lock,
    /// in the same critical section as the `begin` that follows it.
    pub(in crate::afxdp) fn open_export_busy(&self, now_ns: u64) -> Option<u64> {
        let open = self.open_export.lock().unwrap_or_else(|e| e.into_inner());
        match open.as_ref() {
            Some(w) if now_ns.saturating_sub(w.since_ns) < EXPORT_WINDOW_IDLE_EXPIRY_NS => {
                Some(w.sequence)
            }
            _ => None,
        }
    }

    /// #9856: record a fresh window after a `None` from `open_export_busy`.
    pub(in crate::afxdp) fn open_export_begin(
        &self,
        sequence: u64,
        now_ns: u64,
        buffers: &[Arc<crate::afxdp::binding_state::ExportBufferState>],
        acks: &[Arc<AtomicU64>],
        shed: u32,
    ) {
        let dropped_at_begin = buffers.iter().map(|b| b.export_dropped()).collect();
        *self.open_export.lock().unwrap_or_else(|e| e.into_inner()) = Some(OpenExportWindow {
            sequence,
            incarnation: self.export_incarnation,
            since_ns: now_ns,
            buffers: buffers.to_vec(),
            acks: acks.to_vec(),
            dropped_at_begin,
            shed,
        });
    }

    /// #9856: helper incarnation advertised with every page.
    pub(in crate::afxdp) fn export_incarnation(&self) -> u64 {
        self.export_incarnation
    }

    /// #9856: adopt the open window for a continuation: clones out the
    /// sequence, incarnation, buffers, acks, drop baselines and shed count.
    pub(in crate::afxdp) fn open_export_adopt(
        &self,
        now_ns: u64,
    ) -> Option<(
        u64,
        u64,
        Vec<Arc<crate::afxdp::binding_state::ExportBufferState>>,
        Vec<Arc<AtomicU64>>,
        Vec<u64>,
        u32,
    )> {
        let mut open = self.open_export.lock().unwrap_or_else(|e| e.into_inner());
        open.as_mut().map(|w| {
            w.since_ns = now_ns;
            (
                w.sequence,
                w.incarnation,
                w.buffers.clone(),
                w.acks.clone(),
                w.dropped_at_begin.clone(),
                w.shed,
            )
        })
    }

    /// #9856: refresh activity iff `sequence` is still the open window
    /// (per-page proof of collection; healthy paged exports never idle out
    /// no matter how many pages they span).
    pub(in crate::afxdp) fn open_export_refresh_if(&self, sequence: u64, now_ns: u64) {
        let mut open = self.open_export.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(w) = open.as_mut() {
            if w.sequence == sequence {
                w.since_ns = now_ns;
            }
        }
    }

    /// #9856: clear the open window iff it is still `sequence` (terminal
    /// pages and error paths). Single-waiter-per-window + kick-under-lock:
    /// the sequence match means this can never clear a newer window.
    pub(in crate::afxdp) fn open_export_clear_if(&self, sequence: u64) {
        let mut open = self.open_export.lock().unwrap_or_else(|e| e.into_inner());
        if matches!(open.as_ref(), Some(w) if w.sequence == sequence) {
            *open = None;
        }
    }

    /// Test seam for the idle-expiry path: overwrite the activity stamp of
    /// the open window (no-op when idle), so a cell can age a window out
    /// without sleeping 60 s.
    #[cfg(test)]
    pub(in crate::afxdp) fn open_export_set_since_for_test(&self, since_ns: u64) {
        let mut open = self.open_export.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(w) = open.as_mut() {
            w.since_ns = since_ns;
        }
    }
}
