use super::*;

/// #925 Phase 1: render a panic payload as an operator-readable string.
///
/// Cases:
/// - `&str` payload → the panic argument verbatim.
/// - `String` payload → its content.
/// - Anything else → literal `"non-string panic payload"`.
///
/// We deliberately do NOT try to extract a concrete type name from a
/// `dyn Any` payload — `type_name_of_val` on a `Box<dyn Any>` returns
/// the trait object's name, not the inner type, which would mislead.
pub(super) fn panic_payload_message(payload: &Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        String::from("non-string panic payload")
    }
}

/// #925 Phase 1.5: spawn an auxiliary (non-worker) thread on a
/// named thread and wrap it with `catch_unwind`. On panic, log a
/// stderr message that surfaces in journald, then exit the thread
/// without respawning.
///
/// Used for control-plane helper threads that don't have per-worker
/// `runtime_atomics` (e.g. `neigh-monitor`, `xpf-native-gre-origin-*`).
/// Worker threads use `spawn_supervised_worker` which records the
/// panic in the per-worker `dead` flag exposed through
/// `crate::protocol::WorkerRuntimeStatus` on the userspace
/// control-socket JSON status path (NOT gRPC — the dataplane status
/// is JSON-over-Unix-socket, only the daemon's outward-facing API
/// is gRPC). Aux threads have no equivalent status surface and rely
/// on journald log scraping.
///
/// Operator-visible degradation when an aux thread dies (#925-A):
/// - `neigh-monitor` death: dynamic neighbor cache stops updating;
///   forwarding falls back to slow-path NDP/ARP resolution after
///   kernel TTL expiration. Degrades over minutes.
/// - `xpf-native-gre-origin-*` death: that tunnel's local-origin
///   packet stream stops; transit packets through the tunnel are
///   unaffected (those go through worker_loop).
///
/// `AssertUnwindSafe` rationale: aux thread bodies own their state
/// and `Arc`s; no `&mut` parameters cross the unwind. Shared
/// `Arc<Mutex<…>>` may become poisoned. Consumers in `coordinator/mod.rs`
/// follow two poison-tolerant patterns: (a) `into_inner` recovery
/// (e.g. the worker `panic_slot` write at the bottom of
/// `spawn_supervised_worker`), and (b) `if let Ok(mut guard) =
/// lock { ... }` which silently drops the guard on poison and
/// proceeds — lossy for that one operation but never propagates
/// the panic (see `recent_exceptions` users in `coordinator/mod.rs`).
/// Aux threads only touch `Arc<Mutex<…>>` via the `(b)` pattern, so a
/// poisoned mutex degrades a single error-recording attempt and
/// does not cascade.
pub(super) fn spawn_supervised_aux<S, F>(name: S, body: F) -> std::io::Result<thread::JoinHandle<()>>
where
    S: Into<String>,
    F: FnOnce() + Send + 'static,
{
    let name = name.into();
    let log_name = name.clone();
    thread::Builder::new().name(name).spawn(move || {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(body));
        if let Err(payload) = result {
            let msg = panic_payload_message(&payload);
            eprintln!(
                "xpf-userspace-dp: aux thread '{log_name}' panicked: {msg}",
            );
        }
    })
}

/// #925 Phase 1: spawn `body` on a named thread and wrap it with
/// `catch_unwind`. On panic, mark `runtime_atomics.dead = true` and
/// publish the rendered payload to `panic_slot`.
///
/// `AssertUnwindSafe` rationale (narrow): `worker_loop` takes owned
/// values and `Arc`s — there are no `&mut` parameters to invalidate
/// across an unwind. Owned values get dropped on unwind. Shared
/// `Arc<Mutex<…>>` state MAY become poisoned; per #925's "detection
/// only" framing this PR does not promise full state recovery — see
/// `docs/pr/925-worker-supervisor/plan.md` §"AssertUnwindSafe rationale".
pub(super) fn spawn_supervised_worker<F>(
    worker_id: u32,
    runtime_atomics: Arc<crate::afxdp::worker_runtime::WorkerRuntimeAtomics>,
    panic_slot: Arc<Mutex<Option<String>>>,
    body: F,
) -> std::io::Result<thread::JoinHandle<()>>
where
    F: FnOnce() + Send + 'static,
{
    thread::Builder::new()
        .name(format!("xpf-userspace-worker-{worker_id}"))
        .spawn(move || {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(body));
            if let Err(payload) = result {
                let msg = panic_payload_message(&payload);
                eprintln!(
                    "xpf-userspace-dp: worker_loop panicked (worker_id={worker_id}): {msg}",
                );
                // Write the message under the slot mutex; on poison
                // (a prior panic during read), use into_inner — same
                // pattern as #949's dynamic_neighbors policy.
                match panic_slot.lock() {
                    Ok(mut slot) => *slot = Some(msg),
                    Err(poisoned) => *poisoned.into_inner() = Some(msg),
                }
                // Mark dead. Relaxed is fine — the panic_slot mutex
                // publishes the message; the dead flag is a one-shot
                // diagnostic, not a synchronization barrier.
                runtime_atomics
                    .dead
                    .store(true, std::sync::atomic::Ordering::Relaxed);
            }
        })
}
