//! #7158: DNS resolution for WireGuard peer endpoints authored as hostnames.
//!
//! A peer behind a dynamic WAN is reachable by a DDNS name, not a literal. The
//! commit gate used to reject a hostname outright, which made that topology
//! unauthorable. It is now accepted, and this is where the name becomes an
//! address.
//!
//! ## Why a thread, and not a lookup in the control loop
//!
//! The WireGuard control loop is not a control-only loop: it blocks in `poll(2)`
//! over `{UDP socket, TUN}` and carries the tunnel's DATA path. `to_socket_addrs`
//! is a blocking call whose worst case is a resolver timeout — seconds. Calling
//! it from that loop would not merely delay re-resolution, it would stall every
//! packet on the tunnel behind a slow or unreachable DNS server, converting a
//! name-service problem into a forwarding outage.
//!
//! The dedicated resolver uses a bounded worker set for blocking lookups, and
//! the control loop reads the latest answer with an uncontended lock and never
//! waits for DNS.
//!
//! ## Why not at commit either
//!
//! Two independent reasons, either sufficient — see `endpointFamily` in
//! `pkg/config/compiler_validate_wireguard.go`, which is the other half of this
//! decision:
//!
//! * a commit is a config transaction, and a lookup in it hangs commits on a
//!   broken resolver, including the commit that would fix the resolver;
//! * an answer cached at commit is correct at commit and silently stale a day
//!   later, which is precisely what a DDNS name is for. That failure is worse
//!   than not resolving, because it looks configured.
//!
//! ## Failure policy: retain the last good address
//!
//! A failed lookup changes nothing. The peer keeps the address that last worked,
//! the session is untouched, and the failure is counted. The alternative —
//! clearing the endpoint on a failed lookup — would tear down a working tunnel
//! because a DNS server blinked, which inverts the dependency: the tunnel would
//! become less reliable than the name service in front of it.
//!
//! The cost of retaining is a stale address after a real DDNS change while
//! lookups are failing. That is the better failure: it is the same state the
//! tunnel would be in anyway, it self-corrects on the next successful lookup,
//! and it is visible in the counters below rather than silent.
//!
//! ## Visibility
//!
//! An operator whose tunnel is down because DNS is broken must be able to see
//! that from the box rather than infer it. Every outcome is counted
//! ([`WgEndpointResolverCounters`]) and the most recent failure text is
//! retained, including the family-mismatch case — a name that resolves only to
//! the family the interface socket cannot send from is a configuration error
//! that would otherwise present as a peer that simply never initiates.

use std::collections::HashMap;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

/// Re-resolve cadence once a peer has an address. DDNS records carry short
/// TTLs (commonly 60 s); 30 s picks up a change within roughly one TTL without
/// making the tunnel a meaningful source of query load.
pub(crate) const WG_ENDPOINT_RESOLVE_INTERVAL_SECS: u64 = 30;

/// Retry cadence for a peer that has NO address yet. Faster than the steady
/// cadence because this interval is bring-up latency: until the first answer
/// the peer cannot initiate at all, so a 30 s wait would be 30 s of tunnel
/// downtime after a resolver outage clears.
pub(crate) const WG_ENDPOINT_RETRY_INTERVAL_SECS: u64 = 5;

/// Granularity at which the resolver thread notices `stop`. Small enough that
/// teardown is not perceptibly delayed, large enough not to spin.
const STOP_POLL_SLICE_MS: u64 = 250;

/// The half of the resolver's state that an OPERATOR SURFACE needs, split out
/// so the coordinator can hold it (#7936).
///
/// The resolver itself is a local of the WG control thread and is dropped when
/// that thread exits — deliberately, because its lifetime must be exactly the
/// thread's. That makes it unreachable from the 1 Hz status path, which is why
/// #7158's counters were in-process only. Handing the thread an Arc the
/// coordinator already holds is the same shape `recent_exceptions` uses for the
/// same reason, and it keeps the counters readable across a control-thread
/// restart rather than resetting them on every re-spawn.
#[derive(Debug, Default)]
pub(crate) struct WgEndpointResolverTelemetry {
    pub(crate) counters: WgEndpointResolverCounters,
    /// Most recent failure text. `family_mismatch` writes here too, because the
    /// COUNT alone does not tell an operator which name resolved to the wrong
    /// family — and that is the diagnosis this counter exists to enable.
    pub(crate) last_error: Mutex<Option<String>>,
}

impl WgEndpointResolverTelemetry {
    /// Load all four counters and the error text in one call, for the status
    /// path. Relaxed loads: these are independent monotonic counters, and a
    /// reader that saw a torn pair would draw no wrong conclusion from it —
    /// there is no invariant BETWEEN them to preserve.
    pub(crate) fn snapshot(&self) -> (u64, u64, u64, u64, String) {
        (
            self.counters.resolve_ok.load(Ordering::Relaxed),
            self.counters.resolve_fail.load(Ordering::Relaxed),
            self.counters.family_mismatch.load(Ordering::Relaxed),
            self.counters.endpoint_changed.load(Ordering::Relaxed),
            self.last_error
                .lock()
                .ok()
                .and_then(|e| e.clone())
                .unwrap_or_default(),
        )
    }
}

#[derive(Debug, Default)]
pub(crate) struct WgEndpointResolverCounters {
    /// Lookups that returned at least one usable address.
    pub(crate) resolve_ok: AtomicU64,
    /// Lookups that returned an error or no addresses at all.
    pub(crate) resolve_fail: AtomicU64,
    /// Lookups that SUCCEEDED but yielded no address of the interface socket's
    /// family. Counted separately from `resolve_fail` because the operator
    /// action differs: the name works and the record is wrong (or the tunnel is
    /// bound to the wrong family), rather than the resolver being unreachable.
    pub(crate) family_mismatch: AtomicU64,
    /// Times a lookup produced an address DIFFERENT from the one held — the
    /// DDNS-change signal, and the counter that shows re-resolution is doing
    /// something rather than merely running.
    pub(crate) endpoint_changed: AtomicU64,
}

struct ResolverShared {
    /// Last good address per peer. A peer absent from this map has never
    /// resolved; a peer present keeps its entry across failed lookups.
    resolved: Mutex<HashMap<[u8; 32], SocketAddr>>,
    /// Counters and last-error text, shared with the coordinator (#7936) so
    /// they survive this thread and reach the status wire.
    telemetry: Arc<WgEndpointResolverTelemetry>,
    stop: AtomicBool,
}

/// Handle to one tunnel's endpoint-resolution thread.
pub(crate) struct WgEndpointResolver {
    shared: Arc<ResolverShared>,
    join: Option<std::thread::JoinHandle<()>>,
}

impl WgEndpointResolver {
    /// Start resolving `targets` (peer pubkey -> authored `host:port`).
    ///
    /// Returns `None` when there is nothing to resolve, so a tunnel whose peers
    /// are all IP literals — every tunnel that existed before #7158 — starts no
    /// thread and is bit-identical to its previous behaviour.
    pub(crate) fn spawn(
        tunnel_name: &str,
        targets: Vec<([u8; 32], String)>,
        socket_is_v6: bool,
        telemetry: Arc<WgEndpointResolverTelemetry>,
    ) -> Option<Self> {
        if targets.is_empty() {
            return None;
        }
        let shared = Arc::new(ResolverShared {
            resolved: Mutex::new(HashMap::new()),
            telemetry,
            stop: AtomicBool::new(false),
        });
        let thread_shared = Arc::clone(&shared);
        let name = format!("xpf-wg-dns-{tunnel_name}");
        let join = std::thread::Builder::new()
            .name(name)
            .spawn(move || resolver_thread(thread_shared, targets, socket_is_v6))
            .ok()?;
        Some(Self {
            shared,
            join: Some(join),
        })
    }

    /// The freshest address known for `pubkey`, or `None` if it has never
    /// resolved. Never blocks on DNS — this is a map read under an uncontended
    /// mutex, safe to call from the control loop's timer pass.
    pub(crate) fn latest(&self, pubkey: &[u8; 32]) -> Option<SocketAddr> {
        self.shared
            .resolved
            .lock()
            .ok()
            .and_then(|m| m.get(pubkey).copied())
    }

    /// Test-only constructor with pre-seeded answers and NO thread, so a
    /// caller's adoption logic can be driven deterministically without a
    /// resolver, a clock, or a sleep.
    #[cfg(test)]
    pub(crate) fn with_resolved_for_test(entries: &[([u8; 32], SocketAddr)]) -> Self {
        let mut map = HashMap::new();
        for (pk, addr) in entries {
            map.insert(*pk, *addr);
        }
        Self {
            shared: Arc::new(ResolverShared {
                resolved: Mutex::new(map),
                telemetry: Arc::new(WgEndpointResolverTelemetry::default()),
                stop: AtomicBool::new(true),
            }),
            join: None,
        }
    }

    pub(crate) fn counters(&self) -> &WgEndpointResolverCounters {
        &self.shared.telemetry.counters
    }

    /// Most recent failure text, for the operator surface.
    pub(crate) fn last_error(&self) -> Option<String> {
        self.shared
            .telemetry
            .last_error
            .lock()
            .ok()
            .and_then(|e| e.clone())
    }
}

impl Drop for WgEndpointResolver {
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::Relaxed);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

/// One resolution pass over every target. Split out so it is testable without
/// a thread or a clock.
///
/// Returns the number of targets that hold an address after the pass, which the
/// thread uses to choose its next cadence.
fn resolve_once(
    shared: &ResolverShared,
    targets: &[([u8; 32], String)],
    socket_is_v6: bool,
) -> usize {
    resolve_once_with(shared, targets, socket_is_v6, |host_port| {
        host_port.to_socket_addrs().map(|a| a.collect::<Vec<_>>())
    })
}

/// The single place where a lookup outcome is folded into shared state.
/// Outcomes are applied in target order to preserve the existing counter,
/// last-good-address and last-error semantics.
fn apply_resolution(
    shared: &ResolverShared,
    pubkey: &[u8; 32],
    host_port: &str,
    socket_is_v6: bool,
    outcome: std::io::Result<Vec<SocketAddr>>,
) -> bool {
    match outcome {
        Ok(addrs) => {
            // Keep only the family the interface's single UDP socket can
            // send from. A dual-stack name on a v4 socket must yield its A
            // record, not whichever answer happened to sort first.
            let chosen = addrs.into_iter().find(|a| a.is_ipv6() == socket_is_v6);
            match chosen {
                Some(addr) => {
                    shared
                        .telemetry
                        .counters
                        .resolve_ok
                        .fetch_add(1, Ordering::Relaxed);
                    if let Ok(mut map) = shared.resolved.lock() {
                        let prior = map.insert(*pubkey, addr);
                        if prior != Some(addr) {
                            shared
                                .telemetry
                                .counters
                                .endpoint_changed
                                .fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
                None => {
                    shared
                        .telemetry
                        .counters
                        .family_mismatch
                        .fetch_add(1, Ordering::Relaxed);
                    set_last_error(
                        shared,
                        format!(
                            "{host_port} resolved, but to no {} address; \
                             this WireGuard interface binds one {} UDP socket",
                            if socket_is_v6 { "IPv6" } else { "IPv4" },
                            if socket_is_v6 { "IPv6" } else { "IPv4" },
                        ),
                    );
                }
            }
        }
        Err(e) => {
            shared
                .telemetry
                .counters
                .resolve_fail
                .fetch_add(1, Ordering::Relaxed);
            set_last_error(shared, format!("{host_port}: {e}"));
            // Deliberately no removal from `resolved`: the last good
            // address is retained across a failed lookup.
        }
    }
    shared
        .resolved
        .lock()
        .map(|m| m.contains_key(pubkey))
        .unwrap_or(false)
}

/// A pass with the blocking lookup injected, so concurrency can be tested
/// without depending on DNS or the environment.
fn resolve_once_with<F>(
    shared: &ResolverShared,
    targets: &[([u8; 32], String)],
    socket_is_v6: bool,
    lookup: F,
) -> usize
where
    F: Fn(&str) -> std::io::Result<Vec<SocketAddr>> + Sync,
{
    if targets.len() < 2 {
        let mut held = 0;
        for (pubkey, host_port) in targets {
            if apply_resolution(shared, pubkey, host_port, socket_is_v6, lookup(host_port)) {
                held += 1;
            }
        }
        return held;
    }
    // Bound blocking calls and per-pass worker creation even if a tunnel has
    // many peers. Workers claim the next target as soon as they finish, so a
    // slow lookup does not hold up later peers merely because they share a
    // batch. State application below remains single-threaded and ordered.
    const MAX_CONCURRENT_LOOKUPS: usize = 8;
    let lookup = &lookup;
    let next_index = AtomicUsize::new(0);
    std::thread::scope(|scope| {
        let next_index = &next_index;
        let (send, receive) = std::sync::mpsc::channel();
        let workers = targets.len().min(MAX_CONCURRENT_LOOKUPS);
        let mut handles = Vec::with_capacity(workers);
        for _ in 0..workers {
            let send = send.clone();
            handles.push(scope.spawn(move || loop {
                let index = next_index.fetch_add(1, Ordering::Relaxed);
                let Some((_, host_port)) = targets.get(index) else {
                    break;
                };
                let outcome =
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| lookup(host_port)))
                        .unwrap_or_else(|_| Err(std::io::Error::other("endpoint lookup panicked")));
                if send.send((index, outcome)).is_err() {
                    break;
                }
            }));
        }
        drop(send);

        // Receive into indexed slots, then fold in target order so the
        // observable counters and last-error value retain their old ordering.
        let mut outcomes: Vec<Option<std::io::Result<Vec<SocketAddr>>>> =
            (0..targets.len()).map(|_| None).collect();
        for _ in 0..targets.len() {
            let (index, outcome) = receive
                .recv()
                .expect("endpoint lookup workers stopped before completing the pass");
            outcomes[index] = Some(outcome);
        }
        for handle in handles {
            handle
                .join()
                .expect("endpoint lookup worker panicked outside the lookup");
        }

        let mut held = 0;
        for ((pubkey, host_port), outcome) in targets.iter().zip(outcomes) {
            if apply_resolution(
                shared,
                pubkey,
                host_port,
                socket_is_v6,
                outcome.expect("each endpoint lookup must return one outcome"),
            ) {
                held += 1;
            }
        }
        held
    })
}

fn set_last_error(shared: &ResolverShared, msg: String) {
    if let Ok(mut slot) = shared.telemetry.last_error.lock() {
        *slot = Some(msg);
    }
}

fn resolver_thread(
    shared: Arc<ResolverShared>,
    targets: Vec<([u8; 32], String)>,
    socket_is_v6: bool,
) {
    while !shared.stop.load(Ordering::Relaxed) {
        let held = resolve_once(&shared, &targets, socket_is_v6);
        // Fast cadence while any peer still has no address at all: that
        // interval is tunnel downtime, not staleness.
        let wait_secs = if held < targets.len() {
            WG_ENDPOINT_RETRY_INTERVAL_SECS
        } else {
            WG_ENDPOINT_RESOLVE_INTERVAL_SECS
        };
        let slices = (wait_secs * 1000) / STOP_POLL_SLICE_MS;
        for _ in 0..slices {
            if shared.stop.load(Ordering::Relaxed) {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(STOP_POLL_SLICE_MS));
        }
    }
}

#[cfg(test)]
#[path = "endpoint_resolver_tests.rs"]
mod endpoint_resolver_tests;
