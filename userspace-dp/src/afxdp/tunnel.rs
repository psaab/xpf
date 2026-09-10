use super::*;

/// #2412: poll(2) cap for the GRE local-origin loop. With the eventfd
/// wake below, idle wakeups are NOT paced by this cap — the loop blocks
/// in poll until the TUN fd is readable, the delivery eventfd is
/// signalled (peer-decap inbound delivery), or stop is requested. The
/// cap is only a liveness backstop against a missed wake (the eventfd
/// signal is best-effort on the cold reinjection path) and bounds the
/// worst-case stop latency if the stop-wake write were ever to fail. At
/// 250ms a wholly idle tunnel wakes ~4×/sec instead of ~1000×/sec — the
/// #2412 busy-poll is eliminated without depending solely on the wake.
const LOCAL_TUNNEL_POLL_CAP_MS: i32 = 250;

/// #2412: an eventfd-backed wake shared between the GRE local-origin
/// delivery producers (worker slow path), the coordinator stop path,
/// and the local-origin loop's poll(2). Replaces the 1ms busy-poll: the
/// loop blocks in poll on {TUN fd, this eventfd} and wakes only when
/// there is work (a TUN read, a queued delivery, or shutdown) instead of
/// spinning at 1000 wakeups/sec/tunnel.
///
/// EFD_NONBLOCK so `drain()` cannot block the loop; the counter
/// semantics coalesce N signals into one readable event, so a single
/// drain after the poll wake suffices to clear it (the loop then drains
/// the mpsc queue to completion regardless of the counter value).
pub(crate) struct TunnelWake {
    fd: std::os::fd::OwnedFd,
}

impl TunnelWake {
    pub(crate) fn new() -> io::Result<Self> {
        // SAFETY: eventfd(2) with valid flags returns a new fd or -1.
        let raw = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        use std::os::fd::FromRawFd;
        // SAFETY: `raw` is a fresh, owned, valid fd from eventfd(2).
        let fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(raw) };
        Ok(Self { fd })
    }

    pub(crate) fn raw_fd(&self) -> c_int {
        self.fd.as_raw_fd()
    }

    /// Wake the poll(2) waiter. Best-effort: a full counter (EAGAIN, the
    /// only failure short of a closed fd) still leaves the eventfd
    /// readable, so the waiter wakes anyway. Called from the worker slow
    /// path (cold branch) and the stop path.
    pub(crate) fn signal(&self) {
        let val: u64 = 1;
        // SAFETY: writing 8 bytes from a u64 to the owned eventfd.
        unsafe {
            libc::write(
                self.fd.as_raw_fd(),
                &val as *const u64 as *const c_void,
                std::mem::size_of::<u64>(),
            );
        }
    }

    /// Clear the readable state after a poll wake. EFD_NONBLOCK, so an
    /// empty counter returns EAGAIN — harmless.
    fn drain(&self) {
        let mut val: u64 = 0;
        // SAFETY: reading 8 bytes into a u64 from the owned eventfd.
        unsafe {
            libc::read(
                self.fd.as_raw_fd(),
                &mut val as *mut u64 as *mut c_void,
                std::mem::size_of::<u64>(),
            );
        }
    }
}

/// #2412: delivery endpoint for one GRE local-origin thread — the mpsc
/// sender the worker slow path pushes decapsulated inbound packets into,
/// paired with the eventfd that wakes the thread's poll(2). The pair is
/// stored in `local_tunnel_deliveries` so the producer can both enqueue
/// AND wake in the same cold branch.
#[derive(Clone)]
pub(crate) struct LocalTunnelDelivery {
    pub(in crate::afxdp) tx: SyncSender<Vec<u8>>,
    pub(in crate::afxdp) wake: Arc<TunnelWake>,
}

impl LocalTunnelDelivery {
    /// Enqueue a delivery and wake the loop. Mirrors `SyncSender::try_send`
    /// so the worker slow path keeps its Full/Disconnected handling; the
    /// eventfd is signalled ONLY on a successful enqueue (no point waking
    /// for a packet that was dropped).
    pub(in crate::afxdp) fn try_send(
        &self,
        packet: Vec<u8>,
    ) -> Result<(), std::sync::mpsc::TrySendError<Vec<u8>>> {
        self.tx.try_send(packet)?;
        self.wake.signal();
        Ok(())
    }
}

const LOCAL_TUNNEL_SESSION_PRUNE_INTERVAL_NS: u64 = 5_000_000_000;
const LOCAL_TUNNEL_SESSION_STALE_NS: u64 = 30_000_000_000;
const LOCAL_TUNNEL_SESSION_PRUNE_THRESHOLD: usize = 4096;

fn local_tunnel_io_error_is_fatal(err: &io::Error) -> bool {
    matches!(
        err.raw_os_error(),
        Some(code)
            if code == libc::EINVAL
                || code == libc::EBADF
                || code == libc::EBADFD
                || code == libc::ENODEV
                || code == libc::ENXIO
    )
}

/// #1881: fatal-errno predicate for TUN delivery WRITES. Differs from
/// the read predicate in exactly one errno: `EINVAL` on a TUN write
/// means the kernel rejected THAT PACKET (malformed/mis-sliced inner
/// — e.g. the off-by-VLAN local-delivery extraction observed live on
/// the loss cluster), a per-packet condition. Treating it as fatal
/// let ONE bad delivery kill the local-origin thread — permanently on
/// pre-#1881 master (no respawn), and as a 15s tombstone/respawn churn
/// loop with the #1881 liveness (every peer keepalive reply re-killed
/// the fresh thread). On READS, `EINVAL` remains fatal (fd/iface-level
/// condition). `EBADF`/`EBADFD`/`ENODEV`/`ENXIO` stay fatal in both
/// directions — the fd is genuinely dead (anchor deleted/recreated).
fn local_tunnel_write_error_is_fatal(err: &io::Error) -> bool {
    matches!(
        err.raw_os_error(),
        Some(code)
            if code == libc::EBADF
                || code == libc::EBADFD
                || code == libc::ENODEV
                || code == libc::ENXIO
    )
}

pub(super) enum LocalTunnelDrainOutcome {
    /// `stop` observed — the loop must return so the coordinator's
    /// join is bounded even under a busy delivery producer (#1881,
    /// Codex plan r1 MAJOR 2: the pre-#1881 drain ran to
    /// `Empty`/`Disconnected` only, and the queue is deep enough for
    /// a producer to keep it non-empty indefinitely).
    Stopped,
    /// Fatal TUN write errno — the loop must exit (finished sweep
    /// tombstones the entry; liveness respawns it with a fresh fd).
    FatalIo,
    /// Queue drained (or one non-fatal write error) — proceed to the
    /// TUN read.
    Drained,
}

/// #1881: one bounded delivery-drain chunk, extracted from
/// `local_tunnel_source_loop` so the stop-latency contract is unit
/// testable (plan §9 test 4).
///
/// #2438: writes go through `write_packet`, a single-`write()`
/// whole-packet seam (the production caller passes
/// `crate::slowpath::write_packet_nonblocking`), NOT std
/// `Write::write_all`. The TUN fd is `O_NONBLOCK`, and `write_all`'s
/// stream-resume loop would re-write `buf[n..]` after a short count —
/// injecting the remainder as a SECOND, malformed packet (the #2407
/// corruption class). The seam retries the WHOLE packet on
/// WouldBlock/EINTR and drops (Err, non-fatal errno) on a genuine
/// partial, so this drain's fatal-errno classification is unchanged.
pub(super) fn drain_local_tunnel_deliveries(
    write_packet: &mut impl FnMut(&[u8]) -> io::Result<()>,
    delivery_rx: &Receiver<Vec<u8>>,
    stop: &AtomicBool,
    tunnel_name: &str,
    recent_exceptions: &Arc<Mutex<ExceptionEventRing>>,
) -> LocalTunnelDrainOutcome {
    loop {
        if stop.load(Ordering::Relaxed) {
            return LocalTunnelDrainOutcome::Stopped;
        }
        match delivery_rx.try_recv() {
            Ok(packet) => {
                if let Err(err) = write_packet(&packet) {
                    record_local_tunnel_exception(
                        recent_exceptions,
                        tunnel_name,
                        format!("write_local_tunnel_delivery:{err}"),
                    );
                    if local_tunnel_write_error_is_fatal(&err) {
                        return LocalTunnelDrainOutcome::FatalIo;
                    }
                    return LocalTunnelDrainOutcome::Drained;
                }
            }
            Err(TryRecvError::Empty) | Err(TryRecvError::Disconnected) => {
                return LocalTunnelDrainOutcome::Drained;
            }
        }
    }
}

/// #1881 D.1b: whether the loaded forwarding state still describes
/// the tunnel this thread is attached to. The TUN fd is bound to the
/// netdev captured at spawn — if the endpoint is gone, no longer a
/// GRE mode, or re-attached to a different ifindex/name, this thread
/// must PARK (drop without building) until the coordinator prune
/// joins it. Recomputed ONLY when the forwarding Arc rotates, so the
/// steady-state per-packet cost is zero. This is the correctness
/// boundary for the store-to-join window in
/// `refresh_runtime_snapshot_inner`: the #1873 owner check compares
/// the endpoint row against a resolution derived from the SAME
/// loaded state, so it cannot detect a thread reading the wrong TUN.
pub(super) fn endpoint_attachment_valid(
    forwarding: &ForwardingState,
    tunnel_endpoint_id: u16,
    spawned_logical_ifindex: i32,
    spawned_tunnel_name: &str,
) -> bool {
    let Some(endpoint) = forwarding.tunnel_endpoints.get(&tunnel_endpoint_id) else {
        return false;
    };
    if endpoint.mode != "gre" && endpoint.mode != "ip6gre" {
        return false;
    }
    endpoint.logical_ifindex == spawned_logical_ifindex
        && forwarding
            .ifindex_to_name
            .get(&endpoint.logical_ifindex)
            .is_some_and(|name| name == spawned_tunnel_name)
}

// Spawn plumbing: the shared state this thread reads is threaded in by
// value/Arc at spawn (#1881). #2412 added the `wake` eventfd (16→17).
#[allow(clippy::too_many_arguments)]
pub(super) fn local_tunnel_source_loop(
    tunnel_name: String,
    tunnel_endpoint_id: u16,
    spawned_logical_ifindex: i32,
    shared_runtime: RuntimeViewReader,
    ha_state: Arc<ArcSwap<BTreeMap<i32, HAGroupRuntime>>>,
    dynamic_neighbors: Arc<ShardedNeighborMap>,
    live: BTreeMap<u32, Arc<BindingLiveState>>,
    identities: BTreeMap<u32, BindingIdentity>,
    shared_sessions: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: SharedSessionOwnerRgIndexes,
    // #6471: node-shared live-IKE-exchange table — seeded when the firewall
    // INITIATES IKE through this tunnel so the peer's replies are recognized
    // as established at Stage 11 (see `build_local_origin_tunnel_tx_request`).
    ike_exchanges: crate::afxdp::forwarding::SharedIkeExchangeTable,
    worker_commands: Vec<Arc<Mutex<VecDeque<WorkerCommand>>>>,
    delivery_rx: Receiver<Vec<u8>>,
    // #2412: the eventfd this thread blocks on in poll(2) alongside the
    // TUN fd. Producers (worker slow path) and the stop path signal it
    // to wake the loop, replacing the 1ms busy-poll.
    wake: Arc<TunnelWake>,
    recent_exceptions: Arc<Mutex<ExceptionEventRing>>,
    stop: Arc<AtomicBool>,
) {
    let mut tun = match open_tun(&tunnel_name) {
        Ok((file, _actual_name)) => file,
        Err(err) => {
            record_local_tunnel_exception(&recent_exceptions, &tunnel_name, err);
            return;
        }
    };
    if let Err(err) = set_fd_nonblocking(tun.as_raw_fd()) {
        record_local_tunnel_exception(&recent_exceptions, &tunnel_name, err);
        return;
    }

    let mut packet = vec![0u8; 65_536];
    let mut next_slot = 0usize;
    let mut local_sessions = FastMap::<SessionKey, u64>::default();
    let mut local_sessions_last_prune_ns = 0u64;
    let tun_fd = tun.as_raw_fd();
    let wake_fd = wake.raw_fd();
    // #1881 D.1: track the worker-visible forwarding ArcSwap instead
    // of a spawn-time clone. ONE load point per outer iteration (the
    // #1188 ptr_eq short-circuit); the same Arc is used for the WHOLE
    // packet build below, so resolution, session synthesis, CoS, and
    // encap are coherent by construction. Cost honesty: this loop is
    // syscall-paced (read(2) drained per iteration, then a blocking
    // poll(2) when idle — #2412 replaced the 1ms busy-poll, single-digit
    // pps workload) — a drained read pass IS the batch, so the per-BATCH
    // ArcSwap rule holds and the AF_XDP worker hot path is untouched.
    //
    // #6592: this thread needs only the forwarding half of the published
    // `RuntimeView` (it builds and encapsulates local-origin packets; it does
    // not match shim generation stamps), so it reads through
    // `load_forwarding_if_changed`. A validation-only publish rotates the view
    // but not the inner forwarding Arc, so it correctly sees no change here.
    let mut forwarding: Arc<ForwardingState> = shared_runtime.load().forwarding().clone();
    let mut endpoint_attached = endpoint_attachment_valid(
        &forwarding,
        tunnel_endpoint_id,
        spawned_logical_ifindex,
        &tunnel_name,
    );
    while !stop.load(Ordering::Relaxed) {
        if let Some(new_forwarding) =
            super::types::load_forwarding_if_changed(&forwarding, &shared_runtime)
        {
            forwarding = new_forwarding;
            endpoint_attached = endpoint_attachment_valid(
                &forwarding,
                tunnel_endpoint_id,
                spawned_logical_ifindex,
                &tunnel_name,
            );
        }
        // #1881 (AGY plan r1): ONE HA-state load per iteration, passed
        // down so resolution enforcement and reverse-entry synthesis
        // see the same map. Cross-source (forwarding↔HA) atomicity is
        // not claimed — they are published independently by design,
        // matching the worker path.
        let ha_runtime = ha_state.load();
        // #2438: deliver each queued packet with a single-write,
        // whole-packet seam (non-blocking TUN fd) — never std
        // `Write::write_all`, whose short-count resume would corrupt the
        // device. `tun_fd` is a plain i32 copy, so this closure does not
        // borrow `tun` (the read below still uses `tun`).
        let mut write_packet = |buf: &[u8]| crate::slowpath::write_packet_nonblocking(tun_fd, buf);
        match drain_local_tunnel_deliveries(
            &mut write_packet,
            &delivery_rx,
            &stop,
            &tunnel_name,
            &recent_exceptions,
        ) {
            LocalTunnelDrainOutcome::Stopped | LocalTunnelDrainOutcome::FatalIo => return,
            LocalTunnelDrainOutcome::Drained => {}
        }
        // #2412: drain every currently-readable TUN packet, then block
        // in poll(2) below. The old code read ONE packet per outer
        // iteration and slept 1ms when idle; draining here keeps the TUN
        // from backing up under a burst and makes the poll the single
        // idle wait point.
        let mut wait = LocalTunnelWait::Block;
        loop {
            if stop.load(Ordering::Relaxed) {
                return;
            }
            match tun.read(&mut packet) {
                // EOF on a TUN fd does not occur in practice; treat it as
                // "nothing more right now" and fall through to poll.
                Ok(0) => break,
                Ok(len) => {
                    // #1881 D.1b: parked — the loaded state no longer
                    // describes this thread's TUN attachment (endpoint
                    // removed, mode flipped, or reattached). Drop without
                    // building; the coordinator prune will join us. Keep
                    // reading so the TUN never backs up.
                    if !endpoint_attached {
                        debug_log!(
                            "LOCAL_TUNNEL[{}]: drop endpoint={} reason=local_tunnel_unattached",
                            tunnel_name,
                            tunnel_endpoint_id
                        );
                        continue;
                    }
                    let packet = &packet[..len];
                    match build_local_origin_tunnel_tx_request(
                        packet,
                        tunnel_endpoint_id,
                        &forwarding,
                        ha_runtime.as_ref(),
                        &dynamic_neighbors,
                        &ike_exchanges,
                    ) {
                        Ok(plan) => {
                            maybe_enqueue_local_tunnel_session(
                                &shared_sessions,
                                &shared_nat_sessions,
                                &shared_forward_wire_sessions,
                                &shared_owner_rg_indexes,
                                &worker_commands,
                                &mut local_sessions,
                                &mut local_sessions_last_prune_ns,
                                &plan,
                            );
                            if let Some(target_live) = select_live_binding_for_ifindex(
                                &identities,
                                &live,
                                plan.tx_ifindex,
                                next_slot,
                            ) {
                                next_slot = next_slot.wrapping_add(1);
                                if let Err(err) = target_live.enqueue_tx(plan.tx_request) {
                                    record_local_tunnel_exception(
                                        &recent_exceptions,
                                        &tunnel_name,
                                        format!("enqueue_local_tunnel_tx:{err}"),
                                    );
                                }
                            } else {
                                record_local_tunnel_exception(
                                    &recent_exceptions,
                                    &tunnel_name,
                                    format!("no_live_binding_for_tx_ifindex:{}", plan.tx_ifindex),
                                );
                            }
                        }
                        Err(err) => {
                            #[cfg(not(feature = "debug-log"))]
                            let _ = &err;
                            debug_log!(
                                "LOCAL_TUNNEL[{}]: drop endpoint={} reason={}",
                                tunnel_name,
                                tunnel_endpoint_id,
                                err
                            );
                        }
                    }
                }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => break,
                Err(err) => {
                    record_local_tunnel_exception(
                        &recent_exceptions,
                        &tunnel_name,
                        format!("read_local_tunnel:{err}"),
                    );
                    if local_tunnel_io_error_is_fatal(&err) {
                        return;
                    }
                    // Transient read error: don't hot-spin re-reading the
                    // same broken fd. Back off via a short poll instead of
                    // blocking for the full cap, then re-evaluate.
                    wait = LocalTunnelWait::Backoff;
                    break;
                }
            }
        }
        if stop.load(Ordering::Relaxed) {
            return;
        }
        // #2412: idle — block in poll(2) on {TUN readable, delivery
        // eventfd} until there is work or the cap elapses. The stop
        // path signals the eventfd so shutdown is observed immediately,
        // not after the cap. POLLERR/POLLHUP/POLLNVAL on the TUN are
        // fatal (device destroyed/downed — poll would return instantly
        // forever); the tombstone/respawn path recovers.
        match wait_for_local_tunnel_event(tun_fd, wake_fd, &wake, wait) {
            LocalTunnelPollOutcome::Ready | LocalTunnelPollOutcome::Idle => {}
            LocalTunnelPollOutcome::Fatal(reason) => {
                record_local_tunnel_exception(
                    &recent_exceptions,
                    &tunnel_name,
                    format!("poll_local_tunnel:{reason}"),
                );
                return;
            }
        }
    }
}

/// #2412: which poll(2) timeout the idle wait should use.
enum LocalTunnelWait {
    /// Normal idle wait — block up to the poll cap.
    Block,
    /// A transient TUN read error just occurred — wait ~50ms before
    /// re-reading, preserving the pre-#2412 backoff without hot-spinning.
    Backoff,
}

/// #2412: poll(2) wait disposition for the GRE local-origin loop.
enum LocalTunnelPollOutcome {
    /// At least one fd is readable (or EINTR — treat as a wakeup).
    Ready,
    /// Timed out (cap or backoff elapsed) — re-run the loop.
    Idle,
    /// Unrecoverable TUN fd state — exit the thread (tombstone respawn
    /// is the recovery path).
    Fatal(&'static str),
}

/// #2412: block on {TUN readable, delivery eventfd} until work arrives,
/// the stop-wake fires, or the timeout elapses. Replaces the three 1ms /
/// 50ms `thread::sleep` busy-poll sites. The eventfd is drained after a
/// wake so the next poll blocks again instead of returning instantly.
fn wait_for_local_tunnel_event(
    tun_fd: c_int,
    wake_fd: c_int,
    wake: &TunnelWake,
    wait: LocalTunnelWait,
) -> LocalTunnelPollOutcome {
    let timeout_ms = match wait {
        LocalTunnelWait::Block => LOCAL_TUNNEL_POLL_CAP_MS,
        LocalTunnelWait::Backoff => 50,
    };
    let mut fds = [
        libc::pollfd {
            fd: tun_fd,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: wake_fd,
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    // SAFETY: two valid pollfds, count 2.
    let rc = unsafe { libc::poll(fds.as_mut_ptr(), 2, timeout_ms) };
    if rc < 0 {
        let err = io::Error::last_os_error();
        if err.kind() == io::ErrorKind::Interrupted {
            return LocalTunnelPollOutcome::Ready; // spurious — re-run
        }
        return LocalTunnelPollOutcome::Fatal("poll_failed");
    }
    if rc == 0 {
        return LocalTunnelPollOutcome::Idle;
    }
    if fds[0].revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
        return LocalTunnelPollOutcome::Fatal("tun_revents");
    }
    // Coalesced eventfd signals: one drain clears the readable state; the
    // caller drains the mpsc queue to completion regardless of the count.
    if fds[1].revents & libc::POLLIN != 0 {
        wake.drain();
    }
    LocalTunnelPollOutcome::Ready
}

pub(super) fn build_local_origin_tunnel_tx_request(
    packet: &[u8],
    tunnel_endpoint_id: u16,
    forwarding: &ForwardingState,
    ha_runtime: &BTreeMap<i32, HAGroupRuntime>,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    // #6471: seeded for an outbound IKE initiation (see below). Production
    // passes the node-shared table; tests pass a scratch one to assert the
    // seed (or its absence).
    ike_exchanges: &crate::afxdp::forwarding::IkeExchangeTable,
) -> Result<LocalTunnelTxPlan, String> {
    let mut meta = local_origin_packet_meta(packet)
        .ok_or_else(|| "unsupported_local_origin_packet".to_string())?;
    let inner_frame = wrap_raw_ip_packet_for_tunnel(packet, meta.addr_family);
    meta.l3_offset = 14;
    meta.l4_offset = meta.l4_offset.saturating_add(14);
    meta.payload_offset = meta.payload_offset.saturating_add(14);
    // #1881 (AGY plan r1): the caller loads HA state ONCE per loop
    // iteration and passes the map down — resolution enforcement and
    // the reverse-entry synthesis below must see the same HA map.
    let resolution = enforce_ha_resolution_snapshot(
        forwarding,
        ha_runtime,
        monotonic_nanos() / 1_000_000_000,
        resolve_tunnel_forwarding_resolution(
            forwarding,
            Some(dynamic_neighbors),
            tunnel_endpoint_id,
            0,
        ),
    );
    if resolution.disposition != ForwardingDisposition::ForwardCandidate {
        return Err(format!(
            "local_tunnel_resolution:{}",
            resolution.status(None, forwarding).disposition
        ));
    }
    let decision = SessionDecision {
        resolution,
        nat: NatDecision::default(),
    };
    let mut flow = parse_session_flow_from_bytes(&inner_frame, meta)
        .ok_or_else(|| "parse_local_origin_session_flow_failed".to_string())?;
    // #9032: STAMP THE ROUTING DOMAIN. #7160 made `routing_domain` part of
    // session identity and stamped it at what its own comment calls "THE single
    // site that populates `SessionKey.routing_domain` for a received frame"
    // (`poll_descriptor/mod.rs`). This producer never reaches that site: it
    // reads packets off the TUN, outside the AF_XDP descriptor loop, so
    // `parse_session_flow_from_bytes` left the domain at 0 and the session was
    // PUBLISHED under domain 0 — a different identity from the one the same
    // flow gets when it arrives on a wire, on a box with routing instances.
    //
    // The domain is available here and was already being used one line below
    // for `egress_zone_id`: the tunnel's own logical ifindex, resolved into
    // `decision.resolution.egress_ifindex`. There is no ingress interface for a
    // locally-originated packet, so the tunnel's egress interface IS the
    // interface whose routing instance this flow belongs to.
    //
    // `ingress_routing_domain` is the shared lookup rather than a second
    // spelling of the same map probe, so this cannot drift from the wire path;
    // it short-circuits to 0 on `!has_routing_domains`, keeping a deployment
    // with no routing instances bit-identical to pre-#7160.
    flow.forward_key.routing_domain = crate::afxdp::forwarding::ingress_routing_domain(
        forwarding,
        decision.resolution.egress_ifindex,
        0,
        None,
    );
    // #6471: a firewall-INITIATED IKE exchange routed via this tunnel sees
    // its replies arrive on the Stage-11 secondary path (GRE-inner local
    // destination) with the Responder SPI set and NO inbound seed — without
    // this outbound seed the reply would fail the live-exchange lookup and
    // face the host-inbound `ike` gate as a forgery, breaking
    // firewall-initiated tunnels on zones that omit `ike` (the primary path
    // admits such replies via kernel conntrack-established). Only a genuine
    // initiation (all-zero Responder SPI) seeds; the firewall's own later
    // packets in the exchange are ignored here (they already match the seed
    // direction-wise on the return lookup).
    crate::afxdp::forwarding::maybe_seed_local_origin_ike(
        ike_exchanges,
        &inner_frame,
        meta.l4_offset as usize,
        &flow,
        monotonic_nanos(),
    );
    // #921: zone_id is now a u16 field on EgressInterface — direct
    // load, no name round-trip.
    // #6713/#6722: route through the shared resolver rather than open-coding
    // the `egress`-only read, so this site cannot drift from the zone the
    // policy plane adjudicated. `resolve_tunnel_forwarding_resolution` sets
    // `egress_ifindex` to the tunnel's OWN logical ifindex, so this really is
    // asking "what zone is this tunnel in". No behavior change today: the ONLY
    // endpoint types reaching this loop are `gre` and `ip6gre` —
    // `endpoint_attachment_valid` parks the thread for any other mode — and
    // both carry a Junos `tunnel { source destination }` stanza and therefore
    // always have an `egress` row, so the fallback cannot fire. It is the next
    // MAC-less endpoint type admitted to this loop that would otherwise
    // reintroduce #6713 here.
    let zone_id = forwarding.egress_zone_id(decision.resolution.egress_ifindex);
    let bytes = encapsulate_native_gre_frame(&inner_frame, meta, &decision, forwarding)
        .ok_or_else(|| "encapsulate_native_gre_frame_failed".to_string())?;
    let session_entry = SyncedSessionEntry {
        key: flow.forward_key,
        decision,
        metadata: SessionMetadata {
            ingress_zone: zone_id,
            egress_zone: zone_id,
            ingress_ifindex: 0,
            ingress_vlan_id: 0,
            owner_rg_id: owner_rg_for_resolution(forwarding, decision.resolution),
            fabric_ingress: false,
            is_reverse: false,
            nat64_reverse: None,
            // #6224: this is the LOCAL-ORIGIN (host-outbound) GRE encapsulation
            // path — the firewall's own kernel-routed traffic read off the TUN
            // device (`local_tunnel_source_loop`), NOT a peer HA-sync import.
            // `resolve_tunnel_forwarding_resolution` does route/next-hop/neighbor
            // resolution ONLY; no security policy or application term is matched
            // here (Junos runs no security policy on firewall-self-originated
            // traffic). There is therefore no admitting policy/application to
            // source the per-policy `then log` selection, the policy ID, the
            // per-application idle timeout, or the hit-counter handle from.
            // Zeroed policy fields and the global per-protocol idle timeout
            // (`inactivity_timeout_ns: None` -> `session_timeout_ns` falls back
            // to the per-protocol default) are the correct values for
            // self-originated traffic; a per-app timeout would only differ if an
            // admitting application existed, which it does not. The
            // `origin: SessionOrigin::SyncImport` tag below is an install-path
            // plumbing artifact (it reaches the uncapped coordinator-authoritative
            // install path, see session_glue/mod.rs), NOT a peer wire import.
            //
            // (The earlier #2508/#3056/#3227/#3073 comments here mis-described
            // this path as "peer-seeded import ... does not cross the HA wire
            // yet". The real peer-import path — server/helpers.rs — DOES stamp
            // all of these from `SessionSyncRequest` post-#3301; this path is
            // simply not a wire path, so nothing crosses to read.)
            log_session_init: false,
            log_session_close: false,
            policy_id: 0,
            inactivity_timeout_ns: None,
            policy_counter_idx: 0,
            policy_counter: None,
        },
        origin: SessionOrigin::SyncImport,
        protocol: meta.protocol,
        tcp_flags: if meta.protocol == PROTO_TCP {
            extract_tcp_flags_and_window(&inner_frame)
                .map(|(flags, _)| flags)
                .unwrap_or_default()
        } else {
            0
        },
        // Locally decapsulated tunnel session: no peer install generation (#2170).
        generation: 0,
        session_id: 0,
        tcp_close_class: 0,
    };
    let reverse_session_entry = synthesized_synced_reverse_entry(
        forwarding,
        ha_runtime,
        dynamic_neighbors,
        &session_entry,
        monotonic_nanos() / 1_000_000_000,
    );
    let now_ns = monotonic_nanos();
    // #2362 fold B: local tunnel-origin path — the inner-frame L3/L4 offsets in
    // `meta` describe the pre-encap packet, so use the meta-only extra
    // (tcp_flags authoritative; is-fragment / icmp-type under-match on this rare
    // local path rather than risk mis-parsing inner offsets).
    let cos_extra = crate::afxdp::frame::term_match_extra_from_meta(meta.into());
    let cos = resolve_cos_tx_selection_at(
        forwarding,
        decision.resolution.egress_ifindex,
        meta,
        Some(&session_entry.key),
        cos_extra,
        now_ns,
    );
    if cos.drop {
        return Err("local_tunnel_packet_dropped_by_three_color_policer".to_string());
    }
    Ok(LocalTunnelTxPlan {
        tx_ifindex: decision.resolution.tx_ifindex,
        tx_request: TxRequest {
            bytes,
            expected_ports: None,
            expected_addr_family: meta.addr_family,
            expected_protocol: meta.protocol,
            flow_key: Some(session_entry.key.clone()),
            egress_ifindex: decision.resolution.egress_ifindex,
            cos_queue_id: cos.queue_id,
            dscp_rewrite: cos.dscp_rewrite,
            mirror_clone: false,
            enqueue_ns: 0,
        },
        session_entry,
        reverse_session_entry,
    })
}

pub(super) fn local_origin_packet_meta(packet: &[u8]) -> Option<UserspaceDpMeta> {
    let version = packet.first()? >> 4;
    let addr_family = match version {
        4 => libc::AF_INET as u8,
        6 => libc::AF_INET6 as u8,
        _ => return None,
    };
    let (l4_offset, protocol) = packet_rel_l4_offset_and_protocol(packet, addr_family)?;
    Some(UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l4_offset: l4_offset.min(u16::MAX as usize) as u16,
        payload_offset: l4_offset.min(u16::MAX as usize) as u16,
        pkt_len: packet.len().min(u16::MAX as usize) as u16,
        addr_family,
        protocol,
        ..UserspaceDpMeta::default()
    })
}

pub(super) fn wrap_raw_ip_packet_for_tunnel(packet: &[u8], addr_family: u8) -> Vec<u8> {
    let mut frame = vec![0u8; 14 + packet.len()];
    frame[12..14].copy_from_slice(if addr_family as i32 == libc::AF_INET {
        &[0x08, 0x00]
    } else {
        &[0x86, 0xdd]
    });
    frame[14..].copy_from_slice(packet);
    frame
}

pub(super) fn maybe_enqueue_local_tunnel_session(
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: &SharedSessionOwnerRgIndexes,
    worker_commands: &[Arc<Mutex<VecDeque<WorkerCommand>>>],
    local_sessions: &mut FastMap<SessionKey, u64>,
    local_sessions_last_prune_ns: &mut u64,
    plan: &LocalTunnelTxPlan,
) {
    let now_ns = monotonic_nanos();
    prune_local_tunnel_sessions(local_sessions, local_sessions_last_prune_ns, now_ns);
    let entry = &plan.session_entry;
    let refresh_after_ns = if matches!(entry.protocol, PROTO_TCP) {
        5_000_000_000
    } else {
        1_000_000_000
    };
    if matches!(
        local_sessions.get(&entry.key),
        Some(last) if now_ns.saturating_sub(*last) < refresh_after_ns
    ) {
        return;
    }
    local_sessions.insert(entry.key.clone(), now_ns);
    publish_shared_session(
        shared_sessions,
        shared_nat_sessions,
        shared_forward_wire_sessions,
        shared_owner_rg_indexes,
        entry,
    );
    if let Some(reverse) = &plan.reverse_session_entry {
        publish_shared_session(
            shared_sessions,
            shared_nat_sessions,
            shared_forward_wire_sessions,
            shared_owner_rg_indexes,
            reverse,
        );
    }
    for pending in worker_commands {
        // #1807: recover-and-push — `if let Ok` silently DROPPED the
        // local-tunnel UpsertLocal pair for a poisoned worker queue. A
        // panic between the forward and reverse pushes leaves the
        // committed prefix (forward only); commands are self-contained.
        {
            let mut pending = worker_queue::lock_recover(pending);
            worker_queue::push_bounded(&mut pending, WorkerCommand::UpsertLocal(entry.clone()));
            if let Some(reverse) = &plan.reverse_session_entry {
                worker_queue::push_bounded(&mut pending, WorkerCommand::UpsertLocal(reverse.clone()));
            }
        }
    }
    wait_for_local_tunnel_session_install(worker_commands, now_ns + 1_000_000);
}

fn prune_local_tunnel_sessions(
    local_sessions: &mut FastMap<SessionKey, u64>,
    last_prune_ns: &mut u64,
    now_ns: u64,
) {
    if local_sessions.len() < LOCAL_TUNNEL_SESSION_PRUNE_THRESHOLD
        || now_ns.saturating_sub(*last_prune_ns) < LOCAL_TUNNEL_SESSION_PRUNE_INTERVAL_NS
    {
        return;
    }
    let cutoff_ns = now_ns.saturating_sub(LOCAL_TUNNEL_SESSION_STALE_NS);
    local_sessions.retain(|_, seen_ns| *seen_ns >= cutoff_ns);
    *last_prune_ns = now_ns;
}

pub(super) fn wait_for_local_tunnel_session_install(
    worker_commands: &[Arc<Mutex<VecDeque<WorkerCommand>>>],
    deadline_ns: u64,
) {
    while monotonic_nanos() < deadline_ns {
        // #1807: a recovered (previously poisoned) guard is read as a
        // normal queue — poison used to read as "not drained" and spun
        // this wait until its deadline.
        let all_drained = worker_commands
            .iter()
            .all(|pending| worker_queue::lock_recover(pending).is_empty());
        if all_drained {
            break;
        }
        std::hint::spin_loop();
        thread::sleep(Duration::from_micros(50));
    }
}

pub(super) fn select_live_binding_for_ifindex(
    identities: &BTreeMap<u32, BindingIdentity>,
    live: &BTreeMap<u32, Arc<BindingLiveState>>,
    tx_ifindex: i32,
    next_slot: usize,
) -> Option<Arc<BindingLiveState>> {
    let mut candidate_count = 0usize;
    for identity in identities.values() {
        if identity.ifindex != tx_ifindex {
            continue;
        }
        if let Some(live_state) = live.get(&identity.slot) {
            if live_state.bound.load(Ordering::Relaxed) {
                candidate_count += 1;
            }
        }
    }
    if candidate_count == 0 {
        return None;
    }
    let target_index = next_slot % candidate_count;
    let mut current_index = 0usize;
    for identity in identities.values() {
        if identity.ifindex != tx_ifindex {
            continue;
        }
        if let Some(live_state) = live.get(&identity.slot) {
            if live_state.bound.load(Ordering::Relaxed) {
                if current_index == target_index {
                    return Some(live_state.clone());
                }
                current_index += 1;
            }
        }
    }
    None
}

pub(super) fn set_fd_nonblocking(fd: c_int) -> Result<(), String> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(format!(
            "fcntl(F_GETFL) failed: {}",
            io::Error::last_os_error()
        ));
    }
    let rc = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if rc < 0 {
        return Err(format!(
            "fcntl(F_SETFL,O_NONBLOCK) failed: {}",
            io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[cfg(test)]
#[path = "tunnel_tests.rs"]
mod tests;

pub(super) fn record_local_tunnel_exception(
    recent_exceptions: &Arc<Mutex<ExceptionEventRing>>,
    tunnel_name: &str,
    reason: String,
) {
    if let Ok(mut recent) = recent_exceptions.lock() {
        push_recent_exception(&mut recent, control_notice_event(tunnel_name, reason));
    }
}
