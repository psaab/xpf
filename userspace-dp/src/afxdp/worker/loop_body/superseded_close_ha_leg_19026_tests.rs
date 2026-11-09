// #19026 (Codex R16 F1): a parked Close must not delete its own tuple's
// replacement on the HA peer.
//
// Parking (close_barrier.rs) lets RX run while an old Close(A) waits for its
// tuple permit. Once the permit frees, RX on the SAME worker can admit a
// replacement B on the exact key, and the post-RX export flushes Open(B)
// before the next tick retries Close(A). The binary HA Close (type 2)
// carries no session id, and the daemon's id-conditional peer delete exists
// only for a stated routing domain (`queueDeltaSink.deleteV4/V6`), so in
// routing domain 0 an HA Close for that key after Open(B) is a bare delete of
// B on the peer.
//
// These cells drive ONE worker through the production paths: the expiry and
// the barrier in `run_session_housekeeping`, with the loop's REAL flush
// (`flush_session_deltas_loop`, which delivers HA and RT_FLOW frames on a
// connected event stream) as its flush closure, and the same real flush for
// the post-RX export of the replacement's Open. "HA frames" are the type-1
// Open and type-2 Close session-sync frames DELIVERED for the tuple;
// `rt_flow_closes` counts the type-14 RT_FLOW SESSION_CLOSE frames carrying a
// session's stable id (payload [152:160]).
//
// What these cells do NOT claim: RT_FLOW exactly-once for a session with
// several copies. The `== 1` RT_FLOW assertions below hold because the
// session here has ONE copy on ONE worker. On this branch a restored
// `SharedPromote` session still has a copy on every worker, and each copy
// still closes A at its own idle deadline, as on master. So Codex's F1 probe
// on the three-worker restore fixture delivers only Open(B) on the HA stream
// (the F1 property), but 3 RT_FLOW Closes for A, one per copy. One Close per
// restored session is Part 2, #19063.

use super::*;
use crate::afxdp::testfx::{test_forwarding_state_split_rgs, test_metadata, test_resolution};
use crate::protocol::SessionDeltaInfo;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::AtomicU32;

const SEC: u64 = 1_000_000_000;

fn f1_key(src_port: u16, routing_domain: u32) -> SessionKey {
    SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_UDP,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 63, 107)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 212)),
        src_port,
        dst_port: 5201,
        discriminator: Default::default(),
        routing_domain,
    }
}

fn f1_decision() -> SessionDecision {
    SessionDecision {
        resolution: test_resolution(),
        nat: crate::nat::NatDecision::default(),
        install_table_domain: 0,
        install_table_check: 0,
    }
}

fn f1_metadata() -> SessionMetadata {
    let mut metadata = test_metadata();
    metadata.inactivity_timeout_ns = Some(60 * SEC);
    metadata
}

fn ha_at(now_ns: u64) -> BTreeMap<i32, HAGroupRuntime> {
    let now_secs = now_ns / SEC;
    let mut ha = BTreeMap::new();
    for rg in [1, 2] {
        ha.insert(
            rg,
            HAGroupRuntime {
                active: true,
                watchdog_timestamp: now_secs,
                lease: HAGroupRuntime::active_lease_until(now_secs, now_secs),
            },
        );
    }
    ha
}

/// One worker with the loop's real flush and a connected event stream.
struct F1Worker {
    table: SessionTable,
    queue: Arc<Mutex<VecDeque<WorkerCommand>>>,
    barrier: super::close_barrier::ClosePermitBarrier,
    overflow: Vec<SessionDelta>,
    recycles: Vec<(u32, u64)>,
    wedged: bool,
    shared_sessions: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_wire: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    indexes: SharedSessionOwnerRgIndexes,
    recent: Arc<Mutex<VecDeque<SessionDeltaInfo>>>,
    event_stream: Option<crate::event_stream::EventStreamWorkerHandle>,
    event_rx: std::sync::mpsc::Receiver<crate::event_stream::codec::EventFrame>,
    frames: Vec<crate::event_stream::codec::EventFrame>,
    runtime: RuntimeViewChannel,
    rg_epochs: [AtomicU32; crate::afxdp::flow_cache::MAX_RG_EPOCHS],
    pptp: crate::session::pptp_control::PptpControlInbox,
    forwarding: ForwardingState,
}

impl F1Worker {
    fn new() -> Self {
        let mut table = SessionTable::new();
        table.set_session_id_namespace(0, 0);
        let (event_handle, event_rx) = crate::event_stream::test_worker_handle_connected(
            1 << 16,
            crate::event_stream::DataplaneEventRateLimitConfig {
                events_per_second: 0,
                burst: 0,
                session_close_events_per_second: 0,
                session_close_burst: 0,
                session_create_events_per_second: 0,
                session_create_burst: 0,
            },
        );
        Self {
            table,
            queue: Arc::new(Mutex::new(VecDeque::new())),
            barrier: Default::default(),
            overflow: Vec::new(),
            recycles: Vec::new(),
            wedged: false,
            shared_sessions: Arc::new(Mutex::new(FastMap::default())),
            shared_nat: Arc::new(Mutex::new(FastMap::default())),
            shared_wire: Arc::new(Mutex::new(FastMap::default())),
            indexes: SharedSessionOwnerRgIndexes::default(),
            recent: Arc::new(Mutex::new(VecDeque::new())),
            event_stream: Some(event_handle),
            event_rx,
            frames: Vec::new(),
            runtime: RuntimeViewChannel::default(),
            rg_epochs: std::array::from_fn(|_| AtomicU32::new(0)),
            pptp: crate::session::pptp_control::PptpControlInbox::default(),
            forwarding: test_forwarding_state_split_rgs(),
        }
    }

    fn publish(&self, entry: &SyncedSessionEntry) {
        crate::afxdp::shared_ops::publish_shared_session(
            &self.shared_sessions,
            &self.shared_nat,
            &self.shared_wire,
            &self.indexes,
            entry,
        );
    }

    /// Install a local session on this worker and publish it, as the
    /// production install does. Returns its session id.
    fn install(&mut self, key: &SessionKey, now_ns: u64) -> u64 {
        assert!(
            self.table.install_with_protocol_with_origin(
                key.clone(),
                f1_decision(),
                f1_metadata(),
                SessionOrigin::ForwardFlow,
                now_ns,
                PROTO_UDP,
                0,
            ),
            "FIXTURE: the session installs"
        );
        let entry = self
            .table
            .synced_entry_for(key)
            .expect("FIXTURE: installed row");
        self.publish(&entry);
        entry.session_id
    }

    /// The loop's real flush of `deltas` (the closure `worker_loop` builds).
    fn flush(&mut self, deltas: &[SessionDelta]) {
        let by_id: BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>> =
            [(0u32, self.queue.clone())].into_iter().collect();
        let runtime = self.runtime.reader();
        super::flush_session_deltas_loop(
            &mut self.table,
            &[],
            SteeringMap::unshared_for_test(-1),
            -1,
            -1,
            &self.shared_sessions,
            &self.shared_nat,
            &self.shared_wire,
            &self.indexes,
            &self.recent,
            &[],
            &by_id,
            &self.event_stream,
            &self.forwarding,
            &runtime,
            &mut self.wedged,
            0,
            deltas,
        );
    }

    /// The post-RX export slice's ordinary ring drain and flush (it does not
    /// see parked work).
    fn export_ring(&mut self) -> Vec<SessionDelta> {
        let deltas = self.table.drain_deltas(256);
        self.flush(&deltas);
        deltas
    }

    /// One worker tick's housekeeping, flushing through the real flush.
    /// Returns `true` when the loop would skip RX this tick.
    fn tick(&mut self, now_ns: u64) -> bool {
        let Self {
            table,
            queue,
            barrier,
            overflow,
            recycles,
            wedged,
            shared_sessions,
            shared_nat,
            shared_wire,
            indexes,
            recent,
            event_stream,
            runtime,
            rg_epochs,
            pptp,
            forwarding,
            ..
        } = self;
        let ha = ha_at(now_ns);
        let by_id: BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>> =
            [(0u32, queue.clone())].into_iter().collect();
        let command_queues = crate::afxdp::types::WorkerCommandQueues::new(by_id.clone());
        let shared_runtime = runtime.reader();
        let peers: Vec<Arc<Mutex<VecDeque<WorkerCommand>>>> = Vec::new();
        let mut flush_deltas = |sessions: &mut SessionTable,
                                bindings: &mut [BindingWorker],
                                wedged: &mut bool,
                                deltas: &[SessionDelta]| {
            super::flush_session_deltas_loop(
                sessions,
                bindings,
                SteeringMap::unshared_for_test(-1),
                -1,
                -1,
                shared_sessions,
                shared_nat,
                shared_wire,
                indexes,
                recent,
                &peers,
                &by_id,
                event_stream,
                forwarding,
                &shared_runtime,
                wedged,
                0,
                deltas,
            );
        };
        run_session_housekeeping(
            table,
            &mut Vec::new(),
            &WorkerBindingLookup::default(),
            forwarding,
            &ha,
            now_ns,
            now_ns / SEC,
            rg_epochs,
            SteeringMap::unshared_for_test(-1),
            -1,
            -1,
            0,
            &command_queues,
            pptp,
            Some(&*queue),
            &peers,
            shared_sessions,
            shared_nat,
            shared_wire,
            indexes,
            &shared_runtime,
            wedged,
            recycles,
            overflow,
            barrier,
            &mut flush_deltas,
        )
    }

    fn drain_frames(&mut self) {
        while let Ok(frame) = self.event_rx.try_recv() {
            self.frames.push(frame);
        }
    }

    /// Delivered HA session-sync frame types (1 = Open, 2 = Close) for
    /// `key`'s tuple, in order.
    fn ha_frames(&mut self, key: &SessionKey) -> Vec<u8> {
        self.drain_frames();
        let header = crate::event_stream::codec::FRAME_HEADER_SIZE;
        self.frames
            .iter()
            .map(|frame| frame.as_bytes())
            .filter(|bytes| {
                (bytes[4] == crate::event_stream::codec::MSG_SESSION_OPEN
                    || bytes[4] == crate::event_stream::codec::MSG_SESSION_CLOSE)
                    && bytes.len() >= header + 6
                    && bytes[header + 1] == key.protocol
                    && u16::from_le_bytes([bytes[header + 2], bytes[header + 3]]) == key.src_port
                    && u16::from_le_bytes([bytes[header + 4], bytes[header + 5]]) == key.dst_port
            })
            .map(|bytes| bytes[4])
            .collect()
    }

    /// Delivered RT_FLOW SESSION_CLOSE frames (type 14) for `session_id`.
    fn rt_flow_closes(&mut self, session_id: u64) -> usize {
        self.drain_frames();
        let at = crate::event_stream::codec::FRAME_HEADER_SIZE + 152;
        self.frames
            .iter()
            .map(|frame| frame.as_bytes())
            .filter(|bytes| {
                bytes.len() >= at + 8
                    && bytes[4] == crate::event_stream::codec::MSG_SESSION_CLOSE_RT_FLOW
                    && u64::from_le_bytes(bytes[at..at + 8].try_into().expect("8 bytes"))
                        == session_id
            })
            .count()
    }

    fn shared_id(&self, key: &SessionKey) -> Option<u64> {
        crate::afxdp::shared_ops::lock_shared_recover(&self.shared_sessions)
            .get(key)
            .map(|entry| entry.session_id)
    }
}

/// Codex R16 F1's schedule on one worker. Session A idles out while another
/// holder has its tuple permit; its Close parks at the RX bound. The permit
/// frees; if `replace`, RX on this SAME worker admits B on the exact key and
/// the post-RX export flushes Open(B); then the next tick retries Close(A).
/// Returns (HA frame types for the key since the park, A's RT_FLOW Closes,
/// the shared row's id, A's id, B's id or 0).
fn parked_close_then_same_worker_replacement(
    src_port: u16,
    replace: bool,
) -> (Vec<u8>, usize, Option<u64>, u64, u64) {
    let mut w = F1Worker::new();
    let key = f1_key(src_port, 0);
    // The real monotonic clock, as the worker loop's own `loop_now_ns`.
    let t0 = crate::afxdp::neighbor::monotonic_nanos();
    let old_id = w.install(&key, t0);
    w.export_ring();
    let held = crate::afxdp::bpf_map::global_tuple_gate()
        .try_acquire_installs([key.clone()])
        .expect("FIXTURE: another holder has the tuple permit");
    let mut now = t0;
    while w.barrier.parked.is_empty() {
        now += SEC;
        assert!(now < t0 + 200 * SEC, "FIXTURE: A's Close never parked");
        w.tick(now);
    }
    assert!(
        w.barrier
            .parked
            .iter()
            .any(|d| d.kind == SessionDeltaKind::Close && d.session_id == old_id),
        "FIXTURE: Close(A) is the parked delta"
    );
    assert_eq!(
        w.shared_id(&key),
        Some(old_id),
        "FIXTURE: A is still published"
    );
    w.drain_frames();
    w.frames.clear();
    drop(held);
    let mut new_id = 0;
    if replace {
        let permits = crate::afxdp::bpf_map::global_tuple_gate()
            .try_acquire_installs([key.clone()])
            .expect("FIXTURE: the replacement's install permit");
        new_id = w.install(&key, now);
        drop(permits);
        assert_ne!(new_id, old_id, "FIXTURE: a new incarnation");
        let exported = w.export_ring();
        assert!(
            exported
                .iter()
                .any(|d| d.kind == SessionDeltaKind::Open && d.session_id == new_id),
            "FIXTURE: the post-RX export carries Open(B)"
        );
    }
    w.tick(now + SEC);
    assert!(
        w.barrier.parked.is_empty(),
        "FIXTURE: Close(A) retired once its permit freed"
    );
    let ha = w.ha_frames(&key);
    let rt_flow = w.rt_flow_closes(old_id);
    (ha, rt_flow, w.shared_id(&key), old_id, new_id)
}

/// Codex R16 F1: after the same-worker replacement the stream carries Open(B)
/// and NO HA Close for that key (it would bare-delete B on the peer). A's
/// RT_FLOW Close is still delivered, and B survives locally and in the shared
/// map (the id-conditional local teardown). Without the superseded gate:
/// [Open(B), Close(A)].
#[test]
fn superseded_parked_close_sends_no_ha_close_after_the_replacements_open_19026() {
    let (ha, old_rt_flow, shared_id, _old_id, new_id) =
        parked_close_then_same_worker_replacement(19_101, true);
    assert_eq!(
        ha,
        vec![crate::event_stream::codec::MSG_SESSION_OPEN],
        "#19026 Codex R16 F1: no HA Close for the exact key after the replacement's Open"
    );
    assert_eq!(
        old_rt_flow, 1,
        "the old session's RT_FLOW Close is still delivered"
    );
    assert_eq!(
        shared_id,
        Some(new_id),
        "the replacement survives in the shared map"
    );
}

/// Twin: the same parked Close with NO replacement is not superseded and still
/// sends its HA Close (and its RT_FLOW Close), and its flush retires A's
/// shared row.
#[test]
fn a_parked_close_that_is_not_superseded_still_sends_its_ha_close_19026() {
    let (ha, old_rt_flow, shared_id, _old_id, _) =
        parked_close_then_same_worker_replacement(19_102, false);
    assert_eq!(
        ha,
        vec![crate::event_stream::codec::MSG_SESSION_CLOSE],
        "an ordinary parked Close keeps its HA leg"
    );
    assert_eq!(old_rt_flow, 1);
    assert_eq!(shared_id, None, "the Close's flush retired the shared row");
}

/// A Close that is stale only because the same bare tuple is published under
/// ANOTHER routing domain is not superseded (the peer keys that other session
/// differently), so through the real flush it keeps its HA Close frame.
#[test]
fn an_other_scope_stale_close_keeps_its_ha_close_19026() {
    let mut w = F1Worker::new();
    let key = f1_key(19_103, 0);
    let old_id = w.install(&key, 10_000 * SEC);
    w.export_ring();
    let mut other = w.table.synced_entry_for(&key).expect("row");
    other.key.routing_domain = 7;
    other.session_id = old_id + 1;
    w.publish(&other);
    let close = {
        let mut producer = SessionTable::new();
        producer.emit_close_delta_with_origin(
            key.clone(),
            f1_decision(),
            f1_metadata(),
            SessionOrigin::ForwardFlow,
            false,
            old_id,
        );
        producer.drain_deltas(1).pop().expect("close")
    };
    assert!(
        crate::afxdp::session_delta::close_delta_is_stale_incarnation(
            &close,
            None,
            &w.shared_sessions,
            &w.indexes,
        ),
        "FIXTURE: the Close is stale (another scope holds the bare tuple)"
    );
    w.drain_frames();
    w.frames.clear();
    w.flush(&[close]);
    assert_eq!(
        w.ha_frames(&key),
        vec![crate::event_stream::codec::MSG_SESSION_CLOSE],
        "#19026 R16 F1: an other-scope stale Close keeps its HA leg"
    );
    assert_eq!(w.rt_flow_closes(old_id), 1);
}

/// The gate itself is scope-exact and incarnation-exact: a Close is
/// superseded only while its EXACT key (routing domain included) holds a
/// different nonzero incarnation, in this worker's table or in the shared map.
/// Cases after Codex's review probe of 973b11b0d9.
#[test]
fn superseded_gate_is_exact_key_including_scope_19026() {
    let mut w = F1Worker::new();
    let key = f1_key(19_104, 0);
    let a = w.install(&key, 10_000 * SEC);
    let row_a = w.table.synced_entry_for(&key).expect("row A");
    let close = {
        let mut producer = SessionTable::new();
        producer.emit_close_delta_with_origin(
            key.clone(),
            f1_decision(),
            f1_metadata(),
            SessionOrigin::ForwardFlow,
            false,
            a,
        );
        producer.drain_deltas(1).pop().expect("close")
    };
    let gate = |local: Option<&SessionTable>, w: &F1Worker| {
        crate::afxdp::session_delta::close_delta_is_superseded_on_exact_key(
            &close,
            local,
            &w.shared_sessions,
        )
    };
    assert!(
        !gate(Some(&w.table), &w),
        "A itself, locally and shared: not superseded"
    );
    assert!(
        !gate(None, &w),
        "A itself in the shared map: not superseded"
    );
    // A table holding `id` on `key` (another worker's row).
    let table_with = |key: &SessionKey, id: u64| {
        let mut table = SessionTable::new();
        assert!(
            table.install_with_protocol_with_origin_and_source_nat_with_session_id(
                key.clone(),
                f1_decision(),
                f1_metadata(),
                SessionOrigin::ForwardFlow,
                10_000 * SEC,
                PROTO_UDP,
                0,
                None,
                id,
            )
        );
        assert_eq!(
            table.session_id_for(key),
            id,
            "FIXTURE: the table holds the id"
        );
        table
    };
    // B in another worker's table while the shared map still shows A.
    let mut local_b = table_with(&key, a + 1);
    assert!(gate(Some(&local_b), &w), "local B, shared A");
    // An identity-less Close (id 0) is never superseded: nothing says which
    // incarnation it ends.
    let mut anonymous = close.clone();
    anonymous.session_id = 0;
    assert!(
        !crate::afxdp::session_delta::close_delta_is_superseded_on_exact_key(
            &anonymous,
            Some(&local_b),
            &w.shared_sessions,
        ),
        "an id-0 Close is not superseded"
    );
    // A third incarnation C in the shared map.
    let mut row_c = row_a.clone();
    row_c.session_id = a + 2;
    w.publish(&row_c);
    assert!(gate(None, &w), "shared C");
    local_b.delete(&key);
    assert!(gate(Some(&local_b), &w), "B gone locally, shared C");
    crate::afxdp::shared_ops::remove_shared_session(
        &w.shared_sessions,
        &w.shared_nat,
        &w.shared_wire,
        &w.indexes,
        &key,
    );
    assert!(
        !gate(Some(&local_b), &w),
        "no current exact key: no suppression"
    );
    // The same bare tuple under another routing domain, shared and local.
    let mut other_scope = row_a.clone();
    other_scope.key.routing_domain = 99;
    other_scope.session_id = a + 3;
    w.publish(&other_scope);
    assert!(
        !gate(None, &w),
        "another scope in the shared map does not supersede"
    );
    let local_other = table_with(&other_scope.key, a + 3);
    assert!(
        !gate(Some(&local_other), &w),
        "another scope locally does not supersede"
    );
}

/// The RPC-fallback HA leg (no connected event stream, so nothing is
/// streamed and the flush mirrors the delta into the binding's fallback
/// FIFO). Returns the Closes mirrored for the tuple when the shared map holds
/// A (`superseded = false`) or a replacement B on the exact key (`true`).
fn rpc_fallback_closes(src_port: u16, superseded: bool) -> usize {
    let mut w = F1Worker::new();
    let key = f1_key(src_port, 0);
    let old_id = w.install(&key, 10_000 * SEC);
    let _ = w.table.drain_deltas(256);
    if superseded {
        let mut b = w.table.synced_entry_for(&key).expect("row");
        b.session_id = old_id + 1;
        w.publish(&b);
    }
    let close = {
        let mut producer = SessionTable::new();
        producer.emit_close_delta_with_origin(
            key.clone(),
            f1_decision(),
            f1_metadata(),
            SessionOrigin::ForwardFlow,
            false,
            old_id,
        );
        producer.drain_deltas(1).pop().expect("close")
    };
    let live = BindingLiveState::new();
    let ident = BindingIdentity {
        slot: 0,
        queue_id: 0,
        worker_id: 0,
        interface: Arc::<str>::from(""),
        ifindex: -1,
    };
    let by_id: BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>> =
        [(0u32, w.queue.clone())].into_iter().collect();
    let runtime = w.runtime.reader();
    let _ = crate::afxdp::session_delta::flush_session_deltas(
        &ident,
        Some(&live),
        SteeringMap::unshared_for_test(-1),
        -1,
        -1,
        &[close],
        &w.shared_sessions,
        &w.shared_nat,
        &w.shared_wire,
        &w.indexes,
        &w.recent,
        &[],
        &by_id,
        &None,
        &w.forwarding,
        &runtime,
        &mut w.wedged,
        Some(&mut w.table),
    );
    live.drain_session_deltas(1024)
        .iter()
        .filter(|info| info.event == "close" && info.src_port == src_port)
        .count()
}

/// Codex R16 F1, RPC-fallback leg: a superseded Close mirrors no HA close
/// into the fallback FIFO (the daemon applies it as the same bare delete).
#[test]
fn a_superseded_close_mirrors_no_rpc_fallback_close_19026() {
    assert_eq!(
        rpc_fallback_closes(19_105, true),
        0,
        "#19026 Codex R16 F1: no fallback HA close for a superseded Close"
    );
}

/// Twin: a Close whose exact key still holds its own incarnation mirrors its
/// fallback HA close.
#[test]
fn a_close_that_is_not_superseded_mirrors_its_rpc_fallback_close_19026() {
    assert_eq!(
        rpc_fallback_closes(19_106, false),
        1,
        "an ordinary Close keeps its fallback leg"
    );
}
