//! #18541: a connection that arrives while an accept loop is idle is
//! accepted at once, not after the loop's poll interval.
//!
//! Before the fix the idle wait was `thread::sleep(poll)`. The Go side dials
//! one session-socket connection per request, immediately after reading the
//! previous response — i.e. just after the loop went idle — so each request
//! waited out ~the whole 10 ms sleep. Two requests per synced session (the
//! forward `mirror_upsert` and its `mirror_publish_only` companion) made a
//! 522-session HA bulk take ~10 s, the ~51 sessions/s seen on loss fw0.
//!
//! The cells give the loop an idle interval far longer than their wait
//! budget (`NEVER` vs `WAIT_BUDGET`), so a loop that sleeps cannot answer in
//! time; the budget is a liveness backstop sized for a loaded host (#8218
//! clause 3), never the pass criterion. The last test drives the PRODUCTION
//! session spec and prints the per-session cost; it asserts only that every
//! request was answered.

use super::{AcceptLoopSpec, PanicPolicy, run_accept_loop, wait_for_pending_connection};
use crate::server::lifecycle::SESSION_SOCKET_IDLE_WAIT;
use crate::server::{ServerState, SocketMode, handle_stream};
use crate::state_writer::StateWriter;
use crate::{ControlRequest, ControlResponse, ProcessStatus, SessionSyncRequest, afxdp};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

/// An idle interval no test budget reaches.
const NEVER: Duration = Duration::from_secs(120);
/// Liveness backstop for one wait/round trip on a loaded host.
const WAIT_BUDGET: Duration = Duration::from_secs(30);

struct SockDir(PathBuf);

impl Drop for SockDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A private directory for one socket. Short names: `sun_path` is 108 bytes.
fn sock_dir(tag: &str) -> (SockDir, PathBuf) {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "xpf-aw-{tag}-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).expect("create socket dir");
    let path = dir.join("s.sock");
    (SockDir(dir), path)
}

fn bind_nonblocking(path: &PathBuf) -> UnixListener {
    let listener = UnixListener::bind(path).expect("bind test listener");
    // Exactly as production (lifecycle.rs): the loop polls a non-blocking
    // listener so it can observe `running`.
    listener.set_nonblocking(true).expect("set nonblocking");
    listener
}

#[test]
fn idle_wait_ends_when_a_connection_is_pending() {
    let (_dir, path) = sock_dir("wake");
    let listener = bind_nonblocking(&path);
    // Queued BEFORE the wait begins, so only a wait that looks at the
    // listener can return before `NEVER`.
    let _client = UnixStream::connect(&path).expect("connect");
    let waiter = listener.try_clone().expect("clone listener");
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let _ = tx.send(wait_for_pending_connection(&waiter, NEVER));
    });
    match rx.recv_timeout(WAIT_BUDGET) {
        Ok(true) => {}
        Ok(false) => panic!("the idle wait returned without reporting the pending connection"),
        Err(_) => panic!(
            "the idle wait was still running {WAIT_BUDGET:?} after a connection was queued: it \
             sleeps its interval instead of waking on the arrival, so every session-socket \
             request pays the poll interval (#18541)"
        ),
    }
}

#[test]
fn idle_wait_times_out_without_a_connection() {
    let (_dir, path) = sock_dir("idle");
    let listener = bind_nonblocking(&path);
    let waiter = listener.try_clone().expect("clone listener");
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let _ = tx.send(wait_for_pending_connection(
            &waiter,
            Duration::from_millis(20),
        ));
    });
    assert!(
        !rx.recv_timeout(WAIT_BUDGET)
            .expect("a bounded idle wait never returned"),
        "an idle wait with nothing queued must report no connection, or the loop accepts \
         WouldBlock and waits again with no bound on how fast it cycles"
    );
}

/// #18541 review (bulk-B): a `shutdown(2)` listener polls `POLLIN|POLLHUP`
/// forever while `accept` returns `EAGAIN`. The wait must not report that as
/// a pending connection, and must sleep its interval rather than return at
/// once, or the loop cycles `WouldBlock -> Idle -> poll` at full speed. The
/// duration check is a LOWER bound that `thread::sleep` guarantees, so load can
/// only lengthen it; the deleted-sleep mutant returns in microseconds.
#[test]
fn idle_wait_sleeps_on_a_shut_down_listener() {
    use std::os::fd::AsRawFd;
    const MAX: Duration = Duration::from_millis(200);
    let (_dir, path) = sock_dir("hup");
    let listener = bind_nonblocking(&path);
    // SAFETY: `listener` owns this listening descriptor for the whole call.
    let rc = unsafe { libc::shutdown(listener.as_raw_fd(), libc::SHUT_RDWR) };
    assert_eq!(
        rc,
        0,
        "shutdown listener: {}",
        std::io::Error::last_os_error()
    );
    // Fixture: the listener must really be in the hang-up state with nothing
    // to accept, or the timeout arm alone would pass this cell.
    let mut pfd = libc::pollfd {
        fd: listener.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: one initialised pollfd for a descriptor `listener` keeps open.
    let ready = unsafe { libc::poll(&mut pfd, 1, 0) };
    assert!(
        ready == 1 && (pfd.revents & libc::POLLIN) != 0 && (pfd.revents & libc::POLLHUP) != 0,
        "fixture: a shut-down listener should poll POLLIN|POLLHUP at once, got rc={ready} revents={:#x}",
        pfd.revents
    );
    assert!(
        matches!(listener.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock),
        "fixture: a shut-down listener should have nothing to accept"
    );
    let waiter = listener.try_clone().expect("clone listener");
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let start = Instant::now();
        let pending = wait_for_pending_connection(&waiter, MAX);
        let _ = tx.send((pending, start.elapsed()));
    });
    let (pending, elapsed) = rx
        .recv_timeout(WAIT_BUDGET)
        .expect("a bounded idle wait never returned");
    assert!(
        !pending,
        "a POLLIN|POLLHUP listener was reported as having a connection pending: the loop would spin \
         WouldBlock -> Idle -> poll"
    );
    assert!(
        elapsed >= MAX,
        "the wait returned after {elapsed:?} on a hung-up listener, before its {MAX:?} interval: the \
         loop would cycle at poll speed"
    );
}

fn new_state() -> Arc<Mutex<ServerState>> {
    Arc::new(Mutex::new(ServerState {
        status: ProcessStatus::default(),
        snapshot: None,
        afxdp: afxdp::Coordinator::new(),
        state_writer: Arc::new(StateWriter::new()),
        quarantined_after_panic: false,
        snapshot_policy_mismatch_total: 0,
    }))
}

/// The session loop exactly as `lifecycle::run` wires it, over the real
/// `handle_stream` dispatcher, with the given idle interval.
struct SessionLoop {
    _dir: SockDir,
    path: PathBuf,
    running: Arc<AtomicBool>,
}

impl SessionLoop {
    fn start(tag: &str, poll: Duration) -> Self {
        let (dir, path) = sock_dir(tag);
        let listener = bind_nonblocking(&path);
        let state = new_state();
        let session_domain = state.lock().expect("state").afxdp.session_domain().clone();
        let running = Arc::new(AtomicBool::new(true));
        let state_file = dir.0.join("state.json").to_string_lossy().into_owned();
        {
            let running = running.clone();
            thread::spawn(move || {
                let _ = run_accept_loop(
                    &listener,
                    AcceptLoopSpec {
                        name: "session socket",
                        poll,
                        retry_unclassified: true,
                        peer_label: "session socket",
                    },
                    &running,
                    PanicPolicy::QuarantineAndStop {
                        sock_name: "session",
                        state: &state,
                    },
                    |stream| {
                        handle_stream(
                            stream,
                            &state_file,
                            state.clone(),
                            running.clone(),
                            session_domain.clone(),
                            SocketMode::Session,
                        )
                    },
                );
            });
        }
        SessionLoop {
            _dir: dir,
            path,
            running,
        }
    }

    /// One Go-shaped round trip: a fresh dial, one request, one response.
    /// `None` when no response arrived inside the budget.
    ///
    /// The request goes out as ONE write, as Go's `json.Encoder` sends it, and
    /// the write is bounded too. `serde_json::to_writer` on an unbuffered
    /// stream issues one `write(2)` per token, each charged a full skb; against
    /// a loop that is not reading (the regression these cells exist to catch)
    /// that exhausts the send buffer and blocks forever with no write timeout,
    /// turning the cell's red into a hang that holds the shared cargo lock.
    fn round_trip(&self, request: &ControlRequest) -> Option<ControlResponse> {
        let mut stream = UnixStream::connect(&self.path).expect("dial session socket");
        stream
            .set_read_timeout(Some(WAIT_BUDGET))
            .expect("set read timeout");
        stream
            .set_write_timeout(Some(WAIT_BUDGET))
            .expect("set write timeout");
        let mut body = serde_json::to_vec(request).expect("encode request");
        body.push(b'\n');
        std::io::Write::write_all(&mut stream, &body).ok()?;
        serde_json::from_reader(std::io::BufReader::new(stream)).ok()
    }
}

impl Drop for SessionLoop {
    fn drop(&mut self) {
        // Stop the loop: clear `running`, then wake it with a bare dial so
        // it observes the flag without waiting out its idle interval. The
        // woken loop exits WITHOUT accepting, so this must not write or
        // read: best effort, never a panic in a destructor.
        self.running.store(false, Ordering::SeqCst);
        let _ = UnixStream::connect(&self.path);
    }
}

/// The two requests the Go receiver issues per bulk session
/// (`dataPlaneSessionStore.PutClusterSyncedV4` -> `SetClusterSyncedSessionV4`
/// twice): the forward, then its reverse companion.
fn bulk_session_requests(i: u16) -> [ControlRequest; 2] {
    let forward = SessionSyncRequest {
        operation: "mirror_upsert".to_string(),
        addr_family: libc::AF_INET as u8,
        protocol: 6,
        src_ip: "10.0.61.10".to_string(),
        dst_ip: "172.16.80.200".to_string(),
        src_port: 20000 + i,
        dst_port: 5201,
        egress_ifindex: 7,
        neighbor_mac: "02:bf:72:01:02:03".to_string(),
        src_mac: "02:bf:72:0a:0b:0c".to_string(),
        ..SessionSyncRequest::default()
    };
    let reverse = SessionSyncRequest {
        operation: "mirror_publish_only".to_string(),
        src_ip: forward.dst_ip.clone(),
        dst_ip: forward.src_ip.clone(),
        src_port: forward.dst_port,
        dst_port: forward.src_port,
        is_reverse: true,
        ..forward.clone()
    };
    [forward, reverse].map(|sync| ControlRequest {
        request_type: "sync_session".to_string(),
        suppress_status: true,
        session_sync: Some(sync),
        ..ControlRequest::default()
    })
}

#[test]
fn the_session_loop_serves_back_to_back_dials_without_its_idle_interval() {
    let lp = SessionLoop::start("b2b", NEVER);
    // Each dial follows the previous response, the shape that found the
    // loop idle on every request. 32 in a row: a sleeping loop would have to
    // be beaten back to accept() 32 times running to pass.
    for i in 0..16u16 {
        for request in bulk_session_requests(i) {
            if lp.round_trip(&request).is_none() {
                panic!(
                    "round trip {i} got no response within {WAIT_BUDGET:?}: the session loop waited \
                     out its idle interval with a connection pending (#18541)"
                );
            }
        }
    }
}

/// The hermetic measurement behind #18541: a 522-session bulk (1044
/// requests) through the PRODUCTION session idle wait and the real
/// dispatcher. Prints the cost; asserts only that every request was answered.
/// Before the fix this printed ~10 ms per request (~20 ms per session).
#[test]
fn a_522_session_bulk_through_the_production_session_spec() {
    const SESSIONS: u16 = 522;
    let lp = SessionLoop::start("bulk", SESSION_SOCKET_IDLE_WAIT);
    let mut answered = 0u32;
    let mut ok = 0u32;
    let mut first_error = String::new();
    let start = Instant::now();
    for i in 0..SESSIONS {
        for request in bulk_session_requests(i) {
            if let Some(response) = lp.round_trip(&request) {
                answered += 1;
                if response.ok {
                    ok += 1;
                } else if first_error.is_empty() {
                    first_error = response.error;
                }
            }
        }
    }
    let elapsed = start.elapsed();
    let requests = 2 * u32::from(SESSIONS);
    eprintln!(
        "#18541 measured: {SESSIONS} sessions / {requests} requests through the session loop \
         (idle wait {SESSION_SOCKET_IDLE_WAIT:?}) in {elapsed:?}: {:?}/request, {:?}/session; \
         {ok} ok, first refusal: {first_error:?}",
        elapsed / requests,
        elapsed / u32::from(SESSIONS),
    );
    assert_eq!(
        answered, requests,
        "every session-socket request must be answered"
    );
}
