// Daemon lifecycle: argument parsing, control-socket setup, daemon
// supervision loop. Extracted from main.rs (Issue 69.2).
//
// `run` is the main daemon driver — initializes Args, builds the
// initial Coordinator + ServerState, opens the control socket, and
// runs the accept-and-dispatch loop forever.
// `parse_args` parses the command-line into Args.
// `derive_session_socket_path` / `derive_event_socket_path` are
// small helpers that derive companion socket paths from the
// primary control-socket path.
//
// Pure relocation. Bodies byte-for-byte identical; visibility
// widened from file-private to `pub(crate)` so main.rs's `fn main()`
// shell can call into `server::lifecycle::run`.

use super::super::*;
use std::time::Instant;

// Target for the kernel socket-buffer sysctls, in bytes. MUST match the Go
// control plane's `tuneSocketBuffers` target (`pkg/dataplane/userspace/
// process.go`, `const desired = 67108864`). Both components raise these
// host-global sysctls so AF_XDP copy-mode sockets can receive at line rate;
// keeping the targets identical means whichever runs second is a no-op rather
// than a fight (#2970).
const SOCKBUF_TARGET: i64 = 67108864; // 64 MiB

/// Raise-only sysctl computation (#2970): given the current sysctl contents
/// and a target, return `Some(target)` if the target is strictly higher than
/// the current value, otherwise `None` (already >= target, or unparseable —
/// never lower a value an operator or the Go control plane set higher).
///
/// Pure function so it can be unit-tested without touching real `/proc`.
fn raise_only_value(current: &str, target: i64) -> Option<i64> {
    let cur: i64 = current.trim().parse().ok()?;
    if cur >= target { None } else { Some(target) }
}

/// Apply `raise_only_value` to a real sysctl path: read the current value and
/// only write the target when it would raise (never lower). Host-global
/// rmem/wmem ceilings must never be clobbered downward — the Go control plane
/// already raises these to 64 MiB before launching us, and an operator may
/// have tuned them even higher (#2970).
fn raise_sysctl(path: &str, target: i64) {
    let current = match fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("warn: read {path}: {e}");
            return;
        }
    };
    match raise_only_value(&current, target) {
        Some(val) => {
            if let Err(e) = fs::write(path, val.to_string()) {
                eprintln!("warn: set {path}: {e}");
            } else {
                eprintln!("set {path}={val} (raised from {})", current.trim());
            }
        }
        None => {
            eprintln!("keep {path}={} (>= target {target})", current.trim());
        }
    }
}

/// Human-readable file-type label for a diagnostic, so a refusal names what
/// was actually found at the path rather than a bare errno.
fn describe_file_type(ft: &std::fs::FileType) -> &'static str {
    use std::os::unix::fs::FileTypeExt;
    if ft.is_file() {
        "regular file"
    } else if ft.is_dir() {
        "directory"
    } else if ft.is_symlink() {
        "symlink"
    } else if ft.is_fifo() {
        "fifo"
    } else if ft.is_block_device() {
        "block device"
    } else if ft.is_char_device() {
        "char device"
    } else if ft.is_socket() {
        "socket"
    } else {
        "unknown"
    }
}

/// Remove a stale Unix-domain socket at `path`, failing closed on a non-socket
/// (#2974). The helper runs as root and takes `--control-socket` as an
/// argument; the historical behavior was an unconditional `remove_file`, which
/// would silently delete a regular file (or any other object) if the helper
/// were pointed at a wrong path. Guard the unlink:
///   * path absent (`NotFound`) -> `Ok(())` (nothing to remove; bind creates it)
///   * path is a socket -> `remove_file` (clean up a stale socket from a prior
///     run — the normal happy path)
///   * path is anything else (regular file, dir, symlink, fifo, ...) -> refuse
///     and return an error naming the path and observed type, so the caller
///     fails closed instead of destroying it.
///
/// `symlink_metadata` is used so the path's own type is inspected without
/// following symlinks: a symlink reports as `is_symlink()` (not `is_socket()`)
/// and is therefore refused rather than followed — a deliberately conservative
/// fail-closed choice. The subsequent `bind` then surfaces a clear error.
fn remove_stale_socket(path: &str) -> std::io::Result<()> {
    let meta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    use std::os::unix::fs::FileTypeExt;
    let ft = meta.file_type();
    if ft.is_socket() {
        fs::remove_file(path)
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!(
                "refusing to unlink {path}: existing path is a {}, not a Unix socket",
                describe_file_type(&ft)
            ),
        ))
    }
}

/// #9003: the compiled-in default control-socket / state-file locations.
///
/// They MUST agree with the Go control plane's `DefaultControlSocket` /
/// `DefaultStateFile` (`pkg/dataplane/userspace/socket_trust_9003.go`) — the
/// daemon resolves the same defaults when the operator omits
/// `system dataplane control-socket`, and the #1993 boot armed-probe dials the
/// path the daemon derived, not the one this binary would have chosen. A skew
/// between them makes a surviving helper undialable at boot.
pub(crate) const DEFAULT_CONTROL_SOCKET: &str = "/run/xpf/userspace-dp.sock";
pub(crate) const DEFAULT_STATE_FILE: &str = "/run/xpf/userspace-dp.json";

/// Mode for a runtime directory this helper CREATES. Only root traverses it.
/// An existing directory keeps its own mode — the Go side judges that one
/// (`ensureTrustedRuntimeDir`) and refuses bring-up rather than chmod'ing a
/// directory it does not own, because a chmod an attacker can undo is not a
/// control.
const RUNTIME_DIR_MODE: u32 = 0o750;

/// Mode for a bound helper socket. Root-only, explicitly.
///
/// #9003: before this the mode was `0o777 & !umask` — a value inherited from
/// whatever the unit and the ambient environment happened to supply, asserted by
/// no code, no unit file and no test. Under the documented `/run/xpf` config and
/// systemd's default umask it happened to land 0755 and an unprivileged
/// `connect()` got EACCES; a `UMask=0000` in the unit would have silently
/// converted that to "any local user can read the WireGuard private key" with no
/// signal anywhere. An unasserted umask is not a control.
const SOCKET_MODE: u32 = 0o600;

/// Create a runtime directory with a restrictive mode. `create_dir_all` applies
/// the process umask to the mode, so the directory is created at
/// `RUNTIME_DIR_MODE & !umask` — never wider.
fn create_runtime_dir(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new()
        .recursive(true)
        .mode(RUNTIME_DIR_MODE)
        .create(path)
}

/// Restrict a bound Unix socket to its owner. Called AFTER `bind` — there is no
/// atomic bind-with-mode, so the window between bind and chmod is closed by the
/// accept-side peer check rather than by the mode.
fn restrict_socket_mode(path: &str) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(SOCKET_MODE))
        .map_err(|e| format!("restrict mode on {path}: {e}"))
}

/// #9003: refuse a control/session-socket peer that is neither root nor this
/// process's own uid.
///
/// This is the authoritative gate, and it is the one that does not race. The
/// socket mode above is a question about a NAME at some earlier instant;
/// `SO_PEERCRED` is answered by the kernel for the process on the other end of
/// THIS connection, so it holds even if the path was swapped after the bind.
///
/// The handler dispatch (`server/handlers/mod.rs`) serves `ping` / `status` /
/// `apply_snapshot` / `set_forwarding_state` / `update_ha_state` with no caller
/// check at all, so a connectable socket is dataplane TAKEOVER, not merely key
/// readback.
///
/// The own-uid arm exists so a non-root test binary can drive the real accept
/// path against a socket it bound itself. In production both ends are root and
/// the arm never fires.
pub(crate) fn reject_unprivileged_peer(
    kind: &str,
    stream: &std::os::unix::net::UnixStream,
) -> Result<(), String> {
    // `UnixStream::peer_cred` is still unstable (rust-lang#42839), so read
    // SO_PEERCRED directly. Same kernel answer, no nightly.
    use std::os::fd::AsRawFd;
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: `stream` owns a live AF_UNIX fd for the duration of the call;
    // `cred` and `len` are a correctly-sized, correctly-typed out-parameter
    // pair for SO_PEERCRED.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            std::ptr::from_mut(&mut cred).cast::<libc::c_void>(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(format!(
            "read {kind} peer credentials: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: geteuid(2) has no failure mode and no preconditions.
    let self_uid = unsafe { libc::geteuid() };
    peer_uid_refusal(kind, cred.uid, cred.gid, cred.pid, self_uid)
}

/// The DECISION, split from the syscall shell above (#9171).
///
/// The shell cannot be driven by an unprivileged test: exercising a refusal
/// needs a peer running as a DIFFERENT uid, and becoming one needs a capability
/// the test binary does not have. So the arms were unreachable from any cell,
/// and a mutation making the check unreachable survived every source-level
/// assertion — the checker's NAME was still in the file.
///
/// This mirrors what `runtimeDirTrustError` does on the Go side for the same
/// reason, and that function says so outright: the project rule is that a test
/// needing a kernel capability STUBS it rather than skipping on it (#6675),
/// because a skip is indistinguishable from a pass in every summary line.
/// Making the decision a pure function of the credentials is that stub — the
/// shell supplies real values in production and the cells supply hostile ones.
pub(crate) fn peer_uid_refusal(
    kind: &str,
    peer_uid: u32,
    peer_gid: u32,
    peer_pid: i32,
    self_uid: u32,
) -> Result<(), String> {
    if peer_uid != 0 && peer_uid != self_uid {
        return Err(format!(
            "refusing {kind} connection from uid {peer_uid} (gid {peer_gid}, pid {peer_pid}): \
             not root and not this process (uid {self_uid}). The control protocol carries the \
             WireGuard private key and every preshared key in cleartext, and its handlers are \
             unauthenticated."
        ));
    }
    Ok(())
}

pub(crate) fn run() -> Result<(), String> {
    // Increase socket buffer ceilings — needed for AF_XDP copy mode to avoid
    // drops when the kernel backlog is large. Raise-only: never lower a value
    // the Go control plane (64 MiB) or an operator already set higher (#2970).
    // Cover both rmem and wmem to match the Go side.
    for sysctl in &[
        "/proc/sys/net/core/rmem_default",
        "/proc/sys/net/core/rmem_max",
        "/proc/sys/net/core/wmem_default",
        "/proc/sys/net/core/wmem_max",
    ] {
        raise_sysctl(sysctl, SOCKBUF_TARGET);
    }
    let args = parse_args()?;
    // Enable NAPI busy polling sysctls only in busy-poll mode.
    // In interrupt mode, skip these so the kernel uses normal interrupt delivery.
    if args.poll_mode == PollMode::BusyPoll {
        for (path, val) in &[
            ("/proc/sys/net/core/busy_poll", "50"),
            ("/proc/sys/net/core/busy_read", "50"),
        ] {
            if let Err(e) = fs::write(path, val) {
                eprintln!("warn: set {path}: {e}");
            } else {
                eprintln!("set {path}={val}");
            }
        }
    } else {
        eprintln!("xpf-userspace-dp: interrupt mode — skipping busy_poll sysctls");
    }
    if let Some(parent) = Path::new(&args.control_socket).parent() {
        create_runtime_dir(parent).map_err(|e| format!("create control dir: {e}"))?;
    }
    if let Some(parent) = Path::new(&args.state_file).parent() {
        create_runtime_dir(parent).map_err(|e| format!("create state dir: {e}"))?;
    }
    // Only unlink a stale Unix socket left by a prior run — never blindly
    // delete a regular file or other object at these privileged paths (#2974).
    // A non-socket aborts bind with a diagnostic instead of being destroyed.
    remove_stale_socket(&args.control_socket)
        .map_err(|e| format!("control socket {}: {e}", args.control_socket))?;
    let session_socket = derive_session_socket_path(&args.control_socket);
    remove_stale_socket(&session_socket)
        .map_err(|e| format!("session socket {session_socket}: {e}"))?;

    let listener = UnixListener::bind(&args.control_socket)
        .map_err(|e| format!("listen {}: {e}", args.control_socket))?;
    restrict_socket_mode(&args.control_socket)?;
    listener
        .set_nonblocking(true)
        .map_err(|e| format!("set nonblocking listener: {e}"))?;

    let session_listener = UnixListener::bind(&session_socket)
        .map_err(|e| format!("listen session {}: {e}", session_socket))?;
    restrict_socket_mode(&session_socket)?;
    session_listener
        .set_nonblocking(true)
        .map_err(|e| format!("set nonblocking session listener: {e}"))?;
    eprintln!("xpf-userspace-dp: session socket at {}", session_socket);
    // #9726: name the libraries this binary linked, once.
    eprintln!(
        "xpf-userspace-dp: linked libxdp {} and vendored libbpf {}; the build host's libbpf (pkg-config) was {}",
        env!("XPF_LINKED_LIBXDP_VERSION"),
        env!("XPF_LINKED_LIBBPF_VERSION"),
        env!("XPF_BUILD_HOST_LIBBPF_VERSION"),
    );

    let state_writer = Arc::new(StateWriter::new());
    let running = Arc::new(AtomicBool::new(true));
    let state = Arc::new(Mutex::new(ServerState {
        status: ProcessStatus {
            pid: std::process::id() as i32,
            config_snapshot_protocol_version: CONFIG_SNAPSHOT_PROTOCOL_VERSION,
            inject_packet_tuple_protocol_version: INJECT_PACKET_TUPLE_PROTOCOL_VERSION,
            session_export_paging_protocol_version: SESSION_EXPORT_PAGING_PROTOCOL_VERSION,
            session_delta_schema_fingerprint:
                crate::protocol::session_delta_schema::session_delta_schema_fingerprint(),
            linked_libxdp_version: env!("XPF_LINKED_LIBXDP_VERSION").to_string(),
            linked_libbpf_version: env!("XPF_LINKED_LIBBPF_VERSION").to_string(),
            build_host_libbpf_version: env!("XPF_BUILD_HOST_LIBBPF_VERSION").to_string(),
            started_at: Utc::now(),
            control_socket: args.control_socket.clone(),
            state_file: args.state_file.clone(),
            workers: args.workers,
            ring_entries: args.ring_entries,
            helper_mode: "rust-afxdp-bootstrap".to_string(),
            io_uring_planned: true,
            io_uring_active: false,
            io_uring_mode: String::new(),
            io_uring_last_error: String::new(),
            enabled: false,
            forwarding_armed: false,
            capabilities: UserspaceCapabilities::default(),
            last_snapshot_generation: 0,
            last_fib_generation: 0,
            last_snapshot_at: None,
            interface_addresses: 0,
            neighbor_entries: 0,
            session_table_entries: 0,
            max_sessions: 0,
            nat_reverse_key_collisions: 0,
            nat_reverse_key_collisions_distinct_src: 0,
            session_create_drops: 0,
            session_install_admission_refused: 0,
            session_install_partial: 0,
            flow_cache_capacity: 0,
            neighbor_cache_capacity: 0,
            neighbor_generation: 0,
            manager_neighbor_generation: 0,
            route_entries: 0,
            worker_heartbeats: Vec::new(),
            worker_runtime: Vec::new(),
            cos_no_owner_binding_drops_total: 0,
            neighbor_warm_drops_total: 0,
            neighbor_warm_disconnected_total: 0,
            neg_neigh_fast_fail_total: 0,
            pending_neigh_duplicate_drops_total: 0,
            pending_neigh_decap_drops_total: 0,
            source_nat_match_consulted_total: 0,
            source_nat_match_matched_total: 0,
            source_nat_match_unavailable_total: 0,
            source_nat_match_no_match_total: 0,
            io_uring_retained_buffers_total: 0,
            io_uring_retained_bytes_total: 0,
            io_uring_write_refused_total: 0,
            io_uring_write_refused_bytes_total: 0,
            pending_neigh_capacity_drops_total: 0,
            dynamic_neighbor_learn_cap_drops_total: 0,
            session_publish_errors_total: 0,
            // #4800 new-flow-install contention surface.
            shared_session_publishes_total: 0,
            owner_rg_filings_declined_total: 0,
            shared_session_publish_lock_acquisitions_total: 0,
            shared_session_publish_lock_contended_total: 0,
            session_replication_upserts_total: 0,
            session_replication_enqueued_total: 0,
            session_replication_lock_contended_total: 0,
            session_replication_queue_depth_sum: 0,
            session_replication_queue_depth_max: 0,
            dnat_publish_errors_total: 0,
            synced_import_cap_drops_total: 0,
            nat_reverse_key_shared_displacements_total: 0,
            // #6751 PR 2/3: interface-mode SNAT identity registry counters.
            interface_snat_pat_collisions_total: 0,
            nat64_frag_cross_domain_misses_total: 0,
            nat64_frag_protocol_alias_misses_total: 0,
            interface_snat_identity_exhaustion_total: 0,
            interface_snat_sync_identity_conflict_drops_total: 0,
            interface_snat_registry_cap_exhaustion_total: 0,
            worker_command_queue_poison_recoveries: 0,
            worker_command_queue_drops: 0,
            session_delete_replica_dropped: 0,
            session_delete_replica_drop_repaired: 0,
            peer_delete_refused_local_owned: 0,
            shared_session_poison_recoveries: 0,
            session_install_stale_ignored: 0,
            session_delete_stale_ignored: 0,
            session_delete_dropped_released: 0,
            tunnel_purge_reservations_released: 0,
            synced_import_reserve_refused: 0,
            synced_import_unknown_routing_domain: 0,
            synced_import_zone_unresolved: 0,
            synced_import_unpublished: 0,
            synced_reverse_rederived: 0,
            gre_decap_ecn_illegal_drops_total: 0,
            wg_decap_ecn_illegal_drops_total: 0,
            gre_encap_df_oversize_drops_total: 0,
            gre_decap_checksum_invalid_drops_total: 0,
            gre_decap_unsupported_version_refusals_total: 0,
            time_exceeded_rate_limited_total: 0,
            packet_too_big_rate_limited_total: 0,
            reject_rate_limited_total: 0,
            dynamic_neighbor_keys: Vec::new(),
            neighbor_resolver_queue_depth: 0,
            neighbor_resolver_enqueue_drops_total: 0,
            neighbor_resolver_disconnected_total: 0,
            neighbor_resolver_get_attempts_total: 0,
            neighbor_resolver_get_resolved_total: 0,
            neighbor_resolver_probe_on_stale_total: 0,
            neighbor_resolver_get_failures_total: 0,
            neighbor_resolver_epoch_rejects_total: 0,
            neighbor_pending_dwell_buckets: Vec::new(),
            neighbor_pending_dwell_sum_ns: 0,
            neighbor_pending_dwell_count: 0,
            neighbor_resolver_get_rtt_buckets: Vec::new(),
            neighbor_resolver_get_rtt_sum_ns: 0,
            neighbor_resolver_get_rtt_count: 0,
            neighbor_pending_timeout_drops_total: 0,
            neighbor_pending_max_depth: 0,
            neighbor_resolver_get_backoff_attempts_total: 0,
            neighbor_netlink_enobufs_total: 0,
            neighbor_netlink_redumps_total: 0,
            neighbor_netlink_redump_upserts_total: 0,
            neighbor_pending_keys: 0,
            neg_neigh_keys: 0,
            // #1865: WG telemetry rows arrive on the first
            // refresh_status; empty start keeps the wire omitted.
            wg_tunnels: Vec::new(),
            per_binding: Vec::new(),
            flow_worker_map: Vec::new(),
            flow_worker_map_truncated: false,
            cos_active_flow_counts: Vec::new(),
            cos_active_flow_counts_truncated: false,
            ha_groups: Vec::new(),
            fabrics: Vec::new(),
            queues: Vec::new(),
            bindings: Vec::new(),
            recent_session_deltas: Vec::new(),
            recent_exceptions: Vec::new(),
            cos_interfaces: Vec::new(),
            policy_rule_counters: Vec::new(),
            nat_rule_counters: Vec::new(),
            filter_term_counters: Vec::new(),
            // #3651: per-zone traffic block is empty until the first status
            // refresh reads the helper's zone-counter store.
            zone_counter_layout_version: 0,
            zone_counter_overflow_active: false,
            zone_traffic_counters: Vec::new(),
            // #3651: per-zone flood-event block is empty until the first status
            // refresh reads the helper's flood-counter store.
            flood_counter_layout_version: 0,
            flood_counter_overflow_active: false,
            zone_flood_counters: Vec::new(),
            three_color_policer_counters: Vec::new(),
            source_nat_pools: Vec::new(),
            last_resolution: None,
            slow_path: SlowPathStatus::default(),
            debug_worker_threads: 0,
            debug_identity_slots: 0,
            debug_live_slots: 0,
            debug_planned_workers: 0,
            debug_planned_bindings: 0,
            debug_reconcile_calls: 0,
            debug_reconcile_stage: String::new(),
            event_stream_connected: false,
            event_stream_seq: 0,
            event_stream_acked: 0,
            event_stream_sent: 0,
            event_stream_dropped: 0,
            event_stream_write_stalls: 0,
            event_stream_replay_evictions: 0,
            event_stream_invalid_acks: 0,
            event_stream_producer_seq_lock_acquisitions_total: 0,
            event_stream_producer_seq_lock_contended_total: 0,
            event_stream_session_close_sent: 0,
            event_stream_session_close_dropped: 0,
            event_stream_session_create_sent: 0,
            event_stream_session_create_dropped: 0,
            last_cache_flush_at: 0,
            fabric_link_skipped_malformed_total: 0,
            fabric_link_unresolved_peer_total: 0,
            learned_route_import_capped: None,
        },
        snapshot: None,
        afxdp: {
            let mut c = afxdp::Coordinator::new();
            c.poll_mode = args.poll_mode;
            c
        },
        state_writer: state_writer.clone(),
    }));
    eprintln!("xpf-userspace-dp: poll_mode={:?}", args.poll_mode);

    // #7209: cloned ONCE, here, while nothing else holds the mutex. The
    // coordinator never reassigns the fields this mirrors — it only mutates
    // them through their own interior synchronization — so a handle taken now
    // observes every later publish rather than freezing a snapshot of startup.
    // Taking it here rather than per-request is also what keeps the session
    // socket off the mutex: deriving it from `state` would need the very lock
    // this exists to avoid.
    let session_domain = {
        let guard = state.lock().expect("state poisoned");
        guard.afxdp.session_domain().clone()
    };
    let main_session_domain = session_domain.clone();

    // Start the event stream sender (connects to daemon's event listener socket).
    {
        let event_socket_path = derive_event_socket_path(&args.control_socket);
        let mut guard = state.lock().expect("state poisoned");
        guard.afxdp.start_event_stream(&event_socket_path);
        eprintln!(
            "xpf-userspace-dp: event stream targeting {}",
            event_socket_path
        );
    }

    {
        let running = running.clone();
        ctrlc::set_handler(move || {
            running.store(false, Ordering::SeqCst);
        })
        .map_err(|e| format!("install ctrlc handler: {e}"))?;
    }

    write_state(&args.state_file, &state)?;

    // Spawn a dedicated thread for the session socket so session installs
    // (HA sync path) proceed concurrently with main socket operations
    // (status polls, snapshot publishes). The shared `state` mutex already
    // protects concurrent access. Fixes #452.
    let session_thread = {
        let state = state.clone();
        let running = running.clone();
        let state_file = args.state_file.clone();
        thread::Builder::new()
            .name("session-socket".to_string())
            .spawn(move || {
                let mut backoff = AcceptBackoff::new();
                while running.load(Ordering::SeqCst) {
                    let decision = accept_step(
                        session_listener.accept(),
                        Duration::from_millis(10),
                        "session socket",
                        &mut backoff,
                        Instant::now(),
                        true,
                    );
                    if let Some(line) = decision.log {
                        eprintln!("xpf-userspace-dp: {line}");
                    }
                    match decision.step {
                        AcceptStep::Serve((stream, _)) => {
                            // #9003: prove the peer before dispatching. A
                            // connectable session socket installs and reads
                            // sessions.
                            if let Err(err) =
                                reject_unprivileged_peer("session socket", &stream)
                            {
                                eprintln!("xpf-userspace-dp: {err}");
                                continue;
                            }
                            // Log handle_stream failures rather than discarding
                            // them: a request that fails to decode (e.g. a
                            // wire-type mismatch) closes the socket with no
                            // response, and the Go side sees only a bare EOF.
                            // Surfacing the error here turns a silent
                            // multi-session debugging chase into one log line
                            // (#1961).
                            if let Err(err) =
                                handle_stream(
                                    stream,
                                    &state_file,
                                    state.clone(),
                                    running.clone(),
                                    session_domain.clone(),
                                )
                            {
                                eprintln!("xpf-userspace-dp: session request failed: {err}");
                            }
                        }
                        AcceptStep::Sleep(delay) => thread::sleep(delay),
                        // Unreachable with retry_unclassified = true; kept so a
                        // future change to accept_step cannot turn it into a
                        // hot loop or a process exit from this thread.
                        AcceptStep::Fail(msg) => {
                            eprintln!("xpf-userspace-dp: {msg}");
                            thread::sleep(AcceptBackoff::MAX);
                        }
                    }
                }
            })
            .map_err(|e| format!("spawn session thread: {e}"))?
    };

    let mut backoff = AcceptBackoff::new();
    while running.load(Ordering::SeqCst) {
        let decision = accept_step(
            listener.accept(),
            Duration::from_millis(50),
            "control socket",
            &mut backoff,
            Instant::now(),
            false,
        );
        if let Some(line) = decision.log {
            eprintln!("xpf-userspace-dp: {line}");
        }
        match decision.step {
            AcceptStep::Serve((stream, _)) => {
                // #9003: prove the peer before dispatching. This socket carries
                // apply_snapshot — the WireGuard private key and every preshared
                // key — and its handlers run no caller check of their own.
                if let Err(err) = reject_unprivileged_peer("control socket", &stream) {
                    eprintln!("xpf-userspace-dp: {err}");
                    continue;
                }
                // See the session-socket note above: surface decode/handler
                // failures instead of discarding them. This is the socket that
                // carries apply_snapshot, where a wire-type mismatch silently
                // left the helper disabled and forwarding nothing (#1961).
                if let Err(err) =
                    handle_stream(
                        stream,
                        &args.state_file,
                        state.clone(),
                        running.clone(),
                        main_session_domain.clone(),
                    )
                {
                    eprintln!("xpf-userspace-dp: control request failed: {err}");
                }
            }
            AcceptStep::Sleep(delay) => thread::sleep(delay),
            AcceptStep::Fail(msg) => return Err(msg),
        }
    }

    // Wait for the session thread to finish.
    if let Err(panic) = session_thread.join() {
        eprintln!("xpf-userspace-dp: session thread panicked: {panic:?}");
    }
    {
        let mut guard = state.lock().expect("state poisoned");
        guard.afxdp.stop_with_event_stream();
        refresh_status(&mut guard);
    }
    afxdp::remove_kernel_rst_suppression();
    write_state(&args.state_file, &state)?;
    // Shutdown cleanup mirrors the startup guard: remove only our own stale
    // sockets, never a non-socket object (#2974). Keep the existing
    // best-effort posture — a cleanup failure logs a warning and does not
    // fail shutdown.
    if let Err(e) = remove_stale_socket(&args.control_socket) {
        eprintln!(
            "xpf-userspace-dp: control socket cleanup {}: {e}",
            args.control_socket
        );
    }
    if let Err(e) = remove_stale_socket(&session_socket) {
        eprintln!("xpf-userspace-dp: session socket cleanup {session_socket}: {e}");
    }
    Ok(())
}

/// #9172 (V031): what one `accept()` result tells an accept loop to do.
///
/// The control loop used to turn every non-`WouldBlock` accept error into
/// `Err`, which `main` turns into `process::exit(1)` -- and the helper is the
/// only forwarding path. On a listening AF_UNIX socket the errors the kernel's
/// accept path returns under descriptor or memory pressure are EMFILE / ENFILE
/// (no descriptor) and ENOBUFS / ENOMEM (no socket). Exiting on those turned
/// transient pressure into a supervisor crash-loop with up to 60 s of no
/// forwarding per cycle. The session thread had the opposite defect: it
/// `continue`d with no sleep and spun a core on a persistent EMFILE.
///
/// So resource errors are RETRIED on both loops, on a backoff that doubles from
/// 50 ms to a 1 s ceiling, with one journal line when an episode starts and one
/// when a successful accept ends it. There is deliberately NO time bound that
/// exits the helper: a bound on "no successful accept" cannot tell a descriptor
/// leak from fluctuating pressure, because the kernel reserves the result
/// descriptor before looking at the backlog -- an EMPTY listener returns EMFILE
/// at the limit and EAGAIN once one descriptor frees, with no accept in between
/// (measured). Recovering a helper wedged by a genuine leak is issue 9651.
///
/// Any other error is handled per loop, because errno does not say where it came
/// from (an LSM hook runs before `unix_accept` and its errno is propagated
/// unchanged). The CONTROL loop fails on it, which is its behaviour before this
/// change. The SESSION loop retries it the same way: it has no path to end the
/// process, and exiting would take forwarding down with the HA session socket.
///
/// EINTR is deliberately absent: std's `accept` already retries it (`cvt_r`),
/// so it cannot reach this function.
#[derive(Debug)]
pub(crate) enum AcceptStep<T> {
    /// A connection to serve.
    Serve(T),
    /// Nothing to serve yet, or a failure being retried: sleep this long and
    /// accept again.
    Sleep(Duration),
    /// Stop accepting (control loop only).
    Fail(String),
}

/// One accept decision plus the journal line, if any, the loop should write.
/// Returning the line instead of printing it is what lets the log VOLUME be
/// tested: a persistent failure must produce one onset line and no more.
#[derive(Debug)]
pub(crate) struct AcceptDecision<T> {
    pub(crate) step: AcceptStep<T>,
    pub(crate) log: Option<String>,
}

/// Whether an accept error is one the accept path returns under descriptor or
/// memory pressure.
pub(crate) fn accept_error_is_transient(err: &std::io::Error) -> bool {
    matches!(
        err.raw_os_error(),
        Some(libc::EMFILE | libc::ENFILE | libc::ENOBUFS | libc::ENOMEM)
    )
}

/// State across one episode of retried accept failures: a backoff of 50 ms
/// doubling to a 1 s ceiling, reset by the next successful accept.
pub(crate) struct AcceptBackoff {
    failures: u64,
    delay: Duration,
    last_failure: Option<Instant>,
}

impl AcceptBackoff {
    pub(crate) const INITIAL: Duration = Duration::from_millis(50);
    pub(crate) const MAX: Duration = Duration::from_secs(1);
    /// During an episode the loop retries at most [`Self::MAX`] apart. A longer
    /// quiet stretch between two failures means the first episode ended without
    /// a successful accept to say so; the next failure starts a new episode, and
    /// its onset line says so, rather than the ending going unrecorded.
    pub(crate) const EPISODE_GAP: Duration = Duration::from_secs(5);

    pub(crate) fn new() -> Self {
        Self {
            failures: 0,
            delay: Self::INITIAL,
            last_failure: None,
        }
    }

    fn reset(&mut self) {
        self.failures = 0;
        self.delay = Self::INITIAL;
        self.last_failure = None;
    }
}

/// The single decision both accept loops make on every `accept()` result.
/// `idle` is the loop's poll interval for a non-blocking listener with nothing
/// pending. `retry_unclassified` is true for the session loop, which retries
/// every error, and false for the control loop, which fails on an error that is
/// not a resource error. `now` is passed in so the episode logic is testable
/// without sleeping.
pub(crate) fn accept_step<T>(
    result: std::io::Result<T>,
    idle: Duration,
    socket: &str,
    backoff: &mut AcceptBackoff,
    now: Instant,
    retry_unclassified: bool,
) -> AcceptDecision<T> {
    match result {
        Ok(conn) => {
            let log = (backoff.failures > 0).then(|| {
                format!(
                    "accept on {socket} recovered after {} failure(s)",
                    backoff.failures
                )
            });
            backoff.reset();
            AcceptDecision {
                step: AcceptStep::Serve(conn),
                log,
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => AcceptDecision {
            step: AcceptStep::Sleep(idle),
            log: None,
        },
        Err(err) if accept_error_is_transient(&err) || retry_unclassified => {
            let mut ended = None;
            if let Some(last) = backoff.last_failure {
                if now.saturating_duration_since(last) > AcceptBackoff::EPISODE_GAP {
                    ended = Some(backoff.failures);
                    backoff.reset();
                }
            }
            backoff.last_failure = Some(now);
            let log = (backoff.failures == 0).then(|| {
                let kind = if accept_error_is_transient(&err) {
                    "retrying with backoff"
                } else {
                    "retrying with backoff; this loop does not exit the helper"
                };
                match ended {
                    Some(n) => format!(
                        "accept on {socket}: {err}; {kind} (#9172; the previous episode of \
                         {n} failure(s) ended without a successful accept)"
                    ),
                    None => format!("accept on {socket}: {err}; {kind} (#9172)"),
                }
            });
            backoff.failures += 1;
            let delay = backoff.delay;
            backoff.delay = (backoff.delay * 2).min(AcceptBackoff::MAX);
            AcceptDecision {
                step: AcceptStep::Sleep(delay),
                log,
            }
        }
        Err(err) => AcceptDecision {
            step: AcceptStep::Fail(format!("accept on {socket}: {err}")),
            log: None,
        },
    }
}

/// Derive the session socket path from the control socket path.
/// `/run/xpf/userspace-dp.sock` -> `/run/xpf/userspace-dp-sessions.sock`
pub(crate) fn derive_session_socket_path(control_socket: &str) -> String {
    match control_socket.rsplit_once('/') {
        Some((dir, _)) => format!("{}/userspace-dp-sessions.sock", dir),
        None => "userspace-dp-sessions.sock".to_string(),
    }
}

/// Derive the event socket path from the control socket path.
/// `/run/xpf/control.sock` -> `/run/xpf/userspace-dp-events.sock`
pub(crate) fn derive_event_socket_path(control_socket: &str) -> String {
    match control_socket.rsplit_once('/') {
        Some((dir, _)) => format!("{dir}/userspace-dp-events.sock"),
        None => "userspace-dp-events.sock".to_string(),
    }
}

/// #2524: parse and bound the `--ring-entries` CLI value. Accepts a power
/// of two in [1..MAX_RING_ENTRIES]; otherwise returns a clean startup error
/// so an out-of-range value cannot drive an enormous per-binding UMEM
/// preallocation (binding_frame_count_for_driver ~3×ring_entries frames).
/// Independent backstop for the Go commit-time gate (ValidateRingEntries).
fn validate_ring_entries_arg(val: &str) -> Result<usize, String> {
    let parsed = val
        .parse::<usize>()
        .map_err(|e| format!("parse --ring-entries: {e}"))?;
    let max = crate::afxdp::MAX_RING_ENTRIES as usize;
    if parsed < 1 || parsed > max {
        return Err(format!(
            "--ring-entries out of range [1..{max}] (got {parsed})"
        ));
    }
    if parsed & (parsed - 1) != 0 {
        return Err(format!(
            "--ring-entries must be a power of two in [1..{max}] (got {parsed})"
        ));
    }
    Ok(parsed)
}

pub(crate) fn parse_args() -> Result<Args, String> {
    // #9003: default under /run/xpf, NOT under the temp directory. The control
    // socket carries the WireGuard local private key and every per-peer
    // preshared key in cleartext, and a default of
    // `${TMPDIR}/xpf-userspace-dp/control.sock` put it in a subdirectory of a
    // world-writable directory that either side creates on first boot — a
    // directory an unprivileged local user can create FIRST and thereby own.
    // These spellings match the Go control plane's DefaultControlSocket /
    // DefaultStateFile (pkg/dataplane/userspace/socket_trust_9003.go) and the
    // shipped reference configs; the Go side always passes --control-socket
    // explicitly, so this default only governs a hand-run helper.
    let mut control_socket = DEFAULT_CONTROL_SOCKET.to_string();
    let mut state_file = DEFAULT_STATE_FILE.to_string();
    let mut workers = 1usize;
    let mut ring_entries = 4096usize;
    let mut poll_mode = PollMode::BusyPoll;

    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        let val = args
            .next()
            .ok_or_else(|| format!("missing value for argument {arg}"))?;
        match arg.as_str() {
            "--control-socket" => control_socket = val,
            "--state-file" => state_file = val,
            "--workers" => {
                workers = val
                    .parse::<usize>()
                    .map_err(|e| format!("parse --workers: {e}"))?
                    .max(1)
            }
            // #2524: fail-closed at the CLI boundary — reject an
            // out-of-range or non-power-of-two value with a clean startup
            // error instead of letting it drive an enormous per-binding
            // UMEM preallocation. Mirrors the Go commit gate (pkg/config
            // ValidateRingEntries, MaxRingEntries).
            "--ring-entries" => ring_entries = validate_ring_entries_arg(&val)?,
            "--poll-mode" => poll_mode = PollMode::from_str(&val),
            other => return Err(format!("unknown argument {other}")),
        }
    }

    Ok(Args {
        control_socket,
        state_file,
        workers,
        ring_entries,
        poll_mode,
    })
}

#[cfg(test)]
mod ring_entries_tests {
    use super::validate_ring_entries_arg;

    #[test]
    fn accepts_powers_of_two_in_range() {
        for v in ["1", "2", "1024", "4096", "8192", "16384"] {
            assert!(
                validate_ring_entries_arg(v).is_ok(),
                "expected {v} to be accepted"
            );
        }
    }

    #[test]
    fn rejects_over_max() {
        // 16385 = max+1; 32768 / 65536 powers of two above the ceiling.
        for v in ["16385", "32768", "65536"] {
            let err = validate_ring_entries_arg(v).unwrap_err();
            assert!(err.contains("out of range"), "got: {err}");
        }
    }

    #[test]
    fn rejects_non_power_of_two() {
        for v in ["3", "1000", "1023", "12345"] {
            let err = validate_ring_entries_arg(v).unwrap_err();
            assert!(err.contains("power of two"), "got: {err}");
        }
    }

    #[test]
    fn rejects_zero_and_garbage() {
        assert!(validate_ring_entries_arg("0").is_err());
        assert!(validate_ring_entries_arg("asd").is_err());
    }
}

#[cfg(test)]
mod stale_socket_guard_tests {
    // #2974 fail-on-revert: the helper must unlink ONLY a stale Unix socket,
    // never a regular file (or other object) at the configured control/session
    // socket path. Before #2974 the startup/shutdown cleanup did an
    // unconditional `fs::remove_file`, which would silently delete a regular
    // file if the root helper were pointed at a wrong path. The regular-file
    // test below goes RED (the file is deleted, no error) if reverted.
    use super::remove_stale_socket;
    use std::fs;
    use std::os::unix::net::UnixListener;

    fn unique_path(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "xpf-2974-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ))
    }

    #[test]
    fn removes_a_real_socket_and_allows_rebind() {
        let path = unique_path("sock");
        let p = path.to_str().unwrap();
        let _ = fs::remove_file(p);
        // Bind a real Unix socket, then drop the listener so only the inode
        // remains — a stale socket from a "prior run".
        let listener = UnixListener::bind(p).expect("bind socket");
        drop(listener);
        assert!(fs::symlink_metadata(p).is_ok(), "socket inode should exist");

        remove_stale_socket(p).expect("stale socket should be removed");

        assert!(
            fs::symlink_metadata(p).is_err(),
            "stale socket must be gone after remove_stale_socket"
        );
        // A subsequent bind must succeed on the freed path (the happy path).
        let relisten = UnixListener::bind(p).expect("rebind after cleanup");
        drop(relisten);
        let _ = fs::remove_file(p);
    }

    #[test]
    fn refuses_to_delete_a_regular_file() {
        let path = unique_path("regfile");
        let p = path.to_str().unwrap();
        fs::write(p, b"precious operator data").expect("write file");

        let err =
            remove_stale_socket(p).expect_err("a regular file must NOT be removed — fail closed");

        // The core regression assertion: the file must still exist.
        assert!(
            fs::symlink_metadata(p).is_ok(),
            "remove_stale_socket must not delete a regular file"
        );
        let body = fs::read_to_string(p).expect("file readable");
        assert_eq!(body, "precious operator data", "file contents intact");
        let msg = err.to_string();
        assert!(
            msg.contains("regular file") && msg.contains(p),
            "diagnostic must name the path and type, got: {msg}"
        );
        let _ = fs::remove_file(p);
    }

    #[test]
    fn missing_path_is_ok() {
        let path = unique_path("absent");
        let p = path.to_str().unwrap();
        let _ = fs::remove_file(p);
        assert!(fs::symlink_metadata(p).is_err(), "path must be absent");
        remove_stale_socket(p).expect("absent path is a no-op Ok");
    }

    #[test]
    fn refuses_to_delete_a_directory() {
        let path = unique_path("dir");
        let p = path.to_str().unwrap();
        let _ = fs::remove_dir_all(p);
        fs::create_dir_all(p).expect("mkdir");

        let err = remove_stale_socket(p).expect_err("a directory must NOT be removed");
        assert!(fs::symlink_metadata(p).is_ok(), "directory must survive");
        assert!(err.to_string().contains("directory"), "got: {err}");
        let _ = fs::remove_dir_all(p);
    }
}

#[cfg(test)]
mod sockbuf_raise_only_tests {
    // #2970 fail-on-revert: the helper must NEVER lower a socket-buffer
    // sysctl below its current value. Before #2970 `run()` unconditionally
    // wrote 16 MiB to rmem_default/rmem_max, clobbering the 64 MiB the Go
    // control plane had just raised them to. These tests pin the raise-only
    // contract: revert to the unconditional write and they go RED.
    use super::{raise_only_value, raise_sysctl, SOCKBUF_TARGET};
    use std::fs;

    // 16 MiB — the value the pre-#2970 helper unconditionally forced.
    const OLD_FORCED: i64 = 16_777_216;

    #[test]
    fn target_matches_go_control_plane() {
        // Must equal the Go `tuneSocketBuffers` desired (64 MiB) so whichever
        // component runs second is a no-op rather than a downgrade.
        assert_eq!(SOCKBUF_TARGET, 67_108_864);
        // And the old forced value is strictly smaller — the whole point.
        assert!(OLD_FORCED < SOCKBUF_TARGET);
    }

    #[test]
    fn does_not_lower_a_higher_existing_value() {
        // Go raised it to 64 MiB; helper must leave it alone.
        assert_eq!(raise_only_value("67108864", SOCKBUF_TARGET), None);
        // Operator tuned it even higher (128 MiB); must not be lowered.
        assert_eq!(raise_only_value("134217728", SOCKBUF_TARGET), None);
        // Exactly at target — no write.
        assert_eq!(raise_only_value(" 67108864\n", SOCKBUF_TARGET), None);
    }

    #[test]
    fn raises_a_lower_value_to_target() {
        // Kernel default 208 KiB → raised to 64 MiB.
        assert_eq!(raise_only_value("212992", SOCKBUF_TARGET), Some(SOCKBUF_TARGET));
        // The pre-#2970 forced 16 MiB is itself below target → would be raised.
        assert_eq!(raise_only_value("16777216", SOCKBUF_TARGET), Some(SOCKBUF_TARGET));
    }

    #[test]
    fn unparseable_current_is_left_alone() {
        assert_eq!(raise_only_value("garbage", SOCKBUF_TARGET), None);
        assert_eq!(raise_only_value("", SOCKBUF_TARGET), None);
    }

    // End-to-end against a real file: the strongest fail-on-revert guard.
    // If `run()`'s sysctl loop is reverted to an unconditional 16 MiB write,
    // a path pre-seeded with 64 MiB would be clobbered to 16 MiB and this
    // assertion fails.
    #[test]
    fn raise_sysctl_preserves_higher_value_on_disk() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "xpf-2970-rmem-{}-{}",
            std::process::id(),
            // distinguish from the lower-value test below
            "hi"
        ));
        let p = path.to_str().unwrap();
        // Simulate the Go control plane having already raised it to 64 MiB.
        fs::write(p, "67108864").unwrap();

        raise_sysctl(p, SOCKBUF_TARGET);

        let after: i64 = fs::read_to_string(p).unwrap().trim().parse().unwrap();
        let _ = fs::remove_file(p);
        assert_eq!(
            after, 67_108_864,
            "raise_sysctl must NOT lower a value the Go side already raised"
        );
        assert_ne!(
            after, OLD_FORCED,
            "regression: helper lowered rmem back to the pre-#2970 16 MiB"
        );
    }

    #[test]
    fn raise_sysctl_raises_a_low_value() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("xpf-2970-rmem-{}-lo", std::process::id()));
        let p = path.to_str().unwrap();
        // Kernel default, well below target.
        fs::write(p, "212992").unwrap();

        raise_sysctl(p, SOCKBUF_TARGET);

        let after: i64 = fs::read_to_string(p).unwrap().trim().parse().unwrap();
        let _ = fs::remove_file(p);
        assert_eq!(after, SOCKBUF_TARGET, "raise_sysctl must raise a low value to target");
    }
}

/// #9003: the helper side of the control-socket trust contract.
///
/// The socket carries the WireGuard local private key and every per-peer
/// preshared key in cleartext, and `server/handlers/mod.rs` dispatches `ping` /
/// `status` / `apply_snapshot` / `set_forwarding_state` with no caller check —
/// so a connectable socket is dataplane TAKEOVER, not merely key readback.
#[cfg(test)]
mod socket_trust_9003_tests {
    use super::{
        DEFAULT_CONTROL_SOCKET, DEFAULT_STATE_FILE, create_runtime_dir, reject_unprivileged_peer,
        restrict_socket_mode,
    };
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::{UnixListener, UnixStream};

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "xpf-9003-{}-{}-{:?}",
            name,
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn a_bound_socket_is_owner_only_9003() {
        let dir = scratch("mode");
        create_runtime_dir(&dir).expect("create runtime dir");
        let path = dir.join("control.sock").to_string_lossy().to_string();
        let _listener = UnixListener::bind(&path).expect("bind");

        // FAIL-ON-REVERT. Without restrict_socket_mode the socket keeps
        // `0o777 & !umask` — 0755 under the usual 022 — and an unprivileged
        // connect() succeeds. The pre-#9003 safety rested entirely on an
        // inherited umask that no code, unit file or test asserted.
        let before = std::fs::metadata(&path).expect("stat").permissions().mode() & 0o777;
        restrict_socket_mode(&path).expect("restrict mode");
        let after = std::fs::metadata(&path).expect("stat").permissions().mode() & 0o777;
        assert_eq!(
            after, 0o600,
            "bound control socket mode is {after:o}, want 0600 (it was {before:o} before the chmod)"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_created_runtime_dir_has_no_world_bits_9003() {
        let dir = scratch("dirmode");
        create_runtime_dir(&dir).expect("create runtime dir");
        let mode = std::fs::metadata(&dir).expect("stat").permissions().mode() & 0o777;
        assert_eq!(
            mode & 0o007,
            0,
            "runtime dir mode {mode:o} carries world bits; the control socket lives here"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// POSITIVE CONTROL for the SO_PEERCRED read.
    ///
    /// A getsockopt whose failure was swallowed would leave a zeroed `ucred`,
    /// whose uid is 0 — exactly the value the gate ACCEPTS. So "it returned Ok"
    /// proves nothing on its own; this drives a real connection and asserts the
    /// gate accepts it, which is only true if a real credential came back.
    #[test]
    fn a_same_uid_peer_is_accepted_9003() {
        let dir = scratch("peer");
        create_runtime_dir(&dir).expect("create runtime dir");
        let path = dir.join("control.sock").to_string_lossy().to_string();
        let listener = UnixListener::bind(&path).expect("bind");
        let _client = UnixStream::connect(&path).expect("connect");
        let (server_side, _) = listener.accept().expect("accept");
        reject_unprivileged_peer("control socket", &server_side)
            .expect("a connection from this very process must be accepted");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The defaults must agree with the Go control plane, which resolves the
    /// same paths when `system dataplane control-socket` is omitted and then
    /// dials the path IT derived at boot (#1993 armed probe).
    #[test]
    fn defaults_are_not_in_a_temp_directory_9003() {
        for p in [DEFAULT_CONTROL_SOCKET, DEFAULT_STATE_FILE] {
            assert!(
                p.starts_with("/run/xpf/"),
                "default helper path {p} is not under the root-owned runtime directory"
            );
            assert!(
                !p.starts_with(&std::env::temp_dir().to_string_lossy().to_string()),
                "default helper path {p} is under the temp directory — that is the #9003 defect"
            );
        }
    }
}

#[cfg(test)]
mod peer_uid_refusal_9171_tests {
    use super::peer_uid_refusal;

    /// #9171: the peer-credential decision, driven directly.
    ///
    /// The syscall shell around it cannot be exercised unprivileged — a refusal
    /// needs a peer running as a different uid — so before this split the arms
    /// were unreachable from any cell, and a mutation making the whole check
    /// unreachable survived every source-level assertion because the checker's
    /// NAME was still in the file.
    #[test]
    fn peer_uid_decision_table_9171() {
        const SELF: u32 = 1000;
        for (name, uid, want_refusal) in [
            ("root peer is accepted", 0u32, false),
            ("our own uid is accepted", SELF, false),
            ("a FOREIGN uid is refused", 4242u32, true),
            ("uid 1 is refused — non-zero is not privileged", 1u32, true),
            ("a high foreign uid is refused", 65534u32, true),
        ] {
            let got = peer_uid_refusal("event stream socket", uid, 100, 7, SELF);
            assert_eq!(
                got.is_err(),
                want_refusal,
                "{name}: peer_uid_refusal(uid={uid}, self={SELF}) = {got:?}"
            );
            if let Err(msg) = got {
                // Assert the MESSAGE, not merely the refusal: a refusal reached
                // through the wrong arm reads exactly like a working guard.
                assert!(
                    msg.contains(&uid.to_string()),
                    "{name}: refusal must name the offending uid: {msg}"
                );
                assert!(
                    msg.contains("event stream socket"),
                    "{name}: refusal must name which socket: {msg}"
                );
            }
        }
    }

    /// NARROWNESS. `self_uid` is what makes "our own uid" acceptable, so a build
    /// that ignored it would accept every uid. Same peer, different self.
    #[test]
    fn the_self_uid_actually_discriminates_9171() {
        assert!(
            peer_uid_refusal("k", 1000, 0, 1, 1000).is_ok(),
            "uid 1000 must be accepted when we ARE uid 1000"
        );
        assert!(
            peer_uid_refusal("k", 1000, 0, 1, 2000).is_err(),
            "uid 1000 must be refused when we are uid 2000 — otherwise the check \
             compares nothing and accepts anyone"
        );
    }
}

#[cfg(test)]
#[path = "lifecycle_accept_step_tests_9172.rs"]
mod accept_step_tests_9172;
