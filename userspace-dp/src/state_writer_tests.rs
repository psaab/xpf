use super::*;
use std::cell::RefCell;
use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

thread_local! {
    static SYNC_CALLS: AtomicUsize = const { AtomicUsize::new(0) };
    // 1-based index of the fsync call to fail; 0 = never fail.
    static SYNC_FAIL_AT: AtomicUsize = const { AtomicUsize::new(0) };
    // Records, per sync_all call, whether the synced fd was a directory.
    static SYNC_WAS_DIR: RefCell<Vec<bool>> = const { RefCell::new(Vec::new()) };
}

fn fd_is_dir(f: &File) -> bool {
    f.metadata().map(|m| m.is_dir()).unwrap_or(false)
}

/// Test hook: counts every fsync, records whether each was a directory fd,
/// and optionally fails one specific call (1-based) for fault injection.
fn recording_sync(f: &File) -> io::Result<()> {
    let this_call = SYNC_CALLS.with(|c| c.fetch_add(1, AtomicOrdering::Relaxed) + 1);
    SYNC_WAS_DIR.with(|v| v.borrow_mut().push(fd_is_dir(f)));
    let fail_at = SYNC_FAIL_AT.with(|r| r.load(AtomicOrdering::Relaxed));
    if fail_at != 0 && this_call == fail_at {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "injected fsync failure",
        ));
    }
    real_sync_all(f)
}

struct SyncGuard;
impl SyncGuard {
    fn install() -> Self {
        SYNC_CALLS.with(|c| c.store(0, AtomicOrdering::Relaxed));
        SYNC_FAIL_AT.with(|r| r.store(0, AtomicOrdering::Relaxed));
        SYNC_WAS_DIR.with(|v| v.borrow_mut().clear());
        SYNC_ALL_HOOK.with(|h| h.set(recording_sync));
        SyncGuard
    }
    fn calls(&self) -> usize {
        SYNC_CALLS.with(|c| c.load(AtomicOrdering::Relaxed))
    }
    fn dir_syncs(&self) -> usize {
        SYNC_WAS_DIR.with(|v| v.borrow().iter().filter(|&&d| d).count())
    }
    /// Make the `n`th fsync (1-based) fail.
    fn fail_at(&self, n: usize) {
        SYNC_FAIL_AT.with(|r| r.store(n, AtomicOrdering::Relaxed));
    }
}
impl Drop for SyncGuard {
    fn drop(&mut self) {
        SYNC_ALL_HOOK.with(|h| h.set(real_sync_all));
    }
}

thread_local! {
    // Pids the test has marked DEAD (no live process at all); the
    // start-time hook reports None for these, so the instance liveness gate
    // sees a true orphan. Deterministic, no real processes spawned.
    static DEAD_PIDS: RefCell<Vec<u32>> = const { RefCell::new(Vec::new()) };
    // Pids that are LIVE but with a (pid -> current start time) mapping. The
    // start-time hook returns this value, letting a test simulate PID reuse:
    // a still-live pid whose CURRENT start time differs from the one
    // embedded in a stale temp. Any pid not listed and not dead falls back
    // to a default "alive, matching" start time so legacy tests stay simple.
    static LIVE_START_TIMES: RefCell<Vec<(u32, u64)>> = const { RefCell::new(Vec::new()) };
}

/// Deterministic start-time hook driven by the test tables above. A dead pid
/// reports None (no process); a pid with an explicit live start time reports
/// it; any other pid reports a sentinel matching start time so a plain
/// "(pid, start) embedded == live" temp is preserved without per-test setup.
const TEST_DEFAULT_START_TIME: u64 = 9_000_000;
fn test_proc_start_time(pid: u32) -> Option<u64> {
    if DEAD_PIDS.with(|d| d.borrow().contains(&pid)) {
        return None;
    }
    if let Some((_, st)) =
        LIVE_START_TIMES.with(|m| m.borrow().iter().find(|(p, _)| *p == pid).copied())
    {
        return Some(st);
    }
    Some(TEST_DEFAULT_START_TIME)
}

/// Installs deterministic liveness hooks (real instance check over a faked
/// start-time source) for the orphan sweep and lets the test declare
/// specific pids dead or alive-with-a-given-start-time (PID reuse).
/// Restores the real checks on drop.
struct PidGuard;
impl PidGuard {
    fn install() -> Self {
        DEAD_PIDS.with(|d| d.borrow_mut().clear());
        LIVE_START_TIMES.with(|m| m.borrow_mut().clear());
        // Drive the production instance gate (instance_is_alive) through the
        // faked start-time source, so the test exercises the REAL pid+start
        // matching logic rather than a stubbed verdict.
        START_TIME_HOOK.with(|h| h.set(test_proc_start_time));
        PidGuard
    }
    fn mark_dead(&self, pid: u32) {
        DEAD_PIDS.with(|d| d.borrow_mut().push(pid));
    }
    /// Mark `pid` as LIVE but currently running with `start_time` — used to
    /// simulate PID reuse (a stale temp embeds a DIFFERENT start time).
    fn mark_live_with_start(&self, pid: u32, start_time: u64) {
        LIVE_START_TIMES.with(|m| m.borrow_mut().push((pid, start_time)));
    }
    /// The matching start time a temp must embed for a default-live pid to
    /// be preserved.
    fn matching_start() -> u64 {
        TEST_DEFAULT_START_TIME
    }
}
impl Drop for PidGuard {
    fn drop(&mut self) {
        START_TIME_HOOK.with(|h| h.set(real_proc_start_time));
    }
}

fn tmpdir() -> PathBuf {
    let base = std::env::var_os("TMPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp"));
    let unique = format!(
        "xpf-state-writer-test-{}-{:?}",
        std::process::id(),
        thread::current().id()
    );
    let dir = base.join(unique);
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create test dir");
    dir
}

// The durability contract that both modes must honor: exactly the file
// fsync + the parent-directory fsync. If either fsync is deleted from
// finalize_durably, these counts drop and the test fails (#2147 / #1968:
// a durability test must fail if the durable effect is removed).
const EXPECTED_FSYNCS_PER_PERSIST: usize = 2; // temp file + parent dir
const EXPECTED_DIR_FSYNCS_PER_PERSIST: usize = 1; // parent dir

#[test]
fn fallback_persist_fsyncs_file_and_parent_dir() {
    let dir = tmpdir();
    let path = dir.join("state.json");
    let path_str = path.to_str().unwrap();
    let guard = SyncGuard::install();

    persist_sync(path_str, b"hello durable fallback").expect("fallback persist");

    assert_eq!(
        guard.calls(),
        EXPECTED_FSYNCS_PER_PERSIST,
        "fallback path must fsync the temp file AND the parent dir"
    );
    assert_eq!(
        guard.dir_syncs(),
        EXPECTED_DIR_FSYNCS_PER_PERSIST,
        "fallback path must fsync the parent directory after rename"
    );
    assert_eq!(fs::read(&path).unwrap(), b"hello durable fallback");
    let _ = fs::remove_dir_all(&dir);
}

// Decisive regression (#16048): the published state file — and any temp that
// could be observed before the rename — must be owner-only 0600, not
// `0666 & umask` (0644 under umask 022). The parent dir is forced to 0755
// and the process umask to 000 (the worst case the issue allows: a
// pre-existing 0755 dir plus a hostile umask) so this test cannot pass by
// inheriting a restrictive ambient umask. Removing `.mode(0o600)` from
// `open_state_temp` makes both results 0666 here,
// turning both transport assertions RED. umask is process-global, so
// the value is restored on every exit path via the guard below (the same
// restore-on-drop discipline as SyncGuard/PidGuard above).
struct UmaskGuard(libc::mode_t);

impl UmaskGuard {
    fn install(mask: libc::mode_t) -> Self {
        // SAFETY: umask(2) always succeeds; it only swaps the mask.
        Self(unsafe { libc::umask(mask) })
    }
}

impl Drop for UmaskGuard {
    fn drop(&mut self) {
        // SAFETY: umask(2) always succeeds; restoring the prior mask.
        unsafe { libc::umask(self.0) };
    }
}

fn file_mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(path).expect("stat file").permissions().mode() & 0o777
}

#[test]
fn persisted_state_file_is_0600_under_umask_000_in_0755_dir() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tmpdir();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).expect("chmod dir 0755");
    let _umask = UmaskGuard::install(0);

    // Sync transport: pre-create the destination world-readable. The atomic
    // rename must REPLACE it with the temp's 0600 mode, not preserve the
    // destination's old (readable) mode.
    let dest = dir.join("state.json");
    fs::write(&dest, b"previous world-readable state").unwrap();
    fs::set_permissions(&dest, fs::Permissions::from_mode(0o644)).expect("chmod dest 0644");
    persist_sync(dest.to_str().unwrap(), b"sync state").expect("sync persist");
    assert_eq!(
        file_mode(&dest),
        0o600,
        "sync-published state file must be 0600 under umask 000 in a 0755 dir"
    );
    assert_eq!(fs::read(&dest).unwrap(), b"sync state");

    // The temp itself is 0600 from creation: a leaked/orphaned temp (crash
    // between create and rename) must never be world-readable either.
    let tmp = dir.join("state.json.inflight.tmp");
    let _tmp_file = open_state_temp(&tmp).expect("create state temp");
    assert_eq!(
        file_mode(&tmp),
        0o600,
        "state temp file must be created 0600, not 0666 & umask"
    );
    drop(_tmp_file);
    let _ = fs::remove_file(&tmp);

    // io_uring transport: same published mode through the other creator.
    // Skip (not pass silently) only when the kernel cannot provide a ring,
    // mirroring the demotion test — the sync assertions above still ran.
    let ring = match crate::io_uring_write::RingWriter::new(8) {
        Ok(r) => r,
        Err(_) => {
            eprintln!("io_uring unavailable on this kernel; sync mode assertions already ran");
            let _ = fs::remove_dir_all(&dir);
            return;
        }
    };
    let ring_dest = dir.join("state-ring.json");
    fs::write(&ring_dest, b"previous world-readable state").unwrap();
    fs::set_permissions(&ring_dest, fs::Permissions::from_mode(0o644))
        .expect("chmod ring dest 0644");
    let mut mode = WriteMode::IoUring(ring);
    let outcome = persist_with_mode(
        &mut mode,
        ring_dest.to_str().unwrap(),
        b"ring state".to_vec(),
    );
    assert!(
        outcome.result.is_ok(),
        "io_uring persist failed: {:?}",
        outcome.result
    );
    assert_eq!(
        file_mode(&ring_dest),
        0o600,
        "io_uring-published state file must be 0600 under umask 000 in a 0755 dir"
    );
    assert_eq!(fs::read(&ring_dest).unwrap(), b"ring state");

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn finalize_durably_fsyncs_file_and_parent_dir() {
    // Drive the shared finalizer directly so the test pins the contract
    // both transports route through, independent of write mechanism.
    let dir = tmpdir();
    let dest = dir.join("snap.json");
    let dest_str = dest.to_str().unwrap();
    let tmp = temporary_path(dest_str);
    let guard = SyncGuard::install();

    let file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&tmp)
        .unwrap();
    {
        use io::Write;
        (&file).write_all(b"payload").unwrap();
    }
    finalize_durably(&file, &tmp, dest_str).expect("finalize");

    assert_eq!(guard.calls(), EXPECTED_FSYNCS_PER_PERSIST);
    assert_eq!(guard.dir_syncs(), EXPECTED_DIR_FSYNCS_PER_PERSIST);
    assert!(!tmp.exists(), "temp file must be renamed away");
    assert_eq!(fs::read(&dest).unwrap(), b"payload");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn file_fsync_failure_is_propagated_and_does_not_rename() {
    // First fsync is the temp file. If it fails, the rename must NOT run —
    // the destination must keep its prior contents.
    let dir = tmpdir();
    let dest = dir.join("state.json");
    let dest_str = dest.to_str().unwrap();
    fs::write(&dest, b"previous-good").unwrap();

    let guard = SyncGuard::install();
    guard.fail_at(1); // 1st fsync = temp file

    let err = persist_sync(dest_str, b"new-data").expect_err("file fsync should fail");
    assert!(
        err.contains("sync temp state file"),
        "unexpected error: {err}"
    );
    assert_eq!(
        fs::read(&dest).unwrap(),
        b"previous-good",
        "destination must be untouched when the temp-file fsync fails"
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn temporary_path_is_unique_per_call_for_same_dest() {
    // The core #2705 invariant: two writes targeting the SAME destination
    // must get DISTINCT temp paths so they can never open/truncate/write the
    // same temp file and publish crossed bytes under a successful rename.
    // With the old deterministic `<dest>.tmp` both calls returned the same
    // path and this assertion goes RED (fail-on-revert).
    let dest = "/tmp/xpf-state-uniq/state.json";
    let a = temporary_path(dest);
    let b = temporary_path(dest);
    assert_ne!(
        a, b,
        "two writes to the same dest must use distinct temp paths (got {a:?} twice)"
    );
    // Still a recognizable sibling of the destination, in the same dir.
    assert_eq!(a.parent(), Path::new(dest).parent());
    assert_eq!(b.parent(), Path::new(dest).parent());
    for p in [&a, &b] {
        let name = p.file_name().unwrap().to_str().unwrap();
        assert!(
            name.starts_with("state.json."),
            "unexpected temp name: {name}"
        );
        assert!(name.ends_with(".tmp"), "unexpected temp name: {name}");
    }
    // Extension-less destinations also get a unique temp.
    let c = temporary_path("/tmp/xpf-state-uniq/state");
    let d = temporary_path("/tmp/xpf-state-uniq/state");
    assert_ne!(c, d, "extension-less dest must also get unique temp paths");
}

#[test]
fn two_concurrent_writers_never_publish_crossed_bytes() {
    // Simulate two writers (two logical "processes"/instances) racing the
    // same destination. Each writes a distinct, self-describing payload many
    // times. Because every write uses a private O_EXCL temp + atomic rename,
    // the destination must ALWAYS contain exactly one writer's COMPLETE
    // payload — never a mix. With a shared deterministic temp, the open(+
    // truncate)/write/rename sequences could interleave and publish crossed
    // bytes; here that is impossible.
    let dir = tmpdir();
    let dest = dir.join("state.json");
    let dest_str = dest.to_str().unwrap().to_string();

    // Two payloads of equal length, each internally consistent.
    let payload_a = vec![b'A'; 64 * 1024];
    let payload_b = vec![b'B'; 64 * 1024];

    let iters = 200usize;
    let d_a = dest_str.clone();
    let p_a = payload_a.clone();
    let d_b = dest_str.clone();
    let p_b = payload_b.clone();

    let h_a = thread::spawn(move || {
        for _ in 0..iters {
            persist_sync(&d_a, &p_a).expect("writer A persist");
        }
    });
    let h_b = thread::spawn(move || {
        for _ in 0..iters {
            persist_sync(&d_b, &p_b).expect("writer B persist");
        }
    });
    h_a.join().unwrap();
    h_b.join().unwrap();

    // The final file must be exactly one writer's complete payload.
    let final_bytes = fs::read(&dest).unwrap();
    assert!(
        final_bytes == payload_a || final_bytes == payload_b,
        "final file is neither complete payload (len={}, first byte={:?}) — crossed bytes",
        final_bytes.len(),
        final_bytes.first()
    );

    // No private temp files leaked: only the destination should remain.
    let leftovers: Vec<_> = fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n != "state.json")
        .collect();
    assert!(
        leftovers.is_empty(),
        "temp files leaked after concurrent writes: {leftovers:?}"
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn failed_write_cleans_up_its_unique_temp() {
    // A unique temp is never renamed on failure, so it must be removed or it
    // would accumulate. Inject a temp-file fsync failure and assert no temp
    // sibling is left behind in the directory.
    let dir = tmpdir();
    let dest = dir.join("state.json");
    let dest_str = dest.to_str().unwrap();

    let guard = SyncGuard::install();
    guard.fail_at(1); // temp-file fsync fails -> no rename, temp must be cleaned

    let err = persist_sync(dest_str, b"doomed").expect_err("write should fail");
    assert!(
        err.contains("sync temp state file"),
        "unexpected error: {err}"
    );

    let leftovers: Vec<_> = fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    assert!(
        leftovers.is_empty(),
        "failed write must clean up its unique temp; found: {leftovers:?}"
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn parent_dir_fsync_failure_is_propagated() {
    // Let the file fsync succeed but fail the directory fsync (the 2nd
    // call). The error must surface so a caller never believes a snapshot
    // is durable when the rename may be lost on power loss.
    let dir = tmpdir();
    let dest = dir.join("state.json");
    let dest_str = dest.to_str().unwrap();

    let guard = SyncGuard::install();
    guard.fail_at(2); // 2nd fsync = parent dir

    let err = persist_sync(dest_str, b"data").expect_err("parent dir fsync should fail");
    assert!(err.contains("fsync parent dir"), "unexpected error: {err}");
    // Both fsyncs were attempted (file succeeded, dir failed) -> 2 calls.
    assert_eq!(guard.calls(), 2);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn instance_from_temp_name_parses_our_format_only() {
    // `<stem>.<pid>_<start>.<seq>.tmp` and `<stem>.<ext>.<pid>_<start>.<seq>.tmp`.
    assert_eq!(
        instance_from_temp_name("state.1234_777.0.tmp"),
        Some(ProcInstance {
            pid: 1234,
            start_time: 777
        })
    );
    assert_eq!(
        instance_from_temp_name("state.json.999_42.7.tmp"),
        Some(ProcInstance {
            pid: 999,
            start_time: 42
        })
    );
    // Foreign / non-matching names must NOT be parsed (so they are skipped).
    assert_eq!(instance_from_temp_name("state.json"), None);
    assert_eq!(instance_from_temp_name("state.tmp"), None); // no inst.seq
    assert_eq!(instance_from_temp_name("state.0.tmp"), None); // only one comp
    // Legacy bare-pid temps (no `_<starttime>`) are no longer ours (#2957).
    assert_eq!(instance_from_temp_name("state.1234.0.tmp"), None);
    assert_eq!(instance_from_temp_name("state.json.999.42.tmp"), None);
    // Instance component malformed.
    assert_eq!(instance_from_temp_name("state.abc_777.0.tmp"), None); // pid not numeric
    assert_eq!(instance_from_temp_name("state.1234_abc.0.tmp"), None); // start not numeric
    assert_eq!(instance_from_temp_name("state.1234_.0.tmp"), None); // empty start
    assert_eq!(instance_from_temp_name("state._777.0.tmp"), None); // empty pid
    assert_eq!(instance_from_temp_name("state.1234.def.tmp"), None); // seq not numeric (and no _)
    assert_eq!(instance_from_temp_name(".1234_777.0.tmp"), None); // empty stem
}

// Fail-on-revert (#2714): a dead-pid orphan must be swept while a live
// writer's in-flight temp (and unrelated files) are preserved. Reverting the
// sweep (sweep_stale_temps a no-op) leaves the orphan and fails this test.
#[test]
fn sweep_removes_dead_pid_orphan_preserves_live_and_foreign() {
    let dir = tmpdir();
    let dest = dir.join("state.json");
    let dest_str = dest.to_str().unwrap();
    let st = PidGuard::matching_start();

    // Orphan from a CRASHED writer (dead pid) — must be removed.
    let dead_pid = 4242u32;
    let dead_orphan = dir.join(format!("state.json.{dead_pid}_{st}.7.tmp"));
    fs::write(&dead_orphan, b"crashed mid-write").unwrap();

    // In-flight temp of a LIVE other writer (#2705 hazard) — must survive.
    let live_pid = 5151u32;
    let live_temp = dir.join(format!("state.json.{live_pid}_{st}.3.tmp"));
    fs::write(&live_temp, b"another writer in flight").unwrap();

    // A temp for a DIFFERENT destination, dead pid — out of scope, survives.
    let other_dest_temp = dir.join(format!("other.json.{dead_pid}_{st}.1.tmp"));
    fs::write(&other_dest_temp, b"other dest").unwrap();

    // A foreign .tmp not matching our instance format — survives.
    let foreign = dir.join("state.json.backup.tmp");
    fs::write(&foreign, b"foreign").unwrap();

    // A LEGACY bare-pid temp (pre-#2957, no `_<starttime>`) — not ours under
    // the new scheme, so it is left untouched.
    let legacy = dir.join(format!("state.json.{dead_pid}.9.tmp"));
    fs::write(&legacy, b"legacy bare-pid temp").unwrap();

    // An existing published destination — never a sweep candidate.
    fs::write(&dest, b"existing good state").unwrap();

    let pids = PidGuard::install();
    pids.mark_dead(dead_pid); // live_pid stays alive (default matching start)

    sweep_stale_temps(dest_str);

    assert!(
        !dead_orphan.exists(),
        "dead-pid orphan must be swept (revert -> still present, RED)"
    );
    assert!(
        live_temp.exists(),
        "a live writer's in-flight temp must be preserved (#2705)"
    );
    assert!(
        other_dest_temp.exists(),
        "a temp for a different destination must be out of scope"
    );
    assert!(
        foreign.exists(),
        "a non-format foreign .tmp must be preserved"
    );
    assert!(
        legacy.exists(),
        "a legacy bare-pid temp is not a candidate under the instance scheme"
    );
    assert!(
        dest.exists(),
        "the published destination must never be touched"
    );
    assert_eq!(fs::read(&dest).unwrap(), b"existing good state");

    let _ = fs::remove_dir_all(&dir);
}

// Fail-on-revert (#2957): the orphan-temp identity must be pid + process
// START TIME, not the bare pid. A stale temp left by a CRASHED writer whose
// pid has since been REUSED by an unrelated live process must STILL be
// swept — the reused process's start time differs from the one embedded in
// the orphan's name. With the old bare-pid keying (`pid_is_alive(pid)`),
// `/proc/<reused-pid>` exists so the sweep PRESERVES the orphan forever;
// this test then goes RED (orphan still present). A genuinely-live writer
// (pid AND start time match) is still preserved.
#[test]
fn sweep_removes_orphan_whose_pid_was_reused_by_another_process() {
    let dir = tmpdir();
    let dest = dir.join("state.json");
    let dest_str = dest.to_str().unwrap();

    // The crashed writer ran as pid 7000 with start time 100. Its orphan
    // temp encodes that exact instance.
    let crashed_pid = 7000u32;
    let crashed_start = 100u64;
    let reuse_orphan = dir.join(format!("state.json.{crashed_pid}_{crashed_start}.5.tmp"));
    fs::write(&reuse_orphan, b"crashed, pid later reused").unwrap();

    // A genuinely-live writer (pid 8000, start 200) — its in-flight temp
    // encodes its real, currently-running instance and must survive.
    let live_pid = 8000u32;
    let live_start = 200u64;
    let live_temp = dir.join(format!("state.json.{live_pid}_{live_start}.2.tmp"));
    fs::write(&live_temp, b"live writer in flight").unwrap();

    let pids = PidGuard::install();
    // pid 7000 is LIVE again (reused) but now started at a DIFFERENT time
    // (999) than the orphan's embedded start (100) — the impostor.
    pids.mark_live_with_start(crashed_pid, 999);
    // pid 8000 is live with the SAME start time its temp embeds.
    pids.mark_live_with_start(live_pid, live_start);

    sweep_stale_temps(dest_str);

    assert!(
        !reuse_orphan.exists(),
        "orphan whose pid was reused (different start time) must be swept \
             (bare-pid keying preserves it -> RED)"
    );
    assert!(
        live_temp.exists(),
        "a genuinely-live writer's temp (pid+start match) must be preserved"
    );

    let _ = fs::remove_dir_all(&dir);
}

// Fail-on-revert (#3009): the self-process shortcut in `instance_is_alive`
// must match the FULL instance (pid AND start time), not the bare pid. The
// #2957 PID-reuse fix left a residual: if a crashed writer's pid is recycled
// as the CURRENT helper's pid, the orphan temp embeds (our pid, the dead
// writer's start time). A bare-pid self-shortcut returns `true` for it and
// pins the dead writer's debris for the rest of our lifetime — exactly the
// PID-reuse hazard #2957 set out to close, for the one pid equal to ours.
//
// This test drives the real `instance_is_alive`/sweep gate:
//   * a recycled-pid orphan (pid == OUR pid, but a DIFFERENT embedded start
//     time) MUST be swept;
//   * our OWN genuine in-flight temp (pid AND start time == self) MUST be
//     preserved.
// With the bare-pid shortcut (`inst.pid == self_instance().pid`) the orphan
// is preserved and the first assertion goes RED.
#[test]
fn sweep_removes_self_pid_orphan_with_mismatched_start_time() {
    let dir = tmpdir();
    let dest = dir.join("state.json");
    let dest_str = dest.to_str().unwrap();

    let me = self_instance();

    // A crashed predecessor whose pid Linux later recycled as ours: the
    // orphan embeds OUR pid but the predecessor's start time. Guard against
    // the (vanishingly unlikely) case where our real start time is 0 or
    // collides with the chosen impostor value.
    let impostor_start = if me.start_time == 0 { 1 } else { 0 };
    let recycled_orphan = dir.join(format!("state.json.{}_{impostor_start}.5.tmp", me.pid));
    fs::write(&recycled_orphan, b"crashed predecessor, our pid recycled").unwrap();

    // Our OWN in-flight temp: pid AND start time match self exactly.
    let self_temp = dir.join(format!("state.json.{}_{}.2.tmp", me.pid, me.start_time));
    fs::write(&self_temp, b"our genuine in-flight write").unwrap();

    let pids = PidGuard::install();
    // Our pid is, of course, LIVE — and `/proc` reports OUR real start time.
    // The recycled orphan's embedded start (impostor_start) therefore does
    // not match, so the normal (pid,start) gate must sweep it; our own temp
    // (start == me.start_time) must survive.
    pids.mark_live_with_start(me.pid, me.start_time);

    sweep_stale_temps(dest_str);

    assert!(
        !recycled_orphan.exists(),
        "an orphan with OUR pid but a mismatched start time must be swept \
             (bare-pid self-shortcut preserves it -> RED)"
    );
    assert!(
        self_temp.exists(),
        "our own in-flight temp (pid+start match self) must be preserved"
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn persist_sweeps_stale_orphan_before_write() {
    // End-to-end through persist_sync's caller-visible effect: pre-seed a
    // dead-pid orphan, then drive a real write; the sweep that the writer
    // runs once per destination must have removed the orphan, leaving only
    // the freshly published destination.
    let dir = tmpdir();
    let dest = dir.join("state.json");
    let dest_str = dest.to_str().unwrap();

    let dead_pid = 31337u32;
    let dead_start = PidGuard::matching_start();
    let orphan = dir.join(format!("state.json.{dead_pid}_{dead_start}.0.tmp"));
    fs::write(&orphan, b"leaked").unwrap();

    let pids = PidGuard::install();
    pids.mark_dead(dead_pid);

    // Mirror the writer-thread contract: sweep once for this destination,
    // then persist.
    sweep_stale_temps(dest_str);
    persist_sync(dest_str, b"fresh state").expect("persist");

    let leftovers: Vec<_> = fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(
        leftovers,
        vec!["state.json".to_string()],
        "only the published destination should remain after sweep+write"
    );
    assert_eq!(fs::read(&dest).unwrap(), b"fresh state");
    let _ = fs::remove_dir_all(&dir);
}

// Fail-on-revert (#2958): a RUNTIME io_uring write failure must DEMOTE the
// writer to sync — permanently — so (a) the reported mode flips to "sync"
// and active=false, (b) the demotion cause is recorded as last_error, and
// (c) every subsequent write takes the sync branch and never re-submits to
// the broken ring. Reverting the demotion (leaving *mode = IoUring) makes
// the post-failure assertions RED: the mode stays IoUring and a later write
// still reports io_uring_failed=true.
#[test]
fn runtime_io_uring_failure_demotes_to_sync_permanently() {
    let dir = tmpdir();
    let dest = dir.join("state.json");
    let dest_str = dest.to_str().unwrap().to_string();

    // Construct a writer in io_uring mode. If the kernel cannot provide a
    // ring (older CI), the demotion path is unreachable, so skip rather than
    // give a false pass — production always starts in io_uring when a ring
    // is available, which is the scenario this regression guards.
    let ring = match crate::io_uring_write::RingWriter::new(8) {
        Ok(r) => r,
        Err(_) => {
            eprintln!("io_uring unavailable on this kernel; skipping demotion test");
            return;
        }
    };
    let mut mode = WriteMode::IoUring(ring);

    // Mirror the StateWriter startup state: active + mode reflect io_uring.
    let active = AtomicBool::new(true);
    let mode_str = Mutex::new(String::from("io_uring"));
    let last_error = Mutex::new(String::new());

    // Simulate the writer loop receiving an io_uring transport failure whose
    // sync fallback succeeded — exactly what persist_with_mode produces on a
    // runtime ring failure.
    let demotion_cause = "io_uring write failed, demoting to sync: injected".to_string();
    let outcome = PersistOutcome {
        result: Ok(()),
        io_uring_failed: true,
        demotion_cause: Some(demotion_cause.clone()),
    };
    let res = apply_outcome(outcome, &mut mode, &active, &mode_str, &last_error);
    assert!(res.is_ok(), "sync fallback succeeded, write must report Ok");

    // (a) mode demoted.
    assert!(
        matches!(mode, WriteMode::SyncFallback),
        "runtime io_uring failure must demote WriteMode to SyncFallback"
    );
    // (b) reported status reflects sync.
    assert!(
        !active.load(Ordering::Relaxed),
        "status.active must be false after demotion"
    );
    assert_eq!(
        *mode_str.lock().unwrap(),
        "sync",
        "status.mode must report sync after demotion"
    );
    assert_eq!(
        *last_error.lock().unwrap(),
        demotion_cause,
        "last_error must record the demotion cause"
    );

    // (c) no further io_uring attempts: a subsequent write now goes through
    // the sync branch (io_uring_failed=false) and actually persists. With
    // the demotion reverted, `mode` would still be IoUring here and this
    // write would route through the ring.
    let next = persist_with_mode(&mut mode, &dest_str, b"after demotion".to_vec());
    assert!(next.result.is_ok(), "post-demotion write must succeed");
    assert!(
        !next.io_uring_failed,
        "post-demotion write must NOT touch io_uring (must take the sync branch)"
    );
    assert!(
        matches!(mode, WriteMode::SyncFallback),
        "mode must stay sync for the writer's lifetime (no flapping)"
    );
    assert_eq!(fs::read(&dest).unwrap(), b"after demotion");

    let _ = fs::remove_dir_all(&dir);
}
