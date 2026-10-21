use crate::io_uring_write::{RingWriter, WriteResult};
use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;

/// Durability seam: fsync a [`File`]. Indirected through a function pointer so
/// crash-safety unit tests can record calls (and so a test FAILS if the fsync
/// is removed from the durable finalizer). Production always uses
/// [`real_sync_all`].
#[cfg(test)]
type SyncAllFn = fn(&File) -> io::Result<()>;

fn real_sync_all(f: &File) -> io::Result<()> {
    f.sync_all()
}

#[cfg(test)]
thread_local! {
    static SYNC_ALL_HOOK: std::cell::Cell<SyncAllFn> = const { std::cell::Cell::new(real_sync_all) };
}

#[cfg(test)]
fn sync_all(f: &File) -> io::Result<()> {
    SYNC_ALL_HOOK.with(|h| (h.get())(f))
}

#[cfg(not(test))]
#[inline]
fn sync_all(f: &File) -> io::Result<()> {
    real_sync_all(f)
}

/// Mode for every state-file temp, and therefore for the published state file
/// (`finalize_durably` renames the temp onto the destination, carrying the
/// temp's mode). The persisted payload clones the entire snapshot — topology,
/// policy, NAT, routes, tunnel endpoints — so it is owner-only, asserted at
/// creation rather than inherited from the process umask (#16048). With
/// `create_new` (O_EXCL) the temp is always freshly created here, so
/// `.mode()` always applies: `0o600 & !umask` can only narrow it further,
/// never widen it past 0600. Both transports create their temps through
/// [`open_state_temp`] so neither can drift from this mode.
const STATE_FILE_MODE: u32 = 0o600;

/// Create one write's private temp file with [`STATE_FILE_MODE`]. This is
/// the single creation site for both transports (io_uring and the sync
/// fallback); a temp created any other way would silently fall back to
/// `0666 & umask` (0644 under umask 022) and publish that mode on rename.
fn open_state_temp(tmp: &Path) -> io::Result<File> {
    OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(STATE_FILE_MODE)
        .open(tmp)
}

/// A writer's *process instance* identity: its pid PLUS its process start time
/// (`/proc/<pid>/stat` field 22, clock ticks since boot). The pid alone is NOT
/// a stable identity across a crash — Linux recycles pids, so after the helper
/// crashes an unrelated process can be assigned the crashed writer's pid before
/// the next helper starts. Pairing the pid with the start time disambiguates a
/// genuinely-live original writer from a reused-pid impostor: the start time of
/// the original process can never be reproduced by a later process on the same
/// pid (the start-time monotonically advances with each fork). This is the
/// identity embedded in temp names and checked by the orphan sweep (#2957).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ProcInstance {
    pid: u32,
    /// Process start time in clock ticks since boot (`/proc/<pid>/stat` field
    /// 22). 0 is a sentinel meaning "unknown" — used only when the start time
    /// could not be read, and is never matched against a live process (an
    /// unknown-start-time temp is treated as orphaned once its pid is dead).
    start_time: u64,
}

/// Read the process start time (clock ticks since boot) from `/proc/<pid>/stat`
/// field 22. The stat line is `pid (comm) state ...` where `comm` can itself
/// contain spaces and parentheses, so we split AFTER the last ')' to skip the
/// comm field, then count whitespace-separated fields. After the last ')' the
/// next field is `state` (field 3), so field 22 (starttime) is index 19 in the
/// post-comm split. Returns `None` if the process is gone or the stat is
/// unparseable.
fn real_proc_start_time(pid: u32) -> Option<u64> {
    let stat = fs::read_to_string(Path::new("/proc").join(pid.to_string()).join("stat")).ok()?;
    // `comm` is wrapped in parentheses and may contain ')' itself; the kernel
    // guarantees the FINAL ')' terminates comm. Everything after it is a clean
    // whitespace-separated field list starting at `state` (field 3).
    let after_comm = &stat[stat.rfind(')')? + 1..];
    // Fields after comm, 0-indexed: 0=state(3) ... 19=starttime(22).
    after_comm.split_whitespace().nth(19)?.parse::<u64>().ok()
}

/// Start-time seam: indirected through a function pointer so the orphan-temp
/// sweep's PID-reuse handling can be tested deterministically (a test can make
/// a still-live pid report a DIFFERENT start time than the one embedded in a
/// stale temp, simulating pid reuse, without spawning real processes). A test
/// FAILS if the start-time match is removed from the liveness gate. Production
/// always uses [`real_proc_start_time`].
#[cfg(test)]
type StartTimeFn = fn(u32) -> Option<u64>;

#[cfg(test)]
thread_local! {
    static START_TIME_HOOK: std::cell::Cell<StartTimeFn> =
        const { std::cell::Cell::new(real_proc_start_time) };
}

/// Single seam through which all liveness start-time lookups route, so a test
/// can fake a pid's current start time (simulating PID reuse) and so the gate
/// below is exercised against that fake rather than real `/proc`.
#[cfg(test)]
fn lookup_start_time(pid: u32) -> Option<u64> {
    START_TIME_HOOK.with(|h| (h.get())(pid))
}

#[cfg(not(test))]
#[inline]
fn lookup_start_time(pid: u32) -> Option<u64> {
    real_proc_start_time(pid)
}

/// This process's own instance identity (pid + start time), computed once. Used
/// both to name our temps and to short-circuit the sweep's liveness check for
/// our own in-flight temps regardless of any `/proc` visibility quirk. Reads the
/// real start time (never the test seam) — our own identity is fixed.
fn self_instance() -> ProcInstance {
    use std::sync::OnceLock;
    static SELF: OnceLock<ProcInstance> = OnceLock::new();
    *SELF.get_or_init(|| {
        let pid = std::process::id();
        ProcInstance {
            pid,
            start_time: real_proc_start_time(pid).unwrap_or(0),
        }
    })
}

/// A writer instance is "alive" only if a process with the embedded pid exists
/// AND its current start time matches the embedded start time (#2957). This is
/// the concurrency-safety gate for the orphan sweep (#2714): the
/// unique-per-write temp scheme leaks `<dest>.<pid>_<starttime>.<seq>.tmp` on a
/// crash between create and rename, but a naive glob-sweep would re-introduce
/// the #2705 cross-writer hazard by deleting a still-live OTHER writer's
/// in-flight temp. Matching on pid alone is unsafe: after a crash Linux can
/// recycle the pid, and a bare-pid check would then preserve the dead writer's
/// orphan as if a live process still held it, pinning crash debris for the rest
/// of the helper's lifetime. Requiring the start time to match too means a
/// reused pid (different start time) is correctly treated as a dead instance
/// and its orphan is swept, while a genuinely-live writer (pid AND start time
/// match) is always preserved.
fn instance_is_alive(inst: ProcInstance) -> bool {
    // The writer's own process is always alive; never treat its in-flight temps
    // as orphans regardless of /proc visibility quirks or start-time read races.
    // The shortcut MUST match the FULL instance (pid AND start time), not the
    // bare pid: after our predecessor crashed, Linux can recycle its pid as OUR
    // pid. A stale orphan then embeds (our pid, the predecessor's start time).
    // A bare-pid shortcut would preserve that recycled-pid debris forever — the
    // exact PID-reuse hazard #2957 closed, re-opened for the one pid that equals
    // ours (#3009). Comparing the whole instance preserves only our genuine
    // in-flight temp (pid AND start time match) and lets the normal path below
    // sweep a recycled-pid orphan (same pid, different embedded start time).
    if inst == self_instance() {
        return true;
    }
    match lookup_start_time(inst.pid) {
        // pid exists; preserve ONLY if it is the SAME process instance. A temp
        // whose embedded start time is the "unknown" sentinel (0) can never
        // match a real start time, so it is treated as orphaned once we reach
        // here (its original owner is gone — a live owner would carry its real
        // start time). PID reuse (live pid, different start time) -> not alive.
        Some(now) => now == inst.start_time && inst.start_time != 0,
        // No such process -> the writer is gone, the temp is a true orphan.
        None => false,
    }
}

enum WriteMode {
    IoUring(RingWriter),
    SyncFallback,
}

struct WriteRequest {
    path: String,
    data: Vec<u8>,
    resp: mpsc::Sender<Result<(), String>>,
}

#[derive(Clone, Debug, Default)]
pub struct WriterStatus {
    pub active: bool,
    pub mode: String,
    pub last_error: String,
}

pub struct StateWriter {
    tx: mpsc::Sender<WriteRequest>,
    active: Arc<AtomicBool>,
    mode: Arc<Mutex<String>>,
    last_error: Arc<Mutex<String>>,
}

impl StateWriter {
    pub fn new() -> Self {
        let (tx, rx) = mpsc::channel::<WriteRequest>();
        let active = Arc::new(AtomicBool::new(false));
        let mode = Arc::new(Mutex::new(String::from("sync")));
        let last_error = Arc::new(Mutex::new(String::new()));

        let active_bg = active.clone();
        let mode_bg = mode.clone();
        let last_error_bg = last_error.clone();
        thread::Builder::new()
            .name("xpf-state-writer".to_string())
            .spawn(move || {
                let mut write_mode = match RingWriter::new(8) {
                    Ok(ring) => {
                        active_bg.store(true, Ordering::Relaxed);
                        if let Ok(mut m) = mode_bg.lock() {
                            *m = "io_uring".to_string();
                        }
                        WriteMode::IoUring(ring)
                    }
                    Err(err) => {
                        if let Ok(mut m) = mode_bg.lock() {
                            *m = "sync".to_string();
                        }
                        if let Ok(mut last) = last_error_bg.lock() {
                            *last = format!("io_uring unavailable: {err}");
                        }
                        WriteMode::SyncFallback
                    }
                };

                // Destinations whose stale-orphan sweep has already run this
                // process lifetime. The sweep removes `<dest>.<pid>.<seq>.tmp`
                // leaked by a crash between create and rename (#2714); running
                // it once per distinct destination keeps it off the per-write
                // hot path while still cleaning up at process start.
                let mut swept: HashSet<String> = HashSet::new();

                while let Ok(req) = rx.recv() {
                    if swept.insert(req.path.clone()) {
                        sweep_stale_temps(&req.path);
                    }
                    let outcome = persist_with_mode(&mut write_mode, &req.path, req.data);
                    let result = apply_outcome(
                        outcome,
                        &mut write_mode,
                        &active_bg,
                        &mode_bg,
                        &last_error_bg,
                    );
                    let _ = req.resp.send(result);
                }
            })
            .expect("start state writer thread");

        Self {
            tx,
            active,
            mode,
            last_error,
        }
    }

    pub fn persist(&self, path: &str, data: Vec<u8>) -> Result<(), String> {
        let (resp_tx, resp_rx) = mpsc::channel();
        self.tx
            .send(WriteRequest {
                path: path.to_string(),
                data,
                resp: resp_tx,
            })
            .map_err(|e| format!("queue state write: {e}"))?;
        resp_rx
            .recv()
            .map_err(|e| format!("state writer response: {e}"))?
    }

    pub fn status(&self) -> WriterStatus {
        WriterStatus {
            active: self.active.load(Ordering::Relaxed),
            mode: self.mode.lock().map(|m| m.clone()).unwrap_or_default(),
            last_error: self
                .last_error
                .lock()
                .map(|v| v.clone())
                .unwrap_or_default(),
        }
    }
}

/// Result of one persistence attempt, carrying the I/O outcome plus whether the
/// io_uring transport failed on this write. The writer loop uses `io_uring_failed`
/// to decide whether to demote `WriteMode` to sync for the rest of its lifetime
/// (#2958): a runtime ring failure that fell back to a successful sync write must
/// still flip the reported mode and stop future ring submissions.
struct PersistOutcome {
    result: Result<(), String>,
    /// The io_uring transport failed on this write (regardless of whether the
    /// sync fallback then succeeded). Always false when already in sync mode.
    io_uring_failed: bool,
    /// The io_uring error that triggered the demotion, recorded as `last_error`
    /// even when the sync fallback succeeded so the demotion cause is visible.
    demotion_cause: Option<String>,
}

fn persist_with_mode(mode: &mut WriteMode, path: &str, data: Vec<u8>) -> PersistOutcome {
    match mode {
        WriteMode::IoUring(ring) => match persist_with_io_uring(ring, path, data) {
            IoUringPersist::Done => PersistOutcome {
                result: Ok(()),
                io_uring_failed: false,
                demotion_cause: None,
            },
            IoUringPersist::Retry(bytes, ring_err) => {
                // io_uring failed but nothing durable landed AND the buffer was
                // handed back (a reaped terminal failure). Fall back to a sync
                // write to a FRESH temp for THIS request from the returned buffer,
                // and flag the failure so the writer loop demotes the mode
                // persistently (status + no future ring attempts).
                let cause = format!("io_uring write failed, demoting to sync: {ring_err}");
                let result = persist_sync(path, &bytes)
                    .map_err(|sync_err| format!("{ring_err}; {sync_err}"));
                PersistOutcome {
                    result,
                    io_uring_failed: true,
                    demotion_cause: Some(cause),
                }
            }
            IoUringPersist::Deferred(ring_err) => {
                // The write did NOT reach a terminal state: its buffer is RETAINED
                // in the ring's in-flight registry (never freed while an SQE may
                // reference it, #5800) and cannot be synchronously retried — the
                // buffer is no longer ours and the op may be in flight. Fail this
                // write and demote; dropping the RingWriter on demotion runs the
                // teardown drain, which frees the parked buffer once it observes
                // the write's terminal CQE, and then closes the ring fd (#6168:
                // the fd close narrows, but does not close, the window for a
                // buffer the drain could not prove terminal).
                let cause =
                    format!("io_uring write deferred (buffer retained), demoting to sync: {ring_err}");
                PersistOutcome {
                    result: Err(cause.clone()),
                    io_uring_failed: true,
                    demotion_cause: Some(cause),
                }
            }
        },
        WriteMode::SyncFallback => PersistOutcome {
            result: persist_sync(path, &data),
            io_uring_failed: false,
            demotion_cause: None,
        },
    }
}

/// Apply a [`PersistOutcome`] to the writer's shared state and return the
/// caller-visible result. This is the runtime-demotion chokepoint (#2958):
///
/// * On an io_uring transport failure (`io_uring_failed`), if we are still in
///   io_uring mode, demote `*mode` to [`WriteMode::SyncFallback`] PERMANENTLY
///   (no cooldown retry — avoids flapping) and flip the reported status:
///   `active=false`, `mode="sync"`. Every subsequent write then takes the sync
///   branch directly, never re-submitting to the broken ring, and the status
///   path stops claiming io_uring is active.
/// * `last_error` is set to the write error when the write failed, or to the
///   demotion cause when the sync fallback succeeded (so an operator can see
///   why the writer left io_uring even on a "successful" write).
///
/// Extracting this from the writer-thread loop lets a unit test drive the exact
/// demotion logic on the test thread (fail-on-revert): remove the demotion and
/// the mode stays io_uring, turning the test RED.
fn apply_outcome(
    outcome: PersistOutcome,
    mode: &mut WriteMode,
    active: &AtomicBool,
    mode_str: &Mutex<String>,
    last_error: &Mutex<String>,
) -> Result<(), String> {
    if outcome.io_uring_failed && matches!(mode, WriteMode::IoUring(_)) {
        *mode = WriteMode::SyncFallback;
        active.store(false, Ordering::Relaxed);
        if let Ok(mut m) = mode_str.lock() {
            *m = "sync".to_string();
        }
    }
    match &outcome.result {
        Err(err) => {
            if let Ok(mut last) = last_error.lock() {
                *last = err.clone();
            }
        }
        Ok(()) => {
            // The write itself succeeded. If io_uring failed and we fell back to
            // sync, surface the demotion cause so the transition is observable
            // even without a failed write.
            if outcome.io_uring_failed {
                if let (Ok(mut last), Some(cause)) =
                    (last_error.lock(), outcome.demotion_cause.as_ref())
                {
                    *last = cause.clone();
                }
            }
        }
    }
    outcome.result
}

/// Outcome of one io_uring state-file write attempt (#5800). Distinguishes a
/// reaped TERMINAL failure whose buffer was handed back (safe to sync-retry to a
/// FRESH temp) from a DEFERRED write whose buffer the ring RETAINED in its
/// in-flight registry (must NOT sync-retry — the op may be in flight and the
/// buffer is no longer ours to re-send).
enum IoUringPersist {
    /// The write completed and the temp was durably finalized.
    Done,
    /// The io_uring path failed (submit error, kernel completion error, zero-byte
    /// completion, id-space exhaustion, temp-open failure, or a durable-finalize
    /// failure) but transferred nothing durable AND handed the owned buffer back.
    /// The buffer feeds a synchronous rewrite to a fresh temp. Carries
    /// (buffer, cause).
    Retry(Vec<u8>, String),
    /// The write did NOT reach a reaped terminal state: the owned buffer has been
    /// MOVED into the ring's in-flight registry (retained until its CQE is reaped
    /// or the ring is torn down and drained). The write FAILS — no sync retry (the
    /// buffer is gone and the SQE may still be in flight). Carries the cause.
    Deferred(String),
}

fn persist_with_io_uring(ring: &mut RingWriter, path: &str, data: Vec<u8>) -> IoUringPersist {
    // Each write gets a PRIVATE temp path (pid + monotonic counter), created
    // with O_EXCL so two concurrent writers — even different helper processes
    // racing the same destination during a restart/upgrade handover — can never
    // open, truncate, or write the SAME temp file. The atomic rename then
    // publishes onto `path` (last-writer-wins on the final file is acceptable;
    // crossed bytes under a successful rename are not, #2705).
    let tmp = temporary_path(path);
    let file = match open_state_temp(&tmp) {
        Ok(f) => f,
        Err(e) => {
            // The temp was never created — nothing is on disk and the buffer is
            // intact, so hand it back for a synchronous retry.
            return IoUringPersist::Retry(
                data,
                format!("open temp state file {}: {e}", tmp.display()),
            );
        }
    };
    // The owned buffer MOVES into the ring. A positioned (file-offset) byte-stream
    // write: a short count legitimately resumes from `offset + n`, so a partial is
    // never `Transferred` here. On a Deferred outcome the ring RETAINS the buffer
    // (never freed while an SQE may reference it, #5800).
    match ring.write(file.as_raw_fd(), data, true, "state") {
        WriteResult::Done(bytes) => {
            // The bytes are on the temp file and the write CQE was reaped. Apply
            // the durability contract (fsync + rename + parent-dir fsync). A
            // finalize failure hands the buffer back so the sync fallback can
            // rewrite a fresh temp.
            match finalize_durably(&file, &tmp, path) {
                Ok(()) => IoUringPersist::Done,
                Err(e) => {
                    let _ = fs::remove_file(&tmp);
                    IoUringPersist::Retry(bytes, e)
                }
            }
        }
        WriteResult::NothingWritten(bytes, msg) => {
            // Nothing reached the temp — discard it and hand the buffer back.
            let _ = fs::remove_file(&tmp);
            IoUringPersist::Retry(bytes, msg)
        }
        WriteResult::Transferred(bytes, msg) => {
            // Unreachable for a positioned write (a short count resumes via the
            // offset, never `Transferred`). Handle defensively: the CQE was reaped
            // (buffer terminal), the partial temp is discarded, and a sync rewrite
            // to a fresh temp is safe.
            let _ = fs::remove_file(&tmp);
            IoUringPersist::Retry(bytes, msg)
        }
        WriteResult::Deferred { id, message, .. } => {
            // The write did not reach a terminal state and its buffer is parked in
            // the ring's registry (retained, not freed); `id` identifies the
            // parked write for teardown correlation. Discard the partial temp; do
            // NOT sync-retry (the buffer is gone and the op may be in flight). The
            // caller demotes to sync, which drops the RingWriter (teardown drain +
            // ring-fd close) and frees the parked buffer safely.
            let _ = fs::remove_file(&tmp);
            IoUringPersist::Deferred(format!("{message} (in-flight id {id}, buffer retained)"))
        }
    }
}

fn persist_sync(path: &str, data: &[u8]) -> Result<(), String> {
    // See persist_with_io_uring: O_EXCL unique temp, atomic rename publish.
    let tmp = temporary_path(path);
    let mut file = open_state_temp(&tmp)
        .map_err(|e| format!("open temp state file {}: {e}", tmp.display()))?;
    let result = (|| {
        {
            use io::Write;
            file.write_all(data)
                .map_err(|e| format!("write temp state file {}: {e}", tmp.display()))?;
        }
        finalize_durably(&file, &tmp, path)
    })();
    cleanup_on_error(&tmp, result)
}

/// On a failed write the unique temp is never renamed into place, so it would
/// leak. Remove it (best-effort) and propagate the original error. On success
/// the rename already consumed the temp, so there is nothing to clean up.
fn cleanup_on_error(tmp: &Path, result: Result<(), String>) -> Result<(), String> {
    if result.is_err() {
        let _ = fs::remove_file(tmp);
    }
    result
}

/// Shared crash-safe finalizer for both write transports (io_uring and the
/// sync fallback). The temp file's data must already be fully written. Applies
/// the same durability contract regardless of how the bytes got there:
///   1. fsync the temp file so its data + metadata reach stable storage,
///   2. atomically rename it onto the destination,
///   3. fsync the parent directory so the rename itself survives power loss.
///
/// Without (1) the file can be empty/torn after a crash; without (3) the rename
/// (the dirent change) can be lost even though the file data is durable. Both
/// modes go through here so neither can drift from this contract.
fn finalize_durably(file: &File, tmp: &Path, dest: &str) -> Result<(), String> {
    sync_all(file).map_err(|e| format!("sync temp state file {}: {e}", tmp.display()))?;
    fs::rename(tmp, dest).map_err(|e| format!("rename {} -> {dest}: {e}", tmp.display()))?;
    sync_parent_dir(dest)?;
    Ok(())
}

/// fsync the directory that contains `dest` so the rename's dirent update is
/// durable. A missing parent (path has no directory component) is treated as
/// the current directory.
fn sync_parent_dir(dest: &str) -> Result<(), String> {
    let parent = Path::new(dest).parent().filter(|p| !p.as_os_str().is_empty());
    let dir = match parent {
        Some(p) => p,
        None => Path::new("."),
    };
    let dir_file =
        File::open(dir).map_err(|e| format!("open parent dir {} for fsync: {e}", dir.display()))?;
    sync_all(&dir_file).map_err(|e| format!("fsync parent dir {}: {e}", dir.display()))?;
    Ok(())
}

/// Process-global monotonic counter that makes every temp path produced by this
/// process unique, even for back-to-back writes to the same destination.
static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// Build a PRIVATE temp path for one write:
/// `<dest>.<pid>_<starttime>.<seq>.tmp`. The pid+start-time pair is this
/// process's stable *instance* identity (`<pid>_<starttime>`, joined by `_` so
/// it stays a single dot-component) — it isolates separate helper processes
/// (restart/upgrade handover) AND, unlike a bare pid, lets the orphan sweep tell
/// a genuinely-live writer from a reused-pid impostor after a crash (#2957). The
/// per-process monotonic counter isolates concurrent or rapid in-process writes.
/// Two distinct writers therefore never name — and so never open/truncate/write
/// — the same temp file, which is what previously let a successful rename
/// publish crossed bytes (#2705). The destination's own extension is preserved
/// in the stem so the temp stays a recognizable sibling.
fn temporary_path(path: &str) -> PathBuf {
    let me = self_instance();
    let pid = me.pid;
    let start = me.start_time;
    let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let mut tmp = PathBuf::from(path);
    let suffix = tmp
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| format!("{ext}.{pid}_{start}.{seq}.tmp"))
        .unwrap_or_else(|| format!("{pid}_{start}.{seq}.tmp"));
    tmp.set_extension(suffix);
    tmp
}

/// Parse the embedded writer-instance (pid + start time) out of a temp file
/// NAME (not a full path) produced by [`temporary_path`]. The format is
/// `<stem>[.<ext>].<pid>_<starttime>.<seq>.tmp`, so after stripping the trailing
/// `.tmp` the last two dot-components are `<pid>_<starttime>` and `<seq>`. The
/// instance component is itself `<pid>_<starttime>` (joined by `_`). Returns
/// `None` if `name` does not match that shape — a foreign file that merely ends
/// in `.tmp`, or a legacy bare-`<pid>.<seq>` temp from before #2957, is left
/// untouched (a legacy temp lacking a start time can't be safely PID-reuse
/// disambiguated, so it is not a sweep candidate under the new scheme).
fn instance_from_temp_name(name: &str) -> Option<ProcInstance> {
    let body = name.strip_suffix(".tmp")?;
    let mut parts = body.rsplitn(3, '.');
    let seq: &str = parts.next()?; // trailing <seq>
    let inst_str = parts.next()?; // <pid>_<starttime> immediately before <seq>
    let stem = parts.next()?; // at least one leading stem component must exist
    if stem.is_empty() {
        return None;
    }
    // The seq component must be all-digits to be one of our temps.
    if seq.is_empty() || !seq.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    // The instance component must be exactly `<pid>_<starttime>`, both numeric.
    let (pid_str, start_str) = inst_str.split_once('_')?;
    if pid_str.is_empty() || !pid_str.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if start_str.is_empty() || !start_str.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(ProcInstance {
        pid: pid_str.parse::<u32>().ok()?,
        start_time: start_str.parse::<u64>().ok()?,
    })
}

/// Best-effort removal of stale `<dest>.<pid>_<starttime>.<seq>.tmp` orphans
/// left in `dest`'s directory by a crash between temp create and atomic rename
/// (#2714).
///
/// Concurrency safety (the #2705 hazard): a unique-per-write temp belonging to a
/// DIFFERENT, still-running writer (e.g. a replacement helper started before the
/// old one fully exits) must NEVER be removed — deleting its in-flight temp
/// would break its atomic write. This sweep therefore removes a candidate ONLY
/// when its embedded writer *instance* (pid + process start time) is no longer
/// live. Keying on the pid alone is unsafe: after a crash Linux can recycle the
/// dead writer's pid, and a bare-pid liveness check would then preserve the
/// stale orphan as if a live writer held it, pinning crash debris indefinitely
/// (#2957). Matching the start time too means a reused pid is correctly seen as
/// a dead instance. The current process's own pid is always treated as alive,
/// so this never races our own writes.
///
/// Scoped to siblings of `dest` whose name starts with `dest`'s file name plus a
/// dot, so it cannot touch unrelated files or temps for other destinations in
/// the same directory. Fail-safe: any error (unreadable dir, racey unlink) is
/// swallowed so a sweep failure can never break the subsequent write.
fn sweep_stale_temps(dest: &str) {
    let dest_path = Path::new(dest);
    let dir = match dest_path.parent().filter(|p| !p.as_os_str().is_empty()) {
        Some(p) => p,
        None => Path::new("."),
    };
    let dest_name = match dest_path.file_name().and_then(|n| n.to_str()) {
        Some(n) if !n.is_empty() => n,
        _ => return,
    };
    // Our temps for this destination are named
    // `<dest_name>.<pid>_<starttime>.<seq>.tmp`.
    let prefix = format!("{dest_name}.");

    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return, // dir may not exist yet on first write — nothing to sweep
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = match name.to_str() {
            Some(n) => n,
            None => continue,
        };
        if !name.starts_with(&prefix) || !name.ends_with(".tmp") {
            continue;
        }
        let inst = match instance_from_temp_name(name) {
            Some(i) => i,
            None => continue, // not one of our `<pid>_<starttime>.<seq>.tmp` temps
        };
        if instance_is_alive(inst) {
            continue; // a live writer (possibly another helper) may still hold it
        }
        let victim = entry.path();
        match fs::remove_file(&victim) {
            Ok(()) => eprintln!(
                "xpf-state-writer: swept stale orphan temp {} (dead instance pid {} start {})",
                victim.display(),
                inst.pid,
                inst.start_time
            ),
            Err(_) => { /* best-effort: raced unlink or perms — ignore */ }
        }
    }
}

#[cfg(test)]
#[path = "state_writer_tests.rs"]
mod tests;
