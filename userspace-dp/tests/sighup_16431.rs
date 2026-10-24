//! #16431: the real helper binary must survive SIGHUP and keep
//! answering its control socket.
//!
//! #15084 made xpfd ignore SIGHUP, but the helper kept the default
//! disposition: it is spawned with a plain `exec.Command` (no
//! `SysProcAttr`), and xpfd's `signal.Notify(SIGHUP)` is a caught
//! disposition, which resets to SIG_DFL across `exec`. So
//! `systemctl kill -s HUP xpfd` (which delivers to every process in
//! the unit) killed the helper even though xpfd logged
//! "SIGHUP received and ignored" — transit failed closed until the
//! supervisor's backoff respawn.
//!
//! These cells spawn the REAL `xpf-userspace-dp` binary
//! (`CARGO_BIN_EXE_xpf-userspace-dp`), deliver a real SIGHUP with
//! `kill(2)`, and assert the process is alive AND still answers a
//! `ping` on its control socket. A second cell pins that the Go
//! supervisor's graceful stop still works: the `shutdown` control
//! verb (what `stopLocked` sends first) exits 0. Note the helper's
//! ctrlc handler covers SIGINT only (ctrlc without the
//! `termination` feature), so a bare SIGTERM has always killed the
//! helper by signal - the Go stop path tolerates either outcome
//! (it falls back to SIGTERM, then SIGKILL, against the
//! supervisor's exit channel). That pre-existing SIGTERM
//! disposition is deliberately NOT changed here (#16431 scope:
//! SIGHUP only).
//!
//! RED on revert: removing `ignore_sighup()` from
//! `server::lifecycle::run` makes the SIGHUP cell's child die by
//! signal (`exited by signal: 1 (Hangup)`), so the liveness assert
//! fails; routing SIGHUP into the ctrlc handler instead (e.g. via
//! ctrlc's `termination` feature) makes it exit 0, which the same
//! assert also rejects.
//!
//! The helper is spawned with `--poll-mode interrupt` and
//! `--workers 1`: no AF_XDP binding is attempted until a snapshot
//! arrives, so the bare helper serves ping/status on its control
//! socket without hardware, root, or /proc writes beyond the
//! raise-only sysctl reads at startup (which only warn on failure).

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const PING: &str = "{\"type\":\"ping\",\"suppress_status\":true}\n";

struct HelperGuard {
    child: Child,
    _dir: tempfile_dir::TempDir,
}

mod tempfile_dir {
    use std::path::PathBuf;

    /// Minimal unique tempdir (no tempfile dev-dep in this crate).
    pub struct TempDir(pub PathBuf);

    impl TempDir {
        pub fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "xpf-sighup-16431-{tag}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("clock")
                    .as_nanos()
            ));
            std::fs::create_dir_all(&dir).expect("create tempdir");
            TempDir(dir)
        }
        pub fn path(&self) -> &std::path::Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

fn spawn_helper(tag: &str) -> (HelperGuard, PathBuf) {
    let dir = tempfile_dir::TempDir::new(tag);
    let control = dir.path().join("userspace-dp.sock");
    let state = dir.path().join("userspace-dp.json");
    let bin = env!("CARGO_BIN_EXE_xpf-userspace-dp");
    let child = Command::new(bin)
        .args([
            "--control-socket",
            control.to_str().expect("utf8 control path"),
            "--state-file",
            state.to_str().expect("utf8 state path"),
            "--workers",
            "1",
            "--ring-entries",
            "1024",
            "--poll-mode",
            "interrupt",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn xpf-userspace-dp");
    let guard = HelperGuard { child, _dir: dir };
    (guard, control)
}

fn wait_for_socket(path: &Path, child: &mut Child) {
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        if path.exists() {
            return;
        }
        if let Some(status) = child.try_wait().expect("try_wait helper") {
            panic!("helper exited before binding control socket: {status}");
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    panic!("helper did not bind {} within 15s", path.display());
}

fn ping(control: &Path) -> String {
    let mut stream = UnixStream::connect(control)
        .unwrap_or_else(|e| panic!("connect control socket {}: {e}", control.display()));
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set read timeout");
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .expect("set write timeout");
    stream.write_all(PING.as_bytes()).expect("write ping");
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).expect("read ping response");
    assert!(!line.is_empty(), "empty ping response from helper");
    line
}

fn kill(pid: u32, sig: i32) {
    // SAFETY: kill(2) with a pid we spawned and a valid signal number.
    let rc = unsafe { libc::kill(pid as i32, sig) };
    assert_eq!(
        rc,
        0,
        "kill({pid}, {sig}): {}",
        std::io::Error::last_os_error()
    );
}

fn assert_alive(child: &mut Child, what: &str) {
    // Give a wrongly-terminating helper a bounded window to die, so
    // the assert observes the death rather than racing it.
    std::thread::sleep(Duration::from_millis(300));
    if let Some(status) = child.try_wait().expect("try_wait helper") {
        let mut stderr = String::new();
        if let Some(mut pipe) = child.stderr.take() {
            let _ = pipe.read_to_string(&mut stderr);
        }
        panic!("helper {what}: exited with {status}; stderr: {stderr}");
    }
}

impl Drop for HelperGuard {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

#[test]
fn helper_survives_sighup_and_still_answers_ping_16431() {
    let (mut guard, control) = spawn_helper("hup");
    wait_for_socket(&control, &mut guard.child);
    let pid = guard.child.id();

    // Control: the helper answers before any signal.
    let before = ping(&control);
    assert!(
        before.contains("\"ok\":true"),
        "pre-HUP ping must succeed, got: {before}"
    );

    // The defect delivery: SIGHUP to the helper pid, exactly as
    // `systemctl kill -s HUP xpfd` reaches every unit process.
    kill(pid, libc::SIGHUP);
    assert_alive(&mut guard.child, "must survive SIGHUP (#16431)");

    // Still forwarding-plane alive: the control socket answers.
    let after = ping(&control);
    assert!(
        after.contains("\"ok\":true"),
        "post-HUP ping must succeed, got: {after}"
    );

    // A burst is equally inert (SIG_IGN discards at the kernel).
    kill(pid, libc::SIGHUP);
    kill(pid, libc::SIGHUP);
    assert_alive(&mut guard.child, "must survive repeated SIGHUP (#16431)");
    let burst = ping(&control);
    assert!(
        burst.contains("\"ok\":true"),
        "post-burst ping must succeed, got: {burst}"
    );
}

#[test]
fn helper_still_exits_gracefully_on_shutdown_verb_16431() {
    let (mut guard, control) = spawn_helper("term");
    wait_for_socket(&control, &mut guard.child);
    let before = ping(&control);
    assert!(
        before.contains("\"ok\":true"),
        "pre-shutdown ping must succeed, got: {before}"
    );

    // The Go stop path (`stopLocked`) sends the `shutdown` verb
    // first; it flips `running` to false and the accept loop exits,
    // so the helper exits 0. SIGHUP handling must not disturb this.
    let mut stream = UnixStream::connect(&control).expect("connect for shutdown");
    stream
        .write_all(b"{\"type\":\"shutdown\",\"suppress_status\":true}\n")
        .expect("write shutdown");
    let mut resp = String::new();
    BufReader::new(stream)
        .read_line(&mut resp)
        .expect("read shutdown response");
    assert!(
        resp.contains("\"ok\":true"),
        "shutdown verb must succeed, got: {resp}"
    );

    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = guard.child.try_wait().expect("try_wait helper") {
            assert!(
                status.success(),
                "shutdown verb must exit 0 (graceful), got {status}"
            );
            return;
        }
        assert!(
            Instant::now() < deadline,
            "helper did not exit within 10s of the shutdown verb"
        );
        std::thread::sleep(Duration::from_millis(25));
    }
}
