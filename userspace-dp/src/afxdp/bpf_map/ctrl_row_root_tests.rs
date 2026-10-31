//! #18560 (review seat V): the production path of the helper-side ctrl stamp
//! against a real BPF map. It needs CAP_BPF and a bpffs at /sys/fs/bpf. Like
//! the XFRM lifecycle cells (`require_xfrm_monitor_for_lifecycle_test`), it is
//! gated at RUNTIME, not `#[ignore]`d: without the privilege it prints SKIP and
//! passes, and with `XPF_REQUIRE_CTRL_ROW_ROOT` set (`make test-ctrl-row-root`,
//! part of `make test-root`) a missing privilege fails it instead.

use super::*;
use crate::afxdp::coordinator::{CtrlStamp, CtrlStampOutcome, PinnedCtrlMap};

fn create_array(value_size: u32) -> c_int {
    let name = std::ffi::CString::new("xpf_t18560").expect("name");
    // SAFETY: a plain map create with a NUL-terminated name and no opts.
    let fd = unsafe {
        libbpf_sys::bpf_map_create(libbpf_sys::BPF_MAP_TYPE_ARRAY, name.as_ptr(), 4, value_size, 1, std::ptr::null())
    };
    assert!(fd >= 0, "bpf_map_create: {} (needs CAP_BPF)", io::Error::last_os_error());
    fd
}

fn pin(fd: c_int, path: &str) {
    let c = std::ffi::CString::new(path).expect("path");
    // SAFETY: fd is a live map fd; path is NUL-terminated.
    let rc = unsafe { libbpf_sys::bpf_obj_pin(fd, c.as_ptr()) };
    assert_eq!(rc, 0, "bpf_obj_pin {path}: {} (needs a bpffs at /sys/fs/bpf)", io::Error::last_os_error());
}

struct Unpin(String, c_int);
impl Drop for Unpin {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
        // SAFETY: closing the fd this test created.
        let _ = unsafe { libc::close(self.1) };
    }
}

#[derive(Debug, PartialEq, Eq)]
enum CtrlRowRootAction {
    Continue,
    Skip,
    Fail,
}

fn ctrl_row_root_action(capable: bool, must_run: bool) -> CtrlRowRootAction {
    match (capable, must_run) {
        (true, _) => CtrlRowRootAction::Continue,
        (false, false) => CtrlRowRootAction::Skip,
        (false, true) => CtrlRowRootAction::Fail,
    }
}

/// Can this process create and pin a BPF array map? Probed the same way the
/// cell uses the kernel, then cleaned up.
fn ctrl_row_root_capable() -> Result<(), String> {
    let name = std::ffi::CString::new("xpf_t18560_probe").expect("name");
    // SAFETY: a plain map create with a NUL-terminated name and no opts.
    let fd = unsafe {
        libbpf_sys::bpf_map_create(libbpf_sys::BPF_MAP_TYPE_ARRAY, name.as_ptr(), 4, 8, 1, std::ptr::null())
    };
    if fd < 0 {
        return Err(format!("bpf_map_create: {}", io::Error::last_os_error()));
    }
    let path = format!("/sys/fs/bpf/xpf_t18560_probe_{}", std::process::id());
    let c = std::ffi::CString::new(path.clone()).expect("path");
    // SAFETY: fd is a live map fd; path is NUL-terminated.
    let rc = unsafe { libbpf_sys::bpf_obj_pin(fd, c.as_ptr()) };
    let pin_err = io::Error::last_os_error();
    let _ = std::fs::remove_file(&path);
    // SAFETY: closing the probe fd.
    let _ = unsafe { libc::close(fd) };
    if rc != 0 {
        return Err(format!("bpf_obj_pin {path}: {pin_err}"));
    }
    Ok(())
}

/// True when the cell should run; prints SKIP or panics otherwise.
fn require_ctrl_row_root() -> bool {
    let must_run = std::env::var_os("XPF_REQUIRE_CTRL_ROW_ROOT").is_some();
    let probe = ctrl_row_root_capable();
    match ctrl_row_root_action(probe.is_ok(), must_run) {
        CtrlRowRootAction::Continue => true,
        CtrlRowRootAction::Skip => {
            eprintln!(
                "SKIP: ctrl_row_root_18560 needs CAP_BPF and a bpffs ({}); make test-ctrl-row-root runs it",
                probe.err().unwrap_or_default()
            );
            false
        }
        CtrlRowRootAction::Fail => panic!(
            "XPF_REQUIRE_CTRL_ROW_ROOT is set, but this process cannot create and pin a BPF map ({}); \
             this cell must run in the privileged gate",
            probe.err().unwrap_or_default()
        ),
    }
}

#[test]
fn ctrl_row_root_gate_skips_unprivileged_and_fails_when_required_18560() {
    assert_eq!(ctrl_row_root_action(true, false), CtrlRowRootAction::Continue);
    assert_eq!(ctrl_row_root_action(true, true), CtrlRowRootAction::Continue);
    assert_eq!(ctrl_row_root_action(false, false), CtrlRowRootAction::Skip);
    assert_eq!(ctrl_row_root_action(false, true), CtrlRowRootAction::Fail);
}

#[test]
fn ctrl_row_root_18560() {
    if !require_ctrl_row_root() {
        return;
    }
    let pid = std::process::id();
    // The real shape: a one-entry array of 56-byte values.
    let path = format!("/sys/fs/bpf/xpf_t18560_ctrl_{pid}");
    let fd = create_array(std::mem::size_of::<UserspaceCtrlValue>() as u32);
    pin(fd, &path);
    let _cleanup = Unpin(path.clone(), fd);

    // Seed it as Go would: enabled, current metadata version, stamped 11/4.
    let seeded = UserspaceCtrlValue {
        enabled: 1,
        metadata_version: crate::afxdp::coordinator::EXPECTED_CTRL_METADATA_VERSION,
        workers: 6,
        queue_count: 6,
        config_generation: 11,
        fib_generation: 4,
        heartbeat_timeout_ms: 1500,
        ..UserspaceCtrlValue::default()
    };
    let row = open_ctrl_row(&path).expect("open_ctrl_row accepts the shim shape");
    update_ctrl_row(&row, &seeded).expect("BPF_EXIST update of the existing entry");
    assert_eq!(lookup_ctrl_row(&row).expect("lookup"), seeded);

    // The coordinator's adapter advances the real row, BPF_EXIST and all.
    let mut io = PinnedCtrlMap::open(&path).expect("PinnedCtrlMap::open");
    let mut now = crate::afxdp::monotonic_nanos;
    let deadline = crate::afxdp::monotonic_nanos() + 10_000_000_000;
    let outcome = crate::afxdp::coordinator::advance_ctrl_stamp(
        &mut io,
        CtrlStamp { config_generation: 11, fib_generation: 4 },
        CtrlStamp { config_generation: 14, fib_generation: 5 },
        deadline,
        &mut now,
    );
    assert_eq!(outcome, CtrlStampOutcome::Advanced);
    let mut want = seeded;
    want.config_generation = 14;
    want.fib_generation = 5;
    assert_eq!(lookup_ctrl_row(&row).expect("lookup"), want, "only the stamp moved");

    // A map whose value is not the shim ABI is refused before any write.
    let bad_path = format!("/sys/fs/bpf/xpf_t18560_bad_{pid}");
    let bad = create_array(40);
    pin(bad, &bad_path);
    let _bad_cleanup = Unpin(bad_path.clone(), bad);
    let err = match open_ctrl_row(&bad_path) {
        Ok(_) => panic!("a 40-byte value map was accepted as userspace_ctrl"),
        Err(err) => err,
    };
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
}
