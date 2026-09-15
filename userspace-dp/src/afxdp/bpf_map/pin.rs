// libbpf fd pinning + pinned degraded-path stats reader.
//
// Pure code motion out of `bpf_map/mod.rs` (#2003): the RAII wrapper that
// opens a pinned BPF object by sysfs path (`bpf_obj_get`) and closes the
// fd on drop, plus the debug-gated reader for the pinned
// `userspace_fallback_stats` map, now live here. These are the only
// items that talk to the bpffs pin paths directly.
//
// Behaviour-preserving: `OwnedFd::open_bpf_map` keeps the same
// `CString`/`bpf_obj_get`/`last_os_error` contract, `Drop` still closes
// the fd, and `read_degraded_path_stats` keeps the same 16-slot scan and
// debug-log gating. The pin-path constant and reason-name table move with
// the reader. The orchestrator and tests resolve these via the `bpf_map`
// re-export, exactly as before.
//
// Precedent: the sibling `publish_conntrack.rs` split (#1356).

use super::*;

pub(in crate::afxdp) struct OwnedFd {
    pub(in crate::afxdp) fd: c_int,
}

/// #2440 test seam: pin paths beginning with this prefix are resolved
/// WITHOUT touching bpffs, so the reconcile-preflight ordering can be
/// exercised from any thread (the control-socket handler runs on a
/// spawned thread, ruling out a thread-local hook). A path of
/// [`TEST_MAP_PIN_OK`] yields a harmless dummy fd; one of
/// [`TEST_MAP_PIN_FAIL`] yields an `ENOENT` open failure. The prefix is
/// not a valid bpffs path, so production callers never collide with it.
#[cfg(test)]
pub(in crate::afxdp) const TEST_MAP_PIN_OK: &str = "test-map-pin-ok://";
#[cfg(test)]
pub(in crate::afxdp) const TEST_MAP_PIN_FAIL: &str = "test-map-pin-fail://";

impl OwnedFd {
    pub(in crate::afxdp) fn open_bpf_map(path: &str) -> io::Result<Self> {
        // #2440 test seam: sentinel pin paths short-circuit the real
        // `bpf_obj_get` so the preflight ordering is testable without
        // bpffs. Production builds compile this branch out entirely.
        #[cfg(test)]
        {
            if let Some(rest) = path.strip_prefix(TEST_MAP_PIN_FAIL) {
                let _ = rest;
                return Err(io::Error::from_raw_os_error(libc::ENOENT));
            }
            if path.starts_with(TEST_MAP_PIN_OK) {
                // fd = -1: never a real map; `Drop`'s close(-1) is a
                // harmless EBADF no-op.
                return Ok(Self { fd: -1 });
            }
        }
        let path = CString::new(path)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid map path"))?;
        let fd = unsafe { libbpf_sys::bpf_obj_get(path.as_ptr()) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { fd })
    }
}

impl Drop for OwnedFd {
    fn drop(&mut self) {
        let _ = unsafe { libc::close(self.fd) };
    }
}

// The pinned map path keeps the historical "fallback" spelling for
// mixed-version shim compatibility. Operator-facing names use
// degraded-path terminology.
//
// #1776: the only production reader (the per-second degraded-path
// dump in worker/loop_body/debug_report.rs) is debug-log-gated, so
// these items are cfg-gated to match (REASON_NAMES is also asserted
// by unit tests, hence `any(test, ...)`).
#[cfg(feature = "debug-log")]
pub(in crate::afxdp) const DEGRADED_PATH_STATS_PIN_PATH: &str =
    "/sys/fs/bpf/xpf/userspace_fallback_stats";
#[cfg(any(test, feature = "debug-log"))]
pub(in crate::afxdp) const DEGRADED_PATH_REASON_NAMES: &[&str] = &[
    "ctrl_disabled",            // 0
    "parse_fail",               // 1
    "binding_missing",          // 2
    "binding_not_ready",        // 3
    "heartbeat_missing",        // 4
    "heartbeat_stale",          // 5
    "icmp",                     // 6
    "early_filter",             // 7
    "adjust_meta",              // 8
    "meta_bounds",              // 9
    "redirect_err",             // 10
    "interface_nat_no_session", // 11
    "no_session",               // 12
    "strict_drop",              // 13
    "pass_to_kernel",           // 14
    "transit_drop",             // 15
    "qinq_drop",                // 16
];

#[cfg(feature = "debug-log")]
pub(in crate::afxdp) fn read_degraded_path_stats() -> Option<Vec<(String, u64)>> {
    let fd = OwnedFd::open_bpf_map(DEGRADED_PATH_STATS_PIN_PATH).ok()?;
    // #4113 (F13): userspace_fallback_stats is a PER-CPU array. On a lookup
    // the kernel fills value_size * num_possible_cpus bytes (one u64 per
    // CPU), so the destination buffer MUST be sized for all possible CPUs —
    // a single-u64 buffer would be overrun (stack corruption). Sum across
    // CPUs to recover the cumulative per-reason count.
    let ncpus = unsafe { libbpf_sys::libbpf_num_possible_cpus() };
    if ncpus <= 0 {
        return None;
    }
    let ncpus = ncpus as usize;
    let mut result = Vec::new();
    // Iterate the authoritative reason list rather than a hardcoded 16 so the
    // scan cannot drift if a degraded-path reason is added or removed.
    for idx in 0u32..DEGRADED_PATH_REASON_NAMES.len() as u32 {
        let mut values = vec![0u64; ncpus];
        let rc = unsafe {
            libbpf_sys::bpf_map_lookup_elem(
                fd.fd,
                (&idx as *const u32).cast::<c_void>(),
                values.as_mut_ptr().cast::<c_void>(),
            )
        };
        if rc == 0 {
            let total: u64 = values.iter().copied().sum();
            if total > 0 {
                let name = DEGRADED_PATH_REASON_NAMES
                    .get(idx as usize)
                    .copied()
                    .unwrap_or("unknown");
                result.push((name.to_string(), total));
            }
        }
    }
    Some(result)
}
