//! Address-family dispatch, map I/O, and test-double selection for the
//! conntrack maps — the single conntrack I/O boundary (#17271).
//!
//! `conntrack_target` is the only code that reads `key.addr_family` for family
//! selection. The primitives below own every per-session conntrack libbpf syscall
//! and the only `#[cfg(test)]` row-backend dispatch — selected only when the fd
//! chosen for the key's own family is the test sentinel, so a v4/v6 fd transposition
//! cannot be hidden by per-function predicate copies.

use super::*;

#[cfg(test)]
pub(crate) const CONNTRACK_TEST_MAP_FD: c_int = -2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ConntrackTarget {
    V4(c_int),
    V6(c_int),
    NoMap { family: u8, fd: c_int },
    CrossFamily,
}

impl ConntrackTarget {
    pub(crate) fn v4_fd(self) -> Option<c_int> {
        match self {
            Self::V4(fd) => Some(fd),
            Self::NoMap { family, fd } if family == libc::AF_INET as u8 => Some(fd),
            Self::V6(_) | Self::NoMap { .. } | Self::CrossFamily => None,
        }
    }

    pub(crate) fn v6_fd(self) -> Option<c_int> {
        match self {
            Self::V6(fd) => Some(fd),
            Self::NoMap { family, fd } if family == libc::AF_INET6 as u8 => Some(fd),
            Self::V4(_) | Self::NoMap { .. } | Self::CrossFamily => None,
        }
    }

    pub(crate) fn is_no_map(self) -> bool {
        matches!(self, Self::NoMap { .. })
    }
    #[cfg(test)]
    pub(crate) fn is_test_map(self) -> bool {
        match self {
            Self::V4(fd) | Self::V6(fd) => is_conntrack_test_fd(fd),
            Self::NoMap { .. } | Self::CrossFamily => false,
        }
    }
}

/// Select the fd for the key's address family, validating that the IP values
/// agree with the family byte before any caller reaches a map operation.
///
/// A negative fd is `NoMap`, except the test-only sentinel: it becomes a V4 or
/// V6 target only when it occupies that key family's selected slot. This is
/// the single family-sensitive test-double dispatch for every conntrack path.
pub(crate) fn conntrack_target(
    conntrack_v4_fd: c_int,
    conntrack_v6_fd: c_int,
    key: &SessionKey,
) -> ConntrackTarget {
    match (key.addr_family as i32, &key.src_ip, &key.dst_ip) {
        (libc::AF_INET, IpAddr::V4(_), IpAddr::V4(_)) => {
            selected_target(libc::AF_INET as u8, conntrack_v4_fd)
        }
        (libc::AF_INET6, IpAddr::V6(_), IpAddr::V6(_)) => {
            selected_target(libc::AF_INET6 as u8, conntrack_v6_fd)
        }
        _ => ConntrackTarget::CrossFamily,
    }
}

fn selected_target(family: u8, fd: c_int) -> ConntrackTarget {
    if fd >= 0 || is_conntrack_test_fd(fd) {
        if family == libc::AF_INET as u8 {
            ConntrackTarget::V4(fd)
        } else {
            ConntrackTarget::V6(fd)
        }
    } else {
        ConntrackTarget::NoMap { family, fd }
    }
}

/// Whether an fd represents a usable map for any-map-presence checks.
pub(crate) fn conntrack_fd_available(fd: c_int) -> bool {
    fd >= 0 || is_conntrack_test_fd(fd)
}

fn is_conntrack_test_fd(fd: c_int) -> bool {
    #[cfg(test)]
    {
        fd == CONNTRACK_TEST_MAP_FD
    }
    #[cfg(not(test))]
    {
        let _ = fd;
        false
    }
}

// ── Typed per-session conntrack I/O primitives ──
//
// One ref-enum pair per call: the key/value spelling is derived from the
// already-selected target and the session key exactly once here, so no caller
// re-derives which slot or family a row belongs to. Return shapes preserve the
// historical syscall contract: lookup/update report the raw `c_int` rc (0 on
// success, -1 on failure — the kernel's -errno in production, the ENOENT
// shape under the test backend), and delete tolerates an absent row.
// `libbpf` return codes carry their negative errno directly; no caller reads
// ambient errno to explain a failed or missing conntrack row.

#[derive(Clone, Copy)]
pub(crate) enum ConntrackKeyRef<'a> {
    V4(&'a BpfSessionKeyV4),
    V6(&'a BpfSessionKeyV6),
}

#[derive(Clone, Copy)]
pub(crate) enum ConntrackValueRef<'a> {
    V4(&'a BpfSessionValueV4),
    V6(&'a BpfSessionValueV6),
}

pub(crate) enum ConntrackValueMutRef<'a> {
    V4(&'a mut BpfSessionValueV4),
    V6(&'a mut BpfSessionValueV6),
}


/// Look up the row for `key` on `target`, filling `value` on a hit. A fake miss
/// is represented as `-ENOENT`, just like the kernel syscall result; only
/// `NoMap`/`CrossFamily` return `None`.
pub(crate) fn conntrack_lookup(
    target: ConntrackTarget,
    key: &SessionKey,
    value: ConntrackValueMutRef<'_>,
) -> Option<c_int> {
    #[cfg(test)]
    if target.is_test_map() {
        let Some(row) = conntrack_row_for_test(key) else {
            return Some(-libc::ENOENT);
        };
        match (target, &key.src_ip, &key.dst_ip, value) {
            (ConntrackTarget::V4(_), IpAddr::V4(_), IpAddr::V4(_), ConntrackValueMutRef::V4(value)) => {
                project_test_row_v4(value, &row);
            }
            (ConntrackTarget::V6(_), IpAddr::V6(_), IpAddr::V6(_), ConntrackValueMutRef::V6(value)) => {
                project_test_row_v6(value, &row);
            }
            _ => return None,
        }
        return Some(0);
    }
    match (target, value) {
        (ConntrackTarget::V4(fd), ConntrackValueMutRef::V4(value)) if fd >= 0 => {
            let (IpAddr::V4(src), IpAddr::V4(dst)) = (key.src_ip, key.dst_ip) else {
                return None;
            };
            let bpf_key = bpf_session_key_v4(
                src.octets(),
                dst.octets(),
                key.src_port,
                key.dst_port,
                key.protocol,
            );
            Some(unsafe {
                libbpf_sys::bpf_map_lookup_elem(
                    fd,
                    ConntrackKeyRef::V4(&bpf_key).as_ptr(),
                    (value as *mut BpfSessionValueV4).cast::<c_void>(),
                )
            })
        }
        (ConntrackTarget::V6(fd), ConntrackValueMutRef::V6(value)) if fd >= 0 => {
            let (IpAddr::V6(src), IpAddr::V6(dst)) = (key.src_ip, key.dst_ip) else {
                return None;
            };
            let bpf_key = bpf_session_key_v6(
                src.octets(),
                dst.octets(),
                key.src_port,
                key.dst_port,
                key.protocol,
            );
            Some(unsafe {
                libbpf_sys::bpf_map_lookup_elem(
                    fd,
                    ConntrackKeyRef::V6(&bpf_key).as_ptr(),
                    (value as *mut BpfSessionValueV6).cast::<c_void>(),
                )
            })
        }
        _ => None,
    }
}

/// App-ID restamp lookup, with its historical test-only lookup counter.
pub(crate) fn conntrack_lookup_app_id(
    target: ConntrackTarget,
    key: &SessionKey,
    value: ConntrackValueMutRef<'_>,
) -> Option<c_int> {
    #[cfg(test)]
    if target.is_test_map() {
        count_conntrack_test_lookup();
    }
    conntrack_lookup(target, key, value)
}

/// Update a typed row; production forwards the supplied `flags` to libbpf.
/// Publish uses `BPF_ANY`; in-place restamps and refresh use `BPF_EXIST`.
/// Snapshot restore uses the separate exact-byte update primitive. Under the
/// test backend, current in-place updates fail on a missing row and sync the
/// fake row's mirrored fields.
pub(crate) fn conntrack_update(
    target: ConntrackTarget,
    key: &SessionKey,
    value: ConntrackValueRef<'_>,
    flags: u64,
) -> Option<c_int> {
    #[cfg(test)]
    if target.is_test_map() {
        match (target, &key.src_ip, &key.dst_ip, value) {
            (ConntrackTarget::V4(_), IpAddr::V4(_), IpAddr::V4(_), ConntrackValueRef::V4(value)) => {
                return Some(update_test_row(
                    key,
                    ConntrackValueRef::V4(value),
                    flags,
                ));
            }
            (ConntrackTarget::V6(_), IpAddr::V6(_), IpAddr::V6(_), ConntrackValueRef::V6(value)) => {
                return Some(update_test_row(
                    key,
                    ConntrackValueRef::V6(value),
                    flags,
                ));
            }
            _ => return None,
        }
    }
    match (target, value) {
        (ConntrackTarget::V4(fd), ConntrackValueRef::V4(value)) if fd >= 0 => {
            let (IpAddr::V4(src), IpAddr::V4(dst)) = (key.src_ip, key.dst_ip) else {
                return None;
            };
            let bpf_key = bpf_session_key_v4(
                src.octets(),
                dst.octets(),
                key.src_port,
                key.dst_port,
                key.protocol,
            );
            Some(unsafe {
                libbpf_sys::bpf_map_update_elem(
                    fd,
                    ConntrackKeyRef::V4(&bpf_key).as_ptr(),
                    (value as *const BpfSessionValueV4).cast::<c_void>(),
                    flags,
                )
            })
        }
        (ConntrackTarget::V6(fd), ConntrackValueRef::V6(value)) if fd >= 0 => {
            let (IpAddr::V6(src), IpAddr::V6(dst)) = (key.src_ip, key.dst_ip) else {
                return None;
            };
            let bpf_key = bpf_session_key_v6(
                src.octets(),
                dst.octets(),
                key.src_port,
                key.dst_port,
                key.protocol,
            );
            Some(unsafe {
                libbpf_sys::bpf_map_update_elem(
                    fd,
                    ConntrackKeyRef::V6(&bpf_key).as_ptr(),
                    (value as *const BpfSessionValueV6).cast::<c_void>(),
                    flags,
                )
            })
        }
        _ => None,
    }
}

/// Refresh update wrapper: count only successful refreshes, not the other
/// `BPF_EXIST` restamps that share the primitive.
pub(crate) fn conntrack_refresh_update(
    target: ConntrackTarget,
    key: &SessionKey,
    value: ConntrackValueRef<'_>,
) -> Option<c_int> {
    let rc = conntrack_update(target, key, value, libbpf_sys::BPF_EXIST as u64)?;
    #[cfg(test)]
    if target.is_test_map() && rc == 0 {
        CONNTRACK_TEST_REFRESH_WRITES.with(|writes| writes.set(writes.get() + 1));
    }
    Some(rc)
}

/// Delete the row for `key` on `target`; an already-absent row is tolerated.
pub(crate) fn conntrack_delete(target: ConntrackTarget, key: &SessionKey) -> Option<bool> {
    #[cfg(test)]
    if target.is_test_map() {
        return Some(delete_test_row(key));
    }
    match target {
        ConntrackTarget::V4(fd) if fd >= 0 => {
            let (IpAddr::V4(src), IpAddr::V4(dst)) = (key.src_ip, key.dst_ip) else {
                return None;
            };
            let bpf_key = bpf_session_key_v4(
                src.octets(),
                dst.octets(),
                key.src_port,
                key.dst_port,
                key.protocol,
            );
            let rc = unsafe {
                libbpf_sys::bpf_map_delete_elem(fd, ConntrackKeyRef::V4(&bpf_key).as_ptr())
            };
            Some(rc >= 0 || rc == -libc::ENOENT)
        }
        ConntrackTarget::V6(fd) if fd >= 0 => {
            let (IpAddr::V6(src), IpAddr::V6(dst)) = (key.src_ip, key.dst_ip) else {
                return None;
            };
            let bpf_key = bpf_session_key_v6(
                src.octets(),
                dst.octets(),
                key.src_port,
                key.dst_port,
                key.protocol,
            );
            let rc = unsafe {
                libbpf_sys::bpf_map_delete_elem(fd, ConntrackKeyRef::V6(&bpf_key).as_ptr())
            };
            Some(rc >= 0 || rc == -libc::ENOENT)
        }
        _ => None,
    }
}

/// Publish outcome mapping and family-specific error diagnostic for a real
/// `BPF_ANY` write.
fn conntrack_write_result(addr_family: u8, rc: c_int) -> ConntrackPublishResult {
    if rc >= 0 {
        return ConntrackPublishResult::Written;
    }
    let family = if addr_family == libc::AF_INET as u8 {
        "v4"
    } else {
        "v6"
    };
    eprintln!(
        "xpf-ha: conntrack {family} map update failed: {}",
        std::io::Error::from_raw_os_error(rc.saturating_neg()),
    );
    ConntrackPublishResult::KernelError
}

impl ConntrackKeyRef<'_> {
    fn as_ptr(self) -> *const c_void {
        match self {
            Self::V4(key) => (key as *const BpfSessionKeyV4).cast::<c_void>(),
            Self::V6(key) => (key as *const BpfSessionKeyV6).cast::<c_void>(),
        }
    }
}

/// Publish one mirrored row through the primitives. The value builders in
/// `publish_conntrack` stay pure; this owns the write. Under the test fd the
/// fake `Written` outcome is returned without running the real builder or
/// syscall — NAT64 tests deliberately publish a v6 key with IPv4 NAT rewrites,
/// whose v6 builder refuses the v4 reverse key — and the caller commits the
/// record only after publish overrides resolve.
pub(crate) fn publish_conntrack_row(
    target: ConntrackTarget,
    key: &SessionKey,
    decision: SessionDecision,
    metadata: &SessionMetadata,
    flags: u16,
    ingress_zone_id: u32,
    egress_zone_id: u32,
    now_secs: u64,
    alg_disable_flags: u8,
    app_id: u16,
    session_id: u64,
    timeout_secs: u32,
) -> ConntrackPublishResult {
    #[cfg(test)]
    if target.is_test_map() {
        return ConntrackPublishResult::Written;
    }
    match target {
        ConntrackTarget::V4(fd) if fd >= 0 => {
            if !matches!((&key.src_ip, &key.dst_ip), (IpAddr::V4(_), IpAddr::V4(_))) {
                return ConntrackPublishResult::IntentionallySkipped;
            }
            let Some(value) = publish_conntrack::build_conntrack_value_v4(
                key,
                decision,
                metadata,
                flags,
                ingress_zone_id,
                egress_zone_id,
                now_secs,
                alg_disable_flags,
                app_id,
                session_id,
                timeout_secs,
            ) else {
                return ConntrackPublishResult::IntentionallySkipped;
            };
            match conntrack_update(
                target,
                key,
                ConntrackValueRef::V4(&value),
                libbpf_sys::BPF_ANY as u64,
            ) {
                Some(rc) => conntrack_write_result(libc::AF_INET as u8, rc),
                None => ConntrackPublishResult::IntentionallySkipped,
            }
        }
        ConntrackTarget::V6(fd) if fd >= 0 => {
            if !publish_conntrack::v6_session_key_is_publishable(key.protocol) {
                return ConntrackPublishResult::IntentionallySkipped;
            }
            if !matches!((&key.src_ip, &key.dst_ip), (IpAddr::V6(_), IpAddr::V6(_))) {
                return ConntrackPublishResult::IntentionallySkipped;
            }
            let Some(value) = publish_conntrack::build_conntrack_value_v6(
                key,
                decision,
                metadata,
                flags,
                ingress_zone_id,
                egress_zone_id,
                now_secs,
                alg_disable_flags,
                app_id,
                session_id,
                timeout_secs,
            ) else {
                return ConntrackPublishResult::IntentionallySkipped;
            };
            match conntrack_update(
                target,
                key,
                ConntrackValueRef::V6(&value),
                libbpf_sys::BPF_ANY as u64,
            ) {
                Some(rc) => conntrack_write_result(libc::AF_INET6 as u8, rc),
                None => ConntrackPublishResult::IntentionallySkipped,
            }
        }
        ConntrackTarget::NoMap { .. } => ConntrackPublishResult::NoMap,
        ConntrackTarget::CrossFamily => ConntrackPublishResult::IntentionallySkipped,
        _ => ConntrackPublishResult::IntentionallySkipped,
    }
}

/// Snapshot the exact key/value bytes while the caller holds its tuple gate.
pub(crate) fn snapshot_conntrack_entry(
    target: ConntrackTarget,
    key: &SessionKey,
) -> Result<Option<ConntrackEntrySnapshot>, ()> {
    #[cfg(test)]
    if target.is_test_map() {
        return Ok(conntrack_row_for_test(key)
            .map(|record| ConntrackEntrySnapshot(ConntrackEntrySnapshotData::Test(record))));
    }
    match (target, &key.src_ip, &key.dst_ip) {
        (ConntrackTarget::V4(fd), IpAddr::V4(src), IpAddr::V4(dst)) if fd >= 0 => {
            let bpf_key =
                bpf_session_key_v4(src.octets(), dst.octets(), key.src_port, key.dst_port, key.protocol);
            let mut key_bytes = [0u8; std::mem::size_of::<BpfSessionKeyV4>()];
            let mut value = [0u8; std::mem::size_of::<BpfSessionValueV4>()];
            unsafe {
                std::ptr::copy_nonoverlapping(
                    (&bpf_key as *const BpfSessionKeyV4).cast::<u8>(),
                    key_bytes.as_mut_ptr(),
                    key_bytes.len(),
                );
            }
            match conntrack_lookup_bytes(target, &key_bytes, &mut value).ok_or(())? {
                0 => Ok(Some(ConntrackEntrySnapshot(ConntrackEntrySnapshotData::V4 {
                    key: key_bytes,
                    value,
                }))),
                rc if rc == -libc::ENOENT => Ok(None),
                _ => Err(()),
            }
        }
        (ConntrackTarget::V6(fd), IpAddr::V6(src), IpAddr::V6(dst)) if fd >= 0 => {
            let bpf_key =
                bpf_session_key_v6(src.octets(), dst.octets(), key.src_port, key.dst_port, key.protocol);
            let mut key_bytes = [0u8; std::mem::size_of::<BpfSessionKeyV6>()];
            let mut value = [0u8; std::mem::size_of::<BpfSessionValueV6>()];
            unsafe {
                std::ptr::copy_nonoverlapping(
                    (&bpf_key as *const BpfSessionKeyV6).cast::<u8>(),
                    key_bytes.as_mut_ptr(),
                    key_bytes.len(),
                );
            }
            match conntrack_lookup_bytes(target, &key_bytes, &mut value).ok_or(())? {
                0 => Ok(Some(ConntrackEntrySnapshot(ConntrackEntrySnapshotData::V6 {
                    key: key_bytes,
                    value,
                }))),
                rc if rc == -libc::ENOENT => Ok(None),
                _ => Err(()),
            }
        }
        (ConntrackTarget::NoMap { .. }, _, _) => Ok(None),
        (ConntrackTarget::CrossFamily, _, _) => Ok(None),
        _ => Ok(None),
    }
}

/// Restore an exact-byte snapshot with `BPF_ANY`; test snapshots restore only
/// through the selected test fd.
pub(crate) fn restore_conntrack_entry(
    conntrack_v4_fd: c_int,
    conntrack_v6_fd: c_int,
    snapshot: &ConntrackEntrySnapshot,
) -> bool {
    let target = match &snapshot.0 {
        ConntrackEntrySnapshotData::V4 { .. } => {
            selected_target(libc::AF_INET as u8, conntrack_v4_fd)
        }
        ConntrackEntrySnapshotData::V6 { .. } => {
            selected_target(libc::AF_INET6 as u8, conntrack_v6_fd)
        }
        #[cfg(test)]
        ConntrackEntrySnapshotData::Test(record) => {
            conntrack_target(conntrack_v4_fd, conntrack_v6_fd, &record.key)
        }
    };
    match (&snapshot.0, target) {
        (ConntrackEntrySnapshotData::V4 { key, value }, ConntrackTarget::V4(fd)) if fd >= 0 => {
            conntrack_update_bytes(target, key, value, libbpf_sys::BPF_ANY as u64)
        }
        (ConntrackEntrySnapshotData::V6 { key, value }, ConntrackTarget::V6(fd)) if fd >= 0 => {
            conntrack_update_bytes(target, key, value, libbpf_sys::BPF_ANY as u64)
        }
        #[cfg(test)]
        (ConntrackEntrySnapshotData::Test(record), _) if target.is_test_map() => {
            if conntrack_restore_failure_for_test() {
                return false;
            }
            insert_conntrack_test_row(record.clone());
            true
        }
        _ => false,
    }
}

/// Commit a successful orchestrated publish to the fake backend only after
/// publish overrides have selected the final result.
#[cfg(test)]
pub(crate) fn commit_conntrack_test_publish(
    target: ConntrackTarget,
    record: ConntrackPublishRecord,
    result: ConntrackPublishResult,
) {
    if target.is_test_map() && result == ConntrackPublishResult::Written {
        insert_conntrack_test_row(record);
    }
}


// ── Exact-byte snapshot/restore I/O ──
//
// Snapshot/restore move the row's exact key/value bytes (padding included),
// so they take byte slices rather than the typed structs above.

/// Exact-byte lookup for snapshots: fills `value` and returns the syscall
/// shape (`Some(0)` hit, `Some(rc != 0)` miss/error, `None` no route). Under
/// the test fd the caller substitutes its recorded snapshot instead.
pub(crate) fn conntrack_lookup_bytes(
    target: ConntrackTarget,
    key_bytes: &[u8],
    value: &mut [u8],
) -> Option<c_int> {
    let fd = match target {
        ConntrackTarget::V4(fd) | ConntrackTarget::V6(fd) if fd >= 0 => fd,
        _ => return None,
    };
    Some(unsafe {
        libbpf_sys::bpf_map_lookup_elem(
            fd,
            key_bytes.as_ptr().cast::<c_void>(),
            value.as_mut_ptr().cast::<c_void>(),
        )
    })
}

/// Exact-byte update for restores; `false` when there is no route or the
/// update fails.
pub(crate) fn conntrack_update_bytes(
    target: ConntrackTarget,
    key_bytes: &[u8],
    value: &[u8],
    flags: u64,
) -> bool {
    let fd = match target {
        ConntrackTarget::V4(fd) | ConntrackTarget::V6(fd) if fd >= 0 => fd,
        _ => return false,
    };
    unsafe {
        libbpf_sys::bpf_map_update_elem(
            fd,
            key_bytes.as_ptr().cast::<c_void>(),
            value.as_ptr().cast::<c_void>(),
            flags,
        ) == 0
    }
}

// ── Test row backend ──
//
// The fake conntrack rows and their instrumentation. Backend operation
// wrappers (`conntrack_lookup`/`conntrack_update`/`conntrack_delete` above and
// the helpers below) are the only consumers; orchestration recorders
// (`CONNTRACK_PUBLISHES`, publish overrides, #10590 `RESTAMP_ATTEMPTS`) stay in
// `mod.rs` because they instrument callers, not the backend.

#[cfg(test)]
thread_local! {
    static CONNTRACK_TEST_ROWS:
        std::cell::RefCell<std::collections::HashMap<SessionKey, ConntrackPublishRecord>> =
        std::cell::RefCell::new(std::collections::HashMap::new());
    static CONNTRACK_RESTORE_FAIL: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static CONNTRACK_TEST_APP_ID_RESTAMP_WRITES: std::cell::Cell<usize> =
        const { std::cell::Cell::new(0) };
    /// #12620: restamp lookups (the per-connection BPF read). Thread-local
    /// like the writes counter: production cannot take a lock, and each
    /// revalidation test drives its hits synchronously on its own thread.
    static CONNTRACK_TEST_APP_ID_RESTAMP_LOOKUPS: std::cell::Cell<usize> =
        const { std::cell::Cell::new(0) };
    static CONNTRACK_TEST_REFRESH_WRITES: std::cell::Cell<usize> =
        const { std::cell::Cell::new(0) };
}

#[cfg(test)]
fn bare_conntrack_test_key(key: &SessionKey) -> SessionKey {
    let mut key = key.clone();
    key.routing_domain = 0;
    key.discriminator = Default::default();
    key
}

#[cfg(test)]
pub(crate) fn conntrack_row_for_test(key: &SessionKey) -> Option<ConntrackPublishRecord> {
    CONNTRACK_TEST_ROWS.with(|rows| rows.borrow().get(&bare_conntrack_test_key(key)).cloned())
}

#[cfg(test)]
pub(crate) struct ConntrackRestoreFailureGuard;

#[cfg(test)]
impl Drop for ConntrackRestoreFailureGuard {
    fn drop(&mut self) {
        CONNTRACK_RESTORE_FAIL.with(|fail| fail.set(false));
    }
}

#[cfg(test)]
pub(crate) fn force_conntrack_restore_failure_for_test() -> ConntrackRestoreFailureGuard {
    CONNTRACK_RESTORE_FAIL.with(|fail| fail.set(true));
    ConntrackRestoreFailureGuard
}

#[cfg(test)]
pub(crate) fn conntrack_restore_failure_for_test() -> bool {
    CONNTRACK_RESTORE_FAIL.with(std::cell::Cell::get)
}

#[cfg(test)]
pub(crate) fn clear_conntrack_rows_for_test() {
    CONNTRACK_TEST_ROWS.with(|rows| rows.borrow_mut().clear());
    CONNTRACK_TEST_APP_ID_RESTAMP_WRITES.with(|writes| writes.set(0));
    CONNTRACK_TEST_APP_ID_RESTAMP_LOOKUPS.with(|lookups| lookups.set(0));
    CONNTRACK_TEST_REFRESH_WRITES.with(|writes| writes.set(0));
}

#[cfg(test)]
pub(crate) fn conntrack_refresh_writes_for_test() -> usize {
    CONNTRACK_TEST_REFRESH_WRITES.with(std::cell::Cell::get)
}

#[cfg(test)]
pub(crate) fn conntrack_app_id_restamp_writes_for_test() -> usize {
    CONNTRACK_TEST_APP_ID_RESTAMP_WRITES.with(std::cell::Cell::get)
}

#[cfg(test)]
pub(crate) fn conntrack_app_id_restamp_lookups_for_test() -> usize {
    CONNTRACK_TEST_APP_ID_RESTAMP_LOOKUPS.with(std::cell::Cell::get)
}

/// Commit a published row to the fake backend (publish commit and restore).
#[cfg(test)]
pub(crate) fn insert_conntrack_test_row(record: ConntrackPublishRecord) {
    CONNTRACK_TEST_ROWS.with(|rows| {
        rows.borrow_mut()
            .insert(bare_conntrack_test_key(&record.key), record);
    });
}

#[cfg(test)]
fn delete_test_row(key: &SessionKey) -> bool {
    CONNTRACK_TEST_ROWS
        .with(|rows| rows.borrow_mut().remove(&bare_conntrack_test_key(key)))
        .is_some()
}

/// Project the fake row onto a v4 value for a test-backend lookup. Only the
/// fields `ConntrackPublishRecord` carries are projected; the rest of the
/// caller's zeroed value is untouched, exactly as the pre-boundary seams did.
#[cfg(test)]
fn project_test_row_v4(value: &mut BpfSessionValueV4, row: &ConntrackPublishRecord) {
    value.session_id = row.session_id;
    value.app_id = row.app_id;
    value.flags = cluster_synced_flags(value.flags, row.cluster_synced);
    value.ingress_zone = row.ingress_zone as u16;
    value.egress_zone = row.egress_zone as u16;
    value.ingress_ifindex = row.ingress_ifindex;
    value.ingress_vlan_id = row.ingress_vlan_id;
    value.is_reverse = if row.is_reverse { 1 } else { 0 };
}

/// V6 counterpart to [`project_test_row_v4`].
#[cfg(test)]
fn project_test_row_v6(value: &mut BpfSessionValueV6, row: &ConntrackPublishRecord) {
    value.session_id = row.session_id;
    value.app_id = row.app_id;
    value.flags = cluster_synced_flags(value.flags, row.cluster_synced);
    value.ingress_zone = row.ingress_zone as u16;
    value.egress_zone = row.egress_zone as u16;
    value.ingress_ifindex = row.ingress_ifindex;
    value.ingress_vlan_id = row.ingress_vlan_id;
    value.is_reverse = if row.is_reverse { 1 } else { 0 };
}

/// Test-backend half of `conntrack_update`: sync the fake row's mirrored
/// fields from the stamped value, maintain the AppID restamp counter, and
/// report a missing in-place update as the syscall's `-ENOENT` result.
#[cfg(test)]
fn update_test_row(key: &SessionKey, value: ConntrackValueRef<'_>, flags: u64) -> c_int {
    let _ = flags;
    CONNTRACK_TEST_ROWS.with(|rows| {
        let mut rows = rows.borrow_mut();
        let Some(row) = rows.get_mut(&bare_conntrack_test_key(key)) else {
            return -libc::ENOENT;
        };
        match value {
            ConntrackValueRef::V4(value) => {
                let app_changed = row.app_id != value.app_id;
                row.app_id = value.app_id;
                row.cluster_synced = value.flags & SESS_FLAG_CLUSTER_SYNCED != 0;
                row.ingress_zone = u32::from(value.ingress_zone);
                row.egress_zone = u32::from(value.egress_zone);
                if app_changed {
                    CONNTRACK_TEST_APP_ID_RESTAMP_WRITES
                        .with(|writes| writes.set(writes.get() + 1));
                }
            }
            ConntrackValueRef::V6(value) => {
                let app_changed = row.app_id != value.app_id;
                row.app_id = value.app_id;
                row.cluster_synced = value.flags & SESS_FLAG_CLUSTER_SYNCED != 0;
                row.ingress_zone = u32::from(value.ingress_zone);
                row.egress_zone = u32::from(value.egress_zone);
                if app_changed {
                    CONNTRACK_TEST_APP_ID_RESTAMP_WRITES
                        .with(|writes| writes.set(writes.get() + 1));
                }
            }
        }
        0
    })
}

/// Count one test-backend restamp lookup (#12191/#12620 instrumentation).
#[cfg(test)]
pub(crate) fn count_conntrack_test_lookup() {
    CONNTRACK_TEST_APP_ID_RESTAMP_LOOKUPS.with(|lookups| lookups.set(lookups.get() + 1));
}
