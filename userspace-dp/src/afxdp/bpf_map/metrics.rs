// Telemetry / ring-metrics publishing for the BPF session map.
//
// Pure code motion out of `bpf_map/mod.rs` (#2003): the raw XDP ring
// state probe, the USERSPACE_SESSIONS entry count/dump diagnostics, and
// the always-on / debug-gated publish counters now live here. None of
// these touch the forwarding decision; they exist purely to surface map
// occupancy and publish health to the CLI / Prometheus collectors.
//
// Behaviour-preserving: signatures, the getsockopt/mmap raw-ring probe,
// the bpf_map_get_next_key iteration, the 10000-entry safety limit, and
// the debug-log gating are unchanged from the pre-split orchestrator.
//
// Precedent: the sibling `publish_conntrack.rs` split (#1356).

use super::*;

pub(in crate::afxdp) fn diagnose_raw_ring_state(
    sock_fd: c_int,
) -> Option<(u32, u32, u32, u32, u32, u32, u32, u32)> {
    // SOL_XDP (283) comes from afxdp/mod.rs via `use super::*` —
    // #1826 deduplicated the former local copy.
    const XDP_MMAP_OFFSETS: i32 = 1;
    const XDP_PGOFF_RX_RING: i64 = 0;
    const XDP_PGOFF_TX_RING: i64 = 0x80000000;
    const XDP_UMEM_PGOFF_FILL_RING: i64 = 0x100000000;
    const XDP_UMEM_PGOFF_COMPLETION_RING: i64 = 0x180000000;

    // xdp_mmap_offsets_v2 (kernel >= 5.4): 4 rings × 4 fields × u64 each
    #[repr(C)]
    #[derive(Default)]
    struct XdpRingOffset {
        producer: u64,
        consumer: u64,
        desc: u64,
        flags: u64,
    }
    #[repr(C)]
    #[derive(Default)]
    struct XdpMmapOffsets {
        rx: XdpRingOffset,
        tx: XdpRingOffset,
        fr: XdpRingOffset,
        cr: XdpRingOffset,
    }

    let mut off = XdpMmapOffsets::default();
    let mut optlen = core::mem::size_of::<XdpMmapOffsets>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            sock_fd,
            SOL_XDP,
            XDP_MMAP_OFFSETS,
            (&mut off as *mut XdpMmapOffsets).cast::<libc::c_void>(),
            &mut optlen,
        )
    };
    if rc != 0 {
        return None;
    }

    fn read_ring_pair(sock_fd: c_int, off: &XdpRingOffset, pgoff: i64) -> (u32, u32) {
        let map_len = (off.desc.max(off.consumer).max(off.producer) + 8) as usize;
        let mmap_ptr = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                map_len,
                libc::PROT_READ,
                libc::MAP_SHARED,
                sock_fd,
                pgoff,
            )
        };
        if mmap_ptr == libc::MAP_FAILED {
            return (0, 0);
        }
        let prod = unsafe { *(mmap_ptr.byte_add(off.producer as usize) as *const u32) };
        let cons = unsafe { *(mmap_ptr.byte_add(off.consumer as usize) as *const u32) };
        unsafe { libc::munmap(mmap_ptr, map_len) };
        (prod, cons)
    }

    let (rx_prod, rx_cons) = read_ring_pair(sock_fd, &off.rx, XDP_PGOFF_RX_RING);
    let (fr_prod, fr_cons) = read_ring_pair(sock_fd, &off.fr, XDP_UMEM_PGOFF_FILL_RING);
    let (tx_prod, tx_cons) = read_ring_pair(sock_fd, &off.tx, XDP_PGOFF_TX_RING);
    let (cr_prod, cr_cons) = read_ring_pair(sock_fd, &off.cr, XDP_UMEM_PGOFF_COMPLETION_RING);

    Some((
        rx_prod, rx_cons, fr_prod, fr_cons, tx_prod, tx_cons, cr_prod, cr_cons,
    ))
}

/// Count total entries in the BPF USERSPACE_SESSIONS map.
pub(in crate::afxdp) fn count_bpf_session_entries(map_fd: c_int) -> u32 {
    let mut count = 0u32;
    let key_size = core::mem::size_of::<UserspaceSessionMapKey>();
    let mut key = vec![0u8; key_size];
    let mut next_key = vec![0u8; key_size];
    // First key
    let rc = unsafe {
        libbpf_sys::bpf_map_get_next_key(
            map_fd,
            core::ptr::null(),
            next_key.as_mut_ptr().cast::<c_void>(),
        )
    };
    if rc != 0 {
        return 0;
    }
    count += 1;
    key.copy_from_slice(&next_key);
    loop {
        let rc = unsafe {
            libbpf_sys::bpf_map_get_next_key(
                map_fd,
                key.as_ptr().cast::<c_void>(),
                next_key.as_mut_ptr().cast::<c_void>(),
            )
        };
        if rc != 0 {
            break;
        }
        count += 1;
        key.copy_from_slice(&next_key);
        if count > 10000 {
            break; // safety limit
        }
    }
    count
}

/// Decode a `UserspaceSessionMapKey` from a raw BPF key buffer produced by
/// `bpf_map_get_next_key`.
///
/// #4882: the buffer is a `Vec<u8>` (alignment 1) but the struct is
/// `#[repr(C)]` with `u16` fields (alignment 2). A plain `ptr::read` (or a
/// `&*(ptr as *const UserspaceSessionMapKey)` cast) requires the source
/// pointer to be aligned for the target type, which the byte buffer does not
/// guarantee — that is UB and faults on architectures that reject misaligned
/// loads (x86 tolerates it but it remains UB and a portability footgun). Use
/// the crate's existing unaligned-metadata idiom (`frame::inspect`'s
/// `read_unaligned`).
fn decode_session_map_key(key_bytes: &[u8]) -> UserspaceSessionMapKey {
    debug_assert!(key_bytes.len() >= core::mem::size_of::<UserspaceSessionMapKey>());
    // SAFETY: `read_unaligned` imposes no alignment requirement on the source
    // pointer. The caller passes a buffer sized to `key_size` (==
    // `size_of::<UserspaceSessionMapKey>()`), and every bit pattern is a valid
    // value for this POD `#[repr(C)]` struct (only `u8`/`u16`/`[u8; N]`
    // fields), so the read is sound.
    unsafe { core::ptr::read_unaligned(key_bytes.as_ptr().cast::<UserspaceSessionMapKey>()) }
}

/// Dump first N entries from the BPF USERSPACE_SESSIONS map for debugging.
#[allow(unused_variables)]
pub(in crate::afxdp) fn dump_bpf_session_entries(map_fd: c_int, max_entries: u32) {
    let key_size = core::mem::size_of::<UserspaceSessionMapKey>();
    let mut key_bytes = vec![0u8; key_size];
    let mut next_key_bytes = vec![0u8; key_size];
    let mut value = 0u8;
    let mut count = 0u32;
    // First key
    let rc = unsafe {
        libbpf_sys::bpf_map_get_next_key(
            map_fd,
            core::ptr::null(),
            next_key_bytes.as_mut_ptr().cast::<c_void>(),
        )
    };
    if rc != 0 {
        debug_log!("BPF_MAP_DUMP: empty (no entries)");
        return;
    }
    loop {
        // Read the key as UserspaceSessionMapKey (alignment-safe: the key
        // buffer is a `Vec<u8>` with no alignment guarantee — see #4882).
        let map_key: UserspaceSessionMapKey = decode_session_map_key(&next_key_bytes);
        let _ = unsafe {
            libbpf_sys::bpf_map_lookup_elem(
                map_fd,
                next_key_bytes.as_ptr().cast::<c_void>(),
                (&mut value as *mut u8).cast::<c_void>(),
            )
        };
        #[cfg(feature = "debug-log")]
        {
            let src_ip = if map_key.addr_family == libc::AF_INET as u8 {
                format!(
                    "{}.{}.{}.{}",
                    map_key.src_addr[0],
                    map_key.src_addr[1],
                    map_key.src_addr[2],
                    map_key.src_addr[3]
                )
            } else {
                format!(
                    "v6[{:02x}{:02x}::{:02x}{:02x}]",
                    map_key.src_addr[0],
                    map_key.src_addr[1],
                    map_key.src_addr[14],
                    map_key.src_addr[15]
                )
            };
            let dst_ip = if map_key.addr_family == libc::AF_INET as u8 {
                format!(
                    "{}.{}.{}.{}",
                    map_key.dst_addr[0],
                    map_key.dst_addr[1],
                    map_key.dst_addr[2],
                    map_key.dst_addr[3]
                )
            } else {
                format!(
                    "v6[{:02x}{:02x}::{:02x}{:02x}]",
                    map_key.dst_addr[0],
                    map_key.dst_addr[1],
                    map_key.dst_addr[14],
                    map_key.dst_addr[15]
                )
            };
            debug_log!(
                "BPF_MAP_DUMP[{}]: af={} proto={} {}:{} -> {}:{} val={}",
                count,
                map_key.addr_family,
                map_key.protocol,
                src_ip,
                map_key.src_port,
                dst_ip,
                map_key.dst_port,
                value,
            );
        }
        count += 1;
        if count >= max_entries {
            break;
        }
        key_bytes.copy_from_slice(&next_key_bytes);
        let rc = unsafe {
            libbpf_sys::bpf_map_get_next_key(
                map_fd,
                key_bytes.as_ptr().cast::<c_void>(),
                next_key_bytes.as_mut_ptr().cast::<c_void>(),
            )
        };
        if rc != 0 {
            break;
        }
    }
    debug_log!("BPF_MAP_DUMP: total={count} entries");
}

pub(in crate::afxdp) static SESSION_PUBLISH_VERIFY_OK: AtomicU64 = AtomicU64::new(0);
pub(in crate::afxdp) static SESSION_PUBLISH_VERIFY_FAIL: AtomicU64 = AtomicU64::new(0);
/// #1789: failed USERSPACE_SESSIONS BPF-map publishes from call sites
/// that have no per-binding context (HA `upsert_synced_session`,
/// session-glue worker publishes, post-reconcile `replay_synced_sessions`,
/// activation/reverse prewarm). Always-on (NOT debug-gated, unlike the
/// VERIFY counters above which only move under `debug-log`): a swallowed
/// publish `Err` means the XDP shim never learns the key and the flow
/// takes the NO_SESSION degraded path. Per-binding worker poll sites use
/// `BindingLiveState::session_publish_errors` instead; the two are summed
/// by `Coordinator::session_publish_errors_total()` and surfaced as
/// `xpf_userspace_session_publish_errors_total`.
pub(in crate::afxdp) static SESSION_PUBLISH_ERRORS_SHARED: AtomicU64 = AtomicU64::new(0);
// #2170 `SESSION_INSTALL_STALE_IGNORED` / `SESSION_DELETE_STALE_IGNORED` and
// #5674 `SYNCED_IMPORT_CAP_DROPS` used to live here as process-global statics.
// They are now PER-COORDINATOR fields on `SessionManager`
// (`coordinator/session_manager.rs`: `install_stale_ignored`,
// `delete_stale_ignored`, `import_cap_drops`) — every bump site and every read
// site already had a `&self` `Coordinator`, and production builds exactly one
// `Coordinator`, so the emitted metric values are unchanged. As globals they
// were shared by the one-`Coordinator`-per-`#[test]` suite, which made each
// test's assertion depend on what every concurrently-running test did (#6819).
pub(in crate::afxdp) static SESSION_CREATIONS_LOGGED: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "debug-log")]
pub(in crate::afxdp) static ICMPV6_EMBED_LOGGED: AtomicU32 = AtomicU32::new(0);

#[cfg(test)]
mod tests {
    use super::*;

    /// #4882: the debug BPF session dump decodes a `#[repr(C)]` key struct
    /// (alignment 2 — it carries `u16` fields) out of a `Vec<u8>` key buffer
    /// (alignment 1). The old `core::ptr::read` required the source pointer to
    /// be aligned for the struct, which the byte buffer does not guarantee →
    /// UB. `decode_session_map_key` uses `read_unaligned`; this drives it
    /// through a deliberately mis-aligned (odd-address) source and asserts the
    /// fields decode correctly.
    #[test]
    fn decode_session_map_key_from_misaligned_buffer() {
        let key = UserspaceSessionMapKey {
            addr_family: libc::AF_INET as u8,
            protocol: 6,
            pad: 0,
            src_port: 0x1234,
            dst_port: 0xabcd,
            src_addr: [10, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            dst_addr: [10, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        };
        let size = core::mem::size_of::<UserspaceSessionMapKey>();

        // Native byte view of the reference key.
        let key_bytes: &[u8] = unsafe {
            core::slice::from_raw_parts((&key as *const UserspaceSessionMapKey).cast::<u8>(), size)
        };

        // Copy those bytes so that the decode source starts at an ODD address,
        // guaranteeing misalignment for an alignment-2 struct regardless of the
        // allocator's base alignment. The old `ptr::read` on this pointer is UB;
        // `read_unaligned` is sound.
        let mut buf = vec![0u8; size + 1];
        let off = if buf.as_ptr() as usize % 2 == 0 { 1 } else { 0 };
        buf[off..off + size].copy_from_slice(key_bytes);
        let misaligned = &buf[off..off + size];
        assert_eq!(
            misaligned.as_ptr() as usize % 2,
            1,
            "decode source must be misaligned for an alignment-2 struct",
        );

        let decoded = decode_session_map_key(misaligned);

        assert_eq!(decoded.addr_family, key.addr_family);
        assert_eq!(decoded.protocol, key.protocol);
        assert_eq!(decoded.src_port, key.src_port);
        assert_eq!(decoded.dst_port, key.dst_port);
        assert_eq!(decoded.src_addr, key.src_addr);
        assert_eq!(decoded.dst_addr, key.dst_addr);
    }
}
