// #18560: the shim's `userspace_ctrl` row, read and rewritten by the helper
// when it advances the generation stamp at its view store
// (`coordinator/ctrl_stamp.rs`). The syscalls live here, beside every other
// map write, so the #16187 unsafe ratchet keeps them in one directory.

use super::*;

/// Byte-for-byte mirror of the shim's `UserspaceCtrl`
/// (userspace-xdp/src/lib.rs). `ctrl_stamp_mirror_matches_shim_struct_18560`
/// pins the field order and types against the shim source; the asserts
/// below pin the size and the two offsets this module writes.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct UserspaceCtrlValue {
    pub(crate) enabled: u32,
    pub(crate) metadata_version: u32,
    pub(crate) workers: u32,
    pub(crate) queue_count: u32,
    pub(crate) flags: u32,
    pub(crate) wg_port_count: u32,
    pub(crate) wg_ports: [u16; 8],
    pub(crate) config_generation: u64,
    pub(crate) fib_generation: u32,
    pub(crate) heartbeat_timeout_ms: u32,
}

const _: () = assert!(std::mem::size_of::<UserspaceCtrlValue>() == 56);
const _: () = assert!(std::mem::offset_of!(UserspaceCtrlValue, config_generation) == 40);
const _: () = assert!(std::mem::offset_of!(UserspaceCtrlValue, fib_generation) == 48);

/// Open the pinned ctrl map and refuse one whose shape is not the shim ABI
/// this helper was built against (a one-entry array of 56-byte values).
pub(in crate::afxdp) fn open_ctrl_row(path: &str) -> io::Result<OwnedFd> {
    let fd = OwnedFd::open_bpf_map(path)?;
    let mut info = libbpf_sys::bpf_map_info::default();
    let mut len = std::mem::size_of::<libbpf_sys::bpf_map_info>() as u32;
    // SAFETY: `info` is a live, writable bpf_map_info and `len` is its size;
    // the kernel writes at most `len` bytes.
    let rc = unsafe {
        libbpf_sys::bpf_obj_get_info_by_fd(
            fd.fd,
            (&mut info as *mut libbpf_sys::bpf_map_info).cast::<c_void>(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    if info.type_ != libbpf_sys::BPF_MAP_TYPE_ARRAY
        || info.key_size != 4
        || info.value_size as usize != std::mem::size_of::<UserspaceCtrlValue>()
        || info.max_entries != 1
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "userspace_ctrl shape type={} key={} value={} entries={} is not the shim ABI",
                info.type_, info.key_size, info.value_size, info.max_entries
            ),
        ));
    }
    Ok(fd)
}

pub(in crate::afxdp) fn lookup_ctrl_row(fd: &OwnedFd) -> io::Result<UserspaceCtrlValue> {
    let key = 0u32;
    let mut value = UserspaceCtrlValue::default();
    // SAFETY: key and value point at live locals of the map's key and value
    // sizes (checked by open_ctrl_row).
    let rc = unsafe {
        libbpf_sys::bpf_map_lookup_elem(
            fd.fd,
            (&key as *const u32).cast::<c_void>(),
            (&mut value as *mut UserspaceCtrlValue).cast::<c_void>(),
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(value)
}

pub(in crate::afxdp) fn update_ctrl_row(fd: &OwnedFd, value: &UserspaceCtrlValue) -> io::Result<()> {
    let key = 0u32;
    // SAFETY: as lookup_ctrl_row; BPF_EXIST never creates an entry.
    let rc = unsafe {
        libbpf_sys::bpf_map_update_elem(
            fd.fd,
            (&key as *const u32).cast::<c_void>(),
            (value as *const UserspaceCtrlValue).cast::<c_void>(),
            libbpf_sys::BPF_EXIST as u64,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
