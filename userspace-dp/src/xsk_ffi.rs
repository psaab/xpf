//! Drop-in replacement for xdpilone using libxdp's XSK helpers via C bridge.
//!
//! Provides the same type names and API surface as xdpilone so that the
//! rest of the codebase needs minimal changes:
//!   - `Umem`, `UmemConfig`, `UmemChunk`, `BufIdx`
//!   - `IfInfo`, `Socket`, `SocketConfig`, `User`
//!   - `DeviceQueue`, `RingRx`, `RingTx`
//!   - `ReadRx`, `WriteTx`, `WriteFill`, `ReadComplete`
//!   - `XdpDesc` (re-export from `xdp` submodule)

use core::ffi::{c_char, c_int, c_void};
use core::ptr::NonNull;
use std::ffi::CString;

// ── C bridge FFI declarations ────────────────────────────────────────

#[repr(C)]
pub(crate) struct XskRingProd {
    cached_prod: u32,
    cached_cons: u32,
    mask: u32,
    size: u32,
    producer: *mut u32,
    consumer: *mut u32,
    ring: *mut c_void,
    flags: *mut u32,
}

#[repr(C)]
pub(crate) struct XskRingCons {
    cached_prod: u32,
    cached_cons: u32,
    mask: u32,
    size: u32,
    producer: *mut u32,
    consumer: *mut u32,
    ring: *mut c_void,
    flags: *mut u32,
}

/// Opaque libxdp types — we only hold pointers to these.
#[repr(C)]
pub(crate) struct XskUmemOpaque {
    _opaque: [u8; 0],
}

#[repr(C)]
pub(crate) struct XskSocketOpaque {
    _opaque: [u8; 0],
}

unsafe impl Send for XskRingProd {}
unsafe impl Send for XskRingCons {}

unsafe extern "C" {
    fn bridge_xsk_umem_create(
        umem_out: *mut *mut XskUmemOpaque,
        umem_area: *mut c_void,
        size: u64,
        fill: *mut XskRingProd,
        comp: *mut XskRingCons,
        fill_size: u32,
        comp_size: u32,
        frame_size: u32,
        headroom: u32,
        flags: u32,
    ) -> c_int;

    fn bridge_xsk_umem_delete(umem: *mut XskUmemOpaque) -> c_int;
    fn bridge_xsk_umem_fd(umem: *const XskUmemOpaque) -> c_int;

    fn bridge_xsk_socket_create_private(
        xsk_out: *mut *mut XskSocketOpaque,
        ifname: *const c_char,
        queue_id: u32,
        umem: *mut XskUmemOpaque,
        rx: *mut XskRingCons,
        tx: *mut XskRingProd,
        fill: *mut XskRingProd,
        comp: *mut XskRingCons,
        rx_size: u32,
        tx_size: u32,
        libxdp_flags: u32,
        xdp_flags: u32,
        bind_flags: u16,
    ) -> c_int;

    fn bridge_xsk_socket_create_shared(
        xsk_out: *mut *mut XskSocketOpaque,
        ifname: *const c_char,
        queue_id: u32,
        umem: *mut XskUmemOpaque,
        rx: *mut XskRingCons,
        tx: *mut XskRingProd,
        fill: *mut XskRingProd,
        comp: *mut XskRingCons,
        rx_size: u32,
        tx_size: u32,
        libxdp_flags: u32,
        xdp_flags: u32,
        bind_flags: u16,
    ) -> c_int;

    fn bridge_xsk_socket_delete(xsk: *mut XskSocketOpaque);
    fn bridge_xsk_socket_fd(xsk: *const XskSocketOpaque) -> c_int;

    fn bridge_xsk_ring_prod_reserve(ring: *mut XskRingProd, nb: u32, idx_out: *mut u32) -> u32;
    fn bridge_xsk_ring_prod_submit(ring: *mut XskRingProd, nb: u32);
    fn bridge_xsk_ring_prod_cancel(ring: *mut XskRingProd, nb: u32);
    fn bridge_xsk_ring_prod_needs_wakeup(ring: *const XskRingProd) -> c_int;
    fn bridge_xsk_fill_addr_set(fill: *mut XskRingProd, idx: u32, addr: u64);
    fn bridge_xsk_tx_desc_set(tx: *mut XskRingProd, idx: u32, addr: u64, len: u32, options: u32);

    fn bridge_xsk_ring_cons_peek(ring: *mut XskRingCons, nb: u32, idx_out: *mut u32) -> u32;
    fn bridge_xsk_ring_cons_release(ring: *mut XskRingCons, nb: u32);
    #[allow(dead_code)]
    fn bridge_xsk_ring_cons_cancel(ring: *mut XskRingCons, nb: u32);
    fn bridge_xsk_rx_desc_get(
        rx: *const XskRingCons,
        idx: u32,
        addr_out: *mut u64,
        len_out: *mut u32,
        options_out: *mut u32,
    );
    fn bridge_xsk_comp_addr_get(comp: *const XskRingCons, idx: u32) -> u64;

    fn bridge_xsk_cons_nb_avail(ring: *mut XskRingCons, nb: u32) -> u32;
    fn bridge_xsk_prod_nb_free(ring: *mut XskRingProd, nb: u32) -> u32;

    fn bridge_xsk_ring_prod_producer(ring: *const XskRingProd) -> u32;
    fn bridge_xsk_ring_prod_consumer(ring: *const XskRingProd) -> u32;
    fn bridge_xsk_ring_cons_producer(ring: *const XskRingCons) -> u32;
    fn bridge_xsk_ring_cons_consumer(ring: *const XskRingCons) -> u32;

    fn bridge_xsk_get_stats_v2(
        fd: c_int,
        rx_dropped: *mut u64,
        rx_invalid_descs: *mut u64,
        tx_invalid_descs: *mut u64,
        rx_ring_full: *mut u64,
        rx_fill_ring_empty_descs: *mut u64,
        tx_ring_empty_descs: *mut u64,
    ) -> c_int;
}

// ── XDP descriptor (kernel ABI) ──────────────────────────────────────

pub mod xdp {
    /// Rx/Tx descriptor — matches `struct xdp_desc` from the kernel.
    #[repr(C)]
    #[derive(Default, Debug, Copy, Clone)]
    pub struct XdpDesc {
        pub addr: u64,
        pub len: u32,
        pub options: u32,
    }
}

pub use xdp::XdpDesc;

// ── Error type ───────────────────────────────────────────────────────

/// Error wrapper matching the xdpilone `Errno` interface.
pub struct Errno(pub c_int);

impl Errno {
    pub fn last_os_error() -> Self {
        Errno(unsafe { *libc::__errno_location() })
    }

    pub fn get_raw(&self) -> c_int {
        self.0
    }
}

impl core::fmt::Display for Errno {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let st = unsafe { libc::strerror(self.0) };
        let cstr = unsafe { core::ffi::CStr::from_ptr(st) };
        write!(f, "{}", cstr.to_string_lossy())
    }
}

impl core::fmt::Debug for Errno {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Errno({}: {})", self.0, self)
    }
}

// ── BufIdx ───────────────────────────────────────────────────────────

/// Buffer index — transparent wrapper around u32, same as xdpilone.
#[repr(transparent)]
#[derive(Debug, Copy, Clone)]
pub struct BufIdx(pub u32);

// ── UmemConfig ───────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct UmemConfig {
    pub fill_size: u32,
    pub complete_size: u32,
    pub frame_size: u32,
    pub headroom: u32,
    pub flags: u32,
}

impl Default for UmemConfig {
    fn default() -> Self {
        UmemConfig {
            fill_size: 1 << 11,
            complete_size: 1 << 11,
            frame_size: 1 << 12,
            headroom: 0,
            flags: 0,
        }
    }
}

// ── UmemChunk ────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug)]
pub struct UmemChunk {
    pub addr: NonNull<[u8]>,
    pub offset: u64,
}

// ── SocketConfig ─────────────────────────────────────────────────────

#[derive(Debug, Default, Clone)]
pub struct SocketConfig {
    pub rx_size: Option<core::num::NonZeroU32>,
    pub tx_size: Option<core::num::NonZeroU32>,
    pub bind_flags: u16,
}

impl SocketConfig {
    pub const XDP_BIND_SHARED_UMEM: u16 = 1 << 0;
    pub const XDP_BIND_COPY: u16 = 1 << 1;
    pub const XDP_BIND_ZEROCOPY: u16 = 1 << 2;
    pub const XDP_BIND_NEED_WAKEUP: u16 = 1 << 3;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum XskCreateMode {
    PrivateUmem,
    SharedUmem,
}

impl XskCreateMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::PrivateUmem => "private",
            Self::SharedUmem => "shared",
        }
    }
}

// ── IfInfo ───────────────────────────────────────────────────────────

/// Interface info — tracks ifindex/queue_id/ifname for socket creation.
#[derive(Clone, Copy)]
pub struct IfInfo {
    ifindex: u32,
    queue_id: u32,
    ifname: [u8; libc::IFNAMSIZ],
}

impl IfInfo {
    pub fn invalid() -> Self {
        IfInfo {
            ifindex: 0,
            queue_id: 0,
            ifname: [0u8; libc::IFNAMSIZ],
        }
    }

    pub fn from_ifindex(&mut self, index: u32) -> Result<(), Errno> {
        let mut buf = [0i8; libc::IFNAMSIZ];
        let err = unsafe { libc::if_indextoname(index, buf.as_mut_ptr()) };
        if err.is_null() {
            return Err(Errno::last_os_error());
        }
        self.ifindex = index;
        self.queue_id = 0;
        // Copy name bytes
        for (i, &b) in buf.iter().enumerate() {
            self.ifname[i] = b as u8;
        }
        Ok(())
    }

    pub fn set_queue(&mut self, queue_id: u32) {
        self.queue_id = queue_id;
    }

    pub fn ifindex(&self) -> u32 {
        self.ifindex
    }

    pub fn queue_id(&self) -> u32 {
        self.queue_id
    }

    fn ifname_cstring(&self) -> CString {
        let nul_pos = self
            .ifname
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.ifname.len());
        CString::new(&self.ifname[..nul_pos]).unwrap_or_else(|_| CString::new("").unwrap())
    }
}

// ── Umem ─────────────────────────────────────────────────────────────

/// UMEM region backed by libxdp's `xsk_umem__create`.
pub struct Umem {
    inner: *mut XskUmemOpaque,
    fill: Box<XskRingProd>,
    comp: Box<XskRingCons>,
    config: UmemConfig,
    umem_area: NonNull<[u8]>,
}

// Umem is not actually thread-safe (single-writer rings), but the
// previous xdpilone code used it as Send-able. We preserve that.
unsafe impl Send for Umem {}

impl Umem {
    /// Create a new Umem using libxdp's `xsk_umem__create`.
    ///
    /// # Safety
    /// The caller must ensure `area` points to a valid, page-aligned
    /// mmap'd region that outlives this Umem.
    pub unsafe fn new(config: UmemConfig, area: NonNull<[u8]>) -> Result<Self, Errno> {
        // Safety: all operations here require the caller-guaranteed valid area.
        unsafe {
            let area_ptr = area.as_ptr() as *mut u8;
            let area_len = area.len() as u64;

            let mut fill: Box<XskRingProd> = Box::new(core::mem::zeroed());
            let mut comp: Box<XskRingCons> = Box::new(core::mem::zeroed());
            let mut umem_ptr: *mut XskUmemOpaque = core::ptr::null_mut();

            let rc = bridge_xsk_umem_create(
                &mut umem_ptr,
                area_ptr.cast::<c_void>(),
                area_len,
                &mut *fill,
                &mut *comp,
                config.fill_size,
                config.complete_size,
                config.frame_size,
                config.headroom,
                config.flags,
            );

            if rc != 0 {
                return Err(Errno(if rc < 0 { -rc } else { rc }));
            }

            Ok(Umem {
                inner: umem_ptr,
                fill,
                comp,
                config,
                umem_area: area,
            })
        }
    }

    /// Get the address/offset for a buffer index.
    pub fn frame(&self, idx: BufIdx) -> Option<UmemChunk> {
        let pitch = self.config.frame_size;
        let area_len = self.umem_area.len() as u64;
        let offset = u64::from(pitch) * u64::from(idx.0);
        if area_len.checked_sub(u64::from(pitch)) < Some(offset) {
            return None;
        }
        let base = unsafe { self.umem_area.cast::<u8>().as_ptr().offset(offset as isize) };
        let slice = core::ptr::slice_from_raw_parts_mut(base, pitch as usize);
        let addr = unsafe { NonNull::new_unchecked(slice) };
        Some(UmemChunk { addr, offset })
    }

    /// Count frames.
    pub fn len_frames(&self) -> u32 {
        let area_len = self.umem_area.len() as u64;
        let count = area_len / u64::from(self.config.frame_size);
        u32::try_from(count).unwrap_or(u32::MAX)
    }

    /// Get raw FD of the UMEM socket.
    pub fn fd(&self) -> c_int {
        unsafe { bridge_xsk_umem_fd(self.inner) }
    }

    /// Get the raw libxdp UMEM pointer for socket creation.
    pub(crate) fn as_raw_ptr(&self) -> *mut XskUmemOpaque {
        self.inner
    }
}

impl Drop for Umem {
    fn drop(&mut self) {
        if !self.inner.is_null() {
            unsafe { bridge_xsk_umem_delete(self.inner) };
        }
    }
}

// ── Socket (placeholder for API compat) ──────────────────────────────

/// In xdpilone, Socket was a raw XDP socket FD with interface info.
/// With libxdp, socket creation and binding happen in one call
/// (`xsk_socket__create_shared`), so this is now just a marker.
pub struct Socket;

impl Socket {
    /// Unused — provided for API compatibility only.
    pub fn with_shared(_info: &IfInfo, _umem: &Umem) -> Result<Self, Errno> {
        Ok(Socket)
    }

    pub fn new(_info: &IfInfo) -> Result<Self, Errno> {
        Ok(Socket)
    }
}

// ── User (placeholder for API compat) ────────────────────────────────

/// In xdpilone, User owned the rx/tx ring configuration on a socket FD.
/// With libxdp, `xsk_socket__create_shared` does everything, so User
/// just holds the resulting socket FD for XSK map registration.
pub struct User {
    fd: c_int,
}

impl User {
    pub fn as_raw_fd(&self) -> c_int {
        self.fd
    }
}

impl std::os::fd::AsRawFd for User {
    fn as_raw_fd(&self) -> c_int {
        self.fd
    }
}

// ── Partial-reservation helper ───────────────────────────────────────
//
// libxdp's `xsk_ring_prod__reserve(ring, n, idx)` is **all-or-nothing**:
// it returns `n` when `free >= n`, otherwise 0.  xdpilone accepted a
// *range* `1..=n` and reserved however many slots were available (≥1).
//
// This helper restores partial-reservation semantics.  It queries the
// actual free count via `xsk_prod_nb_free`, clamps it to `max`, and
// calls reserve with the clamped value.  Because `nb_free` already
// refreshed `cached_cons`, the subsequent `reserve(clamped)` is
// guaranteed to succeed (no entries can become *less* free between the
// two calls — the kernel only advances the consumer).

fn reserve_up_to(ring: &mut XskRingProd, max: u32, idx: &mut u32) -> u32 {
    if max == 0 {
        return 0;
    }
    // First try the fast path: ask for everything at once.
    let reserved = unsafe { bridge_xsk_ring_prod_reserve(ring, max, idx) };
    if reserved > 0 {
        return reserved;
    }
    // All-or-nothing failed.  Query actual free count (this refreshes
    // the cached consumer from the kernel side) and retry with that.
    let free = unsafe { bridge_xsk_prod_nb_free(ring, max) };
    let want = free.min(max);
    if want == 0 {
        return 0;
    }
    unsafe { bridge_xsk_ring_prod_reserve(ring, want, idx) }
}

// ── DeviceQueue ──────────────────────────────────────────────────────

/// Fill/completion ring pair + the underlying libxdp socket handle.
pub struct DeviceQueue {
    xsk: *mut XskSocketOpaque,
    fill: Box<XskRingProd>,
    comp: Box<XskRingCons>,
    fd: c_int,
}

unsafe impl Send for DeviceQueue {}

impl DeviceQueue {
    /// Submit buffers to the fill ring.
    ///
    /// Unlike libxdp's all-or-nothing `xsk_ring_prod__reserve`, this
    /// accepts a **partial** reservation (1..=max) matching xdpilone's
    /// `reserve(1..=n)` semantics. Without this, `reserve(max)` returns
    /// 0 whenever `free < max`, starving the fill ring and stalling TX.
    pub fn fill(&mut self, max: u32) -> WriteFill<'_> {
        let mut idx: u32 = 0;
        let reserved = reserve_up_to(&mut *self.fill, max, &mut idx);
        WriteFill {
            ring: &mut *self.fill,
            base_idx: idx,
            reserved,
            written: 0,
        }
    }

    /// Reap completed TX buffers from the completion ring.
    pub fn complete(&mut self, n: u32) -> ReadComplete<'_> {
        let mut idx: u32 = 0;
        let peeked = unsafe { bridge_xsk_ring_cons_peek(&mut *self.comp, n, &mut idx) };
        ReadComplete {
            ring: &mut *self.comp,
            base_idx: idx,
            peeked,
            read_count: 0,
        }
    }

    /// Completion ring entries available.
    pub fn available(&self) -> u32 {
        // Use cached_prod - cached_cons (relaxed reads via the C struct fields).
        // This matches xdpilone's DeviceQueue::available() which calls count_pending().
        let prod = unsafe { bridge_xsk_ring_cons_producer(&*self.comp) };
        let cons = unsafe { bridge_xsk_ring_cons_consumer(&*self.comp) };
        prod.wrapping_sub(cons)
    }

    /// Fill ring entries pending (produced - consumed by kernel).
    pub fn pending(&self) -> u32 {
        let prod = unsafe { bridge_xsk_ring_prod_producer(&*self.fill) };
        let cons = unsafe { bridge_xsk_ring_prod_consumer(&*self.fill) };
        prod.wrapping_sub(cons)
    }

    /// Get the raw FD for poll/wake operations.
    pub fn as_raw_fd(&self) -> c_int {
        self.fd
    }

    /// Query if the fill ring needs wakeup.
    pub fn needs_wakeup(&self) -> bool {
        unsafe { bridge_xsk_ring_prod_needs_wakeup(&*self.fill) != 0 }
    }

    /// Get XDP statistics (v2).
    pub fn statistics_v2(&self) -> Result<XdpStatisticsV2, Errno> {
        let mut stats = XdpStatisticsV2::default();
        let rc = unsafe {
            bridge_xsk_get_stats_v2(
                self.fd,
                &mut stats.rx_dropped,
                &mut stats.rx_invalid_descs,
                &mut stats.tx_invalid_descs,
                &mut stats.rx_ring_full,
                &mut stats.rx_fill_ring_empty_descs,
                &mut stats.tx_ring_empty_descs,
            )
        };
        if rc != 0 {
            return Err(Errno(if rc < 0 { -rc } else { rc }));
        }
        Ok(stats)
    }

    /// Bind a User's socket to this device queue.
    /// With libxdp this is a no-op since binding happened at socket creation.
    pub fn bind(&self, _interface: &User) -> Result<(), Errno> {
        Ok(())
    }
}

impl Drop for DeviceQueue {
    fn drop(&mut self) {
        if !self.xsk.is_null() {
            unsafe { bridge_xsk_socket_delete(self.xsk) };
        }
    }
}

impl std::os::fd::AsRawFd for DeviceQueue {
    fn as_raw_fd(&self) -> c_int {
        self.fd
    }
}

// ── XdpStatisticsV2 ──────────────────────────────────────────────────

#[derive(Debug, Default, Copy, Clone)]
pub struct XdpStatisticsV2 {
    pub rx_dropped: u64,
    pub rx_invalid_descs: u64,
    pub tx_invalid_descs: u64,
    pub rx_ring_full: u64,
    pub rx_fill_ring_empty_descs: u64,
    pub tx_ring_empty_descs: u64,
}

// ── RingRx ───────────────────────────────────────────────────────────

/// Receive ring backed by libxdp's consumer ring.
pub struct RingRx {
    ring: Box<XskRingCons>,
    fd: c_int,
}

unsafe impl Send for RingRx {}

impl RingRx {
    /// Peek and begin receiving up to `n` descriptors.
    pub fn receive(&mut self, n: u32) -> ReadRx<'_> {
        let mut idx: u32 = 0;
        let peeked = unsafe { bridge_xsk_ring_cons_peek(&mut *self.ring, n, &mut idx) };
        ReadRx {
            ring: &*self.ring,
            base_idx: idx,
            peeked,
            read_count: 0,
            released: false,
        }
    }

    /// Count of available RX descriptors using the same cached ring state
    /// that `receive`/`peek` uses internally (`xsk_cons_nb_avail`).
    ///
    /// Previous implementation read raw `*producer` / `*consumer` mmap
    /// pointers via relaxed atomics — a different code-path from the
    /// `cached_prod` / `cached_cons` state that `xsk_ring_cons__peek`
    /// maintains.  If `cached_prod` had not yet been refreshed (still 0
    /// from initialisation), `peek(n)` would load `*producer`, see the
    /// new value, and return entries — but the separate `available()`
    /// read could race or disagree with that cached state.
    ///
    /// By calling `xsk_cons_nb_avail` (the exact helper `peek` calls
    /// first), `available()` now refreshes `cached_prod` on the same
    /// struct the next `peek` will use, keeping them in sync.
    pub fn available(&mut self) -> u32 {
        unsafe { bridge_xsk_cons_nb_avail(&mut *self.ring, u32::MAX) }
    }

    /// Relaxed read of raw kernel producer/consumer pointers.
    /// Use for diagnostics only — does NOT touch cached ring state.
    pub fn available_relaxed(&self) -> u32 {
        let prod = unsafe { bridge_xsk_ring_cons_producer(&*self.ring) };
        let cons = unsafe { bridge_xsk_ring_cons_consumer(&*self.ring) };
        prod.wrapping_sub(cons)
    }

    /// Query needs_wakeup on the RX ring (uses the flags field).
    pub fn needs_wakeup(&self) -> bool {
        // RX is a consumer ring; the flags field indicates kernel needs wakeup.
        let flags_ptr = self.ring.flags;
        if flags_ptr.is_null() {
            return false;
        }
        (unsafe { *flags_ptr } & 1) != 0
    }

    pub fn as_raw_fd(&self) -> c_int {
        self.fd
    }
}

// ── RingTx ───────────────────────────────────────────────────────────

/// Transmit ring backed by libxdp's producer ring.
pub struct RingTx {
    ring: Box<XskRingProd>,
    fd: c_int,
}

unsafe impl Send for RingTx {}

impl RingTx {
    /// Reserve slots and begin transmitting up to `n` descriptors.
    ///
    /// Uses partial-reservation semantics (1..=n) to match xdpilone.
    /// See [`DeviceQueue::fill`] for rationale.
    pub fn transmit(&mut self, n: u32) -> WriteTx<'_> {
        let mut idx: u32 = 0;
        let reserved = reserve_up_to(&mut *self.ring, n, &mut idx);
        WriteTx {
            ring: &mut *self.ring,
            base_idx: idx,
            reserved,
            written: 0,
        }
    }

    /// Query needs_wakeup on the TX ring.
    pub fn needs_wakeup(&self) -> bool {
        unsafe { bridge_xsk_ring_prod_needs_wakeup(&*self.ring) != 0 }
    }

    pub fn as_raw_fd(&self) -> c_int {
        self.fd
    }
}

impl std::os::fd::AsRawFd for RingTx {
    fn as_raw_fd(&self) -> c_int {
        self.fd
    }
}

// ── ReadRx ───────────────────────────────────────────────────────────

/// Iterator over received descriptors. Must call `release()` when done.
pub struct ReadRx<'a> {
    ring: &'a XskRingCons,
    base_idx: u32,
    peeked: u32,
    read_count: u32,
    released: bool,
}

impl ReadRx<'_> {
    pub fn read(&mut self) -> Option<XdpDesc> {
        if self.read_count >= self.peeked {
            return None;
        }
        let idx = self.base_idx.wrapping_add(self.read_count);
        let mut addr: u64 = 0;
        let mut len: u32 = 0;
        let mut options: u32 = 0;
        unsafe {
            bridge_xsk_rx_desc_get(self.ring, idx, &mut addr, &mut len, &mut options);
        }
        self.read_count += 1;
        Some(XdpDesc { addr, len, options })
    }

    pub fn release(&mut self) {
        if !self.released && self.read_count > 0 {
            // Safety: we cast away the shared ref to call the release bridge.
            // This is sound because ReadRx has exclusive logical access to
            // the consumer side of this ring during its lifetime.
            let ring_ptr = self.ring as *const XskRingCons as *mut XskRingCons;
            unsafe { bridge_xsk_ring_cons_release(ring_ptr, self.read_count) };
            self.released = true;
        }
    }
}

impl Drop for ReadRx<'_> {
    fn drop(&mut self) {
        let ring_ptr = self.ring as *const XskRingCons as *mut XskRingCons;
        if !self.released && self.read_count > 0 {
            unsafe { bridge_xsk_ring_cons_release(ring_ptr, self.read_count) };
        }
        // Cancel any peeked-but-unread entries so cached_cons doesn't
        // drift ahead of the real consumer pointer.
        let unreleased = self.peeked - self.read_count;
        if unreleased > 0 {
            unsafe { bridge_xsk_ring_cons_cancel(ring_ptr, unreleased) };
        }
    }
}

// ── WriteTx ──────────────────────────────────────────────────────────

/// Writer for the TX ring. Must call `commit()` when done.
pub struct WriteTx<'a> {
    ring: &'a mut XskRingProd,
    base_idx: u32,
    reserved: u32,
    written: u32,
}

impl WriteTx<'_> {
    /// Insert descriptors from an iterator. Returns count inserted.
    pub fn insert(&mut self, it: impl Iterator<Item = XdpDesc>) -> u32 {
        let mut n = 0u32;
        for desc in it {
            if n >= self.reserved {
                break;
            }
            let idx = self.base_idx.wrapping_add(n);
            unsafe {
                bridge_xsk_tx_desc_set(self.ring, idx, desc.addr, desc.len, desc.options);
            }
            n += 1;
        }
        self.written += n;
        n
    }

    /// Commit written descriptors to the kernel.
    pub fn commit(&mut self) {
        if self.written > 0 {
            unsafe { bridge_xsk_ring_prod_submit(self.ring, self.written) };
            self.reserved -= self.written;
            self.written = 0;
        }
    }
}

impl Drop for WriteTx<'_> {
    fn drop(&mut self) {
        // Submit anything written, then cancel only the *unused* part
        // of the reservation so `cached_prod` doesn't drift ahead of
        // the real producer — matching xdpilone's cancel-on-drop.
        if self.written > 0 {
            unsafe { bridge_xsk_ring_prod_submit(self.ring, self.written) };
        }
        let unused = self.reserved.saturating_sub(self.written);
        if unused > 0 {
            unsafe { bridge_xsk_ring_prod_cancel(self.ring, unused) };
        }
    }
}

// ── WriteFill ────────────────────────────────────────────────────────

/// Writer for the fill ring. Must call `commit()` when done.
pub struct WriteFill<'a> {
    ring: &'a mut XskRingProd,
    base_idx: u32,
    reserved: u32,
    written: u32,
}

impl WriteFill<'_> {
    /// Insert buffer offsets into the fill ring.
    pub fn insert(&mut self, it: impl Iterator<Item = u64>) -> u32 {
        let mut n = 0u32;
        for addr in it {
            if n >= self.reserved {
                break;
            }
            let idx = self.base_idx.wrapping_add(n);
            unsafe { bridge_xsk_fill_addr_set(self.ring, idx, addr) };
            n += 1;
        }
        self.written += n;
        n
    }

    pub fn commit(&mut self) {
        if self.written > 0 {
            unsafe { bridge_xsk_ring_prod_submit(self.ring, self.written) };
            self.reserved -= self.written;
            self.written = 0;
        }
    }
}

impl Drop for WriteFill<'_> {
    fn drop(&mut self) {
        if self.written > 0 {
            unsafe { bridge_xsk_ring_prod_submit(self.ring, self.written) };
        }
        let unused = self.reserved.saturating_sub(self.written);
        if unused > 0 {
            unsafe { bridge_xsk_ring_prod_cancel(self.ring, unused) };
        }
    }
}

// ── ReadComplete ─────────────────────────────────────────────────────

/// Reader for the completion ring.
pub struct ReadComplete<'a> {
    ring: &'a mut XskRingCons,
    base_idx: u32,
    peeked: u32,
    read_count: u32,
}

impl ReadComplete<'_> {
    pub fn read(&mut self) -> Option<u64> {
        if self.read_count >= self.peeked {
            return None;
        }
        let idx = self.base_idx.wrapping_add(self.read_count);
        let addr = unsafe { bridge_xsk_comp_addr_get(self.ring, idx) };
        self.read_count += 1;
        Some(addr)
    }

    pub fn release(&mut self) {
        if self.read_count > 0 {
            unsafe { bridge_xsk_ring_cons_release(self.ring, self.read_count) };
            // Prevent double-release in drop
            self.peeked -= self.read_count;
            self.read_count = 0;
        }
    }
}

impl Drop for ReadComplete<'_> {
    fn drop(&mut self) {
        if self.read_count > 0 {
            unsafe { bridge_xsk_ring_cons_release(self.ring, self.read_count) };
        }
        // Cancel peeked-but-unread entries (mirrors xdpilone cancel-on-drop).
        let unreleased = self.peeked - self.read_count;
        if unreleased > 0 {
            unsafe { bridge_xsk_ring_cons_cancel(self.ring, unreleased) };
        }
    }
}

// ── Unified creation: create_xsk_binding ─────────────────────────────
//
// This replaces the multi-step xdpilone flow:
//   1. Socket::with_shared(info, umem)
//   2. umem.fq_cq(&sock)
//   3. umem.rx_tx(&sock, &config)
//   4. user.map_rx() / user.map_tx()
//   5. umem.bind(&user)
//
// With libxdp, xsk_socket__create or xsk_socket__create_shared does all of
// this in one call. The private and shared entry points stay explicit because
// their fill/completion ring ownership differs.

/// Create an XSK socket bound to `ifname:queue_id`, returning all ring
/// handles needed by the worker.
///
/// `bind_flags` is the raw XDP bind flags (copy/zerocopy/need_wakeup).
pub fn create_xsk_binding_private(
    umem: &mut Umem,
    info: &IfInfo,
    ring_entries: u32,
    bind_flags: u16,
) -> Result<(User, RingRx, RingTx, DeviceQueue), Errno> {
    let umem_ptr = umem.as_raw_ptr();
    create_xsk_binding_impl(
        Some(umem),
        umem_ptr,
        info,
        ring_entries,
        bind_flags,
        XskCreateMode::PrivateUmem,
    )
}

/// Create a shared-UMEM XSK socket using per-socket fill/completion rings.
///
/// # Safety
/// `umem_ptr` must be a live libxdp UMEM pointer owned by a `WorkerUmem` that
/// outlives the returned `DeviceQueue`. The socket must be deleted before the
/// UMEM is deleted.
pub unsafe fn create_xsk_binding_shared(
    umem_ptr: *mut XskUmemOpaque,
    info: &IfInfo,
    ring_entries: u32,
    bind_flags: u16,
) -> Result<(User, RingRx, RingTx, DeviceQueue), Errno> {
    if umem_ptr.is_null() {
        return Err(Errno(libc::EINVAL));
    }
    create_xsk_binding_impl(
        None,
        umem_ptr,
        info,
        ring_entries,
        bind_flags,
        XskCreateMode::SharedUmem,
    )
}

/// Backward-compatible private-UMEM constructor.
pub fn create_xsk_binding(
    umem: &mut Umem,
    info: &IfInfo,
    ring_entries: u32,
    bind_flags: u16,
) -> Result<(User, RingRx, RingTx, DeviceQueue), Errno> {
    create_xsk_binding_private(umem, info, ring_entries, bind_flags)
}

fn create_xsk_binding_impl(
    mut private_umem: Option<&mut Umem>,
    umem_ptr: *mut XskUmemOpaque,
    info: &IfInfo,
    ring_entries: u32,
    bind_flags: u16,
    mode: XskCreateMode,
) -> Result<(User, RingRx, RingTx, DeviceQueue), Errno> {
    let ifname = info.ifname_cstring();

    let mut rx_ring: Box<XskRingCons> = Box::new(unsafe { core::mem::zeroed() });
    let mut tx_ring: Box<XskRingProd> = Box::new(unsafe { core::mem::zeroed() });
    // Shared create uses these per-socket fill/comp rings. Private create
    // ignores them and uses the UMEM's original fill/comp rings instead.
    let mut fill_ring: Box<XskRingProd> = Box::new(unsafe { core::mem::zeroed() });
    let mut comp_ring: Box<XskRingCons> = Box::new(unsafe { core::mem::zeroed() });
    let mut xsk_ptr: *mut XskSocketOpaque = core::ptr::null_mut();

    // XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD = 1 << 0
    // We manage our own XDP program; don't let libxdp load one.
    let libxdp_flags: u32 = 1;

    let rc = unsafe {
        match mode {
            XskCreateMode::PrivateUmem => bridge_xsk_socket_create_private(
                &mut xsk_ptr,
                ifname.as_ptr(),
                info.queue_id,
                umem_ptr,
                &mut *rx_ring,
                &mut *tx_ring,
                &mut *fill_ring,
                &mut *comp_ring,
                ring_entries,
                ring_entries,
                libxdp_flags,
                0,
                bind_flags,
            ),
            XskCreateMode::SharedUmem => bridge_xsk_socket_create_shared(
                &mut xsk_ptr,
                ifname.as_ptr(),
                info.queue_id,
                umem_ptr,
                &mut *rx_ring,
                &mut *tx_ring,
                &mut *fill_ring,
                &mut *comp_ring,
                ring_entries,
                ring_entries,
                libxdp_flags,
                0,
                bind_flags,
            ),
        }
    };

    if rc != 0 {
        return Err(Errno(if rc < 0 { -rc } else { rc }));
    }

    let fd = unsafe { bridge_xsk_socket_fd(xsk_ptr) };

    // Diagnostic: verify ring structs were populated by create_shared.
    // If any pointer is null or size/mask is 0, the ring wasn't initialised.
    eprintln!(
        "xpf-xsk-ffi: create_xsk_binding mode={} fd={} rx_ring=[mask={:#x} size={} \
         producer={:?} consumer={:?} ring={:?} flags={:?} cached_prod={} cached_cons={}] \
         fill_ring=[mask={:#x} size={} cached_prod={} cached_cons={}]",
        mode.as_str(),
        fd,
        rx_ring.mask,
        rx_ring.size,
        rx_ring.producer,
        rx_ring.consumer,
        rx_ring.ring,
        rx_ring.flags,
        rx_ring.cached_prod,
        rx_ring.cached_cons,
        fill_ring.mask,
        fill_ring.size,
        fill_ring.cached_prod,
        fill_ring.cached_cons,
    );

    let user = User { fd };

    let rx = RingRx { ring: rx_ring, fd };

    let tx = RingTx { ring: tx_ring, fd };

    let (fill, comp) = match private_umem.as_deref_mut() {
        Some(umem) => {
            // Private create uses the UMEM's fill/comp rings (not the
            // per-socket boxes passed to the bridge).
            (
                std::mem::replace(&mut umem.fill, fill_ring),
                std::mem::replace(&mut umem.comp, comp_ring),
            )
        }
        None => {
            // Shared create uses the per-socket fill/comp rings returned by
            // xsk_socket__create_shared.
            (fill_ring, comp_ring)
        }
    };

    let device = DeviceQueue {
        xsk: xsk_ptr,
        fill,
        comp,
        fd,
    };

    Ok((user, rx, tx, device))
}
