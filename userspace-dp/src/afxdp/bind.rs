use super::*;
use crate::xsk_ffi::{self, DeviceQueue, IfInfo, RingRx, RingTx, SocketConfig};
use std::path::Path;

const AUTO_BIND_FLAGS: [u16; 1] = [0];
const COPY_ONLY_BIND_FLAGS: [u16; 1] = [XSK_BIND_FLAGS_COPY];
const EXPLICIT_MODE_BIND_FLAGS: [u16; 2] = [XSK_BIND_FLAGS_ZEROCOPY, XSK_BIND_FLAGS_COPY];
const SHARED_OWNER_BIND_FLAGS: [u16; 1] = [XSK_BIND_FLAGS_ZEROCOPY];
const SHARED_SECONDARY_BIND_FLAGS: [u16; 1] = [SocketConfig::XDP_BIND_SHARED_UMEM];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum AfXdpBindStrategy {
    UmemOwnerSocket,
    #[allow(dead_code)]
    SeparateOwnerSocket,
}

impl AfXdpBindStrategy {
    #[allow(dead_code)]
    fn uses_umem_owner_socket(self) -> bool {
        matches!(self, Self::UmemOwnerSocket)
    }

    pub(super) fn describe(self) -> &'static str {
        match self {
            Self::UmemOwnerSocket => "umem-owner-socket",
            Self::SeparateOwnerSocket => "separate-owner-socket",
        }
    }
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum AfXdpBinder {
    Umem,
    DeviceQueue,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum XskSocketRole {
    Private,
    SharedOwner,
    SharedSecondary,
}

impl XskSocketRole {
    pub(super) fn describe(self) -> &'static str {
        match self {
            Self::Private => "private",
            Self::SharedOwner => "shared-owner",
            Self::SharedSecondary => "shared-secondary",
        }
    }

    fn create_mode(self) -> xsk_ffi::XskCreateMode {
        match self {
            Self::Private => xsk_ffi::XskCreateMode::PrivateUmem,
            Self::SharedOwner | Self::SharedSecondary => xsk_ffi::XskCreateMode::SharedUmem,
        }
    }

    fn requires_zerocopy(self) -> bool {
        !matches!(self, Self::Private)
    }
}

/// Total UMEM frames per binding: reserved TX + 2×ring_entries for RX fill.
/// For virtio_net (fabric parent), reserved TX = ring_entries, so total is
/// 3×ring_entries frames. At UMEM_FRAME_SIZE=4096 and ring_entries=8192,
/// that's ~96 MB per binding (×queues per interface).
pub(super) fn binding_frame_count_for_driver(driver: Option<&str>, ring_entries: u32) -> u32 {
    reserved_tx_frames_for_driver(driver, ring_entries)
        .saturating_add(ring_entries.saturating_mul(2).max(1))
}

pub(super) fn ifinfo_from_binding(
    binding: &BindingStatus,
) -> Result<IfInfo, Box<dyn std::error::Error + Send + Sync>> {
    let mut info = IfInfo::invalid();
    info.from_ifindex(binding.ifindex as u32)
        .map_err(|e| format!("lookup ifindex {}: {e}", binding.ifindex))?;
    info.set_queue(binding.queue_id);
    Ok(info)
}

pub(super) fn preferred_bind_strategy(binding: &BindingStatus) -> AfXdpBindStrategy {
    bind_strategy_for_driver(interface_driver_name(&binding.interface).as_deref())
}

/// Open the AF_XDP socket/ring handles for one binding.
///
/// # Safety
/// For private UMEM bindings, the returned `DeviceQueue` borrows
/// `worker_umem`'s fill/completion ring structs. The caller must store/drop
/// the returned XSK handles before `worker_umem`, so `xsk_socket__delete`
/// runs while the UMEM ring structs are still live and before
/// `xsk_umem__delete`.
pub(super) unsafe fn open_binding_worker_rings(
    worker_umem: &mut WorkerUmem,
    info: &IfInfo,
    ring_entries: u32,
    bind_strategy: AfXdpBindStrategy,
    socket_role: XskSocketRole,
    driver_name: Option<&str>,
    poll_mode: crate::PollMode,
    pre_bind_fill_offsets: Option<&[u64]>,
) -> Result<
    (
        User,
        RingRx,
        RingTx,
        XskBindMode,
        u16,
        AfXdpBindStrategy,
        DeviceQueue,
    ),
    Box<dyn std::error::Error + Send + Sync>,
> {
    let bind_flag_candidates = bind_flag_candidates_for_socket_role(info, driver_name, socket_role);
    let mut strategies = vec![bind_strategy];
    if let Some(fallback_strategy) = alternate_bind_strategy(driver_name, bind_strategy) {
        strategies.push(fallback_strategy);
    }
    let mut last_err: Option<Box<dyn std::error::Error + Send + Sync>> = None;
    for (strategy_idx, strategy) in strategies.iter().copied().enumerate() {
        for (flags_idx, flags) in bind_flag_candidates.iter().copied().enumerate() {
            match try_open_bind(
                worker_umem,
                info,
                ring_entries,
                flags,
                socket_role,
                poll_mode,
                pre_bind_fill_offsets,
            ) {
                Ok((user, rx, tx, bind_mode, actual_flags, device)) => {
                    return Ok((user, rx, tx, bind_mode, actual_flags, strategy, device));
                }
                Err(err) => {
                    last_err = Some(err);
                    let more_flag_attempts = flags_idx + 1 < bind_flag_candidates.len();
                    let more_strategy_attempts = strategy_idx + 1 < strategies.len();
                    if more_flag_attempts {
                        eprintln!(
                            "xpf-userspace-dp: {} bind failed using {}: {} — trying {}",
                            describe_bind_flags(flags),
                            strategy.describe(),
                            last_err.as_ref().unwrap(),
                            describe_bind_flags(bind_flag_candidates[flags_idx + 1]),
                        );
                    } else if more_strategy_attempts {
                        eprintln!(
                            "xpf-userspace-dp: {} bind failed using {} on driver {:?}: {} — retrying {}",
                            describe_bind_flags(flags),
                            strategy.describe(),
                            driver_name,
                            last_err.as_ref().unwrap(),
                            strategies[strategy_idx + 1].describe(),
                        );
                    }
                }
            }
        }
    }
    Err(last_err.unwrap_or_else(|| "AF_XDP bind: no attempts executed".into()))
}

pub(super) fn bind_flag_candidates_for_interface(
    info: &IfInfo,
    driver: Option<&str>,
) -> &'static [u16] {
    if interface_uses_generic_xdp(info.ifindex()) {
        return match driver {
            Some("virtio_net") => &AUTO_BIND_FLAGS,
            _ => &COPY_ONLY_BIND_FLAGS,
        };
    }
    bind_flag_candidates_for_driver(driver)
}

pub(super) fn bind_flag_candidates_for_socket_role(
    info: &IfInfo,
    driver: Option<&str>,
    socket_role: XskSocketRole,
) -> &'static [u16] {
    match socket_role {
        XskSocketRole::Private => bind_flag_candidates_for_interface(info, driver),
        XskSocketRole::SharedOwner => &SHARED_OWNER_BIND_FLAGS,
        XskSocketRole::SharedSecondary => &SHARED_SECONDARY_BIND_FLAGS,
    }
}

pub(super) fn bind_flag_candidates_for_driver(driver: Option<&str>) -> &'static [u16] {
    match driver {
        Some("virtio_net") => &AUTO_BIND_FLAGS,
        _ => &EXPLICIT_MODE_BIND_FLAGS,
    }
}

fn interface_uses_generic_xdp(ifindex: u32) -> bool {
    let mut opts = libbpf_sys::bpf_xdp_query_opts {
        sz: core::mem::size_of::<libbpf_sys::bpf_xdp_query_opts>() as _,
        ..Default::default()
    };
    let rc = unsafe { libbpf_sys::bpf_xdp_query(ifindex as c_int, 0, &mut opts) };
    if rc != 0 {
        eprintln!(
            "xpf-userspace-dp: bpf_xdp_query(ifindex={}) failed rc={} — assuming generic XDP",
            ifindex, rc
        );
        return true;
    }
    opts.attach_mode == libbpf_sys::XDP_ATTACHED_SKB as u8
}

pub(super) fn describe_bind_flags(flags: u16) -> &'static str {
    if flags == 0 {
        "auto-mode"
    } else if (flags & SocketConfig::XDP_BIND_SHARED_UMEM) != 0 {
        "shared-umem"
    } else if (flags & SocketConfig::XDP_BIND_ZEROCOPY) != 0 {
        "zero-copy"
    } else {
        "copy-mode"
    }
}

pub(super) fn prime_fill_ring_offsets(
    device: &mut DeviceQueue,
    offsets: &[u64],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let inserted = {
        let mut fill = device.fill(offsets.len() as u32);
        let inserted = fill.insert(offsets.iter().copied());
        fill.commit();
        inserted
    };
    eprintln!(
        "prime_fill_ring: inserted={}/{} fill_pending={}",
        inserted,
        offsets.len(),
        device.pending()
    );
    if inserted == 0 {
        return Err(format!("prefill fill ring inserted 0/{}", offsets.len()).into());
    }
    // Trigger NAPI to consume fill ring entries and post RX WQEs.
    // mlx5 zero-copy processes the fill ring during RX NAPI poll.
    // We trigger it by calling recvmsg() which enters the busy-poll
    // path (if SO_BUSY_POLL is set) and drives NAPI processing.
    // Also use poll(POLLIN) and sendto() as belt-and-suspenders.
    let fd = device.as_raw_fd();
    for _ in 0..20 {
        // recvmsg with MSG_DONTWAIT triggers xsk_recvmsg → busy-poll
        let mut iov = libc::iovec {
            iov_base: core::ptr::null_mut(),
            iov_len: 0,
        };
        let mut msg: libc::msghdr = unsafe { core::mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        unsafe { libc::recvmsg(fd, &mut msg, libc::MSG_DONTWAIT) };
        // Also poll and sendto
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        unsafe { libc::poll(&mut pfd, 1, 1) };
        unsafe {
            libc::sendto(
                fd,
                core::ptr::null_mut(),
                0,
                libc::MSG_DONTWAIT,
                core::ptr::null_mut(),
                0,
            );
        }
        std::thread::yield_now();
    }
    Ok(())
}

pub(super) fn bind_strategy_for_driver(driver: Option<&str>) -> AfXdpBindStrategy {
    match driver {
        _ => AfXdpBindStrategy::UmemOwnerSocket,
    }
}

#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn binder_for_strategy(strategy: AfXdpBindStrategy) -> AfXdpBinder {
    if strategy.uses_umem_owner_socket() {
        AfXdpBinder::Umem
    } else {
        AfXdpBinder::DeviceQueue
    }
}

pub(super) fn alternate_bind_strategy(
    driver: Option<&str>,
    current: AfXdpBindStrategy,
) -> Option<AfXdpBindStrategy> {
    match (driver, current) {
        _ => None,
    }
}

pub(super) fn reserved_tx_frames_for_driver(driver: Option<&str>, ring_entries: u32) -> u32 {
    let preferred = match driver {
        Some("virtio_net") => ring_entries,
        _ => ring_entries.saturating_div(2),
    };
    preferred
        .clamp(MIN_RESERVED_TX_FRAMES, MAX_RESERVED_TX_FRAMES)
        .min(ring_entries.saturating_mul(2).saturating_sub(1))
        .max(1)
}

pub(super) fn umem_ring_size(entries: u32) -> u32 {
    entries
        .max(64)
        .checked_next_power_of_two()
        .unwrap_or(entries.max(64))
}

pub(super) fn interface_driver_name(ifname: &str) -> Option<String> {
    if ifname.is_empty() {
        return None;
    }
    let driver_link = Path::new("/sys/class/net")
        .join(ifname)
        .join("device")
        .join("driver");
    let target = std::fs::read_link(driver_link).ok()?;
    target.file_name()?.to_str().map(str::to_string)
}

#[cfg(test)]
pub(super) fn shared_umem_group_key_for_device(
    driver: Option<&str>,
    device_path: Option<&str>,
) -> Option<String> {
    match (driver, device_path) {
        // Narrow prototype only: same-device mlx5 bindings can share UMEM safely.
        (Some("mlx5_core"), Some(path)) if !path.is_empty() => Some(format!("mlx5:{path}")),
        _ => None,
    }
}

/// Create and bind an XSK socket using libxdp's `xsk_socket__create_shared`.
///
/// This replaces the multi-step xdpilone flow (Socket::with_shared →
/// umem.fq_cq → umem.rx_tx → user.map_rx/map_tx → umem.bind) with a
/// single libxdp call that does UMEM registration, ring setup, and bind
/// atomically — matching the proven libbpf xsk code path.
fn try_open_bind(
    worker_umem: &mut WorkerUmem,
    info: &IfInfo,
    ring_entries: u32,
    bind_flags: u16,
    socket_role: XskSocketRole,
    poll_mode: crate::PollMode,
    pre_bind_fill_offsets: Option<&[u64]>,
) -> Result<
    (User, RingRx, RingTx, XskBindMode, u16, DeviceQueue),
    Box<dyn std::error::Error + Send + Sync>,
> {
    for attempt in 0..BIND_RETRY_ATTEMPTS {
        let create_result = match socket_role.create_mode() {
            xsk_ffi::XskCreateMode::PrivateUmem => unsafe {
                xsk_ffi::create_xsk_binding_private(
                    worker_umem.umem_mut(),
                    info,
                    ring_entries,
                    bind_flags,
                )
            },
            xsk_ffi::XskCreateMode::SharedUmem => unsafe {
                xsk_ffi::create_xsk_binding_shared(
                    worker_umem.as_raw_umem_ptr(),
                    info,
                    ring_entries,
                    bind_flags,
                )
            },
        };
        match create_result {
            Ok((user, rx, tx, mut device)) => {
                let user_fd = user.as_raw_fd();

                // Prime the fill ring AFTER bind — libxdp already binds
                // the socket during create_shared. Post-bind fill ring
                // priming triggers NAPI to consume entries and post WQEs.
                if let Some(offsets) = pre_bind_fill_offsets {
                    prime_fill_ring_offsets(&mut device, offsets)?;
                }

                let bind_mode = query_bound_xsk_mode(user_fd).unwrap_or(XskBindMode::Copy);
                if socket_role.requires_zerocopy() && !bind_mode.is_zerocopy() {
                    return Err(format!(
                        "{} bind(fd={}) did not report XDP_OPTIONS_ZEROCOPY after bind",
                        socket_role.describe(),
                        user_fd
                    )
                    .into());
                }
                set_busy_poll_opts(user_fd, poll_mode);
                eprintln!(
                    "xpf-userspace-dp: libxdp bind(fd={}) OK on attempt {} role={} mode={:?} flags=0x{:04x}",
                    user_fd,
                    attempt,
                    socket_role.describe(),
                    bind_mode,
                    bind_flags,
                );

                return Ok((user, rx, tx, bind_mode, bind_flags, device));
            }
            Err(err) => {
                let msg = err.to_string();
                if attempt + 1 < BIND_RETRY_ATTEMPTS && msg.contains("Device or resource busy") {
                    thread::sleep(BIND_RETRY_DELAY);
                    continue;
                }
                return Err(format!(
                    "libxdp {} bind(flags=0x{:04x}): {msg}",
                    socket_role.describe(),
                    bind_flags,
                )
                .into());
            }
        }
    }
    Err(format!(
        "libxdp bind: exhausted {} retries with flags=0x{:04x}",
        BIND_RETRY_ATTEMPTS, bind_flags,
    )
    .into())
}

fn query_bound_xsk_mode(fd: c_int) -> Option<XskBindMode> {
    let mut opt = XdpOptions { flags: 0 };
    let mut optlen = core::mem::size_of::<XdpOptions>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            SOL_XDP,
            XDP_OPTIONS,
            (&mut opt as *mut XdpOptions).cast::<c_void>(),
            &mut optlen,
        )
    };
    if rc != 0 || optlen as usize != core::mem::size_of::<XdpOptions>() {
        return None;
    }
    Some(if (opt.flags & XDP_OPTIONS_ZEROCOPY) != 0 {
        XskBindMode::ZeroCopy
    } else {
        XskBindMode::Copy
    })
}

fn set_busy_poll_opts(fd: c_int, poll_mode: crate::PollMode) {
    const SO_BUSY_POLL: c_int = 46;
    const SO_PREFER_BUSY_POLL: c_int = 69;
    const SO_BUSY_POLL_BUDGET: c_int = 70;
    // Use 1us timeout: just enough to trigger one napi_busy_loop() cycle
    // per poll() call, which posts fill ring WQEs. The 50us value caused
    // 15% CPU overhead from spin-waiting. 1us triggers NAPI and returns
    // immediately, bootstrapping the fill ring with negligible overhead.
    let busy_poll_us: c_int = if poll_mode == crate::PollMode::Interrupt {
        1
    } else {
        50
    };
    let prefer: c_int = 1;
    let budget: c_int = RX_BATCH_SIZE as c_int;

    unsafe {
        let _ = libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            SO_BUSY_POLL,
            (&busy_poll_us as *const c_int).cast::<c_void>(),
            core::mem::size_of::<c_int>() as libc::socklen_t,
        );
        let _ = libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            SO_PREFER_BUSY_POLL,
            (&prefer as *const c_int).cast::<c_void>(),
            core::mem::size_of::<c_int>() as libc::socklen_t,
        );
        let _ = libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            SO_BUSY_POLL_BUDGET,
            (&budget as *const c_int).cast::<c_void>(),
            core::mem::size_of::<c_int>() as libc::socklen_t,
        );
    }
}
