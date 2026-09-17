use super::*;
use crate::xsk_ffi::{self, DeviceQueue, IfInfo, RingRx, RingTx, SocketConfig};
use std::path::Path;

// #9924 AUTO row: request zero-copy and NEED_WAKEUP explicitly, then fall
// back to copy mode with NEED_WAKEUP if the driver cannot do zero-copy. A
// private socket has no owner pool to inherit these bits from. The explicit
// pair preserves the old row's zero-copy-then-copy negotiation while making
// both wake requests visible to the kernel.
const AUTO_BIND_FLAGS: [u16; 2] = [XSK_BIND_FLAGS_ZEROCOPY, XSK_BIND_FLAGS_COPY];
const COPY_ONLY_BIND_FLAGS: [u16; 1] = [XSK_BIND_FLAGS_COPY];
const EXPLICIT_MODE_BIND_FLAGS: [u16; 2] = [XSK_BIND_FLAGS_ZEROCOPY, XSK_BIND_FLAGS_COPY];
const SHARED_OWNER_BIND_FLAGS: [u16; 1] = [XSK_BIND_FLAGS_ZEROCOPY];
// #9924 secondary row: SHARED_UMEM-only is KERNEL-MANDATED, not an omission.
// `xsk_bind` rejects a shared socket carrying any of COPY/ZEROCOPY/NEED_WAKEUP
// with -EINVAL ("Cannot specify flags for shared sockets", `net/xdp/xsk.c`,
// verified v5.15/v6.12/v6.18/v7.0/master), so requesting NEED_WAKEUP here
// would break the bind. The secondary instead inherits both properties from
// the owner pool: same-queue secondaries share the pool object outright
// (`xs->pool = umem_xs->pool`, `xs->zc = xs->umem->zc`), and cross-queue
// secondaries go through `xp_assign_dev_shared`, which rebuilds
// `umem->zc ? ZEROCOPY : COPY` plus the owner's `uses_need_wakeup`
// (`net/xdp/xsk_buff_pool.c`). The owner row above is therefore the source of
// both inherited bits, and `try_open_bind` fails a secondary closed when
// zero-copy was not inherited. (The kernel spells the flag
// `XDP_USE_NEED_WAKEUP`, `linux/if_xdp.h`; the repo alias
// `XDP_BIND_NEED_WAKEUP` is the same 1<<3.)
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

// F-151 (#9904): post-bind identity re-verification.
//
// Bind resolves the planned ifindex to a name (`if_indextoname` in
// `IfInfo::from_ifindex`) and then creates the socket BY NAME
// (`xsk_socket__create*` takes `ifname`). A rename landing in that window
// binds another interface's queue, and the rename actor is the product
// itself (xpf renames interfaces at startup via `pkg/daemon/linksetup.go`
// positional renames + `.link` files) — a product-internal ordering
// question, not a hypothetical operator race.
//
// The guard re-resolves the BOUND name back to an ifindex after socket
// creation and fails on any planned-vs-observed mismatch. It is deliberately
// best-effort, with two documented residuals: (1) a rename landing between
// socket creation and this check false-positives on a HEALTHY socket (the
// kernel holds an ifindex reference; post-bind renames do not move it), so
// callers MUST fresh-resolve + retry on mismatch rather than failing the
// whole bind immediately — transients self-heal, persistent mismatches fail
// closed after the retry budget; (2) delete+recreate reusing both the name
// AND the ifindex is invisible to a name→ifindex check (no getsockname-style
// ground truth exists for AF_XDP). What this catches is the ordering window
// itself: binding under a name that already means a different ifindex.
pub(super) fn verify_bind_identity_with_resolver(
    planned_ifindex: u32,
    bound_ifname: &std::ffi::CStr,
    resolve: impl Fn(&std::ffi::CStr) -> Option<u32>,
) -> Result<(), String> {
    match resolve(bound_ifname) {
        Some(observed) if observed == planned_ifindex => Ok(()),
        Some(observed) => Err(format!(
            "planned ifindex {planned_ifindex} but bound name {:?} now resolves to ifindex {observed}",
            bound_ifname.to_string_lossy()
        )),
        None => Err(format!(
            "planned ifindex {planned_ifindex} but bound name {:?} no longer resolves",
            bound_ifname.to_string_lossy()
        )),
    }
}

pub(super) fn verify_bind_identity(
    planned_ifindex: u32,
    bound_ifname: &std::ffi::CStr,
) -> Result<(), String> {
    verify_bind_identity_with_resolver(planned_ifindex, bound_ifname, |name| {
        let idx = unsafe { libc::if_nametoindex(name.as_ptr()) };
        (idx != 0).then_some(idx)
    })
}

pub(super) fn preferred_bind_strategy(binding: &BindingStatus) -> AfXdpBindStrategy {
    bind_strategy_for_driver(interface_driver_name(&binding.interface).as_deref())
}

/// Open the AF_XDP socket/ring handles for one binding.
///
/// # Safety
/// The returned XSK handles must be stored/dropped before `worker_umem`, so
/// `xsk_socket__delete` runs while the UMEM state is still live and before
/// `xsk_umem__delete`. Private UMEM sockets borrow `worker_umem`'s
/// fill/completion ring structs directly. Shared UMEM sockets own
/// socket-local fill/completion rings but still depend on the live shared UMEM
/// pointer passed through `worker_umem`.
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
        // #2374: fill-ring suffix the bringup prime could not place — the
        // caller stashes this in `pending_fill_frames` so it is retried by
        // the steady-state drain rather than leaked.
        Vec<u64>,
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
                Ok((user, rx, tx, bind_mode, actual_flags, device, uninserted_fill)) => {
                    return Ok((
                        user,
                        rx,
                        tx,
                        bind_mode,
                        actual_flags,
                        strategy,
                        device,
                        uninserted_fill,
                    ));
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

/// Bringup fill-ring total-failure predicate (#2374).
///
/// A *total* failure (the very first reserve placed zero frames into a
/// non-empty fill request) is fatal: the socket would run with no RX
/// descriptors at all, so the bind must fail closed. An empty request
/// (`total == 0`) is not a failure. Extracted as a pure helper so the
/// fail-closed decision is unit-testable without a bound `DeviceQueue`.
pub(super) fn fill_prime_is_total_failure(total: usize, inserted_first: usize) -> bool {
    total > 0 && inserted_first == 0
}

/// Bringup fill-ring partial-insert suffix recovery (#2374).
///
/// Given the offsets handed to the bringup prime and the total number the fill
/// ring eventually accepted (after retries), return the un-inserted suffix the
/// caller MUST defer into the worker's `pending_fill_frames` queue. Returning
/// the suffix (rather than dropping it) is what prevents the UMEM frame leak:
/// the steady-state `tx::rings::drain_pending_fill` loop then retries exactly
/// these offsets. A full insert returns an empty `Vec`. Pure helper so the
/// recovery is unit-testable without a bound `DeviceQueue`.
pub(super) fn defer_uninserted_fill_suffix(offsets: &[u64], inserted_total: usize) -> Vec<u64> {
    let inserted_total = inserted_total.min(offsets.len());
    offsets[inserted_total..].to_vec()
}

/// Upper bound on bringup NAPI-trigger iterations in `prime_fill_ring_offsets`.
///
/// mlx5 zero-copy consumes the fill ring during RX NAPI poll, so we kick NAPI
/// (recvmsg/poll/sendto) to make the kernel post RX WQEs. A transiently-full
/// ring may need several kicks before it accepts the deferred suffix; this caps
/// the retries so a persistently-rejecting ring still falls through to the
/// deferred-suffix path instead of spinning.
pub(super) const FILL_PRIME_MAX_ITERS: usize = 20;

/// Drive the bringup fill-ring NAPI-trigger loop (#2481).
///
/// Runs `iter` (one NAPI kick + deferred-suffix retry, returning the
/// post-iteration `remaining` count) at most `FILL_PRIME_MAX_ITERS` times,
/// starting from `initial_remaining`. Stops as soon as the ring is fully primed
/// (`remaining == total`) — but only AFTER at least one iteration, so the NAPI
/// kick that posts the RX WQEs always fires even when the initial fill already
/// placed every frame. Returns the final `remaining`.
///
/// Before #2481 the loop ran the full `FILL_PRIME_MAX_ITERS` unconditionally:
/// a fully-successful prime still burned 19 wasted recvmsg/poll/sendto + 1ms
/// poll iterations (~20ms/queue × up to 16 queues ≈ ~320ms avoidable serial
/// bringup latency). The early-out cuts that tail while preserving the >=1 NAPI
/// trigger and the up-to-cap retry for a partial prime. Extracted as a pure
/// driver so the early-out is unit-testable without a bound `DeviceQueue`.
pub(super) fn drive_fill_prime_loop(
    initial_remaining: usize,
    total: usize,
    mut iter: impl FnMut(usize) -> usize,
) -> usize {
    let mut remaining = initial_remaining;
    for _ in 0..FILL_PRIME_MAX_ITERS {
        // Always run at least one iteration: the NAPI kick that posts the RX
        // WQEs must fire even if the initial fill already primed the ring.
        remaining = iter(remaining);
        // Early-out once fully primed (#2481) — the break is at the END of the
        // iteration so the post-work `remaining` is read; a partial prime
        // (remaining < total) keeps retrying up to the cap.
        if remaining == total {
            break;
        }
    }
    remaining
}

/// Prime the RX fill ring with `offsets` at socket bringup.
///
/// Returns the suffix of `offsets` that could NOT be inserted into the fill
/// ring (empty `Vec` when all `offsets.len()` frames were placed). The caller
/// MUST hand that suffix to the worker's `pending_fill_frames` queue so the
/// steady-state `drain_pending_fill` loop retries it — otherwise those UMEM
/// frame addresses are leaked from every local pool, permanently shrinking RX
/// capacity (#2374).
///
/// A *total* failure (`inserted == 0` on the very first reserve) is fatal and
/// returns `Err` so the bind fails closed rather than running with no RX
/// descriptors. A *partial* insert is recovered: this matches the steady-state
/// suffix recovery in `tx::rings::drain_pending_fill` (push the un-inserted
/// suffix back for retry) rather than silently dropping it.
pub(super) fn prime_fill_ring_offsets(
    device: &mut DeviceQueue,
    offsets: &[u64],
) -> Result<Vec<u64>, Box<dyn std::error::Error + Send + Sync>> {
    // An empty prime request is a no-op (not a total failure — see
    // `fill_prime_is_total_failure`). Return the empty deferred suffix without
    // entering the NAPI-trigger loop below (which always runs at least one
    // iteration), avoiding a wasted recvmsg/poll/sendto at bringup for no frames.
    if offsets.is_empty() {
        return Ok(Vec::new());
    }
    // `remaining` is the slice index of the first not-yet-inserted offset.
    // We retry the insert across the NAPI-trigger loop below: each NAPI kick
    // lets the kernel consume fill-ring entries and post RX WQEs, which frees
    // ring slots so a transiently-full ring can accept the suffix on a later
    // iteration without leaking frames.
    let total = offsets.len();
    let mut remaining: usize = {
        let mut fill = device.fill(total as u32);
        let inserted = fill.insert(offsets.iter().copied());
        fill.commit();
        inserted as usize
    };
    eprintln!(
        "prime_fill_ring: inserted={}/{} fill_pending={}",
        remaining,
        total,
        device.pending()
    );
    // A total failure on the first reserve means the ring rejected everything;
    // fail closed (no RX descriptors at all). Do NOT regress this behavior.
    if fill_prime_is_total_failure(total, remaining) {
        return Err(format!("prefill fill ring inserted 0/{}", total).into());
    }
    // Trigger NAPI to consume fill ring entries and post RX WQEs.
    // mlx5 zero-copy processes the fill ring during RX NAPI poll.
    // We trigger it by calling recvmsg() which enters the busy-poll
    // path (if SO_BUSY_POLL is set) and drives NAPI processing.
    // Also use poll(POLLIN) and sendto() as belt-and-suspenders.
    let fd = device.as_raw_fd();
    remaining = drive_fill_prime_loop(remaining, total, |remaining| {
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
        // After NAPI has had a chance to drain the ring, retry inserting the
        // un-inserted suffix. This recovers a transiently-full fill ring at
        // bringup the same way the steady-state drain does.
        let mut remaining = remaining;
        if remaining < total {
            let suffix = &offsets[remaining..];
            let inserted = {
                let mut fill = device.fill(suffix.len() as u32);
                let inserted = fill.insert(suffix.iter().copied());
                fill.commit();
                inserted as usize
            };
            remaining += inserted;
        }
        std::thread::yield_now();
        remaining
    });
    if remaining < total {
        eprintln!(
            "prime_fill_ring: partial prime — {} of {} frames not placed, deferring suffix to pending_fill_frames",
            total - remaining,
            total
        );
    }
    // Return the un-inserted suffix (frames the ring still has not accepted).
    // The worker constructor stashes these in `pending_fill_frames` so the
    // running loop's `drain_pending_fill` retries them — never leaked.
    Ok(defer_uninserted_fill_suffix(offsets, remaining))
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
// F-151 (#9904): mismatch teardown. Takes ownership of the just-created
// handles and returns the terminal bind error. Drops run device-first —
// socket delete while the rx/tx ring boxes are still alive — matching
// `WorkerXskRings` declaration order (`worker/xsk_rings.rs`: device, rx,
// tx), whose normal teardown likewise deletes the socket before freeing
// the rings libxdp was handed. Only `DeviceQueue` has a `Drop`
// (`xsk_socket__delete`); `User`/`RingRx`/`RingTx` hold a raw fd (closed
// by the delete, never by us) plus Box rings. Nothing is XSKMAP-registered
// yet — registration happens later in the caller — so the delete is the
// complete undo. Hermetically tested below (`new_for_test` fixtures make
// the delete a null-handle no-op while exercising the real drop path).
fn fail_identity_mismatched_bind(
    user: User,
    rx: RingRx,
    tx: RingTx,
    device: DeviceQueue,
    attempt: usize,
    mismatch: String,
) -> Box<dyn std::error::Error + Send + Sync> {
    eprintln!(
        "xpf-userspace-dp: bind identity mismatch after socket create \
         (attempt {attempt}): {mismatch} — failing bind closed",
    );
    drop(device);
    drop(tx);
    drop(rx);
    drop(user);
    format!("bind identity mismatch: {mismatch}").into()
}

fn try_open_bind(
    worker_umem: &mut WorkerUmem,
    info: &IfInfo,
    ring_entries: u32,
    bind_flags: u16,
    socket_role: XskSocketRole,
    poll_mode: crate::PollMode,
    pre_bind_fill_offsets: Option<&[u64]>,
) -> Result<
    (User, RingRx, RingTx, XskBindMode, u16, DeviceQueue, Vec<u64>),
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
                // F-151 (#9904): re-resolve the bound name BEFORE priming or
                // publishing anything, and fail the bind closed on any
                // mismatch. Deliberately NO in-bind retry: re-creating a
                // socket on a UMEM whose owner socket was just deleted would
                // reuse owner resources across the delete/re-create boundary,
                // whose post-delete state this tree cannot prove from its
                // linked libxdp. Recovery is the outer reconcile loop, which
                // rebuilds workers wholesale (fresh UMEM + fresh `IfInfo`
                // from `BindingStatus` on every `bring_up_workers`) — the
                // retry boundary that reconstructs owner resources. A
                // transient rename-storm mismatch therefore delays bringup
                // until the next driven reconcile instead of bricking it.
                let bound_ifname = info.ifname_cstring();
                if let Err(mismatch) = verify_bind_identity(info.ifindex(), &bound_ifname) {
                    return Err(fail_identity_mismatched_bind(
                        user, rx, tx, device, attempt, mismatch,
                    ));
                }
                let user_fd = user.as_raw_fd();

                // Prime the fill ring AFTER bind — libxdp already binds
                // the socket during create_shared. Post-bind fill ring
                // priming triggers NAPI to consume entries and post WQEs.
                // Any suffix the ring could not accept is returned so the
                // worker stashes it in `pending_fill_frames` (#2374) instead
                // of leaking the UMEM frames.
                let uninserted_fill = match pre_bind_fill_offsets {
                    Some(offsets) => prime_fill_ring_offsets(&mut device, offsets)?,
                    None => Vec::new(),
                };

                let bind_mode = query_bound_xsk_mode(user_fd).unwrap_or(XskBindMode::Copy);
                if socket_role.requires_zerocopy() && !bind_mode.is_zerocopy() {
                    return Err(format!(
                        "{} bind(fd={}) did not report XDP_OPTIONS_ZEROCOPY after bind",
                        socket_role.describe(),
                        user_fd
                    )
                    .into());
                }
                let busy_poll = set_busy_poll_opts(user_fd, poll_mode);
                eprintln!(
                    "xpf-userspace-dp: libxdp bind(fd={}) OK on attempt {} role={} mode={:?} flags=0x{:04x}",
                    user_fd,
                    attempt,
                    socket_role.describe(),
                    bind_mode,
                    bind_flags,
                );
                // #5190 (A1-b12-F2): a refused busy-poll option leaves the
                // worker on different NAPI/poll semantics than configured.
                // The bind is still usable, so this is a WARNING beside the
                // OK line rather than a bind failure — but it is no longer
                // silent.
                if busy_poll.degraded() {
                    eprintln!(
                        "xpf-userspace-dp: WARNING bind(fd={}) busy-poll DEGRADED — kernel refused: {} (poll_mode={:?}); the worker runs with the kernel's default NAPI/poll semantics",
                        user_fd,
                        busy_poll.describe(),
                        poll_mode,
                    );
                }

                return Ok((user, rx, tx, bind_mode, bind_flags, device, uninserted_fill));
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

/// #5190 (A1-b12-F2): outcome of the three busy-poll `setsockopt` calls.
/// `0` means the option was accepted by the kernel; any other value is the
/// `errno` the kernel returned. Every one of these can legitimately fail on
/// a production box — `SO_PREFER_BUSY_POLL` requires `CAP_NET_ADMIN`,
/// `SO_BUSY_POLL_BUDGET` requires it above the sysctl default, and all three
/// are absent on old kernels — so a failure is NOT fatal to the bind. It is,
/// however, a real change in the worker's NAPI/poll semantics, and before
/// #5190 all three returns were discarded with `let _ =` and the caller
/// logged an unqualified "bind OK".
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(super) struct BusyPollSetup {
    pub(super) busy_poll_errno: i32,
    pub(super) prefer_busy_poll_errno: i32,
    pub(super) budget_errno: i32,
}

impl BusyPollSetup {
    /// True when at least one option the worker asked for was refused, i.e.
    /// the socket is running with different poll semantics than configured.
    pub(super) fn degraded(&self) -> bool {
        self.busy_poll_errno != 0 || self.prefer_busy_poll_errno != 0 || self.budget_errno != 0
    }

    /// Operator-facing summary naming each refused option and its errno.
    /// Bind-time only — never called on the packet path.
    pub(super) fn describe(&self) -> String {
        let mut out = String::new();
        for (name, err) in [
            ("SO_BUSY_POLL", self.busy_poll_errno),
            ("SO_PREFER_BUSY_POLL", self.prefer_busy_poll_errno),
            ("SO_BUSY_POLL_BUDGET", self.budget_errno),
        ] {
            if err != 0 {
                if !out.is_empty() {
                    out.push(' ');
                }
                out.push_str(&format!("{name}=errno {err}"));
            }
        }
        out
    }
}

/// Apply the three busy-poll socket options, REPORTING which ones the kernel
/// refused (#5190). The bind itself still succeeds on refusal — busy poll is
/// an optimisation, not a correctness requirement — but the caller logs the
/// degradation instead of claiming an unqualified success.
fn set_busy_poll_opts(fd: c_int, poll_mode: crate::PollMode) -> BusyPollSetup {
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

    // `errno` is only meaningful immediately after a failing call, so each
    // return is classified before the next setsockopt runs.
    let apply = |opt: c_int, val: &c_int| -> i32 {
        let rc = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                opt,
                (val as *const c_int).cast::<c_void>(),
                core::mem::size_of::<c_int>() as libc::socklen_t,
            )
        };
        if rc == 0 {
            0
        } else {
            std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
        }
    };
    BusyPollSetup {
        busy_poll_errno: apply(SO_BUSY_POLL, &busy_poll_us),
        prefer_busy_poll_errno: apply(SO_PREFER_BUSY_POLL, &prefer),
        budget_errno: apply(SO_BUSY_POLL_BUDGET, &budget),
    }
}

/// #5190 (A1-b12-F2) fail-on-revert: the three busy-poll `setsockopt`
/// returns used to be discarded with `let _ =`, so a kernel refusal
/// (missing support, missing `CAP_NET_ADMIN`, sysctl budget cap) was
/// invisible and the caller still logged an unqualified "bind OK". These
/// tests drive the REAL `set_busy_poll_opts` against a closed descriptor
/// so every call is guaranteed to fail, and assert the failure is both
/// reported and named. Restoring `let _ =` (making the function return a
/// default/empty report) turns them RED.
#[cfg(test)]
mod busy_poll_report_tests {
    use super::{BusyPollSetup, set_busy_poll_opts};

    #[test]
    fn refused_busy_poll_opts_are_reported_not_swallowed() {
        // fd -1 is never a socket: every setsockopt returns EBADF (9).
        let report = set_busy_poll_opts(-1, crate::PollMode::Interrupt);
        assert!(
            report.degraded(),
            "a kernel refusal of the busy-poll options must be REPORTED, \
             not discarded — a silently-degraded socket runs with different \
             NAPI/poll semantics than the worker asked for (#5190)"
        );
        assert_eq!(
            report.busy_poll_errno,
            libc::EBADF,
            "SO_BUSY_POLL failure must carry the kernel errno"
        );
        assert_eq!(
            report.prefer_busy_poll_errno,
            libc::EBADF,
            "SO_PREFER_BUSY_POLL failure must carry the kernel errno"
        );
        assert_eq!(
            report.budget_errno,
            libc::EBADF,
            "SO_BUSY_POLL_BUDGET failure must carry the kernel errno"
        );
        let described = report.describe();
        for opt in [
            "SO_BUSY_POLL",
            "SO_PREFER_BUSY_POLL",
            "SO_BUSY_POLL_BUDGET",
        ] {
            assert!(
                described.contains(opt),
                "the operator warning must NAME each refused option; {opt} \
                 missing from {described:?}"
            );
        }
    }

    #[test]
    fn all_applied_busy_poll_setup_is_not_degraded() {
        // Control: the "everything accepted" report must not warn, so the
        // degraded() gate cannot fire on a healthy bind.
        let ok = BusyPollSetup::default();
        assert!(!ok.degraded());
        assert_eq!(ok.describe(), "");
    }
}

#[cfg(test)]
mod fill_prime_tests {
    use super::{
        defer_uninserted_fill_suffix, drive_fill_prime_loop, fill_prime_is_total_failure,
        FILL_PRIME_MAX_ITERS,
    };
    use std::cell::Cell;

    // #2374: a partial bringup prime (inserted < N) MUST recover the
    // un-inserted suffix so the worker can stash it in pending_fill_frames.
    // If the recovery is removed (e.g. revert to dropping the suffix), the
    // returned Vec would be empty and the (N - inserted) frames would leak —
    // this test asserts the suffix is the EXACT tail and FAILS on that revert.
    #[test]
    fn partial_prime_recovers_uninserted_suffix_not_leaked() {
        let offsets: Vec<u64> = vec![0, 4096, 8192, 12288, 16384];
        // Ring accepted only the first 3; the remaining 2 must be deferred.
        let inserted = 3;
        let suffix = defer_uninserted_fill_suffix(&offsets, inserted);
        assert_eq!(
            suffix,
            vec![12288, 16384],
            "partial bringup prime must defer the exact un-inserted suffix \
             (else the (N - inserted) UMEM frames leak — #2374)"
        );
        // No frame is lost: inserted-count + deferred-count == total.
        assert_eq!(
            inserted + suffix.len(),
            offsets.len(),
            "every bringup fill frame must be either inserted or deferred — none dropped"
        );
        // A partial insert is NOT a total failure (must not fail closed).
        assert!(
            !fill_prime_is_total_failure(offsets.len(), inserted),
            "a partial insert must be recovered, not treated as a fatal bind failure"
        );
    }

    // No regression: a full insert defers nothing and is not a failure.
    #[test]
    fn full_prime_defers_nothing() {
        let offsets: Vec<u64> = vec![0, 4096, 8192, 12288];
        let inserted = offsets.len();
        let suffix = defer_uninserted_fill_suffix(&offsets, inserted);
        assert!(
            suffix.is_empty(),
            "a full insert must defer nothing (no spurious pending_fill_frames)"
        );
        assert!(!fill_prime_is_total_failure(offsets.len(), inserted));
        // Defensive: an over-count (inserted reported > total) still defers
        // nothing and never panics (min() clamp).
        assert!(defer_uninserted_fill_suffix(&offsets, inserted + 10).is_empty());
    }

    // No regression: a total failure (inserted == 0 on a non-empty request)
    // must still be classified as fatal so the bind fails closed.
    #[test]
    fn zero_insert_is_total_failure() {
        let offsets: Vec<u64> = vec![0, 4096, 8192];
        assert!(
            fill_prime_is_total_failure(offsets.len(), 0),
            "inserted == 0 on a non-empty prime must remain a fatal bind failure (fail closed)"
        );
        // An empty prime request is a no-op, not a failure. The empty-offsets
        // early return in `prime_fill_ring_offsets` yields exactly this: no
        // total failure AND an empty deferred suffix (and skips the NAPI loop).
        assert!(
            !fill_prime_is_total_failure(0, 0),
            "an empty fill request must not be treated as a failure"
        );
        let empty: Vec<u64> = Vec::new();
        assert!(
            defer_uninserted_fill_suffix(&empty, 0).is_empty(),
            "an empty prime defers nothing"
        );
        // Even when total-failure errors out upstream, the suffix helper for a
        // zero insert would be the whole set (nothing accepted) — proving the
        // recovery path would otherwise carry all frames.
        assert_eq!(defer_uninserted_fill_suffix(&offsets, 0), offsets);
    }

    // #2481: when the initial fill already primed the whole ring
    // (initial_remaining == total), the NAPI-trigger loop must run EXACTLY ONE
    // iteration — one kick to post the RX WQEs, then break. If the early-out is
    // reverted (loop runs the full cap unconditionally), this asserts 1 != 20
    // and FAILS. This is the fail-on-revert guard for the avoidable ~320ms
    // bringup latency the early-out removes.
    #[test]
    fn already_primed_runs_exactly_one_iteration() {
        let total = 8;
        let calls = Cell::new(0usize);
        let final_remaining = drive_fill_prime_loop(total, total, |remaining| {
            calls.set(calls.get() + 1);
            // Ring is already full: nothing to retry, remaining stays at total.
            remaining
        });
        assert_eq!(
            calls.get(),
            1,
            "an already-primed ring must run exactly ONE NAPI-trigger iteration \
             (>=1 to post RX WQEs, then early-out) — not the full {} cap (#2481)",
            FILL_PRIME_MAX_ITERS
        );
        assert_eq!(final_remaining, total);
    }

    // #2481: a ring that completes after a few retries must break as soon as it
    // is fully primed — not run the remaining cap iterations. Mocks a ring that
    // accepts one more frame per kick until full.
    #[test]
    fn stops_as_soon_as_fully_primed() {
        let total = 5;
        let calls = Cell::new(0usize);
        // Start with 2 of 5 placed; each kick lets the kernel free one slot.
        let final_remaining = drive_fill_prime_loop(2, total, |remaining| {
            calls.set(calls.get() + 1);
            (remaining + 1).min(total)
        });
        // 2 -> 3 -> 4 -> 5: three iterations reach total, then break.
        assert_eq!(
            calls.get(),
            3,
            "the loop must stop the iteration it reaches full, not spin to the cap"
        );
        assert_eq!(final_remaining, total);
    }

    // #2481: a persistently-rejecting ring (remaining < total forever) must run
    // the full cap — the early-out must NOT short-circuit a partial prime, or
    // the ring would be left under-primed (RX drops). Also confirms the final
    // remaining is carried out so the caller defers the un-inserted suffix.
    #[test]
    fn partial_prime_runs_full_cap_and_never_underprimes() {
        let total = 6;
        let calls = Cell::new(0usize);
        // Ring never accepts more than the initial 4 — stuck below total.
        let final_remaining = drive_fill_prime_loop(4, total, |remaining| {
            calls.set(calls.get() + 1);
            remaining // no progress
        });
        assert_eq!(
            calls.get(),
            FILL_PRIME_MAX_ITERS,
            "a partial prime that never completes must retry up to the full cap \
             (no premature break that leaves the ring under-primed)"
        );
        assert_eq!(
            final_remaining, 4,
            "the final remaining must be returned so the caller defers the \
             un-inserted suffix to pending_fill_frames (no leak)"
        );
    }
}

// ---------------------------------------------------------------------------
// #7497 acceptance criterion 1: the UMEM memory figures are a CONTRACT.
// ---------------------------------------------------------------------------
//
// `etc/sysctl.d/99-xpf-hugepages.conf` reserves a hugepage pool, and
// `docs/userspace-dataplane-architecture.md` states a per-binding cost and a
// RAM sizing formula. Both are arithmetic over THIS function, and until now
// neither had a test — so a change to `MAX_RESERVED_TX_FRAMES` or to the
// reserved-TX policy would silently invalidate an operator's provisioning
// without failing anything.
//
// The numbers below were cross-checked against a live measurement, not derived
// from the doc: on `loss:xpf-userspace-fw1` (mlx5, `--ring-entries 16384`,
// 3 binding candidates x 6 queues = 18 bindings) `/proc/<pid>/smaps_rollup`
// reported `Private_Hugetlb: 2949120 kB` = 2880 MiB = 18 x 160 MiB.
#[cfg(test)]
mod umem_sizing_contract_tests {
    use super::{binding_frame_count_for_driver, reserved_tx_frames_for_driver};

    const FRAME: u64 = 4096;
    const MIB: u64 = 1024 * 1024;
    const HUGE: u64 = 2 * MIB;

    fn mib_per_binding(driver: Option<&str>, ring: u32) -> u64 {
        binding_frame_count_for_driver(driver, ring) as u64 * FRAME / MIB
    }

    /// At the maximum permitted `ring_entries` the reserved-TX CLAMP makes both
    /// drivers cost the SAME, and that is the non-obvious half.
    ///
    /// `reserved_tx_frames_for_driver` prefers `ring_entries` for virtio_net
    /// and `ring_entries / 2` otherwise, but then clamps to
    /// `MAX_RESERVED_TX_FRAMES` (8192). At ring = 16384 the virtio preference
    /// (16384) is clamped down to 8192 — the same value mlx5 arrives at from
    /// below — so both are `8192 + 2*16384 = 40960` frames.
    ///
    /// The architecture doc claimed virtio_net cost `3 x ring_entries` =
    /// 192 MB per binding at ring = 16384. That ignores the clamp and
    /// over-states the figure by 20%; it is corrected in the same change that
    /// added this test.
    #[test]
    fn per_binding_umem_at_max_ring_entries_is_160_mib_for_both_drivers_7497() {
        for driver in [Some("mlx5_core"), Some("virtio_net"), None] {
            assert_eq!(
                reserved_tx_frames_for_driver(driver, 16384),
                8192,
                "reserved TX at ring=16384 must be the MAX_RESERVED_TX_FRAMES \
                 clamp for driver {driver:?}; if this moves, the hugepage \
                 reservation in etc/sysctl.d/99-xpf-hugepages.conf is wrong"
            );
            assert_eq!(
                binding_frame_count_for_driver(driver, 16384),
                40960,
                "driver {driver:?} at ring=16384 must cost 40960 frames"
            );
            assert_eq!(
                mib_per_binding(driver, 16384),
                160,
                "driver {driver:?} at ring=16384 must cost 160 MiB per binding \
                 — the figure both the architecture doc and the hugepage \
                 sysctl are computed from"
            );
        }
    }

    /// Below the clamp the two drivers genuinely DIFFER, so the equality above
    /// is a property of ring=16384 and not of the function. Without this cell a
    /// mutation collapsing the virtio branch into the default would leave the
    /// test above green.
    #[test]
    fn reserved_tx_still_differs_by_driver_below_the_clamp_7497() {
        assert_eq!(reserved_tx_frames_for_driver(Some("virtio_net"), 8192), 8192);
        assert_eq!(reserved_tx_frames_for_driver(Some("mlx5_core"), 8192), 4096);
        assert_eq!(mib_per_binding(Some("virtio_net"), 8192), 96);
        assert_eq!(mib_per_binding(Some("mlx5_core"), 8192), 80);
    }

    /// The quantity `etc/sysctl.d/99-xpf-hugepages.conf` must be sized in.
    ///
    /// The shipped reservation was 600 pages, derived from "one NIC's UMEM"
    /// (6 bindings). Since #7497 the planner mints `Σ min(rx_i, 16)` across
    /// ALL binding candidates — the fabric IPVLAN parent included — so the
    /// pool has to cover the SUM, not one interface's share. The measured
    /// loss-cluster topology is 3 candidates x 6 queues.
    #[test]
    fn hugepages_needed_tracks_total_bindings_not_one_nic_7497() {
        let per_binding_pages = binding_frame_count_for_driver(Some("mlx5_core"), 16384) as u64
            * FRAME
            / HUGE;
        assert_eq!(per_binding_pages, 80, "160 MiB / 2 MiB");

        let one_nic = 6 * per_binding_pages;
        assert_eq!(one_nic, 480, "the old 'one NIC' basis for nr_hugepages=600");

        // 3 binding candidates x 6 queues, measured on loss:xpf-userspace-fw1.
        let measured_cluster = 18 * per_binding_pages;
        assert_eq!(measured_cluster, 1440);
        assert!(
            measured_cluster > 600,
            "the shipped nr_hugepages=600 does NOT cover the measured 18-binding \
             topology ({measured_cluster} pages needed); the reservation must be \
             sized from the total binding count"
        );
    }
}

#[cfg(test)]
mod bind_flags_9043_tests {
    use super::*;

    /// #9043: a generic-XDP interface binds COPY-ONLY, so `XDP_PASS` there
    /// cannot consume a UMEM frame at all.
    ///
    /// This is the in-repo fact that settles one of the two mutually
    /// inconsistent README claims: `userspace-dp/README.md` said "Generic-XDP
    /// fallback consumes UMEM frames permanently on mlx5", and the umem README
    /// says copy mode "operates on kernel DMA buffers, not UMEM frames". Both
    /// cannot be right, and the bind decision is what makes the second one the
    /// true one.
    ///
    /// Pinned as a cell because the correction is now DOCUMENTATION, and a
    /// documented fact with nothing asserting it is how the wrong version got
    /// written in the first place. If this bind ever stops being copy-only, the
    /// corrected README sentence becomes false and this fails.
    #[test]
    fn generic_xdp_binds_copy_only_9043() {
        assert_eq!(
            COPY_ONLY_BIND_FLAGS,
            [XSK_BIND_FLAGS_COPY],
            "the copy-only bind must actually request copy mode; the README \
             correction in #9043 rests on this"
        );
        // And AUTO must NOT be copy-only, or the distinction the branch draws
        // is vacuous and the assertion above says nothing.
        assert_ne!(
            AUTO_BIND_FLAGS.first(),
            Some(&XSK_BIND_FLAGS_COPY),
            "AUTO and COPY_ONLY must differ, or the generic-XDP branch is not \
             choosing anything"
        );
    }
}

#[cfg(test)]
mod bind_identity_9904_tests {
    use super::*;
    use std::ffi::CString;

    // F-151 (#9904): the post-bind identity check with an injected resolver
    // (no real interfaces needed). Match → Ok; mismatch → Err carrying
    // planned-vs-observed; unresolvable → Err (fail closed: an interface
    // that vanished mid-bind cannot be proven to be the planned one).
    // The wiring (called in `try_open_bind` before the fill prime, with
    // fresh-resolve retry) is review-pinned: driving it needs a real AF_XDP
    // bind, and the source tripwire
    // `tests/bind_identity_verification_9904.rs` pins the call site.
    #[test]
    fn verify_bind_identity_matches_and_mismatches_9904() {
        let name = CString::new("eth0").expect("fixture name");
        assert!(verify_bind_identity_with_resolver(11, &name, |_| Some(11)).is_ok());
        let err = verify_bind_identity_with_resolver(11, &name, |_| Some(12))
            .expect_err("ifindex 12 for planned 11 must fail");
        assert!(
            err.contains("11") && err.contains("12"),
            "mismatch must log planned-vs-observed, got: {err}"
        );
        let gone = verify_bind_identity_with_resolver(11, &name, |_| None)
            .expect_err("unresolvable bound name must fail closed");
        assert!(
            gone.contains("11"),
            "unresolvable error must name the planned ifindex, got: {gone}"
        );
    }
}

#[cfg(test)]
mod bind_mismatch_teardown_9904_tests {
    use super::*;

    // F-151 (#9904): behavioral result-handling pin for the mismatch arm.
    // The `new_for_test` device carries a null xsk handle, so the socket
    // delete inside is a no-op while the real ordered-drop path (device,
    // tx, rx, user) and the terminal error still execute. What this cannot
    // cover — driving `try_open_bind` itself to the mismatch — needs a real
    // AF_XDP bind; that invocation ordering (after create, before prime) is
    // pinned by the `tests/bind_identity_verification_9904.rs` tripwire.
    #[test]
    fn mismatched_bind_teardown_fails_closed_with_planned_vs_observed_9904() {
        let err = fail_identity_mismatched_bind(
            User::new_for_test(-1),
            RingRx::new_for_test(-1, 8),
            RingTx::new_for_test(-1, 8),
            DeviceQueue::new_for_test(-1, 8),
            3,
            "planned ifindex 11 but bound name \"eth0\" now resolves to ifindex 12".to_string(),
        );
        let msg = err.to_string();
        assert!(
            msg.contains("bind identity mismatch")
                && msg.contains("11")
                && msg.contains("12"),
            "mismatch teardown must fail closed with planned-vs-observed, got: {msg}"
        );
    }
}
