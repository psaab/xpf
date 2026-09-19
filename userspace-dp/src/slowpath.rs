use crate::io_uring_write::WriteResult;
use crate::slowpath_reinject_9506::{
    classify_leased_write, AdmissionClass, AdmitDecision, ReinjectCore, ReinjectLease,
    ReinjectStatusSnapshot, SubmitFrame, TransferVerdict, ADMIT_BAD_LEASE, SUBMIT_FLAG_DRY_RUN,
};
use std::ffi::CString;
use std::fs::OpenOptions;
use std::io;
use std::os::unix::fs::OpenOptionsExt;
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, AtomicU8, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

// Firewall-local traffic is reinjected through the slow path. Keep the queue
// bounded, but do not rate-limit it so aggressively that normal TCP ACK
// traffic collapses sender throughput.
/// #7820: how long `SlowPathReinjector::new` waits for the worker to report
/// live-or-failed before giving up and returning optimistically. `open_tun`
/// resolves in microseconds; this bound exists so a pathological stall cannot
/// wedge dataplane startup.
const INIT_HANDSHAKE_TIMEOUT: Duration = Duration::from_millis(500);
/// Poll granularity for that handshake.
const INIT_HANDSHAKE_POLL: Duration = Duration::from_millis(1);
const DEFAULT_QUEUE_DEPTH: usize = 16_384;
const DEFAULT_RATE_LIMIT_PACKETS_PER_SEC: u64 = 1_000_000;
const DEFAULT_RATE_LIMIT_BYTES_PER_SEC: u64 = 4 * 1024 * 1024 * 1024;
const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
const IFF_TUN: libc::c_short = 0x0001;
const IFF_MULTI_QUEUE: libc::c_short = 0x0100;
const IFF_NO_PI: libc::c_short = 0x1000;

/// Queue zero is opened by the sole adjudicated xpf-usp1 writer. Linux stores
/// an RX queue in skb->queue_mapping as queue_index + 1, so the TC program
/// matches mapping one; every other mapping is explicitly cleared to zero.
const ADJUDICATED_QUEUE_INDEX: u32 = 0;
const ADJUDICATED_QUEUE_MAPPING: u32 = ADJUDICATED_QUEUE_INDEX + 1;
const ADJUDICATED_TRANSIT_MARK: u32 = 0x5846_5001;
const ADJUDICATED_TRANSIT_MARK_MASK: u32 = 0xffff_ffff;
const ADJUDICATED_TC_PRIORITY: u32 = 0x7fff;

/// The MTU the kernel assigns a freshly created TUN device. When the
/// desired-MTU programming ioctl fails, this is the MTU the live TUN still
/// has, so it is the largest L3 frame the slow path can actually inject
/// (#2471). Reinjected frames above it are silently dropped by the kernel on
/// TUN egress, so the reinjector must refuse them with a counter and the
/// status must report the degraded state rather than a plain `active`.
const DEFAULT_TUN_MTU: i32 = 1500;
/// #10069: cap delegated MTU recovery to three attempts per eight reconcile
/// ticks. The retry state is logical-tick based so tests can pin the exact
/// ioctl bound without sleeping, while production reconciles naturally advance
/// the same bounded window.
const MTU_RETRY_MAX_ATTEMPTS_PER_WINDOW: u8 = 3;
const MTU_RETRY_WINDOW_TICKS: u32 = 8;

#[derive(Default)]
struct MtuRetryState {
    desired_mtu: i32,
    tick: u32,
    /// Ticks at which the last bounded attempts were issued, oldest first.
    /// Keeping the fixed-size ring inline avoids allocations on reconcile.
    attempt_ticks: [u32; MTU_RETRY_MAX_ATTEMPTS_PER_WINDOW as usize],
    attempts: u8,
    next_retry_tick: u32,
    was_degraded: bool,
}


#[derive(Clone, Debug, Default)]
pub struct SlowPathStatus {
    pub active: bool,
    /// #2471: the slow-path worker is running (`active`) but the desired-MTU
    /// programming ioctl failed, so the live TUN MTU is below the configured
    /// data-interface MTU. Jumbo reinjection is refused (see `live_mtu`);
    /// status must surface this so an operator is not misled by a bare
    /// `active = true` while jumbo frames silently drop.
    pub degraded: bool,
    /// #2471: the MTU the live TUN device is actually programmed with. On a
    /// successful program this equals the desired MTU; on a failed program it
    /// falls back to the kernel-default `DEFAULT_TUN_MTU` (1500). Frames whose
    /// total length exceeds this are refused at enqueue.
    pub live_mtu: i32,
    pub device_name: String,
    pub mode: String,
    pub last_error: String,
    pub queued_packets: u64,
    pub injected_packets: u64,
    pub injected_bytes: u64,
    pub dropped_packets: u64,
    pub dropped_bytes: u64,
    pub rate_limited_packets: u64,
    pub queue_full_packets: u64,
    pub write_errors: u64,
    /// #2471: frames refused at enqueue because their length exceeds the live
    /// TUN MTU (counted into `dropped_packets`/`dropped_bytes` as well). A
    /// non-zero value while `degraded` is the operator-visible proof that
    /// jumbo reinjection is being dropped by the firewall, not the kernel.
    pub mtu_dropped_packets: u64,
}

pub enum EnqueueOutcome {
    Accepted,
    RateLimited,
    QueueFull,
    /// #2471: the frame's length exceeds the live TUN MTU (the slow path is
    /// degraded — MTU programming failed and the TUN is at the 1500 default).
    /// Refused at enqueue with a counter instead of being silently dropped by
    /// the kernel on TUN egress.
    MtuExceeded,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PacketQueue {
    /// The xpf-usp0 single queue; no skb mark is needed there.
    Trusted,
    /// Queue zero of the xpf-usp1 multi-queue TUN; TC marks this packet.
    Adjudicated,
    /// Queue one of the xpf-usp1 multi-queue TUN; TC clears its mark.
    Delegated,
}

struct PacketRequest {
    bytes: Vec<u8>,
    queue: PacketQueue,
    /// Some only for the adjudicated 9506 path. Trusted/delegated and the
    /// legacy adjudicated caller intentionally retain lease=None semantics.
    lease: Option<ReinjectLease>,
    flow_tag: u64,
}
fn admission_class(queue: PacketQueue) -> Option<AdmissionClass> {
    match queue {
        PacketQueue::Adjudicated => Some(AdmissionClass::Adjudicated),
        PacketQueue::Delegated => Some(AdmissionClass::Delegated),
        PacketQueue::Trusted => None,
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SlowPathWorkerOutlet {
    Trusted,
    Delegated,
}
struct QueueMarkClassifier {
    hook: libbpf_sys::bpf_tc_hook,
    handle: u32,
    priority: u32,
    owns_clsact: bool,
}

impl Drop for QueueMarkClassifier {
    fn drop(&mut self) {
        let mut opts = libbpf_sys::bpf_tc_opts {
            sz: std::mem::size_of::<libbpf_sys::bpf_tc_opts>() as u64,
            handle: self.handle,
            priority: self.priority,
            ..Default::default()
        };
        // The TUN disappears with its last fd during normal teardown. A
        // detach failure in that case is harmless; do not mask the worker's
        // terminal status with a best-effort cleanup error.
        unsafe {
            let _ = libbpf_sys::bpf_tc_detach(&self.hook, &opts);
            if self.owns_clsact {
                let _ = libbpf_sys::bpf_tc_hook_destroy(&mut self.hook);
            }
        }
    }
}

fn bpf_insn(code: u32, dst: u8, src: u8, off: i16, imm: i32) -> libbpf_sys::bpf_insn {
    let mut insn = libbpf_sys::bpf_insn {
        code: code as u8,
        off,
        imm,
        ..Default::default()
    };
    insn.set_dst_reg(dst);
    insn.set_src_reg(src);
    insn
}

fn load_queue_mark_program(queue_mapping: u32, mark: u32) -> Result<i32, String> {
    // tc ingress __sk_buff offsets are stable UAPI fields:
    // mark=8 and queue_mapping=12. Clear mark for every queue first, then
    // set the adjudicated value only for queue zero. Unknown queues therefore
    // remain explicitly unmarked and hit the fence's DROP policy.
    let insns = [
        bpf_insn(
            libbpf_sys::BPF_LDX | libbpf_sys::BPF_W | libbpf_sys::BPF_MEM,
            2,
            1,
            12,
            0,
        ),
        bpf_insn(
            libbpf_sys::BPF_ALU64 | libbpf_sys::BPF_MOV | libbpf_sys::BPF_K,
            0,
            0,
            0,
            0,
        ),
        bpf_insn(
            libbpf_sys::BPF_STX | libbpf_sys::BPF_W | libbpf_sys::BPF_MEM,
            1,
            0,
            8,
            0,
        ),
        bpf_insn(
            libbpf_sys::BPF_JMP | libbpf_sys::BPF_JEQ | libbpf_sys::BPF_K,
            2,
            0,
            1,
            queue_mapping as i32,
        ),
        bpf_insn(libbpf_sys::BPF_JMP | libbpf_sys::BPF_JA, 0, 0, 3, 0),
        bpf_insn(
            libbpf_sys::BPF_ALU64 | libbpf_sys::BPF_MOV | libbpf_sys::BPF_K,
            0,
            0,
            0,
            mark as i32,
        ),
        bpf_insn(
            libbpf_sys::BPF_STX | libbpf_sys::BPF_W | libbpf_sys::BPF_MEM,
            1,
            0,
            8,
            0,
        ),
        bpf_insn(
            libbpf_sys::BPF_ALU64 | libbpf_sys::BPF_MOV | libbpf_sys::BPF_K,
            0,
            0,
            0,
            0,
        ),
        bpf_insn(
            libbpf_sys::BPF_JMP | libbpf_sys::BPF_EXIT,
            0,
            0,
            0,
            0,
        ),
    ];
    let name = b"xpf_usp1_queue_mark\0";
    let license = b"GPL\0";
    let mut opts = libbpf_sys::bpf_prog_load_opts {
        sz: std::mem::size_of::<libbpf_sys::bpf_prog_load_opts>() as u64,
        ..Default::default()
    };
    let fd = unsafe {
        libbpf_sys::bpf_prog_load(
            libbpf_sys::BPF_PROG_TYPE_SCHED_CLS,
            name.as_ptr().cast(),
            license.as_ptr().cast(),
            insns.as_ptr(),
            insns.len() as u64,
            &mut opts,
        )
    };
    if fd < 0 {
        return Err(format!(
            "load xpf-usp1 queue-mark classifier: {}",
            io::Error::from_raw_os_error(-fd)
        ));
    }
    Ok(fd)
}

fn install_queue_mark_classifier(ifname: &str) -> Result<QueueMarkClassifier, String> {
    let c_name = CString::new(ifname).map_err(|_| format!("invalid TUN name {ifname:?}"))?;
    let ifindex = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
    if ifindex == 0 {
        return Err(format!(
            "resolve xpf-usp1 ifindex for queue-mark classifier: {}",
            io::Error::last_os_error()
        ));
    }
    let prog_fd = load_queue_mark_program(
        ADJUDICATED_QUEUE_MAPPING,
        ADJUDICATED_TRANSIT_MARK,
    )?;
    let mut hook = libbpf_sys::bpf_tc_hook {
        sz: std::mem::size_of::<libbpf_sys::bpf_tc_hook>() as u64,
        ifindex: ifindex as i32,
        attach_point: libbpf_sys::BPF_TC_INGRESS,
        ..Default::default()
    };
    let create_rc = unsafe { libbpf_sys::bpf_tc_hook_create(&mut hook) };
    let owns_clsact = match create_rc {
        0 => true,
        rc if rc == -libc::EEXIST => false,
        rc => {
            unsafe {
                libc::close(prog_fd);
            }
            return Err(format!(
                "create xpf-usp1 queue-mark clsact: {}",
                io::Error::from_raw_os_error(-rc)
            ));
        }
    };
    let priority = ADJUDICATED_TC_PRIORITY;
    let mut opts = libbpf_sys::bpf_tc_opts {
        sz: std::mem::size_of::<libbpf_sys::bpf_tc_opts>() as u64,
        prog_fd,
        priority,
        ..Default::default()
    };
    let attach_rc = unsafe { libbpf_sys::bpf_tc_attach(&hook, &mut opts) };
    unsafe {
        libc::close(prog_fd);
    }
    if attach_rc < 0 {
        if owns_clsact {
            unsafe {
                let _ = libbpf_sys::bpf_tc_hook_destroy(&mut hook);
            }
        }
        return Err(format!(
            "attach xpf-usp1 queue-mark classifier: {}",
            io::Error::from_raw_os_error(-attach_rc)
        ));
    }
    Ok(QueueMarkClassifier {
        hook,
        handle: opts.handle,
        priority,
        owns_clsact,
    })
}

/// Dual token-bucket rate limiter for the slow-path control queue (#2912).
///
/// The previous fixed-window limiter zeroed its counters whenever 1s of wall
/// time had elapsed since the window opened. A fixed window admits the full
/// per-second budget at the very end of window N AND the full budget at the
/// start of window N+1 — up to **2x** the configured rate in an arbitrarily
/// short interval straddling the boundary, which can overload downstream
/// control processing.
///
/// A token bucket smooths the admitted rate across boundaries: tokens
/// accumulate continuously at `rate` per second (one packet-token and one
/// byte-token bucket) and are spent on admission. The bucket caps at `rate`
/// (1s of accumulation) so the maximum burst in ANY interval is bounded by the
/// configured per-second rate, not 2x. Fractional accrual is preserved by
/// tracking the token balance as `f64` and folding the proportional refill into
/// it on every admission, so a steady stream at exactly the rate is never
/// under-admitted by repeated truncation.
struct RateLimiter {
    /// Wall-clock instant the token balances were last refreshed. Each refill
    /// reads `now - last_refill`, accrues `elapsed * rate` tokens into the f64
    /// balances (capped at capacity), and advances `last_refill` to `now`.
    last_refill: Instant,
    /// Currently available packet tokens (capacity == `max_packets_per_sec`).
    packet_tokens: f64,
    /// Currently available byte tokens (capacity == `max_bytes_per_sec`).
    byte_tokens: f64,
    max_packets_per_sec: u64,
    max_bytes_per_sec: u64,
}

impl RateLimiter {
    fn new(max_packets_per_sec: u64, max_bytes_per_sec: u64) -> Self {
        Self {
            last_refill: Instant::now(),
            // Start full so a freshly created limiter does not penalize the
            // first burst (matches the prior fixed-window behaviour, which
            // admitted a full budget in the first window).
            packet_tokens: max_packets_per_sec as f64,
            byte_tokens: max_bytes_per_sec as f64,
            max_packets_per_sec,
            max_bytes_per_sec,
        }
    }

    /// Admit (or refuse) one `packet_len`-byte frame, using the real clock.
    /// Production entry point; thin wrapper over the clock-injectable
    /// [`Self::allow_at`].
    fn allow(&mut self, packet_len: usize) -> bool {
        self.allow_at(Instant::now(), packet_len)
    }

    /// Clock-injectable core of [`Self::allow`]. `now` is the current instant
    /// (the real clock in production; a controlled instant in tests so the
    /// boundary behaviour is deterministic without sleeping). Accrues tokens for
    /// the time since the last refill, then spends one packet token and
    /// `packet_len` byte tokens iff BOTH buckets can pay — a refused frame
    /// charges neither bucket.
    fn allow_at(&mut self, now: Instant, packet_len: usize) -> bool {
        let elapsed = now.saturating_duration_since(self.last_refill).as_secs_f64();
        self.last_refill = now;

        // A zero rate admits nothing and never accrues tokens.
        if self.max_packets_per_sec > 0 {
            let cap = self.max_packets_per_sec as f64;
            self.packet_tokens = (self.packet_tokens + elapsed * cap).min(cap);
        } else {
            self.packet_tokens = 0.0;
        }
        if self.max_bytes_per_sec > 0 {
            let cap = self.max_bytes_per_sec as f64;
            self.byte_tokens = (self.byte_tokens + elapsed * cap).min(cap);
        } else {
            self.byte_tokens = 0.0;
        }

        let need_bytes = packet_len as f64;
        // Both buckets must have a token available; do not spend either unless
        // both can be paid (avoid charging one bucket for a refused packet).
        if self.packet_tokens < 1.0 || self.byte_tokens < need_bytes {
            return false;
        }
        self.packet_tokens -= 1.0;
        self.byte_tokens -= need_bytes;
        true
    }
    fn would_allow(&self, packet_len: usize) -> bool {
        let elapsed = Instant::now()
            .saturating_duration_since(self.last_refill)
            .as_secs_f64();
        let packet_cap = self.max_packets_per_sec as f64;
        let byte_cap = self.max_bytes_per_sec as f64;
        let packets = if self.max_packets_per_sec == 0 {
            0.0
        } else {
            (self.packet_tokens + elapsed * packet_cap).min(packet_cap)
        };
        let bytes = if self.max_bytes_per_sec == 0 {
            0.0
        } else {
            (self.byte_tokens + elapsed * byte_cap).min(byte_cap)
        };
        packets >= 1.0 && bytes >= packet_len as f64
    }
}

enum WriteMode {
    IoUring(crate::io_uring_write::RingWriter),
    SyncFallback,
}

struct SharedStatus {
    active: AtomicBool,
    /// #9637 GPT-1: single-atomic worker initialization outcome, published
    /// by the worker thread and read by the constructor handshake. The old
    /// handshake sampled `active` and the `last_error` diagnostic in two
    /// loads: a worker that had published `active` but not yet its
    /// io_uring-fallback note (or an MTU-degradation error before `active`)
    /// could be misread as failed-while-healthy. One load decides; the
    /// diagnostic slot is consulted ONLY after Failed is observed (the
    /// worker records the cause BEFORE publishing Failed, so it is present).
    /// 0 = starting, 1 = live, 2 = failed.
    init_state: AtomicU8,
    /// #2471: set when the worker is active but the live TUN MTU is below the
    /// configured/desired MTU (set_if_mtu failed). See `SlowPathStatus`.
    degraded: AtomicBool,
    /// #2471: the live TUN MTU. `AtomicI64` so the reinjector enqueue path can
    /// read it lock-free on the hot path. Defaults to `DEFAULT_TUN_MTU` until
    /// the worker programs (or fails to program) the device.
    live_mtu: AtomicI64,
    queued_packets: AtomicU64,
    injected_packets: AtomicU64,
    injected_bytes: AtomicU64,
    dropped_packets: AtomicU64,
    dropped_bytes: AtomicU64,
    rate_limited_packets: AtomicU64,
    queue_full_packets: AtomicU64,
    write_errors: AtomicU64,
    mtu_dropped_packets: AtomicU64,
    mode: Mutex<String>,
    device_name: Mutex<String>,
    last_error: Mutex<String>,
}

/// #9637 GPT-1: worker initialization outcome as a single atomic value.
/// Values match the `init_state` encoding (0 = starting, 1 = live,
/// 2 = failed).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OutletInit {
    Starting,
    Live,
    Failed,
}

impl SharedStatus {
    /// The worker's published initialization outcome: ONE atomic load, so
    /// the constructor handshake can never combine a stale `active` with
    /// a fresh diagnostic (or vice versa).
    fn init_outcome(&self) -> OutletInit {
        match self.init_state.load(Ordering::Relaxed) {
            1 => OutletInit::Live,
            2 => OutletInit::Failed,
            _ => OutletInit::Starting,
        }
    }
    fn new() -> Self {
        Self {
            active: AtomicBool::new(false),
            init_state: AtomicU8::new(OutletInit::Starting as u8),
            degraded: AtomicBool::new(false),
            live_mtu: AtomicI64::new(DEFAULT_TUN_MTU as i64),
            queued_packets: AtomicU64::new(0),
            injected_packets: AtomicU64::new(0),
            injected_bytes: AtomicU64::new(0),
            dropped_packets: AtomicU64::new(0),
            dropped_bytes: AtomicU64::new(0),
            rate_limited_packets: AtomicU64::new(0),
            queue_full_packets: AtomicU64::new(0),
            write_errors: AtomicU64::new(0),
            mtu_dropped_packets: AtomicU64::new(0),
            mode: Mutex::new(String::from("sync")),
            device_name: Mutex::new(String::new()),
            last_error: Mutex::new(String::new()),
        }
    }

    /// #7820: the worker's recorded failure cause, or `None` if it has not
    /// recorded one. Distinguishes "no error yet" from an error, which the
    /// startup handshake needs and a bare `String` getter cannot express —
    /// the empty string is the initial value, not a failure.
    fn last_error_if_set(&self) -> Option<String> {
        let err = self.last_error.lock().unwrap_or_else(|e| e.into_inner());
        if err.is_empty() {
            None
        } else {
            Some(err.clone())
        }
    }

    /// #2471: apply the desired MTU to the live TUN and record the resulting
    /// status. On success the live MTU is the desired MTU and the path is not
    /// degraded. On failure the live MTU falls back to the kernel-default TUN
    /// MTU (1500), `degraded` is set, and the error is recorded — the path
    /// stays usable for <=1500 frames but jumbo reinjection is refused.
    ///
    /// `programmer` is the MTU-programming seam (`set_if_mtu` in production, a
    /// failure-injecting closure in tests). Returns the live MTU now in
    /// effect.
    fn apply_mtu_status(
        &self,
        name: &str,
        desired_mtu: i32,
        programmer: impl FnOnce(&str, i32) -> Result<(), String>,
    ) -> i32 {
        match programmer(name, desired_mtu) {
            Ok(()) => {
                self.live_mtu.store(desired_mtu as i64, Ordering::Relaxed);
                self.degraded.store(false, Ordering::Relaxed);
                desired_mtu
            }
            Err(err) => {
                eprintln!(
                    "xpf-slowpath: set MTU {desired_mtu} on {name}: {err} \
                     (slow-path DEGRADED: jumbo frames > {DEFAULT_TUN_MTU} will be refused)"
                );
                self.set_last_error(err);
                self.live_mtu.store(DEFAULT_TUN_MTU as i64, Ordering::Relaxed);
                self.degraded.store(true, Ordering::Relaxed);
                DEFAULT_TUN_MTU
            }
        }
    }

    /// Reprogram the live TUN MTU on a day-2 reconcile (#5801) and update
    /// status, returning the live MTU now in effect.
    ///
    /// This is the day-2 sibling of [`Self::apply_mtu_status`]. The creation
    /// path falls a FAILED program back to the kernel-default 1500 because the
    /// TUN was just created at 1500. On a reconcile the running TUN already
    /// carries whatever MTU it was last programmed with, so a failed
    /// `SIOCSIFMTU` must KEEP the existing `live_mtu` (resetting it to 1500
    /// would wrongly refuse frames the device can still carry). On success
    /// `live_mtu` advances to `desired_mtu` and `degraded` clears; on failure
    /// `live_mtu` is unchanged, `degraded` is set, and the error is recorded.
    fn reprogram_mtu_status(
        &self,
        name: &str,
        desired_mtu: i32,
        programmer: impl FnOnce(&str, i32) -> Result<(), String>,
    ) -> i32 {
        match programmer(name, desired_mtu) {
            Ok(()) => {
                self.live_mtu.store(desired_mtu as i64, Ordering::Relaxed);
                self.degraded.store(false, Ordering::Relaxed);
                desired_mtu
            }
            Err(err) => {
                let live = self.live_mtu.load(Ordering::Relaxed) as i32;
                eprintln!(
                    "xpf-slowpath: reconcile MTU {desired_mtu} on {name}: {err} \
                     (slow-path DEGRADED: live TUN stays at {live}; frames > {live} refused)"
                );
                self.set_last_error(err);
                self.degraded.store(true, Ordering::Relaxed);
                live
            }
        }
    }

    fn set_mode(&self, mode: &str) {
        if let Ok(mut value) = self.mode.lock() {
            *value = mode.to_string();
        }
    }

    fn set_device_name(&self, name: &str) {
        if let Ok(mut value) = self.device_name.lock() {
            *value = name.to_string();
        }
    }

    fn set_last_error(&self, err: String) {
        if let Ok(mut value) = self.last_error.lock() {
            *value = err;
        }
    }

    fn snapshot(&self) -> SlowPathStatus {
        SlowPathStatus {
            active: self.active.load(Ordering::Relaxed),
            degraded: self.degraded.load(Ordering::Relaxed),
            live_mtu: self.live_mtu.load(Ordering::Relaxed) as i32,
            device_name: self
                .device_name
                .lock()
                .map(|v| v.clone())
                .unwrap_or_default(),
            mode: self.mode.lock().map(|v| v.clone()).unwrap_or_default(),
            last_error: self
                .last_error
                .lock()
                .map(|v| v.clone())
                .unwrap_or_default(),
            queued_packets: self.queued_packets.load(Ordering::Relaxed),
            injected_packets: self.injected_packets.load(Ordering::Relaxed),
            injected_bytes: self.injected_bytes.load(Ordering::Relaxed),
            dropped_packets: self.dropped_packets.load(Ordering::Relaxed),
            dropped_bytes: self.dropped_bytes.load(Ordering::Relaxed),
            rate_limited_packets: self.rate_limited_packets.load(Ordering::Relaxed),
            queue_full_packets: self.queue_full_packets.load(Ordering::Relaxed),
            write_errors: self.write_errors.load(Ordering::Relaxed),
            mtu_dropped_packets: self.mtu_dropped_packets.load(Ordering::Relaxed),
        }
    }
}

pub struct SlowPathReinjector {
    /// 9506 completion/epoch state. This mutex is independent of the
    /// snapshot-wide ServerState lock and is safe for socket + worker threads.
    reinject_core: Arc<ReinjectCore>,
    tx: SyncSender<PacketRequest>,
    /// #9637 operator narrowing: outlet for reinjects that did NOT pass a
    /// userspace host-inbound gate (delegated NoRoute/MissingNeighbor,
    /// ForwardCandidate fallback, exempt IPsec). Separate worker + TUN
    /// (`xpf-usp1`); the kernel holds no accept for it. `tx` stays the
    /// adjudicated-only outlet (`xpf-usp0`).
    tx_delegated: SyncSender<PacketRequest>,
    limiter: Mutex<RateLimiter>,
    status: Arc<SharedStatus>,
    /// Per-outlet status for the delegated TUN (live MTU, degraded, active,
    /// counters). Admission and MTU gating read the outlet's own status.
    status_delegated: Arc<SharedStatus>,
    /// #10069: logical-tick retry state for delegated MTU recovery. This is
    /// preserved with the reinjector across snapshots and bounds SIOCSIFMTU
    /// attempts under a persistent delegated failure.
    mtu_retry: Mutex<MtuRetryState>,
    /// MTU the live slow-path TUN is currently programmed with. Set at
    /// creation (#2408) and, on a day-2 config MTU change (#5801), updated by
    /// [`Self::reconcile_mtu`]: the reinjector is PRESERVED across snapshot
    /// reconciles, so a later MTU change must reprogram the RUNNING TUN and
    /// record the new value here so `mtu()`, `live_mtu`, and enqueue admission
    /// stay in agreement. `AtomicI64` (mirroring `SharedStatus::live_mtu`) so
    /// `mtu()`/`reconcile_mtu` need no `&mut` on the Arc-shared reinjector.
    /// Dual-outlet (#9637): both TUNs take the same desired MTU;
    /// `reconcile_mtu` reprograms both and records the minimum live value.
    mtu: AtomicI64,
}

/// #9637 F3 (GPT-1 form): one dual-outlet startup-handshake step as pure logic.
///
/// Each outlet contributes its single-atom `OutletInit` outcome: Live means
/// the worker owns a TUN (later diagnostics, e.g. the io_uring-unavailable
/// note recorded while the sync fallback succeeds, cannot un-live it);
/// Failed means it recorded a cause THEN published failure (so the Fail arm
/// can always report it). Terminal failure fast-fails without waiting for
/// the sibling; a both-pending timeout stays optimistic (pre-existing
/// behaviour). The pinning matrix lives in slowpath_tests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HandshakePoll {
    Wait,
    Ready,
    Fail,
}

fn handshake_step(a: OutletInit, b: OutletInit, timed_out: bool) -> HandshakePoll {
    // #9637 GPT-1: each outlet contributes ONE atomic outcome, so the four
    // booleans (and their read-skew) are gone. Live dominates: a live
    // outlet's diagnostics can never fail the handshake — the worker
    // publishes Live before recording any diagnostic note, and Failed only
    // after recording its cause (which the Fail arm below then reports).
    // A both-pending timeout stays optimistic (pre-existing behaviour).
    if a == OutletInit::Live && b == OutletInit::Live {
        return HandshakePoll::Ready;
    }
    if a == OutletInit::Failed || b == OutletInit::Failed {
        return HandshakePoll::Fail;
    }
    if timed_out {
        return HandshakePoll::Ready;
    }
    HandshakePoll::Wait
}

impl SlowPathReinjector {
    /// Create the slow-path reinjector and spawn its worker.
    ///
    /// `mtu` is the MTU (in bytes) to program on the slow-path TUN device so
    /// that reinjected frames up to the largest configured data-interface MTU
    /// are not dropped on the TUN egress (#2408). The caller sources it from
    /// the config snapshot (`ConfigSnapshot::slow_path_mtu`), never hardcoded.
    pub fn new(name: &str, mtu: i32) -> Result<Self, String> {
        let reinject_core = ReinjectCore::new_shared();
        let status = Arc::new(SharedStatus::new());
        let (tx, rx) = mpsc::sync_channel(DEFAULT_QUEUE_DEPTH);
        let thread_status = status.clone();
        let name = name.to_string();
        thread::Builder::new()
            .name("xpf-slowpath".to_string())
            .spawn(move || {
                slow_path_worker(
                    &name,
                    mtu,
                    rx,
                    thread_status,
                    SlowPathWorkerOutlet::Trusted,
                    None,
                )
            })
            .map_err(|e| format!("spawn slow-path worker: {e}"))?;
        // #9637 operator narrowing: the delegated outlet gets its own worker
        // + TUN. Either worker failing to come up fails construction: an
        // adjudicated-only reinjector would silently re-widen (delegated
        // traffic with nowhere safe to go), and a delegated-only one would
        // silently reopen the residual.
        let status_delegated = Arc::new(SharedStatus::new());
        let (tx_delegated, rx_delegated) = mpsc::sync_channel(DEFAULT_QUEUE_DEPTH);
        let thread_status_delegated = status_delegated.clone();
        let delegated_core = reinject_core.clone();
        let delegated_name = crate::afxdp::DELEGATED_SLOW_PATH_TUN.to_string();
        thread::Builder::new()
            .name("xpf-slowpath-delegated".to_string())
            .spawn(move || {
                slow_path_worker(
                    &delegated_name,
                    mtu,
                    rx_delegated,
                    thread_status_delegated,
                    SlowPathWorkerOutlet::Delegated,
                    Some(delegated_core),
                )
            })
            .map_err(|e| format!("spawn delegated slow-path worker: {e}"))?;

        // #7820: wait for the worker to report EITHER that it is live or why it
        // is not, instead of returning Ok the instant the thread is spawned.
        //
        // `slow_path_worker` opens the TUN as its first act, and on failure it
        // records the cause, clears `active`, and RETURNS. Without this
        // handshake `new` had already handed back an `Ok` reinjector whose
        // worker was gone and whose receiver was dropped, so the real cause
        // ("TUNSETIFF ...: Operation not permitted", a name collision, a
        // missing /dev/net/tun) sat unread in `last_error` while every
        // subsequent enqueue failed with the downstream symptom
        // "slow-path worker is not running". That is the production form of
        // #7820: the one caller (`reconcile/snapshot.rs`) has an `Err` arm that
        // surfaces the cause into `last_slow_path_status`, and it could never
        // be reached.
        //
        // A timeout, not a block: `open_tun` either succeeds or fails
        // promptly, so exceeding the deadline means something pathological and
        // we prefer today's optimistic behaviour to hanging dataplane startup.
        let deadline = Instant::now() + INIT_HANDSHAKE_TIMEOUT;
        loop {
            // One load per outlet: no read-skew between a flag and a
            // diagnostic is possible here by construction.
            let a = status.init_outcome();
            let b = status_delegated.init_outcome();
            match handshake_step(a, b, Instant::now() >= deadline) {
                HandshakePoll::Wait => thread::sleep(INIT_HANDSHAKE_POLL),
                HandshakePoll::Ready => break,
                HandshakePoll::Fail => {
                    // Report the first terminally failed outlet's cause
                    // (Failed ⟹ cause present by worker contract).
                    if a == OutletInit::Failed {
                        return Err(status.last_error_if_set().unwrap_or_else(|| {
                            "slow-path worker failed without a recorded cause".to_string()
                        }));
                    }
                    return Err(status_delegated.last_error_if_set().unwrap_or_else(|| {
                        "delegated slow-path worker failed without a recorded cause".to_string()
                    }));
                }
            }
        }
        Ok(Self {
            reinject_core,
            tx,
            tx_delegated,
            limiter: Mutex::new(RateLimiter::new(
                DEFAULT_RATE_LIMIT_PACKETS_PER_SEC,
                DEFAULT_RATE_LIMIT_BYTES_PER_SEC,
            )),
            status,
            status_delegated,
            mtu_retry: Mutex::new(MtuRetryState::default()),
            mtu: AtomicI64::new(mtu as i64),
        })
    }

    /// #7820: a reinjector with NO worker thread and NO TUN, for tests of the
    /// enqueue-side logic.
    ///
    /// Six tests built a real `SlowPathReinjector` purely to exercise logic
    /// that needs no device — the #2471 live-MTU admission gate and the day-2
    /// reconcile, both driven entirely by `status.live_mtu`. Wherever the suite
    /// runs without CAP_NET_ADMIN (which is everywhere it currently runs)
    /// `open_tun` fails, so the worker exited immediately and dropped the
    /// receiver. Those tests passed only when they won the race to enqueue
    /// before the disconnect landed, and lost it under load — the whole of
    /// #7820. One of them documented the dead worker in a comment and asserted
    /// around it, accepting either outcome; that is a test that cannot fail for
    /// the reason it was written.
    ///
    /// The receiver is deliberately `forget`-ed rather than returned: it must
    /// outlive the reinjector for the channel to stay connected, and making
    /// every call site thread a binding through would reintroduce the same
    /// disconnect the moment one of them dropped it. Leaking one channel
    /// endpoint per construction is confined to the test binary.
    ///
    /// `active` is set because the gate under test runs on the live path — not
    /// as a claim that a device exists.
    #[cfg(test)]
    pub(crate) fn new_without_worker(mtu: i32) -> Self {
        Self::new_without_worker_with_core(mtu, ReinjectCore::new_shared())
    }

    /// Same hermetic constructor with an injected completion core for the
    /// lease/socket tests.
    #[cfg(test)]
    pub(crate) fn new_without_worker_with_core(
        mtu: i32,
        reinject_core: Arc<ReinjectCore>,
    ) -> Self {
        let status = Arc::new(SharedStatus::new());
        let (tx, rx) = mpsc::sync_channel(DEFAULT_QUEUE_DEPTH);
        std::mem::forget(rx);
        status.active.store(true, Ordering::Relaxed);
        status.init_state.store(OutletInit::Live as u8, Ordering::Relaxed);
        let status_delegated = Arc::new(SharedStatus::new());
        let (tx_delegated, rx_delegated) = mpsc::sync_channel(DEFAULT_QUEUE_DEPTH);
        std::mem::forget(rx_delegated);
        status_delegated.active.store(true, Ordering::Relaxed);
        status_delegated.init_state.store(OutletInit::Live as u8, Ordering::Relaxed);
        Self {
            reinject_core,
            tx,
            tx_delegated,
            limiter: Mutex::new(RateLimiter::new(
                DEFAULT_RATE_LIMIT_PACKETS_PER_SEC,
                DEFAULT_RATE_LIMIT_BYTES_PER_SEC,
            )),
            status,
            status_delegated,
            mtu_retry: Mutex::new(MtuRetryState::default()),
            mtu: AtomicI64::new(mtu as i64),
        }
    }

    /// The MTU the live slow-path TUN is currently programmed with. Equals the
    /// creation MTU (#2408) until a day-2 [`Self::reconcile_mtu`] reprograms it
    /// (#5801).
    ///
    /// #6097: the day-2 reconcile TRIGGER no longer reads this — it compares the
    /// desired MTU against `status().live_mtu` (the value the TUN is actually
    /// programmed with) so a startup-`SIOCSIFMTU`-failure divergence self-heals.
    /// `mtu()` is retained as the reinjector's "installed MTU" accessor (updated
    /// by `reconcile_mtu`) and is exercised by the #5801/#6097 tests, so it is
    /// no longer read on the production path; keep it compiled without warning.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn mtu(&self) -> i32 {
        self.mtu.load(Ordering::Relaxed) as i32
    }

    /// Test-only seam: force the reinjector into a specific
    /// `(mtu(), live_mtu, degraded)` triple so a test can reproduce the
    /// STARTUP-`SIOCSIFMTU`-failure divergence (#6097) — `mtu()` at the
    /// creation-desired value (e.g. 9000) while the live TUN is stuck at the
    /// 1500 kernel default and the path is marked `degraded`. That state is
    /// otherwise reachable only by a real ioctl failure inside the worker
    /// thread, which needs CAP_NET_ADMIN to provoke deterministically. Compiled
    /// out of release builds.
    #[cfg(test)]
    pub(crate) fn force_mtu_state_for_test(&self, mtu: i32, live_mtu: i32, degraded: bool) {
        self.mtu.store(mtu as i64, Ordering::Relaxed);
        self.status.live_mtu.store(live_mtu as i64, Ordering::Relaxed);
        self.status.degraded.store(degraded, Ordering::Relaxed);
    }

    #[cfg(test)]
    pub(crate) fn force_delegated_mtu_state_for_test(&self, live_mtu: i32, degraded: bool) {
        self.status_delegated
            .live_mtu
            .store(live_mtu as i64, Ordering::Relaxed);
        self.status_delegated
            .degraded
            .store(degraded, Ordering::Relaxed);
    }

    /// Reprogram the live slow-path TUN to `desired_mtu` on a day-2 config MTU
    /// change (#5801) and return the MTU now in effect.
    ///
    /// The reinjector is preserved across snapshot reconciles, so a config MTU
    /// change committed after startup does NOT reach the running TUN unless the
    /// live device is reprogrammed here. This:
    ///   1. reprograms the live TUN via `programmer` (`set_if_mtu`/`SIOCSIFMTU`
    ///      in production; injectable in tests),
    ///   2. updates `live_mtu`/`degraded` from the result so enqueue admission
    ///      (which reads `live_mtu`) converges, and
    ///   3. records the installed MTU as this reinjector's `mtu()`.
    ///
    /// A failed `SIOCSIFMTU` is non-fatal: [`SharedStatus::reprogram_mtu_status`]
    /// KEEPS the current live MTU (the running TUN retains whatever it was last
    /// programmed with — it is NOT reset to the 1500 creation default), marks
    /// the path DEGRADED, and records the error; `mtu()` then reports the
    /// retained value, so `mtu()`, `live_mtu`, and admission still agree.
    pub(crate) fn reconcile_mtu(
        &self,
        desired_mtu: i32,
        mut programmer: impl FnMut(&str, i32) -> Result<(), String>,
    ) -> i32 {
        // #9637: reprogram BOTH outlets; report the minimum live MTU so no
        // caller treats one outlet's success as both converged. A partial
        // failure degrades exactly like the single-outlet case (retained live
        // MTU, degraded flag, logged cause) on the failing outlet only.
        let live_trusted = self.reconcile_outlet_mtu(&self.status, desired_mtu, &mut programmer);
        let live_delegated =
            self.reconcile_outlet_mtu(&self.status_delegated, desired_mtu, &mut programmer);
        let live = live_trusted.min(live_delegated);
        // Record what was ACTUALLY installed (== desired on success, or the
        // retained live MTU on a failed program) so mtu() never over-reports a
        // ceiling the device cannot honour.
        self.mtu.store(live as i64, Ordering::Relaxed);
        live
    }
    /// Reprogram only the delegated outlet. This is used once the trusted
    /// outlet has converged, so recovery does not re-issue a trusted ioctl on
    /// every delegated retry.
    pub(crate) fn reconcile_delegated_mtu(
        &self,
        desired_mtu: i32,
        mut programmer: impl FnMut(&str, i32) -> Result<(), String>,
    ) -> i32 {
        let live_delegated =
            self.reconcile_outlet_mtu(&self.status_delegated, desired_mtu, &mut programmer);
        let live_trusted = self.status.live_mtu.load(Ordering::Relaxed) as i32;
        let live = live_trusted.min(live_delegated);
        self.mtu.store(live as i64, Ordering::Relaxed);
        live
    }

    /// #10069: admit one delegated retry in a rolling logical-tick window.
    /// A degraded transition re-arms the next retry without discarding
    /// attempt history, while old attempt ticks age out. This permits eventual
    /// recovery after a persistent failure without allowing one reconcile tick
    /// to issue an unbounded ioctl stream.
    pub(crate) fn delegated_mtu_retry_permitted(
        &self,
        desired_mtu: i32,
        delegated_degraded: bool,
    ) -> bool {
        let mut state = self.mtu_retry.lock().unwrap_or_else(|e| e.into_inner());
        state.tick = state.tick.saturating_add(1);
        if desired_mtu != state.desired_mtu {
            state.desired_mtu = desired_mtu;
            state.attempts = 0;
            state.attempt_ticks = [0; MTU_RETRY_MAX_ATTEMPTS_PER_WINDOW as usize];
            state.next_retry_tick = state.tick;
        }
        if delegated_degraded && !state.was_degraded {
            // A newly observed degraded edge re-arms the next retry without
            // erasing the rolling attempt history. Clearing `attempts` here
            // could exceed the three-attempt bound when an outlet becomes
            // degraded as the result of the retry that just ran.
            state.next_retry_tick = state.tick;
        }
        while state.attempts > 0
            && state.tick.saturating_sub(state.attempt_ticks[0]) >= MTU_RETRY_WINDOW_TICKS
        {
            state.attempts -= 1;
            state.attempt_ticks.rotate_left(1);
            let remaining = state.attempts as usize;
            state.attempt_ticks[remaining] = 0;
            if state.attempts == 0 {
                state.next_retry_tick = state.tick;
            }
        }
        state.was_degraded = delegated_degraded;
        state.attempts < MTU_RETRY_MAX_ATTEMPTS_PER_WINDOW
            && state.tick >= state.next_retry_tick
    }

    /// Record the result of a delegated retry and apply exponential backoff
    /// before the next logical reconcile tick.
    pub(crate) fn record_delegated_mtu_retry(&self, succeeded: bool) {
        let mut state = self.mtu_retry.lock().unwrap_or_else(|e| e.into_inner());
        if succeeded {
            state.attempts = 0;
            state.attempt_ticks = [0; MTU_RETRY_MAX_ATTEMPTS_PER_WINDOW as usize];
            state.next_retry_tick = state.tick;
            state.was_degraded = false;
            return;
        }
        let slot = state.attempts as usize;
        state.attempt_ticks[slot] = state.tick;
        state.attempts += 1;
        let shift = state.attempts.saturating_sub(1).min(3) as u32;
        state.next_retry_tick = state.tick.saturating_add(1u32 << shift);
    }


    fn reconcile_outlet_mtu(
        &self,
        status: &Arc<SharedStatus>,
        desired_mtu: i32,
        programmer: &mut impl FnMut(&str, i32) -> Result<(), String>,
    ) -> i32 {
        let name = status
            .device_name
            .lock()
            .map(|v| v.clone())
            .unwrap_or_default();
        status.reprogram_mtu_status(&name, desired_mtu, programmer)
    }

    pub fn enqueue(&self, bytes: Vec<u8>) -> Result<EnqueueOutcome, String> {
        self.enqueue_on(&self.tx, &self.status, bytes, PacketQueue::Trusted)
    }

    /// #10391: enqueue a userspace-adjudicated xfrm/reinject packet to queue
    /// zero of the shared xpf-usp1 TUN. The TC ingress classifier maps that
    /// structural queue identity to the fence mark; callers cannot choose the
    /// queue through the delegated API.
    pub fn enqueue_adjudicated(&self, bytes: Vec<u8>) -> Result<EnqueueOutcome, String> {
        self.enqueue_on(
            &self.tx_delegated,
            &self.status_delegated,
            bytes,
            PacketQueue::Adjudicated,
        )
    }

    /// #9637 operator narrowing: enqueue to the DELEGATED outlet
    /// (`xpf-usp1`) for reinjects that did NOT pass a userspace host-inbound
    /// gate. Admission, rate limiting and counters run on that outlet's own
    /// status; the kernel holds no accept for it.
    pub fn enqueue_delegated(&self, bytes: Vec<u8>) -> Result<EnqueueOutcome, String> {
        self.enqueue_on(
            &self.tx_delegated,
            &self.status_delegated,
            bytes,
            PacketQueue::Delegated,
        )
    }

    fn enqueue_on(
        &self,
        tx: &SyncSender<PacketRequest>,
        status: &Arc<SharedStatus>,
        bytes: Vec<u8>,
        queue: PacketQueue,
    ) -> Result<EnqueueOutcome, String> {
        let packet_len = bytes.len() as u64;
        // Refuse frames larger than the live TUN MTU before they reach a
        // worker; this keeps the existing degraded-path accounting intact.
        let live_mtu = status.live_mtu.load(Ordering::Relaxed);
        if live_mtu > 0 && packet_len > live_mtu as u64 {
            status.mtu_dropped_packets.fetch_add(1, Ordering::Relaxed);
            status.dropped_packets.fetch_add(1, Ordering::Relaxed);
            status
                .dropped_bytes
                .fetch_add(packet_len, Ordering::Relaxed);
            if let Some(class) = admission_class(queue) {
                self.reinject_core.record_class_refused(class);
            }
            return Ok(EnqueueOutcome::MtuExceeded);
        }
        let allowed = self
            .limiter
            .lock()
            .map_err(|_| "slow-path limiter lock poisoned".to_string())?
            .allow(bytes.len());
        if !allowed {
            status.dropped_packets.fetch_add(1, Ordering::Relaxed);
            status
                .dropped_bytes
                .fetch_add(packet_len, Ordering::Relaxed);
            status
                .rate_limited_packets
                .fetch_add(1, Ordering::Relaxed);
            if let Some(class) = admission_class(queue) {
                self.reinject_core.record_class_refused(class);
            }
            return Ok(EnqueueOutcome::RateLimited);
        }
        status.queued_packets.fetch_add(1, Ordering::Relaxed);
        match tx.try_send(PacketRequest {
            bytes,
            queue,
            lease: None,
            flow_tag: 0,
        }) {
            Ok(()) => {
                if let Some(class) = admission_class(queue) {
                    self.reinject_core.record_class_admitted(class);
                }
                Ok(EnqueueOutcome::Accepted)
            }
            Err(TrySendError::Full(req)) => {
                status.queued_packets.fetch_sub(1, Ordering::Relaxed);
                status.dropped_packets.fetch_add(1, Ordering::Relaxed);
                status
                    .dropped_bytes
                    .fetch_add(req.bytes.len() as u64, Ordering::Relaxed);
                status
                    .queue_full_packets
                    .fetch_add(1, Ordering::Relaxed);
                if let Some(class) = admission_class(queue) {
                    self.reinject_core.record_class_refused(class);
                }
                Ok(EnqueueOutcome::QueueFull)
            }
            Err(TrySendError::Disconnected(req)) => {
                status.queued_packets.fetch_sub(1, Ordering::Relaxed);
                status.dropped_packets.fetch_add(1, Ordering::Relaxed);
                status
                    .dropped_bytes
                    .fetch_add(req.bytes.len() as u64, Ordering::Relaxed);
                if let Some(class) = admission_class(queue) {
                    self.reinject_core.record_class_refused(class);
                }
                let err = "slow-path worker is not running".to_string();
                status.set_last_error(err.clone());
                Err(err)
            }
        }
    }
    /// Admit and enqueue one leased adjudicated frame. This is the only
    /// production caller that creates `PacketRequest { lease: Some(..) }`;
    /// trusted/delegated and legacy adjudicated APIs remain lease-free.
    /// Validate-only socket path. It performs MTU and limiter checks but never
    /// allocates a PacketRequest or touches the worker channel/TUN.
    pub(crate) fn validate_dry_run_frame(&self, frame: SubmitFrame) -> AdmitDecision {
        let mut decision = self.reinject_core.validate_dry_run(&frame);
        if decision.admitted {
            let packet_len = frame.bytes.len() as u64;
            let live_mtu = self.status_delegated.live_mtu.load(Ordering::Relaxed);
            if live_mtu > 0 && packet_len > live_mtu as u64 {
                decision.admitted = false;
                decision.reason = ADMIT_BAD_LEASE;
            } else {
                let allowed = self
                    .limiter
                    .lock()
                    .map(|limiter| limiter.would_allow(frame.bytes.len()))
                    .unwrap_or(false);
                if !allowed {
                    decision.admitted = false;
                    decision.reason = ADMIT_BAD_LEASE;
                }
            }
        }
        self.reinject_core.note_dry_run(decision.admitted);
        decision
    }

    pub(crate) fn submit_adjudicated_frame(&self, frame: SubmitFrame) -> AdmitDecision {
        if frame.flags & SUBMIT_FLAG_DRY_RUN != 0 {
            self.reinject_core
                .record_class_refused(AdmissionClass::Adjudicated);
            return self.reinject_core.refuse_non_dry_run(&frame);
        }
        let packet_len = frame.bytes.len() as u64;
        let live_mtu = self.status_delegated.live_mtu.load(Ordering::Relaxed);
        if live_mtu > 0 && packet_len > live_mtu as u64 {
            self.status_delegated
                .mtu_dropped_packets
                .fetch_add(1, Ordering::Relaxed);
            self.status_delegated
                .dropped_packets
                .fetch_add(1, Ordering::Relaxed);
            self.status_delegated
                .dropped_bytes
                .fetch_add(packet_len, Ordering::Relaxed);
            self.reinject_core
                .record_class_refused(AdmissionClass::Adjudicated);
            return AdmitDecision {
                request_id: frame.lease.request_id,
                permit_epoch: frame.lease.permit_epoch,
                queue_epoch: frame.lease.queue_epoch,
                queue_number: frame.lease.queue_number,
                family: frame.origin.family,
                hook: frame.origin.hook,
                owned_ifindex: frame.origin.owned_ifindex,
                admitted: false,
                reason: ADMIT_BAD_LEASE,
            };
        }

        let mut decision = self
            .reinject_core
            .admit_with_class(&frame, Some(AdmissionClass::Adjudicated));
        if !decision.admitted {
            return decision;
        }
        let allowed = match self.limiter.lock() {
            Ok(mut limiter) => limiter.allow(frame.bytes.len()),
            Err(_) => false,
        };
        if !allowed {
            self.reinject_core
                .refuse_queued(&frame.lease, "rate limited".to_string());
            self.reinject_core
                .record_class_refused(AdmissionClass::Adjudicated);
            self.status_delegated
                .rate_limited_packets
                .fetch_add(1, Ordering::Relaxed);
            self.status_delegated
                .dropped_packets
                .fetch_add(1, Ordering::Relaxed);
            self.status_delegated
                .dropped_bytes
                .fetch_add(packet_len, Ordering::Relaxed);
            decision.admitted = false;
            decision.reason = ADMIT_BAD_LEASE;
            return decision;
        }

        self.status_delegated
            .queued_packets
            .fetch_add(1, Ordering::Relaxed);
        let request = PacketRequest {
            bytes: frame.bytes,
            queue: PacketQueue::Adjudicated,
            lease: Some(frame.lease),
            flow_tag: frame.flow_tag,
        };
        match self.tx_delegated.try_send(request) {
            Ok(()) => decision,
            Err(TrySendError::Full(req)) => {
                self.status_delegated
                    .queued_packets
                    .fetch_sub(1, Ordering::Relaxed);
                self.status_delegated
                    .queue_full_packets
                    .fetch_add(1, Ordering::Relaxed);
                self.status_delegated
                    .dropped_packets
                    .fetch_add(1, Ordering::Relaxed);
                self.status_delegated
                    .dropped_bytes
                    .fetch_add(req.bytes.len() as u64, Ordering::Relaxed);
                self.reinject_core
                    .refuse_queued(&frame.lease, "queue full".to_string());
                self.reinject_core
                    .record_class_refused(AdmissionClass::Adjudicated);
                decision.admitted = false;
                decision.reason = ADMIT_BAD_LEASE;
                decision
            }
            Err(TrySendError::Disconnected(req)) => {
                self.status_delegated
                    .queued_packets
                    .fetch_sub(1, Ordering::Relaxed);
                self.status_delegated
                    .dropped_packets
                    .fetch_add(1, Ordering::Relaxed);
                self.status_delegated
                    .dropped_bytes
                    .fetch_add(req.bytes.len() as u64, Ordering::Relaxed);
                self.reinject_core
                    .refuse_queued(&frame.lease, "worker stopped".to_string());
                self.reinject_core
                    .record_class_refused(AdmissionClass::Adjudicated);
                decision.admitted = false;
                decision.reason = ADMIT_BAD_LEASE;
                decision
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn submit_leased(&self, frame: SubmitFrame) -> AdmitDecision {
        self.submit_adjudicated_frame(frame)
    }
    pub(crate) fn publish_reinject_epochs(&self, permit_epoch: u64, queue_epochs: &[(u16, u64)]) {
        self.reinject_core.publish_epochs(permit_epoch, queue_epochs);
    }

    pub(crate) fn reinject_core(&self) -> Arc<ReinjectCore> {
        self.reinject_core.clone()
    }

    pub(crate) fn reinject_stats(&self) -> crate::slowpath_reinject_9506::ReinjectStats {
        self.reinject_core.stats_snapshot()
    }
    pub(crate) fn reinject_status(&self) -> Option<ReinjectStatusSnapshot> {
        self.reinject_core.status_snapshot()
    }
    pub fn status(&self) -> SlowPathStatus {
        self.status.snapshot()
    }
    /// Snapshot of the delegated outlet's status (live MTU, degraded, active,
    /// counters). Consumed by reconcile_mtu internals, the partial-failure
    /// pin, and the Coordinator's operator-facing status-wire and metrics
    /// projections.
    pub fn delegated_status(&self) -> SlowPathStatus {
        self.status_delegated.snapshot()
    }
}

fn slow_path_worker(
    name: &str,
    mtu: i32,
    rx: Receiver<PacketRequest>,
    status: Arc<SharedStatus>,
    outlet: SlowPathWorkerOutlet,
    reinject_core: Option<Arc<ReinjectCore>>,
) {
    let (tun, adjudicated_tun, actual_name, _classifier) = match outlet {
        SlowPathWorkerOutlet::Trusted => match open_tun_with_flags(name, false) {
            Ok((tun, actual_name)) => (tun, None, actual_name, None),
            Err(err) => {
                status.set_last_error(err);
                status.init_state.store(OutletInit::Failed as u8, Ordering::Relaxed);
                status.active.store(false, Ordering::Relaxed);
                return;
            }
        },
        SlowPathWorkerOutlet::Delegated => {
            let first = match open_tun_with_flags(name, true) {
                Ok(v) => v,
                Err(err) => {
                    status.set_last_error(err);
                    status.init_state.store(OutletInit::Failed as u8, Ordering::Relaxed);
                    status.active.store(false, Ordering::Relaxed);
                    return;
                }
            };
            let second = match open_tun_with_flags(name, true) {
                Ok(v) => v,
                Err(err) => {
                    status.set_last_error(err);
                    status.init_state.store(OutletInit::Failed as u8, Ordering::Relaxed);
                    status.active.store(false, Ordering::Relaxed);
                    return;
                }
            };
            if first.1 != second.1 {
                let err = format!(
                    "xpf-usp1 multi-queue TUN name changed from {} to {}",
                    first.1, second.1
                );
                status.set_last_error(err);
                status.init_state.store(OutletInit::Failed as u8, Ordering::Relaxed);
                status.active.store(false, Ordering::Relaxed);
                return;
            }
            let classifier = match install_queue_mark_classifier(&first.1) {
                Ok(classifier) => classifier,
                Err(err) => {
                    status.set_last_error(err);
                    status.init_state.store(OutletInit::Failed as u8, Ordering::Relaxed);
                    status.active.store(false, Ordering::Relaxed);
                    return;
                }
            };
            (second.0, Some(first.0), second.1, Some(classifier))
        }
    };
    // #2408: the kernel creates the TUN at the default 1500 MTU. Raise it to
    // the largest configured data-interface MTU so reinjected jumbo frames
    // are not silently dropped on the TUN egress. A failure here is non-fatal:
    // the TUN is still usable for <=1500 frames, so the path stays active but
    // is marked DEGRADED (#2471).
    status.apply_mtu_status(&actual_name, mtu, set_if_mtu);
    status.set_device_name(&actual_name);
    status.active.store(true, Ordering::Relaxed);
    // #9637 GPT-1: publish initialization only after the complete outlet
    // setup, including the structural queue classifier.
    status.init_state.store(OutletInit::Live as u8, Ordering::Relaxed);

    let mut mode = match crate::io_uring_write::RingWriter::new(256) {
        Ok(ring) => {
            status.set_mode("io_uring");
            WriteMode::IoUring(ring)
        }
        Err(err) => {
            status.set_mode("sync");
            status.set_last_error(format!("slow-path io_uring unavailable: {err}"));
            WriteMode::SyncFallback
        }
    };

    while let Ok(req) = rx.recv() {
        status.queued_packets.fetch_sub(1, Ordering::Relaxed);
        let fd = match (outlet, req.queue) {
            (SlowPathWorkerOutlet::Trusted, PacketQueue::Trusted)
            | (SlowPathWorkerOutlet::Delegated, PacketQueue::Delegated) => tun.as_raw_fd(),
            (SlowPathWorkerOutlet::Delegated, PacketQueue::Adjudicated) => adjudicated_tun
                .as_ref()
                .expect("delegated outlet owns the adjudicated queue")
                .as_raw_fd(),
            _ => {
                status.dropped_packets.fetch_add(1, Ordering::Relaxed);
                status
                    .dropped_bytes
                    .fetch_add(req.bytes.len() as u64, Ordering::Relaxed);
                continue;
            }
        };
        // The q0 lease check is the authorization linearization point:
        // immediately before entering the TUN write, never at admission.
        let lease = req.lease;
        if let Some(lease) = lease {
            let pre = reinject_core
                .as_ref()
                .map(|core| core.pre_write_check(&lease))
                .unwrap_or(crate::slowpath_reinject_9506::PreWrite::Unknown);
            if !matches!(pre, crate::slowpath_reinject_9506::PreWrite::Proceed) {
                status.dropped_packets.fetch_add(1, Ordering::Relaxed);
                status
                    .dropped_bytes
                    .fetch_add(req.bytes.len() as u64, Ordering::Relaxed);
                continue;
            }
        }
        // The owned packet buffer MOVES into the write path. In io_uring mode
        // a deferred outcome moves it into the ring's in-flight registry.
        let bytes_len = req.bytes.len();
        let (outcome, leased_verdict) = if lease.is_some() {
            let (verdict, outcome) = write_packet_with_lease(&mut mode, fd, req.bytes);
            (outcome, Some(verdict))
        } else {
            (write_packet_with_mode(&mut mode, fd, req.bytes), None)
        };
        if let (Some(lease), Some(verdict), Some(core)) =
            (lease, leased_verdict, reinject_core.as_ref())
        {
            // No post-write epoch check: a definitive full-frame success
            // after WRITE_STARTED is the REINJECT COMMIT point.
            core.resolve_write(&lease, verdict);
        }
        apply_slowpath_outcome(outcome, &mut mode, bytes_len, &status);
    }
    status.active.store(false, Ordering::Relaxed);
}

/// The fate of ONE slow-path packet write, separating PACKET-TRANSFER CERTAINTY
/// from io_uring RING HEALTH (#5172).
///
/// The two axes are independent:
///   * `result` — did THIS packet reach the TUN (`Ok`, counted as injected) or
///     was it dropped (`Err`, counted as a write error + drop). This is the
///     #2477 per-call decision: an io_uring failure that put nothing on the
///     device is rescued by a synchronous write; an ambiguous/partial one is
///     dropped (NO-RETRY — re-sending could double-transmit).
///   * `ring_terminal` — is the io_uring ring itself durably broken, so the
///     worker must stop submitting to it for the rest of its life. Set ONLY for
///     a non-`safe_to_retry` io_uring failure (an ambiguous submit/reap — the
///     ring is wedged; a packet-fd short write cannot occur on an atomic TUN
///     write, so this variant means the ring, not the packet). A transient
///     `NothingWritten` failure that the sync fallback rescued does NOT set it
///     (keep io_uring, do not demote on a momentary blip).
struct SlowPathWriteOutcome {
    result: Result<(), String>,
    ring_terminal: bool,
    /// The io_uring error that triggered the demotion, formatted for the status
    /// `last_error` so an operator can see WHY the ring was retired. `Some` iff
    /// `ring_terminal`.
    demotion_cause: Option<String>,
}

/// Write one packet under the current [`WriteMode`], returning a structured
/// outcome (packet fate + ring health). The io_uring arm classifies a runtime
/// ring failure via [`classify_io_uring_write`]; the sync arm can never fail the
/// ring, so it is always healthy.
fn write_packet_with_mode(
    mode: &mut WriteMode,
    fd: i32,
    bytes: Vec<u8>,
) -> SlowPathWriteOutcome {
    match mode {
        WriteMode::IoUring(ring) => {
            // Move the owned buffer into the ring. A stream write to the packet
            // TUN (no file offset). On a Deferred outcome the ring KEEPS the
            // buffer in its in-flight registry (never freed while an SQE may
            // reference it, #5800); a NothingWritten hands it back for the
            // synchronous fallback.
            let result = ring.write(fd, bytes, false, "slow-path");
            classify_io_uring_write(result, |b| write_packet_sync(fd, &b))
        }
        WriteMode::SyncFallback => SlowPathWriteOutcome {
            result: write_packet_sync(fd, &bytes),
            ring_terminal: false,
            demotion_cause: None,
        },
    }
}
/// Lease-aware writer preserving the structural io_uring taxonomy. The legacy
/// writer remains untouched for lease=None calls; this arm converts the
/// classifier's verdict to the old status outcome only after classification.
fn write_packet_with_lease(
    mode: &mut WriteMode,
    fd: i32,
    bytes: Vec<u8>,
) -> (TransferVerdict, SlowPathWriteOutcome) {
    match mode {
        WriteMode::IoUring(ring) => {
            let result = ring.write(fd, bytes, false, "slow-path");
            let leased = classify_leased_write(result, |buffer| {
                sync_classified_verdict(fd, &buffer)
            });
            let legacy = leased_outcome_to_status(
                &leased.verdict,
                leased.ring_terminal,
                leased.demotion_cause.clone(),
            );
            (leased.verdict, legacy)
        }
        WriteMode::SyncFallback => {
            let classified = write_packet_sync_classified(fd, &bytes);
            let verdict = classified_verdict(&classified);
            let status = classified_outcome_to_status(classified);
            (verdict, status)
        }
    }
}

#[derive(Debug)]
enum SyncWriteOutcome {
    Written(u32),
    NothingWritten(String),
    Transferred(String),
}

fn write_packet_sync_classified(fd: i32, bytes: &[u8]) -> SyncWriteOutcome {
    let len = bytes.len();
    loop {
        let rc = unsafe { libc::write(fd, bytes.as_ptr().cast::<libc::c_void>(), len) };
        if rc < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return SyncWriteOutcome::NothingWritten(format!("slow-path write: {err}"));
        }
        let count = rc as usize;
        if count == len {
            return SyncWriteOutcome::Written(len as u32);
        }
        if count == 0 {
            return SyncWriteOutcome::NothingWritten(
                "slow-path short write on packet fd: 0".to_string(),
            );
        }
        return SyncWriteOutcome::Transferred(format!(
            "slow-path short write on packet fd: wrote {count} of {len} bytes"
        ));
    }
}

fn classified_verdict(outcome: &SyncWriteOutcome) -> TransferVerdict {
    match outcome {
        SyncWriteOutcome::Written(bytes) => TransferVerdict::Written { bytes: *bytes },
        SyncWriteOutcome::NothingWritten(reason) => TransferVerdict::Refused {
            reason: reason.clone(),
        },
        SyncWriteOutcome::Transferred(reason) => TransferVerdict::Uncertain {
            reason: reason.clone(),
        },
    }
}

fn sync_classified_verdict(fd: i32, bytes: &[u8]) -> TransferVerdict {
    match write_packet_sync_classified(fd, bytes) {
        SyncWriteOutcome::Written(bytes) => TransferVerdict::Written { bytes },
        SyncWriteOutcome::NothingWritten(reason) => TransferVerdict::Refused { reason },
        SyncWriteOutcome::Transferred(reason) => TransferVerdict::Uncertain { reason },
    }
}

fn classified_outcome_to_status(outcome: SyncWriteOutcome) -> SlowPathWriteOutcome {
    let result = match outcome {
        SyncWriteOutcome::Written(_) => Ok(()),
        SyncWriteOutcome::NothingWritten(reason) => Err(reason),
        SyncWriteOutcome::Transferred(reason) => Err(reason),
    };
    SlowPathWriteOutcome {
        result,
        ring_terminal: false,
        demotion_cause: None,
    }
}

fn leased_outcome_to_status(
    verdict: &TransferVerdict,
    ring_terminal: bool,
    demotion_cause: Option<String>,
) -> SlowPathWriteOutcome {
    let result = match verdict {
        TransferVerdict::Written { .. } => Ok(()),
        TransferVerdict::Refused { reason } | TransferVerdict::Uncertain { reason } => {
            Err(reason.clone())
        }
        TransferVerdict::Fenced => Err("fenced".to_string()),
        TransferVerdict::Denied => Err("denied".to_string()),
        TransferVerdict::Accepted => Ok(()),
        TransferVerdict::WouldReinject => Ok(()),
    };
    SlowPathWriteOutcome {
        result,
        ring_terminal,
        demotion_cause,
    }
}
/// Classify a single io_uring [`WriteResult`] into a [`SlowPathWriteOutcome`]
/// (#5172 + #5800). Separates packet-transfer certainty (the #2477 sync-fallback
/// decision) from ring health, and distinguishes the four outcomes the acceptance
/// criteria require: successful completion, deferred in-flight ownership,
/// cancellation/partial transfer, and fatal ring teardown.
///
///   * `Done` — delivered via io_uring; ring healthy. No sync fallback.
///   * `NothingWritten` — nothing reached the TUN (submit-queue full, a per-packet
///     completion error, a zero-byte completion, or id-space exhaustion). The
///     returned buffer feeds a synchronous retry that rescues THIS packet.
///     TRANSIENT: keep io_uring mode (do not demote on a momentary blip, #2477).
///   * `Transferred` — a packet-fd partial write: `0 < n < len` bytes are already
///     on the TUN and the CQE was REAPED (terminal, buffer safe). Re-sending the
///     whole packet would duplicate it → DROP, no sync retry. The ring reaped
///     cleanly, so it is NOT demoted.
///   * `Deferred` — the op did NOT reach a reaped terminal state, so the buffer
///     has been MOVED into the ring's in-flight registry (retained, not freed) and
///     the packet did not reliably reach the TUN → DROP (no sync retry; the write
///     may be in flight). A FATAL ring (dead fd, `fatal_ring = true`) is TERMINAL
///     — demote to sync so later packets stop hitting a dead ring. A bare
///     retry-ceiling storm (`fatal_ring = false`) keeps io_uring: the ring is
///     otherwise healthy and the parked buffer is reclaimed on a later write's
///     reap.
///
/// The `sync_fallback` thunk receives the handed-back buffer (only the
/// `NothingWritten` arm invokes it). Factored so the classification is
/// unit-testable without a live ring or TUN.
fn classify_io_uring_write<F>(
    result: WriteResult,
    sync_fallback: F,
) -> SlowPathWriteOutcome
where
    F: FnOnce(Vec<u8>) -> Result<(), String>,
{
    match result {
        WriteResult::Done(_bytes) => SlowPathWriteOutcome {
            result: Ok(()),
            ring_terminal: false,
            demotion_cause: None,
        },
        WriteResult::NothingWritten(bytes, _msg) => SlowPathWriteOutcome {
            // Nothing on the fd — the sync fallback rescues this packet from the
            // returned buffer. The ring stays live (transient, not a demotion).
            result: sync_fallback(bytes),
            ring_terminal: false,
            demotion_cause: None,
        },
        WriteResult::Transferred(_bytes, msg) => SlowPathWriteOutcome {
            // Bytes already on the TUN (reaped, terminal). Drop, never re-send.
            // The ring is healthy — not a demotion.
            result: Err(msg),
            ring_terminal: false,
            demotion_cause: None,
        },
        WriteResult::Deferred {
            id,
            message,
            fatal_ring,
        } => {
            // The buffer is parked in the ring's registry (retained, not freed);
            // `id` identifies the parked in-flight write so an operator can
            // correlate it with the teardown drain. Only a FATAL ring demotes; a
            // retry-ceiling storm keeps io_uring.
            let message = format!("{message} (in-flight id {id}, buffer retained)");
            let demotion_cause = fatal_ring.then(|| {
                format!("slow-path io_uring ring failure, demoting to sync: {message}")
            });
            SlowPathWriteOutcome {
                result: Err(message),
                ring_terminal: fatal_ring,
                demotion_cause,
            }
        }
    }
}

/// Apply a [`SlowPathWriteOutcome`] to the worker's shared status and, on a
/// TERMINAL ring failure, demote the write mode ONCE (#5172). This is the
/// runtime-demotion chokepoint, mirroring `state_writer::apply_outcome` (#2958):
///
///   * On `ring_terminal`, if still in io_uring mode, retire the ring
///     ([`retire_ring_to_sync`]) and flip the reported `mode` to `"sync"`. Every
///     later packet then takes the sync branch directly, never re-submitting to
///     the broken ring — the fix for the "every packet retries the broken ring"
///     degradation. The demotion is PERMANENT (no cooldown re-promotion — avoids
///     flapping). Unlike `state_writer`, the slow path's `active` flag tracks
///     TUN/worker liveness (not io_uring), so it is left untouched — the path is
///     still active, just in sync mode.
///   * Counters mirror the pre-#5172 loop exactly: `Ok` → injected; `Err` →
///     write error + drop, with `last_error` set. On a demotion the more useful
///     `demotion_cause` (which embeds the ring error) is recorded last.
///
/// Extracting this lets a unit test drive the exact demotion (fail-on-revert):
/// remove the `*mode = SyncFallback` assignment and the mode stays io_uring.
fn apply_slowpath_outcome(
    outcome: SlowPathWriteOutcome,
    mode: &mut WriteMode,
    bytes_len: usize,
    status: &SharedStatus,
) {
    if outcome.ring_terminal && matches!(mode, WriteMode::IoUring(_)) {
        retire_ring_to_sync(mode);
        status.set_mode("sync");
    }
    match &outcome.result {
        Ok(()) => {
            status.injected_packets.fetch_add(1, Ordering::Relaxed);
            status
                .injected_bytes
                .fetch_add(bytes_len as u64, Ordering::Relaxed);
        }
        Err(err) => {
            status.write_errors.fetch_add(1, Ordering::Relaxed);
            status.dropped_packets.fetch_add(1, Ordering::Relaxed);
            status
                .dropped_bytes
                .fetch_add(bytes_len as u64, Ordering::Relaxed);
            status.set_last_error(err.clone());
        }
    }
    // Record the demotion cause LAST so it overrides the generic drop error as
    // `last_error`: an operator inspecting status sees WHY io_uring was retired.
    if let Some(cause) = outcome.demotion_cause {
        status.set_last_error(cause);
    }
}

/// Retire the io_uring ring to [`WriteMode::SyncFallback`] (#5172 + #5800).
///
/// Overwriting `*mode` DROPS the [`RingWriter`], whose `Drop` runs a bounded
/// teardown drain (submit an AsyncCancel per still-in-flight entry, observe each
/// target write's terminal CQE) and then closes the ring fd. The drain is the
/// synchronous proof: every buffer it releases is provably unreferenced, which
/// is the parked-buffer case the pre-#5800 code could not cover. A straggler the
/// drain could NOT prove terminal is retained and freed only when the in-flight
/// registry drops, which field order puts after the ring fd close — a
/// best-effort narrowing of the window, not a barrier, because the fd close only
/// queues the kernel's asynchronous `io_ring_exit_work` (#6168; see the
/// `io_uring_write` module doc). No re-promotion (avoids flapping).
fn retire_ring_to_sync(mode: &mut WriteMode) {
    *mode = WriteMode::SyncFallback;
}

fn write_packet_sync(fd: i32, bytes: &[u8]) -> Result<(), String> {
    write_packet_atomic(bytes.len(), |buf_len| {
        // SAFETY: `bytes` is a valid slice for `buf_len` bytes; `fd` is the TUN
        // fd owned by the worker. Always writes from offset 0 — a TUN write is
        // one packet, never a partial-offset resubmit.
        unsafe { libc::write(fd, bytes.as_ptr().cast::<libc::c_void>(), buf_len) }
    })
}

/// Write one whole packet to a packet-oriented fd (the TUN device).
///
/// A TUN/TAP fd is datagram-like: each successful `write()` injects exactly one
/// L3 packet. There is no byte-stream resume — re-writing a "remainder" after a
/// short count would inject the leftover bytes as a SECOND, malformed packet
/// (#2407). So this never advances an offset:
///
///   * `EINTR` — the write never started; retry the WHOLE packet.
///   * full count (`rc == len`) — success.
///   * partial (`0 < rc < len`) — the packet is unsendable as written and a
///     resubmit would corrupt the stream; DROP it (return `Err`, which the
///     caller counts as a dropped packet + write error).
///   * `rc == 0` or `rc < 0` (any other errno, incl. `EAGAIN`) — `Err` (drop).
///
/// `writer(len)` performs one `write(fd, buf, len)` and returns its raw result,
/// mirroring `libc::write`: a non-negative byte count on success, or `-1` on
/// error with `errno` set separately (the unit-test seam sets `errno`
/// explicitly). On a `-1` return `write_packet_atomic` reads `errno` via
/// `io::Error::last_os_error()` to distinguish `EINTR` (retry the whole packet)
/// from a hard error (drop). It is a seam so the short-count / EINTR behaviour
/// is unit-testable without a real fd.
fn write_packet_atomic<F>(len: usize, mut writer: F) -> Result<(), String>
where
    F: FnMut(usize) -> isize,
{
    loop {
        let rc = writer(len);
        if rc < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                // The write was interrupted before transferring any bytes;
                // retry the whole packet from offset 0.
                continue;
            }
            return Err(format!("slow-path write: {err}"));
        }
        let n = rc as usize;
        if n == len {
            return Ok(());
        }
        // A short or zero count on a packet device: the packet cannot be
        // resumed (re-writing bytes[n..] would inject a corrupt packet), so
        // drop it. This is unexpected for a valid TUN write; dropping avoids
        // corrupting the device stream.
        return Err(format!(
            "slow-path short write on packet fd: wrote {n} of {len} bytes (packet dropped)"
        ));
    }
}

/// Bound on the WouldBlock/EAGAIN retry spin for a NON-BLOCKING packet fd
/// (#2438). The WG/GRE local-delivery TUN fds are opened `O_NONBLOCK`, so a
/// transient EAGAIN is normal backpressure, not an anomaly — we retry the
/// WHOLE packet rather than drop it. But the retry must be bounded so a
/// genuinely stuck device (full kernel TUN queue with no drainer) cannot wedge
/// the delivery thread in an unbounded busy-spin. After this many EAGAINs we
/// give up and drop the single packet (counted by the caller); the next packet
/// gets a fresh budget. The TUN egress queue is drained by the kernel routing
/// stack, so in practice EAGAIN clears within a few iterations.
const NONBLOCK_WOULDBLOCK_RETRY_BUDGET: u32 = 1024;

/// Synthetic errno for the exhausted-WouldBlock-budget drop (#2438) so the
/// caller's fatal-errno classifier sees a NON-fatal, per-packet condition
/// (matching how a real transient EAGAIN would be classified) rather than a
/// hard fd-death code. `ENOBUFS` is the natural "queue full, packet dropped"
/// errno and is non-fatal in the WG/GRE write predicates.
const WOULDBLOCK_EXHAUSTED_ERRNO: i32 = libc::ENOBUFS;

/// #7174 M05: how long one WouldBlock wait blocks on POLLOUT, in milliseconds.
///
/// Short on purpose. `NONBLOCK_WOULDBLOCK_RETRY_BUDGET` bounds how MANY waits a
/// single packet may make, so this bounds how long each one costs — and the
/// product is the worst case a genuinely wedged device can hold the delivery
/// thread. A longer slice would swap the CPU-burn this fixes for
/// head-of-line blocking, which is the same defect wearing different clothes.
const NONBLOCK_WOULDBLOCK_POLL_SLICE_MS: i32 = 1;

/// Write one whole packet to a NON-BLOCKING packet-oriented fd (the WG/GRE
/// local-delivery TUN devices, opened `O_NONBLOCK`).
///
/// This is the non-blocking sibling of `write_packet_atomic` (#2438). The
/// packet-device semantics are identical — each `write()` injects exactly one
/// L3 packet, there is NO byte-stream resume, so a "remainder" write of
/// `buf[n..]` after a short count would inject the leftover bytes as a SECOND,
/// malformed packet (the #2407 corruption that std `Write::write_all` causes on
/// a packet fd). The ONE behavioural difference from the blocking helper is the
/// EAGAIN/`WouldBlock` arm:
///
///   * `EINTR` — the write never started; retry the WHOLE packet.
///   * `WouldBlock`/`EAGAIN` — the fd is non-blocking and the TUN queue is
///     momentarily full; this is legitimate backpressure, NOT a per-packet
///     fault. Retry the WHOLE packet (never `buf[n..]`), bounded by
///     `NONBLOCK_WOULDBLOCK_RETRY_BUDGET` so a stuck device cannot wedge the
///     thread. On the (blocking) slow path #2407 dropped here because EAGAIN
///     could not legitimately occur on its blocking fd — dropping here would
///     lose packets under load, which is exactly the #2438 bug.
///   * full count (`rc == len`) — success.
///   * partial (`0 < rc < len`) — the packet is unsendable as written and a
///     resubmit would corrupt the device stream; DROP it (Err — counted as a
///     dropped packet + write error). Never resume `buf[n..]`.
///   * `rc == 0` or any other negative errno — `Err` (drop).
///
/// Returns the underlying `io::Error` on failure so the caller's fatal-errno
/// classifier (`local_tunnel_write_error_is_fatal`) keeps working. The
/// exhausted-budget drop surfaces as `ENOBUFS` (non-fatal — drop the packet,
/// keep the thread).
///
/// `writer(len)` performs one `write(fd, buf, len)` and returns its raw result
/// (mirroring `libc::write`: a byte count on success, `-1` with `errno` set on
/// error). It is a seam so the short-count / EINTR / EAGAIN behaviour is
/// unit-testable without a real non-blocking fd.
fn write_packet_atomic_nonblocking<F, W>(
    len: usize,
    mut writer: F,
    mut wait_writable: W,
) -> io::Result<()>
where
    F: FnMut(usize) -> isize,
    W: FnMut(),
{
    let mut wouldblock_retries: u32 = 0;
    loop {
        let rc = writer(len);
        if rc < 0 {
            let err = io::Error::last_os_error();
            match err.kind() {
                io::ErrorKind::Interrupted => {
                    // Interrupted before any byte transferred; retry the whole
                    // packet from offset 0. Does NOT consume the WouldBlock
                    // budget (a distinct, non-backpressure condition).
                    continue;
                }
                io::ErrorKind::WouldBlock => {
                    // Non-blocking fd backpressure: the TUN queue is full right
                    // now. Retry the WHOLE packet — never a partial offset.
                    // Bounded so a wedged device cannot spin forever.
                    wouldblock_retries += 1;
                    if wouldblock_retries > NONBLOCK_WOULDBLOCK_RETRY_BUDGET {
                        return Err(io::Error::from_raw_os_error(WOULDBLOCK_EXHAUSTED_ERRNO));
                    }
                    // #7174 M05: WAIT for the device instead of asking it again
                    // immediately. This arm used to be a bare `continue`, so a
                    // full TUN queue produced up to
                    // NONBLOCK_WOULDBLOCK_RETRY_BUDGET back-to-back EAGAIN
                    // syscalls before the packet was dropped — a tight spin
                    // burning a core under sustained backpressure, and doing it
                    // once per dropped packet.
                    //
                    // The wait is INJECTED rather than done here because this
                    // function is deliberately fd-free so it can be unit-tested
                    // without a real non-blocking device (#2438). Keeping that
                    // property is why it is a second closure and not a poll()
                    // call: a test supplies a counting no-op and can assert the
                    // wait actually happened, which a poll buried in here could
                    // not be asked about.
                    wait_writable();
                    continue;
                }
                _ => return Err(err),
            }
        }
        let n = rc as usize;
        if n == len {
            return Ok(());
        }
        // A short or zero count on a packet device: the packet cannot be
        // resumed (re-writing bytes[n..] would inject a corrupt packet), so
        // drop it. Unexpected for a valid TUN write — dropping avoids
        // corrupting the device stream (the #2438 / #2407 corruption). Use
        // EMSGSIZE so the caller classifies it as a non-fatal per-packet
        // rejection (drop + count), never as fatal fd death.
        return Err(io::Error::from_raw_os_error(libc::EMSGSIZE));
    }
}

/// Write one whole packet to a NON-BLOCKING TUN fd (#2438), wrapping
/// `write_packet_atomic_nonblocking` around a real `libc::write`. Used by the
/// WG decap inner-delivery path (`coordinator/wg_control/dispatch.rs`) and the
/// GRE local-origin delivery path (`tunnel.rs`), both of which open their TUN
/// `O_NONBLOCK`.
/// Replaces std `Write::write_all`, whose stream-resume loop corrupts a packet
/// device on a short count.
pub(crate) fn write_packet_nonblocking(fd: i32, bytes: &[u8]) -> io::Result<()> {
    write_packet_atomic_nonblocking(
        bytes.len(),
        |buf_len| {
            // SAFETY: `bytes` is a valid slice for `buf_len` bytes; `fd` is the
            // TUN fd owned by the caller's thread. Always writes from offset 0
            // — a TUN write is one packet, never a partial-offset resubmit.
            unsafe { libc::write(fd, bytes.as_ptr().cast::<libc::c_void>(), buf_len) }
        },
        || {
            // #7174 M05: block briefly until the device can accept a write,
            // instead of re-asking immediately. POLLOUT is the primitive that
            // answers exactly the question EAGAIN raised.
            //
            // The slice is deliberately SHORT (1 ms). The retry budget bounds
            // the number of waits, so the slice bounds the worst case a wedged
            // device can cost this delivery thread — 1 ms x budget — and a
            // longer slice would trade a CPU-burn problem for a
            // head-of-line-blocking one. Under real backpressure the kernel
            // routing stack drains the TUN in far less than a slice, so the
            // common case returns immediately and adds no latency.
            //
            // A poll error is deliberately ignored: it degrades to the previous
            // immediate-retry behaviour, which is bounded by the same budget, so
            // there is nothing safer to do here than try the write again.
            let mut pfd = libc::pollfd {
                fd,
                events: libc::POLLOUT,
                revents: 0,
            };
            // SAFETY: `pfd` is a valid, initialised pollfd for the caller-owned
            // fd; poll does not retain the pointer.
            unsafe { libc::poll(&mut pfd, 1, NONBLOCK_WOULDBLOCK_POLL_SLICE_MS) };
        },
    )
}

pub(crate) fn open_tun(name: &str) -> Result<(std::fs::File, String), String> {
    open_tun_with_flags(name, false)
}

fn open_tun_with_flags(
    name: &str,
    multi_queue: bool,
) -> Result<(std::fs::File, String), String> {
    // O_CLOEXEC so the TUN fd is NOT inherited by any child process xpfd execs
    // (frr-reload, ip, sysctl helpers, etc.) — a leaked TUN fd in a child both
    // wastes a descriptor and pins the device open past helper exit (#2480).
    let tun = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_CLOEXEC)
        .open("/dev/net/tun")
        .map_err(|e| format!("open /dev/net/tun: {e}"))?;
    let flags = IFF_TUN | IFF_NO_PI | if multi_queue { IFF_MULTI_QUEUE } else { 0 };
    let mut ifr = IfReq::new(name, flags)?;
    let rc = unsafe { libc::ioctl(tun.as_raw_fd(), TUNSETIFF, &mut ifr) };
    if rc < 0 {
        return Err(format!(
            "TUNSETIFF {}: {}",
            name,
            io::Error::last_os_error()
        ));
    }
    let actual_name = ifr.name_string();
    set_if_up(&actual_name)?;
    // Slow-path injected IPv4 replies arrive on the TUN device, but their
    // reverse route still points at the real egress interface. Disable
    // per-device rp_filter so the kernel accepts those packets.
    set_ipv4_sysctl(&actual_name, "rp_filter", "0")?;
    // The kernel computes the effective rp_filter as max(conf/all, conf/dev).
    // Do not mutate the host-global knob; emit the existing bringup warning.
    let all_rpf = read_all_rp_filter(ALL_RP_FILTER_PATH);
    if let Some(line) = rp_filter_all_warning(&actual_name, all_rpf) {
        eprintln!("{line}");
    }
    Ok((tun, actual_name))
}

/// Production default path to the host-global IPv4 reverse-path-filter sysctl.
/// `read_all_rp_filter` takes the path as a parameter, so tests pass their own
/// temp-file path directly; this constant is only the live-`/proc` default that
/// `open_tun` reads.
const ALL_RP_FILTER_PATH: &str = "/proc/sys/net/ipv4/conf/all/rp_filter";

/// Read the integer value of `conf/all/rp_filter` from `path`. Returns `None`
/// if the file is missing or unparsable (treated as "cannot determine, do not
/// warn") so a read failure never produces a spurious warning.
fn read_all_rp_filter(path: &str) -> Option<i32> {
    let raw = std::fs::read_to_string(path).ok()?;
    raw.trim().parse::<i32>().ok()
}

/// Decide whether to warn that a non-zero conf/all/rp_filter will drop
/// slow-path reinjection.
///
/// The kernel uses max(conf/all/rp_filter, conf/<dev>/rp_filter), so a non-zero
/// conf/all/rp_filter defeats reverse-path acceptance on the slow-path TUN
/// regardless of the per-device value. The message states the hazard from the
/// all-knob directly (it does NOT assert that the per-device 0 was written), so
/// it is accurate whether or not the per-device write succeeded. Returns
/// `Some(warning_line)` when `all_rpf` is a known non-zero value, `None` when
/// it is 0 or unknown. Seamed (takes the already-read value) so it is
/// unit-testable without touching live /proc.
fn rp_filter_all_warning(dev: &str, all_rpf: Option<i32>) -> Option<String> {
    match all_rpf {
        Some(v) if v != 0 => Some(format!(
            "xpf-ha: WARNING net.ipv4.conf.all.rp_filter={v} is non-zero; the \
             kernel uses max(all,dev) so slow-path reinjected IPv4 packets on \
             TUN {dev} will be SILENTLY DROPPED until \
             'sysctl -w net.ipv4.conf.all.rp_filter=0' is set (#2378)"
        )),
        _ => None,
    }
}

/// Run an ioctl on `sock`, capture its errno, THEN close `sock` (#2479).
///
/// Returns `(ioctl_rc, ioctl_err, close_rc)`. The ioctl's `io::Error` is
/// captured BEFORE `close()` runs, so a caller reporting `ioctl_err` always
/// sees the ioctl's failure — never the errno a failing `close()` would leave
/// behind. The fd is always closed (no leak) even when the ioctl failed.
///
/// `ioctl_fn` receives the fd and must return the raw ioctl return code; the
/// thread-local errno it leaves is what gets captured.
#[inline]
fn ioctl_then_close(
    sock: libc::c_int,
    ioctl_fn: impl FnOnce(libc::c_int) -> libc::c_int,
) -> (libc::c_int, io::Error, libc::c_int) {
    let rc = ioctl_fn(sock);
    // Capture immediately, before close() can touch errno.
    let err = io::Error::last_os_error();
    let close_rc = unsafe { libc::close(sock) };
    (rc, err, close_rc)
}

fn set_if_up(name: &str) -> Result<(), String> {
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if sock < 0 {
        return Err(format!(
            "open control socket: {}",
            io::Error::last_os_error()
        ));
    }
    let mut ifr = IfReq::new(name, 0)?;
    let get_rc = unsafe { libc::ioctl(sock, libc::SIOCGIFFLAGS, &mut ifr) };
    if get_rc < 0 {
        let err = io::Error::last_os_error();
        unsafe { libc::close(sock) };
        return Err(format!("SIOCGIFFLAGS {}: {err}", name));
    }
    let flags = unsafe { ifr.ifru.flags } | (libc::IFF_UP as libc::c_short);
    ifr.ifru.flags = flags;
    // #2479: capture the ioctl's errno BEFORE close(). close() is a syscall
    // that can overwrite thread-local errno (success leaves it untouched per
    // POSIX, but a failing close sets EBADF), so reading last_os_error() after
    // close risks reporting close's errno, not the ioctl's failure. The seam
    // captures-then-closes in one place; mirrors the SIOCGIFFLAGS
    // capture-before-close above.
    let (set_rc, set_err, close_rc) =
        ioctl_then_close(sock, |s| unsafe { libc::ioctl(s, libc::SIOCSIFFLAGS, &ifr) });
    if set_rc < 0 {
        return Err(format!("SIOCSIFFLAGS {}: {}", name, set_err));
    }
    if close_rc < 0 {
        return Err(format!(
            "close control socket: {}",
            io::Error::last_os_error()
        ));
    }
    Ok(())
}

/// Program the MTU on a TUN device via `SIOCSIFMTU` (#2408).
///
/// `mtu` must be > 0; a non-positive value is a programming error and is
/// rejected without touching the device. Returns `Err` (caller logs and
/// continues) on socket/ioctl failure.
pub(crate) fn set_if_mtu(name: &str, mtu: i32) -> Result<(), String> {
    if mtu <= 0 {
        return Err(format!("invalid MTU {mtu} for {name}"));
    }
    // Build the ifreq BEFORE opening the socket so an invalid-name early
    // return does not leak the control-socket fd (Copilot #2439).
    let mut ifr = IfReq::new(name, 0)?;
    ifr.ifru.mtu = mtu as libc::c_int;
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if sock < 0 {
        return Err(format!(
            "open control socket: {}",
            io::Error::last_os_error()
        ));
    }
    // #2479: capture the ioctl's errno BEFORE close() via the shared seam
    // (see set_if_up). A failing close() would otherwise clobber errno and we
    // would report close's failure instead of the ioctl's.
    let (set_rc, set_err, close_rc) =
        ioctl_then_close(sock, |s| unsafe { libc::ioctl(s, libc::SIOCSIFMTU, &ifr) });
    if set_rc < 0 {
        return Err(format!("SIOCSIFMTU {} mtu={}: {}", name, mtu, set_err));
    }
    if close_rc < 0 {
        return Err(format!(
            "close control socket: {}",
            io::Error::last_os_error()
        ));
    }
    Ok(())
}

fn set_ipv4_sysctl(iface: &str, key: &str, value: &str) -> Result<(), String> {
    let path = format!("/proc/sys/net/ipv4/conf/{iface}/{key}");
    std::fs::write(&path, value).map_err(|e| format!("write {path}: {e}"))
}

#[repr(C)]
union Ifru {
    flags: libc::c_short,
    _addr: libc::sockaddr,
    _ifindex: libc::c_int,
    mtu: libc::c_int,
}

#[repr(C)]
struct IfReq {
    ifr_name: [libc::c_char; libc::IFNAMSIZ],
    ifru: Ifru,
}

impl IfReq {
    fn new(name: &str, flags: libc::c_short) -> Result<Self, String> {
        let mut ifr = Self {
            ifr_name: [0; libc::IFNAMSIZ],
            ifru: Ifru { flags },
        };
        let bytes = name.as_bytes();
        if bytes.is_empty() || bytes.len() >= libc::IFNAMSIZ {
            return Err(format!("invalid interface name {}", name));
        }
        for (idx, byte) in bytes.iter().enumerate() {
            ifr.ifr_name[idx] = *byte as libc::c_char;
        }
        Ok(ifr)
    }

    fn name_string(&self) -> String {
        let len = self
            .ifr_name
            .iter()
            .position(|c| *c == 0)
            .unwrap_or(self.ifr_name.len());
        self.ifr_name[..len]
            .iter()
            .map(|c| *c as u8)
            .collect::<Vec<_>>()
            .into_iter()
            .map(char::from)
            .collect()
    }
}

#[cfg(test)]
#[path = "slowpath_tests.rs"]
mod tests;
