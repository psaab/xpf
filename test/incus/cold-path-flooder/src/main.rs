// #1607 / #1611 cold-path-flooder — runner body
//
// Generates UDP traffic with randomized source IPs, source ports,
// and (optionally) destination ports against the loss userspace
// cluster firewall. AF_PACKET SOCK_RAW + sendmmsg(batch=32) with
// PACKET_QDISC_BYPASS for sustained ≥2.5 Mpps single-core on
// virtio-VM hosts (per #1611 plan v4 §4.5 + AGY r1 finding 2).
//
// Two regimes:
//   * `--cohort=unbounded` (DEFAULT, AGY r3 axis 1): sweeps /16
//     src-IP × full 16-bit src-port = ~4.3 B unique 5-tuples.
//     Session table fills in ~26 ms; remaining ~99.9% measures
//     the pure policy-eval cold path
//     (cache_miss → policy_eval → install_rejected_fast_return),
//     cross-worker replicate bypassed.
//   * `--cohort=bounded` (DIAGNOSTIC opt-in): fits the session
//     table (DEFAULT_MAX_SESSIONS = 131_072). Every cold-path
//     sample measures real session miss → install → replicate.
//
// True 64 B Ethernet frames: 14 (Eth) + 20 (IPv4) + 8 (UDP) +
// 22 (payload) = 64.
//
// Per #1611 plan v4 the runner runs on `loss:cluster-userspace-host`
// (LAN-side neighbour) and the AF_PACKET TX traffic arrives at the
// firewall's AF_XDP RX socket via normal Ethernet — AF_PACKET TX
// and AF_XDP RX live on independent kernel paths on the two ends.

#![deny(unsafe_op_in_unsafe_fn)]

use std::ffi::CString;
#[cfg(test)]
use std::fs;
use std::mem::{size_of, zeroed};
use std::net::Ipv4Addr;
use std::os::raw::c_void;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const MIN_ETH_FRAME: usize = 64;
const DEFAULT_DURATION_SECS: u64 = 30;
const DEFAULT_WARMUP_SECS: u64 = 2;
const DEFAULT_BATCH: usize = 32;
// Bounded-mode constants — see step-1 #1613 commit msg + plan v2-r4 §4.2.0.
const BOUNDED_SRC_IP_SPAN: u32 = 16_384; // 14 bits
const BOUNDED_SRC_PORT_SPAN: u32 = 8; // 3 bits
const BOUNDED_DST_PORT_SPAN: u32 = 1;
// Unbounded mode defaults — sweeps a full /16 + full 16-bit source-port
// space. 65_536 × 65_536 × 1 = 4_294_967_296 unique 5-tuples.
const DEFAULT_SRC_IP_SPAN: u32 = 65_536;
// Reserved-port-0 avoidance: per #1611 plan §4 + AGY r3 step-2 minor 2,
// userspace-dp/src/afxdp/frame/inspect.rs:207 short-circuits TCP/UDP
// flows with src_port==0 onto a different code path, which would skew
// the cold-path histogram. Default src-port base = 1024 (start of
// ephemeral range). `--src-port-base 0` is permitted opt-in.
const DEFAULT_SRC_PORT_BASE: u16 = 1024;
// Default src-port span = 65_536 - DEFAULT_SRC_PORT_BASE = 64_512. This
// is the largest span that, combined with the default base, keeps every
// generated port in [1024, 65_536) — guaranteed > 0, no u16 wrap. When
// the operator passes `--src-port-base 0` explicitly, they can also pass
// `--src-port-span 65536` to get the full /16. The validator rejects
// base + span > 65_536 either way.
const DEFAULT_SRC_PORT_SPAN: u32 = 64_512;
const DEFAULT_DST_PORT_SPAN: u32 = 1;
const DEFAULT_DST_PORT_BASE: u16 = 5201;

// #1615 multi-thread defaults. Per plan-v4.md §3.1 the MAX_THREADS hard
// cap with --allow-oversubscribe is 64; without the flag it is min(64,
// allowed_cpus.len()) measured at startup. DEFAULT_THREADS preserves
// the #1611 single-thread baseline when --threads is omitted.
const DEFAULT_THREADS: u32 = 1;
const MAX_THREADS_HARD_CAP: u32 = 64;
// Golden-ratio mixing constant for per-thread RNG seed derivation
// (AGY r1 finding 4 + Codex r1 CODEX-4). The seed=0 fallback constant
// 0xA5A5_..._A5A5 is a known xorshift64-safe non-degenerate state.
const PER_THREAD_SEED_MIX: u64 = 0x9E37_79B9_7F4A_7C15;
const PER_THREAD_SEED_ZERO_FALLBACK: u64 = 0xA5A5_A5A5_A5A5_A5A5;

// Frame layout constants — plan v4 §4 frame assembly.
const ETH_HDR: usize = 14;
const IPV4_HDR: usize = 20;
const UDP_HDR: usize = 8;
const UDP_PAYLOAD: usize = 22; // "XPF-COLD-PATH-MIN64\n\0\0"
const FRAME_V4_TOTAL: usize = ETH_HDR + IPV4_HDR + UDP_HDR + UDP_PAYLOAD;
const IPV4_TOTAL_LEN: u16 = (IPV4_HDR + UDP_HDR + UDP_PAYLOAD) as u16; // 50
const UDP_LEN: u16 = (UDP_HDR + UDP_PAYLOAD) as u16; // 30

// Compile-time wire-byte invariants — plan v4 §4 + hidden-invariants §2.
const _: () = assert!(FRAME_V4_TOTAL == 64);
const _: () = assert!(IPV4_TOTAL_LEN == 50);
const _: () = assert!(UDP_LEN == 30);
// Bounded cohort exactly fits DEFAULT_MAX_SESSIONS.
const _: () = assert!(
    BOUNDED_SRC_IP_SPAN as usize
        * BOUNDED_SRC_PORT_SPAN as usize
        * BOUNDED_DST_PORT_SPAN as usize
        == 131_072
);

// PACKET_QDISC_BYPASS constant — not exposed by every libc version,
// so define locally. Value 20 from include/uapi/linux/if_packet.h.
const PACKET_QDISC_BYPASS_OPT: libc::c_int = 20;

// Magic payload to make the 22-byte UDP payload easy to spot in
// pcap. Plan v4 §4 frame assembly.
const PAYLOAD_MAGIC: [u8; UDP_PAYLOAD] = *b"XPF-COLD-PATH-MIN64\n\0\0";

#[derive(Debug, Clone)]
struct Args {
    iface: String,
    dst_mac: [u8; 6],
    src_mac: [u8; 6],
    dst_ip: Ipv4Addr,
    dst_port_base: u16,
    dst_port_span: u32,
    src_ip_base: u32,
    src_ip_span: u32,
    src_port_base: u16,
    src_port_span: u32,
    duration: Duration,
    warmup: Duration,
    frame_bytes: usize,
    batch: usize,
    seed: u64,
    cohort_unbounded: bool,
    // #1615 multi-thread fields.
    threads: u32,
    cpu_base: u32,
    no_cpu_pin: bool,
    allow_oversubscribe: bool,
}

impl Args {
    fn parse() -> Result<Self, String> {
        let mut args = Args {
            iface: "ge-0-0-1".to_string(),
            dst_mac: [0xff; 6],
            src_mac: [0; 6],
            dst_ip: Ipv4Addr::new(172, 16, 80, 200),
            dst_port_base: DEFAULT_DST_PORT_BASE,
            dst_port_span: DEFAULT_DST_PORT_SPAN,
            src_ip_base: u32::from_be_bytes([10, 42, 0, 0]),
            src_ip_span: DEFAULT_SRC_IP_SPAN,
            src_port_base: DEFAULT_SRC_PORT_BASE,
            src_port_span: DEFAULT_SRC_PORT_SPAN,
            duration: Duration::from_secs(DEFAULT_DURATION_SECS),
            warmup: Duration::from_secs(DEFAULT_WARMUP_SECS),
            frame_bytes: MIN_ETH_FRAME,
            batch: DEFAULT_BATCH,
            seed: 0,
            cohort_unbounded: true,
            threads: DEFAULT_THREADS,
            cpu_base: 0,
            no_cpu_pin: false,
            allow_oversubscribe: false,
        };
        // Track explicit overrides so --cohort=bounded knows whether to narrow.
        let mut user_set_src_ip_span = false;
        let mut user_set_src_port_span = false;
        let mut user_set_dst_port_span = false;

        let argv: Vec<String> = std::env::args().skip(1).collect();
        let mut i = 0;
        while i < argv.len() {
            let arg = &argv[i];
            let next = || argv.get(i + 1).cloned().ok_or(format!("{} needs value", arg));
            match arg.as_str() {
                "--iface" => {
                    args.iface = next()?;
                    i += 2;
                }
                "--dst-ip" => {
                    args.dst_ip = next()?.parse().map_err(|e| format!("bad ip: {e}"))?;
                    i += 2;
                }
                "--dst-port-base" => {
                    args.dst_port_base = next()?.parse().map_err(|e| format!("{e}"))?;
                    i += 2;
                }
                "--dst-port-span" => {
                    args.dst_port_span = next()?.parse().map_err(|e| format!("{e}"))?;
                    user_set_dst_port_span = true;
                    i += 2;
                }
                "--src-ip-base" => {
                    let ip: Ipv4Addr = next()?.parse().map_err(|e| format!("bad ip: {e}"))?;
                    args.src_ip_base = u32::from(ip);
                    i += 2;
                }
                "--src-ip-span" => {
                    args.src_ip_span = next()?.parse().map_err(|e| format!("{e}"))?;
                    user_set_src_ip_span = true;
                    i += 2;
                }
                "--src-port-base" => {
                    args.src_port_base = next()?.parse().map_err(|e| format!("{e}"))?;
                    i += 2;
                }
                "--src-port-span" => {
                    args.src_port_span = next()?.parse().map_err(|e| format!("{e}"))?;
                    user_set_src_port_span = true;
                    i += 2;
                }
                "--duration-secs" => {
                    args.duration =
                        Duration::from_secs(next()?.parse().map_err(|e| format!("{e}"))?);
                    i += 2;
                }
                "--warmup-secs" => {
                    args.warmup =
                        Duration::from_secs(next()?.parse().map_err(|e| format!("{e}"))?);
                    i += 2;
                }
                "--frame-bytes" => {
                    args.frame_bytes = next()?.parse().map_err(|e| format!("{e}"))?;
                    if args.frame_bytes < MIN_ETH_FRAME {
                        return Err(format!(
                            "frame-bytes {} < MIN_ETH_FRAME {}",
                            args.frame_bytes, MIN_ETH_FRAME
                        ));
                    }
                    // For now the runner only emits 64-byte frames.
                    // Larger frames would need payload padding; defer.
                    if args.frame_bytes != MIN_ETH_FRAME {
                        return Err(format!(
                            "--frame-bytes {} not yet supported; \
                             this runner emits exactly 64-byte frames \
                             (follow-up issue tracks variable-size frames)",
                            args.frame_bytes
                        ));
                    }
                    i += 2;
                }
                "--batch" => {
                    args.batch = next()?.parse().map_err(|e| format!("{e}"))?;
                    i += 2;
                }
                "--seed" => {
                    args.seed = next()?.parse().map_err(|e| format!("{e}"))?;
                    i += 2;
                }
                "--dst-mac" => {
                    args.dst_mac = parse_mac(&next()?)?;
                    i += 2;
                }
                "--src-mac" => {
                    args.src_mac = parse_mac(&next()?)?;
                    i += 2;
                }
                "--threads" => {
                    args.threads = next()?.parse().map_err(|e| format!("{e}"))?;
                    i += 2;
                }
                "--cpu-base" => {
                    args.cpu_base = next()?.parse().map_err(|e| format!("{e}"))?;
                    i += 2;
                }
                "--no-cpu-pin" => {
                    args.no_cpu_pin = true;
                    i += 1;
                }
                "--allow-oversubscribe" => {
                    args.allow_oversubscribe = true;
                    i += 1;
                }
                "--cohort" => {
                    let v = next()?;
                    match v.as_str() {
                        "bounded" => args.cohort_unbounded = false,
                        "unbounded" => args.cohort_unbounded = true,
                        _ => return Err(format!("bad --cohort {v}; use bounded|unbounded")),
                    }
                    i += 2;
                }
                "-h" | "--help" => {
                    eprintln!("{}", help());
                    std::process::exit(0);
                }
                _ => return Err(format!("unknown arg: {arg}")),
            }
        }

        // Default is unbounded (AGY r3 axis 1). Narrow when --cohort=bounded.
        if !args.cohort_unbounded {
            if !user_set_src_ip_span {
                args.src_ip_span = BOUNDED_SRC_IP_SPAN;
            }
            if !user_set_src_port_span {
                args.src_port_span = BOUNDED_SRC_PORT_SPAN;
            }
            if !user_set_dst_port_span {
                args.dst_port_span = BOUNDED_DST_PORT_SPAN;
            }
            // Cohort multiplier u128 to avoid u64 overflow at 3×u32::MAX.
            let cohort = args.src_ip_span as u128
                * args.src_port_span as u128
                * args.dst_port_span as u128;
            if cohort > 131_072 {
                return Err(format!(
                    "bounded cohort {} > DEFAULT_MAX_SESSIONS 131072; \
                     either narrow the spans or omit --cohort bounded \
                     (default is unbounded)",
                    cohort
                ));
            }
        }

        validate_args(&args)?;

        if args.seed == 0 {
            // SAFETY: getpid/clock_gettime are always available on Linux.
            let pid = unsafe { libc::getpid() } as u64;
            let mut ts: libc::timespec = unsafe { zeroed() };
            unsafe {
                libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts);
            }
            args.seed = pid
                .wrapping_mul(0x9E3779B97F4A7C15)
                ^ (ts.tv_nsec as u64).wrapping_mul(0xBF58476D1CE4E5B9);
            if args.seed == 0 {
                args.seed = 1;
            }
        }

        Ok(args)
    }
}

/// Validate `--threads` against the allowed cpuset (#1615 plan-v4 §3.1).
/// Returns Ok if threads <= allowed.len() OR allow_oversubscribe is set;
/// returns Err otherwise. The MAX_THREADS_HARD_CAP is enforced
/// unconditionally.
fn validate_threads(threads: u32, allowed_len: usize, allow_oversubscribe: bool) -> Result<(), String> {
    if threads == 0 {
        return Err("--threads must be >= 1".to_string());
    }
    if threads > MAX_THREADS_HARD_CAP {
        return Err(format!(
            "--threads {} exceeds MAX_THREADS_HARD_CAP {}",
            threads, MAX_THREADS_HARD_CAP
        ));
    }
    if threads as usize > allowed_len && !allow_oversubscribe {
        return Err(format!(
            "--threads {} exceeds allowed cpuset size {}; pass \
             --allow-oversubscribe to override (diagnostic only)",
            threads, allowed_len
        ));
    }
    Ok(())
}

/// Per-thread RNG seed derivation. Mixes base_seed with thread_id via
/// the golden-ratio constant; if the result is zero (xorshift64 dead
/// state) falls back to PER_THREAD_SEED_ZERO_FALLBACK.
/// (AGY r1 finding 4 + Codex r1 CODEX-4.)
fn worker_seed(base_seed: u64, thread_id: u32) -> u64 {
    let mixed = base_seed ^ (thread_id as u64).wrapping_mul(PER_THREAD_SEED_MIX);
    if mixed == 0 { PER_THREAD_SEED_ZERO_FALLBACK } else { mixed }
}

/// Query the calling process's allowed CPU set via sched_getaffinity.
/// Returns a Vec of allowed CPU IDs (e.g. [0,1,2,...,15] or a sparse
/// subset in a cgroup-constrained container). #1615 AGY r1 finding
/// AGY-2.
fn allowed_cpu_set() -> Result<Vec<i32>, String> {
    // SAFETY: cpu_set_t is a C-layout array of unsigned longs; zero-init
    // is a valid empty set.
    let mut mask: libc::cpu_set_t = unsafe { zeroed() };
    let rc = unsafe {
        libc::sched_getaffinity(0, size_of::<libc::cpu_set_t>(), &mut mask)
    };
    if rc < 0 {
        return Err(format!(
            "sched_getaffinity failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    let mut allowed: Vec<i32> = Vec::new();
    // CPU_SETSIZE is typically 1024 on glibc. Walk the bitmask.
    for cpu in 0..libc::CPU_SETSIZE {
        // SAFETY: CPU_ISSET on an initialised cpu_set_t with cpu < CPU_SETSIZE.
        if unsafe { libc::CPU_ISSET(cpu as usize, &mask) } {
            allowed.push(cpu);
        }
    }
    if allowed.is_empty() {
        return Err("sched_getaffinity returned empty cpuset".to_string());
    }
    Ok(allowed)
}

/// Centralized arg-validation. Pulled out so unit tests can hit
/// every branch without spoofing argv.
fn validate_args(a: &Args) -> Result<(), String> {
    if a.src_ip_span == 0 {
        return Err("--src-ip-span must be >= 1".to_string());
    }
    if a.src_port_span == 0 {
        return Err("--src-port-span must be >= 1".to_string());
    }
    if a.dst_port_span == 0 {
        return Err("--dst-port-span must be >= 1".to_string());
    }
    if a.batch == 0 {
        return Err("--batch must be >= 1".to_string());
    }
    if a.batch > 1024 {
        return Err(format!(
            "--batch {} > 1024 (UIO_MAXIOV); keep batch <= 1024",
            a.batch
        ));
    }
    // AGY r3 step-2 minor 1: dst_port_base + dst_port_span <= 65536.
    if a.dst_port_base as u32 + a.dst_port_span > 65_536 {
        return Err(format!(
            "--dst-port-base {} + --dst-port-span {} > 65536; \
             generated dst port would silently u16-wrap into reserved \
             range. Narrow the span or lower the base.",
            a.dst_port_base, a.dst_port_span
        ));
    }
    // Same overflow guard for src ports.
    if a.src_port_base as u32 + a.src_port_span > 65_536 {
        return Err(format!(
            "--src-port-base {} + --src-port-span {} > 65536; \
             generated src port would silently u16-wrap. Narrow the \
             span or lower the base.",
            a.src_port_base, a.src_port_span
        ));
    }
    Ok(())
}

fn help() -> &'static str {
    "cold-path-flooder — #1607/#1611 cold-path measurement helper

USAGE:
  cold-path-flooder [OPTIONS]

OPTIONS:
  --iface NAME            (default ge-0-0-1)
  --dst-ip IP             (default 172.16.80.200)
  --dst-mac MAC           (required; no ARP-resolve in this runner)
  --src-mac MAC           (default auto-resolved from iface via SIOCGIFHWADDR)
  --dst-port-base N       (default 5201; iperf-a class)
  --dst-port-span N       (default 1)
  --src-ip-base IP        (default 10.42.0.0)
  --src-ip-span N         (default 65536; bounded: 16384)
  --src-port-base N       (default 1024; --src-port-base 0 opts into reserved-port-0 sweep)
  --src-port-span N       (default 64512 = 65536-base; bounded: 8)
  --duration-secs N       (default 30)
  --warmup-secs N         (default 2)
  --frame-bytes N         (default 64; only 64 supported in this runner)
  --batch N               (sendmmsg batch; default 32; min 1 max 1024)
  --seed N                (default: pid XOR clock)
  --cohort bounded|unbounded   (default unbounded)
  --threads N             (default 1; #1615 multi-thread; <=64; hard-error if > cpuset unless --allow-oversubscribe)
  --cpu-base K            (default 0; index into allowed cpuset; worker T pins to allowed[(cpu_base+T) % allowed.len()])
  --no-cpu-pin            (skip pthread_setaffinity_np; useful for diagnostic runs; not comparable to #1611 baseline)
  --allow-oversubscribe   (permit --threads N > allowed cpuset size; diagnostic only — do NOT use for smoke gate runs)
"
}

fn parse_mac(s: &str) -> Result<[u8; 6], String> {
    let parts: Vec<_> = s.split(':').collect();
    if parts.len() != 6 {
        return Err(format!("bad MAC {s}"));
    }
    let mut out = [0u8; 6];
    for (i, p) in parts.iter().enumerate() {
        out[i] = u8::from_str_radix(p, 16).map_err(|e| format!("{e}"))?;
    }
    Ok(out)
}

/// 64-bit xorshift PRNG. Maximum-period (2^64 - 1).
#[derive(Clone, Copy)]
struct Xorshift64(u64);

impl Xorshift64 {
    #[inline(always)]
    fn next(&mut self) -> u64 {
        let mut s = self.0;
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        self.0 = s;
        s
    }
}

/// One transmit slot — a 64-byte frame + the iovec/msghdr that points at it.
/// `#[repr(align(64))]` per AGY r1 finding D — cache-line aligned for the
/// kernel copy path on the sendmmsg fast path.
#[repr(align(64))]
struct TxSlot {
    frame: [u8; FRAME_V4_TOTAL],
}

impl TxSlot {
    fn new() -> Self {
        TxSlot {
            frame: [0u8; FRAME_V4_TOTAL],
        }
    }

    /// Initialise the static parts of the frame (dst MAC, src MAC, ethertype,
    /// IPv4 fixed fields, UDP payload). Variable fields (src IP, src/dst port,
    /// IPv4 csum, IPv4 ID) are mutated per packet.
    fn init_static(&mut self, dst_mac: &[u8; 6], src_mac: &[u8; 6], dst_ip: Ipv4Addr) {
        // Eth header
        self.frame[0..6].copy_from_slice(dst_mac);
        self.frame[6..12].copy_from_slice(src_mac);
        self.frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes()); // IPv4

        // IPv4 header (will fill mutable fields per-packet)
        self.frame[14] = 0x45; // v=4, ihl=5
        self.frame[15] = 0x00; // tos
        self.frame[16..18].copy_from_slice(&IPV4_TOTAL_LEN.to_be_bytes()); // total_len = 50
        self.frame[18..20].copy_from_slice(&0u16.to_be_bytes()); // id (mutated)
        self.frame[20..22].copy_from_slice(&0x4000u16.to_be_bytes()); // flags=DF, frag_off=0
        self.frame[22] = 64; // ttl
        self.frame[23] = 17; // proto = UDP
        self.frame[24..26].copy_from_slice(&0u16.to_be_bytes()); // csum (mutated)
        self.frame[26..30].copy_from_slice(&[0; 4]); // src ip (mutated)
        self.frame[30..34].copy_from_slice(&u32::from(dst_ip).to_be_bytes());

        // UDP header
        self.frame[34..36].copy_from_slice(&0u16.to_be_bytes()); // src port (mutated)
        self.frame[36..38].copy_from_slice(&0u16.to_be_bytes()); // dst port (mutated)
        self.frame[38..40].copy_from_slice(&UDP_LEN.to_be_bytes()); // len = 30
        self.frame[40..42].copy_from_slice(&0u16.to_be_bytes()); // csum = 0 per RFC 768

        // UDP payload — fixed magic.
        self.frame[42..64].copy_from_slice(&PAYLOAD_MAGIC);
    }

    /// Mutate per-packet fields: src IP, IPv4 ID, src port, dst port.
    /// Recompute the IPv4 header checksum.
    #[inline(always)]
    fn fill_packet(
        &mut self,
        src_ip: u32,
        ip_id: u16,
        src_port: u16,
        dst_port: u16,
    ) {
        // IPv4 ID
        self.frame[18..20].copy_from_slice(&ip_id.to_be_bytes());
        // IPv4 csum field zero before computing
        self.frame[24..26].copy_from_slice(&0u16.to_be_bytes());
        // IPv4 src
        self.frame[26..30].copy_from_slice(&src_ip.to_be_bytes());
        // UDP src/dst port
        self.frame[34..36].copy_from_slice(&src_port.to_be_bytes());
        self.frame[36..38].copy_from_slice(&dst_port.to_be_bytes());

        // IPv4 header checksum (one's-complement, RFC 1071).
        let mut sum: u32 = 0;
        let hdr = &self.frame[14..34]; // 20 bytes
        for chunk in hdr.chunks_exact(2) {
            sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        }
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        let csum = (!sum as u16).to_be_bytes();
        self.frame[24..26].copy_from_slice(&csum);
    }
}

/// Per-iteration runner state. `slots` and `iovecs` are stable-address heap
/// allocations sized once at startup; `msgs` references the iovecs by raw
/// pointer. Lifetime: all three live for the entire run; nothing is freed
/// or resized in the hot loop.
struct TxRing {
    slots: Vec<TxSlot>,
    iovecs: Vec<libc::iovec>,
    msgs: Vec<libc::mmsghdr>,
    dst_sll: libc::sockaddr_ll,
}

// SAFETY: TxRing contains two classes of raw pointers in its `msgs`
// field:
//   1. `msg_hdr.msg_iov` -> `&iovecs[i]`: iovecs is a Vec, so its
//      backing storage lives at a heap-stable address; Vec move
//      does NOT relocate the underlying buffer, so these pointers
//      stay valid across struct moves.
//   2. `msg_hdr.msg_name` -> `&self.dst_sll`: dst_sll is an INLINE
//      field of TxRing. Moving TxRing relocates dst_sll. This means
//      `wire_msgs()` MUST be invoked at the TxRing's final stack
//      location — calling wire_msgs() before a subsequent move
//      leaves dangling pointers in msg_name and sendmmsg dereferences
//      a relocated stack frame. Caller contract (enforced by
//      run_multi_threaded + worker_loop): TxRing is moved into the
//      worker closure → moved into worker_loop's stack frame →
//      `ctx.ring.wire_msgs()` is then called as the worker's second
//      action (after pin) at the final memory location. No move
//      occurs after wire_msgs in the worker. (CODEX code-r1 finding
//      1; AGY impl-r1 finding 1+2.)
//
// We construct + use TxRing within a single thread (the worker),
// so there is no cross-thread aliasing concern.
unsafe impl Send for TxRing {}

impl TxRing {
    fn new(batch: usize, dst_mac: &[u8; 6], src_mac: &[u8; 6], dst_ip: Ipv4Addr,
           ifindex: i32) -> Self {
        let mut slots: Vec<TxSlot> = (0..batch).map(|_| TxSlot::new()).collect();
        for s in &mut slots {
            s.init_static(dst_mac, src_mac, dst_ip);
        }
        // Construct the sockaddr_ll once; sendmmsg per-msg msg_name points at it.
        // SAFETY: sockaddr_ll is a C-layout POD struct; zero-init is valid
        // before we populate sll_family / sll_protocol / sll_ifindex below.
        let mut sll: libc::sockaddr_ll = unsafe { zeroed() };
        sll.sll_family = libc::AF_PACKET as u16;
        sll.sll_protocol = (libc::ETH_P_IP as u16).to_be();
        sll.sll_ifindex = ifindex;
        sll.sll_halen = 6;
        sll.sll_addr[..6].copy_from_slice(dst_mac);

        // Construct iovecs pointing at each frame.
        let iovecs: Vec<libc::iovec> = slots
            .iter_mut()
            .map(|s| libc::iovec {
                iov_base: s.frame.as_mut_ptr() as *mut c_void,
                iov_len: FRAME_V4_TOTAL,
            })
            .collect();

        TxRing {
            slots,
            iovecs,
            msgs: Vec::with_capacity(batch),
            dst_sll: sll,
        }
    }

    /// Wire the mmsghdr array. Called once after `new()` so the
    /// iovec / sockaddr pointers stay stable for the entire run.
    fn wire_msgs(&mut self) {
        let sll_ptr = (&self.dst_sll) as *const _ as *mut c_void;
        let sll_len = size_of::<libc::sockaddr_ll>() as u32;
        self.msgs.clear();
        for iov in &mut self.iovecs {
            // SAFETY: msghdr is a C-layout POD struct; zero-init is valid
            // before we populate msg_name / msg_iov below.
            let mut hdr: libc::msghdr = unsafe { zeroed() };
            hdr.msg_name = sll_ptr;
            hdr.msg_namelen = sll_len;
            hdr.msg_iov = iov as *mut libc::iovec;
            hdr.msg_iovlen = 1;
            self.msgs.push(libc::mmsghdr {
                msg_hdr: hdr,
                msg_len: 0,
            });
        }
    }
}

/// Resolve --iface to ifindex; fail loudly on 0 (not found).
/// Claude SMR r1 MINOR-3.
fn resolve_ifindex(iface: &str) -> Result<i32, String> {
    let c = CString::new(iface).map_err(|_| "iface name has nul byte".to_string())?;
    // SAFETY: if_nametoindex takes a NUL-terminated C string; CString
    // guarantees that. Return value 0 sentinel handled below.
    let idx = unsafe { libc::if_nametoindex(c.as_ptr()) };
    if idx == 0 {
        let errno = std::io::Error::last_os_error();
        return Err(format!(
            "interface '{}' not found — check `ip link show` ({})",
            iface, errno
        ));
    }
    Ok(idx as i32)
}

/// Verify the interface is IFF_UP via SIOCGIFFLAGS. AGY r1 finding C.
fn check_iface_up(fd: i32, iface: &str) -> Result<(), String> {
    // SAFETY: ifreq is a C-layout POD union; zero-init is the documented
    // pattern for SIOCGIFFLAGS calls (kernel writes ifr_ifru.ifru_flags).
    let mut ifr: libc::ifreq = unsafe { zeroed() };
    let name_bytes = iface.as_bytes();
    if name_bytes.len() >= libc::IFNAMSIZ {
        return Err(format!("iface '{}' name >= IFNAMSIZ", iface));
    }
    for (i, b) in name_bytes.iter().enumerate() {
        ifr.ifr_name[i] = *b as libc::c_char;
    }
    // SAFETY: ifreq is a kernel-defined union; SIOCGIFFLAGS fills
    // ifr_ifru.ifru_flags. We read it back below via a transmute that
    // is well-defined because libc::ifreq is repr(C).
    let ret = unsafe { libc::ioctl(fd, libc::SIOCGIFFLAGS, &mut ifr) };
    if ret < 0 {
        return Err(format!(
            "SIOCGIFFLAGS on '{}': {}",
            iface,
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: SIOCGIFFLAGS is documented to write ifr_ifru.ifru_flags
    // (man 7 netdevice). We never read any other ifr_ifru variant.
    let flags = unsafe { ifr.ifr_ifru.ifru_flags };
    if (flags as u32 & libc::IFF_UP as u32) == 0 {
        return Err(format!(
            "interface '{}' is DOWN — run 'ip link set {} up' first",
            iface, iface
        ));
    }
    Ok(())
}

/// Read iface hwaddr metadata via SIOCGIFHWADDR.
fn read_iface_hwaddr(fd: i32, iface: &str) -> Result<(u16, [u8; 6]), String> {
    // SAFETY: ifreq is a C-layout POD union; zero-init before SIOCGIFHWADDR.
    let mut ifr: libc::ifreq = unsafe { zeroed() };
    let name_bytes = iface.as_bytes();
    if name_bytes.len() >= libc::IFNAMSIZ {
        return Err(format!("iface '{}' name >= IFNAMSIZ", iface));
    }
    for (i, b) in name_bytes.iter().enumerate() {
        ifr.ifr_name[i] = *b as libc::c_char;
    }
    let ret = unsafe { libc::ioctl(fd, libc::SIOCGIFHWADDR, &mut ifr) };
    if ret < 0 {
        return Err(format!(
            "SIOCGIFHWADDR on '{}': {}",
            iface,
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: SIOCGIFHWADDR writes ifr_hwaddr.sa_family and
    // ifr_hwaddr.sa_data[0..6] (well-defined union access).
    let family = unsafe { ifr.ifr_ifru.ifru_hwaddr.sa_family as u16 };
    let mut mac = [0u8; 6];
    unsafe {
        for i in 0..6 {
            mac[i] = ifr.ifr_ifru.ifru_hwaddr.sa_data[i] as u8;
        }
    }
    Ok((family, mac))
}

/// Read iface MAC via SIOCGIFHWADDR.
fn read_iface_mac(fd: i32, iface: &str) -> Result<[u8; 6], String> {
    read_iface_hwaddr(fd, iface).map(|(_, mac)| mac)
}

fn format_progress_json(
    elapsed: Duration,
    stats: &RunStats,
    prev_emit_stats: &RunStats,
    emit_window: Duration,
) -> String {
    let tx_packets_delta = stats.tx_packets.saturating_sub(prev_emit_stats.tx_packets);
    let tx_batches_delta = stats.tx_batches.saturating_sub(prev_emit_stats.tx_batches);
    let err_eagain_delta = stats.err_eagain.saturating_sub(prev_emit_stats.err_eagain);
    let err_partial_delta = stats.err_partial.saturating_sub(prev_emit_stats.err_partial);
    let err_other_delta = stats.err_other.saturating_sub(prev_emit_stats.err_other);
    let pps = if emit_window.is_zero() {
        0
    } else {
        (tx_packets_delta as f64 / emit_window.as_secs_f64()) as u64
    };
    format!(
        "{{\"t\":{},\"pps\":{},\"tx_packets_delta\":{},\"tx_batches_delta\":{},\"err_eagain_delta\":{},\"err_partial_delta\":{},\"err_other_delta\":{}}}",
        elapsed.as_secs_f64(),
        pps,
        tx_packets_delta,
        tx_batches_delta,
        err_eagain_delta,
        err_partial_delta,
        err_other_delta
    )
}
/// Convert cumulative counters to run-phase counters using a shared
/// warmup snapshot. This keeps every progress field in the same window.
fn progress_stats_since_warmup(stats: &RunStats, baseline: &RunStats) -> RunStats {
    RunStats {
        tx_packets: stats.tx_packets.saturating_sub(baseline.tx_packets),
        tx_batches: stats.tx_batches.saturating_sub(baseline.tx_batches),
        err_eagain: stats.err_eagain.saturating_sub(baseline.err_eagain),
        err_partial: stats.err_partial.saturating_sub(baseline.err_partial),
        err_other: stats.err_other.saturating_sub(baseline.err_other),
        first_other_errno: stats.first_other_errno,
    }
}

#[cfg(test)]
fn select_smoke_test_iface() -> Result<Option<String>, String> {
    match std::env::var("XPF_RAW_SOCKET_TEST_IFACE") {
        Ok(iface) => {
            let iface = iface.trim();
            if iface.is_empty() {
                return Err("XPF_RAW_SOCKET_TEST_IFACE is empty".to_string());
            }
            return Ok(Some(iface.to_string()));
        }
        Err(std::env::VarError::NotPresent) => {}
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err("XPF_RAW_SOCKET_TEST_IFACE is not valid UTF-8".to_string());
        }
    }

    let entries = fs::read_dir("/sys/class/net")
        .map_err(|e| format!("read_dir('/sys/class/net') failed: {}", e))?;
    let mut names: Vec<String> = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| format!("read_dir('/sys/class/net') entry failed: {}", e))?;
        names.push(entry.file_name().to_string_lossy().into_owned());
    }
    names.sort();

    let ethernet_type = libc::ARPHRD_ETHER.to_string();
    for iface in names {
        let hwtype_path = format!("/sys/class/net/{}/type", iface);
        let operstate_path = format!("/sys/class/net/{}/operstate", iface);
        let hwtype = match fs::read_to_string(&hwtype_path) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let operstate = match fs::read_to_string(&operstate_path) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if hwtype.trim() == ethernet_type && operstate.trim() == "up" {
            return Ok(Some(iface));
        }
    }
    Ok(None)
}

/// Open AF_PACKET SOCK_RAW + bind to iface ifindex + enable QDISC_BYPASS +
/// SO_SNDBUF. Returns the fd. Caller drops fd on exit.
fn open_socket(ifindex: i32, frame_bytes: usize, batch: usize) -> Result<i32, String> {
    // SAFETY: socket() is always callable.
    let fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            (libc::ETH_P_IP as u16).to_be() as i32,
        )
    };
    if fd < 0 {
        let errno = std::io::Error::last_os_error();
        if errno.raw_os_error() == Some(libc::EPERM)
            || errno.raw_os_error() == Some(libc::EACCES)
        {
            return Err(format!(
                "socket(AF_PACKET, SOCK_RAW) failed: {} \
                 --- HINT: re-run with sudo or grant CAP_NET_RAW ---",
                errno
            ));
        }
        return Err(format!("socket(AF_PACKET, SOCK_RAW) failed: {}", errno));
    }

    // SO_SNDBUF — try setting; not fatal if it fails.
    let sndbuf: libc::c_int = (frame_bytes * batch * 256) as libc::c_int;
    // SAFETY: setsockopt with valid fd and value pointer.
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_SNDBUF,
            &sndbuf as *const _ as *const c_void,
            size_of::<libc::c_int>() as libc::socklen_t,
        );
    }

    // PACKET_QDISC_BYPASS — plan v4 §4.5 + AGY r1 finding 2. Non-fatal
    // on failure (older kernels) but the smoke gate will catch any
    // resulting throughput shortfall.
    let one: libc::c_int = 1;
    // SAFETY: setsockopt with valid fd and value pointer.
    let bypass_ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_PACKET,
            PACKET_QDISC_BYPASS_OPT,
            &one as *const _ as *const c_void,
            size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if bypass_ret != 0 {
        eprintln!(
            "warning: PACKET_QDISC_BYPASS setsockopt failed: {} \
             (kernel < 3.14?) — continuing through qdisc",
            std::io::Error::last_os_error()
        );
    }

    // Bind to ifindex.
    // SAFETY: sockaddr_ll is a C-layout POD struct; zero-init before
    // populating sll_family / sll_protocol / sll_ifindex below.
    let mut sll: libc::sockaddr_ll = unsafe { zeroed() };
    sll.sll_family = libc::AF_PACKET as u16;
    sll.sll_protocol = (libc::ETH_P_IP as u16).to_be();
    sll.sll_ifindex = ifindex;
    // SAFETY: bind with valid fd, sockaddr_ll pointer, and correct len.
    let ret = unsafe {
        libc::bind(
            fd,
            &sll as *const _ as *const libc::sockaddr,
            size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        let errno = std::io::Error::last_os_error();
        // SAFETY: close on a valid fd.
        unsafe {
            libc::close(fd);
        }
        return Err(format!("bind to ifindex {} failed: {}", ifindex, errno));
    }

    Ok(fd)
}

#[derive(Default, Debug, Clone, Copy)]
struct RunStats {
    tx_packets: u64,
    tx_batches: u64,
    err_eagain: u64,
    err_partial: u64,
    err_other: u64,
    first_other_errno: i32,
}

/// RAII wrapper for an AF_PACKET fd owned by a worker thread. Drop
/// closes once. Main thread does NOT retain a copy after moving the
/// WorkerFd into the worker closure. (#1615 SMR r1 MAJOR-1, Codex r1
/// CODEX-6.)
struct WorkerFd(libc::c_int);

impl WorkerFd {
    fn raw(&self) -> libc::c_int { self.0 }
}

impl Drop for WorkerFd {
    fn drop(&mut self) {
        if self.0 >= 0 {
            // SAFETY: WorkerFd holds exclusive ownership; close once.
            unsafe { libc::close(self.0); }
        }
    }
}

/// Per-thread atomic stats block, cache-line aligned to prevent false
/// sharing between adjacent workers' slots when Vec<Arc<PaddedStats>>
/// is iterated. (#1615 AGY r1 finding AGY-1, Codex r1 CODEX-1, SMR
/// MAJOR-4.) `first_other_errno=0` is the "no error" sentinel since
/// Linux errnos start at 1.
#[repr(align(64))]
struct PaddedStats {
    tx_packets: AtomicU64,
    tx_batches: AtomicU64,
    err_eagain: AtomicU64,
    err_partial: AtomicU64,
    err_other: AtomicU64,
    first_other_errno: AtomicI32,
}

impl PaddedStats {
    fn new() -> Self {
        PaddedStats {
            tx_packets: AtomicU64::new(0),
            tx_batches: AtomicU64::new(0),
            err_eagain: AtomicU64::new(0),
            err_partial: AtomicU64::new(0),
            err_other: AtomicU64::new(0),
            first_other_errno: AtomicI32::new(0),
        }
    }

    fn snapshot(&self) -> RunStats {
        RunStats {
            tx_packets: self.tx_packets.load(Ordering::Relaxed),
            tx_batches: self.tx_batches.load(Ordering::Relaxed),
            err_eagain: self.err_eagain.load(Ordering::Relaxed),
            err_partial: self.err_partial.load(Ordering::Relaxed),
            err_other: self.err_other.load(Ordering::Relaxed),
            first_other_errno: self.first_other_errno.load(Ordering::Relaxed),
        }
    }
}
fn publish_warmup_baseline_if_due(
    now: Instant,
    warmup_end: Instant,
    published: &mut bool,
    stats: &PaddedStats,
    packet_baseline: &AtomicU64,
    batch_baseline: &AtomicU64,
    ready: &AtomicBool,
) {
    if *published || now < warmup_end {
        return;
    }
    packet_baseline.store(stats.tx_packets.load(Ordering::Relaxed), Ordering::Relaxed);
    batch_baseline.store(stats.tx_batches.load(Ordering::Relaxed), Ordering::Relaxed);
    ready.store(true, Ordering::Release);
    *published = true;
}

// PaddedStats must be exactly one cache line so adjacent slots in a
// Vec do not share a cache line with neighbouring workers' atomics.
const _: () = assert!(std::mem::size_of::<PaddedStats>() == 64);

/// Compute per-thread `tx_packets` max/min ratio. For N=1 the ratio is
/// defined as 1.0 (trivially uniform). For N>=2 the ratio is
/// `max / max(min, 1)`. (#1615 plan-v4 §3.7 + AGY r3-3.)
fn per_thread_ratio(per_thread: &[RunStats]) -> f64 {
    if per_thread.len() <= 1 { return 1.0; }
    let mx = per_thread.iter().map(|s| s.tx_packets).max().unwrap_or(0);
    let mn = per_thread.iter().map(|s| s.tx_packets).min().unwrap_or(0);
    mx as f64 / mn.max(1) as f64
}

/// Pin the calling thread to a single CPU id via pthread_setaffinity_np.
/// Called as the worker's first action so main-thread affinity is not
/// mutated. (#1615 plan-v4 §3.3 + SMR MAJOR-2 + Codex r2 CODEX-r2-4.)
fn pin_self_to_cpu(cpu: i32) -> Result<(), String> {
    // SAFETY: cpu_set_t is a C-layout array of unsigned longs; zero-init
    // is a valid empty set.
    let mut mask: libc::cpu_set_t = unsafe { zeroed() };
    // SAFETY: CPU_SET on an initialised mask with cpu < CPU_SETSIZE.
    unsafe { libc::CPU_SET(cpu as usize, &mut mask); }
    // SAFETY: pthread_self() returns the calling thread's pthread_t;
    // pthread_setaffinity_np accepts a stable size and a valid mask
    // pointer.
    let rc = unsafe {
        libc::pthread_setaffinity_np(
            libc::pthread_self(),
            size_of::<libc::cpu_set_t>(),
            &mask,
        )
    };
    if rc != 0 {
        return Err(format!(
            "pthread_setaffinity_np(cpu={}) failed: errno {}",
            cpu, rc
        ));
    }
    Ok(())
}

/// Per-thread context passed into a worker closure. Owns its WorkerFd
/// (RAII close on drop), its PaddedStats publish slot, its seed, and
/// a clone of the shared shutdown_flag + first_fatal_error slot.
/// `start_at` and `total_deadline` define the shared worker run window.
struct WorkerCtx {
    thread_id: u32,
    fd: WorkerFd,
    ring: TxRing,
    seed: u64,
    stats: Arc<PaddedStats>,
    shutdown_flag: Arc<AtomicBool>,
    first_fatal: Arc<Mutex<Option<String>>>,
    pin_cpu: Option<i32>,
    /// All workers wait for the shared start time so their warmup
    /// interval is identical and no packets are sent before it begins.
    start_at: Instant,
    warmup_end: Instant,
    total_deadline: Instant,
    /// Atomic warmup baseline — set by the worker at warmup-end (one
    /// store per worker), read by main at summary time to subtract
    /// warmup work from final tx_packets. (CODEX code-r1 finding 2.)
    warmup_baseline: Arc<AtomicU64>,
    // #7174 C15: the BATCH baseline, captured at the same instant as the packet
    // one. Without it tx_packets was warmup-subtracted while tx_batches stayed
    // cumulative-since-start IN THE SAME RECORD, so packets-per-batch derived
    // from that record was wrong and nothing in it said so.
    warmup_baseline_batches: Arc<AtomicU64>,
    warmup_baseline_ready: Arc<AtomicBool>,
}

/// Total number of unique 5-tuples a run can generate, given the span
/// arguments. u64 is wide enough for the unbounded default (4.29e9).
fn tuple_space(args: &Args) -> u64 {
    (args.src_ip_span as u64)
        * (args.src_port_span as u64)
        * (args.dst_port_span as u64)
}

/// C175-HC-072: the half-open tuple-index slice `[base, end)` that
/// worker `thread_id` of `threads` owns. Slices partition `[0, space)`
/// exactly (floor division; `base_0 = 0`, `base_threads = space`), so no
/// two workers ever emit the same bounded tuple — the cross-worker
/// collision source under the old shared-random scheme.
fn worker_slice(thread_id: u32, threads: u32, space: u64) -> (u64, u64) {
    let n = threads.max(1) as u64;
    let t = thread_id as u64;
    (t * space / n, (t + 1) * space / n)
}

/// C175-HC-072: decompose a monotonic tuple index into its
/// (src_ip_off, src_port_v, dst_port_v) components. Enumerating indices
/// `base..end` visits every distinct tuple in a worker's slice exactly
/// once before wrapping, so the first pass installs a fresh session per
/// packet (a genuine cache_miss -> install -> replicate) instead of the
/// birthday-colliding random draws that measured warm hits. Spans are
/// validated >= 1 (see validate()), so the divisions never trap.
fn decompose_tuple_index(
    idx: u64,
    src_port_span: u32,
    dst_port_span: u32,
) -> (u32, u32, u32) {
    let dsp = dst_port_span as u64;
    let ssp = src_port_span as u64;
    let dst_port_v = (idx % dsp) as u32;
    let tmp = idx / dsp;
    let src_port_v = (tmp % ssp) as u32;
    let src_ip_off = (tmp / ssp) as u32;
    (src_ip_off, src_port_v, dst_port_v)
}

/// Per-worker hot loop. Publishes per-batch deltas into self.stats
/// via fetch_add(Relaxed). Returns Ok on graceful shutdown; the
/// first fatal error (EPERM/EACCES from sendmmsg, pin failure) is
/// recorded into first_fatal and shutdown_flag is set.
fn worker_loop(args: &Args, mut ctx: WorkerCtx) {
    // First action inside the worker thread: pin self to assigned CPU
    // if requested. Pin failure is fatal — sets shutdown_flag so peer
    // workers exit promptly.
    if let Some(cpu) = ctx.pin_cpu {
        if let Err(e) = pin_self_to_cpu(cpu) {
            let msg = format!("worker {} pin failed: {}", ctx.thread_id, e);
            let mut slot = ctx.first_fatal.lock().unwrap();
            if slot.is_none() { *slot = Some(msg.clone()); }
            ctx.shutdown_flag.store(true, Ordering::Relaxed);
            return;
        }
    }

    // Wire the mmsghdr array AFTER ctx has reached its final stack
    // location. wire_msgs() stores a raw pointer to ctx.ring.dst_sll
    // (an inline TxRing field, not heap) into each msghdr.msg_name.
    // If we called wire_msgs before the move into worker_loop, the
    // pointer would dangle after the move and sendmmsg would dereference
    // garbage. (CODEX code-r1 finding 1; AGY impl-r1 finding 1.)
    ctx.ring.wire_msgs();

    let fd = ctx.fd.raw();
    let mut prng = Xorshift64(ctx.seed);
    let mut warmup_baseline_published = false;

    // C175-HC-072: in bounded (diagnostic) mode this worker enumerates a
    // disjoint slice of the tuple space sequentially, so every packet in
    // the first pass over its slice is a genuinely new 5-tuple (real
    // session install), not a birthday-colliding random draw that lands
    // on an already-installed session. Unbounded mode keeps random draws
    // over its ~4.3 B space (session table fills in ~26 ms by design and
    // the rest measures the policy-eval cold path). ip_id stays random in
    // both modes — it is not part of the session key.
    let bounded = !args.cohort_unbounded;
    let (slice_base, slice_end) =
        worker_slice(ctx.thread_id, args.threads, tuple_space(args));
    let mut seq_idx = slice_base;

    while Instant::now() < ctx.start_at {
        if ctx.shutdown_flag.load(Ordering::Relaxed) { return; }
        std::thread::sleep(ctx.start_at.saturating_duration_since(Instant::now()));
    }
    loop {
        let now = Instant::now();
        // Publish the baseline before either shutdown or deadline exits:
        // zero-duration runs and workers awakened at the deadline still
        // need to exclude all warmup traffic from the final summary.
        publish_warmup_baseline_if_due(
            now,
            ctx.warmup_end,
            &mut warmup_baseline_published,
            &ctx.stats,
            &ctx.warmup_baseline,
            &ctx.warmup_baseline_batches,
            &ctx.warmup_baseline_ready,
        );
        if ctx.shutdown_flag.load(Ordering::Relaxed) {
            return;
        }
        if now >= ctx.total_deadline {
            return;
        }

        // Refill all batch slots with fresh tuples.
        for slot in ctx.ring.slots.iter_mut() {
            let s = prng.next();
            let (src_ip_off, src_port_v, dst_port_v) = if bounded {
                // Sequential non-repeating sweep of this worker's slice.
                let (ip_off, sp_v, dp_v) = decompose_tuple_index(
                    seq_idx, args.src_port_span, args.dst_port_span,
                );
                seq_idx += 1;
                // Wrap at the slice end so reuse is deterministic and only
                // begins after a full pass (an honest table refill), never
                // the birthday collisions of shared random draws.
                if seq_idx >= slice_end {
                    seq_idx = slice_base;
                }
                (ip_off, sp_v, dp_v)
            } else {
                (
                    (s as u32) % args.src_ip_span,
                    (s >> 16) as u32 % args.src_port_span,
                    (s >> 32) as u32 % args.dst_port_span,
                )
            };
            let src_port = args.src_port_base.wrapping_add(src_port_v as u16);
            let dst_port = args.dst_port_base.wrapping_add(dst_port_v as u16);
            let src_ip = args.src_ip_base.wrapping_add(src_ip_off);
            let ip_id = (s >> 48) as u16;
            slot.fill_packet(src_ip, ip_id, src_port, dst_port);
        }

        // SAFETY: sendmmsg with the worker's owned mmsghdr array and fd.
        let sent = unsafe {
            libc::sendmmsg(
                fd,
                ctx.ring.msgs.as_mut_ptr(),
                args.batch as libc::c_uint,
                0,
            )
        };

        if sent < 0 {
            let errno = std::io::Error::last_os_error();
            match errno.raw_os_error() {
                Some(libc::EAGAIN) | Some(libc::ENOBUFS) => {
                    ctx.stats.err_eagain.fetch_add(1, Ordering::Relaxed);
                    std::thread::yield_now();
                    continue;
                }
                Some(libc::EINTR) => continue,
                Some(libc::EPERM) | Some(libc::EACCES) => {
                    let msg = format!(
                        "worker {} sendmmsg EPERM/EACCES: {} (hint: CAP_NET_RAW)",
                        ctx.thread_id, errno
                    );
                    let mut slot = ctx.first_fatal.lock().unwrap();
                    if slot.is_none() { *slot = Some(msg); }
                    ctx.shutdown_flag.store(true, Ordering::Relaxed);
                    return;
                }
                Some(code) => {
                    // Record only the first non-recoverable errno via
                    // compare_exchange (0 = "no error" sentinel; Linux
                    // errnos start at 1 so 0 is safe).
                    let _ = ctx.stats.first_other_errno.compare_exchange(
                        0, code, Ordering::AcqRel, Ordering::Relaxed,
                    );
                    ctx.stats.err_other.fetch_add(1, Ordering::Relaxed);
                    std::thread::yield_now();
                    continue;
                }
                None => {
                    let msg = format!(
                        "worker {} sendmmsg -1 without errno: {}",
                        ctx.thread_id, errno
                    );
                    let mut slot = ctx.first_fatal.lock().unwrap();
                    if slot.is_none() { *slot = Some(msg); }
                    ctx.shutdown_flag.store(true, Ordering::Relaxed);
                    return;
                }
            }
        }

        let n = sent as u64;
        ctx.stats.tx_packets.fetch_add(n, Ordering::Relaxed);
        if n as usize == args.batch {
            ctx.stats.tx_batches.fetch_add(1, Ordering::Relaxed);
        } else {
            ctx.stats.err_partial.fetch_add(1, Ordering::Relaxed);
        }
    }
}

fn emit_summary(args: &Args, agg: &RunStats, per_thread: &[RunStats]) {
    let secs = args.duration.as_secs_f64();
    let avg_pps = if secs > 0.0 {
        (agg.tx_packets as f64 / secs) as u64
    } else {
        0
    };
    let src_ip_str: Ipv4Addr = Ipv4Addr::from(args.src_ip_base);
    let ratio = per_thread_ratio(per_thread);

    // Build per-thread JSON array.
    let mut per_thread_json = String::from("[");
    for (i, s) in per_thread.iter().enumerate() {
        if i > 0 { per_thread_json.push(','); }
        let pps = if secs > 0.0 { (s.tx_packets as f64 / secs) as u64 } else { 0 };
        per_thread_json.push_str(&format!(
            "{{\"thread_id\":{},\"tx_packets\":{},\"tx_batches\":{},\
             \"avg_pps\":{},\"err_eagain\":{},\"err_partial\":{},\
             \"err_other\":{},\"first_other_errno\":{}}}",
            i, s.tx_packets, s.tx_batches, pps,
            s.err_eagain, s.err_partial, s.err_other, s.first_other_errno,
        ));
    }
    per_thread_json.push(']');

    println!(
        "{{\"version\":3,\
         \"threads\":{},\
         \"cohort\":\"{}\",\
         \"tuple_space\":{},\
         \"duration_secs\":{},\
         \"warmup_secs\":{},\
         \"frame_bytes\":{},\
         \"batch\":{},\
         \"tx_packets\":{},\
         \"tx_batches\":{},\
         \"avg_pps\":{},\
         \"per_thread_ratio\":{:.3},\
         \"err_eagain\":{},\
         \"err_partial\":{},\
         \"err_other\":{},\
         \"first_other_errno\":{},\
         \"src_ip_base\":\"{}\",\
         \"src_ip_span\":{},\
         \"src_port_base\":{},\
         \"src_port_span\":{},\
         \"dst_ip\":\"{}\",\
         \"dst_port_base\":{},\
         \"dst_port_span\":{},\
         \"seed\":{},\
         \"per_thread\":{},\
         \"clock_source\":\"monotonic\"}}",
        args.threads,
        if args.cohort_unbounded { "unbounded" } else { "bounded" },
        tuple_space(args),
        args.duration.as_secs(),
        args.warmup.as_secs(),
        args.frame_bytes,
        args.batch,
        agg.tx_packets,
        agg.tx_batches,
        avg_pps,
        ratio,
        agg.err_eagain,
        agg.err_partial,
        agg.err_other,
        agg.first_other_errno,
        src_ip_str,
        args.src_ip_span,
        args.src_port_base,
        args.src_port_span,
        args.dst_ip,
        args.dst_port_base,
        args.dst_port_span,
        args.seed,
        per_thread_json,
    );
}

/// Multi-threaded driver — spawns N workers, runs the aggregate
/// progress emitter on the main thread, joins workers, and returns
/// aggregate + per-thread stats. Per plan-v4.md §3.1-3.9.
fn run_multi_threaded(
    args: &Args,
    fds: Vec<WorkerFd>,
    ifindex: i32,
    pin_cpus: Vec<Option<i32>>,
) -> Result<(RunStats, Vec<RunStats>), String> {
    let n = args.threads as usize;
    assert_eq!(fds.len(), n);
    assert_eq!(pin_cpus.len(), n);

    let shutdown_flag = Arc::new(AtomicBool::new(false));
    let first_fatal: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let stats_slots: Vec<Arc<PaddedStats>> =
        (0..n).map(|_| Arc::new(PaddedStats::new())).collect();
    // Per-worker warmup baselines (initialised to 0 == no warmup
    // observed yet; worker writes its baseline at warmup-end).
    let warmup_baselines: Vec<Arc<AtomicU64>> =
        (0..n).map(|_| Arc::new(AtomicU64::new(0))).collect();
    let warmup_baselines_batches: Vec<Arc<AtomicU64>> =
        (0..n).map(|_| Arc::new(AtomicU64::new(0))).collect();
    let warmup_baseline_ready: Vec<Arc<AtomicBool>> =
        (0..n).map(|_| Arc::new(AtomicBool::new(false))).collect();
    // Shared deadlines so every worker uses the same window.
    let start_at = Instant::now() + Duration::from_millis(50);
    let warmup_end = start_at + args.warmup;
    let total_deadline = warmup_end + args.duration;

    let mut handles: Vec<std::thread::JoinHandle<()>> = Vec::with_capacity(n);
    let mut spawn_error: Option<String> = None;

    // Spawn workers. Each consumes its WorkerFd via move. The fds +
    // pin_cpus iterators are consumed in forward order; tid==0 gets
    // fds[0], tid==1 gets fds[1], etc.
    let mut fds_iter = fds.into_iter();
    let mut pins_iter = pin_cpus.into_iter();
    for tid in 0..n {
        // AGY-r4-2: if any previously-spawned worker has already
        // failed (e.g., pin error in thread 0 racing ahead), short-
        // circuit the spawn loop so we don't waste OS resources.
        if shutdown_flag.load(Ordering::Relaxed) {
            spawn_error = Some(format!(
                "spawn loop aborted at thread {} — earlier worker failed",
                tid
            ));
            break;
        }
        let fd = fds_iter.next().unwrap();
        let pin_cpu = pins_iter.next().unwrap();
        let seed = worker_seed(args.seed, tid as u32);
        let ring = TxRing::new(
            args.batch, &args.dst_mac, &args.src_mac, args.dst_ip, ifindex,
        );
        // Note: ring.wire_msgs() must be called *after* the ring is
        // moved into the worker (its msg pointers reference its own
        // iovecs which must keep stable addresses after move). The
        // worker calls wire_msgs() before entering the hot loop.
        let ctx = WorkerCtx {
            thread_id: tid as u32,
            fd,
            ring,
            seed,
            stats: stats_slots[tid].clone(),
            shutdown_flag: shutdown_flag.clone(),
            first_fatal: first_fatal.clone(),
            pin_cpu,
            start_at,
            warmup_end,
            total_deadline,
            warmup_baseline: warmup_baselines[tid].clone(),
            warmup_baseline_batches: warmup_baselines_batches[tid].clone(),
            warmup_baseline_ready: warmup_baseline_ready[tid].clone(),
        };
        let args_owned = args.clone();
        // std::thread::Builder is mandatory (#1615 plan-v4 §3.9 +
        // AGY r3-1 + Codex r3-5): it returns io::Result on spawn
        // failure rather than panicking, so we can rollback.
        let builder = std::thread::Builder::new()
            .name(format!("flooder-{}", tid));
        // NOTE: wire_msgs() is called inside worker_loop AFTER the ctx
        // move into worker_loop's stack frame, so the raw pointer to
        // ctx.ring.dst_sll points at the final stack location.
        // (CODEX code-r1 finding 1; AGY impl-r1 finding 1.)
        match builder.spawn(move || {
            worker_loop(&args_owned, ctx);
        }) {
            Ok(h) => handles.push(h),
            Err(e) => {
                spawn_error = Some(format!(
                    "spawn(flooder-{}) failed: {}", tid, e
                ));
                shutdown_flag.store(true, Ordering::Relaxed);
                break;
            }
        }
    }

    // If spawn failed, join whatever's running, then surface the error.
    // A panicked worker here doesn't matter — we're already returning
    // the spawn_error to the caller.
    if let Some(err) = spawn_error {
        for h in handles { let _ = h.join(); }
        return Err(err);
    }

    // Main-thread aggregate progress loop — sole stderr emitter so
    // worker output cannot interleave. Per plan-v4.md §3.8. Uses the
    // SAME `total_deadline` that workers honour — when main reaches
    // the deadline it also stores shutdown_flag so any worker still
    // in mid-batch exits promptly. (CODEX code-r1 finding 3.)
    let mut next_emit_at = warmup_end + Duration::from_secs(1);
    let mut prev_agg = RunStats::default();
    let mut prev_emit_at = warmup_end;
    let mut progress_baseline_ready = false;
    let mut progress_warmup_baseline = RunStats::default();
    while Instant::now() < total_deadline {
        if shutdown_flag.load(Ordering::Relaxed) {
            // Worker reported fatal; break out and join below.
            break;
        }
        let now = Instant::now();
        if now >= next_emit_at {
            if !progress_baseline_ready
                && warmup_baseline_ready
                    .iter()
                    .all(|ready| ready.load(Ordering::Acquire))
            {
                progress_warmup_baseline.tx_packets = warmup_baselines
                    .iter()
                    .map(|baseline| baseline.load(Ordering::Relaxed))
                    .sum();
                progress_warmup_baseline.tx_batches = warmup_baselines_batches
                    .iter()
                    .map(|baseline| baseline.load(Ordering::Relaxed))
                    .sum();
                progress_baseline_ready = true;
            }
            if !progress_baseline_ready {
                next_emit_at = now + Duration::from_millis(100);
            }
            if progress_baseline_ready {
                let agg = progress_stats_since_warmup(
                    &sum_slots(&stats_slots),
                    &progress_warmup_baseline,
                );
                let elapsed = now - start_at;
                eprintln!(
                    "{}",
                    format_progress_json(elapsed, &agg, &prev_agg, now - prev_emit_at)
                );
                prev_agg = agg;
                prev_emit_at = now;
                next_emit_at = now + Duration::from_secs(1);
            }
        }
        // Sleep up to 100 ms or until next emit, whichever sooner.
        let sleep_until = next_emit_at.min(now + Duration::from_millis(100));
        let dur = sleep_until.saturating_duration_since(Instant::now());
        if !dur.is_zero() { std::thread::sleep(dur); }
    }
    // Signal end-of-run so workers stop emitting packets even if their
    // local clock check is mid-batch behind the deadline.
    shutdown_flag.store(true, Ordering::Relaxed);

    // Join all workers. A panicked worker would not have set
    // first_fatal/shutdown_flag itself, so we surface the panic into
    // first_fatal here so the summary path returns Err instead of
    // silently reporting partial stats. (Copilot code-r1 finding 3.)
    let mut panic_tids: Vec<u32> = Vec::new();
    for (tid, h) in handles.into_iter().enumerate() {
        if h.join().is_err() { panic_tids.push(tid as u32); }
    }
    if !panic_tids.is_empty() {
        let msg = format!("worker(s) panicked: {:?}", panic_tids);
        let mut slot = first_fatal.lock().unwrap();
        if slot.is_none() { *slot = Some(msg); }
    }

    // Check fatal-error slot.
    if let Some(msg) = first_fatal.lock().unwrap().clone() {
        return Err(msg);
    }

    // Collect per-thread snapshots and subtract warmup baselines so
    // the reported tx_packets AND tx_batches reflect only the run-phase
    // work. (CODEX code-r1 finding 2; batches added by #7174 C15 — they
    // are the denominator of packets-per-batch and must share the
    // numerator's window.)
    //
    // The err_* counters are deliberately NOT subtracted, because warmup
    // errors are a legitimate diagnostic signal — if EAGAIN was high during
    // warmup it indicates the device backed up. That is a DIFFERENT window on
    // purpose and is documented here so the record's mixed accounting is a
    // stated choice rather than the silent one C15 found.
    let mut per_thread: Vec<RunStats> = Vec::with_capacity(stats_slots.len());
    for (i, s) in stats_slots.iter().enumerate() {
        let mut snap = s.snapshot();
        let baseline = warmup_baselines[i].load(Ordering::Relaxed);
        snap.tx_packets = snap.tx_packets.saturating_sub(baseline);
        // #7174 C15: tx_batches shares tx_packets' accounting window. It used
        // to stay cumulative-since-start alongside a warmup-subtracted
        // tx_packets in the SAME record, so packets-per-batch read off that
        // record was wrong — understated by however many batches the warmup
        // sent — and the record carried nothing to reveal the mix.
        let baseline_batches = warmup_baselines_batches[i].load(Ordering::Relaxed);
        snap.tx_batches = snap.tx_batches.saturating_sub(baseline_batches);
        per_thread.push(snap);
    }
    // Aggregate from the warmup-adjusted per-thread Vec to keep both
    // views consistent.
    let mut agg = RunStats::default();
    for s in &per_thread {
        agg.tx_packets += s.tx_packets;
        agg.tx_batches += s.tx_batches;
        agg.err_eagain += s.err_eagain;
        agg.err_partial += s.err_partial;
        agg.err_other += s.err_other;
        if agg.first_other_errno == 0 && s.first_other_errno != 0 {
            agg.first_other_errno = s.first_other_errno;
        }
    }
    Ok((agg, per_thread))
}

fn sum_slots(slots: &[Arc<PaddedStats>]) -> RunStats {
    let mut out = RunStats::default();
    for s in slots {
        out.tx_packets += s.tx_packets.load(Ordering::Relaxed);
        out.tx_batches += s.tx_batches.load(Ordering::Relaxed);
        out.err_eagain += s.err_eagain.load(Ordering::Relaxed);
        out.err_partial += s.err_partial.load(Ordering::Relaxed);
        out.err_other += s.err_other.load(Ordering::Relaxed);
        let fo = s.first_other_errno.load(Ordering::Relaxed);
        if out.first_other_errno == 0 && fo != 0 { out.first_other_errno = fo; }
    }
    out
}

fn main() {
    let mut args = match Args::parse() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: {e}\n\n{}", help());
            std::process::exit(2);
        }
    };

    // dst_mac must be explicitly supplied — broadcast default is a sentinel
    // for "operator forgot to pass --dst-mac". Per plan v4 §4 point 1.
    if args.dst_mac == [0xff; 6] {
        eprintln!(
            "error: --dst-mac required; ARP-resolve is not implemented \
             in this runner. On the loss userspace cluster, the peer \
             firewall RETH MAC is stable — pass it explicitly. \
             See docs/pr/1611-flooder-runner-body/plan.md §4."
        );
        std::process::exit(2);
    }

    // #1615 multi-thread setup: query allowed cpuset + validate --threads.
    let allowed_cpus = match allowed_cpu_set() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(2);
        }
    };
    if let Err(e) = validate_threads(args.threads, allowed_cpus.len(), args.allow_oversubscribe) {
        eprintln!("error: {e}\n\n{}", help());
        std::process::exit(2);
    }

    // Resolve interface + ifindex.
    let ifindex = match resolve_ifindex(&args.iface) {
        Ok(idx) => idx,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(2);
        }
    };

    // Open ONE socket up-front to centralise CAP_NET_RAW errors AND
    // discover the iface MAC + IFF_UP via that fd; then open the
    // remaining N-1 sockets for the worker fleet.
    let probe_fd = match open_socket(ifindex, args.frame_bytes, args.batch) {
        Ok(fd) => fd,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(2);
        }
    };

    // Check IFF_UP. AGY r1 finding C.
    if let Err(e) = check_iface_up(probe_fd, &args.iface) {
        eprintln!("error: {e}");
        // SAFETY: close on a valid fd.
        unsafe { libc::close(probe_fd); }
        std::process::exit(2);
    }

    // Auto-fill src_mac from iface if still default [0; 6].
    if args.src_mac == [0; 6] {
        match read_iface_mac(probe_fd, &args.iface) {
            Ok(mac) => args.src_mac = mac,
            Err(e) => {
                // #7174 C16: FAIL CLOSED. This used to warn and continue with
                // an all-zero source MAC, which is not a valid measurement —
                // frames sourced from 00:00:00:00:00:00 are not what the
                // device under test would ever see, and the run still printed
                // a summary record as though it were.
                //
                // A harness that reports a wrong number without saying so is
                // worse than one that refuses, because every conclusion drawn
                // from it inherits the error silently and the warning scrolls
                // past in a log nobody re-reads. Refusing costs one obvious
                // failure; continuing costs an unknown number of wrong results.
                eprintln!(
                    "cold-path-flooder: could not read the MAC of {} ({}). Refusing to \
                     run with an all-zero source MAC — the result would not be a valid \
                     measurement. Pass --src-mac explicitly to override.",
                    args.iface, e
                );
                std::process::exit(2);
            }
        }
    }

    // The probe fd becomes WorkerFd #0; open additional fds for
    // workers 1..N. Each fd is wrapped in WorkerFd RAII (#1615 SMR
    // MAJOR-1).
    let mut worker_fds: Vec<WorkerFd> = Vec::with_capacity(args.threads as usize);
    worker_fds.push(WorkerFd(probe_fd));
    for tid in 1..args.threads {
        match open_socket(ifindex, args.frame_bytes, args.batch) {
            Ok(fd) => worker_fds.push(WorkerFd(fd)),
            Err(e) => {
                eprintln!("error: open_socket for thread {} failed: {}", tid, e);
                // Explicitly close previously-opened fds before exit.
                // process::exit bypasses Rust destructors so the Vec
                // is NOT dropped automatically; the kernel reaps fds
                // on process exit, but being explicit here keeps the
                // ownership story correct. (Copilot code-r2 finding 3.)
                drop(worker_fds);
                std::process::exit(2);
            }
        }
    }

    // CPU pinning plan: build a Vec<Option<i32>> of pin targets, one
    // per worker. None = skip pin (--no-cpu-pin).
    let pin_cpus: Vec<Option<i32>> = (0..args.threads)
        .map(|tid| {
            if args.no_cpu_pin {
                None
            } else {
                let idx = (args.cpu_base as usize + tid as usize) % allowed_cpus.len();
                Some(allowed_cpus[idx])
            }
        })
        .collect();

    eprintln!(
        "cold-path-flooder v2: iface={} ifindex={} src_mac={:02x?} dst_mac={:02x?} \
         dst_ip={} cohort={} src_port_base={} threads={} cpu_base={} no_cpu_pin={} \
         allow_oversubscribe={} allowed_cpus={:?} duration={:?} warmup={:?} \
         frame_bytes={} batch={}",
        args.iface, ifindex, args.src_mac, args.dst_mac, args.dst_ip,
        if args.cohort_unbounded { "unbounded" } else { "bounded" },
        args.src_port_base, args.threads, args.cpu_base, args.no_cpu_pin,
        args.allow_oversubscribe, allowed_cpus, args.duration, args.warmup,
        args.frame_bytes, args.batch,
    );

    let (agg, per_thread) =
        match run_multi_threaded(&args, worker_fds, ifindex, pin_cpus) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("error: {e}");
                std::process::exit(1);
            }
        };

    emit_summary(&args, &agg, &per_thread);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_default_args() -> Args {
        Args {
            iface: "ge-0-0-1".to_string(),
            dst_mac: [0x02, 0xbf, 0x72, 0xcc, 0x00, 0x01],
            src_mac: [0x02, 0xbf, 0x72, 0xcc, 0x00, 0x02],
            dst_ip: Ipv4Addr::new(172, 16, 80, 200),
            dst_port_base: DEFAULT_DST_PORT_BASE,
            dst_port_span: DEFAULT_DST_PORT_SPAN,
            src_ip_base: u32::from_be_bytes([10, 42, 0, 0]),
            src_ip_span: DEFAULT_SRC_IP_SPAN,
            src_port_base: DEFAULT_SRC_PORT_BASE,
            src_port_span: DEFAULT_SRC_PORT_SPAN,
            duration: Duration::from_secs(DEFAULT_DURATION_SECS),
            warmup: Duration::from_secs(DEFAULT_WARMUP_SECS),
            frame_bytes: MIN_ETH_FRAME,
            batch: DEFAULT_BATCH,
            seed: 1,
            cohort_unbounded: true,
            threads: 1,
            cpu_base: 0,
            no_cpu_pin: false,
            allow_oversubscribe: false,
        }
    }

    // --- C175-HC-072: bounded cohort sequential enumeration ---------------

    #[test]
    fn hc072_tuple_space_matches_spans() {
        let mut a = build_default_args();
        a.src_ip_span = BOUNDED_SRC_IP_SPAN;
        a.src_port_span = BOUNDED_SRC_PORT_SPAN;
        a.dst_port_span = BOUNDED_DST_PORT_SPAN;
        assert_eq!(tuple_space(&a), 131_072);
    }

    #[test]
    fn hc072_worker_slices_partition_space_disjointly() {
        let space = 131_072u64;
        for threads in [1u32, 3, 4, 6, 7, 64] {
            let mut prev_end = 0u64;
            let mut covered = 0u64;
            for t in 0..threads {
                let (base, end) = worker_slice(t, threads, space);
                assert_eq!(base, prev_end, "threads={threads}: slice {t} gap/overlap");
                assert!(end >= base);
                covered += end - base;
                prev_end = end;
            }
            assert_eq!(prev_end, space, "threads={threads}: did not reach space");
            assert_eq!(covered, space, "threads={threads}: coverage != space");
        }
    }

    #[test]
    fn hc072_bounded_enumeration_first_pass_is_distinct() {
        // One worker sweeping the whole bounded space visits every 5-tuple
        // exactly once — a clean table fill, zero collisions. The old
        // random draws hit birthday collisions long before 131_072 draws.
        let space = 131_072u64;
        let (base, end) = worker_slice(0, 1, space);
        assert_eq!((base, end), (0, space));
        let mut seen = std::collections::HashSet::with_capacity(space as usize);
        for idx in base..end {
            let t = decompose_tuple_index(
                idx, BOUNDED_SRC_PORT_SPAN, BOUNDED_DST_PORT_SPAN,
            );
            assert!(t.0 < BOUNDED_SRC_IP_SPAN);
            assert!(t.1 < BOUNDED_SRC_PORT_SPAN);
            assert!(t.2 < BOUNDED_DST_PORT_SPAN);
            assert!(seen.insert(t), "duplicate tuple at idx {idx}: {t:?}");
        }
        assert_eq!(seen.len() as u64, space);
    }

    #[test]
    fn hc072_bounded_multiworker_tuples_globally_distinct() {
        // Across 4 workers each sweeping its slice once, the union is the
        // whole space with no cross-worker overlap (the shared-random
        // scheme let two workers emit the same tuple).
        let space = 131_072u64;
        let threads = 4u32;
        let mut seen = std::collections::HashSet::with_capacity(space as usize);
        for t in 0..threads {
            let (base, end) = worker_slice(t, threads, space);
            for idx in base..end {
                let tup = decompose_tuple_index(
                    idx, BOUNDED_SRC_PORT_SPAN, BOUNDED_DST_PORT_SPAN,
                );
                assert!(seen.insert(tup), "cross-worker duplicate at idx {idx}");
            }
        }
        assert_eq!(seen.len() as u64, space);
    }

    #[test]
    fn bounded_cohort_constants_fit_max_sessions() {
        let cohort = BOUNDED_SRC_IP_SPAN as u64
            * BOUNDED_SRC_PORT_SPAN as u64
            * BOUNDED_DST_PORT_SPAN as u64;
        assert_eq!(cohort, 131_072);
    }

    #[test]
    fn unbounded_is_default_regime() {
        let default_cohort = DEFAULT_SRC_IP_SPAN as u64
            * DEFAULT_SRC_PORT_SPAN as u64
            * DEFAULT_DST_PORT_SPAN as u64;
        assert!(default_cohort > 131_072);
    }

    #[test]
    fn bounded_cohort_overflow_check_uses_u128() {
        let s1: u32 = u32::MAX;
        let s2: u32 = u32::MAX;
        let s3: u32 = u32::MAX;
        let cohort: u128 = s1 as u128 * s2 as u128 * s3 as u128;
        assert!(cohort > 131_072);
        assert!(cohort > u64::MAX as u128);
    }

    #[test]
    fn zero_spans_and_batch_rejected() {
        let mut a = build_default_args();
        a.src_ip_span = 0;
        assert!(validate_args(&a).is_err());

        a = build_default_args();
        a.src_port_span = 0;
        assert!(validate_args(&a).is_err());

        a = build_default_args();
        a.dst_port_span = 0;
        assert!(validate_args(&a).is_err());

        a = build_default_args();
        a.batch = 0;
        assert!(validate_args(&a).is_err());

        a = build_default_args();
        a.batch = 2048;
        assert!(validate_args(&a).is_err());

        assert!(validate_args(&build_default_args()).is_ok());
    }

    #[test]
    fn dst_port_overflow_rejected_by_validator() {
        // AGY r3 step-2 minor 1.
        let mut a = build_default_args();
        a.dst_port_base = 60_000;
        a.dst_port_span = 10_000;
        let err = validate_args(&a).unwrap_err();
        assert!(err.contains("dst-port-base"));
        assert!(err.contains("65536"));
    }

    #[test]
    fn dst_port_base_plus_span_eq_65536_allowed() {
        // Boundary case — dst_port_base + dst_port_span == 65536 is OK.
        let mut a = build_default_args();
        a.dst_port_base = 60_000;
        a.dst_port_span = 5_536;
        assert!(validate_args(&a).is_ok());
    }

    #[test]
    fn src_port_overflow_rejected_by_validator() {
        let mut a = build_default_args();
        a.src_port_base = 60_000;
        a.src_port_span = 10_000;
        let err = validate_args(&a).unwrap_err();
        assert!(err.contains("src-port-base"));
        assert!(err.contains("65536"));
    }

    #[test]
    fn xorshift_nonzero_and_progresses() {
        let mut x = Xorshift64(1);
        let a = x.next();
        let b = x.next();
        assert_ne!(a, 0);
        assert_ne!(b, 0);
        assert_ne!(a, b);
    }

    #[test]
    fn parse_mac_valid() {
        let m = parse_mac("02:bf:72:cc:00:01").unwrap();
        assert_eq!(m, [0x02, 0xbf, 0x72, 0xcc, 0x00, 0x01]);
    }

    #[test]
    fn parse_mac_invalid_segments() {
        assert!(parse_mac("02:bf:72").is_err());
        assert!(parse_mac("02:bf:72:cc:00:0z").is_err());
    }

    #[test]
    fn unbounded_default_spans_match_plan() {
        assert_eq!(DEFAULT_SRC_IP_SPAN, 65_536);
        // Plan §4 + reserved-port-0 protection: default src_port_span =
        // 65_536 - DEFAULT_SRC_PORT_BASE = 64_512, so emitted ports stay
        // in [1024, 65_536) without u16 wrap.
        assert_eq!(DEFAULT_SRC_PORT_SPAN, 64_512);
        assert_eq!(DEFAULT_SRC_PORT_BASE, 1024);
        assert!(DEFAULT_SRC_PORT_BASE as u32 + DEFAULT_SRC_PORT_SPAN <= 65_536);
        assert_eq!(DEFAULT_DST_PORT_SPAN, 1);
    }

    #[test]
    fn default_src_port_base_skips_reserved_zero() {
        // #1611 plan §4: default src_port_base=1024 to avoid the
        // metadata_tuple_complete short-circuit at
        // userspace-dp/src/afxdp/frame/inspect.rs:207. Operators can
        // opt into port-0 sweep via `--src-port-base 0`.
        assert_eq!(DEFAULT_SRC_PORT_BASE, 1024);
    }

    #[test]
    fn frame_bytes_must_be_at_least_min_eth() {
        assert_eq!(MIN_ETH_FRAME, 64);
        assert!(64 >= MIN_ETH_FRAME);
    }

    /// Plan v4 §4 — wire-byte invariants.
    #[test]
    fn frame_layout_constants_match_plan() {
        assert_eq!(ETH_HDR, 14);
        assert_eq!(IPV4_HDR, 20);
        assert_eq!(UDP_HDR, 8);
        assert_eq!(UDP_PAYLOAD, 22);
        assert_eq!(FRAME_V4_TOTAL, 64);
        assert_eq!(IPV4_TOTAL_LEN, 50);
        assert_eq!(UDP_LEN, 30);
        assert_eq!(PAYLOAD_MAGIC.len(), UDP_PAYLOAD);
    }

    #[test]
    fn frame_assembly_default_v4_is_exactly_64_bytes() {
        let mut slot = TxSlot::new();
        slot.init_static(
            &[0x02, 0xbf, 0x72, 0xcc, 0x00, 0x01],
            &[0x02, 0xbf, 0x72, 0xcc, 0x00, 0x02],
            Ipv4Addr::new(172, 16, 80, 200),
        );
        slot.fill_packet(u32::from_be_bytes([10, 42, 0, 5]), 0x1234, 1024, 5201);
        assert_eq!(slot.frame.len(), 64);
    }

    #[test]
    fn frame_assembly_ipv4_total_len_field_is_50() {
        let mut slot = TxSlot::new();
        slot.init_static(
            &[0x02; 6],
            &[0x03; 6],
            Ipv4Addr::new(172, 16, 80, 200),
        );
        slot.fill_packet(0x0A2A0001, 0x4321, 1024, 5201);
        let total_len = u16::from_be_bytes([slot.frame[16], slot.frame[17]]);
        assert_eq!(total_len, 50);
    }

    #[test]
    fn frame_assembly_udp_len_field_is_30() {
        let mut slot = TxSlot::new();
        slot.init_static(
            &[0x02; 6],
            &[0x03; 6],
            Ipv4Addr::new(172, 16, 80, 200),
        );
        slot.fill_packet(0x0A2A0001, 0x4321, 1024, 5201);
        let udp_len = u16::from_be_bytes([slot.frame[38], slot.frame[39]]);
        assert_eq!(udp_len, 30);
    }

    #[test]
    fn frame_assembly_udp_csum_is_zero_per_rfc768() {
        let mut slot = TxSlot::new();
        slot.init_static(
            &[0x02; 6],
            &[0x03; 6],
            Ipv4Addr::new(172, 16, 80, 200),
        );
        slot.fill_packet(0x0A2A0001, 0x4321, 1024, 5201);
        let udp_csum = u16::from_be_bytes([slot.frame[40], slot.frame[41]]);
        assert_eq!(udp_csum, 0);
    }

    #[test]
    fn frame_assembly_ipv4_csum_one_complement_fold() {
        // Golden value: with the static header fields below + src_ip
        // 10.42.0.5, ip_id 0x1234, the IPv4 csum is deterministic.
        // Verify by recomputing externally.
        //
        //   v=4 ihl=5 tos=0      0x4500
        //   total_len = 50       0x0032
        //   id = 0x1234
        //   flags=DF, frag=0     0x4000
        //   ttl=64 proto=17      0x4011
        //   csum (zero for computation)
        //   src = 10.42.0.5      0x0A2A 0x0005
        //   dst = 172.16.80.200  0xAC10 0x50C8
        //
        // 16-bit sum (carry-folded) of header words excluding csum:
        //   0x4500 + 0x0032 + 0x1234 + 0x4000 + 0x4011 + 0x0000
        //     + 0x0A2A + 0x0005 + 0xAC10 + 0x50C8 = 0x1DE7E
        //   carry-fold: 0xDE7E + 0x0001 = 0xDE7F
        //   one's complement: 0xFFFF - 0xDE7F = 0x2180
        let mut slot = TxSlot::new();
        slot.init_static(
            &[0x02; 6],
            &[0x03; 6],
            Ipv4Addr::new(172, 16, 80, 200),
        );
        slot.fill_packet(u32::from_be_bytes([10, 42, 0, 5]), 0x1234, 1024, 5201);
        let csum = u16::from_be_bytes([slot.frame[24], slot.frame[25]]);
        assert_eq!(csum, 0x2180, "ipv4 csum mismatch: {:#06x}", csum);
    }

    #[test]
    fn frame_assembly_payload_magic_matches_plan() {
        // Plan v4 §4: payload b"XPF-COLD-PATH-MIN64\n\0\0" (22 bytes).
        let mut slot = TxSlot::new();
        slot.init_static(
            &[0x02; 6],
            &[0x03; 6],
            Ipv4Addr::new(172, 16, 80, 200),
        );
        slot.fill_packet(0x0A2A0001, 0x4321, 1024, 5201);
        assert_eq!(&slot.frame[42..64], PAYLOAD_MAGIC.as_slice());
        assert_eq!(slot.frame[42..62], *b"XPF-COLD-PATH-MIN64\n");
        assert_eq!(slot.frame[62], 0);
        assert_eq!(slot.frame[63], 0);
    }

    #[test]
    fn src_port_zero_never_emitted_with_default_base() {
        // The default config (base=1024, span=64512) keeps every emitted
        // src_port in [1024, 65_536) — strictly above the reserved-port-0
        // short-circuit at userspace-dp/src/afxdp/frame/inspect.rs:207.
        let args = build_default_args();
        assert!(validate_args(&args).is_ok());

        let mut prng = Xorshift64(args.seed);
        for _ in 0..16_384 {
            let s = prng.next();
            let src_port_v = ((s >> 16) as u32 % args.src_port_span) as u16;
            let src_port = args.src_port_base.wrapping_add(src_port_v);
            assert!(
                src_port >= 1024,
                "src_port < 1024: {} (base {} + v {})",
                src_port,
                args.src_port_base,
                src_port_v
            );
        }

        // Confirm the validator hard-rejects a misconfig that would
        // wrap into the reserved range.
        let mut bad = build_default_args();
        bad.src_port_base = 1024;
        bad.src_port_span = 65_536;
        assert!(validate_args(&bad).is_err());
    }

    #[test]
    fn progress_json_reports_window_rate_and_deltas() {
        let prev = RunStats {
            tx_packets: 1_000,
            tx_batches: 31,
            err_eagain: 4,
            err_partial: 1,
            err_other: 2,
            first_other_errno: 0,
        };
        let now = RunStats {
            tx_packets: 3_000,
            tx_batches: 63,
            err_eagain: 7,
            err_partial: 2,
            err_other: 5,
            first_other_errno: 0,
        };
        let line = format_progress_json(
            Duration::from_millis(3500),
            &now,
            &prev,
            Duration::from_millis(500),
        );
        assert!(line.contains("\"t\":3.5"));
        assert!(line.contains("\"pps\":4000"));
        assert!(line.contains("\"tx_packets_delta\":2000"));
        assert!(line.contains("\"tx_batches_delta\":32"));
        assert!(line.contains("\"err_eagain_delta\":3"));
        assert!(line.contains("\"err_partial_delta\":1"));
        assert!(line.contains("\"err_other_delta\":3"));
    }
    #[test]
    fn first_progress_interval_excludes_warmup_traffic() {
        // At the first progress tick after a 2-second warmup, the slots
        // contain 2 seconds of warmup plus 1 second of measured traffic.
        let after_one_second = RunStats {
            tx_packets: 300_000,
            tx_batches: 9_375,
            ..RunStats::default()
        };
        let warmup = RunStats {
            tx_packets: 200_000,
            tx_batches: 6_250,
            ..RunStats::default()
        };
        let run_stats = progress_stats_since_warmup(&after_one_second, &warmup);
        let line = format_progress_json(
            Duration::from_secs(3),
            &run_stats,
            &RunStats::default(),
            Duration::from_secs(1),
        );
        assert!(line.contains("\"pps\":100000"));
        assert!(line.contains("\"tx_packets_delta\":100000"));
    }

    #[test]
    fn warmup_baseline_is_published_at_deadline() {
        let stats = PaddedStats::new();
        stats.tx_packets.store(1_234, Ordering::Relaxed);
        stats.tx_batches.store(38, Ordering::Relaxed);
        let packet_baseline = AtomicU64::new(0);
        let batch_baseline = AtomicU64::new(0);
        let ready = AtomicBool::new(false);
        let deadline = Instant::now();
        let mut published = false;

        publish_warmup_baseline_if_due(
            deadline,
            deadline,
            &mut published,
            &stats,
            &packet_baseline,
            &batch_baseline,
            &ready,
        );

        assert!(published);
        assert!(ready.load(Ordering::Acquire));
        assert_eq!(packet_baseline.load(Ordering::Relaxed), 1_234);
        assert_eq!(batch_baseline.load(Ordering::Relaxed), 38);
    }

    #[test]
    fn progress_json_zero_window_clamps_pps_to_zero() {
        let now = RunStats {
            tx_packets: 99,
            ..RunStats::default()
        };
        let line = format_progress_json(
            Duration::from_secs(2),
            &now,
            &RunStats::default(),
            Duration::ZERO,
        );
        assert!(line.contains("\"pps\":0"));
        assert!(line.contains("\"tx_packets_delta\":99"));
    }

    // #1615 multi-thread additions.

    #[test]
    fn worker_seed_avoids_zero_state() {
        // base_seed=0, thread_id=0: mixed = 0 ^ 0 = 0 -> fallback.
        assert_eq!(worker_seed(0, 0), PER_THREAD_SEED_ZERO_FALLBACK);
        // base_seed=0, thread_id=1: nonzero.
        assert_ne!(worker_seed(0, 1), 0);
        // base_seed=1, thread_id=0: 1 ^ 0 = 1 (nonzero).
        assert_eq!(worker_seed(1, 0), 1);
    }

    #[test]
    fn worker_seed_disjoint_across_threads() {
        for &base in &[0u64, 1, 42, 0xDEAD_BEEF_CAFE_BABE] {
            let seeds: Vec<u64> = (0..16).map(|t| worker_seed(base, t)).collect();
            // All seeds distinct.
            let mut sorted = seeds.clone();
            sorted.sort();
            sorted.dedup();
            assert_eq!(sorted.len(), 16, "base={base}: duplicate per-thread seeds");
        }
    }

    #[test]
    fn multi_thread_seeds_produce_disjoint_5tuples_first_window() {
        use std::collections::BTreeSet;
        let base_seed = 42u64;
        let mut sets: Vec<BTreeSet<(u32, u16, u16)>> = vec![BTreeSet::new(); 4];
        for tid in 0..4u32 {
            let mut prng = Xorshift64(worker_seed(base_seed, tid));
            for _ in 0..1000 {
                let s = prng.next();
                let src_ip_off = (s as u32) % 65_536;
                let src_port = 1024u16.wrapping_add(((s >> 16) as u32 % 64_512) as u16);
                let dst_port = 5201u16;
                sets[tid as usize].insert((src_ip_off, src_port, dst_port));
            }
        }
        // Pairwise: intersection should be empty or vanishingly small.
        for i in 0..4 {
            for j in (i + 1)..4 {
                let inter: usize = sets[i].intersection(&sets[j]).count();
                // Probability of incidental collision in 1000 samples
                // each across 4.3B-tuple space is < 1e-9; allow up to 2
                // collisions as slack for the modulo-65_536 narrowed
                // tuple space used in this test (~2^31 distinct
                // tuples, so 1000^2 / 2^31 ≈ 5e-4 expected).
                assert!(
                    inter <= 2,
                    "threads {} and {} share {} tuples — RNG correlation",
                    i, j, inter
                );
            }
        }
    }

    #[test]
    fn validate_threads_rejects_zero() {
        assert!(validate_threads(0, 16, false).is_err());
    }

    #[test]
    fn validate_threads_rejects_above_hard_cap() {
        let r = validate_threads(MAX_THREADS_HARD_CAP + 1, 1024, true);
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("MAX_THREADS_HARD_CAP"));
    }

    #[test]
    fn validate_threads_rejects_above_cpuset_without_oversubscribe() {
        // allowed_len=2, threads=4, no oversubscribe -> err.
        let r = validate_threads(4, 2, false);
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("--allow-oversubscribe"));
    }

    #[test]
    fn validate_threads_accepts_above_cpuset_with_oversubscribe() {
        // allowed_len=2, threads=4, with override -> ok.
        assert!(validate_threads(4, 2, true).is_ok());
    }

    #[test]
    fn validate_threads_accepts_within_cpuset() {
        assert!(validate_threads(4, 16, false).is_ok());
        assert!(validate_threads(16, 16, false).is_ok());
    }

    #[test]
    fn padded_stats_layout_is_64_bytes() {
        assert_eq!(std::mem::size_of::<PaddedStats>(), 64);
    }

    #[test]
    fn padded_stats_vec_has_no_false_sharing() {
        // Slots in a Vec<PaddedStats> must be 64 bytes apart so adjacent
        // workers' atomics never share a cache line.
        let v: Vec<PaddedStats> = (0..4).map(|_| PaddedStats::new()).collect();
        let p0 = &v[0] as *const PaddedStats as usize;
        let p1 = &v[1] as *const PaddedStats as usize;
        assert_eq!(p1 - p0, 64, "PaddedStats slots not cache-line spaced");
    }

    #[test]
    fn per_thread_ratio_n1_is_1_0() {
        let single = vec![RunStats { tx_packets: 12345, ..Default::default() }];
        assert_eq!(per_thread_ratio(&single), 1.0);
    }

    #[test]
    fn per_thread_ratio_balanced_under_1_5() {
        let four = vec![
            RunStats { tx_packets: 1_000_000, ..Default::default() },
            RunStats { tx_packets: 1_050_000, ..Default::default() },
            RunStats { tx_packets:   980_000, ..Default::default() },
            RunStats { tx_packets: 1_020_000, ..Default::default() },
        ];
        let r = per_thread_ratio(&four);
        assert!(r > 1.0 && r < 1.5, "ratio = {}", r);
    }

    #[test]
    fn per_thread_ratio_skewed_above_2_0() {
        let four = vec![
            RunStats { tx_packets: 3_000_000, ..Default::default() },
            RunStats { tx_packets: 1_000_000, ..Default::default() },
            RunStats { tx_packets: 1_000_000, ..Default::default() },
            RunStats { tx_packets: 1_000_000, ..Default::default() },
        ];
        let r = per_thread_ratio(&four);
        assert!(r > 2.0, "expected >2.0, got {}", r);
    }

    #[test]
    fn per_thread_ratio_zero_min_does_not_divide_by_zero() {
        let two = vec![
            RunStats { tx_packets: 2_500_000, ..Default::default() },
            RunStats { tx_packets: 0, ..Default::default() },
        ];
        let r = per_thread_ratio(&two);
        // min(0,1)=1 in formula; ratio = max / 1 = 2.5e6. Sanity check
        // we did NOT panic on /0.
        assert_eq!(r, 2_500_000.0);
    }

    #[test]
    fn cpu_base_modulo_maps_into_allowed_cpus() {
        // Synthetic allowed_cpus.
        let allowed: Vec<i32> = vec![2, 4, 6, 8];
        let cpu_base = 1u32;
        // Thread 0 -> idx (1+0) % 4 = 1 -> allowed[1] = 4
        // Thread 1 -> idx (1+1) % 4 = 2 -> allowed[2] = 6
        // Thread 2 -> idx (1+2) % 4 = 3 -> allowed[3] = 8
        // Thread 3 -> idx (1+3) % 4 = 0 -> allowed[0] = 2
        let pins: Vec<i32> = (0..4u32)
            .map(|tid| {
                let idx = (cpu_base as usize + tid as usize) % allowed.len();
                allowed[idx]
            })
            .collect();
        assert_eq!(pins, vec![4, 6, 8, 2]);
    }

    #[test]
    fn allowed_cpu_set_returns_nonempty_on_host() {
        // sched_getaffinity should always return at least one CPU.
        let cpus = allowed_cpu_set().expect("sched_getaffinity should succeed on host");
        assert!(!cpus.is_empty());
        // All values should be in [0, CPU_SETSIZE).
        for cpu in &cpus {
            assert!(*cpu >= 0);
            assert!(*cpu < libc::CPU_SETSIZE);
        }
    }

    /// CAP_NET_RAW integration test — Codex r1 MAJOR-3.
    /// Skipped by default. Run via:
    ///   XPF_RUN_RAW_SOCKET_TESTS=1 \
    ///   XPF_RAW_SOCKET_TEST_IFACE=eth0 \
    ///   sudo -E cargo test --release \
    ///     -- --ignored test_open_af_packet_raw_smoke
    #[test]
    // #9052: the reason is DECLARED rather than left to the doc comment above.
    // A census cannot read prose — the marker is the machine-readable half, and
    // a bare `#[ignore]` says nothing about why the cell is off or when it
    // should come back. MEASUREMENT is the correct kind here: this needs
    // CAP_NET_RAW and a real interface, so it is environment-gated forever
    // rather than fail-until-fixed, and there is no issue whose closure should
    // reactivate it.
    #[ignore = "MEASUREMENT: needs CAP_NET_RAW and a real interface; see the doc comment above for the invocation"]
    fn test_open_af_packet_raw_smoke() {
        if std::env::var("XPF_RUN_RAW_SOCKET_TESTS").as_deref() != Ok("1") {
            eprintln!("Skipped: set XPF_RUN_RAW_SOCKET_TESTS=1 to run.");
            return;
        }
        let iface = match select_smoke_test_iface().expect("select_smoke_test_iface should work") {
            Some(iface) => iface,
            None => {
                eprintln!(
                    "Skipped: no IFF_UP ARPHRD_ETHER iface found; set XPF_RAW_SOCKET_TEST_IFACE."
                );
                return;
            }
        };
        let ifindex = resolve_ifindex(&iface).expect("smoke-test iface should exist");
        // Open the socket.
        let fd =
            open_socket(ifindex, 64, 1).expect("open_socket on smoke-test iface should succeed");
        assert!(fd >= 0);
        if let Err(err) = check_iface_up(fd, &iface) {
            unsafe {
                libc::close(fd);
            }
            eprintln!("Skipped: {}", err);
            return;
        }
        let (hwaddr_family, iface_mac) =
            read_iface_hwaddr(fd, &iface).expect("SIOCGIFHWADDR should succeed");
        if hwaddr_family != libc::ARPHRD_ETHER as u16 {
            unsafe {
                libc::close(fd);
            }
            eprintln!(
                "Skipped: iface '{}' has ARPHRD {} not ARPHRD_ETHER ({})",
                iface,
                hwaddr_family,
                libc::ARPHRD_ETHER
            );
            return;
        }
        // Build one packet and send.
        let mut ring = TxRing::new(
            1,
            &iface_mac,
            &iface_mac,
            Ipv4Addr::new(127, 0, 0, 1),
            ifindex,
        );
        ring.wire_msgs();
        ring.slots[0].fill_packet(u32::from_be_bytes([127, 0, 0, 1]), 1, 1024, 5201);
        let sent = unsafe {
            libc::sendmmsg(fd, ring.msgs.as_mut_ptr(), 1, 0)
        };
        assert!(sent == 1, "expected sendmmsg to send 1, got {}", sent);
        unsafe {
            libc::close(fd);
        }
    }
}
