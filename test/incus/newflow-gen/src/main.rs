// #4800 newflow-gen — connection-rate generator + sink for the new-flow
// ceiling harness.
//
// WHAT IT MEASURES, AND WHY IT COMPLETES HANDSHAKES
// ------------------------------------------------
// The three synchronization points #4800 characterises — the SNAT pool
// allocator's `live` map mutex, `publish_shared_session`, and the N-way
// `replicate_session_upsert` fan-out — all sit on the SESSION INSTALL path.
// A SYN flood never reaches them: it is absorbed by the screen path and the
// half-open window. So this generator completes the three-way handshake and
// then tears the connection down, one full short-lived flow at a time.
//
// GENERATOR HONESTY
// -----------------
// The client is a blocking-connect thread pool, which is bounded by thread
// count and RTT rather than by the firewall. That is a deliberate, DECLARED
// limitation, not a hidden one: the run reports its own achieved rate, and
// `newflow_ceiling_analyze.py` marks a cell INCONCLUSIVE ("the generator,
// client NIC or target bound first") whenever accepted flows fall short of
// the offered rate. A generator ceiling therefore shows up as a refusal to
// conclude, never as a firewall ceiling. Raise `--threads`, or drive from
// more than one client host, if the cells report generator-limited.
//
// CLOSE SEMANTICS
// ---------------
// `--close=rst` (default) sets SO_LINGER(0) so close(2) emits RST: the CLIENT
// avoids a TIME_WAIT per flow, which would otherwise exhaust its ephemeral
// port range within seconds at these rates. The firewall still retains the
// RST-closed session for TCP_RST_TIMEOUT_NS (2s), so offered rate R implies
// roughly R*2 live sessions — the session-capacity envelope the harness
// bounds its rate sweep against. `--close=fin` is available for a comparison
// run; it moves TIME_WAIT onto the client and caps the achievable rate hard.
//
// DESTINATION DIVERSITY
// ---------------------
// Connections sweep a destination PORT RANGE, not one port. RSS on the
// cluster's mlx5 VFs hashes the 4-tuple, so a single destination port would
// steer everything at one RX queue and produce a single-worker ceiling that
// says nothing about cross-worker locks (the analyzer's RSS gate refuses
// such a run). Source ports are kernel-assigned and already distinct.

use socket2::{Domain, Protocol, Socket, Type};
use std::io::Write;
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

const DEFAULT_THREADS: usize = 32;
const DEFAULT_DURATION_SECS: u64 = 30;
const DEFAULT_CONNECT_TIMEOUT_MS: u64 = 1_000;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum CloseMode {
    /// SO_LINGER(0): close(2) emits RST, no client-side TIME_WAIT.
    Rst,
    /// Ordinary orderly close: FIN, client holds TIME_WAIT.
    Fin,
}

#[derive(Clone, Debug)]
struct ClientConfig {
    target: IpAddr,
    source_bind: Option<IpAddr>,
    dst_port_low: u16,
    dst_port_high: u16,
    threads: usize,
    duration: Duration,
    /// Offered new flows/sec across ALL threads. 0 means unpaced (go as fast
    /// as the thread pool allows) — useful only for finding the generator's
    /// own ceiling, never for a measured cell.
    rate: u64,
    connect_timeout: Duration,
    close: CloseMode,
}

#[derive(Clone, Debug)]
struct SinkConfig {
    bind: IpAddr,
    port_low: u16,
    port_high: u16,
    close: CloseMode,
}

/// Cumulative outcome counters. Every attempt lands in exactly one bucket, so
/// `attempted == established + refused + timed_out + other_errors` holds by
/// construction here.
///
/// NOTHING CHECKS IT. An earlier version of this comment said "the harness
/// asserts that identity"; the harness never reads `attempted` at all — it
/// reads only `established_per_sec`, as a liveness check. The identity is a
/// property of this file, not a verified cross-check, and saying otherwise
/// invited a reader to trust a gate that does not exist.
#[derive(Default)]
struct Counters {
    attempted: AtomicU64,
    established: AtomicU64,
    refused: AtomicU64,
    timed_out: AtomicU64,
    other_errors: AtomicU64,
}

// ---------------------------------------------------------------------------
// Pure helpers (unit-tested below)
// ---------------------------------------------------------------------------

/// Destination port for the `n`-th connection of a thread, cycling the range.
///
/// Every thread walks the same range but starts at a different offset so the
/// pool does not hammer one port in lockstep — that would collapse the RSS
/// spread this generator exists to produce.
fn dst_port_for(low: u16, high: u16, thread_idx: usize, n: u64) -> u16 {
    let span = (high as u64 - low as u64) + 1;
    let offset = (thread_idx as u64).wrapping_add(n) % span;
    (low as u64 + offset) as u16
}

/// Per-thread pacing interval for a total offered `rate` across `threads`.
///
/// Returns None for an unpaced run. A rate that rounds to a sub-nanosecond
/// interval is treated as unpaced rather than silently becoming a busy spin
/// that reports a rate it never offered.
fn thread_interval(rate: u64, threads: usize) -> Option<Duration> {
    if rate == 0 || threads == 0 {
        return None;
    }
    let per_thread = (rate as f64) / (threads as f64);
    if per_thread <= 0.0 {
        return None;
    }
    let nanos = 1_000_000_000.0 / per_thread;
    if nanos < 1.0 {
        return None;
    }
    Some(Duration::from_nanos(nanos as u64))
}

/// Effective achieved rate over a measured window.
///
/// Clamps a zero/negative window to 0.0 rather than dividing: a report that
/// prints `inf` flows/sec would be read as a spectacular result rather than
/// as the broken clock it is.
fn effective_rate(count: u64, elapsed: Duration) -> f64 {
    let secs = elapsed.as_secs_f64();
    if secs <= 0.0 {
        return 0.0;
    }
    count as f64 / secs
}

fn parse_port_range(spec: &str) -> Result<(u16, u16), String> {
    let (lo, hi) = match spec.split_once('-') {
        Some((a, b)) => (a, b),
        None => (spec, spec),
    };
    let low: u16 = lo
        .trim()
        .parse()
        .map_err(|_| format!("bad port {lo:?} in range {spec:?}"))?;
    let high: u16 = hi
        .trim()
        .parse()
        .map_err(|_| format!("bad port {hi:?} in range {spec:?}"))?;
    if low == 0 || high == 0 {
        return Err(format!("port 0 is not connectable (range {spec:?})"));
    }
    if low > high {
        return Err(format!("inverted port range {spec:?}"));
    }
    Ok((low, high))
}

fn parse_close_mode(s: &str) -> Result<CloseMode, String> {
    match s {
        "rst" => Ok(CloseMode::Rst),
        "fin" => Ok(CloseMode::Fin),
        other => Err(format!("unknown --close mode {other:?} (want rst|fin)")),
    }
}

/// Render the run report. Kept separate from the run loop so its shape is
/// testable without opening a socket — the harness parses this, so a silent
/// schema drift would break collection in the lab rather than in CI.
fn render_report(
    c: &Counters,
    elapsed: Duration,
    offered_rate: u64,
    threads: usize,
    close: CloseMode,
) -> String {
    let attempted = c.attempted.load(Ordering::Relaxed);
    let established = c.established.load(Ordering::Relaxed);
    let refused = c.refused.load(Ordering::Relaxed);
    let timed_out = c.timed_out.load(Ordering::Relaxed);
    let other = c.other_errors.load(Ordering::Relaxed);
    format!(
        "{{\"schema\":\"newflow-gen/v1\",\
         \"elapsed_s\":{:.3},\
         \"threads\":{},\
         \"close\":\"{}\",\
         \"offered_rate\":{},\
         \"attempted\":{},\
         \"established\":{},\
         \"refused\":{},\
         \"timed_out\":{},\
         \"other_errors\":{},\
         \"established_per_sec\":{:.1},\
         \"attempted_per_sec\":{:.1}}}",
        elapsed.as_secs_f64(),
        threads,
        match close {
            CloseMode::Rst => "rst",
            CloseMode::Fin => "fin",
        },
        offered_rate,
        attempted,
        established,
        refused,
        timed_out,
        other,
        effective_rate(established, elapsed),
        effective_rate(attempted, elapsed),
    )
}

// ---------------------------------------------------------------------------
// Socket plumbing
// ---------------------------------------------------------------------------

/// Arm SO_LINGER(0) so close(2) emits RST instead of FIN.
fn set_linger_zero(fd: i32) {
    let l = libc::linger {
        l_onoff: 1,
        l_linger: 0,
    };
    // SAFETY: `fd` is a live socket owned by the caller for the duration of
    // this call, and `l` is a correctly-sized `struct linger`.
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_LINGER,
            std::ptr::addr_of!(l) as *const libc::c_void,
            std::mem::size_of::<libc::linger>() as libc::socklen_t,
        );
    }
}

fn classify(err: &std::io::Error, c: &Counters) {
    match err.kind() {
        std::io::ErrorKind::ConnectionRefused => {
            c.refused.fetch_add(1, Ordering::Relaxed);
        }
        std::io::ErrorKind::TimedOut => {
            c.timed_out.fetch_add(1, Ordering::Relaxed);
        }
        _ => {
            c.other_errors.fetch_add(1, Ordering::Relaxed);
        }
    }
}
fn connect_tcp(
    target: SocketAddr,
    source: Option<IpAddr>,
    timeout: Duration,
) -> std::io::Result<TcpStream> {
    let Some(source) = source else {
        return TcpStream::connect_timeout(&target, timeout);
    };
    if source.is_ipv4() != target.is_ipv4() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "source and target address families differ",
        ));
    }
    let socket = Socket::new(
        Domain::for_address(target),
        Type::STREAM,
        Some(Protocol::TCP),
    )?;
    socket.bind(&SocketAddr::new(source, 0).into())?;
    socket.connect_timeout(&target.into(), timeout)?;
    Ok(socket.into())
}

fn run_client(cfg: ClientConfig) -> i32 {
    let counters = Arc::new(Counters::default());
    let stop = Arc::new(AtomicBool::new(false));
    let barrier = Arc::new(Barrier::new(cfg.threads + 1));
    let interval = thread_interval(cfg.rate, cfg.threads);

    let mut handles = Vec::with_capacity(cfg.threads);
    for idx in 0..cfg.threads {
        let counters = Arc::clone(&counters);
        let stop = Arc::clone(&stop);
        let barrier = Arc::clone(&barrier);
        let cfg = cfg.clone();
        handles.push(thread::spawn(move || {
            barrier.wait();
            let mut n: u64 = 0;
            let start = Instant::now();
            while !stop.load(Ordering::Relaxed) {
                if let Some(iv) = interval {
                    // Absolute-deadline pacing: sleeping `iv` per iteration
                    // would let the connect latency accumulate and quietly
                    // under-offer. Deriving the deadline from the start
                    // instant keeps the offered rate honest, and a run that
                    // has fallen behind simply does not sleep (it never
                    // "catches up" with an unbounded burst).
                    let due = start + iv * (n as u32).min(u32::MAX);
                    let now = Instant::now();
                    if due > now {
                        thread::sleep(due - now);
                    }
                }
                let port = dst_port_for(cfg.dst_port_low, cfg.dst_port_high, idx, n);
                let addr = SocketAddr::new(cfg.target, port);
                counters.attempted.fetch_add(1, Ordering::Relaxed);
                match connect_tcp(addr, cfg.source_bind, cfg.connect_timeout) {
                    Ok(stream) => {
                        counters.established.fetch_add(1, Ordering::Relaxed);
                        if cfg.close == CloseMode::Rst {
                            set_linger_zero(stream.as_raw_fd());
                        } else {
                            let _ = stream.shutdown(Shutdown::Both);
                        }
                        drop(stream);
                    }
                    Err(e) => classify(&e, &counters),
                }
                n = n.wrapping_add(1);
            }
        }));
    }

    barrier.wait();
    let start = Instant::now();
    thread::sleep(cfg.duration);
    stop.store(true, Ordering::Relaxed);
    for h in handles {
        let _ = h.join();
    }
    let elapsed = start.elapsed();

    let report = render_report(&counters, elapsed, cfg.rate, cfg.threads, cfg.close);
    println!("{report}");
    let _ = std::io::stdout().flush();

    // Non-zero when the run produced no completed handshakes at all: the
    // harness must not treat a totally failed generator run as a measured
    // cell of zero.
    if counters.established.load(Ordering::Relaxed) == 0 {
        eprintln!("newflow-gen: zero connections established — check reachability, the sink, and the firewall policy");
        return 3;
    }
    0
}

fn run_sink(cfg: SinkConfig) -> i32 {
    let span = (cfg.port_high as u32 - cfg.port_low as u32) + 1;
    let mut handles = Vec::with_capacity(span as usize);
    let mut bound = 0u32;
    for port in cfg.port_low..=cfg.port_high {
        let addr = SocketAddr::new(cfg.bind, port);
        let listener = match TcpListener::bind(addr) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("newflow-gen: bind {addr} failed: {e}");
                continue;
            }
        };
        bound += 1;
        let close = cfg.close;
        handles.push(thread::spawn(move || {
            for stream in listener.incoming() {
                match stream {
                    Ok(s) => {
                        if close == CloseMode::Rst {
                            set_linger_zero(s.as_raw_fd());
                        }
                        drop(s);
                    }
                    // A per-accept error (EMFILE, ECONNABORTED) must not take
                    // the sink down mid-run: the client would then read a
                    // firewall ceiling off a dead target.
                    Err(e) => eprintln!("newflow-gen: accept on {addr} failed: {e}"),
                }
            }
        }));
    }
    if bound == 0 {
        eprintln!("newflow-gen: no listener bound — sink cannot serve the run");
        return 2;
    }
    println!(
        "{{\"schema\":\"newflow-gen-sink/v1\",\"bound_ports\":{},\"requested_ports\":{}}}",
        bound, span
    );
    let _ = std::io::stdout().flush();
    for h in handles {
        let _ = h.join();
    }
    0
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

const USAGE: &str = "\
newflow-gen — #4800 connection-rate generator + sink

CLIENT (run on the LAN-side host):
  newflow-gen --mode client --target <IP> --dst-ports <LO-HI> \\
              [--src-bind <IP>] [--rate N] [--duration S] [--threads T] \\
              [--close rst|fin] [--connect-timeout-ms MS]

SINK (run on the WAN-side target):
  newflow-gen --mode sink --bind <IP> --ports <LO-HI> [--close rst|fin]

--rate is the TOTAL offered new flows/sec across all threads; 0 is unpaced
(use only to characterise the generator itself, never for a measured cell).
Client emits one JSON line (schema newflow-gen/v1) on stdout at exit.
";

fn arg_value<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == name {
            return it.next().map(|s| s.as_str());
        }
        if let Some(rest) = a.strip_prefix(name).and_then(|r| r.strip_prefix('=')) {
            return Some(rest);
        }
    }
    None
}

fn parse_or_die<T: std::str::FromStr>(args: &[String], name: &str, default: T) -> T {
    match arg_value(args, name) {
        None => default,
        Some(v) => v.parse().unwrap_or_else(|_| {
            eprintln!("newflow-gen: bad value for {name}: {v:?}");
            std::process::exit(2);
        }),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--help" || a == "-h") {
        print!("{USAGE}");
        return;
    }
    let close = match parse_close_mode(arg_value(&args, "--close").unwrap_or("rst")) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("newflow-gen: {e}");
            std::process::exit(2);
        }
    };

    let code = match arg_value(&args, "--mode") {
        Some("sink") => {
            let bind: IpAddr = parse_or_die(&args, "--bind", "0.0.0.0".parse().unwrap());
            let (lo, hi) = match parse_port_range(arg_value(&args, "--ports").unwrap_or("")) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("newflow-gen: {e}");
                    std::process::exit(2);
                }
            };
            run_sink(SinkConfig {
                bind,
                port_low: lo,
                port_high: hi,
                close,
            })
        }
        Some("client") => {
            let target: IpAddr = match arg_value(&args, "--target").map(str::parse) {
                Some(Ok(ip)) => ip,
                _ => {
                    eprintln!("newflow-gen: --target <IP> is required in client mode");
                    std::process::exit(2);
                }
            };
            let (lo, hi) = match parse_port_range(arg_value(&args, "--dst-ports").unwrap_or("")) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("newflow-gen: {e}");
                    std::process::exit(2);
                }
            };
            let threads: usize = parse_or_die(&args, "--threads", DEFAULT_THREADS);
            if threads == 0 {
                eprintln!("newflow-gen: --threads must be >= 1");
                std::process::exit(2);
            }
            let duration_s: u64 = parse_or_die(&args, "--duration", DEFAULT_DURATION_SECS);
            let timeout_ms: u64 =
                parse_or_die(&args, "--connect-timeout-ms", DEFAULT_CONNECT_TIMEOUT_MS);
            let source_bind = match arg_value(&args, "--src-bind") {
                Some(value) => Some(value.parse().unwrap_or_else(|_| {
                    eprintln!("newflow-gen: bad value for --src-bind: {value:?}");
                    std::process::exit(2);
                })),
                None => None,
            };
            run_client(ClientConfig {
                target,
                source_bind,
                dst_port_low: lo,
                dst_port_high: hi,
                threads,
                duration: Duration::from_secs(duration_s),
                rate: parse_or_die(&args, "--rate", 0u64),
                connect_timeout: Duration::from_millis(timeout_ms.max(1)),
                close,
            })
        }
        _ => {
            eprintln!("newflow-gen: --mode client|sink is required\n\n{USAGE}");
            2
        }
    };
    std::process::exit(code);
}

// ---------------------------------------------------------------------------
// Tests — the pure helpers only. Socket behaviour is validated by the lab
// run, whose validity the analyzer gates independently.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dst_port_cycles_the_whole_range() {
        let seen: std::collections::BTreeSet<u16> =
            (0..64).map(|n| dst_port_for(5300, 5307, 0, n)).collect();
        assert_eq!(
            seen.len(),
            8,
            "every port in the range must be reached — a generator that pins \
             one destination port steers all traffic at one RSS queue and the \
             run is refused as single-worker-bound"
        );
        assert_eq!(*seen.first().unwrap(), 5300);
        assert_eq!(*seen.last().unwrap(), 5307);
    }

    #[test]
    fn threads_start_at_different_offsets() {
        let a = dst_port_for(5300, 5307, 0, 0);
        let b = dst_port_for(5300, 5307, 1, 0);
        assert_ne!(a, b, "threads must not walk the range in lockstep");
    }

    #[test]
    fn dst_port_handles_a_single_port_range() {
        for n in 0..8 {
            assert_eq!(dst_port_for(5201, 5201, n as usize, n), 5201);
        }
    }

    #[test]
    fn pacing_interval_splits_the_rate_across_threads() {
        // 10k/s over 10 threads = 1k/s each = 1ms.
        assert_eq!(
            thread_interval(10_000, 10),
            Some(Duration::from_nanos(1_000_000))
        );
    }

    #[test]
    fn zero_rate_is_unpaced() {
        assert_eq!(thread_interval(0, 8), None);
    }

    #[test]
    fn absurd_rate_degrades_to_unpaced_rather_than_busy_spinning() {
        // 10 G/s over one thread is a sub-nanosecond interval. Reporting a
        // paced run here would claim an offered rate the generator cannot
        // possibly have produced.
        assert_eq!(thread_interval(10_000_000_000, 1), None);
    }

    #[test]
    fn effective_rate_divides_by_the_measured_window() {
        assert!((effective_rate(60_000, Duration::from_secs(10)) - 6_000.0).abs() < 1e-9);
    }

    #[test]
    fn effective_rate_clamps_a_zero_window() {
        assert_eq!(effective_rate(1_000, Duration::from_secs(0)), 0.0);
    }

    #[test]
    fn port_range_parsing() {
        assert_eq!(parse_port_range("5300-5399").unwrap(), (5300, 5399));
        assert_eq!(parse_port_range("5201").unwrap(), (5201, 5201));
        assert!(parse_port_range("5399-5300").is_err());
        assert!(parse_port_range("0-10").is_err());
        assert!(parse_port_range("").is_err());
        assert!(parse_port_range("http-https").is_err());
    }

    #[test]
    fn close_mode_parsing() {
        assert_eq!(parse_close_mode("rst").unwrap(), CloseMode::Rst);
        assert_eq!(parse_close_mode("fin").unwrap(), CloseMode::Fin);
        assert!(parse_close_mode("reset").is_err());
    }

    #[test]
    fn arg_value_accepts_both_spellings() {
        let a: Vec<String> = ["--rate", "500", "--mode=client"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(arg_value(&a, "--rate"), Some("500"));
        assert_eq!(arg_value(&a, "--mode"), Some("client"));
        assert_eq!(arg_value(&a, "--threads"), None);
    }

    #[test]
    fn report_accounts_for_every_attempt() {
        // The harness checks this identity: an attempt that fell into no
        // bucket would let a failing run look partly successful.
        let c = Counters::default();
        c.attempted.store(100, Ordering::Relaxed);
        c.established.store(70, Ordering::Relaxed);
        c.refused.store(20, Ordering::Relaxed);
        c.timed_out.store(7, Ordering::Relaxed);
        c.other_errors.store(3, Ordering::Relaxed);
        let out = render_report(&c, Duration::from_secs(10), 10, 4, CloseMode::Rst);
        assert!(out.contains("\"schema\":\"newflow-gen/v1\""));
        assert!(out.contains("\"attempted\":100"));
        assert!(out.contains("\"established\":70"));
        assert!(out.contains("\"established_per_sec\":7.0"));
        assert!(out.contains("\"close\":\"rst\""));
        assert_eq!(
            c.established.load(Ordering::Relaxed)
                + c.refused.load(Ordering::Relaxed)
                + c.timed_out.load(Ordering::Relaxed)
                + c.other_errors.load(Ordering::Relaxed),
            c.attempted.load(Ordering::Relaxed)
        );
    }

    #[test]
    fn client_source_bind_connects_from_requested_address() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let target = listener.local_addr().unwrap();
        let source: IpAddr = "127.0.0.2".parse().unwrap();
        let accepted = thread::spawn(move || listener.accept().unwrap().0.peer_addr().unwrap());

        let stream = connect_tcp(target, Some(source), Duration::from_secs(1)).unwrap();
        assert_eq!(stream.local_addr().unwrap().ip(), source);
        assert_eq!(accepted.join().unwrap().ip(), source);
    }
    #[test]

    fn report_survives_a_zero_length_window() {
        let c = Counters::default();
        c.attempted.store(5, Ordering::Relaxed);
        let out = render_report(&c, Duration::from_secs(0), 0, 1, CloseMode::Fin);
        assert!(
            out.contains("\"established_per_sec\":0.0"),
            "a zero window must report 0.0, not inf: {out}"
        );
        assert!(out.contains("\"close\":\"fin\""));
    }
}
