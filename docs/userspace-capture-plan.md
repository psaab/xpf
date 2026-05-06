# Userspace Dataplane Packet Capture Design

Date: 2026-03-18

## Problem

When the userspace AF_XDP dataplane is active, transit packets bypass the
kernel networking stack entirely. Standard tools like `tcpdump` on the
firewall's data interfaces see nothing — the XDP shim redirects frames to
AF_XDP sockets before they reach the kernel. This makes debugging forwarding,
NAT, and policy decisions nearly impossible on a live system.

## Goal

Provide a `tcpdump`-compatible capture interface into the userspace forwarding
path, so operators can sniff:

- **Ingress**: raw frames as received from the NIC (before any rewrite)
- **Egress**: rewritten frames as they leave (after NAT, TTL, MAC changes)
- **Drops**: packets denied by policy, screen, or session state

With BPF-style filter expressions and per-interface/per-zone scoping.

## Approach: Virtual Monitor Interfaces

Create virtual `tap` or `dummy` interfaces (e.g., `mon-ge-0-0-1`,
`mon-ge-0-0-2`) that mirror packets from the userspace forwarding path. These
appear as normal Linux network interfaces that `tcpdump` can attach to.

```
$ tcpdump -ni mon-ge-0-0-1          # ingress on ge-0-0-1
$ tcpdump -ni mon-ge-0-0-2-egress   # egress on ge-0-0-2
```

### Why virtual interfaces instead of pcap files

- `tcpdump` works unchanged — no custom tools needed
- Live streaming — no need to stop/start capture or rotate files
- Kernel BPF filters on the tap interface — `tcpdump -ni mon-ge-0-0-1 'tcp port 443'`
  filters at the socket level (the worker still enqueues all captured packets
  to the tap; filtering happens on the read side, not the write side)
- Works with `wireshark`, `tshark`, `ngrep`, and any libpcap consumer
- Multiple concurrent captures with different filters are trivial

### Why not AF_PACKET or pcap files directly

- AF_PACKET requires a raw socket per capture point — harder to manage
- pcap files need rotation, naming, and cleanup
- Neither integrates with `tcpdump -i <interface>` out of the box
- tap/dummy interfaces are zero-overhead when nobody is listening (TX queue
  drains immediately with no readers)

## Architecture

```
                    Worker Thread
                         |
     ┌───────────────────┼───────────────────┐
     |                   |                   |
  RX Ring            Processing           TX Ring
     |                   |                   |
     v                   v                   v
 [Ingress]          [Decision]          [Egress]
  capture             capture            capture
  point               point              point
     |                   |                   |
     └───────┬───────────┼───────────────────┘
             |           |
             v           v
        ┌────────────────────┐
        │  CaptureDispatcher │   (per-worker, lock-free)
        │                    │
        │  Ring buffer of    │
        │  (metadata, bytes) │
        │  entries           │
        └────────┬───────────┘
                 |
                 v
        ┌────────────────────┐
        │  CaptureWriter     │   (dedicated thread)
        │                    │
        │  Reads from ring   │
        │  Writes to tap fds │
        │  Rate-limited      │
        └────────────────────┘
                 |
           ┌─────┴──────┐
           v             v
      mon-ge-0-0-1  mon-ge-0-0-2
       (tap dev)     (tap dev)
           |             |
      tcpdump -ni   tcpdump -ni
```

## Capture points

### 1. Ingress capture

**Location**: `afxdp.rs:poll_binding()`, after RX ring read, before metadata
parse.

```rust
// Line ~2144 in poll_binding
if let Some(rx_frame) = unsafe { &*area }.slice(desc.addr as usize, desc.len as usize) {
    // CAPTURE POINT: raw ingress frame with Ethernet header
    if capture.ingress_enabled(binding.ifindex) {
        capture.enqueue(CapturePoint::Ingress, binding.ifindex, rx_frame);
    }
    // ... continue with metadata parse, session lookup, etc.
}
```

**What's captured**: Raw frame as received by the NIC. Includes Ethernet
header, VLAN tags (if present), IP header, payload. No metadata prepended.

### 2. Egress capture

**Location**: `userspace-dp/src/afxdp/tx/transmit.rs::transmit_batch()`, after frame is written to
UMEM but before TX ring submission.

```rust
// In transmit_batch, after copy_from_slice:
frame.copy_from_slice(&req.bytes);
if capture.egress_enabled(binding.ifindex) {
    capture.enqueue(CapturePoint::Egress, binding.ifindex, &req.bytes);
}
```

And in `transmit_prepared_batch()` for the direct-TX path:

```rust
// After prepared frame is in UMEM:
if let Some(frame_data) = binding.umem.area().slice(req.offset as usize, req.len as usize) {
    if capture.egress_enabled(binding.ifindex) {
        capture.enqueue(CapturePoint::Egress, binding.ifindex, frame_data);
    }
}
```

**What's captured**: Fully rewritten frame. Ethernet MACs are the egress
values, IP addresses reflect NAT rewrites, TTL is decremented, checksums
are updated. This is what the peer/next-hop actually receives.

### 3. Drop capture

**Location**: `afxdp.rs:poll_binding()`, at each drop/deny point.

```rust
// Policy deny (line ~2908):
if decision == PolicyDecision::Deny {
    if capture.drops_enabled(binding.ifindex) {
        capture.enqueue_drop(binding.ifindex, source_frame, "policy_deny", rule_id);
    }
    // recycle frame
}

// Screen drop:
if screen_verdict == ScreenVerdict::Drop {
    if capture.drops_enabled(binding.ifindex) {
        capture.enqueue_drop(binding.ifindex, source_frame, "screen", check_name);
    }
}
```

Drop captures include the original (unrewritten) frame plus a reason string.

## Data structures

### CaptureConfig (per-worker, set via control socket)

```rust
struct CaptureConfig {
    /// Dense bitset indexed by ifindex (max 1024 interfaces).
    /// Single array lookup — NOT a HashMap — so the enabled check
    /// is truly a single branch on a bool, not a hash probe.
    ingress: [bool; 1024],
    egress: [bool; 1024],
    drops: bool,
    /// 1-in-N sampling (1 = capture all, 100 = 1%). 0 = disabled.
    sampling_rate: u32,
    /// Max bytes per frame to capture (0 = full frame)
    snap_len: u32,
    /// Ring buffer size (entries)
    ring_size: u32,
}
```

### CaptureEntry (ring buffer element)

```rust
/// Fixed-size entry to avoid per-packet heap allocation.
/// Uses an inline byte array sized to snap_len (default 256).
struct CaptureEntry {
    timestamp_ns: u64,         // monotonic_nanos()
    ifindex: i32,              // ingress or egress interface
    point: CapturePoint,       // Ingress / Egress / Drop
    original_len: u32,         // full frame length
    captured_len: u32,         // after snap_len truncation
    drop_reason: Option<&'static str>,
    bytes: [u8; 256],          // inline buffer, no heap allocation
}

enum CapturePoint {
    Ingress,
    Egress,
    Drop,
}
```

### CaptureDispatcher (per-worker, lock-free)

```rust
struct CaptureDispatcher {
    config: CaptureConfig,
    ring: crossbeam_queue::ArrayQueue<CaptureEntry>,
    stats: CaptureStats,
    sample_counter: u32,  // mutable — owned by worker thread, no sharing
}

impl CaptureDispatcher {
    fn enqueue(&mut self, point: CapturePoint, ifindex: i32, frame: &[u8]) {
        // Sampling check (sampling_rate=0 means disabled)
        if self.config.sampling_rate == 0 {
            return;
        }
        self.sample_counter = self.sample_counter.wrapping_add(1);
        if self.sample_counter % self.config.sampling_rate != 0 {
            return;
        }
        // Snap length truncation
        let max_snap = 256; // matches CaptureEntry inline buffer size
        let snap = if self.config.snap_len > 0 {
            frame.len().min(self.config.snap_len as usize).min(max_snap)
        } else {
            frame.len().min(max_snap)
        };
        // Build entry with inline buffer — no heap allocation
        let mut entry = CaptureEntry {
            timestamp_ns: monotonic_nanos(),
            ifindex,
            point,
            original_len: frame.len() as u32,
            captured_len: snap as u32,
            drop_reason: None,
            bytes: [0u8; 256],
        };
        entry.bytes[..snap].copy_from_slice(&frame[..snap]);
        // Try non-blocking enqueue (drop capture entry if ring full,
        // NEVER drop the actual packet)
        if self.ring.push(entry).is_err() {
            self.stats.ring_drops += 1;
        }
    }
}
```

### CaptureWriter (dedicated thread)

```rust
struct CaptureWriter {
    /// Map from (ifindex, CapturePoint) to tap fd
    tap_fds: FastMap<(i32, CapturePoint), RawFd>,
    /// Shared ring references from all workers
    worker_rings: Vec<Arc<ArrayQueue<CaptureEntry>>>,
}

impl CaptureWriter {
    fn run(&self) {
        loop {
            let mut did_work = false;
            for ring in &self.worker_rings {
                while let Some(entry) = ring.pop() {
                    let key = (entry.ifindex, entry.point);
                    if let Some(&fd) = self.tap_fds.get(&key) {
                        let _ = unsafe {
                            libc::write(fd, entry.bytes.as_ptr().cast(), entry.captured_len as usize)
                        };
                    }
                    did_work = true;
                }
            }
            if !did_work {
                std::thread::sleep(Duration::from_micros(100));
            }
        }
    }
}
```

## Control interface

### CLI syntax (Junos-style)

```
# Enable capture on a specific interface
set system dataplane capture interface ge-0-0-1 direction ingress
set system dataplane capture interface ge-0-0-1 direction egress
set system dataplane capture interface ge-0-0-2 direction both
set system dataplane capture snap-length 256
set system dataplane capture sampling-rate 100

# Operational commands
monitor traffic interface ge-0-0-1         # like Junos monitor traffic
monitor traffic interface ge-0-0-1 detail  # with packet decode
```

### Control protocol extension

```go
// protocol.go
type CaptureControlRequest struct {
    Enabled      bool           `json:"enabled"`
    Interfaces   []CaptureIface `json:"interfaces"`
    SnapLength   int            `json:"snap_length"`
    SamplingRate int            `json:"sampling_rate"`
    RingSize     int            `json:"ring_size"`
}

type CaptureIface struct {
    Ifindex   int    `json:"ifindex"`
    Interface string `json:"interface"`
    Ingress   bool   `json:"ingress"`
    Egress    bool   `json:"egress"`
    Drops     bool   `json:"drops"`
}
```

### Go manager creates tap interfaces

```go
func (m *Manager) EnableCapture(cfg CaptureConfig) error {
    for _, iface := range cfg.Interfaces {
        tapName := fmt.Sprintf("mon-%s", config.LinuxIfName(iface.Interface))
        // Create tap interface
        tap, err := createTapInterface(tapName)
        if err != nil { return err }
        // Bring up (tcpdump needs it UP)
        netlink.LinkSetUp(tap)
        // Send capture config to Rust helper
        m.requestLocked(ControlRequest{
            Type: "capture",
            Capture: &CaptureControlRequest{
                Enabled: true,
                Interfaces: []CaptureIface{{
                    Ifindex: iface.Ifindex,
                    Ingress: true,
                    Egress: true,
                }},
            },
        }, &status)
    }
    return nil
}
```

## Performance considerations

### Zero overhead when disabled

When capture is disabled (the default):
- `capture.ingress_enabled(ifindex)` is an array index + branch on a bool
  (the `[bool; 1024]` bitset is constant-time, no hash probe)
- The compiler can predict this branch as not-taken
- No allocation, no ring access, no tap write
- Cost: ~1 CPU cycle per packet (branch prediction hit)

### Controlled overhead when enabled

- **Sampling**: `sampling_rate=100` means only 1% of packets are captured
- **Snap length**: `snap_len=96` captures headers only (no payload copy)
- **Ring buffer**: Lock-free `ArrayQueue` — no mutex on the hot path
- **Dedicated writer thread**: Tap writes happen off the forwarding workers
- **Backpressure**: Ring full → drop capture entry (not the packet)

### Estimated overhead

| Scenario | Overhead |
|----------|----------|
| Disabled | ~0 (branch prediction) |
| Enabled, 1:100 sampling, snap=96 | <1% throughput loss |
| Enabled, full capture, full frame | ~5-10% throughput loss |
| Enabled, full capture, full frame, high rate | Writer thread becomes bottleneck; ring drops increase |

## Implementation phases

### Phase 1: Ingress-only capture via TAP

Use TAP interfaces (IFF_TAP, not IFF_TUN) to preserve the full L2
Ethernet frame including VLAN tags. TUN is L3-only and would strip
the Ethernet header.

Reuse the existing `SlowPathReinjector` pattern for async writes:
- Create a TAP device per monitored interface (e.g., `mon-ge-0-0-1`)
- In `poll_binding()`, after RX read, conditionally enqueue to ring
- `CaptureWriter` thread reads ring and writes to TAP fds
- Control via existing control socket (`"capture"` request type)
- No egress capture yet

**Deliverable**: `tcpdump -ni mon-ge-0-0-1` shows ingress packets
with full Ethernet headers

### Phase 2: Egress capture + ring buffer

- Add capture points in `transmit_batch()` and `transmit_prepared_batch()`
- Create `capture.rs` module with `CaptureDispatcher` + `CaptureWriter`
- Replace direct TUN writes with ring buffer + dedicated writer thread
- Support egress tap interfaces (`mon-ge-0-0-1-egress`)

**Deliverable**: `tcpdump -ni mon-ge-0-0-1-egress` shows rewritten frames

### Phase 3: Drop capture + CLI integration

- Add capture points at policy deny, screen drop, session reject
- Create `mon-drops` virtual interface for all drops
- Add `monitor traffic` CLI command
- Add `show system dataplane capture` status command

### Phase 4: Sampling, snap length, per-zone capture

- Implement sampling_rate and snap_len
- Add per-zone capture (capture all interfaces in a zone)
- Add BPF filter pass-through (set kernel BPF filter on tap interface)

## Alternative: pcapng file writer

For offline analysis, an alternative to tap interfaces is writing pcapng
files directly from the Rust helper:

```rust
struct PcapWriter {
    file: BufWriter<File>,
    snap_len: u32,
}

impl PcapWriter {
    fn write_packet(&mut self, ts: u64, ifindex: i32, frame: &[u8]) {
        // Write Enhanced Packet Block (EPB) with interface ID
        // pcapng format allows per-packet interface association
    }
}
```

This avoids the tap interface overhead but loses live `tcpdump` capability.
Could be offered as a `capture-to-file` option alongside tap interfaces.

## Files to create/modify

| File | Change |
|------|--------|
| `userspace-dp/src/capture.rs` | NEW: CaptureDispatcher, CaptureWriter, CaptureConfig |
| `userspace-dp/src/afxdp.rs` | Add capture hooks in poll_binding |
| `userspace-dp/src/afxdp/tx/transmit.rs` | Add capture hooks in transmit paths |
| `userspace-dp/src/main.rs` | Handle "capture" control requests |
| `pkg/dataplane/userspace/protocol.go` | CaptureControlRequest struct |
| `pkg/dataplane/userspace/manager.go` | EnableCapture, tap interface lifecycle |
| `pkg/config/ast.go` | Schema for `set system dataplane capture` |
| `pkg/config/compiler.go` | Compile capture config |
| `pkg/cmdtree/tree.go` | `monitor traffic` command |
