# Session Sync Design

## Goal

Improve HA session sync so that it is:

- fast enough to preserve established traffic during failover
- explicit enough to gate failover admission correctly
- simple enough to reason about ownership and replay semantics
- efficient enough to avoid treating a 1-second map sweep as the primary steady-state producer

This document is a forward-looking design note. It complements the current-state
writeup in [session-sync-architecture.md](./session-sync-architecture.md).

**Current state baseline** (as of PR #265): the architecture doc covers bulk
sync with sender-side ack, incremental sweep, depth-counted pause/resume,
barrier-ordered demotion prep with retryable admission errors, userspace delta
filtering by `FabricRedirect`/`FabricIngress`/`local_delivery`, and readiness
generation guards. None of that has changed the fundamental producer model
described below — the sweep is still the primary kernel producer and the
userspace helper is still polled via RPC.

## Current State

Today the architecture is split across:

- [pkg/cluster/sync.go](../pkg/cluster/sync.go)
  - sync wire protocol
  - bulk sync
  - delete journal
  - incremental sweep
  - barriers
- [pkg/daemon/daemon.go](../pkg/daemon/daemon.go)
  - readiness gating
  - ownership filtering
  - bulk-prime retry
  - userspace delta drain/export
  - graceful demotion prep
- [pkg/dataplane/userspace/manager.go](../pkg/dataplane/userspace/manager.go)
  - helper RPCs for delta drain/export and cluster-synced install
- [userspace-dp/src/afxdp/session_glue.rs](../userspace-dp/src/afxdp/session_glue.rs)
  - userspace session lifecycle inside the Rust helper

That split is not accidental. It reflects two different responsibilities:

1. cluster control-plane ownership and failover gating
2. dataplane-local session production and install

The problem is not that the current split is conceptually wrong. The problem is
that the steady-state producer model is still too sweep-heavy, and the userspace
helper is still integrated through polling instead of an ordered stream.

## What Is Wrong With The Current Model

### 1. The kernel sweep is still treated as a primary producer

The sweep in [pkg/cluster/sync.go](../pkg/cluster/sync.go) is still doing the
bulk of steady-state kernel session discovery by scanning `sessions_v4` /
`sessions_v6` on a timer and comparing `Created` / `LastSeen` against the prior
window.

That has three problems:

- it is too coarse for failover-sensitive traffic
- it creates unnecessary work when nothing materially changed
- it couples sync freshness to sweep cadence instead of actual session events

### 2. Userspace helper sync is still polled

The Rust helper currently exports steady-state session changes through
`DrainSessionDeltas(...)`, which the daemon polls periodically.

That means the lowest-latency session producer in the system is still forced
through a polling boundary. This adds delay, complexity, and another place where
quiescence has to fight background work.

### 3. Ownership and filtering live in the right place, but too late in the path

The daemon is currently the right owner for HA filtering decisions such as:

- `ShouldSyncZone(...)`
- `IsPrimaryForRGFn(...)`
- stale-owner `FabricRedirect` exceptions
- `local_delivery` suppression

But we are paying for those decisions after collecting data through broad sweeps
or polling loops rather than from narrower event sources.

### 4. Readiness and replication are now more sophisticated than the producer model

Current failover admission already depends on:

- inbound bulk receipt
- outbound `BulkAck`
- quiescence
- barriers
- explicit userspace export/drain during demotion prep

That is a stronger control-plane model than the producer side deserves. The
producer side still behaves like a periodic best-effort replication loop.

## Options Considered

### Option A: Keep Everything In `xpfd`

That means:

- keep the sync transport in Go
- keep kernel sweeps as the main producer
- keep helper polling through RPC
- improve tuning around the edges

#### Pros

- minimal architectural change
- no new cross-language streaming interface
- easiest short-term implementation path

#### Cons

- preserves the wrong steady-state producer model
- keeps helper-originated events behind polling latency
- keeps sweeping as the main answer to missing kernel session events

This is not the right end state.

### Option B: Move Session Sync Into Rust

That means:

- Rust helper owns peer TCP sync transport
- Rust helper owns bulk sync, barriers, replay, and readiness
- Go daemon becomes mostly a consumer of Rust sync state

#### Pros

- one runtime owns all userspace session production and transport
- avoids helper-to-daemon polling for userspace sessions

#### Cons

- pushes HA/control-plane logic into the dataplane runtime
- duplicates or fragments ownership logic that already lives in Go
- complicates VRRP / RG admission / config / fence / failover sequencing
- creates an awkward split for kernel/BPF-originated sessions, which still do
  not originate in Rust

This is the wrong tradeoff. The session-sync transport is part of the HA
control plane, not just the userspace dataplane.

### Option C: Hybrid Event-First Design (Recommended)

Keep the HA/session-sync control plane in Go, but replace broad polling with
narrower event producers.

#### Core idea

- `xpfd` remains the owner of:
  - peer transport
  - bulk sync
  - readiness
  - barriers
  - demotion handoff
  - ownership filtering
- the Rust helper becomes a streaming producer for userspace session events
- kernel/BPF session sync becomes event-first, with sweep reduced to
  reconciliation

This preserves architectural ownership while fixing the main inefficiencies.

## Recommendation

Use Option C.

In concrete terms:

1. keep `pkg/cluster/sync.go` as the sync protocol owner
2. keep failover admission and demotion sequencing in `pkg/daemon/daemon.go`
3. replace helper delta polling with a long-lived ordered local stream
4. make kernel sync event-first
5. demote the timer sweep to reconciliation / backstop duty

## Target Architecture

### 1. `xpfd` remains the authoritative sync coordinator

The daemon should continue to own:

- sync transport connection management
- bulk sync / `BulkAck`
- ownership filtering by zone / RG
- failover readiness
- graceful demotion barriers and quiescence
- install into kernel dataplane and userspace manager

Reason:

- HA ownership is already expressed here
- cluster readiness already gates promotion here
- other cluster control-plane messages already live on the same transport here

Moving this into Rust would not simplify the system. It would shift the wrong
kind of responsibility into the dataplane helper.

### 2. Replace helper polling with helper-to-daemon streaming

Instead of periodic `DrainSessionDeltas(...)`, use a long-lived local stream
between the helper and `xpfd`.

#### Properties

- ordered delivery
- monotonically increasing sequence number
- bounded local backlog
- daemon ack of last applied sequence
- reconnect/resume semantics
- explicit snapshot/export remains available for reconnect recovery and
  demotion prep

#### Why this is better

- lower latency than polling
- no need to wake a drain loop to discover nothing changed
- simpler quiescence during demotion because the stream can be paused or
  checkpointed explicitly

### 3. Make kernel sync event-first

Kernel/BPF sessions should not depend primarily on a 1-second or 15-second map
scan.

The design target should be:

- immediate event for session create
- immediate event for delete
- event for material state transitions
- event for ownership-relevant changes
- sweep only to recover missed events or reconnect gaps

The ring-buffer callback already points in this direction. It should become a
first-class producer instead of a small optimization in front of the sweep.

### 4. Sweep becomes reconciliation, not primary replication

The sweep should still exist, but with a different job:

- catch missed events
- recover after disconnect or queue overflow
- verify convergence
- repair journal or event loss

It should run less frequently and carry less semantic weight.

A reconciliation sweep is still valuable. A reconciliation sweep as the main
steady-state sync producer is not.

### 5. Sync only material changes

The current sweep logic keys off `Created` / `LastSeen` movement. That is too
coarse.

The better model is to sync when one of these changes:

- session create
- session delete
- TCP state change
- NAT allocation / NAT tuple change
- disposition / ownership change
- timeout bucket change that matters for failover survivability

For long-lived established flows, frequent `LastSeen` movement is usually not a
reason to send another sync update.

## Detailed Proposal

### Local producer model

#### Kernel producer

A kernel-side producer emits:

- `SessionCreate`
- `SessionUpdate`
- `SessionDelete`

Updates are emitted only for material state changes.

The event contains:

- key
- address family
- reason / update class

The daemon can fetch the full session value by key if needed before queueing it
onto peer sync.

#### Userspace producer

The Rust helper emits:

- `SessionOpen`
- `SessionUpdate`
- `SessionClose`
- optional `SessionAliasOpen/Close` for translated forward-wire aliases

These events flow over a local ordered stream rather than RPC polling.

#### Reconciliation producer

A slower reconciliation pass periodically verifies:

- local producer health
- peer convergence
- no unacked backlog explosion
- no missed deletes / stale peer-owned sessions

### Sync coordinator behavior

The coordinator in `xpfd` should:

- accept events from kernel and helper producers
- apply ownership filtering once
- queue peer sync once
- keep bulk sync as reconnect/bootstrap only
- keep explicit demotion export as a targeted handoff tool

That gives one control-plane authority, not two.

### Why Not Put Kernel Session Sync In Rust

Because the kernel session tables are not Rust-owned.

The helper can own userspace-originated sessions because it created them. It is
not the right owner for:

- kernel conntrack lifetime
- cluster readiness
- RG ownership filtering
- config / failover / fence sequencing

Trying to centralize all sync in Rust would make userspace sessions simpler, but
kernel sessions and HA control-plane behavior more complicated.

That is a net loss.

## Phased Plan

### Phase 1: Replace helper polling with a local stream — DONE

Implemented in commits `a597d3c1` (Rust producer) and `a09b24f2` (Go consumer):

- Binary-framed event stream over `/run/xpf/userspace-dp-events.sock`
- 9 frame types: SessionOpen/Close/Update, Ack, Pause/Resume, DrainRequest/DrainComplete, FullResync
- Sequence numbers + replay buffer for reconnect
- Demotion-prep: Pause → DrainRequest → Barrier → Resume
- Automatic fallback to RPC polling when stream disconnected
- Validated: 3-cycle failover test, 0 drops, 14.5-16.4 Gbps

### Phase 2: Promote kernel event sync to primary path

Implement:

- structured session-open / delete events from the kernel-side producer path
- on-demand full-session fetch by key for sync encoding
- minimal update classes for material state changes

Reduce dependence on:

- full map scans every active interval

### Phase 3: Convert sweep into reconciliation

After Phase 2 is stable:

- lengthen sweep intervals
- stop using sweep as the main fresh-session discovery mechanism
- run sweep mainly for convergence repair and missed-event detection

### Phase 4: Reduce update churn

Add more selective update rules:

- timeout bucket changes instead of raw `LastSeen`
- TCP state transitions
- NAT tuple changes
- ownership / disposition changes

That should reduce peer sync traffic substantially without making failover
worse.

## Operational Improvements This Enables

If the design above is implemented, we should get:

- lower steady-state sync CPU
- lower sync latency for userspace-originated sessions
- less demotion-prep fighting with background polling loops
- clearer readiness semantics
- less dependence on arbitrary 1-second scan cadence
- simpler debugging because event provenance is explicit

## Acceptance Criteria

The redesign should not be considered complete unless all of these are true:

1. helper-originated sessions are streamed, not polled, in steady state
2. kernel session create/delete are event-first, not sweep-first
3. periodic sweep can be slowed substantially without failover regression
4. graceful failover does not require broad background drain loops to settle
5. crash/rejoin still converges correctly with reconnect bulk sync
6. ownership filtering remains centralized in `xpfd`
7. the peer sync transport and readiness model stay single-owner and coherent

## Non-Goals

This design does **not** propose:

- rewriting HA/session-sync transport in Rust
- deleting bulk sync
- deleting reconciliation sweep entirely
- making the helper the owner of RG/VRRP/failover admission

## Bottom Line

The problem is not that session sync lives in Go.

The problem is that the producer side is still too polling-oriented.

The right redesign is:

- keep the HA/session-sync control plane in `xpfd`
- move userspace session production to a local stream
- move kernel session sync to an event-first model
- keep sweep as reconciliation, not as the primary steady-state source

---

## Phase 1 Protocol Specification

### Problem

The Rust helper buffers session deltas in per-binding ring buffers
(`pending_session_deltas`). The Go daemon polls these via single-use Unix
socket RPC (`drain_session_deltas`). Each poll opens a new connection, sends
JSON, reads JSON, closes. Latency = poll interval + round-trip. Deltas are
dropped when the ring overflows.

### Design: Second Unix Socket for Event Stream

Add a dedicated **event stream socket** alongside the existing control socket.
The control socket keeps its request/response RPC semantics. The event socket
is a long-lived unidirectional stream: helper pushes, daemon reads.

```
Existing:   daemon --[control.sock]--> helper    (request/response, JSON lines)
New:        helper --[events.sock]---> daemon    (push stream, binary framed)
```

### Transport

- **Path**: `/run/xpf/userspace-dp-events.sock` (derived from control socket path)
- **Direction**: Helper connects to daemon listener (daemon creates the socket
  before spawning the helper, helper dials on startup)
- **Lifetime**: Single persistent connection. Helper reconnects on disconnect.
- **Protocol**: Length-prefixed binary frames (NOT JSON lines — too expensive at
  high event rates)

### Wire Format

```
Frame:
  [0:4]   Length (uint32 little-endian, payload only)
  [4:5]   Type (uint8)
  [5:8]   Reserved
  [8:16]  Sequence (uint64 little-endian, monotonically increasing)
  [16..]  Payload (type-specific, binary)

Types:
  1 = SessionOpen
  2 = SessionClose
  3 = SessionUpdate
  4 = Ack (daemon → helper)
  5 = Pause (daemon → helper)
  6 = Resume (daemon → helper)
  7 = DrainRequest (daemon → helper, with target sequence)
  8 = DrainComplete (helper → daemon, confirms all events up to seq flushed)
```

**Note**: The event socket is bidirectional for control (Ack/Pause/Resume flow
from daemon to helper), but the primary data flow is helper → daemon.

### Session Event Payload

SessionOpen and SessionUpdate share the same payload:

```
  [0]     AddrFamily (4 or 6)
  [1]     Protocol (TCP=6, UDP=17, ICMP=1, etc.)
  [2:4]   SrcPort (uint16 LE)
  [4:6]   DstPort (uint16 LE)
  [6:8]   NATSrcPort (uint16 LE)
  [8:10]  NATDstPort (uint16 LE)
  [10:14] OwnerRGID (int32 LE)       — #2467: widened from int16
  [14:18] EgressIfindex (int32 LE)   — #2467: widened from int16
  [18:22] TXIfindex (int32 LE)       — #2467: widened from int16
  [22:24] TunnelEndpointID (uint16 LE)
  [24:26] TXVLANID (uint16 LE)
  [26]    Flags (bit0=FabricRedirect, bit1=FabricIngress, bit2=IsReverse)
  [27:29] IngressZoneID (uint16 LE) — #3075: widened from u8
  [29:31] EgressZoneID (uint16 LE)  — #3075: widened from u8
  [31]    Disposition (uint8: 0=Accept, 1=LocalDelivery, 2=Reject, ...)
  [32:36] SrcIP (4 bytes for v4, first 4 of 16 for v6)
  [36:40] DstIP
  [40:44] NATSrcIP
  [44:48] NATDstIP
  For IPv6: addresses are 16 bytes each (payload is larger)
  After addresses:
  [N:N+6]  NeighborMAC (6 bytes, zero if unresolved)
  [N+6:N+12] SrcMAC (6 bytes)
  [N+12:N+16] NextHop (4 bytes v4 or 16 bytes v6, zero if direct)
```

SessionClose payload is minimal:

```
  [0]     AddrFamily (4 or 6)
  [1]     Protocol
  [2:4]   SrcPort
  [4:6]   DstPort
  [6:10]  SrcIP (4 or 16 bytes)
  [10:14] DstIP (4 or 16 bytes)
  [N:N+4] OwnerRGID (int32 LE)       — #2467: widened from int16
  [N+4]   Flags (bit0=FabricRedirect, bit1=FabricIngress)
  [N+5:N+7] IngressZoneID (uint16 LE) — #3075: widened from u8 (#919/#922 origin)
  [N+7:N+9] EgressZoneID (uint16 LE)  — #3075: widened from u8 (#919/#922 origin)
```

> **#2467 (breaking wire change):** the three identity fields in the open
> frame (`OwnerRGID`, `EgressIfindex`, `TXIfindex`) and the close frame's
> `OwnerRGID` were widened from signed 16-bit to signed 32-bit. Linux
> ifindexes are a full `int` and wrap negative past 32767 on long-running
> systems with interface churn. The event-stream frame is unversioned and
> fixed-layout, so this is NOT a rolling-upgrade-compatible change: the Rust
> encoder (`event_stream/codec.rs`) and the Go decoder
> (`pkg/dataplane/userspace/eventstream.go`) must be deployed together. They
> always are — `xpfd` and the `userspace-dp` helper ship as one binary set.

### Flow Control

**Ack**: Daemon sends Ack frames with the highest consumed sequence number.
Helper can discard events up to that sequence from its replay buffer.

**Backpressure**: Helper uses non-blocking writes. Workers enqueue events with
a non-blocking `try_send` into a bounded mpsc channel (`CHANNEL_CAPACITY` =
8192); a full channel drops the newest event and increments
`event_stream_dropped` (per-kind RT_FLOW telemetry also bumps its `queue_full`
counter). The I/O thread drains the channel into a pending socket-write
backlog (`write_buf`) and writes non-blocking; on `WouldBlock` it keeps the
remainder for the next cycle. Daemon detects gaps via sequence numbers and can
request a full reconciliation.

**Seq/enqueue atomicity (#3878)**: because the daemon detects gaps via sequence
numbers and has zero reorder tolerance, the seq allocation and the channel
enqueue happen together under `producer_seq_lock` — the seq embedded in a frame
is monotonic in wire (channel-FIFO) order across all producer threads. A
full-channel drop rolls the allocated seq back rather than burning it, so a
saturation drop does not open a hole that the reader would mistake for a lost
session mutation and answer with a spurious full owner-RG resync (self-
amplifying during recovery). See `event_stream/README.md` for the mechanism.

The idle **keepalive** also rides the canonical write path (#2883): the
connected loop enqueues the keepalive frame into `write_buf` rather than calling
`write_all` directly. Before #2883 the keepalive used `write_all` on the
nonblocking socket and treated ANY error — including `WouldBlock` when the
kernel send buffer is full under a slow reader — as fatal, returning an
immediate reconnect. That bypassed the partial-write/WouldBlock backpressure and
stall accounting and caused reconnect churn → replay storms (which then hit the
blocking replay path, #2877). Routed through `write_buf`, a keepalive WouldBlock
is ordinary backpressure (retained for the next flush); a genuinely dead
consumer is still detected by the normal socket-error / EOF path.

The reconnect **replay** (`replay_buffered`) and demotion **drain**
(`handle_drain_request`) paths write on the SAME nonblocking socket via a
bounded, stop-aware writer (`write_all_backpressured`, #2877) — they do NOT
flip the socket to blocking and call `write_all`. On `WouldBlock` the writer
sleeps `REPLAY_DRAIN_WRITE_POLL` and retries, polling the I/O-thread stop flag
each cycle and bailing at a `REPLAY_DRAIN_WRITE_DEADLINE` (5s) shared across the
whole pass. Before #2877 these two paths used a blocking `write_all` with no
deadline and no stop check: a daemon that connected but stopped reading wedged
the I/O thread in the blocking write, and because `EventStreamSender::stop`
joins that thread, the write-blocked thread could not observe the stop flag —
so helper stop / RG demotion hung. The stop flag now lives in the shared state
(`EventStreamShared.stop`) so every I/O-thread function observes it; a stuck
reader during replay forces a reconnect, and during drain causes DrainComplete
to be withheld (the daemon then times out and refuses demotion, #2876) instead
of wedging.

The bounded channel is the ONLY backpressure surface. The write backlog is
capped at `WRITE_BACKLOG_MAX_BYTES` (16 MiB ≈ 8× a fully-drained 8192×256 B
channel, since `EventFrame` is a fixed `[u8; 256]`; `drain_channel_into_write_buf`
in `event_stream/mod.rs`, #2381). The cap is tested at the top of the drain
loop, so the effective bound is `cap + one max EventFrame` (≤ 256 B) — the
in-flight frame already pulled can carry `write_buf` just past 16 MiB before the
drain halts; the overshoot is bounded and accepted. A wedged daemon that keeps the socket open
but stops reading (writes perpetually `WouldBlock`) would otherwise let the
I/O thread migrate the whole channel into the heap-backed `write_buf` every
cycle while the channel refills from `try_send`, growing `write_buf` without
bound → helper OOM / allocator pressure on the **forwarding plane**. Once the
backlog hits the cap the drain halts, leaving frames in the bounded channel so
producers shed (newest-first, counted) there instead; each capped pass
increments `event_stream_write_stalls`
(`xpf_userspace_event_stream_producer_frames_total{result="write_stalled"}`).
Oldest queued + replay frames are preserved so RT_FLOW stays current. **Core
invariant: the data plane never stalls because a telemetry consumer is slow —
a stuck consumer degrades telemetry (bounded, counted loss + a stall
counter + eventual keepalive-driven reconnect/FullResync), never forwarding.**

**Pause/Resume**: Daemon sends Pause to stop event emission (used during
demotion prep). Helper buffers events during pause. Daemon sends Resume to
restart. Events accumulated during pause are flushed in order.

**DrainRequest/DrainComplete**: Daemon sends DrainRequest with a target
sequence. Helper flushes all buffered events up to that sequence and sends
DrainComplete. This replaces `ExportOwnerRGSessions` RPC for demotion prep —
the daemon drains the stream to current head instead of doing a separate RPC
export.

The fence is honored strictly (#2882): `handle_drain_request` writes ONLY
buffered frames with `seq <= target_seq` and reports DrainComplete with the
fence target (the highest seq `<= target` actually flushed; `target_seq` when
the buffer held nothing at/below the fence because it was already ACK-trimmed).
It does NOT write every frame in the replay buffer, and it does NOT report
`replay_buf.back().seq` (which can exceed the target). Before #2882 the handler
flushed and reported the current replay head, changing the contract from "fence
up to target" to "dump current replay head" — that masks holes and couples
demotion correctness to unrelated later-buffered frames. DrainComplete is still
withheld entirely if the fence was never reached within the drain timeout
(#2876) or a frame write failed against a stuck/stopping reader (#2877).

**Lossless-demotion fence for session deltas (#2875).** A paused drain is the
stable window the future owner reads before demotion completes, but the replay
buffer is bounded (`REPLAY_BUFFER_CAPACITY`, 4096). A pause long enough to
overrun the buffer evicts the oldest frames (the #2382 path), and an evicted
frame may be an HA session-sync delta (`SessionOpen`/`SessionUpdate`/
`SessionClose`). Reporting `DrainComplete` after such an eviction would finish
demotion even though the evicted session mutation never reached the new owner —
silent session loss on failover. The drain is therefore POISONED on any
session-delta eviction during pause: `evict_replay_frame` sets
`session_evicted_while_paused` when it evicts a frame whose
`EventFrame::is_session_sync()` is true while the helper is paused, and
`handle_drain_request` then WITHHOLDS `DrainComplete` and emits a `FullResync`
(type 9) instead — the same recovery path as the reconnect replay-gap below.
The daemon's `SendDrainRequest` receives no DrainComplete, times out, and
refuses to proceed with demotion until the resync re-exports full session
state. The fix is poison-on-loss, NOT an unbounded buffer (that would be a
memory DoS on the forwarding plane). Telemetry eviction (RT_FLOW
deny/screen/filter + session create/close frames) does NOT poison — those are
not session-sync deltas, and poisoning on them would cause spurious resyncs.
Poison lifecycle: set on session-frame eviction during pause; cleared at
pause-start (`MSG_PAUSE`, so each fresh pause window starts clean) and after a
poisoned drain emits its `FullResync`.

**Control-frame payload cap (#2879).** `process_control_frames` reads the
32-bit length from each daemon→helper frame and waits for the full frame before
parsing. All current daemon→helper opcodes (Ack/Pause/Resume/DrainRequest) are
header-only (zero payload), so `MAX_CONTROL_PAYLOAD_LEN` is `0`. The parser
validates the declared length on the header alone (the loop already requires a
full 16-byte header) BEFORE waiting for the rest of the frame: any
`payload_len` above the cap can never form a valid control frame, so the helper
disconnects (reconnect clears `ctrl_read_buf`) instead of buffering. Without
this a buggy or compromised local daemon could send a header with
`payload_len = 1<<30` and trickle bytes, growing `ctrl_read_buf` without bound
on the forwarding plane while consuming nothing. A legitimately partial
header-only frame still parses once complete — a split HEADER never reaches the
length check, and a zero `payload_len` always passes. The constant is named so
a future payload-carrying opcode raises it deliberately rather than the parser
honoring an arbitrary 32-bit length.

### Reconnect / Replay

On disconnect, the helper retains its replay buffer (bounded, ~4096 events per
binding). On reconnect, it replays from the last acked sequence. If the buffer
has been trimmed past the last acked sequence (long disconnect), it sends a
special `FullResync` frame (type 9) that tells the daemon to treat this as a
fresh start and request a bulk export. The helper retains the stale replay
window until the daemon ACKs the `FullResync`; otherwise an unacked resync could
be lost across a second reconnect. HA backup nodes ACK and ignore session
events because they are permanent non-owners, while transient primary readiness
gaps withhold ACK for replay.

**Go reader re-baselines `prevSeq` on the barrier (#5362)**: the producer emits
the replay-gap `FullResync(S)` in wire==seq order (#5361), so `S` is the new
sequence baseline and the next live delta is `S+1`. The daemon's Go reader
(`eventstream.go` `readLoop`) must advance its local `prevSeq` to `S` when it
successfully dispatches the barrier — exactly as the session-delta cases do —
so `S+1` is contiguous. Without that advance the first post-barrier delta is
compared against the stale pre-barrier `prevSeq` and trips the `#2874`
session-sync gap check (`seq > prevSeq+1 && prevSeq > 0`), forcing one spurious
`handleSessionSyncGap` → full re-export + reconnect on the active-traffic
recovery path. With #5361's wire-monotonic barrier that was a single benign
reconnect (not a loop); #5362 removes even that. Only the successful-dispatch
path advances `prevSeq`; the drop paths already advance it via
`markDroppedFrameApplied`.

**Replay-buffer eviction loss (#2382)**: the replay buffer is bounded at
`REPLAY_BUFFER_CAPACITY` (4096). If the daemon disconnects or withholds ACKs
long enough for the buffer to wrap, the oldest accepted-and-enqueued frame is
evicted to make room. That frame was already counted in `event_stream_sent` at
enqueue, but is unrecoverable after reconnect — a real telemetry loss (exactly
the storm / daemon-restart path operators inspect for deny/drop/log audit
completeness). The buffer-full eviction path (`evict_replay_frame` in
`event_stream/mod.rs`) increments `event_stream_replay_evictions`, surfaced as
`xpf_userspace_event_stream_producer_frames_total{outcome="replay_evicted"}`
and in `show ... | display` status (`Event stream producer: ... replay_evictions=N`).
This is **distinct from ACK-trim** (`pop_replay_frame` via the MSG_ACK handler),
which removes acknowledged frames that WERE delivered — ACK-trim and shutdown
drain do NOT bump the eviction counter, so a growing `replay_evictions` value is
an unambiguous accepted-telemetry-loss signal, not normal acknowledged removal.

**Per-event-type RT_FLOW counters are surfaced everywhere (#2510)**: the
daemon-side `EventStream` keeps an `events` counter and a `drops` counter for
each RT_FLOW frame type it consumes — `policy_deny`, `screen_drop`,
`screen_alarm`, `filter_log`, and (since #2460/#2508) `session_close` /
`session_create`. All of these thread atomically from
`EventStream.{recordDataplaneEvent,recordDataplaneEventDrop}` through the public
`EventStream.Status()` DTO (`EventStreamStatus`, `pkg/dataplane/userspace/
protocol.go`) to every observability surface:
- CLI `show ...` status (`Event stream events: ... session_close=N
  session_create=N` and `Event stream drops: ... session_close=N
  session_create=N`, `pkg/dataplane/userspace/format/status.go`);
- REST + gRPC, which serialize the `EventStreamStatus` DTO directly (the close /
  create counts ride the `session_close_events` / `session_close_drops` /
  `session_create_events` / `session_create_drops` JSON fields — there is no
  separate protobuf message for these counters, so the DTO change auto-carries
  to gRPC);
- Prometheus `xpf_userspace_event_stream_dataplane_events_total{type="..."}` and
  `..._dataplane_event_drops_total{type="..."}` (`pkg/api/metrics_userspace.go`),
  which now enumerate the `session_close` and `session_create` labels alongside
  the other four types.
The `session_close` *drops* counter is the operator-facing signal that
post-#2460/#2465 SESSION_CLOSE frames — which feed flow-export close records —
were dropped at the daemon (a data-retention/export-completeness incident).
A rising `..._event_drops_total{type="session_close"}` delta means close
records are being lost before the flow exporter sees them.

**RT_FLOW event timestamps are emission-time, wall-clock (#2470)**: the
deny / screen-drop / screen-alarm / filter-log RT_FLOW events
(`afxdp/event_emit.rs`) stamp `timestamp_ns` (wire offset 0, LE u64, absolute
Unix nanoseconds — the same field/format the SESSION_CLOSE frame uses, see
`encode_session_close_rt_flow`) at the instant the dataplane makes the
decision, NOT when the Go daemon consumes the frame. The emitter has the
decision instant in the CLOCK_MONOTONIC domain (the worker poll loop's
`now_ns`/`now_secs`); it converts that to wall-clock Unix ns via
`event_stream::mono_ns_to_wall_clock_unix_ns` (one anchored `(mono, wall)`
clock read per emit, reusing #2465's `read_mono_and_wall_clocks` +
`monotonic_ns_to_unix_ns`). This is the conversion boundary between the
monotonic dataplane clock and the absolute wire timestamp. These events fire
on drops / denies / log-matched packets (not per normal packet), so a clock
read per emit is cheap; correctness is preferred. The Go decoder
(`pkg/logging/ringbuf.go`, `DecodeRawEventRecord`) prefers a nonzero on-wire
timestamp for `rec.Time` and falls back to receive time (`time.Now()`) only
when it is 0 (a clock-read failure or an old, unstamped frame). Before #2470
all four emitters wrote 0, so under helper backlog / reconnect / CPU
contention the logged event time reflected consumption time, not decision
time — damaging timeline reconstruction.

### Integration with Existing Code

**Rust side** (`userspace-dp/src/main.rs`):
- Add `EventStreamSender` that manages the event socket connection
- Worker threads push events to `EventStreamSender` instead of per-binding
  `pending_session_deltas` ring buffers
- Main loop calls `EventStreamSender::flush()` periodically to batch-write
  buffered events to the socket
- Pause/Resume/DrainRequest are read from the socket in the flush loop

**Go side** (`pkg/dataplane/userspace/manager.go`):
- Add `eventStreamListener` that creates the Unix socket and accepts the helper
  connection
- Add `eventStreamReader` goroutine that reads frames and dispatches to the
  existing `queueUserspaceSessionDeltas` path
- Replace the periodic `DrainSessionDeltas` poll loop with the stream reader
- Ack frames sent back periodically (every N events or every 100ms)

**Daemon side** (`pkg/daemon/daemon.go`):
- `shouldSyncUserspaceDelta()` filtering applies to stream events exactly as it
  does to polled deltas today
- Demotion prep uses Pause + DrainRequest instead of
  `PauseIncrementalSync` + `DrainSessionDeltas` RPC
- `ExportOwnerRGSessions` RPC kept as fallback for cases where the stream is
  disconnected during demotion prep

### Migration Strategy

1. Implement the event socket alongside the existing control socket
2. Keep `DrainSessionDeltas` RPC working as fallback
3. Daemon prefers event stream when connected, falls back to RPC polling
4. Once validated, remove the polling path and simplify

### Why Binary, Not JSON

At 10K sessions/sec (achievable under load), JSON encoding/decoding adds
measurable CPU overhead. A fixed binary layout avoids allocation, parsing, and
string conversion for every event. The control socket stays JSON for human
readability and debuggability.
