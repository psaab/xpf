# #2035 — LLDP socket lifecycle vs TLV codec split, immediate stop cancellation

**Status: DRAFT v1 (draft-fanout — not yet reviewed by Codex / AGY / Copilot)**

Issue: https://github.com/psaab/xpf/issues/2035
Branch: `research/2035-lldp-socket-lifecycle`
Plan doc: `docs/research/2035-lldp-socket-lifecycle/plan.md`
Base: origin/master `c4e7c77cd` (includes merged #2036/#2038 LLDP TLV
fail-closed codec).

---

## 1. Issue framing

Severity per the issue: MEDIUM — apply/shutdown latency on an HA firewall.

Two concrete defects in `pkg/lldp/lldp.go` (verified against the current
source on this branch):

1. **RX cancellation is timeout-polled, not immediate.** `rxLoop`
   (`lldp.go:240`) sets `SO_RCVTIMEO = 2s` (`:258-259`) and blocks in
   `unix.Recvfrom` (`:269`). Cancellation is observed only between
   `Recvfrom` returns (timeout or frame) and the next `select` on
   `ctx.Done()` (`:263-267`). So `Manager.Stop()` — which calls
   `cancel()` then `wg.Wait()` (`:160-162`) — can block for **up to ~2s
   per call** waiting for every per-interface RX goroutine to finish its
   current `Recvfrom`. With N LLDP interfaces the goroutines time out in
   parallel, so the worst case is one 2s floor, not N×2s, but it is still
   a 0–2s tail latency gated on a sleep, not on work.

2. **TX opens an AF_PACKET socket per frame.** `sendFrame`
   (`lldp.go:211`) does `unix.Socket(AF_PACKET, SOCK_RAW, …)` + `Close`
   on **every** advertisement (`:220-225`). At the default 30s interval
   this is trivial churn, but it is a syscall pair (plus the implicit
   security/audit overhead of opening a raw socket) per frame per
   interface, with no clean per-interface socket ownership. There is no
   correctness bug here, only structural untidiness and minor churn.

The blocking element of (1) matters because `Manager.Stop()` runs on the
daemon shutdown critical path (`pkg/daemon/daemon_run.go:1446-1449`),
**before** the HA shutdown-mode determination and VRRP/dataplane teardown
(`:1451+`). A 0–2s stall there delays the entire shutdown sequence,
including the priority-0 VRRP resignation burst that drives sub-second
HA failover. On a planned `systemctl restart xpfd` / ISSU cut-over, a 2s
LLDP tail directly inflates the control-plane downtime window.

### What is NOT in the blast radius (important scoping correction)

LLDP is started **once, at daemon startup** (`daemon_run.go:890-906`).
Grep confirms there is **no `reconcileLLDP`** in the commit/apply path —
`Apply()` and `lldp.New()` have exactly one non-test call site each, both
in the startup sequence. A live `set protocols lldp …` commit does **not**
currently re-run `Apply()`; the config only takes effect on the next
daemon restart. Therefore:

- The "apply latency" framing in the issue is, today, really
  **shutdown/restart latency**. `Apply()` internally calls `Stop()`
  first (`lldp.go:100`), so the 2s floor *would* bite a hypothetical
  live re-apply, but no such path exists yet.
- This plan does **not** add live LLDP reconfiguration. That is a
  separate feature (see Out of scope). The win we are buying is a
  bounded, near-zero `Stop()`.

---

## 2. Honest scope and value

**Value:** removes a 0–2s sleep-gated tail from the daemon shutdown /
restart critical path, on which HA failover timing depends; removes a
per-frame raw-socket open; and makes the package unit-testable at the
socket-lifecycle layer (today only the codec is testable; `Stop()` has a
single idempotency test that never exercises a live RX goroutine).

**Cost:** churn. `pkg/lldp` is ~492 lines in one file with a clean codec
already extracted in #2036. The proposed three-way split
(`codec`/`socket`/`manager`) plus a per-interface session type is a
non-trivial reorganization of a small, working, low-traffic subsystem.
The public surface (`New`, `Apply`, `Stop`, `Neighbors`, `Neighbor`,
`LLDPConfig`, `LLDPInterface`, and the exported codec funcs `BuildFrame`,
`EncodeTLV`, `ParseTLVs`) is consumed by `pkg/daemon`, `pkg/grpcapi`,
`pkg/cli` and must not change.

> If reviewers conclude the perf gain/scope is too small to justify the
> churn, PLAN-KILL is acceptable.

The strongest case for doing it anyway is not the 30s-interval TX churn
(negligible) — it is (a) the deterministic shutdown latency on an HA
appliance, and (b) testability: today there is no way to assert "Stop
returns in <X ms with a live RX socket" because the socket is created
inline in `rxLoop` with no seam. A minimal fix could buy the latency win
without the full package split (see Path B / Path C).

---

## 3. What is already shipped

- **#2036 / #2038 (merged, on this base):** the TLV codec is fail-closed.
  `EncodeTLV` rejects values over the 9-bit (511-byte) limit instead of
  wrapping the length; `BuildFrame` propagates that error; `mustEncodeTLV`
  panics only for compile-time-bounded callers. The codec functions
  (`BuildFrame`, `EncodeTLV`, `ParseTLVs`, `maxTLVValueLen`) are already
  logically a codec — they just live in the same file as the manager.
  This plan **does not touch codec behavior**, only its file location.
- The neighbor table, TTL expiry loop, and `Neighbors()` snapshot are
  stable and well-tested (`lldp_test.go`).

---

## 4. Concrete design (code-level)

### 4.1 Target package layout

```
pkg/lldp/
  codec.go        // moved verbatim from lldp.go: BuildFrame, EncodeTLV,
                  //   mustEncodeTLV, ParseTLVs, encodeChassisID,
                  //   encodePortID, encodeTTL, Neighbor, TLV constants,
                  //   maxTLVValueLen. Zero behavior change.
  socket.go       // raw-socket I/O abstraction + the per-interface session.
  manager.go      // Manager, New, Apply, Stop, Neighbors, neighbor table,
                  //   expiryLoop. Orchestration only.
  *_test.go       // codec_test.go (moved codec tests), socket_test.go (new,
                  //   injectable fd), manager_test.go (moved table/stop tests).
  README.md       // updated module map.
```

All three are `package lldp` — this is an **intra-package file split**,
not new importable packages. (The issue text says "pkg/lldp/codec" etc.;
see Path A vs Path A-prime below for whether these become sub-packages or
just files. Sub-packages force the codec/socket symbols to be exported,
which is a larger API commitment. Default recommendation is files, not
sub-packages.)

### 4.2 Per-interface session (`socket.go`)

```go
// ifSession owns the RX and TX sockets for one interface for the life of
// an Apply() generation. Closing rxFD unblocks a parked Recvfrom in the
// RX goroutine immediately (precedent: pkg/vrrp/instance.go:1190-1198).
type ifSession struct {
    iface *net.Interface
    rxFD  int           // AF_PACKET bound to ifindex, ETH_P_LLDP
    txFD  int           // AF_PACKET for periodic Sendto, opened once
    closeOnce sync.Once
}

func newIfSession(iface *net.Interface) (*ifSession, error) // opens+binds both fds
func (s *ifSession) recv(buf []byte) (int, error)           // unix.Recvfrom(rxFD)
func (s *ifSession) send(frame []byte) error                // unix.Sendto(txFD, …)
func (s *ifSession) close()                                 // closeOnce: Close both fds
```

Key change vs today:
- **No `SO_RCVTIMEO`.** `recv` blocks indefinitely; cancellation is by
  closing `rxFD`, which makes the parked `Recvfrom` return `EBADF`/`EINTR`
  immediately. This is the exact pattern VRRP already uses to unblock its
  receiver on stop. The RX goroutine treats any error after close as
  "shutdown, return".
- **TX socket opened once** in `newIfSession`, reused by every periodic
  `send`, closed in `close()`.

### 4.3 Manager orchestration (`manager.go`)

`Apply()` builds one `*ifSession` per enabled interface, stores them in a
slice/map under the manager mutex (or in a generation struct), then
launches the TX and RX goroutines bound to that session. `Stop()`:

```go
func (m *Manager) Stop() {
    m.mu.Lock()
    sessions := m.sessions; m.sessions = nil
    m.mu.Unlock()
    if m.cancel != nil { m.cancel() }   // stop TX ticker + expiry loop
    for _, s := range sessions { s.close() } // unblock parked RX recv immediately
    m.wg.Wait()                          // now bounded, no 2s floor
    m.cancel = nil
    m.mu.Lock(); m.neighbors = make(map[string]*Neighbor); m.mu.Unlock()
}
```

The RX goroutine no longer needs the per-iteration `select { ctx.Done }`
gate (it can keep it as a belt-and-suspenders pre-check, but the
authoritative unblock is the fd close). The TX goroutine and expiry loop
keep their `ctx.Done()` selects (they are timer-driven, not blocked in a
syscall).

**Ordering note:** `cancel()` then `close()` then `wg.Wait()`. We must
NOT `wg.Wait()` before closing the fds, or we reintroduce the block. We
must close fds while goroutines may still be using them — `closeOnce`
plus the goroutine's "error after close ⇒ return" makes the race benign
(a recv on a just-closed fd returns an error; a recv that already started
returns EBADF when the fd is reclaimed). This is the same benign close-
under-read race VRRP relies on.

### 4.4 Why a `socket.go` seam buys testability

Today `rxLoop` does `unix.Socket` inline, so a unit test cannot inject a
fake fd. With `newIfSession` as the single construction point we can add
a package-internal constructor seam (e.g. a `var newIfSessionFn = newIfSession`
override, mirroring the fsync-seam pattern used in the upgrade subsystem
per MEMORY) so a `socket_test.go` can supply a `socketpair(2)`-backed
session and assert: (a) `Stop()` returns within a tight deadline while a
goroutine is parked in `recv`; (b) closing rxFD unblocks recv.

---

## 5. Public API preservation

No exported signature changes. Verified consumers:

| Symbol | Consumers | Preserved? |
|---|---|---|
| `lldp.New()` | daemon_run.go:892 | yes |
| `Manager.Apply(ctx, *LLDPConfig)` | daemon_run.go:900 | yes |
| `Manager.Stop()` | daemon_run.go:1448 | yes (faster) |
| `Manager.Neighbors() []*Neighbor` | daemon_run.go:1228/1342, grpcapi, cli | yes |
| `Neighbor` (struct + fields) | cli.go:50/160, grpcapi/server.go:52/85 | yes |
| `LLDPConfig`, `LLDPInterface` | daemon_run.go:893-905 | yes |
| `BuildFrame`, `EncodeTLV`, `ParseTLVs` | tests + intra-pkg | yes (moved file only) |

`go vet ./...` + `go build ./...` + the existing `lldp_test.go` (split
into the new files but otherwise unchanged assertions) are the contract
guard.

---

## 6. Hidden invariants to preserve

- **HA/failover ordering (highest priority).** `Stop()` runs at
  `daemon_run.go:1446`, *before* the HA shutdown-mode / VRRP resignation
  logic. The whole point of this change is that `Stop()` gets faster —
  but we must not make it *slower or hanging* in any path, or we delay
  the priority-0 VRRP burst that gives ~1ms peer takeover. The new
  `Stop()` must be strictly bounded and must remain idempotent
  (`TestStopIdempotent` — double Stop, Stop-before-Apply).
- **`Apply()` calls `Stop()` first** (`lldp.go:100`). If a future live
  re-apply path is added it inherits the bounded Stop automatically — but
  the close-then-Wait ordering must hold so re-apply does not deadlock on
  the old generation's sockets.
- **Hot-path allocation:** LLDP is NOT a packet hot path (one frame per
  interface per 30s, RX at neighbor-announcement rate). The hot-path
  allocation rules in `docs/engineering-style.md` do not bind here, but
  reusing the TX socket and a fixed RX buffer (already `make([]byte,
  1600)` once per goroutine) is still the right shape.
- **Byte order:** `htons` (`lldp.go:488`) converts protocol numbers to
  network order for `AF_PACKET`. This must move with the socket code
  unchanged. `binary.BigEndian` for TLV headers stays in the codec. Do
  not "simplify" `htons` to `binary.BigEndian` — it is deliberately a
  host→network conversion for the `Protocol`/`socket type` fields.
- **Boot class:** none. LLDP does not participate in `computeBootClass`
  or the bootstrap/HA-guard logic.
- **Dual-AST / config compile:** out of scope — the config→`LLDPConfig`
  mapping in `daemon_run.go` is untouched; this plan does not add config
  surface, so the parser/`setSchema` dual-AST concerns do not apply.
- **CAP_NET_RAW:** opening sockets eagerly in `newIfSession` means a
  capability/permission failure now surfaces at `Apply()` time (logged,
  interface skipped) rather than silently per-frame. This is arguably
  better but is a behavior change in *when* the warning fires — call it
  out in the PR. Today an RX socket failure already aborts that
  interface's RX (`lldp.go:241-245`); a TX socket failure today is logged
  per-frame at Debug (`:222`). Eager TX-open changes per-frame-Debug into
  once-at-Apply-Warn. Decide whether to keep TX best-effort (open lazily
  on first send, retain a `Stop()`-safe close) or eager.
- **Neighbor map locking:** unchanged — `Neighbors()` returns copies
  under `RLock`; RX writes under `Lock`. The session refactor must not
  move neighbor-table mutation out from under the mutex.

---

## 7. Risk table (4 classes)

| Risk | Class | Likelihood | Mitigation |
|---|---|---|---|
| `Stop()` deadlock if `wg.Wait()` ordered before fd close | **Correctness** | low | Enforce cancel→close→Wait order; unit test Stop-with-parked-recv under deadline |
| Close-under-read race causes panic/double-close | **Correctness** | low | `sync.Once` on session close; "error after close ⇒ return" in RX loop (VRRP precedent) |
| Eager TX-socket open changes when CAP_NET_RAW failure surfaces | **Behavioral** | med | Document; consider lazy-open-on-first-send to preserve current timing, OR accept the earlier+louder failure as an improvement |
| Removing `SO_RCVTIMEO` leaves an RX goroutine permanently parked if fd close is ever skipped | **Correctness** | low | All Apply-generation sessions tracked in the manager; `Stop()` closes every tracked session; test asserts no goroutine leak (goleak-style or wg-based) |
| Three-file split churns blame/imports for a small pkg with low future-change rate | **Maintainability** | high (it WILL churn) | Keep it a single intra-package file split (no new import paths); move funcs verbatim; one commit = mechanical move, second = behavior change, for reviewable diffs |
| Codec moved into sub-package forces exporting internals | **API** | med | Default to files-not-subpackages (Path A); only sub-package if reviewers want a hard codec boundary |
| Per-frame TX socket removal masks a latent ifindex-staleness bug (socket cached across link flap) | **Behavioral** | low | TX socket is bound by `Ifindex` in the `Sendto` sockaddr, not at open; an `ifindex` change across a flap is rare and LLDP is restarted on daemon restart anyway — note as an open question |

---

## 8. Test plan

### 8.1 Unit (no privilege, no lab)
- **Codec tests:** moved verbatim into `codec_test.go` — round-trip,
  fail-closed overlength, incomplete/truncated/empty parse. Already green.
- **Session tests (new, `socket_test.go`):** use a `socketpair(2)` or an
  injected fake fd via the `newIfSessionFn` seam to assert:
  - `recv` blocks; closing the rx fd unblocks it within a tight deadline
    (e.g. 50ms), proving no 2s floor.
  - `close()` is idempotent (double close, close-without-open).
- **Manager tests (`manager_test.go`):**
  - `Stop()` returns within a deadline (e.g. <100ms) with a live RX
    goroutine parked in `recv` — this is the regression test for the
    2s-floor bug and MUST fail against today's code if the seam were
    backported.
  - `TestStopIdempotent` retained.
  - Goroutine-leak assertion after Stop (wg drained; optionally goleak).
  - Existing neighbor-table / expiry tests retained.

### 8.2 Integration / live
- **CAP_NET_RAW path:** a privileged test (build-tag `//go:build linux &&
  privileged` or skip-if-not-root) opening a real AF_PACKET pair to
  confirm send/recv and immediate-stop on a real socket. Optional — the
  socketpair fake covers the cancellation logic; the real-socket test
  only adds confidence on the AF_PACKET binding specifics.
- **Standalone VM smoke:** `make test-vm` + `set protocols lldp interface
  …`, confirm `show lldp neighbors` still populates, and time a
  `systemctl restart xpfd` to confirm shutdown no longer carries the
  ~0–2s LLDP tail (`journalctl` timestamp between "Clean up LLDP" and the
  VRRP resignation log line).

### 8.3 Does it need the loss cluster / make test-failover / multi-increment?
- **`make test-failover`:** NOT strictly required by the change itself —
  LLDP is not cluster/VRRP/session-sync/failover *code*. BUT `Stop()` sits
  on the shutdown path immediately before VRRP resignation, so a failover
  run is cheap insurance that the faster Stop did not perturb the
  resignation burst timing. Recommend running it once as a sanity gate,
  not as a gating requirement.
- **Loss cluster lab:** NOT required. The change is dataplane-agnostic
  (control-plane Go only, no userspace-dp / AF_XDP involvement). The
  standalone VM is sufficient to observe the shutdown-latency win.
- **Multi-increment:** the work is small enough for one PR, but a clean
  reviewable diff wants **two commits in one PR**: (1) mechanical
  file-only split (codec.go/socket.go/manager.go, zero behavior change,
  tests still pass), (2) the session lifecycle + immediate-cancel +
  TX-reuse behavior change with its new tests. See Path options.

---

## 9. Out of scope

- **Live LLDP reconfiguration** (re-running `Apply()` on a `set protocols
  lldp` commit without daemon restart). It does not exist today; adding it
  is a separate feature/issue. This plan only ensures the existing
  Stop/Apply are fast and testable.
- **Any change to TLV codec behavior** — #2036 settled fail-closed; we
  only relocate the functions.
- **LLDP-MED, additional TLVs, management-address TLV emission** — the
  `tlvManagementAddr = 8` constant is defined but unused; not this issue.
- **Config schema / parser surface** — no new config.
- **Sub-packaging the codec for external import** unless reviewers
  explicitly want the hard boundary (see Path A vs A-prime).

---

## 10. Multiple path options

### Path A — intra-package 3-file split + per-iface session (RECOMMENDED)
Files `codec.go` / `socket.go` / `manager.go`, all `package lldp`. Session
owns RX+TX fds, close-on-cancel, TX reuse. Two commits (mechanical move,
then behavior). 
- **Pro:** matches the issue's intent; testable seam; no API export
  pressure; bounded blast radius.
- **Con:** still churns a small package; the file split is mostly
  cosmetic relative to the actual bug fix.

### Path A-prime — true sub-packages `pkg/lldp/codec`, `pkg/lldp/socket`
As the issue text literally reads. Forces `codec.BuildFrame`,
`socket.Session`, etc. to be exported and importable.
- **Pro:** hard, enforced boundary; codec reusable by tests/tools without
  the manager.
- **Con:** larger, permanent public API commitment for a subsystem with
  no second consumer; more import churn in `manager`. Recommend only if a
  reviewer argues the boundary must be compiler-enforced.

### Path B — minimal fix, NO package split
Keep one file. Just (1) drop `SO_RCVTIMEO`, track per-iface fds in the
Manager, close them in `Stop()` to unblock `Recvfrom`; (2) hoist the TX
socket open out of `sendFrame` into the TX goroutine setup, reuse it.
Add the Stop-latency test via a small `newIfSessionFn` seam.
- **Pro:** smallest diff; buys 100% of the latency + churn-reduction win;
  minimal blame disruption.
- **Con:** doesn't deliver the "decomposition" the issue asks for; codec
  stays co-located (already fine after #2036). If the issue's real intent
  is *latency*, this is the highest value-per-line option.

### Path C — latency-only, defer codec/structure
Path B's socket-lifecycle fix only, explicitly leaving the file split for
a later cleanup issue. 
- **Pro:** ship the perf-relevant part fast.
- **Con:** leaves the issue partially open.

**Recommendation:** Path A if the team wants the decomposition on record;
**Path B if the priority is purely the shutdown-latency fix with minimal
churn.** Both are single-PR. Lead with Path B in review and let reviewers
upgrade to Path A if they value the structure. Avoid Path A-prime unless a
hard compiler boundary is explicitly wanted.

---

## 11. Open questions for adversarial review (>=5)

1. **Is the shutdown-latency win real and worth it?** The 0–2s tail only
   bites on daemon stop/restart, and LLDP `Stop()` runs *before* the
   VRRP resignation. Does anyone have a measured shutdown trace showing
   the LLDP leg is actually on the critical path, or is it dwarfed by FRR
   reload / dataplane teardown that runs later in the same shutdown? If
   the LLDP leg is <5% of observed shutdown time, that argues PLAN-KILL or
   Path C.
2. **Files vs sub-packages (Path A vs A-prime)?** The issue text says
   `pkg/lldp/codec` etc. Do reviewers read that as literal sub-packages
   (export commitment) or as "logical split into files"? This changes the
   public API footprint materially.
3. **Eager vs lazy TX socket open** — does opening the TX socket at
   `Apply()` (surfacing CAP_NET_RAW failure earlier and louder) regress
   any environment that runs xpfd without `CAP_NET_RAW` and relies on LLDP
   silently no-op'ing? Or is the earlier, single Warn strictly better than
   today's per-frame Debug spam?
4. **Close-under-read correctness on all target kernels.** VRRP relies on
   "close fd ⇒ parked `Recvfrom` returns EBADF/EINTR." Is that guaranteed
   on the >=6.18 kernel floor for AF_PACKET `SOCK_RAW`, or can a parked
   `recvfrom` ever miss the close and hang until a frame arrives? (If the
   latter is possible, we need a fallback — e.g. keep a *long* RCVTIMEO,
   say 30s, as a safety net, or `shutdown(2)` the socket before close.)
5. **Goroutine-leak / generation safety.** If `Apply()` is ever called
   twice (today only via the internal `Stop()` at the top of `Apply()`),
   are all old-generation sessions guaranteed closed before new ones bind
   the same ifindex? Could two RX sockets briefly bind the same
   interface+ethertype and double-count a neighbor? (AF_PACKET allows
   multiple bound sockets, so a brief overlap just double-delivers a
   frame, which is idempotent in the map — but worth stating.)
6. **Is the 2-commit split worth the reviewer overhead** for a ~500-line
   package, or should it be one squashed commit? (Style: the repo prefers
   reviewable diffs; a mechanical-move commit + behavior commit is the
   cleanest, but for a package this small a single well-described commit
   may be acceptable.)

---

## 12. Claude self-SMR (hostile)

**Strongest objection to my own plan:** The headline benefit is a 0–2s
shutdown tail, but I have NOT measured it. LLDP `Stop()` is one line at
`daemon_run.go:1446`; everything *expensive* in shutdown — VRRP
resignation wait, dataplane teardown, FRR reload (which the codebase
deliberately runs with a 15s context per leg and a 20s systemd
`TimeoutStopSec`) — runs *after* it. If the FRR/dataplane legs dominate
the shutdown window, shaving 2s off LLDP is invisible to the operator and
irrelevant to HA failover (the priority-0 VRRP burst is sent from the
*peer-facing* path which is gated by the resignation logic *after* LLDP
Stop, so a faster LLDP Stop only moves the resignation 0–2s earlier — a
real but possibly immaterial gain). The TX-per-frame "churn" is, at a 30s
interval, ~2 syscalls every 30 seconds per interface — genuinely
negligible. So the *measured* value could be near zero, and the cost is
real churn on a working, low-risk package.

**Counter to my own objection:** even if the latency win is modest, two
things stand independently: (a) the package is currently **untestable at
the socket-lifecycle layer** — there is no seam to assert Stop unblocks,
and that gap is exactly the kind of thing that hides a future regression;
(b) the close-on-cancel pattern is already the house style (VRRP), so
LLDP is the odd one out using a timeout poll. Aligning it is cheap with
Path B.

**Disposition: PLAN-DRAFTED-ready-for-review, leaning Path B.**

This is a legitimate, single-PR, control-plane-only cleanup with a small
but real correctness/latency improvement and a clear testability win. It
does **not** need the loss cluster and does **not** need to be split
across increments. The honest risk is that the latency benefit is too
small to justify even Path A's churn — so I am explicitly flagging
**PLAN-KILL as an acceptable outcome** if a reviewer produces a shutdown
trace showing the LLDP leg is in the noise, OR a downgrade to **Path
B/Path C** (latency-only, no decomposition) as the most likely landing
spot. I am NOT classifying this as DEFER-LAB or DEFER-MULTI-INCREMENT:
the work is small, lab-independent, and single-PR.

Recommended next step for the reviewer round: get answers to open
questions 1 (measured shutdown trace) and 4 (close-under-read kernel
guarantee) **before** choosing Path A vs B — those two answers decide
whether this ships, ships minimal, or gets killed.
