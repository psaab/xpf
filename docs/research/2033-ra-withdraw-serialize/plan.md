# Plan-of-Action: #2033 — serialize RA goodbye withdrawal with sender shutdown

> Revision: r4 (folds round-3 review: Codex r3 + AGY r3 + SMR r3)
> Branch: `research/2033-ra-withdraw-serialize`
> Base: origin/master `c4e7c77cd`
> Mode: /research — STOPS AT PLAN-READY. No production code edits in this branch.

## 1. Status

PLAN DRAFT r4. Round-1 (Codex+AGY+SMR) all NEEDS-REVISION → r2. Round-2 (Codex
r2 NEEDS-REVISION 2 MAJOR+1 MOD; SMR r2 PLAN-READY after finding I13; AGY r2
timed out) → r3. Round-3: AGY r3 PLAN-READY-WITH-NITS (independently found the
`m.mu`-held-across-withdraw bottleneck + the deadlock); SMR r3
PLAN-READY-WITH-ONE-NIT (found the same deadlock); **Codex r3 NEEDS-REVISION**
(3 MAJOR + 1 MOD + 1 MINOR — the deepest findings yet, all correct). r4 folds
all of round 3. This document does not modify production source; the only files
written are under `docs/research/2033-ra-withdraw-serialize/`.

### Round-3 review deltas folded into r4
- **Owner performs the conn.Close, after the goodbye** (Codex r3 MAJOR #1): the
  r3 hard-`stop()`-closes-before-join BROKE graceful-upgrades-hard (a racing
  hard close could kill the upgraded goodbye; residual NOT sub-µs). Fix: only
  the owner closes the conn, in `finishShutdown`, after emitting the goodbye —
  exactly one close, always after any goodbye. §5 + I17.
- **Bounded owner writes** (Codex r3 MODERATE #4): `SetWriteDeadline` on every
  `WriteTo` so a stuck socket cannot wedge withdrawal; this also lets the owner
  always return promptly, removing the need for hard close-before-join. §9 seam
  + I18.
- **I13 corrected** (Codex r3 MAJOR #2): in CLUSTER mode, `daemon_apply.go`
  does NOT call `ra.Apply`/`ra.Clear` at all (`!isCluster` guard); all HA RA
  ops run on VRRP/reconcile goroutines with NO `applySem`. `pkg/ra`'s `m.mu` is
  the only serialization. §7 I13 rewritten.
- **Don't hold `m.mu` across the blocking withdraw** (AGY r3 MAJOR #2 + SMR r3
  N1 + the MINOR #3 coupling): snapshot+delete under `m.mu`, release, then
  `withdrawAndStop()` outside the lock — else multi-iface demotion stalls
  Status/Apply for hundreds of ms on the failover hot path. Releasing `m.mu` is
  also what makes the graceful-vs-hard race reachable (so the upgrade logic is
  necessary, not redundant). §5 note + I16.
- **WithdrawOnce/Apply: defer+second-pass ONLY** (Codex r3 MAJOR #3): killed
  the "skip + rely on reconcile tick" option — skipping drops a MASTER `Apply`.
  §5 + I4.
- **Invariant test predicate uses the FIRST goodbye** (Codex r3 MINOR #5): "no
  lifetime>0 seq greater than the FIRST goodbye"; the shorthand "goodbye is
  last write" is unsound (misses a normal RA interleaved between goodbye
  packets). §5 invariant + §9 T1.

### Round-2 review deltas folded into r3
- **Invariant overclaim** (Codex r2 MAJOR #1): the achievable guarantee is
  "goodbye is LAST / no lifetime>0 RA after the first goodbye," NOT "no normal
  RA after withdrawal begins" (there is an unavoidable check-to-`WriteTo` gap).
  §5 invariant + §9 T1 reworded to the achievable property; `draining()` checks
  are best-effort early-outs, single-owner emission is the correctness
  mechanism.
- **WithdrawOnce claim must make Apply WAIT, not skip** (Codex r2 MAJOR #2): if
  `WithdrawOnce` wins the claim and a MASTER `Apply` is dropped, no RA sender
  exists after release. §5 + I4: `Apply` must serialize/retry behind the claim,
  never skip.
- **conn.Close-after-join only for graceful** (Codex r2 MODERATE #3): keep the
  current close-BEFORE-join for `modeHard` (`Clear`/`Apply`-remove) so a stuck
  packet op can be unblocked; only the graceful path needs close-after-join
  (conn alive for the owner-emitted goodbye). §5 + I9.

### Round-1 review deltas folded into r2
- **W2 corrected** (all three): the dangerous window is the ~100 ms goodbye
  burst, NOT "~500 ms after the goodbye finishes." `stop()` closes `stopCh`
  immediately after the goodbye returns, so a post-burst RS sleep IS caught by
  the existing post-sleep `stopCh` re-check. §2 W2 rewritten.
- **W3 corrected** (all three): `ipv6.PacketConn.WriteTo` is documented
  concurrency-safe, so W3 is an *ordering* bug, not a Go data race. The only
  genuine Go data races are W4 (`lastRA`) and S2 (`ResendBurst`). §2 W3/§9 T2
  rewritten; data-race claims scoped to W4/S2.
- **Path A single-channel shutdown** (Codex + AGY CRITICAL): the r1 two-channel
  (`withdrawCh` + `stopCh`) sketch had a `select` race that could SKIP the
  goodbye entirely. Replaced with a single `stopCh` close + an atomic
  `shutdownMode {graceful|hard}` read by the owner. §5 Path A rewritten.
- **Path A serializes the startup burst** (Codex CRITICAL): `run()` ran
  `sendStartupBurst()` before the select loop with no stop check; a withdraw
  during startup could still emit normal RAs. The burst is now interruptible.
  §5 Path A + I3/I11.
- **WithdrawOnce claim protocol** (Codex MAJOR): the running-guard was
  point-in-time; `Apply` could start a real sender after the guard check. r2
  adds an atomic claim under `m.mu`. §5 + I4.
- **Goodbye-only path must not toggle the link** (SMR MAJOR): promoted from
  open-question Q3 to a design constraint. §5 + I12.
- **S1 wording** (Codex/AGY): the WithdrawOnce burst is asynchronous
  (`go run()`), so a normal RA is possible before/during/after the goodbye —
  not strictly "guaranteed before." §2 S1 reworded.
- **Test seam** (all three): rewritten to a conn-level seam (read + write) so
  RS injection + deterministic timer/rand/clock control are possible; T1 now
  forces the bad interleave. §9 rewritten.
- **rsReceiver 1 s shutdown latency** (AGY MINOR): close the conn right after
  the owner emits the goodbye to unblock `ReadFrom`. §7 I10.

## 2. Issue framing

`pkg/ra` runs one goroutine per RA-emitting interface (`sender.run`,
`pkg/ra/sender.go:129`). That goroutine owns three *normal* (router
lifetime > 0) RA emit paths:

- the **startup burst** (`sendStartupBurst`, called at the top of `run`),
- the **periodic timer** (`advTimer.C` → `sendRA`, `sender.go:148-150`),
- the **RS-triggered** response (`rsCh` → up to 500 ms random sleep →
  `sendRA`, `sender.go:152-172`).

Withdrawal (the *goodbye*, router lifetime = 0) is emitted on a **different**
goroutine — the caller of `Manager.Withdraw()` /
`Manager.WithdrawInterfaces()` / `Manager.WithdrawOnce()`. Those methods do
`s.sendGoodbyeRA()` (`ra.go:106 / 135 / 172`) and only **afterwards**
`s.stop()` (`ra.go:107 / 136 / 173`). `stop()` is what closes `stopCh` and
the NDP socket and joins `run()` (`sender.go:120-126`).

Because the goodbye runs *before* `stop()`, the `run()` goroutine is alive
and free to emit a normal RA during or immediately after the lifetime-zero
burst. A host that processes a normal RA *after* the goodbye re-installs (or
never removes) the default route toward the firewall that is demoting
itself.

### The four concrete race windows (all verified against the source)

W1 — **periodic vs goodbye.** `Withdraw()` calls `sendGoodbyeRA()` on the
caller goroutine. Concurrently `advTimer.C` can fire in `run()` and call
`sendRA()` (lifetime > 0). The goodbye burst spans up to
`2 × goodbyeDelay = 100 ms` (`sender.go:230-239`); any periodic fire inside
or just after that window emits a normal RA that lands after the goodbye on
the wire.

W2 — **RS-triggered vs goodbye (corrected window).** An RS that arrives just
before withdraw starts is queued on `rsCh`; `run()` then performs a random
sleep of up to `maxRSDelay = 500 ms` (`sender.go:161-162`) before the
post-sleep re-check and `sendRA()`. **Corrected per round-1 review:** the
exposure is NOT "~500 ms after the goodbye finishes." In `Withdraw`
(`ra.go:106-107`) `sendGoodbyeRA()` returns and then `stop()` runs
*immediately*, and `stop()` closes `stopCh` (`sender.go:121`). The RS path's
post-sleep re-check is `select { case <-s.stopCh: return; default: }`
(`sender.go:164-168`). Therefore:
  - If the RS random sleep ends **during** the ~100 ms goodbye burst (caller
    still in `sendGoodbyeRA`, `stop()` not yet reached) → `stopCh` is still
    open → the re-check falls through → a normal lifetime>0 RA is emitted.
    **REACHABLE — this is the real W2 window (~100 ms per goodbye, plus the
    tiny scheduling gap between the goodbye returning and `stop()` closing
    `stopCh`).**
  - If the RS sleep ends **after** `stop()` has closed `stopCh` → the re-check
    returns, no normal RA. **NOT reachable.**
So the danger is a normal RA landing *during/at the tail of* the goodbye
burst (last packet on the wire could still be a goodbye if the normal RA
fires mid-burst, but a normal RA fired in the gap-after-burst-before-stop
becomes the last packet). Either way the host can observe a lifetime>0 RA at
or after the withdrawal moment. The bug is real and HIGH; the *window* is
~100 ms, not 500 ms.

W3 — **concurrent `WriteTo` — ordering bug, NOT a Go data race.** When
W1/W2 fire, the goodbye's `conn.WriteTo` (caller goroutine) and the normal
`sendRA`'s `conn.WriteTo` (`run()` goroutine) execute on the **same**
`*ndp.Conn`. **Corrected per round-1 review:** `ndp.Conn.WriteTo`
(`conn.go:200`) marshals a local buffer and delegates to
`ipv6.PacketConn.WriteTo`; `net.PacketConn` methods are documented safe for
concurrent use (`net/net.go:317-320`), and the ndp wrapper holds no mutable
shared state across `WriteTo`. So W3 is purely a **packet-ordering** problem
(a normal RA interleaved with the goodbye burst), NOT a Go memory race —
`go test -race` will NOT flag it. The genuine Go data races are W4 below and
S2. Fixing W1/W2 (single writer / serialized emit) eliminates the ordering
problem as a side effect.

W4 — **`lastRA` data race.** `sendRA` writes `s.lastRA = time.Now()`
(`sender.go:220`) with no lock. `run()` reads `s.lastRA` for RS
rate-limiting (`sender.go:157`, same goroutine as the periodic writer — OK)
**but** `Manager.Status()` reads `s.lastRA` (`ra.go:244`) from an arbitrary
gRPC/CLI goroutine under `m.mu`, while `sendRA` writes it under no lock.
`go test -race` will flag this read/write pair.

### Two secondary call-path defects found while mapping the race

S1 — **`WithdrawOnce` emits normal RAs (startup burst) around the goodbye.**
`WithdrawOnce` (`ra.go:150`) calls `s.start()` on a fresh sender
(`ra.go:168`). `start()` launches `go s.run()` (`sender.go:115`), and `run()`
**first** calls `sendStartupBurst()` (3 normal RAs, `sender.go:134/176-183`).
`WithdrawOnce` then calls `s.sendGoodbyeRA()` on the *caller* goroutine
(`ra.go:172`). **Corrected per round-1 review:** because the burst runs on a
*separate* goroutine (`go run()`), the 3 normal RAs are emitted
asynchronously — possibly before, during, or after the caller's goodbye, not
strictly "before." Either way the "withdraw stale routes on boot-as-
secondary" path *installs* a default route (the startup burst) and races a
goodbye against it — the inversion the issue describes. The existing
`running`-guard only prevents clobbering a *live primary*; it does not stop
the freshly-started temporary sender from bursting, and (S1b) the guard is
point-in-time — see I4.

S2 — **`ResendBurst` concurrent `WriteTo`.** `ResendBurst` (`ra.go:117`)
launches `go s.sendStartupBurst()` while `run()` is alive and may be doing
periodic/RS sends — another unserialized concurrent `WriteTo` on the same
conn (same W3 class, but normal-vs-normal so not a *correctness* inversion,
only a data race).

## 3. Honest scope and value

**Value: real, HIGH, but probabilistic.** This is a correctness defect in
the HA demotion path. When it fires, a host keeps/restores a default route
toward a firewall that has just demoted itself, producing intermittent
post-failover IPv6 blackholing until the host's own RA cache expires or the
new primary's RA wins. It is *not* deterministic — it needs a periodic timer
or a queued RS to land in a sub-second window during demotion — which is
exactly why it is filed as "intermittent." The blast radius is IPv6 default
routing for directly attached hosts during/just-after failover.

**Mitigating reality:** the new primary sends its own startup burst on
becoming master, and RFC 8028/8106 hosts generally prefer the higher-/equal-
preference live router; the demoted node's link is often also being cycled
(RETH MAC). So the bug is a *tail* failure, not a guaranteed one. That is the
honest reason it is HIGH-but-not-CRITICAL.

**Scope discipline.** This is a `pkg/ra`-internal serialization fix. It must
not change: RA wire format, timing constants, the goodbye-count / startup-
burst semantics, or any public `Manager` method signature. It must not touch
VRRP or the daemon demotion sequencing (those callers stay byte-identical).

## 4. What is already shipped (today's behavior, to preserve)

- Per-interface sender goroutine with startup burst + periodic + RS reply.
- Goodbye = 3 × lifetime-0 RAs at 50 ms spacing (`goodbyeCount`,
  `goodbyeDelay`).
- Startup burst = 3 × normal RAs at 100 ms spacing.
- `WithdrawOnce` skips interfaces with a running sender (don't clobber a live
  primary).
- `Apply` diffs senders; unchanged configs keep running with no RA gap.
- `Status()` snapshots config + `lastRA` under `m.mu`.
- Callers (must remain behavior-compatible): `daemon_run.go:1485`
  (`Withdraw` on shutdown), `daemon_ha.go:716` (`go WithdrawOnce` on
  boot-as-secondary), `daemon_ha.go:958` (`WithdrawInterfaces` when another
  RG still master), `daemon_ha.go:960 / 1078` (`Withdraw` on BACKUP),
  `daemon_apply.go:887` (`ResendBurst` after link cycle).

## 5. Concrete design — path options

The invariant to establish (precise wording per round-2 Codex MAJOR #1, with
the round-3 Codex MINOR #5 correction): **no lifetime>0 RA is emitted after the
FIRST goodbye packet** (equivalently: every lifetime>0 RA has a lower `seq`
than the first lifetime-0 RA). This is the achievable and sufficient guarantee
for the HA-correctness bug — a host that processes a normal RA *before* the
goodbye is then corrected by the goodbye; the bug is only a normal RA *after*
the goodbye. NOTE the shorthand "goodbye is the last write" is slightly weaker
and unsound as a test predicate, because a normal RA interleaved *between* the
three goodbye packets would still satisfy "last write is a goodbye" — so the
test asserts against the FIRST goodbye, not the last.

Note the *stronger* phrasing "no normal RA after withdrawal begins" is NOT
achievable without a per-send lock, because there is an unavoidable
check-to-`WriteTo` gap: the owner can pass a `draining()` check, a withdraw
can land, and the in-flight `sendRA` still writes. BUT because the owner emits
the goodbye only on its way out (`finishShutdown`, after the loop), any such
in-flight normal RA necessarily PRECEDES the goodbye — so "goodbye is last"
still holds. The plan therefore targets "goodbye is last / nothing
lifetime>0 after the goodbye," and the test (§9 T1) asserts exactly that
(`seq` of last goodbye > `seq` of every normal RA), NOT the unachievable
stronger property. Single-owner emission is what makes this hold without a
per-send lock; the `draining()` checks are a best-effort early-out to reduce
spurious normal RAs during teardown, not the correctness mechanism.

### Path A (recommended) — single-owner goroutine; goodbye emitted by the owner

Make `run()` the sole owner of *all* writes on the connection, including the
goodbye and the startup/re-burst. The shutdown signal is a **single** channel
close (`stopCh`) plus an **atomic `shutdownMode`** the owner reads when it
wakes. This eliminates the round-1 CRITICAL select race (two channels could
let `select` pick the hard-stop case and skip the goodbye).

Sketch (final names settled in implementation):

```
type shutdownMode int32
const ( modeNone shutdownMode = iota; modeHard; modeGraceful )

type sender struct {
    ...
    mode     atomic.Int32     // shutdownMode: set BEFORE close(stopCh)
    stopOnce sync.Once        // guards close(stopCh)
    burstCh  chan struct{}    // buffered(1): request a re-burst (ResendBurst)
    lastRAMu sync.Mutex       // guards lastRA (Status reads, owner writes)
}

// signalStop sets the mode, then closes stopCh exactly once. The mode is
// published (atomic store, happens-before the close) BEFORE the close, so any
// owner wakeup that observes the closed channel also observes the mode.
//
// GRACEFUL UPGRADES HARD (resolves D1, §11 Q3): a graceful withdraw must win
// over a hard stop, because the demotion Withdraw (VRRP-event goroutine, NO
// applySem) can race a config-apply Clear (applySem) for the same sender (see
// §7 I13). First-writer-wins would let a benign Clear drop the demotion
// goodbye — the exact bug. So: if a graceful request arrives after a hard
// mode was set but BEFORE the owner has read it, upgrade to graceful. The
// owner reads mode AFTER waking on the closed stopCh; the upgrade store must
// happen-before that read. Because stopCh is already closed, the upgrade
// cannot rely on the close as the publish edge — use an atomic store and
// accept that if the owner already read modeHard, the upgrade is a no-op
// (acceptable: the goodbye burst is best-effort and the new primary's RA is
// the real recovery; the residual window is sub-microsecond and only when a
// Clear is already mid-shutdown). NEVER downgrade graceful->hard.
func (s *sender) signalStop(m shutdownMode) {
    if m == modeGraceful {
        // Upgrade: set graceful unconditionally (graceful wins over hard).
        s.mode.Store(int32(modeGraceful))
    } else {
        // Hard: only set if nothing set yet (don't clobber a graceful).
        s.mode.CompareAndSwap(int32(modeNone), int32(modeHard))
    }
    s.stopOnce.Do(func() { close(s.stopCh) })
}

func (s *sender) run() {
    defer close(s.stopped)
    // Interruptible startup burst: each send checks stopCh first so a
    // withdraw during startup cannot emit a normal RA after withdrawal.
    s.burstInterruptible()
    if s.draining() { s.finishShutdown(); return }

    advTimer := time.NewTimer(s.randomAdvInterval()); defer advTimer.Stop()
    rsCh := make(chan netip.Addr, 8)
    go s.rsReceiver(rsCh)
    for {
        select {
        case <-s.stopCh:
            s.finishShutdown(); return
        case <-s.burstCh:
            s.burstInterruptible()
        case <-advTimer.C:
            s.sendRA(); advTimer.Reset(s.randomAdvInterval())
        case _, ok := <-rsCh:
            if !ok { s.finishShutdown(); return }
            if time.Since(s.getLastRA()) < minRAMulticastDelay { continue }
            t := time.NewTimer(time.Duration(rand.IntN(int(maxRSDelay))))
            select {
            case <-s.stopCh: t.Stop(); s.finishShutdown(); return
            case <-t.C:
            }
            s.sendRA(); advTimer.Reset(s.randomAdvInterval())
        }
    }
}

func (s *sender) draining() bool { return s.mode.Load() != int32(modeNone) }

// finishShutdown is the ONLY place the goodbye is emitted AND the ONLY place
// the conn is closed (I17). It runs on the owner goroutine after the loop is
// gone. Because the OWNER closes the conn AFTER emitting the goodbye, a racing
// hard stop() can never close the socket out from under the goodbye (Codex r3
// MAJOR #1). The owner re-reads mode here, so a graceful upgrade that landed
// before the owner woke is honored.
func (s *sender) finishShutdown() {
    if shutdownMode(s.mode.Load()) == modeGraceful {
        s.sendGoodbyeRA()   // bounded by SetWriteDeadline (I18); last packet
    }
    if s.conn != nil { s.conn.Close() }   // single close, always after goodbye
}

// burstInterruptible: 3 normal RAs, each gated on stopCh so a concurrent
// withdraw stops the burst immediately.
func (s *sender) burstInterruptible() {
    for i := 0; i < startupBurstCount; i++ {
        if s.draining() { return }
        s.sendRA()
        if i < startupBurstCount-1 {
            t := time.NewTimer(startupBurstDelay)
            select { case <-s.stopCh: t.Stop(); return; case <-t.C: }
        }
    }
}

// stop (hard, no goodbye) and withdrawAndStop (graceful) both just signal +
// join; the OWNER closes the conn in finishShutdown (I17). With bounded writes
// (I18) the owner always returns promptly, so neither caller needs to
// close-before-join to unblock a stuck owner. The rsReceiver is unblocked by
// the owner's conn.Close (I10) — at worst a 1 s deadline tail on a detached
// goroutine, off the withdraw critical path.
func (s *sender) stop()           { s.signalStop(modeHard);     <-s.stopped }
func (s *sender) withdrawAndStop(){ s.signalStop(modeGraceful); <-s.stopped }

// NOTE (I16): Withdraw()/WithdrawInterfaces() must, under m.mu, move the
// sender to a DRAINING TOMBSTONE (NOT bare-delete — a deleted sender looks
// absent and a concurrent Apply/WithdrawOnce would start a second sender on
// the same interface, racing the goodbye), signal stop, RELEASE m.mu, then
// join (<-stopped) outside the lock; on completion remove the tombstone under
// m.mu. Apply/WithdrawOnce treat a draining tombstone like a claim (I4):
// defer + wait, never start a new sender. This keeps a single live conn per
// interface AND frees m.mu during the ~100ms join. Releasing m.mu is also what
// makes the graceful-vs-hard race reachable, hence signalStop's upgrade logic.
```

Key properties:
- **Single shutdown channel + published mode** → no select race; `select`
  always exits via `stopCh`, and the owner *then* reads `mode` to decide
  goodbye-or-not. The goodbye cannot be skipped (fixes round-1 CRITICAL #1).
- The goodbye is emitted **by `run()` itself** in `finishShutdown`,
  structurally after the loop → no normal RA can follow it (W1, W2
  eliminated by construction).
- The **startup burst is interruptible** and checks `draining()`/`stopCh`
  → best-effort early-out so a withdraw during startup stops the burst
  promptly (fixes round-1 CRITICAL #2). Note: this is an early-out, not the
  correctness mechanism — see the invariant note above re: the check-to-write
  gap; "goodbye is last" holds because the goodbye is owner-emitted on exit.
- Only `run()` ever calls `WriteTo` → the W3 ordering problem is gone, and
  S2's concurrent `WriteTo` is gone (re-burst now goes through `burstCh`).
- `lastRA` reads/writes are serialized by `lastRAMu`; `Status` uses
  `getLastRA()` (W4 fixed). The owner's RS rate-limit read also uses
  `getLastRA()` (covers Codex MINOR #8's "all reads" note).
- **`WithdrawOnce`**: gets a **goodbye-only** entry point that NEVER launches
  `run()` and NEVER runs the burst — `sendGoodbyeStandalone()` opens a conn,
  sends the 3× goodbye, closes. Two corrections from round 1:
  - It must **claim** the interface atomically: under `m.mu`, check no sender
    exists AND insert a placeholder/claim so a concurrent `Apply` does NOT
    start a real sender for that interface mid-goodbye (fixes Codex r1 MAJOR
    #5; see I4). Per Codex r2 MAJOR #2 the concurrent `Apply` must **WAIT/retry
    behind the claim, NOT skip** — dropping a MASTER `Apply` would leave the
    interface with no RA sender after the claim releases. Release the claim
    when the standalone goodbye finishes; `Apply` then proceeds and starts the
    real sender. (The standalone goodbye is brief — 3× at 50 ms ≈ 100 ms — so
    the `Apply` wait is bounded.)
  - It must **NOT toggle the link** — `sendGoodbyeStandalone` must obtain a
    source LLA without the link-cycling branch of `ensureLinkLocal` (I12).
- `ResendBurst`: route the re-burst through the owner via `burstCh`
  (buffered, non-blocking send) instead of `go s.sendStartupBurst()` (S2).

Cost: the most code change. The handshake correctness rests on: (1) `mode`
stored before `close(stopCh)` (store happens-before close happens-before the
receiver's wakeup — standard Go memory model); (2) graceful UPGRADES hard in
`signalStop`, never downgrade (I13); (3) `sync.Once` around the close; (4) the
OWNER is the single closer of the conn, in `finishShutdown` after the goodbye
(I17) — no caller closes directly; (5) every owner `WriteTo` is bounded by
`SetWriteDeadline` (I18); (6) `Withdraw` snapshots+deletes under `m.mu` and
calls `withdrawAndStop` OUTSIDE the lock (I16); (7) the burst and RS-sleep both
honor `stopCh`. All are covered by the test plan (§9).

### Path B (interim) — synchronized `withdrawing` flag + stop normal emission first

Keep the goodbye on the caller goroutine but make every normal emit path
check an atomic `withdrawing` flag, and **stop normal emission before the
goodbye burst**:

```
type sender struct { ... withdrawing atomic.Bool; raMu sync.Mutex }

func (s *sender) sendRA() {           // normal RA
    if s.withdrawing.Load() { return }
    s.raMu.Lock(); defer s.raMu.Unlock()
    if s.withdrawing.Load() { return } // re-check under lock
    ... WriteTo ...; s.setLastRA(now)
}
func (s *sender) sendGoodbyeRA() {
    s.withdrawing.Store(true)          // gate normal RAs first
    s.raMu.Lock(); defer s.raMu.Unlock()  // serialize with any in-flight sendRA
    ... WriteTo goodbye ...
}
```

Properties (clarified per round-1 m3/Codex #8):
- The flag + `raMu` serialize goodbye and normal RA on the conn.
- **W2 IS closed by Path B as sketched**, because in the current code the RS
  random sleep happens BEFORE `sendRA()` (`sender.go:161-169`). So the flag
  check that matters is the one *inside* `sendRA`, after the sleep: a
  post-sleep `sendRA` re-acquires `raMu`, sees `withdrawing == true`, and
  returns. (This was stated inconsistently in r1; it is correct as long as
  the suppression check is the under-`raMu` one inside `sendRA`, not a
  pre-sleep check.) The earlier "residual hole" framing was wrong for this
  code shape.
- `lastRA`: ALL reads/writes — including the RS rate-limit read at
  `sender.go:157` (Codex #8) — must be covered by the same synchronization
  (move under `raMu` or a dedicated `lastRAMu`); `Status` reads under that
  lock (W4).
- **What Path B does NOT fix cleanly:** S1 (WithdrawOnce burst) and S2
  (ResendBurst concurrent burst) still need separate surgery, because the
  flag only guards `sendRA` against the goodbye — it does not make the burst
  single-owner. Path B would need the flag checked inside `sendStartupBurst`
  too, and a claim for WithdrawOnce (I4), and the no-link-toggle constraint
  (I12) — at which point it approaches Path A's complexity without the
  single-owner clarity.

Cost: smaller core diff, but the correctness rests on double-checked locking
done exactly right, the goodbye still runs on the caller goroutine (two
goroutines touch the conn), and the secondary defects (S1/S2/I4/I12) still
need the same fixes. Genuinely *interim*.

### Path C — PLAN-KILL if the race is unreachable

Considered and rejected. The race **is** reachable: W2 (queued RS + 500 ms
sleep) and S1 (`WithdrawOnce` startup burst) are not merely theoretical —
S1 is a guaranteed ordering inversion on the boot-as-secondary path, and W2
has a sub-second window every demotion. PLAN-KILL is not justified.

### Recommendation

**Path A.** It is the only option that makes the invariant *structural*
(single writer; goodbye emitted after the loop cannot fire a normal RA)
rather than *defended by a flag that must be checked at every site forever.*
It also cleanly fixes S1 and S2, which Path B does not address without
additional surgery. Path B is the documented fallback if review finds Path A
too invasive for a HIGH-severity targeted fix.

## 6. Public API preservation

No signature changes. `Manager.Withdraw() error`,
`Manager.WithdrawInterfaces([]string)`,
`Manager.WithdrawOnce([]*config.RAInterfaceConfig)`,
`Manager.ResendBurst()`, `Manager.Apply(...)`, `Manager.Clear() error`,
`Manager.Status() []SenderInfo`, `New()` all keep their exact signatures and
observable semantics. Internally `Withdraw*` route through
`sender.withdrawAndStop()` (Path A) or the flag+goodbye sequence (Path B).
Callers in `pkg/daemon` and `pkg/grpcapi` are unchanged.

## 7. Hidden invariants (must not be broken)

I1 — **HA demotion ordering.** Goodbye (lifetime 0) must be the *last* RA a
demoting sender ever emits. (This is the bug; the fix makes it structural.)

I2 — **Goodbye burst semantics.** Still 3 × lifetime-0 RAs at 50 ms (do not
reduce reliability; multiple goodbyes survive packet loss). Do not convert to
a single send.

I3 — **Startup burst semantics.** Still 3 × normal RAs at 100 ms on a
*legitimate* start, so hosts relearn quickly. The fix must NOT suppress the
startup burst on a normal `Apply`/start — only on the `WithdrawOnce`
goodbye-only path.

I4 — **`WithdrawOnce` must NOT clobber a live primary, atomically, and must
not starve a concurrent `Apply`.** Round-1 (Codex MAJOR #5): the current guard
checks `m.senders` under `m.mu`, releases the lock, then opens the temp sender
— `Apply` can start a real sender in the gap. The fix performs a **claim under
`m.mu`**: check no sender exists AND record a claim, do the standalone
goodbye, release the claim. Round-2 (Codex r2 MAJOR #2): a concurrent `Apply`
for a claimed interface must **wait/retry behind the claim, NOT skip** — if
`WithdrawOnce` wins and a MASTER `Apply` is dropped, the interface ends up with
no RA sender after the claim releases. So `Apply`'s per-interface start
serializes on the claim (re-check after the claim clears) rather than skipping
the interface. The goodbye is bounded (~100 ms) so the wait is bounded.

**Implementation constraint (SMR r3 N1 + Codex r3 MAJOR #3) — `Apply` must NOT
block under `m.mu`, and must NOT skip.** `Apply` (`ra.go:31-94`) holds `m.mu`
for its entire body including `s.start()`, while `WithdrawOnce` needs `m.mu` to
release the claim. So "`Apply` waits behind the claim" must be a **deferral**,
NOT a block-under-lock (deadlock: `Apply` holds `m.mu`, `WithdrawOnce` can't
re-take it to clear the claim). The ONLY acceptable shape is **defer + second
pass**:
  - Under `m.mu`, `Apply` collects claimed interfaces into a deferred list,
    releases `m.mu`, waits (bounded — the standalone goodbye is ~100 ms) for
    the claim(s) to clear, re-acquires `m.mu`, and starts the deferred senders
    after re-checking they still don't exist.
  - The claim is released via `defer` in the goodbye-only path so a panic
    cannot strand it.
Codex r3 MAJOR #3 KILLED the alternative "skip this pass + rely on the
reconcile tick": skipping violates the r2 requirement that `Apply` not drop a
MASTER `Apply` (the interface would have no sender until the next reconcile
tick — an RA gap on the new primary). Defer + second pass is mandatory.

I5 — **No RA gap on unchanged `Apply`.** A config-equal interface keeps its
existing sender; the refactor must not stop/restart it.

I6 — **`stop()` (no goodbye) must remain available** for `Clear` and
`Apply`'s "removed/changed sender" path — those intentionally do NOT send a
goodbye (e.g. config change should not blackhole hosts). Path A must keep a
hard-stop channel distinct from the withdraw channel.

I7 — **Idempotent / re-entrant shutdown.** `Withdraw` may be called on an
already-stopping sender (e.g. shutdown racing a BACKUP transition). Closing
`stopCh` twice panics — guard with `sync.Once`. The withdraw request send
must be non-blocking (`select … default`).

I8 — **`ResendBurst` is fire-and-forget today** (`go s.sendStartupBurst()`,
called from the apply path holding `m.mu`). The refactor must keep it from
blocking the apply path while still serializing the burst with the owner.

I9 — **`conn.Close()` is owner-only (SUPERSEDED by I17 — Codex r4 MODERATE
#3).** The r2/r3 "split by mode, caller closes" design is OBSOLETE. In r4+ the
OWNER is the single closer, in `finishShutdown`, after the goodbye (I17). No
caller (`stop`/`withdrawAndStop`) closes the conn. This removes the
close-vs-goodbye race entirely and the bounded writes (I18) make the early
close unnecessary for unblocking the owner. Disregard any earlier text about
hard-closes-before-join / caller-closes-after-join.

I10 — **`rsReceiver` lifecycle + shutdown latency (owner-closes variant).**
`rsReceiver` blocks in `ReadFrom` with a 1 s deadline and exits on `stopCh`
(`sender.go:185-209`). (a) the receiver's exit must not deadlock the owner —
the owner exits on `stopCh` regardless of `rsCh` state; (b) the owner's
`conn.Close()` in `finishShutdown` unblocks `ReadFrom` so the detached
receiver exits within one deadline at worst. Sequencing: owner emits goodbye
→ owner closes conn → owner returns (`close(stopped)`) → `<-s.stopped`
returns. The receiver is a detached goroutine bounded by the owner's close;
NOT on the withdraw critical path. (Also see I-spin / AGY r4 MINOR #4: bound
`rsReceiver` against a persistent non-temporary read error so it cannot spin
at 100% CPU if the interface dies while `stopCh` is still open — add a short
backoff on consecutive errors.)

I11 — **Startup/re-burst must be interruptible by withdrawal.** Per Codex
CRITICAL #2: the burst (startup and `ResendBurst`) must check `stopCh`/
`draining()` between sends so a withdraw during a burst cannot emit a normal
RA after withdrawal begins. The burst still emits its full 3 RAs on a normal
start (I3).

I12 — **Goodbye-only path must NOT toggle the link.** Per SMR MAJOR #1:
`start()`→`ensureLinkLocal` (`sender.go:69`) can `LinkSetDown`/`LinkSetUp`
(`sender.go:398-400`) when no LLA exists. `WithdrawOnce`'s
`sendGoodbyeStandalone` must obtain a source LLA WITHOUT the link-cycling
branch — if no usable LLA exists, skip the goodbye (best-effort) rather than
cycle the link of a demoting interface (which may be mid-RETH-MAC-cycle).

I13 — **In cluster/HA mode, ALL `ra` Apply/Clear/Withdraw run on
VRRP/reconcile goroutines WITHOUT `applySem`; `pkg/ra`'s `m.mu` is the ONLY
serialization.** Corrected per Codex r3 MAJOR #2 (my r3 source claim was
wrong). Verified against the daemon:
  - `daemon_apply.go` only calls `ra.Apply`/`ra.Clear` when `!isCluster`
    (`daemon_apply.go:1016-1028`) — i.e. NEVER in cluster mode. The non-cluster
    Apply at `:1019` is under `applySem` (via `commitAndApply`), but that path
    is irrelevant to HA demotion.
  - In CLUSTER mode, RA is managed entirely by VRRP/reconcile:
    `applyRethServicesForRG`→`ra.Apply` (`daemon_ha.go:911/1055`) and
    `clearRethServicesForRG`→`ra.Withdraw`/`WithdrawInterfaces`
    (`daemon_ha.go:958-960`), reached from the VRRP event goroutine
    (`daemon_ha.go:418/448/670/672`) and the direct-VIP path
    (`daemon_ha_vip.go:165/191`). NONE of these hold `applySem`.
  CONSEQUENCE: in the HA case that matters, `Apply` (graceful-relevant start),
  `Withdraw` (graceful), and `Clear` (hard) for the same sender are serialized
  ONLY by `ra.Manager.mu`. So the correctness of graceful-upgrades-hard
  depends entirely on the `pkg/ra` locking discipline (I16), NOT on any daemon
  lock. This makes I16 (don't hold `m.mu` across the blocking withdraw) the
  load-bearing decision: it is BOTH the concurrency fix AND what makes the
  graceful-vs-hard race reachable (and thus makes the upgrade logic necessary
  rather than redundant — see I16/AGY r3 MINOR #3).

I14 — **`rsCh` closes only after `stopCh` (no spurious goodbye).** `rsReceiver`
(`sender.go:186-209`) returns (closing `rsCh`) ONLY when `stopCh` is observed
closed (its `select { case <-stopCh: return; default: continue }` on a read
error). So the owner's `case _, ok := <-rsCh: if !ok` branch implies shutdown
is already in progress and `mode` is set — `finishShutdown` does the right
thing. The implementer MUST NOT make `rsReceiver` exit on a bare read error
without the `stopCh` check, or `rsCh` could close while `mode==modeNone` and
trigger a spurious/incorrect shutdown. (SMR r2 n1.)

I15 — **`burstCh`/`stopCh` select ties are harmless.** If `ResendBurst`'s
buffered `burstCh` send and a shutdown race, the owner may select `burstCh`
during draining; `burstInterruptible` re-checks `draining()` and
short-circuits, so no normal RA escapes after withdrawal. (SMR r2 n2.)

I16 — **Withdraw must not hold `m.mu` across the blocking stop, but must NOT
delete the sender before its goodbye completes — use a DRAINING TOMBSTONE
(AGY r4 MAJOR #1 + Codex r4 MAJOR #1; supersedes the r4 delete-before-stop
shape).** Two competing requirements:
  - Don't hold `m.mu` across `withdrawAndStop()`'s ~100 ms `<-stopped` (else
    multi-iface demotion stalls Status/Apply on the failover hot path — AGY r3
    MAJOR #2).
  - Don't make a *draining* sender look ABSENT, or a concurrent `Apply`
    re-promotion / `WithdrawOnce` will start a NEW sender (`sB`) for the same
    interface while the old one (`sA`) is still emitting its goodbye →
    EADDRINUSE/stall on `sB`'s `ndp.Listen`, OR `sA`'s goodbye lands AFTER
    `sB`'s startup burst → re-introduces the exact bug (AGY r4 / Codex r4
    MAJOR #1).
RESOLUTION — a **draining tombstone** in the manager keyed by interface
(separate from `m.senders`, or a per-entry `draining bool`):
  1. Under `m.mu`: move the sender from "active" to a "draining" set (record
     the tombstone), set its mode (graceful), signal stop — do NOT block.
  2. Release `m.mu`.
  3. Join the sender (`<-stopped`) outside the lock; when it finishes, under
     `m.mu` remove the tombstone.
  A concurrent `Apply` / `WithdrawOnce` that finds a **draining** tombstone for
  an interface treats it like a CLAIM (I4): it must NOT start a new sender —
  it defers (second pass) and waits for the tombstone to clear before
  starting. This guarantees a single live `ndp.Conn`/sender per interface at
  all times (no bind conflict, no goodbye-after-new-burst). The graceful-vs-
  hard upgrade (§5 `signalStop`) still applies if a `Clear` hits the same
  draining sender. COUPLING note: the tombstone (not bare deletion) is what
  makes the design correct AND keeps `m.mu` free during the blocking join.

I16b — **Deferred `Apply` second pass must be EPOCH-GUARDED against stale
resume (AGY r4 MAJOR #2).** A deferred `Apply` (waiting on a claim/tombstone,
I4) releases `m.mu` and waits; the node can transition to BACKUP and a
`Withdraw`/`Clear` can run in the interim. If the deferred `Apply` then wakes
and starts a sender, it STARTS RA on a BACKUP node — HA state inversion.
RESOLUTION: a `Manager.epoch` counter bumped on every state-mutating call
(`Apply`, `Withdraw`, `WithdrawInterfaces`, `Clear`). The deferred `Apply`
captures `epoch` before releasing `m.mu`; on re-acquire it ABORTS the deferred
start if `epoch` changed (a newer call superseded it). The newer call's own
result is authoritative. (Mirrors the per-key epoch pattern used by the
neighbor resolver, #1769/#1771.)

I17 — **Arbitrate the EFFECTIVE shutdown mode BEFORE any `conn.Close()` (Codex
r3 MAJOR #1).** The r3 split (hard `stop()` closes BEFORE join) BREAKS
graceful-upgrades-hard: a racing hard `stop()` can `conn.Close()` before the
owner emits the upgraded-to-graceful goodbye → goodbye lost on a closed
socket. The residual is NOT sub-µs. Fix: the close decision must read the
SAME arbitrated `mode` the owner uses. Concretely: a caller does NOT close the
conn directly; instead it signals (sets mode, closes stopCh, waits on
`stopped`), and the OWNER performs the close in `finishShutdown` after emitting
the goodbye (single point of truth). OR: the caller's pre-close is gated on
`mode.Load()==modeHard` re-checked at close time, else it joins-then-closes.
Owner-performs-the-close is cleaner: only the owner closes, after the goodbye,
so there is exactly one close and it is always after any goodbye. The hard
path then closes in the owner too (no goodbye, immediate). To preserve the
"unblock a stuck `WriteTo`/`ReadFrom`" benefit of close-before-join for hard,
combine with I18 (write deadline) so a hard stop never needs the early close
to unblock the owner. §5 sketch updated accordingly.

I18 — **Graceful (and all) owner writes must be bounded (Codex r3 MODERATE
#4).** If the owner is blocked in a `WriteTo` (normal or goodbye), the graceful
`withdrawAndStop()` (close-after-join / owner-closes) can HANG. `mdlayher/
ndp.Conn` supports `SetWriteDeadline`; the owner must set a short write
deadline on every `WriteTo` (or a timed fallback) so a stuck socket cannot
wedge withdrawal. This also removes the need for hard-stop close-before-join to
unblock the owner (I17): a bounded write means the owner always returns
promptly, so owner-performs-the-close is safe for both modes.

## 8. Risk table

| # | Risk | Likelihood | Impact | Mitigation |
|---|------|-----------|--------|------------|
| R1 | **Goodbye skipped by select race** (round-1 CRITICAL) | — | Stale route persists | Single `stopCh` close + atomic `mode` read by owner; NO two-channel select (§5 Path A) |
| R1b | Double-close of `stopCh` panic when `Withdraw` races `Clear` | Med | Crash | `sync.Once` (`stopOnce`) around close |
| R1c | A `Clear` (hard) races a demotion `Withdraw` (graceful) and drops the goodbye | Med (cluster RA ops share only `m.mu` — I13) | Re-introduces the bug | `signalStop` graceful UPGRADES hard (never downgrade) + owner-performs-close-after-goodbye (I17) so a racing hard close cannot kill the upgraded goodbye; tested (T7) |
| R12 | Racing hard `conn.Close()` kills the upgraded-to-graceful goodbye | Med | Goodbye lost | Only the owner closes, in `finishShutdown`, after the goodbye — single close, always post-goodbye (I17, Codex r3 MAJOR #1) |
| R13 | Stuck owner `WriteTo` wedges graceful withdrawal | Low | Withdraw hang on failover | `SetWriteDeadline` on every owner write (I18, Codex r3 MODERATE #4) |
| R14 | `Withdraw` holds `m.mu` ~100 ms/iface → stalls Status/Apply on failover | Med | Failover latency | Snapshot+delete under `m.mu`, withdraw OUTSIDE the lock (I16, AGY r3 MAJOR #2) |
| R2 | Normal RA emitted in the check-to-`WriteTo` gap during teardown | Low | None (precedes the goodbye) | Achievable invariant is "goodbye is last," which holds because the goodbye is owner-emitted on exit; `draining()` checks are best-effort early-outs (§5, Codex r2 MAJOR #1); test T1 asserts seq-order |
| R11 | `WithdrawOnce` claim STARVES a concurrent MASTER `Apply` (skip → no sender) | Med | No RA after claim release | `Apply` WAITS/retries behind the claim, never skips (I4, Codex r2 MAJOR #2); test T4b |
| R3 | Refactor suppresses the *startup* burst on a legit start | Med | Slow relearn after failover | Burst only short-circuits when `draining()`; legit start emits all 3 (I3/I11); test T9 |
| R4 | `WithdrawOnce` clobbers a live primary (point-in-time guard) | Low | Primary blackholed | Atomic claim under `m.mu` (I4); test T4b `-race` |
| R5 | `ResendBurst` blocks the apply path (holds `m.mu`) | Med | Apply stall | Non-blocking buffered `burstCh` send; owner consumes (I8) |
| R6 | `Status` still races `lastRA` | Low | `-race` failure | `lastRAMu` accessor; owner uses it for the RS read too (W4) |
| R7 | Withdraw on a never-started/failed sender (nil conn) | Low | nil deref | nil-guard conn in goodbye + close |
| R8 | Behavior change observed by daemon/VRRP callers | Low | Failover regression | Signatures + observable semantics unchanged; `make test-failover` gate |
| R9 | Goodbye-only path toggles the link of a demoting iface | Low | Demotion disruption | No-link-toggle constraint (I12); skip goodbye if no LLA |
| R10 | 1 s shutdown stall on detached `rsReceiver` | Low | Slow teardown | Close conn right after goodbye to unblock `ReadFrom` (I10) |

## 9. Test plan

All tests are unit-level in `pkg/ra` (no live cluster needed for the race
proof). The HA gate is the regression backstop.

**Test seam (rewritten per round-1: writer-only is insufficient).** The owner
loop creates `rsCh` locally and reads RS from `s.conn.ReadFrom` (`sender.go:
140/190`), and the random sleep uses `time.Sleep`/`rand.IntN`. A writer-only
seam cannot inject an RS, control the sleep, or drive the timer. The seam must
therefore be **conn-level + clock/rand injection**:
  - Extract a tiny interface `ndpConn { WriteTo(msg, cm, dst) error;
    ReadFrom() (...); Close() error; SetReadDeadline(...);
    SetWriteDeadline(...) (I18 bounded writes); JoinGroup; SetICMPFilter }`
    (the subset `sender` uses). Real path = `*ndp.Conn`;
    tests = a `fakeConn` whose `ReadFrom` returns injected RS messages and
    whose `WriteTo` records `{lifetime, seq}` (a monotonically increasing
    sequence counter, NOT wall-clock — deterministic ordering).
  - Inject the sleep/timer via a `sleepFn func(d) <-chan time.Time` (or a
    `clock` field) so the test controls when the RS random sleep elapses, and
    a `randFn` so the delay is deterministic.
  - These are compile-time seams (project-preferred), default-wired to the
    real implementations.

T1 — **Ordering proof that FORCES the bad interleave (the headline test).**
Using the `fakeConn` recorder (records `{lifetime, seq}` per write) and the
injectable sleep/clock:
  1. Start a sender; let the startup burst complete.
  2. Inject a queued RS via `fakeConn.ReadFrom`; let the owner enter the RS
     random-sleep branch and BLOCK it on the injected sleep channel (do not
     release it yet).
  3. Call `Withdraw` (graceful). On buggy code this sets nothing that stops
     the in-flight RS path; on fixed code the owner exits via `stopCh` →
     `finishShutdown` → goodbye.
  4. Release the RS sleep channel.
  5. Assert (Codex r3 MINOR #5 predicate): **no lifetime>0 write has a `seq`
     greater than the FIRST lifetime-0 write.** (Do NOT assert merely "the last
     write is a goodbye" — a normal RA interleaved between goodbye packets would
     pass that weaker check.)
  Crucially, to be a true guard the test runs the SAME scenario against a
  "buggy" shape (or a build that retains the old caller-goodbye ordering) and
  asserts it FAILS, OR — simpler and CI-stable — the test asserts the
  achievable invariant of the fixed code (**goodbye is the last write / no
  lifetime>0 write has a `seq` greater than the first lifetime-0 write**; per
  Codex r2 MAJOR #1 this is the achievable property, NOT "no normal RA after
  withdraw begins") under a forced interleave that, on the old code, would
  deterministically emit a normal RA AFTER the goodbye. The forced-block on the
  injected sleep makes the interleave deterministic (no flakiness), addressing
  the round-1 C2 / AGY #2 / Codex #7 finding. A companion micro-test exercises
  W1 by forcing a periodic-timer fire (via the injected timer) concurrent with
  the withdraw and asserting the same seq-order property.

T2 — **`go test -race` clean** for the genuine races: concurrent `Status()`
+ active `sendRA` (W4, `lastRA`); concurrent `ResendBurst` + periodic
(S2). (W3 is NOT a Go data race — see §2 — so it is not a `-race` target; it
is covered by the T1 ordering assertion and the single-owner design.) Run the
whole `pkg/ra` suite under `-race`.

T3 — **`WithdrawOnce` emits NO normal RA (S1) and no link toggle (I12).**
Use `fakeConn`; assert the goodbye-only path records *only* lifetime-0 writes
(no startup burst) and never calls the link-toggle path (assert via a stubbed
`ensureLinkLocal` seam / netlink recorder that the link is not cycled).

T4 — **`WithdrawOnce` skips a running sender + claim race + Apply-not-starved
(I4).** Three cases: (a) start a sender, then `WithdrawOnce` the same
interface; assert the live sender is untouched and no goodbye was sent on it.
(b) a `-race` test that runs `Apply` (starting a real sender) concurrently with
`WithdrawOnce` on the same interface and asserts exactly one owner exists at
the end and no goodbye-then-burst inversion (covers Codex r1 MAJOR #5). (c)
**Apply-not-starved** (Codex r2 MAJOR #2): `WithdrawOnce` wins the claim, then
a MASTER `Apply` arrives for the same interface; assert that after the claim
releases there IS a running sender (the `Apply` waited/retried, did not skip).

T5 — **`Apply` config-equal keeps sender (I5).** Assert no stop/start and no
goodbye when re-applying an identical config.

T6 — **`Clear`/`Apply`-remove sends NO goodbye (I6).** Assert the hard-stop
path records zero lifetime-0 writes.

T7 — **Idempotent / graceful-upgrades-hard shutdown (I7/I13/I17).** Call
`Withdraw` twice (assert no panic via `sync.Once`, no deadlock). Then the
graceful-vs-hard race: in BOTH orderings (hard-then-graceful and
graceful-then-hard), a graceful `Withdraw` MUST result in the goodbye being
emitted — graceful upgrades hard (§5 `signalStop`), and because the owner
performs the close AFTER the goodbye (I17), a racing hard `Clear` close cannot
suppress it. Assert the goodbye IS emitted whenever a graceful call
participated, regardless of order. (This corrects the r3 wording that a hard
stop "correctly" skips a goodbye when a graceful call also raced — that
contradicted I13; with the upgrade + owner-close, graceful always wins.) The
only no-goodbye case is a PURE hard `Clear`/`Apply`-remove with no graceful
caller — T6 covers that.

T8 — **`ResendBurst` serialized, non-blocking (I8/S2).** Assert the re-burst
writes are interleaved-free with periodic writes (single-writer) and that
`ResendBurst` returns promptly while holding `m.mu`.

T9 — **Startup burst preserved (I3).** Assert a fresh `Apply`/start records 3
normal RAs.

T10 — **HA regression gate.** `make test-failover` (mandatory per CLAUDE.md
for any change touching cluster/VRRP/failover paths — `pkg/ra` withdrawal is
on the demotion path). Manual sanity on the loss userspace cluster: demote an
RG, capture RAs on a LAN host (`tcpdump -i ... 'icmp6 && ip6[40]==134'`),
confirm the last RA before silence has Router Lifetime 0 and no lifetime>0 RA
follows it.

Note on the seam: a minimal `ndpConn` interface (read + write + close +
deadline) so the recorder is a real type, not a monkey-patched func, matching
project preference for compile-time seams over runtime hooks.

## 10. Out of scope

- RA wire format, option set, timing constants (max/min interval, goodbye
  count/delay, startup burst count/delay) — unchanged.
- VRRP demotion sequencing, daemon HA ordering — unchanged; callers keep
  exact signatures.
- DHCPv6 / Kea withdrawal (separate subsystem; `clearRethServices` also
  stops Kea — not touched).
- Any new config knob for goodbye behavior.
- Restructuring `pkg/ra` into a sub-package (the issue mentions a "narrow
  `pkg/ra/sender/` package" as one option; this plan keeps it in-package
  unless review insists, to minimize blast radius).

### Resolved in r2 (were open in r1)
- **R-Q3 (link toggle):** RESOLVED → I12. Goodbye-only path must NOT toggle
  the link; skip the goodbye if no usable LLA.
- **R-Q4 (W3 data race):** RESOLVED → W3 is an *ordering* bug only, not a Go
  data race; data-race claims scoped to W4/S2. `-race` targets W4/S2.
- **R-Q6 (seam shape):** RESOLVED → conn-level `ndpConn` interface (read +
  write), because a writer-only seam cannot inject an RS or drive the timer.

## 11. Open questions (≥5)

Q1 — **Path A vs B for a HIGH-severity targeted fix?** r2 strengthens the
recommendation for **Path A**: the round-1 review showed Path B does not
cleanly fix S1/S2/I4/I12 (it needs the same surgery) and leaves two
goroutines on the conn. But Path A is the larger diff on a failover-critical
path. Does review accept Path A, or still prefer a minimized Path B for the
first landing with a follow-up to single-owner?

Q2 — **Best-effort goodbye on a closing/cycled conn.** If the NDP socket is
already gone (link cycled during demotion), the goodbye `WriteTo` fails;
today that is logged and swallowed. Is best-effort acceptable (lean yes — the
new primary's RA is the real recovery), or should the fix attempt a re-listen
before the goodbye?

Q3 — **RESOLVED in r2 → graceful-upgrades-hard.** Investigation (I13) showed
the demotion `Withdraw` (VRRP-event goroutine, no `applySem`) CAN race a
config-apply `Clear` (applySem) for the same sender — the paths are NOT
serialized. So `signalStop` makes graceful win over hard (§5) to avoid a
benign `Clear` dropping the demotion goodbye. The residual (owner already
read `modeHard` before the upgrade) is a sub-µs best-effort window. Remaining
question for review: is the residual acceptable, or does /engineer want the
upgrade to also re-arm a goodbye if the owner already exited (e.g. a
post-exit standalone goodbye)? Lean: acceptable as best-effort.

Q4 — **`ResendBurst` and the goodbye: one typed request channel or
separate?** r2 uses a separate buffered `burstCh` + the `stopCh`/`mode`
shutdown. Is a single typed owner-request channel
(`{burst|withdraw|hardstop}`) preferred for clarity, or are separate
channels fine?

Q5 — **RS-path in-flight reply already sent before withdraw.** If an RS
reply (normal RA) was already emitted just before withdraw, the goodbye burst
follows it and overrides at the host. Is the standard 3× goodbye burst
sufficient, or should the owner emit an extra immediate goodbye when it
detects it interrupted an RS reply? (Lean: sufficient.)

Q6 — **In-package vs `pkg/ra/sender` sub-package.** The issue floated a
"narrow `pkg/ra/sender/` package." r2 keeps it in-package to minimize blast
radius. Does review want the sub-package split for the single-owner model, or
is in-package acceptable?

Q7 — **`rsReceiver` join vs detach.** r2 leaves `rsReceiver` detached (bounded
by conn-close + 1 s deadline). Should the owner explicitly join it for a clean
shutdown (no detached goroutine), at the cost of a slightly more complex
handshake?
