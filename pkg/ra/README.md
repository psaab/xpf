# pkg/ra

Embedded IPv6 Router Advertisement sender. Replaces external `radvd`
with per-interface goroutines built on `mdlayher/ndp`. Handles startup
burst, goodbye RAs, and re-burst recovery after RETH MAC link-cycle.

## Shutdown contract (single-owner + draining tombstone, #2033)

The lifetime-zero **goodbye** RA (router withdraw) MUST be the last RA on
the wire for an interface — otherwise a host keeps a dead default route
after HA failover. To make that **structural**, not flag-defended:

- **Single-owner emission.** Per interface, exactly ONE goroutine
  (`sender.run`) writes the NDP connection — startup burst, periodic RAs,
  RS-triggered replies AND the goodbye. No other goroutine calls
  `conn.WriteTo` or `conn.Close`. `ResendBurst` routes the re-burst
  through the owner via a buffered `burstCh` (no second writer).
- **Goodbye is owner-emitted on exit.** Shutdown is signalled via
  `signalStop(mode)`: it publishes an atomic `shutdownMode`
  (`hard`/`graceful`), then closes `stopCh` once (`sync.Once`). The owner
  wakes, leaves the loop, and in `finishShutdown` (the ONLY place a
  goodbye is sent and the ONLY place the conn is closed) emits the
  lifetime-zero goodbye as its FINAL write when the mode is graceful,
  then closes the conn. A normal RA can never follow the goodbye because
  the goodbye is emitted structurally after the loop.
- **The draining tombstone is the single atomic claim-and-hold for the
  goodbye (exactly one per withdrawn interface).** In cluster mode RA
  `Apply`/`Withdraw`/`Clear` for the same sender are serialized ONLY by the
  manager mutex (no `applySem`). Each draining interface has ONE `drainEntry`
  in `m.draining` (all fields read/written only under `m.mu`), owned by
  exactly ONE goroutine — the one that joins its sender (or the
  `WithdrawOnce`/standalone claimant). That single owner is the SOLE emitter
  of any standalone goodbye and HOLDS the entry across the whole emit. This
  makes "this interface owes a goodbye" a state CLAIMED ONCE and HELD, so
  there is no check-then-act anywhere:
    - **Graceful intent is atomic.** A graceful withdraw beats a racing hard
      `Clear`: `signalStop` stores graceful unconditionally and hard only via
      compare-and-swap from "none" — never a downgrade. `Withdraw`/
      `WithdrawInterfaces` install the entry (active-sender case) or flip
      `goodbyeWanted` on an existing one, AND `signalStop(modeGraceful)`,
      under the SAME lock that bumps the epoch — a racing `Clear` cannot slip
      a hard stop into a gap.
    - **An upgrade only works while the owner is alive.** Once a sender has
      run `finishShutdown` (read modeHard, emitted no goodbye, exited) it is
      DEAD and cannot be resurrected. So the guarantee is decoupled from the
      live-sender lifecycle: each `sender` records `goodbyeEmitted` (set in
      `finishShutdown` before `close(stopped)`). The entry's single owner, in
      `releaseDrain`, JOINS the sender (`<-stopped`, which orders the
      `goodbyeEmitted` read) and then, UNDER `m.mu`, takes the goodbye
      EXACTLY ONCE (`!goodbyeClaimed` → set it) if one is wanted and the
      owner emitted none.
    - **Claim-once (closes the concurrent-Withdraw double-send):** only the
      one owner releases the entry; concurrent Withdraws merely flip
      `goodbyeWanted`. `goodbyeClaimed` under `m.mu` ensures a single emit.
    - **Held-across-emit (closes the live-sender clobber):** the owner keeps
      the entry in `m.draining` for the ENTIRE standalone emit (open conn → 3×
      lifetime-0 RA → close), removing it only afterward. A concurrent `Apply`
      sees the tombstone and DEFERS — no new sender starts during the emit, so
      the standalone never clobbers a re-claimed master and ≤1 live conn holds.
      The tombstone IS the mutual exclusion; there is no separate check-then-act
      on `m.senders`.
    - **Timeout DEFERS the emit/replacement to the reclaimer — it must not
      ERASE the owed action (#5094):** `releaseDrain` reads `goodbyeEmitted` /
      opens a replacement ONLY after a successful `<-stopped`. If the join times
      out (`claimWaitTimeout` — pathological, since owner writes are bounded by
      `SetWriteDeadline`), it does NOT act inline (the `goodbyeEmitted` read
      would be unordered and the old conn may still be live → a replacement
      would break ≤1-conn). It LEAVES the tombstone held — so any future
      `Apply`/reconcile defers, never opening a second conn — and detaches a
      reclaimer, handing it the SAME `startEpoch` + `onProvenClose`. The
      reclaimer waits for `<-stopped` (the wedged owner finally proving its conn
      closed — restoring the happens-before AND the old-conn-closed precondition)
      and then runs the EXACT SAME ordered decision body (`finishDrainDecision`)
      the proven-close arm runs: emit the owed goodbye and/or start the
      still-current replacement, re-evaluated against fresh state under `m.mu`,
      before removing the tombstone. A timeout thus DEFERS the action, never
      drops it — the pre-#5094 reclaimer merely `delete`d the tombstone, leaving
      the interface senderless (or its goodbye lost) until an unrelated later
      `Apply` re-drove it. The transient degraded state is "old sender lingers,
      no replacement yet, tombstone held (Status shows `join timed out`)" — never
      two conns, never an unordered emit — self-healed once the owner exits.
  Net: EXACTLY ONE goodbye per withdrawn interface — the owner's if the
  upgrade landed, otherwise one standalone — and ZERO for a pure changed-config
  replace. Because the owner closes the conn AFTER its goodbye, a racing hard
  close cannot suppress it.
- **Single stop-then-act path (round-4 unification).** `releaseDrain` is the
  SOLE owner of "stop the old sender (join-or-timeout) → optionally emit
  exactly-once → optionally start a replacement on PROVEN-close → release
  tombstone." `Withdraw`, `WithdrawInterfaces`, `Clear` and `Apply` (both the
  removal and the changed-config **restart**) all route through it. The restart
  passes an `onProvenClose` callback that opens the replacement conn — it runs
  ONLY on the proven-closed (`<-stopped`) arm, under `m.mu`, with the tombstone
  still held, and only if no graceful withdraw superseded the replace. The
  proven-close arm's "emit goodbye and/or start replacement, then release" logic
  lives in ONE helper, `finishDrainDecision`, which the join-timeout reclaimer
  ALSO runs after the wedged owner finally exits (#5094) — so a timeout defers
  that same decision instead of a divergent path dropping it. `onProvenClose` is
  a bare `startLocked` closure that touches no `Apply`-local state, precisely so
  the reclaimer can run it in another goroutine without a data race; the
  make-before-break `waitConnReady` now lives inside `releaseDrain`. There is
  no divergent inline copy of these rules, so the timeout / happens-before /
  ≤1-conn class cannot reappear in a third path.
- **Replacement decision is atomic under the act-lock (round-5).** The
  "start the replacement?" test (epoch still `startEpoch` AND `!goodbyeWanted`)
  is re-evaluated against the LIVE tombstone under the SAME lock hold that
  performs the start — never a boolean computed before an unlock and trusted
  after. `goodbyeWanted` is monotonic (false→true) and `epoch` only increases,
  so a "start" decision observed under the act-lock cannot be invalidated while
  the lock is held; a racing `Withdraw`/`Clear` that lands before the act-lock
  is seen (decision aborts, the withdraw's goodbye is emitted), and one that
  lands after is harmless (no supersession existed at the act moment). The only
  unlock inside `releaseDrain` is for the blocking standalone-goodbye send; the
  loop re-acquires and re-evaluates fresh state before touching the replacement.
  NOTE: `onProvenClose` calls `startLocked` under `m.mu`. As of #2453 that is
  cheap: `startLocked` only does the synchronous `InterfaceByName` check and the
  `m.senders` bookkeeping, then launches the owner goroutine and returns. The
  socket open — `ensureLinkLocal` + the `ndp.Listen` bind RETRY that sleeps up
  to ~2s while a settling/RETH link-local appears — now runs in the owner
  goroutine's `openConn()` BEFORE its main loop, NOT under `m.mu` (see "Bind
  retry runs unlocked" below). The tombstone (held) still provides mutual
  exclusion for the start.
- **A dead sender has a retry owner (#6793).** `openConn` runs in the owner
  goroutine — the bind retry must not hold `m.mu` — so `startLocked` returns
  SUCCESS and a failed open surfaces only as `sender.dead()` afterwards. `Apply`
  has known how to rebuild that sender since #2865 (the "rebuilding dead sender
  (initial conn open failed)" branch), but only when something calls `Apply`
  again, and until #6793 nothing did:
  - **standalone** applies RA from `applyServicesReconcile`, which runs only on
    a config apply, and `reconcileRGStateLoop` is cluster-only — so a boot-time
    bind failure left the interface advertising nothing until an operator
    happened to commit, on a node that reported a successful commit;
  - **cluster** runs `reconcileClusterRAServices` every 2s but DIGEST-GATES it,
    and a dead sender does not move the desired-set digest — so its own "a
    transient boot-time bind failure recovers on the next reconcile with NO
    config change" promise did not hold either.

  `Manager.HasDeadSenders()` is the probe both owners gate on (a map walk over
  live senders; `dead()` is a non-blocking channel probe, so it is free on the
  common path). The cluster reconcile bypasses its digest while it is true; the
  daemon additionally runs an always-on `raDeadSenderReassertLoop`, mirroring
  `proxyARPReassertLoop` — unconditional, re-reading the active config each tick,
  and taking `applySem` BEFORE that read for the #4001 reason (a tick that read
  the config outside the semaphore could re-assert RA on an interface a
  concurrent commit had just removed it from). The gate is checked again INSIDE
  the semaphore: a commit that landed while the tick queued may already have
  rebuilt the sender, and re-applying then would be a gratuitous RA restart.

- **A failed FINAL goodbye is returned AND retained (#6777).** The graceful
  withdrawal path gets exactly two chances to put a lifetime-0 RA on the wire:
  the owner's own emit in `finishShutdown`, and — if that failed, leaving
  `goodbyeEmitted` false — `finishDrainDecision`'s standalone backstop on a
  fresh conn. Before #6777 a failure of that LAST chance was logged and then
  erased: the same pass set `goodbyeClaimed`, deleted the tombstone and dropped
  the sender, and `finishDrainDecision` returned only the replacement-start
  error. `Withdraw()` returned a hard-coded `nil`, so all three production call
  sites (`applyServicesReconcile`'s RA-removal branch, daemon shutdown, and the
  VRRP BACKUP transition) carried an `if err := d.ra.Withdraw(); err != nil`
  branch that was unreachable. Worse, the daemon's own retry driver
  (`reconcileClusterRAServices`) advances `lastRAReconcileHash` **only on a
  successful apply** — so a swallowed failure was latched as converged and the
  every-2s pass never retried. Operators saw a clean withdrawal while the stale
  IPv6 default-router identity lived on hosts for up to Router Lifetime (default
  1800s).

  Both halves are now fixed. `finishDrainDecision` returns the goodbye error
  separately from the start error; `releaseDrain` joins them; `Withdraw()` and
  `Apply`'s empty-config branch aggregate across interfaces. And the failure
  leaves **retry debt** in `Manager.goodbyeOwed`, because surfacing alone is not
  enough — once the tombstone and sender are gone a later pass has nothing left
  to act on. `Apply` re-attempts every owed goodbye whose interface is not in the
  desired set (through `WithdrawOnce`, so a retry takes the same claim-and-hold
  tombstone and can never open a second conn), and returns non-nil while any debt
  survives — which is what keeps the reconcile digest un-advanced so the periodic
  pass re-drives it. The debt is the graceful-path twin of the one-shot
  `WithdrawOnce` debt #5093 introduced.

  Three rules keep the debt from becoming a liability of its own:
  - **A vanished netdev records nothing.** `sendOneGoodbye` wraps a missing
    interface as `errGoodbyeIfaceMissing`; there is no link to emit on and no
    host behind it left to hear a goodbye, so retaining it would make a
    legitimately removed interface a permanent `Apply` error and suppress the
    node's whole RA reconcile digest. Only a bind failure or `errGoodbyeWrite`
    is retained — the transient shapes the debt exists for.
  - **It is bounded** (`maxGoodbyeRetries`). An interface that can never accept
    the goodbye is given up on with a single Warn rather than re-applying and
    logging every 2s forever.
  - **It is dropped when the router comes back.** A debt whose interface
    reappears in the desired set is dropped rather than retried — emitting it
    would withdraw the router the new sender is advertising. That drop lives in
    exactly ONE place (`retryOwedGoodbyes`), not also in `startLocked`: every
    path that starts a sender does so from an interface that is in `desired`, so
    a second clear there would be a redundant copy of one invariant, and a
    divergence between two copies of "a sender implies no debt" is always a bug.
    A debt recorded by the CURRENT `Apply` is held over to the next pass
    (`recordedEpoch`) instead of being retried microseconds after the backstop
    already failed on a fresh conn.
- **Draining tombstone — one live conn per interface, including replaces.**
  Every transition that removes OR replaces a sender installs a
  per-interface DRAINING tombstone under the manager mutex BEFORE releasing
  it, stops the old sender (closing its conn) OUTSIDE the lock, and only
  THEN opens any replacement conn. A changed-config `Apply` is a hard
  replace (no goodbye — the router is not going away) but still goes
  stop-old → start-new with the tombstone covering the whole window — it
  never opens the replacement while the old conn is live. While the
  tombstone is present the interface is NOT absent: a concurrent `Apply` or
  `WithdrawOnce` treats it as a claim and defers. This guarantees **at most
  one live NDP conn per interface** at any time (no `ndp.Listen` collision,
  no goodbye-after-new-burst inversion).
- **Make-before-break on a changed-config replace (#2834).** The ≤1-conn
  rule above means the old conn is PROVEN closed before the replacement is
  started — but `start()` opens the new conn ASYNCHRONOUSLY in the owner
  goroutine (the `openConn` bind retry must not run under `m.mu`; see "Bind
  retry runs unlocked"). So between `startLocked` returning and the owner's
  `openConn` completing there is a brief window with ZERO live conns — an
  IPv6-RA outage after a config change (hosts could lose the default route /
  RDNSS). On the changed-config restart path ONLY, `Apply` therefore waits —
  UNLOCKED, after `releaseDrain` returns — on the replacement sender's
  `connReady` signal (closed by the owner once `openConn` resolves), bounded
  by `claimWaitTimeout`. `Apply` returns only once the replacement RA conn is
  LIVE, so the live-conn count goes 1 → (briefly 0, internal) → 1 with no
  observable 0-conn window for callers, and never momentarily 2 (the old conn
  is gone first). This applies ONLY to a replace — it is NOT a withdrawal, so
  it still emits no goodbye; a genuine `Withdraw`/removal keeps its existing
  lifetime-0-goodbye + go-down behavior (`Clear` is the explicit no-goodbye
  primitive). The sender exposes
  `waitConnReady(timeout) bool`; the owner calls `signalConnReady(opened)`
  after `openConn` so a failed/pre-empted open releases the waiter promptly
  rather than blocking the full timeout on a sender that will never serve.
- **Dead-sender rebuild on reconcile (#2865).** A sender whose initial
  `openConn()` FAILS — the bind retry exhausts (link still doing DAD, the
  link-local has not appeared yet, a transient link-down at cold boot) or a
  stop pre-empts the open — has its owner go straight to `finishShutdown` and
  exit, but the `sender` struct REMAINS in `m.senders`. Such a sender will
  never emit an RA. Without special handling the next `Apply` reconcile would
  see the config is unchanged (`configEqual`) and `continue`, treating the
  dead entry as healthy and NEVER rebuilding it — so a transient boot-time
  bind failure would leave that interface permanently without RAs (IPv6 hosts
  lose their default route / RDNSS) until the daemon restarts or the RA config
  for that interface changes. The reconcile therefore probes `sender.dead()`
  (the open attempt RESOLVED — `connReady` closed — WITHOUT producing a live
  conn: `!connOpened`) and treats a dead sender as a hard-REBUILD even when
  the config is unchanged. The rebuild reuses the make-before-break replace
  path (tombstone → stop old → start replacement on PROVEN-close); because a
  dead sender's `run()` has already exited and closed its conn, the
  `releaseDrain` join returns immediately. A `sender` whose open is still in
  flight is NOT dead (`dead()` returns false until `connReady` is closed), so
  an in-progress slow bind is never spuriously torn down. Net effect: a
  transient open failure recovers on the next reconcile with NO config change.
- **Deferred / restart Apply is epoch-guarded (two-level, #4961).** An
  `Apply` start that waits behind a tombstone (a pre-existing drain, or its own
  changed-config stop) captures TWO baselines: the whole-manager fence
  (`m.epoch`) and the target interface's per-interface revision
  (`m.ifaceEpoch[name]`, recorded on the restart's `drainEntry.startIfaceEpoch`
  and captured per deferred interface). The (re)placement starts only if BOTH
  are unchanged. The whole-manager fence is bumped by `Apply`, `Withdraw`, and
  `Clear` (a node-wide transition to BACKUP must abort every in-flight start).
  The INTERFACE-SCOPED withdraws (`WithdrawInterfaces`, `WithdrawOnce`) bump
  ONLY the per-interface revision of the interfaces they name — NOT the fence.
  Before #4961 they bumped the global fence, so an unrelated
  `WithdrawInterfaces([B])` (e.g. from a concurrent HA reconcile, which is not
  under `applySem`) cancelled interface A's in-flight changed-config restart:
  the epoch mismatch suppressed A's replacement AND deleted its tombstone, so A
  silently lost its RA sender and A's hosts lost their IPv6 default route /
  RDNSS until the next RG transition. Scoping supersession per interface fixes
  that while a withdraw NAMING A still supersedes A's restart (both the
  per-interface epoch bump and the `goodbyeWanted` flip fire).
- **The three RA header timers are bounded before ndp marshals them
  (#8597).** The typed-leaf schema bounds Router Lifetime, Reachable Time
  and Retrans Timer to `[0, max]` at strict commit, and that gate is
  STRICT-only: the tolerant Load / peer-sync ingress downgrades it to a
  warning per #1960. Measured on the wire before the bound
  (`ndp.MarshalMessage` of `buildRA`):

  ```
  DefaultLifetime = -1  ->  Router Lifetime 65535   (~18 hours)
  ReachableTime   = -1  ->  4294967295 ms           (~49 days)
  RetransTimer    = -1  ->  4294967295 ms
  ```

  A NEGATIVE router lifetime advertised this box as a default router for
  the MAXIMUM the field can express. `pruneUnmarshalableOptions` probes
  only the OPTIONS for a marshal abort; the header fields marshal without
  complaint precisely because they wrap silently, so nothing noticed.

  Flooring at 0 invents no intent: 0 is the documented neutral for all
  three — "not a default router" for the lifetime, "unspecified, use your
  own defaults" for the other two — and is what the RA carried before
  these leaves existed. Above the field width the value SATURATES, which
  is monotone where wrapping is not (70000 s used to marshal as 4464, a
  lifetime an order of magnitude SHORTER than asked for).

  Both clamps bind `config.RARouterMaxLifetimeSeconds` /
  `config.RAReachableRetransMaxMillis` — the same constants the commit
  gate uses — rather than a local literal, so the gate and the sender
  cannot disagree about the ceiling. #4525 put a runtime floor on the
  advertisement INTERVAL for exactly this ingress; the header timers were
  not covered by it.
- **A supersession bump must accompany superseding RESPONSIBILITY (#8597).**
  #4961 scoped the interface-scoped withdraws' bump to the interfaces they
  NAME. `WithdrawOnce` then bumped every named interface in a loop that ran
  BEFORE the busy check — including the ones it went on to SKIP.

  A skip emits nothing, claims nothing, and reports `Skipped`, so the bump
  superseded work this call took no responsibility for. `finishDrainDecision`
  starts a changed-config replacement only while
  `m.ifaceEpoch[name] == e.startIfaceEpoch`, and `applyDeferred` aborts a
  deferred start on the same comparison — so a concurrent cold-boot
  `WithdrawOnce` (the daemon runs `runStartupGoodbye` on its own goroutine)
  made the replacement silently not happen, released the tombstone anyway, and
  returned nil from BOTH error paths. The interface ended with no RA sender
  while every caller was told it succeeded, and its hosts kept the router until
  Router Lifetime (1800 s default) expired.

  The bump now lives INSIDE the claim branch. It is moved, not deleted: on the
  claimed path this call takes the interface over and emits the goodbye, so a
  deferred `Apply` start that captured the epoch in `deferredIfaceEpoch` must
  still be superseded — deleting it would let a deferred start bring the sender
  back after the operator withdrew it. `WithdrawInterfaces` keeps its
  unconditional bump, because it flips `goodbyeWanted` on the entry it
  supersedes and therefore does take over.

  The contrast is the invariant, stated as a test: a `WithdrawOnce` that SKIPS
  must not cancel a restart, and a `WithdrawInterfaces` naming the same
  interface still must.
- **Bounded writes.** Every owner `WriteTo` sets a 1 s write deadline so a
  stuck socket cannot wedge withdrawal; the owner always returns promptly,
  which is what makes owner-performs-the-close safe for both modes.
- **rsReceiver backoff.** The RS receiver polls with a read deadline and
  backs off on a persistent non-deadline read error (so it cannot
  hot-loop at 100% CPU if the interface dies while `stopCh` is still
  open). It is a detached goroutine unblocked by the owner's `conn.Close`.
- **RS receive validation (RFC 4861 §6.1.1, #5095).** Before forwarding a
  Router Solicitation to the owner (which replies with a multicast RA),
  `rsReceiver` runs `validRSReceive`: the IP **Hop Limit MUST be 255** (a
  value forwarding would have decremented, so 255 proves the RS
  originated on-link) and the **source MUST be the unspecified address or
  a link-local unicast** (the only sources a conformant solicitor uses).
  Anything else — wrong hop limit, or a global/ULA/multicast source — is
  silently discarded so an off-link or spoofed RS cannot trigger an RA
  (RA-injection / DoS surface). `openConn` enables
  `ipv6.FlagHopLimit` via `SetControlMessage` so the received hop limit is
  available; a **nil** control message (hop limit unknown) fails closed.
  If the socket cannot report the hop limit, solicited RAs pause until the
  next periodic RA rather than answering a possibly off-link solicitation.

`WithdrawOnce` (boot-as-secondary stale-route withdraw) uses a
goodbye-ONLY path (`sendGoodbyeStandalone`) that never launches an owner
or a startup burst (so it cannot re-advertise the router it withdraws)
and never toggles the link (no `ensureLinkLocal` link-cycle on a demoting
interface — if no usable link-local exists the bind fails and no goodbye
goes out this pass).

**Goodbye write failures are surfaced, not swallowed (#5093).**
`sendGoodbyeRA` returns whether the full lifetime-0 sequence was written;
`sendGoodbyeStandalone` and `sendOneGoodbye` propagate a non-nil error
(wrapping `errGoodbyeWrite`) when the bind succeeds but the write fails;
and `WithdrawOnce` returns a `[]GoodbyeResult` — one per interface, each
`Sent` (a lifetime-0 RA went out), `Skipped` (the interface was busy so
another owner holds the goodbye), or carrying `Err` (bind/write failed).
The cold-boot one-shot caller (`pkg/daemon`
`reconcileRGState`/`runStartupGoodbye`) marks the RG done ONLY after every
interface reports `Sent`/`Skipped`; a failure leaves the sticky bit unset
so the reconcile ticker retries. Previously the daemon marked the one-shot
done *before* launching the async withdraw, so a bind/write failure was
never retried and the stale IPv6 default-router identity lingered on hosts
(ECMP to an inactive node) until Router Lifetime expiry.

## Entry points

- `Manager` — `ra.go`.
- `New()` — `ra.go`.
- `Apply(configs []*config.RAInterfaceConfig) error` — `ra.go`.
  Starts/stops per-interface senders; defers + retries (epoch-guarded)
  any interface that is currently draining. A CHANGED config is a hard
  replace (no goodbye — the router is not going away, the replacement
  re-advertises at once). A REMOVED config — this interface dropped from a
  non-empty desired set, OR an empty `configs` (all RA removed) — is a
  GRACEFUL withdraw that emits a final lifetime-0 goodbye (#5092), so hosts
  drop this router immediately instead of holding the stale default route
  until Router Lifetime (default 1800s) expires. The empty-config branch
  shares `Withdraw()`'s path via `collectGracefulWithdrawLocked`.
- `Withdraw() error` — `ra.go`. Graceful goodbye + stop on every sender.
- `ResendBurst()` — `ra.go`. Re-sends the startup burst (used after a
  link cycle) on every active sender, via the owner goroutine. The owner
  RE-RESOLVES the interface's current hardware address (`interfaceByNameFn`,
  owner-serialized) BEFORE the burst so the ICMPv6 source link-layer address
  (SLLA) reflects a post-link-cycle RETH/VLAN virtual-MAC change instead of the
  `net.Interface` value snapshot cached at Start (#5302). A day-2 MAC change
  leaves the RA config unchanged, so reconciliation keeps the sender and only
  requests a burst — without the re-resolve the burst would advertise the OLD
  MAC and point hosts' router neighbor entry at a MAC the active node no longer
  owns (IPv6 blackhole, the opposite of the burst's repair intent). If the
  re-resolve fails, the burst is SKIPPED and logged rather than advertising a
  known-stale SLLA (host NUD + the next successful refresh recover).
- `WithdrawInterfaces(names []string)` — `ra.go`. Graceful goodbye + stop
  by interface name.
- `WithdrawOnce(configs []*config.RAInterfaceConfig) []GoodbyeResult` —
  `ra.go`. Goodbye-only (no burst, no link toggle); skips busy interfaces.
  Returns a per-interface outcome (`Sent`/`Skipped`/`Err`) so a caller can
  retain retry debt on a failed goodbye (#5093). The
  busy-check and the claim-and-hold tombstone install are performed
  ATOMICALLY under `m.mu` by `claimWithdrawOnceLocked` (#2272): holding the
  lock across BOTH closes the check-and-act window in which a concurrent
  `Apply`/`WithdrawOnce` could otherwise start a competing sender between
  the check and the claim (two owners on one link, or a sender racing the
  goodbye — the #2033 blackhole class). The tombstone is then HELD across
  the goodbye emit, so the busy state — and thus the mutual exclusion —
  extends over the whole operation, not just the install instant.
- `Clear() error` — `ra.go`. Hard stop (no goodbye) of every sender — the
  explicit no-goodbye primitive for a forced/unsafe stop. NOTE: config-driven
  removal no longer uses this; the daemon's standalone reconcile now withdraws
  gracefully (`Withdraw()`) when all RA config is removed (#5092).
- `ClearInterfacesWithoutGoodbye(names []string) error` — `ra.go`. Silent per-interface stop;
  leaves unrelated senders running, supersedes pending starts, and drops
  existing or late goodbye retry debt for those names. Cluster demotion uses it
  when the stable RETH source is shared with the peer, because a goodbye would
  withdraw that peer's live router. If both members are BACKUP, an old route
  may remain until Router Lifetime expiry; a new master's RA refresh repairs it.
- `Status()` — `ra.go`. Per-interface `SenderInfo`. A running sender has
  `State == "active"`; an interface whose sender is tearing down /
  emitting its goodbye is reported with `State == "draining"` (distinct
  from active, so a withdrawing router is neither read as still
  advertising nor silently invisible). A draining entry whose owner wedged
  past the join timeout also sets `JoinTimedOut` (#5094) so the display can
  show `draining (join timed out; reclaiming)` — a stuck drain being
  self-healed by the reclaimer, not a silent hang.

## Callers

`pkg/daemon`, `pkg/cli`, `pkg/grpcapi`.

## Dependencies

`pkg/config`.

## Gotchas

- Link DOWN→UP during a RETH MAC cycle kills the AF_PACKET socket.
  `ResendBurst()` is what closes that gap — without it, hosts see an RA
  outage from the moment of the link cycle until the next periodic RA.
- The goodbye RA carries router lifetime 0, telling hosts to drop this
  router as default gateway. Send one when explicitly withdrawing a zone
  or shutting down. It is emitted by the per-interface owner goroutine as
  its last write (see the shutdown contract above) so a normal RA can
  never follow it on the wire.
- Prefix lifetimes are clamped to satisfy RFC 4861 §4.6.2 (#2271):
  `buildRA` (`sender.go`) clamps each PrefixInformation's preferred
  lifetime DOWN to its valid lifetime (`if prefLife > validLife`). A pair
  where preferred > valid is malformed and a conforming host (RFC 4862
  §5.5.3) ignores the prefix, so an operator that types
  `preferred-lifetime` larger than `valid-lifetime` (or a 0-defaulted
  valid life paired with a large explicit preferred life) would otherwise
  silently lose SLAAC on every host. The clamp is never the reverse —
  extending validity would advertise a longer-lived prefix than configured.
- **RA lifetimes are bounded so one bad option cannot blackhole the whole
  segment (#3895).** The entire RA is built and sent in ONE `conn.WriteTo`,
  which internally marshals every option, so a single option whose lifetime
  overflows its on-wire field aborts the ENTIRE advertisement — the segment
  then silently stops receiving RAs and hosts lose their default route / SLAAC
  when the current RAs expire. Two guards, in depth:
  - **Primary (commit-time gate, `pkg/config` `schema_routing.go`):** the
    router-advertisement lifetime leaves are bounded to their wire fields —
    `default-lifetime` ≤ 65535 (RFC 4861 §4.2 16-bit), `prefix
    valid-/preferred-lifetime` ≤ 4294967295 (RFC 4861 §4.6.2 32-bit), and
    `nat-prefix`/`nat64prefix lifetime` ≤ 65528 (RFC 8781 §4 13-bit
    scaled-by-8, `8191*8`). An over-large value is rejected loudly at commit
    (#2497 typed these leaves but left them unbounded).
  - **Defense-in-depth (send-time, `buildRA` → `pruneUnmarshalableOptions`,
    `sender.go`):** each option is probed through `ndp.MarshalMessage` (the
    same encoder `conn.WriteTo` uses); any option that fails to marshal is
    logged and DROPPED so the rest of the RA still goes out. This backstops a
    config that predates the commit-time bound (e.g. a loaded `active.json`) —
    a bad option degrades to "missing that one option" instead of a total RA
    blackout. NDP options are independent on the wire, so per-option probing is
    faithful to how the combined RA marshals.
- **`configEqual` must track EVERY field `buildRA` stamps onto the wire.**
  `Apply` gates the sender restart on `configEqual(existing.cfg, cfg)` — an
  interface whose config compares EQUAL keeps running untouched (no RA gap),
  so any wire-affecting field that `buildRA` (`sender.go`) reads but
  `configEqual` (`ra.go`) omits produces a silent "commit clean but not
  enforced": the operator commits a change, sees no error, yet the wire keeps
  advertising the old value until an unrelated RA edit or a daemon restart
  reconciles it. The scalar comparison list is therefore the change-detection
  contract and must be kept in lockstep with the fields `buildRA` marshals.
  Two fixes of this exact class: `DefaultLifetimeSet` (#4119 — the set-flag is
  part of the identity because unset→1800 and explicit-0 marshal DIFFERENT
  Router Lifetimes) and `ReachableTime` / `RetransTimer` (#4570 — the RFC 4861
  §4.2 ND timer hints wire-stamped by #4307; here 0=unspecified maps directly
  to a zero wire field with no unset/default coercion, so a plain int compare
  is exact and no companion set-flag is needed).
  - **The converse also holds: CIDR fields compare by parsed value, not raw
    text (#4590 A5-03).** `buildRA` re-parses `NAT64Prefix` and each advertised
    `Prefixes[i].Prefix` via `netip.ParsePrefix`, so two strings that parse to
    the same `netip.Prefix` produce byte-identical wire. A raw-string compare
    therefore over-triggered: an operator re-typing an equivalent-but-
    non-canonical form (`64:ff9b::/96` → `0064:ff9b::/96`) forced a spurious
    sender restart (sub-second RA gap) with no wire change. `configEqual` now
    routes those fields through `prefixEqual`, which normalizes via
    `netip.ParsePrefix` and falls back to an exact string compare when either
    side fails to parse (so a genuine change is never masked — an unnecessary
    restart is harmless, a missed one is not).
- IPv6 NODAD is set on the per-instance NDP socket so it doesn't fight
  the kernel's own duplicate-address detection on the link-local
  address.
- `ensureLinkLocal` (`sender.go`) guarantees a link-local exists for the
  NDP socket. RETH members run with `addr_gen_mode=1` (set by the daemon's
  `setRethIPv6Knobs`) to suppress kernel EUI-64 auto-generation and its
  MLDv2 noise, so a member may have no link-local when the sender starts.
  When one is missing the sender adds the EUI-64 `fe80::/64` directly via
  `netlink.AddrAdd` with `IFA_F_NODAD` — the same primitive the daemon uses
  in `ensureRethLinkLocal` / `addStableLLToInterface`. It does **not** mutate
  `addr_gen_mode` and does **not** cycle the link (#2034): `addr_gen_mode=1`
  is a contract the apply path sets deliberately, and an out-of-band link
  DOWN/UP from inside the RA manager would un-reconcile VIPs / stable LLAs
  and race the AF_XDP dataplane rebind. An interface with no usable 6-byte
  MAC degrades to a soft-logged warning (the caller only `slog.Warn`s the
  error); the explicit `source-link-local` config and the `listen()` retry
  loop (now in the owner goroutine, see below) are the recovery path.
- **Configured source link-local is picked from ANY unit (#2996).** The
  daemon's `buildRAConfigs` (`pkg/daemon/daemon_ra.go`) seeds each RA's
  `SourceLinkLocal` from an operator-configured `fe80::/10` address on the RA
  interface, so the sender binds to that address instead of an auto-selected
  transient EUI-64. `protocols router-advertisement interface <name>` may name
  a bare interface (`reth1`, `ge-0/0/2`) or a VLAN subinterface
  (`ge-0/0/2.50`, `reth0.50`); `cfg.Interfaces.Interfaces` is keyed by the
  BASE name with logical units under `ifc.Units`, so `resolveRASourceLinkLocal`
  splits the unit off the RA name before the lookup. Selection rule
  (deterministic across reconciles): a **unit-qualified** RA name uses the
  link-local configured on THAT unit; a **bare** name scans units lowest-first
  and uses the lowest-numbered unit that carries a configured link-local
  (byte-identical to the historical unit-0-only lookup when unit 0 holds it).
  When no unit carries a configured link-local, a RETH interface still falls
  back to `cluster.StableRethLinkLocal`. Before #2996 the lookup only ever read
  `Units[0]`, so an RA on a subinterface (link-local under a non-zero unit)
  silently ignored the configured source.
- **Bind retry runs UNLOCKED, in the owner goroutine (#2453).** `start()` no
  longer opens the NDP conn synchronously. It just launches `run()` and returns,
  so `Manager.startLocked` holds `m.mu` only for the cheap `InterfaceByName`
  check plus the `m.senders` bookkeeping. The socket open — `ensureLinkLocal`
  plus the `ndp.Listen` bind retry, which sleeps up to ~2s (10 × 200 ms) while a
  settling/RETH link-local appears — runs in the owner goroutine's `openConn()`
  before its main loop, with NO lock held. Before this, a slow/settling
  link-local on one interface stalled EVERY other RA manager op (a VRRP-failover
  `Withdraw`, or an `Apply` on a different interface) for up to ~2s, because they
  all contend `m.mu`. The bind retry is now interruptible by `stopCh`: a withdraw
  signalled mid-retry aborts the sleep instead of running the full ~2s.
  Consequences for the single-owner / #2033 invariants: `s.conn` is still opened,
  used, and closed solely by the owner goroutine. If the bind ultimately fails
  (or a stop lands before/during the retry) `openConn` returns false and `run`
  goes straight to `finishShutdown`, which tolerates a nil conn — no goodbye is
  written and `goodbyeEmitted` stays false, so the manager's release-time
  backstop (`sendOneGoodbye` on a FRESH conn) still emits a standalone goodbye if
  a graceful withdraw owed one. `start()` therefore never returns a listen error
  (the open is async); the only caller cost is that an unreachable interface is
  logged by the owner instead of surfaced as an `Apply` error — and every `Apply`
  call site already only `slog.Warn`s that error. `srcAddr` is now written by the
  owner goroutine and read by `Status` under `m.mu`, so it carries its own
  `srcMu` guard (`getSrcAddr`/`setSrcAddr`).
- Per RFC 5798, `AdvertiseInterval` is stored in milliseconds but goes
  on the wire in centiseconds. Don't double-convert.
