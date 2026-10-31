# HA Failover Status

Date: 2026-05-21 (updated)

This is the single authoritative document for userspace dataplane HA failover.
It replaces the fragmented state across a dozen prior docs. Read this first;
refer to the others only for implementation-level detail.

## Goal

Failover should be:

1. VRRP moves the virtual MAC
2. New owner sends GARP/NA
3. Traffic continues forwarding through synced sessions

No activation-time repair, no re-resolution, no queue bring-up, no barrier
choreography. Sessions are synced continuously — the standby should already
be able to forward.

## Current Reality

The system is closer to this goal than it has ever been, but it is not there
yet. Here is what is true today:

- Sessions sync continuously via event stream (real-time) + bulk (startup)
- Synced sessions are resolved with local egress on receipt (#326), not at
  activation time
- Flow cache uses epoch-based invalidation (#327) — no transition-time scans
- Demotion is a single `update_ha_state(active=false)` call (#359) — no
  two-phase prepare + demote
- Activation is a single `update_ha_state(active=true)` call (#358) — no
  explicit refresh RPC
- Manual failover uses request/ack/commit protocol (PRs #395-#397) — not
  weight-zero heuristics
- Takeover readiness gates on proven userspace dataplane health (#391): the
  control socket + ping, forwarding armed, XSK liveness, session mirror health,
  AND — since #5273 — the local event-stream listener being bound
  (`EventStream.ListenerBound()`). The listener is the primary local
  helper-to-daemon push path feeding the peer-sync pipeline, so a node whose
  `net.Listen` failed to bind is denied takeover readiness rather than silently
  starting in the slower `DrainSessionDeltas` polling fallback. The gate keys on
  the listener being UP, not on the local helper currently being connected;
  transient stream disconnects are covered by polling
- The takeover readiness gate applies on COLD BOOT, not only when the peer is
  alive (#7161). `electSingleNode` previously gated on `m.peerAlive`, so the
  gate was fully enforced on the peer-alive path and fully bypassed on the
  peer-dead path. The condition is `(m.peerAlive || !m.peerEverSeen)`:
  - **peer LOSS** (`peerEverSeen && !peerAlive`) keeps the fail-open. An
    established cluster had a working primary and it died; a survivor that
    refuses takeover is a TOTAL OUTAGE and may be the only node that can
    forward.
  - **cold BOOT** (`!peerEverSeen`) applies the gate. `handlePeerNeverSeen`
    records `peerConfirmedAbsent` separately, releasing the non-preempt hold
    without changing `peerEverSeen`. There is no established forwarding to
    preserve, and an unready node that promotes forwards nothing anyway — it
    claims the VIPs and the RG while unable to serve them, and denies the peer
    a clean takeover (#10697; #103 acceptance criterion 1).

  **POLICY CHANGE, declared:** a userspace-configured data RG with no published
  dataplane fail-closes in `checkUserspaceTakeoverReadinessFor`, so on a cold
  boot it now stays SECONDARY where it previously promoted. It forwards nothing
  either way; the difference is that it now says so instead of advertising
  itself primary for traffic it cannot carry.

  The prior in-code rationale ("sync readiness is impossible without a peer")
  was stale and has been replaced rather than narrowed: sync readiness is not a
  term in that conjunction at all. `IsReadyForTakeover` consults local
  interfaces, local VRRP and the local userspace dataplane — all determinable
  with no peer — and `fabricReady` is already forced true when the peer is down.

  **Degraded-promotion fallback** (`DefaultDegradedPromoteTimeout`, 2 min): after
  that much CONTINUOUS not-readiness a single node promotes anyway, with the
  reason surfaced on the election event and `DegradedPromoted` set, so a
  readiness bug can never cost the cluster both nodes. Two properties are
  load-bearing and are pinned by tests:
  - it is gated on NO peer condition — not `peerAlive`, not `peerEverSeen`, not
    sync connectivity. #110 shows the failure mode: `armSyncReadyTimer`'s
    callback bails on `!d.syncPeerConnected`, so its fallback never fires in
    exactly the peer-absent case it was written for. A fallback whose firing
    depends on the condition it compensates for is not a fallback.
  - it is armed at the DECLINE SITE in `electSingleNode`, not in `SetRGReady`. A
    cold-boot RG starts not-ready and may never see a readiness TRANSITION, so
    arming from the transition branch would leave it unarmed in precisely the
    case it exists for.
- Bounded startup promotion hold for `no-reth-vrrp` / `private-rg-election`
  (#7162). RETH VRRP mode has suppressed startup preemption since #466
  (`vrrp.Manager.SetSyncHold`, 30s, armed once at bringup, released by bulk
  session sync or its own timer). These modes had no equivalent —
  `checkNoRethTakeoverReadiness` was VIP ownership and nothing else — so a node
  could promote an RG before bulk sync delivered any conntrack/NAT state and
  every established flow reset on the transition.

  `Daemon.armNoRethSyncHold` (`pkg/daemon/daemon_ha_noreth_hold.go`) is the
  sibling: same 30s bound, armed at the same bringup site, consulted by
  `checkNoRethTakeoverReadiness`, released by bulk sync
  (`bulk-sync-complete`) or its own timer (`timeout-degraded`).

  **It is a bounded HOLD, not a `cluster.IsSyncReady()` conjunct, and the
  difference is the whole of #110.** `syncReady` has no bound while the
  session-sync channel is down (`armSyncReadyTimer` early-returns unless
  `syncPeerConnected`), and the election blocks a not-ready RG whenever the peer
  is alive — so a sync-flag conjunct blocks promotion INDEFINITELY when the peer
  is up on the control link with session sync down, which is exactly the
  degraded-peer case preemption exists for. Two properties keep this one
  bounded, and both are pinned by tests:
  - the timer callback consults NO peer condition — not `syncPeerConnected`, not
    `peerAlive`, not `IsSyncReady()`. A release that depended on the peer would
    be no release at all, because the peer being absent is why the hold is still
    held.
  - it is armed EXACTLY ONCE at bringup and never re-armed on reconnect, which
    keeps it a startup hold rather than a mid-life block.

  Releasing the hold DRIVES a reconcile (`triggerReconcile`). Readiness is
  recomputed per reconcile pass, so without that the RG would sit secondary until
  an unrelated event happened to trigger one — bounded in name only. The RETH
  sibling meets the same obligation with `triggerPreemptNow()`.

  **Deploy-tooling coupling (#7962).** `cluster-deploy`'s post-deploy primary
  reassert waits on this fallback, because on an idle cluster it is the only
  path to convergence: XSK liveness cannot self-prove on a node holding a data
  RG (`shouldAutoProveIdleStandbyXSKLocked` requires `!hasActiveDataRGLocked()`,
  and node0 holds RG1), and nothing is driving traffic. The reassert's budget
  was 30s against a 120s fallback, so it failed **by construction** on a
  restarted idle cluster — and both its passes and its failures were timing
  artifacts, indistinguishable from an HA regression in whatever branch happened
  to deploy next (#7688, #7939).

  The reassert now (a) PRIMES liveness with a little LAN→WAN traffic, which is
  what an operator does by hand and converges the common case in seconds rather
  than waiting out the fallback, and (b) falls back to a budget derived from
  `DefaultDegradedPromoteTimeout` only when priming was impossible — so a
  failing deploy is not routinely slower. `DEPLOY_REASSERT_FALLBACK_BUDGET_S`
  (`test/incus/deploy-lib.sh`) and this constant are coupled by
  `TestDeployReassertBudgetExceedsDegradedFallback7962`, which reads the shell
  default and fails if either side moves such that the budget stops covering the
  fallback.

  Its failure message now distinguishes the two states it used to crush into
  one: *traffic was driven and the dataplane still did not prove liveness* (a
  real signal) versus *traffic could not be driven, so the precondition was
  absent* (not an HA regression).

  Interaction with #7161: on a cold boot the readiness gate now applies, so the
  hold and the gate compose — the node holds secondary for the hold window, then
  promotes when readiness recomputes. The #7161 degraded-promotion fallback
  (2 min) is a strictly longer backstop, so the 30s hold is the binding
  constraint.

  **Observability:** `show chassis cluster information` gains a
  `Startup promotion hold:` block reporting the mode (`reth-vrrp` / `no-reth`),
  whether it is still holding, and how it ended. The RETH hold had recorded
  `bulk-sync-complete` / `timeout-degraded` since #466 and surfaced it NOWHERE,
  so an operator could not distinguish a normal startup from one that promoted
  degraded because sync never arrived — which is precisely the explanation for a
  flow reset after a boot. While the hold is active it also appears in the RG's
  `Takeover ready: no (...)` reasons.
- A manual failover into a node inside its startup promotion hold no longer
  leaves the RG owned by NEITHER node (#9452). `request chassis cluster failover
  redundancy-group N` demotes the local primary immediately; the peer's promotion
  then went through the bare readiness gate, so a request issued inside the
  bounded #7162 30s hold on a just-rejoined node was DEFERRED rather than
  refused — for 19s on the reproduction, up to the full 30s — with the CLI having
  already reported `Manual failover triggered`. Measured consequences in one
  `make test-failover` run: fw0 primary for none of RG0/1/2 at the check, and
  `ip neigh show proxy` EMPTY on both nodes for the pool-NAT address.

  The iperf3 average in the same run also fell from 22.5 to 18.1 Gbit/s, and that
  is a SEPARATE signal despite how well the arithmetic fits (~20-25s of a 120s
  stream carrying nothing). The fix refuted it: with the ownership gap closed to
  0-1s, two consecutive runs came back at 18.9 and 20.3, against
  `make harness-compare GATE=test-failover`'s `[21.375, 23.625]` green band — so
  closing the gap bought far less than the theory predicted, and the spread
  between two identical runs is a third of what is left. Tracked as #9484.

  The gate now recognizes a third reported shape beside peer LOSS and cold
  BOOT: a live peer that reports NON-OWNERSHIP — `secondary-hold` (explicit
  transfer-out) or weight 0. An explicitly zero-weight peer is forced to
  SECONDARY by election. A kernel-upgrade-held peer instead advertises weight
  0 as a wire clamp without changing its local weight, so the receiver cannot
  infer why the peer reports zero from this field alone.

  For explicit non-ownership, the cold-boot argument does not apply:
  established forwarding stops when the peer steps down. A SECONDARY/weight-1
  peer with observed PRIMARY history in its current session is also a yielded
  shape (#12164), so a not-ready receiver may promote DEGRADED. Without that
  history, SECONDARY/weight-1 remains the cold-boot shape and the gate holds.
  The held-peer weight-zero shape can also promote a not-ready receiver
  DEGRADED. These are intentional availability gains over remaining ownerless,
  despite the receiver's inability to distinguish the hold clamp from
  resignation. `DegradedPromoted` history says "peer reports weight 0"; it does
  not claim a held peer chose to resign.
  After `ClearKernelUpgradeHold`, the not-ready node may keep the RG over a
  recovered ready peer; clearing the hold does not automatically return
  ownership. The same keep can follow the two-minute degraded-promotion timeout
  if the hold lasts longer than that timeout.

  **The 30s hold is in contract and was not changed.**
  `daemon_ha_noreth_hold.go` states it releases on its own timer regardless of
  sync or peer state, so this was never a hold-duration bug: with perfect NTP and
  a fast bulk sync, a manual failover within 30s of a peer restart still
  blackholed the RG.

  `test/incus/test-failover.sh` also stopped hiding the difference. The
  assertion was a fixed `sleep 5` plus a boolean, which cannot tell a REFUSED
  transfer from one still in flight — and lengthening the sleep would have
  reported a 30s blackhole as a pass. It is now a bounded poll that reports the
  elapsed seconds per RG, its failure text carries `rg_ownership_diagnosis`
  (both nodes' `Takeover ready:` / `Transfer ready:` / `Forwarding:` lines, the
  peer's view, and the election journal tail), and the `request` command's stderr
  is captured instead of discarded. Note which readiness term was false: on #9452
  `Transfer ready` was `yes` on both nodes for all three RGs and `Takeover ready`
  was the blocker, so a message carrying only the transfer-readiness reason would
  still have said nothing.
- Blackhole routes skipped in userspace mode (#354)
- Helper watchdog threshold aligned with sync cadence (#349)
- Reverse companions pre-installed via sync path (#310)
- BPF conntrack entries written for zone/interface display (fab9230c)
- Userspace counters aggregated into BPF global counters (#332)
- Shared sessions indexed by owner RG for O(1) demotion/activation (PRs
  #404-#406) — no full-table scans during failover
- Priority barrier channel for acks (PR #407) — barrier/bulk acks bypass
  session data in send queue
- Planned failover decoupled from bulk sync (PR #407) — barrier ack
  proves peer is current, no bulk-sync gate
- Transfer readiness surfaced separately from takeover readiness (PR #402)
- Manual/planned failover refuses a config-stale standby (#5563): transfer
  readiness now also gates on the config-sync generation. A standby that has
  received a newer config generation from the primary than it has successfully
  applied (`PeerConfigGen > AppliedConfigGen` in `TransferReadinessSnapshot`) is
  reported not transfer-ready, so `request chassis cluster failover` will not
  promote it onto a stale policy set (fail-open after a tightening commit,
  false-deny after a loosening one). A legitimate same-generation failover still
  proceeds; the unplanned/crash path is not gated. Surfaced in
  `show chassis cluster status` transfer-readiness reason as "standby config
  stale: applied gen=N behind peer committed gen=M"
- The untargeted failover, the batch form and `ForceSecondary` refuse a
  config-stale standby too (#9569). The #5563 gate above runs on the node that
  becomes primary, so only the node-targeted form reached it. The untargeted
  `request chassis cluster failover redundancy-group N` and the ISSU drain
  (`request system software in-service-upgrade`) demote the local node instead,
  and they now refuse while the standby's latest config-apply nack matches the
  newest generation this node sent. The error names the generation.
- (removed in #8573) HA configs that use per-pool source NAT `persistent-nat`
  used to be refused userspace forwarding entirely, on the #1449 reasoning that
  leases are helper-local and not HA-synchronized. Measured on the loss
  userspace cluster, they are synchronized; the disarm is gone. The residual is
  narrower and is described under "Persistent SNAT Lease Boundary"

## The #16217 aged-failover chain (OPEN — not a cure)

PR #16217 (Refs #16215 #16216 #16109 #16222 #16223 #16269 #16270) is
**not merged and not an aged-failover cure**. Every live aged cell on
its head still fails the acceptance below. This section is the
authoritative root-cause chain so no leg is re-diagnosed from scratch;
per-leg evidence lives in `docs/log/16215.md`, `docs/log/16222.md`,
`docs/log/16223.md`, `docs/log/16269.md`, `docs/log/16270.md`,
`docs/log/16270-cache-supersession.md`, and
`docs/log/16217-fabric-adoption.md` on that branch.

**Acceptance (unchanged, never met live):** all-node0 posture
(RG0/RG1/RG2 primary on node0, asserted by the harness before
traffic), P4 iperf3 60 s to `172.16.80.200:5211`, RG1 fw0→fw1 at
**30 s measured stream age at the RG transition instant**, **zero**
aggregate (`[SUM]`) and per-stream zero intervals, and a zero delta
in `xpf_userspace_snat_revoked_sessions_total` on both nodes
between the **stream-start** baseline and the post-failover sample
(a pre-failover baseline would hide the ~28 s revocation leg).
fails it: the source tables record **130 zero intervals** for that
arm — the column is headed "Zero SUM intervals" in some tables and
left unqualified in others, and 130 exceeds the ~30 aggregate
intervals a 60 s run has after the failover, so that number is a
per-stream/line count, **not** 130 aggregate intervals; do not quote
it as a SUM baseline. The comparable aggregate signature on the PR
head is 25 SUM zero intervals (31 s→end), all from failover+1 s. A
young-flow failover pass proves none of this.

The chain, in the order each leg was proven and closed (each fix is
necessary, none is sufficient; the residual always moved one stage
later):

1. **Seed / DiscardRoute demotion (#16269).** Post-revocation
   retransmits demoted the cluster-terminal FIB row to a plain
   `DiscardRoute`; fw1's fabric-ingress cache hit then consumed that
   cached discard as a terminal drop. Fix: HA demotion preserves
   cluster-terminal provenance (`source_ifindex`), the seed
   (`from_deny_decision`) preserves it into the cached entry with no
   1 s deny TTL, and both fabric converters rescue a `DiscardRoute`
   whose would-be egress RG is now peer-owned / locally active.
   Operator discards (`source_ifindex == 0`) stay bit-identical
   drops — the rescue is provenance-gated, never a guess.
2. **FIB republication ordering (#16270 FIB leg).** Connected-RG
   republication was async and duplicate-skippable, so an arriving
   retransmit could hit the pref-200 cluster-terminal before the
   helper FIB held the republished /24. Fix: synchronous
   `republishConnectedRG` under `applySem` **before** `SetRGActive`
   on both activation paths, plus a guarded FIB connected-win (a
   covering connected prefix beats a selected non-cluster terminal
   only while a cluster-terminal row proves republication is owed;
   settled-FIB operator discards are bit-identical).
3. **Supersession (#16270 cache leg, #16222).** Cache revalidation
   had supersession arms for `FabricRedirect` and `DiscardRoute`
   but none for a locally-egressing `ForwardCandidate` whose egress
   RG became peer-owned, and it judged cached redirects with a
   destination-only lookup against a per-flow session resolution
   (split-RG `fabric_local_wins` churn, ~25k evictions/s). Fix:
   `ForwardCandidateEgressDeparted` eviction arm (known egress RG,
   not forwarding-active locally, non-empty HA map only) and
   per-flow ECMP revalidation judged against the stored resolution
   context — a different-owner local candidate supersedes only if
   it serves the flow locally. Live nuance: on the uninstrumented
   build the pre-existing `lookup_rg_epoch`/`lookup_lease` fences
   usually evict first; the arm owns the enforce-equal shape.
4. **Split handshake (#16223).** In split posture (RG1 fw0, RG2
   fw1) flows never left the 20 s TCP opening window: the
   completion predicate's `syn_ack_first == is_reverse` conjunct
   never fires for a plain pending pair hit on its reverse half,
   pure Opening rows never arm, and GC's `companion_keeps_alive`
   refused pending companions — both halves expired at ~20 s under
   continuous cache service (`Timeout: 20` at every sampler).
   Fix: served-evidence completion (`cache_hit_handshake_progress`:
   promoted companion / refreshed half / nonzero admitted reverse
   counters — a dropped spoofed SYN-ACK charges none) promotes both
   halves to Established (`Timeout: 1800`) + HA Update, with
   node-level evidence consulted before the local refusals and a
   replica fence so a `WorkerLocalImport` expiry cannot evict the
   serving incarnation's cache/NAT state. Pure Opening pairs keep
   the #6752/#13679 refusal; closing pairs keep their fuse.
   **#18520 residual (intra-node split).** The node-level arms read
   per-table `node_served_stamps` that no sibling ever wrote, so a
   flow whose SYN and SYN-ACK land on different workers of ONE node
   (every SNAT'd flow, by RSS) still never completed on the worker
   holding the authoritative forward row: `Timeout: 20` for the
   flow's life, Opening exported over HA sync, and the evidence scan
   on every cached packet. Fix: a cross-worker handshake relay
   (`session/handshake_relay.rs`) carries the validated SYN-ACK
   (with its ack and the server SYN end, re-validated by the
   receiver, #16042) and the completion between sibling tables
   through the worker command queues, once per loop pass. The
   authoritative row normally completes on the client's completing
   ACK (or, if that ACK beats the relay, on a later client segment
   or the SYN-ACK worker's relayed completion) and emits the
   Established HA Update then, so a failover imports Established
   instead of Opening. A connection idle right after its handshake
   with that race lost still sits on the opening window (see
   `userspace-dp/src/session/README.md`, "Limits"); the worker import keeps
   the handshake stage monotonic per incarnation, so a stale bulk
   Open cannot regress that replica back to the 20 s window (whose
   3 x 20 s standby HOLD ceiling reaped it before a failback).
5. **Wire-stage / counter carriage (#16217 Wire3–Wire13).** The
   fabric-ingress adoption gate read only the shared synced wire,
   which stayed `HandshakePending` (`w=2`) for exactly the heavy
   split streams: completion evidence was per-table (split across
   workers, never assembled), gated on the 10 s conntrack-refresh
   slice, excluded `WorkerLocalImport` serving rows, and — once
   scoped-evidence adoption existed — the HA wire carried
   `fwd=0/rev=0` on every delta (Rust stamped
   `SessionCounters::default()`, Go had no counter fields, import
   hard-stamped zero; the unit arm constructed counts in-process —
   test-only-green, FZDiag19). Fixes, all fail-closed: node-wide
   evidence aggregation at the ct-slice (shared Established remains
   OUTPUT only), same-packet-path wire advance on cache-hit
   completion, Established export stamp at all three export sites,
   evidence requiring an actual reverse packet count > 0, scoped
   (full `SessionKey`, never `bare_tuple()`) pending-row adoption,
   backup-origin publication, additive live-counter carriage on
   Open/Update/bulk in both families with monotonic per-incarnation
   merge, and backup-arm slice admission. FZDiag20 proved there is
   **no steady-state HA delta**: all emission is transition-triggered,
   so counters are only as fresh as the last transition — any future
   gate must not assume a periodic sync vehicle exists.
6. **Neighbor / seed completion (Wire13).** Once fw1's rows finally
   read `Timeout: 1800` pre-failover and fabric packets adopted,
   resolution landed on `MissingNeighbor`: fw1 never served the
   flow pre-failover, its kernel entry for the direct server hop
   `172.16.80.200` (connected /24, `next_hop == None`) had aged to
   FAILED, and the coordinator warmer only walked route next-hops
   and fabric peers — no code named the direct destination. Fix:
   `queue_warm_pass` also enqueues direct destinations of shared
   synced forward rows covered by a connected prefix, re-driven at
   RG activation (`on_rg_promote_active`). Proven closed live:
   `172.16.80.200 … REACHABLE` on fw1 from d28 through post, fw1
   `Neighbor misses = 0`, in both runs.
7. **HA-inactive on the receiving worker (OPEN residual).** The
   current head (`b9741b5bd7`) still fails twice-on-loss (26 and 25
   SUM zero intervals, all from failover+1 s, no pre-failover
   zeros). fw1's last resolution for the heavy wire tuples now
   reads `ha_inactive ingress-ifindex=4 egress-ifindex=14
   next-hop=172.16.80.200` — neighbor resolved, sessions
   Established, but the fabric packets are HA-gated/discarded
   instead of adopted/served on the receiving worker. **This leg
   FZFixWire22 stamped backup-served counters (ct-slice stamps
   every forward pair, any origin/stage) and made the adoption
   gate read the fresh coordinator RG-active set, yet the live
   aged cell (99.16217.43.dirty, cell52) still fails with 29 SUM
   zero intervals, fw1 rows still `Timeout: 20` at d28 and last
   resolution still `ha_inactive` -- so this leg is STILL open
   and unnamed beyond those two arms. Do not merge #16217 as the
   aged-failover cure until a cell shows zero zeros with this leg
   closed.**

Also closed on the branch, independently of the aged cell:
peer-synced rows (incl. `DemoteOwnerRGS`-retagged `SyncImport`)
whose stored decision is terminal **or** `FabricRedirect` decline
SNAT revalidation (the fabric pseudo-egress has no `EgressInterface`
row, so the first geometry check revoked unconditionally; the
`FabricRedirect` half is superseded by #18531 below: any origin, keyed
on the judged resolution, with `HAInactive` added);
revocation only on a fresh decision's withdrawn translation, and
`StaleSourceNat` revocations are counted per binding and exported
as `xpf_userspace_snat_revoked_sessions_total`. Reverse hits never
substitute the reply decision for the stored forward decision.

**#18531: an ownership transient is no ground to revoke an SNAT session.**
A split-RG failback (RG1/WAN to the peer, RG2/LAN kept) killed every
established SNAT stream, on both nodes, through the source-NAT revalidation
(`source_nat_revocation_on_session_hit_with_ingress`).

*The node keeping the LAN RG (fw1).*

1. `update_ha_state` publishes the inactive RG1 before the workers drain
   `DemoteOwnerRGS`.
2. The serving worker's first LAN packet after the RG-epoch flow-cache
   invalidation hits its crash-takeover `SharedPromote` row, which is
   locally authored and not yet retagged.
3. The packet re-resolves to `FabricRedirect` and persists it.
4. The row's SNAT judgment is Stale: while the flow cache served the row,
   every kernel neighbor batch advanced the #16109 neighbor generation.
5. The #16215 `FabricRedirect` decline was gated on `is_peer_synced()`, so
   the validator judged the fabric parent, which has no egress row, and
   revoked the pair. The Close passed the daemon's fabric-redirect sync
   branch and deleted the WAN owner's live copy.

*The node taking RG1 (fw0), in the window after the peer demoted RG1 and
before this node activated it.* fw1 fabric-redirects the translated flow,
and fw0's imported row re-resolves to `HAInactive`. With the #18519 split
FIB that resolution is the default via the WAN gateway on reth0.50,
because the peer-owned reth0.80 prefix is withheld. The validator judged
reth0.50's address against the reth0.80 translation and revoked the pair.
That Close is not synced back (owner-RG gate, fw0 not yet primary), but
fw0 had lost the session for good.

The rules now:

- **Decline keyed on the judged resolution.** A judged `FabricRedirect` or
  `HAInactive` names no egress this node forwards out of, so the judgment
  is declined for every origin. The session is kept, the packet takes its
  HA disposition (redirected, dropped, or forwarded on a #16217 adopted
  candidate), and the stamp stays stale.
- **Live egress judged first.** The live-resolution substitution runs
  before that decline for every origin (it was peer-synced only). When the
  egress RG returns, the forward hit is judged on the real egress, even at
  the same generation, where nothing re-stores the row.
- **Persisted redirect keeps its owner RG.**
  `persisted_owner_rg_for_resolution` keeps the recorded owner RG for a
  `FabricRedirect`; the fabric parent names none. The row therefore stays
  in the RG index that `DemoteOwnerRGS` and `RefreshOwnerRGS` walk. That
  RG is inactive here, so the WAN owner's revocation, arriving as a peer
  delete, is not refused by the #9048 locally-owned guard.
- **No alias purge on a fabric arrival.** On a non-owner, a translated
  forward hit on a peer-synced row is held transient
  (`should_keep_synced_hit_transient`) and, before this, was then purged
  (`purge_translated_synced_hit_with_context`), silently and with no
  Close. On the RG-taking node the peer's fabric redirect is exactly such
  a hit, so the window removed the forward-wire alias of a live flow.
  Where the alias was the only copy, the first packet after activation
  missed and the flow died. This takes the purge away from its original
  population: it was introduced for fabric arrivals (75965fb3ff) and
  widened to direct arrivals later (8ea4d780eb); #6599 is the later report
  that a spoofed direct packet can abuse the purge-and-re-enter path. It is
  safe to hold: the row stays transient (not materialized), the packet
  still takes its HA disposition (a fabric arrival is never redirected
  back, so it is dropped, or forwarded on a #16217 adopted candidate), and
  the owner's Close or the row's idle timeout reclaims it. A held hit
  probably refreshes the row's idle clock (the lookup takes the packet
  time; inferred), so a node that never takes the RG keeps the row while
  the peer redirects. When this node owns the RG nothing is held. The purge
  still runs for a direct arrival on a non-owner.
- **On a fabric arrival, a live `HAInactive` is judged, then declined.** A
  keep-transient hit persists nothing, so the validator judged the stored
  import-time line. On the RG-taking node under the split FIB, for v6, and
  for both families when the import found no neighbor (`MissingNeighbor`),
  that line is egress 13 (reth0.50), which does not carry the reth0.80
  translation, so it revoked. On a fabric-link arrival the live decision
  now stands in when it is `HAInactive` as well as a forward candidate, and
  the decline above holds the session. The rule is by arrival link. A
  fabric arrival is the peer's redirect of a flow whose egress this node
  does not forward, so the egress owner judges it. A direct arrival on a
  non-owner is not a redirect, so its stored line is judged here as before
  (#12187: a later same-tuple static SNAT revokes there). The #12187 cell
  pins both. A live `FabricRedirect` never stands in.
- **A peer delete of the translated tuple removes the canonical row.** The
  owner's revocation is what removes the LAN node's declined row. An owner
  that holds only the translated alias (plus the reverse synthesized from
  it) can name nothing but the translated tuple, and the LAN node, which
  matched peer deletes on the exact key, kept its original-tuple row and its
  withdrawn translation. `SessionDomain::delete_synced` now resolves a
  peer delete of a key this node does not hold through the forward-wire
  index to the canonical row it names, and deletes that pair under the same
  mode. The #9714 locally-owned guard applies; the #10512 identity check
  applies only to a SCOPED delete. An ordinary peer Close arrives unscoped,
  so it removes whichever row holds that translation now, including a later
  flow that reuses the translated tuple (pinned by
  `widened_peer_delete_identity_and_outcome_18531`). A refusal of the
  canonical delete (gate busy, mirror write, locally owned, identity) is
  what the caller sees, so the daemon keeps and retries its rows. A delete
  of a key this node holds is never widened, so Go's #6368 stale-epoch
  rollback of an install that landed deletes only that key. Gap: with a
  routing instance configured, a bare (domainless) delete of a key held in
  no domain stops in the handler's ambiguity probe before
  `delete_synced`, so the widening does not run there. (e760f5eef5 first had
  the owner close the canonical tuple, recovered from its reverse row; that
  cannot work for the production alias-only owner, whose reverse was
  synthesized from the alias, and was removed.)
- **The canonical row wins the import over a peer-synced alias.** The
  import used to let the canonical row and its forward-wire alias compete
  for ONE translated-tuple reservation, keeping whichever arrived first.
  When the alias won, the node held the flow only as the alias (diag6: 5 of
  8 flows; diag7b: 3 of 8): at the activation its reverse resolved to
  `LocalDelivery` (handled below), and at the full failback, when the LAN RG
  moved there too, the original-tuple packets missed and the flow died
  (diag7b, `LOCAL-ABSENT key=10.0.61.102:<port>` right after fw0 activated
  RG2). Now:
  - A peer-synced alias never books the translation (coordinator import
    and worker twin). Nor does a local promotion of one: a fabric hit
    after this node took the WAN RG re-tags the alias `SharedPromote` and
    replicates it to the other workers, and each replica used to book the
    identity, so every later canonical import was refused for the flow's
    lifetime (review E/F, probe R2-P1). A `SharedPromote` row of the alias
    shape takes no new booking and keeps whatever booking the row it
    replaces held, so a prewarm `SharedPromote` over a reserving
    `WorkerLocalImport` keeps it (#15966r). Pinned by
    `promoted_alias_does_not_refuse_its_canonical_import_18531`.
  - An alias import is refused while its canonical row is held, so it can
    never replace that row's reverse with its own. The daemon sends the
    canonical row first, so a healthy split cluster refuses aliases at the
    redirected-flow rate. The refusal has its own outcome
    (`RejectedSupersededAlias`, wire reason `superseded-alias`) and does not
    count in `xpf_userspace_synced_import_reserve_refused_total`, whose
    growth means flows that will not survive a failover. The daemon still
    rolls back the alias's mirror row and counts it in `Imports refused by
    helper`, as it did when the same arrival failed the reservation.
  - A canonical import retires a peer-synced alias of the same flow
    (forward key only). It retires through the peer-delete path, so the
    removal re-checks the row under the shared-map lock and keeps a row a
    worker promoted in the meantime (the #9714 locally-owned guard, on the
    workers too), and no CLEAR close is harvested for a flow that lives on.
    A promoted alias stays beside the canonical row (the shared store
    already treats that pair as one session under two keys); it books
    nothing, so it never refuses the canonical row. The cost: while a
    promoted alias is this node's ONLY copy of the flow (the alias arrived
    first, or the canonical import was refused for another reason), the
    flow's translation is unbooked here, so a new local flow to the same
    server and port can be handed the same translated port and share the
    reverse key (the #4388/#6600 collision). The window closes when the
    canonical row lands and books it. Pinned by
    `canonical_import_supersedes_its_alias_18531` (both orders, v4/v6) and
    `alias_promoted_during_the_canonical_import_is_kept_18531`.
  - Gap: an identity translation (the original source already is the
    translated address and port) has the alias shape, and a row carries
    nothing that tells the two apart. A peer-synced canonical row of that
    shape books nothing on the importing node either, so after a takeover
    a new local flow could be handed the same identity (the #4388 hazard).
    Interface SNAT produces it only for a client whose source already is
    the egress address. Before #18531 such a row booked like any other.
- **An alias's reverse is handed to the peer, never to the host.** A reverse
  synthesized from a forward-wire alias takes the alias key's source as the
  client, which is the SNAT address itself: its un-NAT rewrites nothing.
  On the node that owns the egress RG that address is local, so the target
  lookup answered `LocalDelivery`, and the next WAN reply ran the
  host-inbound gate, was denied and tore the pair down (diag6: the five
  streams fw0 lost were exactly the five it held only as the alias; the
  activation `RefreshOwnerRGS` logged `old_disp=FabricRedirect
  new_disp=LocalDelivery`). A reverse whose un-NAT names its own wire
  destination (`reverse_un_nat_targets_itself`) now resolves to the fabric
  redirect toward the peer that holds the canonical row: at synthesis from
  an alias, and in the one re-resolution pipeline (`reresolve_stored_session`:
  session hit, `RefreshOwnerRGS`, `DemoteOwnerRGS`) only when the target
  lookup answers `LocalDelivery`. That gate matters: the reverse-synthesis
  arm also installs a self-targeting row for a reply that arrives already
  un-NATed (the peer un-NATed it and handed it over the fabric), keyed by
  the client tuple. Its target is the real client and it must forward; the
  ungated version dropped every such reply on the LAN node after a FIB
  generation bump (loss diag8). Pinned by
  `lan_node_unnatted_fabric_reply_keeps_forwarding_18531`. Without a redirect (a
  fabric-borne reply, or no fabric) the row resolves to `HAInactive`, so a
  reply is dropped, never bounced, delivered locally, or forwarded on a raw
  FIB answer. The match is on NAT shape: an identity translation (the
  original source is the SNAT address and the port is unchanged) looks the
  same and is handed to the peer too. The synthesis arm is not gated, so a
  pool alias's reverse (its target, the pool address, answered by proxy
  ARP, is not local, so the lookup answers the WAN neighbor path) is
  handed to the peer at import (pinned by
  `pool_alias_reverse_is_handed_to_peer_at_synthesis_18531`). Gap: the
  gated re-resolution leaves that row on the WAN neighbor path
  (`MissingNeighbor` toward the pool address after `RefreshOwnerRGS`),
  so an alias-only pool-SNAT flow still loses its replies on the node
  that took the WAN RG. The DNAT-only and port-only alias reverses
  (pre-existing) are not covered either; see #18535. A reverse that un-NATs to a genuinely
  local address other than its wire destination is still host-bound and
  still gated. The LAN node's own reverse rows un-NAT to the client and are
  unaffected.

A withdrawn translation is revoked by the node that owns the egress, on
its next slow-path hit with a stale stamp. That is not every redirected
packet: flow-cache hits are not re-judged. The terminal
(`DiscardRoute` / `ClusterTerminalHAInactive`) decline is still gated on
peer-synced origin.

A window remains on the reverse side. Reverse hits never substitute (the
reply's own resolution is the LAN egress). So when the egress RG returns
with a translation withdrawn, a reply that arrives before any forward
packet judges the forward row's stored `FabricRedirect` or `HAInactive`,
declines, and is un-NATed and delivered. `RefreshOwnerRGS` does not close
it: it rewrites the stored line to the real egress but, like every HA
identity rewrite, clears the row's source-NAT judgment, and the #16217
guard declines reverse revocation of an unjudged row with no forward VLAN
provenance. The window closes at the first forward slow-path hit, which
judges the real egress and revokes the pair. An inbound-only flow (for
example UDP pushed from the server) can therefore keep reaching the
client through the withdrawn binding until a forward packet arrives.
Pinned by `rg_return_reply_first_window_closes_at_forward_hit_18531`;
tracked in #18535.

Pinned by `afxdp::tests_split_rg_failback_18531`, which drives the
production poll pipeline on the captured split snapshots, and by the
`SharedPromote` cell of `peer_synced_fabric_redirect_snat_declines_16215`.
The daemon-side routing of the owner's Close is the existing owner-RG gate
and is not covered by those cells; the two-node cell
`alias_only_owner_revocation_removes_lan_row_18531` feeds the owner's
Close keys to the LAN node's coordinator as the peer deletes the daemon
sends (the Go legs were read, not run). Residuals are tracked in #18535:
- a translated alias row removed in the RG gap, so an alias-only copy
  loses the flow (fixed here);
- activation before the connected-RG FIB republish (open);
- scope-less imports not judged by the owner (open);
- the reverse-side window above (open, pinned);
- why the RG-taking node held only the alias of some flows (fixed: the
  import race above);
- DNAT-only and port-only alias reverses, whose un-NAT also targets itself
  (open, pre-existing);
- loss cluster, after this fix (0.0.26021, diag9/diag9b), still open:
  - in the split state (WAN RG on one node, LAN RG on the other) every
    stream crawls at about 0.1 Gbit/s until the LAN RG follows; it was also
    there before (diag7b);
  - one of 8 streams died at the full failback, its reverse on the new
    owner stuck on a missing LAN neighbor (inferred from one trace);
  - an intermittent crash-takeover death: the server answers the first
    forwarded packets with RSTs and the close relay retires the flows
    (diag7b double-failover transition 1; diag9 test-failover transition
    1; diag8 and diag9b survived);
  - 6 to 12 s of outage at the double-failover second takeover (peer-loss
    detection; the flows survive).

### Never-again gates

- **Aged cell, not young cell.** The harness gate is
  `scripts/userspace-ha-failover-validation.sh --aged-failover`
  (port 5211, P4 60 s): it asserts RG0/RG1/RG2 are all primary on
  node0 before traffic, stamps the actual stream start once
  `start_iperf` proves the client live, and schedules the RG1
  transition to **land** at 30 s measured stream age: it times an
  identical 8-call CLI snapshot pass (`capture_cycle_state`)
  immediately beforehand and sleeps only the remainder, then stamps
  the age again at confirmed ownership — failing closed if the
  snapshot lead already overshoots 30 s. The 60 s stream keeps 30 s
  of post-transition traffic. `MAX_ZERO_INTERVALS` is forced to 0
  (per-stream and preflight zero budgets already default to 0), and
  the `xpf_userspace_snat_revoked_sessions_total` delta from the
  stream-start baseline must be 0 on both nodes (an unavailable
  metric fails the gate, it does not skip it). A failover issued
  inside the 20 s opening window or the first conntrack-refresh
  cycle is not evidence.
- **Twice on loss.** No leg is "fixed live" on one run; every leg
  above was required to fail twice on the same build before the
  next leg was named, and the cure must pass with the identical
  25-zero signature absent — not merely reduced.
- **Homogeneous build proof.** Helper sha256 must match
  `/proc/<pid>/exe` on both nodes before traffic; cluster restored
  to clean master and re-verified after each cell. Mid-stream
  helper restarts invalidate the cell (FZDiag20 cells 33–35).
- **No test-only-green evidence.** A unit arm that constructs the
  very evidence the wire was dropping (Wire10 counters) does not
  close a leg; the evidence must cross the real encode/import path.
- **Fail-closed adoption.** Every gate above declines on absent,
  pending, closing, reverse-only, scope-mismatched, or zero-count
  evidence, and falls through to the ordinary miss/drop path.
  Operator discards without provenance are never rescued.

## What Works

Manual failover with `request chassis cluster failover redundancy-group 1
node N` successfully moves RGs between nodes. Sessions are synced, SNAT is
applied on the new owner, traffic continues. Validated with iperf3 4-stream
tests showing 27M SNAT packets on the new owner after failover.

The key fixes that made this work:

| Commit | Fix |
|--------|-----|
| ba1c4304 | Async bulk ack + HA sync throttle — bulk sync completes reliably |
| 7417144e | Re-resolve synced sessions with owner_rg_id=0 |
| 71b80b3d | refresh_for_ha_activation bypasses synced guard — SNAT works |
| a21018f3 | Epoch flow cache, resolve on receipt, owner_rg_id at sender |
| dcc59c67 | Unified synced flag → origin-based collision detection |
| PRs #395-397 | Explicit RG transfer protocol (request/ack/commit) |
| PRs #404-406 | Owner RG indexes — O(1) demotion/activation |
| PR #407 | Priority barrier channel + decouple failover from bulk sync |

### Failover command/action grammar — one strict parser (#5810, #5851)

The manual-failover command and its wire action string are validated by a
single, side-effect-free grammar in `pkg/clusterfailover`. Every entry point —
the remote CLI (`cmd/cli/request.go`), the in-process CLI
(`pkg/cli/cli_request_chassis.go`), the gRPC loopback handler
(`pkg/grpcapi/server_diag_system_action.go`), and the fabric-allowlist
interceptor (`pkg/grpcapi/server.go` `parseProxiedFailoverAction`) — routes
through `clusterfailover.ParseCommand` (operator tokens) or
`clusterfailover.ParseAction` (wire string) and acts on the SAME typed
operation. Callers never assemble or partially parse the privileged action
string ad hoc.

The grammar is closed. Exactly four forms are accepted:

| Operation | Command | Wire action |
|-----------|---------|-------------|
| Plain RG failover (untargeted) | `redundancy-group <rg>` | `cluster-failover:<rg>` |
| Targeted RG failover | `redundancy-group <rg> node <0\|1>` | `cluster-failover:<rg>:node<0\|1>` |
| Data failover | `data node <0\|1>` | `cluster-failover-data:node<0\|1>` |
| Reset | `reset redundancy-group <rg>` | `cluster-failover-reset:<rg>` |

`<rg>` is a non-negative decimal group ID; `<0|1>` is a supported chassis node.
Unknown, missing, misspelled, duplicate, signed, whitespace-laden, or trailing
tokens — and an empty `:node` suffix — are rejected with usage/`InvalidArgument`
BEFORE any cluster method or peer dial. This closes the class where a truncated
automation variable or a typo (`redundancy-group 1 nod 0`, `redundancy-group 1
node`, or the gRPC `cluster-failover:1:node`) silently degraded to the broader
untargeted `ManualFailover(<rg>)`, moving ownership in an unintended direction.

The loopback handler and the fabric interceptor now share this parser, so they
can never disagree on which action strings are well-formed. The fabric gate may
still deny a valid but local-only form (plain RG failover, reset) by policy —
only the two node-targeted forms are proxyable — but that denial is a policy
choice, never a divergent parse. Shared accept/reject token-vector tables live
in `pkg/clusterfailover/grammarvectors` and are exercised by all four layers'
tests so the verdicts cannot drift.

## Persistent SNAT Lease Boundary

**#8573: the admission boundary is LIFTED.** A chassis cluster whose source-NAT
rules reference a pool with `persistent-nat` now forwards. The gate that refused
it, and the reason string it reported —

```
userspace persistent-nat source pool leases are not HA-synchronized
```

— are both deleted, along with the #8447 commit advisory that announced them.

### Why it was there, and why it is not

#1449 closed as an admission boundary rather than partial lease replay: leases
were held to be helper-local allocator state that the helper does not
synchronize or replay to the peer, so the dataplane declined to forward rather
than forward with semantics it could not honour. #8447 then found that the
refusal was *silent* — the interfaces stay up, the config commits cleanly, and
the failure presents as a connectivity problem rather than a NAT one — and made
it visible at commit, at disarm, and as a metric.

What neither could do was check the premise, because the gate disarmed the
forwarding a check would have needed. #8573 was filed to unblock exactly that,
and the answer is that the premise had stopped being true. Three sync routes had
landed underneath it (#7360, #8132, #8121 — the census below), and their
exhaustiveness is bound by a test rather than left in prose.

**Measured on the loss userspace cluster, with the gate lifted on both nodes**
and a rule-referenced `persistent-nat` pool committed:

| | result |
|---|---|
| both nodes armed | `FWDD State Online`, pool SNAT allocating sequentially into the pool range |
| lease reaches the standby | identical identity on both nodes — same source tuple, same translated address and port, same pool |
| lease survives failover | present on both nodes after a manual RG0 failover |
| lease is HONOURED after failback | node1 allocated a translated identity; node0 imported it with the remaining timeout intact; after failback node0 translated the SAME source identity to the SAME translated identity node1 had chosen |

The last row is the whole of what persistent NAT promises, and it is the one a
lease that merely *arrived* would not satisfy.

### What the residuals are

Two, and both mean "this particular lease did not reach the standby" — never
"the standby forwards with semantics it cannot honour".

**The sync window.** A lease created on the active in the interval before the
next export/import cycle is not yet on the standby, so a failover inside that
window drops it — the flow gets a fresh translated identity instead of its
pinned one. That is a much narrower statement than "not HA-synchronized", and
it is the same window every other synced object lives with.

**A refused import.** A lease whose pool address the standby's config lacks,
whose port bit is already held there, or that arrived already expired, is
refused by design (#8121). Each refusal is correct: the standby mints its own
translation rather than install a duplicate or a wrong translated identity. The
helper logs one line per import BATCH naming the refusal classes —

```
xpf-dp: idle-lease import installed=N existing=N expired=N unknown_addr=N unknown_pool=N port_busy=N malformed=N
```

— and #8573 widened that line's trigger to fire on `unknown_addr` too. That is
the class meaning the two nodes disagree about a pool's address list, and it
previously logged NOTHING: a batch in which every lease was refused for it was
silent. That mattered less while the gate refused to forward these configs at
all; with the gate lifted it is the residual's main surface.

The other surface is the existing per-pool persistent-lease counters
(`show security nat source persistent-nat-table detail`, and the pool status table's
lease counts), which are per-node: comparing the two nodes shows whether the
standby is tracking the active. They are the right surface for a post-lift
world precisely because they are a *quantity to compare*, where the removed
reason string was a verdict with no gradations — it could say only "refused",
never "behind by three leases".

### What this does NOT say: pool-mode return traffic is separately broken

The gate is lifted on the strength of the LEASE measurement, and that
measurement was read from the session table and the persistent-NAT lease tables
on both nodes — deliberately not from throughput, because pool-mode source-NAT
return traffic on this cluster does not work at all, with or without
`persistent-nat`.

That is **#8621**, a different defect, and it is not attributable to this one:
it reproduces with `persistent-nat` removed from the pool, while interface-mode
SNAT from the same host to the same target got 7.44 Gbit/s at the same moment.
Root cause is a kernel proxy-ARP arm the pool address cannot reach — `ip route
get` for the pool address returns the egress interface itself, and all three
arms of `arp_process`'s proxy branch are gated on the route's device differing
from the ingress device — so the firewall never answers ARP for the pool
address and no return frame is ever addressed to it.

The distinction matters to an operator reading this section: **"HA persistent-NAT
is supported" is a statement about lease survival across a failover, not a
statement that pool-mode SNAT forwards end to end today.** Both are needed for
the feature to be usable, they are independent, and only the first is what
#8573 measured.

### What the operator sees now

Nothing. The configuration commits and forwards, which is the point. The
disarm machinery #8447 built is unchanged and still live for the capability
reasons that remain (a color-aware three-color policer, a SYN-cookie screen
profile with no root-authentication material): the WARN at disarm and
`xpf_dataplane_forwarding_supported` are both untouched, and are more
load-bearing now that a disarm is a rarer event an operator is even less likely
to be looking for.

The predicate `config.UsesPersistentSourceNATPool` SURVIVES the removal. It no
longer gates forwarding, but `ensurePersistentSourceNATProtocolLocked` reads it
to raise the required helper protocol version to
`MinProtocolPersistentSourceNAT` — so a wrong answer still ships persistent-NAT
config to a helper that cannot honour it. It stays keyed on the **rule**, not
the pool table: a `persistent-nat` pool no rule references translates nothing.

### What the standby DOES rebuild today (#7360, #8132, #8121)

This is the census the lift above rests on. The standby does not hold nothing —
it reconstructs a lease for every persistent session it imports, and receives
the idle ones explicitly.

**Reconstruction, not replay.** A lease is a property of the SOURCE; session
sync carries SESSIONS. So the standby does not receive leases — it derives them
from the imports that actually succeeded, in `reserve_synced_on_first_pool_owner`
(`userspace-dp/src/nat/source/synced.rs`). Deriving rather than carrying is the
load-bearing choice: the standby installs a strict subset of what the active
sends (reserve refusal, capacity, stale generation, discriminator withhold), so
a carried `active_flows` would credit the lease for sessions this node does not
hold — and a refcount that never reaches zero is never idle, so the lease would
never enter the expiry index and no GC path could reclaim it.

There are two reserve paths, and they needed separate fixes because they are
separate functions:

| path | selected by | reserve | fixed in |
|---|---|---|---|
| port-translating (PAT) | a translated port on the wire | `reserve_flow_maybe_persistent` | #7360 |
| address-only | `port no-translation` in a session path; also available to port-less protocols when they have a session decision | `reserve_address_only_maybe_persistent` | #8132 |

**Flowless transit caveat (#10679).** The address-only lease path is a
per-session allocator, not a guarantee that every port-less packet gets a
translation decision. Raw ESP/GRE and other no-L4 transit packets take the
flowless path from #6837 and do not have a session decision to carry that
lease. If a same-family NAT rule requires their source or destination to be
translated, the dataplane drops them before TX, missing-neighbor buffering, or
permitted NoRoute kernel-FIB reinjection rather than leaking the untranslated
source. NoRoute probes configured egresses because its actual egress is
unknown. Pref64 retains NAT64 attribution, and raw ESP/AH non-first fragments
retain the Stage-11/reassembly park path. The separate flowless-NAT-drop counter
records the fence; the allocator behavior above continues to describe sessions
that actually reach address-only reservation.

**The two paths pin different things, and that changes what can fail.** Under
PAT the lease pins a `(address, port)` and the PORT is the fragile half — with
`address-persistent` the address survives a failover for free, because
`sticky_pool_index` is a pure function of `(src_ip, pool_len)` under the fixed
`STICKY_POOL_HASH_SEED` (#14627) and both nodes compute it. Under
`port no-translation` the client keeps its own source port on
the wire, so there is no translated port at all: the lease pins an ADDRESS, and
the address is the whole promise. A test that asserts the address while
`address-persistent` is on measures the hash rather than the repair, which is
why the cells for both live on multi-address pools with that flag OFF and decoy
flows interleaved.

**The IDLE lease is rebuilt too, by a different route.** A lease whose flows
have all closed but whose inactivity window is still open has no session to be
derived from, so nothing above reaches it. #8121's `export_idle_leases` /
`import_idle_leases` verbs carry that population explicitly, and the chain is
wired end to end — allocator verbs, control handler, Go manager, cluster sync
payload, daemon hook — with the wire pinned across the two languages
(`idle_lease_wire` in `protocol_wire_v1.json`).
The receiver and live-session reserve paths admit new leases into the same
bounded `persistent_by_source` table used by local persistent-NAT mints. If
the table is still at `max_tracked_flows` after one bounded expiry-GC pressure
pass, the new lease is refused (idle imports report capacity separately from a
busy identity). The cap bounds total table growth, not each side separately:
idle imports, synced-session mints, and local mints share the table
first-come-first-served, while joining an existing lease does not consume a
second entry. Imports in either lease mode also check
both live ownership domains for overlaps at their remote scope: exact endpoint,
target-host (`host, 0`) wildcard, or any-remote.

### The population is now claimed COMPLETE, and the claim is bound

Three routes, and between them every lease an active node holds:

| lease | route to the standby |
|---|---|
| has live flows, port-translating | rebuilt from the synced sessions (#7360) |
| has live flows, address-only | rebuilt from the synced sessions (#8132) |
| idle, inside its timeout | exported and imported (#8121) |

That is an exhaustiveness claim, and defining a population by a mechanism is a
CLAIM that the mechanism is the only route — which fails silently when a sixth
site appears that nobody classifies. So it is not left in prose:
`every_persistent_lease_creation_site_has_a_sync_route_8121` pins the five
production sites that create a lease, by enclosing function, and reds until a
new one is classified. It carries a positive control, because a scanner whose
pattern has rotted compares empty to empty and passes forever.

**What this bears on.** This census was written as an argument that the #1449
gate's stated reason no longer described the tree, deliberately stopping short
of re-deciding the gate — re-arming forwarding for a disarmed configuration
class is a user-facing availability change needing its own verification, not a
side effect of the work that removed its premise. #8573 ran that verification
and removed the gate.

The census is therefore no longer an argument *against* a gate. It is what holds
the gate's removal up, and its failure mode inverted with it: a sixth
unclassified insert site used to mean an argument was overstated, and now means
clustered persistent-NAT is forwarding with leases that do not survive a
failover. `every_persistent_lease_creation_site_has_a_sync_route_8121` is the
thing standing between those two states.

## What Was Fixed Recently

### P0: Barrier delivery during bulk sync — FIXED (PR #407)

Barrier acks and bulk acks now route through a dedicated priority channel
(`barrierCh`). The `sendLoop` drains `barrierCh` before `sendCh`, so acks
are never stuck behind bulk session data. Barrier requests still go through
`sendCh` to preserve ordering (the barrier must be after all queued sessions
so the ack proves the peer processed them).

### P2: Manual failover rejected during bulk sync — FIXED (PR #407)

Removed `syncPeerBulkPrimed` and `TransferReadiness` bulk-state checks from
the planned failover path. The barrier ack alone proves the peer is current.
Bulk sync is a startup concern, not a failover concern.

### P3: Split-RG readiness stuck — LIKELY FIXED

Root cause was barrier/bulk ack delivery stuck behind bulk data (P0). With
priority ack channel, acks should deliver promptly. Needs live validation
on split-RG cluster.

### Daemon restart blackhole: orderly stop now resigns (#18540) — NEEDS LIVE GATE

`make test-restart-connectivity` lost 1/7/33 pings per cycle on loss (tcp: 8).
The journals are skewed: loss fw1's wall clock runs 66.8 s behind fw0's.
Aligned, fw1 detected peer loss and took every RG in all three cycles, and no
control-plane dual-secondary occurred. The causes:

- **Orderly stop sent no handover.** Its only signal was the arm floor
  (weight 1), which RG0 never yields on and which a peer parked in
  secondary-hold by the harness's manual-failover restore cannot take. The
  peer waited 3.3-3.4 s for heartbeat loss plus the sync-recency deferral,
  with the stopping node's helper already gone. Cycle 1 (no holds) moved
  RG1/RG2 in 0.26 s on the arm-debt yield.
- **A peer restart missed by loss detection kept the old incarnation's
  holds** (latent; it did not fire in this run).

Now an HA stop with a live peer installs the full-cost `__planned-shutdown__`
debt (weight 0) after the fail-closed actions, and kicks one heartbeat. A lone
node skips the resign: a demotion there would let the still-live event
watcher confirm a pending `commit confirmed`. A heartbeat
from a new peer incarnation ends ManualFailover, transfer-out and abort holds,
exactly as peer loss does. See `pkg/cluster/README.md` "Planned-shutdown
resign and peer-restart hold release (#18540)".

**Status:** unit-tested and mutation-checked; needs `make
test-restart-connectivity`, `make test-failover` and `make test-ha-crash` on a
gate cluster.

**Note for that gate:** the peer now promotes before it has drained the
stopping node's sync backlog, so more synced imports land after activation.
Such an import does not replace a local session the new owner already holds
(#9678, deliberate). It does reach `USERSPACE_SESSIONS` through the worker
fan-out (verified in #18550/#18551). Post-takeover loss leads are tracked in
#18550/#18551.

### Manual failover refused 11-29 s after a peer restart — FIXED IN SOURCE (#18541, #18374), NOT YET LIVE-VALIDATED

After a peer restart the survivor's barrier fence refuses manual failover
until the restarted node acks a cold-prime bulk. On loss (2026-10-30
`test-ha-crash` phase 3) that took 11-29 s for ~520 sessions, for two
independent reasons:

- **Install throughput (#18541).** The receiver installs each bulk session
  with two helper session-socket round trips, and the helper's accept loop
  slept 10 ms whenever it found nothing to accept — which was every time,
  because Go dials each request just after the previous response. ~20 ms per
  session, ~51 sessions/s, ~10 s per 522-session bulk, linear in table size.
  The loop now wakes on the listener's readiness.
- **Discarded bulk (#18374).** Any config apply or interface-link refresh
  inside the receive window advanced the ownership generation, even when it
  installed identical ownership, so the reconcile was skipped, the `BulkAck`
  withheld and the whole bulk discarded; the second bulk then paid the same
  ~10 s again. Ownership installs now carry a resolver digest and keep the
  generation when nothing the reconcile reads changed.

Both are covered by hermetic cells; neither has been through `make
test-ha-crash` on a cluster yet.

### A RETH address removed by commit stayed on the RG owner (#18573) — FIXED IN SOURCE

In direct-VIP mode (private-RG election, the compiler default) the add and
remove passes both derived their set from the active config at call time. A
commit that renumbered `reth0.50` (`.10` -> `.42` on tcp, `.11` -> `.43` on
udp) left the old address on the owner indefinitely. The owner answered ARP for
it, and a demotion left it behind too. Because the userspace snapshot is built
from the kernel listing, interface SNAT kept translating new LAN flows to the
removed address (udp: LAN to 1.1.1.1 0/30) until the next snapshot.

Now every direct-mode VIP is stamped in the kernel (`IFA_PROTO`,
`pkg/vipstamp`), and every reconcile pass deletes a stamped address the config
no longer assigns to its netdev, on the owner and the non-owner alike. The
snapshot builder never publishes such a leftover, and a reconcile-path change
queues an interface-link snapshot refresh. See `pkg/daemon/README.md`
"Direct-mode VIP failover" and `pkg/dataplane/README.md` "Interface rows
never publish a direct-VIP leftover (#18573)".

**Limit:** a pre-#18573 VIP that the config had already dropped before the
upgrade carries no stamp and must be deleted by hand once.

**Status:** unit, real-kernel (netns) and mutation-checked; live renumber +
RG move on tcp pending.

## What Still Needs Work

### Cycle-3 post-takeover loss in `test-restart-connectivity` (#18540, OPEN)

In the 06:32 run, cycle 3 lost 33 of 40 pings. The ping stayed dead for
about 14 s after fw1 owned RG0/1/2 and had sent GARP/NA. fw1 logged no
`SESSION_OPEN` for that ping (cycle 2's takeover opened a fresh session), and
fw1 kept draining about 700 of the dead peer's `session_v4` frames (about
21 ms each) for up to 7 s after takeover. The control plane does not explain
it. The orderly-stop resign shortens the ownerless window, but the
post-takeover loss needs an instrumented re-run: a LAN-host capture plus
`show security flow session` on the new owner during the gap.

### Inherited translated tuples resolve as HA-inactive (was P1)

After failover, some inherited forward-wire tuples (translated 5-tuples
from SNAT) may resolve as `HAInactive` on the new owner. PRs #404-406
added owner RG indexes to shared session stores, which should improve
the lookup path. Needs live validation to confirm the fix.

**Status:** Likely improved, needs testing.

### Live validation of all fixes

The recent changes (priority barrier channel, owner RG indexes, planned
failover decoupled from bulk sync) have not been validated together with
a live `/failover-test` run. The individual pieces are tested but the
end-to-end flow needs validation.

### Throughput parity on fabric redirect path

When traffic is fabric-redirected (old owner → new owner via fabric link),
throughput is ~7 Gbps vs 15-17 Gbps for direct forwarding. This is a
hardware/topology limitation — fabric redirect adds an extra hop through
the virtio fabric interface. Traffic should converge to direct forwarding
on the new owner quickly.

## Architecture

### Session Sync Flow

```
Active node:
  helper creates session → event stream → daemon → session sync TCP → peer

Standby node:
  session sync TCP → daemon → SetClusterSyncedSessionV4 → helper UpsertSynced
  → resolve with local egress immediately (not at activation)
  → session is forwarding-ready in the helper's session table
```

#### Import refusals and the split-truth rollback (#6785)

The standby's install is transactional (#5305): the daemon snapshots the BPF
session row, writes it, mirrors to the helper, and RESTORES the snapshot if the
mirror fails — so a failed install never leaves a row for a session the helper
does not hold.

The helper can refuse an import for three SEMANTIC reasons, none of which are
faults:

| refusal | reason | issue |
|---|---|---|
| `stale-generation` | the stored entry is NEWER than the incoming one | #2170 |
| `capacity` | the aggregate synced-import entry ceiling is full | #5674 |
| `reserve` | the translated NAT tuple could not be reserved for this import | #6600 |

Before #6785 all three returned `ok = true`, so the daemon recorded a success
and left its BPF row behind — the exact split truth the transactional install
exists to prevent, on the one failure class it could not observe. The helper now
answers `ok = false` with a `synced-import-refused:<reason>` token, and the
existing rollback runs.

**A refusal is NOT a mirror failure, and the two must not be conflated.** A
transport failure means the helper session socket is sick and gates HA
takeover-readiness (#5247). A refusal comes from a HEALTHY helper answering
correctly — the peer sent something stale, or this node is at its own ceiling.
Gating takeover on a refusal would keep a working standby from ever taking over
once a peer oversubscribed it, which is worse than the divergence being fixed.
So a refusal:

- rolls back the local BPF row (no split truth),
- does **not** set the sticky session-mirror-failure flag,
- does **not** count toward the session-sync `Errors` total,
- counts into `Imports refused by helper`, rendered by
  `show chassis cluster information` only when non-zero.

That counter is health **debt**, not an error: the local state is consistent, but
the PEER believes it synced a session this node does not hold, and only the
peer's next full sync closes the gap. A persistently non-zero count means the
peer is oversubscribing this node.

### Failover Flow (Target)

```
1. CLI: request failover RG1 to node1
2. node0: barrier check (peer has all sessions)
3. node0: update_ha_state(RG1=false) — atomic demotion
   - bump RG epoch (flow cache auto-expires)
   - demote shared sessions
4. node0: VRRP sends priority-0 burst → node1 becomes MASTER
5. node1: VRRP MASTER → addVIPs → GARP/NA
6. node1: update_ha_state(RG1=true) — activation
   - sessions already resolved with local egress (from step above)
   - bump FIB generation
   - traffic starts flowing immediately
```

### Failover Flow (Current)

Steps 1-6 above are now the actual flow. Remaining differences from target:
- Some translated tuples may still resolve as HAInactive (needs validation)
- Neighbor warmup still runs async after activation (harmless — ARP/NDP
  for next-hops, not blocking the forwarding path)

### Requested transfer is make-before-break (#18559)

The flow above is the VRRP-era picture. In the default private-RG mode, a
requested transfer (`request chassis cluster failover redundancy-group N node
<peer>`, or `data node <peer>`) is run by the REQUESTER, and it now opens its
dataplane before the owner closes its own:

```
1. requester: readiness + transfer-readiness checks
2. requester: pre-activate — republish connected-RG routes, then open helper
   forwarding for the data RGs (cluster state still secondary)
3. requester -> owner: failover request
4. owner: session-sync barrier, secondary-hold, rg_active=false, VIPs removed
   (#5640 fence), applied-ack
   - traffic still reaching the owner is fabric-redirected to a requester
     that already forwards it
5. requester: election -> primary, rg_active=true (already open), VIPs, GARP/NA
6. requester: commit-ready, commit -> owner; release the pre-activation
```

Before #18559, step 2 did not exist. Everything the owner redirected between
step 4 and step 5 was dropped at the requester's fabric-ingress HA-inactive
gate: 100-137 ms per RG for per-RG moves and about 200 ms per RG for the
batch, measured on the loss cluster. Design and invariants:
`pkg/cluster/README.md` ("Make-before-break transfer pre-activation") and
`pkg/dataplane/README.md` ("Transfer pre-activation overlay").

Measured on the loss cluster (iperf3 `-P8 -i0.1` to 172.16.80.200:5211 plus
`ping -i 0.01`; RG0/1/2 moved to node1 and back; `docs/log/18559.md`):

| build | moves | ping lost (failover / failback) | worst stream gap | HA-inactive drops |
|---|---|---|---|---|
| master + #18556 | per-RG | 23 / 26 | 700 / 1000 ms | +19.2k on the new owner per move |
| + #18559 | per-RG | 4 / 11 | 500 / 900 ms | 0 |
| master + #18556 | `data` batch | 20 / 21 | 800 / 1300 ms | (same shape) |
| + #18559 | `data` batch | 13 / 5 | 1300 / 500 ms | 0 |

Every packet still lost after #18559 is a `config_generation_mismatch` /
`fib_generation_mismatch` drop. Each helper publish (the pre-activation's own
route republish, and the FRR-driven republish and FIB bump after every
ownership edge) drops in-flight packets until Go rewrites the shim's
generation stamp. That is #18560.

The untargeted form (`request chassis cluster failover redundancy-group N`
on the owner) still demotes locally and lets the peer promote on the next
heartbeat. Prefer the node-targeted form, and the `data node <peer>` batch
when moving every data RG: the batch has no split window between RGs.

### Watchdog heartbeat: map write every tick vs IPC on change/backstop (#2549)

The daemon runs a per-RG watchdog timestamp refresh (`pkg/daemon/daemon_ha_sync.go`)
on a 500ms ticker. The `ha_watchdog` map is Go-owned bookkeeping: no live
userspace-XDP shim BPF program references or reads it (#10791). If the daemon is
SIGKILL'd while the helper remains alive, missing `update_ha_state` receipts
let the helper's receipt-anchored **10s forwarding lease**
(`ActiveUntil(max(watchdog, now) + 10s)`) expire; the peer separately takes
over after its heartbeat timeout. The lease is stored in helper memory and does
not survive helper death; process loss/ctrl-disable and fresh-helper republish
are separate from lease expiry. The HA timestamp has two distinct write paths
with **different cadence requirements**, and `UpdateHAWatchdog`
(`pkg/dataplane/userspace/manager_ha.go`) decouples them:

- **Go-owned `ha_watchdog` map write — EVERY tick (500ms), never throttled.**
  This keeps Go's own map-readback refresh paths current. It is a cheap local
  map update, not a socket round-trip or helper-health input.
- **`update_ha_state` socket IPC — throttled.** The full HA-state JSON IPC over
  the shared Rust-helper control socket is the expensive part. Issuing it every
  tick is a 2/s-per-RG control-socket caller — exactly what the CLAUDE.md
  *Control socket contention* rule forbids (">1/s … will starve session installs
  during bulk sync"). It now fires only when:
  1. **An RG `Active` state CHANGES** (failover/failback) — published
     IMMEDIATELY. This is the load-bearing failover-timing path and is NEVER
     throttled. (The authoritative active-change publish is `UpdateRGActive`'s
     own direct `update_ha_state`; the heartbeat path also force-syncs on a
     detected per-RG `Active` delta as defense in depth.)
  2. **As a periodic BACKSTOP** — once the watchdog timestamp has advanced by
     `haWatchdogIPCBackstopSecs` (3s) since the last IPC for that RG, so the
     helper's receipt-anchored 10s lease is refreshed well before expiry.

  Per-RG throttle state (`haWatchdogIPCSynced`, under `m.mu`) records the last
  timestamp/`Active` published per RG; the first heartbeat after startup/seed
  has no baseline and always syncs. The baseline is recorded BEFORE the send so
  a post-send error cannot cause a per-tick resync storm (the next ≤3s backstop
  retries), and `UpdateRGActive` records it too so the heartbeat does not
  redundantly re-fire right after a failover.

**Pending demotions while the manager lock is held (#10781):** `UpdateRGActive(false)`
announces a pending demotion before waiting for `m.mu`. While one is pending,
watchdog ticks keep writing the Go-owned timestamp map but do not refresh the
helper over the session socket; queued session sends recheck before dialing. Once
the inactive snapshot is published, refreshes resume from that state. This
preserves helper lease expiry as the fail-closed behavior while a demotion is
waiting on manager work.

**Threshold rationale:** 3s gives a >3x margin under the helper's 10s
receipt-anchored lease and drops the heartbeat's control-socket load from 2/s
per RG to at most ~0.33/s per RG (≈6x reduction), while Go continues writing its
bookkeeping map at the full 500ms cadence. Failover/failback timing is unchanged
because state changes bypass the throttle entirely.

**Live-config read every tick (#3917):** the heartbeat loop re-reads the
CURRENT redundancy-group set (`d.currentRedundancyGroups()` →
`d.store.ActiveConfig()`) on each tick rather than the `cc.RedundancyGroups`
snapshot captured when `startClusterComms` first ran. `startClusterComms` is
only restarted on a **transport-field** change (`clusterTransportKey`), so a
redundancy-group added by a day-2 commit would otherwise never receive a
watchdog write — its watchdog would stay stale and the dataplane would refuse
to forward for it. The loop is now gated on a published dataplane alone (no startup
RG-count precondition) so it also picks up the first RG added to a cluster that
booted with none.

### Peer fence reads the live config (#3917)

On a heartbeat timeout the surviving node may send a **fence** over the sync
channel; on receipt `OnFenceReceived` (`pkg/daemon/daemon_ha_sync.go`) attempts
to deactivate `rg_active` for every redundancy group. This can suppress peer
forwarding at that instant, but does not demote the peer or release its VIPs,
so it is not dual-primary exclusion. The handler
(`d.fenceAllRedundancyGroups`) reads the CURRENT active config via
`d.currentRedundancyGroups()`, NOT the startup `cfg` closure. Before #3917 the
callback iterated the snapshot captured at `startClusterComms` time; because
comms are only restarted on a transport change, a day-2 redundancy-group was
absent from that snapshot and was **never fenced** — leaving it active on this
node while the peer also became active for it (split-brain dual-active, the
exact failure the fence exists to prevent). The handler is nil-safe in
config-only mode (no published dataplane) and when the config has no cluster stanza.

### Observing peer fencing (#72)

`show chassis cluster information` renders a **Peer fencing:** block whenever
`peer-fencing` is configured or a fence has ever fired on this node:

```
Peer fencing:
  Action: disable-rg
  Attempts:
    Aug 21 09:14:02  Fence disable-rg sent to peer
    Aug 21 09:31:47  Fence failed: peer not connected
```

`Action` is the CURRENTLY committed `set chassis cluster peer-fencing` value —
`disabled` when the leaf is absent — which can differ from the action the listed
attempts were recorded under, because the event history outlives a config
change. Each attempt line is one `handlePeerTimeout` fence decision and its
outcome.

The absent `peer-fencing` leaf is the default and sends **no fence**. After any
peer-loss takeover without a peer confirmation, both `show chassis cluster
status` and `show chassis cluster information` render `Peer-loss takeover:
DEGRADED`, with the reason and time; the information view also reports local
node health as degraded. This is an operator warning, not a gate: the node
still takes over. A later peer heartbeat clears the marker.

### `disable-rg` — best-effort, unacknowledged

`SessionSync.SendFence` (`pkg/cluster/sync_failover.go`) writes `syncMsgFence`
and returns; nothing is sent back. A `sent to peer` line therefore means the
write reached the socket, not that the peer disabled its redundancy groups.
Local takeover is consequently NOT gated on the fence — `handlePeerTimeout`
runs `electSingleNode()` BEFORE it attempts the fence, so a dead peer (fence
unreachable) can never block the survivor from forwarding.

Because this policy has no acknowledgement, a sent, failed, or skipped
best-effort attempt is still reported as an unconfirmed/degraded takeover. A
successful socket write must never be read as confirmation that the peer
stopped forwarding.

Attempt lines: `Fence disable-rg sent to peer`, `Fence failed: <err>` (the sync
channel was down — the node still takes over on the heartbeat timeout), or
`Fence skipped: sync not available` (no session-sync peer-fence function was
armed).

### `disable-rg-confirmed` — acknowledged, bounded, fail-open (#7147)

`set chassis cluster peer-fencing disable-rg-confirmed` sends a SEQUENCED fence
BEFORE the election and waits, bounded, for the peer to report what it
disabled. `SendFenceAwait` (`pkg/cluster/sync_fence_ack_7147.go`) writes
`syncMsgFence` carrying an 8-byte sequence number; the peer runs its fence and
replies `syncMsgFenceAck` (type 35) carrying that sequence, a status, and the
number of redundancy groups it drove to `rg_active=false` out of the number in
its live config.

**"Fenced" means peer-confirmed, not merely acknowledged.** The ack is written
only after the receiver's `fenceAllRedundancyGroups` has run, and only a
full-success result is reported as confirmed. A peer in config-only mode (no
published dataplane) replies `unavailable` rather than a vacuous success over
an empty RG set.

**The gate never withholds ownership.** Every negative outcome proceeds with the
takeover:

| Situation | Cost | Attempt line |
|---|---|---|
| Peer not connected | none — returns immediately | `Fence unconfirmed, took over anyway: peer not connected` |
| Peer predates #7147 | none — capability not advertised | `Fence unconfirmed, took over anyway: peer does not support fence acknowledgement` |
| Sync channel dropped mid-wait | none — waiter released at once | `Fence unconfirmed, took over anyway: session sync disconnected...` |
| Socket alive, peer silent | up to `FenceConfirmTimeout` (1 s) | `Fence unconfirmed, took over anyway: timed out after 1s...` |
| Peer partly fenced | none | `Fence NOT confirmed (peer disabled only 1/3 redundancy groups), took over anyway` |
| Peer confirmed | one fabric round trip | `Fence confirmed by peer (peer disabled 4/4 redundancy groups)` |

The only row that spends the timeout is one where the TCP socket is still up
but no ack comes back. The ordinary dead-peer takeover costs nothing extra,
because `SendFenceAwait` returns immediately when there is no active
connection — there is nothing to wait for.

Every fail-open confirmed-policy outcome is also rendered as a degraded
peer-loss takeover, including an acknowledgement timeout. The marker clears
when a later peer heartbeat returns.

A `Confirmations: received N, timed out N, sent to peer N` line accompanies
`Action` whenever the policy is armed or any ack traffic has occurred. Read
`timed out` as "takeovers that proceeded without the guarantee you selected";
it is the only place that number appears, since `Fences sent` counts a
confirmed and an unconfirmed takeover identically.

### What peer fencing does NOT give you

**Neither the default nor either configured policy excludes dual-primary
ownership.** `disable-rg` has no acknowledgement; `disable-rg-confirmed` has a
bounded wait and its fail-open outcomes are visibly degraded, but even a
positive acknowledgement is only a point-in-time dataplane-suppression receipt.
It does not demote the peer or release its VIPs. The peer can resume forwarding
on its next reconcile, and both nodes can continue to report PRIMARY while
heartbeats are partitioned.

With `disable-rg-confirmed`, the sync socket can remain live while its packets
are blackholed: the fence write succeeds but no acknowledgement arrives. After
`FenceConfirmTimeout` the node takes over anyway while the peer may still be
alive and forwarding; status marks that takeover degraded with the timeout
reason. The fixed bound is a fail-open policy, not a guarantee that an
acknowledgement will arrive before promotion.

Failing CLOSED and refusing takeover without confirmation could leave nobody
forwarding when a partition never resolves. The policy therefore favors
availability, and operators must treat the degraded marker as evidence that
fencing did not establish mutual exclusion.

An operator selecting confirmed fencing gets a point-in-time suppression
acknowledgement when it arrives in time, and local election is ordered after
that acknowledgement. They do **not** get proof that the peer is demoted, has
released the VIPs, or will remain dataplane-inactive.

### Telling a confirmed fence from a fail-open

The configured action does not reveal the result. `EventFence` records the
attempt outcome, while `Peer-loss takeover: DEGRADED` in both status views
records that the latest peer-loss takeover proceeded without confirmation.
The marker gives the reason (for example, fencing disabled, a best-effort
unacknowledged send, timeout, disconnect, or incomplete peer fence), and the
information view marks local node health degraded. The marker clears on a
returning peer heartbeat.

### What a CONFIRMED fence does and does not give you (#9120)

A confirmed fence is narrower than the word suggests, and the gap is the part an
operator would misjudge, so it is stated here rather than left to be inferred
from the code. `fenceAllRedundancyGroups` drives `rg_active=false` on the
dataplane and re-arms the RG state machine. It does NOT:

- **release the VRRP virtual addresses.** The fenced node keeps every VIP, keeps
  answering ARP/ND for them, and keeps winning the VRRP election on the RETH
  members. Upstream L2 still steers that traffic at it and the dataplane drops
  it. A confirmed fence turns the peer into a BLACKHOLE, not into a node that
  has handed the addresses over. Traffic converges when the surviving node's own
  takeover moves the VIPs, not when the ack arrives.
- **demote the peer.** `clusterPri` is untouched: the fenced node still reports
  itself primary for those groups in `show chassis cluster status`, and an
  operator comparing the two nodes during a partition will see two primaries.
  That is expected and is not the sign of a failed fence.
- **hold.** `desired = clusterPri || allVrrpMaster`, and the fence changes
  neither input, so the next `reconcileRGState` pass on the fenced node
  re-drives `rg_active=true` (that re-arm is #6530's required behaviour — a
  fenced-then-recovered primary must not stay dark forever). **The suppression
  therefore lasts at most one reconcile interval** unless something else
  changes one of those inputs first: the peer observing the takeover over the
  sync channel, an operator, or a real crash.

What `disable-rg-confirmed` buys is ordering the local election after a
point-in-time dataplane-suppression acknowledgement, when one arrives in time.
It does not guarantee zero VIP overlap, lasting suppression, peer demotion, or
dual-primary exclusion. It is not a lease; a stronger guarantee needs a fence
that changes `clusterPri` with a bounded self-clearing timer, since an
unbounded fence would turn a lost sync channel into a no-primary outage.
Pinned by `TestFenceAckProvesDataplaneSuppressionOnly9120`.

**Mixed-version clusters are safe and need no coordinated upgrade.** Both wire
changes are additive: `syncMsgFenceAck` is a new type that an old peer skips
via the receive switch's missing `default` arm, and the fence sequence is
trailing data on an existing type whose old receiver reads no payload. A
fence-ack capability bit rides the trailing byte of `syncMsgPeerCapabilities`
(#6650). Neither `SessionSyncWireVersion` nor `CurrentHAProtocolVersion` is
bumped — bumping would push `GateProtocolCompat`'s single-point compatibility
window off the peer's version and refuse the rolling upgrade this has to
survive. A mixed pair degrades exactly to `disable-rg` behaviour on both sides.

Do not read this block as the **Install fence:** block that appears above it in
the same output — that one reports the bulk-sync install barrier sequence
(`LastFenceSeq`), an unrelated mechanism.

## What Was Eliminated

These mechanisms existed before the simplification work and have been
removed or bypassed:

| Mechanism | Removed in | Why |
|-----------|-----------|-----|
| `FlushFlowCaches` worker command | a21018f3 | Replaced by epoch-based invalidation |
| `refresh_owner_rgs` explicit RPC | 5ac423a3 | Sessions pre-resolved on receipt |
| `prepare_ha_demotion` two-phase | #359 | Demotion is atomic in update_ha_state |
| `SuppressedUntil` lease variant | #359 | No longer needed without prepare step |
| `syncPeerBulkPrimed` hard gate | e42c882e | Replaced by barrier-based readiness |
| Quiescence retry loop | a21018f3 | Single barrier is sufficient |
| Event stream drain/pause/resume | a21018f3 | Barrier proves delivery |
| Kernel session journal flush | a21018f3 | eBPF ctrl is disabled in userspace mode |
| `pendingRGTransitions` map | 5ac423a3 | Replaced by atomic bool |
| Blackhole routes (userspace mode) | 5ac423a3 | XDP shim + rg_active handles this |
| Weight=0 manual failover | PR #395 | Replaced by explicit transfer state |
| `synced: bool` field | dcc59c67 | Replaced by origin-based collision |
| `syncPeerBulkPrimed` failover gate | PR #407 | Barrier ack proves peer is current |
| `TransferReadiness` bulk-state check | PR #407 | Planned failover doesn't depend on bulk |
| Full-table scans on demotion/activation | PRs #404-406 | Owner RG indexes for O(1) lookups |
| `waitForSendQueueDrain` in barrier path | PR #407 | Priority channel for acks |

## Testing

### Automated

```bash
# Hardened RG move under load (the primary validator).
# Keep the run long enough to expose late collapses, move RG1 quickly in both
# directions, and keep all eight stream lines visible during the run.
BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env \
IPERF_TARGET=172.16.80.200 \
TOTAL_CYCLES=12 CYCLE_INTERVAL=5 \
scripts/userspace-ha-failover-validation.sh --duration 600 --parallel 8
```

```bash
# Aged-failover never-again gate (#16217): streams age 30s (past the
# 20s TCP opening window) before a single RG1 failover; acceptance is
# NO zero intervals. Expect this to FAIL until the HA-inactive leg
# named in "The #16217 aged-failover chain" is closed.
BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env \
IPERF_TARGET=172.16.80.200 \
scripts/userspace-ha-failover-validation.sh --aged-failover --duration 60 --parallel 4
```

```bash
# Reverse-path coverage is also required. The validator currently exercises the
# source-sending path, so run a matching reverse iperf after the forward pass.
iperf3 -c 172.16.80.200 -P 8 -t 600 -R
```

### Manual CLI test

```bash
# Start long-running forward traffic and keep all per-stream lines visible.
iperf3 -c 172.16.80.200 -P 8 -t 600

# Rapidly move RG1 between fw0 and fw1 while traffic is active.
cli -c "request chassis cluster failover redundancy-group 1 node 1"
sleep 5
cli -c "request chassis cluster failover redundancy-group 1 node 0"
sleep 5
cli -c "request chassis cluster failover redundancy-group 1 node 1"
sleep 5
cli -c "request chassis cluster failover redundancy-group 1 node 0"

# Verify: SNAT > 0 on the new owner, no stream wedges at 0, and the run
# recovers back to full throughput after each move.
cli -c "show chassis cluster data-plane statistics" | grep SNAT
```

```bash
# Repeat the same RG movement under reverse traffic. This exercises the return
# path ownership and catches failovers that only work when the host is sending.
iperf3 -c 172.16.80.200 -P 8 -t 600 -R

cli -c "request chassis cluster failover redundancy-group 1 node 1"
sleep 5
cli -c "request chassis cluster failover redundancy-group 1 node 0"
sleep 5
cli -c "request chassis cluster failover redundancy-group 1 node 1"
sleep 5
cli -c "request chassis cluster failover redundancy-group 1 node 0"
```

### Pass criteria

- All 8 iperf3 streams survive every RG move in both forward and reverse runs
- Zero per-stream zero-throughput intervals in both directions
- Zero aggregate zero-throughput intervals in both directions
- No permanently wedged stream after failback in either direction
- SNAT packets > 0 on new owner
- Session misses < 1000 on new owner
- RG moves to the requested node

## Remaining Work (Priority Order)

1. **Close the #16217 HA-inactive leg** — name and fix the
   receiving-worker `ha_inactive` gate above, then pass the
   `--aged-failover` cell twice on the same build
2. **Live validation** — run `/failover-test` with all recent fixes deployed
   to confirm end-to-end failover works with zero stream loss
3. **Validate translated tuple fix** — confirm PRs #404-406 resolved the
   HAInactive resolution for inherited forward-wire entries
4. **Validate split-RG** — confirm priority ack channel fixed split-RG
   readiness convergence
5. **Throughput parity** — hardware/topology limitation, not a software fix

## Superseded Documents

These docs contain historical investigation detail but should not be
read as current truth. This document supersedes all of them:

- `docs/archived/userspace-failover-hardening-plan.md`
- `docs/archived/userspace-failover-next-steps.md`
- `docs/archived/userspace-ha-failover-parity-plan.md`
- `docs/archived/failover-hardening-progress.md`
- `docs/archived/ha-failover-simplification-audit.md`
- `docs/archived/ha-simple-failover-design.md`
- `docs/archived/ha-failover-implementation-plan.md`
- `docs/archived/ha-forwarding-state-inventory.md`
- `docs/archived/userspace-forwarding-and-failover-gap-audit.md`
