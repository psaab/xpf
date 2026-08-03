# Claude SMR plan review — round 13 — #6749 armed-state plan v8.8 (c2147e57329e)

**Reviewer:** Claude SMR (hostile; author-is-reviewer yellow-flag rule
applies DOUBLY — I wrote the v8.8 folds, so this pass attacks my own
fold text first). Attack surface: the `config_epoch` wire authority
(mint/carry/advance rules), the epoch-gated adoption + fence + tag,
the content-dedup collapse, the active-config re-apply, the
defer-intent argument, the three-obligation debt, the daemon-side
scheduler, the causal env token, the typed error outcome.

**Verdict: DEMAND-REVISION** — one BLOCKER in my own fold (SMR13-1:
the content-dedup collapse advances the WRONG counter, permanently
wedging the adoption gate AND the fabric fence for any staged config
whose forwarding content equals the incumbent's), plus four
MINOR/NIT specification gaps. The rest of the v8.8 surface holds
under my attacks (trace below).

---

## SMR13-1 (BLOCKER) — the dedup collapse moves the wrong counter

My §5-C (iii) and epoch-contract text says: "on the content-dedup
skip the manager collapses `m.acceptedConfigEpoch =
m.pendingConfigEpoch` — the helper provably already runs that
config's content, so adopting its epoch is truthful."

Trace the mechanics. The helper sets its stored `config_epoch` ONLY
on accepted full applies (snapshot.rs:153's sibling) and echoes it
in every full status. A content-dedup skip (process_status.go:72-80,
builder.go:156-178's generation/fib/time/pointer-excluding hash)
performs NO publish — the helper's stored epoch stays at the OLD
value E_a. My collapse sets `acceptedConfigEpoch = E_b` (the staged
config's mint). Now:

- Adoption gate: `status.config_epoch (E_a) ==
  acceptedConfigEpoch (E_b)` is FALSE — fabric adoption blocks
  until the next full apply, which may be months away (or never).
- Fabric fence: `update_fabrics` carries
  `expected_config_epoch = E_b` (the derivation config's epoch);
  the helper's stored epoch is E_a → REFUSED — fabric sync dead
  for every dedup-skipped staged config.
- Completion tag: any debt keyed on E_b refuses identically.

The collapse direction is backwards. The correct rule: on a
content-dedup skip, RETIRE the staged mint — collapse
`m.pendingConfigEpoch = m.acceptedConfigEpoch` (the staged config
will never publish; its mint is burned, harmless). Then pending ==
accepted (nothing staged), `status.config_epoch (E_a) ==
acceptedConfigEpoch (E_a)` holds, the fence's `expected = E_a`
matches the stored E_a, and adoption carries content-proven-equal
fabrics (harmless by the builder hash). One direction flip; the
fold's current text wedges both gates deterministically.

## SMR13-2 (MINOR) — the re-sync debt is named but not identified

The UNKNOWN-ownership text invokes "the re-sync debt (backoff +
edge Warn)" without saying whether it IS the #5134 debt or a new
fourth debt. They differ in purpose (#5134 = deferred-worker-arm
republish; re-sync = divergence republish) and in epoch keying (see
SMR13-3). Pin it: a SEPARATE re-sync debt, keyed on
`pendingConfigEpoch` of the re-applied config, firing the
active-config re-apply on its own backoff, superseded when
`acceptedConfigEpoch` reaches its key.

## SMR13-3 (MINOR) — the debt keying sentence conflates pending and accepted

The epoch-contract text says "Debts key on `m.pendingConfigEpoch`
at creation; `retryDeferredWorkerArmLocked` fires only while the
CURRENT `m.acceptedConfigEpoch` equals the debt's." For the #5134
debt (created AFTER the defer apply's observed-accepted publish)
the recorded key IS the accepted epoch at that moment; for the MAC
debt (created at epoch opening, also post-publish) the same. For
the re-sync's fresh debts (created pre-publish, pending=E_c,
accepted=E_a) the key must be pending. State it uniformly: a debt
records the epoch of the config that OWNS it (the config whose
precheck created it), and fires only while that epoch is the
accepted one — with the re-sync debts explicitly keyed on the
re-applied config's pending epoch.

## SMR13-4 (NIT) — two posture sentences

1. **The recovery rebind drop window.** A `macAndLinkRecovery`
   member's link returns; the recovery runs program-MAC (link
   DOWN→setMAC→UP, mlx5 queue reinit) + setUp + repairs + rebind.
   Between the MAC cycle and the rebind's completion the member's
   queues carry traffic with stale XSK sockets — a bounded (ms)
   drop window on a recovering member, with NO enabled-gate flap
   (the member's slots stay registered+armed throughout). State
   it; it is the same posture as any linkcycle and acceptable.
2. **The guard-verdict oscillation posture.** A marginally
   flapping sysfs (queue count oscillating 0↔N at ~1Hz) makes the
   guard verdict flap with it: each accept marks-all and each
   reject re-enables after the pulse. The fail-closed posture
   (dataplane down while the projection is unstable) is the
   correct severity-High posture; state it explicitly and note
   the hysteresis question is deliberately out of scope.

## Attack trace (what else I tried, and why it fails to break v8.8)

1. **The (v) echo gate vs exit (a)'s lost completion response.**
   The lost-response case has pending == accepted (no staged
   config) and no compile in flight → the gate opens and the echo
   reconciles — consistent. A new compile staged between the loss
   and the poll blocks the echo, but that compile's own accepting
   apply clears all three via exit (b) — consistent.
2. **The arm-sync gate during a long compile (the deleted
   pre-Compile SetDeferWorkers window).** The deleted call
   protected nothing: during a long compile of a deferred B, an
   arm-sync firing before Compile sets the intent operates on the
   CURRENT accepted config A (armed and forwarding — the status
   quo). B's plan is unpublished, so no B-worker can be armed
   pre-MAC through that path; the defer intent matters from B's
   publish onward, and it is set before any publish (the same
   critical section stamps `snap.DeferWorkers`). No hole.
3. **The lock hierarchy proof.** The manager holds no reference
   to `applySem` (it is daemon-side); every m.mu acquisition by a
   daemon flow already holds applySem (Compile, Report, Validate
   all run applySem → m.mu); manager threads (status loop,
   retries) take m.mu without ever acquiring applySem. The AB
   half (m.mu → applySem) is unconstructible. One sentence of
   proof in §5-C would help reviewers (nit-grade).
4. **The union watch's retained-rejected value.** Bounded (one
   value, replaced per rejection); replace-on-reject is the only
   sane rule (a B/B' flap re-watches the newest; both are in the
   union only via the newest — the older's candidates may leave
   the watch, but its rejection is superseded by B''s, so the
   suppression tracks the newest rejection anyway). Acceptable;
   the replace-on-reject rule should be stated (folds into
   SMR13-2's paragraph or the (i) text).
5. **Q1 twelfth enumeration.** The fence/tag refusals perform NO
   mutation; the (v) gated echo reconciles flag/cache, not slots;
   the re-apply is a full apply (S-rules). No new
   `Registered && !Armed && state==none` producer.

## Required for convergence

SMR13-1's direction flip (retire pending, not advance accepted),
SMR13-2/3's debt identity/keying sentences, SMR13-4's two posture
sentences, plus whatever Codex/AGY r13 find. If their verdicts are
PLAN-READY or PLAN-READY-WITH-NITS modulo these same items, fold
and ship to `/engineer`; any new BLOCKER iterates to round 14.

**Verdict: DEMAND-REVISION.**
