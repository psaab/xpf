# Claude SMR — hostile plan review, #6169 boot-epoch, round 6 (plan v6)

Stance: HOSTILE re-attack of v6. Verified against `origin/master` @ `11e23b49a`.
Written before Codex r6. I was overconfident at r5, so this pass actively tries to
construct a dual-primary / wrong-owner and treats "I can't break it" as weak
evidence, not proof.

## Round-5 findings — resolution check

- **The fundamental impossibility (r5 §1).** v6 chooses **consistency**: an
  epoch-ineligible node in a *configured* cluster never promotes. This is the only
  correct choice without a witness/quorum. I could not construct a dual-primary in
  the eligible-only world (both eligible ⇒ both persisted ⇒ normal epoch-ordered
  election yields one owner) nor from an ineligible node (it never promotes). The
  sole dual-primary path left is the **operator override**, which is a manual fence
  decision (see R1). **Resolved — the right call.**
- **Peer-visible ineligibility (r5 §2).** Advertising an ineligible RG flag closes
  the `sawEpoch=false` asymmetric gap; the `sawEpoch=true` sub-case is closed by
  the peer's normal timeout (see R2 for the interaction that must be spelled out).
- **Strict successor (r5 §4).** `next = max(durable, emitted)+1` never re-publishes
  `P`; `MaxUint64`→fail-held; a stale retry re-reads `durable`. **Resolved.**
- **Sender snapshot (r5 §5).** One `{keyGen,…}` snapshot + re-snapshot on change
  closes the stale-K1-under-K2 send. **Resolved.**
- **Separate hold flag / #5639 message-time gen check (r5 §3/§6).** Both addressed.
  **Resolved.**

## Required (bounded) items to carry into /engineer

- **R1 — The operator override is a manual fence and must be documented as such.**
  `force-primary epoch-degraded` issued while the peer is actually
  alive-but-partitioned → dual-primary. This is the standard witness-less 2-node
  STONITH problem: the runbook must require the operator to **power-fence the peer
  first**. State it explicitly; it is the one residual dual-primary path.
- **R2 — Spell out the ineligible-flag ↔ epoch-strip interaction.** When the peer
  holds `sawEpoch`, it **rejects** the ineligible node's markerless frame (epoch
  strip) and therefore never *reads* the flag — it must take over via the normal
  went-silent timeout instead. When the peer's `sawEpoch=false`, it *accepts* the
  markerless frame and acts on the flag. Both routes must yield peer ownership;
  the PR must verify both, and that the flag is an **additive body field present
  in v1-markerless frames too** (so an ineligible node advertises it regardless of
  whether it can emit an epoch).
- **R3 — Mixed-version caveat.** A pre-#6169 peer cannot read the ineligible flag;
  in the (double-rare) mixed-version + persist-fault window it would not yield on
  the flag alone (it would still take over via timeout if it lacks `sawEpoch`).
  Note it; it is transient (rolling upgrade) and does not affect a fully-upgraded
  cluster.
- **R4 — Ineligibility is a real wire + election-logic addition** (a per-RG flag +
  "peer-ineligible ⇒ I own regardless of priority" at every election site). Bounded,
  but it is new surface, not a pure receiver change.

## The decision this research now surfaces

v6 is, in my assessment, a **sound and complete design** — I cannot construct a
correctness failure that is not either the documented safe-outage or the
operator-fenced override. But five rounds have made the true shape unmistakable:
closing a **narrow** replay residual (on-path sniffer, ≥65 captures) now requires a
**#5639 prerequisite + a wire/election ineligibility protocol + making a node's
PRIMARY-eligibility depend on durably writing a boot-epoch file** (a persist fault
→ possible safe-outage). That is a **material HA-availability cost for a
defense-in-depth gain**, and whether it is worth paying is a **user cost/benefit
judgment**, not a further engineering question — which is precisely what
`/research` exists to surface before code is written.

## Verdict

The design has converged and I cannot break it; the remaining items are bounded
implementation precision (R1–R4). Whether to pay the availability cost is the
user's call. On the engineering merits this is implementable.

VERDICT: PLAN-READY (conditional on the user accepting the §11 availability
cost/benefit; else PLAN-KILL/defer is equally legitimate)

---

## Self-correction (post-Codex-r6, same round)

My READY-conditional again under-checked the cross-LAYER seams (I stayed at the
Manager/election layer). Codex r6 found two real ones I missed, both verified:

1. **Advertise-before-actuation dual-primary.** The logical demote sets
   `Manager.State` + enqueues an event, but the actual VRRP resignation +
   dataplane deactivation run later in the daemon event consumer (async,
   droppable, 64-event channel vs 255 RGs). So the peer can promote on the
   advertised ineligibility *before* the ineligible node has physically resigned →
   both dataplanes own. Needs a **two-phase actuation barrier** (fence physical
   demotion, then advertise) — the plan stayed at the logical layer.
2. **No rolling-upgrade-safe wire contract for the ineligibility flag.** RG
   records are fixed 5-byte with no flags field; an old receiver honors only
   `weight=0` / `StateSecondaryHold` as an unconditional yield, so a new
   "ineligible flag" is ignored by an old peer → both-secondary in a mixed cluster.
   Fix: **project ineligibility onto the existing yield encoding**, not a new flag.

Plus the override needs real fencing + auto-revoke, and the engagement predicate
`epochRequired = configuredCluster && keyConfigured` was implicit.

These are fixable, but they confirm the pattern: **every round surfaces a new,
real, cross-layer hazard.** That is the decisive signal for the §13 conclusion —
Stage 1 is a full-HA-stack program, not a bounded fix. I therefore withdraw the
unqualified READY and align with the §13 recommendation: **ship Stage 0, defer /
PLAN-KILL Stage 1 pending a user cost/benefit decision.**

VERDICT: PLAN-NEEDS-MAJOR (Stage 1 as scoped) / recommend ship-Stage-0 + defer-Stage-1
