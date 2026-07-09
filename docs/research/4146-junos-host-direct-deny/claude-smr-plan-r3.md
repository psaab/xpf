# Claude SMR — hostile plan-review r3 — #4146 (on plan r5)

Reviewer: Claude (self-model, HOSTILE). Base `b4f2ddb2f`, plan rev r5.

Codex r2 (on r4) returned PLAN-REVISE with five STILL-OPEN items. r5 was reworked
to fold them. I re-verified each against the code (not accepting the rework on
faith).

## Did r5 close Codex r2's STILL-OPEN items?

- **First-match ordering across tiers — CLOSED.** r5 §5.1 builds ONE effective
  ordered program per (ingress zone, family) = exact zone-pair terms + applicable
  global terms in tier order, and gates representability + rendering on the WHOLE
  per-ingress program. An unrepresentable term in any contributing tier
  suppresses the entire ingress program → the "omitted unrepresentable exact
  permit exposes a rendered global deny" hole is closed (test in §9.2).
- **global-any ingress hole — CLOSED.** r5 renders a global-any term per ingress
  zone with that zone's non-lifeline netdevs, NEVER as an unscoped rule (§5.1,
  §8-inv-1). It can no longer fire on a lifeline/unzoned ingress.
- **Coarse-before-fine (fine permit re-admits coarse-rejected) — CLOSED, and
  better than a placement tweak.** r5 emits DROP-ONLY rules: a `permit` never
  becomes an nft `accept`; it subtracts its set from every later deny
  (`saddr != …`). Verified against Rust `poll_descriptor/mod.rs:138` ("a `then
  permit` can never re-admit what host-inbound already rejected"). With no fine
  accept, the coarse gate is provably the sole admit authority (§8-inv-5).
- **`application any` deny vs ND/PMTUD — CLOSED.** Verified `host_inbound.rs:484`
  admits ND/PMTUD/ICMP-error at the coarse layer and `mod.rs:2285` runs fine
  policy afterward, so r5 places the DROP-only subchain BEFORE the ND/PMTUD
  accepts (only ESP/AH — genuinely IPsec-passthrough-exempt — and reply-direction
  established precede it). A denied source's PMTUD is dropped; others' preserved
  (§6.4, §9.2 ordering test).
- **tcp-rst zone — CLOSED.** Verified `ZoneConfig.TCPRst` (`types_security.go:319`).
  A deny program whose ingress zone has tcp-rst is unrepresentable in the
  silent-drop slice → warns (§6.2, §8-inv-10); the reject follow-up lifts it.
- **Established parity — CLOSED.** reply-direction established accepted ahead of
  the deny; denied source's original-direction established dropped (deny precedes
  the residual established-accept); the non-denied per-hit coarse-recheck
  divergence is correctly scoped out as pre-existing chain behaviour.

## Residual attack surface (checked, non-blocking)

- **Set-subtraction representability boundary:** when a permit and a later deny
  scope on DIFFERENT dimensions (permit-by-app, deny-by-source) the subtraction
  is a cross-product that may not be a clean nft match; r5 correctly marks such a
  program unrepresentable → warn (§5.1). This is the right conservative choice —
  no partial/incorrect rule is emitted. Adequate.
- **iifname/RETH/VLAN netdev resolution** remains the top implementation risk
  (unchanged from r2 SMR) — design-correct, tested in §9.2 + §9.3-step-5.
- **Fail-closed apply (§5.5)** stays an explicit /engineer open item with the two
  code refs to reconcile — a correctness requirement, not a design gap.
- **Parity fixture oracle** pinned to authoritative Rust (§9.1). Adequate.

## Verdict

**PLAN-READY.** r5 folds every Codex r2 STILL-OPEN item with a code-verified fix,
and the DROP-only + set-subtraction + single-effective-program model is a
genuinely stronger design than r4 (it removes the coarse-bypass class entirely
rather than ordering around it). The kernel-nft locus and availability posture
are unchanged and correct. Residual items are bounded /engineer-time
implementation risks with tests specified. This is a shippable DENY-slice plan
that un-defers the security bug; reject and source-restricted-permit are
legitimately-scoped tracked follow-ups. Not a re-defer, not a PLAN-KILL.
