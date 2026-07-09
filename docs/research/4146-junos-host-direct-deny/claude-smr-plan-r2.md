# Claude SMR — hostile plan-review r2 — #4146 (on plan r3)

Reviewer: Claude (self-model, HOSTILE). Base `b4f2ddb2f`, plan rev r3.

r3 was reworked in response to Codex plan-r1 (which I treat as adversarial input
to re-attack, not accept on faith) and my own r1 findings. I re-verified the
corrected design against the code.

## Did r3 actually fix the r1/r2 bugs?

- **Per-term → ordered-chain projection (Codex FLAW-1):** FIXED. §5.1 projects
  the config-ordered list (permit→accept short-circuit, deny→drop) and gates
  emission on the WHOLE chain being representable; a scope containing a
  reject/source-restricted-permit term is marked unrepresentable rather than
  silently dropping the term and changing the chain's meaning. This is the safe
  handling — earlier permits carve exceptions ahead of a broader deny, and no
  partial ordered chain is emitted.
- **daddr → iifname ingress scope (Codex FLAW-3, contradicts my r1 SMR-F1):**
  FIXED, and my r1 "bounded/safe-side daddr" defense is correctly RETRACTED.
  Codex is right: daddr both under-denies (WAN ingress → LAN-owned IP) and
  over-denies (LAN ingress → WAN IP), and #3718
  (`dup_host_local_address.go:43`) does not prevent either; that file names
  ingress-interface matching the correct model (`:32`). r3 scopes by
  `iifname` of the from-zone's non-lifeline netdevs. Good.
- **Coarse-then-fine (Codex FLAW-2):** ADDRESSED. r3 reproduces the Rust order
  (verified: `poll_descriptor/mod.rs` coarse `host_inbound_gated_lo0_action`
  ~2202 then fine `junos_host_local_policy` :2280) and pins the exact
  exemption-ordering nuances via a cross-language parity fixture, marking any
  unfaithful placement unrepresentable rather than diverging. reject is deferred
  (§6.5) precisely to avoid the silent-drop-vs-RST divergence.
- **Missed hazards:** all folded — `SourcePort`, app-set OR→multiple rules,
  cross-family excluded, `DestinationAddresses`, reject TCP+ICMPx pair (deferred),
  counter multi-reference assertion, warning-suppression-on-render, early-return
  on emitted rules, hit-counter honesty (§6.6), established-session parity
  decision (§8-inv-7), RETH/VIP active+backup tests, fail-closed apply open item
  (§5.5), scheduler exclusion, recursive feed-taint (§6.2).
- **Remainder framing:** FIXED. r3 keeps (ii) but redefines representability on
  the ordered chain, suppresses the warning only on rendered rules, drops the
  "Junos-correct" label for the remainder (now "documented partial-coverage
  limitation"), and records Codex's strict-reject-hybrid as a future option
  without adopting it (correct — strict-reject would refuse legal XSK-enforced
  configs).

## Residual items I attacked in r3

- **Parity-fixture oracle authority:** a fixture is only as good as its oracle.
  r3 now pins the oracle to the authoritative Rust `junos_host_local_policy`
  (cargo test), allowing the Go `policymatch` simulator only where an existing
  contract test already pins it to Rust. Adequately closed.
- **iifname/RETH/VLAN netdev resolution** is the highest IMPLEMENTATION risk
  (resolving `reth0.50` to the correct member/VLAN netdev for the `iifname`
  set). This is an /engineer-time risk, not a plan-level design gap — the design
  is correct; §5.1 flags the resolution and §9.2/§9.3-step-5 test it (active +
  backup RETH). Acceptable to carry into /engineer.
- **Fail-closed apply (§5.5)** is left as an explicit open item with the two
  code refs to reconcile (`daemon_apply.go` #4034 tail vs `daemon_nft.go:234`).
  This is a correctness requirement clearly stated, not a design uncertainty —
  appropriate for a plan.

## Verdict

**PLAN-READY.** The kernel-nft locus is correct and availability-preserving
(both reviewers agree); the r1/r2 emission bugs (ordering, daddr, coarse/fine)
are corrected into an ordered, ingress-scoped, coarse-gated, parity-verified
projection with a whole-chain representability gate; the operator decision is
resolved (direction b + remainder ii, redefined) with a documented safe default.
The residual items are bounded /engineer-time implementation risks with tests
specified, not design holes. This is a shippable plan, not a re-defer, and not a
PLAN-KILL.
