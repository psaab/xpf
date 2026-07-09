# Claude SMR — hostile plan-review r4 — #4146 (on plan r6)

Reviewer: Claude (self-model, HOSTILE). Base `b4f2ddb2f`, plan rev r6.

Codex r3 (on r5) resolved 4/5 prior items and raised one STILL-OPEN + two
sub-points, all about the fine-eligible decision domain. r6 folds them; I
verified each against the code.

- **Three-tier effective program — CLOSED.** Verified Rust evaluates exact →
  from-any → global (`policy.rs:2978/3014/3050`; #3090 from-any tier in
  `compiler_uniformgates.go:153`, `policymatch.go:781`). r6 §5.1 assembles all
  three tiers under one whole-program gate, so a `from-any permit; global deny`
  carve-out is honored (§9.2 test).
- **IKE/NAT-T black-hole — CLOSED.** Verified `poll_stages.rs` Stage 11 IPsec
  passthrough covers ESP/AH AND coarse-admitted IKE (UDP 500/4500) before fine.
  r6 §6.7 restricts the DROP to the fine-eligible L4 domain (excludes 500/4500 in
  ike-zones), so a denied source's IKE is not black-holed.
- **ident-reset RST → silent drop — CLOSED.** Verified the coarse-terminal
  ident-reset `reject with tcp reset` (#3310, `daemon_nft.go` ident-reset arm).
  r6 §6.7 excludes TCP/113 from the DROP in ident-reset zones, preserving the RST.
- A deny explicitly scoped to an IKE/ident application is unrepresentable → warns
  (§6.7), so the DENY slice never silently mismodels an exempt class.

Residual: the fine-eligible-domain exclusion is per-ingress-zone-config-dependent
(ike/ident-reset), so the builder must read the zone's coarse host-inbound set —
a bounded /engineer detail, tested in §9.2. iifname/RETH resolution and
fail-closed apply remain the flagged /engineer risks.

**Verdict: PLAN-READY.** r6 closes Codex r3's last item and both sub-points with
code-verified fixes; the DROP-only + set-subtraction + three-tier +
fine-eligible-domain model is a faithful, safe kernel projection of the
representable junos-host DENY subset. Reject and source-restricted-permit remain
legitimately-scoped tracked follow-ups. Not a re-defer, not a PLAN-KILL.
