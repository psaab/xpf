# Claude SMR — hostile plan review r2 (#5837)

**Verdict: PLAN-READY** (with the explicit scoping in "What PLAN-READY means" below).
Round-1 raised real blockers (B1 fix-sufficiency, verifier honesty) and Codex raised
seven; r2 closes all of them substantively, and my independent re-verification confirms
the two load-bearing changes hold. This is not a soft-pass — r1 was a genuine REVISE.

## r1 blockers — resolution check
- **SMR-B1 (fix sufficiency)** — closed by §4a, verified firsthand: helper computes
  `pre_routing_dnat` then resolves forwarding on `effective_resolution_target`
  (translated internal dst), policy on post-translation tuple (#2345). Steering the
  first packet to XSK is sufficient; no helper translation change.
- **SMR-B2 (ICMP echo-reply)** — addressed: ICMP intent emitted only where an
  ICMP-bearing translation is configured; `is_icmp_to_interface_nat_local` echo-reply
  handling for non-translated addresses preserved.
- **SMR-B3 / Codex-5 (verifier honesty)** — addressed: framing demoted to "unknown
  until `make generate`," tail-call removed (correctly — it's canary-forbidden),
  Phase-2 = separate verified candidate, fallback ladder = v4-exact-only / reclaim /
  PLAN-KILL.
- **Codex-1 (shared-key collision)** — closed by switching to a dedicated
  `dnat_intent_v4/v6` map; the collision was the reason to abandon `dnat_table` reuse
  and the plan now states it as the Option-A rejection.
- **Codex-2 (key contract)** — closed: native-endian rebuild `from_ne_bytes(dst)`,
  zone-agnostic key, cross-side key test.
- **Codex-3 (static-NAT representability)** — closed by explicit §11 scoping
  (per-proto expansion, no proto-any/prefix, port-0 wildcard for ranges).
- **Codex-4 (generation transaction)** — closed: insert-verify-before-swap,
  abort-apply-on-failure, stale-delete retry, restart reconciliation.
- **Codex-6 (WG/ESP/IKE precedence)** — closed by §8.6 + §11 out-of-scope.
- **Codex-7 (availability)** — closed: RED availability tests in §10.

## Independent re-verification of the two decisions that matter
1. **New-map rollout is safe (strengthens Option B).** I traced
   `validateUserspaceShimLivePins` (loader_userspace_shim.go): a map with no live pin
   is skipped (`if !exists { continue }` — "fresh node / first load"), and
   `abiCheckedRefSpec` returns nil for a name the new dataplane doesn't own. So a new
   `dnat_intent_v4/v6` on the deploy that introduces it does NOT trigger a
   chicken-and-egg ABI reject against the old running daemon. Adding a Go SSOT spec
   (or letting the shim declare it) is the only wiring cost. This removes the one
   rollout risk I feared and makes B cleaner than A′ (which shares session capacity).
2. **Helper pre-routing order** re-confirmed (see §4a cites).

## Remaining non-blocking clarifications (fold at implement time)
- **N1 — ICMP intent is identifier-agnostic.** A DNAT/static rule has no ICMP
  identifier at config time, so ICMP intent must be a port-0 (identifier-wildcard)
  entry — which couples ICMP-translation-on-interface-address to the Phase-2 wildcard
  probe. State this so ICMP DNAT isn't assumed covered by Phase-1 exact-only.
- **N2 — zone-scoped DNAT sharing a port with a local service in another zone.** The
  zone-agnostic intent steers both to XSK; the helper's zone-scoped DNAT won't match
  the other-zone packet, so it resolves LocalDelivery on the original interface dst and
  reinjects — correct, no bypass, but it's the availability tradeoff Codex-7 names.
  One sentence in §8 would make the "no bypass" explicit.
- **N3 — max_entries for the intent maps** should be derived from a config bound (rule
  count) with a fail-closed cap, not a session-scale number; state it so the intent map
  can't be the thing that fills.

## What PLAN-READY means here (the honest caveat)
"Ready to implement," NOT "guaranteed to ship at full scope." The verifier is the
first implement-time gate: `make generate`/`shimverify` on Phase-1 exact-only decides
go/no-go, and the plan has a defined fallback (v4-exact-only + documented v6 limit) and
a PLAN-KILL branch if even that rejects. That is exactly the right shape for a
research deliverable on a shim-gated change — the design is sound and bounded; the one
irreducible unknown is a mechanical gate the implementer runs first. I would green-light
`/engineer 5837` with the instruction: build Phase-1 exact-only, run shimverify BEFORE
writing the rest, and treat a REJECT as the scope-reduction/PLAN-KILL fork, not a
surprise.

## Bottom line
r2 is architecturally sound, closes every r1 blocker, and correctly reframes the
verifier crux with an honest, bounded fallback. **PLAN-READY.**
