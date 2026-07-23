# Codex — hostile plan review r2 — #6177 (medium effort, 27.8k tokens)

Raw transcript: `codex-plan-r2-raw.txt`. Verdict + findings extracted verbatim below.

## Findings

1. **ACK claim too universal.** If all three priority-0 adverts are lost, the peer
   does not enter the 1 ms takeover path; its post-ACK commit / `ForceRGMaster`
   become causal. Batch resignations make it sharper (some VRIDs promote pre-ACK via
   priority-0, others via post-ACK forcing). "Adds no ordering guarantee" must be
   narrowed. (Sync-hold does NOT refute the plan — received priority-0 bypasses it.)
2. **"Universal benign" is false.** A failed `SetRGActive(false)` (daemon_ha.go:367)
   only logs a warning; `signalFailoverActuated` (:389) still fires. Combine failed
   fabric prep + failed rg_active clear + priority-0 peer promotion + failed VIP
   removal ⇒ both nodes retain forwarding authority + VIP = the exact
   forwarding/security condition the plan says cannot happen. #5482 bounds retry
   EFFORT not stale-VIP lifetime (instance_vip.go:125 leaves the VIP after 5 attempts
   until the next transition), so "benign for any δ_remove" / "~1 s worst case" are
   incorrect. GARP/per-node-MAC do not PROVE safety (a stale node still answers later
   ARP / MAC-addressed traffic) — "no RST / no security violation" are assertions.
3. **A cheaper sound lever was missed** — hard forwarding fence BEFORE priority-0:
   prepare fabric → clear rg_active successfully → only then ResignRG/priority-0; if
   the fence fails, do not advertise resignation or ack, retain the owner, fail the
   transfer. No netlink-VIP wait, no peer round-trip. Conflicts with the #485
   "ResignRG before clear" invariant → must be researched before approval, but the
   plan cannot DISMISS Residual-1 until this is evaluated. Also: the Option-A hybrid
   "buys nothing" is unfair — it closes overlap for every SUCCESSFUL slow removal.
4. **Drop Residual-2 as proposed.** Channel-aware disarm/timeout while
   `signalFailoverActuated` stays key-only and `armFailoverActuation` can overwrite =
   half-hardening a forbidden state, backed by tests that manufacture it. Either a
   coherent generation model across arm/signal/timeout/disarm, or keep the serialized
   invariant. YAGNI → drop now.
5. **Residual-3 must be branch-level.** Primitive-only barrier tests cannot prove the
   `SetRGActive(false)`→signal ordering. Add a branch-level test covering successful
   AND failed `SetRGActive`, or stop claiming the barrier tests protect that ordering.

**VERDICT: PLAN-NEEDS-REVISION** — evaluate hard rg_active fencing before priority-0,
cover its failure path, narrow the ACK claim, drop partial Residual-2 hardening, and
add a demotion-order test.

## Adjudication (research6177, firsthand)

- F1 VALID — narrow the ACK claim to the priority-0-present path.
- F2 VALID and material — the failed-`SetRGActive` path is a real (reconcile-bounded)
  forwarding hazard the r2 "universal benign" glossed. Firsthand: `reconcileRGStateLoop`
  (daemon_ha.go:604-620) re-drives rg_active every 2 s, so the dual-forward window is
  bounded to ~2 s + self-heals — real but not unbounded. #5482 exhaustion point
  confirmed (instance_vip.go:125).
- F3 PARTIALLY VALID — the fence is worth EVALUATING, but firsthand it is NOT a
  slam-dunk: gating/withholding the ack cannot un-take the peer's priority-0 VIP move,
  so aborting the transfer risks a LONGER blackhole (both rg_active=false, peer holds
  VIP) than today's ~2 s dual-forward-then-settle. It conflicts with #485. → It needs
  its OWN design pass; do not bundle it as ship-ready here. FILE a new issue.
- F4 VALID — drop Residual-2.
- F5 VALID — expand Residual-3 to a branch-level demotion-order test.
