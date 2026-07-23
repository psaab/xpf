# Claude SMR hostile plan-review — #6371 r2

Reviewing `docs/research/6371-rgactive-fence/plan.md` @ r2 (commit 49d852ae3),
base origin/master @ 3ecdc80568a3. The r2 rewrite folded my r1 findings + all 6
Codex r1 findings. Hostile posture on the new recommendation (Path B).

## Corrections faithfully incorporated — spot-verified firsthand

- **RETH clear point / fence semantics (SMR-F1 + Codex-F2):** correct. Default
  `desired = clusterPri || allVRRPMaster` (`rg_state.go:255`) → RETH cluster-event
  demotion is `tr.Changed=false` while VRRP MASTER → line 367 skipped; the real
  clear is the VRRP-BACKUP handler (`daemon_ha.go:583`); `signalFailoverActuated`
  (389) fires regardless. Verified.
- **Ack is not a fence (Codex-F3):** correct. `ManualFailover` sets
  `StateSecondaryHold` (`failover.go:127`); peer promotes on observing it
  (`election.go:160`), independent of the ack. Option D PLAN-KILL is sound.
- **No fabric mitigation (Codex-F4):** correct — `fce172532` ("collapse userspace
  demotion prep to barrier only") removed the flow-cache demote; the demotion
  comments are stale.
- **Bounded ~11 s + gate-universality caveat (Codex-F2/F5):** correct wording.
- **Dead-map ordering (Codex "safety-critical map"):** confirmed —
  `manager_ha.go:638` returns on the eBPF-map error before the live
  `update_ha_state` at `:699`.

## Findings on the r2 recommendation

**F-r2-1 (SHOULD FIX — specify the alarm as PERSISTENCE-based, not one-shot).**
§5 item 2 puts the alarm "on a failed clear" at the two clear sites (367 / 583).
But a **single** failed clear is transient-indistinguishable — the very reason
the reconcile `Warn` is not actionable. The genuinely actionable signal is a
**persistent** failure: the `reconcileRGState` loop (`daemon_ha.go:820-848`)
already retries the clear every 2 s and dedups via `ShouldLogApplyError` /
`ShouldLogRetry`, so it is the natural place to detect "clear has been failing
for ≥N ticks / ≥T seconds" and raise/clear the `show security alarms` entry with
hysteresis (matching the existing NAT-pool / alarm-manager pattern,
`daemon.go:201`). A one-shot alarm at the actuation site will either be noisy
(fires on benign transients) or miss the persistent case (fires once, no
clear/hysteresis). Re-scope item 2 to a **hysteresis alarm driven off the
reconcile loop's consecutive-failure count**, with the clear sites merely
seeding it. This makes item 2 the load-bearing observability the plan claims.

**F-r2-2 (SHOULD FIX — put the dead-map-decouple safety argument IN the plan).**
§6 says "preserve the existing poll-race lock discipline" but does not state WHY
attempting the live update after a failed map write is safe. It is safe, and the
reasoning must be explicit so /engineer does not reintroduce the race: the poll
(`process_status.go`) syncs the helper from the **BPF map value**; if
`bpfShim.UpdateRGActive` FAILED, the map still holds the OLD value, so the poll
cannot have observed a new value to prematurely sync — the whole poll-race the
`m.mu` guard prevents cannot occur on the failure path. Therefore running the
live `update_ha_state` after a failed map write introduces no race. Also state
the activation invariant: on `active=true`, if the live update fails,
`UpdateRGActive` MUST still return an error (fail closed) — `errors.Join` of the
two must be non-nil so a partial activate is never reported as success.

**F-r2-3 (severity honesty — say item 1 is LOW-probability).** The plan calls the
dead-map decouple "the one genuine latent bug," which is fair, but the trigger
(`ebpf.Map.Update` syscall failure on a present map) is rare — effectively
ENOMEM/EINVAL or a torn-down map. State the severity honestly: it is an ordering
**hygiene** fix that removes a dead dependency from the safety-critical path, not
a frequently-hit bug. This keeps Path B correctly framed as
"hygiene + observability + doc," not a critical security fix — consistent with
the (correct) PLAN-DEFER of the deep redesign.

**F-r2-4 (MINOR — confirm the two clear sites are the only ones).** §5/§7 scope
the alarm to lines 367 and 583. There is a THIRD `SetRGActive(false)` in the
reconcile loop (`daemon_ha.go:846`) and the activation-side ones. Confirm the
alarm/counter is driven off the reconcile persistent-failure path (F-r2-1) so it
does not need to enumerate every one-shot site — otherwise the "both sites"
framing is incomplete (it omits the reconcile site, which is exactly where a
persistent failure manifests).

**F-r2-5 (test plan — the direct-mode vs RETH harness).** §7 asks for a daemon
test that reaches both the direct-mode (367) and RETH-BACKUP (583) branches.
Confirm the harness can put the `rgStateMachine` into each regime (no-reth-vrrp
vs VRRP-master-then-backup) in a unit test without a live cluster — else split
into a direct-mode test (SetCluster false, no VRRP) and a RETH test (VRRP master
→ backup event). Name which existing helper seeds each.

## Verdict

The r2 rewrite is factually solid — every r1 finding is correctly incorporated —
and the recommendation (PLAN-KILL Option D + Path A′; ship narrow Path B;
PLAN-DEFER the redesign) is the honest, proportionate outcome. The remaining gaps
are in item-2's alarm mechanism (persistence/hysteresis off the reconcile loop,
not one-shot — F-r2-1) and making the dead-map-decouple safety argument explicit
(F-r2-2). These are refinements to nail before PLAN-READY, not a kill.

VERDICT: PLAN-NEEDS-REVISION
