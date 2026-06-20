# Codex hostile plan review r11 — #2079

Agent: a89ae9d363cb3918d (~5 min full pass — waited for completion this time,
no fast-retry override).

## Verdict: PLAN-READY-WITH-NITS (no MAJOR, no BLOCKER)

The r10 BLOCKER is resolved. All four verification questions confirmed against
source:

1. **Q1 (capture only on RECONCILED apply) — VERIFIED.** The non-deferred apply
   sites are synchronous `requestLocked` calls that wait for the OK reply
   (manager.go:688/796/950, process.go:352; process.go:195). Rust swaps forwarding
   BEFORE writing that reply — via `reconcile_status_bindings`
   (snapshot.rs:143; afxdp/coordinator/reconcile/snapshot.rs:21,89) OR, for a
   same-plan apply, `refresh_runtime_snapshot` (snapshot.rs:103;
   snapshot_refresh.rs:179). So a RETURNING non-deferred apply_snapshot proves the
   forwarding/NAT state is the new gen — the manager can reliably capture
   appliedSnapshot then. (NIT: the plan's "only replaced during reconcile" wording
   was slightly imprecise — same-plan refresh also swaps; both synchronous, so the
   design holds. FOLDED into r11 wording.)
2. **Q1b (post-NotifyLinkCycle signal) — VERIFIED.** NotifyLinkCycle sends
   `rebind` and applies returned status (process.go:1063,1068); Rust `rebind` runs
   `reconcile_status_bindings` + `refresh_status` (rebind.rs:46) and attaches
   status before the response (handlers/mod.rs:164).
3. **Q2 (deferred-accept skew) — VERIFIED CLOSED.** Deferred accept advances
   last_snapshot_generation immediately (snapshot.rs:63) but skips reconcile
   (snapshot.rs:113,138); r11 keeps appliedSnapshot old until reconcile and
   `Coherent := gen-equality && !m.deferWorkers`. Even after the daemon clears
   m.deferWorkers (daemon_apply.go:705,894), generation equality still fails until
   the post-rebind capture. Solid.
4. **Q3 (first-boot gen==0) — VERIFIED.** r11 makes no-reconciled-snapshot
   Available=false (not cfg==nil clear-all); cold status starts gen=0 + empty NAT
   pools (lifecycle.rs:91,158); Go resets helper status on stop (process.go:561).
5. **Q4 (HOLD on !Available/!Coherent) — VERIFIED.** §6.4 defers clears rather
   than clearing from a control-plane-only view.

NITs (both FOLDED into r11):
- terminology "only replaced during reconcile" → "swapped synchronously before
  the apply reply (reconcile OR same-plan refresh)".
- path: `afxdp/coordinator/reconcile/snapshot.rs:21,89` (not `reconcile/snapshot.rs`).

"Overall: r11 resolves the r10 blocker. The plan no longer trusts helper
last_snapshot_generation alone, avoids recording a deferred-but-accepted snapshot
as applied, gates coherent evaluation through the last reconciled applied
generation, and HOLDs unavailable or incoherent views."
