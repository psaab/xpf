# Codex — plan review r2 (convergence) (#2387)

Reviewed plan v3. Codex ran successfully (NOT infra-blocked). Verbatim verdict:

---

**PLAN-NEEDS-REVISION** (conditional — converges to PLAN-DEFER after two wording
fixes, both landed in v4 below).

Two remaining blockers preventing PLAN-DEFER convergence:

**Blocker 1 — §4c stale "latent/non-forwarding" wording.** `plan.md:217-219`
still said the NAT coherence gap "remains latent only because §4b makes the
trigger non-forwarding." That contradicts the PBR-live finding. NAT runs inside
the same PBR-triggered path (`forwarding/mod.rs:211-212` resolves NAT scope;
`session_glue/mod.rs:1037-1042` looks up `&flow.forward_key`). The sentence needs
to say latent in default mode and live under PBR.

**Blocker 2 — §A.1 stale "hard reject" wording.** `plan.md:382` and `:400-402`
described the compile-time check as a "commit error / rejects." The plan's own
`plan.md:254-265` correctly describes it as a commit-time WARNING. Appendix A.1
must be aligned.

**Items confirmed:**
1. **PBR reachability — CONFIRMED.** `poll_descriptor/mod.rs:474` calls
   `resolve_flow_session_decision` (short-circuits before forwarding), and `:1208`
   builds `route_table_override` (the PBR override). Plan correctly states
   default=latent, PBR=live.
2. **Citation fixes — CONFIRMED.** `pkg/cluster/heartbeat.go:27-31`
   `CurrentHAProtocolVersion`; `pkg/cluster/sync.go:36` `SessionSyncWireVersion`
   alias; path-shorthand note for `src/afxdp/` subtree at `plan.md:104-109`. All
   line numbers verified.
3. **Phase ordering — CONFIRMED.** B-min (P0/P2/P3) and B-ext (per-VRF default
   FIB) are split, with explicit "NOT a prerequisite" at `plan.md:293-294`.
   Logically sound: PBR override at `poll_descriptor/mod.rs:1208-1248` is
   independent of the default-table globals at `forwarding/mod.rs:12-13`.
4. **§4d/§7 — CONFIRMED still accurate.** HA wire: `sync_protocol.go:81` 16-byte
   key, `:136-145` encodes reverse key, `:332-368` decode gates. Reverse-flow
   domain: `session/key.rs:84`/`:124` reverse key; `forwarding/mod.rs:1579-1604`
   leaked-flow recursion.

"After those two sentences are corrected, the plan converges and PLAN-DEFER is
appropriate — the findings are real, B-min is the minimal fix, and it correctly
identifies the maintainer product-scope decision and HA wire bump as the gate."

---

**Disposition (v4):** both blockers fixed — §4c rewritten to "latent in default
mode, live under PBR"; the §8 risk-table and §9 test-plan A.1 wording aligned to
"commit WARNING (not reject)." Per Codex's own statement, the plan now converges:
**PLAN-DEFER**, 3-of-3 (Claude SMR + AGY + Codex).
