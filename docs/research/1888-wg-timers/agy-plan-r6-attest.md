I will view the `plan.md` file to inspect the v9 status block, the "Attempt-boundary state hygiene" bullet, the §9 regression tests, and evaluate the v8 and v9 Codex-driven deltas.
I will view the rest of the `plan.md` file (from line 800 to the end) to see the rest of the plan, including §9 regression tests and the status block.
I will list the files in the plan's directory to verify if there are other files related to this task.
### Adversarial Review: Delta-Attest for v8/v9

This review evaluates the Codex-driven deltas in v8 and v9 of the [plan.md](file:///home/ps/git/bpfrx/.claude/worktrees/1888-research/docs/research/1888-wg-timers/plan.md) to confirm that they preserve the established **H1** and **H2** safety guarantees without introducing new regression traces.

---

### 1. v8 Delta: `t7_arm` Clearing Locus and H1 Preservation

* **Guaranteed Behavior (H1):** A handshake T5 give-up must clear `t7_arm` and drain request edges so that stale data sends during the active attempt do not immediately re-trigger a fresh attempt window (preventing the A1 loop).
* **The Delta:** The success path in `attempt.drive` no longer clears `t7_arm`. Instead, the authenticated completion site (socket read burst) clears it via the §3 any-authenticated-receive rule. The give-up cleanup path remains unchanged.
* **Preservation of H1:** Since the give-up cleanup path is untouched, the H1 guarantee remains fully intact.
* **Risk & Trace Assessment:** Handshake completion is triggered by receiving a valid msg1 or msg2, which naturally falls under the §3 any-authenticated-receive rule. This guarantees `t7_arm` is zeroed out at session installation. If outbound data is sent in the same iteration's TUN burst, `try_encap` legitimately sets `t7_arm = now_ns`. Under the prior draft, `attempt.drive` success would have overwritten this legitimate arm with `0` at the end of the iteration, breaking dead-peer detection. Moving the clear to the completion site correctly preserves the post-completion arm.

---

### 2. v9 Delta: Request Edge Drain Locus and H2 Preservation

* **Guaranteed Behavior (H2):** Attempt end (success or give-up) must drain both request edges (`take_rekey_request` and `take_handshake_request`) to prevent stale during-attempt sends on the old session from triggering a second handshake immediately after success.
* **The Delta:** The success-side request-edge drain is relocated from the post-burst `attempt.drive` to the inline authenticated completion site.
* **Preservation of H2:** Since the completion site runs during the socket read burst (before the TUN burst), it clears all stale request edges accumulated during the attempt. Any subsequent sends in the TUN burst will target the newly installed session. If the new session is valid, no edges are re-armed; if it is unconfirmed (responder-role), the edge is armed legitimately. In either case, stale edges from the old session cannot survive to cause an immediate secondary handshake. Thus, H2 is preserved.
* **Risk & Trace Assessment:** In the peer-initiated unconfirmed-responder success case, same-iteration TUN egress legitimately arms the `NoSession` edge. Under the old plan, clearing request edges at the end of the iteration in `attempt.drive` would wipe this legitimate arm. Moving the drain inline to the completion site ensures the newly-armed edge survives, preventing a key-confirmation deadlock.

---

PLAN-READY: The v8 and v9 deltas correctly resolve same-iteration race hazards identified in the peer-initiated responder-success case. They maintain the H1 and H2 guarantees by ensuring stale state is cleared at the completion site prior to same-iteration egress while leaving give-up cleanup untouched.
