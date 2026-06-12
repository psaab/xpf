I will first check the current permission grants to see what access we have.
I will read the revision log and contents of the plan file.
I will read the remaining lines of the plan starting from line 700 to have the complete picture.
I will list the contents of the worktree directory to see the project structure.
I will search for `wg_control` related files in the codebase using grep to locate the control loop files.
I will read the current implementation of `wg_control.rs` around the sleep loop to see the structure.
I will check the directory contents of `docs/research/1888-wg-timers/` to see other logs or drafts that might give context on the revision history.
I will view the `agy-plan-r3.md` file to see the findings of the previous review round.
I will view the earlier lines of `wg_control.rs` to see how `effective_endpoint` is defined and updated.
I will search for `drive_initiation` in `wg_control.rs` to see its signature and how its return values are handled.
I will view `wg_control.rs` starting around line 423 to inspect the `drive_initiation` implementation. my goal is to verify how we handle failures and if it returns a value or modifies anything.
I will search for the definition of `monotonic_nanos` to see what clock it reads.
I will view `userspace-dp/src/afxdp/neighbor.rs` to see what clock source `monotonic_nanos()` uses.
I will search for any existing `poll` or `libc` usage in the coordinator module to see how polling is implemented elsewhere.
I will list the contents of the `userspace-dp/src/afxdp/wg/` directory to locate the engine, peer, and session files for accurate link mapping.
Here is the adversarial review of the proposed [plan.md](file:///home/ps/git/bpfrx/.claude/worktrees/1888-research/docs/research/1888-wg-timers/plan.md) v6.

---

### 1. G1 / G2 / G3 Verification Audit

*   **G1:** **RESOLVED**
    *   *Evidence:* §5.2 outlines the skip-pacing logic where a fired T6/T8 advances its anchor (`t6_arm := now`, T8 paces on `t8_last_attempt_ns` advancing on skip/fail), `timer_pass` emits no deadlines when `endpoint_known` is false, and failed `drive_initiation` still advances `attempt.last_tx_ns` ([plan.md:L512-522](file:///home/ps/git/bpfrx/.claude/worktrees/1888-research/docs/research/1888-wg-timers/plan.md#L512-L522)).
*   **G2:** **RESOLVED**
    *   *Evidence:* §5.2 specifies the attempt success condition as `current.is_some() && current_index != baseline_session`, preventing session expiry clearing `current` to `None` from triggering a false success ([plan.md:L569-573](file:///home/ps/git/bpfrx/.claude/worktrees/1888-research/docs/research/1888-wg-timers/plan.md#L569-L573)).
*   **G3:** **RESOLVED**
    *   *Evidence:* §5.2 converts the nanosecond deadline delta to milliseconds explicitly before clamping to `WG_POLL_CAP_MS`: `((next_deadline.saturating_sub(now) / 1_000_000).min(WG_POLL_CAP_MS as u64)) as i32` ([plan.md:L500-503](file:///home/ps/git/bpfrx/.claude/worktrees/1888-research/docs/research/1888-wg-timers/plan.md#L500-L503)).

---

### 2. Codex r3 Fold Verification (a, b, c)

*   **(a) Inbound-only-stream keepalive (~10s) holds:**
    *   *Verification:* Under the armed model, the first inbound data packet sets `t6_armed_recv_ns` to `t_0` (via CAS-from-0). Sub-second data packets fail the CAS and do not push the deadline. After 10s, T6 fires, sending a keepalive. The keepalive send clears `t6_armed_recv_ns` to `0`. The next incoming packet resets the arm to the new receive timestamp, establishing a stable 10s cadence.
*   **(b) A1 give-up no-retrigger holds (with caveat, see Finding 1):**
    *   *Verification:* On attempt start, `t7_armed_send_ns` is cleared to `0`. Handshake initiations sent during the attempt do not arm T7. Thus, if the attempt fails and gives up after 90s, the T7 timer is inactive (`0`), preventing immediate re-triggering. Only new outbound transport data can arm T7.
*   **(c) No new spin/suppression traces under the armed model:**
    *   *Verification:*
        *   *Outbound-only:* T7 is armed once on the first send and not updated by subsequent sends. If the peer is dead and does not reply, it fires exactly at `armed + 15s` (no suppression).
        *   *Bidirectional:* Receiving packets clears T7, and sending packets clears T6, preventing unnecessary fires.
        *   *Idle-then-burst:* The first packet of a burst arms the timer, and subsequent packets in the burst fail the CAS, preventing starvation of the deadline.

---

### 3. New Findings (Round 4)

#### Finding 1 (MAJOR) — Loop Retrigger / Handshake Loop Risk if Egress Traffic is Sent During an Active Handshake Attempt
*   **Evidence:** In §5.1, `try_encap` arms `t7_armed_reinit_ns` unconditionally when sending transport data ([plan.md:L380](file:///home/ps/git/bpfrx/.claude/worktrees/1888-research/docs/research/1888-wg-timers/plan.md#L380)). If workers send egress data during an active 90s handshake attempt (using a stale but unexpired session where `age < 180s`), `t7_armed_reinit_ns` will be set to `now`. Because the attempt is active, the control loop ignores this T7 trigger. However, when the attempt eventually gives up (T5) and `attempt` is cleared to `None`, `t7_armed_reinit_ns` will still be set to the past timestamp. On the very next tick, the control loop will see T7 is due and immediately start a new handshake attempt. This violates the A1 give-up no-retrigger requirement.
*   **Fix Direction:** When the handshake attempt gives up (T5) or when the attempt is active, the control loop or attempt machine must clear `t7_armed_reinit_ns` to `0` on the [Peer](file:///home/ps/git/bpfrx/.claude/worktrees/1888-research/userspace-dp/src/afxdp/wg/peer.rs) struct. This guarantees that only data sent *after* the attempt ends can re-trigger a rekey.

#### Finding 2 (MINOR) — Double-Handshake Risk due to Stale `rekey_request_pending` flag
*   **Evidence:** Egress traffic sent during an active handshake attempt will continue to hit the stale session and set `rekey_request_pending = true` ([plan.md:L375-377](file:///home/ps/git/bpfrx/.claude/worktrees/1888-research/docs/research/1888-wg-timers/plan.md#L375-L377)). When the response is processed and a new session is installed, the handshake attempt terminates with success. Since the `rekey_request_pending` flag remains `true`, the control loop will immediately initiate a second handshake attempt on the brand-new session on the next iteration.
*   **Fix Direction:** Explicitly clear/consume the `rekey_request_pending` flag (set it to `false`) when a handshake attempt succeeds or a new session is installed on the [WgEngine](file:///home/ps/git/bpfrx/.claude/worktrees/1888-research/userspace-dp/src/afxdp/wg/engine.rs).

#### Finding 3 (NIT) — Omission of `t8_last_attempt_ns` in [Peer](file:///home/ps/git/bpfrx/.claude/worktrees/1888-research/userspace-dp/src/afxdp/wg/peer.rs) additions
*   **Evidence:** §5.2 mentions that "T8 paces on a `t8_last_attempt_ns` that advances on skip/fail too" ([plan.md:L516-517](file:///home/ps/git/bpfrx/.claude/worktrees/1888-research/docs/research/1888-wg-timers/plan.md#L516-L517)). However, this field is omitted from the structural additions to the `Peer` struct listed in §5.1 ([plan.md:L329-335](file:///home/ps/git/bpfrx/.claude/worktrees/1888-research/docs/research/1888-wg-timers/plan.md#L329-L335)).
*   **Fix Direction:** Add `t8_last_attempt_ns: AtomicU64` to the `Peer` struct additions in §5.1.

---

### Summary of Work

I have performed a thorough review-only analysis of the [plan.md](file:///home/ps/git/bpfrx/.claude/worktrees/1888-research/docs/research/1888-wg-timers/plan.md) v6. While the v6 deltas successfully resolve previous concerns (skip-pacing, false-positive success checking, and timeout calculation units), my pressure-test identified a major risk where traffic sent during an active handshake attempt could trigger a double-handshake loop or immediate re-handshake triggers upon give-up or completion.

PLAN-NEEDS-REVISION: The plan successfully resolves the round-3 findings but introduces risks of immediate handshake re-triggering upon attempt completion or give-up due to un-cleared atomic state flags. Additionally, the structural additions in §5.1 must be updated to include the newly introduced T8 pacing anchor.
