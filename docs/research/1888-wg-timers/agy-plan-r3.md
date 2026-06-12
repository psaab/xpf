I will view the `plan.md` file in the research worktree to examine the v5 design and revision log.
I will view the rest of the `plan.md` file (lines 700 to 841) to see the rest of the test plan, design points, and Q1-Q3.
I will list the contents of the `1888-wg-timers` documentation directory to check for Codex/AGY r2 documents.
I will view `agy-plan-r2.md` to see the details of our Round 2 findings.
I will view `codex-plan-r2.md` to see Codex's Round 2 findings and see what changes they recommended that were folded into v5.
I will view `claude-smr-plan-r2.md` to see if there is any other context.
I will run a grep search or find the file `wg_control.rs` to see its path and inspect it if needed.
I will list the root directory of the codebase `/home/ps/git/bpfrx/` to understand the project structure.
I will search for `wg_control` in the codebase to find where the WireGuard control thread implementation resides.
I will list the contents of the `userspace-dp` directory to see the structure of the Rust userspace data plane.
I will search for the file `wg_control.rs` inside the `userspace-dp/src` directory.
I will list the contents of `userspace-dp/src` to see the structure of the source directory.
I will list the contents of the `afxdp` directory under `userspace-dp/src` to locate WireGuard files.
I will list the contents of `userspace-dp/src/afxdp/wg` to find files related to WireGuard logic, timers, and control.
I will list the contents of the `coordinator` directory to see if `wg_control.rs` is there.
I will list the files under `userspace-dp/src/afxdp/frame/` to locate the worker transit/encap code.
I will view `userspace-dp/src/afxdp/frame/wg.rs` to see the transit/encap code and where it already heap-allocates or calls `monotonic_nanos()`.
I will search for `install_session` in `engine.rs` to see how session indices are allocated, verified for uniqueness, and if they can be reused quickly (ABA hazard).
I will view `engine.rs` around `install_session` (lines 615 to 680) to understand session installation and `local_index` management.
I will view the `peer.rs` file to see how `rotate_session` is implemented.
I will search for `pending` or `handshake` in `engine.rs` to see how pending handshakes are managed.
I will view `engine.rs` (lines 550 to 614) to see the existing `pending_by_peer` cleanup logic and how it's integrated with locks.
I will search for `release_pending` in `engine.rs` to see its implementation.
I will search for `reserve_pending` in `engine.rs` to see where the pending handshake registration/release logic lives.
I will search for `.pending.` or `.pending_by_peer.` or similar in `handshake_session.rs` or `engine.rs` to see where the pending handshake collection is mutated or queried.
I will view `handshake_session.rs` from lines 230 to 260 to see how reservations are cleared.
I will view `wg_control.rs` starting from line 1 to see the imports, thread spawn, and stop handle structure.
I will search for `stop_all_wg_control_threads` and `prune_wg_control_threads_for_snapshot` in the coordinator source code to see how threads are currently stopped.
I will search for `wg_control` in `coordinator/mod.rs` to find control thread management functions.
I will view `coordinator/mod.rs` (lines 225 to 245) to see the teardown logic for the control threads.
I will search for `wg_control_threads` in `coordinator/mod.rs` to find all paths where the control threads are removed or stopped.
I will view `coordinator/mod.rs` (lines 460 to 520) to see how control threads are pruned or spawned.
I will search for `prune` in `coordinator/mod.rs` to locate the other pruning/stopping paths.
I will search for `snapshot` in `coordinator/mod.rs` to find the snapshot-related thread pruning function.
I will search for `wg_control_threads` or any thread joining patterns in `coordinator/mod.rs` to see if there is another thread stopping path.
I will view lines 210 to 226 in `coordinator/mod.rs` to understand the first join path.
I will search for `.remove` or similar operations on `wg_control_threads` in the codebase.
I will search for `remove(&` in `coordinator/mod.rs` to locate thread removal sites.
I will search for `stop_remove_wg_control` in `userspace-dp/src` to see if/where it's defined and how it stops a single thread.
I will view lines 730 to 765 in `coordinator/mod.rs` to see how a single entry is stopped and removed, and to verify if it is indeed `stop_remove_wg_control_entry`.
I will search for `fn stop_` in `coordinator/mod.rs` to find stop functions.
I will search for `stop_remove` anywhere in `userspace-dp` to see if there is a similarly-named function.
I will search for `stop_remove_wg_control_entry` in the research worktree path to see if it's there.
I will view `coordinator/mod.rs` in the research worktree around line 739 to see the implementation of `stop_remove_wg_control_entry`.
I will search for `install_session` in `engine.rs` and `handshake_session.rs` to see when sessions are installed for both initiator and responder roles.
I will search for the definition of `try_encap` in `engine.rs` to create accurate deep links.
I will search for `try_decap` in `engine.rs` to locate its line number.
### 1. Round-2 Resolution Audit

All five AGY Round 2 findings are verified as **RESOLVED** in the [plan.md](file:///home/ps/git/bpfrx/.claude/worktrees/1888-research/docs/research/1888-wg-timers/plan.md) v5 draft:

*   **A1 (Infinite Handshake Loop on T5 Give-up): RESOLVED**
    *   *Evidence:* [plan.md:31-34](file:///home/ps/git/bpfrx/.claude/worktrees/1888-research/docs/research/1888-wg-timers/plan.md#L31-L34), [plan.md:179-184](file:///home/ps/git/bpfrx/.claude/worktrees/1888-research/docs/research/1888-wg-timers/plan.md#L179-L184), and [plan.md:484-487](file:///home/ps/git/bpfrx/.claude/worktrees/1888-research/docs/research/1888-wg-timers/plan.md#L484-L487) specify that starting an attempt consumes `last_send_data_ns` (sets it to `0`), transferring the handshake obligation to the active attempt machine and requiring new egress data to re-arm the trigger after a T5 give-up.
*   **A2 (T8 Keepalive NAT Pinhole Failure): RESOLVED**
    *   *Evidence:* [plan.md:35-38](file:///home/ps/git/bpfrx/.claude/worktrees/1888-research/docs/research/1888-wg-timers/plan.md#L35-L38), [plan.md:167](file:///home/ps/git/bpfrx/.claude/worktrees/1888-research/docs/research/1888-wg-timers/plan.md#L167), and [plan.md:221](file:///home/ps/git/bpfrx/.claude/worktrees/1888-research/docs/research/1888-wg-timers/plan.md#L221) explicitly define a "usable session" as confirmed and unexpired. If `current` is an unconfirmed responder-role session, T8 correctly treats it as unusable and initiates a handshake.
*   **A3 (UDP POLLNVAL Busy-Spin): RESOLVED**
    *   *Evidence:* [plan.md:39-40](file:///home/ps/git/bpfrx/.claude/worktrees/1888-research/docs/research/1888-wg-timers/plan.md#L39-L40) and [plan.md:554-560](file:///home/ps/git/bpfrx/.claude/worktrees/1888-research/docs/research/1888-wg-timers/plan.md#L554-L560) state that UDP `POLLNVAL` specifically exits the control loop thread, allowing the tombstone and backoff respawn machinery to recover, while transient `POLLERR`/`POLLHUP` errors remain non-fatal.
*   **A4 (T6 Suppression under Inbound-Only Streams): RESOLVED**
    *   *Evidence:* [plan.md:41-45](file:///home/ps/git/bpfrx/.claude/worktrees/1888-research/docs/research/1888-wg-timers/plan.md#L41-L45), [plan.md:165](file:///home/ps/git/bpfrx/.claude/worktrees/1888-research/docs/research/1888-wg-timers/plan.md#L165), and [plan.md:732-734](file:///home/ps/git/bpfrx/.claude/worktrees/1888-research/docs/research/1888-wg-timers/plan.md#L732-L734) pin the T6 predicate to `last_recv_data_ns > last_send_any_ns && now - last_send_any_ns >= 10s`, ensuring keepalives are anchored on our last send rather than being suppressed by inbound data.
*   **A5 (Tick-Anchor Slop): RESOLVED**
    *   *Evidence:* [plan.md:46-47](file:///home/ps/git/bpfrx/.claude/worktrees/1888-research/docs/research/1888-wg-timers/plan.md#L46-L47) and [plan.md:440-445](file:///home/ps/git/bpfrx/.claude/worktrees/1888-research/docs/research/1888-wg-timers/plan.md#L440-L445) show that `last_timer_pass_ns` is only updated when the 1s `tick_due` condition is met, preventing sub-second deadline executions from delaying periodic tick work.

---

### 2. Clock Reversal Evaluation

The clock reversal ([plan.md:12-18](file:///home/ps/git/bpfrx/.claude/worktrees/1888-research/docs/research/1888-wg-timers/plan.md#L12-L18), [plan.md:308-320](file:///home/ps/git/bpfrx/.claude/worktrees/1888-research/docs/research/1888-wg-timers/plan.md#L308-L320)) is **accepted**.

#### Cost Trace
In the S2a topology, `try_decap` only runs on the control thread. Egress `try_encap` runs on the control thread and the rarely-hit AF_XDP worker transit path ([frame/wg.rs:98](file:///home/ps/git/bpfrx/.claude/worktrees/1888-research/userspace-dp/src/afxdp/frame/wg.rs#L98)). 
*   **Control Thread:** Reading `CLOCK_MONOTONIC` via a vDSO call (~20–25ns) once per iteration is negligible compared to the socket and TUN I/O operations (~1000–5000ns).
*   **Transit Path:** The transit path already heap-allocates twice per packet and calls `monotonic_nanos()` on its `NoSession` arm. A 20ns clock read is a tiny fraction of the allocation and AEAD encryption overhead (~500–1500ns).
*   **Fast Path:** The AF_XDP worker fast path does not call `try_encap` or read the clock, so there is exactly **0ns** cost added to the main forwarding path.

#### Correctness Trace
If the control thread is descheduled or blocked (e.g., in a long burst), a cached clock will fail to update. If we enforce T3 using a cached clock, workers on AF_XDP threads will continue calling `try_encap` with stale time, sending transport packets past `REJECT_AFTER_TIME` (180s). This violates WireGuard's forward-secrecy guarantees. A per-use vDSO read in [try_encap](file:///home/ps/git/bpfrx/.claude/worktrees/1888-research/userspace-dp/src/afxdp/wg/engine.rs#L709) provides absolute enforcement of the 180s key discard deadline regardless of control-loop scheduling.

---

### 3. Attack on v5-New Machinery

*   **`baseline_session` ABA Hazard:** No hazard exists. Global uniqueness of `local_index` is enforced by [install_session_locked](file:///home/ps/git/bpfrx/.claude/worktrees/1888-research/userspace-dp/src/afxdp/wg/engine.rs#L641), which rejects duplicate indices across the entire engine. Because an old session is rotated to `previous` and remains in the demux map until a second rekey or explicit expiry, its `local_index` cannot be reused until it is fully evicted. By that time, the attempt machine has already terminated on the first observed fresh session.
*   **A1 Stamp-Consumption Interplay with T7:** Setting `last_send_data_ns := 0` when starting an attempt correctly suppresses T7 while the handshake is in progress and after it gives up (T5). New egress data that attempts transmission will hit the `NoSession` edge or successfully encrypt, properly re-arming the handshake attempt or T7 pacing.
*   **Post-msg2 Keepalive Interplay with T6 Ping-Pong Guard:** The post-msg2 keepalive is an empty transport packet. It is a SEND on our side, updating `last_send_any_ns` without stamping `last_recv_data_ns`. On the peer, receiving this empty message updates its `last_recv_any_ns` and confirms the session, but does not stamp `last_recv_data_ns` (non-empty transport only). Thus, the keepalive confirms the responder's session without arming T6, successfully avoiding a ping-pong loop.

---

### 4. New Findings (Round 3)

#### Finding 1 (MAJOR) — Busy-spin when keepalive/initiation sends are skipped (no endpoint) or fail
*   **Evidence:** [plan.md:167](file:///home/ps/git/bpfrx/.claude/worktrees/1888-research/docs/research/1888-wg-timers/plan.md#L167) (T8 trigger), [plan.md:399](file:///home/ps/git/bpfrx/.claude/worktrees/1888-research/docs/research/1888-wg-timers/plan.md#L399) (`timer_pass` actions), and [plan.md:437-440](file:///home/ps/git/bpfrx/.claude/worktrees/1888-research/docs/research/1888-wg-timers/plan.md#L437-L440) (control-loop keepalive send).
*   **Vulnerability:** If T8 (persistent keepalive) or T6 (passive keepalive) is due but the peer has no configured or learned endpoint, the control loop skips the keepalive send. Because no packet is sent, the activity stamp (`last_send_any_ns`) is not updated. On the next iteration, the timer will evaluate as due again. Since `timer_pass` computes the next deadline based on the stale stamps, the deadline remains in the past, causing a `timeout = 0` and a 100% CPU busy-spin.
*   **Fix Direction:** If a keepalive or handshake initiation send is skipped (due to no endpoint) or fails at the socket level, the loop/engine must still update the pacing stamp (`last_send_any_ns` for keepalives, or `last_tx_ns` / `started_ns` for handshakes) to `now` to pace the next attempt and prevent tight loop spins.

#### Finding 2 (MINOR) — Attempt success false-positive on session expiry
*   **Evidence:** [plan.md:501-509](file:///home/ps/git/bpfrx/.claude/worktrees/1888-research/docs/research/1888-wg-timers/plan.md#L501-L509) (attempt success identity check).
*   **Vulnerability:** If the attempt baseline session is `Some(idx_A)`, and the session expires and is cleared by `expire_sessions(now)` during the active 90s attempt, `current` becomes `None`. A naive check for "differs from the baseline" (e.g., `current_index != baseline_session`) evaluates `None != Some(idx_A)` as `true`, causing the attempt machine to falsely declare success, clear the active attempt, and stop retrying.
*   **Fix Direction:** Define the attempt success condition strictly as: `current_session_index.is_some() && current_session_index != baseline_session`.

#### Finding 3 (NIT) — Unit and type mismatch in poll timeout calculation
*   **Evidence:** [plan.md:448-454](file:///home/ps/git/bpfrx/.claude/worktrees/1888-research/docs/research/1888-wg-timers/plan.md#L448-L454) (timeout calculation).
*   **Vulnerability:** The code sketch compares a nanosecond delta `next_deadline.saturating_sub(now)` directly against `WG_POLL_CAP` (defined as a `Duration::from_millis(100)`). This is a Rust type mismatch and a unit mismatch.
*   **Fix Direction:** Explicitly convert the nanosecond delta to milliseconds and clamp it to the millisecond cap:
    ```rust
    let timeout_ms = ((next_deadline.saturating_sub(now) / 1_000_000).min(100)) as i32;
    ```

---

### Verdict

PLAN-NEEDS-REVISION

*Justification:* The plan successfully resolves all previous findings and correctly incorporates the clock reversal to guarantee forward secrecy. However, it introduces a major busy-spin risk if keepalives are skipped on peers without resolved endpoints, along with a false-positive handshake success condition upon session expiry.
