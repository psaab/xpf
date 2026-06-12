I will read the plan under review to understand the proposed architecture and details.
I will view the contents of the main coordinator file to understand how `wg_control.rs` is currently implemented.
I will read the peer session management code to see where stamps, keys, and configured parameters live.
I will view `session.rs` to understand the current session structure and variables.
I will read parts of `engine.rs` to understand try_encap, try_decap, install_session, and how session/peer configuration are managed.
I will read the next part of `engine.rs` to see `try_encap`, `try_decap`, `install_session`, and how peer maps are accessed.
I will read lines 601-900 of `engine.rs` to inspect the implementation of `try_encap`, `try_decap`, and `install_session`.
I will read lines 901-1200 of `engine.rs` to see the rest of `try_decap`, replay prechecks, and AllowedIPs gating.
I will view `handshake_session.rs` to see how handshakes and their lifetimes are managed.
I will read `forwarding_build/wg.rs` to see how the engine is reused across reloads and check identity reuse rules.
I will view the coordinator thread stop/join lifecycle in `mod.rs` to see how the coordinator cleans up wg_control threads.
I will read lines 801-940 of `mod.rs` to see the remainder of the supervisor/coordinator structure for wg_control threads.
I will read `frame/wg.rs` to see where `try_encap` is called on the dataplane/worker-side, and what contract it expects.
I will read the interop test script lines 620-790 to see the tests for rekeying and recovery.
I will check the correct path to the `wg-interop.sh` file.
I will search for the definition of `monotonic_now_ns` to see if it reads a real-time clock via vDSO or if there is a cached/coarse clock implementation.
I will view the counters file to inspect how time is read and what counters are defined.
An adversarial review of the proposed integration plan for WireGuard timers (#1888) and blocking `poll(2)` loop (#1889) has been performed against the active code in the `1888-research` worktree.

The findings below highlight several critical issues—including three blockers—that will cause infinite handshake loops, rekey failures, and CPU busy-spinning if the plan is implemented as currently drafted.

---

### Adversarial Findings

#### 1. Infinite Handshake Loop due to Peer-Scoped Stamps (BLOCKER)
* **Evidence**: [plan.md:L98-101](file:///home/ps/git/bpfrx/.claude/worktrees/1888-research/docs/research/1888-wg-timers/plan.md#L98-L101) ("These four stamps live on `Peer`... matching wireguard-go") and [plan.md:L81](file:///home/ps/git/bpfrx/.claude/worktrees/1888-research/docs/research/1888-wg-timers/plan.md#L81) (T7: "After sending a data message, if we have received nothing within 15s").
* **Vulnerability**: If we send a data packet on Session 1, `last_send_data_ns` on `Peer` is updated. If we receive nothing, T7 triggers at 15s and initiates a handshake. The peer responds, and we successfully complete the handshake and install Session 2 via [consume_response_inner](file:///home/ps/git/bpfrx/.claude/worktrees/1888-research/userspace-dp/src/afxdp/wg/handshake_session.rs#L353-L414). However, because a handshake response is a type-2 control message (not an authenticated transport record), `last_recv_any_ns` on `Peer` is **not** updated. Because the stamps live on `Peer` and survive the rekey, `last_send_data_ns` remains newer than `last_recv_any_ns` and older than 15s. On the very next tick, T7 will fire again and immediately initiate another handshake, resulting in an infinite loop of handshake initiations on every tick.
* **Fix Direction**: Place the transport-activity stamps on `WgSession` instead of `Peer`. When a new session is installed, it naturally starts with zeroed stamps, which resets the no-reply detection window and keepalive pacing.

#### 2. Rekey Handshake Retry Blocking (BLOCKER)
* **Evidence**: [plan.md:L249-275](file:///home/ps/git/bpfrx/.claude/worktrees/1888-research/docs/research/1888-wg-timers/plan.md#L249-L275) and the retry gate `if (requested || allow_timer) && !engine.peer_has_confirmed_session(&pk)`.
* **Vulnerability**: When rekeying, the old session is still active and confirmed (keys are not expired until `REJECT_AFTER_TIME` = 180s). The plan's one-shot `rekey_request_pending` edge triggers the *first* initiation. If this packet is dropped on the wire, the next retry check (5s later) will evaluate `rekey_request_pending` as false (since it was cleared when consumed) and `peer_has_confirmed_session` as true (since the old session is still valid). Consequently, the rekey handshake will never retry, leaving the tunnel vulnerable to a complete traffic drop once the old keys hit the 180s hard expiry.
* **Fix Direction**: The control loop must track whether a handshake is actively in progress for a peer (e.g., by checking if `engine.pending_by_peer` has an entry for the peer's public key). If a handshake is in progress, it should retry paced by `REKEY_TIMEOUT` (5s), bypassing the `!peer_has_confirmed_session` check.

#### 3. Event-Loop Busy-Spin on Deadline Expiration (BLOCKER)
* **Evidence**: [plan.md:L256-265](file:///home/ps/git/bpfrx/.claude/worktrees/1888-research/docs/research/1888-wg-timers/plan.md#L256-L265) and the 1s tick throttle: `if now - last_timer_pass_ns >= WG_TIMER_TICK_NS`.
* **Vulnerability**: If `next_deadline` is set to a sub-second interval (e.g., 500ms for a keepalive or a retry), `poll` wakes up when the deadline expires. However, because `now - last_timer_pass_ns` is `< 1s`, the timer pass is skipped. Since the timer pass is skipped, `next_deadline` is not recalculated and remains in the past, causing `timeout` to saturate to 0. The loop will then busy-spin with a timeout of 0 on every iteration (consuming 100% CPU) until the 1s boundary is crossed.
* **Fix Direction**: Run the timer pass (and recalculate `next_deadline`) whenever `now >= next_deadline`, regardless of the 1s tick throttle.

#### 4. Persistent Keepalive Handshake Lock-Out (MAJOR)
* **Evidence**: [plan.md:L258-262](file:///home/ps/git/bpfrx/.claude/worktrees/1888-research/docs/research/1888-wg-timers/plan.md#L258-L262) ("paced by REKEY_TIMEOUT (5s), capped by REKEY_ATTEMPT_TIME (90s) since attempt_started").
* **Vulnerability**: If the tunnel is idle and a handshake fails after 90s, the initiator gives up. If `attempt_started` is never reset unless a session completes or a worker `NoSession` edge arrives, then future `persistent_keepalive` (T8) ticks will be blocked because `now - attempt_started` will remain greater than 90s, permanently disabling NAT pinhole maintenance.
* **Fix Direction**: The control loop must reset the `attempt_started` stamp (or start a new attempt window) when a persistent keepalive tick triggers a new handshake attempt after the previous 90-second attempt window has expired.

#### 5. Busy-Spin on Fatal TUN/Socket Error (MAJOR)
* **Evidence**: [plan.md:L298-302](file:///home/ps/git/bpfrx/.claude/worktrees/1888-research/docs/research/1888-wg-timers/plan.md#L298-L302) and [wg_control.rs:L230-239](file:///home/ps/git/bpfrx/.claude/worktrees/1888-research/userspace-dp/src/afxdp/coordinator/wg_control.rs#L230-L239).
* **Vulnerability**: If a fatal error occurs on the TUN device (e.g., interface destroyed under us), `poll` returns instantly with `POLLERR` or `POLLHUP`. The `tun.read` call will return a fatal `Err` (not `WouldBlock`), which breaks the inner burst loop but does not exit the outer thread loop. The control thread will loop and spin at 100% CPU indefinitely.
* **Fix Direction**: Exit the thread loop immediately on any fatal I/O error (such as a `read`/`recv_from` error other than `WouldBlock`, or when `poll` returns with `POLLNVAL` or `POLLERR` flags on the fds). The supervisor's tombstone respawn machinery will handle recovery.

#### 6. High-Path Clock-Read Overhead (MINOR)
* **Evidence**: [plan.md:L182-194](file:///home/ps/git/bpfrx/.claude/worktrees/1888-research/docs/research/1888-wg-timers/plan.md#L182-L194) and [counters.rs:L225-237](file:///home/ps/git/bpfrx/.claude/worktrees/1888-research/userspace-dp/src/afxdp/wg/counters.rs#L225-L237) (vDSO `clock_gettime` per packet).
* **Vulnerability**: Calling `clock_gettime(CLOCK_MONOTONIC)` on every packet in `try_encap`/`try_decap` introduces unnecessary vDSO syscall overhead. While acceptable in S2a (decap on control thread), this is a performance regression trap if decap/encap is migrated to AF_XDP workers in S3.
* **Fix Direction**: Publish a coarse timestamp (updated once per control loop iteration/tick) in an atomic variable, and read this cached time inside `try_encap`/`try_decap`. A 1s tick granularity is more than sufficient for session expiry checks.

#### 7. Serial Join Latency on Coordinator Reload (MINOR)
* **Evidence**: [mod.rs:L683-685](file:///home/ps/git/bpfrx/.claude/worktrees/1888-research/userspace-dp/src/afxdp/coordinator/mod.rs#L683-L685) and [mod.rs:L739-752](file:///home/ps/git/bpfrx/.claude/worktrees/1888-research/userspace-dp/src/afxdp/coordinator/mod.rs#L739-L752).
* **Vulnerability**: When reclaiming stale threads, `coordinator/mod.rs` stops and joins them synchronously in a loop. With a `poll` cap of 100ms, if N tunnels are being stopped, the coordinator will block for up to `N * 100ms` waiting for joins.
* **Fix Direction**: Signal all stale threads to stop concurrently (by setting their `stop` flags to true) before entering the loop to join them. This bounds the total reload latency to at most 100ms.

#### 8. Explicit Check for Poll Errors (MINOR)
* **Evidence**: [plan.md:L298-302](file:///home/ps/git/bpfrx/.claude/worktrees/1888-research/docs/research/1888-wg-timers/plan.md#L298-L302) (progress tracking).
* **Fix Direction**: Directly inspect the `revents` returned by `poll(2)`. If `revents & (POLLERR | POLLHUP | POLLNVAL) != 0` on the TUN or socket fd, treat it as a fatal error and exit the thread immediately.

#### 9. Rollback Compatibility Warning (MINOR)
* **Evidence**: [plan.md:L403](file:///home/ps/git/bpfrx/.claude/worktrees/1888-research/docs/research/1888-wg-timers/plan.md#L403).
* **Vulnerability**: An old-xpf peer lacks timers. If the new-xpf peer initiates and then goes idle, it will expire the session at 180s. If the old-xpf peer then tries to send traffic, new-xpf will drop it. Because old-xpf lacks timers and is responder-only, it will never re-initiate, permanently blackholing the tunnel.
* **Fix Direction**: Document this rolling-upgrade compatibility risk in the release notes.

---

### Open Questions Verdicts

1. **T3 enforcement locus**: **locus-ok, but cached clock required.** Exact enforcement in the engine is correct, but vDSO syscalls on the hot path are a trap for the future. Use a coarse atomic clock published by the control thread.
2. **Stop wakeup**: **eventfd unnecessary, but concurrent join required.** The 100ms cap is fine, but the coordinator must signal all threads to stop concurrently before joining them to avoid `N * 100ms` serial delays.
3. **Stamp placement**: **PLACEMENT-FAIL on `Peer`.** Stamps must go on `WgSession` to avoid carrying over expired states and triggering infinite handshake loops.
4. **Initiation pacing**: **spec pacing preferred, but reset logic must be fixed.** Spec pacing is correct, but the state machine must handle new attempt windows triggered by T8 after the 90s timer expires (Finding 4).
5. **T7 in scope**: **YES.** Necessary to avoid 180s blackhole windows on dead sessions.
6. **Expired-decap error shape**: **YES.** A distinct `DecapError::Expired` variant is highly recommended for Prometheus metrics sanity.
7. **Counter granularity**: **YES.** Folded metrics are fine, provided they are documented.

---

### Verdict

PLAN-NEEDS-REVISION

**Justification**:
While the combined approach of implementing timers and blocking `poll` is architecturally sound, the plan contains critical logic bugs—specifically, infinite handshake loops caused by peer-scoped activity stamps, rekey retry blocking when a confirmed session exists, and a busy-spin bug when the timer tick and poll deadlines are out of sync. These issues must be addressed in the design before any files are modified.
