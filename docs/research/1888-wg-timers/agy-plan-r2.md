I will view the `plan.md` file (v3 of the plan) to analyze the proposed implementation and see how the previous round 1 findings were addressed, and to identify any new risks or issues.
 clean}
-md,toolSummary:Viewing file}
### Round-1 Findings Verification

All round-1 findings from `agy-plan-r1.md` have been reviewed against the revised **v3 plan** (`plan.md`):

*   **AGY F1 (peer-stamp infinite-T7 loop): RESOLVED**
    The handshake-traversal stamps introduced in v2/v3 correctly ensure that a valid inbound `msg2` stamps `last_recv_any_ns` via the `consume_response` wrapper, clearing the T7 suspect-dead condition. (Note: A new infinite-T7 loop related to handshake timeouts is identified below as Finding 1).
*   **AGY F2 (rekey-retry starvation): RESOLVED**
    The new `HandshakeAttempt` state machine (§5.2) successfully paces retries at `REKEY_TIMEOUT` (5s) and bypasses the `peer_has_confirmed_session` check during active attempts.
*   **AGY F3 (mid-tick deadline busy-spin): RESOLVED**
    The control loop now runs the timer pass whenever `now >= next_deadline` or the 1s tick elapses, correctly avoiding zero-timeout busy-spinning on sub-second deadlines.
*   **AGY F4 (T8 lock-out after give-up): RESOLVED**
    T5 give-up now clears the `attempt` state, allowing the next T8 due-tick to successfully start a fresh attempt window.
*   **AGY F5/F8 (fatal-fd busy spin): RESOLVED**
    TUN `POLLERR`/`POLLHUP`/`POLLNVAL` revents and consecutive non-`WouldBlock` read failures now exit the control thread loop (though UDP socket `POLLNVAL` was missed, see Finding 3).
*   **AGY F6 (high-path clock-read): RESOLVED**
    The engine reads the coarse `cached_now_ns` published by the control loop, avoiding vDSO syscall overhead on the hot path.
*   **AGY F7 (serial join latency): RESOLVED**
    `spawn_wg_control_threads` and `stop_all_wg_control_threads` now set all `stop` flags before joining, bounding stop latency to a single cap.
*   **AGY F9 (upgrade note): RESOLVED**
    The rolling-upgrade compatibility warning has been integrated into §8.

---

### Adversarial Findings (Round 2)

#### 1. Infinite Handshake Loop on T7 Expiry and T5 Give-up (BLOCKER)
*   **Evidence**: [`plan.md:122`](file:///home/ps/git/bpfrx/.claude/worktrees/1888-research/docs/research/1888-wg-timers/plan.md#L122) (T7 definition), [`plan.md:324-335`](file:///home/ps/git/bpfrx/.claude/worktrees/1888-research/docs/research/1888-wg-timers/plan.md#L324-L335) (T5 give-up), and [`plan.md:391-424`](file:///home/ps/git/bpfrx/.claude/worktrees/1888-research/docs/research/1888-wg-timers/plan.md#L391-L424) (HandshakeAttempt machine).
*   **Vulnerability**: When a handshake attempt times out after 90 seconds (T5 give-up), the control loop calls `abort_pending_for_peer` and clears `attempt` (sets it to `None`). On the next timer tick, the control loop evaluates the initiation predicates again. Since no egress data was sent since the timeout, `last_send_data_ns` remains unchanged. The T7 predicate `last_send_data_ns > last_recv_any_ns && now - last_send_data_ns >= 15s` will evaluate to `true` again, immediately starting a brand new 90-second handshake attempt window. This loop cycles indefinitely, hammering the peer with handshakes and completely defeating the 90s give-up timeout.
*   **Fix Direction**: Clear `last_send_data_ns` (set it to 0) upon starting a handshake attempt or when giving up (T5), so that it cannot trigger another attempt until new egress data is actually encrypted and sent.

#### 2. T8 Persistent Keepalive NAT Pinhole Failure on Unconfirmed Session (MAJOR)
*   **Evidence**: [`plan.md:123`](file:///home/ps/git/bpfrx/.claude/worktrees/1888-research/docs/research/1888-wg-timers/plan.md#L123) (T8 trigger definition) and [`plan.md:280-285`](file:///home/ps/git/bpfrx/.claude/worktrees/1888-research/docs/research/1888-wg-timers/plan.md#L280-L285) (keepalive encryption contract).
*   **Vulnerability**: T8 triggers if "no usable session exists". A responder-role session is installed as unconfirmed (`confirmed = false`), meaning it is not usable for sending transport data or keepalives. If T8 evaluates "usable session" simply by checking if `peer.current` is `Some`, it will try to send a keepalive on this session. The keepalive will fail the `confirmed` gate in `try_encap`, meaning no keepalive is sent on the wire and no handshake is initiated. This silently breaks NAT pinhole maintenance.
*   **Fix Direction**: Explicitly define a "usable session" for T8 as a session that is both *confirmed* and *not expired*. If the current session is unconfirmed, T8 must initiate a handshake.

#### 3. Infinite Busy-Spin on UDP Socket `POLLNVAL` (MAJOR)
*   **Evidence**: [`plan.md:20-21`](file:///home/ps/git/bpfrx/.claude/worktrees/1888-research/docs/research/1888-wg-timers/plan.md#L20-L21) and [`plan.md:449-460`](file:///home/ps/git/bpfrx/.claude/worktrees/1888-research/docs/research/1888-wg-timers/plan.md#L449-L460) ("UDP errors never exit").
*   **Vulnerability**: If the UDP socket fd becomes invalid or is closed externally (e.g., during a network device reload), `poll(2)` on that socket fd will immediately return `POLLNVAL` in `revents`. Since the plan states that UDP errors never exit the thread, the control loop will continue to poll and immediately wake up with `POLLNVAL` in a tight busy-spin, consuming 100% CPU.
*   **Fix Direction**: Inspect the UDP socket fd's `revents` and exit the control loop thread if `POLLNVAL` is set on it.

#### 4. Passive Keepalive (T6) Suppression under Inbound-Only Data Streams (MAJOR)
*   **Evidence**: [`plan.md:121`](file:///home/ps/git/bpfrx/.claude/worktrees/1888-research/docs/research/1888-wg-timers/plan.md#L121) (T6 trigger definition) and [`plan.md:135-141`](file:///home/ps/git/bpfrx/.claude/worktrees/1888-research/docs/research/1888-wg-timers/plan.md#L135-L141) (activity stamps).
*   **Vulnerability**: If the T6 trigger check is implemented as `now - last_recv_data_ns >= 10s`, a continuous stream of inbound-only transport packets (updating `last_recv_data_ns` every few seconds) will prevent `now - last_recv_data_ns` from ever reaching 10s. Thus, T6 will never fire. However, since we are sending nothing back, the peer receives nothing and will hit its T7 (15s) timeout, triggering unnecessary handshake rekeys and disrupting the session.
*   **Fix Direction**: Define the T6 predicate as `last_recv_data_ns > last_send_any_ns && now - last_send_any_ns >= KEEPALIVE_TIMEOUT (10s)`.

#### 5. Timer Pass Tick-Reset Slop (MINOR)
*   **Evidence**: [`plan.md:370-378`](file:///home/ps/git/bpfrx/.claude/worktrees/1888-research/docs/research/1888-wg-timers/plan.md#L370-L378) (timer pass conditions in the loop).
*   **Vulnerability**: The control loop updates `last_timer_pass_ns = now;` whenever the timer pass runs, including for mid-tick deadline executions. If deadlines fire frequently (< 1s apart), `now - last_timer_pass_ns` will never reach `WG_TIMER_TICK_NS` (1s), indefinitely postponing the periodic 1s tick-based checks.
*   **Fix Direction**: Only update `last_timer_pass_ns` when the 1s tick condition `now - last_timer_pass_ns >= WG_TIMER_TICK_NS` is met, or decouple the periodic tick check from the deadline checks.

---

### Open Questions Adjudication

*   **§11 Q8 (T8 Traversal Pacing):** The v3 reading of `max(last_send_any_ns, last_recv_any_ns)` is correct and matches `wireguard-go`'s `timersAnyAuthenticatedPacketTraversal`. Since handshakes and keepalives keep the NAT pinhole open, resetting the persistent keepalive timer on any authenticated traversal prevents unnecessary keepalive packets.
*   **§11 Q9 (Handshake Stamp-Site Asymmetry):** The proposed asymmetry (sends stamped at socket write success, receives stamped in the engine consume wrappers) is sound. Stamping receives inside the consume wrappers guarantees that we only stamp successfully authenticated packets, preventing unauthenticated spoofing/replay packets from resetting our dead-session or keepalive timers.

---

VERDICT: PLAN-NEEDS-REVISION. The plan successfully resolves all round 1 issues but introduces new blocking and major flaws, specifically an infinite handshake loop after timeout give-up, passive keepalive suppression during inbound-only traffic, and a 100% CPU busy-spin on UDP socket POLLNVAL. These issues must be addressed before the plan is ready for implementation.
