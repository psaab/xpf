1. **BLOCKER — persistent-keepalive semantics are wrong.**  
   Evidence: [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1888-research/docs/research/1888-wg-timers/plan.md:82) says T8 fires “if nothing sent”; wireguard-go resets persistent keepalive on any authenticated traversal, sent or received, including handshakes (`timersAnyAuthenticatedPacketTraversal`, GitHub `device/timers.go` lines 983-991).  
   Fix direction: Pace T8 from `last_auth_traversal_ns`, not `last_send_any_ns`, and update it for authenticated transport plus authenticated handshake send/receive.

2. **BLOCKER — the stamp table omits authenticated handshakes, so T6/T7/T8 can fire incorrectly.**  
   Evidence: [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1888-research/docs/research/1888-wg-timers/plan.md:91) defines `last_send_any_ns` only for encap data/keepalive, and [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1888-research/docs/research/1888-wg-timers/plan.md:95) defines `last_recv_any_ns` only for transport records; wireguard-go says “any type of authenticated packet” includes keepalive, data, or handshake (`device/timers.go` lines 920-938), and calls it on handshake RX (`device/receive.go` lines 1876-1880, 1926-1930).  
   Fix direction: Add handshake traversal stamps in `drive_initiation`, response send, `consume_response`, and `consume_initiation_create_response`.

3. **MAJOR — passive keepalive arming is too narrow if wired only to successful delivered inner packets.**  
   Evidence: [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1888-research/docs/research/1888-wg-timers/plan.md:88) says `last_recv_data_ns` is set on successful non-empty `try_decap`; current `try_decap` only returns `Ok` after AllowedIPs and inner parsing, with post-AEAD errors at [engine.rs](/home/ps/git/bpfrx/.claude/worktrees/1888-research/userspace-dp/src/afxdp/wg/engine.rs:982) and [engine.rs](/home/ps/git/bpfrx/.claude/worktrees/1888-research/userspace-dp/src/afxdp/wg/engine.rs:1016). wireguard-go sets `dataPacketReceived` before AllowedIPs delivery (`device/receive.go` lines 2019-2028).  
   Fix direction: Arm T6 after authenticated, replay-accepted, non-empty transport plaintext, before inner-IP/AllowedIPs rejection.

4. **MAJOR — T3 decap should enforce expiry, not initiate a rekey.**  
   Evidence: [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1888-research/docs/research/1888-wg-timers/plan.md:196) says expired decap drops and arms rekey; wireguard-go send path initiates on expired/no key (`device/send.go` lines 1882-1888), while receive drops expired keypairs before delivery and relies on send-side/new-data behavior.  
   Fix direction: On expired receive, count/drop/expire only; initiate from send-side NoSession/expired local data, T1/T2, T7, or T8.

5. **MAJOR — T5/T9 do not specify pending-handshake cleanup, so stale msg2 can complete after give-up.**  
   Evidence: [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1888-research/docs/research/1888-wg-timers/plan.md:79) says give up after 90s, but [handshake_session.rs](/home/ps/git/bpfrx/.claude/worktrees/1888-research/userspace-dp/src/afxdp/wg/handshake_session.rs:202) stores pending state and [handshake_session.rs](/home/ps/git/bpfrx/.claude/worktrees/1888-research/userspace-dp/src/afxdp/wg/handshake_session.rs:362) can later promote it.  
   Fix direction: Timestamp pending handshakes and release/zero the reservation on T5 give-up or before accepting msg2 beyond the attempt window.

6. **MAJOR — poll error handling is under-specified and may exit on UDP error readiness or spin on persistent readiness.**  
   Evidence: [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1888-research/docs/research/1888-wg-timers/plan.md:296) treats UDP ERR/HUP as normal but also proposes a generic “poll-ready-but-zero-progress” exit guard; current socket/TUN error arms only break the drain loop at [wg_control.rs](/home/ps/git/bpfrx/.claude/worktrees/1888-research/userspace-dp/src/afxdp/coordinator/wg_control.rs:200) and [wg_control.rs](/home/ps/git/bpfrx/.claude/worktrees/1888-research/userspace-dp/src/afxdp/coordinator/wg_control.rs:231).  
   Fix direction: Make the guard fd-specific: exit on TUN `POLLNVAL/HUP` or repeated TUN read failure, but do not tombstone the thread for transient UDP `POLLERR`.

7. **MAJOR — exact T3 in `try_encap`/`try_decap` is the right locus; tick-only teardown is not acceptable.**  
   Evidence: the whitepaper says after Reject-After-Time the implementation refuses send or receive (`wireguard.pdf` lines 766-767), while [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1888-research/docs/research/1888-wg-timers/plan.md:476) still frames tick-only as an open alternative.  
   Fix direction: Close Q1: require per-use engine enforcement; the control pass is cleanup only.

8. **MINOR — rekey/timeout jitter is omitted more broadly than documented.**  
   Evidence: [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1888-research/docs/research/1888-wg-timers/plan.md:78) documents T4 jitter omission, but T7 also uses `KeepaliveTimeout + RekeyTimeout + jitter` in wireguard-go (`device/timers.go` lines 890-895).  
   Fix direction: Either implement jitter for both T4 and T7 or document both deviations.

9. **MINOR — Arc reload ordering is acceptable.**  
   Evidence: unchanged identity reuses the same engine Arc at [forwarding_build/wg.rs](/home/ps/git/bpfrx/.claude/worktrees/1888-research/userspace-dp/src/afxdp/forwarding_build/wg.rs:61), and engine-changed stale threads are stopped and joined before spawn at [coordinator/mod.rs](/home/ps/git/bpfrx/.claude/worktrees/1888-research/userspace-dp/src/afxdp/coordinator/mod.rs:653).  
   Fix direction: Keep timer state on `Peer`/`WgSession`; only make retry pacing thread-local.

**§11 Verdicts:** Q1: exact engine T3 gate, not tick-only. Q2: 100ms cap is defensible for current single-digit tunnels. Q3: peer-level stamps are right, but the stamp set must include handshake traversal and persistent traversal. Q4: adopt 5s/90s spec pacing. Q5: keep T7 in scope. Q6: use `DecapError::Expired`. Q7: split `rekeys_initiated` by at least `age`, `dead_peer`, and `persistent_no_session` unless wire budget is truly constrained.

PLAN-NEEDS-REVISION — The architecture is salvageable, but §3 is not faithful to wireguard-go because persistent keepalive and “any authenticated packet” traversal are wired wrong, and pending handshake expiry is underspecified. Fix those before implementation; otherwise the plan will ship observable wrong timers, not just harmless telemetry drift.

Codex session ID: 019eba8e-b6ed-7b61-a471-7b81fb8fa4e7
Resume in Codex: codex resume 019eba8e-b6ed-7b61-a471-7b81fb8fa4e7
