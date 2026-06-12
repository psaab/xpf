**R1 Resolution Audit**
- B1 persistent-keepalive traversal pacing: RESOLVED. `plan.md:123` and `:152-154` now pace T8 on authenticated traversal in either direction; Linux confirms this in `/home/ps/git/linux/drivers/net/wireguard/timers.c:215-219`.
- B2 handshake stamps missing: RESOLVED. `plan.md:142-151` now includes authenticated handshake send/receive; Linux calls traversal for handshake send/receive in `send.c:34-42`, `send.c:94-100`, and `receive.c:201-202`.
- M3 T6 pre-AllowedIPs arming: RESOLVED. `plan.md:135-140` and `:291` place `last_recv_data_ns` after auth/replay but before inner parse/AllowedIPs.
- M4 expired decap drop-only: RESOLVED. `plan.md:286-289` says decap T3 is drop/count only, no rekey arm.
- M5 T5 pending release: RESOLVED for cleanup. `plan.md:324-333` and `:418-421` add `abort_pending_for_peer`; existing completion locking supports the race semantics (`handshake_session.rs:357-360`, `:407-413`).
- M6 fd-specific poll guard: RESOLVED. `plan.md:449-460` scopes fatal exit to TUN revents/read failures, not UDP.
- M7 per-use T3 locus: RESOLVED for locus, but see Finding 2 for cached-clock freshness.
- m8 T7 jitter doc: RESOLVED. `plan.md:122` and `:654-656` document the T4/T7 jitter deviation.
- Q7 counter split: RESOLVED. `plan.md:486-488` and `:705-707` split age/dead-peer/keepalive-no-session.

1. **BLOCKER — Attempt success can fail forever after a valid msg2 because `created_ns` can be stamped from stale cached time.**  
Evidence: `plan.md:300-302` says session `created_ns` is stamped from the cached clock; `plan.md:360-365` publishes the clock after the socket/TUN burst; `plan.md:415-417` requires `current.created_ns > started_ns`; `plan.md:410-413` then retries while active while bypassing `peer_has_confirmed_session`. A fast response received in the next socket burst can install a healthy session using the previous cached timestamp, equal to or older than `started_ns`, so the attempt never observes success and retries every 5s until T5.  
Fix direction: do not use a wall-clock inequality as the attempt generation test. Store the baseline current session identity/local_index at attempt start and end the attempt when current changes, or publish a fresh timestamp before dispatch and before every install plus use a non-fragile generation check.

2. **MAJOR — The cached-clock T3 slop bound is not proven for worker encap.**  
Evidence: `plan.md:258-266` claims `≤100ms` idle and `~0.2s` worst-case slop, but `plan.md:206-209` admits `try_encap` also runs on the worker transit path, and `frame/wg.rs:108` calls `engine.try_encap(...)` without publishing time. If the control thread is descheduled, stuck in long bursts, or otherwise not iterating, workers can keep using an old `cached_now_ns` and send past REJECT_AFTER_TIME.  
Fix direction: either restore a per-use monotonic read for T3, add a freshness guard/fallback read in `try_encap`, or make the clock publisher independent of the control loop. Do not claim hard `~0.2s` slop without a hard publisher bound.

3. **MAJOR — Deadline state still has a zero/past-deadline spin shape unless the sentinel is specified.**  
Evidence: `plan.md:344` makes `next_deadline_ns` a raw `u64`; `plan.md:370-381` recomputes `next_deadline = actions.next_deadline_ns.min(attempt.next_retry_ns)` and then uses `saturating_sub(now)`. The plan never defines initialization or the “no deadline/no attempt” value; if either side returns `0`, the AGY F3 busy-spin comes back.  
Fix direction: use `Option<u64>` or `u64::MAX` as the no-deadline sentinel, initialize explicitly, and require every recomputed active deadline to be future or intentionally force exactly one immediate pass.

4. **MAJOR — Post-msg2 transport confirmation is missing from the plan’s packet sequence.**  
Evidence: Linux sends a keepalive immediately after processing a handshake response when no queued data exists (`receive.c:176-186`). xpf responder sessions are unconfirmed until inbound transport (`session.rs:82-93`), and `try_encap` rejects unconfirmed current sessions as `NoSession` (`engine.rs:728-743`). v3 resets T8 on the inbound msg2 (`plan.md:152-154`) but does not send immediate transport, so a persistent-no-session handshake can leave the responder unconfirmed until the next keepalive interval.  
Fix direction: on successful `consume_response`, send queued data if any, otherwise send an immediate empty transport keepalive, and stamp it through `last_send_any_ns`.

5. **MINOR — Signal-then-join misses one multi-entry stop path.**  
Evidence: v3 names stale-prune and stop-all only (`plan.md:461-467`); current stale-prune is serial at `coordinator/mod.rs:683-684`, and stop-all is serial at `:934-938`. There is also deferred snapshot pruning, also serial, at `coordinator/mod.rs:952-970`.  
Fix direction: introduce one bulk stop helper that collects all affected entries, sets all stop flags, then joins/removes all of them; use it from stale-prune, stop-all, and deferred snapshot prune.

PLAN-NEEDS-REVISION — v3 fixes the r1 timer semantic gaps, including traversal pacing and handshake stamps, but the new cached-clock attempt-success design has a verified trace that retries after a valid handshake. The deadline sentinel and worker-clock freshness issues also need to be specified before implementation, or the plan can reintroduce CPU spin and violate the claimed T3 bound.