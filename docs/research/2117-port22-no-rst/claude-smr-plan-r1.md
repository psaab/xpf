# Claude SMR — hostile plan review r1 — #2117

**Posture:** hostile. I tried to make this a REAL bug. It is not.

## VERDICT: PLAN-KILL CORRECT

The plan's root cause is right and I independently re-verified the load-bearing
facts in the worktree source, plus one angle the two external hostile reviewers
touched but did not fully nail (the re-probe / session path).

## Independently verified (my own reads, worktree)

1. **Untrust ingress carries the input filter.** `test/incus/xpf-test.conf:20-26`
   — `ge-0/0/1` (untrust, 10.0.2.10) family inet → `filter { input dscp-filter; }`.
2. **`block-ssh` discards TCP/22, and 22 is the only discarded TCP dport.**
   `xpf-test.conf:404-413` (`from { protocol tcp; destination-port 22; } then {
   log; discard; }`); `term default { then accept; }` (414-416) catches
   23/3389/9999/8080. Only inet-filter `discard` for a TCP dport is :22 (grep
   confirmed).
3. **`Discard` is silent.** `userspace-dp/src/filter/mod.rs:31-35` — "Silently
   drop the packet."
4. **Input filter runs first and short-circuits, on BOTH the session-miss and
   session-hit paths:**
   - session-miss: `poll_descriptor/mod.rs:659-677` —
     `evaluate_non_pbr_input_filter`; `if action != Accept { ...; recycle;
     continue; }`. The reject sites are downstream at 1758 and 2416.
   - session-hit: `mod.rs:371-394` — `evaluate_dscp_sensitive_input_filter_on_
     session_hit`; same `if action != Accept { recycle; continue; }`.
5. **`build_reject_rst_frame` is port-agnostic** (`frame/tcp.rs:352-373`,
   `tcp_segment_consumed_len:380-428`) — never reads the dst port. The project's
   own test `reject_tcp_with_egress_enqueues_rst` (`reject_reply.rs:89,168-205`)
   uses **dst_port 22** and asserts a RST is enqueued: :22 RSTs whenever it
   reaches the reject path. Conclusive that the reject path is not the suppressor.

## The angle I added — re-probe / session determinism (kill survives)

A reviewer might argue "the FIRST SYN is discarded, but a re-probe hits a cached
session that behaves differently." Refuted: a `discard`ed SYN is dropped at
`mod.rs:676` **before any session install** (the install/decision code is all
downstream of L678). So no session is ever created for :22; every retry is a
fresh session-miss that re-hits L659 and is discarded again. Deterministic
silent drop on every packet — exactly the observed "silent timeout, 0 arrivals."
No first-vs-subsequent divergence to exploit.

## Alternatives I tried to resurrect — all dead

- **SYN-cookie/screen swallow** — would emit a SYN-ACK, not silence
  (`mod.rs:214-226`); screen verdicts are port-agnostic. Dead.
- **build_reject_rst_frame None for :22** — builder ignores port; unit test
  proves :22 → RST. Dead.
- **TX-budget / RST-storm suppression for :22** — gate + storm guard are
  port-agnostic and a SYN is never an inbound RST; and :22 never reaches the
  code anyway. Dead.
- **host-inbound `system-services { ssh }` on trust diverting :22** — local
  delivery is disposition-driven (DUT-owned IP), dst is the trust-HOST
  10.0.1.102 (transit), and the filter discards :22 before resolution regardless.
  Dead.

## The one fair criticism (folded into plan r2)

External reviewer A correctly flagged that recommendation §6.2 ("amend the smoke
doc") targets `docs/smoke/security-matrix-2026-06-20.md`, which is an UNTRACKED
local file — not on origin/master. The closure note needs a durable target. The
plan r2 reframes §6.2: the durable record is (a) this research doc + (b) the
issue-closure comment; amending the untracked smoke doc is optional/local
bookkeeping, not the system-of-record. This does not affect the kill.

## Bottom line

PLAN-KILL is correct. No production code change. Close #2117 as
working-as-configured; the #2089 reject path is correct and is in fact
*positively confirmed live* by this same smoke on 4 of 5 ports.
