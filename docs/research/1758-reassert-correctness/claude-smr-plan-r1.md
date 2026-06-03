# Claude SMR adversarial review — #1758 plan v2

Role: domain SMR (conntrack/NAT state machines), CPU/cache datapath, and
data-structure design. Hostile verify, not confirm.

## Reachability verdict: REACHABLE (independent confirmation)

I independently reproduced the collision with five reverted unit probes
(research-only; production source/tests left clean, verified via
`git checkout` + `git status`). Evidence:

- `reverse_wire_key(s1)==reverse_wire_key(s2)` is TRUE for two
  interface-mode-SNAT forward flows from distinct internal hosts sharing
  a source port to the same server behind one egress IP
  (`session/key.rs:84-122`, `nat/source.rs:431-441`). Printed `rk_equal=true`.
- End-to-end through `SessionTable`: S1 install→`K→S1`; S2 install→`K→S2`;
  S1 refresh re-asserts→`K→S1`; S1 expires→value-guarded removal sees
  `K→S1`→deletes K. Final: `s2_live=true reply_resolves=None`. **AGY r2's
  trace is mechanically real.**
- Counterfactual: with NO S1 re-assert, S2 survives THIS ordering
  (`reply_resolves=Some(S2)`).
- Displacement-victim: install-time hijack alone strands the older live
  session (`after_s2_hijack=Some(S2)`); only the re-assert lets the victim
  re-win (`after_s1_refresh_rewin=Some(S1)`).
- Allocator: a 2-port pool handed `40000`,`40001` then `exhausted` —
  pool-mode never duplicates a live external tuple (`allocator.rs:461`
  `owner_by_translated.contains_key` refusal). Pool-mode is IMMUNE.

Codex r1's broadening (NAT64 `nat64.rs:97/109`, DNAT-shared-backend
`destination.rs:126`, port-preserving static NAT `static_nat.rs:70`) is
correct — all leave `rewrite_src_port=None`. I verified NAT64 and DNAT by
reading the cited lines; both produce non-injective reverse tuples.

## Where I push on the plan

1. **The re-assert is a SYMPTOM, not the root, and the plan now says so
   (§4a) — good.** The root is two non-injective reverse tuples sharing a
   single-valued index. This is exactly the class of "structural defect
   dressed as a perf nit" that #1207/#1545/#1317 were KILLED for. The plan
   correctly refuses to remove the re-assert under the perf banner. AGREE.

2. **Severity is genuinely bounded but the plan must not over-soften it.**
   The primary reverse path is the dedicated reverse `SessionEntry`'s own
   `key_to_handle` / `reverse_translated_index` (`shared_ops.rs:384` runs
   before the `nat_reverse_index` fallback at `:425`). BUT that reverse
   entry's primary key is ALSO the (shared) reply tuple, so it collides at
   `key_to_handle` too (`install` evicts via `remove_entry:682`). So the
   collision is not masked — it just moves. The honest statement (now in
   §4a) is: steady-state forward-active flows self-heal on the next
   forward packet; forward-silent / reverse-active flows (server-push,
   UDP, long-poll) can stay dead. That is the correct severity envelope.

3. **Counter cost (Q4) is real.** Adding a `get`-before-`insert` compare on
   `index_forward_nat_key_parts` is on the per-refresh path that #1753 just
   optimized. The "different live handle" check needs the prior value, but
   `insert` already returns the displaced value — so it is a single
   `HashMap::insert` whose return is inspected, NOT an extra `get`. Net
   cost ~0 (the insert happens regardless; we just read its return). The
   plan should state this so reviewers don't kill the counter on a phantom
   cost. [Recommend folding this into Q4 / rec 3.]

4. **DNAT-shared-backend is the most operationally likely vector**, more
   than interface-SNAT source-port collisions: load-balancing multiple
   VIPs to one backend on the same port is a common pattern, and the
   client side often has stable source ports for keep-alive pools. The
   tracker's severity ranking should put DNAT-shared-backend first, not
   interface-SNAT. [Minor — ordering of §6.]

## Verdict

- **#1758 perf framing: PLAN-KILL.** Do not remove the re-assert; it is
  load-bearing and removal trades one corruption for another. The ~1% is
  not worth it. Label `plan-kill`, keep perf issue closed.
- **Disposition (kill perf + separate correctness tracker covering all
  four vectors + telemetry-first counter): PLAN-READY.** Sound, honest,
  and avoids the rearchitecture trap. Fold the §4a vectors and the Q4
  cost-clarification (point 3 above) before the issue comment.

No blocking objection to the disposition. The only edits requested are
the two clarifications above (counter cost, DNAT severity ordering).
