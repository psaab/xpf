# Codex — hostile plan review r1 — #2238

Verbatim terminal verdict (codex-rescue / gpt-5.x, read-only, grounded in line
references across icmp.rs, cos_classify.rs, reject_reply.rs, cookie_reply.rs,
tx/dispatch/mod.rs, mirror/fast_path.rs, mirrors.go, filter/engine/*,
afxdp/mod.rs, umem/*, protocol/tests.rs):

```
- [HIGH] PATH RISK (A vs B vs C) — Path B is lower-risk than A/C; Path A can
  route local replies into the transit loop, and the dispatch mirror is
  input-direction only, not free for egress. Disposition: BLOCKING unless the
  plan commits to Path B.
- [HIGH] FAIL-OPEN ON INTERNAL PARSE FAILURE (§6.2) — The plan must fail-closed
  and drop the packet on internal parse failure during classification.
  Disposition: BLOCKING.
- [MEDIUM] ICMP KEYING — TX-selection eval may not currently key on icmp-type;
  this is a wiring detail if the design requires ICMP terms to carry icmp-type.
  Disposition: implementation note.
- [MEDIUM] COUNTER WIRING — New per-packet counters need both BatchCounters and
  live/snapshot fields; Time Exceeded has multiple descriptor paths and some
  lack a counter handle. Disposition: implementation note.
- [LOW] ICMP ports=0 — Plan explicitly handles no port match on ICMP.
  Disposition: resolved.
- [LOW] HOT-PATH / COLD-PATH SPLIT — resolved.
- [LOW] HA/FABRIC — resolved.
- [LOW] WIRE CONTRACT — resolved.

PLAN NO
Blocking defects: (1) plan does not commit to Path B — Path A is present as an
option and risks transit-loop on local replies; (2) §6.2 is silent/fail-open on
parse-failure disposition — implementation must be fail-closed (drop), and the
plan must say so explicitly.
```

## Disposition (folded into plan r3)

- **Blocker 1 (commit to Path B):** APPLIED. Plan §5 now marks Path B as the
  COMMITTED decision; A/C are rejected-with-reason and not re-openable.
- **Blocker 2 (fail-closed §6.2):** APPLIED. Plan §6.2 flipped to fail-CLOSED
  (drop) + mandatory `generated_reply_classify_parse_errors` counter. Converges
  with AGY-r1 (same finding).
- **ICMP keying / counter wiring / Time Exceeded multi-path:** captured as
  `/engineer` implementation notes in plan §8.1 (non-blocking; design
  unchanged).

NOTE: the first codex-rescue dispatch stalled mid-investigation (the documented
"Codex companion infra-drop after deep dive" pattern); the verdict above is from
the follow-up dispatch that synthesized the already-grounded findings. Both
external reviewers (Codex + AGY) converged on the fail-closed blocker
independently.
