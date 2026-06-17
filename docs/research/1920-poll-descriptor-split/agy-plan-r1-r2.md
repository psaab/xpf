# AGY plan-review record — #1920

## Round 1 — `adversarial-review-mqi8dngo-clmkj8` — PLAN-NEEDS-WORK (reject-kill)

AGY claimed Path B viable via two extractions:
1. Region F (embedded-ICMP, ~913–1058) cleanly liftable via an
   `EmbeddedIcmpOutcome` enum.
2. MissingNeighbor block (~2397–2620) writes none of the tail-read locals;
   `continue` re-dispatchable via a boolean → liftable.
3. Asserted §2 perf refutation correct "because `codegen-units = 1` forces
   thinLTO cross-module inlining."
4. Prior-art (#1327, #1697) citations verified accurate.

**Adjudication (Claude SMR, against the source):** claims 1–3 refuted.
- (1) The `if is_embedded_icmp_error` block is the `if`-half of an if/else-if
  chain; the sibling `else if … ForwardCandidate` writes `flow_cache_owner_rg_id`
  (1066). Extracting one branch behind an outcome enum is logic-bearing.
- (2) The MissingNeighbor *arm* opens at 2242 (not 2397); writes
  `decision.resolution.disposition = PolicyDenied` at 2374–2375; the full arm
  2242–2981 is non-terminal (falls through to shared tail reading
  `decision`/`meta` at 2989–3014; `recycle_now=false` at 2959).
- (3) `userspace-dp/Cargo.toml` has no `[profile.release]`; `Makefile:44` plain
  release build → `codegen-units=16`, LTO off. AGY's premise is factually wrong.

## Round 2 — `adversarial-review-mqi8ok4h-f77z3q` — PLAN-KILL-CORRECT (NEEDS-WORK withdrawn)

AGY re-verified against the source and **withdrew** the round-1 dissent:
1. CLAIM 1 refuted — MissingNeighbor arm has loop-control `continue`s, mutates
   `recycle_now`, modifies `decision` read by the tail. Logic-bearing, not
   code-motion.
2. CLAIM 2 refuted — embedded-ICMP `if`-half; sibling mutates
   `flow_cache_owner_rg_id`. Requires call-site control logic + outcome enum.
3. CLAIM 3 refuted — confirmed no `[profile.release]`, plain release build,
   `codegen-units=16`, LTO off.
4. LOC gate — even extracting BOTH blocks leaves mod.rs at ~2128 LOC, still over
   the 2000 ceiling.

**Final AGY verdict: PLAN-KILL-CORRECT.**

(AGY's exact line numbers differ from the master-relative numbers because AGY
read a slightly different file revision via its absolute /home/ps/git/bpfrx
path; the structural facts — decision/recycle_now writes, non-terminal arm,
if/else-if sibling coupling, no release profile — are identical on the
research-branch source and were independently confirmed by Codex and Claude
SMR against `research/1920-poll-descriptor-split`.)
