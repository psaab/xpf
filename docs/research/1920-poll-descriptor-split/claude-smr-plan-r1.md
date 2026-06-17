# Claude SMR hostile plan review — #1920 r1

**Verdict: PLAN-KILL-CORRECT (Path A).** I attacked the kill recommendation,
adjudicated the Codex/AGY conflict against the actual source, and the kill
survives. AGY's PLAN-NEEDS-WORK (reject-kill, expand Path B) is **refuted on
the code** — both blocks AGY called "cleanly liftable" are structurally coupled,
and AGY's codegen-units premise is factually false.

## Reviewer conflict and how I resolved it

Codex (`019ed638-…`) returned PLAN-KILL-CORRECT. AGY
(`adversarial-review-mqi8dngo-clmkj8`) returned PLAN-NEEDS-WORK, claiming Region
F (embedded-ICMP, 913–1058) and the MissingNeighbor arm (2397–2620) are cleanly
liftable. I did not take either reviewer's word — I read the disputed regions.

### Fact check 1 — codegen-units (objective, decisive)

AGY: *"§2 perf refutation is correct because the release profile's
`codegen-units = 1` forces thinLTO cross-module inlining."*

**FALSE.** `userspace-dp/Cargo.toml` has NO `[profile.release]` section; there is
no workspace-root `Cargo.toml` with a profile; `Makefile:44` runs a plain
`cargo build --manifest-path userspace-dp/Cargo.toml --release`. So
`codegen-units` is the default **16**, LTO is **off**. Codex caught this
correctly. AGY's premise is fabricated. (Consequence: AGY's own perf rationale
for Path B — "moving blocks out-of-line reduces register pressure under thinLTO"
— rests on a profile that does not exist.)

### Fact check 2 — MissingNeighbor arm liftability

AGY: the 2397–2620 slice writes none of the five tail-read locals; `continue`
re-dispatchable via a boolean → liftable.

**Refuted.** The `MissingNeighbor` match arm opens at **line 2242**, not 2397.
At the TOP of the arm it computes `(from_zone_id, to_zone_id)` (2248+) and runs
the #1913 policy-deny gate which **writes `decision.resolution.disposition =
PolicyDenied` at 2374–2375** then `continue` at 2388. AGY's 2397–2620 slice is
hand-picked to start AFTER that write — but you cannot extract a mid-arm slice:
it shares the arm-top `from_zone_id`/`to_zone_id`/`decision`/`meta`/`debug`, and
Codex verified the full arm (2242–2981) is **non-terminal** — it falls through
into the shared tail that reads `decision.resolution` (2989), `meta` (2991),
re-checks `decision.resolution.disposition` (3006), and feeds `meta`/`decision`
into `maybe_reinject_slow_path_from_frame` (3013–3014), with `recycle_now=false`
written mid-arm (2959). Extraction is a return-value redesign, not code-motion.
BLOCKED.

### Fact check 3 — Region F (embedded-ICMP) liftability

AGY: lines 913–1058 are cleanly liftable via an `EmbeddedIcmpOutcome` enum.

**Refuted.** `if is_embedded_icmp_error { … }` (913–1062) is the **`if` half of an
`if / else if` chain** — line 1062 is `} else if decision.resolution.disposition
== ForwardCandidate {` which is the *sibling branch* of the same dispatch, and
that sibling immediately writes `flow_cache_owner_rg_id` (1066). The `if` body
reads `flow`, `meta`, `from_zone`, `to_zone`, `decision`, conditionally mutates
`recycle_now`, and falls through (comment 1059–1061: *"fall through to
slow-path"*). Extracting one branch of an if/else-if and threading an outcome
enum back is exactly the logic-bearing restructure the issue forbids ("pure
code-motion increments"). BLOCKED / COSMETIC.

## My independent attack on §3 (did the plan miss a clean block?)

I traced every `continue` (21 sites, indent 24–52). The pre-slow-path continues
(144–149 raw-frame slice fail; 157/237 link-layer/ipsec recycle) are before the
mutable-locals web exists — extracting them is cosmetic and below the win bar.
Every post-flow-cache continue is inside a match/if-let arm that reads `meta`
and/or `decision`. There is no self-contained `continue`-terminated block beyond
the already-extracted flow-cache fast path. This is the #946 Phase-2 + #1327
stages-12+ verdict restated against the current file — both prior-art docs verify
(Codex confirmed line refs; I spot-checked `docs/pr/1327-…/plan.md` records the
ceiling and `docs/pr/1697-…/plan.md` records the "PLAN-KILL if only cosmetic
hot-path file-motion" stance).

## Required edits before the plan is final (Codex's two, ratified)

1. **§2:** drop the "same CGU / LLVM inlines across modules in the same CGU"
   wording. The production profile is `codegen-units=16`, LTO off — so an
   unannotated cross-module call is NOT guaranteed to inline. Reframe: the
   correct and only reliable I-cache lever is `#[cold] #[inline(never)]` on
   genuinely-cold bodies (the #1697 mechanism), independent of file layout — and
   that lever is orthogonal to a file split, which is what makes the audit's
   "L1-i" claim a non-sequitur. This makes the perf refutation airtight rather
   than resting on a wrong CGU assumption.
2. **§4/§9:** correct the LOC arithmetic. The MissingNeighbor *arm* is 2242–2981
   (740 lines), not the 224-line 2397–2620 slice. Removing the whole arm would
   leave ~2313 production LOC — STILL over 2000. Removing the narrow slice leaves
   ~2829. State explicitly that the arm is non-terminal (falls through to the
   shared disposition/reinject tail) so it cannot be a terminal cold block, and
   that no boundary clears the 2000 threshold. This kills Path B outright.

## Bottom line

Three independent reviewers' net position after adjudication: **Codex KILL-
CORRECT, Claude SMR KILL-CORRECT, AGY's NEEDS-WORK refuted on the code (both
liftability claims false, codegen premise false).** Path B is not viable; Path C
is the twice-killed split. PLAN-KILL (Path A) is the correct, evidence-backed
outcome. The plan needs the two factual corrections above (which strengthen the
kill), then it is PLAN-READY-as-KILL.
