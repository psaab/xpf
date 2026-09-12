# Engineering style for xpf

This file describes the coding and review personality the project has
settled on. It is checked into the repo so new contributors — human or
agent — internalise it before touching code or reviews. It is terser and
more opinionated than `CLAUDE.md`; keep it that way.

Read this file in full before:

- writing non-trivial code in `userspace-dp/` or any hot path
- reviewing a PR
- opening a PR that claims a performance improvement

### Before every push: read the diffstat against master, in BOTH forms

```
git diff --stat origin/master HEAD      # catches a real DELETION
git diff --stat origin/master...HEAD    # says whether the change is YOURS
```

**Neither alone is the check — the pair is.** Two-dot compares the trees, so it
shows files your branch would remove *including* ones it never touched, when
master has moved underneath you. Three-dot compares from the merge base, so it
shows only what you actually changed and would hide a deletion that is real.

Both halves cost real work today. A branch was about to merge with a 413-line
guard file and its testdata deleted — a stale base, and **the full suite was
green precisely because those files were absent from the branch. A deleted
guard cannot fail.** Later the same day, two-dot alone reported eighteen files
including a `pkg/daemon` test nobody had opened; three-dot showed nine, all
genuinely the branch's.

A test suite tells you what your change does to the code that is present. It
cannot tell you what your change removes.

`git diff --stat` alone also **understates** a change: a new file that is not
yet `git add`ed is invisible to it. A lane landing #8993 had two new files and
a diffstat that did not mention either.

### A WRONG INSTRUMENT and a WRONG POPULATION need different remedies

An instrument can be wrong in two ways that look identical in its output and
are not fixable by the same move.

**WRONG INSTRUMENT** — it measured the right subject at the wrong layer. Four
of these cost real numbers on one class in one day:

| # | error | cost |
|---|---|---|
| 1 | `CompileConfig` where the commit gate is `CheckText` | a whole census reported the tolerant channel as the operator one |
| 2 | a schema walk where a later compiler gate also runs | 246 blind, 205 actually accepted |
| 3 | counting `groups`-rehosted paths as distinct | 205 collapsed to 102 |
| 4 | hierarchical text where the subject is a flat run | would have measured #8437's guard and reported it as the walk |

Every one is found by **a control at that layer**. Add the good-value probe,
the end-to-end spot-check, the per-prefix histogram, the flat-vs-hierarchical
pair — and the number moves.

**WRONG POPULATION** — the subject was never admitted, so no control at any
layer can reach it. A control interrogates what the filter passed; it cannot
interrogate what the filter removed.

The instance, measured: the #8939 collector admits a leaf only when
`children == nil && wildcard == nil && !multi`, discarding 63% of containers
before the census runs. A fix to `system login class` turned `permissions` from
read to inert — and `permissions` is `multi`, so **the census could not have
measured that leaf under any outcome.** The row left the loser list, which
reads as the fix working.

> **An aggregate ratchet cannot see a fix that breaks a neighbour inside the
> same row. A ratchet cannot see anything its filter removed at all. The first
> needs the dimensions kept separate; the second needs a SECOND INSTRUMENT.**

`TestSchemaSpellingDifferentialGate` caught it, because it reports per-spelling
verdicts rather than one number per subject, and because its population is
filtered differently.

So:

- **Publish the denominator.** `SILENT: 0` over 9 containers and over 139 are
  the same string; `losers=48` over 133 reached and over 363 walked are the
  same string. A census that does not state its reach is asserting the world.
- **Print a per-prefix breakdown.** Nearly free, and it catches unit errors
  without anyone remembering the rule — a `groups` double-count was found this
  way by someone who had personally written the note warning about it.
- **A hedge that is accurate and load-bearing is worse than a wrong claim**,
  because it survives review: the reviewer checks it and it holds. "EMPTY,
  every container the census could reach" was true, and the qualifier carried
  130 containers. Repair it by stating the reach in numbers, not by softening
  it further.
- **Before landing a fix, point the instrument at a known-good one and check
  the delta is the one you predicted.** An instrument validated only against
  the population it measures cannot detect a coverage loss, because the
  population is what moved.

### When you CORRECT someone, ask whether you are CONJOINING or REPLACING

A lane held the container-level half of a discriminator. A second lane found the
leaf-level half while correcting them -- and named their own half as *the*
discriminator rather than conjoining the two. The corrected rule was as wrong as
the one it replaced, in the same direction, and it propagated into an issue body
and a test file's comment before measurement caught it.

Measured, the rule is a CONJUNCTION:

```
container                    unknown-kw   run@untyped   run@typed
system login class           ACCEPT       ACCEPT        REJECT
security ike gateway         ACCEPT       ACCEPT        REJECT
security ipsec proposal      REJECT       REJECT        REJECT
security flow tcp-session    REJECT       --            REJECT
```

> A flat run is ACCEPTED iff the container is OPEN-WORLD **and** the leaf it
> starts at is UNTYPED. Either condition alone rejects it.

`security ipsec proposal` falsifies the leaf-only form: its starting leaf is
untyped and the run is rejected anyway, because that container is closed-world.

**This is not ordinary over-generalisation.** Correcting someone puts you in a
frame where their account is the thing being replaced, and a newly-measured half
arrives feeling like the whole. You have just demonstrated that their claim was
incomplete -- which is the worst state in which to test your own for the same
property. The lane who did it said it exactly: *"I shipped a rule with the exact
defect I had just diagnosed in theirs, in the same message."*

Ask it explicitly: **is the thing I just measured a REPLACEMENT for their
account, or a CONJUNCT with it?** A replacement needs the old account to be
FALSE, not merely partial -- and if their evidence still holds where they
measured it, it is a conjunct.

Corollary for the receiving side: a correction arrives carrying the authority of
its measurement, and that authority covers the half that was measured, not the
scope claimed for it.

### Hand over a MECHANISM, not a count — and gate a shared helper with a DIFFERENTLY-FILTERED instrument

Two rules that came out of the same afternoon, both about what a finding does to
the person who receives it.

**A COUNT INVITES A FIX SCOPED TO THE COUNTED ROWS.** A lane found that three
census rows were mislabelled `vacuous` and, rather than filing "3 rows are
wrong", handed over the mechanism plus an explicit lower bound because their
schema walk was crude. The real cause sat one level above: the generator derived
every value from the leaf's NAME when the schema already carried an example --
`530 leaves, 57 typed, 42 handed a placeholder their validator rejects`. Filing
the count would have made three special cases the plausible remedy and left 39
typed leaves still guessed. The mechanism invited a fix where the mechanism
lived: one lookup.

This does NOT contradict "publish the denominator" or "an aggregate count is not
reviewable". Those are rules for a CLAIM. This is a rule for a HANDOFF: a number
tells the recipient how big the problem is and simultaneously tells them where to
stop looking. State the count for scale, hand over the mechanism for repair, and
say which of the two you are confident in.

**A CHANGE TO A SHARED TRAVERSAL HELPER MUST BE GATED BY AN INSTRUMENT WHOSE
POPULATION FILTER DIFFERS FROM THE ONE THAT MOTIVATED THE CHANGE.**

The concrete instance: an edit to `expandFlatRun` broke three leaves at three
unrelated containers, every one of them `multi` -- and `!multi` is the #8939
collector's own eligibility filter, so its fixture reported nothing at any of
them. `TestSchemaSpellingDifferentialGate` caught all three because it sweeps a
differently-filtered population and reports per-spelling verdicts.

Today the full-package gate enforces this by accident. **The reason it works is
not that it is bigger, it is that it is differently filtered** -- so a future
scoped gate would look like a reasonable optimisation and would silently remove
the only instrument that can see this class. That is why the rule is written
here rather than left to package scope.

Corollary, from the same instance: a wrong-population blind spot does not fail
once. It fails silently every time the same helper meets the same excluded class.

### `git stash` is REPO-GLOBAL. In a multi-worktree repo it is a shared stack.

Every worktree of one repository shares **one** stash stack. `git stash pop`
with no argument takes whatever is on TOP, which in a campaign is very likely
another lane's work.

This is not hypothetical, and the evidence is on the stack itself. Measured
2026-09-05: **32 entries, oldest from 2026-05-28**, two of which exist *because
it already went wrong* —

```
RESCUE-2026-08-21-foreign-stash-accidentally-popped-into-wt-close-cohorts
                                    (icmp_embed/nat64/wg WIP, NOT mine)
RESCUE-2026-06-17-displaced-1635wip-from-errant-pop
```

Somebody popped someone else's work into their worktree, twice, and had to
stash the displacement to get it back. The recovery is itself on the shared
stack, where the next bare `pop` can take it.

- **Prefer not to stash at all.** `git worktree` gives you a second tree;
  `git merge origin/master` updates a stale base in place. Both avoid the
  stack entirely, and the stale-base problem that usually prompts a stash is
  better solved by the merge anyway.
- If you must stash: **push and pop immediately**, and **verify the restored
  files are yours** before doing anything else. The whole exposure is the gap
  between the two, so make it as close to zero as you can.
- **Never `git stash drop` or `git stash clear`.** Entries that look like
  abandoned debris are how stranded work looks from outside; several of those
  32 are plausibly real. Tidying the stack is the destructive move it already
  documents.


## First principles

1. **Latency is sacred.** Memory is cheap. Microseconds on the packet
   path are not. When two approaches trade bytes for branches, take the
   one that's branchless at the hot path.

2. **Correctness first, performance second, convenience last.**
   Defensive code that catches a class of bugs at build time beats tests
   that catch one instance. Favour `const _: () = assert!(...)` over
   `#[test]` pins for invariants that must not drift.

3. **One source of truth for every formula.** If two code paths compute
   the same denominator, they WILL drift. Centralise via a helper the
   first time you notice the duplication. The #704 bug was two gates
   computing "active flow count" differently.

4. **Honest framing always.** If live data doesn't support the PR's
   hypothesis, update the PR body. Don't bury it in a changelog. Don't
   hide behind "tests pass".

5. **Narrow scope.** Bug fix and behaviour choice do not ride in the
   same PR. If a reviewer flags a "maybe we should also" concern, file
   a tracking issue and cross-reference it. Don't silently expand
   scope.

6. **All code changes go through a PR.** No direct pushes to `master`
   for code — not for one-line fixes, not for hotfixes, not for revert
   commits. The PR flow is where reviewers catch what tests miss,
   where live data gets contrasted against the hypothesis, and where
   the commit message and PR body become the permanent record of why
   the change was made. Skipping it to "save time" is how regressions
   land. Docs-only maintenance skills that explicitly direct-push
   (e.g. `/sync-history`) are the only exception and must be declared
   in their `SKILL.md`.

## Workflow for every change

Every non-trivial change follows this ordering. It's the target going
forward — recent PRs have been close but not uniform, and the point of
writing it down is so the next agent can cite "step N" without having
to re-derive the pattern. Cross-references point to sections that carry
the mechanics, so this section is sequencing only.

1. **Issue first.** File a GitHub issue (or pick up an existing one)
   before writing code. Body: problem, hypothesis, acceptance criteria.
   The PR later references it by number in the title.

2. **Plan.** Read the existing code, then write a short plan under
   `docs/pr/<N>-<name>/plan.md` (the `<N>-<name>` prefix follows the
   existing convention documented in `docs/pr/README.md`) or the
   plan-mode scratch file: goal, approach, alternatives rejected, files
   touched, test strategy. No code yet.

3. **Hostile plan review with Codex (`gpt-5.5`).** Spawn via the
   `codex-rescue` agent; brief it to *critique*, not validate.
   **Terminal artifact:** Codex returns `PLAN YES` (or equivalent) AND
   every raised concern has a written disposition in the plan doc
   (applied, or rejected with reason). If Codex pushes back twice on
   the same point, assume it's right until you can show otherwise —
   "Codex stopped objecting" is not agreement. If you and Codex are
   stuck, stop and ask the user.

4. **Hostile architecture review** — same agent, same terminal rule —
   when the change touches a boundary: new BPF map, new protocol
   field, new syscall, cross-dataplane coordination, config/CLI
   surface. Skip this step for pure-local changes.

5. **Code.** Edit existing files; keep the diff scoped to the plan.
   Follow "Hot-path coding discipline" and "API shape discipline"
   below. Scope creep → separate issue + separate PR.

6. **Unit tests that reproduce the failure mode** — see the "Test
   strength" bullet under "Review discipline" below for what counts as
   a strong test.

7. **Hostile code review with Codex.** Same terminal rule: Codex
   returns `MERGE YES` (or equivalent) AND every finding has a written
   disposition. Fixes go into the same branch before push.

8. **Deploy + feature validation.** Unit tests pass ≠ firewall works.
   Run at minimum:

   | What changed | Deploy | Validation | Pass criteria |
   |---|---|---|---|
   | Any change | `make test-deploy` (standalone) | ping between zones | 0% loss |
   | Any change | `make cluster-deploy` (loss userspace cluster) + re-apply CoS (`./test/incus/apply-cos-config.sh loss:xpf-userspace-fw0` — deploy wipes CoS) | `iperf3 -P 16 -t 30 -p 5211` → 172.16.80.200 | ≥ 23 Gbit/s, no regression vs previous run |
   | Admission / DSCP / scheduler / queueing | above + re-apply CoS (`./test/incus/apply-cos-config.sh <target>`) | `show class-of-service interface` | targeted counter (`flow_share`, `buffer`, `ecn_marked`) moves in the predicted direction — see [`cos-validation-notes.md`](cos-validation-notes.md) |
   | NAT / screens / filter / VLAN / IPsec | above | exercise that feature end-to-end from a test host | session / hit counters advance; negative case drops |
   | HA / VRRP / session sync / fabric | `make cluster-deploy` | `make test-failover` + `make test-ha-crash` | 0 / very low packet loss across failover/failback, both nodes converge |

   **Which HA smoke is required, and which are compared against a baseline
   (#9728).**
   - `make test-failover` and `make test-ha-crash` are required for every HA,
     VRRP, session-sync or fabric change. They are the gates `harness-compare`
     judges against a band, so each must keep at least three green
     both-node-attested rows (`exe_scope`) at the loss userspace env
     (`docs/harness-ledger.md`).
   - Every other destructive HA smoke target (`test-double-failover`,
     `test-stress-failover`, `test-chained-crash`, `test-active-active`,
     `test-private-rg`, `test-restart-connectivity`, and any later HA
     acceptance gate) is required only when a change targets the behaviour that
     smoke exists for:
     - back-to-back or chained failovers;
     - repeated rapid moves;
     - split per-RG ownership;
     - private-RG election;
     - daemon restart in HA mode;
     - a specific synced feature.

     Each still records a ledger row when run, but none is baseline-compared by
     default. A NO-BASELINE verdict for them is expected, not a gap, until a
     change makes one routine.

   **Use 5211, not 5203, for the throughput row — and the two are not
   interchangeable (#7610).** The same row tells you to apply
   `test/incus/cos-iperf-config.set` first, and in that fixture the port IS the
   class: `bandwidth-output` term 3 maps **5203 → `iperf-3g` → `scheduler-3g`,
   `transmit-rate 3.0g exact`**, while term 11 maps **5211 → `iperf-uncapped`**.
   Measured back-to-back on a healthy fw0: **5203 → 2.86 Gbit/s, 5211 → 23.1
   Gbit/s**. This row asked for 5203 against a ≥ 23 Gbit/s bar until #7610, so a
   lane following it literally read a *correctly working shaper* as an 8x
   throughput regression — and the criterion "no regression vs previous run" made
   that reading look confirmed, because every previous run of the same wrong port
   reported the same ~3 Gbit/s. Ports 5200-5211 each select a different
   forwarding class; check `cos-iperf-config.set` before substituting one.

   5203 is the right port when you are validating the **shaper** rather than the
   dataplane: there the pass criterion is ≈ 3 Gbit/s, and a result near 23 means
   the shaper is NOT engaging.

   **Every gate in this table now leaves a ledger row (#8302).** The nine
   cluster gates run through `test/incus/harness-result.sh`, which appends one
   JSON row per run to the tracked `test/results/ledger.d/`: verdict as a
   STRING (`PASS` / `FAIL` / **`VOID`**), the headline metric, and the sha256 of
   the binary that was actually RUNNING on the node. Two things follow for you
   as an author:

   * **`make test-failover` still exits exactly as it did.** The row's verdict
     and the gate's exit status are separate; an unattributable run records a
     VOID row and does not red the gate. The one change is in the safe
     direction — a gate that exits 0 without reaching its summary now exits 2,
     a state that used to be indistinguishable from a clean run.
   * **"no regression vs previous run" has an instrument now.** Run
     `make harness-compare GATE=test-failover` instead of eyeballing the last
     number. It bands the last K ≥ 3 green runs at the same env and answers
     `WITHIN-BAND` / `REGRESSION` / `IMPROVED` / `NO-BASELINE` / `VOID`.
     `NO-BASELINE` is **not** a pass — it means the ledger has no grounds to
     judge the run yet. See [`harness-ledger.md`](harness-ledger.md).

   **`-P 16` is canonical, not illustrative — dropping it costs 4.4x.** The
   invocation in the row IS the method; a figure reported without it is an
   anecdote, not a measurement. Measured on a healthy fw0 with CoS applied,
   minutes apart, on the SAME port 5211: **`-P 16 -t 30` → 23.1 Gbit/s,
   single-stream → 5.23 Gbit/s.** So a lane that improvises
   `iperf3 -c 172.16.80.200 -p 5211` reads 5.23 against a ≥ 23 bar and owns a
   4.4x "regression" created entirely by its own invocation. #7480 did exactly
   that, then spent a lock cell and two hypotheses on the gap — auditing
   `cos-iperf-config.set`, `scheduler-uncapped` and `afxdp/cos/admission.rs`,
   and concluding from single-stream numbers both that CoS state made figures
   incomparable and that a 24g class "delivers 6.11" — before reading this row.
   Both conclusions were retracted. **A number that disagrees with a documented
   threshold is evidence about the INSTRUMENT before it is evidence about the
   system**, and a mechanism hunt feels like rigour while being structurally
   unable to detect a wrong invocation.

   Omitting `-p` entirely is worse than substituting a port. iperf3's default is
   **5201 → `iperf-100m` → `transmit-rate 100m exact`**, so a bare
   `iperf3 -c 172.16.80.200` silently measures a 100 Mbit shaper (~96 Mbit/s
   observed) instead of the dataplane.

   When a validation lane can't be run in the test env, say so
   explicitly in the PR body with the reason. Never claim success for
   a check that wasn't executed.

   **A green smoke owes a WITNESS that your change ran (#8280, #8290).**
   A passing cluster run tells you the build is not broken. It does not
   tell you the run reached your code, and the two are indistinguishable
   in the output. #8280 passed **17/17 while never executing the change
   it was owed for** — the cluster carries no pool-mode source-NAT rule,
   so that run would have looked identical had the change been correct,
   broken, or reverted. It could only be established afterwards, by
   reading the cluster config.

   Establish it FORWARD instead, with a counter:

   1. Find a counter whose **only** increment site is downstream of your
      change. Verify "only" by grep, with a positive control — search a
      counter you know has several bump sites in the same command, so a
      wrong pattern shows up as the control coming back empty rather
      than as your counter looking unique.
   2. Prefer one sitting behind a **short-circuit** your change
      participates in. `&&` evaluates left to right, so a bump is a
      proof that every clause to its left evaluated true — that is a
      statement about which branch ran, not merely that the process
      stayed alive.
   3. Snapshot `/metrics` on both nodes before and after the run and
      diff it. Report the delta, per node.

   Worked example (#8290, taking `sync_session`'s worker-set read off an
   owned map). `xpf_userspace_synced_import_reserve_refused_total` has
   exactly one `fetch_add`, inside:

   ```rust
   if entry.origin.is_peer_synced()
       && !entry.metadata.is_reverse
       && !worker_records.is_empty()          // <-- the changed read
       && !self.reserve_synced_translation(&entry)
   ```

   It moved 2 -> 12 on fw0 and 0 -> 2 on fw1, so twelve times the changed
   line ran and evaluated non-empty. That is a witness; "17 passed" is
   not.

   **Then say what the run did NOT reach**, in the same breath and with
   the same specificity. In the same #8290 run the cap's refusal branch
   never fired (`synced_import_cap_drops_total` stayed 0), so a wrong cap
   *magnitude* would have looked identical; and the property the change
   existed for — several worker-set decisions sourced from one snapshot —
   is **inert** while dispatch is single-threaded, so the green was
   identical for the change and for its absence. An unexercised dimension
   that goes unmentioned is read as covered, which is how a smoke's
   verdict annexes dimensions it never measured.

   A counter that stays flat is not a failure of the technique; it is the
   answer, and it belongs in the PR body next to the ones that moved.

9. **PR open + Copilot review + Codex re-review + merge** — see
   "PR discipline" and "Merging" below for the body template and
   mechanics. Two distinct review surfaces:

   - **GitHub Copilot** auto-posts an inline review on every push to
     a PR (~30s after `git push`). It catches a different class of
     issues than Codex: stale comments, unwired fields, accidentally-
     ignored errors, missing tests. **Always fetch and triage Copilot
     comments before requesting human review** — pretend they're
     from a thoughtful but pedantic colleague. Real ones get fixed
     in the same branch; non-issues get a short reply explaining
     why.

     Standard fetch:
     ```
     gh api repos/<owner>/<repo>/pulls/<N>/comments | \
       jq -r '.[] | select(.user.login | startswith("copilot")) |
              "\(.path):\(.line // .original_line) — \(.body)"'
     ```

   - **Codex hostile code review** runs separately via the
     `codex-rescue` agent. Same terminal rule as the plan review:
     Codex returns `MERGE YES` AND every finding has a written
     disposition. Codex sees the diff with eyes that have not seen
     Copilot's findings — keep the two reviews independent so they
     can disagree productively.

   Iterate until BOTH reviewers are clean (or have explicit-with-
   reason dispositions), then merge once the findings are resolved AND
   the gates below are green. If the diff grows in response to review,
   push and request a re-review — both Copilot and Codex re-fire on the
   new HEAD.

   **"Once CI is green" used to stand here, and there is no CI (#9052
   item 3).** `.github/` contains only `instructions/`; the Makefile says
   so twice in as many words — *"There is no CI in this repo, so this is a
   developer convenience, not an automated gate: nothing runs it unless
   invoked"*. So the written merge criterion was **vacuously satisfiable**:
   a PR could satisfy the procedure with `make test` alone, and every gate
   below is developer-invoked and chained from no default target. Naming
   the gates is the fix; a criterion that cannot be unsatisfied is not a
   criterion.

   Run what your diff touches, not all of them every time:

   | Gate | Run it when |
   |---|---|
   | `make test` | always — Go **and** Rust; a Rust regression fails it |
   | `go test ./...` | a `pkg/config` type change, or a NEW commit-time rejection: both have repo-wide blast radius, and a package list cannot see it |
   | `make selftest` | image / day-0 / dist / deploy tooling |
   | `make harness-census` | adding or moving anything under `test/incus/` or `scripts/userspace-*.sh` |
   | `make ignored-cell-census` | adding or changing a Rust `#[ignore]` |
   | `make go-skip-census` | adding or changing a Go `t.Skip` |
   | `sudo make test-root` | touching the XDP shim — its behavioural cells SKIP unprivileged, and the #1864 verifier gate does not substitute (two distinct WRONG fixes pass it) |
   | `make test-failover` | cluster, VRRP, session-sync or failover code — **mandatory**, self-locked, shared cluster |

   The last two are the ones that get skipped, and they are the two whose
   subjects nothing else examines.

## Hot-path coding discipline

### Allocations

- **Never allocate per packet.** `Vec::push` that may grow, `VecDeque`
  that returns from a function, `Box::new` inside a `while let Some`
  loop — all land on the allocator.
- **Drain into caller-provided buffers.** Prefer
  `drain_into(&mut out: VecDeque<T>)` over `drain() -> VecDeque<T>`.
  Caller reuses its buffer across polls.
- **Pre-size everything.** `VecDeque::with_capacity(expected)` at
  construction. Fixed-cap rings (`[T; N]`) where the upper bound is
  known statically.
- **Drop policy on full: drop-newest.** Dropping the head of a queue
  evicts a packet that was already close to being serviced and
  extends tail latency. Dropping the incoming packet loses a packet
  that has travelled zero further than the sender. Prefer drop-newest
  unless there's a specific reason otherwise, and document the
  rationale at the drop site.

### Atomics

- **Pick orderings deliberately.** `Relaxed` for counters. `Acquire` /
  `Release` for publish/subscribe slot patterns. `AcqRel` only when
  both sides of a CAS need ordering. If you're reaching for
  `SeqCst` — stop and re-read the algorithm.
- **No `Mutex<VecDeque>` on the hot path.** Use lock-free primitives
  (Vyukov bounded MPMC, SPSC ring, or hand-rolled MPSC). If a mutex
  is unavoidable, isolate it to a slow path.
- **Cache-pad cross-core atomics.** Producer CAS on `head` + consumer
  store on `tail` share a cache line → every op invalidates the
  other core. Split into `#[repr(align(64))] CachePadded<T>` for
  primitives whose job is cross-core coordination.

### Branches

- **Prefer branchless arithmetic.** `saturating_add`,
  `saturating_mul`, `.max()`, `.min()`, `.clamp()`, and
  `bool as u64` conversions generate predictable code.
- **Make hot-path branches predictable.** Config-time booleans
  (`flow_fair`, `exact`) that don't change at runtime give the
  branch predictor a free win. Lift them to early returns at the
  top of hot functions.
- **Don't early-return on rare errors; account for them.** Error
  paths should bump a counter and continue, not unwind. TCP doesn't
  stop because one packet didn't fit; the scheduler shouldn't
  either.

### Compile-time guards

- `const _: () = assert!(condition)` at module level is free. Use
  it for structural invariants: power-of-two sizes, fast-retransmit
  floors, maximum values that fit in a narrower type.
- A `#[test]` that asserts `CONST >= N` runs only on `cargo test`.
  A `const _: () = assert!` runs on every `cargo build`. Prefer
  the latter for values that must not drift.
- **Prefer a compile-time guard — but measure before assuming one
  exists.** A guard that cannot catch the bugs that motivated it is
  decoration, and a lint whose false positives get suppressed is worse
  than no lint: a suppressed lint reads as a checked property. Before
  proposing a `go vet` / `analysistest` rule for a recurring defect,
  pull two or three of the real historical instances out of git history
  and check the rule reds on them. A rule keyed to the vocabulary a FIX
  introduced is structurally blind to the pre-fix code — it tests the
  repair, not the property. `docs/applied-marker-invariant.md` is the
  worked example: the applied/published/converged marker rule proposed
  in #6533 missed 3 of 3 sampled historical defects and flagged the
  correct mechanisms, including its own flagship target, because
  correct markers are correct via caller contracts and readbacks that
  no intra-function dominance rule can see.

## API shape discipline

- **Signatures encode contracts.** If a function must not reallocate,
  take `&mut VecDeque<T>` not `-> VecDeque<T>`. If a function expects
  the consumer to hold the "SC" half of an MPSC invariant, mark it
  `unsafe` and document the invariant at the call site.
- **Helpers over duplication, always.** The moment you write the same
  formula in two places, even if they look right today, extract it.
  This is a future-correctness guarantee, not a style choice.
- **Operator-visible units match operator config.** Tests that exercise
  admission boundaries use the same units the operator types. If the
  operator writes `buffer-size 125k` and that parses to 125000 bytes,
  the fixture is `buffer_bytes: 125_000`, not `125 * 1024`. Don't mix
  KB and KiB.

## Modularity discipline

Monolithic files and god functions silently degrade reviewability and
inlining. Treat the trend as a defect, not a style preference.

- **No monolithic files.** A `.rs` file that crosses ~2,000 LOC of
  production code (excluding `mod tests`) is a smell. By the time it
  hits ~3,000 LOC the next change to that file should split it before
  adding new logic. Apply the same rule to test files: when a single
  `mod tests` block accumulates >200 tests across unrelated subjects,
  colocate the tests next to the code they exercise (per-file `mod
  tests` blocks are the project pattern; see the `tx/` and `cos/`
  layouts for examples).
- **No god functions.** A function with >100 lines or >8 parameters
  is a refactor cue. Pull subsystems into their own helpers (state
  machine → enum + dispatch fn, repeated parameter cluster → context
  struct). The standing cautionary example is
  `poll_binding_process_descriptor` in `afxdp.rs`: #945 brought it
  down from 31 parameters to 15, but the body is still long and the
  parameter cluster is still a refactor smell — tracked as #961.
- **One responsibility per module.** A module that mixes admission
  policy with byte-mutation, or memory mapping with ring management,
  will get sliced apart eventually — do it on the way in. The
  `userspace-dp/src/afxdp/` decomposition (`tx/`, `cos/`, the planned
  `umem/` and `frame/` splits in #986/#988) is the working template.
- **Refactor with new features, not after.** When a feature would
  add ~200+ LOC to a module that's already approaching the threshold
  above, the PR splits the module first, lands the feature on the
  smaller pieces. "I'll clean it up next sprint" doesn't survive
  contact with the next on-call rotation.
- **Reviewers escalate monolith creep.** A PR that adds a new
  helper to a 2,500-line file gets a Medium+ review note pointing
  to the relevant tracking issue (or asking the author to open
  one). Don't let "but the surrounding code is already like that"
  land.
- **The gate reds the author of the growth, not the next merger**
  (#7253). `pkg/refactoraudit`'s
  `TestTouchedFileCrossedModularityThreshold` fails when a file **your
  branch touches** crosses 1500 or 2000 LOC, measured from your own diff
  against the merge base — so an unrelated file growing elsewhere can
  never red you, and regenerating `docs/refactoring-audit-current.txt`
  can never silence you. Split the file, or record the decision and its
  reason in `docs/refactoring-audit-accepted.txt`. Keeping the global
  heatmap current is `make audit-refresh`'s job; its lag fails nothing.
  See `docs/refactoring-audit.md` "The two gates".

## Overflow / failure policy

| Scenario | Policy |
|---|---|
| Bounded queue, producer push on full | Return `Err(T)` so the caller can decide. In the admission-path wrapper, drop-newest + bump overflow counter. |
| Bounded queue, consumer drain | Never fails. Loop until `pop()` returns `None`. |
| Invariant violation at config time | `panic!` with context. Not recoverable; crash-start is safer than running with a wrong invariant. |
| Invariant violation at runtime (rare, driver bug) | Bump a dedicated counter, continue. Crashing the dataplane on a single misbehaved packet punishes every other flow. |
| "Path not found" at config apply | Warn + continue if the path is a best-effort cleanup; fail hard if the path is load-bearing. Don't let `|| true` mask the load-bearing case. |

## A fail-closed exclusion owes a show-surface annotation (#6534)

When you make the snapshot builder DROP or DISARM a config object to fail
closed, you have created a second, quieter bug: the operator's `show`
output still renders that object from config, so the box now reports as
enforced something it is deliberately not enforcing. #6534 found this had
happened at ~21 sites, because each individual fail-closed fix was
reviewed on its own and every one of them looked complete.

The rule: a PR that adds an exclusion must also make the surface tell the
truth, in the same PR. Concretely:

1. Put the drop predicate in `pkg/config` as an exported
   `...ExcludedReason(...) string` (or `...Unsupported(...) bool`), not
   inline in the builder. `nat_exclusion_reason.go` and `nptv6_scope.go`
   are the worked examples.
2. Have BOTH the builder and the renderer call it. Two copies drift, and
   they drift in two directions that fail differently: a builder that
   drops what the renderer calls armed lies to the operator, and a
   renderer that annotates what the builder installs cries wolf.
3. Surface the REASON, not just the fact. "NOT INSTALLED" alone makes the
   operator guess which of five conditions fired.
4. Bind the two halves with an AGREEMENT test that names WHICH site
   diverged, and pin each fixture to ground truth first so a fixture that
   stops constructing the malformed shape fails loudly instead of passing
   vacuously (`TestNATExclusionBuilderRendererAgree_6534`).

What NOT to reach for: an applied-set readback from the helper. These
exclusions are decided by the Go builder at snapshot-build time as a
deterministic function of the committed config — the dataplane does not
decide anything at runtime, it honors a verdict already reached. There is
no runtime fact to read back, and `AppliedNATView` hands back the applied
CONFIG, not the applied SNAPSHOT, so it does not carry the drop bit
anyway. What the renderer is missing is the predicate, not a data path.

Reachability, so severity is judged correctly — and it is NOT uniform
across families, so measure it rather than assuming:

- **Lenient-path backstop.** The NAT families and the firewall-filter
  `then dscp` rewrite (#7422) are here. The strict commit gate rejects
  the config outright, so the lying-show state is reachable only via
  `Store.Load` at boot or `Store.SyncApply` on HA peer-sync
  (`opts.lenientFirewallRefs`, #1960 no-brick) — which is exactly when an
  operator is reading `show` output to work out why traffic is not
  flowing.
- **Reachable through an ORDINARY commit.** A port-mirroring instance
  with no `output interface` (#7354), a CoS entry naming an undefined
  forwarding-class (#7348, a commit WARNING only) and a `flow-server`
  with no `port` (#7422) all commit cleanly, because no strict gate
  covers them. These are the severe ones: the operator did nothing
  unusual and the show surface lied anyway.

Do not write "every one of these is a lenient-path backstop" into a
fixture comment without checking. A `Commit()`-based fixture for a
lenient-only family passes only because the commit gate rejected the
input and the test then asserted over an empty set; a lenient-path
fixture for a commit-reachable family tests a harder route than the one
operators take. `pkg/showaudit`'s registry rows record which is which.

## Persistence classes (#1894)

Every file write that replaces on-disk state belongs to exactly one
class, and the class picks the writer. `pkg/fsatomic` is the single
source of truth; an AST canary in that package (`TestNoDirectOsWriteFile`)
walks EVERY production `.go` file under `pkg/` (#1916, repo-wide — not a
package allowlist) and fails the suite when a direct `os.WriteFile` lands
in a function that is not on the receiver-aware allowlist.

**The first three classes are all defined over REPLACE-A-FILE writes.** A
fourth operation exists and had no row here until #9057, which is why four
sites got it wrong the same way — see `DurableNamespace` below.

| Class | Writer | Meaning | Examples |
|---|---|---|---|
| DurableState | `fsatomic.WriteFileDurable` | Must survive power loss: temp + fsync + rename + parent-dir fsync. | active config (`.configdb`), rollback slot 1, rescue config, `master.key`, DHCPv6 DUID, `frr.conf`, `/etc/hostname`, sudoers drop-in, user + root `authorized_keys`, TLS cert + key (`/etc/xpf/tls/*`), lifeline record, provisioned-users / -passwords / -keys markers (#5841) |
| AtomicGeneratedConfig | `fsatomic.WriteFileAtomic` | Regenerated on boot/apply; a torn file is unacceptable, a lost-on-power-cut update is fine. **No fsync — this class exists so hot apply paths never pay one.** | swanctl conf, Kea configs, networkd `.link`/`.network`, rollback slots 2..N, sshd drop-in, rsyslog drop-in, chrony drop-in, `ssh_known_hosts`, `/etc/timezone`, `/etc/resolv.conf` |
| BestEffortKernelKnob | direct `os.WriteFile` | procfs/sysfs: rename does not exist there, the atomic writers are impossible by construction. Also the `/etc/resolv.conf` bind-mount in-place fallback (rename onto a bind mount is EXDEV/EBUSY). | `rp_filter`, `accept_dad`/`addr_gen_mode`, RPS/RFS/XPS, `fib_multipath_hash_policy`, socket-buffer sysctls |
| **DurableNamespace** (#9057) | `fsatomic.RenameDurable`, or the renames followed by ONE `fsatomic.SyncDir` | The durable artifact is the DIRECTORY ENTRY, not a file's contents: rotating a generation set (`x` → `x.1` → `x.2`), or any rename whose new name must survive a power cut. A rename is atomic for the entry and the entry is **not durable until the containing directory is fsynced**. | audit-journal segment rotation, local-log and flow-trace rotation, CLI monitor trace rotation |

**Why DurableNamespace needed its own row rather than a note under
DurableState.** Four sites rotated generations without a directory fsync, and
they did not do it because four authors were careless — the operation had no
row in this table and no primitive in `pkg/fsatomic` to reach for, and the
canary that enforces the table only ever looked at `os.WriteFile`. That is what
a missing class looks like from below: not one bug repeated, but the same gap
found four times. **Two of the four were in no review report**; they were found
by sweeping the OPERATION rather than by reading the file a finding pointed at,
and one of them is a near-verbatim sibling of another that was hardened
*alongside* it for symlink safety and *apart* from it for durability.

`TestNoUnsyncedRename` (the #9057 sibling canary) enforces the row. It accepts a
bare `os.Rename` in a function that also reaches `fsatomic.SyncDir` or
`RenameDurable` — which is what a correct rotation looks like: N renames into
one directory, then ONE `SyncDir`. **Keying on the function's behaviour rather
than on a list of blessed paths** is deliberate: every `pkg/upgrade` staged
promotion already syncs in-function and therefore needs no allowlist entry at
all, so the list stays short and cannot rot as files move.

The honest consequence bound, because the class name sounds worse than it is:
the observable window is an **unclean shutdown only** (power cut / panic), and
what is lost is the newest seconds of lines plus possibly the generation
numbering. It is **not** corruption, and no file contents are destroyed.

Special cases:

- **TLS cert + key are DurableState** (#1916 D6): the HTTPS API can bind a
  non-loopback `system services web-management https interface` address, so
  cert churn after a power-cut loss would break remote clients' TOFU pins.
  The pair is written with the #1916 D5 STRICT sequence — strict-remove the
  stale pair (ignore only ENOENT; any other remove/SyncDir error ABORTS the
  write, so the `{neither}` start is proven) → key (0600) → cert (0644) — so
  a crash can never leave a MISMATCHED pair. A persistence failure logs and
  serves the in-memory cert (HTTPS still installs); only a true generation
  failure returns a non-nil error.
- **`authorized_keys` uses `fsatomic.WithOwner(uid, gid)`** (#1916 D7): a
  plain durable write replaces the inode with a root-owned temp, and a crash
  before a separate post-rename chown would leave root-owned `0600` keys that
  sshd refuses (EACCES → lockout). `WithOwner` fchowns the temp fd BEFORE the
  rename so the file is correctly owned atomically at install. The owner is
  resolved cgo-free from `/etc/passwd` (`lookupUIDGID` — never `os/user`).
- **`WithOwner` vs `WithPreserveExisting` precedence**: if both are set,
  owner = `WithOwner`'s, mode = preserved-existing's (explicit owner wins).
- **`ssh_known_hosts` WRITE is AtomicGeneratedConfig, but its REMOVAL
  fsyncs the parent dir** (#5112): the write is a no-fsync
  `WriteFileAtomic` because a lost-on-power-cut rewrite just re-renders the
  SAME trust next apply. Clearing `security ssh-known-hosts` REMOVES the
  xpf-owned file (`applySSHKnownHosts` → `removeManagedSSHKnownHosts`,
  ownership-guarded on the managed header so a foreign/hand-maintained file
  is never deleted), and that removal fsyncs the parent dir
  (`fsatomic.SyncDir`): a lost unlink is the DANGEROUS direction — it would
  resurrect a revoked, now-untrusted host key on reboot. Applied durable
  trust must not outlive desired trust.

Rules of thumb:

- fsync cost lands on operator-paced commit paths only (commit,
  rollback save, rescue save, DUID persist, frr.conf reload) — never on
  per-apply, per-packet, or per-poll-tick paths.
- Multi-file shuffles batch namespace durability with one trailing
  `fsatomic.SyncDir` (renames AND unlinks) instead of per-file dir
  fsyncs — see configstore `saveRollbackFiles`.
- Temp+rename WITHOUT fsync is namespace atomicity, not durability:
  after power loss the rename can surface a zero-length file or vanish.
  Do not hand-roll it; pick a class.
- A daemon that cannot persist config must not boot pretending
  otherwise: `configstore.New` is fail-closed (#1893) — there is no
  "file-only" fallback backend.

## Time in tests (#8218)

Four tests in four packages red full-suite gates under load, in diffs that
could not reach the code they failed in. They look like one defect and are
three, and the single rule "assert on work, not wall-clock" — which is how this
was first written down — is correct for two of them and would damage the other
two. Sort the test into a clause before applying it.

**1. A pass criterion must never be a duration, or a ratio of durations.**
Measure work: allocations, operations, syscalls, bytes. A count cannot be moved
by machine load; a duration can, and a ratio of two durations can too, because
the readings are taken at different moments and a scheduling hiccup landing on
one of them moves the ratio and nothing else does.

`TestGetBulkCostDoesNotScaleWithMaxRepetitions_6551` (#8211) carried exactly
the wrong rationale in its own comment — *"a ratio between two measurements of
the same magnitude on the same machine, so machine load cancels out"* — and
that sentence is why nobody looked at it. Ported to `testing.AllocsPerRun`,
against its v3 twin which had always done it right, it reads 1.0x bounded and
51.8x with the bound removed: the same threshold, now deterministic. When you
port one of these, rewrite the rationale too. A false explanation of why a
measurement is safe outlives the measurement.

**2. A degeneracy guard must FAIL, not skip, when the state under test did not
occur — and it should OBSERVE that state, not infer it from timing.** A skip is
indistinguishable from a pass in every summary line and CI badge, so the guard
stops running and nothing says so. The failure mode is perverse: the faster the
machine, the likelier the vacuous pass.

And before giving a degenerate state a verdict, check whether the FIXTURE
caused it. `TestDetachXDPIsNotSelfSerializing7547` reported "this cell measured
nothing" under load, and the cause was its own non-yielding busy-wait starving
the second goroutine — `GOMAXPROCS=1` reproduced it 30/30, adding
`runtime.Gosched()` removed it 0/30 and made the overlap structural rather than
lucky. A cell that waits without yielding, sleeps for an interleaving, or races
for a window is manufacturing its own degeneracy, and a new verdict class for
it would have kept the flake and made it quieter. Reach for one only where the
interleaving genuinely cannot be forced.

**3. A deadline that bounds a WAIT is legitimate, and clause 1 does not reach
it.** The duration is not the pass criterion — the assertion is already
work-based — and the deadline exists so that a broken build fails instead of
hanging. Applied literally here, clause 1 says delete it, which converts a
flake into a hang: a hang prints nothing, has no `--- FAIL` line, and destroys
every later test by eating the budget. Size it for the LOADED case and leave
it.

This is the same rule as *"A liveness backstop is not a timing assertion, and a
red there is never fixed by raising it"* under Project-specific reminders,
approached from the other end, and the two only appear to disagree. That bullet
governs a backstop already sized orders of magnitude above the healthy path: if
one of those reds, something is genuinely wedged and raising it hides a real
defect. This clause governs a backstop that was never sized to that rule at all
— `SetReadDeadline(2s)` (#8182), `time.After(3s)` (#8031) — where the fix is to
bring it into compliance. Raising 3s to 60s is not "raising a bound to make a
red go away"; it is sizing a backstop that was never a backstop.

**Where this came from, and what is still open.** #8211 is fixed. #8207
(`pkg/cluster` heartbeat probe) is clause 2 and #8182 / #8031 are clause 3;
all three remain open. The rule is documented here rather than left in the
tracker because a policy that lives only in an issue is not read before the
next test is written, which is how this reached four packages.

**4. SLEEP-THEN-ASSERT is clause 1 wearing clause 3's clothes, and it is the
one that keeps getting written (#9110).** The shape is

```go
time.Sleep(2 * SomeInterval)   // "let the goroutine get going"
if counter.Load() == 0 { t.Error("it never ran") }
```

There is no deadline here and nothing is being waited FOR. The sleep is a
*guess* at how long the scheduler will take, and the assertion silently becomes
"the goroutine was scheduled AND made progress inside my guess" — a claim about
the machine, wearing the words of a claim about the code. Under `go test ./...`
on an oversubscribed box it reds a test whose subject is perfectly healthy.

Convert it to clause 3: **wait for the condition, with a budget sized for the
LOADED case, and dump the goroutines when the budget expires.**
`waitForTeardownProgress` (#7970, `pkg/cluster`) is the reference implementation
and its comment carries the reason the dump is not optional — this wait cannot
tell a STARVED goroutine from a BLOCKED one, and those have completely
different fixes, but the stack can tell them apart immediately.

**A flaky red is worse than no test.** At the moment you must decide whether to
merge, a flaky red and a real red are the same output, and the correct response
to each is the opposite of the other. That is what trains people to explain reds
away — and then a real red gets explained away too.

### Before you call a red a flake, DIFF — do not re-run (#9110)

A cell that passes alone and fails in the suite differs by something specific,
and it is almost never luck. Look for these first, in this order:

1. **The rest of its package ran first.** This is the difference "run it alone"
   deletes, so an isolation re-run cannot see it. Reproduce with the whole
   package binary, in its normal order — and run it from the package directory,
   because a prebuilt test binary invoked from elsewhere fails every
   source-scanning cell for a reason that has nothing to do with the defect.
2. **A shared resource.** A package-level `var` a test mutates and restores,
   `/tmp`, `/dev/shm`, the cluster lock, the stash.
3. **An unsound match.** A cell scanning for a byte value or a substring that
   randomised data can legitimately contain reds at a rate nobody can explain
   and everybody calls flake.
4. **The tree changed under the gate.** A background `go test ./...` plus a
   `git checkout` in the SAME worktree measures a tree that no longer exists.
   Gate in a dedicated worktree with nothing else running; this turned two
   unexplainable reds into clean passes in one session.

And the failure this rule exists to prevent, which is not flakiness at all:
**a red in a package your diff never touched can simply be REAL.** The #9110
investigation found `TestTreeIsGofmtClean` redding on `origin/master` for every
lane, from an un-gofmt'd file in an unrelated package — the most flake-shaped
red imaginable, and entirely genuine. Confirm the tree, not the vibe:
`git show origin/master:<path> | gofmt -l` answers it in one command.

**What a non-reproduction is worth.** The two #9110 tests were run ~100 times
each across three load shapes — 3x CPU oversubscription; concurrent with a full
repo-wide `go test ./...`; and the whole package in order under load — with
zero failures. That does not clear them, and it is not a licence to close the
issue: the rate may simply be below 1-in-100. It does mean "timing-sensitive"
stays an unconfirmed hypothesis rather than becoming an inherited fact, and
that a fix must be justified by reading the test, not by the premise.

## Ports in tests (#9549)

A unit test that binds a FIXED port goes red whenever a second copy of the suite
runs on the same host, and a mutation matrix runs two copies by design. The
panic names a bind, so it reads like a product defect. #9549 found thirteen
such cells in the `userspace-dp` WireGuard control-thread tests. It then
reproduced the failure on demand, on those cells alone:

- With an external process holding their ports, 4 of the 13 cells failed.
- With 8 concurrent copies run 5 times, 36 of the 40 copies had a failure.

The other 9 cells stayed green while their listener could not bind. That is the
worse outcome, because they silently stopped exercising a bound listener.

Before #9549 landed, an unrelated change (#9592) merged two more WireGuard cells
with fixed ports. That is why this is a written rule rather than a one-time
cleanup. All fifteen cells now take their ports from `crate::test_ports`.

**Take every port a `userspace-dp` test binds from `crate::test_ports`**
(`userspace-dp/src/test_ports.rs`):

- `hold_ephemeral_udp_port()` when the test needs the port HELD, as a blocker
  that makes the code under test fail its own bind.
- `reserve_ephemeral_udp_port()` when the code under test binds the port itself.
  The port is released before the call returns, and the same port is never
  handed out twice in one process, so parallel tests cannot collide. One risk
  remains: another process can take a released port in the milliseconds before
  the code under test binds it. That is far rarer than a fixed port, but not
  zero.

A literal port in a snapshot field or an endpoint string is fine as long as
nothing binds it; the rule is about binds. In Go the same remedy applies:
listen on port 0 and read the assigned port back from the listener.

This is the same class as "Time in tests" above with a different shared
resource. Both turn another lane's activity on the machine into this lane's red.

## Verification discipline (#8348)

Two rules earned by a defect that stayed invisible for four months while every
health signal stayed green.

### A check you had to manufacture to pass is measuring your setup, not the system

`.git/config` carried `merge.union.driver = true` — a custom driver **named** after
git's built-in `union` whose command is the shell no-op `true`. A custom driver
**shadows** the built-in, so every `merge=union` path resolved to *ours* and silently
discarded the other side. Exit 0, no conflict, nothing in the merge summary. Rows were
lost from `test/results/ledger.jsonl`.

The provenance is the lesson. `docs/issues/pr-history.md:26283` is the verification
checklist of PR **#1582** — a `merge=union` attempt **closed/rejected** in May 2026:

```
- [x] `git config --get-all merge.union.driver` returns `cat %A %B > %A` (built-in)
```

Git's built-in union has **no** `.driver` config key, so a healthy repo returns
nothing. **The check could only pass if someone set the key — passing the verification
required manufacturing the defect.** That is not a weak check; it is an inverted one.
The PR was rejected; the config residue outlived it by four months.

**The test:** *would this step pass on a fresh clone with nothing done to it?* If the
honest answer is no, the check is describing your workspace. A verification step that
fails on a clean machine and passes only after you have configured something has
verified your own edit and nothing else.

Corollaries:

- **Never name a custom merge driver after a built-in.** It silently redefines an
  attribute the rest of the repo documents and relies on. Use a distinct name.
- **A detector's docstring is a claim about what it can see.** `ledger_compare.py`'s
  lint claimed to be "what catches that reasoning being wrong rather than trusting
  it". It keys on a repeated `run_id` with a *differing payload* — corruption — and a
  silently **dropped** row is well-formed and lint-clean by construction. An
  overstated docstring is worse than none: it stops the next person looking.

### Tell a peer what baseline to expect, so their green becomes falsifiable

A `make test-failover` run reported `20 passed, 0 failed`. The branch predated
`ff6551d88`, so it ran the **older cell set** — which coincidentally also totals 20.
Same number, different tests. Nothing in the output distinguished them.

It was caught only because a peer had said in advance: *expect two `KNOWN` gap lines.*
None appeared, and that got checked rather than shrugged at.

**A summary line is not a result — it is a count of whatever ran.** "N passed" is
silent about *which* N. So a brief that names the expected signal converts an
unfalsifiable summary into a checkable one, and that is a property of the **dispatch**,
not of the recipient's diligence:

- name the specific lines, markers or counts a correct run produces;
- say what their **absence** means (usually: the wrong thing ran — not that it passed);
- prefer a signal that is **structurally** different between right and wrong, not a
  total. A count is exactly what collided here.

## Crafted-frame probes need an arrival witness (#8336)

Any measurement that sends a crafted frame at the cluster and reads a counter
has a **third outcome** beside "it was dropped" and "it was not", and collapsing
it into either produces a false finding. Two attempts at reproducing #8298 did
exactly that.

**A flat counter has two indistinguishable causes.** The frame never reached
the firewall — routing, L2, the host stack, or the NIC discarding a malformed
header before AF_XDP ever sees it — or it arrived and was not dropped, which is
the actual result you were testing for. Only the second is a finding.

So pair the subject with a **witness**: a companion frame crafted to trip a
different, per-reason check, sent alongside it. The witness counter moving is
what proves the path is live. A flat witness means **the measurement did not
happen** — `VOID`, never a pass — and the check must be made *before* the
subject is read, or a frame that never arrived reports as one that was
permitted.

Three specific traps, all of which cost a real attempt:

- **The standard smoke exercises no screen code at all.** `stage_screen_check`
  is gated on `has_screen_state()`, and the loss userspace cluster carries no
  `security screen` configuration. A `cluster-deploy` plus `test-failover`
  against a screen change is green for reasons unrelated to the change. Arm a
  profile first, and disarm after — the cluster is shared, config syncs to the
  peer, so verify removal on **both** nodes.
- **The per-reason counter cannot see a parse-error drop.**
  `extract_screen_info` failing closed yields reason `ip-malformed`, and that
  reason — with `syn-cookie` and `icmp-fragment` — is surfaced *only* through
  the aggregate `xpf_screen_drops_total`. There is no label to sample in
  `xpf_screen_drops_by_reason_total`, so a fail-closed drop is invisible there
  by construction and the zero reads exactly like "nothing happened". Sample
  the aggregate for anything that may drop on a malformed header.
- **"Did not move" and "could not be read" are different.** An absent metric, a
  failed scrape and a helper restart mid-probe all render as "no number", and
  treating any of them as zero turns a broken instrument into a clean result.

`test/incus/screen-probe.sh` is the procedure; `screen-probe-lib.sh` is the
verdict, hermetically tested by `make test-screen-probe-lib` so the ordering
above is asserted rather than remembered.

### A guard that MODELS a predicate instead of CALLING it fails silently

When a guard needs to know what production computes — which argument a pass is
handed, which key a lookup uses — **call the production code and observe, or
instrument the call site and measure. Do not reconstruct it.**

This is not a style preference. Two lanes independently wrote guards over the same
normalizer predicate, each reconstructing the argument rather than calling the
pass, and **both were wrong in the same direction**:

| reconstructed | production actually passes |
|---|---|
| `("xpfarg","class")` — the census walk's schema placeholder | `node.Keys[0]`, the stanza keyword |
| `kw := fields[len(fields)-2]` off an inventory path | `("ge-0-0-0","mtu")` — the **instance name** under a named-child container |

One cost a hidden site — admitted count moved 48 -> 49 once admission came from
*running the pass and asking whether it touched the tree*. The other is latent and
**sound only by accident**: an arbitrary instance name matches no static rule, and
a head-only rule happens to match both queries. It goes blind precisely on the
named-child-with-args shape.

**The asymmetry is what makes this class dangerous.** A model that
**over**-admits fails loudly the first time it admits something wrong. A model
that **under**-admits is **silent forever and looks like a clean scope** — there
is no red, no anomaly, and the guard reports success. Reconstruction errors are
overwhelmingly of the second kind, because a reconstruction is written from a
reading of the common case.

Measuring costs one throwaway probe: instrument the production call site, print
what it passes for three or four representative shapes, and compare against what
your guard derives. Both lanes above reasoned about it and got it wrong; the probe
answered it immediately.

**And when two independent implementations of the same model fail the same way,
that is a fact about the source they are reading, not a coincidence** — expect a
third, and fix the source rather than the copies.

### A content-scanning guard is never in anyone's diff scope, so everyone runs it

A merge gate is normally scoped to the packages a diff touches: `git diff
origin/master...HEAD` names the files, and you run those packages' tests. That
gate is **structurally incapable** of seeing a guard that selects its subjects by
CONTENT rather than by ownership — a census that walks the whole tree looking for
a shape.

The failure has a distinctive and expensive signature: **the lane that breaks it
stays green, and every other lane inherits the red.** The breaking diff does not
touch the guard's package, so the author's scoped run passes; the guard lives
elsewhere, so it fires on the next person to merge, who then investigates a
failure they did not cause.

Three instances in one day, from three lanes, across two guards:

| guard | lives in | broken by a diff touching |
|---|---|---|
| `TestTreeIsGofmtClean` | tree-wide | one package's formatting |
| `TestOperatorPackagesOnlyUseDocumentedLegacyDataplaneImports` | `pkg/dataplane` | a new file in `pkg/cli` |
| `TestRetirementBoundaryDocsMentionLegacyImportAllowlist` | `pkg/dataplane` | an allowlist entry with no docs row |

**So the merge gate has a step that is deliberately NOT scoped to your diff.**

The honest form of that step is **`go test ./...`**, and the reason is a measured
one: content-scanning guards live in **18 packages**, not two —

```
pkg/api          pkg/cli          pkg/cmdtree      pkg/config
pkg/configstore  pkg/daemon       pkg/dataplane    pkg/dataplane/userspace
pkg/durationaudit pkg/eventengine pkg/fsatomic    pkg/grpcapi
pkg/linuxsock    pkg/memlockcensus pkg/nftables   pkg/osident
pkg/refactoraudit pkg/upgrade
```

found by looking for tests that walk the tree or the schema rather than a fixture
(`filepath.Walk`, `packages.Load`, `parser.ParseDir`, `setSchema`). That list will
be out of date the next time someone adds a census, which is exactly why **the
rule is a category and not a command list**: any enumeration you run against is a
snapshot, and the guard that bites you is the one added after it.

At minimum, always:

```
gofmt -l .            # whole tree, not just touched files
go test ./...         # ~6-8 min; the only reliable cover for the category
```

`go test ./pkg/dataplane/` alone is **not** sufficient — it was the first place we
found boundary canaries, not the only place they live. A narrower run is a bet
that your diff did not perturb any of the other seventeen packages' censuses, and
that bet is unverifiable from inside your diff.

**Corollary — when you satisfy a guard by adding to its allowlist, find the guard
that guards the allowlist.** A registry that exists to record exceptions is
exactly the kind of thing bound to documentation or to a count elsewhere; the
obvious one-line fix can be one commit away from a different red. Grep for other
tests naming the same identifier before landing.

**And distinguish the two kinds of allowlist entry, because only one is
legitimate:**

- **A new capability gaining an exception is weakening the guard.** The cure for
  a guard's noise must never be loosening the guard.
- **A relocation is keeping the guard accurate.** The allowlist is keyed by
  FILENAME, so splitting code out of an already-allowlisted file trips it while
  the import boundary is unchanged. Existing entries carry this category
  explicitly (`#1444 relocated from cli.go`, `#2158 split from
  cli_show_security.go`, `#5661 pure-motion split`).

An allowlist reason string is a **claim about the import boundary**, not a
description of the change that moved the code — write it so it stays true after
that change's rationale is rewritten.

## Review discipline

### Reviewing (adversarial by design)

- **Be antagonistic in service of quality.** Reviewers who default to
  "LGTM" let regressions land. The architect/reviewer role exists to
  hold a deliberately high bar.
- **Separate severity from style.** Correctness bugs, perf cliffs, and
  API contract issues are Medium+. Terminology drift, rustdoc rendering,
  redundant no-ops are Low. Call the severity explicitly; it tells the
  author what to do first.
- **Concrete code shape, not vague complaints.** "Consider centralising
  the formula" is less useful than a five-line snippet showing the
  exact helper signature. If you want a specific change, show it.
- **Test strength matters.** A regression test that leaves state at
  `0` before the final assertion is an arithmetic-consistency check,
  not a regression guard. Tests must recreate the failure mode.
  Counter-factual assertions that reconstruct the pre-fix formula and
  prove it *would* fail are the strongest pin.
- **Split behaviour choices out of bug fixes.** If a reviewer spots
  "while you're here, we should also clamp...", that's a separate PR
  or a follow-up issue. Don't let scope creep hide behind
  "review feedback".
- **Trust but verify.** An agent's commit summary describes what it
  intended. Read the diff. Re-run the tests on the updated head before
  approving.
- **A comment is a CLAIM, not a check — verify it before you rely on
  it.** A comment that justifies a direction ("we do X because Y") is
  the most dangerous kind, because a reader takes the direction and
  never re-derives Y. Y was verified once, at authorship, and never
  again. Three landed in a single review batch, all true when written
  and false at head:

  - `daemon_apply_tail.go` asserted "every step below still RUNS (no
    early return)". A lane whose teardown sits below it checked the
    code rather than the comment, because if it *had* early-returned the
    teardown would silently stop running on exactly the commits that
    fail.
  - `netlink_lo0.go` justified per-term fail-closed with "a rejected
    table leaves NO host filter = fail-OPEN". True before #6476 added
    the cold-boot fence; false after, which is what unblocked the
    correct plan-failure direction in #6806.
  - `daemon_nft.go` justified dropping a protocol predicate as
    "mirroring the tcp-flags lowering" — and tcp-flags does not drop its
    predicate. Wrong when written.

  So: **when a comment is load-bearing for your change, read the code it
  describes.** If it is stale, annotate it as historical rather than
  deleting it — the next reader needs to know it *was* true, not merely
  that it is gone. Note the failure mode this shares with a refuted
  finding whose refutation never reached the code: in #6807 the review
  had *disproven* the repo's FRR permit-all model, and the repo's own
  comments and tests still asserted it — so a reader had not a neutral
  prior but a confidently wrong one, with every local check agreeing.
- **An agreement test cannot see a defect the two sides SHARE.** The
  #6806 lo0 parity gate compares the netlink installer against the text
  oracle. Both dropped an unresolvable token, so they agreed perfectly
  while both were fail-open, and the gate was green the whole time. When
  two implementations must match, "assert the agreement, never pin one
  to a literal" is right for drift — but drift is not the only defect.
  Add a cell asserting the PROPERTY each side owes independently (here:
  neither mirror may lose the refusal evidence at its own boundary), or
  the shared blind spot is invisible by construction.
- **A tool-gated leg that SKIPs is a green that measured nothing.** Say
  whether it ran. `nft`-dependent parity, cargo legs, cluster smoke:
  report tests-collected, not just `ok`.
- **A harness nothing INVOKES is a gate that never ran, and it does not
  SKIP — it is silent.** `make selftest` carries three censuses (#8153,
  #7296, #8278) and each exists because a test accumulated on disk that
  nothing executed. One layer up the same thing had happened at scale:
  28 of 41 runnable harnesses under `test/incus/` and
  `scripts/userspace-*.sh` were reached by no Makefile recipe, 15 of
  them gates the tree had built, unit-tested, documented, and run zero
  times — the #4800 new-flow ceiling among them, whose own doc opens
  *"the code ships; the measurement is OWED"*. `make harness-census`
  (#8302) is that census: every runnable harness is invoked by a recipe
  — directly or transitively through another invoked harness — or
  declared in `test/incus/HARNESSES.unreached` with a one-line reason,
  and that list is only allowed to shrink.

  Four shapes LOOK like registration and are not, all four real in this
  Makefile: a mention in a **comment**; a similarly-named **sibling
  target** (`test-fbf-steering-lib` runs the selftest, not the harness);
  a **`bash -n` lint** (run-unreachable, lint-reachable); and a **bare
  relative path in a lint list**. Adding a harness means adding a recipe
  or writing the reason down — there is no third option that leaves the
  board green.
- **Format the files you TOUCHED, never a directory.** `gofmt -w pkg/daemon`
  reformatted **12 pre-existing unformatted files** a lane had never
  touched, silently widening its diff. Master carries unformatted files,
  so `gofmt -w` on a directory is not idempotent with respect to your
  change in this repo specifically — and a widened diff is how an
  unrelated change rides in unreviewed. Use `gofmt -w <file>...`. If it
  has already happened, recover by filtering: for each modified `.go`,
  if its diff adds none of your change's identifiers,
  `git checkout HEAD -- <file>`.
- **In `userspace-dp`, do not run a formatter at all — not `cargo fmt`,
  and not `rustfmt <file>` (#8945).** The Rust tree is NOT
  rustfmt-managed and the per-file workaround above does not rescue it:
  - `cargo fmt` on the crate rewrites **~380 files** and **fails the
    suite** — the #6592 runtime-view canary counts `RuntimeView`
    constructions by scanning source lines, and rewrapping one changes
    the count. The failure lands in `worker/loop_body/mod.rs`, a file
    you did not touch, so the two obvious next moves (debug the canary,
    debug your change) are both dead ends.
  - `rustfmt <file>` walks the module SUBTREE, so formatting
    `worker/mod.rs` also formats `worker/loop_body/*` and
    `worker/cos/*`. Five files in, sixteen files out.
  - Worst: a **`#[path]`-included file that lives inside a `mod` block
    in its parent** is indented four spaces by convention while its
    braces live in the parent. rustfmt sees a standalone module,
    concludes the file is over-indented, and **de-indents every line** —
    `neighbor_dispatch_mirror_tests.rs` is ~48KB rewritten end to end
    with the real edit invisible inside it. That file cannot be
    simultaneously rustfmt-clean and correct in its parent's context.

  Match the surrounding style by hand, and **check `git status
  --porcelain` before you trust a suite failure**: a modified-file count
  larger than what you edited means a formatter ran wide and the failure
  you are about to debug is probably not yours. This cost two separate
  hours in one day, the second time while applying the per-file
  workaround that this bullet's Go half recommends.
- **Two independent review surfaces.** Codex (hostile, design-level)
  and Copilot (inline, mechanical-detail) catch different classes of
  bugs. Treat them as separate passes; do not skip either. Codex
  often misses the unwired-field or stale-comment bug that Copilot
  spots; Copilot often misses the architectural concern that Codex
  flags. The combined coverage is the point — losing one halves
  the review.

### Responding to review (as author)

- **Apply review items by severity, fastest first.** Cleanup-level
  items (docs, naming) land in the same push. Medium items get their
  own commit if they're substantive. Design questions get a reply
  asking for the decision before coding.
- **Don't silently defer.** If a reviewer raises a concern you don't
  act on, reply with why, and file a tracking issue. The next
  reviewer should not have to re-discover the concern.
- **Update the PR body when live data disagrees.** If the hypothesis
  turns out to be partly wrong, rewrite the summary. Keep both the
  before data and the after data visible. Future readers need the
  honest picture.

## PR discipline

### Title

- Imperative. `userspace-dp: lock-free redirect inbox eliminates cross-
  producer mutex (#706)`, not "Removed mutex".
- Issue reference in parentheses at the end. Multiple if the PR closes
  multiple.

### Body

- **Summary**: 3–6 bullets. What changed and why.
- **Hot-path shape** (for perf PRs): explicit about added instructions,
  allocations, atomics. "One `saturating_mul` + one `max` per
  admission (~2–3 ns)" is the right specificity.
- **Test plan**: checkbox list. What tests were added, what was run.
- **Live data** (for PRs that claim to move a metric): before/after
  table. If the metric doesn't move, say so.
- **Deferred**: named follow-ups with tracking issue numbers. Not
  "TODO later".

### A closing keyword cannot be negated

GitHub's parser does not read negation. `Does not close #N`,
`why this does not close #N` and `merging this must not close #N` each
contain a live `close #N` token, and the issue is closed the instant the PR
merges — against the explicit written intent of the sentence it appears in.

**To scope an issue OUT of a PR, drop the verb.** Write `Refs #N`, or
`#N is out of scope, see below`. `advances #N` and `part 1 of 2 for #N` are
also safe. Never `close`/`closes`/`closed`/`fix`/`fixes`/`fixed`/
`resolve`/`resolves`/`resolved` adjacent to `#N` unless you mean it.

**One correct form does not neutralise an incorrect one elsewhere in the same
body.** A PR that ended with `Refs #7406` still closed #7406, because a
scope-explaining sentence earlier in the body said "Does not close #7406."

**Watch the heading/first-line pair.** A `## What this does NOT close` heading
followed by a paragraph beginning `` `#NNNN` `` reads to the parser as
`close #NNNN` across the blank line.

**Merge pre-flight — run it on the FLATTENED body.** These phrases wrap across
lines and carry `**` mid-token, so a line-based `grep` misses them; that is how
this got past a reviewer who was specifically looking for it:

```bash
gh pr view <n> --json body -q .body | tr '\n' ' ' | sed 's/[*_`]//g' \
  | grep -oiE '(close[sd]?|fix(e[sd])?|resolve[sd]?) +#[0-9]+'
```

Every hit must be an issue you intend to close. Also check every commit
message body — GitHub scans those on the default branch too, so a clean PR
body does not save you.

**It is mechanical now (#9551).** `scripts/close_keyword_lint.py` implements
GitHub's documented grammar plus the two measured shapes above. It refuses a
close pair that follows a negation, or a scoping heading, within its own clause,
and names the issue and the spellings that pass. Verdicts are per pair, so a
`Closes #N` in the same body goes through. It runs in two places today, and a
third is written but not installed:

- `scripts/close_keyword_lint_ci.sh` holds both pull-request legs (the PR body
  and every commit message in the range). The GitHub Actions job that would call
  it on every pull request is **not in the tree**: pushing a workflow file needs
  an OAuth token with `workflow` scope, which the token in use does not have
  (#9551). Until it lands, nothing checks a PR BODY unless someone runs
  `make close-keyword-lint PR=<n>`. `master` is not branch-protected either, so
  even with the job a red check would not block `gh pr merge`.
- `make close-keyword-lint` checks this branch's commit messages
  (`origin/master..HEAD`); with `PR=<n>` it checks that PR's body and commit
  messages.
- `make install-git-hooks` installs a `commit-msg` hook that refuses at commit
  time. It is not installed by default, because one hooks directory can serve
  every worktree of a clone.

**Why this is worth a section.** The failure is invisible after the fact: the
wrongly-closed issue reads `COMPLETED`, so every subsequent sweep for open work
skips it forever, and the only contradicting evidence is a one-second gap
between the merge and the close on an issue the PR itself disclaimed. Six
issues have been recovered this way — #6683, #7406, #5192, #5084, #7033, #6979
— none by anyone noticing, all by a periodic sweep:

```bash
gh pr list --state merged --limit 400 --json number,body,mergedAt \
  -q '.[]|"===PR\(.number)|\(.mergedAt)===\(.body)"'
# flatten each body, then match:
#   \b(not|never|without)\b[^.#]{0,45}?\b(close[sd]?|fix(e[sd])?|resolve[sd]?)\b\s+#(\d+)
# a hit whose issue closed within ~2s of mergedAt is a victim
```

**Check the gap before reopening.** A real auto-close is within a second or
two. One candidate closed 4.6 hours after its merge and was a deliberate close;
reopening a legitimately-closed issue is its own kind of damage.
- **Refs**: every related issue.

### Commit messages

- Same shape as PR titles. Imperative, prefixed with the subsystem.
- Body paragraphs explain *why*, not *what*. The diff shows what.
- No emoji. No marketing. No "Makes the code better".

### Merging

- **Every code change lands via PR.** Even revert commits. Even
  "obviously right" one-line fixes. Even cherry-picks from someone
  else's branch. If you find yourself typing `git push origin master`
  for anything except a docs-only maintenance skill that explicitly
  does that (see first principle #6), stop — open a PR.
- Squash-merge, single commit per PR on master. Commit message is the
  PR title.
- Do not merge with failing tests. Do not `--no-verify` to skip hooks.
- Close referenced issues with a pointer to the merge commit and the
  specific follow-up issues if any part was deferred.

## Project-specific reminders

These are not "style" but are worth keeping next to the rest because
they repeatedly bite:

- **Never assert an exact count or an in-flight state that the SCHEDULER
  can move (#7563).** Three tests in three packages failed under a
  full-tree parallel `go test ./...` and passed on immediate re-run of
  the SAME tree, on branches that could not reach the code they failed
  in. They shared one shape: each sampled an asynchronous observable at
  a fixed point, so the value read was a reading of the machine rather
  than of the subject.
  The three mechanisms are worth recognising, because none of them is a
  data race and `-race` finds none of them:
  1. a **retry-loop test that let one attempt reach the real resource** —
     the fixture stubbed the failing attempts and let the winning one
     bind a live port, so a genuine conflict made the loop resample
     correctly and the exact-attempt-count assertion fail;
  2. a **single sample taken right after an async enqueue** — the pass
     under test hands work to a worker goroutine and returns, so "0
     applies so far" is the correct answer to the wrong question;
  3. a **counter read taken from a callback the producer fires BEFORE
     it accounts the event** — the callback is delivered first by
     construction, so observing it and then reading the counter races
     an `Add(1)` that has not happened yet.
  The fixes, in preference order: make the fixture unable to observe
  the machine at all (inject the outcome rather than sampling a real
  resource); otherwise wait on the observable that actually implies the
  property, and make the wait FAIL LOUDLY, naming what never arrived.
  Where the producer already publishes a completion watermark, wait on
  that — it is advanced by the same goroutine after the accounting, so
  a read taken once it covers the item happens-after the accounting.
  What NOT to do: add a retry or a sleep to the assertion. That hides
  the sensitivity instead of removing it, and a test that passes on the
  second attempt is indistinguishable from one that passes for the
  wrong reason. Nor is "just re-run it" free: classifying one of these
  costs a full repo-wide re-run, and — the real damage — it trains
  reviewers to re-run a red instead of reading it, which is precisely
  the habit that lets a genuine regression through.
  **Verify the population empirically rather than by pattern.** Of the
  15 counter reads in `eventstream_test.go` that matched shape 3 by
  eye, injecting a delay at the producer's accounting site red-flagged
  exactly two. Pattern-matching would have rewritten a dozen tests that
  were already sound. Reproduce a load-sensitive assertion by injecting
  the scheduling perturbation a loaded box supplies for free, and fix
  what actually reds.

- **A test that needs a kernel capability must STUB it, not skip on it
  (#6675).** `pkg/dataplane/userspace` builds every snapshot through
  `buildRouteSnapshots`, which dumps the kernel ip-rule table via
  `ruleListFn` and — correctly, per #3772 M9 — refuses to swallow a dump
  failure. In a sandbox without `CAP_NET_ADMIN` that returns EPERM,
  `buildSnapshot` returns a nil `*ConfigSnapshot`, and the ~45 test call
  sites that discard the error dereference it. A nil dereference is a
  SIGSEGV that aborts the whole test BINARY, so the first one takes every
  remaining test in the package with it: the review run shows a crash with
  no diagnostic, and reviewers chase a phantom regression in whatever PR
  happened to be under test.
  The fix is a `TestMain` that replaces the enumerator package-wide, NOT a
  `t.Skipf` on EPERM. Skipping trades a crash for silence and leaves the
  package with zero coverage in exactly the reduced-capability
  environments where reviews run; stubbing lets those tests actually run
  there. Guard the wiring with a code-pointer comparison against the real
  function (`TestPackageIsHermeticWrtKernelIPRules_6675`) — a behavioural
  check passes on any machine that HAS the capability, which is every
  laptop and most CI runners, so it would never notice the stub being
  deleted.
  **Follow-through (#7446):** hermeticity stops the ENVIRONMENT causing
  that crash; it does not stop a bad fixture causing it. The 44 call sites
  that discarded the error now go through `mustBuildSnapshot` /
  `mustBuildSnapshotWithSchedulerState`, which make the safe form the SHORT
  form — a call site gets shorter by adopting them, which is what keeps the
  population from growing back. An AST guard
  (`TestNoDiscardedSnapshotBuildErrors_7446`) fails if the discarding shape
  returns. Scope such a guard to the builders that return a POINTER: a nil
  slice or map reads back safely, so sweeping those in would flag call sites
  that cannot exhibit the defect — the guard carries a negative-control cell
  proving it does not.
  And when a package-wide default is introduced, compare the PASS SET before
  and after, not just "still green": still-green and unchanged are different
  claims, and only the second rules out a test that was passing because the
  real dependency happened to return real data.

- **Smoke tests run ONLY on the loss userspace cluster.** The smoke
  target is `loss:xpf-userspace-fw0` / `loss:xpf-userspace-fw1`,
  driven by `INCUS_REMOTE=loss` + `test/incus/loss-userspace-cluster.env`.
  Invocation: `BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env
  ./test/incus/cluster-setup.sh deploy all`. Do NOT smoke on the
  local `bpfrx-fw0/1` (legacy eBPF cluster, regression-only) or
  `bpfrx-fw` (standalone eBPF reference). `make cluster-deploy`
  without `BPFRX_CLUSTER_ENV` targets the legacy local cluster —
  that is the wrong path for any userspace-dp validation.
- **Deploy wipes CoS config.** After `cluster-setup.sh deploy`, re-run
  `./test/incus/apply-cos-config.sh <target>` before running iperf3
  for any #706 / #707 / #708 / #709 / #718 validation.
- **A `Mutex`/`RwLock` in production Rust is acquired
  poison-tolerantly, never with `.unwrap()`.** `std` poisons a lock the
  moment a thread panics under its exclusive guard, and every later
  acquisition returns `Err` — so `.unwrap()` turns one contained panic
  (the #925 worker supervisor contains it) into a panic on EVERY
  subsequent acquisition of that lock, i.e. a permanent outage of
  whatever the lock guards. Three settled forms, in order of preference:
  - `worker_queue::lock_recover` / `try_lock_recover` (#1807) for the
    worker-command queues and `shared_ops::lock_shared_recover` (#2402)
    for the shared-session / owner-RG maps. These also `clear_poison()`
    and bump a per-subsystem recovery counter. Use them **only** for
    their own subsystem: each stamps a subsystem-specific journald line,
    so borrowing one for unrelated state makes both the operator message
    and the counter lie.
  - the inline idiom `lock().unwrap_or_else(|e| e.into_inner())` — the
    tree-wide default (`nat::allocator`, `event_stream`,
    `afxdp::sharded_neighbor`, `afxdp::icmp_ratelimit`, `afxdp::wg`
    #6422). It is the only form that covers `RwLock`, which neither
    helper takes.
  - **Never** `if let Ok(g) = m.lock()` (silently skips the operation)
    or `.lock().map(..).unwrap_or_default()` (substitutes EMPTY state).
    #2402 was exactly the latter: an empty shared-session table on the
    HA promotion path silently dropped every active synced session at
    the moment of failover.

  Recovery keeps the committed prefix of everything already written,
  which is the right answer for a map. Before converting a lock that
  guards a cross-field invariant, check the critical section for panic
  sites: if there are none the recovered value is by construction
  well-formed, and if there are some, ask whether panicking forever
  actually repairs the inconsistency (it usually does not — an
  idempotent reconcile pass that can still run does).

- **Rust tests must be parallel-safe — `make test-rust` forces
  `--test-threads=1`, but a plain `cargo test --release` does not.** A
  test that silently assumed serial execution (a shared process-global
  counter, or heavy busy-spin threads) flaked or deadlocked the moment
  someone ran the suite in parallel (#6148 progress-gated liveness;
  #6157/#6294 the WG engine/frame tests wedged a full-suite run for
  >100min). Two settled patterns:
  - **A test-only global counter/state → make it `thread_local!`**, not
    a `static AtomicUsize`. Each test thread then resets/mutates/reads
    its own copy, so no parallel sibling can corrupt the assertion
    (`OUTER_ROUTE_RESOLVE_COUNT` in `afxdp/frame/wg.rs`, #6294). Strictly
    stronger than serializing every mutator behind a lock.
  - **A test that MUST touch a genuinely shared global, or that spawns
    busy-spinning worker threads → serialize it behind a poison-tolerant
    module-local guard** held for the whole body:
    `LOCK.lock().unwrap_or_else(|e| e.into_inner())`
    (`icmp_ratelimit::global_bucket_test_lock`,
    `wg::engine_tests::wg_engine_test_serial` #6157). The blocked sibling
    PARKS on the mutex (futex wait) instead of compounding scheduler
    oversubscription. Every test sharing a given global must take the
    SAME lock.
  - **A worker thread whose progress the test ASSERTS must reach its
    first cycle by CONSTRUCTION, not by scheduling — write the loop as
    a do-while.** A `while !stop { work }` unbounded worker racing a
    BOUNDED one can be scheduled for the first time only after the
    bounded side finished and the main thread stored `stop`: zero
    cycles, and a `cycles >= 1` "we made progress on both sides"
    precondition trips as a scheduler artifact rather than a
    regression. `loop { work; if stop { break } }` costs one extra
    cycle and makes the precondition unfalsifiable by the scheduler
    (`#3457` in the WG snapshot-atomicity reader; `#6633`
    `reconcile_churn_until`). The do-while's contract is deterministic,
    so calling the helper with `stop` ALREADY set is an exact
    fail-on-revert
    (`reconcile_churn_completes_a_cycle_even_when_already_stopped_6633`),
    which the scheduling assertion it replaces could never be.
  - **But making a precondition guard true BY CONSTRUCTION does not make
    it MEAN anything — it can convert a false red into a vacuous
    green.** `#6633`'s do-while removed the flake in
    `install_session_serializes_with_reconcile_removal`
    (`#6989`/`#6985`/`#6945`) and, in the same move, made
    `reconcile_iters >= 1` satisfiable by a reconciler that ran its one
    cycle entirely AFTER the installer had joined. That is zero overlap:
    exactly the case the guard exists to catch, now reporting the same
    value as a healthy run. When the fix for a scheduling artifact is
    "make the number always ≥ 1", ask what the number is still able to
    distinguish. So ALSO wait on the OBSERVABLE: publish the cycle count
    live and have the bounded thread block until it advances
    (`wait_for_first_reconcile_cycle`, `#6989`). The do-while stays — it
    is what makes the count non-zero; the counter is what makes it
    visible while the loop is still running.
  - **A rendezvous between test threads is safe when it cannot cycle and
    cannot wedge — check both, don't assume either.** `#6633` rejected
    one on the grounds that it adds a blocking edge and turns a false red
    into a hang, which is the right default. It is admissible when (a)
    there is no cycle in the wait-for graph — the awaited thread is
    unbounded, takes no lock the waiter holds, and its `stop` is set by a
    third thread only after the waiter is joined — and (b) the wait is
    not a block but a bounded poll that PANICS BY NAME, so a stall is a
    named assertion failure and never an rc=124 wedge. Record the
    disposition at the call site: a later reader will find the older
    "prefer the do-while to a rendezvous" rule and needs to know which
    conditions changed.
  - **A liveness backstop is not a timing assertion, and a red there is
    never fixed by raising it.** Size it orders of magnitude above the
    healthy path (60s against a microsecond publish; 30s against a
    microsecond sweep) and say so IN THE FAILURE TEXT, because the next
    person to see it red will be deciding whether the machine was merely
    loaded. Tightening a bound to "make the wait meaningful" just moves
    the wall-clock sample — a 5s bound reddened master twice.
  - **`thread_local!` is only for a TEST-ONLY global. A PRODUCTION global
    takes the guard, whatever its shape.** `DETERMINISTIC_V6_DOWNGRADE_COUNT`
    (`nat64.rs`) is an `AtomicU64` two tests assert deltas on, which looks like
    the counter case above — but it is bumped on the real downgrade path and
    read by the operator warning, so making it thread-local would break the
    product: the increment happens on whichever thread compiles the snapshot
    and a reader on another thread would see zero. Check where the global is
    WRITTEN before choosing the pattern (#7413).
  - **Enumerate the affected population by RUNNING every test alone, not by
    reading call sites.** For #7413 the two shared observables were a
    production counter and the process-wide count of threads named
    `neigh-monitor`. Reading call sites suggested ~28 candidate coordinator
    tests; running all 4549 tests individually and watching for each
    observable's own log line found **exactly 2** counter bumpers and
    **exactly 10** monitor spawners — and showed that every one of the ten
    STOPS its monitor, which ruled out a leak and left concurrent overlap as
    the only mechanism. It also found the one spawner in a different module,
    which is what forced the guard to be `pub(crate)` rather than
    module-scoped. A guard over the population you guessed is a guard over
    part of it.
  - **Be explicit about which guards are BOUND and which are precautionary.**
    In #7413 the guard on the two asserting gates reds 5/8 when removed; the
    guard on the other eight spawners does NOT red even when paired one-to-one
    with an asserter at `--test-threads=2`, because their monitor windows are
    too short to overlap the assertion window today. They are kept as defence
    in depth over an enumerated population — not claimed as tested — and the
    two gates carry a `before == 0` precondition so a future spawner that does
    collide fails by NAMING the missing lock instead of as an off-by-one delta
    that reads like a real leak.
  - Prove the ISOLATION variant with a **deterministic fail-on-revert**
    (two barrier-synced threads whose per-thread counter assertion is
    mathematically impossible under a shared global). The mutex GUARD
    variant's fail-on-revert is **scheduler-dependent** (barrier + many
    iterations + a widened critical window make it effectively certain)
    and pins the guard PRIMITIVE's exclusivity, not that each heavy test
    TAKES it — verify that application by inspection, since a deterministic
    test for it reduces to the underlying flake. Back both with repeated
    parallel runs of the previously-flaky test.
  - **Not every parallel-only wedge is a scheduling problem. MEASURE the
    wedged process before theorising: sample `utime+stime` from
    `/proc/<pid>/stat` over 5s. Non-zero => spinning (oversubscription,
    starvation). ZERO => every thread is parked, and it is a real deadlock
    that no amount of serialization fixes.** #6952 was the residual wedge
    left after the #6157 guard, and it measured ZERO ticks: three tests
    appeared hung, but two were innocents parked on `wg_engine_test_serial`
    and the third — `install_session_serializes_with_reconcile_removal` — sat
    in `RwLock::write_contended` inside `reconcile_peers`, on its OWN read
    guard. The cause was a **shadowed lock-guard rebind**:

        let by_index = engine.sessions_by_local_index.read().unwrap();
        ... asserts ...
        engine.reconcile_peers(&[]);   // takes .write() on the SAME RwLock
        let by_index = engine.sessions_by_local_index.read().unwrap();

    The second `let` shadows the name but does NOT drop the first guard — a
    shadowed value lives to the end of the enclosing BLOCK, not to its last
    use — so the read guard was still held across the reconcile, and
    `std::sync::RwLock` is not reentrant. Scope the guard (`{ ... }` or an
    explicit `drop`); do not rely on rebinding to release it. The sweep for
    this class is cheap: within one function, a lock guard binding that is
    still in scope when the same lock is taken again.
  - **A conditional write is what makes such a self-deadlock INTERMITTENT.**
    `reconcile_peers` takes the demux write lock only when
    `dropped_indices` is non-empty, i.e. only when the peer it removes still
    owns a live session. In a test that races an installer against a
    reconciler, whether it does is decided by the interleaving — so the
    deadlock fired on roughly one schedule in six and every other run passed
    with the bug fully present. When a hazard is gated on a conditional, a
    regression test must ARRANGE the deciding condition deterministically
    (`orphan_demux_sweep_does_not_self_deadlock_6952` installs a session and
    asserts the demux map is non-empty BEFORE running the sweep) rather than
    inherit it from the racing caller, which reds one run in six.
  - **`--test-threads=1` does not make a test's OWN threads safe.** It
    serializes libtest's test slots, not threads a test body spawns. #6952
    self-deadlocks a single thread; serial mode only shifts CPU availability
    and therefore the odds. Treat the flag as a rate reducer, never as a
    correctness guarantee — and never as evidence that a wedge is a
    parallelism artifact.
  - **Wrap a body that can self-deadlock in a bounded runner so a revert
    fails BY NAME.** A wedge exits 124: neither "the guard fired" nor "the
    guard failed to fire", so any mutation cell that lands on it is
    uninterpretable and scoring it as either polarity manufactures evidence.
    `engine_tests::run_bounded` runs the body on a worker thread and asserts
    completion against a deliberately loose 30s backstop (the healthy path is
    microseconds, so a loaded machine cannot flake it). The parked worker is
    left detached on the deadlock path; libtest exits the process rather than
    joining it.
  - **Such a runner must distinguish a body that PANICKED from a body that
    PARKED.** Deciding "done" from a flag the worker sets AFTER calling the
    body reports a panicking body as a deadlock: the flag stays false, the
    caller burns the whole backstop, and the named failure claims the wrong
    defect. `run_bounded` polls the join handle alongside the flag and
    `resume_unwind`s the body's payload, so the failure names the assertion
    that actually fired (#6989 — found when a mutation cell removing
    `reconcile_lock` produced "found 126 … install/reconcile race left
    orphans" and it was buried 30s later under a #6952 self-deadlock claim).
    A body that genuinely parks never finishes, so the deadlock path is
    untouched.
  - **Score a cell on four facts, never on rc: applied, built, collected,
    named-FAIL.** `rc != 0` is not "the tests failed". A build break, a panic
    before collection, and a full disk all exit non-zero with no failing test.
    A harness keying on rc calls them kills; one keying on "no named FAIL"
    calls them escapes. They are VOID, and the two wrong answers are the two
    that end the investigation. `scripts/mutate-lib.sh` encodes the ordering —
    infrastructure, then applied, then built, then collected, then failures —
    because each earlier condition makes the later numbers meaningless.
  - **A harness must REFUSE a cell it could not have observed.** A runner that
    gates in one language scores every mutation in another as an ESCAPE,
    because nothing it ran could possibly have failed — and an escape is a
    claim that the code is untested. Derive the language set from the
    mutation's touched paths and emit "cannot score", never a verdict, when a
    touched language has no configured gate. `make test-mutate-lib` pins this.
  - **A GATE and a mutation CELL pull opposite ways on `rc`.** The rule above
    is about scoring a cell, where `rc != 0` must not be read as "the tests
    failed". Running `make test-go` / `make test-rust` to decide whether a
    change is shippable is the inverse case: there `rc` is the only signal that
    catches a panic, because a panic emits no `--- FAIL` line anywhere in the
    log. A `^--- FAIL`-counting gate reads a SIGSEGV as a clean run. Measured
    on #7209: a new Prometheus emit landed in a function a test drives with a
    partially-initialised collector, so the new `*prometheus.Desc` was nil and
    `MustNewConstMetric` segfaulted — `GO_RC=2`, zero `--- FAIL` lines, 71
    packages `ok`. Gate on the exit code AND on packages-collected; score a
    cell on the four facts. Neither rule substitutes for the other.
  - **A HANG is a fifth void shape, and the most expensive one.** A build
    break, an edit that never applied, a panic and a `-race` red are the four
    above; a test that never returns is a fifth. It emits no `--- FAIL`, no
    compile signature and no panic trace, so every log heuristic reports
    NOTHING — and unlike the others it consumes the whole time budget, so one
    hang in a batch can lose every cell after it. Measured on #7611: giving the
    primary gRPC listener a retry supervisor changed `Run` from "returns an
    error on a bind failure" to "returns only when ctx is done", and an
    existing cell that called it with `context.Background()` and asserted the
    error stopped returning. The package went from 12s to a 600s timeout. What
    identified it was the exit code plus the goroutine dump, not the log scan.
    Run suites under an explicit `-timeout` so a hang becomes a reportable
    failure with a stack rather than a stuck job, and treat a run that consumed
    its whole budget as VOID until you have read the dump.
  - **A `-race` failure has no `--- FAIL` line.** It emits `WARNING: DATA
    RACE` plus a package-level FAIL, so a `^--- FAIL` counter scores a genuine
    race red as a PASS. Count both.
  - **ANCHORING a `--- FAIL` scan is unsound, and the direction is the
    damaging one (#8213).** Parallel `go test -v` interleaves concurrent
    tests MID-LINE, so a real `--- FAIL: TestX` can be spliced into another
    test's failure text and no longer start at column 0. An anchored scan
    then reports zero named failures for a run that genuinely failed, and the
    cell scores as an ESCAPE — which reads as "the fix is not bound" and
    points a reviewer at the TEST as the thing to weaken. It does not merely
    lose a signal; it manufactures an argument for deleting a guard that
    works. Observed shape, from the #8000 matrix:

    ```
    ...left the barrier armed --- FAIL: TestR--- FAIL: TestRemoteFailover... (0.60s)
    ```

    Every anchor variant fails somewhere. Measured against a fixture holding
    one top-level failure, one subtest failure and the spliced line above
    (three real failing tests):

    | pattern | finds | misses |
    |---|---|---|
    | `^--- FAIL` | 1 | the indented SUBTEST and the spliced line |
    | `^\s+--- FAIL` | 1 | the TOP-LEVEL line — it has no leading whitespace |
    | `^\s*--- FAIL` | 2 | the spliced line |
    | unanchored `grep -oE -- '--- FAIL: '` | **4** | nothing — it OVER-counts |
    | `go test -json`, `.Action=="fail"` | 3 | nothing, by construction |

    Note the second row against the first: the two anchors fail in OPPOSITE
    directions, so "tighten the anchor" and "loosen the anchor" each fix one
    and break the other. `^\s*` is not the bug — it is strictly better than
    both `^` and `^\s+` — it is just still text.

    The unanchored count is the landed mitigation (`mutation_go_failed` in
    `scripts/mutate-lib.sh`). It returns FOUR for three real failures, because
    the spliced line carries two markers — the truncated `TestR` fragment and
    the real name. That over-count is the right trade and it is why the
    counter is used only for the VERDICT: over-counting cannot turn a kill
    into an escape, whereas the anchored under-count could and did.

    It is NOT sound for ATTRIBUTION. Anything reporting WHICH test killed a
    mutant must use `mutation_go_failed_names_json` over `go test -json`,
    where events are emitted one per line and cannot splice, or it will report
    a test named `TestR` that does not exist.

  - **The gate target emits the machine-readable stream; the driver does NOT
    bypass the gate to produce one (#8231).** `make test-go GOTESTJSON=<path>`
    appends the `go test -json` event stream to that file while leaving stdout
    byte-identical (`scripts/go-test-json.sh` reconstructs the human stream from
    the `.Output` fields, which carry every byte the text formatter would have
    written). `scripts/mutate.sh` sets it per cell and, when a spec row names a
    target test in an optional 5th TAB column, refines the verdict with
    `mutation_verdict_for_target`.

    **A name is not a reason (#9564).** A guard with a LIVENESS fatal ("the
    parser found no anchors") and a violation branch scores KILLED by name
    whichever branch fired, so a mutant that merely broke the fixture reads as
    covered. An optional 6th TAB column gives a fixed substring the target's
    own failure output must contain. `mutation_verdict_for_message` matches it
    against the jq-DECODED `Output` of the target and its subtests only (so a
    `"` in the message matches, and a sibling test's message cannot satisfy it).
    A target that failed without it scores `KILLED-WRONG-MSG`: not KILLED,
    because the reason is unproven, and not ESCAPED, because the target did
    fail. An empty column leaves every verdict byte-identical.

    **Do not close the attribution gap by converting the driver to
    `go test -json` instead. That narrows the gate.** Gating through `make` is
    why a mutation cell carries `go vet`, the targeted `-race` runs with
    `-count=2`, and on the Rust side `--release` and `--test-threads=1`. A bare
    per-package `go test -json` driver buys attribution and pays for it in
    COVERAGE — and a narrower gate that agrees with the old one is
    indistinguishable from a sufficient one right up until the day it is not.

    The defect this closes is a FALSE CLAIM OF COVERAGE, not a missing
    convenience: when a cell's target did not fail but another test in the same
    package was already red, the count-based verdict is KILLED with rc and count
    in agreement and nothing looking wrong. Only a NAME refutes it.
    `scripts/go-test-json-selftest.sh` case 5 is exactly that run, and case 6 is
    its control — an attribution that returned ESCAPED unconditionally would
    satisfy case 5 and destroy every real kill.

    Two properties are load-bearing and each has its own case. The default path
    (`GOTESTJSON` unset) execs `go test` unchanged, so the shared gate acquires
    no `jq` dependency and no new failure mode. And a set `GOTESTJSON` with no
    `jq` REFUSES rather than falling back, because a caller that asked for
    attribution and silently received a stream it cannot attribute over would
    read an empty file as "no failing tests" — the
    indistinguishable-from-healthy value this whole mechanism exists to prevent.

  - **The Rust half is NOT exposed, and that asymmetry is deliberate.**
    `mutation_rust_failed` keeps its `^test .* \.\.\. FAILED` anchor.
    Measured on a full parallel `cargo test` run of 5217 tests: zero lines
    carry a `test ... ` marker anywhere but column 0, and zero lines carry two
    of them. Rust's libtest holds the stdout lock for each result line, so it
    cannot interleave the way Go's `-v` output does. Do not "fix" the Rust
    pattern by symmetry with the Go one, and do not read the Rust pattern's
    safety as evidence the Go one was fine.
  - **Count collection in PACKAGES, not in result lines.** If `collected`
    includes `--- FAIL` lines it moves with the failure count, and a package
    that failed to BUILD hides behind another package's extra failures.
  - **Commit before mutating.** A harness that restores files by checkout or
    copy will eat uncommitted work; this has cost a full fix rewrite.
    The sharper form, learned again the hard way: **`git checkout --` is a
    RESTORE when your work is committed and a DELETION when it is not** — the
    same command, opposite meaning, and the discriminator is invisible at the
    moment you type it. A killed belt that leaves a mutant applied over
    uncommitted work is recoverable only from a `cp` backup, and the backup's
    CONTENTS must be checked before restoring rather than its filename trusted.
  - **A guard that SKIPS is indistinguishable from one that passes (#8371).**
    42 tests across 19 files call `rlimit.RemoveMemlock()` and `t.Skipf` on
    failure. Without `CAP_SYS_RESOURCE` they skip, the package reports `ok`, and
    the guards provide no protection — and a reviewer who greps for the test
    name concludes the defect is guarded. Measured on the development host
    (uid 1000, `ulimit -l` 8192): **all 42 are inert there**, which is where
    `make test-go` runs and where changes are first validated, so this is not a
    CI-only concern.
    `pkg/memlockcensus` makes the SET a gated quantity: a new memlock-gated
    guard cannot appear without a registry row, and a dead row cannot linger.
    It deliberately does NOT red the suite when memlock is missing — a gate
    everyone learns to ignore is worse than the silence it replaces — but it
    reports the inert guards BY NAME, and fails under
    `XPF_REQUIRE_MEMLOCK_GUARDS=1` so a privileged leg cannot silently stop
    executing them.
    **The registry is the fallback, not the remedy.** Ask first whether the test
    needs a real BPF map: #8370 moved four of its own below the privilege
    boundary through the `fakeCtrlMap` seam (added by #5486 for this reason) and
    they now execute unprivileged while still asserting the row was never
    written.
- **NEVER `git stash` in this checkout (#8489).** The stash is a property of the
  REPOSITORY, not of a worktree. Every `.claude/wt-*` and `/var/tmp/*` worktree
  on this box shares ONE stack, and several agents run concurrently in different
  worktrees — so a `push` races every other lane's `pop` and `drop`, and neither
  side gets a signal.

  Three incidents, and the third is a different shape from the first two. The
  first two were bad POPs — a lane popping another lane's entry. The third was a
  silent loss on the WRITE side:

  ```
  git stash push -u -m "lane7699-overreach" -- userspace-dp/src/server/tests.rs
  # exit 0. The file WAS reverted in the working tree.
  git stash list --format='%gd %H %gs' | grep lane7699-overreach   ->   no match
  ```

  The entry was never findable. No work was lost only because the edit had been
  generated by a script that still existed on disk. The stack held 31 entries at
  the time and its top TWO were both rescue markers from previous stash
  accidents.

  **A push that exits 0 and creates no entry is indistinguishable from a
  successful one at the call site** — the codebase's recurring failure shape,
  arriving in a place where the cost is someone's uncommitted work.

  Use a patch file. Same cost, cannot be reaped by another worktree, and its
  existence on disk IS the verification, which is why this is a substitution
  rather than a check:

  ```
  git diff -- <paths> > /var/tmp/<lane>/setaside.patch
  git checkout -- <paths>
  # later
  git apply /var/tmp/<lane>/setaside.patch
  ```

  For work set aside wholesale, a temporary WIP commit on the lane's own branch
  is unaffected by any of this and remains the guidance.

  And note the interaction with the restore rule above: **`git checkout --` is a
  RESTORE when your work is committed and a DELETION when it is not.** The
  patch-file recipe is safe because the patch is written FIRST; running the
  `checkout` half alone destroys the edit.

  `scripts/no-git-stash-selftest.sh` keeps the tree itself free of the hazard.
  Today no tracked script uses `git stash`; the selftest exists so that stays
  true, because a harness that stashes would expose every lane to it silently.

- **Shared-cluster lock protocol (#1875).** The loss userspace cluster
  is shared by concurrent agents; ownership is serialized by the
  advisory flock on `/tmp/xpf-cluster.lock` with holder metadata in
  `/tmp/xpf-cluster.owner`. Who locks what:
  | Actor | Protocol |
  |---|---|
  | `cluster-setup.sh` deploy/start/stop/restart/create/destroy/init | self-locks (re-execs through `with-cluster.sh`; the build stays outside the lock) |
  | `apply-cos-config.sh` | self-locks the same way |
  | Destructive HA smoke (`test-failover`, `test-ha-crash`, `test-double-failover`, `test-stress-failover`, `test-chained-crash`, `test-active-active`, `test-restart-connectivity`, `test-private-rg`) | self-locks the same way via the `cluster-cell.sh` preamble (#4020) — a reboot / force-stop / failover QUEUES behind a held lock instead of colliding with a concurrent deploy/smoke. Read-only `test-connectivity.sh` stays lock-free |
  | Multi-command measurement cells (deploy → apply-cos → measure) | wrap the WHOLE cell: `./test/incus/with-cluster.sh "purpose" -- cmd...` |
  | `wg-interop.sh` | self-locks per command standalone; runs lock-free inside a cell (marker-aware) |
  | Ad-hoc one-liners around commands that do NOT self-lock | `flock /tmp/xpf-cluster.lock sg incus-admin -c "..."` still valid |
  Rules that keep the mutex sound:
  - **Never wrap a self-locking script in a raw outer
    `flock /tmp/xpf-cluster.lock`** — it deadlocks (the inner acquire
    cannot see a raw caller's lock). Use `with-cluster.sh`, whose
    `XPF_CLUSTER_LOCK_HELD=<lockpath>:<pid>` marker (validated by
    path + pid liveness + ancestry) makes nesting safe.
  - **Never `rm` the lock or owner files.** flock binds the inode —
    deleting the path silently splits the mutex into two "owners".
    Stuck holder recovery is `kill <holder-pid>` (kernel releases the
    lock on fd close), and only for YOUR OWN holders.
  - **Never kill another agent's holder.** The lock serializes you:
    wait (the wait loop prints who holds it, since when, and why,
    every 30s) or coordinate. `XPF_CLUSTER_LOCK_TIMEOUT=<s>` opts a
    cell into fail-fast instead of waiting forever.
  - **Never hand-roll binary deploys** (`incus file push` + restart
    loops) to the cluster — they bypass the lock AND the #1864/#1869
    verify-dataplane gate. Deploys go through `cluster-setup.sh
    deploy` / `make cluster-deploy`. The same gate now runs on the
    standalone `setup.sh deploy` path too (#6493), so `make
    test-deploy` is no longer the one binary-swap route that can put
    a verifier-rejected shim on a box and report success.
  - **Destructive HA smoke self-locks (#4020).** A `test-failover`
    that reboots a node mid-iperf is FAR more disruptive than a
    deploy, so the reboot/force-stop/failover smoke scripts share the
    `cluster-cell.sh` preamble (`xpf_enter_destructive_cluster_cell`):
    they re-exec through `with-cluster.sh` and QUEUE behind a held
    lock rather than colliding with a concurrent agent's deploy/smoke.
    Add a new destructive smoke script by sourcing `cluster-cell.sh`
    in its preamble; the `make test-cluster-lock-lib` self-test (also
    covers the `with-cluster.sh` contention matrix) asserts every
    destructive script takes the lock before it mutates a node and
    fails RED if one drops the wiring. No cluster needed — private
    lock path, mocked incus.
  - **A worktree with a QUEUED or RUNNING cluster cell is off-limits.** The
    cell verifies the TREE it finds when the lock is granted, not the branch
    name it was launched from, and a lock wait can be tens of minutes. Amend
    during that window and you smoke-test one tree while shipping another —
    with logs identical to a correct run. #7480 amended during a ~20 minute
    wait; the cell recorded a different HEAD than the PR carried, and the
    result transferred only because that diff happened to be comments-only
    (`git diff <tested> <head>` → zero non-comment lines). That is luck, not
    method. Kill the cell and re-launch if you must amend, and echo the tested
    HEAD from inside the cell so the two can be compared afterwards.
  - **The lock serialises ACCESS, not the ARTIFACT — verify the BUILD you
    are measuring.** The bullet above is about your own tree changing under
    a queued cell; this is its mirror image, and it bites without any
    mistake on your part. A lane waited ~5 minutes for the lock, never
    touched the holder, acquired cleanly, and measured a binary another
    lane's deploy had installed moments earlier — whose subject was the
    very code path under test. Every lock-level check said clean. The only
    tell was a CLI banner reading `uptime: 1m46s` for a daemon it believed
    it had deployed hours before, and the same lane had the build change
    under it a SECOND time in a later cell. Two runs of careful,
    plausible-looking numbers described the wrong binary.
    `with-cluster.sh` now records the deployed `xpfd` sha per node at
    acquire and reports a change at release (`cluster-build-identity.sh`).
    The boundary report is ADVISORY — a cell that deploys on purpose
    re-baselines (`xpf_cluster_rebaseline_build`, wired into
    `cluster-setup.sh`'s deploy), and an unwired path that legitimately
    replaces the binary must not break a working target for a diagnostic.
    A MEASUREMENT should call `xpf_assert_cluster_build_unchanged`
    immediately before it samples: that fails hard, and it fails on
    "cannot tell" as well as on a change, because a measurement that
    cannot name its subject is not evidence. `XPF_CLUSTER_BUILD_STRICT=1`
    promotes the boundary report to fatal. Covered by
    `make test-cluster-lock-lib` (mocked incus, no cluster).
  - **`incus exec` reads its stdin (#9683).** Inside a loop fed on stdin
    (`while read -r x; do ...; done <<<"$list"`, `... | while read`,
    `done < file`), an `incus exec` without `-n` forwards the loop's input
    to the remote command. The FIRST call drains the rest of the list, and
    the body runs once, silently, exit 0. Measured: the post-deploy
    reassert transferred only RG0, so every deploy that needed RG1/RG2
    back failed as "node0 is not primary for every redundancy group"; and
    the build-identity probe above sampled only FW0. Use `incus exec -n` in
    any such loop. A mock `incus` that ignores stdin cannot see this, so
    the deploy-lib and build-identity self-test mocks drain stdin unless
    `-n` is given, like the real client.
  - Queue diagnosis: `cat /tmp/xpf-cluster.owner` +
    `fuser -v /tmp/xpf-cluster.lock`. A dead recorded pid with the
    lock still held means a child inherited the fd (pre-#1875 raw
    holders only; `with-cluster.sh` runs cells with the lock fd
    closed, so killing a cell's tree releases instantly).
- **Raw/datagram sockets go through `pkg/linuxsock` (#2608).** A raw
  `unix.Socket(2)` is NOT close-on-exec by default (unlike Go `net`
  sockets), so a bare raw `AF_PACKET`/raw-ICMP/datagram fd leaks into
  every helper the daemon fork-execs (`frr-reload.py`, `swanctl`, DHCP
  helpers) — an fd leak and a raw-frame security boundary. Use
  `linuxsock.Socket(domain, typ, proto)` (ORs `SOCK_CLOEXEC` atomically
  into the type), never `unix.Socket` directly. `pkg/linuxsock`'s
  `TestNoDirectUnixSocket` canary scans every production `.go` under
  `pkg/` and fails the suite on a new direct call site (the one
  justified exception, `pkg/vrrp`'s pre-#2476 receiver, is allowlisted
  and pinned by its own `afpacket_cloexec_test.go`).
- **Always `source ~/.sshrc` before `git push`.** The user's SSH agent
  config lives there.
- **172.16.80.200 is the iperf3 test endpoint.** Not 172.16.50.x.
- **Use `cli`, not `xpfctl`.** The remote CLI binary is `cli`.
- **Primary is fw0 on RG0 in the loss userspace cluster.** Apply config
  changes to the primary; sync takes care of the secondary.
- **`make build` does NOT require `make generate` (#1864).** The
  git-tracked `pkg/dataplane/userspace_xdp_bpfel.o` is the deployable
  artifact; only regenerate it when `userspace-xdp/` source changes.
  Regeneration requires the PINNED toolchain
  (`userspace-xdp/rust-toolchain.toml` + the bpf-linker pin in
  `pkg/dataplane/build-userspace-xdp.sh`) and passes a kernel-verifier
  verify-then-install gate — an unpinned nightly once produced an
  object that blew the 1M-insn verifier cap and took both cluster
  dataplanes down. Never commit a regenerated `.o` unless the gate
  PASSed and `git diff --exit-code pkg/dataplane/userspace_xdp_bpfel.o`
  is clean after a pinned re-run. Recovery from a bad artifact:
  `git checkout -- pkg/dataplane/userspace_xdp_bpfel.o && make build`.
- **The shim has TWO budgets, and BPF's five-argument call limit is a
  design constraint on both (#8249).** Processed instructions are the one
  every gate here measures; the other is **512 bytes of stack COMBINED
  across a call path**, pinned by
  `pkg/dataplane/shim_stack_margin_8249_test.go`. The lever for the stack
  budget is usually OUTLINING work out of the entry program rather than the
  scratch maps CLAUDE.md suggests — check what the frame is made of first,
  because the shim's was over half register spills with no large named
  object to move.

  Outlining runs into the limit immediately: **a bpf-to-bpf call takes at
  most FIVE arguments**, and the useful helper almost always wants six. It
  has been rediscovered three times. **Do not pack two values into a wider
  word to get under it** — #5173 exists because nothing rejects a REDUCTION
  of the interface coordinate by type, and a pack/unpack pair is a new site
  for exactly that. Move a cheap scalar out of the call instead (#8625
  stores `pkt_len` after the call rather than passing it, so both
  coordinates still travel as bare u32s).

  **A "revert the fix" mutation on the shim is silently vacuous whenever
  the mutant fails to verify (#8249).** `make generate` is verify-then
  -install: a candidate the kernel verifier rejects is correctly NOT
  installed, so the tracked `.o` stays at the previous — working —
  object, and `make test-shim-run` loads that. The mutation then reports
  a clean PASS, which reads as the mutation ESCAPING: the most alarming
  possible result, and the one most likely to be chased rather than
  distrusted. The gate is doing its job; it just makes a whole class of
  mutation meaningless without saying so.

  Two remedies, both cheap. **A sound shim mutation must produce a
  VERIFIABLE object with the defect restored** — reverting the whole
  change does; removing one guard from a fix often does not, because the
  guard was also pruning verifier state. And **assert the object md5
  moved** before believing any shim measurement, mutation or otherwise:
  a stale object answers every question confidently and with the wrong
  build.

  And **sharing duplicated code between subprograms is not generically
  profitable here.** Sharing an inner map lookup between the two GRE
  classifiers saved 23,181 instructions; sharing the port-parse beside it
  the same way COST 6,652, because passing a `&mut` to a stack struct
  through the call verifies worse than the duplicated inline code. Measure
  each one — the sign is not predictable from the shape.
- **Before claiming a CoS admission-path PR moves a metric, read the
  counters.** `show class-of-service interface` surfaces `flow_share`,
  `buffer`, and `ecn_marked` drop counts per queue since #724. See
  [`cos-validation-notes.md`](cos-validation-notes.md) for the
  methodology, the decision tree mapping counter patterns to fixes,
  and the current test-env limitation that blocks ECN end-to-end
  validation. Iterating on admission logic without reading these
  counters is how #721/#722 landed dormant on the live workload
  (#725).

## Tone signals (patterns that have worked)

- "The honest fix is..." → frame the real engineering tradeoff, not
  the easy one.
- "I would either ... or ..." → offer options in reviews, don't
  dictate.
- "I would not silently land ..." → insist on explicit agreement for
  operator-visible changes.
- "Behaviour choice, not a bug fix" → scope discipline in one phrase.
- "Does not recreate the old failure mode" → test-strength review in
  one phrase.
