# Three-way adversarial research review

Use for research conclusions and every supplied claim, not only solution plans.
The three actual reviewers are **Codex + AGY + Claude subject-matter review
(SMR)**. The coordinator synthesizes their evidence; it is not one of the three
independent passes. Three personas in one agent or three copies of its conclusion
do not satisfy this gate. Implementation review later runs the declared-pool triple gate through `/engineer`.

## Assign the question and expertise

Pin the question, claim IDs, source/comparison revisions and evidence-bundle
revision. Batch related claims when useful, but keep a per-claim coverage matrix:
claim/conclusion ID, each reviewer's task/model identity, reviewed revision,
proposed disposition, decisive evidence, dissent and remaining check. Every supplied
claim needs all three passes, including proposed NEG, FIXED, STALE and DUP outcomes.
For a general question, review the material conclusions and alternatives without
inventing a defect ledger, full audit or implementation plan.

All three must challenge both false acceptance and false dismissal. Assign
explicit complementary lenses rather than relying on provider diversity:

- **Subject matter and defensive boundaries:** Linux kernel/NIC datapath,
  networking/firewall semantics and the affected domains from the entrypoint;
  supported reachability, actor/fault assumptions, actual guards, alternate paths,
  ownership and lifecycle transitions. Adversarial reasoning stays defensive:
  source analysis and benign local checks, never exploit construction/live probes.
- **CPU architecture and high-performance systems:** cache/NUMA/layout, SIMD,
  branches, atomics/orderings, allocation, contention and scaling; distinguish
  source-proven costs from measured throughput, latency or connection capacity.
- **Software design and evidence quality:** contracts, coupling, all affected
  consumers, recovery and testability; whether observations actually measure the
  claim, independent oracles/controls, and whether the purported refutation covers
  the same state and path. A passing test or a nearby guard is not enough.

Record the lead reviewer for each relevant lens. These are not exclusive silos:
each reviewer checks the overall claim and can challenge any premise. Mark
irrelevant expertise with a reason, not invented hardware claims or credentials.

## Independent first passes, then evidence-led reconciliation

1. Give each reviewer the raw question/claims and inspectable evidence without
   the originating model, the coordinator's preferred disposition, or the other
   reviewers' conclusions. Preserve authoritative source identities, versions and
   required context; blind author/model prestige, not the evidence itself.
2. Ask for the strongest supported defect/conclusion, the strongest supported
   refutation or alternative, and the decisive unresolved check. A hostile review
   challenges premises in both directions; it is not an objection quota or a
   request to reject everything. Reviewers may identify a narrower valid claim.
3. Collect actual results before synthesis. For code claims use the shared gate
   dispositions; general conclusions get supported/refuted/unresolved reasoning.
   All three must cover the same claim and relevant evidence revision before its
   disposition is final. Agreement without sufficient primary evidence proves
   nothing. A missing pass is not an approval, and silence is not a dismissal.
4. Reconcile substantive dissent with evidence, revise the claim/evidence revision,
   and rerun affected passes. Require all three to support the final bounded
   factual disposition; do not majority-vote away a contrary guard or a real
   residual. Severity-only dissent need not block filing a defect all three agree
   exists: use the supported conservative impact and retain the disagreement.
   Unresolved factual disagreement stays NEEDS_VALIDATION with the next check.
5. Release individually completed findings to the coordinator for filing under
   the entrypoint's default. Missing reviews on another claim do not hold them
   back. A known uncertainty is reportable; do not falsely mark the uncertain
   claim confirmed or dismissed just to finish the run.

Discover available review tools instead of copying historical paths or model
defaults. Record actual task ID, role/host, evidenced model/source, scope and
reviewed revision in the run manifest. Save each round's raw reviewer output
under the owned run directory using its actual reviewer identity; a GPT pass
must not be named Claude. Delegated reviewers have no filing authority.

An unavailable reviewer leaves a named gap: retain the evidence/report and pursue
other ready findings. A substitute or reduced-review exception requires explicit
user approval and must be recorded, not quietly renamed into a missing slot.
For a genuine infrastructure failure, retry through fresh supported tasks and
record failures; after three consecutive matching failures stop that lane and
report the blocker. A still-running task is not a failure. Use supported waits,
keep user updates flowing, and never evade access or safety restrictions.

## Keep finding validation separate from solution approval

File a validated defect even if its proposed solution is rejected, unaffordable,
or awaiting a plan reviewer. State a corrective direction and acceptance criterion
without claiming the plan is approved. Rejected solutions cannot turn a defect NEG
or authorize closing its issue.

If a substantial plan is requested, apply [plan review](plan-review.md). The same
three reviewers can continue into planning, but must produce distinct finding and
plan verdicts against their respective revisions. A finding pass does not approve
a plan; a PLAN-KILL does not refute the finding. Implementation still requires
the user's later manual approval.
