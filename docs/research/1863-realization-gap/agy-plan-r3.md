An adversarial review spot-check of the latest commit (`7c340eee6`) on branch `research/1863-realization-gap` in `/home/ps/git/bpfrx/.claude/worktrees/1863-research` has been completed.

### Analysis of the Diff (Commit `7c340eee6`)

The commit rewrites exactly the three stale passages identified by Codex r2 to align the text with the **Finding 2 (Mandatory Step-0 Attribution Instrument)** requirement:

1. **Section 4.2 tail**:
   - *Previous state*: Suggested the split between worker demand mismatch (a) and sampling loss (b) was only measurable "if needed" and could be derived at "fix-validation time."
   - *Current state*: Explicitly states that resolving this split is **MANDATORY** before any fix is coded, using the Path-A Step-0 instrument and decision rule (rather than deferring it).
2. **Section 8 (Pooled grant metrics)**:
   - *Previous state*: Wrongly asserted that existing class-level send counters and single-knob configurations established per-class grant identity.
   - *Current state*: Corrects this to note they only establish a "worker-pooled implication." It explicitly states that the per-class grant identity is **NOT** established by existing counters and requires the Step-0 instrument to capture it.
3. **Section 9 (Open questions, Q3)**:
   - *Previous state*: Left Q3 open, asking if the split was worth a pre-fix instrument or if validation-time derivation was sufficient.
   - *Current state*: Formally marks Q3 as **RESOLVED (round 1)**, concurring with all three reviewers that the pre-fix instrument is mandatory and validation-time derivation is insufficient.

### Risk & Alignment Assessment

- **Logical Alignment**: The changes are highly targeted and strictly enforce the reviews' mandate. They eliminate any ambiguity or loop-holes that could have led an engineer to skip the Step-0 telemetry instrument and write code for `A-ii` blindly.
- **Operational Safety**: Requiring the telemetry instrument pre-coding acts as a critical fail-fast gate. If the instrument reveals that worker demand mismatch (a) is dominant, it prevents the team from implementing the `A-ii` carry-over logic, which would fail to solve the undergrant problem and could introduce latency regression under load.
- **Complexity**: The instrument's scoped nature (with a pre-registered decision rule and a plan to clean up or keep it at fix-delivery time) avoids long-term technical debt.

The diff strengthens the plan, eliminates internal contradictions, and aligns the implementation sequence with the validated design invariants.

### Verdict
**PLAN-READY**
