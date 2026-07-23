# Codex hostile plan-review — #6371 r6 (VERDICT: PLAN-NEEDS-REVISION)

Concurrency BLOCKER CLOSED (linearization invariant sufficient); §5.4 residual analysis correct. Only 5 narrow plan-text-consistency defects remained (fixed in r7).

---

R6 closes the concurrency blocker, but the artifact still needs a narrow revision—no architectural redesign.

- The §5.2 linearization invariant is sufficient if the single apply gate orders generation advancement, validation, and the complete map/helper mutation. A check-then-unlock implementation would violate the stated invariant and retain a TOCTOU race, but that would be an implementation bug, not missing plan design.
  - G clear vs G+1 activation: either clear lands first and activation supersedes it, or activation advances the generation and the stale clear is dropped.
  - G activation vs G+1 peer-fence: either activation completes first and the fence clears it, or the fence advances the generation and drops the old activation.
  - Current-generation readback and surviving tombstones correctly prevent stale debt retirement.

- §5.4’s substantive residual analysis is now correct. The map-write failure returns at [manager_ha.go:638](/home/ps/git/bpfrx/.claude/worktrees/6371-research/pkg/dataplane/userspace/manager_ha.go:638) before manager/helper mutation; retries and alarms detect but cannot terminate persistent failure.

Remaining plan defects:

1. [plan.md:135](/home/ps/git/bpfrx/.claude/worktrees/6371-research/docs/research/6371-rgactive-fence/plan.md:135) still says §5.2 “closes … persistent modes,” directly contradicting §5.4’s detected-but-unfixed disclosure. This is residual r5 factual contradiction, not new scope.

2. The plan requires a follow-up “filed now” but provides no issue ID/link, and calls the residual “accepted” while its accepting signer remains pending. If the issue exists, link it; otherwise make acceptance explicitly conditional.

3. [plan.md:220](/home/ps/git/bpfrx/.claude/worktrees/6371-research/docs/research/6371-rgactive-fence/plan.md:220) says “log + proceed helper-unarmed,” conflicting with §5.1’s abort-or-retain-suppression-gate contract. Explicitly say proceeding retains the replay/poll/watchdog gate until quarantine succeeds.

4. [plan.md:281](/home/ps/git/bpfrx/.claude/worktrees/6371-research/docs/research/6371-rgactive-fence/plan.md:281) retains “up-to-30 s,” contradicting the correctly stated ≥30-second floor.

5. Minor locator error: `manager_ha.go:635` should be `638–640`.

Gate wiring, test barriers, snapshot locking, alarm threshold, and signer selection remain legitimate `/engineer` details. The listed corrections are small, but factual consistency and the plan’s own residual-acceptance prerequisite are not yet satisfied.

VERDICT: PLAN-NEEDS-REVISION
