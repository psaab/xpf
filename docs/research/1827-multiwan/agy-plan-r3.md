I will start by checking if `docs/research/1827-multiwan/plan.md` exists and viewing its contents to verify the changes.
I will search for `plan.md` in the workspace to locate the correct path of the plan file.
I will search specifically under the `docs/` directory for any files containing `multiwan` or `1827` in their name.
I will check the git log of the current branch to see recent commits and understand the context of the branch diff.
I will list all files containing `1827` or `agy-plan-r2` or `plan.md` in their path.
I will check the content of `.claude/codex-review/workflows/20260529-074550-6bad9c/artifacts/plan.md` to see if it is the plan we are looking for.
I will read the last part of `.claude/codex-review/workflows/20260529-074550-6bad9c/artifacts/plan.md` to see the end of the file.
I will list all the local and remote branches to see if there is a specific branch for the 1827-multiwan feature.
I will retrieve the plan from the `origin/research/1827-multiwan` branch using `git show`.
I will write the plan file from the `origin/research/1827-multiwan` branch to a temporary file in the workspace so we can view it using `view_file`.
I will check the files inside the `docs/research/1827-multiwan/` directory in the `origin/research/1827-multiwan` branch.
I will copy the `agy-plan-r2.md` file from the `origin/research/1827-multiwan` branch to the workspace so we can inspect our previous conditions.
I will copy `codex-plan-r2.md` from the `origin/research/1827-multiwan` branch to check the Codex r2 folds.
I will read `/home/ps/git/bpfrx/agy-plan-r2.md` to review the 4 conditions we established in round 2.
I will read `/home/ps/git/bpfrx/codex-plan-r2.md` to review the Codex r2 findings and conditions so we can verify if the folds are correct and do not introduce new defects.
I will view the contents of the plan file `/home/ps/git/bpfrx/plan-1827.md` to check if it correctly folds the 4 r2 conditions and Codex's conditions.
I will delete the temporary files created to keep the workspace clean.
PLAN-READY

### Confirmations
1. **AGY r2 Condition (1) (§4.3 step 3):** Faithfully folded. Enforces strict `apply_snapshot` success before calling `BumpFIBGeneration()`, backed by a named ordering test.
2. **AGY r2 Condition (2) (§4.3 Operator-commit overlay preservation):** Faithfully folded. `applyConfigLocked` consumes the active overlay from `d.ipmon.ActiveOverlay()` via the shared `assembleFRRConfig` helper and the overlay-aware `buildRouteSnapshots`.
3. **AGY r2 Condition (3) (§4.2 item 4):** Faithfully folded. On startup, a `clear()` pass is executed over the 50-99 band, and the probe tables are flushed.
4. **AGY r2 Condition (4) (Coalescing/Throttle):** Faithfully folded. Adds a 3s minimum inter-actuation throttle on top of the 1s debounce, with a smoke flap test asserting $\le 1$ actuation per throttle window.
5. **Codex r2 Folds:** Verified correct. The per-test mark/table allocation (`0x1000 + idx`, `probe-table-base + idx`) within the 50-99 band with `TableID` collision checks, the named `PublishRouteOverlaySnapshot` API, and the `assembleFRRConfig` constructor contract introduce no new defects.
