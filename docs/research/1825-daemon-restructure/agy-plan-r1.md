I will view the plan file from the specified worktree path.
I will list the files in the `pkg/daemon` directory of the worktree to verify the structure and locate the daemon type definition.
I will view `daemon.go` around line 66 to verify the definition of `type Daemon struct` and check its field count.
I will view the rest of the Daemon struct definition to count the total number of fields.
I will view the remaining fields of the `Daemon` struct.
I will view the rest of the fields of the `Daemon` struct.
I will execute a python analysis script to verify the exact numbers of Daemon fields, methods, and unexported selectors in the production files of the `pkg/daemon` package.
I will run a python snippet to debug why the method count was 0 and list some method declarations to inspect their formats.
I will run the corrected python script using `re.M` (multiline) flag, and print the methods it finds to ensure accurate verification.
I will run a python script to count all unexported and exported selector spellings on `d` to verify the exact number of unique fields/selectors accessed in the package.
I will run a python script to count the total lines of code (LOC) of these 30 production files to verify the 14,263 LOC figure.
I will run a python script to count total Go files and total LOC, as well as test files and test LOC, to verify the remaining file and line metrics.
I will view the `go.mod` file in the worktree to identify the module path.
I will search for imports of the `pkg/daemon` package across the entire codebase (excluding `pkg/daemon` itself and any files outside the package) to verify its importers.
I will view `cmd/xpfd/main.go` to verify the three identifiers (`daemon.New`, `daemon.Options`, `daemon.CleanupFabricIPVLANs`) referenced in the plan.
I will search git commit logs for comments, fixes, or commits mentioning "mutex", "lock", "deadlock", "race", or "wrong file" in `pkg/daemon` to see if the flat structure has historically led to bugs.
I will query the recent commit history in `pkg/daemon` to check for lock/race related bugs.
I will search for `refactoring-audit-current.txt` in the worktree to see if there are any listed refactoring priorities or warnings about `pkg/daemon`.
I will search for `refactoring-audit` files in the repository using the absolute path.
I will view `docs/refactoring-audit-current.txt` to verify the claim that there are zero `pkg/daemon` entries in the audit.
I will check the line count of `pkg/daemon/daemon_run.go` in the worktree.
I will query the local git branches to confirm the active in-flight work mentioned in the plan.
I will check for any references to the `Daemon` type in the test files for rss_indirection and coalescence to verify Option C's test coupling claims.
I will check if the production files `rss_indirection.go` and `coalescence.go` refer to `Daemon`.
I will locate all the function definitions in `rss_indirection.go` and `coalescence.go` to see which ones are unexported and if they are accessed from other files in `pkg/daemon`.
I will search the `pkg/daemon` directory for references to `applyCoalescence` and `applyRSSIndirection` to verify their usage in other files.
I will search for `applyRSSIndirection` references.
I will search for references to `restoreDefaultRSSIndirection` to verify if it is one of the references in the `pkg/daemon` package.
I will search for `coalescenceMatches` references in `pkg/daemon` to check if it is called from outside `coalescence.go`.
I will view the contents of `pkg/daemon/daemon_dhcp.go` to see the exact coupling of the DHCP methods to the `Daemon` fields.
### Verdict: `PLAN-READY(D)`

The plan to **KILL the package restructure (Option D)** and maintain a flat package layout for `pkg/daemon` is sound, realistic, and recommended. The refactoring is net-negative value when weighed against the severe risk of behavioral regressions and merge conflicts with active in-flight features.

---

### 1. Structural Blocker Verification
The plan's metrics on the daemon's size and coupling are correct down to the single digit:
* **Fields**: The `Daemon` struct in [daemon.go:66-325](file:///home/ps/git/bpfrx/.claude/worktrees/research-1825-daemon/pkg/daemon/daemon.go#L66-L325) has exactly **116 fields**.
* **Methods**: There are exactly **167 receiver methods** defined on `*Daemon` or `Daemon` across the 30 production files.
* **Selectors**: There are exactly **272 unique selector spellings** accessed on receiver `d` (269 unexported lowercase, 3 exported uppercase).
* **Blocker Severity**: Because Go forbids cross-package method declarations, moving files to subpackages (`ha/`, `neighbor/`, `apply/`) is blocked. Decomposing `Daemon` into smaller state structs or introducing wide bidirectional interfaces (e.g. ~20 methods for the neighbor cluster alone) is a full rewrite of the daemon's locking, synchronization, and testing seams, exposing the codebase to massive regression risk.

---

### 2. Value Claim Verification
* **Single Importer**: The only package importing `pkg/daemon` is `cmd/xpfd/main.go` ([main.go:13](file:///home/ps/git/bpfrx/.claude/worktrees/research-1825-daemon/cmd/xpfd/main.go#L13)). It consumes exactly **3 identifiers**:
  1. `daemon.CleanupFabricIPVLANs` ([main.go:38](file:///home/ps/git/bpfrx/.claude/worktrees/research-1825-daemon/cmd/xpfd/main.go#L38))
  2. `daemon.New` ([main.go:128](file:///home/ps/git/bpfrx/.claude/worktrees/research-1825-daemon/cmd/xpfd/main.go#L128))
  3. `daemon.Options` ([main.go:128](file:///home/ps/git/bpfrx/.claude/worktrees/research-1825-daemon/cmd/xpfd/main.go#L128))
* **Dry Audit**: As verified in [docs/refactoring-audit-current.txt](file:///home/ps/git/bpfrx/.claude/worktrees/research-1825-daemon/docs/refactoring-audit-current.txt), there are zero `pkg/daemon` entries. The largest file, `daemon_run.go`, contains exactly **1,417 lines** ([daemon_run.go:1-1417](file:///home/ps/git/bpfrx/.claude/worktrees/research-1825-daemon/pkg/daemon/daemon_run.go)), which remains safely below the 1,500 line watch threshold.
* **Flatness Cost**: Navigability is fully solved by the existing naming prefixes (`daemon_ha_*`, `daemon_neighbor_*`, etc.). There is no historical evidence in `docs/bugs.md` or git logs showing wrong-file edits, lock-ordering bugs, or scope leaks caused by package flatness.

---

### 3. Cost Table Integrity (Options A / B / C)
The cost and merge-conflict estimates are accurate. Even for the cleanest leaf-extraction candidate under **Option C** (`nictune` containing `coalescence.go` and `rss_indirection.go`):
* The files reference `priorHostTunables`, which is defined as an unexported struct in [host_tunables.go:50](file:///home/ps/git/bpfrx/.claude/worktrees/research-1825-daemon/pkg/daemon/host_tunables.go#L50).
* Extracting them would cause a circular dependency because `pkg/daemon` must import `nictune` to call `applyCoalescence` ([coalescence.go:55](file:///home/ps/git/bpfrx/.claude/worktrees/research-1825-daemon/pkg/daemon/coalescence.go#L55)) and `applyRSSIndirection` ([rss_indirection.go:144](file:///home/ps/git/bpfrx/.claude/worktrees/research-1825-daemon/pkg/daemon/rss_indirection.go#L144)), preventing `nictune` from importing types back from `pkg/daemon`.
* This necessitates type hoisting and export expansion, creating churn for zero structural or operational payoff.

---

### 4. Section 12 Open Questions

* **Q1 (Defect Class)**: **No.** Lock-coordination, loop freezes, and state machine transition bugs are logical concurrency bugs. Splitting the package would worsen coordination by forcing channels or exported accessor overhead, rather than resolving it.
* **Q2 (Pure-Function Seam)**: **No.** Moving pure leaf functions does not clean up the flat directory since the 167 stateful daemon receiver methods (which do the heavy lifting) must remain in the parent package.
* **Q3 (DHCP Glue Coupling)**: **Representative.** Although small (216 lines), `daemon_dhcp.go`'s methods ([daemon_dhcp.go:75](file:///home/ps/git/bpfrx/.claude/worktrees/research-1825-daemon/pkg/daemon/daemon_dhcp.go#L75), [daemon_dhcp.go:108](file:///home/ps/git/bpfrx/.claude/worktrees/research-1825-daemon/pkg/daemon/daemon_dhcp.go#L108)) tightly access 7 fields and lifecycle hooks of the `Daemon` context, rendering clean extraction impossible.
* **Q4 (Wedge `internal/nictune`)**: **Reject.** Do not ship `internal/nictune`. It would serve as a dead-end demonstrator since stateful subsystems cannot follow it, and it conflicts with active in-flight timeout boundary work. Organic leaf extractions should follow the `pkg/daemon/system` precedent.
* **Q5 (Defer vs. Kill)**: **Kill.** This issue should be permanently closed as **KILLED**. Deferring suggests that there is a future queue state where the refactor makes sense. Because of Go's package method constraints and the 116-field struct, the cost-benefit ratio will never become positive.
* **Q6 (Future Consumers)**: **No change.** Even if a test harness or second binary imports `pkg/daemon` in the future, it only interacts with the exported surface. Internal flatness does not affect public visibility.
