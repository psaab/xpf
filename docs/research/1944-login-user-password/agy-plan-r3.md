I will list the files in the directory `docs/research/1944-login-user-password/` to locate the plan document and other review-related files.
I will view the contents of the plan file `docs/research/1944-login-user-password/plan.md` to review the current revision (r3).
I will list the current permissions to see if git commands are already approved.
I will run the git diff command to verify what changes exist in the branch compared to `origin/master`.
I will check the git status to see if there are any modified files or changes that aren't visible in the short status.
I will run git log to check the recent commit messages on the current HEAD.
I will run `git diff` to see if there are any uncommitted changes in the workspace.
I will run `git branch -a` to list all branches in the repository.
I will check the latest commit of the branch `origin/research/1944-login-user-password` to see if it matches our HEAD.
I will check out the `research/1944-login-user-password` branch to make sure we are reviewing the latest revision (r3).
I will view the `plan.md` file in the worktree where the `research/1944-login-user-password` branch is checked out.
I will search for `useradd` in `pkg/daemon/daemon_system.go` to see how users are created and if there is any existing metadata (like comments or specific UIDs) we can use.
I will run the grep search again with `MatchPerLine: true` to see the actual matching lines in `pkg/daemon/daemon_system.go`.
I will view the `pkg/daemon/daemon_system.go` file around line 656 to understand the user provisioning logic.
# Hostile Plan Review: Issue #1944 — `system login user` encrypted-password

## Verdict: `PLAN-NEEDS-WORK`

The proposed revision **r3** of the plan document [docs/research/1944-login-user-password/plan.md](file:///home/ps/git/bpfrx/.claude/worktrees/1944-research-login-user-password/docs/research/1944-login-user-password/plan.md) successfully resolves the three findings raised in the **r2** review. However, the introduction of the new provenance marker mechanism introduces a migration defect and a stale-marker lockout risk that must be addressed before the plan is marked ready.

---

## Verification of Past Findings (Resolved)

### Finding-1: `isLockedShadow` treats empty as locked
* **Status: Resolved**
* **Evidence:** In [plan.md:L245-249](file:///home/ps/git/bpfrx/.claude/worktrees/1944-research-login-user-password/docs/research/1944-login-user-password/plan.md#L245-L249):
  > `- **isLockedShadow(s)** returns true ONLY for an actually-locked field: s == "*" || strings.HasPrefix(s, "!"). An empty field is passwordless (passwd -d), the MOST permissive state — NOT locked, so D2 locks it...`
* **Analysis:** Empty fields (`""`) are no longer treated as locked. This ensures passwordless accounts will be locked under declarative reconciliation (D2), resolving the original lockout concern.

### Finding-2: Shared validator rejecting bare `*` / `!` sentinels
* **Status: Resolved**
* **Evidence:** In [plan.md:L277-282](file:///home/ps/git/bpfrx/.claude/worktrees/1944-research-login-user-password/docs/research/1944-login-user-password/plan.md#L277-L282):
  > `3. **Explicit lock sentinels**: a bare *, !, or !! (r2/S2-3, AGY Finding-2). These are the intentional Unix way to lock an account and are the ONLY way to lock root via root-authentication encrypted-password "*"...`
* **Analysis:** The validator now explicitly accepts bare sentinels, meaning root can be locked through configuration (since root is excluded from D2 auto-locking).

### Finding-3: `getent shadow` NSS caching
* **Status: Resolved**
* **Evidence:** In [plan.md:L241-244](file:///home/ps/git/bpfrx/.claude/worktrees/1944-research-login-user-password/docs/research/1944-login-user-password/plan.md#L241-L244):
  > `- **currentShadowHash(name) (string,bool)** reads /etc/shadow directly (daemon is root), line-parses field 2... NOT getent shadow — that shells out and is subject to nscd/NSS caching → stale reads...`
* **Analysis:** Direct reads of `/etc/shadow` bypass NSS caches, preventing daemon apply from acting on stale data.

---

## Analysis of New r3 Mechanisms

### (a) Pure `passwordAction` Helper (Sound)
The helper functions correctly and cleanly implements the required fail-open/fail-closed asymmetry:
* **Fail-open for configured password (`desired != ""`)**: If shadow read fails (`ok == false`), it returns `pwApply`, forcing the daemon to attempt to write the desired password and preventing operator lockout.
* **Fail-closed for unconfigured password (`desired == ""`)**: If shadow read fails (`ok == false`), it returns `pwNoop`. The daemon will not attempt to lock the account, preventing accidental lockout from transient read errors.

---

### (b) Provenance Marker `/var/lib/xpf/provisioned-users/<name>` (Unsound Lifecycle)

We identified two major defects in the proposed marker lifecycle:

#### 1. Transition/Migration Bug (Active Orphans on Removal)
* **Quoted Evidence:** In [plan.md:L250-252](file:///home/ps/git/bpfrx/.claude/worktrees/1944-research-login-user-password/docs/research/1944-login-user-password/plan.md#L250-L252):
  > `- **Provenance** (r2/S2-2, Codex New-Fatal-2): on useradd success drop a marker /var/lib/xpf/provisioned-users/<name> (dir 0700); xpfProvisioned(name) checks it.`
* **Defect:** If a user was provisioned by an older version of xpf, the marker file will not exist. If the operator subsequently configures a password for this user (which writes it to shadow via `pwApply`), and later removes the `encrypted-password` directive, `pwLock` will be skipped because `xpfProvisioned` returns `false`. This leaves an active orphan credential in `/etc/shadow`.
* **Resolution:** Drop the marker file on **both** successful `useradd` and successful `pwApply` (any password write from xpf makes it managed/provisioned).

#### 2. Stale Marker Leakage (Out-of-Band User Lockout)
* **Quoted Evidence:** In [plan.md:L250-253](file:///home/ps/git/bpfrx/.claude/worktrees/1944-research-login-user-password/docs/research/1944-login-user-password/plan.md#L250-L253):
  > `on useradd success drop a marker /var/lib/xpf/provisioned-users/<name> (dir 0700); xpfProvisioned(name) checks it. pwLock runs ONLY for provisioned accounts — never locks a pre-existing out-of-band account referenced in config.`
* **Defect:** If a user is removed from the xpf configuration, the marker file `/var/lib/xpf/provisioned-users/<name>` is left orphaned. If the operator manually deletes the user from the OS (`userdel`) and recreates them out-of-band with a password, and later references the user in the config again *without* `encrypted-password` (e.g., to manage SSH keys), the stale marker will cause xpf to lock their password, locking out the out-of-band user.
* **Resolution:** Garbage collect markers. When `applySystemLogin` runs, it should scan `/var/lib/xpf/provisioned-users/` and delete any marker files for usernames that are no longer present in `cfg.System.Login.Users`.
