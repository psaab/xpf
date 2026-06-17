I will first list the files in the `docs/research/1944-login-user-password/` directory to locate the plan and any other relevant revision files.
I will now view the contents of the plan file `docs/research/1944-login-user-password/plan.md` using the `view_file` tool to inspect the latest revision (r4) of the plan.
I will run `git diff origin/master...HEAD` to verify the exact changes in the branch, especially the contents of `docs/research/1944-login-user-password/plan.md` to ensure I'm looking at revision r4.
I will check the recent git commits and status of the current branch to clarify the history and see if `plan.md` has been updated recently.
I will run `git status` to see if there are any uncommitted modifications in the working directory that might have updated `plan.md`.
I will locate all `plan.md` files in the repository and `.claude` workspace directories to make sure we find the correct r4 revision.
I will check all git branches to see if there is another branch (such as a local or remote tracking branch) containing revision r4 of the plan.
I will inspect the commit log of the remote branch `remotes/origin/research/1944-login-user-password` to see if there are any newer commits that we haven't checked out.
I will checkout the branch HEAD (commit `e4b03da2d`) to get the r4 revision of the plan.
I will now view the updated plan file `docs/research/1944-login-user-password/plan.md` to review the r4 content in detail.
I will view `pkg/daemon/daemon_system.go` around line 656 to inspect `applySystemLogin` and see the context of the user creation, GC, and marker logic.
I will check the git diff of the current commit to see if there are changes in other files on this branch besides `plan.md`.
I will list the files in the directory again now that we are on the branch HEAD commit.
I will view `docs/research/1944-login-user-password/agy-plan-r3.md` to read the findings from our previous review round.
I will search for any locking or synchronization mechanisms in `pkg/daemon` to verify if apply/commit runs are serialized.
# Adversarial Plan Review: Issue #1944 — `system login user` encrypted-password (r4)

## Verdict: `PLAN-NEEDS-WORK`

The revision **r4** of the plan document solves the validation and provenance requirements identified in round 3. However, two defects remain in the provenance marker lifecycle—one is a critical garbage collection bypass, and the other is a state-reconciliation inconsistency for users leaving and rejoining the config.

---

## Verification of Past Findings & Core Mechanics (Resolved)

1. **Defect-1 (pwApply without a marker orphans xpf-applied passwords):** Resolved. As described in §5.4:
   > `markProvisioned(user.Name) // xpf now manages this password (r3/Major-1)`
   is executed inside `case pwApply` on successful write, and also on successful `useradd`.
2. **Defect-2 (stale marker leakage locks out recreated account):** Partically resolved via GC logic, but contains a bypass defect (see Finding-1 below).
3. **Validator Parity (Legacy DES & modular checksums):** Resolved. Under §5.5 Case 1:
   > `$<id>$<salt>$<checksum>` ... `<checksum>` (the segment after the FINAL `$`) is non-empty
   Under Reject:
   > `password12345` (13 alnum — r3 Major-2, the DES-drop case), `**$6$salt$**` (empty checksum — r3 Major-3), `**$6$$hash**` (empty salt)
4. **Race conditions & Durability:**
   - There are **no race conditions** under the apply lock; `applyConfigLocked` is serialized sequentially under the daemon semaphore `d.applySem`.
   - `/var/lib/xpf` is **durable and persistent** (confirmed as it holds the config database).
   - `markProvisioned-only-on-success` correctly avoids arming a lock for a failed apply on pre-existing users.

---

## New Findings & Defects (r4)

### 1. Stale Marker GC Bypass on Empty Configuration (Critical Blocker)
* **Quoted Evidence (plan.md L262-264):**
  > `**GC'd** (marker file removed) for any username present in /var/lib/xpf/provisioned-users/ but **no longer in** cfg.System.Login.Users, at the top of applySystemLogin.`
* **Quoted Evidence (pkg/daemon/daemon_system.go L657-658):**
  ```go
  if cfg.System.Login == nil || len(cfg.System.Login.Users) == 0 {
      return
  }
  ```
* **Defect:** If the operator removes **all** configured users from the configuration (rendering `cfg.System.Login.Users` empty), `applySystemLogin` returns early. Because of this early return, the GC logic never executes.
* **Counter-Example:**
  1. Operator has provisioned `userA` and `userB`. Markers `/var/lib/xpf/provisioned-users/userA` and `userB` exist.
  2. Operator deletes all configured users from the configuration and commits.
  3. `applySystemLogin` hits the early return check at line 657 and exits immediately.
  4. Both marker files are leaked on disk.
  5. Operator manually deletes `userA` from the OS (`userdel userA`) and recreates `userA` out-of-band with a password.
  6. Operator adds `userA` back to the configuration without a password (SSH keys only).
  7. xpf sees the stale marker, enters `pwLock`, and locks the operator out of the recreated out-of-band `userA` account.
* **Resolution:** Ensure the GC is run before the early return, or structure the early return to execute GC on an empty set of users.

---

### 2. Leave-and-Rejoin Password Reconciliation Gap (Medium Risk)
* **Analysis:** Because the GC immediately deletes the marker file when a user is absent from `cfg.System.Login.Users` in the current config snapshot, a user leaving and rejoining across commits results in an orphan credential.
* **Counter-Example:**
  1. `userA` is provisioned by xpf with a password in Commit 0 (marker exists).
  2. In Commit 1, `userA` is removed from the configuration (but the OS account is not deleted, as `userdel` is a non-goal).
  3. The GC runs at Commit 1, sees `userA` is absent from the config, and deletes `/var/lib/xpf/provisioned-users/userA`.
  4. In Commit 2, `userA` is re-added to the configuration with **no password** (SSH keys only).
  5. `applySystemLogin` runs at Commit 2. The marker no longer exists, so `pwLock` is skipped.
  6. `userA`'s old password remains active, violating declarative reconciliation (D2).
* **Resolution:** Consider storing the provisioned user's UID inside the marker file `/var/lib/xpf/provisioned-users/<name>` instead of GCing immediately. When checking `xpfProvisioned(name)`, compare the current OS user's UID to the recorded UID. If they match, the user is the same xpf-provisioned user, and the lock should be applied. If they mismatch or the user was deleted/recreated, skip the lock.
