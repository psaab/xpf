I will list the workspace directory using `list_dir` to see the structure of the repository.
I will view the content of `docs/research/1944-login-user-password/plan.md` to see the current revision (r2) of the design plan.
I will run `git diff origin/master...HEAD` to inspect the exact changes made to `plan.md` in the current branch.
I will run `git log -n 5` to inspect the commit history on this branch.
I will run `git status` to see if there are any untracked or modified files in the working directory that correspond to the "r2" revision or are related to this review.
I will run `git branch -a` to see all available branches in the local and remote repositories.
I will list the local branches to see if there is any other local branch or stash we should inspect.
I will search the workspace for "Revision: r2" to find where the r2 plan document might be.
I will list the contents of the `docs/research/1944-login-user-password/` directory to see all the files inside.
I will run `git log` on the remote branch `origin/research/1944-login-user-password` to see if there are newer commits that are not checked out locally.
I will checkout the remote branch `origin/research/1944-login-user-password` to bring the local working tree up to date with Revision r2 of the plan.
I will view the contents of the updated `docs/research/1944-login-user-password/plan.md` file to inspect Revision r2 of the plan.
I will view the content of `pkg/config/schema_system.go` to verify the schema locations referenced in the plan.
I will view lines 640 to 800 of `pkg/daemon/daemon_system.go` to inspect the code context of the apply functions.
I will search for `exec_timeout.go` using a grep search to verify the existence of the timeout helper function.
I will run `getent shadow root` to verify the output format of `getent shadow` on the system.
I will run a grep search for `shadow` or `lock` in the codebase to check if there is any existing implementation of shadow verification or locking logic.
I will check if the user has sudo permissions to inspect or run `chpasswd` related commands.
I will run a test sequence on a temporary user to verify the exact behavior of `chpasswd -e` when passed `!` as the password hash.
I will run `/usr/sbin/useradd` directly, as `/usr/sbin` may not be in the current shell's PATH.
I will check the current user's ID without sudo to see if we need to prepend sudo for administrative commands.
I will run the command with `sudo` to create the temporary user and verify the shadow entry.
I will test setting the user's password to a crypt hash and then locking it with `chpasswd -e` to check if `!` is correctly encoded.
I will delete the temporary user to clean up the system.
I will search `pkg/config/parser_system_test.go` to see the existing root authentication test cases and their hash values.
I will view lines 310 to 360 of `pkg/config/parser_system_test.go` to see the context of the root-authentication tests.
I will search for `lenient` in the codebase to confirm if the lenient parsing/compiling logic is indeed present at boot time.
I will view the beginning of `pkg/config/schema_validators.go` to see the structure of existing validators.
I will view the contents of `pkg/config/types_system.go` around line 282 to see how the `LoginUser` struct is currently defined.
I will check `pkg/config/compiler_system.go` to inspect the compilation logic for system login users.
I will view lines 70 to 120 of `pkg/config/compiler_system.go` to examine the compilation process for system users.
I will grep for `ValueType` or `ValueIPAddress` in the codebase to find where the `ValueType` enum and `Placeholder()` function are located.
I will view lines 30 to 100 of `pkg/config/value_type.go` to see the structure of the `ValueType` enum and where `ValueCryptHash` should be added.
I will search for `$6$abc` across the entire codebase to identify all the test fixtures that need to be updated.
I will view lines 595 to 625 of `pkg/config/dual_ast_differential_test.go` to check if this test case will also be impacted by the new `root-authentication` or `user` `encrypted-password` validation.
I will search for `CompileConfig` in `pkg/config/dual_ast_differential_test.go` to see if the differential test runs validation.
I will search for `SchemaValidate` in `pkg/config/dual_ast_differential_test.go` to see if the differential test runs schema validation.
I will search for `SchemaValidate` in `pkg/config/parser_system_test.go` to see if the system parser tests invoke schema validation.
I will search for `SchemaValidate` in `pkg/config/` to find the test files that run schema validation.
I will search for `encrypted-password` or `root-authentication` in all `schema_validate_*.go` files to check if there are test cases verifying `root-authentication` configuration that would run validation.
I will search for `root-authentication` or `encrypted-password` in the `pkg/configstore` directory to see if configstore tests run validation on those paths.
I will view `pkg/config/schema_validate_test.go` to understand how schema validation tests are structured and what they check.
I will read the updated `docs/research/1944-login-user-password/reviewer-ids.md` to check the status of other reviewers.
I will run a search to find files in `.claude/codex-review` to see if there are any other plan reviews or notes from r1 or r2.
I will view the content of `.claude/codex-review/workflows/20260529-043712-edae7d/artifacts/plan-findings-r2.md` using `view_file` to see if there are any related findings.
I will view `.antigravitycli/b001c14b-8a10-4d7a-b1e7-65bf749a1fb7.json` to see if it contains context about this task.
I will write the review analysis to an artifact file `plan_review_r2.md` in the artifacts directory.
I have reviewed **Revision r2** of the design plan for issue #1944. My verdict is **`PLAN-NEEDS-WORK`**.

Please see the detailed review in the artifact:
* [plan_review_r2.md](file:///home/ps/.gemini/antigravity-cli/brain/ba5227d6-ed11-46f3-a0a8-d783dbc8c38f/plan_review_r2.md)

---

### **Verdict: `PLAN-NEEDS-WORK`**

#### **Finding 1 (Security Gap): `isLockedShadow` treats empty string `""` as locked, leaving passwordless accounts unlocked**
* **Evidence from [plan.md](file:///home/ps/git/bpfrx/docs/research/1944-login-user-password/plan.md)**:
  ```go
  226: - `isLockedShadow(s)`: `s == "" || s == "*" || s == "!" || s == "!!" ||
  227:   strings.HasPrefix(s,"!")` — already locked, no re-lock.
  ```
  ```go
  212:     if cur, ok := currentShadowHash(user.Name); ok && !isLockedShadow(cur) {
  ```
* **Analysis**: An empty password field `""` in `/etc/shadow` represents a **passwordless account** where access is allowed without password validation, which is an active credential (not a locked one). Treating `""` as locked inside `isLockedShadow(cur)` means the lock check `!isLockedShadow(cur)` evaluates to `false`. This causes the daemon to skip locking passwordless accounts, leaving them accessible and bypassing the declarative reconciliation (Path D2) intended to secure accounts without configured passwords.
* **Fix**: Remove `s == ""` from `isLockedShadow` in [pkg/daemon/daemon_system.go](file:///home/ps/git/bpfrx/pkg/daemon/daemon_system.go).

#### **Finding 2 (Root Management Gap): E1 shared validator rejects bare sentinels, preventing root lock via config**
* **Evidence from [plan.md](file:///home/ps/git/bpfrx/docs/research/1944-login-user-password/plan.md)**:
  ```go
  252: - A value that is **only** a sentinel: `*`, `!`, `!!`, empty (S-4/F-1).
  ```
* **Analysis**: Root is explicitly excluded from the D2 automatic lock logic on removal. Consequently, setting `root-authentication encrypted-password` to `*` or `!` in the configuration is the only way for an operator to lock the root password. However, under E1, the root configuration shares the `ValidateCryptHash` validator in [pkg/config/schema_validators.go](file:///home/ps/git/bpfrx/pkg/config/schema_validators.go). Because the validator now rejects `*` and `!` as sentinels, the operator is blocked from explicitly locking the root password.
* **Fix**: Allow bare sentinels (`*`, `!`) in the validator, or allow them specifically when validating root.

#### **Finding 3 (Operational Risk): NSS Caching with `getent shadow <user>`**
* **Evidence from [plan.md](file:///home/ps/git/bpfrx/docs/research/1944-login-user-password/plan.md)**:
  ```go
  224: - `currentShadowHash`: `getent shadow <user>` (daemon runs as root) and
  ```
* **Analysis**: Relying on `getent shadow <user>` introduces an external process execution overhead and makes the daemon susceptible to stale cached lookups if `nscd` (Name Service Cache Daemon) is caching `/etc/shadow` entries.
* **Fix**: Since the daemon runs as root, read and parse `/etc/shadow` directly via standard file-read routines. This is faster, simpler, and immune to NSS caching.
