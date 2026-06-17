# Codex Hostile Plan Review — #1944 (r1)

Codex task id: `019ed47f-3e33-7d92-8bde-0e0f5277e568`

## Verdict: PLAN-NEEDS-WORK

### Fatal
- **F-1** Validator accepts locked sentinels `*`/`!`/`!!` → `encrypted-password "!"` commits clean and creates a locked console account under a field meant to enable login.
- **F-2** Deleting the directive leaves a stale live credential (D1) — old password keeps working while config shows nothing. `applySystemLogin` is additive-only.
- **F-3** Plan pseudocode uses raw `exec.Command("chpasswd","-e")` + `CombinedOutput()`; current `applyRootAuth` uses `runCommandStdinTimeout` (exec_timeout.go) — a hung chpasswd wedges commit apply.
- **F-4** Idempotency compare with no error channel can `useradd` then silently skip the password set → same lockout the issue fixes.

### Minor
- **M-1** Root-auth parity (E) still open; E1 must update invalid fixtures `$6$abc123`.
- **M-2** Validator under-tested for `:`/newline/NUL rejection (chpasswd stdin `user:hash` injection).
- **M-3** Dual-AST shape equality not pinned by a test.
- **M-4** Missing tests: removal, stale-hash retention, shadow-read failure, chpasswd nonzero, crash-after-useradd-before-chpasswd.
- **M-5** Docs target not concrete; no `openssl passwd -6` example → operators paste plaintext.
- **M-6** #1916 claim too broad — sudoers/authorized_keys in the same function still use `os.WriteFile`.

### Nits
- Schema line refs stale: system schema is `pkg/config/schema_system.go`, not `schema.go:1039/1078`.
- Use `<crypt-hash>` placeholder, not `<password>`.
- Add `ValueCryptHash` to `ValueType.Placeholder()`.

### Rationale
Core mechanism sound (chpasswd -e on stdin avoids argv leak; dual-AST handled). Blockers: validator must reject bare sentinels; directive removal must lock not orphan; apply must use the timeout wrapper.
