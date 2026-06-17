# Plan of Action — #1944: `system login user` encrypted-password (console login for non-root operators)

- **Issue**: #1944
- **Branch**: `research/1944-login-user-password`
- **Revision**: r1 (initial draft for 3-way hostile plan-review)
- **Mode**: `/research` — STOPS at PLAN-READY. No PR, no production code.

---

## 1. Problem Statement

A password configured under `system login user <name>` never reaches
`/etc/shadow`. Only **root** gets a password applied:

- `system root-authentication encrypted-password <hash>` →
  `applyRootAuth` (`pkg/daemon/daemon_system.go:756`) runs
  `chpasswd -e` with stdin `root:<hash>`. ✅
- `system login user <name>` → `applySystemLogin`
  (`pkg/daemon/daemon_system.go:648`) runs `useradd -m -s /bin/bash`,
  writes `/etc/sudoers.d/xpf-<name>` (`NOPASSWD: ALL` for super-user),
  and writes `~/.ssh/authorized_keys` — **but never sets a password.**

The `LoginUser` type (`pkg/config/types_system.go:282`) carries only
`Name / UID / Class / SSHKeys`. The compiler
(`pkg/config/compiler_system.go:94-102`) parses only `ssh-ed25519 /
ssh-rsa / ssh-dsa` under `user … authentication`; it does **not** parse
`encrypted-password`. The schema (`pkg/config/schema.go:1078`) defines
`authentication` under `login user` as `{children: nil}` — a bare
keyword with no value slot and no completion (asymmetric vs
`root-authentication` at `schema.go:1039-1044`, which enumerates
`encrypted-password` + the three ssh-* key leaves).

Consequence: a freshly `useradd`-created account has a **locked/empty
password field** (`useradd` without `-p`/`-d` leaves `!` in
`/etc/shadow`). On the **serial console** there is no SSH-key path, so a
non-root operator account **cannot log in at all**. This is a Junos
parity + day-0 operability gap surfaced during #1922 SAFE-BOOTSTRAP /
#1930.

### What works today (so we don't regress it)
- Root console login: passwordless factory root (`passwd -d root`) or a
  day-0 config carrying `root-authentication encrypted-password`.
- Non-root SSH login: `authorized_keys` only.
- Non-root sudo: `NOPASSWD: ALL` (sudoers) — **independent of the login
  password**; this plan does not touch sudo.

---

## 2. Goal / Success Criteria

1. `set system login user <name> authentication encrypted-password
   "<crypt-hash>"` parses, compiles, validates, and on commit places the
   hash in `/etc/shadow` for `<name>` so the operator can log in on the
   serial console (and via SSH password if `sshd` permits).
2. Behaviour mirrors `applyRootAuth` (`chpasswd -e`, idempotent, logs on
   apply, warns on failure) — **no new mechanism class**.
3. Commit-check rejects a value that is not a recognizable crypt(3) hash
   (defense against pasting a plaintext password into a field labeled
   "encrypted-password", which would lock the account silently).
4. Tab-completion + `?` help under `login user … authentication` lists
   `encrypted-password` (and, for free, the ssh-* leaves that the
   compiler already accepts but the schema currently hides).
5. Idempotent: re-commit with an unchanged hash does **not** re-invoke
   `chpasswd` (avoids churn / log spam / unnecessary `/etc/shadow`
   rewrites). This is a behaviour **improvement over `applyRootAuth`**,
   which currently re-runs `chpasswd` every apply.
6. Docs updated (module contract).
7. No regression to existing root-auth, SSH-key, sudoers, or user-create
   paths. `make test` green.

### Explicit non-goals (this issue)
- Password **hashing in the CLI** (Junos `set … plain-text-password`
  prompt that hashes interactively). xpf takes a pre-computed crypt hash,
  same as `root-authentication`. (Could be a follow-up.)
- Login **class → PAM/permission enforcement** beyond the existing
  sudoers grant. `Class` already drives sudoers; unchanged here.
- Account **lifecycle/removal** (`userdel` when a user leaves the
  config) — see §6 Path D; current code never removes users and this
  plan keeps that property unless we deliberately choose otherwise.

---

## 3. Affected Code (walked)

| File | Location | Role |
|------|----------|------|
| `pkg/config/types_system.go` | `LoginUser` @282; `RootAuthConfig` @130 | Add `EncryptedPassword string` to `LoginUser` (parity with `RootAuthConfig.EncryptedPassword`). |
| `pkg/config/compiler_system.go` | `case "authentication":` @94-102 | Add `case "encrypted-password":` → `user.EncryptedPassword = nodeVal(authChild)`. |
| `pkg/config/schema.go` | `login user` node @1074-1080; `root-authentication` @1039-1044 | Give `authentication` under `login user` a children map mirroring `root-authentication` (encrypted-password typed leaf + ssh-ed25519/rsa/dsa). |
| `pkg/config/schema_validators.go` | new `ValidateCryptHash` | crypt(3) hash validator. |
| `pkg/config/schema_walk.go` | typed-leaf dispatch @89, @298, @331 | (no change — consumes `valueType`+`validator` set in schema.go) |
| `pkg/daemon/daemon_system.go` | `applySystemLogin` @648-709; `applyRootAuth` @756-789 | Apply `chpasswd -e` for each user with a hash, idempotently. |
| `pkg/config/value_type.go` | `ValueType` enum | Add `ValueCryptHash` (or reuse a generic typed-leaf marker). |
| `pkg/config/parser_system_test.go` | `TestParseLoginClass` @1245; root-auth test @319 | Add hierarchical + flat-set coverage. |
| docs (TBD §10) | — | Module contract. |

### Existing patterns confirmed
- **Parser dual-AST**: `namedInstances(child.FindChildren("user"))`
  (compiler_system.go:83) already yields per-user nodes whose children
  are the per-user props for **both** hierarchical and flat-set shapes
  (CLAUDE.md "Parser Dual AST Shape"). `nodeVal(authChild)` is the same
  accessor `root-authentication` uses, so the value extraction is
  shape-agnostic by reuse.
- **Typed-leaf machinery** (#1319): `schemaNode.isTypedLeaf()` (true
  when `valueType != ValueAny`) drives `SchemaValidate`
  (schema_walk.go:40) to invoke `validator` at commit-check. Setting
  `valueType: ValueCryptHash, validator: ValidateCryptHash` on the leaf
  is the complete commit-check wiring.
- **Apply ordering** (daemon_apply.go:912-918): `applySystemLogin` runs
  **before** `applyRootAuth`. Both are best-effort, log-on-failure, no
  hard error to commit. We stay inside `applySystemLogin`.

---

## 4. Blast Radius

- **Tiny.** One new struct field, one compiler case, one schema subtree,
  one validator, one apply block, plus tests + docs.
- No wire-protocol change (this is control-plane OS-account state, never
  crosses to userspace-dp or the dataplane).
- No HA/cluster path: user accounts are local OS state applied
  identically on every node from synced config; `chpasswd` is
  node-local and idempotent. No session/VRRP/sync interaction. (Confirm
  in review: config sync already replicates `system login` to the peer,
  so both nodes converge — no special handling needed.)
- No interaction with #1916 fsatomic shadow-file concerns: we invoke
  `chpasswd -e` (a process that does its own locked update of
  `/etc/shadow` via `pam_chauthtok`/`lckpwdf`), **not** a direct file
  write. Same as the existing `applyRootAuth`. Note this explicitly in
  the PR so #1916 doesn't try to wrap it.

---

## 5. Proposed Design (recommended path)

### 5.1 Type
```go
// pkg/config/types_system.go
type LoginUser struct {
    Name              string
    UID               int
    Class             string
    EncryptedPassword string   // crypt(3) hash, applied via `chpasswd -e`
    SSHKeys           []string
}
```

### 5.2 Compiler
```go
// pkg/config/compiler_system.go, inside case "authentication":
case "encrypted-password":
    user.EncryptedPassword = nodeVal(authChild)
case "ssh-ed25519", "ssh-rsa", "ssh-dsa":
    if v := nodeVal(authChild); v != "" {
        user.SSHKeys = append(user.SSHKeys, v)
    }
```

### 5.3 Schema (closes the asymmetry)
```go
// pkg/config/schema.go, login user node:
"authentication": {desc: "Authentication methods", children: map[string]*schemaNode{
    "encrypted-password": {desc: "Encrypted password", args: 1,
        placeholder: "<password>",
        valueType: ValueCryptHash, validator: ValidateCryptHash},
    "ssh-ed25519": {desc: "SSH ED25519 public key", args: 1, placeholder: "<key>"},
    "ssh-rsa":     {desc: "SSH RSA public key", args: 1, placeholder: "<key>"},
    "ssh-dsa":     {desc: "SSH DSA public key", args: 1, placeholder: "<key>"},
}},
```
**Open decision for review**: should `root-authentication
encrypted-password` (schema.go:1040, currently `children: nil`, no
`valueType`) *also* gain `ValueCryptHash`/`ValidateCryptHash` for
parity? Recommended: **yes, in the same PR**, so root and per-user
share one validator and one error message. Low risk — the validator is
permissive (see §5.5). If review prefers minimal scope, gate root behind
a follow-up and only validate the per-user leaf.

### 5.4 Apply (idempotent — improvement over applyRootAuth)
Inside `applySystemLogin`, after user-exists/useradd and before/around
SSH keys, per user:
```go
if user.EncryptedPassword != "" {
    if d.currentShadowHash(user.Name) != user.EncryptedPassword {
        cmd := exec.Command("chpasswd", "-e")
        cmd.Stdin = strings.NewReader(user.Name + ":" + user.EncryptedPassword + "\n")
        if out, err := cmd.CombinedOutput(); err != nil {
            slog.Warn("failed to set user password",
                "user", user.Name, "err", err, "output", string(out))
        } else {
            slog.Info("user encrypted-password applied", "user", user.Name)
        }
    }
}
```
`currentShadowHash` reads the field-2 of the user's `/etc/shadow` line
(via `getent shadow <user>` or a guarded read of `/etc/shadow`).
**Idempotency decision (Path B in §6)**: recommended to skip re-apply
when the on-disk hash already equals the desired hash. If review judges
the `/etc/shadow` read too fragile (permissions, NSS backends, getent
shadow availability), fall back to **unconditional `chpasswd` every
apply** (exactly what `applyRootAuth` does today) — correct but noisier.

### 5.5 Validator (crypt(3) hash recognizer)
```go
// pkg/config/schema_validators.go
// ValidateCryptHash accepts a crypt(3)-style hash: either a modular
// crypt format ($id$[params$]salt$hash, ids 1/2a/2b/2y/5/6/y/gy/7) or a
// legacy DES 13-char hash. Rejects obvious plaintext to prevent silently
// locking an account.
func ValidateCryptHash(raw string, _ *Config) error
```
Validation policy (permissive, fail-OPEN-ish but catches the footgun):
- Accept `$<id>$...` where `<id>` ∈ {`1`,`2a`,`2b`,`2y`,`5`,`6`,`y`,`gy`,`7`}
  and the remainder is non-empty and uses the crypt base64 alphabet
  (`[./0-9A-Za-z$]`), with at least one `$` after the id (salt present).
- Accept a 13-char classic DES hash (`[./0-9A-Za-z]{13}`).
- Accept `*` and `!`/`!!` (explicitly-locked sentinels — Junos/operators
  may want a locked account; warn-not-reject is the alternative).
- Reject everything else with a message naming the expected formats.
The intent is to catch plaintext (no leading `$`, wrong length) — the
classic "I typed my password into encrypted-password" mistake — not to
cryptographically validate the hash. **Review must confirm the id list
matches what glibc on the target Debian 13 actually supports** (yescrypt
`$y$` is the Debian 13 default; `$6$` sha512crypt is universal).

### 5.6 Commit-check warning (optional, parity with §1 root warning)
Consider a commit warning when a `login user` has neither
`encrypted-password` nor `ssh-*` keys (account is unreachable). Mirrors
the existing root SYN-cookie warning style (compiler.go:641). **Decision
for review**: nice-to-have, not required for the fix. Recommend
including it — it directly addresses the "can't log in" class of bug.

---

## 6. Multiple Path Options (where the design branches)

### Path A — apply mechanism: `chpasswd -e` vs `usermod -p`
- **A1 `chpasswd -e` (RECOMMENDED)**: byte-identical to `applyRootAuth`;
  one code idiom in the file; stdin avoids the hash appearing in
  `ps`/argv; handles the modular crypt formats. **Chosen.**
- **A2 `usermod -p <hash>`**: hash visible in process argv (leaks via
  `/proc/<pid>/cmdline` to any local reader during the call) — **worse**,
  and diverges from the established pattern. Rejected.

### Path B — idempotency: skip-if-unchanged vs always-apply
- **B1 skip-if-unchanged (RECOMMENDED)**: read current `/etc/shadow`
  field, compare, apply only on diff. Quiet, no churn, but needs a
  reliable shadow read (`getent shadow` requires root — daemon runs as
  root, OK). Risk: NSS edge cases.
- **B2 always-apply**: unconditional `chpasswd` every commit. Dead
  simple, matches `applyRootAuth` exactly, but re-writes `/etc/shadow`
  and logs on every commit (log spam violates the project's loop-logging
  rule if commits are frequent). Acceptable fallback.
- **Decision**: ship B1; if the shadow read proves flaky in review/smoke,
  degrade to B2 (and optionally retrofit B1 onto `applyRootAuth` later).

### Path C — validation strictness
- **C1 permissive recognizer (RECOMMENDED, §5.5)**: accept known crypt
  id formats + DES + locked sentinels; reject plaintext. Catches the
  real footgun without over-fitting to a glibc version.
- **C2 strict per-id structural parse** (validate salt length, rounds
  param, base64 length per algorithm): higher fidelity, but brittle
  across libc versions and yescrypt's variable params; risks rejecting a
  valid hash the OS would accept. Rejected as over-engineering.
- **C3 no validation** (accept any string, like root today): simplest,
  but reproduces the silent-lockout footgun. Rejected.

### Path D — password REMOVED from config (reconciliation)
The issue explicitly asks. Current code **never removes** user state
(no `userdel`, sudoers/keys are only rewritten, never cleared). Options
when `encrypted-password` is deleted from a still-present user:
- **D1 leave the existing hash (do nothing) (RECOMMENDED for r1)**:
  matches today's non-removal behaviour for SSH keys/sudoers; least
  surprising; avoids accidentally locking out an admin mid-session. The
  operator removed the *config directive*, not necessarily the intent to
  keep the account usable. Document the limitation.
- **D2 lock the account (`passwd -l <user>` / set `!`)**: "config is
  truth" semantics — removing the directive disables password login.
  More correct as declarative reconciliation, but riskier (a typo'd
  delete locks the operator out of the console). If chosen, must be paired
  with a commit warning.
- **D3 clear to empty/passwordless**: dangerous (passwordless console
  login). Rejected.
- **Decision for review**: r1 recommends **D1** (least-surprise, matches
  existing reconciliation posture for the other login attributes), with
  D2 noted as a possible explicit-opt-in follow-up. This keeps the
  change additive and consistent: xpf's `system login` is currently
  *additive* (it provisions, it does not deprovision); fixing that
  asymmetry is a separate, larger decision (§ also touches D for users
  entirely removed from config — out of scope here).

### Path E — root-authentication parity scope (from §5.3)
- **E1 also wire `ValueCryptHash` onto `root-authentication
  encrypted-password` (RECOMMENDED)**: one validator, consistent errors,
  fixes root's identical (currently-unvalidated) footgun.
- **E2 per-user only**: minimal diff; leaves root unvalidated. Acceptable
  if review wants to minimize blast radius.

---

## 7. Test Plan

### Unit (Go, `make test`)
1. **Compiler hierarchical**: extend `TestParseLoginClass` — add
   `authentication { encrypted-password "$6$abc$..."; ssh-ed25519 "..."; }`
   under a user; assert `EncryptedPassword` + `SSHKeys` populate.
2. **Compiler flat-set**: via `ParseSetCommand` + `tree.SetPath` loop
   (NEVER `NewParser` for set lines, per CLAUDE.md):
   `set system login user op authentication encrypted-password "$6$..."`
   → assert field set. Covers the dual-AST shape.
3. **Validator**: table test for `ValidateCryptHash` — accept `$6$`,
   `$y$`, `$2b$`, 13-char DES, `*`, `!`; reject `plaintext`, empty,
   `$99$bogus`, `$6$` (no salt/hash body).
4. **SchemaValidate / commit-check**: a config with a plaintext
   `encrypted-password` fails `SchemaValidate` with the typed-leaf error;
   a valid hash passes.
5. **(If E1)** root-authentication encrypted-password runs through the
   same validator — keep `TestParse...RootAuth` green with `$6$abc123`
   (note: existing test uses `"$6$abc123"` which has **no salt
   separator** — the validator must accept it OR the test value must be
   updated to a well-formed `$6$salt$hash`; flag this in review as a
   compatibility decision).

### Smoke (loss userspace cluster — only if review wants live proof)
This is a control-plane-only change with no dataplane/forwarding
impact, so a full perf smoke is unwarranted. Minimal live check:
1. `make cluster-deploy`; add `set system login user op class operator
   authentication encrypted-password "<known $6$ hash for 'test123'>"`;
   commit.
2. `cluster-ssh` → `getent shadow op` shows the hash in field 2.
3. From the VM console (or `su - op` then password): authenticate with
   `test123` — succeeds.
4. Re-commit unchanged → journal shows **no** "user encrypted-password
   applied" line (idempotency B1).
5. Confirm root login + SSH-key login + sudo still work (no regression).

`make test` is the gate; smoke is confirmatory and optional per
reviewer call.

---

## 8. Rollback / Risk

- **Risk: validator rejects a valid hash** → operator can't commit a
  good password. Mitigated by the permissive recognizer (Path C1) + the
  glibc-id-list review check.
- **Risk: shadow read (B1) misbehaves** → either spurious re-apply
  (harmless) or skipped apply (operator can't log in). Mitigated by B2
  fallback; smoke step 4 verifies.
- **Risk: locking out the console operator** — only if D2 chosen; r1
  picks D1 to avoid this entirely.
- Rollback: revert the commit; no persistent migration, no schema
  version bump, no map/wire change. Existing `/etc/shadow` entries are
  left as-is (they were set by the OS, not removed by this code).

---

## 9. Open Questions for Reviewers

1. **Path E scope**: validate root-auth in the same PR (E1) or per-user
   only (E2)?
2. **Path D**: D1 (leave hash on directive removal) vs D2 (lock). r1
   says D1.
3. **B1 vs B2** idempotency — is `getent shadow`/`/etc/shadow` read
   acceptable, or keep it simple with always-apply?
4. **Validator id list** — confirm yescrypt `$y$`/`$gy$` + the rest
   match Debian 13 glibc; should we accept `$7$` (scrypt) and `$gy$`?
5. **Existing test value** `"$6$abc123"` (no salt separator): does the
   chosen validator accept it, or do we update the fixture? (Determines
   whether E1 is backward-compatible with the current root-auth test.)
6. **Locked-sentinel handling** (`*`,`!`): accept (allow operator to
   pre-lock) or reject?

## 10. Documentation Updates

- **Module contract doc**: there is no dedicated `docs/system-config.md`;
  `system login` / `root-authentication` semantics are referenced in
  `docs/junos-config-display-reference.md`, `docs/feature-gaps.md`, and
  `docs/phases.md`. Plan: add a short subsection to the most
  authoritative of these (candidate: a new `docs/system-login.md` OR a
  section in `feature-gaps.md`/display-reference) documenting:
  - `system login user X authentication encrypted-password` now applies
    to `/etc/shadow` for console login.
  - The crypt-hash requirement + accepted formats + commit-check.
  - The reconciliation posture (D1: removing the directive does not
    clear the hash) — so operators aren't surprised.
  - That this is a `chpasswd` invocation (relevant to #1916 fsatomic).
- **Reviewer must confirm** which doc is the canonical module contract
  for `system login` and update *that* one (per CLAUDE.md doc rule), not
  create a redundant file. r1 leans toward a focused
  `docs/system-login.md` if none exists.
- Update `docs/feature-gaps.md` to mark the per-user console-password gap
  closed.

## 11. Reviewer Verdict Ledger

Tracked in `reviewer-ids.md`. Convergence requires Claude SMR + Codex +
AGY all PLAN-READY on the final revision.

| Round | Claude SMR | Codex | AGY |
|-------|-----------|-------|-----|
| r1    | pending   | pending | pending |
