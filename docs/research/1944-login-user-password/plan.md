# Plan of Action — #1944: `system login user` encrypted-password (console login for non-root operators)

- **Issue**: #1944
- **Branch**: `research/1944-login-user-password`
- **Revision**: r2 (addresses convergent r1 findings from Codex + AGY + Claude SMR)
- **Mode**: `/research` — STOPS at PLAN-READY. No PR, no production code.
- **Base**: origin/master `004c6eaf4` — all code refs anchored to this base.

---

## 1. Problem Statement

A password configured under `system login user <name>` never reaches
`/etc/shadow`. Only **root** gets a password applied:

- `system root-authentication encrypted-password <hash>` →
  `applyRootAuth` (`pkg/daemon/daemon_system.go:774`) runs
  `runCommandStdinTimeout(stdin, "chpasswd", "-e")` with stdin
  `root:<hash>`. ✅
- `system login user <name>` → `applySystemLogin`
  (`pkg/daemon/daemon_system.go:656`) runs
  `runCommandTimeout("useradd", …)` (@677), writes
  `/etc/sudoers.d/xpf-<name>` (`NOPASSWD: ALL` for super-user, @691),
  and writes `~/.ssh/authorized_keys` (@708) — **but never sets a
  password.**

The `LoginUser` type (`pkg/config/types_system.go:282`) carries only
`Name / UID / Class / SSHKeys`. The compiler
(`pkg/config/compiler_system.go:94-102`) parses only `ssh-ed25519 /
ssh-rsa / ssh-dsa` under `user … authentication`; it does **not** parse
`encrypted-password`. The schema
(**`pkg/config/schema_system.go:70`**) defines `authentication` under
`login user` as `{children: nil}` — a bare keyword with no value slot
and no completion (asymmetric vs `root-authentication` at
`schema_system.go:31-36`, which enumerates `encrypted-password` + the
three `ssh-*` key leaves).

Consequence: a freshly `useradd`-created account has a **locked password
field** (`useradd` without `-p`/`-d` leaves `!` in `/etc/shadow`). On the
**serial console** there is no SSH-key path, so a non-root operator
account **cannot log in at all**. Junos parity + day-0 operability gap
surfaced during #1922 SAFE-BOOTSTRAP / #1930.

### What works today (must not regress)
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
2. Apply mirrors `applyRootAuth`: **`runCommandStdinTimeout(…, "chpasswd",
   "-e")`** (NOT a raw `exec.Command` — r1/S-2,F-3 fix), idempotent, logs
   on apply, warns on failure.
3. Commit-check **hard-rejects** (at operator commit; warning-only on
   boot/peer-sync — see §5.6) a value that is not a recognizable crypt(3)
   hash, including rejecting bare locked sentinels and plaintext.
4. Tab-completion + `?` help under `login user … authentication` lists
   `encrypted-password` and the `ssh-*` leaves (closes the schema
   asymmetry the compiler already half-implements).
5. **Idempotent, fail-open-toward-applying**: skip `chpasswd` only when
   the on-disk shadow hash *successfully reads and equals* the desired
   hash; on any read error / missing entry / mismatch → apply (so a
   first commit never silently skips the password — r1/S-8,F-4 fix).
6. **Declarative reconciliation (Path D2)**: when a configured user has
   no `encrypted-password` (directive removed or never set) AND xpf
   provisioned the account, **lock** the password (`<user>:!` via
   `chpasswd -e`) so removing the directive disables password login
   instead of orphaning a live credential (r1/S-3,F-2 fix). Idempotent
   (only lock on transition to locked). Never touches root; never
   touches users absent from config (deprovisioning is out of scope).
7. Docs updated with a concrete target + a hash-generation example.
8. No regression to root-auth, SSH-key, sudoers, or user-create paths.
   `make test` green.

### Explicit non-goals (this issue)
- CLI-side interactive plaintext→hash (`set … plain-text-password`
  prompt). xpf takes a pre-computed crypt hash, same as root-auth.
- Login class → PAM permission enforcement beyond existing sudoers.
- **Deprovisioning users entirely removed from config** (`userdel`).
  Today xpf never removes accounts; this plan keeps that and only
  changes the *password* lifecycle for users still in config. (The
  user-fully-removed case is a separate, larger declarative-lifecycle
  decision — explicitly deferred.)

---

## 3. Affected Code (walked, anchored to origin/master `004c6eaf4`)

| File | Location | Role |
|------|----------|------|
| `pkg/config/types_system.go` | `LoginUser` @282; `RootAuthConfig` @130 | Add `EncryptedPassword string` to `LoginUser`. |
| `pkg/config/compiler_system.go` | `case "authentication":` @94-102; root-auth @130-141 | Add `case "encrypted-password":` → `user.EncryptedPassword = nodeVal(authChild)`. |
| `pkg/config/schema_system.go` | `login user` @66-71; `root-authentication` @31-36 | Give `authentication` under `login user` a children map (encrypted-password typed leaf + ssh-ed25519/rsa/dsa). Optionally (E1) add typed-leaf to root-auth `encrypted-password` @32. |
| `pkg/config/schema_validators.go` | new `ValidateCryptHash` | crypt(3) hash validator (precise spec §5.5). |
| `pkg/config/value_type.go` | `ValueType` enum + `Placeholder()` | Add `ValueCryptHash` + a `Placeholder()` arm. |
| `pkg/config/schema_walk.go` | typed-leaf dispatch @40,89,298,331 | No change (consumes `valueType`+`validator`). |
| `pkg/daemon/daemon_system.go` | `applySystemLogin` @656-721; `applyRootAuth` @774; `exec_timeout.go` `runCommandStdinTimeout` | Apply/lock password via `runCommandStdinTimeout(…, "chpasswd","-e")`, idempotent. |
| `pkg/configstore/check.go` | SchemaValidate gate @13 | No change (validator auto-runs through the gate). |
| `pkg/config/parser_system_test.go` | `TestParseLoginClass` @1245; root-auth @319,727 | Add hierarchical + flat-set + validator coverage; update root fixtures if E1. |
| docs (§10) | — | Module contract + hash-gen example. |

### Existing patterns confirmed
- **Parser dual-AST**: `namedInstances(child.FindChildren("user"))`
  (compiler_system.go:83) yields per-user nodes for both hierarchical and
  flat-set shapes; `nodeVal(authChild)` (compiler.go:1698-1704) is
  shape-agnostic. Same accessor root-auth uses.
- **Typed-leaf machinery** (#1319): `schemaNode.isTypedLeaf()` (true when
  `valueType != ValueAny`) drives `SchemaValidate` (schema_walk.go:40) to
  invoke `validator` at commit-check. Setting `valueType: ValueCryptHash,
  validator: ValidateCryptHash` on the leaf is the complete wiring.
- **Apply ordering** (daemon_apply.go:912-918): `applySystemLogin` runs
  before `applyRootAuth`; both best-effort, log-on-failure, no hard
  commit error. We stay inside `applySystemLogin`.
- **Timeout wrappers** (`pkg/daemon/exec_timeout.go`):
  `runCommandTimeout(name,args…)` and `runCommandStdinTimeout(stdin,name,
  args…)` bound apply-path commands. `applyRootAuth` uses the latter for
  chpasswd — we must too.

---

## 4. Blast Radius

- **Tiny.** One struct field, one compiler case, one schema subtree, one
  validator + enum arm, one apply block (+ one lock block), tests + docs.
- No wire-protocol change — control-plane OS-account state, never crosses
  to userspace-dp / the dataplane.
- No HA/cluster special-casing: `system login` is replicated by config
  sync; `chpasswd` is node-local + idempotent; both nodes converge. No
  session/VRRP/sync interaction.
- #1916 fsatomic: the **password** path is a `chpasswd` *process*
  invocation (does its own `lckpwdf`-protected shadow update), not a file
  write — so #1916 should not wrap it. Narrow this claim per Codex M-6:
  the *same function* still uses `os.WriteFile` for sudoers (@691) and
  `authorized_keys` (@708); those are separate and unchanged.

---

## 5. Proposed Design (recommended path)

### 5.1 Type
```go
// pkg/config/types_system.go
type LoginUser struct {
    Name              string
    UID               int
    Class             string
    EncryptedPassword string   // crypt(3) hash; applied via `chpasswd -e`
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
// pkg/config/schema_system.go, login user node @66:
"authentication": {desc: "Authentication methods", children: map[string]*schemaNode{
    "encrypted-password": {desc: "Encrypted password", args: 1,
        placeholder: "<crypt-hash>",
        valueType: ValueCryptHash, validator: ValidateCryptHash},
    "ssh-ed25519": {desc: "SSH ED25519 public key", args: 1, placeholder: "<key>"},
    "ssh-rsa":     {desc: "SSH RSA public key", args: 1, placeholder: "<key>"},
    "ssh-dsa":     {desc: "SSH DSA public key", args: 1, placeholder: "<key>"},
}},
```
**Path E (decided → E1)**: also set `valueType: ValueCryptHash,
validator: ValidateCryptHash` on `root-authentication
encrypted-password` (`schema_system.go:32`), so root + per-user share
one validator + one error message and root's identical plaintext footgun
is closed. This forces updating two root-auth test fixtures (§5.7).

### 5.4 Apply + lock (idempotent, timeout-wrapped)
Inside `applySystemLogin`, per user, after the user-exists/`useradd`
block and alongside the SSH-key block. Helper `currentShadowHash(name)
(string, bool)` returns the field-2 hash and an `ok` flag (false on any
read error / no entry):
```go
desired := user.EncryptedPassword
if desired != "" {
    // Apply only on (read fails) OR (read != desired) — fail-open toward applying.
    cur, ok := currentShadowHash(user.Name)
    if !ok || cur != desired {
        stdin := strings.NewReader(user.Name + ":" + desired + "\n")
        if out, err := runCommandStdinTimeout(stdin, "chpasswd", "-e"); err != nil {
            slog.Warn("failed to set user password",
                "user", user.Name, "err", err, "output", strings.TrimSpace(string(out)))
        } else {
            slog.Info("user encrypted-password applied", "user", user.Name)
        }
    }
} else {
    // Path D2: no password configured for a provisioned user → lock the
    // account so a removed directive disables password login. Idempotent:
    // only lock when not already locked (cur not present or not a `!`/`*`).
    if cur, ok := currentShadowHash(user.Name); ok && !isLockedShadow(cur) {
        stdin := strings.NewReader(user.Name + ":!\n")
        if out, err := runCommandStdinTimeout(stdin, "chpasswd", "-e"); err != nil {
            slog.Warn("failed to lock user password",
                "user", user.Name, "err", err, "output", strings.TrimSpace(string(out)))
        } else {
            slog.Info("user password locked (no encrypted-password in config)",
                "user", user.Name)
        }
    }
}
```
- `currentShadowHash`: `getent shadow <user>` (daemon runs as root) and
  split on `:` field 2; on error or absence return `("", false)`.
- `isLockedShadow(s)`: `s == "" || s == "*" || s == "!" || s == "!!" ||
  strings.HasPrefix(s,"!")` — already locked, no re-lock.
- **Never** lock root and **never** touch a username not in
  `cfg.System.Login.Users` (the lock branch is inside the per-config-user
  loop, so it is structurally scoped to provisioned users only).
- The lock uses `<user>:!` (chpasswd -e accepts `!` as the encrypted
  field, writing a locked entry). Alternative impl: `usermod -L <user>` /
  `passwd -l <user>` via `runCommandTimeout` — equivalent; pick one in
  implementation (chpasswd keeps a single idiom).

### 5.5 Validator (crypt(3) hash recognizer — precise)
```go
// pkg/config/schema_validators.go
func ValidateCryptHash(raw string, _ *Config) error
```
Accept (case-sensitive):
1. **Modular crypt**: optional leading `!` or `!!` (locked-but-restorable
   form), then `$<id>$` with `<id>` ∈ {`1`,`2a`,`2b`,`2y`,`5`,`6`,`7`,
   `y`,`gy`}, then a non-empty body using the alphabet
   `[./0-9A-Za-z$=,+-]` (crypt base64 is `./0-9A-Za-z`; `$` separates
   fields; `=` and `,` appear in `rounds=` / yescrypt params), with at
   least one `$` after the id (salt present). **`=` MUST be in the
   alphabet** (AGY #1 / S-5).
2. **Legacy DES**: 13 chars from `[./0-9A-Za-z]` (optional leading `!`).
Reject:
- Anything not matching the above (plaintext: no `$`, wrong length).
- A value that is **only** a sentinel: `*`, `!`, `!!`, empty (S-4/F-1).
  These would lock the account under a directive meant to enable login;
  to ship a locked account, prepend `!` to a real hash (§ case 1).
- `:` anywhere (would corrupt `chpasswd` stdin `user:hash`) — excluded
  by the alphabet; add an explicit negative test (S-7/M-2).
- Control chars are independently hard-rejected at strict commit by the
  freetext gate (`pkg/config/freetext.go`), so newline/NUL cannot reach
  `chpasswd` stdin (S-7).
**Review must confirm** the id list matches Debian 13 glibc: yescrypt
`$y$` is the default, `$6$` sha512crypt universal, `$2b$` bcrypt via
libxcrypt, `$gy$`/`$7$` present in libxcrypt — accept the superset; the
OS, not the validator, is the final authority, so err permissive within
"clearly-a-hash".

### 5.6 SchemaValidate gate semantics (verified contract — S-9)
`ValidateCryptHash` runs through the #1319 typed-leaf gate:
- **Operator commit / commit-check**: `pkg/configstore/check.go` →
  `SchemaValidate` **hard-fails** the commit on a bad hash
  (`TestCheckTextSchemaValidateGate` proves the gate fires). Plaintext is
  rejected at the entry point. ✅ (footgun closed)
- **Boot / peer-sync (lenient path)**: SchemaValidate violations are
  **downgraded to a warning** (`pkg/config/freetext.go:20-25`,
  `configstore.compileTreeLenient`), so an already-persisted or
  peer-synced bad value cannot brick boot. ✅ (no boot-lockout)
This is the desired behavior; state it in the PR so the
"does this lock us out of boot?" objection is pre-answered.

### 5.7 Test-fixture update (E1 consequence — S-10/M-1/AGY#4)
Existing root-auth fixtures `"$6$abc123"` (parser_system_test.go:320,358)
and `"$6$abc"` (:727,745) have **no salt separator** and a strict
validator rejects them. Under E1 these would fail commit. **Fix the
fixtures** to well-formed `"$6$saltsalt$<hash>"` — do NOT weaken the
validator to keep dummy values green (AGY #4). Update both the input
string and the assertion.

### 5.8 Commit-check warning (optional, parity with root warning)
A commit warning when a `login user` has neither `encrypted-password`
nor `ssh-*` keys (account unreachable) mirrors the existing root warning
style (compiler.go:641). **Decision**: include it — directly addresses
the "can't log in" bug class. Low cost.

---

## 6. Multiple Path Options (resolved)

### Path A — apply mechanism: **A1 `chpasswd -e`** (decided)
Byte-identical idiom to `applyRootAuth` *including the
`runCommandStdinTimeout` wrapper* (S-2 fix); hash on stdin → no argv
leak. A2 `usermod -p` rejected (hash visible in `/proc/<pid>/cmdline`).

### Path B — idempotency: **B1 skip-if-unchanged, fail-open** (decided)
Read shadow via `getent shadow`; apply on read-fail / missing / mismatch
(S-8/F-4 fix — never skip a needed apply). B2 (always-apply, like root
today) is the safe fallback if the read proves flaky in smoke.

### Path C — validation strictness: **C1 permissive recognizer** (decided)
Accept known crypt id formats + DES + optional `!`-prefix; reject
plaintext + bare sentinels (§5.5). C2 strict per-id structural parse
rejected (brittle across libc / yescrypt params — would reject valid
hashes). C3 no validation rejected (reproduces the footgun).

### Path D — directive removal: **D2 lock the account** (decided — flipped from r1)
Removing `encrypted-password` from a configured user locks password
login (`<user>:!`), idempotently, provisioned-users-only, never root.
D1 (do nothing) **rejected** — orphans a live credential outside config
control (Codex F-2 + AGY #2 + SMR S-3, three-way convergence). D3
(passwordless) rejected (dangerous). Note: this makes the *password*
attribute declarative while SSH-keys/sudoers remain additive — a
deliberate, documented asymmetry (a live password is a higher-severity
orphan than a stale key).

### Path E — root-auth parity: **E1 share the validator** (decided)
One validator + consistent errors; closes root's identical plaintext
footgun. Cost: update two root-auth test fixtures (§5.7). E2 (per-user
only) rejected — leaves root unvalidated for no real saving.

---

## 7. Test Plan

### Unit (Go, `make test`)
1. **Compiler hierarchical**: extend `TestParseLoginClass` — add
   `authentication { encrypted-password "$6$salt$hash"; ssh-ed25519 "…"; }`;
   assert `EncryptedPassword` + `SSHKeys`.
2. **Compiler flat-set**: via `ParseSetCommand` + `tree.SetPath` loop
   (NEVER `NewParser` for set lines):
   `set system login user op authentication encrypted-password "$6$salt$hash"`
   → assert field set. Pins the dual-AST shape (Codex M-3) — assert the
   flat-set compiled output equals the hierarchical compiled output.
3. **Validator table test** (`ValidateCryptHash`):
   - Accept: `$6$salt$hash`, `$6$rounds=656000$salt$hash` (the `=` case),
     `$y$j9T$…`, `$2b$…`, 13-char DES, `!$6$salt$hash` (locked-restorable).
   - Reject: `plaintext`, ``(empty), `*`, `!`, `!!`, `$99$bogus`, `$6$`
     (no salt body), `$6$salt:hash` (colon), `$6$ab cd` (space).
4. **SchemaValidate / commit-check**: a config with a plaintext per-user
   `encrypted-password` fails `SchemaValidate` (hard gate); a valid hash
   passes. Mirror for root-auth (E1).
5. **Root-auth E1 fixtures**: update `$6$abc123`/`$6$abc` to well-formed
   hashes; assertions follow (§5.7).
6. **Daemon apply logic** (unit-testable parts): `isLockedShadow`
   table test; `currentShadowHash` parse (field-2 split) given a sample
   `getent shadow` line. (`chpasswd` exec itself is integration/smoke.)

### Smoke (loss userspace cluster — confirmatory, optional)
Control-plane-only change, no dataplane/forwarding impact → no perf
smoke. Minimal live check:
1. `make cluster-deploy`; `set system login user op class operator
   authentication encrypted-password "<known $6$ hash for 'test123'>"`;
   commit.
2. `cluster-ssh` → `getent shadow op` shows the hash in field 2.
3. Console / `su - op`: authenticate with `test123` — succeeds.
4. Re-commit unchanged → journal shows **no** "user encrypted-password
   applied" (idempotency B1).
5. **D2**: delete the `encrypted-password` directive, commit →
   `getent shadow op` field 2 is `!` (locked); console password login
   for `op` now fails; SSH-key + sudo still work.
6. Root login + SSH-key login + sudo unchanged (no regression).

`make test` is the gate; smoke is confirmatory per reviewer call.

---

## 8. Rollback / Risk

- **Validator rejects a valid hash** → can't commit a good password.
  Mitigated by permissive recognizer (C1) + `=`/`rounds=` coverage +
  the glibc-id-list review check + boot-path downgrade (§5.6 — a
  persisted hash never bricks boot).
- **Shadow read (B1) misbehaves** → fail-open applies (harmless re-apply)
  rather than skips; D2 lock branch also reads — same fail-open posture
  (on read fail, `ok==false` → do NOT lock, avoiding an accidental
  lockout from a transient read error). Smoke 4/5 verify.
- **Accidental console lockout via D2** → only locks users *in config*
  whose `encrypted-password` is absent; an operator relying on a console
  password keeps it as long as the directive is present; SSH-key + sudo
  are unaffected by the lock. The lock is reversible (re-add the
  directive). Documented (§10).
- Rollback: revert the commit; no migration, no schema version bump, no
  map/wire change. Existing `/etc/shadow` entries set before the revert
  remain as the OS left them.

---

## 9. Open Questions for Reviewers (r2 — narrowed)

1. **D2 lock mechanism**: `chpasswd -e` with `<user>:!` vs
   `usermod -L`/`passwd -l`. Plan leans chpasswd (single idiom). OK?
2. **Locked-restorable form**: accept leading `!`/`!!` on a real hash
   (§5.5 case 1)? Plan says yes; confirm it's wanted, not scope creep.
3. **Validator id superset**: accept `$7$` (scrypt) + `$gy$` in addition
   to the universal set? Plan says accept (OS is final authority).
4. **D2 scope**: lock-on-removal applies only to users still in config.
   Confirm we are NOT taking on full deprovisioning (`userdel`) here.
5. **Commit warning** (§5.8) for users with no auth method at all —
   include? Plan says yes.

## 10. Documentation Updates

- **No existing canonical `system login` contract doc** (verified: no
  `docs/system-login.md`; `system login`/`root-authentication` are only
  referenced in `docs/junos-config-display-reference.md`,
  `docs/feature-gaps.md`, `docs/phases.md`). **Decision**: create a
  focused `docs/system-login.md` covering:
  - `system login user X authentication encrypted-password` applies to
    `/etc/shadow` for console login.
  - The crypt-hash requirement + accepted formats + commit-check
    (hard-fail on commit, warning on boot — §5.6).
  - **A hash-generation example** (Codex M-5 / S-11):
    `openssl passwd -6` or `mkpasswd -m sha512crypt` — so operators do
    not paste plaintext into `encrypted-password`.
  - **D2 reconciliation**: removing the directive **locks** the password
    (does not silently keep it); re-adding restores it; SSH-key + sudo
    are independent.
  - `chpasswd` invocation note for #1916 (password path is a process,
    not a file write; sudoers/keys in the same function still are file
    writes — Codex M-6).
- Update `docs/feature-gaps.md` to mark the per-user console-password
  gap closed.

## 11. Reviewer Verdict Ledger

Tracked in `reviewer-ids.md`. Convergence requires Claude SMR + Codex +
AGY all PLAN-READY on the final revision.

| Round | Claude SMR | Codex | AGY |
|-------|-----------|-------|-----|
| r1    | PLAN-NEEDS-WORK | PLAN-NEEDS-WORK | PLAN-NEEDS-WORK |
| r2    | pending | pending | pending |
