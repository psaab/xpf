# Plan of Action — #1944: `system login user` encrypted-password (console login for non-root operators)

- **Issue**: #1944
- **Branch**: `research/1944-login-user-password`
- **Revision**: r5 (UID-keyed provenance marker dissolves the r4 GC-bypass + leave-rejoin tension; §6 DES consistency fix)
- **Mode**: `/research` — STOPS at PLAN-READY. No PR, no production code.
- **Base**: origin/master `004c6eaf4` — all code refs anchored to this base.

---

## 1. Problem Statement

A password configured under `system login user <name>` never reaches
`/etc/shadow`. Only **root** gets a password applied:

- `system root-authentication encrypted-password <hash>` →
  `applyRootAuth` (`pkg/daemon/daemon_system.go:774`) runs
  <!-- apply call site: daemon_apply.go:1027 -->

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
   boot/peer-sync — see §5.6) **plaintext and other unrecognized
   non-hash values**. Bare lock sentinels (`*`, `!`, `!!`) are
   deliberately **accepted** (the intentional way to lock an account /
   the only way to lock root via config — r3 Minor-1).
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
| `pkg/config/types_system.go` | `LoginUser` @302; `RootAuthConfig` @151 | Add `EncryptedPassword string` to `LoginUser`. |
| `pkg/config/compiler_system.go` | `case "authentication":` @94-102; root-auth @131-141 | Add `case "encrypted-password":` → `user.EncryptedPassword = nodeVal(authChild)`. |
| `pkg/config/schema_system.go` | `login user` @66-71; `root-authentication` @31-36 | Give `authentication` under `login user` a children map (encrypted-password typed leaf + ssh-ed25519/rsa/dsa). E1: add typed-leaf to root-auth `encrypted-password` @32. |
| `pkg/config/schema_validators.go` | new `ValidateCryptHash` | crypt(3) hash validator (precise spec §5.5). |
| `pkg/config/value_type.go` | `ValueType` enum + `Placeholder()` | Add `ValueCryptHash` + a `Placeholder()` arm. |
| `pkg/config/schema_walk.go` | typed-leaf dispatch @236 (`isTypedLeaf()` @schema.go:97); validator invocation downstream | No change (consumes `valueType`+`validator`). |
| `pkg/daemon/daemon_system.go` | `applySystemLogin` @656-721 (early-return @657-659); `applyRootAuth` @774; `exec_timeout.go` `runCommandStdinTimeout` | Apply/lock password via `runCommandStdinTimeout(…, "chpasswd","-e")`, idempotent; new pure `passwordAction` decision helper + `currentShadowHash` (direct `/etc/shadow` read) + `isLockedShadow` + `lookupUID` + UID-keyed provenance marker (`markProvisioned`/`xpfProvisioned`). |
| `pkg/configstore/check.go` | SchemaValidate gate @13 | No change (validator auto-runs through the gate). |
| `pkg/daemon/daemon_apply.go` | apply calls @1021 (`applySystemLogin`), @1027 (`applyRootAuth`) | No change (call sites; ordering unchanged). |
| `pkg/config/compiler.go` | root-auth warning style @699-707 | Reference for the §5.8 "no auth method" warning. |
| `pkg/config/parser_system_test.go` | `TestParseLoginClass` @1245; root-auth @320,727 | Add hierarchical + flat-set + validator coverage; update root fixtures (E1). |
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
- **Apply ordering** (daemon_apply.go:1021 `applySystemLogin`, :1027
  `applyRootAuth`): `applySystemLogin` runs before `applyRootAuth`; both
  best-effort, log-on-failure, no hard commit error; both serialized
  under the apply lock (`applyConfigLocked`/`d.applySem`) so there is no
  marker/shadow race. We stay inside `applySystemLogin`.
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

### 5.4 Apply + lock (idempotent, timeout-wrapped, pure decision helper)
The decision is factored into a **pure, table-testable helper** so the
read-failure / lock / skip invariants are tested without exec'ing
`chpasswd` (r2/S2-5, Codex M-4). The apply path is the thin exec shell.
```go
type pwAction int
const ( pwNoop pwAction = iota; pwApply; pwLock )

// passwordAction is pure. Fail-OPEN toward applying a real password;
// fail-CLOSED (noop) on a read error in the lock branch so a transient
// read error can never lock out an operator.
func passwordAction(cur string, ok bool, desired string) pwAction {
    if desired != "" {
        if !ok || cur != desired { return pwApply } // apply on read-fail/miss/mismatch
        return pwNoop
    }
    // desired == "": Path D2 lock.
    if !ok { return pwNoop }            // do NOT lock on a read error (S2-1)
    if isLockedShadow(cur) { return pwNoop }
    return pwLock                       // empty (passwordless) OR a usable hash → lock
}
```
Apply shell inside `applySystemLogin`, per user (pwLock gated on
provenance — see below):
```go
desired := user.EncryptedPassword
curUID, uidOK := lookupUID(user.Name)        // user.Lookup → current OS UID
cur, ok := currentShadowHash(user.Name)
switch passwordAction(cur, ok, desired) {
case pwApply:
    stdin := strings.NewReader(user.Name + ":" + desired + "\n")
    if out, err := runCommandStdinTimeout(stdin, "chpasswd", "-e"); err != nil {
        slog.Warn("failed to set user password", "user", user.Name,
            "err", err, "output", strings.TrimSpace(string(out)))
    } else {
        if uidOK { markProvisioned(user.Name, curUID) } // xpf manages this exact account's password
        slog.Info("user encrypted-password applied", "user", user.Name)
    }
case pwLock:
    if !uidOK || !xpfProvisioned(user.Name, curUID) { break } // only lock this exact xpf-managed account
    stdin := strings.NewReader(user.Name + ":!\n")
    if out, err := runCommandStdinTimeout(stdin, "chpasswd", "-e"); err != nil {
        slog.Warn("failed to lock user password", "user", user.Name,
            "err", err, "output", strings.TrimSpace(string(out)))
    } else {
        slog.Info("user password locked (no encrypted-password in config)",
            "user", user.Name)
    }
}
```
- **`currentShadowHash(name) (string,bool)`** reads `/etc/shadow`
  **directly** (daemon is root), line-parses field 2, returns `("",false)`
  on error/absence. NOT `getent shadow` — that shells out and is subject
  to `nscd`/NSS caching → stale reads (r2/S2-4, AGY Finding-3).
- **`isLockedShadow(s)`** returns true ONLY for an actually-locked field:
  `s == "*" || strings.HasPrefix(s, "!")`. An **empty** field is
  passwordless (`passwd -d`), the MOST permissive state — NOT locked, so
  D2 locks it (r2/S2-1, Codex New-Fatal-1 + AGY Finding-1, found
  independently). (`!!` and `!<hash>` match `HasPrefix("!")`.)
- **Provenance — UID-keyed marker** (r2/S2-2 + r3 Major-1 + AGY-r3
  defect-1/-2 + r4 Codex/AGY GC-bypass + AGY-r4 leave-rejoin): a marker
  file `/var/lib/xpf/provisioned-users/<name>` (dir 0700) records that
  **xpf manages this account's password**, and its **content is the
  numeric UID** of the account at the time xpf wrote the password.
  - `markProvisioned(name, uid)` writes the UID to the marker on **both**
    successful `useradd` AND successful `pwApply` — so once xpf has
    written a password (even to a pre-existing or marker-wiped account),
    removing the directive will lock it (fixes r3 Major-1, Codex Major-1
    + AGY defect-1).
  - `xpfProvisioned(name, curUID)` returns true ONLY if the marker exists
    **and its recorded UID equals the current OS account's UID**. The
    current UID is obtained from `user.Lookup(name)` (or parsing
    `/etc/passwd`) — the daemon already shells `id` here.
  - `pwLock` runs ONLY when `xpfProvisioned(name, curUID)` is true.
  - **Why UID-keyed instead of name-only + GC** (r4): a name-only marker
    forced an impossible choice — keep it and a `userdel`+out-of-band
    recreate gets locked (AGY-r3 defect-2); GC it and a leave-then-rejoin
    of the *same* account orphans the old password (AGY-r4 leave-rejoin);
    and GC-at-top collides with the empty-login early-return (Codex/AGY-r4
    GC-bypass). The UID disambiguates all three **without any GC**:
    - Leave-then-rejoin same account: UID unchanged → `pwLock` fires →
      old password revoked (D2 honored).
    - `userdel` + out-of-band recreate: new account gets a different UID
      (or the operator chose a fixed UID — see edge case) → UID mismatch
      → `pwLock` skips → out-of-band account untouched.
    - Empty-login early-return: irrelevant — no GC pass to bypass; the
      marker simply persists and is re-validated by UID on the next apply
      that includes the user.
  - **Edge case (documented)**: if an out-of-band recreate happens to
    reuse the *exact same UID* xpf recorded, the marker would match and
    `pwLock` would fire. This is acceptable and arguably correct — same
    name + same UID is indistinguishable from the original xpf-managed
    account; the operator can re-add `encrypted-password` to restore it.
    Note in docs.
  - **Marker cleanup** is opportunistic, not a separate GC pass: when
    `xpfProvisioned` finds a marker whose UID no longer matches (account
    deleted/recreated), it MAY rewrite/remove the stale marker inline.
    No dependency on the early-return path.
  This makes "xpf-managed-this-exact-account" **enforced**, not asserted.
- **Never** lock root (root is excluded from this loop at @668; handled by
  `applyRootAuth`).
- `<user>:!` via `chpasswd -e` produces a locked entry — verified live by
  AGY in r2. (`usermod -L`/`passwd -l` equivalent; chpasswd keeps one
  idiom.)

### 5.5 Validator (crypt(3) hash recognizer — precise)
```go
// pkg/config/schema_validators.go
func ValidateCryptHash(raw string, _ *Config) error
```
Accept (case-sensitive):
1. **Modular crypt**: optional leading `!` or `!!` (locked-but-restorable
   form), then `$<id>$<salt>$<checksum>` where `<id>` ∈ {`1`,`2a`,`2b`,
   `2y`,`5`,`6`,`7`,`y`,`gy`}, `<salt>` is non-empty (may itself contain
   `$`-separated params such as `rounds=N` for `$5$`/`$6$` or yescrypt
   `$y$` params), and **`<checksum>` (the segment after the FINAL `$`) is
   non-empty** (r3 Major-3 — `$6$salt$` with an empty checksum is
   rejected: it would write a malformed shadow field PAM rejects). The
   alphabet for salt/checksum is `[./0-9A-Za-z]`; field separators are
   `$`; `rounds=N` introduces `=` so `=` is allowed **inside a param
   field only** (AGY r2 #1). Concretely: at least two `$` after the id,
   and a non-empty final field.
2. **Explicit lock sentinels**: a bare `*`, `!`, or `!!` (r2/S2-3, AGY
   r2 Finding-2). The *intentional* Unix way to lock an account, and the
   ONLY way to lock root via `root-authentication encrypted-password "*"`
   (root is excluded from D2 auto-lock). Accepting these is NOT the F-1
   footgun — that was **plaintext** silently accepted, not a deliberate
   sentinel.
**Legacy DES dropped** (r3 Major-2): a 13-char crypt-base64 string was
in r3, but it makes plaintext-rejection non-absolute — `"password12345"`
(13 alnum) would pass and write garbage to shadow. No Junos operator
ships DES; dropping it makes "reject plaintext" a hard guarantee.
Reject:
- Anything not matching cases 1-2 — in particular **plaintext** (no `$`,
  not a bare sentinel). This is the real F-1 footgun: an operator pasting
  cleartext into `encrypted-password`. With DES gone this is now
  absolute. Empty string is also rejected at the leaf (a typed leaf
  requires a value; "no password" is expressed by omitting the directive,
  which D2 handles).
- A modular hash with an empty final field (`$6$salt$`, `$6$$x` where the
  salt is empty) — r3 Major-3.
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
A commit warning when a `login user` has **no usable auth method** —
i.e. no `ssh-*` keys AND (no `encrypted-password` OR an
`encrypted-password` that is a bare lock sentinel `*`/`!`/`!!`) (r3
Minor-2 — a sentinel password is not a usable login path). Mirrors the
existing root warning style (compiler.go:699-707). **Decision**: include
it — directly addresses the "can't log in" bug class. Low cost.

---

## 6. Multiple Path Options (resolved)

### Path A — apply mechanism: **A1 `chpasswd -e`** (decided)
Byte-identical idiom to `applyRootAuth` *including the
`runCommandStdinTimeout` wrapper* (S-2 fix); hash on stdin → no argv
leak. A2 `usermod -p` rejected (hash visible in `/proc/<pid>/cmdline`).

### Path B — idempotency: **B1 skip-if-unchanged, fail-open** (decided)
Read `/etc/shadow` **directly** (not `getent`/NSS — r2/S2-4); apply on
read-fail / missing / mismatch (S-8/F-4 — never skip a needed apply).
Decision encapsulated in the pure `passwordAction` helper (§5.4). B2
(always-apply, like root today) is the safe fallback if the direct read
proves problematic in smoke.

### Path C — validation strictness: **C1 permissive recognizer** (decided)
Accept modular crypt ids with a non-empty checksum + optional `!`-prefix
+ **bare lock sentinels `*`/`!`/`!!`** (r2/S2-3); **reject plaintext**
(the real footgun) and **legacy DES** (dropped in r4 so the
plaintext-rejection is absolute — §5.5, r3 Major-2). C2 strict per-id
structural parse rejected (brittle across libc / yescrypt params). C3 no
validation rejected (reproduces the plaintext footgun).

### Path D — directive removal: **D2 lock the account** (decided — flipped from r1)
Removing `encrypted-password` from a configured user locks password
login (`<user>:!`), idempotently, **only for the exact xpf-managed
account** (enforced by the **UID-keyed** `/var/lib/xpf/provisioned-users/
<name>` marker — §5.4, r4), never root, and **never on a shadow read
error** (r2/S2-1 — `passwordAction` returns `pwNoop` when `ok==false`).
D1 (do nothing) **rejected** — orphans a live credential outside config
control (Codex F-2 + AGY #2 + SMR S-3, three-way convergence). D3
(passwordless) rejected. This makes the *password* attribute declarative
while SSH-keys/sudoers remain additive — a deliberate, documented
asymmetry (a live password is a higher-severity orphan than a stale
key). An operator can also lock explicitly via `encrypted-password "*"`
(Path C accepts the sentinel) without removing the directive.

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
     `$y$j9T$salt$hash`, `$2b$10$…`, `!$6$salt$hash` (locked-restorable),
     **bare `*`, `!`, `!!`** (explicit lock — r2/S2-3).
   - Reject: `plaintext`, `password12345` (13 alnum — r3 Major-2, the
     DES-drop case), ``(empty), `$99$bogus`, `$6$` (no salt body),
     **`$6$salt$`** (empty checksum — r3 Major-3), **`$6$$hash`** (empty
     salt), `$6$salt:hash` (colon), `$6$ab cd` (space).
4. **SchemaValidate / commit-check**: a config with a plaintext per-user
   `encrypted-password` fails `SchemaValidate` (hard gate); a valid hash
   passes. Mirror for root-auth (E1) — including that
   `root-authentication encrypted-password "*"` (lock root) is accepted.
5. **Root-auth E1 fixtures**: update `$6$abc123`/`$6$abc` to well-formed
   hashes; assertions follow (§5.7).
6. **`passwordAction` pure decision table test** (r2/S2-5, Codex M-4) —
   the core invariant coverage, no exec:
   - desired set, `ok=true`, cur != desired → `pwApply`.
   - desired set, `ok=true`, cur == desired → `pwNoop`.
   - desired set, `ok=false` (read fail) → `pwApply` (fail-open).
   - desired empty, `ok=true`, cur == "" (passwordless) → `pwLock` (S2-1).
   - desired empty, `ok=true`, cur == "$6$…" (usable hash) → `pwLock`.
   - desired empty, `ok=true`, cur == "!"/"*"/"!$6$…" (locked) → `pwNoop`.
   - desired empty, `ok=false` (read fail) → `pwNoop` (no transient-error
     lockout).
7. **`isLockedShadow` table test**: `""`→false, `"*"`→true, `"!"`→true,
   `"!!"`→true, `"!$6$x"`→true, `"$6$x"`→false.
8. **`currentShadowHash` parse**: given a sample `/etc/shadow` line, returns
   field-2 + ok; missing user → `("",false)`. (`chpasswd` exec is
   integration/smoke.)
9. **Provenance UID-keyed marker** (r3 Major-1 + AGY-r3/-r4 + r4
   GC-bypass) — temp marker dir injected for the test:
   - `markProvisioned(name, 1001)` then `xpfProvisioned(name, 1001)` →
     true; `xpfProvisioned(name, 2002)` (UID mismatch) → false; no marker
     → false.
   - **Set-then-marker invariant**: after a `pwApply`, the marker exists
     with the right UID (so a subsequent directive removal locks). Covers
     the orphan on an initially-unmarked account (Codex Major-1 + AGY
     defect-1).
   - **Leave-then-rejoin same account**: marker UID == current UID →
     `pwLock` fires (D2 honored) — no orphan (AGY-r4 leave-rejoin).
   - **userdel + out-of-band recreate (different UID)**: marker UID !=
     current UID → `pwLock` skips → out-of-band account untouched
     (AGY-r3 defect-2 / AGY-r4).
   - **Empty-login config**: removing all users does NOT strand the
     mechanism — no GC pass exists to be bypassed by the early-return
     (Codex/AGY-r4 GC-bypass); markers persist and are UID-revalidated on
     the next apply that includes the user.

### Smoke (loss userspace cluster — confirmatory, optional)
Control-plane-only change, no dataplane/forwarding impact → no perf
smoke. Minimal live check:
1. `make cluster-deploy`; `set system login user op class operator
   authentication encrypted-password "<known $6$ hash for 'test123'>"`;
   commit.
2. `cluster-ssh` → `getent shadow op` shows the hash in field 2; marker
   `/var/lib/xpf/provisioned-users/op` exists and contains `op`'s UID.
3. Console / `su - op`: authenticate with `test123` — succeeds.
4. Re-commit unchanged → journal shows **no** "user encrypted-password
   applied" (idempotency B1).
5. **D2**: delete the `encrypted-password` directive, commit →
   `getent shadow op` field 2 is `!` (locked); console password login
   for `op` now fails; SSH-key + sudo still work.
6. **Provenance**: manually create an out-of-band account `extuser` with
   a password (no marker), then add `set system login user extuser` (no
   encrypted-password), commit → `extuser`'s password is **untouched**
   (no marker → no D2 lock). Then `userdel op` + recreate `op`
   out-of-band with a new UID + password, re-commit the (still
   password-less) `op` config → `op` password untouched (marker UID !=
   new UID → skip).
7. Root login + SSH-key login + sudo unchanged (no regression).

`make test` is the gate; smoke is confirmatory per reviewer call.

---

## 8. Rollback / Risk

- **Validator rejects a valid hash** → can't commit a good password.
  Mitigated by permissive recognizer (C1) + `=`/`rounds=` coverage +
  the glibc-id-list review check + boot-path downgrade (§5.6 — a
  persisted hash never bricks boot).
- **Shadow read (B1) misbehaves** → `passwordAction` set-branch returns
  `pwApply` (harmless re-apply) rather than skipping; lock branch returns
  `pwNoop` on `ok==false`, so a transient read error can NEVER lock out an
  operator (the asymmetric fail-open/fail-closed posture is the central
  safety invariant, table-tested §7.6). Direct `/etc/shadow` read avoids
  the NSS-cache staleness `getent` would introduce.
- **Accidental console lockout via D2** → only locks **xpf-provisioned**
  users (marker-gated) whose `encrypted-password` is absent; an operator
  relying on a console password keeps it as long as the directive is
  present; SSH-key + sudo are unaffected; out-of-band accounts are never
  touched. The lock is reversible (re-add the directive). Documented
  (§10).
- Rollback: revert the commit; no migration, no schema version bump, no
  map/wire change. Existing `/etc/shadow` entries set before the revert
  remain as the OS left them.

---

## 9. Open Questions for Reviewers (r5 — narrowed)

1. **Provenance store**: **UID-keyed** marker file
   `/var/lib/xpf/provisioned-users/<name>` (content = UID; written on
   useradd AND pwApply; validated by UID at lock time; no separate GC
   pass). Alternatives considered + rejected: name-only marker (forces an
   unwinnable keep-vs-GC choice — see §5.4), `/etc/shadow` comment, or
   the sudoers file. `/var/lib/xpf` is persistent (holds the config DB +
   archive — confirmed durable). OK, or prefer a different store?
2. **Validator id superset**: accept `$7$` (scrypt) + `$gy$` beyond the
   universal set? Plan says accept (OS is final authority).
3. **Legacy DES drop** (r3 Major-2): plan drops 13-char DES support to
   make plaintext-rejection absolute. Confirm no operator relies on DES
   (none should on Debian 13). If any did, they would re-hash.
4. **Commit warning** (§5.8) for users with no *usable* auth method
   (no keys AND no non-sentinel password) — include? Plan says yes.

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
    are independent. The lock applies only to xpf-managed accounts
    (UID-keyed marker); an account `userdel`'d + recreated out-of-band
    with a new UID is left alone. **Edge case**: if the recreate reuses
    the same name + same UID, xpf treats it as the original managed
    account and may lock it — re-add `encrypted-password` to restore.
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
| r2    | PLAN-NEEDS-WORK | PLAN-NEEDS-WORK | PLAN-NEEDS-WORK |
| r3    | PLAN-NEEDS-WORK | PLAN-NEEDS-WORK | PLAN-NEEDS-WORK |
| r4    | PLAN-NEEDS-WORK | PLAN-NEEDS-WORK | PLAN-NEEDS-WORK |
| r5    | pending | pending | pending |
