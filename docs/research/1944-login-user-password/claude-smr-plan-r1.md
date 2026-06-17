# Claude SMR Hostile Plan Review — #1944 (r1)

## Verdict: PLAN-NEEDS-WORK

The mechanism (mirror `applyRootAuth`'s `chpasswd -e`, typed-leaf
crypt-hash validator, close the schema asymmetry) is structurally
correct and the blast radius is genuinely small. But r1 has **stale
code references** (it was drafted against a checkout behind
origin/master), **two recommended Path decisions that are wrong**
(D1 reconciliation, validator accepting bare sentinels), and a
**material omission** (the apply-path timeout wrapper). Convergent with
Codex + AGY. Blocks until r2.

---

### [S-1] FATAL — r1 references the WRONG file and stale line numbers
r1 §3/§5.3 cites `pkg/config/schema.go:1039/1078` for the login +
root-authentication schema. On origin/master (the worktree base,
`004c6eaf4`) the system schema lives in **`pkg/config/schema_system.go`**
— `root-authentication` @31-33, `login user authentication` @66-70
(`children: nil`). `schema.go` is the top-level tree; the system subtree
was extracted. This is the same drift Codex flagged as a "nit" but it is
load-bearing: an implementer following r1's line refs edits the wrong
file. **Fix**: r2 must re-anchor every code reference to the
origin/master reality:
- schema: `pkg/config/schema_system.go` (login @66, root-auth @31)
- apply: `applySystemLogin` @656, `applyRootAuth` @774
- root chpasswd already uses `runCommandStdinTimeout(stdin,"chpasswd","-e")`
  @784; `useradd` uses `runCommandTimeout` @677.

### [S-2] FATAL — r1's apply pseudocode drops the timeout wrapper (matches Codex F-3)
r1 §5.4 writes `exec.Command("chpasswd","-e")` + `CombinedOutput()`. The
*current* `applyRootAuth` uses `runCommandStdinTimeout` (exec_timeout.go).
r1 claims "byte-identical to applyRootAuth" — it is not. A raw
`exec.Command` with no timeout can wedge the daemon apply path. **Fix**:
r2 pseudocode must use `runCommandStdinTimeout(strings.NewReader(...),
"chpasswd","-e")`.

### [S-3] FATAL — D1 leaves an orphaned live credential (matches Codex F-2 + AGY #2)
Both companions independently flag this; I concur and it is the single
most important design correction. r1 §6 Path D recommends D1 ("leave the
hash on directive removal"). In a declarative config system, removing
`encrypted-password` and committing must **disable** that password —
otherwise the old console/SSH password keeps working while the config
shows nothing. That is a silent security regression *introduced by this
feature*. r1's "least surprise / don't lock out mid-session" rationale
is wrong: locking the *password* does not terminate live sessions and
the operator still has SSH-key + sudo. **Fix**: adopt **D2** — when a
configured user has an empty `EncryptedPassword`, lock the account via
`chpasswd -e` with stdin `<user>:!` (or `usermod -L`/`passwd -l`). Pair
with idempotency (§S-5) so we only lock on transition, and only for
users xpf provisioned (never root; never users absent from config —
that's the separate out-of-scope deprovisioning question, keep it out).
Note the asymmetry r1 leaned on (SSH keys/sudoers are additive-only) is
itself arguably a latent gap, but a *password* orphan is higher-severity
than a stale key because it's a memorizable secret.

### [S-4] FATAL — validator accepts bare locked sentinels as a "password" (matches Codex F-1)
r1 §5.5 / §7 accepts `*`, `!`, `!!` as valid `encrypted-password` values.
Combined with the apply path, `set ... encrypted-password "!"` commits
clean and writes a locked field under a directive whose entire purpose is
to *enable* login. **Fix**: the validator must **reject** a value that is
*only* a sentinel. The legitimate need AGY raises (#3) — a real hash
prepended with `!`/`!!` to ship a pre-locked-but-restorable account — is
different and should be handled by §S-6, not by accepting bare `!`.

### [S-5] HIGH — validator alphabet rejects valid `rounds=` hashes (matches AGY #1)
r1 §5.5 alphabet `[./0-9A-Za-z$]` omits `=`. `$6$rounds=656000$salt$hash`
and `$5$rounds=...$...` are standard and would be **rejected at commit**,
locking the operator out of committing a good password. **Fix**: allow
`=` (and `,` is not used by crypt, but yescrypt `$y$` params use `$`
separators only — confirm). r2 should specify the regex precisely and
table-test `rounds=`.

### [S-6] HIGH — leading `!`/`!!` on a real hash unhandled (matches AGY #3)
Standard Unix lock-with-restore is `!$6$salt$hash`. r1's recognizer
doesn't allow an optional leading `!`/`!!` before a valid hash. If we
support pre-locked accounts at all, this is the correct form (not bare
`!`). **Fix**: optional leading `!`/`!!` prefix accepted; bare sentinel
rejected (§S-4). Decision for r2: do we even *want* to support pre-locked
hashes, or is that scope creep? I lean **accept the prefix** (cheap, and
it's the only safe way to express "locked account" without the §S-4
footgun) but it's a legit reviewer choice.

### [S-7] MEDIUM — colon / newline injection into `chpasswd` stdin (matches Codex M-2)
`chpasswd -e` reads `user:hash\n` line-oriented. A hash containing `:`
or a newline (which the typed-leaf control-char gate in `freetext.go`
*does* hard-reject at strict commit — see S-9, so newline is covered)
would mis-parse. Crypt base64 never contains `:`, so a correct validator
that constrains the alphabet inherently blocks `:`. **Fix**: ensure the
validator's accepted alphabet excludes `:` (it does, if specified as
crypt-base64 + `$=!`), and add a negative test for `:`.

### [S-8] MEDIUM — idempotency read fragility under-specified (matches Codex F-4)
r1 §5.4/§6 Path B1 reads `/etc/shadow`/`getent shadow`. If the read
fails and the code treats "can't read" as "matches, skip", a first-time
commit can `useradd` then *skip* the password set → the exact lockout
this issue fixes. **Fix**: r2 must specify fail-OPEN-toward-applying:
on read error OR no entry OR differing hash → apply. Only skip when the
read *succeeds and equals* the desired hash. Also note root-auth (B2,
always-apply) is the safe simple fallback and is acceptable.

### [S-9] LOW — clarify the SchemaValidate gate semantics (strengthens the plan)
r1 doesn't state where SchemaValidate runs. Verified: it is a **hard
commit-check gate** (`pkg/configstore/check.go`,
`TestCheckTextSchemaValidateGate`) — so the crypt validator *does* block
plaintext at operator-commit time. BUT on the lenient boot/peer-sync
path SchemaValidate violations are **downgraded to a warning**
(`pkg/config/freetext.go:20-25`, `compileTreeLenient`). This is exactly
the behavior we want: plaintext is rejected when an operator commits,
but an already-persisted bad value (or a peer-synced one) cannot brick
boot. r2 should state this explicitly in §5.5/§8 — it converts an
implicit assumption into a verified contract and pre-empts the "does the
validator lock us out of boot?" objection.

### [S-10] LOW — fixtures `$6$abc123` / `$6$abc` will fail E1 (matches Codex M-1, AGY #4)
If Path E1 (validate root-auth with the shared validator) lands, the
existing test fixtures `"$6$abc123"` (parser_system_test.go:320,358) and
`"$6$abc"` (:727,745) have no salt separator and a strict validator
rejects them. **Fix**: update fixtures to well-formed
`$6$salt$hash` rather than weakening the validator (AGY #4 is right —
don't weaken production code for a dummy). r2 should pick E1 and own the
fixture update, OR pick E2 (per-user only) and explicitly leave root's
footgun for a follow-up. I lean **E1** — one validator, consistent
errors, and root's plaintext footgun is identical and worth closing.

### [S-11] LOW — docs target must be concrete (matches Codex M-5)
r1 §10 hand-waves "candidate doc or new docs/system-login.md". Confirmed
there is no `docs/system-login.md` and no single canonical system-login
contract doc. r2 should commit to a concrete target and MUST include a
hash-generation example (`openssl passwd -6` / `mkpasswd -m sha512crypt`)
so operators don't paste plaintext — this is the documentation
counterpart to the §S-4 validator footgun.

---

## What r1 got right (keep)
- `chpasswd -e` over `usermod -p` (Path A1) — no argv leak. Correct.
- Typed-leaf `ValueCryptHash` + validator wiring via #1319 machinery —
  correct mechanism (verified `schemaNode.isTypedLeaf` →
  `SchemaValidate` dispatch).
- #1916 fsatomic note (chpasswd is a process, not a file write) — correct
  for the password line, though Codex M-6 rightly narrows it (sudoers /
  authorized_keys in the same function ARE `os.WriteFile`).
- Dual-AST handling via `namedInstances` + `nodeVal` reuse — correct;
  add the explicit flat-set test (Codex M-3).
- Small blast radius, no wire/HA/dataplane impact — correct.

## Required for r2 to reach PLAN-READY
1. Re-anchor all code refs to origin/master (schema_system.go; line nums). [S-1]
2. Use `runCommandStdinTimeout` in the apply pseudocode. [S-2]
3. Switch Path D recommendation D1 → **D2** (lock on removal, idempotent,
   provisioned-users-only). [S-3]
4. Validator: reject bare `*`/`!`/`!!`; accept optional leading `!`/`!!`
   prefix on a real hash; include `=` in the alphabet; exclude `:`;
   precise regex + table tests. [S-4,S-5,S-6,S-7]
5. Idempotency: specify fail-open-toward-applying on read error / no
   entry. [S-8]
6. State the SchemaValidate hard-gate-at-commit / warning-on-boot
   contract. [S-9]
7. Pick E1 and own the fixture updates (or pick E2 with explicit
   follow-up). [S-10]
8. Concrete docs target + hash-generation example. [S-11]
9. Add tests: directive-removal/lock, read-failure, chpasswd-nonzero,
   flat-set shape equality, validator negatives (`:`, plaintext, bare
   sentinel, `rounds=` accept, `!`-prefix accept). [Codex M-4]
