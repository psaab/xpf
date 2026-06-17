# Claude SMR Hostile Plan Re-Review — #1944 (r3)

## Verdict: PLAN-NEEDS-WORK (concur with Codex + AGY)

r3 resolved every r2 finding. The three new r3 blockers are all real and
two were found independently by both companions. I concur and validated
the fixes folded into r4.

### [S3-1] FATAL — `pwApply` without a marker orphans xpf-managed passwords (Codex Major-1 + AGY-r3 defect-1, independent)
Confirmed by trace: a pre-existing/marker-wiped account gets a password
via `pwApply` (no marker required in r3), the operator removes the
directive, `passwordAction` → `pwLock`, but `if !xpfProvisioned { break }`
skips because no marker exists. The credential xpf just wrote is never
revoked — D2's whole point defeated. **Fix folded into r4**: drop the
marker on every successful `pwApply` too (`markProvisioned` after the
chpasswd succeeds), so "xpf wrote this password" implies "xpf will
revoke it." This is the correct semantic — the marker should mean
"xpf-managed password," not "xpf-created account."

### [S3-2] HIGH — stale marker leakage locks out a recreated out-of-band account (AGY-r3 defect-2)
A user is removed from config; the marker file lingers. The operator
`userdel`s + recreates out-of-band with a password, re-references in
config (for SSH keys, no password) → stale marker → `pwLock` locks the
new account. **Fix folded into r4**: GC markers at the top of
`applySystemLogin` for any marker whose username is not in
`cfg.System.Login.Users`. This is the symmetric bookend to S3-1 and
makes the marker set track the config set.

### [S3-3] HIGH — 13-char plaintext passes the legacy-DES regex (Codex Major-2)
`"password12345"` is 13 alnum chars → matches DES → written as garbage,
console login fails, commit said success. The plaintext-rejection
guarantee (the feature's core safety property) is broken by DES support.
**Fix folded into r4**: drop legacy DES entirely. No Debian 13 operator
ships DES; removing it makes "reject plaintext" absolute. Verified: this
does not lose any realistic capability.

### [S3-4] MEDIUM — empty-checksum modular hash accepted (Codex Major-3)
`$6$salt$` (empty final field) passes r3's "non-empty body + ≥1 `$`
after id" rule but is a malformed shadow field PAM rejects → de-facto
lockout with a "successful" commit. **Fix folded into r4**: require a
non-empty final field (checksum) — at least two `$` after the id and a
non-empty tail. Negative tests for `$6$salt$` and `$6$$hash`.

### [S3-5] LOW — success criterion 3 contradicted §5.5 (Codex Minor-1)
§2 success criterion said "reject bare locked sentinels"; §5.5 (since r3)
accepts them. **Fixed in r4** — criterion 3 now: reject plaintext;
accept deliberate sentinels.

### [S3-6] LOW — "no auth method" warning silent for sentinel-locked accounts (Codex Minor-2)
`encrypted-password "*"` + no keys = no usable login, but the directive
is present so the r3 warning wouldn't fire. **Fixed in r4**: warning
condition is "no keys AND (no password OR password is a bare sentinel)."

### [S3-7] NIT — remaining stale anchors (Codex Nit-1)
`schema_walk.go` dispatch @236 (not 40/89/298/331), `isTypedLeaf`
schema.go @97, compiler_system root-auth @131. **Fixed in r4.**

---

## My own additional checks (no new blockers)
- **Marker-on-pwApply ordering**: r4 calls `markProvisioned` only on
  chpasswd *success*. Correct — never claim management of a password we
  failed to write (otherwise a failed apply would arm a future lock of an
  unmanaged account). ✓
- **GC vs apply ordering**: GC must run at the *top* of `applySystemLogin`
  BEFORE the per-user loop, so a user that's both leaving and re-entering
  in different commits is handled by the current config snapshot. r4 says
  "top of applySystemLogin." ✓ Confirm GC reads the *current* cfg user
  set, not a cached one.
- **`/var/lib/xpf` durability**: the marker store must survive reboot for
  D2 to be reliable. `/var/lib/xpf` already holds the configstore DB +
  archive dir (durable, not tmpfs). ✓ (Flagged as open Q1 for reviewer
  confirmation.)
- **Concurrency**: `applySystemLogin` runs under the apply lock
  (`applyConfigLocked`), single-threaded per commit — no marker race. ✓
- **passwordAction asymmetry** re-verified sound (both companions agree):
  set-branch fail-OPEN (apply), lock-branch fail-CLOSED (noop). ✓

## Required for r4 → PLAN-READY (all folded in this rev)
1. Marker on `pwApply` too; gate `pwLock` on the marker = "xpf-managed". [S3-1]
2. GC stale markers for users no longer in config. [S3-2]
3. Drop legacy DES → plaintext-rejection absolute. [S3-3]
4. Require non-empty checksum (reject `$6$salt$`, `$6$$hash`). [S3-4]
5. Reword success criterion 3 (accept sentinels). [S3-5]
6. Warning fires for sentinel-locked + no-keys. [S3-6]
7. Fix remaining anchors. [S3-7]
