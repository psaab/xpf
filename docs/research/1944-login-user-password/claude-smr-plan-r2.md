# Claude SMR Hostile Plan Re-Review — #1944 (r2)

## Verdict: PLAN-NEEDS-WORK (concur with Codex + AGY)

r2 correctly resolved all r1 fatals. But the new D2 lock machinery
introduced three real defects, two found independently by both
companions. I concur and add design resolution for the
sentinel/validator tension.

### [S2-1] FATAL — `isLockedShadow("")` is inverted (Codex New-Fatal-1 + AGY Finding-1, independent convergence)
r2 §5.4 lists `isLockedShadow(s): s == "" || ... ` and the lock branch
fires only when `ok && !isLockedShadow(cur)`. An **empty** shadow field
is *passwordless login* (`passwd -d` semantics — the plan itself cites
factory passwordless root), the MOST permissive state, not a locked one.
Treating `""` as "already locked" means a passwordless account with no
configured password is **never** locked — the opposite of D2's intent.
**Fix**: `isLockedShadow(s)` returns true only for an actually-locked
field: `s == "*" || strings.HasPrefix(s, "!")`. An empty field is NOT
locked → it falls into the lock branch and gets `!` written. (Note:
`*` and `!!` and `!<hash>` all satisfy `HasPrefix("!")` except `*`,
hence the explicit `*` arm.)

### [S2-2] FATAL — "provisioned-users-only" is an unenforced claim (Codex New-Fatal-2)
r2 asserts the lock is "structurally scoped to provisioned users only"
because the branch is inside the per-config-user loop. That only scopes
it to *configured* users, not *xpf-provisioned* ones. A pre-existing
local account (created out-of-band, with its own password) that an
operator later references in config **without** `encrypted-password`
would get its password locked by D2 — surprising and potentially a
lockout of a legitimately-managed account. **Fix options for r3**:
- **(a) Marker file**: on `useradd`, drop `/var/lib/xpf/provisioned-users/<name>`
  (or a comment in sudoers we already own); D2 locks only if the marker
  exists. Clean, explicit, survives reboot.
- **(b) Just-created only**: lock-on-removal only applies in the same
  apply where we did NOT just create the user AND we have a recorded
  provenance; otherwise leave it. Weaker.
- **(c) Narrow the contract**: D2 only ever *unlocks via apply* and only
  ever locks accounts whose shadow field is currently empty/`!` from our
  own prior `useradd` — i.e. never overwrite a non-empty non-locked hash
  we didn't set. This is subtle; (a) is cleaner.
- Recommend **(a)** marker file. Document that D2 reconciliation applies
  only to xpf-provisioned accounts; out-of-band accounts referenced in
  config are left alone.

### [S2-3] FATAL/HIGH — E1 + bare-sentinel rejection breaks root lock-via-config (AGY Finding-2)
This is a design conflict I introduced in r2: §5.5 rejects bare `*`/`!`,
but root is **excluded** from D2 auto-lock (§5.4 "never root"), so for
root the *only* way to express "lock the password" is
`root-authentication encrypted-password "*"` (or `"!"`) — which the
shared E1 validator now rejects. **Resolution**: re-examine F-1's actual
footgun. F-1 was about **plaintext** silently locking an account. Bare
`*`/`!`/`!!` are not plaintext — they are the *explicit, intentional*
Unix way to request a locked account, and Junos/operators legitimately
use them. So the correct validator policy is:
- **Accept** bare `*`, `!`, `!!` (explicit lock — operator clearly meant
  it; this also restores root lock-via-config and lets a per-user
  account be explicitly locked without removing the directive).
- **Accept** a crypt hash, optionally `!`/`!!`-prefixed.
- **Reject** plaintext (no `$`, not 13-char DES, not a bare sentinel) —
  the real footgun.
This is *simpler* than r2 and removes the §S2-3 conflict entirely. The
original F-1 ("accepts locked sentinels defeats the purpose") was
half-right: the fix is not to reject sentinels but to reject *plaintext*.
A bare sentinel is a deliberate lock, not an accident. D2's empty/lock
handling (§S2-1) covers the "no directive at all" case separately.

### [S2-4] MEDIUM — read `/etc/shadow` directly, not `getent shadow` (AGY Finding-3)
`getent shadow` shells out and is subject to `nscd`/NSS caching →
stale reads → spurious re-apply or a missed lock. The daemon is root;
read `/etc/shadow` directly (line-parse, field 2) — faster, no NSS
cache, no subprocess. **Fix**: `currentShadowHash` reads `/etc/shadow`
directly with a guarded open; returns `("", false)` on error/absence.

### [S2-5] MEDIUM — M-4 still open: add the D2 lock-transition unit test
Both r1 (Codex M-4) and r2 leave the lock-transition path untested at
unit level. The decision logic (given `cur` + `desired`, should we
apply / lock / skip?) is pure and testable if extracted into a helper
like `passwordAction(cur string, ok bool, desired string) action`
(returns apply / lock / noop). r3 must add a table test over that helper
covering: desired set + cur differs → apply; desired set + cur equal →
noop; desired empty + cur unlocked → lock; desired empty + cur `!`/`*`
→ noop; desired empty + read fail (ok=false) → noop (don't lock on a
read error — avoid transient-error lockout). Extracting the pure
decision also resolves Codex's "does the lock branch do nothing on read
failure?" concern by making it a tested invariant.

### [S2-6] NIT — fix the stale line anchors (Codex nit)
r3 must correct: `LoginUser @302`, `RootAuthConfig @151`
(types_system.go); apply calls `daemon_apply.go @1021/1027`; root
warning `compiler.go @699-707`. (Verified against origin/master.)

---

## What r2 got right (keep)
- `runCommandStdinTimeout` apply (S-2 fixed). ✅
- Path D2 *intent* (lock on removal) is correct — only the predicate
  (S2-1) and provenance (S2-2) need fixing. ✅
- Validator `=`/`rounds=` + `!`-prefix + `:` exclusion. ✅ (just also
  accept bare sentinels per S2-3.)
- Fail-open-toward-applying idempotency for the *set-password* branch. ✅
- SchemaValidate hard-gate-at-commit / warning-on-boot contract. ✅
- E1 + fixture updates. ✅ (now also unblocks root lock per S2-3.)
- Concrete docs target + openssl example. ✅

## Required for r3 → PLAN-READY
1. `isLockedShadow`: empty is NOT locked; locked = `*` or `!`-prefix. [S2-1]
2. Concrete provenance mechanism (marker file) for D2 scope. [S2-2]
3. Validator: ACCEPT bare `*`/`!`/`!!` (explicit lock); reject only
   plaintext. Unblocks root lock-via-config under E1. [S2-3]
4. `currentShadowHash` reads `/etc/shadow` directly (no getent/NSS). [S2-4]
5. Extract pure `passwordAction` decision helper + table test incl
   read-failure → noop. [S2-5]
6. Correct the stale line anchors. [S2-6]
