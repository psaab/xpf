# Codex Hostile Plan Re-Review — #1944 (r2)

Codex task id: `019ed488-dcaf-7ad1-9e62-193a57045937`

## Verdict: PLAN-NEEDS-WORK

r1 fatals F-1..F-4 and minors M-1..M-3, M-5/M-6 resolved. M-4 still open. Two NEW r2 fatals:

### New Fatal 1 — empty shadow field treated as locked (isLockedShadow off-by-one)
`isLockedShadow(s): s == "" || ...` treats an empty `/etc/shadow` field as "locked", but empty = passwordless login (passwd -d semantics). A non-root user with an empty field + no configured password falls through `ok && !isLockedShadow(cur)` (false) → never locked → passwordless login stays active. Predicate must be `strings.HasPrefix(s,"!") || s=="*"` (lock empty), NOT `s==""` as already-locked.

### New Fatal 2 — "provisioned-users-only" guarantee is phantom
origin/master `applySystemLogin` has NO provenance marker. The loop is over configured users, skips root, `id`/creates on error — no record of whether xpf provisioned the account. A pre-existing local `op` account with an out-of-band password later added to config WITHOUT encrypted-password would be locked even though xpf did not create it. Need a concrete provenance mechanism (creation-time marker / only-just-created / sentinel) not an unenforced scope claim.

### Minor (M-4 unresolved) — D2 lock-transition unit test still only smoke.

### Nit — stale line anchors persist:
- LoginUser @302 / RootAuthConfig @151 (not 282/130)
- daemon_apply.go apply calls @1021-1027 (not 912-918)
- compiler.go root warning @699-707 (not 641)
