# Claude SMR Hostile Plan Re-Review — #1944 (r4)

## Verdict: PLAN-NEEDS-WORK (concur with Codex + AGY)

r4 resolved Major-1, Major-3, Minor-1/2, and most anchors. Two issues
remained, one of them a real ordering bug found independently by both
companions, and AGY surfaced a deeper design tension that the r4 name-only
marker could not resolve. r5 adopts a UID-keyed marker that dissolves all
three problems at once.

### [S4-1] FATAL — GC bypassed by the empty-login early-return (Codex Major + AGY Finding-1, independent)
`applySystemLogin` returns early at @657-659 when there are zero
configured users. r4's "GC at the top of applySystemLogin" collides with
this: remove ALL users → early-return → GC never runs → markers leak →
the very stale-marker lockout GC was added to prevent (defect-2) returns.
Found independently by Codex and AGY (the latter rated it Critical with a
7-step counter-example). **Root cause**: GC is the wrong primitive — it
ties marker validity to *config membership at GC time*, which is fragile.

### [S4-2] HIGH — leave-then-rejoin orphan (AGY Finding-2), unsolvable by name-only marker
AGY's deeper catch: even with GC working, a name-only marker forces an
unwinnable choice. Keep the marker on user-removal → a `userdel`+recreate
gets locked (defect-2). GC it on removal → a leave-then-rejoin of the
*same* account orphans its old password (D2 violated). The two failure
modes are mutually exclusive under a name-only key. **AGY's resolution is
correct**: key the marker by **UID** and compare against the live UID at
lock time. This disambiguates "same account" (UID match → lock) from
"recreated out-of-band" (UID mismatch → skip), and — crucially —
**eliminates GC entirely**, which also dissolves S4-1 (no GC pass to be
bypassed by the early-return). r5 adopts this.

### [S4-3] MEDIUM — §6 Path C still listed DES (Codex Major/consistency)
§5.5/§7 dropped DES (r4) but §6 Path C still read "Accept ... DES ...".
An implementer following §6 re-adds the 13-char-plaintext footgun.
**Fixed in r5** — §6 Path C now says reject DES.

### [S4-4] NIT — stale anchor daemon_apply.go:912-918 (Codex Nit)
The apply-ordering reference pointed at comment text, not the calls
(@1021/1027). **Fixed in r5.**

---

## My own analysis of the r5 UID-keyed design (no new blockers)
- **UID availability**: confirmed `applySystemLogin` already resolves the
  account (shells `id`); `user.Lookup(name).Uid` (or `/etc/passwd` parse)
  gives the live UID cheaply. `lookupUID` returns `(uid, ok)`; `pwLock`
  skips if `!ok` (can't resolve → don't lock). ✓
- **Edge case — UID reuse**: if an out-of-band recreate reuses the exact
  recorded UID, the marker matches and `pwLock` fires. I judge this
  ACCEPTABLE: same name + same UID is operationally indistinguishable
  from the original xpf-managed account, and the lock is reversible by
  re-adding the directive. Documented in §5.4 + §10. (A stricter design
  could also store a creation timestamp or a random nonce, but that's
  over-engineering for a same-name-same-UID collision.)
- **No GC ⇒ no early-return interaction**: the marker is only ever
  consulted (and opportunistically rewritten) inside the per-user loop,
  which is past the early-return but only reached when the user IS in
  config — exactly when we want to evaluate it. The empty-config case
  correctly does nothing. ✓ (S4-1 dissolved.)
- **markProvisioned only-on-success**: unchanged from r4; a failed
  chpasswd never arms a lock. ✓
- **Concurrency**: serialized under `applyConfigLocked`/`d.applySem`
  (AGY-confirmed) — no marker/shadow race. ✓
- **Durability**: `/var/lib/xpf` holds the configstore DB + archive →
  persistent, not tmpfs (AGY-confirmed). ✓

## Required for r5 → PLAN-READY (all folded in this rev)
1. UID-keyed marker; no GC pass; `pwLock` gates on UID match. [S4-1,S4-2]
2. §6 Path C: reject DES (consistency). [S4-3]
3. Fix the apply-ordering anchor. [S4-4]
