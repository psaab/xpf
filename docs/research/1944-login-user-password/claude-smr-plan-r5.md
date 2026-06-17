# Claude SMR Hostile Plan Review — #1944 (r5, FINAL)

## Verdict: PLAN-READY

r5 is sound. Every finding across r1-r4 from all three reviewers is
resolved, and I independently verified the load-bearing claims against
origin/master. Convergent with Codex r5 (PLAN-READY) and AGY r5
(PLAN-READY).

### Re-verified resolutions
- **Apply mechanism**: `runCommandStdinTimeout(…, "chpasswd","-e")` —
  matches `applyRootAuth` exactly, no argv leak, timeout-bounded. ✓
- **Validator**: rejects plaintext absolutely (DES dropped), rejects
  empty-checksum modular hashes, accepts deliberate lock sentinels,
  accepts `rounds=`/yescrypt. §2/§5.5/§6/§7 self-consistent. ✓
- **Idempotency**: pure `passwordAction` with the fail-open(set) /
  fail-closed(lock) asymmetry, table-tested — a transient `/etc/shadow`
  read error can never lock out an operator. ✓
- **`isLockedShadow`**: empty = passwordless (locked by D2), not
  already-locked. ✓
- **Direct `/etc/shadow` read** (no NSS staleness). ✓
- **Provenance (UID-keyed marker)**: the r5 keystone. Resolves the
  name-only marker's unwinnable keep-vs-GC dilemma AND eliminates the GC
  pass (so the empty-login early-return cannot strand anything). I
  traced all four cases (set-then-remove, leave-rejoin, userdel-recreate,
  empty-config) — correct. The same-name-same-UID edge case is the only
  residual and is acceptable + documented + reversible. ✓
- **Scope discipline**: never root; out-of-band accounts untouched;
  no deprovisioning (`userdel`) taken on. ✓
- **E1 root parity** + fixture updates; closes root's plaintext footgun
  and unblocks `root-authentication encrypted-password "*"`. ✓
- **Docs**: concrete `docs/system-login.md` target with a
  hash-generation example, D2/UID semantics, #1916 note. ✓
- **Anchors**: corrected to origin/master.

### Why this is a good place to stop
The blast radius is small and well-contained (control-plane OS-account
state, no wire/HA/dataplane impact), the safety invariants are pure and
testable, and the three hardest design questions — directive-removal
reconciliation, validator footgun, and provenance — were each driven to
a defensible answer through four rounds of adversarial pressure with
independent convergence on the key defects.

### Recommendation
Ship **all decided paths**: A1 (chpasswd -e), B1 (skip-if-unchanged,
direct read, fail-open), C1 (permissive recognizer, DES dropped), D2
(UID-keyed lock-on-removal), E1 (shared validator). This is the option
set the plan converged on; no remaining either/or for the implementer
beyond the §9 open questions, which are confirmations rather than forks.
