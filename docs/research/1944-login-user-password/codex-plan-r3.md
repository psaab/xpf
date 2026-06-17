# Codex Hostile Plan Re-Review — #1944 (r3)

Codex task id: `019ed492-c170-72a0-a794-229b20731d8e`

## Verdict: PLAN-NEEDS-WORK

r2 findings: New-Fatal-1 RESOLVED (isLockedShadow empty no longer locked); New-Fatal-2 PARTIALLY (pwApply has no marker req → Major-1); M-4 RESOLVED (passwordAction table test); stale anchors RESOLVED for the 4 r2 anchors.

### Major-1 — pwApply-without-marker orphans xpf-applied passwords on removal
extuser pre-exists (no marker). Operator adds encrypted-password → pwApply writes it (no marker required). Operator later removes directive → passwordAction returns pwLock → `if !xpfProvisioned { break }` skips (still no marker) → the live password xpf applied is NEVER revoked. Also hits marker-wiped pre-r3 accounts. Fix: drop a password-managed marker on every pwApply; gate pwLock on either marker.

### Major-2 — 13-char alnum plaintext passes as legacy DES hash
`encrypted-password "password12345"` (13 alnum) passes the DES regex; chpasswd -e writes garbage; console login fails though commit reported success. Plaintext-rejection not absolute. Fix: drop legacy DES support (no Junos operator uses it) or document the accepted risk + test.

### Major-3 — modular hash with empty checksum accepted
`$6$salt$` has a non-empty body + a `$` after id but no checksum → regex accepts → chpasswd writes a malformed field PAM rejects → de-facto lock. Fix: require a non-empty checksum after the final `$`; negative tests for `$6$salt$`, `$6$$hash`.

### Minor-1 — success criterion 3 contradicts §5.5 (says reject bare sentinels; §5.5 accepts them). Reword.
### Minor-2 — "no auth method" warning won't fire for `encrypted-password "*"` + no keys. Define condition as no-usable-auth.
### Nit-1 — stale anchors: schema_walk.go dispatch @236 (not 40/89/298/331); isTypedLeaf schema.go @97; compiler_system root-auth @131 (not 130).

### Verdict rationale
passwordAction fail-open(set)/fail-closed(lock) asymmetry is sound. Three blockers: provenance pwApply orphan; DES plaintext acceptance; empty-checksum modular hash.
