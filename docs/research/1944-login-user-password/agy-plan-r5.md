I will view the content of `docs/research/1944-login-user-password/plan.md` using the `view_file` tool to inspect the plan document for Issue #1944 (Revision r5).
# Verdict: `PLAN-READY`

I have reviewed Revision r5 of the design plan in [docs/research/1944-login-user-password/plan.md](file:///home/ps/git/bpfrx/docs/research/1944-login-user-password/plan.md) for issue #1944. All conditions are successfully met, and the design is fully coherent and ready for implementation.

---

### Verification and Findings

#### (a) Leave-rejoin same account → UID match → lock (no orphan)
* **Status**: **Verified**
* **Quoted Evidence**:
  > `277:     - Leave-then-rejoin same account: UID unchanged → pwLock fires ��`
  > `278:       old password revoked (D2 honored).`
* **Analysis**: Because the marker `/var/lib/xpf/provisioned-users/<name>` holds the account UID, when the user is temporarily removed and then re-added to the configuration under the same account, the current OS UID matches the recorded UID. This causes `xpfProvisioned(name, curUID)` to evaluate to `true` (lines 266-267) and trigger `pwLock` (lines 235-236), successfully locking the password to prevent an orphan credential.

#### (b) Userdel + recreate different UID → mismatch → skip
* **Status**: **Verified**
* **Quoted Evidence**:
  > `279:     - userdel + out-of-band recreate: new account gets a different UID`
  > `280:       (or the operator chose a fixed UID — see edge case) → UID mismatch`
  > `281:       → pwLock skips → out-of-band account untouched.`
* **Analysis**: If the user account is deleted and recreated out-of-band, the new account gets a different UID. Consequently, the UID read from the marker file mismatch against the new UID. `xpfProvisioned` returns `false` (line 270), and the lock operation is safely skipped, ensuring that independent/external user accounts are not locked by `xpf`.

#### (c) Empty-login → no GC to bypass
* **Status**: **Verified**
* **Quoted Evidence**:
  > `276:     and GC-at-top collides with the empty-login early-return (Codex/AGY-r4`
  > `277:     GC-bypass). The UID disambiguates all three without any GC:`
  > `282:     - Empty-login early-return: irrelevant — no GC pass to bypass; the`
  > `283:       marker simply persists and is re-validated by UID on the next apply`
  > `284:       that includes the user.`
* **Analysis**: Replacing the name-based GC model with a stateless UID-keyed marker verification dissolves the need for an active GC pass in the user apply loop. Because there is no GC run, the early-return of an empty login configuration in `applySystemLogin` (lines 22-23) cannot bypass any clean-up logic.

#### (d) Same-name-same-UID edge case documented + acceptable
* **Status**: **Verified**
* **Quoted Evidence**:
  > `285:   - Edge case (documented): if an out-of-band recreate happens to`
  > `286:     reuse the exact same UID xpf recorded, the marker would match and`
  > `287:     pwLock would fire. This is acceptable and arguably correct — same`
  > `288:     name + same UID is indistinguishable from the original xpf-managed`
  > `289:     account; the operator can re-add encrypted-password to restore it.`
  > `290:     Note in docs.`
  > ...
  > `568:   - D2 reconciliation: ... The lock applies only to xpf-managed accounts`
  > `569:     (UID-keyed marker); an account userdel'd + recreated out-of-band`
  > `570:     with a new UID is left alone. Edge case: if the recreate reuses`
  > `571:     the same name + same UID, xpf treats it as the original managed`
  > `572:     account and may lock it — re-add encrypted-password to restore.`
* **Analysis**: The edge case where an out-of-band recreate reuses the same name and exact same UID is documented in both the design section and the documentation updates section, and is accepted as correct behaviour.

#### (e) §6 Path C no longer contradicts the DES drop
* **Status**: **Verified**
* **Quoted Evidence**:
  > `397:   (the real footgun) and legacy DES (dropped in r4 so the`
  > `398:   plaintext-rejection is absolute — §5.5, r3 Major-2).`
* **Analysis**: The multiple path option for validation strictness (§6 Path C) correctly references the drop of legacy DES (previously defined in lines 325-328), removing any previous contradiction.

#### (f) §2/§5.5/§6/§7 self-consistent
* **Status**: **Verified**
* **Analysis**: The specifications for the `ValidateCryptHash` validator (Section 5.5, lines 302-348), the path choices (Section 6, lines 380-420), goals (Section 2, lines 55-96), and testing cases (Section 7, lines 423-481) are fully aligned. The test cases assert all validator outputs, including explicit bare lock sentinels (`*`/`!`/`!!`) and the rejection of 13-character plain text passwords. The decision flows for [passwordAction](file:///home/ps/git/bpfrx/pkg/daemon/daemon_system.go) align with the documented behavior of `isLockedShadow`.

---

### File Links

- [docs/research/1944-login-user-password/plan.md](file:///home/ps/git/bpfrx/docs/research/1944-login-user-password/plan.md)
- [pkg/daemon/daemon_system.go](file:///home/ps/git/bpfrx/pkg/daemon/daemon_system.go)
- [pkg/config/types_system.go](file:///home/ps/git/bpfrx/pkg/config/types_system.go)
- [pkg/config/compiler_system.go](file:///home/ps/git/bpfrx/pkg/config/compiler_system.go)
- [pkg/config/schema_system.go](file:///home/ps/git/bpfrx/pkg/config/schema_system.go)
- [pkg/config/schema_validators.go](file:///home/ps/git/bpfrx/pkg/config/schema_validators.go)
- [pkg/config/value_type.go](file:///home/ps/git/bpfrx/pkg/config/value_type.go)
- [pkg/config/parser_system_test.go](file:///home/ps/git/bpfrx/pkg/config/parser_system_test.go)

---

### Summary of Work

I have inspected the updated plan document [plan.md](file:///home/ps/git/bpfrx/docs/research/1944-login-user-password/plan.md) and verified that all five issues raised during previous rounds, as well as the inconsistency/correctness metrics (a) through (f), are addressed correctly and cleanly under Revision r5. I have returned the requested exact verdict of `PLAN-READY`.
