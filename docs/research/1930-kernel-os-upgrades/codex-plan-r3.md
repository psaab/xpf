# Codex — hostile plan review r3 (#1930)

Codex thread `019ed2b3-d355-74c2-b379-50c5cc37ecd3`, turn
`019ed2b3-d786-7221-83ea-a0fd54381714`. Verdict: **PLAN-NEEDS-WORK** (reviewed
v3.1).

- **NEW-F10 — STILL-OPEN (inconsistency, not the original loop):** v3.1 adds the
  right topology caveat (ESP-grubenv primary) in the body but the risks/
  acceptance/tests/recommendation still describe BootNext/per-kernel UEFI as the
  active path (`plan.md:707-712`, `:737-757`, `:776-780`); bake only writes a GRUB
  drop-in today (`bake.py:264-265`).
- **F8 — CLOSED.** do-release-upgrade UNSUPPORTED everywhere.
- **NEW-F11 — STILL-OPEN:** §3.3 corrected (text config carries) but §7 still
  said `.configdb`/`node-id`/`master.key` "carries across all lanes unchanged"
  (`plan.md:651-652`).
- **NEW-F12 — STILL-OPEN:** plan still names `deploy_rolling()` as existing
  (`plan.md:87`, `:374-384`); the script has only `deploy`/`launch`/`inventory`
  (`xpf-deploy.py:453-487`); version-check/lease/self-recovery are plan-proposed,
  not present (`rolling.go:62-82` is in-process STOP→FLIP→START).
- **NEW-F13 — MAJOR:** the one-shot substrate is internally contradictory — body
  adopted ESP-grubenv as primary while risks/invariants/acceptance/tests/
  recommendation still describe BootNext/UEFI as the live mechanism.
- **NEW-F14 — MINOR:** dpkg-query hold is correct; keep the verification
  requirement (bake has no hold yet).

**Verdict: PLAN-NEEDS-WORK** — right direction on state-carry + do-release-
upgrade, but not converged: the one-shot substrate is internally contradictory
across sections, and the deploy substrate still names a non-existent
`deploy_rolling()` as current capability.

## v4 disposition
v4 replaced the contradictory mix with a SINGLE substrate (A4: fixed A/B UEFI
slots, shim-staged, BootNext-selected, non-destructive BootOrder) threaded
through ALL sections (F13/NEW-F10-inconsistency); scrubbed `deploy_rolling()`
(F12); fixed the §7 master.key leftover (F11). NEW-F14 verification requirement
retained in INC-0/tests.
