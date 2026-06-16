# Codex — hostile plan review r4 (#1930)

Codex thread `019ed2bc-ca6c-7e30-88a0-abed56e2f243`, turn
`019ed2bc-ce97-79b2-bbc5-f47771929501`. Reviewed v4 (before the v5 `$cmdpath`
fold). Verdict: **PLAN-NEEDS-WORK**.

Ground-truth confirmations: `xpf-deploy.py` has only `deploy`/`launch`/
`inventory` (no `deploy_rolling`); `pkg/upgrade` `RunRolling` is binary-cut HA
only (no UEFI/A-B); `bake.py` builds one offline image + `update-grub`, no A/B
today; `docs/install-images.md` still has stale `deploy_rolling()` text.

- **F11 (state-carry) — FIXED.** §7 per-lane TEXT-vs-DB correct.
- **F12 (`deploy_rolling()`) — FIXED** in the plan (only negation contexts).
- **F14 (forward-beacon gating) — RETAINED.**
- **F13 (substrate consistency) — STILL-BROKEN at v4:** v4 carried BOTH a
  `$cmdpath`-selector design AND stale "static per-slot `grub.cfg`" framing +
  pre-A4 per-candidate mechanics.

New findings (folded into v5/v5.1):
- **NEW-F15 (HIGH):** two competing substrates coexist (`$cmdpath` vs static
  per-slot grub.cfg). → v5 committed fully to `$cmdpath`; v5.1 scrubbed residue.
- **NEW-F16 (HIGH):** stale per-candidate `--bootnext <candidate-entry>` /
  `grub-set-default` / "removes the candidate UEFI entry" in §3.1. → v5.1
  replaced with A/B fixed-slot `efibootmgr --bootorder` + selector-reset.
- **NEW-F17 (HIGH):** §11 wrongly said LANE 1 HA uses recreate-via-`launch`
  (that's LANE 2). → v5.1 fixed: LANE 1 HA drives `xpfd upgrade kernel` in place.
- **NEW-F18 (MED):** slot-detection underspecified. → v5.1 added `BootCurrent` +
  `uname -r` double-check before promote.
- **NEW-F19 (MED):** BootNext power-loss durability. → v5.1 added (NVRAM-durable,
  single-shot, BootOrder fallback).
- **NEW-F20 (MED):** `docs/install-images.md` stale `deploy_rolling()`. → v5.1
  added to INC-3's doc-fix list.

A4 audit: Secure-Boot chain, fixed-slot/no-NVRAM-wear, ESP capacity, bake
bootstrap, both-slots-bad recovery all addressed; the gaps were the v4 stale-text
inconsistencies now resolved.
