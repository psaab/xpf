# Codex — hostile plan review r2 (#1930)

Codex thread `019ed2a8-d3cb-7b60-b9a9-457408861823`, turn
`019ed2a8-d808-7cc3-bc31-b60516d41b31`. Verdict: **PLAN-NEEDS-WORK**.

## r1 finding dispositions
- **F2 — NOT-FIXED.** v2's `next_entry`+Linux-clear still loops if the candidate
  panics before the Linux/initramfs clear runs; watchdog reset re-reads the
  still-set marker → re-enters candidate. Same as NEW-F10.
- **F3 — PARTIALLY-FIXED.** Persistent-watchdog requirement correct, but the
  initramfs early-arm is unverified (no concrete hook; bake installs no watchdog
  config today) and cannot protect a hang before initramfs.
- **F4 — PARTIALLY-FIXED.** Correctly stops using in-process rolling.go for the
  reboot cut, but `xpf-deploy.py` does not yet do kernel-rolling / rejoin-confirm
  / cluster lock — design direction fixed, not existing capability (INC-2).
- **F5 — FIXED.** Stable menuentry id from regenerated grub.cfg; numeric/title
  rejected.
- **F6 — FIXED.** /boot capacity gate, prune-before-install, GC purge.
- **F7 — FIXED.** Unconditional session-survival claim removed; pre-swap
  mixed-base gate fail-closed.
- **F8 — PARTIALLY-FIXED.** §3.3 drops do-release-upgrade but the §3 lane
  summary still calls it a "documented, gated, non-HA fallback" — contradiction
  that can reintroduce the half-upgraded brick.
- **F9 — FIXED.** `xpfd upgrade kernel`.

## New findings
- **NEW-F10 — FATAL.** A1' still boot-loops if the candidate dies before the
  Linux clear (the clear relies on a boot that never reaches Linux). The r1
  fatal was never closed. [= SMR B4 / AGY Hazard A]
- **NEW-F11 — MAJOR.** LANE 3 state-carry contract contradicts existing docs:
  `docs/install-images.md:188-190` + `deploy-quickstart.md:125-128` say the
  portable artifact is `xpf.conf`+`node-id`, NOT `.configdb`; `xpf-deploy.py`
  only builds a day-0 ISO with `xpf.conf`+optional `node-id`. A reimaged node
  factory-boots from text; a carried encrypted `.configdb` can't decrypt under a
  new `master.key`.
- **NEW-F12 — MAJOR.** `xpf-deploy.py` is deploy/launch/inventory only
  (`:453-487`); it cannot perform an in-place base-OS swap or rejoin gate. The
  LANE 2/3 playbook leans on a driver capability that does not exist.

## Verdict
**PLAN-NEEDS-WORK** — F5/F6/F7/F9 fixed cleanly; F3/F4/F8 progressed; three
blockers remain: (1) the marker still fails the pre-Linux crash sequence
(F2/NEW-F10), (2) do-release-upgrade internally contradictory, (3) image-replace
relies on state-carry + swap orchestration the referenced script/docs do not
provide. All verifiable against the tree, not editorial.
