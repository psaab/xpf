# Claude SMR — #1917 increment B plan v2, round 2

**Verdict: PLAN-READY** (with one sharpened must-do at /engineer that the
plan already flags as OQ#2 — making it a hard requirement, not an open
question, would make this airtight; it is acceptable to ship the plan as
READY because the requirement is correctly identified and the fallback is
stated).

## Round-1 blockers — all resolved in v2

- **Respawn race** → STOP-before-FLIP + versioned ExecStart (§5A, §6.1
  steps 5-7). The ordering structurally removes any live process that
  could respawn. ✔
- **Verify isolation** → §6.1 step 4 + §8 invariant 10: throwaway
  control-socket/state-file/pin paths. ✔
- **Envelope location + rollback gate** → §6.4 embeds the envelope in
  `active.json` (old-reader-rejecting) AND mandates binary+DB atomic
  rollback with a PREFLIGHT DB snapshot. ✔ This also subsumes AGY#3.

## Confirmed: the versioned-ExecStart detail is load-bearing (sharpen OQ#2)

I verified the current packaged unit: `test/incus/xpfd.service:8`
`ExecStart=/usr/local/sbin/xpfd`, and `debian/rules:56` injects
`ExecStartPre=/usr/local/sbin/xpfd verify-dataplane`. **systemd does NOT
resolve symlinks in `ExecStart` — `argv[0]` is the literal configured
path.** So if the unit keeps `ExecStart=/usr/local/sbin/xpfd` (a symlink
to `versions/current/xpfd`), then `os.Args[0]` =
`/usr/local/sbin/xpfd`, `dir(os.Args[0])` = `/usr/local/sbin`, and
`findBinary` (`process.go:175`) resolves the FLIPPED
`/usr/local/sbin/xpf-userspace-dp`. The STOP-before-FLIP ordering still
saves correctness for the standalone cut (the daemon is down across the
flip), BUT the versioned-ExecStart "defense in depth" claimed in §5A only
holds if the unit's `ExecStart` is the CONCRETE versioned path
(`/var/lib/xpf/versions/<ver>/xpfd`), templated + `daemon-reload` per cut
— OR `/var/lib/xpf/versions/current/xpfd` ONLY IF verified that systemd's
argv[0] is the post-resolution absolute path (it is generally NOT).

**Recommendation (already OQ#2):** at /engineer, template `ExecStart` (and
`ExecStartPre verify-dataplane`) to the concrete `versions/<ver>/xpfd`
path and `daemon-reload` as part of the FLIP step. Do NOT rely on symlink
resolution for argv[0]. The plan correctly flags this; promote it from
"open question" to a §6.1 hard step. Not a blocker — the STOP-before-FLIP
ordering already guarantees correctness; this only restores the
defense-in-depth layer.

## No new contradictions introduced by v2

- Stop-before-flip in the HA path is NOT redundant with the drain: the
  drain (§6.2 steps 2-4) moves TRAFFIC to the peer; the stop (§6.1 step 5)
  is still needed so the local node's own xpfd/helper exit before the flip
  — but it is harmless because no traffic rides the drained node. Coherent.
- Controlled-promotion forward-verify (§6.2 step 7) could add a second
  transition; v2 OQ#8 honestly raises this and the default
  ("upgraded node becomes primary, then upgrade the peer") folds the
  verify into the natural failback — so the common path is one transition
  per node, not two. Acceptable.

## Endorsed

The A1+B1+C1+D1 composition, the honest multi-second standalone gap, the
M-mech-2 deferral, the disk-PREFLIGHT + `.partial`+rename, the postinst
stage-only-on-cluster contract, and the session-sync fixture mandate are
all sound. PLAN-READY pending the round-2 Codex/AGY confirmations.
