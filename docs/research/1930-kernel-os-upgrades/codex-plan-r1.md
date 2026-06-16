# Codex — hostile plan review r1 (#1930)

Codex thread `019ed2a0-1cf1-77e2-a747-80da4d484d0a`, turn
`019ed2a0-2149-7be3-ad00-60df305a42b5` (model gpt-5.5, xhigh). Verdict:
**PLAN-NEEDS-WORK**.

**Finding 1 [INFO] — Core factual grounding checks out.** `bake.py:70/264`
GRUB_DROPIN is `init_on_alloc=0` only; no `apt-mark`/`GRUB_DEFAULT`/
`GRUB_SAVEDEFAULT`. `verify_userspace_shim.go:113` `ebpf.NewCollection` =
running-kernel verdict. `docs/in-place-upgrade.md:169` hands kernel/OS to #1930.

**Finding 2 [FATAL] — GRUB old-default preservation not specified.** `GRUB_DEFAULT
=saved` with no durable `saved_entry` pinned to the old kernel → a watchdog reset
after a failed candidate can fall back to GRUB's first/newest entry (the failed
candidate) = boot loop. Fix: pin + verify old kernel as saved_entry before
one-shot; prove grubenv contents.

**Finding 3 [FATAL] — Watchdog "brick-proof" under-specified.** Many watchdog
paths disarm on clean shutdown / `/dev/watchdog` close unless `nowayout`. If not
armed across shutdown→firmware→GRUB→early candidate boot, the early-hang revert
guarantee is false. Fix: specify devices, nowayout/shutdown semantics, deadline
budget, live test.

**Finding 4 [FATAL] — Existing rolling driver cannot survive the reboot it
sequences.** `RunRolling` (rolling.go:62) is local-node, calls the cut inline
(:152) then waits sync/reset-failover (:165/:178). A reboot kills the local
process before post-reboot rejoin/failback/repeat. Fix: external coordinator or
boot-resumable agent + cluster locking so two nodes can't start kernel lanes
concurrently.

**Finding 5 [MAJOR] — GRUB candidate selection underspecified.** No mapping of
`<candidate>` to a stable menuentry/submenu id, no `recordfail`/grubenv-write
verification. Fix: resolve ids from generated grub.cfg, verify next_entry,
handle recordfail.

**Finding 6 [MAJOR] — Kernel install preflight misses /boot, initramfs, dpkg side
effects.** cutover.go:254 only checks versions-dir space. Full /boot, failed
update-initramfs, or postinst failure can half-install before revert logic runs.
Fix: /boot/ESP capacity checks, initramfs/grub validation, package-state
rollback, prune before install.

**Finding 7 [MAJOR] — Image-replace HA session survival overclaimed.** Existing
guard (rolling.go:109, in-place-upgrade.md:147/153) only checks running
local/peer protocol after a mixed cluster exists. Fix: staged/new-image HA
protocol introspection + mixed-base validation before claiming survival.

**Finding 8 [MAJOR] — do-release-upgrade fallback not coherent.** Holding all
linux-* blocks the upgrade / leaves old kernel under new userspace; intercepting
the final reboot is not bounded. Fix: drop B2 / mark unsupported.

**Finding 9 [MINOR] — Command name inconsistency.** `xpf-upgrade kernel` vs
`xpfd upgrade kernel`; real surface is `xpfd upgrade` (cmd/xpfd/upgrade.go:12).

**PLAN-NEEDS-WORK** — verifier invariant + 3-lane split plausible, but LANE 1's
safety proof has holes in GRUB saved-default handling, watchdog persistence, and
HA orchestration across reboot. Bricking/outage scenarios, not wording. Fix those
invariants (or drop LANE 1 until validated) before implementation.
