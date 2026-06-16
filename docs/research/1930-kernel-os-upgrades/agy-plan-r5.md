# AGY — adversarial plan review r5 (#1930)

Verdict: **PLAN-NEEDS-WORK**. v5 resolves all r4 UEFI flaws (F1 per-slot grub.cfg
dropped → `$cmdpath`; F2 NVRAM→first-boot; F3 kernels in /boot; F4 shared-/boot
SPOF documented). Four NEW implementation-detail flaws:

### Flaw (a) — `$cmdpath` includes the device prefix; no string-compare; regexp may be unavailable
GRUB populates `$cmdpath` as `(hd0,gpt1)/EFI/xpf-A` — a naive `[ "$cmdpath" =
"/EFI/xpf-A" ]` fails (device portion varies by drive enumeration). Under Secure
Boot lockdown `regexp` may not be loadable to strip the prefix. Fix: NEVER
string-compare; use `$cmdpath` directly as a path — `source
"$cmdpath/xpf.selector"` expands natively to the right slot dir.

### Flaw (b) — `$cmdpath` branch must be a `/etc/grub.d/` drop-in (update-grub clobbers grub.cfg)
A direct edit of `/boot/grub/grub.cfg` is overwritten by every `update-grub`. Fix:
ship the branching as `/etc/grub.d/09_xpf` (executable drop-in), emitted at the
top of the regenerated grub.cfg.

### Flaw (c) — first-boot registration via xpf-day0-config is bypassed / image-only / boot-blocking
(1) `xpf-day0-config` exits early once `/etc/xpf/.configdb` exists → on a
SAFE-BOOTSTRAP node (no day-0 media) the A/B slots are NEVER registered → broken
LANE 1. (2) The script is an image-only helper (copied in bake), NOT in the xpfd
.deb → manual/foreign-host installs lack it. (3) It is `Before=xpfd.service`, so a
hanging `efibootmgr` blocks xpfd → blocks the SAFE-BOOTSTRAP lifeline = brick.
(4) Read-only/no-EFI-vars platforms (some cloud) would crash if errors are fatal.
Fix: DECOUPLE slot registration into an independent NON-BLOCKING oneshot
(packaged in the .deb), `timeout 5 efibootmgr ...`, non-fatal (log + disable LANE
1 + boot in degraded mode), idempotent/self-healing.

### Flaw (d) — selector file format/read-path underspecified
Fix: the selector is a GRUB-script file (`set xpf_slot_kernel="vmlinuz-…"; set
xpf_slot_initrd="initrd.img-…"`) loaded via GRUB's native `source` (parseable
under lockdown — a raw text file is not).
