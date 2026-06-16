# Codex — hostile plan review r6 (#1930)

Two r6 passes: a direct `codex exec` (thread `019ed2c7-f57a-72e3-83f6-...`)
returned PLAN-READY; the deeper background `codex-rescue` agent (thread
`019ed2c7-f57a-72e3-83f6-83daed5d4223`) caught two residual cross-section
contradictions at HEAD `795a3c83f` (v6.1) and returned **PLAN-NEEDS-WORK**. The
agent's two findings are authoritative (cross-section verification) and were
folded in v6.2.

**Earlier-corrections checklist — all PASS:** deploy_rolling scrubbed
(`xpf-deploy.py:453` = deploy|launch|inventory); state-carry TEXT-only
(`xpf-deploy.py:235` builds `xpf.conf`+`node-id`); do-release-upgrade UNSUPPORTED;
LANE 1 HA in-place not recreate.

**Substrate checklist:** (a) `source "$cmdpath/xpf.selector"` not string-compared
PASS; (b) `/etc/grub.d/09_xpf` survives update-grub — canonical text PASS but
INC-1 stale (Finding 1); (c) separate non-blocking `.deb` oneshot — canonical
text PASS but §10 stale (Finding 2); (d) selector is GRUB-script PASS.

**Finding 1 (blocker) — INC-1 (plan.md:687) still sized ESP for per-slot
`grub.cfg` staging** despite the A4 design dropping per-slot `grub.cfg`. → v6.2:
INC-1 now sizes ESP for `shim/grub + xpf.selector` only ("no per-slot grub.cfg,
no kernel on the ESP").

**Finding 2 (blocker) — §10 (plan.md:881) assigned NVRAM slot registration to
the day-0 service** (which is `Before=xpfd`, exits early once `.configdb` exists,
TimeoutStartSec=120 — the exact unit the v6 fix forbids). → v6.2: §10 first-boot
test now exercises the SEPARATE non-blocking `.deb` oneshot (NOT xpf-day0-config,
NOT Before=xpfd), idempotent, degrades on read-only NVRAM.

After the two fixes the plan is internally aligned around fixed A/B shim→GRUB
slots, `$cmdpath`-branched shared `grub.cfg`, `BootNext` one-shot, non-destructive
`BootOrder`. (See r6-final for the post-fix PLAN-READY.)
