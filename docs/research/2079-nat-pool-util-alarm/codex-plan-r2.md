# Codex hostile plan review r2 — #2079

## Note: 1st r2 agent (ab90b37ade3bef368) infra-dropped (empty). The retry
## (fresh session, agent a5710146c20086d4d) COMPLETED — slow ~4.5 min, not dropped.

## Verdict (retry): PLAN-REVISE

Codex confirmed all 6 r2 folds and raised 3 NEW pseudocode-quality MAJORs + a
re-flagged MAJOR (FOLD-5). All folded into r3.

### Confirmed folds (CONFIRMED-OK)
- FOLD-1 dedup-by-pool-name (shared Arc) — vs source.rs:281-290,
  allocator.rs:153-154, status.rs:9-25.
- FOLD-2 `Manager.LastStatus()` cached accessor vs `Status()` socket I/O
  (manager.go:1840-1852; cache refresh process.go:393-410, store
  manager.go:1085-1094).
- FOLD-3 both render sites (server_show_security_text.go:304-361 +
  cli_show_security.go:1788-1845; dispatch cli_show_security_dispatch.go:331-332).
- FOLD-4 hard commit validation 0<clear<raise<=100, bare-stanza rejected
  (compiler_nat.go:334-369; types_security.go:251-255).
- FOLD-6 deterministic skip with comma-ok cfg lookup
  (types_security.go:233-241,328-337; compiler_nat.go:325-331).

### NEW findings (folded into r3)
- **FOLD-5 (MAJOR):** capacity pseudocode did the uint16 subtraction/addition
  BEFORE the uint64 cast (`uint64(s.PortHigh - s.PortLow + 1)`); cast operands
  first. r3: `uint64(s.PortHigh)-uint64(s.PortLow)+1`.
- **NEW-1 (MAJOR):** clear comparator inconsistent — §6.2 text said "drops below"
  but pseudocode used `pct <= ClearThreshold`. Expected: raise `>=`, clear strict
  `<`. r3: pseudocode + text use strict `<`.
- **NEW-2 (MAJOR):** prune only cleared pools absent from `byPool`; an alarm
  sticks if the pool stays in the cached snapshot but is removed from config or
  changed to deterministic (it is `continue`-skipped, never pruned). r3: prune
  reconciles against an `eligible` set (in-config AND non-deterministic).
- **NEW-3 (MAJOR):** monitor dereferenced `cfg.Security...` unguarded;
  `ActiveConfig()` can return nil (store.go:1572-1577, fail-closed nil documented
  store.go:243-244, daemon/README.md:75-84). r3: nil-guard cfg first.

"Overall: r2 correctly folded the shared-allocator dedup, cached-status accessor,
both render sites, commit validation, and deterministic skip intent. It still
needs revision before implementation because the plan's pseudocode can leave
stale alarms, has ambiguous/wrong clear semantics, and fails the promised uint64
capacity arithmetic." — all folded into r3.
