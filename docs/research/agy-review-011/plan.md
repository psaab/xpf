# AGY review-011 — plan of action (Part I hardening + Part II refactor assessment)

**Status:** DRAFT v1 — pending adversarial plan review (Codex + AGY + Claude SMR)
**Base:** `3cd181323` (origin/master)
**Outcome shape:** Part I → one LOW defensive-hardening issue (both findings are
**latent**, not live bugs); Part II → **KILL/DEFER all 5** (all under the
project's 2000-prod-LOC modularity threshold). `/research` only — no code.

## 1. Issue framing

AGY review-011 (`/tmp/agy-review-011.md`) has two parts: **Part I** = 2 claimed
systems bugs in `pkg/upgrade`; **Part II** = 5 de-monolization refactor
proposals. Paths referenced a `gemini-xpf` checkout; all mapped + verified
against `3cd181323`.

## 2. Honest scope/value framing

- **Both Part I findings are LATENT — neither triggers on the current tree.**
  AGY framed them as active systems bugs; verification shows they cannot fire
  today. They are cheap defensive-hardening items, LOW priority.
- **All 5 Part II targets are under the 2000-prod-LOC modularity threshold**
  (docs/engineering-style.md). Two are already file-decomposed. The project has
  PLAN-KILLED 5 comparable refactors (#1207, #1165, #1545, #1519, #1317) for
  cosmetic churn / hot-path restructuring risk. *PLAN-KILL is the expected and
  appropriate verdict for Part II.*

## 3. What's already shipped / adjacent

- **#1916** (closed) covered the fsatomic canary for pkg/daemon+pkg/api + TLS
  cert/key atomicity — **unrelated** to AGY-I-1 (copyTree dir-fsync). Not a dup.
- `pkg/upgrade/kernel_*.go` is **already split 6 ways** (kernel.go 334,
  kernel_linux.go 665, kernel_run.go 555, kernel_drain.go 134,
  kernel_selfrecover.go 249) — AGY Part-II-3's "~1937 LOC" is a SUM of these
  already-separate files.
- `pkg/configstore/{envelope.go 262, crypto.go 252, check.go 36}` are **already
  3 separate files** — AGY Part-II-4 proposes moving them into a `secure/`
  subdir (cosmetic).

## 4. Part I design (LOW defensive hardening)

### AGY-I-1 — copyTree nested-directory fsync (LATENT)
`copyTree` (runner.go:241) `os.MkdirAll`s nested dirs and fsyncs **files**
(copyFileFsync), but never fsyncs the **nested parent directories**; only the
caller's top-level `SyncDir(partial)`/`SyncDir(snapPartial)` runs (cutover.go
~285). **Cannot trigger today:** `.configdb/` is flat (active.json,
candidate.json, rollback.N.json — verified pkg/configstore/db.go:56-68; the
journal is a sibling `.config.journal`, not nested), and the staged→versions
copy is flat binaries — so the single top-level SyncDir covers every entry. It
becomes a real power-loss corruption hazard only if `.configdb/` (or staged)
ever gains a subdir. **Fix (cheap, future-proofing):** in `copyTree`, collect
the set of `dirname(target)` created during the walk and fsync each, top-down,
before returning (apply identically to the staged copy). Add a test with a
nested source tree asserting every intermediate dir is fsynced.

### AGY-I-2 — parseSyncEstablished scoped parse (LATENT)
`parseSyncEstablished` (cluster_cli.go:177) returns on the **first** line
starting with `status:` across the whole `show chassis cluster information`
text. It gates draining (`DrainComplete` cluster_cli.go:119; kernel_drain.go:124;
rolling.go:101/168) — a wrong parse would drain a node whose sync link is Down.
**Not broken today:** `FormatInformation()` emits `Status:` exactly once
(pkg/cluster/status.go:248, the sync-link section); `FormatIPMonitoringStatus`
(status.go:496, "Status: unreachable") is a **separate** function not folded
into `FormatInformation`. The hazard is the unenforced assumption — a future
merge of IP-monitoring (or any pre-sync section with `Status:`) into
`FormatInformation` would silently mis-gate drains. **Fix (defensive):** scope
the match to the `Sync link statistics:` / `Fabric link statistics:` section
(find the header, scan until the next blank/header); add a test asserting
`FormatInformation` emits exactly one `Status:` and that it is the sync link.

### Disposition
File **one** issue: *"Upgrade durability + drain-gate parser: latent
defensive hardening (AGY review-011 Part I)"*, LOW. Both fixes are small,
isolated, and test-backed. Honest framing in the issue: neither triggers today;
this hardens against future schema/format drift.

## 5. Part II assessment — KILL/DEFER (none meet the threshold)

| # | Target | Largest prod LOC | >2000? | Already split? | Hot path | Verdict | Why |
|---|---|---|---|---|---|---|---|
| 1 | `wg_control.rs` | 1411 | no | no | **yes** | **DEFER** | Under threshold; cohesive single control loop; splitting risks per-poll indirection (the #1207 hot-path precedent). No testability gap at this size. |
| 2 | `routing/tunnel.go` | 1748 | no | no | no | **DEFER** | Under threshold (closest); three apply-phases already helper-factored; operator-paced, not per-packet. Revisit only if it crosses 2000. |
| 3 | `kernel_*.go` | 665 | no | **yes (6 files)** | no | **KILL** | Already decomposed; the "~1937" is a sum of existing files. Proposal is stale namespace churn on the freshly-shipped #1930 subsystem. |
| 4 | `configstore/secure/` | 262 | no | **yes (3 files)** | no | **KILL** | Already 3 files <300 LOC each. Cosmetic subdir move. |
| 5 | `tunnel_supervision.rs` | 863 | no | no | per-apply | **DEFER** | Under threshold; cohesive three-pass reconcile; intentional GRE/WG parallel structure. |

**The one real modularity finding AGY missed:** `pkg/configstore/store.go` is
**2,011 prod LOC — the only file at/over the 2000 threshold** in this vicinity
(AGY targeted the already-tiny `secure/` files instead). It is borderline (just
over) and the scheduled fortnightly modularity audit will flag it; if any
decomposition is pursued, store.go is the legitimate target, not AGY's. Noted
here, not filed (marginal; let the audit drive it).

## 6. Recommendation

- **Part I:** file the single LOW hardening issue #1968 (§4). PLAN-READY direction —
  small, isolated, test-backed.
- **Part II:** **PLAN-KILL all 5 as proposed.** None meet the threshold; #3/#4
  are already decomposed; #1/#5 are hot-path/cohesive. Do not file refactor
  issues (filing them would invite churn the project's own discipline rejects).
  If a reviewer insists on a future target, it is store.go @ 2011, via the
  audit.

## 7. Public API / contract preservation
No API changes. Part I fixes are internal (copyTree fsync set; parser scoping).

## 8. Hidden invariants the change must preserve
- copyTree's checksum + atomic-rename + existing top-level SyncDir behavior is
  unchanged; the new dir-fsyncs are additive.
- `parseSyncEstablished` must remain conservative (return false / not-synced on
  ambiguous/missing section) so it never *over*-reports "synced" and green-lights
  a drain it shouldn't.

## 9. Risk assessment
| Class | Level | Note |
|---|---|---|
| Behavioral regression | LOW | additive fsyncs; parser scoping with conservative fallback |
| Lifetime/borrow | LOW | Go |
| Performance | NONE | upgrade/cluster-control path, not packet path |
| Architectural mismatch | LOW | Part II KILL avoids it entirely |

## 10. Out of scope
- Any Part II decomposition (KILL/DEFER).
- store.go @ 2011 decomposition (defer to the scheduled modularity audit).
- The Codex review-011 upgrade items (#1964/#1965/#1966/#1967) — separate.

## 11. Open questions for adversarial review
1. Are both Part I findings correctly LATENT, or is there a path (now) where
   `.configdb` is nested / `FormatInformation` emits multiple `Status:` that I
   missed? (verify pkg/configstore + pkg/cluster/status.go)
2. Is filing Part I as a single LOW issue right, or should AGY-I-2 (drain-gate)
   be its own MEDIUM given the failure mode (wrong drain) is worse than AGY-I-1?
3. Does any Part II target deserve PLAN despite being under threshold — a real
   testability/correctness win the assessment undervalued?
4. Is store.go @ 2011 worth a decomposition issue now, or correctly left to the
   audit?
