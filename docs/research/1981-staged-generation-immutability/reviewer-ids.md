# Reviewer task IDs / verdict ledger — #1981

Research mode (3-way): Codex + AGY + Claude SMR. Copilot does NOT review at
research time (it reviews code PRs only — joins at `/engineer`).

| Round | Reviewer | Task ID / artifact | Verdict |
|---|---|---|---|
| r1 | Codex | companion thread `019edce6-e15c-7a90-adee-9e9b94bc09a8`; `codex-plan-r1.md` | PLAN-NEEDS-MAJOR |
| r1 | AGY | `adversarial-review-mqk34a34-sgfmxd`; `agy-plan-r1.md` | PLAN-NEEDS-MAJOR |
| r1 | Claude SMR | `claude-smr-plan-r1.md` | PLAN-NEEDS-MAJOR |
| r2 | Codex | thread `019edced-1fe1-7921-b4bd-57acc1466775`; `codex-plan-r2.md` | PLAN-NEEDS-MAJOR (mechanism B ratified, spec tighten) |
| r2 | AGY | `adversarial-review-mqk3esm6-knh8qs`; `agy-plan-r2.md` | PLAN-NEEDS-MAJOR (mechanism B accepted, spec tighten) |
| r2 | Claude SMR | `claude-smr-plan-r2.md` | PLAN-READY w/ 2 MINORs (folded into r3) |
| r3 | Codex | `codex-plan-r3.md` | (pending) |
| r3 | AGY | `agy-plan-r3.md` | (pending) |
| r3 | Claude SMR | `claude-smr-plan-r3.md` | (pending) |

## r1 convergent themes (all three)
- **P1 ordering / abort-upgrade wedge** (SMR-MAJOR1, Codex#1+#2, AGY#1-CRIT):
  writing `"unpacking"` before the lock gate false-refuses a contended cut; and
  dpkg error-unwind (`new-postrm abort-upgrade` → `old-postinst abort-upgrade`)
  strands `"unpacking"` because the OLD package's abort path never rewrites a
  valid manifest. Permanent-wedge class.
- **Option D keeps fighting the maintainer-script lifecycle; Option B avoids the
  whole class** (Codex#6, AGY#4, SMR-MINOR2): all three independently argue B's
  rejection is not earned. B reads from a published immutable generation, never
  from live `staged/`, so it has no preinst sentinel, no abort-* handling, no
  permanent-wedge window.
- **Post-PREFLIGHT refusal regresses #1967** (Codex#3): a `copyStaged` refusal
  leaves a stale `.dbsnap` + journal at StatePreflight.
- **seed must write the manifest incl. the seed-failure fallback** (Codex#4,
  AGY#3, SMR-MAJOR2.2).
- **`.generation` copied into `versions/<ver>` by copyTree?** unspecified
  (Codex#5).
- **first-install / `preinst install` window** (AGY#2).

→ r2 FLIPS the recommendation to **Option B** per the unanimous convergence.
