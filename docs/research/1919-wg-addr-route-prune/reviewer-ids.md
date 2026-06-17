# Reviewer ID ledger — #1919 research

Plan doc: `docs/research/1919-wg-addr-route-prune/plan.md`
Branch: `research/1919-wg-addr-route-prune` off origin/master @ ee3f336d3

| Round | Reviewer | Task ID / artifact | Verdict |
|---|---|---|---|
| r1 | Codex | foreground `codex exec`; saved `codex-plan-r1.md` | PLAN-NEEDS-MAJOR |
| r1 | AGY | `adversarial-review-mqhsrqnx-nfetsd` (re-run after `-mqhskc68-lg4dje` MCP timeout); saved `agy-plan-r1.md` | PLAN-NEEDS-MAJOR |
| r1 | Claude SMR | `claude-smr-plan-r1.md` | PLAN-NEEDS-MAJOR |
| r2 | Codex | foreground `codex exec`; saved `codex-plan-r2.md` | PLAN-NEEDS-MAJOR (1 residual: AddrList fallback) |
| r2 | AGY | `adversarial-review-mqht5pea-afak5r`; saved `agy-plan-r2.md` | PLAN-READY |
| r3 | Codex | foreground `codex exec`; saved `codex-plan-r3.md` | PLAN-READY-WITH-NITS (stale sig nit — fixed) |
| r3 | AGY | `adversarial-review-mqhtbf4l-xx3xta`; saved `agy-plan-r3.md` | PLAN-READY |
| r3 | Claude SMR | `claude-smr-plan-r3.md` | PLAN-READY |

## Convergence

Final rev r3: all three reviewers PLAN-READY (Codex's sole nit — a stale
one-return helper signature in the §4 design note — fixed in the
committed final rev; §5 already carried the correct `(failed, retry)`
signature).

## Finding trail

- **r1 MAJOR (all 3)**: retry-on-AddrDel-failure inferred from
  `reconcileLinkAddrsLocked`'s `len(remaining)>0` is broken for
  non-link-local addresses (that fn records failed deletes only for
  fe80). → r2 added dedicated `pruneAppliedAddrsLocked`.
- **r1 MAJOR/MED (Codex + AGY)**: any `LinkByName` failure dropping
  tracking strands transient errors. → r2 gated on `isLinkNotFound`.
- **r1 MED overclaim (all 3)**: prune is not applied-only; deletes all
  non-link-local stale addrs. → r2 §4b documented precisely.
- **r2 MAJOR (Codex)**: `AddrList`-error fallback returned only
  `applied`; empty-applied + transient list failure → drop → leak. →
  r3 `(failed, retry)` signature; retain on `retry`, not `len(failed)`.
- **r3 NIT (Codex)**: stale signature in §4 design note. → fixed.
