# Claude-SMR hostile self-review — plan.md r1 (#1987 DHCP consolidation)

Reviewer: Claude (SMR persona, hostile). Companion-free round. Goal: try to
break the plan's two load-bearing claims — (1) "no cycle" and (2) "`common/`
is a kill / no shared code" — and surface any factual error, omission, or
over/under-claim. Verdict at the end.

## Methodology

Re-derived every quantitative claim from `origin/master` @ `3fa0af3b5` rather
than trusting the plan's tables. Attacked the cycle claim from the back-edge
direction (does a leaf import back into the three?), attacked the `common/`
kill by hunting for ANY shared symbol, and attacked the blast-radius numbers
for undercounting.

## Findings

### F1 — [RESOLVED in r1] "alias requirement" was a factual overstatement
**Original text** claimed `goimports` "will want an explicit alias … That alias
requirement is the same on every importer." Go does **not** require an import
alias when the directory tail differs from the package name; the bare
`import ".../services/dhcp/client"` compiles and the identifier is `dhcp`. An
alias is a *readability option*, not a requirement. Left uncorrected, a reader
might think Strategy A forces 19 alias edits as a hard constraint.
**Disposition:** FIXED in §4b, §6, §8 — now states the alias is optional and
the bare import works. Severity was Low (cosmetic), but it's the kind of
imprecision a hostile companion would flag, so corrected pre-publish.

### F2 — [HOLDS] "No cycle" — attacked from the back-edge, survives
The kill precedent (#2002/#2004) was a *parent↔child* and a *leaf↔shared-family*
cycle. I attacked #1987's claim by checking whether the leaves the three import
(`pkg/config`, `pkg/fsatomic`) import *back* into any DHCP package:
```
grep -rn "pkg/dhcp\|pkg/dhcpserver\|pkg/dhcprelay" pkg/config pkg/fsatomic --include=*.go
```
Only hit: `pkg/config/types.go:235` — a **comment** ("the lease-lookup key that
pkg/dhcp.Manager …"), not an import. No back-edge. The dependency subgraph is a
forest. Re-homing leaves with zero inter-group edges into a sibling parent
directory cannot create an edge. **Claim holds.** The plan correctly identifies
the structural difference from #2002/#2004 (those moved *coupled* code; this
moves *already-decoupled* packages).

Residual attack: could the eventual PR *accidentally* create a parent `dhcp.go`
that re-exports the three and couples them? Yes — and the plan pre-empts this in
§3c ("directory only, no parent package") and §8 (risk row). Good.

### F3 — [HOLDS] "`common/` has nothing to extract" — attacked hard, survives
This is the most consequential claim (it downgrades the issue's headline from a
4-subpackage consolidation to a 3-sibling regroup). I tried to falsify it:

- **Two `Lease` types:** confirmed genuinely different domains — `dhcp.Lease` is
  `netip.Prefix`/gateway/DNS/duration (client), `dhcpserver.Lease` is six
  `string` fields from Kea CSV (server). Force-merging would be a defect, not
  dedup. Claim holds.
- **option-82 / broadcast validation:** greps to `pkg/dhcprelay` ONLY. The
  issue's "duplicates … between relay and server" is false. Claim holds.
- **Shared unexported helpers server↔relay:** `comm -12` of unexported func
  names = empty. Claim holds.
- **`AddressFamily`/`AFInet`:** client-private; server/relay never reference
  them. Claim holds.
- **config types:** server uses `config.DHCPServer*`, relay uses
  `config.DHCPRelay*` — disjoint. Shared *through* `pkg/config`, not duplicated.
  Claim holds.

I could not find a single symbol that belongs in `common/`. **The `common/`
PLAN-KILL is correct and well-evidenced.** This is the right call and the plan
makes it explicitly rather than silently dropping `common/`.

### F4 — [HOLDS] Blast radius — attacked for undercount, survives
Plan says 19 importer files across 4 packages (api 4, cli 4, daemon 9,
grpcapi 2). Re-ran the grep including `cmd/`:
```
grep -rln 'psaab/xpf/pkg/(dhcp|dhcpserver|dhcprelay)"' --include=*.go cmd/   # empty
```
No `cmd/` importers, no importers outside the 4 named packages. 19 total
confirmed. The 99/6/4 external qualified-ref counts reproduce. **Not
undercounted.** Note the plan honestly *increases* the footprint vs the issue
(20 files / 8.6K LOC vs the issue's implied 3 files / 2.6K) by surfacing the
DDNS subsystem — that is the harder, more honest direction.

### F5 — [ACCEPTED] Recommendation altitude: DEFER, not "do now"
The plan recommends PLAN-READY-but-DEFERRED (fold into the next DHCP feature).
Hostile question: is "deferred" a cop-out that fails to deliver a decision?
No — it is the *issue's own disposition* ("refactor-with-next-DHCP-feature
preferred") and matches `docs/engineering-style.md` "Refactor with new features,
not after." The plan does not hide behind "deferred": it fully specifies the
move (Strategy A, file list, validation) so the next feature PR can execute it
mechanically. This is the correct altitude for a low-value-cosmetic refactor.
**Accepted.**

### F6 — [MINOR, no fix needed] Monolith argument is correctly dismissed
The issue leans on "1415 LOC approaching the monolith smell floor." The plan
correctly notes the floor is ~2000 and the must-split line ~3000, so 1415 is
585 under the smell floor. A hostile reviewer might want the plan to also note
that *splitting `dhcp.go` itself* (intra-package, like #2006 did for vrrp) is a
separate, more defensible refactor than the inter-package regroup #1987 asks
for. The plan implicitly covers this (the regroup doesn't reduce any file's
LOC) but does not propose the intra-file split as an alternative.
**Disposition:** Not a defect — #1987 is specifically about the 3→1 package
regroup, not file-splitting. Noted for completeness; out of scope.

### F7 — [VERIFIED] Smoke-not-required claim is correct
The plan asserts no smoke/failover gate applies. Verified: none of the three
packages contain dataplane/HA/VRRP/session-sync/forwarding code (they import
`config`/`fsatomic` only; relay does AF socket dispatch but that's not the
cluster failover path). `go test ./...` is the right gate. The plan states this
explicitly to pre-empt the reflexive "run failover" reviewer note. Good — this
is a known project gotcha (CLAUDE.md mandates failover only for
cluster/VRRP/session-sync/failover code).

## Attempted falsifications that FAILED (claim survived)

1. Back-edge from `config`/`fsatomic` into DHCP packages → only a comment, no
   import. Cycle claim survives.
2. Hunt for any shared type/helper/const across the three → none. `common/`
   kill survives.
3. Hidden `cmd/` or non-api/cli/daemon/grpcapi importer → none. Blast radius
   survives.
4. Transitive cycle via `config` (does the eventual parent need config which
   needs dhcp?) → config has no DHCP import edge. Survives.

## Net assessment

The plan's two load-bearing claims (no cycle; `common/` is a kill) are
**correct and reproducibly evidenced**. The one factual slip (alias
"requirement", F1) was cosmetic and is fixed. The recommendation altitude
(PLAN-READY reduced scope, DEFERRED, `common/` killed) is honest and matches
both the issue disposition and the style guide. Blast radius is accurate and, if
anything, more conservative (larger) than the issue implied.

**SMR verdict: CONCUR with the plan.**
- `common/`: **PLAN-KILL** (no shared code) — confirmed.
- 3-sibling regroup: **PLAN-READY, DEFERRED to next DHCP feature** — confirmed.
- Cycle wall (#2002/#2004): **does not apply** (zero inter-package edges, no
  parent package) — confirmed.

No blocking issues. The plan is ready as a research deliverable. It should NOT
be executed as a standalone churn PR now; it should be picked up by the next
change that touches `pkg/dhcp*`.
