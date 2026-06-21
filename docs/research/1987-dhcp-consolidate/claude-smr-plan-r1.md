# Claude SMR — hostile plan review r1, #1987

Stance: hostile. I authored r1 of the plan and I am now trying to break
it. Two independent hostile Claude reviewers already ran; I verified
their findings against origin/master myself rather than trusting them.

## The one MAJOR I have to own

Reviewer A and Reviewer B both independently caught the same defect,
and **they are correct, I was wrong:**

- My r1 §2.1/§2.2 numbers were measured against the LIVE checkout
  `/home/ps/git/bpfrx`, which is **STALE / behind origin/master**. The
  live working tree predates #1387-inc-2 (the DDNS subsystem) and #2112
  (`l2send_linux.go`). Re-measuring against the worktree (which IS
  origin/master @ 5fa964c13) gives the reviewers' numbers, not mine:

  | metric | r1 (WRONG, stale) | r2 (origin/master, verified) |
  |---|---|---|
  | dhcpserver prod LOC | 701 | **2836** |
  | dhcpserver files | 2 | **13** (incl. 6 ddns*.go prod) |
  | dhcpserver importers | 4 | **9** (incl. daemon_ddns.go) |
  | dhcprelay prod LOC | 568 | **958** |
  | relay.go LOC | 539 | **705** |
  | total import-site lines | 26 | **31** |
  | distinct importer files | 21 | **21** (coincidentally same) |
  | dhcp prod LOC / dhcp.go | 1779 / 1415 | 1779 / 1415 (correct) |

  This is a real verification failure: a research plan whose entire
  premise is a code inventory must measure the inventory on the base it
  claims (origin/master), not on a stale local checkout. r2 fixes every
  number and re-grounds the reasoning.

## Does the corrected inventory FLIP the recommendation?

This is the question that matters. I checked the worst case: did the
DDNS subsystem (which I never looked at in r1) introduce shared code
that would give `common/` something to hold?

**No — and I verified it three ways on origin/master:**
1. `grep` for cross-package imports (prod + test) among the three
   packages = **0** in every direction. DDNS did not create coupling.
2. `pkg/dhcpserver` DDNS speaks the **DNS wire** (RFC 2136 via
   `github.com/miekg/dns`, 4 sites in ddns_rfc2136.go). `pkg/dhcprelay`
   speaks the **DHCP wire** (insomniacslk/dhcpv4, option-82). These are
   **different protocols** with no shared parse/format/validate code.
   The server's DDNS types (`ddnsLease`, `LeaseDNSRecord`) and helpers
   (`reversePTRName`, `identity4`) are server-only.
3. The two `Lease` types remain structurally unrelated.

So the linchpin (`common/` would be empty) **survives the correction**.
The recommendation direction does NOT flip. But my r1 *reasoning*
("the server never touches the wire / does not do packet formatting at
all") is now demonstrably false — the server DOES touch a wire (DNS),
just not the same one as the relay. r2 restates this correctly.

## What the corrected inventory CHANGES about the recommendation

It actually **strengthens** the case against the issue-as-specified
and **strengthens** Option C:

- `pkg/dhcpserver` is now a **2836-LOC package spanning two distinct
  subsystems** (Kea-mgmt + DDNS/RFC2136). That is the real, present
  modularity smell — far more so than dhcp.go's 1415 LOC. The
  issue-as-specified (regroup three roots under a directory + invent an
  empty `common/`) does nothing about it. Option C-style **in-place
  file/intra-package decomposition** (which dhcpserver already has —
  it's split into ddns_*.go files!) is the pattern the codebase is
  ALREADY using and the one that addresses real cohesion.
- Indeed dhcpserver's own ddns_*.go layout is living proof that
  in-place file splitting (Option C) is the project's working answer to
  Go file growth — no new package, no import churn. The issue's
  cross-package regroup is solving a problem the codebase doesn't have.

## Hostile pressure on the terminal verdict (DEFER vs KILL)

- The defer's sole trigger ("refactor-with-next-DHCP-feature") fired
  twice now and shipped flat both times: #1387-inc-2 (DDNS, a major
  server feature) AND #2076/#2112 (relay raw-L2). Neither bundled the
  consolidation. The trigger is not just "passed" — it's been ignored
  across two separate DHCP features. Re-DEFER is indefensible; that
  makes it a permanent backlog ghost.
- KILL of the `common/`-consolidation-as-specified is the honest
  terminal state: the spec's central deliverable (`common/` dedup) is
  provably unbuildable, no LOC threshold forces the move (Go; the
  engineering-style monolith rule is `.rs`-scoped at 2000/3000), and
  the realized benefit is cosmetic directory grouping at the cost of a
  31-site cross-package diff + blame/log discontinuity.

## SMR verdict

PLAN-REVISE (mandatory): r2 MUST fix the §2.1/§2.2 numbers to the
origin/master values (dhcpserver 2836 LOC / 9 importers / 13 files;
dhcprelay 958 LOC / relay.go 705; total 31 import lines), add the DDNS
subsystem to the inventory, and restate §2.3 as "server speaks
DNS-wire (RFC 2136), relay speaks DHCP-wire — different protocols, no
shared code" instead of "server never touches the wire." After that
correction the substantive verdict is **PLAN-KILL of the `common/`
consolidation-as-specified**, with **Option C (in-place file split,
zero import churn)** offered as the cheap, codebase-idiomatic
alternative for whoever wants to act on the modularity intent. The
no-`common/` conclusion is independently verified correct and does NOT
flip.
