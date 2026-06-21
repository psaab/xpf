# Plan of Action — #1987: consolidate pkg/dhcp + pkg/dhcpserver + pkg/dhcprelay into pkg/services/dhcp/{client,server,relay,common}

- **Revision:** r2 (numbers corrected to origin/master after r1 review)
- **Status:** CONVERGED — recommendation PLAN-KILL of common/-consolidation-as-specified
- **Author:** Claude research pass
- **Issue:** #1987 (label `enhancement`, `plan-deferred-operator`)
- **Mode:** `/research` — terminal at PLAN-READY / PLAN-DEFER / PLAN-KILL. No code.

## 1. Problem statement

#1987 (from AGY review 012 Part II.1) proposes consolidating the three
flat root DHCP packages into a nested namespace:

```
pkg/services/dhcp/
  client/   # lease watcher + systemd-networkd integration   (was pkg/dhcp)
  server/   # kea-dhcp4 config render + listener              (was pkg/dhcpserver)
  relay/    # relay agent socket dispatch + option-82 inserts (was pkg/dhcprelay)
  common/   # shared packet structs, parser types, lease models
```

The stated rationale: (a) `pkg/dhcp/dhcp.go` at 1415 LOC approaches a
"monolith smell floor"; (b) "root-namespace fragmentation masks the
functional relationship"; (c) the move "duplicates type mappings /
packet formatting / broadcast-option validation between relay and
server" that `common/` would dedup.

The issue was previously **PLAN-DEFERRED-operator** with the explicit
disposition: *"large mechanical move (import-path churn across the
tree)... refactor-with-next-DHCP-feature preferred per the style
guide."* The user now wants every open issue driven to a terminal
state, so this pass RE-EVALUATES whether the defer still holds.

## 2. Blast radius (measured on origin/master @ 5fa964c13 — RE-MEASURED in r2)

> r1 ERRATUM: the r1 table was measured against a STALE local checkout
> that predated #1387-inc-2 (the DDNS subsystem) and #2112
> (`l2send_linux.go`). All three hostile reviewers caught it. The
> numbers below are re-measured against the actual base
> (origin/master @ 5fa964c13, via the research worktree).

### 2.1 Subject packages (production LOC, excludes `_test.go`)

| Package | Prod LOC | Largest file | External deps |
|---|---|---|---|
| `pkg/dhcp` (client) | 1779 | dhcp.go (1415) | insomniacslk/dhcp (v4/v6/nclient/iana), vishvananda/netlink |
| `pkg/dhcpserver` | **2836** | dhcpserver.go (732) **+ 6 ddns*.go** | pkg/config, pkg/fsatomic, **github.com/miekg/dns** (DDNS/RFC 2136) |
| `pkg/dhcprelay` | **958** | relay.go (705) | insomniacslk/dhcp (dhcpv4 only), pkg/config |

`pkg/dhcpserver` is NOT a thin Kea wrapper: it now spans TWO
subsystems — Kea config render/listener (dhcpserver.go) AND a full
**DDNS / RFC 2136 dynamic-DNS-update backend** (`ddns.go` 633,
`ddns_rfc2136.go` 502, `ddns_leases.go` 378, `ddns_hostname.go` 215,
`ddns_state.go` 176, `ddns_dns.go` 130; #1387 inc-2). `pkg/dhcprelay`
carries the #2112 raw-L2 work (`l2send_linux.go`, `delivery_test.go`,
`l2send_test.go`). dhcp.go at 1415 is the single largest source file
but dhcpserver as a *package* is the largest at 2836 prod LOC.

### 2.2 Importers (real tree, `.claude/worktrees/` excluded)

| Importer of | Files | Import-site lines |
|---|---|---|
| `pkg/dhcp` | 19 | 19 |
| `pkg/dhcpserver` | **9** | 9 |
| `pkg/dhcprelay` | 3 | 3 |
| **distinct importer files (union)** | **21** | **31** |

Importing packages: `pkg/api`, `pkg/cli`, `pkg/daemon` (the bulk —
daemon_dhcp.go, daemon_dns.go, daemon.go, daemon_run.go, daemon_ra.go,
daemon_flow.go, **daemon_ddns.go**, **daemon_ddns_test.go** + other
tests), `pkg/grpcapi`. All within the Go control plane; **no Rust, no
proto, no build scripts** reference these paths. The dhcpserver
importer set includes `daemon_ddns.go` + `daemon_ddns_test.go` — any
move executor MUST rewrite all 9, not 4.

Non-Go references: `docs/architecture.md`, `docs/phases.md`,
`CLAUDE.md` (Code Layout table, 2 rows), plus historical
`docs/pr/*` and `docs/issues/issue-history.md` (frozen history — do
NOT rewrite).

### 2.3 Cross-package coupling — THE DECISIVE FINDING

**The three packages have ZERO inter-imports.** `grep` confirms:
- `pkg/dhcpserver` does not import `pkg/dhcp` or `pkg/dhcprelay`.
- `pkg/dhcprelay` does not import `pkg/dhcp` or `pkg/dhcpserver`.
- `pkg/dhcp` does not import either of the other two.

There is **no shared code today** and there is **nothing to extract
into `common/`**:
- The `Lease` type exists in BOTH `pkg/dhcp` and `pkg/dhcpserver`
  but they are **structurally unrelated**:
  - client `dhcp.Lease`: `{Interface string; Family AddressFamily;
    Address netip.Prefix; Gateway netip.Addr; DNS []netip.Addr;
    LeaseTime time.Duration; Obtained time.Time}` — runtime watcher
    state from the netlink/nclient path.
  - server `dhcpserver.Lease`: `{Address, HWAddress, Hostname,
    ValidLife, ExpireTime, SubnetID string}` — a parsed row of Kea's
    on-disk CSV lease file. (DDNS additionally has its own server-only
    `ddnsLease` / `LeaseDNSRecord` types — also unshared.)
  These model different things (a client's own lease vs a row of the
  server's lease DB). Merging them into one `common.Lease` would be
  *wrong* — it would force a false abstraction over two unrelated
  domain objects.
- **Each component speaks a DIFFERENT wire — no shared parse/format/
  validate code.** (r1 wrongly said "the server never touches the
  wire." It does — just not the same wire as the relay.)
  - `pkg/dhcprelay` speaks the **DHCP wire**: `dhcpv4.*` (insomniacslk)
    at 15+ sites, option-82 (`addOption82`/`stripOption82`),
    broadcast-flag handling, ports 67/68 — all relay-only.
  - `pkg/dhcpserver` DDNS speaks the **DNS wire**: RFC 2136 dynamic
    updates over `github.com/miekg/dns` (`dns.Client`, `dns.Msg` in
    `ddns_rfc2136.go`), with server-only helpers (`reversePTRName`,
    `identity4`, `deriveFQDN`/`sanitizeLabel`). It has **0**
    `insomniacslk/dhcp` imports.
  - `pkg/dhcp` (client) uses `dhcpv4`/`dhcpv6` at 2 sites for its own
    lease acquisition.
  Different protocols (DHCP vs DNS), different libraries
  (insomniacslk/dhcp vs miekg/dns), zero overlapping helpers. The
  issue's specific claim of "broadcast-option validation between relay
  and server" is **REFUTED** — broadcast/option-82 handling is entirely
  relay-side; the server never sees a DHCP packet.

**Conclusion:** the issue's premise that `common/` would dedup shared
type mappings / packet formatting / broadcast-option validation is
**factually incorrect on the current code.** `common/` would be born
empty (or would contain a single forced-merge `Lease` that is an
anti-abstraction). The "deduplication" value proposition does not
exist.

### 2.4 The "next DHCP feature" trigger has already fired — and shipped without the refactor

The defer's condition was *"refactor-with-next-DHCP-feature."* That
feature arrived and merged **one day ago**:
- **#2076** (raw-L2 unicast OFFER/ACK for broadcast-flag-clear clients)
  → **PR #2112 MERGED 2026-06-20**, adding `pkg/dhcprelay/l2send_linux.go`,
  `delivery_test.go`, `l2send_test.go` plus relay.go changes — a
  substantial relay feature (the literal "next DHCP feature").
- It shipped **on the flat package structure**, NOT bundled with the
  consolidation. The window the defer was holding for has **passed
  unused**.
- **#2115** (OPEN, `plan-deferred-lab`) is the residual follow-up: a
  live wire-capture (lab-gated) + a merged-Keys `overrides` regression
  test. The test item is a *pure test addition to pkg/dhcprelay* (no
  new feature, no 200+ LOC). It is NOT a "next feature" that would
  re-open the refactor-with-feature window in a meaningful way.

This is the key calculus change vs the original defer: the style
guide's "refactor with new features, not after" rule was the entire
justification for deferring, and that opportunity is now in the past
tense. There is no scheduled DHCP feature on the horizon to bundle
with (the only open DHCP item, #2115, is lab + test-hardening).

## 3. Risk assessment

### 3.1 Behavioral risk: LOW (pure code-motion if done)
A package move is `git mv` + `package` rename + import-path rewrite at
26 call-sites. No logic changes. Compiler + `go test ./...` catch any
miss. Risk of behavioral regression is near-zero **provided** it stays
pure motion (no opportunistic "while I'm here" edits).

### 3.2 Diff-width / merge-conflict risk: MODERATE-WIDE
- 31 import-site edits across 21 files in 5 packages (api, cli,
  daemon, grpcapi + the 3 moved packages). `pkg/daemon` is the
  highest-churn consumer (7+ files) and is one of the most
  frequently-touched packages in the tree.
- The diff touches `git`-history continuity: `git log -- pkg/dhcp/...`
  stops at the move unless `--follow` is used. `git blame` continuity
  survives `git mv` but is muddied by the simultaneous package-name
  rename in the same commit.

### 3.3 The honest cost/benefit
- **Cost:** wide mechanical diff, blame/log discontinuity, reviewer
  time across 5 packages, doc updates (CLAUDE.md, architecture.md,
  3 README.md relocations).
- **Benefit IF the `common/` premise were true:** real dedup. It is
  **not** true (§2.3). So the realized benefit collapses to: (a)
  namespace tidiness (`pkg/services/dhcp/*` reads better than three
  flat roots); (b) a *directory* grouping of related-but-decoupled
  subsystems. Neither reduces a single line of duplicated code, and
  neither is forced by any LOC threshold:
  - The engineering-style "no monolithic files" rule is written for
    **`.rs` at ~2,000 / ~3,000 LOC**. `dhcp.go` at 1415 prod LOC is
    below even the Rust smell floor, and Go is not the language the
    rule targets. The "approaching the monolith smell floor" claim in
    the issue is overstated for a 1415-LOC Go file.

### 3.4 Is there a real modularity defect worth fixing?
Yes — but it is *intra-package*, not the cross-package regroup #1987
asks for:
- `pkg/dhcp/dhcp.go` (1415 LOC: client + v4 + v6 + PD + DUID +
  RA-mapping in one file) is the largest single source file. Splitting
  it into `dhcp_v4.go` / `dhcp_v6.go` / `duid.go` / `prefix_delegation.go`
  *within the existing package* addresses cohesion with **zero importer
  churn**.
- Notably, `pkg/dhcpserver` (2836 prod LOC) is **already** decomposed
  in-place into `dhcpserver.go` + 6 `ddns_*.go` files — living proof
  that the project's working answer to Go file growth is in-package
  file splitting (Option C), NOT cross-package regrouping. The issue's
  proposed `pkg/services/dhcp/` directory move would not reduce a single
  line; the codebase's own idiom (and the engineering-style "one
  responsibility per module / split on the way in" rule) is satisfied
  by in-package file cohesion, which dhcpserver demonstrates.

That is a different, smaller, zero-churn piece of work (Option C) and
is not what #1987 asks for.

## 4. Path options

### Option A — Full consolidation as specified (move all 3 + create common/)
Move `pkg/dhcp` → `pkg/services/dhcp/client`, `pkg/dhcpserver` →
`.../server`, `pkg/dhcprelay` → `.../relay`, create `.../common`.
- **Problem:** `common/` has nothing to hold (§2.3). Creating an empty
  or forced-merge `common/` is an anti-pattern. Realized benefit =
  directory tidiness only; cost = full 26-site churn.

### Option B — Incremental move WITHOUT common/ (3 pure-motion commits)
Move each package to `pkg/services/dhcp/{client,server,relay}`, one
per commit, each building green, drop `common/` from scope entirely
(re-introduce only if/when real shared code appears). This is the
"safe incremental decomposition" the prompt asks about IF we proceed.
- **Pro:** each commit is independently revertable, bisectable, green.
- **Con:** still 26-site import churn for zero dedup; the `common/`
  half of the issue is acknowledged as unbuildable and dropped.

### Option C — Narrow the issue to the real defect: split dhcp.go in place
Leave package locations alone. Split `pkg/dhcp/dhcp.go` (1415 LOC)
into cohesive files within the same package (`client_v4.go`,
`client_v6.go`, `duid.go`, `prefix_delegation.go`). **Zero importer
churn** (same package, same import path). Addresses the only
measurable smell (file size). Re-file #1987 as a file-split issue.

### Option D — PLAN-DEFER (keep deferred) / PLAN-KILL
Recognize that the `common/` premise is false, no LOC threshold is
breached, no feature is queued to bundle with, and the realized
benefit is cosmetic directory grouping at the cost of a wide
cross-package diff with blame/log discontinuity. Either keep deferred
(re-trigger only with a genuine multi-component DHCP feature that
*creates* shared code), or KILL and optionally spin Option C as a
separate cheap issue.

## 5. Recommendation

**PLAN-KILL of the `common/` consolidation as specified in #1987**
(converged at r2 across all three hostile reviewers), with **Option C**
(in-place `dhcp.go` file split, zero importer churn) offered as the
cheap, optional, codebase-idiomatic alternative.

Reasoning:
1. The central justification (`common/` dedup) is **factually
   unsupported** — there is zero cross-package shared code and the two
   `Lease` types must NOT be merged. The issue as written cannot
   deliver its stated benefit.
2. The deferral's own trigger ("refactor-with-next-DHCP-feature")
   **already fired and shipped** (#2076/#2112, 2026-06-20) on the flat
   structure. The bundling opportunity is in the past; the only open
   DHCP work (#2115) is lab + a test addition, not a feature.
3. No LOC threshold is breached (Go, 1415 < Rust 2000 smell floor),
   so reviewers-escalate-monolith-creep does not bite.
4. Realized benefit = directory cosmetics; cost = wide 26-site
   cross-package churn + blame/log discontinuity + doc churn. Negative
   expected value for a pure-motion refactor with no functional
   driver.
5. If the team wants to act on the *one* defensible sliver (dhcp.go
   file size), Option C does it for near-zero churn and is a better
   use of the slot.

Since the user's directive is "drive every open issue down to a
terminal state," the terminal recommendation is: **close #1987 as
won't-do (or convert to Option C)**, because re-deferring an issue
whose trigger has already passed is not a real terminal state. The
3-way review will decide between DEFER-vs-KILL framing; both are
terminal and acceptable per the prompt.

## 6. If the reviewers insist on proceeding (the SAFE plan)

If 3-way convergence lands on "do it anyway for namespace hygiene,"
ship **Option B** with these guardrails (this is the converged-safe
decomposition, recorded so /engineer has it):

1. **Commit 1:** `git mv pkg/dhcprelay pkg/services/dhcp/relay`
   (incl. `relay.go`, `sockopt_linux.go`, `l2send_linux.go` + tests);
   `sed` package decl `dhcprelay` → `relay`; rewrite the 3 importers +
   their import aliases; move README.md; update CLAUDE.md row. Build +
   `go test ./...` green. (Smallest blast radius first — 3 importers.)
2. **Commit 2:** same for `pkg/dhcpserver` → `.../server` (**9**
   importers — incl. `pkg/daemon/daemon_ddns.go` +
   `daemon_ddns_test.go`; move ALL of `dhcpserver.go` + the 6
   `ddns_*.go` + tests + test_seams.go). Do NOT miss the DDNS
   importers — using the r1 "4 importers" number would break the build.
3. **Commit 3:** same for `pkg/dhcp` → `.../client` (19 importers,
   largest — do last so the first two are proven patterns).
4. **NO `common/`** — explicitly out of scope; document in the PR that
   §2.3 found no shared code. Re-open a `common/` issue only when a
   future feature creates genuinely shared wire/parse code.
5. Each commit pure-motion: NO logic edits, NO signature changes, NO
   "while I'm here." Any cleanup is a separate follow-up.
6. Update docs (architecture.md, phases.md current-state references,
   CLAUDE.md) in the final commit. Do NOT rewrite frozen history
   (`docs/issues/issue-history.md`, `docs/pr/*`).
7. Verification bar (pure code-motion, no lab): `go build ./...`,
   `go vet ./...`, `go test ./...` all green; `git diff --stat` shows
   only moves + import rewrites + doc updates (no logic hunks); a
   reviewer confirms zero behavioral hunks. No cluster/lab smoke
   required (no runtime behavior changes).

## 7. Test / validation strategy

Pure code-motion → bar is compiler + existing test suite + reviewer
eyeball that the diff contains no logic changes. Specifically:
- `go build ./... && go vet ./... && go test ./...` green.
- `git log -p` per commit shows ONLY `R`ename + package-decl + import
  path edits (+ doc). No `+`/`-` inside function bodies.
- Reviewer + Claude SMR confirm "no behavioral hunk." No iperf, no
  failover, no cluster (forwarding path untouched; DHCP client/server/
  relay all keep identical logic).

## 8. Documentation impact

- `CLAUDE.md` Code Layout table: 2 rows → updated paths (+1 if
  `common/` ever lands). Note the dhcpserver row should also mention
  DDNS/RFC 2136 (currently only says "Kea DHCP server management").
- `docs/architecture.md`, `docs/phases.md`: current-state path refs.
- 3 × `README.md` relocated with their packages.
- Move executor must also rewrite `pkg/daemon/daemon_ddns.go` +
  `daemon_ddns_test.go` (dhcpserver importers missed in r1).
- Frozen history (`docs/issues/*`, `docs/pr/*`) left untouched.
- If DEFER/KILL: update the issue + add a one-line note to the
  Go-LOC audit doc that #1987's `common/` premise was disproven.

## 9. Multiple-path summary table

| Option | common/ | Importer churn | Realized benefit | Verdict |
|---|---|---|---|---|
| A full-spec | empty/forced | 31 sites | cosmetic + false dedup | reject (anti-pattern) |
| B move-only | dropped | 31 sites | directory cosmetics | viable-if-insisted |
| C split dhcp.go in place | n/a | 0 sites | fixes the real file-size smell cheaply | best value if acting |
| D **KILL** common/-spec | n/a | 0 | none (no negative either) | **converged recommendation** |

## 10. Open questions for reviewers

1. Does the team accept that `common/` is unbuildable today (§2.3), or
   is there a planned DHCP feature that would create shared
   wire/parse/option code? (If yes, defer-with-that-feature is the
   right call and this becomes a true DEFER, not KILL.)
2. Is namespace tidiness alone (Option B) worth a 26-site
   cross-package diff with blame/log discontinuity, given zero dedup?
3. Is Option C (in-place dhcp.go split, zero churn) the better
   expression of the modularity intent behind #1987?

## 11. Decision record (converged at r2)

Companions (Codex/AGY) infra-degraded this session → 3 independent
hostile Claude reviewers (2 subagent + 1 SMR) per the research-skill
exception. See `reviewer-ids.md`.

- **Claude hostile reviewer A (r1):** "PLAN-REVISE ... After revision,
  land terminal state as KILL of the common/ consolidation-as-specified
  with Option C in-place dhcp.go split re-filed as the cheap modularity
  follow-up. The no-common/ conclusion itself is verified correct and
  does NOT flip."
- **Claude hostile reviewer B (r1):**
  "PLAN-REVISE-fix-stale-LOC-and-importer-counts-and-add-DDNS-to-inventory-then-KILL-common-consolidation"
- **Claude SMR (r1):** "PLAN-REVISE (mandatory) ... After that
  correction the substantive verdict is PLAN-KILL of the common/
  consolidation-as-specified, with Option C (in-place file split, zero
  import churn) offered as the cheap, codebase-idiomatic alternative.
  The no-common/ conclusion is independently verified correct and does
  NOT flip."

**Convergence:** unanimous. All three flagged the SAME single MAJOR
(r1's numbers were measured against a stale local checkout and omitted
the DDNS subsystem); all three independently verified the substantive
recommendation is CORRECT and does not flip. r2 corrects every number
to origin/master and re-grounds §2.3.

**Converged outcome: PLAN-KILL of the `common/` consolidation as
specified in #1987.** The central deliverable (`common/` dedup) is
provably unbuildable (zero cross-package shared code; three distinct
wire protocols; two unrelated `Lease` types); no LOC threshold forces
the move (Go; engineering-style monolith rule is `.rs`-scoped); the
defer's "refactor-with-next-feature" trigger has fired and shipped flat
TWICE (#1387-inc-2 DDNS, #2076/#2112 raw-L2); realized benefit is
cosmetic directory grouping at the cost of a 31-site cross-package diff
+ blame/log discontinuity. **Option C** (in-place `dhcp.go` file split,
zero importer churn — the idiom dhcpserver already follows) is offered
as the cheap, optional alternative for whoever wants to act on the
modularity intent, to be re-filed as its own small issue if desired.
