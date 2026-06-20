# Research plan — #1987: consolidate `pkg/dhcp` + `pkg/dhcpserver` + `pkg/dhcprelay` into `pkg/services/dhcp/{client,server,relay,common}`

**Status:** PLAN-READY (scope reduced) — but the `common/` subpackage in the
issue title is PLAN-KILL (`reason: no shared code to extract`). Recommend a
*three-sibling regroup only* (`client`/`server`/`relay`, NO `common`),
**deferred** to the next DHCP feature per the issue's own disposition.

**Issue:** #1987 (OPEN, enhancement, AGY review 012 Part II.1, "AGY priority #2")
**Branch:** `research/1987-dhcp-consolidation`
**Base:** `origin/master` @ `3fa0af3b5`
**Companion-free:** drafted by Claude only; no Codex/AGY run. Stops at a drafted
plan + hostile Claude-SMR self-review. No production source changed. No PR.

---

## 1. Problem statement (as filed) and what the evidence actually shows

The issue asks to fold three flat root packages into one parent with four
subpackages:

```
pkg/services/dhcp/
  client/   # lease watcher + systemd-networkd integration   (was pkg/dhcp)
  server/   # kea-dhcp4 config render + listener              (was pkg/dhcpserver)
  relay/    # relay agent socket dispatch + option-82 inserts (was pkg/dhcprelay)
  common/   # shared packet structs, parser types, lease models
```

The stated rationale has three claims. Verified against `origin/master`
@ `3fa0af3b5`:

| Issue claim | Evidence | Verdict |
|---|---|---|
| "`pkg/dhcp/dhcp.go` (1415 LOC) approaching the monolith smell floor" | `dhcp.go` = 1415 LOC. Style floor is ~2000 LOC; "must-split-before-adding" is ~3000. | **Weak.** 585 LOC under the smell floor; nowhere near the split mandate. |
| "Root-namespace fragmentation masks the functional relationship" | All three are sibling `pkg/` packages; daemon wires them side-by-side. | **True but cosmetic.** Pure namespacing, not a coupling problem. |
| "duplicates type mappings / packet formatting / broadcast-option validation between relay and server" | **No shared code found** (see §3). option-82 / broadcast lives ONLY in `dhcprelay`. The two `Lease` structs model different domains. Server and relay reference *different* `config.*` types. Zero shared unexported helpers. | **FALSE.** This is the load-bearing justification for `common/`, and it does not hold. |

Stale LOC in the issue: it cites `pkg/dhcpserver/dhcpserver.go=662` and implies
the server is small. In reality `pkg/dhcpserver/` is **4414 LOC across 9 files**
— it carries an entire DDNS subsystem (`ddns.go`, `ddns_dns.go`,
`ddns_hostname.go`, `ddns_leases.go`, `ddns_state.go`, `ddns_test.go` =
2945 LOC). The "consolidation" is therefore moving ~20 files / ~8.6K LOC, not
the three files implied.

## 2. Pre-flight: is it already shipped or stale-open? (the #2003 check)

- `gh pr list --state merged --search "1987 in:title"` → **empty**.
- `pkg/services/dhcp/` does **not** exist on `origin/master`.
- `gh issue view 1987` → **OPEN**, 0 comments, unassigned.

Conclusion: NOT already shipped. (#2003 was; #1987 is not.) Proceed to the
cycle analysis.

## 3. The import-cycle question (the #2002 / #2004 wall) — resolved

#2002 (`config`↔`ast`) and #2004 (`daemon`↔`multiqueue`) were PLAN-KILLED
because the code being *moved into a subpackage* was tightly coupled to code
*left behind in the parent*, so the subpackage and parent each needed to import
the other → a bidirectional edge → an illegal Go import cycle. #1987 is
structurally different and must be evaluated on its own facts.

### 3a. The three packages today

```
$ grep -rn "psaab/xpf/pkg/dhcp" pkg/dhcp pkg/dhcpserver pkg/dhcprelay   # cross-imports
(no output)
```

The three packages **do not import each other at all**. Their only
intra-repo dependencies are leaf utilities:

| Package | Intra-repo imports (non-test) |
|---|---|
| `pkg/dhcp` (client) | `pkg/fsatomic` |
| `pkg/dhcpserver` (server) | `pkg/config`, `pkg/fsatomic` |
| `pkg/dhcprelay` (relay) | `pkg/config` |

`pkg/config` and `pkg/fsatomic` are low-level leaves that neither import any of
the three DHCP packages (verified: no edge back). So the dependency subgraph for
the three packages is a **forest of independent trees**, not a coupled cluster.

### 3b. Would the proposed layout create a cycle?

**`client`/`server`/`relay` as siblings: NO cycle, by construction.** Re-homing
three packages that already have zero edges between them into a shared parent
directory changes only their *import paths*, not their *dependency graph*. Go
import cycles are a property of the package dependency graph; moving a leaf
package to a new path with the same (empty) set of intra-group edges cannot
introduce an edge. There is no parent package to couple to (the parent
`pkg/services/dhcp/` would be a directory, not a Go package, unless we
deliberately add a `dhcp.go` there).

**`common/` as a fourth subpackage: would be EMPTY, so the cycle question is
moot — but the *reason* it's empty is the kill.** The `common/` package only
makes sense if there is shared code to host. There is not:

- **No shared types.** `dhcp.Lease` (client: `netip.Prefix` address, gateway,
  DNS slice, lease duration) and `dhcpserver.Lease` (server: six `string`
  fields parsed from a Kea CSV) are *different domain models that happen to
  share a name*. Merging them would be wrong, not deduplication.
- **No shared packet code.** option-82 (`OptionRelayAgentInformation`),
  `addOption82`/`stripOption82`, and `dhcpv4.FromBytes` packet
  parsing exist ONLY in `pkg/dhcprelay`. The server renders Kea JSON and parses
  Kea CSV; the client uses `nclient4`/`nclient6`. No overlap.
- **No shared validation.** "broadcast-option validation" greps to
  `pkg/dhcprelay` only (relay.go, sockopt_linux.go); the server has none.
- **No shared helpers.** `comm -12` of the unexported function names in
  `dhcpserver.go` vs `relay.go` → **empty intersection**.
- **`AddressFamily`/`AFInet`/`AFInet6` are client-private.** Neither server nor
  relay reference them.

So `common/` would be created with nothing in it (or we would manufacture
artificial "shared" types by force-merging unrelated structs, which is
anti-modular). **`common/` is PLAN-KILL: no shared code to extract.** The
duplication premise in the issue is not borne out by the source.

### 3c. Does the parent dir need a Go package?

No. `pkg/services/dhcp/` should be a *directory only* (no `.go` files at that
level). The daemon imports the three leaves directly
(`.../services/dhcp/client`, `.../server`, `.../relay`). A parent `dhcp` package
that re-exported the three would (a) be pointless and (b) reintroduce the exact
parent↔child coupling that killed #2002/#2004. Avoid it.

## 4. Blast radius (the external-caller churn)

### 4a. Files importing the three packages (must edit the import path)

19 non-`/dhcp*/` files import at least one of the three (some import two or
three): `pkg/api/{interfaces.go, server.go, iface_name_test.go,
metrics_descriptor_coverage_test.go}`, `pkg/cli/{apply.go, cli.go,
cli_show_interfaces.go, cli_show_services.go}`, `pkg/daemon/{daemon.go,
daemon_run.go, daemon_dhcp.go, daemon_dns.go, daemon_dns_test.go,
daemon_flow.go, daemon_ra.go, dhcp_nexthop_resolver_test.go,
dhcp_reconcile_test.go}`, `pkg/grpcapi/{server.go, server_show_interfaces.go}`.

Per-package importer counts:

| Package | importer files (total / non-test) |
|---|---|
| `pkg/dhcp` | 19 / 14 |
| `pkg/dhcpserver` | 4 / 4 |
| `pkg/dhcprelay` | 3 / 3 |

### 4b. Qualified-reference churn (depends on the package-name decision)

The dominant cost driver is whether the moved packages **keep** their package
names (`package dhcp`, `package dhcpserver`, `package dhcprelay`) or **rename**
to match the directory (`package client`, `package server`, `package relay`).

External qualified references on master:

| Prefix | external refs | unique symbols | top symbols |
|---|---|---|---|
| `dhcp.*` | 99 | 24 | `AFInet`(20), `Lease`(16), `Leases`(12), `AFInet6`(11), `Manager`(10), `New`(7), `AddressFamily`(7) |
| `dhcpserver.*` | 6 | 2 | `Manager`(3), `New`(2) |
| `dhcprelay.*` | 4 | 2 | `Manager`(3), `NewManager`(1) |

Two strategies:

- **Strategy A — keep package names, change only paths.** Edit the 19 import
  lines (`pkg/dhcp` → `pkg/services/dhcp/client` etc.). The package *identifier*
  stays `dhcp`/`dhcpserver`/`dhcprelay`, so all 99+6+4 = **109 call sites are
  untouched**. Mechanical, near-zero risk. Downside: directory `client/` has
  `package dhcp` inside — a mild surprise. Go does **not** *require* an import
  alias when the path tail (`client`) differs from the package name (`dhcp`):
  `import "…/services/dhcp/client"` compiles and is referenced as bare `dhcp.`.
  An explicit alias (`dhcp "…/services/dhcp/client"`) is *optional* — some
  linters/reviewers prefer it for readability since the path tail no longer
  matches the identifier. If adopted, it is uniform across all importers; if
  not, the bare import still works. Either way, zero call-site identifier edits.
- **Strategy B — rename packages to `client`/`server`/`relay`.** "Cleaner"
  reading at call sites (`client.Manager`, `server.Manager`, `relay.Manager`)
  but `client`/`server`/`relay` are *generic* identifiers that collide with
  local variables and read ambiguously across the tree (`server.New()` next to
  gRPC/HTTP servers is confusing). Forces editing all **109** qualified
  references, and `client`/`server` are high-collision names. Higher churn,
  higher risk, worse readability.

**Recommendation: Strategy A.** Lower blast radius, mechanically verifiable,
keeps the descriptive `dhcp`/`dhcpserver`/`dhcprelay` identifiers at call sites.
The directory naming (`client`/`server`/`relay`) still delivers the namespacing
the issue wants.

### 4c. Cross-repo / non-Go references

- `go.mod` module is `github.com/psaab/xpf` (single module) — no replace
  directives, no second module to update.
- README files (`pkg/dhcp/README.md`, `pkg/dhcpserver/README.md`,
  `pkg/dhcprelay/README.md`) move with the code and need path/title touch-ups
  (module-contract docs per CLAUDE.md).
- Search for path strings in non-Go files (docs/scripts) is part of Step 1
  below; none expected (these are internal Go import paths).

## 5. Proposed end state (if/when executed — scope-reduced)

```
pkg/services/dhcp/
  client/    # 8 files  (was pkg/dhcp)        — package dhcp        (Strategy A)
  server/    # 9 files  (was pkg/dhcpserver)  — package dhcpserver
  relay/     # 3 files  (was pkg/dhcprelay)   — package dhcprelay
  (NO common/  — nothing to put in it)
  (NO parent dhcp.go — directory only, avoids parent↔child cycle)
```

20 files moved via `git mv` (preserves blame). 19 importer files get a
one-line import-path edit each (with an explicit `dhcp`/`dhcpserver`/`dhcprelay`
alias on the import line). Zero call-site identifier edits. Zero new
inter-package edges. Zero possibility of an import cycle.

## 6. Implementation steps (for the eventual feature-coupled PR — NOT now)

1. **Path-string sweep.** `grep -rn "pkg/dhcp\"\|pkg/dhcpserver\|pkg/dhcprelay"`
   across the whole tree (incl. docs, scripts, Makefile, `.golangci.yml`,
   embed directives) to confirm the only references are Go imports. Record the
   list.
2. **`git mv`** the three dirs:
   `pkg/dhcp → pkg/services/dhcp/client`,
   `pkg/dhcpserver → pkg/services/dhcp/server`,
   `pkg/dhcprelay → pkg/services/dhcp/relay`. Keep package clauses unchanged
   (Strategy A).
3. **Rewrite import paths** in the 19 importer files (`pkg/api` ×4, `pkg/cli`
   ×4, `pkg/daemon` ×9, `pkg/grpcapi` ×2). The package identifier still reads
   `dhcp.`/`dhcpserver.`/`dhcprelay.` (Strategy A); optionally add an explicit
   import alias for readability. Scriptable with `sed` + `goimports`, but verify
   each by eye.
4. **Move the three READMEs** with the code; fix their first-line titles/paths.
5. **`goimports -w` + `go build ./... && go vet ./... && go test ./...`** — the
   compiler is the cycle oracle. A green build *is* the proof no cycle formed.
6. **Update `CLAUDE.md` Code-Layout table** (the three `pkg/dhcp*` rows → one
   `pkg/services/dhcp/{client,server,relay}` row) — module-contract doc.
7. Commit as a single mechanical-move PR (or, preferred, fold into the next
   DHCP feature PR per the issue disposition).

## 7. Validation plan

- **Build/vet/test:** `go build ./...`, `go vet ./...`, `go test ./pkg/services/dhcp/... ./pkg/daemon/... ./pkg/api/... ./pkg/cli/... ./pkg/grpcapi/...`.
- **Cycle proof:** a successful `go build ./...` is dispositive — Go refuses to
  compile an import cycle. No separate tooling needed.
- **Blame preservation:** `git log --follow` on a moved file shows history
  survives (`git mv` + `--follow`).
- **No behavior change:** this is a pure move + path edit; diff should contain
  only `import` lines and file relocations (and the alias additions). A
  `git diff --stat` dominated by renames + import lines is the smell test.
- **Smoke:** NOT required — no dataplane, HA, VRRP, session-sync, or failover
  code is touched (these three packages have no cluster/forwarding code). A
  `go test ./...` pass is sufficient. (Stated explicitly to avoid the reflexive
  "run failover" gate; it does not apply to a pure Go package move.)

## 8. Risks and mitigations

| Risk | Likelihood | Mitigation |
|---|---|---|
| Import cycle | **None** (proven §3) | Build is the oracle; no parent package. |
| Hidden path string in a script/embed/golangci config | Low | Step 1 path-string sweep before moving. |
| `common/` scope-creep (someone force-merges the two `Lease` types) | Medium if not guarded | Plan explicitly DROPS `common/`; reviewers reject any merged-Lease attempt. |
| Alias confusion (Strategy A: `package dhcp` lives at `…/client`) | Low | Alias is OPTIONAL (Go doesn't require it); if used, uniform across importers and documented in the PR body. |
| Stale-LOC expectation (reviewer expects 3 small files, sees 20/8.6K) | Low | This plan documents the real footprint up front. |
| Merge conflict against live DHCP WIP | Medium | Land coupled to the next DHCP feature, or on a quiet window; it's all mechanical so rebase is trivial. |

## 9. Honest scope assessment — churn vs benefit

**Cost:** 20 file moves + 19 importer edits + 3 README touch-ups + 1 CLAUDE.md
row + a build/vet/test cycle. Mechanical, low-risk, but non-trivial diff
surface (~25 files touched) and a guaranteed rebase tax against any in-flight
DHCP work.

**Benefit:** purely organizational — one `pkg/services/dhcp/` namespace instead
of three `pkg/dhcp*` siblings. **No** deduplication (the `common/` premise is
false), **no** decoupling (already decoupled), **no** monolith relief (largest
file is 585 LOC under the smell floor).

**Net:** the benefit is real but small and aesthetic. The issue's own
disposition agrees: *"refactor-backlog — large mechanical move (import-path
churn across the tree). Do NOT plan-converge here. … refactor-with-next-DHCP-
feature preferred per the style guide."* That matches the engineering-style
"Refactor with new features, not after" rule exactly.

## 10. Recommendation

- **`common/` subpackage: PLAN-KILL (reason: no shared code to extract).** The
  load-bearing "duplication between relay and server" premise is false against
  current source. Creating `common/` would either leave it empty or force an
  anti-modular merge of unrelated `Lease` types.
- **`client`/`server`/`relay` sibling regroup: PLAN-READY but DEFERRED.** It is
  clean (zero cycle risk, Strategy A keeps 109 call sites untouched), but it is
  a low-value mechanical move that the issue itself flags as
  refactor-with-next-feature. Do NOT land it as a standalone churn PR now; fold
  it into the next DHCP feature PR (next change to `pkg/dhcp*`), per the
  disposition and the style guide.
- **Cycle question (the #2002/#2004 wall): RESOLVED — no cycle.** Unlike
  config↔ast and daemon↔multiqueue, the three DHCP packages have zero edges
  between each other and no parent package to couple to, so re-homing them as
  siblings cannot create a cycle. This is the key structural difference from the
  plan-killed precedents.

**Overall verdict: PLAN-READY (reduced to a 3-sibling regroup, no `common/`),
DEFERRED to the next DHCP feature.** Not already-shipped; not cycle-blocked; the
`common/` portion is a kill.

## 11. Appendix — commands run (reproducibility)

```
gh issue view 1987
gh pr list --state merged --search "1987 in:title"           # empty
git ls-tree -r --name-only origin/master | grep pkg/dhcp     # no pkg/services/dhcp
grep -rn "psaab/xpf/pkg/dhcp" pkg/dhcp pkg/dhcpserver pkg/dhcprelay   # no cross-imports
grep -rh "psaab/xpf/" pkg/dhcp*/*.go pkg/dhcprelay/*.go       # intra-repo deps (fsatomic, config)
grep -rln '"github.com/psaab/xpf/pkg/dhcp{,server,relay}"' --include=*.go .   # 19 importers
grep -rho '\bdhcp\.[A-Z]...'  --exclude-dir=dhcp              # 99 ext refs / 24 symbols
comm -12 <server unexported fns> <relay unexported fns>       # empty -> no shared helpers
wc -l pkg/dhcp*/*.go pkg/dhcprelay/*.go                       # 20 files, real LOC
```
