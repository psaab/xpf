# 10486: REST / gRPC / CLI session-filter contract convergence

Status: DRAFT v1 — plan only, no production code.
Base: `origin/master b71c52d60`; worktree `.claude/worktrees/10486-session`,
branch `fix/10486-session-filter-contracts`. All `file:line` refs re-pinned at
that HEAD (the issue's evidence pin `1a6952b` is stale).

## 1. Issue framing

Issue #10486 (OPEN, bug/audit/validated-by:research): the REST session-filter
query builder takes `protocol` raw with no validation while fail-closing every
sibling dimension, and the gRPC surface rejects the same token.

- REST: `pkg/api/sessions.go:1358` — `q.proto = r.URL.Query().Get("protocol")`
  sits inside `buildSessionQuery` (`:1351-1410`), whose `zone` (`:1353-1357`),
  `nat_only` (`:1362-1368`), `source_nat_pool` (`:1369-1378`),
  `source_prefix`/`destination_prefix` (`:1384-1397`) and
  `source_port`/`destination_port` (`:1398-1407`) branches each return an
  HTTP-400 reason string on bad input. `protocol` has no branch.
- gRPC: `pkg/grpcapi/server_sessions.go:499-502` — `buildSessionFilter`
  resolves `f.protoFilter` through `appid.ProtocolNumberLenient` and records
  `codes.InvalidArgument` on failure, with the rationale comment at `:493-498`:
  an invalid protocol would otherwise iterate to an empty list and return as a
  *successful* RPC, indistinguishable from "no such sessions" (`#3439 L2`).
- CLI: third contract, explicitly not differenced token-by-token in the issue.
  This plan differences it (sections 2 and 5).

Observable divergence at HEAD: `protocol=tcpip` answers `200` + empty list on
REST and `InvalidArgument` on gRPC. Automation cannot distinguish "no sessions"
from "bad filter" on REST. Worse, the divergence is not only about invalid
tokens: REST's matchable named set is narrower than gRPC's accepted set, so
some *valid* tokens silently undercount on REST too (section 2, rows P2-P3).

## 2. The three (actually five) contracts

There is no single "CLI contract". Four protocol-matching implementations feed
five operator surfaces:

| # | Surface | Parse / validate site | Match site | Invalid-token behavior |
|---|---------|-----------------------|------------|------------------------|
| R | REST list (`sessionsHandler`, `pkg/api/sessions.go:102`) | `buildSessionQuery` `:1351-1410`; `protocol` raw at `:1358` | `protoFilterMatches` `:1784-1792` (`EqualFold(protoName(p),f) \|\| Atoi(f)==p`; `protoName` `:1801-1810` = `ToUpper(appid.ProtocolName)`, `ICMPv6` special) | `200` + empty list (fail-open) |
| G | gRPC `GetSessions`/`ClearSessions` (`pkg/grpcapi/server_sessions.go:57`, `:1272`) | `buildSessionFilter` `:456-545`; protocol guard `:499-502` via `appid.ProtocolNumberLenient` (`pkg/appid/catalog.go:371-386`) | `protoFilterMatches` `:436-441` (same Lenient resolution) | `InvalidArgument` (fail-closed) |
| L | Local interactive CLI show/clear (`pkg/cli/cli_show_flow.go:211`, `pkg/cli/cli_clear.go:173`) | `parseSessionFilterMode` `:100-245`; protocol switch `:128-149` accepts `tcp/udp/icmp/icmpv6` + `Atoi 1-255`, else `parseErr "unknown protocol"` | direct `uint8` compare `:276` (v4) / `:321` (v6) | command fails with `parseErr` (fail-closed) |
| S | Remote `cli show security flow session` (`cmd/cli/show_flow.go:201`) | `parseFlowSessionArgs` `:57-199`; protocol via Lenient `:92-94`, forwarded upper-cased `:95` | server-side (G) | client-side error before RPC (fail-closed) |
| C | Remote `cli clear security flow session` (`cmd/cli/clear.go:166`) | **none client-side**: `req.Protocol = args[i]` raw at `:191-193` | server-side (G), via `ClearSessions`→`getReq` translation `:1344-1354` + `buildSessionFilter` `:1367` | server-side `InvalidArgument` after a round trip (fail-closed, late) |

Full-dimension divergence matrix (this is the token-by-token diff the issue
marks out of scope for itself; the CLI arm is now differenced):

| Dimension | REST (R) | gRPC (G) | Local CLI (L) | Remote show (S) / clear (C) |
|---|---|---|---|---|
| P1 invalid protocol (`tcpip`) | 200+empty | InvalidArgument | parseErr | S: client error; C: server InvalidArgument |
| P2 valid-per-G names (`sctp/ospf/egp/igmp/pim/ah/vrrp`, `junos-*` aliases) | empty success (never matches: `protoName` only renders the `#2949` SSOT set `tcp/udp/icmp/icmpv6/gre/esp/ipip/ipv6`) | accept + match | parseErr (switch has 4 names) | S: accept (Lenient), server matches |
| P3 numeric edge tokens | `Atoi`: `6`/`47`/`+6`/`007` match; `256`/`-1`/space-padded numerics match nothing, no error; space-padded names also match nothing | canonical uint `0-255`; surrounding whitespace is trimmed for names/aliases but rejected for numeric tokens; `0` = HOPOPT legitimate (`#2124` Layer G) | `Atoi 1-255`: `0` rejected, `+6`/`007` accepted; names are not trimmed | S: Lenient (= G); C: raw, server decides |
| zone | numeric `uint16` strict, 400 (`:1353`) | `uint32` + `>65535` guard (`:484-486`) | name→ID via `cr.ZoneIDs`, not-found error (`:371-373`) | S: name as typed + `resolveSessionZone` (`:214`, `#9065`); C: string, server resolves (`:1355-1366`) |
| src/dst prefix | 400 (`:1384-1397`) | InvalidArgument (`:506-519`) | parseErr (`:150-181`) | S: forwarded, server decides; C: raw, server decides |
| src/dst port | 400, `0`=any (`:1398-1407`) | InvalidArgument on `>65535`, `0`=any (`:487-492`) | `1-65535` else parseErr — **`0` is an error, not any** (`:182-197`) | S: `1-65535` else error (`:111-132`); C: same (`:197-210`) |
| nat_only | `ParseBool`, 400 (`:1362-1368`) | `bool` field | valueless flag (`:198-199`) | S/C: valueless flag |
| application | raw string, unknown app matches nothing (empty success) | same | same (`SessionMatches`) | same (forwarded) |
| interface | raw string + zone-fallback match | same | same + recorded-identity corroboration (`:482-532`) | same (forwarded) |
| source_nat_pool | not-found → 400 (`:1369-1378`) | not-found → InvalidArgument (`validate`, `:450-451`) | not-found → error (`validate`, `:368-370`) | forwarded; server decides |
| pagination/summary/sort-by | `page_size>0` cursor else offset (`:154-172`); no summary/sort params | `PageSize>0` cursor (`:141`) else limit/offset (`:840`); summary RPCs separate | `summary/brief/sort-by` local; `sort-by` restricted to `bytes\|packets` (`:232-236`); peer fetch `Limit:10000`, no `PageSize` (`:664`) | `Limit:100` (`show_flow.go:58`); `summary`/`sort-by` reject combination with filters (`:195-197`) |

Rows P2/P3/port-0/zone-by-name show the filed bug is one cell of a wider
pattern; section 4 says which cells this plan touches and why.

## 3. Honest scope / value

What shipping the filed acceptance buys: REST `protocol` becomes fail-closed
(400 + reason) like its seven sibling branches, so `200` means "query ran" on
every surface and automation can trust empty-as-empty. The fix is one branch in
one function plus tests — small, reviewable, and it deletes a documented
automation trap (success+empty vs rejection for the same logical query).

What it does NOT buy: it does not unify the valid-token match sets. After an
invalid-only fix, `protocol=sctp` with live SCTP sessions still returns them on
G/S while R returns empty and L refuses to run (row P2) — a silent undercount,
arguably worse than the invalid-token case because the token is *valid*.
Likewise `+6`, `007`, and space-padded numeric tokens keep three-way splits
until Q3 chooses a grammar; space-padded names are a separate name-trimming
case. `0` keeps the wildcard-vs-legitimate-protocol split, and `port 0`
keeps its wildcard-vs-error split. Callers who assume "same filter, same
answer" across surfaces remain wrong after Option A alone.

Why not fix every cell now: each widening is its own compat decision (section 7)
with a different owner (REST 400-vs-200; local-CLI newly accepted names;
canonical-vs-`Atoi` numeric grammar). Bundling them into one change makes the
blast radius unreviewable and couples a safe fail-closed correction to
behavior-widening ones. This plan therefore prices two options: A (fail-closed
only, resolves the filed acceptance) and B (shared ruler, resolves P1+P2+P3 for
protocol while leaving zone/port/app/interface/pagination to follow-ups).

## 4. Already-shipped context (residuals this plan builds on)

Each item landed; each leaves the specific residual named.

- `#2935`: REST match became case-insensitive + numeric
  (`sessions.go:1784-1792`; pinned by `pkg/api/README.md:2555-2561`).
  Residual: matching widened, validation never added — this issue's R cell.
- `#2949`: `appid.ProtocolName` is the render SSOT (`catalog.go:388-436`).
  Residual: render set ≠ filter-accept set on R (P2).
- `#3393`: `ipv6=41` round-trips (`catalog.go:325-330`); Lenient documented as
  belt-and-suspenders over Strict (`:356-370`); pinned by
  `pkg/appid/protocol_lenient_3439_test.go:12-34`. Residual: none on G/S; R/L
  do not use either resolver.
- `#3439 H5/L2`: remote-show strict parse (`cmd/cli/show_flow.go:48-56`) and
  gRPC `InvalidArgument` (`server_sessions.go:493-503`), pinned by
  `pkg/grpcapi/session_filter_3439_test.go:32-67` and
  `cmd/cli/show_flowsession_3439_test.go`. Residual: the R-side half — this issue.
- `#3421 M2/H4/M8`: REST prefix/port fail-closed (`sessions.go:1380-1407`),
  cursor tokens node-local (`:1820-1822`), `queryIntStrict` guards. No residual.
- `#1827 PR-3`: show/clear share one gRPC matcher
  (`server_sessions.go:1339-1354`; `pkg/grpcapi/README.md:615-619`) + SNAT-pool
  dimension. Invariant B must preserve (section 8).
- `#4792`: multi-interface zone maps (`pkg/cli/session_filter.go:59-66`,
  `populateIfaceMaps :382-399`). Invariant, untouched.
- `#5066`: clear-all guard — exactly-empty token list is the only clear-all
  (`parseClearSessionFilter :93-95`, `hasFilter :355-359`,
  `cmd/cli/clear.go:177-183`, gRPC empty-check `:1309-1313`); pinned by
  `pkg/cli/cli_clear_flow_display_reject_test.go:114-143`. Invariant B must
  preserve; the read-path change here must not alter any clear predicate.
- `#5034/#5033/#4908`: filtered totals + `-1` sentinel + CLI fallback
  (`peerSessionsTotal`, `session_filter.go:760-768`). Untouched.
- `#4983/#4650/#6960/#6928/#6987`: egress/ingress identity resolution
  (`:423-603`). Untouched; display stays stricter than filter.
- `#9899 F102`: canonical numerics on the strict path (`catalog.go:347-349`).
  Open: whether the shared ruler inherits canonical or `Atoi` (Q3).
- `#2124 Layer G`: protocol `0` (HOPOPT) legitimate (`catalog.go:300-304`).
  The shared ruler MUST accept `"0"`; L's `1-255` switch currently rejects it.
- `#9065`: remote-show zone names (`show_flow.go:68-83`). Untouched.
- `#3423 M5` + `#4920`: `include_peer` fan-out (`sessions.go:138-145`,
  `peerSessionsRequest :567-607`, page_size forward `:603-605`). Note: the
  forwarder re-reads `protocol` raw (`:571`) and relies on peer re-validation
  (`:564-566`) — with `include_peer=true`, an invalid token today yields a
  local silent-empty plus a peer `InvalidArgument`, a mixed response worth a
  test row (section 9).
- `#5318/#5433/#5880` admission, `#5454` bounded clear, `#5882` non-atomic
  clear reporting: untouched invariants (section 8).
- Fable-review-161 `sort-by` fail-open note is stale at HEAD: the show path
  validates `bytes|packets` (`session_filter.go:232-236`). No action.

## 5. Concrete design

### Blast radius (all counts at `b71c52d60`)

- `protoFilterMatches`: 2 definitions (R `:1784`, G `:436`), 4 match call
  sites (R `:1434`/`:1478`, G `:610`/`:655`).
- `ProtocolNumberLenient`: 1 definition (`catalog.go:371`), 3 production call
  sites in 2 files (G match `:437`, G validate `:500`, S validate
  `cmd/cli/show_flow.go:92`), 1 dedicated test file.
- `buildSessionQuery`: 1 definition, 1 validating caller (`sessionsHandler`,
  `:131-136`) + 1 lenient re-reader (`peerSessionsRequest`, `:567`).
- `buildSessionFilter`: 1 definition, 3 callers (`GetSessions :153`,
  legacy/cursor `:853`, `ClearSessions :1367`); `GetSessionsRequest`
  referenced from 28 files (including the protobuf schema, generated bindings,
  production callers, and tests).
- CLI parse: 3 definitions (`:79`/`:93`/`:100`), 2 production callers
  (`cli_show_flow.go:211`, `cli_clear.go:173`); `parseFlowSessionArgs` 1
  definition + 1 caller (`show_flow.go:57`, `:202`).

### Option A — REST-side validation (resolves the filed acceptance)

In `buildSessionQuery`, immediately after `:1358`, resolve the token through
the same taxonomy G uses and fail closed like the sibling branches:

```go
q.proto = r.URL.Query().Get("protocol")
if q.proto != "" {
    if _, ok := appid.ProtocolNumberLenient(q.proto); !ok {
        return q, "invalid protocol filter: " + q.proto
    }
}
```

`pkg/api/sessions.go` already imports `pkg/appid` (use at `:1452`), so no new
dependency. `writeError(w, http.StatusBadRequest, …)` at `:134` renders it.
Touched: 1 branch + tests. G/S/L/C byte-identical. P2/P3/port-0 rows unchanged
(deliberately; section 3).

### Option B — one shared ruler for match + validate (resolves P1+P2+P3)

Home: `pkg/appid` (leaf package, imports only `pkg/config`; already owns
`ProtocolNumber`, `ProtocolNumberLenient`, `ProtocolName` — no import cycle for
`pkg/api`, `pkg/grpcapi`, `pkg/cli`, `cmd/cli`, all of which import it today).

```go
// ValidateProtocolFilterToken reports whether tok is an admissible
// session-filter protocol token under the Lenient taxonomy
// (names + aliases + canonical numerics 0-255, case-insensitive),
// returning the resolved number for matchers that compare numerically.
func ValidateProtocolFilterToken(tok string) (uint8, bool)

// ProtoFilterMatches reports whether session protocol p matches filter
// tok. Unknown tokens match nothing; callers MUST validate first so an
// unparseable token surfaces instead of returning an empty success.
func ProtoFilterMatches(p uint8, tok string) bool
```

`ProtoFilterMatches` is the G `:436-441` body moved verbatim; G keeps a thin
alias or re-points its 2 match sites + 1 validate site. Migration per surface:

- R: `buildSessionQuery` validates via `ValidateProtocolFilterToken`
  (400 + reason, same string shape as A); `matchV4`/`matchV6` (`:1434`/`:1478`)
  call the shared matcher. R's private `:1784-1792` is deleted. Effect: P1
  closes AND P2 closes on R (`sctp` starts matching). `protoName` (`:1801-1810`)
  stays (rendering, not matching).
- G: alias to shared functions; behavior identical (same Lenient core).
- S: `show_flow.go:92` calls `ValidateProtocolFilterToken`; behavior identical
  (same Lenient core); keep the `ToUpper` forward (`:95`).
- L: `session_filter.go:128-149` switch becomes
  `if n, ok := appid.ValidateProtocolFilterToken(v); ok { f.proto = n; f.protoSet = true } else { parseErr }`.
  This requires a presence bit because the local `uint8` field currently uses
  `0` as "any": add `protoSet bool`, use it in both `matchesV4`/`matchesV6`
  (`:276`/`:321`), `hasFilter` (`:355-359`), and `fetchPeerSessions`
  (`:670-672`). Otherwise accepting the legitimate `protocol 0` token would
  silently become an unfiltered local/peer query. The `protoSet` bit is
  parser state only; matching remains an exact `uint8` comparison.
  Effect: L newly accepts `gre/sctp/ospf/…`, aliases, and `0` (behavior
  widening; section 7), and `+6`/`007` plus space-padded numeric tokens follow
  the shared numeric grammar (Q3 decides which). Surrounding whitespace on
  names follows Lenient's existing `TrimSpace` behavior. Matchers otherwise
  stay numeric.
- C: optional `ValidateProtocolFilterToken` at `clear.go:191-193` for early
  client-side error; server already guards. Latency-only (Q5).
- `peerSessionsRequest` (`:567-607`): unchanged shape, but its lenient comment
  (`:564-566`) becomes true for protocol too once R validates; add a test row
  for the mixed local-empty/peer-error case (section 9).

### Recommendation

Ship B, with A's one-branch R validation as the first commit so the filed
acceptance lands even if the L-widening or grammar questions (Q2-Q4) kill the
rest. B without L is still coherent (R/G/S share the ruler; L keeps its
narrower documented switch) but leaves two matchers — say so in the commit
trailer rather than claiming full unification.

## 6. API preservation

- R invalid-token `200`+empty → `400` + `invalid protocol filter: <tok>`: the
  intended break. Same `writeError` envelope as the seven sibling branches, so
  no new body schema; only the status code and reason string change, and only
  for tokens that previously produced a provably meaningless empty list.
  Valid tokens (including `TCP`, `6`, `gre`, `47`, `ipv6`, `0`) stay `200`.
  Risk: automation that asserts `200` unconditionally now sees `400` (Q1).
- G: no wire or status change under A or B (same Lenient core, same
  `InvalidArgument` sites). `GetSessionsRequest.Protocol` stays `string`
  (`xpf.pb.go:2918`); no proto bump.
- L under B: previously-erroring inputs (`protocol gre|sctp|…`, `protocol 0`)
  start succeeding. That is widening, not tightening: scripts asserting the
  old parse error break (Q4). Under A: no L change.
- S: no behavior change under B (Lenient → Lenient). C under B-with-client-guard:
  same error, earlier (no RPC); scripts matching on timing could notice (Q5).
- Peer wire (`PeerSessions`, `peerSessionsRequest`): field set unchanged;
  values now pre-validated on R, still re-validated by the peer.

## 7. Hidden invariants (must hold after the change)

1. Fail-closed, never widening: every invalid-input branch records
   `inputErr`/`parseErr`/400-reason instead of zeroing a predicate
   (G `:462-468` comment states the clear-all hazard explicitly).
2. First-error retention: `setInputErr` (`:419-423`), `setParseErr`
   (`session_filter.go:259-263`) keep the first error.
3. Exactly-empty selector is the only clear-all (G `:1309-1313`, L `:93-95` +
   `:355-359`, C `:177-183`). The read-path change MUST NOT alter any clear
   predicate or guard.
4. Shared show/clear matcher on G (`:1339-1354`, `#1827 PR-3`): any helper move
   keeps both paths on the same function.
5. Zone matches on either side (`IngressZone==z || EgressZone==z`) on all
   surfaces (R `:1431`, G `:609`, L `:266`).
6. Key ports are network order; `ntohs` exactly once at compare
   (R `:1443-1448`, G `:614-619`, L `:285-291`).
7. Multi-interface zone maps are caller-populated (`populateIfaceMaps`,
   `#4792`); clear path MUST call it (`:377-381`).
8. Ingress recorded-identity + zone corroboration; egress FIB-precise else
   zone fallback; display stricter than filter (`:423-603`, `#4983/#6987`).
9. Cursor tokens are node-local and never forwarded (R `:601-602`, G `:753-755`).
10. Admission limiter acquired once at the external boundary, lease re-stamped
   for nested fan-out (`sessionsHandler :122-129`, `#5880`).
11. `Protocol 0` (HOPOPT) is legitimate input (`#2124` Layer G); the shared
    ruler accepts `"0"`.
12. Local CLI protocol `0` is representable only with a presence bit:
    `protoSet=true` must gate matching, `hasFilter`, and peer serialization;
    checking `proto != 0` would turn HOPOPT into an unfiltered query.
13. Forward-only matching: `IsReverse` rows skipped before predicates
    (R `:1428`, L `:266`ff, G matchers).

## 8. Four-class risk table

| Class | Risk | Likelihood × Impact | Mitigation | Residual |
|---|---|---|---|---|
| Correctness / Security | R-400 validation accidentally widens a predicate (e.g. validating but still matching on failure) or touches a clear path, degrading a filtered clear toward clear-all | Low × Critical | Validate-then-return before any match state (A sketch returns `q` + reason, caller 400s before iteration); B keeps G's shared matcher single; A does not touch clear code, while B's local parser/matcher/`hasFilter`/peer-serialization edits are covered by the `#5066` empty-only-clear-all guard and protocol-0/SCTP clear rows; regression rows in section 9 pin the guard | Shared-matcher coupling remains: future dimension edits must still update show+clear together (existing `#1827` hazard, unchanged) |
| Correctness / Security | L widening under B newly matches sessions an operator did not intend (e.g. `protocol 0` now selects HOPOPT rows in a filtered `clear`) | Medium × High | Widening is still conjunctive narrowing (more tokens accepted, each match exact); clear path already requires `validate()` + `hasFilter()`; add clear-path test: `protocol sctp` clears only SCTP rows | Operator surprise on previously-erroring commands now succeeding (Q4 compat note) |
| Compatibility / Operational | Automation asserting R-`200` on arbitrary tokens now gets `400`; dashboards scraping `protocol=<typo>` flip from empty-graph to error | Medium × Medium | Same envelope as 7 sibling 400s; reason string includes the token; valid-token traffic unaffected; document in release note; Q1 decides warn-then-enforce vs single-shot | Single-shot 400 is observable in status-code metrics by design |
| Compatibility / Operational | Numeric-grammar standardization (`+6`/`007`/whitespace) breaks scripts on one surface or another (Q3) | Medium × Low | Q3 picks canonical-vs-`Atoi` BEFORE code; conformance matrix (section 9) pins the chosen grammar on all 5 surfaces at once | One surface's historical leniency is deliberately retired |
| Performance | Shared-helper move adds per-session cost on the conntrack-walk hot path | Low × Low | Lenient resolution stays per-request (validate once), per-session match stays one `uint8` compare on L and one Lenient call on R/G as today; R match cost unchanged in shape (EqualFold+Atoi → Lenient lookup) | None expected; no new per-row allocation (matchers stay predicate-only) |
| Modularity / Maintainability | Third copy of the matcher survives (B-without-L), or R/G drift again after the move | Medium × Low | Delete R's private `:1784-1792` in the same commit that re-points it; alias (not copy) on G; `pkg/api/README.md:2555-2561` contract paragraph updated in the same commit | L's numeric-compare shape legitimately differs (parse-time resolution); documented, not duplicated logic |

## 9. Test plan

### Unit (REST — the filed acceptance)

In `pkg/api` (extend the `sessions_pagination_test.go:152`
`TestRESTSessionPrefixPortFilters` table style; no existing protocol rows —
that absence is the gap):

- Valid → `200` + narrowed list: `tcp`, `TCP`, ` tcp `, `6`, `47`, `gre`, `GRE`,
  `ipv6`, `sctp`, `0`, `255`.
- Invalid → `400` + `invalid protocol filter: <tok>`: `tcpip`, `bogus`,
  `256`, `-1`, ` 6`, `""` (empty = no filter → `200`, control row), `+6`,
  `007` (expected per Q3 decision — write the row, assert the decided grammar).
- Mixed: invalid protocol + `include_peer=true` → `400` before any fan-out
  (no partial local-empty/peer-error response).

### Contract-conformance matrix (the anti-regression core)

One shared token vector asserted on all five surfaces in the same test run
(per-surface table tests over a copied vector; if B lands, the vector lives
next to the shared helper):

| Token | R (status) | G (code) | L (err/proto) | S (err/`req.Protocol`) | C (client/server) |
|---|---|---|---|---|---|
| `tcp` | 200 match | OK match | proto=6 | `TCP` | server OK |
| `TCP` | 200 match | OK match | proto=6 | `TCP` | server OK |
| `6` | 200 match | OK match | proto=6 | `6`→`6` | server OK |
| `gre`/`47` | 200 match pre-B/A/B | OK match | parseErr pre-B / proto=47 post-B | accept | server OK |
| `sctp` | 200 match (B) / 200 empty pre-B | OK match | parseErr pre-B / proto=132 post-B | accept | server OK |
| `ipv6` | 200 match | OK match | parseErr pre-B / proto=41 post-B | accept | server OK |
| `0` | 200 match pre-B/A/B | OK match | parseErr pre-B / proto=0 + `protoSet=true` post-B | accept | server OK |
| `tcpip`/`bogus` | 400 | InvalidArgument | parseErr | client error | server InvalidArgument (client error if C-guard lands) |
| `256`/`-1` | 400 | InvalidArgument | parseErr | client error | server InvalidArgument |
| ` tcp ` | 200 match (B) / 200 empty-for-whitespace-name pre-B | OK match | parseErr pre-B / proto=6 post-B | accept | server OK |
| ` 6` | 200 empty pre-B / 400 post-B | InvalidArgument | parseErr | client error | server InvalidArgument |
| `+6`/`007` | per Q3 | per Q3 | per Q3 | per Q3 | per Q3 (server) |
| `""` (absent) | 200 unfiltered | OK unfiltered | no predicate | no predicate | N/A (empty = clear-all guard path, separate tests) |

Pre-B vs post-B cells that differ are marked; the matrix is committed with the
decided grammar so a revert of any single surface goes red.

### Regression guards (existing suites that must stay green, unmodified)

- `pkg/grpcapi/session_filter_3439_test.go:32-67` (L2 reject/accept matrix),
  `session_filter_test.go:93` (match matrix), `session_filtered_total_5034`
  (totals parity), `sessions_iterator_error`, `sessions_top_5319`.
- `pkg/appid/protocol_lenient_3439_test.go:12-34`.
- `pkg/cli/session_filter_test.go:209-222` (hasFilter guard, numeric 47),
  `session_filter_multi_iface_4792` (`#4792`),
  `cli_clear_flow_display_reject_test.go:114-143` (`#5066`).
- `cmd/cli/show_flowsession_3439_test.go`, `selector_type_and_scope_9065_test.go`.
- New: filtered-clear-with-bad-protocol errors on G and never clears
  (delete-widening guard for the shared matcher).

### Non-goals for verification

No fuzz corpus (noted gap in `session_filter_3439`, out of scope), no
live-cluster runs in this round (parent sequences smoke at merge time).

## 10. Out of scope

- Zone-by-name on REST, port-`0` wildcard-vs-error split, `application` /
  `interface` fail-open-to-empty on all surfaces (same hazard class, separate
  filings if Q6 says expand — not this change).
- Pagination / summary / sort-by unification (`Limit:100` vs `Limit:10000`,
  `PageSize` gating per `docs/log/9060.md:30-33`, remote combo rule
  `show_flow.go:195-197`).
- The 18/26 arithmetic the issue explicitly excludes (Limits section).
- Any `*.proto` / wire change (field stays `string`).
- Strict-vs-Lenient taxonomy change itself (`#3393` settlement stands; Q2 only
  decides which side the shared ruler takes).

## 11. Open questions (each states its kill condition)

- Q1 — R `200→400` shippability: does any supported automation assert `200`
  for arbitrary `protocol` values, requiring a warn-then-enforce window (e.g.
  one release emitting a deprecation header before the 400)? If yes and the
  window is unacceptable, PLAN-KILL single-shot A; re-plan as phased rollout.
- Q2 — Lenient as the shared ruler: R adopting the full Lenient accept set
  turns today's silent undercount (`sctp` → empty) into new matches — a
  behavior widening beyond the filed invalid-token complaint. Should the ruler
  instead be Strict (narrowing G first), or is Lenient-set widening on R the
  intended semantic? If Strict wins, PLAN-KILL B-as-drawn; re-plan around
  narrowing G/S first.
- Q3 — Numeric grammar: names and aliases are always `TrimSpace`-normalized by
  the Lenient resolver, so surrounding whitespace on `tcp` is not part of the
  numeric decision. For numeric tokens, should the shared helper use canonical
  (`ParseCanonicalUint`, rejecting `+6`/`007`/numeric whitespace, `#9899 F102`)
  or `Atoi` (accepting `+6`/`007`, today's R/L behavior)? If neither can be
  chosen without breaking a supported script corpus, PLAN-KILL the shared
  numeric path; scope B to names only.
- Q4 — L widening: is newly accepting `gre/sctp/…` + `0` on the on-box CLI in
  scope for a REST-filed issue? If the CLI owner rejects widening, PLAN-KILL
  B-with-L; ship B-without-L (R/G/S share the ruler, L documents its narrower
  switch) or A-only.
- Q5 — C client-side guard: server-side `InvalidArgument` already fails
  closed; a client-side check only saves a round trip. Is that diff worth it,
  or churn? If churn, PLAN-KILL the C half of B (keep C raw + server-guarded).
- Q6 — `application`/`interface` fail open to empty on ALL five surfaces
  today — the same "empty or bad?" hazard class. Is protocol-only convergence
  an arbitrary line? If the hazard class must ship together, PLAN-KILL this
  scope; re-file as all-dimensions validation.
- Q7 — Provenance: `#2935` (R match) + `#3439` (G/S strictness) already own
  two thirds of this story. Should this land as a follow-up commit series on
  those issues rather than a standalone `#10486` change? If process says fold,
  PLAN-KILL the standalone plan; re-plan as `#3439`-R-residual.
