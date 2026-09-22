# 10486: REST / gRPC / CLI session-filter contract convergence

Status: DRAFT v3 — plan only, no production code.
Base: `origin/master b71c52d60`; worktree `.claude/worktrees/10486-session`,
branch `fix/10486-session-filter-contracts`. All `file:line` refs re-pinned at
that HEAD (the issue's evidence pin `1a6952b` is stale).
Review lineage: v1 (`44f4e10bc`) drew two concurring PLAN-NEEDS-MAJOR verdicts
(direction sound, Lenient/canonical ruler, staged A-then-B; bug real). v2
(`366ee44f8`) folded the adjudication (Q2 closed, Q3 canonical, A/B tables,
parse-once `(proto,hasProto)` ruler, `hasProto` peer-clear site) and drew a
split delta: READY / STILL-NEEDS-WORK on executable-test gaps. This v3 folds
the delta-2 residuals only: proto-41 + proto-7 fixture rows, URL-encoded REST
rows, explicit conformance matrix, SCTP selective-clear test, G wiring proof,
C serialization-only scope, and citation/mechanical-wording corrections. No
production code in this round; v3 goes to delta-3 (single confirming pass).

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
from "bad filter" on REST. The divergence is wider than invalid tokens: REST's
matchable named set is narrower than gRPC's accepted set (row P2), and the
numeric grammars disagree on `+6` (row P3) — but `007` is accepted on ALL five
surfaces today (canonical digits-only, no leading-zero ban), not a split.

## 2. The three (actually five) contracts

There is no single "CLI contract". Four protocol-matching implementations feed
five operator surfaces:

| # | Surface | Parse / validate site | Match site | Invalid-token behavior |
|---|---------|-----------------------|------------|------------------------|
| R | REST list (`sessionsHandler`, `pkg/api/sessions.go:102`) | `buildSessionQuery` `:1351-1410`; `protocol` raw at `:1358` | `protoFilterMatches` `:1784-1792` (`EqualFold(protoName(p),f) \|\| Atoi(f)==p`; `protoName` `:1801-1810` = `ToUpper(appid.ProtocolName)`, `ICMPv6` special) | `200` + empty list (fail-open) |
| G | gRPC `GetSessions`/`ClearSessions` (`pkg/grpcapi/server_sessions.go:57`, `:1272`) | `buildSessionFilter` `:456-546`; protocol guard `:499-502` via `appid.ProtocolNumberLenient` (`pkg/appid/catalog.go:371-386`) | `protoFilterMatches` `:436-441` (same Lenient resolution) | `InvalidArgument` (fail-closed) |
| L | Local interactive CLI show/clear (`pkg/cli/cli_show_flow.go:211`, `pkg/cli/cli_clear.go:173`) | `parseSessionFilterMode` `:100-246`; protocol switch `:128-149` accepts `tcp/udp/icmp/icmpv6` + `Atoi 1-255`, else `parseErr "unknown protocol"` | direct `uint8` compare `:276` (v4) / `:321` (v6) | command fails with `parseErr` (fail-closed) |
| S | Remote `cli show security flow session` (`cmd/cli/show_flow.go:201`) | `parseFlowSessionArgs` `:57-199`; protocol via Lenient `:92-94`, forwarded upper-cased `:95` | server-side (G) | client-side error before RPC (fail-closed) |
| C | Remote `cli clear security flow session` (`cmd/cli/clear.go:166`) | **none client-side**: `req.Protocol = args[i]` raw at `:191-193` | server-side (G), via `ClearSessions`→`getReq` translation `:1344-1354` + `buildSessionFilter` `:1367` | server-side `InvalidArgument` after a round trip (fail-closed, late) |

Full-dimension divergence matrix (all cells verified at HEAD):

| Dimension | REST (R) | gRPC (G) | Local CLI (L) | Remote show (S) / clear (C) |
|---|---|---|---|---|
| P1 invalid protocol (`tcpip`) | 200+empty | InvalidArgument | parseErr | S: client error; C: server InvalidArgument |
| P2 valid-per-G names (`sctp/ospf/egp/igmp/pim/ah/vrrp`, `junos-*` aliases) | empty success (never matches: `protoName` only renders the `#2949` SSOT set `tcp/udp/icmp/icmpv6/gre/esp/ipip/ipv6`) | accept + match | parseErr (switch has 4 names) | S: accept (Lenient), server matches |
| P3a `+6` (the lone numeric match-split) | 200+match (`Atoi`) | InvalidArgument (canonical rejects sign) | accept (Atoi 1-255) | S: client error; C: server InvalidArgument |
| P3b `007` (NO split — accepted everywhere) | 200+match (`Atoi`→7) | OK match (canonical digits-only, no leading-zero ban, `ParseCanonicalUint` `compiler_applications.go:1070-1082`) | accept (Atoi→7) | S: accept; C: server OK |
| P3c space-padded numerics (`" 6"`) | 200+empty (`Atoi` rejects whitespace → matcher false, no validation) | InvalidArgument (canonical rejects; names trim at `catalog.go:310` but numerics take the untrimmed original at `:349`) | parseErr | S: client error; C: server InvalidArgument |
| P3d space-padded names (`" tcp "`) | 200+empty (`EqualFold` untrimmed + `Atoi` fails) | OK match (Lenient trims names) | parseErr (no trim) | S: accept (trim), forwards upper-cased; C: server decides |
| `0` (HOPOPT, legitimate per `#2124` Layer G, `catalog.go:300-304`) | 200+match (`Atoi`→0) | OK match | parseErr (`1-255` switch) | S: accept; C: server OK |
| zone | numeric `uint16` strict, 400 (`:1353`) | `uint32` + `>65535` guard (`:484-486`) | name→ID via `cr.ZoneIDs`, not-found error (`:371-373`) | S: name as typed + `resolveSessionZone` (`:214`, `#9065`); C: string, server resolves (`:1355-1366`) |
| src/dst prefix | 400 (`:1384-1397`) | InvalidArgument (`:506-519`) | parseErr (`:150-181`) | S: forwarded, server decides; C: raw, server decides |
| src/dst port | 400, `0`=any (`:1398-1407`) | InvalidArgument on `>65535`, `0`=any (`:487-492`) | `1-65535` else parseErr — **`0` is an error, not any** (`:182-197`) | S: `1-65535` else error (`:111-132`); C: same (`:197-210`) |
| nat_only | `ParseBool`, 400 (`:1362-1368`) | `bool` field | valueless flag (`:198-199`) | S/C: valueless flag |
| application | raw string, unknown app matches nothing (empty success) | same | same (`SessionMatches`) | same (forwarded) |
| interface | raw string + zone-fallback match | same | same + recorded-identity corroboration (`:482-532`) | same (forwarded) |
| source_nat_pool | not-found → 400 (`:1369-1378`) | not-found → InvalidArgument (`validate`, `:450-451`) | not-found → error (`validate`, `:368-370`) | forwarded; server decides |
| pagination/summary/sort-by | `page_size>0` cursor else offset (`:154-172`); no summary/sort params | `PageSize>0` cursor (`:122`) else limit/offset (`:840`); summary RPCs separate | `summary/brief/sort-by` local; `sort-by` restricted to `bytes\|packets` (`:232-236`); peer fetch `Limit:10000`, no `PageSize` (`:664`) | `Limit:100` (`show_flow.go:58`); `summary`/`sort-by` reject combination with filters (`:195-197`) |

## 3. Honest scope / value

What shipping the filed acceptance (Option A) buys: REST `protocol` becomes
fail-closed (400 + reason) like its seven sibling branches, so `200` means
"query ran" on every surface and automation can trust empty-as-empty. The fix is
one branch in one function plus tests — small, reviewable, and it deletes the
documented automation trap (success+empty vs rejection for the same query).

Two honest carve-outs vs the v1 framing:

1. A is NOT invalid-only. A's guard is `ProtocolNumberLenient`, i.e. canonical
   numerics (Q3, decided). `+6` previously produced meaningful matches on R
   (`Atoi`), so under A it flips `200-match → 400` — intended per the decided
   grammar, but a tightening, not a meaningless-empty cleanup. v1's "only …
   for tokens that previously produced a provably meaningless empty list" was
   false as written.
2. A creates validated-yet-empty. P2 tokens (`sctp`) and whitespace names
   (`" tcp "`) PASS A's validation (Lenient accepts) but still match nothing on
   R (matcher unchanged) — a documented residual until B, pinned as A-expected
   in §9 rather than left implicit.

What A does NOT buy: it does not unify the valid-token match sets
(`protocol=sctp` with live SCTP sessions still returns them on G/S while R
returns validated-empty and L refuses to run), and `port 0` keeps its
wildcard-vs-error split. Callers who assume "same filter, same answer" across
surfaces remain wrong after A alone.

Why not fix every cell now: each widening is its own compat decision (§6) with
a different owner (REST 400-vs-200; local-CLI newly accepted names;
canonical-vs-`Atoi` numeric grammar — now decided). Bundling them into one
change makes the blast radius unreviewable and couples a safe fail-closed
correction to behavior-widening ones. This plan therefore prices two options:
A (fail-closed + canonical numerics, resolves the filed acceptance) and B
(shared ruler, resolves P1+P2+P3 for protocol while leaving
zone/port/app/interface/pagination to follow-ups).

## 4. Already-shipped context (residuals this plan builds on)

Each item landed; each leaves the specific residual named.

- `#2935`: REST match became case-insensitive + numeric
  (`sessions.go:1784-1792`; pinned by `pkg/api/README.md:2555-2561`).
  Two halves, two lineages: the SHIPPED match-fix leaves the R-validation
  residual (A-lineage, this issue's R cell); the PROPOSED-but-not-shipped
  "extract `protoFilterMatches` into a shared helper used by REST, CLI, and
  gRPC" is exactly Option B (B-lineage, Q7 trailers).
- `#2949`: `appid.ProtocolName` is the render SSOT (`catalog.go:388-437`).
  Residual: render set ≠ filter-accept set on R (P2).
- `#3393`: `ipv6=41` round-trips through the STRICT resolver
  (`catalog.go:325-330`); Lenient is documented as belt-and-suspenders over
  Strict (`:356-370`: "for the current tables this function is equal to
  ProtocolNumber"), pinned by `pkg/appid/protocol_lenient_3439_test.go:12-34`.
  Residual: none on G/S — Lenient == Strict behaviorally at HEAD (Q2 closed);
  R/L do not use either resolver.
- `#3439 H5/L2`: remote-show strict parse (`cmd/cli/show_flow.go:48-56`) and
  gRPC `InvalidArgument` (`server_sessions.go:493-503`), pinned by
  `pkg/grpcapi/session_filter_3439_test.go:32-67` and
  `cmd/cli/show_flowsession_3439_test.go`. Residual: the R-side half — this
  issue, i.e. Option A is the `#3439`-R-residual (Q7 trailers).
- `#3606` + `#3679`: canonical-uint doctrine — commit-time numerics route
  through `ParseCanonicalUint` (`parseCanonicalPort`,
  `compiler_applications.go:1097-1099`), and diagnostic/REST numerics follow
  (`queryIntStrict`, `pkg/api/api.go:185-201`). Settles Q3 for canonical.
- `#9899 F102`: strict path routes numeric protocol tokens through
  `ParseCanonicalUint` (`catalog.go:347-349`). No residual; Q3 inherits it.
- `#3421 M2/H4/M8`: REST prefix/port fail-closed (`sessions.go:1380-1407`),
  cursor tokens node-local (`:1820-1822`), `queryIntStrict` guards. No residual.
- `#1827 PR-3`: show/clear share one gRPC matcher
  (`server_sessions.go:1339-1354`; `pkg/grpcapi/README.md:615-619`) + SNAT-pool
  dimension. Invariant B must preserve (§7).
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
- `#2124 Layer G`: protocol `0` (HOPOPT) legitimate (`catalog.go:300-304`).
  The shared ruler MUST accept `"0"`; L's `1-255` switch currently rejects it,
  and L's `uint8` field needs a presence bit to represent it (§5).
- `#9065`: remote-show zone names (`show_flow.go:68-83`). Untouched.
- `#3423 M5` + `#4920`: `include_peer` fan-out (`sessions.go:138-145`,
  `peerSessionsRequest :567-607`, page_size forward `:603-605`). Note: the
  forwarder re-reads `protocol` raw (`:571`) and relies on peer re-validation
  (`:564-566`) — pre-change, `include_peer=true` with an invalid token yields
  local silent-empty plus a peer `InvalidArgument`. A's validation must replace
  that mixed response with local 400 before fan-out and zero peer calls (§9).
- `#5318/#5433/#5880` admission, `#5454` bounded clear, `#5882` non-atomic
  clear reporting: untouched invariants (§7).
- Fable-review-161 `sort-by` fail-open note is stale at HEAD: the show path
  validates `bytes|packets` (`session_filter.go:232-236`). No action.

## 5. Concrete design

### Blast radius (all counts at `b71c52d60`)

- `protoFilterMatches`: 2 production definitions (R `:1784`, G `:436`), 4
  production match call sites (R `:1434`/`:1478`, G `:610`/`:655`).
- `ProtocolNumberLenient`: 1 definition (`catalog.go:371`), 3 production call
  sites in 2 files (G match `:437`, G validate `:500`, S validate
  `cmd/cli/show_flow.go:92`), 1 dedicated test file.
- `buildSessionQuery`: 1 production definition, 1 production validating
  caller (`sessionsHandler`, `:131-136`) + 1 production lenient re-reader
  (`peerSessionsRequest`, `:567`).
- `buildSessionFilter`: 1 production definition, 3 production callers
  (`GetSessions :153`, legacy/cursor `:853`, `ClearSessions :1367`);
  `GetSessionsRequest` is referenced from exactly 28 files (protobuf schema,
  generated bindings, production callers, tests).
- CLI parse: 3 definitions (`:79`/`:93`/`:100`), 2 production callers
  (`cli_show_flow.go:211`, `cli_clear.go:173`); `parseFlowSessionArgs` 1
  production definition + 1 production caller (`show_flow.go:57`, `:202`).
- L `f.proto` census (repo-wide grep, `\.proto\b|proto:` in `pkg/cli`):
  prod writes at parse `:132,134,136,138,144`; prod gates at `:276` (matchesV4),
  `:321` (matchesV6), `:356` (hasFilter), `:670` (fetchPeerSessions),
  `cli_clear.go:654-670` (buildPeerClearRequest); test sites at
  `session_filter_test.go:183,220` and
  `session_filter_ingress_identity_4983_test.go:361`. Unrelated namesakes
  excluded by audit: `builtinApp.proto` (`app_resolve.go:27-41`, app catalog),
  display `e.proto` fields (`cli_show_flow.go:834`, `top_talkers_bound_8597.go`),
  `formatQueryProtoTail` (`testpolicy`), `protoNameToID` (security-log event
  rendering only, `cli_show_security_log.go:121-155`).
- G `protoFilter` census: production field/gates at
  `server_sessions.go:375,478,493-501,610,655`, plus direct test literals
  in `pagination_test.go:158-171` and helper assertions in
  `session_filter_test.go:93` and `session_filter_3439_test.go:62-66`.
  B changes the field to `(proto uint8, hasProto bool)`, parses once before
  matching, and changes the `server_sessions.go:478` `hasFilters` predicate
  from raw-string presence to `f.hasProto`; protocol-only requests, including
  proto 0, therefore remain filtered. Every listed test must build or assert
  the parsed pair; no raw-string matcher call remains.

### Option A — REST-side validation (resolves the filed acceptance)

In `buildSessionQuery`, immediately after `:1358`, resolve the token through
the Lenient taxonomy (names + aliases + canonical numerics — Q3 decided, not
open) and fail closed like the sibling branches:

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
Touched: 1 branch + tests. G/S/L/C byte-identical. Effects beyond invalid-only
(deliberate, Q3-decided): `+6` flips `200-match → 400` on R; P2/whitespace-name
tokens become validated-yet-empty on R (no 400, still no match until B); `007`
stays `200` (accepted, pre-existing); port-0 row unchanged.

### Option B — one shared ruler for match + validate (resolves P1+P2+P3)

Home: `pkg/appid` (leaf package, imports only `pkg/config`; already owns
`ProtocolNumber`, `ProtocolNumberLenient`, `ProtocolName` — no import cycle for
`pkg/api`, `pkg/grpcapi`, `pkg/cli`, `cmd/cli`, all of which import it today).
Ruler = the Lenient seam (behaviorally == Strict at HEAD per
`catalog.go:362-370` + `#3393` closure; Q2 closed — there is no Strict
alternative with different behavior).

```go
// ParseProtocolFilterToken resolves one non-empty session-filter token through
// the Lenient taxonomy (names + aliases + canonical numerics 0-255,
// case-insensitive; surrounding whitespace trimmed for names, rejected for
// numerics). It returns the numeric protocol and ok=false for an invalid
// token. The empty token returns (0, false); callers keep the tok != "" guard
// so absence remains "no filter" rather than an invalid request.
//
// This is the only string parse inside a given matcher path. Each
// sessionQuery/sessionFilter builder calls it once and stores the resulting
// (proto uint8, hasProto bool) pair.
func ParseProtocolFilterToken(tok string) (proto uint8, ok bool)

// ProtoFilterMatches compares a session protocol with a parsed filter pair.
// It MUST NOT parse a string or call ProtocolNumberLenient; builders validate
// once before iteration and callers use hasProto to preserve protocol 0.
func ProtoFilterMatches(p uint8, filterProto uint8, hasProto bool) bool
```

`ParseProtocolFilterToken` delegates to `ProtocolNumberLenient`, preserving
the source-resolved Lenient==Strict behavior at HEAD. `ProtoFilterMatches` is
the G `:436-441` numeric comparison moved to `pkg/appid`; G keeps a thin alias
or re-points its 2 match sites. Migration per surface:

- R: `sessionQuery` stores `proto uint8` plus `hasProto bool`. In
  `buildSessionQuery`, guard the raw query value for empty, call
  `ParseProtocolFilterToken` once, and return the HTTP-400 reason on `ok=false`.
  `matchV4`/`matchV6` (`:1434`/`:1478`) call
  `ProtoFilterMatches(key.Protocol, q.proto, q.hasProto)`. R's private
  string parser `:1784-1792` is deleted. Effect: P1 closes AND
  P2/whitespace-name mismatches close on R (`sctp`/`" tcp "` start matching).
  `protoName` (`:1801-1810`) stays (rendering, not matching).
- G: `sessionFilter` stores `proto uint8` plus `hasProto bool` instead of the
  raw `protoFilter string`. `buildSessionFilter` calls
  `ParseProtocolFilterToken(req.Protocol)` once when non-empty, stores the
  parsed pair before computing `hasFilters`, records `inputErr` on `ok=false`,
  and computes `hasFilters` from `hasProto` at `server_sessions.go:478` (not
  from a raw string) before either matcher runs. Both matchers (`:610`/`:655`)
  call `ProtoFilterMatches(key.Protocol, f.proto, f.hasProto)`. The shared
  show and clear paths therefore use the same parsed pair and retain the
  exactly-empty clear-all guard.
- S: `show_flow.go:92` calls `ParseProtocolFilterToken` once for client-side
  validation; keep the raw token upper-cased on the wire (`:95`) so the server
  re-parses its own request once. Behavior remains Lenient/canonical.
- L: `session_filter.go:128-149` switch becomes
  `if n, ok := appid.ParseProtocolFilterToken(v); ok { f.proto = n; f.hasProto = true } else { parseErr }`.
  This requires a presence bit because the local `uint8` field currently uses
  `0` as "any": add `hasProto bool`, gate ALL FIVE read sites on it —
  `matchesV4` (`:276`), `matchesV6` (`:321`), `hasFilter` (`:355-359`),
  `fetchPeerSessions` (`:670-672`), AND `buildPeerClearRequest`
  (`cli_clear.go:654-672`, serialize `"0"` for proto 0). The fifth site is
  safety-critical: without it, `clear security flow session protocol 0` would
  clear filtered-locally but forward `Protocol:""` — an otherwise-empty peer
  request the peer interprets as clear-all (`server_sessions.go:1309-1313`;
  the translator's own hazard comment at `cli_clear.go:637-642`).
  Migration step: repo-wide `f.proto`/`hasProto` grep (census above) to catch
  every gate; `protoNameToID` (`proto.go:42-57`) stays untouched (security-log
  rendering only, caller-audited). Effect: L newly accepts
  `gre/sctp/ospf/…`, aliases, `0`, whitespace-names (behavior widening, §6);
  `+6`/space-padded numerics follow canonical (tightening on `+6`, Q3-decided).
  Matchers otherwise compare numeric pairs only.
- C: UNCHANGED (Q5 default-omit). Server-side `InvalidArgument` already fails
  closed; a client guard would change error text/shape/timing, not just
  latency — deliberate contract change needing its own spec, not worth it.
- `peerSessionsRequest` (`:567-607`): unchanged shape, but its lenient comment
  (`:564-566`) becomes true for protocol too once R validates; add a test row
  asserting invalid protocol + `include_peer=true` returns 400 before any
  peer call (zero peer calls). The mixed local-empty/peer-error response is
  pre-change behavior documented in §4, not a target.
- Stale Lenient-vs-Strict comments asserting a live difference MUST be
  corrected in the same B commit (exact replacements):
  1. `server_sessions.go:431-432`: replace the display-only-name premise with
     "Lenient equals the strict ProtocolNumber for the current tables
     (#3393 closed the last gap, `ipv6`=41) and is retained as the stable
     filter seam, so a future render-only name still resolves here".
  2. `session_filter_3439_test.go:53-57`: replace the strict-rejection
     premise with "post-#3393 both resolvers accept it; the Lenient-seam guard
     must accept it AND the matcher must match proto-41 sessions".
  3. `docs/junos-cli-reference.md:128-135`: replace the one-way-name premise
     with "the resolver equals the strict resolver for the current tables
     (#3393 closed the one-way gap for `ipv6`=41) and is retained as the
     stable filter seam".
- Doc updates in the same B commit: `junos-cli-reference.md:75` filter list
  (`protocol tcp|udp|icmp` → the accepted Lenient set incl. names/0-255 +
  canonical-numeric note); `pkg/api/README.md:2555-2561` contract paragraph
  (validation + shared ruler).

B touch list (B-with-L, exhaustive): `pkg/appid/catalog.go` (2 new fns);
`pkg/api/sessions.go` (validate + 2 match sites, delete `:1784-1792`);
`pkg/api/sessions_pagination_test.go` (matrix fixture + REST A/B rows);
`pkg/grpcapi/server_sessions.go` (field, parse/hasFilters, alias/re-point +
stale comment 1); `pkg/grpcapi/pagination_test.go` (direct filter literals);
`pkg/grpcapi/session_filter_test.go` (parsed-pair matcher matrix);
`pkg/grpcapi/session_filter_3439_test.go` (stale comment 2, direct matcher
assertions, + extended validation sets);
`pkg/cli/session_filter.go` (field/parse + 4 gates);
`pkg/cli/cli_clear.go` (5th gate);
`pkg/cli/cli_clear_bounded_4886_test.go` (SCTP selective-clear proof);
`pkg/cli/session_filter_test.go` (literals + new rows);
`pkg/cli/session_filter_ingress_identity_4983_test.go` (`:361` presence-bit literal);
`cmd/cli/show_flow.go` (`:92` re-point, no behavior change);
`cmd/cli/show_flowsession_3439_test.go` (S matrix rows);
`cmd/cli/clear_session_filter_10486_test.go` (new C serialization-only test);
`docs/junos-cli-reference.md` (`:75` + stale paragraph 3);
`pkg/api/README.md` (contract paragraph). `cmd/cli/clear.go` explicitly NOT
touched (Q5 omit).

### Recommendation

Ship B, with A's one-branch R validation as the first commit so the filed
acceptance lands even if the L-widening question (Q4) kills the rest. B without
L is still coherent (R/G/S share the ruler; L keeps its narrower documented
switch) but leaves two matchers — say so in the commit trailer rather than
claiming full unification. Commit trailers split per Q7: A carries
`Refs #3439` (the `#3439`-R-residual follow-up); B carries
`Refs #2935-direction` (the proposed-not-shipped helper) plus standalone
`#10486` justification and the CLI-owner sign-off for the L half.

## 6. API preservation

- R invalid-token `200`+empty → `400` + `invalid protocol filter: <tok>`: the
  intended break. Same `writeError` envelope as the seven sibling branches, so
  no new body schema; only the status code and reason string change.
  Carve-outs (Q3-decided, NOT meaningless-empty cleanups): `+6` flips
  `200-match → 400`; all other previously-matching valid tokens (`TCP`, `6`,
  `007`, `gre`, `47`, `ipv6`, `0`) stay `200`. Risk: automation asserting
  `200` unconditionally now sees `400` (Q1).
- G: no wire or status change under A or B (same Lenient core, same
  `InvalidArgument` sites). `GetSessionsRequest.Protocol` stays `string`
  (`xpf.pb.go:2918`); no proto bump.
- L under B (honest): numeric-using scripts are UNAFFECTED (L already accepts
  `1-255` incl. `47`/`89`, pinned by `session_filter_test.go:176-181,219-222`).
  Widening: names (`gre/sctp/…`, aliases), `0`, whitespace-names — previously
  parseErr, now accepted. Tightening: `+6` flips accept → parseErr (canonical).
  Plus the `junos-cli-reference.md:75` doc update. Scripts asserting the old
  parse errors break either way (Q4 owner gate). Under A: no L change.
- S: no behavior change under B (Lenient → Lenient).
- C: no change under default-omit (Q5). IF a guard were ever added, it would
  emit client-side text (e.g. S-shaped `unknown protocol %q`) instead of
  today's server text (`invalid session filter: invalid protocol %q` after the
  `:1374` wrap, printed via `clear.go:224-227`) — a text+shape+timing change
  needing compat tests, which is why omit is the default.
- Peer wire (`PeerSessions`, `peerSessionsRequest`): field set unchanged;
  values now pre-validated on R, still re-validated by the peer.

## 7. Hidden invariants (must hold after the change)

1. Fail-closed, never widening: every invalid-input branch records
   `inputErr`/`parseErr`/400-reason instead of zeroing a predicate
   (G `:462-468` comment states the clear-all hazard explicitly).
2. First-error retention: `setInputErr` (`:419-423`), `setParseErr`
   (`session_filter.go:259-263`) keep the first error.
3. Exactly-empty selector is the only clear-all (G `:1309-1313`, L `:93-95` +
   `:355-359`, C `:177-183`). Option A touches no clear code; option B's local
   parser/matcher/`hasFilter`/serializer edits preserve the guard (§9 pins it).
4. Shared show/clear matcher on G (`:1339-1354`, `#1827 PR-3`): any helper move
   keeps both paths on the same function.
5. Zone matches on either side (`IngressZone==z || EgressZone==z`) on all
   surfaces (R `:1431`, G `:607`, L `:266`).
6. Key ports are network order; `ntohs` exactly once at compare
   (R `:1443-1448`, G `:619-624`, L `:285-291`).
7. Multi-interface zone maps are caller-populated (`populateIfaceMaps`,
   `#4792`); the clear path MUST call `f.populateIfaceMaps(c)` at
   `pkg/cli/cli_clear.go:235` before matching. `session_filter.go:377-381`
   documents the requirement; the call-site citation is the executable
   invariant.
8. Ingress recorded-identity + zone corroboration; egress FIB-precise else
   zone fallback; display stricter than filter (`:423-603`, `#4983/#6987`).
9. Cursor tokens are node-local and never forwarded (R `:601-602`, G `:753-755`).
10. Admission limiter acquired once at the external boundary, lease re-stamped
    for nested fan-out (`sessionsHandler :122-129`, `#5880`).
11. `Protocol 0` (HOPOPT) is legitimate input (`#2124` Layer G); the shared
    ruler accepts `"0"`.
12. Local CLI protocol `0` is representable only with a presence bit:
    `hasProto=true` must gate matching (`:276`, `:321`), `hasFilter`
    (`:355-359`), AND both peer serializers (`fetchPeerSessions :670-672`,
    `buildPeerClearRequest cli_clear.go:654-672` — the latter emitting
    `Protocol:"0"`, never empty); checking `proto != 0` anywhere in this chain
    would turn HOPOPT into an unfiltered query or a peer clear-all.
13. Forward-only matching: `IsReverse` rows never match. R and G skip inside
    the matchers (R `:1428`, `:1473`; G `:604`, `:649`); L skips at the
    iteration call sites before matching (`cli_show_flow.go:411,538,791,804`,
    `cli_clear.go:353,401,491,529`) — `matchesV4/V6` themselves assume
    forward-only input.
14. Protocol strings are parsed once per surface request: R's
    `sessionQuery`, G's `sessionFilter`, and L's `sessionFilter` each cache
    `(proto uint8, hasProto bool)` before iteration; no matcher reparses a
    string or re-runs Lenient lookup per session.

## 8. Four-class risk table

| Class | Risk | Likelihood × Impact | Mitigation | Residual |
|---|---|---|---|---|
| Correctness / Security | R-400 validation accidentally widens a predicate (e.g. validating but still matching on failure) or touches a clear path, degrading a filtered clear toward clear-all | Low × Critical | Validate-then-return before any match state (A sketch returns `q` + reason, caller 400s before iteration); B keeps G's shared matcher single; A does not touch clear code, while B's local parser/matcher/`hasFilter`/peer-serialization edits are covered by the `#5066` empty-only-clear-all guard and protocol-0/SCTP clear rows; regression rows in section 9 pin the guard | Shared-matcher coupling remains: future dimension edits must still update show+clear together (existing `#1827` hazard, unchanged) |
| Correctness / Security | L widening under B newly matches sessions an operator did not intend; the `buildPeerClearRequest` site in particular could forward an empty `Protocol` for proto 0 (peer clear-all) | Medium × High | All FIVE `f.proto` gates migrate to `hasProto` (repo-wide grep census in §5 — no sixth site exists outside audited-unrelated namesakes); widening is still conjunctive narrowing (more tokens accepted, each match exact); clear path already requires `validate()` + `hasFilter()`; §9 adds the protocol-0 peer-forward test (`"0"`, never empty) + `protocol sctp` selective-clear test | Operator surprise on previously-erroring commands now succeeding, plus `+6` tightening (accept → parseErr; Q4 compat note) |
| Compatibility / Operational | Automation asserting R-`200` on arbitrary tokens now gets `400`; dashboards scraping `protocol=<typo>` flip from empty-graph to error | Medium × Medium | Same envelope as 7 sibling 400s; reason string includes the token; previously-matching valid tokens unaffected EXCEPT `+6` (decided flip, Q3); document in release note; Q1 decides single-shot vs phased (precedent: single-shot) | Single-shot 400 is observable in status-code metrics by design |
| Compatibility / Operational | Canonical numeric grammar retires R/L leniencies (`+6` accepted today on both; space-padded numerics silently empty on R) | Medium × Low | Grammar decided BEFORE A (Q3: canonical per #3606/#3679/#9899-F102 + REST zone/port `ParseUint` precedent); the explicit §9 token matrix pins changed and control cells across R/G/L/S/C, including `007`, L/C protocol-0 forwarding, explicit-empty/absent, and C whitespace-name server matching | R/L `+6`-accepting scripts must drop the sign; one surface's historical leniency deliberately retired |
| Performance | Shared-helper move adds per-session cost on the conntrack-walk hot path | Low × Low | Every builder calls `ParseProtocolFilterToken` once per request; R/G/L matchers compare the cached `(proto,hasProto)` pair per session with no per-row string parse or Lenient lookup. No new per-session allocation; S/C are unchanged | None expected; matcher work stays one numeric comparison |
| Modularity / Maintainability | Third copy of the matcher survives (B-without-L), or R/G drift again after the move | Medium × Low | Delete R's private `:1784-1792` in the same commit that re-points it; alias (not copy) on G; `pkg/api/README.md:2555-2561` contract paragraph + 3 stale Lenient-vs-Strict comments updated in the same commit | No duplicate string parser; all matchers consume the same parsed pair |

## 9. Test plan

### Fixture (new, dedicated)

`newProtocolMatrixDP()` in `pkg/api/sessions_pagination_test.go` (NEW helper;
`multiSessionDP` is left untouched because cursor/parity count assertions pin
its 4 rows): v4 TCP×2 (dports 80/443), UDP, GRE(47), SCTP(132), HOPOPT(0),
protocol 7, protocol 41, and 255; v6 UDP + ICMPv6. Every row is forward-only
with distinct tuples, and every changed numeric/name row below has a non-zero
exact count on both offset and cursor paths.

### Unit table A-expected (REST — the filed acceptance; must pass after A alone)

Extend `TestRESTSessionFilterFailsClosed` (`sessions_pagination_test.go:195`)
with 400-rows: `protocol=tcpip`, `protocol=bogus`, `protocol=256`,
`protocol=-1`, `protocol=%206` (decoded `" 6"`), and `protocol=%2B6`
(decoded `"+6"`). These tests build raw query strings, so whitespace MUST be
encoded as `%20` and the plus sign as `%2B`; assert the decoded error reason
contains `+6`. New `TestRESTProtocolFilterMatrixA` over the matrix DP:

| Token / query encoding | A-expected | Why |
|---|---|---|
| `tcp`,`TCP`,`6`,`47`,`gre`,`GRE`,`ipv6` (41), `0`,`255`,`007` (7) | 200 + exact non-zero narrowed counts | validate + match; protocol 41 and 7 fixture rows make `ipv6`/`007` red-on-revert rather than vacuous |
| `sctp`, `%20tcp%20` (decoded `" tcp "`) | 200 + EMPTY (pinned residual) | validate (Lenient) but matcher unchanged — documents what B closes |
| `tcpip`,`bogus`,`256`,`-1`, `%206` (decoded `" 6"`), `%2B6` (decoded `"+6"`) | 400 + `invalid protocol filter: <decoded token>` | decided grammar; `%2B6` must not become a space |
| absent `protocol` | 200 unfiltered | control |
| explicit `protocol=` | 200 unfiltered | explicit-empty equals absent on REST |
| invalid protocol + `include_peer=true` | 400 before any fan-out, zero peer calls | validation (`sessionsHandler :132-136`) runs before fan-out — no partial local-empty/peer-error response |

Red-on-revert: validator branch removed → every 400-row returns 200; matcher
narrowed → exact counts flip. The `sctp`/`%20tcp%20` empty-rows fail (become
matches) exactly when B lands — they are specified to move to the B table in
the B commit, so neither commit can silently drift.

### Unit table B-expected (REST — added/adjusted by the B commit)

Same test, B rows: `sctp` → exact SCTP count; `%20tcp%20` (decoded
`" tcp "`) → exact TCP count; all A rows unchanged. A test asserting
B-expectations fails pre-B by construction (committed WITH B).
### Five-surface conformance matrix (post-A/B contract)

This is the shared matrix referenced by §8. Each cell names the observable
proof; direct helper tables are not substitutes for the endpoint/builder
rows. `R(A/B)` records the staged REST result, while G/L/S/C record the final
B contract:

| Token / wire spelling | R | G | L | S | C | Proof |
|---|---|---|---|---|---|---|
| `tcp`, `6` | A/B 200 + exact TCP count | exact match | exact match | parse/forward + exact match | raw/forward; paired G exact match | R offset+cursor counts; G endpoint; C serialization + G |
| `sctp` | A 200 empty; B exact SCTP count | exact match | B exact match | parse/forward + exact match | raw/forward; paired G exact match | R A/B rows; G/L endpoint rows; C serialization + G |
| `ipv6` (41) | A/B 200 + non-zero proto-41 count | exact match | B exact match | parse/forward + exact match | raw/forward; paired G exact match | fixture row makes all counts non-vacuous; C serialization + G |
| `007` (7) | A/B 200 + non-zero proto-7 count | exact match | B exact match | accept + forward + exact match | raw `007`; paired G exact match | protocol-7 fixture; C serialization + G |
| `+6` (wire `%2B6`) | A/B 400, reason contains `+6` | InvalidArgument | parseErr | client parseErr | raw `+6`; paired G InvalidArgument | encoded REST row; G/S/C status tests |
| `" 6"` (wire `%206`) | A/B 400 | InvalidArgument | parseErr | client parseErr | raw `" 6"`; paired G InvalidArgument | encoded REST row; status tests |
| `" tcp "` (wire `%20tcp%20`) | A empty; B exact TCP count | exact match after Lenient trim | B exact match | accept/forward + exact match | raw whitespace reaches G; paired server trims and exact-matches TCP | R A/B rows; G wiring; C raw-forward + G endpoint |
| `0` | A/B 200 + exact HOPOPT count | exact match | B exact match with `hasProto` | accept/forward + exact match | raw `"0"`; paired G exact match | protocol-0 peer/show/clear tests |
| `tcpip` | A/B 400 | InvalidArgument | parseErr | client parseErr | raw `tcpip`; paired G InvalidArgument | fail-closed status rows |
| absent / explicit empty | 200 unfiltered | no protocol filter | no protocol filter | no protocol field | no protocol field; paired clear-all only when every selector is empty | absent vs `protocol=` controls and clear-all guard |

### Executable cell map (one test + observable + red-on-revert per surface)

- R-400: `TestRESTSessionFilterFailsClosed` += rows above. Observable: HTTP
  status + reason substring. Red-on-revert: as above.
- R-match: `TestRESTProtocolFilterMatrixA(/B)` over the matrix DP, asserted on
  BOTH offset and cursor paths. Observable: per-token session counts.
  Red-on-revert: count flip on any matcher/validator revert.
- G-validate: extend `TestSessionFilterRejectsInvalidProtocol`
  (`session_filter_3439_test.go:27-68`): add `007` to the valid set, `+6` and
  `" 6"` to the InvalidArgument set, `" tcp "` to the valid set. Observable:
  `validate()` status/code. The existing FAIL-ON-REVERT header (`:8-13`)
  protects the invalid-token guard; already-valid compatibility rows are
  not themselves claimed as production red-on-revert coverage.
- G-match: extend the `ProtoFilterMatches` matrix (`session_filter_test.go:93`)
  with parsed-pair cases `(7,7,true)→true`, `(6,7,true)→false`, and
  `(6,0,false)→true`. Observable: helper boolean only; the direct table is
  not production wiring proof.
- G-wiring: NEW endpoint/builder coverage uses a separate
  `sessionRowsGRPCDP` fake, not `viewFaultGRPCDP`: explicit
  `v4Sessions`/`v6Sessions` maps drive callback-based
  `IterateSessions`/`IterateSessionsV6` (with `IsLoaded` true), and each map
  has matching and nonmatching rows for the exercised protocols. Send
  `"tcp"`, `"6"`, `" tcp "`, `"0"`, `"sctp"`, `"ipv6"`, and `"007"` through
  `buildSessionFilter`/the session endpoint and assert exact selective counts
  across both v4 and v6 rows, plus `f.hasProto`/`f.proto` and
  `f.hasFilters=true` for protocol-only filters (including proto 0).
  Red-on-revert: forgetting to store the parsed number/bit or changing
  `hasFilters` to raw-string/`proto!=0` produces an unfiltered count or drops
  the protocol-only predicate. `viewFaultGRPCDP` remains only for
  validation/zero-clear tests that reject before iteration; this fake is the
  production call-site proof for both G matchers and complements, rather than
  duplicates, the helper truth table.
- G-clear: NEW `TestClearSessionsRejectsInvalidProtocol` (same file family,
  `newViewServer` + `viewFaultGRPCDP` fixture per `:28`): `ClearSessions`
  with `Protocol:"tcpip"` → `InvalidArgument` (`invalid session filter: …`
  wrap) + zero cleared. Red-on-revert: validate bypass → clear proceeds.
- L-parse/match: extend `session_filter_test.go` parse table: post-B accepts
  `gre/sctp/ipv6/0/007/" tcp "` (with `hasProto=true` asserted), rejects `+6`
  (parseErr) and still rejects `ospfx`; match assertions run `matchesV4/V6`
  against fixed `SessionKey`s for protocols 7, 41, and 0 (observable:
  boolean, NOT the `proto` field — a field assertion would pass even if the
  matcher ignored it).
- L-peer-show: `fetchPeerSessions` protocol-0 case: parsed `protocol 0` →
  forwarded `req.Protocol == "0"`. Observable: serialized request field.
  Red-on-revert: `hasProto` gate omitted → `""`.
- L-peer-clear: NEW `TestBuildPeerClearRequestProtocolZero` mirroring
  `TestBuildPeerClearRequestProtocolCoverage` (`:171-188`): `{0, "0"}` row
  plus parse-path integration (`parse ["protocol","0"]` → request `"0"`,
  never empty). Red-on-revert: 5th-site omission forwards `""` = peer
  clear-all — the exact F4 hazard.
- S: extend `show_flowsession_3439_test.go` tables (`:41-44` pattern): `+6`
  and `" 6"` join the want-error set; `007` joins the accept set (with
  `req.Protocol` value assertion). Observable: error presence + forwarded
  value. The existing FAIL-ON-REVERT header protects the invalid-token
  rejection; valid compatibility rows are not claimed as shared-ruler wiring
  proof because the same behavior exists at HEAD.
- L-selective-clear: NEW coverage in
  `pkg/cli/cli_clear_bounded_4886_test.go` seeds forward SCTP and TCP rows,
  runs `clear security flow session protocol sctp`, and asserts only SCTP
  rows (and their companions) are deleted while TCP remains. Observable:
  deletion set. Red-on-revert: the local shared parser/matcher or a missing
  `hasProto` gate changes the deleted set; this fulfills the SCTP selective
  clear promised by §8.
- C: NEW `cmd/cli/clear_session_filter_10486_test.go` is
  serialization-only: a capturing fake asserts raw forwarding for `tcp`, `6`,
  `sctp`, `ipv6`, `+6`, `" 6"`, `tcpip`, `" tcp "` (quoted whitespace-name),
  `007`, and `0`; malformed port remains
  rejected client-side (`clear.go:197-210`). It MUST NOT claim that the fake
  proves server rejection or fail-closed behavior. The G-clear endpoint test
  above is the paired proof of server `InvalidArgument`; C's observable is
  only captured request shape and client-side error. Red-on-revert:
  forwarding dropped → empty request assertion catches the peer-clear-all
  shape.

REST test ownership is intentionally parallel: the existing
`rest_filter_failclosed_test.go:286-314` suite remains an unmodified guard for
the shipped GRE/case/numeric contract, while the new
`sessions_pagination_test.go` fixture owns the A/B token matrix across offset
and cursor paths without disturbing `multiSessionDP`'s pinned four-row counts.

### Regression guards (precisely scoped)

MUST stay green UNMODIFIED: `session_filtered_total_5034` (totals parity),
`sessions_iterator_error`, `sessions_top_5319`,
`protocol_lenient_3439_test.go:12-34`,
`TestRESTSessionCursorPagination` (untouched `multiSessionDP` counts),
`rest_filter_failclosed_test.go` (`TestRESTProtocolFilterCaseInsensitiveNumeric`
`:286-314` valid-token 200 rows + GRE DP),
`cli_clear_flow_display_reject_test.go:114-143` (`#5066`),
`selector_type_and_scope_9065_test.go`, `session_filter_test.go:219-222`
(numeric-47 parse still sets `proto=47`; this existing guard remains
unmodified), `TestSessionFilterParseErrors`
(`ospfx`/missing-value/bad-port still parseErr).

REQUIRE mechanical updates under B-with-L (named, not "unmodified"):
`pkg/grpcapi/pagination_test.go:158,167` (direct filter literals become
`proto` + `hasProto:true`, preserving pagination assertions);
`pkg/cli/session_filter_test.go:171-188` (literals gain `hasProto:true`;
add `{0,"0"}` row) and
`pkg/cli/session_filter_ingress_identity_4983_test.go:361` (direct
`f.proto = 17` gains `f.hasProto = true`, else the mismatch-reject assertion
inverts). `session_filter_test.go:219-222` remains unchanged and only guards
numeric-47 parsing; proto-0 and peer-clear wiring are covered by the new rows.

### Non-goals for verification

No fuzz corpus (noted gap in `session_filter_3439`, out of scope), no
live-cluster runs in this round (parent sequences smoke at merge time).

## 10. Out of scope

- Zone-by-name on REST, port-`0` wildcard-vs-error split (kept as-is).
- `application`/`interface` validation: Q6 CLOSED — protocol-only is the
  principled increment (closed static taxonomy validatable centrally vs
  config-defined open strings; follow-up filings, not this change).
- Pagination / summary / sort-by unification (`Limit:100` vs `Limit:10000`,
  `PageSize` gating per `docs/log/9060.md:30-33`, remote combo rule
  `show_flow.go:195-197`).
- Any `*.proto` / wire change (field stays `string`).

## 11. Open questions (each states its kill condition)

- Q1 — R `200→400` rollout: source evidence supports single-shot, but owner
  confirmation remains REQUIRED before implementation. All seven sibling
  fail-closed validations in this handler shipped as single-shot 400 with no
  warn phase (zone, prefix/port, limit/offset, page_size, nat_only,
  include_peer), and no deprecation-header machinery exists in `pkg/api`
  (`[Dd]eprecat` search: only two unrelated comments). Warn-then-enforce would
  new machinery for a one-cell fix. The owner gate is whether supported
  external automation asserts 200 on arbitrary tokens. If none, Q1 closes;
  if a corpus surfaces AND phased rollout is unacceptable, PLAN-KILL
  single-shot A and re-plan phased.
- Q2 — CLOSED as source-resolved (no kill branch). The strict and lenient
  resolvers are behaviorally IDENTICAL at HEAD: `catalog.go:362-370` ("for the
  current tables this function is equal to ProtocolNumber"), the strict
  `ipv6=41` reverse at `:325-330`, and the full render set (`:416-437`) all
  reversing at `:311-330` — #3393 closed the last gap. Ruler = the Lenient
  seam (retained per #3393's rationale so a future render-only name still
  resolves). There is no Strict-narrowing alternative; the v1 kill branch is
  deleted. The 3 stale comments asserting a live difference are corrected as
  specified B-touch-list edits (§5).
- Q3 — DECIDED: canonical, now (no kill branch). `ParseCanonicalUint`
  (`compiler_applications.go:1070-1082`) requires a bare run of ASCII digits —
  `007`→7 accepted, `+`/whitespace rejected. `007` is therefore accepted on
  ALL five surfaces today (pre-existing agreement, needs no decision — v1's
  four `007` claims are corrected throughout). Canonical aligns commit
  doctrine (#3606), diagnostics (#3679 `queryIntStrict`), the strict resolver
  (#9899 F102), and REST zone/ports (`ParseUint` rejects signs,
  `api.go:165-175`); choosing `Atoi` would re-split filters from commit
  grammar AND widen G (which rejects `+6` today). Disclosed cost: `+6` flips
  `200-match → 400` on R under A and accept → parseErr on L under B.
- Q4 — L widening: open ONLY for CLI-owner sign-off (genuine scope question).
  Honest statement: numeric-using scripts are unaffected (L already accepts
  `1-255` incl. `47`/`89`, pinned by `session_filter_test.go:176-181,219-222`);
  widening = names (`gre`/`sctp`/aliases), `0`, whitespace-names; tightening =
  `+6` (canonical); plus the `junos-cli-reference.md:75` doc update. Owner
  question: accept that package, or ship B-without-L (R/G/S share the ruler, L
  documents its narrower switch — coherent fallback, stated in the trailer)?
  If the owner vetoes widening AND deems B-without-L incoherent, PLAN-KILL B
  and ship A-only.
- Q5 — C client guard: default OMIT (reversible only with exact-text spec).
  Server-side `InvalidArgument` already fails closed; a client guard changes
  error text (`unknown protocol %q` a la `show_flow.go:93` vs today's server
  `invalid session filter: invalid protocol %q` after the `:1374` wrap),
  shape, and timing — not "same error, earlier". If retained despite this, the
  kept text MUST be specified (`unknown protocol %q`, matching S) with compat
  tests asserting scripts keyed on today's server text still behave.
- Q6 — CLOSED, no expansion (no kill branch). The protocol-only line is
  PRINCIPLED, not arbitrary: protocol has a closed static taxonomy decidable
  centrally (Lenient: names + 0-255), while application names are
  config-defined open strings compared by case-exact equality AFTER per-session
  resolution (`SessionMatches`, `runtime.go:223-228` — "unknown" is undecidable
  up front, and unresolved sessions legitimately match), and interface names
  are config + FIB/zone-fallback open strings with parent/unit prefix semantics
  (`ifaceMatches`, `session_filter.go:404-409`). Validating those needs
  config-aware existence checks with different failure modes — separate
  filings per the issue's own Limits.
- Q7 — SPLIT trailers (no kill branch). Option A lands as the
  `#3439`-R-residual follow-up (same guard idiom, same rationale lineage;
  trailer `Refs #3439` + `#10486`). Option B re-opens #2935's
  proposed-not-shipped helper direction AND widens L beyond any filed issue
  (trailer `Refs #2935-direction` + standalone `#10486` justification + Q4
  CLI-owner sign-off). The A-first-commit-then-B sequencing already implements
  this; the trailers just label it.
