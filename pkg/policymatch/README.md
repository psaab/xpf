# pkg/policymatch

Single operator-side security-policy simulator shared by every
`match-policies` surface:

- REST `GET /api/v1/security/match` (`pkg/api` `matchPoliciesHandler`)
- gRPC `MatchPolicies` (`pkg/grpcapi`)
- gRPC `ShowText` `test-policy:` topic (`pkg/grpcapi` `showTestPolicy`) — the
  backing handler for the operational `test policy` CLI command
- CLI `show security match-policies` and `test policy` (`pkg/cli`)

Each surface is a THIN adapter: it parses/validates inputs and renders the
verdict, then delegates the matching to `policymatch.Match`.

It also holds the policy **shadow / redundancy lint** behind
`request security policies check`, for the same reason and by the same rule:

- CLI `request security policies check` (`pkg/cli` `handleRequestSecurityPolicies`)
- gRPC `ShowText` `policies-check` topic (`pkg/grpcapi` `showPoliciesCheck`) —
  what the REMOTE `cli` binary runs

Both the analysis (`AnalyzePolicyShadowing`) and its operator-facing rendering
(`RenderPolicyCheck`) are shared. Sharing only the analysis would leave each
surface owning its own header line, empty-result sentence and nil-config
wording — three strings that must agree for the command to mean the same thing
on either surface, with nothing to notice when one of them changed.

It moved here from `pkg/cli` in #8597 K47. The remote `cli` — the surface most
operators use — rejected the verb outright (`unknown request security target:
policies`) although the SSOT command tree advertises it and completion offers
it, and `pkg/grpcapi` cannot import `pkg/cli` (`pkg/cli` imports
`pkg/grpcapi`), so a server-side implementation had to be either a second copy
of the analysis or a move. `pkg/cli/policy_check_surface_agreement_8597_test.go`
pins that the two surfaces render identically.

## Port input validation (#3116)

`Match` gates a port term on `SrcPort/DstPort > 0`, so a port of `0` means
"unspecified" (no port constraint — the wildcard). That makes a malformed,
negative, or out-of-range port DANGEROUS at the adapter boundary: if it
silently coerces to `0` it becomes "match any port" and the simulator returns a
verdict for a packet that cannot exist on the wire (false confidence during
policy verification / incident response). Two shared validators close this
across every surface:

- `ValidatePort(int) error` — for the already-parsed numeric inputs (the gRPC
  `int32` field, and the REST query int after `queryIntStrict`). Accepts `0`
  (unspecified) and `1..65535`; rejects negative or `>65535`.
- `ParsePort(string) (int, error)` — for operator string tokens (the CLI
  `destination-port`/`source-port` args, the gRPC `ShowText` `test-policy:`
  `port=` token, and the remote `cli` client's `destination-port`/`source-port`
  — the remote surface was fixed in #3354 to route through `ParsePort` instead
  of a silent `strconv.Atoi` drop that coerced a malformed port to the `0`
  wildcard). An
  empty/whitespace token is unspecified `(0, nil)`; a non-empty token must parse
  and pass `ValidatePort`; a malformed (`abc`), signed (`+80`/`-80`, #3679),
  or out-of-range token is rejected. An explicit `0` is accepted as
  "unspecified" for parity with the gRPC `int32` field, where proto3 cannot
  distinguish an unset scalar from `0`.
- `ParseICMPValue(string) (*uint8, error)` — for the CLI/REST/gRPC ICMP
  `type`/`code` selector tokens. Empty/whitespace is unspecified `(nil, nil)`; a
  non-empty token must be a canonical unsigned decimal in `0..255`; malformed,
  signed (`+8`/`-8`, #3679), or out-of-range is rejected.
- #3679: `ParsePort` and `ParseICMPValue` route their non-empty token through
  `config.ParseCanonicalUint` — the same canonical-form primitive the #3606
  commit-time and Rust dataplane port parsers use — so a signed spelling
  (`strconv.Atoi` accepted `+80` as `80`) that the config grammar and dataplane
  now reject can no longer be accepted on a diagnostic surface. This closes the
  commit-vs-diagnostic split that made automated policy verification green for a
  token the platform rejects.

This is applied at ALL FOUR simulator surfaces (matching the thin-adapter list
above), so "all surfaces validate the port" is literally true:

- REST `matchPoliciesHandler` — `queryIntStrict` (malformed/negative) +
  `ValidatePort` (range) → HTTP 400;
- gRPC `MatchPolicies` — `ValidatePort` on the `int32` source/dest port →
  `InvalidArgument`;
- gRPC `ShowText` `test-policy:` (`showTestPolicy`) — `ParsePort` on the `port=`
  token → an "invalid port" diagnostic in the handler output (the same way a bad
  src/dst IP is reported);
- CLI `test policy` + `show security match-policies` (local `pkg/cli`) AND the
  remote `cli` client (`cmd/cli`) — `ParsePort` → a command error.

A VALID port (`1..65535`) and an ABSENT port behave exactly as before; only an
explicitly-invalid port newly errors. Coverage: `port_test.go` (helpers),
`pkg/api/rest_filter_failclosed_test.go`, `pkg/grpcapi/server_cluster_test.go`
(`MatchPolicies` + `ShowText` `test-policy:`), `pkg/cli/policymatch_port_test.go`,
and `cmd/cli/testpolicy_port_test.go`.

## Protocol input validation (#3108)

`matchApp` short-circuits to "match any application" only for the genuine
match-any cases (`len(apps)==0`, or a policy term of `application any`); a
protocol-constrained application term is NOT short-circuited by an empty `proto`
(#3323) — it is resolved through the protocol gate and fails closed for an
omitted/unresolvable protocol, exactly like the runtime. That still leaves an
unvalidated protocol token DANGEROUS at the adapter boundary in exactly the way
an unvalidated port is: a non-empty but unresolvable protocol (an operator typo
like `tcpp`, an unknown name, or an out-of-range number like `999`) is never
rejected by the matcher — it simply fails closed against every
protocol-constrained term, masking the typo as a default-policy verdict instead
of surfacing the error. One shared validator closes this:

- `ValidateProtocol(string) error` — an empty/whitespace token is "unspecified"
  (no protocol constraint — the wildcard, unchanged); a non-empty token must
  resolve via `appid.ProtocolNumber` (a known name/alias `tcp`/`udp`/`icmp`/
  `ospf`/... or a numeric `0..255`); an unknown name or out-of-range/non-numeric
  value is rejected. There is no `any` protocol keyword — omit the token for the
  wildcard (the runtime constrains the protocol dimension only when a resolvable
  protocol is supplied). A single string validator suffices for every surface,
  since each accepts the protocol as a string `matchApp` resolves identically by
  name or number (unlike ports, which arrive both as a numeric gRPC field and as
  operator strings).

This is applied at ALL FOUR simulator surfaces (mirroring the #3116 port wiring):

- REST `matchPoliciesHandler` — `ValidateProtocol(protocol)` → HTTP 400;
- gRPC `MatchPolicies` — `ValidateProtocol(req.Protocol)` → `InvalidArgument`;
- gRPC `ShowText` `test-policy:` (`showTestPolicy`) — `ValidateProtocol` on the
  `proto=` token → an "invalid protocol" diagnostic in the handler output (the
  same way a bad port/src/dst is reported);
- CLI `test policy` + `show security match-policies` (local `pkg/cli`) AND the
  remote `cli` client (`cmd/cli`) — `ValidateProtocol` → a command error.

A VALID protocol (name or `0..255`) and an ABSENT protocol behave exactly as
before; only an explicitly-invalid protocol newly errors. Coverage:
`protocol_test.go` (helper), `pkg/api/rest_filter_failclosed_test.go`,
`pkg/grpcapi/server_proto_validation_test.go` (`MatchPolicies` + `ShowText`
`test-policy:`), `pkg/cli/policymatch_protocol_test.go`, and
`cmd/cli/testpolicy_protocol_test.go`.

## Selector grammar strictness (#3696)

The value validators above (#3116 port, #3108 protocol, #3284 icmp, #1711 IP)
are only reached when the OUTER selector grammar actually delivers the token to
them. Before #3696 each of the four CLI surfaces hand-maintained its own
`for i := range args { switch args[i] {...} }` loop, and all four shared the two
fail-OPEN defects the session-filter parser hit and #3439 (H5) fixed strictly:

- a value-taking selector present WITHOUT a following value was guarded by
  `if i+1 < len(args)` with no else, so a trailing selector left the field at its
  zero/empty wildcard — `... destination-port` (no value) evaluated ALL
  destination ports;
- the switch had no `default:` arm, so an UNKNOWN/misspelled selector token (and
  its value) were both silently skipped — `... protcol tcp` dropped both tokens
  and yielded an any-protocol verdict.

Because the shared matcher treats a zero port / empty protocol / nil icmp-type
as "no constraint", either defect silently WIDENED the query: the operator got a
permit/deny verdict for a BROADER set of traffic than they typed.

The usage text was already a shared SSOT (#3628); the PARSING is now too:

- `ParseSelectorArgs(args []string) (SelectorArgs, error)` — the single strict
  grammar for the space-separated `from-zone <z> to-zone <z> [source-ip <ip>]
  [destination-ip <ip>] [source-port <p>] [destination-port <p>]
  [protocol <name|number>] [icmp-type <n>] [icmp-code <n>]` token vector. A
  value-taking selector with no value (or an explicit-empty value — M01) errors
  `selector "X" requires a value` (a `takeValue` helper mirroring
  `cmd/cli/show.go` `parseFlowSessionArgs`); an unknown token errors
  `unknown selector "X"` (default arm); every value routes through the existing
  `ParsePort` / `ParseICMPValue` / `ValidateProtocol` / `net.ParseIP` validators.
  A field left at its zero value therefore means the operator OMITTED it (legit
  wildcard), never "present but silently dropped". `SelectorArgs.Query()` builds
  a `policymatch.Query` (empty IP → nil `net.IP` wildcard) for the local/gRPC
  in-process surfaces.

This is applied at ALL FOUR CLI surfaces (mirroring the #3116 / #3108 wiring)
plus the gRPC text bridge:

- CLI `test policy` + `show security match-policies` (local `pkg/cli`) AND the
  remote `cli` client (`cmd/cli`) — `ParseSelectorArgs` → a command error before
  any RPC;
- gRPC `ShowText` `test-policy:` (`showTestPolicy`) — the server-boundary sibling
  hardened directly: a comma segment lacking `key=value`, an unknown key, or an
  explicit-empty typed value (`port=`, indistinguishable from "key absent" under
  the old `ParsePort("") == (0, nil)`) is reported as a `malformed selector
  segment` / `unknown selector` diagnostic instead of being silently skipped. A
  bare `test-policy:` (no params) still falls through to the missing-from/to-zone
  diagnostic.

A VALID query behaves exactly as before; only a missing value, an unknown
selector, or an explicit-empty value newly errors. The #3628 usage tail now
documents the strict failure. Coverage: `selector_args_3696_test.go` (the shared
primitive), `pkg/cli/query_strictness_3696_test.go`,
`cmd/cli/query_strictness_3696_test.go`, and
`pkg/grpcapi/server_testpolicy_strictness_3696_test.go` (red-on-revert on every
surface).

## The surface #3042 missed (#3103)

The original #3042 consolidation routed the REST/gRPC `MatchPolicies` and CLI
`match-policies`/`test policy` paths through this package but left the gRPC
`ShowText` `test-policy:` handler (`grpcapi.showTestPolicy`) on its own pre-#3042
bespoke matcher (`matchShowPolicyAddr`/`matchShowPolicyApp`). That handler is
what the remote `cli` binary's `test policy` command actually drives, so a remote
operator could still be told `Default deny` while the dataplane permits under
`default-policy permit-all`, or miss a predefined-app / global / literal-CIDR /
feed-backed match. #3103 made `showTestPolicy` a thin adapter too (passing the
daemon's live feed overlay via `Server.feedOverlayFn`, mirroring `MatchPolicies`)
and deleted the bespoke helpers. Its rendered output format is unchanged except
the formerly hard-coded `Default deny` line now reflects the configured
default-policy (`Default permit`/`Default deny`/`Default reject`).

## Verdict scope and identity (#3331)

A match-policies answer of "policy X matched" is ambiguous: duplicate policy
names are legal across different from-zone/to-zone pairs and the global scope
(Junos), so a name alone cannot be mapped back to the runtime policy, the
session-table policy ID, or the policy-deny/permit audit record. `Result` (and
the REST `MatchPoliciesResult` / gRPC `MatchPoliciesResponse` it feeds) therefore
carries the matched policy's full identity:

- `Global` — true when the match came from a `policy global` rule rather than a
  zone-pair rule.
- `FromZone` / `ToZone` — the SCOPE of the matched policy. For a zone-pair policy
  these are the surrounding `from-zone`/`to-zone` stanza; for a global policy
  they are its optional `match from-zone`/`match to-zone` scope (#3148), empty
  meaning the global policy applies to every zone (rendered `any`).
- `PolicyID` — the stable runtime/RT_FLOW/session-table policy ID, computed by
  the SSOT `dataplane/userspace.RuntimePolicyIDs` (the same span-accumulated
  namespace the dataplane write side and the `show policies` Index column use,
  #3063). `Match` resolves this map once up front and stamps the ID by the
  matched policy's `[policySetID, sliceIndex]` coordinates (a global policy's
  `policySetID` is `len(cfg.Security.Policies)`), so a verdict cross-references
  the session table / audit log even when policy names collide across scopes.
- `RuleID` (#3668) — the stable `<from>-><to>/<name>` rule identity the
  inventory (`GetPolicies`), the snapshot, and the event path share, computed by
  the SSOT `dataplane/userspace.StablePolicyRuleID`. `PolicyID` is the runtime,
  reorder-fragile numeric id; `RuleID` is the stable join key an operator uses to
  tie a simulator hit to the inventory row / logs / tests even after a policy
  reorder. A matched GLOBAL policy uses `junos-global->junos-global/<name>`
  exactly like the inventory global rows — `matchedResult` remaps the global
  branch's match-SCOPE zones to that reserved pair so the identities line up.
- `SourceAddressExcluded` / `DestinationAddressExcluded` (#3668) — true when the
  matched policy carries Junos `source-address-excluded` /
  `destination-address-excluded`: the rule matches every address EXCEPT those in
  `SrcAddresses`/`DstAddresses`. The matcher (`matchAddr`) already inverts the
  address test correctly for the excluded side; these flags exist so the DISPLAY
  does not read backwards. Before #3668 a positive verdict against a source
  OUTSIDE an excluded set printed the excluded list with no negation marker,
  implying the match happened BECAUSE of the excluded address when the real
  reason is the opposite — unsafe for a Junos-style negated-address audit. The
  CLI renderers annotate this as `Source addresses (except): ...` via the SSOT
  `ExceptSuffix` helper.

These are meaningful only on a concrete match (`Matched == true`); the
default-policy and host-inbound verdicts leave them zero-valued.

## Why this exists (#3042)

Before #3042 each surface carried its own hand-written shadow matcher, and all
of them diverged from the runtime evaluator — so the diagnostic could report
the OPPOSITE of what the dataplane actually enforces (a dangerous bug for a
"why is this packet allowed/denied?" tool). The old matchers:

- looped only `cfg.Security.Policies` (zone-pair sets) and never consulted
  `cfg.Security.GlobalPolicies`;
- hard-coded `deny (default)` on a miss, ignoring `default-policy permit-all`;
- matched addresses with `any` + address-book names/sets only — no literal
  CIDRs, no `any-ipv4`/`any-ipv6`, no `*-address-excluded` exclusion flags, no
  feed overlay;
- matched applications against `cfg.Applications.Applications` only — so
  predefined apps (`junos-http`, ...) never matched, only one application-set
  level was expanded, and source-port terms were ignored.

## Ground truth

The semantics replicate `userspace-dp/src/policy.rs`
(`evaluate_policy_result_with_len` + `try_match_rule` + `parse_v3_literal_set`
+ `CompiledApplications`) fed by the Go snapshot builder
(`pkg/dataplane/userspace/policies.go`). Transit precedence, first-match
terminating:

1. **exact zone-pair** (both zones concrete);
2. **single-wildcard tier** (#3090) — `from-zone any to-zone <X>` and
   `from-zone <X> to-zone any`, merged in config order;
3. **both-any** (#3090) — `from-zone any to-zone any`;
4. **global** (`junos-global`), gated by the optional `match from-zone` /
   `match to-zone` scope (#3148): an empty/`any` scope applies to every zone, a
   typo'd/undefined-zone scope fails closed (matches nothing);
5. **configured default-policy**.

The entire transit block (tiers 1-4) is gated on BOTH query zones being
DEFINED (#3355), mirroring the runtime's `from_id != 0 && to_id != 0` guard
(`evaluate_policy_result_with_icmp`): an unconfigured zone name resolves to the
reserved unknown id 0 and is ineligible for zone-pair, wildcard, or global
policies, so a query naming an undefined zone falls straight through to the
default-policy instead of wrongly matching a `from-zone any`/`to-zone any`/
global rule. `zoneKnown` mirrors the runtime UNCONDITIONALLY — a zone is known
iff it is present in `Security.Zones`, with NO empty-Zones leniency: policy.rs
applies the `from_id/to_id != 0` gate on every evaluation, so a config with no
defined zones resolves every name to id 0 and matches nothing in the transit
tiers. A committed config always populates `Security.Zones`. The REST and gRPC
surfaces additionally
REJECT a missing from/to-zone (HTTP 400 / `InvalidArgument`) for parity with
the CLI, which already requires both zones (#3355 H06).

**#8318 — eligibility is symmetric, the TERMINAL ACTION is not.** Everything
above is about ELIGIBILITY and is unchanged: an unknown zone on EITHER side is
excluded from the zone-pair, wildcard and global tiers, which is what
`zoneKnown` "mirrors the runtime UNCONDITIONALLY" means. What happens AFTER that
exclusion differs by side, and the simulator used to collapse the two:

| case | dataplane | simulator (before #8318) |
|---|---|---|
| unknown **ToZone** | falls through to default-policy | default-policy — agreed |
| unknown **FromZone**, `deny-all` | Deny | Deny — agreed, coincidentally |
| unknown **FromZone**, `permit-all` | **Deny** | **Permit** — DIVERGED |

The runtime denies an unzoned INGRESS unconditionally, without consulting
default-policy (#6682, `policy.rs`: `if from_id == 0`) — Junos does not pass
transit on an interface in no zone, and screens were already skipped for it. It
deliberately does NOT do the same for the egress side: denying on `to_id` "would
risk black-holing a correctly-configured path to fix a case that has not been
shown to occur" (#6713 is the cited precedent, a MAC-less xfrmi egress resolving
to 0 for an unrelated reason).

Because `deny-all` is the default default-policy, both sides denied and the
divergence was invisible. It mattered on the surface an operator uses to VERIFY
policy before trusting it: a `permit-all` box reported PERMIT for a flow the
dataplane drops, so the operator concluded the policy was right and looked
elsewhere.

The FROM arm now returns `Result{UnzonedIngress: true, Action: PolicyDeny}`.
`DefaultUsed` is deliberately **false** there — its contract is "Action is the
configured default-policy", and this deny overrides it; reporting true would
render "deny (default)" and name a default that produced no such thing.
`UnzonedIngress` exists for the same reason `HostInboundUnmatched` does: the
verdict is otherwise indistinguishable from a default-deny in operator-facing
output. Pinned by `unzoned_ingress_parity_8318_test.go`, whose fixture MUST use
`permit-all` — under `deny-all` a cell passes on the broken code.

A `to-zone junos-host` query takes the separate **host gate** (#3285,
`matchJunosHost` ↔ `evaluate_junos_host_policy`): exact `from-zone <ingress>
to-zone junos-host`, then `from-zone any to-zone junos-host`, then a GLOBAL
`policy match to-zone junos-host` (#3639 / #3611 Piece B) — most-specific-first,
with **no** transit default fallback (and the transit `to-zone any` / `from-zone
any to-zone any` wildcards are NOT pulled onto the host path; only a global
explicitly scoped `to-zone junos-host` is). An unmatched host-bound flow returns
`Result.HostInboundUnmatched` — no security *policy* governs it, never an
inherited transit verdict. One exception since #6576: an unmatched host walk
that SKIPPED an overlapping port-bearing DENY returns that deny instead (the
fall-through is permit-like, so the fragment fails closed against it) — see the
next paragraph.

**Non-first fragments on the host path (#6576).** The host gate applies the
same #4569 fragment-associated deny the transit walk does — it learned this in
the dataplane in #6465 (PR #6505) and the simulator followed in #6576. Both
walks share one `fragDenyTracker`, so a future host-gate change cannot silently
diverge again (that drift is exactly what #6576 was: #6505 touched five files,
none of them this package, and the simulator then reported PERMIT / "local
delivery" for a host-bound fragment the box DROPS). The host fall-through is
additionally **permit-like** — an unmatched host-bound flow is delivered — so a
fragment that skipped an overlapping port-bearing DENY fails closed against it
even when nothing matched at all, mirroring the post-walk arm in
`evaluate_junos_host_policy`. An ordinary L4 query never records a candidate, so
the management lifeline is unchanged.

Local delivery is instead gated by
host-inbound-traffic service admission, which post-#3405 DEFAULT-DENIES a zone
with no host-inbound-traffic stanza, so an unmatched result does **not** mean
the packet is delivered (#3627 — the earlier "local delivery proceeds" wording
was misleading for a no-stanza zone). The CLI / `show` / `request` surfaces
render the shared `policymatch.HostInboundShowLine`:
"host-inbound: local delivery subject to host-inbound-traffic service admission
(a zone with no host-inbound-traffic stanza denies by default; transit
global/default-policy NOT applied)"; the gRPC `MatchPolicies` response carries
the bit as `host_inbound_unmatched`.

Both the REST and gRPC `match-policies` surfaces fill `action` through the
shared SSOT `Result.DisplayAction()` (#3375), which returns
`HostInboundActionString` for a host-inbound-unmatched result:
"host-inbound (local delivery subject to host-inbound-traffic service admission
— a zone with no host-inbound-traffic stanza denies by default;
transit/global/default policy NOT applied)". Routing both transports through one
method keeps them from diverging and prevents a blank verdict on the host path.

**Admitting host-inbound token (#3627 B1a).** For a `to-zone junos-host` query,
`Match` additionally classifies the ingress zone's `host-inbound-traffic`
admission for the query tuple and attaches it as `Result.HostInbound`
(`*dataplane/userspace.HostInboundAdmission`; `nil` off the host path). It
reports WHICH system-service/protocol token admits the packet (`token-admit` +
`Token`/`Kind`), a `global-accept` (ICMP error/PMTUD, IPv6 ND, or ESP/AH — the
top-of-chain nft accepts, #3171), a `denied` (post-#3405 default-deny — the box
drops it), or `indeterminate` (the query omits the protocol, or the
destination-port / icmp-type a port/ICMP token needs). The classifier
(`ClassifyHostInbound`) reads the SAME structured token→tuple SSOT the kernel-nft
builder renders from (`config.HostInboundServiceMatch` /
`HostInboundProtocolMatch`), so the reported token cannot claim a port the kernel
does not open. `ident-reset` is reported as NOT admitting (it resets, #3310).
This is ADDITIONAL context, not a verdict tier — it never changes `Matched` /
`HostInboundUnmatched` (the host gate has no transit fallback, #3285). The local
CLI `show security match-policies` prints it after `HostInboundShowLine`;
surfacing it on the REST/gRPC responses (a presence-safe `host_inbound` object /
proto message) and a per-tuple Rust parity test are deferred follow-ups.

Address matching honors literal CIDRs, address
books (recursive set expansion), `any`/`any-ipv4`/`any-ipv6`, source/destination
exclusion (the #2008 empty-excluded fail-closed rule, hardened in #3356 to run
BEFORE the empty-list match-any short-circuit and to gate fail-closed on BOTH
families being empty — so an empty-but-excluded set never inverts to match-all
and a single-family exclusion, e.g. a v6-only `*-excluded` set, does not
over-block the other family), and the live
dynamic-address feed overlay (`Query.FeedOverlay`, supplied by the daemon via
`feeds.Manager.SnapshotForBindings`). Application matching resolves predefined +
user apps via `config.ResolveApplication`, expands application-sets recursively
via `config.ExpandApplicationSet`, compares protocols by IANA number via
`appid.ProtocolNumber` (a protocol-constrained application term fails closed on
an OMITTED or unresolvable query protocol, #3323 — the runtime always carries a
concrete protocol and keys its per-application terms under it, `by_protocol.get
(&protocol)?`, so a protocol-bearing term can only match a packet of that
protocol; an omitted query protocol resolves to `(0,false)` and matches no such
term, falling through to the default-policy. A NAMED application that carries NO
protocol is NOT match-any either: the dataplane cannot represent it and never
enforces it — the snapshot builder fails closed
(`deriveUserspaceCapabilities`, `capabilities.go` returns `ok=false` for
`proto==""` → the `__unsupported__` whole-snapshot reject, #3261) and strict
commit hard-rejects it (`compiler_validate_strict.go`) — so reporting it as a
concrete match would over-report vs the runtime; such an app fails closed in the
simulator too. Only the literal `application any` token is match-any), honors both
source-port and destination-port terms
(a destination-port-constrained term fails closed on an OMITTED query
destination port, #3330 — mirroring the runtime keying exact_dst_ports/range
terms on the concrete packet port; a SOURCE-port-constrained term likewise
fails closed on an OMITTED query source port, #3415 — the runtime always
carries a concrete source port and gates the app on it
(`appid.matchTuple`/`policy.rs CompiledApplications.matches`), so certifying a
permit for an omitted source port over-matches vs the runtime. This supersedes
#3107's earlier "omitted source port stays unconstrained" diagnostic stance;
an unconstrained source-port term still matches any source port), and
enforces ICMP/ICMPv6 type/code constraints (#3284, junos-ping = type 8,
junos-pingv6 = type 128) from `Query.ICMPType` / `Query.ICMPCode`. A
type-constrained application term matches only when the query's type is known
and equal (and the code too, when the term constrains a code); a query that
omits the type fails closed for that term, mirroring the dataplane's
`packet_icmp = None` path. An unconstrained ICMP application (junos-icmp-all) is
unaffected. The surfaces accept the type/code as `icmp_type`/`icmp_code` (REST
query, gRPC `MatchPolicies` optional fields), `icmp-type`/`icmp-code` (CLI
tokens), and `ictype=`/`iccode=` (gRPC `test policy` topic).

## Address token precedence (#9523)

`resolveToken` resolves a policy address token in the same order as the
snapshot builder's `classifyPolicyAddresses`: a match-all keyword (`any`, `any4`,
`any6`, `any-ipv4`, `any-ipv6`, per `config.IsPolicyAddressWildcardKeyword`)
first; then an address-book address, address-set or dynamic-address feed
binding by NAME; then a literal CIDR or IP. The keyword set and each keyword's
families come from `config.PolicyAddressWildcardFamilies`, the helper the
snapshot builder uses, so the two cannot recognise different keywords (#9574).
The compiled config also keeps `any-ipv4` / `any-ipv6` raw since #9574, so an
object named `0.0.0.0/0` cannot capture them either. Before #9523 the keyword test ran
after the name lookup, so an object literally named `any` captured the keyword
here exactly as it did on the wire, and the simulator agreed with the narrowed
enforcement instead of flagging it. Name-before-literal is unchanged for every
other token.

## Content-rejected verdict (#3727, #4394)

A policy that references content the userspace matcher cannot represent makes the
runtime fail the WHOLE snapshot closed — the helper retains its previous-good
snapshot or fresh-boots default-deny and enforces NONE of the config. `Match`
detects the SAME fail-closed set up front, config-wide, BEFORE any per-tier or
host-gate evaluation, and returns a first-class `Result.ContentRejected` verdict
carrying `ContentRejectionReasons` that name the offending policy + object.
`DisplayAction` renders the dedicated `ContentRejectedActionString` (the SSOT
shared by REST/gRPC), and the CLI / `test policy` text surfaces print
`ContentRejectedShowLine` plus the reasons.

The detection delegates to the single dataplane SSOT
`dpuserspace.PolicyContentRejectionReasons(cfg, feedOverlay)` — the EXACT
fail-close set `buildSnapshot` enforces — so the simulator can never drift from
the helper. It covers every fail-closed policy-content axis:

- **Unexpandable application-SET (#3727)** — `config.ExpandApplicationSet` errors
  (a member that does not resolve, nesting deeper than the max, or a missing
  set). Two runtime paths fail closed on it: the app catalog builder
  (`pkg/appid.BuildCatalog`, consumed by `buildAppCatalogSnapshot`) errors so
  `buildSnapshot` itself errors (#3438), and the policy snapshot builder poisons
  the rule with the `__unsupported__` sentinel the helper integrity preflight
  rejects (#3261). The catalog path is ORDER-INSENSITIVE, so `[ any bad-set ]`
  fails closed too (the per-rule scan short-circuits a leading `any`).
- **Protocol-less application (#3323)** — a named app with no protocol
  (`proto == ""`) is unrepresentable (`expandUserspacePolicyApplications` returns
  `ok=false` → `__unsupported__`).
- **Unrepresentable protocol or port (#2124/#4345)** — `appid.ProtocolNumber` or
  `userspacePortSpecRepresentable` rejects it (e.g. a bogus protocol name, or a
  destination-port outside the u16 wire space).
- **Undefined application reference** — `match application X` where X is neither
  a defined application nor an application-set
  (`resolveUserspaceApplicationNames` returns `ok=false`).
- **Unresolvable address (#3261)** — an undefined address-book / prefix-list
  name, or a defined book/set whose value is a non-literal (Junos dns-name /
  wildcard-address / range-address) or resolves to no concrete prefix
  (`addrRepresentable` false → `__unsupported_address__`). The scan is feed-aware
  (`q.FeedOverlay`): a healthy dynamic-address feed policy resolves through the
  overlay and is NOT falsely flagged.
- **Zone-pair stanza naming `junos-global` (#9570)** — reachable only on the
  tolerant load path, since strict commit rejects it. The snapshot builder
  poisons the rule with `__unsupported__`, because the both-sided spelling is
  wire-identical to a real global rule and the helper cannot tell them apart.
  The reason names the side and renders the ZONE-PAIR scope
  (`junos-global->junos-global/p1`), never `global/p1`.
- **Duplicate rule identity (#9584)** — two rules that resolve to one stable
  identity (`<from>-><to>/<name>`, or the explicit wire `rule_id`), or that share
  a non-zero `policy_id`. Strict commit rejects a duplicate policy name (#3473),
  but the tolerant load path keeps one written in separate stanzas (two
  `security {}` roots, two stanzas for one zone pair, two `policies` or `global`
  blocks) unmerged, because the #8752 fold only merges within one stanza. The
  helper refuses such a snapshot (`DuplicateRuleId` / `DuplicatePolicyId`,
  #3713); the mirror follows its order, identity first, and reports each
  duplicate once.

Before this, `matchApp` / `matchAddr` SILENTLY SKIPPED the unrepresentable term
(a per-term no-match) and fell through to a later rule / the configured
default-policy — so under a `default-policy permit-all` the simulator reported
PERMIT for a config the dataplane fail-closes (and `match application
[ bad-set any ]` returned a confident positive match, review M01). #3727 fixed
the application-SET axis; #4394 extended the gate to the remaining four axes
above, which the pre-#4394 simulator reported as a fabricated permit/deny/default
verdict. The detection is config-wide: a single unrepresentable rule anywhere
fails EVERY query for the config, mirroring the whole-snapshot rejection — a
query whose own zone pair has a clean rule is still reported content-rejected
because that clean rule is not enforced either.

The runtime reference is pinned in
`pkg/dataplane/userspace/app_set_reject_3727_test.go` (`buildSnapshot` errors or
records `PolicyContentRejected` for the same input); the simulator
fail-on-revert artifacts are in `app_set_failclosed_3727_test.go` (#3727) and
`content_reject_4394_test.go` (#4394 — the four extended axes plus the
no-over-report control).

Where the runtime and the old simulators disagreed, the runtime wins.

## Non-first fragment / fragment-associated deny (#5572)

`Query.NonFirstFragment` marks the query as a NON-FIRST IP fragment — the
dataplane's flowless / no-L4 packet shape (`evaluate_policy_result_l3_aware`
`l4_present == false`, #3291/#4569). A non-first TCP/UDP fragment carries the
datagram's post-IP bytes as PAYLOAD, not an L4 header, so `SrcPort`/`DstPort`
are meaningless (ignored) and there is no readable ICMP type/code. The default
`false` is a normal L4-present packet, so every existing caller is unchanged.

Before #5572 the simulator had no fragment discriminator: a non-first fragment
could only be expressed as ports `0`, which `Match` evaluated as a real port-0
packet. In an ordered `deny junos-https` (TCP/443) then `permit any` vector it
skipped the port-bearing deny at the port gate, fell through to the later
permit, and reported PERMIT — while the DATAPLANE applied the #4569
fragment-associated deny and dropped the fragment. The oracle contradicted the
live firewall on exactly the traffic an operator debugs during an incident,
hiding the enforcing policy id.

With `NonFirstFragment == true`, `Match` reproduces the dataplane's #4569
override EXACTLY:

- `matchApp` (via the threaded `l4Present == false`) fails a PORT-BEARING or
  ICMP-type-constrained application term closed regardless of any port value —
  even a `destination-port 0-1023` range a naive port-0 query would spuriously
  match — while a PROTOCOL-ONLY / `application any` term still matches on the L3
  identity + known IP protocol the fragment carries (mirror of
  `CompiledApplications::matches`);
- while walking the tiers in first-match precedence order — the transit tiers in
  `Match` and, since #6576, the three host tiers in `matchJunosHost`, both
  driving the shared `fragDenyTracker` —
  `isSkippedFragDeny` (the mirror of `rule_is_skipped_frag_ambiguous_deny`)
  remembers the FIRST port-bearing DENY/REJECT whose L4-constrained term is
  inapplicable to the fragment (`hasL4ConstrainedTerm`), that does NOT match
  flowlessly, and whose source+destination ADDRESS overlaps the fragment (the
  zone is fixed by the tier);
- if the walk then lands on a PERMIT — a matched permit, a transit
  default-permit, or (host path, #6576) the permit-like unmatched
  fall-through — `fragDenyTracker.override` /
  `fragDenyTracker.overridePermissiveTerminal` OVERRIDE it to that deny
  (`Result.FragmentAssociatedDeny`, attributed to the enforcing policy so
  `PolicyName`/`PolicyID`/`RuleID` name the real rule), and
  `Result.FragmentDenyNote()` renders the SSOT over-drop advisory.

`Result.Action` on a fragment-associated verdict is ALWAYS `config.PolicyDeny`,
never `reject`, even when the shadowing rule is a `reject`. A non-first fragment
has no L4 header, so the dataplane cannot emit a RST/ICMP — it can only silently
DROP — and `frag_associated_deny_result` hardcodes `PolicyAction::Deny` to match
(`isSkippedFragDeny` still accepts a `reject` because a reject shadows the
fragment identically to a deny; only the reported label is normalized to deny).
Both verdicts are DROPs, so the #5572 false-permit is not re-introduced — this
only keeps the deny-vs-reject label in parity with the wire.

Scoped narrowly, mirroring the dataplane: a fragment a real (protocol-only /
`any`) deny matches directly is a normal deny (not flagged as an override); a
deny for a DIFFERENT protocol (`hasL4ConstrainedTerm` false) or a
NON-overlapping source/destination leaves the fragment on its forward path.

BOTH walks carry the override. A `to-zone junos-host` fragment takes the host
gate, which learned the same #4569 override in the dataplane in #6465 (PR
#6505) and in this package in #6576 — see "Non-first fragments on the host
path" above. (Before #6505 the host gate had no override; a doc sentence
asserting that outlived the code and is exactly the stale-assertion trap #6576
was, so it is called out rather than silently deleted.)

Every operator surface threads the discriminator: the valueless
`non-first-fragment` CLI selector (local + remote `show security match-policies`
/ `test policy`, via `ParseSelectorArgs`), the gRPC `MatchPolicies` RPC
`non_first_fragment` field, the gRPC `test-policy:` bridge `frag=1` token, and
the REST `non_first_fragment` query parameter. The verdict + advisory ride the
gRPC `MatchPoliciesResponse` (`fragment_associated_deny`/`fragment_deny_note`)
and REST `MatchPoliciesResult` so remote clients explain the over-drop
identically to the local CLI.

The fail-on-revert artifacts are in `fragment_5572_test.go` (the fixture is the
issue's `deny junos-https` then `permit any`, IPv4 + IPv6): reverting the
discriminator makes the fragment query report `permit-all` and fails the
want-deny assertion, catching the exact simulator-vs-dataplane divergence. The
dataplane reference is `userspace-dp/src/policy.rs` (`note_skipped_frag_deny` /
`apply_frag_deny_override` / `rule_is_skipped_frag_ambiguous_deny` /
`has_l4_constrained_term`) pinned in `userspace-dp/src/policy_tests.rs` (#4569).

## Unsupported tuple family (V4 src / V6 dst) — codex-182 A10-b02-C1

`matchAddr` evaluates the source and destination address sides INDEPENDENTLY,
so a query carrying an IPv4 source with an IPv6 destination could match a rule
per-side and yield a concrete permit/deny/default verdict for a packet shape the
forwarding path never produces. NAT46 is not implemented, so no inbound
translation yields a v4 source with a v6 destination, and the runtime matcher
fails that arm closed (`userspace-dp/src/policy.rs` `try_match_rule` `_ =>
return false`). The reverse (V6 src, V4 dst) tuple IS valid — it is the NAT64
arm — and every same-family tuple is normal.

`Match` therefore rejects the impossible tuple up front, at the single shared
entry point every transport (CLI, REST, gRPC `MatchPolicies`) funnels through,
so the fix covers all three without per-surface logic. When the source is IPv4
and the destination is IPv6 (both sides specified — a nil/unspecified side is a
wildcard and never triggers the gate), it returns a first-class
`Result.UnsupportedTupleFamily` verdict: `Matched`/`DefaultUsed`/
`HostInboundUnmatched`/`ContentRejected` are all false, `Action` is the
conservative `PolicyDeny` for a raw reader, and `DisplayAction` renders the
dedicated `UnsupportedTupleFamilyActionString`. Family is **colon-strict**
(#6377, see below): `queryTupleFamily` prefers the caller's
`Query.SrcFamily`/`Query.DstFamily` text hint and falls back to `To4()` only
when no hint is supplied. The fail-on-revert artifact is
`mixed_family_tuple_5720_test.go`: dropping the gate makes the (V4 src, V6 dst)
query fall through to a fabricated default verdict.

### Colon-strict family — IPv4-mapped IPv6 source (#6377, resolved)

`net.IP.To4()` FOLDS an IPv4-mapped IPv6 literal:
`net.ParseIP("::ffff:192.0.2.1").To4()` is non-nil. Before #6377 the gate read
family with `To4()` alone, so a source authored as `::ffff:192.0.2.1` against a
`2001:db8::1` destination was classified (V4 src, V6 dst) and **falsely**
reported `UnsupportedTupleFamily`, even though the colon-strict runtime matcher
(`userspace-dp/src/policy.rs`) treats the mapped literal as V6 and sees a valid
same-family V6/V6 tuple that should be evaluated normally. This is the
documented Go/Rust family-parity trap: the authoritative colon-strict classifier
is `config.NATAddrFamily` / `natAddrFamily`
(`pkg/config/compiler_nat_helpers.go`), which keys family on the presence of a
`':'` in the *original text* — precisely the signal `net.ParseIP` has already
discarded by the time the gate sees `q.SrcIP`/`q.DstIP`.

The fix threads that colon-strict text family from every caller into the query.
`Query` carries an optional `SrcFamily`/`DstFamily` ("v4"/"v6"/"") hint, and all
FIVE builders (`cli_request_testcmd.go`, `cli_show_security.go`,
`server_show_firewall.go`, `server_cluster.go`, and the REST
`api/security.go` `matchPoliciesHandler`) populate it with
`config.NATAddrFamily` on the RAW operator string before `net.ParseIP` folds it.
`queryTupleFamily` prefers the hint and falls back to `To4()` only when a caller
supplies none (the `net.IP`-only callers, e.g. tests — their pre-#6377 fold is
preserved). So `::ffff:192.0.2.1` now yields `SrcFamily == "v6"`, the tuple is a
same-family V6/V6 pair, and the gate falls through to normal evaluation, exactly
as the runtime does. A genuine dotted-quad `10.0.0.1 -> 2001:db8::1` still
classifies (V4 src, V6 dst) and is still flagged. The fail-on-revert artifact is
`mapped_ipv4_tuple_6377_test.go`
(`TestMatchMappedIPv6SourceNotGated`): restoring the `To4()`-only gate folds the
mapped source to v4 and falsely flags it. The pre-fix failure mode was a
spurious "unsupported tuple" advisory on a diagnostic surface (fail-safe — it
never hid or fabricated a permit), not a dataplane effect.

The same colon-strict family also governs the policy EVALUATOR, not just the
up-front gate. `matchAddr` (the per-side address matcher) classifies the
packet's family with `queryTupleFamily(ip, family)` — the threaded hint, falling
back to `To4()` only when absent — so a mapped source is tested against the
**V6** address rules, never folded to v4. Without this, letting the mapped tuple
fall through the gate would be **worse** than the original bug: `net.IP.To4()`
folds `::ffff:192.0.2.1` to `192.0.2.1`, which is inside a `192.0.2.0/24` V4
policy, so the simulator would **fabricate a PERMIT** (fail-OPEN) the runtime
never produces (the Rust matcher evaluates the V6 source against the V6 rules →
default-deny). Only the `isV4` branch selection consumes the family; the
`v4Empty`/`v6Empty` gates key on the ADDRESS SETS, so the #3023 cross-family and
#2008 excluded fail-closed semantics are unchanged. The evaluation fail-on-revert
artifacts are `TestMatchMappedIPv6SourceNotEvaluatedAsV4` (matcher) and
`TestMatchPoliciesRESTMappedIPv6SourceNotEvaluatedAsV4_6377` (REST): restoring
`isV4 := ip.To4() != nil` makes the mapped source match a V4-only permit rule.

The host-inbound classifier is the third colon-strict consumer.
`hostInboundAdmission` derives the nft-style family token via `ipFamilyStrict`
(the hint mapped to `ip`/`ip6`, `To4()` fallback when absent) instead of the
folding `ipFamily`, so a mapped-v6 host-bound destination (e.g. a DHCPv6 flow to
the firewall authored as `::ffff:...`) is classified `ip6`. A family-scoped
`system-services` token (`dhcpv6`=ip6, `dhcp`=ip; `ping`'s ICMP vs ICMPv6 type)
would otherwise be mis-admitted. Fail-on-revert:
`TestHostInboundMappedIPv6DstClassifiedAsV6` — restoring `family =
ipFamily(q.DstIP)` flips a mapped-v6 dst on udp/547 from `TokenAdmit(dhcpv6)` to
`Denied`.

The `Match`-side gate is transport-agnostic (every surface funnels through the
one entry point), but rendering the *dedicated verdict* to an operator is
per-surface: the REST (`pkg/api`) and gRPC `MatchPolicies`
(`server_cluster.go`) paths already emit `res.DisplayAction()`, so they surface
`UnsupportedTupleFamilyActionString` for free. The three hand-rolled text
renders — `cli_request_testcmd.go` (`test security policy-match`),
`cli_show_security.go` (`show security match-policies`), and
`server_show_firewall.go` (gRPC show-firewall `test policy` bridge) — each
format the verdict fields by hand, so #5720 gives them an explicit
`if res.UnsupportedTupleFamily` branch (mirroring their `ContentRejected` /
`HostInboundUnmatched` arms) that prints `DisplayAction()`. Without it an
operator on those surfaces would read an ordinary `Default deny (no matching
policy)` for an *impossible* tuple and be tempted to add a permit that can
never take effect. The render-side fail-on-revert artifact is
`server_show_testpolicy_unsupported_tuple_5720_test.go`: dropping the
gRPC-text arm makes the (V4 src, V6 dst) topic fall back to the fabricated
`no matching policy` line.

### Colon-strict family — containment and prefix classification (#6577, resolved)

#6377 above fixed **which** family's rules a mapped address is tested against.
It left two independent surfaces where `net.IP.To4()` still folded: **V6 query
containment** and **address-set family classification**. The two failed in
OPPOSITE directions — the query side let a mapped address reach the V6 branch
and match nothing at all, while the classification side routed a mapped
*prefix* into the V4 set, where the fold degraded it to a `/0` that matched
every IPv4 address (see below). #6577 closed both.

**The query side — containment.** `net.IPNet.Contains` opens with the same
`if x := ip.To4(); x != nil { ip = x }` narrowing, so a mapped address folded to
4 bytes and then failed Contains' `len(ip) != len(nn)` guard against **every**
16-byte v6 prefix — `::/0` included. A mapped destination could therefore never
match ANY concrete v6 prefix, while the dataplane's `PrefixV6::contains`
(`userspace-dp/src/prefix.rs`) compares unfolded 128-bit values
(`(u128::from(ip) & self.mask) == self.network`) and matched it. A v6 DENY that
drops the packet on the box fell through to a later PERMIT in the simulator.
`matchAddr`'s v6 branch now uses `containsAnyV6`, an explicit 16-byte masked
compare that mirrors the Rust mask exactly. The v4 branch deliberately KEEPS
`Contains`: `net.ParseIP` returns a 16-byte 4-in-6 slice for a dotted quad while
v4 prefixes are stored 4-byte, so the fold is what makes those widths meet.

**The address-set side — prefix classification.** `addCIDRValue` classified a
parsed value with `ipnet.IP.To4() != nil`, which folds the same way, so
`::ffff:0:0/96`, every mapped `/97`-`/128` prefix, and a bare
`::ffff:a.b.c.d` landed in the **V4** set. That is not benign misfiling:
`Contains` then folds the 16-byte network through `To4()` and slices the 16-byte
mask down to its TRAILING four bytes (`net.networkNumberAndMask`), so
`::ffff:0:0/96` degrades to an IPv4 **/0 matching every IPv4 address** and a
mapped `/120` aliases to the embedded IPv4 `/24`. Rust does the opposite:
`parse_address` runs `prefix.parse::<IpNet>()` and `Ipv4Addr::from_str` REJECTS
a colon-bearing literal, so the arm taken is `Ok(IpNet::V6(net))`. On a DENY the
simulator therefore claimed the rule covered all of IPv4 — a false sense of
protection for traffic the box does not filter — while reporting no coverage for
the mapped addresses it actually denies. `addCIDRValue` now classifies from the
literal's TEXT via `addrValueFamily` (`config.NATAddrFamily` on
`config.NATCIDRIPPart`), the same colon-strict SSOT #6377 uses. Ordinary
literals are unaffected: a dotted quad has no colon, a genuine v6 literal has
one, and both classify exactly as `To4()` did — only the mapped forms move.
`net.ParseCIDR` accepts these tokens at commit
(`policyMatchAddressTokenRecognized`), so the shape is reachable, not
theoretical.

One caveat worth knowing: on the address-BOOK path `pkg/dataplane/userspace`
still pre-splits book values into the wire v4/v6 buckets with the folding
`isV4CIDR`, and Rust's `parse_book_prefix_into` enforces the declared family and
REJECTS the whole snapshot for a mapped prefix filed under v4
(`UnrepresentableAddressBookPrefix`). That path fails closed at config push and
programs nothing, so classifying the literal v6 here is strictly closer to the
dataplane either way; the exact Go/Rust agreement is on the DIRECT policy
literal, which `classifyPolicyAddresses` passes through unchanged.

Fail-on-revert artifacts: `mapped_ipv6_contains_6577_test.go` (query side) and
`mapped_ipv6_prefix_6577_test.go` (address-set side). The latter drives the real
`resolveToken`/`addCIDRValue` construction path rather than calling the helper
directly, and carries the over-reach guards —
`TestAddressFamilyClassificationUnchanged_6577` (ordinary v4/v6 prefixes, bare
IPs, `any`/`any-ipv4`/`any-ipv6`, and sub-`/96` mapped prefixes that were
already v6) and `TestOrdinaryV4PolicyUnaffectedByPrefixFix_6577` both stay GREEN
under the revert. Note `containsAnyV6` cannot itself distinguish a dotted quad
from its mapped form (`net.ParseIP` returns byte-identical values for both), so
the colon-strict family hint is the SOLE guard against a v4 address being tested
against `::/0`; every production call site derives that hint from the same raw
string it parses the IP from.

## Independent oracle: the shared policy-verdict corpus (#9167)

`show security match-policies` had no independent oracle, and the demonstrated
escape says exactly why. PR #6505 taught the Rust junos-host gate the #4569
fragment-associated deny by changing `userspace-dp/src/policy.rs`,
`policy_snapshot_error.rs`, `policy_tests.rs`, `_Log.md` and
`docs/feature-gaps.md` — **no Go at all** — and this package kept reporting
PERMIT for a host-bound fragment the box DROPS until #6576 wrote a second hand
mirror.

**The issue's account of the mechanism is corrected here.** It names three
sub-verdicts that call `pkg/dataplane/userspace` helpers (`RuntimePolicyIDs`,
`ClassifyHostInboundForInterface`, `PolicyContentRejectionReasons`) as an oracle
that cannot disagree with the implementation. Those calls share code with the Go
**write** path, and that sharing is correct: the simulator must report the same
policy ids and the same fail-closed set the write path computes. The gap is one
layer out — the Go write path and this simulator are BOTH mirrors of
`policy.rs`, and nothing compared either one to the enforcer. #6505's file list
is the measurement.

### Design

| piece | produced by | read by |
|---|---|---|
| `testdata/policy_verdict_corpus.txt` — configs, query tuples, **expected verdicts** | authored | the Go simulator test **and** the Rust enforcer test |
| `testdata/policy_verdict_corpus_snapshots.json` — the snapshot Go puts on the wire for each config | the Go generator (`UPDATE_9167=1`), freshness-gated | the Rust enforcer test |

- **The oracle is the expectation column.** It is authored from the Junos
  semantics and produced by neither implementation. Go compiles the config with
  strict `config.CompileConfig` and runs `Match`; Rust parses the snapshot with
  the enforcer's own `parse_policy_state_with_counters` and evaluates with the
  enforcer's own entry points — `evaluate_policy_result_l3_aware` for a transit
  pair, `evaluate_junos_host_policy_l3_aware` for `to-zone junos-host`. Each
  compares to the column; neither calls the other.
- **Host-bound and fragment rows.** A `to-zone junos-host` row goes through the
  host gate, where no matching rule means local delivery (written `-`), and a
  `frag` row is a non-first fragment evaluated with no L4 header. Together they
  are the #6505 escape itself: `junos-host-fragment-associated-deny`.
- **The expectations reach Rust from the text, not through Go.** The generator
  emits only snapshots, so a Go misreading of an expected verdict cannot be
  transcribed into what Rust asserts.
- **Compared:** the action, matched-versus-default, and on the Rust side the
  runtime policy id. The id check turns `RuntimePolicyIDs` from an unchecked
  shared helper into a checked one: the id this package shows is compared with
  the id the enforcer resolves.

### The fixture reproduces the production wire shape

The first generated file carried `"address_books": null`, and the Rust decoder
refused it. Normalising `nil` to `[]` in the generator would have made the
fixture MORE well-formed than the real producer — which can hide exactly the
Go/Rust mismatch this differential exists to catch. The producer was measured
instead: `ConfigSnapshot.Zones`, `.Policies` and `.AddressBooks` are all
`,omitempty`, as is every slice field of `PolicyRuleSnapshot`,
`AddressBookSnapshot` and `ZoneSnapshot`, and the Rust decoder marks each one
`#[serde(default)]`. Production therefore sends an **absent key**, never `null`.
The `null` came from the generator's own wrapper, which lacked `,omitempty`. The
wrapper now carries the same tags, and
`TestPolicyCorpusSnapshotMirrorsTheWireShape9167` pins them to `ConfigSnapshot`'s
by reflection. (The null-tolerant class is real in this tree — #2214's
`null_tolerant_vec` exists for NAT64 `pool_addresses` and filter `terms`, which
carry no `,omitempty` — but none of those fields is part of this snapshot.)

### The honest bound

The snapshot handed to Rust is built by Go's snapshot **builder**, so the builder
is shared input. That is not a blind spot for the tier walk: this simulator reads
the *config*, not the snapshot, so a builder that drops or mangles a rule makes
the two halves disagree. What stays invisible is a builder defect that the
expectation column was **also** written to match — which is why the column is
authored from the Junos semantics rather than transcribed from a run.

### Measured: what the corpus catches

Every mutant below changes PRODUCTION code, is confirmed applied by occurrence
count, and is scored by the NAME of the failing Go test (`go test -json`) or by
the corpus row the Rust panic names.

| escape mutant | Rust half | Go half |
|---|---|---|
| revert the Rust #6505 junos-host fragment deny | **FAIL**, names `junos-host-fragment-associated-deny` | PASS |
| revert the Go #6576 mirror (`matchJunosHost` fragment override) | PASS | **FAIL**, names `junos-host-fragment-associated-deny` |

| tier-walk mutant | Rust (`policy.rs`) | Go (`policymatch.go`) |
|---|---|---|
| widen a scoped global to all zones | KILLED: `scoped-global-applies-only-in-scope` | KILLED: `scoped-global-applies-only-in-scope` |
| switch off the exact zone-pair tier | KILLED: `exact-zone-pair-permit` | KILLED: `exact-zone-pair-permit` and 3 more rows |
| reverse first-match-wins inside a pair | KILLED: `first-match-wins-within-a-pair` | KILLED: `first-match-wins-within-a-pair` |

The halves are independent, which the escape rows show: each is sensitive only
to its own implementation. Drift is loud because the EXPECTATION is shared: a
change to either implementation that the corpus disagrees with reds that half,
and changing an expectation to match one implementation reds the other half until
it agrees.

### The wiring is bound from the Go side

The Rust half is a `#[path]` test module declared in `policy.rs`. Delete that
declaration and `cargo test` stays green; the corpus test simply stops executing
(measured). A test cannot notice its own absence, so
`TestPolicyVerdictCorpusRustHalfIsRegistered9167` (`pkg/dataplane/userspace`,
beside the generator) pins the declaration and both `include_str!` paths, and
reds when the declaration is severed (measured).

### Adding a row

Add it to `testdata/policy_verdict_corpus.txt` and regenerate the snapshots with
`UPDATE_9167=1 go test ./pkg/dataplane/userspace/ -run 9167`. Both languages then
assert it; a row only one side knows about cannot exist.

## Not modeled

Scheduler-driven policy `inactive` state is not applied — a scheduled policy is
simulated as if active (matching the pre-#3042 surfaces). This is
operator-diagnostic only; it never touches the dataplane or the snapshot wire.

The regression matrix from the issue is pinned in `policymatch_test.go`
(`TestSharedMatcherRegressionMatrix`), and `TestOldNarrowMatcherDiverges` is
the concrete fail-on-revert artifact proving the old per-surface logic returns
the opposite verdict on the affected cases.

The #3148 global-policy `match from-zone`/`match to-zone` scope tier (Tier 4)
has its own cross-language SSOT lock in
`global_scope_regression_4365_test.go` (`TestSharedMatcherGlobalScopeRegression`
`Matrix`, #4365): a table of vectors that assert the full verdict contract
(`Matched`/`Global`/`Action`/`PolicyName`, the #3331 from/to-zone SCOPE, and the
`RuntimePolicyIDs` `PolicyID`) for a matching scope, a non-matching scope
(from-, to-, and undefined/fail-closed), an empty/`any` scope spanning all
zones, and tier precedence (a matching exact zone-pair and a matching both-any
wildcard each outrank a matching scoped global). The Rust dataplane
(`userspace-dp/src/policy.rs` `GlobalZoneScope::matches`) mirrors these vectors
so the simulator and the wire cannot diverge on the scoped-global tier.
