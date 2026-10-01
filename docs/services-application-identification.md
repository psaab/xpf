# Application Identification (AppID) on xpf

This is the authoritative reference for what
`set services application-identification` actually does on
xpf today, and what it explicitly does NOT do, vs the Junos
vSRX feature of the same name. (#653)

## TL;DR

- xpf parses `services application-identification` as a
  Junos-compatible config knob.
- The runtime does **port + protocol matching only** against
  the configured `applications` catalog — *not* L7 deep packet
  inspection, *not* signature-based identification, *not*
  payload heuristics.
- The knob's only runtime effect is to switch the "session app
  name when no port match exists" behaviour from "guess from
  built-in port heuristic" to **"`UNKNOWN` (honest)"**.
- L7 features that depend on real AppID — dynamic-application
  policies, AppTrack, AppFW, AppQoS — are **not implemented**.

## Live status surface

```
> show services application-identification status
```

That command surfaces the contract documented here at runtime
so an operator looking at a session that says `junos-http`
knows it came from a `(proto=6, dst-port=80)` lookup, not L7
inspection.

A commit-time warning fires if `services
application-identification` is enabled, telling the operator
upfront what they're getting and not getting.

## How session app names are assigned today

1. **Compile time**: `pkg/appid/runtime.go:CatalogNames` builds
   the application catalog name set from policies + the
   predefined junos-* application list + user-defined
   applications. Each name is assigned a **STABLE, name-derived**
   `u16 app_id` (#5296) — a FNV-1a fold of the application NAME into
   `[1, 65535]` (`config.StableAppID`), assigned through the shared
   `config.AssignStableAppIDs` SSOT called by BOTH
   `pkg/dataplane/compiler.go:compileApplications`
   (`CompileResult.AppNames`, the `app_id → name` map the show
   path consumes) and `pkg/appid/catalog.go:BuildCatalog` (which
   also carries each application's
   `(protocol, dst-port-range, src-port-range)` match rule). A Go
   test (`pkg/dataplane/appid_catalog_parity_test.go`) pins that the
   two id assignments are identical, so an id stamped by the
   dataplane always resolves to the right name.

   The id is a pure function of the NAME (never of the catalog set or
   compile order), so an ordinary catalog edit that inserts an
   earlier-sorting application no longer renumbers existing
   applications — a RETAINED session's frozen `app_id` keeps
   resolving to the application it was stamped under. This replaces
   the legacy sorted `1..N` positional assignment, whose ids shifted
   on any such edit and mis-labeled retained sessions (#5296); it is
   the same name-hash pattern zone ids use (`config.StableZoneID`,
   #3075). Predefined applications are a FIXED, mutually
   collision-free set (frozen by `TestPredefinedAppIDsCollisionFree`)
   and always own their `StableAppID` slot; a rare USER-app hash
   collision is resolved by a deterministic displaced-slot fill, so
   only the colliding user apps can renumber — never the whole
   catalog. **Honest residual (#5296):** stability is NOT absolute —
   adding a user app that hash-collides with an existing user app can
   renumber that small colliding set. Because this is the one case that
   warrants operator attention, `AssignStableAppIDs` emits a
   `slog.Warn` at catalog build (config compile, never per-packet)
   whenever a user app is displaced off its natural `StableAppID` slot —
   naming the `application`, the `natural_app_id` slot it wanted, and
   the `assigned_app_id` it was displaced to (#5988). An operator who
   sees this log knows a displacement (and thus a possible
   renumber-across-edit for that app) has occurred; a collision-free
   catalog stays silent. The zero-residual path (versioning application
   identity in the session state) is a cross-language conntrack-ABI +
   HA-wire change, deliberately out of scope for this bounded fix.
2. **Snapshot ship**: `buildAppCatalogSnapshot`
   (`pkg/dataplane/userspace/flow.go`) emits the catalog as the
   `app_catalog` field of the config snapshot — an ordered list
   of `(app_id u16, protocol u8, dst_port_low/high u16,
   src_port_low/high u16)`. It is an additive wire field with
   `omitempty` on the Go side and `#[serde(default)]` on the
   Rust side (`AppCatalogEntry` in
   `userspace-dp/src/protocol/security.rs`), so an old snapshot
   without it decodes to an empty catalog (HA/upgrade-safe).
3. **Session create (userspace dataplane)**: the snapshot
   catalog is compiled into `ForwardingState.app_catalog`
   (`AppCatalog` in `userspace-dp/src/policy.rs`). When a worker
   creates a new session (`poll_descriptor`), it calls
   `AppCatalog::lookup_directional(protocol, src_port, dst_port,
   is_reverse)` and the resolved `app_id` (0 = no match) is stamped
   on the conntrack session value in `publish_conntrack.rs`
   (previously hardcoded to 0). The well-known service port is the
   DESTINATION on a forward-keyed flow and the SOURCE on a
   reverse-keyed flow (`is_reverse` selects the slot, #3321), so the
   forward and reverse conntrack entries resolve to the same
   `app_id` without cross-slot probing. **Overlap precedence
   (#3612):** when more than one catalogued app matches a tuple, the
   winner is the more SPECIFIC one — a port-constrained entry
   (destination and/or source port set) beats a bare protocol-only
   entry — with ties broken by the lowest `app_id` within a tier.
   Since #5296 `app_id` is a stable name-hash (`config.StableAppID`),
   NOT the sorted-name position, so "lowest `app_id`" no longer means
   "alphabetically-first name" — it means lowest `StableAppID`. The
   AppID-DISABLED Go fallback (`resolveTupleFallback`, #2578) was
   re-keyed to break same-tier ties on the SAME `StableAppID` (rather
   than alphabetically) so the two paths still agree. This is the SAME
   binary-specificity rule on both, so the same 5-tuple is labeled
   identically whether AppID is on or off; the shared fixture
   `userspace-dp/tests/fixtures/appid_precedence_v1.json` pins the
   two paths together (Go `TestAppIDPrecedenceParityFixture` + Rust
   `app_catalog_precedence_parity_fixture`). Before #3612 the enabled
   path tie-broke on lowest `app_id` regardless of specificity, so a
   broad protocol-only app could shadow a specific port-based app on
   the enabled path only.

   > **Behavior change (#5296):** for a session that matches MULTIPLE
   > overlapping same-tier catalog applications, the displayed
   > application-name label winner changes from "alphabetically-first
   > name" to "lowest `StableAppID`". It is deterministic and stable
   > across reloads, and it is applied identically on the AppID-enabled
   > (Rust) and AppID-disabled (Go) paths, so the two agree. This is a
   > DISPLAY/log-label change only — it does NOT affect policy matching
   > or forwarding (the policy `application` set is evaluated separately
   > by `CompiledApplications`). To keep the enabled-path exact-port
   > tiebreak (`AppCatalog::exact_dst` first-writer-wins) aligned with
   > "lowest id", `BuildCatalog` now emits catalog entries in ascending
   > `app_id` order. A zero-delta alternative that would preserve the
   > exact alphabetical tiebreak — a classify-time `rank` field on the
   > Go→Rust catalog snapshot (never stamped/persisted) that Rust ties
   > on — decouples identity from precedence but is a cross-language
   > change, tracked as a possible follow-up beyond this bounded fix.

   **Note**: only the local
   session-owner stamps `app_id` in the conntrack map (the same
   property as `alg_type`); an HA-synced session on the standby
   peer is not mirrored into the conntrack map, and a session
   re-created locally after failover is re-stamped from the
   catalog (the catalog is shipped to both nodes), so `app_id`
   is re-derived rather than carried on the session-sync wire.
4. **Show output**:
   `pkg/appid/runtime.go:ResolveSessionName` resolves the
   `app_id` back to a name via the `compiler.go` `AppNames`
   map. A nonzero `app_id` present in `AppNames` resolves to its
   name directly. Otherwise:
   - When `services application-identification` is **enabled**,
     return `UNKNOWN` — for `app_id == 0` (unstamped/legacy) AND
     for a nonzero `app_id` that is absent from `AppNames`. The
     latter is a control/dataplane catalog skew (e.g. a snapshot
     mismatch); the contract is honest `UNKNOWN`, never a
     port-heuristic guess that would mask the skew (#3438 L1).
   - When **disabled**, return a tuple fallback: a configured
     `applications` entry whose `(protocol, source-port,
     destination-port)` constraints all match the session, else a
     built-in port→name guess (`junos-http=80`, `junos-https=443`,
     `junos-ssh=22`, `junos-ftp=21`, etc. — the 15-entry
     `builtinFallbacks` map). The fallback honors a configured
     `source-port` constraint as well as the destination port, so
     a source-port-scoped custom app is not matched on dst-port
     alone (#3428); the session source port is threaded into
     `ResolveSessionName` for this purpose.

**Filter matching is case-sensitive (#5820)**: `SessionMatches`
(`pkg/appid/runtime.go`) compares an operator `show ... application
<name>` / `clear ... application <name>` filter against the session's
resolved application name with **case-EXACT equality** (`==`, not
`strings.EqualFold`). Application names are case-sensitive identifiers
everywhere else in the stack — the parser, typed store, resolver,
catalog, and AppID stamping all preserve and key on exact case, so
`Payroll` and `payroll` are two DISTINCT applications with distinct
AppIDs and distinct session labels, and a user `JUNOS-HTTP` never
folds onto the predefined `junos-http`. The pre-#5820 fold was the sole
inconsistency: it let a single-case filter collapse two distinct
applications on the display path and — because the same predicate drives
the destructive `ClearSessions` walk — broaden a filtered clear to delete
sessions the operator did not name. Junos application filters are
case-exact, so exact matching is the parity contract. Regression:
`pkg/appid` `TestSessionMatchesCaseSensitive5820` (fail-on-revert).

**`UNKNOWN` name reserved out of the user namespace (#5821, relaxed to
exact-case in #5820)**: because `ResolveSessionName` returns the literal
upper-case `UNKNOWN` for the unclassified/unstamped/catalog-skew state and
`SessionMatches` compares an operator filter against that same flattened
name, a user-defined application (or application-set) named `UNKNOWN`
would be indistinguishable from the sentinel — the filter could not tell
"no known application" from the configured app, and a destructive filtered
session clear could delete both groups. A commit-time gate
(`validateReservedApplicationNamesStrict`,
`pkg/config/compiler_validate_strict_application.go`) therefore
**reserves `UNKNOWN` out of the `applications application` /
`applications application-set` namespace, case-sensitively**. The
sentinel is only ever rendered upper-case `UNKNOWN`, and now that filter
matching is case-exact (#5820), only an application literally named
`UNKNOWN` can alias it — `unknown` / `Unknown` are distinct names that are
now ACCEPTED (this is the #5820 relaxation of the original #5821
case-insensitive reservation). The reserved literal
`config.ReservedApplicationName` is kept equal to `appid.Unknown` by the
`pkg/appid` `TestReservedApplicationNameMatchesUnknownSentinel` canary.
This is a **fail-closed restriction** (release-note behavior change): a
previously-valid config that already named an application `UNKNOWN` now
hard-rejects on the operator's next commit. The tolerant load / peer-sync
path downgrades the reject to a warning so an already-persisted or
peer-synced config still boots (#1960 no-brick). A residual display-side
gap remains for an already-stamped session whose real catalog app is
literally `UNKNOWN` on a leniently-loaded legacy config — the sentinel and
that app still flatten to the same string on the show/clear surface until
the operator renames the app; carrying an explicit typed unknown-kind
through the filter path is tracked as a follow-up.

**`app_id` space cap (#3438 H4)**: `app_id` is a `u16` on the
Rust wire with `0` reserved as the unknown sentinel, so real
applications occupy ids `1..65535`. Both id-assignment walks
(`compiler.go:compileApplications` and `catalog.go:BuildCatalog`)
assign through `config.AssignStableAppIDs`, which rejects a config
holding more than 65535 distinct applications with a deterministic
error rather than assigning a duplicate or the reserved id `0`
(#5296 moved the boundary from the positional counter into the
shared assignment helper). The reject is fail-closed on the live
apply path (`CompileUserspaceShim → CompileConfig →
compileApplications`): the apply aborts and the daemon retains the
previous-good snapshot.

### ICMP type/code constraint in policy matching (#3020, #11340)

The version-bounded Junos defaults cited by #11340 define `junos-ping` and
`junos-pingv6` as protocol-only ICMP/ICMPv6 applications: each matches every
message type/code of its protocol. The echo-only application is
`junos-icmp-ping` (ICMP type 8, no code constraint). The explicitly all-ICMP
aliases `junos-icmp-all` / `junos-icmp6-all` also remain unconstrained.
Current-release vSRX readback is still outstanding.

Junos rejects an application name such as `junos-ping` in a custom application's
`protocol` leaf. XPF retains that syntax as a compatibility extension for
user-defined applications and keeps it echo-constrained (type 8 / 128); this is
distinct from the predefined `junos-ping` all-ICMP object.

The constraint is modeled as an optional `(ICMPType, ICMPCode)` on an
application (`pkg/config/predefined.go` for `junos-icmp-ping`), carried on the
policy snapshot's application term (`PolicyApplicationSnapshot.ICMPType` /
`.ICMPCode`, `pkg/dataplane/userspace/protocol.go`) and the Rust matcher
(`ApplicationMatch.icmp_type` / `.icmp_code`, `userspace-dp/src/policy.rs`).
`nil`/`None` means "no constraint" (match all types/codes of the protocol).
The wire field is additive: a pointer + `omitempty` on the Go side and
`#[serde(default, skip_serializing_if = "Option::is_none")]` on the Rust side,
so an old helper missing the field — or an old Go snapshot omitting it —
decodes to `None` and ignores the constraint (match-all, the pre-#3020
behavior); version skew degrades safely rather than failing to decode.

The Rust matcher reads the packet's ICMP type/code from the live frame at
policy-evaluation time (`policy_packet_icmp` in `poll_descriptor`, reusing the
fragment/truncation-safe `term_match_extra_from_frame`). When the type/code is
unknown (a truncated frame or a non-first fragment) an icmp-type-constrained
term fails closed (does not match). Policy evaluation is on the cold path
(session miss), so the per-packet extraction cost is incurred once per session.

This affects **policy matching** only. The app-identification catalog
(`app_id` session stamping, above) does NOT carry ICMP type/code. The
type-constrained `junos-icmp-ping` and custom ICMP applications therefore do
not ship protocol-only catalog rows (which would overmatch); protocol-only
`junos-ping` / `junos-icmp-all` rows can still resolve to the same `app_id` for
`show security flow session` display — cosmetic naming, not enforcement.

## What's parsed but not implemented

These config paths are accepted at commit time and their
runtime effect is the L3/L4 catalog classification above
(catalog ship + per-session `app_id` stamp + name resolution):

- `services application-identification` — enables catalog
  classification and toggles the show-output `UNKNOWN` vs
  port-guess behaviour for no-match sessions.
- `applications application <name>` — populates the catalog
  for port-based matching; a session matching it is stamped
  with this application's `app_id`.
  - **#2142 commit-time validation (fail-closed):** an application
    whose `destination-port` / `source-port` is malformed
    (not a valid numeric port, port range, or known service
    name, out of `1..65535`, or an inverted `low>high`
    range) or whose `protocol` is not a known name, a `junos-*`
    alias, or a `0..255` number is **rejected at commit** —
    *but only when the application is referenced by a security
    policy or a source/destination-NAT rule's `match application`
    (#2187), or when `services application-identification` is
    enabled* (every user application then compiles into the
    catalog). Such a spec was previously only WARNED: commit
    succeeded, the app-id compiler recorded the AppID name and
    then skipped the unparsable port (a never-match AppID), and a
    policy referencing it failed CLOSED on a `permit` rule or fell
    through OPEN on a `deny` rule (`validateApplicationSpecsStrict`,
    `pkg/config/compiler.go`). A source/destination-NAT rule's
    `match application` consumes the same port/proto
    (`appPortsFromSpec`, `pkg/dataplane/userspace/nat.go`), so a
    malformed app referenced only by a NAT rule used to escape both
    this commit gate and the #2124 runtime gate, silently
    never-matching (or over-matching) the NAT term; #2187 closes that
    by collecting NAT-rule references into the same strict walk
    (static NAT carries no `match application`, so only source and
    destination NAT rule-sets are walked). At the dataplane the
    source-NAT `match application` term enforces the application's
    **protocol, destination-port, AND source-port** (#3429 carried
    protocol + destination-port; #3491 added the source-port axis —
    `buildSourceNATAppTerms` / `SourceNatAppTerm::l4_matches`); each
    axis is AND-ed, and an axis whose configured spec coalesces to no
    representable port fails CLOSED (never-match sentinel) rather than
    widening to match-any. The **destination-NAT** `match application`
    term reaches the same parity (#3437): in addition to the protocol
    and destination-port it already keyed on, the DNAT snapshot now
    carries the application's **source-port** (H10,
    `MatchSourcePorts`) and **ICMP/ICMPv6 type[,code]** (H11,
    `MatchICMPType` / `MatchICMPCode`), enforced by
    `DnatEntry::l4_extra_matches` in `nat/destination.rs`. Before
    #3437 a `match application junos-icmp-ping` DNAT rule published its
    VIP for **every** ICMP type (errors, replies, non-echo) and every
    source port — a fail-open widening that regressed the #3020/#3194
    ICMP type/code parity already enforced on the policy path. The
    source-port axis carries the same never-match sentinel as the
    source-NAT path (an out-of-range configured source-port fails
    CLOSED), and an ICMP-type-constrained DNAT entry fails CLOSED for a
    non-ICMP packet. An **unreferenced** application with
    app-id disabled is not matchable by anything, so its malformed
    spec stays a *warning* (the operator can iterate on a
    not-yet-wired application library). This is the
    application-DEFINITION sibling of #2124's policy-app-term
    fail-closed gate. On the tolerant LOAD / peer-sync path the
    error is downgraded to a warning (no-brick, #1960/#2008
    doctrine): an already-persisted/synced config carrying a bad
    referenced app still BOOTS — the dataplane independently skips
    the bad port and the #2124 runtime capability gate
    (`expandUserspacePolicyApplications`) fails the snapshot closed
    (`ForwardingSupported=false`) for a referenced app it cannot
    represent, so the leniently-loaded bad app is inert rather than
    silently mis-matching.
  - **#3434 undefined / empty-set NAT `match application` (fail-closed,
    Codex audit 095 H07/H08):** distinct from #2142 above, which
    validates the SPEC of a DEFINED app — this gate
    (`validateNATMatchApplicationsStrict`) rejects a source- or
    destination-NAT `match application <name>` whose NAME resolves to no
    predefined/user application and no NON-EMPTY application-set: an
    UNDEFINED token (H07, a typo / dangling reference) or a defined-but-
    EMPTY application-set (H08). It is the NAT analog of the policy
    #3144/#3146 gate. Before #3434 such a reference resolved to zero
    application terms and the DNAT builder fell THROUGH to its
    explicit-match fallback (`protocol="" + destination-port 0`),
    publishing the pool VIP for **every** flow to the destination — a
    fail-open wildcard translation. The commit-time gate hard-rejects on
    the strict path (naming the NAT kind, rule-set, rule, and the
    unresolved token); on the tolerant LOAD / peer-sync path it is
    downgraded to a warning (#1960 no-brick). The dataplane is now an
    independent backstop: the source-NAT builder already emits a
    `natProtoNever` never-match term and the destination-NAT builder now
    emits the #3437 source-port never-match sentinel
    (`natNeverMatchPortRange`) for a configured-but-unresolvable app, so
    a leniently-loaded bad reference fails CLOSED (matches nothing)
    rather than widening to the wildcard VIP.
  - **#3109 protocol-less application (fail-closed):** a custom
    application with a port (or any spec) but **no `protocol`** is
    likewise **rejected at commit** under the same referenced-only
    scope. Junos requires `protocol` for a usable application, and the
    userspace matcher keys every term on a protocol *number*
    (`appid.ProtocolNumber`) plus the port — a port is meaningless
    without a protocol. `compileApplications` defaults a protocol-less
    application to the empty protocol (`protocols = []string{""}`),
    which is unrepresentable on **both** sides: the Go capability gate
    (`normalizeUserspaceApplicationProtocol("")` →
    `expandUserspacePolicyApplications` `ok=false`) trips #2124's
    refuse-to-arm and sets `ForwardingSupported=false` for the **whole**
    userspace dataplane — so *one* protocol-less app used to silently
    disable security-policy enforcement for the entire config (a
    system-level fail-OPEN, traffic falling to the kernel slow path) —
    and the Rust snapshot builder hard-errors
    `SnapshotIntegrityError::UnrepresentableApplicationProtocol`
    (`parse_protocol("") => None`). The commit gate
    (`validateApplicationSpecsStrict`) now names the one offending
    application, so a NEW config can no longer reach the dataplane and
    disable everything at apply time. **Caveat — the lenient/HA-sync path
    is NOT yet isolated (#3261):** on the tolerant LOAD / peer-sync path
    the error is downgraded to a warning (no-brick) so an
    already-persisted / older-peer-synced config still BOOTS, but the
    #2124 runtime gate is COARSE — an unrepresentable application still
    makes `deriveUserspaceCapabilities` set `ForwardingSupported=false`
    for the **whole** userspace dataplane, disarming userspace forwarding
    and falling back to the kernel slow path (a system-level fail-OPEN).
    So one protocol-less app on the lenient path STILL disables
    enforcement globally; the strict commit gate is the real fix (it
    stops such an app from ever being committed). Per-policy fail-closed
    isolation of the lenient path is design-sensitive — a clean
    per-policy *drop* is fail-open for deny rules, conflicting with the
    deliberate #2124 whole-snapshot-reject fail-closed family — and is
    tracked in #3261.
  - **#3320 malformed inactivity-timeout / timeout (fail-closed):** an
    application's `inactivity-timeout` / `timeout` leaf used to be an
    untyped schema leaf with no integer validation. A malformed value (a
    unit suffix like `30s`, a non-numeric like `thirty`, a negative, or an
    out-of-range integer) **committed cleanly** and was then **silently
    dropped** by `compileApplications` (the `strconv.Atoi` error was
    ignored), leaving `InactivityTimeout` at its zero default — which the
    userspace serializer (`clampNonNegU32`,
    `pkg/dataplane/userspace/capabilities.go`) treats as "use the global
    per-protocol timeout". The operator's intent to age a sensitive
    application early was silently lost (the per-application #3227 timeout
    above never engaged). It is now **typed and validated** at two layers,
    each with the #1960 strict-commit / lenient-load downgrade: (1) the
    schema typed leaf (`schema_security.go`, `ValueInteger` +
    `ValidateInteger(0, 86400)`) rejects a malformed **top-level** value at
    commit-check for every application via the `SchemaValidate` gate; (2)
    `validateApplicationSpecsStrict` rejects a malformed top-level **or
    inline-`term`** timeout of a **referenced** application (the inline-term
    shape is opaque to the schema walk) using the raw token
    `compileApplications` records in `Application.UnknownTimeouts` (mirroring
    `UnknownActions` / `UnknownFlexMatch`). On the tolerant LOAD / peer-sync
    path both layers downgrade to a warning (no-brick) so an
    already-persisted / older-peer-synced config carrying a bad timeout
    still BOOTS — the dataplane already falls back to the global timeout for
    it. The accepted range is **`0..86400`** seconds, where **`0` is the
    pre-existing inherit-global sentinel** (the dataplane treats
    `InactivityTimeout <= 0` as "use the global per-protocol timeout",
    `clampNonNegU32` / `capabilities.go`; `types_security.go` documents `0 =
    default`), so `inactivity-timeout 0` keeps committing cleanly. Only
    non-numeric, negative, and `>86400` values are rejected.
- `applications application-set` — expands into individual
  applications at compile time. Members may be either
  `application <name>` references or nested
  `application-set <name>` references; `ExpandApplicationSet`
  recurses into nested sets (max depth 3) so a policy matching a
  parent set also matches applications defined only in a nested
  child set. (Before #2068 the compiler silently dropped nested
  `application-set` members, so such a policy under-matched.)
  A referenced set is resolved through `config.ResolveApplicationSet`
  (user-defined sets first, then the built-in `junos-defaults`
  bundle table `PredefinedApplicationSets` — junos-ms-rpc,
  junos-sun-rpc, junos-cifs, junos-routing-inbound, #4102).
  `CatalogNames` (AppID-disabled catalog) and BOTH NAT snapshot
  builders (`buildSourceNATAppTerms` / `buildDestinationNATSnapshots`,
  `pkg/dataplane/userspace/nat_source.go` / `nat_destination.go`)
  go through that same predefined-set-aware lookup, so a strict
  predefined bundle named in a security policy OR a source/destination
  NAT `match application` expands to the SAME member applications on
  every path. (Before #5629 the catalog and the two NAT builders gated
  set expansion on a bare `cfg.Applications.ApplicationSets[name]` map
  membership test, which only sees user-defined sets: a predefined
  bundle was recorded as a bare app name in the catalog and resolved to
  ZERO terms in NAT — the SNAT rule failed closed to `natProtoNever`
  and the DNAT rule to the #3434 never-match sentinel, silently never
  translating. A user application whose name shadows a predefined-set
  name still wins — the application is resolved first, matching the
  policy path `resolveUserspaceApplicationNames`.)

These config paths are accepted with NO runtime effect today
(parse-only):

- `services application-identification application-system-cache`
- `services application-identification download`
- `services application-identification global-offload`
- `services application-identification statistics`
- `applications application <name> signature ...` (custom
  L7 signatures — config schema present, runtime is port-only)

## What is missing vs Junos vSRX

The vSRX feature set under `services
application-identification` includes a full Junos AppID engine:

| Feature | xpf today | Junos vSRX |
|---|---|---|
| Port + protocol matching | ✅ implemented | ✅ |
| L7 DPI signature engine | ❌ not implemented | ✅ identifies 4000+ apps |
| Signature package download | ❌ not supported | ✅ `request services application-identification download` |
| Application System Cache | ❌ not supported | ✅ caches per-flow-tuple results |
| Custom L7 signatures | ❌ not supported (parse-only) | ✅ user-defined byte-pattern matching |
| Dynamic-application policy match | ❌ not implemented | ✅ `match dynamic-application` |
| AppTrack logging | ❌ not implemented | ✅ |
| Application Firewall (AppFW) | ❌ not implemented | ✅ |
| Application QoS (AppQoS) | ❌ not implemented | ✅ |
| Application Policy-Based Routing (APBR) | ❌ not implemented | ✅ |

These are tracked in `docs/feature-gaps.md` under "AppSecure
suite". A real L7 DPI engine is a multi-month effort
(signature compiler, packet-payload state machine, signature
package format, on-the-fly download/auto-update).

## Future direction

If full L7 AppID parity is required, the implementation path
would be:

1. **L7 DPI signature engine** — a packet-payload state
   machine driven by signature definitions. Either home-grown
   or via integration of an existing library (e.g.
   `nDPI`, `libprotoident`).
2. **Signature package format** — Junos uses a binary
   signature package downloaded from a server URL. xpf would
   need a compatible packaging format AND a compiler from
   per-application signature definitions to runtime byte
   patterns.
3. **Application System Cache** — a `(5-tuple, app_id)` cache
   that bypasses L7 inspection for already-classified flows.
4. **Dynamic-application policy match** — wire L7 app_id back
   into the policy lookup path, allowing policies to filter
   on the L7 result (currently policy app match resolves to
   the catalog port-based app_id at session-create time).
5. **AppTrack / AppFW / AppQoS** — per-feature runtime hooks
   that consume the L7 app_id.

This is out of scope for #653; #653 is purely the
contract-clarification piece. If/when this work is taken up,
file a fresh issue with the L7 engine architecture as the
starting point.
