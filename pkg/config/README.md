# pkg/config

Junos configuration parser, AST, typed data model, and compilation
pipeline. Three phases: text → AST (`ConfigTree`) → typed `Config` struct.
Handles both hierarchical (`family inet { dhcp; }`) and flat set
(`set interfaces eth0 unit 0 family inet dhcp`) syntaxes.

This is the foundation almost every other package imports. It depends on
nothing internal.

## Entry points

- `Lexer` — `lexer.go`. Bracket-list delimiters (`[ a b c ]`) are stripped
  **iteratively** in the leading whitespace/comment loop of `Next()`, not via
  self-recursion — see the recursion-bound note below.
- `Parser` — `parser.go`. **Hierarchical** input. Block nesting is capped at
  `maxParseDepth` (256) — see the recursion-bound note below.

**Recursion and size bounds are load-bearing security guards (H-2).** The
lexer and recursive-descent parser are reachable, unauthenticated, from the
localhost gRPC/REST config-load API AND the HA peer config-sync ingress
(`configstore.Store.SyncApply`). A single sub-4 MiB payload of consecutive
`[` (the lexer once recursed one goroutine-stack frame per bracket) or a
deeply nested `a{a{…}` brace payload (the parser had no depth guard) grew the
goroutine stack past Go's 1 GiB `maxstacksize` and aborted xpfd with
`fatal error: stack overflow` — an unrecoverable runtime throw, not a
recoverable panic. Three layers now bound this: (1) the lexer strips brackets
iteratively (O(1) stack); (2) `parseStatements` caps nesting at
`maxParseDepth` (256, far above any real Junos hierarchy), recording one
`ParseError` and draining the over-deep block via the non-recursive
`skipToBlockClose` past the cap; (3) `configstore.MaxConfigSize` (16 MiB)
rejects an over-large payload before `NewParser`, backed by
`grpc.MaxRecvMsgSize` and `http.MaxBytesReader` at the two transports. Do NOT
reintroduce `return l.Next()` bracket recursion or remove the depth cap.
Regression coverage: `pkg/config/parser_recursion_dos_hb164_test.go`,
`pkg/configstore/config_size_ceiling_hb164_test.go`,
`pkg/api/config_load_bodycap_hb164_test.go`,
`pkg/grpcapi/server_recvsize_hb164_test.go`.

**Retained-diagnostic cap is a fourth guard (#5827).** The parser records one
`ParseError` per bad token; an all-invalid payload (up to `MaxConfigSize`)
otherwise pins ~16 million `ParseError` structs — each holding a formatted
message string — LIVE at once, an unbounded-heap OOM DoS reachable from the
same unauthenticated config-load / HA-sync ingress. `addError`/`addErrorf` now
cap the RETAINED diagnostic set at `maxParseErrors` (64): past the cap they
count the drop in `Parser.suppressed` (and skip formatting) instead of
appending, and `Parse` folds the count into ONE deterministic trailing
`additional parse errors suppressed (N)` diagnostic — so `len(errs)` is bounded
to `maxParseErrors+1` and the retained heap to O(cap) regardless of input size.
The first ≤64 diagnostics keep their parse order + line/column. The lexer still
drains the whole input O(input) for deterministic termination (only the
parser's RETENTION is capped), mirroring the `skipToBlockClose` depth-cap
suppression. `ParseSetVerb`/`ParseSetCommand` (flat-set) are already bounded —
they return on the FIRST bad token. Do NOT remove the cap. Regression coverage:
`pkg/config/parser_error_cap_5827_test.go` (16 MiB bound + retained-heap budget
+ ordering + depth×token interaction + `FuzzParseErrorBound_5827`),
`pkg/configstore/parse_error_cap_5827_test.go` (load-path concise-error /
no-partial-apply).

**The AST itself is a fifth guard (#8597).** #5827's own words are the hole:
*"only the parser's RETENTION is capped"*. The TREE was not, and a
VALID-syntax payload produces zero diagnostics, so it passes the #5827 cap by
construction. Measured (`runtime.MemStats.HeapAlloc` after GC, tree alive):

```
stmts=10000    live heap  1,824,960   -> 182 B/statement
stmts=100000   live heap 18,589,296   -> 185 B/statement
stmts=500000   live heap 92,647,960   -> 185 B/statement
```

Linear, roughly 60x the input bytes for a minimal `a;` statement — so the
16 MiB `MaxConfigSize` ceiling admits ~5.6M statements and about a GIGABYTE of
live AST, built before any gate runs. `configstore.CheckText` validates a
day-0 config-drive blob on first boot with no operator involved; the same
parser sits behind load/commit and HA config-sync.

Neither earlier guard covers it: `maxParseDepth` bounds STACK and a flat
`a;a;a;…` payload never nests, and the group-expansion budget runs after the
tree already exists.

`maxParseNodes` (200,000) bounds nodes BUILT, parser-wide rather than
per-block, and `noteNodeBudget` records one deterministic diagnostic. That
diagnostic is appended DIRECTLY, bypassing `maxParseErrors`, for the same
reason the suppressed-count summary is: a hostile payload can exhaust both
caps, and the one error explaining why the tree is truncated must never be the
one that gets dropped — a truncated tree with no error is silently accepted as
the whole configuration.

**The number is chosen against real configurations, not against the input
ceiling.** The largest configuration in this repository
(`test/incus/xpf-test.conf`) is 250 statements and the largest shipped one
(`docs/ha-cluster-userspace.conf`) is 120; the cap is ~800x the former and
bounds the live AST to about 37 MB. Deriving it from `MaxConfigSize` would
defeat the purpose — 16 MiB of minimal statements IS 5.6M nodes. Regression
coverage: `pkg/config/parse_node_budget_8597_test.go` (bounded-heap ratio with
a positive control, the diagnostic-cap interaction, a
10x-real-configuration over-reach control, and the parser-wide-vs-per-block
distinction).
- `ParseSetCommand(input string) ([]string, error)` — `parser.go`.
  Parses one flat-set line into the path components. The caller then
  applies that path with `tree.SetPath()` to build the AST.
- `ConfigTree` — `ast.go`. Hierarchical node tree built by both shapes.
  `ast.go` owns the AST node types (`Node`, `ConfigTree`) and tree
  navigation/mutation helpers — the parser's data model.
- `setSchema` + `schemaNode` — `schema.go` (split out of `ast.go` in
  #1699). The config-mode grammar SSOT; see `docs/config-schema.md`.
  Completion / path-resolution helpers (`CompleteSetPath`,
  `CompleteSetPathWithValues`, `ResolveConsumedSetPathTokens`) live in
  `schema_complete.go`.
- `Config` — `types.go`. The fully typed result every consumer wants.
- `CompileConfig(tree) (*Config, error)` — `compiler.go`. AST-to-typed-
  struct walker. Clones the tree, expands `apply-groups` (with
  `${node}` fallback for cluster mode), then dispatches over AST
  nodes via a switch statement to fill the typed `Config`. Eleven
  `compiler*.go` files in this package, ~7.6K LOC total
  (`compiler.go` + `compiler_interfaces.go`, `compiler_routing.go`,
  `compiler_security.go`, `compiler_services.go`, `compiler_system.go`,
  `compiler_firewall.go`, `compiler_nat.go`, `compiler_ipsec.go`,
  `compiler_protocols.go`, `compiler_class_of_service.go`).
  Note: this is the **AST → typed Go struct** stage; the BPF-map
  compilation (zones, policies, NAT IDs, etc.) happens later in
  `pkg/dataplane.Manager.Compile`.
  This stage also performs a few **fail-closed semantic checks** that the
  `setSchema` typed-leaf gate cannot express. The firewall-filter
  `from tcp-flags` enforceability check rejects an expression the
  conjunctive dataplane matcher cannot represent — disjunction (`|`), a
  negated group (`!(...)`), an unknown flag, a dangling negation, a
  contradictory required/forbidden pair (#3076/#4714), or an
  operator-only / empty-operand / dangling-`&` expression that sets no
  flag bits (`"&"`, `"()"`, a leading/trailing/duplicated `&` such as
  `"syn &"` or `"syn && ack"`, #5455) — via `ParseTCPFlagsExpression`
  (`tcp_flags.go`). A NON-EMPTY value that parses to no flag bits (or that
  silently drops a dangling `&`) is distinct from a legitimately-ABSENT
  value (empty / whitespace, which stays `ok=false` with no error, i.e.
  "no tcp-flags constraint"): the former must ERROR, the latter must not.
  Before this gate such an expression committed cleanly and the constraint
  was silently dropped on the wire (the term matched regardless of flags —
  a fail-open hole); a representable expression such as `syn & !ack` is
  parsed into required-bits + forbidden-bits masks and carried to the
  dataplane.
  **#4953:** this reject (and the class-of-service numeric DSCP/PCP
  code-point range reject #2447) moved OUT of the section compilers
  (`compileFirewall` / `compileClassOfService`, which the P4 dispatch
  calls with no `compileOpts` so they cannot be mode-gated) and became
  strict/tolerant gates: `validateFirewallTCPFlagsStrict`
  (`compiler_validate_strict_filter.go`, run in `runUniformGates`) and the
  `lenientCoSNumericCodePoint`-gated call sites in `compileClassOfService`.
  Commit / commit-check stay strict; the tolerant `Store.Load` /
  `Store.SyncApply` path (`lenientFirewallTCPFlags` /
  `lenientCoSNumericCodePoint`) downgrades to a warning so a config an
  older binary persisted — or a peer authored — before the reject existed
  cannot blackout-boot a node or alarm-loop HA config sync (#1960
  no-brick). The leniently-loaded tcp-flags term keeps its raw value,
  which the userspace snapshot builder marks `TCPFlagsUnparseable` to fail
  the term CLOSED (#3367) — a deny sentinel, never a match-all widening;
  the out-of-range code-point entry is dropped (the pre-#2447 fail-safe).
- `ValueType` — `value_type.go`. Classifies a typed leaf's value
  (`ValueRate`, `ValueByteSizeOrPercent`, `ValueEnumOf`, ...) and supplies
  the `?`-completion placeholder via `Placeholder()`. Lives here (not
  cmdtree) so `setSchema` can carry typed-leaf metadata directly;
  `pkg/cmdtree` re-exports it via aliases. See `docs/config-schema.md`.
- `SchemaValidate(tree, cfg)` + the generic walker — `schema_walk.go`.
  The #1319 commit-check gate. Descends `setSchema` against the AST (the
  SAME tree the live config-mode `set ... ?` completer walks via
  `CompleteSetPathWithValues`) and invokes each typed leaf's validator on
  its value. It is a no-op for untyped subtrees (opt-in per leaf), so
  per-subsystem typing lands incrementally without touching this walker.
  Called by `pkg/configstore.compileTree` on the apply-groups-expanded
  clone BEFORE compile, so garbage like `transmit-rate asd` fails loud at
  `commit check` even when it arrives through `groups { ... }`. (Re-homed
  from `pkg/cmdtree.SchemaValidate` in #1319 PR 1.) The gate is strict
  ONLY on the commit/commit-check path: the tolerant `Store.Load` /
  `Store.SyncApply` ingress (`compileTreeLenient`) downgrades a violation
  to a warning so a stored or peer-synced config carrying a value typed
  or range-tightened after it was persisted cannot blackout-boot a node
  or alarm-loop HA config sync (#1319 PR 2 boot safety).
- `Validate*` functions — `schema_validators.go`. Stateless string
  validators (`ValidateRate`, `ValidateByteSize`,
  `ValidateByteSizeOrPercent`,
  `ValidateInteger(min,max)`, `ValidateEnum(allowed)`,
  `ValidatePercent(min,max)`) for the typed-leaf gate. Attached to
  `setSchema` leaf `validator` fields (and `cmdtree.Node.Validator` for
  operational leaves) and dispatched by `SchemaValidate` at commit-check
  time, on the same apply-groups-expanded tree the compiler consumes, so
  garbage like `transmit-rate asd` fails loud instead of silently zeroing
  in the existing parsers. Scheduler `buffer-size` validation accepts byte
  sizes with explicit suffixes and percent values with an explicit `%`
  suffix. The compiler stores percent values separately from
  `BufferSizeBytes`; the userspace snapshot adds `buffer_size_percent`
  while preserving the legacy `buffer_size_bytes` field. The Rust
  userspace dataplane resolves percent buffers against the interface CoS
  burst pool when a scheduler is bound to an interface queue. The strict
  config pass rejects scheduler-map percent totals above 100% on one
  interface unit. xpf rejects Junos `0%` intentionally because the
  additive wire field uses zero as the legacy absent value.
  `parseBandwidthLimitStrict` / `parseBurstSizeLimitStrict` /
  `parseScaledDecimalUnitStrict` in `compiler_protocols.go` are the
  error-returning siblings of the legacy zero-return parsers — the legacy
  versions keep their "unset = 0" contract for compatibility.

## Node modifiers

- `inactive:` (`#2008` H1) — the Junos deactivate-without-delete marker.
  An operator deactivates any statement by prefixing it with `inactive:`;
  the node stays in the tree (it displays in `show configuration`,
  persists through commit/reboot, syncs to the HA peer, and can be
  re-enabled later) but is EXCLUDED from compilation/application — the
  firewall behaves as if the statement were absent. Because `:` is an
  identifier character, the lexer emits `inactive:` as a single token; the
  parser (`parser.go`) detects it as a statement's leading key and LIFTS it
  into `Node.Inactive`, leaving the node's real `Keys` (its identity)
  intact so every key match, schema walk, and group merge keeps working
  unchanged. `inactive.go` provides the single centralized strip
  (`ConfigTree.WithoutInactive`, a no-op clone-free pass when nothing is
  deactivated) that prunes inactive subtrees BEFORE group expansion and
  compilation (both `compileConfig*` entry points) and BEFORE the typed-leaf
  schema walk (`SchemaValidateWithDefinitions`). Stripping first means an
  `inactive: apply-groups foo` suppresses the inherited config, inactive
  nodes inside a `groups {}` body are pruned, the pre-expansion tunnel-id
  collision gate ignores inactive tunnel definitions, and a deactivated leaf
  with a deliberately-invalid value commits clean (Junos parks WIP). The
  ~15 compiler files and the schema gate never observe an inactive node, so
  none of them changed. All five display serializers (text, inheritance,
  set, JSON, XML) plus the `show | compare` diff re-emit the marker from the
  flag via the shared `inactivePrefix` / `xmlInactiveAttr` helpers; set form
  emits a `deactivate <path>` line (Junos `display set` convention) and
  `nodesEqual` treats a flipped `Inactive` as a difference so a pure
  activate/deactivate shows in `show | compare`. The flag round-trips
  through the persisted DB automatically — `Node.Inactive` is JSON-tagged
  `,omitempty`, so active-node on-disk output is byte-identical to
  pre-`#2008`. The `deactivate <path>` line that `display set` emits also
  round-trips through reload: `ParseSetVerb` (`parser.go`) recognizes
  `deactivate` / `activate` as real verbs and `ConfigTree.DeactivatePath` /
  `ActivatePath` (`ast_edit.go`) apply them (used by the configstore
  `LoadSet` / `LoadMerge` replay loops), so an inactive node reloads inactive
  rather than being skipped (silently reactivated) or parsed as a junk path.
  Regression coverage: `pkg/config/inactive_test.go`,
  `pkg/configstore/inactive_test.go`. The interactive standalone
  `activate` / `deactivate` config-mode verbs (editing the candidate directly,
  distinct from `load set` replay) shipped in #2051 across all four config
  surfaces (local CLI, remote CLI, gRPC, REST) on top of these primitives —
  the store wrappers `configstore.Store.DeactivateFromInput` /
  `ActivateFromInput` route through the same `applyEditLine` verb switch.
  A toggle addressed to ONE member of a node that names several
  (`deactivate ... security-zone zga` against `security-zone [ zga zgb ]`)
  is refused rather than prefix-matching and toggling the whole node,
  matching #8992's delete refusal (#9793, `deactivate_packed_member_9793.go`).
  Two addresses still toggle the node: a path naming every key (the grouped
  line `display set` emits) and a path ending at a statement whose own
  content is packed behind it (`security-zone trust screen edge tcp-rst;`).
  A LATER member of a bracketed group (`zgb` in `security-zone [ zga zgb ]`)
  resolves to the group for a path-scoped `show`, as the first member always
  did, and `delete`, `deactivate` and `activate` refuse it with the same
  re-author guidance instead of reporting no node (#9799). Bracket provenance
  (`Node.KeyBracketed`) decides membership, so a packed body is never read as
  a member.

## Callers

Almost everyone. The package has no internal dependencies.

## Gotchas

The compiler must accept both AST shapes:

- Hierarchical `family inet { dhcp; }` lowers to `Node{Keys:["family","inet"]}`
  with a child `Node{Keys:["dhcp"]}`. **Flat `set interfaces eth0 unit 0 family
  inet dhcp` lowers to the IDENTICAL tree** — `SetPath` descends a `compoundKey`
  container exactly as the parser does (#8808).
- **The variable is BRACING, not flat-vs-hierarchical**, and there are three
  shapes:

  | spelling | tree |
  |---|---|
  | `family inet { dhcp; }` | `[family inet]` + child `[dhcp]` (COMPOUND) |
  | `family { inet { dhcp; } }` | `[family]` → `[inet]` → `[dhcp]` (SPLIT) |
  | `family inet dhcp;` | `[family inet dhcp]` (PACKED, the #2419 class) |

If you only handle one shape, one spelling will look fine and another will
silently drop the value. The SPLIT form is where a bare `Node{Keys:["family"]}`
with an `inet` child comes from — a separately braced family, never a `set`
command. Believing the flat form has a different shape is how a defect proven
against the compound shape gets assumed not to apply to `set` input; it does
(#8763, #8797).

**Testing flat-set syntax:** ALWAYS use `ParseSetCommand()` + a
`tree.SetPath()` loop, NEVER `NewParser()` on a multi-line set blob. The
parser treats newlines as whitespace and merges multiple set lines into
one giant node. This trap has bitten the project repeatedly — see
CLAUDE.md.

**A stanza's members can live on the STANZA's own Keys, not only in its
children (#6525).** The dual-shape rule above has a third shape that is easy
to miss because `set` cannot produce it: the hierarchical COMPACT LEAF.
`security zones security-zone <z> interfaces ge-0/0/1.0;` lowers to
`Node{Keys:["interfaces","ge-0/0/1.0"]}` with **nil Children**, so a compiler
arm written as `for _, x := range prop.Children` runs ZERO times and the
stanza compiles to nothing — silently. For zone membership that meant a zone
with no interfaces at all: the interface was never AF_XDP-bound (it kept
`Zone == ""`), every policy naming the zone applied to nothing, and both
strict zone gates passed VACUOUSLY because they iterate the empty
`zone.Interfaces`. When you add a compiler arm for a container stanza, read
`prop.Keys[1:]` as well as `prop.Children` — and when the member can carry a
BODY (here `host-inbound-traffic`), exclude the body from the member names in
BOTH positions, or the fix trades a silent drop for a silent invention.
`compileZones` normalizes the compact shape onto the block shape
(`zoneInterfaceMemberNodes`, `compiler_security_zones.go`) so there is one
read path, and `validateZoneInterfacesNonEmptyStrict`
(`compiler_validate_strict_zones.go`) rejects a content-bearing stanza that
still compiles to zero members. See `docs/config-schema.md` "The COMPACT-LEAF
spelling…".

**A bracket tail does not always collapse onto one Keys slice — a schema-named
keyword makes `SetPath` DESCEND instead (#6735).** `set ... interfaces [ a b c ]`
collapses `b c` onto one leaf under `a` only because none of them names a child
the schema declares at that position. Put a declared keyword in the list and
`SetPath` descends it, parking everything after it a level DEEPER:
`[ a host-inbound-traffic b ]` becomes the chain `interfaces -> a ->
host-inbound-traffic -> b`. A reader that skips body keywords by NAME then skips
`b` with them. So when a stanza's grammar has both a member slot and named body
keywords, a validator over that stanza has to inspect the keyword node's SUBTREE,
not only the Keys around it. See `docs/config-schema.md` "A body keyword with
dropped tokens after it is REJECTED".

**Interface-name canonicalization is not injective (#5832).**
`LinuxIfName` only replaces `/` with `-`, so the DISTINCT authored names
`ge-0/0/0` and `ge-0-0-0` collapse to the SAME Linux device / ifindex.
Each authored interface still emits its own forwarding-snapshot row (zone,
routing-instance, host-inbound, NAT, address, tunnel), but the Rust
forwarding-state builder keys by ifindex and OVERWRITES the earlier row —
the lexicographically later name silently wins, hijacking that device's
security-zone / routing identity. `validateInterfaceNameCollisionStrict`
(`compiler_validate_strict_ifname_collision.go`, wired into
`runUniformGates`) hard-REJECTS such a collision — and a canonical name over
the kernel IFNAMSIZ limit (15 bytes) — on the strict commit / commit-check
path, naming both authored names, the shared device, and the winner. The
tolerant load / peer-sync path downgrades to a warning
(`opts.lenientIfNameCollision`, #1960 no-brick) so a grandfathered config
still boots but the overwrite is no longer silent. The fix is a GATE, not a
remapping: `LinuxIfName`'s mapping is unchanged, so every existing
single-name config compiles exactly as before.

**The authored interface-name set is NOT the kernel device-name set (#6964).**
The #5832 gate above compares AUTHORED names only, which is not the whole
population of device names a config claims. A logical unit that carries its own
`tunnel` stanza gets its OWN Linux device, named by `compileInterfaces` as the
interface's canonical name plus `u<unit>` for unit > 0 and stored verbatim in
`unit.Tunnel.Name`. So `gr-0/0/0 unit 1` needs the device `gr-0-0-0u1`, which is
byte-identical to the canonical name of an interface an operator is free to
author as `gr-0/0/0u1` — `u` and digits are ordinary allowed characters
(`ValidateInterfaceName`, #6834). The two AUTHORED keys (`gr-0/0/0u1` and
`gr-0/0/0`) are distinct, so the authored-only walk never saw them touch and the
config compiled with `err == nil`.

The consequence is at the routing layer. `pkg/routing` keys ALL of its
per-device state by `TunnelConfig.Name` (`tunnel.go`): the desired/owned set
(`desired[tc.Name]`), the applied-address set (`appliedAddrs[tc.Name]`), the
VRF claim (`appliedRI[tc.Name]`), and the keepalive runner. The two records
collapse to ONE entry in `desired` and then reconcile the SAME device TWICE
within one `Apply`. The second pass runs `reconcileLinkAddrsLocked` against the
first pass's applied set, which `AddrDel`s every non-link-local address on the
device that is absent from the second record's `Addresses` — the two records
delete each other's addresses off the shared device — and rewrites its VRF
claim and keepalive runner on top. Which record is "second" is the
`cfg.Interfaces.Interfaces` MAP order (`collectAppliedTunnels`, `pkg/daemon`),
and BOTH orders were observed within a single process (measured 174/26 over 200
calls), so there is no stable winner.

Scope of that claim, checked rather than assumed: the endpoint-comparing
delete+recreate in `applyKernelTunnelLocked` (`legacyTunnelMatches`) is NOT the
production path — the daemon always sets `AnchorOnly`, so `applyAnchorLocked`
runs and `anchorReusable` ignores tunnel endpoints, reusing the TUN in place.
The name-keyed address / VRF / keepalive overwrite is common to both paths; the
additional link flap belongs to the standalone-CLI path only.

`validateInterfaceNameCollisionStrict` therefore compares the EFFECTIVE
DEVICE-NAME SET: every authored canonical name PLUS every per-unit tunnel
device name, with the same IFNAMSIZ length check applied to the derived name
(a base that fits can have a `u<unit>` derivative that does not, and that
device silently never materializes). Two rules keep it from over-rejecting:

- a unit whose tunnel device name IS its interface's own canonical name is
  SKIPPED — that is `unit 0`, which collapses onto the base device by design;
  reporting it would refuse the ordinary single-tunnel config.
- the walk reads the compiler-ASSIGNED `unit.Tunnel.Name` rather than
  re-deriving `base + "u" + N`, so the gate cannot drift from the naming scheme
  it polices.

Same strict/lenient split as #5832 (`opts.lenientIfNameCollision`): the shape
was reachable in an already-committed config, so the tolerant load / peer-sync
path WARNS naming the collision rather than bricking a config that predates the
gate (#1960). The tolerant path makes the collision visible; it does not repair
it.

**Present-but-nil interface/unit slots — walk via `RangeInterfaces` /
`RangeUnits` (#5813).** The tolerant load / HA config-sync path admits a
present-key/nil-value `InterfaceConfig` (`cfg.Interfaces.Interfaces["ge-0/0/0"]
= nil`) or `InterfaceUnit` (`ifc.Units[7] = nil`) — same #3494/#5068 no-brick
tolerance as the policy/zone nil cases above. A raw `for _, ifc := range
cfg.Interfaces.Interfaces { for _, unit := range ifc.Units { unit.Number … } }`
nil-derefs on such a slot and panics the in-process daemon during a routine
read-only presentation (`show security flow session`, gRPC `GetSessions`, REST
`/sessions`). `RangeInterfaces(cfg, fn)` and `RangeUnits(ifc, fn)`
(`interfaces_iter.go`) are the shared nil-safe walk: they skip the nil slots (and
no-op on a nil `cfg`/`ifc`), so every read-only presenter that walks the
interface tree stays panic-safe with the guard in ONE place. The three session
egress-interface map builders (CLI `buildSessionEgressIfacesWithLookup`, gRPC
`buildSessionFilter`, REST `buildSessionView`) route through them, and #5910
extended the same walk to the show presenters that the first pass missed —
`showVLANs` (gRPC `show vlans`) and the `show security zones` detail renderers
(gRPC `showZonesDetail`, CLI `showZonesDisplay`), where a bare
`ifc, ok := …Interfaces[name]` proved key presence but not a non-nil value.
#5913 extended it once more to the `show interfaces extensive`/`detail` text
presenters (gRPC `showInterfacesExtensive`/`showInterfacesDetail`), whose
config-map builders (`ifCfgMap`/`ifDescMap`) still carried the same raw
`range cfg.Interfaces.Interfaces` reading `ifc.Name`/`ifc.Description`. New
interface-tree presenters should route through these helpers too rather than
reintroducing a raw range.

**Comments (`# ...`, `// ...`, `/* ... */`) and unterminated blocks
(M-8):** the lexer (`skipWhitespaceAndComments`) skips `#`/`//` line
comments to end-of-line and `/* */` block comments to their closing
`*/`. An **unterminated** `/*` — one that reaches EOF with no closing
`*/` — used to be swallowed silently to end-of-input, dropping every
stanza after it while `Parse()` reported zero errors: one typo'd comment
could delete an arbitrary tail of the config (e.g. security policies) and
still `commit` successfully — a fail-open config-integrity path. The
lexer now stashes a `TokenError{"unterminated block comment"}` (keyed to
the opening `/*` line/column, mirroring `readString`'s "unterminated
string"), surfaced via `Lexer.pending` at the top of `Next`, so
`parseStatements` records a `ParseError` and the load/commit paths reject
the truncated config. Single-line `/* x */` and `#`/`//` comments are
unaffected — only the unterminated multi-line block is rejected.

**Security-policy terminal action is fail-closed (#3043):** `PolicyAction`'s
zero value is `PolicyPermit`, so a policy whose `then` stanza names no
terminal action (log-only/count-only or a typo'd `then`) historically
compiled to a silent PERMIT. `validatePolicyTerminalActionStrict`
(`compiler_validate_strict.go`) hard-rejects a policy that does not name
exactly one of permit/deny/reject at commit; the tolerant load/peer-sync
path downgrades to a warning AND `compilePolicy` defaults an actionless
policy's `Action` to `PolicyDeny`, so a leniently-loaded bad config fails
closed rather than open. See `docs/config-schema.md` "#3043".

**A duplicate policy name never turns a deny into a permit on load (#9571):**
a strict commit rejects two policies that share a name in one context (#3473).
The tolerant load / peer-sync / upgrade path instead folds the repeated
`policy <name>` statements into the first occurrence (#8752,
`dup_instance_merge_8752.go`), and the merged policy takes the LAST terminal
action and the UNION of the statements' match criteria. When one statement said
`deny` or `reject` and the merged policy permits, the merge would admit traffic
that statement denied. Such a policy is still merged but is marked
`LenientContentDropped` (`markFoldWidenedPolicies9571`): the snapshot builder
poisons it, the helper refuses the whole snapshot (previous-good retained,
fresh-boot default-deny), `show security match-policies` reports the refusal,
and `commit confirmed` will not arm a rollback to it (#6707). Before the fold the
same text was refused as well, by the helper's duplicate-rule-id check. The
narrowing direction (a later `deny` over an earlier `permit`, the #8752 fixture)
still folds without poison, and so do duplicates whose actions agree. Both
compile entry points apply it; the actions are read by calling `compilePolicy`,
not by re-parsing `then`. Coverage: `dup_policy_fold_widening_9571_test.go`,
`pkg/dataplane/userspace/dup_policy_fold_widening_9571_test.go`,
`pkg/policymatch/fold_widening_9571_test.go`.

**Security-policy `then log` requires session-init/session-close (#3060):**
the schema accepts a bare `then log`, and `compilePolicy` compiles it to a
non-nil `PolicyLog` with both `SessionInit` and `SessionClose` false. The
policy then REPORTS logging enabled over REST (`pkg/api/security.go`:
`Log: rule.Log != nil`), gRPC, and CLI, yet emits NO session records — on a
security appliance, audit looks active while producing nothing. Junos
requires at least one of session-init/session-close under `then log`.
`validatePolicyLogActionStrict` (`compiler_validate_strict.go`) hard-rejects
a policy (zone-pair OR global) whose `then log` names neither at commit;
rejecting the bare form moots the REST/gRPC/CLI display divergence (no
bare-log config can exist post-commit). The tolerant load/peer-sync path
downgrades to a warning (`lenientPolicyLogAction`) so an already-persisted or
peer-synced config still boots (#1960 no-brick) — a leniently-loaded bare-log
policy simply logs nothing, exactly as before. Same fail-closed-on-load
doctrine as #3043.

**Security-policy `match application` must be defined (#3144):** a policy
`match application <name>` token resolving to NONE of {predefined junos-*
application, user-defined `applications application <name>`, user-defined
`applications application-set <name>`} was previously only WARNED at commit
(`compiler_validate_warn.go`). But at runtime the userspace capability gate
(`resolveUserspaceApplicationNames` in `pkg/dataplane/userspace/capabilities.go`)
resolves the SAME name set and returns false for an unknown name →
`expandUserspacePolicyApplications` fails → the built rule carries the reserved
`__unsupported__` sentinel term → the dataplane refuses to arm that policy
(#3261, helper integrity preflight). The operator
got a green commit and a silently DISARMED policy engine on the firewall's
primary allow/deny path — a commit/apply split, fail-open.
`validatePolicyMatchApplicationsStrict` (`compiler_validate_strict.go`)
hard-rejects an undefined reference (zone-pair OR global, including every
element of a `match application [ a b c ]` list) at commit, naming the policy
scope, the policy, and the undefined token. Resolution mirrors the runtime gate
`resolveUserspaceApplicationNames`: a name resolves only if it is a predefined /
user application (`ResolveApplication` — user apps then the predefined table)
OR an `application-set` that EXPANDS to >= 1 member (`ResolveApplicationSet` +
`ExpandApplicationSet`, the exact runtime check). `any` and the empty token are
always accepted. A defined-but-EMPTY application-set (#3146) is rejected with a
distinct message: the set resolves by name but expands to zero applications, so
the runtime gate returns false and the dataplane refuses to arm — the same
fail-open class. (#2217's `validateApplicationSetMembersStrict` `continue`s on
an empty set, so this gate is the one that catches it.) The tolerant load/peer-sync path downgrades to
a warning (`lenientPolicyMatchApplications`) so an already-persisted or
peer-synced config still boots (#1960 no-brick) — the dataplane independently
refuses the policy, so a leniently-loaded bad config is no worse off, now
flagged. Distinct from #2217 (`validateApplicationSetMembersStrict`), which
rejects a dangling MEMBER of a DEFINED application-set; this gate catches a
wholly undefined top-level reference that #2217's `ExpandApplicationSet` walk
never sees. The `compiler_validate_warn.go` application warning was removed
(converted): the strict gate supersedes it on commit and the lenient gate emits
the single warning on load — eliminating both a duplicate warning and the old
24-entry builtin list's false positive on predefined apps outside it (e.g.
`junos-pingv6`, `junos-tcp-any`). Same fail-closed-on-load doctrine as
#3043/#2401.

**Security-policy address references must fully resolve (#3149, folds #3147):**
the address-book sibling of #3144/#3146. A policy `match source-address` /
`match destination-address` that names a DEFINED address-book entry (an address
or an address-set) whose recursive members DANGLE (point at an undefined
address/address-set), or that is a defined-but-EMPTY address-set, or a defined
address with no configured prefix, was previously only WARNED at commit
(`compiler_validate_warn.go`). At runtime the userspace address resolver
(`resolveUserspaceAddressBookEntry` + `expandUserspacePolicyAddresses` in
`pkg/dataplane/userspace/capabilities.go`) returns false for the same name — a
dangling member fails the WHOLE set, an empty set never sets `resolvedAny`, a
prefix-less address has an empty Value — so `expandUserspacePolicyAddresses`
fails → the built rule carries the `__unsupported_address__` sentinel → the
dataplane refuses to arm that policy. The operator got a green commit and a
silently DISARMED allow/deny path — a commit/apply split, fail-open.
`validatePolicyMatchAddressSetMembersStrict` (`compiler_validate_strict.go`)
hard-rejects such a reference (zone-pair OR global, source AND destination,
including the recursive address-set-of-address-sets case) at commit, naming the
policy scope, policy, field, and the inner failure. Resolution mirrors the
runtime resolver EXACTLY (`policyMatchAddressBookResolves` replicates
`resolveUserspaceAddressBookEntry`'s fail-closed semantics and the outer
`len(values) == 0` reject), so the commit gate and the runtime gate cannot
diverge. `any` / `any-ipv4` / `any-ipv6` / the empty token and literal CIDR/IP
tokens are passed through; a wholly-undefined token stays the domain of
`validatePolicyMatchAddressesStrict` (#2008), which runs first. **#3147
excluded-inversion safety:** the resolver runs on the same address lists the
runtime gate checks, regardless of `*-address-excluded`, so rejecting an empty /
dangling set at COMMIT is fail-CLOSED for the excluded case too — an empty
excluded set can never be committed, so it can never reach the dataplane and
invert to MATCH-ALL (the historic fail-open this constraint guards against). The
tolerant load/peer-sync path downgrades to a warning
(`lenientPolicyMatchAddressSetMembers`) so an already-persisted or peer-synced
config still boots (#1960 no-brick) — the dataplane independently refuses to arm
such a policy, so a leniently-loaded bad config is no worse off, now flagged. The
`compiler_validate_warn.go` address-set member warning is RETAINED for the
lenient path and for unreferenced sets (which never reach the runtime gate, so
they stay warn-only). Same fail-closed-on-load doctrine as #3144/#3146.

**Warn pass must agree with strict on the valid address-reference forms
(#3958):** the non-fatal `ValidateConfig` warn pass
(`compiler_validate_warn.go`) emits a `policy … source/destination-address …
not in address-book` advisory for a policy address token it does not recognize.
It previously excluded only the bare `any` keyword and address-book entry names,
so it drew a FALSE warning for every OTHER valid reference form on a perfectly
good policy: a literal IPv4/IPv6 address or CIDR (`10.0.0.0/8`, `2001:db8::/32`),
the `any-ipv4` / `any-ipv6` wildcards, and a dynamic-address
FEED binding name (a direct #2049/#3294 reference). Spurious warnings on normal
commits train operators to ignore validation output (alarm fatigue), burying a
REAL undefined-reference warning. The strict commit gate
`validatePolicyMatchAddressesStrict` (#2008/#3294) already accepts exactly these
forms; the warn pass had drifted. The acceptance logic is now a single source of
truth — `policyMatchNamedAddressRefs` (address-book entries + feed bindings) and
`policyMatchAddressTokenRecognized` (the `any`/literal/named predicate) in
`compiler_validate_strict.go` — that BOTH the strict gate and the warn pass call,
so they cannot diverge again. The warn pass now warns only for a token that is
NONE of {`any`/`any-ipv4`/`any-ipv6`, literal CIDR/IP, feed binding, address-book
entry} — a genuinely undefined reference, which still warns (and is hard-rejected
by #2008 on the strict commit path). The address-set MEMBER validation keeps its
own address-book-only set: a feed binding nested in an address-set stays
deliberately NOT strict-accepted (#3294 anti-Option-C), so it is not added to the
member-check set.

**Policy match-all address keywords are reserved (#9523):** `any`,
`any-ipv4` and `any-ipv6` (and the internal short forms `any4` / `any6`) mean
"every address" in a policy `source-address` / `destination-address`. Junos
reserves them, so no address-book object can capture them. xpf resolved a policy
address token by NAME first, which is deliberate and stays in force for every
other token (an entry named `10.0.1.0/24` with another value is still resolved by
name). For these keywords it was a hijack: an address, address-set or
dynamic-address binding literally named `any` turned every `match ... any` in
every policy into a match on that object's prefixes, on all four config channels,
with no warning. `validateReservedAddressNamesStrict`
(`policy_address_keywords_9523.go`, run on the pristine books before the
zone-local fold) now rejects such an object at commit, naming it; the tolerant
load / peer-sync path keeps it with a warning (`lenientReservedAddressNames`,
#1960 no-brick). Every resolver asks `IsPolicyAddressWildcardKeyword` before any
name lookup: the snapshot builder (`classifyPolicyAddresses`), the
`match-policies` simulator (`resolveToken`), and the CLI / gRPC detail renderers.
So on the tolerant path the keyword keeps matching every address, and every
surface shows what is enforced. `0.0.0.0/0` remains a legal object name.

**`any-ipv4` / `any-ipv6` stay keywords until the snapshot is built (#9574):**
`compilePolicy` used to rewrite `any-ipv4` / `any-ipv6` to `0.0.0.0/0` / `::/0`
while compiling the policy (#2008 H11), BEFORE any address-book resolution. So
the keyword had already become a CIDR string by the time it was classified, and
an address, address-set or zone-local object NAMED `0.0.0.0/0` (legal in Junos
and in xpf) captured every `any-ipv4` in every policy, with a clean strict
commit. #9523's keyword check could not reach it, because by then there was no
keyword left to test. The compiled config now keeps the keyword. Every resolver
classifies it as a keyword first, and only the userspace snapshot builder
(`classifyPolicyAddresses`, and the legacy `expandUserspacePolicyAddresses`)
writes the CIDR the dataplane parses, via `PolicyAddressKeywordLiteral`. The wire
is byte-identical to before for any config without such an object. The #2008 H11
reason for the rewrite (the dataplane must receive a parseable CIDR) still holds;
only its position moved. `PolicyAddressWildcardFamilies` is now the single source
for the keyword set and its families. Name-before-literal is unchanged: a literal
`0.0.0.0/0` typed in a policy still resolves to an object of that name. `show
security policies detail` renders `any-ipv4(global): 0.0.0.0/0`, and the REST and
gRPC inventories show the keyword the operator wrote instead of the CIDR.

**An address takes one value form; a mixed entry is rejected (#9524):** a Junos
`address` is a prefix OR a `dns-name` / `wildcard-address` / `range-address`, and
xpf implements only the prefix. An entry carrying BOTH used to compile to the
prefix alone on all four config channels with no warning, so a `deny` naming the
object silently under-covered it by exactly the form that was dropped (measured:
a host named by the object's `range-address` fell through the deny to a
`permit-all` default). `mergeAddressNode` now records the form on
`Address.UnimplementedForms`, in both parser shapes, and the zone-local fold
carries it. `validateAddressUnimplementedFormsStrict` rejects the mixed entry at
commit, naming the prefix and the dropped form; the tolerant load / peer-sync path
warns (`lenientAddressUnimplementedForms`). `Address.UsableValue()` returns `""`
for such an entry, and the resolvers that decide representability (userspace
`nameRepresentability` and the junos-host deny projection) read it, so on the
tolerant path a referencing policy fails closed exactly like the sole-value case
(#2229, #3261): the `__unsupported_address__` sentinel then replaces the rule's
addresses on both wire shapes, which is why the legacy expansion needs no change. A sole
unimplemented form is valid Junos and is unchanged: warned, and strict-rejected
only when referenced (#3149). `Value` is kept, so show surfaces still render the
configured prefix. Not switched: static-NAT `prefix-name` resolution, which takes
one scalar translation target and already refuses an address with no prefix.

**Zone-local address books (#3061):** Junos supports both the global
`security address-book global { ... }` and a per-zone book attached inline
under `security zones security-zone <z> address-book { address ...;
address-set ...; }`. xpf parses the zone-local shape into
`ZoneConfig.AddressBook` (`compileZones`, same entry grammar as the global
book via the shared `parseAddressBookEntries`). Resolution order follows
Junos scoping: a policy's `match source-address` resolves against its
FROM-zone book first, `match destination-address` against its TO-zone book
first, then both fall back to the global book. `resolveZoneLocalAddressBooks`
(`compiler_security.go`, run from `compileExpanded` after the name gate below)
folds every zone-local entry into the global `SecurityConfig.AddressBook`
under a `/`-separated zone-qualified internal name (`zone-local/<zone>/<name>`)
and rewrites each policy match token that resolves zone-locally to that
qualified name. A token NOT defined in the policy's zone book is left unchanged
so it resolves against the global book. The synthetic `zone-local/` namespace
is collision-proof: the lexer permits `/` in an identifier token (needed for
IP literals like `10.0.0.0/24`), but `validateAddressBookEntryNamesStrict`
(#3061, run BEFORE the fold on the pristine global book) hard-rejects `/` in
any address-book entry name (global or zone-local) and any security-zone name
at commit — matching Junos object-naming rules — so no operator-typed name can
contain `/` and therefore none can equal a synthetic name (only the NAME is
checked, never the address VALUE/prefix; the fold also skips an already-present
key as a defence-in-depth no-clobber on the tolerant load path, which warns
rather than rejects per #1960). After this pass
the entire downstream path (wire snapshot, `nameToID`,
`classifyPolicyAddresses`, the strict/warn validators, the
`resolveUserspaceAddressBookEntry` runtime resolver) keeps operating on a
single flat global book — no zone needs to be plumbed through resolution. A
name present only in zone A's book is therefore invisible to a policy in zone
B: if B's policy references it and the global book has no such entry,
`validatePolicyMatchAddressesStrict` (#2008) rejects it at commit, exactly as
Junos treats an undefined reference. NAT rule address-name references
(`source-address-name` etc.) remain global-only; zone-local resolution is
scoped to security-policy match addresses.

**An interface belongs to exactly one security zone (#3072):**
`pkg/dataplane/userspace.buildInterfaceZoneMap` builds the interface->zone
lookup by iterating zone names in SORTED order and writing each interface
(plus its base/unit aliases) first-writer-wins. An interface listed under
two zones was therefore silently accepted at commit and resolved to
whichever zone name sorts first — independent of operator intent — so
traffic was evaluated against the wrong zone's policy.
`validateZoneInterfaceMembershipStrict` (`compiler_validate_strict.go`)
hard-rejects a config that assigns the same interface to more than one
zone, naming the interface and both conflicting zones; the tolerant
load/peer-sync path downgrades to a warning
(`lenientZoneInterfaceMembership`) so an already-persisted or peer-synced
config still boots (`buildInterfaceZoneMap` keeps its deterministic
first-writer-wins resolution, so the leniently-loaded config forwards
exactly as before). Two DIFFERENT units of one physical interface in two
zones (`ge-0/0/0.0` in trust, `ge-0/0/0.1` in untrust — a valid VLAN
split) are NOT rejected; a bare physical interface and one of its units
across zones ARE (same logical interface). Same fail-closed-on-load
doctrine as #3043/#2401.

**Backup-router destination family must match the next-hop (#2911):**
`renderBackupRouter` (`pkg/frr/config_render.go`) keys the static-route
prefix keyword (`ip` vs `ipv6`) on the NEXT-HOP family (#2891/#2907). An
explicit `system backup-router <nh> destination <prefix>` whose prefix is a
DIFFERENT family than the next-hop therefore renders a mismatched-family
static — e.g. `backup-router 2001:db8::1 destination 0.0.0.0/0` →
`ipv6 route 0.0.0.0/0 2001:db8::1 250` — which frr-reload rejects, failing
the ENTIRE static config load (the exact breakage #2907 fixed for the
empty-destination case). `validateBackupRouterDst` (`compiler_system.go`)
hard-rejects an explicit family mismatch at commit, naming both addresses
and families; the tolerant load/peer-sync path downgrades to a warning
(`lenientBackupRouterDst`) so an already-persisted or peer-synced config an
older binary accepted still boots (#1960 no-brick). An EMPTY destination is
left to #2907's next-hop-family-aware default (never a mismatch); a
matched-family explicit destination passes. Same fail-closed-on-load
doctrine as #3043.

**VRRP virtual-address must fall within a unit subnet (#3013):** a
`vrrp-group <id> virtual-address <vip>` is authored under a
`family inet|inet6 address <prefix>` on an interface unit. In Junos/vSRX a
VIP outside every on-link subnet of the unit is a commit-time configuration
error; xpf accepted it and at runtime installed the VIP as a route-less host
address — return traffic sourced from the VIP has no on-link subnet
association and silently blackholes. `validateVRRPVirtualAddressSubnet`
(`compiler_validate_strict.go`) asserts each VIP is contained in the prefix
of at least one address configured on the SAME unit for the MATCHING family.
The owner / priority-255 case (VIP equals an interface address) passes for
free (an address is contained in its own subnet); a cross-family VIP (e.g. a
v4 literal authored under a v6-only address) has no matching-family subnet
and is rejected. The strict commit/commit-check path hard-rejects naming the
interface, unit, group, VIP and family; the tolerant load/peer-sync path
downgrades to a warning (`lenientVRRPVirtualAddress`) so an already-persisted
or peer-synced config an older binary accepted still boots (#1960 no-brick).
This is config-only commit-time validation — it never touches the VRRP
runtime/state machine. Same fail-closed-on-load doctrine as #2911.

**VRRP virtual-address count must fit one advertisement (#6779):** RFC 5798
§5.2.4 makes an advertisement's "Count IPvX Addr" a single byte, so one advert
carries at most 255 addresses of a family — 254 for IPv6, where §6.1 reserves
the first slot for the mandatory link-local address `pkg/vrrp`
`sendPacketIPv6` prepends. `pkg/vrrp` `Marshal` REFUSES an out-of-range count
rather than truncating it (#5090), and `sendAdvert` discards that error at
`slog.Debug`, so an oversized set made EVERY advert fail — **after**
`becomeMaster` had already claimed the VIPs and published MASTER. The node then
owned the addresses while emitting nothing: the peer stopped hearing a master,
promoted itself, and both answered for the same addresses; with the same config
synced to both nodes, the addresses were stranded with no advertising owner.
`validateVRRPVIPCountStrict`
(`compiler_validate_strict_vrrp_vipcount.go`) rejects such a set at commit,
covering BOTH VIP sources: the explicit `vrrp-group ... virtual-address` list,
and the RETH-derived instances where a redundancy-group interface's own unit
addresses BECOME the advertised set (`CollectRethInstances`) — a gate walking
only `unit.VRRPGroups` would miss the RETH path entirely. It mirrors
`CollectRethInstances`' early return, so `no-reth-vrrp` / `private-rg-election`
(no synthesized RETH VRRP instance) is not rejected. The tolerant load/peer-sync
path downgrades to a warning (`lenientVRRPVIPCount`, #1960 no-brick); the
`pkg/vrrp` runtime guards independently refuse to build the instance
(`UpdateInstances`) and refuse to claim MASTER (`becomeMaster`), so a
leniently-loaded oversized set is held out of the election rather than seated as
a silent non-advertiser. The cap is spelled in both packages
(`MaxVRRPVirtualAddressesIPv4/IPv6` here, `MaxConfiguredVIPs` there) because
`pkg/vrrp` imports `pkg/config` and not the reverse; they are bound by a
behavioural agreement test in `pkg/vrrp` that measures what the real `Marshal`
accepts rather than pinning either side to a literal. Same doctrine as #4826.

**No-match default-policy is fail-closed (#3065):** the sibling of #3043
for the implicit fallback. When a flow matches NO zone-pair, global, or
default policy, the verdict is `SecurityConfig.DefaultPolicy`. Because the
`PolicyAction` zero value is `PolicyPermit`, an unset
`security policies default-policy` stanza historically compiled to
permit-all — fail-OPEN, the opposite of the Junos SRX
`default-security-policy` (deny-all). `CompileConfig` now initializes
`SecurityConfig.DefaultPolicy = PolicyDeny` (`compiler.go`), so an absent
stanza denies unmatched traffic. An operator opts back into the legacy
permit-all explicitly with `set security policies default-policy
permit-all`; `deny-all` and `reject-all` are the other accepted values
(`compilePolicies`, `compiler_security.go` — `reject-all` previously fell
through the switch and was silently ignored). The value is plumbed to the
userspace dataplane via the `ConfigSnapshot.DefaultPolicy` string
(`policyActionString` → Rust `parse_action` → `PolicyState.default_action`,
the no-match verdict). The `default-policy` leaf is a typed `ValueEnumOf`
in `schema_security.go`, so a bogus value fails `commit check`. See
`docs/config-schema.md` "#3065".
**Implicit default-policy RT_FLOW logging (#3534):** `set security policies
default-policy-log session-init|session-close` emits RT_FLOW session logs for
the implicit default verdict, mirroring a named policy's `then log`. It is a
SIBLING container (not `default-policy then log`) because the `default-policy`
enum leaf cannot carry `then` children (schema.go typed-leaf invariant). The
flags compile to `SecurityConfig.DefaultPolicyLogSessionInit/Close` →
`ConfigSnapshot.DefaultLogSessionInit/Close` → the Rust default-verdict result;
a default-PERMIT session then emits RT_FLOW_SESSION_CREATE/CLOSE. They are inert
under default deny-all/reject-all (no session installed — already logged via the
policy-deny record), which commit flags WARN-only. See `docs/config-schema.md`
"#3534".
**Zone screen-profile reference is fail-closed (#3066):** a security zone's
`screen <name>` that references a screen-ids-option profile the config never
defines historically committed with a warning only, and at runtime the
userspace dataplane fails OPEN — `screen/mod.rs` returns `ScreenVerdict::Pass`
for a missing profile, silently skipping every screen check for that zone while
the operator believes screening is active. `validateScreenProfileReferencesStrict`
(`compiler_validate_strict.go`) hard-rejects an undefined screen-profile
reference at commit. Unlike the policy gates the dataplane is NOT independently
safe on the tolerant load/peer-sync path (the missing profile still fails
open), so that path only downgrades to a warning to preserve #1960 no-brick
boot — the strict commit gate, which keeps a bad reference from ever reaching
the dataplane, is the real fix.

**Reserved zone names are rejected at definition (#3055):** a `security zones
security-zone <name>` whose name is a reserved sentinel — `junos-global`, `any`,
or `junos-host` — historically compiled cleanly. `junos-global` is the
device-wide global-policy sentinel: the userspace dataplane
(`userspace-dp/src/policy.rs`) string-matches a from-zone/to-zone literally
equal to `junos-global` and reclassifies the policy as a global fallback
(`JUNOS_GLOBAL_ZONE_ID = u16::MAX`) evaluated for EVERY flow, so an
operator-defined zone of that name silently turns its zone-scoped policies into
device-wide permits across unrelated zone pairs — a security-boundary escape.
(That match was on EITHER side until #9570; it now requires BOTH, and the
snapshot builder poisons a zone-pair rule that names the sentinel — see below.)
`any`/`junos-host` are reserved policy context tokens that must likewise never
be a real zone name. `validateReservedZoneNamesStrict`
(`compiler_validate_strict.go`) hard-rejects such a definition at commit. The
DEFINITION-reject set (`reservedZoneNames` = `{junos-global, any, junos-host}`)
is DELIBERATELY DISTINCT from the zone-REFERENCE exemption set
(`policyZoneSpecialTokens` = `{"", any, junos-host}`, unchanged from #2401): the
two gates are mutually reinforcing and must NOT be unified. `policyZoneSpecialTokens`
must keep OMITTING `junos-global` — a policy that *references* `from-zone
junos-global` / `to-zone junos-global` against no defined zone stays hard-rejected
(and warned) by the #2401 reference gate. Making it reference-exempt would let
the reference reach the dataplane, which (`policy.rs:1021`) then classifies it as
a device-wide global rule — re-opening the exact fail-open this gate closes.
Because the definition gate guarantees no zone named `junos-global` can exist, an
explicit `junos-global` reference is always the bug, never a legitimate
named-zone use. The tolerant load/peer-sync path downgrades the definition gate
to a warning (`lenientReservedZoneNames`) so an already-persisted or peer-synced
config an older binary accepted still boots — #1960 no-brick doctrine, same as
#3066/#2401.

**A zone-pair stanza naming `junos-global` fails closed on the tolerant path
(#9570).** The #2401 reference gate rejects `from-zone junos-global` /
`to-zone junos-global` at commit with a dedicated error that names the reserved
global-policy context instead of telling the operator to define a zone #3055
forbids (`ZonePairGlobalSentinelSide` is the shared predicate). The tolerant
load / peer-sync / upgrade path only warns, and before #9570 the stanza then
reached the helper verbatim, where `from_zone == "junos-global" || to_zone ==
"junos-global"` enforced it as a device-wide GLOBAL rule for every zone pair.
`show security match-policies` meanwhile reported the half spellings refused and
returned the default verdict for the both-sided one. Two changes close it:

- the helper classifies a rule as global only when BOTH sides carry the
  sentinel, so a half-sentinel rule takes the zone-pair arm and is refused as an
  unresolvable zone (#3402);
- the both-sided spelling is wire-identical to a real `security policies global`
  rule, so the userspace snapshot builder, the only layer that knows which list
  a rule came from, poisons every zone-pair rule naming the sentinel with the
  #5575 `__unsupported__` application sentinel. The helper refuses the whole
  snapshot (previous-good retained, fresh-boot default-deny), and
  `PolicyContentRejectionReasons` reports one dedicated reason per rule, so the
  simulator agrees for all three spellings.

A real `security policies global` rule is never asked the question and is
unchanged. Coverage: `pkg/config/zone_pair_global_sentinel_9570_test.go`,
`pkg/dataplane/userspace/policies_reject_global_sentinel_9570_test.go`,
`pkg/policymatch/zone_pair_global_sentinel_9570_test.go`,
`userspace-dp/src/policy_junos_global_9570_tests.rs`.

**Wildcard from-zone/to-zone `any` is committed AND enforced (#3090):** an
ordinary zone-pair policy whose `from-zone` or `to-zone` is the literal Junos
wildcard `any` is a first-class enforced policy. The #2401 reference gate
exempts `any` (`policyZoneSpecialTokens`) so it is not mistaken for an
undefined-zone reference, and a `security zone` named `any` is still rejected by
`validateReservedZoneNamesStrict`. The userspace snapshot builder
(`pkg/dataplane/userspace/policies.go`) carries the literal `"any"` string
unchanged for an ordinary zone-pair policy (only `security policies global` maps
to the `junos-global` sentinel), and `PolicyState::from_snapshots`
(`userspace-dp/src/policy.rs`) routes a wildcard rule into one of three
dedicated index lists keyed for O(1) lookup:

- **from-any** — `from-zone any`, concrete `to-zone`: keyed by the concrete
  to-zone id; matches a flow into that to-zone regardless of ingress zone.
- **to-any** — concrete `from-zone`, `to-zone any`: keyed by the concrete
  from-zone id; matches a flow out of that from-zone regardless of egress zone.
- **both-any** — `from-zone any to-zone any`: matches every defined zone pair.

`evaluate_policy_result_with_icmp` consults these in Junos most-specific-first
precedence: exact `(from,to)` zone pair → single-wildcard tier (from-any /
to-any merged in config order) → both-any → `junos-global` → default policy.
There is **no N×N hot-path expansion** — the wildcard tiers are FxHashMap O(1)
probes (or a small Vec scan only when such rules exist), so a config with no
wildcard policy pays only two empty-slice probes per cold-path evaluation. A
`from-zone any to-zone junos-host` rule — and a GLOBAL `policy match to-zone
junos-host` (#3639 / #3611 Piece B) — are also enforced on the host
(LocalDelivery) path (`evaluate_junos_host_policy`, most-specific-first: exact →
from-any → global); `to-zone any` / `from-zone any to-zone any` transit
wildcards are intentionally NOT applied to host-bound traffic so a broad rule
cannot silently brick the management lifeline (only a global explicitly scoped
`to-zone junos-host` is consulted). Wildcard tiers live inside the
`from_id != 0 && to_id != 0` guard, so an unzoned flow still falls through to
the default action (#3110), exactly like a global policy. This lifts the #3018
interim commit reject (`validatePolicyWildcardZoneStrict` and its
`lenientPolicyWildcardZone` downgrade, both removed). The unrelated `any` tokens
elsewhere in a policy (`match source-address any` / `match application any`) are
unaffected.

**NAT rule-set `from`/`to` `interface`/`routing-instance` scope is fully
enforced (#3096, lifts the #3079/#3095 interim reject):** Junos NAT rule-sets
scope matched traffic with a `from`/`to` clause taking one of `zone | interface
| routing-instance`. xpf originally extracted only the `zone` children, so an
`interface`- or `routing-instance`-scoped rule-set committed cleanly but had its
scope SILENTLY DISCARDED and applied GLOBALLY (translated sessions leaked across
the routing boundary — a security/isolation failure); #3095 made that an interim
commit reject (`validateNATRuleSetScopeAST`). #3096 implements the full path:

- **Capture.** `parseNATMatchScopes` / `collectNATScopes` (`compiler_nat.go`,
  generalizing the old `parseZoneList`) read `zone`, `interface`, AND
  `routing-instance` from both AST shapes (inline + child-leaf, bracket lists
  collapsed). The from/to scope lists Cartesian-expand into one
  `NATRuleSet` / `StaticNATRuleSet` per (from-scope, to-scope) pair, mirroring
  the existing from-zone × to-zone expansion.
- **Typed model.** `NATRuleSet` gains `FromInterface`/`ToInterface`/
  `FromRoutingInstance`/`ToRoutingInstance`; `StaticNATRuleSet` gains
  `FromInterface`/`FromRoutingInstance` (static NAT has only a `from` clause).
  Exactly one of zone/interface/routing-instance is non-empty per side for a
  scoped rule-set; all-empty = match-any (global), the unchanged legacy case.
- **Snapshot + dataplane match.** The scope plumbs through the userspace
  snapshot (`from_interface`/`to_interface`/`from_routing_instance`/
  `to_routing_instance`, additive #1961 wire fields) and is enforced per-flow in
  the Rust match path: `SourceNatRule::matches` AND-s the scope against the
  flow's ingress (`from_*`) / egress (`to_*`) interface config-name and routing
  instance; DNAT (`nat/destination.rs`) and static NAT (`nat/static_nat.rs`)
  gate on the ingress identity (and, for static NAT's reverse SNAT direction,
  the egress identity — symmetric with the #2871 egress-zone gate). The Rust
  forwarding layer resolves each ifindex to its config name and VRF via
  `ifindex_to_config_name` / `ifindex_to_routing_instance`.

The `from`/`to` `zone` scope and the legitimate global (no-from/to) case are
unchanged. Cross-rule-set context-specificity ordering (Junos evaluates
interface- before zone- before routing-instance-scoped rule-sets) is NOT
implemented — xpf keeps first-match-in-list across the flat rule list, identical
to the pre-#3096 zone behavior. NPTv6 rule-sets under `security nat static`
ignore the `from` scope entirely (zone, interface, AND routing-instance) — a
pre-existing limitation of the stateless prefix-indexed NPTv6 translator, not a
regression introduced by lifting the reject. The `validateNATRuleSetScopeAST`
gate and its `lenientNATRuleSetScope` opt are removed; `interface`/
`routing-instance` are now declared under the NAT rule-set `from`/`to` in
`schema_security.go` for commit-time validation and CLI completion.

**Unsupported security-policy `match` leaves are rejected at commit (#3113,
interim):** Junos SRX security policies match traffic with a rich `match`
criteria set. Beyond the L3/L4 leaves xpf enforces, vSRX accepts unified-policy /
identity / L7 leaves like `dynamic-application`, `url-category`, and
`source-identity`. xpf's policy compiler (`compilePolicy`, `compiler_security.go`)
only switches on the supported subset — `source-address`, `destination-address`,
`source-address-excluded`, `destination-address-excluded`, and `application`; any
other `match` child fell out of the switch with NO error and was SILENTLY DROPPED
(the set-schema does not list the leaves and `schema_walk.go` returns nil for
unknown keywords by design). Dropping a match criterion WIDENS the policy: a rule
the operator wrote to match only one `dynamic-application` compiled as if that
constraint were absent — a broad L3/L4 permit/deny over every application,
permitting/denying traffic the operator never intended (a security fail-OPEN, not
a cosmetic gap). `validatePolicyMatchLeavesStrict`
(`compiler_policy_match.go`) hard-rejects a policy carrying an unsupported `match`
leaf at commit, naming the policy scope (zone-pair or global), the policy, and the
offending leaf, and directing the operator to remove it. It is an AST pre-walk in
`compileExpanded` (not a typed validator) because the unsupported leaf is exactly
what the compiler drops — by the time the typed `*Config` exists the leaf is gone
from `PolicyMatch` — and because `SchemaValidate` returns nil for unknown keywords
by design and cannot REJECT `match dynamic-application ...`. The allowlist is the
EXACT set `compilePolicy` enforces (`supportedPolicyMatchLeaves`); keep the two in
lockstep. Both zone-pair (`from-zone`/`to-zone`) and `global` policies are
covered. This is the INTERIM contract: full support for those match types (typed
fields + capability gate + Rust enforcement) is a substantial feature deferred to
a follow-up. The tolerant load/peer-sync path downgrades to a warning
(`lenientPolicyMatchLeaves`) so an already-persisted or peer-synced config an
older binary silently accepted still boots — the leaf stays dropped (the
pre-existing behaviour), now flagged (#1960 no-brick doctrine, same as
#3018/#3055/#3060).

The #3113 gate originally inspected only the DIRECT children of `match`, which
left a multi-value-leaf ESCAPE (#3142, codex-review-067 finding 067-01). `match
application` is a `multi:true` leaf (`schema_security.go`), so the flat-set
absorber collapses every trailing non-sibling token onto the application leaf's
OWN node (`Keys[1:]` plus child sub-nodes — the #2419 collapse), not as a
sibling of `match`. So `set ... policy p match application any dynamic-application
junos:FTP` compiles to a single `application` leaf with tail tokens `[any
dynamic-application junos:FTP]`; the direct-child scan saw only the supported
`application` leaf and never the tail, so the unsupported `dynamic-application`
criterion escaped the gate and the policy silently armed as a broad application
match (`capabilities.go` short-circuits on the first `any`) — the same fail-open
#3113 closes, reached via the multi-value path. `validatePolicyMatchLeavesStrict`
now also scans the collapsed tail of a supported match leaf
(`firewallMatchValues`) and rejects any token in `unsupportedPolicyMatchLeaves`
(the KNOWN unsupported match dimensions: `dynamic-application`, `url-category`,
`source-identity`). A legitimate application VALUE is never one of those keywords,
so a real bracketed list like `match application [ junos-http junos-https ]` is
NOT over-rejected — only a known unsupported match-leaf keyword masquerading as
an application value is. Same strict-reject / lenient-warn split as #3113.

**Unsupported security-policy `then permit` children are rejected at commit
(#3114, interim):** Junos SRX `then permit` accepts action modifiers that turn a
bare permit into a permit-with-inspection or a permit-into-tunnel —
`application-services { utm-policy X; idp; }` (UTM/IDP/AppFW/SSL-proxy/SecIntel
attachment), `firewall-authentication`, `tunnel ipsec-vpn`, etc. xpf's policy
compiler (`compilePolicy`, `compiler_security.go`) handles the `then` arm by
switching only on the tokens it implements (`permit`, `deny`, `reject`, `log`,
`count`); the `permit` arm sets `pol.Action = PolicyPermit` and NEVER inspects the
permit node's children/tail, so any modifier under `then permit` fell out with NO
error and was SILENTLY DROPPED (the set-schema does not list them and
`schema_walk.go` returns nil for unknown keywords by design). Dropping a permit
service chain turns a permit-only-with-inspection rule into an UNCONDITIONAL
permit — an operator who writes `then permit application-services utm-policy
strict-web` believes traffic is inspected while xpf forwards it without the chain
(a security fail-OPEN). `validatePolicyThenPermitStrict` (`compiler_policy_then.go`)
hard-rejects a policy whose `then permit` carries an unsupported child at commit,
naming the policy scope (zone-pair or global), the policy, and the offending
modifier, and directing the operator to remove it. It is an AST pre-walk in
`compileExpanded` (not a typed validator) for the same reasons as #3113 — the
dropped modifier is gone from the typed `*Config`, and `SchemaValidate` cannot
REJECT an unknown keyword. The modifier appears either collapsed onto the permit
node's `Keys[1]` (flat set) or as a child node (hierarchical block); both shapes
are checked. The allowlist (`supportedPolicyThenPermitChildren`) is EMPTY today
because the compiler enforces no `then permit` child — keep it in lockstep with
`compilePolicy` so a future typed service chain is no longer rejected. Both
zone-pair and `global` policies are covered. This is the INTERIM contract: a typed
service-chain model + userspace capability gate + Rust enforcement is a deferred
follow-up. The tolerant load/peer-sync path downgrades to a warning
(`lenientPolicyThenPermit`) so an already-persisted or peer-synced config an older
binary silently accepted still boots — the modifier stays dropped (the
pre-existing behaviour), now flagged (#1960 no-brick doctrine, same as #3113).

**The tolerant-path downgrade of #3044/#3113/#3114 must NOT widen the permit
(#5575):** the #1960 lenient downgrade keeps the daemon booting, but the compiler
then SILENTLY DROPS the offending constraint — a missing required match dimension
(#3044) leaves the match slice EMPTY; an unsupported `match` leaf (#3113) or an
unsupported `then permit` modifier (#3114) is never read. The userspace matcher
reads an empty dimension as match-ANY (`expandUserspacePolicyApplications`
returns `(nil, true)` for an empty slice; the address/literal sides default to
match-any when empty), so the leniently-loaded policy silently widens to a permit
BROADER than the operator configured — a security fail-OPEN on exactly the
persisted-load / HA-sync path `CompileConfigLenient` serves. `compilePolicy` now
records this on the typed policy: `Policy.LenientContentDropped` is set (via the
SAME per-policy predicates the three strict gates use —
`policyMissingRequiredMatchDimensions`, `policyUnsupportedMatchLeafFindings`,
`policyUnsupportedThenPermitModifiers` — so the flag fires for EXACTLY the
policies a strict commit would reject). The userspace snapshot builder
(`buildOneRuleSnapshot`) then poisons such a rule with the `__unsupported__`
application sentinel, so the Rust integrity preflight rejects the WHOLE snapshot
(previous-good retained; fresh-boot default-deny) — an action-agnostic fail-CLOSED
that turns the widened permit (and a symmetric over-broad deny) into never-match
instead of match-any. Because the strict path hard-rejects all three BEFORE
`compilePolicy` runs, a clean strict-committed policy always leaves the flag
false and its snapshot is byte-identical. The flag is derived at compile time
(never serialized), so it is recomputed identically on both HA peers. The
distinction between an INTENTIONAL wildcard (`match application any` → a non-empty
`["any"]` slice → legitimate match-any, flag false) and a DROPPED / MISSING
constraint (empty slice, flag true) is made on the AST: an omitted leaf is treated
differently from an explicit `any`, so a legitimate `any→any:any` permit is NOT
poisoned.

**Unsupported security-policy `then reject` children are rejected at commit
(#3115, interim — codex-review-066 finding 066-03):** the sibling of #3114 for the
`reject` arm. Junos SRX `then reject` accepts a custom reject-response `profile
<name>` and a per-packet-type reject (e.g. `tcp-reset`). `compilePolicy`'s `then`
switch `reject` arm sets `pol.Action = PolicyReject` and NEVER inspects
`t.Children`, so any modifier under `then reject` fell out with NO error and was
SILENTLY DROPPED (set-schema does not list reject children and `schema_walk.go`
returns nil for unknown keywords). Unlike #3114 this is not a fail-OPEN (reject
still rejects), but the configured custom reject response is inert — a wire-contract
/ operator-observability divergence the operator cannot detect at commit.
`validatePolicyThenRejectStrict` (`compiler_policy_then.go`) hard-rejects a policy
whose `then reject` carries an unsupported child at commit, naming the policy scope
(zone-pair or global), the policy, and the offending modifier; a bare `then reject`
(no child) still commits. It is an AST pre-walk in `compileExpanded` for the same
reasons as #3114, checks both AST shapes (`Keys[1]` flat-set / child node
hierarchical), and covers zone-pair and `global` policies. The allowlist
(`supportedPolicyThenRejectChildren`) is EMPTY today because the compiler enforces
no `then reject` child — keep it in lockstep with `compilePolicy` so a future
synthesized reject response / packet-type reset is no longer rejected. Reject-profile
support (a typed reject-response model + dataplane synthesis) is a deferred
follow-up. The tolerant load/peer-sync path downgrades to a warning
(`lenientPolicyThenReject`) so an already-persisted or peer-synced config an older
binary silently accepted still boots — the modifier stays dropped (the pre-existing
behaviour), now flagged (#1960 no-brick doctrine, same as #3114).

**`then deny` log/count modifier wired; other collapsed deny modifiers
rejected (#3141 — codex-review-068 finding 068-01):** the deny sibling of
#3114/#3115, but NOT a pure reject. `then deny` legitimately combines with the
observability modifiers `log` (with `session-init`/`session-close`) and `count`,
which the standalone `then log`/`then count` arms already implement. A flat-set
`then deny log session-init` collapses the modifier onto the deny node
(`Keys=["deny","log","session-init"]`, no children) instead of nesting a sibling
`then log` node; `compilePolicy`'s `then` switch `deny` arm read only `t.Name()`
and silently dropped the collapsed tail, so deny-with-logging committed but
`pol.Log` was never set — the configured audit logging was inert (a deny-rule
observability / compliance failure, not a packet fail-OPEN). The fix WIRES the
collapsed `log`/`count` modifiers in `applyCollapsedDenyModifiers`
(`compiler_security.go`), so deny+log works in BOTH the flat-collapsed form and
the separate-node `then { deny; log session-init; }` form (the latter already
handled by the `log` arm); `pol.Log` flows into the policy snapshot
(`PolicyRuleSnapshot.LogSessionInit/Close`, #2508) independent of `Action`, so a
deny rule emits the configured session log. The safety net for any REMAINING
collapsed deny modifier the compiler cannot enforce is
`validatePolicyThenDenyStrict` (`compiler_policy_then.go`): it hard-rejects a
`then deny <unsupported>` modifier at commit, naming the policy scope (zone-pair
or global), the policy, and the offending modifier; a bare `then deny`,
`then deny log`, and `then deny count` still commit. AST pre-walk in
`compileExpanded`, both AST shapes, zone-pair and `global` coverage. The gate
is **parse-shape-agnostic** (#3377): `collapsedThenActionTokens`
(`compiler_policy_then.go`, shared by the permit/reject/deny gates) flattens an
action node's modifier tokens — `deny.Keys[1:]` plus the keys of every
descendant node — into the SAME token sequence the compiler's
`applyCollapsedDenyModifiers` (`compiler_security.go`) acts on, and the gate
checks EVERY token in that sequence against
`recognizedCollapsedDenyToken` (the exact `{log, session-init, session-close,
count}` set `applyCollapsedDenyModifiers` consumes). Flattening is what makes
the gate independent of how the flat-set parser grouped the modifiers: once
`deny` (and its `log`/`count` modifiers) became declared schema leaves (#3377),
the trailing tokens of a `then deny log session-init count` no longer always
collapse onto deny's own `Keys` — depending on which tokens are known leaves
they may land on deny's `Keys` (`["deny","log","session-init","count"]`), on a
single collapsed child node (`deny → child Keys=["count","session-init"]`), or
fully nested (`deny → log → session-init → count`). Reading only the first key
of a child (the pre-#3377 per-child `supportedPolicyThenDenyChildren` allowlist,
now removed) let a supported-leads / unsupported-trails sequence like
`then deny count session-init` or `then deny count evilmod` slip through
silently — exactly the fail-through the gate exists to prevent. Keep
`recognizedCollapsedDenyToken` in lockstep with `applyCollapsedDenyModifiers`.
**#3374:** `session-init`/`session-close` are LOG sub-options, valid ONLY when
a `log` token accompanies them in the same collapsed action. Because
`recognizedCollapsedDenyToken` cannot tell a sub-token from a top-level modifier
positionally, a `then deny session-init` (no `log`) used to pass the gate and
`applyCollapsedDenyModifiers` silently wired session-init logging — syntax Junos
rejects. The gate now scans the flattened token sequence for a `log` token and
rejects a `session-init`/`session-close` that has no `log` parent
(`emitOrphanLogSub`) regardless of how the parser grouped it;
`then deny log session-init` (and the
standalone `then log session-init`) still commit. The tolerant load/peer-sync
path downgrades both the unsupported-modifier and the orphan-sub-token reject
to a warning (`lenientPolicyThenDeny`) so an already-persisted or peer-synced
config an older binary silently accepted still boots (#1960 no-brick doctrine,
same as #3114/#3115).

**All-nodes walk (#3377 review fold):** the permit/reject/deny gates iterate
EVERY same-named action node under `then` (`FindChildren`, not `FindChild`). A
flat-set `set ... then permit` followed by `set ... then permit
application-services X` produces TWO separate `then permit` nodes (a bare leaf
plus an extended one — the split predates #3377 and is independent of the schema
change); a FindChild-first gate inspected only the bare first node and missed
the unsupported modifier on the second. The strict commit path still rejected
such a config via the #3043 conflicting-terminal-action gate, but with a generic
message — only the all-nodes walk surfaces the specific #3114/#3115/#3141
diagnostic (and the matching lenient-path warning, where #3043 is only a
warning). The deny gate additionally unions `hasLog` across all deny nodes to
match the compiler's per-node `applyCollapsedDenyModifiers` accumulation onto
`pol.Log`.

**Path-scoped `show configuration <path>` returns ALL siblings sharing the
terminal keyword (#3980 — the display-side sibling of the #3377 all-nodes
walk):** `navigatePath` (`ast.go`, the node selector behind every
`FormatPath*` renderer — hierarchical text, `display set`, JSON, XML,
inheritance) resolves a path that ends on a bare keyword. A hierarchy level
may hold multiple DISTINCT statements with the same leading keyword — several
`system ntp server <addr>`, repeated `system archival configuration
archive-sites <url>`, many `routing-options static route <dest>`. The
terminal single-key match previously returned `[]*Node{n}` (the FIRST
sibling only), so `show configuration system ntp server` — and, worse, its
`| display set` — showed only `server 1.1.1.1`, hiding the rest; a scoped
`display set` backup taken that way silently dropped the hidden statements on
restore. The fix gathers EVERY sibling whose first key equals the keyword
(FindChildren-not-FindChild) at the terminal element. The FULL-tree
serializers (`Format` / `FormatSet`, no path) already walked each sibling
slice element and were never affected; naming a specific keyed value
(`... server 2.2.2.2`) still resolves via the keyword+value multi-key branch
to that one entry. Regression coverage:
`pkg/config/show_config_repeated_keyword_3980_test.go` (path-scoped ntp +
static-route render, static-route `display set` round-trip, full-tree
control, single-statement no-regression). NOTE: a separate, orthogonal
construction defect still collapses the *keyed-list leaves* `system ntp
server` / `system archival configuration archive-sites` on flat-set replay —
their `setSchema` entries are `args:1, children:nil` non-`multi`, so
`SetPath`'s single-value-replace branch (`ast_edit.go`) keeps only the LAST
on `set ...`/`load set`, even though the compiler reads all of them via
`FindChildren` (`compiler_system.go`). That is a schema/SetPath fix (mark
them keyed-list + read via `firewallMatchValues`), not a renderer change, and
is tracked separately.

**Path-scoped `show`/`display set` descends into ALL same-prefix siblings,
not just the first (#4562 — the intermediate-descent twin of the #3980
terminal fix):** #3980 fixed the case where a display path *ends* on a
repeated keyword. `navigatePath` also has two INTERMEDIATE-descent branches
that walk *past* a matched level to resolve the rest of the path: the
multi-key branch (`current = matched[0].Children`) and the single-key branch
(`current = n.Children` for the first matching node). Both previously
descended into only the FIRST matching sibling's subtree. When a
hand-authored HIERARCHICAL config carries a DUPLICATE context block — two
identical 4-key `from-zone untrust to-zone trust { ... }` policy contexts, or
two identical single-key `interfaces { ... }` blocks — AND the display path
continues deeper (`... from-zone untrust to-zone trust policy B`), the second
duplicate-context block's statements were dropped from the path-scoped
`show` and its `| display set`, so a scoped display-set backup silently lost
them on restore. The fix descends into the UNION of every same-prefix (or
same-keyword) sibling's children via `unionChildren` before continuing —
mirroring the #3980 terminal read-all-siblings behavior onto the descent
(same #3842 / #2419 read-all-siblings class). Single-match is unchanged
(`unionChildren` returns the one node's children directly), so a normal
non-duplicate path and a single-context config render byte-identical.
`navigatePath` is DISPLAY-ONLY (all callers are `FormatPath*` in
`ast_format.go`; the compiler reads the full AST directly), so the hidden
statement was still ENFORCED — the impact was a display / scoped-backup gap,
not a forwarding or security bypass. Preconditions are narrow: flat-set
`SetPath` MERGES same-key containers, so only a hand-authored duplicate-
context config plus a path-SCOPED display command triggers it (an unscoped
`show configuration` renders the whole tree fine). Regression coverage:
`pkg/config/show_config_dup_context_4562_test.go` (multi-key + single-key
duplicate-context descent, single-context no-regression control).

**Empty security IDENTITIES are rejected at commit (#7525):** a zone name, a
zone-pair's `from-zone`/`to-zone`, and a policy name are all NAMES, and an empty
one is not a name. Four spellings committed cleanly and then diverged from what
the operator wrote — `security-zone ""`, `from-zone ""`, `to-zone ""`, and
`policy ""` (measured at master, with the fixture built up past the #3044 and
zone-reference gates that fire first and otherwise mask the question).

The consequence is a **widening, not an error**. `sortDedupZones`
(`types_security.go`) STRIPS the empty string from a zone set, and
`ZoneScopeSetLabel` renders an empty set as the idiomatic Junos `any` — so the
identity silently applies to every zone, which for a `then permit` is a
fail-open. The userspace preflight, meanwhile, rejects the same concrete empty
reference outright. The two halves therefore disagree about the same config,
and the operator learns about it at runtime rather than at the commit where
they can act.

`validateNonEmptySecurityIdentities` runs in the prewalk, on the
group-expanded, inactive-pruned AST, **ahead of normalization** — because
normalization is exactly the step that makes the mistake unobservable. Once
`sortDedupZones` has run there is no empty string left to complain about, only
a wildcard indistinguishable from an intended one. Strict on commit /
commit-check; lenient (warn) under `lenientEmptySecurityIdentity` on the load
and peer-sync ingress so an already-persisted config still boots (#1960).

Two shape notes, both learned by the tests rather than by inspection. The
zone-pair AST has **two** forms — a single node with a four-element key
(`["from-zone","trust","to-zone","untrust"]`) and a nested
`from-zone -> name -> to-zone -> name` chain — and `compileSecurityPolicies`
reads both, so a gate reading one covers only the spelling its author tested
(the #2419 class); the first version of this validator missed every empty
`to-zone` and every empty policy name. And the walk uses `forEachChild` at each
level rather than first-match, for the #3562 duplicate-block reason: a benign
first `security {}` followed by a second carrying the empty identity would
otherwise slip past.

The scoped-global case (`security policies global policy p match from-zone ""`)
is **not** handled here — #6526 already rejects it, with a message that names
this exact widening. Duplicating it would give one config two errors for one
mistake.

**Security policies missing a required `match` criterion are rejected at commit
(#3044 — codex-review-061 finding 061-03):** Junos/vSRX requires every security
policy `match` clause to specify all three core dimensions — `source-address`,
`destination-address`, AND `application`; a policy missing any of them (or omitting
the `match` block entirely) cannot commit. xpf's policy compiler (`compilePolicy`,
`compiler_security.go`) instead treated the whole `match` block — and every leaf
within it — as OPTIONAL: each field is filled only when the leaf is present, and an
absent dimension simply left the corresponding slice empty. The userspace dataplane
then interprets an empty slice as match-ANY (`capabilities.go` returns a nil app-term
list for "no apps"; `userspace-dp/src/policy.rs` compiles an empty app list as
`match_any:true` and defaults `source/destination_*_match_any` to true when the
literal+book sets are empty). A partial policy is therefore SILENTLY broader than
typed: `match source-address corp; then permit` permits `corp -> any:any`, and a
match-less policy becomes a zone-pair-wide permit/deny. A single dropped line in an
automation template widens a narrow rule to all traffic — a fail-OPEN for a permit
policy, an over-broad block for a deny. `validatePolicyRequiredMatchStrict`
(`compiler_policy_missing_match.go`) hard-rejects a policy whose `match` omits a
required dimension at commit, naming the policy scope (zone-pair or global), the
policy, and EVERY missing dimension, and directing the operator to add it. A missing
dimension is treated DIFFERENTLY from an explicit wildcard: the operator must write
`any` (or `any-ipv4`/`any-ipv6`, an address-book name, a CIDR, a named
application/application-set) — exactly as Junos demands. `source-address-excluded` /
`destination-address-excluded` are MODIFIERS of the base address leaf, not
substitutes, so they do not by themselves satisfy the source/destination-address
requirement. It is an AST pre-walk in `compileExpanded` (not a typed validator) for
the same reasons as #3113 — a missing leaf leaves no trace in the typed `*Config`
(an empty slice is indistinguishable from an explicit-any that also resolves to
match-any), and `SchemaValidate` cannot REJECT an absence. The walk runs on the
group-expanded, inactive-pruned tree, so an apply-groups-inherited dimension counts
and an `inactive:` policy is ignored. Both zone-pair and `global` policies are
covered. The tolerant load/peer-sync path downgrades to a warning
(`lenientPolicyMissingMatch`) so an already-persisted or peer-synced config an older
binary silently accepted still boots — the policy keeps its match-any-for-missing
compilation, now flagged (#1960 no-brick doctrine, same as #3113).

**Ambiguous secure-tunnel `bind-interface` aliases are rejected at commit
(#2933):** `security ipsec vpn <name> bind-interface` is a free-form 1-arg
string stored verbatim on the typed VPN (`compiler_ipsec.go`); the runtime
resolves it to a Linux xfrmi device name and a stable XFRM if_id via
`XFRMIfNameAndID` (`xfrmi.go`): `if_id = stIndex<<16 | (unit+1)`, unit
defaulting to 0. A bare `st0` is therefore the SAME device as `st0.0` (both
if_id 1). Two VPNs binding those two distinct strings committed cleanly but
collide at apply time — only one xfrm device can carry the if_id, so the #2929
pkg/routing guard refuses to create EITHER device and both tunnels go down with
a journal ERROR (before #2929 it silently leaked one VPN's SA onto the other's
tunnel). `validateSecureTunnelBindInterfaceAST` (`compiler_ipsec_bindiface.go`)
turns that apply-time both-down into a commit-check error: it derives the if_id
for every VPN's bind-interface and hard-rejects when two DISTINCT strings derive
the SAME non-zero if_id, naming each offending string, its VPN(s), and the
shared if_id. The gate is SURGICAL — it does NOT fire when the same string is
shared by several VPNs (one device, one if_id) nor when a bind-interface cannot
parse as `st<N>[.unit]` (if_id 0); an unambiguous map (st0.0 + st0.1, or st0 +
st1) commits cleanly. It is an AST pre-walk in `compileExpanded` so an
apply-groups-inherited bind-interface is covered and an `inactive:` VPN is
ignored. The tolerant load/peer-sync path downgrades to a warning
(`lenientSecureTunnelBindIface`) so an already-persisted or peer-synced config
an older binary accepted still boots (#1960 no-brick doctrine) — the #2929
routing guard stays the runtime backstop.

The same gate carries a DISTINCT `bind-interface` fail-closed arm (#5297): a
NON-EMPTY bind-interface that `XFRMIfNameAndID` resolves to **if_id 0** (any name
that is not the canonical `st<N>` / `st<N>.<unit>`, e.g. `secure0`, a bare `st`,
`ge-0/0/0`) creates NO XFRM device at reconciliation, so the route-based VPN
commits cleanly but silently carries no traffic. The #2933 collision arm
deliberately `continue`d past if_id 0 (a collision needs two VALID, non-zero
if_ids); the #5297 arm instead hard-rejects such a name on the strict commit /
commit-check path (naming the canonical `st<N>[.unit]` requirement) and warns on
the tolerant load / peer-sync path. This is ALSO enforced at the typed-leaf
schema layer — the `bind-interface` leaf is `ValueSecureTunnelIf` with the
`ValidateSecureTunnelBindInterface` validator (`xfrmi.go`) — so commit-check and
`?`-completion reject it early; the compiled-config gate stays as the belt for
group-expanded / packed forms the schema layer can miss (#1960 layered defense).
The pkg/routing "invalid bind-interface name" log is the runtime backstop for a
tolerated invalid config.

**The decrypted plaintext is NOT zone-adjudicated, and the operator is told so
at commit (#5619):** a route-based VPN's `bind-interface st<N>[.unit]` is
deliberately excluded from the ingress-adjudication set, the AF_XDP binding plan
and the RSS allowlist — and `syncInterfaceAttachments`
(`pkg/dataplane/userspace/manager_compile.go`) then calls `DetachXDP` on every
ifindex outside the allowed set, so the shim is detached from the xfrmi rather
than attached to it. There is no kernel substitute: no `hook forward` rule
covers it and `ip_forward` is 1 whenever the dataplane is armed (since #5275
that knob is armed-conditional — an UNARMED node forwards no transit at all,
plaintext included, which closes this gap only by closing everything).

The problem this advisory solves is not the gap itself but the FALSE
affirmation around it. `set security zones security-zone vpn interfaces st0.0`
commits cleanly (#4515 accepts a zone naming a bind-interface with no explicit
`set interfaces st0 unit 0`), and nothing in the CLI or the commit output
distinguishes that zone from one that is enforced. An operator who zones a VPN
interface and sees it accepted has been told something specific and untrue about
their security posture, which is worse than an unimplemented feature.

Two wordings, on purpose: a ZONED tunnel reads as an escalation, because a
specific untrue thing was asserted; an unzoned tunnel gets a plain statement of
the gap. The advisory's population is the set of `bind-interface` refs for which
`XFRMIfNameAndID` builds a device (a non-zero if_id) — the same set
`pkg/routing/xfrm.go` creates xfrmis for, since it skips `ifID == 0`. It does
NOT key off `IsSecureTunnelIfName`, and saying so was a stale claim corrected in
#7090: since #6691 round 5 the dataplane exclusion reads the snapshot's
`SecureTunnel` flag (`snapshotSecureTunnel`), and `xfrmi.go` states that the
predicate "is NOT the ownership test and no longer gates any dataplane set". The
two populations still coincide, but through the shared if_id rather than a
shared call — a coincidence, not a mechanical binding, and a real anti-drift
guard would have to be a test asserting the populations agree. It
fires on all four compile entry points — strict, lenient, and both node-aware
variants — because the operator who most needs it is the one whose config
arrives by restart or peer-sync and who never re-commits.

Like the #2933 and #5297 arms above it, this NEVER rejects: a bind-interface
resolving to if_id 0 is skipped here, since it is already reported by the #5297
arm as a silent tunnel-down and a second complaint about a plaintext path that
does not exist would just be noise.

**Undefined policy community references are rejected at commit (#2881):** a
policy-statement term's `from community <name>` (rendered FRR `match community
<name>`) and `then community delete <name>` (the strip-by-list operation added
in #2848, rendered `set comm-list <name> delete`) both reference an FRR
`bgp community-list <name>` that `pkg/frr` emits ONLY from a defined
`policy-options community <name>`. With no validation a term naming an UNDEFINED
community committed cleanly, then a dangling `match community` / `set comm-list
... delete` line failed the WHOLE `frr-reload` of the managed section (a single
`vtysh -f` add-batch exits non-zero on any `CMD_WARNING_CONFIG_FAILED`), leaving
dynamic routing stale — a commit-accepted config the routing daemon cannot load.
`validatePolicyCommunityReferencesStrict` (`compiler_validate_strict.go`) runs
on the fully-compiled `*Config` (the community map is populated regardless of
authoring order) and hard-rejects an undefined `from community` / `then
community delete` reference at commit/commit-check, naming the policy, term, and
missing community. The tolerant load/peer-sync path downgrades to a warning
(`lenientPolicyCommunityRef`) so an already-persisted or peer-synced config an
older binary accepted still boots (#1960 no-brick doctrine). The gate is
SURGICAL — only NAME references are checked; `then community (set|add) <value>`
carries a community VALUE (e.g. `65000:100`), not a list reference, and a defined
community reference commits unchanged.

**The `-xpf-redist` route-map-name suffix is reserved (#5116):** the FRR renderer
derives a per-use-site fail-closed redistribute route-map alias
`name + "-xpf-redist"` (`redistFailClosedRouteMap`, `pkg/frr`) into FRR's GLOBAL
name-keyed route-map namespace so a BGP-default-accept policy's trailing permit
cannot leak into an IGP `redistribute` (#4481). FRR keys route-maps by NAME, so
an operator policy-statement literally named `<X>-xpf-redist` alongside a dual-use
`<X>` would collide with the generated alias in that shared object and could
silently undo the fail-closed BGP/IGP separation — reintroducing route
redistribution leakage under a config that otherwise passes validation.
`validatePolicyReservedRedistNameStrict` (`compiler_validate_strict_routing.go`,
constant `ReservedRedistSuffix`) hard-rejects a policy-statement whose name ends
in the reserved suffix at commit / commit-check (naming the policy and the
suffix), making the generated-alias namespace injective BY CONSTRUCTION. The
alias derivation in `pkg/frr` references the SAME `ReservedRedistSuffix` constant
so the two cannot drift. The tolerant load / peer-sync path downgrades to a
warning (`lenientPolicyReservedRedistName`) so an already-persisted or
peer-synced config an older binary accepted still boots (#1960 no-brick
doctrine); as defense-in-depth the renderer's `redistAliasCollision` (invoked by
`ApplyFull`) then fails the managed-section apply CLOSED if a leniently-loaded
alias still collides, so the collision cannot leak even when the strict gate was
bypassed.

**The `-xpf-chain` route-map-name suffix is reserved (#5442):** the direct
parity sibling of the `-xpf-redist` reservation above. #5277 composes an ordered
BGP import/export policy chain of length >= 2 into a SINGLE FRR route-map named
`join(chain, "-") + "-xpf-chain"` (`composedChainName`, `pkg/frr`) in FRR's
GLOBAL name-keyed route-map namespace. An operator policy-statement literally
named `<X>-xpf-chain` lands in that reserved suffix namespace and can collide
with a generated composed route-map — FRR MERGES two same-named route-map
definitions, silently altering the operator's BGP filtering.
`validatePolicyReservedChainNameStrict` (`compiler_validate_strict_routing.go`,
constant `ReservedChainSuffix`) hard-rejects a policy-statement whose name ends
in the reserved suffix at commit / commit-check (naming the policy and the
suffix), making the composed-name namespace injective against operator
policy-statements BY CONSTRUCTION. The composed-name derivation in `pkg/frr`
re-exports the SAME `ReservedChainSuffix` constant
(`frr.ReservedChainSuffix = config.ReservedChainSuffix`) so the two cannot drift.
The tolerant load / peer-sync path downgrades to a warning
(`lenientPolicyReservedChainName`) so an already-persisted or peer-synced config
an older binary accepted still boots (#1960 no-brick doctrine); as
defense-in-depth the renderer's `bgpComposedChainCollision` (invoked by
`ApplyFull`) then fails the managed-section apply CLOSED if a leniently-loaded
composed name still collides, so the collision cannot leak even when the strict
gate was bypassed.

**Policy-referenced application protocols are validated against the dataplane
resolver (#3150 — codex-review-067 finding 067-06):** a user-defined
`set applications application <name> protocol <token>` that is REFERENCED by a
security policy or NAT rule's `match application` (or any application when
`services application-identification` is on) is hard-rejected at commit by
`validateApplicationSpecsStrict` (`compiler_validate_strict.go`) when the
protocol token is unresolvable. The bug: that gate resolved the token via the
LENIENT `validateProtocol`, which blanket-accepts ANY `junos-` prefix
(`strings.HasPrefix("junos-")`). So `protocol junos-foobar` committed cleanly,
but the dataplane resolves protocols only through `appid.ProtocolNumber`
(`pkg/appid`), which knows only the CONCRETE junos-* aliases (`junos-ping`,
`junos-tcp-any`, ...) — it rejects `junos-foobar`. The userspace policy
capability gate (`pkg/dataplane/userspace`) then disarms the snapshot
(`ForwardingSupported=false`): a commit-succeeds / apply-fails split. The fix
resolves the application's protocol through `filterProtocolResolvable` — the
same `appid.ProtocolNumber` mirror the firewall-filter `from protocol` gate
(#2175) already uses, pinned to the SSOT by the `pkg/appid` drift-guard test
`TestFilterProtocolResolvableMatchesProtocolNumber` — so a token the dataplane
cannot represent is rejected at commit. Real protocol names, numeric 0..255
values, and resolvable junos-* aliases still commit; only genuinely
unresolvable tokens reject. The lenient `validateProtocol` is unchanged and
still used by `ValidateConfig`'s warning surface (so an UNREFERENCED library
app with a bogus protocol stays a warning, not a commit error). The tolerant
load/peer-sync path downgrades the reject to a warning
(`lenientApplicationSpecs`) so an already-persisted or peer-synced config an
older binary accepted still boots (#1960 no-brick doctrine). Distinct from
#2124/#2142 (those fixed alias drift / malformed port-or-protocol specs); this
residual was specifically the strict app-spec path still using the blanket
`junos-` HasPrefix.

**Ports are valid only on a protocol the dataplane extracts ports for (#3373 —
audit finding):** the same `validateApplicationSpecsStrict` gate hard-rejects a
referenced (or app-id-enabled) `set applications application <name>` that sets
`source-port`/`destination-port` while its `protocol` is one this dataplane does
NOT extract L4 ports for. The authoritative port-bearing set is the dataplane's
own extraction predicate — `userspace-dp/src/ip_proto.rs` `has_l4_ports` ==
**TCP (6) / UDP (17)** ONLY, mirrored by `inspect.rs parse_flow_ports` (which
reads port bytes only for TCP/UDP) — NOT a name→number resolver. ICMP/ICMPv6,
GRE, OSPF, ESP, AH, VRRP, IGMP, PIM, IP-in-IP do not carry ports the dataplane
reads; **SCTP (132) is also excluded** — it has ports on the wire, but this
dataplane deliberately never extracts or rewrites them (CRC32c checksum, see the
`ip_proto.rs has_l4_ports` rationale), so an SCTP packet still presents
`dst_port`/`src_port` = 0 to the matcher. Before the gate `protocol icmp
destination-port 80` (or `protocol ospf destination-port 89`, `protocol esp
source-port 4500`, `protocol sctp destination-port 80`) committed: the port
passed `validatePortSpec` and the protocol passed `filterProtocolResolvable`,
but the runtime then compiled a port matcher indexed by the protocol number
(`userspace-dp/src/policy.rs` keys port terms on the packet's extracted
`src_port`/`dst_port`, which are 0 for any non-extracted protocol), so the term
became a NEVER-MATCH — fail-OPEN for a deny rule, fail-CLOSED for a permit rule.
Rejecting at commit is the fail-closed-correct outcome: the dataplane cannot
enforce the constraint, so refuse it rather than silently compile a never-match
term. The gate resolves the port-bearing subset inline via
`protocolIsPortBearing` (appid cannot be imported here — pkg/appid imports
pkg/config — so the subset is pinned to the `ip_proto.rs has_l4_ports` SSOT by
the drift-guard test `TestProtocolIsPortBearingMatchesDataplaneExtraction`). It
fires ONLY when a port is set AND the protocol is not in the extraction set, so
an icmp-type-constrained ICMP app with no port (junos-ping shape) and a bare
`protocol gre`/`protocol sctp` still commit. The tolerant load/peer-sync path
downgrades the reject to a warning (`lenientApplicationSpecs`) per the #1960
no-brick doctrine. Junos does not couple ports to non-port protocols, so this is
a vSRX-parity fix.

**Custom-application named ports resolve through the shared service catalog
(#3340):** a custom application's `source-port`/`destination-port` used to accept
only a hard-coded 15-name subset (`http https ssh telnet ftp ftp-data smtp dns
pop3 imap snmp ntp bgp ldap syslog`), so a valid Junos service name beyond it —
notably `domain`, the canonical alias of the already-accepted `dns` — was
rejected at commit even though the dataplane can represent the numeric port
exactly. `compileApplications` / `parseApplicationTerms` now run each port spec
through `resolveAppPort`, which resolves named ports against the **same
`junosServicePorts` catalog** (`filter_match_resolve.go`) the firewall-filter
path uses (`resolveFilterPortTokens`) — the single source of truth for Junos
service-name → port number. Resolution emits the NUMERIC form (`domain` → `53`,
`http-https` → `80-443`) so the dataplane only ever parses numerics: the Rust
`parse_port_spec` and its Go mirror `userspacePortSpecRepresentable` (the #2124
capability gate) recognize only the 15 literal names, so passing a broader name
through verbatim would commit yet be unrepresentable at apply (a commit/apply
split that disables forwarding). `resolveFilterPort` is NOT reused for this
because it splits on `-` before a whole-spec lookup, mangling hyphenated service
names (`ftp-data`, `tacacs-ds`, `kerberos-sec`); `resolveAppPort` does the
whole-spec catalog lookup first. The lookup is case-insensitive, so a mixed-case
service name resolves rather than passing through unresolved. **This case-fold
is load-bearing (#3372):** the userspace #2124 capability gate
(`userspacePortSpecRepresentable`) and Rust `parse_port_spec` match the 15
literal aliases CASE-SENSITIVELY (lowercase only), while the strict commit gate
`validatePortSpec` is case-insensitive. Without `resolveAppPort` lowering a
recognized name to its number first, a mixed-case `destination-port HTTPS` would
pass commit yet reach the case-sensitive userspace gate as a raw name, which
rejects it — a commit/apply split. The apply failure is the #3261 class-(i)
unrepresentable-content path, NOT a disarm/fail-open: the policy term is
unrepresentable, `buildOneRuleSnapshot` emits the `__unsupported__` sentinel and
records `snap.Capabilities.PolicyContentRejected`, and a current
preflight-capable helper REJECTS the whole snapshot while STAYING ARMED — a
running node retains its previous-good policy state, a fresh boot lands on
default-deny (disarm/XDP_PASS-to-kernel is only the narrow
pre-preflight-protocol-version backstop). So a removed case-fold would break
APPLY (the new config silently does not take effect), not admit traffic
fail-open. Because `resolveAppPort` canonicalizes to the numeric form first, the
case-sensitive gate never sees a raw alias. The two 15-name backstop tables are
pinned consistent with `junosServicePorts` by the
`TestNamedPortAliasTablesDoNotDrift` canary. An unresolvable
name (unknown service, out-of-range/malformed number, inverted/unresolved range)
is left verbatim so `validatePortSpec` hard-rejects it at the strict commit gate
and the tolerant load/peer-sync path downgrades it to a warning
(`lenientApplicationSpecs`, #1960 no-brick).

**Custom-application ICMP type/code constraints (#3348):** a user-defined
application whose `protocol` is the `junos-ping` / `junos-pingv6` alias now
carries the same echo-request type constraint the predefined `junos-ping`
object does (ICMP type 8 / ICMPv6 type 128, the #3020 parity). Before this fix
the alias lowered to bare ICMP with no type, so a custom `protocol junos-ping`
app projected a term the userspace matcher (and the `pkg/policymatch`
simulator) treated as match-ALL ICMP — silently widening any policy that
referenced it to every ICMP type (unreachable / redirect / timestamp / ...).
`aliasEchoICMPType` (`compiler_applications.go`) attaches the echo type on both
the top-level and inline-`term` paths, AFTER the child loop so an explicit
`icmp-type` leaf still wins; the all-ICMP aliases (`junos-icmp-all` /
`junos-icmp6-all`) stay unconstrained. The grammar now also exposes typed
`icmp-type` / `icmp-code` leaves (0..255, range-validated by the schema) on a
custom application and inline term, so an operator can author a constrained
echo / traceroute / ICMP-control app rather than only the all-ICMP widening.
`validateApplicationSpecsStrict` rejects an `icmp-type`/`icmp-code` on a
non-ICMP protocol (a never-match term, the same #3373 hazard as a port on a
non-port protocol) and an `icmp-code` without an `icmp-type` (an ambiguous
half-constraint); both downgrade to a warning on the tolerant load/peer-sync
path. `protocolIsICMPFamily` mirrors the ICMP arm of `filterProtocolResolvable`.
Two inline-`term` edge cases (the term is opaque to `SchemaValidate`): a term
listing BOTH a junos-ping alias AND an unconstrained ICMP alias dedups onto one
`icmp` term whose union is all-ICMP, so `unconstrainedICMP[proto]` suppresses the
echo narrowing (a widening INVERSION otherwise); and a malformed inline
`icmp-type`/`icmp-code` is recorded on `Application.UnknownICMP` (not silently
dropped, which would leave the term matching all ICMP) for the same strict-reject
/ lenient-warn gate.

**Application is EITHER direct OR term-based, never both; conflicting duplicate
term leaves rejected (#3366):** a custom `applications application <name>` may
define EITHER a direct match body (`protocol` / `destination-port` /
`source-port` / `inactivity-timeout` / `timeout` / `icmp-type` / `icmp-code` /
`alg`) OR one or more `term` sub-blocks — Junos rejects the mix. Before this fix
`compileApplications` stored ONLY the synthesized per-term applications for a
term-bearing app (the `if len(terms) > 0 { ... } else { apps.Applications[appName]
= app }` branch), so a config that combined a direct body with a `term` silently
DROPPED the direct match. For a deny application that erased the deny and let
traffic fall through to a later permit or the default policy (a fail-OPEN
under-match), with no commit error. `compileApplications` now records such a
parent on `cfg.Applications.MixedDirectTermApps` and `validateApplicationStructureStrict`
(`compiler_validate_strict.go`) hard-rejects it at commit (move the direct match
into its own `term`). The same gate also rejects a single-valued (scalar) term
leaf — `destination-port` / `source-port` / `inactivity-timeout` / `timeout` /
`alg`, and since #6766 `icmp-type` / `icmp-code` — that appears more than once
inside ONE inline term with a CONFLICTING
value: the inline `term` is opaque to the `SchemaValidate` walk, so a repeat (via
apply-groups, flat-set ordering, or hand authoring) was last-writer-wins,
silently overriding the earlier value by token order; `parseApplicationTerms`
records the offending leaf on `Application.DuplicateTermLeaves`. (#6766: the
#3366 framework omitted the ICMP leaves, so a conflicting `icmp-type` /
`icmp-code` repeat overwrote the pointer with no record and a referenced DENY
enforced only the LAST type/code — a silent narrowing of the deny match, the
inline-term analogue of the #5574 direct-body ICMP tracking. On the TOLERANT
path the conflict is only a warning. The compiled term keeps the LAST value
(pinned at the compiled struct in `compiler_application_term_icmp_dup_6766_test.go`),
but since #9525 a policy referencing it is refused rather than enforcing that
narrowed term (pinned at the verdict, for both leaves, in
`pkg/policymatch/app_inline_term_icmp_dup_6766_test.go`).) An IDEMPOTENT
same-value repeat (e.g. the `timeout` / `inactivity-timeout` aliases both set to
the same number) is harmless and accepted, and a repeated `protocol` is the
documented multi-protocol-term syntax (one application per unique protocol) and
is NOT flagged. Both checks run over EVERY user-defined application — referenced
or not — like the #3352/#3353 syntactic gate (a structural grammar error Junos
rejects at definition, regardless of policy wiring), and the tolerant
load/peer-sync path downgrades the reject to a warning (`lenientApplicationSpecs`)
so an already-persisted or older-peer-synced config still boots (#1960 no-brick
doctrine). Distinct from #3339 (implicit-set vs explicit-set collision / duplicate
term NAMES), #3352 (unknown leaves inside a term), and #3320 (malformed timeout).

**Unknown application-set member keyword rejected (#3890 — fable-review-161
F-160):** an `applications application-set <name>` member is `application
<name>`, `application-set <name>` (nested), or `description <text>` (metadata).
The schema declares `application-set` as an opaque `args:1` leaf (`children:
nil`), so the `SchemaValidate` walk never reaches its members. Before this fix
`compileApplications`' member switch had NO default arm, so a TYPO'd member
keyword (e.g. `applicaton foo` for `application foo`, or a mistyped
`application-set`) was SILENTLY DROPPED — the set was under-populated with no
commit error. If that set was referenced by a DENY policy the deny then matched
FEWER applications than the operator intended, permitting traffic meant to be
blocked (a fail-OPEN under-match; for a permit policy it is the fail-closed
inverse). `compileApplications` now records the offending keyword on
`ApplicationSet.UnknownMembers` (a `description` is accepted-and-ignored, the
documented way to author an otherwise-empty set), and
`validateApplicationSyntaxStrict` (`compiler_validate_strict.go`) hard-rejects
the first one at commit — the same all-user-sets, referenced-or-not scope and
strict-reject / lenient-warn discipline as the #3352 opaque-`term` unknown-leaf
gate it mirrors. The tolerant load/peer-sync path downgrades the reject to a
warning (`lenientApplicationSpecs`) so an already-persisted or older-peer-synced
config still boots (#1960 no-brick doctrine). Implicit application-sets
synthesized for term-bearing applications never carry `UnknownMembers`, so they
are unaffected. Distinct from #2068 (a dropped NESTED-set member — a valid
keyword the old switch already handled) and the #3144/#3146/#3434 empty-set gate
(a set that resolves by name but expands to zero members).

**Tolerant-path application drops refuse the policy (#9525):** the application
gates above are strict on commit / commit-check and downgrade to a warning on
the tolerant load / peer-sync path (`lenientApplicationSpecs`). Several members
still left a well-formed-looking term on the wire that matched something other
than what was authored, with `PolicyContentRejectionReasons` empty:
- a `destination-port` on a protocol with no L4 ports (icmp, gre, sctp) never
  matches;
- a `source-port` on icmp/icmpv6 is compared with the ICMP query Identifier,
  which the sender chooses;
- a malformed `icmp-type`/`icmp-code` is dropped, so the term matches every type
  or code;
- an icmp field on a non-ICMP protocol, or a code without a type, is refused by
  the helper (#3712) while the simulator certified a verdict;
- a dangling or conflicting match leaf is dropped or keeps only its last value;
- a direct body mixed with `term` blocks is discarded.

`config.ApplicationReferenceMatchDrops` names these, walking nested sets as the
expansion does. `expandUserspacePolicyApplications` then refuses the reference,
so the policy lowers to the #3261 `__unsupported__` sentinel. The helper refuses
the whole snapshot (a running node keeps its previous one), and the mirror names
the application.

Only MATCH leaves count. `applicationMatchLeaves9525` and
`applicationSettingLeaves9525` partition `valueTakingApplicationLeaves`, so a
bad, dangling or conflicting timeout or `alg`, which does not change what
matches, is still installed.

An UNRECOGNIZED statement (`UnknownDirectLeaves`, `UnknownTermLeaves`,
`UnknownMembers`) is refused only on the structural line #9595 measured
(`application_unknown_statement_9595.go`):
- the application is otherwise protocol-wide on a dimension its protocol has
  (tcp/udp with no port, icmp/icmpv6 with no icmp-type), AND the unrecognized
  run carries a constraint-shaped token (a port spec, a decimal integer or
  range, an ICMP type) — a misspelled `destination-poort 22` on `protocol tcp`
  would otherwise install as tcp-any; or
- an application-set's unrecognized member statement names a real
  application or application-set (a misspelled member reference).

The compiler records the whole unrecognized run (`UnknownDirectTokens`) and
each member's value (`UnknownMemberValues`) for this. #6524's
`TestStrayStatementDoesNotDisarmSiblingLeaves` shape (a stray `bogus value`
beside a retained port) stays armed. The measured limits: a constraint lost
BESIDE a retained one (`destination-port 80; source-poort 1024`) is left
installed, because structure cannot tell it from a numeric stray beside a
retained constraint without keyword similarity (decision: #9603); and a
numeric or named-port stray on a protocol-wide application (`protocol tcp;
bogus 8080;`) is refused, because it is structurally a lost port. NAT
application terms are lowered separately
(`buildSourceNATAppTerms`, `appTermFor`) and are unchanged.

**C struct alignment:** when mirroring C BPF structs in Go, match `sizeof`
exactly with trailing `Pad [N]byte` fields. cilium/ebpf serializes map
values in native endian, not big-endian, so use `binary.NativeEndian`
when packing IP addresses (already in network byte order on the wire).

**Group expansion of named-instance leaves (#9801, #9831):** `mergeNodes`
(`ast_groups.go`) treats a named instance written as a leaf, such as
`security-zone trust;` or `system syslog host 10.0.0.2;`, as the instance it
names.
- A group's named-instance leaf is matched against the inline node naming the
  same instance: the keyword plus the instance keys (`sameInstancePeer9831`).
  Before #9831 it matched on the keyword alone, so an inline
  `security-zone trust;` overrode, and dropped, a group's `security-zone zga;`.
- A multi-value leaf (`multi` or `valueList`), such as a static route's
  `next-hop [ a b ]`, is a list of values rather than an instance. It keeps the
  leaf-list and override paths. Matched by its first member, a group's
  `next-hop 192.0.2.2;` would miss `[ 192.0.2.1 192.0.2.2 ]` and compile a
  duplicate next hop.
- A group leaf that carries keys past the instance it names is not overridden
  by that instance's inline node, because the override would drop the extra
  keys. Examples are `security-zone [ zga zgb ];` and a mistyped
  `security-zone trust scren edge;`.
  - A braced peer takes a packed statement through #7648; otherwise the leaf
    is adopted.
  - Beside a leaf zone, the leaf is adopted too, so #9656 judges it as it
    would the same text written inline.
  - Any other leaf instance keeps the override. Adopting
    `host 10.0.0.1 any any;` beside `host 10.0.0.1;` would compile a second
    syslog destination.
- A `<*>` group reaches a zone written as a leaf. The leaf becomes the empty
  container its braced spelling is (`zoneLeafTakesWildcard9801`). Before #9801
  the wildcard merge visited only non-leaf destinations, so
  `security-zone trust;` lost a group's screen that `security-zone trust { }`
  took.
- The wildcard change is scoped to zones. An interface or routing instance
  written as a leaf compiles no instance at all (#9838), so a wildcard group
  must not turn one into an instance.
