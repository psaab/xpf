# pkg/frr

FRR (FRRouting) integration. Generates a managed section inside
`/etc/frr/frr.conf` from the typed config (static routes, OSPF, BGP,
ISIS, RIP, BFD profiles, multi-VRF instances) and queries protocol state
via `vtysh`.

This package is the only place in the codebase that's allowed to touch
kernel routes — and it doesn't, directly. It writes config and reloads
FRR, which then owns the kernel route table.

`frr.conf` is DurableState (#1894): `atomicWriteFile` delegates to
`fsatomic.WriteFileDurable` with `WithPreserveExisting` +
`WithResolveSymlinks` (the #1883 mode/owner/symlink semantics were
lifted into that package), gaining the parent-dir fsync the local
writer lacked. The file carries operator content outside the managed
section, so it must survive power loss.

**File mode (#4484 L-6):** the managed section carries routing-auth
secrets (BGP TCP-MD5, OSPF/IS-IS/RIP keys), so `frr.conf` must not be
world-readable. The write perm is **0640** (was 0644). Because 0640 is
readable only by owner+group, a **fresh** create (no operator file to
preserve) is installed **owned `root:frr`** via `fsatomic.WithOwner`, so
the unprivileged frr daemons (group `frr`) can still read it —
`atomicWriteOwnerOpt` resolves the frr gid (`resolveFRRGroup`). The
owner override is applied **only** when (a) the target does not already
exist — an existing operator file keeps its own mode+ownership
(`WithPreserveExisting`, never restamped) — AND (b) the process is root
and the `frr` group resolves. When the group is absent (FRR not
installed — a dev host / unit test) or the process is non-root the
override is skipped and the file lands 0640 `root:root` (harmless:
nothing reads `frr.conf` without a running FRR). This mirrors the
pkg/dhcpserver #2450 Kea-memfile ownership handling.

## File layout

The package is split across cohesive per-aspect sibling `.go` files (no
sub-packages, no filename prefixes). #6424 further decomposed the render
layer: `generateProtocols` now lives in `protocols_render.go`,
`resolveRedistribute` in `redistribute.go`, the #5277 composed-chain
resolution in `bgp_policy_chain.go`, the #2550 BFD accumulator in
`bfd.go`, route-filter/from-prefix-list rendering in
`prefix_list_render.go`, and `sanitizeFRRValue` + the value-validation
belt in `render_validate.go`. `policy_render.go` retains
policy-statement -> route-map rendering (`generatePolicyOptions`),
community classification, `renderComposedRouteMap`, and the `-xpf-redist`
alias guard. The detailed rendering semantics documented in the
`policy_render.go` row below apply wherever each function now lives:

### Non-protocol route operands have a final validity belt (#6795)

The `ip route` / `ipv6 route` renderers — static routes
(`generateStaticRouteInTable`), generate-routes (`renderGenerateRoutes`) and,
since #8597, the backup-router default (`renderBackupRouter`) —
interpolate RAW STRINGS from the parser: `sr.Destination`, `nh.Address`,
`ifName`, `gr.Prefix`. The protocol renderers already have belts
(`validRouterID` #2980, `validClusterID` / `validBGPOrigin` #4919); these did
not.

The blast radius is what makes it matter: a malformed operand fails the **whole**
frr-reload — one `vtysh -f` add-batch exits non-zero on any
`CMD_WARNING_CONFIG_FAILED` — so one bad route takes **every other route on the
box** with it. A value carrying whitespace additionally splits into extra
operands, or adds a statement outright. Commit validates these, but the tolerant
load / HA config-sync paths only warn (#1960 no-brick), so the renderer is the
last place to stop it.

Three predicates in `render_validate.go`:

| operand | predicate | accepts |
|---|---|---|
| destination / generate prefix | `validFRRRoutePrefix` | CIDR **or** a bare address |
| gateway | `validFRRNextHopAddress` | a bare address only |
| interface | `validFRRInterfaceOperand` | one token |

`validFRRRoutePrefix` accepts a maskless host route deliberately: the
destination is a raw string and a host route may reach here without a mask, and
**dropping a route form that renders today is an outage**. The belt exists to
keep UNRENDERABLE operands out of `frr.conf`, not to re-litigate the accepted
grammar. `validFRRInterfaceOperand` is a token test rather than a name-charset
test for the same reason.

**Granularity is deliberate.** A bad DESTINATION drops the route; a bad
NEXT-HOP drops only that next-hop. A `next-hop [ a b ]` ECMP list with one
malformed member must still install the good ones — dropping the whole route
would turn a typo in one gateway into a blackhole for the prefix, and the
no-next-hop path already renders NOTHING rather than a `Null0` (#3872), so a
whole-route drop is silently fail-wide.

**The DHCP-learned routes deliberately get no belt.** They look like the
highest-risk operands — they come from a DHCP server on the wire — but they are
not raw strings: `lease.Gateway` is a `netip.Addr` and `cr.Destination` a
`netip.Prefix`, both `String()`-ed, and those types cannot stringify to anything
containing whitespace. `TestDHCPRouteOperandsAreStructurallySafe6795` records
that measurement so the question is re-asked if either field is ever widened to
a string.

**`renderBackupRouter` was the one renderer never brought along (#8597).** It
checked only `BackupRouter == ""` and interpolated both operands raw. The gap
was a **validator/renderer disagreement**, not merely a missing check:
`validateBackupRouterDst` (#4808/#2911) rejects a malformed next-hop, a
malformed destination, and a next-hop/destination FAMILY MISMATCH at strict
commit, and on the tolerant path downgrades each to a warning ending
*"(ignored: backup-router default route not installed until corrected)"*. The
renderer ignored nothing, so the promise in the log was false and the emitted
line failed the whole managed-section reload — with the log pointing AWAY from
the cause. **A validator that promises "ignored" owes a renderer that skips**,
and `TestMalformedBackupRouterIsNotRendered_8597` pins both sides so a future
change cannot leave the disagreement pointing the other way.

All **three** of the validator's checks are mirrored, not the two an
operand-shape reading suggests. A v4 next-hop with a v6 destination has two
individually well-formed operands and still renders `ipv6 route <v6dst>
<v4nh>`, which frr-reload rejects — the #2891 case the renderer's own
family-selection comment already describes. That third check compares two
INDEPENDENT operands, so it uses `frrOperandIsV6` (netip) rather than the
`strings.Contains(s, ":")` spelling used inline where both operands derive from
one value: `::ffff:192.168.50.1` contains a colon and is v4.

Not covered here: the `vrf <name>` clause still goes through `sanitizeFRRValue`
(#5557). That sanitizer maps control bytes to a space — the sink's own separator
— so it is the weaker belt described under #6796, but the routing-instance name
is validated at commit and is out of this issue's scope.

### `VRFName == ""` means the master table, and only the master table (#9409)

`InstanceConfig.VRFName` is overloaded by construction. The daemon's
`assembleFRRConfig` clears it for an `instance-type forwarding` instance —
correct, because such an instance has **no VRF device** and its statics must
render into `table <id>` so the kernel agrees with the FBF/PBR ip rules (#1827
PR-2). But `generateProtocols` reads an empty `VRFName` as *the global
instance*: `vrfSuffix` stays empty and every stanza renders unscoped.

Carrying a forwarding instance's protocols through that produced, on a commit
all four config channels ACCEPT with zero warnings:

| composition | rendered |
|---|---|
| forwarding + ospf | **two** `router ospf` blocks, neither with a `vrf` suffix; the instance's interface activated in the GLOBAL instance |
| forwarding + isis | a GLOBAL `router isis xpf` |
| forwarding + rip | a GLOBAL `router rip` |
| forwarding + bgp | the instance's `peer-as 65002` neighbor under a **second** `router bgp 65001` — it JOINS THE GLOBAL AS |

A `virtual-router` control on the same fixture renders `router ospf vrf
vrf-ISP-B` correctly, so this is specific to the forwarding type and not to
per-instance protocols in general.

The composition is now rejected at strict commit
(`config.validateForwardingInstanceProtocolsStrict`), and `assembleFRRConfig`
NILs a forwarding instance's protocol pointers before they reach this package.
The renderer is deliberately left alone: nothing here can distinguish "the
master table" from "a forwarding instance's table" through one empty string,
and the fix belongs where the discriminator still exists.

### Protocol interface operands are RESOLVED, not copied (#9405)

`protocols ospf area <a> interface <ref>` — and the OSPFv3 / IS-IS / RIP
equivalents — carried the **authored Junos reference** all the way into the
managed section. Compiled, `interface ge-0/0/1.0` stays `ge-0/0/1.0`; Linux
`dev_valid_name()` forbids `/`, so the rendered `interface ge-0/0/1.0` block
**could never bind a netdev** and no adjacency ever formed. Measured on all four
config channels (`configstore.CheckText`, `CompileConfig`,
`CompileConfigLenient`, `SchemaValidate`): every one ACCEPTS. The operator got a
green commit, a running FRR, and a dynamic-routing uplink that blackholes with
no diagnostic anywhere.

Static routes never had this problem — `generateStaticRoute` has carried its own
RETH map and `.0` strip since #5557/#6795 — and the sibling leaf in the same
`protocols` container (`router-advertisement`) already resolves through
`Config.ResolveKernelIfName` in `pkg/daemon`. The protocol stanzas were the
outlier.

`FullConfig.IfNameResolver` closes it. The daemon's `assembleFRRConfig` wires it
to `Config.ResolveKernelIfName` — the canonical resolver, which owns the
slash→dash rewrite, the RETH→local-member map, the unit-0 collapse and the
`.<vlan-id>` arm (#5107: a unit NUMBERED 80 carrying `vlan-id 180` is the netdev
`<member>.180`, and a resolver missing that arm names the wrong VLAN while
looking entirely plausible). `buildManagedSection` applies it once, to the
global block **and** to every routing instance, in `protocol_ifname_9405.go`.

Three properties are load-bearing:

- **Copies, never in place.** The pointers on `FullConfig` are the daemon's
  ACTIVE compiled config; a renderer that rewrites them is the #9141 defect.
  Every struct is copied by value, so a field added later to `OSPFInterface` or
  `ISISInterface` is carried through without an edit here.
- **A nil resolver is IDENTITY.** Direct `generateProtocols` callers (86 of them
  in `frr_test.go` alone) and any `FullConfig` built without a `*config.Config`
  in hand render exactly what they rendered before #9405.
- **The token belt applies either way.** `validFRRInterfaceOperand` — the same
  #6795 predicate the static-route interface operand uses — now covers the
  protocol operands, because they reach `frr.conf` by the same route: the schema
  leaf is free-form, so `interface "ge-0/0/1.0 zzz"` and `interface
  "ge-0/0/1.0; foo"` commit clean on all four channels. A reference that fails
  the belt is **dropped with a warning**, not rendered: it can never name a
  netdev, and one malformed line fails the whole frr-reload (#1880/#2223) —
  which would take down every protocol rather than one interface.

Resolving the operand also un-hid a collision. `generateInterfaceSettings`
suppresses its `ip ospf network point-to-point` line when the OSPF config sets
an explicit network-type, keying that suppression on the OSPF interface NAME
while `InterfacePointToPoint` is keyed by KERNEL name. With the raw slash
spelling the two could never match, so the suppression was inert; now that both
sides name `ge-0-0-1` it must actually fire, and `buildManagedSection` feeds the
interface-settings pass the RESOLVED OSPF set for exactly that reason.

The renderer cannot invent a device, so the other half of the silence is closed
at commit: `config.validateProtocolInterfaceRefWarnings` emits an advisory when
a protocol interface reference names no configured interface or unit, and a
distinct one for `interface all` (legal Junos, unimplemented here — it renders
as the literal operand `all`). Advisory rather than gate, per #1960: the
tolerant load / HA config-sync paths must still accept a config the strict
interface set does not explain.

### BGP neighbor identity is a single FRR token (#6796)

`n.Address` is rendered RAW at 24 sites in `protocols_render.go` — unlike every
operand around it (`update-source`, `description`, `password` all go through
`sanitizeFRRValue`). FRR's command lexer has **no quoted-string and no
rest-of-line token: it splits on whitespace**, so an identity carrying a space
or a newline SPANS MULTIPLE FRR STATEMENTS. An address of
`1.1.1.1 remote-as 65000\n neighbor 2.2.2.2` renders a valid first statement
followed by an attacker-chosen second one — arbitrary FRR configuration,
including peerings the operator never wrote, injected through a config value.

**`sanitizeFRRValue` is deliberately NOT the tool here.** It maps control bytes
to a SPACE, and space is exactly the separator FRR tokenizes on: replacing a
newline with a space still splits the token, and a plain embedded space is not a
control byte at all, so it passes through untouched. A sanitizer whose
replacement character is the sink's delimiter cannot make a value safe for that
sink.

The belt is `validBGPNeighborAddress` (`render_validate.go`), applied at the
`validNeighbors` construction — the SINGLE exclusion set the declaration loop,
the address-family activation loop and the BFD accumulator all iterate. That
placement is deliberate: a per-site guard would have to be repeated 24 times and
could diverge, and a neighbor declared-but-not-activated (or activated-but-not-
declared, or carrying a `bfd` peer without a declaration) makes vtysh reject the
**whole** managed section. It also covers the "reused raw by BGP and BFD" half of
the issue for free.

**The test is token COUNT, not address form.** FRR's grammar is
`neighbor <A.B.C.D|X:X::X:X|WORD>`, and this tree already commits configs whose
neighbor is a hostname — the first version of this fix required a bare IP and was
caught by a pre-existing parser test peering with `peer.example.com`.
Over-rejection in routing config is an outage.

Commit / commit-check stay strict (`validateBGPNeighborAddressStrict`,
`pkg/config`), with `lenientBGPNeighborAddress` registered per #1960 so a
tolerantly-loaded or peer-synced config still boots. The two predicates must
accept exactly the same set: a stricter commit gate tells operators a working
config is invalid, a stricter belt silently drops a committed peering, and
neither divergence produces an error anywhere.
`TestNeighborTokenGateAgreesWithTheRenderBelt6796` asserts the agreement by
reading both function bodies rather than pinning either to a literal — the first
version had BOTH wrong in the same direction, so trusting either side would have
encoded the mistake.

| File | Owns |
|---|---|
| `manager.go` | `Manager` struct + lifecycle (`New`, `ApplyFull`, `Clear`, `writeManagedSection`, `reload`), top-level types (`InstanceConfig`, `DHCPRoute`, `FullConfig`), package constants, and the zero-value-safe `executor()` accessor. The legacy `Apply`/`ApplyWithInstances` partial constructors were deleted (#1827 AGY F1, PR #1843): they bypassed `assembleFRRConfig` and would have wiped an active failover overlay. |
| `config_render.go` | Non-protocol config rendering: `generateInterfaceSettings`, `generateStaticRoute` (+ `generateStaticRouteInTable`, the table-suffix variant for `instance-type forwarding` instances, #1827 PR-2), named `ApplyFull` extractors (`renderGenerateRoutes`, `renderDHCPDefaults`, `renderBackupRouter`, `renderPreferredRoutes` — the #1827 ip-monitoring overlay as distance-1 statics, emission step 7 — `renderClusterModeDefaults`), and `resolveECMP` (which has a documented side effect: mutates `fc.ConsistentHash`). **`renderBackupRouter` family-awareness (#2891):** the route PREFIX family is matched to the NEXT-HOP (`BackupRouter`) family, not just the destination. An IPv6 backup-router with an empty/default `BackupRouterDst` defaults to `::/0` and emits `ipv6 route ::/0 <v6nh> 250`; before #2891 the default was always `0.0.0.0/0`, so a v6 next-hop with no destination emitted `ip route 0.0.0.0/0 <v6nh> 250` — a v4 prefix with a v6 next-hop, which frr-reload rejects and which fails the ENTIRE static config load. A v4 backup-router still defaults to `0.0.0.0/0` (`ip route 0.0.0.0/0 <v4nh> 250`). The complementary EXPLICIT-destination case — a `destination` prefix whose family MISMATCHES the next-hop (e.g. `backup-router 2001:db8::1 destination 0.0.0.0/0`) — is rejected at commit by `config.validateBackupRouterDst` (#2911) before it can reach this renderer, so frr-reload never sees the mismatched-family static. |
| `policy_render.go` (+ #6424 render siblings) | **Protocols + policy rendering** (documented here as one contract; #6424 split the code across `policy_render.go` + `protocols_render.go` + `redistribute.go` + `bgp_policy_chain.go` + `bfd.go` + `prefix_list_render.go` + `render_validate.go` — `generateProtocols` for OSPF/OSPFv3/BGP/RIP/ISIS, `generatePolicyOptions` for prefix-lists/route-maps/communities, `resolveRedistribute`, BFD profile + peer dedup). **All BFD is consolidated into a SINGLE top-level `bfd { ... }` block emitted exactly once** by `manager.go`'s `buildManagedSection` (#2550). FRR's `bfdd` is one global daemon, so a per-routing-instance `bfd` block produced redundant blocks and repeated profile definitions in the consolidated `frr.conf` (frr-reload parse-warning risk) once BFD was configured in more than one routing instance. The manager creates one `*bfdSection` accumulator (`newBFDSection`) and passes it to every `generateProtocols` call (default instance + each VRF); each call ACCUMULATES its OSPFv2/OSPFv3/ISIS interface profiles (`addProfile`, dedup by profile name) and BGP BFD peers (`addPeer`, in instance order) into the shared section and emits NO `bfd` block itself. After all instances render, `bfdSection.render()` emits one block — all peers first (instance order), then all profiles (sorted by name for determinism) — outside any `router`/instance scope. When `generateProtocols` is called WITHOUT a shared section (direct callers / unit tests, the optional `shared ...*bfdSection` variadic param is absent), it falls back to a function-local section emitted at the end: byte-identical per-stanza output, so only the block COUNT changes (one global block instead of one per instance). Each `peer` line still carries the in-scope `vrf <name>` suffix when the owning instance is VRF-scoped — `peer 10.1.1.2 vrf vrf-1`. FRR's `bfdd` is a single daemon: a bare `peer <addr>` line lands in the DEFAULT VRF and never associates with the VRF-bound BGP session, so the BFD session would stay permanently DOWN and sub-second failover would never work for VRF BGP peers (#2489). Default-instance peers (`vrfName == ""`) get NO suffix. `buildManagedSection` is the pure assembly half of `ApplyFull` (split out so whole-section invariants like the single-`bfd`-block property are unit-testable via the real assemble path). OSPFv2 area membership is rendered per-interface as `ip ospf area <id>` under `interface <name>` (matching the OSPFv3 idiom), never as a global `network <prefix> area` statement — see #1712. **Route-filter match-types** (the `from route-filter <prefix> <match-type>` switch in `generatePolicyOptions`) render to FRR prefix-list entries as: `exact` → bare prefix (no `le`/`ge`); `orlonger` → default `le 32`/`le 128` (`le == prefix-len` on a `/32`/`/128` is FRR-VALID — only `ge`/`le` *strictly less than* the prefix length is rejected); `longer` → `ge <plen+1> le max`; `upto /N` → bare `le N` (NO `ge`), with `upto /N == prefix-len` — and any `upto` on a max-length host prefix (`/32`/`/128`) — rendering as **exact** (bare prefix, no `le`/`ge`), since a max-length prefix has no more-specifics (#2072). For `longer`, a max-length prefix (`/32`/`/128`) has no strictly-more-specific routes at all — the empty set — so the entry is **skipped entirely** rather than emitting the FRR-invalid `ge <plen+1> le max` (e.g. `ge 33 le 32`, which fails FRR's YANG range `0..32` and `ge > le`); the boundary skips ONLY `plen == max`, so `/31 longer` still emits the valid `ge 32 le 32` (#2103). When a term's route-filters are ALL skipped (or all malformed), the renderer emits no `ip/ipv6 prefix-list` entry lines (a materialised count==0 prefix-list is FRR `PREFIX_PERMIT`/match-ALL, so the list name must NEVER be created) but STILL emits the `match … prefix-list <name>` line referencing the now-undefined list: FRR resolves an undefined prefix-list to NULL → `RMAP_NOMATCH` (DENY), so the term matches NOTHING and stays fail-closed. The match line must NOT be suppressed — a `route-map … permit <seq>` with no `match` clauses is treated by FRR as match-ALL, which would flip a `/32 longer` empty-set term to permit-everything (Copilot #2110). This mirrors the `from prefix-list` branch, which likewise emits a `match` line for an unknown/empty list. The `match`-line address family is derived from the first *emitted* entry, else the first *parseable* route-filter (a skipped `/32 longer` still names a real family), else IPv4 (#2103/#2105). **Mixed-family route-filter terms (#2607):** a single term whose route-filters mix IPv4 AND IPv6 prefixes (a legitimate dual-stack export/import) is rendered as **TWO route-map sequences** — one per family — each with its own seq slot, a single-family `match ip|ipv6 address prefix-list` line over a per-family list (`<policy>-<term>_v4` / `<policy>-<term>_v6`), and the full term body (`set`/action, plus `on-match next` when non-terminating). This is required because FRR ANDs match clauses of DIFFERENT types within ONE route-map index (`lib/routemap.c route_map_apply_match` invokes every match rule with no address-family pre-filter): emitting both `match ip` and `match ipv6` in one sequence would make a v4 route NOMATCH the ipv6 clause and a v6 route NOMATCH the ip clause → `MATCH + NOMATCH = NOMATCH` ANDs the index to a silent deny for BOTH families (the same AND finding that drove #2071's single-matcher decision). The pre-#2607 renderer compressed the term into ONE `matchV6` boolean and emitted a single match line, so the OTHER family's prefix-list entries were written but never matched and those routes silently failed the term. The two per-family lists carry distinct NAMEs so neither match line can pick up an off-family entry, and a co-resident `from prefix-list` match clause is emitted ONLY in the sequence whose family matches the referenced list (so it never AND-NOMATCHes the off-family sequence — the #2071 co-resident collision, avoided by construction). A **homogeneous** (single-family) or empty route-filter term is UNCHANGED: ONE sequence, the historical un-suffixed `<policy>-<term>` list name, ONE match line — byte-identical to the pre-#2607 render (no churn for the common case). **Repeated same-type `from` matches (#2642):** Junos allows MULTIPLE sibling `from prefix-list`/`from community`/`from as-path` statements in ONE term (e.g. `from { community c1; community c2; }`), which match with OR ("any") semantics — `PolicyTerm.PrefixList`/`FromCommunity`/`FromASPath` are `[]string` so every repeated match is kept (the pre-#2642 single-string field silently dropped all but the last). FRR holds only ONE rule of each match TYPE per route-map index: `route_map_add_match` (`lib/routemap.c`) REPLACES a same-type rule, so two `match community` (or two `match ip address prefix-list`, two `match as-path`) lines in one sequence keep only the LAST — the very loss #2642 fixes, just moved into FRR. OR is therefore expressed the same way #2607 expresses the family split: one route-map SEQUENCE per value, each carrying the full term body and the same `permit`/`deny` action, so a route matching ANY value reaches a sequence it satisfies. Because different match TYPES must AND while same-type ORs, `generatePolicyOptions` emits the **CARTESIAN PRODUCT** of the three from-* OR-sets (prefix-list × community × as-path), nested INSIDE the route-filter family split (a mixed-family term with multi-matches still splits per family first, then cross-products within each family): e.g. `from { community c1; community c2; as-path a1; }` = `(c1|c2) AND a1` renders as two sequences `{c1,a1}` and `{c2,a1}` — the as-path match ANDs into BOTH. A single-valued term (one or zero of each from-* type) collapses to ONE sequence with the historical un-suffixed list name — byte-identical to the pre-#2642 render. **Route-map sequence-number ceiling (#5701):** FRR route-map sequence numbers occupy `route-map WORD <permit|deny> (1-65535)`, and `renderPolicyTermSequences` numbers each emitted term sequence in steps of 10 starting at 10 with one trailing default sequence, so a policy expanding to `N` term sequences uses a highest seq of `10*(N+1)` — over 65535 once `N > 6552`. A `route-map` line past seq 65535 is rejected by FRR (`CMD_WARNING_CONFIG_FAILED`) and a single failed line makes the vtysh-batched `frr-reload` exit non-zero, POISONING the whole managed-section reload. The count is bounded at commit: `config.RouteMapSequenceCount` (the SSOT projected-count helper, mirroring the per-term `family-split × prefix-list × community × as-path` product) feeds `validatePolicyRouteMapSequenceBoundStrict` (`pkg/config`, wired in `runUniformGates`), which hard-rejects an over-`config.MaxRouteMapSequences` (6552) policy on commit / commit-check and warns on the tolerant load / peer-sync path (`lenientPolicyRouteMapSeq`, #1960). As the render-side belt for that lenient path, `generatePolicyOptions` SKIPS a policy whose `config.RouteMapSequenceCount` exceeds the ceiling (emitting no route-map, logging a `slog.Warn`) so a leniently-loaded oversized policy renders nothing rather than poisoning the reload. **Composed BGP policy-CHAIN ceiling (#5732):** `renderComposedRouteMap` concatenates an ordered `export`/`import [ A B ... ]` chain (#5277) into ONE route-map with a RUNNING seq accumulated across all rendered members, so a chain whose members each pass the per-policy bound can still SUM past 65535 (the #5701 overflow re-introduced at the chain level, trivially reached by splitting one oversized policy in two). `config.ComposedChainSequenceCount` (the SSOT composed-count helper — the sum of `RouteMapSequenceCount` over the chain's members, truncated at the first member with an explicit terminating policy default, since `renderComposedRouteMap` stops there) feeds `validateBGPComposedChainSequenceBoundStrict` (`pkg/config`, wired in `runUniformGates`), which resolves every neighbor's effective export/import chain (mirroring `bgpNeighborExportChain`/`filterDefinedPolicies` across the default instance + every VRF) and hard-rejects an over-`MaxRouteMapSequences` chain on commit / commit-check (warns on the tolerant path, `lenientPolicyRouteMapSeq`). `renderComposedRouteMap` consults the SAME `config.ComposedChainSequenceCount` predicate and renders NOTHING for an over-ceiling chain on the tolerant path (its `route-map <composedName> out` then dangles → FRR permit-all, strictly better than a poisoned reload — the same tradeoff `generatePolicyOptions` takes). The per-policy #5701 gate is kept for defense in depth. **Flat-set convergence (#2630, fixed):** repeated `set ... from community c1` / `from community c2` siblings used to be COLLAPSED by `ConfigTree.SetPath` onto one AST node before the compiler ran, so only the LAST value survived on the flat-set path. #2630 marks the four repeatable `from` leaves — `route-filter`, `prefix-list`, `community`, `as-path` — `multi: true` in `setSchema` (`pkg/config/schema_routing.go`), so `SetPath` now keeps every repeated `set ... from <type> <value>` line as a distinct sibling leaf. The flat-set and hierarchical/brace AST shapes therefore CONVERGE on the same compiled OR-set, and the Cartesian-product rendering above applies identically regardless of which syntax produced the term. Per-entry seq slots keep each route-filter's ORIGINAL index across the split, so a split term's v4 and v6 entries occupy the same seq numbers (with FRR-legal gaps where the other family's entries sit) they would have in a combined list. The `ge` value used in a rendered line is ALWAYS strictly greater than the prefix length, and `le` is ALWAYS >= the prefix length (never strictly less — `orlonger`/`upto` may emit `le == prefix-len`, which is FRR-valid), and a rejected line can fail the whole `frr-reload` (`frr-reload.py` applies the add-batch via a single `vtysh -f` and exits non-zero on any `CMD_WARNING_CONFIG_FAILED`) — that is why `longer` uses `plen+1`/skips at max, and `upto` emits a bare `le N`. `upto` length 0/unset (the compiler rejects `upto /0` so 0 means unset) degrades to a valid `le family-max` (orlonger-equivalent superset) when the prefix is not max-length. `upto` lengths **below the base prefix** (`< prefix-len`, an EMPTY length range) or **above the family max** (`> 32`/`128`) have no valid Junos meaning and are **skipped (match-nothing, fail-CLOSED)** — the earlier #2072/#2102 code degraded these to the open-ended `le family-max`, which silently WIDENED the match to base-plus-all-more-specifics (fail-OPEN on a route-filter that gates route accept/redistribute, #4484 L-12). Skip aligns with the #2525 fail-closed posture the sibling invalid match-types (`prefix-length-range`/`through`/unknown) already use, and — like them — emits no line (an FRR-legal seq gap), never the invalid `le < prefix-len` the #2102 degrade was avoiding. The **route-filter prefix is CIDR-validated at commit** (`ValidateRouteFilterArg` keyValidator, `pkg/config`): a malformed prefix is rejected at commit/commit-check (strict) but tolerated on load/HA-sync (lenient, #1960); the renderer carries a belt-and-suspenders skip for any malformed prefix that reaches it via the lenient path (#2105). `prefix-length-range /lo-/hi` renders as FRR `ge lo le hi` (#2525); the `/lo-/hi` bounds are parsed into `RouteFilter.RangeLow`/`RangeHigh` and semantically validated at commit (`validateRouteFilterMatchTypesStrict`, `pkg/config`): low<=high, both within the family max (`32`/`128`), and low **strictly greater than** the base prefix length (FRR requires `len < ge-value`; a `ge <= base` line is rejected and would fail the whole `frr-reload`, #1880-class). The renderer re-derives the base length and SKIPS the entry (match-nothing) on the lenient path when `low <= base`, so a downgraded-to-warning range never emits an FRR-invalid `ge <= base` line. `through <p2>` has NO lossless FRR prefix-list (ge/le) equivalent — it matches a two-prefix radix-tree containment path, not a length range — so it is **hard-rejected at commit** (lenient-warn on load/HA-sync per #1960); the renderer carries a belt-and-suspenders skip for both a stored `through` and a malformed/out-of-bounds `prefix-length-range` that reach it via the lenient path, and the `switch` has a `default` arm so NO unhandled match-type can ever fall through to the open-ended `le 32`/`le 128` default again (the #2525 silent-leak bug). **Multi-term fall-through (`on-match next`, #2451):** Junos evaluates a policy-statement's terms sequentially — a term whose `then` carries ONLY modifications (`community`, `local-preference`, …) and NO `then accept`/`then reject` (`PolicyTerm.Action == ""`) APPLIES its `set` clauses and FALLS THROUGH to the next term. FRR otherwise STOPS a route-map after the first matching `permit` sequence runs its `set` clauses, silently truncating every later term. `generatePolicyOptions` therefore appends ` on-match next` to each non-terminating term's sequence (rendered `permit`, `Action != accept/reject`), making FRR run the `set` clauses then continue evaluating subsequent sequences. A terminating term — `then accept` (permit, stop) or `then reject` (deny, stop) — gets NO `on-match next`, matching Junos terminating semantics. `on-match next` only fires on a MATCHED sequence (a non-matching term advances regardless), and falling off the end still hits the policy `default-action` sequence emitted after the term loop, so the overall default behavior is preserved. **Next-hop address family (#2403):** `then next-hop <addr>` is rendered with the FRR set-clause matching the literal's family — an IPv6 next-hop (detected by `strings.Contains(addr, ":")`, the same AF probe the prefix-list path uses) renders `set ipv6 next-hop global <ip>`, NOT `set ip next-hop <ip>` (FRR rejects a v6 address on the v4 clause with a syntax error that fails the WHOLE route-map parse and can brick a reload); a v4 literal keeps `set ip next-hop <ip>`. `next-hop peer-address` emits BOTH `set ip next-hop peer-address` and `set ipv6 next-hop peer-address` since the carrying BGP session's family is unknown at render time and FRR applies each clause only to the matching family. **`next-hop self` (#2977, term-scoped in #5115):** FRR has NO literal `set ... next-hop self` clause (its parser rejects it and fails the WHOLE route-map), but in an OUTBOUND route-map `set ip next-hop peer-address` resolves to the LOCAL end of the BGP session — i.e. self — and is evaluated PER-ROUTE. So `then next-hop self` renders inside the term's route-map sequence as BOTH `set ip next-hop peer-address` and `set ipv6 next-hop peer-address` (the session AF is unknown at render time; FRR applies each clause only to its matching family, mirroring the `then next-hop peer-address` branch), scoped to exactly the routes that term matches. A BGP export policy is always rendered as `route-map <name> out`, so the clause always evaluates outbound (= self). Because the set-clause overrides the next-hop unconditionally for every route the sequence matches, it still rewrites route-reflector-REFLECTED (iBGP-learned) routes — the #2977 blackhole case xpf supports via `cluster-id` + `route-reflector-client` — the same effect the old `force` gave, now correctly limited to the term. A bare `then next-hop self` term (no `from` match) renders a match-all sequence, so a genuinely neighbor-wide self keeps its neighbor-wide effect. `next-hop self` is an OUTBOUND/advertise concept and, since the lowering lives in the shared route-map body, applies wherever that policy is used as an export. **#5115 fix:** earlier revisions lowered `then next-hop self` to the neighbor-wide `neighbor <peer> next-hop-self force` knob (via a `policyStatementHasNextHopSelf` scan of the effective export policy). FRR's knob runs AFTER route selection and rewrites EVERY route advertised to the peer — including routes accepted by OTHER terms that never requested self — silently WIDENING a term-scoped action to the whole neighbor (e.g. a policy that sets self on one prefix-list term while another term advertises third-party next-hops unchanged). The per-term route-map `set` clause restores Junos monotonicity (a term action affects only that term's routes) while keeping the #2977 iBGP/RR rewrite. The pre-#2977 renderer emitted NOTHING for `then next-hop self` on the false premise that "eBGP rewrites next-hop to self by default" — true for eBGP but NOT for iBGP / route-reflector advertisements, where the next-hop is PRESERVED by default; dropping the rewrite left iBGP peers with the original eBGP next-hop, no IGP path to it, and a silent blackhole. **BGP maximum-paths vs global ECMP (#2791):** the BGP address-family `maximum-paths` line is driven SOLELY by the explicit `protocols bgp multipath` knob (`bgp.Multipath`). It is NOT seeded from the global forwarding-table ECMP value (`ecmpMaxPaths` from `resolveECMP`) — ECMP is a zebra/kernel forwarding concept and the global knob still reaches the IGP/zebra `maximum-paths` lines (OSPFv2 `router ospf`, OSPFv3 `router ospf6`, and the top-of-instance render), but it must never silently turn on BGP multipath path-selection the operator did not configure. The pre-fix code did `bgpMaxPaths := ecmpMaxPaths` then only bumped it up for `bgp.Multipath`, so any global ECMP rendered `maximum-paths` into both BGP unicast address-families. **OSPFv3 ECMP (#2997):** the `router ospf6` block emits ` maximum-paths <n>` from the SAME global `ecmpMaxPaths` (`resolveECMP`) as the OSPFv2 `router ospf` block, gated identically on `ecmpMaxPaths > 1` and placed after the per-interface area-membership lines, before the redistribute lines. OSPFv3 has no separate maximum-paths config leaf — it reuses the global forwarding-table ECMP knob exactly like OSPFv2. Before #2997 the ospf6 block omitted the line entirely, so FRR `ospf6d` installed a single best path and IPv6 OSPF ECMP was never enabled even when global forwarding-table ECMP > 1. **`then metric` / MED presence (#2847):** the `set metric <N>` clause is emitted on PRESENCE (`PolicyTerm.HasMetric`, set by the compiler whenever the `then metric` leaf is parsed — both the hierarchical and flat-set paths in `compiler_routing.go`), NOT on `Metric > 0`. A metric/MED of **0** is a valid BGP traffic-engineering value (advertise a highly preferred route); the pre-#2847 `if term.Metric > 0` gate could not tell an explicitly configured `then metric 0` apart from an unset metric, so it silently dropped `set metric 0` and the operator's MED never reached FRR. An UNSET metric (`HasMetric == false`) still emits no `set metric` clause, so the common case is byte-identical. **`then local-preference` presence (#2857):** the direct sibling of #2847 — the `set local-preference <N>` clause is emitted on PRESENCE (`PolicyTerm.HasLocalPreference`, set by the compiler whenever the `then local-preference` leaf is parsed — both the hierarchical and flat-set paths in `compiler_routing.go`), NOT on `LocalPreference > 0`. A BGP **local-preference of 0** is a valid value (maximally deprioritize a route within the AS; FRR's route-map YANG range starts at 0); the pre-#2857 `if term.LocalPreference > 0` gate could not tell an explicitly configured `then local-preference 0` apart from an unset value, so it silently dropped `set local-preference 0` and the operator's intent never reached FRR. An UNSET local-preference (`HasLocalPreference == false`) still emits no `set local-preference` clause, so the common case is byte-identical. **`then community` operations (#2848):** the community action is no longer replace-only. Junos/vSRX `then community (add \| delete \| set) <name>` plus `then community none` (and the legacy bare `then community <value>` = replace) compile into `PolicyTerm.CommunityOp` (`""`/`set`/`add`/`delete`/`none`) with the value in `Community` (replace), `CommunityAdd` (append), or `CommunityDelete` (community-list NAME(S) to strip — a `[]string`, see #2902) — set by `applyCommunityAction` (`compiler_routing.go`) on both the hierarchical and flat-set paths via the multi-value `then community` leaf. The renderer maps each operation to its FRR route-map set clause: `add` → `set community <v> additive` (APPEND — the parity fix; emitting only the replace clause wiped any upstream-set communities), `delete` → one `set comm-list <name> delete` line PER referenced list (strip members of each named `bgp community-list <name>` xpf already renders from `policy-options community <name>`), `none` → `set community none` (strip all), and `set`/`""` → `set community <v>` (whole-attribute replace, byte-identical to the pre-#2848 render). A community add/delete/none term with no `then accept`/`reject` is non-terminating like any other set-only term and still gets `on-match next` (#2451). **Multi-list delete (#2902):** `then community delete [ listA listB ]` references MULTIPLE community-lists; FRR's `set comm-list <name> delete` strips ONE list per line, so `CommunityDelete` is a `[]string` and the compiler accumulates every name in `vals[1:]` (the lexer strips the brackets so the clause flattens to `delete listA listB` — the #2419 multi-value shape) and the renderer emits one `set comm-list <name> delete` clause per list. The pre-#2902 code stored only `vals[1]`, so `listB...` were silently dropped and the communities the operator meant to strip leaked into advertised prefixes. **`then as-path-prepend` (#2892):** Junos `then as-path-prepend "<asn> <asn> ..."` (BGP inbound traffic-engineering — repeating the local ASN lengthens the advertised `AS_PATH` so peers prefer a shorter alternate path) compiles into the ordered `PolicyTerm.ASPathPrepend []string` and renders the single FRR clause `set as-path prepend <asn> <asn> ...` with every ASN in order. The leaf is `multi:true` (`then as-path-prepend` in `setSchema`, `pkg/config/schema_routing.go`) so a quoted `"65001 65001"` or bracketed `[ 65001 65001 ]` list — the lexer strips quotes and brackets alike — flattens onto the node's Keys/Children rather than collapsing to last-only; the compiler reads EVERY ASN via `firewallMatchValues` on both the hierarchical and flat-set paths (reading only `Keys[1]` would drop all but the first prepend — the #2419/#2892 trap — and dropping the repeats defeats the whole mechanism). An empty `ASPathPrepend` emits no clause, so a term without prepend is byte-identical to the pre-#2892 render. A prepend-only term with no `then accept`/`reject` is non-terminating and gets `on-match next` (#2451) like any other set-only term. **iBGP multipath (#2978):** the address-family `maximum-paths <n>` line above enables eBGP multipath ONLY — FRR keeps a single best-path for iBGP-learned prefixes unless the SEPARATE `maximum-paths ibgp <n>` command is also present, so iBGP ECMP was never enabled even when `protocols bgp multipath` was configured. When the operator adds `protocols bgp multipath ibgp` (`BGPConfig.MultipathIBGP`, a sibling flag of `multipath multiple-as` parsed in `compiler_protocols.go`), the renderer emits `maximum-paths ibgp <n>` immediately after the eBGP `maximum-paths <n>` in BOTH unicast address-families, reusing the same `bgpMaxPaths` count. Without the flag the render is byte-identical to pre-#2978 (eBGP-only), so configs that relied on eBGP-only multipath are unaffected. **Policy-statement default action (#2998):** a Junos policy-statement that reaches its end without a terminating term falls through to the PROTOCOL default policy, which is application-specific — **BGP import AND export both default-ACCEPT** the unmatched route (vSRX advertises/accepts it unmodified), while a **redistribute / forwarding-table export** policy defaults to **REJECT**. FRR route-maps carry an implicit trailing deny, so a BGP policy that only tweaks attributes on a few terms and expects the rest to pass unmodified would BLACKHOLE every non-matching route under the old unconditional trailing `route-map <name> deny <seq>` for `DefaultAction == ""`. The fix threads the protocol-application context into the terminal-sequence render: `manager.go`'s `buildManagedSection` builds a set of policy-statement names applied as a BGP `route-map in`/`out` via `collectBGPRouteMapPolicies` (default instance + every VRF; it MIRRORS the exact emit conditions in `generateProtocols` — effective per-neighbor import/export resolved by `bgpNeighborImportChain`/`bgpNeighborExportChain` (#5277) and filtered to defined policy-statements, recording only SINGLE-policy chains since a multi-policy composed chain carries its BGP-accept default internally; bare redistribute tokens take the redistribute path and never enter the set) and passes it to `generatePolicyOptions` (optional `bgpAccept ...map[string]bool` variadic — direct/test callers omit it and keep the historical fail-closed `deny`). The default-action `switch` then renders: explicit `then accept` → `permit`; explicit `then reject` → `deny`; **no policy default + BGP route-map context → `permit`** (BGP default-accept, the #2998 fix); no policy default elsewhere (redistribute / forwarding-table export / a standalone unused policy) → `deny` (fail-closed, matches the OSPF/redistribute Junos default AND FRR's implicit deny — the deliberate fail-closed posture this fix must NOT weaken). The classifier is BGP-route-map-usage scoped. **Cross-context leak fix (#4481):** because FRR route-maps are keyed by NAME (one object shared by every use site), the rare config that shares ONE policy-statement between a BGP route-map in/out AND an IGP `redistribute` export would previously let the BGP-accept trailing `permit` govern the redistribute too — leaking every non-matching route into the IGP (Junos redistribute default is REJECT). The renderer now emits a **per-use-site fail-closed alias**: `generatePolicyOptions` renders the base `route-map <name>` with the BGP permit default AND, when `policyNeedsRedistAlias` holds (name in `bgpAcceptDefault` with no explicit default), a second `route-map <name>-xpf-redist` carrying the fail-closed trailing `deny`; `resolveRedistribute` points the `redistribute <proto> route-map` line at that alias while the BGP neighbor keeps referencing the permit-default base. The whole per-policy body is factored into `renderRouteMapForPolicy(po, emitName, ps, trailingAction)` so the base and the alias share identical terms/matches/set-clauses (inline route-filter prefix-lists derive from `emitName`, so the alias gets its own self-contained lists) and differ ONLY in the header name and the trailing default. `buildManagedSection` computes the GLOBAL `bgpAcceptDefault` union (default instance + every VRF) once and threads it into BOTH `generatePolicyOptions` AND `generateProtocols`→`resolveRedistribute`, so a policy used as a BGP map in one instance and redistributed in another still aliases correctly. The `-xpf-redist` suffix (`config.ReservedRedistSuffix`) is RESERVED and now ENFORCED (#5116): the strict commit gate `validatePolicyReservedRedistNameStrict` (`pkg/config`) hard-rejects an operator policy-statement whose name ends in it (lenient-warn on load/HA-sync per #1960), so the generated-alias namespace is injective by construction; the derivation (`redistFailClosedRouteMap`) and the validator share the one constant so they cannot drift. As defense-in-depth, `redistAliasCollision` — called by `ApplyFull` before it builds the managed section — refuses to render (returns an error, so the whole apply fails CLOSED and FRR keeps its last-good config) if a generated alias would still collide with an operator policy-statement of that exact name on the tolerant path where the strict gate only warned. This closes the former F-220-class non-injective-name caveat for redist aliases rather than merely documenting it as unlikely. A policy with an explicit `then accept`/`then reject` default renders the same trailing action in every context and needs no alias. |
| `protocol_ifname_9405.go` | **Protocol interface operand resolution + belt (#9405).** `FullConfig.ifNameResolver` (nil ⇒ identity) plus `resolveOSPFIfNames` / `resolveOSPFv3IfNames` / `resolveRIPIfNames` / `resolveISISIfNames`, which return COPIES with each reference resolved to its kernel netdev name and each unrenderable reference dropped through `validFRRInterfaceOperand`. Called once from `buildManagedSection`, for the global block and every instance. BGP is absent because its peers are addresses, not interface references. |
| `naming.go` | **FRR identifier naming for xpf-GENERATED objects (#5872).** When a route-map sequence carries BOTH a same-family route-filter `match ip\|ipv6 address prefix-list` line AND a `from prefix-list` match, the two same-type rules would COLLIDE in FRR (`route_map_add_match` REPLACES a same-type rule, keeping the last), silently dropping the route-filter constraint — so `policy_render.go`'s `renderFromPrefixListACL` materializes the from-prefix-list as an ACCESS-LIST (a distinct FRR rule type) and FRR ANDs the two (#5730). That access-list needs a name. The pre-#5872 renderer built it as `fromPrefixList + "_rf"` — a bare concatenation of an operator-controlled Junos identifier with **no namespace, no byte-length bound, and no collision registry**, so a long valid name could exceed FRR's ~128-byte access-list identifier limit (reload rejection) and two long names sharing a >=125-byte prefix could truncate-collide inside FRR to one stored token (two unrelated access-lists MERGE → a silent, security-relevant widen/narrow of a routing policy). **`routeFilterACLName(prefixList, matchKW)`** replaces the concatenation: a reserved `xpf-rf-` namespace prefix (distinct from raw operator names), a human-readable `sanitizeFRRIdent`-cleaned + byte-bounded slice of the source name, and a deterministic SHA-256 suffix over `(family, FULL prefixList)` — hashing the FULL name (not the truncated slice) is what defeats the truncation-collision, and determinism (no map order, no randomness) keeps the name STABLE across daemon restarts. The result is bounded to `frrACLNameMaxLen` (96, generous margin under 128). The renderer uses the SAME return value for both the access-list DEFINITION and the route-map REFERENCE, so they always agree by construction. **`routeFilterACLNameCollision(po)`** is the render-side belt (called by `ApplyFull` beside `redistAliasCollision`/`bgpComposedChainCollision`, deterministic sorted order, FIRST offending pair reported): it fails the whole apply CLOSED — FRR keeps its last-good config — when an operator prefix-list name intrudes on the reserved `xpf-rf-` namespace, or when two distinct `(family, prefix-list)` identities map to the same final name within one address family (a 64-bit hash collision), checking EVERY family a list renders under (a mixed list can materialize an access-list in BOTH). `prefixListFamilies` is the SINGLE shared family selector — the per-family generalization that supersedes the old single-family `prefixListMatchKW` collapse: it returns `["ip"]` / `["ipv6"]` for a single-family list and **BOTH `["ip", "ipv6"]`** for a mixed v4+v6 list, so the renderer and the collision precheck never disagree. A mixed `from prefix-list` therefore binds BOTH families instead of collapsing to ipv6 and silently dropping every v4 route (#2607): `policy_render.go`'s `fromPrefixListRefs` expands a mixed referenced list into one `ip` ref and one `ipv6` ref, each emitted in its own route-map sequence (the two families cannot share an index — FRR ANDs match clauses, so a v4 route would NOMATCH the ipv6 clause and vice versa), reusing the same one-sequence-per-OR-value mechanism as the #2642 multi-value split. Other FRR identifier surfaces can adopt the same helpers as a follow-up. |
| `vtysh.go` | `frrExecutor` interface (Vtysh / FrrReloadPy / VtyshLoad / **VtyshStream**), `realExecutor` (production exec.Command implementation), `ExecVtysh`, and all raw-output Get* shells (`GetBFDPeers`, `GetRouteMapList`, `GetISIS*Detail`/`Database`/`Routes`, `GetOSPF*Detail`/`Database`/`Interface`/`Routes`, `GetBGPNeighbor*`). **`VtyshStream(ctx, command)` returns stdout as an `io.ReadCloser` + a `finish()` reaper** so a caller can scan a huge table incrementally instead of buffering it whole (`Vtysh`); `exec.CommandContext` kills vtysh when `ctx` is cancelled, which is how `StreamBGPRoutes` stops a full-RIB dump on client disconnect / write failure (#5056). |
| `status_parse.go` | Parsed Get* methods + their public types (`RIPRouteEntry`, `ISISAdjacency`, `OSPFNeighbor`, `BGPPeerSummary`, `BGPRoute`, `FRRRouteDetail`, `FRRNextHop`) + `parseRouteJSON`, `parseBGPSummaryJSON`, `parseBGPRouteLine`, `FormatRouteDetail`. **`GetBGPSummary` parses `show bgp summary json`** (structured JSON, `parseBGPSummaryJSON`), NOT the text table — see the #3942 note below. **`GetBGPRoutes` buffers the whole `show bgp ipv4 unicast` table** (vtysh stdout string + parsed `[]BGPRoute`) and is used by the CLI/gRPC show paths that already render the full result. **`StreamBGPRoutes(ctx, limit, fn)` is the bounded-memory variant** (#5056): it scans vtysh stdout one line at a time via `VtyshStream`, hands each parsed route to `fn`, stops after `limit` routes (reporting `truncated`), and cancels vtysh on `ctx` cancellation or an `fn` error. Both share `parseBGPRouteLine` so they interpret the table identically. The REST `/routing/bgp?type=routes` handler uses `StreamBGPRoutes`. **`GetRouteDetailJSON` per-family error contract (#5125):** it runs `show ip route json` and `show ipv6 route json` independently and, on a per-command vtysh or JSON-parse failure, `errors.Join`s the failure (tagged with the failing command) into the returned error INSTEAD of the pre-#5125 `continue`-and-return-`nil` swallow, while still returning the family that succeeded. A non-nil error alongside a non-empty slice therefore means "partial" — the `show route detail` callers (`pkg/cli/cli_show_routing.go`, `pkg/grpcapi/server_show_routes_text.go`) render the partial and emit a non-fatal `warning: partial route display ...` line rather than dropping the whole view. This mirrors the read-side contract documented in `pkg/routing/README.md` ("Route-display read error contract"). |

## Every operational vtysh shell-out is bounded and cancellable (#9143)

`Manager.vtysh(ctx, command)` is the SINGLE funnel every operational FRR read in
this package goes through. It does two things the individual `Get*` shells used
to skip:

1. **Admission.** It takes a slot from `diagcmd.VtyshLimiter`
   (`MaxConcurrentVtyshShellOuts`, process-wide, shared by REST and gRPC).
   Over-cap returns `frr.ErrVtyshBusy` **before forking**. Fail-fast, not
   queued — a queued request holds the same connection it would have held while
   running, so queueing converts a concurrency bound into a latency bound.
2. **Cancellation.** It hands the CALLER's context to the executor.
   `realExecutor.Vtysh` composes `context.WithTimeout(ctx, vtyshTimeout)`, so the
   effective deadline is the earlier of the caller's and 15s, and a cancelled
   request (HTTP client disconnect, cancelled gRPC stream) makes
   `exec.CommandContext` kill and reap the child immediately.

**Which side of "every X except one" was wrong.** Before #9143 exactly ONE
branch of one handler was gated: #6809 put `ribStreamLimiter` on
`GET /api/v1/routing/bgp?type=routes` because a full-RIB stream is expensive in
memory and holds a connection. Every other FRR shell-out — REST `ospf` (both
branches) and `bgp` summary, plus the gRPC `GetOSPFStatus` / `GetBGPStatus` /
`GetRIPStatus` / `GetISISStatus` / `GetRoutes` RPCs — forked one child per
request with no admission at all, and `realExecutor.Vtysh` hardcoded
`context.Background()` so the client could not stop what it started.

The gated branch was RIGHT and under-generalized; the ungated majority is the
outlier. That is not a judgement call — `pkg/diagcmd` already asserts the same
rule three times for this cost class: `DefaultLimiter` (#5057) bounds the
REST+gRPC ping/traceroute handlers because they fork a child,
`SessionWalkLimiter` (#5433/#5708) bounds every full-table walk on both
surfaces, and `SnapshotReadLimiter` (#8151) bounds the snapshot copies. An FRR
status read forks a child for up to 15s; it is the same class as a forking ping
handler and was simply never gated. So generalizing the rule extends an existing
convention rather than propagating a mistake — which is the check worth making
before funnelling anything, since a funnel applies whatever it holds to every
call site at once.

The bound is enforced in the funnel rather than at each handler on purpose:
gating them one at a time would leave the twentieth FRR read to be added
unbounded again. Nothing in this package can reach `vtysh` except through
`Manager.vtysh`.

**The apply path is deliberately NOT behind it.** `FrrReloadPy` and `VtyshLoad`
are driven by a config commit rather than by a client, and are already
serialized by the reload lock. Putting them behind a client-facing budget would
let a status flood refuse a commit. Pinned by
`TestApplyPathIsNotBehindTheStatusBudget9143`.

**Surface mapping.** `ErrVtyshBusy` is a REFUSAL, not a fault — the FRR daemons
are healthy and we declined to ask. REST renders it **429 + Retry-After**
(`writeFRRError`, `pkg/api/routing.go`), gRPC renders it
**`codes.ResourceExhausted`** (`frrStatusErr`, `pkg/grpcapi`). The two surfaces
classifying one event identically is the #9142 lesson applied here. Both
mappings are ADDITIVE: every error that could be returned before #9143 still
renders 500 / `codes.Internal`, because `ErrVtyshBusy` is a new condition only
the new limiter can produce.

Guards: `vtysh_admission_ctx_9143_test.go` (including a cell that drives all
nineteen operational reads and asserts each is behind the funnel — coverage that
is structural rather than a hand-picked list), `pkg/api/routing_frr_admission_9143_test.go`,
`pkg/grpcapi/routing_frr_admission_9143_test.go`.

## Entry points

- `Manager` — `manager.go`.
- `New() *Manager` — `manager.go`. Defaults to `/etc/frr/frr.conf` and
  to a real `os/exec`-backed `frrExecutor`.
- `ApplyFull(fc *FullConfig) error` — `manager.go`. Apply full config
  (idempotent diff against on-disk).
- `FullConfig`, `InstanceConfig`, `DHCPRoute` — `manager.go`.
- State queries: raw-text shells in `vtysh.go`, parsed `Get*` methods
  in `status_parse.go`. All shell-outs route through `m.executor()`
  so they can be faked in tests (see `executor_test.go`).

## Callers

`pkg/daemon` (lifecycle), `pkg/grpcapi` (show commands).

`FullConfig.PreferredRoutes` (#1827) carries the ip-monitoring
effective-route overlay; the daemon's `assembleFRRConfig` is the sole
`FullConfig` constructor for both the full apply path and the
routes-only actuator, so an operator commit can never wipe an active
failover route. The `ApplyFull` emission-order contract comment lists
the overlay as step 7.

## Dependencies

`pkg/config` only.

## Managed-section markers

`! BEGIN BPFRX MANAGED CONFIG` … `! END BPFRX MANAGED CONFIG`. User-edited
content **outside** the markers is preserved across `ApplyFull`. Don't
move or rename the markers — they're literal strings.

`writeManagedSection` strips the old managed block before re-appending the
new one. Two corruption hazards are handled defensively because the file
also carries operator content:

- **Orphaned begin / missing end (#1646).** A torn write can leave a begin
  marker with no end. The strip discards the begin-to-EOF tail rather than
  appending a second block (which a later write would over-cut).
- **Stale end before begin (#2908).** The end-marker search is anchored
  strictly *after* the begin marker. An unanchored `strings.Index(content,
  markerEnd)` from index 0 would match a stale/orphaned end marker that
  appears *before* the live begin marker (operator hand-edit, interleaved
  partial copy, external tooling), returning `end < start`; the strip
  `content[:start] + content[end:]` would then DUPLICATE the text between
  the stale end and the begin while leaving the live begin in place —
  two begin markers and a corrupt block that FRR reload rejects. Anchoring
  keeps `end >= start`, so the slice can never duplicate.

## The sequence bound and the renderer share ONE expansion (#7526)

`config.MaxRouteMapSequences` is admission's ceiling on how many route-map
sequences a policy may expand to; rendering past FRR's maximum sequence number
"poisons the ENTIRE frr-reload", which is why the bound exists at all.

**The bound and the renderer disagreed on the cardinality.** `fromPrefixListRefs`
expands one referenced prefix-list NAME into one match line **per family it
holds** — a mixed v4+v6 list yields an `ip` ref and an `ipv6` ref so both
families bind a family-correct match (#2607). `RouteMapSequenceCount` counted
`len(term.PrefixList)` — names, family-blind. So a policy referencing
mixed-family lists rendered up to **twice** the sequences admission approved,
and a config sitting just under the ceiling rendered past it.

The fix is not to teach the bound the renderer's rule; it is to have one rule.
`config.PrefixListFamilies` decides WHICH families a list holds and is read by
both. `prefixListFamilies` here keeps only the mapping to FRR's `ip`/`ipv6`
match keywords, which are FRR spellings; the counts are now equal **by
construction** rather than by two implementations agreeing.

`RouteMapSequenceCount` and `ComposedChainSequenceCount` therefore take the
`*PolicyOptionsConfig`. It is **required, not optional**, so the compiler
enumerates every call site — an optional table would be nil exactly where it
matters and the count would silently fall back to the family-blind answer.

Three things the mutation matrix established that inspection did not:

- The nil/empty-list fallback to IPv4 was **duplicated** here, and the duplicate
  made the config-side normalization dead — removing it changed no behaviour
  because this fallback silently covered for it. Two places deciding the same
  thing is the disease, so the duplicate is gone.
- A term with **no** `from-prefix-list` must count 1, not 0. Zero multiplies the
  whole term's cross-product to zero, so the bound would report that a large
  policy expands to nothing and admit anything. That is the most common term
  shape and it was uncovered.
- An **undefined or empty** referenced list counts as ONE family: the renderer
  still emits one fail-closed NOMATCH match line for it.

The saturation contract is unchanged and was verified rather than adjusted:
`checkedMulU64` and the running-sum guard clamp to `math.MaxUint64`, and
admission rejects strictly `> MaxRouteMapSequences` — saturating at the ceiling
instead would make an over-limit count equal the accepted maximum.

The regression test asserts the **agreement**, not a literal: it renders the
policy, counts the emitted sequence lines, and compares that to what the bound
predicts. Pinning a number I computed would encode which of the two I decided to
trust, and this issue is precisely a case where one of them was wrong.

## An undefined route-map name DENIES (#6807) — the repo said the opposite

**FRR does not permit-all on a dangling route-map reference. It denies.**
This page, eight production comments and three tests all asserted the
opposite for years; every one of those claims is corrected in place and
this section is the reference.

FRR `stable/10.6` `bgpd/bgp_route.c` — the deployed line
(`vtysh -c 'show version'` on the test cluster reports FRRouting 10.6.0):

```c
bgp_input_modifier:   rmap = route_map_lookup_by_name(rmap_name);
                      if (!rmap) return RMAP_DENY;

bgp_output_modifier:  if (!rmap_name) return RMAP_PERMIT;
                      rmap = route_map_lookup_by_name(rmap_name);
                      if (rmap == NULL) return RMAP_DENY;
```

Read the two arms carefully, because the distinction is the whole point:

| state | FRR result |
|---|---|
| **no** `route-map` attached to the neighbor/AF | **permit** (`RMAP_PERMIT`) |
| attachment **names** a map that does not exist | **deny** (`RMAP_DENY`) |

So the failure directions are the reverse of the intuition the old comments
encoded:

- **Omitting the ATTACHMENT** = no policy = permit-all = fail **open**.
- **Omitting the DEFINITION** while keeping the attachment = deny-all =
  fail **closed**, but as a silent, total withdrawal.

### What #6807 fixed

`generatePolicyOptions` (#5701) and `renderComposedRouteMap` (#5732) skip a
policy whose Cartesian expansion would exceed FRR's route-map sequence
ceiling, because a `route-map <name> permit 70000` line makes FRR reject the
command and **poisons the whole vtysh-batched `frr-reload`** — not just that
policy. That skip is correct and is unchanged.

What was wrong is that the skip emitted **nothing**, while BGP rendering
emits the attachment independently off the policy's presence in
`PolicyStatements`. The result was a live `neighbor <ip> route-map <name>
in|out` naming a map FRR could not resolve → **every route on those
neighbors withdrawn**, with one `slog.Warn` as the only signal, on a path
(`tolerant load / peer-sync / rollback`, #1960) that exists precisely so a
node can come up.

Both sites now emit a **bounded explicit deny** under the referenced name:

```
route-map <name> deny 10
exit
```

One sequence, so it can never approach the ceiling the skip exists to respect.
The redistribute alias (`<name>-xpf-redist`) is quarantined under the same
rule when `policyNeedsRedistAlias` holds, because `resolveRedistribute`
references whichever of the two names applies.

### Why deny and not "drop the attachment too"

Dropping the attachment is the only other option that renders, and it means
**no policy at all** — Junos BGP default-accept, advertising or accepting
every route the operator's policy existed to filter. That is fail-open on an
authorization decision, the direction this project does not take (cf. #3333
lo0/host-inbound, #3392, #6790). Failing the render outright is not available
either: this path serves the tolerant/peer-sync/rollback config that must not
brick (#1960).

So the OUTCOME is unchanged (deny). Three things change:

1. it is **deliberate** rather than an accident of FRR's undefined-map
   behaviour;
2. it is **visible** — `show route-map <name>` shows an explicit deny instead
   of nothing, which is the difference between diagnosing a total route
   withdrawal in minutes and in hours;
3. it is **stable** — a later change that "cleans up the dangling reference"
   can no longer silently convert the deny into a permit.

### The withdrawal is alertable, not just logged

A quarantined policy is still an **outage** — every route on a neighbor
carrying one of its attachments is withdrawn until the policy is reduced.
Before #6807 the only signal was one `slog.Warn` at render time, which
nothing alerts on: a total route withdrawal looked exactly like a healthy
box to every dashboard.

`Manager.QuarantinedRouteMaps()` returns the sorted names the LAST rendered
managed section quarantined, and `xpf_frr_route_maps_quarantined` publishes
its length. **Alert on `> 0`.**

Two properties the metric depends on, both bound by tests:

- The set is **rebuilt from scratch on every `buildManagedSection`**, so an
  operator who reduces the policy and re-commits stops being paged — an
  alert that keeps firing after the fix gets muted, and a muted alert is
  how the next real one is missed.
- The gauge publishes an explicit **0** on a healthy box rather than going
  absent, because `xpf_frr_route_maps_quarantined > 0` cannot tell "nothing
  quarantined" from "this series stopped being reported". It is published
  only when the FRR hook is actually wired, so a daemon that never consulted
  FRR reports nothing rather than a confident zero.

One oversized policy can quarantine **two** names — itself and its
`-xpf-redist` alias — so the gauge is a count, not a boolean.

### The undefined-policy asymmetry (#7625) — emptied half resolved

The `#2473`/`#2490`/`#2539` guards drop a reference to an **undefined**
(never-authored) policy. Under the corrected semantics that drop *produces*
permit-all — the leak those guards were written to prevent. #7625 splits that
into two shapes, because they are not the same defect:

| authored chain | after the drop | before #7625 | now |
|---|---|---|---|
| `[GHOST]` | `[]` | no attachment → **permit-all** | bounded deny |
| `[REAL, GHOST]` | `[REAL]` | attachment to `REAL` | unchanged |

**Emptied → bounded deny.** Every member unresolvable meant no `route-map`
line at all, and an *absent* attachment is the one shape FRR permits. So the
direction the operator filtered hardest ended up unfiltered — a hole, not a
degradation. The attachment sites now resolve through `bgpNeighborImportRef` /
`bgpNeighborExportRef` (`policy_chain_emptied_deny_7625.go`), which reference a
reserved `xpf-emptied-chain-xpf-chain` deny. Reference and definition are
emitted together, so #6807's "every referenced name is defined in this section"
property holds **by construction** rather than by the reference being dropped.
The name is quarantine-counted, so it shows up in
`xpf_frr_route_maps_quarantined` like the oversized cases.

**The direction asymmetry is real.** A bare protocol token (`static`, `direct`)
in an `export` list means `redistribute <proto>` on a separate path, so such a
list also filters to empty — but attaching a deny there would withdraw every
route to the peer, a worse outage than the bug. On **import** there is no
redistribute construct, so the same token is just a name that resolves to
nothing and must deny. The exclusion is therefore export-only.

**Narrowed → unchanged, but no longer silent (#8363).** A chain that keeps some
members still renders the surviving subset, byte-identically. The measurement
that gated this (`policy_chain_narrowed_eval_8363_test.go`) refuted the stated
objection and found a different one:

- An **accepting member terminates** evaluation — xpf emits `on-match next` only
  for non-terminating terms, so a `then accept` term is a bare `permit` and FRR
  stops there. A route the surviving member accepts never reaches a later deny.
  The feared "works-but-narrowed goes deny-all" does not happen that way.
- **Position does.** A synthesized deny is a chain member with a terminating
  *default* action, and `renderComposedRouteMap` breaks on the first such member,
  so every later member is never emitted. `[GHOST, REAL]` renders as a lone
  `deny 10` — deny-all, invisible in the output because nothing is left to look
  wrong.

So a synthesized deny is safe **iff the undefined members form a suffix** of the
authored chain. Ghost-last is safe; ghost-first or ghost-middle is a routing
outage. Rather than take that behaviour change on a working config, the narrowing
is made **visible** — and operationally, not at commit time, because the affected
population never commits: strict rejects an undefined reference in both
directions, so these configs arrive via `Store.Load` / `SyncApply` on a reboot,
peer sync or rollback. A commit-time warning would reach nobody in it.

`warnNarrowedChains` logs each site with what was authored, what is applied, and
what was discarded, and two gauges carry it:

| gauge | meaning |
|---|---|
| `xpf_frr_policy_chains_narrowed` | attachments filtered by less than authored. Alert on > 0. |
| `xpf_frr_policy_chains_narrowed_deny_safe` | the subset whose ghosts form a suffix — where a deny *would* be safe |

They are deliberately **separate** from `xpf_frr_route_maps_quarantined`, whose
documented meaning is that every route on those neighbors is being *withdrawn*.
A narrowed chain withdraws nothing, so folding it in would fire that alert for
non-withdrawals. Both sets are rebuilt per render, so a config that stops
narrowing stops reporting. The `deny_safe` split exists so the decision on
whether to ever synthesize a deny here is sized on how often the safe shape
actually occurs, rather than on argument — which is what this measurement just
had to overturn. Before this it was completely silent —
the rendered section is self-consistent, the session works, and `show route-map`
displays a real well-formed policy that is simply not the one the operator
wrote.

**Reachability.** Strict commit rejects an undefined policy reference in either
direction (`config.TestBGPNeighborImportTypoRejected`), so no commit-time
surface was added: these configs reach the renderer only on the lenient load /
HA peer-sync / rollback path (#1960), having committed on an older binary or
arrived from a peer. Two render-side collision guards fail the apply **closed**, because
FRR merges same-named route-maps and a merge would fuse permits into the deny
(reopening the hole) while corrupting the other object's filter in the same
step. Both are required — neither sees the other's case:

- `emptiedChainDenyCollision` — an operator policy-statement **named** the
  reserved name.
- `bgpComposedChainCollision` — a composed chain that **derives** it. The
  reserved suffix does *not* make the name unforgeable, which an earlier version
  of this section wrongly implied: strict rejects a policy-statement whose name
  *ends* in `-xpf-chain`, but nothing stops several legally named policies from
  joining into it — `composedChainName(["xpf","emptied","chain"])` is
  byte-identical to `xpf-emptied-chain-xpf-chain`.

## Gotchas

- Static routes have RETH names (`reth0`) but FRR wants the physical
  member name in cluster mode. The package translates via `RethMap` from
  the typed config.
- `InstanceConfig` has two rendering modes (#1827 PR-2):
  `VRFName != ""` renders `vrf <name>` (virtual-router instances);
  `VRFName == ""` with `TableID > 0` renders `table <id>`
  (`instance-type forwarding` instances — no VRF device exists, and the
  table must match the FBF/PBR `ip rule` target and the dataplane's
  `<ri>.inet.0`). `renderPreferredRoutes` resolves an overlay entry's
  instance via `InstanceConfig.Name`; legacy callers that never set
  `Name` keep the historical `vrf-<name>` rendering.
- IPv6 next-hops without an explicit interface require `IPv6NextHopInterfaces`
  for link-local resolution — link-local addresses alone are ambiguous to
  FRR. The map is built by `inferIPv6StaticNextHopInterfaces`
  (`pkg/daemon/daemon_run.go`); `generateStaticRoute` uses an explicit
  `NextHopEntry.Interface` first and falls back to this map only for an
  unqualified next-hop. It also resolves the **ip-monitoring overlay's**
  literal next-hops (`RouteOverlayEntry.NextHop`, passed as the second
  argument, #3759) so a link-local preferred-route next-hop renders with
  the same interface scope as a static route — `renderPreferredRoutes`
  looks the scope up under the same VRF key the render uses (`""` for
  master + `instance-type forwarding`, `vrf-<name>` otherwise).
- **Link-local (`fe80::/64`) static next-hops (#2452).** A link-local
  next-hop is interface-scoped and FRR rejects `ipv6 route <dst> fe80::x`
  without a trailing `<iface>`. Link-local addresses are never declared
  under `unit.Addresses` (the kernel auto-assigns them), so
  `inferIPv6StaticNextHopInterfaces` adds a synthetic `fe80::/64` candidate
  per IPv6-capable logical interface. Disambiguation rule for an
  **unqualified** link-local next-hop: (1) if the operator wrote
  `qualified-next-hop fe80::x interface <if>` / `next-hop fe80::x interface
  <if>` the explicit interface is used directly and inference is skipped;
  (2) otherwise it resolves only when exactly ONE IPv6-capable interface is
  in scope (the single defensible answer); (3) with multiple IPv6
  interfaces and no qualifier the next-hop is genuinely ambiguous — the
  inference refuses to guess (leaves it unresolved) rather than route to the
  wrong link, and the operator must add an interface qualifier.
- **Static `next-hop [ a b ]` ECMP list (#3872).** A static route's
  `next-hop [ gw1 gw2 ]` is the canonical Junos ECMP spelling — multiple
  next-hops = equal-cost multipath. The schema `next-hop` leaf is `multi:
  true, valueList: true` (`schema_routing.go`) so the bracket list collapses
  onto one leaf in both AST shapes, and the compiler
  (`compileStaticRoutes`) reads EVERY gateway from `Keys[1:]` (plus separate
  `next-hop` statements). Each gateway becomes a `NextHopEntry`, and
  `generateStaticRouteInTable` emits one `ip route` line per next-hop → FRR
  installs equal-cost multipath. Before #3872 the leaf was a plain container
  and the compiler read a single address, so `next-hop [ a b ]` silently
  installed only the first gateway. A plain list carries NO per-next-hop
  preference (all equal-cost) — kept distinct from the floating
  `qualified-next-hop` backup below.
- **Floating static via `qualified-next-hop` (#3871).** A static route's
  `qualified-next-hop <gw> { preference N; metric M; }` is the Junos floating-
  static idiom — a primary next-hop plus a LESS-preferred backup that installs
  only when the primary is down. `generateStaticRouteInTable` renders each
  next-hop with its OWN admin distance: a next-hop carrying a per-next-hop
  preference (`NextHopEntry.HasPreference`, set by the compiler from the
  qualified-next-hop's `preference` child/inline key) uses that distance; a
  plain next-hop uses the route-level `StaticRoute.Preference` (default 5). So
  `next-hop 10.0.0.1` + `qualified-next-hop 10.0.0.2 preference 250` emits
  `ip route <dst> 10.0.0.1 5` and `ip route <dst> 10.0.0.2 250` — FRR installs
  the distance-5 primary and floats the distance-250 backup in only when the
  primary's next-hop is unresolvable. Before #3871 the qualified preference was
  folded into a single route-level `Preference`, so every next-hop rendered at
  equal cost and the floating static became equal-cost ECMP that load-balanced
  over the backup. A plain `next-hop [ a b ]` bracket LIST is equal-cost ECMP
  (#3872) — kept distinct: no per-next-hop preference. FRR's static-route CLI
  has no metric field, so `NextHopEntry.Metric` is carried in the typed config
  (parity/display) but not emitted — the floating behavior is entirely the
  per-next-hop distance. A metric-ONLY `qualified-next-hop <gw> { metric M; }`
  (no `preference`) therefore does NOT float: with `HasPreference == false` it
  renders at the route-level distance, equal-cost with the primary — a
  `preference` is REQUIRED to make a qualified-next-hop a floating backup.
- **Negative routes: `discard` vs `reject` (#5298).** A static route's
  terminal `discard` or `reject` action installs an ACTIVE no-next-hop route
  so matching traffic is dropped instead of following a less-specific route.
  The two differ in what the source sees: `discard` → FRR `Null0`
  (`RTN_BLACKHOLE`, a SILENT drop), `reject` → FRR `reject`
  (`RTN_UNREACHABLE`, drop + ICMP unreachable to the source). The compiler
  (`compileStaticRoutes`) sets `StaticRoute.Discard` / `StaticRoute.Reject`
  (mutually exclusive) from both the inline route-keys and hierarchical/
  flat-set action switches, and `generateStaticRouteInTable` emits the single
  line `ip|ipv6 route <dst> (Null0|reject) [<pref>] [vrf/table]` for either
  BEFORE the empty-next-hops guard. Before #5298 the compiler handled only
  `discard`; a committed `reject` (accepted by the schema leaf) was silently
  dropped end-to-end — no disposition, no next-hop — and the renderer then
  emitted NOTHING for the resulting no-next-hop route, so the reject prefix
  fell through to the default (a fail-wide). The userspace AF_XDP FIB folds
  `Reject` into its silent-drop disposition (`buildRouteSnapshots`, #5298) so
  the fast path drops the prefix too rather than LPM-matching a less-specific
  route; a userspace-generated ICMP unreachable (vs the kernel/FRR reject
  route's ICMP) is a follow-up. A no-next-hop route WITHOUT `discard`/`reject`
  still renders nothing (#3872), not a blackhole.
- **VRRP-VIP-only subnets (#2452 secondary).** A bondless-RETH member that
  carries only a VRRP virtual address (no matching `unit.Addresses` entry)
  also contributes its VIP subnet as a connected prefix, so a static
  next-hop inside the VIP subnet resolves to that member interface. The VIP
  is read from `VRRPGroup.VirtualAddresses` (the `unit.VRRPGroups` map
  VALUE, a CIDR string — the same field `pkg/vrrp` feeds to
  `netlink.ParseAddr`); the map KEY is `"<CIDR>_grp<id>"`
  (`compiler_interfaces.go`) and is deliberately NOT parsed as an address.
- In cluster mode the package emits a blackhole default at admin distance
  250 so traffic to the active fabric peer survives a brief
  active/active overlap.
- **A DHCP route's `vrf` clause names the KERNEL namespace, not the Junos
  one (#9136).** `DHCPRoute.VRF` carries the BARE routing-instance name —
  the suppression maps in `renderDHCPDefaults` key on it and are internally
  consistent that way — but FRR knows `vrf-<name>`, the device
  `pkg/routing/vrf.go` creates, and an `instance-type forwarding` instance
  has no VRF device at all. `renderDHCPDefaults` previously interpolated the
  bare name, so a tenant's DHCP-learned default named a VRF that does not
  exist and a forwarding instance was given a `vrf` clause it can never
  have. Both are now resolved through **`instanceRouteTarget`**, extracted
  from `renderPreferredRoutes` so the two renderers cannot disagree:
  `vrf <InstanceConfig.VRFName>` for a virtual-router, `table <TableID>` for
  a forwarding instance, no clause when the instance carries neither (the
  master table), and the historical `vrf-<name>` on a lookup miss. The
  #5557/#8963 control-character belt still applies, now to the resolver's
  output; the `table` arm needs none, `TableID` being an int.
  Coupled to #9135: before that fix `DHCPRoute.VRF` was non-empty only for
  a dash-authored config, so this clause was rarely exercised.
- **DHCP default routes bind the originating interface for BOTH families
  (#2547).** `renderDHCPDefaults` (admin distance 200) emits `ip route
  0.0.0.0/0 <gw> <iface> 200` / `ipv6 route ::/0 <gw> <iface> 200` whenever
  the lease records an interface (`DHCPRoute.Interface != ""`, populated by
  `collectDHCPRoutes` in `pkg/daemon/daemon_flow.go` for v4 and v6 alike),
  falling back to the gateway-only form when it is empty. The IPv4 branch
  previously dropped the interface — an unintended asymmetry that left the
  kernel unable to pick the correct egress in multi-WAN / shared-gateway-IP
  deployments (default-route conflicts / blackholing).
- **Export references are validated at commit (#2144).** A dynamic-protocol
  `export` (OSPF/OSPFv3/BGP/IS-IS), a RIP `redistribute`, a BGP
  group/neighbor `export`, and a `routing-options forwarding-table export`
  are checked against the defined policy-statement set (and, for the
  redistribute-backed exports — OSPF/OSPFv3/RIP/IS-IS, plus a global
  `protocols bgp export` whose token is a bare protocol; a global BGP
  export that names a policy-statement renders as peer-level `route-map
  out` instead, see #2473 below — the known protocol tokens
  `connected`/`direct`/`static`/`kernel`/`ospf`/`bgp`/`rip`/`isis`) by
  `validateRoutingExportReferencesStrict` in `pkg/config/compiler.go`.
  Strict on commit/commit-check; lenient (warn) on load/HA-sync (#1960).
  This closes the render-side fail-open paths that previously turned a typo
  into broken or silent config: a BGP group/neighbor export renders
  `route-map <name> out`, where a missing route-map is unresolvable
  (see the #6807 correction below — FRR **denies**, withdrawing the peer's
  routes; this text previously said permit-all); and `resolveECMP` returns 0 max-paths
  for a missing forwarding-table policy (silently disables
  ECMP/consistent-hash). Those render fallbacks remain as
  belt-and-suspenders for a config that reaches the renderer via the
  lenient path (an older-binary persisted config or a peer-synced one). The
  bare-protocol render path also normalizes the Junos `direct` token to the
  FRR `redistribute connected` keyword (`export direct` previously rendered
  the FRR-invalid `redistribute direct`, failing the reload) — matching the
  policy-term `FromProtocols` normalization and keeping the commit gate's
  acceptance of `direct` honest.
- **BGP local-AS resolves from `routing-options autonomous-system` (#3870).**
  `generateProtocols` gates the `router bgp <N>` block on `BGPConfig.LocalAS
  > 0`, and ONLY `protocols bgp local-as` populated `LocalAS`. A canonical
  vSRX config that declares the AS at the global `routing-options
  autonomous-system <N>` (the standard Junos placement) — with `protocols
  bgp` but no `local-as` — therefore rendered NO `router bgp` block at all,
  silently, and BGP never came up. `resolveBGPAutonomousSystem`
  (`compiler_routing.go`), run once after the whole tree compiles (so
  `routing-options` and `protocols` may appear in either order), fills
  `LocalAS` from the global `autonomous-system` when `local-as` was omitted;
  `local-as` still WINS when present (Junos precedence). A per-routing-instance
  BGP without `local-as` inherits the instance's own `routing-options
  autonomous-system` if set, else the global one. No AS anywhere leaves
  `LocalAS == 0` and renders no `router bgp`, unchanged.
- **A BGP neighbor's peer-as (remote-as) is validated at commit (#2963).**
  `peer-as` is optional in the parser/compiler, so a neighbor authored
  without one (and without an inherited group `peer-as`) keeps a zero
  `BGPNeighbor.PeerAS`, and `generateProtocols` would emit `neighbor <addr>
  remote-as 0`. AS 0 is reserved (RFC 7607) and FRR/vtysh rejects
  `remote-as 0`, which fails the WHOLE `frr-reload` (a single `vtysh -f`
  add-batch exits non-zero on any `CMD_WARNING_CONFIG_FAILED`) and leaves
  dynamic routing broken/stale — a commit-accepted config the routing daemon
  cannot load. `validateBGPNeighborPeerASStrict` (`pkg/config`) hard-rejects
  a neighbor whose effective `PeerAS == 0` at commit/commit-check (both the
  global `protocols bgp` and per-routing-instance scopes), naming the
  offending group + neighbor; lenient (warn) on load/HA-sync (#1960). As
  defense-in-depth the renderer (`policy_render.go`, `generateProtocols`)
  SKIPS a neighbor with `PeerAS == 0` entirely, so AS 0 never reaches
  frr.conf for a config that arrives via the lenient path (an older-binary
  persisted config or a peer-synced one) — keeping the rest of the reload
  alive instead of bricking it for every other peer. **All three
  neighbor-referencing render loops agree on that exclusion (#5518).**
  `generateProtocols` computes a single `validNeighbors` slice (`PeerAS != 0`)
  ONCE and drives the `neighbor <addr> remote-as`/`update-source`/`timers`/…
  DECLARATION loop, the address-family ACTIVATION loop
  (`inet4Neighbors`/`inet6Neighbors` → `neighbor <addr> activate` +
  `route-map … in/out`), AND the BFD peer accumulator (`bfd { peer <addr> }`)
  from it. Before #5518 only the declaration loop carried the guard: a
  remote-as-0 neighbor was kept out of the declaration yet STILL emitted
  `activate` / route-map / `neighbor <addr> bfd` / a `bfd` peer — and vtysh
  rejects an `activate`/`bfd`/`peer` for a neighbor that was never declared,
  so a single lenient remote-as-0 neighbor bricked the managed `frr-reload`
  for every valid BGP peer. Unifying on `validNeighbors` makes the three loops
  structurally unable to diverge. **`validNeighbors` must NOT be given a
  first-wins dedup (#9192).** It is the obvious place to remove the duplicate
  `neighbor <ip> remote-as` line that one authored neighbor used to produce, and
  doing so silently drops the POLICY-BEARING entry — deleting the `activate` and
  `route-map … in` lines with it, on a config that still commits and a peer that
  still comes up with the operator's route filter absent. That fix was written
  and reverted for exactly this reason. The duplication was a COMPILER
  representation defect — `compileBGP` appended one `*BGPNeighbor` per AST node,
  and a bare `neighbor <ip>` declaration plus a later `neighbor <ip> <leaf>` are
  two nodes — and it is fixed there, by find-or-create on (GroupName, Address).
  `TestBGPNeighborMergeRendersOneDeclaration9192` asserts BOTH halves at this
  layer: exactly one declaration line, and the `activate` / route-map lines
  still present. (The route-map DEFINITION collectors
  `collectBGPRouteMapPolicies`/`bgpEffectiveChains` still iterate all
  neighbors — they emit no `neighbor <addr>` line, only route-map objects, so
  an unreferenced definition for a skipped neighbor is harmless valid config.)
- **OSPF/OSPFv3 interface adjacency timers + DR priority (#4285).** The
  per-interface `hello-interval`, `dead-interval`, `retransmit-interval`, and
  `priority` leaves (schema + `OSPFInterface`/`OSPFv3Interface` structs +
  `compiler_protocols.go`) render under the interface stanza as
  `ip ospf hello-interval/dead-interval/retransmit-interval/priority` (v4) and
  `ipv6 ospf6 hello-interval/dead-interval/retransmit-interval/priority` (v6).
  hello/dead MUST match a neighbor or the adjacency never forms (stuck in
  Init/ExStart) — a fast-timer neighbor (hello 1s) never adjacencies with FRR's
  silent default 10s/40s. Priority uses a `HasPriority` presence flag (mirroring
  `HasMetric`/`HasLocalPreference`): priority **0** is a valid value ("never
  DR"), so a bare-int gate can't tell it from unset — the renderer emits the
  line IFF `HasPriority`, so an interface with no `priority` leaf keeps FRR's
  default and never emits a stray `ip ospf priority 0`. The four leaves carry
  commit-time range validators (`schema_routing.go`): hello/dead/retransmit
  `ValidateInteger(1, 65535)` (0 is invalid for these), priority
  `ValidateInteger(0, 255)` — FRR's ranges. An out-of-range value would
  otherwise commit and render a stanza FRR REJECTS, and a rejected line fails
  the WHOLE `frr-reload` (one bad leaf = a routing outage). All FOUR schema
  copies — top-level `protocols {ospf,ospf3}` AND the `routing-instances`
  mirrors — carry the leaves + validators (the compiler already handled both
  scopes via the shared `compileProtocols`).
- **BGP update-source / passive / hold-time / local-as (#4286).** The group-level
  (and per-neighbor override) `local-address`, `passive`, `hold-time`, and
  `local-as` leaves flatten onto each `BGPNeighbor` and render as
  `neighbor <peer> update-source <local-address>`, `neighbor <peer> passive`,
  `neighbor <peer> timers <keepalive> <hold-time>` (keepalive = hold/3, floor
  1), and `neighbor <peer> local-as <asn>`. `update-source` is load-bearing for
  iBGP loopback peering: without it the BGP TCP session sources from the egress
  interface IP, not the loopback the peer has a `neighbor` statement for, so the
  peer rejects the connection and the session never establishes. `local-as`
  carries a commit-time `ValidateInteger(1, 4294967295)` (a valid ASN; AS 0 is
  reserved, RFC 7607). `hold-time` uses `ValidateBGPHoldTime` — 0 **or** 3..65535
  only: FRR requires the hold-time to be 0 or >= 3 (keepalive = hold/3), so a
  hold-time of 1 or 2 renders `timers 1 1|2` which FRR REJECTS and fails the
  whole reload; the validator rejects 1/2 at commit while still accepting 0
  (hold-timer disabled, treated as unset by the renderer's `> 0` gate). NOTE:
  FRR's `neighbor X local-as` is an eBGP-oriented knob and may be rejected on an
  iBGP-shaped peer (peer-as == router AS); the classic eBGP local-as use is the
  supported case.
- **An OSPF/OSPFv3/BGP router-id is validated at commit (#2980).** `router-id`
  is parsed as a raw string with no validation, so a malformed value (not a
  32-bit IPv4 dotted-quad — e.g. garbage, an out-of-range octet, or an IPv6
  address) flowed verbatim into `frr.conf`. FRR/vtysh requires a 32-bit IPv4
  router-id for ALL routing protocols — including the IPv6 protocols OSPFv3
  (`ospf6 router-id`) and BGP (`bgp router-id`) — and rejects anything else,
  failing the WHOLE `frr-reload` and leaving dynamic routing broken/stale — a
  commit-accepted config the routing daemon cannot load.
  `validateRouterIDStrict` (`pkg/config`) hard-rejects a non-IPv4 router-id at
  commit/commit-check (both the global `protocols {}` and per-routing-instance
  scopes, covering OSPF/OSPFv3/BGP), naming the scope and protocol; lenient
  (warn) on load/HA-sync (#1960). The check is `net.ParseIP` + `To4() != nil`
  (a router-id is the dotted-quad form even for v6 protocols); an empty
  router-id is allowed and omitted so FRR auto-derives one. As
  defense-in-depth the renderer (`policy_render.go`, `validRouterID` guard at
  each of the three `generateProtocols` render sites) SKIPS an invalid
  router-id, so a malformed value never reaches frr.conf for a config that
  arrives via the lenient path — keeping the rest of the reload alive.
- **A global `protocols bgp export <token>` is split by token shape
  (#2473).** The render classifies each entry by the SAME
  policy-statement-exists predicate the commit-time validator uses
  (`checkRedist`/`checkPolicyRef`, `pkg/config`), via
  `isDefinedPolicyStatement`:
  - **A DEFINED policy-statement name** is a Junos DEFAULT export policy
    applied to every peer (a group/global default), NOT redistribution.
    The old render routed ALL of `bgp.Export` through
    `resolveRedistribute`, which for such a policy produced `redistribute
    ospf route-map ...` under `router bgp` — actively ANNOUNCING the
    OSPF/connected RIB into BGP (route leak: internal subnets advertised
    to external peers, failure mode 1) — and for a prefix/community-only
    policy with no `from protocol` returned `""`, SILENTLY DROPPING the
    operator's advertise filter (failure mode 2). `generateProtocols` now
    applies a policy-statement export as a peer-level `neighbor <X>
    route-map <name> out` per neighbor/address-family (`bgpNeighborExportChain`
    + `bgpRouteMapRef`; a single-policy chain references that same route-map
    `generatePolicyOptions` already emits, a multi-policy chain references a
    composed route-map, #5277). Neighbors with no explicit
    `family` are routed into the ipv4-unicast block when such a global
    export is set (FRR default-activates them there) so the default
    reaches every peer.
  - **A BARE PROTOCOL TOKEN** (`connected`/`direct`/`static`/`kernel`/
    `ospf`/`bgp`/`rip`/`isis` — NOT a defined policy-statement) is this
    firewall's redistribution shorthand and KEEPS rendering as
    `redistribute <proto>` via `resolveRedistribute`. A bare token has no
    route-map to reference; rendering it as `neighbor X route-map
    connected out` would point at a non-existent route-map (#6807: FRR
    **denies** an unresolvable name — this text previously said
    PERMIT-ALL/leak; the split is still correct, the consequence was not). The
    split keeps the bare-token redistribute correct while the
    policy-statement path filters advertisements.

  **Coexistence (Junos most-specific-wins)** applies ONLY among the
  policy-statement-name route-map-out exports: a neighbor's OWN `export`
  OVERRIDES the global default for that neighbor (the group-vs-neighbor
  LEVEL precedence is resolved in the compiler — a neighbor's own export
  REPLACES the inherited group list, #5277). FRR accepts a single
  `route-map out` per neighbor/AF, so exactly one is emitted — the
  neighbor's own effective chain when present (a single-policy chain
  references the standalone route-map, a multi-policy chain the composed
  one, #5277), else the global default chain; the two never compete on one
  peer. A bare-token redistribute is a GLOBAL
  redistribute verb, not per-neighbor, emitted once under `router bgp`.
  `resolveRedistribute` is still called on the BGP export path, but ONLY
  for bare tokens — never for a policy-statement name (that was the leak).
  Both `route-map out` emit sites (ipv4 + ipv6 AF) are guarded by
  `isDefinedPolicyStatement` (#2539, sibling of the #2490 inbound guard):
  `globalExport` is already restricted to defined policy-statements, but a
  per-neighbor `export` (parseable as of #2490) can carry a bare token or an
  undefined ref that slipped the strict validator on the lenient load/HA-sync
  path. The guard skips it instead of emitting a dangling `route-map out`
  (#6807: a dangling out-ref is FRR **deny**, not permit-all — so the skip is
  the fail-OPEN direction, not the fail-closed one it was described as.
  Behaviour unchanged; see the correction section below). Bare tokens never
  reach here as a defined name, so the bare-token→redistribute path is
  unchanged.
- **`protocols bgp ... import <policy>` renders inbound `route-map in`
  (#2490).** BGP neighbors/groups now carry an `Import []string` symmetric
  to `Export`. A global `protocols bgp import`, a group `import`, and a
  per-neighbor `import` are parsed (`compiler_protocols.go`) and rendered as
  `neighbor <X> route-map <name> in` per neighbor/address-family
  (`bgpNeighborImportChain` + `bgpRouteMapRef`, symmetric to the export path).
  Before #2490 the `import` clause parsed to NOTHING — inbound route
  filtering on a BGP peer was a silent no-op. **Coexistence (most-specific-
  wins):** a per-neighbor import overrides the group/global default import;
  FRR accepts exactly one `route-map in` per neighbor/AF, so the neighbor's
  own policy wins when present. **#2473-lesson guard (inbound direction):**
  unlike export, import has NO redistribute equivalent — inbound filtering is
  route-map-only — so an import ref MUST name a DEFINED policy-statement. An
  undefined/bare-token ref is REJECTED at commit (`checkPolicyRef` in
  `validateRoutingExportReferencesStrict`, strict) and SKIPPED on the lenient
  load/HA-sync path (the render guards with `isDefinedPolicyStatement` before
  emitting `route-map <name> in`). (#6807: rendering a dangling `route-map
  <token> in` would resolve to **RMAP_DENY** in FRR, not PERMIT-ALL as this
  previously said — it is the skip that accepts everything. Behaviour
  unchanged; see the correction section below.) The referenced route-map is the
  same block `generatePolicyOptions` already emits for the policy-statement.
- **Ordered import/export policy CHAINS are composed, not collapsed to the
  last (#5277).** A Junos import/export policy LIST `[ A B C ]` is a CHAIN:
  each policy is evaluated in order, the first terminal action (`accept`/
  `reject`) wins, and a policy that reaches its end with no terminal action
  falls through to the NEXT policy; the protocol default applies only if none
  matched. The pre-#5277 renderer resolved the effective policy with
  `lastNonEmpty` and emitted exactly ONE `route-map <name> in|out`, so
  `export [ BLOCK-PRIVATE ALLOW-CUSTOMER ]` rendered only `route-map
  ALLOW-CUSTOMER out` — the leading `BLOCK-PRIVATE` reject/attribute policy
  was SILENTLY DROPPED, so a route it would reject was advertised/accepted
  (leaks internal prefixes / imports prohibited routes) while control-plane
  health stayed green. **Two-step fix:**
  1. **Select the most-specific LEVEL (compiler).** Junos level precedence is
     resolved in `compiler_protocols.go`: a neighbor's OWN `export`/`import`
     REPLACES the inherited group list (it does NOT merge) — the first own
     entry drops the inherited group chain, then same-level entries
     accumulate. So `n.Export`/`n.Import` is a COHERENT same-level ordered
     chain, not a group+neighbor merge that the old `lastNonEmpty` picked the
     last of. A neighbor with no own policy still inherits the full group
     chain; a global `protocols bgp export`/`import` chain applies to
     neighbors with no own list.
  2. **Compose that level's chain (renderer).** `bgpNeighborExportChain` /
     `bgpNeighborImportChain` (and the global chains) return the ordered,
     DEFINED-policy-filtered list. `bgpRouteMapRef` maps it to the neighbor's
     `route-map` name: an empty chain emits nothing; a SINGLE-policy chain
     references the standalone per-policy route-map (byte-identical to the
     pre-#5277 render, no churn for the common case); a chain of >= 2
     references a COMPOSED route-map (`composedChainName` = the members joined
     + the reserved `-xpf-chain` suffix, `ReservedChainSuffix`) that
     `renderComposedRouteMap` emits. The composed route-map lays each policy's
     TERM sequences (via the shared `renderPolicyTermSequences`) in order with
     CONTINUOUS sequence numbering: a terminating term keeps `permit`/`deny`
     with no `on-match next` (first-terminal-wins), a non-terminating term
     keeps `on-match next` (fall-through, #2451). A policy with an EXPLICIT
     policy-level default (`then accept`/`then reject`) emits a match-all
     `permit`/`deny` that TERMINATES the chain (later policies are
     unreachable); a policy with no explicit default falls through to the next
     policy. If the route falls off the end of EVERY policy, the trailing
     Junos BGP default-ACCEPT `permit` is emitted (#2998 — a composed chain is
     only ever a BGP `route-map in`/`out`). Per-policy inline prefix-lists are
     namespaced `<composedName>-<policyName>-<termName>` so a term name reused
     across chained policies cannot fuse two prefix-lists. The composed
     route-map DEFINITIONS are emitted beside `generatePolicyOptions` in
     `buildManagedSection` (deduped + sorted; FRR resolves the neighbor
     reference regardless of definition order). **Collision guard:** FRR keys
     route-maps by NAME in one global namespace and merges same-named objects,
     so `bgpComposedChainCollision` (called by `ApplyFull`, mirroring
     `redistAliasCollision`) fails the whole apply CLOSED if a composed name
     collides with an operator policy-statement or two distinct chains derive
     the same name. **Commit-time reservation (#5442):** the `-xpf-chain`
     suffix (`config.ReservedChainSuffix`, which `frr.ReservedChainSuffix`
     re-exports so the two cannot drift) is ALSO reserved at commit /
     commit-check — `validatePolicyReservedChainNameStrict` (`pkg/config`,
     mirroring `validatePolicyReservedRedistNameStrict`) hard-rejects an
     operator policy-statement whose name ends in it (lenient-warn on
     load/HA-sync per #1960), so an operator name collision is rejected
     cleanly at commit instead of surfacing as a late whole-section apply
     failure; `bgpComposedChainCollision` remains the render-side
     defense-in-depth for the tolerant path. `collectBGPRouteMapPolicies`
     records only SINGLE-policy
     chains into `bgpAcceptDefault` (a composed chain carries its BGP-accept
     default INTERNALLY, so its members' standalone route-maps are not the
     referenced objects). RED-on-revert covered by `bgp_policy_chain_5277_test.go`
     (frr) + `bgp_policy_chain_level_5277_test.go` (config).
- **Auth secrets with whitespace are rejected at commit, not quoted
  (#2889).** A BGP neighbor TCP-MD5 password (`neighbor <addr> password
  <secret>`) and an OSPF/RIP/IS-IS authentication key
  (`ip ospf message-digest-key`/`authentication-key`,
  `ip rip authentication string`, `area-password`/`domain-password`,
  `isis password`) all render the secret directly into a frr.conf line via
  `sanitizeFRRValue`. FRR's command lexer (`lib/command_lex.l`) tokenizes a
  vtysh/frr.conf line purely on whitespace and has **no quoted-string rule
  and no rest-of-line (`LINE`) token** — a double-quoted value is NOT
  grouped, the quotes are taken literally. So a secret containing a space or
  tab is split into multiple arguments at config load: the secret is
  truncated at the first space, or the trailing words become spurious vtysh
  arguments (malformed-line / injection risk). Quoting cannot fix this, so
  the contract is to **reject** such a value at commit — `validateFRRAuthValuesStrict`
  (`pkg/config/compiler_validate_strict.go`) hard-fails commit / commit-check
  naming the field (strict), and downgrades to a `cfg.Warnings` entry on the
  lenient load / HA-sync path (`opts.lenientFRRAuthValues`, #1960
  fail-closed-on-load class). The render-side `sanitizeFRRValue` belt still
  collapses any embedded control chars to spaces so a leniently-loaded bad
  value stays single-line/inert. Only whitespace + the C0/DEL control set is
  rejected; other punctuation (`.`/`@`/`!`/`#`) is matched by the lexer's
  single-char catch-all rule and is safe. **Free-form `neighbor description`
  is NOT covered by this gate** (it is cosmetic, not a security secret, and
  historically multi-word); it remains control-char-sanitized only — a
  follow-up if FRR's `description` token ever needs the same treatment.
- **Community members and as-path regexes get the render-side sanitize belt
  (#4097).** `generatePolicyOptions` renders a `policy-options community
  <name> members <value>` member as `bgp community-list <kind> <name> permit
  <value>` and a `policy-options as-path <name> <regex>` as `bgp as-path
  access-list <name> permit <regex>`. Both were the last free-text frr.conf
  interpolations still emitting the value with a bare `%s`; they now pass
  through `sanitizeFRRValue` for parity with the auth/description fields —
  the third of the documented #1798 defense layers ("the render-side belt …
  at each free-text file interpolation"). The **newline-injection vector
  itself is already closed by the first two #1798 layers**, which cover these
  two values because they are ordinary AST node values: the strict commit path
  hard-rejects any control character (`validateNodesControlChars`,
  `pkg/config/freetext.go`) and the lenient load / HA-sync / rollback path
  scrubs it in place (`sanitizeNodesControlChars`) — so a `\n` the lexer
  materializes from a quoted escape never reaches the renderer on any current
  path (guarded by `pkg/config` `TestFRRPolicyValueControlCharsBlocked_4097`).
  The render belt is defense-in-depth for any future path that hands the
  renderer a typed value the AST walk never saw. Unlike an auth secret a
  **space is legitimate** here — FRR takes the community/as-path value as a
  rest-of-line token — so `sanitizeFRRValue` (which strips only the C0/DEL set
  and leaves `0x20`) is the right tool, and no whitespace-rejecting commit gate
  is added. (NOTE: a Junos→FRR as-path regex *syntax* translation is still
  absent — Junos regex operates on whole AS-number terms, FRR uses POSIX ERE
  over the space-separated AS string — tracked separately, not part of #4097.)
- **The render-side belt now covers the route-map `set` clauses and
  prefix-list entries too (#4482).** #4097 wrapped only the community-list /
  as-path-list DEFINITIONS; the route-map `set community` / `set community …
  additive` / `set comm-list … delete` / `set as-path prepend` clauses, the
  `match community` / `match as-path` names, and the `ip/ipv6 prefix-list …
  permit <prefix>` entries (both the top-level `policy-options prefix-list`
  and the inline route-filter lists) still emitted their value with a bare
  `%s` — a residual bypass on the TOLERANT-load path (peer-sync / rollback /
  lenient load, where the strict #1798 commit gate only warns, #1960). All of
  those slots now pass through `sanitizeFRRValue`, so ALL FRR-rendered
  free-text is sanitized regardless of load path. Like the #4097 values these
  take a rest-of-line token, so a legitimate space (a multi-AS `set as-path
  prepend`, a multi-word regex) survives while a `\n` collapses to a space and
  cannot inject a standalone frr.conf command. Guarded by
  `TestGeneratePolicyOptions_SetClauseAndPrefixListSanitized_4482` (fail on
  revert of any wrapped site).
- **Three route-map slots the #4482 sweep missed are now wrapped too
  (#4498).** The #4494 hostile review noted that `set ip/ipv6 next-hop
  <term.NextHop>`, `set origin <term.Origin>`, and `match source-protocol
  <proto>` still rendered their value with a bare `%s` on the tolerant-load
  path — a residual of the same class #4482 closed (next-hop is the most
  notable: an IP-typed slot, but a malformed leniently-loaded value could
  still inject). All three now pass through `sanitizeFRRValue` for parity with
  the rest of the route-map belt, so EVERY free-text route-map interpolation is
  sanitized regardless of load path. The #4482 guard test was extended to
  drive an injection payload through all ten #4482 slots PLUS these three, so a
  revert of any single wrapped site is caught (the previous guard exercised
  only 3 of the wrapped slots — an incomplete fail-on-revert). The inline
  route-filter prefix-list slot's sanitize sits BEHIND the #2105 `net.ParseCIDR`
  belt (a control-char prefix is skipped fail-closed before the sanitize call),
  so its coverage is asserted as the fail-closed property, not a payload
  collapse.
- **A BGP-neighbor SHOW command validates its IP before it reaches vtysh
  (#4588).** The #1798/#4097/#4482 belts above cover the config-RENDER path;
  the operational SHOW path is a separate surface. `GetBGPNeighborReceivedRoutes`
  / `GetBGPNeighborAdvertisedRoutes` / `GetBGPNeighborDetail` (`vtysh.go`)
  concatenate a neighbor IP straight into `vtysh -c "show bgp neighbor <ip> …"`.
  That IP arrives from the operator via `GetBGPStatus` (`pkg/grpcapi/server_routing.go`,
  `received-routes:<ip>` / `advertised-routes:<ip>` / `neighbor:<ip>` selectors)
  and `pkg/cli/cli_show_routing.go` — and unlike the config path it was never
  sanitized. The local gRPC listener (127.0.0.1:50051) is unauthenticated, so a
  malformed token (`1.1.1.1\nconfigure terminal…`) could reach the vtysh command
  line: `realExecutor.Vtysh` is `exec.CommandContext` (no OS shell, so shell
  metacharacters are inert) but `vtysh -c` historically splits its argument on
  NEWLINES, which would turn an embedded `\n` into a second raw FRR CLI command
  with no commit-audit trail. Each wrapper now rejects a non-parseable IP with
  `net.ParseIP(ip) == nil → error` (the load-bearing belt, closest to the exec);
  `GetBGPNeighborDetail` still allows an EMPTY ip (selects every neighbor).
  `GetBGPStatus` re-validates at the trust boundary and returns
  `codes.InvalidArgument` (defense-in-depth). `net.ParseIP` accepts IPv4 and
  IPv6 neighbors, so the happy path is unchanged. Guarded by
  `TestBGPNeighbor*RejectsUnvalidatedIP` / `TestBGPNeighborValidIPsPass`
  (`bgp_neighbor_ip_guard_4588_test.go`) and
  `TestGetBGPStatusRejectsUnvalidatedNeighborIP`
  (`pkg/grpcapi/server_bgp_status_ip_guard_4588_test.go`).
- **Group address-family flags are gated by neighbor address version
  (#2454).** When `compiler_protocols.go` copies a BGP group's `family inet`
  / `family inet6` flags down to each neighbor, it parses the neighbor's
  address (`net.ParseIP`) and inherits ONLY the matching family: an
  IPv4-addressed neighbor gets `FamilyInet` (never `FamilyInet6`), an
  IPv6-addressed neighbor gets `FamilyInet6` (never `FamilyInet`). Before
  this gate, a dual-stack group (`family inet` AND `family inet6`) marked
  BOTH flags on every neighbor regardless of its IP version, so the render's
  `inet4Neighbors`/`inet6Neighbors` partition put a bare IPv4 neighbor into
  the ipv6 set and emitted `neighbor <ipv4> activate` under
  `address-family ipv6 unicast`. Activating an IPv4 address for IPv6 unicast
  is invalid without RFC 5549 extended-nexthop (this config model has no
  such knob), and FRR rejects/ignores the activation — breaking the peer's
  AF setup. Edge cases: an address that is not a literal IP (a hostname or
  peer-group template) cannot be classified, so it preserves the prior
  behavior of inheriting BOTH group flags (no silent family drop, no crash);
  a per-neighbor explicit `family` clause is operator-authoritative and is
  applied as-is after the inherited flags. The gate does not over-restrict:
  an IPv4 neighbor in a v4-only or family-less group still establishes — FRR
  default `bgp default ipv4-unicast` auto-activates it, and an explicit
  `family inet` group still surfaces `FamilyInet`.
- **`resolveRedistribute` never emits an invalid `redistribute <name>`
  line (#2223).** FRR's `redistribute` requires a source-protocol token
  (`connected`/`static`/`ospf`/`bgp`/`rip`/`isis`/`kernel`); a bare
  policy-statement name or a typo is rejected by FRR's parser, and
  because the line lives in the xpf-managed section that ONE rejected line
  fails the WHOLE reload. `frr-reload.py` exits non-zero, and the additive
  `vtysh -f` fallback applies every other line but also exits non-zero on
  that one (FRR stable/10.6 `vtysh_config_from_file` continues past a
  rejected line and returns its error), so every retry fails the same way.
  Additions still reach FRR; REMOVALS do not. A later commit that deletes a
  route, neighbour or policy leaves it live in FRR for as long as the bad
  line is rendered. The commit-time strict validator accepts any DEFINED
  policy-statement for a redistribute-backed export; it does NOT require the
  policy to carry a `from protocol`. So a policy that matches only `from
  community` / `from prefix-list` / `from as-path` passes commit but yields
  zero `FromProtocols` at render time. In that case — and for any token that
  is neither a known protocol nor a defined policy-statement (a name slipped
  past validation on a lenient load/HA-sync path) — `resolveRedistribute`
  now SKIPS emission and logs a `slog.Warn` (returns `""`) rather than
  falling back to the FRR-invalid bare-name line. Redistribute has no
  construct to express "redistribute whatever this policy matches" without a
  source protocol, so skipping is the only correct outcome; the operator is
  warned to add a `from protocol <proto>` (or use a bare protocol token).
  This is the load-bearing invariant: a single unresolvable export can never
  poison the entire managed-section reload. `knownRedistProtocols` includes
  `ospf6` and `ripng` (the FRR keywords for OSPFv3 / RIPng redistribution) so
  a bare `export ospf6` / `export ripng` renders the valid line instead of
  falling through to skip-and-warn and silently dropping IPv6 IGP
  redistribution (#2943).
- **`resolveRedistribute` excludes the SELF protocol (#2943).** It takes a
  `self` argument naming the enclosing router protocol (`ospf` / `ospf6` /
  `bgp` / `rip` / `isis`; `""` for callers with no enclosing protocol such as
  unit tests). FRR rejects a protocol redistributing into itself
  (`redistribute ospf` under `router ospf`), and one rejected line fails
  the whole managed reload (#1880/#2223). Both render paths drop the self
  protocol: a bare self token returns `""` (skip+warn), and a policy-statement
  term whose `from protocol` names the self protocol is filtered out while its
  sibling non-self terms still render. Each `generateProtocols` call site
  passes its own protocol as `self`.
- **`resolveRedistribute` drops a source outside the enclosing router's
  address family (#9510).** FRR's `redistribute` grammar is per family.
  `lib/route_types.pl` builds each daemon's source list with
  `collect($daemon, ipv4, ipv6)`, so `ospf6`/`ripng` are not in ospfd's or
  ripd's list and `ospf`/`rip` are not in ospf6d's. Such a line is rejected
  at parse exactly like a typo. The commit gate cannot catch this, because a
  `from protocol` token is valid or not per USE SITE, not per policy: the
  same policy is valid under `router ospf6`. So both render paths filter at
  the use site through `redistSourceFitsNode` (`redistribute_afi_9510.go`),
  and a policy whose every `from protocol` was filtered says so in its warning
  instead of claiming it has none. **BGP is the easy row to get wrong.** bgpd
  is dual-stack, but a bare-token export is written directly under
  `router bgp` (BGP_NODE), where `bgp_vty.c` installs only the IPv4 grammar
  (`FRR_IP_REDIST_STR_BGPD`). `redistribute ospf6` is rejected there too;
  the IPv6 grammar exists only under `address-family ipv6 unicast`, and this
  renderer does not write redistribution there (#9667). IS-IS lists both
  families, so nothing is filtered under `router isis`, but the plain
  `redistribute <proto>` form is not IS-IS grammar at all (#9666).
- **A policied family-less IPv6 BGP neighbor activates under ipv6 unicast,
  not ipv4 (#2941).** The "default-activate a family-less policied neighbor
  under ipv4 unicast" fall-through (#2473/#2490) is correct ONLY for an IPv4
  peer address. An IPv6 peer (address contains `:`) with a global/per-neighbor
  policy but no explicit `family inet6` also satisfies `!FamilyInet6`, so the
  pre-#2941 code routed it into the ipv4 set and emitted `neighbor <v6>
  activate` under `address-family ipv4 unicast` — FRR cannot resolve an IPv4
  next-hop over an IPv6 session (no RFC 8950 extended-next-hop), so the
  session drops prefixes. The ipv4 fall-through is now gated on the peer
  address family, and a family-less-but-policied IPv6 peer is routed into the
  ipv6 set so it activates (with its `route-map out`/`in`) under ipv6 unicast.
- **IS-IS per-interface `isis bfd` is emitted INSIDE the interface block
  (#2942).** `isis bfd` / `isis bfd profile <name>` are interface-scoped
  commands; the IS-IS interface loop now writes them before the interface
  block's `exit\n!\n`, mirroring the OSPFv3 ordering. Emitting them after
  `exit` lands them in global config scope, which vtysh rejects and (one bad
  line) fails the whole managed-section reload (#1880/#2223).
- **Community-lists: `standard` vs `expanded` is per-DEFINITION (#2643).**
  An FRR `standard` community-list accepts ONLY literal community values
  (`ASN:VALUE`, or a well-known name such as `no-export` /
  `no-advertise` / `internet` / `local-AS`); it REJECTS any POSIX-regex /
  wildcard member (`65000:*`, `.*`, `65001:1..`) at config load, and a
  single rejected line fails the whole `frr-reload` of the managed
  section, leaving the routing daemon stale/unconfigured for the entire
  commit. An `expanded` community-list accepts a POSIX regex per member.
  `generatePolicyOptions` therefore inspects every member of a named
  community definition: a member containing any of
  `* . + ? ^ $ [ ] ( ) | \ { }` (`communityMemberIsRegex` —
  the braces cover POSIX-ERE interval bounds like `65000:1{2,3}`) is
  regex; a plain `digits:digits` or well-known name is literal. If ANY
  member is regex, the WHOLE definition renders as
  `bgp community-list expanded <name> …`; otherwise it stays
  `bgp community-list standard <name> …`. FRR forbids the same list NAME
  from being declared both standard and expanded, so a MIXED
  literal+regex definition CANNOT be split across the two kinds — it is
  rendered entirely as `expanded`. Members are written as-is (the
  wildcard `65000:*` becomes the FRR regex verbatim, matching Junos
  intent). NUANCE: FRR matches expanded community-list members
  UNANCHORED, so a literal value folded into an expanded list (the MIXED
  case) matches as a substring — `65000:100` would also match
  `65000:1000` / `165000:100`. This only affects MIXED definitions
  (uncommon); a literal-only definition stays `standard` (anchored exact
  match) and is unaffected. This is the same fail-closed-the-whole-reload
  class as the route-filter `ge`/`le` bounds above (#1880).
- **Policy community references are validated at commit (#2881).** A
  policy-statement term's `from community <name>` renders `match community
  <name>` and `then community delete <name>` (the strip-by-list operation
  added in #2848) renders `set comm-list <name> delete`. Both reference an
  FRR `bgp community-list <name>` that `generatePolicyOptions` emits ONLY
  for a defined `policy-options community <name>`. With no validation a term
  naming an UNDEFINED community committed cleanly, then a dangling `match
  community` / `set comm-list ... delete` line failed the WHOLE `frr-reload`
  of the managed section (a single `vtysh -f` add-batch exits non-zero on any
  `CMD_WARNING_CONFIG_FAILED`), leaving dynamic routing stale — a
  commit-accepted config the routing daemon cannot load.
  `validatePolicyCommunityReferencesStrict` (`pkg/config`) hard-rejects an
  undefined `from community` / `then community delete` reference at
  commit/commit-check, naming the policy, term, and missing community; lenient
  (warn) on load/HA-sync (#1960). Only NAME references are checked — `then
  community (set|add) <value>` carries a community VALUE (e.g. `65000:100`),
  not a list reference, and is not validated. Same fail-closed-the-whole-reload
  class as the community-list definition gate above.
- **`GetBGPSummary` parses JSON, not the text table (#3942).**
  `GetBGPSummary` runs `show bgp summary json` and decodes it via
  `parseBGPSummaryJSON` (`status_parse.go`), mirroring the `parseRouteJSON`
  pattern. The pre-#3942 code scraped the `show bgp summary` TEXT table with a
  `strings.Fields` field-count heuristic, which had two defects: (a) the footer
  line `Total number of neighbors N` has exactly 5 fields, so it passed the
  `len(fields) < 5` guard and became a PHANTOM peer (`Neighbor="Total"`,
  `AS="of"`); (b) the FRR text table overloads ONE `State/PfxRcd` column — for
  an Established peer that column holds the prefix count, not a state word — so
  the scraper stored the pfxRcd DIGIT in `State` and never populated `PfxRcd`
  at all. Every real peer therefore showed 0 prefixes and a bogus extra peer
  appeared. The JSON path keys peers by neighbor address under each AFI/SAFI
  object (`ipv4Unicast`/`ipv6Unicast`/…), with distinct `state`, `pfxRcd`,
  `remoteAs`, `msgRcvd`/`msgSent`, and `peerUptime` fields — no column overload,
  no footer to misparse. `BGPPeerSummary` gains an `AddressFamily` field so a
  neighbor activated in multiple families produces one disambiguated row per
  family (both `bgpAFILabel`-labelled and sorted for deterministic output). A
  non-JSON response (an older FRR `% BGP instance not found` banner, a wedged
  vtysh) or a peerless/empty summary yields no peers and NO error — "no BGP
  peers" is a valid state on the observability path, not a failure. The CLI /
  REST / gRPC `show bgp summary` renderers now surface the `AF` and `PfxRcd`
  columns.
- `vtysh -c` is run synchronously in batch mode for MOST state queries:
  `Vtysh` buffers the whole stdout into a string. The ONE streaming
  exception is `VtyshStream` (behind `StreamBGPRoutes`), added for the
  full-RIB BGP routes dump so a ~1M-route internet table is scanned
  incrementally rather than buffered whole and can be cancelled on client
  disconnect (#5056).
- All `vtysh` and `frr-reload.py` shell-outs route through the
  package-private `frrExecutor` interface. Tests inject a fake;
  production uses `realExecutor{}` (which `exec.Command`s the real
  binary). A zero-value `Manager{}` is tolerated via the `executor()`
  accessor — useful for same-package literals.
- Reload mechanism (#1880): the primary reload is a DIRECT bounded
  `/usr/lib/frr/frr-reload.py --reload <frr.conf>` — NEVER
  `systemctl reload frr`. On FRR 10.6 the unit's ExecReload
  (frrinit.sh reload) unconditionally restarts watchfrr, the
  Type=forking unit's MainPID, so every systemd-mediated reload cancels
  its own job, parks frr.service in `stop-sigterm` for 2 minutes, and
  ends with systemd SIGKILLing all FRR daemons. The direct invocation
  keeps the unit state untouched and restores stale-config REMOVAL on
  commit (the systemctl branch had been 100%-failing, so every reload
  silently ran the additive fallback).
- Each reload leg gets its OWN 15-second `context.WithTimeout`: the
  primary and, when it fails (any cause, including timeout), a FRESH
  context for the additive `vtysh -f` fallback. The real executor runs
  frr-reload.py in its own process group and SIGKILLs the group on
  cancel (`Setpgid` + `cmd.Cancel`), so no child `vtysh` writer can
  survive a timeout and race the fallback. Worst case on the apply
  path: ≤40s (2×15s + up to two 5s WaitDelay windows; an apply also
  waits at most one teardown window behind a pre-cancelled in-flight
  retry, ≤45s total).
- Degraded mode: fallback success returns `ErrFRRReloadDegraded`
  (wrapping the primary cause). A single-flight in-manager retry loop
  re-runs the primary at 15s/30s/60s then every 5min until a full diff
  converges (`frr.conf` on disk is the SSOT; a newer apply supersedes
  and a fully-successful reload cancels the episode). All reloads —
  applies AND the retry — serialize under `reloadMu`; `confGen` guards
  against a stale success clearing the state. The condition is exported
  via `Manager.ReloadDegraded()` → `xpf_frr_reload_degraded` (0/1
  gauge). `frr-pythontools` missing is classified explicitly
  (warn-once, slow-cadence retry). `Manager.Stop()` (wired into daemon
  shutdown) cancels in-flight process groups and reaps the retry
  goroutine; `DisableDegradedRetry()` is the one-shot (`xpfd cleanup`)
  configuration.
- Hard failure (#5109): when BOTH frr-reload.py AND the additive
  `vtysh -f` fallback fail, `reloadLocked` returns the underlying error
  (NOT the degraded sentinel) — nothing was applied, so live FRR keeps
  its previous config while `frr.conf` on disk already carries the new
  desired managed section. `noteReloadOutcomeLocked` treats this exactly
  like a degraded reload for RECOVERY: it sets the gauge and arms the
  same single-flight retry loop, which re-runs the primary reload against
  the on-disk SSOT until a full diff converges — so a hard failure
  self-heals without a restart. The error still propagates to the caller
  (the daemon's full-apply path logs it and continues, #5109; the
  ip-monitoring actuator uses it to avoid publishing a divergent snapshot,
  #3757). Before #5109 a hard failure from a non-degraded state hit no
  case in the outcome switch: the gauge stayed 0, no retry debt was armed,
  and live FRR kept the stale forwarding state until the next commit or a
  daemon restart while the operator's commit reported success.
