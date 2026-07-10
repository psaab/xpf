# Config schema: the two-SSOT split (#1319)

xpf has **two** command-tree sources of truth. Knowing which one to edit
is the single most common mistake when adding CLI completion or config
validation.

## Operational tree → `pkg/cmdtree`

`run` / `show` / `clear` / `request` / `monitor` / `ping` / `traceroute`
and friends are defined in `pkg/cmdtree/tree.go` (`OperationalTree`).
Adding an operational command there propagates to all three frontends
(local CLI, remote CLI, gRPC) for tab completion and `?` help. Operational
leaves may be typed (`Node.ValueType` / `ValueDesc` / `ValueExamples` /
`Validator`).

## Config-mode grammar → `pkg/config` `setSchema`

The `set` / `delete` / `show` / `edit` configuration grammar is owned by
`config.setSchema` (a tree of `schemaNode` rooted in `pkg/config/schema.go`),
NOT by cmdtree. Since the #1891 domain split, `schema.go` holds the
`schemaNode` type and the root composition; the per-domain subtrees live in
sibling aspect files in the same package (`schema_security.go`,
`schema_interfaces.go`, `schema_routing.go`, `schema_system.go`,
`schema_chassis.go`, `schema_cos.go` — see the file map in `schema.go`).
`setSchema` drives **four** things off one tree:

1. **Structural completion** — what keywords are valid at each position.
2. **Flat-set token grouping** — how `set a b c d` packs into AST
   `Node.Keys` (`SetPath`, `ast_edit.go`). This is parser-critical: the
   replace-vs-container decision keys on `children == nil`.
3. **Value-slot `?` completion** — for a typed leaf, the placeholder
   (`<rate>`) + example values (`CompleteSetPathWithValues`,
   `schema_complete.go`).
4. **Commit-check validation** — the typed-leaf gate
   (`SchemaValidate` + the generic walker in `schema_walk.go`). Strict
   ONLY on the operator-driven commit / commit-check path
   (`configstore.compileTree`); the tolerant `Store.Load` /
   `Store.SyncApply` ingress (`compileTreeLenient`) downgrades a
   violation to a `slog.Warn` so an already-persisted or peer-synced
   config carrying a value that was typed (or range-tightened) later
   cannot blackout-boot a node or alarm-loop HA config sync. Boot
   safety is non-negotiable: when you tighten a range, any legacy value
   the compiler accepted MUST still load (`TestLoad_ToleratesStored*`
   in `pkg/configstore`).

Because completion (3) and validation (4) read the SAME node, they cannot
drift — typing a leaf fixes both `set ... ?` help and `commit check`
rejection together.

## Strict commit-time validators → `pkg/config/compiler_validate_strict_*.go`

The typed per-leaf `SchemaValidate` walk (4) cannot express cross-field or
cross-stanza rules (e.g. "this `then policer` names a defined policer",
"this VIP falls inside the interface subnet"). Those rules live in the
strict `validate*Strict(cfg *Config) error` family, dispatched from the
typed-config phase of `compileExpanded` (`compiler.go`) — strict on the
operator commit / commit-check path, lenient (warn, #1960 no-brick) on the
tolerant load / peer-sync ingress. #4405 split the former ~7k-LOC
`compiler_validate_strict.go` monolith by domain into sibling files
(`compiler_validate_strict_{observability,cos,ipsec,routing,filter,application,policy,nat,zones,screen}.go`),
mirroring the #1891 `schema_*.go` layout; the residual
`compiler_validate_strict.go` keeps the system/dataplane group
(dataplane-type, managed-process names, SYN-cookie, DHCP static bindings,
VRRP virtual-address, flow aging, trailing tokens). It was a pure
code-motion split — every `(compiler_validate_strict.go)` locator
elsewhere in this document still names the correct, unchanged function, now
in whichever sibling file holds it (grep the function name to find it).

Each gate is a hand-wired `if err := validate<X>Strict(cfg); err != nil {
... }` line in `runUniformGates` (`compiler_uniformgates.go`) / `compiler.go`.
Adding a gate function without adding that invocation line leaves it DEAD —
it compiles, its own unit test may still pass if it calls the function
directly, yet the commit path never runs it and the misconfiguration it
guards silently ships. `TestEveryStrictCommitGateIsWired`
(`pkg/config/strict_gate_wiring_canary_test.go`, #4422) is the completeness
canary that closes that gap: it parses the package source (`go/ast`),
collects every top-level `func validate*Strict(cfg *Config) error`, and fails
if any is never invoked in a non-test file. It mirrors the metrics-side
`pkg/api` `TestCollectorDescriptorCoverage` idiom. So: define a new strict
gate AND wire it into `runUniformGates`, or the canary goes red naming it.

The live config-mode completers — `pkg/cli` `completeConfigWithDesc` and
`pkg/grpcapi` `completeConfigPairs` — route `set` paths through
`config.CompleteSetPathWithValues` over `setSchema`. `cmdtree.ConfigTopLevel`
only supplies the config-mode TOP-LEVEL keywords (`set`/`delete`/`commit`/
`load`/...) plus the retained `set system dataplane` description overlay.

### `class-of-service forwarding-classes queue` range (#4594)

`validateClassOfServiceForwardingClassQueueStrict`
(`compiler_validate_strict_cos.go`, gated in `runUniformGates`) hard-rejects a
forwarding-class whose `queue` is outside **0..255** on the strict commit /
commit-check path. The value used to be warn-only (`ValidateConfig`) and
COMMITTED, while the userspace helper deserializes the queue id via a checked
`u8::try_from` and fail-closes the WHOLE CoS snapshot on `CosQueueIdOutOfRange`
(#2410), silently keeping the node's STALE CoS forwarding state — a
config/dataplane divergence the operator could not see. xpf's valid range is
0..255 (the dataplane's `u8` queue id), NOT Junos-classic 0..7. The tolerant
load / peer-sync path downgrades to a warning
(`opts.lenientCoSForwardingClassQueue`) so an already-persisted queue that
committed under an older binary still boots (#1960 no-brick); the
`CosQueueIdOutOfRange` fail-close is the stale-but-safe backstop on that boot.

### `protocols lldp` TTL bounds (#4596)

The `transmit-interval` and `hold-multiplier` leaves (`schema_routing.go`) now
carry `ValidateInteger` typed-leaf validators bounding them to the IEEE 802.1AB
LLDP-MIB ranges Junos also enforces — `lldpMessageTxInterval` **5..32768** and
`lldpMessageTxHoldMultiplier` **2..10**. Their product feeds the 16-bit LLDP TTL
TLV (`ttl = transmit-interval × hold-multiplier`); before this gate both leaves
were untyped (bare `Atoi`), so e.g. `transmit-interval 16384` × default
hold-multiplier 4 = 65536 wrapped `uint16` to a TTL of 0 and IMMEDIATELY expired
the neighbor. `encodeTTL` (`pkg/lldp/lldp.go`) additionally clamps the computed
TTL to `[0, 0xffff]` as a defensive backstop so even the in-range IEEE extreme
(32768 × 10) — and any constructed caller — cannot wrap, matching the standard's
own `txTTL = min(65535, msgTxInterval × msgTxHold)`.

### `security zones` interface-defined reference (ps-review-002 F6, #4515)

`validateZoneInterfaceDefinedStrict` (`compiler_validate_strict_zones.go`, gated
in `runUniformGates`) hard-rejects a `security zones security-zone <z> interfaces
<if>` entry that names an interface which is **not** defined under `interfaces`
(and is not a daemon-materialized dynamic interface), on the strict commit /
commit-check path. Junos rejects such a zone member; xpf previously only WARNED
(`ValidateConfig`) then compiled and kept the zone. At runtime the referenced
interface is absent, so the daemon brings it DOWN (fail-closed for real traffic)
— safe but silent: a typo'd `ge-0/0/99` zone member carried no packets with no
commit-time signal.

The reference set is the **generous** union `zoneReferenceableInterfaceBases`
builds — this union is the safeguard that makes the promotion safe (the naive
`cfg.Interfaces.Interfaces`-only set is why the gap was left warn-only; it would
false-reject a legitimate dynamic-interface reference, the #4191 over-rejection
class):

- every explicitly-configured interface (`cfg.Interfaces.Interfaces`) — GRE /
  IPIP / WireGuard tunnels and VRF (routing-instance) member interfaces are
  covered here for free, because a tunnel device and a routing-instance member
  must both be configured under `interfaces`;
- `lo0` — the always-present loopback, a reserved Junos interface a zone may
  reference (host-inbound self-traffic) with no explicit `set interfaces lo0`;
- every secure-tunnel base derived from an IPsec `bind-interface`
  (`cfg.Security.IPsec.VPNs[*].BindInterface`) — `bind-interface st0.0`
  materializes the st0 xfrmi device at apply time (`daemon_apply` →
  `routing.ApplyXfrmi`) even with no explicit `set interfaces st0 unit 0`. The
  base is the bind string with any `.unit` stripped, so every unit of a bound
  secure tunnel is admitted.

The tolerant load / peer-sync path downgrades to a warning
(`opts.lenientZoneInterfaceDefined`) so an already-persisted or peer-synced
config an older binary accepted still boots (#1960 no-brick); runtime behavior on
that path is unchanged (the unresolved member carries no traffic). Runs AFTER
`validateZoneInterfaceMembershipStrict` (#3072, the same-interface-in-two-zones
gate) so a duplicate-assignment error still wins the first-error slot. Covered by
`pkg/config/zone_interface_defined_4515_test.go`.

Sibling gap **F11-part2** (a malformed address-book VALUE such as
`10.0.1.0/32/24`) was evaluated in the same issue and kept **warn-only**
DELIBERATELY: the `security address-book ... address` schema leaf is an
intentionally-open `multi:true` leaf (`schema_security.go`, `children:nil`) and
the non-literal Junos forms `dns-name` / `range-address` / `wildcard-address` are
not modeled — they compile to an empty prefix and warn ("no usable prefix
configured"). A malformed positional prefix also compiles to an empty prefix
(the same `looksLikeIPOrCIDR` gate that populates `Address.Value` rejects it), so
the empty-prefix warn conflates a genuine typo with a valid-but-unmodeled
non-literal form. Promoting it to a strict reject would false-reject every
`dns-name`/`range-address`/`wildcard-address` entry (the #4191 over-rejection
class) unless those forms are modeled first, and the residual fail-open is
narrow and theoretical (a permit rule referencing an empty-prefix address is
already fail-CLOSED — it matches nothing; only a deny blocklist entry could fail
open, the same class as a typo'd address-book NAME). See #4515.

## Multi-value leaves and bracketed lists (the dual-AST contract)

A `multi: true` leaf with `children: nil` (e.g. `from protocol`,
`from source-address`, `from destination-port`, and the scoped-global
`security policies global policy <p> match from-zone`/`to-zone`, #4626 M03)
accepts a Junos bracketed list value:

```
from protocol [ tcp udp icmp ];                     # hierarchical block
set ... from protocol [ tcp udp icmp ]              # flat-set command
```

The **lexer strips the brackets** (`lexer.go` `[`/`]` cases just advance and
recurse), so by the time either parser sees the tokens the list value is
flat: `protocol tcp udp icmp`. Both AST shapes MUST converge on a single
leaf whose Keys carry every value:

```
Keys=[protocol tcp udp icmp]   IsLeaf=true   (no children)
```

- The **hierarchical** parser already does this — `parseKeys` appends every
  identifier on the line to one node's Keys.
- The **flat-set** path (`ParseSetCommand` → `SetPath`) had a dual-AST gap
  (#2419): the schema-walk consumed only `args` tokens onto the node key
  (`Keys=[protocol tcp]`) and split the tail into an ORPHAN child leaf
  (`Keys=[udp icmp]`), so the compiler — reading the node key only — dropped
  every list member after the first. `SetPath` now, for a
  `children == nil && multi` leaf, ABSORBS every following non-sibling token
  onto the node's own Keys (`ast_edit.go`), emitting the same single leaf as
  the hierarchical parser. The `low to high` range spelling
  (`destination-port 20000 to 20003`) is absorbed identically (none of
  `20000`/`to`/`20003` is a sibling keyword), matching the hierarchical
  `Keys=[destination-port 20000 to 20003]`.

**Compiler contract for multi-value leaves.** Because both shapes now deliver
the values on `child.Keys[1:]` (with the hierarchical-block-with-children
shape still possible for nested forms), a compiler reading a multi-value leaf
MUST read BOTH `child.Keys[1:]` AND `child.Children` and ACCUMULATE — never
read only `child.Keys[1]`. `firewallMatchValues` (`compiler_firewall.go`) is
the canonical helper; `parseDNATPortList` and `appendPoolAddresses`
(`compiler_nat.go`, the latter the source-NAT-pool `address` reader, #4521)
and `descriptionText` (`compiler_security.go`) parse the unified single-leaf
shape directly off the node keys. `parseZoneList` (`compiler_nat.go`, the
static/source/destination-NAT `from`/`to` zone reader) and the WireGuard
peer `allowed-ips` reader (`parseTunnelWireguardPeer`,
`compiler_interfaces.go`) also follow the contract — both were silently
dropping all but the first bracketed value before the #2419 fold (static-NAT
`from zone [ trust dmz ]` lost the `dmz` rule-set entirely, FAIL-OPEN NAT).
Reading only `Keys[1]` silently drops all but the first list value — the
#2419 bug class. The flat-set bracket list is pinned to the hierarchical
shape by `TestFlatSetBracketListMatchesHierarchical` in
`pkg/config/parser_bracket_list_2419_test.go`; the static-NAT multi-zone and
allowed-ips folds are covered by the `security-nat-static-multi-zone` and
`interfaces-wireguard-allowed-ips-multi` dual-AST fixtures plus
`TestWireguardAllowedIPsBracketList{FlatSet,Hierarchical}`.

**`multi: true` ALSO prevents single-value REPLACE for repeated keyed-list
leaves (#3984).** The `#2419` discussion above is about ONE statement with a
bracket list. The SAME `multi: true` marker fixes a second, distinct shape:
a keyed-list leaf that the operator writes as SEPARATE `set` statements, one
value per line, which the compiler reads back as DISTINCT siblings via
`FindChildren`:

```
set system ntp server 1.1.1.1
set system ntp server 2.2.2.2
set system ntp server 3.3.3.3
```

Each statement consumes exactly `1 + args` tokens with NO trailing token, so
`SetPath` reaches its terminal-leaf branch (`i >= len(path)`). For a leaf
declared `args > 0, children: nil` WITHOUT `multi`, that branch takes the
**single-value REPLACE** path (correct for a scalar such as `host-name`): the
SECOND `set` replaces the first, and the config silently collapses to the
LAST value on any flat-set / `load set` / `| display set` round-trip. A leaf
whose compiler reads MULTIPLE siblings (accumulating into a slice) is NOT a
scalar — it must be `multi: true` so the terminal branch instead DEDUPs and
APPENDS, keeping each occurrence a distinct sibling. The leaves in this class
are `system ntp server`, `system archival configuration archive-sites`,
`system services web-management api-auth api-key`, and `security flow
traceoptions flag` (joining the already-`multi` `name-server` /
`domain-search`). The compiler stays `FindChildren`-based and unchanged — the
bug was purely the SetPath collapse. `archive-sites` also carries an optional
trailing `password <s>` modifier, which lands on `Keys[2:]` of the collapsed
leaf and is read there (`compiler_system.go`). Pinned by
`pkg/config/set_repeated_leaf_3984_test.go` (RED on revert of the markers).
This is the SET-side sibling of the display-side #3980 (`navigatePath` renders
all N siblings) and the delete/deactivate-side #3846/#3975 (member-wise edit,
which these leaves now inherit for free because `delete`/`deactivate` route a
`multi: true, children: nil, args == 1` leaf through the member matcher).

**`system archival configuration transfer-interval <minutes>` — periodic
off-box archive (#4078).** Junos archives the running config to `archive-sites`
every N minutes, independent of `transfer-on-commit` (a periodic backup for a
config that rarely changes). The leaf compiled into
`config.ArchivalConfig.TransferInterval` from the start, but no runtime consumer
read it — so the timed archive never fired (accepted-but-inert). It is now a
typed `setSchema` leaf (`ValueInteger`, `ValidateInteger(1, 2880)`) AND is wired
to a runtime timer: `daemon.reconcileArchiveTimer` (called from
`applyConfigLocked`, mirroring `reconcileRPM`) arms `runArchiveTimer`, which
fires every N minutes and archives the CURRENT active config via the SAME
`archiveToSites` transport `transfer-on-commit` uses (`daemon_flow.go`). The two
compose — either, both, or neither. The timer is hash-gated on
`(interval, sites)` so an unrelated commit never bounces a healthy timer; a
change to the interval or the site set reschedules; removing the leaf (or
dropping to interval 0 / no sites) stops it; and it re-arms on daemon restart
because the boot apply runs the same reconcile against the active config.
Periodic archival needs BOTH a positive interval AND at least one archive-site;
a bare `transfer-on-commit` config never spins a periodic goroutine.

**`valueList` — a bracketed value list on a multi leaf that ALSO has a
modifier child (#3872).** The bracket-absorption above fires only for a
`multi: true` leaf with `children: nil`. The static-route `next-hop` leaf is
the exception: it is `multi: true` (so `next-hop [ gw1 gw2 ]` — canonical Junos
ECMP — collapses onto ONE leaf `Keys=[next-hop gw1 gw2]` and the compiler
installs every gateway as an equal-cost next-hop) BUT it also declares an
`interface` modifier child for the IPv6 link-local form
(`next-hop fe80::1 interface reth0.50`). A plain `multi` leaf with children
would stay a container and never absorb the list; a plain-container leaf would
mis-nest the second gateway as an orphan child. `next-hop` therefore sets
`valueList: true`, which tells `SetPath` (`ast_edit.go`) to absorb a trailing
value list (tokens that are neither a sibling nor a known child) onto the leaf
while STILL descending into the container when the next token names the
`interface` child. Only `next-hop` sets it; every other `multi`+children node
(the CoS named containers) is unchanged — the guard `children == nil ||
valueList` keeps them on the container path. The compiler reads every gateway
from `Keys[1:]` (skipping an inline `interface <if>` pair) plus the `interface`
child. This is DISTINCT from a `qualified-next-hop`, which is a separate
floating-backup leaf carrying its own per-next-hop preference (#3871): a plain
`next-hop` list is equal-cost ECMP, a `qualified-next-hop` is a distance-N
backup.

**Fully-inline route-keys form drops the `interface` modifier (#3881).** The
above covers the flat-set and hierarchical-brace shapes, where `next-hop` is
its own leaf/child node. A THIRD shape exists: the hierarchical route written
on ONE line with no braces (`route 2001:db8::/32 next-hop fe80::1 interface
reth0.50;`) collapses the WHOLE route onto one leaf with NO children —
`Keys=[route <dst> next-hop fe80::1 interface reth0.50]`. `compileStaticRoutes`
(`compiler_routing.go`) reads this via the inline-keys switch, walking the route
node's `Keys[2:]` clause by clause; `isRouteInlineKeyword` (which includes
`interface`) bounds the multi-value gateway run so it stops before the modifier.
Before #3881 the switch had a `next-hop` case but NO logic to consume the
trailing `interface <if>` after the gateway run, so the egress interface was
silently dropped — fatal for an IPv6 link-local next-hop (`fe80::/10`), whose
gateway is unresolvable without a bound egress interface. The inline-keys
`next-hop` case now consumes a trailing `interface <if>` and applies it to the
gateway(s), mirroring the child/brace form. Both the inline-keys case and the
child/brace read treat `interface` as the modifier keyword ONLY after ≥1
gateway is parsed, so a next-hop value literally named `interface` as the FIRST
token stays a gateway value rather than being misparsed as the modifier.

**Delete-side contract: `delete` a member, not the whole list (#3846).**
The read-side accumulate rule above has a mirror on the edit side. A
`delete ... from protocol tcp` on a bracket-list leaf must remove ONLY the
named member (`tcp`), leaving `[ udp icmp ]` intact — NOT prefix-match the
leaf by its first key and drop the whole list. Before #3846 `deletePath`
(`ast_edit.go`) fell straight into `removeMatchingNode`/`keysMatch`, whose
prefix match deleted the entire node on `delete ... protocol tcp` (udp +
icmp silently gone) and left a NON-FIRST member undeletable
(`delete ... protocol udp` matched nothing and errored) — a
config-integrity fail-wide and potential fail-open (a removed match
constraint widens the term). `deletePath` now intercepts value-list
multi-leaves (`multi: true`, `children: nil`, `args == 1`) and routes them
to `removeMultiLeafMembers`, which:

- with trailing member token(s), drops ONLY those members — reading BOTH
  the flat `Keys[1:]` shape and the child-node shape, exactly mirroring
  `firewallMatchValues` on the read side — and removes the leaf entirely
  only once it is emptied of all members;
- with NO trailing member (`delete ... from protocol`), still clears the
  whole leaf (via `removeMatchingNode`);
- reports a member that is not present as not-found, matching
  `removeMatchingNode`'s contract.

The `args == 1` gate keeps keyed multi entries on whole-node delete
semantics: `address <name> <prefix>` (`args: 2`) and named containers with
children such as `interfaces <name>` are untouched, so `delete ... address
a1` still removes that whole entry, not just its name token. Covered by
`pkg/config/delete_multi_leaf_member_3846_test.go` (firewall `from
protocol`, host-inbound-traffic `system-services`, policy match
`source-address`, and the keyed-entry `address` non-regression).

**Deactivate-side contract: toggle the whole bracket leaf, round-trippably
(#3975).** `deactivate` / `activate` (`setInactiveAtPath`, `ast_edit.go`)
needed the SAME multi-leaf interception the delete side got in #3846. The
`Inactive` marker is a NODE-level flag and a bracket list collapses onto ONE
node's `Keys[1:]`, so a bracket-list leaf can only be toggled whole — but the
pre-#3975 schema-driven traversal ate the first member as an extra key
(`nodeKeyCount == 2`) and then treated the remaining members as container
tokens, so `deactivate ... from protocol tcp udp icmp` ERRORED with
`container "protocol tcp" does not exist`. That is exactly the line
`show | display set` emits for an inactive bracket leaf (`ast_format.go`
expands `deactivate <path> tcp udp icmp`), so an inactive bracket leaf did NOT
round-trip: replaying its display-set errored and the leaf reloaded ACTIVE — a
silent loss of the operator's deactivate intent, the deactivate-side
counterpart of the #3846 fail. `setInactiveAtPath` now intercepts value-list
multi-leaves (`multi: true`, `children == nil` or `valueList`, `args == 1`) and
routes them to `markMultiLeafMembersInactive`, which:

- with no trailing member (`deactivate ... from protocol`), toggles the whole
  leaf (via `markMatchingNodeInactive`);
- with trailing member token(s), toggles the WHOLE node when any named member
  rides on `Keys[1:]` (the flat/bracket shape — a bracket list is one statement
  and cannot be half-deactivated), and for a plain value-list leaf ALSO toggles
  any named child node (the hierarchical block shape, e.g.
  `system-services { ssh; https; }`);
- reports a member that is not present anywhere as not-found, matching
  `removeMultiLeafMembers`'s contract.

The `args == 1` gate keeps keyed multi entries (`address <name> <prefix>`,
`args: 2`) on whole-node toggle semantics, exactly like the delete side.
Covered by `pkg/config/deactivate_multi_leaf_3975_test.go` (firewall `from
protocol` whole-list / no-member / member / absent-member / activate-reverse /
display-set round-trip, policy match `source-address`, block-shape
`system-services` member toggle, single-value-leaf and keyed-entry
non-regression).

**Rename-side contract: resolve the SPECIFIC named sibling by full identity
(#3982).** `rename <old> to <new>` (`RenamePath`, `ast_edit.go`) is the same
read-all-siblings class as the delete/deactivate fixes above, but on a
named-entity axis: with several same-keyword siblings (`policy A/B/C`,
`term X/Y/Z`) the operator must be able to rename the 2nd+ occurrence. The
pre-#3982 implementation resolved the source through `removeNode`, whose
per-level loop broke on the FIRST child whose FIRST key matched
(`matchNodeKeys > 0` returns `1` for a keyword-only match). So `rename policy B
to B2` with siblings `[A B C]` matched `policy A`, descended into it looking for
`B`, and failed `source not found` (for other shapes it could rename the wrong,
first node). The operator's only recourse was delete + re-add, losing ordering
and sub-config. `RenamePath` now:

- resolves the source through `findNodeWithParent`, which prefers the LONGEST
  key match (`consumed > bestConsumed`) and so selects the specific `policy B`
  by its full identity, not the first `policy` keyword;
- renames IN PLACE when the destination parent is the source parent (the common
  case — only the name changes), preserving sibling order and the node's
  children/sub-config; a cross-parent rename detaches the node and appends it
  under the new parent (via `childrenAtPath`), also keeping its subtree;
- rejects a rename whose new identity collides with an existing sibling under
  the destination parent (`rename policy B to C` when `C` exists), so a rename
  never silently creates a duplicate named entity.

The now-dead `removeNode` helper (first-keyword-match, order-destroying
append-on-reinsert) was removed. Covered by `TestRenameNonFirstSibling` in
`pkg/config/parser_ast_test.go` (non-first `B->B2` renames exactly B with
`[A B C]` order preserved and `then permit` sub-config intact, first-sibling
`A->A2` still works, colliding `B->C` rejected with the tree unchanged, and a
post-rename `CompileConfig` seeing `[A B2 C]`).

**`annotate <path> "comment"` resolves through `navigatePath` (#4587).**
`annotate` attaches a `/* comment */` to the statement at a path, and — like
`delete`/`deactivate`/`rename` above — the path routinely crosses NAMED /
multi-key containers: `security zones security-zone trust`, `security policies
from-zone <z> to-zone <z> policy <p>`, `interfaces <name> unit <n>`, `family
inet`. `Store.Annotate` (`pkg/configstore/store_command.go`) previously used a
hand-rolled walk that consumed ONE path token per node but matched it against
ANY key in the node's `Keys`, so it entered a multi-key node on its first key
(`security-zone` of `Keys=[security-zone,trust]`) and then failed to find the
argument token (`trust`) as a child — `path not found` for every zone, policy,
interface-unit, and family-inet path. Annotate worked only for a chain of pure
single-key nodes such as `system`. It now delegates to
`ConfigTree.AnnotatePath` (`pkg/config/ast.go`), which reuses the SAME
multi-key-aware `navigatePath` traversal that `show <path>` / `FormatPath`
use (the #3980/#4562 read-all-siblings display resolver) — a multi-key node is
consumed as a unit, so every named container resolves. The comment is set on
the first resolved node (single-node semantics; the single-key `system` case is
byte-identical), and an unresolved path still returns a clear `path not found:
<path>` error and mutates nothing. The #3900 comment-delimiter rejection
(`ValidateAnnotationText`) runs BEFORE resolution and is unchanged. Covered by
`TestAnnotateMultiKeyContainers` in `pkg/configstore/store_test.go` (zone /
zone-description-leaf / from-zone-to-zone-policy / interface-unit / family-inet
resolve + RED on revert, single-key `system` non-regression, non-existent
multi-key path still errors).

**Firewall-filter `source/destination-prefix-list` refs are dual-AST too
(#3843).** These `from` leaves are NOT `multi: true` value-tails — each
reference carries an optional trailing `except` modifier, so they compile
through a dedicated helper `firewallPrefixListRefs` (`compiler_firewall.go`)
rather than `firewallMatchValues`. The helper reads BOTH shapes and groups each
`<name> [except]` pair:

- **hierarchical single-name leaf** `source-prefix-list plX;` /
  `source-prefix-list plX except;` — the name(s) ride on `child.Keys[1:]` with
  ZERO children (the `load merge` / config-file shape).
- **hierarchical block** `source-prefix-list { pl1; pl2 except; }` and
  **flat-set** `set ... source-prefix-list plX except` — one child node per
  referenced list (`child.Children`).

Before #3843 the `source/destination-prefix-list` case iterated only
`child.Children`, so the single-name leaf shape had its scope SILENTLY DROPPED:
the term compiled with NO prefix-list refs (implicit match-all) yet passed
strict commit cleanly — a HIGH fail-open (the #2419 dual-AST class on the
prefix-list-ref leaf, distinct from the #2506 dataplane-snapshot resolver).
Because the dropped ref never reached `term.SourcePrefixLists`, the
`validateFirewallPrefixListReferencesStrict` gate (#2506) had nothing to check
and an undefined name also slipped through. Reading `child.Keys[1:]` guarantees
the scope survives; an unresolvable name is then hard-rejected at commit, so a
dropped scope is impossible. Coverage:
`compiler_prefix_list_hier_leaf_3843_test.go` (single-name source/dest/except +
undefined-reject fail-on-revert, plus block / flat-set regression guards).

**The prefix-list DEFINITION body is dual-AST too (#3996).** Distinct from the
`from source/destination-prefix-list` *reference* above, this is the
`policy-options prefix-list NAME { <p1>; <p2>; ... }` *definition*. Its schema
leaf (`schemaPolicyOptions`, `schema_routing.go`) is `args: 1` (the name) with
`children: nil`, so every prefix under the name lands as a CHILD of the named
node. Two child shapes occur: one child per prefix (a `set ... prefix-list NAME
<p>` per line, or a brace block with one `<p>;` per line — each child holds a
single prefix in `Keys[0]`), OR the bracketed-list form `set ... prefix-list
NAME [ p1 p2 p3 ]`, where the lexer strips `[`/`]` and packs EVERY prefix onto a
SINGLE child node's `Keys`. `compilePolicyOptions` (`compiler_routing.go`) reads
the FULL `Keys` slice of each child — note it reads from `Keys[0]`, NOT
`Keys[1:]`, because a prefix-list entry carries no field-name prefix (the child's
keys ARE the prefix values), so `firewallMatchValues` (which skips `Keys[0]`) is
the WRONG helper here. Before #3996 the loop read only `entry.Keys[0]`, so a
bracketed list kept just the FIRST prefix and silently dropped the rest → an
under-populated prefix-list (a route-filter, firewall filter, or dynamic address
group matched a partial prefix set with no commit error). The separate-command
and single-prefix shapes were unaffected (each child had exactly one key).
Coverage: `compiler_prefix_list_bracket_3996_test.go` (bracketed all-three +
display-set round-trip fail-on-revert, plus separate-command / single-prefix
regression guards); the multi-block MERGE case is `compiler_prefix_list_merge_2641_test.go`.

**NAT `match` axes are multi-value (#3431).** The source/destination NAT rule
`match` leaves `application`, `protocol` (DNAT), `source-address-name`, and
`destination-address-name` are all `multi: true` (alongside the already-plural
`source-address` / `destination-address` / `destination-port`). The source and
destination NAT parsers (`compiler_nat.go`) accumulate EVERY value via
`firewallMatchValues` into the `NATMatch` plural slices `Applications`,
`Protocols`, `SourceAddressNames`, and `DestinationAddressNames`, keeping the
singular `Application` / `Protocol` / `SourceAddressName` /
`DestinationAddressName` = the first element for back-compat. Before #3431 these
four axes used `nodeVal(m)` (first value only), so `match application [ a b ]`,
`match protocol [ tcp udp ]`, or a multi-name list silently kept ONE value and
dropped the rest — a NAT rule narrowed unexpectedly with no commit error (Codex
audit 095 H04/H05/H06). Consumers read through the `NATMatch.{Application,
Protocol,SourceAddressName,DestinationAddressName}List()` accessors (which fall
back to the scalar for a config JSON-synced from a pre-#3431 peer): the strict
commit validators (`compiler_validate_strict.go`) now reject a bad value in ANY
list position, and the userspace snapshot builders (`pkg/dataplane/userspace/
nat.go`) expand the union — one DNAT entry per protocol, one app term per
resolved application (an application-set still expands to its members). Coverage:
`compiler_nat_match_multivalue_3431_test.go` (both AST shapes, all axes) and
`nat_match_multivalue_3431_test.go` (snapshot expansion).

**A source-NAT pool `address` is multi-value (#4521).** A source pool's
`address` value carries EVERY IP the SNAT allocator may draw from, in four
shapes: discrete `set` lines (one `address <ip>;` per IP), a bracket list
`address [ a b c ]`, a range `address <low> to <high>`, and a hierarchical
block `address { a; b; c }`. `address` under a source pool is UNMODELED in the
schema (`schema_security.go` pool children are port / persistent-nat /
port-overloading-factor / routing-instance), so SetPath's unmodeled-leaf path
collapses the whole bracket list onto ONE node key (`Keys=["address","a","b",
"c"]`) — the classic #2419 collapse. Before #4521 `compileNATSource`
(`compiler_nat.go`) read only `prop.Keys[1]` (and the range branch required
`Keys[2]=="to"`), so a discrete bracket list with no `to` silently kept ONLY
the first IP → the pool shrank to one address → premature source-port
exhaustion under load. The fix reads the FULL `prop.Keys[1:]` token stream
(plus the block `prop.Children`) via `appendPoolAddresses`, expanding any
`<low> to <high>` sub-range in place — the #2419 dual-shape read pattern
(mirroring `firewallMatchValues`), so every shape (discrete, bracket, range,
mixed `[ a b to c ]`, block) accumulates every address. Coverage:
`compiler_nat_source_pool_address_4521_test.go`.

**Security host-inbound and session-log surfaces are multi-value (#3703).** The
same #2419 collapse class recurred on four security leaves that #2419 never
converted, all modeled as CONTAINERS (or nil-children non-multi leaves) instead
of `multi: true` value-tail leaves — so a bracket / single-line list mis-nested
the tail under the first token and the compiler readers dropped everything after
it, silently and with the dropped tokens (including typos) bypassing strict
validation:

- **host-inbound `system-services` / `protocols`** (zone level AND the #3362
  per-interface override) — `hostInboundSchemaChildren` (`schema_security.go`)
  makes both `args: 1, multi: true, children: nil` (untyped: the token allowlist
  is the shared `host_inbound_tokens.go` SSOT). `parseHostInboundNode`
  (`compiler_security.go`) reads every value via `firewallMatchValues`, so the
  compiled `HostInboundTraffic.SystemServices/Protocols` slices carry the whole
  list and `validateHostInboundTokensStrict` (already on the compiled slice)
  rejects an unknown token at commit. A dropped host-inbound service silently
  NARROWS admission (`system-services [ ssh netconf ]` → only `ssh`), which can
  strand SSH / routing.
- **per-policy `then log`, `default-policy-log`, and `pre-id-default-policy then
  log`** — the shared `sessionLogModeLeaf` factory (`schema_security.go`) makes
  each a `multi: true, children: nil` typed ENUM leaf
  (`valueType: ValueEnumOf`, `validator: ValidateEnum([session-init,
  session-close])`). Because it is a typed multi leaf, `SchemaValidate`
  dispatches to `validateMultiValueLeaf`, which validates EVERY token (Keys[1:]
  plus block-list children) — so an unknown log mode is REJECTED at commit
  (strict) / warned on the tolerant load path (#1960 no-brick), closing the gap
  that `validatePolicyLogActionStrict` (both-false only) and the
  default-policy-log / pre-id WARN-only validators left open. The compiler
  readers (`compilePolicy` `then log` arm, the `default-policy-log` arm, and the
  `pre-id-default-policy` reader in `compiler_security.go`) accumulate every mode
  via `firewallMatchValues` across ALL sibling `log` leaves and only CREATE the
  target struct once (never reset), so both the bracket form
  (`then log [ session-init session-close ]`) and the repeated-line form
  (`then log session-init` + `then log session-close`, two sibling leaves) land
  both flags. Dropping the container children does not lose `?` completion — the
  two modes surface via `valueExamples`. A dropped `session-close` loses
  session-duration / close audit records despite valid syntax. Coverage:
  `compiler_security_bracket_list_3703_test.go` (all four surfaces, both harm
  directions — tail-drop and typo-bypass — across bracket / repeated-line /
  hierarchical shapes, plus the value-slot completion pin).

**The `to` range separator in `validateMultiValueLeaf` is opt-in (#4556 L-01).**
`validateMultiValueLeaf` (`schema_walk.go`) treats the fixed mid-token `to` as
a range separator (`<a> to <b>`) ONLY for a leaf that sets `rangeSeparator: true`
on its `schemaNode`. The separator is meaningful solely for a leaf whose value
domain is a numeric RANGE — port-range and NAT-pool-address. Those production
leaves are compiler-validated (they carry no schema `validator`), so they never
reach `validateMultiValueLeaf`; every typed multi leaf that DOES reach it today
is an IP/CIDR leaf (`name-server`, VRRP `virtual-address`, RA `dns-server-address`)
or a session-log-flag leaf, where `to` is never a valid member. On those leaves
`rangeSeparator` stays false, so a literal `to` is validated as an ordinary value
and rejected with a clear "invalid value" message (e.g. `name-server 1.1.1.1 to
8.8.8.8` — name-server takes no range — is rejected, not silently accepted by
skipping `to`). Before the gate, `to` was special-cased on EVERY typed multi
leaf, leniently skipping it. Only the white-box walker test's synthetic
port-range leaf sets `rangeSeparator` today (`schema_walk_internal_test.go`);
`TestSchemaValidate_NameServer_ToNotRangeSeparator` pins the non-range behaviour.

**IKE/IPsec proposals, RIP export/redistribute, and routing-instance interface
are multi-value (#3904).** Four more leaves of the #2419/#3431/#3703
bracket-list-truncation class (fable-161 F-040/F-161/F-162/F-163), all fixed by
routing the compiler read through `firewallMatchValues` (Keys[1:] + child nodes,
both AST shapes):

- **IKE/IPsec policy `proposals`** (`schema_security.go`) — both leaves are now
  `args: 1, multi: true`. `IKEPolicy.Proposals` and `IPsecPolicyDef.Proposals`
  changed from a scalar `string` to `[]string`, and `compileIKE` /`compileIPsec`
  (`compiler_ipsec.go`) accumulate EVERY reference. The strongSwan generator
  (`pkg/ipsec/ike.go` `resolveIKESettings` / `resolveESPSettings`) builds each
  resolvable proposal and comma-joins them into the swanctl `proposals =` /
  `esp_proposals =` list (strongSwan negotiates the first mutually acceptable
  one); the auth method + lifetime come from the first resolvable proposal, and
  the policy-level PFS group applies to every ESP proposal. Before #3904 the
  scalar kept only the FIRST reference, so `proposals [ p1 p2 ]` silently offered
  only `p1` — crypto negotiation NARROWED and a peer requiring `p2` could not
  establish. The strict commit validators (`compiler_validate_strict.go`) now
  require EVERY reference in the list to resolve (a dangling trailing reference
  is a typo the commit-check rejects, mirroring the NAT H05 gate). Coverage:
  `compiler_ipsec_proposals_multivalue_3904_test.go` (both AST shapes + dangling-
  second rejection) and `pkg/ipsec/ike_proposals_multivalue_3904_test.go` (both
  proposals comma-joined into the rendered swanctl config, PFS applied to all).
- **RIP `redistribute` / group `export` / `neighbor` / `passive-interface`**
  (`schema_routing.go` — the declared top-level leaves are now `multi: true`; the
  `group` block stays an opaque `children: nil` container, so its `export` /
  `neighbor` bracket list already collapses onto Keys[1:]). The RIP block in
  `compileProtocols` (`compiler_protocols.go`) reads every value via
  `firewallMatchValues` into the already-plural `RIPConfig.Redistribute` /
  `Interfaces` / `Passive` slices. Before #3904 each read only `child.Keys[1]`, so
  `redistribute [ static connected ]` or `export [ pa pb ]` kept ONE entry — a
  RIP node silently advertised / redistributed less than configured. The existing
  RIP export strict validator (`compiler_validate_strict.go`) already walks the
  full slice, so a dangling non-first export name is rejected at commit. Coverage:
  `compiler_rip_multivalue_3904_test.go` (both AST shapes).
- **routing-instance `interface`** (`compiler_routing.go`) — the
  `interface [ i1 i2 ]` list is compiled through `firewallMatchValues` into the
  already-plural `RoutingInstanceConfig.Interfaces`. `interface` is an OPAQUE
  implicit leaf under the `routing-instances` wildcard (not a declared schema
  child — like `instance-type`), so the flat-set bracket already collapses onto
  Keys[1:] and no schema change is required. Before #3904 the read was
  `nodeVal(prop)` (Keys[1] only), so `interface [ ge-0/0/1 ge-0/0/2 ]` bound only
  the first port to the VRF and the rest stayed in the DEFAULT table — a VRF
  isolation break. Coverage: `compiler_routing_instance_interface_3904_test.go`
  (both AST shapes + single-value back-compat).

**Policy match source-/destination-address/application share the reader
(#4121, divergence-elimination, NOT a fail-open).** `compilePolicy`
(`compiler_security.go`) previously read the three `multi: true` policy-match
value leaves with a per-arm either/or (`if len(m.Keys) >= 2 { Keys[1:] } else {
Children }`) while the strict match gates read them via `firewallMatchValues`
(Keys[1:] AND Children). VERIFY-FIRST established the either/or was NOT lossy for
any shape the parser actually emits: a bracket / inline list collapses onto
`Keys` (read by the Keys[1:] arm), a hierarchical block `source-address { a; b; }`
yields `Keys=["source-address"]` + child nodes (read by the Children arm), and
repeated statements yield sibling leaves (each read on its own pass) — the three
shapes are mutually exclusive, so either/or picked the correct slot every time
and the #2419 bracketed-list class was already read in full. The ONE shape where
either/or diverged from read-both — a node carrying members in BOTH slots
(`source-address a1 { a2; }`, not emitted by any canonical Junos or display-set
round-trip) — dropped the child members. The three arms now route through
`firewallMatchValues` (address arms keep the `any-ipv4`/`any-ipv6` →
`0.0.0.0/0`/`::/0` normalization via `normalizePolicyAddrTokens`) so the compiler
and the strict gates share ONE match-value reader: a future dual-AST divergence
becomes a shared-test change rather than a silent drift. Coverage:
`compiler_policy_match_ssot_4121_test.go` (flat/hier bracket, flat/hier repeated,
hier block all read every value; the both-slots node is the fail-on-revert case).
The `compiler_security.go` file-split (issue #4121 part B) is done: the former
2357-line grab-bag is split into focused per-concern modules, all in package
config, as PURE CODE MOTION (function bodies byte-identical, no behavior
change) — `compiler_security.go` now holds only the `compileSecurity`
dispatcher, with `compiler_security_zones.go` (zone compilation),
`compiler_security_policy.go` (policy compilation + the shared-reader arms
above), `compiler_security_screen.go` (screen/IDS), `compiler_security_addressbook.go`
(global + zone-local address books), `compiler_security_log.go` (security log),
`compiler_security_flow.go` (flow + tcp-mss + traceoptions gates), and
`compiler_security_alg.go` (ALG). Folding `trafficSelectorValues`
(`compiler_ipsec_trafficselector.go`) onto the shared reader remains deferred
(the #4104 DRY note, low-value/high-churn).

## Duplicate host-local-address fail-closed gate (#3718, Option B)

Beyond the per-leaf token allowlist above, host-inbound admission has a
**cross-field** commit-time gate. The kernel host-inbound nftables chain matches
on **destination address only** (no ingress-interface / VRF predicate) over a
single global input chain, so two security zones that resolve the SAME
firewall-local address (a duplicated interface address, a duplicated VRRP VIP, or
the same address reused across routing-instances) emit two rule blocks keyed on
the same `daddr` in zone-sort order — the earlier-sorting zone decides the packet
regardless of ingress, and can even disagree with the ingress-scoped userspace-dp
path (split-brain). `validateDuplicateHostLocalAddressStrict`
(`compiler_validate` group, `dup_host_local_address.go`) **rejects at commit /
commit-check** a config where the same `(family, host address)` — interface
address OR VRRP VIP — is host-inbound-reachable from more than one **distinct
effective host-inbound token set**. It keys on *differing* sets (via the shared
`config.CanonicalHostInboundTokenSig`), NOT merely ">1 zone", so a deliberate
duplicate with **identical** service sets across its zones is allowed (no false
positive), and management/cluster-control lifeline interfaces (fxp0 / em0 / fab*)
are excluded. Lenient downgrade to a `cfg.Warnings` entry on the tolerant load /
peer-sync path (`lenientDuplicateHostLocalAddress`, #1960 no-brick); the runtime
`dpuserspace.AmbiguousHostInboundAddresses` reporter + the
`xpf_host_inbound_ambiguous_addresses` gauge surface any tolerantly-loaded
ambiguity (it is NOT self-healing). The kernel `iifname` ingress-scope fix
(Option A) and per-VRF host-inbound chains (Option C) are deferred follow-ons —
see `docs/host-inbound-service-matrix.md`. Coverage:
`dup_host_local_address_3718_test.go` (config), `zones_ambiguous_3718_test.go`
(reporter), `metrics_host_inbound_ambiguous_3718_test.go` (metric),
`host_inbound_ambiguous_3718_test.go` (daemon log transitions).

## Trailing-token arity on scalar value leaves (#3332)

The mirror image of the multi-value contract is the **scalar** value leaf: a
keyword that consumes EXACTLY `args` value token(s) and models no
sub-structure (`description`, `host-name`, `peer-address`, `scheduler-map`,
`port`, …). In the flat-set grammar a recognized non-multi leaf parks any
trailing token its arity does not expect as a CHILD node rather than on Keys
— `set interfaces ge-0-0-0 description hello bogus` becomes
`Keys=[description hello]` with an orphan child `Keys=[bogus]` (`SetPath`,
`ast_edit.go`). The compiler reads only the declared value span, so before
#3332 the orphan was silently DROPPED: a typo'd extra token committed cleanly
and the operator's garbage was discarded with no warning. (This is distinct
from the #3318 unknown-KEYWORD gate — here the leaf keyword itself IS
supported; only the trailing token is not. The screen subset was closed
earlier by #3411's `compileScreen` `recordKeyExtras`/`recordChildExtras`;
#3332 is the general schema-walk gate.)

`SchemaValidate` (`schema_walk.go`) now rejects the excess —
`validateScalarValueLeaf` rejects the first Keys token past `1+args` AND the
first AST child, with a value-arity message ("the extra token would be
silently dropped"). The gate fires only on an EXACT keyword match (a wildcard
match means the keyword is a dynamic instance NAME, not this leaf's value
slot) and only on a leaf the `schemaNode.isScalarValueLeaf` predicate
(`schema.go`) admits.

**Why an explicit `scalar: true` opt-in, not structural inference.** An
`args > 0, children: nil` node is NOT reliably a value leaf: several are
deliberately-OPAQUE CONTAINERS whose body is left to the compiler and parsed
off the node's AST children — `applications application-set <name> {
application <member>; }`, `applications application <name> { ... }`, `system
syslog file <name> { ... }`. Their legitimate body lands on Keys/Children
exactly like a typo would, so a structural-only gate would false-reject real
config (caught in review: `application-set my-set application junos-http`).
The arity contract therefore lives on an explicit per-leaf `scalar: true`
tag, asserted only on leaves audited to take a fixed value and NO body
(`description` across the tree, `system host-name`, dynamic-peer/feed
`hostname`). This is the "design pass on the value-arity contract" the #3332
body called for; new scalar leaves opt in as they are audited.

**#4415 L12 → #4626 M03 — scoped global-policy `from-zone`/`to-zone` (a zone
SET).** A Junos global policy may carry an optional `match from-zone` /
`match to-zone` to scope it to a set of zones (#3148). The typed model behind
it — `config.PolicyMatch.FromZones` / `.ToZones` — is a `[]string` SET
(sorted + de-duplicated at compile; an empty slice = all zones; a one-element
slice = the single-zone case, bit-identical to the pre-#4626 single string). A
zone LIST (`match from-zone [ trust dmz ]`) collapses via the #2419 lexer onto
one leaf's Keys (`["from-zone","trust","dmz"]`); both leaves therefore carry
`multi: true` (NOT `scalar: true`), and the compiler
(`compiler_security_policy.go`) ACCUMULATES every value via the
`firewallMatchValues` dual-AST SSOT rather than keeping only `Keys[1]`. The
pre-#4626 code kept `trust` and silently DROPPED `dmz`; the #4415 L12 interim
fail-closed `scalar: true` rejected the list outright — both are now replaced
by real multi-zone parity (a packet matches iff its from-zone ∈ `FromZones`
AND its to-zone ∈ `ToZones`). The strict commit gate validates per element
(undefined-zone reject; `from-zone junos-host` reject; a scope list mixing
`any` with concrete zones, or a `to-zone` list mixing `junos-host` with other
zones, rejected). The scope crosses the wire as ADDITIVE plural
`match_from_zones` / `match_to_zones` alongside the retained singular
`match_from_zone` / `match_to_zone` (first element, rolling-upgrade safe).
Pinned by `pkg/config/schema_global_zone_list_4415_test.go` (now a positive
multi-zone accept) and `pkg/config/scoped_global_zoneset_4626_test.go`.

`isScalarValueLeaf` also carries belt-and-braces structural guards, so a
future mis-tag on a node that is actually multi / typed / a container
degrades to a no-op rather than a surprise rejection. It exempts:

- **`!scalar`** — un-tagged leaves are untouched (the opt-in default).
- **`multi`** — bracketed lists / value tails (#2419, above) absorb every
  trailing value by design.
- **`children != nil` / `wildcard != nil`** — named-instance / modifier
  containers (`address <cidr> { primary; }`, `transmit-rate 1g exact`): the
  trailing tokens are real sub-structure the container path validates.
- **`compoundKey` / `midKeyword`** — the trailing token is part of the node
  key (`family inet6`, `from-zone X to-zone Y`).
- **`isTypedLeaf`** — `validateTypedLeaf` already rejects unknown trailing
  tokens and unexpected children for typed leaves.
- **`args == 0`** — a childless, untyped, zero-arg node is AMBIGUOUS between
  a presence-only flag (`dhcp`) and a deliberately-OPAQUE leaf whose subtree
  the compiler reads despite no schema children (`tcp-mss <mode> <value>`,
  #1979; the unmodeled NAT pool `address`/`host` leaves — `port` is now a
  modeled container for its `deterministic`/`range` sub-stanzas, #3864). The
  screen flag subset (`tcp land`, …) is handled by #3411 instead.

A quoted multi-word value (`description "trust zone"`) arrives as ONE token,
so it is unaffected — only an UNQUOTED trailing token (`description trust
zone`, invalid Junos) is rejected. Minimum arity is NOT enforced — a missing
value is still left to the compiler; the gate is scoped strictly to EXCESS
trailing tokens, the silent-drop bug class. Pinned by
`pkg/config/schema_validate_trailing_token_3332_test.go`
(`TestSchema3332_*`, including the `application-set` opaque-container guard).

**Compiler-side companion gate for the shapes the walker cannot reach.** Two
silent-drop sites are NOT reachable by the schema-walk scalar gate and are
caught by `validateTrailingTokensStrict` (`compiler_validate_strict.go`)
instead, recorded on the typed struct during compile and rejected on the
strict commit / commit-check path (lenient downgrade to a `cfg.Warnings`
entry on the tolerant load / peer-sync path, `lenientTrailingTokens`):

- **address-book `address <name> <prefix>` / `address <name> description
  <text>`** — the `address` schema node is `multi:true` (it must absorb the
  `description` sub-token onto its Keys to keep the #2419 dual-AST shape), so
  the scalar gate (which exempts `multi`) never reaches the value slot and
  `mergeAddressNode` reads only the prefix / `descriptionText` token.
  `address h2 description web-server bogus` and `address h2 1.2.3.4/32 bogus`
  now record the leftover on `Address.TrailingTokens` (global AND zone-local
  books, since `resolveZoneLocalAddressBooks` copies only Value/Description).
- **IKE gateway compact-hierarchical `dynamic hostname <fqdn> <extra>`** — the
  flat-set form lands `hostname <fqdn>` as a scalar CHILD the generic gate
  covers, but the compact-hierarchical one-liner collapses the tokens onto the
  parent `dynamic` node's Keys and `compileIPsec` reads only `Keys[2]`. The
  leftover is recorded on `IPsecGateway.DynamicHostnameExtras`.

The address-book `address-set description` leaf is deliberately NOT tagged
`scalar: true`: `AddressSet` has no `Description` field and the compiler does
not read it, so the value is currently unsupported and discarded — an arity
gate there would assert validation on a no-op feature (tag it only if/when
`AddressSet.Description` is wired).

## Per-subtree closed-world keyword validation (#4313)

The scalar-arity gate (#3332, above) is a token-level fix: it catches an
extra token trailing a MODELED leaf. It does not touch the deeper default of
the whole schema — **the config schema is OPT-IN at the KEYWORD level**. When
the generic walker (`walkSchemaNode`, `schema_walk.go`) resolves a keyword and
finds no schema child (`resolveSchemaChild` returns nil, no exact child and no
wildcard), it returns nil and moves on — an unmodeled keyword is not the gate's
concern, reporting is left to the compiler. But the compiler has no schema case
for a keyword the schema does not model either, so such a leaf commits clean
and is then silently DROPPED. The parity campaigns have repeatedly closed one
of these per subtree (each "silently dropped … added a schema child + compiler
case" entry in the changelog below), but the *default* remained silent-accept.

A **blanket** flip of that default is infeasible: several subtrees are
deliberately lenient — they accept-with-advisory rather than reject, so that a
not-yet-modeled or peer-only Junos knob survives a load / sync instead of
failing the whole snapshot (#1960/#3307/#3318 lenient-warn; the #2078/#4231
accept-with-advisory knobs). Rejecting every unmodeled keyword tree-wide would
break those on purpose-lenient paths and false-reject valid-but-not-yet-modeled
Junos configs (the #4191 strand-preflight false-reject class).

The remedy is therefore a **per-subtree closed-world flag**, landed as a
dormant MECHANISM in PR-A:

- `schemaNode.closedWorld bool` (`schema.go`). Default false = today's opt-in,
  silent-accept behaviour. When true on a container node, an unmodeled child
  keyword anywhere under that subtree is REJECTED at strict commit instead of
  silently dropped.
- The walker threads a `closed` parameter (`walkSchemaChildren` /
  `walkSchemaNode` / `walkInstanceChildren`). The top-level call passes
  `closed=false`; descending into a resolved container folds in that node's
  flag (`childClosed := closed || childSchema.closedWorld`), so once a subtree
  opts in, every level below it inherits closed-world enforcement.
- The single behavioural branch is at the keyword-resolution gate: when
  `closed` is true AND the keyword is unmodeled (`childSchema == nil`), the
  walker returns a `typedLeafErrorf` reject ("unknown configuration keyword
  … under closed-world subtree"), mirroring the existing modifier-level
  unknown-keyword rejects. When `closed` is false — the state for EVERY
  production subtree today — behaviour is byte-identical to pre-#4313
  (return nil, silent-accept).

PR-A landed the mechanism DORMANT (no production subtree set `closedWorld`,
zero false-reject risk). It is white-box tested with a SYNTHETIC subtree
(`schema_walk_internal_test.go`, `TestClosedWorld_*`): an unmodeled keyword
under a `closedWorld:true` node is rejected; the same shape under a default
(open-world) node is still silently accepted; a modeled keyword under the
closed node passes; and closed-world inherits into modeled descendant
containers.

**First production flip — destination-NAT rule then-action (PR-B, #4313).**
`security nat destination rule-set <rs> rule <r> then` now sets
`closedWorld:true` (`schema_security.go`). It is the first production subtree
to opt in. The completeness audit that gates the flip:

- The Junos DNAT rule then-action is exactly `destination-nat { off | pool
  <pool-name> }`. Directly under `then` the only valid keyword is
  `destination-nat`; directly under `destination-nat` the only valid keywords
  are `off` and `pool`; `off` is a value-less leaf and `pool <name>` is a
  terminal pool reference with no sub-block (there is no rule-level
  persistent-nat for destination NAT — that is a source-NAT feature). Every
  keyword at every level below `then` is modeled, and the compiler
  (`compileNATDestination`) reads only these same keywords, so closing carries
  no false-reject risk.
- The reject fires on the STRICT operator commit path (`SchemaValidate`); the
  tolerant `Store.Load` / `SyncApply` path downgrades it to a warning
  (`compileTreeLenient`, #1960), so a stored or peer-synced config is never
  bricked. A typo (`then destination-nat poool dp`) or garbage keyword now
  fails the commit with a "closed-world subtree" error instead of committing
  clean and being silently dropped. Production tests:
  `schema_closedworld_nat_then_4313_test.go` (RED on revert of the flag).

**NOT flipped — source-NAT rule then-action.** The sibling `security nat source
… rule … then` is deliberately left open-world. Junos permits `then source-nat
pool <name> persistent-nat { … }` at the RULE level, which xpf instead models
per-pool (`security nat source pool <name> persistent-nat`). Flipping the
source-NAT then would inherit closed-world down to its `pool` leaf and
false-reject that valid Junos config (the #4191 class). It is a follow-up:
model the rule-level persistent-nat leaves (or make an accept-with-advisory
decision) FIRST, then flip.

**More production flips — IPsec leaf-complete option containers (PR-C, #4313).**
Three additional `security` subtrees now set `closedWorld:true`
(`schema_security.go`), each after the same leaf-completeness audit — the
modeled child set equals the full Junos grammar AND equals the exact keyword
set the compiler (`compiler_ipsec.go`) reads, so closing carries no
false-reject risk:

- `security ipsec vpn <v> traffic-selector <ts>` — the entire Junos grammar is
  `local-ip <prefix>` and `remote-ip <prefix>` (both modeled); the compiler
  traffic-selector loop reads only those two. A typo (`local-op`) would
  silently drop the selector prefix and negotiate the wrong crypto proxy-id;
  it is now rejected at commit.
- `security ipsec vpn <v> vpn-monitor` — the full grammar is `source-interface`,
  `destination-ip`, and `optimized` (all modeled); the compiler `vpn-monitor`
  arm reads only those three. (The feature itself is accepted-but-not-enforced
  advisory, but the flip still catches typos.)
- `security {ike,ipsec} gateway <gw> dead-peer-detection` (both identical copies
  of the block are flipped) — the full grammar is `always-send`, `optimized`,
  `probe-idle-tunnel`, `interval <seconds>`, and `threshold <count>` (all
  modeled); `parseDeadPeerDetectionNode` reads only those five. A typo
  (`intervl`) would silently keep the Junos default; it is now rejected.
  **#4878:** the closed-world flip caught a bad KEYWORD but not a bad VALUE —
  `interval banana` still committed (the compiler's `strconv.Atoi` error was
  ignored → DPD silently reverted to the strongSwan default) and
  `interval 9223372036854775807 threshold 9223372036854775807` overflowed the
  rendered `delay*threshold` timeout to a negative that was then dropped. Both
  `interval` and `threshold` are now typed `ValueInteger` leaves with bounded
  validators (`ValidateInteger(1, 3600)` / `ValidateInteger(1, 100)`), so a
  non-numeric / non-positive / overflow-sized value is rejected at commit — and,
  like every typed leaf, downgraded to a warning on the tolerant
  `Store.Load` / `SyncApply` path (#1960). The chosen upper bounds keep
  `interval*threshold` far from int overflow. Production test:
  `dpd_typed_value_4878_test.go` (RED on revert of the two validators).

Every value leaf in these subtrees (`local-ip`/`remote-ip`,
`source-interface`/`destination-ip`, `interval`/`threshold`) carries its value
on the same statement line — there is no nested value block in Junos — so
closed-world never descends into an AST child of a value leaf in EITHER parser
shape, and cannot false-reject a valid config. As with PR-B, the reject fires
only on the strict commit path; `compileTreeLenient` downgrades it to a warning
on `Store.Load` / `SyncApply`. Production tests:
`schema_closedworld_ipsec_4313_test.go` (RED on revert of each flag).

**More production flips — `system master-password` (#4578).** The
`system master-password` subtree now sets `closedWorld:true`
(`schema_system.go`) after the same leaf-completeness audit: xpf models AND
consumes exactly one leaf, `pseudorandom-function` (the configstore
at-rest-encryption PRF selector, read raw from the AST by
`configstore.masterPasswordPRF`). Because `system` is open-world (#4515/X-1), a
typo in the KEYWORD (`pseudo-random-fnuction`) previously committed clean —
`masterPasswordPRF` then found no `pseudorandom-function` child, fell through to
its empty default, and **at-rest config encryption was silently OFF** while the
operator believed it was on. The flip rejects the keyword typo at strict commit.
Paired with it, the `pseudorandom-function` value slot is now enum-validated
(`ValidateMasterPasswordPRF`, `schema_validators.go`) against the exact selector
set `configstore.prfHash` understands (`MasterPasswordPRFNames`, matched
case-insensitively because prfHash lower-cases), so a typo in the VALUE
(`bogus-prf`, or `hmac-sha256` missing the `2-`) is caught too rather than
falling through prfHash's default and failing the persisted-tree write with an
opaque error. This is deliberately SCOPED to the master-password subtree — the
broader `system` open-world remediation (#4515/X-1) is untouched, because a
blanket `system` closed-world would false-reject valid-but-unmodeled leaves (the
#4191 class). A `pkg/configstore` drift test (`crypto_prf_sync_4578_test.go`)
asserts `prfHash` honours every name the commit gate advertises, so the gate and
the encrypt path cannot silently diverge. Production tests:
`schema_master_password_prf_4578_test.go` (RED on revert of the closedWorld flag
AND the value validator). As with the other flips, the reject fires only on the
strict commit path; `compileTreeLenient` downgrades it to a warning on
`Store.Load` / `SyncApply`.

**More production flips — `security ike proposal` (Phase-1 crypto, #4313).**
The Phase-1 IKE proposal container (`security ike proposal <name>`) now sets
`closedWorld:true` (`schema_security.go`) after adding the one missing leaf
that made it leaf-complete. The completeness audit that gates the flip:

- The full Junos `security ike proposal <name>` grammar is exactly
  `authentication-method`, `authentication-algorithm`, `dh-group`,
  `encryption-algorithm`, `lifetime-seconds`, and `description`. The first five
  were already modeled; this change models `description` (cosmetic, scalar,
  compiler-ignored) so the closed subtree does not false-reject a valid proposal
  that carries it. The compiler (`compiler_ipsec.go`, the IKE proposal loop)
  reads a STRICT SUBSET of the modeled set (the five crypto leaves; description
  falls through its switch), so closing carries no false-reject risk (the #4191
  class). Phase-1 has **no** `lifetime-kilobytes` — that is a Phase-2/ESP
  volume-rekey knob — so, unlike the sibling `security ipsec proposal`, this
  subtree is complete with `description` alone.
- Every modeled leaf carries its value on the same statement line (no nested
  value block in Junos), so closed-world never descends into an AST child of a
  value leaf in EITHER parser shape.
- Silent-drop here FAILS OPEN on crypto: a fat-fingered `encryption-algorith`
  or `authentication-algoritm` used to commit clean, the compiler then found no
  such child, and the Phase-1 SA negotiated WITHOUT the operator's chosen
  cipher/hash — a silent downgrade to whatever the proposal (or a proposal-set
  default) still carried, believed to be aes-256 while it was not. The flip
  rejects the typo at strict commit; the tolerant `Store.Load` / `SyncApply`
  path downgrades it to a warning (`compileTreeLenient`, #1960). Production
  tests: `schema_closedworld_ike_proposal_4313_test.go` (RED on revert of the
  flag; the lenient-no-brick case is covered too).

**More production flips — `security ipsec proposal` (Phase-2 ESP crypto,
#4313).** The Phase-2 ESP proposal container (`security ipsec proposal <name>`)
now sets `closedWorld:true` (`schema_security.go`), the sibling of the closed
Phase-1 IKE proposal above. The completeness audit that gates the flip:

- The full Junos `security ipsec proposal <name>` grammar is exactly `protocol`,
  `encryption-algorithm`, `authentication-algorithm`, `dh-group`,
  `lifetime-seconds`, `lifetime-kilobytes`, and `description`. The first five
  were already modeled; this change models `lifetime-kilobytes` (the ESP
  volume-based rekey knob that DISTINGUISHES the Phase-2 proposal from the
  Phase-1 IKE proposal — Phase-1 has none, which is why `description` alone
  completed it) and the cosmetic `description`. The compiler (`compiler_ipsec.go`,
  the IPsec proposal loop) reads `protocol` / `encryption-algorithm` /
  `authentication-algorithm` / `dh-group` / `lifetime-seconds` /
  `lifetime-kilobytes` and ignores `description`, i.e. a subset of the modeled
  set — so closing carries no false-reject risk (the #4191 class).
- Every modeled leaf carries its value on the same statement line (no nested
  value block in Junos), so closed-world never descends into an AST child of a
  value leaf in EITHER parser shape.
- Silent-drop here FAILS OPEN on crypto exactly like the IKE proposal: a
  fat-fingered `encryption-algorith` or `authentication-algoritm` used to commit
  clean, the compiler then found no such child, and the ESP SA negotiated
  WITHOUT the operator's chosen cipher/hash — a silent downgrade. The flip
  rejects the typo at strict commit; the tolerant `Store.Load` / `SyncApply`
  path downgrades it to a warning (`compileTreeLenient`, #1960).
- `lifetime-kilobytes` is CAPTURED (`IPsecProposal.LifetimeKilobytes`) but
  accepted-only: the strongSwan renderer emits `rekey_time` (seconds) and no
  `rekey_bytes`, so volume-based rekey is not yet enforced. `ValidateConfig`
  emits an accepted-only advisory (`compiler_validate_warn.go`) so an operator
  is not silently misled into believing the SA rekeys on bytes — strictly
  better than the pre-flip silent commit-and-drop. Production tests:
  `schema_closedworld_ipsec_proposal_4313_test.go` (RED on revert of the flag;
  the lenient-no-brick case and the advisory are covered too).

**More production flips — `security nat nat64` and `security nat natv6v4`
(xpf-native NAT64 stanzas, #4313).** Both now set `closedWorld:true`
(`schema_security.go`). These are xpf-NATIVE stanzas (Junos does NAT64 via
source/destination NAT + `then static-nat inet`, not this spelling), so the
grammar IS exactly what xpf models and compiles — there is no external Junos
superset to false-reject, making them leaf-complete by construction:

- `security nat nat64` — the container's only child is `rule-set`, and a
  rule-set's only children are `prefix` and `source-pool` (both modeled value
  leaves whose value rides on the same statement line). The compiler
  (`compileNAT64`) reads ONLY those two and the struct (`NAT64RuleSet`) holds
  ONLY `Prefix` + `SourcePool`. `closedWorld` is set on the `nat64` container so
  it is inherited down (the `childClosed` fold): a typo at the nat64 level
  (`rulset`) OR under a rule-set (`prefx` / `source-pol`) is rejected. Silent-
  drop was a real footgun: a typo'd `prefx` left `NAT64RuleSet.Prefix` empty,
  `validateNAT64PrefixStrict` skipped the rule (`Prefix == ""` → continue), and
  NAT64 translation silently did nothing — IPv6-only clients lost IPv4
  reachability with no error. Tests: `schema_closedworld_nat64_4313_test.go`.
- `security nat natv6v4` — its entire grammar is the single flag
  `no-v6-frag-header` (modeled); the compiler reads ONLY that keyword and the
  struct (`NATv6v4Config`) holds ONLY `NoV6FragHeader`. A typo
  (`no-v6-frag-heder`) previously committed clean and silently left the IPv6
  fragment header in translated packets; it is now rejected at strict commit.
  Tests: `schema_closedworld_natv6v4_4313_test.go`.

As with every flip, the reject fires only on the strict commit path;
`compileTreeLenient` downgrades it to a warning on `Store.Load` / `SyncApply`.

**The systematic per-subtree closure continues (#4313).** Each of the flips
above (destination-NAT then, the three IPsec option containers, master-password,
the Phase-1 IKE proposal, now the Phase-2 IPsec proposal and the two
xpf-native NAT64 stanzas) closes one leaf-complete high-risk subtree; the
blanket-default flip stays deferred (it would break the deliberately-lenient
accept-with-advisory knobs #2078/#4231 and false-reject valid-but-unmodeled
Junos, the #4191 class). Both the remaining per-subtree flips and the
blanket-flip doctrine decision remain tracked on #4313.

**Remaining per-subtree flips (future PRs, tracked on #4313).** Turning
`closedWorld` on for the other umbrella candidates (`snmp community` — INCOMPLETE:
Junos allows `view` / `client-list-name` / `routing-instance`, unmodeled;
`security nat static … then static-nat` —
UNSAFE: `static-nat` is a free-form leaf and the Junos hierarchical form
`static-nat { prefix { … } }` would false-reject under closed-world; `security
screen ids-option` — INCOMPLETE, deliberately open-world; `security ipsec vpn
<v> ike` bindings — INCOMPLETE: Junos allows `proxy-identity` /
`no-anti-replay`, unmodeled; the source-NAT rule `then` — deferred (rule-level
persistent-nat, see above); `protocols {ospf,bgp} interface` and `interfaces …
family`) is only safe once that subtree is LEAF-COMPLETE — every valid Junos
keyword under it is modeled — otherwise the flip false-rejects a valid config.
The Phase-2 `security ipsec proposal` is now CLOSED (both `description` and
`lifetime-kilobytes` were modeled first — see above). Each remaining flip is
its own follow-up gated on a Junos-leaf completeness audit for that subtree. Do
NOT set `closedWorld` on a subtree without that audit.

### `firewall ... from tcp-flags` — semantic validation, not just a list (#3076)

`from tcp-flags` is a `multi: true` leaf, so the dual-AST contract above
delivers its tokens uniformly (`firewallMatchValues`). But unlike a plain
value list, the tokens form a Junos logical *expression* — `"syn & !ack"`,
`"(syn & ack)"`, `"ack | rst"` — where `&`/`|`/`!`/`(`/`)` carry meaning.
A quoted expression arrives as a single token string; a bracket/space list
(`[ syn ack ]`, `"syn ack"`) is an implicit conjunction.

`ParseTCPFlagsExpression` (`pkg/config/tcp_flags.go`) parses the joined tokens
into a **required-bits** mask and a **forbidden-bits** mask over the TCP flags
byte (`(flags & required) == required && (flags & forbidden) == 0`). The
conjunctive AF_XDP matcher can carry one required set and one forbidden set, so
the following are **rejected at commit** (`compileFirewall` returns an error)
rather than silently dropped:

- disjunction (`|`, e.g. `"ack | rst"`) — not a single required/forbidden pair;
- a negated parenthesized group (`!(...)`) — a disjunction by De Morgan;
- an unrecognized flag token;
- a flag that is both required and forbidden (the term could never match).

This is the #3076 fix: before it, the schema accepted any `tcp-flags` token
(the leaf is `multi: true` with no value validator) and the snapshot builder's
bare-name-only lookup silently dropped any expression it could not map — the
filter term then matched **regardless** of TCP flags (a fail-open security
hole). Validation is now fail-closed: an unenforceable constraint is refused at
commit, and a representable one (including `syn & !ack`) is carried to the
dataplane via the `tcp_flags` / `tcp_flags_forbidden` wire fields.

### `firewall ... from icmp-type` / named ports — resolve + fail closed (#3205)

`from icmp-type` / `icmp-code` and the four port leaves (`source-port`,
`destination-port`, `source-port-except`, `destination-port-except`) accept
SYMBOLIC Junos match values: icmp-type names (`echo-request`, `echo-reply`,
`destination-unreachable`, ...) and service/port names (`ssh`, `http`,
`domain`, ...). `pkg/config/filter_match_resolve.go` is the SSOT that resolves
these to numbers at compile time — the icmp-type table is **family-selected**
(ICMPv4 for `family inet`, ICMPv6 for `family inet6`: `echo-request` = 8 vs
128), and the port table is the canonical Junos service-name set (e.g.
`domain` = 53). Resolved ports are rewritten to numeric form so the dataplane
only ever sees numerics.

This is the #3205 fix (agy-070 #07/#08). Before it:

- `icmp-type`/`icmp-code` were parsed with `strconv.Atoi` and the error was
  IGNORED, so a symbolic name was silently dropped — the type/code set went
  empty, and an empty set matches **ALL** ICMP, so an `accept` term meant to
  permit only `echo-request` silently permitted every ICMP type (a policy
  bypass);
- an unknown named port left the port set constrained-but-empty, and a
  `*-port-except` term then matched **ALL** ports (fail open — it permitted the
  very port it was meant to exclude).

`validateFilterMatchValuesStrict` (`compiler_validate_strict.go`) **rejects at
commit** any term whose icmp-type/icmp-code name or port name could not be
resolved (the unresolved token is recorded on the term as
`UnknownICMPTypes`/`UnknownICMPCodes`/`UnknownPorts`, mirroring
`UnknownActions`). On the tolerant load / peer-sync path the error is
downgraded to a warning (#1960 no-brick) and the token is kept verbatim so the
dataplane fails CLOSED independently (the Rust `port_match` constrained+empty
guard now fails closed for `except` too — see `userspace-dp/src/filter/
README.md`). Symbolic icmp-CODE names are not resolved (Junos code names are
type-dependent) — a numeric 0-255 is required and a symbolic code is rejected.
Fail-on-revert: `TestFilterICMPTypeNameResolves{V4,V6}_3205`,
`TestFilterUnknown{ICMPType,Port}Rejected_3205`,
`TestFilterNamedPortExceptResolves_3205` in
`pkg/config/firewall_symbolic_match_3205_test.go`.

### `firewall ... from` cross-field satisfiability — port/tcp-flags/icmp must match the protocol (#3723)

A firewall-filter `from` block can combine a `protocol` (or the inet6
`next-header`) with an L4 predicate the dataplane matcher can never satisfy for
that protocol. Such a term compiled cleanly but became a **never-match** at
runtime, and because an xpf filter falls through to an implicit **ACCEPT** on
no-match, a `then discard` / `then reject` written over such a pair was silently
dead — the traffic it was meant to drop was admitted by a later permit or the
implicit accept (a **fail-OPEN**). Junos rejects these combinations at commit,
so accepting them was also a config-language parity gap. This is the
stateless-filter mirror of the application cross-field gate (#3373 port /
#3348 icmp).

The offending pairs (matcher behavior in `userspace-dp/src/filter/engine/
matching.rs`):

- **port on a non-port-bearing protocol** — `port_match` tests the constrained
  port set against the extracted L4 port, which is `0` for any protocol the
  dataplane does not extract ports for (only TCP/UDP — `ip_proto::has_l4_ports`).
  So `from protocol gre; destination-port 80` (also esp/ah/ospf/vrrp/icmp/...,
  and numeric 47) never matches (H01).
- **tcp-flags on a non-TCP protocol** — `per_packet_l4_matches` returns false
  when the packet protocol is not TCP, so `from protocol udp; tcp-flags syn`
  never matches. UDP is port-bearing but still not TCP, so the tcp-flags arm
  uses the stricter `protocolIsTCP` predicate, not `protocolIsPortBearing` (H02).
- **icmp-type/icmp-code on a non-ICMP protocol** — the icmp arms return false for
  a non-ICMP(v6) packet, so `from protocol tcp; icmp-type echo-request` never
  matches (H03).

`validateFilterCrossFieldStrict` (`compiler_validate_strict.go`) **rejects at
commit** any term that combines these, reusing the same SSOT the application
gate uses — `protocolIsPortBearing` / `protocolIsICMPFamily` (plus the new
`protocolIsTCP` for the tcp-flags arm). Handling of the folded findings:

- **mixed protocol list (M01)** — if ANY protocol token in a bracket list such
  as `from protocol [ tcp gre ]` is incompatible with the predicate, the term is
  rejected (a single configured deny that only enforces on the compatible
  protocol and silently never-matches the rest).
- **inet6 next-header (M02)** — `compileFilterFrom` routes both `protocol` and
  `next-header` into `term.Protocols`, so the gate covers `family inet6` filters
  with no extra code.
- **icmp-code without icmp-type (M03)** — rejected, mirroring the #3348/#3506
  application reject: a code-only term constrains the code while the type stays
  unconstrained, matching a broader ICMP set than a Junos config implies
  (icmp-code 0 is common across many types).

The gate fires **only when a protocol is PRESENT**. A port / tcp-flags / icmp
match with NO protocol is legitimate and enforceable for a FILTER (unlike an
application, whose matcher keys on protocol+port): the filter matcher matches
the port on whatever port-bearing packet arrives, and the tcp-flags/icmp arms
self-gate on the packet protocol. The only no-protocol exception is M03
(icmp-code-without-type), which is rejected regardless.

On the tolerant load / peer-sync path the error is downgraded to a warning
(`lenientFilterCrossField`, #1960 no-brick). The Rust snapshot builder is the
fail-closed backstop: `parse_term` rejects the whole snapshot with
`SnapshotIntegrityError::UnsatisfiableFilterCrossField` (the reconcile preflight
keeps the previous good filter state) so a leniently-loaded / drifted never-match
term never silently forwards — the same defense-in-depth as the #2505/#3367/#3406
filter backstops. Fail-on-revert: `pkg/config/firewall_crossfield_3723_test.go`
(including the L12 cross-package canary that pins the application and filter gates
to the shared port-bearing / ICMP-family / TCP SSOT) and the
`filter_crossfield_3723_*` tests in `userspace-dp/src/filter/tests.rs` (including
an L06 runtime guard that drives the real matcher over a fabricated gre+port term
to prove it falls through to Accept).

#### Ports must be a canonical unsigned decimal (#3606)

A numeric port token must be a plain unsigned decimal — no leading sign
(`+80` / `-80`), no surrounding whitespace. Junos rejects a signed port, and
the two userspace-dataplane parsers historically DISAGREED about it: the Go
capability gate `userspacePortSpecRepresentable`
(`pkg/dataplane/userspace/capabilities.go`) parses with `strconv.ParseUint`,
which rejects the sign, while the Rust `parse_port_spec`
(`userspace-dp/src/policy.rs`) parses with `u16::from_str`, which ACCEPTS a
leading `+` (`"+80"` -> `Ok(80)`). The commit-time gates used `strconv.Atoi`,
which also accepts `+80` (`Atoi("+80") = 80`; `-80` was already caught by the
`>= 1` bound). So `+80` committed cleanly, the CLI simulator said it matched,
and the port was then either silently downgraded to unsupported (application
path — the capability gate rejected it) or silently coerced to `80` (filter /
NAT paths, which normalize to a number before the wire) — a commit-vs-dataplane
split on a security leaf.

The single parse authority is now `parseCanonicalPort`
(`pkg/config/compiler_applications.go`): it requires a bare run of ASCII
decimal digits and is used by every commit-time port-spec parser —
`validatePortSpec` (application `source-port` / `destination-port`),
`resolveSinglePort` (firewall-filter port leaves), `parseDNATPortList` (NAT
`match destination-port`), and `validateDNATPoolStrict` (destination-NAT pool
`port`). The Rust `parse_port_spec` was tightened in lock-step (`parse_port_u16`
rejects the sign) so all three parsers agree. Fail-on-revert:
`TestSignedPortRejectedAtCommit_3606` / `TestParseCanonicalPort_3606`
(`pkg/config/compiler_signed_port_3606_test.go`) and
`parse_port_spec_rejects_signed_3606` (`userspace-dp/src/policy_tests.rs`).

The `system domain-search` and `system name-server` readers
(`compileSystem`, `compiler_system.go`) are also contract-compliant via
`firewallMatchValues`. Both are `multi:true`; before the second #2419 fold
they read only `child.Keys[1]` plus orphan leaf children. That orphan-children
path worked on flat-set BEFORE #2419 (the bracket split into child leaves), so
#2419's collapse onto `Keys[1:]` (no children) silently dropped every value but
the first — a #2419 regression (search domains lost; the DNS resolver drop-in
written from `name-server` lost every server but the first). Fail-on-revert
covered by `TestSystemDomainSearchBracketList{FlatSet,Hierarchical}` and
`TestSystemNameServer{BracketListFlatSet,BlockListHierarchical}` in
`pkg/config/system_multileaf_test.go`.

The routing-protocol export/import readers and the policy-options community
`members` reader were brought onto the contract in #2587. The schema leaves
were already `multi:true` (`schema_routing.go`: `protocols ospf export`,
`protocols ospf3 export`, `protocols bgp export`/`import`, `protocols isis
export`, `policy-options community <name> members`), but the compilers
(`compileProtocols`, `compiler_protocols.go`; `compilePolicyOptions`,
`compiler_routing.go`) read only `child.Keys[1]` with no children iteration,
so `protocols ospf export [ connected static ]` redistributed only
`connected` and `community c1 members [ 65000:1 65000:2 ]` truncated to the
first member. All six now route through `firewallMatchValues`.

The BGP **group** and **neighbor** export/import readers
(`compiler_protocols.go`, #2490) were NOT on the contract: they used the
`nodeVal(child)`-first pattern (`if v := nodeVal(child); v != "" { append v }
else if len(Keys) >= 2 { append Keys[1:] }`). Because `nodeVal` returns
`Keys[1]` (non-empty for a bracket list), the `v != ""` branch fired and
appended ONLY the first policy — the `Keys[1:]` fallback never ran, so
`group g1 export [ OUT-A OUT-B ]` and `neighbor 10.0.0.1 export [ N-A N-B ]`
silently dropped every policy past the first (#2702; an earlier #2690 review
note that these readers were "already correct" was wrong). All four
(group export/import, neighbor export/import) now route through
`firewallMatchValues`, matching the top-level readers. Fail-on-revert covered
by the `TestOSPFExport*`, `TestBGPExportImport*`,
`TestBGPGroupExportImport*`, `TestBGPNeighborExportImport*`,
`TestOSPFv3Export*`, `TestISISExport*`, and `TestCommunityMembers*` cases in
`pkg/config/protocols_multileaf_2587_test.go`.

The policy-statement `from community`, `from prefix-list`, and `from as-path`
match readers were the same class and were brought onto the contract in #2689
(`as-path` folded in during review). All three leaves are `multi:true`
(`schema_routing.go`: `policy-options policy-statement <name> term <name> from
prefix-list`/`community`/`as-path`), but `parsePolicyTermChildren`
(`compiler_routing.go`) read only `nodeVal(fc)` = `child.Keys[1]`, so
`from community [ c1 c2 ]` matched only `c1`, `from prefix-list [ p1 p2 ]`
matched only `p1`, and `from as-path [ a1 a2 ]` matched only `a1` (the dropped
as-path was silently absent from the `policy_render.go` cartesian OR product).
All three now route through `firewallMatchValues`. This composes with the #2642
repeated-sibling append below — a term carrying BOTH a bracket list AND a
separate `from community c3` sibling keeps every value (`[c1 c2 c3]`).
Fail-on-revert covered by `TestPolicyFromCommunity*`, `TestPolicyFromPrefixList*`,
and `TestPolicyFromASPath*` in `pkg/config/policy_from_multileaf_2689_test.go`.

The policy-statement ACTION `then as-path-prepend "<asn> <asn> ..."` (#2892) is
the same class on the `then` side. The leaf is `multi:true`
(`schema_routing.go`: `policy-options policy-statement <name> term <name> then
as-path-prepend`) so a quoted `"65001 65001"` or bracketed `[ 65001 65001 ]`
list — the lexer strips quotes and brackets alike — flattens onto the node's
`Keys`/`Children` rather than collapsing to last-only. `parsePolicyTermChildren`
and `parsePolicyTermInlineKeys` (`compiler_routing.go`) read EVERY ASN via
`firewallMatchValues` (reading only `Keys[1]` would drop all but the first
prepend — and dropping the repeats defeats the AS-path-prepend mechanism, which
is exactly the repetition). The ordered list lands in `PolicyTerm.ASPathPrepend
[]string` and renders as the FRR `set as-path prepend <asn> <asn> ...` clause
(`policy_render.go`). Fail-on-revert covered by `TestASPathPrepend_*` in
`pkg/config/compiler_as_path_prepend_2892_test.go` (parse) and
`TestGeneratePolicyOptions_ASPathPrepend` in
`pkg/frr/policy_as_path_prepend_2892_test.go` (render).

### Quoted-value escape round-trip contract (#3854)

When a key or value contains a character that is not a bare Junos identifier
byte (`isIdentChar` in `lexer.go` — anything outside letters/digits/`-_./:*+%=,<>`),
`Format`/`FormatSet` wrap it in double quotes via `quoteKey` (`ast.go`). The set
of characters `quoteKey` escapes MUST exactly match the set the lexer's
`readString` un-escapes on parse, or the config does not round-trip. The lexer
decodes exactly three sequences — `\"` → `"`, `\\` → `\`, and `\n` → newline —
and preserves any other `\X` verbatim. `quoteKey` therefore escapes exactly
those three characters (backslash, double-quote, newline) via the single-pass
`keyEscaper` (`strings.NewReplacer(`\`→`\\`, `"`→`\"`, "\n"→`\n`)). Backslash is
escaped first (in the same pass) so `\"` cannot double-process into `\\"`.

This symmetry guarantees `Format(Parse(x)) == x` and `Parse(Format(x)) == x` for
every value — critically an IKE pre-shared-key `ascii-text` (or any string leaf)
containing a backslash. Before #3854 `quoteKey` escaped only `"`, so a value like
`P@ss\next` (backslash before `n`) was corrupted on every `Format→Parse` cycle:
HA config sync (which is `Format→wire→Parse`) silently diverged the standby's PSK
so IPsec failed to re-establish on failover, and rollback slots serialized via
`Format` round-tripped to a different, possibly invalid config. Do NOT add escapes
for characters the lexer does not interpret (e.g. `\t`) — that would over-escape
and break the symmetry in the other direction. Pinned by
`pkg/config/quotekey_roundtrip_3854_test.go` (`TestQuoteKeyLexerSymmetry3854`,
`TestFormatParseRoundTrip3854`, `TestFormatParseIdempotent3854`).

## Firewall-filter cross-family name collision fail-closed gate (#3884)

Junos namespaces firewall filters **per family**, so `family inet filter blockX`
and `family mpls filter blockX` are two distinct filters. xpf cannot: `compileFirewall`
(`compiler_firewall.go`) selects the destination pool(s) — `fw.FiltersInet` for
most families, `fw.FiltersInet6` for `inet6`, and BOTH for `any` (#4287, see
below) — so EVERY family except `inet6` and `any` (`inet`, `mpls`, `ccc`,
`vpls`, `bridge`, and any not-yet-modelled token — `SchemaValidate` does not
reject an unknown family keyword) folds into the single `fw.FiltersInet` pool,
then writes `dest[filter.Name] = filter` **unconditionally**. Two same-name
filters authored
under two different non-inet6 families therefore silently collapse — the later
definition last-write-wins over the earlier with no commit error. If the `family
inet` filter was a `discard`/deny and the colliding-family filter is accept-all,
the effective IPv4 filter becomes accept-all: a deny silently downgraded to an
accept (a security **fail-open**).

Downstream consumers reference filters by **name** within the inet (V4) / inet6
(V6) buckets only — an interface unit's `FilterInputV4` resolves against
`fw.FiltersInet`, `FilterInputV6` against `fw.FiltersInet6`
(`compiler_validate_warn.go`, `routing/rules.go`, `dataplane/userspace/filters.go`).
There is no family dimension in the reference, so once two non-inet6 families
share a name the map cannot disambiguate them and the reuse is genuinely
ambiguous. `validateFirewallFilterFamilyCollisionsAST` (`compiler_firewall.go`)
**rejects at commit / commit-check** a filter name defined under more than one
distinct non-inet6 family, naming the filter and the colliding families. It is an
AST pre-walk (mirroring `validateApplicationNameCollisionsAST`, #3339) because the
colliding definitions are merged away by last-write-wins by the time
`fw.FiltersInet` exists — only the raw AST still carries every family's
definition — and it aggregates across every top-level `firewall {}` block
(compileFirewall folds each into the same map, so a split-block collision is just
as real).

`inet6` has its own dest map (`fw.FiltersInet6`) and is the ONLY family that folds
there, so a name shared between `family inet` and `family inet6` lands in two
different maps and does **not** collide — the legitimate dual-stack case (one
filter name for the V4 and V6 path) is preserved. Only a name under ≥ 2 distinct
non-inet6 families is flagged. Because the schema-driven flat `set` grammar only
structures `family inet` / `family inet6`, an unknown family (`any`, `mpls`, …)
reaches a structured `filter` subtree — and thus the fold-overwrite — only via a
hierarchical config-file parse or a directly-constructed / peer-synced AST; that
is exactly the reachable path the gate closes.

On the tolerant load / peer-sync path the error downgrades to a `cfg.Warnings`
entry (`lenientFirewallFilterFamilyCollisions`, #1960 / #3261 no-brick), keeping
the arbitrary-but-stable last-write-wins map so an already-persisted or
peer-synced config an older binary silently accepted still BOOTS. Fail-on-revert:
`pkg/config/compiler_firewall_family_collision_3884_test.go` (strict reject on
`CompileConfig`, warn-not-brick on `CompileConfigLenient` with the surviving
accept asserted, plus the inet/inet6 dual-stack and single-family no-false-reject
cases).

## Firewall-filter `family any` applies to BOTH v4 and v6 (#4287)

Junos `family any` firewall filters are **protocol-independent** — they match
BOTH IPv4 and IPv6. Before #4287, `compileFirewall` folded every non-inet6
family (including `any`) into the single `fw.FiltersInet` (IPv4) pool, so a
uniquely-named `family any` discard/deny filter was enforced on IPv4 **only**
and silently let IPv6 through — a security **fail-open** (an operator writes a
`family any` deny expecting it to block both families; the v6 arm is lost).
This is distinct from the #3884 same-name cross-family overwrite above: here a
*uniquely-named* filter loses its v6 arm.

`compileFirewall` now compiles a `family any` filter into **both**
`fw.FiltersInet` and `fw.FiltersInet6` (the `dests` slice in
`compiler_firewall.go`), so the deny applies to both address families. Because
`family any` now folds into the inet6 pool as well,
`validateFirewallFilterFamilyCollisionsAST` was extended with an `any`+`inet6`
cross-check: a `family any` filter name shared with a distinct `family inet6`
filter would silently overwrite in `FiltersInet6`, so it is rejected at strict
commit / warned on the lenient load path (same #1960 no-brick doctrine).

Reachability is the same as #3884: the schema-driven flat `set` grammar does
not model `family any`, so a flat `set firewall family any ...` collapses and
never mints a structured filter; the fail-open is reachable only via a
hierarchical config-file parse or a directly-constructed / peer-synced AST.
Fail-on-revert: `pkg/config/compiler_firewall_family_any_4287_test.go` (both
pools populated for a `family any` discard; strict reject + lenient warn for
the any+inet6 collision; lone `family any` no-false-reject).

### Family-specific matches under `family any` are rejected (#4296)

The #4287 dual-compile has a residual: a `family any` term whose `from` block
carries a **family-specific** match is dual-compiled **verbatim** into both
pools, so the copy in the "wrong" pool can never match. A v4/v6
`source-address`/`destination-address` literal or a per-family
`icmp-type`/`icmp-code` (`echo-request` resolves to ICMPv4 type 8 for
`af=="any"`, which never matches an IPv6 ICMP packet whose echo-request is
type 128) leaves the inet6 (or inet) arm with a never-matching predicate — the
term falls through to the implicit ACCEPT for that family, an imperfect v6
UNDER-block (it degrades to the pre-#4287 state for that term; never an
over-block, so no legitimate v6 traffic is broken). These configs are also
non-Junos (Junos disallows family-specific matches under `family any`).

`validateFirewallFilterFamilyAnyMatchesAST` (`compiler_firewall.go`, invoked in
`compiler.go` right after the collision gate) **rejects** such a term at strict
commit / commit-check with a message pointing the operator at `family inet` /
`family inet6`, and **warns** on the tolerant load / peer-sync path
(`lenientFirewallFilterFamilyAnyMatches`, same #1960 no-brick doctrine). The
flagged leaves are exactly `source-address`, `destination-address`,
`icmp-type`, `icmp-code`. `next-header` (the inet6 spelling of `protocol`,
matching family-agnostic L4 protocol numbers) and `source-prefix-list` /
`destination-prefix-list` (named prefix-lists may legitimately mix v4+v6) are
deliberately NOT flagged. The gate fires **before**
`validateFilterAddressLiteralsStrict` (#3433), which also rejects a wrong-family
address literal but with a less specific message; for the address case the
#4296 gate wins the first-error slot with the clearer diagnostic, and for the
`icmp-type`/`icmp-code` case it is the ONLY gate that catches the residual.
Fail-on-revert: `pkg/config/compiler_firewall_family_any_match_4296_test.go`
(strict reject of a v4 source-address and a symbolic icmp-type; lenient warn;
family-agnostic `protocol` under `family any` still commits into both pools;
single-family filters with address literals not flagged).

### Single-family prefix-lists under `family any` are rejected (#4426)

The #4296 gate deliberately leaves `source-prefix-list` /
`destination-prefix-list` alone because a *named* prefix-list MAY mix v4+v6 —
its family content is not knowable from the leaf keyword. But a reference whose
**resolved** prefixes cover only ONE family reproduces the exact same
under-block (audit codex-164 C164-H04): `from source-prefix-list v4-only then
discard` under `family any` dual-compiles the v4-only list into the inet6 pool,
where the v6 arm has zero v6 prefixes, matches nothing, and falls through to the
implicit ACCEPT — a silent v6 under-block.

`validateFirewallFilterFamilyAnyMatchesAST` therefore also resolves every
prefix-list reference against the candidate tree's `policy-options prefix-list`
definitions (via `firewallPrefixListFamilies`, which mirrors
`compilePolicyOptions`' #3996 dual-shape prefix read so the family verdict
matches what the compiler loads). Coverage is aggregated **per direction**
across every `from` block of the term, tracking **positive** and **`except`**
references separately (`hasPos`/`hasExc`, `posFam`/`excFam`) because they fail
in **opposite** ways under `family any`, mirroring `resolvePrefixListAddrs`
(#4338):

- A single-family **positive** list (`from source-prefix-list v4-only`) leaves
  the missing-family arm with no matching prefixes → matches **nothing** → falls
  through to the implicit ACCEPT → a silent **under-block**.
- A single-family **`except`** list (`from source-prefix-list v4-only except`)
  is the clean-except case: the missing-family arm evaluates `except` over a set
  with no entries for that family = **match ALL** → an **over-block** on `then
  discard`, a fail-**open** over-accept on `then accept` — the *opposite* of an
  under-block. (A defined positive ref makes the direction positive-wins and any
  `except` ref is dropped, so the except branch only fires for a *sole* `except`
  reference — exactly the runtime's clean-except path.)

Each is rejected at strict commit / warned on the lenient load path with a
message describing the **correct** failure mode (an inverted "under-block"
message for the `except` case would be misinformation worse than the gap).
Accepted (not flagged):

- a **mixed-family** prefix-list (v4 AND v6 prefixes in one list — positive or
  `except`),
- **two single-family lists** in one direction that together cover both
  families (`source-prefix-list { v4-only; v6-only; }`),
- an **empty** list (both-families-absent → left to the empty-set match
  semantics), and an **undefined** reference (left to
  `validateFirewallPrefixListReferencesStrict`).

Same reachability as #4287/#4296 (hierarchical / peer-synced AST only; the flat
`set` grammar does not model `family any`). Fail-on-revert:
`pkg/config/compiler_firewall_family_any_prefixlist_4426_test.go` (strict reject
of a v4-only and a v6-only positive list with the under-block message; strict
reject of a v4-only `except` list — and an `except`+`accept` fail-open — with
the over-match message, NOT the under-block wording; lenient warn preserving the
dual-compile; mixed-family, mixed-family-except, and two-list-both-families
commit; single-family filters with single-family lists not flagged).

## Repeated same-type sibling matches (NOT bracketed multi-value)

The dual-AST contract above covers a single leaf carrying a bracketed list
(`from community [ c1 c2 ]`). A SEPARATE phenomenon is the same match
statement REPEATED as sibling leaves in one block:

```
policy-options policy-statement P term t1 {
    from {
        community c1;        # repeated sibling leaves, NOT a bracket list
        community c2;
        prefix-list pl1;
        prefix-list pl2;
        as-path a1;
        as-path a2;
    }
    then accept;
}
```

Junos OR's repeated same-type `from` matches ("match any"). `PolicyTerm`
holds these as `[]string` (`PrefixList` / `FromCommunity` / `FromASPath`) and
the compiler (`parsePolicyTermChildren`, `parsePolicyTermInlineKeys` in
`compiler_routing.go`) APPENDS every value rather than overwriting — the
pre-#2642 single-string field silently kept only the LAST. The FRR renderer
turns each value into its own route-map sequence (OR semantics; FRR replaces
a same-type `match` rule in one index, so multiple match lines cannot OR) —
see `pkg/frr/README.md` (`policy_render.go`, #2642).

**Dual-AST convergence (#2630, fixed):** the HIERARCHICAL (brace) parser has
always accumulated every sibling correctly. The FLAT-SET path used to be
LIMITED — `ConfigTree.SetPath` collapsed repeated `set ... from community c1` /
`from community c2` sibling paths onto ONE AST node before the compiler ran, so
only the last value reached the compiler (silently dropping all but the last
`route-filter` / `prefix-list` / `community` / `as-path`). #2630 fixes this by
marking those four `from` leaves `multi: true` in `setSchema`
(`schema_routing.go`): the same `SetPath` multi-value-leaf logic that keeps
`from protocol` siblings distinct now keeps each repeated `set` line as its own
sibling leaf, so the two AST shapes CONVERGE on the same typed config.
`route-filter` is `args: 2` (prefix + match-type); a trailing
`upto /N` / `prefix-length-range /lo-/hi` / `through <cidr>` arg is absorbed as
a fourth packed key by the multi value-tail logic, matching the brace AST the
compiler reads via `routeFilterTrailingToken`. Proven by
`TestRouteFilterFlatSetMultipleAccumulate` + `TestRouteFilterFlatSetBraceParity`
(`compiler_route_filter_range_2525_test.go`) and
`TestPolicyTermMultiMatch_FlatSet_2630` /
`TestPolicyTermMultiMatch_Hierarchical_2642`
(`compiler_policy_term_multimatch_2642_test.go`).

## Repeated definition blocks merge (prefix-list, community)

A named policy-options DEFINITION can be authored across multiple separate
blocks — two `prefix-list NAME { ... }` braces, or two
`set policy-options prefix-list NAME ...` set groups (and likewise for
`community NAME`). `compilePolicyOptions` (`compiler_routing.go`) MERGES these
by reusing the existing `po.PrefixLists[name]` / `po.Communities[name]` map
entry and APPENDING each block's prefixes/members, rather than allocating a
fresh struct and overwriting `po.PrefixLists[name]` (which discarded the
earlier block — the #2641 prefix-list bug; the community loop already merged).
The two AST shapes converge: flat-set `SetPath` collapses repeated same-name
set groups onto one AST node so they accumulate naturally; the hierarchical
parser keeps two same-name brace blocks as distinct `namedInstances`, and the
map-reuse merge keeps both. Fail-on-revert covered by
`TestPrefixListMergeDuplicateBlocksFlatSet` /
`TestPrefixListMergeDuplicateBlocksHierarchical`
(`compiler_prefix_list_merge_2641_test.go`).

## apply-groups leaf-list UNION vs scalar OVERRIDE (#4070)

apply-groups inheritance (`pkg/config/ast_groups.go`, `mergeNodes`) is TYPED
the same way the schema classifies leaves — it is discriminated by the
statement KIND, not by AST shape:

- **Leaf-list** (`setSchema` `multi:true && children==nil` — name-server,
  domain-search, policy `match application` / `source-address` /
  `destination-address`, firewall `from protocol` / addresses, routing
  `export` / `import` chains, …): the group's members are inherited IN
  ADDITION to the inline members — **UNION**. Inline members keep precedence
  and order; group members not already present are appended in group order,
  deduplicated. Exactly ONE node results for the key.
- **Scalar leaf** (`host-name`, `domain-name`, …): the inline value
  **OVERRIDES** the group value (the explicit stanza wins via first-match
  ordering).
- **Unmodeled leaf** (not resolvable in `setSchema`): OVERRIDE — the safe,
  non-regressing fallback. As schema leaf-coverage grows, more statements
  gain the correct union behavior automatically.

**Why this is the Junos behavior.** apply-groups is Juniper's mechanism for a
common group to CONTRIBUTE statements to many objects; the canonical use is a
group adding a shared name-server list / export policy / match condition that
ADDs to per-object config (`show … | display inheritance` shows both). Junos
unions leaf-lists and only overrides scalars.

**What changed (the #4070 fix).** Before #4070 the merge keyed on AST SHAPE,
not statement type, so behavior was inconsistent: collapsed+collapsed
(`name-server 9.9.9.9` inheriting `name-server [ 1.1.1.1 2.2.2.2 ]`) OVERRODE
while block+block UNIONED. PR-A (#4325) first made the MIXED shape stop
emitting a duplicate leaf AND container for one key; this PR makes every
leaf-list UNION regardless of shape. The security-relevant symptom was
fable-164 L-8: an inline policy `match application junos-http` that inherited a
group's `match application junos-https` silently DROPPED junos-https, so a
`then deny` no longer denied junos-https. It now denies both.

**Migration note.** This changes apply-groups merge semantics: a config that
relied on the OLD collapsed-leaf-list override (inline replaces the group's
list) now UNIONs instead. This is Junos-parity-correct — a fix, not a break —
but an operator who was (perhaps unknowingly) depending on override to shrink an
inherited list must now scope the group narrower or not inherit it for that
object.

**Exclusions — token-packed / multi-token leaves OVERRIDE (not union).** The
`multi:true && children==nil` discriminator over-includes leaves that pack a
SEPARATOR/OPERATION keyword onto the value list, or that carry multiple tokens
per member. Token-level union would corrupt these, so they revert to the safe
pre-#4070 OVERRIDE. `isLeafListSchema` therefore requires `multi && children==nil
&& args<=1 && !groupReplace`:

- **`args<=1`** — a member must be a SINGLE token. An `args>=2` multi leaf packs
  multiple tokens per member: route-filter (`<prefix> <match-type>`),
  address-book `address <name> <prefix>`, policy-options `as-path <name>
  <regex>`, CoS `queue <n> <class>`. Unioning them token-flattens the members
  into one mashed leaf (`address net-a 10.0.0.0/24 net-b 10.0.1.0/24`). Excluded
  structurally — no per-leaf flag needed.
- **`!groupReplace`** — an `args<=1` leaf that packs a separator/operation
  keyword is opted out explicitly via the `schemaNode.groupReplace` flag:
  firewall/NAT `destination-port`/`source-port`(`-except`) carry a range `to`
  separator (`3000 to 4000`); merging two ranges yields `3000 to 4000 1000 2000`,
  a fail-OPEN matcher on a discard/reject term. policy-options `then community
  add|set|delete|none` packs an operation keyword, and `then as-path-prepend` is
  order+repetition sensitive — both are ACTIONS, not match-list members. A
  belt-and-braces `leafListCarriesRange` net (values containing `to`) blocks the
  union even if a range-bearing leaf is not flagged. `from community` (a MATCH
  leaf-list) still unions — the flag lives on the `then community` node, so the
  from/then keyword collision is resolved by schema CONTEXT, not by keyword.

**Implementation.** `mergeNodes(dst, src, ancestorPath)` threads the from-root
key path (the same `ancestorPath` `expandGroupsRecursive` already builds for
group-context walking). `isLeafListSchema(ancestorPath, key)` walks `setSchema`
down that path (reusing `resolveSchemaChild` + `consumeNodeKeys` for
args/compoundKey/wildcard descent) and returns true iff the leaf is
`multi && children==nil && args<=1 && !groupReplace`; `leafListUnionEligible`
adds the range-separator net. `mergeLeafListInto(dst, src)` reads both sides'
members via the #2419 dual-shape SSOT `firewallMatchValues` (Keys[1:] AND child
leaves), preserves the dst node's shape (collapsed leaf grows on Keys, block
container gains one child leaf per added member), and dedups. Scalar leaves and
multi-key hierarchical containers (`family inet` / `family inet6`) are never
unioned. Covered by `pkg/config/apply_groups_leaflist_test.go` (all four shape
combinations, flat-set + dedup, the L-8 policy-match compile-level union, and
scalar-still-overrides) plus the mixed-shape no-duplicate invariant from #4325.
The exclusions are covered by `pkg/config/apply_groups_leaflist_exclude_test.go`
(port-range override, `then community` / `then as-path-prepend` override, the
args>=2 `address` no-token-merge, and — the narrow-exclusion proof — firewall
`from protocol` in the same subtree STILL unions).

### Transitive (nested) apply-groups (#4474)

A group body may itself contain `apply-groups G2` — a NESTED-group template, a
standard Junos idiom where a group composes other groups (`grpA { apply-groups
grpB; }` applied at the top with `apply-groups grpA`). `grpB`'s content must be
inherited transitively.

Before #4474 this SILENTLY DROPPED `grpB`. `expandGroupsRecursive` captured the
top-level `applyNames` (`[grpA]`) BEFORE merging, merged `grpA`'s body — which
contains the `apply-groups grpB` leaf — into the top level, then stripped ALL
`apply-groups` nodes at that level before recursing. `grpB` was never in
`applyNames` and its merged-in reference was stripped, so a security zone or
policy authored behind `grpB` VANISHED with a CLEAN commit (config fail-open, a
HIGH-severity parity gap: a stanza the operator wrote is silently not enforced).

**The fix** expands each group's OWN `apply-groups` to a FIXED POINT before
merging its body. In `expandGroupsRecursive`, after cloning a group's
context-walked children (`srcChildren`), it recursively calls
`expandGroupsRecursive` on the clone (same `groups` map, same `ancestorPath`,
same `seen` set) so any nested `apply-groups` inside the group body are resolved
first; only then does `mergeNodes` splice the fully-expanded body into the
parent. This composes to arbitrary depth (`grpA -> grpB -> grpC`).

Cycles are fail-CLOSED: the existing `seen` circular-reference guard already
marks `name` before the pre-merge expansion, so `grpA -> grpB -> grpA` surfaces
the same `apply-groups circular reference` error as a direct self-cycle rather
than recursing forever — a rejected commit beats a silently-dropped zone.

**Bounding the fan-out (memoization).** The `seen` guard bounds only CYCLES, not
fan-out: `delete(seen, name)` runs per branch, so a group reached via N distinct
paths would be re-expanded N times. A converging DAG (a diamond lattice — each
level referencing the next via two edges) has 2^depth root->leaf paths, so the
naive fixed-point recursion is EXPONENTIAL (a machine-generated deep
nested-group DAG hung the synchronous commit for tens of seconds). The bound is
a `memo map[string][]*Node` threaded through the whole expansion, keyed by
`(group name, ancestor-context)` — the two inputs the expansion actually depends
on (`walkGroupToContext` and the nested-expansion context both use
`ancestorPath`; `tagInherited`/`vars` are constant per `ExpandGroups` call). A
completed memo entry is a fully-resolved, cycle-free body (a cyclic expansion
errors out BEFORE it is cached), so reusing it is always correct; a diamond
re-uses the memo instead of re-expanding, and `mergeNodes`'s same-key merge
still folds every path's copy to a single instance (count-once). The memo and
the cycle guard do not conflict — the guard tracks IN-PROGRESS recursion, the
memo tracks COMPLETED expansions. Because `mergeNodes` mutates its `src`
argument, the cache holds a pristine `cloneNodes` copy and every use (store and
reuse) is a fresh clone. Net cost is O(distinct groups x distinct contexts).

`| display inheritance` attribution stays correct: `tagNodesInherited(cloned,
name)` runs BEFORE the nested expansion, so it tags only the outer group's own
body; nodes contributed by the nested group are tagged by the recursive call
with THAT nested group's name (not the outer one). Covered by
`pkg/config/apply_groups_transitive_4474_test.go` (headline zone present,
outer-own-content-kept, three-deep chain, cycle-terminates, tagged inheritance
attribution, and a depth-22 converging diamond lattice that expands in
sub-millisecond memoized but times out / runs for tens of seconds un-memoized).

## `then community` operations: add / delete / set / none (#2848)

The policy-term action `then community` supports the Junos/vSRX community
operations in addition to the legacy bare replace form. Junos grammar is
`then community (add | delete | set) <community-name>` plus `then community none`;
the bare `then community <value>` is the historical whole-attribute replace and
stays valid for back-compat.

| Junos `then community ...` | xpf `CommunityOp` | FRR route-map set clause |
|----------------------------|-------------------|--------------------------|
| `add <value>`              | `add`             | `set community <value> additive` |
| `delete <name>`            | `delete`          | `set comm-list <name> delete`    |
| `delete [ <a> <b> ... ]`   | `delete`          | one `set comm-list <name> delete` PER list (#2902) |
| `set <value>`              | `set`             | `set community <value>`          |
| `<value>` (bare)           | `""`              | `set community <value>`          |
| `none`                     | `none`            | `set community none`             |

`add` APPENDS to (does not overwrite) the existing community attribute — the
parity gap that motivated #2848: emitting only `set community <value>` wiped
upstream-set communities, breaking community-based traffic engineering and tag
propagation in transit networks. `delete <name>` references a named
`policy-options community <name>` (which xpf already renders as a
`bgp community-list <name>`), so FRR's `set comm-list <name> delete` strips
exactly its members. `none` strips all communities.

**Multi-list delete (#2902):** `then community delete [ listA listB ]` references
MULTIPLE community-lists. FRR's `set comm-list <name> delete` strips ONE list per
line, so `PolicyTerm.CommunityDelete` is a `[]string`: the compiler accumulates
every name in `vals[1:]` (the lexer strips the brackets, so the clause flattens
to `delete listA listB` — the #2419 multi-value shape) and the renderer emits one
`set comm-list <name> delete` clause per list. The pre-#2902 code stored only
`vals[1]`, silently dropping `listB...` so the communities the operator meant to
strip leaked into advertised prefixes.

Schema (`schema_routing.go`): `then community` is a `multi: true` leaf that
packs the optional operation keyword plus the value onto one leaf's Keys
(`community add 65000:111`, `community none`, `community 65000:111`). The
compiler's `applyCommunityAction` (`compiler_routing.go`) reads every token via
the `firewallMatchValues` SSOT and interprets the first token: `add`/`delete`/
`set`/`none` select the operation, any other first token is a bare replace
value. Both AST shapes converge — `SetPath`/block parse both nest `then` as a
child node, so the hierarchical compile path is the one exercised; the flat
inline path carries belt-and-suspenders handling for the same forms.

Fail-on-revert: compiler-level
`TestPolicyCommunityOperationsCompile` and
`TestPolicyCommunityDeleteMultiListCompile` (`pkg/config/parser_security_test.go`)
and end-to-end `TestPolicyCommunityOperations` +
`TestPolicyCommunityDeleteMultiList` (`pkg/frr/frr_test.go`, full
ParseSetCommand + SetPath + CompileConfig + `generatePolicyOptions`).

## How to add a config-mode typed leaf

Edit the leaf's `schemaNode` in `setSchema` (in the domain's
`pkg/config/schema_<domain>.go` aspect file). Set:

```go
"transmit-rate": {
    args:          1,
    valueType:     ValueRate,                // placeholder + opt-in
    valueDesc:     "Bandwidth (e.g. 100k, 10m, 1g) ...",
    valueExamples: []string{"100k", "10m", "1g"},
    validator:     ValidateRate,             // commit-check
    children:      map[string]*schemaNode{   // modifiers ONLY if pre-existing
        "exact": {children: nil},
    },
},
```

Rules:

- **Range policy: runtime first, Junos second.** The binding bound is
  what the xpf runtime actually consumes — the narrowest binary encoding
  (e.g. `cluster-id` is one byte of the RETH virtual MAC;
  `reth-advertise-interval` must encode into the 12-bit VRRPv3
  centisecond field) or an explicit runtime clamp/ignore. Check the
  Junos vSRX range second and call out deliberate divergences in the
  annotation comment: xpf's own defaults sit OUTSIDE the Junos ranges
  for several chassis knobs (heartbeat-interval default 100 ms vs Junos
  1000..2000), and the killed #1319 Phase-3a plan copied Junos ranges
  blindly — it would have rejected deployed configs. **No schema-only
  caps** (Codex review, PR #1845): if the runtime accepts any value, use
  min-only semantics (`ValidateIntegerMin`) or the runtime-derived
  ceiling (`MaxDurationMillis` for millisecond knobs that convert to
  `time.Duration`); a sanity cap must be enforced in the runtime FIRST,
  never in the schema alone. Cite the source file:line for every bound
  next to the annotation.
- **Fields only, do not add a `children` map just to type a leaf.** SetPath's
  grouping keys on `children == nil` (`ast_edit.go:196`); flipping a leaf to
  a container changes flat-set grouping for existing configs. The
  `TestSetPathGrouping_Golden` test in
  `pkg/config/schema_validate_test.go` guards this.
- **Only type a leaf the compiler actually consumes.** Typing a leaf the
  compiler ignores would make `commit check` reject config the compiler
  would have silently dropped — a behaviour change beyond completion/
  validation. A leaf the compiler stores into a typed field but the
  dataplane cannot yet enforce is fine (accepted-but-inert) as long as a
  commit advisory flags the inertness — e.g. scheduler `buffer-size
  temporal` (#4228 Gap 2 follow-up) is now carried into
  `BufferSizeTemporalUS` with an advisory; what the rule forbids is typing a
  leaf that is silently dropped with no field and no advisory.
- **Validators live in `pkg/config/schema_validators.go`** and are stateless
  string-checkers reusing the compiler's parsers. Add a generic one
  (`ValidateInteger(min,max)`, `ValidateEnum([...])`, the IP family
  validators `ValidateIPAddress` / `ValidateIPv6Address` /
  `ValidateIPv4CIDR` / `ValidateIPv6CIDR` / `ValidatePREF64CIDR`)
  or a bespoke `ValidateX(raw string, cfg *Config) error`. **cfg is always
  nil in production** — both call sites run the gate BEFORE compile
  (`configstore.compileTree` / `compileTreeLenient`), so a validator must
  never depend on compiled state. Cross-reference validators use the
  TREE-based `treeValidator` field instead: `SchemaValidate` pre-collects
  referenceable definitions from the candidate tree into `schemaRefs`
  (`collectSchemaRefs`, e.g. the forwarding-class names) and hands them to
  the validator, so a definition + reference in the same commit validate
  atomically. The refs union includes group bodies (applied or not) so
  node-variable configs never false-reject.
- **Typed KEY slots (named-instance containers).** A container whose value
  is its IDENTITY token (`family inet address <cidr> { primary; }`) cannot
  use `valueType`/`validator` — that would flip the walker into the
  typed-LEAF branch and mis-validate the container's real block children.
  Set `keyValueType`/`keyValueDesc`/`keyValueExamples`/`keyValidator`
  instead: the walker validates the identity arg token(s) in both the
  packed-Keys and the nested instance-name shapes (both of which
  `namedInstances` compiles), and `?` completion surfaces the key
  placeholder + examples at the empty identity slot.
- **Multi value-tail leaves accept the block-list spelling.** A
  `multi && children == nil` typed leaf is compiled from BOTH the packed
  Keys (`name-server 1.1.1.1`, ranges with the `to` separator) and the
  hierarchical block list (`name-server { 1.1.1.1; 8.8.8.8; }`) — the
  walker's `validateMultiValueLeaf` validates each block child's FIRST
  token, exactly what the compilers read.
- **Whole-tail leaves (`tailValidator`) for irregular grammars.** A leaf
  whose value/modifier tail is heterogeneous — the first token is EITHER a
  value OR a keyword — cannot be validated token-by-token. CoS
  `transmit-rate (rate | percent <n> | remainder) [exact]` and `shaping-rate
  (rate | percent <n>)` are the cases (#4228 Gap 2). Set a `tailValidator`
  (leave `validator` nil); `keyword percent <n>` groups in flat-set as a
  container plus a child leaf while the hierarchical parser packs it onto one
  node's Keys, so the walker's `validateTailLeaf` gathers the whole tail with
  `gatherLeafTailTokens` (Keys[1:] plus every descendant leaf's Keys) and
  hands the flattened slice — plus the same-keyword sibling tails, so a
  split-set modifier-only line (`transmit-rate exact` beside `transmit-rate
  1g`) is still accepted — to the validator. `valueType` may still be set for
  `?` completion. The compiler reads the SAME tail via `gatherLeafTailTokens`
  (`parseCoSTransmitRate` / `parseCoSShapingRate`) so validation and
  compilation never drift. Percent/remainder are accepted-but-inert (see
  `docs/cos-traffic-shaping.md`).
- The generic walker (`schema_walk.go`) needs **no** changes per leaf — it
  descends `setSchema` and validates any typed leaf it finds. Walker rows it
  handles: container/args/compoundKey/midKeyword/wildcard, the standard
  typed leaf (first token is the value, remaining tokens must be known
  modifier children), the `multi && children == nil` value-tail/range shape
  (`destination-port 20000 to 20003`, rejecting dangling/all-separator
  tails), and the cross-sibling modifier-only line (`transmit-rate exact`
  valid only when a sibling leaf supplies the rate).
- **Compiler-faithful rule (important).** The walker validates typed leaves
  exactly where the per-subsystem compiler reads them. For a named-instance
  container (e.g. `class-of-service schedulers <name> { ... }`) the compiler
  reads leaves from the instance node's CHILDREN; tokens packed into the
  instance node's own Keys beyond the name are NOT compiled, so the walker
  ignores them — it never validates, nor mis-attributes block children to,
  such packed tokens. This means malformed shorthand the compiler silently
  discards (e.g. `schedulers be transmit-rate asd` as a single node with no
  children) is intentionally NOT rejected: rejecting config the compiler
  ignores is a behaviour change beyond #1319's compiled-leaf-only scope. The
  real symptom-2 path — `set class-of-service schedulers be transmit-rate
  asd` — lands the leaf as a CHILD, where it IS compiled and IS rejected.
  This contract was converged across 7 hostile Codex review rounds; do not
  re-add packed-tail validation without re-checking compiler reachability.

## Help-text discipline (#1892)

Every `schemaNode` in `setSchema` MUST carry a `desc:` — an empty desc
renders as a blank line in `?` completion across all three frontends.
The #1892 audit filled all 493 previously-empty nodes; do not add new
nodes without one. Rules:

- **Verified behavior only.** A wrong help text is worse than a missing
  one. Write the desc from the compiler/runtime consumer, not from what
  the keyword sounds like. Containers get structural descs ("Source NAT
  configuration"); behavior-bearing leaves state what the consumer does,
  with enum values / units / defaults in parens ONLY when read from
  code (model: `claim-host-tunables` — "Allow xpfd to write host-scope
  tunables (true|false, default false)").
- **desc / placeholder are display-only.** They never affect SetPath
  grouping, so help fixes are always grouping-safe. Structure fields
  (`args`, `children`, `wildcard`, `multi`) are NOT — see the typed-leaf
  rules above.
- **`groups <*>` mirrors the top level by pointer** (`init()` in
  `schema.go`), so a top-level desc automatically documents the same
  path under `groups <name> ...`. Never duplicate nodes to add help.

## Retired knobs (#1525 / #1892)

Retired DPDK-era `system dataplane` knobs — `cores`, `memory`,
`socket-mem`, `rx-mode {idle-threshold, resume-threshold,
sleep-timeout}`, `ports <name> {interface, rx-mode, cores}` — remain
parseable for stored-config compatibility (a stanza that committed once
must never stop loading), but have NO consumer:
`compileUserspaceDataplane` records them in
`UserspaceConfig.RetiredKnobsSeen` and `userspaceRetiredKnobWarnings`
emits a per-knob commit warning ("retired DPDK-era knob (#1525),
accepted for config compatibility but ignored") on both the strict and
lenient compile paths. Their schema descs say "(retired, ignored)" so
completion stops advertising them as live. Follow this pattern —
keep-parsing + warn + honest desc — when retiring any future knob;
hard-reject (the `dataplane-type dpdk` / `ebpf` sentinel errors) is
reserved for whole-dataplane selection where a rewrite shim
(`rewriteRetiredDataplaneType`) protects stored configs.

## Rollout (#1319)

- **PR 1 (merged, #1682):** moved `ValueType` to `pkg/config`; added the
  typed fields to `schemaNode`; wired typed-value `?` completion into
  `CompleteSetPathWithValues`; replaced the schedulers-only hand-rolled
  walker + class-of-service early-return with the generic
  `config.SchemaValidate` walker; re-homed the schedulers typed leaves onto
  `setSchema`; retired the cmdtree config-mode overlay. 3 typed leaves
  (schedulers transmit-rate / priority / buffer-size).
- **PR 2 (this work, chassis cluster):** downgraded the gate to a warning
  on the tolerant Load/SyncApply paths (boot safety — PR 1 had wired it
  strict there too); typed 13 chassis-cluster leaves (cluster-id, node,
  reth-count, heartbeat-interval/-threshold, reth-advertise-interval,
  takeover-hold-time, peer-fencing, RG node priority,
  gratuitous-arp-count, ip-monitoring global-weight / global-threshold /
  target weight) with runtime-derived, source-cited ranges. Deliberately
  NOT typed, with reasons in the `schema_chassis.go` comments: the
  `redundancy-group <id>` / RG-scoped `node <id>` instance-name slots
  (the walker's compiler-faithful contract consumes identity tokens
  without validation — typing them needs a new walker feature; note
  #4434 added a *semantic* commit-time cap on redundancy-group
  cardinality and id — `validateChassisClusterStrict` in
  `compiler_validate_strict.go`'s sibling
  `compiler_validate_strict_chassis.go` — because the HA heartbeat wire
  encodes both the group COUNT and each GroupID as a single byte
  (`pkg/cluster/heartbeat.go`): >255 groups wrap the count byte to 0 and
  desync the wire, an id >255 truncates and collides. That gate runs on
  the compiled `*Config`, NOT through the schema walker, so it does not
  change the identity-token typing decision above),
  `interface-monitor <if> weight <n>` (tokens pack inline into a
  `children==nil` leaf; typing the weight needs a children map, which
  would flip SetPath grouping), `control-ports` (not compiled), and the
  address/interface string leaves (IP value types arrive with the
  interfaces PR). Known residual: the hierarchical packed one-liner
  `node 0 priority <v>;` bypasses the gate (identity-token rule) even
  though `compileChassis` reads its inline tokens — pinned by
  `TestSchemaValidate_ChassisCluster_PackedOneLinerBypassesGate`.
- **PR 3 (this work):** the remaining converged-plan sections in one PR —
  (a) **interfaces**: `ValueIPAddress`/`ValueCIDR` value types, the typed
  KEY-slot walker feature, and 16 typed slots (mtu ×3, vlan-id,
  inner-vlan-id, family inet/inet6 `address` CIDR key slots, vrrp-group
  priority / advertise-interval / virtual-address, tunnel
  source/destination/ttl/key, wireguard listen-port /
  persistent-keepalive). **#2384 — IPv6 VRRP:** the `vrrp-group <id>`
  subtree now exists under **both** family `inet` and family `inet6`
  (built by the shared `vrrpGroupSchemaNode(v6 bool)` helper in
  `schema_interfaces.go`, parsed by the shared `parseVRRPGroups` helper in
  `compiler_interfaces.go` from both family arms). The only difference is
  the `virtual-address` validator: `ValidateIPv4CIDR` under `inet`,
  `ValidateIPv6CIDR` under `inet6` — so a v6 VIP commits cleanly under
  `inet6` and is rejected under `inet` (and vice versa). The native VRRP
  engine already family-detects each VIP at parse (`ip.To4()==nil`,
  `pkg/vrrp/instance.go`), so no runtime change was needed. Compiled
  groups are keyed `<address-CIDR>_grp<id>`, so a dual-stack unit may
  carry an `inet` AND an `inet6` vrrp-group with the SAME group id without
  collision (the address strings differ → two distinct
  `unit.VRRPGroups` entries). **#4573 — VRRP VRID range gate:** the
  `vrrp-group <id>` instance-name slot stays an unvalidated identity
  token in the schema (same deferral class as `redundancy-group <id>`),
  but a *semantic* commit-time cap now bounds it —
  `validateVRRPGroupIDStrict` in `compiler_validate_strict_vrrp.go`,
  the exact sibling of the chassis `validateChassisClusterStrict`
  (#4434). The VRRP VRID is a single wire byte (RFC 5798 §5.2.3, valid
  range 1..255): the native engine truncates the configured id onto it
  (`uint8(vi.cfg.GroupID)`, `pkg/vrrp/instance.go`), so `vrrp-group 256`
  wrapped to the RESERVED VRID 0 (a strict RFC peer such as Juniper
  discards the advert → the VIP never masters → HA cold-boot blackhole)
  and 257 aliased VRID 1 onto an unrelated group. Non-numeric garbage was
  always dropped by `parseVRRPGroups`, but an out-of-range NUMERIC id
  used to produce a live wrong-VRID instance — that asymmetry is closed.
  Like the #4434 gate it runs on the compiled `*Config`, NOT the schema
  walker (so it does not change the identity-token typing decision), and
  the tolerant load / peer-sync path downgrades it to a warning
  (`lenientVRRPGroupID`, #1960 no-brick) with a defensive runtime range
  check at instance creation (`pkg/vrrp` `MinVRID`/`MaxVRID`,
  `manager.go UpdateInstances`) that refuses to advertise an
  out-of-range VRID for a value that slips through the lenient path.
  B-002 companion: the `priority`/`preempt hold-time`/`advertise-interval`
  parse in `parseVRRPGroups` no longer swallows an `strconv.Atoi` error
  with `_ =` — a bad parse kept the constructor default (priority 100)
  instead of silently resetting to 0 (the RFC 5798 resignation value).
  **#4826 — reth-derived VRID range gate:** #4573 only bounded the
  *explicit* `vrrp-group <id>` slot; a RETH interface's VRRP GroupID is
  separately synthesized as `100 + redundancy-group-id`
  (`CollectRethInstances`, `pkg/vrrp/vrrp.go`), and that path had no
  commit-time bound at all. The chassis `redundancy-group <id>` gate
  (#4434, `validateChassisClusterStrict`) caps the id at 255 — the
  single-byte HA *heartbeat* wire limit, unrelated to VRRP — so a
  redundancy-group in 156..255 committed cleanly while its derived VRID
  (256..355) silently lost VRRP at runtime (`pkg/vrrp/manager.go
  UpdateInstances` skips the out-of-range GroupID with only a WARN log —
  no wrong-VRID advert on the wire, but a live HA blackhole for that
  redundancy group). `validateRethVRRPGroupIDStrict`
  (`compiler_validate_strict_reth_vrrp.go`) closes the gap the same way
  #4573 closed it for the explicit path: hard-reject a
  `redundant-ether-options redundancy-group <id>` above 155 at commit /
  commit-check, downgraded to a warning on the tolerant load / peer-sync
  path (`lenientRethVRRPGroupID`, #1960 no-brick). It mirrors
  `CollectRethInstances`' own early return for `no-reth-vrrp` /
  private-rg-election (the compiler default for any `chassis cluster`
  stanza) so a redundancy-group id that produces no synthesized VRRP
  instance is never rejected. `pkg/config` cannot import `pkg/vrrp` (the
  dependency runs the other way), so the `100` offset is a documented
  duplicated constant (`RethVRRPGroupIDBase`), not an import.
  **#2850 — `preempt hold-time`:** the
  `vrrp-group <id> preempt` leaf gained a nested `hold-time <seconds>`
  child (`schema_interfaces.go`, typed `ValidateInteger(1, 3600)`), Junos
  `set interfaces <if> unit <n> family inet vrrp-group <id> preempt
  { hold-time <s>; }`. It compiles to `VRRPGroup.PreemptHoldTime`
  (seconds; `compiler_interfaces.go` parses both the braced child and the
  flat-set `preempt hold-time <n>` Keys-run), plumbed to
  `vrrp.Instance.PreemptHoldTime`. Bare `preempt` (no hold-time) keeps
  PreemptHoldTime 0 = immediate preemption (unchanged). At runtime a
  higher-priority backup reclaiming mastership from a STILL-LIVE
  lower-priority master defers the takeover by hold-time seconds (so
  dynamic routing converges before failback); a dead/silent master or a
  graceful priority-0 resignation is never delayed
  (`pkg/vrrp/instance.go` `preemptHoldDuration` /
  `preemptingLiveLowerMaster`). **#2900 — armed-hold re-validation:** an
  armed hold is re-validated at two points the original #2850 arming did
  not cover. (1) At expiry, before promoting, the hold-elapsed case re-runs
  `shouldPreemptObservedMaster` (the same RFC 5798 §6.4.2 gate the
  force/sync-hold path uses): preemption must still be enabled AND, while a
  live master is still present, our effective priority must still be
  strictly higher than its last advert. If preempt was disabled or our
  priority was demoted below the live master (track-interface link-down)
  during the hold, the node does NOT take over — it returns to a normal
  BACKUP tenure by re-arming `masterDownTimer`. A master that went silent
  during the hold reads as stale and still triggers a dead-master takeover.
  (2) `updateConfig` (manager goroutine) signals the run loop via
  `configUpdatedCh` after mutating cfg; the BACKUP select tears any in-flight
  hold down (`disarmPreemptHold`) and re-arms `masterDownTimer`, so the next
  expiry re-evaluates against the fresh config — a changed `hold-time` arms
  the NEXT countdown with the new duration, and a disabled preempt /
  demotion no longer fires a spurious takeover at the old expiry. All
  `preemptHoldTimer` Stop/Reset calls stay on the single run-loop goroutine;
  `preemptHoldArmed` (mu-guarded) tracks the armed state across the two
  goroutines. The WireGuard `peer` node is a NAMED-INSTANCE
  container keyed by the peer public key (#1434 multi-peer):
  `set interfaces <wg> tunnel wireguard peer <public-key>
  { allowed-ips <cidr>; endpoint <ip:port>; persistent-keepalive <s>;
  preshared-key <hex>; }`. A WG interface may terminate N peers on one
  listen port; the pubkey is the instance identity (modeled on
  `vrrp-group <id>`, dual-AST via `namedInstances`). A commit-time gate
  (`validateWireguardPeersStrict`, `compiler_validate_wireguard.go`)
  hard-rejects a WG tunnel with a missing/invalid LOCAL identity (#3863)
  — a `listen-port` not in `[1,65535]` (the Rust `hydrate_wg_identity`
  drops a row whose `wg_listen_port` is 0, and `parseTunnelWireguard`
  collapses a missing/0/out-of-range listen-port to 0), or a
  `private-key` that is not exactly 64 hex chars / 32-byte X25519 (the
  Rust `decode_wg_key_hex` drops a row whose private key does not
  decode). Without this gate a bad local identity COMMITTED CLEAN and the
  dataplane then silently dropped the WHOLE tunnel row — a permanent VPN
  outage with no diagnostic. The listen-port VALUE bound is also enforced
  at the schema layer (`ValidateInteger(1,65535)`), but that runs only on
  the author path and cannot see a MISSING leaf; the private-key has NO
  schema value validator, so the compiler gate is the universal chokepoint
  every compile/load/HA-sync path funnels through. The gate also
  hard-rejects a WG tunnel with zero peers, a duplicate or malformed
  (non-64-hex) peer pubkey, a malformed preshared-key,
  endpoint-bearing peers that disagree on outer transport family (one
  UDP socket = one outer family), or an EXACT-duplicate `allowed-ips`
  prefix across two peers (#2445 — the cryptokey routing table maps a
  prefix to exactly one peer, so an exact tie has no longest-prefix
  winner and the engine LPM resolves it by insertion order, silently
  blackholing the loser; the check canonicalizes each CIDR to its masked
  network so `10.0.0.5/24` and `10.0.0.0/24` collide, while a
  broader/narrower OVERLAP — a `0.0.0.0/0` catch-all peer plus a
  more-specific peer — stays valid because LPM resolves it
  deterministically); the tolerant load / peer-sync path
  (`lenientWireguardPeers`) downgrades these to warnings so an
  already-persisted or peer-synced config still boots (#1960). The
  compiler sorts `WgPeers` by pubkey at the snapshot-builder boundary so
  both HA nodes serialize byte-identical snapshots. The pubkey is
  lowercased at parse so the canonical form drives the dedup key, the
  wire bytes, and the documented "64-char lowercase hex" contract
  together (a `AA..`/`aa..` pair collides at commit instead of orphaning
  a peer in the engine's release-build reconcile). **Syntax-migration
  note:** the pre-#1434 leaf form `peer { public-key <key>; ... }`
  (#1432 S2a) is NOT auto-migrated to the named-instance form `peer
  <key> { ... }`. There is no production persisted old-form WG config
  (WG was experimental and live interop is deferred to #1703), but an
  old-form config reloaded leniently parses the literal token
  `public-key` as a bogus peer name, fails the hex validator, and
  downgrades to a load-time warning — fail-safe (no brick, #1960), but
  the tunnel silently loses its real peer until re-authored in the new
  syntax. (b) **firewall**:
  the `then forwarding-class`
  tree-based cross-ref for both families (dangling references reject at
  commit; same-commit definition + reference passes; `best-effort` is
  always resolvable; the other Junos default classes are deliberately NOT
  implicit — xpf's runtime does not define them); (c) **system/services**:
  22 typed slots (name-server, ssh root-login enum, ssh key-exchange
  multi-value list (H5/#2008; renders to sshd `KexAlgorithms` —
  `pkg/daemon/daemon_system.go` `buildSSHDConfig`; left untyped/no enum
  because sshd validates the algorithm spellings at reload), the dataplane
  workers/ring-entries/poll-mode/rss-indirection/claim-host-tunables/
  netdev-budget/coalescence knobs, the rpm probe knobs, ip-monitoring
  hold-down / preferred-metric) plus the `validateMultiValueLeaf`
  block-list walker extension the deployed `name-server { 1.1.1.1; }`
  shape requires. Deliberately untyped, with reasons in
  `schema_system.go` / `schema_interfaces.go`:
  `unit <n>` / `vrrp-group <id>` instance ids (cross-referenced from other
  subsystems — one dedicated pass later), `track-interface priority-cost`
  (#1814 pre-walk owns it), `cpu-governor` (pass-through by design), dhcp
  client knobs, tunnel keepalives.
- **#2524 (ring-entries bound):** `system dataplane ring-entries` was
  min-only (`ValidateIntegerMin(1)`) — any large value committed and was
  handed to the Rust helper, which preallocates ~3×ring_entries UMEM frames
  per binding (~96 MB/binding at ring_entries=8192), so an out-of-range
  value OOM'd at bring-up instead of failing as a clean commit error. The
  leaf now uses `ValidateRingEntries`: bounded `[1..MaxRingEntries]`
  (`MaxRingEntries = 16384`) AND required power-of-two (the helper rounds
  ring sizes up to a power of two, so the configured number stays honest
  about the depth allocated). A matching helper-side backstop clamps at
  bring-up (`afxdp::MAX_RING_ENTRIES`,
  `coordinator/reconcile/bringup.rs`) and rejects out-of-range /
  non-power-of-two values at the `--ring-entries` CLI boundary
  (`server/lifecycle.rs validate_ring_entries_arg`). Go and Rust ceilings
  must stay equal.
- **#4572 (workers zero-init loop backstop):** `system dataplane workers`
  is the sibling min-only (`ValidateIntegerMin(1)`) leaf, and its runtime
  ceiling is "owned by the runtime" (schema comment) rather than a strict
  upper bound. `programBootstrapMapsLocked` zero-inits the
  `userspace_heartbeat` Array (`Array<u64>`, `max_entries = 4096`) with
  `slot < uint32(cfg.Workers)*2*16`. The **negative** case the issue
  headlines (`workers -1` → `uint32(-1)*32 = 4,294,967,264` iterations) is
  already defended one layer up: `deriveUserspaceConfig` (capabilities.go)
  coerces `workers<=0 -> 1` before the value ever reaches the loop. The
  **live** exposure is a large **positive** value: strict commit ACCEPTS it
  (min-only validator) and `deriveUserspaceConfig` does not cap the upper
  side, so `workers 999999999` reaches the loop and
  `uint32(999999999)*32` wraps `uint32` to ~1.9B iterations of
  `heartbeatMap.Update` — an apply/commit hang for hours (a control-plane
  DoS, not a fail-open). The Go side now clamps once
  (`workers := maxInt(cfg.Workers, 1)`, mirroring the adjacent `QueueCount`
  / disabled-ctrl coercions) for the `userspace_ctrl` fields, and the
  heartbeat zero-init loop bound is computed by
  `heartbeatZeroSlots(cfg.Workers, heartbeatMap.MaxEntries())`
  (`pkg/dataplane/userspace/maps_sync.go`): it clamps the worker count into
  `[1, mapCap/heartbeatSlotsPerWorker]` so neither a negative nor an absurd
  positive worker count can make the loop wrap `uint32` or index past the
  fixed-size Array. This is the "lenient WARN-not-hang" contract applied at
  the runtime consumer.
- **#1746:** added the `class-of-service schedulers <s>
  equal-flow-target-policy (slowest | mean | ideal-share)` typed enum
  leaf (ValueEnumOf + `ValidateEnum`, same recipe as the scheduler
  `priority` leaf): value-slot completion, flat-set commit-check
  rejection of unknown values, plus a strict-compile re-check
  (`validateClassOfServiceStrict`) for externally-assembled configs.
- **#2458 (Rust fail-closed backstop):** the helper-side
  `EqualFlowTargetPolicy::parse` previously mapped any unrecognized
  wire string to `Slowest` via a catch-all match arm — identically to
  the empty (legacy/unset) string — so a typo or a mixed-version
  snapshot that slipped past the Go gate silently changed queue
  fairness with no failure surfaced. The parse is now fallible: the
  EMPTY string still decodes to the byte-unchanged `Slowest` default,
  but a NON-EMPTY unknown value fails the snapshot CLOSED with
  `SnapshotIntegrityError::CosUnknownEqualFlowTargetPolicy` naming the
  offending forwarding-class and value (preflight keeps the previous
  live CoS state). The Go commit-time gate above stays the PRIMARY
  defense; this is the helper-boundary backstop against version /
  snapshot drift, consistent with the #2447 CoS fail-closed family.
- **scheduler-map dangling `scheduler` reference (strict commit +
  Rust safe default):** a `scheduler-map <m> forwarding-class <fc>
  scheduler <name>` entry naming a scheduler that is NOT defined under
  `class-of-service schedulers` was previously WARN-only at commit
  (`ValidateConfig`) and then FAIL-OPEN in the helper: the per-queue
  builder (`userspace-dp forwarding_build/cos.rs`) resolved the dangling
  name to `None`, left `guarantee_enabled` false, set the queue's
  transmit rate to the WHOLE interface shaping rate, and derived the
  MAXIMUM surplus weight (16). So a premium class (e.g. `ef`) whose
  scheduler name was a typo did not merely lose its guarantee — it
  silently won the LARGEST best-effort surplus share, invisible outside
  the runtime queue rows. `validateClassOfServiceSchedulerMapRefsStrict`
  (`compiler_validate_strict.go`) now HARD-REJECTS the dangling
  reference at strict commit / commit-check, mirroring
  `validatePolicySchedulerReferencesStrict` (the policy → scheduler
  sibling) and Junos, which rejects an unresolved scheduler reference.
  The call site downgrades it to a `cfg.Warnings` entry on the tolerant
  load / peer-sync paths (`lenientSchedulerMapRef`, #1960 no-brick) so a
  config persisted by an older binary — which only warned — still boots.
  The helper-side backstop keeps that leniently-loaded reference
  fail-SAFE rather than fail-OPEN: an UNRESOLVED scheduler pins the
  queue to the minimal best-effort surplus weight (1) instead of the
  whole-interface-rate maximum, while KEEPING the queue materialized
  under its real queue id / forwarding-class (dropping the entry — the
  undefined-forwarding-class treatment — would blackhole any traffic a
  classifier steers to the class's queue). `guarantee_enabled` stays
  false and priority stays `low`, so no guarantee or priority is
  fabricated. A DEFINED scheduler that merely omits `transmit-rate` is
  unchanged (it keeps `surplus_weight = 16`). The redundant
  `ValidateConfig` scheduler warn was removed (single SSOT), consistent
  with every other cross-reference gate. Coverage:
  `TestSchedulerMapDanglingSchedulerRejectedStrict` (strict reject +
  lenient downgrade + valid-scheduler control, `pkg/config`) and
  `build_cos_state_dangling_scheduler_reference_uses_safe_best_effort_default`
  (`userspace-dp forwarding_build/tests.rs`).
- **BA classifier code-point → unmaterialized queue (commit warn + Rust
  safe default, #hb166 T-4):** a DSCP / IEEE-802.1p classifier code-point
  that maps to a forwarding-class whose queue the interface does NOT
  materialize (the forwarding-class has no `scheduler-map` entry on that
  interface, and the interface is still admitted to CoS via shaping or
  another materialized code-point) was a 100% SILENT BLACKHOLE: the
  per-interface classifier table (`build_cos_dscp_queue_table` /
  `build_cos_ieee8021_queue_table`, `userspace-dp forwarding_build/cos.rs`)
  copied the unmaterialized queue id verbatim, `resolve_cos_queue_idx`
  (`tx/cos_classify.rs`) found no such queue and returned `None`, and the
  enqueue path turned that into a drop — while the config committed
  cleanly. The helper now fails SAFE: the build-time table substitutes the
  interface default (best-effort) queue for any code-point whose queue is
  not in the interface's materialized set, and `resolve_cos_queue_idx`
  carries a matching runtime fallback (unmaterialized requested queue →
  default queue). The commit path emits an operator WARNING
  (`classOfServiceClassifierQueueWarnings`, `compiler_validate_warn.go`)
  naming the forwarding-class and queue that has no scheduler-map entry on
  the interface. Unlike the dangling-SCHEDULER case above this is a WARN,
  NOT a strict reject: a classifier steering to a forwarding-class that
  merely lacks a scheduler-map entry is a VALID Junos config (all queues
  exist by default in Junos regardless of scheduler-map), so a hard reject
  would refuse configs Junos accepts and configs the xpf test suite already
  asserts compile (`TestCompileClassOfServiceHierarchicalDSCPClassifier`).
  The commit warn fires iff the dataplane would have blackholed — its
  materialization + admission model mirrors `build_cos_iface_config`
  exactly. Coverage: `TestHB166_T4_ClassifierUnmaterializedQueue_Warns` /
  `TestHB166_T4_ClassifierMaterializedQueue_NoWarn` (`pkg/config`),
  `build_cos_state_classifier_unmaterialized_queue_falls_back_to_default`
  and `resolve_cos_queue_idx_falls_back_to_default_on_explicit_queue_miss`
  (`userspace-dp`).
- **#1956 (chassis device-map):** added the bare-metal stable-identity
  managed allowlist under `chassis device-map` (a SIBLING of `cluster`, so
  per-node apply-groups compose). New value types `ValuePCIAddr` /
  `ValueMAC` with `ValidatePCIAddr` (canonical `DDDD:BB:DD.F`) /
  `ValidateMAC` (6-octet unicast, non-zero); a named-instance
  `interface <logical-name>` container using the typed-KEY-slot recipe
  (`keyValueType` + `ValidateDeviceMapLogicalName`) carrying typed `pci` /
  `mac` / `key` leaves; and the `unmapped-interface-policy` enum leaf
  (`leave-alone` default / `manage-down`). Compile lives in
  `compiler_chassis.go` (`compileDeviceMap`), independent of `cluster`
  (`compileChassis` compiles the device-map subtree even with no cluster —
  a standalone box). Cross-entry invariants that a single typed-leaf
  validator cannot express (duplicate logical name / PCI / MAC FATAL,
  RETH-member-must-be-PCI, FPC/node alignment in cluster mode) live in
  `validateDeviceMapStrict`, wired into the strict accumulator group in
  `compiler.go` and DOWNGRADED to a warning on the lenient load / peer-sync
  paths via the `lenientDeviceMap` compile opt (so a peer-node section with
  different hardware does not stall config sync — #1956 V-1). Device-map
  MODE is selected on `len(Entries) > 0`, never `DeviceMap != nil`, so an
  empty `device-map {}` block is positional mode (closes the
  empty-tree-compiles-non-nil trap). The pure identity resolver +
  host-NIC enumeration live in `pkg/devicemap` (shared by the daemon rename
  / pre-flight and the CLI `show`).
- **#2008 (Tier-1.5 schema-hardening sweep):** declared typed children on
  five subtrees whose leaves were fully parsed + compiled + honored at
  runtime but whose `setSchema` node carried `children: nil`, so the gate
  skipped them and an invalid value committed silently:
  - `security log stream transport` — `protocol` (enum `udp|tcp|tls`,
    matching the `pkg/logging/syslog.go` dial switch) + `tls-profile`.
    - **#3350 (tls-profile reject):** `transport tls-profile <name>` is
      parsed/stored but was NEVER resolved into a `*tls.Config` at runtime
      (`daemon_system.go` applyLogStreams passes a nil `*tls.Config`, and
      there is no TLS profile definition stanza — cert / trusted-ca / SNI —
      to resolve it to; only IPsec/IKE define certs). A TLS syslog stream
      therefore silently used the system CA roots instead of the named
      profile — a secure-syslog posture silently downgraded (fail-open). It
      is now REJECTED at commit by `validateSecurityLogStreamTLSProfileAST`
      (compiler.go), the strict-reject + lenient-downgrade (#1960/#3261)
      AST-gate pattern shared with the #3349 stream-port gate (the token
      lives under the `transport` block, a location SchemaValidate cannot
      express, so it is gated in the compiler not setSchema). A plain
      `transport protocol tls` stream that trusts the system CA roots stays
      valid; only the named-but-unapplied profile is rejected. If profile
      resolution is implemented later, build the `*tls.Config` in
      `daemon_system.go` and lift the compiler reject.
  - IKE (`security ike proposal`) and IPsec (`security ipsec proposal`)
    crypto leaves — `authentication-method` (IKE only, enum
    `pre-shared-keys|rsa-signatures|ecdsa-signatures`, matching
    `authMethodToSwan`), `dh-group`, and `lifetime-seconds`
    (`ValidateIntegerMin(1)` — 0/garbage previously silently compiled to
    0). Both `dh-group` leaves use `ValueDHGroup` + `ValidateDHGroup` and
    accept the bare-integer (`14`) and the Junos `group<N>` (`group14`)
    spellings identically (#2639):
    - IKE `dh-group` — the IKE compiler loop (`compiler_ipsec.go`
      `compileIKE`) strips a leading `group` prefix before `strconv.Atoi`.
    - IPsec Phase-2 `dh-group` — the Phase-2 compiler loop (`compileIPsec`)
      ALSO strips the `group` prefix, via the shared `parseDHGroup` helper
      that both loops (and the PFS `keys` stanza) now call. Before #2639
      the Phase-2 loop used a bare `strconv.Atoi` that left `group14` at
      `DHGroup=0`, silently dropping the PFS/modp term from the ESP
      proposal; the schema deliberately rejected the prefixed spelling to
      stay compiler-faithful. The compiler fix makes both gates accept
      `group<N>`, and the shared helper keeps the two sites from drifting
      again. The validator still rejects 0/garbage that would drop the
      modp/ecp term.
    `protocol` and `encryption-algorithm` / `authentication-algorithm` stay
    UNTYPED: the swanctl renderer normalizes arbitrary algorithm spellings
    by string substitution, so an enum there would false-reject valid
    configs.
  - **#3896 (IKE negotiation-mode / version / NAT-T enums):** the IKE
    gateway `version`, IKE policy `mode`, and gateway `nat-traversal` leaves
    were untyped free-form (`args:1`, no validator) in BOTH the `ike` and
    `ipsec` stanza copies of the gateway schema, so a typo committed clean and
    was then silently mis-mapped by the swanctl generator — a MEDIUM security
    footgun (silent negotiation weakening):
    - `version` — `ValidateEnum([v1-only, v2-only])`. `pkg/ipsec/policy.go`
      emits `version = 2` for `v2-only` and `version = 1` for `v1-only`; any
      OTHER spelling emits no `version` line, so a `v2-onyl` typo dropped the
      v2-only pin and the gateway silently accepted legacy IKEv1 (a downgrade).
    - `mode` — `ValidateEnum([main, aggressive])`. `pkg/ipsec/ike.go`
      `resolveIKESettings` sets `aggressive = (Mode == "aggressive")`; every
      other spelling (including a `agressive` typo) fell back to main mode.
    - `nat-traversal` — `ValidateEnum([enable, disable, force])`. The
      `pkg/ipsec/policy.go` switch maps `disable`→`encap = no`,
      `force`→`forceencaps = yes`, and default (`enable`/empty)→auto-detect;
      an unrecognized value silently took the auto-detect default.

    The accepted sets are EXACTLY the generator-recognized values (a value the
    generator handles but the enum omitted would be a false-reject regression).
    A typo is now rejected at commit with an error naming the bad value.
  - **#2404 (responder-only / dynamic-IP peer):** the `security ike gateway
    <g> dynamic` node now declares a `hostname <fqdn>` child (it was a
    `children: nil` leaf in both the `ike` and `ipsec` stanza copies of the
    gateway schema). The semantics: `dynamic hostname <fqdn>` is a peer with
    a dynamic IP but a resolvable DNS name (renders `remote_addrs = <fqdn>`,
    unchanged); a BARE `dynamic` block — no address, no hostname — marks a
    responder-only peer that dials in from an unknown source address. The
    compiler (`compileIKE` / `compileIPsec`) sets `IPsecGateway.ResponderOnly`
    when the `dynamic` block resolves no hostname; the strict commit-time
    validator (`validateIPsecGatewayReferencesStrict`) accepts such a gateway
    instead of rejecting it as addressless; and the swanctl render
    (`resolveRemoteAddr`, `pkg/ipsec/policy.go`) emits `remote_addrs = %any`
    so strongSwan listens for the inbound IKE rather than skipping the
    connection. `local-address` (or `external-interface`) still pins the
    local endpoint as usual.
  - `security nat static rule-set rule match` — declared the
    `source-address` / `destination-address` children the static-NAT
    compiler reads (the subtree was previously unreachable by the walker).
    #2491 added `match destination-port` as a typed `ValueInteger`
    (1..65535) leaf: it is the external (pre-translation) port a
    port-mapped static-NAT rule matches on. The companion
    `then static-nat prefix <ip> mapped-port <port>` carries the internal
    (post-translation) port. `static-nat` deliberately stays a
    `children: nil` free-form leaf (so `prefix <ip> mapped-port <port>`,
    `prefix-name <addr>` (#4290), and a trailing
    `... routing-instance <ri>` (#4292) all collapse onto ONE leaf node and
    SetPath grouping is preserved); the
    `mapped-port` token therefore bypasses the schema value validator and
    is range-checked in the compiler (`validateNATHostMaskStrict`,
    `compiler_nat.go`), which ALSO rejects a `mapped-port` with no
    matching `match destination-port` (the reverse SNAT could not recover
    the original port) AND the mirror half-config — a `match
    destination-port` with no `mapped-port` (#2769). The port-match-without-
    mapped-port form is a port-scoped 1:1 (no port translation); rejecting
    it at strict commit-check forces the operator to either drop the port
    match (a whole-address 1:1) or add a `mapped-port` (a port forward). If
    such a rule slips through the lenient load / peer-sync path, the Rust
    dataplane backstop (`static_nat.rs from_snapshots`) keys the reverse
    SNAT on `(internal_ip, Some(match_dst_port))` rather than
    `(internal_ip, None)`, keeping the source translation scoped to the one
    matched port instead of broadening it to every source port on the
    internal host. The snapshot fields `match_destination_port` /
    `mapped_port` (`StaticNATRuleSnapshot`, both Go `omitempty` + Rust
    `#[serde(default)]`, default 0) are an additive, backward-compatible
    wire change; a single external IP can host several per-port mappings
    plus a port-less whole-address 1:1 rule (the dataplane keys the
    static-NAT tables by `(IP, Option<port>)` and falls back to the
    port-less entry).
  - `security nat source/destination rule-set rule match
    destination-address-name <book-entry>` (#3229) — the destination twin
    of the `source-address-name` leaf (#2416). It references an
    `security address-book` address / address-set instead of a literal
    prefix; the snapshot builder
    (`appendNATDestinationAddressName`, `pkg/dataplane/userspace/nat.go`)
    resolves the name through the same address-book expander the policy +
    source-address-name paths use and feeds the resolved prefixes into the
    existing destination list (no new wire field). For DNAT each resolved
    host installs its own exact-host `DnatTable` entry; a non-host prefix is
    stripped to its network address exactly like a literal `match
    destination-address` CIDR. An undefined name is hard-rejected at commit
    (`validateNATSourceAddressNameReferencesStrict`, which gates BOTH the
    source and destination name leaves) and fails closed on the lenient
    load / peer-sync path (the unresolved raw token cannot parse as an IP,
    so the rule matches NOTHING rather than broadening to match-any).
    **#3425 — defined-but-unresolvable references**: the same gate now also
    rejects a name that IS defined under `security address-book` but
    resolves to NO concrete address — a defined-but-empty `address-set`, a
    set whose members dangle, or an `address` with no prefix
    (`Value == ""`). Existence alone is not enough: the snapshot builder
    resolves the name through `resolveUserspaceAddressBookEntry` (which
    returns `ok=false` for these cases) and appends the raw unparseable
    token, so the SNAT source list stays non-empty-but-unmatchable and the
    DNAT rule emits zero `DnatTable` entries — the rule translates no
    traffic. Strict commit now surfaces this as an operator-visible error
    (resolution mirrors the runtime via the shared
    `policyMatchAddressBookResolves` helper, so commit and apply cannot
    diverge — the NAT analog of the #3149 policy-address representability
    gate and the #3434 NAT match-application gate). A DIRECT
    `security dynamic-address address-name <name>` feed binding is ACCEPTED
    (its static expansion is empty but the live feed overlay supplies the
    prefixes at runtime, #3303) — mirroring the
    `validatePolicyMatchAddressesStrict` feed carve-out (#3294); a feed
    member NESTED in an address-set stays poisoned by the static resolver
    (the anti-Option-C guardrail). Lenient load / peer-sync downgrades to a
    warning so an already-persisted or peer-synced config still boots
    (#1960); the dataplane fails closed independently. **#3418** — the
    feed carve-out is now pinned through the full `CompileConfig` strict
    commit path for ALL FOUR SNAT/DNAT source/destination address-name
    combinations (the #3303 snapshot tests call the builder directly and
    bypass the strict validator, which is how the over-reject survived for
    the three combinations the #3425 SNAT-source test did not cover).
  - `security nat static rule-set rule then static-nat prefix-name <addr>`
    (#4290) — the NAMED form of `then static-nat prefix <ip>`. `prefix-name`
    references a global `security address-book` entry whose literal prefix
    is the 1:1 translation target. The compiler records the raw name
    (`StaticNATRule.ThenPrefixName`) and `resolveStaticNATThenPrefixNames`
    (compiler.go, run AFTER `resolveZoneLocalAddressBooks` folds the
    zone-local books into the global book — `compileNAT` can run before
    `compileAddressBook` within a `security {}` root, so resolution cannot
    happen inline in the then switch) resolves it to the single prefix and
    writes `rule.Then`. A single `address <name> <prefix>` resolves to its
    prefix; a one-member `address-set` resolves to that member's prefix;
    anything else (undefined / prefix-less / multi-member / dangling) leaves
    `Then == ""`. Before #4290 the target keyword fell through the then
    switch and the rule installed with an EMPTY translation target (silent
    broken static NAT). A defensive **empty-target guard**
    (`validateStaticNATThenTargetStrict`) now rejects at strict commit ANY
    non-NPTv6 `then static-nat` that produced `Then == ""` — the unresolvable
    `prefix-name` AND any unhandled/misspelled target keyword — reusing the
    `lenientFirewallRefs` downgrade (warn on load / peer-sync, #1960; the
    dataplane fails closed since the empty prefix does not parse as an IP).
  - **Accepted-only NAT knobs (typed + advisory, not enforced).** Three
    knobs are now schema-typed so they complete and commit, but the
    userspace dataplane does not enforce them — commit emits an accepted-only
    advisory (`ValidateConfig`, mirroring the #2078/#4231 doctrine) instead
    of the prior silent drop: `security nat source interface port-overloading`
    (enum `{off}`) and pool `port-overloading-factor <n>` (`ValueInteger`
    1..32) (#4291 — the SNAT allocator always overloads source ports, so
    `off` hardens nothing); and the NAT translation-TARGET routing-instance —
    the source/destination pool `routing-instance <ri>` leaf and the free-form
    `then static-nat {inet|prefix <ip>} routing-instance <ri>` trailing token
    (#4292 — the dataplane routes the post-translation packet against the
    ingress / default instance; DISTINCT from the enforced #3096 from/to SCOPE
    routing-instance). Full enforcement of all three is a userspace-dp
    follow-up.
  - `protocols router-advertisement interface` — typed the
    second-denominated leaves (`max/min-advertisement-interval`,
    `default-lifetime`, `link-mtu`; the latter was tightened from
    `ValidateIntegerMin(1)` to `ValidateIntegerMin(1280)` in #2497, see
    below) and declared the remaining compiler-consumed structural children
    (managed/other-stateful-configuration, dns-server-address, prefix
    flags). The per-`prefix` `valid-lifetime` / `preferred-lifetime` leaves
    are typed as non-negative integers (`ValidateIntegerMin(0)`): the
    compiler parses them with a bare `strconv.Atoi` and 0 means "use the
    SLAAC default" (`pkg/ra` clamps `<=0`), so 0 is accepted but garbage
    (e.g. `valid-lifetime abc`, which previously silently became 0) now
    fails at commit.
  - `system syslog host/file/user` — a wildcard `<facility>` child (the
    facility namespace is open-ended) whose value slot is the fixed Junos
    severity vocabulary (`syslogFacilitySeverityLeaf`), so a misspelled
    severity that `ParseSeverity` would silently treat as "no filter" now
    fails at commit; `allow-duplicates` is an explicit presence-only flag.
  Pure schema hardening — no runtime behavior change. Regression coverage:
  `pkg/config/schema_validate_2008_test.go`.
- **#2497 (router-advertisement string/identity leaves):** #2008 typed
  only the RA integer leaves; the five string/identity leaves below were
  still accepted untyped and then silently skipped or mis-advertised by
  the RA sender (`pkg/ra/sender.go buildRA`). Wired at commit:
  - `prefix` — the prefix value is the named-instance identity arg, so it
    uses `keyValidator: ValidateIPv6CIDR` (not the typed-leaf `validator`,
    which would mis-treat the on-link/autonomous flag children as
    modifiers). A typo'd or IPv4 prefix previously committed and the
    sender's `netip.ParsePrefix` error path logged-and-skipped it, so
    hosts got no PrefixInformation option and SLAAC silently broke.
  - `nat-prefix` / `nat64prefix` — `keyValidator: ValidatePREF64CIDR`,
    which reuses `ValidateIPv6CIDR` and then enforces the RFC 8781 §4
    PREF64 length set `{32,40,48,56,64,96}` (the only lengths the 3-bit
    PLC wire field encodes). The `lifetime` child is now
    `ValidateIntegerMin(0)` (was an Atoi-on-error-zero leaf).
  - `preference` — `ValueEnumOf` + `ValidateEnum(high|medium|low)`. A
    typo fell through the sender's `switch` default and silently
    advertised Medium, perturbing host default-router selection.
  - `dns-server-address` — `ValueIPAddress` + `ValidateIPv6Address` (a
    new validator: bare IPv6 literal, IPv4 rejected). The RDNSS option
    (RFC 8106) is IPv6-only; the sender skipped unparseable strings but
    did NOT family-gate, so a valid IPv4 literal reached the wire.
  - `link-mtu` — floor raised to `ValidateIntegerMin(1280)` (RFC 8200 §5
    IPv6 minimum link MTU); a smaller value was advertised verbatim and
    blackholes hosts that honor it.
  Pure schema hardening — no runtime behavior change (the sender's
  parse-and-skip / default paths are now unreachable for committed
  configs). New validators `ValidateIPv6Address` / `ValidatePREF64CIDR`
  live in `schema_validators.go`. Regression coverage:
  `pkg/config/schema_validate_2497_test.go`.
- **#4307 (router-advertisement reachable-time / retransmit-timer,
  fable-review-167 I-2):** the RFC 4861 §4.2 Reachable Time and Retrans
  Timer RA header fields had no schema leaf, no `RAInterfaceConfig`
  field, and the sender never set them, so both went on the wire as 0
  ("unspecified") and hosts could not be tuned via RA. Added
  `reachable-time` / `retransmit-timer` as typed millisecond leaves
  (`ValidateInteger(0, raReachableRetransMaxMillis)` — the 32-bit ms
  field maximum so an over-large value does not silently wrap in ndp's
  `Duration/time.Millisecond -> uint32`), compiled into
  `RAInterfaceConfig.ReachableTime` / `RetransTimer`, and set on
  `ndp.RouterAdvertisement.ReachableTime` / `RetransmitTimer` in
  `pkg/ra/sender.go buildRA`. 0 keeps the pre-#4307 unspecified default.
  Coverage: `pkg/config/parser_routing_test.go` (compile) +
  `pkg/ra/sender_marshal_4307_test.go` (wire round-trip).
- **#4308 (interface ARP/addressing parity knobs, fable-review-167
  I-3):** five common Junos interface knobs were accepted by the
  permissive parser but never modeled or compiled, so they silently
  vanished at commit. They are now typed leaves + compiled fields +
  carry an accepted-only advisory (the #2078 doctrine), because full
  enforcement needs design/cluster work:
  - `native-vlan-id <id>` (interface-level, `ValidateInteger(1, 4094)`)
    — folds into the QinQ tagging pipeline (#2354).
  - `gratuitous-arp-reply` / `no-gratuitous-arp-request`
    (interface-level flags) — map to per-interface ARP sysctls the
    interface apply path does not write yet.
  - `family inet unnumbered-address <interface>` — needs a networkd
    borrow-address implementation (resolve the donor unit's address).
  - `family inet targeted-broadcast` — needs dataplane directed-
    broadcast forwarding.
  Compiled into `InterfaceConfig.{NativeVlanID,GratuitousARPReply,
  NoGratuitousARPRequest}` and `InterfaceUnit.{UnnumberedInet,
  TargetedBroadcast}`; `validateInterfaceParityWarnings`
  (compiler_validate_warn.go) emits one deterministic per-interface
  accepted-only warning at commit. Coverage:
  `pkg/config/interface_parity_4308_test.go` (compile + advisory +
  no-false-positive).
- **#4309 (DHCP relay overrides, fable-review-167 I-4):** the dhcp-relay
  `overrides` block modeled only `always-broadcast`; three standard
  relay knobs were silently dropped. Added under group `overrides`:
  - `maximum-hop-count <1..16>` (`ValidateInteger(1, 16)`) — **enforced**.
    The relay's hop limit was hardcoded at 16; it is now the group's
    configured value (default 16), a request at the limit is dropped, and
    `RelayStats.RequestsDroppedMaxHops` counts the drop. Compiled into
    `DHCPRelayGroup.MaximumHopCount` and flows into `relaySpec.maxHopCount`.
  - `forward-only` / `relay-agent-option` — **accepted-only**. The xpf
    relay already forwards statelessly and always inserts Option 82, so
    each matches the default; compiled into `DHCPRelayGroup.ForwardOnly`
    / `RelayAgentOption` with a commit-time accepted-only advisory
    (`validateDHCPRelayParityWarnings`). Both AST shapes handled (inline
    flat-set Keys and block-form children). Coverage:
    `pkg/config/compiler_dhcp_relay_overrides_test.go` (compile flat-set
    + merged-Keys value + block form + advisory) and
    `pkg/dhcprelay/relay_test.go` (`TestRunRelay_ConfiguredMaxHopCount`).
- **#2008 H7 (security log profile):** declared the `security log
  profile <name>` stanza — `stream-name` (`ValueHintStreamName`
  completion), `default-profile` (presence flag), and
  `category session field-extra-name`. Before H7 the whole stanza parsed
  but was silently dropped (no schema child, no compiler case), so a real
  imported config such as `vsrx-ha.conf`'s `profile default-syslog {
  stream-name syslog-container; default-profile; }` committed with no
  validation and no effect. It now compiles to typed `LogConfig.Profiles`
  (`LogProfile{Name, StreamName, DefaultProfile}`) and the compiler
  cross-references `stream-name` against the configured streams
  (`validateLogProfileStreamReferencesStrict`): a profile naming an
  undefined stream is rejected at commit / commit-check (strict) and
  downgraded to a warning on the tolerant load / peer-sync paths
  (`lenientLogProfileStreamRef`, mirroring the IPsec proposal/gateway
  cross-ref gates and the #1960 fail-closed-on-load doctrine). **No
  runtime/dataplane change:** xpf per-stream routing is already a Junos
  superset (every stream whose category/severity filter matches receives
  the event), so a profile's `stream-name` designates the stream that
  carries its events; the `default-profile` flag records the operator's
  default designation and `category field-extra-name` is accepted for
  parity but not yet used to alter the emitted structured-data field set.
  Regression coverage: `pkg/config/log_profile_test.go` +
  `pkg/config/log_profile_schema_test.go`.
- **#3349 (security log stream/top-level field validation):** the remaining
  `security log` leaves were untyped (`children: nil`, no `valueType`), so a
  typo committed cleanly and then silently widened / remapped / fell back at
  runtime — a fail-open for an audit path. Typed as enum/value schema leaves
  (validated by `SchemaValidate`, strict on commit / commit-check, downgraded
  to a warning on the tolerant load / peer-sync paths exactly like every other
  typed leaf): `security log mode` (`stream|event`), `format` and `stream
  <s> format` (`sd-syslog|syslog|binary|structured`), `stream <s> severity`
  (`error|warning|info`, matching `pkg/logging` `ParseSeverity`), `facility`
  (the `ParseFacility` set incl. `local0..7`/`change-log`), `category`
  (`all|session|policy|screen|firewall`, matching `ParseCategory`), and
  `source-address` (`ValueIPAddress`). `source-interface` uses
  `ValidateSyslogSourceInterface`, which rejects a non-numeric `.<unit>`
  suffix (`resolveSourceAddr` silently `Atoi`-fell-back to unit 0, binding the
  wrong source IP). The enum value sets live in `schema_security.go`
  (`syslogLogModes`/`syslogLogFormats`/`syslogSeverities`/`syslogFacilities`/
  `syslogCategories`) and MUST stay in sync with those `pkg/logging` parsers —
  a value the validator allows but the runtime does not recognize would
  reintroduce the silent-fallback bug. **Port** (`stream <s> port` AND the
  nested `host { port }`) is range-checked `[1..65535]` by the
  `validateSecurityLogStreamPortsAST` compiler pass instead of a schema leaf,
  because the value has two AST locations the declarative schema walker cannot
  express — the same dual-location rationale as `tcp-mss`
  (`validateTCPMSSRanges`); strict on commit, `lenientLogStreamPort`-downgraded
  to a warning on load/peer-sync. Before this change a bad port was ignored by
  `compileLog` and silently kept the default 514. No runtime/dataplane change.
  Regression coverage: `pkg/config/log_stream_config_3349_test.go`.

  **Event-mode format compatibility (cross-field).** The top-level
  `security log format` value feeds two different runtimes depending on
  `security log mode`. As of #3409 BOTH runtimes honor every schema format —
  the event-mode local-file writer (`pkg/logging` `LocalLogWriter`, driven by
  the `ringbuf.go` local-writer fanout) implements `structured` (Junos RT_FLOW
  body) and `sd-syslog` (RFC 5424 envelope) alongside `binary` and the standard
  default, so nothing silently falls back. The schema leaf validates the value
  to a known format in *any* mode; `validateLogEventModeFormatStrict`
  (post-compile on `cfg.Security.Log`, strict on commit /
  `lenientLogEventModeFormat`-downgraded on load/peer-sync) now accepts the
  full enum in either mode and only fires defensively if a future schema value
  is added but not yet honored by the writer. Support matrix:

  | `format` | `mode stream` (remote syslog) | `mode event` (local file) |
  |---|---|---|
  | `binary` | binary records | binary records |
  | `structured` | Junos RT_FLOW | Junos RT_FLOW (local timestamp+tag prefix) |
  | `sd-syslog` | RFC 5424 envelope | RFC 5424 envelope |
  | `syslog` / unset | standard RFC 3164 text | standard text (local timestamp+tag prefix) |

  The #3409 follow-up closed the prior event-mode gap (before it, `structured`
  / `sd-syslog` were rejected at commit because the event-mode writer would
  silently no-op them to standard text). The event-honorable set in
  `validateLogEventModeFormatStrict` MUST stay in sync with the `ringbuf.go`
  local-writer fanout: a value accepted there but unhonored in the fanout would
  reintroduce the silent fallback.
- **#2008 H9/H10 (interface silent-drop reject):** two interface stanzas
  that parsed-accepted and were silently dropped (no schema child, no
  compiler case, no dataplane consumer) are now hard-rejected at commit /
  commit-check by an AST pre-walk
  (`validateUnsupportedInterfaceStanzasAST`,
  `compiler_interfaces_unsupported.go`):
    - **H9** `interfaces <if> unit <n> family inet|inet6 policer arp
      <name>` — xpf has no per-interface ARP policer (`feature-gaps.md`
      "Interface Policer ... Missing").
    - **H10** `interfaces <if> [unit <n>] mac <addr>` — the interface MAC
      is read-only (cluster RETH MAC is computed deterministically per
      node via `programRethMAC`), so a static override diverges from
      Junos and is unimplemented.
  Unlike H7 these are NOT given schema children — advertising a stanza
  that is rejected would be misleading; the honest contract for an
  unenforceable stanza is a commit rejection. Strict on commit /
  commit-check, downgraded to a warning on the tolerant load / peer-sync
  paths (`lenientUnsupportedInterfaceStanzas`, #1960 fail-closed-on-load
  doctrine) so an older-binary-persisted or peer-synced config that
  silently accepted these stanzas still boots, and an `inactive:` /
  apply-groups-inherited stanza is handled correctly (the walk runs after
  the inactive prune + group expansion). Detection is scoped to the
  `interfaces` stanza so the firewall `policer <name>` definition and the
  chassis `device-map interface ... mac` identity key are untouched. M1
  (`commit persist-groups-inheritance`) stays warn-only — it is a daemon
  no-op knob, not a false dataplane/identity promise — and its real
  implementation is split to /research. Regression coverage:
  `pkg/config/compiler_interfaces_unsupported_test.go`.
- **#4027 (interface-range expansion):** `interfaces interface-range
  <name> { member <if>; [member-range <a> to <b>;] <shared cfg> }` is a
  Junos construct that applies a shared configuration block to a SET of
  member interfaces. Before the fix xpf had no handling: the generic
  `interfaces` wildcard treated `interface-range` itself as an interface
  NAME, so the compiler minted a PHANTOM `InterfaceConfig` keyed
  `interface-range` (matching no kernel NIC, later reconciled admin-down)
  and both the shared config and the member interfaces were silently
  dropped. `expandInterfaceRanges` (`compiler_interface_range.go`) now
  rewrites every interface-range stanza into its member interfaces as an
  AST pre-pass in `compileExpanded`, BEFORE section compilation and the
  H9/H10 gate above (so both see the real members, never the phantom).
  Each member gets the range's shared statements — flattened to
  `set`-command suffixes and replayed through `ConfigTree.SetPath`, so
  they re-nest with the exact schema-driven shape a normal per-interface
  config would have — merged with the member's own per-interface config:
  the member's own statements are re-applied LAST so they WIN on a scalar
  conflict (e.g. a member-local `mtu` overrides the range `mtu`) while
  additive statements (addresses) accumulate. `member-range <a> to <b>`
  expands over the trailing decimal (endpoints must share a prefix; capped
  at `interfaceRangeMaxMembers` to bound a typo). The pass handles BOTH AST
  shapes (flat-set replay packs the range name into each leaf's `Keys[0]`;
  the hierarchical parser packs it into the `interface-range` node's
  `Keys[1]`) and is a strict no-op — the tree is left byte-identical —
  when no interface-range stanza is present. This is a compile-time AST
  rewrite, not a `setSchema` change: adding schema children for `member` /
  `member-range` would alter the flat-set grouping the expansion depends
  on, so the construct stays out of the grammar SSOT and is normalized
  before any typed-leaf walk. Regression coverage:
  `pkg/config/compiler_interface_range_4027_test.go`.
- **#3444 (destination-NAT rule-set `to` scope reject):** a Junos
  destination-NAT rule-set has only a `from` clause (zone | interface |
  routing-instance) — DNAT translates the destination on inbound, so there
  is no egress / `to` context (only source NAT, which has both `from` and
  `to`, can scope by an egress context). xpf briefly advertised a `to`
  subtree under `security nat destination rule-set` and
  `compileNATDestination` Cartesian-expanded the collected `to` scopes onto
  each `NATRuleSet` (`ToZone`/`ToInterface`/`ToRoutingInstance`), but the
  userspace snapshot builder (`buildDestinationNATSnapshots`,
  `pkg/dataplane/userspace/nat.go`) and the Rust DNAT runtime
  (`userspace-dp/src/nat/destination.rs`) model ONLY the `from` clause — the
  `DestinationNATRuleSnapshot` wire struct intentionally has no `to_*`. So a
  configured `to` scope was silently dropped: the translation applied
  regardless of the operator's declared destination context, with no commit
  error. The `to` subtree is removed from the DNAT rule-set `setSchema` (so
  completion no longer offers it), `compileNATDestination` no longer collects
  or stamps a `to` scope (`collectNATScopes(..., false)` — no phantom `To*`
  on the typed config), and an AST pre-walk
  (`validateDNATRuleSetToScopeAST`, `compiler_nat_dnat_to.go`) hard-rejects
  any `to` scope at strict commit / commit-check, naming the rule-set. Strict
  on commit, downgraded to a warning on the tolerant load / peer-sync paths
  (`lenientDNATToScope`, #1960 fail-closed-on-load doctrine) so an
  older-binary-persisted or peer-synced config that silently accepted a `to`
  scope still boots (the scope is ignored either way, now flagged); an
  `inactive:` / apply-groups-inherited `to` is handled correctly (the walk
  runs after the inactive prune + group expansion). Detection is scoped to
  `security nat destination rule-set` so the source-NAT `to` clause (a real
  feature, #3096) is untouched. If a future design genuinely wants
  egress-scoped DNAT after route resolution, that is a separate enhancement
  (add `to_*` to the snapshot + runtime + a regression that a mismatched
  `to zone` DNAT does not translate). Regression coverage:
  `pkg/config/compiler_nat_dnat_to_3444_test.go`.
- **#4881 (NAT rule-set mixed-scope-kind reject):** a Junos NAT rule-set
  `from` (and source-NAT `to`) clause scopes matched traffic by EXACTLY ONE
  kind — `zone`, `interface`, or `routing-instance`. Multiple VALUES of the
  chosen kind are a legitimate list (`from zone [ trust untrust ]` = match
  either zone — OR is correct there), but MIXING kinds in one clause is
  invalid Junos. `setSchema` declares the three as independent `multi:true`
  children with no mutual-exclusion validator, and the #3096 compiler
  Cartesian-expands the collected from-scopes × to-scopes into one typed
  `NATRuleSet` per `(fromScope, toScope)` pair — so `from zone trust` +
  `from interface ge-0/0/1.0` compiled into TWO rule-sets matching EITHER
  scope (OR), WIDER than the operator's intent and contradicting the in-tree
  `parseNATMatchScopes` comment that claimed the mix was "AND-ed fail-closed
  at match time" (it never was). An AST pre-walk
  (`validateNATRuleSetMixedScopeAST`, `compiler_nat_mixed_scope.go`) now
  hard-rejects any `from` (all three NAT kinds) or source-NAT `to` clause
  carrying >1 distinct scope kind, at strict commit / commit-check, naming
  the NAT kind, rule-set, clause, and mixed kinds. Detection reuses
  `parseNATMatchScopes` + aggregates the distinct kinds exactly as
  `collectNATScopes` feeds the Cartesian product, so what the gate rejects is
  precisely what the compiler would OR-expand; it runs after the inactive
  prune + group expansion so an `inactive:` / apply-groups-inherited mix is
  handled, and iterates every duplicate `security`/`nat`/`source`/etc. block
  (`forEachChild`, #3562 class). Downgraded to a warning on the tolerant load
  / peer-sync paths (`lenientNATMixedScope`, #1960) so an older-binary-
  persisted or peer-synced config that silently accepted a mixed clause still
  boots (it is OR-expanded as before, now flagged). A single-kind `from` plus
  a single-kind `to` (each its own clause) and a same-kind value list are
  untouched. Destination NAT is checked on `from` only — its `to` clause is
  separately rejected wholesale by `validateDNATRuleSetToScopeAST` (#3444).
  Regression coverage: `pkg/config/compiler_nat_mixed_scope_4881_test.go`.
- **#3562 (strict-reject AST walks must iterate EVERY `security` root — the
  duplicate-block discipline):** `parseStatements` (`parser.go`) APPENDS a
  repeated top-level block instead of merging it, and `compileExpanded` /
  `compileSecurity` / `compilePolicies` process EVERY `security` root (and
  every matching sibling at each level they descend). A strict-reject AST
  pre-walk that latched onto only the FIRST `security` node (`Name()=="security"`
  → assign → `break`), and often first-only `FindChild` at deeper levels, was
  therefore BYPASSABLE: an offending stanza placed in a SECOND duplicate
  `security {}` (or duplicate `policies {}` / `ipsec {}` / `nat {}` / …) block
  was still compiled while the gate waved it through — losing the fail-open
  diagnostic. This is reachable via the hierarchical `LoadOverride` path
  (`configstore/store_command.go` parses hierarchical input through
  `NewParser`). The shared `forEachChild(children, name, fn)` primitive
  (`compiler_nat_dnat_to.go`) is the SSOT walk discipline for this class:
  it invokes `fn` for EVERY child whose `Name()` matches, at every level the
  walk descends, so an offending stanza in ANY duplicate block at ANY level is
  caught. #3561 first applied it to `validateDNATRuleSetToScopeAST`; #3562
  converted the remaining six gates to descend with `forEachChild` over all
  `security` roots (and all `policies`/`ipsec` siblings) while leaving each
  validator's inner narrow leaf check unchanged (scope precision preserved):
  `validateSecureTunnelBindInterfaceAST` (#2933 — aggregates the if_id
  collision map across every block), `validatePolicyMatchLeavesStrict` (#3113),
  `validatePolicyRequiredMatchStrict` (#3044), and the three then-action gates
  `validatePolicyThenPermitStrict` (#3114) / `validatePolicyThenRejectStrict`
  (#3115) / `validatePolicyThenDenyStrict` (#3141). RULE OF THUMB: a new
  strict-reject AST pre-walk MUST descend with `forEachChild` (never a
  first-match `FindChild`/`break`) so it cannot be bypassed by a duplicate
  block. Regression coverage:
  `pkg/config/compiler_dup_security_3562_test.go` (one duplicate-`security`-block
  RED-on-revert test per validator, built with `NewParser` for the
  hierarchical / `LoadOverride` path).
- **#3566 (the SUB-level sibling of #3562 — descend with `forEachChild` at EVERY
  container level, not just the top):** the SMR of PR #3565 found that four
  flow-trace / log-stream gates iterated all top-level `security` roots (the
  #3562 fix) but then descended with a first-only `FindChild` at the SUB-level,
  so the same bypass survived ONE level down. `parseStatements` appends a
  repeated block as a sibling at EVERY level — not just the top — so a duplicate
  `flow {}` / `traceoptions {}` / `file` / `log {}` sub-block within one
  `security {}` could still hide the offending stanza (e.g. a benign first
  `flow { traceoptions { file good.log; } }` followed by a second
  `flow { traceoptions { file ../../tmp/leak; } }`). The four gates now descend
  `security > flow > traceoptions > file` (and `security > log`) with
  `forEachChild` at EVERY level, leaving each inner leaf check + lenient-warn
  (#1960) unchanged: `validateFlowTraceFileAST` (#3420),
  `validateFlowTraceFlagsAndFiltersAST` (#3422), `validateFlowTraceSizeFilesAST`
  (#3424) and `validateSecurityLogStreamTLSProfileAST` (#3350). RULE OF THUMB
  (restated for descent): use `forEachChild` at EVERY container level a
  strict-reject walk descends — a first-only `FindChild` at any intermediate
  level is the bypass in a smaller costume. Regression coverage:
  `pkg/config/compiler_dup_flow_subblock_3566_test.go` (per-validator
  RED-on-revert subtests duplicating each descended level — `flow`,
  `traceoptions`, `file`, `log` — built with `NewParser`).
- **#3842 (the innermost sibling of #3562/#3566 — duplicate `match {}`/`then {}`
  blocks UNDER ONE policy term):** #3562/#3566 fixed the duplicate-block bypass
  at the `security`/`policies`/`flow` container levels, but the per-policy check
  itself still read only the FIRST inner `match {}` / `then {}` block via
  `polNode.FindChild("match")` / `FindChild("then")` — both in the COMPILER
  (`compilePolicy`, `compiler_security.go`) and in the six strict policy gates.
  A policy term with a DUPLICATE inner `match {}` or `then {}` block — the shape
  `LoadMerge`/`LoadOverride` yields, since `parseStatements` appends a repeated
  block at EVERY level (it cannot be produced by flat-set `SetPath`, which
  merges the block) — had the SECOND block silently DROPPED: an L7 `application`
  constraint, an address constraint, or a `then reject`/`deny` in the duplicate
  block was discarded, WIDENING the policy with a clean commit (a HIGH security
  fail-open), and the gates never validated it either. The fix ACCUMULATES over
  all blocks via three shared helpers in `compiler_security.go` —
  `policyMatchChildren` (children of every `match {}`), `policyThenChildren`
  (children of every `then {}`), and `policyThenActionNodes(pol, action)` (every
  permit/deny/reject node across every `then {}`, composing with the #3377
  per-then-block two-node handling). The compiler and all six gates
  (`validatePolicyMatchLeavesStrict` #3113, `validatePolicyRequiredMatchStrict`
  #3044, `validatePolicyThenPermitStrict` #3114, `validatePolicyThenRejectStrict`
  #3115, `validatePolicyThenDenyStrict` #3141) now read through these helpers, so
  every block is enforced AND validated — Junos merge semantics. Two blocks with
  CONFLICTING terminal actions (`then { permit }` + `then { reject }`) surface as
  two `pol.terminalActions` and are rejected by the #3043 conflicting-terminal-
  action gate at commit (the fail-closed floor) rather than the second being
  dropped into a fail-open permit. RULE OF THUMB (restated for the leaf level):
  the per-instance body of a strict walk must also union same-named repeated
  BLOCKS (`match`/`then`) — a `FindChild`-first read of an inner block is the
  same bypass one level deeper. Regression coverage:
  `pkg/config/compiler_policy_dup_block_3842_test.go` (compiler accumulate,
  conflicting-then-block reject, second-block unsupported-leaf #3113 and
  unsupported-modifier #3114 rejection incl. the lenient-warn surface, split
  required dimensions merged, single-block regression guard — built with
  `NewParser` for the `LoadOverride` shape).
- **#3915 (the NAT-node analogue of #3842 — duplicate `source`/`destination`/
  `static`/`nat64`/`natv6v4`/`proxy-arp` blocks UNDER ONE `nat {}` node):**
  `compileNAT` (`compiler_nat.go`) read each of these six sub-blocks with
  `node.FindChild(<name>)` (FIRST match only). `parseStatements` appends a
  repeated hierarchical block as a sibling at EVERY level, so a
  `LoadMerge`/`LoadOverride` that produced a SECOND `source {}` (or
  `destination`/`static`/`nat64`/`proxy-arp`) block under one `nat {}` had that
  block's rule-sets SILENTLY DROPPED — the SNAT/DNAT/static rule-set vanished
  and traffic that should have been translated egressed UNtranslated (a NAT
  bypass / connectivity break) with a clean commit. The fix iterates EVERY
  same-named sub-block via the shared `forEachChild(node.Children, <name>, fn)`
  primitive. Each sub-block compiler (`compileNATSource` / `compileNATDestination`
  / `compileNATStatic` / `compileNAT64` and the inline proxy-arp loop) already
  APPENDS its rule-sets (`sec.NAT.Source` / `Destination.RuleSets` / `Static` /
  `NAT64` / `ProxyARP`) and map-assigns its pools, so invoking it once per
  duplicate block MERGES the blocks exactly as Junos merges duplicate
  hierarchical stanzas; with a single block the callback fires exactly once,
  bit-identical to the prior `FindChild` read. `natv6v4` additionally
  initializes its struct once and ORs the flag so a second block cannot reset an
  already-observed `no-v6-frag-header`. This is the sub-block-level sibling of
  #3444/#3562 (which fixed the `security`/`nat`/`destination` CONTAINER levels of
  the DNAT-`to` strict gate) and of #3842 (the same defect at the policy
  `match`/`then` level). Regression coverage:
  `pkg/config/compiler_nat_dup_subblock_3915_test.go` (per-sub-block merge
  RED-on-revert for source/destination/static/nat64/proxy-arp, pool merge,
  single-block bit-identical guard — built with `NewParser` for the
  `LoadOverride` dup-block shape, driving `compileNAT` directly).
- **#3850 (the NAT-RULE and filter-TERM analogue of #3842 — duplicate
  `match {}`/`then {}` / `from {}` blocks UNDER ONE rule or term):** #3842 fixed
  the duplicate inner `match`/`then` blocks for SECURITY POLICIES and #3915 for
  the `nat {}` SUB-blocks, but the SAME first-block-only fail-open survived in
  three sibling constructs. The per-rule / per-term body read only the FIRST
  inner block via `FindChild`:
  - **NAT rules** — `compileNATSource` / `compileNATDestination` /
    `compileNATStatic` (`compiler_nat.go`) read `ruleInst.node.FindChild("match")`
    and `FindChild("then")`. A rule with a duplicate `match {}` block had the
    second block's constraint (e.g. a `destination-address` split into a second
    block by `load merge`) silently dropped → the NAT rule matched a WIDER set of
    traffic than configured (a fail-open widening / mis-translation).
  - **Firewall filter terms** — `compileFirewall` read `termInst.node.FindChild(
    "from")` and `FindChild("then")`. A term with duplicate `from {}` blocks
    likewise dropped the second block's match conditions (fail-open widening);
    a duplicate `then {}` dropped the second block's action.
  - **`pre-id-default-policy`** — `compileSecurity` read the singleton `then {}`
    with `FindChild` (narrow surface, session-log modes only).

  The fix iterates EVERY sibling block with `FindChildren` (a two-nested-loop
  form that preserves brace depth): the NAT rule loops read `match {}` and
  `then {}` blocks in full; the filter term calls `compileFilterFrom` /
  `compileFilterThen` once per block (both ACCUMULATE into the term, and
  `compileFilterThen` still handles the leaf form `then accept;` where the
  action rides on `Keys`, not `Children`). All match/from conditions AND-combine;
  a NAT rule's single translation action and a filter term's terminal action
  (accept/discard/reject) resolve last-wins across duplicate `then` blocks (Junos
  merges duplicate stanzas — the second is applied, never silently dropped). The
  flat-set path is INHERENTLY SAFE: `SetPath` container-descent (`ast_edit.go`)
  merges two `set … match X` / `set … match Y` lines onto ONE `match` node, so
  this fail-open is reachable ONLY via the hierarchical `NewParser` /
  `LoadMerge`/`LoadOverride` shape. SECONDARY (same review): the #3843/#3043
  conflicting-terminal-action gate `validatePolicyTerminalActionStrict`
  (`compiler_validate_strict.go`) now DEDUPS `pol.terminalActions` by distinct
  value before the count, so two IDENTICAL `then { permit; }` blocks merge
  silently (Junos-faithful) instead of over-rejecting as "2 conflicting terminal
  actions (permit, permit)"; only DIFFERENT actions (permit + reject) still trip
  the gate. Regression coverage:
  `pkg/config/compiler_dup_match_then_3850_test.go` (RED-on-revert: NAT
  source/destination/static two-`match`-block merge, NAT source two-`then`-block
  last-wins, filter term two-`from`/two-`then`-block merge, `pre-id-default-policy`
  two-`then`-block; flat-set split-condition merge regression guards; single-block
  bit-identical guards; identical-permit merge + permit/reject-still-rejected for
  the dedup — built with `NewParser` for the `LoadOverride` shape, driving
  `compileNAT`/`compileFirewall`/`compileSecurity` directly).
- **#4544 (the host-inbound analogue of #3842/#3915/#3850 — duplicate
  `host-inbound-traffic {}` blocks UNDER ONE zone or interface):** `compileZones`
  (`compiler_security_zones.go`) read the zone-level block with a bare `=`
  assignment (`zone.HostInboundTraffic = parseHostInboundNode(prop)` — the switch
  case fires once per block, so the LAST block wins) and the #3362 per-interface
  override with `iface.FindChild("host-inbound-traffic")` (FIRST block wins).
  `parseStatements` appends a repeated hierarchical block as a same-key sibling,
  so a `LoadOverride` of a hand-authored config with two literal
  `host-inbound-traffic { ... }` blocks under one zone/interface — e.g.
  `host-inbound-traffic { system-services ssh; }` then
  `host-inbound-traffic { protocols ospf; }` — had the extra block silently
  dropped: host-inbound admission NARROWED (a service DoS) or fail-opened if the
  dropped block was the restrictive one, with a clean commit. Junos MERGES the
  blocks. The fix accumulates over EVERY `FindChildren("host-inbound-traffic")`
  at both levels via `mergeHostInbound` (`compiler_security_zones.go`), which
  UNIONS the SystemServices/Protocols and dedups (first-seen order). A single
  block returns the first parse UNCHANGED (no dedup, no copy — byte-identical to
  the pre-#4544 read). Flat-set `SetPath` and `load merge` (FormatSet round-trip)
  both merge two same-key lines onto ONE node, so — like every entry in this
  cluster — the fail-open was reachable ONLY via the hierarchical `NewParser` /
  `LoadOverride` shape. Distinct from the #3362/#3720 union, which merges
  host-inbound authored at DIFFERENT granularities (zone ∪ physical ∪ unit);
  #4544 merges repeated blocks at the SAME granularity. Regression coverage:
  `pkg/config/host_inbound_dup_block_4544_test.go` (zone + interface two-block
  merge, cross-block dedup, single-block byte-identical guard — built with
  `NewParser` for the `LoadOverride` shape); operator doc:
  `docs/host-inbound-service-matrix.md` "Repeated host-inbound-traffic blocks
  merge (#4544)".
- **#4818/#4820/#4821 (the TOP-LEVEL named-instance analogue of #4544/#3842/
  #3915/#3850 — duplicate `security-zone <name>` / `probe <name>` /
  `ssh-known-hosts host <name>` INSTANCES, not sub-blocks within one instance):**
  every prior entry in this cluster fixed a duplicate SUB-block within one
  named instance (`match`/`then` within one policy, `source`/`destination`
  within one `nat {}`, `host-inbound-traffic` within one zone/interface). This
  trio is the same defect one level UP: `namedInstances()` (`compiler_protocols.go`)
  returns one `(name, node)` pair per hierarchical AST sibling, so a `load
  override` config with two literal top-level blocks sharing a name — e.g. two
  `security-zone trust { ... }` blocks — yields TWO instances for `"trust"`.
  Three compilers read that loop with an unconditional per-iteration allocate
  + map-assign, so the SECOND instance silently replaced the first's entire
  compiled value:
  - **`compileZones`** (`compiler_security_zones.go`) — `zone := &ZoneConfig{...}`
    + `sec.Zones[inst.name] = zone` dropped the first instance's
    interfaces/host-inbound/address-book/description/screen/tcp-rst wholesale
    (#4818). Fix: find-or-create the `ZoneConfig` by name so every sibling
    instance's properties accumulate onto the SAME zone — `Interfaces` appends,
    `HostInboundTraffic`/`InterfaceHostInbound` merge via the existing
    `mergeHostInbound` (now also applied across instances, not just across
    blocks within one instance), `AddressBook` merges by address/address-set
    name (find-or-create, reusing `parseAddressBookEntries`'s own #4706
    find-or-create). `ScreenProfile`/`TCPRst`/`Description` are scalars with no
    natural union and stay last-wins across instances (unchanged from their
    existing last-wins behavior across repeated properties within one
    instance).
  - **`compileRPM`** (`compiler_services.go`) — `probe := &RPMProbe{Tests:
    make(...)}` + `rpmCfg.Probes[probe.Name] = probe` dropped the first
    instance's `Tests` map wholesale, disabling every RPM test it declared
    (#4820). Fix: find-or-create the `RPMProbe` by name; `probe.Tests[test.Name]
    = test` (unchanged) now accumulates test blocks from every sibling
    instance into the one shared `Tests` map.
  - **`ssh-known-hosts`** (`compiler_security.go`, inline in `compileSecurity`'s
    switch) — `sec.SSHKnownHosts[hostInst.name] = keys` (bare overwrite, plus
    `sec.SSHKnownHosts = make(...)` re-running on every `ssh-known-hosts`
    block) dropped the first `host` instance's key(s) — an operator-visible SSH
    host-key verification failure against that host (#4821). Fix:
    `sec.SSHKnownHosts` is initialized once (find-or-create the map), and each
    key is APPENDED (`sec.SSHKnownHosts[hostInst.name] = append(..., key)`)
    rather than the whole per-instance slice replacing the map entry — for a
    single instance this is byte-identical to the pre-fix build-then-assign
    (append onto nil == a fresh slice).

  As with every entry in this cluster, flat-set `SetPath` and `load merge`
  (FormatSet round-trip) both fold two same-key top-level lines onto ONE AST
  node, so a duplicate *instance* (as opposed to a duplicate *sub-block*) is
  reachable ONLY via the hierarchical `NewParser` / `LoadOverride` shape — see
  each issue's "Correction to the reviewed trace" for the refuted flat-set
  reproduction. Regression coverage: `pkg/config/zone_dup_block_4818_test.go`,
  `pkg/config/rpm_probe_dup_block_4820_test.go`,
  `pkg/config/ssh_known_hosts_dup_block_4821_test.go` (each: primary
  two/three-instance merge RED-on-revert, and a single-block/single-instance
  byte-identical negative control — built with `NewParser` for the
  `LoadOverride` shape, driving `CompileConfig` directly).
- **#3473 (duplicate security-policy names — strict commit gate):**
  `validateDuplicatePolicyNamesStrict` (`compiler_validate_strict.go`)
  hard-rejects two security policies that share a name within the same
  from/to-zone zone-pair, or within the global rulebase, matching Junos (a
  policy name must be unique within a context). `compilePolicies` appends every
  named instance without a uniqueness check, so duplicates compiled silently;
  because the userspace hit counter is NAME-keyed
  (`RuleID = "<from>-><to>/<name>"`, `pkg/dataplane/userspace`) the duplicates
  coalesce onto one `Arc<PolicyRuleCounter>` — `show security policies
  hit-count` cannot tell them apart, deleting one duplicate hands its
  accumulated hits to the survivor, and the Go-side `buildPolicyRuleCounterIndex`
  is last-write-wins on the RuleID. Strict on commit / commit-check;
  downgraded to a `cfg.Warnings` entry on the tolerant load / peer-sync paths
  (`lenientDuplicatePolicyNames`, #1960 no-brick — first-match enforcement is
  still correct on that path, only the shared-counter observability bug
  remains). This is a TYPED-config validator, NOT a raw-AST pre-walk, so it is
  duplicate-block-safe by construction: `compileConfig` runs `compileSecurity`
  for EVERY top-level `security` root and `compilePolicies` appends into the
  shared `cfg.Security.Policies` / `cfg.Security.GlobalPolicies`, so a duplicate
  split across two `security {}` blocks already lands in the aggregated typed
  slices the validator reads (the typed-family analogue of the `forEachChild`
  descent the #3562/#3566 raw-AST gates use). A duplicate NAME is only
  expressible via the hierarchical / `NewParser` (and `LoadOverride`) path;
  flat-set `ParseSetCommand` + `SetPath` MERGES same-name lines into one node,
  so it is structurally immune. Regression coverage:
  `pkg/config/compiler_dup_policy_name_3473_test.go` (zone-pair + global
  RED-on-revert, the cross-`security`-block split for both, the flat-set merge,
  name-reuse-across-contexts / distinct-names over-reject controls, and the
  lenient downgrade).
- **#3200 (host-inbound-traffic token validation):** `security zones <z>
  host-inbound-traffic { system-services <tok>; protocols <tok>; }` keeps its
  untyped-container schema shape (the leaves stay `children: nil` so flat-set
  grouping and `?` completion are unaffected), but the token VALUE is now
  validated in the compiler by `validateHostInboundTokensStrict`
  (`compiler_validate_strict.go`) against the recognized-token SSOT in
  `host_inbound_tokens.go` (`KnownHostInboundSystemServices` /
  `KnownHostInboundProtocols`). An unknown/typo token is hard-rejected at
  commit / commit-check. This is the SAME doctrine as the IPsec/log/scheduler
  reference validators above — a value the runtime cannot honor is a commit
  rejection rather than a schema enum (an enum would have to be re-derived from
  the dataplane classifier anyway, and the SSOT keeps the nft kernel mirror +
  the Rust AF_XDP classifier in agreement so a committed token never enforces
  inconsistently). Strict on commit, downgraded to a warning on the tolerant
  load / peer-sync paths (`lenientHostInboundTokens`, #1960 no-brick). Matching
  is case-sensitive against the canonical lowercase spellings (the nft matcher
  switch is case-sensitive). Regression coverage:
  `pkg/config/host_inbound_tokens_test.go` (commit reject + accept + lenient
  downgrade) and `pkg/daemon/host_inbound_parity_test.go` (nft-matcher-domain
  == SSOT parity + zero-match-zone fail-closed).
- **#3751 (event-options within/trigger numeric validation — fail-open typo):**
  `event-options policy <name> within <seconds> { trigger (on|until) <count>; }`
  gated a remediation on a temporal threshold, but `compileEventOptions`
  (`compiler_services.go`) parsed the time-interval and the trigger count with
  `strconv.Atoi` and SILENTLY DROPPED the error — a typo (`within bogus`,
  `trigger on typo`) coerced the field to 0. The engine's `withinMatches`
  (`pkg/eventengine`) then skipped both `> 0`-guarded trigger tests and
  returned true, so the policy fired on EVERY matching event: a typo silently
  converted a threshold-gated remediation (e.g. "rewrite the default route only
  after 4 probe failures in 30s") into an UNCONDITIONAL one — the dangerous
  fail-open direction. This folds H11 (typo→0→always-fire), H12 (negative /
  absurdly-huge / zero window — the huge case also risked a `time.Duration`
  overflow when multiplied by `time.Second`) and H13 (a single clause carrying
  BOTH `trigger on` and `trigger until`, which the engine ANDs into an
  almost-certainly-unintended narrow one-count band). Like
  `validateDNATRuleSetToScopeAST` (#3444) this is an AST pre-walk
  (`validateEventOptionsWithinAST`, `event_options_within.go`), NOT a
  SchemaValidate typed leaf: the raw typo'd token is lost once the compiler
  coerces it to 0, and the constraint spans a whole `within` clause (the
  seconds slot AND the nested trigger keyword/count AND the on/until mutual
  exclusion) — which a per-leaf validator cannot express, and SchemaValidate
  returns nil for keywords it does not know so it cannot REJECT a malformed
  trigger. The walk descends with `forEachChild` over EVERY top-level
  `event-options` block (the #3562 duplicate-block discipline —
  `event-options` is a top-level stanza) on the group-expanded, inactive-pruned
  tree, so an apply-groups-inherited clause is validated and an `inactive:` one
  is ignored. It rejects a non-numeric / negative / zero / out-of-range
  `within` (`1..86400` seconds) or `trigger` count (`1..1000000`), an unknown
  trigger keyword (Junos's unsupported `after`), a within clause with no
  trigger (gates nothing), and the on+until combination. Strict on commit /
  commit-check (hard-reject naming the policy + value); downgraded to a
  `cfg.Warnings` entry on the tolerant load / peer-sync paths
  (`lenientEventWithinTrigger`, #1960 no-brick) so an older-binary-persisted or
  peer-synced config that silently accepted a coerced-to-0 clause still boots.
  Defense-in-depth (#3751 second half): on that legacy boot the engine's
  `withinMatches` now fails CLOSED (the policy does NOT fire) on a within
  clause with no usable positive threshold — a leftover 0 no longer over-fires
  — while a policy with NO within clauses at all still fires on every match
  (no temporal filter). Regression coverage:
  `pkg/config/event_options_within_3751_test.go` (both AST shapes: commit
  reject per error class + accept + H13 + lenient downgrade) and
  `pkg/eventengine/engine_within_failclosed_3751_test.go` (fire-only-after-N,
  0-threshold + 0-window fail-closed, no-clause-still-fires).
- **#1387 (DHCP dynamic-DNS — live rfc2136 backend):** added an opt-in
  `dynamic-dns` subtree under BOTH `services dhcp-local-server` and
  `services dhcpv6-local-server` (a single shared `config.DHCPDynamicDNSConfig`
  on `DHCPServerConfig`; absent block == nil == today's behaviour). The
  schema tree is built by `dhcpDynamicDNSSchema()` in `schema_system.go`
  and shared by both parents (returned fresh per call so the two parents
  do not alias a mutable map). Typed leaves, validated where the
  reconciler/runtime consume them:
  - `enable` — presence-only flag (turns the reconciler on).
  - `ttl` — `ValueInteger` + `ValidateIntegerMin(1)` (record TTL seconds;
    the runtime defaults an unset/<=0 value to 300 in `policyFromConfig`,
    so the schema enforces only the positive floor).
  - `hostname-source` — `ValueEnumOf` + `ValidateEnum(client-hostname |
    fqdn | mac-fallback)`, matching `deriveFQDN`'s three modes.
  - `conflict-policy` — `ValueEnumOf` + `ValidateEnum(replace-owned |
    skip-existing | strict-fail)`.
  - `backend` — `ValueEnumOf` + `ValidateEnum(rfc2136 | kea-d2)`. `rfc2136`
    is LIVE (#1387 inc-2: the always-on reconcile loop publishes/withdraws
    records over real RFC 2136 UPDATE). `kea-d2` is a RESERVED enum value
    that is NOT implemented (Kea D2 is not in the image); the enum accepts it
    so a config naming it commits, but selecting it warns at commit and
    publishes nothing.
  Deliberately UNTYPED (free-form `args:1` leaves), with reasons in
  `schema_system.go`: `domain`, `update-server`, `tsig-key`,
  `tsig-algorithm`, `tsig-secret`. These are not rejected at the typed-schema
  layer (a hostname / base64 secret is not validatable by the existing
  IP/identifier validators without false-rejecting valid input); instead the
  live rfc2136 backend warn-validates them at commit
  (`validateDDNSBackendWarnings` in `compiler_validate_warn.go`): an enabled
  rfc2136 backend with no/garbage `update-server`, an unsupported
  `tsig-algorithm`, or an incomplete TSIG tuple (`tsig-key` without
  `tsig-secret`, or `tsig-secret` without `tsig-key`) each emit a WARN-only
  commit message (#2666) — never a hard reject, and the backend degrades
  safely at runtime. An `update-server` set with NO `tsig-key` at all also
  warns (#4483): TSIG is the only authenticator on this path, so an unsigned
  UPDATE trusts a forgeable response rcode — a spoofed `NOERROR` records a name
  as published though the server wrote nothing (silent blackhole) and a spoofed
  `REFUSED` suppresses a legitimate publish. The same no-`tsig-key` warning is
  emitted for the Surface A provider catalog by `validateSurfaceADDNSWarnings`.
  Both are WARN-only (a hard reject would brick a previously-inert config); the
  backend also emits a once-per-update-server runtime `slog.Warn`
  (`warnUnsignedOnce` in `pkg/ddns/backend_rfc2136.go`) the first time it
  actually sends an unsigned UPDATE. `tsig-secret` is
  SENSITIVE: it is redacted in `DHCPDynamicDNSConfig.String()` (logging) AND,
  since #2053, by its `config.Secret` field type on every JSON/YAML marshal
  (so the compiled-config dump on `GET /api/v1/config` never leaks it — see
  "Config secret redaction" below). Compile lives in `compileDHCPDynamicDNS`
  (`compiler_services.go`), handling both the hierarchical and flat-set AST
  shapes (walk + first-value-wins, mirroring `collectDeviceMapProps`); an
  empty/garbage block returns nil (positional/disabled, closing the
  empty-tree-compiles-non-nil trap). Regression coverage:
  `pkg/config/compiler_dhcp_ddns_test.go` (dual-AST equality, absent-default,
  TSIG redaction, enum/ttl accept+reject).
- **#2691 P1b (DDNS ScopeKey + independent v4/v6 policy + source binding):**
  three additions to the `dynamic-dns` subtree above.
  - **#2663 — independent v4/v6 policy.** The v4 (`dhcp-local-server`) and v6
    (`dhcpv6-local-server`) blocks now compile to SEPARATE fields —
    `DHCPServerConfig.DynamicDNS` (v4) and `DHCPServerConfig.DynamicDNSv6`
    (v6) — instead of one field-merged struct. Each family keeps its OWN
    `domain` / `update-server` / `tsig-*` / `ttl` / `conflict-policy` /
    source-binding, so v4 leases and v6 leases can target different zones /
    servers / TSIG keys, and a v4 conflict or v4 turn-off never affects v6.
    Backward compatibility: a config that sets the block under only ONE family
    still works — the engine (`ReconcileScoped`) INHERITS that single policy for
    the other family at reconcile time, so committed single-block configs are
    byte-for-byte unchanged; the moment BOTH families set their own block they
    are fully independent. The pre-P1b field-merge (`mergeDHCPDynamicDNS`) is
    retained only as a defensive same-family-block-seen-twice no-op.
  - **#2665 — source / interface / VRF binding** (three new free-form
    `args:1` leaves on the `dynamic-dns` subtree, per family):
    - `source-address <ip>` — bind the RFC 2136 UPDATE socket's source IP.
    - `destination-interface <if>` — pin egress to an interface
      (`SO_BINDTODEVICE`).
    - `routing-instance <name>` — egress from a routing-instance / VRF (binds
      to the VRF master device, which shares the routing-instance name).
    They are free-form (an IP / interface / instance name is not rejected at the
    typed-schema layer) and FAIL-OPEN at runtime: an invalid `source-address`
    makes the live backend fall back to no-op for that family (logged + counted),
    never a hard commit brick — matching the existing `update-server` / `tsig-*`
    posture. The live rfc2136 backend (`pkg/ddns/backend_bind.go`) builds a
    custom `net.Dialer` (a single `Control` hook does `unix.Bind` for the source
    IP and `SO_BINDTODEVICE` for the interface/VRF, so the bind works for both
    the UDP-first and the TCP-retry exchange); a config with no binding leaves
    the default transport unchanged. `destination-interface` wins over
    `routing-instance` for `SO_BINDTODEVICE` (the more specific pin).
  - **ScopeKey (#2663/#2664).** Ownership records now carry a `ScopeKey`
    `{Family, Interface, Unit, RoutingInstance, RGOwner, PolicyID}`
    (`pkg/ddns/state.go`) and are keyed by `{ScopeKey, identity, address}`. The
    ZERO scope reproduces the pre-P1b `identity|address` key byte-for-byte, so a
    pre-P1b ownership store loads with no migration (the `scope` JSON field is a
    pointer, omitted for the global lease scope). This is the load-bearing
    primitive the per-RG HA gate and (future) Surface-A router publish build on.
  Regression coverage: `pkg/config/compiler_dhcp_ddns_test.go`
  (independent-policy, single-family-applies-to-both, source-binding-leaves),
  `pkg/ddns/scope_test.go` (ScopeKey distinctness + pre-P1b round-trip +
  independent v4/v6 + per-RG gate), `pkg/ddns/backend_bind_test.go` (dial
  config), `pkg/daemon/daemon_ddns_scope_test.go` (per-RG resolver + gate).
- **#2691 P2 (Surface A — router/interface-address DDNS):** added the
  operator-facing `system services dynamic-dns` provider catalog + a
  per-interface per-family `dynamic-dns` binding so the firewall can publish its
  OWN learned address (DHCP-lease / static / netlink) as a configured FQDN.
  - **Provider catalog** (`services dynamic-dns provider <name>`, a repeatable
    named instance built by `ddnsServicesSchema()` in `schema_system.go`,
    compiled by `compileDDNSServices`/`compileDDNSProvider` in
    `compiler_system.go` into `config.DDNSServicesConfig`/`DDNSProvider` on
    `System.Services.DynamicDNS`): credentials configured ONCE, referenced by
    scope. Leaves: `backend` (enum: `rfc2136`/`dyndns2`/`duckdns`/`cloudflare`/
    `route53`/`generic` — all live), `update-server`, `tsig-key`,
    `tsig-algorithm`, `tsig-secret` (`config.Secret`-redacted), and the
    `source-address` / `destination-interface` / `routing-instance` transport
    binding (#2665, reused). Plus the engine tunables `forced-refresh` and
    `error-backoff-max` (a Go duration like `24h` OR a bare-seconds integer,
    parsed by `parseDurationSeconds`).
  - **Per-interface binding** (`interfaces <if> unit <n> family <af>
    dynamic-dns`, schema `interfaceDynamicDNSSchema()` in `schema_interfaces.go`,
    compiled by `compileInterfaceDynamicDNS` in `compiler_interfaces.go` into
    `InterfaceUnit.DynamicDNSInet` / `.DynamicDNSInet6`): `provider <name>`
    (catalog reference), `hostname <fqdn>`, `address-source` (enum:
    `interface` default | `dhcp`), `ttl`, and a per-binding `source-address`
    override. v4 and v6 are INDEPENDENT (distinct fields), like the Surface B
    per-family policy split (#2663).
    - **`hostname` is a TYPED leaf (#2779, `ValueHostname` + `ValidateDDNSHostname`).**
      Unlike the DHCP-lease path (where the CLIENT supplies the name and
      sanitizing untrusted input is reasonable), a router-owned Surface A
      hostname is OPERATOR INTENT. The publish path (`surfaceAName` →
      `sanitizeFQDN`) silently lower-cases + strips non-LDH characters + drops
      empty-sanitizing labels, so a name with an underscore / space / `@` /
      non-ASCII char / empty label / leading-or-trailing-dash label would be
      published as a DIFFERENT public DNS name with no error (e.g.
      `wan_1.example.net` → `wan1.example.net`). The validator REJECTS such a
      name at commit, naming the offending hostname, so the operator fixes it.
      ACCEPTED unchanged: LDH labels (`[A-Za-z0-9-]`) joined by single dots,
      with case-folding and a single trailing dot treated as benign DNS
      canonicalization. Contract: every name that passes commit is a fixed
      point of `sanitizeFQDN` (cross-package test
      `pkg/ddns/surface_a_hostname_2779_test.go`).
    - **`source-address` is a TYPED leaf (#2780, `ValueIPAddress` +
      `ValidateIPAddress`, reusing the GRE/tunnel IP-literal validator).** It
      was free-form. The runtime feeds it to `netip.ParseAddr`
      (`pkg/ddns/backend_bind.go` `resolveBindConfig`), where an unparseable
      value is a HARD error: the backend then falls back to a no-op for that
      scope and the binding SILENTLY stops emitting UPDATEs. Typing the leaf
      rejects a non-IP literal at commit (naming the `source-address` leaf)
      instead of committing garbage that disables the scope at runtime. A bare
      IP only (v4 or v6, no prefix length) — matching `netip.ParseAddr`. The
      validator has no family context (the leaf closure receives only the raw
      value), so either family literal commits under either `inet`/`inet6`
      parent; a genuine v4-record / v6-bind family mismatch is left to the
      runtime + Surface A status (not a commit-time gate). Regression coverage:
      `pkg/config/schema_validate_ddns_source_address_2780_test.go`
      (fail-on-revert accept/reject table).
  - **Reuses the pkg/ddns spine** (`pkg/ddns/surface_a.go`,
    `SurfaceAManager`): the SAME `DNSUpdater`/rfc2136 backend (self-ownership —
    no DHCID), the SAME `ScopeKey`, and the SAME durable-state shape (a separate
    file, `interface-ddns-state.json`). The engine adds change-detection,
    forced-refresh (a wire floor), and per-scope error backoff. The per-RG HA
    gate is the SAME one Surface B uses (publish only on the RG master;
    stop-writing-never-withdraw on a partial demotion). Warn-only validation:
    `validateSurfaceADDNSWarnings` (undefined provider, missing hostname,
    rfc2136 provider with no update-server, P3-reserved backend). Observability:
    `show services dynamic-dns [detail]` (CLI + gRPC), the
    `xpf_ddns_surface_a_*` Prometheus family. Regression coverage:
    `pkg/config/compiler_surface_a_ddns_test.go` (flat-set + hierarchical +
    warnings), `pkg/ddns/surface_a_test.go` (change-detect / forced-refresh /
    replace / withdraw / per-RG gate / backoff), and
    `pkg/daemon/daemon_ddns_surface_a_test.go` (scope build + RG attribution +
    gate).
- **#2691 P3 (HTTP provider backends + checkip — completes #2679):** added the
  consumer/SaaS DNS backends behind the SAME `services dynamic-dns provider
  <name>` catalog, so a provider is `backend dyndns2|duckdns|cloudflare|route53|generic`
  instead of `rfc2136`, with per-backend leaves. Every HTTP backend implements
  the SAME `DNSUpdater` interface the rfc2136 backend does — the Surface A engine
  (change-detection, forced-refresh, per-RG HA gate, error backoff) drives them
  identically; only the wire mechanism differs (`pkg/ddns/backend_dyndns2.go`,
  `backend_duckdns.go`, `backend_cloudflare.go`, `backend_route53.go`,
  `backend_generic.go`, the shared `backend_http.go`, the minimal SigV4 signer
  `sigv4.go`).
  - **New provider leaves** (all on `services dynamic-dns provider <name>`,
    schema `ddnsServicesSchema()`, compiled by `compileDDNSProvider` —
    credentials are `config.Secret`-redacted):
    - dyndns2: `server` (endpoint host/URL; a known provider NAME like `no-ip`
      / `dyn` resolves a built-in endpoint), `username`, `password`.
    - duckdns (#2960; its OWN backend, NOT a dyndns2 alias — DuckDNS is not
      dyndns2-protocol-compatible): `api-token` (the DuckDNS token, sent as a
      query param not HTTP Basic), `server` optional (defaults to
      `https://www.duckdns.org/update`). `UpsertLease` ⇒
      `?domains=<label>&token=&ip=`/`&ipv6=`; success on the literal `OK` body
      (`KO` ⇒ hard error); withdraw ⇒ `&clear=true` (removes both A and AAAA).
    - cloudflare: `api-token` (Bearer), `zone` (zone NAME; the zone id is
      resolved at update time).
    - route53: `aws-access-key`, `aws-secret-key`, `aws-region` (default
      us-east-1), `hosted-zone-id` (SigV4-signed `ChangeResourceRecordSets`
      UPSERT/DELETE).
    - generic templated (config-only — no Go code per provider): `url-template`
      (`%h` host, `%i` IP, `%u` user, `%p` pass, `%%` literal; quote the value —
      `?`/`&`/`%` need quoting in a `set` command), `ok-response`
      (success-substring matcher; default good/nochg/ok/true/updated).
    - checkip (opt-in, behind-NAT address source): `checkip-url` +
      `checkip-allowlist` (comma/space bogus addresses to ignore, e.g. the
      embedded `1.1.1.1` in a /cdn-cgi/trace page; a malformed token is no
      longer silently dropped — it warns at commit, naming the token, #2839).
      The per-interface binding's `address-source` enum gains `checkip`.
  - **Security** (plan §8.1): every credential is `config.Secret` (revealed only
    at the transport boundary, never in a URL/error/log; `DDNSProvider.String()`
    redacts all of them); HTTPS with system-trust cert+hostname verification
    (no InsecureSkipVerify); bounded request timeout; capped response body.
  - **Commit warnings** (`validateSurfaceADDNSWarnings`): an incomplete HTTP
    provider (dyndns2 with no server + unknown name, duckdns missing api-token
    (#2960), cloudflare missing
    api-token/zone, route53 missing keys/hosted-zone-id, generic missing
    url-template) warns and publishes nothing at runtime (fail-open, never a
    hard reject). A malformed `checkip-url` (not an http(s) URL with a host —
    e.g. `ftp://`, `not a url`, host-less `http://`) also warns at commit
    (#2773); the scheme check is case-INSENSITIVE per RFC 3986 §3.1, so an
    uppercase/mixed-case `HTTPS://host` is accepted, not warned (#2842). A
    malformed generic `url-template` (no host / wrong scheme) likewise warns at
    commit (#2841, mirror `ddnsGenericURLTemplateValid`) — previously it was
    validated PREFIX-ONLY (a bare `HasPrefix` http(s):// with no host parse), so
    a host-less template committed silently and only failed at the first publish.
    That validator is deliberately TEMPLATE-AWARE and string-based (not
    `net/url`): it extracts the scheme + host and tolerates the inadyn
    `%h/%i/%u/%p` specifiers (including a credential in the userinfo, e.g.
    `https://user:%p@host/upd`, which would make `url.Parse` fail) and `{{...}}`
    placeholders in the rest of the URL — same rationale as `RedactURL` (#2781).
    Both the commit mirror and the runtime gate `TrimSpace` the template before
    validating so they stay byte-for-byte in lockstep (a leading-whitespace
    template must not warn while the runtime trims+accepts it). The malformed
    template is `RedactURL`'d in the warning message (it may carry a credential).
    Without the commit-time check the typo committed silently and the runtime
    fetch then masqueraded forever as a transient observation failure,
    suppressing publishing indefinitely. The runtime `ddns.CheckIP` gate
    (`validateCheckIPURL`) and the generic backend's `validateGenericURLTemplate`
    (in `newGenericBackend`) fail closed on the same malformed URL regardless, so
    a URL that slips past commit cannot reach a fetch. A malformed
    `checkip-allowlist` token (operator typo, e.g. `8.8.8.8x`) also warns at
    commit and NAMES the offending token (#2839); the allowlist is a bogus-IP
    safety gate, so a token that was previously SILENTLY DROPPED shrank the gate
    and let the checkip parser admit the very IP the operator meant to suppress.
    Valid tokens are still retained; the runtime parse
    (`ddns.ParseAllowlistChecked`) mirrors this and fails lenient — it drops the
    bad token, keeps the valid entries, and logs ONCE per `(provider, allowlist)`
    in the surface-A observer (the per-poll-tick path must not flood). The
    commit-warn parse is mirrored in `ddnsAllowlistMalformedTokens`
    (`compiler_validate_warn.go`) because `pkg/ddns` imports `pkg/config`.
    Regression coverage:
    `pkg/config/compiler_p3_http_providers_test.go`,
    `pkg/ddns/backend_http_test.go` / `backend_cloudflare_test.go` /
    `backend_route53_test.go` / `sigv4_test.go` / `checkip_test.go` /
    `surface_a_http_test.go` (mock-server tests through the real backends).
  - **Live-provider verify is the deferred lab gate** (no provider creds/network
    in CI) — the mock-server tests are the merge gate.
- **#2243 (DHCP-server static / fixed / reserved host bindings):** added a
  `static-binding <mac>` named-instance subtree under `services
  dhcp-local-server group <g> pool <p>` AND `services dhcpv6-local-server
  group <g> pool <p>`. The schema tree is built by `dhcpStaticBindingSchema()`
  in `schema_system.go` (returned fresh per call so the v4/v6 parents do not
  alias a mutable map). The instance key is the client hardware (MAC)
  address — `keyValueType: ValueMAC` + `keyValidator: ValidateMAC`, so a
  malformed MAC fails at `?` completion and commit-check. Typed children:
  - `fixed-address` — `ValueIPAddress` + `ValidateIPAddress` (the reserved
    IP the matching client always receives).
  - `host-name` — free-form `args:1` (optional Kea reservation hostname).
  Compile lives in the `static-binding` case of `compileDHCPLocalServer`
  (`compiler_services.go`), handling both AST shapes via
  `namedInstances([]*Node{pp})` (the MAC is `Keys[1]` in flat-set and
  hierarchical alike; the leaves are the instance node's children). It
  populates `DHCPPool.StaticBindings []*DHCPStaticBinding`
  (`types_system.go`). Cross-binding semantics that need the compiled pool
  (subnet) live in `validateDHCPStaticBindingsStrict`
  (`compiler_validate_strict.go`): it rejects a missing/malformed
  fixed-address, a family-mismatched literal (v6 under v4 or vice-versa),
  an address outside the pool subnet (Kea would silently drop it), and a
  duplicate MAC identity or duplicate fixed-address within the same pool.
  **Strict/lenient split (#2243 review, flag `lenientDHCPStaticBindings`):**
  the gate is strict on the commit / commit-check path (`CompileConfig` —
  hard-reject) and downgraded to a `cfg.Warnings` entry on the tolerant
  load / peer-sync paths (`CompileConfigLenient` /
  `CompileConfigForNodeLenient`) so an already-persisted or peer-synced
  config carrying a bad binding still BOOTS (#1960 fail-closed-on-load
  doctrine). It runs AFTER the strict accumulator (mirroring
  `validatePolicyMatchAddressesStrict`), not inside it — the original
  in-accumulator placement hard-rejected the whole tolerant config-load,
  inconsistent with every sibling fail-open validator.
  The Kea renderer (`generateKea4Config`/`generateKea6Config`,
  `pkg/dhcpserver/dhcpserver.go`) emits a per-subnet `reservations` array
  (`hw-address` → `ip-address` for v4; `hw-address` → `ip-addresses[]` for
  v6, plus optional `hostname`). The MAC is canonicalized to Kea's accepted
  colon-lowercase form via `canonicalMAC` (`net.ParseMAC().String()`) at
  both render sites — `ValidateMAC` accepts the Cisco dotted-triplet and
  uppercase, which Kea's hw-address parser rejects, so a clean-committing
  config would otherwise break the Kea reconfigure. Reservations derive
  entirely from the committed config, so an HA pair serving identical
  subnets is reservation-consistent by construction via the existing
  cluster config-sync — no per-lease replication is needed for the static
  case (the dynamic-lease HA gap is the separate companion #2239).
  Regression coverage: `pkg/config/dhcp_static_binding_test.go` (dual-AST
  compile, schema MAC/IP rejection, strict out-of-subnet / duplicate /
  family / missing-address rejection, **strict-reject-vs-lenient-warn
  gate**) and `pkg/dhcpserver/reservations_test.go` (v4 + v6 Kea
  `reservations` render, **dotted/uppercase MAC canonicalization**,
  no-binding omits the key).

### #4217/#4218/#4219/#4220 — CoS interface-binding + scheduler typed leaves (fable-review-166 G-3/G-4/G-5/G-1)

Four class-of-service config-schema gaps where a leaf was untyped,
missing, or inert. All four are typed in `schema_cos.go` (shared
constructors `cosShapingRateSchema` / `cosOversubscriptionPolicySchema` /
`cosPriorityLowMinShareSchema` keep the unit level and the #4021
interface level identical), so garbage HARD-REJECTS at commit instead of
compiling to a silent 0.

- **#4217 (G-4) `shaping-rate` / `burst-size`.** Both untyped, so `set
  class-of-service interfaces reth0 unit 80 shaping-rate 10gg` committed:
  `parseBandwidthLimit("10gg")` returns 0, the compiler reads 0 as
  "unset", and the root shaper silently disappeared (unshaped ~25G
  egress). `shaping-rate` is a CONTAINER (it carries the `burst-size`
  child), so it uses the typed-KEY-slot feature (`keyValueType:
  ValueRate`, `keyValidator: ValidateRate`) — NOT `valueType`, which
  would flip the walker into the typed-LEAF branch and mis-treat
  `burst-size` as a presence-only modifier. `burst-size` is a plain typed
  value leaf (`ValueByteSize` / `ValidateByteSize`); bare-integer
  burst-size is now rejected as ambiguous (same tightening `buffer-size`
  got in #1319).
- **#4218 (G-3) `codel-target`.** Absent from `setSchema`, so no
  completion and `codel-target banana` was silently dropped by the
  compiler's `err == nil` parse guard. Now a typed `ValueInteger` /
  `ValidateIntegerMin(0)` leaf under `schedulers`. The CoDel AQM is still
  NOT enforced (#1829 Phase 2 PLAN-KILLED), so a commit warning fires
  when `CodelTargetNS > 0` (`compiler_validate_warn.go` scheduler loop).
- **#4219 (G-5) `oversubscription-policy` / `priority-low-min-share`.**
  Both absent from `setSchema` — no completion, no validation, unknown
  policy strings committing. `oversubscription-policy` is now a container
  `{ guarantee-rate <fraction 0..1> | proportional }` (adding it to the
  schema changes SetPath grouping flat→hierarchical; the compiler already
  handled both shapes). The guarantee-rate fraction is validated
  `ValidatePercent(0,1)`, so `1.7` is rejected at commit instead of
  silently clamping to 1.0. `priority-low-min-share` is `ValueRate` /
  `ValidateRate`.
- **#4220 (G-1) `priority-low-min-share` truth-in-labeling.** The knob is
  INERT — it is wire-surface-only and no scheduler code consults it (the
  `cap_eff` per-pass reservation does not exist). The typed leaf + commit
  warning (`compiler_validate_warn.go` interface loop) surface the
  inertness; a misleading `queue_service/mod.rs` comment that cited a
  nonexistent `cap_eff` subtraction is corrected, and
  `docs/fairness-regimes.md` gate 2 is marked DEFERRED/NOT-IMPLEMENTED.
  The ENFORCEMENT (cap_eff reservation) is a separate deferred-research
  item, out of scope here.

Regression coverage: `pkg/config/schema_cos_hb166_test.go` (flat-set
schema reject-on-garbage for all four, valid-value accept, the two inert
warnings, and completion presence of the new leaves at unit + interface
level). FAIL-ON-REVERT: dropping the validators / warnings makes the
garbage values commit clean again and the inert knobs go silent.

### #3043 — Security-policy missing/conflicting terminal action (commit fail-closed)

`PolicyAction`'s zero value is `PolicyPermit` (`types_security.go`:
`PolicyPermit PolicyAction = iota`). `compilePolicy` builds the typed
`Policy` and only mutates `Action` when it sees `then permit` / `then deny`
/ `then reject`; `then log` / `then count` set modifiers only. So a policy
whose `then` stanza carried ONLY modifiers (an audit/drop placeholder such
as `then log session-init`) — or whose terminal action was dropped or
typo'd — compiled with `Action == PolicyPermit` and silently **PERMITTED**
every packet matching its match conditions: a zone-pair-wide silent
fail-OPEN. Symmetrically, a policy that named MORE than one terminal action
(e.g. a group-merged `then permit` + `then deny`) resolved last-wins by
child visitation order rather than failing the commit, so the enforced
action depended on parse order. Junos requires every policy term to specify
exactly one terminal action.

**`validatePolicyTerminalActionStrict`** (`compiler_validate_strict.go`)
restores that fail-CLOSED parity. `compilePolicy` records the terminal
action tokens it sees in the unexported `Policy.terminalActions` slice (the
typed `Config` is never serialized, so the field carries no persistence /
back-compat obligation); the validator requires exactly one such token per
per-zone-pair policy AND per global policy, rejecting zero (no terminal
action) and more than one (conflicting actions). It iterates
`cfg.Security.Policies` then `cfg.Security.GlobalPolicies` in deterministic
order, so the first-reported error is stable.

**Runtime fail-closed default:** `compilePolicy` now defaults an actionless
policy's `Action` to **`PolicyDeny`** (not the `PolicyPermit` zero value).
This makes the tolerant load / HA-sync path safe: a leniently-loaded
actionless policy DENIES rather than fails open. The `PolicyAction` enum
zero value is left unchanged (changing it is invasive and unnecessary once
the actionless policy is explicitly set to deny at compile).

**Strict/lenient split (flag `lenientPolicyTerminalAction`):** strict on the
commit / commit-check path (`CompileConfig` — hard-reject), downgraded to a
`cfg.Warnings` entry on the tolerant load / peer-sync paths
(`CompileConfigLenient` / `CompileConfigForNodeLenient`) so an
already-persisted or peer-synced config that an older binary accepted still
BOOTS (#1960 fail-closed-on-load doctrine) — the runtime default-to-deny
keeps a leniently-loaded actionless policy fail-closed. The gate runs AFTER
`validatePolicyZoneReferencesStrict`, mirroring the sibling fail-open
validators, so a structural error, a bad match-address, and a bad zone
reference still win the first-error slot.
Regression coverage: `pkg/config/policy_terminal_action_3043_test.go`
(`TestPolicyNoTerminalActionFailsCommit` and
`TestGlobalPolicyNoTerminalActionFailsCommit` — fail-on-revert reject
guards, `TestPolicyConflictingTerminalActionsFailsCommit` — last-wins
conflict guard, `TestPolicyNoTerminalActionLenientDefaultsDeny` — lenient
warn + default-to-deny, `TestPolicyExactlyOneTerminalActionCommits` —
positive control).

### #3065 — Unspecified `default-policy` is fail-closed (deny-all) + `reject-all` + schema leaf

The sibling of #3043 for the IMPLICIT fallback. When a flow matches no
zone-pair policy, no global policy, and no explicit term, the verdict is the
*default policy*, held in `SecurityConfig.DefaultPolicy`. Because
`PolicyAction`'s zero value is `PolicyPermit` (`types_security.go`), a config
that omits the `security policies default-policy` stanza compiled to the zero
value and shipped **permit-all** — a silent fail-OPEN that is the opposite of
the Junos SRX `default-security-policy`, which denies all unmatched traffic.
(`compiler_validate_strict.go`'s own comment flagged this.) Two adjacent
gaps: `compilePolicies` (`compiler_security.go`) handled only `permit-all` /
`deny-all`, so the valid Junos `reject-all` fell through the switch and was
silently ignored; and the `default-policy` leaf was absent from
`schema_security.go`, so a misspelled value was accepted unchecked by the
schema walker.

**Fail-closed default:** `CompileConfig` (`compiler.go`) now initializes
`SecurityConfig.DefaultPolicy = PolicyDeny` when it constructs the typed
`Config`. An absent stanza therefore denies unmatched zone-pair traffic
(Junos parity). The `PolicyAction` enum zero value is left unchanged
(matching the #3043 decision) — the default is set explicitly at construction
rather than by flipping `iota`.

**Explicit override:** an operator restores the legacy permit-all behaviour
with `set security policies default-policy permit-all`; `deny-all` and
`reject-all` are the other accepted values, with `reject-all` now mapped to
`PolicyReject` in the `compilePolicies` switch.

**Dataplane plumbing:** the value flows to the userspace dataplane unchanged
via the snapshot string — `policyActionString(cfg.Security.DefaultPolicy)`
(`pkg/dataplane/userspace/builder.go`) → `ConfigSnapshot.DefaultPolicy` →
Rust `parse_action` → `PolicyState.default_action`
(`userspace-dp/src/policy.rs`), which is the no-match verdict. The Rust
struct default was already `Deny`; the Go zero value was overriding it with
`"permit"`, so the Go init is the operative fix.

**Schema leaf:** `default-policy` is a typed `ValueEnumOf` child of
`policies` (`schema_security.go`) validated by
`ValidateEnum([]string{"permit-all","deny-all","reject-all"})`, so a bogus
value (`allow-everything`) fails `commit check` instead of being silently
accepted.

Regression coverage: `pkg/config/compiler_default_policy_3065_test.go`
(`TestDefaultPolicyFailsClosed` — fail-on-revert: unset stanza must compile
to `PolicyDeny`; `TestDefaultPolicyExplicitOverrides` — permit-all/deny-all/
reject-all mapping; `TestDefaultPolicySchemaValidation` — enum accept/reject)
and `pkg/dataplane/userspace/default_policy_3065_test.go`
(`TestSnapshotDefaultPolicyFailsClosed` — the snapshot string the Rust verdict
reads is `"deny"` for an unset config, `"permit"`/`"reject"` for the explicit
overrides).

### #3534 — `default-policy-log session-init|session-close` (implicit default RT_FLOW logging)

Split from #3363 Part 2. Operators want the implicit default-policy verdict to
emit RT_FLOW session logs like a named policy's `then log` selection. The
natural Junos-style spelling, `default-policy then log session-init`, is **not**
expressible: the #3065 `default-policy` leaf is a typed `ValueEnumOf` leaf, and
the `schema.go` typed-leaf invariant forbids a typed leaf from carrying a
`children` map (flipping a leaf to a container regresses flat-set SetPath
grouping). #3363 deferred the knob for exactly this reason. The fix puts the log
selection in a **sibling container** — `security policies default-policy-log`
with presence-only flag children `session-init` / `session-close`
(`schema_security.go`) — so the `default-policy` enum leaf is untouched (its
replace semantics + enum `commit check` from #3065 are preserved bit-for-bit).
This mirrors the `pre-id-default-policy` logging-bool model, but unlike
pre-id-default-policy (#2509, accepted-but-inert) it is **wired**.

**Compile:** `compilePolicies` (`compiler_security.go`) reads the two flags into
`SecurityConfig.DefaultPolicyLogSessionInit` / `…Close`.

**Dataplane plumbing:** `builder.go` threads them into
`ConfigSnapshot.DefaultLogSessionInit` / `…Close` (additive wire — `omitempty`
on the Go side, `#[serde(default)]` on the Rust `ConfigSnapshot`, so an old
helper or an old Go binary decodes a missing field as `false`). The Rust build
site (`forwarding_build/mod.rs`) sets `PolicyState.default_log_session_init` /
`…_close`, and the implicit-default-verdict result (`policy.rs`,
`evaluate_policy_result_*`) stamps them onto `PolicyEvaluationResult.log_session_*`.
The session-create hot path already copies those onto the session metadata, so a
**default-PERMIT** flow installs a session that emits RT_FLOW_SESSION_CREATE /
RT_FLOW_SESSION_CLOSE exactly like a named policy — riding the #3528
default-policy verdict path (sentinel `policy_id` → rendered `default-policy`).

**Inert under deny/reject (WARN):** a **default-DENY/REJECT** verdict installs
no session, so the session-init/close records cannot fire; that verdict is
already logged unconditionally via the policy-deny RT_FLOW record. Commit emits a
WARN-only message (`validateDefaultPolicyLogWarnings`, `compiler_validate_warn.go`)
naming the inert modes and pointing at `permit-all`. Never an error — the stanza
is valid and a hard reject would brick a boot on a previously-committed value.

Regression coverage: `pkg/config/compiler_default_policy_log_3534_test.go`
(compile flags + schema accept + inert-warning fail-on-revert),
`pkg/dataplane/userspace/default_policy_log_3534_test.go` (snapshot wiring),
and Rust `policy::tests::default_verdict_carries_default_policy_log_flags` +
`afxdp::tests::build_forwarding_state_threads_default_policy_log_flags` +
the `wire_invariant_default_specimens` fixture.

### #4373 — `then log session-init|session-close` inert on a deny/reject policy (WARN)

avo-review-007 E1. The per-policy analog of the #3534 default-policy advisory
above. An operator writes a NAMED or GLOBAL policy `then reject; then log
session-close` expecting an RT_FLOW close record when the flow is rejected — but
a **deny/reject verdict installs no session**, so the requested
RT_FLOW_SESSION_CREATE / RT_FLOW_SESSION_CLOSE records never fire (session-close
has no session to close). The deny is logged unconditionally via the RT_FLOW
**policy-deny** record instead (`userspace-dp` `emit_policy_deny_event` fires on
every non-permit verdict, never gated on a per-policy log flag), so `then log
session-init` is redundant and `then log session-close` is inert. Per-policy
`then log` session records fire only for a **`then permit`** policy, whose
admitted session the dataplane stamps the log flags onto at install (the #2508
path). Without a signal the policy REPORTS session-close logging on every
operator surface (REST/gRPC/CLI) yet produces no close record — a silent
observability gap that reads as a bug.

**Advisory (WARN):** `validatePolicyLogInertOnDenyWarnings`
(`compiler_validate_warn.go`) emits a WARN-only commit-time message for each
named/global policy whose action is deny/reject and that carries a
session-init/session-close `then log` selection, naming the inert mode(s) and
the verdict. Never an error — `then log` on a deny/reject is valid Junos and a
hard reject would brick a previously-committed config (#1960 no-brick). This is
distinct from the bare-`then log` gate (`validatePolicyLogActionStrict`, #3060),
which still hard-rejects a `then log` naming neither mode. The log RENDERING side
of the same confusion (a reject is logged as `POLICY_DENY` / `FILTER_LOG
action=reject`, never a misleading `SESSION_CLOSE`) was already unambiguous —
`SESSION_CLOSE` omits the action byte (#2513) and `POLICY_DENY` carries a
distinct reason (#3610); this advisory closes the remaining CONFIG-time
confusion. The E4/H2/H7 route-drop-before-policy half of avo-review-007 shipped
separately (#4504); the live NoRoute/martian drop counter remains a deferred
`userspace-dp` (Rust) slice.

Regression coverage: `pkg/config/compiler_policy_log_inert_deny_4373_test.go`
(zone-pair + global deny/reject warn fail-on-revert; permit + no-log negative
gates).

### #2401 — Security-policy undefined-zone references (commit fail-closed)

A `set security policies from-zone <a> to-zone <b> { policy ... }` stanza
whose `from-zone` or `to-zone` names a security zone the configuration
never defines (a typo, or a zone deleted out from under the policy) was
historically only a `ValidateConfig` **warning** — the commit succeeded.
The rule was compiled and KEPT, but the userspace dataplane resolves the
unknown zone name to no zone-id; before **#3402** it then silently DROPPED
the unindexed rule, so the zone pair fell through to `state.default_action`:
under a **permit** default this was a silent fail-OPEN (a deny rule the
operator wrote against a mistyped zone did nothing); under a deny default it
blackholed with no operator signal beyond a stderr line. Junos rejects an
undefined zone reference at commit. As of **#3402** the dataplane no longer
drops the rule: its integrity preflight rejects the WHOLE snapshot
(`SnapshotIntegrityError::UnresolvableZoneReference`) and retains the
previous good `PolicyState` (default-deny on a fresh boot) — see the
"#3402" entry below.

**`validatePolicyZoneReferencesStrict`** (`compiler_validate_strict.go`)
restores that fail-CLOSED parity. It hard-rejects any zone-pair policy
whose from/to-zone is not a defined `security zones security-zone` and is
not one of the reserved special tokens **`any`** (Junos wildcard zone),
**`junos-host`** (reserved self-traffic context), or the empty token (see
`policyZoneSpecialTokens`). A global policy's STRUCTURAL from/to-zone is always
the `junos-global` sentinel (mapped only at snapshot-build time), so it never
names an undefined structural zone. As of **#3148** a global policy MAY carry
an optional `match from-zone`/`match to-zone` context (all-zones when absent);
`validatePolicyZoneReferencesStrict` now validates those match zones against the
same special-token + defined-zone gate. The dataplane fails CLOSED for an
undefined global match zone — since #3402 `build_global_zone_scope` raises
`SnapshotIntegrityError::UnresolvableZoneReference` (rejecting the whole
snapshot) rather than building a matches-nothing scope — and the commit gate
rejects it anyway for operator-visible parity.

**Strict/lenient split (flag `lenientPolicyZoneRefs`):** strict on the
commit / commit-check path (`CompileConfig` — hard-reject), downgraded to
a `cfg.Warnings` entry on the tolerant load / peer-sync paths
(`CompileConfigLenient` / `CompileConfigForNodeLenient`) so an
already-persisted or peer-synced config carrying a stale zone reference
still BOOTS the daemon (#1960 fail-closed-on-load doctrine: the management
plane stays alive so the operator can fix it). Since #3402 the dataplane
itself fails CLOSED on such a snapshot (whole-snapshot integrity reject,
previous-good `PolicyState` retained), so a leniently-loaded bad config does
not silently un-enforce a rule. The
gate runs AFTER `validatePolicyMatchAddressesStrict`, mirroring the sibling
fail-open validators, so a structural CoS/policer/device-map error and a
bad match-address still win the first-error slot.
Regression coverage: `pkg/config/policy_zone_ref_test.go`
(`TestPolicyUndefinedZoneFailsCommit` — the fail-on-revert guard for both
an undefined from-zone and to-zone, `TestPolicySpecialZoneTokensCommit` —
`any`/`junos-host`/global anti-over-reject, `TestPolicyDefinedZonesCommit`,
`TestPolicyUndefinedZoneLenientDowngradesToWarning`).

### #3402 — Undefined-zone policy snapshot (dataplane fail-closed backstop)

The #2401 commit gate is the primary defense, but it is downgraded to a
warning on the lenient / upgrade-state / HA-replay path, and a corrupt or
version-drifted snapshot can carry an undefined zone name regardless. Before
#3402 the userspace dataplane handled such a snapshot rule as a stderr-only
DROP: the zone-pair / single-wildcard index build skipped it ("rule kept, but
not indexed") and the scoped-global build produced a matches-nothing
`GlobalZoneScope::Unresolved`. In both cases the rule never participated in
evaluation and its traffic fell through to `default-policy` — a fail-OPEN
stale `deny` under `default-policy permit-all`, a blackholing stale `permit`
under `deny-all` — invisible to the control plane.

`parse_policy_state_with_counters` (`userspace-dp/src/policy.rs`) now raises
`SnapshotIntegrityError::UnresolvableZoneReference { rule_id, zone }` for an
unresolvable from/to zone (zone-pair and single-wildcard paths) and for an
unresolvable scoped-global `match from-zone`/`match to-zone`
(`build_global_zone_scope`). The integrity preflight in the apply handler
rejects the WHOLE snapshot and retains the previous good `PolicyState` (a
fresh boot keeps the default-deny state), action-agnostic and consistent with
the #2124/#3261/#3365/#3367 fail-closed family. The special tokens `any`,
`junos-host`, and the empty token always resolve, so a clean config never
trips this. The `GlobalZoneScope::Unresolved` variant was removed: a live
scope is now only `Any` or a resolved `Zone(id)`.

**Preflight zone source (boot-safety).** A `ConfigSnapshot` ships its zones AND
its policies atomically, but the live forwarding zone table is empty on a fresh
boot (and stale on a new-zone commit / an HA standby's first sync) — it is only
populated by `populate_zones(snapshot)` LATER inside `build_forwarding_state`.
The integrity preflight therefore resolves a rule's zones against the INCOMING
snapshot's OWN zones via the shared `policy::zone_name_to_id_from_snapshot`
helper (the same validated `{name → id}` map `populate_zones` installs), NOT
against the live table. Resolving against the empty live table would flag every
concrete-zone policy as `UnresolvableZoneReference` and reject the whole boot
snapshot. A policy referencing a zone genuinely ABSENT from `snapshot.zones`
still fails closed.

Regression coverage: `unknown_zone_pair_fails_closed`,
`unknown_single_wildcard_zone_fails_closed`, `resolvable_zone_pair_still_compiles`
(over-reject guard), `global_policy_unknown_zone_context_fails_closed` in
`userspace-dp/src/policy_tests.rs`; and the apply-path integration tests
`reconcile_fresh_boot_concrete_zone_policy_passes_preflight_3402` (fresh boot
with concrete-zone policy succeeds — RED if the preflight reverts to the live
table) and `reconcile_policy_references_undefined_zone_still_fails_closed_3402`
(undefined zone still rejected) in `userspace-dp/src/afxdp/coordinator/tests.rs`.

### #3300 — Dynamic-address `address-name … feed-name` cross-reference gate

A `security dynamic-address address-name <addr> profile feed-name <feed>`
binding records `<feed>` verbatim into `AddressBinding.FeedNames`
(`compileDynamicAddress`, `compiler_services.go`) with no cross-reference
against the configured `feed-server`s. The `feed-name` schema leaf is a
free-form value (`schema_security.go`), so the #2008/#2009 undefined-token
gate does NOT catch a typo. At runtime an unknown feed name resolves to a
non-nil EMPTY prefix set (`feeds.Manager.SnapshotForBindings`, `feeds.go`),
so the AF_XDP address book gets a book ID matching NOTHING — fail-closed,
which is correct for a "declared but not yet fetched" feed but
indistinguishable from a typo. A feed-backed deny policy then silently
denies nothing, with no commit error.

**`validateDynamicAddressFeedReferencesStrict`** (`compiler_validate_strict.go`)
restores Junos commit-time parity: a binding whose `feed-name` resolves to no
declared feed is hard-rejected at commit / commit-check, with a message
naming both the address-name and the unknown feed-name. The valid feed-name
set is computed exactly as `feeds.Manager` keys feeds (`feeds.go` Start): each
`feed-server`'s `feed-name` entries, or — for a single-feed server with no
explicit `feed-name` — the server name itself.

A second gate closes the same fail-open at the feed-server **root**:
**`validateDynamicAddressFeedServerEndpointStrict`** (run just before the
cross-reference gate) hard-rejects a `feed-server` with neither `url` nor
`hostname`. `feeds.Manager.Apply` derives a server's base URL via
`resolveBaseURL` (explicit `url`, else `https://<hostname>`, else `""`) and
SKIPS a server whose base URL is empty — it registers NONE of its feeds. Such
a server still compiles into `DynamicAddress.FeedServers`, so its feed names
are syntactically "declared", but no feed exists at runtime: a bound
address-name resolves to a match-nothing book exactly as a typo'd feed-name
would. Rejecting the endpoint-less server at its root ALSO makes the
cross-reference gate's declared-feed set EXACT — every server it trusts is one
`Apply` would actually register. The gate replicates `resolveBaseURL`'s
emptiness condition (`feedServerBaseURLEmpty`) directly on the `FeedServer`
struct rather than importing `pkg/feeds` (no import cycle), mirroring it
BRANCH-FOR-BRANCH: `resolveBaseURL` prefers `url` and returns
`strings.TrimRight(url, "/")` BEFORE it ever falls back to `hostname`, so a
slash-only `url` (`/`, `//`) trims to `""` and the server is skipped EVEN when
a hostname is also set — a flat `url=="" && hostname==""` check would miss it
(`/` is a valid lexer identifier char, accepted by the schema with no
url-format validation). No whitespace trimming is performed (resolveBaseURL
only `TrimRight`s `"/"`). Keep `feedServerBaseURLEmpty` in sync with
`resolveBaseURL`.

**Strict/lenient split (flag `lenientDynamicAddressFeedRef`, shared by both
gates):** strict on the commit / commit-check path (`CompileConfig` —
hard-reject), downgraded to a `cfg.Warnings` entry on the tolerant load /
peer-sync paths (`CompileConfigLenient` / `CompileConfigForNodeLenient`) so an
already-persisted config (older binaries never validated the reference) or a
peer-synced config still BOOTS (#1960 / #3261 fail-closed-on-load doctrine) —
the runtime stays fail-closed (match-none) for the unknown feed or skipped
server, so a leniently-loaded typo/endpoint-less server denies nothing rather
than bricking. Regression coverage:
`pkg/config/compiler_dynamic_address_feed_ref_3300_test.go`
(`TestValidateDynamicAddressFeedReferences` — the fail-on-revert guard plus
feed-entry / single-feed / server-name positive controls and the lenient
downgrade; `TestValidateDynamicAddressFeedServerEndpoint` — endpoint-less
reject, url / hostname-only positive controls, lenient downgrade).

### #3117 — Security-policy `scheduler-name` schema leaf (completion parity)

A security-policy `scheduler-name <name>` binds a class-of-service scheduler
to the policy. It is compiled — `compiler_security.go`
(`polInst.node.FindChild("scheduler-name")` → `nodeVal`, read for BOTH
zone-pair and global policies) — and an undefined reference is strict-rejected
at commit by `validatePolicySchedulerReferencesStrict`
(`compiler_validate_strict.go`, downgraded to a warning on the tolerant load /
peer-sync paths via `compiler_validate_warn.go`). The leaf was nonetheless
ABSENT from `setSchema`, so `set security policies ... policy <p> scheduler-name`
had no structural / value-slot `?` completion — a violation of the two-SSOT
rule that every compiled + validated leaf is declared in the schema tree.

The fix declares `scheduler-name` under both the zone-pair policy node and the
global policy node in `pkg/config/schema_security.go`, as a sibling of
`description`/`match`/`then`. It is an **untyped (plain string) leaf** like
`description`: the compiler consumes the raw token, and the strict
undefined-scheduler reference check remains the SSOT for rejection (no
`treeValidator` is added, so completion and validation stay in agreement and
no compiler/validator behaviour changes). Regression coverage:
`pkg/config/schema_scheduler_name_3117_test.go` — the leaf is offered by
`CompleteSetPathWithValues` for zone-pair and global policies (fail-on-revert),
and the declared form passes `SchemaValidate` without a false reject.

### #3377 — Security-policy `then` action leaves (permit/deny/reject/count completion + drift canary)

The config-mode `then` action subtree under `security policies` declared only
the `log` leaf; the terminal actions `permit`/`deny`/`reject` and the `count`
modifier lived solely in a `// permit, deny, reject, count → leaf` comment
placeholder even though the policy compiler (`compiler_security.go`,
`compilePolicy`'s `then` switch) consumes all of them. That is the
compiled-but-not-schema-visible drift the two-SSOT rule exists to prevent:
`set security policies ... then ?` completion / `?` help could not offer the
most basic policy actions. (`SchemaValidate` did not *reject* the missing
actions — `walkSchemaNode` returns nil for unknown keywords — so this was a
completion gap, not a commit-time false reject.)

The fix declares the `then` children in `pkg/config/schema_security.go` via a
shared `policyThenSchemaChildren()` factory used by BOTH the zone-pair and the
global policy `then` nodes (a factory, not a shared var, so the two scopes get
independent mutable schema trees). The child set mirrors the compiler switch
**and the EXACT supported surface**, so completion never advertises a leaf the
commit-check then rejects:

- `permit` / `reject` — declared **childless**. A bare `then permit` / `then
  reject` is supported; any child (`application-services`, `tunnel`,
  `firewall-authentication` under permit; `profile`, `tcp-reset` under reject)
  is rejected at commit by `validatePolicyThenPermitStrict` (#3114) /
  `validatePolicyThenRejectStrict` (#3115), which remain the SSOT for that
  rejection. `walkSchemaNode` ignores unknown descendants of a childless
  container, so the schema does not double-reject.
- `deny` — carries the `log`/`count` observability modifiers it legitimately
  combines with (`applyCollapsedDenyModifiers`, #3141); any other deny modifier
  is rejected by `validatePolicyThenDenyStrict`.
- `log` — carries its `session-init`/`session-close` sub-options (the exact
  tokens `compilePolicy`'s `log` arm reads).

**Parser-grouping interaction (the load-bearing detail):** declaring `deny`
(and its modifiers) as schema leaves changes how the flat-set parser groups a
collapsed `then deny log session-init count` — instead of collapsing onto the
deny node's own Keys (`Keys=["deny","log",...]`, the historical shape when
`deny` was unknown) the trailing tokens become a child node (collapsed-child or
fully nested). The #3141/#3374 reject gate read only the first child key, so
`then deny count session-init` (an orphan `session-init` with no `log`) would
have slipped through under the new shape. `validatePolicyThenDenyStrict` is now
parse-shape-agnostic: `collapsedThenActionTokens` flattens deny's modifier
tokens into the SAME sequence the compiler's `applyCollapsedDenyModifiers` acts
on (deny `Keys[1:]` plus every key of every descendant node), so the gate and
the wiring agree on the modifier set across all three AST shapes. The
now-redundant `supportedPolicyThenDenyChildren` map was removed;
`recognizedCollapsedDenyToken` is the single source of truth for the supported
deny-modifier tokens.

**All-nodes walk (review fold):** the three then-action reject gates
(`validatePolicyThenPermitStrict` #3114, `validatePolicyThenRejectStrict` #3115,
`validatePolicyThenDenyStrict` #3141) inspected only the FIRST action node via
`thenNode.FindChild`. But `SetPath` can build TWO nodes for one action: a bare
leaf (`set ... then permit`) plus a later extended form
(`set ... then permit application-services X`) as a SECOND `permit` node (this
split predates #3377 and reproduces whether or not permit/reject are schema
leaves). The compiler iterates every `then` child, so the unsupported modifier
on the second node is silently dropped — yet the FindChild-first gate checked
only the (valid) bare node. The strict commit path still rejected such a config
via the #3043 conflicting-terminal-action gate, but with a generic message; the
specific #3114/#3115/#3141 fail-open diagnostic (and, on the tolerant load /
peer-sync path where #3043 is only a warning, the specific warning) was
suppressed. All three gates now iterate every same-named action node
(`FindChildren`) and flatten each node's tokens via the shared
`collapsedThenActionTokens`; the deny gate unions `hasLog` across all deny nodes
to match the compiler's per-node accumulation onto `pol.Log`.

Regression coverage: `pkg/config/schema_policy_then_3377_test.go` — the actions
are offered by `CompleteSetPathWithValues` for both scopes, the `deny`/`log`
sub-options complete, the declared forms pass `SchemaValidate`, and a **drift
canary** (`TestSchema3377_ThenSchemaMatchesCompiler`) pins the schema `then`
child set to the compiler's `then` switch token set
(`{permit, deny, reject, log, count}`) for both scopes so a future compiled
action cannot drift back out of the schema. Reverting the schema addition turns
the completion and canary tests RED.
`pkg/config/compiler_policy_then_twonode_3377_test.go` — the two-node bypass:
a bare `then permit`/`reject`/`deny` plus a second node carrying an unsupported
modifier is rejected at commit with the SPECIFIC #3114/#3115/#3141 diagnostic
(and emits the matching lenient warning); reverting the gates to FindChild-first
turns them RED (the strict error degrades to the generic #3043 conflict and the
specific warning vanishes).

### #3148 — Global-policy `match from-zone`/`to-zone` zone context

A Junos global policy may carry optional `set security policies global policy
<p> match from-zone <z>` / `match to-zone <z>` so one global policy applies to a
chosen zone pair (or one wildcard side) instead of every zone pair. xpf
previously modeled a global policy as an all-zones fallback only — the context
was unrepresentable, so an imported vSRX policy like "apply this global deny to
all Internet-egress zones but not management" had to be hand-duplicated.

The two leaves are declared **only under the global policy `match` node** in
`pkg/config/schema_security.go` (zone-pair policies take their zones from the
surrounding from-zone/to-zone stanza, so the `match`-level leaves are
global-only — `globalOnlyPolicyMatchLeaves` in `compiler_policy_match.go`
admits them through the #3113 unsupported-leaf gate for global scope and the
gate still rejects them under a zone-pair policy). `compilePolicy` accumulates
them (via `firewallMatchValues`) into `Policy.Match.FromZones`/`.ToZones`
(`[]string`, sorted + de-duplicated; empty = all zones — #4626 M03).

**#3673 — the zone-context sibling of the #3142 tail escape.** Because
from-zone/to-zone are NOT registered `match` siblings under a zone-pair policy,
a flat-set or bracketed list that writes them after a value collapses them onto
the preceding multi:true leaf's tail (the #2419 collapse) rather than making
them a direct child — e.g. `match application any from-zone C` yields one
`application` leaf whose tail carries `from-zone C`, and `match application
[ from-zone bad ]` does the same. The #3113 direct-child scan never inspects the
tail, so from-zone/to-zone are consumed as bogus application (or, on a
source-address/destination-address tail, address) operands. The
undefined-application gate (#3144) and the address-definedness gate reject the
unknown token only because it is not defined — an operator who defines an
application/address literally named `from-zone`/`to-zone` satisfies those gates
and the reserved keyword commits silently as an operand (a fail-open).
`validatePolicyMatchLeavesStrict` now also scans the collapsed tail for the
`swallowedStructuralMatchTokens` set (from-zone/to-zone) and rejects a match
there (strict on commit, warn on the tolerant load path — #1960), mirroring the
#3142 `unsupportedPolicyMatchLeaves` tail scan. The global scope is unaffected:
there from-zone/to-zone ARE siblings, so the collapse stops at them and they
stay a legitimate direct-child match leaf. Coverage:
`pkg/config/compiler_policy_match_3673_test.go`.

On the wire the global policy keeps the `junos-global` sentinel on its
structural from/to-zone (so the dataplane classifier keeps it in the global
tier and preserves global config order) and carries the context on the additive
fields `match_from_zone` / `match_to_zone` (`PolicyRuleSnapshot`,
`omitempty` + `serde(default)` — #1961 additive; the wire fixture
`protocol_wire_v1.json` was regenerated). The dataplane resolves them into a
`GlobalZoneScope` and consults it inside the `junos-global` tier loop, so a
zone-scoped global policy is evaluated in the global ordering (after the exact
zone-pair and the #3090 `from-zone any`/`to-zone any` wildcard tiers), not
promoted ahead of them. An undefined match zone is strict-rejected at commit
(`validatePolicyZoneReferencesStrict`, downgraded to a warning on the tolerant
load path) and independently fails closed in the dataplane
(`GlobalZoneScope::Unresolved` matches nothing).

**Special-token semantics (commit gate ⇔ dataplane parity).** An OMITTED
`from-zone`/`to-zone` and an explicit `match from-zone any` / `to-zone any` are
the SAME thing — the Junos all-zones default. Both commit clean (`any` is a
reserved special token) and `build_global_zone_scope` (policy.rs) short-circuits
`""` and `"any"` to `GlobalZoneScope::Any`; without that short-circuit `"any"`
would route through `resolve_policy_zone_id` → `None` → `Unresolved` and a
`permit` global would silently over-restrict / a `deny` global silently no-op —
a commit-vs-dataplane divergence on a security leaf. The reserved `junos-host`
zone is direction-split (#3639 / #3611 Piece B): `match to-zone junos-host`
(host-INBOUND) commits and IS enforced — host-bound traffic traverses the
AF_XDP LocalDelivery gate and the dataplane consults the global tier there
(`evaluate_junos_host_policy_l3_aware`, filtered to the junos-host egress
scope, most-specific-after-exact-and-from-any). `match from-zone junos-host`
(host-ORIGINATED) is still hard-rejected by `validatePolicyZoneReferencesStrict`
at commit: locally generated traffic egresses via the kernel TX path, not the
AF_XDP RX gate, so it could only ever silently never-match (#3611 Piece A,
documented not built).

**Zone-local address books in a scoped global (#3287).** A scoped global
(`match from-zone <z>` / `match to-zone <z>`) resolves a zone-local
address-book reference (#3061) against that zone's local book — the same
zone-qualified resolution `resolveZoneLocalAddressBooks` already applied to
zone-pair policies. It rewrites a scoped global's `source-address` tokens under
its `match from-zone` scope and `destination-address` tokens under its `match
to-zone` scope to the `zone-local/<zone>/<name>` qualified entry. Without this,
the bare token kept pointing at the global book (which holds the entry only
under its qualified name), so the constraint silently resolved to match-none and
legitimate zone-scoped global traffic fell through to default-deny (or was
rejected at commit as an undefined address). An UNSCOPED global (empty / `any`
scope) names no single zone-local book and is left to resolve against the global
book. Because the simulator (`pkg/policymatch`) and the dataplane snapshot
builder both consume the post-fold compiled book, this keeps them in agreement.

Regression coverage:
`pkg/config/compiler_policy_global_zone_3148_test.go`,
`pkg/dataplane/userspace/policy_global_zone_3148_test.go`, the Rust
`global_policy_*` tests in `userspace-dp/src/policy_tests.rs`, and
`pkg/policymatch/scoped_global_zonelocal_test.go` (#3287).

### #3075 — Stable zone ids (supersedes the #2391 u8 count cap)

Security-zone ids are a **stable name-hash** (`config.StableZoneID`, `zoneid.go`):
FNV-1a/64 xor-folded into `[1, ZoneIDReservedMin-1] = [1, 65533]`, a **pure
function of the zone NAME** — never of the zone set or compile order. Adding,
renaming, or removing a zone therefore can never renumber a surviving zone, so
an established session's stored numeric zone id always reverse-resolves to the
correct name after a config edit, and both HA nodes plus a cold-booting node
compute identical ids with zero synced/persisted state. The two duplicated
positional maps (`pkg/dataplane.assignZoneIDs`, `pkg/daemon.buildZoneIDs`) both
call this SSOT; an HA-symmetry test pins them byte-identical.

**#3704 — live wire builder unified onto the SSOT.** #3075 converted
`assignZoneIDs` / `buildZoneIDs` (and every CLI/API/HA-fallback consumer) to
`StableZoneID`, but the LIVE dataplane wire builder
`buildZoneSnapshots` (`pkg/dataplane/userspace/zones.go`) was a THIRD id call
site it missed — it kept the legacy sorted-positional `uint16(i+1)`. For any
`>= 2`-zone config the wire (and thus every session's stored
`IngressZone`/`EgressZone`, the event-stream delta, and the fabric zone-encoded
MAC) diverged from the name-hash namespace everything else uses. Two live
regressions followed: session zone-name **display** reverse-mapped a positional
session id through the name-hash map and missed (wrong `zone-N` labels), and
`cluster.ShouldSyncZone(session.IngressZone)` queried the name-hash `zoneRGMap`
(`pkg/daemon.buildZoneRGMap` key space) with a positional id and always missed —
**per-RG active/active session-sync ownership collapsed to the global primary**.
#3704 makes `buildZoneSnapshots` assign `config.StableZoneID(name)` too, so the
wire id equals `CompileResult.ZoneIDs[name]` / `buildZoneIDs[name]` /
`buildZoneRGMap` key by construction — one namespace across the compiler, the
wire/session/HA path, the per-RG map, and the display reverse-map. The Rust side
already consumed the wire id name-keyed (`zone_name_to_id_from_snapshot`,
`populate_zones`), so no dataplane change was needed. Because the id is a pure
function of the NAME, a nil zone entry on one HA peer can no longer shift another
zone's id (Codex C131-M01).

This replaces the legacy sorted `1..N` positional assignment, whose ids shifted
whenever an earlier-sorting zone was added/removed and mis-mapped in-flight
session / HA-delta / status metadata carrying an old numeric id (#3075).

The zone id reaches the live AF_XDP userspace dataplane as the per-flow
ingress/egress zone in the event-stream wire record and as the zone-table key in
the forwarding snapshot. #3075 widened the three same-host **u8 chokepoints** to
**u16**: the event-stream SessionOpen/SessionClose delta
(`userspace-dp/src/event_stream/codec.rs` ↔ `pkg/dataplane/userspace/eventstream.go`),
the forwarding-snapshot zone table
(`userspace-dp/src/afxdp/forwarding_build/zones.rs` + the `policy.rs`
`zone_name_to_id_from_snapshot` SSOT helper), and the fabric zone-encoded MAC
(`forwarding/mod.rs` encode ↔ `frame/inspect.rs` decode). The widen is
same-version IPC (xpfd spawns the helper as a child; the #1917 STOP→FLIP→START +
socket recreate + FullResync drain means no frame straddles the width change), so
no record-version negotiation is required. The cross-node HA session wire was
already u16 and name-keyed.

A commit-time **collision gate** (`validateZoneIDCollisionAST`, mirroring the
#1873 tunnel-id gate) hard-rejects a config whose two zone names fold to the same
id (strict on commit/commit-check; lenient warning on load/peer-sync), using the
three-view (View 1 pre-expansion union + node0/node1 `${node}` expansion) union
discipline so the verdict is identical on both cluster nodes.

**#3719 — lenient-path collision QUARANTINE (runtime enforcement of the
warning).** The strict gate rejects a collision, but the lenient path only
**warned** while every downstream builder still published BOTH colliding zones
with the same numeric id. Two `ZoneSnapshot`s sharing an id merge two security
zones in the dataplane: the Rust id-keyed maps
(`zone_id_to_name` / `zone_host_inbound` / `zone_tcp_rst`, `populate_zones`) let
the later zone overwrite the earlier's reverse name, host-inbound admission set,
and tcp-rst bit, and both zones' interfaces/policies resolve to one id — a
zone-isolation failure the lenient warning falsely claimed was quarantined.
`config.QuarantinedZoneNames` (`zoneid.go`) is the SSOT that, for each id claimed
by more than one name, keeps the **sorted-first** name (the survivor) and
quarantines the rest. It is a pure function of the name set, so both HA nodes and
a cold-booting node agree. The userspace builder's `quarantineCollidingZones`
(`pkg/dataplane/userspace/zones.go`) applies it to the built snapshot BEFORE
publish: it **drops** the quarantined `ZoneSnapshot`, **unzones** any interface
bound to it (`Zone=""` → default-deny, fail closed), and **drops** any policy
whose from/to zone is quarantined (leaving a dangling policy→zone reference would
trip the Rust `UnresolvableZoneReference` preflight and reject the WHOLE snapshot
— a brick on a fresh boot). The rest of the config still loads (#1960 no-brick).
The id→name reverse maps resolve a colliding id to the survivor deterministically
(`config.StableZoneIDOwner`; `pkg/cli/apply.go:syslogZoneNameMap`,
`pkg/dataplane/userspace/manager_ha.go:zoneNameByID`) rather than to whichever
name won a map-iteration race. The quarantine is surfaced to the operator as a
loud one-shot `slog.Error` naming both zones, on `ProcessStatus.ZoneIDCollisions`
(`show`), and as the `xpf_userspace_zone_id_collision` 0/1 gauge, so an operator
is paged until one zone is renamed. Regression coverage:
`pkg/config/zoneid_test.go` (`TestQuarantinedZoneNamesDropsLaterColliding`,
`TestStableZoneIDOwnerReturnsSurvivor`,
`TestZoneIDCollisionLenientWarningStatesQuarantine`),
`pkg/dataplane/userspace/zones_collision_3719_test.go`
(`TestBuildSnapshotQuarantinesCollidingZone` — RED-on-revert), and
`pkg/cli/apply_syslog_zonemap_3704_test.go`
(`TestSyslogZoneNameMapCollisionResolvesToSurvivor`). A defense-in-depth Rust
backstop `SnapshotIntegrityError::DuplicateZoneId` (`zones::reject_duplicate_zone_ids`,
called before `populate_zones` in `build_forwarding_state`) rejects a snapshot
that STILL carries two different zones under one nonzero non-reserved id — the
helper-boundary guard for a corrupt / version-drifted snapshot that bypassed the
Go quarantine (regression `build_forwarding_state_rejects_duplicate_zone_ids`).

**`MaxUsableZoneID`** is now `ZoneIDReservedMin-1` (65533) — the pigeonhole bound
of the u16 stable-hash space, not the old 255-id u8 wire limit (**#2391
superseded**). The forwarding builder still rejects any id `>= ZONE_ID_RESERVED_MIN`
(`u16::MAX-1`, the reserved `JUNOS_GLOBAL_ZONE_ID` / junos-host sentinels), and
the fold guarantees a configured zone never lands there.
**`validateZoneCountStrict`** (`compiler_validate_strict.go`) remains as a cheap
O(1) pigeonhole belt (a config cannot define more distinct zones than ids); the
collision gate is the PRIMARY duplicate-id protection.

**Rust fail-closed backstop (load-bearing for unknown-name references).**
`populate_interfaces` / `populate_egress`
(`userspace-dp/src/afxdp/forwarding_build/interfaces.rs`) previously resolved a
missing zone NAME to `zone_id == 0` via `unwrap_or(0)`. They now return
`SnapshotIntegrityError::InterfaceUnknownZone` when an interface names a
non-empty zone absent from the zone table, so the snapshot load fails closed
(the apply preflight keeps the previous good state) rather than collapsing the
interface to "unknown". An interface with NO zone (empty string) stays the
legitimate "unzoned" case mapping to 0. This is load-bearing because the Go cap
only bounds the COUNT — it does not catch a version-drifted or hostile snapshot
whose interface references a zone name the snapshot never defines.

**Strict/lenient split (flag `lenientZoneCount`):** strict on the
commit / commit-check path (`CompileConfig` — hard-reject), downgraded to a
`cfg.Warnings` entry on the tolerant load / peer-sync paths
(`CompileConfigLenient` / `CompileConfigForNodeLenient`) so an
already-persisted or peer-synced over-cap config that an older binary accepted
still BOOTS (#1960 fail-closed-on-load doctrine) — the dataplane fails closed on
every overflowing zone, so a leniently-loaded over-cap config is inert (the
overflow zones do not forward). The gate runs AFTER
`validatePolicyZoneReferencesStrict`, mirroring the sibling fail-open
validators, so a structural error and a bad zone reference still win the
first-error slot. Regression coverage: `pkg/config/zone_count_cap_test.go`
(`TestZoneCountOverCapFailsCommit` — fail-on-revert guard,
`TestZoneCountAtCapCommits` — inclusive boundary anti-over-reject,
`TestZoneCountNormalConfigUnaffected`,
`TestZoneCountOverCapLenientDowngradesToWarning`) and the Rust
`interface_pointing_at_skipped_zone_fails_closed`,
`interface_with_unknown_zone_name_fails_closed`,
`interface_with_empty_zone_builds_with_zone_zero` tests in
`userspace-dp/src/afxdp/forwarding_build/tests.rs`.

### #3061 — Zone-local address books

Junos supports a per-zone address book attached inline under the zone, in
addition to the global `security address-book global`:

```
set security zones security-zone trust address-book address web-server 10.0.1.100/32
set security zones security-zone trust address-book address-set servers address web-server
```

The entry grammar is identical to the global book (`address` / `address-set`),
only the attachment point differs (no `global` wrapper). The schema leaf lives
under `security-zone` in `setSchema` (`schema_security.go`); `compileZones`
parses it into `ZoneConfig.AddressBook` via the shared
`parseAddressBookEntries`.

**Resolution order (Junos scoping):** a policy's `match source-address`
resolves against its FROM-zone book first, `match destination-address` against
its TO-zone book first, then both fall back to the global book.
`resolveZoneLocalAddressBooks` (run from `compileExpanded` after the name gate
below) folds every zone-local entry into the global
`SecurityConfig.AddressBook` under a zone-qualified internal name
(`zone-local/<zone>/<name>`) and rewrites each policy match token that resolves
zone-locally to that qualified name. A token NOT defined in the policy's zone
book is left unchanged so it resolves against the global book; when a name
exists in BOTH, the zone-local value WINS.

**Collision-proof synthetic namespace (#3061, narrowed in #4340):** real vSRX
configs almost universally name an address object after its prefix —
`net_10.0.0.0/8`, `net4_sfmix_72.52.96.201/32`, `net_2001:559:8585:200::/64` —
so the NAME legitimately contains `/` (the lexer already permits `/` in an
identifier, needed for the CIDR VALUE too). `/` in a name is a display
identifier, never a structural token: the whole downstream resolution path
(`policyMatchNamedAddressRefs`, `resolveUserspaceAddressBookEntry`,
`classifyPolicyAddresses`, the wire snapshot) keys objects by the FULL name via
direct map lookups, so a `/`-bearing name resolves correctly end to end.
`validateAddressBookEntryNamesStrict` (run BEFORE the fold, on the pristine
global book) therefore enforces only the two invariants the synthetic
`zone-local/<zone>/<name>` key actually needs:

1. **No operator entry name may begin with the reserved `zone-local/` prefix**
   (global or zone-local `address`/`address-set`). Otherwise a global address
   named `zone-local/trust/web-server` would collide with the synthetic name
   the fold mints for a zone-local `web-server` in zone `trust`, and the fold's
   no-clobber guard would silently drop the zone-local entry. Reserving only
   the PREFIX — not every `/` — keeps `/` free elsewhere in a name.
2. **No security-zone NAME may contain `/`.** The zone is the `/`-free first
   segment after the prefix; `ZoneLocalUnqualify` splits zone from name on the
   FIRST `/`, so a `/`-free zone keeps the split unambiguous even when the
   address name that follows contains `/` (`zone-local/trust/net_10.0.0.0/8`
   → zone `trust`, name `net_10.0.0.0/8`). Zones never carry a prefix-in-name
   convention, so this costs nothing real.

Only the NAME is checked, never the address VALUE/prefix. Strict on commit /
commit-check; the tolerant load / peer-sync path (`lenientAddressBookNames`)
downgrades the reserved-prefix / zone-slash reject to a warning (#1960
no-brick), backstopped by the fold's no-clobber guard (it skips a global-book
key that already exists).

After this pass the whole downstream resolution path
(wire snapshot, `nameToID`, `classifyPolicyAddresses`, the strict/warn
validators, the `resolveUserspaceAddressBookEntry` runtime resolver) keeps
operating on a single flat global book.

**Scoping:** a name present only in zone A's book is invisible to a policy in
zone B. If B's policy references it and the global book has no such entry,
`validatePolicyMatchAddressesStrict` (#2008) rejects it at commit, exactly as
Junos treats an undefined reference. NAT rule address-name references
(`source-address-name` etc.) remain global-only; zone-local resolution is
scoped to security-policy match addresses. Regression coverage:
`pkg/dataplane/userspace/zone_local_addressbook_3061_test.go`
(`TestZoneLocalAddressBookResolves` — fail-on-revert resolution guard,
`TestZoneLocalAddressBookScoping` — precedence + cross-zone isolation) and
`pkg/config/addressbook_name_slash_3061_test.go`
(`TestAddressBookReservedPrefixNameRejected`,
`TestAddressBookZoneLocalReservedPrefixRejected`,
`TestSecurityZoneNameSlashRejected` — collision-safety fail-on-revert guards,
`TestAddressBookNameSlashNormalConfigUnaffected` — prefix-value anti-over-reject,
`TestAddressBookReservedPrefixLenientDowngrades` — tolerant-path warning) and
`pkg/config/addressbook_name_slash_4340_test.go`
(`TestAddressBookSlashNameCommits` — prefix-named objects commit + resolve,
`TestAddressBookSlashNameZoneLocalFoldRoundTrips` — fold + unqualify round-trip
of a `/`-bearing zone-local name) plus
`pkg/dataplane/userspace/addressbook_slash_name_4340_test.go`
(`TestPolicySlashNameResolvesToPrefix` — end-to-end dataplane resolution).

**Operator display (#3358).** The synthetic `zone-local/<zone>/<name>` key is an
INTERNAL identity, never an operator-facing string. The display surfaces that
render a policy's match addresses unqualify it back to the authored name via
`config.ZoneLocalUnqualify` / `config.DisplayAddressName(s)` (the inverse of
`zoneLocalQualify`, unambiguous because no operator name contains `/`): the CLI
`show security policies detail` renders `web(zone trust): <prefix>` (NOT the old
`zone-local/trust/web(global)` — a zone-scoped object must not be mislabelled
`(global)`), the CLI standard `show security policies` view shows the bare
authored name (`joinDisplayAddressNames`), the gRPC `show security policies`
text shows `web (<prefix>)`, and the REST (`GET /api/v1/security/policies`) +
gRPC (`GetPolicies`) inventories list the bare authored name (`web`), with the
zone implied by the rule's from/to-zone. `show security match-policies` is
covered at its SSOT: `policymatch.matchedResult` (the shared simulator feeding
all three match-policies transports — CLI, gRPC `MatchPolicies`, REST
`MatchPoliciesResult`) unqualifies `Result.Src/DstAddresses` once, so no
transport leaks the token. `Result.Src/DstAddresses` are display-only —
re-matching reads `pol.Match` directly — so the unqualification cannot affect
the verdict. CIDR resolution still keys off the qualified token (it is the
global-book key). Regression coverage:
`pkg/config/zone_local_unqualify_3358_test.go` (helper round-trip + no-op
fall-through + non-mutation),
`pkg/cli/cli_show_security_zone_local_3358_test.go` (detail view, source +
destination, with a global-name control),
`pkg/cli/cli_show_security_flat_zone_local_3358_test.go` (standard flat view),
`pkg/grpcapi/server_show_policies_zone_local_3358_test.go` (GetPolicies + text),
`pkg/api/security_zone_local_3358_test.go` (REST inventory), and
`pkg/policymatch/zone_local_display_3358_test.go` (match-policies SSOT).

### #2399 — firewall-filter unknown `then` action + unsupported `from protocol` (commit fail-closed)

Two fail-OPEN behaviors in the firewall-filter compiler, both now rejected
at commit (the firewall-FILTER analog of the #2401 policy fail-closed
pattern). Provenance: codex review-032 findings 032-16 / 032-17.

**(032-16) Unknown `then` action → silent ACCEPT.** A filter term whose
`then` block carries a token that is neither a recognized terminating
action (`accept`/`reject`/`discard`) nor a recognized modifier
(`count`/`log`/`syslog`/`forwarding-class`/`loss-priority`/`dscp`/
`traffic-class`/`policer`/`routing-instance`) was historically DROPPED by
`compileFilterThen` (no default arm). The term's `Action` stayed `""`,
which the dataplane compiler (`pkg/dataplane/compiler_filter.go`) and the
Rust filter (`userspace-dp/src/filter/compiler.rs` `parse_term`) both map
to `FilterAction::Accept` — a term the operator meant to DENY (a misspelled
`then accpet`, or a newer action a peer node understands) silently became a
PERMIT, and commit reported SUCCESS. Junos rejects an unknown filter action
at commit. `compileFilterThen` now records the unrecognized token on
`FirewallFilterTerm.UnknownActions`, and **`validateFilterActionsStrict`**
(`compiler_validate_strict.go`) hard-rejects any term carrying one, naming
the family / filter / term / offending token. Note that an EMPTY action
(`Action == ""`) is the legitimate "no terminating action" case (a term
with only modifiers falls through to the next term) and is NOT flagged.
Two more VALID Junos constructs are recognized so a real config import is
NOT over-rejected: `then reject <message-type>` (the standard ICMP-unreachable
codes plus `tcp-reset`) commits as a plain reject and captures the type on
`FirewallFilterTerm.RejectMessageType` for fidelity — the dataplane acts only
on `FilterAction::Reject` today, so the type is compile-time-only (no wire
field); and `then next term` / `then next` (explicit fall-through) commits as
a no-op, marked `FirewallFilterTerm.NextTerm`. A token after `reject` that is
NOT a known message-type is still a typo and IS flagged.
Defense-in-depth in the Rust filter: a NON-EMPTY unrecognized action (only
reachable via a mixed-version snapshot now that commit rejects it) fails
CLOSED to `Discard`, never `Accept`; the empty string keeps the
fall-through `Accept` semantics.

**(032-17) Unsupported `from protocol` alias → dropped constraint.**
Already handled by #2175 — **`validateFilterProtocolsStrict`** rejects a
`from protocol <token>` that the centralized `appid.ProtocolNumber` SSOT
cannot resolve (a name, a `junos-*` alias, or a 0..255 number). Without the
gate an unresolvable alias was silently dropped from the protocol set, so
the term matched ALL protocols. Documented here for completeness; no new
code in #2399.

**Strict/lenient split (flag `lenientFilterActions`, sibling of
`lenientFilterProtocols`):** strict on the commit / commit-check path
(`CompileConfig` — hard-reject), downgraded to a `cfg.Warnings` entry on
the tolerant load / peer-sync paths (`CompileConfigLenient` /
`CompileConfigForNodeLenient`) so an already-persisted or peer-synced
config carrying an unknown action still BOOTS (#1960 fail-closed-on-load
doctrine). The gate runs immediately after `validateFilterProtocolsStrict`.
Regression coverage: `pkg/config/compiler_filter_action_test.go`
(`TestFilterAction_UnknownAction_RejectsAtCommit` and the
misspelled/inet6 variants — fail-on-revert guards,
`TestFilterAction_ValidActions_Commit` — anti-over-reject across every
terminating action and modifier + a modifier-only fall-through term + the
reject message-types + `next term`, `TestFilterAction_RejectMessageType_-
CommitsAndCaptures`, `TestFilterAction_NextTerm_CommitsAndMarks`,
`TestFilterAction_UnknownRejectMessageType_RejectsAtCommit` — a typo after
reject still rejects, `TestFilterAction_Unknown_LenientWarns`,
`TestFilterAction_CompileCapturesUnknownToken`) and, on the Rust side,
`userspace-dp/src/filter/tests.rs`
(`unknown_nonempty_action_fails_closed_discard`,
`empty_action_falls_through_to_accept`).

### #4375 — firewall-filter conflicting terminating actions (commit fail-closed)

Junos treats the three terminating actions `accept` / `reject` / `discard`
as **mutually exclusive**: a filter term has at most ONE terminating action.
xpf stores the resolved action on the single-valued `FirewallFilterTerm.Action`,
which `compileFilterThen` overwrites **last-write-wins** — so a term carrying
BOTH `then accept` AND `then reject` (in one `then {}` block or across two, since
#3850 applies every block) silently compiled to whichever keyword appeared last.
Commit reported SUCCESS, the operator's intent was ambiguous, and the compiled
behavior did not necessarily match what they wrote — a silent misconfiguration.
Provenance: avo-review-007 H3.

`compileFilterThen` now records EVERY terminating keyword it sees on
`FirewallFilterTerm.TerminalActions` (in order, with duplicates), and
**`validateFilterTerminalConflictStrict`** (`compiler_validate_strict_filter.go`)
hard-rejects any term whose **distinct**-terminal count exceeds one, naming the
family / filter / term / the conflicting actions. Two constructs are explicitly
NOT flagged so a real config is not over-rejected: repeating the SAME terminal
(e.g. two `then discard` blocks — a redundancy, one distinct terminal), and a
non-terminating modifier co-located with exactly one terminal (`then count X
accept` — `count`/`log`/`forwarding-class`/`loss-priority`/`dscp`/
`traffic-class`/`policer`/`routing-instance` are NOT terminals and coexist with
one). `then routing-instance` co-located with a terminating `discard`/`reject`
is a separate contradiction handled by `validateFilterRoutingInstanceConflict-
Strict` (#3308); `next term` is a fall-through control, not a terminating action.

**Strict/lenient split (flag `lenientFilterTerminalConflict`, sibling of
`lenientFilterRoutingInstanceConflict`):** strict on the commit / commit-check
path (`CompileConfig` — hard-reject), downgraded to a `cfg.Warnings` entry on the
tolerant load / peer-sync paths (`CompileConfigLenient` /
`CompileConfigForNodeLenient`) so an already-persisted or peer-synced config
carrying a contradictory term still BOOTS (#1960 fail-closed-on-load doctrine) —
the last-wins `Action` drives the dataplane deterministically on that boot. The
gate runs immediately after `validateFilterRoutingInstanceConflictStrict`.
Regression coverage: `pkg/config/firewall_terminal_conflict_4375_test.go`
(accept/reject, accept/discard, reject/discard conflicts + inet6 — fail-on-revert
guards; `then count X log accept`, a single terminal, and duplicate-same-terminal
accepted — anti-over-reject; lenient path does not hard-fail).

### #3445 — lo0 input-filter `then` modifiers: nft-mirror support policy (commit warning)

The lo0.0 input filter (`interfaces lo0 unit 0 family inet[6] filter input
<name>`) is mirrored onto a kernel nftables chain (`inet xpf_lo0`,
`pkg/daemon/daemon_nft.go`) because the XDP shim shunts ordinary host-bound
traffic to the Linux kernel before it reaches userspace-dp — so that chain is the
PRIMARY enforcement of the lo0 filter for host traffic. Every non-terminating
`then` modifier now has an explicit policy rather than being silently dropped
from the mirror (the pre-fix action switch read only `term.Action`):

- **Honored on the kernel mirror:** `then log` / `then syslog` → an nft `log`
  statement; `then count <name>` → a NAMED nft counter. These commit with no
  warning.
- **Warned (cannot be faithfully honored on a `hook input` chain):**
  `then policer` (Junos bandwidth+burst token bucket with a configurable
  then-action; nft `limit` cannot reproduce it), `then dscp` (traffic-class
  rewrite) and `then forwarding-class` (egress CoS selection is meaningless for
  locally-delivered traffic). **`validateLo0FilterKernelMirrorWarnings`**
  (`compiler_validate_warn.go`, wired into `ValidateConfig`) emits a commit
  WARNING naming the family / filter / term / modifier so the operator knows the
  kernel host-bound path will not enforce them (userspace remains authoritative
  for whatever lo0-filtered traffic actually reaches the XSK). It is WARN-only —
  these are valid Junos and a hard reject would brick a boot on a
  previously-committed config — and SCOPED to the lo0 input filter (the same
  modifier on an interface filter is userspace-enforced and not warned).
  `then loss-priority` is already reported globally inert by
  `validateFilterLossPriorityWarnings` (#2507), which subsumes the mirror gap.
- **`reject`** is lowered to a faithful TCP-RST + ICMP/ICMPv6
  administratively-prohibited pair mirroring the userspace reject-reply synthesis
  (see `pkg/daemon/README.md` "lo0 input filter").

Regression coverage: `pkg/config/compiler_lo0_mirror_modifiers_3445_test.go`
(warns per modifier, commit-succeeds, scoped-no-false-positive,
honored-modifiers-no-warn) and, on the nft-generation side,
`pkg/daemon/lo0_filter_test.go` (`TestNftRuleFromTermLogMirror`,
`TestNftRuleFromTermCountMirror`, the faithful-reject pair, shared-counter
single-declaration). Like the other firewall-filter gates these are
compiler/daemon-side, not typed `setSchema` leaves.

### #2545 — firewall-filter `from protocol`/`dscp`/`icmp-type`/`icmp-code` are multi-value (match-ANY)

`protocol`, `dscp`/`traffic-class`, `icmp-type`, and `icmp-code` are all
schema-declared `multi: true` (`schema_cos.go`), and Junos accepts the
match criterion repeated within one `from` block. Historically the typed
term stored them as SCALARS (`Protocol string`, `DSCP string`,
`ICMPType int`, `ICMPCode int`), and `compileFilterFrom` OVERWROTE on each
repeated child — the LAST value won and earlier constraints were silently
dropped. `from protocol tcp; from protocol udp` compiled to
`Protocol == "udp"`, losing the TCP constraint with no commit error.

The typed term now carries SLICES — `Protocols []string`, `DSCPs []string`,
`ICMPTypes []int`, `ICMPCodes []int` (the existing `SourcePorts`/`TCPFlags`
shape) — and `compileFilterFrom` APPENDS every value across both parser AST
shapes (repeated hierarchical children, a bracket list `[ tcp udp ]`, and
repeated flat-set commands), via the `firewallMatchValues` helper. An EMPTY
slice means the criterion is unconstrained (matches any), exactly like the
prior empty-string / `-1` sentinels.

**Wire + dataplane.** `protocol` and `dscp` were ALREADY vectors on the
wire (`FirewallTermSnapshot.Protocols []string` → Rust `protocol_bitmap`;
`DSCPValues WireUint8List` → Rust `dscp_bitmap`) — the chokepoint was only
the Go typed config, which now populates the full set. `icmp-type` /
`icmp-code` were SCALAR on the wire (`*uint8` / `Option<u8>`, exact
equality) and are extended to vectors: `ICMPTypes`/`ICMPCodes`
(`WireUint8List`, JSON `icmp_types`/`icmp_codes`) on the Go side and
`Vec<u8>` → 256-bit `icmp_type_bitmap`/`icmp_code_bitmap` set-membership on
the Rust side (`per_packet_l4_matches`). The wire specimen
`userspace-dp/tests/fixtures/protocol_wire_v1.json` was regenerated for the
field rename. Match semantics: a term matches if the packet's protocol /
dscp / icmp-type / icmp-code is IN the corresponding set (match-ANY within
a field), AND across fields; an empty set leaves the field unconstrained
(the `l4_present` fail-closed gate for icmp on non-first fragments is
preserved). The retired-eBPF `pkg/dataplane/compiler_filter.go` (no longer
the runtime path) keeps the first value of each set so it still compiles.
Regression coverage: `pkg/config/firewall_multivalue_2545_test.go` (both
AST shapes + bracket list, fail-on-revert), the snapshot emit test
`pkg/dataplane/userspace/filters_multivalue_2545_test.go`, and the Rust
matcher `icmp_type_multi_value_matches_any_in_set_2545` /
`icmp_type_empty_set_matches_any_2545`.

### #2622 — firewall-filter `source-port-except` / `destination-port-except` (negated port match)

Junos firewall filters accept the negated port match conditions
`from source-port-except` / `from destination-port-except`: match every
port EXCEPT the listed ones (the inverse of the positive `source-port` /
`destination-port`). xpf previously had no schema leaf, so migrating a
config carrying a port exclusion failed to parse / silently dropped the
condition. The two leaves are added to `schemaFirewall`'s `from` block in
`schema_cos.go` (BOTH `family inet` and `family inet6`), `multi: true` so a
bracketed list `[ 80 443 ]` collapses onto one leaf per #2419.

The typed term carries `SourcePortsExcept []string` /
`DestPortsExcept []string` (`types_system.go`), populated by
`compileFilterFrom` via `firewallMatchValues` (same accumulation as the
positive port slices, both AST shapes).

**Wire + dataplane.** Two additive wire fields on `FirewallTermSnapshot` —
`source_ports_except` / `destination_ports_except` (Go
`pkg/dataplane/userspace/protocol.go`, Rust `protocol/security.rs`,
`serde(default)` for #1961 mixed-version parity). The Rust compiler
(`filter/compiler.rs`) selects ONE port spec list per direction — the
positive list if it carries real entries, otherwise the `-except` list — and
sets a per-direction `source_port_except` / `dest_port_except` inversion flag
on `FilterTerm`. A positive port match and its `*-port-except` counterpart are
mutually exclusive in the same direction; the Go commit gate
`validateFilterPortExceptStrict` (#3297) rejects a term carrying both, and the
Rust compiler resolves a drifted/leniently-loaded snapshot that has both as
positive-wins (the except list is ignored — a deliberate narrowing, never a
widening). The matcher `port_match` (`filter/engine/matching.rs`) evaluates
`matcher.matches(port) XOR except` for a RESOLVED port set, mirroring the
address `nets_match_v4` / `nets_match_v6` `except` inversion. #3205 hardened
the all-malformed case: an except term whose port list ALL fails to parse
(constrained + empty `PortMatcher::Any`) FAILS CLOSED = match NOTHING in BOTH
directions — NOT "match all ports except {}" = match ALL. A port scope has no
prefix-list indirection, so `constrained + Any` can only mean every token was
unparseable; `validateFilterMatchValuesStrict` rejects such a term at commit,
making the fail-closed matcher defense-in-depth on the tolerant load / peer-
sync path. (The empty-except = match-ALL semantic still applies to the ADDRESS
path, where an empty prefix-list scope is reachable and legitimate.) The wire
specimen `userspace-dp/tests/fixtures/protocol_wire_v1.json` was regenerated
for the two new fields. Regression coverage:
`pkg/config/firewall_port_except_2622_test.go` (hierarchical + flat-set
bracket list + inet6, fail-on-revert) and the Rust matcher
`destination_port_except_negation` / `source_port_except_negation`
(a port IN the except list does NOT match; a port NOT in it DOES —
fail-on-revert), plus `destination_port_except_unresolved_fails_closed_3205` /
`destination_port_except_resolved_name_matches_3205` (#3205 fail-closed) and
`port_both_positive_and_except_positive_wins_3716` (#3716 positive-wins
boundary pin). Scope: ports only; `packet-length` from the same review-039
finding is NOT implemented here.

### #2053 — Config secret redaction at JSON/YAML marshal time

The compiled `*config.Config` carries every operator secret verbatim in
memory (it must — the reconciler/render paths need the cleartext). The
hazard is that a *marshaller* of that struct leaks it. There was a live
leak: `GET /api/v1/config` (`pkg/api/config.go` `configHandler` →
`writeOK(w, store.ActiveConfig())`) JSON-encodes the whole compiled config,
so before #2053 it returned every secret in plaintext to any authorized
REST client (loopback by default, but bindable non-loopback over HTTPS via
`web-management https interface`). The per-struct `String()` redaction
(logging hygiene) did NOT close this — `encoding/json` ignores `Stringer`.

The fix is type-enforced, not by-convention. **`config.Secret`**
(`pkg/config/secret.go`) is a named `string` type whose value-receiver
`MarshalJSON` / `MarshalYAML` emit the sentinel `config.SecretRedacted`
(`<redacted>`) for a non-empty value and `""` for empty (so unset stays
distinguishable). `Reveal()` returns the cleartext for render/reconcile
sites; `String()` redacts for `%v`/`%s`/slog; `UnmarshalJSON` accepts a
plain string but REFUSES the sentinel (fail-closed if a compiled-config
JSON ingest is ever added — none exists today, the SSOT is the `*ConfigTree`
AST). Because the receiver is a value, redaction fires for a `Secret` struct
field, in a `[]Secret` slice (`APIKeys`), and as a map value.

**Converted fields (16):** `IKEPolicy.PSK`, `IPsecVPN.PSK`
(`types_security.go`); `OSPFInterface.AuthKey`, `RIPConfig.AuthKey`,
`ISISConfig.AuthKey`, `ISISInterface.AuthKey`, `BGPNeighbor.AuthPassword`,
`TunnelConfig.WgLocalPrivkeyHex` (`types_routing.go`); `VRRPGroup.AuthKey`
(`types_interfaces.go`); `RootAuthConfig.EncryptedPassword`,
`LoginUser.EncryptedPassword`, `APIAuthUser.Password`, `APIAuthConfig.APIKeys`
(`[]Secret`), `SNMPv3User.AuthPassword`, `SNMPv3User.PrivPassword`,
`DHCPDynamicDNSConfig.TSIGSecret` (`types_system.go`).

**SNMP community string** is a special case: it is the secret AND the
`SNMPConfig.Communities` map key, so `SNMPCommunity.Name` stays a plain
`string` (map lookup in `pkg/snmp` is by the on-wire community string) and
redaction is done with targeted marshallers — `SNMPCommunity.MarshalJSON`
redacts the `Name` field, and `SNMPConfig.MarshalJSON` renders the
`Communities` map as a sorted slice so the secret never leaks as a JSON
object key. Text `show snmp` / `show configuration` print the map key, not
the marshalled struct, so the #2053 marshaller does not cover them — the
raw-AST render path is closed separately in **#4051 below** for the remote
surfaces (REST + gRPC), while the on-box CLI stays cleartext (operators read
their own secrets — Junos parity).

**Borderline fields left as plain string** (rulings): `MasterPassword`
(commit-encryption PRF selector, not a user secret), `ArchiveSitesWithPassword`
(URLs whose inline password was already discarded), `SSHKeys` /
`LoginUser.SSHKeys` (public keys). **Round-trip is safe** — nothing
unmarshals a compiled `*config.Config` (persistence/HA-sync ship the AST
tree, not the compiled struct), so a redacting marshaller cannot starve any
consumer. **Adding a new secret config field is one annotation:** type it
`config.Secret` and call `.Reveal()` at the render site (the compiler finds
every reader). Do NOT feed `Reveal()` output into a log line. Regression
coverage: `pkg/config/secret_test.go` (marshal/unmarshal/slice/map/SNMP) and
`pkg/api/config_secret_redaction_test.go` (the live `GET /api/v1/config`
leak net + in-memory-cleartext-preserved render guard).

### #4051 — Raw-AST secret redaction on the config display endpoints

#2053 closed the leak on the TYPED compiled-config marshal (`GET
/api/v1/config`) but NOT on the raw-AST render surface. The
`*ConfigTree` serializers in `ast_format.go` (`Format` / `FormatSet` /
`FormatJSON` / `FormatXML` / `FormatInheritance` / `FormatCompare`) print
leaf key tokens VERBATIM, so the endpoints that render the AST returned the
same secrets in CLEARTEXT: the REST config **show / export / search /
rollback** handlers (`pkg/api/config.go`) and the gRPC **ShowConfig /
ShowCompare / ShowRollback** RPCs (`pkg/grpcapi/server_config.go`). Combined
with a non-loopback REST bind an attacker could read every PSK / auth-key /
SNMP community. Junos redacts secrets in `show configuration`
(`SECRET-DATA`); xpf's raw-AST paths did not (fable-161 F-020).

The fix is a DISPLAY-only AST transform. **`ConfigTree.RedactedClone()`**
(`pkg/config/ast_redact.go`) returns a deep clone with every secret leaf
value masked by **`config.SecretDataPlaceholder`** (`##SECRET-DATA##`, the
Junos `SECRET-DATA` idiom — deliberately distinct from the typed-struct
`<redacted>` sentinel so the two surfaces stay independently greppable). It
walks the tree on the FLATTENED key path so a secret is matched identically
in both AST shapes (hierarchical parse vs a flat-set collapsed leaf,
CLAUDE.md dual-shape rule). The masked render is byte-identical to the
cleartext render except at the secret tokens and stays structurally valid
(the placeholder is quoted where needed).

**Secret-leaf set = #2053's `config.Secret` field set** resolved to AST
keyword signatures (verified against the compiler's `Secret(...)` sites):
distinctive keywords `pre-shared-key` (keeps the `ascii-text`/`hexadecimal`
qualifier), `authentication-key`, `authentication-password`,
`privacy-password`, `encrypted-password`, `simple-password`, `api-key`,
`tsig-secret`, `api-token`, `aws-secret-key`, `private-key`,
`preshared-key`; and three GENERIC keywords disambiguated by required
ancestor context so a non-secret look-alike is never masked — `key` only
under `authentication md5 <id>` (OSPF hello key, not a GRE tunnel `key` or a
chassis device-map identity `key`), `password` only under `api-auth` /
`dynamic-dns` (not a future non-secret `password`), and `community` only
directly under `snmp` (the v1/v2c community IS the secret — masked as a
container-identity token — not a `policy-options community` routing object).

**Redaction is applied at the REST + gRPC boundary only.** The cleartext
`Store.Show*` methods remain the SSOT for **HA config sync**
(`daemon_ha_sync.go` → the peer must receive real secrets), the
**DR/compliance archive** (`daemon_flow.go`), on-disk **persistence +
rollback** (`configstore`), and the **on-box CLI** (operator reads own
secrets). The display endpoints call new redacted siblings
(`ShowActive*Redacted` / `ShowCandidate*Redacted` / `ShowRollback*Redacted`
/ `ShowCompare*Redacted` in `store_format.go`) that render a `RedactedClone`
of the source tree. The remote `cli` binary is covered transitively (it goes
through gRPC ShowConfig). Regression coverage: `pkg/config/ast_redact_test.go`
(mask-every-format + no-source-mutation + no-over-masking + qualifier-kept),
`pkg/api/config_raw_ast_redaction_test.go` (REST show/export/search),
`pkg/grpcapi/server_config_redaction_test.go` (gRPC ShowConfig incl.
path-scoped).

### #1979 — flow / flow-export NUM_WIDTH commit-time validation (Layer B)

Layer A (#1977, `pkg/dataplane/userspace/flow.go` `buildFlowSnapshot` /
`buildFlowExportSnapshot`) coerces every flow/flow-export wire field into its
Rust `u16`/`u32`/`u64` range at the snapshot boundary so an out-of-range value
cannot abort the `apply_snapshot` decode (the #1961 failure class). Layer B
adds the commit-time companion: reject the bad value at `commit check` with a
clear range error instead of silently coercing it. The bounds equal the
Layer-A caps EXACTLY (a value Layer B accepts is one Layer A leaves unchanged;
a value Layer B rejects is one Layer A would have coerced).

Layer B uses BOTH commit-check validation families, chosen per leaf by whether
the value sits in a single typed slot:

- **Typed `setSchema` leaves (Tiers 1+2 — the declarative `#1319` path):**
  - `services flow-monitoring version9 template <t> flow-active-timeout` /
    `flow-inactive-timeout` — `ValidateInteger(0, maxWireU32)` (Rust u32
    ActiveTimeout/InactiveTimeout). The parallel `version-ipfix` pair is typed
    identically for UX parity even though it does NOT reach the wire
    (`buildFlowExportSnapshot` reads `fm.Version9` only).
  - `security flow tcp-session` expanded to a container: `established-timeout`
    (Rust u64 TCPSessionTimeout), `initial-timeout`, `closing-timeout`,
    `time-wait-timeout` (config-only, not wire-reaching) all
    `ValidateInteger(0, MaxDurationSeconds)` — the Duration-overflow ceiling,
    NOT u64-max. This is the operator-facing reject; it stays in lockstep with
    the runtime saturation backstop `SessionTimeouts::from_seconds` (#2441),
    which converts `secs → ns` with `checked_mul` and saturates at
    `MAX_SESSION_TIMEOUT_NS` (`MAX_SESSION_TIMEOUT_SECS == MaxDurationSeconds ==
    i64::MAX / 1e9`) so an out-of-band snapshot or future caller that bypasses
    this gate can never wrap `secs*1e9` into a tiny premature-expiry timeout;
    plus the
    presence flags `no-syn-check`, `no-syn-check-in-tunnel`,
    `rst-invalidate-session`, and `no-sequence-check` (#2008 M9) declared
    presence-only for completion parity. The presence flags compile into
    `TCPSessionConfig` (NoSynCheck / NoSynCheckInTunnel / RstInvalidateSession
    / NoSequenceCheck) but are typed-config only — the userspace dataplane does
    not read them. The session table is a pure 5-tuple flow entry with no TCP
    state machine and no sequence/window tracking, so there is nothing for any
    of these knobs to enforce or skip. **#2078:** setting any of them emits a
    single accepted-only commit advisory (`pkg/config/compiler.go`,
    `security flow tcp-session ... accepted-only`) so an operator is not
    silently misled; research #2078 converged PLAN-KILL on enforcement.
    The RST design rationale (suppress RST→CLOSED for ESTABLISHED, keep
    `rst-invalidate-session` as the opt-in override) is in
    `docs/active-active-new-connections.md`. The dead legacy `flow_config_map`
    `TCPFlags` write was removed in #2078 (the map was retired with the eBPF
    dataplane, #1373/#1476).
  - `security flow udp-session` / `icmp-session` expanded to a container with a
    typed `timeout` (`ValidateInteger(0, MaxDurationSeconds)`).
  - `security flow aging` expanded from an opaque untyped node (#3440 H2) to a
    container with three typed integer leaves: `early-ageout`
    (`ValidateInteger(0, 86400)`, seconds, 0 = disabled), `high-watermark` and
    `low-watermark` (`ValidateInteger(0, 100)`, percent of max sessions, 0 =
    disabled). The cross-field rule (`low-watermark < high-watermark` when both
    nonzero) and unknown-leaf rejection live in `validateFlowAgingStrict`
    (`compiler_validate_strict.go`, dispatched from `compiler.go` with a
    `lenientFlowAging` no-brick downgrade) because the schema walker is
    single-leaf. **#3440 H1:** watermark aging drives only the Go-side
    conntrack GC hysteresis, which is skipped on the userspace AF_XDP
    dataplane (the only runtime forwarding path), so setting any aging knob
    emits an accepted-only commit advisory (`compiler_validate_warn.go`,
    `security flow aging ... accepted-only`) — typing the schema only stops
    invalid values from persisting, it does not make the knob enforced.
    Per-application `inactivity-timeout` (#3227) is a separate, fully-enforced
    idle-timeout knob and is unaffected.
  - `security flow` accepted-only knobs (#4231, fable-167 P-3): five leaves
    that previously had no schema entry and no compiler case, so they committed
    clean and did nothing with zero operator signal. Now typed +
    compiler-recorded: `route-change-timeout` and `multicast-session-lifetime`
    (`ValidateInteger(6, 1800)`, seconds — the Junos bounds), and three
    presence flags `sync-icmp-session`, `force-ip-reassembly`,
    `preserve-incoming-fragment-size`. None reach the dataplane wire; each
    emits a commit advisory (`compiler_validate_warn.go`, the #2078 doctrine).
    `sync-icmp-session` carries a DISTINCT advisory: it is a no-op not because
    it is unenforced but because xpf already syncs ICMP sessions to the HA peer
    UNCONDITIONALLY — the session-sync path is protocol-agnostic
    (`publish_shared_session` / `snapshot_all_sessions_export` in `userspace-dp`
    apply no protocol filter, and `pkg/cluster` has no protocol filter), so the
    Junos opt-in knob has nothing to turn on and cannot turn it off.
  - Container-level accepted-but-inert advisories (#4232, fable-167 P-4): the
    `setSchema` gate is opt-in (unknown keywords pass to the compiler), and the
    exhaustive policy `match`/`then` gates (#3113/#3114/#3115) do NOT cover the
    `policy <name>` level itself or the `security alg <proto>` level, so a
    typo'd direct policy child (`descripton`, `scheduler-nam`) and an
    unimplemented ALG proto (`h323`, `msrpc`, ...) were silently dropped.
    `compilePolicy` now records unrecognized policy children
    (`Policy.UnknownChildren`) and `compileALG` records unwired ALG protos
    (`ALGConfig.UnsupportedProtos`); `compiler_validate_warn.go` emits an
    accepted-but-inert / probable-typo advisory for each. These are advisories,
    not strict rejects — a harder allowlist-reject at these container levels is
    the deeper parity move and is deferred.
  - `forwarding-options sampling instance <i> input rate` —
    `ValidateInteger(0, maxWireU32)`. **0 is accepted** (the documented
    `0 = sample all` sentinel, `types_system.go`; Layer A normalizes
    `rate<=0 -> 1`) — EXACT Layer-A agreement, rejecting only the
    decode-aborting `>u32max`.
  - `forwarding-options sampling … output flow-server <addr> port` —
    `ValidateInteger(1, maxWireU16)` (Rust u16 CollectorPort; Layer A skips a
    server whose port is `<1` or `>65535`). `flow-server` keeps `args:1` for
    the collector address and gains a children map (the typed `port` plus the
    other compiler-read children `version9-template`, `version9 { template }`,
    `version-ipfix-template`, `version-ipfix { template }`, `source-address`),
    which deliberately flips a BARE `flow-server <addr>` from single-value
    REPLACE to named-container APPEND — benign: a bare no-port server compiles
    `Port==0` and the snapshot builder skips it, and real multi-collector
    configs already take the container path. The `version9` / `version-ipfix`
    per-server selectors bind the collector to exactly one export protocol
    (Junos semantics, #2136); the live Go exporter routes each flow-server to a
    single version's collector set so a collector configured under both global
    version stanzas is never double-exported (an unbound server resolves to
    IPFIX when both globals are set — see `pkg/flowexport/README.md`).
  - `forwarding-options sampling … family <af> output source-address <addr>`
    (#2605) — the **output-level** flow-export source-address: the standard
    Junos hierarchy where `source-address` is a sibling of `flow-server`
    directly under `output { ... }` (not nested inside a flow-server). It is
    the per-output default that every flow-server in that family inherits and
    is stored on the per-family `SamplingFamily.SourceAddress`. The
    output-level value also seeds `inline-jflow`'s source when inline-jflow
    sets none. The output-level form was previously dropped silently (no
    compile error and no completion entry) — `compileSamplingFamily` only
    read the flow-server-nested / inline-jflow-nested forms before #2605.
  - `forwarding-options sampling … output flow-server <addr> source-address
    <src>` (#3745) — the **per-collector** override, nested inside an
    individual flow-server. It is stored PER COLLECTOR on
    `FlowServer.SourceAddress` and **wins** over the output-level default
    for THAT collector only. `pkg/flowexport` resolves the effective bind
    per collector (`collectInstanceVersionCollectors`: nested override else
    the family default else the inline-jflow default), so two collectors of
    the same family can each pin their own source. Before #3745 the nested
    value was collapsed into the single family-wide
    `SamplingFamily.SourceAddress` (last-writer-wins across servers of the
    same family), so a second same-family collector could not bind its own
    configured source and dialed with the wrong bind. The resolved
    per-collector source is surfaced in the health surfaces (CLI `... source
    <src>`, REST `source_address`, and the `source` label on the
    `xpf_flow_export_collector_*` Prometheus metrics).
  - `forwarding-options allow-dataplane-sleep` (#2008 H13 Stage 1) — a
    presence-only flag (no value, `children: nil`). Previously accepted via the
    no-schema-match fall-through and silently dropped; now a typed leaf that
    compiles into `ForwardingOptionsConfig.AllowDataplaneSleep` and emits an
    accepted-but-unenforced commit warning (the userspace workers busy-poll;
    the idle-yield runtime is Stage 2, lab-gated). Same shape as the
    `security flow power-mode-disable` presence flag.

- **Compiler AST pre-walk (Tier 3 — the `validateVRRPTrackInterfaceAST`
  precedent):** `security flow tcp-mss {ipsec-vpn|gre-in|gre-out|all-tcp}`
  stays OPAQUE in `setSchema` because its MSS value can live in EITHER the
  kind node's flat `Keys[1]` (`gre-in 1400`) OR a hierarchical `mss` sub-child
  (`gre-in { mss 1360; }`) — a dual value-location the declarative walker
  cannot express. `validateTCPMSSRanges` (`compiler_security.go`, wired into
  `compileExpanded` next to the VRRP pre-walk) range-checks the
  COMPILER-SELECTED token via `selectMSSToken` (shared with `parseMSSValue` so
  it can never diverge: `mss` child first, flat fallback) against
  `[0, 65535]`. A mixed shape `gre-in 70000 { mss 1360; }` therefore PASSES
  (the compiler selects the child 1360 and discards the flat 70000).

**Strict vs lenient (boot/HA safety):** Tiers 1+2 get the strict/lenient split
for free (a typed-leaf `SchemaValidate` violation hard-rejects on the strict
commit path and downgrades to a warning on `Store.Load` / `Store.SyncApply`,
`configstore.compileTreeLenient`). Tier 3's `validateTCPMSSRanges` takes a
`lenient` flag (the `lenientTCPMSSRange` `compileOpt`, set by
`CompileConfigLenient` / `CompileConfigForNodeLenient`) exactly like the VRRP
validator: strict commit hard-rejects, but the tolerant load/peer-sync path
WARNS and lets Layer A coerce, so an upgraded node loading a legacy
`tcp-mss gre-in 70000` (a value an older binary accepted) still boots.

Pure commit-time validation — no Layer A / Rust / wire change. Regression
coverage: `pkg/config/schema_validate_flow_numwidth_test.go` (Tiers 1+2 via
`SchemaValidate`), `pkg/config/compiler_tcp_mss_range_test.go` (Tier 3 via
`CompileConfig`, dual-shape + mixed-shape precedence + strict/lenient), and
`pkg/dataplane/userspace/flow_numwidth_agreement_test.go` (the directional
Layer-A agreement property).

### #2079 — NAT pool-utilization-alarm threshold validation

`security nat source pool-utilization-alarm raise-threshold/clear-threshold` is
a Tier-3 compiler-side validation with the standard **strict-vs-lenient** split
(same doctrine as #1979 / tcp-mss). `validatePoolUtilizationAlarm`
(`pkg/config/compiler_nat.go`, invoked from the typed-config phase of
`compileExpanded` in `compiler.go`) requires `0 < clear-threshold <
raise-threshold <= 100`.

`clear-threshold` is OPTIONAL (#4077, Junos-faithful). A raise-only config
(`raise-threshold` with no `clear-threshold`) is legal: the parser defaults the
clear-threshold to a 10-point hysteresis margin below raise
(`defaultPoolAlarmClearThreshold`, floored at 1 — raise 90 → clear 80, raise 5 →
clear 1) BEFORE the gate runs, so the raise-only config both commits and arms
the runtime monitor. The default always lands inside `0 < clear < raise`, so the
gate below only ever sees a zero/invalid clear when the operator EXPLICITLY
provided one (an explicit `clear-threshold 0` is still rejected).

- **Strict (`commit` / `commit check`):** a bare `pool-utilization-alarm;`
  (raise=0/clear=0, an always-firing alarm) and inverted/equal thresholds are
  HARD commit errors (Junos itself requires raise > clear).
- **Lenient (`Store.Load` / HA peer-sync — `CompileConfigLenient` /
  `CompileConfigForNodeLenient`, flag `lenientNATPoolAlarmThreshold`):** the
  violation downgrades to a `cfg.Warnings` entry so a node that committed a
  legacy/loose alarm config BEFORE this gate existed still BOOTS after upgrade
  instead of failing closed (#1960 fail-closed-on-compile-failure would
  otherwise brick the daemon on restart). The runtime monitor treats
  `raise-threshold <= 0` as "feature disabled", so a leniently-loaded bad config
  is inert (not always-firing), and the operator's next strict commit rejects it
  loudly.

The thresholds are a single GLOBAL pair (no per-pool override syntax in the
parsed Junos grammar). Regression coverage:
`pkg/config/compiler_nat_pool_alarm_test.go` (strict reject + lenient
accept-with-warning + valid-no-warning + raise-only default + explicit-clear
still-validated). The runtime consumer (#2079) is
documented in `docs/deterministic-nat-cgnat.md`.

NOTE: `pool-utilization-alarm` is not yet a typed `setSchema` leaf (no
config-mode value-slot completion); the validation is compiler-side only. Adding
schema completion is a separate, optional UX follow-up.

### #2173 — static-NAT / NAT64 host-mask validation

Static NAT is strictly host-1:1 and NAT64 source-pool entries are discrete host
source IPs, so the ONLY meaningful mask on a static-NAT match/prefix or a NAT64
pool address is the canonical host mask (`/32` for IPv4, `/128` for IPv6; a bare
address is a host too). #2122/#2123 (PR #2132) made the Rust dataplane TOLERATE
the canonical host mask; PR #2167 then hardened the Rust parser
(`parse_nat_addr` in `userspace-dp/src/nat/static_nat.rs`, `parse_pool_v4` in
`userspace-dp/src/nat64.rs`) to REJECT a non-host mask (`/24`, `/64`, garbage
suffix, ...). The net effect before #2173 was a SILENT dataplane drop: a
misconfigured `/24` match/prefix was parsed-out and the rule was never installed,
with no operator feedback.

`validateNATHostMaskStrict` (`pkg/config/compiler_nat.go`, invoked from the
typed-config phase of `compileExpanded` in `compiler.go`, alongside the other
strict-vs-lenient gates) closes that gap. The host-route rule mirrors the Rust
gate EXACTLY (shared predicate `isHostMaskAddress`):

- **Scope:** static-NAT rules' `match destination-address` (→ snapshot
  `ExternalIP`) and `then static-nat prefix` (→ `InternalIP`) are checked with
  the family-aware `isHostMaskAddress` (matching `parse_nat_addr`). A NAT64
  `rule-set ... source-pool` pool's addresses are checked with the **IPv4-only**
  `isNAT64PoolHostAddress` (matching `parse_pool_v4`, which is `Ipv4Addr`-only):
  the pool translates to IPv4 source addresses, so an IPv6 pool entry — even a
  `/128` — is silently dropped by the dataplane and is rejected at commit too.
  Both predicates classify address family **textually** (`natAddrFamily`: a
  colon means IPv6) to match the Rust `from_str` parsers exactly — Go's
  `net.ParseIP(...).To4()` folds the IPv4-mapped `::ffff:1.2.3.4` form to v4,
  but Rust `Ipv4Addr::from_str` rejects it and `IpAddr::from_str` classifies it
  as V6, so the mapped form is treated as IPv6 here (never accepted as a v4 host
  the dataplane would then silently drop).
- **Exempt:** `then static-nat nptv6-prefix` rules (genuine RFC 6296 prefix
  translation, never host-checked by the Rust parser) and `then static-nat
  inet` rules (a NAT64 translation whose `match` is the well-known prefix, e.g.
  `64:ff9b::/96`, driven by the separate NAT64 snapshot, not the static_nat
  table). NPTv6 prefixes are exempt from the *host-mask* gate (a prefix is
  expected, not a host), but they have their own strict gate
  (`validateNPTv6Strict`, #2240/#2241/#2380): prefix-length equality, supported
  length (`/48` or `/64`), IPv6 family, overlap rejection, and — #2380 — a
  **host-bits-zero** check on BOTH the `match` and `nptv6-prefix` slots.
  `net.ParseCIDR` silently masks the address to the prefix length, so a prefix
  with bits set beyond the prefix length (e.g. `2001:db8:1:2::/48`) would
  otherwise compile as a DIFFERENT prefix (`2001:db8:1::/48`) than the operator
  wrote, with no feedback. Junos rejects host bits on a prefix and so does the
  strict gate. This routes through the SAME strict/lenient `emit` as the other
  NPTv6 checks: a hard commit error under strict, a `cfg.Warnings` entry under
  `CompileConfigLenient`. **#4519 — the Rust helper now fails CLOSED on host
  bits too.** `parse_prefix` (`userspace-dp/src/nptv6.rs`) previously carried
  only a `debug_assert!` (compiled out in release) and then MASKED the extra
  words, returning `Some`, so a leniently-loaded / peer-synced pre-#2380 rule
  with host bits INSTALLED the silently-widened over-broad prefix in a release
  helper — contradicting the lenient warning that promises the helper rejects
  the snapshot and keeps the prior live state. `parse_prefix` now returns `None`
  on host bits, so `Nptv6State::try_from_snapshots` rejects the WHOLE snapshot
  (a `SnapshotIntegrityError`) and the apply preflight keeps the previous live
  forwarding state — the lenient warning's promise now holds in every build.
  This is the helper-boundary backstop in the #2124/#2142/#2173/#2212
  fail-closed family; the `None`-return is the sole enforcement (no release-
  compiled-out `debug_assert!`).
- **Strict (`commit` / `commit check`):** a non-host mask is a HARD commit error
  naming the rule-set, rule, slot, and offending prefix.
- **Lenient (`Store.Load` / HA peer-sync — `CompileConfigLenient` /
  `CompileConfigForNodeLenient`, flag `lenientNATHostMask`):** the violation
  downgrades to a `cfg.Warnings` entry so a node that committed a non-host
  static-NAT mask BEFORE this gate existed (or a peer-synced config) still BOOTS
  after upgrade instead of failing closed (#1960
  fail-closed-on-compile-failure). The dataplane drops the bad entry
  independently, so a leniently-loaded config is already inert for that rule —
  and the operator's next strict commit rejects it loudly.

**#3206 — unparseable static-NAT match/prefix.** The host-mask check above
fires only when the value *parses* as an IP (`parsed && !host`). A
`match destination-address` or `then static-nat prefix` that is NOT a parseable
literal IP/CIDR (an address-book name like `web-server`, or a typo'd prefix like
`10.0.0.300`) therefore skipped both the host-mask and block-pair checks and
fell through to the Rust dataplane, where `parse_nat_prefix`
(`userspace-dp/src/nat/static_nat.rs`) returns `None` and `from_snapshots` does
`continue`, SILENTLY dropping the WHOLE static-NAT mapping with no commit error
or runtime feedback — the operator authored a rule that does not exist at
runtime. `validateNATHostMaskStrict` now rejects an unparseable match/prefix
FIRST (before the block-pair / host-mask checks) via `natStaticPrefixInfo`'s
`parsedIP == false` signal, naming the rule-set, rule, slot, and offending
value. Static NAT takes literal IP/CIDR endpoints, not address-book references.
Strict = hard commit error; lenient = `cfg.Warnings` entry (the Rust
`from_snapshots` drop remains the lenient/peer-sync backstop). Same exemptions
apply (NPTv6, `then static-nat inet`).

Regression coverage: `pkg/config/compiler_nat_host_mask_test.go` (bare/​/32/​/128
accept; v4 + v6 non-host match/prefix reject with asserted message; NPTv6 and
`inet` exemptions; NAT64 source-pool host vs non-host; strict-reject /
lenient-warn / valid-no-warning; `isHostMaskAddress` table; #3206 unparseable
match/prefix reject + parseable host/​block still-compile + lenient-warn). Like
`pool-utilization-alarm`, this is compiler-side only — not yet a typed
`setSchema` leaf.

### #3886 — NAT64 rule-set `prefix` /96 commit gate

A NAT64 rule-set `prefix` (`security nat nat64 rule-set <r> prefix <p>`) is read
verbatim into the wire snapshot (`compileNAT64` in `compiler_nat.go` →
`NAT64RuleSnapshot.Prefix` via `buildNAT64Snapshots`) and parsed at dataplane
apply by `Nat64State::from_snapshots` (`userspace-dp/src/nat64.rs`). That
**/96-integrity check** requires an IPv6 `<address>/96`: it splits the string on
`/`, the token after the first `/` MUST parse as a decimal `96` (only `/96` is
supported by the translator), and the address token before the `/` MUST parse as
an `Ipv6Addr`. Anything else — a non-`/96` length, a missing/garbage mask, or a
non-IPv6 / malformed address — makes `from_snapshots` SKIP the offending NAT64
rule (logging a loud one-line warning) and publish the rest (#3888, fail-scoped).
**Pre-#3888** the fallible `try_from_snapshots` instead returned a
`SnapshotIntegrityError` that propagated via `?` out of
`build_reconcile_forwarding` and **aborted the ENTIRE forwarding rebuild WITHOUT
publishing** — the dataplane was then frozen at the last-good snapshot and every
later commit (new sessions, policy, NAT) silently stopped reaching the dataplane.
#3888 scopes that runtime blast radius to the one bad NAT64 rule; the commit gate
below remains the primary defense so a bad prefix is rejected before it is ever
emitted. The
`prefix` `setSchema` leaf (`schema_security.go`) carries no `keyValidator`
(unlike the RA `nat-prefix`/`nat64prefix` leaves, whose `ValidatePREF64CIDR`
accepts the broader RFC 8781 `{32,40,48,56,64,96}` set — WRONG for a NAT64
translator that supports `/96` only), so before this gate a bad prefix committed
GREEN and wedged the whole control→dataplane pipeline.

`validateNAT64PrefixStrict` (`pkg/config/compiler_nat.go`, invoked from the
typed-config phase of `compileExpanded` in `compiler.go`, right after
`validateNPTv6Strict`) closes that gap and mirrors the Rust check EXACTLY (split
on `/`, mask token must be `96`, address token must be IPv6 via the textual
`natAddrFamily` — a colon means IPv6, matching Rust `Ipv6Addr::from_str` for the
IPv4-mapped `::ffff:x` form), so anything that would abort the rebuild at runtime
is rejected at commit — no commit-accept → runtime-abort gap.

- **Scope / out-of-scope:** only a NON-EMPTY prefix is validated. An empty/absent
  prefix is deliberately exempt — `buildNAT64Snapshots` skips an empty-prefix
  rule, so it is never emitted on the wire and never reaches the Rust check, so
  it cannot freeze the rebuild.
- **Strict (`commit` / `commit check`):** a non-`/96` or malformed prefix is a
  HARD commit error naming the rule-set and offending prefix.
- **Lenient (`Store.Load` / HA peer-sync — `CompileConfigLenient` /
  `CompileConfigForNodeLenient`, flag `lenientNAT64Prefix`):** the violation
  downgrades to a `cfg.Warnings` entry so a node that committed a bad NAT64
  prefix BEFORE this gate existed (or a peer-synced config) still BOOTS after
  upgrade instead of failing closed (#1960 fail-closed-on-compile-failure). The
  Rust helper's own `from_snapshots` backstop (#3888) SKIPS the bad NAT64 rule
  and publishes the rest, so a leniently-loaded bad prefix degrades NAT64 only
  (not the whole dataplane) — and the operator's next strict commit rejects it
  loudly.

> Defense-in-depth follow-up (DONE in #3888): a bad NAT64 prefix arriving via HA
> peer-sync/lenient — a path the commit gate does not cover — now makes the Rust
> `from_snapshots` SKIP just the offending NAT64 rule and publish the rest,
> rather than aborting the WHOLE forwarding rebuild. NPTv6 intentionally stays
> abort-all (its #2241 overlap rejection is order-dependent, so a blind per-rule
> skip would be ambiguous) — a flagged follow-up, out of #3888 scope.

Regression coverage: `pkg/config/compiler_nat64_prefix_test.go` (well-known
`64:ff9b::/96` + `/96` NSP accept; non-`/96` lengths, missing mask, garbage
mask, malformed IPv6 address, and IPv4 prefix reject with asserted message;
lenient strict-reject → warn + valid-no-warning). Compiler-side only — not a
typed `setSchema` leaf (a schema `keyValidator` has no lenient mode and would
hard-reject on the load path too, re-introducing the #1960 boot-brick).

### #2217 — firewall / application undefined-reference validation

Three firewall/application cross-references compiled cleanly with no operator
feedback and then silently FAILED OPEN at the dataplane. The schema declared the
relevant leaves with `args:1` and no validator, and `ValidateConfig` checked the
neighbouring references (SNAT/DNAT pools, forwarding-class, routing-instance
interface membership) but not these three. Each gap is closed by a strict
commit-time gate in `pkg/config/compiler_validate_strict.go`, invoked from the
typed-config phase of `compileExpanded` (`compiler.go`) alongside the other
strict-vs-lenient gates:

- **Finding A — `then policer <name>` →
  `validateFirewallPolicerReferencesStrict`.** A firewall-filter term whose
  `then policer` names a policer defined under neither `firewall policer` nor
  `firewall three-color-policer` is rejected. Pre-fix the term kept
  `Policer="no-such-policer"` and the rate-limit silently never applied
  (fail-open — the term's traffic passed unpoliced).
- **Finding B — application-set member →
  `validateApplicationSetMembersStrict`.** An `applications application-set
  <set>` member that resolves to neither a defined application (user-defined or
  `junos-*` predefined) nor a defined nested application-set is rejected. It
  reuses `ExpandApplicationSet` — the SAME resolver the compiler already uses —
  so no new definedness table is introduced (it also surfaces the existing
  max-depth-3 nesting bound at commit). Implicit application-sets minted for
  multi-term user applications are skipped (their members are
  compiler-synthesized, not operator references). Pre-fix a policy matching the
  set silently failed to match the intended traffic (the unresolved member never
  matches — an effective no-op term). **Sibling gate (#3890, fable-review-161
  F-160):** Finding B checks a member's NAME resolves; a mistyped member KEYWORD
  (`applicaton foo` instead of `application foo`, or a bad `application-set`) is a
  distinct failure — the token never becomes a reference at all, it is silently
  dropped and the set is UNDER-POPULATED (a fail-open under-match for a deny
  policy referencing it). `compileApplications` records the bad keyword on
  `ApplicationSet.UnknownMembers` and `validateApplicationSyntaxStrict` rejects it
  (a `description` is accepted as metadata); it runs EARLIER than Finding B, so a
  typo'd keyword is reported as "unknown member statement" rather than a dangling
  reference. Same strict-reject / lenient-warn discipline (`lenientApplicationSpecs`).
  **Predefined application-set bundles (#4102, fable-review-163 F14):**
  `ResolveApplicationSet` / `ExpandApplicationSet` (`pkg/config/predefined.go`)
  fall back to a `PredefinedApplicationSets` table AFTER user-defined sets —
  mirroring `ResolveApplication`'s user-then-predefined order — so the standard
  Junos `junos-defaults` bundles resolve without an operator having to redefine
  them. Seeded from a real `show configuration groups junos-defaults` dump:
  `junos-ms-rpc` = {`junos-ms-rpc-tcp`, `junos-ms-rpc-udp`}, `junos-sun-rpc` =
  {`junos-sun-rpc-tcp`, `junos-sun-rpc-udp`}, `junos-cifs` =
  {`junos-netbios-session`, `junos-smb-session`}, `junos-routing-inbound` =
  {`junos-bgp`, `junos-rip`, `junos-ldp-tcp`, `junos-ldp-udp`}. Every member is
  in the `PredefinedApplications` table, so each set expands to >= 1 member and
  clears the empty-set fail-open gate (#3146). Before #4102 only the
  protocol-split members shipped and the bundle names were nowhere, so a stock
  vSRX policy `match application junos-ms-rpc` hard-failed at commit
  (`validatePolicyMatchApplicationsStrict`) and, on the tolerant path, at runtime
  (`resolveUserspaceApplicationNames` → `__unsupported__` →
  `SnapshotIntegrityError`). Both the commit gate and the runtime resolver route
  through these two functions, so the one table fixes every surface. A
  user-defined set of the same name still shadows the predefined bundle (user
  wins), and an unknown set name still hard-fails. Coverage:
  `predefined_app_sets_4102_test.go`.
- **Finding C — `then routing-instance <name>` (FBF) →
  `validateFirewallRoutingInstanceReferencesStrict`.** A firewall-filter term
  whose filter-based-forwarding steer names a routing-instance not defined under
  `routing-instances` is rejected. Any defined instance is a valid steer target
  (virtual-router / vrf / forwarding alike), so instance-type is intentionally
  not constrained — only the dangling-name case is closed. Pre-fix the FBF
  snapshot carried the unknown name and the dataplane steered matched packets
  toward a routing table that does not exist (silent blackhole / fall-through to
  the default table).
- **#3432 — output-attached `then routing-instance` direction →
  `validateFilterRoutingInstanceDirectionStrict`.** FBF route override is an
  INGRESS-only operation: the userspace forwarding path
  (`ingress_route_table_override` / `interface_filter_affects_route_lookup`,
  `userspace-dp/src/afxdp/forwarding/mod.rs`) resolves the ingress logical
  ifindex and only consults the INPUT filter's `affects_route_lookup` flag —
  the Rust filter compiler (`userspace-dp/src/filter/compiler.rs`) sets that
  flag only on the input attach branch. So a filter carrying a `then
  routing-instance` term attached with `filter output` compiled cleanly but
  the steering silently never fired. This gate rejects an output attach of any
  filter that carries a routing-instance term, naming the interface/unit/family
  and pointing the operator at `filter input` instead. The SAME filter on an
  INPUT attach is the legitimate PBR case and still commits. (The Finding C
  reference gate and the #3308 routing-instance+discard/reject conflict gate
  check the target NAME and the terminal-action conflict; neither checks the
  attach DIRECTION.)

All four cover both filter families (`inet` + `inet6`) / both AST shapes
(hierarchical and flat-set), sorted for a deterministic first-error message
(the #3432 gate walks interface attachments — inet then inet6 — rather than the
filter maps directly).

**Strict (`commit` / `commit check`):** a dangling reference is a HARD commit
error naming the filter/term (or application-set) and the offending name.
**Lenient (`Store.Load` / HA peer-sync — `CompileConfigLenient` /
`CompileConfigForNodeLenient`, flags `lenientFirewallRefs` and
`lenientApplicationSetMembers`):** the violation downgrades to a `cfg.Warnings`
entry so a node that committed a dangling reference BEFORE this gate existed (or
a peer-synced config) still BOOTS after upgrade instead of failing closed (#1960
fail-closed-on-compile-failure). The dataplane behaves exactly as before for the
leniently-loaded reference (term unpoliced / steered to a missing table /
unresolved member dropped), so it is already inert — and the operator's next
strict commit rejects it loudly.

Regression coverage: `pkg/config/compiler_undefined_ref_2217_test.go` (per
finding: undefined-reject in both AST shapes, defined-commits-cleanly,
lenient-warns; plus three-color-policer + `junos-*` predefined + nested-set +
implicit-multi-term-not-false-rejected cases). Like the gates above, these are
compiler-side only — not yet typed `setSchema` leaves.

### #3339 — application / application-set name-collision validation

`compileApplications` (`compiler_applications.go`) collects user applications and
application-sets into two name-keyed maps with **last-write-wins** semantics, and
a multi-term `applications application <X>` additionally MINTS an implicit
application-set under the application's own name
(`apps.ApplicationSets[appName] = implicitSet`). Every one of these writes
silently overwrote a colliding earlier definition with no commit error
(Codex review 080, M07 + M08):

- **Application vs application-set sharing a name (M07).** An explicit
  `applications application-set <X>` silently replaced the implicit set minted
  for a multi-term `applications application <X>` (and, generally, an application
  and an application-set are one flat Junos namespace). A policy referencing `<X>`
  then enforced whichever definition won the map-write race — and the two
  resolvers DISAGREE on which that is: policy expansion
  (`resolveUserspaceApplicationNames`) resolves application-first, while the
  AppID catalog (`addPolicyApps`) resolves application-set-first, so a session
  could be admitted by one definition but cataloged/labeled by the other.
- **Duplicate term-generated application name (M08).** Two `term`s under one
  application generating the same per-term name (`<parent>-<term>`, with a
  protocol suffix only when one term carries multiple protocols) made the later
  `apps.Applications[name] = t` overwrite the earlier while the implicit set
  still listed the duplicate member — ambiguous and silent.
- **Duplicate application / application-set definition** (the same name authored
  twice in one namespace) is also rejected. Such duplicates survive as distinct
  AST siblings only on a hierarchical file parse (the set-command config tree
  merges same-named siblings), but rejecting them keeps the gate honest for
  either representation.

The gate `validateApplicationNameCollisionsAST`
(`pkg/config/compiler_applications_collision.go`) is an **AST pre-walk** run on
the group-expanded, inactive-pruned tree in `compileExpanded` (alongside
`validateUnsupportedInterfaceStanzasAST`), NOT a post-compile check on the typed
`*Config`: by the time the maps are built the colliding definitions have already
been merged away by last-write-wins — only the raw AST still carries every
definition. It aggregates counts across EVERY top-level `applications {}` node (a
hierarchical parse can emit several sibling blocks and `compileExpanded` compiles
all of them), so a collision SPLIT across two `applications {}` blocks is caught
just like one inside a single block — the walk must not stop at the first node.
The predefined `junos-*` table lives outside the AST, so a user
`application junos-http` that merely SHADOWS a predefined application is not a
collision (one AST stanza, no peer) and is left untouched; a multi-term
application minting an implicit set under its own name is likewise not a
self-collision.

**Strict (`commit` / `commit check`):** the first collision is a HARD commit
error naming the offending name. **Lenient (`Store.Load` / HA peer-sync —
`CompileConfigLenient` / `CompileConfigForNodeLenient`, flag
`lenientApplicationNameCollisions`):** the violation downgrades to a
`cfg.Warnings` entry so a node that committed a colliding config BEFORE this gate
existed (or a peer-synced config) still BOOTS after upgrade instead of failing
closed (#1960 / #3261 fail-closed-on-load doctrine); `compileApplications` keeps
producing the same (arbitrary but stable) last-write-wins maps on that path.

Regression coverage: `pkg/config/compiler_applications_collision_3339_test.go`
(app-vs-set collision, implicit-set-overwrite, duplicate application / set
definition, duplicate term-generated name, distinct-names-commit incl. a
predefined shadow, lenient-warns). Compiler-side only — not a typed `setSchema`
leaf (applications stay opaque to `SchemaValidate`).

### #3472 — generated per-term application names join the collision namespace

#3339 above counted only AUTHORED `application` / `application-set` nodes. The
GENERATED per-term names (`<parent>-<term>`, written into `apps.Applications` by
`compileApplications`) were invisible to it, so they still silently
last-write-wins into the map. `validateApplicationNameCollisionsAST` now builds a
global table of every generated name → the distinct parent applications that
produce it (`genParents` / `genOrder`) and checks it against the rest of the flat
namespace (Codex review audit 116, H01/H02/H03 + M03):

- **H01 — a generated name overwrites an authored application.** Multi-term
  `application app` term `ssh` mints `app-ssh`; an authored `application app-ssh`
  also exists. Both write `apps.Applications["app-ssh"]`, the later wins, and
  policy / AppID can enforce or label the wrong application. **HARD reject**
  (strict) / warn (lenient).
- **H02 — a generated name collides with an authored application-set.** Generated
  `app-ssh` (in `apps.Applications`) vs `application-set app-ssh` (in
  `apps.ApplicationSets`). They share one flat namespace but live in different
  maps, and the two resolvers diverge (policy expansion application-first, AppID
  catalog application-set-first), so the token enforces one definition and is
  attributed to the other. **HARD reject** (strict) / warn (lenient).
- **H03 — cross-parent generated-name collision.** `application a-b term c` and
  `application a term b-c` both mint `a-b-c`; #3339's `termSeen` was scoped per
  parent so the later term silently won across parents. **HARD reject** (strict) /
  warn (lenient).
- **M03 — a generated name shadows a predefined `junos-*` application.**
  `application junos term ssh` mints `junos-ssh`, which shadows the predefined
  service (`ResolveApplication` prefers user-defined over predefined). This is a
  **WARNING on BOTH paths**, never a hard reject: a generated name is a user
  application and an authored shadow of a `junos-*` name is already a documented-
  legitimate override (the #3339 scope note), so reserving the `junos-*`
  namespace would be inconsistent and could brick a config an older binary
  accepted. The warning makes an accidental shadow operator-visible.

The within-parent duplicate-generated-name check (M08, #3339) is unchanged; a
within-parent duplicate has one distinct parent so it does not trip H03.
Regression coverage lives alongside the #3339 fixtures in
`compiler_applications_collision_3339_test.go`
(`TestGeneratedTermNameOverwritesAuthoredApplicationRejected`,
`TestGeneratedTermNameCollidesWithApplicationSetRejected`,
`TestCrossParentGeneratedNameCollisionRejected`,
`TestGeneratedTermNameShadowsPredefinedWarns`,
`TestGeneratedTermNameCollisionLenientWarns`,
`TestGeneratedTermNamesNoCollisionCommit`).

### #3348 — custom `protocol junos-ping` echo constraint + `icmp-type`/`icmp-code` grammar

A **user-defined** application that set `protocol junos-ping` (or `junos-pingv6`)
lowered to bare ICMP with NO type constraint, so the projected policy term matched
**every** ICMP type — silently widening any policy referencing it (a permit term
then admitted unreachable / redirect / timestamp / ... not just echo), and broader
than the predefined `junos-ping` object which carries `ICMPType=8` (the #3020 fix).
`appid.ProtocolNumber` and the capability snapshot (`capabilities.go`) folded the
alias to ICMP and carried `app.ICMPType`, which was `nil` for the custom-app path.

- **alias echo constraint** — `aliasEchoICMPType` (`compiler_applications.go`)
  maps `junos-ping`→type 8, `junos-pingv6`→type 128. `compileApplications`
  applies it AFTER the child loop (so an explicit `icmp-type` leaf wins), and
  `parseApplicationTerms` applies it per normalized protocol inside an inline
  `term` (capturing the echo type before `normalizeProtocol` folds the alias to
  `icmp`/`icmpv6`). The all-ICMP aliases (`junos-icmp-all`/`junos-icmp6-all`)
  return `nil` so they stay match-ALL.
- **typed grammar** — `schemaApplications.application` gains `icmp-type` and
  `icmp-code` `ValueInteger` leaves (`ValidateInteger(0,255)`), so an operator can
  author a constrained custom echo / traceroute / ICMP-control app. The compiler
  parses them on both the top-level and inline-`term` paths into
  `Application.ICMPType`/`ICMPCode`.
- **strict guards** — `validateApplicationSpecsStrict` rejects an
  `icmp-type`/`icmp-code` on a NON-ICMP protocol (a never-match term — the same
  fail-open/fail-closed hazard as the #3373 port-on-non-port gate) via
  `protocolIsICMPFamily`, and rejects an `icmp-code` without an `icmp-type` (an
  ambiguous half-constraint the matcher would apply code-only). Both downgrade to
  a `cfg.Warnings` entry on the tolerant load / HA peer-sync path
  (`lenientApplicationSpecs`, #1960 no-brick).

Two inline-`term` edge cases (the term shape is opaque to `SchemaValidate`, so
both are handled in `parseApplicationTerms` + the deferred strict gate):

- **widening inversion** — a term that lists BOTH a junos-ping alias AND an
  unconstrained ICMP alias (`term t { protocol junos-ping; protocol
  junos-icmp-all; }`) normalizes both to `icmp` and DEDUPS to one term. The
  union of echo + all-ICMP is all-ICMP (the Rust matcher ORs separate app
  terms), so applying the echo type to the collapsed term would spuriously
  NARROW it. `unconstrainedICMP[proto]` records that an all-ICMP alias landed on
  the normalized protocol and SUPPRESSES the `echoByProto` default for it — the
  collapsed term stays unconstrained.
- **fail-open malformed inline icmp-type/code** — a bad inline `icmp-type`
  (`term t { protocol icmp; icmp-type 999; }`) is NOT seen by the schema range
  check (opaque term), so silently dropping it would leave the term matching
  every ICMP type. `parseApplicationTerms` records the raw token on
  `Application.UnknownICMP` (mirroring `UnknownTimeouts`) and the strict gate
  rejects the first one at commit (lenient-warn on load/peer-sync). The
  top-level path also records `UnknownICMP` so the malformed value is caught on
  the tolerant load path (which does not run `SchemaValidate`).

The snapshot already carries `ICMPType`/`ICMPCode` and the matcher already
enforces `icmp_constraints` (#3020). Regression coverage:
`pkg/config/compiler_application_junos_ping_3348_test.go` (alias echo type top-level
+ inline term, all-ICMP stays unconstrained, explicit grammar, explicit-over-alias,
both strict guards) and the end-to-end matcher test
`pkg/policymatch/app_junos_ping_3348_test.go` (custom `protocol junos-ping` permits
type 8, denies 13/5).

**#3712 — Rust snapshot-boundary fail-closed backstop for the two invalid ICMP
combos.** The #3348 strict guards run at COMMIT, but `lenientApplicationSpecs`
downgrades both to a `cfg.Warnings` entry on the tolerant load / HA peer-sync
path — so a corrupt / hand-built / older-peer-synced snapshot can still carry an
invalid combo to the userspace helper, the only enforcement plane. The pre-#3712
Rust matcher turned each into a WRONG-behaving term rather than rejecting it:

- **`icmp-code` without `icmp-type` → match-ALL ICMP (fail-OPEN).**
  `CompiledApplications::from_matches` (`userspace-dp/src/policy.rs`) steers a
  term into `icmp_constraints` ONLY when `icmp_type.is_some()`, so a
  code-without-type ICMP term fell through to an empty-range `range_terms`
  entry = protocol-only match-all; the `icmp_code` was silently dropped and a
  narrow permit widened to every ICMP message.
- **`icmp-type`/`icmp-code` on a non-ICMP protocol → never-match (fail-OPEN for
  a deny).** The term was pushed into `icmp_constraints` under the non-ICMP
  protocol (losing any destination-port), and `matches` skips that arm for a
  non-ICMP packet, so the term never matched — a `deny tcp/80 icmp-type 8`
  never applied and default-permit admitted the traffic.

`parse_applications` now records the first offending term and
`parse_policy_state_with_counters` rejects the whole snapshot with
`SnapshotIntegrityError::InvalidApplicationIcmpFields { rule_id, application,
reason }` (the preflight keeps the previous good state; a fresh boot keeps the
default-deny `PolicyState`), consistent with the #2124/#3367/#3711 fail-closed
family. The non-ICMP-protocol arm is checked first (any icmp field is
meaningless there); the code-without-type arm applies once the protocol is
ICMP/ICMPv6. Regression coverage: `userspace-dp/src/policy_tests.rs`
(`icmp_code_without_type_rejects_whole_snapshot`,
`non_icmp_term_with_icmp_type_rejects_whole_snapshot`,
`non_icmp_term_with_icmp_code_rejects_whole_snapshot`,
`valid_icmp_type_and_code_still_compiles_and_matches`,
`valid_icmpv6_type_and_code_still_compiles`).

### #3352 / #3353 — unknown inline-`term` leaf + per-application `alg` validation

An inline `applications application <a> term <t> { ... }` is declared as an
opaque `args:1` schema leaf (`schemaApplications.application.term`,
`children:nil`), so `SchemaValidate` cannot reach inside it. Two silent-accept
gaps lived under that opacity:

- **#3352 — unknown leaf inside a `term`.** `parseApplicationTerms`
  (`compiler_applications.go`) was a fixed `switch` with no `default` arm, so a
  typo'd leaf (`term t1 { protocol tcp; destination-poort 22; }`) was silently
  dropped along with its value token — the term kept only its remaining
  constraints (`protocol tcp`) and a narrow permit/deny term **widened to
  all-TCP**, with no commit error. The parser now records every unrecognized
  token on `Application.UnknownTermLeaves` (mirroring `UnknownTimeouts` /
  `UnknownICMP`), and `validateApplicationSpecsStrict` rejects the first one at
  commit. A custom application term accepts only `protocol` / `source-port` /
  `destination-port` / `inactivity-timeout` / `timeout` / `icmp-type` /
  `icmp-code` / `alg`.
- **#3353 → #4337 — per-application `alg` accept-with-advisory (relaxed from a
  hard reject).** The `alg` leaf was a raw `args:1` string with no validator, so
  a typo (`alg ftpp`) committed cleanly and the operator believed an ALG was
  pinned when none existed. #3353 first made an unsupported name (outside the
  SSOT set `dns`/`ftp`/`sip`/`tftp`) a hard commit error. **#4337 relaxes that
  to an accepted-but-inert advisory**: a per-application ALG is NOT carried into
  the userspace dataplane snapshot at all (the only ALG signal on the wire is
  the *global* `alg_disable_flags` bitfield, `userspace-dp` `snapshot.rs`), so
  even a KNOWN name is informational today — hard-rejecting an UNKNOWN one
  blocked real vSRX drop-in configs that tag applications with ALGs xpf does not
  implement (e.g. `alg ssh`) for a knob with no functional effect. The unknown
  name now commits, and `ValidateConfig` (`compiler_validate_warn.go`) emits an
  advisory naming the unenforced alg — `application <a>: alg "<name>" accepted
  but not enforced …` — mirroring the global `security alg` accepted-but-inert
  advisory (#4232). A KNOWN name (case-insensitive, via
  `supportedApplicationALGs` in `compiler_applications.go`) commits silently and
  keeps its (informational) behavior. This covers both the top-level `app.ALG`
  and the inline-term `alg` (the term app carries it).

  **Enforcement remains deferred.** Wiring per-application ALG (e.g. `alg ftp
  destination-port 2121`) through to enforcement needs a new snapshot field plus
  Rust session-metadata handling — a genuine dataplane fork that is the
  per-application slice of the broader ALG parity tracked under **#2008**, and
  is deliberately not built here.

**Scope — ALL user-defined applications, referenced or not.** The unknown
term-leaf hard reject (#3352) lives in a SEPARATE pass,
`validateApplicationSyntaxStrict`, that iterates every entry in
`cfg.Applications.Applications`, NOT the reference-scoped
`applicationsToValidateStrict` subset that `validateApplicationSpecsStrict` uses
for its port / protocol / icmp / timeout checks. The reference scope is correct
for those SEMANTIC checks (an unreferenced malformed-port app cannot break a
live policy decision, so it stays a warning so an operator iterating on a
not-yet-wired application library is not blocked). But an unknown term statement
is a SYNTACTIC violation — the config names a statement that does not exist —
which Junos rejects at commit regardless of policy wiring; deferring it until
reference would let a typo'd term-leaf silently widen a term from the moment the
app is defined. The per-application `alg` advisory (#4337) likewise applies to
every entry (`ValidateConfig` iterates all user apps). `cfg.Applications.
Applications` holds ONLY user-defined applications (and the per-term apps they
generate); PREDEFINED junos-* apps (`junos-rtsp`, `junos-h323`, ...) live in the
separate `PredefinedApplications` table and are never in this map, so neither
the term-leaf gate nor the `alg` advisory ever touches a predefined app that
legitimately carries an out-of-supported-set ALG.

The #3352 term-leaf gate is STRICT on the commit / commit-check path and
downgrades to a `cfg.Warnings` entry on the tolerant load / HA peer-sync path
(`lenientApplicationSpecs`, #1960 no-brick), the same discipline as the #3320 /
#3348 application gates; the #4337 alg check is always an advisory (never a
commit error). Regression coverage:
`pkg/config/compiler_application_term_alg_3352_3353_test.go` (unknown term leaf
rejected referenced AND unreferenced, well-formed term keeps its port
constraint, unknown alg accepted-with-advisory top-level + inline-term +
unreferenced, supported alg names accepted on both paths, predefined-app
reference not rejected).

### #4336 — application `source-port` / `destination-port` `0-N` range floor

Junos accepts `0` as the FLOOR of an application port range. Real vSRX
multi-term application defs routinely split a port space as `0-N` /
`N+1-65535` (e.g. FaceTime `term 0_41640 { source-port 0-41640; }`). xpf
hard-rejected the low half with `source-port: invalid port 0: must be
1-65535` — a pure drop-in blocker. `resolveAppPort` (`compiler_applications.go`,
the single canonicalization chokepoint for BOTH direct-match and inline-term
ports) now normalizes a range floor of `0` to `1`. Port 0 never appears on the
wire, so `0-N` matches identically to `1-N`; normalizing at this one point keeps
the config, `validatePortSpec`, the `userspacePortSpecRepresentable` #2124
capability gate, and the Rust `parse_port_spec` all in agreement (the latter two
both reject a raw `0` floor, so accepting `0-N` WITHOUT normalizing would create
a commit-succeeds / apply-fails split). A bare single port `0` (no hyphen) stays
invalid, matching Junos, and an out-of-range / non-numeric endpoint still
hard-rejects on the referenced (strict) path. Regression coverage:
`pkg/config/compiler_application_port_range_zero_4336_test.go` (source-port,
destination-port, and inline-term `0-N` normalized to `1-N`; normal `1-N`
unchanged; garbage still rejected) plus the `FaceTime-0_41640` assertion in
`TestMultiTermApplication`.

### #3366 — application EITHER direct OR term-based; conflicting duplicate term leaf

A custom `applications application <name>` may carry EITHER a direct match body
(`protocol` / `destination-port` / `source-port` / `inactivity-timeout` /
`timeout` / `icmp-type` / `icmp-code` / `alg`) OR one or more `term` sub-blocks —
Junos rejects the mix. Two silent-accept gaps lived in `compileApplications` /
`parseApplicationTerms` (`compiler_applications.go`):

- **Mixed direct body + `term` dropped the direct match.** The final store is
  all-or-nothing: `if len(terms) > 0 { /* store only the synthesized term apps +
  the implicit application-set */ } else { apps.Applications[appName] = app }`.
  So a shape combining a direct body with a term
  (`application X { protocol tcp; destination-port 22; term t1 { protocol udp;
  destination-port 53; } }`) silently DISCARDED the direct `protocol tcp /
  destination-port 22` match — for a deny application that erased the deny and
  let traffic fall through to a later permit or the default policy (a fail-OPEN
  under-match), with no commit error. `compileApplications` now records such a
  parent on `cfg.Applications.MixedDirectTermApps` (a direct body is any match
  leaf — `description` is metadata propagated onto each term, not a match
  constraint, so it does NOT count), and `validateApplicationStructureStrict`
  (`compiler_validate_strict.go`) rejects it at commit (move the direct match
  into its own `term`).
- **Conflicting duplicate scalar leaf inside one `term` was last-writer-wins.**
  `parseApplicationTerms` parses `destination-port` / `source-port` / `alg` /
  `inactivity-timeout` / `timeout` into single scalars; the inline `term` is
  opaque to `SchemaValidate`, so a repeated leaf (via apply-groups, flat-set
  ordering, or hand authoring) silently overwrote the earlier value by token
  order with no validation — a repeated `destination-port` in a deny term
  narrowed the deny to the final value. The parser now records a CONFLICTING
  repeat (a second occurrence with a DIFFERENT value) on
  `Application.DuplicateTermLeaves`, and the same gate rejects the first one. An
  IDEMPOTENT same-value repeat (e.g. the `timeout` / `inactivity-timeout` aliases
  both set to the same number) is harmless and accepted; a repeated `protocol` is
  the documented multi-protocol-term syntax (one application per unique protocol,
  `TestMultiProtocolTerm`) and is NOT flagged.

**Scope — ALL user-defined applications, referenced or not.** Like the
#3352/#3353 syntactic gate, `validateApplicationStructureStrict` runs over every
entry rather than the reference-scoped `applicationsToValidateStrict` subset: a
mixed-shape application and a conflicting duplicate term leaf are STRUCTURAL
errors Junos rejects at definition regardless of policy wiring. Both checks are
STRICT on the commit / commit-check path and downgrade to a `cfg.Warnings` entry
on the tolerant load / HA peer-sync path (`lenientApplicationSpecs`, #1960
no-brick), the same discipline as the #3320 / #3348 / #3352 / #3353 application
gates. Distinct from #3339 (implicit-set vs explicit-set collision / duplicate
term NAMES), #3352 (unknown leaves inside a term), and #3320 (malformed timeout).
Regression coverage: `pkg/config/compiler_application_mixed_term_3366_test.go`
(mixed rejected referenced + unreferenced + per-direct-leaf + hierarchical;
description+term and direct-only / term-only accepted; conflicting duplicate
leaf rejected per leaf; repeated-protocol multi-protocol term accepted; lenient
path downgrades to a warning).

### #2226 — rib-group `import-rib` undefined-reference validation

`routing-options rib-groups <group> import-rib <rib>` was unvalidated: an
import-rib naming a rib that resolves to no real routing table (a typo, a
non-existent routing-instance, or unparseable garbage) compiled cleanly. At apply
time `resolveRibTable` (`pkg/routing/rules.go`) mapped any unresolvable name to a
bare table **0**. Because a routing-instance's source table is always `>= 100`,
the unresolvable name yielded `targetTable(0) != sourceTable`, which set
`needsLeak` and installed an `ip rule from all lookup <sourceTable> pref 33000`
for a rib that does not exist — a silent mis-leak of the source table into the
main lookup, with no diagnostic. (`ValidateConfig` only ever emitted an
over-limit *warning* for rib-groups; it never checked that an import-rib names a
real rib.)

Two layers close the gap:

- **Commit-time gate (preferred) — `validateRibGroupImportRibReferencesStrict`**
  in `pkg/config/compiler_validate_strict.go`, invoked from `compileExpanded`
  (`compiler.go`) alongside the other strict gates. A valid import-rib names
  `inet.0` / `inet6.0` (the main table) or `"<instance>.inet.0"` /
  `"<instance>.inet6.0"` for a defined routing-instance. Any other name is a HARD
  commit error naming the rib-group and the offending rib. Every defined
  rib-group is validated (not only ones referenced by an instance's
  interface-routes rib-group), mirroring Junos, which rejects an undefined rib
  regardless of whether the group is in use. Rib-groups are iterated in sorted
  order for a deterministic first-error.
- **Runtime backstop — `resolveRibTable` now returns `(tableID int, ok bool)`.**
  The `Apply` `needsLeak` loop treats `ok == false` as "unknown rib": it skips
  the entry (with a `slog.Warn`) and never sets `needsLeak` from it, so no rule
  is installed for a phantom rib and nothing is ever installed into table 0 from
  an unresolved name. This guards any reference that still reaches apply via the
  tolerant load / peer-sync path.

**Strict (`commit` / `commit check`):** a dangling import-rib is a hard commit
error. **Lenient (`Store.Load` / HA peer-sync — `CompileConfigLenient` /
`CompileConfigForNodeLenient`, flag `lenientRibGroupRefs`):** downgraded to a
`cfg.Warnings` entry so a node that committed a dangling import-rib BEFORE this
gate existed (or a peer-synced config) still BOOTS (#1960
fail-closed-on-compile-failure). The runtime backstop keeps a leniently-loaded
reference inert (the phantom rib is skipped, no rule installed), matching the
post-fix behaviour, and the operator's next strict commit rejects it loudly.

Regression coverage: `pkg/config/compiler_ribgroup_ref_2226_test.go`
(undefined-reject in both AST shapes, garbage-token reject, defined-ribs +
inet6-ribs commit cleanly, lenient-warns) and `pkg/routing/rules_test.go`
(`TestRibGroupRulesApply_UnknownRibNoLeak` — an all-unknown rib-group installs
ZERO rules; `TestRibGroupRulesApply_DefinedRibStillLeaks` — a defined rib still
leaks correctly). Like the gates above, this is compiler-side only — not yet a
typed `setSchema` leaf.

## The `inactive:` universal node modifier (#2008 H1)

`inactive:` is the Junos deactivate-without-delete marker and is NOT a
schema leaf — it is a UNIVERSAL node modifier that can prefix ANY statement
at ANY position, so it lives OUTSIDE `setSchema` entirely. The parser
(`parser.go`) recognizes a leading `inactive:` token, lifts it into
`Node.Inactive`, and leaves the node's real `Keys` intact. Because the
modifier never appears in the node's identity, the `setSchema` walk, the
flat-set token grouping, and the value-slot `?` completion are all
unaffected — they continue to see the node's real keyword.

**Inline `inactive:` (mid-statement, #4335).** Junos also collapses a
deactivated *sub-statement* onto its parent statement's line, e.g. a
destination-NAT pool address with a deactivated port:
`address 2001:db8::7aef/128 inactive: port 32400;`. Here `inactive:`
deactivates the `port 32400` modifier, not the address. Because `:` is an
identifier character the lexer tokenizes `inactive:` as one identifier, so
an inline marker lands mid-`Keys` rather than leading. A node carries a
single `Inactive` flag for its whole identity and cannot mark only part of
a flat leaf inactive, so `parseStatement` drops the inline marker and every
token it governs (the remainder of that statement) from the active `Keys` —
consistent with the doctrine that a deactivated statement behaves as if it
were absent. The parent statement (the address) stays active; the governed
sub-statement (the port) is simply absent for compilation, exactly as a
deactivated leaf would be. Before this fix the marker leaked mid-`Keys` and
the DNAT-pool compiler read the literal `inactive:` token as the pool
address, hard-rejecting a valid drop-in vSRX config
(`inline_inactive_4335_test.go`).

**Quoted `"inactive:"` is a value, not a marker (#4348).** The marker
detection is gated on the source TOKEN KIND, not just the token text. A
bare `inactive:` lexes as a `TokenIdentifier`; a quoted `"inactive:"` (e.g.
`description "inactive:";`) lexes as a `TokenString`. `parseKeys` returns a
parallel token-kind slice alongside the key values, and BOTH the leading
(index 0) and inline (index > 0) marker checks require
`kinds[i] == TokenIdentifier && keys[i] == inactiveMarker`. Without the
kind gate the flattened `[]string` made a quoted value equal to the marker
text indistinguishable from a bare marker, so the value was silently
truncated (leading: the whole statement wrongly deactivated and the value
dropped; inline: the value and everything after it dropped from `Keys`). A
quoted `"inactive:"` is now preserved verbatim as a literal value
(`quoted_inactive_4348_test.go`). Real-world impact is near-zero — no Junos
leaf's value is the bare token `inactive:` — but the parser no longer loses
data for a value that merely equals the marker text.

**Strip-before-validate / strip-before-compile contract.** A deactivated
statement must be excluded from BOTH the typed-leaf gate and the compiler,
and Junos accepts a deactivated leaf even when its value would be rejected
if active (it parks work-in-progress). The single centralized strip,
`ConfigTree.WithoutInactive` (`pkg/config/inactive.go`), prunes inactive
subtrees and runs at two coordinated entry points:

1. `SchemaValidateWithDefinitions` (`schema_walk.go`) strips both the tree
   and the cross-reference `defsSource` BEFORE the typed-leaf walk, so a
   deactivated typed leaf with a deliberately-invalid value does not fail
   `commit check`, and a deactivated definition neither satisfies an active
   reference nor is itself validated.
2. The commit-check / schema gate in `configstore`
   (`schemaValidateExpandedTreeForNode`, `store.go`) strips inactive
   subtrees BEFORE group expansion, mirroring the compile path. This matters
   because `ExpandGroups` (`ast_groups.go`) collects every `apply-groups`
   node by name WITHOUT checking `Inactive`: stripping only inside
   `SchemaValidateWithDefinitions` (which runs AFTER expansion) would let an
   `inactive: apply-groups missing` still fail commit-check as an undefined
   group, and an `inactive: apply-groups g` still schema-validate inherited
   content the compiler will never apply. Strip → expand → validate now
   holds everywhere a tree is compiled OR schema-validated.
3. Both `compileConfig*` entry points (`compiler.go`) strip FIRST — before
   the pre-expansion tunnel-id collision gate, group expansion, and section
   compilation — so `inactive: apply-groups foo` suppresses the inherited
   config, inactive nodes inside `groups {}` bodies are pruned, and the
   ~15 compiler files never observe an inactive node. Centralizing the
   strip in the shared node-aware `compileConfigForNodeWithOpts` guarantees
   BOTH cluster nodes compile the identical active set from the same
   JSON-synced (`Inactive`-flag-carrying) tree — no split-brain posture.

Strip only REMOVES nodes from the compiled set, but that is NOT a guarantee
that a previously-compiling config stays compilable: deactivating a
*referenced definition* (an address-book entry a policy still matches, a
group an active `apply-groups` still applies, a scheduler a scheduler-map
still names, etc.) can leave that active reference dangling and surface a
dangling-reference commit error. That behavior is correct and expected —
deactivating an object an active statement depends on is operator intent,
and the schema gate deliberately enforces it for schema cross-references and
policy address references (the active reference is validated against the
stripped definitions, so a deactivated definition no longer satisfies it).
`WithoutInactive` is a clone-free no-op when nothing is deactivated, so the
all-active path is unchanged. Regression coverage:
`pkg/config/inactive_test.go`, `pkg/configstore/inactive_test.go`.

**Round-trippable `deactivate` / `activate`.** `show | display set` emits a
`deactivate <path>` line after each inactive node's `set` line(s)
(`ast_format.go`). `ParseSetVerb` (`parser.go`) recognizes `deactivate` and
`activate` as real verbs alongside `set` / `delete`, and the configstore
replay paths (`LoadSet`, `LoadMerge`, and the hierarchical
`FormatSet`-replay inside `LoadMerge`) apply them via
`ConfigTree.DeactivatePath` / `ActivatePath` (`ast_edit.go`). So display-set
output round-trips: an inactive node reloads inactive rather than being
skipped (and silently reactivated) or parsed as a junk path beginning
"deactivate". A bracket-list (`multi: true`) leaf round-trips too: its
display-set `deactivate` line carries the fully-expanded member list
(`deactivate ... from protocol tcp udp icmp`), and `setInactiveAtPath` routes
that shape through the multi-leaf branch (#3975, see "Deactivate-side contract"
above) instead of erroring on the trailing members.

**Interactive `activate` / `deactivate` config-mode verbs (#2051).** The two
verbs are first-class config-mode edits on all four surfaces. The store
exposes `DeactivateFromInput` / `ActivateFromInput` (`configstore/store.go`),
thin wrappers that prepend the verb and route through the same
`applyEditLine` switch the replay paths use, so the verb logic lives in one
place. Local CLI (`cli_dispatch.go`) and remote CLI (`cmd/cli/shared.go`
`dispatchConfig`) dispatch the verbs; the remote CLI rides the gRPC `Set` RPC
with the verb kept as the input prefix, and `Server.Set`
(`grpcapi/server_config.go`) prefix-routes `deactivate `/`activate ` to the
store wrappers BEFORE the `SetFromInput` fall-through — otherwise the
fall-through would parse `set deactivate <path>` and create a junk node named
"deactivate". REST exposes `POST /api/v1/config/deactivate` and
`/config/activate`. Path completion has schema parity with `delete` (paths to
existing nodes via `CompleteSetPathWithValues`); cmdtree lists both verbs in
`ConfigTopLevel`.

**`load set` is a real service-mode op (#2052).** `load set` now works on the
remote CLI, gRPC, and REST (previously local-CLI-only) via
`LoadRequest.mode == "set"` → `store.LoadSet`. The applied-count is logged
(no response field). This makes `show | display set` output — including the
`deactivate <path>` lines above — round-trippable through every service
surface.

### #2447 — class-of-service DSCP/802.1p code-points are domain-validated at commit

`class-of-service` classifier (and DSCP rewrite-rule) code-points are now
range-checked at commit, not silently aliased into a different traffic class.

- **DSCP** (`classifiers dscp ...`, `rewrite-rules dscp ...`) — domain `0..63`
  (the 6-bit DiffServ field). A symbolic alias (`be`, `ef`, `af11`, `cs6`, …)
  resolves through `coSDSCPValues`; a numeric token outside `0..63` is a
  **commit error** (`compileClassOfService`, `expandCoSCodePointToken` in
  `pkg/config/compiler_class_of_service.go`).
- **802.1p / IEEE 802.1** (`classifiers ieee-802.1 ...`, `rewrite-rules
  ieee-802.1 ...`) — domain `0..7` (the 3-bit PCP field). A numeric token
  outside `0..7` is a **commit error** (`collectCoS8021CodePoints` on the
  classifier side; `collectCoS8021RewriteCodePoint` on the #4228 Gap 4 rewrite
  side).

Before #2447 these were **silently dropped** at the Go parse layer (no commit
error) and, on a version/snapshot-drifted helper, the dataplane builder masked
`dscp & 0x3f` / clamped `pcp.min(7)` — so a configured DSCP 110 installed a
classifier for DSCP 46 (a DIFFERENT class) and PCP 9 installed one for PCP 7,
with no failure surfaced. A non-numeric, non-alias token (a typo) is still
skipped (not an error), preserving Junos-compatibility for unknown spellings.

The Rust forwarding-build is the second trust boundary: an out-of-range
code-point reaching `build_cos_dscp_queue_table` / `build_cos_ieee8021_queue_table`
fails the snapshot CLOSED (`SnapshotIntegrityError::CosDscpCodePointOutOfRange`
/ `CosIeee8021CodePointOutOfRange`) — the apply preflight keeps the previous
live CoS state rather than building a classifier for the wrong class. This is
the same fail-closed posture as #2410/#2696/#2713 (queue id, scheduler-map
class, interface MTU). Runtime packet-field masking is retained where it
belongs: `resolve_cos_dscp_classifier_queue_id` / `resolve_cos_ieee8021_classifier_queue_id`
(`tx/cos_classify.rs`) still mask the LIVE packet's DSCP/PCP to index the
fixed-size table — the table is now built only from validated indices, so the
mask just bounds the physically-limited wire field, it no longer aliases config.

### #2448 — static-route destination + next-hop typed at commit

`routing-options static route <destination>` and its `next-hop <gateway>`
child are now typed so a malformed prefix or gateway fails the commit instead
of installing silently and then vanishing from the dataplane.

- **destination** — the `route` identity arg uses `keyValidator:
  ValidateRouteDestination` (`keyValueType: ValueCIDR`), a family-agnostic
  CIDR with a REQUIRED `/prefix-length`. The default routes `0.0.0.0/0` and
  `::/0` parse via `net.ParseCIDR` and are accepted; a bare IP (no length), an
  out-of-range mask (`/99`), or outright garbage is a commit error. v4 and v6
  both pass because a static block holds either family.
- **next-hop** — the `next-hop` gateway uses `keyValidator:
  ValidateStaticNextHop` (`keyValueType: ValueIPAddress`). next-hop is modeled
  as a CONTAINER node (like `qualified-next-hop`), NOT a typed value-leaf, so
  the gateway is validated through the identity-arg keyValidator while the
  optional `interface <iface>` CHILD still walks as a normal value-bearing
  child. This matters: the compiler accepts an EXPLICIT egress interface on a
  plain next-hop (for IPv6 link-local gateways) in BOTH the hierarchical
  `next-hop fe80::50 { interface reth0.50; }` and the flat/inline
  `next-hop fe80::50 interface reth0.50` shapes (compiler_routing.go). A
  typed value-leaf would route the `interface` child through the presence-only
  modifier path and reject the value token after `interface` as `unknown
  modifier` — the #2448 over-rejection regression caught in review. Accepted
  gateway values: a bare IPv4/IPv6 address (the FRR renderer emits it
  verbatim, the Rust FIB parses it), a bare interface name (`ge-0-0-0.0`,
  `reth0.50`, `eth1` — a valid Junos interface next-hop that FRR renders as an
  interface route), and the Rust-FIB `ip@interface` / `@interface` spec (the
  Junos lexer rejects `@`, so this form reaches only a programmatic caller,
  but the validator classifies it correctly: the IP part, when present, must
  parse, else the spec silently degrades to interface-only). Rejected: a
  botched IP literal (`1.2.3.999`, `2001:db8::garbage`), an `ip@iface` whose
  IP part does not parse, and any value that is neither a valid IP nor a
  plausible interface name (`[A-Za-z0-9._-]`, at least one ASCII letter so a
  numeric-only dotted token cannot masquerade as a name). The gateway is still
  validated when an explicit `interface` is present — the keyValidator runs on
  the gateway identity arg regardless of the child.
- **what is NOT rejected** — a plain `next-hop <ip> interface <iface>` (the
  link-local form above, both shapes); `discard` / `reject` / `next-table` /
  `qualified-next-hop ... interface ...` are declared children of the `route`
  node, so a no-next-hop blackhole/leak route and the link-local-IPv6
  qualified-next-hop form still commit.
- **preference (#3771, #3827)** — BOTH the route-level `preference` leaf
  (#3771) AND the `qualified-next-hop <addr> preference <n>` leaf (#3827) are
  typed `ValueInteger` + `ValidateInteger(0, maxWireI32)`: a non-negative
  administrative distance representable on the i32 wire field the compiler
  folds every preference into (`route.Preference`, compiler_routing.go). A
  negative (would sort ahead of every route in the Rust FIB tie-break),
  non-numeric, or i32-overflowing preference is a commit error naming the
  leaf. This is the primary gate; the Rust helper backstops the wire bound
  (`RoutePreferenceOutOfRange`) with a fail-closed snapshot rejection for a
  corrupt / version-drifted snapshot. Typing the qualified-next-hop leaf
  (#3827) closed the completeness gap where a bad preference expressed via the
  qualified-next-hop syntax skipped the Go gate and reached only the opaque
  Rust backstop (retained-prior-state instead of a commit diagnostic).
  Fail-on-revert tests: `pkg/config/schema_route_preference_3771_test.go`
  (route-level) and `pkg/config/schema_route_qnh_preference_3827_test.go`
  (qualified-next-hop).

Before #2448 both leaves were accepted untyped: the Rust FIB builder
(`userspace-dp forwarding_build/fib.rs populate_routes`) soft-skips a
destination that parses as neither v4 nor v6 (no error, no counter), and the
next-hop resolver falls back to ifindex 0 / interface-only on an unparseable
spec — so an operator typo committed cleanly and then either never installed
or installed a blackhole, with no signal. The SSOT is `staticRouteNode()` in
`schema_routing.go`, shared by the `routing-options`, per-`rib`, and
`routing-instances` static blocks. Regression + fail-on-revert tests:
`pkg/config/schema_validate_route_2448_test.go`.

### #4895 — `system login user <name>` identity validated (sudoers injection)

`system login user <name>` was an untyped keyed instance with NO username
validator. The daemon writes an `/etc/sudoers.d/xpf-<name>` NOPASSWD grant for
every `class super-user` account by formatting the raw config key directly into
sudoers syntax (`writeSudoersGrant`, `pkg/daemon/daemon_system.go`). Because the
lexer decodes `\n` inside a quoted string into a literal newline
(`lexer.readString`), a crafted key such as

    set system login user "x\nnobody ALL=(ALL) NOPASSWD: ALL" class super-user

materialized a username containing a newline, and the grant writer emitted TWO
valid sudoers lines. Both pass `visudo -cf` (a syntax checker, not a containment
checker), so the drop-in installed and granted an unmodeled account passwordless
root (CWE-74).

- **schema (PRIMARY)** — the `user` login container uses `keyValidator:
  ValidateLoginUsername` (`keyValueType: ValueIdentifier`), a safe POSIX
  account shape `^[a-z_][a-z0-9_-]*$` capped at 32 characters. A name with a
  newline, whitespace, `/`, `:`, `,`, `=`, a leading hyphen, uppercase, or a
  leading digit is a commit error. Strict on the operator commit path,
  downgraded to a warning on the tolerant Load / SyncApply path
  (`compileTreeLenient`), the same #1960 doctrine as the other typed leaves.
- **daemon (DEFENSE)** — `reconcileSudoers` SKIPS any super-user whose name
  fails `ValidateLoginUsername` (neither desired nor written, so a stale grant
  is also revoked), and `writeSudoersGrant` re-validates the name at entry and
  refuses to format an unvalidated name into sudoers. This closes the
  lenient-load / HA config-sync bypass where a bad name reaches the writer
  despite the downgraded commit gate.

The validator lives in `schema_validators.go` (shared symbol
`config.ValidateLoginUsername`); the schema wiring is in `schema_system.go`.
Regression + fail-on-revert tests: `pkg/config/login_username_4895_test.go`
(schema gate, hierarchical + flat-set) and
`pkg/daemon/daemon_sudoers_username_4895_test.go` (daemon defense).

### #2978 — BGP `multipath ibgp` (iBGP ECMP / `maximum-paths ibgp`)

`set protocols bgp multipath ibgp` enables iBGP equal-cost multipath. FRR's
`maximum-paths N` line (rendered from the existing `protocols bgp multipath`
knob, `BGPConfig.Multipath`) applies ONLY to eBGP-learned routes — iBGP
multipath requires the SEPARATE `maximum-paths ibgp N` command. Without it FRR
installs a single best-path for any iBGP-learned prefix, so ECMP is silently
disabled for iBGP routes in redundant leaf-spine / route-reflector topologies
(agy-review-057 finding 057-04).

- **schema** — `multipath ibgp` is a flag child of the `protocols bgp
  multipath` node (`schema_routing.go`), a sibling of the existing
  `multiple-as`, mirroring its shape.
- **typed field** — `BGPConfig.MultipathIBGP bool` (`types_routing.go`); the
  compiler (`compiler_protocols.go`) sets it from the `ibgp` child the same way
  it sets `MultipathMultipleAS` from `multiple-as`. The count comes from the
  same `Multipath` value (default 64 when `multipath` is present).
- **render** — when `bgpMaxPaths > 1` AND `MultipathIBGP` is set, the BGP
  address-family blocks (`policy_render.go`, both ipv4 and ipv6 unicast) emit
  `maximum-paths ibgp <n>` directly after the existing eBGP `maximum-paths
  <n>` line. Without the flag the render is byte-identical to pre-#2978
  (eBGP-only), so existing configs are unaffected.
- **tests** — parse: `TestBGPMultipathIBGPSetSyntax` (`parser_routing_test.go`);
  render fail-on-revert: `TestGenerateProtocols_BGPMultipathIBGP` +
  `TestGenerateProtocols_BGPMultipathNoIBGP` (`frr_test.go`).

### #2823 — Source-NAT pool `persistent-nat permit` three-way enum

Junos `persistent-nat permit` is a three-way enum
(`any-remote-host | target-host | target-host-port`), not a binary flag. The
pre-#2823 model parsed only `permit any-remote-host` into a
`PermitAnyRemoteHost bool`, so `target-host` (remote-IP-only lease scope) was
unreachable, and the source-NAT `pool <name>` node carried NO schema body — the
whole pool stanza (address, port, persistent-nat) was unmodeled, so
`set ... persistent-nat permit target-host?` neither completed nor validated.

- **schema** — the `pool` node under `security nat source`
  (`schema_security.go`) gains a `children` map (it is a real container, so the
  SetPath replace-vs-container decision is unaffected — trailing tokens always
  descend, and a bare `pool <name>` still emits a leaf). The `persistent-nat`
  subtree declares `permit` as a `ValueEnumOf` + `ValidateEnum(any-remote-host
  | target-host | target-host-port)` typed leaf (same recipe as
  `default-policy`) and `inactivity-timeout` as a `ValueInteger` +
  `ValidateInteger(1,86400)` leaf. Other pool leaves (address/port/host) stay
  unmodeled and are left to the compiler per the opt-in-gate contract
  (`schema_walk.go`: unknown keywords return nil, never reject).
- **typed field** — `PersistentNATConfig.Permit PersistentNATPermit`
  (`types_security.go`) replaces the `PermitAnyRemoteHost bool`. The default
  (persistent-nat configured with no `permit`) is `target-host-port`, the
  byte-identical equivalent of the pre-#2823/#2819 false-flag `(dst_ip,
  dst_port)` keying. The parser (`compiler_nat.go`) accepts all three values in
  BOTH the flat-set (Keys) and hierarchical (Children) AST shapes.
- **wire** — `SourceNATRuleSnapshot.PersistentNATPermit` (string,
  `persistent_nat_permit`) carries the enum to the helper; the legacy
  `persistent_nat_permit_any_remote_host` bool is still emitted for skew
  against an older helper, which falls back to it. Additive — the only
  `protocol_wire_v1.json` change is the new key.
- **lease keying** (Rust, `userspace-dp/src/nat/source.rs`,
  `PersistentNatPermit`) — `any-remote-host`→`remote=None` (source-tuple-only),
  `target-host`→`remote=Some((dst_ip,0))` (port dropped, new remote port on the
  same host reuses), `target-host-port`→`remote=Some((dst_ip,dst_port))`.
- **tests** — Go parse/default/schema:
  `pkg/config/compiler_nat_persistent_permit_test.go`. Rust per-mode reuse
  fail-on-revert: `pool_snat_persistent_target_host_reuses_across_remote_ports`,
  `pool_snat_persistent_target_host_port_distinct_per_remote_port`,
  `pool_snat_persistent_any_remote_host_reuses_everywhere`,
  `pool_snat_persistent_permit_empty_string_falls_back_to_legacy_bool`
  (`userspace-dp/src/nat/tests.rs`).

### #3849 — Policy time-range `schedulers` daily/per-day window descend + fail-closed

The top-level `[edit schedulers]` policy time-range stanza compiled
`start-time`/`stop-time` only as DIRECT children of `scheduler <name>`, so
the actual Junos shape — `daily { start-time X; stop-time Y; }` (and the
`monday`..`sunday` day arms) — left `StartTime`/`StopTime` EMPTY. The
runtime evaluator (`pkg/scheduler.isWithinWindow`) then treated an empty
window as always-active, so a policy `scheduler-name <s>` scoped to
business hours actually permitted traffic 24/7 (HIGH, fail-open;
fable-review-161 F-014). The stanza was also ABSENT from `setSchema`
(F-013), so flat-set `set schedulers scheduler X daily start-time ...`
packed the whole line onto one leaf node and the compiler dropped it.

- **compiler** — `compileSchedulers` (`compiler_system.go`) descends into
  the `daily {}` container AND each `monday`..`sunday` container via
  `schedulerWindowFromNode`, reading `start-time`/`stop-time`/`all-day`/
  `exclude` for BOTH the hierarchical and flat-set AST shapes. The legacy
  direct-child `start-time`/`stop-time` shape still compiles unchanged.
- **typed model** — `SchedulerConfig` gains `AllDay bool` (`daily
  all-day`) and `Days map[string]*SchedulerDayWindow` (per-weekday
  overrides keyed by lowercase weekday name); a weekday override wins over
  the daily window, `Exclude` forces a day closed (`types_security.go`).
- **schema** — a new top-level `schedulers` entry
  (`schema_schedulers.go`, registered in `schema.go`) makes SetPath group
  flat-set scheduler config into the nested AST the hierarchical parser
  produces. The `start-time`/`stop-time` slots are `ValueTimeOfDay` +
  `ValidateTimeOfDay`, and `start-date`/`stop-date` are `ValueDate` +
  `ValidateDate`, so a malformed window is rejected at commit (the
  fail-closed-at-commit half). Unknown keywords stay lenient
  (`schema_walk.go`), so no valid scheduler config is newly rejected.
- **fail-closed runtime** — `isWithinWindow` no longer returns
  always-true on an empty window. A scheduler that resolves to NO window
  for a given instant (no daily window, no applicable per-day override,
  no date-only range) returns `false`. A policy bound to a window that
  failed to compile now DENIES, matching the firewall's fail-closed
  posture. "Always active" is expressed by omitting `scheduler-name` or
  using `daily all-day`. The existing
  `validatePolicySchedulerReferencesStrict` commit check (an undefined
  `scheduler-name` is already rejected) is complementary and unchanged.
- **tests** — compile descend (both shapes) + commit rejection:
  `pkg/config/compiler_schedulers_3849_test.go`; runtime fail-closed +
  per-day evaluation: `pkg/scheduler/scheduler_3849_test.go` and the
  updated `pkg/scheduler/scheduler_test.go`
  (`TestIsWithinWindow_NoWindowFailsClosed`).

## fable-167 F-2 / F-3: CoS traffic-control-profiles + filter/CoS schema gaps

**F-2 — hierarchical traffic-control-profiles (#4315).** The Junos
hierarchical shaping binding is now modeled in `schemaClassOfService`
(`schema_cos.go`) and **wired**:

- `traffic-control-profiles <name>` — typed leaves `shaping-rate`,
  `guaranteed-rate`, `delay-buffer-rate` (all `ValueRate` + `ValidateRate`)
  and `scheduler-map`.
- `output-traffic-control-profile <name>` — a binding leaf at BOTH the
  interface-unit level and the interface level (mirroring `scheduler-map`).

`resolveCoSTrafficControlProfiles` (`compiler_class_of_service.go`, called
from `compiler.go` after `applyCoSInterfaceLevelBindings`) folds a bound
profile's `shaping-rate` + `scheduler-map` into the referencing
`CoSInterfaceUnit.ShapingRateBytes` / `SchedulerMap` — so the existing
per-unit shaper enforces it. A **direct unit-level knob wins** over the
profile. Before #4315 the whole binding was silently dropped (SchemaValidate
ignores unknown keywords, no compiler read it) → a clean commit with **zero
shaping**. `guaranteed-rate` / `delay-buffer-rate` are typed + captured but
**accepted-but-inert** (no per-unit absolute reservation in the shaper); a
commit advisory (`compiler_validate_warn.go`) surfaces the inertness, and a
dangling `output-traffic-control-profile` reference also warns.

**F-3a — firewall `interface-specific` (#4316).** Added as a presence flag
under `firewall family {inet,inet6} filter <name>`; captured on
`FirewallFilter.InterfaceSpecific`. It is **accepted-but-inert** — xpf keeps
a single shared counter rather than a per-interface instance — with a commit
advisory (`validateFirewallInterfaceSpecificWarnings`).

**F-3b — CoS `inet-precedence` + `exp` (#4316).** Added
`classifiers inet-precedence`, `rewrite-rules inet-precedence`, and
`rewrite-rules exp` to `schemaClassOfService` (completion + `?` help). They
are **accepted-but-inert** — the userspace dataplane classifies / rewrites on
`dscp` / `ieee-802.1` only. Their names are recorded on
`ClassOfServiceConfig` (`INetPrecedenceClassifiers` /
`INetPrecedenceRewriteRules` / `EXPRewriteRules`) solely to drive a commit
advisory; no runtime structure is built.

**Gap 4 — CoS `rewrite-rules ieee-802.1` (802.1p PCP egress rewrite,
#4228).** Added `rewrite-rules ieee-802.1 <name> { forwarding-class <fc> {
loss-priority <lp> code-point <0..7>; } }` to `schemaClassOfService`, plus the
`rewrite-rules ieee-802.1 <name>` binding at the interface unit and
interface level. Unlike F-3b (name-only), the mapping is **fully modeled** —
`compileClassOfService` parses it into `IEEE8021RewriteRules`
(`CoSIEEE8021RewriteRule` / `CoSIEEE8021RewriteRuleEntry`, mirroring the DSCP
rewrite), the loss-priority typo gate and the code-point `0..7` range check
apply, and dangling forwarding-class / rewrite-rule references warn — but it is
**accepted-but-inert**: the userspace dataplane rewrites `dscp` on egress only
and does not yet own the 802.1Q tag write, so a commit advisory
(`compiler_validate_warn.go`) surfaces the inertness. The classifier side
(`classifiers ieee-802.1`) is already enforced; only the egress rewrite half
awaits egress 802.1Q tag ownership in the AF_XDP TX path (the Rust follow-up).
Modeled so imported vSRX configs commit clean instead of being rejected as an
unknown leaf.

## System syslog host/file sub-statements (#4303 S-1)

A `system syslog host <h>` / `file <f>` / `user <u>` destination body is a
mix of `<facility> <severity>` pairs (`any warning;`, `daemon info;`) and
NON-facility modifiers (`source-address 10.0.1.1;`, `port 5514;`,
`match "re";`, `structured-data;`, `explicit-priority;`, `archive size 1m
files 5;`). The compiler previously treated EVERY non-`allow-duplicates`
child as a `<facility> <severity>` pair via a `len(Keys) >= 2` fallback, so
`source-address 10.0.1.1` was captured as
`SyslogFacility{Facility:"source-address", Severity:"10.0.1.1"}`.
`applySystemSyslog` reads `Facilities[0].Facility` for the remote client's
facility, so a leading `source-address` set the whole forwarding client's
facility to garbage. The strict commit-check ALSO rejected these lines: the
schema `host`/`file`/`user` nodes carried only the `<facility> <severity>`
wildcard, so `source-address 10.0.1.1` was validated against the severity
enum and rejected (an IP is not a severity).

- **compiler** — `compileSystem` syslog loop (`compiler_system.go`) now
  switches on the known modifier keywords before the pair fallback. Host
  `source-address`/`port` are captured into `SyslogHostConfig.SourceAddress`
  / `.Port`; `match`/`structured-data`/`explicit-priority`/`log-prefix`/
  `facility-override`/`archive` are recognized-and-skipped. The
  `syslogFacilitySeverity` helper extracts the pair (flat `Keys[0]/Keys[1]`
  or hierarchical `Keys[0]` + child) and returns ok=false for a valueless
  leaf, so a bare/garbage keyword is dropped instead of appended as a
  half-populated filter.
- **schema** — `syslogDestinationModifiers` models the modifiers as named
  children so they take precedence over the wildcard. `source-address` is
  `ValueIPAddress`, `port` is `ValueInteger(1,65535)`; the rest are accepted
  structurally. No valid syslog config is newly rejected.
- **runtime** — `applySystemSyslog` (`pkg/daemon/daemon_system.go`) now binds
  the outgoing socket to `host.SourceAddress` (via
  `logging.NewSyslogClientWithSource`) and honors `host.Port` instead of the
  hardcoded 514.
- **tests** — `pkg/config/compiler_syslog_hostmods_4303_test.go` (facilities
  not polluted, source-address/port captured, strict commit accepts).

## Custom system login class (#4304 S-2)

The `system login user <n> class <c>` leaf was a fixed enum over the
system-defined built-ins (`ValidLoginClasses()`), so a config that defined
its own RBAC class (`set system login class noc-admin permissions all` +
`set system login user bob class noc-admin`) was HARD-REJECTED at commit —
blocking the whole config. This is accept-with-advisory now:

- **schema** — a new `system login class <name>` container
  (`schema_system.go`) with children `permissions` (multi), `idle-timeout`
  (int), `allow-commands`, `deny-commands`, `allow-configuration`,
  `deny-configuration`, `login-alarms`, `login-tip`. The `user ... class`
  leaf switched from `ValidateEnum(ValidLoginClasses())` to the tree-aware
  `treeValidator: validateLoginClassRef`, which accepts the built-ins UNION
  the custom class names collected from the tree (`schemaRefs.loginClasses`,
  `collectSchemaRefs`, merged from `defsSource` too). An undefined class
  still fails closed.
- **compiler** — `compileSystem` login loop parses the `class` definitions
  (before users) into `LoginConfig.Classes`, folding the Junos `permissions`
  tokens onto the coarse xpf model via `mapJunosPermissions`
  (`LoginClass.MappedPermissions`). Only whole-box tokens map precisely;
  everything else folds DOWN to a PermView floor (never over-grants
  config/control/maint from a narrow subsystem token). **No privilege
  escalation** (#4311 review): `reset` = restart daemons → PermControl (NOT
  PermMaint — the destructive reboot/halt/zeroize verbs); `rollback` = revert
  to a prior commit → PermView floor (NOT PermConfig); only `maintenance` →
  PermMaint and only `configure` → PermConfig.
- **advisory** — `loginClassAdvisoryWarnings` emits one `cfg.Warnings` entry
  per custom class naming the mapped permissions. `allow-commands` /
  `allow-configuration` / `idle-timeout` are named as accepted-but-not-enforced
  (neutral). `deny-commands` / `deny-configuration` get an explicit `WARNING`
  that, because they are unenforced blacklists, the class is **more permissive
  than the Junos config** (the denied verbs stay allowed) — a weaker posture,
  not merely "unenforced". Full per-command deny enforcement is a follow-up.
- **runtime** — `pkg/cli/permissions.go` `resolveClassPerms` consults the
  built-ins first, then `store.ActiveConfig().System.Login.Classes`, so a
  custom-class user is enforced against the mapped permissions instead of
  being locked out as an "unknown login class". Both `checkPermission` and
  `showConfigRedacted` route through it.
- **tests** — `pkg/config/login_custom_class_4304_test.go` (commit accepts +
  mapping + advisory + undefined-still-rejected);
  `pkg/cli/permissions_custom_class_4304_test.go` (runtime enforcement +
  redaction).

## SSH hardening knobs (#4305 S-4)

The SSH compiler read only `root-login` + `key-exchange`, so the standard
sshd-hardening knobs committed clean (unknown-key accepted-inert) and never
reached the `sshd_config.d/xpf.conf` drop-in — the box kept base-image cipher/
MAC defaults even when the operator configured hardened algorithms.

- **schema** (`schema_system.go`) — `services ssh` gains `ciphers` (multi),
  `macs` (multi), `connection-limit` (int 1-250), `rate-limit` (int 1-250),
  `client-alive-interval` (int 0-65535), `client-alive-count-max` (int 0-255),
  `protocol-version` (enum v1|v2). ciphers/macs are free-form (sshd validates
  spellings at reload). OpenSSH `@`-suffixed algorithm names are configurable
  via quoting (`ciphers "aes256-gcm@openssh.com"`).
- **compiler** (`compiler_system.go`) — parses them into `SSHServiceConfig`.
  ciphers/macs read every value via `firewallMatchValues` so a `[ a b ]`
  bracketed list is not truncated. client-alive-* carry presence flags because
  0 is a meaningful sshd value.
- **runtime** (`daemon_system.go buildSSHDConfig`) — renders `Ciphers`, `MACs`,
  `MaxStartups` (connection-limit's nearest sshd equivalent),
  `ClientAliveInterval`, `ClientAliveCountMax`.
- **validation gate** (#4311 review) — `applySSHConfig` runs `sshd -t`
  (`sshdValidateCmd`) on the merged config AFTER writing the drop-in but BEFORE
  the reload. A bad `Ciphers`/`MACs`/`KexAlgorithms` spelling fails `sshd -t`,
  the drop-in is reverted to its prior content (or removed when there was
  none), and the reload (SIGHUP) is **skipped entirely** — so a cipher typo can
  never make sshd re-exec into an invalid config and drop its listener (SSH
  lockout on the appliance). This makes the lockout protection self-contained
  rather than relying on the base-image `ExecReload=sshd -t`; the reload-failure
  revert stays as a backstop.
- **advisory** — `protocol-version` is accept-with-advisory: modern sshd is
  SSH-2 only, so `v2` is a silent no-op and any other value emits a
  `cfg.Warnings` advisory (`sshHardeningAdvisoryWarnings`). `rate-limit` has no
  clean sshd equivalent; it is accepted and covered by the S-5 inert-knob
  advisory scan.
- **tests** — `pkg/config/compiler_ssh_hardening_4305_test.go`,
  `pkg/daemon/daemon_ssh_test.go` (`TestBuildSSHDConfigHardeningKnobs`,
  `TestBuildSSHDConfigClientAlivePresence`, and the validation-gate guards
  `TestApplySSHConfig_ValidationGateBlocksReload` /
  `...ValidationGateRemovesWhenNoPrior` / `...ValidationPassesThenReloads`).

## Grouped system/SNMP inert knobs — accept-with-advisory (#4306 S-5)

A cluster of `system`/`snmp` knobs commit clean but do nothing, several
security-relevant. Rather than silently dropping them, the compiler now emits
a loud accept-with-advisory (`cfg.Warnings`) so the operator learns the knob is
inert. Advisory messages are built from the node IDENTITY (keywords) only —
never a leaf value — so an SNMP community string or an NTP authentication-key
is never echoed into a warning.

- **SNMP** (`snmpInertKnobWarnings`, `compiler_system.go`) — `view` /
  community `view` (MIB view scoping is NOT enforced → full ifTable exposure),
  `trap-options source-address` (traps use the default egress IP),
  `health-monitor`, `rmon` (no-ops).
- **system** (`systemInertKnobWarnings`) — `login message` / `announcement`
  (banners not applied), `login retry-options` (lockout not enforced), `ntp
  boot-server` / `authentication-key` / `source-address`, and
  `internet-options` leaves beyond `no-ipv6-reject-zero-hop-limit`. Also the
  S-4 `services ssh rate-limit` (no sshd equivalent).
- These are advisory-only by design: the knobs already committed clean
  (unknown keys under a known container are accepted-inert by the opt-in
  typed-leaf gate), so no valid config is newly rejected. The security-relevant
  ones (community view scoping, trap source-address) get an explicit
  "accepted but NOT enforced" note rather than an implicit full-exposure
  surprise. Note: SNMP community `clients` source-IP restriction is tracked
  separately (S-3, not this change).
- **tests** — `pkg/config/compiler_inert_knobs_4306_test.go` (advisories fire,
  no secret echoed).
