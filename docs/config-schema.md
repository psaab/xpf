# Config schema: the two-SSOT split (#1319)

xpf has **two** command-tree sources of truth. Knowing which one to edit
is the single most common mistake when adding CLI completion or config
validation.


## Compact (packed) stanza bodies

A stanza body can be written NESTED or PACKED onto one line, and the two are the
same configuration:

```
security { screen { ids-option s1 { icmp { ping-death; } } } }   nested
security { screen { ids-option s1 icmp ping-death; } }           packed
```

The parser does not normalise them. A packed body arrives as extra tokens on the
node's OWN `Keys`, with no `Children` at all:

```
nested   [ids-option s1] -> [icmp] -> [ping-death]
packed   [ids-option s1 icmp ping-death]
```

A compiler that descends only `node.Children` therefore sees an EMPTY body. The
instance NAME survives, which is what makes this class hard to notice: the
profile/host/term exists, `show configuration` displays what the operator wrote,
it binds to a zone or an interface normally — and it enforces nothing. Known
instances all failed in the security-relevant direction: a syslog host with zero
facilities ships nothing (#6684), a filter term with an empty action does not
discard (#6685), and a filter term whose `from` was dropped matches EVERYTHING
(#7457).

**Use `packedBodyChildren` / `packedBody` (`compact_tail.go`) instead of reading
`node.Children` directly** when compiling a stanza that accepts a packed body.

Two further instances were fixed this way (#6818, #6822), both failing in the
security-relevant direction with **zero warnings on the strict commit path**:

| issue | stanza | what the compact spelling dropped |
|---|---|---|
| #6818 | `protocols ospf area <a> interface <i> authentication` | `AuthType`/`AuthKey` — the adjacency forms UNAUTHENTICATED |
| #6822 | `snmp v3 usm local-engine user <u> authentication-* / privacy-*` | the passwords, while the PROTOCOL still set — the user is registered as requiring SHA-256 and AES-128 with empty credentials |

**A packed tail and a nested block can appear on ONE node**, contrary to what
`packedBodyChildren`'s comment used to claim. `authentication md5 7 { key "x"; }`
parses as `Keys=["authentication","md5","7"]` with `Children=[["key","x"]]`.
Returning the two as SIBLINGS is wrong in the silent direction: OSPF compiled
`AuthType=md5` with an **empty key**. They spell one path, so the nested block is
now attached UNDER the deepest packed node.

**#6821 is now fixed, and the rule that blocked it is what fixed it.** The strict
gate ignores leftover `Keys` on a container by design — compiler-faithful, since
the compiler did not read them either. That equivalence breaks the moment a
compiler starts reading them, and measured on master before the fix it had:
`transport { protocol tpc; }` was rejected by the enum while
`transport protocol tpc;` was **accepted**.

So the rule stands: **a compiler may only start reading a packed tail at a site
where the gate validates the same expansion.** #6818's leaves have no enum to
bypass (a bogus child is inert in both spellings today), which is why that one
landed first.

`schemaNode.packedTail` is how a site satisfies the rule instead of waiting for
it. Setting it says *"a compiler reads this container's packed tail"*, and
`walkSchemaNode` then validates the same `packedBodyChildren` expansion the
compiler consumes — one schema fact rather than two files agreeing by comment.
Default-off is deliberate: for every other container the tail is not compiled,
so validating it would reject a configuration that behaves identically either
way.

`security log stream <s> transport` sets it, and all three readers now share one
expansion resolved by `securityLogTransportSchema()`:

| spelling | gate | compile |
|---|---|---|
| `transport { protocol tls; }` | accept | `Protocol="tls"` |
| `transport protocol tls;` | accept | `Protocol="tls"` (was `""`) |
| `transport { protocol tpc; }` | **reject** (enum) | — |
| `transport protocol tpc;` | **reject** (enum) (was accept) | — |
| `transport { tls-profile p; }` | accept | **reject** (#3350) |
| `transport tls-profile p;` | accept | **reject** (#3350) (was accept-and-drop) |

The empty-`Protocol` consequence is worth stating plainly because it is not
inert: `daemon_system.go` defaults an empty protocol to `udp`, so the compact
spelling of a TLS audit stream shipped over **plaintext UDP** while the config
on disk still read `protocol tls`. The `tls-profile` half fails the other way —
xpf resolves no TLS profile at all, so the block spelling is *rejected* at
commit; the compact one lost that diagnostic as well as the value.

#6822 is the one that does not use `packedBodyChildren`: its protocol comes from
the reader's `case` label rather than from a value, so the reader needs the whole
key run rather than a rebuilt child tree. `parseSNMPv3UserKeys` already consumes
exactly that run for the flat-`set` path, so the compact block form is routed
through the same function rather than growing a second copy of its table.

**Not every divergence is a defect.** `system login user <u> authentication`
(#6817) reads `node.Children` deliberately: the compact spelling is rejected at
commit by the #6662 packed-login-body gate, and on the tolerant load / peer-sync
path it warns and leaves the stanza inert so a peer-synced config behaves exactly
as the binary that accepted it behaved (#1960). Compiling it there would change
RBAC across an HA sync between nodes on different binaries. The #2419 inventory
records this in a `filedByDesign` category so the entry is not mistaken for one
awaiting a fix. #6821's two leaves USED to sit in the same category; they moved
to `filedFixed` once `packedTail` removed their blocker.

A group applying a stanza in the compact spelling over an existing same-name
peer drops the group's value (#7648). That is a property of the group merge
rather than of any compiler, and it predates these fixes — but #6822 changes its
consequence for SNMPv3 from "nothing configured" to "authentication selected
without a key".

### Why it is schema-driven

The packed tail does NOT expand uniformly, which is why a split on whitespace is
wrong and why fixing one site by hand does not generalise:

| packed | expands to | shape |
|---|---|---|
| `ids-option s1 icmp ping-death` | `[icmp]` -> `[ping-death]` | a chain |
| `host 10.0.0.1 any any` | `[any any]` | ONE two-key leaf |
| `term t1 then discard` | `[then]` -> `[discard]` | a chain |

How many tokens each level swallows is a property of the grammar, and the
grammar already has a single source of truth: `setSchema`, whose
`schemaNode.args` is "extra tokens consumed as part of this node's key".
The expander uses `consumeNodeKeys`, the same primitive `SchemaValidate` uses,
so expansion cannot drift from validation.

A tail that leaves the modelled grammar is returned UNEXPANDED rather than
guessed — the helper exists to stop configuration being silently dropped, and
inventing a shape the schema does not describe is another way of doing that.

**A stanza whose leaves are not modelled in `setSchema` cannot be expanded**,
because an unmodelled keyword cannot be resolved and the expander declines
rather than guessing. That was the blocker on #6683: `security screen ids-option
<p> icmp` modelled only `fragment`. The screen subtree is now modelled in full
(#6683/#7460) — every check flag plus every sub-knob — which also gives those
leaves `?` completion and `SchemaValidate` reach that they never had.

Modelling a subtree is not free, and the screen case is the worked example of
what else has to move with it:

- **Sub-knob children are load-bearing, not decoration.** `flood` modelled as a
  bare flag makes the expander stop at `[flood]` and silently DROP a trailing
  `threshold 500` — the same silent weakening the issues are about. Model the
  value, or do not model the parent.
- **Modelling changes flat-set token grouping.** `ast_edit.go` keys on
  `args`/`children`/`compoundKey`/`multi`, so a value that used to collapse onto
  `Keys` now parks as a CHILD. Any compiler reading a fixed `Keys` index for
  that value breaks on a path that worked. `flood` read `Keys[2]` while its
  siblings read `Children`; single-sourcing all four onto the child shape is
  what made the change safe (#7460).
- **It moves trailing-garbage detection from `Keys` to `Children`.** A modelled
  childless leaf parks flat-set trailing tokens as children, so a compiler
  calling only `recordKeyExtras` stops seeing them and the #3332/#3318 gate goes
  quiet. Arm `recordChildExtras` on every leaf you model.
- **It can add entries to the #2419 spelling-differential gate.** Ten bare flags
  legitimately name a different garbage token per spelling. Allowlisting that is
  a CLAIM, so it is paired with a test asserting the commit decision is REJECT
  in BOTH spellings — otherwise the allowlist would hide a fail-open.

### Where it is NOT done

Expansion is deliberately not done in the parser. `show configuration` renders
from the AST, so normalising at parse time would rewrite the operator's packed
one-liner into nested form on display — a round-trip fidelity change well beyond
fixing the compile-time drops.

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

## Typed WILDCARD identity slots (`keyValidator` on a wildcard, #6834)

A `keyValidator` on a **named-keyword** node validates the arg token(s) that
follow the keyword — `unit <n>`, `address <cidr>`. The walker implements that as
`node.Keys[1:1+args]`.

A **wildcard** node is different: its identity IS the keyword, at `Keys[0]`, and
it declares no args. So the arg span is `Keys[1:1]` — empty — and before #6834 a
`keyValidator` on a wildcard validated **nothing at all** and returned nil. Every
one of the schema's existing `keyValidator`s sat on a `<keyword> <arg>` slot, so
the gap had no instance and no symptom until an interface name needed gating.

`walkSchemaNode` now validates a wildcard's own keyword as identity slot 0.
Which of the two cases applies is decided by a single hoisted `exactMatch`
local, read by both the scalar-value-leaf rule and this one — two copies of
"was this an exact match?" could only ever disagree by mistake.

**Precondition, verified rather than assumed.** `exactMatch` is
`parent.children[keyword] == childSchema`, a POINTER comparison. If any parent
registered the same `*schemaNode` as both a named child and as its wildcard, the
predicate would report EXACT for a wildcard match and this gate would silently
stop running — no failure, just unvalidated config again.
`TestNoSchemaNodeIsBothChildAndWildcard_6834` walks the whole schema (1464 nodes,
0 aliases at the time of writing) to keep that true, and
`TestAliasDetectorFindsARealAlias_6834` plants an alias so the detector itself
cannot rot into a tripwire that never fires.

### The rule reaches TYPED LEAVES too (#6844)

#6834 installed the wildcard-identity check in `walkSchemaNode`'s **container**
branch. The **typed-leaf** branch returns before that point, so a wildcard node
that is a typed leaf validated its VALUE and never its identity.

`system syslog <dest> <facility> <severity>` is exactly that shape — the
facility is the wildcard key, the severity is the value. The severity has been
enum-gated since #2008; the facility accepted anything, so

```
set system syslog file audit "daemon;*.* /tmp/pwn" info
```

passed `SchemaValidate` and committed. #6829 belts the RENDER site, so nothing
injected reaches rendered rsyslog configuration — but the commit path told the
operator nothing and their configuration silently did not do what it said.

The typed-leaf branch now runs the same `!exactMatch` identity check, and
`exactMatch` is hoisted above it: still one computation, now three readers.

`ValidateSyslogFacility` **delegates to the render belt's own predicate**
(`config.SyslogSelectorFacilitySafe`) rather than carrying its own alphabet.
`pkg/daemon` imports `pkg/config`, so the rule lives here and the belt calls it —
what the commit path ACCEPTS and what the render path WRITES are one set by
construction.

That matters because the first cut did carry its own alphabet, and it was wrong
in both directions at once: it rejected `auth,authpriv` and bare `*` (rsyslog-native,
documented, render-asserted, so valid configs would have stopped committing) while
admitting `.` and `_`, which the belt drops — leaving the
"commit succeeds, destination disappears" class the gate exists to close still
open. `TestCommitGateAndRenderBeltAcceptTheSameFacilities_6844` binds the
agreement over a derived corpus, with anti-vacuity floors in both directions and
the only two licensed disagreements (empty, and the length bound) named so a
third cannot hide among them.

It is not membership of a facility enum, deliberately. The Junos vocabulary already lives in `pkg/logging`, and
`pkg/logging` imports `pkg/config` (`trace.go`), so the two cannot be
single-sourced without a new leaf package. Two independently maintained copies
drift, and the drift is silent in the direction that REJECTS a valid operator
config the renderer maps correctly — worse than accepting an unknown but
well-formed name, which #6830 already diagnoses at render, by name. The alphabet
matches `syslogNameRE`'s because the facility is formatted into the same
rendered drop-in body.

No new lenient opt is needed. The #1319 split already bounds it: `SchemaValidate`
is strict only on the operator-driven commit path, and `Store.compileTreeLenient`
downgrades a violation to a warning on the tolerant `Load` / `SyncApply` ingress,
so a persisted or peer-synced config still boots (#1960). A cell pins that
boundary by asserting the COMPILER still accepts the value — if the rejection
migrated into `CompileConfig` it would become unconditional and blackout-boot the
node.

The strictness boundary is proved rather than asserted:
`pkg/configstore`'s `TestLoadToleratesAnInjectableSyslogFacility_6844` drives the
real `Store.Load` and requires the node to boot with an active config, paired
with a commit-check cell that requires the same value to be rejected. Without the
pair, "Load tolerates it" is satisfied by a build where nothing rejects it
anywhere — the pre-#6844 state.

`TestWildcardTypedLeafKeyValidatorInventory_6844` enumerates every leaf the new
rule reaches — the three system-syslog destinations and nothing else today — so
adding a `keyValidator` to a wildcard typed leaf is a deliberate edit rather than
a config that quietly stops committing. It reads schema METADATA, so it cannot
see whether the rule actually RUNS —
`TestWildcardTypedLeafKeyValidatorRuleIsWired_6844` drives all three destinations
through the real gate and is the half that reds when the walker hunk is reverted.

### `interfaces <name>` is the first typed wildcard identity

The interface name is interpolated into four sites in the generated systemd
units, and one of them — `[Match] Name=` in the `.network` file — systemd reads
as a **whitespace-separated list of shell-style globs, matching the device name
or its alternative names**. An unvalidated name does not corrupt the unit file;
it makes one `.network` claim SEVERAL interfaces.

`ValidateInterfaceName` is an **allowlist**: letters, digits, `-`, `.`, `_`, `/`.
The slash is included because the Junos spelling `ge-0/0/0` is the documented
form and is canonicalised to `ge-0-0-0` downstream.

**Do not "simplify" it into a call to `sanitizeUnitValue`.** That helper maps
control bytes to a SPACE, which for a whitespace-separated list is the
SEPARATOR — it would turn one pattern into two, each claiming devices. Applying
the safe-looking neighbouring helper to this sink is strictly worse than
rendering the field raw.

**No length bound**, deliberately: `IFNAMSIZ` applies to the DERIVED kernel name
(slashes folded, `.<unit>` appended), so a bound here would have to model that
derivation, and a validator wrong in the *rejecting* direction turns a working
config into a failed commit with no operator workaround (the #6564
`ValidateOSPFArea` lesson, where a `>= 1` floor would have refused OSPF area 0).

### `interfaces <if> tunnel mode` — the leaf allowlist mirrors the dataplane (#6924)

`tunnel mode` carried **no validator at all** until #6924, so
`set interfaces gr-0/0/0 tunnel mode banana` committed green. `buildKernelTunnelLink`
(`pkg/routing/tunnel.go`) has a `default:` arm that builds a GRE device for
anything that is not `ipip`, so the operator got a visible, UP interface that
carried nothing — the same symptom #4785 exists to reject, reached by a route
#4785's `ipip`-keyed gate cannot see.

The leaf now carries `valueType: ValueEnumOf` +
`validator: ValidateEnum(TunnelModeNames)`, and **`TunnelModeNames` is a mirror,
not a source**. The SSOT is the dataplane's own predicate, `tunnel_mode_kind` in
`userspace-dp/src/afxdp/forwarding_build/tunnels.rs`: a mode it maps to
`TunnelKind::Gre` or `TunnelKind::WireGuard` is carried, everything else falls to
`TunnelKind::Unknown` and is dropped. The two lists are in different languages so
neither can import the other, and the agreement — not either literal — is what
`TestTunnelModeAllowlistMatchesTheDataplane_6924` asserts, by parsing the Rust
match arms. Same shape as `MasterPasswordPRFNames` against `configstore.prfHash`.

Accepted: `gre`, `ip6gre`, `wireguard`.

`ipip` is deliberately **absent**. It is a mode the system recognises and the
dataplane does not carry, so the leaf refuses it as one instance of the general
rule rather than as a special case; #4785's strict gate still runs and still
produces the endpoint-naming diagnostic for the case the leaf cannot see — an
`ip-*` interface with no `mode` statement at all, which the parser defaults to
`ipip`.

**#1960 no-brick.** The leaf validator runs only on the STRICT path
(`compileTreeStrict` → `schemaValidateExpandedTreeForNode`). `compileTreeLenient`,
which `Store.Load` and `Store.SyncApply` use, does not schema-validate at all, so
a config already persisted with an unrecognised mode still boots and keeps the
stanza verbatim. Both halves are bound at the STORE ingress
(`tunnel_mode_no_brick_6924_test.go`), not only at the validator, because a change
that made `Store.Load` schema-validate would leave every `pkg/config` test green
while a booting node lost its config.

**The `valueExamples` order is load-bearing.** They are listed `ip6gre, gre`, not
`gre, ip6gre`. The #2419 compact/block census synthesises its probe values from
`valueExamples[0]` and `[1]`, and this site is compact-blind: the compact spelling
drops the value and `Mode` falls back to the parser's default, which is `gre`.
Putting `gre` first makes the dropped value and the fallback identical, so a real
divergence reads as EQUIVALENT and the #2419 inventory entry looks stale. A
fixture must never use the value the bug falls back to.

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

The lenient WARN side (`ValidateConfig(cfg *Config) []string`, aggregated on
the same commit path but appending advisories instead of failing) got the
same treatment in #4845: the former ~3.6k-LOC `compiler_validate_warn.go`
monolith was split by domain into sibling files
(`compiler_validate_warn_{host_inbound,routing,firewall,ddns,cos}.go`),
mirroring the strict layout. The residual `compiler_validate_warn.go` keeps
`ValidateConfig` itself (the dispatcher) plus the generic helpers it calls
inline (NAT `sortedPoolNames` / `deterministic*Enforced`,
`schedulerHasEffectiveWindow`, `anySamplingDirectionConfigured`). It was a
pure code-motion split with byte-identical bodies — grep the function name to
find its current file.

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

### RETH `redundancy-group` token fail-open (#6782)

`interfaces <name> redundant-ether-options redundancy-group <id>` is an
UNTYPED schema leaf (`schema_interfaces.go`: `args: 1`, no `valueType`, no
`validator`), so `SchemaValidate` never inspects the token. `compileInterfaces`
then reads it as

```go
if v, err := strconv.Atoi(nodeVal(rgNode)); err == nil {
    ifc.RedundancyGroup = v
}
```

— the parse error is DISCARDED, so a non-numeric / fractional / int64-overflow
token leaves the group at its `0` default, and a NEGATIVE token parses
successfully and is stored verbatim.

The consequence is not cosmetic. Every downstream consumer decides "is this a
RETH?" with `redundancy-group > 0`: `pkg/dataplane/compiler_iface.go` sets
`isReth` and `isVRRPReth` that way. With a non-positive group the interface is
treated as ORDINARY — the `169.254.<group>.<node+1>/32` link-local substitution
does not fire, and the reth's real service address is written onto the physical
device with `KeepAddresses:false`. **Both nodes run the same synced
configuration, so BOTH configure that address** — a duplicate-address /
split-brain condition on the data path, from a config that commits silently.

`validateRethRedundancyGroupTokensAST` (`compiler_reth_rg_token.go`, an AST
pre-walk gate in `runPreWalkGates`) closes it: strict-reject at commit /
commit-check, warn on the tolerant load / peer-sync path
(`lenientRethRedundancyGroup`). It runs on the raw AST for the same reason
`validateChassisClusterIdentitiesAST` (#5694) does — once the typed
`InterfaceConfig` exists, a malformed token has already collapsed to `0` and is
indistinguishable from a reth with no `redundant-ether-options` stanza at all.

Accepted range is `1..255`:

- The floor is 1 because **group 0 is the chassis-cluster CONTROL-PLANE group**,
  not a data-plane one — `cluster.Manager.DataGroupIDs` already documents and
  enforces exactly that ("RG0 is reserved for control-plane ownership and is
  omitted"). A reth in group 0 is a contradiction by the codebase's own
  definition.
- The ceiling is 255 because the group id is the THIRD OCTET of the derived
  link-local address, and it is also the ceiling
  `MaxHeartbeatRedundancyGroupID` already places on the group declarations, so
  no id above it can name a declared group.

This is a DIFFERENT, looser bound than `MaxRethRedundancyGroupID` (155), which
exists for the RFC 5798 VRID range and is enforced by
`validateRethVRRPGroupIDStrict` ONLY when a reth-derived VRRP instance is
actually synthesized — that gate returns early under `no-reth-vrrp` /
`private-rg-election`, and **private-rg-election is the compiler DEFAULT**
(`compiler_system.go`), so on a default cluster config it never runs. The
link-local substitution is not mode-gated, so the octet ceiling has to be
enforced independently. The two compose: in a VRRP mode the stricter 155
applies, otherwise this 255 does.

**The tolerant path suppresses, it does not merely warn.** Warning and then
installing the address anyway would make the lenient path the bug, so
`suppressInvalidRethAddresses` (`compiler_interfaces.go`) additionally strips
the affected reth's unit addresses — and those of any interface inheriting from
it via `RedundantParent`, which would otherwise reintroduce exactly what was
removed. The node still BOOTS as #1960 requires; it simply offers no service on
that interface until the group is repaired. The group id is deliberately left
as written: it is what the operator has to fix, and rewriting it here would
erase the evidence and let a later strict commit-check pass on a config that is
still wrong.

**Deliberately out of scope**, each measured rather than assumed:

- A reth with NO `redundant-ether-options` stanza is an ABSENT token, not an
  invalid one. Several in-tree configs legitimately touch a reth without
  redeclaring its group as a partial/overlay fragment
  (`test/incus/sqm-cookbook-config.set` sets an ADDRESS that way), so requiring
  presence would reject them. Separate policy question.
- A positive id naming no DECLARED `chassis cluster redundancy-group` does not
  trigger this fail-open at all — it still reads as RG-scoped and still takes
  the link-local substitution — so rejecting it would be a new restriction
  rather than a fix.

Pinned by `compiler_reth_rg_token_6782_test.go`, which tests the range from both
sides (1 and 255 must commit; 0 and 256 must not) and asserts the tolerant-path
suppression together with its positive control.

### firewall-filter term rule-expansion count overflow (#5456)

This is a `uint32`-overflow fix plus an **advisory warning** — NOT a strict
commit gate. `config.FilterTermExpansionCount` returns the per-term counter-slot
**stride** (the #3459 SSOT the retired-eBPF filter-counter readers walk): the
cross-product (literal source-addresses + every source-prefix-list prefix) ×
(literal destination-addresses + every destination-prefix-list prefix) ×
destination-ports × source-ports. It was computed as `int` products and cast
straight to `uint32` with no overflow check, so a term whose product exceeds 2^32
(e.g. a 5000-prefix source list × a 5000-prefix destination list × 100
dest-ports × 100 src-ports = 2.5e11) **wrapped** to a small wrong stride — which,
**on the retired-eBPF per-rule counter path only**, would drift a later term onto
a neighbour's counter slots.

The fix computes the product in overflow-checked `uint64`
(`FilterTermExpansionCount64`, `math/bits.Mul64`) and **clamps** the `uint32`
stride to `MaxFilterTermExpansion` (1<<20 = 1,048,576, in
`firewall_filter_expand.go`) instead of wrapping; `pkg/dataplane.expandFilterTerm`
(retired-eBPF compiler) caps its materialized slice at the same bound, so the
drift-guard invariant (count == `len(expandFilterTerm)`) holds for an over-bound
term too. The wrap can no longer occur.

**Why no hard reject.** The cross-product and its stride are retired-eBPF-path
artifacts. The **live userspace dataplane** enforces a filter term natively —
prefix-**set** membership (`ResolveFilterPrefixListAddrs`) with **name-keyed**
per-term counters (`FirewallFilterTermCounterKey`) — never materializes the
cross-product, and is immune to stride drift. A term referencing two ~1500-entry
prefix-lists (2.25M cross-product) is handled trivially by the live runtime, so
rejecting it at commit would false-reject a legitimate, enforceable config.
Instead `warnFilterTermExpansionOverBound` (`compiler_validate_strict_filter.go`,
called unconditionally in `runUniformGates`) appends an advisory that per-rule
`show firewall filter` counts on the retired-eBPF path (unused on this build)
would be clamped/inexact for such a term. It never blocks commit or load (#1960).
Distinct from #3459, which fixed the stride's *layout* SSOT, not its overflow.

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
  (`cfg.Security.IPsec.VPNs[*].BindInterface`) — a `bind-interface`
  materializes an xfrmi device at apply time (`daemon_apply` →
  `routing.ApplyXfrmi`) even with no explicit `set interfaces st0 unit 0`. The
  base is the bind string with any `.unit` stripped, so every unit of a bound
  secure tunnel is admitted.

  The device is named after the AUTHORED bind string, not after the unit ref:
  `bind-interface st0.0` creates a netdev literally named `st0.0`, while
  `bind-interface st0` creates one named `st0` — and the unit ref is `st0.0` in
  both cases, so the name cannot be derived from the ref. This line previously
  read "`bind-interface st0.0` materializes the st0 xfrmi device", which is the
  exact conflation #5619 exists to correct.

  The bind string is taken VERBATIM; nothing canonicalizes the index. `st5`,
  `st05` and `st+5` are three different device names that happen to derive one
  XFRM if_id, and each admits only its own spelling as a zone-referenceable
  base. Commit accepts all three (`ValidateSecureTunnelBindInterface` only
  requires a nonzero if_id), and rejecting the unusual spellings was considered
  and declined in #6691 — a new commit-time rejection would brick a persisted
  or peer-synced config that already carries one (#1960 no-brick). Ownership is
  therefore matched on the spelling, so `bind-interface st05` does not claim an
  interface named `st5`.

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

### `security ipsec vpn … bind-interface` canonical-name fail-closed (#5297)

`security ipsec vpn <name> bind-interface` is a free-form 1-arg string the
runtime resolves to a Linux xfrmi device name and a stable XFRM if_id via
`XFRMIfNameAndID` (`xfrmi.go`). Only the canonical secure-tunnel spelling
`st<N>` or `st<N>.<unit>` (e.g. `st0`, `st0.1`) resolves; every OTHER name
(`secure0`, a bare `st`, a physical `ge-0/0/0`) yields **if_id 0** — the
authoritative "creates no XFRM device" sentinel. Before #5297 such a name
committed successfully: the #2933 if_id-collision gate deliberately `continue`d
past any if_id-0 name (out of scope for a *collision* between two VALID
aliases), the schema leaf was untyped, and the compiler stored the string
verbatim. At reconciliation the routing manager logged "invalid bind-interface
name" and created no device, so the route-based VPN was silently DOWN with a
clean commit — the #5297 vSRX-parity gap.

The fix fails closed at **two layers** (the #1960 layered-defense doctrine),
both strict-on-commit / lenient-on-load:

- **Typed-leaf schema layer** — the `bind-interface` leaf (`schema_security.go`)
  is now `valueType: ValueSecureTunnelIf` with the
  `ValidateSecureTunnelBindInterface` validator (`xfrmi.go`). `SchemaValidate`
  rejects a non-canonical name at commit-check with an actionable message
  naming the value and the `st<N>`/`st<N>.<unit>` requirement, and `?`-completion
  surfaces the placeholder + examples. The validator's decision is the
  authoritative `XFRMIfNameAndID` if_id-0 check; only the message is lexical.
- **Compiled-config strict gate** — `validateSecureTunnelBindInterfaceAST`
  (`compiler_ipsec_bindiface.go`) gained a distinct invalid-name arm: a
  NON-EMPTY bind-interface that resolves to if_id 0 is now hard-rejected on the
  strict path (rather than silently `continue`-ing) and downgraded to a warning
  on the tolerant load / peer-sync path. Because it is an AST pre-walk over the
  group-expanded, inactive-pruned tree, it catches apply-groups-inherited /
  duplicate-block forms the schema layer can miss — the reason both layers are
  kept.

The change is surgical: it fires ONLY for names resolving to if_id 0 (which are
never valid), so the #2909/#2933 two-VALID-alias collision case (`st0` + `st0.0`,
both if_id 1) is unchanged — still handled by the collision arm, still rejected
naming the shared if_id. An empty bind-interface (none configured) is still
skipped. The pkg/routing "invalid bind-interface name" guard remains the runtime
backstop for a tolerated-but-invalid config. Covered by
`pkg/config/compiler_ipsec_bindiface_validate_5297_test.go` (strict reject +
valid-compiles-to-expected-if_id + tolerant-warn + schema-layer reject +
#2933-non-regression, each RED on revert to the silent `continue` / untyped
leaf).

### Numeric interface-unit alias collision fail-closed (#5631, both-node union #5878)

`compileInterfaces` (`compiler_interfaces.go`) keys logical units by their
numeric value: it iterates `namedInstances(child.FindChildren("unit"))` and
canonicalizes each RAW spelling through `strconv.Atoi` — but only AFTER the AST
has already split `unit 00` and `unit 0` into two SEPARATE named instances. The
two instances then collide on the same `ifc.Units[unitNum]` key with two
DISAGREEING side effects: `ifc.Units[unitNum] = unit` is **last-writer-wins**
(the later spelling's firewall filter and addresses replace the earlier unit),
while the interface-level tunnel-address collection
(`ifc.Tunnel.Addresses = append(ifc.Tunnel.Addresses, unit.Addresses...)`) is
**append-only** (it accumulates the addresses of every spelling). The observable
filter + address ownership therefore flips with config order and a stale tunnel
address from the spelling that LOST the filter race survives — a fail-open on the
interface firewall filter, decided by the order two otherwise-equivalent `set`
lines happen to appear (codex-review-181 M23).

Junos treats a logical unit as an integer identity — `unit 00` and `unit 0` are
the same unit, and no valid config has two numeric aliases of one unit carrying
DIFFERENT security state. Rather than pick an arbitrary winner (exactly the
order-dependent ambiguity that makes this unsafe), the fix REJECTS the aliased
config at commit so the operator authors a single canonical `unit <n>`:

- **Compiled-config strict gate (both-node union)** —
  `validateInterfaceUnitAliasCollisionsAST` (`compiler_interface_unit_alias.go`).
  It groups the distinct raw unit spellings under each interface by their
  canonical unit and, when two DISTINCT spellings resolve to the same unit,
  hard-rejects on the strict commit / commit-check path naming the interface,
  the spellings, and the canonical unit — and downgrades to a `cfg.Warnings`
  entry on the tolerant load / peer-sync path
  (`lenientInterfaceUnitAliasCollisions`, #1960 fail-closed-on-load class), so an
  already-persisted or peer-synced config an older binary accepted still boots.

**One canonical normalizer (#5878).** Canonicalization is centralized in
`CanonicalLogicalUnit(raw) (int, string, error)` (`schema_validators.go`), the
ONE function that folds every alias spelling of a numeric unit to its shared
identity (`01`==`1`, `+1`==`1`, `-0`/`00`==`0`), rejecting a malformed /
out-of-range token via the same range check `ValidateLogicalUnit` has always
used (`ValidateLogicalUnit` now delegates to it, so validation and
canonicalization can never diverge). The alias gate keys collisions by this
canonical unit.

**Both-node-effective union — the #5878 gap.** The #5631 gate originally ran
INSIDE `compileExpanded` (`runPreWalkGates`) AFTER
`tree.ExpandGroupsWithVars({node: nodeN})`, so it saw only the SUBMITTING node's
post-`${node}` effective view, and commit compiles `s.nodeID` alone
(`Store.compileTree` → `CompileConfigForNode`). A peer-only
`groups node1 { … unit 01 }` applied through `apply-groups "${node}"` folds its
aliasing spelling onto a base `unit 1` ONLY in the standby's effective view —
invisible at a node0 commit. The active node commits green; the standby's
compiled config then diverges (a different firewall filter / address set) and a
failover silently changes forwarding / security posture despite a
"synchronized" commit. The gate is now the BOTH-NODE UNION, modeled exactly on
`validateTunnelEndpointIDCollisionAST` (`tunnelid.go`) and run in the
**pre-expansion** gate block of `compileConfigForNodeWithOpts` /
`compileConfigWithOpts` (beside the tunnel/zone/table-id gates):
  - **View 1** — the pre-expansion presence union across every `interfaces`
    root AND every `groups` block, grouped per interface by canonical unit.
  - **Views 2/3** — the concrete per-interface unit spellings after expanding
    the candidate for node0 and node1 (`ExpandGroupsWithVars` +
    `expandInterfaceRanges`), so a wildcard / interface-range apply-group whose
    alias only lands on a concrete interface post-expansion is caught. Per-node
    expansion errors are non-fatal (contribute the empty set); View 1 still
    covers any collision inside an un-expandable group.
  Because all three views are pure functions of the same candidate config
  (Views 2/3 computed on both nodes), the accept/reject verdict is IDENTICAL on
  node0 and node1 (no originator-accepts / peer-rejects split) and MONOTONE over
  the old single-view gate — the same HA-symmetry argument `tunnelid.go` makes.
  A node0 commit now rejects a node1-only alias collision.

The gate is surgical: a single canonical `unit 0` (the overwhelming common case)
and distinct unit numbers (`unit 0` + `unit 1`) never trip it, and same-spelling
flat-set lines merge into one AST node upstream (they are the same unit, not an
alias) — so non-colliding compilation is bit-identical. A non-numeric unit token
is REJECTED at commit rather than silently skipped (see the #5829 gate
below). Where a duplicate-spelling config ALSO produces a
pre-expansion tunnel-endpoint-id collision (#1873), that earlier gate rejects
first — either way the aliased config is refused, never silently committed.
Covered by `pkg/config/interface_unit_alias_5631_test.go` (both config orders
reject identically = order-independent, lenient-warn, non-colliding-commits),
`pkg/config/interface_unit_parity_5878_test.go` (peer-only-node1 collision
rejected at a node0 commit, both-node verdict parity, alias-form + injection-
vector matrices, VLAN-split regression guards, `CanonicalLogicalUnit` units) and
the reconciled `tunnelid_test.go` duplicate-spelling case, each RED on revert of
the gate wiring (the parity test goes RED — node0 accepts — when the gate is put
back node-local).

**Peer-effective SOURCE-NAT — the #5876 gap.** The same divergent-commit class
bit the strict SOURCE-NAT gates. Those validators
(`validateSourceNATPoolStrict`, `validateSourceNATPoolAddressGrammarStrict`,
`validateSourceNATPersistentNoTranslationStrict`,
`validateNATPoolReferencesStrict`, `validateNATSourceAddressNameReferencesStrict`
in `compiler_validate_strict_nat.go`) run inside `runUniformGates`, so a commit
that compiles `s.nodeID` alone (`Store.compileTree` → `CompileConfigForNode`)
strict-validated only the SUBMITTING node's source-NAT view. A `${node}`
apply-group substitution / per-node rewrite that selects a source-NAT pool or
reference valid on the origin but INVALID on the peer — a per-node pool
`address` / `port range`, or a shared top-level rule whose
`then source-nat pool <name>` names a pool only a peer `groups nodeN` block
defines — passed green, and the standby then lenient-loaded the config-synced
snapshot (`Store.SyncApply` → `CompileConfigForNodeLenient`, which downgrades the
strict SNAT gate to a warning and fails the translation CLOSED). SNAT silently
degraded on the node that just took over. Unlike the #5631/#5878 unit-alias gate
— a pure-AST union that can be computed pre-expansion — source-NAT
representability needs the fully COMPILED per-node view (pools resolved), so the
fix RE-COMPILES rather than unions: `ValidatePeerEffectiveStrict(tree,
localNodeID)` (`compiler_peer_effective.go`), wired into
`configstore.compileTreeStrict` after the local compile + cross-checks, compiles
the PEER node with `CompileConfigForNodeLenient(peerID)` — the exact transform
the standby applies — and re-runs the registered strict SUBJECTS against that
peer-effective `*Config`. A peer-only source-NAT error is now rejected at the
origin commit, naming the peer node and the offending pool, so BOTH
node-effective source-NAT outputs are proven representable before promotion.
A peer view that will not compile at all is left to the peer's own load path (no
false-reject of the origin commit).

**Subjects, not one gate (#4785).** The peer view is a FULL compile, so it is
built ONCE and every registered subject runs against it; a second standalone
entry point would compile it again on every cluster commit. The registry
(`peerEffectiveStrictSubjects`) currently holds the source-NAT subject
(`validateSourceNATStrictView`, #5876) and the IPIP tunnel subject
(`validateIpipTunnelStrictView`, #4785) — the latter because the strict IPIP
rejection has the identical bypass: a peer-only `ip-*` interface commits green
on the origin, the RAW group tree is what synchronises, and the standby
lenient-loads a tunnel the dataplane drops in both directions. Each subject
reuses the LOCAL strict validators verbatim, so the peer gate and the local
commit path cannot drift, and each carries its own operator-facing framing
naming the peer node. A strict gate whose verdict is node-INDEPENDENT gains
nothing from registration. Gate errors on the peer view for concerns NOT
registered here remain out of scope (downgraded to warnings by the lenient
compile).
Standalone (`nodeID < 0`) has no peer and is a no-op — zero behavior change off a
cluster. Covered by `pkg/config/compiler_peer_effective_snat_5876_test.go`
(peer-only reversed-range / per-node address / dangling-pool-reference vectors,
both-views-valid + standalone over-reject guards, node0/node1 symmetry) and
`pkg/configstore/peer_effective_snat_5876_test.go` (store-gate wiring), each RED
on revert of the peer gate (node0 accepts the peer-only SNAT error).

### Source-NAT / NAT64 external-tuple overlap (#5144)

The Rust dataplane keys the source-NAT `PortAllocator` by pool name + address
vector (`userspace-dp/src/nat/source.rs`) and the NAT64 allocator by
`(prefix_bytes, pool_v4)` (`userspace-dp/src/nat64.rs`). Nothing tied those
independent allocators together, so four config shapes each gave two allocators
an overlapping claim on the same translated IPv4/IPv6 address: differently-named
source pools with overlapping addresses; a source pool that also backs a NAT64
`source-pool`; two NAT64 rule-sets sharing one pool under DIFFERENT prefixes; and
duplicate/overlapping members WITHIN one pool. Independent occupancy bitmaps
share no ownership word, so two flows to the same remote endpoint can be handed
the same `(family, translated IP, translated port)` and the reverse (1:N) NAT
index cannot disambiguate the return packet — it is misdelivered. The only
pre-existing NAT overlap gate was NPTv6 static-prefix (#2241); this is its
source-NAT / NAT64 analog.

`validateNATPoolExternalTupleOverlapStrict(cfg, lenient)`
(`compiler_validate_strict_nat.go`, wired into `runTailGates` right after the
NPTv6 / NAT64 gates) rejects the overlap at commit. It enumerates one allocator
"owner" per the exact keys the helper uses — one per DISTINCT source-NAT
pool a pool-mode `then source-nat pool` rule references, and one per DISTINCT
`(canonical prefix, source-pool)` a `nat64 rule-set` references (unreferenced
pools build no allocator and are out of scope, mirroring the #5877 aggregate
gate). A NAT64 rule-set is an owner ONLY when its prefix would build a live
allocator — `nat64PrefixOwnerKey` mirrors the Rust `nat64.rs` build condition and
`validateNAT64PrefixStrict`'s accept set exactly (split on `/` into two parts, the
mask a decimal 96, the address IPv6 by the colon-strict rule) and returns the
CANONICAL /96 network (the Rust 12-byte identity) via `netip … Masked()`. An
empty / malformed / non-/96 prefix builds no allocator (Rust skips it; the strict
gate rejects a non-empty malformed prefix and *skips* an empty one), so it is
dropped from the owner set — never enumerated as a phantom owner that would
falsely report an overlap (two empty-prefix rule-sets sharing a pool, or an
empty-prefix rule-set vs a live source-NAT owner). The canonical key means two
rule-sets naming one pool under the SAME /96 in different valid spellings —
`64:ff9b::/96` vs `0064:ff9b:0:0:0:0:0:0/96` vs a leading-zero `64:ff9b::/096`
(which `validateNAT64PrefixStrict` and Rust's numeric mask parse both accept, but
a raw `netip.ParsePrefix` rejects) — are ONE runtime allocator, so keying on raw
text would FALSELY reject them. Each owner's members (`pool.Address` +
`pool.Addresses`, ranges already expanded to /32s) become family-scoped numeric
intervals — v4 vs v6 bucketed by the colon-strict textual family
(`natAddrFamily(natCIDRIPPart(...))`, the Go/Rust parity rule, so an IPv4-mapped
IPv6 literal never compares against a real v4 member) — and an O(n log n)
sort-and-sweep per family reports the first overlapping pair. Two members of the
SAME owner is a within-pool duplicate/overlap; two owners is the cross-pool /
cross-feature collision.

The gate is ALSO carried in the #5876 peer-effective source-NAT view
(`validateSourceNATStrictView`, `compiler_peer_effective_snat.go`): a
`${node}`/groups rewrite whose PEER resolution produces an overlapping pool set
while the origin's is disjoint would otherwise commit green on the origin and let
the standby lenient-load the vulnerable independent allocators — the same
divergent-commit fail-open #5876 closes for the other source-NAT gates. Run
strict there (`lenient=false`), it rejects the node1-only overlap at a node0
commit.

**Interface-mode SNAT egress addresses are a THIRD owner domain (#6751 §5.7).**
Interface mode draws no pool — it translates onto the egress interface's own
address — so before #6751 the owner set enumerated only source-NAT pools and
NAT64, and a pool containing an interface's own address met no gate at all. The
two allocators are keyed independently, so both could mint the same
`(address, port)` and the reverse index could not disambiguate: the #5144
misdelivery, on the arm #5144 never covered.

The candidate egress addresses are derived per rule-set from its TO-side scope
(`interfaceSNATEgressAddresses`, `compiler_nat_iface_egress.go`), mirroring the
dataplane's `scope_matches` (`userspace-dp/src/nat/source.rs`) treatment of an
empty scope field as a WILDCARD:

| rule-set to-scope | candidate addresses |
|---|---|
| `to-interface` | that interface's addresses |
| `to-routing-instance` | that instance's interfaces' addresses |
| `to-zone` | that zone's interfaces' addresses |
| none | **every** dataplane interface's addresses |

The last row replaces the earlier `maps_sync.go` precedent, which collected only
non-empty `ToZone` and returned NOTHING for an unscoped rule-set — understating
the candidate set precisely where it is widest, i.e. failing OPEN on the
broadest possible input. Owners are **deduped by address**: several
interface-mode rule-sets egressing one WAN interface occupy ONE address, and one
owner per rule would make them overlap each other and false-reject correct
multi-zone configs. A `then source-nat off` rule mints nothing and contributes
no candidate.

**Whole-address statics on an interface egress (#6751 §5.7).** A whole-address,
port-preserving static mapping whose external address is also an interface-SNAT
egress emits the SAME external tuple as interface SNAT itself. The #5837
first-packet-inert advisory (`compiler_validate_warn_nat_iface_addr.go`)
suppresses itself when interface SNAT owns the address — correct about
inertness, and it left this case with NO diagnostic at all. That suppression is
NARROWED, not removed: the inert advisory stays suppressed and
`staticOnInterfaceEgressCollisions` emits the collision instead — strict
REJECTS, tolerant load / peer-sync WARNS (#1960). A MAPPED-PORT static
(`match destination-port` / `mapped-port`) emits a distinct external port and is
deliberately NOT flagged; reserving its emitted port is the runtime half's job.

Config-time only. Addresses resolved at RUNTIME (DHCP, netlink) are foreclosed
by the snapshot-builder half of §5.7, which needs the DRAIN discipline behind it
— marking a pool unusable with nothing draining would strand every live session
on it.

This is the commit-time DETECTION half of #5144 (material choice **S1**: reject
independently-owned overlap). It does NOT introduce the deferred packet-path
global cross-domain allocator (the R2 design, gated on user signoff and
#2387/#5338/#5698) — rejecting the overlap at commit forecloses the runtime
collision because the vulnerable config never reaches the dataplane. Strict
(commit / commit-check): hard-reject naming both allocators and the overlapping
members. Lenient (load / peer-sync): warn via `opts.lenientNATPoolOverlap`
(#1960 no-brick) so a config committed before this gate existed still boots —
but UNLIKE NPTv6 / NAT64 the dataplane does NOT reject the overlapping snapshot,
so the latent reverse-index collision persists until corrected and the warning
says so. Covered by `pkg/config/compiler_nat_pool_overlap_5144_test.go`
(exact-duplicate / partial-overlap / source-NAT-vs-source-NAT /
source-NAT-vs-NAT64 same-and-distinct-pool / NAT64-different-prefix /
within-pool-duplicate / IPv6-overlap / IPv6-nesting / IPv6-bare-vs-/128 reject
cases; a peer-only-`${node}`-overlap reject through the #5876 peer gate; plus
distinct-pool / shared-pool / cross-family / same-prefix-dedup /
NAT64-equivalent-prefix-spelling / NAT64-leading-zero-`/096`-mask /
NAT64-empty-prefix-not-an-owner / adjacent-v4 / adjacent-v6 /
mapped-v6-vs-genuine-v4 / unreferenced accept guards), RED on revert of the gate
(the overlap is accepted) — and separately RED on revert of the canonical NAT64
key (equivalent + leading-zero spellings wrongly rejected), of the empty-prefix
owner skip (an inert NAT64 rule-set falsely reported as an overlap), and of the
peer-view wiring (node0 accepts the peer-only overlap). The shipped `test/incus/xpf-test.conf` and
`test/incus/xpf-cluster-fw0.conf` each carried the cross-feature overlap (one
pool drawn by both NAT64 and a source-NAT rule) and were separated into distinct
pools + proxy-ARP as part of this change.

### Duplicate `system login user` name (#6992)

The same `user` name authored in two `system login` blocks was WORSE than the
last-writer-wins drop the #5180 gate covers: both blocks survived in
`Login.Users`, and two readers picked DIFFERENT ones.

| reader | picks |
|---|---|
| `configuredClass` (`pkg/cli/identity.go`) | the FIRST block with a non-empty class |
| `applySystemLogin` (`pkg/daemon/daemon_system.go`) | iterates every block in order, so the account state that lands comes from the LAST |

Measured on a config that committed CLEAN at strict:

```
user alice { uid 2001; class admins; authentication { ssh-rsa "K1"; } }
user alice { uid 2002; class ops;    authentication { ssh-rsa "K2"; } }
```

`applySystemLogin` rewrites `authorized_keys` per entry with
`WriteFileDurable`, so **K2** — the key the operator wrote under the VIEW-only
block — is the one on disk, while `configuredClass` answered **admins**. The
credential that authenticates and the class that authorizes it came from
different blocks, in the permissive direction. This is the third instance of the
class in this area: #6861 keyed an advisory on a name the runtime resolved
differently, #6838 keyed a fold on a class name the runtime picked differently.

**The fix is a fold, not a matched tie-break.** `compileSystemLogin` collapses a
duplicated name into ONE entry with per-LEAF last-authored-wins — which is what
the FLAT spelling already produces, because `SetPath` merges `set system login
user alice …` written twice onto one node and replaces each leaf. That makes the
two AST shapes agree (the #5180 dual-AST-equivalence property) rather than
inventing a third answer, and it is stronger than teaching one reader the
other's tie-break: after the fold there is no tie to break. #6838 records why the
weaker form is wrong — matching a tie-break is a proxy that rots the day the
other reader changes.

Per-LEAF, not per-block: a second block authoring only a `class` must leave the
first block's `uid` in place, because that is what the flat spelling gives.
Folding to the last BLOCK would silently zero it.

The `authentication` section is the one exception — a later block's section
replaces the earlier block's key set wholesale rather than merging into it. That
is chosen so the fold preserves the PROVISIONED state exactly: `authorized_keys`
is already rewritten per entry, so the last entry's keys are already the ones on
disk.

`system login user` is also registered in the #5180 duplicate-named-block gate,
because a fold is still a silent drop of the earlier block's uid / class / keys.
Strict rejects; the tolerant load / peer-sync path warns and boots (#1960).

Deliberately NOT applied to `system login class`: #6838 already made the class
cohort reader-independent by folding permissions across the whole same-named
set, and a merge here would fight that design.

### Duplicate containers beyond the original four (#6768)

The #5180 gate started as four hand-written copies of one walk. #6768 turned
the walk into a registry — `namedDupRules` / `singletonDupRules` in
`pkg/config/dup_named_blocks.go` — so adding a container is one row and the
strict gate, the lenient warning, and the #6455 group-expanded re-run all pick
it up without any of the three being edited. `groups` and `interfaces` keep
bespoke walks: their name extraction (a merged two-key head) and skip rules
(the non-interface keyword allowlist) genuinely differ, and folding them into
the table would mean inventing hooks for two callers.

The rows added were derived from a PREDICATE, not from the effects the issue
named: *a container that can be authored more than once as a hierarchical
sibling, and whose compile silently loses configuration the FLAT `set` spelling
would have merged.* `tree.SetPath` collapses a repeated flat statement onto one
node, so a duplicate CONTAINER sibling is reachable only from the hierarchical
shape — which is exactly the dual-AST-equivalence invariant #5180 exists to
enforce. Six sites matched, in three distinct loss modes:

| container | loss mode | measured effect |
|---|---|---|
| `security log stream <n>` | last-writer-wins (`Streams[name] = stream`) | a stream authored `transport { protocol tls; }` in the first block and `severity info` in the second compiles with severity=info and NO transport — a TLS syslog stream silently reverts to plain syslog |
| `security log profile <n>` | last-writer-wins (`Profiles[name] = p`) | `stream-name` and `default-profile` from the first block both vanish; the profile is left bound to nothing |
| `protocols bgp group <n>` | split instances (per-instance locals) | `group g { peer-as 65001; export P; }` + `group g { neighbor N; }` compiles N with `peerAS=0` and `export=[]`; only the peer-as half warns |
| `services flow-monitoring` | first-wins (`FindChild`) | the whole second block is ignored — a `version-ipfix` half authored after a `version9` half never exists |
| `services rpm` | first-wins (`FindChild`) | every probe in the second block disappears |
| `services ip-monitoring` | first-wins (`FindChild`) | every policy in the second block disappears, with zero warnings |

Three of the six are the effects the issue named; the other three came from the
predicate. `services application-identification` is deliberately excluded — it
is a presence flag, so a repeat loses nothing, and a gate that rejected every
repeated sibling would break configurations that are fine.

Two side notes worth keeping:

- The message is now per-container. The original single sentence said the
  EARLIER block is dropped, which is true for a last-writer-wins map store and
  exactly backwards for a `FindChild` first-sibling-only read; it would have
  sent an operator to delete the surviving block. `dupEffectStrict` /
  `dupEffectLenient` render the truth for each mode. The pre-existing
  ids-option FAMILY check was mislabelled the same way and is corrected to
  first-wins, which is what `compileScreen` actually does.
- A duplicate can BLIND another gate. With the BGP blocks duplicated the export
  policy never reaches the neighbour, so the existing undefined-`policy-statement`
  cross-reference gate has nothing to check and stays silent; the same config
  authored once is correctly rejected when the policy is undefined.

**Gate only, no fold.** #6992 folded `system login user` because two READERS
picked different blocks — a credential authored under a VIEW-only block could
authenticate into a super-user CLI — and a fold was the only way to remove that
divergence. There is no divergent reader here; the loss is a plain silent drop,
the shape `groups` / `interfaces` / `screen ids-option` are already handled
with, so the gate alone is the matching remedy. Strict rejects on commit /
commit-check; the tolerant load / peer-sync path warns and boots (#1960), where
the historical result is preserved unchanged.

### Duplicate NAT rule name (#5649, C181-M18)

NAT rule-sets are ordered, first-match tables keyed by rule name, so a rule's
CONFIG identity is `natType/ruleset/rule`. Two rules authored with the SAME
name in one rule-set are NOT reduced to last-writer-wins like a #5180
hierarchical block — they BOTH survive: `namedInstances` (the rule loop in
`compiler_nat_source.go` / `compiler_nat_destination.go` /
`compiler_nat_static.go`) appends each as a separate first-match entry sharing
that one config identity. For source / destination / ordinary static NAT that
identity is also the shared `natType/ruleset/rule` hit counter (so `show` /
counter surfaces cannot tell the rows apart); for a counter-less NPTv6 (RFC
6296) static rule they are two snapshots (`buildNptv6Snapshots`). Either way the
duplicate name is a config error — the harm is type-independent (the shared
config identity), which is why the gate's diagnostic is type-agnostic (below).

`validateDuplicateNATRuleNamesAST(tree, lenient)`
(`pkg/config/dup_nat_rule_names.go`, wired beside the #5180 duplicate-named-block
gate in both `compileConfigWithOpts` and `compileConfigForNodeWithOpts`) rejects
this at commit. It runs **pre-expansion** on top-level `security` stanzas only —
apply-groups DEEP-MERGES a same-named rule rather than duplicating it, and the
flat `set` form reuses the rule node, so only a directly-authored hierarchical
duplicate reaches the gate. The seen-set is keyed by `(natType, rule-set, rule)`
and unioned across repeated `security` / `nat` / `source|destination|static`
blocks (compileNAT merges those, #3915), so a rule name split across two
`source {}` blocks is caught too. The same rule name in two DIFFERENT rule-sets
(a distinct identity) is accepted. Strict (commit / commit-check) hard-rejects;
lenient (load / peer-sync) warns via `opts.lenientDuplicateNATRuleName` (#1960
no-brick) and keeps the historical two-row behavior.

The reason line is deliberately **type-agnostic** — it states the genuine,
type-independent defect (a rule-set is keyed by rule name, so the same name
authored twice is a config error) and never claims a per-rule hit counter.
NPTv6 (RFC 6296) static rules are COUNTER-LESS — `compileStaticNAT` skips
`rule.IsNPTv6` before `assignNATCounterID`, and `buildNptv6Snapshots`
(`pkg/dataplane/userspace/nat_nptv6.go`) appends each rule as its own snapshot —
so a counter-specific diagnostic would be false for them. The #2241 NPTv6
overlap gate (`compiler_validate_strict_nat.go`) also deliberately SKIPS
same-`(rule-set, rule)` pairs (#4339, so a single multi-`from`-scope rule is not
flagged against itself), so it never compares two same-named NPTv6 rules — this
duplicate-name gate is the ONLY one that catches them, and it does so with the
same name-identity reason it uses for every other NAT type.

Covered by `pkg/config/dup_nat_rule_names_5649_test.go` (source / destination /
static reject, NPTv6 counter-less reject, lenient warn, and distinct-name /
different-rule-set / flat-set-merge accept guards), RED on revert of the gate
(the duplicate is accepted) and, separately, RED if the diagnostic reintroduces
a per-rule counter claim (false for a counter-less NPTv6 rule).

The quoted-empty rule name this gate once skipped is now rejected as an
authoring error (#6455, see the subsection below). The other limitation it
shares with its #5180 sibling — a duplicate authored entirely inside an applied
group — is now closed by the POST-expansion gate
`validateDuplicateNamesExpandedAST` (#6455 Finding 1), which re-runs this
scanner on a group-expanded clone. A pre-expansion per-group-body scan would
false-reject a legitimate apply-groups fragment config that coalesces
post-expansion; running after expansion sees the coalesced result instead.

### Duplicate NAT rule-SET name (#6454, C181-M18 sibling)

The #5649 gate above closes the rule-NAME axis; #6454 closes the rule-SET-name
axis one level up. A rule-set name is its operational identity — the from/to
scope binding and the CLI show key. It is UNIQUE per nat type but reusable
ACROSS nat types (Junos gives source / destination / static / nat64 independent
name spaces; `NATCounterKey` in `pkg/dataplane/compiler_nat.go` is natType-
prefixed for the counted types). Two rule-sets authored with the SAME name
WITHIN one nat type are NOT reduced to last-writer-wins like a #5180
hierarchical block — they BOTH survive: `compileNATSource` /
`compileNATDestination` / `compileNATStatic` / `compileNAT64` each APPEND the
rule-set (`sec.NAT.Source` / `Destination.RuleSets` / `Static` / `NAT64`), never
merging by name, so both compile as separate first-match tables sharing one
name. The operator authored what they read as one rule-set; it compiles to two,
evaluated in sequence. The CLI named-rule-set show lookup
(`showNATSourceRuleSet` in `pkg/cli/cli_show_nat.go`) returns on the FIRST name
match, so the second same-named rule-set — and its rules — is invisible on that
surface and the operator cannot disambiguate the two. This is NOT a per-rule
counter merge: `NATCounterKey` includes the rule name, so the disjoint rules
this gate uniquely catches get distinct counter keys (a SAME rule name in both
is caught first by the #5649 gate); a nat64 rule-set (prefix / source-pool, no
`rule` nodes — correctly excluded from the #5649 rule-name gate) is counter-less
anyway. The harm is type-independent (the shared rule-set NAME identity), which
is why the diagnostic is type-agnostic and never claims a per-rule counter.

`validateDuplicateNATRuleSetNamesAST(tree, lenient)`
(`pkg/config/dup_nat_ruleset_names.go`, wired beside the #5649 duplicate-rule-name
gate in both `compileConfigWithOpts` and `compileConfigForNodeWithOpts`) rejects
this at commit. It runs **pre-expansion** on top-level `security` stanzas only,
for the same reasons as #5649 — apply-groups DEEP-MERGES a same-named rule-set
rather than duplicating it, and the flat `set` form reuses the rule-set node
(`tree.SetPath` merges), so only a directly-authored hierarchical duplicate
reaches the gate. The seen-set is keyed by `(natType, rule-set)` and unioned
across repeated `security` / `nat` / sub-block stanzas (compileNAT merges those,
#3915), so a rule-set name split across two `source {}` blocks is caught too.
The same rule-set name in two DIFFERENT nat types (a distinct
natType-prefixed namespace) is accepted. Crucially the dedup is at the AST
rule-set-INSTANCE level, NOT the compiled level: a single authored rule-set
carrying a bracket list of from/to scopes Cartesian-expands into MULTIPLE
same-named `NATRuleSet` objects downstream (#3096) — that is one AST instance
and is NOT flagged (a compiled-level dedup would false-positive here). Strict
(commit / commit-check) hard-rejects; lenient (load / peer-sync) warns via
`opts.lenientDuplicateNATRuleSetName` (#1960 no-brick) and keeps the historical
two-table behavior.

Covered by `pkg/config/dup_nat_ruleset_names_6454_test.go` (source / destination
/ static / nat64 reject, nat64 counter-less-diagnostic guard, lenient warn, and
distinct-name / different-nat-type / bracket-list-scope-expansion / flat-set-merge
accept guards), RED on revert of the gate (the duplicate is accepted). The
quoted-empty rule-set name it once skipped is now rejected (#6455, this gate
owns the empty rule-set name); the applied-group limitation it shares with its
#5649 / #5180 siblings is deferred (see the subsection below).

**Phase 2 (#5878) — reference-binder canonicalization.** Phase 1 (above) closes
the divergent-commit fail-open by rejecting a duplicate-spelling collision at
commit. The second, subtler half of #5878 is that a cross-subsystem reference
carrying a `.<unit>` suffix was BOUND by its raw string, not its canonical unit,
so a `.01` reference and a `.1` reference resolved to DIFFERENT runtime units —
even without a duplicate-spelling collision, a peer-only `${node}` rewrite that
emits `.01` on the standby (vs `.1` on the active) could bind a zone / NAT /
routing member to a different unit on standby. Phase 2 threads the canonical
identity through the reference binders via one helper,
`CanonicalInterfaceUnitRef(ref)` (`schema_validators.go`), which folds the
`.<unit>` suffix through `CanonicalLogicalUnit` (`.01`→`.1`, `.+1`→`.1`,
`.00`→`.0`) and returns a bare / trailing-dot / malformed-suffix ref unchanged (a
malformed suffix is still rejected at commit by the #5933 reference gate). The
per-unit interface snapshot keys every binder map by the canonical `"%s.%d"`
unit name, so each binder now stores its map key on the canonical unit:

  - **Security-zone membership** — `buildInterfaceZoneMap` (`zones.go`) and its
    two mirrors, the #3072 conflict-detection SSOT `zoneIfaceLogicalKeys`
    (`compiler_validate_strict_zones.go`) and the kernel host-deny scope map
    `junosHostZoneByInterface` (`junos_host_deny.go`). Canonicalizing the
    detector alongside the binder is load-bearing: without it, a `.01` member
    would bind canonical unit 1 in `buildInterfaceZoneMap` (first-writer-wins)
    while the detector still saw `.01` and `.1` as distinct keys, silently
    reopening the multi-zone fail-open #3072 closed.
  - **Routing-instance membership** — `buildInterfaceRoutingInstances` and
    `buildInterfaceRouteTables` (`routes.go`).
  - **Per-interface host-inbound override** — `buildInterfaceHostInboundMap`
    (`zones_override.go`), plus the operator-facing lookups in
    `ClassifyHostInboundForInterface` / `ResolveHostInboundIngressInterface`
    (`host_inbound_classify.go`) so a `.01` ingress-interface ref resolves to
    the canonical unit's zone.

  **class-of-service** was already canonical: the nested `interfaces <if> unit
  <n>` form keys `iface.Units[unitID]` by the canonical int (`CanonicalLogicalUnit`,
  #5963), and the `.unit`-suffix-in-key form never resolves to a runtime unit in
  the consumer (`interfaces.go` keys CoS by base name + int unit), so no CoS
  divergence is possible. **NAT** rules bind by zone / routing-instance /
  address, not by an interface-unit reference, so there is nothing to
  canonicalize.

  The daemon netlink VRF / tunnel-membership resolver is threaded too:
  `riMemberLinuxName` (`pkg/daemon/daemon_run.go`) — shared by the step-0a VRF
  bind loop and the `collectAppliedTunnels` RIListMember scan — now canonicalizes
  the member ref BEFORE resolving it, so a `.01` routing-instance member binds the
  SAME Linux device as `.1`. `TunnelNameMap` keys are built from the canonical int
  unit number (`ifName + "." + strconv.Itoa(unitNum)`), so canonicalizing at the
  top makes BOTH the tunnel-device path (tunMap hit) and the
  `LinuxIfName`/unit-0-collapse path use the canonical name. This is NOT covered
  by the Phase 1 alias gate: `validateInterfaceUnitAliasCollisionsAST` gates
  `interfaces ... unit` DEFINITIONS, not routing-instance / zone membership
  REFERENCES — a peer-only `groups node1 { routing-instances ri interface
  ge-0/0/0.01 }` reference is a divergence the definition gate never sees, so the
  reference must be canonicalized directly at the binder (it is). #5878 has no
  remaining reference-binding residual.

  Covered by `pkg/dataplane/userspace/unit_canonical_refbind_5878_test.go` (zone /
  routing-instance / host-inbound `.01`→canonical-unit-1 binding, RED on revert of
  each binder), `pkg/config/unit_canonical_refkey_5878_test.go`
  (`CanonicalInterfaceUnitRef` matrix, `zoneIfaceLogicalKeys` canonical claim, and
  a two-zone `.01`/`.1` duplicate-membership reject), and
  `pkg/daemon/ri_member_canonical_5878_test.go` (netlink `.01`→canonical device
  via both the tunnel-device and LinuxIfName paths, RED on revert).

### Quoted-empty names + group-authored duplicates (family-wide, #6455)

The three pre-expansion duplicate-name gates — `validateDuplicateNamedBlockAST`
(#5180: groups / interfaces / screen ids-option), `validateDuplicateNATRuleNamesAST`
(#5649: NAT rule names), and `validateDuplicateNATRuleSetNamesAST` (#6454: NAT
rule-set names) — shared two limitations. #6455 closes the quoted-empty-name half
here (shared helpers in `pkg/config/dup_names_6455.go`) and DEFERS the
group-authored half (below).

**Closed — quoted-empty names.** The gates `continue` on an empty name, so a
quoted-empty name (`rule ""`, `rule-set ""`, `group ""`, `interface ""`,
`ids-option ""`) was neither rejected as a duplicate nor rejected as empty. An
empty name is not a valid operational identity for any of these containers — the
object cannot be referenced or shown by name — so it is an authoring error
regardless of duplication (mirroring the #5636 empty-credential rejection). Each
gate now rejects it: strict commit / commit-check hard-rejects (`empty <kind>
name … (#6455)`), tolerant load / peer-sync (#1960) warns and keeps booting.
Duplicates keep first-error priority, so a config with no empty name produces
byte-identical pre-#6455 diagnostics. The empty **rule-set** name is owned by the
#6454 gate — the #5649 rule-name gate skips an empty rule-set — so the lenient
warning fires exactly once, not double-reported.

**Group-authored duplicates (#6455 Finding 1) — CLOSED by the post-expansion
gate.** A duplicate authored entirely inside an applied group body (no inline
peer) survives `ExpandGroups()` and reaches the compiler with BOTH instances
alive, while the byte-identical inline duplicate is hard-rejected — same config,
same compiled shape, opposite verdict, decided by where the operator happened to
write it. Measured before the fix: the issue's repro compiled clean and produced
a rule-set holding two rules both named `R`.

The tempting fix — a pre-expansion per-group-body scan — is WRONG, and was tried
and withdrawn in PR #6491: it false-rejects a legitimate apply-groups FRAGMENT
config. Fragments of one named object authored across repeated group roots (two
`interfaces` roots each contributing a `ge-0/0/0` unit; a screen profile split
into an ICMP fragment + a TCP fragment; a NAT rule split into complementary
`match` / `then` fragments) COALESCE into a SINGLE object under `mergeNodes`
during `ExpandGroups`, and a pre-expansion sibling-scan cannot model that
same-pass coalescing.

`validateDuplicateNamesExpandedAST` (`pkg/config/dup_names_expanded_6455.go`)
runs the SAME three scanners on a group-EXPANDED clone, where the coalescing has
already happened: a fragment pair is one node by then and reports nothing, while
a genuinely duplicated pair is still two siblings and reports. Reusing the
scanners verbatim — rather than reimplementing the name-keying — is what keeps
the two views from disagreeing about what "duplicate" means.

The clone is expanded once per cluster node (node0 AND node1), mirroring the
#5878 / #5879 / #6178 / #6662 union gates and reusing
`collectNodeExpandedInterfaceUnitSpellings`'s clone-and-expand shape, so a
`groups node1` duplicate that only the PEER's `${node}` expansion selects is
rejected at commit rather than committing green on the active node and merely
warning on the standby. Both views are computed on both physical nodes from the
shared candidate, so the verdict is a pure function of the candidate.

Findings the three PRE-expansion gates already produced are subtracted (they are
present in the expanded tree too), so an inline duplicate is reported exactly
once on the lenient path. Deduplication is by rendered message because both
views render through the same scanner functions — an identical finding produces
a byte-identical string by construction, with no second wording to keep in sync.
On the strict path the subtraction is a no-op: the pre-expansion gates return
their error immediately, so reaching this gate means they found nothing.

`expandInterfaceRanges` is deliberately NOT applied to the clone (the
unit-alias helper does apply it): a range expanding to two identical interface
names is a different defect on a different axis, nothing detects it today, and
widening this gate to cover it would be the same speculative scope that produced
the withdrawn false-reject.

Covered by `pkg/config/dup_names_expanded_6455_test.go`: the issue's verbatim
repro rejected, one fixture per member of `dupNameScannersExpanded` so dropping
any single scanner reds exactly its own subtest, the peer-only `groups node1`
union proof, the report-exactly-once dedup control, the #1960 lenient
warns-not-bricks guard, and the inline-plus-group deep-merge ACCEPT control (the
original reason the pre-expansion gates are top-level-only).

Covered by `pkg/config/dup_names_6455_test.go`: quoted-empty reject for all five
containers (RED on revert of the empty-name recording), a lenient warns-EXACTLY-
once guard for the empty rule-set, and — the load-bearing accept-side guard, now
for the post-expansion gate rather than for a deferral —
`TestDup6455GroupFragmentCoalescingAccepted` locks the four fragment-
coalescing configs (interface / screen / NAT-rule fragments, group-siblings +
inline peer) as ACCEPT so a future group-authored detector cannot reintroduce the
false-reject. Plus the top-level no-false-positive accepts (apply-groups
deep-merge carrying both rules, cross-group coalescing, #3096 bracket-list
expansion).

### Non-numeric logical-unit identity fail-closed (#5829)

`interfaces <if> unit <identity>` had NO positional key validation: the `unit`
schema node deliberately left its instance key untyped (deferred with the
`vrrp-group <id>` class), and `compileInterfaces` parsed it with `strconv.Atoi`
and a bare `continue` on error. So a non-numeric identity such as `unit tenant`
passed schema + commit, and the compiler then **silently discarded the whole
unit** — its addresses, firewall filters, sampling, DHCP/DDNS and tunnel state
vanished with no diagnostic. The security bite: a unit-level input/output
firewall FILTER committed with **no enforcement** (fail-open), the same class as
the undefined-filter-reference gate.

The fix is fail-CLOSED at two layers, both keyed to one canonical validator
`ValidateLogicalUnit` (`schema_validators.go`, range `0..MaxLogicalUnit` = 16385
— non-numeric, negative, integer overflow, and out-of-range all fail; since
#5878 it delegates the validation half to `CanonicalLogicalUnit` so the same
function both validates AND emits the canonical identity):

- **Schema (strict commit/check):** the `unit` node carries
  `keyValidator: ValidateLogicalUnit`, so `commit`/`commit check`
  (`SchemaValidate`) reject a malformed identity naming the interface and the
  raw token, for both the flat-set and hierarchical AST shapes (the shared
  `validateKeySlot` path, same mechanism as the typed `address <cidr>` key).
- **Compiler (defense-in-depth, all paths):** `compiler_interfaces.go` returns a
  hard error instead of the bare `continue`. On the tolerant load / peer-sync
  paths the `lenientNonNumericUnit` opt (set by `CompileConfigLenient` /
  `CompileConfigForNodeLenient`) downgrades that to a `cfg.Warnings` entry and
  **quarantines** the unit — dropped, its children never reattached to another
  unit — so a config an older binary silently truncated still boots, now with a
  deterministic warning instead of a silent drop.

Valid numeric units (including the `0` and `16385` boundaries) compile
bit-identically and reach the typed `ifc.Units` map. This pass types the
`interfaces <if> unit <n>` slot; the cross-subsystem `.unit`-reference grammar is
closed by #5933 (below). Covered by
`pkg/config/interface_unit_nonnumeric_5829_test.go` (strict reject via both
gates naming the interface + token, valid-unit-reaches-map, lenient
warn-and-quarantine), RED on revert of either the `keyValidator` or the compiler
gate.

### Cross-subsystem interface `.unit`-reference validation (#5933)

The residual #5829 deferred: three subsystems reference an interface by a
`<if>.<unit>` string (NOT the `interfaces <if> unit <n>` instance key), and each
parsed the `.unit` suffix WITHOUT `ValidateLogicalUnit`:

- **class-of-service** — `class-of-service interfaces <if>.<unit>` (the shaper /
  classifier binding; the reference is the `cos.Interfaces` map key);
- **security-zone membership** — `security zones security-zone <z> interfaces
  <if>.<unit>` (`zone.Interfaces`);
- **routing-instance membership** — `routing-instances <ri> interface
  <if>.<unit>` (`ri.Interfaces`; the route-leak / VRF member split is
  `strings.Cut` + `strconv.Atoi` with a bare `continue` on error).

None fail-open a firewall FILTER (filters bind only inside the now-gated
`interfaces <if> unit <n>` loop — materiality confirmed lower than #5829's core
in the #5932 review), but a malformed `.unit` there silently **mis-binds**: the
CoS shaper never attaches, the zone-membership key never matches a configured
unit, the route-leak member is dropped — a committed reference that carries no
effect.

The fix (`validateInterfaceUnitReferencesStrict`, `compiler_validate_strict_unitref.go`,
dispatched from `runUniformGates` after the zone-interface-defined gate) routes
every `.unit` suffix through the SAME canonical `ValidateLogicalUnit`, splitting
on the FIRST `.` exactly as each subsystem's runtime does so schema acceptance
matches runtime binding. A bare interface (no `.`) or a trailing-dot bare form
(`base.`) carries no unit and is skipped. Strict on commit / commit-check
(hard-reject); the `lenientInterfaceUnitRef` opt downgrades it to a `cfg.Warnings`
entry on the tolerant load / peer-sync paths (#1960 no-brick — the runtime already
ignores an unresolvable `.unit` suffix, so a leniently-loaded malformed reference
is inert). This is a compiler-layer gate only: unlike #5829's dedicated numeric
`unit` instance key, the interface-name token here is a free wildcard (legitimately
bare OR unit-qualified), so a schema `keyValidator` would over-reject bare names.
Covered by `pkg/config/interface_unit_ref_5933_test.go` (per-subsystem strict
reject naming the subsystem + bad token, valid-unit accepted, bare-interface
accepted, lenient warn), each subsystem independently RED on revert.

#### Residual closed: the NESTED `class-of-service interfaces <if> unit <n>` form (#5963)

#5933 above closed the three `.unit` SUFFIX references, but the DISTINCT nested
grammar slot — `class-of-service interfaces <if> unit <n> ...`, where the unit is
a CHILD node rather than a `.unit` suffix — remained unvalidated. Its schema node
(`schema_cos.go`) carries no `keyValidator` (the `unit` key is a free
`<unit-number>` placeholder), so `SchemaValidate` accepted a non-numeric `unit`,
and the CoS compiler then SILENTLY DROPPED it: `strconv.Atoi(unitNode.Keys[1]); if
err != nil { continue }` in `compiler_class_of_service.go`. `set class-of-service
interfaces ge-0-0-0 unit abc shaping-rate 1m` compiled clean (`CompileConfig`
returned nil) and the shaper never bound — the SAME mis-bind / silent-drop class
#5829/#5933 closed, and arguably the more common Junos CoS syntax. #5933 could not
catch it: by the time `validateInterfaceUnitReferencesStrict` runs the malformed
unit is already dropped at parse, so there is nothing left at the reference gate.

The fix routes `unitNode.Keys[1]` through the canonical `CanonicalLogicalUnit`
normalizer (#5878) AT the CoS parse site — it returns the parsed int (used to key
`iface.Units`) plus the shared #5829 acceptance check in one call, so a
non-numeric / negative / integer-overflow / out-of-range `[0..MaxLogicalUnit]`
unit is REJECTED at commit instead of dropped. Strict on commit / commit-check
(hard-reject naming the interface + bad token); the `lenientInterfaceUnitRef` opt
(the same flag the #5933 suffix gate uses) downgrades it to a `cfg.Warnings` entry
on the tolerant load / peer-sync paths (#1960 no-brick — the malformed unit was
inert before the gate too, the shaper simply did not bind). A VALID unit still
binds the shaper unchanged. Covered by `pkg/config/cos_nested_unit_5963_test.go`
(strict reject of non-numeric/negative/overflow/out-of-range naming the token,
valid `unit 0`/`unit 100` binds the shaper, lenient warn-and-drop), RED on revert
of the parse-site gate.

#### Residual closed: the `forwarding-classes queue <N>` token (#5973)

Surfaced during the independent review of PR #5972 (#5963): the SAME silent-drop
class existed on a DISTINCT CoS field in the same file — the
`class-of-service forwarding-classes queue <N> <fc>` parse site. Its schema node
(`schema_cos.go`, the `queue` leaf) carries no `keyValidator`, so `SchemaValidate`
accepts a non-numeric queue token; the CoS compiler then SILENTLY DROPPED a token
`strconv.Atoi` could not parse (`strconv.Atoi(queueNode.Keys[1]); if err != nil {
continue }` in `compiler_class_of_service.go`). `set class-of-service
forwarding-classes queue abc iperf-video` compiled clean and the
forwarding-class → queue mapping never bound — the same mis-bind / silent-drop
class #5963/#5933 closed, and inconsistent with the sibling fairness
rss-expectation queue parse in the same file, which hard-rejects
`err != nil || queue < 0 || queue > 255`.

Division of labour with the existing #4594 range gate: a PARSEABLE but
out-of-range queue (e.g. `999`) or a negative one already flows to the downstream
`validateClassOfServiceForwardingClassQueueStrict` gate, which rejects it on the
strict path and warns on the tolerant path (queue domain is **0..255**, the
dataplane's `u8` queue id — NOT the Junos-classic 0..7). #5973 closes the ONE
case that range gate can never see: a `strconv.Atoi` error means the FC never
binds, so there is no `Queue` int left for the range gate to check. The fix
rejects the strconv-error token AT the parse site (strict on commit /
commit-check, naming the forwarding-class + bad token); the
`lenientCoSForwardingClassQueue` opt — the SAME #4594 flag the downstream range
gate uses — downgrades it to a `cfg.Warnings` entry on the tolerant load /
peer-sync paths (#1960 no-brick — the malformed queue was inert before the gate
too, the FC simply did not bind). A VALID queue still binds unchanged. Covered by
`pkg/config/cos_fc_queue_5973_test.go` (strict reject of non-numeric/overflow
naming the token, valid `queue 0`/`7`/`255` binds, lenient warn-and-drop leaving
the FC inert), RED on revert of the parse-site gate.

### security address-book same-name `address` + `address-set` collision (#5676)

`address` and `address-set` entries share ONE operator-visible namespace (a
policy `match source-address <name>` / `destination-address <name>` names a
single token) but are stored in two SEPARATE maps
(`AddressBook.Addresses` / `AddressBook.AddressSets`). So an operator can author
`address blocklist 10.0.1.0/24` AND `address-set blocklist { address other; }`
in the same book with no commit error — and every place a name is resolved to
prefixes checks `Addresses` before `AddressSets` (**address-first**: the
dataplane `expandBookNameRecursive` / `nameRepresentability` /
`capabilities`, and the host-inbound `junos_host_deny` compiler). The plain
address therefore SILENTLY SHADOWS the same-named address-set: a deny built on
the SET covers only the single address, so the set's other members leak (an
under-block) — a security-relevant change to which traffic a rule covers, with
no diagnostic (codex-review-182 M10, High).

`validateAddressBookNameCollisionStrict` (`compiler_validate_strict_addrbook.go`,
wired in `runEarlyStrictAndFolds` right after `validateAddressBookEntryNamesStrict`
and BEFORE the zone-local fold — the same PRISTINE-book ordering constraint, so a
global `address foo` and a *different* zone's zone-local `address-set foo`
(genuinely distinct namespaces after the fold) are never misreported, and a real
zone-local collision names the clean zone). It hard-rejects the collision on the
strict commit / commit-check path — matching vSRX, which itself forbids a
same-name `address` + `address-set` in one book (there is no vendor-defined
precedence to honor). The tolerant load / peer-sync path
(`opts.lenientAddressBookNameCollision`, #1960 no-brick) downgrades to a
`cfg.Warnings` entry so an already-persisted or peer-synced config carrying a
pre-existing collision still BOOTS — and keeps the **deterministic address-first
winner** the runtime already used (`resolveAddressBookNameKind`, the single
source of truth), so a leniently-loaded config forwards exactly as before rather
than silently changing its dispositions on reload. Covered by
`pkg/config/addr_set_namespace_5676_test.go` (global + zone-local reject,
both config orderings, lenient-warn, deterministic-winner, namespace-aware
absent-collision, non-colliding-commits), the strict-reject + lenient-warn cases
RED on revert of the gate wiring.

## Compact vs block stanza spellings (the #2419 sub-leaf contract)

The bracketed-list contract below is about a **leaf** that carries several
values. This section is about the neighbouring case that bit four security
stanzas: a **container** whose sub-leaf is written on the container's own line.

For a plain keyword stanza with `(name, value)` sub-leaves, the same operator
intent has two legal spellings:

```
authentication { encrypted-password "$6$..."; }     # BLOCK
authentication encrypted-password "$6$...";          # COMPACT
```

They produce different trees:

```
BLOCK    Keys=[authentication]                             children=1
           └─ Keys=[encrypted-password $6$...]  IsLeaf
COMPACT  Keys=[authentication encrypted-password $6$...]   children=0
```

So a compiler stanza that iterates only `prop.Children` and dispatches on child
names reads the block spelling and **silently drops** the compact one. That is
#2419 applied to sub-leaves rather than to list values, and it is where #6817
(a login credential), #6818 (OSPF interface authentication), #6821 (a
security-log TLS profile) and #6822 (an SNMPv3 password) all live. Each fails
toward LESS security on a commit that reports success, and `SchemaValidate`
accepts the compact spelling, so this is the normal commit path — not the
tolerant-load path.

Three things to know before working on this class:

1. **The flat-set path is NOT the source of the compact shape.**
   `ParseSetCommand` + `SetPath` produces the BLOCK tree — `authentication` as a
   container with an `encrypted-password` child, bit-identical to the block
   spelling. The compact tree comes from the HIERARCHICAL parser on
   hand-authored or `load merge`d text, and from tools that render flat paths
   into partial braces. A test that compares "flat-set vs block" is comparing
   block against block: vacuously equal for every leaf and green everywhere.
2. **A NAMED INSTANCE is compactable too, and that is where the dangerous
   variant lives.** An earlier version of this section claimed collapsing a
   named instance (`interfaces ge-0/0/0`, `user ops`, `stream audit`) produces
   "a node the compiler cannot recognise as that instance at all". **That was
   wrong**, generalized from a single probe, and wrong in the direction that
   hides defects. There are two outcomes and they are not equally bad:

   - **instance not created** — `interfaces { ge-0/0/0 description hello; }`
     compiles to zero interfaces. A loud, total drop.
   - **instance created, body dropped** — `interface ge-0/0/0.0 cost 10;`
     compiles the interface with `cost=0`. This is the dangerous one: the
     half-built object reaches the renderer and the runtime, so
     `show configuration` displays what the operator wrote, the object binds
     normally, and it enforces nothing. #7653 is this shape two levels deep,
     where the dropped body is OSPF authentication.

   `interfaces` gave the first outcome; everything else checked gives the
   second. Excluding named instances hid ~169 sites of exactly the class the
   census exists to count.
3. **Bracketed multi-value lists are schema LEAVES, not containers.**
   `from protocol [ tcp udp ]` legitimately collapses onto `Keys` (see the next
   section). Any fix for this class must key on the schema's container/leaf
   distinction, or it will destroy every bracket list in the fleet.

`pkg/config/compact_block_equivalence_2419_test.go` is the gate for the class:
it walks `setSchema`, builds both spellings for every sub-leaf under a plain
stanza, compiles both, and requires the typed configs to be equal. Sites that
fail today are recorded in
`pkg/config/testdata/compact_block_divergences_2419.txt` as an expected-failure
inventory, so a NEW compact-blind reader reds the suite and a fixed site that
is not removed from the file reds it too.

Two properties of that gate are load-bearing and easy to lose:

- **The vacuity guard.** A cell only counts once changing the VALUE is shown to
  change the compiled config. Without it a site whose fixture observes nothing
  reports a pass, and the census silently stops being a census.
- **The positive control.** The four filed instances are asserted present by
  construction. The first version of this instrument found two of them; an
  instrument that quietly stops finding known-true sites reports "clean" for
  exactly the reason the textual sweeps did.

The inventory's `# checked:` header is a coverage RATCHET: sites must not drain
out of the tested population into the skip buckets. The "not observable" skips
are UNRULED, not clean — each is a site whose synthesized fixture was too thin
to see the value (as #6821 was until a required-sibling `host` line was added),
so the census is a floor.

### The census measures ONE packing depth (#7653)

Junos compaction is **recursive**, and the `#2419` census is not:

```
authentication simple-password "x"     2 tokens packed   <- measured
authentication md5 7 key "x"           3 tokens packed   <- was NOT measured
```

`compact_block_equivalence_2419_test.go` collapses exactly one container onto
the leaf line. A compiler that reads `prop.Children` correctly at one level can
still drop the body at two, so its divergent figure is a floor in a second
dimension nobody had stated.

`pkg/config/compact_depth_census_7653_test.go` extends the SAME walker —
`collectCompactSites`, `synthPair`, `contextFor`, `nest`, `compileText`,
`cfgEqual` — across depths, so the two censuses cannot drift into disagreeing
about what a site is. Depth 1 is by construction the base census's spelling, and
a cross-check asserts the two report the same divergent count there; without it,
each would report its own number and neither would be checked against the other.

**Measured, and the shape is the finding — divergence gets WORSE with depth:**

| depth | population | divergent | rate |
|---|---|---|---|
| 2 | 546 | 354 | 65% |
| 3 | 539 | 467 | **87%** |
| 4 | 442 | 428 | **97%** |
| 5 | 301 | 297 | 99% |
| 6–8 | 255 | 247 | 97% |

**≥1793 divergent cells over ≥527 distinct sites.** The base census's 354 is
therefore the population at the *most favourable* depth: roughly 173 further
sites compile the single-level spelling correctly and drop the body at two.

Read the rows as separate populations, not one shrinking cohort — a site too
shallow to have a depth-5 spelling is **absent** from that row rather than
passing it.

**Only 2 cells in the entire sweep are REJECTED**, and rejected cells are
excluded from the divergent count deliberately: a spelling the config system
already refuses is not a silent divergence. This class is *accepted and
dropped*, and the near-zero rejection count is the measurement that says so.

Two assertions in that file are load-bearing beyond the report:

- **Anti-vacuity on depth 3.** Existence of depth-3 cells is not evidence they
  PACK — a generator emitting the block spelling at every depth would report a
  full population, call every cell equivalent, and pass. A zero divergent count
  there has two very different causes (the class was fixed, or the generator
  stopped packing) and the failure says to determine which.
- **The rate must not fall between depth 2 and 3.** Every measurement says
  deeper packing is dropped more often; an inversion means the generator or the
  population changed shape and the headline needs re-deriving.

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

**A nested BLOCK is a third shape, and it is not the flat-set chain (#6689).**
The two shapes above are the ones the bracket-list contract is about. A leaf can
also be authored as a brace block — `from { protocol { bgp; ospf; static; } }` —
which leaves the node itself with `Keys=["protocol"]` and files one leaf child
per value as SIBLINGS. A reader that descends `Children[0]` at each level is
correct for the flat-set CHAIN (one child deep at every level) and reaches
exactly one value of a block (N children wide at one level). That was the
`collectProtocolList` defect: a routing-policy term written to filter three
protocols compiled to one, and with `then reject` the two dropped protocols were
silently ACCEPTED and installed — a fail-OPEN route-acceptance widening whose
authored config renders back intact. Descend EVERY child, not the first, and the
chain and the block are both covered.

Note this leaf has no per-value option keyword, so every token below the node is
a value and the full descent carries no promotion hazard. That is a property of
the leaf, not of the descent — see the `system ntp server` case under
"A widened read must not PROMOTE a token the old reader discarded" for a leaf
where it does not hold. The routing-policy `from protocol` value domain is
UNVALIDATED at commit in every spelling (unlike the firewall-filter leaf of the
same name, which `filterProtocolResolvable` checks): widening the read makes the
block spelling behave like the four that already reach `pkg/frr`
`match source-protocol`, rather than adding a new exposure, but the absent gate
is tracked separately.

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

**A leaf whose flat-set bracket list lands on a CHILD's Keys needs more than
`firewallMatchValues` (#6694).** The SSOT helper reads `Keys[1:]` of the node
plus — since #6714 — every key of each child, which covers every leaf whose
flat-set path absorbs the list onto the node itself. `interfaces fab0 fabric-options
member-interfaces` does not: its schema node is a plain `children: nil` leaf
with no `args` and no `multi`, so `SetPath` files the whole bracket list as ONE
child carrying every name on that child's Keys — and `firewallMatchValues`
would keep only the first. `fabricMemberValues` (`compiler_interfaces.go`)
therefore descends the subtree and takes EVERY key. The same read is now driven
through `FindChildren("member-interfaces")` rather than `FindChild`, because
repeated hierarchical statements land as sibling nodes. Before the fold the
hierarchical bracket spelling and the plain single-value spelling
(`member-interfaces ge-0/0/7;`) both compiled to an EMPTY fabric member list —
a chassis-cluster fabric that cannot form, silent at commit. Widening the read
also ARMS the existing fab0/fab1 shared-member overlap check in
`compiler_validate_warn.go`, which previously saw nothing to compare for
bracket-authored fabrics; that check emits a warning, not a rejection, so no
config that committed before is rejected now.

**That leaf shape is a PREDICATE, not three special cases (#7126).** The
discriminator is mechanical and worth stating as a rule, because the sites it
catches all LOOK compliant:

> A leaf declared `children: nil` and **NOT** `multi: true` in `setSchema`, read
> by a compiler that takes `Keys[0]` / `Name()` of each child, drops every value
> past the first when the operator authors a bracket list through the flat-set
> path (`set`, `load set`, the CLI).

`SetPath` files a bracket list differently depending on the flag:

| schema | `set … <leaf> [ v1 v2 ]` becomes |
|---|---|
| `multi: true, children: nil` | `Keys=["<leaf>","v1","v2"]`, no children — the tail absorber runs |
| **`multi: false, children: nil`** | `Keys=["<leaf>"]` with **ONE child** `Keys=["v1","v2"]` |

In the second row every value sits on one child's Keys, so `child.Name()`
returns `v1` and discards the rest — which is why a reader can obey the
"`Keys[1:]` AND `Children`" rule above to the letter and still drop. **Reading
`Children` is not the same as reading every KEY of each child.** The
hierarchical parser is unaffected (it puts the list on the node's own tail), so
these sites survive every brace-authored test and bite only the `set` path.

`fabricMemberValues` was the first instance; #7126 found two more —
`routing-options rib-groups <g> import-rib` and `event-options policy <p>
events` — so the body now lives once, in `ast.go` as **`plainListValues`**, and
`fabricMemberValues` is a wrapper that keeps its leaf-specific argument attached
to its leaf. A divergence between the three would always be a bug, so there is
one implementation rather than three copies. Use it only where every non-empty
token below the node is a value: NOT for a leaf with per-value option keywords
(`ntp server <ip> prefer`, `source-prefix-list <name> except`, `route <prefix>
discard` — promoting a modifier into the value list is the #6690 hazard), and
NOT where an EMPTY authored value must survive (`multiLeafAuthoredValues`).

Both new sites also needed `FindChildren`, not `FindChild`: repeated
hierarchical statements land as SIBLING nodes, and reading only the first drops
that spelling too even where the flat-set repeated spelling — the same
configuration, filed as CHILDREN of one node — accumulated correctly. And the
`import-rib` drop was a GATE ESCAPE as well as a value drop: the #2226
cross-reference check iterates `ImportRibs`, so an undefined rib named in slot 1
committed CLEAN while the identical name in slot 0 was rejected. The newly
visible entries land on #2226's existing tolerant-path downgrade
(`lenientRibGroupRefs`), so no already-persisted config is turned into a boot
failure.

The two `import-rib` read sites were byte-identical duplicates in two arms of
`compileRoutingOptions`, which is the hazard #7126 names: a fix landing in one
arm leaves the other spelling broken and nothing says so. They now share
`compileRibGroup`. (Measured: the named-instance arm is INERT at HEAD — it
selects with `FindChildren("")`, which matches only a child whose first key is
the empty string, and no parse produces one. The duplication was latent, which
is precisely why no test could have caught a divergence.)

**The one-sided read has a SECOND half, and it is not a leaf spelling at all
(#6714).** Everything above is about the five ways ONE statement can be
spelled. Three more sites dropped values for a different reason: the parser
keeps a repeated same-keyed STATEMENT as a SIBLING node, so a compiler that
resolves it with `FindChild` compiles the first and discards the rest. That is
invisible to the behavioural spelling gate
(`schema_spelling_differential_gate_test.go`), which authors one statement per
site and cannot emit a second one.

| site | shape that dropped | fix |
|---|---|---|
| `event-options policy <p> then change-configuration commands` | repeated `commands` statements, and repeated `change-configuration` blocks | `FindChildren` on both levels |
| `routing-options forwarding-table export` | two sibling `forwarding-table` blocks in ONE `routing-options` root | `FindChildren("forwarding-table")` for the LIST; the scalar still binds to the FIRST block |
| `firewallMatchValues` (~70 call sites) | a value tail riding on a block CHILD (`flag { basic-datapath session; }`, `flag { [ a b ]; }`) | read every key of each child, not `Keys[0]` |

The `commands` row is worth reading twice, because it inverts the usual
advice. CLAUDE.md tells you to test flat-set syntax with
`ParseSetCommand` + `SetPath`; here the flat-set spelling was the one that
already WORKED (`SetPath` merges a repeated leaf into one node), and only the
brace-authored file dropped. A fixture built the recommended way could not have
seen it. Build BOTH.

The `firewallMatchValues` row states a property rather than a shape: the reader
already took every token of the node's OWN tail, so taking only `Keys[0]` of a
child made the identical token sequence read differently depending on which
side of the AST the parser put it on. The fix is that agreement, and it is
pinned as an agreement (`TestFirewallMatchValues6714ReadsEveryKeyOfEveryChild`)
rather than as an expected output. Note the blast radius is bounded by depth:
the reader takes each child's Keys and does NOT descend, because a child with a
sub-block (`neighbor 10.0.0.1 { metric 2; }`) contributes its name only — that
is what separates it from `plainListValues`, which descends and must therefore
never be pointed at a leaf whose children are containers.

Other `multi: true` sites still take `Keys[0]` of each child through
`multiLeafAuthoredValues` / `addressSetMemberValues` / `proxyARPAddressValues`,
and that residue was MEASURED rather than assumed: a `leaf { v1 v2; }` probe
across the whole schema names 30 sites where the second token is still
dropped. They are left
alone deliberately — that spelling is not authorable Junos (Junos writes one
value per statement inside a block), the readers differ for stated reasons
(`multiLeafAuthoredValues` keeps empty values to hold the
`multiLeafAuthoredValues(n)[0] == nodeVal(n)` invariant; `proxyARPAddressValues`
holds #6673's measured install-parity), and adding the spelling to the gate
would assert a defect at 30 sites that no operator can author.

**A silent DROP can be closed by diagnosing it instead of widening the read
(#6714, proxy-ARP).** `security nat proxy-arp … address` accepts one
address/prefix, one `<low> to <high>` range, or a list of plain addresses —
never a MIXTURE. A statement that mixes them (`address [ 192.0.2.1 192.0.2.2 to
192.0.2.9 ]`) falls through both range branches, and #6673 pinned the fallback
to master's single-value read against a corpus measured through the installer's
own `netip.ParsePrefix` gate. Widening it would have invented a grammar Junos
does not have AND made an upgraded appliance answer ARP for addresses it did not
answer for before. The compiler now stamps the offending statement into
`ProxyARPEntry.MalformedRangeSpecs` (a `json:"-"` compile artifact, mirroring
`NATPool.PortRangeInvalidSpec`) and `validateProxyARPAddressesStrict` rejects it
at commit while the tolerant load / peer-sync path warns and installs exactly
what it installed before. The installed set does not move; what an operator can
COMMIT does. A rejection can be relaxed into an expansion later if the demand
appears; an ARP response cannot be un-sent.

**Widening a multi-value READ requires widening its VALIDATOR in the same
change (#6659).** Adopting the accumulating reader at a site changes what a
malformed value DOES. Before, a bad value in slot 2 was discarded at compile and
could never reach the dataplane; after, it materialises in the typed config and
the runtime installer is the first thing that sees it. `security nat proxy-arp
address` is the worked example: `address [ 192.0.2.1 bogus ]` used to compile to
one entry, and with the widened read it compiles to
`["192.0.2.1/32", "bogus/32"]`, which `pkg/dataplane/proxyarp.go` parses with
`netip.ParsePrefix`, logs a bounded warning about, and SKIPS — a silently-inert
address that answers no ARP/ND. `validateProxyARPAddressesStrict`
(`compiler_validate_strict_nat.go`, wired in
`compiler_uniformgates_firewall_nat2.go`) now checks EVERY value with the
installer's own parse: strict rejects, tolerant warns (#1960 no-brick).

The mirror-image rule applies to a validator that already exists: widen it
per-value only where the OPERAND is the value being widened. The static-NAT
`match destination-address` host-route and `/0` checks moved to a per-address
block-pair classification, but the `then static-nat prefix` checks and the #3202
port check kept the SCALAR pair, because only ONE value is ever lowered
(`ExternalIP: rule.Match`, `pkg/dataplane/userspace/nat_static.go`). That value
is what `nodeVal` selected from the LAST authored `match destination-address`
statement — within a bracketed list, that statement's first value — so it is
**not** in general `MatchAddresses[0]`: author a bracket followed by a repeated
sibling and `MatchAddresses[0]`, `MatchAddresses[len-1]` and `rule.Match` are
three different prefixes. Reading the scalar is therefore the only way to name
the prefix that actually installs — an
"any authored match address pairs with the target" flag would SUPPRESS a true
complaint about the pair that actually installs. For the same reason the
match-side widening buys DIAGNOSTIC completeness, not a dataplane backstop: the
tail values never reach the Rust parser at all.

**A one-sided read is a GATE ESCAPE, not a value-drop, wherever the leaf's only
validator lives in the compiler loop (#6673).** The discriminator is mechanical,
not a judgement call: a leaf declaring a schema `validator` gets dual-shape
checking for free, because `validateMultiValueLeaf` (`schema_walk.go`) walks
`Keys[1:]` AND every child's `Keys[0]`. A leaf whose only check is an inline
`if` inside the compiler's own read loop is checked exactly where that loop
looks — so the shape the loop does not read commits CLEAN, while the identical
token authored in the shape it does read is REJECTED. Three deferred sites were
classified through `configstore.CheckText`, each paired with a single-value
control so an ACCEPT only counts beside a REJECT of the same token:

| Leaf | Shape that ESCAPES | Same token REJECTED as | Tracked |
|---|---|---|---|
| CoS `code-points` | hierarchical BLOCK (`{ totally-bogus; }`) | bracket `[ totally-bogus ]` — *"is not a valid DSCP alias or 0..63 value"* | #6697 — **CLOSED**, see below |
| `system archival archive-sites` | bracket `[ "scp://a/b" "-oProxyCommand=id" ]` | single value AND block — *"must not begin with '-'"* (#4589 A7 F-02, CWE-88) | #6692 — **CLOSED**, see below |
| `bridge-domains vlan-id-list` | BOTH bracket and block | single value — *"out of range (1-4094)"* / *"invalid vlan-id-list value"* | #6687 — **CLOSED**, see below |

Note the first two escape in OPPOSITE directions — `collectCoSDSCPCodePoints`
read `child.Keys[1:]` plus the inline tail and never `child.Children`, while
the archive-sites loop reads children and only slot 1 of the tail. "Which shape
escapes" is a property of the individual reader; do not generalise from one.

The CoS row is closed: all five code-point readers now go through
`coSCodePointTokens` (`compiler_class_of_service.go`), which returns the leaf
node's tail, EVERY key of each of its children, and the inline `loss-priority
low code-points ef;` tail, and every caller still runs its per-value domain
check over every token it returns. Its escape was worse than the table row
suggests: the block spelling did not truncate the code-point list, it lost the
WHOLE classifier, because the compiler stores a classifier only when it has at
least one entry. A regression test asserting "the entry has both code points"
would have passed VACUOUSLY against it, so the tests in
`cos_code_points_spellings_6697_test.go` report ABSENT and WRONG-VALUES as
distinct failures.

**Closing a gate escape owes a SEVERITY SPLIT, not just a widened read
(#6687).** `vlan-id-list` is now read with `multiLeafAuthoredValues` and every
authored id runs the parse and range checks, so `[ 10 99999 ]` is rejected
exactly as `vlan-id-list 99999` always was. But the values it now examines are
values the OLD gate accepted: a config carrying a bad id in slot 1 committed
clean, persisted, and would refuse to BOOT after the upgrade if the widened
check kept its old severity on every path. So the check is split the way every
other AST-level gate in this compiler is split (`compiler_opts.go`): strict
(commit / commit-check) hard-rejects naming the value, lenient (tolerant load /
peer-sync, `lenientBridgeDomainVlanID`) warns and drops that one id. The
leniently-loaded config therefore carries exactly the VLAN set master compiled —
the bad id was never installed on either build — and only the warning is new.
The check stays in the compiler rather than moving to a typed `validator` in
`setSchema` for a second reason: a strict schema gate firing FIRST would mask
whether the compiler's own loop ever widened, so the regression test could not
tell a fix from a no-op.

**And an escape can become live when someone else fixes the value-drop.** The
archive-sites escape is inert TODAY only because the value is also dropped. A
follow-up that widens that read without widening the leading-dash check in the
same change ships a live CWE-88 argument injection; the warning is stated at the
read site itself in `compiler_system.go`, not only here.

That follow-up is #6692, and it widened BOTH in one change — see
"#6692: four system-stanza multi-value leaves" below. The leading-dash gate now
runs over every entry `archiveSiteEntries` returns, so the escape closed in the
same commit that could have armed it.

**An EMPTY authored value is a value, and whether to keep it depends on whether
the leaf SELECTS or SETS (#6673).** `firewallMatchValues` skips blank tokens,
which is right where every value it returns is installed — but a leaf that reads
one value into a scalar that installs, plus a list that only validators consume,
must keep them. `nodeVal` SELECTS a blank token, so filtering it out of the list
lets the scalar hold a value the list does not contain, and every validator and
diagnostic reading the list then describes a rule that is not the one in effect.
Four categories, and the non-uniformity is deliberate:

| Category | Leaves | Reader | Empty value |
|---|---|---|---|
| SELECTION (scalar installs, list validates) | `routing-options forwarding-table export`, `security nat static … match destination-address` | `multiLeafAuthoredValues` (`ast.go`) | KEPT |
| SET (every value installs) | `security flow traceoptions flag`, `security nat proxy-arp … address` | `firewallMatchValues` / `proxyARPAddressValues` | SKIPPED |
| VALIDATED LIST (a downstream checker rejects a malformed entry) | `event-options … attributes-match` | `eventAttributesMatchExprs` | KEPT |
| REPORTED LIST (nothing rejects it; the list IS the compiled policy) | `event-options … then change-configuration commands` | `eventChangeConfigCommands` | KEPT |

**KEPT is about the LIST, not about the SELECTION (#7216).** The SELECTION row
says the empty value stays in `MatchAddresses`, and it still does — that is what
keeps `Match` present in the list so every validator and diagnostic describes
the rule actually in effect. It never meant that a rule whose SELECTION is the
blank is a shippable config. For `security nat static … match
destination-address` it is not: `rule.Match` lowers to
`StaticNATRuleSnapshot.ExternalIP`, the Rust `parse_nat_prefix` returns `None` on
`""`, and `from_snapshots` drops the WHOLE mapping — the operator authored a
rule that does not exist at runtime. #6673 already said as much in the one place
it could see the case (its `rule.Match == ""` arm of the cardinality gate, which
fires only when two or more prefixes are also listed);
`validateStaticNATSelectedMatchAddressStrict` (#7216) completes it. The two
properties are independent and both are now asserted: the cardinality gate must
not COUNT an empty slot, and the blank SELECTION must not COMMIT. See "#7216"
below.

The last two rows look like one category and are not. `attributes-match` really
is validated — `ValidateEventAttributesMatchStrict` hard-rejects a `""` expression at
strict commit. `commands` is not: `eventengine.classifyPlan` trims and SKIPS an
empty command, so an empty entry never reaches a checker and the remediation
batch is unaffected by it. Its entry is kept because the compiled list is
observable in its own right (below), not because anything gates on it.

**Two of those leaves accept ONE value permanently, and #6674 ratified that
rather than implementing the list.** #6673 fixed the READ half for both — every
authored value now reaches validation and a multi-valued list is hard-REJECTED
at commit, warned on the tolerant path — but the scalar the runtime installs is
still a single value at three successive layers. Six source sites told the
reader a follow-up was coming; none is. The two arms ratify for DIFFERENT
reasons, and conflating them is how the wrong decision gets made for the pair:

- `security nat static … rule … match destination-address`: **Junos takes one
  prefix here**, so the schema's `multi: true` is an xpf over-advertisement of
  the grammar, not a promise. A static-NAT rule is a 1:1 mapping — one `match
  destination-address` against one `then static-nat prefix` — so N external
  prefixes against one internal prefix names no target, and fanning the rule
  into N rows would have to invent a pairing Junos does not define. `rule R1` /
  `rule R2` already expresses the intent.
- `routing-options forwarding-table export`: **Junos genuinely takes a policy
  CHAIN**, so "the schema over-advertises" is not available here — and neither
  is the tempting shortcut "a chain is equivalent to its first policy", which
  was MEASURED FALSE (`pkg/frr/forwarding_export_chain_6674_test.go`: for a
  plain first policy and a load-balancing second, the first-policy reading gives
  `maximum-paths` 0 and the OR-composed chain gives 64). It ratifies for a
  structural reason instead: `resolveECMP` derives exactly two booleans from the
  ONE named policy — any term with a load-balance action sets `ecmpMaxPaths` to
  64, any `consistent-hash` term sets `ConsistentHash` — and evaluates no `from`
  match, term order, or terminating action. Junos evaluates an export chain PER
  ROUTE and stops at the first terminating action, so the cheap composition
  (OR across the chain) is not Junos, and the faithful one is not expressible at
  all because the value being derived is FRR's GLOBAL `maximum-paths`. A chain
  needs a per-route forwarding-policy model xpf does not have — a feature,
  tracked as its own issue, not a defect in the multi-value read.

The operator-facing half is pinned behaviourally rather than by comment:
`TestRatifiedGatesDoNotPromiseAFollowUp_6674` compiles each config on the
tolerant path and asserts the warning the operator READS neither promises a
follow-up nor drops the reason, with the still-rejects/still-commits pair as its
green control. A comment that rots is bad; a warning that promises a feature
which is never coming is worse, because the operator acts on it — they leave the
list in place and wait.

**SIX leaf families, SEVEN read sites AT #6673 — the category table above has
FOUR rows and is not the inventory.** (The table is appended to as later fixes
land; row 8 is #6687's, and the counts in this sentence describe #6673 only.) The four rows classify EMPTY-VALUE semantics, and
its `Reader` column names four reader mechanisms because two of them serve two
leaves each. Counting rows (or readers) undercounts what this change had to
widen. The inventory is:

| # | Leaf family | Read site (pkg/config) | Reader | Both sides? |
|---|---|---|---|---|
| 1 | `routing-options forwarding-table export` | `compiler_routing.go` `compileRoutingOptions` | `multiLeafAuthoredValues` | yes |
| 2 | `security nat static … rule … match destination-address` | `compiler_nat_static.go` static-rule loop | `multiLeafAuthoredValues` | yes |
| 3 | `security flow traceoptions flag` — COMPILE | `compiler_security_flow.go` `compileFlow` | `firewallMatchValues` | yes |
| 4 | `security flow traceoptions flag` — COMMIT GATE | `compiler_security_flow.go` `validateFlowTraceFlagsAndFiltersAST` | `firewallMatchValues` | yes |
| 5 | `security nat proxy-arp … address` | `compiler_nat_source.go` `compileNAT` | `proxyARPAddressValues` | yes |
| 6 | `event-options … attributes-match` | `compiler_services.go` `eventAttributesMatchExprs` | `eventMultiWordLeafValues` (tail + each child) | yes |
| 7 | `event-options … then change-configuration commands` | `compiler_services.go` `eventChangeConfigCommands` | `eventMultiWordLeafValues` (tail + each child) | yes |
| 8 | `bridge-domains <bd> vlan-id-list` | `compiler_services.go` `compileBridgeDomains` | `multiLeafAuthoredValues` | yes (added by #6687, after this inventory was written) |

Family 3 has TWO read sites, and that is the whole reason the count differs from
the family count: the `flag` leaf is read once by the compiler and once by the
#3422 commit gate, and widening only one of them would leave a validation
fail-open where the gate and the compiler disagree about which values exist.
When auditing a widening, count READ SITES, not leaves — and not table rows.

**What this change does NOT cover, and where it is tracked.** These are
multi-value leaves whose readers are still one-sided; each is filed rather than
bundled, because each needs its own value-domain gate widened in the same change
(see the GATE ESCAPE table above):

| Leaf | Still one-sided | Tracked |
|---|---|---|
| ~~`system archival archive-sites` (+ three sibling system leaves)~~ | ~~reads `Children` and only slot 1 of the tail~~ | #6692 — FIXED |
| ~~nested-bracket tails, proxy-ARP after a range, repeated `commands` leaves~~ | ~~assorted value drops~~ | #6714 — FIXED (see "The one-sided read has a SECOND half" above) |

The table is empty of live rows. That is a state to defend rather than a state
to fill: the next entry belongs here only after the behavioural gate below has
been asked and found blind, with the reason it was blind written down.

### The list above is now enforced by a gate, not maintained by hand

`TestSchemaSpellingDifferentialGate` (`pkg/config/schema_spelling_differential_gate_test.go`)
walks `setSchema`, authors a two-element list at every value-bearing leaf in all
five spellings the grammar admits — hierarchical bracket / block / repeated, and
flat-set bracket / repeated — and fails the build when a leaf compiles
differently depending on which one the operator used. Its primitive is
deliberately behavioural rather than syntactic:

```
dropped(spelling) := compile(spelling, [v1]) == compile(spelling, [v1 v2])
```

**A DROPPED value and an UNREAD SHAPE are different defects, and the
differential only sees the first (#6697).** The primitive above discards any
spelling where the FIRST value did not move the output — "inert" — because a
synthetic parent path the compiler rejects makes every form identical. A reader
that ignores one shape ENTIRELY is indistinguishable from that: both `[v1]` and
`[v1 v2]` compile to nothing in the shape it does not read, so the spelling is
dropped from the comparison and the leaf reports agreement. Reverting all five
CoS code-point reads left this gate green. The third class closes it: for a leaf
the schema marks `multi: true` — a declared value list, where the block form is
legal Junos — a spelling that is READ sitting beside one that is INERT is itself
the finding. Restricting it to `multi` leaves is what makes it usable: over all
value-bearing leaves the same rule fires at 117 sites, almost all scalar leaves
for which `leaf { v; }` is not a Junos spelling. Over `multi` leaves it fires at
ZERO today, and that is what lets it be a build gate rather than a report; its
non-vacuity is the mutation, not the count — revert the five CoS code-point
reads and it names all three classifier sites, where the first two classes stay
silent.

**The compared output must exclude the DIAGNOSTIC channel, and a leaf is only
covered by a value pair its DOMAIN accepts (#6697).** `cfg.Warnings` is a field
of `Config`, so it used to be marshalled into the compared string. A value the
leaf rejects is recorded there by the tolerant compile path, which moves the
output off the no-value baseline and satisfies the guard that exists to catch
exactly that case — and because these readers fail FAST on the first bad token,
`[v1]` and `[v1 v2]` then produce the IDENTICAL single warning and the pair
reads as a uniform drop at a leaf with no defect. That is how all five #6697
sites reported "uniform drop" on every value pair OUTSIDE their domain while
reporting clean on the one pair inside it, at the same commit. `gateMarshal`
clears `Warnings` before comparing: a warning is what the compiler says ABOUT
the input, not configuration it installed. The corollary is the `pcp` value pair
(3/5) — without a pair inside 0..7 the `ieee-802.1` and `inet-precedence`
classifier leaves reject all the others, go inert, and carry no verdict, so a
fix there cannot be proven by removing an allowlist row.

**Why a gate and not a lint.** There is no single correct reader to lint FOR:
this package now has at least six accumulating readers, one of which
(`ntpServerValues`) must additionally skip per-value option KEYWORDS. A rule
matching "reads `Keys[1]`" would flag compliant code, and would have missed the
#7126 sites entirely — both of those read `Keys[1:]` AND `Children` exactly as
this document instructs, and still dropped, because reading `Children` is not the
same as reading every KEY of each child (both are fixed and their allowlist rows
removed; the predicate is stated above). A differential asks whether the compiler
disagrees with ITSELF, which is the actual defect.

**When the gate fails, there are exactly two correct responses**, and picking the
wrong one is how this rots:

1. The leaf IS a value list -> fix the compiler's read. Do not add a row.
2. The leaf is NOT a value list (a named container, a bare flag, an action with
   one optional argument) -> add it to `notAValueList` **with the reason, having
   verified where the extra tokens actually land**. Several such leaves park
   trailing tokens in the `UnknownLeaves` / `UnknownActions` diagnostic buckets,
   which looks exactly like a value list from the outside.

A third response — adding a row to `knownSpellingInconsistencies` — is only for a
defect that is real, tracked, and deferred, and each row is keyed by the ISSUE
NUMBER that owns it. A row whose site has stopped disagreeing is a HARD FAILURE,
so the row is removed by whoever fixes the defect and closes the issue, rather
than being deleted quietly to get green.

**A green run is not a swept schema, and the gate says so in its own output.**
It compares 607 of the 1017 sites it enumerates; the other 410 go inert under
synthetic parent paths the compiler rejects and carry no verdict in either
direction. It also sees ONE DIRECTION — a compiler DROPPING a value. The opposite
defect, a reader PROMOTING a per-value modifier keyword into the value list (the
hazard `ntpServerValues` exists to avoid), is not detectable by any differential,
because the lexer strips brackets before anything can observe them:
`route 10.9.0.0/16 discard;` and `route [ 10.9.0.0/16 discard ];` compile
byte-identically. Separating those two needs knowledge of the leaf's Junos
grammar, which exists today only where `setSchema` models a leaf's modifiers as
children — and `system ntp server` does not, which is why that leaf needed a
hand-written option table instead of a schema lookup.

`multiLeafAuthoredValues` exists to make one invariant TOTAL:
`multiLeafAuthoredValues(n)[0] == nodeVal(n)` for every node shape — including a
node carrying no value slot at all (`export [ ];`, whose brackets the lexer
strips, leaving `Keys=["export"]`), for which it returns one empty value because
that is what `nodeVal` selects. Consumers therefore MUST skip empty entries when
validating a value and MUST count only non-empty entries when enforcing
cardinality (`nonEmptyValues`) — an empty slot is a selection, not a second
policy or prefix, so counting it would invent a rejection. For the same reason a
cardinality gate must also count only DISTINCT entries (`dedupeValuesBy`): a
repeated value is one value, and rejecting it invents a rejection too. See
"A cardinality gate counts DISTINCT values" below for how each leaf picks its
identity.

### The ESCAPE half is a second gate, because the differential cannot see it

`TestSlotEscapeSweep` / `TestSlotEscapeTable` / `TestSlotEscapeCoverage`
(`pkg/config/schema_slot_escape_gate_test.go`, fixtures in
`schema_slot_escape_fixtures_test.go`) assert the other half of the property in
the GATE ESCAPE table above: **a value the commit check REJECTS in slot 0 must
also be rejected in every later slot.**

```
escape := commit(leaf, [bad]) != nil  &&  commit(leaf, [good bad]) == nil
```

Neither gate subsumes the other, and the reason is structural rather than a
matter of thoroughness. The spelling differential compares COMPILED OUTPUT
across spellings, so a leaf that drops NOTHING but checks only slot 0 compiles
identically in every spelling and reports agreement. Conversely a leaf can read
every value and check only the first (#6687, #6692, #6688), or read only the
first and thereby never check the rest (#7126) — the same defect reached from
opposite directions, and only one of those two is a value drop.

The escape gate's control is a CLEAN COMMIT, not a compiled string, so it needs
a parent path the compiler accepts. That splits the schema three ways, and
`TestSlotEscapeCoverage` re-derives the split on every run rather than stating
it here:

- sites where a synthetic parent commits clean AND some pool token is rejected
  are probed automatically by the sweep;
- sites where every pool token commits clean have no check to escape; the list
  is LOGGED, never asserted, because a leaf that later GAINS a check must not
  fail the build for it;
- sites whose synthetic parent is rejected for reasons unrelated to the leaf —
  a bare `security policies from-zone ... policy p match source-address` is
  refused for its two missing criteria — carry no verdict from any automatic
  probe. Those need a hand fixture supplying a real prerequisite config, and
  the coverage test FAILS if a schema addition lands one there without a row.
  That is the anti-rot property: growing the schema without covering the new
  leaf is a build failure, not a silent hole.

**Calibrate a sweep on defects you have already confirmed.** All six escapes
that existed at 22e17c2de — #6687, #6688, #6692, #6697 (two CoS rewrite-rule
families) and #7126 — are pinned as named rows in `slotEscapeHistoricalRows`,
and the file records that every one of them FAILS there and passes at master.
Three independent mutations kill it at three separate production sites: narrow
`multiLeafAuthoredValues(vlanNode)` to `[:1]`, `break` out of
`validateMultiValueLeaf`'s `Keys[1:]` loop, or truncate `coSCodePointTokens` to
one token.

**A token the GRAMMAR rejects is not a value the leaf refused.** An earlier
version of the pool carried `scp://u@h:/p`, which `ParseSetCommand` fails to
lex. That gave every site a "rejected" token, so every site with any accepted
token looked probed and the coverage figure came out nearly twice its true
value. Keep the pool to tokens the grammar accepts; a sweep that counts its own
parse failure as a leaf's gate over-reports coverage in exactly the direction
nobody checks.

### #6692: four system-stanza multi-value leaves, and why only three shared a fix

Four `multi: true` leaves under `system` were read with a single-value accessor,
so a bracketed list — which the lexer collapses onto ONE node's `Keys` — compiled
its first member and silently dropped the rest. Measured with the
spelling-differential gate's own `spellingVerdicts`, before the fix:

| Site | A hier-bracket | B hier-block | C hier-repeat | D set-bracket | E set-repeat |
|---|---|---|---|---|---|
| `system archival configuration archive-sites` | drop | keep | keep | drop | keep |
| `system services ssh key-exchange` | drop | drop | keep | drop | keep |
| `system services web-management api-auth api-key` | drop | drop | keep | drop | keep |
| `system dataplane shared-umem interface` | drop | drop | keep | drop | keep |

(Identical for all eight of the gate's value pairs — the drop is shape-driven,
not domain-driven.) `archive-sites` differs on B because its reader already
walked `Children`; the other three read neither side past slot 0.

**Three of the four share a fix; the fourth does not, and assuming otherwise
would have shipped a secret into an scp argv.**

- `key-exchange` and `shared-umem interface` take `firewallMatchValues` — every
  value they return is installed and an empty token means absence. `key-exchange`
  now matches the `ciphers`/`macs` siblings that were already converted in
  #4305/#4902.
- `api-key` takes `multiLeafAuthoredValues`, NOT `firewallMatchValues`, because
  an EMPTY value is load-bearing on this leaf: a quoted-empty `api-key ""`
  authenticates any request presenting the empty token, so it must still reach
  `validateAPIAuthNoEmptySecretsStrict` to be hard-rejected (#5636). An
  empty-skipping reader would make an empty key in a non-zero slot VANISH,
  silently withdrawing an operator-visible security rejection. The
  `multiLeafAuthoredValues(n)[0] == nodeVal(n)` invariant is what keeps slot 0
  byte-identical to the pre-fix read.
- `archive-sites` takes neither. Its value tail INTERLEAVES a `password
  <secret>` modifier with the site URLs (`archive-sites "scp://a/cfg" password
  "$9$..."` → `Keys=["archive-sites","scp://a/cfg","password","$9$..."]`), so
  accumulating the tail wholesale would promote the keyword AND the secret into
  `ArchiveSites`, where runtime archival hands each entry to `scp <src> <dest>`.
  It needs a GROUPING reader — `archiveSiteEntries` (`compiler_system.go`), the
  same `<value> [modifier ...]` shape as `firewallPrefixListRefs` — which binds
  `password` to the site preceding it and consumes its operand. A trailing
  `password` with no operand still marks the preceding site rather than becoming
  one.

The four AST shapes `archiveSiteEntries` covers were measured, not assumed:

```
archive-sites [ a b ];              Keys=["archive-sites","a","b"]
archive-sites a password S;         Keys=["archive-sites","a","password","S"]
archive-sites a { password S; }     Keys=["archive-sites","a"], child ["password","S"]
archive-sites { a password S; b; }  Keys=["archive-sites"], one child per site
archive-sites { a { password S; } } Keys=["archive-sites"], child "a" with a password child
```

**Widening the read is what CLOSED the #4589 gate escape, because the gate was
widened in the same change.** The leading-dash check (`must not begin with '-'`,
CWE-88) previously ran on slot 1 alone, so a `-oProxyCommand=` member authored
past the first was both dropped and unchecked — the bracket form ACCEPTED what
the same token authored alone REJECTED. It now runs over every entry
`archiveSiteEntries` returns.

On the validator axis for the other two security-relevant leaves: `key-exchange`
declares a schema `validator` (`ValidateSSHAlgorithm`), so `validateMultiValueLeaf`
already walks `Keys[1:]` AND every child's `Keys[0]` — the widened read does not
outrun its validation, which `TestSSHKeyExchangeValidatorCoversEverySlot_6692`
pins with a rejection in a NON-ZERO slot plus an over-reject control. `api-key`
has no schema validator; its check is the #5636 empty-secret gate, which the
widened read now feeds every authored slot.

Fail-on-revert: `pkg/config/compiler_system_multivalue_6692_test.go`. Six
single-site mutations were run, each localising to its own assertion with
`go build` and `go vet` at exit 0 — including one that narrows ONLY the
leading-dash gate (leaving the read widened) and one that swaps `api-key` to the
empty-skipping reader.

### #6696: the two dhcp-local-server list leaves, and why they take DIFFERENT readers

`system services dhcp-local-server group <g> interface` and `... group <g> pool
<p> dns-server` were read with `nodeVal`, so a bracketed list — which the lexer
collapses onto ONE node's `Keys` — compiled its first member and dropped the
rest. The group served only its first interface (the second segment got **no
leases at all**, a failure that looks like a network problem rather than a config
one) and a pool offered one resolver where two were configured, so the operator's
redundancy was simply absent.

**The failing axis is BRACKETED-vs-repeated-leaf, not strict-vs-tolerant.**
Measured at `origin/master` before the fix:

| spelling | strict | tolerant |
|---|---|---|
| `interface [ ge-0/0/0.0 ge-0/0/1.0 ]` | `["ge-0/0/0.0"]` | `["ge-0/0/0.0"]` |
| two `set … interface <v>` lines | both | both |

The issue that reported this named the tolerant path as the one that mattered. A
reader who tested only that path would have found the drop there, concluded the
strict commit path was safe, and been wrong. The strict-path result makes the HA
argument STRONGER, not weaker: a bracket-authored group is narrowed at the
ORIGINAL commit, so both cluster nodes agree — on the wrong value — and there is
no divergence to notice. The tests therefore compile every case on BOTH paths and
assert the two AGREE.

**Both leaves are now modelled, and modelling is what made the fix decidable.**
Neither leaf existed in `setSchema` at all, so the grammar said nothing about how
many tokens they take. Both families' `group` subtrees are now ONE function,
`dhcpLocalServerGroupSchema` — a divergence between v4 and v6 is always a bug
(the compiler is one function with an `isV6` flag), so it is made
unrepresentable rather than merely tested against.

**They take different readers, and that is the point:**

- `pool dns-server` is a plain value list (`multi: true`, `children: nil`,
  `ValidateIPAddress`), read with `firewallMatchValues` — both sides, every key
  of every child. Modelling it also brought it under the spelling-differential
  gate, which immediately caught a `Keys`-only first attempt as class-C INERT in
  spelling B (`dns-server { v1; v2; }`), a shape the old `nodeVal` fallback did
  handle.
- `group interface` is NOT a plain value list. It is the one leaf here carrying
  per-interface Junos MODIFIERS (`interface ge-0/0/0.0 exclude`, `…
  upgrade-server <addr>`), so it is `multi: true, valueList: true` with those
  modifier keywords modelled as CHILDREN — the #3872 static-route `next-hop`
  precedent, whose doc comment uses this exact `interface` modifier as its
  example. `valueList` absorbs a trailing token that is neither a sibling nor a
  known child (the bracket list) while still DESCENDING when the next token names
  a known child (the modifier). xpf parses and ignores every one of those
  modifiers — as it did before, where the single-value read dropped them — and
  they are modelled so the grammar has somewhere to park them other than the
  value list.

  `dhcpGroupInterfaceValues` then reads `Keys[1:]` when the statement names an
  interface on its own line (any child is then a modifier BODY), and every key of
  every child only for a bare `interface { … }` value block, whose values have
  nowhere else to live. Using `firewallMatchValues` here would PROMOTE `exclude`
  into the interface list — the #6673 promotion class, but with an unusually
  sharp consequence: `group.Interfaces` is handed to Kea verbatim as
  `interfaces-config.interfaces`, and one name no device answers to takes the
  WHOLE DHCP server down, not just that group. **The differential gate does not
  state that direction** — it detects a DROPPED value, not a PROMOTED modifier.
  Measured rather than assumed: swapping in `firewallMatchValues` DOES red the
  gate, but only INDIRECTLY, at the modelled `interface <if> <modifier>` sub-leaf
  sites — which exist only because the modifiers are modelled. Delete those
  children and the gate goes green with the promotion still present, and only
  `TestDHCPGroup6696PerInterfaceModifierIsNotAnInterface` reds. The property is
  owned by that test, not by the gate.

**A widened read needs a widened validator.** Before the fix only slot 0 could
reach a consumer, so a malformed element past it was inert; now every element is
installed. `dns-server` carries `ValidateIPAddress`; `interface` carries
`keyValidator: ValidateInterfaceName` — keyValidator rather than validator
because the node declares children, so its values ride the identity KEY slot and
it is the #5726 `valueList`+`keyValidator` arm of the schema walk that checks
EVERY packed value instead of only the first. Both run on the strict commit /
commit-check path only (`schemaValidateExpandedTreeForNode`, `pkg/configstore`),
so an already-persisted config still boots (#1960).

Fail-on-revert covered by `pkg/config/compiler_dhcp_group_multivalue_6696_test.go`.

### A widened read must not PROMOTE a token the old reader discarded (#6673)

Widening a one-sided reader has a failure mode symmetric to the one it fixes.
The old reader ignored one side of the AST; where the ignored side held garbage,
ignoring it was LOAD-BEARING. Reading it now materialises that garbage into the
compiled config, and a downstream consumer that refuses it converts a working
configuration into an inert one — with commit still succeeding on both trees, so
no gate reports anything.

**Where this can happen is decidable, not a matter of taste.** `nodeVal` reads
`Keys[1]` when present and falls back to `Children[0].Name()`, so every leaf
that used it ALREADY preferred the node's own tail; widening such a leaf can
only add values from slots the old reader never reached. The two `event-options`
arms are the exception in the #6659 set: they read `Children` and NOTHING else,
so for them the tail is exactly the discarded side. Both PROMOTION regressions
landed there.

That is a statement about promotion only, and an earlier revision of this
section over-read it into "both regressions landed there, and only there" —
which was wrong, and wrong in the direction that stops the next reader looking.
Promotion is one of the two ways a widened reader misreads a node. The other is
the TOKEN BOUNDARY below, and it bites in a place this section originally did
not consider: not the tail, but a CHILD's Keys.

The concrete shape is a node carrying BOTH a tail and children —
`<leaf> <identifier> { <value>; }`, which the parser renders as
`Keys=["<leaf>","<identifier>"]` with one child:

```
attributes-match bogus { "e.test-owner matches ^alice$"; }
then { change-configuration { commands bogus { "set system host-name foo"; } } }
```

Master discarded `bogus` in both. Promoting it made the first a HARD COMMIT
REJECTION (`ValidateEventAttributesMatchStrict` sees an expression with no
`matches` separator) and the second an INERT REMEDIATION
(`eventengine.classifyPlan` matches neither the `set ` nor the `delete ` prefix
and rejects the WHOLE batch, so `HandleEvent` discards it). Hence the rule both
readers now follow: **CHILDREN WIN — when the node has children they are the
whole value list and the node's own tail is ignored, verbatim master behaviour;
the tail is read only when there are no children, which is the shape master
compiled nothing from.**

**CHILDREN WIN is a rule for leaves whose tail is an IDENTIFIER, not a rule for
every leaf (#6690).** The two `event-options` arms adopt it because in
`<leaf> <identifier> { <value>; }` the tail names the statement and the children
are the values, so reading the tail promotes a name into the value list.
`system ntp server` is the opposite arrangement: the tail is the VALUE (the
server address) and a child is a per-server OPTION. `server 1.1.1.1 { prefer; }`
under CHILDREN WIN would compile `prefer` as the NTP server and discard
`1.1.1.1`. `ntpServerValues` (`compiler_system.go`) therefore reads both sides
and discriminates by TOKEN NAME instead of by side, skipping the four Junos
per-server option keywords — `prefer`, `key`, `version`, `routing-instance` —
together with their argument tokens, and carrying that skip count across the
`Keys` -> `Children` boundary.

Name-based discrimination is unavoidable for this leaf rather than a stylistic
choice. Once the lexer has stripped the brackets, `server 1.1.1.1 prefer;` and
`server [ 1.1.1.1 2.2.2.2 ];` are the SAME AST shape, so no structural rule can
separate an option from a second server. The schema cannot separate them either:
the leaf is `args: 1, multi: true`, which makes both `SetPath` and the block
parser absorb trailing tokens silently, and `prefer` is a syntactically valid
hostname that `ValidateNTPServer` accepts. Promoting it would render `prefer`
verbatim into a chrony `server` directive — the injection surface #4902 typed
the value to close.

Before this fold the nested-block spelling `ntp { server { a; b; } }` compiled
ZERO servers (the reader tested `len(Keys) >= 2`, which that shape never
satisfies) and the bracket spelling kept only the first — a green commit with no
time sync, whose symptoms (certificate validity windows, IPsec rekey scheduling,
cross-node log correlation) surface far from the cause.

#### The token boundary is a property of the GROUP, not of the tail (#6673)

When a leaf's value is itself a MULTI-WORD string, "how many values does this
token group hold" cannot be answered by counting tokens. Both `event-options`
arms are like this — a command carries its `set `/`delete ` prefix, an
expression carries `" matches "` — and both spellings are legal:

| Spelling | tokens | Meaning |
|---|---|---|
| `attributes-match e.owner matches X;` | `["e.owner","matches","X"]` | ONE expression the lexer split |
| `attributes-match [ "e.a matches X" "e.b matches Y" ];` | `["e.a matches X","e.b matches Y"]` | TWO whole expressions |

**Apply the rule to every group — the tail AND each child's Keys.** Which of the
two a bracketed list lands in is decided by WHICH PARSER RAN, not by what the
operator wrote:

| | `commands [ "set a b" "delete c" ]` becomes |
|---|---|
| `NewParser` (hierarchical / `load merge`) | `Keys=["commands","set a b","delete c"]`, no children |
| `ParseSetCommand` + `SetPath` (flat set / `load set` / CLI) | `Keys=["commands"]` with ONE child `Keys=["set a b","delete c"]` |

A rule applied to the tail alone therefore fixes one operator's spelling and
leaves the other's fusing. That was the #6673 defect: the branch split the tail
and joined the children, so the hierarchical bracket compiled correctly while
the identical flat-set bracket compiled to one fused string. For `commands` that
string still begins with `set `, so `classifyPlan` ACCEPTS it and the
remediation applies a path nobody wrote — strictly worse than the pre-#6659
reader, which applied the first command and dropped the rest. For
`attributes-match` it produced
`e.test-owner matches ^alice$ e.test-name matches ^wan$`, which
`ParseEventAttributesMatch` splits at the FIRST separator and accepts — the
remainder compiles as a valid regex — so the policy committed and then never
matched anything.

Note that neither leaf declares `multi: true`, and that is what makes the two
shapes diverge (a `multi` leaf absorbs a bracket onto its own tail under
`SetPath`). **Declaring them `multi` is not the fix**, for three reasons
measured firsthand and pinned by
`TestEventMultiValueLeaf6673TokenBoundaryBothParsers`: it routes an UNQUOTED
value onto the tail where a per-token read shatters it; it turns repeated
flat-set statements into sibling nodes that `ccNode.FindChild` (singular) drops
after the first; and it cannot repair an ALREADY-PERSISTED config, because the
configstore deserializes Nodes from JSON and `SetPath` never runs. Fix the
boundary in the reader, where both parser shapes and both storage paths meet.

**The discriminator is the FIRST token, not any token.** A first token that was
QUOTED means every token in the group is a whole value. Testing "any token"
instead breaks the legitimate mixture `commands set system host-name "foo bar"`,
a quoted VALUE inside an otherwise bare statement, shattering one command into
four. Testing the first token also takes the fail-CLOSED side of the opposite
mixture: `[ "set a b" bogus ]` splits, so `bogus` reaches `classifyPlan`'s prefix
check alone and rejects the whole batch, rather than being fused onto a valid
command and applied.

**"Was it quoted" is read from the AST, never inferred from the token text.**
The first cut of this rule asked whether the first token CONTAINED A SPACE or
was EMPTY, reasoning that the lexer never leaves a space inside a bare word.
That reasoning is sound but one-directional: every space-bearing token was
quoted, while a quoted token need NOT bear a space. A quoted one-word first
member — `commands [ "set" "system host-name pwned" ]` — carries neither marker,
so it read as bare and the list JOINED into `set system host-name pwned`: a
syntactically perfect command that passes `classifyPlan`'s `set ` prefix check
and is APPLIED. The authoring the operator wrote is a bare `set` member, which
is precisely what the fail-closed path exists to reject. No refinement of a text
test can separate the two — the tokens are byte-identical — so the bit is
carried STRUCTURALLY instead:

| Layer | Carries the bit |
|---|---|
| `Node.KeysQuoted []bool` (`ast.go`) | per-key provenance; `nil` when nothing is quoted, so the persisted JSON is byte-identical for the majority of nodes |
| `Parser.parseKeys` → `parseStatement` (`parser.go`) | hierarchical spelling; `parseKeys` already returned the token KINDS for the `inactive:` marker (#4348) |
| `ParseSetVerbQuoted` → `ConfigTree.SetPathQuoted` (`parser.go`, `ast_edit.go`) | flat-set spelling; `Store.SetFromInputAs` / `applyEditLine` call these, so CLI, gRPC and REST all carry it |
| `keyNeedsAuthoredQuote` (`ast.go`) | re-emits the authored quote on a NON-TERMINAL key so a serialize/re-parse cycle (HA config sync, `display set` replay, load merge, archive) does not launder it away |

Read it with `Node.KeyQuoted(i)`; ask `Node.KeysHaveQuoteProvenance()` before
treating a `false` as "this key was bare". A node with NO provenance — compiler
synthesis, or a config DB written before #6673 — falls back to the old text rule
rather than being assumed all-bare, because assuming all-bare is a false claim in
the fail-OPEN direction and assuming all-quoted would split
`commands set system host-name "foo bar"` and break a working remediation across
an upgrade. The fallback is not a second guess: for a group that genuinely has no
quoted token the two rules AGREE, since a bare word can be neither empty nor
space-bearing.

Serialization is deliberately NOT "preserve every authored quote", which would
render `description foo` as `description "foo"` in every `show configuration`.
It is as wide as the ambiguity — but **the terminal test differs between the two
renderers, and conflating them was a fail-open** (#6673 r11).

| Renderer | What "terminal" means | Why |
|---|---|---|
| hierarchical (`QuotedKeyPath`) | last key OF THE NODE | a node's last key is followed by `{`, so it stays a container key on re-parse and its quoting decides nothing |
| display-set (`joinQuotedKeysProv`) | last key OF THE EMITTED LINE | flattening concatenates a container's keys with its children's, so a container's last key lands at the FRONT of the child's group — the grouping-deciding token |

Applying the per-node rule to the flat path dropped exactly that quote.
Measured: `commands "set" { "system host-name pwned"; }` compiles, through
`load override`, to a batch `classifyPlan` DECLINES; its display-set dump emitted
the terminal `"set"` bare, and replaying that dump through `load set` compiled an
applicable `set system host-name pwned`. Same authored bytes, reject became
apply. `origin/master` does not have this — its reader compiles `["set"]` on the
replay side, which is declined too.

What is assertable, and what is not: display-set cannot express the difference
between a container's identifier slot (`commands "x" { "y"; }`) and a two-member
list (`commands [ "x" "y" ]`) — both flatten to one line, and that ambiguity is
pre-existing. So the two ingresses are NOT required to compile identical command
lists. They are required never to disagree toward EXECUTION: a batch one ingress
declines must not be applied by the other.
`TestIngressesDoNotDisagreeTowardExecution_6673` (pkg/configstore) binds that
through the real `LoadOverride` and `LoadSet`;
`TestEventCommands6673QuoteProvenanceSurvivesTextRoundTrip` binds the
round-trip fidelity of the leaf shapes.

Residual, unchanged: an ALL-BARE group (`[ seta setb ]`) still joins. Provenance
cannot help — both authorings have zero quoted tokens and the AST does not record
the brackets — and every well-formed value of both leaves contains a space, so
such a group is malformed either way and reaches the same gate under both rules.
Second residual: a tree that arrives with no provenance is still decided by the
text rule, so a policy authored before #6673 and still sitting in the persisted
config DB keeps the fused read until the operator re-authors the line (any `set`
through the CLI/gRPC/REST re-stamps it).

**Test this at the CONSUMER.** Every one of these is invisible to an assertion
about the compiler's intermediate string: the constraint list exists, the
command list exists, the config commits. What changed is the engine's verdict.
`pkg/eventengine/multivalue_leaf_runtime_6673_test.go` asserts whether the
policy fires and whether the batch classifies into an executable plan, against
origin/master's own reader run over the same AST.

Two consequences worth stating rather than leaving to be re-derived:

- **The `nodeVal` arms were checked and are NOT instances of this.** Feeding the
  same mixed shape to them — `destination-address 192.0.2.1/32 { 198.51.100.1/32;
  }`, `export p1 { p2; }` — does now fail commit where master accepted, but for
  a different reason and one that is not shape-specific: the tail there IS a
  value slot (`nodeVal` selects it), so the node carries two genuinely authored
  values and the cardinality gate rejects it in EVERY spelling, brackets
  included. That gate is #6659's reviewed core. Nothing is being promoted that
  the old reader threw away. `proxy-arp … address a { b; }` still commits.
- **The residual, stated: a value in the identifier slot beside a block is
  DROPPED.** `attributes-match "e.a matches X" { "e.b matches Y"; }` compiles to
  the child alone, and so does `commands "set a" { "set b"; }`. That is exactly
  what master did, so nothing regresses — but authoring a value there has never
  been supported and silently loses it. Author the block members, or the packed
  form; not both.

### The `flag` leaf installs every NON-EMPTY value, in every slot (#6673)

`security flow traceoptions flag` is a SET leaf, and #6659 changed what installs
for any multi-slot list. That change is deliberate and is recorded here because
it is operator-visible on upgrade.

Before #6659 the compiler read the leaf with `nodeVal` — the FIRST slot only —
and dropped an empty selection, so the installed set depended on where the
operator happened to write things:

| Authored | master installed | now installs |
|---|---|---|
| `flag [ session basic-datapath ];` | `{session}` | `{basic-datapath, session}` |
| `flag [ "" session ];` | `{basic-datapath, session}` (writer defaults) | `{session}` |
| `flag [ session "" ];` | `{session}` | `{session}` |

The middle two rows are the same configuration with the tokens swapped, and
master installed different flag sets for them; the first row is an operator
asking for two flags and getting one with no diagnostic. Neither behaviour was
designed — both fall out of slot-0 selection. The rule now is
POSITION-INDEPENDENT: every non-empty authored flag installs, and an empty token
is not a flag — it contributes nothing, it does not suppress the flags beside it,
and it does not re-enable `NewTraceWriter`'s defaults.

An empty token is NOT rejected at commit, because master accepted it and
inventing a rejection for an already-committed configuration is the failure mode
above. The "writer defaults apply" state is not lost either: authoring no `flag`
stanza remains the documented way to get it, which is what
`pkg/logging/flow_trace_flag_installed_6673_test.go` pins — at the writer, using
`NewTraceWriter`'s own flag map rather than the compiled slice.

### Detect a grammar keyword by CLASS, never by position (#6673)

`proxyARPAddressValues` is a SET reader with one exception: a MALFORMED RANGE
does not widen. `security nat proxy-arp … address` accepts `<low> to <high>`,
and the compiler consumes the two well-formed range shapes before the value
reader runs — so a `to` that survives to the reader means the statement is a
broken range, not a list, and it falls back to `nodeVal` (master's single-value
read). Widening it instead PROMOTES the range's surviving endpoint to a
standalone proxy address: `pkg/dataplane/proxyarp.go` installs an `NTF_PROXY`
neighbour for it and enables the per-interface kernel proxy responder, so the
appliance answers ARP/ND for an address that was never authored as one.

The detector for that must be over the statement's TOKEN STREAM, not over a
list of positions. Enumerating positions failed three times, because the parser
puts a `to` in at least four different places for this one statement:

| Spelling | Where the `to` lands |
|---|---|
| `address [ .1 .2 to .9 ];` | `prop.Keys[n]` (the bracket collapses onto one node) |
| `address { to; .5; }` | `Children[i].Keys[0]` |
| `address { .1; .2 to .9; }` | `Children[i].Keys[1]` — the BLOCK form, on the child's own Keys |
| `address { .1 .2 to .9; }` | `Children[i].Keys[2]` |
| `address { .1 { to .9; } }` | `Children[i].Children[j].Keys[0]`, nesting arbitrarily deep |

Each position-based revision passed its own tests and shipped the next
unenumerated shape as a live install divergence from master. `nodeSubtreeHasKey`
walks the whole subtree the parser built for the statement instead: every token
the parser keeps lands in some node's `Keys` there, so no shape — present or
future — can hide the keyword from it. **When a reader must recognise a grammar
keyword inside a multi-value leaf, scan the subtree; do not enumerate slots.**

The veto is per STATEMENT, so a malformed range suppresses the widening for the
whole statement it appears in (`address { .1; .2 to .9; 198.51.100.1; }` yields
`.1` alone). That matches what master installs and what the bracket form already
did; vetoing per CHILD instead would install an address master never claimed.
Separate `address` statements are independent, so a broken one never suppresses
a well-formed sibling statement.

Two traps this closed, both invisible to a shape matrix that never builds an
empty value:

- **A selection can move.** Deriving the scalar from `list[0]` over an
  empty-filtered list made `export [ "" p1 ];` select `p1` where it had selected
  nothing — silently ENABLING an ECMP policy the operator had blanked. The
  scalar is now the verbatim pre-#6659 statement (`FindChild` + `nodeVal`),
  which also preserves LAST-ROOT-WINS across two top-level `routing-options`
  blocks: `compiler_dispatch.go` calls `compileRoutingOptions` once per root, so
  the scalar re-assigns while the list appends, and `list[0]` named the first
  root's policy instead of the rendered one.
- **Dropping an empty entry can turn a fail-CLOSED gate fail-OPEN.** The
  pre-#6659 `attributes-match` reader appended every child expression
  unconditionally, so a stray `""` was hard-rejected as a malformed match
  expression; filtering it accepted that config and let the event policy fire on
  every occurrence of its event.
- **A leaf that merely LOOKS validated is a trap of its own.** The sibling
  `commands` leaf keeps its empty entry too, but not for the reason above:
  `classifyPlan` skips an empty command, so the batch runs identically either
  way and master never declined it. What filtering would change is the compiled
  policy — `policySemanticRevision` hashes every `ThenCommands` entry, and
  `show event-options` prints the list verbatim — so the empty is kept for
  OUTPUT PARITY. Assuming the fail-closed story generalises from one event-
  options leaf to the next is exactly the guess that has to be checked against
  the consumer rather than inferred from the shape of the config.

A diagnostic about a NON-SELECTED value must not describe the selected one's
fate. `emitMatchAddr` (`compiler_validate_strict_nat.go`) picks the tolerant-path
suffix per value: the selected value really does drop the whole rule, while a
malformed value in any other slot never reaches the dataplane at all, so the rule
installs and keeps translating. Telling an operator their published service is
down when it is up is the same class of defect as the silence #6659 removed.

**But do not overcorrect into the mirror claim.** "The rule keeps translating"
holds only when the SELECTED value would itself install, and nothing guarantees
that: with `destination-address bad-old;` then `destination-address
bad-selected;` both values are malformed, so the warning about `bad-old`
announcing that `bad-selected` "stays active" was contradicted by the very next
warning on the same rule. The same trap sits on the routing side: the
forwarding-table export diagnostic must re-run `checkPolicyRef` on the selected
policy before saying it "still resolves", because the loop reports whichever
undefined value it reaches first and that is usually not the selected one. State
the consequence you have CHECKED, not the one the happy path suggests.

**And OBSERVE the verdict; do not MIRROR it (#6673).** The first fix here gave
`emitMatchAddr` a `selectedInstalls` flag recomputed from the two match-side
checks the loops apply. That mirror was wrong by three causes — the then-side
parse, the then-side host-mask, and the `/0` block-pair loop each drop the rule
without touching a match address — so the contradiction simply moved rather than
closing. A hand-written mirror of a set of checks drifts from that set by
construction, exactly as a hand-written list of AST positions drifts from the
parser's shapes.

The reliable form is to make the emission itself carry the verdict.
`validateNATHostMaskStrict` declares a per-rule `ruleDropped` flag that `emit` —
the closure whose suffix is *"rule dropped by dataplane until corrected"* — sets
on every call, while the genuinely narrower `emitSuffix` callers deliberately do
not. Any check added later participates for free. The per-value complaints are
then appended with a blank suffix and patched in place at the end of the rule
(which preserves warning order), once the verdict is final. Also keep the
empty-selection case, which is not a verdict about validity at all: `[ "" a b ]`
blanks `ExternalIP` and the Rust parse drops the mapping, so there is no
surviving rule to describe.

**"Observed, not mirrored" is only as good as the ROUTING of each check.** Two
whole-rule-dropping checks were reported through `emitSuffix` with port-scoped
wording and so never set the flag: the block-pair-plus-port gate (#3202 — the
Rust block branch `continue`s on any port) and the out-of-range `match
destination-port` gate (#5101 — `buildStaticNATSnapshots` drops the rule so an
invalid port cannot fail OPEN onto the port-0 wildcard). Both now go through
`emit`. Decide the routing from the two LOWERING stages, never from how narrow
the message sounds:

| Check | Effect | Route |
|---|---|---|
| match/then address unparseable, non-host, or `/0` block pair | whole rule dropped (Rust `from_snapshots`) | `emit` |
| block pair + any port (#3202) | whole rule dropped (Rust block branch) | `emit` |
| `match destination-port` out of range (#5101) | whole rule dropped (Go `buildStaticNATSnapshots`) | `emit` |
| `match destination-port` with no `mapped-port` | port-scoped 1:1 still installs | `emitSuffix` |
| `mapped-port` present-but-malformed | folds to 0; plain 1:1 still installs | `emitSuffix` |
| `mapped-port` with no `match destination-port` | port dropped; plain 1:1 still installs | `emitSuffix` |

The malformed-`mapped-port` row is narrower only because
`combineMappedPortOperands` folds ANY malformed operand to `0`, while the
`destination-port` arm stores whatever `Atoi` returned — so the arithmetically
identical fault reaches the whole-rule drop on one leaf and not the other. If
that fold ever changes, that row moves to `emit`.

**The bound, as an inventory rather than an example.** The flag reports what
THAT validator concluded, so a rule-breaking cause it does not itself report
leaves "stays active" standing. Two cases, both measured: an EMPTY `then
static-nat` target (a misspelled target keyword — the Go lowering emits
`InternalIP: ""` and the Rust parse drops the mapping; it IS reported, but by the
sibling `validateStaticNATThenTargetStrict` (#4290), whose emissions this flag
cannot see), and a CROSS-FAMILY host pair such as `192.0.2.1/32` ->
`2001:db8::1/128` (both sides parse and both are host routes, so no validator
checks it at all). Closing either needs a cross-validator verdict channel or a
new rejection, not a wording change. Write the inventory, not one example — "one
exception" invites the next reader to assume the rest are covered.

**Cardinality gates name the SELECTED value, which is not element `[0]`.**
`compileNATStatic` assigns `rule.Match = nodeVal(m)` once per
`destination-address` sibling, so the LAST authored statement wins; only within
one bracket/block list is the selected value that statement's first. The
forwarding-table export scalar behaves the same way across repeated
`routing-options` roots. Both gates quote the scalar, and both special-case an
empty scalar — "only one is honoured" is false when the answer is none.

**A cardinality gate counts DISTINCT values, never raw value slots (#6673).**
Widening a read makes repetition visible for the first time, and a gate that
counts slots then hard-rejects a configuration `origin/master` accepted and
compiled BYTE-IDENTICALLY — an invented rejection, which is the opposite failure
mode to the silent value-drop the widening was fixing. A repeat is not a second
prefix or policy: the scalar selects the same value either way, the lowering
emits the same single row, and *"only `X` would take effect and the rest would be
silently ignored"* is false when "the rest" IS `X`. Both gates therefore run
`dedupeValuesBy` after `nonEmptyValues`, for exactly the reason the empty slot is
already spared.

Choose the IDENTITY per leaf, and justify it:

- `forwarding-table export` values are opaque POLICY NAMES with no canonical
  form, so only an exact text repeat may be collapsed (`dedupeValues`).
- `match destination-address` values are ADDRESSES, so the identity is the
  canonical form the dataplane reduces them to — `staticNATMatchAddrKey` mirrors
  Rust `parse_nat_prefix` (a bare address is a host route; the base is masked to
  the prefix length). That collapses `192.0.2.1` with `192.0.2.1/32`, and
  `192.0.2.5/24` with `192.0.2.0/24`. Exact-text dedupe alone would leave those
  rejected — the same invented rejection, one spelling over. Equal keys mean the
  rule translates identically whichever spelling the compiler selects, which is
  what makes collapsing SOUND rather than merely lenient; a value with no
  canonical form (unparseable, malformed mask) keys on its raw text so two
  different typos never merge into one.
- **…but the identity belongs to the CONSUMER, and `match destination-address`
  has two.** The masking above mirrors `parse_nat_prefix`, which is the plain
  static-NAT lowering. The SAME leaf on an `nptv6-prefix` rule is consumed by
  `parse_prefix` in `userspace-dp/src/nptv6.rs`, which does the opposite: *"OR
  host bits are set beyond the prefix length (#4519 — fail closed, do NOT
  mask)"*, returning `None`. So for an NPTv6 rule `2001:db8:1:2::/48` and
  `2001:db8:1::/48` mask alike and install NOTHING alike — one translates, the
  other is refused. Keying them together made
  `destination-address [ 2001:db8:1::/48 2001:db8:1:2::/48 ]` commit clean with
  the invalid tail visible to no gate at all: the cardinality gate counted one
  prefix, the per-address validator skips NPTv6 rules, and
  `validateNPTv6PrefixesStrict` reads only the scalar `rule.Match`.
  `staticNATMatchAddrKeyFor(rule.IsNPTv6)` therefore withholds masking from a
  value that actually carries host bits, so the pair counts as two and the
  cardinality gate fires. The resulting coverage claim is narrow and exact: a
  widened NPTv6 value DISTINCT from the selected one is rejected by the
  cardinality gate, and a value IDENTICAL to it *is* the selected value, which
  `validateNPTv6PrefixesStrict` already checks. There is no per-value NPTv6
  validator. **Before reusing a dedupe key on a second leaf, check that the
  second leaf's consumer reduces values the same way the first one does.**

Deduplication must never loosen the rejection itself: genuinely distinct
prefixes or policies still fail commit, because one of them really would carry
no translation.

The exposure is not hypothetical even where the CLI cannot author it. Flat set
is idempotent and `apply-groups` does not duplicate, but a repeat survives
`tree.Format()` verbatim — a hand-edited config, a `load merge`, a generated
config or a peer-synced tree keeps it across reboot and HA sync. The tolerant
load path only warns (#1960) so the box boots, and the operator then cannot
commit ANY change until they find the duplicated line.

**A multi-value leaf can be PRESENT and still carry NOTHING — presence must be
decided by VALUES, never by the leaf NAME (#6526).** `firewallMatchValues`
skips blank tokens, and its doc comment states the contract: *an empty result
means "criterion absent"*. A gate that instead decides presence from the leaf
name (`present[child.Name()] = true`) is asserting something about VALUES using
a check on NAMES, and the two disagree for exactly one input — the leaf written
with **no operand**:

```
match { source-address; }                                # hierarchical
set security policies from-zone t to-zone u policy p match source-address
```

Both shapes yield `Keys=["source-address"]` with no children, so
`firewallMatchValues` returns nothing and the dimension compiles to the
**byte-identical empty slice the OMITTED form produces** — which the userspace
matcher reads as match-ANY. Under `then permit` that is a fail-open: an
operator who hits enter one token early commits a permit-any policy. Because
`multi: true` leaves are UNTYPED (no `validator`) and `schema_walk.go`
deliberately declines minimum arity (see "Trailing-token arity on scalar value
leaves", #3332 — the arity gate is scoped strictly to EXCESS tokens and only
runs for `scalar: true` leaves), `SchemaValidate` cannot catch this: in
`pkg/config` a leaf that opts out of typing opts out of every value check.
`policyValuelessMatchDimensions` (`compiler_policy_missing_match.go`) closes it
for the five value-bearing security-policy match dimensions by asking
`firewallMatchValues` — the SAME reader `compilePolicy` uses — whether the
dimension carries anything; see the #6526 section below. RULE OF THUMB: when a
gate's claim is *"this dimension constrains something"*, evaluate it with the
compiler's own value reader, not with a name lookup.

**Bracketed lists on a WILDCARD container collapse differently — a NESTED
chain, not `Keys[1:]` (#5248).** The contract above assumes a `multi: true`
value leaf, whose surplus bracket tokens land on ONE leaf's `Keys`. A
bracket list whose element is instead a **wildcard container** —
`security zones security-zone <z> interfaces [ ge-0/0/0 ge-0/0/1 ]`, where
the interface name is `schemaNode.wildcard` with its own `host-inbound-traffic`
child, NOT a `multi` leaf — does NOT collapse onto `Keys[1:]`. `SetPath`
descends the wildcard for the FIRST token, then (the interface-name node has
no wildcard of its own) nests every remaining token as a child UNDER that
first member: `interfaces -> ge-0/0/0(container) -> ge-0/0/1(leaf)`; a 3+
element list collapses the whole tail onto the deepest leaf's Keys
(`interfaces -> a(container) -> leaf Keys=[b c]`). `firewallMatchValues` is
therefore the WRONG helper here — it reads one node's `Keys[1:]` + immediate
children and would still see only the first member. `compileZones`
(`compiler_security_zones.go`) flattens the nested chain with the recursive
`zoneInterfaceMembers`, which reads every key at each level and skips a
`host-inbound-traffic` body (a bracketed member is bare membership in flat-set /
canonical `set` syntax — it cannot carry a per-interface host-inbound stanza
there; the `[ a b ] { host-inbound-traffic ... }` shape documented below is
reachable only via a raw-hierarchical `load override` parse). Before #5248 the
reader took only
`iface.Name()` and silently dropped every member after the first — a zone-
membership (security boundary) loss that also hid the dropped interface from
the strict `validateZoneInterfaceDefinedStrict` gate. Covered by
`pkg/config/compiler_zone_interfaces_bracket_5248_test.go`.

**The COMPACT-LEAF spelling puts the members on the STANZA's own Keys — reading
only `prop.Children` compiles the zone with ZERO interfaces (#6525).** The
`interfaces` stanza reaches the compiler in two structurally different shapes,
and only one of them is reachable from `set`:

| authored as | `interfaces` node | members live in |
|---|---|---|
| `interfaces { a; b; }` — BLOCK; `set` also always lands here | `Keys=["interfaces"]` | `Children` — one node per member for a block or a single `set`, but a flat bracket list NESTS (see below) |
| `interfaces a;` — COMPACT LEAF | `Keys=["interfaces","a"]` | the stanza's own `Keys[1:]`; `Children` nil |
| `interfaces [ a b ];` | `Keys=["interfaces","a","b"]` | ditto (the lexer strips the brackets, #2419) |
| `interfaces a { host-inbound-traffic {...} }` | `Keys=["interfaces","a"]` | `Keys[1:]`; `Children` is the member's **BODY**, not more members |

A flat-set bracket list does **not** fan out to one child per member. `set
security zones security-zone Z interfaces [ a b c ]` produces a NESTED chain,
because the schema models the interface name as a wildcard CONTAINER: `SetPath`
descends the wildcard for `a`, then — the interface-name node has no wildcard of
its own — collapses every remaining token onto ONE leaf beneath it.

```
interfaces            Keys=["interfaces"]  children=1
  a                   Keys=["a"]           children=1
    b c               Keys=["b","c"]       children=0
```

`zoneInterfaceMembers` RECURSES and reads every key at each level, so this is
read correctly — but a reader that walked only `prop.Children` one level deep
would see member `a` alone. Shape pinned by
`TestZoneInterfaces6735FlatSetBracketNestsRatherThanFanning`.

**A body keyword with dropped tokens after it is REJECTED (#6735).**
Because the lexer has already stripped the brackets, `interfaces [ a
host-inbound-traffic b ]` and `interfaces a host-inbound-traffic system-services
ssh` are indistinguishable, and their readings disagree about membership — the
truncator keeps only the names BEFORE the keyword, dropping either a valid
member (left with no zone, never dataplane-bound) or the whole override. The
compiler refuses rather than guessing: `validateZoneInterfacePackedTailStrict`
hard-rejects at commit and warns on the tolerant load / peer-sync path (#1960
no-brick). Rewrite in the block spelling, which is unambiguous — `interfaces {
a; b; }` for membership, `interfaces { a { host-inbound-traffic { ... } } }` for
a per-interface body. A keyword with NOTHING after it is accepted: truncation
loses nothing there.

The dropped tokens do **not** have to be on the same `Keys` slice, and assuming
they were is how the gate first shipped with the headline statement escaping it
in the `set` ingest. `host-inbound-traffic` is a schema CHILD of the
interface-name wildcard, so when it is the token immediately after the first
bracket token, `SetPath` **descends** it instead of collapsing the tail:

```
set ... interfaces [ a host-inbound-traffic b ]
interfaces -> a -> host-inbound-traffic -> b        # b parks UNDER the keyword
set ... interfaces [ a b host-inbound-traffic c ]
interfaces -> a -> Keys=["b","host-inbound-traffic","c"]   # c on one Keys slice
```

Both lose their trailing member; only the second was visible to a Keys-only
detector. The gate therefore also inspects a keyword NODE's subtree
(`zoneInterfaceHostInboundStrayTokens`): a token there is a dropped member unless
it is legitimate body content (`system-services` / `protocols`, derived from
`hostInboundSchemaChildren` so the two cannot drift) or one of the
`apply-groups` / `apply-groups-except` / `apply-macro` statements that may appear
anywhere in the hierarchy — `apply-groups-except` and `apply-macro` survive group
expansion as live nodes, so reading one as a member would false-reject a
legitimate config.


`compileZones` iterated `prop.Children`, so every compact spelling ran the loop
body ZERO times and the zone compiled with NO interfaces — cleanly, with no
error and no warning. Both strict zone gates
(`validateZoneInterfaceMembershipStrict`, `validateZoneInterfaceDefinedStrict`)
then passed VACUOUSLY: they iterate `zone.Interfaces`, which was empty, so the
two gates that exist specifically to protect zone membership were inert against
a membership list that never arrived. Downstream, `UserspaceBoundLinuxInterfaces`
skips any interface with `Zone == ""`, so the interface was never AF_XDP-bound
and every policy naming that zone never applied to its traffic.

Two traps in the fix, both live:

- **`zoneInterfaceMembers(prop)` is the WRONG fix.** Its Keys loop starts at
  index 0, which is a member name for a CHILD but the stanza keyword
  `interfaces` for the stanza itself — it compiles a zone member literally named
  `interfaces`. `zoneInterfaceMemberNodes` synthesizes a member node from
  `prop.Keys[1:]` instead.
- **Excluding the BODY matters as much as reading the Keys.** In the compact
  with-body shape `prop.Children` holds the `host-inbound-traffic` node, and in
  the hierarchical PACKED shape (`interfaces a host-inbound-traffic
  system-services ssh;`) the body sits on the member's own Keys. Reading either
  without excluding the body trades a silent DROP for a silent INVENTION — body
  keywords promoted to interface names (measured on master:
  `ifaces=[host-inbound-traffic system-services ssh]`). `zoneInterfaceMembers`
  now truncates a member's Keys at a `zoneInterfaceBodyKeywords` token and stops
  recursing there; that token set mirrors the schema (the interface-name
  wildcard's only child is `host-inbound-traffic`) and must be kept in lockstep
  with it.

Normalizing the compact shape onto the block shape — rather than adding a second
read path — keeps membership, the #5248 bracket flatten and the #6391 Keys-scoped
override in ONE implementation; a second derivation is exactly how this defect
class arises.

**Fail-closed belt (#6525).** `validateZoneInterfacesNonEmptyStrict` rejects an
`interfaces` stanza that CARRIES CONTENT yet contributes zero members, so any
future shape the compiler cannot read is LOUD instead of silent. It asks the
compiler's own reader (`zoneInterfaceStanzaMembers`) and runs on the
group-expanded `*ConfigTree`, because a compiled `ZoneConfig` cannot distinguish
"no stanza" from "a stanza that compiled to nothing". It deliberately does NOT
fire on a stanza that carries nothing at all: `delete security zones
security-zone <z> interfaces <if>` of the last member leaves the empty container
behind (`deletePath` does not prune it), and rejecting that would make an
ordinary edit uncommittable against a stanza that renders invisibly — the #4191
over-rejection class. Strict on commit / commit-check, downgraded to a warning on
the tolerant load / peer-sync paths (`lenientZoneInterfacesNonEmpty`, #1960
no-brick). Covered by
`pkg/config/compiler_zone_interfaces_compact_leaf_6525_test.go`.

REACHABILITY (honest bound): the COMPACT-LEAF shape above is hierarchical text
ingest only — `load override` / `load merge` / the persisted config file / HA
`SyncApply`. `set` cannot produce it (`SetPath` always descends the `interfaces`
container), and `show configuration | display set` round-trips safely. Those are
still the boot path and the peer-sync path. The #6735 packed-tail shape is a
different matter: it IS reachable from the ordinary `set` CLI, in both the
Keys-collapsed and keyword-descended arrangements shown above.

### Four more members of the same family (#6564)

The #6525 zone-membership case above is one instance of a recurring shape. Four
further sites read the operand from ONE side only, and each dropped it BEFORE an
otherwise-correct strict gate read it, so the gate iterated an empty slice and
passed VACUOUSLY. In every case the config committed clean and the control was
simply not in force.

| Statement | Read before #6564 | Silent consequence |
|---|---|---|
| `security alg { dns disable; }` | `FindChild("disable")` — Children only | ALG stayed **ENABLED**; the #4232 unsupported-proto advisory does not fire either, because `dns` IS wired |
| `policy-options { prefix-list PL 10.0.0.0/8; }` | `inst.node.Children` only | list compiled **NAMED but EMPTY**; a filter term scoped by it silently stopped matching |
| `route R { next-hop { 192.168.1.1; } }` | `prop.Keys` only; Children matched just the `interface` modifier | route carried **ZERO** dispositions — `staticRouteDispositionConflict` rejects only >= 2, never zero — and rendered nothing into FRR |
| `security flow { tcp-mss all-tcp 1350; }` | `mssNode.Children` in BOTH the compiler and `validateTCPMSSRanges` | MSS clamping silently off; the range validator passed vacuously |

The static-route case is the INVERSE of the usual direction — the operand is in
the Children and the reader took it from the Keys — which is worth naming
explicitly, because "read Keys as well as Children" is the wrong generalisation.
The property is *read the side the operand is actually on*, and a fix that only
ever adds a Keys read will miss this one.

**One reader, not two (`tcpMSSOptionNodes`).** `tcp-mss` had two independent
Children walks — the compiler's and the range validator's — which is precisely
how the two halves drift. The packed leaf is now surfaced as a synthetic option
node by a single helper both call, so a future shape is handled once or not at
all, never half.

**Widening the grammar is a failure mode too.** `mss` is the HIERARCHICAL
keyword (`all-tcp { mss 1350; }`); inline it is a typo, and the half-packed
`tcp-mss { all-tcp mss 1350; }` already hard-rejects it (`selectMSSToken` picks
the literal `mss`). The synthetic node therefore carries the tokens VERBATIM so
the fully-packed leaf inherits the same rejection. Teaching it to strip `mss`
would have made the two shapes disagree in the opposite direction — accepting a
spelling one level up refuses. The acceptance criterion is "identical in both
shapes OR rejected at commit", and for that token the answer is rejected.

Covered by `pkg/config/compact_leaf_cohort_6564_test.go`, which asserts the
brace and flat-set spellings AGREE with the compact one rather than asserting
the compact one alone — a test that pinned only the compact shape would not
notice the two drifting apart again.

### The strict-reject members of the same cohort (#6564)

Three further #6564 members are NOT shape defects and must not be fixed as if
they were. The statement is structurally readable; its VALUE is malformed, or
its trailing token is unreachable, and the compiler silently coerced or
discarded it. There is no correct value to infer, so the only honest repair is
to refuse it.

| Statement | Silent behaviour before | Repair |
|---|---|---|
| `routing-options autonomous-system <bad>` | `strconv.ParseUint`'s error was discarded with no `else` and no record, so `AutonomousSystem` stayed 0, `resolveBGPAutonomousSystem` left `LocalAS` 0, and `pkg/frr` gates `router bgp` on `LocalAS > 0` — **one bad token silently disabled BGP entirely** | `valueType` + `validator`, matching its `local-as` / `peer-as` siblings, which already had both |
| `security-zone <z> screen <p> <trailing>` | the zone compiler reads `Keys[1]` via `nodeVal` and never the node's children, so a chained statement after the profile name is dropped | `scalar: true`, so the existing `validateScalarValueLeaf` arity gate sees it |
| `protocols ospf area <bad>` (×4 sites) | no key validator at all, so a malformed id was written **verbatim** into `frr.conf` | `keyValidator: ValidateOSPFArea` |

**Member 2 is a swallowed error, not a Keys-vs-Children defect** — `nodeVal`
already reads both shapes. A shape-family fix applied there would have looked
right and changed nothing, which is precisely why each member of a cohort has
to be diagnosed rather than pattern-matched to the family.

**The posture is asymmetric, and that is the point (#1960 no-brick).** All three
repairs are schema-level, so they inherit the #1319 PR 2 split for free:
`SchemaValidate` is STRICT on the operator commit / commit-check path
(`Store.compileTree`) and DOWNGRADED TO A WARNING on the tolerant
`Store.Load` / `Store.SyncApply` path (`Store.compileTreeLenient`). A new
operator edit is refused loudly; a config an older binary already accepted still
BOOTS after an upgrade. Refusing on both paths would blackout-boot a node or
alarm-loop HA config sync at the worst possible moment — during an upgrade,
possibly on the standby of an HA pair mid-ISSU.

`pkg/config/silent_drop_strict_6564_test.go` asserts BOTH directions: the strict
gate must reject, AND the compiler must still produce a config so the lenient
wrapper has something to continue with. A strict-only matrix would pass a fix
that bricks the boot path.

Two further guards worth keeping when this area is edited: the OSPF area
validator must accept **area 0** (the backbone has no `>= 1` floor, unlike a BGP
cluster-id), and the `autonomous-system` range must stay `1..4294967295` — a
mutation loosening either is a silent over-acceptance, and both are pinned.

### The dangling-keyword member (#6564 member 9)

`parseApplicationTerms` guards every value-taking arm with
`if i+1 < len(keys)` and has no `else`, so a RECOGNIZED leaf keyword in the LAST
position fell through recording nothing at all — and the `default:` arm that
feeds `UnknownTermLeaves` is unreachable for a keyword the switch recognizes.

The consequence is the exact fail-open the rest of that function exists to stop.
`default:`'s own comment says it records the token "rather than silently
dropping the constraint and widening the match", and #3348's says a dropped
`icmp-type` "would leave the term UNCONSTRAINED ... a fail-open widening". A
dangling keyword does precisely that: `term t1 protocol tcp destination-port`
compiled to protocol-only, so an application written to match ONE port matched
EVERY TCP port, and any policy permitting it widened with it.

**Why the surrounding family missed it.** #3320 (malformed timeout), #3348
(malformed icmp-type), #3352 (unrecognized leaf) and #6524 (trailing token on
the application body) each instrument a MALFORMED VALUE. This shape has no value
to be malformed — the defect is the ABSENCE of one — so none of their gates
could see it. A cohort built around "instrument the bad value" has a blind spot
at "there is no value", and that is worth checking for whenever a family of
value-validators accumulates.

**One guard, not eight `else` branches.** The check runs once before the switch,
keyed on `valueTakingTermLeaves`. A per-arm `else` would have to be repeated for
every future value-taking leaf, which is the duplication that drifts.

**The set is pinned to the switch textually.** `valueTakingTermLeaves` is the
arity contract, and a future leaf added to the switch WITHOUT being added to the
set silently re-opens the fail-open — while every behavioural test still passes,
because they can only exercise keywords someone remembered to list.
`TestValueTakingTermLeavesCoversEveryConsumingArm6564` therefore scans the
function's own source: every `case "<kw>":` arm whose body reads `keys[i+1]`
must be a member, and the counts must match in both directions so the set cannot
accumulate entries for leaves that no longer exist. It fails loudly if its own
scan pattern stops matching, so it cannot rot into a vacuous pass. Same
discipline as the #6588 no-arg statement registry.

`IncompleteTermLeaves` is deliberately separate from `UnknownTermLeaves`: the
keyword IS supported, so calling it an "unknown statement" would send the
operator hunting a typo that is not there. Posture is the cohort's usual —
strict on commit / commit-check, warn on the tolerant load / peer-sync path via
the existing `lenientApplicationSpecs` (#2142) downgrade.

REACHABILITY (honest bound): as with #6525, these compact spellings are
hierarchical text ingest only — `load override` / `load merge` / the persisted
config file / HA `SyncApply`. `set` cannot produce them and `display set`
round-trips safely. Those are still the boot path and the peer-sync path.

**A per-interface `host-inbound-traffic` override is scoped by the KEYS of the
node it is authored on, never by that node's CHILDREN (#6391).** The
`zoneInterfaceMembers` flatten above is for zone MEMBERSHIP only — it recurses
into children. Host-inbound is compiled separately and deliberately does NOT: it
applies to every name in `iface.Keys` and stops there.

That distinction exists because the two shapes below are NOT the same AST, which
is the opposite of what this document asserted before #6391 (it claimed they were
"structurally identical" and that no AST-keyed fan could separate them — a claim
disproved by dumping both):

| authored as | compiled AST | meaning |
|---|---|---|
| `interfaces { [ ge-0/0/0 ge-0/0/1 ] { host-inbound-traffic {...} } }` | ONE container `Keys=["ge-0/0/0","ge-0/0/1"]`, **no** membership child | multi-member intent → **both** members |
| `interfaces { ge-0/0/0 ge-0/0/1 { host-inbound-traffic {...} } }` — the **bare** spelling | identical to the row above; the lexer discards `[` / `]` (#2419), so the brackets are **cosmetic at this position** | multi-member intent → **both** members |
| `set ... interfaces [ ge-0/0/0 ge-0/0/1 ]`<br>`set ... interfaces ge-0/0/0 host-inbound-traffic system-services ssh` | container `Keys=["ge-0/0/0"]` with membership **child leaf** `Keys=["ge-0/0/1"]` | ssh scoped to `ge-0/0/0` **only** |

`SetPath` descends the wildcard for the FIRST bracket token and nests the tail
under it, then the second `set` REUSES that same `ge-0/0/0` container — which is
why the container ends up carrying both the `ge-0/0/1` membership leaf and the
host-inbound body even though ssh is single-scoped. Fanning across
`zoneInterfaceMembers` (children included) is exactly what PR #6389 did, and it
OPENS ssh on `ge-0/0/1`, which the operator never configured — an over-permission
/ host-inbound leak (admission is additive, `host_inbound_view.go`). #6389 closed
unmerged.

**What genuinely IS identical** — and the reason the children-fan leaks so
broadly — is the flat-set shape above and the hand-authored
`interfaces { ge-0/0/0 { ge-0/0/1; host-inbound-traffic {...} } }`. The latter is
the former's SERIALIZATION: `ConfigTree.Format()` (the render `configstore`
persists through, and the one HA config sync ships via `ShowActive()`) emits
literally that text, and re-parsing it is byte-identical. So a fan that fires on
that shape leaks on every RELOAD of an ordinary single-scoped config, and
first-member-only is the permanently correct answer there — not a compromise.

**Why keying on `Keys` is safe, not merely convenient.** A false positive here
would re-open the #6389 leak, so the load-bearing property is that **no
`set`-authored config can produce a multi-key interface container**. That holds by
schema construction: the interface name is `schemaNode.wildcard` with `args: 0`,
`multi: false`, `compoundKey: false` (`schema_security.go`), so `SetPath`'s
`nodeKeyCount = 1 + childSchema.args` is ALWAYS 1 and its container branch stores
exactly one token. Surplus bracket tokens can only land on a child LEAF, which has
no `host-inbound-traffic` child and is therefore never read by the fan. The
multi-key shape is reachable ONLY from a hierarchical parse (`load override`, a
hand-authored config file). `ExpandGroups` preserves the distinction (an inherited
multi-key node stays a separate sibling rather than merging into a single-key
one).

Scope rules that follow:

- **Individually-scoped isolation (UNCONDITIONAL).** A service authored under ONE
  named interface via its own `set` statement
  (`interfaces ge-0/0/0 host-inbound-traffic system-services ssh`) is
  single-scoped and must NEVER appear on a sibling.
- **Multi-member body applies to every member.** A body authored ON a bracket
  membership (`interfaces [ ge-0/0/0 ge-0/0/1 ] { host-inbound-traffic { ... } }`)
  applies to both. This is an admission WIDENING relative to pre-#6391, which
  applied it to the first member only — see the operator note in
  `docs/host-inbound-service-matrix.md`.
- **A nested extra membership is out of scope.**
  `[ a b ] { c; host-inbound {...} }` fans to `a` and `b` but NOT `c`. This is
  forced by the fix's own invariant rather than chosen: `c` is a nested CHILD,
  not a bracket PEER, and its AST position is indistinguishable from the flat-set
  membership tail that caused #6389 (`set ... interfaces [ a b ]` nests `b` as
  exactly this kind of child). Applying the body to `c` would restore the
  forbidden children-fan and re-open the original leak by another route. `c`
  remains a zone MEMBER and falls back to the zone-level host-inbound.
- **Members do not share a backing store.** `mergeHostInbound` returns `src`
  unchanged when `dst` is nil, so the fan clones per key (`cloneHostInbound`).
  Without that, a later single-scoped override merged into one member would
  mutate the value its bracket siblings point at.

**Round-trip: fixed in #6668.** The multi-key shape survives `Format()` →
`NewParser` (local persistence) and HA config sync byte-for-byte, and it now
survives `show | display set` as well.

It did not before. `FormatSet()` emitted
`set ... interfaces ge-0/0/0 ge-0/0/1 host-inbound-traffic system-services ssh`,
and the flat replay re-split that run at the schema arity — `nodeKeyCount =
1 + args` is 1 at the zone-`interfaces` wildcard — so `ge-0/0/0` became the
container and `ge-0/0/1` was demoted to the first key of a LEAF
(`Keys=["ge-0/0/1","host-inbound-traffic","system-services","ssh"]`) with the
whole body re-parented under it.

Three things about that are worth keeping, because they generalize to any
bracket authored at a CONTAINER position — the trigger is a non-leaf node with
`len(Keys) > 1 + schema.args`, not `multi: true` (every bracketed VALUE leaf
round-tripped clean all along, because SetPath's trailing-value absorber
re-collapses a leaf's tail — the #2419 contract):

- It was **not display-only.** `Store.LoadMergeAs`'s hierarchical branch renders
  the parsed file with `FormatSet` and replays it through `applyEditLine`, so
  `load merge <file>` rewrote the operator's config inside the daemon and
  reported success. `load override` was unaffected (it installs the parse tree
  directly) and so was HA config sync (it ships `Format()`, whose `{` terminates
  the key list).
- It was **not uniformly fail-closed.** The zone-`interfaces` case was rejected
  on reload, but `system login user [ alice bob ] { class super-user; }` and
  `class-of-service scheduler-maps [ m1 m2 ] { ... }` were REJECTED as authored
  and COMMITTED CLEAN after the round trip, with the second member's body gone —
  a round trip that launders a config past a commit gate.
- It was **invisible to an idempotency check.** Re-rendering the damaged tree
  produced the same flat line: the corruption is a fixed point of `FormatSet`.

The fix records, per key, whether the operator authored it inside `[ ... ]`
(`Node.KeysBracketed`, the bracket sibling of the #6673 `KeysQuoted`
provenance), re-emits the delimiter for a bracketed CONTAINER group, and honours
it on replay (`ParseSetVerbGrouped` → `SetPathQuotedGrouped` /
`DeletePathGrouped` / `DeactivatePathGrouped`). A group only ever WIDENS a node's
key slice, never narrows it. Rendering keys off the authored provenance rather
than off "wider than the arity" deliberately: the arity rule would also bracket
the PACKED-statement family (`unit 0 shaping-rate 10g { ... }`), whose flat
replay already reconstructs an equivalent config and which is tracked separately
(#6588 / #6665 / #6672).

All of the above is pinned by
`pkg/config/compiler_zone_iface_hostinbound_sibling_6391_test.go`, which asserts
the FULL per-interface host-inbound map (every interface, both system-services AND
protocols). Re-introducing a children-fan turns the CONTAINER-SHARING cases RED
(first-member, three-member, multi-service, protocols, and the
`a { b; host-inbound }` serialization case); reverting the Keys-fan turns
`TestHostInbound6391HierarchicalBracketBodyFansToAllMembers` RED. The later-member
and no-shared-backing-store cases stay GREEN CONTROLS (their interfaces do not
share a SetPath container). `TestHostInbound6391FlatSetNeverYieldsMultiKeyContainer`
guards the negative direction — a future `SetPath` or schema change that let
flat-set yield a multi-key container fails there rather than silently widening
admission.

**Sibling leaves on ONE flat-set line also collapse into a NESTED chain, not
siblings — the third collapse pattern (#6524).** The two patterns above cover a
bracket LIST (one leaf, many values). This one is about several DISTINCT leaves
written on a single `set` line. When a schema leaf declares `children: nil` and
is neither `multi` nor a wildcard container, `SetPath` consumes its `args`
tokens and then — having no sub-schema to descend — parks the REST of the line
under the node it just created. So

```
set applications application myapp protocol tcp destination-port 8080
```

does NOT build two siblings; it builds a chain
`application myapp -> protocol tcp -> destination-port 8080`, and only the
FIRST link gets a node of its own — every token after it is PACKED flat onto
one child (`protocol tcp -> Keys=[source-port 5000 destination-port 8080]` for
a three-leaf line). A compiler iterating the container's immediate `Children`
therefore sees only the first leaf and silently drops the rest.

That was the #6524 fail-open: `compileApplications` saw only `protocol`, never
assigned `DestinationPort`, and an empty port term matches ANY port
(`pkg/policymatch`), so a policy matching the application permitted **all TCP**.
Nothing caught it — `protocol` / `destination-port` / `source-port` were the
only `applications application` match leaves that were neither typed nor
`scalar: true`, so no arity gate engaged and the chained form validated clean at
BOTH `SchemaValidate` and strict commit. The REVERSE token order was caught only
incidentally (the chain drops `protocol` instead, tripping the #3109
protocol-less gate) — that asymmetry hid it.

`applicationDirectLeaves` (`compiler_applications.go`) is the canonical reader:
it walks the chain, splits each node's packed Keys into one leaf per recognized
keyword (a keyword-delimited scan, the same shape `parseApplicationTerms` uses),
and returns every token it cannot map to a known leaf so the deferred strict
gate rejects it. That last part is what makes `protocol [ tcp udp ]` and
`destination-port [ 22 23 ]` an operator-visible commit error: a DIRECT
application body holds ONE protocol and ONE port (`Application.Protocol` /
`.DestinationPort` are single fields — multi-valued matching is what `term`
sub-blocks are for), so the bracket tail is unrepresentable rather than merely
mis-read.

Two properties of that scan are load-bearing and easy to get wrong:

- **Reserve the value slot before resuming the keyword scan.** These leaves are
  `args: 1`, so each consumes exactly ONE token as its value *even when that
  token spells a grammar keyword*. `description destination-port` is a
  description whose text is `destination-port`, not a description followed by a
  port statement. Without the reservation the scan synthesizes a phantom
  valueless leaf that RESETS an already-assigned field — driving
  `DestinationPort` back to `""` (match-every-port on the tolerant path, the
  very widening this section is about), wiping `Protocol` to `""` (a
  config-wide fail-closed via #3323), and setting `hasDirectBody`
  unconditionally, which falsely trips the #3366 mixed direct+term gate on a
  term-only application. `description` is the only realistic vector — no
  protocol name/alias, `junosServicePorts` entry, ALG name, or numeric
  timeout/ICMP value collides with a grammar keyword.
- **Every consumer of the body must share this walk.** The chain reaches `term`
  nodes too, so `compileApplications` mints `<parent>-<term>` applications from
  a chained term. `collectApplicationCollisions`
  (`compiler_applications_collision.go`) predicts those same generated names to
  guard the flat Junos namespace (#3472/#3339); while it enumerated
  `inst.node.Children` directly it could not see a chained term, so a generated
  name silently OVERWROTE an authored application and erased any deny
  referencing it — with no commit error. Both sides now derive from the same
  walk: the compiler consumes `applicationDirectLeaves` directly, and the
  collision gate reaches it through `applicationTermNodes`, with both
  reassembling the term's tokens via `applicationTermKeys` so the predicted
  name always equals the written one. Adding a third reader of the application
  body means routing it through those helpers, not open-coding a fourth
  traversal.
- **An unrepresentable token POISONS the rest of its run and subtree — it must
  not be skipped so a later keyword can be recovered.** This is the direction
  that matters on the tolerant path: master ignored an unrecognized child node
  whole, so `bogus value protocol tcp` left the application PROTOCOL-LESS and
  therefore unrepresentable (fail-closed — `pkg/policymatch` reports
  `ContentRejected`, and the #2124 gate refuses to arm). Skipping `bogus` and
  compiling the `protocol tcp` that follows converts an inert residual into an
  ACTIVE all-TCP permit on boot / HA `SyncApply`, where the strict reject is
  only a warning. The same applies to a bracket tail:
  `destination-port [ 22 23 ] protocol tcp` must not drop `23` and then recover
  `protocol tcp`. Unknown direct-body content must leave the application NO
  WIDER than master. Sibling leaves are unaffected — they are separate nodes,
  so a stray line does not poison its neighbours.
- **`description` is a TAIL leaf, not `args: 1`.** Junos takes its text to the
  end of the statement, so the walk joins the run rather than flagging the tail;
  `description destination-port` keeps its keyword-spelling text intact, and a
  multi-word description packed onto one node's Keys compiles as written.
  Rejecting a metadata leaf that cannot affect matching would be pure friction,
  and that spelling committed on master. Note the join covers ONE of the three
  positions a multi-word description can occupy, and it is worth being exact
  about which, so nobody later loosens a gate master also held:
  - *sibling* (hierarchical or its own `set` line) — governed by the leaf's
    `scalar: true` arity (#3332), untouched;
  - *head of a chain* (`set ... description my web app protocol tcp`) — the
    tail is parked in a CHILD node, so `web` opens a fresh run;
    `SchemaValidate` rejects the line with `unexpected trailing token "web"`,
    exactly as on master, and it stays a commit error;
  - *packed chain tail* (`set ... protocol tcp description my web app`) — the
    whole description lands on one node's Keys, below the depth the schema walk
    reaches (`SchemaValidate` returns nil). **This is the only position the
    join rescues**, and the only one where a spelling master committed would
    otherwise have become a new hard reject.

**Known limitation — the chained spelling is enforced but not individually
editable.** Because the leaves are nested rather than siblings,
`delete applications application myapp destination-port 8080` (and the bare
`... destination-port`) fail with `path not found`: the node lives under
`protocol tcp`, not at application level. Re-setting a different port adds a
second sibling, which the #5574 conflicting-duplicate gate then rejects, and
that gate's remediation text ("split conflicting values into separate `term`
sub-blocks") is aimed at a genuine conflict rather than at "I want to change the
port". The escape is to delete the head of the chain (`delete applications
application myapp protocol tcp`), which drops the whole line, and re-author it.
This is pre-existing `SetPath`/`DeletePath` behaviour for every chained leaf,
not specific to applications — fixing it means teaching the AST editor to
address a leaf nested under a value node, which changes path resolution for
every `children: nil` leaf in the schema and is deliberately out of scope here.
Prefer the one-leaf-per-line spelling when authoring config you expect to edit.

**Why the fix is in the COMPILER, not the schema.** Typing the three leaves (or
tagging them `scalar: true`) would reject the chained form at commit-check, but
`CompileConfigLenient` — the boot-load and HA `SyncApply` path — downgrades a
schema rejection to a WARNING and keeps compiling. A schema-only fix therefore
leaves a persisted or peer-pushed config still compiling protocol-only and still
permitting all TCP, precisely where no operator sees the warning. Making the
compiler consume the chain fixes every path at once. It also avoids minting a
new commit-vs-load split for a spelling that now has well-defined semantics —
the same divergence class #3606 calls out for ports. Covered by
`pkg/config/compiler_application_chained_leaves_6524_test.go` and the
policy-OUTCOME suite `pkg/policymatch/app_chained_leaves_6524_test.go`.

**A PACKED hierarchical statement carries its entries on its OWN Keys — the
fourth collapse pattern, and the only one the flat-set path never produces
(#6588).** The three patterns above are all `SetPath` artifacts. This one comes
from the *hierarchical* parser and therefore reaches the compiler only through a
hand-authored config file, `load merge` / `load override`, or a peer config
sync — never through a `set` command. A statement that groups entries can be
written three ways, and they do NOT produce the same AST:

```
interface-monitor { ge-0/0/0 weight 255; }   # CONTAINER: Keys=[interface-monitor], one child per entry
interface-monitor ge-0/0/0 weight 255;       # PACKED:    Keys=[interface-monitor ge-0/0/0 weight 255], NO children
interface-monitor ge-0/0/0 { weight 255; }   # PACKED + body: Keys=[interface-monitor ge-0/0/0], children are that ENTRY's attributes
set ... interface-monitor ge-0/0/0 weight 255   # flat-set: SetPath yields the CONTAINER shape
```

A compiler that enumerates entries by iterating the statement's `Children`
alone sees NOTHING in the packed shape. That was the #6588 fail-open: a packed
`chassis cluster redundancy-group <n> interface-monitor <if> weight <w>`
compiled to ZERO interface monitors and a packed `ip-monitoring` to zero
targets, while `commit` succeeded with no error and no warning — the operator
had link and probe tracking configured and a redundancy group that never
demoted on failure. The third spelling was worse than a drop: the entry name
packs onto the statement while the attributes arrive as children, so reading
`Children` minted a monitor for an interface literally named `weight`.

`packedOrContainerEntries(cfgNode, skip)` (`compiler_system.go`) is the
canonical reader — `skip` is how many leading Keys name the statement itself.
Note its rule is **EITHER/OR, not accumulate**, which is the opposite of the
`#2419` multi-value contract above and the distinction to get right: a
multi-value leaf spreads values across Keys AND children of the same kind, so
`firewallMatchValues` must sum both; a grouping statement with an inline tail IS
one entry, so its children are that entry's properties, not sibling entries.
Accumulating there mints the bogus `weight` monitor. `namedInstances`
(`compiler_protocols.go`) already applies the same either/or rule to named
instances. Only the outermost level is unpacked — one tail is one entry, which
is what Junos renders (one statement per line).

Consequences worth knowing when adding a reader:

- **The schema walker does not see this shape** — unless the subtree is
  NORMALIZED before the walk. `SchemaValidate` walks the AST from `setSchema`,
  and a packed tail sits below the depth it reaches, so a typed leaf's
  `validator` never fires on it. Two answers exist, and which one is available
  depends on whether the packed body can be split back into statements:
  - Where it can, split it **before both consumers**. `chassis cluster`
    (#6672, below) expands its packed body into children at the top of
    `SchemaValidateWithDefinitions` and inside `compileChassis`, so the
    EXISTING typed-leaf validators fire on the packed spelling unchanged. That
    is strictly better than a parallel gate: there is one bounds table, and it
    is the one the container spelling already uses.
  - Where it cannot, the gate has to run on the COMPILED struct
    (`validateChassisClusterStrict`), not on the schema — which is only true
    once the packed shape actually compiles.

  Either way, **making a packed spelling compile without also making it
  validate opens a range-gate escape that did not exist before**: while the
  packed form compiled to nothing, the missing walker coverage was inert. This
  is not hypothetical — `cluster-id` is one byte of the RETH virtual MAC and
  `reth-advertise-interval` is a 12-bit VRRP wire field.
- **Silently compiling to nothing is the worst of the three options.** A
  statement whose packed spelling is genuinely unsupported must be REJECTED at
  commit with an actionable error. `services ip-monitoring` (a different
  stanza, `compiler_services.go`) is the fail-CLOSED example: its packed
  `then preferred-route ...;` is likewise dropped, but a policy with zero
  compiled routes is a hard commit error ("at least one then preferred-route
  route is required"), so the operator is told rather than left with a silent
  no-op.
- **`chassis cluster` is the whole-stanza case (#6672).** The same shape one
  level ABOVE the redundancy group dropped the ENTIRE cluster configuration.
  Four spellings exist and three were silently empty:

  ```
  chassis { cluster { cluster-id 1; node 0; } }   # container  -> compiles
  chassis { cluster cluster-id 1 node 0; }        # packed body -> ClusterConfig, every field zero
  chassis cluster { cluster-id 1; node 0; }       # keyword packed onto the chassis line -> Cluster == nil
  chassis cluster cluster-id 1 node 0;            # fully packed -> Cluster == nil
  ```

  A fifth arrives from the child side — `cluster { node 1 reth-count 2; }`, one
  child carrying two statements — and is split the same way. `compileChassis`
  reads the body with `FindChild`, i.e. off `.Children`, so a packed body was an
  empty stanza: no cluster-id, no node identity, no control PSK, no fabric
  addresses, no redundancy groups, and a clean `commit` with
  `show configuration` echoing what the operator wrote.

  `clusterStatements` (`compiler_chassis_cluster_packed.go`) is the SSOT for the
  statement set and each statement's value arity, and `clusterBodyStatements` is
  the splitter. Two properties are specific to this level and worth carrying:

  - **It nests, so `packedStatementPropsArity` (#6665) is not enough.** That
    helper is flat: any registered keyword re-arms it. The cluster and
    redundancy-group tables OVERLAP on exactly one token, `node` — the cluster's
    own identity and a group's per-node priority — so under the flat rule
    `redundancy-group 1 node 0 priority 200` re-arms at `node`, setting the
    CLUSTER's node identity and dropping the group's election priority. That is
    the #6588 failure reintroduced one level up. The rule is: once
    `redundancy-group` opens, a token re-arms only if it is `redundancy-group`
    itself or a cluster statement that is NOT also a redundancy-group statement.
    Overlap resolves to the INNER scope; cluster-only statements written after a
    packed group (`... redundancy-group 1 preempt reth-count 2`) still compile.
  - **The #6665 value-slot reservation crosses the boundary.** While a
    redundancy-group tail is open the splitter honours
    `redundancyGroupStatementArity`, so `interface-monitor reth-count weight 255`
    keeps a monitored interface literally named after a CLUSTER keyword instead
    of re-arming the outer splitter. `ValidateDeviceMapLogicalName` admits
    keyword-shaped names, so that is a name an operator can configure.

  Two divergences the work surfaced, both tracked separately rather than folded
  in: `fabric1-interface` and `fabric1-peer-address` are compiled by
  `compileChassis` but absent from `schemaChassis` (no completion, no
  validator), and `additional-authentication-key` / `control-ports` /
  `private-rg-election` sit on the other side of that line for stated reasons.
  `TestClusterSplitterAndSchemaAgree_6672` binds the set in both directions with
  the exception list as an EQUALITY, so the exception cannot outlive the
  divergence it documents.

- **`system login` is the fail-closed example with a dedicated gate (#6662).**
  Where `ip-monitoring` gets its rejection for free (an empty policy is
  independently invalid), an empty login class is *structurally* fine, so the
  drop needed its own AST gate:
  `validateLoginPackedStatementsAST` (`compiler_system_login_gates.go`), wired
  in `runPreWalkGates`, strict at commit / warn on the tolerant path
  (`lenientLoginPackedStatements`). It covers `login class <n>` and
  `login user <n>` at the instance line, plus `authentication` — the one login
  body statement the compiler reads exclusively through `.Children` — written
  inline one level down.

  It is worth stating **why** this one had to reject rather than compile
  something. Every downstream safety net in the stanza is guarded on
  NON-EMPTINESS, so an empty compile silences the whole belt at once: an empty
  user class is `pkg/cli`'s deliberate legacy "no RBAC configured" shortcut
  (allow every command, render secrets in cleartext), and the
  `deny-commands` "MORE PERMISSIVE" advisory is guarded on
  `lc.DenyCommands != ""` — the field the bug dropped is the field the guard
  reads. Unpacking instead would have to be exactly right for every leaf to
  avoid minting a wrong-but-non-empty class, which is worse than an empty one;
  both accepted spellings already work, so the operator has a mechanical
  rewrite. See `docs/system-login.md` for the operator-facing table.

  **The gate reproduces `namedInstances`' two-shape branch rather than calling
  it**, because it needs the number of leading IDENTITY keys and that helper
  discards it: `len(Keys) >= 2` is the node itself (identity 2), otherwise it
  is a child of a bare `user { }` container (identity 1). Branching on the
  shape — rather than sniffing `Keys[0]` against the keyword — stays correct
  for an instance literally named `user` or `class`.

  **The packing has THREE levels, and the gate's first revision saw only one
  (#6706).** The walk descends with `forEachChild` and `FindChildren`, which
  both match on `Keys[0]`, so a path packed onto an ANCESTOR line was invisible
  to it: with the instance on the `login` line that node carries
  `Keys=["login","user","alice",…]` and zero children, so `FindChildren("user")`
  returns nothing; with `login` on the `system` line, `sys.Children` is empty
  and the inner walk never runs. Measured through `configstore.CheckText` — the
  real commit / `commit check` / `xpfd check-config` pipeline — both
  `system { login user alice class ops; }` and `system login user alice class
  ops;` committed GREEN and compiled nothing.

  The sharp form of why that mattered: the one level the gate covered is the
  one whose runtime outcome is fail-CLOSED (an instance with an empty class
  resolves to `unauthorized`), while the two it missed were the fail-OPEN ones —
  `System.Login == nil` used to hit `pkg/daemon` `applyCLILoginClass`'s early
  return, so `SetUserClass` was never called and `pkg/cli` ran with an empty
  class: allow every command, render secrets in cleartext.

  That description is now HISTORICAL for the system level, and the tense is
  load-bearing (corrected #6706 review r11). `LoginDroppedByPacking` suppresses
  that early return, so a system-line packed path no longer fails open: a
  non-root caller gets `unauthorized` and root keeps its default. The
  login-line level was never nil-Login in the first place — it compiles a
  NON-nil but empty `LoginConfig`, which denies through `ResolveLoginClass`
  without consulting the flag at all. Both spellings therefore deny today, by
  two different mechanisms; #6972 asks whether a content-free prefix should.

  The generalisation is one predicate at two node levels — a `system` node with
  `Keys[1] == "login"`, or a `login` node with any key beyond its own — and a
  finding at an ancestor SUBSUMES everything below it, since the stanza the
  operator wrote does not exist at all. A prefix that stops before an instance
  NAME and has no children below (`system login;`, `system login user;`) names
  no user and no class, so there is nothing dropped to report and it is not
  rejected. It does NOT "declare nothing in either spelling" — an earlier
  revision said that and it is false (#6706 review r11): the nested
  `system { login; }` compiles a non-nil empty `LoginConfig` and denies every
  non-root caller, while the packed `system login;` compiles nil and reaches the
  legacy allow-everything mode. Reporting and runtime posture are separate
  decisions; the divergence is closed by `Config.System.LoginDroppedByPacking`
  (set by `loginPathPackedAnywhere` for EVERY packed shape, reported or not) and
  `pkg/daemon` `applyCLILoginClass`, which refuses the legacy unset-class mode
  when it is set. Both REPORTING arms ride the same
  `lenientLoginPackedStatements` flag as the instance arm and the same
  `forEachClusterNodeView` both-node union.

  The sibling shadow gate (`validateLoginClassShadowsBuiltinAST`) skips a
  `login` node carrying extra keys for the mirror-image reason: its children are
  then an INSTANCE body, so reading a `class <n>` child there misreads a user's
  class ASSIGNMENT as a class DEFINITION — it reported `system login class
  read-only: this definition is INERT` for a definition never written. The
  stanza is still rejected, by the ancestor arm, which names the real defect.

**The two collapses COMPOSE, and a monitor statement hits both.** The packed
collapse above is orthogonal to the `#2419` bracket collapse at the top of this
section, and `interface-monitor` is subject to each independently:

```
interface-monitor [ ge-0/0/0 ge-0/0/1 ];    # PACKED *and* bracketed
```

The lexer strips the brackets, so N interface names land on ONE node's Keys — in
the packed statement, in a hierarchical container child, and in the flat-set
child alike. Unpacking the statement but then treating its whole tail as a
single entry compiles the FIRST name and silently discards the rest: the same
failover fail-open as dropping the statement, one monitor at a time. So
`monitorEntryNodes` splits each candidate's Keys at entry boundaries — a token
that is neither the `weight` keyword nor the value slot reserved immediately
after it starts a new entry. The value-slot reservation is the same rule the
#6524 application walk needs, and for the same reason: `weight` consumes exactly
one following token even when that token spells something else.

**An inline attribute on a bracketed list is CANDIDATE-scoped, not positional.**
`interface-monitor [ ge-0/0/0 ge-0/0/1 ] weight 255` applies 255 to BOTH names.
Attaching the weight to the entry that precedes it — the obvious reading — left
`ge-0/0/0` at weight ZERO: monitored, present in `show`, and deducting nothing
when its link fails, so the group did not demote. With N names, N-1 monitors
were inert. That is worse than reading only the first name (which at least
protected `ge-0/0/0` at 255), and it contradicted the children-block spelling
`[ a b ] { weight 255; }`, which already applied the weight to both. Apply-to-all
makes the two spellings agree and is the fail-safe direction. Two inline weights
in one bracketed statement are ambiguous about which member each belongs to and
are REJECTED, consistent with the duplicate-weight gate.

Assert compiled WEIGHTS, not just names, when testing this. A name-only
assertion is blind to precisely the failure that matters: a monitor that exists
with weight 0 is indistinguishable at runtime from no monitor at all, and the
regression above shipped past a full bracket-list suite for exactly that reason.

Note the two rules pull in opposite directions and both are needed:

| | tail vs children | why |
|---|---|---|
| **entry list** (`interface-monitor`, ip-monitoring `inet` addresses) | EITHER/OR | a tail means the statement IS one entry, so children are that entry's ATTRIBUTES — accumulating mints a monitor for an interface literally named `weight` |
| **property body** (`ip-monitoring` itself) | BOTH | properties are siblings at the same level, so a packed tail and a real block body lose nothing when combined; the tail is split only at recognized property keywords (`packedStatementProps`) so `global-weight 255` is not shredded into two |

**A value that is present but UNUSABLE needs an AST gate — the compiled struct
cannot express it.** `compileChassis` parses a monitor weight with
`strconv.Atoi` and leaves the 0 default on failure, so by the time the
compiled-int range gate runs, `weight nope`, `weight 0`, and no weight at all
are indistinguishable. `interface-monitor ge-0/0/0 weight nope;` therefore
committed clean and installed a monitor that deducts NOTHING on link-down —
the same silent-nothing class as the dropped statement. It is rejected by
`validateMonitorWeightTokensAST` (`compiler_chassis_monitor_weight.go`), which
derives its entries from `monitorEntryNodes` / `monitorWeightTokens` so the gate
and the compiler can never disagree about which token is a weight or which entry
owns it. Strict at commit, warn on the tolerant load / peer-sync path (#1960).

That gate also settles a spelling-dependent answer: a DUPLICATE weight used to
compile to 200 inline (`weight 100 weight 200` — the inline scan overwrote) but
to 100 in a block (`{ weight 100; weight 200; }` — `FindChild` returns the
first). The compiler is now uniformly first-wins via `monitorWeightTokens`, and
a duplicate is rejected outright, so no operator is relying on which form they
happened to write.

**A gate that walks ENTRY LISTS will miss the statement's own PROPERTIES.** The
weight gate above was first written around `monitorEntryNodes`, which produces
entries — interface names, `family inet` addresses. `ip-monitoring`'s
`global-weight` and `global-threshold` are properties of the statement, not
entries of a list, so nothing looked at them and
`ip-monitoring global-weight nope;` committed clean at a compiled 0. That is the
WORST instance of the class rather than a lesser one: a malformed per-target
weight costs the group one target's demotion debt, whereas an unusable global
weight is zero debt for the entire group, so no number of failing probes demotes
it and failover never happens. `validateMonitorWeightTokensAST` now applies the
same missing-value / non-integer / duplicate rules to both globals, through one
shared `checkTokens` rather than a second copy. The globals' reader is
`ipMonitoringGlobalTokens`, which walks the same `packedStatementProps` result
the compiler dispatches from — `nodeVal(findNamedNode(props, name))` is
`ipMonitoringGlobalTokens(props, name)[0]` whenever the property is present, so
the gate cannot validate a token the compiler does not use. Pinned by
`TestIPMonitoringGlobalTokensMatchesCompilerRead_6588`.

**A statement that takes NO argument still needs its arity checked.** `preempt`
and `strict-vip-ownership` compile to a bool and never read the node, so
anything else written on them is discarded in silence:

```
redundancy-group 1 preempt weight 255;      # Preempt=true, `weight 255` gone
redundancy-group 1 preempt delay 5;         # Preempt=true, `delay 5` gone
redundancy-group 1 preempt { delay 5; }     # Preempt=true, the block gone
```

Unlike the value-position collision described later, this needs no implausible
input — a stray token is ordinary typing, and `preempt delay`/`limit`/`period`
are real Junos SRX options xpf does not implement, so accepting them silently
tells the operator they configured a preempt delay that does not exist.
`SchemaValidate` accepts all three (measured), and a bool has nowhere to record
what was dropped, so `validateRGNoArgStatementsAST`
(`compiler_chassis_rg_arity.go`) checks it on the AST through the same
`redundancyGroupBody` splitter. The flag set is written by hand — arity is not
recoverable from a handler's type, since every handler has the same signature
whether or not it reads the node — and
`TestRedundancyGroupNoArgStatementsAreRegistered_6588` keeps it from naming a
statement the dispatch table does not have.

**The dispatch table and `setSchema` are two SSOTs for one grammar, and they
had drifted (#6663).** `redundancyGroupStatements` is what `compileChassis`
actually compiles; `setSchema` is what config-mode completion and `?` help
read. `strict-vip-ownership` was in the first and missing from the second.

It was **not** a commit rejection — the redundancy-group subtree is
open-world (`schema_walk.go`), so the statement committed and took effect. It
was a COMPLETION gap: `set chassis cluster redundancy-group 1 ?` never offered
a knob the compiler implements, so it was discoverable only by reading the
compiler.

`TestRedundancyGroupCompilerAndSchemaAgree_6663` now binds them, and it
deliberately asserts **one direction only**:

- **compiler ⇒ schema** is checked. A statement the compiler honours while the
  schema omits it is always a defect, for the reason above.
- **schema ⇒ compiler** is NOT checked. A leaf declared but not yet compiled is
  the documented accepted-only posture (#2078/#4231/#5804): advertised,
  committing, with an advisory saying it is inert. Asserting that direction
  would red every deliberate use of it.

A second test pins that `strict-vip-ownership` is both declared AND still
compiles — otherwise the agreement test could be satisfied by deleting the
compiler entry, which is a feature removal wearing the shape of a fix.

**The packing recurses: an INSTANCE can carry its whole body on its own Keys
too.** Everything above is about a statement inside a named instance's body.
The instance line itself packs the same way:

```
redundancy-group 1 { interface-monitor ge-0/0/0 weight 255; }   # container
redundancy-group 1 interface-monitor ge-0/0/0 weight 255;       # PACKED instance
redundancy-group 1 node 0 priority 200 preempt;                 # PACKED, several statements
```

`namedInstances` (`compiler_protocols.go`) resolves the instance NAME across
both shapes — it reads `Keys[1]` — but hands the node back with the body still
on `Keys`, so a caller that then walks `.Children` sees an **empty instance**.
Every statement compiled to nothing while `commit` succeeded. For a
redundancy group that includes `node <id> priority <p>`, the election priority
itself: the operator sets it, `show configuration` echoes it, and the cluster
elects on defaults, so the WRONG NODE can hold the group — strictly worse than
"the group never demotes".

`redundancyGroupBody` (`compiler_system.go`) undoes it for the chassis-cluster
surface, splitting the tail at redundancy-group statement keywords so a
multi-statement line yields one node each. Those keywords come from
`redundancyGroupStatements`, a `map[string]func(*RedundancyGroup, *Node)` that
is BOTH the compiler's dispatch table and the splitter's token set — adding a
statement means adding one entry, which registers it with the splitter in the
same edit. The invariant is "all dispatch goes through the table", and it is
made natural rather than enforced: see the qualification below.

That is deliberately not a checked hand-written list. It was one: a test parsed
`compileChassis`'s source and extracted the `case "..."` literals of its switch.
The guard PASSED while a 7th statement was still dropped from a packed
multi-statement line in three ways — a `case` on a named CONSTANT rather than a
string literal (the idiom this same file uses for `monitorWeightKeyword`), a
statement handled by a helper called outside the switch, and a nested `switch`
inside a `default:` arm. Worse, the failure is camouflaged: the same statement
ALONE on a line still works, because the splitter opens the first node
regardless of the predicate. A developer adds the statement, checks the packed
spelling, sees green, and ships the fold bug. **Modelling another program's
source text is the wrong tool for keeping two things in step; derive both from
one table instead.** Registering a statement the ordinary way is now correct by
construction, which closes two of the three routes above outright — a
named-constant KEY registers exactly like a literal one, and no switch remains
to nest another inside. The third is demoted, not eliminated: compiling a
statement WITHOUT registering it still folds it, but that now means ad-hoc
dispatch beside a five-line loop whose only other content is the table lookup —
obvious in review, where adding a `case` to an existing switch was the
idiomatic act and diverged silently.

**Those three routes are all the table UNDER-covering the compiler; there is a
fourth of the opposite shape.** The splitter matches a registered keyword
wherever the token appears in the tail, including where the token is a VALUE
rather than a statement keyword, so a value spelled like a statement is stolen
and compiled as that statement. Measured:

```
redundancy-group 1 interface-monitor preempt weight 255;        # InterfaceMonitors=[]              Preempt=true
redundancy-group 1 { interface-monitor preempt weight 255; }    # InterfaceMonitors=[{preempt 255}] Preempt=false
```

The two spellings disagree — exactly what splitting the packed line exists to
prevent. It is not fixed, because the stolen token must sit in entry-NAME
position and no legal Junos interface name or IP address collides with a
registered keyword (`ge-*`/`xe-*`/`et-*`, `reth*`, `fxp*`, `em*`, `lo0`, `st0`,
`ae*`, `fab*`, `irb`, `vlan`), so it is unreachable from a real config rather
than merely unlikely. There is deliberately no test pinning the divergence —
that would assert the wrong answer is correct — and none asserting "keyword is
not an interface name" either, because the project has no canonical
interface-name predicate and inventing one in a test repeats the
source-modelling mistake described above. What is guarded is the EDIT that would
make the route reachable: registering a statement trips the completeness check
in `TestRedundancyGroupStatementsSurvivePackedLine_6588`, which is where the
collision question has to be asked. A real fix means splitting position-aware —
a keyword opens a statement only where a statement may begin — which changes the
splitter contract.

The splitter must also pick the right offset for the shape it is handed:
`namedInstances` returns EITHER the `redundancy-group <id>` node itself
(`Keys[0]` is the keyword, body starts at `Keys[2]`) OR, for a bare
`redundancy-group { ... }` wrapper, a child whose `Keys[0]` IS the id (body
starts at `Keys[1]`). `Keys[0]` discriminates them exactly. A fixed offset of 2
swallowed the statement keyword on the second shape and opened a node named
after a value, matching no switch arm — the same silent-nothing outcome,
election priority included. All FOUR readers of that body use it —
`compileChassis` plus the three AST gates (`validateMonitorWeightTokensAST`,
`validateChassisClusterIdentitiesAST`, `validateGratuitousARPCountAST`) —
because teaching the compiler to see a shape the gates cannot admits, through
the packed instance line only, exactly what those gates exist to reject.

**Why this is NOT fixed inside `namedInstances`.** Making the helper synthesize
the packed tail as a child would fix every caller at once, and it is tempting
for that reason. It also breaks callers that already handle the tail
themselves. `namedInstances` has ~130 call sites and 24 of them read
`inst.node.Keys` directly; synthesizing a child double-feeds those readers, and
`compileStaticRoutes` additionally branches on `len(node.Children) == 0` to
detect the packed shape, so a synthetic child silently disables its packed
path. Measured, not assumed — the experiment turns
`TestDHCPRelayOverrides_*` red (the override tokens get swallowed into
`Interfaces`) and `TestVRRPTrackInterface_KeysPackedDuplicateStrictReject` red
(lenient first-wins yields an empty `TrackInterface`). A future central fix
needs the 24 inline readers migrated first; that is its own change.

**Other `namedInstances` callers are NOT all safe, and that is tracked
separately.** Measured by direct compile: `system login class ops permissions
view;` compiles a class with EMPTY permissions, `system login user bob class
ops;` compiles a user with no class, and `system syslog host 10.0.0.9 any;`
compiles a host with zero facilities. Same root cause, different stanzas, no
security-boundary equivalence to the RG election — they are follow-up work, not
a claim of safety.

Covered by `pkg/config/compiler_chassis_packed_monitor_6588_test.go`, which
pins all three interface-monitor spellings against each other, covers the
bracketed / malformed / duplicate cases in each, adds the packed-instance
spelling for every redundancy-group statement, and keeps the
container/flat-set and single-entry cases as green controls. Its `assertMonitors`
helper requires a weight for every name — there is no name-only variant, because
having one meant every bracketed-list case in that file ran weight-less and the
apply-to-all rule above was unguarded.

**Two things that file learned the hard way, both worth keeping.** First, a
refactor can delete regression coverage for a bug that is still fixed, and
nothing goes red: the dispatch-table change dropped the bracket-inline-weight
and bare-`redundancy-group { <id> ... }` suites along with the source-parsing
drift guard it was deliberately replacing, leaving the apply-to-all rule and the
`Keys[0]` offset discrimination unguarded while both behaviours still worked.
When a refactor removes tests, account for each one: replaced, or restored.

Second, a completeness check that only asserts a sample EXISTS proves nothing. A
table entry keyed `review-placeholder` whose sample text was `preempt`, with a
`Preempt` assertion, satisfied every check in
`TestRedundancyGroupStatementsSurvivePackedLine_6588` while `review-placeholder`
never appeared in the input and its handler was never dispatched. The typed
assertions cannot catch this, because `preempt` sets `rg.Preempt` no matter
which key the sample is filed under. The test now requires each sample to begin
with its own statement keyword AND instruments the dispatch table so a case that
never reaches the handler it is filed under fails.

**A redundancy-group is folded by CANONICAL ID, not by the spelling
(#6543).** `namedInstances` yields one entry per AST node and
`compileChassis` parses the instance name with `strconv.Atoi`, which maps `1`,
`01`, `001` and `+1` to the SAME int. Appending one `*RedundancyGroup` per
instance therefore committed **two** records sharing `ID=1`:

```
set chassis cluster redundancy-group 1 node 0 priority 200   # record A: NodePriorities{0:200}
set chassis cluster redundancy-group 01 preempt              # record B: NodePriorities{} Preempt
```

The repeated hierarchical block hits the same split for a different reason —
`SetPath` merges same-name flat-set children, but the hierarchical parser
leaves `redundancy-group 1 { ... } redundancy-group 1 { ... }` as two nodes.

Everything downstream keys redundancy groups by the **int** id.
`cluster.Manager.UpdateConfig` (`pkg/cluster/group_state.go`) walks the slice
into an id-keyed map and does `existing.LocalPriority = rg.NodePriorities[m.nodeID]`,
so whichever record it visited last won: the empty-map record overwrote the
configured 200 with the **map-miss zero** and node 0 ran RG 1 at priority 0 —
it loses an election it was configured to win. The #4880 node-priority range
gate could not catch it either; it iterated the empty-map record and passed
**vacuously**, having nothing to range-check. Two silent-failure shapes
intersecting: an overloaded zero (map-miss `0` indistinguishable from a
configured `0`) behind a vacuous gate.

`compileChassis` now folds instances into one record per canonical id and
replays each instance's body into it through the same `redundancyGroupStatements`
dispatch table, so the merge is **leaf-level last-wins** — ordinary Junos `set`
semantics — rather than one whole record silently displacing another.
First-appearance order of the ids is preserved so the compiled slice, and every
first-error message derived from it, stays deterministic. Merging rather than
rejecting is deliberate: the repeated-hierarchical-block spelling is legal
Junos that merges, so a hard reject would newly refuse a config an operator can
legitimately write.

Covered by `pkg/config/compiler_chassis_rg_id_canonical_6543_test.go` (the
compile half, including a distinct-ids negative control and the #4880 gate now
seeing the merged record) and `pkg/cluster/rg_id_canonical_6543_test.go` (the
runtime half — real set lines through the real compiler into the real
`Manager`, asserting `LocalPriority` is the configured 200 and is insensitive
to which spelling came first).

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

**Commit-time gateway validation of a value list (#5726).** The container
keyValidator loop in `schema_walk.go` normally validates only the declared
identity-arg span (`1 + args` tokens). For a `valueList` leaf that would leave
every gateway past the first UNVALIDATED — a typo'd ECMP member
(`next-hop [ 192.168.1.1 1.2.3.999 ]`) then committed clean and FRR silently
dropped it (fail-open). The loop therefore special-cases `valueList &&
keyValidator != nil` (only `next-hop`) to run `ValidateStaticNextHop` over the
WHOLE `Keys[1:]` run, mirroring the compiler's keyword-bounded gateway scan
(#3881): an `interface <name>` token appearing AFTER at least one gateway is the
egress modifier and is skipped (an ifname is not a valid gateway literal), while
a LEADING `interface` token is itself a gateway value. A POSITIONAL multi leaf
(`route-filter`, `keyValidatorPos` + a per-position grammar and a value tail) is
NOT a `valueList` and keeps the declared-arg span. `qualified-next-hop` now also
carries the `ValidateStaticNextHop` keyValidator on its gateway identity arg
(#5726) — before, a malformed floating-backup gateway committed clean and the
backup never installed.

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

**Scoped display-set parent prefix: use `navigatePath`'s TRUE consumed width,
not a key-token heuristic (#5717).** `FormatPathSet` (`ast_format.go`, the
`show configuration <path> | display set` renderer) reconstructs the leading
prefix for each emitted `set` line by removing the matched terminal node's tokens
from the scoped path. Two heuristics both failed on legal repeated names:
searching the path left-to-right for the FIRST token equal to the matched node's
first key dropped an ancestor token when an ANCESTOR argument equaled that key (a
security zone NAMED `interfaces` holding an `interfaces` stanza rendered
`set security zones security-zone interfaces ge-0/0/9.0`, one `interfaces`
missing); suffix-aligning the node's WHOLE keys against the path over-stripped
when an ancestor value repeated the node's keys (a firewall filter NAMED `term`
holding a term NAMED `term`, `... filter term term term`, scoped to
`... filter term term` — the `term term` node matched by only its first key, but
the path tail `["term","term"]` also equalled its full keys). The robust fix
exposes the exact number of trailing path tokens `navigatePath` consumed into the
terminal node — `navigatePathWidth` (`ast.go`) returns `(matches, width)`, and
`navigatePath` is now a thin wrapper — so the parent prefix is
`path[:len(path)-width]` from the TRUE width (a single-key bare-keyword terminal
consumes ONE token even when its full Keys are longer). This is the display-side
twin of the copy-side #5822 fix (`CopyPath` first-keyword `insertNode`); both are
the codex-182 A3-b00-C001 AST path-identity cohort. Covered by
`pkg/config/ast_format_pathset_ancestor_5717_test.go` (zone-named-`interfaces`
round-trip, policy-named-`then` prefix, and every scoped depth of the
filter-`term`/term-`term` chain; fail-on-revert restores the token-heuristic and
drops a token).

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

**Copy-side contract: same resolver, same collision rule (#5822).** `copy <src>
to <dst>` (`CopyPath`, `ast_edit.go`) is the copy-side sibling of the rename fix.
The pre-#5822 implementation resolved the DESTINATION PARENT through `insertNode`,
whose per-level loop broke on the FIRST child whose FIRST key matched (the same
`matchNodeKeys`-returns-`1` keyword-only match) — so a copy whose destination
parent was a non-first same-keyword sibling (`copy ... to policy Z` with siblings
`[A B Z]`) descended into `policy A`, could not find the rest of the
destination-parent path, and failed `destination parent ... not found` (the issue
title), or — on a resolvable-but-existing target — silently appended a DUPLICATE.
`CopyPath` now resolves BOTH the source (`findNodeWithParent`) and the destination
parent (`childrenAtPath`) by full identity — the SAME longest-key-match navigator
`RenamePath` uses — so the two edit paths no longer carry divergent navigation
semantics (that divergence WAS the bug). It rejects a copy whose new identity
already exists under the destination parent (never a silent merge/duplicate), and
resolves + validates fully BEFORE cloning/appending so a failed copy (missing
destination parent OR collision) leaves the tree byte-for-byte unchanged; a
missing destination parent wraps `config.ErrPathNotFound`. The now-dead
first-keyword-match `insertNode` helper was removed. Covered by
`copypath_sibling_5822_test.go` (`pkg/config`) — first/middle/last + nested
multi-key sibling parents, collision-rejected-unchanged, missing-parent sentinel
— and `copy_sibling_5822_test.go` (`pkg/configstore`, the operational
`Store.Copy` path).

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

**A protocol-less `match destination-port` matches tcp AND udp (#6462).** When a
DNAT rule pins a `match destination-port` but NO `match protocol`, Junos matches
BOTH TCP and UDP (ports exist only for those two L4s). `buildDestinationNATSnapshots`
(`pkg/dataplane/userspace/nat_destination.go`) therefore emits one entry under
`tcp` AND one under `udp` — not a single `tcp` default (the pre-#6462 bug, which
left UDP to the VIP:port silently untranslated), and not a single `PROTO_ANY`
entry (that would wrongly translate ICMP/other, and the Rust `DnatTable` lookup
probes `(proto,dst_ip,dst_port) -> (proto,dst_ip,0) -> (PROTO_ANY,dst_ip,0)` but
never `(PROTO_ANY,dst_ip,dst_port)`, so a UDP packet could not find a
`PROTO_ANY`+port row anyway). The two rows are identical except the protocol key
and share the rule's single counter id, exactly like an explicit `match protocol
[ tcp udp ]`: a packet is tcp or udp, so it hits exactly one row and the counter
increments once. An explicit `match protocol` is honored verbatim (no synthetic
second protocol); a protocol-less rule with NO port stays a single match-any
(empty-protocol) entry. Coverage: `nat_destination_6462_test.go`.

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

**NAT match address arms read both slots (#6693) — the #4121 defect at five
sites that were not swept.** Source-NAT `match source-address` /
`match destination-address`, destination-NAT `match destination-address` /
`match source-address`, and static-NAT `match source-address` all carried the
same per-arm either/or (`if len(m.Keys) >= 2 { Keys[1:] } else { Children }`),
while the four SIBLING arms in the same switch — `source-address-name`,
`destination-address-name`, `protocol`, `application` — already read both slots.

The reachable input is `match { source-address 10.0.0.0/8 { 192.0.2.0/24; } }`:
`parseStatement`'s `case TokenLBrace` keeps every key token AND the block, so
`Keys=["source-address","10.0.0.0/8"]` with `Children=[["192.0.2.0/24"]]`, the
first branch fires, and the `else if` is structurally unreachable. It commits
CLEAN — these leaves are untyped (`args: 1, multi: true, children: nil`, no
validator) in an open-world subtree — and the second prefix never reaches the
dataplane. Two consequences, and they are independent: the rule silently matches
LESS traffic than authored (for source NAT that means untranslated egress, i.e.
an internal source address on the wire), and the dropped value ESCAPES
`validateNATMatchAddressLiteralsStrict` (#7145), which reasons from the compiled
list — so a malformed prefix in the child slot committed clean.

It is NOT reachable from flat-set: for a `multi` leaf with no children `SetPath`
always emits a leaf at the same level and never descends, so a flat replay
produces packed Keys or sibling leaves and never both slots. That is worth
recording, because a prior investigation enumerated the flat and one-slot
hierarchical spellings, found perfect agreement, and concluded the shape was
unreachable and a fix would be unfalsifiable. The enumeration was sound; it was
not exhaustive.

The five arms now use `natMatchAddressValues`
(`compiler_nat_match_values.go`), which accumulates both slots. It is
deliberately NEITHER of the two existing readers, and both alternatives were
measured rather than reasoned about:

- **not `firewallMatchValues`** (what the siblings use): it DROPS empty tokens,
  and here an authored empty is not absence. Switching these arms to it turned
  five #7216 subtests from reject to commit-clean, because `match
  source-address ""` no longer reached the compiled list that
  `validateStaticNATSelectedMatchAddressStrict` reasons from. Fixing a
  fail-closed drop by opening a fail-open hole is worse than the drop.
- **not `multiLeafAuthoredValues`** (#6673, which does keep empties): it
  synthesizes ONE empty value for a node with no value slot at all, to keep
  `values[0] == nodeVal(n)` total for a SELECTION leaf. These arms have no such
  scalar invariant, and a bare `source-address;` compiling to `[""]` would make
  the Rust `source_constrained` flag true over a prefix that parses as nothing —
  the rule then matches NOTHING instead of leaving the criterion absent.

So: accumulate both slots, keep empties, synthesize nothing. It reads every KEY
of each child rather than `child.Name()`, per #6714.

### The gate's own COVERAGE is gated too (#7484)

The differential above can only fail a leaf it actually compared. It needs two
spellings to return a usable `keep`/`drop` verdict; a leaf that does not reach
that bar carries **no verdict at all** and cannot fail anything. At `6b47801de`
that was **430 of 1049 enumerated leaves**, and the number lived only in a
`t.Logf` — so 619-compared and 1049-compared both rendered as PASS.

That is not hypothetical. `security log stream <*> transport protocol` and
`… tls-profile` were among the 430, and **#6821 reports exactly that leaf as
broken** (compact-leaf spelling drops the TLS profile, audit logs ship
unprotected). The gate built to catch the #2419 class was reporting "no spelling
inconsistencies" over a leaf where one was already filed.

`TestSchemaSpellingGateCoverageIsGated_7484` makes coverage a **gated property**:

- `gateCoverageFloor` is a FLOOR — coverage may rise freely, and a rise is a fix
  working, never a regression. Falling below it fails the build.
- each blind class carries a CEILING — a blind spot may shrink freely but not
  grow, so a new schema leaf that lands COVERED costs nothing while one that
  lands BLIND forces a deliberate decision.
- an IMPROVEMENT also fails, with the measured numbers and an instruction to
  tighten the constants. A ceiling nobody lowers rots into a rubber stamp.

**The four blind classes are four different diagnoses**, and lumping them as
"inert/unstable" hid that:

| class | meaning | is it a gap? |
|---|---|---|
| `unreachable` | the leaf changed nothing at all — the synthetic parent compiled but the compiler discarded the container, so the leaf never reached it | **yes** — the real gap |
| `flag` | the compiler READS the leaf but no value ever moves the output: a boolean | no — it has no value dimension to compare |
| `err` | the synthetic parent/bare stanza does not compile | yes |
| `valueMoves` | a value DOES move the output, yet fewer than two spellings produced a verdict | yes — the gate lost it some other way |

**Why the classifier is behavioural and not `args == 0`.** The obvious shortcut
is to drop leaves the schema declares value-less. It is wrong, and measurably:
of the 232 `args == 0` leaves, **15 are compared today and are genuinely
value-bearing lists** — `firewall … from source-prefix-list`,
`interfaces <*> fabric-options member-interfaces`,
`routing-options rib-groups <*> import-rib`, `event-options policy <*> events`,
`security ike gateway <*> local-identity`. Those are **under-declared in
setSchema**, not value-less. Excluding by `args` would have retired 15 live
cells to make the number look better. The behavioural test cannot do that: a
leaf that produces verdicts is already `compared` and never reaches the
classifier.

No leaf is allowlisted here. An allowlist row asserts a DEFECT exists and for
these none has been demonstrated; #6693's `mixedChildIsAModifierBlock` is the
precedent — where a verdict carries no information, drop the verdict rather than
claim a defect.

**A missing verdict used to read as a passing one.** `spellingVerdicts` builds
its map by ranging `gateSpellingsMulti`, while a scalar leaf compares over
`gateSpellingsScalar`. The two are consistent today and nothing enforced it, so
`state[name]` for an unpopulated spelling yielded `""` — neither
`err`/`unstable`/`inert` nor a real verdict, and it was counted as usable.
Found by mutation: removing two entries from `gateSpellingsMulti` made coverage
appear to RISE 619 → 1034, because every scalar leaf then scored two phantom
verdicts. The helper now accepts only an explicit `keep`/`drop`, and
`TestGateSpellingSetsAreConsistent_7484` pins the invariant.

**The remaining gap, measured.** The 228 `unreachable` leaves spread across 46
top-two-token parent prefixes — a long tail, not one bug. Largest:
`interfaces <*>` (81), `system services` (28), `system syslog` (26),
`protocols bgp` (25), `routing-instances <*>` (21), `security policies` (19).
The cause is per-parent: the harness authors the leaf alone, and a compiler that
requires a sibling discards the whole container. Confirmed on the #6821 leaf —
`security { log { stream X { transport { protocol V; } } } }` is discarded,
while adding a `host` sibling makes the value land. Recovering these means
teaching the harness a per-parent prerequisite, which is why it is tracked
separately rather than bundled here.

**The #2419 cohort does NOT share this cause.** Measured against the eight issues
open at the time: only #6821 sat in the blind spot (it is fixed now — see the
`packedTail` section above — but the measurement below is what it was when
taken, and the blind spot itself is unchanged). `#6736`, `#6817`, `#6953`, `#6966`
and `#7033` all have leaves the differential compares today, so their defects
escaped for some other reason and closing them as one cohort would be wrong.

### Parent prerequisites, and what the `unreachable` bucket actually is (#7492)

The harness authors a leaf **alone** inside its synthetic parent path. Some
compilers refuse to build the container until a required sibling is present, and
then the leaf never reaches the compiler at all: every spelling compiles to the
same thing, the differential calls them all `inert`, and the leaf drops out of
coverage. `gateParentPrereq` names the statement(s) that make such a container
materialise, injected identically into the zero-, one- and two-value configs so
it **cancels out of every comparison** — it decides only whether there is a
comparison to make.

A row is **not** an allowlist entry: it asserts nothing about the leaf, claims no
defect, and cannot hide one. It is refused outright if it would author the leaf
under test, so a prerequisite can never supply the value it exists to make
observable (`TestGateParentPrereqRefusesToAuthorTheLeafUnderTest_7492`).

**#7492's own premise turned out to be mostly wrong, and that is the useful
result.** The issue assumed the 228 `unreachable` leaves were largely a
parent-path synthesis problem. Measured, they are not:

- **A general mechanism was tried first and refuted.** Scaffolding each parent
  with its own other childless leaves — values drawn from the gate's candidate
  pool, keeping any that compiled — recovered **2 of 228**.
- **Most plausible per-parent recipes do not work either.** Probed directly and
  all still lose the value: `system syslog host <*>` with `any any`,
  `interfaces <*> unit <*> tunnel` with `source` + `destination`,
  `… vrrp-group <*>` with a `virtual-address`, and
  `dhcp-local-server … interface <*>` with an `upto` sibling.
- **One recipe works**, and it is in the table: a BGP group with no `neighbor` is
  discarded wholesale, so every group-level leaf looked inert.

So a per-parent prerequisite table is the right mechanism for a *minority* of the
bucket. The remaining ~215 are something else: a coarse probe (does the parent
path produce any output at all?) suggests most parents DO produce output while
the leaf stays unreflected — but that signal is unreliable, because an OUTER
object materialising is not the same as the innermost container materialising
(`chassis { cluster { … } }` yields a non-nil `Chassis` with a nil `Cluster`).
The next investigation needs a per-parent answer to two questions the current
probes cannot separate: does the innermost container materialise, and is the leaf
read by the compiler at that path at all. The second would be the #6696 class —
`setSchema` advertising a knob nothing implements.

**A blind-spot count that RISES after a fix can be the fix working.** Adding the
BGP row moved 13 leaves out of `unreachable`: **10 became compared, and 3 were
revealed to be `flag`s** once their container materialised and the classifier
could finally see them. The `flag` ceiling therefore goes UP (158 → 161) in the
same change that improves coverage. The population changed; a pre-fix number
carried forward as a target would have read that as a regression.

### Typed path identifiers, and the real cause of the `unreachable` bucket (#7492)

The harness names every `args` slot in a synthetic parent path with a
synthetic WORD (`xa20`). Many slots are not word-typed. `interfaces <if> unit
<n>` needs a NUMBER, and `unit xa20` does not parse as a unit — so the compiler
discards the whole unit subtree and every leaf beneath it looks `inert`.

That single cause accounted for **72 of the 215** remaining `unreachable`
leaves, all under `interfaces <*>` — the largest parent prefix, and one general
mechanism rather than the 46 per-parent recipes the issue predicted.

`gateEffectivePath` therefore compiles a leaf with the **word path first** and
falls back to a numeric-arg path only when the word path leaves the first value
inert AND the numeric path does not. The substitution happens at COMPILE time
only: `gateLeaf.path` keeps its word tokens, so `siteKey()` / `parentKey()`
normalisation, allowlist rows and prerequisite rows are all unaffected by which
form a leaf ends up using.

**Fallback, never default — and that is not caution, it is measured.** Making
the numeric form the default instead scores **worse in both directions**:
coverage falls to 635 (below the 687 the fallback reaches, because ~52 slots
genuinely need a word), *and* it manufactures FALSE #2419 findings at
`class-of-service classifiers dscp <*> forwarding-class <*> loss-priority <*>
code-points` with `A=inert B=inert C=inert D=keep E=keep F=inert` — `7` is not a
valid loss-priority, so the brace forms go inert while the set forms still read
the leaf. An always-numeric harness would have looked like a simplification and
been strictly worse.

**What the `unreachable` bucket is NOT.** Two hypotheses were measured and
refuted before this one:

- *"setSchema advertises knobs nothing implements"* (the #6696 class). Of the
  215, only 14 distinct leaf names never appear as a quoted literal anywhere in
  non-test, non-schema compiler source — 22 leaves — and **21 of those 22 are
  explicitly self-documented in their own schema description**: `rx-mode` says
  "retired, ignored", `security ipsec vpn <*> manual` says "NOT supported —
  rejected at commit", and every `dhcp-local-server … interface <*>` modifier
  says "(parsed, not implemented)". Deliberate, declared, and correctly inert.
  Exactly one leaf lacks such a note — see below.
- *"the value is a dangling reference the harness never defines"*. Refuted
  directly: `scheduler-map SM1` and `classifiers dscp CL1` both land in the
  compiled config whether or not the referent exists.

Widening the instrument does not rescue the first hypothesis either: only 31 of
the 215 carry a not-implemented marker in their description at all.

**The one genuine finding it did surface.** `security log profile <*> category
session field-extra-name` commits CLEAN on the strict path, its container
materialises, and the value never reaches the compiled config — while its
description ("Extra field to include in session records") reads like a working
feature, unlike its 21 neighbours. Tracked separately rather than folded here.

**The durable half is the gate.** `TestSchemaSpellingDifferentialGate` gains a
SEVENTH spelling, `F-hier-mixed` (`leaf <v1> { <v2>; }`) — the only spelling that
puts values in both AST slots of one node, which is exactly what an either/or
reader cannot see. Across the whole schema it moved ONE site beyond the five it
was added for, and that site is not a defect: `system archival configuration
archive-sites` puts a per-site MODIFIER block under an authored value
(`archive-sites a { password S; }`), so its child is not a member and dropping it
is correct. That is recorded in a third category,
`mixedChildIsAModifierBlock` — separate from `notAValueList` (the leaf is not a
list in ANY spelling) and from `knownSpellingInconsistencies` (a tracked
DEFECT), because neither of those is true here and using either would state
something false.

**The sharpest statement of the defect is a PERSISTENCE divergence.** The mixed
shape round-trips two different ways and they used to disagree with each other.
`ConfigTree.Format()` re-renders it verbatim (value in the identifier slot, tail
in the block), while `FormatSet()` — the spelling the configstore persists and
the CLI replays — renders it PACKED (`set … match source-address 10.0.0.0/8
192.0.2.0/24`). Both re-parse to a ONE-SLOT shape the either/or reader handled
correctly, so one config text had two meanings: as authored it matched only the
first prefix, and after any save/load cycle through the set spelling it matched
both. A rule silently WIDENS on the next reboot while `show | compare` reports no
change. `TestMixedShapeAgreesWithItsOwnPersistedRendering_6693` asserts the three
readings AGREE rather than pinning any one of them to a hand-written expectation.

Coverage is per-arm on both compile paths. The five arms are each asserted under
STRICT `CompileConfig` and tolerant `CompileConfigLenient`, agreeing with each
other before either is compared to the authored pair, and each is separately
shown to carry a malformed tail INTO its strict gate (three different gates cover
the five arms) while the tolerant path still ACCEPTS it — the #1960 no-brick
half, since a box can already hold a config whose tail never reached a gate. The
static-NAT fixture carries a valid `match destination-address` sibling for the
same reason the issue names: without it the #7216 "selected external prefix is
MISSING" gate fires first and its rejection is indistinguishable from the gate
under test firing on the tail.

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

## BGP group inheritance is sibling-order-independent (#5270)

A BGP `group`'s `neighbor` children and its group-level default attributes are
**semantically-unordered** Junos siblings. A neighbor inherits every group-level
default it does not override: `peer-as`, `local-as`, `local-address`,
`hold-time`, `passive`, `description`, `multihop`, `export`, `import`,
`family` (inet/inet6 + per-family `prefix-limit maximum`), `authentication-key`,
`bfd-liveness-detection` (interval/multiplier), `default-originate`, `loops`
(allow-as-in), and `remove-private`.

`compileProtocols` (`compiler_protocols.go`) used to walk a group's children
ONCE and stamp each neighbor with whatever group defaults had been *seen so
far* at the moment the `neighbor` child was encountered. That made inheritance
**encounter-order-dependent**: a `neighbor` authored before the group's
`export` (or `peer-as`, `local-address`, …) captured the empty/zero default,
so a config like

```
set protocols bgp group G neighbor 192.0.2.1     # neighbor FIRST
set protocols bgp group G export OUT             # export AFTER
```

compiled the neighbor with an empty `Export` → the FRR renderer emitted no
outbound route-map → routes leaked outbound (fail-open, not vSRX-equivalent).
Junos treats the two `set` lines as order-independent; xpf did not.

The compiler now does a **two-pass** group walk that is order-independent in
BOTH AST shapes (hierarchical block and flat-set):

- **Pass 0** processes every NON-`neighbor` child, fully collecting all
  group-level defaults regardless of sibling order (multi-value list leaves
  such as `export`/`import` accumulate via `firewallMatchValues` per the
  dual-AST contract above).
- **Pass 1** processes only the `neighbor` children, stamping each from the
  now-completed group defaults. Per-neighbor explicit values are applied on top
  and still OVERRIDE the inherited group default — the override precedence is
  unchanged; only the DEFAULT source moved from "seen-so-far" to
  "fully-collected".

The result: semantically-unordered sibling statements compile to IDENTICAL
neighbor state regardless of encounter order. The same `compileProtocols` runs
for top-level `protocols bgp` and per-`routing-instances` BGP, so both inherit
the fix. Covered by `pkg/config/bgp_group_inherit_order_5270_test.go` (neighbor
-before-export inherits, both orders identical across export/peer-as/
local-address/hold-time, per-neighbor override still wins in both orders, and a
hierarchical-shape variant).

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
positive), and management/cluster-control lifeline interfaces (fxp0 / em0 / fab<N>, exact — #5250)
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

## Unkeyed chassis-cluster fail-closed gate (#6611)

Three control-channel authentication mechanisms — fabric gRPC auth (#4357),
heartbeat HMAC + anti-replay (#4326) and session-sync challenge/response +
per-frame HMAC (#4369) — all key off ONE leaf, `chassis cluster
authentication-key`, and all three deliberately fail **OPEN** when it is
absent (`fabricAuthDecision` / `heartbeatAuthDecision` return accept on
`!keyConfigured`; `performSyncHandshake` runs no handshake with no local key).
That fail-open is what makes a rolling key rollout possible, but it means an
unkeyed cluster runs its **entire** control channel unauthenticated —
allowlist-only — so any host on the control segment can forge a heartbeat to
drive election, invoke the allowlisted fabric RPCs (read/clear sessions,
cross-node failover), and open a session-sync connection. Before #6611 no
config in the repository set the leaf, so those enforcing branches had never
run against real cluster traffic.

`validateClusterAuthKeyStrict`
(`pkg/config/compiler_validate_strict_cluster_auth.go`, invoked last in
`runUniformGatesClusterZone` so every structural cluster error still wins the
first-error slot) **rejects on the strict path** a `chassis cluster` stanza
whose `authentication-key` is absent or whitespace-only. The whitespace case is
an EMPTINESS normalization: trimming makes the gate STRICTER than the
runtime's `len(key) > 0` test (the runtime would treat `"   "` as a
configured key), which is the right direction on the strict path. It is not
an entropy floor — a one-character key passes. Key strength is a continuum and is reported by
`ClusterAuthKeyStrengthWarnings` as a `cfg.Warnings` entry on BOTH paths
(below `MinAdvisedControlLinkKeyLen` = 16 characters, or a key matching one of
this repository's published `CHANGE-ME`/`EXAMPLE-ONLY` placeholders) rather
than rejected — hard-rejecting a weak-but-real key would create a new brick
class for an operator who already configured authentication.

### The rotation overlap leaf (#6630)

`chassis cluster additional-authentication-key <key>` is a SECOND key the node
**accepts** on the control channel and never **signs** with, so a PSK rotation
can be rolled one node at a time instead of taken as a planned outage. It
compiles to `ClusterConfig.ControlLinkAuthKeyAlt`, is `Secret`-typed, and is in
`ast_redact.go`'s secret keyword set in its own right (`##SECRET-DATA##` in
raw-AST renders). `ClusterAuthKeyStrengthWarnings` judges it on the same terms
as the primary — a weak or published value there forges the control channel
just as effectively, and a rotation is exactly when an operator reaches for a
throwaway.

Two strict refusals attach to it, both downgraded to warnings on the tolerant
path for the #1960 no-brick reason:

- **Set without `authentication-key`.** The additional key is only ever
  verified against, so a node holding only it signs nothing and the channel
  fails OPEN exactly as if unkeyed. `validateClusterAuthKeyStrict` names this
  case specifically rather than emitting the generic absence message, which
  would send an operator to re-add a leaf they already have.
- **Set to the SAME value as `authentication-key`
  (`validateClusterAuthKeyOverlapStrict`).** That accepts exactly one key — no
  overlap at all — while the config and `show chassis cluster statistics` both
  read as though a rotation window were open. The operator proceeds to the next
  commit believing they are protected, which is the dual-master window the leaf
  exists to close. Compared whitespace-normalised on both sides, since the
  runtime compares raw bytes and a trim-equal pair is an overlap that isn't.

Neither refusal echoes a key. Operator procedure — including the five-step
rolling sequence and how to tell when finalize is safe — is in
`pkg/cluster/README.md` → "Rotation".

**Strict here means every caller of `compileTreeStrict`, not just the operator
commit.** Three paths reject an unkeyed cluster, and they differ in
consequence:

- `Store.Commit` / `CommitCheck` / `CommitConfirmed` — the operator commit.
  **Inert for traffic:** the active config and the dataplane are untouched, so
  the cluster keeps running while the operator adds the key.
- `daemon.bootstrapFromFile` — the UNATTENDED first-boot import of
  `/etc/xpf/xpf.conf`, taken whenever the config DB has no active config
  (`daemon_run_bringup.go`). A reject leaves the node with **no active config**,
  not a warning. This is the reimage / node-replacement / DR-restore path, and
  the path `test/incus/cluster-setup.sh` takes on every `make cluster-deploy`
  (it wipes `/etc/xpf/.configdb`).
- `configstore.CheckText` — `xpfd check-config`, wired into
  `scripts/deploy/xpf-deploy.py`, `scripts/image/make_config_drive.py` and the
  first-boot loader `scripts/image/xpf-day0-config` (which falls back to the
  factory bootstrap on reject).
- `pkg/eventengine` — AUTONOMOUS remediation. A `change-configuration` policy
  runs `store.CommitCheck()` and then the daemon's commit closure, both strict,
  with no operator present. On an in-place-upgraded unkeyed cluster — the
  population that boots leniently — every such policy silently fails from the
  moment of upgrade until the cluster is keyed.

Lenient downgrade to a `cfg.Warnings` entry on the tolerant load / peer-sync
path (`lenientClusterAuthKey`, #1960 no-brick) — that downgrade **is** the
IN-PLACE upgrade path: a cluster that was unkeyed before this gate existed
keeps its config DB, loads it through `CompileConfigLenient` at daemon start,
boots, keeps forwarding, and is keyed on the operator's next commit;
the heartbeat and fabric gRPC dual-accept then lets the key roll out one node
at a time without dropping the cluster — but **not** session sync, whose
dual-accept #5078 removed: a keyed node rejects an unkeyed peer, so session sync
stays down until both nodes are keyed and both have restarted (see
`pkg/cluster/README.md` -> "Rolling it onto a live unkeyed cluster", which marks
the old sequence STALE, #6881). Because the
unattended paths above fail closed, the migration has a REQUIRED ORDER: **key
the running cluster first, then re-provision / reimage / rebuild a day-0
drive.** `pkg/cluster/README.md` -> "Operating the control-link PSK (#6611)"
is the operator-facing statement of that order, and of the #6628 caveat that
session sync only picks the key up on a NEW connection (so a daemon restart is
required for it to enforce).

The gate error names the leaf and the remediation but never renders the value
— `authentication-key` is `config.Secret`-typed and is in `ast_redact.go`'s
secret set. Every shipped cluster config (`docs/ha-cluster*.conf`,
`test/incus/xpf-cluster-fw{0,1}.conf`, `examples/deploy/ha-pair.conf`) now
carries a key so the HA smoke cluster exercises the enforcing branch.
Operator guidance (generation, distribution, rolling rollout, rotation) is in
`pkg/cluster/README.md` → "Operating the control-link PSK (#6611)". Coverage:
`cluster_authkey_required_6611_test.go` — strict reject, whitespace-only
reject, tolerant-path warning, value-independent error text, key-strength and
placeholder advisories, and the shipped-config regression locks;
`pkg/daemon/bootstrap_cluster_authkey_6611_test.go` and
`pkg/configstore/check_cluster_authkey_6611_test.go` pin the two UNATTENDED
strict paths (including that a rejected bootstrap leaves no active config).
Negative controls assert a keyed cluster, a standalone (no `chassis cluster`)
config, and a keyed unattended bootstrap are all unaffected.

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

**Bracket-list members inside opaque set containers — the reader must
accumulate, not index (#4791 address-set, #5181 application-set).** The
`applications application-set <name>` body is an opaque `args:1` leaf
(`children:nil`), so `SchemaValidate` never walks into it and its member leaves
carry NO `multi:true` tag. But a member list is still authored as a Junos
bracketed list — `application [ app1 app2 app3 ]` — which the lexer collapses
onto ONE leaf's Keys (`["application","app1","app2","app3"]`) per the #2419
dual-shape rule. A compiler reading only `Keys[1]` (via `nodeVal`) kept just
`app1` and silently dropped the rest, so a policy referencing the set
under-matched — a DENY covered only the first application (fail-open). Both the
`application` and nested `application-set` member arms in
`compileApplications` now read every value through `applicationSetMemberValues`
(`Keys[1:]` AND each child's `Keys[0]`), the applications-side sibling of
`addressSetMemberValues` (`compiler_security_addressbook.go`, #4791) and the
`firewallMatchValues` SSOT. This is a compiler-reader fix, NOT a schema tag:
the opaque container stays `args:1` (the #3890 default arm still records typo'd
member keywords for the strict syntax gate). Pinned by
`pkg/config/applicationset_bracket_members_5181_test.go` (flat-set +
hierarchical bracket lists, nested-set bracket list, deny-policy expansion, and
a single-member negative control), RED on revert to `Keys[1]`.

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
  unknown-keyword rejects. When `closed` is false, behaviour is
  byte-identical to pre-#4313 (return nil, silent-accept) — which remains the
  default for every subtree that has not opted in.

  This paragraph deliberately carries NO count of armed subtrees. It used to
  say "the state for EVERY production subtree today", which was true when
  written and silently false a month later once the rollout began; the same
  stale claim in `schema_walk.go` mis-scoped a later lane that trusted it. The
  armed set is whatever carries `closedWorld: true` in `pkg/config/schema_*.go`
  — grep it, or read the `schema_closedworld_*_4313_test.go` files, one per
  closed subtree. A count in prose is a coverage claim and it rots.

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

**Terminal-action CARDINALITY — NAT rule `then` (codex-review-181 M16, #5628).**
The closed-world keyword audit above validates WHICH keywords may appear under
`then`, but not HOW MANY translation actions a rule carries. A malformed or
mixed-version rule could still present a complete `then {}` block with ZERO
NAT-terminal actions (actionless — the snapshot builder installs no
translation and the rule does not stop evaluation, so an intended `off`
exemption silently disappears and the traffic falls through: translated by a
later broader rule if one matches, otherwise left untranslated) or TWO+
mutually-exclusive actions (`off` + `pool`,
`interface` + `pool` — the compiler silently picked one by packed-key / child
order, so an exemption could publish as a translation). `security nat
{source,destination} rule … then` must therefore carry EXACTLY ONE NAT-terminal
action (SNAT: `source-nat` `interface` | `pool <p>` | `off`; DNAT:
`destination-nat` `pool <p>` | `off`). This is a cross-cutting cardinality rule
the per-leaf schema walk cannot express, so it lives in the strict-gate family
as `validateNATTerminalActionCardinalityStrict`
(`compiler_validate_strict_nat.go`, wired in `runUniformGates`): strict on
commit / commit-check, lenient (warn — `lenientNATTerminalAction`, #1960
no-brick) on the tolerant load / peer-sync path. It counts actions WITHIN one
complete `then` block — duplicate `then` CONTAINERS remain #3850's intentional
last-wins merge (`compileNAT{Source,Destination}` reset `rule.Then` per block,
so the count reflects the winning block) and are NOT rejected. The
`compileNAT{Source,Destination}` hierarchical setters were changed from an
`else if` chain to independent `if`s so a single-node contradiction
(`source-nat { interface; pool p; }`) records both fields rather than silently
picking one. Production tests:
`compiler_nat_terminal_action_5628_test.go` (RED on revert, flat + hierarchical
zero/two/valid + #3850 last-wins preservation).

The gate has a SECOND registration: `validateSourceNATStrictView`
(`compiler_peer_effective_snat.go`), the source-NAT subject of the #5876
peer-effective strict list. Both are load-bearing and neither substitutes for
the other. `runUniformGates` adjudicates the SUBMITTING node's view; the
peer-effective run adjudicates the PEER's `${node}` / `groups nodeN` expansion,
and it is the only strict adjudication that view ever gets, because the standby
ingests the synced config through `Store.SyncApply` →
`CompileConfigForNodeLenient`, where this gate is downgraded to a warning. A
peer-only contradiction therefore commits green on the origin and lands
malformed on the standby unless the peer-effective call runs. Deleting that call
left four packages green until #6820 added
`TestPeerOnlyNATTerminalActionRejectedAtOriginCommit_6820` (plus a
node1-perspective and a both-views-clean over-reject control) in
`compiler_peer_effective_nat_terminal_action_6820_test.go`.

Both rejection MESSAGES are content-bound by
`TestNATTerminalActionMessageContent_6820`, not just their firing. They are
operator-visible on both paths — verbatim at strict commit, wrapped into a
`cfg.Warnings` entry on the tolerant one — and the 2+-action text used to state
a mechanism the compiler had stopped using (a packed-key/child-order pick),
which no test could see. It now says what actually happens — and says it
PER KIND, because the two kinds do not share a mechanism (#6820 round 3). For
source NAT every authored action is published and the DATAPLANE resolves the
rule `off` > `interface` > `pool`. For destination NAT the COMPILER resolves
`off` itself: `buildDestinationNATSnapshots` short-circuits on `isOff`, never
looks the pool up, and publishes `PoolAddress: ""`, so "every action is
published" is false for a DNAT rule; the dataplane's `off` > `pool` branch then
covers any entry that arrives carrying both. Either way all but one authored
action is discarded, and *within that block* the survivor is decided by the
fixed precedence rather than by the order the actions were written.

Scope that to the block and no further (#7035). Across duplicate `then`
CONTAINERS configuration order DOES decide: `compileNATSource` /
`compileNATDestination` reset `rule.Then` at the top of every container, so the
LAST one supplies the fields that get counted — swap
`then { source-nat { off; pool P; } }` with
`then { source-nat { interface; pool P; } }` and the surviving action changes
from `interface` to `off` while the rejection text is identical. Both rows are
pinned by `TestNATTerminalActionContainerOrderPicksSurvivor_7035`.

And the gate counts RESOLVED FIELDS, not authored tokens, which bounds what it
can see (#7034). The packed branch of those compilers reads a single key
(`switch t.Keys[1]`), so a contradiction whose tokens sit on ONE node —
`then { source-nat off pool P; }`, `then { source-nat pool P off; }`,
`then { source-nat { pool P off; } }`, or the flat
`set … then source-nat pool P off` — lowers to a single field, counts as one
action. The same holds for `destination-nat`. That was the behaviour gap #7033,
and it is **closed**: those rows no longer commit. A separate check —
`natThenPackedContradictionModes`, reading the authored MODES recorded beside the
resolved `NATThen` — rejects them at strict commit, and the resolved-field
count's message now names that check instead of naming an open issue.
`TestNATTerminalActionPackedContradictionRejected_7034_7033` pins each spelling.

The fix is DETECTION, not accumulation in the lowering, and the distinction is
the reason it holds. Two rounds of #6820 tried to make the lowering read every
packed token and each was reverted for a regression in the ACCEPTING direction:
round 5 made `then { destination-nat interface pool PD; }` resolve as a pool
translation, round 6 fabricated an exemption out of
`then { source-nat { frobnicate { off; } } }`. Nothing about what a packed run
lowers to has changed — the flipped #7034 test asserts the same resolved values
it always did, now read off the lenient path.

Three properties bound the scan, each with its own cell in
`compiler_nat_then_packed_contradiction_7033_test.go`:

- **`pool` consumes exactly one value token**, so `pool off` stays a pool NAMED
  `off` rather than becoming a pool plus an exemption.
- **The scan stops at the first unrecognised token**, so #4313's open-world
  trailing grammar survives — including the adversarial case where the tail
  itself contains the word `off`, which is the smallest shape in which the stop
  rule changes an outcome.
- **The walk does not descend past an unrecognised container**, so round 6's
  `frobnicate { off; }` keeps its ZERO-action rejection instead of yielding an
  exemption nobody wrote.

A packed contradiction need not involve a pool. `then { source-nat interface
off; }` authors an exemption and publishes an interface translation, and it is
rejected on the same footing as the pool rows — the per-container record is
ranked by distinct MODES first and pool names second, so a container naming no
pool is still captured. Ranking on pool names alone made that whole class
invisible while every pool-bearing row was correctly rejected.

The check applies to the `n == 1` class only, so a block that lowers two actions
(or none) keeps the diagnostic it already had. Two sites enforce that and either
alone suffices — the call sits after the count's switch, and the predicate
independently refuses any rule whose resolved count is not one — which means only
a compound mutation can demonstrate the restriction is guarded.

*Same-mode repeats are a separate check (#7013).* A packed `off pool P` still
collapses to one field — #7033 rejects it on the authored modes rather than by
changing that. A block naming the SAME mode twice is no
longer invisible: `then destination-nat pool PD pool PD2` and
`then { destination-nat { pool PD; pool PD2; } }` are rejected at strict commit
by an occurrence check that runs BEFORE the mode count, reading a per-container
record of the authored pool NAMES (`natThenAuthored`, unexported on `NATRule`,
built by `natThenAuthoredOccurrences` at both lowering sites). Where the collapse
happens the FIRST authored pool is the one that takes effect, in both spellings.

Three neighbouring shapes stay legal, and the distinction is the whole of why
this does not disturb #3850 or #7035:

- **Duplicate `then` CONTAINERS** — last-container-wins, unchanged. The record is
  scoped to ONE container precisely so summing cannot false-reject them.
- **Two separate `set … then destination-nat pool X` lines** — NOT a collapse.
  The second REPLACES the leaf in the candidate tree, as a single-value leaf
  should, so only one pool ever reaches the compiler and `show configuration`
  displays what will be enforced. #7013's body described this as the same defect;
  it is ordinary leaf replacement at a different layer.
- **The same pool named twice in one block** — nothing is discarded, so it is a
  redundancy rather than an error.

Repeating `off` or `interface` is likewise a redundancy: they carry no value, so
`off off` means the same exemption twice and commits. **That is a statement about
a REPEAT, not about the mode.** `off pool P` packs two DIFFERENT modes onto one
run, one of them is discarded, and #7033 rejects it — the asymmetry is why the
authored record carries modes as well as pool names.
`compiler_nat_then_occurrences_7013_test.go` pins every row above, including the
three legal ones, and
`TestRepeatedValuelessModeIsARedundancyNotAContradiction_7033` pins both halves
of the asymmetry side by side.

*What the tolerant path actually does (#5717).* Only a malformed rule reaches
the lenient arm — the strict commit path rejects it — but the two arities land
there very differently, and the difference is load-bearing:

- **Contradictory (2+ actions) CONTAINING `off` resolves to the EXEMPTION.**
  Recording every field is what makes this safe: `off` takes precedence over
  `interface` / `pool`, so such a contradiction can never publish the INVERSE of
  the authored action. The two builders reach that outcome differently —
  source NAT forwards every field to Rust, destination NAT short-circuits on
  `isOff` in `pkg/dataplane/userspace/nat_destination.go` and publishes a
  pool-less exemption entry — but **the precedence itself is decided in Rust on
  both paths** (#6820): the `rule.off` early return in
  `userspace-dp/src/nat/source.rs` for SNAT, and the `off`-only branch of
  `DnatEntry::to_outcome` in `userspace-dp/src/nat/destination.rs` for DNAT.
  The Go short-circuit is CANONICALIZATION, not the decision: a snapshot
  carrying both `Off=true` and a usable pool — which Go never emits but a
  hand-built or mixed-version one can — still resolves to the exemption,
  measured by `dnat_off_exemption_is_decided_by_off_not_by_an_empty_pool_6820`
  (`userspace-dp/src/nat/tests_destination.rs`), whose control arm clears `off`
  on the same rule and gets the translation. Both halves are now pinned:
  `TestTolerantContradictory{SNAT,DNAT}*_5717`
  (`pkg/dataplane/userspace/nat_terminal_action_tolerant_5717_test.go`) and
  `off_wins_over_contradictory_{interface,pool}_action_5717`
  (`userspace-dp/src/nat/tests_source.rs`). The pre-existing
  `off_rule_short_circuits_translation` does NOT cover this — its rule sets
  `off` alone, so it stays green under a mutation that lets `interface` win.

- **Contradictory WITHOUT `off` gives INTERFACE MODE precedence.** Source NAT
  also admits `interface` + `pool`, which carries no `off` to take precedence.
  The Rust matcher checks `off` -> `interface_mode` -> `pool_mode` in that order
  (`nat/source.rs`), so interface mode wins and the authored pool is silently
  discarded. That produces interface translation when the egress interface has a
  suitable same-family address, and a fail-closed `Unavailable`
  (`InterfaceNoEgressAddress`) when it does not — the #5688 belt, which refuses
  to forward untranslated rather than leaking the private source. "A contradiction resolves to the exemption" is therefore true ONLY
  of the `off`-bearing case; stating it unqualified is the same
  untested-safety-claim defect this section documents. Both halves of this one
  are pinned, and they need separate fixtures: the translating half by
  `interface_wins_over_pool_without_off_5717`, the fail-closed half by
  `interface_with_pool_no_egress_fails_closed_5717`. The generic no-egress
  tests (`interface_source_nat_no_v{4,6}_egress_addr_fails_closed`) do not
  cover the second half — they use interface mode with NO pool, so a fallback
  from the belt into pool translation leaves them green. On the Go side
  `TestTolerantContradictorySNATWithoutOffCarriesBothActions_5717` pins that
  the builder publishes BOTH actions (and the tolerant-path warning), since a
  Rust test building its snapshot directly cannot see a Go edit that drops the
  pool. Note a claim quantified over
  "2+ actions" cannot be discharged by pairwise fixtures alone — the three-action
  `interface` + `off` + `pool` shape needs its own fixture, because two pairwise
  tests both survive a predicate that mishandles only the three-action case. It
  needs one on EACH SIDE of the language boundary, which is the correction #6820's
  re-gate made: `off_wins_over_all_three_actions_5717` pins the Rust resolution
  but HAND-BUILDS its `SourceNATRuleSnapshot`, so it never crosses Go
  publication, and the three Go sub-tests were all pairwise. That gap was
  measured, not inferred — publishing `Off: rule.Then.Off &&
  !(rule.Then.Interface && rule.Then.PoolName != "")` (correct on every pair,
  wrong only on the triple) kept the whole Go suite green while the operator's
  authored `off` published as `Off=false` and Rust translated on the
  `interface_mode` branch. The Go half is now pinned by the
  `hierarchical single-node interface+off+pool` sub-test of
  `TestTolerantContradictorySNATCarriesOff_5717`, which drives the triple through
  a real tolerant compile.

- **Zero actions is NOT inert.** It installs no translation, but the matched
  traffic FALLS THROUGH — and what it falls through TO depends on what follows
  it. If a later, broader rule matches, that rule translates it: the fail-open
  the gate's own zero-action rejection text describes. If NOTHING later matches,
  the matcher's loop simply ends and the packet leaves **untranslated**. Only
  the first is a fail-open: the packet is translated against the operator's
  intent. In the second the packet's disposition COINCIDES with the intended
  exemption, so nothing is observably wrong today — calling that a fail-open
  too conflates a live wrong disposition with a latent one. What is wrong there
  is the RULE, not the packet: it is non-terminal, so adding any later broader
  rule silently turns the same config into the first case. That is why the gate
  rejects it either way. An earlier revision of this bullet asserted only the
  first outcome ("and is translated by that"), which presumes a later rule
  exists (#6820 re-gate). Source NAT reaches the fall-through by emitting
  the actionless rule and letting the Rust matcher's `else` arm `continue`;
  destination NAT reaches it by skipping the rule in the builder. Whether to
  make such a rule TERMINAL instead was a migration-contract question, decided
  on #6823 — see "#6823 — an actionless NAT rule is NON-TERMINAL" below.
  `TestTolerantActionlessRuleIsNotInert_5717`,
  `actionless_rule_falls_through_to_later_broader_rule_5717`,
  `actionless_rule_with_no_later_rule_passes_untranslated_5717` and
  `actionless_dnat_entry_falls_through_6823` pin BOTH dispositions on BOTH
  kinds, so neither the "inert" framing nor the "always translated by a later
  rule" framing can silently return.

**#6823 — an actionless NAT rule is NON-TERMINAL (decided).** A NAT rule
admitted by the TOLERANT path carrying ZERO terminal actions does not stop rule
evaluation: matching traffic falls THROUGH to whatever rule follows. That is
now the stated contract rather than merely the observed behaviour, and changing
it is a deliberate migration decision, not a cleanup. Four options were on the
table — **A** non-terminal fall-through (chosen), **B** terminal (matched =>
exempt, evaluation stops), **C** refuse to install the rule at the builder,
**D** terminal and fail-CLOSED (drop the flow).

- **B is the only option that changes a packet's fate, and it changes it in the
  leaking direction.** Take the pinned fixture: an actionless rule matching
  `10.0.61.0/24` followed by a broad `10.0.0.0/8 interface` rule. Today
  `10.0.61.102` falls through and is translated to the egress address; under B
  it is exempt and **leaves on the WAN untranslated**. That is the same
  disposition #5688 went out of its way to eliminate a few lines above this very
  `continue`, in this very matcher ("forwarded the packet UNTRANSLATED — the
  private/internal source leaked onto the egress. Fail CLOSED instead"). The two
  error directions are not symmetric: when the operator meant "translate", A is
  correct and B leaks a private source silently, on upgrade; when the operator
  meant "exempt", B is correct and A breaks the intent in a way that is
  functional, visible and leaks nothing.
- **Only B needs the fleet count; A is correct at any count.** The rule survives
  only on a tolerant load — a config persisted before #5628 added the gate, one
  peer-synced from an older node, or a rollback target — and until #7643 that
  population was not merely unmeasured but MISREPRESENTED, because the `show`
  renderer displayed `Action: interface` for an actionless rule. A migration
  cost cannot be estimated from a view that could not show the shape.
- **Junos parity does not decide it.** Junos NAT matching IS terminal, but Junos
  requires `then`, so a committed Junos config cannot express this input at all.
  Parity argues for terminal MATCHING — which this matcher already does on every
  other arm — and says nothing about what an actionless ACTION should mean.
- **C is packet-identical to A and strictly weaker.** A rule that is not
  installed is not matched, so evaluation proceeds to the next rule, which is
  exactly what `continue` does; the same `else` arm already sets
  `*matched_counter = None`, so the rule is counter-invisible either way. C buys
  no packet behaviour and removes the information the dataplane would need to
  implement B later.
- **D is the option most faithful to #5688 and it is still wrong here.** It
  would blackhole flows a deployed node forwards today. #1960's no-brick
  doctrine governs the tolerant load path specifically: its job is to keep a
  node forwarding on a config it cannot refuse. Turning a malformed rule into a
  drop is the brick #1960 exists to prevent.
- **The #3043 security-policy precedent does not carry over.** An actionless
  POLICY defaults to `PolicyDeny` (`compiler_security_policy.go`) — actionless
  => fail-closed. That works because a policy's action space `{permit, deny}` is
  ORDERED by safety, so a safe default exists. A NAT rule's is
  `{translate, exempt}`, which is not ordered: exempting leaks the private
  source, translating overrides the operator's intent. With no safe default AT
  the rule, the safe move is not to decide at the rule at all — which is what
  falling through does.

**B is not foreclosed, and the reopening criterion is explicit.**
`xpf_nat_rules_lenient_terminal_action` (#7640, shipped in #7643) reading zero
across the fleet makes B's migration cost zero, at which point terminal matching
is the better parity answer. The information B needs is still on the wire — the
SNAT builder publishes the actionless rule, so the dataplane can be taught to
stop on it. Preserving that is precisely why C was rejected.

**No upgrade note and no first-hit log**, because A is the status quo: there is
no behaviour difference to announce or to log. The operator-facing surface for
the shape is the #7640 gauge plus the per-rule `show security nat
{source,destination} rule detail` annotation.

**The SNAT/DNAT builder asymmetry is deliberate, and aligning it would be a
regression.** Source NAT emits the actionless rule and lets Rust's `else` arm
`continue`; destination NAT skips it in `buildDestinationNATSnapshots`. Both
reach the same decided disposition, so the asymmetry costs no packet. Aligning
DNAT to SNAT — installing the entry — is NOT free: measured, `from_snapshots`
cannot parse the empty `pool_address`, so it drops the entry and records a #4718
reconcile parse error for every such rule on every reconcile, turning a
config-level malformation into a recurring wire-corruption diagnostic. Aligning
SNAT to DNAT is option C. What the asymmetry did owe was a BINDING on the DNAT
side: the Go builder's skip was pinned (`TestTolerantActionlessRuleIsNotInert_5717`
asserts ZERO published entries) but the resulting Rust behaviour was not, and
`DestinationNATRuleSnapshot` is the xpfd->helper wire form, so a hand-built
snapshot or a mixed-version pair delivers the shape anyway.
`actionless_dnat_entry_falls_through_6823` closes that: it discriminates
three-ways between today's fall-through, B landing by accident (`None`), and the
`snap.off` placeholder being widened to cover any pool-less entry — which reads
like a harmless generalization but installs the rule with a `0.0.0.0` pool, and
`DnatEntry::to_outcome` branches on `off` ALONE, so every matching flow is
translated into a blackhole. That single `if snap.off` token is the whole guard.

  The no-later-rule test asserts on `SourceNatLookup`, via
  `match_source_nat_result_for_tuple`, and NOT on the `Option`-returning
  `match_source_nat` wrapper (#6820 re-gate). The wrapper folds
  `NoMatch | Unavailable(_) => None`, so a `None` assertion cannot tell
  "forwarded untranslated" from "dropped" — precisely the distinction the test
  name makes. Production splits them oppositely: `NoMatch` becomes
  `Ok(NatDecision::default())` and the packet is forwarded, while `Unavailable`
  becomes `Err` and `poll_descriptor` records a source-NAT failure and recycles
  the descriptor — the packet is DROPPED. The wrapper is also reachable in a
  non-test build only through `match_source_nat_for_flow`, which carries
  `#[cfg_attr(not(test), allow(dead_code))]`; `match_source_nat_result_for_tuple`
  is the live entry point.

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

### #5195 — pkg/config secret-handling cohort (codex-177 A3-b2)

Two low-severity but security-relevant residuals in the config compiler: a
crypto-namespace collision that silently downgrades an IPsec proposal, and a
VRRP validator that echoes an auth secret into diagnostics. Both are AST
pre-walk gates with the standard strict-reject / lenient-warn (#1960) split.

- **F7 — reserved synthetic proposal-set name (`validateReservedIPsecProposalNamesAST`,
  `compiler_ipsec_proposalset.go`).** When a policy carries a predefined
  `proposal-set`, `expandIKEProposalSets` / `expandIPsecProposalSets` mint
  concrete proposals under synthetic `__proposal-set/<policy>/<set>/<index>`
  names and write them into the SAME name-keyed `IKEProposals` / `Proposals`
  maps that hold operator-authored proposals, AFTER those maps are built. The
  lexer permits `/ _ .` in bare identifiers, so an operator can author a
  proposal with that exact name — the unconditional map write then silently
  overwrites one with the other, installing a different (typically weaker)
  crypto proposal than configured (a silent downgrade). The `__proposal-set/`
  prefix (`reservedProposalSetNamePrefix`, the single source of truth shared
  with `syntheticProposalSetName`) is now RESERVED: an authored `security
  {ike|ipsec} proposal` whose name uses it hard-rejects at strict commit and
  warns on the tolerant load / peer-sync path. The two expand loops additionally
  keep an occupancy guard — they never overwrite a slot already taken — so a
  leniently-loaded squatter that an older binary accepted is preserved, not
  clobbered. The gate enumerates names with the SAME `namedInstances` helper
  `compileIKE` / `compileIPsec` use to key the maps, so it checks exactly the
  names that could collide. Tests:
  `compiler_ipsec_reserved_proposal_name_5195_test.go` (strict reject IKE + ESP,
  lenient no-downgrade with the authored crypto preserved, and a no-false-
  positive clean-expansion case; RED on revert of both the gate and the guard).

- **F10 — VRRP track validator secret echo (`validateVRRPTrackInterfaceAST`,
  `compiler_interfaces.go`).** The duplicate-`track-interface` shape check built
  its diagnostic node path from the FULL vrrp-group node `Keys`. In the
  Keys-packed spelling `vrrp-group 1 authentication-key <secret> track-interface
  X track-interface Y` the authentication-key VALUE rides on that same Keys run,
  so the strict error / lenient warning echoed the secret into logs + CLI. The
  path is now built from `vrrpGroupIDKeys(n)` (the value-free `vrrp-group <id>`
  identity) BEFORE any message — mirroring the identical guard the #4288 auth
  validator (`validateVRRPAuthenticationAST`) already applies. Same
  message-from-identity-only doctrine as the #4306 S-5 inert-knob advisories.
  Tests: `vrrp_track_secret_5195_test.go` (strict + lenient, RED on revert:
  the sentinel secret appears in the message).

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

**`then static-nat inet` (Junos NAT64) is rejected at strict commit (#5859).**
The Junos static-NAT NAT64 target `then static-nat inet` parses and the compiler
records `StaticNATRule.Then == "inet"`, but there is NO dataplane lowering of the
keyword: the userspace snapshot builder stores an IP address in the static_nat
table's `InternalIP` slot, so emitting the literal string `"inet"` made the Rust
`parse_nat_prefix` fail and the rule was SILENTLY SKIPPED — a strict-valid config
claimed NAT64 translation but installed nothing (an inert, security-relevant NAT
rule). Until the keyword is lowered into the native NAT64 IR (a larger design
change — match scope, source pool, routing-instance, counters, fragments,
reverse BIB, HA sync — tracked as a `/research`-scoped follow-up), the compiler
FAILS CLOSED: `validateStaticNATInetTargetStrict` hard-rejects the target at
strict commit / commit-check (naming the rule-set + rule and directing the
operator to the native `security nat nat64` rule-set); the tolerant load /
peer-sync path downgrades to a surfaced warning and `buildStaticNATSnapshots`
DROPS the rule so the unparseable `"inet"` sentinel never reaches the dataplane.
The supported IPv6→IPv4 path is the xpf-native `security nat nat64` rule-set
above (`buildNAT64Snapshots` from `cfg.Security.NAT.NAT64`), which is unaffected.
Tests: `static_nat_inet_failclosed_5859_test.go` (both `pkg/config` and
`pkg/dataplane/userspace`).

**A static-NAT rule has EXACTLY ONE translation target (#6483).** A Junos
`then static-nat` maps to exactly one of `prefix <ip>` | `prefix-name <name>`
(#4290) | `nptv6-prefix <p6>` | `inet` (#5859). Authoring two or more — both a
`prefix` and a `prefix-name`, an `inet` sibling alongside a `prefix` sibling, two
`prefix` targets — is invalid Junos, but the compiler silently accepted it: the
`compileNATStatic` child loop honors the FIRST target it matches by a fixed
priority (`nptv6-prefix` > `prefix-name` > `prefix` > `inet`) and drops the rest,
and because `prefix` / `inet` / `nptv6-prefix` all land in the shared `Then`
field a later target simply overwrites an earlier one. The rule compiled to one
arbitrary target with no operator feedback — `inet` + `prefix` even installed as
a plain prefix rule, EVADING the #5859 `inet` reject. Dropping a target this way
also dropped any `mapped-port` that rode ONLY on the discarded target (the #6479
/ C179-038 residual), because that target's node was never the one whose modifier
the mapped-port fold read. `validateStaticNATSingleTargetStrict` now counts the
DISTINCT translation targets a rule declares — from the AST during compile
(`staticNATThenTargetCount`, recorded as `StaticNATRule.ThenTargetCount`), BEFORE
the fields collapse — and hard-rejects a rule declaring more than one. The count
is a GRAMMAR-ROLE-AWARE FULL TRAVERSAL (#6484), the SAME slot-classification walk
the #6479 mapped-port scan uses (`staticNATCollectTargetIdentsFromKeys` mirrors
`staticNATMappedPortOperandsFromKeys`): it walks the ENTIRE key stream of the
`static-nat` node AND every child, plus the grandchild values of a bare keyword,
classifying each position as a KEYWORD slot or a consumed VALUE slot. Reading only
the FIRST `(keyword, value)` pair per node — the pre-#6484 `Keys[1]`/`Keys[2]` /
`Children[0]` read — undercounted a rule whose two targets COLLAPSE onto one
node/child and let it escape: the free-form `static-nat` leaf packs a one-line
`prefix <ip> prefix-name POOL` / `prefix <ip> inet` / `prefix <ip> prefix <ip2>`
onto a SINGLE child's Keys, and a hierarchical `prefix { <ip>; <ip2>; }` carries
two prefix values as grandchildren of ONE `prefix` keyword — all counted 1 and
ACCEPTED on master (the #6484 MAJOR). The full traversal registers every distinct
`(keyword, value)` identity across the whole leaf, so these now count 2 and
reject. A **lexer-collapsed bracketed list** `prefix [ X Y ]` / `prefix-name
[ A B ]` / `nptv6-prefix [ P6a P6b ]` (#2419 strips the brackets onto one leaf's
Keys — `["prefix","X","Y"]`) is the same escape in packed form: the round-2
counter registers EVERY packed value after a target keyword as a distinct target,
not just the first, so a two-value bracketed list rejects (the round-1 walk
consumed only the first value and let the rest fall through — a residual #6484
escape). Two role subtleties make the walk correct: (1) a `prefix-name` value is
an OPAQUE address-book name that is ALWAYS its value — so `prefix-name mapped-port`
(a pool literally NAMED "mapped-port") registers a genuine target, not a modifier
carrier (the pre-#6484 counter wrongly pre-filtered a value equal to a modifier
keyword and DISCARDED that target). For a packed prefix-name the FIRST token is
always consumed as the name; only a FOLLOWING keyword lexeme ends the packed-name
run. (2) a `prefix` / `nptv6-prefix` value is an IP that can never be a modifier
keyword, so a FOLLOWING `mapped-port` / `routing-instance` IS a modifier carrier
(the canonical separate-set-line `prefix mapped-port <port>` form) and registers
no second target. The grandchild walk applies the SAME slot classification: for a
bare hierarchical `prefix-name { POOL; mapped-port 8080; }` the FIRST grandchild
is the opaque name (`POOL`) and a LATER modifier grandchild (`mapped-port` /
`routing-instance`) is skipped — so the rule counts ONE target, not two. The
round-1 grandchild walk registered EVERY grandchild of a name-valued bare keyword
as a target, counting `POOL` and `mapped-port` as two and FALSE-REJECTING a valid
single-target rule that origin/master accepted (the round-2 second finding).
Counting DISTINCT identities (not occurrences) keeps the canonical "restate the
target to attach a mapped-port" form — `then static-nat prefix-name N` + `then
static-nat prefix-name N mapped-port 8080` — a single target (both restatements
share identity `prefix-name\x00N`). Rejecting the multi-target rule
outright is the Junos-faithful closure and FORECLOSES the #6479 dropped-target
mapped-port residual as a side effect (the rule never compiles, so no
dropped-target modifier can slip). The gate runs in `runTailGates` AFTER the
host-mask (#2173) and NPTv6 (#2240/#5818) gates, so a rule that ALSO carries a
malformed `mapped-port` or a bad nptv6 prefix reports that concrete token first
(the multi-target defect is still caught on the next compile once the token is
fixed — never masked). Strict on commit / commit-check (hard reject); the
tolerant load / peer-sync path downgrades to a warning (#1960 no-brick) — the
compiler still lowers the single honored target, so a leniently-loaded config is
no worse than before the gate. A well-formed single-target rule (any of the four,
in any authoring shape, with or without a `mapped-port` / `routing-instance`
modifier) is unaffected. Tests: `static_nat_multitarget_6483_test.go`.

**The systematic per-subtree closure continues (#4313).** Each of the flips
above (destination-NAT then, the three IPsec option containers, master-password,
the Phase-1 IKE proposal, now the Phase-2 IPsec proposal and the two
xpf-native NAT64 stanzas) closes one leaf-complete high-risk subtree; the
blanket-default flip stays deferred (it would break the deliberately-lenient
accept-with-advisory knobs #2078/#4231 and false-reject valid-but-unmodeled
Junos, the #4191 class). Both the remaining per-subtree flips and the
blanket-flip doctrine decision remain tracked on #4313.

**Remaining per-subtree flips (future PRs, tracked on #4313).** Turning
`closedWorld` on for the other umbrella candidates (`snmp community` — INCOMPLETE,
and MORE incomplete than this note used to say. A #4313 attempt to close it was
reverted in PR #6887 after the gate measured four defects; treat these as the
entry criteria for any future attempt:
  1. `routing-instance` is a CONTAINER in Junos, not a scalar — it nests a
     `clients { … }` block. Modeling it as a bare leaf and closing the subtree
     hard-rejects `snmp community <c> routing-instance <ri> clients <prefix>`,
     which is valid config. Measured: an SNMP-scoped-to-a-VRF node could not
     commit ANY change, including an emergency one, until the operator deleted
     valid Junos.
  2. `logical-system` is a SIXTH child this note omits —
     `[edit snmp community <c> logical-system <ls>] routing-instance <ri>`.
  3. There are TWO ingestion surfaces. The compiler reads snmp from
     `compiler_dispatch.go` (top-level `snmp {}`) AND from `compiler_system.go`
     via `FindChild("snmp")` (`system { snmp {} }`), but `setSchema` anchors
     `snmp` only at the top level. Measured: the same typo is rejected under
     `snmp {}` and silently accepted under `system { snmp {} }` — and
     `test/incus/xpf-test.conf` uses the accepted spelling. Closing one surface
     leaves #4289 live on the one our own reference config uses.
  4. `client-list-name` and `routing-instance` produce NO inert-knob advisory
     (only `view` does). Modeling them without one makes the CLI advertise a
     source-IP restriction the firewall accepts, applies nothing for, and warns
     nobody about.
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
- a flag that is both required and forbidden (the term could never match);
- an operator-only / empty-operand / dangling-`&` or dangling-`!` expression
  that sets no flag bits (`"&"`, `"()"`, `"syn &"`, `"syn & !"`) — it would
  otherwise match every TCP segment (#4714/#5455, fail-open);
- an unbalanced or reversed parenthesis (`"(syn"`, `"syn)"`, `"syn)("`) — the
  grouping parens are redundant, so before C180-024 they were stripped
  unconditionally and a malformed value committed as if they were absent.
  Balanced groups, including nested ones (`"((syn & !ack))"`), stay accepted;
- a misordered group — an operand directly juxtaposed against another operand
  with no `&` between them. Both directions are now rejected symmetrically: a
  closed group followed by an operand (`"(syn)ack"`, `"(syn)(ack)"`,
  `"(syn)!ack"`) **and** the mirror, a flag followed by a `(` group
  (`"syn(ack)"`, `"ack(syn)"`, `"syn (ack)"`, `"syn(&ack)"`). A group is an
  operand, so it must be joined to a preceding flag with `&` (`"syn & (ack)"`).
  Before the mirror guard the flag-then-group forms parsed as a plain
  conjunction and committed; `"syn(&ack)"` additionally leaked the outer flag's
  presence into the inner group and let its leading `&` pass. A group that
  itself leads with `&`/`)` (`"(&ack)"`, `"(&)"`, `"((&syn))"`) stays rejected
  by the empty-left-operand checks.

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

The #3205 kept-verbatim channel had a residual fail-open (#6459/#6463): on the
tolerant path the Rust filter compiler dropped an unresolvable port token (or
a malformed literal address token) PER-TOKEN, so a PARTIALLY-bad list still
built a matcher over the surviving subset — a `then discard`/`reject` term
silently enforced a NARROWER set than the operator wrote (the rest fell
through to the implicit accept). The all-unresolvable case already failed
closed at match-time (#2400/#3205); the partial case now carries fail-closed
wire markers, same shape as the #3406 ICMP/DSCP family: the snapshot builder
sets `ports_unrepresentable` from `UnknownPorts` and
`address_unrepresentable` from `UnknownAddresses` (recorded by
`recordFilterAddrTokens` via the shared `classifyFilterAddrFamily`), and the
Rust `parse_term` rejects the WHOLE snapshot
(`SnapshotIntegrityError::UnrepresentableFilterPorts` /
`UnrepresentableFilterAddress`). The strict gates
(`validateFilterMatchValuesStrict`, `validateFilterAddressLiteralsStrict`)
remain the primary defense; the markers guard the lenient / peer-synced /
hand-built / version-drifted snapshot. Sibling parser alignment (#6477): the
Rust filter-side `parse_port_spec` now routes through the shared digit-only
`parse_port_u16` (#3606), so all four port parsers (Go commit gate, Go
capability gate, policy-side Rust, filter-side Rust) reject the same
non-canonical tokens (e.g. `+80`). Fail-on-revert:
`TestFilterSnapshot*Unrepresentable*` /
`TestFilterSnapshotLenientPartial{Port,Address}List*` (Go,
`pkg/dataplane/userspace/filters_snapshot_integrity_6459_test.go`),
`TestFilterMalformedAddressRecorded_6463` (Go,
`pkg/config/firewall_address_unknown_6463_test.go`), and
`ports_unrepresentable_marker_*` / `address_unrepresentable_marker_*` /
`filter_parse_port_spec_rejects_signed_6477` (Rust).

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
`match destination-port`), `validateDNATPoolStrict` (destination-NAT pool
`port`), and — since #5457 — `parseSourcePoolPortRange` (source-NAT pool `port
[range]`). The Rust `parse_port_spec` was tightened in lock-step
(`parse_port_u16` rejects the sign) so all three parsers agree. Fail-on-revert:
`TestSignedPortRejectedAtCommit_3606` / `TestParseCanonicalPort_3606`
(`pkg/config/compiler_signed_port_3606_test.go`) and
`parse_port_spec_rejects_signed_3606` (`userspace-dp/src/policy_tests.rs`).

**Source-NAT pool `port [range]` fail-closed (#5457).** Before #5457 the
source-pool port endpoints were parsed with `strconv.Atoi` and returned
`ok=true` with no value-range or order check, so `port range low -1 high 99999`
became `(-1, 99999)` and `low 5000 high 100` became the inverted `(5000, 100)`.
A non-zero out-of-range/reversed value was still caught downstream (the strict
gate `validateSourceNATPoolStrict` and the snapshot builder both read the
STAMPED value), but a `0`-valued endpoint slipped through the parser as the
"unconfigured" sentinel and silently widened to the default `1024-65535` PAT
range. `parseSourcePoolPortRange` now validates each endpoint via
`ParseCanonicalUint` + `1..65535` + non-decreasing order and FAILS CLOSED
(`ok=false`) on any violation, so the bad value is never stamped into
`PortLow`/`PortHigh`. The "configured-but-invalid" fact is preserved in
`NATPool.PortRangeInvalidSpec`, which `validateSourceNATPoolStrict` hard-rejects
at commit (downgraded to a warning on the tolerant load / peer-sync path) and
which the snapshot builder (`sourceNATPoolPortRange`) reads to mark the pool
UNUSABLE — the leniently-loaded bad range installs nothing rather than
PAT-translating over a range the operator did not configure. Fail-on-revert:
`TestParseSourcePoolPortRange_5457` / `TestSourceNATPoolPortRangeFailClosed_5457`
(`pkg/config/compiler_nat_source_pool_port_5457_test.go`) and
`TestSourceNATSnapshotInvalidPortRangeUnusable_5457`
(`pkg/dataplane/userspace/nat_source_pool_port_5457_test.go`).

**Source-NAT pool `port range` has a FIXED arity, and `port range` is not a
value list (#6688).** `#5457` validated the endpoints the grammar consumed; it
did not bound how many tokens the grammar consumed. `parseSourcePoolPortRange`
matched `low <lo> high <hi>` at `len(toks) >= 4` and `<low> to <high>` at
`len(toks) >= 3`, discarding the remainder — so `port range 1000 2000` parsed as
the bare single-port shape `<low>` and compiled `PortLow == PortHigh == 1000`. A
pool the operator sized at 1001 ports provided ONE, committed clean, and
exhausted under the first real translation load; the second slot was never
parsed, so `port range [ 1000 99999 ]` and `port range [ 1000 notaport ]`
committed clean as well.

The lexer strips `[`/`]` before the compiler observes anything (see "Multi-value
leaves and bracketed lists"), so the bracketed spelling and the mistyped bare
spelling arrive as the SAME token slice. Reading `["1000","2000"]` as
`[1000,2000]` was therefore rejected as the fix: it would invent a two-token
`range <low> <high>` grammar Junos does not have AND silently redefine the
mistyped bare form. Both shapes now match at an EXACT arity and any unconsumed
token fails closed through the existing `PortRangeInvalidSpec` channel — strict
commit hard-rejects naming the offending spec, the tolerant path marks the pool
unusable. Fail-on-revert:
`TestParseSourcePoolPortRangeUnconsumedTail_6688` /
`TestSourceNATPoolPortRangeTailFailsClosed_6688` /
`TestSourceNATPoolPortRangeValidUnaffected_6688` (the over-reject control)
(`pkg/config/compiler_nat_source_pool_port_6688_test.go`).

This also retired the `security nat source pool <*> port range` row from
`knownSpellingInconsistencies` (the #2419 spelling-differential gate): with the
tail rejected rather than discarded, every compared spelling of a two-token tail
now reaches the same verdict. The site is still ENUMERATED and COMPARED by the
gate (4 of 5 spellings carry a verdict) — it was not moved to `notAValueList`,
because the agreement is now a real property of the compiler rather than a
meaningless verdict.

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

### The as-path REGEX is the whole token tail, and it is validated (#6686)

`policy-options as-path <name> <regex>` is a `args: 2, multi: true` schema node
(`schema_routing.go`), so the definition's regular expression is the node's
whole trailing token run — not one key. The two spellings of one value land
differently:

| authored | Keys |
|---|---|
| `as-path AP1 ".* 65000 .*"` | `["as-path" "AP1" ".* 65000 .*"]` (one lexer string token) |
| `as-path AP1 .* 65000 .*` | `["as-path" "AP1" ".*" "65000" ".*"]` |

Reading `Keys[2]` alone kept the FIRST token of the unquoted spelling, compiling
`.* 65000 .*` down to `.*` — the whole-path wildcard. A `from as-path AP1; then
accept` term built on that definition accepts **every** BGP path instead of only
those transiting AS 65000: a route-leak / hijack-acceptance exposure that
committed clean with zero warnings, in BOTH the flat-`set` and hierarchical
spellings, while `show configuration` displayed the authored regex back
verbatim. The same widening applied one level down, to a hierarchical brace body
(`as-path AP1 { .* 65000 .*; }`), whose regex tokens land on a CHILD leaf's
`Keys` and were read as `entry.Keys[0]`.

`ASPathRegexFromTokens` (`aspath_regex.go`) rejoins the tail with single spaces
at both sites. That is reconstruction, not a guess: every regex metacharacter
that is also lexer syntax (`^`, `{`, `}`, `|`, `[`, `]`, `;`, `"`) either fails
to lex unquoted or is stripped, so an unquoted regex reaching the compiler is a
whitespace-separated run of identifier tokens. FRR's `bgp as-path access-list`
DEFUN ends in a variadic `LINE...` that `argv_concat` rejoins with single
spaces, which is what makes a multi-AS pattern expressible at all — so the join
matches what FRR itself does with the rendered line.

**The regex is validated, at three layers with one predicate.** `ValidASPathRegex`
(`aspath_regex.go`) rejects an EMPTY regex — reachable with no diagnostic at all
via `set policy-options as-path AP1` with no value — and one that is not a valid
POSIX ERE. Either renders a line frr-reload rejects (an incomplete command, or a
regcomp failure), and a single `CMD_WARNING_CONFIG_FAILED` exits the whole vtysh
add-batch non-zero, failing the ENTIRE reload and leaving every dynamic routing
change stale. `validatePolicyASPathRegexStrict` hard-rejects on commit /
commit-check; the tolerant load / peer-sync paths downgrade to a warning
(`lenientPolicyASPathRegex`, the #1960 no-brick class); and `generatePolicyOptions`
(`pkg/frr/policy_render.go`) OMITS an unrenderable definition so the leniently
loaded config cannot poison the reload — FRR resolves a `match as-path <name>`
with no such list to NO MATCH, confining the damage to the referencing terms.
The three layers share `ValidASPathRegex` so they cannot drift.

Fail-on-revert covered by `pkg/config/compiler_as_path_multitoken_6686_test.go`
(five spellings asserted to AGREE and to equal the authored regex, the empty and
malformed strict/lenient legs, and a tightening control that commits nine real
AS-path regexes clean) and `pkg/frr/policy_aspath_regex_6686_test.go` (the
multi-token regex renders whole; the unrenderable ones are omitted).

### Repeated policy-statement blocks MERGE, not last-win (#5824)

A single `policy-options policy-statement <name>` may be authored across MULTIPLE
separate hierarchical blocks (two `policy-statement P { ... }` braces), repeated
`policy-options` roots, or group-expanded fragments — each is a distinct AST
instance. `compilePolicyOptions` (`compiler_routing.go`) used to build a FRESH
`PolicyStatement` per instance and do an unconditional
`po.PolicyStatements[name] = ps`, so a second same-name block silently REPLACED
the first — its terms, route-filters, actions, and default action vanished. Flat
`set policy-options policy-statement P term ...` lines COMPOSE under one node via
`SetPath`, so the hierarchical and flat spellings of the same policy diverged.
Routing policy is ORDERED security/route-control state: a lost reject term
over-exports/over-imports and a lost accept term withdraws reachability, while
FRR receives a valid-but-incomplete route-map and commit + daemon apply both
look successful.

The policy-statement loop now mirrors the sibling `prefix-list` (#2641) and
`community` (#2587) merge loops above: it REUSES the existing map entry AND a
per-policy term index that persists ACROSS instances, so later blocks MERGE into
the earlier one — new terms append in first-authored ORDER, and a repeated
fragment of the SAME term composes onto the existing `PolicyTerm` (from-match /
route-filters / then-action all accumulate via `parsePolicyTermChildren`). The
policy-level default `then` composes as flat-set does (last-non-empty wins), so
the two spellings compile to an identical `PolicyStatement`. Fail-on-revert
covered by `pkg/config/compiler_policy_block_merge_5824_test.go` (two-block
merge, hierarchical==flat parity, same-term-across-blocks compose, single-block
unchanged) and the end-to-end render guard
`pkg/frr/policy_block_merge_5824_test.go` (the early reject term's `deny`
sequence + route-filter survive into the FRR route-map).

### Repeated scheduler blocks MERGE, not last-win (#5825)

The SAME block-merge rule applies to `schedulers scheduler <name>`. A scheduler
may be authored across multiple hierarchical blocks (two `scheduler S { ... }`
braces) or repeated top-level `schedulers { ... }` roots, each a distinct AST
instance. `compileSchedulers` (`compiler_system.go`) used to allocate a FRESH
`SchedulerConfig` per instance and do an unconditional `cfg.Schedulers[name] =
sched`, so a later same-name block REPLACED the first — every day/window authored
earlier vanished. Flat `set schedulers scheduler S <day> ...` lines compose under
one path, so the hierarchical and flat spellings diverged, and a security policy
time-gated by the scheduler became active/inactive on the WRONG days with a clean
commit.

The loop now REUSES the existing map entry, so distinct weekday windows UNION
across blocks/roots (the `Days` map lives on the reused struct — no separate index
is needed, unlike the policy-statement term index, because per-day dedup is the
map key). The daily/date scalars (`start-time`/`stop-time`/`start-date`/
`stop-date`, the `daily` window, `all-day`) follow flat-set / Junos load-merge
LAST-WINS: a repeated leaf replaces, exactly as a second `set` of the same leaf
does, so no order-dependent divergence from flat is introduced (a "conflict" is
not representable in flat-set — the last `set` simply wins). Fail-on-revert
covered by `pkg/config/compiler_scheduler_block_merge_5825_test.go` (two-block day
merge, hierarchical==flat parity, across-roots merge, daily+weekday compose,
single-block unchanged).

### Quoted-value escape round-trip contract (#3854)

When a key or value is not safe to emit bare (see the next section for the
predicate — historically "contains a byte outside `isIdentChar`"),
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

### What may be emitted BARE — the re-lex predicate (#6523)

`quoteKey` decides bare-vs-quoted through `bareKeySafe` (`ast.go`). The rule is
**not** "every byte is an `isIdentChar`". `isIdentChar` is the LEXER'S ident set
— it admits `/`, `*` and `:` — and is not the set of texts that survive a
serialize/re-parse cycle. Three ident-char-only **classes** are re-interpreted
**structurally** on the way back in. Two of them are entirely silent — zero
parse errors, zero warnings. The unterminated block comment is the exception:
it returns a `TokenError`, so it corrupts loudly, which makes it the least
dangerous of the three (the table's last row states this):

| Value | What the re-read does |
|---|---|
| `//…` | `skipWhitespaceAndComments` consumes to end-of-line. The key **and every key after it on that line** silently vanish. |
| `/*…*/` | Terminated block comment — swallowed silently. |
| `/*…` | Unterminated block comment — swallows the rest of the config; `Parse` errors. |
| `inactive:` | The parser's deactivation marker. **Leading**, it sets `Node.Inactive` on an unrelated statement; **inline**, it TRUNCATES the key list at that point. |

Every path that serializes then re-parses is affected — HA config sync,
rollback, archive, rescue — i.e. the paths an operator leans on when something
has already gone wrong. Demonstrated end states on the receiving side: a
`security-zone` that compiles with **zero interfaces**, a `permit junos-http`
widened to **`permit any any any`**, and an IKE pre-shared-key that becomes the
literal string `ascii-text` (the `//…` / `inactive:` forms eat the value and
leave the preceding `ascii-text` key as the trailing one). Reachable from the
plain `set` CLI (`set … description inactive:`), not only hierarchical ingest.
Both serializers are affected: hierarchical `Format` (via `QuotedKeyPath`) and
`| display set` (via `joinQuotedKeys`), the latter replayed through
`ParseSetVerb`, which drives the same lexer.

`bareKeySafe` therefore asks the **real lexer** instead of a hand-maintained
character table:

1. every byte is an `isIdentChar` (retained as a NECESSARY pre-condition, so the
   change is monotone — output only ever gains quotes, never loses them; without
   it a bracketed endpoint `[2001:db8::1]:51820` would newly go bare, since
   `tryBracketedEndpointLiteral` (#5182) hands it back as one identifier equal to
   itself);
2. the bare text re-lexes as **exactly one `TokenIdentifier` whose value is the
   text itself**, followed by `TokenEOF`;
3. it is not a parser-level marker — enumerated in `parserMarkers`
   (`parser.go`), today just `inactive:`.

Because step 2 defers to the code that will actually read the config back, a
comment syntax or lexer special case added later is covered the day it lands
rather than the day someone remembers to update a denylist.

**Step 3 is the half that cannot be derived**, and it is the one to be careful
with. A parser marker is invisible to the lexer — `inactive:` comes back as an
ordinary identifier — so the predicate has to be told. `parserMarkers` carries
that contract: **teaching `parseStatement` to treat a new bare identifier
structurally requires adding it to `parserMarkers`**, or the serializer emits
that text unquoted and the next `Format`→`Parse` reads it back as structure.
Each marker's semantics stay in `parseStatement`; `parserMarkers` records only
which texts are load-bearing, since a future merge directive would not share
`inactive:`'s deactivation behaviour.

Quoting is also what makes the parser's existing marker defence work: a quoted
`"inactive:"` arrives as a `TokenString`, and `parseStatement` already refuses
to treat a string token as a marker (#4348).

**Do not widen this predicate for speed.** `bareKeySafe` is allocation-free
(the `Lexer` does not escape), pinned by
`TestQuoteKeyBareEmissionIsZeroAlloc6523`.

Pinned by `pkg/config/quotekey_relex_6523_test.go`. The **binders** (each fails
with an assertion if the predicate is reverted) are
`TestQuoteKeyStructuralHazards6523` (each hazard in leading/inline/trailing key
position — the primary one), `TestQuoteKeyHazardsAreQuoted6523`,
`TestQuoteKeySetFormHazards6523` (the `| display set` path — comment forms
only; see below), `TestQuoteKeyZoneInterfaceHazard6523` (the zero-interface
zone end state), `TestBareKeySafeAgreesWithLexer6523` (lexer-level only — see
below), and `TestQuoteKeyRelexProperty6523`, a brute-force sweep over the
lexer's own ident alphabet that re-derives the hazard set instead of trusting a
fixed list. Its coverage is **every** 1- and 2-byte text over the full 74-byte
alphabet, every 2-byte prefix followed by each of four tails, every 3-byte text
over a 14-byte punctuation subset plus embedded/trailing punctuation pairs, and
every registered `parserMarkers` entry — each in three key positions, ~91.8k
round-trips. There is no exhaustive 3-byte sweep over the full alphabet.

Two **guards** are green under revert by design and must stay that way:
`TestQuoteKeyNoOverReach6523` asserts ordinary values (`10.0.0.0/24`,
`ge-0/0/0`, `<*>`, `ascii-text`, `00:11:22:33:44:55`, `junos-ssh`, `00:00:00`,
`1024-65535`, and the near-misses `a//b`, `a/*b`, `*/`, `/x`, `inactive`,
`inactive:x`) still emit **unquoted** — `/` is legitimate and common, so a
predicate that rejected any value containing `/` would be wrong and would churn
every archived config and HA config-sync diff — and
`TestQuoteKeyBareEmissionIsZeroAlloc6523` is a performance guard (it also fails
under `-gcflags=all=-l`, which disables the escape analysis the zero depends
on; the default build and `-race` both report 0).

`TestParserMarkerVocabulary6523` gates the `parserMarkers` contract over the
realistic vocabulary of word-shaped markers (`replace:`, `protect:`,
`delete:`, …): each candidate must either be registered and quoted, or still
round-trip as an ordinary key. A parser change that promotes one of those words
without registering it fails the second leg. This is the anti-rot device for
step 3, and its scope is that enumerated vocabulary — the alphabet sweep cannot
cover it, because its candidates are short and punctuation-shaped, not words.

Two scope caveats worth knowing before trusting a green run. The set-form
`inactive:` case in `TestQuoteKeySetFormHazards6523` is a **consistency** case,
not a binder: `ParseSetVerb` reads a structural verb from the first token only,
so a later `inactive:` is appended to the path literally and even unquoted
output round-trips in set form. Only the comment forms bite there. And
`TestBareKeySafeAgreesWithLexer6523` asserts a **lexer-level** property, so its
`inactive:` case is likewise green under revert — the marker bites one layer
up, at the parser, where `TestQuoteKeyStructuralHazards6523` covers it.

### `firewall ... from flexible-match-range` — at most ONE range per term (#5823)

A firewall-filter term may name **at most one** `flexible-match-range range`.
The userspace matcher (`flex_matches`, `userspace-dp/src/filter/engine/
matching.rs`) evaluates a single byte-offset window per term; multi-range is a
Junos-parity gap deliberately left unimplemented (defining the wire encoding +
hot-path cost is a separate item).

The pre-#5823 compiler (`compileFilterFrom`, `pkg/config/compiler_firewall.go`)
iterated every named range but `break`ed after the first — silently keeping
range #1 and dropping the rest. That is a **security fail-open**: an `accept`
term stopped requiring the dropped ranges' condition (over-permit), and a
`discard`/`reject` term stopped dropping the traffic they scoped (over-drop),
with a clean commit.

`compileFilterFrom` now aggregates EVERY named range across ALL repeated
`flexible-match-range` blocks, both AST shapes (hierarchical + flat-set),
duplicate names, and `from` group-expanded copies into
`FirewallFilterTerm.FlexMatchRangeNames` (it still compiles only the first into
`FlexMatch`, so a single-range term is byte-identical). This follows the
#3203/#3205/#5832/#5833 strict/lenient discipline:

- **Strict commit / commit-check** (`CompileConfig`): `validateFilterFlexMatchStrict`
  (`compiler_validate_strict_filter.go`) hard-REJECTS `len(FlexMatchRangeNames) > 1`
  BEFORE the dataplane apply, naming the family/filter/term and every range.
- **Lenient load / peer-sync** (`CompileConfigLenient`, #1960 no-brick): the
  strict error is downgraded to an operator-visible `cfg.Warnings` entry, and the
  userspace snapshot builder (`buildFilterTermSnapshots`, `pkg/dataplane/
  userspace/filters.go`) POISONS the term to match NOTHING — it emits a
  `FlexMatchSnapshot` with the sentinel match-start `unrepresentable-multi-range`
  (any non-`layer-3`/`layer-4` start lowers to `FlexMatchStart::Unsupported`,
  whose `flex_matches()` returns `false`), plus a `slog.Warn`. This reuses the
  existing per-term fail-closed channel — **no** multi-range support is added to
  the wire/matcher. Silently enforcing only the first range (the pre-fix
  behavior) would be fail-open.

Pinned by `pkg/config/compiler_flexmatch_cardinality_5823_test.go` (strict
reject for accept + discard terms; flat-set + group-expansion aggregation;
lenient mark + warning; single-range unchanged) and
`pkg/dataplane/userspace/filters_flex_multirange_5823_test.go` (wire poison +
single-range byte-identical). Removing the aggregation, the strict gate, or the
wire poison arm turns the matching test RED.

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

The two `route-filter` slots are validated **positionally** (#5576) via a
`keyValidatorPos` (the position-aware sibling of `keyValidator`, see "Typed
KEY slots" below): arg 0 (the prefix slot) must parse as a CIDR and arg 1
(the match-type slot) must be one of `exact`/`longer`/`orlonger`/`upto`/
`prefix-length-range`/`through`. Before #5576 the key validator was
position-AGNOSTIC — it accepted the UNION of CIDRs and match-type keywords in
EITHER slot, so `route-filter longer exact` committed with the keyword
`longer` in the CIDR slot. The FRR renderer's malformed-prefix belt
(`net.ParseCIDR("longer")` fails → `renderRouteFilterEntry` emits no
prefix-list line) then produced an EMPTY prefix-list while the route-map
retained its `match ip address prefix-list` reference — a **match-none**
policy that silently dropped every route the term was authored to accept (a
false-deny). Proven by `TestSchemaValidate_RouteFilter_PositionAware`
(`schema_validate_route_filter_test.go`) and
`TestRouteFilterMatchNoneFalseDeny_5576` (`pkg/frr`).

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

**Bounding a deep acyclic chain (depth + work budget, #5194 A3-b2-F1).** The
`seen` guard bounds only CYCLES and the memo only collapses a converging DAG;
neither bounds a shallow-syntax ACYCLIC chain of DISTINCT groups
(`g1 -> g2 -> ... -> gN`). That chain recurses one `expandGroupsRecursive` frame
per link via the pre-merge nested expansion, so a generated/pathological deep
chain could exhaust the goroutine stack on commit or HA config-sync. Two limits
now thread through the recursion: a `depth` counter (incremented ONLY on the
nested-group recursion, NOT the config-tree descent — tree depth is already
bounded by the parser brace-depth cap #4148) rejected past `maxGroupExpandDepth`
(64), and a shared `groupExpandBudget.work` counter rejected past
`maxGroupExpandWork` (100000) to catch a wide shallow fan-out that stays under
the depth cap. Both fail cleanly with an error rather than crashing; the caps sit
far above any legitimate Junos nesting. Covered by
`pkg/config/apply_groups_depth_5194_test.go` (deep chain rejected, shallow chain
still expands and inherits the deepest leaf).

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
  placeholder + examples at the empty identity slot. For a **multi-arg key
  slot whose positions carry DISTINCT grammars** (`route-filter <prefix>
  <match-type>`, args:2), set `keyValidatorPos` (the position-aware sibling of
  `keyValidator`) instead: the walker passes each token's 0-based arg index
  so slot 0 and slot 1 can be validated with different rules, closing the
  #5576 "keyword accepted in the CIDR slot → match-none false-deny" hole. A
  node sets EITHER `keyValidator` OR `keyValidatorPos`; both are honored in
  the packed-Keys path AND the peeled nested-name path (`validateKeySlot`).
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
  compilation never drift. Percent resolves per-interface (#4228 Gap 2) and
  remainder resolves against the leftover after resolved siblings (#6846);
  each keeps a narrowed advisory for the case that still cannot resolve (see
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
  change the identity-token typing decision above; #5694 further adds
  `validateChassisClusterIdentitiesAST` — an AST PRE-WALK gate in
  `runPreWalkGates` (`compiler_chassis_identity.go`) that rejects a
  MALFORMED `redundancy-group <id>` / RG-scoped `node <id>` token (non-
  numeric, empty, or negative) at strict commit and warns on tolerant
  load, because `compileChassis` otherwise Atoi-coerces such a token to 0
  and silently aliases redundancy-group / node 0. Being an AST walk it
  covers every shape, INCLUDING the packed one-liner the schema walker
  bypasses — pinned by `compiler_chassis_identity_5694_test.go`),
  `interface-monitor <if> weight <n>` (tokens pack inline into a
  `children==nil` leaf; typing the weight needs a children map, which
  would flip SetPath grouping — so **#6549** range-gates the weight the
  same way #4434/#4880 gate the RG id and node priority: on the COMPILED
  `*Config` in `validateChassisClusterStrict`, `0..255`, strict-reject at
  commit / warn on the tolerant load / peer-sync path. Running on the
  compiled int covers ALL THREE spellings with one gate — flat-set,
  container-hierarchical, and (since **#6588**) the PACKED one-liner
  `interface-monitor <if> weight <n>;` written directly under
  `redundancy-group`. The packed spelling used to compile to ZERO monitors,
  so the gate never saw it and no debt was installed either; now that it
  compiles like the other two, the gate covers it for free. Note the
  coverage claim holds BECAUSE the gate reads the compiled int: a typed
  schema leaf would still miss the packed shape, which sits below the depth
  `SchemaValidate` reaches (see "A PACKED hierarchical statement carries its
  entries on its OWN Keys"). #6588 extended the SAME compiled-int gate to the
  ip-monitoring `global-weight` / `global-threshold` / per-target `weight`,
  which #6549 had left to their typed schema leaves: those leaves are real, but
  the schema walker cannot reach the packed spelling for them either, so once
  the packed shape compiled they needed the compiled-int layer too. It is a
  wire-width gate like
  its siblings: the weight is the debt subtracted from the RG weight,
  which the heartbeat advertises through a single byte
  (`HeartbeatGroup.Weight`, `uint8(rg.Weight)`) while the local election
  reads the raw int — `weight -100` on a down monitor left the local node
  at 355 and the peer receiving 99, so both nodes elected primary from
  identical state. Because the gate is DOWNGRADED on the tolerant paths,
  the runtime — not the commit gate — is what actually holds the domain
  closed, and it does so at the point debt is INSTALLED rather than at
  each producer:
  - `cluster.Manager.SetMonitorWeight` (`election.go`) clamps every debt
    on the way in. With `reconcileMonitorDebtsLocked` it owns both of the
    only two writes into `monitorWeights`, so the domain is closed against
    EVERY producer — including `pkg/daemon`'s config-apply tail, which
    feeds `pkg/routing`'s monitor statuses straight in on every commit /
    boot Load / peer SyncApply and would otherwise OVERWRITE the clamp
    `UpdateConfig` had just applied.
  - `config.ClampInterfaceMonitorWeight` bounds the configured weight
    where each producer reads it: `pollInterfaceMonitors`,
    `reconcileMonitorDebtsLocked`, and `pkg/routing`'s
    `monitorManager.Apply` (a NEGATIVE weight is negative DEBT — it
    credits weight BACK and cancels a sibling monitor's real link
    failure).
  - `Monitor.ipTargetWeight` and the aggregate branch of
    `desiredRGIPDebts` bound the ip-monitoring weights. This one is NOT
    redundant with the chokepoint: in global-threshold mode a negative
    target weight SUBTRACTS from the cumulative failure sum, so a second
    genuinely unreachable target pushes the sum back below the threshold
    and drops the aggregate debt the first failure installed — more
    failures produce LESS demotion, and no `SetMonitorWeight` call happens
    at all for the chokepoint to catch.
  - `rgWeightFromDebt` closes the `rg.Weight` domain at every recompute
    site, and `clampWireWeight` saturates rather than wraps at the
    marshal boundary.
  The display fills route through the same clamp
  (`pkg/grpcapi/server_cluster.go`, `pkg/cli/cli_helpers.go`) so
  `show chassis cluster interfaces` never reports a weight the election
  does not apply. Note the ip-monitoring sibling leaves below are gated
  ONLY by their schema `ValidateInteger(0, 255)`, which
  `compileTreeLenient` downgrades to a warning — they carry no compiled-int
  commit gate, so this stanza's posture is STRONGER than theirs, not
  merely consistent with it. Pinned by
  `compiler_validate_strict_chassis_ifmon_6549_test.go` (config),
  `ifmon_weight_divergence_6549_test.go` +
  `ifmon_weight_daemon_apply_6549_test.go` (cluster),
  `monitor_weight_6549_test.go` (routing) and
  `cluster_monitor_weight_6549_test.go` (grpcapi + cli)), `control-ports`
  (not compiled), and the
  address/interface string leaves (IP value types arrive with the
  interfaces PR). Known residual: the hierarchical packed one-liner
  `node 0 priority <v>;` bypasses the gate (identity-token rule) even
  though `compileChassis` reads its inline tokens — pinned by
  `TestSchemaValidate_ChassisCluster_PackedOneLinerBypassesGate`.
  **#5695 (codex-182 M16)** completes the `gratuitous-arp-count`
  "sanity-cap-belongs-in-the-runtime" note above: the runtime now clamps
  the effective GARP/NA burst to `config.GratuitousARPBurstClamp` (32, 2×
  the Junos max) at every send site (`pkg/vrrp` sendGARP, `pkg/daemon`
  directSendGARPs), so an unbounded configured count can no longer fan a
  per-VIP raw-socket exhaustion burst on failover. The schema stays
  min-only (doctrine); the extra commit-side signal is a WARNING (never a
  reject) from the `validateGratuitousARPCountAST` pre-walk gate when a
  count exceeds the clamp — pinned by `garp_clamp_5695_test.go`
  (config), `instance_garp_clamp_5695_test.go` (vrrp), and
  `direct_garp_clamp_5695_test.go` (daemon).
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
  **#5184 — VRRP priority range gate:** the structured `priority`
  spellings are gated at the schema layer by the leaf's
  `ValidateInteger(1,255)`, but the hierarchical PACKED one-liner
  `vrrp-group 1 priority 256;` packs the priority onto the instance
  node's Keys, which the schema walker consumes as an unvalidated
  identity token (`walkInstanceChildren`) — the same identity-token
  residual as the `vrrp-group <id>` slot. `parseVRRPGroups` stored the
  out-of-range value verbatim into the wide `int` `VRRPGroup.Priority`,
  and the native engine later truncates it onto the single wire byte
  (`uint8(priority)` in `sendAdvert`, `pkg/vrrp/instance.go`), so a
  `priority 256` wrapped to the RESERVED priority 0 (RFC 5798 §5.2.4 —
  the group advertises resignation on every beacon and never masters the
  VIP, an HA blackhole) and 300 aliased to 44 (a silent demotion below
  the intended weight). `validateVRRPGroupPriorityStrict`
  (`compiler_validate_strict_vrrp_priority.go`) closes it exactly like
  #4573 closed the VRID slot: it runs on the compiled `*Config` — where
  the wide `int` still shows 256 as 256, before the `uint8` narrowing —
  and hard-rejects a priority outside 1..255 at commit / commit-check,
  catching BOTH the packed one-liner AND the structured form; the
  tolerant load / peer-sync path downgrades it to a warning
  (`lenientVRRPGroupPriority`, #1960 no-brick). Pinned by
  `TestSchemaValidate_Interfaces_PackedVrrpOneLinerBypassesGate` (schema
  passes, compile rejects) and the
  `compiler_validate_strict_vrrp_priority_5184_test.go` matrix.
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
  a peer `endpoint` that is not a concrete `host:port` (IPv6 authored as
  `[addr]:port`) with a numeric UDP port in `1..65535` and an IP-literal
  host — the Rust `hydrate_wg_identity` turns it into a `SocketAddr`
  (`wg_endpoint.parse::<SocketAddr>()`, no DNS), so a port-less/zero-port
  or hostname endpoint that COMMITTED CLEAN would hydrate the peer
  RESPONDER-ONLY (unable to initiate handshakes/keepalives). The lexer
  preserves the bracketed `[v6]:port` literal as one scalar (#5182) — it
  previously split it on the address's inner colons and dropped the port,
  so every IPv6 peer silently degraded; the dataplane now DROPS the row
  on a non-empty unparseable endpoint instead of coercing it to
  responder-only. The gate also rejects
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
  heartbeat zero-init loop bound is `heartbeatZeroSlotBound(
  heartbeatMap.MaxEntries())` (`pkg/dataplane/userspace/maps_sync.go`) — the
  Array's own capacity, which does not read `cfg.Workers` at all, so no value
  of it can make the loop wrap `uint32` or index past the fixed-size Array.
  This is the "lenient WARN-not-hang" contract applied at the runtime
  consumer, now closed by construction rather than by a clamp.

  **#6702 changed that bound, and the reason is worth stating** because the
  pre-#6702 shape (`heartbeatZeroSlots(cfg.Workers, mapCap)`, clamped into
  `[1, mapCap/heartbeatSlotsPerWorker]`) was measuring the wrong quantity. A
  heartbeat slot is indexed by the **binding slot** — the shim reads
  `USERSPACE_HEARTBEAT.get(binding.slot)` — and the binding count
  (`min(rx_queues) * interfaces`) has never been a function of the worker
  count. With the default `Workers: 1` the loop zeroed 32 slots, so a box with
  three interfaces at 16 queues, or six at 6, left its tail slots holding the
  PREVIOUS load's timestamps. A zeroed slot reads as stale and the shim
  correctly refuses to redirect; a slot still holding a timestamp from inside
  the heartbeat timeout reads as FRESH and masks a helper that has STOPPED.
- **#5011 (time-zone path-traversal reject):** `system time-zone` was an
  untyped string leaf rendered directly into the `/etc/localtime` symlink
  target (`/usr/share/zoneinfo/<value>`, `applyTimezone` in
  `pkg/daemon/daemon_system.go`). A `..` component / absolute path / space
  was accepted, a theoretical traversal on the symlink target. It is now a
  typed leaf: a new `ValueTimeZone` slot + `ValidateTimeZone` (a zoneinfo-name
  grammar — one or more `/`-separated segments matching `[A-Za-z0-9][A-Za-z0-9_+-]*`,
  so `.`/`..`/absolute/space/control are rejected; `UTC`,
  `America/Los_Angeles`, `Etc/GMT+5` still pass) strict at commit-check. Per
  the #1960 doctrine the tolerant load / peer-sync path only warns, so the
  daemon carries a **render belt** (`zoneinfoTarget`): it resolves the joined
  target with `filepath.Join` + `filepath.Rel` and refuses (fail-closed, no
  symlink written) any value that is empty, absolute, or escapes the zoneinfo
  root — the same validator+belt double boundary #4902 established for the
  system service/resolver string leaves.
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
  - **#5649 (IPsec VPN `df-bit` enum, codex-181 C181-M22):** the `security
    ipsec vpn <v> df-bit` leaf was untyped free-form (`args:1`, no validator),
    so a typo committed clean and was then silently dropped by the swanctl
    generator — the same MEDIUM footgun class as #3896. `df-bit` is now
    `ValidateEnum([copy, set, clear])`, matching the `pkg/ipsec/policy.go`
    renderer switch EXACTLY: it emits `copy_df = yes` for `copy`/`set` and
    `copy_df = no` for `clear`, and OMITS `copy_df` for any other spelling.
    An intended `clear` typed as `cler` therefore left strongSwan's copy-DF
    default in force (the opposite of `clear`) and could blackhole oversized
    encapsulated packets via PMTUD while commit reported success. This is the
    input-domain gate the #4015 valid-token `set`/`clear` mapping fix and the
    #4301 `establish-tunnels` enum did not cover.
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
    is validated in the compiler (`validateNATHostMaskStrict`,
    `compiler_nat.go`): the compiler records an explicit presence signal
    (`StaticNATRule.MappedPortPresent`) alongside the parsed port and the
    raw token, and a PRESENT mapped-port whose value is not a valid
    1..65535 port is rejected as malformed (C179-038 + fold). One gate
    covers every sentinel-collision sibling: a non-numeric token
    (`notaport`), an empty operand (`mapped-port ""`), a bare `mapped-port`
    with no operand, the literal `0`, and an out-of-range number
    (`70000`). Before the presence signal these all collapsed silently to
    `MappedPort==0`/"no port translation" (the int/string sentinels could
    not tell "absent" from "present-but-malformed"), so a garbage token was
    accepted even though a well-formed value in the same position without a
    `match destination-port` is rejected. The strict error names the
    offending token from `MappedPortRaw` (or `(missing value)` when the
    operand is empty/bare); `MappedPortRaw` and `MappedPortPresent` are
    compile-only (`json:"-"`) and never cross the dataplane wire. A valid
    in-range mapped-port is still rejected when it has no matching `match
    destination-port` (the reverse SNAT could not recover the original
    port), AND the mirror half-config — a `match destination-port` with no
    `mapped-port` (#2769) — is rejected. The port-match-without-
    mapped-port form is a port-scoped 1:1 (no port translation); rejecting
    it at strict commit-check forces the operator to either drop the port
    match (a whole-address 1:1) or add a `mapped-port` (a port forward).
    Two refinements land in the #6479 fold. First,
    `staticNATMappedPortForNode` gathers every `mapped-port` operand
    attached to a `then static-nat` node across EVERY Junos AST shape, into
    ONE list folded through `combineMappedPortOperands` exactly once:
      - the collapsed one-line `prefix <ip> mapped-port <port>` leaf;
      - the CANONICAL separate-set-line form — Juniper documents mapped-port
        as a sub-statement of `prefix`, authored as two set lines
        (`... prefix 10.0.0.5/32` + `... prefix mapped-port 8080`) that
        SetPath collapses to a distinct leaf `Keys=["prefix","mapped-port",
        "8080"]`, mapped-port immediately following the literal `prefix`;
      - the CANONICAL hierarchical nested form — `prefix <ip> { mapped-port
        P; }` / `prefix { <ip>; mapped-port P; }`, where mapped-port is a
        CHILD of the `prefix` node (a grandchild of `static-nat`), scanned
        via the target child's `Children`, not just its `Keys`;
      - a `prefix-name <name> mapped-port <port>` target (#4290) — the
        prefix-name compile branch feeds `staticNATMappedPortForNode` too,
        so a prefix-name-scoped mapped-port is gated identically;
      - a hierarchical `static-nat { prefix X; mapped-port P; }` sibling,
        scanning ALL operands of a packed `mapped-port a mapped-port b`
        child (not just the first);
      - AND every child of a duplicate split across two
        `then static-nat prefix <ip> mapped-port <p>` set lines.
    Duplicate operands are last-wins ONLY when they are all valid in-range
    numbers (`mapped-port 8080 mapped-port 9090` → 9090); a contradictory
    duplicate in ANY shape or ACROSS nodes (e.g. `mapped-port 8080
    mapped-port notaport`) fails closed — any malformed occurrence zeroes
    the port and the strict gate names the bad token, with no first-wins
    gate that could let a later malformed duplicate slip past an earlier
    valid one. Across MULTIPLE `static-nat` sibling targets in ONE `then`
    block (the hierarchical `then { static-nat {…} static-nat {…} }` shape,
    which Junos merges into one action), each sibling's reading folds
    through `mergeMappedPortState`, which OR-accumulates presence and
    LATCHES fail-closed on any malformed operand — so a later clean sibling
    can no longer overwrite an earlier sibling's presence/malformed stamp
    back to false (the #6479 multi-block silent-accept, closed in BOTH the
    nptv6 and the prefix/prefix-name branches). A MODIFIER-ONLY `static-nat`
    sibling (a `static-nat {…}` block carrying ONLY a `mapped-port`, with no
    `prefix`/`prefix-name`/`nptv6-prefix`/`inet` target) is routed through the
    same accumulator by a catch-all `else` branch in `compileNATStatic`, so
    its malformed operand fails closed in either sibling order and even when a
    co-sibling is a clean nptv6 target — previously it matched no target
    branch and reached no validator (the #6479 modifier-only silent-accept).
    This sibling accumulation is
    scoped WITHIN one `then` block; SEPARATE `then {}` blocks remain #3850
    last-then-block-wins (a whole superseded block is dead config, not part
    of the effective action). NOTE on duplicate resolution: the all-valid
    duplicate last-wins (`mapped-port 8080 mapped-port 9090` → 9090) is the
    INTENTIONAL disposition of a contradictory duplicate and DIFFERS from
    origin/master's first-wins (8080). It is not a working-config
    regression — a duplicate mapped-port on one target is malformed
    authoring, defensible either way — and last-wins is chosen for
    consistency with the Junos duplicate-stanza rule the rest of this fold
    already follows. The scan is grammar-ROLE-aware
    (`staticNATMappedPortOperandsFromKeys`): it walks the collapsed key
    stream tracking whether each position is a KEYWORD slot or a consumed
    VALUE slot, and a `mapped-port` counts as the modifier ONLY in a keyword
    slot. A NAME-valued keyword (`mappedPortNameValuedKeywords`:
    `routing-instance`, `prefix-name`) CONSUMES its following token as an
    opaque name, so a `mapped-port` in that consumed slot is the name — a
    translation-target routing-instance NAMED `mapped-port`
    (`... routing-instance mapped-port`, #4292) or a prefix-name entry NAMED
    `mapped-port` compiles clean instead of being falsely rejected as a bare
    mapped-port. Because it is the SLOT (keyword vs value) that decides, never
    the neighbouring text, a target whose NAME is itself literally
    `prefix-name` or `routing-instance`
    (`prefix-name prefix-name mapped-port <bad>`) no longer fools the scan:
    the earlier LEXEME-only lookbehind saw the preceding token `prefix-name`
    and wrongly skipped the real modifier, silently accepting a malformed
    port (the #6479 root cause); the role-aware walk consumes that name as the
    prefix-name VALUE and reads the following `mapped-port` as the
    keyword-slot modifier. `prefix` and `nptv6-prefix` are deliberately NOT
    name-valued: their value is ALWAYS an IP and can never be the string
    `mapped-port`, so the scan does not consume-and-shadow the token after
    them and `prefix mapped-port <port>` / `nptv6-prefix mapped-port <port>`
    (the canonical separate-set-line modifiers) are recovered. A round-4
    over-defensive addition of `prefix` to the name-valued set — and its
    `nptv6-prefix` sibling — broke those canonical forms (false-rejecting the
    clean rule and reopening the C179-038 fail-open, the nptv6 one so
    `validateNPTv6Strict` never fired); #6479 keeps both out. Second, the
    port-match-without-mapped-port (#2769) gate is guarded on
    `!MappedPortPresent` so it fires ONLY on a
    true absence: a present-but-malformed mapped-port that also carries a
    `match destination-port` is owned solely by the presence gate (which
    names the token), never double-reported by the absence gate — which,
    emitting first, would otherwise mask the accurate "not a valid port
    number" message in strict mode and add a second warning in lenient mode.
    If such a rule slips through the lenient load / peer-sync path, the Rust
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
    The #5523/#6479 shape-completeness fold closes the last authoring
    shapes a mapped-port could take. **NPTv6 + mapped-port is rejected on
    PRESENCE.** NPTv6 (RFC 6296) translates the IPv6 address prefix and has
    no transport-port concept, and the host-mask loop
    (`validateNATHostMaskStrict`) skips nptv6 rules entirely, so a
    `then static-nat nptv6-prefix <p6> mapped-port <p>` in ANY shape
    (collapsed keys, hierarchical nptv6-prefix child, or a distinct
    `mapped-port` sibling) previously reached NO validator — a malformed
    operand was silently accepted and a well-formed one silently ignored.
    `recordNPTv6MappedPortPresence` (`compiler_nat_static.go`) now stamps
    `MappedPortPresent` on the nptv6 branches while keeping `MappedPort==0`
    (no bogus port on the port-less nptv6 path), and `validateNPTv6Strict`
    rejects a present mapped-port on an nptv6 rule regardless of value (even
    a well-formed 1-65535 port is meaningless on nptv6) — strict error,
    lenient warning, with the nptv6 prefix translation itself still applied.
    The remaining flagged shapes are fail-safe without new code: the
    modifier-first ordering `... prefix mapped-port <p>` authored BEFORE the
    `... prefix <ip>` set line makes the modifier line's `prefix` keyword
    take the value `mapped-port`, so the target resolves to the literal
    `"mapped-port"` (not an IP) and the rule fails closed on the target;
    a `prefix-name` mapped-port must RESTATE the name on the same statement
    (`prefix-name N mapped-port P`) — the non-restated two-line form
    `prefix-name N` + `prefix-name mapped-port P` parses `mapped-port` into
    the name slot (name-valued skip), recovering no port and installing none
    (a plain prefix-name 1:1, matching origin/master); and a range operand
    (`mapped-port 8080-8090`) is a single non-numeric token that
    `combineMappedPortOperands` fails closed on. In every shape a
    present-but-malformed mapped-port is surfaced (strict reject / lenient
    warn), never silently accepted, and no bogus non-zero port is installed.
    The one residual this fold could not reach — a malformed mapped-port riding
    ONLY on a target the compiler DROPS when a rule declares more than one
    translation target (the dropped target's node is never the one the
    mapped-port fold reads) — is closed by the single-target cardinality gate
    (#6483, `validateStaticNATSingleTargetStrict`): a multi-target static-nat
    rule is rejected outright, so no dropped-target modifier can slip. See "A
    static-NAT rule has EXACTLY ONE translation target" above.
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
  - `security nat source/destination rule-set rule then ... pool <name>`
    (#5626) — a NAT rule's `then source-nat pool` / `then destination-nat
    pool` names a pool that MUST be defined under `security nat source pool
    <name>` / `security nat destination pool <name>`. An undefined reference
    used to be **warn-only** (`ValidateConfig`): the rule committed and then
    behaved incorrectly at runtime in an ORDER-DEPENDENT way — the SNAT
    snapshot builder (`nat_source.go`) marks the rule `poolUnusable`
    (`missing_pool`) and the DNAT builder (`nat_destination.go`) drops the
    rule outright (the pool lookup misses), so the requested translation
    silently never fires and matching traffic falls through to a later rule
    or the no-NAT default. `validateNATPoolReferencesStrict`
    (`compiler_validate_strict_nat.go`) now hard-rejects the dangling
    reference at strict commit / commit-check, naming the NAT kind, rule-set,
    rule, and the undefined pool; the pool-name resolution mirrors the
    snapshot builders exactly (`cfg.Security.NAT.SourcePools` for SNAT,
    `cfg.Security.NAT.Destination.Pools` for DNAT) so commit and apply cannot
    diverge. A rule with no pool reference (`then ... interface`, `then ...
    off`, static NAT's literal `prefix`) carries `PoolName == ""` and is out
    of scope. The gate reuses the `lenientDestNATAddresses` downgrade (warn on
    load / peer-sync, #1960 no-brick; the snapshot builders fail closed
    independently, so a leniently-loaded config with a dangling pool installs
    nothing rather than mis-translating). This gate subsumes the warn-only
    pool-reference loop that previously lived in `ValidateConfig` (keeping it
    would emit a duplicate warning alongside the downgraded gate warning on
    the lenient path). Fail-on-revert:
    `TestNATPoolReferenceUndefinedRejected_5626` /
    `TestNATPoolReferenceGate_LenientDowngrade_5626`
    (`pkg/config/compiler_nat_pool_ref_5626_test.go`).
  - `security nat source pool <name> address <member>` grammar / cap (#5627) —
    the companion to #5626: once a source pool is DEFINED and REFERENCED by a
    pool-mode `then source-nat pool <name>` rule, its ADDRESS members must be
    honorable by the live Rust allocator. The strict path previously validated
    only the pool `port range` (#3906/#5457), so a referenced pool carrying a
    malformed member (`not-an-ip`, `203.0.113.1/garbage`), an over-capacity
    prefix (host count `1 << (addrbits - prefixlen)` **greater than**
    `MaxSourceNATPoolPrefixHosts = 65536` — a `/15`, `10.0.0.0/8`, or a v6
    prefix shorter than `/112`), or **no addresses at all** committed green.
    The snapshot builder (`nat_source.go`) copies the raw strings onto the wire
    and the Rust allocator (`expand_pool_address` / `parse_source_nat_rules`,
    `userspace-dp/src/nat/source.rs`) then returns `false` for the bad member
    and marks the pool `InvalidPool` / `EmptyPool`, DROPPING the rule at runtime
    — a persistent NAT outage visible only after apply, where a single bad
    member poisons an otherwise usable pool.
    `validateSourceNATPoolAddressGrammarStrict`
    (`compiler_validate_strict_nat.go`) closes the divergence by rejecting the
    exact shapes the dataplane rejects: each member must be a bare IP
    (`netip.ParseAddr`, with no IPv6 `%zone`) or a CIDR (`netip.ParsePrefix`;
    host bits may be set, the runtime masks to the network base — documented since
    #5627 but UNOBSERVED until #6812 B2, and now pinned by the fixture's
    `first`/`last`/`expanded` fields on all three host-bits-set rows) whose host
    count does not exceed the cap, and a referenced pool must be non-empty. A
    `/16` (exactly 65536 hosts, at the cap) is accepted, matching the Rust
    `count > MAX_POOL_PREFIX_HOSTS` comparison.
    **Grammar parity is a tested claim, not an asserted one (#6812 F1 round
    3).** "Mirrors the dataplane" is a claim about two PARSERS agreeing, and a
    measured differential over both real parsers found six inputs where they did
    not. The runtime's CIDR branch parsed via `ipnet::IpNet`, whose hand-rolled
    octet reader accepts a leading-zero octet that `std` and `netip` both
    reject, so `010.0.0.0/24` built a working 256-address allocator while this
    gate rejected it at strict commit — a commit-vs-apply divergence (an earlier
    revision of this paragraph called it "an over-rejection on the tolerant
    path", which inverts the direction: at master the tolerant path stamped
    nothing for this class, see the disposition note below); and
    `netip.ParseAddr` accepted a bare `fe80::1%eth0`
    that `std::net::IpAddr` cannot represent. Both are closed — the runtime now
    parses its CIDR address half with the same `std::net::IpAddr` its bare
    branch always used, and the Go predicate rejects a zone on a bare member —
    and the agreement is pinned by a SHARED fixture,
    `userspace-dp/tests/fixtures/snat_pool_grammar_v1.json`, read by
    `TestPoolAddressGrammarMatchesDataplane_6812` (Go) and
    `nat_pool_grammar_parity_fixture` (Rust, through the real
    `expand_pool_address`). Neither side keeps a copy of the table.
    **The disposition of a leading-zero member DID move, and the move is
    deliberate (#6812 F1 round 4).** On the TOLERANT path a pool carrying
    `010.0.0.0/24` went from translating (the merge base shipped it unpoisoned
    and `ipnet` read it as `10.0.0.0/24`) to poisoned and dropping. The poison
    is not the runtime narrowing's: `SourceNATPoolUnusableReason` does not exist
    at the merge base, and its membership-grammar clause is what stamps
    `invalid_pool`. It is kept on the #5875 precedent — a non-representable
    literal is REJECTED, never silently rewritten, and `010` is the weaker case
    of the two since it has two readings where `%zone` has one. Normalizing
    would install a pool on a guess `show configuration` could not reveal. What
    the operator gets instead is a diagnostic that names the one-character fix
    ("spells an octet with a leading zero (`010.0.0.0/24`); write it as
    `10.0.0.0/24` … this pool translates nothing until the address is
    corrected"), on both tolerant entries — it rides `cfg.Warnings`, which the
    daemon logs at apply. Upgrade and peer-sync regression tests live in
    `pkg/dataplane/userspace/nat_pool_leading_zero_upgrade_6812_test.go`.
    The gate iterates ONLY pools a pool-mode rule references — the exact set the
    dataplane snapshot expands, so an unreferenced pool (never seen by the Rust
    grammar) is out of scope and the gate stays grammar-EQUIVALENT with live
    rather than Go-stricter — in sorted rule-set / declaration order for a
    deterministic first offender, and counts hosts off the prefix LENGTH without
    enumerating (O(pool addresses), the audit's no-expansion invariant). It
    reuses the `lenientDestNATAddresses` downgrade (warn on load / peer-sync,
    #1960 no-brick; the snapshot builder marks the pool unusable independently).
    Fail-on-revert: `TestSourceNATPoolBadGrammarRejected` /
    `TestSourceNATPoolBadGrammarLenientWarns`
    (`pkg/config/strict_nat_pool_grammar_5627_test.go`).
  - `security nat source pool <name> address <member>` zone/scope qualifier
    (#5875) — a NEW representability constraint alongside #5627. A source-NAT
    pool address may carry an IPv6 **zone/scope qualifier** (`fe80::1%eth0`):
    the Junos lexer admits `%` (`lexer.go` `isIdentChar`) and Go's
    `netip.ParseAddr` honors a zone, so the scoped literal passed the #5627
    grammar gate (a bare IP with a zone parses fine) and the snapshot builder
    copied the raw string onto the wire. (Since #6812 F1 round 3 the #5627
    grammar gate rejects a zone on a bare member too — it was one of the six
    measured Go/Rust parser divergences. This gate still runs FIRST in both
    `runUniformGates` and the #5876 peer-effective SNAT set, and
    `SourceNATPoolUnusableReason` still writes `zone_scoped_pool_address` after
    the membership-grammar clause, so the operator message and the wire reason
    are unchanged.) But the Rust allocator parses each pool
    member as `std::net::IpAddr` (`expand_pool_address`,
    `userspace-dp/src/nat/source.rs`), which has **no scope model**, so the
    scoped form fails to parse, the whole pool is marked `InvalidPool`, and the
    rule silently stops translating after apply — the same commit-vs-apply
    outage as #5627 but from a different cause. `validateSourceNATPoolAddressScopeStrict`
    (`compiler_validate_strict_nat.go`) **rejects a `%zone`-scoped pool address
    at strict commit**, naming the pool and the offending address, and telling
    the operator to remove the `%zone` suffix. The reject is safe: a global SNAT
    pool address never needs an interface scope, and the issue forbids silently
    stripping `%zone` (it would change the modeled address). The gate iterates
    ONLY referenced pools (same scoping as #5627) and runs BEFORE the #5627
    grammar gate so a `%zone`-scoped member — including a scoped-CIDR the grammar
    gate would otherwise reject with a generic invalid-CIDR message — gets the
    precise scope diagnostic. It reuses the `lenientDestNATAddresses` downgrade
    (warn on load / peer-sync, #1960 no-brick); the snapshot builder
    independently marks such a pool unusable
    (reason `zone_scoped_pool_address`), installing nothing rather than shipping
    the unparseable string. Registered in the SNAT strict set, so the #5876
    peer-effective SNAT gate rejects a peer-`${node}`-only scoped address too.
    The shared detector is `config.PoolAddressHasZoneScope` (a `%` substring
    test), used by both the Go validator and the snapshot builder. Fail-on-revert:
    `TestSourceNATPoolZoneScopedAddressRejected` /
    `TestSourceNATPoolZoneScopedAddressLenientWarns` /
    `TestPeerOnlyZoneScopedSNATPoolRejected_5875`
    (`pkg/config/compiler_zone_scoped_snat_pool_5875_test.go`) and
    `TestSourceNATSnapshotZoneScopedPoolUnusable_5875`
    (`pkg/dataplane/userspace/nat_source_zone_scope_5875_test.go`).
  - `security nat source pool` AGGREGATE cardinality budget (#5877) — the
    per-field / per-member gates above bound ONE pool (a member's host count to
    `MaxSourceNATPoolPrefixHosts = 65536`, a pool's port range to 1..65535), but
    nothing bounded the AGGREGATE across a whole config: pool COUNT, the SUM of
    every pool's address cardinality, or total port capacity. Snapshot/apply
    builds a `PortAllocator` for each pool-mode source-NAT rule
    (`userspace-dp/src/nat/{source,allocator}.rs`) — every pool address gets a
    per-address occupancy bitmap sized to the port range (one bit per port)
    plus a per-address counter — so a large-but-syntactically-valid config
    forces substantial memory + CPU during a security-critical commit-apply
    (stalling commits, watchdogs, HA convergence, or the Rust dataplane), and
    repeated applies magnify it.
    `validateSourceNATAggregateCardinalityStrict` (`compiler_validate_strict_nat.go`)
    rejects an over-budget config at strict commit, fail-closed, before apply
    constructs any allocator. Three explicit budgets (`compiler_validate_strict_nat.go`):
    - **`MaxSourceNATPoolCount = 1024`** — max DISTINCT pool-mode-referenced
      pools (allocator instances).
    - **`MaxSourceNATAggregatePoolAddresses = 16 × MaxSourceNATPoolPrefixHosts =
      1,048,576`** — max SUM of every referenced pool's address host-count (a
      bare IP counts 1; a CIDR counts its full prefix range, matching the Rust
      `expand_pool_address` enumeration). A /12 worth of public addresses,
      vastly more than any real SNAT allocation.
    - **`MaxSourceNATAggregatePortCapacity = 2^33 = 8,589,934,592`** — max SUM of
      (address host-count × port range) = the total occupancy-bitmap SLOTS the
      allocator builds (one bit/slot ⇒ ~1 GiB cap). Admits, e.g., two full /16
      pools at the default 1024-65535 PAT range (65,536 × 64,512 ≈ 4.23e9 slots
      each) or hundreds of realistic CGNAT pools, while rejecting a config that
      would force multi-gigabyte bitmap construction at apply.
    The gate iterates ONLY the DISTINCT pools a pool-mode `then source-nat pool
    <name>` rule references — the exact set apply expands into a `PortAllocator`
    (same scoping as #5627/#5875) — in sorted rule-set order for a deterministic
    first offender, counting hosts off the prefix LENGTH without enumerating.
    Runs AFTER the per-pool value/grammar gates so a single structurally broken
    pool still wins the first-error slot. It reuses the `lenientDestNATAddresses`
    downgrade (warn on load / peer-sync, #1960 no-brick: a config persisted
    before this gate existed still boots, and the operator is warned to shrink
    it). Registered in the SNAT strict set, so the #5876 peer-effective SNAT
    gate bounds the standby's identical allocator build too.
    **#6812 (opus-review-001 R73) — the tolerant path no longer builds the
    over-budget state.** Before #6812, a tolerated (warning-only) over-budget
    config still reached the Rust apply boundary, which built every pool's
    occupancy bitmap EAGERLY — before the reuse maps were consulted, even for
    an already-failed pool, and with no aggregate cap at the final allocation
    boundary (three full-range /16 pools = 12,683,575,296 bitmap bits ≈
    1.48 GiB, enough to stall or OOM the dataplane on upgrade boot / HA
    convergence). Three coordinated changes close that: (1) the userspace
    snapshot builder poisons exactly the pools that do not fit the budget
    (`SourceNATAggregateOverBudgetPools` — the same referenced-pool walk and
    saturating charge arithmetic as the strict validator, first-fit so a
    refused pool does not starve later smaller pools), marking their rules
    `PoolUnusable` with reason `aggregate_over_budget`; (2) the Rust apply
    boundary (`resolve_pool_allocators` in `userspace-dp/src/nat/source.rs`)
    independently enforces the same budgets per distinct allocator key —
    reuse-before-build (a same-config re-apply no longer builds and discards
    a full bitmap per pool), nothing built for a failed pool, reused keys
    consume budget but are always accepted (a no-op re-apply never kills
    live state, and a two-step apply cannot creep past the cap one
    generation at a time), and a new key that does not fit fails its rules
    closed with the `source_nat_pool_over_budget` dataplane diagnostic
    instead of materialising the bitmap. **Reused keys are RESERVED in a
    first phase, before any new key is admitted (#6812 F2 round 4)** —
    charging reuse where the walk MET it made the backstop order-dependent:
    with two pools live at 160 of a 200-slot test budget and a new pool worth
    80, the order `A,B,C` refused the newcomer while `C,A,B` admitted it and
    built its bitmap, landing 240 slots against the cap, repeating one pool
    per apply. Go-side poisoning masks that for snapshots this control plane
    generates, which is exactly why it mattered: this boundary is the
    INDEPENDENT backstop for tolerated, older-control-plane and handcrafted
    snapshots; (3) the `aggregate_over_budget`
    wire reason maps to the new `OverBudget` failure variant (an older
    helper's catch-all maps it to `InvalidPool` — still fail-closed, so the
    marker is wire-skew safe).

    **#6812 F1 — which pools the budget CHARGES is the runtime's own
    verdict, not a derived quantity.** A pool the dataplane refuses builds no
    allocator, so charging it Go-side refuses a HEALTHY pool the dataplane
    would install — fail-closed over-rejection on the tolerant / peer-sync
    recovery path (#1960 no-brick). The budget walk therefore excludes any
    pool `config.SourceNATPoolUnusableReason` calls unusable, and the snapshot
    builder poisons exactly that same set, so the two cannot drift.

    That predicate is ALL-OR-NOTHING over pool membership because the
    dataplane is: `expand_pool_address` failing on ONE member sets
    `invalid_pool_address` and fails the WHOLE pool as `InvalidPool`
    (`userspace-dp/src/nat/source.rs`). A pool of
    `[198.51.100.1, not-an-ip]`, or one carrying an over-capacity `10.0.0.0/15`
    (131,072 hosts against the 65,536 `MaxSourceNATPoolPrefixHosts` cap),
    installs nothing at runtime and is now excluded from the budget for that
    reason, carrying the wire reason `invalid_pool` — which
    `source_nat_failure_reason_from_snapshot` decodes to the same
    `InvalidPool` the parse loop reached on its own, so the dataplane
    disposition is unchanged and only the DECIDER moves. An earlier revision
    approximated this by summing per-member host counts and skipping a
    zero total, which agreed with the runtime only when EVERY member failed;
    the mixed and over-capacity shapes above escaped it (the second one
    precisely because it expands to a LARGE number, charging 98.4% of the
    port-capacity budget for an allocator that never exists).

    **#6812 F2/F3 round 3 — the walk consults the resolved port range, and
    admits pools in the order the DATAPLANE charges them.** Two consumers were
    re-deriving what a shared function already answers. (F2) The charge
    recomputed the port window from the raw `PortLow`/`PortHigh` fields instead
    of consulting `SourceNATPoolPortRange`, the resolver the snapshot builder
    ships — behaviour-identical on the live path, because `compileNATSource`
    defaults an unset range to 1024-65535 before storing the pool, but a
    correctness that rested on a defaulting three files away with nothing
    binding the two together. (F3) The walk ordered rule-sets by NAME, which is
    neither the emitted order nor any Junos semantic. The snapshot builder
    STABLE-sorts its emitted rules by #4161 scope tier and
    `resolve_pool_allocators` charges that emitted slice in order, so with two
    pools that each fit alone but not together, an alphabetically earlier
    ZONE-scoped rule-set took the budget and the more-specific INTERFACE-scoped
    rule-set's pool was poisoned. The walk now stable-sorts by the same tier
    through ONE shared definition (`config.SourceNATScopeTier`, which the
    builder also calls), so the pool Go admits is the pool the dataplane charges
    first. The sibling grammar/scope gates still sort by name — they pick a
    deterministic first-reported OFFENDER, where admission plays no part.

    Fail-on-revert:
    `TestSourceNATAggregatePoolCountRejected` /
    `TestSourceNATAggregateAddressesRejected` /
    `TestSourceNATAggregatePortCapacityRejected` /
    `TestSourceNATAggregateLenientWarns`
    (`pkg/config/compiler_nat_source_pool_aggregate_5877_test.go`),
    `TestAggregateOverBudgetPools{PortCapacity,Addresses,Count,FirstFit,Unreferenced}_6812` /
    `TestAggregateValidatorMatchesPoisonWalk_6812`
    (`pkg/config/compiler_nat_source_pool_aggregate_6812_test.go`),
    `TestAggregateBudgetExcludesUnusablePools_6812` /
    `TestBudgetChargeImpliesHonorableMembers_6812`
    (same file),
    `TestSourceNATSnapshotAggregate{OverBudgetPoisoned,AtBudgetUnaffected}_6812` /
    `TestSourceNATSnapshotUnusablePoolsDoNotPoisonHealthy_6812` /
    `TestSourceNATSnapshotMixedMemberPoolsDoNotPoisonHealthy_6812` /
    `TestSourceNATSnapshotOverCapacityPoolDoesNotStarveHealthy_6812` /
    `TestSnapshotPoisonFollowsEmittedScopeOrder_6812`
    (`pkg/dataplane/userspace/nat_source_aggregate_6812_test.go`),
    `TestAggregateChargeConsultsResolvedPortRange_6812` /
    `TestCompiledPoolCarriesDefaultedPortRange_6812` /
    `TestAggregateFirstFitFollowsEmittedScopeOrder_6812` (F2/F3, in the
    `pkg/config` aggregate file), the grammar-parity pair
    `TestPoolAddressGrammarMatchesDataplane_6812` /
    `TestPoolAddressHostCountMatchesDataplane_6812`
    (`pkg/config/nat_pool_grammar_parity_6812_test.go`), and
    `nat::tests_aggregate_budget` (`userspace-dp/src/nat/tests_aggregate_budget.rs`),
    including `go_side_invalid_pool_verdict_matches_the_parse_loop_verdict_6812`
    for the disposition-equivalence claim and
    `nat_pool_grammar_parity_fixture` /
    `nat_pool_bare_and_host_cidr_grammars_agree` for the F1 round-3 parser
    parity, plus (round 4)
    `reused_keys_reserve_budget_before_a_new_key_is_admitted_6812` /
    `incremental_applies_cannot_creep_past_the_cap_6812` for the reservation,
    `TestAggregateFirstFitSameTierFollowsConfigOrder_6812` /
    `TestAggregateSameTierBudgetBoundaryFollowsConfigOrder_6812` for the
    same-tier tie-break on the WALK side and
    `TestBuilderEmittedOrderIsStableWithinATier_6812` for the BUILDER side —
    F3 is an EQUALITY between two sequences and each half needs its own
    binding; the builder half is the one with a dataplane consequence, since
    the Rust matcher is first-match on the emitted slice and a split rule-set
    misroutes (both use MIXED-tier fixtures of 20 rule-sets: Go's
    `sort.Slice` preserves order for an all-equal key, so a single-keyed
    same-tier fixture cannot distinguish a stable sort from an unstable one —
    measured, and it is why the second of these was re-cut), and
    `TestLeadingZeroPoolMember{Upgrade,PeerSync}IsDiagnosable_6812` for the
    tolerant-path diagnostic. The reuse and failed-pool guards assert a
    PortAllocator CONSTRUCTION count (a thread-local `#[cfg(test)]` counter),
    not just the final allocator's identity or word count — an end-state
    assertion cannot see a bitmap that was built and discarded, which is the
    exact behaviour those two rules exist to forbid. The shared grammar fixture
    also pins WHICH addresses a member expands to (`first` / `last` /
    `expanded`, asserted Rust-side): a missing network-base mask changes the
    address set while leaving the host COUNT identical, so deleting both masks
    left the crate green until those fields existed (#6812 B2). The stake is
    CROSS-LANGUAGE, not merely wrong addresses: `pkg/nat/deterministic.go`
    expands the same pool from `net.ParseCIDR`'s already-masked `ipnet.IP`, and
    `lookupForwardInPool` INDEXES that slice to answer the operator-facing
    "which external address does this subscriber get?" query — so a drifted Rust
    base makes the CLI/gRPC/REST deterministic mapping name a different address
    than the dataplane translates to, the #5794 invariant-8 forensic failure.
    `TestDeterministicPoolExpansionMatchesSharedGrammarFixture_6812` (pkg/nat)
    reads the SAME fixture, so all three consumers are pinned to one table —
    on BOTH halves since #6812 F-C. The accept half pins the expansion identity;
    the reject half caught `net.ParseCIDR` accepting a leading-zero mask
    (`10.0.0.0/016` as `/16`) that every other layer refuses, which had the
    deterministic surface reporting a 65,536-address mapping for a pool that
    translates nothing.
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
    Because the leaf is `multi: true` with `children == nil`,
    `validateMultiValueLeaf` runs this validator over EVERY authored
    slot — `Keys[1:]` and every block-child — which is what made #6695
    safe to widen without an unwidened validator behind it.
  - `link-mtu` — floor raised to `ValidateIntegerMin(1280)` (RFC 8200 §5
    IPv6 minimum link MTU); a smaller value was advertised verbatim and
    blackholes hosts that honor it.
  Pure schema hardening — no runtime behavior change (the sender's
  parse-and-skip / default paths are now unreachable for committed
  configs). New validators `ValidateIPv6Address` / `ValidatePREF64CIDR`
  live in `schema_validators.go`. Regression coverage:
  `pkg/config/schema_validate_2497_test.go`.
- **#6695 (router-advertisement `dns-server-address` multi-value read):**
  the leaf is `multi: true`, but `compileRouterAdvertisement` read it with
  `nodeVal` — `Keys[1]` alone. Measured across all five spellings before
  fixing: A hier-bracket `drop`, B hier-block **inert** (no `Keys[1]` exists
  in that shape, so the block spelling compiled NOTHING), C hier-repeat
  `keep`, D set-bracket `drop`, E set-repeat `keep`. Hosts on the link
  therefore learned ONE RDNSS server while `show configuration` rendered
  both, and the missing redundancy stayed invisible until the primary
  resolver failed. The reader is now `firewallMatchValues` (every value it
  returns is installed into one RFC 8106 `RecursiveDNSServer` option, so an
  empty token legitimately means absence). The
  `protocols router-advertisement interface <*> dns-server-address` row was
  removed from `knownSpellingInconsistencies` in the same change; after the
  fix all FIVE spellings are compared and all report `keep`, so gate coverage
  of this site went UP — the previously inert block spelling now carries a
  verdict. Fail-on-revert:
  `pkg/config/compiler_ra_dns_server_6695_test.go` (compiled slice contents
  per spelling, a three-address case, and the every-slot validator guard) and
  `pkg/ra/sender_marshal_rdnss_6695_test.go`, which drives the real Junos text
  through `CompileConfig` into `buildRA` and re-parses the marshalled option —
  a dropped address is invisible in the option COUNT (the sender emits one
  option holding every server) and shows only in its `Servers` list.
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
- **#5670 (DHCP relay ingress rate limit):** added under group `overrides`:
  - `maximum-packet-rate <pps>` (`ValidateInteger(1, 1000000)`) —
    **enforced (DoS hardening)**. The relay admits at most this many
    client-facing datagrams per second per interface, via a per-interface
    token bucket checked BEFORE `dhcpv4.FromBytes` + the Option-82 fan-out,
    so an untrusted client segment cannot CPU-exhaust the relay or amplify a
    flood into the upstream servers (1 client packet → N server packets).
    Unset = 100 pps default (`resolveMaxPacketRate`); the bucket starts full
    with a 2-second burst; excess is dropped and counted in
    `RelayStats.RequestsDroppedRateLimit`. Compiled into
    `DHCPRelayGroup.MaximumPacketRate` and flows into
    `relaySpec.maxPacketRate` (a change restarts the per-interface relay).
    Both AST shapes handled. Coverage:
    `pkg/config/compiler_dhcp_relay_overrides_test.go` (flat-set + merged +
    block + completion + default) and `pkg/dhcprelay/relay_ratelimit_5670_test.go`
    (`TestTokenBucket_BurstThenRefill` deterministic unit + the end-to-end
    flood-drop `TestRunRelay_RateLimit_5670` / `TestRunRelay_RateLimit_DefaultBound`).
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
  `source-address` (`ValueIPAddress`). **`source-interface` is modelled at BOTH
  levels since #6875** — `security log source-interface` (global) and `security
  log stream <s> source-interface` (per stream), sharing one validator. The
  per-stream spelling previously parsed as an unmodelled keyword (the `stream`
  subtree is open-world), compiled to nothing, and committed clean while the
  stream sourced from the global setting or from nothing; a happy-path test
  pinned that no-op as valid. Apply-time precedence is **`source-address` >
  `source-interface` > global `source-interface`** (`daemon_system.go`): an
  explicitly configured address beats one derived from an interface, and both
  beat the global fallback. A per-stream `source-interface` that resolves to no
  address falls through to the global rather than pinning the stream to "" —
  resolution reads interface state, so an interface that is merely not up yet
  must not permanently strip a source the operator did configure globally.

  Worth knowing when reading either level: `ResolveSyslogSourceAddr` consults
  only `unit.PrimaryAddress` from config, and a plain `address` line populates
  `Addresses` while leaving `PrimaryAddress` empty. So a unit configured
  without an explicit `primary` resolves to "" from config and depends on the
  kernel-lookup fallback. That is pre-existing behaviour of the global feature,
  not something #6875 introduced, and it is why the #6875 precedence tests set
  `primary` explicitly.

  `ValidateSyslogSourceInterface` rejects a non-numeric `.<unit>`
  suffix (`resolveSourceAddr` silently `Atoi`-fell-back to unit 0, binding the
  wrong source IP) AND, since #6218 item 7, a `.<unit>` above `MaxLogicalUnit`
  (16385) — e.g. `ge-0-0-0.50000` — which previously committed even though no
  real interface unit can exceed that ceiling (`compiler_interfaces.go` caps a
  real `unit <n>` there), so the reference could never resolve and
  `ResolveSyslogSourceAddr` silently returned "" (the same audit-source-IP
  loss the non-numeric case closes, reached via an out-of-range unit instead
  of a typo'd one). The enum value sets live in `schema_security.go`
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
- **#2354 / #5879 (canonical per-physical-interface QinQ reject):** the
  AF_XDP shim's `parse_l2` unwinds exactly ONE VLAN tag, so xpf cannot
  represent a double-tagged (802.1ad S-tag + 802.1Q C-tag) frame — an inner
  / second tag is XDP_PASSed to the kernel forwarding path and never
  firewalled. #2354 rejected the one obvious spelling (a per-unit
  `inner-vlan-id` leaf) inside `validateUnsupportedInterfaceStanzasAST`, but
  that validated a LOCAL statement shape on the committing node's own
  expansion, so two classes of unsupported QinQ bypassed it:
    - a DIFFERENT inner-tag spelling — `vlan-tags outer <x> inner <y>` (the
      modern Junos stacked-VLAN syntax) is not in `setSchema` and has no
      compiler consumer, so it parse-accepted and was silently dropped; the
      inner half can even be SPLIT across two `set` statements
      (`vlan-tags outer 100` + `vlan-tags inner 200`), so no single leaf is
      the recognizable `inner-vlan-id`;
    - a PEER-ONLY node view — an `inner-vlan-id`/`vlan-tags inner` under
      `groups node1` + `apply-groups "${node}"` never materializes when the
      candidate is compiled for node0, so a commit ON node0 accepted a stack
      that renders unsupported QinQ on node1 (an active/standby posture
      split — the standby silently PASSes to the kernel what the primary
      firewalls).
  #5879 replaces the local `inner-vlan-id` check with a canonical
  per-physical-interface gate (`validateQinQVLANStackAST`,
  `compiler_interfaces_qinq.go`): it builds each unit's aggregate outer/inner
  tag stack across BOTH spellings (`vlan-id`/`inner-vlan-id` AND
  `vlan-tags outer/inner`, combined onto one statement or split across
  several) and rejects any unit whose stack carries an inner (second) tag.
  It runs PRE-expansion beside the tunnel/zone/table-id/unit-alias union
  gates and evaluates the effective view for EVERY cluster node (the node0
  AND node1 `${node}`/apply-groups + interface-range expansions), so the
  accept/reject verdict is HA-symmetric no matter which node commits and a
  peer-only-group inner tag is caught. Only the two per-node EFFECTIVE views
  are unioned — deliberately NOT the pre-expansion all-groups "View 1" the
  sibling collision gates (`#5878`, `#3075`) fold in, because QinQ trips on a
  SINGLE inner tag and a View-1 union would additionally reject a QinQ stanza
  staged in a group that NO `apply-groups` references (inert dead config
  outside any node's effective view). Single 802.1Q tagging via `vlan-id`
  (with or without `flexible-vlan-tagging`) stays fully supported. Strict on
  commit / commit-check; downgraded to a warning on the tolerant load /
  peer-sync paths (`lenientQinQVLANStack`, #1960) so an older-binary-persisted
  or peer-synced config that silently accepted the inner tag still boots.
  Because rejection is a compile error, the candidate is never promoted — no
  partial outer/inner state survives. Regression coverage:
  `pkg/config/qinq_canonical_vlan_5879_test.go`.
- **#6178 (input-vlan-map / output-vlan-map reject):** Junos
  `input-vlan-map` / `output-vlan-map` under a logical unit request a VLAN
  tag rewrite on ingress / egress — push a tag, pop a tag, or swap the tag
  id (`push`, `pop`, `swap`, `push-push`, `swap-swap`, and the tag arguments
  `vlan-id` / `tag-protocol-id` / `inner-vlan-id`). Neither spelling is in
  the unit `setSchema` and neither has a compiler consumer, so the stanza
  parse-accepted and was SILENTLY DROPPED: the AF_XDP dataplane performs no
  rewrite and forwards the frame with its tags unchanged. Unlike the #5879
  receive-side QinQ case this is NOT a firewall bypass (a single-tagged frame
  still arrives single-tagged and IS firewalled — only the configured
  push/pop/swap never happens), but a strict commit ACCEPTED a rewrite the
  dataplane cannot perform, so the operator believed tags were being pushed /
  swapped when they were not — a config-honesty gap. `validateVLANMapAST`
  (`compiler_interfaces_vlanmap.go`) mirrors the #5879 doctrine exactly: it
  runs PRE-expansion beside the QinQ gate, evaluates the effective view for
  BOTH cluster nodes (node0 AND node1 `${node}`/apply-groups + interface-range
  expansions) so a peer-only-group vlan-map is caught and the verdict is
  HA-symmetric, and detects the stanza in both AST shapes. Strict on commit /
  commit-check; downgraded to a warning on the tolerant load / peer-sync
  paths (`lenientVLANMap`, #1960) so an older-binary-persisted or peer-synced
  config that silently accepted the vlan-map still boots. Single 802.1Q
  tagging via `vlan-id` stays fully supported. Regression coverage:
  `pkg/config/vlanmap_honesty_6178_test.go`.
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
  at `interfaceRangeMaxMembers` to bound a typo). The expansion loop
  iterates on the bounded COUNT `k` in `0..(en-sn)` (< the cap) and forms
  each name as `sn+k`, NOT on the raw endpoint `i` up to `en`: the endpoint
  values come from `strconv.Atoi` (no typed-schema ceiling) and can sit at
  `math.MaxInt64`, where a `for i := sn; i <= en; i++` loop overflowed —
  `i++` at `MaxInt64` wrapped to `MinInt64`, `i <= en` stayed true, and the
  loop appended forever (#5373 infinite loop / OOM, reachable at commit AND
  on the tolerant / HA config-sync load path). Counting on `k` keeps the
  loop variable small regardless of `en`'s magnitude while `sn+k` still
  yields exactly `sn..en` (this is separate from the #4807 `en-sn+1`
  capacity-overflow guard, which the `en-sn >= cap` check handles). The
  pass handles BOTH AST
  shapes (flat-set replay packs the range name into each leaf's `Keys[0]`;
  the hierarchical parser packs it into the `interface-range` node's
  `Keys[1]`) and is a strict no-op — the tree is left byte-identical —
  when no interface-range stanza is present. This is a compile-time AST
  rewrite, not a `setSchema` change: adding schema children for `member` /
  `member-range` would alter the flat-set grouping the expansion depends
  on, so the construct stays out of the grammar SSOT and is normalized
  before any typed-leaf walk. **#5675 (multi-root aggregation):** the pass
  scans EVERY top-level `interfaces` root, not just the first. A
  hierarchical config can split its interfaces across two sibling
  `interfaces { }` stanzas (flat-set always merges onto one root, so this
  shape is hierarchical-only), and `compileSections` dispatches every root
  — so a `break`-on-first-root scan skipped an interface-range living in a
  second root, re-minting the phantom `interface-range` interface and
  dropping that range's members. The pass now collects ranges and
  member-own config across all `interfaces` roots and replays the expanded
  members through `SetPath` (which `compileSections` merges with the rest).
  Regression coverage:
  `pkg/config/compiler_interface_range_4027_test.go` and
  `pkg/config/compiler_multi_root_5675_5691_test.go`
  (`TestInterfaceRangeSecondRootExpands_5675`). The sibling stable-ID
  collision gates (zone `#3075`, tunnel `#1873`, routing-instance `#3855`)
  carried the same first-root-only defect for split `security` /
  `interfaces` / `routing-instances` roots and were fixed the same way
  (`#5691`, `ConfigTree.FindChildren`-based union across all matching
  roots). **#5744 (the two remaining interface AST pre-walks):** the
  unit-alias collision gate (`validateInterfaceUnitAliasCollisionsAST`,
  `#5631`) and the unsupported-stanza gate
  (`validateUnsupportedInterfaceStanzasAST`, `#2008`; the `#2354` QinQ half
  has since moved to the `#5879` canonical both-node gate) were the last
  sibling pre-walks still `break`-ing on the first `interfaces` root, so a
  unit-alias collision or an unsupported/silently-dropped stanza placed in a
  SECOND `interfaces` root bypassed them. Both now flatten every
  `interfaces` root's children into one per-interface pass (whole-interface
  last-writer-wins across roots keeps the collision intra-node, so each
  interface node is still detected independently, matching
  `compileInterfaces`). Regression coverage:
  `pkg/config/interface_prewalk_all_roots_5744_test.go`.
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
  `LoadOverride` shape. Distinct from the #3362/#3720/#6515 resolution, which
  combines host-inbound authored at DIFFERENT granularities (`physical ∪ unit`,
  then REPLACING the zone level); #4544 merges repeated blocks at the SAME
  granularity. Regression coverage:
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
    **Redirects are constrained (#4861, #6545):** the shared `CheckRedirect`
    (`ddns.guardRedirect`) refuses a 30x `Location` that downgrades the scheme
    (HTTPS→HTTP) or changes the HOST, strips `Referer` from any redirect it does
    follow, and keeps the 10-hop cap. The cross-host refusal exists because Go
    puts the FULL previous URL — query string included — in `Referer` on an
    HTTPS→HTTPS hop (disclosing the DuckDNS/`generic`/`checkip-url` query-param
    token to the redirect target) and forwards `Authorization`/`Cookie` to any
    SUBDOMAIN of the original host (disclosing the dyndns2/`generic` Basic
    credential and the Cloudflare bearer token). Operator-visible consequence: a
    `server` / `url-template` / `checkip-url` pointing at an endpoint that
    redirects to a DIFFERENT host fails the publish with a `refusing cross-host
    redirect from <a> to <b>` error naming both hosts — point the leaf at the
    final host. Same-host redirects (a path or API-version move) still work.
    **The common trigger is an APEX `server` leaf.** No shipped default endpoint
    redirects, but a hand-written bare host resolves to the apex over HTTPS
    (`server duckdns.org` → `https://duckdns.org/update`) and the apex 301s to
    `www` (`https://www.duckdns.org/update`) — so `server duckdns.org` worked
    before and is REFUSED now. Same for a `cloudflare.com` or `amazonaws.com`
    apex leaf. Fix: configure the final host, `server www.duckdns.org`. There is
    no commit-time check because detecting the redirect requires a network call.
    This is NOT fixable by allowing same-registrable-domain hops: `www.<host>` is
    a SUBDOMAIN of `<host>`, and the subdomain hop is exactly where Go forwards
    `Authorization`/`Cookie` — relaxing the guard for the ergonomics would
    re-open the credential disclosure it exists to close.
    A `checkip-url` failure — a refused redirect, a malformed URL, an
    unreachable endpoint, a non-2xx status — is now LOGGED once per (provider,
    error) by the daemon instead of collapsing into a silent, permanent
    "transient observation failure"; the ordinary dual-stack miss (endpoint
    answered, no address of the requested family) stays silent.
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
    `RedactURL` itself was only sound for a WELL-FORMED URL until #6609: it
    located userinfo by finding `@` inside the authority, so the commonest
    credentialed typo — omitting the `@`, as in
    `http://user:s3cr3t.example/` — matched nothing and was returned in full,
    on the very branch that exists to report a malformed template. It now also
    redacts the whole authority when the host part carries a colon whose suffix
    is not a port (a bracketed IPv6 literal is recognised, so a well-formed
    `[2001:db8::1]:8443` is still printed), starts the authority correctly for
    a scheme-relative `//user:pass@host/`, and drops the fragment — which a
    query already dropped as a side effect, so only the no-query case leaked.
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

### #5299 — legacy firewall policer `bandwidth-limit` / `burst-size-limit` fail-closed rate validation

The legacy single-rate two-color policer leaves
`firewall policer <name> if-exceeding bandwidth-limit` /
`burst-size-limit` were untyped (`ValueAny`), so the compiler's
silent-zero parsers coerced garbage / zero / overflow to 0. A typo like
`if-exceeding bandwidth-limit 10mm` COMMITTED CLEAN → `parseBandwidthLimit`
returned 0 bps → the userspace runtime `fail_closed(true)` (#4522/#4514)
drop-alls matching traffic for the default `then discard` (or skips /
inerts the meter for a non-discard action). `parseBurstSizeLimit` was
additionally an unchecked `v * multiplier` uint64 multiply that WRAPPED an
overflowing burst to a small nonzero value — a silently-wrong meter rather
than an outright reject. The #4522/#4514 runtime backstop fail-closes on
the 0 the typo produces but never validated the control-plane quantity, so
the outage was invisible at commit.

Fix (fail-closed, #1960 doctrine):

- **`bandwidth-limit`** is now `valueType: ValueRate` + `validator:
  ValidateRate` (`schema_cos.go`). `ValidateRate` rejects empty, malformed
  (`10mm`), negative, `NaN`/`Inf`, overflow, and anything below 8 bps
  (which folds in `0`, since a sub-8-bps rate round-trips to 0 bytes/sec).
- **`burst-size-limit`** is `valueType: ValueByteSize` + a dedicated
  `validator: ValidatePolicerBurstSize` (`schema_validators_cos.go`).
  Unlike the CoS `ValidateByteSize` gate it does NOT reject a bare integer
  — a bare byte count is unambiguous for a policer bucket and was a valid
  compiling input, so keeping it preserves valid configs. It DOES reject
  empty, zero, negative, malformed (`15kk`), and any k/m/g-scaled product
  that overflows uint64 (via `parseBurstSizeLimitStrict`).
- **`parseBurstSizeLimit`** (the lenient parser) now delegates to
  `parseBurstSizeLimitStrict` and returns 0 on error, so an OVERFLOWING
  value is no longer wrapped to a small nonzero meter — it becomes the
  unambiguous "unset" 0 the strict schema gate already rejects at commit.
  `parseBandwidthLimit` / `parseScaledDecimalUnit` already clamp overflow
  to 0, so no change was needed there.

Tolerant path: the configstore `Store.Load` / `Store.SyncApply` ingress
(`compileTreeLenient`) runs the SAME `SchemaValidate` gate but DOWNGRADES a
violation to a warning and compiles leniently (coercing to 0), so a
peer-synced or older-binary policer cannot blackout-boot the node — the
operator's next strict commit rejects it loudly.

No compiled-`FirewallConfig` strict gate (parallel to
`validateThreeColorPolicersStrict`) was added: `SchemaValidate` runs on the
fully apply-groups-expanded candidate tree, so every strict operator-commit
form — including group-expanded and flat-set-packed values — is already
covered at the schema leaf; there is no compiled-config-only form that
bypasses it on the strict path. The only paths that skip the schema leaf
are the tolerant Load / SyncApply ingress, which #1960 requires to stay
lenient. A hard compiled-config gate there would BRICK a leniently-loaded
policer that coerced to 0 (the existing `validateThreeColorPolicersStrict`
hard-fails even under `CompileConfigLenient` — a contrasting, arguably
latent-brick precedent deliberately not replicated for the legacy policer),
and a compiled `BandwidthLimit == 0` cannot be distinguished from a
legitimately-unset limit without a `Configured` bool the type does not
carry.

Regression coverage: `pkg/config/policer_rate_validate_5299_test.go`
(flat-set `ParseSetCommand` + `SetPath`): valid `10m` / `15k` /
bare-integer accept + compile-to-expected-units, malformed / zero /
negative / `NaN` / `Inf` / overflow strict-REJECT, tolerant-load
WARN-not-hard-fail, and a direct `parseBurstSizeLimit` overflow-returns-0
unit test. FAIL-ON-REVERT: dropping the validators makes the reject cases
commit clean again; reverting the `parseBurstSizeLimit` delegation makes
the overflow test go RED (the old inline multiply returned a wrapped
nonzero, e.g. `20000000000000g` → `3729424098846048256`).

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

### #6526 — A policy `match` leaf with NO OPERAND widens the dimension to match-ANY

The #3044 required-match gate (`validatePolicyRequiredMatchStrict`) decided
whether a Junos-mandatory dimension was present from the leaf **name**:

```go
for _, m := range policyMatchChildren(polNode) { present[m.Name()] = true }
```

while the reader the compiler actually uses — `firewallMatchValues` — skips
blank tokens, so *an empty result means "criterion absent"*. A dimension
written with **no operand** therefore satisfied the gate and compiled to the
**byte-identical empty slice the OMITTED form produces**, which the userspace
matcher reads as match-ANY:

| `match` stanza | before #6526 | after #6526 |
|---|---|---|
| `source-address 10.0.0.0/8;` | ACCEPTED, `SourceAddresses=[10.0.0.0/8]` | unchanged |
| `source-address;` (no operand) | **ACCEPTED, `SourceAddresses=[]` → match-ANY** | REJECTED (#6526) |
| omitted entirely | REJECTED (#3044) | unchanged |

`then permit` on the middle row permits **every** source. It was reachable
through the CLI's own `set` path — `set security policies from-zone trust
to-zone untrust policy p1 match source-address` with the value left off — so
an operator hitting enter one token early shipped a permit-any policy. It also
bypassed the #5575 `LenientContentDropped` poison, which used the same
name-based predicate. The schema cannot catch it (see "A multi-value leaf can
be PRESENT and still carry NOTHING" above): the five match dimensions are
untyped `args: 1, multi: true` leaves with no `validator`, and minimum arity is
deliberately out of scope for `schema_walk.go`.

`policyValuelessMatchDimensions(polNode, isGlobal)`
(`compiler_policy_missing_match.go`) is the shared predicate. It flags a
dimension that is present by name but whose values, **unioned across every
`match {}` block** (#3842 parity, via `policyMatchChildren`), are empty —
precisely the condition under which the compiled slice is empty and the
dimension widens. All **five** value-bearing dimensions are covered:
`source-address`, `destination-address`, `application`, plus the scoped-global
`from-zone` / `to-zone`, whose empty set collapses a global policy to the
all-zones wildcard (a fix that closed only `source-address` would leave that
half open). Deliberately excluded: `source-address-excluded` /
`destination-address-excluded`, which are boolean MODIFIER leaves that
legitimately carry no operand. `from-zone`/`to-zone` are inspected only under a
global policy — under a zone-pair policy they are not match siblings at all and
the #3113 unsupported-leaf gate (which runs first) owns them, so one typo is
never double-attributed.

Enforcement follows the #1960 no-brick split, and the finding is emitted from
the SAME walk as #3044 (so the duplicate-block / dual-AST scope coverage can
never diverge between the two) but with a **distinct message** under a
**distinct lenient flag** (`lenientPolicyValuelessMatch`), so "you did not
write the criterion" stays distinguishable from "you wrote it and left the
value off":

- **Strict (commit / commit-check)** — hard reject, naming the policy scope,
  the policy, and every valueless dimension. The operator authored this
  candidate, so surfacing it is the safe choice and matches Junos, where the
  stanza cannot commit.
- **Tolerant (`Store.Load` / HA `SyncApply` peer-sync)** — warn and continue,
  so an already-persisted or peer-synced config an older binary silently
  accepted still BOOTS instead of blacking out the node or alarm-looping config
  sync. There the policy is additionally **poisoned to never-match** by
  `compilePolicy`'s #5575 `LenientContentDropped` flag, so the dataplane
  publishes the rule with the `__unsupported__` sentinel rather than the
  widened permit — the warning is not the only protection on that path.

When a policy trips BOTH findings, the omitted-dimension (#3044) message is
reported first as the more fundamental authoring error.

Regression coverage:
`pkg/config/compiler_policy_valueless_match_6526_test.go` — all five dimensions
through BOTH the flat `ParseSetCommand` + `SetPath` path and the hierarchical
`NewParser` path; a three-way differential (`normal` accepted with its value /
no-operand rejected by #6526 / omitted rejected by #3044) that asserts each
gate's OWN message and forbids the other's, so a finding can never be silently
re-attributed; the lenient warn + `LenientContentDropped` poison; and
false-positive controls for the `-excluded` modifiers, bracketed lists,
duplicate match blocks that supply the value, explicit `any`, and a global
policy that simply omits `from-zone`/`to-zone`.

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
(`pkg/dataplane/userspace/zones_quarantine.go`) applies it to the built snapshot
BEFORE publish: it **drops** the quarantined `ZoneSnapshot`, **unzones** any
interface bound to it (`Zone=""` → default-deny, fail closed), and scrubs the
quarantined zone out of policies (leaving a dangling policy→zone reference would
trip the Rust `UnresolvableZoneReference` preflight and reject the WHOLE snapshot
— a brick on a fresh boot). The policy scrub distinguishes two cases (#5577):
a rule whose **structurally-required** zone is quarantined is **dropped** — the
singular `FromZone`/`ToZone` of a zone-pair rule, or a scoped-global match side
left with **no** surviving member after pruning; but a scoped-global policy's
plural match-zone SET (`MatchFromZones`/`MatchToZones`, #4626 M03) has only the
colliding member(s) **pruned**, so a multi-zone deny scoped from `[z174, z214]`
where only `z214` collides **survives** scoped to `[z174]`. Dropping the whole
rule there would be **fail-open**: surviving-zone (`z174`) traffic would no longer
hit the deny and would reach a later/default permit while the snapshot publishes
successfully. After pruning, the singular `MatchFromZone`/`MatchToZone` is
regenerated from the surviving set (`config.ScopeSingular`) so any reader of the
singular field sees a surviving, non-quarantined zone rather than the dropped
one. That regeneration keeps the two shapes CONSISTENT; it is not a
rolling-upgrade compatibility guarantee. A helper old enough to read only the
singular field cannot receive the snapshot at all — the config-snapshot protocol
version is `4` and both mutating verbs gate on exact equality, and a multi-zone
scope committed against a pre-`4` helper disarms it and aborts the commit
(`ErrScopedGlobalZoneSetProtocolIncompatible`, #5488; see
`docs/userspace-dataplane-architecture.md` *Config-snapshot protocol version*).
The rest of the config still loads (#1960 no-brick).
The id→name reverse maps resolve a colliding id to the survivor deterministically
(`config.StableZoneIDOwner`; `pkg/cli/apply.go:syslogZoneNameMap`,
`pkg/dataplane/userspace/manager_sessionsync_request.go:zoneNameByID`) rather than to whichever
name won a map-iteration race. The quarantine is surfaced to the operator as a
loud one-shot `slog.Error` naming both zones, on `ProcessStatus.ZoneIDCollisions`
(`show`), and as the `xpf_userspace_zone_id_collision` 0/1 gauge, so an operator
is paged until one zone is renamed. Regression coverage:
`pkg/config/zoneid_test.go` (`TestQuarantinedZoneNamesDropsLaterColliding`,
`TestStableZoneIDOwnerReturnsSurvivor`,
`TestZoneIDCollisionLenientWarningStatesQuarantine`),
`pkg/dataplane/userspace/zones_collision_3719_test.go`
(`TestBuildSnapshotQuarantinesCollidingZone`,
`TestQuarantinePrunesScopedGlobalMemberNotWholeRule`,
`TestBuildSnapshotPrunesScopedGlobalMemberFromRealPath` — the #5577
prune-vs-drop guards, RED-on-revert), and
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
`pkg/dataplane/userspace/protocol_policies.go`, Rust `protocol/security.rs`,
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
  - `services flow-monitoring version9 template <t> template-refresh-rate
    seconds` (and the `version-ipfix` twin) — `ValidateInteger(0,
    MaxDurationSeconds)` (**#6769**). This leaf was the one UNTYPED member of
    the trio: its two siblings above already carried a validator, so a refresh
    rate large enough to overflow `time.Duration(n) * time.Second` reached
    `pkg/flowexport`, wrapped, and became a sub-second template ticker. Because
    `gcd(1e9, 2^64) = 512` the wrapped residues are multiples of 512 ns and the
    smallest positive one is exactly 512 ns — `seconds 20211507185753197`
    produced a 512 ns ticker, re-exporting templates thousands of times a second
    at every collector, and the consumer's only guard (`templateRefreshInterval`
    rejecting `<= 0`) does not see a positive wrap. The ceiling is the
    runtime-derived overflow point already used elsewhere in this file, NOT a
    new policy cap ("no schema-only caps"). Two companion layers share the same
    constant: `validateFlowExportSecondsStrict` (`pkg/config`,
    compiler-side defense-in-depth for the tolerant load / peer-sync path and
    direct `CompileConfig` callers, strict-reject / lenient-warn per #1960,
    mirroring #5244) and `flowexport.secondsToDuration`, which falls back to the
    default for an out-of-range value so a running exporter is safe even on a
    config admitted leniently.
  - `security flow tcp-session` expanded to a container: `established-timeout`
    (Rust u64 TCPSessionTimeout), `initial-timeout`, `closing-timeout`,
    `time-wait-timeout` (config-only, not wire-reaching — see **#6539** below)
    all `ValidateInteger(0, MaxDurationSeconds)` — the Duration-overflow ceiling,
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
    not read them. The session table is a 5-tuple flow entry with no
    sequence/window tracking, so there is nothing for any of these knobs to
    enforce or skip. **#2078:** setting any of them emits a
    single accepted-only commit advisory (`pkg/config/compiler.go`,
    `security flow tcp-session ... accepted-only`) so an operator is not
    silently misled; research #2078 converged PLAN-KILL on enforcement.
    (**#6539** narrowed that sentence: it used to say the dataplane has no TCP
    state machine, which #3152 — OPENING vs established — and #3046 — RST vs
    FIN close — have since made false. Those states are precisely why the
    TIMEOUT leaves need a differently-worded advisory.)

    **#6539 — the three unenforced timeout leaves.** `initial-timeout`,
    `closing-timeout` and `time-wait-timeout` are committable but have no wire
    carrier and no consumer, while REST, CLI and gRPC all printed them in the
    same shape as `established-timeout`, which IS carried. That is worse than a
    plainly unimplemented feature: the surface an operator checks after
    committing confirmed the false belief, and `initial-timeout` is the
    half-open / SYN-flood bounding control. `pkg/config/flow_tcp_timeouts_6539.go`
    is now the single authority for the enforced/unenforced split — the commit
    advisory and all three render surfaces read it, so they cannot disagree, and
    a leaf that later gains a carrier loses its annotation everywhere at once.
    The fixed windows the dataplane applies instead (20s half-open, 30s FIN
    close, 2s RST abort, 300s established fallback) are quoted in operator-facing
    text, so a test re-reads them from `userspace-dp/src/session/mod.rs` and
    fails on drift; another in `pkg/dataplane/userspace` fails if any of the
    three starts reaching the wire snapshot without the table being updated. A
    fourth guard walks `setSchema` and fails if a new `*-timeout` leaf is
    declared under `tcp-session` without an entry in the table — otherwise the
    new leaf would render unannotated and reproduce #6539 for itself.
    Enforcing the three is a separate, larger job: `initial-timeout` maps 1:1
    onto `SessionTimeouts.tcp_opening_ns` and could be carried additively, but
    `time-wait-timeout` has no state to attach to (`session_timeout_ns` splits a
    close only into RST vs FIN), so it needs a close-state split in the Rust
    session machine — and a wire bump owes a cluster smoke.
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
    decode-aborting `>u32max`. This typed-leaf gate hard-rejects a negative
    rate at strict operator commit (#1979). Defense-in-depth (#5244): the
    compiler carries a second lower-bound guard
    (`validateSamplingInputRateStrict`, a uniform gate) so `compileSampling`
    matches the sibling `compilePortMirroring` inline guard and the tolerant
    load / peer-sync path (where the typed-leaf gate is downgraded to a
    warning) still names the fail-open consequence. Strict on commit / commit-
    check; lenient-warn on tolerant load / peer-sync (#1960) — a negative rate
    is otherwise a silent fail-open (the exporter's `SamplingRate > 1` 1-in-N
    gate ignores the ratio and exports every eligible flow).
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

**#7145 — malformed literal in a NAT `match` address, on the four slots that
had no gate at all.** #3206 above closed static-NAT `match
destination-address`; #3228 closed destination-NAT `match destination-address`.
The other four (NAT kind x match leaf) slots had NO parse gate, so the SAME
value — `999.1.1.1/24`, or `zznotanaddr`, so this is not a near-miss in the CIDR
grammar — was refused in one slot of a rule and accepted in the sibling slot of
the same rule:

| kind | `match source-address` | `match destination-address` |
|---|---|---|
| `security nat source` | accepted -> **rejected (#7145)** | accepted -> **rejected (#7145)** |
| `security nat destination` | accepted -> **rejected (#7145)** | rejected (#3228) |
| `security nat static` | accepted -> **rejected (#7145)** | rejected (#3206) |

These values are not inert. The Go snapshot builders copy them to the wire
verbatim and each Rust consumer — `parse_match_prefix`
(`userspace-dp/src/nat/source.rs`), `DnatTable::from_snapshots`
(`nat/destination.rs`), `SourceConstraint::from_list` (`nat/static_nat.rs`) —
drops the entry it cannot parse while the `*_constrained` flag stays set from
the non-empty list. A malformed entry therefore NARROWS the rule below what was
authored, and an all-malformed list leaves the rule constrained with zero
prefixes: it matches NOTHING and stops translating, recorded only as a bounded
NAT parse-error counter (#4718).

`validateNATMatchAddressLiteralsStrict`
(`pkg/config/compiler_validate_strict_nat_match_addr.go`, wired into
`runUniformGatesNAT` immediately after the #3228 sibling) rejects it at strict
commit / commit-check, naming the NAT kind, rule-set, rule, match leaf, and
value. Scope is the LITERAL leaves only: `match source-address-name` /
`destination-address-name` are address-book references whose unresolvable raw
token is deliberately appended to the same wire list as a fail-closed backstop
(#2416), so the gate must never walk the post-resolution list.

The acceptance predicate is `net.ParseCIDR` then `net.ParseIP`
(`natMatchPrefixParses`, `compiler_nat_helpers.go`) — the exact Rust pair,
NOT the `netip` equivalents. `netip.ParsePrefix` is stricter than Rust on the
mask text: it rejects a zero-padded prefix length (`1.2.3.4/024`) that Rust's
`u8::from_str` reads as 24 and installs, and a validator that refuses a value
the dataplane installs bricks the operator's next commit on a working box.

Lenient (`Store.Load` / HA peer-sync, flag `lenientNATMatchAddressLiterals`):
warn, do not fail. That value committed clean on every build before this gate,
so boxes carrying one exist by construction. The tolerant path deliberately
KEEPS the value in the compiled config: dropping it would empty an
all-malformed list, clear the Rust `*_constrained` flag and collapse the rule to
MATCH-ANY — a fail-OPEN regression strictly worse than the silent narrowing this
gate is about.

Regression coverage: `pkg/config/nat_match_address_literal_7145_test.go` (the
full 3x2 census at strict, including the two pre-existing gates as controls;
tolerant warn-and-KEEP with the good value intact and the malformed one authored
second; an over-rejection guard that pins `0.0.0.0/0`, `::/0`, a bare host, a
host-bits CIDR and `1.2.3.4/024` still committing) and
`pkg/configstore/nat_match_address_no_brick_7145_test.go` (the no-brick property
at the REAL ingresses — `Store.Load` and `Store.SyncApply` — plus a
`CommitCheck` over-reach guard). The four sites were also removed from
`slotEscapeUngated` (`schema_slot_escape_fixtures_test.go`), so their #7143
slot-escape rows now run the full slot-1 comparison instead of skipping.

**#7216 — a static-NAT rule with NO external prefix.** #7145 and #3228/#3206
cover a `match destination-address` the dataplane cannot PARSE. They say nothing
about one that is not there. Measured at `7230dcdcd` over the same base config,
an explicitly quoted empty value committed clean on static-NAT `match
destination-address` — the only one of the six (kind x leaf) slots that took it:
**#7215 — an out-of-range MASK on the one slot #7145 did not reach.** After
#7145 the six (kind x leaf) slots agreed on a malformed ADDRESS. They still
disagreed on a malformed MASK. Measured at `353f09592` over the same base
config, `10.0.0.0/33` — and `2001:db8::/129`, `10.0.0.0/abc`, `10.0.0.0/`,
`1.2.3.4/-1`, `10.0.0.1/255.255.255.0`, so this is not one arithmetic check
inside Go's mask parser — was refused on five slots and ACCEPTED on
destination-NAT `match destination-address`:

| kind | `match source-address` | `match destination-address` |
|---|---|---|
| `security nat source` | rejected (#7145) | rejected (#7145) |
| `security nat destination` | rejected (#7145) | rejected (#3228) |
| `security nat static` | rejected (#7145) | accepted -> **rejected (#7216)** |

`compileNATStatic` selects `rule.Match` from the authored value, so a quoted
blank makes it `""`; `buildStaticNATSnapshots` lowers that as
`StaticNATRuleSnapshot.ExternalIP`, and the Rust `parse_nat_prefix`
(`userspace-dp/src/nat/static_nat.rs`) returns `None` on it, so `from_snapshots`
`continue`s and drops the WHOLE mapping, recorded only as a bounded NAT
parse-error counter (#4718). The operator authored a rule that does not exist at
runtime, with no commit error and no warning.

**What the empty value means here, established before rejecting it.** #6673's
empty-slot meaning is a COUNTING rule and is untouched — see "KEPT is about the
LIST, not about the SELECTION" above. This gate reads `rule.Match`, the
SELECTION, and never the slot count, so `destination-address [ 192.0.2.1/32 "" ]`
(blank slot, prefix selected) still commits exactly as it did.

**Scope is the SELECTION, not the keystrokes.** Four authoring shapes reach a
surviving rule with `rule.Match == ""` and all four were measured committing
clean and being dropped identically: a quoted `""`, the leaf with no value at
all, a valid prefix followed by a blank that re-selects, and no `match
destination-address` statement at all. The issue names only the first; the gate
covers all four, because a gate that refused the quoted blank and passed the
omitted statement would bind the authoring shape rather than the defect. The
message distinguishes the two remedies (fill the blank vs add the statement).

**Exemptions, each verified covered by its own gate rather than assumed.** NPTv6
(`then static-nat nptv6-prefix`) lowers through `buildNptv6Snapshots`, not the
`static_nat` table, and already rejects an empty or absent match with a
family-specific message; `then static-nat inet` is already rejected outright by
`validateStaticNATInetTargetStrict` (#5859). Both are asserted to STILL reject —
an exemption whose sibling gate has gone away is a hole, not a scope decision.

The gate runs AFTER `validateStaticNATMatchAddressesStrict` so the
two-or-more-prefix blank-selection shape keeps that gate's richer message, which
can name the prefixes being passed over.

Strict on commit / commit-check; lenient on load / peer-sync (warn, sharing
`lenientFirewallRefs` with the sibling static-NAT gates — #1960 no-brick). The
tolerant path leaves `rule.Match` ALONE: the dataplane already drops the rule, so
a leniently-loaded config behaves exactly as it did before this gate, and
substituting anything for the blank would change what installs on a box that is
only being warned at.

Regression coverage: `pkg/config/nat_static_blank_external_prefix_7216_test.go`
(the 3x2 census; all four authoring shapes with their remedies; a #6673
preservation cell; the two exemptions asserted to keep their own messages; an
over-rejection guard; tolerant warn-and-keep) and
`pkg/configstore/nat_static_blank_prefix_boot_7216_test.go` (the no-brick
property at `Store.Load` and `Store.SyncApply`, with a GOOD rule beside the
blank one so the tolerated load is shown to keep translating it, plus a
`CommitCheck` over-reach guard). The `nat static match source-address`
slot-escape fixture gained a valid `match destination-address`
(`slotEscNatStaticSrc`) so its CONTROL still commits.
| `security nat destination` | rejected (#7145) | accepted -> **rejected (#7215)** |
| `security nat static` | rejected (#7145) | rejected (#3206) |

#7145 did not reach it because its probe (`999.1.1.1/24`) is malformed in the
ADDRESS half, which that slot's gate did see. `validateDestinationNAT
AddressesStrict` (#2396(c)/#3228) split the token at the first `/`
(`natCIDRIPPart`) and ran `net.ParseIP` on the address half ONLY, so
`10.0.0.0/33` read as the perfectly good `10.0.0.0`. Its own consumer,
`dnatDestinationParts` (`pkg/dataplane/userspace/nat_destination.go`), calls
`net.ParseCIDR` on any token carrying a `/` and returns `ok == false` — the
entry is SKIPPED and never reaches the wire. The gate's doc comment claimed the
two matched exactly; they did not, and a comment cannot fail.

The gate now calls the same `natMatchPrefixParses` the other four slots use,
which is extensionally EQUAL to `dnatDestinationParts`'s `ok` (a maskless token
falls through `net.ParseCIDR` to the same `net.ParseIP`; a masked token can
never satisfy `net.ParseIP`, so it reduces to the same `net.ParseCIDR`). That
equality is now bound by a cross-package differential,
`pkg/dataplane/userspace/dnat_gate_builder_agreement_7215_test.go`, which fails
on a disagreement in EITHER direction: `gate accepts / builder drops` is #7215,
`gate refuses / builder installs` is the #1960 brick.

The change is strictly a NARROWING, and every value it newly refuses is one the
builder already discarded. It refuses nothing the dataplane installs —
`0.0.0.0/0`, `::/0`, a bare host, a host-bits CIDR and `1.2.3.4/024` all still
commit, which is why the mirror stays `net.ParseCIDR` and not
`netip.ParsePrefix`. Lenient (`Store.Load` / peer-sync) needed no new plumbing:
the slot's existing `lenientDestNATAddresses` flag downgrades it to a warning
and KEEPS the value.

Regression coverage: `pkg/config/nat_dnat_match_destination_mask_7215_test.go`
(the full 3x2 census at strict with the five unchanged slots as controls;
tolerant warn-and-KEEP with the malformed value authored SECOND so the gate is
pinned to walk the whole bracket list; an over-rejection guard) and
`pkg/configstore/nat_dnat_match_mask_boot_7215_test.go` (the no-brick property
at `Store.Load` and `Store.SyncApply`, plus a `CommitCheck` over-reach guard).

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
  {`junos-bgp`, `junos-rip`, `junos-ldp-tcp`, `junos-ldp-udp`}, and (#5634)
  `junos-sip` = {`junos-sip-udp`, `junos-sip-tcp`} (both destination-port 5060 —
  SIP signals over UDP by default and TCP since 12.3X48-D25 / 17.3R1). Every
  member is in the `PredefinedApplications` table, so each set expands to >= 1
  member and clears the empty-set fail-open gate (#3146). `junos-sip` was the
  one predefined name MOVED from the application table to the set table:
  `resolveUserspaceApplicationNames` resolves an application first, so a
  UDP-only `junos-sip` application would shadow the set and re-drop TCP/5060 —
  it must be a set only (`predefined_sip_5634_test.go`). Before #4102 only the
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

### #5574 — conflicting duplicate DIRECT scalar leaf (the direct-body analogue of #3366)

The #3366 duplicate-scalar detection above covered only the inline `term` path.
The **direct** (scalar) match body had the identical hole: `compileApplications`
assigns each direct leaf straight into a SINGLE typed field
(`app.Protocol = nodeVal(prop)`, `app.DestinationPort = resolveAppPort(...)`,
...) while iterating sibling leaves, with no value-aware duplicate tracking. So a
direct application carrying repeated CONFLICTING scalars —
`application X { protocol tcp; protocol udp; destination-port 22;
destination-port 53; }` (also `source-port` / `inactivity-timeout` / `timeout` /
`icmp-type` / `icmp-code` / `alg`) — committed cleanly under strict validation
but enforced **only the last value** (`protocol udp destination-port 53`). A deny
referencing that application then covered FEWER protocol/port combinations than
authored, so `tcp/22` fell through to a later permit / `default-policy
permit-all` (a fail-open under-match). `validateApplicationStructureStrict`
checked mixed direct+term (#3366) and the term-only duplicate marker, but had no
direct-body duplicate marker.

`compileApplications` now tracks each direct scalar leaf's first assigned value
and records a CONFLICTING repeat (a second occurrence with a DIFFERENT effective
value) on `Application.DuplicateDirectLeaves`; the same
`validateApplicationStructureStrict` gate hard-rejects the first one, naming the
leaf. Details matching the #3366 term model:

- **`protocol` IS tracked here** (it is EXCLUDED in the term path). The direct
  body has no multi-protocol syntax — `Application.Protocol` is a single field, so
  a second `protocol` silently overwrites rather than minting a per-protocol term.
- **Value-aware, not value-blind.** An IDEMPOTENT same-value restate
  (`protocol tcp; protocol tcp`, `destination-port 22; destination-port 22`, the
  `inactivity-timeout 1800` + `timeout 1800` alias pair, or an alias that
  normalizes to the same protocol such as `icmp` / `junos-icmp-all`) is harmless
  and COMMITS — only a differing repeat is rejected. Ports are compared in their
  resolved form and timeouts/icmp in their parsed form, matching the field each
  is stored in.
- **Only reachable via the hierarchical AST shape.** The direct scalar leaves are
  `args:1, children:nil, non-multi` in `setSchema`, so `tree.SetPath` REPLACES a
  single-value leaf (last-wins) — two flat `set` lines collapse to ONE node
  before the compiler runs. The duplicate-sibling shape this gate catches comes
  from a hierarchical config file / `load` / paste, an apply-groups merge, or a
  peer-synced serialized config, all of which preserve both siblings. Regression
  tests therefore parse hierarchically (`hierTree`), a deliberate deviation from
  the flat-set-only testing convention (which governs flat-set token grouping,
  not a drop flat-set structurally cannot carry).

Scope, strictness, and lenient downgrade are identical to the #3366 checks it
sits beside (ALL user apps; strict on commit / commit-check, `cfg.Warnings`
downgrade on the tolerant load / HA peer-sync path via `lenientApplicationSpecs`,
#1960 no-brick). Regression coverage:
`pkg/config/compiler_application_direct_conflict_5574_test.go` (each scalar leaf
rejected; referenced deny under-match rejected + keep-last characterization;
unreferenced rejected; idempotent restate / alias-normalized / single-valued
accepted; lenient path downgrades to a warning — each RED on revert).

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
live CoS state rather than building a classifier for the wrong class. Since
#5193 the DSCP **rewrite-rule** ingest carries the same bound
(`SnapshotIntegrityError::CosDscpRewriteCodePointOutOfRange`, naming rule /
forwarding-class / value): it stores no table to index, so it compares against
`COS_MAX_DSCP_CODE_POINT` (63) directly, and the whole rule is validated before
any entry is inserted so a bad entry cannot install a partial rule. Without it
the classifier side failed closed while the rewrite side accepted 110 and the
transmit helper masked it to DSCP 46 — remarking egress packets into a
different PHB than configured. This is
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

**F-3b — CoS `inet-precedence` + `exp` (#4316, classifier half ENFORCED in
#6847).** Added `classifiers inet-precedence`, `rewrite-rules inet-precedence`,
and `rewrite-rules exp` to `schemaClassOfService` (completion + `?` help).

The two REWRITE directions remain **accepted-but-inert** — the userspace
dataplane rewrites `dscp` on egress only. Their names are recorded on
`ClassOfServiceConfig` (`INetPrecedenceRewriteRules` / `EXPRewriteRules`)
solely to drive a commit advisory; no runtime structure is built.

The `classifiers inet-precedence` half is **enforced since #6847**. #4316
recorded only the classifier NAMES, and the unit-level `classifiers` schema
node had no `inet-precedence` child at all — so the classifier was definable
but NOT bindable, and `set class-of-service interfaces <if> unit <n>
classifiers inet-precedence <name>` was rejected by the schema (an imported
vSRX config failed at the bind line). #6847 added the unit binding site,
compiled the code-point entries into `INetPrecedenceClassifierDefs`
(`CoSINetPrecedenceClassifier` / `...Entry`), published them on the wire as
`inet_precedence_classifiers` + the per-interface
`cos_inet_precedence_classifier`, and made the dataplane classify on the top
3 bits of the DS field (`resolve_cos_inet_precedence_classifier_queue_id`,
`(dscp >> 3) & 0x7`). The entry's `loss-priority` drives the egress rewrite
like the dscp / 802.1p classifiers. The matching accepted-but-inert advisory
was retracted with it.

Because that `loss-priority` is now LIVE it is covered by
`validateClassOfServiceLossPriorityStrict` alongside the dscp / ieee-802.1
classifiers and both rewrite-rule directions: an unrecognized value (an
operator typo such as `hgih`) is hard-rejected at commit, and downgraded to a
warning on the tolerant `Load` / `SyncApply` path. Without that arm the helper
maps the unknown string with `cos_loss_priority_index(...).unwrap_or(0)` and
silently applies the LOW rewrite row — the accepted-but-silently-substituted
drop precedence the classifier's loss-priority arm exists to remove.

A unit may bind **at most one** of `classifiers dscp` and `classifiers
inet-precedence`: IP precedence is the top 3 bits of the same DS field DSCP
reads, so the two are alternative interpretations of one field rather than
composable classifiers. `validateCoSUnitClassifierConflict` hard-rejects the
combination at commit; the tolerant `Load` / `SyncApply` path downgrades it to
a warning (`lenientCoSUnitClassifierConflict`) so an already-persisted or
peer-synced config still boots (#1960), and DSCP wins on that boot because the
BA chain consults it first.

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
  `facility-override` are recognized-and-skipped, and `archive` is
  recognized-recorded-and-warned (see #7146 below). The
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

## Syslog file `archive` is accepted-but-inert (#7146)

The `archive` sub-statement of `system syslog file <name>` is modeled in
`setSchema` in full — `files`, `size`, `start-time`, `transfer-interval`,
`archive-sites` (`multi: true`), `world-readable` / `no-world-readable` — and
is implemented by **nothing**. The #4303 S-1 work above put `archive` in
`compileSystem`'s recognized-modifier skip list so it would not be captured as
a bogus `<facility> <severity>` pair, but no consumer was ever written: the
whole subtree was read and discarded. Every knob committed clean, rendered back
in `show configuration`, and produced no rotation, no retention, and no
off-box transfer. An operator who configured log archival got a clean commit
and no archiving.

The runtime for a syslog file is `applySyslogFiles` (`pkg/daemon/daemon_system.go`),
which writes an rsyslog drop-in (`/etc/rsyslog.d/10-xpf-<name>.conf`) directing
matching facility/severity messages to `/var/log/<name>` — and nothing else.
There is no rotation, size accounting, schedule, or transfer anywhere in the
daemon for a syslog file. (The `archiveConfig` / `archiveTransfer` machinery in
`pkg/daemon` is the **unrelated** `system archival configuration` feature, which
archives the running **config**, not logs, and does work.)

#7146 keeps the block unimplemented and makes it **loud**, the same
accept-with-advisory shape as #4316:

- **compiler** — `compileSystem`'s syslog `file` loop switches `archive` out of
  the skip list into its own case. It sets `SyslogFileConfig.ArchiveConfigured`
  (presence: a bare `archive;` is archiving-with-defaults in Junos, so presence
  alone is what the operator asked for) and records the sub-statement
  **keywords** in `SyslogFileConfig.ArchiveKnobs` (sorted, deduplicated).
  `syslogArchiveTokens` flattens the subtree depth-first pre-order so ONE walker
  covers every shape the dual AST produces for the same stanza — the flat block
  (`Keys=["archive"]` + sibling children), the flat compact form
  (`archive size 1m files 5` → a NESTED key chain, not siblings), the
  hierarchical block, and the hierarchical one-line form
  (`archive size 1m files 5;` → all tokens on `Keys`, no children).
  `syslogArchiveKnobs` then walks those tokens against the
  `syslogArchiveKeywordArgs` allowlist, stepping over each keyword's value so an
  `archive-sites` URL that happens to equal a keyword is not read as one.
- **keywords only, never values** — an `archive-sites` URL can embed credentials
  (`scp://user:pass@host/`), and the advisory is printed at commit and pasted
  into support tickets. This is the same rule `systemInertKnobWarnings` applies
  to the NTP `authentication-key`.
- **advisory** — `ValidateConfig` (`compiler_validate_warn.go`) emits one
  warning per archiving file naming the file, the configured knobs, and the
  consequence:

  ```
  system syslog file "f1" archive [archive-sites files size start-time transfer-interval]:
  accepted for Junos compatibility but NOT implemented — xpf writes /var/log/f1
  through an rsyslog drop-in and applies no rotation, no size cap, no retention
  count, no start-time schedule, and no off-box transfer, so this log file is
  never rotated and its contents are NOT archived anywhere. The configuration is
  valid and this is expected, not a fault in it; rotate and collect /var/log/f1
  with the host's own log policy (#7146)
  ```

- **warn, never reject** — the stanza commits today. A hard reject would fail
  the tolerant load / peer-sync path on a config an operator already has, which
  is the #1960 brick-on-upgrade shape.
- **not a CWE-88** — the #4589 leading-dash gate on `system archival
  configuration archive-sites` exists because that value is handed to `scp` as a
  destination (`pkg/daemon/daemon_flow.go`). The syslog leaf has no such gate and
  does not need one: it reaches no `scp` invocation because it reaches nothing at
  all. Implementing archival would change that and would then owe the #4589
  treatment.
- **tests** — `pkg/config/syslog_archive_inert_7146_test.go`: the advisory fires
  in all four AST shapes and for a bare `archive`, one per file, never on the
  common case (a plain facility/severity file, a `host`/`user` destination,
  `system archival configuration`, or no syslog block), never echoes a value,
  and the commit still succeeds.

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
  (neutral) — ignoring an ADDITIVE grant can only under-grant, so it is
  fail-closed. The advisory says nothing about `deny-commands` /
  `deny-configuration`; the pre-#5831 "MORE PERMISSIVE" advisory for those two
  is **gone**, not reworded.
- **restrictive-regex gate (#5831)** — `deny-commands` / `deny-configuration`
  are RESTRICTIVE, so ignoring them over-grants. `validateLoginClassDenyStrict`
  hard-**rejects** them at commit / commit-check (keyed on leaf PRESENCE, so
  `deny-commands ""` and a valueless `deny-commands` are caught too — an empty
  POSIX regex denies *everything*). On the tolerant load / peer-sync path
  (#1960 no-brick) `foldLoginClassDenyToRepairableFloor` **folds** the class to
  `{view, configure} ∩ what it already held` and warns. That is a blast-radius
  reduction, **not** enforcement: `clear` / `control` / `maintenance` / `all`
  are dropped, but the two RETAINED buckets are levels at which the statement
  does nothing — `deny-configuration` targets `configure`, and a
  `deny-commands` naming `show` / `ping` / `traceroute` / `monitor` targets
  `view`. Both are retained because they are what an operator needs to delete
  the statement. The warning is generated FROM the retained set
  (`loginClassDenyFoldWarning`) so the claim can never be wider than the
  behaviour. Full per-command deny enforcement is a follow-up on #5831.
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

## `system dataplane control-socket` typed as a socket path (#5839)

`control-socket` was an untyped `{args: 1}` leaf, so any string committed and
reached the dataplane verbatim. Three shapes are pathological:

- a **relative** path — the daemon dials it and the Rust helper binds it from
  two separate processes, each resolving it against its own working directory;
- a `..` **traversal** — the path is handed to the stale-socket unlink at every
  helper bring-up, so a stored config could aim that unlink outside the runtime
  directory the path appears to name;
- a path over the **107-octet AF_UNIX `sun_path` limit** — it can never bind, so
  it surfaces as an opaque dataplane bring-up failure rather than a commit error.

The leaf is now `valueType: ValueUnixSocketPath` with the
`ValidateUnixSocketPath` validator (`schema_validators_system.go`): absolute, no
`.`/`..`/empty component, no trailing `/`, no control characters, within the
`sun_path` limit. `?`-completion gains the `<socket-path>` placeholder plus an
example.

Per the #1960 layered-defense doctrine this is **strict-on-commit,
lenient-on-load**: `compileTreeLenient` warns and keeps booting a stored or
peer-synced config carrying a stale value, so typing the leaf cannot brick a
node. The gate is therefore NOT what protects the runtime — the dataplane's
`removeStaleUnixSocket` re-judges the path defensively at every bring-up
(refuses a non-socket, refuses a live listener's socket, never discards an
unlink failure; see `docs/userspace-dataplane-architecture.md` "Socket path
handling"). That runtime layer is what a value which never passed through a
strict commit runs into.

- **tests** — `pkg/config/control_socket_typed_5839_test.go` (validator
  accept/reject table including the exact 107/108-octet boundary, plus the
  leaf driven through `SchemaValidate` + `CompileConfig` so it is pinned as
  WIRED, not merely defined).
