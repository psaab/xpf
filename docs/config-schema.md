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

The live config-mode completers — `pkg/cli` `completeConfigWithDesc` and
`pkg/grpcapi` `completeConfigPairs` — route `set` paths through
`config.CompleteSetPathWithValues` over `setSchema`. `cmdtree.ConfigTopLevel`
only supplies the config-mode TOP-LEVEL keywords (`set`/`delete`/`commit`/
`load`/...) plus the retained `set system dataplane` description overlay.

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
  validation. (This is why scheduler `buffer-size temporal` was NOT carried
  over: the compiler never reads it.)
- **Validators live in `pkg/config/schema_validators.go`** and are stateless
  string-checkers reusing the compiler's parsers. Add a generic one
  (`ValidateInteger(min,max)`, `ValidateEnum([...])`, the IP family
  validators `ValidateIPAddress` / `ValidateIPv4CIDR` / `ValidateIPv6CIDR`)
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
  without validation — typing them needs a new walker feature),
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
  persistent-keepalive); (b) **firewall**: the `then forwarding-class`
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
- **#1746:** added the `class-of-service schedulers <s>
  equal-flow-target-policy (slowest | mean | ideal-share)` typed enum
  leaf (ValueEnumOf + `ValidateEnum`, same recipe as the scheduler
  `priority` leaf): value-slot completion, flat-set commit-check
  rejection of unknown values, plus a strict-compile re-check for
  externally-assembled configs.
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
  - IKE (`security ike proposal`) and IPsec (`security ipsec proposal`)
    crypto leaves — `authentication-method` (IKE only, enum
    `pre-shared-keys|rsa-signatures|ecdsa-signatures`, matching
    `authMethodToSwan`), `dh-group`, and `lifetime-seconds`
    (`ValidateIntegerMin(1)` — 0/garbage previously silently compiled to
    0). The two `dh-group` leaves are validated DIFFERENTLY, on purpose, to
    stay compiler-faithful (the gate must match what each compiler loop
    actually parses):
    - IKE `dh-group` — `ValueDHGroup` + `ValidateDHGroup`. The IKE compiler
      loop (`compiler_ipsec.go` `compileIKE`) strips a leading `group`
      prefix before `strconv.Atoi`, so both the bare-integer (`14`) and the
      Junos `group<N>` (`group14`) spellings compile identically; the
      validator accepts both and rejects 0/garbage that would drop the
      modp term.
    - IPsec Phase-2 `dh-group` — plain positive integer (`ValueInteger` +
      `ValidateIntegerMin(1)`). The Phase-2 compiler loop (`compileIPsec`)
      parses it with a bare `strconv.Atoi` and does NOT strip the `group`
      prefix, so `group14` would compile to `DHGroup=0` and silently drop
      PFS/modp. The schema rejects the `group<N>` spelling for Phase-2 PFS
      rather than admit a value the compiler cannot honor.
    `protocol` and `encryption-algorithm` / `authentication-algorithm` stay
    UNTYPED: the swanctl renderer normalizes arbitrary algorithm spellings
    by string substitution, so an enum there would false-reject valid
    configs.
  - `security nat static rule-set rule match` — declared the
    `source-address` / `destination-address` children the static-NAT
    compiler reads (the subtree was previously unreachable by the walker).
  - `protocols router-advertisement interface` — typed the
    second-denominated leaves (`max/min-advertisement-interval`,
    `default-lifetime`, `link-mtu` via `ValidateIntegerMin(1)`) and
    declared the remaining compiler-consumed structural children
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
- **#1387 (DHCP dynamic-DNS, increment 1):** added an opt-in
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
  - `backend` — `ValueEnumOf` + `ValidateEnum(rfc2136 | kea-d2)`. `kea-d2`
    is a RESERVED enum value (the live backend is `rfc2136`, increment 2;
    Kea D2 is not in the image). The enum accepts it so a config naming it
    commits, but increment 1 implements only `rfc2136`.
  Deliberately UNTYPED (free-form `args:1` leaves), with reasons in
  `schema_system.go`: `domain`, `update-server`, `tsig-key`,
  `tsig-algorithm`, `tsig-secret`. The live rfc2136 backend that would
  constrain `update-server` (host[:port]) lands in increment 2, and a
  hostname / base64 secret is not validatable by the existing IP/identifier
  validators without false-rejecting valid input. `tsig-secret` is
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
the marshalled struct, and are deliberately OUT OF SCOPE (operators read
their own secrets — Junos parity; `show configuration` redaction is a
separate concern).

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
    NOT u64-max, because the helper multiplies `secs*1e9` unchecked; plus the
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
raise-threshold <= 100`:

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
accept-with-warning + valid-no-warning). The runtime consumer (#2079) is
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
  table). A non-IP token (an address-book name) is left to the existing address
  handling.
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

Regression coverage: `pkg/config/compiler_nat_host_mask_test.go` (bare/​/32/​/128
accept; v4 + v6 non-host match/prefix reject with asserted message; NPTv6 and
`inet` exemptions; NAT64 source-pool host vs non-host; strict-reject /
lenient-warn / valid-no-warning; `isHostMaskAddress` table). Like
`pool-utilization-alarm`, this is compiler-side only — not yet a typed
`setSchema` leaf.

## The `inactive:` universal node modifier (#2008 H1)

`inactive:` is the Junos deactivate-without-delete marker and is NOT a
schema leaf — it is a UNIVERSAL node modifier that can prefix ANY statement
at ANY position, so it lives OUTSIDE `setSchema` entirely. The parser
(`parser.go`) recognizes a leading `inactive:` token, lifts it into
`Node.Inactive`, and leaves the node's real `Keys` intact. Because the
modifier never appears in the node's identity, the `setSchema` walk, the
flat-set token grouping, and the value-slot `?` completion are all
unaffected — they continue to see the node's real keyword.

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
"deactivate".

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
