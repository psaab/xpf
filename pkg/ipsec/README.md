# pkg/ipsec

strongSwan integration. Generates `swanctl.conf` from the typed config
(IKE proposals, traffic selectors, DPD profiles, NAT traversal, XFRM
interface IDs) and queries SA/SP state via `swanctl`.

The conf write is AtomicGeneratedConfig (#1894):
`fsatomic.WriteFileAtomic` — strongSwan never parses a torn file, and
the apply path pays no fsync (the file is regenerated on every apply).

## Entry points

- `Manager` — `manager.go`.
- `New()` — `manager.go`. Default swanctl conf dir
  `/etc/swanctl/conf.d`.
- `Apply(ipsecCfg *config.IPsecConfig) error` — `manager.go`. Generate
  config and reload strongSwan, then terminate the live SAs of any
  connection that departed the rendered/loaded set since the last Apply —
  whether the operator DELETED it (#3941) or it became UNRENDERABLE and was
  omitted from the render (#5494). **The returned error is
  load-bearing (#4433):** a render/write/`swanctl --load-all` failure leaves
  the previously-loaded strongSwan config (the OLD tunnels) active, so the
  commit path (`daemon_apply.go` step 6) MUST surface this error rather than
  swallow it at WARN — otherwise a new config is reported committed while the
  enforced IPsec runtime is stale. The daemon joins it into the
  `applyConfigLocked` tail result alongside networkd / Kea / host-inbound /
  lo0 (fail-closed on commit); the config stays promoted + peer-synced and the
  remaining reconcile steps still run, so the operator sees a degraded-state
  error instead of a false success. **The empty-clear branch is symmetric
  (#4898):** deleting the last VPN routes `Apply(nil)` → `clearConfig`, which now
  RETURNS the `swanctl --load-all` error (it previously did `_ = m.reload()` and
  reported success). Promotion of `prevConnNames` and removed-SA termination are
  gated on reload SUCCESS — a failed reload leaves the OLD config effective, so
  the applied-name set is preserved and no SA is torn down, letting the next
  successful Apply/Clear retry the diff + teardown. **A FAILED terminate is
  also load-bearing (#6542):** the failed subset becomes teardown DEBT
  (`pendingTerminate`) that the next Apply folds back into its removed set,
  and Apply RETURNS the failure instead of reporting success over a stale SA
  that is still forwarding.
- `Clear() error` — `manager.go`. Remove the xpf snippet, reload, and
  terminate every previously-applied connection's live SAs (#3941). Like Apply,
  a reload failure is returned and skips promotion/termination (#4898), and a
  failed terminate is carried as debt and returned (#6542).
- `SAStatus`, `TerminateAllSAs`, `InitiateConnection`, `GetSAStatus`,
  `ActiveConnectionNames` — `ike.go`.
- `PrepareConfig(cfg *config.Config) *config.IPsecConfig` — `policy.go`.
- `ApplyWithHooks(ipsecCfg, hooks ApplyHooks) error`, `ApplyHooks{Written, Loaded}` and
  `ApplyNotifyLoaded(ipsecCfg, loaded func()) error` — `manager.go`. `Apply` with callbacks
  at the two points where the on-disk swanctl config and what charon runs can diverge.
  `ApplyNotifyLoaded` is `ApplyWithHooks` with only `Loaded`.
  - `Written` runs once the on-disk config has CHANGED (the new file written, or removed
    for an empty config) and BEFORE the reload. From then until a successful reload,
    charon runs a generation that is not the file on disk, and its own next start or
    reload (`strongswan.service` `ExecStartPost`/`ExecReload` `swanctl --load-all`) loads
    the file. That is the #9511 stopgap window. It does not run on a render or write
    failure.
  - `Loaded` runs the moment strongSwan has LOADED the config: right after the loaded
    connection set is promoted and before departed connections are torn down (#9511).
    It does not run on a failed reload, and it does run when the apply then returns
    teardown debt (#6542).
  - The daemon records the loaded config for HA IPsec attribution from these hooks.
    `SetSwanctlForTesting` (`test_seams.go`) installs the swanctl exec double for other
    packages' tests.
- `ApplyGeneration(ipsecCfg, generation string, hooks ApplyHooks) error` — `manager.go`,
  marker in `generation.go` (#9641). `ApplyWithHooks`, and the file it writes ends with an
  inert **generation marker**: `pools { xpf-gen-<generation> { addrs = 192.0.2.1/32 } }`.
  No connection references the pool, so no SA can lease from or negotiate against it, and
  a pool is not a connection. strongSwan 6.0.5 loads and lists it
  (`testdata/swanctl_list_pools_*_9641.*`). `generation` must be a 64-hex config digest
  (the daemon passes the configstore digest of the active config it applies). Anything
  else, and `ApplyWithHooks`/`Apply`, writes `xpf-gen-unknown`. The marker is appended to
  the render, not rendered inside it, so `renderConfig`'s other consumers are unchanged,
  and the empty-config clear path removes the file, so charon then lists no marker. An
  xpf node's `swanctl --list-pools` therefore shows one `xpf-gen-*` pool with no leases;
  that is expected.
- `LoadedGeneration() (string, error)` — `generation.go`. `swanctl --list-pools --raw`
  (stdout-only seam, `swanctlTimeout`): the generation the single loaded marker names.
  Errors: `ErrNoGenerationMarker` (no xpf-written file loaded, or one from an older xpf),
  `ErrAmbiguousGenerationMarker`, or the exec error when charon cannot be asked. The marker
  is IDENTITY, not proof: `--load-all` is not a transaction, so a partial load can leave
  the pool and the connections at different generations.
- `ListLoadedConns() (LoadedConns, error)`, `LoadedConns`, `(LoadedConns).SANames()`,
  `(LoadedConns).Equal(o) bool` — `list_conns.go`, `generation.go`. What
  `swanctl --list-conns --raw` reports: each loaded connection's children and
  `local_addrs`/`remote_addrs`. `Equal` compares connection names exactly and each list as
  a multiset. An unreachable charon is an error, never an empty set.
- `ExpectedLoadedConns(cfg *config.Config) (LoadedConns, error)` — `generation.go`. What
  charon lists once it has COMPLETELY loaded cfg as xpf renders it, which is the
  validation a marker needs. The candidate renders as a whole: a hard render error is
  returned, and a skipped VPN is excluded. Local addresses are replayed from configuration
  alone (`prepareConfigFromConfig`, `policy_addr.go`, mirroring `PrepareConfig`'s
  configured-address-first resolution). When a rendered connection's local address could
  have come from the kernel (an unconfigured interface address, e.g. DHCP) or from a
  DNS-derived family hint, the result is `ErrGenerationUnvalidatable`. Checked against
  real 6.0.5 captures, including a local-address move that keeps every name.
- `SANameIndex`, `BuildSANameIndex(ipsecCfg) SANameIndex`,
  `(SANameIndex).VPNs(saName) []string`, `(SANameIndex).Collisions() []string` —
  `policy.go`. The inverse of the render (#9511): every SA name
  `swanctl --list-sas` can report for a config (each rendered connection name and
  each rendered child SA name) mapped to the configured VPNs that render it.
  `ActiveConnectionNames` publishes child names once a connection has children (a
  multi-selector VPN's are `<vpn>-<selector>`), and the connection name only for an
  IKE SA with no child yet, so the HA per-RG attribution maps names back here.
  Eligibility is decided by rendering each VPN on its own: a VPN the renderer skips
  contributes no name; a VPN whose render fails outright keeps its names as
  candidates (a failed Apply leaves the previous swanctl config loaded); and two VPN
  names that sanitise alike cannot borrow each other's result. A name two VPNs
  render (`a` + selector `b-c` and `a-b` + selector `c`; or `blue` + selector `red`
  and `blue-red`) lists both, and the index never picks one.

## Module layout (#1989)

The package is split by responsibility (one responsibility per module);
all files stay in `package ipsec`, so the public API is unchanged.

- `manager.go` — transactional SA-config reconciler: `Manager`
  lifecycle (`New`/`Apply`/`Clear`/`reload`), the removed-connection
  diff + live-SA teardown (`promoteConnNames`/`terminateRemovedConns`,
  #3941; promotion gated on reload success, #4898), and the `swanctl`
  shell-out helper (`runSwanctl`, the `sc` seam, `swanctlTimeout`).
- `ike.go` — IKE/ESP settings resolution + proposal builders
  (`resolveIKESettings`/`resolveESPSettings`/`deriveDPD`/`buildESPProposal`/
  `dhGroupBits`) and the SA-status query + `swanctl --list-sas` output
  parsing (`SAStatus`/`GetSAStatus`/`parseSAOutput` + the line helpers
  `parseIKEHeader`/`parseChildHeader`/`parseEndpointHost`/`parseTrafficLine`,
  `TerminateAllSAs`/`InitiateConnection`/`ActiveConnectionNames`). The parser
  is pinned to captured golden fixtures in `testdata/swanctl_list_sas_*.txt`.
- `crypto.go` — **isolated** Junos `$9$` pre-shared-key decryption
  (`normalizePSK`/`decodeJunosSecret`/`junosGap`/`junosGapDecode` and the
  `$9$` alphabet tables). Kept in its own file so the decryption surface
  is auditable and unit-testable without pulling in the swanctl/XFRM
  machinery.
- `policy.go` — swanctl config generation (`renderConfig`/`generateConfig`,
  traffic-selector resolution, value sanitizers, identity formatting,
  `authMethodToSwan`, `xfrmiIfID`) plus XFRM bind-interface preparation
  (`PrepareConfig` and its interface-address resolvers).

## Callers

`pkg/daemon` (lifecycle), `pkg/grpcapi` (show / request commands).

## Dependencies

`pkg/config` only.

## File layout

- Writes `/etc/swanctl/conf.d/xpf.conf` with mode 0600.
- Reloads via `swanctl --reload`.

## Gotchas

- **Deleting a VPN must TERMINATE its live SAs, not just unload the
  config (#3941).** `swanctl --load-all` UNLOADS a removed connection's
  config but leaves its already-established IKE/child SAs installed — the
  deleted tunnel keeps forwarding until rekey/lifetime expiry (a security
  gap: a VPN removed for a compromised peer / decommissioned site stays
  up). `Apply` therefore remembers the previous LOADED connection-name
  set (`prevConnNames`) and on each apply diffs it against the set
  `renderConfig` actually emitted. `Apply`/`Clear` reload FIRST and only on
  reload success advance `prevConnNames` and tear down departed SAs
  (`promoteConnNames`, #4898) — so the departed conn is unloaded and cannot
  re-initiate before teardown, and a failed reload leaves the old set intact
  rather than forgetting a still-loaded connection or disrupting a
  still-effective tunnel. `terminateRemovedConns` then queries live SAs and
  issues `swanctl --terminate --ike <conn>` only for a departed conn that
  actually has a live SA — so deleting a VPN that was never up is a clean
  no-op. If the live-SA query fails, it falls back to an unconditional
  (idempotent) terminate. Modified/added connections are untouched — only
  departures are torn down. All swanctl shell-outs route through the `sc`
  seam so the diff→terminate path is unit-tested against recording doubles
  (`delete_terminate_3941_test.go`, `manager_reload_ordering_4898_test.go`).

- **A FAILED terminate is teardown DEBT, not a log line (#6542).**
  `promoteConnNames` advances `prevConnNames` to the newly-loaded set the
  moment the reload succeeds, so a departed name is gone from the only record
  of "what was loaded" after exactly ONE apply. `terminateRemovedConns` was
  fire-and-forget: a `swanctl --terminate` that errored was logged at WARN and
  dropped, `Apply` still returned nil, and no later reconcile ever retried —
  the departed VPN kept forwarding under its stale child SA until rekey /
  lifetime expiry while the commit reported success. This is the
  "advance-then-act, lose the debt" family: the marker advanced on a path that
  was not verified-success.

  The failed subset is now recorded in `pendingTerminate` and UNIONED into the
  next apply's removed set by `promoteConnNames`, so the teardown is retried
  every reconcile until it succeeds. `Apply`/`Clear` return the failure
  (`recordTerminateDebt`), which the commit path joins into its tail result the
  same way it joins a failed reload (#4433) — the operator sees the degraded
  IPsec state instead of a false success.

  Two properties keep the debt from latching or misfiring:
  - It **discharges** when the departed connection is no longer live —
    `terminateRemovedConns` only terminates (and only charges debt for) a
    removed name that `--list-sas` actually reports, so an SA that died on its
    own clears the debt silently rather than failing every future commit. The
    ambiguous `--list-sas`-failed fallback (unconditional terminate, where a
    "no matching SA" error is indistinguishable from a real failure) is
    likewise self-clearing: the next apply enumerates and discharges.
  - It **never terminates a LOADED connection** — both halves of the removed
    set are filtered by the newly-loaded names, so an operator re-adding the
    VPN discharges the debt instead of tearing the restored tunnel down.

  Covered by `terminate_debt_6542_test.go`.

- **The diff keys off the RENDERED set, not the raw VPN name (#5494 —
  FLIPS the prior #3941 name-keyed behavior).** `renderConfig` returns the
  EXACT set of connection names it emitted; `Apply` diffs THAT. A VPN that
  is still present in the config but dropped out of the render as
  UNRENDERABLE on the tolerant persisted / peer-synced load path — an
  unresolvable gateway reference (#2074), a broken ike-policy chain (#2270),
  or a `protocol ah` proposal with no ESP render path (#4298) — is neither
  loaded nor validated by `swanctl --load-all`, yet the reload SUCCEEDS.
  Under the old name-keyed diff its live child SA kept forwarding under
  now-unloaded (stale) selectors/credentials while the apply reported
  convergence — a security fail-open. Such a VPN is now treated as a
  departure and its SA is torn down. This deliberately trades a sliver of
  availability for security: a transiently-unrenderable VPN's SA is torn
  until its config becomes renderable again, but an unrenderable VPN is
  already non-functional for rekey / new-SA establishment, so keeping a
  stale authorized SA is a hole, not a real availability win. The #4898
  reload-success gate is preserved (a FAILED reload still tears nothing —
  the old config is still effective) and #3941 genuine-deletion teardown is
  unchanged. Covered by `unrenderable_terminate_5494_test.go`.
- **`parseSAOutput` is fed STDOUT ALONE, on both of its call paths (#9068).**
  One parser was reached through two different exec channels: `GetSAStatus`
  used a stdout-only buffer with the comment *"the parser needs stdout alone"*,
  while `liveConnNames` — on the security-critical TEARDOWN path — routed
  through `CombinedOutput`, justified in place by *"parseSAOutput ignores any
  unrecognized stderr lines CombinedOutput may fold in"*. That justification
  was asserted and never tested, and it is true for WHOLE stderr lines and
  false in the one direction that matters: a mid-line splice into an IKE header
  renames the connection (`vpn-corp` → `vpn-cowarning`).
  A lost name is a **fail-open**, not a cosmetic error. `terminateRemovedConns`
  iterates `for name := range live`, so a removed connection absent from `live`
  is neither terminated nor entered into `pendingTerminate` — and
  `prevConnNames` has already advanced past it, so the teardown-debt record
  #6542 exists to keep is never created and a deleted VPN's SA keeps forwarding
  under an unloaded configuration with no retry.
  Whether swanctl can splice mid-line on a *successful* listing was never
  established (stdout to a pipe is block-buffered, stderr unbuffered, so it
  needs a large listing plus a concurrent stderr write). `runSwanctlSplit`
  **removes the question rather than answering it**, and both callers now share
  it, so the two cannot drift again. The NON-parsed calls (`--load-all`,
  `--terminate --ike`) deliberately keep `runSwanctl`/`CombinedOutput`: their
  only consumer is an error message, and folding stderr in is what makes it
  useful.
- **SA-status parsing must match the real `swanctl --list-sas` layout
  (#3937).** `GetSAStatus` shells out to `swanctl --list-sas` and feeds the
  stdout to `parseSAOutput`. The real strongSwan output is
  `name: #<id>, <STATE>, IKEv<n>, <spi>_i* <spi>_r`, then indented
  `local/remote '<id>' @ <host>[<port>]` endpoints, a crypto proposal line,
  an `established/rekeying` timing line, then the child SA header
  `name: #<id>, reqid <n>, <STATE>, <MODE>, ESP:<proposal>` with indented
  `in/out <spi>, <bytes> bytes, <packets> packets` counters and bare-CIDR
  `local/remote` traffic selectors. The `@` distinguishes an IKE endpoint
  line from a child traffic-selector line. The parser previously assumed an
  `ipsec statusall`-style layout (`local: A === B`, `local_ts = C`,
  `bytes_in=N`) that swanctl **never emits**, so every SA field but the
  name/state came back blank and `show security ipsec sa` was permanently
  empty even with active tunnels. Golden fixtures captured from real output
  live in `testdata/swanctl_list_sas_*.txt`; edit the parser only alongside a
  fixture so it can't silently drift from reality again.
- IKE version negotiation supports v1-only, v2-only, or dual (default).
  Aggressive mode is opt-in.
- NAT traversal modes: `disable`, `force`, `enable` (auto-detect).
  `NoNATTraversal` is a legacy flag retained for older configs.
- Traffic selectors are auto-derived from the policy source / destination
  prefixes when not given explicitly. Mixing explicit and derived
  selectors is supported but the explicit set wins.
- **One `local-ip` / `remote-ip` per traffic-selector (#5692).** Each named
  `traffic-selector` carries exactly ONE `local-ip` and ONE `remote-ip`
  prefix — express multiple prefixes as separate NAMED traffic-selectors
  (`effectiveTrafficSelectors` renders each as its own swanctl SA child).
  Repeated `local-ip` / `remote-ip` leaves under one selector survive the
  hierarchical / load-merge / HA-config-sync parse path (the flat-set commit
  path collapses them last-wins in `SetPath`, matching Junos "set replaces"),
  and the typed compiler (`compiler_ipsec.go`) reads them last-wins too —
  silently dropping every prefix but the last even though each passes the
  #4098 value gate. `validateIPsecTrafficSelectorsStrict`
  (`pkg/config/compiler_ipsec_trafficselector.go`) now REJECTS a duplicate at
  strict commit / commit-check (lenient-warn on load / peer-sync, #1960) so
  the truncation is operator-visible instead of a selector that enforces only
  its last prefix.
- **DPD (dead-peer detection).** A `dead-peer-detection` stanza on an IKE
  gateway is compiled by `parseDeadPeerDetectionNode` (`pkg/config`
  `compiler_ipsec.go`) into `gw.DPDEnable` + mode/interval/threshold, and
  rendered by `deriveDPD` (`pkg/ipsec/ike.go`) into swanctl `dpd_delay`,
  `dpd_timeout`, and `dpd_action`. Every Junos form enables DPD (#3994):
  - a bare `dead-peer-detection;` enables DPD with defaults — 10s delay,
    threshold 5 (→ `dpd_timeout = delay × threshold`), and `dpd_action`
    from the default/optimized mapping (`restart` for a
    `establish-tunnels immediately` tunnel, else `clear`);
  - `interval <n>` tunes `dpd_delay`; `threshold <n>` tunes the retry
    count feeding `dpd_timeout`;
  - the mode keyword maps to `dpd_action`: `always-send` → `restart`,
    `optimized` → `clear`/`restart`, `probe-idle-tunnel` → `trap`/`restart`.

  `DPDEnable` is the single source of truth for "is DPD on"; the mode
  string only carries the explicit keyword. Before #3994 the enable check
  was `DeadPeerDetect != ""`, so a bare statement was read as DISABLED and
  an interval-only / threshold-only stanza captured the sub-field name as a
  bogus mode.
- XFRM interface ID is derived from the bind-interface name via
  `xfrmiIfID()`. The same name → same numeric ID across reboots — don't
  rename a bind interface without expecting a reset of the SAs that ride
  it.
- **IPsec policy → proposal cross-reference (#2073).** An IPsec (Phase 2)
  policy's `proposals` reference (or, when omitted, a proposal named after
  the policy) is validated at commit / commit-check by
  `pkg/config` `validateIPsecPolicyProposalReferencesStrict`. A dangling
  reference is **hard-rejected** at commit: previously it fell through to
  `esp_proposals = default` in `resolveESPSettings`, silently substituting
  the operator's entire Phase-2 proposal set — including any configured
  `perfect-forward-secrecy` DH group — with the strongSwan default (which
  carries no required modp term), so PFS was silently disabled. On the
  tolerant load / peer-sync paths the commit check is downgraded to a
  warning (an already-persisted or peer-synced config still boots), and
  `resolveESPSettings` has a render-side safety net that emits a
  conservative **fixed** ESP suite instead of falling through to
  `default`, and logs a warning. Note: strongSwan ≥ 6.0.2 changed its
  `default` ESP set to make PFS *optional* rather than absent, so the
  silent weakening is a downgrade-to-negotiable-PFS there rather than
  no-PFS — the fix is the same.
  - **Absent vs dangling (#4117).** The safety net distinguishes two
    cases. A VPN that names **no** `ipsec-policy` at all
    (`vpn.IPsecPolicy == ""`) legitimately gets `esp_proposals = default`
    — the operator made no crypto choice, so strongSwan's built-in suite
    is their explicit choice. This is the ONLY path that emits `default`.
    A **named-but-unresolved (dangling)** reference — the policy is
    undefined, or the policy resolves but its proposal ref dangles — never
    falls through to `default`. It renders a conservative fixed suite:
    `aes256-sha256-modp<bits>` when a PFS group is configured (the #2073
    case), or `aes256-sha256` (no modp term) when no PFS is configured.
    Before #4117 the no-PFS dangling case still fell through to `default`,
    silently substituting the operator's whole cipher/integrity choice
    with strongSwan's built-in suite (the reasoning was "no PFS = nothing
    to preserve", which overlooked that the cipher/integrity intent is
    also lost). #4117 chose the conservative **fixed suite** over the
    IKE-style whole-VPN **skip** (#2270) for parity with the #2073 PFS
    case, which already emits the fallback rather than skipping: skipping
    only the no-PFS case would drop a no-PFS tunnel entirely while an
    otherwise-identical with-PFS tunnel keeps a working fallback — a
    surprising availability asymmetry driven solely by whether PFS
    happened to be configured. IKE (Phase 1) fails closed by skipping
    instead because it has no equivalent strong fixed suite to offer.
- **DH-group keyword rendering (#2392).** Every IKE/ESP proposal builder
  (`buildIKEProposalFromIKE`, `buildIKEProposal`, `buildESPProposal`, and
  the #2073 PFS fallback above) renders the Diffie-Hellman group suffix
  through the single `formatDHGroup` helper. It emits the canonical
  swanctl proposal keyword: `modp<bits>` for the MODP groups (1/2/5/14/
  15/16 and the MODP-with-subgroup variants 22/23/24), and the
  elliptic-curve spellings for the EC groups — group **19 → `ecp256`**,
  **20 → `ecp384`**, **21 → `ecp521`**, 25 → `ecp192`, 26 → `ecp224`, the
  brainpool groups 27→`ecp224bp`/28→`ecp256bp`/29→`ecp384bp`/30→`ecp512bp`,
  and the Montgomery curves 31 → `curve25519`, 32 → `curve448`. Before the
  helper, all four sites formatted the suffix as `modp<dhGroupBits>`, so an
  EC group emitted the strongSwan-invalid tokens `modp256`/`modp384` and
  swanctl rejected the whole proposal (the tunnel failed to load).
  `pkg/config` `ValidateDHGroup` accepts any positive-integer DH group, so
  the helper's table covers every group an operator can commit; an unlisted
  group falls back to `modp<dhGroupBits>` (which equals the group number
  for unknown groups). Spellings come straight from strongSwan's
  `proposal_keywords_static.txt` / `diffie_hellman_group_names`. Live
  swanctl load-verification of an EC tunnel is lab-bound; the
  `pkg/ipsec` swanctl-render tests are the gate.
- **Gateway reference resolution / `remote_addrs` (#2074).** A VPN's
  `ike gateway <name>` either names a defined `security ike gateway`
  object (whose `address` or `dynamic hostname` becomes `remote_addrs`)
  or, in the legacy inline shape, IS the peer endpoint directly (a
  literal IP or a dotted hostname/FQDN). The invariant is: **a bare
  gateway config-object NAME never reaches swanctl `remote_addrs`** — a
  config-object name strongSwan cannot use would DNS-resolve forever and
  the IKE SA would never come up (a silently-dead tunnel).
  - **Commit-time rejection** (`validateIPsecGatewayReferencesStrict`,
    `pkg/config/compiler_ipsec.go`, run from the strict-validator chain
    in `compileExpanded`): a VPN that references an undefined gateway, or
    a gateway object committed with neither `address` nor `dynamic
    hostname`, fails `commit` / `commit check`. On the tolerant load /
    peer-sync paths the same check is downgraded to a warning
    (`lenientIPsecGatewayRefs`) so a config persisted by an older binary
    or synced from a peer still boots.
  - **Render belt** (`resolveRemoteAddr`, `policy.go`): for any path that
    reaches render without passing local commit (HA sync / direct
    construction), an unrenderable VPN is SKIPPED (logged via
    `slog.Warn`) — its connection and secret are omitted — rather than
    leaking the name or aborting the whole file. Healthy VPNs always
    render, so one bad reference never zeroes healthy tunnels.
  - **Rule-A limitation:** an inline gateway hostname must be dotted
    (FQDN-like). A bare single-label inline hostname (e.g. `vpnpeer`,
    even if resolvable via the system resolver) is rejected so a typo'd
    single-label gateway name is caught. Migration: define a proper
    gateway — `set security ike gateway <name> address <ip>` (or
    `dynamic hostname <fqdn>`). The shared accept predicate is
    `config.IsUsableIPsecEndpoint`.
- **Local-address family selection for dynamic-hostname gateways
  (#2757).** When a gateway has no explicit `local-address` but does name
  an `external-interface`, `PrepareConfig` derives `local_addrs` from the
  interface's address. On a dual-stack appliance the interface carries both
  an IPv4 and an IPv6 address, so the chosen family MUST match the family
  the remote peer is reached over — otherwise the IKE SA is sourced from
  the wrong family and never establishes.
  - **Family hint** (`gatewayRemoteFamilyHint`, `policy.go`): a gateway
    with a literal `address` takes that IP's family. A **dynamic-hostname**
    gateway (`address` empty, `dynamic hostname <fqdn>` set) is resolved
    via `resolveHostFamily` (an injectable package var; the default,
    `defaultResolveHostFamily`, uses `net.Resolver.LookupIPAddr` bounded by
    a 2s context timeout — see the bounded-resolver note below) — IPv6-only
    → family 6, IPv4-only → family 4. Before
    #2757 the empty `address` produced a family-agnostic hint (0), so
    `selectUnitAddress` returned whichever family was listed first on the
    interface (typically IPv4) regardless of the peer — the defect-#2 bug
    deferred from #2404.
  - **Family-matched selection** (`resolveInterfaceAddress`): the local
    address is constrained to the hinted family. If the interface is
    single-stack in the OTHER family, selection falls back to
    family-agnostic so a degraded config still emits a `local_addrs` line
    instead of an empty one.
  - **Dual-stack peer:** when the hostname resolves to BOTH families, no
    explicit preference is configured, so the hint stays family-agnostic
    (0) and the interface's first usable address decides — strongSwan then
    initiates from a routable local source. (An explicit `local-address`
    always wins outright; this path only fires when one is absent.)
  - **Bounded resolver (review fold):** `PrepareConfig` runs synchronously
    inside the daemon apply sequence (`pkg/daemon/daemon_apply.go`) and the
    CLI commit path (`pkg/cli/apply.go`), which did NO DNS before #2757.
    Because the lookup is only a family *hint* (strongSwan does the
    authoritative resolution at IKE time), the default `resolveHostFamily`
    bounds it with a 2s context timeout (`resolveHostFamilyTimeout`). On
    timeout / NXDOMAIN / SERVFAIL it returns family 0 (agnostic) — a slow or
    unreachable resolver degrades to the interface-decides path and NEVER
    stalls `commit` / apply for the full glibc resolver timeout.
  - **Concurrent hint resolution (#4547):** the per-gateway family hints are
    resolved CONCURRENTLY by `resolveGatewayFamilyHints` (`policy.go`) before
    the gateway copy loop, through a bounded worker pool
    (`resolveFamilyHintConcurrency = 8`). Because each dynamic-hostname lookup
    can block for up to the 2s timeout, resolving N gateways sequentially
    stalled the ordered commit apply up to N×2s under DNS failure; the bounded
    pool keeps wall-clock cost at ~one timeout regardless of gateway count. The
    hint is per-gateway and order-independent, so the concurrent result is
    identical to the former inline sequential lookup — only the scheduling
    changed. Only gateways that resolve `local_addrs` from an
    `external-interface` (no explicit `local-address`) are looked up; the cap
    also bounds concurrent resolver goroutines / file descriptors for a
    pathologically large dynamic-hostname set.
  - **IPv6 link-local local binds (#2885):** the candidate filter
    `matchFamily` (`policy.go`) admits an IPv6 link-local unicast source
    (`fe80::/10`) when the gateway family hint is IPv6 (family 6). The
    earlier `IsGlobalUnicast()` gate rejected link-local outright, so an
    IPsec local-bind on a point-to-point / link-local IPv6 link could never
    source from `fe80::` — the documented dynamic-routing local-source over
    such links was unreachable. Link-local is admitted ONLY under an explicit
    family-6 hint: it is excluded from family-4 selection (and IPv4
    link-local `169.254.0.0/16` is never a usable source) and from
    family-agnostic (hint 0) selection, so it never wins implicitly over a
    global address on a dual-stack interface. Multicast, unspecified, and
    loopback stay excluded for every family.
    - **Global wins, order-independent** (`selectFamilyAddress`): family-6
      selection feeds a first-match loop over candidates (config order in
      `selectUnitAddress`; kernel enumeration order in
      `resolveKernelInterfaceAddress`). To keep a global address from losing
      to a link-local one that merely happens to be enumerated first,
      family-6 selection scans twice — pass 1 admits only global-unicast
      addresses, and a link-local is accepted only if NO global is present.
      The common case (kernel lists globals first, configs carry no SLAAC
      `fe80::`) was already safe, but enumeration order is not guaranteed,
      so the preference is made explicit rather than relied upon. Family-4
      and family-agnostic selection need only one pass (link-local is never
      admitted by `matchFamily` there).
    - **Zone-qualified link-local source** (`zoneQualify`): a bare
      `local_addrs = fe80::1` is ambiguous to strongSwan / the kernel when
      more than one interface carries an `fe80::` address. When the selected
      source is link-local, the resolver appends the IPv6 zone
      (`%<iface>`) — e.g. `fe80::1%ge-0-0-3` — using the kernel interface
      name it already has in scope (the looked-up interface name for the
      kernel path; see the reth note below for the configured path).
      Global and IPv4 sources are emitted bare; an address already carrying
      a zone is left unchanged.
    - **The zone must name a KERNEL netdev, so reth is resolved (#9137).**
      The configured path derived the zone as `config.LinuxIfName(base)`,
      which for `external-interface reth0.0` yields `reth0` — and under
      bondless RETH, the shipped HA model, `reth0` is not a kernel device
      at all: xpfd programs the VRRP VIP and virtual MAC on the PHYSICAL
      member and creates no reth netdev (`pkg/dataplane/compiler_iface.go`
      skips reth for the same reason). charon could not
      `if_nametoindex("reth0")`, so the IKE SA never bound and the tunnel
      never established, from a config that commits clean. The zone is now
      `config.LinuxIfName(cfg.ResolveReth(base))`, which also makes the
      function agree with its own sibling — the kernel-lookup fallback in
      `resolveInterfaceAddressFamily` has resolved reth since it was
      written, so the asymmetry lived inside one function pair. `ResolveReth`
      returns a non-reth ref unchanged, so nothing else moves. The result is
      guarded against being EMPTY: a member carrying `RedundantParent` but no
      `Name` makes `RethToPhysical` map `reth0` to `""`, and an unqualified
      `fe80::` is strictly worse than a wrongly-qualified one — it loses the
      #2885 disambiguation entirely.
      The real bound on the defect is `selectFamilyAddress` being global-wins:
      the link-local branch is only reached when the reth unit has no global
      IPv6 address.
- **Runtime re-bind on interface IP change (#2884).** A gateway with an
  `external-interface` and no explicit `local-address` resolves
  `local_addrs` from the interface's CURRENT address at `PrepareConfig`
  time. When that interface is DHCP-managed, its address can change at
  runtime (lease renew to a new address, flap). `PrepareConfig` is
  re-resolution-safe — it re-reads the live address every call — but
  something has to RE-RUN it on the lease change, or swanctl keeps the
  stale bind and the tunnel cannot re-establish until the next commit.
  - The DHCP lease-change callback (`onDHCPAddressChange`,
    `pkg/daemon/daemon_dhcp.go`) drives this. A lease change on a
    DATAPLANE-facing interface already triggers a full `applyConfig`,
    whose step 6 re-renders IPsec. A lease change on a MANAGEMENT-only
    interface skips the full recompile, so that branch now calls
    `reapplyIPsecForLeaseChange`, which re-renders + reloads swanctl
    directly.
  - **Scoping** (`HasDHCPBoundGateway`, `policy.go`): the management-only
    re-render fires only when some gateway is actually lease-dependent —
    `external-interface` set, no explicit `local-address`, and the
    referenced unit is DHCP/DHCPv6-managed. A lease refresh on a
    management interface no IPsec gateway uses is a no-op, so an unrelated
    renew never churns swanctl or resets live SAs. The re-render runs
    under the daemon's apply semaphore to serialize with a concurrent
    commit's IPsec apply.
  - Non-DHCP runtime address changes (e.g. a manual VIP move on a static
    interface) still rely on a commit/boot re-render; only DHCP lease
    changes have a runtime hook today.
  - **Recoverable + visible rebind failure (#4899).** The management-only
    `reapplyIPsecForLeaseChange` re-render is best-effort with respect to
    lease processing (a swanctl failure must never block or fail DHCP
    handling), but its reload error is NO LONGER dropped as a bare
    `slog.Warn`. Before #4899 a failed `swanctl --load-all` on this path
    left strongSwan binding the STALE lease address — the tunnel could not
    re-establish and the operator had no signal and no recovery.
    - **Recoverable:** on failure the daemon raises an
      `ipsecRebindPending` flag and arms a single-flight retry loop
      (`ipsecRebindRetryLoop`, `pkg/daemon/daemon_ipsec_rebind.go`) that
      re-runs the re-render+reload on a slow cadence
      (`ipsecRebindRetryInterval`, 30s) until it converges, then clears the
      flag and disarms. It mirrors the probe-pin retry idiom (#1895,
      `probePinRetryLoop`). The loop re-renders against the LIVE active
      config (`d.store.ActiveConfig`), so a commit that removes the VPN or
      the DHCP binding converges the loop instead of resurrecting deleted
      config. Both the apply and the pending-flag update run under the apply
      semaphore, so the pending state always reflects the last completed
      apply (no lost-failure race against a concurrent commit's IPsec
      apply).
    - **Visible:** while pending, the `xpf_ipsec_rebind_pending` Prometheus
      gauge reads 1 (surfaced via `Daemon.IPsecRebindPending` →
      `api.Config.IPsecRebindPendingFn`), mirroring the
      `xpf_frr_reload_degraded` degraded-state gauge (#1880). It clears to 0
      once swanctl `local_addrs` reconverge on the current lease.
    - This is the DHCP-lease-change best-effort caller ONLY. The
      commit-path IPsec apply already fail-closes the commit on an
      `ipsec.Apply` error (#4433) and is unchanged.
- **IKE policy chain → proposal cross-reference (#2270).** A gateway's
  `ike-policy` reference walks gateway → `ike-policy` → `ike-proposal`
  (`resolveIKESettings`, `ike.go`). When that chain breaks — the
  `ike-policy` is undefined, or its `proposals` reference dangles —
  `resolveIKESettings` previously returned an EMPTY proposal string with a
  nil error, and `renderConfig` (which guards the line with
  `if ikeProposals != ""`) emitted the connection block with NO
  `proposals =` line. strongSwan then negotiated phase-1 with its
  compiled-in default proposal set instead of the configured/required
  crypto — a silent security-posture downgrade, the Phase-1 analogue of the
  #2073 ESP gap.
  - **Fail-closed resolution** (`resolveIKESettings`): the intentional
    no-policy case (gateway with no `ike-policy`) still returns an empty
    proposal with a nil error (strongSwan's default set is the operator's
    explicit choice). A gateway that DOES name an `ike-policy` whose chain
    cannot resolve now returns the `errIKEChainUnresolved` sentinel instead
    of an empty proposal. The legacy direct-proposal fallback (an
    `ike-policy` value that is itself the name of a defined Phase-2
    proposal, rendered via `buildIKEProposal`) is still accepted.
  - **Commit-time rejection** (`validateIKEPolicyChainReferencesStrict`,
    `pkg/config/compiler_validate_strict.go`, run from the strict-validator
    chain in `compileExpanded`): a VPN whose gateway names an undefined
    `ike-policy`, an `ike-policy` whose `proposals` reference dangles, or an
    `ike-policy` defined with no `proposals` leaf at all, fails `commit` /
    `commit check`. The diagnostics name the offending object precisely
    (#2279): the gateway message is stanza-agnostic ("under `security ike`
    or `security ipsec`", since both stanzas populate the same gateway map),
    and the missing-`proposals`-leaf case reports "has no proposals
    configured" rather than a misleading `undefined ike-proposal ""`.
    Only gateways actually referenced by a
    VPN are validated (an orphan never reaches render, matching Junos). On
    the tolerant load / peer-sync paths the same check is downgraded to a
    warning (`lenientIKEPolicyChainRef`) so a config persisted by an older
    binary or synced from a peer still boots (#1960 no-brick).
  - **Render belt** (`renderConfig`, `policy.go`): for any path that
    reaches render without passing local commit (HA sync / direct
    construction / pre-fix persisted config), a VPN whose IKE chain does
    not resolve is SKIPPED (logged via `slog.Warn`) — its connection and
    secret are omitted — rather than emitting a proposal-less connection.
    Healthy VPNs always render, so one bad reference never zeroes a healthy
    tunnel. A non-chain resolve error (e.g. an unknown auth-method token
    from `authMethodToSwan`) is a different class and still aborts the
    whole render.
- **Predefined proposal-set expansion (#4297, fable-167 V-1).** Junos
  `security ike policy P proposal-set <set>` and the `security ipsec policy`
  equivalent are the standard vSRX shorthand for "use a Juniper-curated
  proposal set instead of hand-defining proposals". The keyword used to be
  silently dropped (unknown compiler-switch key), so the policy carried no
  resolvable proposal and the tunnel could not be built (the IPsec side
  hard-rejected with "no resolvable ipsec proposal"; the IKE side left the
  chain unresolved). The compiler now expands each set into concrete
  synthetic proposals — `expandIKEProposalSets` / `expandIPsecProposalSets`
  in `pkg/config/compiler_ipsec_proposalset.go`, run after the proposal and
  policy maps are built — and points the policy's `Proposals` list at them,
  so the whole downstream (strict cross-ref validators + the renderer here)
  works unchanged. The expansion table is the single source of truth and
  uses Junos algorithm spellings that `buildIKEProposalFromIKE` /
  `buildESPProposal` normalize. Members follow Juniper's published tables:
  `basic` / `compatible` / `standard` are the legacy DES/3DES/SHA1/MD5 sets
  (`basic` is DH group 1 in Phase-1, `compatible`/`standard` are DH group 2
  — weak by modern standards and possibly not loaded in a hardened
  strongSwan, but expanded faithfully because the operator asked for the
  legacy set); `suiteb-gcm-128` / `suiteb-gcm-256` are RFC 6379
  Suite-B (AES-GCM + ECDSA + ECP group 19/20). An explicit `proposals` list
  wins (proposal-set only fills an empty list); an unknown set keyword is
  rejected by the schema enum at commit. The crypto is an explicit, tested
  table, never a hidden default substitution.
- **AH (`protocol ah`) is rejected, never faked as ESP (#4298, fable-167
  V-2, SECURITY).** A `security ipsec proposal P protocol ah` selects
  Authentication Header (integrity only, no encryption; swanctl expresses it
  via `ah_proposals`). xpf has no AH render path — `buildESPProposal`
  ignores the protocol and defaults empty encryption to `aes256`, and
  `renderConfig` always emits `esp_proposals` — so a `protocol ah` proposal
  used to render as ESP with a fabricated cipher (the operator asked for AH
  and silently got ESP-with-made-up-crypto, a misrepresentation). The
  commit-time gate `validateIPsecProposalProtocolStrict`
  (`pkg/config/compiler_validate_strict.go`) hard-rejects `protocol ah` with
  a clear "use `protocol esp`" message; the render belt `vpnUsesAHProposal`
  (`ike.go`) makes `renderConfig` SKIP any VPN whose ipsec-policy resolves to
  an AH proposal (tolerant-boot path) rather than emit the fabricated ESP
  tunnel. Full AH support (`ah_proposals`) is a possible follow-up; the
  invariant is: **never substitute ESP for AH silently.**
- **`vpn-monitor` accepted-but-not-enforced (#4299, fable-167 V-3).**
  `security ipsec vpn V vpn-monitor { source-interface; destination-ip;
  optimized; }` drives ICMP-probe tunnel liveness + st0 interface-state
  coupling. xpf implements neither; the stanza used to be silently dropped.
  It is now typed + captured (`compileIPsec`) and `ValidateConfig` emits an
  accepted-only advisory (mirroring the #2078/#4231 doctrine) pointing the
  operator at IKE-layer `dead-peer-detection` for peer liveness. Full
  probe-driven monitoring is a follow-up.
- **Manual-key SA rejected (#4300, fable-167 V-4).** `security ipsec vpn V
  manual { ... }` configures a manual-key SA (no IKE). xpf negotiates all
  SAs via IKE; the block used to be dropped silently, leaving a VPN that
  committed OK but forwarded nothing (a silent dead tunnel).
  `validateIPsecManualKeyStrict` now hard-rejects it at commit with a "use
  an IKE-negotiated VPN" message (lenient warn on load — the block was
  already inert).
- **VPN names must be display-safe (#9623).** A VPN name reaches strongSwan
  raw: it is the connection name, the child name of a VPN with no traffic
  selector, and the prefix of every other child. But `GetSAStatus`
  display-sanitizes every `SAStatus` field (#6584). For a name with a C1
  control, a line or paragraph separator, or invalid UTF-8,
  `ActiveConnectionNames` therefore published, and `TerminateAllSAs`
  terminated, a different string than the one swanctl knows, so HA failover
  never re-initiated that tunnel. `validateIPsecSANamesDisplaySafeStrict`
  (`pkg/config`) now hard-rejects such a name at commit, with a lenient warning
  on load. `termsafe.DisplaySafe` is exactly the condition under which the two
  spellings agree. Traffic-selector names cannot diverge, because
  `sanitizeChildName` maps them to `[A-Za-z0-9._-]`. `terminateIKENames` is
  `TerminateAllSAs`' name selection, split out like `activeSANames` so the whole
  path can be driven from parsed `--list-sas` output.
- **`establish-tunnels` enum validated (#4301, fable-167 V-5).** The leaf
  was untyped, so a typo (`on-tarffic`) or a newer value stored verbatim and
  silently degraded to on-traffic. It is now
  `ValidateEnum([immediately, on-traffic, responder-only])` in
  `setSchema` — a typo fails closed at commit.
- **Two VPNs may not render the same SA name (#9624).** The renderer keeps
  child names unique only within one VPN (#5122). Across VPNs, two
  ordinary-looking configs collide:
  - VPN `a` with selector `b-c` and VPN `a-b` with selector `c` both render
    child `a-b-c`;
  - VPN `blue` with selector `red` renders child `blue-red`, which VPN
    `blue-red` also uses for its connection and child.

  `swanctl --initiate --child` identifies a child by name alone, so HA failover
  could not say which tunnel it brings up. `validateIPsecSANameCollisionsStrict`
  (`pkg/config`) now rejects such a config at commit, naming the VPNs and the SA
  name, with a lenient warning on load. The name derivation lives in
  `pkg/ipsecname`, and both this renderer (`effectiveTrafficSelectors`) and the
  gate call it, so the gate checks exactly what renders.
  `TestSANameDerivationMatchesTheRenderIndex9624` pins the gate to
  `BuildSANameIndex`.
- **AES-GCM IKE PRF + ICV-suffix canonicalization (#2125).** The
  load-bearing fix: a strongSwan IKEv2 AEAD (AES-GCM) proposal MUST
  name a PRF explicitly — an AEAD cipher carries no integrity algorithm
  for strongSwan to derive a PRF from — so a GCM IKE (Phase 1) proposal
  with no PRF is incomplete and the IKE SA fails to negotiate (a
  silently-dead tunnel while the commit succeeds). The IKE builders now
  append a PRF for GCM (`aes256gcm16-prfsha256-modp2048`); the PRF
  mirrors the proposal's auth algorithm when set, defaulting to
  `prfsha256`. ESP children take NO PRF (and no separate integrity alg —
  GCM carries its own ICV). Separately, `normalizeEncAlg` (`ike.go`)
  canonicalizes the Junos-native GCM names
  (`aes-128-gcm`/`aes-192-gcm`/`aes-256-gcm`) to the explicit
  16-octet-ICV swanctl tokens (`aes128gcm16`/`aes192gcm16`/`aes256gcm16`
  — Junos AES-GCM uses a 16-octet ICV). This is a clarity/consistency
  fix, NOT a parse fix: strongSwan also accepts the bare `aes<N>gcm`
  alias (it maps to `ENCR_AES_GCM_ICV16` in
  `proposal_keywords_static.txt`), so the previous `aes256gcm-modp2048`
  ESP render was valid — the canonicalization just makes the ICV
  explicit in the generated config. Already-suffixed forms (e.g.
  `aes256gcm128`) pass through unchanged.
- **ESP/IKE integrity-token mapping (#3851).** `normalizeAuthAlg`
  (`ike.go`) maps a Junos `authentication-algorithm` name to the
  strongSwan integrity keyword charon actually accepts. Junos names an
  ESP integrity algorithm with an explicit HMAC truncation length
  (`hmac-sha-256-128`, `hmac-sha1-96`, `hmac-md5-96`,
  `hmac-sha-384-192`, `hmac-sha-512-256`), but strongSwan's proposal
  keyword table names the BASE algorithm only (`sha256`, `sha1`, `md5`,
  `sha384`, `sha512`) and derives the RFC-mandated truncation
  internally. The truncation suffix must be MAPPED away, not
  dash-stripped: the old normalizer did `ReplaceAll(name, "-", "")`, so
  `hmac-sha-256-128` rendered as `sha256128` and `hmac-sha1-96` as
  `sha196` — neither is a token in
  `proposal_keywords_static.txt`, so charon rejected the ENTIRE ESP
  proposal and the tunnel silently never loaded. The current mapping
  collapses the name (drop `hmac-`, drop dashes) then matches the base
  SHA/MD5 family, so every Junos spelling — the ESP truncated forms, the
  IKE short forms (`sha-256`, `sha1`, `md5`), and already-normalized
  swanctl tokens (idempotent) — yields a valid keyword. AEAD (GCM)
  proposals never reach this function: the builders take the `gcmPRF`
  branch for AEAD ciphers (GCM carries its own ICV, no separate
  integrity algorithm), so this fix does not touch the GCM path.
- **swanctl double-quote / backslash escaping (#2126).** Free-text
  values interpolated inside a swanctl double-quoted string — the PSK
  `secret = "..."` and the `id = "..."` / `certs = "..."` lines — are
  run through `escapeSwanctlQuoted` (`policy.go`), which doubles
  backslashes then escapes double-quotes (order matters). The swanctl
  settings lexer treats a bare `"` as the string terminator and
  processes `\\`/`\"` escapes inside quotes, so a PSK or distinguished-
  name identity containing a literal `"` (e.g. `pa"ss`, `CN=fw, O=acme`)
  no longer corrupts the secrets/identity block (a silent IKE auth
  failure). This composes with — does not replace — the #1798
  `sanitizeSwanctlValue` control-char belt (sanitize first, then
  escape). Identity values are now always emitted quoted so a DN with
  spaces/commas parses as a single value.
- **PSK secret `id` selectors (#3952).** Each `secrets { ike-<conn> {
  secret = ... } }` PSK block now emits `id-<n>` selector(s) scoping the
  secret to its peer (`pskIDSelectors` in `policy.go`). A PSK secret with
  NO id matches ANY peer, so with two or more PSK VPNs strongSwan could
  bind the wrong secret to a peer and IKE authentication would fail (or a
  peer could authenticate against another VPN's PSK). The selector is the
  remote peer's IKE identity — the configured `remote-id` when set,
  otherwise the concrete remote gateway address (strongSwan uses the peer
  IP as its default identity when no id is negotiated), and this is the
  discriminator between two PSK VPNs to different peers. A configured
  `local-id` rides along as a harmless extra owner (two VPNs on the same
  firewall usually share the local id, so it never disambiguates on its
  own, but it can never cause a wrong-peer match either). A dynamic
  responder-only peer (`remote_addrs = %any`) with no `remote-id` has
  nothing to scope by, so it emits no id — never a literal `id = "%any"`
  (which would defeat the scoping and match all peers) — preserving the
  legacy any-peer behavior for that one tunnel. A cert/EAP VPN has no PSK,
  so it emits no secret block and is unaffected. The selector values reuse
  the `sanitizeSwanctlValue`/`escapeSwanctlQuoted` quoting (#1798/#2126).
- **Traffic-selector `local_ts`/`remote_ts` sanitize + commit gate
  (#4098).** The child SA `local_ts = <value>` / `remote_ts = <value>`
  lines (from `security ipsec vpn <name> traffic-selector <ts>
  local-ip/remote-ip`, or the `local-identity`/`remote-identity`
  fallback) are now run through `sanitizeSwanctlValue` at render, parity
  with the sibling child SA name. Before #4098 they were interpolated
  raw: the Junos lexer materializes a `\n` escape inside a quoted value,
  so a selector such as `local-ip "10.0.0.0/24\n        updown =
  /tmp/x.sh"` injected a real newline plus an arbitrary `key = value`
  line into the `children {}` block — and charon runs as **root**, so an
  injected `updown = <script>` is a config-injection → root RCE (an
  injected `esp_proposals`/`mode`/`mark_*` silently rewrites the crypto
  posture). Two layers close it: the render belt above keeps any value
  that reaches the renderer inert, and a commit-time gate
  (`validateIPsecTrafficSelectorsStrict`, `pkg/config/compiler_ipsec_trafficselector.go`)
  rejects a `local-ip`/`remote-ip` value that carries a control
  character or whitespace, or that is not a CIDR prefix / host address /
  IP range. The gate is strict on operator commit / commit-check and
  lenient-downgraded (warn) on load / peer-sync per #1960, mirroring the
  `sanitizeSwanctlValue` render belt on the other swanctl-injection
  surfaces (#1798/#2126). Note: the general free-text control-char gate
  (`validateNodesControlChars`, `pkg/config/freetext.go`) already
  rejected an embedded newline in ANY value at commit — the #4098 gate
  adds the traffic-selector-specific shape check (malformed / mis-scoped
  selector) and the render-side belt.
- **Endpoint AND proposal list sanitize (#6469).** The remaining raw-`%s`
  swanctl render slots that carry peer/operator-influenced free text are
  now run through `sanitizeSwanctlValue`, completing the render belt so
  that EVERY such slot in `renderConfig` (`policy.go`) is sanitized. Two
  groups were still raw:
  - **Endpoints** — the connection `local_addrs = <value>` /
    `remote_addrs = <value>` lines (the resolved peer/local endpoint from
    `resolveRemoteAddr` — a gateway `address`/`dynamic hostname`, a
    `local-address`, an `external-interface`-derived local IP, or the
    legacy inline `vpn.Gateway`). The legacy inline `vpn.Gateway` shape is
    independently filtered by `config.IsUsableIPsecEndpoint` (a
    control-char value is not a usable endpoint → the VPN is skipped), but
    the Gateways-map shape took `address`/`dynamic hostname` verbatim.
  - **Proposals** — the connection-level `proposals = <value>` (IKE /
    Phase 1, `ikeProposals`) and the child-SA `esp_proposals = <value>`
    (ESP / Phase 2, `espProposals`). `buildIKEProposal` /
    `buildIKEProposalFromIKE` / `buildESPProposal` append
    `prop.EncryptionAlg` / `prop.AuthAlg` VERBATIM on the unknown-
    algorithm fall-through (`normalizeAuthAlg`'s default branch returns
    the collapsed token unchanged; `normalizeEncAlg`'s generic gcm strip
    only removes `-cbc`/`-`), so a control character in a peer-synced /
    directly-constructed proposal reaches the renderer. `esp_proposals`
    sits INSIDE `children {}` — the same block whose `local_ts`/`remote_ts`
    belt cites `updown = /tmp/x.sh` executed by charon as **root** — so an
    injected newline there is a config-injection → root RCE, a strictly
    worse vector than the endpoint one on the identical
    validation-bypassed threat model.

  All four are UNQUOTED list slots, so — exactly like the
  `local_ts`/`remote_ts` belt above — sanitize alone is the right form
  (NO `escapeSwanctlQuoted`, which is for the quoted `id`/`certs`/`secret`
  slots): an embedded newline collapses to a space, keeping the tampered
  value inert on one line instead of injecting a live directive
  (`version`/`aggressive`/`also` at the connection level, `updown`/
  `esp_proposals`/`mode`/`mark_*` in the child block). A legitimate value
  is byte-identical — `sanitizeSwanctlValue` only rewrites C0/DEL control
  bytes, so `.`, `,`, `:`, `%`, and `-` are all preserved and a single
  address, a comma-separated multi-address list, an IPv6 literal, the
  responder-only `%any` sentinel, and a dashed multi-proposal list
  (`aes256-sha256-modp2048,aes128-sha256-modp2048`) render unchanged. The
  commit-time gates (`validateIPsecEndpointsStrict` for endpoints, the
  proposal validators for crypto tokens) reject a control-char value at
  commit; this render belt is the by-construction backstop for a
  validation-bypassed path (HA peer-sync of a pre-fix config, a
  directly-constructed `IPsecConfig`, or a config persisted before the
  fix), matching the #1798/#2126/#4098 belt doctrine. The remaining
  interpolated slots are safe by construction: `auth` and `dpd_action`
  are fixed enums (`authMethodToSwan` errors on any unknown token;
  `deriveDPD` only emits `restart`/`clear`/`trap`), the `id`/`certs`/
  `secret` slots already carry the `sanitizeSwanctlValue` +
  `escapeSwanctlQuoted` belt, connection / child / secret NAMES are
  sanitized, and every `dpd_delay`/`rekey_time`/`if_id_*` slot is an
  integer (`%d`).
- **Injective child-section naming (#5122).** Each traffic selector
  renders one swanctl child section named `<conn>-<sanitizeChildName(ts)>`
  (`effectiveTrafficSelectors` in `policy.go`). `sanitizeChildName` maps
  every disallowed rune to a single `-`, so two DISTINCT selector names
  that differ only in sanitized characters (e.g. `site/a` and `site:a`,
  both legal Junos identifier chars) both collapse to `site-a` and used
  to emit DUPLICATE child sections — strongSwan then rejects the config
  or silently merges/loses one selector, a selector-specific
  site-to-site outage. `effectiveTrafficSelectors` now detects any
  sanitized base shared by two or more selectors and appends a stable
  hash of the ORIGINAL selector name (`childNameDisambiguator`, fnv-1a
  low 32 bits, 8 hex chars) to EACH colliding entry so every configured
  selector renders a UNIQUE section. Non-colliding names (the common
  case) are left byte-for-byte unchanged — no churn. The disambiguator
  is a pure function of the original name, so the same config renders
  identical section names across renders and across HA nodes, preserving
  config-sync and idempotent commits. A residual guard extends the name
  deterministically in the astronomically unlikely event a disambiguated
  name still collides. Unlike the #4098 gate this does NOT reject the
  config: two selectors with distinct legal Junos names are valid, so the
  fix makes both render (vSRX parity) rather than failing the commit.
