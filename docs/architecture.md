# xpf architecture

xpf is a Junos-style stateful firewall that replicates Juniper vSRX
capabilities. It has two halves:

- A **Go control plane** (`xpfd`) that compiles Junos configuration,
  manages sessions, drives HA, programs routing, and serves the CLI and
  APIs.
- A **Rust AF_XDP userspace dataplane** (`xpf-userspace-dp`) that is the
  only runtime packet-forwarding path.

## Dataplane: the runtime forwarding path

> Dataplane notice (#1373, complete): the eBPF dataplane retirement is
> done. The Rust AF_XDP userspace dataplane is the only runtime
> forwarding path. Explicit `system dataplane-type ebpf` is hard-rejected
> at commit (`ErrEBPFDataplaneRetired`) and at runtime
> (`ErrEBPFBackendRetired`); use `set system dataplane-type userspace`, or
> omit the knob for the default. The legacy BPF source (`bpf/xdp/*.c`,
> `bpf/tc/*.c`) was deleted in #1476; the only retained eBPF artifacts are
> the userspace XDP shim (`userspace-xdp/`) and the shared
> `bpf/headers/*.h` map/struct bootstrap.

A Rust forwarding engine receives packets via AF_XDP sockets and
processes them in userspace. A Rust XDP shim stamps metadata, redirects
transit traffic into AF_XDP, and hands proven local/control traffic back
to the kernel. If helper/XSK forwarding is degraded, non-local transit
fails closed in both compat and strict modes instead of bypassing
policy, NAT, or conntrack.

```
NIC → XDP shim (redirect transit, pass local/control, drop degraded transit)
    → AF_XDP socket
    → Rust worker thread (session → policy → NAT → FIB → TX)
    → AF_XDP TX ring → NIC
```

- **Per-worker architecture**: one worker per queue shard, with
  session/NAT/policy/FIB handled in Rust.
- **AF_XDP fast path**: supports both copy and zero-copy modes depending
  on driver/path behavior.
- **Kernel pass-through**: cpumap-assisted delivery keeps local/kernel-owned
  traffic out of the AF_XDP fast path.
- **Fail-closed admission**: unsupported userspace configs are gated or
  fail closed rather than bypassing policy, NAT, or conntrack.
- **Degraded mode**: when helper/XSK forwarding is unavailable, the shim
  keeps non-local transit out of the kernel forwarding path, passes only
  proven local/control traffic, and drops degraded transit.

The parser still *accepts* the `ebpf` token so that
`load merge`/`load override` of a pre-retirement config does not
syntax-error during a rolling upgrade — but `commit check` then fails
with the retirement error, and the remediation is
`set system dataplane-type userspace`. If a persisted config still names
`ebpf` on startup, the daemon runs in config-only mode until the operator
updates it.

To tune the userspace dataplane:

```junos
system {
    dataplane {
        binary /usr/local/sbin/xpf-userspace-dp;
        workers 6;
        ring-entries 8192;
    }
}
```

See [`userspace-dataplane-architecture.md`](userspace-dataplane-architecture.md)
for the full architecture and [`userspace-debug-map.md`](userspace-debug-map.md)
for the active debugging map. The current admission boundary is tracked
in [`userspace-dataplane-gaps.md`](userspace-dataplane-gaps.md).

### Historical note: the retired eBPF dataplane

The original dataplane ran in-kernel using 14 BPF programs chained via
tail calls (XDP ingress `main → screen → zone → conntrack → policy →
nat → nat64 → forward`; TC egress `main → screen_egress → conntrack →
nat → forward`) and reached 25+ Gbps on native XDP (mlx5, i40e, ice).
That source (`bpf/xdp/*.c`, `bpf/tc/*.c`) was deleted in #1476; the
pipeline is preserved only in git history (`git log -- bpf/xdp/ bpf/tc/`).
It is no longer a selectable backend.

> DPDK dataplane retired in #1525. Do not add new DPDK code. The
> `dpdk_worker/` C tree and `pkg/dataplane/dpdk/` Go manager were removed
> in #1527/#1528.

## Key design patterns

- **Go control plane** handles config compilation, session GC, management
  APIs, HA cluster, and routing.
- **Rust AF_XDP userspace dataplane** owns the only packet-forwarding path.
- **Retained eBPF surface** is the userspace XDP shim (`userspace-xdp/`)
  plus the shared `bpf/headers/*.h` map/struct bootstrap — not a
  forwarding backend.
- **Userspace AF_XDP shim** (`userspace-xdp/src/lib.rs`): per-CPU binding
  arrays steer packets from native XDP to userspace queues.
- **Dual session entries** (forward + reverse) in the shared conntrack
  hash map back HA session-sync.
- **Three-phase config compilation**: Junos AST → typed Go structs →
  userspace-dp control messages (no eBPF map writes after #1476).
- **FRR-managed routing**: all routes (static, DHCP, per-VRF) live in a
  managed section in `/etc/frr/frr.conf`.
- **Full interface management**: xpfd owns ALL interfaces on the firewall
  — renames them via `.link` files, configures addresses/DHCP via
  `.network` files, and brings down unconfigured interfaces.

## Command trees (two-SSOT split, #1319)

`pkg/cmdtree/tree.go` is the single source of truth for the
**operational** tree (`run`/`show`/`clear`/`request`/…): tab completion
and `?` help across local CLI, remote CLI, and gRPC. The **config-mode
`set`/`delete`/`show`/`edit` grammar** (structural completion, flat-set
token grouping, value-slot `?` completion, and commit-check typed-leaf
validation) is owned by `config.setSchema` in `pkg/config/schema.go`
(completion helpers in `pkg/config/schema_complete.go`) plus
`config.SchemaValidate` in `pkg/config/schema_walk.go` — NOT cmdtree.
Add a config-mode typed leaf by editing `setSchema` (see
[`config-schema.md`](config-schema.md)); add an operational command by
editing cmdtree.

## APIs

- **gRPC** on `127.0.0.1:50051` — 48+ RPCs (config, sessions, stats,
  routes, IPsec, DHCP, cluster). The loopback listener (`Server.Run`) is
  the trusted local surface and serves the full service.
- **Cluster fabric gRPC listener** (`Server.RunFabricListener`) — in
  cluster mode xpfd binds a second gRPC listener on the sync/fabric IP
  (`<fabric-ip>:50051`) so a node can proxy monitor requests to its peer
  over the fabric link. This is the **only** network-exposed gRPC surface,
  so it is **fail-closed** (#4122): a default-deny allowlist interceptor
  pair (`fabricAllowlistUnaryInterceptor` / `fabricAllowlistStreamInterceptor`
  in `pkg/grpcapi/server.go`) serves **only** the RPCs a node actually
  proxies to its peer — `GetStatus`, `GetSessions`, `GetSessionSummary`,
  `GetZonePairSummary`, `ShowText`, `ClearSessions` (unary) and
  `MonitorInterface` (stream). Every other method (Commit, Delete,
  Rollback, the config-mode surface) returns `PermissionDenied`.
  `SystemAction` multiplexes fabric-safe cross-node cluster-failover with
  destructive node actions under one method, so it is gated by request
  action (`isFabricSafeSystemAction`): only the two proxied cross-node
  forms (`cluster-failover-data:node<N>`, `cluster-failover:<rg>:node<N>`)
  pass; `zeroize`/`reboot`/`halt`/`power-off` are denied on the fabric.
  On top of the allowlist, the fabric listener also **authenticates** the
  caller with the control-link PSK (#4107, `fabricAuthUnaryInterceptor` /
  `fabricAuthStreamInterceptor` in `pkg/grpcapi/fabric_auth.go`, chained
  BEFORE the allowlist). When `set chassis cluster authentication-key <key>`
  bearer token (`HMAC-SHA256(PSK, domain‖method‖SHA-256(deterministic
  protobuf request)‖window)`, 30 s window ±1 for skew) in the
  `xpf-fabric-auth` metadata header, verified constant-time. The local node
  attaches it on `dialPeer` via `fabricAuthCreds`. **Both**
  fabric dialers attach the token: the daemon's own `Server.dialPeer`
  (`server_diag.go`) and the in-process operator CLI's peer dialer
  (`pkg/cli` `dialPeer`, which reaches the peer directly for cluster-wide
  `show`/`clear`/`request chassis cluster` proxying) — the latter builds
  the credential from the same live control-link PSK via the shared
  `grpcapi.NewFabricAuthCreds` helper (#5324). Before #5324 the CLI dialer
  used insecure creds only, so enabling the fabric PSK silently broke CLI
  peer observability/role control with `Unauthenticated` once the guard
  armed. This closes the gap where any host on the shared control segment
  could invoke the allowlisted
  read/monitor/`ClearSessions`/cross-node-failover RPCs with no credential.
  **Wall-clock skew past the accept band is DIAGNOSED, not tolerated
  (#6708).** Because the token is time-windowed, more than ~60–90 s of skew
  makes every cross-node fabric RPC fail `Unauthenticated` — permanently,
  since skew does not self-correct without NTP — while VRRP, forwarding and
  failover keep working, so the cluster looks healthy and every cross-node
  query returns LOCAL-ONLY. The accept band is deliberately NOT widened: it
  bounds replay of an identical unary request and any request on a stream
  (whose body cannot be bound at auth time). #10709 binds each unary token to
  the deterministic protobuf request digest, so a captured
  `ClearSessions{filter A}` / `failover rg1` token cannot authorize a different
  filter or RG. A bounded, throttled scan on the reject path measures the
  token that verifies under an accepted key at another window — an
  authenticated measurement, since only a key holder can produce one — so the
  rejection names the clock and the remedy, and `show chassis cluster status`
  carries the skew. A forged token or a genuine PSK mismatch reports no skew,
  so an authentication fault is never mislabelled as a clock fault. Dual-accept (mirroring the heartbeat, `fabricAuthDecision`):
  a node with no key configured accepts everything; once enforcement is
  armed the peer must keep signing (a tokenless call is then a downgrade
  attack and is rejected `Unauthenticated`); a tokenless call before
  enforcement arms is allowed as a key-rollout grace. **Enforcement arms
  off EITHER a prior valid fabric token OR the heartbeat authenticating
  the peer** (`Manager.HeartbeatPeerAuthSeen`): the heartbeat flows
  continuously (~200ms), so after a keyed node restarts the guard arms
  within one interval instead of waiting for the next on-demand fabric RPC
  — closing the post-restart window in which the fabric would otherwise
  grace-accept tokenless `ClearSessions`/failover. In a rolling upgrade
  the not-yet-keyed peer signs neither channel, so the grace still holds.
  (Residual: a >30s wall-clock skew between nodes exceeds the ±1-window
  token tolerance and fails cross-node fabric RPCs `Unauthenticated` until
  corrected — an operational NTP fault, not a bug.) The
  interceptors are installed on the fabric listener only; the loopback
  listener keeps the full service. The **same PSK** authenticates the
  heartbeat (#4326); it shares the `chassis cluster authentication-key`
  leaf and reuses the dual-accept posture. **The PSK is no longer optional
  in practice (#6611):** because all three channels fail OPEN unkeyed, an
  unkeyed cluster runs its entire control channel unauthenticated, and
  every config this repository shipped used to be unkeyed — so the
  enforcing branches were never exercised. `validateClusterAuthKeyStrict`
  now hard-rejects an unkeyed `chassis cluster` on the STRICT compile
  path and warns on the tolerant load / peer-sync path (#1960 no-brick:
  an in-place-upgraded unkeyed cluster keeps its config DB, still boots,
  and is keyed on its next commit), and every reference/test config sets
  a key. Strict is every caller of `compileTreeStrict`, not just the
  operator commit: `daemon.bootstrapFromFile` (the UNATTENDED first-boot
  import, where a reject leaves the node with NO active config) and
  `configstore.CheckText` (`xpfd check-config`, behind xpf-deploy and
  the day-0 loader) also refuse — so provisioning a NEW node fails
  closed, and the migration has a required order: key the running
  cluster first, then re-provision. `pkg/eventengine` remediation is
  strict too, so on a leniently-booted unkeyed cluster every
  `change-configuration` policy silently fails until it is keyed. Note also that session sync fixes a
  connection's auth state at connect and committing the key does not
  restart cluster comms, so an established stream stays unauthenticated
  until a daemon restart (#6628); config-sync carries the PSK in the
  clear over that HMAC-only link, so the key must be provisioned
  out-of-band (#6629); and rotation has no key overlap, making a
  mismatch a ~1s dual-master window rather than an auth hiccup (#6630).
  Operator guidance — generation, distribution, rolling rollout with the
  required restart, rotation — is in `pkg/cluster/README.md` →
  "Operating the control-link PSK (#6611)". The stronger residuals —
  removing the remaining identical-request / stream replay horizon (mTLS with
  per-node certs and stream request binding or a nonce challenge) and giving
  the session-sync stream CONFIDENTIALITY (#6629 — it is HMAC-authenticated
  today, F23 having landed, but not encrypted, so a config-sync push crosses it
  in cleartext) — remain deferred (see `pkg/cluster/README.md`).
  - **No allowlisted RPC may render a configured secret (#6532).** Being on
    this allowlist means being reachable from the peer chassis over the
    fabric IP, so the usual "loopback only" mitigation does not apply to
    anything listed above. `ShowText{Topic:"snmp"}` rendered the SNMPv1/v2c
    community — the v1/v2c authenticator — in cleartext there long after the
    REST (#5315) and CLI (#4111) siblings were hardened. The property is now
    asserted across the surface as a whole by
    `pkg/grpcapi/server_fabric_secret_render_6532_test.go`, which stages a
    config carrying every secret leaf in the redaction SSOT
    (`pkg/config/ast_redact.go` `secretIndices`), drives every allowlisted
    RPC and scans the rendered responses. The method set is **enumerated**
    from the live allowlist maps plus the method names the interceptor
    source special-cases, so allowlisting a new RPC fails the completeness
    gate until it is audited; the ShowText topic set is likewise derived
    from the dispatcher source. The structural reason the sweep finds only
    one class of leak is that every operator secret except the SNMP
    community is a `config.Secret`, whose `String()` masks it under
    `%s`/`%v`/`%q`/`%x` (#2053) — the community is a plain string because it
    is the `Communities` map key. `TestGRPCAPINeverUnwrapsSecretCleartext`
    asserts two things are absent here: any selection named `Reveal` (the
    cleartext accessor), and any **one-argument call** handed a
    Secret-bearing field. The second deliberately ignores the callee —
    matching conversion shapes (`string`, `(string)`, `[]byte`,
    `[](byte)`, …) failed across four review rounds because a conversion's
    callee is a type expression with open grammar, and `type Clear string;
    Clear(x.PSK)` unwraps the secret just as well. One argument is the line
    because the safe idiom `fmt.Fprintf(buf, "%s", x.PSK)` is
    multi-argument and redacts correctly.
    **This guard is syntactic and has a ceiling**, stated on the test
    itself: it fires where a field is NAMED, so it cannot follow a value
    into a local, a parameter, a helper return, an out-of-package field, or
    a multi-argument handoff, nor see `append`/`copy`/ranging/reflection.
    Closing those needs `go/types` resolution, or inverting to an
    explicit-allowlist over all 42 conversions in the package. The clean
    structural fix is upstream — making `config.Secret` a struct instead of
    a named string type would make `string(s)` fail to **compile** and
    collapse the whole shape space to the single accessor — but that is a
    `pkg/config`-wide change (`Secret` is comparable and used as a map key)
    and belongs in its own issue.
    Two companion meta-tests feed the scanner and the field harvest
    synthetic sources and assert each REPORTS every shape it claims. They
    are load-bearing, not decorative: an all-clear from a broken check is
    indistinguishable from an all-clear from a clean package, and this
    check has twice shipped blind while the suite stayed green.
- **HTTP REST** on `127.0.0.1:8080` — health, Prometheus `/metrics`,
  config endpoints, full gRPC parity.
  - **The two redaction SURFACES must agree, and the agreement is asserted
    rather than assumed (#8258).** Every operator secret is rendered by two
    independent routes: the TYPED route (the compiled `*config.Config`
    JSON/REST/gRPC surface), where a secret field is declared as the `Secret`
    type and `Secret.MarshalJSON` redacts automatically; and the AST route
    (`show configuration`, the gRPC config RPCs, the on-box CLI), where
    `secretIndices` matches keywords in a flattened `[]string` path. The typed
    route is SELF-MAINTAINING — one type annotation covers a new field — and
    the AST route is HAND-MAINTAINED, so a fix on the typed side exerts no
    pressure on the AST side. That asymmetry is why `archive-sites ... password`
    still rendered in full on the AST surface (#7511) after #7510 had fixed the
    typed one, and why the same story played out for `feed-server hostname` in
    the sibling URL pass (#8104).
    `pkg/config/ast_secret_redaction_census_8258_test.go` closes it with an
    agreement predicate: **a leaf is secret-bearing iff the typed route redacts
    its field as a `Secret`.** An unmapped field fails, and each mapped leaf is
    verified by planting a secret and rendering all four AST formats.

    The population has TWO routes, and the second was found by #8258's own
    starting point 3 after the first had shipped. A field redacts on the typed
    surface either because it is DECLARED `Secret` — enumerated by reflection
    over the compiled `Config`, in
    `ast_secret_redaction_census_8258_test.go` — or because it is CONVERTED to
    `Secret` at marshal time, which reflection cannot see because the field's
    type is still `string`. `SNMPCommunity.Name` is the live instance: a plain
    string wrapped as `Secret(c.Name)` inside `MarshalJSON`/`MarshalYAML`, and
    the SNMP v1/v2c community string is the v1/v2c authenticator. That route is
    enumerated with `go/ast` in
    `ast_secret_coercion_census_8258_test.go` — a conversion inside a method is
    a syntactic fact, so it is extracted rather than pattern-matched. Both
    censuses feed ONE map, so a leaf enrolled by either route gets the same
    behavioural verdict.

    The general lesson is #8104's own, arriving from the other direction: that
    census warns that defining a set as "things that call X" is a claim that X
    is the only route to the behaviour. Defining a set as "things whose TYPE is
    X" is the same claim, and a conversion is a route the type does not record.
    The sibling census for URL-shaped leaves (redacted by transform, not
    replacement) is `pkg/config/ast_url_redaction_census_8104_test.go`.
  - **Listener lifecycle is all-or-nothing (#5058).** `Server.Run` may
    serve both an HTTP and (with `web-management https` + a self-signed
    cert) an HTTPS listener; the two form ONE lifecycle. Run binds both
    listeners synchronously up front, so a bind failure on either closes
    whichever already bound and returns before anything serves. Once both
    are serving, any terminal serve error OR context cancellation shuts
    down BOTH servers and joins BOTH serve goroutines before Run returns.
    A single-listener failure therefore never leaves the sibling serving
    an orphaned management socket the daemon can no longer reach to close.
  - **Off-loopback bind requires api-auth (#4047).** The REST/config API
    serves the mutating endpoints (`config set/delete/commit/commit-confirmed/
    rollback/load/activate`, `system/action`) with **no** auth middleware
    unless `system services web-management api-auth {user … | api-key …}`
    is configured (`pkg/api/server.go` wires the middleware only when
    `cfg.Auth != nil`). The default loopback bind is safe; a
    `web-management http|https interface <mgmt-if>` stanza rebinds the API
    to a routable address, so binding off-loopback **without** api-auth would
    expose every mutating config RPC to the network. This is now closed at
    two layers: (A) a **commit-time hard-reject**
    (`validateWebManagementAuthStrict`, `pkg/config/compiler.go`) refuses a
    new config that binds off-loopback without api-auth (downgraded to a
    warning on the tolerant load / peer-sync path so an already-persisted
    config still boots — #1960); and (B) a **runtime fail-safe clamp**
    (`clampBindToLoopback` in `pkg/daemon`, applied in `resolveAPIBinds` /
    `daemon_run.go`) that, when the resolved bind is non-loopback and
    `apiCfg.Auth == nil`, pulls the bind back to a same-family loopback
    (`127.0.0.1` for IPv4, `::1` for IPv6, port preserved) and WARNs — so a
    leniently-loaded vulnerable config comes up on loopback (console/SSH remain
    the lifeline) instead of exposed. This clamp runs **unconditionally on every
    startup path** — `resolveAPIBinds` derives the bind/auth from the
    web-management stanza (if any) and then always applies the clamp, so it also
    covers a `--api-addr <routable>` flag with **no** `system services
    web-management` block at all (#5127). Before #5127 the clamp lived inside the
    web-management block and that flag path bound the mutating API off-loopback
    unauthenticated. The non-loopback test (`hostIsLoopback`) treats the Go
    wildcard spelling `:port`/`[::]:port` (an empty or unspecified host after
    `SplitHostPort`) and any unparseable host as **non-loopback** so
    `--api-addr :8080` with no api-auth is clamped, not left listening on every
    interface (#4903); only a genuine loopback IP or the literal `localhost` is
    exempt. The bind
    address is built with `net.JoinHostPort` so an IPv6 mgmt address is bracketed
    and both the clamp and `net.Listen` parse it. Adding api-auth and recommitting
    restores the off-loopback bind. HTTPS is covered by the same rule
    (transport encryption without authentication still lets any reachable
    client mutate config).
  - **Empty api-auth secret is not a credential (#5636).** A quoted-empty
    Basic password (`api-auth user <n> password ""`) or empty api-key
    (`api-key ""`) parses as a real credential row. Before the fix the
    #4047 gate counted it as a valid auth method (so an off-loopback bind
    was accepted), `daemon_run.go` wired the empty secret into the runtime
    `AuthConfig`, and the middleware's constant-time compare matched a
    request presenting `username:` (empty password) or an empty
    `Bearer `/X-API-Key token — an authentication bypass on an off-loopback
    bind. This is now closed at three layers: (1) a **commit-time
    hard-reject** (`validateAPIAuthNoEmptySecretsStrict`,
    `pkg/config/compiler.go`) refuses any api-auth stanza carrying an empty
    secret (downgraded to a warning on the tolerant load / peer-sync path so
    an already-persisted config still boots — #1960), and the #4047 gate's
    "authenticated" predicate (`apiAuthHasUsableCredential`) now counts only
    NON-empty credentials; (2) **runtime wiring** (`daemon_run.go`) drops
    empty passwords / api-keys and leaves `apiCfg.Auth` nil when nothing
    usable survives, so the part-B clamp still pulls a leniently-loaded
    off-loopback bind back to loopback; and (3) the **middleware**
    (`pkg/api/auth.go`) treats an empty configured secret as no valid
    credential (`checkAuthorization` requires `expected != ""`,
    `constantTimeAPIKeyMatch` skips an empty configured key) — the
    constant-time compare still runs unconditionally, so the #4157
    known/unknown-user timing profile is preserved.
  - **`/metrics` posture (#4162).** Authentication policy is owned by each
    enabled HTTP or HTTPS listener, using that listener's configured/effective
    `cfg.Addr` or `cfg.HTTPSAddr`; it is never inferred from the request host,
    forwarded headers, URL, or the sibling listener. With API auth configured,
    `/metrics` is unauthenticated only on a literal IPv4/IPv6 loopback bind
    (the standard Prometheus posture). Every routable, wildcard, hostname,
    malformed, or otherwise unprovable bind fails closed and requires the same
    Basic, Bearer, or API-key credentials as every other protected endpoint.
    `/health` remains exempt. With `cfg.Auth == nil`, no auth wrapper is
    installed on either listener, so both use the shared base mux unchanged.
  - **Cross-site mutation guard (CSRF, #5055).** HTTP Basic auth is an
    *ambient* browser credential (`WWW-Authenticate: Basic`) — once a browser
    is challenged it reattaches the cached credentials to every request to the
    origin, including a cross-site `fetch(...,{credentials:'include'})` or a
    cross-site `<form>` POST. The same-origin policy blocks *reading* the
    response but not *sending* the side-effecting request, so a malicious page
    could drive a credentialed state change. `mutationCrossSiteGuard`
    (`pkg/api/crosssite.go`) wraps the mux BEFORE `authMiddleware` and rejects
    any non-safe-method request (403) that shows cross-site provenance:
    `Sec-Fetch-Site: cross-site|same-site`, an `Origin`/`Referer` whose
    host:port differs from the target, or a CORS "simple" form content type
    (`application/x-www-form-urlencoded` / `multipart/form-data` /
    `text/plain`). A same-origin management-UI request (Sec-Fetch-Site
    same-origin / none, matching Origin, `application/json`) and a programmatic
    client (curl/CLI/scraper — none of those headers, `application/json` or an
    empty body) both pass. Header-based API-key/Bearer clients are unaffected —
    a cross-site page cannot set `Authorization: Bearer` / `X-API-Key`. The
    guard applies whether or not api-auth is configured.
  - The seven `xpf_sessions_*` aggregate gauges are backed by a full walk
    of the shared v4+v6 conntrack tables (up to ~10M entries). That walk is
    served from a short-TTL (`sessionGaugeTTL`, 3s), singleflight-coalesced
    cache, so the walk rate is capped at ≤1 per TTL regardless of scrape
    frequency or concurrency — a tight-loop or unauthenticated scraper
    cannot amplify the O(sessions) scan. Normal scrape intervals (15-60s)
    always land outside the window and see fresh counts. `/metrics` is also
    registered with `promhttp.HandlerOpts{Timeout, MaxRequestsInFlight}` to
    bound slow/concurrent scrapes.
- **CLI** — interactive Junos-style with tab completion, `?` help, pipe
  filters (`| match`, `| count`, `| except`).
- **Remote CLI** — the `cli` binary connects via gRPC with full tab/`?`
  parity.

## Code layout

| Path | Description |
|------|-------------|
| `bpf/headers/*.h` | Shared C structs/constants consumed by the retained Rust AF_XDP shim build and userspace-dp parity tests. The legacy `bpf/xdp/*.c` and `bpf/tc/*.c` source were deleted in #1476 |
| `pkg/config/` | Junos parser, AST, typed config, compiler |
| `pkg/cmdtree/` | Single source of truth for the operational CLI command tree |
| `pkg/configstore/` | Candidate/active/commit/rollback, atomic DB persistence, JSONL audit journal |
| `pkg/dataplane/` | Runtime contracts, retained userspace shim embed/loader, eBPF/DPDK retirement-error sentinels (#1476/#1525) |
| `pkg/dataplane/userspace/` | Go manager for the Rust userspace dataplane |
| `userspace-xdp/` | Retained Rust XDP shim that redirects packets into the AF_XDP userspace runtime |
| `userspace-dp/` | Rust AF_XDP userspace dataplane binary |
| `pkg/daemon/` | Daemon lifecycle, reconciliation, interface management |
| `pkg/cluster/` | Chassis cluster HA (state machine, session sync, config sync, IPsec SA sync) |
| `pkg/vrrp/` | Native VRRPv3 state machine (30ms RETH advertisements) |
| `pkg/ra/` | Embedded RA sender (replaces radvd) |
| `pkg/cli/` | Interactive Junos-style CLI |
| `pkg/conntrack/` | Session garbage collection (with HA delete sync) |
| `pkg/logging/` | Ring buffer reader, event buffer, syslog client |
| `pkg/dhcp/` | DHCPv4/DHCPv6 clients |
| `pkg/frr/` | FRR config generation + managed section in frr.conf |
| `pkg/networkd/` | systemd-networkd .link/.network file generation |
| `pkg/routing/` | GRE tunnels, VRFs, XFRM interfaces, rib-group + next-table route leaking |
| `pkg/ipsec/` | strongSwan config + SA queries |
| `pkg/api/` | HTTP REST API + Prometheus collector |
| `pkg/grpcapi/` | gRPC server + protobuf bindings |
| `pkg/flowexport/` | NetFlow v9 exporter |
| `pkg/feeds/` | Dynamic address feed fetcher |
| `pkg/dhcpserver/` | Kea DHCP server management |
| `pkg/dhcprelay/` | DHCP relay with Option 82 |
| `pkg/eventengine/` | Event-driven automation engine |
| `pkg/rpm/` | RPM probe manager |
| `pkg/snmp/` | SNMP agent (system + ifTable MIB) |
| `pkg/lldp/` | LLDP protocol |
| `proto/xpf/v1/` | Protobuf service definition |
| `cmd/xpfd/` | Daemon main binary |
| `cmd/cli/` | Remote CLI client binary |
| `docs/` | Protocol docs, design notes, test plans, feature gaps |
| `test/incus/` | Test environment scripts and configs |

## See also

- [`engineering-style.md`](engineering-style.md) — coding/review
  discipline and hot-path allocation rules.
- [`critical-patterns.md`](critical-patterns.md) — the project-specific
  gotchas (byte order, struct alignment, BPF verifier, SR-IOV/XDP,
  interface management) that repeatedly bite.
- [`network-topology.md`](network-topology.md) — test-VM and HA-cluster
  interface maps.
- [`feature-coverage.md`](feature-coverage.md) — the full feature matrix.
