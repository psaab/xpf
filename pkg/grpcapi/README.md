# pkg/grpcapi

gRPC server. Implements ~48 RPCs spanning config lifecycle (enter, set,
delete, commit, rollback, history), operational queries (sessions,
routes, NAT, IPsec, DHCP, VRRP, …), diagnostics (ping, traceroute as
server-streaming), monitoring (drops, interface), mutations (clear), and
tab completion. The wire schema is `proto/xpf/v1`.

## Entry points

- `Server` — `server.go`.
- `Config` — `server.go`. Dependency injection point.
- `NewServer(addr string, cfg Config) *Server` — `server.go`.
- `Run(ctx context.Context) error` — `server.go`. Starts the listener
  and blocks until the context is cancelled.
- `RunFabricListener(ctx, addr, vrfDevice)` — `server.go`. Supervises the
  network-exposed peer-proxy listener (see trust boundary below). Blocks
  until ctx is cancelled; the caller starts it **once** and the retry
  supervision is internal (#5047).
- Tab completion: `Complete` RPC, backed by `pkg/cmdtree`.

## Trust boundary (loopback-only, #5035 + per-principal, #5278)

The primary listener started by `Run` is loopback-bound **and** authorizes
every RPC against the caller's Junos login class. Before #5278 it did only
the first, and the first is a **location, not an identity**: the daemon
provisions every `system login user` a real shell account
(`useradd -m -s /bin/bash`), so a `read-only` or `operator` class holder
could log in, dial `127.0.0.1:50051` with three lines of insecure gRPC
client and invoke `SystemAction{zeroize,reboot,power-off}`, `Commit`,
`Delete` and `Rollback` — executed by a root daemon. `pkg/cli`'s
`checkPermission` runs in the CLI **process**, on the caller's side of the
boundary, so it constrained only callers who chose to use the CLI; the
remote `cli` binary carried no login class at all and never ran it. The
#5209 config-lock holder check answers *which connection* holds the lock,
not *who is on it*.

See **Server-side authorization** below. The loopback clamp is unchanged
and still wanted: identity here comes from the kernel's socket table, an
answer that exists only for a caller on this host, so a non-loopback bind
would publish a listener that can only refuse.

**Config-session identity (#5849).** The config lock / candidate DB is a
per-CLIENT-CONNECTION resource. Each config RPC keys its session by
`connSessionID(ctx)` — an **unguessable, connection-scoped id** allocated
in `configLockStatsHandler.TagConn` (crypto/rand), NOT the reusable peer
address. The lock is auto-released **exactly once** on `ConnEnd` (a
per-connection `sync.Once`, plus the store's holder check), never on a
per-RPC cancellation: a client cancelling one unrelated read, or a request
deadline expiring, no longer discards the connection's staged candidate or
steals its lock. Explicit `ExitConfigure` (immediate) and the store's
bounded idle-lease reclaim (`reclaimStaleLockLocked`, #4476) remain as
backstops for a connection whose `ConnEnd` notification is lost. The same
`stats.Handler` is installed on the fabric listener for a uniform lifecycle
(a no-op there — the fabric allowlist never admits config RPCs). `Run` therefore clamps a non-loopback `--grpc-addr`
(`0.0.0.0`, a routable address, or the `:port` wildcard) back to a
same-family loopback (`clampGRPCBindToLoopback`) and warns, mirroring the
web-management (#4903) and cluster-bind (#4928) doctrine. There is no
auth mode that unlocks a non-loopback bind here: the intentionally
network-exposed gRPC surface is the **separate** fabric listener
(`RunFabricListener`), which authenticates (#4107) and allowlists (#4122)
every call.

**Unkeyed fabric listener (#10698).** Without `chassis cluster authentication-key`,
the network-exposed listener admits only `GetStatus` for its health probe.
Session/recon RPCs, `ClearSessions`, `MonitorInterface` and cross-node failover
are rejected as `Unauthenticated` until a PSK is committed. Missing a key is an
indefinite configuration state, not a rollout grace; a configured key retains
the existing peer-authentication rollout grace.

### Peer hop markers are a listener capability, not a header (#5883)

Two internal metadata keys bound cluster forwarding to one hop:
`x-peer-forwarded` (session clear, summary/zone-pair fan-out, system-action
proxying) and `xpf-no-peer` (chassis-forwarding and `MonitorInterface`
proxies). Every handler that reads one uses it to **suppress** work.

They used to be read straight off incoming metadata by presence, which made
them caller-settable: any client that could reach a listener could claim to
be a forwarded peer request and have the node skip the peer half of a
cluster-wide operation while still returning success — a clear that reports
it cleared the cluster and did not.

The trust is now a property of **which listener received the call**, and a
listener decides it:

- the **fabric** listener is the only one a peer dials. Its chain is
  `fabricAuth -> fabricAllowlist -> peerMarker(trust=true)`, in that order,
  so #4107 auth and the #4122 allowlist both accept the call before the
  header is promoted into an in-process context value;
- the **loopback** listener installs `peerMarker(trust=false)`. No peer
  dials it, so an inbound marker there is forged by definition: it is
  stripped and nothing is promoted.

Both listeners then **strip** the reserved keys, so a handler that reaches
for the raw header finds nothing. That is not belt-and-braces — a site in
`server_sessions.go` did exactly that instead of calling the helper, and
stripping is what stops the next one from re-opening the hole.
`reservedPeerMetadataKeys` is the single source of truth for both the strip
and the promote, pinned by `TestReservedPeerMetadataKeysAreComplete`.

The absent-capability default is `false` for both markers, which is the safe
direction: false means *do the peer work*, so a stripped or forged header can
only cause more work to be attempted, never less.

The marker still rides an ordinary metadata header on the wire between nodes
— that is the only channel there is. What changed is that a header is
evidence only when the listener that received it is one a peer could have
dialed.

### Fabric-listener supervision (#5047)

`RunFabricListener` is a supervised loop, not a one-shot. A transient
bind failure or a later `Serve` fault used to be **terminal** — the
listener returned/blocked forever and the peer-proxy surface (monitor,
peer-show, proxied-failover) was permanently lost until the whole
cluster-comms lifecycle restarted, with no fallback on a single-fabric
deployment. It now re-binds and re-serves on any fault with a bounded
exponential backoff (100 ms → 5 s cap, reset after a `Serve` that stayed
up ≥ 30 s) while ctx is live, so a persistent bind failure keeps retrying
at the cap without spinning. The expected graceful-shutdown signals
(ctx cancel, `grpc.ErrServerStopped`) exit cleanly and are never retried,
and neither the supervisor nor its `Serve` worker outlives ctx. Per-bind
up/down health is published via `FabricListenerUp(addr)` /
`FabricListenerHealth()` and logged at Info/Warn on transitions (retry
ticks are Debug).

### Primary-listener supervision, and the one failure that is fatal (#7611/#8233)

The primary (management) listener is supervised the same way, with one
exception: **`EADDRINUSE` is bounded, and then it ends the daemon.**

Unbounded retry there was how a second `xpfd` came up silently. The bind
genuinely fails — the primary listener is a plain `net.Listen("tcp", addr)`
with no `ListenConfig` and no `Control` hook, so it sets **no** socket options
(`RunFabricListener` above *does* set `SO_REUSEPORT`, which is a different
socket and the source of a long-lived misconception recorded in three
`pkg/cluster` comments now corrected). The supervisor logged the failure,
marked the listener Failed, backed off and retried forever, and `Run` returned
nil — so the daemon started, everything else came up, and every gRPC-driven
surface was gone with no external signal (#8195).

**Why bounded rather than fatal on sight.** `test/incus/xpfd.service` sets
`Restart=on-failure`, `RestartSec=1`, `TimeoutStopSec=20`. A restart starts the
successor one second after the predecessor is asked to stop, and the
predecessor has twenty seconds to exit — so `EADDRINUSE` at startup is
*routinely* transient, and it is the predecessor legitimately shutting down.
Failing immediately would turn a slow shutdown into a **restart loop**, because
`Restart=on-failure` makes the fatal exit re-trigger the start. Whether the
collision **resolves** is the only property separating a restart overlap from a
steady-state duplicate, and a window is how you measure it:
`primaryAddrInUseGrace` (30 s) is sized past `TimeoutStopSec`, and
`TestPrimaryAddrInUseGraceExceedsUnitStopTimeout_8233` parses the unit so
raising the stop timeout cannot silently reintroduce the loop.

Scope: **only** `EADDRINUSE` — a permissions failure or a missing VRF is a
different condition and stays supervised forever. The window measures a
*continuous* run, reset by any successful bind or intervening error, so
intermittent collisions cannot accumulate toward it. On expiry `Run` returns
`ErrManagementPortHeld`, the daemon treats it as fatal (`grpcRunErrIsFatal`),
and the process exits non-zero naming what it waited for.

**What this does NOT close.** The mixed-version window. A supervisor that
ignores the exit code can still start a second daemon, and nothing here helps a
node already in the two-daemon state. #7501's live-sibling refiner remains the
mechanism that **tolerates** that state; this reduces how often it is reached.
The two are not alternatives.

## Server-side authorization (#5278)

Every RPC on the primary listener — read, mutation and stream alike — is
gated on a **server-derived principal** before it reaches its handler.
`authz.go` owns the mechanism, `authz_methods.go` the tables, and the
decision itself is `pkg/authz`'s, shared with the REST leg (#5561) so the
two control planes cannot disagree about what a class permits.

**How the caller is identified.** The owning UID of the peer's socket is
read out of the kernel's own socket table (`/proc/net/tcp{,6}`, matched on
the full 4-tuple, `TCP_ESTABLISHED` only), resolved to an account name via
`/etc/passwd` (`pkg/osident`) and then to a class via
`system login user <name> class`. The caller supplies no part of the
answer. `SO_PEERCRED` would answer the same question, but only for
`AF_UNIX`; this is an `AF_INET` listener. The three properties that make
that lookup sound — full-address match, the `TCP_ESTABLISHED` requirement,
and resolution at accept — are argued with their mutation proofs in
[`pkg/api/README.md`](../api/README.md) and `pkg/authz/peer.go`.

**Where this leg differs from the REST leg, and why.**

| | REST (#5561) | gRPC (#5278) |
|---|---|---|
| Identities | peer UID **or** an `api-auth` credential | peer UID only |
| Precedence rule | four rows, one of which admits on a negative | none — anything not an attributed UID is denied |
| Gated surface | mutations only | every RPC, reads included |
| Lookup timing | goroutine at `ConnContext`, bounded pool, request waits | inline in `TagConn` |
| `SystemAction` | one route, folded to `PermMaint` | priced per verb |

- **No credential row** makes this leg strictly stricter. There is nothing
  weaker to fall through to, so `PeerIdentity.Local` is not consulted at
  all: "local but unattributable" and "not on this host" both deny, and
  `authz.PeerCouldBeLocalNow` (which exists to narrow the credential row)
  has nothing to narrow.
- **Reads are gated** because this surface has no scraper population —
  nothing polls `GetSessions` on a timer, and `show configuration` here is
  exactly the render `config-viewer` exists to scope. The REST leg left its
  read surface open for `/metrics` and health probes; that divergence is
  deliberate and is recorded on both sides.
- **The lookup runs inline** because `grpc-go` calls `TagConn` on the
  connection's OWN goroutine (`Server.Serve` → `go handleRawConn` →
  `serveStreams` → `TagConn`), not in its accept loop. `http.Server` calls
  `ConnContext` serially in the accept loop, which is why the REST leg has
  a goroutine, a bounded pool, a per-connection deadline and a request-side
  waiter. None of that machinery is needed here, and none of its failure
  modes are inherited. What remains bounded is bounded in `pkg/authz`: the
  socket-table read is single-flighted with a capped queue whose saturation
  answers with an error, which denies.
- **Two methods are priced from their request, not their name.**
  `SystemAction` multiplexes three permission tiers (`reboot`/`zeroize` at
  `maintenance`, `clear-arp`/`clear system config-lock` at `clear`,
  `request dhcp renew`/`bgp-clear` at `control`), and `ShowText`
  multiplexes ~127 topics across two command families — 124 reached from
  `show ...` at `view`, and three (`test-policy:`, `test-routing:`,
  `test-zone:`) emitted by `test ...`, which the CLI charges at `control`.
  A unary gRPC interceptor is handed the DECODED request, so both are
  available without buffering anything the caller controls. Folding either
  up to its floor — which the REST middleware must do, because it
  deliberately never reads a body — would have taken the `clear` family and
  every `show` topic away from the classes that hold them today. The
  name-level entry for each IS that floor, used only when the request
  cannot be read.

  `ShowText` is also where the first revision of this gate was wrong: it
  was priced flat at `view` with the comment "every topic is a `show ...`",
  which let a `read-only` class run `test policy` — policy reconnaissance,
  i.e. which rule matches a given 5-tuple — over gRPC. Nothing caught it
  because the method-table guard enumerates the service DESCRIPTOR, so a
  complete method table is a **vacuous pass** for topic pricing. A guard
  proves the property it enumerates and nothing adjacent to it; hence the
  sibling guard below.

**Fail closed, and how that is proven.** A method absent from the table —
or a `SystemAction` verb, or a `ShowText` topic — costs the strictest tier
(`PermAll` for a method or topic, `PermMaint` for a verb), and the miss is
logged at `Error`. That is the weak half. The strong half is three guards,
one per dimension, each enumerating **generated or production source**
rather than a list a human typed, and each failing in BOTH directions
(something served but unpriced, something priced but not served):

| Guard | Enumerates |
|---|---|
| `TestEveryServiceMethodHasAPermission_5278` | the generated service descriptor (48 unary + 4 streaming) |
| `TestEverySystemActionVerbHasAPermission_5278` | the `case` labels of `switch req.Action` in `server_diag_system_action.go` |
| `TestEveryShowTextTopicHasAPermission_5278` | every literal compared against `req.Topic` in `server_show.go` — `HasPrefix`, `==`, and `switch` case labels |

Three guards because there are three dimensions, and a guard is vacuous
for every property it does not enumerate. All three `t.Fatal` if their
enumeration source cannot be read or has moved, so an unreadable source
reds rather than passing empty.

**Behaviour changes an operator will see.**

- A `read-only`/`config-viewer`/`operator` class holder running `cli` is now
  refused the RPCs its class does not hold, with a message naming the
  `system login user <name> class <class>` stanza to change.
- A local account that is **not** a `system login user` gets nothing.
  Previously it got everything. "Not in the RBAC model" is a reason to deny,
  not a reason to pick a default class.
- **uid 0 is authorized unconditionally**, without consulting `/etc/passwd`
  or the config (`authz.PrincipalForUID`). Root owns the config DB and the
  daemon process, so a denial would be theater, and depending on a config
  snapshot would refuse the operator on a box that has not finished booting.
  The in-daemon rolling/kernel upgrade driver (`pkg/upgrade`, which dials
  `127.0.0.1:50051`) runs as root and is unaffected.
- The `unauthorized` class holds no permissions, so it now loses `cli`
  entirely — including the startup `GetStatus` probe. That is what the class
  means.

**What is NOT gated.**

- The **fabric listener** keeps its own, different chain: `#4107` PSK
  authentication plus the `#4122` RPC allowlist. A cluster peer is a NODE,
  not a login user — it has no uid on this host, so the principal gate would
  deny every cross-node proxy. The two chains are built in separate
  functions (`buildPrimaryServer` / `buildFabricServer`) and share no
  interceptor; `TestPrimaryAndFabricChainsAreDistinct_5278` pins that
  structurally and `TestFabricListenerDoesNotApplyThePrincipalGate_5278`
  behaviourally. Every peer dial in the tree
  (`pkg/grpcapi/server_diag.go`, `pkg/cli/peer.go`,
  `pkg/daemon/daemon_ha_sync.go`) targets a peer's **fabric** address, never
  a loopback one, so HA is untouched.
- **In-process calls.** `pkg/api` invokes `ClearSessions`/`GetSessions`/
  `GetSessionSummary` on the live `*grpcapi.Server` directly (`#3423`), with
  no connection and therefore no interceptor. That path is gated by the REST
  leg's own #5561 middleware before it gets here. The in-process console CLI
  never dials this listener at all — its three `NewBpfrxServiceClient` call
  sites all go through `dialPeer()` to the PEER's fabric address.
- A **non-TCP** peer (a Unix socket, a `bufconn`) cannot be attributed by
  `authz.LookupPeer` and is therefore denied. That is correct for a listener
  that only ever binds TCP; a test serving over `bufconn` must inject
  `Config.PeerLookupFn`.

## Canonical command tables (#7172)

`authz_methods.go` answers *what permission does this RPC cost*.
`authz_command_table.go` and `authz_command_table_topics.go` answer a
different question — *what command is this RPC* — for `system login class`
`allow-commands` / `deny-commands`, which are regexes matched against a
command string.

**Why the server has to answer it.** The remote `cli` parses the operator's
line CLIENT-side and sends a typed RPC; the line never crosses the wire.
`authorizeRPC` sees `("/xpfv1.BpfrxService/GetInterfaces",
*pb.GetInterfacesRequest)` and nothing resembling a command, so
`deny-commands "show interfaces"` — which `pkg/cli` enforces on the on-box
CLI — would have nothing to match remotely. Adding a command string to the
RPCs was rejected: it would be CLIENT-supplied, and an authorization
decision derived from attacker-controlled input is not an authorization
decision.

**Three tables, because the two multiplexed methods are multiplexed here
too.** `methodCanonicalCommand` keys on the short method name;
`showTextTopicCommand` and `systemActionVerbCommand` key on the decoded
request's topic and verb, exactly as `showTextTopicPermission` and
`systemActionPermission` do. `showTextTopicCommand`'s DATA moved to
`pkg/cmdtree/showtext_topic.go` in #8058 and this package holds a view onto
it — the remote CLI reads the same table to decide what topic to send, so
the two surfaces can no longer disagree about which command a topic means.
Add or rename a topic there; the checks below are unchanged and still run
here, because they are properties of this package's dispatcher. A method with no command entry must be NAMED
in `methodsWithoutCanonicalCommand` with a reason, so an intended absence
is distinguishable from a forgotten one.

| Guard | Enumerates |
|---|---|
| `TestEveryPricedMethodIsMappedOrNamedAbsent7172` | `methodPermissions`, i.e. the pinned method set |
| `TestEveryShowTextTopicHasACanonicalCommand7172` | `showTextTopicsFromDispatcher` — the same `server_show.go` literals the #5278 topic guard reads |
| `TestEverySystemActionVerbHasACanonicalCommand7172` | the `case` labels of `switch req.Action` in `server_diag_system_action.go` |

Plus a validity rule on every value: it must resolve against
`cmdtree.OperationalTree` **to itself**, with every word a real command
KEYWORD rather than a word a value slot absorbed (`show interfaces zzbogus`
canonicalizes fine — value slots take operator data by design, #8094).

**Completeness and canonicality are checked; ATTRIBUTION is not.**
`chassis-cluster-status` mapped to some other real canonical command passes
every test in this package. There is no server-side signal for which command
reaches a topic: deriving it from the topic name reproduces about a third of
the table (`TestTopicNameDerivationDoesNotReproduceTheTable7172` measures and
logs the rate), and the handler name is `camelCase(topic)`, which restates
the topic and agrees with it by construction. The only sound source is
`cmd/cli`, which is not mechanically walkable today (computed topic strings,
nested switches); making that mapping declarative is #8058. Until then, a
reviewer checking these tables is the check.

**Named gap: the entries are ARGUMENT-FREE.** `pkg/cli`'s gate matches a
deny regex against the full canonicalized line *including* arguments and the
output pipe. These strings have neither — a parameter-packed topic
(`route-table:<name>`) maps to the command prefix that precedes the
parameter (`show route table`). So a regex written against argument text
matches on the box and not on the RPC; a regex written against the command
path — the shape Junos' own examples use — matches identically on both,
because matching is partial rather than anchored.

**Prefix-form `SystemAction` verbs have no entry and cannot get one.** The
handler's default branch parses `cluster-failover*` and the `userspace-*`
control forms out of a packed string, so they have no case label to
enumerate. The verb table's completeness guard reads case labels, so it is a
floor over what the handler **dispatches**, not a census of what it
**accepts** — and a complete-looking table is exactly how these would become
allow-by-omission. The gate denies them explicitly, by the same rule as any
other unmapped verb.

### The gate (#7172 cut 5b)

`authorizeRPC` evaluates the calling class's `deny-commands` regexes against
the mapped command, **after** the coarse permission check and never instead
of it. `config.OperationalDenyRegexesFor` owns "whose regexes are in force",
and `pkg/cli`'s cut-3 gate delegates to the same function, so the two
surfaces cannot come to disagree about which classes are restricted or about
leaf **presence** (`deny-commands ""` denies everything; an absent leaf
denies nothing).

**Deny only.** `allow-commands` commits today and is documented as inert;
enforcing it would be a lockout on upgrade, because an allow regex is an
allowlist. It goes live in cut 6 with the #6838 retirement.

**Every uncertain path denies, and only for a class that configured
regexes** — a class with none pays nothing:

| case | why it denies |
|---|---|
| regexes do not compile | validated at commit, so this config arrived by a path that did not validate |
| no canonical command (config-mode method, a method named absent, an unknown topic, a prefix-form verb, an unreadable request) | not knowing which command we hold, we cannot know a deny regex fails to match it |

**The two surfaces do NOT match the same string, and a populated table is not
evidence that they do.** `pkg/cli` matches the full canonicalized line,
argument values and output pipe included. This gate matches the command
**path**, because the remote CLI parses the line client-side — `ping
10.0.0.1` arrives as `Ping{Host:"10.0.0.1"}`. So:

- a deny written against a **path** (`request system reboot`, the shape
  Junos' own examples use) is enforced identically on both, since matching is
  partial rather than anchored;
- a deny written against **argument text** (`show route table secret-vrf`) is
  enforced on the box and **not** here — an under-deny, i.e. fail-open for
  that class of pattern. `TestArgumentLevelDenyIsOnBoxOnly7172` asserts the
  difference in one place rather than leaving it in prose.

The operator is told which of their patterns this affects.
`unenforceableDenyPatterns` asks whether a pattern matches **any** command
this listener can produce; one that matches none can never fire here, and is
logged once per class. That check deliberately does **not** inspect the
pattern: `regexp.LiteralPrefix` returns `""` for `^show route table
secret-vrf`, so a literal-prefix heuristic would cover the unanchored
spelling and silently miss the **anchored** one — the spelling Juniper's
guidance tells operators to use. A guard that covers one spelling of the same
intent reads as coverage and is not.

## Commit advisories: a four-hop chain, and the hop that had no cell (#8484)

A commit-time advisory is only worth having if the operator SEES it. It
crosses four hops, and each one can drop it silently:

| # | hop | code | bound by |
|---|---|---|---|
| 1 | produce | `cfg.Warnings` in the compiler | each advisory's own cell |
| 2 | seam | `commitWithGenBinding` returns the compiled config | `pkg/daemon/commit_seam_advisory_8484_test.go` |
| 3 | transport | `configWarnings()` -> `CommitResponse.warnings` | `commit_advisory_warnings_6515_test.go`, `commit_advisory_transport_8484_test.go` |
| 4 | render | `printRemoteConfigWarnings` in the remote CLI; `printConfigWarnings` in the local CLI | `cmd/cli/remote_commit_advisory_render_8484_test.go` |

**The delivery mechanism is generic and must stay that way.** `configWarnings`
projects `cfg.Warnings` wholesale, so a NEW advisory needs no delivery wiring
at all — #8189's login-class advisory reached the remote CLI with zero
transport work. If an advisory ever needs its own plumbing, the next one will
be dropped; fix the carrier instead.

**Hop 2 is the one to watch.** #8484 was filed believing two advisories were
produced and dropped; measured, they were not — every hop carried them. But
hop 2 had NO cell: a mutant that strips `Warnings` in `commitWithGenBinding`
survived `pkg/daemon`, `pkg/grpcapi`, `cmd/cli`, `pkg/cli`, `pkg/config` and
`pkg/configstore` with **zero** failures. Every advisory cell in the tree
asserted `cfg.Warnings` (hop 1); nothing asserted what the operator reads.

**Every cell here carries an accept-side silence control.** A commit raising no
advisory must render nothing. Without that, a path printing unconditionally
satisfies every delivery assertion while inventing advisories on clean configs
— and an advisory an operator learns to ignore is worse than none.

## Callers

`cmd/xpfd` (instantiates and runs); `cmd/cli` (consumes); HTTP REST
bridge in `pkg/api`.

## Dependencies

`cluster`, `config`, `configstore`, `conntrack`, `dataplane`, `dhcp`,
`dhcpserver`, `feeds`, `frr`, `ipsec`, `logging`, `fwdstatus`, `ra`,
`routing`, `rpm`, `vrrp`, plus most of the rest of `pkg/`.

The dataplane dependency is intentionally narrow: `Config.DP` and
`Server.dp` are typed against the unexported `grpcRuntime`
interface declared in `runtime.go`, **not** the full
`dataplane.DataPlane`. `grpcRuntime` lists exactly the methods the
gRPC handlers invoke via `s.dp.*` (counters, session-read,
session-clear, map-stats, persistent-NAT) and is a strict subset
of `dataplane.DataPlane`, so any concrete dataplane that satisfies
the legacy interface also satisfies `grpcRuntime`. The userspace-
specific provider capabilities (`Status`, `SetForwardingArmed`,
`SetQueueState`, `SetBindingState`, `InjectPacket`) live on named
provider interfaces (`userspaceStatusProvider`,
`userspaceControlProvider`) in the same file; the gRPC server
probes them via type assertion on `s.dp`. Cursor-based session
pagination uses the `sessionCursorIterator` probe, also in
`runtime.go`. This is the boundary that the #1373 eBPF retirement
narrows; see `docs/pr/1373-retire-ebpf-dataplane/README.md` and
`docs/pr/1516-grpcapi-migration/plan.md` for the migration
contract.

## Gotchas

- Configure mode is **exclusive on the secondary node** in cluster mode.
  Primary (RG0 master) is the config authority; the secondary rejects
  `EnterConfigure` until it's promoted.
- `peerSessionID()` is extracted from the gRPC peer credentials and used
  to distinguish exclusive vs. shared configure sessions. A session ID is
  required for any commit.
- `CommitFn` (passed in by the daemon) holds the apply semaphore across
  `Commit()` and the dataplane apply. This is the same primitive `pkg/cli`
  uses; concurrent operator commits serialize via that semaphore (#846).
- **Commit error-code contract (#5742).** `Commit` / `CommitConfirmed`
  classify the callback error structurally via `commitApplyStatus`, keying
  off whether the daemon returned the committed config alongside it:
  a **non-fatal tail-reconcile / ordinary dataplane-apply** error (networkd
  write, Kea restart, IPsec reload, interface reconcile, non-abort apply —
  the daemon commits+arms the config and returns it *with* the error) →
  `codes.Unavailable` (transient, **retryable**; the config was accepted and
  self-heals on the next commit/feed retry, #5646). A true **config-validation
  / compile-reject** (compiler/schema reject, `compileErrorMustAbortApply`
  fail-closed gate, device-map preflight, bootstrap refusal, pre-promotion
  persistence — no config committed, `nil` returned) → `codes.InvalidArgument`
  (fix the config). `context.Canceled` / `DeadlineExceeded` are preserved and
  take precedence. The human-readable message is unchanged; only the code
  distinguishes "retry" from "fix your config". Unclassifiable errors fail
  safe to `InvalidArgument`.
- **Zeroize goes through the apply gate AND stops xpfd (#5281).** The
  `SystemAction{zeroize}` handler does NOT call `performZeroizeWipe`
  directly. It routes through `ZeroizeFn` (wired by the daemon to
  `factoryReset`), which takes the SAME apply semaphore `CommitFn` uses
  and enters a **terminal reset generation** before erasing, so a
  concurrent in-flight apply is drained and no later commit / HA-sync /
  reconcile re-creates the erased `.configdb` SSOT or re-renders the wiped
  secrets (frr.conf / swanctl PSKs / Kea / login accounts). On a
  fully-successful wipe the handler then schedules `scheduleStopDaemon`
  (`systemctl stop xpfd` after a 1 s grace, mirroring the local
  `request system zeroize` CLI path in `pkg/cli`) so the daemon does not
  keep running with the pre-wipe in-memory `ActiveConfig`. The sequence is
  strictly **gate → wipe → stop**, fail-CLOSED: a wipe that does not
  complete returns `Internal` and does **not** stop the daemon (stopping a
  half-wiped box would strand prior-tenant secrets on disk). The `#4108`
  action-journal write still happens BEFORE the wipe. `ZeroizeFn` is nil
  only in a NoDataplane / no-daemon build, where the handler falls back to
  an ungated direct wipe (there is no running reconcile loop to race).
- **The interactive console shares ONE wipe primitive (#5890).** The
  in-process console `request system zeroize` (`pkg/cli`) previously ran
  its OWN partial wipe (`zeroizeConfigState`: config DB + archive only),
  which LEFT `tls/`, the rendered service configs (frr/swanctl/kea), and
  the provisioned login accounts (shadow/authorized_keys/`sudoers.d/xpf-*`)
  on disk — secret residue on a re-tenanted device. The console now
  DELEGATES to the exported log-aware `PerformZeroizeWipeWithLogInventory` —
  the SAME primitive `runZeroize` runs — so both paths erase an IDENTICAL
  single-source-of-truth OWNED-artifact set (including xpf firewall logs) and
  cannot diverge again. Journald copies and remote collectors remain outside
  this local wipe and are named in the success receipt. The
  console keeps its own root resolution (`cli.zeroizeConfigRoot`, #5554/
  #5684) and daemon stop. **The console also runs the wipe THROUGH the
  daemon's coordinated factory-reset transaction (#5871).** It does not dial
  gRPC (it is in-process); instead the daemon wires the SAME `factoryReset`
  gate it wires into the gRPC server as `ZeroizeFn` into the CLI via
  `cli.SetFactoryResetFn(d.factoryReset)`, and `cli.performConsoleZeroize`
  routes the wipe closure through it. So the console wipe now takes
  `d.applySem` and enters the terminal reset generation BEFORE erasing —
  identical fencing to the gRPC path — closing the pre-#5871 window where an
  ungated console wipe let a concurrent commit / HA-sync / reconcile re-create
  the just-erased `.configdb` SSOT or re-render the wiped secrets. When the
  CLI is spawned OUTSIDE the daemon (offline recovery / unit test)
  `factoryResetFn` is nil and the console falls back to the ungated direct
  wipe (no reconcile loop is running to race), mirroring `runZeroize`'s
  `zeroizeFn==nil` fallback. The rendered/BPF/networkd leg targets in
  `performZeroizeWipe` are package vars so the full primitive is hermetically
  testable end-to-end (no real `/etc`) — production paths unchanged.
- **The peer fan-out is charged to the REMOTE budget, not the local
  session-walk budget (#9041 part 2).** `GetSessions`, `GetSessionSummary`,
  `GetZonePairSummary` and `ClearSessions` acquire `sessionWalkLimiter` with
  `defer release()` over the whole handler and dialled the peer INSIDE that
  region. `MaxConcurrentSessionWalks` is 4 and the worst case is `dialPeer` 2s
  per fabric address (4s dual-fabric) plus the peer RPC (3s; 5s for the clear),
  so four concurrent requests saturated the budget below 1 rps and `GetStatus`
  and other genuine LOCAL scans answered `ResourceExhausted` while the local
  table was untouched — the exact wrong `peer_only_5968.go` names and #7294
  item 3 fixed for the peer-ONLY paths. These four are the paths #7294 did not
  reach: on them the slot legitimately covers a real local walk, and only the
  peer-RTT TAIL is excess. `beginPeerLeg` now hands the request off immediately
  before the dial — it takes a `RemoteWalkLimiter` slot FIRST and only then
  releases the local one, so a refused peer leg never costs the caller its
  local admission for a leg that never runs. Not a loosening: bounded by 4
  slots before and 4 after (`MaxConcurrentRemoteWalks == MaxConcurrentSessionWalks`);
  what changes is WHICH budget, so saturating the fan-out can no longer refuse
  a local scan. A refusal is `ResourceExhausted`, which `peerFetchErrorStatus`
  already classifies `PEER_FETCH_STATUS_BUSY`, so the peer block is reported
  refused rather than silently absent (#8306). Under a #5880 lease reuse the
  release is a no-op and the ancestor's slot is deliberately NOT freed — a
  descendant must not give away admission it does not own. The handoff lives in
  the four peer helpers rather than at their six call sites, because a
  forgotten call site is invisible: it just keeps the old behaviour.
- **Zeroize erases the upgrade config-DB SNAPSHOTS, not just the live DB
  (#9236).** `/var/lib/xpf/versions/.<ver>.dbsnap` is an unfiltered `copyTree`
  of `ConfigDBDir`, and `master.key` lives INSIDE that directory — so each
  snapshot is the AES-GCM body **and the key that opens it**, in one place.
  That is the README's own threat model (`pkg/configstore/README.md`: "copy
  `master.key` one directory over and decrypt"). It is not an in-flight
  window: `pkg/upgrade/flip.go`'s GC keeps a snapshot for as long as its
  version dir survives and `protected[]` covers current/target/previous, so
  after one successful upgrade it is the steady state of the box.
  `performZeroizeWipe` had zero occurrences of "versions" while knowing about
  `/var/lib/xpf/archive` and `/var/lib/xpf/provisioned-users`, and returned
  `Configuration erased` regardless — an affirmative receipt, at the RMA /
  resale / re-tenanting boundary the control exists for.
  `zeroizeUpgradeDBSnapshots` erases every `.<ver>.dbsnap` and
  `.<ver>.dbsnap.partial` with the SAME key-first discipline as the live DB
  (unlink `master.key`, fsync, then the body — #4576/#5197) and the same
  #9013 symlink refusal. It takes the host-wide upgrade lock FIRST and **fails
  busy rather than racing a cut**: a concurrent upgrade writes a fresh
  snapshot after the sweep passes it, so a half-erase would report success.
  Version directories, `.<ver>.partial` (staged BINARIES) and the `current`
  symlink are deliberately preserved — the target is the DB snapshots, not the
  running system. Every failure is folded into the surfaced result, so a busy
  lock or a failed unlink is an INCOMPLETE zeroize, never a clean one.
  Censused alongside it: `.configdb.restore.partial` and `.configdb.old`, the
  rollback path's sibling copies, are full DB copies inside the directory the
  reset already walks and matched none of the #5768 owned-name rules; they are
  now erased by the same helper.
- **Zeroize erases the CONFIGURED config root, not a hardcoded `/etc/xpf`
  (#5280).** `runZeroize` resolves the config root from
  `configstore.Store.ConfigPath()` — the daemon's `-config` path, the SAME
  file the store loads from and persists the `.configdb` SSOT / rollback
  slots / `.config.journal` to — and threads `filepath.Dir/Base` of it into
  the `performZeroizeWipe(configDir, configBase)` primitive. A daemon
  started with a non-default `-config` (e.g. `/srv/xpf/site.conf`) therefore
  erases `/srv/xpf`, not `/etc/xpf`; the pre-fix wipe hardcoded `/etc/xpf`
  and left the real root's secrets on disk while reporting a clean reset.
  Resolution runs BEFORE the apply gate and is fail-CLOSED: if the store /
  config path is undeterminable, `runZeroize` returns an error (surfaced as
  `Internal`) rather than wiping the wrong path or nothing — it never
  enters the terminal reset generation on an unknown root. Only the
  config-root leg is parameterized; the rendered-config (frr/swanctl/kea),
  login-account, config-archive, BPF-pin and networkd legs live at fixed
  system paths independent of `-config`. `defaultConfigDir` /
  `defaultConfigBase` remain only as the documented standard-appliance
  default and the RED-on-revert reference, not as the wipe target.
- Tab completion (`Complete` RPC) and `?` help come from `pkg/cmdtree` —
  add commands there once and they show up in every CLI surface.
- Session show and clear share ONE matcher: `ClearSessions` builds the
  same `sessionFilter` (`buildSessionFilter` + `matchV4/matchV6`) the
  `GetSessions` path uses (#1827 PR-3). Do not add a filter dimension
  to one path only — and remember key ports are network byte order
  (`ntohs` before comparing) and unresolvable zone/pool names must
  fail the RPC, not silently widen/void the clear. The
  `source-nat-pool` filter matches the TRANSLATED source
  (`SessFlagSNAT` + `NATSrcIP` in the pool's address set via
  `config.SourceNATPoolNets`).
- `GetSessionsResponse.total` is the EXACT count of filter-matching
  (forward-only) sessions — never the old `-1` sentinel (#5034 /
  C175-HC-073). `setSessionsTotal` uses the lightweight `SessionCount()`
  when unfiltered and a count-only scan (`IterateSessions`/`…V6` +
  `matchV4`/`matchV6`, no enrichment/allocation) when filtered, matching the
  legacy path's `idx` total. Both `matchV4`/`matchV6` and `SessionCount`
  skip reverse entries, so `total` counts unique forward sessions, not raw
  map entries. It is the whole-table total, independent of the returned
  page's size (`len(sessions)` undercounts once a page/limit caps the
  result), so a consumer — including a cluster peer's session detail —
  renders a meaningful "Total sessions". A count-scan iterator error fails
  the RPC (`Internal`) rather than reporting a partial under-count (#2469).
- `MatchPolicies` is a THIN adapter over the single shared policy simulator
  `pkg/policymatch` (#3042) — the same matcher the REST `/security/match`
  handler and the CLI `show security match-policies` / `test policy` commands
  use. It validates inputs, then delegates to `policymatch.Match`, which
  replicates the runtime evaluator (zone-pair → global → configured
  `default-policy`, predefined apps, multi-level application-sets, literal
  CIDRs, `any-ipv4`/`any-ipv6`, source/destination exclusion, and the live
  feed overlay via `FeedOverlayFn`). The pre-#3042 hand-written matcher
  scanned only zone-pair policies and hard-coded `deny (default)`, so the
  diagnostic could report the OPPOSITE of what the dataplane enforces. The
  request gained a `source_port` field so source-port-constrained app terms
  are simulated. #3104: `MatchPolicies` and the `test policy` ShowText surface
  thread live per-scheduler active-state (`s.policyInactiveFn()` →
  `policymatch.Query.PolicyInactiveFn`, sourced from the same
  `Manager.PolicySchedulerActiveState` the #3062 policy-detail display uses) so
  a scheduler-inactive policy is skipped like the runtime. #3414: `policyInactiveFn()`
  is now ALWAYS non-nil — with no live state (no provider / early boot) it binds
  a nil state map, which fails closed so scheduled policies are simulated as
  INACTIVE (matching the dataplane's nil-state => dropped) rather than certified
  as-if-active.
- #3375: the response `action` is rendered through the shared SSOT
  `policymatch.Result.DisplayAction()` for EVERY verdict, so the gRPC and REST
  surfaces can never diverge. Before #3375 gRPC returned a BLANK `action` for
  two security-sensitive verdicts where REST returned an explicit string: a
  `to-zone junos-host` query that matched no host-bound policy (now
  `policymatch.HostInboundActionString` — `host-inbound (local delivery subject
  to host-inbound-traffic service admission — a zone with no
  host-inbound-traffic stanza denies by default; transit/global/default policy
  NOT applied)`, with `host_inbound_unmatched` set; the pre-#3627 wording said
  `local delivery proceeds`, which read as an admit even for a no-stanza
  default-deny zone, #3405), and the no-active-config case (now `deny (default)` instead of an empty
  response). The response also gained a typed `default_used` bit — the
  machine-readable form of the ` (default)` suffix on `action`, set when no
  policy matched and `action` is the configured default-policy (including the
  no-config fail-closed deny), and false for a concrete match and for
  `host_inbound_unmatched` (which has no default-policy fallback). The REST
  `MatchPoliciesResult` carries the same `default_used` JSON field. The CLI
  `show security match-policies` renders its own multi-line, self-describing
  host-inbound block, so it never showed a blank verdict and is unchanged.
- #3627 M06: the response echoes the queried zone pair on
  `queried_from_zone`/`queried_to_zone` (proto fields 13/14) for EVERY answer —
  positive match, no-match/default, and host-inbound. Before #3627 the queried
  zones surfaced only indirectly via the #3331 `from_zone`/`to_zone`, which are
  the matched policy's declared SCOPE and are set ONLY on a positive match; a
  negative/default or host-inbound answer omitted them entirely, so a stored
  diagnostic could not prove which zone pair was tested without a copy of the
  request. The queried echo is the query context, DISTINCT from the matched
  scope (for a wildcard-zone or global match the two can differ). The REST
  `MatchPoliciesResult` carries the same `queried_from_zone`/`queried_to_zone`
  JSON fields.
- #3668: on a MATCH the response also carries `source_address_excluded` /
  `destination_address_excluded` (proto fields 15/16) and the stable `rule_id`
  (proto field 17), mirroring the inventory `PolicyRule` (fields 13/14/18). The
  exclusion flags report whether the matched policy carries Junos
  `source-address-excluded` / `destination-address-excluded` — the rule matches
  every address EXCEPT those in `src_addresses`/`dst_addresses`. The shared
  matcher (`matchAddr`) already inverts the address test correctly for the
  excluded side; the flag is what stops a positive verdict from reading
  BACKWARDS (before #3668 a hit against a source OUTSIDE an excluded set printed
  the excluded list as if it caused the match — unsafe for a Junos-style
  negated-address audit). `rule_id` is the stable `<from>-><to>/<name>` identity
  the inventory `GetPolicies`, the snapshot, and the event path share
  (`dpuserspace.StablePolicyRuleID`); a matched GLOBAL policy uses
  `junos-global->junos-global/<name>` exactly like the inventory global rows, so
  a simulator hit joins to the inventory / logs / tests even after a policy
  reorder shifts the numeric `policy_id`. All three are additive, set only on a
  positive match. The REST `MatchPoliciesResult` carries the same
  `source_address_excluded`/`destination_address_excluded`/`rule_id` JSON
  fields, and both CLI renderers annotate the exclusion as
  `Source addresses (except): ...` plus a `Rule ID:` line.
- #3685 M05/M06: on a MATCH the response also carries the policy `description`
  (proto field 18) and the scheduler binding `scheduler_name` (field 19) /
  effective-active flag `scheduler_active` (field 20). `description` (M05) is the
  matched policy's `description` text, the same field the inventory
  (`GetPolicies`) and the local `show security match-policies` result carry over
  the SAME `policymatch.Result`; a match verdict without it was weaker than the
  inventory / CLI answer (descriptions often hold ticket / change-control
  context). `scheduler_name` (M06) mirrors the inventory `PolicyRule` scheduler
  binding (#3624); `scheduler_active` is the explicit effective-active flag. A
  positive match is by construction currently active — `s.policyInactiveFn()` is
  fail-closed (#3414) and SKIPS a scheduler-inactive rule before it can match —
  so a matched scheduled policy always reports `scheduler_active=true`; it names
  the gate admitting the rule right now. All three are additive, set only on a
  positive match, and both scheduler fields are omitted for a non-scheduled
  policy. The REST `MatchPoliciesResult` carries the same
  `description`/`scheduler_name`/`scheduler_active` JSON fields.
- #3627 B1a: a `to-zone junos-host` query also carries the structured
  `host_inbound` message (proto field 21, `HostInboundAdmission`) — WHICH
  host-inbound-traffic system-service / protocol token admits the host-bound
  tuple, or that the box denies / globally accepts / cannot classify it. It is
  populated from the shared `policymatch.Result.HostInbound`
  (`dataplane/userspace.HostInboundAdmission`), the SAME classifier the local
  CLI `show security match-policies` host-inbound line renders (the merged
  #4352) and the REST `host_inbound` JSON object carries, so the three surfaces
  cannot drift (#3375). Fields: `status`
  (`HOST_INBOUND_ADMISSION_STATUS_{TOKEN_ADMIT,GLOBAL_ACCEPT,DENIED,INDETERMINATE}`;
  the `NOT_COMPUTED` zero value is rendered as an omitted message), `token` and
  `kind` (`system-services` / `protocols`, set only for `TOKEN_ADMIT`), and
  `description` (the one-line CLI explanation so a client renders the same
  sentence without re-deriving it). `hostInboundStatusToProto` maps the Go
  classifier enum to the proto enum explicitly, so a future reordering of either
  fails to compile rather than mislabel a verdict. The classifier reads the same
  structured token->tuple SSOT the kernel-nft builder renders from
  (`config.HostInboundServiceMatch` / `HostInboundProtocolMatch`), so a reported
  token can never claim a port the box does not open. Present ONLY for a
  host-bound query — on both the `host_inbound_unmatched` verdict and a matched
  `to-zone junos-host` policy (the host-inbound gate is a separate admission
  stage); OMITTED for every transit / global / default / content-rejected
  verdict. It is additional context and never changes `matched` /
  `host_inbound_unmatched`.
- #3685 M04: the gRPC-text `test policy` renderer (`server_show_firewall.go`,
  the remote `cli` backend) prints the policy ID, the global match scope, and
  the description for a GLOBAL match, mirroring `show security match-policies`.
  Before #3685 the global branch printed only `Policy:`/`Action:`, dropping the
  ID (session-table / audit join key when a global name collides with a
  zone-pair name), the scope, and the description — the gRPC-text sibling of the
  local request-path gap tracked in #3674 (`pkg/cli/cli_request.go`, a distinct
  renderer). The zone-pair branch already printed the from/to zones.
- The `test policy` operational command (local `pkg/cli` + remote `cmd/cli`
  → ShowText `test-policy:` topic → `showTestPolicy`) carries the same
  source-port input (#3107). The topic adds a `srcport=` key alongside the
  existing `port=` (destination) key; `showTestPolicy` parses it via the
  shared `policymatch.ParsePort` (so empty = unspecified / match any source
  port, and a malformed/out-of-range value reports `invalid source-port`
  instead of silently coercing to the 0 wildcard, the #3116 contract) and
  threads it into `policymatch.Query.SrcPort`. Without it a
  source-port-constrained application was overmatched: the CLI could report a
  PERMIT a real packet from another source port would never receive.
- Server-streaming RPCs (Ping, Traceroute, MonitorPacketDrop,
  MonitorInterface) must drain on client disconnect; cancel the context
  to free buffered output.
- **MonitorInterface re-reads the config every tick for DISPLAY NAMES (#9144).**
  `MonitorInterface` took `cfg := s.store.ActiveConfig()` once at stream open and
  its 1s loop used that snapshot for the life of the stream. The interface SET and
  the COUNTERS were never stale — `monitoriface.TrafficSummaryInterfaces` calls
  `ListTrafficInterfaces()` first, a fresh netlink walk every tick, and reads
  counters by live kernel name. What was stale is the config-derived DISPLAY NAME:
  `applyConfiguredSummaryChoices` maps configured names onto live kernel devices,
  so a commit that re-points an alias (a device-map edit, a RETH member change)
  left live counters rendered under a name that now belongs to something else — a
  wrong label on real data, which is worse than a missing row because nothing
  about it looks wrong. Measured through the real store and a real commit:
  kernel `lo` stayed labelled `reth0` after the config had renamed the alias to
  `reth9`. The per-tick derivation now lives in `monitorSummaryInterfaces`, which
  re-reads the active config on every call and degrades to the opening frame only
  when the re-read returns nil — a monitor stream that dies on a config blip is a
  worse failure than one stale label.

  **This is NOT the #9051 shape and its remedy does not transplant.** #9051 fixed
  a long-lived stream holding open-time state by re-checking at the INTERCEPTOR
  rather than in each handler's loop, because loops cover the streams that exist
  and silently omit the next one. That works there because the property is
  UNIFORM — "is this principal still authorized for this method?" comes from the
  peer identity and the method name, both of which the interceptor holds — and the
  enforcement action is uniform: cancel the stream. A config snapshot is the
  opposite on both counts: the derivation is handler-SPECIFIC (this handler alone
  derives a kernel-name resolver, a RETH predicate, an RG lookup and a
  display-name mapping from `cfg`, and an interceptor cannot re-derive closures
  inside a handler body), and there is no uniform enforcement action — cancelling
  an operator's `monitor interface` because someone committed is plainly wrong. The
  "omits the next one" concern is answered by SCOPE instead: `MonitorInterface` is
  the only stream that renders live data under a config-derived label pinned at
  open. `MonitorPacketDrop` also reads the config at open, but only to validate the
  request's zone/interface filters and resolve the requested alias set — pinning
  the interpretation of what the operator asked for is correct there, and it
  renders no config-derived label.

  **Deliberately NOT refreshed**, so the fix does not half-land: `singleKernelName`
  (single-interface mode) stays resolved at open, because the rate columns are
  deltas against baselines held for a SPECIFIC kernel device and re-resolving
  mid-stream would swap the device under those baselines and render garbage rates
  — replacing a wrong label with wrong numbers; and `isRethName` / `rethRG`, which
  feed the serve-local vs proxy-to-peer dispatch settled once before the loop.
  Guards: `monitor_cfg_refresh_9144_test.go`, including a cell that drives the real
  handler across a real mid-stream commit and asserts the RENDERED FRAMES change
  (the direct-call cells all stay green if the loop stops calling the helper), and
  a control asserting the fixture's alias actually reaches the display-name
  mapping — without it the whole file would pass on a config the summary path never
  consults.
- **MonitorInterface peer proxy — one-hop bound (#5497).** For a RETH (or
  a peer-owned physical member) `MonitorInterface` may forward the stream
  to the cluster peer (`proxyMonitorInterface` → `dialPeer`). Two invariants
  keep this to a single hop, so one management stream stays O(1) in
  server/client resources: (1) it proxies a locally-present RETH ONLY when
  the peer ACTUALLY owns the RG — `!IsLocalPrimary(rg) && IsPeerPrimary(rg)`
  (`decideMonitorProxy`), never merely because the local node is not primary;
  during both-secondary / election / sync-hold / disabled / peer-lost NEITHER
  node is primary, so it serves locally instead. (2) The proxy stamps the
  `xpf-no-peer` hop marker on the outgoing context (the chassis-forwarding
  convention); a request arriving WITH that marker is served locally / reported
  not-found and NEVER re-proxied. Before #5497 the trigger was `!IsLocalPrimary`
  alone with no marker, so two non-primary nodes proxied to each other in an
  A→B→A loop that stormed connections/streams/goroutines. `IsPeerPrimary` lives
  on `cluster.Manager` (reads the heartbeat-advertised peer RG state; false when
  the peer is not alive). The marker only ever SUPPRESSES a second hop, so it
  cannot be spoofed to reach data a client could not otherwise reach.
- **Bounded shutdown (#4910).** Both listeners stop through
  `stopGRPCServer` (`server.go`): `GracefulStop` runs in a goroutine and,
  if active RPCs have not finished within `grpcStopTimeout`, `Stop()`
  force-closes the connections. This is required because `MonitorInterface`
  streams forever off only its client `stream.Context()` — a client
  holding that stream open during shutdown would otherwise block
  `GracefulStop`, and therefore `Run` / `RunFabricListener`, indefinitely
  (a stuck daemon stop / failover / restart). `Run`'s serve+shutdown loop
  is factored into `serveUntilDone(ctx, srv, lis)` so the bounded-stop path
  is exercisable over an in-memory listener. A normal, RPC-idle shutdown
  (or one where every client has disconnected) returns as soon as
  `GracefulStop` completes — the timeout is only a backstop.
- Request-path external commands (ps, df, ss, journalctl, chronyc,
  ntpq, timedatectl, tail, ip neigh flush, systemctl power actions)
  must go through the bounded helpers in `exec_timeout.go` (#1805):
  `outputTimeout` / `combinedOutputTimeout` / `runTimeout` (15s timeout
  + 5s WaitDelay, and — for the first two as of #6552 — a slot from the
  shared diagnostic semaphore; mirroring the apply-path contract in
  `pkg/daemon/exec_timeout.go`, #1794 — not importable here because
  pkg/daemon imports this package). Do not add raw `exec.Command` calls
  in handlers: a wedged binary pins the handler goroutine and its gRPC
  stream. Power actions take `context.Background()` (client disconnect
  must not cancel a confirmed reboot); everything else derives from the
  request ctx. Request-controlled `tail -n N` is additionally clamped
  via `clampTailLines` — a time bound alone does not cap response bytes.
  The streaming Ping/Traceroute diags size their budget from the request
  instead of the 15s constant (#1819): `pingExecTimeout` (count × 1s +
  15s slack, 30s floor) and `diagTracerouteTimeout` (60s, aligned with
  the HTTP path), both capped at the 150s `diagExecCeiling`; the same
  formulas live in `pkg/api/exec_timeout.go` for the REST siblings, and
  `streamDiagCmd` kills the child promptly when a stream send fails.
  `streamDiagCmd` must also reap the child on the scanner-error path
  (#5060): a combined-output line larger than the scanner token cap
  yields `bufio.ErrTooLong`, and — exactly as on the send-failure path —
  the scan goroutine must `cancel()` + `pr.Close()` before the waiter
  returns, or exec.Cmd's internal copy goroutine stays wedged in
  `pw.Write` (WaitDelay closes only the exec-owned OS pipes, not this
  `io.Pipe`) and the RPC leaks past the deadline. The cleanup is a
  `defer` so it fires on every scanner exit; the per-line token is a
  deliberate `Scanner.Buffer` cap (`diagScanMaxToken`), and each
  operator-supplied field (target/source/routing-instance) is bounded at
  `maxDiagArgLen` at the RPC boundary so a multi-kilobyte argument is
  rejected with `InvalidArgument` before it can reach exec.
  The argv builders (`buildPingArgv`/`buildTracerouteArgv`) place the
  user-supplied target after a `--` end-of-options separator so a
  `-`-prefixed target is an operand, not a flag (option-confusion
  hardening, #2084).
  Per-job deadlines are necessary but NOT sufficient: without an
  aggregate bound a request flood holds hundreds of processes/FDs/
  goroutines/streams at once and starves the control plane. So Ping and
  Traceroute first take a slot from the process-wide
  `diagcmd.DefaultLimiter` (`MaxConcurrentDiagnostics = 4`) via the
  `diagLimiter` package var — SHARED with the REST ping/traceroute
  handlers, so one aggregate cap covers BOTH surfaces (#5057). Acquire is
  fail-fast: when the cap is reached the RPC returns
  `codes.ResourceExhausted` immediately (no queue, no wait) and the slot
  is released via `defer` on every path (success, exec error, ctx
  timeout/cancel). `streamDiagCmd` is called through the `streamDiag`
  package-var seam so a test can inject a fake slow diagnostic and assert
  the cap without real subprocesses.

  **That aggregate cap now covers the READ-ONLY diagnostic forks too
  (#6552), and the default is bounded.** Ping/Traceroute were the only
  sites acquiring it; `ShowText{log}` forked `journalctl` on nothing but
  a decodable request, `ShowText{log:<name>}` forked `tail`,
  `ShowText{ntp}` forked up to three of chronyc/ntpq/timedatectl, and
  `GetSystemInfo` forked ps/df/journalctl/ss — ten sites, no admission
  gate. A per-exec TIMEOUT bounds how long ONE fork lives; it does not
  bound how many run at once. `ShowText` is on
  `fabricAllowedUnaryMethods`, so it is not loopback-bounded either.

  The bound is placed so a future caller gets it by default:
  `outputTimeout` and `combinedOutputTimeout` — the plainly-named
  helpers — now `acquireDiagSlot()` before forking, and the unbounded
  forms carry `Unlimited` in the name. Errors go through
  `diagExecError`, which answers `ResourceExhausted` for a refused
  admission and `Internal` for anything the child actually did, so load
  shedding is never reported as a server fault. Acquire at the FORK, not
  at the handler: `GetSystemInfo{users}` forks nothing and must not be
  throttled by the diagnostic budget (a negative-control test pins that).

  Three uses stay UNBOUNDED, each named in
  `declaredUnboundedForks`: `runTimeout`'s deferred `systemctl`
  reboot/halt/poweroff and zeroize daemon-stop (a CONFIRMED power action
  must not be refused because the diagnostic budget is busy), the
  zeroize account teardown (`userdel` / `passwd -l root` — a
  half-zeroized box that left root unlocked is worse than a slow one),
  and the `ip -4/-6 neigh flush` pair (state-changing operator actions
  behind `PermControl`, not diagnostics).
  `TestNoUnboundedForkOutsideTheDeclaredExemptions6552` walks every
  non-test file in the package and fails BOTH on an undeclared
  unbounded fork and on a declared exemption whose site no longer
  exists, so the allowlist cannot rot into a record of things that used
  to be true.

  Both `grpc.NewServer` builders also set
  `grpc.MaxConcurrentStreams(maxConcurrentStreams)` = 256 (#6552).
  grpc-go's server default is UNLIMITED streams per connection, which is
  the multiplier that turns a per-request cost into an amplification;
  256 is far above real operator load (low tens, single-digit long-lived
  streams), so it is a runaway ceiling rather than a throttle.

  `MonitorInterface` draws its own 64-stream budget
  (`diagcmd.MonitorInterfaceLimiter`, `monitorInterfaceLimiter` alias, #9891)
  — sized to the sibling `EventBuffer` streaming cap, fail-fast with
  `ResourceExhausted` after validation but before the ticker and any peer
  dial, so a refused subscriber costs no goroutine, ticker, or connection
  and validation failures (`NotFound`) cost no slot. Each downstream frame
  carries a 30s handler-side send bound: a client that cannot accept one
  frame in 30s is severed with `DeadlineExceeded` (handler returns; the Send
  worker unblocks on the handler-return stream cancel and releases promptly,
  while trailers still queue behind pending DATA until the window opens or
  the connection closes). The timed-out slot TRANSFERS to the Send worker,
  which holds it until Send unblocks on that cancel — so the 64 bounds
  active handlers PLUS in-flight timeout workers (goroutine/slot lifetime),
  while retained H2 transport (queued DATA + trailers + stream state)
  outlives the slot until the client drains or disconnects, bounded
  per-connection by `MaxConcurrentStreams` (256) and the 64KB stream windows,
  not by the 64; timeout ownership is terminal (a timeout never returns
  success) so a continuing stream always holds admission. The proxy leg
  carries a 10s peer-idle bound per frame plus a separate 10s establishment
  bound on peer-stream creation (the peer ticks 1s by construction): a stalled
  peer severs with `Unavailable` and frees its slot instead of parking the
  proxy in `Recv` — or in `NewStream` waiting for quota — until the local
  client leaves, and the establishment timer stops on success so healthy
  monitoring is never lifetime-limited by it.

  Not an injection surface, stated because it reads like one: nine of
  the ten sites pass only compile-time string literals to
  `exec.CommandContext` (no shell). The tenth, `tail -n N <logPath>`, is
  request-derived on both arguments and constrained on both — `N` via
  `clampTailLines` to [1,10000] re-emitted with `strconv.Itoa` (so it
  can never become an option), and `logPath` via
  `config.SyslogLogFilePath`, which refuses any name that is not
  `filepath.Base(name)` and then requires it in the configured
  `system syslog file` allowlist.
- Policy text views (`server_show_policies_text.go`) must render BOTH
  zone-pair AND global policies (#3059). `showPoliciesHitCount` and
  `showPoliciesDetail` loop `cfg.Security.Policies` and then append a
  global section from `cfg.Security.GlobalPolicies` with from/to zone
  `"*"`. Global counter IDs CONTINUE from the zone-pair loop —
  `policySetID*dataplane.MaxRulesPerPolicy + i` where `policySetID ==
  len(cfg.Security.Policies)` after the zone-pair loop — so global hit
  counters stay aligned with the dataplane and match the gRPC detail
  view, CLI, Prometheus collector, REST inventory (#3045/#3050), and
  structured `GetPolicies`. A `from-zone`/`to-zone` filter selects
  zone-pair policies only, so the global section is suppressed when a
  filter is set. Omitting globals from any one surface is the #3059 /
  #3045 class of blind-spot bug. A scoped global (#3148 `match
  from-zone`/`to-zone`) carries its narrowing (#3286): the text
  `policies-hit-count` From/To columns and the `policies-detail` `Source
  zone:`/`Destination zone:` lines show the configured zone for a scoped
  global (group still `*`), and structured `GetPolicies` populates the
  per-rule `match_from_zone`/`match_to_zone` proto fields (empty for an
  unscoped global). Showing the group `*`/`*` but dropping the per-rule
  scope is the #3286 blind spot. #4344: `showPoliciesHitCount`,
  `showPoliciesDetail`, and structured `GetPolicies` read every per-rule
  counter (zone-pair, global, and the default-policy sentinel row) through
  the shared `dpuserspace.NewPolicyCounterReader` bulk snapshot — one brief
  dataplane lock for the whole set — instead of a per-policy
  `ReadPolicyCounters` loop; the reader falls back to the per-policy read
  for a dataplane without the bulk snapshot, so the rendered values are
  identical. A static canary in the test package forbids a direct per-rule
  `ReadPolicyCounters` call in these files.
  #7016: an UNPUBLISHED per-rule counter — the reader's
  `ErrPolicyCounterUnpublished`, meaning the helper has not published that
  stable rule id yet (the window before the first 1 Hz status poll lands, or
  config skew after a non-abort-class apply failure, #5679) — is NOT a read
  failure. `GetPolicies` used to answer it with `codes.Internal`, discarding
  the whole inventory for one unpublished rule; it now sets the additive
  per-rule `hit_counters_unavailable` (field 23) and succeeds, the same
  flag-the-item disposition `GetZones` already uses for
  `dataplane.ErrCounterNotPopulated`. The text renderers print `n/a` cells
  plus a trailing `note: N policy counter(s) not yet published by the
  dataplane` (detail prints `Session statistics: not available`) instead of
  `warning: policy counter read failed`. A GENUINE read failure keeps
  `codes.Internal` / the warning (#3408). See `pkg/api/README.md` for the
  cross-surface disposition table.
- `GetZones` enumerates security zones (`ZoneInfo`). The host-inbound
  admission set is surfaced distinctly (#3328): `host_inbound_configured`
  is the dataplane posture bit (mirrors `ZoneSnapshot.HostInboundConfigured`,
  #3070/#3362/#3405). Post-#3405 EVERY configured security zone is
  host-inbound ENFORCING (Junos default-deny parity), so this bit is `true`
  for every zone the RPC returns — it reports the dataplane truth, not
  config shape. A zone with NO `host-inbound-traffic` stanza default-DENIES
  host-bound traffic exactly like an explicit empty stanza; there is no
  admit-all posture for a configured zone. The admitted set lives in
  `host_inbound_system_services` / `host_inbound_protocols` (empty =
  deny-all; split so a service is distinguishable from a routing protocol);
  `interface_host_inbound` (repeated `InterfaceHostInbound`) carries
  per-interface overrides (#3362), the effective set being the union of
  the zone-level set and the override. The legacy `host_inbound_services`
  flattened list (services + protocols) is kept as a back-compat alias.
  The split projection is the SSOT-shared `ZoneConfig.SortedInterfaceHostInboundRefs`
  iteration the REST `GET /api/v1/security/zones` handler also uses. Before
  #3653 the bit was re-derived from config shape and reported `false` for a
  no-stanza zone — the pre-#3405 "false = admit-all" reading, the OPPOSITE
  of the runtime default-deny, so a controller read the management plane as
  open when it is fail-closed. (Global ICMP/ND/PMTUD accepts and lifeline
  interfaces fxp0/em0/fab* still bypass the per-zone host-inbound deny.)
  Before #3328 this RPC exposed only the flattened list and no `configured`
  flag at all.
- `GetScreen` enumerates the configured screen profiles. `ScreenInfo`
  carries `name`, the `checks` string list, and a `map<string,int64>
  thresholds`. The `checks` list and thresholds come from the shared
  `config.ScreenChecks` / `config.ScreenThresholds` helpers — the same
  single source of truth the REST `GET /api/v1/security/screen` handler
  uses (#3327). Before #3327 this RPC and the REST handler each carried a
  byte-identical copy of the helper that omitted `port-scan`, `ip-sweep`,
  `limit-session-source`, `limit-session-destination`, and
  `icmp-fragment` (all enforced by `pkg/dataplane/userspace/screens.go`)
  and exposed no thresholds — under-reporting active enforcement to a
  structured-state consumer. The `checks` set is kept a superset of the
  dataplane-enforced set; the duplicated-helper drift mechanism is gone.
- `GetEvents` returns recent security events (`EventEntry`) from the
  `pkg/logging` ring buffer. As of #3337 the entry carries the full RT_FLOW
  forensic record so a SIEM can reproduce the CLI close line: beyond the
  5-tuple / zones / policy ID it maps the resolved zone names, policy name,
  application name, ingress interface, close reason, the reverse counters,
  and the additive forensic block — `nat_src_addr`, `nat_dst_addr`,
  `session_id`, `elapsed_time`, `created` (+`created_nanos`),
  `egress_ifindex`, `ingress_ifindex`, `tos`, `tcp_control_bits`, and
  `reason` (proto field numbers 21-31, additive — no renumber). Before
  #3337 the proto stopped at `close_reason` (field 20) and dropped the NAT
  tuples, session ID, timing, ifIndexes, and CoS bits the `EventRecord`
  already held, and REST/SSE dropped even the policy/app/zone-name/reverse
  fields gRPC exposed. The `time` field now formats `RFC3339Nano`
  (sub-second) so high-rate events keep ordering; the REST/SSE surfaces
  mirror the same fields via the shared `eventEntryFromRecord` mapper. The
  zone filter (`zone` + `has_zone`) and out-of-range rejection are unchanged
  (#3334/#3338).
- Request-supplied numeric fields are signed on the wire and must be
  range-checked before they index/slice/size anything (#2282). `Complete`
  rejects a negative `pos` with `InvalidArgument` before slicing
  `line[:pos]` — without the guard `int(-1) < len(line)` passed and
  `line[:-1]` panicked the handler goroutine (`pos > len` is already safe
  because the slice is then skipped). `GetNATPoolStats` computes the
  port-pool size `(portHigh-portLow+1) * len(addresses)` in int64 and
  saturates to int32 via `clampInt32` before assigning the int32 proto
  fields — a bare cast wrapped negative for a large pool (~40k addresses
  over the default 64512-port window) and corrupted the
  `avail = total - used` display.
- Request-supplied tokens that are interpolated into an operational
  shell-out must be validated at the boundary (#4588). `GetBGPStatus`
  (`server_routing.go`) parses a neighbor IP out of `req.Type`
  (`received-routes:<ip>` / `advertised-routes:<ip>` / `neighbor:<ip>`) and
  hands it to the `pkg/frr` `GetBGPNeighbor*` wrappers, which concatenate it
  into a `vtysh -c "show bgp neighbor <ip> …"` command. Because the local
  gRPC listener is UNAUTHENTICATED, the handler rejects a non-parseable IP
  with `codes.InvalidArgument` (`net.ParseIP`) before it reaches vtysh — a
  newline-bearing token would otherwise become a second raw FRR CLI command
  (`vtysh -c` splits on newlines) with no commit-audit trail. `req.Type ==
  "neighbor"` and `neighbor:` with an empty ip stay legal (they select every
  neighbor). The `pkg/frr` wrappers re-validate as the load-bearing belt;
  see `pkg/frr/README.md` "#4588".
