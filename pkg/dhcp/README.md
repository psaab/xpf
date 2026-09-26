# pkg/dhcp

DHCPv4 and DHCPv6 clients. Acquires and renews leases on firewall
interfaces and (DHCPv6) delegated prefixes. Persists DUIDs across
restarts so the same client identifier returns to the same lease.
DUID files are DurableState (#1894): `fsatomic.WriteFileDurable`, so a
power cut cannot silently change the client identity across reboot.

## Entry points

- `Manager` — `dhcp.go`.
- `New(stateDir string, onAddressChange, onGatewayChange func()) (*Manager, error)`
  — `dhcp.go`. The `onAddressChange` callback fires (debounced 2 s)
  when any client's lease **content** changes — address, gateway, DNS,
  or delegated prefixes; not on a content-identical renewal (#1777).
  The `onGatewayChange` callback (#1844, nil-able) fires —
  undebounced, always outside `m.mu` — on gateway-relevant lease
  state changes only: first lease committed, gateway delta on a
  commit (strictly narrower than `onAddressChange`), or lease-record
  removal in `finishClient` (every terminal client exit). It is an
  immutable constructor argument, never a setter — client goroutines
  read it outside `m.mu`, so mutation on a live manager would be a
  data race. Consumer: the ip-monitoring engine's
  `NotifyNextHopChange` (interface-typed preferred-route next-hops).
- `Lease` — `dhcp.go`. Result of one DHCP negotiation.
- `DelegatedPrefix` — `dhcp.go`. From DHCPv6 PD.
- `ClientSpec` — `reconcile.go`. One desired client derived from
  config (interface, family, options). Config identity only — never
  lease/address state.
- `Reconcile(specs []ClientSpec)` — `reconcile.go`. Converge running
  clients with the desired set (#1793): start missing clients, stop
  removed ones, restart clients whose option identity changed. Called
  by the daemon on every config apply.
- `Start(ctx context.Context, ifaceName string, af AddressFamily)` —
  `dhcp.go`. Spawn a per-interface client goroutine.
- `Renew(ifaceName string) error` — `dhcp.go`.
- `StopAll()` — `dhcp.go`. Cancels every client; a cancelled client runs
  `finishClient` → `removeAddress`, so this DROPS the address. Never call it on
  the shutdown path — see `Quiesce`.
- `Quiesce()` / `Quiesced()` — `dhcp.go` (#6788). Stops the address-change
  notification path and latches, WITHOUT stopping clients or touching leases.
- `DelegatedPrefixes() []DelegatedPrefix` — `dhcp.go`.

## Reconcile lifecycle (#1793)

The daemon calls `reconcileDHCPClients` from `applyConfigLocked` on
every commit/apply, so enabling `family inet { dhcp; }` / `family inet6
{ dhcpv6; }` on a running daemon starts a client, and deleting the
stanza stops it — Junos apply-on-commit semantics, not boot-time-only.
The DHCP `Manager` is created lazily on first need; a startup config
without DHCP no longer disables DHCP for the daemon's lifetime.

- **Diff key is config identity**: (interface, family, client options
  including DHCPv6 `stateless` and DUID type), captured as a
  fingerprint when the client starts. An option change on the same
  (interface, family) stops the old client and starts a new one
  (options are read at goroutine start, so a restart is required).
- **Never keyed on lease state**: lease changes fire `onAddressChange`,
  which re-enters the daemon's `applyConfig` and thus `Reconcile`. If
  the diff observed lease/address state, every lease event would
  restart its client and loop forever. There is a regression test
  proving a lease change does not restart clients
  (`TestReconcileLeaseChangeDoesNotRestart`).
- **Stop semantics**: an explicit stop cancels the client's context,
  stops renewals, and removes the leased address from the interface.
  No protocol RELEASE is sent — matching interface-deconfiguration
  behavior elsewhere in the daemon.
- **Registry hygiene**: the run goroutine deregisters itself (and
  cleans residual lease/address state) in a defer on every exit path —
  cancellation, DHCPv4 max-retransmissions, DHCPv6 link-local abort —
  so a dead client can never permanently block a future `Start` for
  the same key.

## Renewal semantics (#1777, RFC wire renewal #2994)

> Wire behavior (#2994): T1/T2 now run the RFC-correct renewal exchange,
> not a full re-acquisition. At T1 the v4 client sends a unicast
> RENEWING `DHCPREQUEST` to the granting server (ciaddr = held address,
> no DISCOVER) and the v6 client sends a `RENEW` echoing the held IA_NA /
> IA_PD with the server's DUID; at T2 the v4 client broadcasts a
> REBINDING `DHCPREQUEST` and the v6 client multicasts a `REBIND` (no
> server DUID). Only lease expiry (both renew and rebind failed) falls
> back to a full DISCOVER / SOLICIT. This supersedes the pre-#2994
> force-DORA / Rapid-Solicit-at-every-T1 behavior (the old #1832 review
> note), which broadcast a fresh server-selection every renewal and
> could move the lease to a different server, churn the address (and
> therefore interface-DDNS / FRR routes / ip-monitoring), and double the
> WAN DHCP traffic.

Acquisition and renewal share one commit path, `commitLease`
(`commit.go`): remove the old address if the server moved us, apply the
new address, store the lease (and DHCPv6 delegated prefixes), and fire
the debounced `onAddressChange` callback when content changed.

- **Renewal timer contract (`renewalTimers`, RFC 2131 §4.4.5 / RFC 8415
  §18.2.4, #5795)**: T1 (renew) fires at **50%** of the lease and T2
  (rebind) at **87.5%** — `renewalTimers` returns `t1 = lease/2` and
  `t2Remaining = 3/8·lease` (the additional wait from T1 to T2). There is
  **no fixed floor**: the ratios are proportional to the lease, so for
  every positive lease `T1 (50%) < T2 (87.5%) < expiry`, down to the 1s
  minimum the wire can express (T1 500ms, T2 875ms). A fixed 30s T1 / 1s
  T2 floor previously pushed T1 past the RFC half-life for any lease under
  60s and scheduled the renew **at or after expiry** for a lease under 30s
  (the run loop kept forwarding on an expired binding, then churned into
  re-acquisition). A **non-positive** lease time is invalid (`ok=false`) —
  RFC 2131 lease 0 is not the infinite sentinel (that is `0xFFFFFFFF`,
  overflow-safe via divide-first, #4526); the run loop **fails closed**,
  abandoning the cycle and re-acquiring, paced by `reacquireBackstop` so a
  server that keeps granting a 0-second lease cannot become a tight
  DISCOVER/SOLICIT loop. v4 and v6 share this one definition.
- **DHCPv6 explicit valid-lifetime-0 invalidation (RFC 8415 §18.2.10.1,
  #5927)**: a Reply that carries an IA_NA whose IAADDR(s) are **all
  valid-lifetime 0** is the server's directive to STOP using the held
  address. `selectIANAAddress` skips 0-lifetime IAADDRs (#4383) and
  `parseV6Reply` reports this distinctly via the `errV6AddrInvalidated`
  sentinel (present-but-0), separate from the generic "no usable IA_NA /
  live IA_PD" error (an **absent / transient** reply). On the sentinel
  during RENEW/REBIND the run loop **deconfigures** the held address and
  re-acquires — the IA_NA analog of the IA_PD withdrawal reconcile — while
  a merely absent/transient reply **keeps** the address and retries
  (T1→T2→solicit, the #4874/#1844 anti-outage path). NOTE: the
  `LeaseTime == 0 → 3600s` default in `parseV6Reply` is NOT this path — it
  only applies to a degenerate no-IA config; the explicit-0 invalidation
  is handled before it.
- **DHCPv6 default-router discovery (#10763)**: because DHCPv6 carries no
  default-router option and managed interfaces disable kernel RA
  acceptance, the client sends Router Solicitations and reads the
  answering RAs directly. Only link-local RA sources with a positive
  Router Lifetime are eligible; among them the highest RFC 4191 router
  preference wins. A router-flagged neighbor entry alone is not enough to
  install a default gateway.

- **Successful T1 renew / T2 rebind is committed**, and the run loop
  returns to the T1 wait with timers recomputed from the renewed
  lease. Pre-#1777 the renewal result was dead-assigned and the loop
  re-entered a full DORA / Solicit, discarding the renewal (changed
  DNS, delegated prefixes) and doubling the DHCP traffic.
- **Wire renewal (#2994)**: the run loop drives an
  `acquire → renew → rebind → re-acquire` exchange-mode state machine
  (`dhcpExchangeMode` in `dhcp.go`; wire builders `buildV4RenewRequest`
  / `v4RenewDest` / `buildV6RenewMessage` in `renew.go`). The server
  identifier (v4 option 54) and server DUID (v6) are captured on the
  granting reply and stored on the (unexported) `Lease.serverID` /
  `Lease.v6ServerDUID` fields so a later RENEW can target the original
  server. DHCPv6 stateless mode has no binding, so every refresh stays
  an Information-Request regardless of mode.
- **Stable client DUID across acquisition and renewal (#5711)**: RFC
  8415 §11 requires the *client* DUID to be constant for the client's
  lifetime — the server binds the lease to it, so a RENEW/REBIND under a
  different DUID is a new client and the lease is not renewed. Both the
  acquisition modifiers (`buildDHCPv6Modifiers`) and the renew modifiers
  (`buildDHCPv6RenewModifiers`) now unconditionally attach the persistent
  `getDUID` client ID. Previously `buildDHCPv6Modifiers` returned no
  modifiers when the interface had no configured DHCPv6 options, so the
  bare-acquisition SOLICIT fell back to `dhcpv6.NewSolicit`'s default
  DUID-LLT (a `GetTime()` timestamp stamped at send) while the renew path
  presented the persistent DUID-LL — a DUID mismatch that churned the
  lease on every renewal.
- **Renew replies are bound to the lease owner (#9944)**: the DHCPv4
  RENEWING and REBINDING matchers require the request transaction ID, client
  hardware address/interface, and stored granting server-identifier. The
  DHCPv6 matchers apply the same transaction/interface/client identity
  checks and require the stored server DUID. Replies from another server,
  including ACKs and NAKs, are ignored rather than rewriting or revoking the
  lease.
- **NAK immediately revokes the lease (#9944, #3956)**: a NAK accepted from
  the granting server is an explicit lease revocation in either RENEWING or
  REBINDING. The client deconfigures and drops the lease record, then starts
  fresh acquisition from INIT; a timeout remains the separate path that
  waits for T2 or retains the address through re-acquisition.
- **Server identity changes are content changes (#9944)**:
  `leaseContentChanged` includes the v4 server-identifier and v6 server DUID,
  so a changed renewal binding is visible to downstream consumers instead
  of silently changing renewal state.
- `Manager.RenewalBindingStats()` exposes per-family counters for replies
  ignored after transaction/client validation because their server identity
  did not match the committed granting lease.
- **Address moves are re-acquisition-equivalent**: if a renewal returns
  a different address, the old one is removed and the new one applied
  via the same netlink mechanisms the fresh-acquisition path uses.
- **Content-unchanged renewals are silent**: the callback re-enters the
  daemon's `applyConfig` (full recompile) and thus `Reconcile`; firing
  it on every T1 interval would recompile the dataplane periodically
  for nothing. `Reconcile` keys on config identity (never lease state),
  so a fire is never a restart-loop hazard — only recompile churn.
  An IA_PD reply with **no prefixes** (silence) retains previously
  delegated prefixes and does not count as a change (the #1844
  anti-outage rule). A prefix returned with **valid-lifetime 0** is an
  RFC 8415 §12.1 *withdrawal*, not silence: `reconcileDelegatedPDs`
  removes it from the held set per-prefix (`(prior \ withdrawn) ∪ live`,
  never a blunt clear-all) so it is neither stored nor re-advertised, and
  fires the recompile so the RA sender drops it (#4874 B). See the
  zero-lifetime IA_PD note under Gotchas.
- The decision logic is concentrated in `commitLease` / `renewalTimers`
  / `leaseContentChanged` / `delegatedPrefixesChanged` and pinned by
  `commit_test.go`. The run-loop state machine itself (the
  acquire→renew→rebind→re-acquire transitions and lease preservation)
  is exercised through the `doV4ExchangeForTest` / `doV6ExchangeForTest`
  / `afterForTest` / `waitLinkLocalForTest` seams (#2994), which replace
  the real socket exchange and the RFC T1/T2 waits so a test drives the
  real `runDHCPv4` / `runDHCPv6` without traffic — see `renew_test.go`.
  The wire builders (`buildV4RenewRequest`, `v4RenewDest`,
  `buildV6RenewMessage`) are pure and unit-tested directly.

## Callers

`pkg/daemon` (lifecycle: `reconcileDHCPClients` in
`daemon_dhcp.go`, invoked from `applyConfigLocked` step 7b and once at
startup after dataplane load).

## Dependencies

External only: `github.com/insomniacslk/dhcp`, `github.com/vishvananda/netlink`.

## Gotchas

- Each DHCP client uses `context.Background()`, not the daemon context.
  On graceful SIGTERM the daemon exits without calling `StopAll()`,
  intentionally leaving the lease in place so the next daemon process
  reuses it (no DAD storm, no DHCP renew at startup). Only an explicit
  stop — `Reconcile` removal/option change, `Renew`, `StopAll` —
  cancels a client.
- The lease-change callback is debounced 2 seconds to avoid floods during
  config apply. **That 2s is long enough to outlive daemon shutdown's only
  apply drain (#6788):** the callback re-enters a full config apply, so a lease
  event arriving just before SIGTERM could land an apply on a daemon whose FRR,
  dataplane and VIPs were already torn down. `runShutdownSequence` therefore
  calls `Quiesce()` before that drain.

  `Quiesce` is deliberately NOT `StopAll`, and the bullet above is why:
  cancelling the clients would strip the DHCP address from every DHCP
  interface — including a DHCP-managed management NIC (`fxp0`) — during
  shutdown AND across the graceful restart the previous bullet's contract
  exists to protect. `Quiesce` leaves every lease, address and client goroutine
  exactly as they are and shuts off only the notification: it stops the armed
  debounce timer, latches so a lease event racing shutdown re-arms nothing, and
  JOINS a callback that had already started (a `time.Timer.Stop` cannot un-fire
  an already-elapsed timer, so the callback re-tests the latch under the mutex
  and takes the join WaitGroup there — registering at arm time would leave a
  stopped timer's `Add` unmatched and wedge `Quiesce` forever).
- DUID is cached per-interface in the state directory with type hints
  (`duid-ll`, `duid-llt`).
  - **A DUID-LLT that cannot be persisted is a hard error (#4909).** A
    DUID-LLT embeds a generation timestamp, so an unpersisted one is ephemeral
    — the next restart mints a different Time, the server sees a new client, and
    the old lease lingers. `getDUID` now surfaces the persist failure for
    `duid-llt` instead of silently handing out an unstable identity. A `duid-ll`
    is a pure function of the hardware address (byte-identical across restart),
    so its persist failure stays benign (logged, non-fatal).
  - **A DUID-type change AUTOMATICALLY ROTATES the identity (#5855).** Changing
    `duid-ll` <-> `duid-llt` restarts the DHCPv6 client (the type is part of the
    reconcile fingerprint), but the client identity is rotated too — no explicit
    `clear` is required (Option 1, operator-friendly). `getDUID` treats the
    configured type + resolved DUID as one lifecycle object: it reuses a cached
    or persisted DUID ONLY when its actual type (`actualDUIDType`) matches the
    requested mode, and on a mismatch atomically regenerates the requested type
    and durably persists it BEFORE the restarted client sends it (persist-before-
    start holds because `Reconcile` stops the old client, waits for it, then
    `Start` calls `getDUID` synchronously before the first Solicit). `Reconcile`
    also drops the cached DUID on a type change so the restarted client can never
    be handed the retired identity. **Persistence-failure fail-safe:** if the new
    -type DUID cannot be durably persisted, `getDUID` RETAINS the previous
    persisted identity and returns it (old type) — it exposes NO unpersisted new
    DUID (a partially-rotated DUID-LLT would be ephemeral and diverge from disk),
    and the client stays coherent on the old identity until a later reconcile
    persists the new one. `show`/API (`DUIDs()`) reports the ACTUAL active DUID
    type, never the configured-but-not-yet-rotated type.
  - **`ClearAllDUIDs` clears persisted DUIDs and surfaces errors (#4909).** It
    unions the in-memory cache with the `dhcpv6-duid-*` files on disk, so a DUID
    a client has not re-fetched since restart (on disk, absent from the cache)
    is still removed, and it returns an aggregated error rather than reporting
    "all cleared" while an I/O/permission failure stranded a file. The gRPC /
    REST / CLI clear-identifier handlers propagate that error.
- The DHCP client owns the address. `pkg/networkd` deliberately skips
  address reconciliation on DHCP-marked interfaces.
- DHCP-learned default routes go into FRR with admin distance 200 — lower
  priority than static routes, so a configured static default wins. DHCP-learned
  classless routes follow the same contract: FRR and the management-VRF twin
  suppress a learned prefix contained by a rendered/operator static route in
  the same table, with a visible warning. In table 999, only operator routes
  stamped `RTPROT_STATIC` are authority; xpf-owned `RTPROT_DHCP` and
  connected/kernel routes are silently ignored, while unexpected
  other-protocol routes are warned and ignored. An option-121 `/0` follows the
  normal DHCP-default suppression contract. Unusually broad classless `/1`
  prefixes and non-forwardable martian ranges (`0/8`, `127/8`, `169.254/16`,
  `224/4`, `240/4`) are refused by default. `XPF_DHCP_TRUST_CLASSLESS_OVERRIDE=1`
  is an explicit escape hatch for covered/broad/martian learned classless
  routes and emits a loud security warning.
- **DHCPv6 IA_NA holds one address, selected deterministically** (#4383):
  a reply may carry multiple IAADDR options within an IA_NA (and multiple
  IA_NA options), but xpf's `Lease` model installs a single `/128`.
  `selectIANAAddress` (`dhcp.go`) chooses one — it skips any IAADDR whose
  valid-lifetime is 0 (an expired/declined address, RFC 8415 §12.1;
  ties into F-264), then prefers the longest preferred-lifetime,
  tie-broken by first-seen (option order). `lease.LeaseTime` is paired
  with the CHOSEN address's own valid-lifetime, never a stale value from
  a different IAADDR. This replaced a last-wins overwrite that installed
  whichever address enumerated last. Pinned by `dhcpv6_iana_test.go`.
- **DHCPv6 zero-valid-lifetime IA_PD is a withdrawal, not a lease** (#4874
  B, RFC 8415 §12.1). Symmetric to the IA_NA skip above:
  `extractDelegatedPrefixes` partitions a reply's prefixes into *live*
  (valid-lifetime > 0) and *withdrawn* (valid-lifetime 0); the withdrawn
  ones are never stored or re-advertised. Before the fix a server that
  revoked an IA_PD by returning it with valid-lifetime 0 (while renewing
  the IA_NA) had the zeroed prefix stored, kept by
  `DelegatedPrefixesForRA`, and re-advertised at the RA sender's 30-day
  valid / 7-day preferred defaults. `reconcileDelegatedPDs` applies
  per-prefix withdrawal semantics — `(prior \ withdrawn) ∪ live`, an
  absent/empty IA_PD stays on the retain path (silence ≠ withdrawal), a
  co-held prefix the reply merely omitted is retained — and the run loop
  updates `committedPDs` to the reconciled set so the next RENEW does not
  echo the withdrawn prefix and invite a re-grant. On acquire, a reply
  that yields no IA_NA address and no *live* prefix (only withdrawn PDs)
  is an acquisition failure and is retried, never settled into an empty
  1h lease — counted regardless of `wantNA` so a PD-only client cannot
  fall through. Pinned by `dhcp_lease_expiry_4874_test.go`.
- **DHCPv6 IA_PD prefix-length is validated at the DECODER** (#6531). The
  wire prefix-length is a single byte, and insomniacslk/dhcp decodes it
  as `net.CIDRMask(int(length), 128)` — which returns a **nil** mask for
  any length > 128. `net.IPMask(nil).Size()` is `(0, 0)`, so
  `extractDelegatedPrefixes` reading only `ones` and discarding `bits`
  turned a crafted length of 129..255 into a `<ip>/0`. That `/0` survived
  `IsValid()` and `DeriveSubPrefix` and reached `pkg/ra`, which applies
  no sanity floor of its own and advertised `PrefixInformation{PrefixLength:
  0, OnLink, Autonomous}` to the downstream LAN — a hostile or buggy
  upstream WAN server hijacking every SLAAC host's on-link determination
  with one crafted option. The guard is `bits != 128 || ones == 0`
  (`bits` is the load-bearing arm: a nil mask and a non-contiguous mask
  both report `bits` 0; `ones == 0` is belt-and-braces for a genuine
  all-zero 128-bit mask that only an in-process constructor can build,
  since the decoder maps a wire length of 0 to a nil `Prefix`). The
  offending IAPREFIX is **skipped**, not the whole reply: an IA_PD is a
  multi-element container, matching the option-121 classless-route loop
  below (which likewise skips an entry whose mask reports `bits != 32`),
  whereas `leaseFromACKv4` refuses the entire v4 message only because an
  ACK carries exactly one address+mask and there is nothing to salvage.
  A skipped entry enters neither the live nor the withdrawn set, so a
  hostile server gains nothing by pairing a malformed prefix with a
  well-formed one. When the skip empties BOTH sets the outcome depends
  on what else the reply carried — neither branch yields a `/0`, but
  they are not the same branch. With no IA_NA address either, the "no
  usable IA_NA address or live IA_PD prefix" guard rejects the reply and
  the acquire/renew loop retries. With a valid IA_NA address the reply
  is still USABLE (that guard fires only when both are missing), so a
  mixed `ia-na` + `ia-pd` client installs the address and simply carries
  no new PD; the empty live+withdrawn pair then reads as SILENCE to
  `reconcileDelegatedPDs`, which returns `apply=false` so a previously
  held delegation is retained untouched (the #1844 anti-outage rule).
  A malformed IAPREFIX therefore cannot clear the held set either.
  `/128` is ACCEPTED (a legal single-address
  delegation — the bound is inclusive). Pinned by
  `dhcpv6_iapd_prefixlen_6531_test.go`, which drives hand-rolled option
  BYTES through `dhcpv6.MessageFromBytes`; the older IA_PD tests build
  `OptIAPrefix` structs directly and cannot reach this path, which is how
  the bug survived (`OptIAPrefix.ToBytes` derives the wire length from
  `Mask.Size()`, so the library's own marshaller cannot emit > 128
  either). The PD → RA chain downstream of the guard is covered in three
  segments meeting at typed seams, each test claiming only its own leg:
  `dhcpv6_iapd_prefixlen_6531_test.go` covers wire bytes → `[]DelegatedPrefix`
  → `DeriveSubPrefix`; `pkg/daemon/ra_pd_prefixlen_6531_test.go` calls the
  real `buildRAConfigs` to cover the stored PD → `config.RAPrefix` hop (and
  pins that `daemon_ra.go`'s `!subPrefix.IsValid()` check does NOT stop a
  `/0`); `pkg/ra/sender_prefixlen_6531_test.go` covers `config.RAPrefix` →
  `buildRA` → `ndp.MarshalMessage` and asserts on the RE-PARSED wire bytes,
  pinning the blast radius from the consumer side.

  **#6587 added the defense-in-depth layer #6531 deliberately deferred, and
  two commit-time range validators.** The decoder remains the primary
  guard; what changed is that `pkg/ra` can now apply a floor of its own
  without breaking legitimate configuration. #6531's reasoning for NOT
  filtering there was that at that point a delegated `/0` is
  "indistinguishable from an operator-authored
  `set interfaces <if> ipv6 router-advertisement prefix ::/0`" — so #6587
  supplied the missing PROVENANCE rather than a blanket floor.
  `config.RAPrefix.Delegated` is set only by `buildRAConfigs` on the PD
  path; the compiler leaves it false, so operator-authored prefixes are
  false BY CONSTRUCTION and no compiler change was needed. `buildRA` then
  refuses exactly `Delegated && Bits() == 0`. Because that flag decides
  whether the PIO is emitted at all it is wire-affecting, so it is also
  compared in `pkg/ra`'s `configEqual` change detector — the #4307 comment
  there records what omitting a wire-affecting field from that list cost
  last time.

  Separately, `preferred-prefix-length` and `sub-prefix-length` are now
  typed `ValidateInteger(0, 128)` leaves. Both were untyped placeholders
  parsed with an unbounded `strconv.Atoi` whose error is DISCARDED. The
  impact was NOT symmetric, contrary to the "fail-closed" framing:
  `sub-prefix-length` was incidentally fail-closed (an invalid
  `netip.Prefix` is caught by `daemon_ra.go`'s `IsValid()`), but
  `preferred-prefix-length` was not — `net.CIDRMask(999, 128)` returns
  nil and `OptIAPrefix.ToBytes` then writes length 0, so the IA_PD hint
  EGRESSES malformed to the upstream server. Either way the guard was
  incidental: it depended on a downstream check noticing rather than on
  the value being rejected where the operator typed it.
- **RFC 3442 classless static routes (option 121 / legacy 249, #4118).**
  `leaseFromACKv4` parses option 121 (the standard `ClasslessStaticRoute`
  accessor) and falls back to the legacy Microsoft option 249 (raw
  `GenericOptionCode(249)` decoded with the identical
  `{mask-length, significant-prefix-octets, gateway}` encoding). Per RFC
  3442 **precedence, option 121/249 SUPERSEDES option 3**: when it is
  present the client MUST ignore the option-3 Router default entirely.
  The `0.0.0.0/0` entry (if any) in the option supplies `lease.Gateway`
  (so every existing gateway consumer — FRR default route, neighbor
  resolution, ip-monitoring next-hop — is unchanged); every more-specific
  route lands on `lease.ClasslessRoutes`. When option 121/249 is absent
  the client falls back to option 3 exactly as before. The classless
  routes are programmed through the same paths as the default route:
  `collectDHCPRoutes` emits one `frr.DHCPRoute` per route (with a non-empty
  `Destination`), and `renderDHCPDefaults` writes
  `ip route <dest> <gw> [<iface>] 200`. Before emission, a connected prefix
  in the same FRR routing context suppresses an equal or more-specific
  learned prefix: otherwise its longer-prefix match could divert traffic from
  the connected network through the DHCP gateway (#10762). A rendered static
  route in the same FRR table also suppresses a learned classless prefix it
  contains, with a visible security warning; this containment rule is what
  makes a static `0.0.0.0/0` defeat a rogue `/1` pair while leaving
  non-overlapping learned routes usable. The management-VRF twin applies the
  same rule against `RTPROT_STATIC` routes in table 999 before `RouteReplace`;
  xpf-owned `RTPROT_DHCP` and connected/kernel routes are silently ignored,
  while unexpected other-protocol routes are warned and ignored rather than
  becoming static precedence authority. An option-121 `0.0.0.0/0` follows the
  normal DHCP-default suppression behavior. `/1` and non-forwardable martian
  classless prefixes are refused by default. `XPF_DHCP_TRUST_CLASSLESS_OVERRIDE=1`
  is an explicit, unset-by-default escape hatch that permits connected-covered,
  static-covered, broad, or martian classless routes and emits a loud security
  warning at each use.
  `leaseContentChanged` diffs `ClasslessRoutes`, so routes are withdrawn/re-installed in lock-step with
  the lease on renew/expiry, like the default route. For the management VRF
  the withdrawal is enforced by a full RECONCILE, not an append-only apply
  (#5108): every route xpf installs in table 999 is stamped `RTPROT_DHCP`,
  and each `applyMgmtVRFRoutes` run lists the xpf-owned routes already in the
  table and `RouteDel`s any whose destination is no longer in the current
  desired set — including the empty-desired case (management lease disabled,
  or option-121 route withdrawn), which the pre-#5108 early-return skipped,
  leaving a stale route that could blackhole management traffic to a prior
  DHCP router.
  The delete is scoped to `RTPROT_DHCP` so operator routes in the VRF are
  never touched.
- **Lease records are NOT expired by the wall clock.** During a
  *timeout-driven* failed re-acquisition (T2 rebind timed out, fresh
  DORA in progress) the lease record and the kernel address intentionally
  persist until replaced — consumers (FRR DHCP routes,
  ip-monitoring resolved next-hops) keep the last-known gateway. This
  deliberately diverges from RFC 2131 §4.4.5 for the *timeout* case (an
  expired lease should stop being used). An explicit **DHCPNAK is honored**
  (#3956, #9944): a granting-server NAK deconfigures immediately through
  `abandonLeaseAfterNAK`, schedules the coupled route recompile, and returns
  the client to INIT; a wrong-server NAK is ignored. A timeout is still the
  separate path that falls through to REBINDING and then fresh acquisition
  while retaining the old lease until replacement.
- **Coupling rule (#1844, extended #4874 A2):** any lease-record removal
  (the NAK path, the `finishClient` max-retransmission/terminal exit, and,
  if clock expiry is ever implemented, that path too) MUST route through a
  path that fires **both** `onGatewayChange` AND `scheduleRecompile`
  (`finishClient` and `abandonLeaseAfterNAK` both do).
  `onGatewayChange` alone only marks the ip-monitoring overlay dirty; the
  base DHCP default/classless routes (from `Leases()`) and the v6 RA prefix
  (from `DelegatedPrefixesForRA()`) are re-rendered ONLY by `applyConfig`,
  which the debounced `scheduleRecompile` drives — so without it a terminal
  exit removes the address but leaves the FRR route + RA prefix stale until
  an unrelated commit (indefinitely on the `finishClient` max-retransmission
  exit, which does not run from an `applyConfig`). The ctx.Done cancellation
  exits already delete the record inline and are re-rendered by their
  surrounding `applyConfig` (Reconcile) or the following re-acquire (Renew),
  so `finishClient` fires the recompile only when a lease record actually
  remained.
- **Degenerate subnet mask is refused (#4101, untrusted input).**
  `leaseFromACKv4` validates option 1 after `net.IPMask.Size()`: a zero
  mask (`0.0.0.0` → `Size()` returns `ones=0`) or a non-contiguous mask
  (`255.255.0.255` → `(0,0)`) is rejected with an error instead of
  producing a `YourIP/0` lease. Without the guard the kernel would install
  an on-link `0.0.0.0/0` connected route on the DHCP interface and
  blackhole/hijack all IPv4 forwarding — a rogue or broken server could
  force this with a single crafted ACK. The rejection propagates through
  `v4Exchange` → `runDHCPv4`, which retries a fresh DISCOVER on acquire (no
  address ever installed) or falls through to T2/expiry keeping the current
  valid lease on renew/rebind. A missing option 1 still falls back to `/24`;
  only a *present-but-degenerate* mask is refused. Valid prefixes including
  `/31` and `/32` (point-to-point / host leases) are accepted.
