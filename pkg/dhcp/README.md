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
  domain-search list, or delegated prefixes; not on a content-identical
  renewal (#1777, #15693).
  The `onGatewayChange` callback (#1844, nil-able) fires —
  undebounced, always outside `m.mu` — on gateway-relevant lease
  state changes only: first lease committed, gateway delta on a
  commit (strictly narrower than `onAddressChange`), or lease-record removal
  in `finishClient`, `abandonLeaseAfterNAK`, or `abandonLeaseAfterExpiry`.
  This hook is an immutable constructor argument, never a setter — client
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
- `Renew(ifaceName string) error` — `dhcp.go`. Takes the LEASE KEY
  (`config.DHCPLeaseIfName`), not an operator spelling: the operator
  surfaces resolve `ge-0/0/0` / `ge-0/0/3.7` / Linux forms through
  `Config.ResolveDHCPRenewTarget` first (#15227 A43-04), so a raw Junos
  target reaching Renew directly still honestly reports no client.
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
  cleans residual lease/address state) in a defer on every exit path,
  so a dead client can never permanently block a future `Start` for
  the same key.
- **Terminal-acquisition self-recovery (#15070)**: neither initial-
  acquisition failure is terminal any more. DHCPv6 exhausting its 30 s
  link-local wait re-waits after a ctx-bound `terminalRetryBackoff`
  (30 s, via the `after` seam) instead of returning; DHCPv4 exhausting
  `retransmission-attempt` paces the same backoff, resets
  attempt/backoff, and re-enters INIT — the attempt budget still bounds
  one INIT cycle's DISCOVER burst. A held lease's expiry still bounds
  the v4 recovery wait. Cancellation (Reconcile removal / Renew /
  StopAll) terminates both promptly; no Reconcile is needed to recover
  a client whose WAN/link simply was not ready at first try.

## Renewal semantics (#1777, RFC wire renewal #2994)

> Wire behavior (#2994): T1/T2 now run the RFC-correct renewal exchange,
> not a full re-acquisition. At T1 the v4 client sends a unicast
> RENEWING `DHCPREQUEST` to the granting server (ciaddr = held address,
> no DISCOVER) and the v6 client sends a `RENEW` echoing the held IA_NA /
> IA_PD with the server's DUID; at T2 the v4 client broadcasts a
> REBINDING `DHCPREQUEST` and the v6 client multicasts a `REBIND` (no
> server DUID). A generic T2 timeout immediately starts a fresh acquisition
> (DISCOVER, SOLICIT, or stateless Information-Request). Stateful leases
> retain the current lease, address, and delegated prefixes until a new reply
> commits or the absolute `Obtained+LeaseTime` deadline arrives. If
> reacquisition is still failing at that deadline, the lease/address/PDs are
> removed, and gateway-change plus recompile notifications withdraw compiled
> state. Stateless DHCPv6 has no binding expiry: its synthetic `LeaseTime` is
> only the Information-Request refresh interval, and failed refreshes retain
> the installed options.
> This supersedes the pre-#2994 force-DORA /
> Rapid-Solicit-at-every-T1 behavior (the old #1832 review note), which
> broadcast a fresh server-selection every renewal and could move the lease
> to a different server, churn the address (and therefore interface-DDNS /
> FRR routes / ip-monitoring), and double the WAN DHCP traffic.

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
- **DHCPv6 acquisition validation (#10858)**: acquisition and stateless replies
  must match the client DUID and successful message status; IA_NA / IA_PD
  contents are accepted only for the requested IAID and successful IA status.
  A non-rapid-commit acquisition collects Advertises for one second and
  Requests the highest-Preference offer (Preference 255 is immediate), then
  accepts the Reply only from that selected server. Stateless Information
  Replies require a server DUID and cannot commit DNS on an error status.
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
- **Co-held IA_NA invalidation (#14998)**: when a RENEW/REBIND Reply carries
  an IA_NA whose IAADDR(s) are all valid-lifetime 0 together with a live
  IA_PD prefix, the explicit invalidation still fires
  `errV6AddrInvalidated` (the PD does not mask it) and the held WAN kernel
  address is removed before re-acquisition; `commitLease` also removes a
  held address when committing an address-less successor. T1/T2 waits are
  anchored to their absolute `Obtained`-derived instants, so a delegated-
  prefix expiry that interrupts the T1 or T2 wait resumes with the
  remaining time (`remainingTimer`) instead of restarting the full tier
  wait; past-expiry safety remains bounded by the lease deadline.
- **Address-less Renew/Rebind with live PD (#15071)**: when a Renew/Rebind
  Reply carries a live IA_PD but no usable IA_NA (IA_NA absent, or only
  refused IAADDRs), `parseV6ReplyChecked` carries the held IA_NA forward
  (`carryForwardV6IANA`: Address/LeaseTime/Obtained preserved) instead of
  committing an address-less lease that would stop echoing the binding,
  hide the address from `show dhcp`, and orphan it on stop. An IA_NA
  Status **NoBinding** instead returns `errV6NoBinding` (RFC 8415
  §18.2.4: send Request) and the run loop re-acquires without waiting
  for T2. Explicit valid-lifetime-0 still fires `errV6AddrInvalidated`.
  `applyAddress` installs the lease's remaining kernel lifetimes
  (`kernelAddrLifetimes` → `ValidLft`/`PreferedLft`, infinite →
  `0xffffffff`) so the kernel expires the address even if userspace
  removal is missed.
- **DHCPv6 default-router discovery (#10763, #11425)**: because DHCPv6
  carries no default-router option and managed interfaces disable kernel RA
  acceptance, the client sends Router Solicitations and reads answering RAs
  directly. Only link-local RA sources with a positive Router Lifetime are
  eligible; the highest RFC 4191 preference wins, and a router-flagged neighbor
  entry alone is not enough to install a default gateway. The client
  re-solicits independently of DHCP T1 (at most every 30 seconds and at
  gateway/RIO lifetime boundaries), retains a live gateway on RA silence,
  and withdraws it immediately on a matching Router-Lifetime-0 advertisement.
  For stateful DHCPv6, a learned gateway expires at the earlier of its RA
  lifetime and the DHCP lease deadline; stateless mode has no DHCP binding
  deadline.
  Route Information options are retained as IPv6 `ClasslessRoutes`; their
  per-route lifetime zero withdraws only the matching destination/next-hop,
  silence retains an unexpired route, and the shared classless broad/martian
  gates protect both FRR and management-VRF installation.

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
- **Renew replies are bound to the lease owner (#9944, #14600)**: the DHCPv4
  RENEWING matcher requires the request transaction ID, client hardware
  address/interface, and stored granting server-identifier; the DHCPv6
  RENEW matcher applies the same transaction/interface/client identity
  checks and requires the stored server DUID. In RENEWING/RENEW a reply
  from another server, including an ACK or NAK, is ignored rather than
  rewriting or revoking the lease. In REBINDING/REBIND any server may
  answer (RFC 2131 §4.3.2, RFC 8415 §18.2.5): the transaction/client
  checks and a present valid server identity are still required, and the
  answering server's identifier/DUID from an accepted extending reply is
  stored as the new granting binding for the next RENEW.
- **REBIND teardown content stays bound to the granting server (#14997)**:
  the DHCPv6 REBIND any-server arm accepts only extensions from a
  non-granting server. A Reply carrying teardown content — a non-Success
  status at message or requested-IA level, an IAADDR with
  valid-lifetime 0, or an IAPREFIX with valid-lifetime 0 — is rejected
  unless it comes from the granting server: RFC 8415 §18.2.5 lets any
  server answer a Rebind, but only about bindings it actually has, and
  §18.2.10/§21 forbid a different server's Reply from replacing the
  binding mid-renewal. Before this gate one spoofed REBIND Reply (the
  transaction ID and client DUID are learnable on-link) could clear the
  WAN lease and every IA_PD delegation via the pdRefused clear, the
  valid-lifetime-0 deconfigure, or the per-prefix withdrawal reconcile.
  DHCPv4 needs no twin: a partner NAK revoking the lease in REBINDING
  is the #14600-documented RFC 2131 §4.3.2 behaviour, and v4 has no
  delegated-prefix set to tear down.
- **Missing IA_PD is re-requested on RENEW/REBIND (#15069, A39-01)**: when
  `ia-pd` is configured but no delegation is currently held — the initial
  acquisition answered `NoPrefixAvail`, a renewal refused or withdrew it,
  or the #14598 per-prefix expiry pruned it — the RENEW/REBIND still
  carries an empty IA_PD (IAID `{0,0,0,1}`) with the acquisition
  prefix-length hint, so the server can grant a prefix on that cycle.
  Before this, the renew builder only echoed held PDs, so an IA_NA-only
  RENEW renewed the address forever and the missing delegation (and the
  LAN RA prefix/SLAAC it feeds) stayed absent until the IA_NA itself
  expired or an operator ran `request dhcp renew`. The matcher now also
  accepts that Reply: the requested empty IA_PD makes
  `v6HasSuccessfulRequestedIA` recognise a grant (and
  `v6ReplyTearsDownHeldBinding` treats a renewed `NoPrefixAvail` as
  teardown content, still bound to the granting server on REBIND per
  #14997). Committing needs no run-loop change — the existing
  reconcile/commit arms store a live prefix carried by a RENEW/REBIND
  reply as soon as it arrives.
- **NAK immediately revokes the lease (#9944, #3956, #14600)**: a NAK
  accepted under the rules above is an explicit lease revocation — from
  the granting server in RENEWING/RENEW, or from any server in
  REBINDING/REBIND. The client deconfigures and drops the lease record,
  then starts fresh acquisition from INIT; a timeout remains the separate
  path that waits for T2 or retains the address through re-acquisition.
- **Server identity changes are content changes (#9944)**:
  `leaseContentChanged` includes the v4 server-identifier and v6 server DUID,
  so a changed renewal binding is visible to downstream consumers instead
  of silently changing renewal state.
- `Manager.RenewalBindingStats()` exposes per-family counters for replies
  ignored after transaction/client validation because their server identity
  was missing or, in RENEWING/RENEW, did not match the committed granting
  lease, plus DHCPv6 REBIND Replies rejected for non-granting teardown
  content (#14997). Accepted REBINDING/REBIND replies from a new server
  that merely extend the binding do not count.
- **Address moves are re-acquisition-equivalent**: if a renewal returns
  a different address, the old one is removed and the new one applied
  via the same netlink mechanisms the fresh-acquisition path uses.
- **Content-unchanged renewals are normally silent (#1777)**: the callback
  re-enters the daemon's `applyConfig` (full recompile) and thus `Reconcile`;
  firing it on every T1 interval would recompile the dataplane periodically
  for nothing. When a caller registers the optional unchanged-lease hook, it
  fires only on such renewals and outside the manager lock; the daemon uses
  that exception solely while #11497 host-inbound gap debt is owed.
  `Reconcile` keys on config identity (never lease state), so the re-drive
  cannot restart clients in a loop — only recompile churn.
  An IA_PD reply with **no prefixes** (silence) retains previously delegated
  prefixes and does not count as a change (the #1844 anti-outage rule). A
  prefix returned with **valid-lifetime 0** is an RFC 8415 §12.1 *withdrawal*,
  not silence: `reconcileDelegatedPDs` removes it from the held set per-prefix
  (`(prior \ withdrawn) ∪ live`, never a blunt clear-all) so it is neither
  stored nor re-advertised, and fires the recompile so the RA sender drops it
  (#4874 B). See the zero-lifetime IA_PD note under Gotchas.
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
  stamped `RTPROT_STATIC`, and xpf's ECMP management statics stamped with
  protocol 0x58 (#12539), are authority; xpf-owned `RTPROT_DHCP` and
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
  `selectIANAAddress` (`dhcpv6.go`) chooses one — it skips any IAADDR whose
  valid-lifetime is 0 (an expired/declined address, RFC 8415 §12.1;
  ties into F-264), discards any IAADDR whose preferred-lifetime exceeds
  its valid-lifetime (RFC 8415 §21.6 MUST), and skips any IAADDR failing
  the IA_PD class/protected validation (#14185, #10856 parity): the
  global-unicast-only `DelegatedIPv6PrefixRefusalReason` on the `/128`
  plus no overlap with the protected configured-prefix set, so a rogue
  server cannot make the firewall bind `::1`, `fe80::1`, a ULA/doc
  address, or a configured LAN address on its WAN interface. Each refused
  IAADDR is skipped independently (usable sibling salvaged; refusal is
  never a withdrawal). It then prefers the longest preferred-lifetime,
  tie-broken by first-seen (option order). `lease.LeaseTime` is paired
  with the CHOSEN address's own valid-lifetime, never a stale value from
  a different IAADDR. This replaced a last-wins overwrite that installed
  whichever address enumerated last. Pinned by `dhcpv6_iana_test.go` and
  `dhcpv6_iana_validation_14185_test.go`.
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
- **DHCPv6 IA_PD preferred lifetime 0 is deprecated, not unset** (#14606,
  RFC 8415 §21.22, RFC 9096 L-15): `extractDelegatedPrefixes` stores the
  IAPREFIX preferred lifetime verbatim (only valid 0 withdraws), and
  `buildRAConfigs` stamps it as `RAPrefix.PreferredLife` with
  `PreferredLifeSet=true` — always, on the PD path. `pkg/ra` honors an
  explicitly-set preferred 0 on the wire instead of substituting the
  7-day default (which the pref≤valid clamp then turned into the full
  valid lifetime), so the ISP's graceful-renumbering signal reaches LAN
  hosts: addresses from the prefix are deprecated (RFC 4862 §5.5.4) but
  the prefix stays on-link/autonomous until its valid lifetime ends. An
  operator prefix with no `preferred-lifetime` leaf keeps the 7-day
  default. Pinned by `pkg/daemon/ra_pd_preferred_zero_14606_test.go` and
  `pkg/ra/sender_preferred_zero_14606_test.go`.
- **Decaying PD lifetimes do not churn the RA desired set** (#15057):
  `DelegatedPrefixesForRA` returns the GRANTED lifetimes with the
  original `Obtained` (it only prunes/skips expired entries);
  `buildRAConfigs` carries the absolute expiry
  (`RAPrefix.ValidExpiresAt`/`PreferredExpiresAt` = Obtained+granted)
  and `pkg/ra` `buildRA` computes the remaining lifetime at send time.
  The cluster `raDesiredHash` and `configEqual` therefore compare
  expiries, not a per-second decayed value, so the 2s reconcile applies
  once instead of hard-restarting the sender every pass. A renewal moves
  the expiry and does restart. Pinned by
  `pkg/daemon/ra_pd_expiry_15057_test.go` and
  `pkg/ra/sender_expiry_15057_test.go`.
- **PD-only NoPrefixAvail refusal clears the delegation; wire infinite lifetime is infinite** (#15224): on a PD-only client (`ia-pd` without `ia-na`), a RENEW/REBIND Reply whose IA_PD carries `NoPrefixAvail` and grants nothing usable returns the typed `errV6PDRefused` from `parseV6ReplyChecked` instead of the generic transient error; the run loop clears the stored delegation (`clearDelegatedPDs`, recompile armed) and re-acquires, so `DelegatedPrefixesForRA` stops advertising the refused prefix immediately rather than at its lifetime end. Silence (no IA_PD) keeps the generic keep-and-retry path. The mixed `ia-na`+`ia-pd` path is unchanged (the address makes parse succeed and the `pdRefused` commit arm clears). Separately, `infiniteLifetime` is the RFC 8415 wire value `time.Duration(math.MaxUint32) * time.Second`; the previous `1<<62` threshold sat above the decoded wire value, so infinite grants decayed and acquired a finite `ExpiresAt`. Pinned by `dhcp_cohort_15224_test.go`.
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
- **Classless routes from DHCPv4 and IPv6 RIO (#4118, #11425).** `leaseFromACKv4`
  parses option 121 (the standard `ClasslessStaticRoute` accessor) and falls
  back to the legacy Microsoft option 249 (raw `GenericOptionCode(249)`) using
  the `{mask-length, significant-prefix-octets, gateway}` encoding. Per RFC
  3442, option 121/249 **supersedes option 3**: when present, the client MUST
  ignore the option-3 Router default. The option's `0.0.0.0/0` supplies
  `lease.Gateway`; more-specific routes land on `lease.ClasslessRoutes`. IPv6
  Route Information options are recorded in that same route list with the
  advertising router as next hop and expire or withdraw independently by
  destination/next-hop. When option 121/249 is absent, DHCPv4 still falls back
  to option 3 as before. Both families use the same route installation paths:
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
  normal DHCP-default suppression behavior, as does an ordinary RA
  default-router gateway (it is not an RIO route). Explicit IPv6 RIO `::/0`
  and IPv4/IPv6 `/1` classless routes, plus non-forwardable destinations in
  either family (including IPv6 link-local and multicast prefixes), are
  refused by default. `XPF_DHCP_TRUST_CLASSLESS_OVERRIDE=1`
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
- **Lease retention and absolute expiry after T2 failure (#1844, #11382).**
  A generic T2 timeout immediately starts a fresh DORA/Solicit or stateless
  Information-Request while the old state stays active during reacquisition.
  For stateful leases, retention ends at the original absolute
  `Obtained+LeaseTime` deadline: if reacquisition is still failing then,
  `abandonLeaseAfterExpiry` removes the lease, v6 PDs, and address, fires
  `onGatewayChange`, and schedules `scheduleRecompile` to withdraw compiled
  routes. Stateless DHCPv6 has no binding expiry; its synthetic `LeaseTime`
  only determines refresh timing, and failed Information-Requests retain
  installed options.
  An explicit **DHCPNAK is honored** (#3956, #9944, #14600): an accepted
  NAK (granting server in RENEWING, any server in REBINDING) deconfigures
  immediately through `abandonLeaseAfterNAK` and returns the client to
  INIT; a non-granting-server NAK in RENEWING is ignored.
- **Coupling rule (#1844, extended #4874 A2 / #11382):** the T2-expiry path
  (`abandonLeaseAfterExpiry`), terminal exits (`finishClient`), and DHCPv4
  NAK (`abandonLeaseAfterNAK`) fire both `onGatewayChange` and
  `scheduleRecompile`. The gateway hook alone only marks the ip-monitoring
  overlay dirty; the base DHCP default/classless routes (from `Leases()`)
  and v6 RA prefix (from `DelegatedPrefixesForRA()`) are re-rendered ONLY by
  `applyConfig`, which the debounced recompile drives. Without it a terminal
  exit or expired lease can leave compiled state stale until an unrelated
  commit. The ctx.Done cancellation exits are re-rendered by their surrounding
  `applyConfig` (Reconcile) or following re-acquire (Renew), so the terminal
  cleanup recompile remains limited to a lease record that still existed.
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
- **Over-broad mask / martian yiaddr is refused (#14183, untrusted input).**
  Extending #4101: `leaseFromACKv4` also refuses a contiguous mask broader
  than `/8` (`/1`–`/7`) and a martian `yiaddr` in the non-forwardable ranges
  refused for classless destinations/gateways (`0/8`, `127/8`, `169.254/16`,
  `224/4`, `240/4`, including `255.255.255.255`). Otherwise `AddrReplace`
  would install a connected prefix covering up to half of IPv4 (or bind a
  loopback/multicast address) on the interface, letting a rogue server
  divert that space on-link. `/8` and narrower (including `/31`/`/32`) and
  private/documentation addresses remain valid. There is no
  classless-trust override for the leased address itself: it is the
  interface's own address, not an optional learned route.
- **Martian-covering supernet / protected overlap refused (#14728).**
  Extending #14183: the martian check runs on the masked installed
  prefix `PrefixFrom(addr, ones)`, not the `/32` yiaddr — a `/8`–`/15`
  prefix covering a martian range (e.g. `169.255.0.1/15` covering
  `169.254.0.0/16`) is refused. `leaseFromACKv4WithProtected` also
  refuses a connected prefix overlapping statically configured IPv4
  interface prefixes (`config.ConfiguredIPv4Prefixes`, installed via
  `Manager.SetProtectedIPv4Prefixes` on every daemon apply — the v4
  analogue of the #10856/#14185 v6 protected set). The free
  `leaseFromACKv4` keeps a nil protected set; `doDHCPv4` goes through
  the manager method so acquire/renew/rebind all re-validate. No
  trust-override for the leased address (same as #14183).
