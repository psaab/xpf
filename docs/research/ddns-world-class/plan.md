# DDNS: World-Class Redesign — Provider Abstraction + WAN/Interface-Address Publish + DHCP-Lease Publish (inadyn-inspired)

**Status: DRAFT v1 — research/design, not yet implemented.** Stops at
PLAN-READY. No production code, no code PR. Awaiting design review;
implement via `/engineer` per the phased plan in §9.

Branch: `research/ddns-world-class`. Doc:
`docs/research/ddns-world-class/plan.md`.

Subsumes / sequences open issues: **#2663, #2664, #2665, #2666, #2667,
#2676, #2679** (see §6). Reference material: inadyn source at
`/home/ps/git/inadyn` (read-only); RFCs 2136 / 3007 / 4701 / 4703 / 8945;
ISC Kea D2; dyndns2 de-facto protocol; Cloudflare / Route 53 DNS APIs.

---

## 1. Status line

DRAFT v1 — research/design, not yet implemented. This is a unifying
architecture proposal. It deliberately **extends** the shipped #1387
DHCP-lease DDNS path (live RFC 2136 backend, DHCID ownership store,
write-ahead durability, node-level HA gate) rather than rebuilding it,
and adds the missing surfaces (router/interface-address publish; provider
backends beyond RFC 2136; per-scope HA ownership; source binding;
independent v4/v6 policy).

---

## 2. Problem framing & goals

### 2.1 What "world-class DDNS" means for xpf

xpf is a Junos-style firewall whose DDNS today publishes **only DHCP-server
leases** over **only RFC 2136**, with **one global policy** and a
**node-level** HA writer gate. A world-class DDNS subsystem for an edge
firewall must cover two distinct *publish surfaces* over a *shared*
provider/transport/state spine:

- **Surface A — router/interface-address DDNS** ("publish the firewall's
  OWN address"): publish `wan0.example.net` / `fw-a.example.net` for the
  firewall's learned WAN address (DHCPv4/DHCPv6 client lease, static,
  IPv6 prefix-delegation churn, or an HA-owned virtual/reth address) to an
  external DNS provider. This is the classic "dyndns client on the CPE"
  use case (the inadyn/ddclient problem). **Entirely missing today
  (#2679).**

- **Surface B — DHCP-lease DDNS** ("publish leases the firewall hands
  out"): publish forward A/AAAA + reverse PTR for active Kea leases. This
  is the shipped #1387 path. It works but has gaps: single global policy,
  no per-interface / independent v4-v6 scope (#2663), node-level (not
  per-RG) HA gate that can double-write (#2664), no source binding
  (#2665), incomplete TSIG validation (#2666), a skip-existing PTR sentinel
  ordering orphan (#2676), and stale "deferred" docs (#2667).

"World-class" = the union of: (1) a provider-neutral backend abstraction
(RFC 2136/TSIG + HTTP providers: dyndns2, Cloudflare, Route 53, generic
templated, like inadyn's plugin model); (2) a robust IP-source/detection
layer (interface read, DHCP lease, checkip, static); (3) an update engine
with change-detection, decoupled forced-refresh interval, error backoff,
ban-avoidance, and a per-host last-published cache; (4) per-scope HA
owner-gating that is correct under partial RG failover; (5) independent
dual-stack (A vs AAAA) policy; (6) source/VRF binding; (7) safe credential
handling (no secrets in logs); (8) full operator surfaces (CLI / gRPC /
REST / Prometheus).

### 2.2 The gaps today (one-liners; details in §4)

- No router/interface-address publish at all (Surface A) — #2679.
- Surface B is single-global-policy; no per-interface / independent v4-v6
  — #2663.
- HA gate is node-level "master for any RG" → stale/double-write on
  partial failover — #2664.
- No source-address / SO_BINDTODEVICE / VRF binding on the UPDATE
  transport — #2665.
- Incomplete TSIG tuple validation (key-without-secret commits, fails at
  runtime) — #2666.
- skip-existing PTR-conflict-after-forward-success orphans the forward
  (sentinel ordering) — #2676.
- Only RFC 2136 backend; no HTTP/API providers (dyndns2/Cloudflare/Route
  53). Needed for Surface A on consumer/SaaS DNS.
- Stale "deferred / config-only" comments and docs — #2667.

### 2.3 Non-goals (full list in §10)

Not a recursive resolver, not authoritative DNS, not a generic DNS proxy
(xpf already has dns-proxy). Not Kea D2 (plan-killed: D2 is not in the
appliance image). Not split-horizon view selection beyond per-scope policy
binding.

---

## 3. inadyn design distilled

Source: `/home/ps/git/inadyn`. Identifiers are exact. The ideas worth
adopting (and the one to avoid):

### 3.1 The plugin/provider abstraction

A provider is a static `ddns_system_t` (`include/plugin.h:45-62`) with
three function pointers as the *entire* behavioral contract:

- `setup` (optional pre-update hook — resolve zone IDs, fetch API key),
- `request` (build the wire request into a buffer),
- `response` (parse the server reply → an `RC_*` verdict),

plus static metadata: `name`, `checkip_name`/`checkip_url`/`checkip_ssl`,
`server_name`/`server_url`, `nousername`. Providers self-register at load
(`PLUGIN_INIT` → `__attribute__((constructor))` → `plugin_register` →
`TAILQ_INSERT_TAIL`). `plugin_find(name, loose)` does exact then substring
match and strips a trailing `:ID` multi-account suffix.

**Tiered reuse:** ~13 dyndns2-compatible providers (`plugins/dyndns.c`)
all delegate to `common_request`/`common_response` (`plugins/common.c`):
canonical `GET /nic/update?hostname=&myip=` + Basic auth, parsing
`good`/`nochg`/`badauth`/`nohost`/`911`. The **generic/custom** provider
(`plugins/generic.c`, `.name="custom"`) needs no code: a templated
`ddns-path` with `%u/%p/%h/%i/%%` format specifiers + a substring-list
response matcher (default `{"OK","good","true","updated","nochg"}`).

### 3.2 IP detection

`get_address_backend()` (`ddns.c:460`) tries three sources in fixed
priority, first-success-wins: (1) shell command `checkip-command`, (2)
local interface read (`getifaddrs`, fallback `SIOCGIFADDR`), (3) remote
checkip HTTP(S) server. Every result runs through `parse_my_address()`
(tries IPv6 first, then IPv4, byte-scans + `inet_pton` + validity gate
that rejects loopback/linklocal/multicast and carries an `except[]`
allowlist so a checkip page that embeds the resolver IP — e.g. Cloudflare
`1.1.1.1` in `/cdn-cgi/trace` — isn't mistaken for the client IP). v4-vs-v6
is **not** a config flag; it's whatever the checkip endpoint returns
(v6-only achieved by pointing checkip at a v6-only host).

### 3.3 Update cadence & change detection

Three periods on `ddns_t`: `normal_update_period_sec` (`period`, default
120s, clamp [30s, 10 days]), `forced_update_period_sec` (`forced-update`,
default 30 days), `error_update_period_sec` (fixed 600s). Two-stage
change detection: in-memory IP compare sets `ip_has_changed`;
`time_to_check()` = `force_addr_update || (now - last_update >
forced_update_period_sec)`. Backoff is **flat, not exponential**: success
→ normal; transient (TCP/DNS/5xx/RETRY_LATER) → error period; auth/notok →
exit. Ban-avoidance is primarily *don't re-send an unchanged IP* (the
cache), plus a niche `fake-address` decoy (send a throwaway `203.0.113.x`,
sleep, then the real IP) to make a no-op look like a change for providers
that expire unchanged records.

### 3.4 The cache / state file

**One file per hostname**: `${cache_dir}/<hostname>.cache` (default
`/var/cache/inadyn`). Body = last-published IP as plain text;
**last-update time is the file mtime** (no parsing). On startup
`read_cache_file()` seeds in-memory state from the cache, or **falls back
to a live DNS lookup** of the hostname if no cache exists — the key
anti-abuse move: never blast an update after a restart when the IP didn't
actually change. The cache is written only **after a successful update**.

### 3.5 Security / transport

HTTPS default (`ssl=true`), pluggable TLS (gnutls/openssl) with cert +
hostname verification (`secure-ssl` toggles fatal-vs-warn, `broken-rtc`
relaxes not-yet-valid for clock-less devices). Credentials are
**plaintext in the config** (`username`/`password`), only `chmod 600`
protects them; Basic-auth header built by hand (to survive `=`/`\` in
passwords). Token providers (Cloudflare) put the token in `password` and
emit `Authorization: Bearer`. Privilege drop via `--drop-privs`. **No
secret store** — this is the wart NOT to copy.

### 3.6 Config model

libConfuse declarative grammar: top-level globals (`period`,
`forced-update`, `iface`, `allow-ipv6`, `verify-address`, `secure-ssl`,
`fake-address`) + repeatable titled `provider <name> {}` / `custom <name>
{}` blocks. Multi-hostname `hostname = { a, b, c }`; multi-account via a
`:ID` title suffix; per-provider overrides of `user-agent`, `ssl`,
`checkip-*`. Signal-driven runtime commands (SIGHUP=reload, SIGUSR1=force
update, SIGUSR2=check-now) with 1-second sleep granularity.

### 3.7 The 9 ideas adopted (each: what / why)

1. **Three-method provider contract (setup/build/parse)** — minimal
   complete surface; a new provider is small. *Why:* clean
   extension point; one interface for RFC 2136 and every HTTP provider.
2. **Tiered reuse: one shared dyndns2 implementation behind many provider
   names** — *Why:* most consumer DDNS providers ARE dyndns2; specialize
   only where the API differs (Cloudflare/Route 53).
3. **Generic/custom templated provider (URL template + response-substring
   matcher)** — *Why:* operators add unsupported providers from config
   alone, no xpf code change. Highest-leverage feature.
4. **Per-host last-published cache, mtime-as-timestamp** — *Why:*
   change-detection + free "last update" without re-sending an unchanged
   IP; xpf already has the durable analogue (`dhcp-ddns-state.json`) —
   extend it to a per-scope last-published cache.
5. **Seed from cache, else live DNS lookup, on startup** — *Why:* never
   blast a redundant update (and risk a provider ban) after a daemon
   restart / failback.
6. **Ordered fallback IP sources with a bogus-IP allowlist** — *Why:*
   robust WAN-address detection (interface → DHCP lease → checkip), and
   don't mistake a checkip page's embedded resolver IP for the client IP.
7. **Forced-refresh interval decoupled from poll interval** — *Why:*
   prove liveness to the provider (and resist record reaping) without
   per-poll traffic; xpf's reconcile loop already re-asserts every 30s —
   add a forced wire-update floor instead of an every-reconcile add.
8. **Flat normal/error update periods + force-on-failure retry** — *Why:*
   simple, predictable ban-avoidance; xpf should add a per-scope error
   backoff so a failing provider doesn't hammer at the reconcile cadence.
9. **Runtime force-update / check-now / reload nudges** — *Why:* xpf
   already has commit + MASTER-takeover nudges; add an operator
   `request system dynamic-dns update` and an address-change nudge.

**Explicitly NOT adopted:** plaintext secrets protected only by file
perms. xpf already has `config.Secret` (redacting type, `Reveal()` /
`SecretRedacted`) — credentials MUST use it everywhere, never logged.

---

## 4. Current xpf DDNS state (what exists / what's missing)

(Verified first-hand against current master, commit `62d323c6a`.)

### 4.1 What exists (the #1387 DHCP-lease path — Surface B, live)

- **Backend abstraction seam already present:** `DNSUpdater` interface
  (`pkg/dhcpserver/ddns_dns.go:51`) with `UpsertLease`/`DeleteLease`; the
  unit is `LeaseDNSRecord` (carries `ClientID` for DHCID). Two impls:
  `nopUpdater` (no backend) and `*rfc2136Updater`. **This is the seam the
  provider abstraction extends.**
- **Live RFC 2136 backend** (`pkg/dhcpserver/ddns_rfc2136.go`): exact-RR
  only (never delete-RRset/name); UDP-first/TCP-on-truncation `exchange`
  (5s timeout); TSIG (`canonicalTSIGAlgorithm` defaults hmac-sha256,
  rejects hmac-md5); DHCID marker (`dhcidRR`, SHA-256 over canonical
  identity string + FQDN wire); RFC 4703 §5.3.2 two-attempt replace-owned
  (`sendAddOwned`); DHCID-match-guarded delete (`sendRemoveForward`).
  **No source binding** — `*dns.Client{Timeout, TsigSecret}` only (#2665).
- **Ownership store / protection boundary:** `ddnsState`
  (`pkg/dhcpserver/ddns_state.go`), JSON at
  `/var/lib/xpf/dhcp-ddns-state.json` via `fsatomic.WriteFileDurable`.
  `ownedRecord` carries `ClientID`, `PTRPending`. A delete is issued ONLY
  for an entry in this store ("never delete non-owned").
- **Write-ahead durability (#2662):** `upsertLocked`
  (`pkg/dhcpserver/ddns.go:563`) persists the ownership intent
  (`PTRPending=true`) + `state.save()` **before** the wire add; clears on
  success, removes on `errDDNSConflictRefused`, keeps + counts on
  `errDDNSPTRPending`.
- **Sentinels:** `errDDNSConflictRefused` (ddns_rfc2136.go:71 — name owned
  by another party; record NO ownership), `errDDNSPTRPending`
  (ddns_rfc2136.go:87 — forward published, reverse PTR failed
  non-skippably; record ownership + retry PTR), plus counted PTR
  NOTAUTH/REFUSED skips (`isPTRSkippable`).
- **Reconcile core:** `reconcileOnceLocked(ctx, pol, leases, untrusted)`
  (ddns.go:361) — Pass 1 expire/reassign deletes, Pass 2 adds;
  `untrusted` family (unreadable CSV) skips the destructive diff
  (mass-delete fail-safe). `deleteOwnedLocked` (ddns.go:667) is the sole
  delete authority, re-deriving the exact record from owned state.
- **Dual-stack already independent (partly satisfies #2663):** v4/v6 Kea
  memfiles parsed separately with independent `untrusted` flags; A vs AAAA;
  in-addr.arpa vs ip6.arpa. **But** policy is still single/global — there
  is no independent v4 vs v6 *policy* (domain/server/TSIG/TTL/conflict).
- **Daemon loop + node-level HA gate:** `runDDNSReconcileLoop`
  (`pkg/daemon/daemon_ddns.go:56`) — immediate first pass, 30s ticker
  (`ddnsReconcileInterval`) + nudge channel, 60s per-pass timeout.
  `ddnsWriterGateOpen()` (line 148): standalone → always writer; cluster →
  writer IFF MASTER for ≥1 RG. Nudged on commit (daemon_apply.go) and
  MASTER takeover (daemon_ha.go).
- **Config:** `config.DHCPDynamicDNSConfig` (types_system.go:922) with
  `Enabled/Domain/TTLSeconds/HostnameSource/ConflictPolicy/Backend/
  UpdateServer/TSIGKeyName/TSIGAlgorithm/TSIGSecret(Secret)`. Grammar
  `dhcpDynamicDNSSchema()` (schema_system.go) under BOTH
  `dhcp-local-server` and `dhcpv6-local-server`. Warn-only validation
  `validateDDNSBackendWarnings()` (compiler_validate_warn.go).
- **Observability:** `Stats()`/`DDNSStats`; `show ... dynamic-dns` (CLI +
  gRPC); `xpf_dhcp_ddns_*` Prometheus.
- **Credential type:** `config.Secret` (secret.go) — redacting `String()`,
  `Reveal()`, `SecretRedacted` sentinel, refuses to ingest the redacted
  sentinel.
- **Address sources for Surface A already exist (unused by DDNS):**
  `pkg/dhcp` client `Manager.Leases()` / `LeaseFor(ifaceName, af) *Lease`,
  the #1844 gateway-change hook (`onGatewayChange`); static addresses in
  `config.InterfaceUnit.Addresses []string`; HA reth/VIP addresses via the
  cluster.

### 4.2 What's missing

- **All of Surface A** (#2679): no config model, compiler path, runtime
  manager, ownership/state, address-observation pipeline, source binding,
  HTTP providers, or operator surfaces for publishing the firewall's own
  address. `*rfc2136Updater` is only ever called with Kea-lease records.
- **Provider backends beyond RFC 2136:** no dyndns2/Cloudflare/Route 53/
  generic-templated. Surface A on consumer/SaaS DNS needs them.
- **Per-scope policy** (#2663): single global `DynamicDNS`; no per-
  interface / independent v4-v6 *policy*; ownership keys
  (`identity|address`) carry no interface/RG/family/VRF scope.
- **Per-RG HA gate** (#2664): node-level gate can double-write on partial
  failover; `ddnsLease`/`ownedRecord` carry no RG/interface owner.
- **Source/VRF binding** (#2665): no `Dialer.LocalAddr` /
  `SO_BINDTODEVICE` / VRF select.
- **TSIG tuple validation** (#2666): key-without-secret / secret-without-
  key commit; fail at runtime.
- **skip-existing PTR-conflict orphan** (#2676): forward published but the
  upsertLocked sentinel ordering checks `errDDNSConflictRefused` first →
  records no ownership → orphans the live forward.
- **Stale docs/comments** (#2667): code + schema + `docs/config-schema.md`
  still say "live updater deferred / config-only".

### 4.3 Stale-comment caveats found (fold into #2667 scope)

- `ddns.go` header + `nodeID` comments say live backend / HA gating
  "deferred" — both shipped.
- `ownerWatermark` (ddns.go:239) does NOT fold `nodeID` into the hash
  (identity+address only), contrary to its comment.

---

## 5. Proposed architecture

### 5.1 Shape: one DDNS spine, two publish surfaces, many backends

```
                 +-----------------------------------------------+
                 |              pkg/ddns (NEW spine)             |
                 |                                               |
 Surface A  ---> | AddressObservation  ---\                      |
 (router/iface)  |  (iface/DHCP/static/HA) \                     |
                 |                          >  UpdateEngine  --\  |
 Surface B  ---> | LeaseObservation   -----/   (per-scope:    | \|
 (DHCP leases)   |  (existing Kea memfile)      change-detect, |  +-> Backend
                 |                              forced-refresh, |  |   abstraction
                 |   ScopeKey {family, iface,   error backoff,  |  |   (Provider)
                 |     unit, routing-instance,  ban-avoid,      |  |
                 |     rg-owner, policy-id}      last-published  |  +-> RFC2136/TSIG
                 |                               cache)          |  |   (reuse today)
                 |   OwnerGate (per-scope HA) --/                |  +-> dyndns2
                 |   StateStore (durable, per-scope)             |  +-> Cloudflare
                 +-----------------------------------------------+  +-> Route53
                                                                    +-> generic-template
```

The **existing #1387 reconciler IS the UpdateEngine for Surface B** — we
extend it (scope keys, per-RG gate, per-scope backend selection) rather
than fork it. Surface A gets a parallel observation feed into the same
engine + state spine, with a different ownership semantic (no DHCID; the
firewall is the sole authoritative owner of its own record).

### 5.2 Backend / provider abstraction

Generalize the existing `DNSUpdater` (currently lease-specific) into a
provider-neutral `Backend` operating on a generic record, with the RFC
2136 updater as the first impl (rename-not-rewrite):

```go
// pkg/ddns/backend.go  (NEW; the existing rfc2136Updater moves here,
// keeping its DHCID/ownership logic intact for Surface B).
package ddns

// Record is the surface-neutral unit (supersedes LeaseDNSRecord; the
// lease path supplies ClientID/DHCID fields, the router path leaves them
// empty and uses owner=self semantics).
type Record struct {
    FQDN    string
    Family  Family        // inet | inet6
    Addr    netip.Addr
    TTL     uint32
    // Lease-only (Surface B): DHCID inputs. Empty => router-owned.
    ClientID string
    PublishPTR bool
}

// Backend is the inadyn ddns_system_t analogue: build+apply an upsert,
// and a guarded delete. Implementations: rfc2136, dyndns2, cloudflare,
// route53, generic-template.
type Backend interface {
    Name() string
    Upsert(ctx context.Context, r Record) error   // idempotent
    Delete(ctx context.Context, r Record) error   // guarded; may no-op
    // Capabilities advertises what the engine may rely on.
    Caps() BackendCaps                            // {SupportsPTR, SupportsTSIG, OwnershipModel}
}
```

- **rfc2136 backend** keeps the DHCID/ownership two-attempt logic and the
  sentinels (`errDDNSConflictRefused`, `errDDNSPTRPending`). Gains source
  binding (§5.7). For Surface A (router-owned, no ClientID) it uses a
  *self-ownership* prereq (name-not-in-use OR matches our prior value)
  instead of DHCID.
- **dyndns2 backend** (inadyn `common_request`/`common_response`
  analogue): `GET /nic/update?hostname=&myip=` + Basic auth, parse
  `good`/`nochg`/`badauth`/`nohost`/`abuse`/`911` → typed verdict. Many
  provider *names* map to this one impl (tiered reuse, inadyn idea #2).
- **cloudflare backend**: token (`Authorization: Bearer`) + zone/record-id
  resolution in a `setup`-style step, `PATCH`/`PUT` record.
- **route53 backend**: SigV4 + `ChangeResourceRecordSets` UPSERT.
- **generic-template backend** (inadyn idea #3): config-only provider —
  templated URL with `%h/%i` + response-substring match. No xpf code per
  new provider.

Provider registration is a Go pattern (no inadyn constructor magic): a
package-level `map[string]BackendFactory` populated by `init()` in each
backend file (the `linkme`/`inventory` analogue), keyed by provider name;
`generic-template` is the config-driven catch-all.

### 5.3 IP-source / address-observation layer (Surface A)

`pkg/ddns/observe` produces `Observation{ScopeKey, Family, Addr, Source,
SeenAt}` from ordered sources (inadyn idea #6), per configured binding:

1. **interface read** — netlink address on the bound interface/unit/
   family (covers static + DHCP-applied + PD-derived + reth/VIP).
2. **DHCP client lease** — `pkg/dhcp.Manager.LeaseFor(iface, af)` (the
   authoritative learned WAN address; fed by the #1844 gateway-change
   hook as a *nudge*).
3. **checkip** — optional HTTP(S) checkip endpoint for NAT'd / behind-
   another-router deployments, with the inadyn bogus-IP allowlist and v6-
   first parse.

Selection is per-scope config: `address-source interface|dhcp|checkip`
(default `interface`). v4 and v6 are observed and published independently.

For **Surface B** the observation is the existing Kea-memfile lease parser
(`pkg/dhcpserver/ddns_leases.go`) — unchanged, just emitting `ScopeKey`-
tagged records.

### 5.4 ScopeKey — the unifying ownership/scope primitive (#2663/#2664)

Replace the flat `identity|address` ownership key with:

```go
type ScopeKey struct {
    Family         Family   // inet | inet6      (#2663 independent v4/v6)
    Interface      string   // e.g. ge-0-0-2.50  ("" for global lease policy)
    Unit           int
    RoutingInstance string  // VRF / routing-instance (#2665)
    RGOwner        int      // redundancy-group id owning this scope (#2664)
    PolicyID       string   // which provider/profile applies
}
```

Ownership records are keyed by `{ScopeKey, identity, address}` (lease) or
`{ScopeKey, fqdn}` (router). This single change subsumes #2663 (per-
interface + independent v4/v6), gives #2664 a per-RG owner to gate on, and
gives #2665 the routing-instance for source binding.

### 5.5 Update engine (change-detection / forced-refresh / backoff / cache)

Per-scope state (extends the existing durable store):

- **Last-published cache** (inadyn idea #4): `{ScopeKey → {addr,
  publishedAt, ptrPending}}` persisted via `fsatomic.WriteFileDurable`.
  Surface A: `/var/lib/xpf/interface-ddns-state.json`. Surface B keeps
  `/var/lib/xpf/dhcp-ddns-state.json` (the existing ownership store,
  scope-extended). A wire upsert fires only when `addr != cached.addr`
  **OR** `now - publishedAt > forced-refresh` **OR** an operator force.
- **Startup seed** (inadyn idea #5): seed the cache from disk; if absent,
  optionally a live DNS lookup of the FQDN to avoid a redundant first-boot
  update (gated by config to avoid a leak in air-gapped setups).
- **Forced-refresh decoupled from poll** (inadyn idea #7): the existing
  30s reconcile re-asserts *desired state* but MUST NOT send a wire
  update every 30s; a per-scope `forced-refresh` (default e.g. 24h) is the
  wire-update floor for an unchanged address.
- **Error backoff** (inadyn idea #8): per-scope error state — on transient
  failure (timeout/SERVFAIL/5xx/HTTP 429) back off (start at the reconcile
  interval, cap at e.g. 1h) instead of retrying every 30s; on auth/abuse
  responses (dyndns2 `badauth`/`abuse`/`911`, HTTP 401/429) back off hard
  and log once (ban-avoidance). Cloudflare 1200/5min and Route 53 5 req/s
  rate limits are respected by the backoff + change-only discipline.
- **Operator nudges** (inadyn idea #9): existing commit + MASTER-takeover
  nudges, plus a new address-change nudge (from the #1844 hook /
  netlink) and `request system dynamic-dns update` (force-now).

### 5.6 HA owner-gating (per-scope) (#2664)

Replace the node-level `ddnsWriterGateOpen()` ("master for any RG") with a
**per-scope** gate: a scope is writable IFF standalone OR the local node
is MASTER for `ScopeKey.RGOwner`. On a **partial demotion** (lose RG1,
keep RG2) the engine: (a) stops publishing RG1 scopes, (b) is nudged after
the filtered DHCP re-apply (close the #2664 "no DDNS nudge on partial
demotion" gap), (c) does NOT withdraw (the new RG1 master refreshes; a
withdraw race would blackhole). Fail-closed on split-brain (uncertain RG
ownership → don't write). Surface B's existing MASTER-filtered Kea memfile
keeps the lease *input* sets disjoint; the per-scope gate makes the
*publish* decision disjoint too. Surface A router records get the RG owner
from the address's interface/reth RG.

### 5.7 Source / VRF binding (#2665)

The rfc2136 backend (and HTTP backends) build their transport with a
custom `net.Dialer`: `LocalAddr` from the scope's `source-address`, and
`Dialer.Control` calling `SO_BINDTODEVICE` for `destination-interface`,
or binding into the VRF for `routing-instance`. Schema leaves
`source-address` / `destination-interface` / `routing-instance` per scope.

### 5.8 Dual-stack independent policy (#2663)

`inet` and `inet6` each carry their own `{domain, provider/backend,
update-server, TSIG, TTL, conflict-policy, source, enable}`. The engine
already parses v4/v6 lease files independently; this adds independent
*policy*. A WAN1-v4 record can go to provider X, WAN1-v6 to provider Y.

### 5.9 Config grammar (Junos-style `set`)

**Shared provider/profile catalog** (credentials once, referenced by
scope; inadyn multi-provider + the `config.Secret` redaction convention):

```
set system services dynamic-dns provider cf-token backend cloudflare
set system services dynamic-dns provider cf-token zone example.net
set system services dynamic-dns provider cf-token api-token "<secret>"      # config.Secret, redacted
set system services dynamic-dns provider corp-2136 backend rfc2136
set system services dynamic-dns provider corp-2136 update-server 10.0.0.53
set system services dynamic-dns provider corp-2136 tsig-key k1
set system services dynamic-dns provider corp-2136 tsig-algorithm hmac-sha256
set system services dynamic-dns provider corp-2136 tsig-secret "<secret>"
# generic templated provider (inadyn custom) — no code needed:
set system services dynamic-dns provider myhost backend generic
set system services dynamic-dns provider myhost url "https://dns.example/upd?host=%h&ip=%i"
set system services dynamic-dns provider myhost ok-response good
set system services dynamic-dns provider myhost username u1
set system services dynamic-dns provider myhost password "<secret>"

# global engine tunables (inadyn period/forced-update analogues)
set system services dynamic-dns forced-refresh 24h
set system services dynamic-dns error-backoff-max 1h
```

**Surface A — router/interface-address DDNS**, per-interface per-family
(independent v4/v6):

```
set interfaces ge-0-0-2 unit 50 family inet  dynamic-dns provider cf-token
set interfaces ge-0-0-2 unit 50 family inet  dynamic-dns hostname wan.example.net
set interfaces ge-0-0-2 unit 50 family inet  dynamic-dns address-source dhcp
set interfaces ge-0-0-2 unit 50 family inet  dynamic-dns ttl 300
set interfaces ge-0-0-2 unit 50 family inet6 dynamic-dns provider corp-2136
set interfaces ge-0-0-2 unit 50 family inet6 dynamic-dns hostname wan6.example.net
set interfaces ge-0-0-2 unit 50 family inet6 dynamic-dns source-address 2001:db8::8
# HA-owned reth/virtual address publish:
set interfaces reth0  unit 80 family inet  dynamic-dns provider corp-2136
set interfaces reth0  unit 80 family inet  dynamic-dns hostname fw-vip.example.net
```

**Surface B — DHCP-lease DDNS**, per-family scoped (extends today's
single-global stanza; backward compatible — existing flat stanza maps to
a global scope):

```
set system services dhcp-local-server dynamic-dns provider corp-2136
set system services dhcp-local-server dynamic-dns domain corp.example.com
set system services dhcp-local-server dynamic-dns conflict-policy replace-owned
set system services dhcp-local-server dynamic-dns publish-ptr
set system services dhcpv6-local-server dynamic-dns provider corp-2136-v6   # independent v6 policy (#2663)
set system services dhcpv6-local-server dynamic-dns domain corp6.example.com
# per-group/pool/interface override (the #2663 scope subtree):
set system services dhcp-local-server group g-trust interface ge-0-0-1 dynamic-dns provider corp-trust
```

Backward compatibility: the existing inline `update-server`/`tsig-*`
leaves under `dhcp-local-server dynamic-dns` remain valid (mapped to an
anonymous provider) so committed configs don't break; the new `provider`
reference is the preferred form.

### 5.10 Go types & placement

Recommended (see §7 for the alternative): a **new `pkg/ddns`** spine that
the existing `pkg/dhcpserver` lease path calls into, NOT a third branch
inside `pkg/dhcpserver`.

| Element | Location |
|---|---|
| `Backend` interface, `Record`, `BackendCaps`, factory registry | `pkg/ddns/backend.go` (NEW) |
| `rfc2136` backend (moved from `pkg/dhcpserver/ddns_rfc2136.go`, logic intact) | `pkg/ddns/backend_rfc2136.go` |
| `dyndns2` / `cloudflare` / `route53` / `generic` backends | `pkg/ddns/backend_*.go` (NEW) |
| `ScopeKey`, per-scope state store (durable) | `pkg/ddns/state.go` (generalizes `ddns_state.go`) |
| `UpdateEngine` (change-detect/forced-refresh/backoff/cache) | `pkg/ddns/engine.go` |
| Surface A address observation (iface/DHCP/checkip) | `pkg/ddns/observe/` |
| Surface B lease observation (Kea memfile) | stays in `pkg/dhcpserver/ddns_leases.go`, emits `ScopeKey` records |
| Per-scope HA gate | `pkg/daemon/daemon_ddns.go` (generalize `ddnsWriterGateOpen`) |
| Surface A config | `pkg/config/types_interfaces.go` + `schema_interfaces.go` + `system services dynamic-dns` in `types_system.go`/`schema_system.go` |
| Surface B scope config | extend `DHCPDynamicDNSConfig` + `dhcpDynamicDNSSchema` (#2663) |
| Validation (TSIG tuple, provider refs) | `pkg/config/compiler_validate_warn.go` (#2666) |
| Operator surfaces | `pkg/cli` / `pkg/grpcapi` / `pkg/api` (per-scope last-published) |

**Reuse, don't replace:** the DHCID logic, the two sentinels, the write-
ahead durability, the never-delete-non-owned boundary, and the destructive
fail-safe all move with the rfc2136 backend / engine intact. The
`config.Secret` type is used for every credential.

---

## 6. How each open DDNS issue maps in

| Issue | Title (short) | Subsumed by | Phase |
|---|---|---|---|
| **#2667** | Docs: live RFC 2136 no longer "deferred" | §4.3 stale-comment cleanup; doc the spine | P0 |
| **#2666** | Incomplete TSIG tuple validation | §5.9 validation; warn key⇔secret | P0 |
| **#2676** | skip-existing PTR-conflict orphans forward | §5.2 sentinel-ordering fix in the rfc2136 backend (forward-published ⇒ record ownership, never the no-ownership branch) | P0 |
| **#2663** | No per-interface / independent v4-v6 policy | §5.4 ScopeKey + §5.8 dual-stack policy + §5.9 scope subtree | P1 |
| **#2664** | Node-level HA gate publishes stale rows | §5.6 per-scope (per-RG) gate + partial-demotion nudge | P1 |
| **#2665** | No source/VRF binding | §5.7 Dialer.LocalAddr / SO_BINDTODEVICE / VRF | P1 |
| **#2679** | No router/interface-address DDNS | §5.3 observation + Surface A config + the whole spine | P2-P3 |

P0 are small, ship-now hardening of the existing path (also de-risk the
refactor). P1 is the ScopeKey/HA/binding refactor that #2679 depends on.
P2-P3 build Surface A + the HTTP providers on top.

---

## 7. Design forks & recommendations

### Fork 1 — Extend `pkg/dhcpserver/ddns` vs new `pkg/ddns`

- **(a) Keep everything in `pkg/dhcpserver`, add a router branch.** Less
  churn short-term. *But* it smears DHCP DHCID/lease semantics onto
  router records, couples Surface A to the DHCP-server package, and
  inherits the node-level gate (the #2679 "fix direction" explicitly warns
  against this).
- **(b) New `pkg/ddns` spine; `pkg/dhcpserver` becomes one *caller*.**
  Clean separation of the two ownership semantics (DHCID vs self-owned),
  reusable backend/engine/state, no DHCP coupling for router records.
  Larger first move (move the rfc2136 backend out).

**Recommendation: (b).** It is the only option that lets Surface A and
Surface B share the engine/backends/state without semantic smear, and it
matches the #2679 fix direction. Mitigate the churn by moving the rfc2136
backend *verbatim* (logic + tests) in P1 before adding scopes.

### Fork 2 — Provider plugins as Go interfaces vs config-driven templates

- **(a) Pure config-driven templates (inadyn generic everywhere).** Zero
  code per provider; operators add anything. But Cloudflare/Route 53 need
  multi-step auth (zone-id resolve, SigV4) that a URL template can't
  express, and a template can't enforce per-provider rate-limit/verdict
  semantics.
- **(b) Pure Go-interface backends.** Type-safe, testable, exact verdicts;
  but every niche provider needs xpf code.
- **(c) Both: Go backends for RFC 2136 / dyndns2 / Cloudflare / Route 53;
  a `generic` template backend as the config-only catch-all.**

**Recommendation: (c)** — exactly inadyn's split (coded `common` family +
coded specialized + `custom` template). Best coverage with least code.

### Fork 3 — Per-host cache file (inadyn) vs one scoped state file

- inadyn: one file per hostname (mtime = timestamp). xpf already has one
  durable JSON store with fsync.

**Recommendation:** keep xpf's **single durable JSON state file per
surface** (it already gives atomic fsync + versioning + the ownership
boundary), but adopt inadyn's *semantics* (per-scope last-published addr +
publishedAt + the seed-or-lookup-on-startup rule). Don't fragment into
per-hostname files — xpf's fsatomic store is strictly better than mtime.

### Fork 4 — checkip dependency for Surface A

- Default to **interface/DHCP-lease read** (the firewall knows its own
  address authoritatively — no external dependency, no ban risk). Offer
  checkip only for behind-NAT deployments, opt-in per scope.

**Recommendation:** interface/DHCP default; checkip opt-in. (xpf is the
router — unlike a generic host, it usually *has* the public address
directly.)

---

## 8. Risk assessment, security, HA correctness

### 8.1 Security

- **Credentials:** every secret (TSIG secret, API token, dyndns2 password)
  uses `config.Secret` — redacted in `String()`/show/logs, `Reveal()` only
  at the transport boundary. No secret in any error string (the rfc2136
  backend already enforces this; new backends MUST too). HTTPS-only for
  HTTP providers with cert + hostname verification (inadyn `secure-ssl`
  default-on analogue; xpf uses the system trust store).
- **TSIG:** keep hmac-md5 rejection; add tuple validation (#2666). RFC
  3007/8945 secure-update posture preserved.
- **DHCID / RFC 4701/4703 (Surface B):** unchanged — replace-owned two-
  attempt + DHCID-match-guarded delete; never adopt/delete a third party's
  RR. Surface A uses self-ownership (name-not-in-use OR matches our prior
  cached value), never a blind RRset replace.
- **Surface A spoofing:** the address comes from the firewall's own
  netlink/DHCP state, not from any untrusted input; checkip responses go
  through the inadyn validity gate + bogus-IP allowlist.

### 8.2 HA correctness

- **Single-writer per scope** (#2664): per-RG gate; fail-closed on
  uncertain ownership; no withdraw on demotion (peer refreshes). Partial-
  demotion nudge after filtered DHCP apply closes the documented gap.
- **No double-write:** Surface B input sets disjoint by MASTER-filtered
  Kea memfile + per-RG publish gate. Surface A records gated by the
  address's owning RG.
- **Write-ahead durability** preserved (#2662) so a crash mid-update can't
  orphan a forward or lose ownership; extended to per-scope.
- **`make test-failover` is mandatory** for any change touching the gate /
  HA path (project rule).

### 8.3 Operational risks

- **Provider bans:** mitigated by change-only updates, per-scope error
  backoff, hard backoff on auth/abuse/429, and the forced-refresh floor
  (not per-poll). Respect Cloudflare 1200/5min and Route 53 5 req/s.
- **Refactor risk** (moving rfc2136 out of `pkg/dhcpserver`): mitigated by
  a verbatim move + the existing ~3,500 lines of tests moving with it,
  P0-first hardening, and a no-behavior-change move PR.
- **IPv6 PD churn:** Surface A must re-publish on prefix change; the
  observation layer keys on the actual learned address, and the DHCPv6/PD
  apply path nudges the engine.
- **Backward-compat:** existing committed Surface B configs must keep
  working (inline provider mapping); fail-on-revert tests required.

---

## 9. Phased delivery (each phase = a shippable PR / `/engineer` run)

**P0 — harden the existing path + de-stale (small, independent, ships
now).** Closes #2667, #2666, #2676.
- #2667: fix stale comments/docs (live backend + HA gate shipped;
  `ownerWatermark` doc).
- #2666: warn-only TSIG tuple validation (key⇔secret) in
  `compiler_validate_warn.go`.
- #2676: fix the upsertLocked sentinel ordering so a forward-published-but-
  PTR-conflict records forward ownership (no orphan); don't double-wrap
  the two sentinels.
- Gate: `make test`; rfc2136 tests green.

**P1a — extract `pkg/ddns` spine (no behavior change).** Move the rfc2136
backend + state store + reconciler engine out of `pkg/dhcpserver` into
`pkg/ddns` with logic + tests verbatim; `pkg/dhcpserver` calls in.
- Gate: `make test`, `make test-failover` (HA-touching), diff is a move.

**P1b — ScopeKey + per-scope policy + per-RG HA gate + source binding.**
Closes #2663, #2664, #2665.
- ScopeKey on ownership records + per-family independent policy + the
  `#2663` scope subtree (group/pool/interface) for Surface B.
- Per-RG `ddnsWriterGateOpen` + partial-demotion nudge (#2664).
- `Dialer.LocalAddr` / `SO_BINDTODEVICE` / VRF bind + schema leaves
  (#2665).
- Gate: `make test`, `make test-failover` (mandatory — gate + HA path).

**P2 — Surface A core (router/interface-address publish over RFC 2136).**
Partial #2679.
- `system services dynamic-dns` provider catalog + per-interface per-family
  `dynamic-dns` binding (config/schema/compiler).
- Address-observation layer (interface read + DHCP-lease feed via the
  #1844 hook + netlink), engine change-detect/forced-refresh/backoff,
  `interface-ddns-state.json`, per-scope HA gate for router records.
- CLI/gRPC/REST/Prometheus per-scope last-published surfaces.
- Gate: `make test`, `make test-failover`, live publish on the standalone
  VM (DHCP-WAN address → A/AAAA at an authoritative test server).

**P3 — HTTP provider backends (dyndns2 / Cloudflare / Route 53 / generic
template).** Completes #2679 for consumer/SaaS DNS.
- dyndns2 shared backend (many provider names), Cloudflare (token + zone-
  id setup), Route 53 (SigV4 UPSERT), generic templated (config-only).
- checkip address source (opt-in, with bogus-IP allowlist).
- Gate: `make test`; live publish against a real provider (lab-gated).

**P4 (optional) — polish.** `request system dynamic-dns update` force-now,
`fake-address` decoy (if a target provider needs it), startup seed-or-
lookup tuning, multi-account `:ID`-style provider references.

Ordering rationale: P0 is risk-free hardening; P1a/P1b build the spine
#2679 depends on; P2/P3 deliver Surface A. Each phase is independently
mergeable.

---

## 10. Out of scope / non-goals

- **Kea D2 backend** — plan-killed; D2 is not in the appliance image
  (`bake.py`). The `kea-d2` enum stays reserved/unimplemented.
- **Authoritative DNS / recursive resolver / DNS proxy** — xpf already has
  dns-proxy; this is a DDNS *client*, not a server.
- **Split-horizon view selection** beyond per-scope provider binding.
- **Arbitrary record types** — A/AAAA forward + PTR reverse only (the DDNS
  use case); not MX/TXT/SRV management.
- **Dynamic provider plugins via dlopen / external binaries** — Go
  in-tree backends + the config-driven generic template only.
- **A second on-disk format per hostname** — keep the single durable
  fsatomic JSON store per surface.
- **Removing the existing inline Surface B stanza** — kept for backward
  compatibility.

---

## 11. Open questions for review

1. **Provider catalog placement:** `system services dynamic-dns provider
   <name>` (shared catalog, referenced by scope) vs inline per-binding
   credentials. Plan assumes a shared catalog. Confirm.
2. **Surface A binding altitude:** per `interfaces <if> unit <n> family
   <af> dynamic-dns` (chosen, matches the #2679 fix direction) vs a flat
   `system services dynamic-dns host <fqdn> { interface ... }` list.
   Confirm the per-interface altitude.
3. **HTTP provider priority:** which providers ship in P3 first?
   (dyndns2-family covers most consumer DDNS; Cloudflare is the most-
   requested SaaS; Route 53 is heavier — SigV4.)
4. **checkip default:** keep it opt-in (interface/DHCP default) — confirm
   no scenario needs checkip-by-default.
5. **forced-refresh default:** 24h proposed for Surface A; should Surface
   B keep "re-assert desired state every 30s but wire-update only on
   change + forced-refresh" (it currently re-adds idempotently each
   reconcile — confirm that's acceptable load vs adding a wire floor).
6. **Partial-demotion withdraw policy:** confirm "stop writing, do NOT
   withdraw" for both surfaces (peer refreshes) vs an explicit handoff.
7. **State-file migration:** does the scope-extended
   `dhcp-ddns-state.json` need a version bump + migration, or is the
   fail-open-to-empty path acceptable on first upgrade?
8. **`pkg/ddns` extraction blast radius:** is a verbatim-move PR (P1a)
   acceptable as a no-behavior-change refactor, given the import churn in
   `pkg/dhcpserver`/`pkg/daemon`?

---

## 12. Hostile self-review (no live companion review run)

Codex/AGY plan-review not invoked for this research-only doc; recorded a
rigorous self-review instead.

- **"Why not just add a router branch to `pkg/dhcpserver`?"** — Rejected:
  smears DHCID/lease ownership onto router records and inherits the unsafe
  node-level gate; the #2679 fix direction explicitly forbids it. §7
  Fork 1.
- **"The `pkg/ddns` extraction is a big risky move."** — True; mitigated
  by P1a being a *verbatim* move (logic + ~3,500 lines of tests intact,
  no behavior change, `make test-failover` gated) done BEFORE any scope
  change. The alternative (never extract) is the worse long-term tax.
- **"Dual-stack is already independent — is #2663 overstated?"** — The
  *parsing/wire* path is independent (separate memfiles, A/AAAA, separate
  untrusted flags), but the *policy* (domain/server/TSIG/TTL/conflict) is
  single+global. #2663 is about independent *policy* and per-interface
  scope, which is genuinely missing. The design must not claim to "add"
  v4/v6 independence that already exists at the wire level — it adds
  policy-level independence. Corrected in §4.1/§5.8.
- **"Forced-refresh could re-introduce ban risk."** — The whole point is
  the opposite: change-only + a *long* forced floor reduces traffic vs the
  current every-30s idempotent re-add. But note (open Q5) the current
  Surface B reconcile re-adds idempotently each pass; switching to a wire-
  update floor is a behavior change that must be measured, not assumed.
- **"Per-RG gate could blackhole on a withdraw race."** — Addressed by
  "stop writing, never withdraw on demotion" + the peer refresh; the risk
  is a *stale* record for one refresh interval, not a blackhole. Confirmed
  the existing path already chose no-withdraw-on-demotion (plan R3).
- **"HTTP backends add a TLS/credential attack surface."** — Constrained
  to HTTPS + system trust + `config.Secret` + no-secret-in-logs; Surface A
  addresses come from the firewall's own state, not untrusted input.
- **"checkip bogus-IP allowlist is a maintenance burden."** — Kept opt-in
  and small (the Cloudflare-anycast case); interface/DHCP is the default
  so most deployments never touch checkip.
- **Falsifiable web claims used:** Cloudflare DNS API ~1200 req/5min;
  Route 53 5 req/s/account/region; dyndns2 `good`/`nochg`/`badauth`/`911`
  verdicts + common 10-min lockout on abuse; Kea D2 RFC 4703 DHCID
  conflict model + "queued NCRs lost on shutdown". These drive the backoff
  / rate-limit and the Kea-D2-non-goal decisions. Sources in §13.

---

## 13. Sources

- RFC 2136 (DNS UPDATE), RFC 3007 (secure update), RFC 8945 / 2845 (TSIG),
  RFC 4701 (DHCID RR), RFC 4703 (DHCP-DNS FQDN conflict resolution) —
  rfc-editor.org / datatracker.ietf.org.
- ISC Kea D2 (DHCP-DDNS) — kea.readthedocs.io/en/latest/arm/ddns.html
  (RFC 4703 DHCID conflict model; `ddns-conflict-resolution-mode`;
  queued NameChangeRequests lost on shutdown).
- dyndns2 de-facto protocol + ban behavior — help.dyn.com/ddclient,
  sourceforge.net/p/ddclient/wiki/protocols, desec.readthedocs.io.
- Cloudflare DNS API (rate limit ~1200/5min, Bearer token, PATCH/PUT) —
  developers.cloudflare.com/dns; Route 53 (5 req/s, ChangeResourceRecord
  Sets UPSERT) — AWS docs.
- inadyn source — `/home/ps/git/inadyn` (`include/plugin.h`,
  `include/ddns.h`, `src/ddns.c`, `src/cache.c`, `src/conf.c`,
  `plugins/{generic,common,dyndns,cloudflare}.c`).
- xpf current DDNS — `pkg/dhcpserver/ddns*.go`, `pkg/daemon/daemon_ddns.go`,
  `pkg/config/{types_system,schema_system,compiler_services,
  compiler_validate_warn,secret}.go`, `docs/config-schema.md`,
  `docs/feature-gaps.md`, issues #2663-2667/2676/2679.
