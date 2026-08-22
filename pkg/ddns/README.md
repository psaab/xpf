# pkg/ddns — Dynamic DNS spine

`pkg/ddns` is the provider-neutral Dynamic DNS spine extracted from
`pkg/dhcpserver` in **#2691 phase P1a** (a verbatim, no-behavior-change code
move; see `docs/research/ddns-world-class/plan.md` §9). It owns the reconcile
engine, the ownership state store, the RFC 2136 backend, and the DNS record /
hostname helpers. `pkg/dhcpserver` is now a *caller* of this spine.

This extraction is the foundation the #2691 world-class redesign (ScopeKey,
per-RG HA gate, source binding, router/interface-address publish, HTTP provider
backends) builds on in phases P1b–P3. P1a changes **no behavior** — every test
moved with its assertions intact.

## What lives here

| File | Contents |
|------|----------|
| `manager.go` | `Manager` (the DDNS reconcile engine — moved from `dhcpserver/ddns.go`): `policyFromConfig`, `Reconcile`, `reconcileOnceLocked`, `upsertLocked`/`deleteOwnedLocked`, `withdrawAllLocked`, `ownerWatermark`, `dhcidSharedWithOther` (#2700 shared-DHCID guard), `wireRRSharedWithOther` (#5709 co-owned wire-RR claim guard), `Stats` (incl. `PTRPendingNow`, #2708), `OwnedRecordView(s)`, the `errDDNSNoBackendToWithdraw` keep-ownership sentinel (#2699), the write-ahead durability + never-delete-non-owned boundary. Also the `Lease` record + `LeaseParser` seam. |
| `state.go` | Ownership state store (`ownedRecord`, `ddnsState`, `loadDDNSState`, durable `save` via `fsatomic.WriteFileDurable`) — moved from `dhcpserver/ddns_state.go`. Also the fail-closed load classifiers `errDDNSStateCorrupt` / `errDDNSStateUnsupportedVersion` + `quarantineBadState` (#2650) + the durable `<path>.degraded` marker helpers `readDegradedMarker` / `writeDegradedMarker` (#4873) that keep the fail-closed posture across restart. The load is SIZE-BOUNDED via `readBoundedStateFile` (`os.Stat` pre-check + `io.LimitReader` sentinel) against the derived `maxDDNSStateBytes` cap; an over-bound file is classified `errDDNSStateTooLarge` (wraps `errDDNSStateCorrupt`) so it fails closed like a corrupt file (#5571, CWE-770). |
| `backend.go` | `DNSUpdater` interface, `LeaseDNSRecord`, `nopUpdater`, the record + reverse-PTR-name helpers — moved from `dhcpserver/ddns_dns.go`. |
| `backend_rfc2136.go` | The LIVE RFC 2136 backend (`rfc2136Updater`): exact-RR adds/deletes, TSIG, RFC 4701 DHCID + RFC 4703 replace-owned two-attempt, the `errDDNSConflictRefused` / `errDDNSPTRPending` sentinels — moved from `dhcpserver/ddns_rfc2136.go`. `sendRemoveForward(..., keepDHCID)` keeps a shared DHCID on a partial dual-stack teardown (#2700); `dnsCanonicalFQDN` mirrors the DHCID FQDN canonicalization. |
| `hostname.go` | Deterministic hostname → DNS-label normalization (pure) — moved from `dhcpserver/ddns_hostname.go`. |
| `surface_a.go` | Surface A router/interface-address publish engine (`SurfaceAManager`): change-detection, forced-refresh wire floor, the `ForceRefresh()` operator force-now latch (#3276), per-scope error backoff, per-RG HA gate, the backend factory `productionSurfaceABackend` (#2691 P2/P3). **Operator-hostname intent (#2779):** the publish path (`surfaceAName` → `sanitizeFQDN`) lower-cases + strips non-LDH characters + drops empty-sanitizing labels. For a *router-owned* Surface A record the hostname is operator intent (the operator types the exact public name), so a name that sanitization would STRUCTURALLY change is now a **commit error** (`config.ValidateDDNSHostname` on the typed `interfaces … dynamic-dns hostname` leaf) instead of a silent rewrite to a different DNS name — e.g. `wan_1.example.net` is rejected at commit rather than published as `wan1.example.net`. Case-folding and a single trailing dot are accepted (benign DNS canonicalizations). Every name that PASSES the commit check is a fixed point of `sanitizeFQDN` (cross-package contract test `surface_a_hostname_2779_test.go`), so the published name equals operator intent. |
| `backend_http.go` | Shared HTTP-backend discipline (#2691 P3): hardened `http.Client` (TLS-verified, bounded timeout), capped body read, `classifyHTTPStatus`, `queryEscape`, the `errHTTPAuth`/`errHTTPRateLimited` verdicts, and **`scrubURLError` — the single renderer for any ERROR VALUE that may carry a request URL** (a deliberately narrower claim than it used to make: provider RESPONSE TEXT is a separate class this does not cover — Cloudflare `Errors[].Message`, Route 53 `Code`/`Message`, and the dyndns2/DuckDNS unrecognized-response lines are rendered verbatim from the body, pre-existing and tracked separately) (#6545): it emits at most `scheme://host[:port]` and withholds a URL that does not parse entirely. The allowlist is over the CHARACTERS, not only the `url.URL` fields: `Host` is **not** credential-free (an IPv6 zone id, a reg-name label, decoded non-ASCII bytes and the port are all places a `%p`-expanded password or a provider `Location` can land), so `safeHostText`/`safeScheme` rebuild it from a closed grammar — IP literals re-rendered from `netip` with the zone dropped, reg-names restricted to `[A-Za-z0-9._-]` labels, port 1..65535, scheme `http`/`https`. `scrubInnerError` renders **only what this package declares**: `classifyTransportError` returns the closed `transportReason` type and every return names a declared constant (proven by `TestClassifyTransportErrorReturnsOnlyConstants`, which resolves each with `go/types`), and the one error whose text is rendered — `*redirectRefusal` — is found by **type assertion**, not `errors.Is`, because `errors.Is`/`As` dispatch to methods a caller-supplied error defines. `safeOp` bounds `url.Error.Op` for the same reason. Every build-request and transport error in the package routes through it; `TestDDNSURLErrorRendersGoThroughScrubber` fails any new site that does not, and `TestClientDoHasExactlyOneCallSite` denies the wrapper-helper move that would hide one from the walk. **Source binding (#2846):** `newHTTPClientBound(bindConfig)` installs the SAME `backend_bind.go` source/interface/VRF `Dialer` (via `Transport.DialContext`) so the HTTP backends + checkip egress from the operator-configured `source-address` / `destination-interface` / `routing-instance` — not the kernel default route. `newHTTPClient()` is the no-bind alias (unbound default, behaviour unchanged). `resolveProviderBindConfig`/`newProviderHTTPClient` adapt a `config.DDNSProvider`'s leaves onto `resolveBindConfig`; a malformed `source-address` is a hard error so the backend constructor degrades to no-op (fail-open, mirrors rfc2136). **Redirect policy (#4861, #6545):** `guardRedirect` is the single `CheckRedirect` every DDNS HTTP client carries. It refuses a scheme downgrade (HTTPS→HTTP) AND any cross-host hop, strips `Referer` from every redirect it does follow, and re-implements the 10-hop cap that setting `CheckRedirect` removes. The cross-host half closes a real credential disclosure: Go's `refererForURL` puts the FULL previous URL — query string included — in `Referer` on an HTTPS→HTTPS hop (the DuckDNS/`generic`/`checkip-url` token), and `shouldCopyHeaderOnRedirect` forwards `Authorization`/`Cookie` to any SUBDOMAIN of the original host (the dyndns2/`generic` Basic credential, the Cloudflare bearer token). Same-host redirects still work. See “Redirect policy” below. |
| `backend_dyndns2.go` | dyndns2 backend (#2691 P3): one impl behind many provider names (`dyndns2Endpoints`), `good`/`nochg`/`badauth`/`abuse`/`911`/`nohost` verdict parsing. |
| `backend_cloudflare.go` | Cloudflare API backend (#2691 P3): Bearer token, zone-id resolve → list → PATCH/POST/DELETE record. **Upsert is value-specific (#3739 H11):** `UpsertLease` lists EVERY A/AAAA at the name and touches ONLY xpf's own row — a row already carrying the new value is a no-op, else the row carrying xpf's PREVIOUS value (`rec.PrevAddr`) is PATCHed in place, else a new record is POSTed. It NEVER PATCHes `recs[0]` (an API-ordering artifact), so a co-resident FOREIGN A/AAAA a human set on the same name is never rewritten to xpf's address. **Withdraw is content-scoped (#2770):** `DeleteLease` lists EVERY record for the FQDN+type and deletes only the rows whose `content` equals the owned address (`rec.Addr.Unmap().String()`), removing ALL such duplicates. It never deletes a row with a different value (a human/automation changed it after xpf published — an ownership conflict that is a success no-op), honouring the Surface A sole-delete-authority boundary that RFC 2136 also enforces (Route 53 now preserves co-resident foreign members via a read-modify-write — #5389, see the P2 note). `recs[0]` is an API-ordering artifact, not ownership. **Record listing paginates (#4909):** `listRecords` walks every page of the dns_records list (driven by `result_info.total_pages`, with a short-page fallback and a 1000-page runaway cap), so an xpf-owned row past the first 100-row page is never hidden — the pre-fix single unpaginated GET could drive a duplicate create (owned row unseen) or a false "already absent" delete. **Hitting the page cap is a hard error (#6218 item 5):** the pre-fix cap hit logged a Warn and returned the partial set with a nil error, so `UpsertLease`/`DeleteLease` could act on a possibly-truncated list — the exact #4909 hazard this function exists to close. `listRecords` now returns a non-nil error instead; both callers already propagate it and skip the write for that reconcile pass rather than acting on incomplete data. |
| `backend_dyndns2.go` | dyndns2 backend (#2691 P3): one impl behind many provider names (`dyndns2Endpoints`), `good`/`nochg`/`badauth`/`abuse`/`911`/`nohost` verdict parsing. **Withdraw (#2772):** `DeleteLease` issues the same update GET with `offline=YES` (the de-facto dyndns2 withdraw verb) and parses the body verdict; a provider failure returns a non-nil error so the engine keeps ownership for retry (was a silent no-op that orphaned the public record). **Dual-stack sibling guard (#3738):** `offline=YES` is HOSTNAME-level (both A and AAAA); when the engine sets `LeaseDNSRecord.SiblingFamilyOwned` (a sibling family is still published at this name/provider) `DeleteLease` SKIPS the offline so the live sibling is preserved (see "Dual-stack same-name withdraw" below). **DuckDNS is NOT here (#2960):** DuckDNS is not dyndns2-protocol-compatible, so it has its own `backend_duckdns.go`; `duckdns` was removed from `dyndns2Endpoints`. **Server validation (#3737):** `resolveDyndns2Endpoint` decides full-URL vs bare-host on the `://` delimiter, parses the URL with `url.Parse`, compares the scheme with `strings.EqualFold` (case-INSENSITIVE per RFC 3986 §3.1, so `HTTPS://host` is accepted — the old case-sensitive `HasPrefix` misclassified it as a bare host and produced a doubly-suffixed malformed URL), and requires a non-empty `Hostname()` in BOTH cases so a hostless value (`http://`, `https:///nic/update`, `:8080`) fails at construction (manager falls back to no-op) instead of only at the first publish. This is the SAME discipline as checkip's `validateCheckIPURL` (#2842) and generic's `validateGenericURLTemplate` (#2841). A malformed `server` is also warned at commit by `config.validateSurfaceADDNSWarnings` (mirror `ddnsDyndns2ServerValid`, RedactURL'd in the message). |
| `backend_duckdns.go` | DuckDNS backend (#2960): its OWN backend, not a dyndns2 alias. `UpsertLease` issues `GET /update?domains=<label>&token=<tok>&ip=<v4>` (or `&ipv6=<v6>` for AAAA) — the token is a QUERY param (the DuckDNS auth model), not HTTP Basic; the `domains` value is the bare subdomain label (`duckdnsDomain` strips a trailing dot + a `.duckdns.org` suffix). Success is the literal `OK` body (`KO` ⇒ hard auth/config error, `errHTTPAuth`); dyndns2's `good`/`nochg` is NOT a DuckDNS success. **Withdraw (#2960):** `DeleteLease` sends `&clear=true` (the DuckDNS clear verb, not dyndns2's `offline=YES`); DuckDNS clear has no per-family form — the spec says `clear=true` "will ignore all ip's and clear both your records", so it removes BOTH the A and the AAAA for the domain. The body verdict is parsed like an upsert, so a failed clear keeps ownership for retry. **Dual-stack sibling guard (#3738):** when the engine sets `LeaseDNSRecord.SiblingFamilyOwned` (a sibling family is still published at this name/provider) `DeleteLease` SKIPS the clear so the live sibling is preserved (see "Dual-stack same-name withdraw" below). The token comes from the `api-token` leaf (reused from cloudflare). The endpoint defaults to `https://www.duckdns.org/update` and is `server`-overridable for test/mocking. **One family per name (#2960):** the DuckDNS update API has no per-family verb — omitting `ip=`/`ipv6=` makes DuckDNS AUTO-DETECT and SET that family ("If you do not specify the IP address, then it will be detected", duckdns.org/spec.jsp), so a v6-only update overwrites the A. Surface A scopes are per-family with no per-FQDN coalescing, so a dual-stack DuckDNS name has two scopes that clobber each other's A/AAAA on every reconcile. The supported topology is therefore ONE family per DuckDNS name; binding the same DuckDNS name on both `inet` and `inet6` is flagged at commit by `config.validateSurfaceADDNSWarnings`. |
| `backend_cloudflare.go` | Cloudflare API backend (#2691 P3): Bearer token, zone-id resolve → find → PATCH/POST/DELETE record. |
| `backend_route53.go` | Route 53 backend (#2691 P3): SigV4-signed `ChangeResourceRecordSets` UPSERT/DELETE change batch. **Publish + withdraw are OWNERSHIP-SCOPED read-modify-writes (#5389):** Route 53 UPSERT/DELETE act on a WHOLE RRset at name+type, so `UpsertLease` first `ListResourceRecordSets`-reads the live members, `mergeUpsertValues` drops ONLY xpf's own prior value (`rec.PrevAddr`) and adds `rec.Addr` while PRESERVING every co-resident FOREIGN value, and UPSERTs the merged set (a live set already equal to the desired one is a no-op). `DeleteLease` reads the live set and removes ONLY xpf's own value: foreign members remaining ⇒ UPSERT the reduced set (live TTL); xpf's value being the sole member ⇒ DELETE the whole RRset (exact live-TTL match); xpf's value absent / set absent ⇒ idempotent no-op. A bare single-value UPSERT (pre-#5389) create-or-replaced the entire RRset and silently deleted a manually-managed round-robin member or another host's A/AAAA at a shared FQDN. **Concurrency caveat:** Route 53 has no compare-and-swap for `ChangeResourceRecordSets`, so the RMW is not atomic — a foreign member added between the List and the change is not seen; the Surface A per-RG HA gate makes xpf a single writer for the name (same residual window the Cloudflare/RFC 2136 value-specific fixes accept). |
| `sigv4.go` | Minimal self-contained AWS SigV4 signer for Route 53 (no AWS SDK dependency). |
| `backend_generic.go` | Generic templated backend (#2691 P3, inadyn "custom"): `%h/%i/%u/%p/%%` URL template + success-token matcher — config-only, no Go code per provider. **Success classification (#2838):** the 2xx body is matched by WHOLE TOKEN (`matchesGenericOK`), not raw `strings.Contains`. A default/`ok-response` token (`good`/`nochg`/`ok`/`true`/`updated`, case-insensitive) is a success only when it equals a trimmed response line or is the leading whitespace-delimited field of a line (so dyndns2-style `good <ip>` still passes). A configured multi-word `ok-response` (e.g. `good nochg`) is split into whole tokens on whitespace (#5557), so each word is matched independently exactly like the default set; storing it as one space-joined element could never match — the embedded space makes the leading-field path dead, so a dyndns2-shape `good nochg <ip>` body was wrongly classified as a failed update (error spam + backoff, DNS goes stale). A body that merely *contains* a token — `not ok`, `error: ok token invalid`, `update not good`, or an HTML page with an `OK` button — is a FAILURE; the old substring matcher turned those explicit provider errors into false successes, after which Surface A recorded ownership and suppressed retry, leaving DNS stale while the router believed the address was published. **Withdraw (#2772):** a single update template has no portable delete verb and xpf exposes no delete template, so `DeleteLease` FAILS (`errGenericDeleteUnsupported`) rather than silently reporting success; the engine keeps ownership so the abandoned record stays operator-visible (was a silent no-op that dropped ownership while the record kept resolving). **Template validation (#2841):** `newGenericBackend` validates the `url-template` with `validateGenericURLTemplate` — the SAME discipline as checkip's `validateCheckIPURL` (a case-INSENSITIVE http(s) scheme per RFC 3986 §3.1 + a non-empty host), so a host-less (`https:///upd`) or wrong-scheme (`ftp://`) template fails closed at construction instead of accepting the backend and only failing at the first publish (the old check was a bare `HasPrefix("http(s)://")` with no host parse). It is deliberately TEMPLATE-AWARE and string-based, NOT `net/url`-based (like `RedactURL`, #2781): it extracts the scheme + host portion and tolerates the inadyn `%h/%i/%u/%p` specifiers and `{{...}}` placeholders anywhere in the userinfo/path/query — a credential embedded in the userinfo (`https://user:%p@host/upd`) makes `url.Parse` fail on the bare `%p`, so it must NOT be validated with `url.Parse`. A typo is also warned at commit by `config.validateSurfaceADDNSWarnings` (mirror `ddnsGenericURLTemplateValid`, RedactURL'd in the message), matching the checkip-url warning. |
| `checkip.go` | Opt-in external check-IP address source (#2691 P3): bogus-IP validity gate + allowlist (`IsPublicAddr`, `parseCheckIPBody`, `CheckIP`, `ParseAllowlist`). **Source binding (#2846):** `NewCheckIPClient(provider)` builds the checkip probe's `http.Client` bound to the provider's `source-address`/`destination-interface`/`routing-instance` so the external "what is my IP" query egresses from the configured source, not the default route (the daemon passes this bound client into `CheckIP`). `CheckIP` fails closed on a malformed `checkip-url` via `validateCheckIPURL` (http(s) scheme + host); a typo is also warned at commit by `config.validateSurfaceADDNSWarnings` so it cannot masquerade as a permanent transient observation failure (#2773). **Public-address gate (#2774, exported #2776):** `IsPublicAddr` accepts only a globally-routable unicast address and rejects the full IANA Special-Purpose Address Registry so a hostile/misconfigured checkip endpoint cannot get a martian/reserved address published as the router's A/AAAA record. It is exported (#2776) so the daemon's Surface A static-address fallback (`staticUnitAddr`) reuses the SAME predicate instead of a weaker partial filter. stdlib `netip` predicates cover unspecified, loopback, link-local (uni + multicast), multicast (incl. interface-local), and the RFC-1918 private ranges (`IsPrivate`: 10/8, 172.16/12, 192.168/16). The `specialPurposeV4`/`specialPurposeV6` prefix tables add the rest: **IPv4** 0.0.0.0/8 (this-network), 100.64/10 (CGNAT), 192.0.0/24 (IETF protocol assignments), 192.0.2/24 + 198.51.100/24 + 203.0.113/24 (TEST-NET-1/2/3 documentation), 192.88.99/24 (6to4 relay anycast), 198.18/15 (benchmarking), 240/4 (reserved), 255.255.255.255/32 (limited broadcast); **IPv6** ::ffff:0:0/96 (IPv4-mapped), 64:ff9b::/96 + 64:ff9b:1::/48 (NAT64), 100::/64 (discard-only), 100:0:0:1::/64 (dummy prefix, RFC 9780 — distinct from 100::/64), 2001::/23 (IETF protocol assignments), 2001:db8::/32 + 3fff::/20 (documentation, RFC 3849/9637), 2002::/16 (6to4), 5f00::/16 (SRv6 SIDs, RFC 9602), fc00::/7 (ULA). |
| `checkip.go` | Opt-in external check-IP address source (#2691 P3): bogus-IP validity gate + allowlist (`IsPublicAddr`, `parseCheckIPBody`, `CheckIP`, `ParseAllowlist`). `CheckIP` fails closed on a malformed `checkip-url` via `validateCheckIPURL` (http(s) scheme + host; the scheme check is case-INSENSITIVE per RFC 3986 §3.1, so `HTTPS://host` is accepted — #2842); a typo is also warned at commit by `config.validateSurfaceADDNSWarnings` so it cannot masquerade as a permanent transient observation failure (#2773). **Public-address gate (#2774, exported #2776):** `IsPublicAddr` accepts only a globally-routable unicast address and rejects the full IANA Special-Purpose Address Registry so a hostile/misconfigured checkip endpoint cannot get a martian/reserved address published as the router's A/AAAA record. It is exported (#2776) so the daemon's Surface A static-address fallback (`staticUnitAddr`) reuses the SAME predicate instead of a weaker partial filter. stdlib `netip` predicates cover unspecified, loopback, link-local (uni + multicast), multicast (incl. interface-local), and the RFC-1918 private ranges (`IsPrivate`: 10/8, 172.16/12, 192.168/16). The `specialPurposeV4`/`specialPurposeV6` prefix tables add the rest: **IPv4** 0.0.0.0/8 (this-network), 100.64/10 (CGNAT), 192.0.0/24 (IETF protocol assignments), 192.0.2/24 + 198.51.100/24 + 203.0.113/24 (TEST-NET-1/2/3 documentation), 192.88.99/24 (6to4 relay anycast), 198.18/15 (benchmarking), 240/4 (reserved), 255.255.255.255/32 (limited broadcast); **IPv6** ::ffff:0:0/96 (IPv4-mapped), 64:ff9b::/96 + 64:ff9b:1::/48 (NAT64), 100::/64 (discard-only), 100:0:0:1::/64 (dummy prefix, RFC 9780 — distinct from 100::/64), 2001::/23 (IETF protocol assignments), 2001:db8::/32 + 3fff::/20 (documentation, RFC 3849/9637), 2002::/16 (6to4), 5f00::/16 (SRv6 SIDs, RFC 9602), fc00::/7 (ULA). |

Tests moved with the code: `manager_test.go` (engine + state-store + hostname),
`backend_rfc2136_test.go` (backend, drives a real in-process miekg/dns server),
`durability_test.go` (#2662 write-ahead), `manager_inc2_test.go`
(manager + live backend integration). P2/P3 add `surface_a_test.go`,
`surface_a_rfc2136_test.go`, `surface_a_http_test.go` (engine-through-real-HTTP-
backend), `backend_http_test.go`, `backend_cloudflare_test.go`,
`backend_route53_test.go`, `sigv4_test.go`, `checkip_test.go` — all
mock-server-driven through the real backend impls (no protocol-bypassing fakes).

## HTTP provider backends (#2691 P3)

The HTTP backends are siblings of the RFC 2136 backend behind the SAME
`DNSUpdater` interface, so the Surface A engine drives them identically — only
the wire mechanism differs. `productionSurfaceABackend` (surface_a.go) is the
single resolution point keyed on `DDNSProvider.Backend`:

| backend | mechanism | required config | credential (config.Secret) |
|---|---|---|---|
| `dyndns2` | `GET /nic/update?hostname=&myip=` + Basic auth; body verdict | `server` or a known provider name | `password` |
| `duckdns` | `GET /update?domains=&token=&ip=`/`&ipv6=`; token is a QUERY param (not Basic); body verdict on the literal `OK`/`KO` | `api-token` (`server` optional, defaults to `https://www.duckdns.org/update`) | `api-token` |
| `cloudflare` | Bearer token; zone-id resolve → PATCH/POST DNS record | `api-token`, `zone` | `api-token` |
| `route53` | SigV4 `ChangeResourceRecordSets` UPSERT | `aws-access-key`, `aws-secret-key`, `hosted-zone-id` | `aws-secret-key` |
| `generic` | templated URL + success-token match (config-only) | `url-template` | `password` (optional) |

All credentials are `config.Secret` (revealed only at the transport boundary,
never logged); HTTP is HTTPS with system-trust cert+hostname verification, a
bounded request timeout, and a capped response body. The `generic` backend
additionally lets an operator embed a credential directly in the `url-template`
(userinfo `user:pass@host`, or a token in the query string via `%u`/`%p` or a
literal `?token=...`), and a `checkip-url` can carry an API key the same way —
neither is `config.Secret`-typed, so `DDNSProvider.String()`
(`pkg/config/types_system.go`, used by `%v`/`%s`/slog) runs `server`,
`url-template`, and `checkip-url` through `config.RedactURL`, which strips
userinfo and the entire query string while keeping the scheme/host/path for
diagnostics (#2781). A construction failure
(missing credential) degrades to the no-op backend (logged; the commit warning
already fired) — fail-open, matching the rfc2136 posture. Live-provider verify
is the deferred lab gate; the mock-server tests are the merge gate.

### Redirect policy — no downgrade, no cross-host (#4861, #6545)

Every HTTP DDNS client is built at ONE site (`newHTTPClientBound`) and every
request goes through ONE `Do()` (`doRequest`), so a single
`http.Client.CheckRedirect` — `guardRedirect` in `backend_http.go` — covers all
six request-building paths: `dyndns2`, `duckdns`, `cloudflare`, `route53`,
`generic`, and the `checkip-url` probe (which builds its own request rather than
going through a backend). The daemon never constructs its own client; it obtains
one from `SurfaceAManager.CheckIPClient`, so there is no bypass.

`guardRedirect` refuses a 30x Location that **downgrades the scheme**
(HTTPS→HTTP, #4861 — a credentialed update must never be walked onto a plaintext
connection) **or changes the host** (#6545), strips `Referer` from every redirect
it does follow, and re-implements the 10-hop cap that setting `CheckRedirect`
otherwise removes (same arithmetic as `net/http`'s `defaultCheckRedirect`: 10
requests total, the 10th redirect refused).

The cross-host half exists because the scheme guard alone left an HTTPS→HTTPS hop
to a different host wide open, and Go discloses real secrets across it:

- **`Referer` carries the full previous URL including the query string.**
  `net/http`'s `refererForURL` strips only the userinfo and suppresses the header
  only for HTTPS→HTTP; on an HTTPS→HTTPS hop the redirect target receives e.g.
  `https://www.duckdns.org/update?domains=h&token=<TOKEN>`. That is a live
  credential for `duckdns` (the token is a QUERY param, not Basic), for `generic`
  (a `%p`-expanded password or a literal `?token=` in `url-template`), and for a
  `checkip-url` carrying an API key. For every backend it also discloses the FQDN
  and the public address being published.
- **Go forwards `Authorization`/`Cookie` to any SUBDOMAIN of the original host**
  (`shouldCopyHeaderOnRedirect` → `isDomainOrSubdomain`), so a Location pointing
  at `sub.<configured-host>` hands over the dyndns2/generic Basic credential and
  the Cloudflare bearer token. Stripping `Referer` would not have closed this
  half — only refusing the hop does.

Refusing rather than sanitizing-and-following is deliberate. These are
machine-to-machine callers of an endpoint the operator PINNED (a built-in
provider constant, or a `server` / `url-template` / `checkip-url` leaf); there is
no discovery step that needs to land elsewhere, and following a Location to an
unconfigured host is itself the trust violation — it ships the update payload,
and on a 307/308 the whole request body (a Route 53 change batch), to a host the
operator never named. The realistic trigger is a mistyped or hostile `server`
leaf, and fail-closed is this package's posture everywhere else (bind error,
malformed `checkip-url`, unrecognized response body). A provider that genuinely
moves to a new host is served by pointing the leaf at the final host; the error
names the CONFIGURED endpoint and the refusal class — never the refused target,
which is provider-chosen — so the operator can do exactly that. **Same-host redirects — the
common real case, a path or API-version move — are still followed.**

#### The concrete break: an APEX `server` leaf (apex → `www`)

No SHIPPED default endpoint redirects at all — `www.duckdns.org/update`,
`api.cloudflare.com/client/v4`, `route53.amazonaws.com`,
`members.dyndns.org/v3/update`, `dynupdate.no-ip.com/nic/update`,
`api.dynu.com/nic/update`, `api.cp.easydns.com/dyn/generic.php` and
`updates.dnsomatic.com/nic/update` were each probed and return no `Location`.
The configuration that DOES break is an **apex host** the operator writes by
hand, because the bare-host forms resolve to the apex over HTTPS
(`backend_duckdns.go` → `https://<host>/update`, `resolveDyndns2Endpoint` →
`https://<host>/nic/update`) and the apex 301s to `www`:

```
set … dynamic-dns provider duck server duckdns.org
  → https://duckdns.org/update   301 → https://www.duckdns.org/update   REFUSED
```

Same shape for `cloudflare.com` → `www.cloudflare.com` and `amazonaws.com` →
`aws.amazon.com`. The failure is loud and the error names the configured
endpoint (never the provider-supplied target). **The fix
is to configure the FINAL host** — `server www.duckdns.org` — not the apex.
There is no commit-time check for this: detecting it requires a network call.

**Do NOT "fix" this by allowing same-registrable-domain redirects.** `www.<host>`
IS a subdomain of `<host>`, and a subdomain hop is exactly where Go forwards
`Authorization`/`Cookie` (the second vector above). Relaxing the guard to make
`duckdns.org` → `www.duckdns.org` work would re-open the dyndns2/generic Basic
credential and the Cloudflare bearer token to any host that can answer for a
subdomain of the configured name. The ergonomic goal and the security goal are in
direct conflict here; refusing is the resolution, and documentation is the only
available lever.

Host comparison is by HOSTNAME only: case-insensitive (RFC 4343), one trailing
root dot normalized away, and deliberately PORT-INDEPENDENT. The trust anchor is
the DNS name and the TLS certificate identity bound to it — what the operator
configured and what cert verification pins — so a port move stays inside that
identity, while a port-strict rule would falsely refuse the plain
`https://prov.example:443/x` → `https://prov.example/x` default-port
normalization. A Unicode (non-punycode) Location host compares unequal to its
A-label spelling and is refused; that is the conservative direction (a false
refusal, never a false allow) and no in-tree provider uses an IDN host.

Fail-on-revert coverage is `redirect_crosshost_6545_test.go`, which drives two
TLS servers on real DNS names through the production client and asserts on what
the SECOND server actually received. Both vectors get an end-to-end test AND a
mutation-sensitivity control that drives the identical harness under the
pre-#6545 scheme-only policy and asserts the credential DOES arrive:

| vector | credential carrier | end-to-end gate | mutation control |
|---|---|---|---|
| cross-host `Referer` | DuckDNS token in the QUERY | `TestCrossHostRedirectDoesNotLeakCredential` | `TestCrossHostRedirectWouldLeakWithoutHostGuard` |
| subdomain header copy | dyndns2 Basic in `Authorization` | `TestSubdomainRedirectReceivesNothingWithGuard` | `TestSubdomainRedirectWouldLeakBasicAuthWithoutHostGuard` |

The subdomain pair drives a real apex → `sub.<apex>` hop — the apex→`www` shape
above in miniature — and the control decodes the Basic header to assert it
carries the CONFIGURED password, so the gate cannot pass for a reason unrelated
to the guard.

`checkip-url` failures are REPORTED, not silent. `CheckIP`/`CheckIPBound` return
`(addr, ok, err)`: a refused redirect, a malformed URL, an unreachable endpoint
or a non-2xx status come back with a stated reason, while the ordinary
dual-stack miss (endpoint answered, no address of the requested family) stays
`ok=false, err=nil`. The daemon logs the failure once per (provider, error)
— a `checkip-url` that redirects cross-host would otherwise be an
indistinguishable, permanent "transient observation failure" with no operator
signal at all, the class #2773/#3737 closed for the publish path.
`TestCheckIPNoAddressIsNotAnError` is the over-reach guard on that split.

**The reported reason is credential-free.** Making the failure operator-visible
also made it operator-LOGGED: the daemon writes the error as a `slog.Warn`
attribute AND retains its text as the `checkIPProbeWarned` dedup map key — so a
leak there is both journalled and resident in memory for the process lifetime. A
`checkip-url` routinely carries an API key in its query or userinfo. Three
distinct surfaces had to be closed, and the split between them is structural:

- **The `*url.Error` wrapper.** `(*url.Error).Error()` re-embeds the complete
  raw URL, query included, so the parse-failure branch must not `%w`-wrap it.
- **The inner parse cause.** Dropping the wrapper is *not* sufficient: several
  `net/url` causes embed input themselves, and two are UNBOUNDED —
  `invalid port %q after host` and `invalid host: ParseAddr("…")`.
  (`url.EscapeError` / `url.InvalidHostError` leak a bounded 3- and 1-byte
  fragment.) Switching on the error *type* cannot separate them: `fmt.Errorf`
  without `%w` yields `*errors.errorString`, the same type as the safe
  `errors.New` causes. `urlParseCause` therefore uses an exact-match allowlist
  of the fixed sentences plus class detection for the four input-bearing shapes,
  and **every return names one of the `cause*` constants** — that invariant, not
  the enumeration, is the safety property, and an unrecognised cause fails CLOSED
  to `malformed URL`. It is enforced two ways, because neither alone is enough.
  The return type is a closed `parseReason` enum, so a bare `return cause` does
  not COMPILE; and `TestURLParseCauseReturnsOnlyDeclaredConstants` walks
  `urlParseCause`'s AST asserting every return is a bare identifier that
  **resolves** to a package-scope `parseReason` constant, which also rejects the
  `parseReason(cause)` conversion form (that one compiles and vets clean) and
  covers branches no test input reaches. It **resolves, it does not name-match**
  (#6545 review round 6): the first version compared identifier NAMES against
  the declared set, and a local shadow —
  `causeMalformedURL := parseReason(cause); return causeMalformedURL` — compiled,
  vetted, and passed both gates while returning the raw parse cause. Names are
  not identity, so the gate now type-checks `checkip.go` with `go/types` (a
  deliberately non-resolving importer plus a swallowing `Config.Error` keeps it
  hermetic — no `go/packages`, no module graph) and requires the return to
  resolve to a `*types.Const` in the **package** scope whose constant VALUE is
  in the independent literal set below. It also refuses to descend into
  `ast.FuncLit`, so a closure's returns cannot satisfy the non-vacuity floor,
  and pins the function's result type as `parseReason`.
  `TestURLParseCauseAlwaysReturnsAConstant` remains as the VALUE check — it
  derives its allowed set from a literal list in the test file, never from a
  production variable, and feeds synthetic `*url.Error` values whose inner cause
  is no recognised `net/url` message. It is a coverage check by nature: a
  selective pass-through on an unexercised branch slips past it, which is exactly
  why the AST gate exists.
- **The URL display itself.** No refusal prints ANY part of the URL, from any
  branch. Redacting instead of omitting is not enough, because `config.RedactURL`
  is a best-effort string scrubber rather than a parser and has at least three
  holes a refusal walks into: a **missing `@`** defeats its userinfo scan
  entirely (`https://user:s3cr3t.example/` comes back unchanged); a
  **scheme-relative authority** (`//user:SECRET@host/`) has no `://` for the scan
  to anchor on, so it takes the authority to be empty and never finds the
  userinfo; and a **fragment** is never redacted at all
  (`ftp://host/#apikey=SECRET`). The last two **parse cleanly**, so a
  "redact only once `url.Parse` succeeded" gate does not help — that gate was an
  earlier iteration of this fix and it was wrong. Omitting costs nothing: the
  daemon carries `provider` as its own log attribute, the commit warning names
  the provider and leaf, and the operator is looking at the value they typed.
  (The general `RedactURL` weakness is tracked as #6609; this validator
  deliberately does not depend on it either way.)

**The TRANSPORT path needed the same treatment.** All of the above guards the
VALIDATOR — the paths that refuse a malformed `checkip-url`. A perfectly VALID
`checkip-url` is accepted and handed to `doRequest`, which renders a transport
failure through `scrubURLError`; that helper cleared `RawQuery` and `User` but
**not** `Fragment`, and `url.URL.Redacted()` renders the fragment. So
`https://checkip.example/p#apikey=SECRET` — a completely valid URL — put the
token in the journal and in the dedup key on every failed probe. Note this makes
**two** independent URL scrubbers in the tree that both dropped the query and
both kept the fragment — `config.RedactURL` has the same blind spot, tracked as
#6609; do not assume one is safe because the other is.

#### The whole class, not one field at a time (#6545 review round 6)

Fixing `Fragment` was still an instance fix, and the next review found the same
bug one field and three call sites over. Two MAJORs:

- **`Path` leaked.** The generic backend permits `%p` **anywhere** in its
  template, so the supported `https://prov.example/update/%p` put the expanded
  password in the transport error — journalled and retained as the
  `checkIPProbeWarned` dedup key. A `checkip-url` with an API key in its path had
  the identical exposure.
- **Four build-request paths never reached the scrubber at all.** DuckDNS,
  Cloudflare and both Route 53 request constructors `%w`-wrapped the raw
  `*url.Error`, whose `Error()` re-embeds the **complete** offending URL. All
  three take their endpoint from the `server` leaf **unparsed**, so a
  credentialed malformed value was rendered verbatim (dyndns2's `update()` had
  the same shape).

The fix is structural, not another field clear. `scrubURLError` is the
**single** renderer for any error that may carry a URL, and every build-request
and transport site routes through it. It allowlists at **two** levels:

- **Fields.** The safe URL is rebuilt, never copied, so
  `User`/`Path`/`RawPath`/`RawQuery`/`Fragment`/`RawFragment`/`Opaque`/`OmitHost`
  and anything `net/url` adds later are absent **by construction**.
- **Characters (round 7).** Field-level allowlisting alone was not enough: an
  allowlist is only as good as the safety of what it admits, and **`Host` is
  not credential-free**. `url.URL.Host` is a container for substituted template
  text, and Go 1.26 `net/url` will legally leave in it: an **IPv6 zone id**
  (RFC 6874 permits "basically any %-encoding", so the supported generic
  template `https://[fe80::1%25%p]/update` parses to
  `Host = "[fe80::1%<password>]"` — and `u.Hostname()` keeps the zone, it only
  strips the brackets); a **reg-name label** (`https://%p.example.com/`); **raw
  non-ASCII bytes** (`%FF` is decoded in place); and a **numeric port**. Any of
  those can also arrive from a provider `Location`. So `safeHostText` rebuilds
  the host from a **closed grammar**: an IP literal is re-rendered from `netip`
  with `WithZone("")` (the zone is dropped *structurally*, not trimmed), a
  reg-name must be dot-separated labels of ASCII letters/digits/`-`/`_` (≤63
  per label, ≤253 total, one optional root dot) or it is withheld entirely, and
  the port must be 1..65535. `safeScheme` reduces the scheme to `http`/`https`.
  Userinfo was never in this list — `url.Parse` splits `user:pass@host` into
  `u.User`, so an ordinary credentialed URL was already safe.

**The rendered error is now guaranteed to contain**, for the URL, at most: the
bounded operation word, then `http` or `https`, then `://`, then either a
zone-free IP literal or a `[A-Za-z0-9._-]` reg-name, then optionally `:` and 1–5
decimal digits — plus, where a whole component vanished, one of three fixed
notes (an out-of-range port is dropped silently, since the host is still fully
rendered). No `%`, no non-ASCII, no delimiter, no path/query/fragment/userinfo,
nothing of unbounded length. `url.Error.Op` is allowlisted too (`safeOp`): it is
caller-settable, and a forged `&url.Error{Op: req.URL.String(), URL:
"https://safe.example/"}` leaked the whole URL through the one field the rebuild
did not touch.

**And for the inner error**, exactly one of: a `transportReason` constant
declared in `backend_http.go`, or a `*redirectRefusal` rendered from fixed prose
plus `refusalHost`/`refusalScheme` output. No error's own `Error()` text and no
Go type name reach the output on any path.

Two residuals, stated rather than papered over. A password used as the **DNS
name** (`https://%p.example.com/`) is retained — it is already in every resolver
query and in the TLS SNI the endpoint sees, the renderer cannot tell a
legitimate label from a password without template-expansion taint, and
withholding every hostname would gut diagnosis. A **numeric** password used as a
valid **port** is likewise retained, as up to five decimal digits. Note the
asymmetry honestly, though: a log is durable and often more widely readable than
a packet capture, so "disclosed elsewhere" justifies these two specifically —
it is not a general licence.

Two further consequences:

- A URL that does **not** re-parse yields **no** URL at all, only the sanitized
  `urlParseCause` reason. The old verbatim `ue.URL` fallback was survivable only
  while the helper was reachable from the transport path alone; a build-request
  failure's defining input is a URL that does not parse.
- **`scrubInnerError` renders only what this package declares (round 8).**
  Round 7 made it "total" by asking, of each error, whether its **provenance**
  was known — and every way of asking that routes through something a
  caller-supplied error controls. `CheckIP` takes a caller-supplied
  `*http.Client`, so its RoundTripper's errors are arbitrary values, and Codex
  defeated the check four ways: `errors.Is` dispatches to the error's own
  `Is(error) bool`, so an error whose `Is` always returns `true` was accepted as
  one of our refusals and its `Error()` — the request URL — printed verbatim;
  `url.Error.Op` was never rebuilt; `syscall.Errno.Error()` is **not** a closed
  table (`syscall.Errno(65432)` renders `"errno 65432"`, so a numeric credential
  survived); and `%T` is **not** a compile-time symbol, because
  `reflect.StructOf` builds a runtime type whose name embeds an input-derived
  struct **tag**.

  The fix removes the ability to express the leak rather than checking for it.
  `classifyTransportError` returns the closed `transportReason` type and **every
  return names a declared constant** — errno is an allowlist of *values*, the
  `*net.OpError` branch selects a stage constant from `Op` alone, and the
  fallback is a bare constant with no type name.
  `TestClassifyTransportErrorReturnsOnlyConstants` proves it by **resolving**
  each returned identifier with `go/types`, the same discipline (and the same
  shadow-proofing) as the `urlParseCause` gate. Classes are still read
  *structurally* (`net.Error.Timeout`, `DNSError.IsNotFound`), never by message
  text — and forging one of those buys nothing, because every branch returns a
  constant.

  The one error whose text is rendered is `*redirectRefusal`, reached by **type
  assertion** over the unwrap chain, never `errors.Is`/`As`: an unexported
  concrete struct type cannot be named, constructed or impersonated from outside
  the package, and a type assertion has no user-defined hook. It stores the
  `*url.URL`s and applies the host/scheme grammar in `Error()`, so the bounding
  happens on the way out rather than being trusted to the construction site.
  Chain walks are depth-bounded (`maxUnwrapDepth`) because `Unwrap` is also the
  caller's method. `errors.Is`/`errors.As` dispatch to that `Unwrap`, so an
  error that unwraps to itself hangs them and an `Unwrap() []error` self-cycle
  overflows the stack; `errTreeWithinBound` walks the tree under a node budget
  before the first `errors.As` and withholds when it blows.
  **What that bounds, precisely:** the `Unwrap` tree as presented at entry. It
  does NOT bound a caller's other methods. A custom `As` can install a fresh
  subtree that was never prewalked, and an `Error()` that blocks or recurses
  hangs at the first render regardless of tree shape — neither is reachable
  without a caller-supplied hostile error, and no production caller supplies
  one, but the bound is not total and should not be read as such. The diagnostic cost — `net/http`'s internal prose, the failing
  address, the unknown-error type name — is accepted: an unrecognised error is
  exactly the case where we cannot say what it contains.
- **`guardRedirect`'s refusals name no provider-supplied host at all.** The
  grammar (`refusalHost`/`safeScheme`) bounds a host's character SET — zone ids,
  raw non-ASCII and anything that is not a plain reg-name are withheld — but it
  does not bound the CONTENT, and that was not enough. A provider answering
  `Location: https://<our-password>.evil.example/` gets the hop refused, yet
  `<password>.evil.example` is a well-formed reg-name, so naming it put the
  credential in the log. `scrubURLError`'s general justification — such a name is
  already in every resolver query and TLS ClientHello — does **not** transfer
  here: `CheckRedirect` aborts before any dial, so a refused target is never
  resolved and never sent anywhere.
  It also defeated deduplication, which is what forced the fix. The daemon keys a
  never-pruned, process-lifetime map on the rendered string to warn once per
  (provider, error), so a provider redirecting to per-request hostnames minted a
  fresh entry every 30s reconcile tick.
  So the refusal renders the refusal CLASS plus `via[0]` — the URL this package
  built from configuration — and describes the target only by class.
  `via[0]`, not the previous hop: same-host comparison is lenient about case, a
  trailing dot and the default port, so a provider could take an allowed hop to
  its own spelling (`Prov.example`) and have THAT rendered, which reintroduced
  the same per-request variability one hop out. The same-host **decision** still
  compares the raw values via `redirectHost`; only the rendering changed.

Gates in `url_render_class_6545_test.go`. The behavioural half pins
`scrubURLError` by **exact equality** rather than sentinel-probing — a field
that is neither dropped nor expected fails whether or not anyone thought to
plant a secret in it, which is exactly how `Path` survived three rounds — plus
end-to-end drives (`TestCheckIPTransportFailureRedactsPath`,
`TestGenericTransportFailureRedactsPasswordInPath`,
`TestGenericTransportFailureRedactsPasswordInHost` (the zone-id repro, driven
through the real template expander),
`TestScrubInnerErrorWithholdsURLFromArbitraryTransportError`,
`TestGuardRedirectRefusalBoundsProviderSuppliedHost`,
`TestScrubURLErrorWithholdsLocationHeaderEcho`,
`TestBackendBuildRequestErrorsWithholdCredentials` across all six backends).
`TestScrubInnerErrorResistsForgedProvenance` drives all four round-8 forgeries
through a caller-supplied RoundTripper — an error whose `Is` always says true,
a `url.Error` carrying the URL in `Op`, an out-of-table `syscall.Errno`, and a
`reflect.StructOf` type whose name embeds an input-derived struct tag.
`TestScrubInnerErrorKeepsRecognisedDiagnostics` is the over-reach floor for the
totality fix — withholding everything would pass every leak test and destroy the
package's diagnostics, so `connection refused`, the DNS/TLS classes and above all
the cross-host refusal must still come out; the exact-equality table likewise
carries IPv4/IPv6/underscore/root-dot/mixed-case rows so a legitimate host stays
identifiable.

The structural half, `TestDDNSURLErrorRendersGoThroughScrubber`, walks the AST
of every production file and fails any site that renders an error from
`http.NewRequest`/`url.Parse`/`client.Do` other than through
`scrubURLError`/`urlParseCause`. It is a **tripwire on the shapes this leak has
taken, not a proof** — round 6's version was walked with an aliased import, a
`do := client.Do` method value, a non-adjacent guard and an `errors.As`
extraction. Those four are closed (import-alias resolution; sites are now the
value's whole **reach** rather than one adjacent `if` body, cut at reassignment;
extraction taint), but an AST walk still cannot follow a value through a
helper's return. `TestClientDoHasExactlyOneCallSite` is what makes that limit
bite: it pins `.Do` to exactly one site (`doRequest`), so the wrapper-helper
move fails outright. The walk carries exactly one documented, **self-expiring**
exemption (`resolveDyndns2Endpoint`, the raw-`server` render tracked as #6606).
Round 7 fixed the self-expiry itself: it recorded the exemption as *hit* merely
because a handler existed in that function, so sanitizing the site left the
exemption standing and green — the opposite of expiring. The hit is now
conditional on the site still being **unsafe**, so fixing #6606 turns this red
and forces the stale entry out. Round 8 narrowed the exemption from
file+function to **file + function + producer + error variable**, and asserts it
covers exactly **one** site: a different unsafe handler moving into
`resolveDyndns2Endpoint` is no longer absorbed by an exemption written for
another one.

`scrubURLError` is still not used in the VALIDATOR paths, which render the cause
directly through `urlParseCause`: it is the same no-leak primitive either way,
and going through the scrubber there would only re-derive the cause from a
re-parse. The commit-time
mirror (`config.validateSurfaceADDNSWarnings`) applies the same parse-first
split. `TestValidateCheckIPURLRedactsCredentials`,
`TestValidateCheckIPURLOmitsUnparseableURL`, and
`TestCheckIPProbeWarnRedactsCredential` (which asserts on rendered log bytes and
on the dedup map keys) are the fail-on-revert gates;
`TestCheckIPValidURLStillAccepted` is the over-reach guard — a credentialed but
VALID `checkip-url` must still be accepted, since redacting before parsing would
refuse every keyed endpoint. Its userinfo cases are what make it a real guard
(`url.Parse` rejects `<redacted>@host` with "invalid userinfo"); a query-only
case would be vacuous, since `?<redacted>` parses fine as a raw query.

### Withdraw (DeleteLease) semantics per backend (#2772)

A withdraw is triggered when a Surface A scope shrinks, a binding is removed, or
the observed address is lost. `withdrawOwnedLocked` drops local ownership ONLY on
a nil-error `DeleteLease`; a non-nil error increments `deleteFail` and KEEPS the
ownership entry for retry. The HTTP backends therefore must never report a false
success for a withdraw they did not actually perform — doing so orphans the
public record while xpf believes it withdrawn (the #2772 bug, originally a no-op
that returned nil on both dyndns2 and generic).

**Withdraw shares the publish error-backoff (#2813).** Both withdraw paths — the
Pass-1 address-loss withdraw in `reconcileScopeLocked` and the Pass-2
gone-from-config withdraw in `Reconcile` — now arm the SAME per-scope flat
exponential backoff (`recordScopeError` → `surfaceAState.nextEligible`) the
publish path uses, via the shared `withdrawScopeLocked` helper. Before #2813 a
persistently-failing withdraw re-attempted (and emitted one `slog.Warn`) on
EVERY 30s reconcile sweep — ~2880 log lines/day/scope — because only publish
participated in the backoff machinery. Now a failing withdraw backs off (30s →
1h cap) and its retry/warn cadence collapses to the backoff schedule. A scope is
only ever a publish OR a withdraw candidate at one time (a gone-from-config scope
is absent from `desired` and never reaches Pass 1), so a SINGLE shared per-scope
backoff slot is correct — there is no separate withdraw-specific slot. A
transient withdraw failure is still retried after the backoff window and clears
the backoff state on success (the record is actually withdrawn — no leaked
ownership). A withdraw that returns `errGenericDeleteUnsupported` (the generic
backend has no portable delete verb) is treated as **terminal**: the wire delete
is attempted at most once, a single warn is emitted, and ownership is kept (the
abandoned RR stays operator-visible) — re-attempting a structurally-unsupported
verb on any cadence is pointless. The terminal mark clears on a successful
publish or a daemon restart (the runtime cache is rebuilt from the durable
store), so a later provider change that adds a delete verb is re-probed.

**A pending withdraw deletes BOTH crash-window candidates (#5334).** A crash-left
PENDING record (`PublishPending=true`, from a renumber A→B killed in the #5285
window) persists the byte-identical shape `{AddrText=B, PriorAddrText=A}` for TWO
different crash windows, and the pending bit cannot tell them apart:

- **Window 1** — crash BETWEEN the durable write-ahead save (`publishLocked`) and
  the wire add: B never reached the provider, so the CONFIRMED prior **A is still
  live**.
- **Window 2** — crash AFTER a SUCCESSFUL wire add but BEFORE the confirm-save
  clears the pending bit: `sendAddSelfOwned` (backend_rfc2136.go) atomically
  `Remove(A)`+`Insert(B)`, so **B is live** and A is gone.

If such a record is withdrawn — the binding is removed while the appliance is
down, then a restart's Pass-2 sweep tears the scope down — deleting EITHER single
value orphans the other window's live RR. So `withdrawOwnedLocked` (via
`withdrawTargets`) issues a value-specific exact-RR delete of **both** `AddrText`
AND `PriorAddrText` (deduplicated). This is safe because an exact-RR delete of a
value that is NOT live is BENIGN — rfc2136 `sendRemove` maps `NXRrset`/`NameError`
to success, and the host-granular backends (DuckDNS `clear=true`, dyndns2
`offline=YES`) ignore the rdata entirely while the existing `SiblingFamilyOwned`
suppression still guards a live sibling family (#3738). The both-delete therefore
removes whichever value the crash left live and no-ops the other, so the "delete
the actually-live value" invariant holds REGARDLESS of the window. The
**non-pending** path is unchanged (delete `AddrText` only), and a PENDING FIRST
publish (empty `PriorAddrText`) deletes its single candidate `AddrText` — the live
B in window 2, a benign no-op in window 1 — never a skip (skipping it would orphan
the window-2 live B, a strict regression). A per-candidate provider failure keeps
ownership so the next reconcile retries every candidate (an already-deleted one is
benign). Fail-on-revert: `surface_a_withdraw_pending_5334_test.go` (both a
single-`AddrText` revert and a prefer-`PriorAddrText`/skip revert go RED).

| backend | withdraw mechanism | per-family withdraw? |
|---|---|---|
| `dyndns2` | the same update GET with `offline=YES` (the de-facto dyndns2 withdraw — dyn/no-ip/dns-o-matic take the hostname offline). Body verdict parsed like an upsert; a provider failure → non-nil error → ownership kept for retry. | **No — HOST-level** (offline=YES takes down BOTH A and AAAA). |
| `duckdns` | the same update GET with `clear=true` (the DuckDNS clear verb, #2960 — NOT dyndns2's `offline=YES`). The DuckDNS spec is explicit that `clear=true` "will ignore all ip's and clear both your records", so it removes BOTH the A and the AAAA for the domain. `OK`/`KO` body verdict parsed like an upsert; a failed clear → non-nil error → ownership kept for retry. | **No — HOST-level** (`clear=true` clears both families). |
| `cloudflare` | real DELETE of the record (zone-id resolve → find → DELETE). | Yes — the exact A/AAAA RR. |
| `route53` | SigV4 `ChangeResourceRecordSets` DELETE change batch. | Yes — the exact A/AAAA RR. |
| `rfc2136` | exact-RR delete (TTL=0 / CLASS=NONE), DHCID-match guarded. | Yes — the exact A/AAAA RR. |
| `generic` | **no portable delete verb and no delete template → FAILS** (`errGenericDeleteUnsupported`). Ownership is kept so the abandoned record stays operator-visible; the operator clears it out of band (or uses a backend that supports a withdraw). | n/a (no withdraw). |

### Dual-stack same-name withdraw preserves the sibling family (#3738)

For a dual-stack scope — an A and an AAAA published at the SAME name through the
SAME provider — withdrawing ONE family must NOT take the sibling down. The two
HOST-level-withdraw backends above (`duckdns` `clear=true`, `dyndns2`
`offline=YES`) have no wire verb that touches only one family, so firing the verb
to withdraw the v6 record would blackhole the still-live v4 (or vice-versa) — a
sibling-family availability bug (codex-157 H10/M06).

The engine closes this with a factual flag on the withdraw record.
`withdrawOwnedLocked` scans the ownership store (`siblingFamilyOwnedLocked`) for
another owned record at the SAME `{PolicyID, FQDN}` under the OPPOSITE family and
sets `LeaseDNSRecord.SiblingFamilyOwned`. A host-level-withdraw backend that sees
this flag SKIPS its destructive verb (a logged no-op returning nil) — the LEAST-
DESTRUCTIVE action: the live sibling is preserved; the withdrawn family's record
is left in place (stale) rather than the sibling being taken down. Per-family
backends (`rfc2136`/`cloudflare`/`route53`) ignore the flag and delete only the
exact A/AAAA RR.

Because the manager still drops the withdrawn family's ownership, the flag is
FALSE on a later withdraw of the LAST family (no sibling remains), so the host-
wide verb DOES fire then and cleans the whole name — a full teardown converges
with no permanent orphan, and a single-family scope's withdraw is unchanged. The
lingering stale record only occurs in the PARTIAL dual-stack case, which is
already flagged at commit for both backends by
`config.validateSurfaceADDNSWarnings` (DuckDNS: the #2960 per-family UPDATE
clobber; dyndns2: the #3738 host-level withdraw). The supported topology is one
family per name, or a per-family backend for dual-stack same-name.

## The package boundary (why a `LeaseParser` seam)

The Kea-memfile lease parser (`parseActiveLeases`, `ddnsLease`, `identity4/6`,
the `keaLeaseType*` constants) **stays in `pkg/dhcpserver`** (`ddns_leases.go`):
it is entangled with the lease-sync memfile fallback (`lease_sync.go`,
#2239/#2262), which is DHCP-server-specific, not DDNS-specific. To keep
`pkg/dhcpserver`'s parser as the lease source **without an import cycle**, the
engine reads leases through an injected seam:

```go
type Lease struct { Family int; Address, Identity, SubnetID, HostName, ClientFQDN string; LeaseType int }
type LeaseParser func(path string, family int, now time.Time) ([]Lease, error)
```

`pkg/dhcpserver` supplies the parser (`keaLeaseParser`, which calls
`parseActiveLeases` and projects each `ddnsLease` onto `ddns.Lease`) when it
constructs the manager. The dependency is one-way: **`pkg/ddns` never imports
`pkg/dhcpserver`.** `pkg/ddns` imports only `pkg/config` (for the typed
`DHCPDynamicDNSConfig` the policy/backend factory consume) and `pkg/fsatomic`.

**Only address-bearing leases publish (`Lease.LeaseType`, #5072).** The v6
lease_type discriminator is carried through the seam so the reconciler can gate
by lease kind: `reconcileOnceLocked` runs an explicit address-lease ALLOWLIST
(`isAddressLease` — IA_NA / IA_TA only) BEFORE name/record derivation, so an
IA_PD delegated-prefix binding never has its prefix base (e.g.
`2001:db8:abcd::`) coerced into a host AAAA/PTR — publishing authoritative DNS
for a delegated network base is an info-disclosure / policy violation. The
`LeaseType` zero value is `LeaseTypeIANA` (an address lease), so a v4 lease and
a v6 lease with no lease_type column are treated as address-bearing; the
Kea-memfile adapter maps a present-but-unparseable / unknown column to
`LeaseTypeUnknown` so it is rejected fail-closed. Skipped leases increment
`Stats.SkippedNonAddress`. Before #5072 the adapter dropped lease_type and every
named lease (IA_PD included) was published.

## Cross-package surface (used via `pkg/dhcpserver` aliases)

`pkg/daemon`, `pkg/grpcapi`, `pkg/cli`, and `pkg/api` keep referring to these
through `dhcpserver.*` type aliases (`DDNSManager`, `DNSUpdater`,
`LeaseDNSRecord`, `DDNSStats`, `DDNSOwnedRecordView`) so the P1a move required
no change in those packages:

| `pkg/ddns` | `pkg/dhcpserver` alias / wrapper |
|---|---|
| `Manager` | `DDNSManager` |
| `DNSUpdater` | `DNSUpdater` |
| `LeaseDNSRecord` | `LeaseDNSRecord` |
| `Stats` | `DDNSStats` |
| `OwnedRecordView` | `DDNSOwnedRecordView` |
| `NewManager(parser, updater, nodeID)` | `NewDDNSManager(updater, nodeID)` (wires `keaLeaseParser`) |
| `NewProductionManager(parser, nodeID)` | `NewProductionDDNSManager(nodeID)` (wires `keaLeaseParser`) |
| `NewManagerForTesting(...)` | `NewDDNSManagerForTesting(...)` (wires `keaLeaseParser`) |

## Invariants preserved (do not weaken)

- **Never delete a record xpf did not create** — the state store is the sole
  delete authority; `deleteOwnedLocked` re-derives the exact tuple from owned
  state. Reinforced on the wire by the DHCID-match-guarded delete.
- **Write-ahead ownership durability (#2662)** — the ownership intent is
  persisted (`PTRPending=true`) BEFORE the wire add; a crash after the add finds
  the record owned. A refused add removes the phantom intent.
- **Sentinel ordering (#2676)** — `upsertLocked` checks `errDDNSPTRPending`
  BEFORE `errDDNSConflictRefused`, so a forward-published-but-PTR-failed record
  is never orphaned.
- **Mass-delete fail-safe** — a family whose `LeaseParser` errors is marked
  untrusted and its destructive diff is skipped.
- **No-backend withdraw keeps ownership (#2699)** — `deleteOwnedLocked` no
  longer drops the ownership entry when only the `nopUpdater` is wired. A record
  in the store was published by a real backend (the nop upsert path records no
  ownership), so forgetting it while the live RR persists would ORPHAN it (after
  a restart with DDNS disabled / no `update-server`, or a backend removal).
  Instead the no-op delete counts `deleteFail`, returns
  `errDDNSNoBackendToWithdraw`, and KEEPS ownership; a later reconcile with a
  live backend withdraws it for real. `reconcileOnceLocked` / `withdrawAllLocked`
  swallow the sentinel so a legitimate disabled-with-no-backend pass is not
  marked failed. Mirrors the Surface A `withdrawOwnedLocked` precedent.
- **Surface B backend/update-server change is a TRANSITION (#5814)** — the
  DHCP-lease reconciler used to define "settled" by DNS CONTENT alone
  (`recordsEqual`: FQDN/type/address/PTR/TTL), so changing the `update-server`
  (or the TSIG key/algorithm, or the source/interface/routing-instance transport
  bind) while the lease + record were otherwise unchanged marked every owned
  record settled: NO publish went to the new server and the OLD server's record
  was left live forever. The fix stamps a NON-SECRET endpoint fingerprint
  (`dhcpBackendFingerprint` — the Surface B analogue of `backendFingerprint`,
  excluding `TSIGSecret`) onto every owned record and folds a
  `backendChangedForOwned` check into the settled shortcut, so an endpoint change
  forces the delete-old-then-add-new transition. Crucially, the OLD-endpoint
  withdraw is routed through the PREVIOUS-cycle live backend for THAT family
  (`reconcileEnv.prevUpdater`, seeded from `Manager.lastLiveUpdater`), NOT the
  newly-resolved one — a delete sent to the new server would no-op and, on a
  "successful" no-op, would falsely drop ownership and orphan the old server's
  record. The anchor is PER FAMILY so a v4 endpoint change never routes v6
  cleanup through v4's backend (#2663 independence). The retained anchor is only
  trusted to withdraw a record when its IDENTITY proves it: a fingerprint kept in
  lockstep (`Manager.lastLiveFP` → `reconcileEnv.prevFP`) must equal the record's
  stored `BackendFingerprint`. This closes the POST-RESTART trap (the #5814
  review): after a restart the anchor is nil for one cycle (correctly orphaned),
  but the FIRST post-restart cycle RE-SEEDS it to the NEW endpoint, so a naive
  non-nil check would find a live anchor pointing at the WRONG server and misroute
  the old-endpoint record's delete through it — orphaning the old server's record,
  dropping ownership, and freezing the alarm at 1. With the identity gate a
  mismatched anchor is treated as unreachable. When the OLD endpoint is not
  reachable in-process (anchor nil OR identity mismatch), ownership is KEPT with
  the old fingerprint (never a wrong-endpoint delete, never a republish that would
  clobber the old cleanup key), `orphanedBackendChange` is counted EVERY cycle the
  mismatch persists (never frozen), and a loud `slog.Warn` + a `show services
  dynamic-dns` ALARM surface the cleanup-required state — mirroring the Surface A
  #3735 deferred-withdrawal posture. Fail-on-revert:
  `backend_change_5814_test.go` (in-process A→B, per-family, unreachable-orphan,
  and the post-restart re-seeded-anchor misroute).
- **Route 53 already-gone DELETE is idempotent (#2771)** — `backend_route53.go`
  `DeleteLease` treats a Route 53 DELETE of an already-absent record as success
  (nil), mirroring the rfc2136 backend's NXRRSET/NXDOMAIN handling
  (`sendRemove`). Since #5389 the withdraw first `ListResourceRecordSets`-reads
  the RRset: an absent set (or an RRset that no longer carries xpf's value) is an
  idempotent no-op WITHOUT issuing a change; the on-wire "not found" swallow below
  now guards the residual RACE where the record disappears between the List and
  the whole-RRSet DELETE. Route 53 reports an already-gone delete as HTTP 400
  `Code=InvalidChangeBatch` with a per-change message `... but it was not
  found`; `r53DeleteAlreadyGone` requires BOTH the `InvalidChangeBatch` code AND
  the "not found" marker, so a genuinely malformed/conflicting batch is NOT
  mistaken for a no-op. Without this, a withdraw against a manually-removed (or
  already-withdrawn-but-ack-lost) record returned non-nil forever; Surface A's
  `withdrawOwnedLocked` only drops ownership on a nil return, so the withdraw
  wedged and retried indefinitely while `show system services dynamic-dns`
  reported an owned record that no longer existed. Genuine
  transient/auth/throttle failures (`SignatureDoesNotMatch`, 5xx, 429, a
  non-"not found" `InvalidChangeBatch`) STILL return non-nil so the engine
  keeps retrying — only the already-gone case is swallowed.
- **Shared-DHCID partial dual-stack teardown (#2700)** — the RFC 4701 DHCID
  digest folds in `client-identity || FQDN` only (NOT the address), so a
  dual-stack client (an A + an AAAA under one FQDN, same client id) shares ONE
  DHCID. `deleteOwnedLocked` scans the store (`dhcidSharedWithOther`); when a
  sibling family still owns the same FQDN+ClientID it sets
  `LeaseDNSRecord.KeepForwardDHCID`, and `sendRemoveForward` then deletes only
  the A/AAAA and LEAVES the shared DHCID (the DHCID-match prerequisite is still
  sent, so the delete stays ownership-guarded). The DHCID is removed only with
  the LAST family's record, so a fully-released name leaves no orphan DHCID and
  a survivor is never left unprotected (no hijack window, no wire leak).
- **Unloadable ownership state fails CLOSED (#2650)** — a corrupt, unknown-
  future-version, or unreadable state file is NOT silently reset to an empty
  store. `loadDDNSState` returns the empty store plus a CLASSIFIED error
  (`errDDNSStateCorrupt` / `errDDNSStateUnsupportedVersion`); `loadStateOrDegrade`
  sets `Manager.degraded`, QUARANTINES a corrupt/unsupported file aside
  (`<path>.corrupt-<UTC-stamp>` — preserved, never overwritten by a later
  `save()`), and `ReconcileScoped` then refuses the WHOLE pass (no publish, no
  withdraw, counted as a reconcile failure) until the operator resolves it.
  `quarantineBadState`'s stamp is second-resolution, so a second quarantine
  event landing in the SAME wall-clock second as an earlier one probes for a
  same-stamp collision and appends a numeric suffix (`.corrupt-<stamp>.1`,
  `.2`, ...) rather than letting `os.Rename` silently clobber the first
  quarantine file (#6218 item 6) — the forensic copy of an EARLIER corruption
  is never destroyed by a LATER one. Fail OPEN would forget every owned record
  (permanent stale-record leak — the cleanup
  half of the feature is lost) AND let a later publish re-claim a name a PEER
  owns, since the lost DHCID/ownership state can no longer veto it. The degraded
  state is surfaced as a `show ... dynamic-dns` ALARM and the
  `xpf_dhcp_ddns_degraded` Prometheus gauge so the lost cleanup authority is
  never silent.
  - **Record SEMANTICS are validated on load, not just JSON/version (#4909).**
    `loadDDNSState` now rejects a valid-JSON, valid-version store whose record
    carries an unparseable textual address (`validOwnedRecordAddrs`): the
    published rdata is always an A/AAAA address, so a malformed one is a corrupt
    record the reconciler cannot turn into a correct wire delete. It fails closed
    exactly like a corrupt file (`errDDNSStateCorrupt`, empty store). Trusting it
    let `deleteOwnedLocked` silently drop the entry WITHOUT a wire delete and
    WITHOUT persisting, so the stale RR was uncleanable and oscillated across
    restart; that drop path now also persists (`state.save()`) as defense in
    depth so it can never re-oscillate.
  - **The load is SIZE-BOUNDED before any allocation (#5571, CWE-770).**
    `loadDDNSState` no longer `os.ReadFile`s the whole file before validating it.
    A very large canonical file — left by a prior crash, filesystem corruption,
    an administrative restore, or a future producer defect — would otherwise drive
    input-proportional heap growth / GC pressure / OOM during daemon STARTUP,
    exactly when the control plane must recover and BEFORE the fail-closed posture
    can engage. `readBoundedStateFile` opens and `os.Stat`s the file, rejecting an
    over-bound size before any read (so an arbitrarily large corrupt file costs one
    stat, not a full read), then reads through `io.LimitReader(f, maxDDNSStateBytes+1)`
    with a sentinel byte so a file that grew after the stat, or whose stat size is
    unreliable, still cannot be buffered past the cap. The cap is DERIVED, not a
    magic number: `maxDDNSStateBytes = maxDDNSStateRecords (65,536 — one full /16
    fully leased, far beyond any realistic deployment) * maxDDNSStateRecordBytes
    (2 KiB — a worst-case pretty-printed record with every optional field at its
    protocol maximum, ~33% headroom) + a small JSON envelope` ≈ 128 MiB. An
    over-bound file is classified `errDDNSStateTooLarge` (which WRAPS
    `errDDNSStateCorrupt`), so it engages the SAME quarantine + durable
    `.degraded` marker posture as an unparseable/bad-version file.
  - **The fail-closed posture is DURABLE across restart (#4873).** Quarantine
    renames the corrupt canonical file away, so a naive reload on the next boot
    would find no file, load an EMPTY store with a nil error, and NOT degrade —
    silently resuming publish/withdraw with all prior ownership forgotten (the
    fail-open the in-memory `degraded` flag alone cannot prevent, since it does
    not outlive the process). `loadStateOrDegrade` therefore writes a durable
    `<path>.degraded` marker (via `fsatomic.WriteFileDurable`) whenever it
    quarantines a corrupt/unsupported file, and honors that marker FIRST on every
    load: while the marker exists the manager stays degraded regardless of the
    canonical file's state. An operator resolves it EXPLICITLY by removing the
    marker (after inspecting/importing the quarantined `.corrupt-*` copy) — a bare
    restart no longer clears it. An unreadable (permission/IO, non-classified)
    file is NOT marker-persisted, because those bytes may be fine on retry.
- **Surface A ownership state fails CLOSED too (#2971)** — the Surface A
  (router/interface-address) `SurfaceAManager` previously BYPASSED the #2650
  wrapper: `NewSurfaceAManager` called `loadDDNSState` directly and, on any load
  error, logged a warning and proceeded with the returned EMPTY store — fail
  OPEN. An empty trusted store made every configured scope look unowned, so the
  next `Reconcile` re-published EVERY scope (a write storm) — overwriting a
  peer/manual owner (the lost ownership can no longer veto the re-claim) and
  forgetting the records it can no longer withdraw. `NewSurfaceAManager` (and the
  test constructor) now load through the SAME `loadStateOrDegrade` gate: a corrupt
  / unsupported-version / unreadable file sets `SurfaceAManager.degraded` (+
  quarantines a corrupt/unsupported file aside), and `Reconcile` then refuses the
  WHOLE pass (no publish, no withdraw, no `save()` — the bad file is preserved)
  until the operator resolves it. A MISSING file (first boot) is NOT degraded, so
  a fresh node — including a STANDALONE (nil-gate) node — still publishes
  normally; a restart after a corrupt file was quarantined stays degraded via the
  durable `.degraded` marker (#4873) until the operator removes it — it no longer
  re-reads an absent store and silently resumes publishing. The degraded state is surfaced as a
  `show services dynamic-dns` Surface A ALARM (CLI + gRPC) and the
  `xpf_ddns_surface_a_degraded` Prometheus gauge, and on `SurfaceAStats.Degraded`
  / `DegradedReason`.
- **No secret in any error string** (TSIG secret revealed only at construction).
- **Unsigned (no-TSIG) UPDATEs are warned, not silent (#4483)** — TSIG is the
  ONLY authenticator on this path. When `tsig-key` is unset the RFC 2136 UPDATE
  is sent unsigned (`exchange()` is UDP-first), and the publish/ownership
  verdict keys on `resp.Rcode` — an UNAUTHENTICATED, forgeable field. An on-path
  (or ID+port-guessing off-path) attacker can forge a `NOERROR` so the manager
  records a name as published though the server wrote nothing (silent
  blackhole), or forge a `REFUSED` to suppress a legitimate publish. The gap is
  fully closed by configuring `tsig-key`/`tsig-secret` (miekg then verifies the
  response MAC and rejects a forgery). Because a hard reject would brick a
  previously-inert config, the weakened posture is surfaced rather than
  forbidden: a COMMIT-time warning (`validateDDNSBackendWarnings` for DHCP DDNS,
  `validateSurfaceADDNSWarnings` for the Surface A provider catalog — both in
  `pkg/config/compiler_validate_warn.go`) whenever an `update-server` is set
  with no `tsig-key`, AND a once-per-update-server RUNTIME `slog.Warn`
  (`warnUnsignedOnce` in `backend_rfc2136.go`, deduped in the package-level
  `unsignedUpdateWarned` map so the per-cycle backend rebuild does not re-warn)
  the first time an unsigned UPDATE is actually sent. Forcing TCP or an explicit
  `no-tsig` opt-in acknowledgment are possible follow-ups; the warn is the
  minimum that makes the operator aware.

The HA writer gate (`ddnsWriterGateOpen`) stays in `pkg/daemon/daemon_ddns.go`
(it reads cluster RG state); P1a did not move or change it.

## Observability — PTR-pending (#2708)

A record can be HALF-PUBLISHED: the forward A/AAAA is live but the reverse PTR
add failed with a non-skippable error (`ownedRecord.PTRPending=true`, #2661).
This condition is surfaced per record and as a current gauge so an operator can
identify the broken record and watch it recover:

- `OwnedRecordView.PTRPending` — exposed on every owned record (CLI + gRPC
  `show ... dynamic-dns detail` print a `Pending` column).
- `Stats.PTRPendingNow` — the CURRENT count of records pending a PTR, distinct
  from the cumulative lifetime `PTRDeferred` (which only ever increases). It
  falls back to 0 once every PTR finally publishes.
- Prometheus `xpf_dhcp_ddns_ptr_pending` (gauge) — current pending count, beside
  the existing `xpf_dhcp_ddns_skipped_total{reason="ptr-deferred"}` lifetime
  counter.

## Phase P1b — ScopeKey, per-family policy, per-RG HA gate, source binding

P1b (closes **#2663, #2664, #2665**) builds on the P1a spine:

- **ScopeKey (`state.go`, #2663/#2664/#2903, plan §5.4)** — the unifying
  ownership primitive
  `{Family, Interface, Unit, RoutingInstance, RGOwner, PolicyID, FQDN}`.
  Ownership records are now keyed by `{ScopeKey, identity, address}`. The ZERO
  scope reproduces the pre-P1b `identity|address` key byte-for-byte (the `scope`
  JSON field is a `*ScopeKey`, omitted for the global lease scope), so a pre-P1b
  store loads with **no migration**. Two scopes for the same name+address (a v4
  vs v6 publish, or an RG0-owned vs RG1-owned publish) are DISTINCT entries.
  **FQDN axis (#2903)** — the published name is part of a *Surface A* scope's
  identity: `scopePrefix()` appends `/fqdn=<name>` only when FQDN is non-empty,
  so a DHCP-lease (Surface B) scope leaves FQDN empty and keeps its pre-#2903
  prefix byte-for-byte (no lease-store migration). Changing the configured
  hostname for a Surface A binding therefore yields a DIFFERENT scope key, which
  the reconciler treats as a rename — the OLD name is withdrawn by the
  gone-from-config sweep (Pass 2) and the NEW name is published — instead of an
  in-place name overwrite that published the new name but ORPHANED the old RR
  (the #2903 data-loss bug). The manager always folds `SurfaceAScope.FQDN` into
  the key via `effectiveKey()`, so the lookup, the stored Scope, and StatusViews
  agree regardless of whether the caller pre-populated `Key.FQDN`.
  **On-disk upgrade is blackhole-safe:** a pre-#2903 record sits under the
  FQDN-less prefix while the configured scope now keys under the FQDN-bearing
  prefix with the SAME name+address. Pass 1 (re)publishes under the new prefix;
  Pass 2 detects that the stale entry's `{FQDN, AddrText}` is still live (owned
  by a configured scope) and ADOPTS it — drops the stale ownership WITHOUT an
  exact-RR delete that would have removed the just-published live RR. A genuine
  rename changes the name, so its old `{FQDN, AddrText}` is NOT in the live set
  and the withdraw still fires.
- **Independent v4/v6 policy (#2663)** — `Reconcile` →
  `ReconcileScoped` resolves an INDEPENDENT policy + backend PER FAMILY
  (`reconcileEnv.pol[2]`/`updater[2]`) from `DHCPServerConfig.DynamicDNS` (v4)
  and `.DynamicDNSv6` (v6). A v4 conflict, a v4 backend error, or a v4 turn-off
  never affects v6. Single-block backward compat: if only one family's block is
  set, the other inherits it at reconcile time.
- **Per-RG HA writer gate (#2664)** — `ReconcileScoped` takes a
  `ScopeGate`/`ScopeResolver` (built in `pkg/daemon/daemon_ddns.go`
  `ddnsReconcileOptions`). The resolver attributes each lease to its owning RG
  by STABLE pool-subnet CIDR membership (not the per-render-unstable Kea
  subnet_id); the gate admits a scope IFF this node is MASTER for its RG. A
  gated-out scope is **stop-writing, never-withdraw**: its owned records are left
  untouched (the peer MASTER for that RG refreshes them — a withdraw would
  blackhole, plan §5.6). Pass 1 protects an owned record by re-consulting the
  SAME gate on the record's STORED scope (`env.scopeAdmits(owned.scopeOf())`),
  NOT only via the current-lease-derived `gatedScope` set — so a STEADY-STATE
  partial demotion, where the demoted RG's leases have aged out of the parsed
  set, still does not withdraw the demoted RG's records (#2664 review MAJOR;
  `TestPerRGGatePartialDemotionSteadyState`). Unattributable leases FAIL-CLOSED
  when RG-owned pools exist. Pool→RG attribution is sorted MOST-SPECIFIC-FIRST so
  overlapping cross-RG pools attribute deterministically across passes (the gate
  cannot flap). The daemon also nudges DDNS on a partial demotion
  (`clearRethServicesForRG`) so the gate change takes effect within one pass.
- **Wire-RR co-ownership claim accounting (#5709, codex-review-182 M36)** —
  ScopeKey makes two scopes' store rows DISTINCT, but on the wire two scopes can
  resolve the SAME host to the SAME address and thus publish ONE shared resource
  record (`h.example.com A 10.0.5.5`). Because `deleteOwnedLocked` reconstructs
  the wire RR from `{FQDN, ForwardType, Address}` alone, one scope's teardown
  (lease expiry / config removal) would issue a wire DELETE that removed the RR
  the OTHER scope still legitimately owns and refreshes — a silent cross-scope
  clobber. `deleteOwnedLocked` now first calls `wireRRSharedWithOther(owned)`: if
  ANOTHER store row (a different scope) carries the same canonical FQDN + forward
  type + rdata, the wire delete is SUPPRESSED, only the departing scope's
  ownership claim is released, and the live RR is left for the surviving scope.
  The equal `{FQDN, Address}` also implies an equal reverse PTR, so suppressing
  the whole `DeleteLease` covers both directions. Only the LAST claimant's
  teardown issues the real wire delete (a reference-count decrement over the
  claim table). Suppressions are counted (`Stats.DeleteCoowned`, the
  `xpf_dhcp_ddns_skipped_total{reason="coowned"}` metric) and covered by
  `TestCoOwnedWireRRSurvivesOtherScopeTeardown`.
- **Cross-surface co-ownership — the guard spans BOTH ownership surfaces
  (#5748)** — the #5709 guard originally scanned ONLY the lease store
  (Surface B, `Manager.state.records`, rdata in `Address`). Router / interface
  DDNS records live in the SEPARATE Surface A store (`SurfaceAManager`, rdata in
  `AddrText`), so a Surface A record and a Surface B lease that resolve the same
  host to the same address co-own ONE wire RR that neither surface's guard could
  see — a teardown on either surface could still clobber the identical RR the
  OTHER owns. Each surface now publishes a LOCK-FREE snapshot of its wire-RR
  claims (`Manager.WireRRClaims` / `SurfaceAManager.WireRRClaims`, backed by an
  `atomic.Pointer[[]WireRRClaim]` rebuilt under the manager's own mutex at the
  end of every non-degraded reconcile pass and after load). The daemon injects
  each surface's accessor into the other (`SetSurfaceACoownerSource` /
  `SetLeaseCoownerSource`, wired in `pkg/daemon/daemon_run.go`).
  `wireRRSharedWithOther` (lease side) and the per-target skip in
  `SurfaceAManager.withdrawOwnedLocked` (Surface A side) consult the peer's
  snapshot in addition to their own store, so a co-owned RR is preserved
  regardless of which surface owns the survivor. **Lock order / deadlock-free by
  construction:** the accessor is a bare atomic load — a teardown reads the peer
  snapshot WITHOUT taking the peer's mutex, so a guard holding its own manager's
  `mu` never blocks on the peer's `mu` (no AB-BA cycle). A nil accessor
  (standalone / pre-wire boot) restores the pre-#5748 single-surface behavior.
  Surface A deferrals are counted (`SurfaceAStats.DeleteCoowned`); both
  directions are fail-on-revert covered by `cross_surface_clobber_5748_test.go`.
  **Deterministic suppression tie-break (#6015, closes window (b)):** the
  cross-surface snapshot is rebuilt at the END of each reconcile pass, so
  cross-surface visibility is eventually- (not strongly-) consistent. Without a
  tie-break, if BOTH surfaces tore down the SAME co-owned RR in overlapping
  passes, each read the OTHER's pre-rebuild snapshot (still listing the RR
  owned) and each suppress-and-RELEASED → the RR was left on the wire UNOWNED
  (orphaned window (b)). The tie-break designates **Surface B (the lease
  `Manager`) as the SOLE SUPPRESSION AUTHORITY**: only Surface B may
  suppress-and-release a cross-surface co-owned RR (unchanged from #6012 —
  `deleteOwnedLocked` / `wireRRSharedWithOther`). **Surface A is the
  NON-AUTHORITY**: on a teardown of a co-owned RR it does NOT delete (that would
  clobber the lease-owned RR — the #6012 caution) and does NOT suppress-and-release
  (that is the window-(b) orphan). Instead it **DEFERS**: it RE-ASSERTS (re-UPSERTs)
  the RR so a leaked RR self-heals, and KEEPS its ownership claim, retrying the
  teardown on later passes. The real wire delete is deferred until the lease
  authority has RELEASED its co-ownership — a later pass finds `leaseWireRRCoowner`
  false for every target and deletes + releases normally
  (`SurfaceAManager.withdrawOwnedLocked`). Because Surface B always releases first
  and Surface A always defers-until-B-is-gone, exactly ONE surface ever deletes a
  cross-surface co-owned RR: mutual suppression can never orphan it (Surface A stays
  the deterministic last-claimant), and Surface A never clobbers a record Surface B
  still owns. `rebuildWireRRClaimsLocked` keeps advertising Surface A's deferred
  claim so the lease side continues to see the co-ownership. The remaining
  **window (a)** (a just-published co-owner not yet in the peer snapshot when the
  other surface tears down → a residual sub-millisecond clobber) is accepted as-is:
  it is operator-repairable via `request system dynamic-dns update` (the #5710
  force-update), and the #6015 Surface A re-assert self-heals it on the next
  deferred pass.
- **Source / VRF binding (#2665, `backend_bind.go`)** — the per-family
  `source-address` / `destination-interface` / `routing-instance` leaves build a
  custom `net.Dialer` (one `Control` hook: `unix.Bind` for the source IP +
  `SO_BINDTODEVICE` for the interface/VRF, working for both the UDP-first and
  TCP-retry exchange). Fail-open at runtime; an invalid source-address falls the
  family back to no-op.
- **Bind-device kernel-name resolution (#5070, `resolveBindConfig`)** —
  `SO_BINDTODEVICE` needs the EXACT current kernel device name, not the Junos
  config token. A `destination-interface` is a Junos interface reference (e.g.
  `reth0.50`, `ge-0/0/2.50`); it is resolved through the daemon's single source
  of truth for Junos→kernel naming, `config.(*Config).ResolveKernelIfName`
  (config/types.go), which the daemon threads in from the committed config —
  NOT the leaf `config.LinuxIfName` (bare slash-substitution). That matters
  because the leaf primitive produces FICTITIOUS devices for exactly the cases
  the HA-cluster WAN binding uses: a `reth` resolves to its LOCAL physical
  member (`reth1` → `ge-0-0-1`, there is no bonded `reth1` kernel device), a
  unit-`0` ref collapses (`ge-0/0/2.0` → `ge-0-0-2`), and a VLAN unit is named
  by its VLAN-ID not its unit number (`ge-0/0/2` unit 50 vlan-id 80 →
  `ge-0-0-2.80`). The resolver is threaded per-reconcile: the DHCP-lease path
  via `ReconcileOptions.InterfaceResolver`, the Surface A path via the trailing
  `SurfaceAManager.Reconcile` resolver arg (read by `resolveBackend` /
  `CheckIPClient`); both are `cfg.ResolveKernelIfName`. A `routing-instance` is
  realized as the kernel VRF master device `vrf-<name>` (pkg/routing), resolved
  through `diagcmd.VRFDeviceName` — the single source of truth for that prefix
  (applied exactly once, #2143; a name already typed `vrf-red` is returned
  unchanged). `routingInst` retains the raw name for informational use only.
  Before #5070 the raw token went straight to `SO_BINDTODEVICE`, targeting a
  nonexistent device so every RFC 2136 / HTTP-provider / check-IP exchange over
  the binding hard-failed at dial. The RFC 2136 constructor now also VALIDATES
  the resolved device exists via `bindConfig.validateDevice()` (an injectable
  `netlink.LinkByName` seam), surfacing a clear construction-time error (`bind
  device %q does not exist`) instead of a cryptic dial failure; a
  transiently-absent device is retried by the resolve-per-Reconcile loop. The
  HTTP-provider and checkip paths get the same deterministic resolution (they
  share `resolveBindConfig`). The per-binding HTTP client cache key stays the
  RAW binding leaves (`bindCacheKey`, #2956 reap consistency); only the bound
  socket's `SO_BINDTODEVICE` target is resolved.
- **Dual-stack source-bind family gate (#2901, `sourceMatchesDialFamily`)** — the
  dialer's `Control` hook applies the `unix.Bind` source-bind **only when the
  source-address family matches the dial socket's address family** (keyed off the
  `Dialer.Control` `network` argument: a `4`/`6` suffix on `tcp4`/`tcp6`/`udp4`/
  `udp6`). The dialer is shared by the RFC 2136 backend and, via
  `newHTTPClientBound` (#2846), every HTTP backend + checkip — those endpoints
  may resolve to both A and AAAA records, and Go's Happy-Eyeballs can dial the
  family that does NOT match the configured `source-address`. Binding a
  `SockaddrInet4` on an AF_INET6 socket (or the reverse) returns
  `EAFNOSUPPORT`/`EINVAL` and aborts the connection, so the gate keeps the bind to
  the matching family. `SO_BINDTODEVICE` is family-agnostic and is always applied.
  This is the DDNS analog of the IPsec family-selection work (#2757/#2832). The
  gate is now a SECONDARY guard behind the #5327 family pin (below).
- **Source-address dial-family pin (#5327, reviewed decision, `constrainDialNetwork`)**
  — a configured `source-address` is a multi-WAN / security egress control and MUST
  always be honored. #2901 originally made a cross-family Happy-Eyeballs dial
  proceed with the kernel-chosen source (SILENTLY skipping the bind) — but that let
  a DDNS update / checkip probe egress the WRONG WAN, BYPASS a source-IP ACL, and
  PUBLISH the wrong external address with no operator-visible error. #5327 closes
  that hole: **whenever a `source-address` is configured, the dial is PINNED to that
  source's address family** so Happy-Eyeballs can no longer pick the other family
  — `cl.Net` is set to `udp4`/`udp6` for the RFC 2136 `*dns.Client` (the TCP
  truncation retry inherits the pin), and the HTTP `Transport.DialContext` is
  wrapped (`boundDialContext` → `constrainDialNetwork`) to force `tcp4`/`tcp6`. With
  the pin in place the source bind ALWAYS applies. **Reviewed behaviour change:** an
  IPv4 `source-address` makes that provider effectively IPv4 for the dial (and vice
  versa). If the endpoint has NO address in the source family (e.g. an IPv4
  `source-address` but an IPv6-only endpoint) the pinned dial **FAILS CLOSED** — a
  clear "no suitable address" dial error the reconciler logs + retries — rather than
  egressing unbound on the wrong family. This deliberately overrides #2901's
  documented "proceed unbound on a family mismatch" behaviour: a source-address
  egress pin must never be silently abandoned. A device-only bind (no
  `source-address`) imposes NO family pin (SO_BINDTODEVICE is family-agnostic), so
  its dual-stack behaviour is byte-for-byte unchanged.
- **HTTP-transport + checkip source binding (#2846)** — originally only the RFC
  2136 backend honored the source binding; the HTTP backends
  (dyndns2/Cloudflare/Route53/generic) and the external checkip probe built a
  plain `newHTTPClient()` and left via the default route. #2846 wires the SAME
  `bindConfig.dialer()` into the HTTP client's `Transport.DialContext`
  (`newHTTPClientBound` in `backend_http.go`), so an HTTP DDNS update and a
  checkip query dial from the configured `source-address` /
  `destination-interface` / `routing-instance`. The provider catalog carries the
  binding leaves (`config.DDNSProvider`, #2780); `resolveProviderBindConfig`
  adapts them onto the same `resolveBindConfig` discipline. When no
  `source-address` is set the Transport gets no `DialContext` override — the
  default-route behaviour is byte-for-byte unchanged. A malformed `source-address`
  is a hard error: the backend constructor degrades to the no-op publisher and the
  publish is SKIPPED — it must NOT fall back to the unbound default and egress from
  the wrong source (fail-closed; the publish path via the cached client is #4437,
  the checkip probe is #3733's `CheckIPBound` gate — see the two bullets below).

- **HTTP client / connection-pool reuse across reconcile passes (#2904)** — the
  Surface A engine rebuilds the lightweight backend OBJECT every reconcile pass
  (resolve-per-Reconcile, #2691) — that is cheap — but each rebuild used to call
  `newProviderHTTPClient`, allocating a brand-new `http.Transport` with its own
  empty keep-alive pool. Every ~30s checkip probe and DNS update then paid a full
  TCP + TLS handshake from scratch (wasted CPU, added latency, ephemeral-port
  churn). The `SurfaceAManager` now owns an `httpClientCache` keyed on the
  provider's source-binding inputs ONLY (`source-address` /
  `destination-interface` / `routing-instance`, `bindCacheKey`); the manager-bound
  resolver (`resolveBackend`) and the checkip path (`CheckIPClient`) pull the
  cached `*http.Client` per binding and thread it into the backend constructors
  (`new{Dyndns2,Cloudflare,Route53,Generic}Backend(p, client)` — a nil client
  makes the constructor build its own, the pre-#2904 path used by direct/test
  callers). Two providers with the same binding share one transport (safe: a
  transport's pool is keyed on the destination host:port, so reuse only ever
  connects to the host a request targets; the client carries no credential/URL —
  those live on the backend object and apply per-request). The cache invalidates
  implicitly: a commit that changes a binding leaf resolves a NEW key and builds a
  fresh bound transport. Cardinality is bounded by the number of distinct
  configured bindings. Backed by the FAIL-ON-REVERT suite
  `surface_a_httpcache_2904_test.go` (same-binding reuse, cross-provider
  same-binding reuse, per-leaf invalidation, checkip↔update shared pool).
- **Cached-client source-bind fail-closed (#4437)** — `httpClientCache.clientFor`
  returns the UNBOUND default client ALONGSIDE the bind-resolution error for a
  malformed `source-address` (the error path is deliberately not cached so a
  corrected leaf on the next commit rebuilds cleanly). `resolveSurfaceABackend`
  used to swallow that error, log a warning, and thread the unbound client into
  the backend constructor — so a provider that configured a `source-address`
  silently published from the DEFAULT ROUTE (the wrong source / interface the
  operator explicitly overrode). The resolver now PROPAGATES the bind error: it
  resolves the source-bound client BEFORE building the backend, so on a bind error
  the constructor is never reached, `newSurfaceAHTTP` degrades to the no-op
  publisher, and the reconcile SKIPS the publish (never a withdraw — the record
  stays as it was on the wire, re-attempted next cycle once the leaf is corrected).
  This matches the nil-cache path (which already surfaced the same error from
  inside `newProviderHTTPClient`) and the checkip observer's #3733 `CheckIPBound`
  fail-closed gate: a publish with a configured `source-address` that cannot be
  honored is an error, not a silent use-default. Backed by the FAIL-ON-REVERT suite
  `surface_a_sourcebind_failclosed_4437_test.go` (cached bind error → no-op +
  uncached; no-source provider → live backend on the default client).
- **Superseded-transport reap (#2956)** — the stale entry left behind by a
  binding-leaf change (above) was never looked up again but also never released,
  and the `SurfaceAManager` lives for the whole daemon lifetime, so distinct
  historical binding tuples accumulated forever (the `*http.Transport` + its
  idle-connection pool retained until process exit, even though `IdleConnTimeout`
  reaps the sockets). Each `Reconcile` pass now calls `httpClientCache.reap` with
  the set of binding keys still referenced by the committed config — every
  configured scope's provider (the per-binding `source-address` override is
  applied on the scope's provider copy) AND every catalog provider (used by the
  removed-binding withdraw backend rebuild) plus the unbound default. Any cached
  client whose key is gone has its idle pool closed (`CloseIdleConnections`, via
  the `closeIdleConns` seam) and is dropped from the map; an active binding's key
  is always in the live set so it is never closed (only an ACTUAL key change is
  superseded). The reap takes the cache's own mutex (the manager's `m.mu` is the
  outer lock, so no lock-order inversion). Backed by the FAIL-ON-REVERT suite
  `surface_a_httpcache_reap_2956_test.go` (superseded-entry close+evict via the
  seam, all-live-bindings-kept, and a binding-churn integration test asserting the
  map stays bounded across N commits).

**HA correctness:** the per-RG gate change MUST pass `make test-failover` (the
project rule for any gate / HA-path change). P1b adds the gate + the
partial-demotion nudge; reason about split-brain (uncertain RG → fail-closed)
and partial demotion (lose one RG, keep another → publish only the kept RG,
withdraw nothing) in `scope_test.go` / `daemon_ddns_scope_test.go`.

## Phase P2 — Surface A (router/interface-address publish)

P2 (partial **#2679**) adds the SECOND publish surface — the firewall publishing
its OWN learned address — on top of the SAME spine, without forking the engine.

- **`SurfaceAManager` (`surface_a.go`)** — a separate manager from the
  DHCP-lease `Manager` (different ownership semantics: self-owned, no DHCID; and
  a different durable state file, `interface-ddns-state.json`), but it drives the
  SAME `DNSUpdater` interface, the SAME RFC 2136 backend (`newRFC2136Updater`),
  the SAME `ScopeKey` ownership primitive, the SAME source/VRF binding
  (`backend_bind.go`, via `DHCPDynamicDNSConfig` as the transport carrier), and
  the SAME write-ahead durability discipline.
- **Self-owned forward ADD = atomic VALUE-SPECIFIC in-place replace**
  (`rfc2136Updater.selfOwned` → `sendAddSelfOwned`). A router record has NO DHCID
  (the firewall IS the authoritative owner of its OWN configured FQDN). The lease
  path's two prerequisites — name-not-in-use (Attempt A) and DHCID-match (Attempt
  B) — both REFUSE a pre-existing name when there is no DHCID, which would pin a
  self-record at its first address forever (the #2691 P2 MAJOR-1 bug). So a
  self-owned forward add is a SINGLE RFC 2136 UPDATE that publishes the new rdata
  and, when the PREVIOUS published value is known (threaded via `LeaseDNSRecord.
  PrevAddr` from `publishLocked`, seeded across restart from the durable store's
  `AddrText`), pairs it with an EXACT-RR delete (RFC 2136 §2.5.4, CLASS=NONE) of
  ONLY xpf's OWN prior value. **#3739 (M08):** this replaced the old
  `RemoveRRset` (CLASS=ANY delete of the WHOLE A/AAAA set at the name), which
  destroyed a CO-RESIDENT FOREIGN A/AAAA a human/other appliance had set on the
  same name. The value-specific replace touches only xpf's own value, so a foreign
  record now SURVIVES. The server applies delete+insert atomically: a same-address
  forced-refresh is an idempotent `Insert`-only no-op (nothing to delete); an
  address change is `Remove(old)`+`Insert(new)` with NO withdraw-then-add
  blackhole gap; a first publish (or a lost prior value) is `Insert`-only
  (additive — coexists with any foreign RR rather than clobbering the name). It
  still never touches a DIFFERENT record TYPE at the name and never issues a
  delete-RRset/delete-name. (Third-party case: two firewalls pointed at the same
  self-record FQDN now COEXIST — each manages only its own value — rather than
  fighting; the per-RG HA gate prevents the in-cluster two-writer case.)
- **Per-provider co-resident behaviour on publish (#3739, #5389).** The
  value-specific publish above is implemented for ALL THREE self-owned-capable
  backends, each touching ONLY xpf's own value so a co-resident foreign A/AAAA at
  a shared name survives: **Cloudflare** (per-record-id `PATCH`/`POST`, #3739 H11),
  **RFC 2136** (exact-RR delete + insert, #3739 M08), and **Route 53**
  (read-modify-write, #5389 — was deferred as M07). Route 53's
  `ChangeResourceRecordSets` `UPSERT`/`DELETE` act on the ENTIRE RRSet at
  name+type (no per-value add/remove, no compare-and-swap), so both the publish
  and the withdraw first `ListResourceRecordSets`-read the live members and then
  change ONLY xpf's own value: **publish** = `mergeUpsertValues` drops
  `rec.PrevAddr` + adds `rec.Addr` while keeping every foreign member, then UPSERTs
  the merged set (a live set already equal to the desired one is a no-op);
  **withdraw** = strip `rec.Addr` from the live set, then UPSERT the reduced set if
  foreign members remain (live TTL) or DELETE the whole RRSet if xpf's value was the
  sole member. The DELETE path still fails SAFE and idempotent on an already-gone
  race (`r53DeleteAlreadyGone`, #2771). **Concurrency caveat:** the read-modify-write
  is not atomic (Route 53 has no CAS for change batches), so a foreign member
  written by a human/automation between the List and the change is not observed;
  the Surface A per-RG HA gate makes xpf itself a single writer for the name, so
  the residual race is the same single-writer window the Cloudflare/RFC 2136 fixes
  accept. The dedicated-name norm (a single, xpf-owned A) is unaffected.
- **Withdraw rebuilds the live backend** (the #2691 P2 MAJOR-2 fix). An
  address-loss withdraw (Pass 1) resolves the backend from the live
  `SurfaceAScope` (`backendFor`); a config-removal withdraw (Pass 2, where the
  binding — and thus the scope — is gone) REBUILDS the same backend the publish
  used by looking the owned record's provider (`scope.PolicyID`) up in the
  still-committed provider catalog passed into `Reconcile` (`backendForOwned` →
  `newBackend`). Production sets only `newBackend` (not the static `backend`
  field), so a withdraw that ignored `newBackend` would no-op and ORPHAN the RR —
  the bug this fixes. If the provider is also gone from the catalog the withdraw
  cannot reach the wire: it counts `deleteFail`, keeps ownership for retry, and
  surfaces an error (never a false `deleteOK`).
- **What the engine ADDS over the lease reconciler** (the inadyn ideas the
  DHCP-lease path does not need, plan §3.3/§5.5):
  - **change detection + last-published cache** — a wire UPDATE fires only when
    the observed address changed (or the forced-refresh floor elapsed). The
    cache is seeded from the durable store on restart (`seedFromStore`) so a
    restart does not blast a redundant update. **A FQDN change is also a change
    (#2903):** the published name is part of the scope identity (`effectiveKey`),
    so renaming the configured hostname (same IP) is a new, not-yet-owned scope —
    the `owned && !changed && !refreshDue` skip does not fire, the new name is
    published, and the old name's record (under the previous FQDN's scope key) is
    withdrawn by Pass 2 (publish-new + withdraw-old, never an orphaned old RR).
  - **durable desired-vs-confirmed crash recovery (#5285)** — the write-ahead
    ownership row now carries a durable `PublishPending` bit and a retained
    `PriorAddrText` (the last-CONFIRMED value), not just the desired address.
    `publishLocked` persists `{desired, PublishPending=true, prior=<last
    confirmed>}` BEFORE the provider I/O and CONFIRMS it (clears the pending bit,
    releases the prior value) with a second save AFTER a successful wire add. This
    closes the save→wire crash window that pre-#5285 mishandled: previously the
    DESIRED address was written into the SOLE ownership row with NO pending bit and
    NO retained prior, so a CRASH between `state.save(B)` and
    `providerIO(UpsertLease)` (the in-process rollback never runs on a crash) seeded
    B as BOTH `lastAddr` and successfully-published — on restart the `owned &&
    !changed && !refreshDue` skip suppressed recovery, public DNS stayed at the OLD
    value A while the appliance reported B, and A's value-specific cleanup key was
    destroyed. Now a PENDING record forces `refreshDue` in `reconcileScopeLocked`
    (`pendingRecovery`), so restart RE-RUNS the wire op for the desired value and
    threads the retained prior A as `PrevAddr` (the value-specific in-place replace
    of xpf's REAL live value — never the phantom desired). Mirrors the DHCP-lease
    `PTRPending` durable-pending idiom. **DISTINCT from #2662:** #2662 write-aheads
    the intent to close the *end-of-pass* orphan window (a live RR with no durable
    owner) but records the desired address as though confirmed; #5285 adds the
    desired-vs-confirmed distinction so a crash in that same window cannot be
    mistaken for a confirmed publish. The in-process rollback (a NON-crash wire
    failure restores the confirmed prior) is preserved — the durable pending bit is
    the crash-safe SUPERSET. Fail-on-revert:
    `surface_a_durable_pending_5285_test.go`.
  - **forced-refresh** — a per-scope wire-update FLOOR (default 24h) decoupled
    from the 30s reconcile cadence, to prove liveness / resist record reaping
    without per-poll traffic.
  - **operator force-now (`request system dynamic-dns update`, #3276)** — a
    one-shot `ForceRefresh()` latch makes the NEXT reconcile pass treat every
    configured scope as refresh-due, re-asserting the wire record even for an
    owned, unchanged address inside the forced-refresh floor. It is the engine
    half of the operator verb: the daemon (`ForceDDNSUpdate`) arms the latch and
    nudges an immediate pass. The latch is consumed by the first non-degraded
    pass (forces exactly one publish round, never a permanent re-assert storm)
    and a degraded pass does NOT consume it. The force does NOT bypass the per-RG
    HA writer gate — only the RG owner publishes (#2972); on a node that masters
    no RG (the backup) `ForceDDNSUpdate` is a no-op that returns a clear
    "not the active writer" message. `request system dynamic-dns check` is the
    no-force sibling: it only nudges a re-observe pass (publishes solely changed
    records). Both are wired cmdtree → gRPC `SystemAction("dynamic-dns-update" |
    "dynamic-dns-check")` → `Daemon.ForceDDNSUpdate` across the local + remote
    CLI. **The force spans BOTH surfaces (#5710 M37):** `ForceDDNSUpdate(true)`
    arms the same one-shot latch on the DHCP Surface-B engine (`Manager.
    ForceRefresh` in `manager.go`) as well as Surface A, so the DHCP-lease
    reconcile re-asserts an UNCHANGED owned record onto the wire instead of the
    routine change-detection skip swallowing it. Before #5710 the verb only
    *nudged* the DHCP loop (a re-observe that still short-circuited unchanged
    records), so an operator forcing an update to repair a drifted / manually-
    deleted DHCP RR got a no-op while the command reported success. The DHCP
    force honours the same per-RG HA writer gate (the unchanged-skip relaxation
    fires only for scopes already admitted into the desired set) and is one-shot
    (consumed by the next non-degraded pass). Fail-on-revert:
    `TestReconcileForceRepublishesUnchangedRecord` +
    `TestForceRefreshLatchArmsNextPass` in `manager_test.go`.
  - **flat error backoff** — on a transient failure a scope backs off
    (30s → cap, default 1h) so a failing provider is not hammered (ban-avoidance).
    The backoff window is tagged with the wire op that armed it (publish vs
    withdraw) and gates ONLY that op (#4423 M03): a PUBLISH-failure backoff must
    not delay a newly-observed address-LOSS withdraw (leaving the record live at a
    dead address is a blackhole), and a WITHDRAW-failure backoff must not delay
    re-publishing a recovered address. Observation now runs BEFORE the window is
    consulted (a cheap netlink/DHCP read, or a checkip GET against a different
    server than the DNS provider the backoff protects), so a definitive address
    loss is acted on promptly; each op re-arms its own backoff on failure, so a
    persistently-failing op still backs off (`TestSurfaceAPublishBackoffDoesNotDelayWithdraw`).
  - **replace, never withdraw-then-add, on address change** — a scope owns
    exactly ONE record (keyed `{scope, "router-self", ""}`); an address change is
    the atomic self-owned in-place replace described above (no blackhole gap).
- **Ownership key.** A router record is keyed on its SCOPE + the fixed identity
  `router-self` + Address `""` (the published address lives in the new
  `ownedRecord.AddrText` field, JSON-omitted for lease records). The scope now
  includes the published FQDN (#2903), so an interface unit/family owns at most
  one record PER configured hostname: an address change replaces that one record
  in place, while a hostname change is a rename (new scope published, old scope
  withdrawn) rather than an in-place overwrite that orphaned the old name.
- **Address observation** is the daemon's job (`pkg/daemon/daemon_ddns_surface_a.go`):
  `AddressObserver` reads netlink (interface source) or `pkg/dhcp.LeaseFor` (dhcp
  source). `ok=false` (transient read failure) → leave the scope untouched
  (never withdraw); a valid-but-Invalid `Addr` (interface down / lease gone) →
  withdraw. Keeping observation in the daemon keeps `pkg/ddns` free of
  netlink/DHCP deps, exactly like the `LeaseParser` seam for Surface B.
  **Transient link-read vs definitive-none (#2840):** `observeInterfaceAddr`
  carefully distinguishes a netlink READ FAILURE from a present-but-addressless
  interface. A `LinkByName`/`AddrList` ERROR (interface absent during a rename,
  reth/HA churn, a netlink hiccup) is TRANSIENT → it returns `(zero, false)` so
  the engine leaves the scope untouched and retries next pass. It does NOT fall
  back to the configured static on a read error — publishing a "configured"
  address that could not be confirmed "active" in the kernel data plane would
  point DNS at a possibly-stale address during a transient link outage. The
  netlink reads go through the `netlinkLinkByName`/`netlinkAddrList` seams so the
  transient-vs-definitive contract is unit-tested without a real kernel
  interface (`TestObserveInterfaceAddrTransientVsDefinitive`).
  **Static-address fallback is public-gated (#2776) and present-but-addressless
  only:** when the interface read SUCCEEDS but yields no usable dynamic address
  (the legitimate static-use case), `observeInterfaceAddr` falls back to the
  unit's configured static address via `staticUnitAddr`, which gates the
  candidate through the SAME `ddns.IsPublicAddr` predicate the netlink and
  checkip sources use (exported for this reuse, #2774). A mis-scoped static
  address (multicast, reserved, ULA, CGNAT, documentation, IANA
  special-purpose) is SKIPPED and surfaced at WARN rather than silently
  published as the router's A/AAAA record — the netlink and static paths no
  longer use divergent publishability predicates (the netlink path already
  rejected multicast; the fallback previously filtered only loopback/
  link-local-unicast/unspecified).
  **IPv6 address-lifetime-aware netlink selection (#2775):** the netlink
  selection (`selectInterfaceAddr`, the pure core of `observeInterfaceAddr`)
  now honors RFC 4862 address state instead of publishing the first
  non-link-local/loopback/multicast address. (1) It NEVER selects an address
  whose DAD has not succeeded — `IFA_F_TENTATIVE` (DAD in progress),
  `IFA_F_DADFAILED` (duplicate detected), or `IFA_F_OPTIMISTIC` (RFC 4429
  optimistic DAD, not yet DAD-confirmed) — publishing one risks a
  duplicate/black-holed answer. (2) It PREFERS an RFC 4862 `preferred` address
  over a `deprecated` one (`IFA_F_DEPRECATED`): a deprecated address is being
  phased out (renumber / PD churn / privacy-address rotation) and will soon be
  invalid, so publishing it black-holes inbound reachability. The first eligible
  preferred address wins; a deprecated address is used ONLY when no preferred
  address exists (never-blackhole — a still-valid deprecated address beats no
  answer). (3) Every candidate STILL passes `ddns.IsPublicAddr`, so a
  preferred-but-ULA (or otherwise reserved) address is rejected — the same gate
  as the static fallback (#2776) and the checkip source. (4) It NEVER selects an
  RFC 4941/8981 SLAAC privacy/temporary address (`IFA_F_TEMPORARY`, #2975): a
  temporary address is an outbound-only ephemeral identifier that rotates on a
  short timer, so publishing it leaks the privacy identifier into public DNS AND
  black-holes inbound reachability the moment it rotates (the record points at an
  address that no longer exists). `IFA_F_TEMPORARY` joins the
  tentative/dadfailed/optimistic skip mask, so the stable permanent address —
  which privacy extensions are designed to KEEP for inbound service — wins even
  when netlink lists a temporary address first. Note this skips ONLY
  `IFA_F_TEMPORARY`; `IFA_F_MANAGETEMPADDR` marks the *permanent* SLAAC address
  that spawns the temporaries and remains a valid publication target. The
  IFA_F_* flags are already parsed off the netlink `RTM_NEWADDR` message into
  `netlink.Addr.Flags` (no extra netlink plumbing was needed — they were simply
  ignored in selection before). A per-family `preferred-address` operator
  override for multi-address interfaces (the issue's secondary ask) remains a
  future refinement.
  **checkip source is fail-closed on a missing checkip-url (#4423 H08).** When a
  binding selects `address-source checkip`, `buildSurfaceAScopes` keeps the scope
  source as `checkip` even if the referenced provider carries NO `checkip-url` —
  it does NOT silently fall back to the interface address. The interface address
  is exactly what a behind-NAT / multi-WAN router must NOT publish (it is the
  private or wrong-WAN address, not the checkip-discovered public IP), so the
  old fallback published the WRONG address. With the source kept as `checkip`
  the observer's missing-url guard returns a TRANSIENT miss (`ok=false`): the
  scope is skipped (no publish, never a withdraw) and shows as `pending`. The
  daemon logs the condition once per provider, and `config.validateSurfaceADDNSWarnings`
  warns at commit (`TestSurfaceACheckIPNoURLDoesNotFallBackToInterface`,
  `TestSurfaceADDNSWarnsCheckIPSourceWithoutURL`).
  **DHCP no-lease: transient gap vs definitive loss (#4423 M10).** A missing DHCP
  lease is treated as a DEFINITIVE address loss (→ withdraw) ONLY when the unit is
  no longer DHCP-configured for the family. While the unit is still DHCP-configured
  (`unit.DHCP` / `unit.DHCPv6`), a missing lease is a TRANSIENT gap — bring-up,
  renewal, or the DHCP client RESTART that `dhcp.Manager.Reconcile` performs on any
  option change (it stops the client, removing the address + lease, then re-DORAs).
  Treating that as definitive withdrew the public record on every benign DHCP
  option change and re-published seconds later (a blackhole flap); it is now an
  `ok=false` transient (never-blackhole). Reading the committed config flag is
  race-free, unlike probing the live client registry which has a stop→start window
  (`TestSurfaceAObserverDHCPTransientGapNoWithdraw`).
  **Invalid bindings stay visible (#4423 M09).** A structurally-incomplete binding
  (no hostname / no provider / undefined provider) builds no reconcile scope, but
  `buildSurfaceAScopes` returns it as a synthesized `SurfaceAStateInvalid` status
  row (with the specific defect in `LastError`) so a broken binding is still shown
  in `show system services dynamic-dns` instead of vanishing — the commit warning
  was previously its only trace (`TestBuildSurfaceAScopesInvalidBindingsVisible`).
  **Deterministic ordering (#4423 M11/M12).** `buildSurfaceAScopes` sorts the scope
  slice by `{interface, unit, family, provider, FQDN}` so the reconcile order (and
  any behavior that depends on it, e.g. two scopes targeting the same FQDN) is
  reproducible rather than Go-map-iteration-random; `SortSurfaceAStatusViews`
  orders the operator status rows by a TOTAL key so the surface is byte-stable even
  when rows tie on `{FQDN, family}` (`TestBuildSurfaceAScopesDeterministicOrder`,
  `TestSortSurfaceAStatusViewsTotalOrder`).
- **HA gate** is the SAME per-RG `ScopeGate` (a router record on a reth/virtual
  interface publishes only on the RG master; stop-writing-never-withdraw
  otherwise). Standalone (nil gate) always publishes.
  **RG0/non-HA single-writer (#2972).** A scope on a non-HA interface attributes
  `RGOwner==0`. Unlike DHCP-lease DDNS — where each node's Kea memfile is
  rendered master-filtered per RG, so the two nodes' lease input sets are
  disjoint and an `RGOwner==0` lease is genuinely a non-HA pool with no peer —
  Surface A scopes are built directly from the active config + interface
  observer, so BOTH nodes build the IDENTICAL `RGOwner==0` scope. The node-level
  writer gate (`ddnsWriterGateOpen`) opens on ANY-RG mastership, so in
  active-active HA (node0 masters RG1, node1 masters RG2) BOTH nodes passed it
  AND — before this fix — `surfaceAGate` admitted every `RGOwner==0` scope
  unconditionally, double-writing the same configured FQDN (the public A/AAAA
  record flaps when the nodes observe different addresses). `surfaceAGate` (in
  `pkg/daemon/daemon_ddns_surface_a.go`) now ties `RGOwner==0` to RG0 — the
  control-plane redundancy group — via `surfaceARG0Writer`: exactly the
  RG0-primary node publishes the non-HA scopes, and the single writer follows
  RG0 failover. When RG0 is not a tracked group (a non-standard cluster with
  only data RGs, or the brief pre-first-election window), it falls back to a
  deterministic single writer — the lowest node ID — so the scope is never
  double-written. (`TestSurfaceAGateRG0SingleWriter`,
  `TestSurfaceAGateRG0FallbackNoRG0`.)
- **Lock discipline — I/O is NEVER performed under the manager mutex (#2778).**
  `SurfaceAManager.mu` guards ALL manager state (the durable ownership store, the
  per-scope runtime cache, the counters), but it is RELEASED across every
  provider network call (`UpsertLease`/`DeleteLease`, which run with a 15s HTTP
  client timeout). A slow or hung provider must NOT block `StatusViews`/`Stats`
  (operator `show` + Prometheus scrapes) or other scopes' reconcile work — that
  would freeze the control plane for up to 15s exactly while the subsystem is
  unhealthy. The pattern (`providerIO`): under the lock, the pass snapshots the
  exact intent (resolved backend + record) and durably write-aheads the
  ownership BEFORE the wire op (so a crash in the unlocked window still finds the
  record owned and converges next pass); it then RELEASES the lock for the wire
  call and RE-ACQUIRES it to commit the result. The commit is guarded by a
  racing-op re-validation (CAS): if a concurrent op changed the scope's owned
  record while the lock was released, the stale wire result does NOT clobber the
  newer truth — a stale publish-rollback is skipped (the newer ownership wins,
  signalled via `errSurfaceAPublishRaced` so the runtime cache is not advanced),
  and a stale withdraw drops ownership only if the live entry is STILL the exact
  record it deleted (a concurrent re-publish with a new address keeps its
  ownership, never orphaned). The single-flight guard in the daemon
  (`surfaceAReconcileInFlight`) means two full passes never run concurrently, but
  the CAS keeps the contract correct regardless. Proven in
  `surface_a_lockio_test.go` (a blocking provider + a concurrent `StatusViews`
  that would hang if the lock were held; fail-on-revert).
- **Operator surfaces:** `show services dynamic-dns [detail]` (CLI + gRPC), the
  `xpf_ddns_surface_a_*` Prometheus family, and
  `SurfaceAManager.StatusViews(scopes)` (per-scope `State` + published address +
  last-published time + last error).
- **Status surfaces EVERY configured scope, not just the owned ones (#2843).**
  `StatusViews` takes the CURRENTLY configured scopes (materialized by the daemon
  from the committed config) and returns the UNION of: a row per configured scope
  (merged with its ownership record + runtime state) AND any ownership record for
  a scope no longer configured (a withdraw is pending). Each row carries a
  `State`: `published` (owns a record), `unpublished` (the provider resolved to
  the no-op backend — `errSurfaceANoBackend`, a half-configured provider; the
  reason is in `LastError`, no backoff armed), `error` (the last publish attempt
  failed; reason + backoff armed), `pending` (configured, not yet owned, no
  recorded error — never attempted or waiting on an address observation / backoff
  window), or `withdraw-pending` (owned but no longer configured). Before #2843
  the status was built from ownership records ONLY, so a scope that failed before
  its first publish — most acutely a half-configured provider whose
  `errSurfaceANoBackend` was swallowed without `recordScopeError` — was INVISIBLE
  in `show ... detail`, the opposite of what an operator needs during bring-up.
  The no-backend state now records a per-scope reason on the runtime cache
  (without arming retry backoff) so the row reports it. Proven (fail-on-revert)
  in `surface_a_http_test.go` (`TestStatusViewsSurfacesUnpublishedScopes`,
  `TestStatusViewsSurfacesPendingAndPublished`).
- **Tests through the REAL backend.** The self-owned replace, forced-refresh,
  and both withdraw paths are proven in `surface_a_rfc2136_test.go` against the
  stateful in-process fake DNS server (the `backend_rfc2136_test.go` harness) with
  PRODUCTION wiring (`newBackend` set, static `backend` nil) — asserting the
  actual zone state + the actual wire DELETE. `fakeUpdater` (`surface_a_test.go`)
  is kept only for backend-agnostic engine cadence (publish-once, skip-unchanged,
  forced-refresh-fires, transient-no-withdraw, backoff, status), because it models
  neither RFC 2136 prerequisites nor the production `newBackend` wiring and so
  cannot catch the two MAJORs above.

P3 (the rest of #2679) adds the HTTP provider backends
(dyndns2/Cloudflare/Route53/generic-template) + the checkip address source;
`productionSurfaceABackend` already routes an unknown backend to the no-op
(logged) so a P3-only provider config does not wedge P2.
