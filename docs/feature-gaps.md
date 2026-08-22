# xpf vs Juniper vSRX Feature Gap Analysis

Last updated: 2026-05-24

> #1373 dataplane note: the Rust AF_XDP userspace dataplane is the
> primary/default target for new dataplane work. Rows that mention only eBPF
> describe legacy/regression coverage unless userspace is explicitly named.
> The authoritative retirement gate for userspace-vs-legacy behavior is
> [`userspace-dataplane-gaps.md`](userspace-dataplane-gaps.md).

> [!IMPORTANT]
> DPDK retired in #1525. References below to "eBPF and DPDK" or
> "eBPF, DPDK, and userspace" parity describe the pre-retirement
> state; the DPDK backend is removed in #1527/#1528.

## Summary

| Category | Fully Missing | Partially Implemented | Parse-Only | Total Gaps |
|----------|--------------|----------------------|------------|------------|
| Security Policies (Unified/Advanced) | 7 | 1 | 0 | 8 |
| Application Security (AppSecure) | 8 | 1 | 0 | 9 |
| IDP/IPS | 8 | 0 | 0 | 8 |
| Content Security (UTM) | 6 | 0 | 0 | 6 |
| SSL/TLS Inspection | 4 | 0 | 0 | 4 |
| Advanced Threat Prevention | 5 | 1 | 0 | 6 |
| User/Identity Firewall | 5 | 0 | 0 | 5 |
| NAT Enhancements | 5 | 0 | 0 | 5 |
| Screen/IDS Enhancements | 4 | 2 | 0 | 6 |
| Security Flow Enhancements | 5 | 0 | 0 | 5 |
| ALG Enhancements | 9 | 0 | 0 | 9 |
| Security Logging Enhancements | 0 | 0 | 0 | 0 |
| PKI / Certificates | 3 | 1 | 0 | 4 |
| Routing Enhancements | 10 | 3 | 0 | 13 |
| VPN Enhancements | 10 | 0 | 0 | 10 |
| HA Enhancements | 0 | 2 | 0 | 2 |
| Firewall Filter Enhancements | 2 | 1 | 0 | 3 |
| QoS / Class of Service | 2 | 4 | 0 | 6 |
| Multi-Tenancy | 4 | 0 | 0 | 4 |
| Management & Automation | 12 | 2 | 0 | 14 |
| Interface Enhancements | 1 | 1 | 0 | 2 |
| System Enhancements | 5 | 0 | 1 | 6 |
| Miscellaneous | 6 | 0 | 0 | 6 |
| **TOTAL** | **120** | **19** | **1** | **140** |

> The per-section counts and grand total above are a hand-maintained
> summary and drift by ±1 against a strict machine row-parse of
> `docs/authoritative-backlog.md` (a known maintenance artifact, not a
> missing feature). Treat the individual section tables below and
> `docs/feature-coverage.md` as authoritative for any specific feature's
> status; the totals are an at-a-glance scale indicator only.

**Implementation status key:**
- **Fully Missing**: No config parsing or runtime support
- **Partially Implemented**: Some aspects work but incomplete
- **Parse-Only**: Config is parsed into AST/types but has no runtime effect

---

## 1. Security Policies (Unified/Advanced)

xpf has zone-based policies with source/dest address, application match, permit/deny/reject actions, logging, counting, and schedulers. Match also supports the family-scoped wildcards `any-ipv4` / `any-ipv6` (normalized to `0.0.0.0/0` / `::/0` at compile time) and the `source-address-excluded` / `destination-address-excluded` modifiers (invert the per-side match in the dataplane), per #2008 H11/H2. The `any-ipv4` / `any-ipv6` wildcards are family-scoped on BOTH the v3 and legacy dataplane parse paths — they match only their own family and never leak across to the opposite family. A policy match address that is not a defined address-book entry, the `any` keyword, or a valid CIDR/IP is hard-rejected at commit (a typo cannot silently ship); the dataplane additionally fails CLOSED on an unexpectedly empty `*-address-excluded` set (defense in depth — an empty excluded set denies rather than inverting into match-all). The fail-closed test is "empty across BOTH address families" (#3023): an excluded set that legitimately lists only one family (e.g. only IPv6 addresses) leaves the OTHER family empty, but a packet in that other family is trivially not in the excluded set and so the side matches — gating fail-closed on the per-family empty flag alone wrongly dropped all cross-family traffic on a permit rule. A genuine typo/parse-drop empties both families and still denies. These gaps represent vSRX-specific advanced policy features.

| Feature | Junos Config Path | Description | Priority | Status |
|---------|-------------------|-------------|----------|--------|
| **Unified Policies** | `security policies ... match dynamic-application` | Single policy combining L3/L4 + L7 app + URL category + user identity match conditions. Foundation for modern SRX policy management. | High | Missing (requires AppID) |
| **Dynamic Application Match** | `security policies ... match dynamic-application junos:FTP` | Match on L7-detected application identity within security policy | High | Missing (requires AppID) |
| **URL Category Match** | `security policies ... match url-category ...` | Match web traffic by URL category (shopping, social-media, etc.) | Medium | Missing |
| **Source Identity Match** | `security policies ... match source-identity ...` | Match on authenticated user identity (AD user/group) in policy | Medium | Missing (requires user-id) |
| **Application Services in Policy** | `security policies ... then permit application-services` | Attach UTM, IDP, SSL-proxy, AppFW, ICAP redirect, SecIntel to policy action | High | Missing |
| **Policy Rematch** | `security policies policy-rematch` | Re-evaluate existing sessions when policy changes | Medium | **Mostly enforced (#4234 / #4342 / #4343).** All halves ship in `pkg/daemon/daemon_policy_invalidate.go` (keyed on the session `policy_id` #3056, propagated to the HA peer via the #2468 delete-sync, run under `d.applySem` after the dataplane apply). (1) The Junos-DEFAULT **deletion-clear** is always on: a session admitted by a policy that a commit DELETES is invalidated immediately at commit, independent of the knob. (2) The **modified-policy re-evaluation** runs when `policy-rematch` is set: a surviving policy (same zones+name) whose MATCH or ACTION changed has its live sessions cleared at commit so the tightened policy re-evaluates traffic (`changedPolicyRuntimeIDs` / `clearSessionsForModifiedPolicies`; identity via `PolicyIDsByStableKey`, match/action diff via `PoliciesByStableKey`; overloaded `policy_id 0` excluded). (3) **Default-policy change (#4342):** a change to the IMPLICIT default-policy re-evaluates the live default-PERMIT sessions, which carry `DefaultPolicySentinelID` (0xFFFFFFFF) rather than any configured id (`defaultPolicyChanged` / `clearSessionsForDefaultPolicyChange`). A verdict change (permit↔deny/reject) clears them UNCONDITIONALLY like the deletion-clear; a session-log flip (`default-policy-log session-init/session-close`) clears them only under `policy-rematch`. The 0xFFFFFFFF sentinel can never alias `policy_id 0`, so the id-0 host-inbound/fabric/synced fail-safe does not apply here. (4) **Scheduler-binding change (#4343):** because `policyRuleInactive` is FAIL-CLOSED (an inactive-scheduled policy is skipped in the rule chain), a surviving policy whose scheduler-name binding or scheduler active-WINDOW flips it active→inactive is treated as a verdict change and its sessions are cleared under `policy-rematch` (`policySchedulerBecameInactive`, driven by the per-scheduler active-state evaluated via `policySchedulerActiveStateForApplyLocked`). What remains is **`policy-rematch extensive`**: Junos re-evaluates even sessions of an UNCHANGED policy when a referenced address-book / application object changes — xpf clears only the policies whose own match/action/scheduler state changed, so `extensive` keeps an advisory (#4234). **Error contract (#5578):** the shared core `clearSessionsForPolicyIDs` and its three wrappers RETURN an aggregated `error` (both families always attempted, errors joined). A PARTIAL invalidation — a failed `ForEachV4/V6` enumerate leaves unvisited sessions in the live table, a failed `DeleteBatchKnownV4/V6` leaves matched sessions installed — is a stale-authorization gap (traffic the new policy should now DENY keeps forwarding on old session state), so the returning callers join it into the result: the commit path (`applyAndSyncCommitted`) surfaces it alongside the non-fatal `applyErr` (mark-and-continue — config stays committed + still syncs to the peer, operator sees the failure and can re-commit), the peer sync-recv path (`syncAndApply`) returns it to `handleConfigSync`, and the void confirm-timeout rollback logs it loudly. The `slog.Error/Warn` diagnostics are kept but the failure is no longer swallowed by a log line alone. |
| **Policy Scheduling (time ranges)** | `schedulers scheduler ...` | Time-based policy activation/deactivation with start/stop dates | Low | Userspace propagation landed in #1396. #1378 is closed: scheduler state, hit-counter survival, strict missing-scheduler behavior, deterministic evidence validation, and live HA artifact capture are complete for userspace. |
| **Reject Action with Profile** | `security policies ... then reject profile ...` | Custom ICMP/TCP-RST reject messages, redirect URLs for blocked content | Low | Missing |

---

## 2. Application Security (AppSecure)

The AppSecure suite is a major differentiator for the vSRX as an NGFW. xpf now has real end-to-end AppID plumbing for L3/L4 application-catalog classification: the control plane ships the `(protocol, port-range) → app_id` catalog to the userspace dataplane in the config snapshot (`app_catalog`), the dataplane stamps the matched `app_id` on each new conntrack session at create time, and `show security flow session` resolves it back to the application name (#2008 M5). It still does not have a full Junos L7 DPI/signature engine.

| Feature | Junos Config Path | Description | Priority | Status |
|---------|-------------------|-------------|----------|--------|
| **Application Identification (AppID)** | `services application-identification` | L7 DPI engine using signatures, heuristics, pattern matching. Identifies 4000+ apps regardless of port/protocol. Foundation for all AppSecure features. | High | Partial — L3/L4 catalog classification only; L7 DPI / signature engine is **not implemented**. The userspace dataplane stamps the matched catalog `app_id` on each session (#2008 M5) so `show security flow session` reports the real application; with the knob enabled, a session matching no catalog entry resolves to `UNKNOWN` (honest) instead of a built-in port guess. Full contract: [docs/services-application-identification.md](services-application-identification.md); operator-facing status: `show services application-identification status`. (#653) |
| **Application Tracking (AppTrack)** | `security application-tracking` | Log and report on applications traversing the device. Generates AppTrack log messages per session with app name, bytes, duration. | Medium | Missing |
| **Application Firewall (AppFW)** | `security application-firewall ...` | (Legacy, replaced by unified policies) Policy enforcement based on detected app identity | Medium | Missing |
| **Application QoS (AppQoS)** | `class-of-service application-traffic-control` | QoS rate-limiting and marking based on detected application | Medium | Missing |
| **Application Quality of Experience (AppQoE)** | `N/A (service suite / policy integration)` | Monitor application quality and user experience, correlate application behavior to network quality, and feed optimization / reporting workflows. Called out as part of the vSRX Content Security Bundle feature set. | Low | Missing |
| **Advanced Policy-Based Routing (APBR)** | `security advance-policy-based-routing profile ...` | Route traffic to different routing instances based on L7 application identity. Profile with rules matching apps/groups to routing-instance. Applied per-zone. | Medium | Missing (xpf has filter-based PBR but not L7-aware) |
| **Application Signature Package** | `request services application-identification download` | Downloadable/updatable signature database, predefined app groups (junos:social-networking, junos:web:streaming, etc.) | Medium | Missing |
| **Application System Cache** | `services application-identification application-system-cache` | Cache app identification results for faster classification of subsequent connections from same source | Low | Missing |
| **Custom Application Signatures** | `services application-identification application ... signature ...` | User-defined L7 signatures with byte patterns for custom/proprietary applications | Low | Missing |

---

## 3. Intrusion Detection & Prevention (IDP/IPS)

IDP is a core NGFW feature supported on vSRX with subscription license. xpf has no IDP engine.

| Feature | Junos Config Path | Description | Priority | Status |
|---------|-------------------|-------------|----------|--------|
| **IDP Policy** | `security idp idp-policy ...` | Policy with rulebases (IPS, exempt) containing match conditions and actions (close-client, close-server, drop, notify, ignore) | High | Missing |
| **Signature Database** | `security idp security-package` | 15,000+ predefined attack signatures, automatic updates from Juniper | High | Missing |
| **Protocol Anomaly Detection** | `security idp idp-policy ... rulebase ips rule ... match attacks predefined-attack-groups` | Detect non-RFC-compliant protocol behavior (65+ protocol decoders, 500+ contexts) | High | Missing |
| **Custom Attack Objects** | `security idp custom-attack ...` | User-defined signatures with regex patterns, protocol contexts, severity levels | Medium | Missing |
| **Dynamic Attack Groups** | `security idp dynamic-attack-group ...` | Auto-grouping based on severity, category, application, CVSS score filters | Medium | Missing |
| **IDP Sensor Configuration** | `security idp sensor-configuration ...` | Tuning parameters: flow-level vs packet-level, performance vs accuracy | Low | Missing |
| **Recommended Policy** | `security idp active-policy recommended` | Pre-built policy curated by Juniper Security Team | Low | Missing |
| **IDP SSL Inspection** | (deprecated in favor of SSL proxy) | Inspect encrypted traffic using loaded RSA private keys | Low | Missing |

---

## 4. Content Security (UTM)

UTM features require subscription license on vSRX. xpf has no content inspection engine.

| Feature | Junos Config Path | Description | Priority | Status |
|---------|-------------------|-------------|----------|--------|
| **Antivirus** | `security utm feature-profile anti-virus ...` | Signature-based AV scanning (Avira engine on vSRX 3.0). File-based and express modes for HTTP, FTP, SMTP, POP3, IMAP. | Medium | Missing |
| **Web Filtering (EWF)** | `security utm feature-profile web-filtering juniper-enhanced ...` | Enhanced Web Filtering: 90+ URL categories, cloud-based categorization, safe search enforcement | Medium | Missing |
| **Anti-Spam** | `security utm feature-profile anti-spam ...` | SMTP spam filtering using Sophos/SBL block lists, real-time blocklist checks | Low | Missing |
| **Content Filtering** | `security utm feature-profile content-filtering ...` | Block/permit by MIME type, file extension, protocol command, embedded object type | Low | Missing |
| **UTM Custom Objects** | `security utm custom-objects ...` | MIME patterns, filename extensions, URL patterns, URL categories for UTM matching | Low | Missing |
| **UTM Policies** | `security utm utm-policy ...` | Named UTM profiles that aggregate AV, web-filter, anti-spam, content-filter and attach to security policies via `application-services utm-policy` | Medium | Missing |

---

## 5. SSL/TLS Inspection

SSL proxy is supported on vSRX 3.0 and enables inspection of encrypted traffic for IDP, AppFW, UTM, etc.

| Feature | Junos Config Path | Description | Priority | Status |
|---------|-------------------|-------------|----------|--------|
| **SSL Forward Proxy** | `services ssl proxy profile ... actions ...` | MITM decryption of outbound TLS: terminate client session, establish new session to server, inspect cleartext. Applied via security policy `application-services ssl-proxy`. | Medium | Missing |
| **SSL Reverse Proxy** | `services ssl proxy profile ... protect-server ...` | Decrypt inbound TLS for server protection. Load server's private key to terminate sessions. | Low | Missing |
| **SSL Decryption Mirroring** | `services ssl proxy ... decryption-mirror ...` | Mirror decrypted traffic to analysis tool/SPAN port | Low | Missing |
| **Certificate Management for SSL** | `security pki ... ; services ssl proxy root-ca ...` | Root CA generation, trusted CA stores, certificate exemptions per URL category, allowlisting by domain | Medium | Missing |

---

## 6. Advanced Threat Prevention (ATP)

ATP Cloud integration provides cloud-based threat analysis. xpf has dynamic
address feeds which partially overlap with SecIntel. As of #2049 these feeds
are ENFORCED: a policy/NAT rule referencing a feed-backed `address-name` now
has the live feed prefixes overlaid into the userspace dataplane's address
book (the `apply_snapshot` the AF_XDP helper enforces), and a feed refresh
republishes the snapshot. Previously the prefixes were fetched and shown but
never reached the forwarding path. The NAT side was completed in #3303: the
snapshot builder now threads the feed overlay into the source/destination NAT
builders, so a NAT rule scoped to a feed-backed `match
source-address-name` / `match destination-address-name` resolves the live feed
prefixes the same way the policy path does (a DIRECT name reference). #3294
extended the SECURITY-POLICY path so an address-SET whose member is a
feed-backed binding now merges that member's live feed prefixes into the set's
address-book row (the feed-aware `expandBookNameRecursive`) — a `deny
<set-containing-a-feed>` enforces the feed portion instead of under-denying it,
and a DIRECT feed reference now also COMMITS under strict validation (the #2008
`bookNames` one-liner). #4925 closes the last piece of this parity: the NAT
path's recursive (feed-member-in-an-address-set) case is no longer a residual —
`resolveNATAddressNamePrefixes` now resolves a NAT `match
source-address-name` / `match destination-address-name` reference through the
SAME `expandBookNameRecursive` expander, so a NAT rule scoped to an address-SET
whose member is a feed (feed-only OR mixed static+feed) resolves that nested
member's live feed prefixes exactly as the policy path does. Fail-closed is
preserved: a set whose only member is a genuinely unresolvable non-feed token
still yields no match (the raw book-name token keeps the constraint non-empty
and unmatchable) rather than widening to match-any.

| Feature | Junos Config Path | Description | Priority | Status |
|---------|-------------------|-------------|----------|--------|
| **SecIntel Threat Feeds** | `services security-intelligence profile ...` | Cloud-curated threat intelligence feeds: C&C servers, attacker IPs, malicious URLs, infected hosts. Applied via security policy. | Medium | Partial (xpf dynamic address feeds are fetched, refreshed, and now ENFORCED via policy/NAT address-name bindings (#2049); SecIntel-format profile integration is still missing) |
| **Malware Sandboxing** | `services advanced-anti-malware policy ...` | Cloud-based sandbox analysis of unknown files (ATP Cloud). File submission, verdict caching. | Low | Missing |
| **Encrypted Traffic Insights** | `services ssl ... encrypted-traffic-insights ...` | Detect malware in encrypted traffic without decryption using TLS metadata analysis (JA3 fingerprints, certificate characteristics) | Low | Missing |
| **GeoIP Filtering** | `security intelligence ... geoip ...` | Block/allow traffic by geographic location of source/destination IP | Medium | Missing |
| **DNS Security** | `services security-intelligence profile ... category dns ...` | DNS request inspection, domain sinkholing, DNS tunneling detection | Medium | Missing |
| **Adaptive Threat Profiling** | `services security-intelligence profile ... adaptive-threat-profiling ...` | Automated threat intelligence generation from local traffic patterns | Low | Missing |

---

## 7. User/Identity Firewall

User-based policy enforcement integrating with directory services. Not implemented in xpf.

| Feature | Junos Config Path | Description | Priority | Status |
|---------|-------------------|-------------|----------|--------|
| **Integrated User Firewall** | `services user-identification active-directory-access ...` | Policy enforcement based on user identity. Reads AD event logs, LDAP queries for user-IP mapping. | Medium | Missing |
| **Captive Portal** | `services user-identification ... ; security policies ... then permit firewall-authentication web-redirect` | Web-based authentication portal for unauthenticated users. Redirect HTTP to login page. | Medium | Missing |
| **Pass-Through Authentication** | `security policies ... then permit firewall-authentication pass-through` | Transparent auth: prompt for credentials via FTP/Telnet/HTTP without redirect | Low | Missing |
| **User Role-Based Policies** | `security policies ... match source-identity role-name` | Security policies matching on user roles/groups from AD/LDAP directory | Medium | Missing |
| **JIMS Integration** | `services user-identification identity-management ...` | Juniper Identity Management Service for user-IP mapping from multiple auth sources | Low | Missing |

---

## 8. NAT Enhancements

xpf has SNAT (interface + pool, address-persistent, source-nat off bypass), DNAT (with pools, hit counters, source-address-name match, destination-address-name match (#3229), protocol-only match, port rewriting, multi-port matching, destination-nat off exemption (#3844)), static 1:1 (host AND block-to-block subnet mappings, #3031; named translation target `then static-nat prefix-name <addr>`, #4290), NAT64, and exemption rules. These are additional NAT features from the vSRX.

> **DNAT `match destination-address` now honors a multi-host prefix
> (#3164 — supersedes the #3029 exact-host limitation).** The userspace
> `DnatTable` installs a longest-prefix-match entry, so a destination-NAT
> rule whose `match destination-address` is a non-host CIDR (e.g.
> `198.51.100.0/24`) translates EVERY host in the block to the rule's pool
> (many:1). The Go builder carries the canonical prefix on the additive
> `destination_prefix` wire field; overlapping prefixes resolve by longest
> match, and an exact-host entry (the longest possible prefix) always wins
> over a covering block via the O(1) exact-host fast path. The
> `docs/feature-coverage.md` §"Destination NAT" row is the current truth.
> Single-host destinations (a bare IP, `/32`, or `/128`), bracket lists of
> hosts (#2395, one table entry per host), and non-host prefixes (#3164)
> are all accepted. The #3029 commit-time reject of a multi-host prefix
> destination (`validateDestinationNATAddressesStrict`, which existed as a
> fail-closed guard against the old silent-narrowing) has been **removed**
> now that the prefix is honored. Whole-block local-address registration
> (proxy-ARP/ND) is bounded: a block at or below 4096 usable hosts (a v4
> /20 or longer) is expanded host-by-host; a larger block registers only
> its network base and must be ROUTED to the firewall (the DNAT match
> itself is independent of this set). Block-mapping semantics (a 1:1
> host-N -> host-N offset map) remain out of scope for DNAT; the many:1
> prefix translation above is what is implemented.
>
> The **static-NAT** sibling block mapping (`static-nat prefix <subnet>`,
> 1:1 by offset) is **supported** (#3031): an equal-length source/
> destination prefix pair installs an offset-preserving `StaticNatTable`
> block rule (forward DNAT + reverse SNAT, host bits preserved), and the
> commit gate accepts the valid equal-length pair while still rejecting
> mismatched-length / mixed-family pairs. A subnet block map is
> **address-only 1:1** — it cannot carry a `match destination-port` /
> `then static-nat mapped-port` (per-port translation is a host-scope
> construct on a `/32`; `StaticNatBlock` has no port fields and would
> silently widen "port 80 of this /24 -> 8080" into an all-port /24 NAT).
> The commit gate REJECTS a block pair that also specifies a port, and the
> dataplane lenient-load path drops it rather than mis-installing an
> all-port block (#3202).
>
> **Named static-NAT target `then static-nat prefix-name <addr>` (#4290,
> fable-167 N-1).** The named form of `then static-nat prefix <ip>`:
> `prefix-name` references a global address-book entry whose literal prefix
> is the 1:1 translation target. Before #4290 the target keyword fell
> through the compiler's `then` switch (which recognized only
> `nptv6-prefix` / `prefix` / `inet`), leaving `rule.Then == ""` — the rule
> committed clean and installed with an **empty translation target** (a
> silent broken static NAT). The compiler now resolves the referenced
> address-book entry to its prefix (`resolveStaticNATThenPrefixNames`, run
> after the zone-local books are folded into the global book). A defensive
> **empty-target guard** (`validateStaticNATThenTargetStrict`) now REJECTS
> at strict commit ANY `then static-nat` that produced an empty target —
> an unresolvable `prefix-name` OR an unhandled/misspelled target keyword —
> so no static-NAT rule can commit with no translation. Lenient load /
> peer-sync downgrades to a warning (#1960) and the dataplane fails closed
> (the empty prefix does not parse as an IP).

> **Accepted-only NAT knobs (advisory, not enforced).** Three NAT knobs are
> now schema-typed and committed but the userspace AF_XDP dataplane does not
> enforce them; each emits a commit-time accepted-only advisory (mirroring
> the #2078 / #4231 doctrine) instead of the prior silent drop:
> - `security nat source interface port-overloading off` and pool
>   `port-overloading-factor <n>` (#4291, fable-167 N-2) — the SNAT allocator
>   always overloads source ports, so `off` hardened NOTHING; the advisory
>   makes the false hardening operator-visible. Unique-src-port-per-mapping
>   and factor-scaled port budgeting are a userspace-dp SNAT-allocator
>   follow-up.
> - the NAT translation-**target** routing-instance — `then static-nat
>   {inet|prefix <ip>} routing-instance <ri>` and a source / destination
>   pool `routing-instance <ri>` (#4292, fable-167 N-3) — the dataplane
>   routes the post-translation packet against the ingress / default routing
>   instance, so the target RI was silently dropped. This is DISTINCT from
>   the #3096 from/to **scope** routing-instance, which IS enforced. Placing
>   the translated packet in a non-ingress table (cross-VRF NAT) is a
>   userspace-dp follow-up.

> **NAT64 inbound policy now matches the real internal IPv4 host (#2358,
> resolved).** For inbound NAT64 flows the security policy is evaluated
> against the POST-translation tuple — the v6 client source matched in the
> IPv6 ingress zone, and the real internal IPv4 server the synthetic NAT64
> address was extracted to, matched in the destination zone. This matches
> Junos/SRX, where inbound destination translation precedes the policy
> lookup. NAT64 is a cross-family translation `(V6 src, V4 dst)`;
> `policy.rs::try_match_rule` grew a dedicated cross-family arm (#2358) that
> matches the source against the rule's IPv6 source set and the destination
> against the rule's IPv4 destination set, so an operator authors a NAT64
> policy against the real IPv4 host. This composes with the same-family
> DNAT/static-DNAT/NPTv6 post-translation matching from #2345. **Migration:**
> NAT64 policies previously authored against the synthetic IPv6
> NAT64-prefix destination no longer match — rewrite them against the real
> IPv4 host address + its destination zone. Note the legacy parse
> convention that an address set with no IPv4 prefix and no `any-ipv4`
> wildcard treats the IPv4 family as match-any still applies, so scope the
> destination to the real IPv4 host explicitly. The reverse `(V4 src, V6
> dst)` tuple (NAT46, unsupported) still fails closed.

| Feature | Junos Config Path | Description | Priority | Status |
|---------|-------------------|-------------|----------|--------|
| **Proxy ARP for NAT** | `security nat proxy-arp interface ... address ...` | Auto-reply ARP for NAT pool addresses on same subnet as ingress interface. Required when SNAT pool, DNAT, or static-NAT external addresses are on same L2 segment. | High | **Done** -- Proxy ARP neighbor entries (NTF_PROXY) for NAT addresses with GARP on addition, AND the per-interface `net.ipv4.conf.<if>.proxy_arp` sysctl is enabled so the kernel actually answers the ARP (#2160). The kernel has two ARP-proxy paths: the pneigh (NTF_PROXY) reply branch, which answers only when the target routes out a *different* interface and does not consult the sysctl; and the `arp_fwd_proxy` path, gated by the per-interface `proxy_arp` sysctl. Whether the sysctl is load-bearing is therefore route-topology dependent (a same-L2-subnet external address is answered by neither path until the sysctl is on -- the #2160 case); enabling it guarantees a reply. Note: with the default `medium_id=0`, `proxy_arp=1` makes the kernel answer ARP on that interface for ANY target routed out a different interface -- broader than Junos `proxy-arp` (which proxies only listed addresses); per-address (v4-only) narrowing is **deferred** in #2197 item 3 (PLAN-DEFER, lab characterization pending -- dropping the sysctl would re-break the same-L2 #2160 case). IPv6 addresses get a real proxy-NDP pneigh install (#2197 item 1, see Proxy NDP row). The reconcile is also re-asserted by an always-on 30s ticker so a non-commit kernel link cycle (HA RETH flap, `programRethMAC`) self-heals without an operator re-commit (#2197 item 2). Removing proxy-arp from an interface now also DISABLES the sysctl: the daemon remembers the last-enabled `(iface -> families)` set and writes `proxy_arp`/`proxy_ndp` back to `0` for any pair that drops out on a later commit, so the over-broad responder no longer leaks on across the config removal until reboot (#2475). A proxy-arp entry on a VLAN sub-interface (`reth0.50`, `ge-0/0/0.100`) resolves to that sub-interface's OWN VLAN netdev ifindex (`cfg.ResolveKernelIfName`, which maps the unit to its 802.1Q VLAN ID and collapses unit 0 onto the bare parent), not the parent -- `proxy_arp`/`proxy_ndp` are per-netdev, so the old parent-ifindex resolution wrote the sysctl on the parent and left the VLAN sub-interface silent (#3010). Config: `set security nat proxy-arp interface <iface> address <addr>` with range support. |
| **Proxy NDP for NAT** | `security nat proxy-ndp interface ... address ...` | IPv6 equivalent of proxy ARP for NAT64/static NAT addresses | Medium | **Done** -- An IPv6 address under `proxy-arp` now installs the kernel proxy-NDP *neighbor table* entry (the v6 NTF_PROXY analogue of `ip -6 neigh add proxy <addr> dev <if>`) AND enables the per-interface `net.ipv6.conf.<if>.proxy_ndp` responder sysctl (#2197 item 1, completing #2160). The kernel answers a v6 NS only with forwarding + `proxy_ndp` + a matching v6 pneigh entry (`net/ipv6/ndisc.c` `pneigh_lookup`), so all three pieces are now wired -- IPv6 static-NAT / NAT64 external proxy works end-to-end with no manual `ip -6 neigh`. v6 proxy-NDP is `pneigh_lookup`-gated (per-address by construction), so there is no v6 over-answer breadth -- the per-address narrowing follow-up (#2197 item 3) is IPv4-only. |
| **Twice NAT** | Combination of SNAT + DNAT rule-sets matching same traffic | Simultaneous source and destination translation in single flow. | Medium | **Done** -- Combined SNAT+DNAT flows now preserve both translations in one session path. Static DNAT is keyed by ingress zone with wildcard fallback for SNAT return-path entries across eBPF and userspace (DPDK retired #1525). Userspace post-DNAT SNAT matching now evaluates destination filters against the translated destination, and session/gRPC visibility preserves both NAT legs. |
| **DNS ALG with NAT** | `security alg dns enable` | DNS payload rewriting when NAT changes embedded IP addresses (A/AAAA record doctoring) | Medium | Missing |
| **Overflow Pool** | `security nat source pool ... overflow-pool ...` | Fallback to interface NAT or another pool when primary SNAT pool is exhausted | Low | Missing |
| **Address Pooling (paired/no-paired)** | `security nat source pool ... address-pooling paired` | Per-pool override of global address-persistent: paired ensures same source always maps to same pool address; no-paired allows round-robin | Low | Missing |
| **Port Randomization Control** | `security nat source pool ... port-randomization disable` | Disable random port selection in SNAT (use sequential instead). Enabled by default. | Low | **Done** -- `port-randomization disable` now compiles for source pools and is enforced in XDP SNAT allocators (DPDK retired #1525). |
| **Deterministic NAT (Port Block Allocation)** | `security nat source pool ... port deterministic ...` | Predictable port mapping for logging compliance. Each source gets fixed port block. | Low | **IPv4 (mode 1) AND IPv6/NAPT64 (mode 2) ENFORCED on userspace (#4559).** Mode 1: the Go builder carries the block/host params (`deterministicSourceNATFields`, `nat_source.go`) and the Rust allocator maps each in-range subscriber IPv4 to a fixed external IP + port block, reversible from `(external IP, port)` with no per-flow state (`allocate_deterministic_v4` / `reverse_deterministic_v4`, `userspace-dp/src/nat/allocator.rs`). Mode 2: a `/32`-or-`/64` IPv6 host on a source pool referenced by a `security nat nat64` rule-set maps each IPv6 subscriber (the 32-bit word after the prefix) to a fixed external IPv4 + port block on the NAT64 forward path (`deterministicNAT64V6Fields`/`nat64.go`; `allocate_deterministic_v6`/`reverse_deterministic_v6`; `nat64.rs allocate_source`). The commit-time advisory (ValidateConfig) is now scoped to the residual UNENFORCEABLE cases (an IPv6 host not wired to NAT64, or an unsupported prefix length). Config-derived block-PROVISIONING utilization landed in #4752 (`xpf_nat_deterministic_pool_blocks_total` / `_allocated` = provisioned subscriber blocks over `len(addresses) * floor(port-range / block-size)` capacity — the capacity-planning signal the pool-wide `UsedPorts` alarm cannot give). The RUNTIME per-subscriber block-exhaustion alarm (live-flow-per-block / block-full events) remains a deferred Rust follow-up (needs new allocator state). The forward/reverse mapping is now exposed for the CGN compliance/forensics workflow (subscriber → translated IP + port block, and translated IP + port → subscriber) via `show security nat source deterministic-nat internal-host`/`nat-ip ... nat-port`, the `GetNATDeterministic` gRPC RPC, and `GET /api/v1/security/nat/deterministic` — one canonical `pkg/nat` query against the last-applied generation, shared by CLI/gRPC/REST (#5794). See `docs/deterministic-nat-cgnat.md`. |
| **NAT Pool Utilization Alarm (runtime consumer)** | `security nat source pool-utilization-alarm raise-threshold/clear-threshold` | Raise a `show security alarms` entry + NAT syslog event when a source pool's port utilization crosses the raise threshold; clear below the clear threshold. | Low | **Done** (#2079) -- 10s daemon monitor over the helper's last-applied NAT pool snapshot (`dp.AppliedNATView()`), transition-gated raise/clear with hysteresis, both `show security alarms` render sites + structured `RT_NAT` syslog, commit-time threshold validation. Previously parsed+stored with NO consumer (silent no-op). Deterministic pools skipped by this alarm (`UsedPorts` is meaningless when ports are pre-partitioned); config-derived block-provisioning gauges landed in #4752, runtime block-occupancy alarm is a deferred Rust follow-up. |

---

## 9. Screen/IDS Enhancements

xpf implements 16 distinct screen checks, each mapping to real dataplane
enforcement (not a parsed-but-inert leaf): **land, syn-flood, ping-death,
teardrop, winnuke, ip-sweep, port-scan, syn-fin, no-flag (tcp-no-flag),
fin-no-ack, syn-frag, source-route-option (ip-source-route), icmp-flood,
udp-flood, icmp-fragment, and limit-session** (per-source / per-destination
session limiting). This count is auditable against
`userspace-dp/src/screen/mod.rs`: 15 of these carry a dedicated per-reason
drop counter — `screen_reason_drop_index` maps exactly `SCREEN_REASON_DROP_COUNT
= 15` ordinals, with `session-limit-src` / `session-limit-dst` folding onto one
`session-limit` ordinal — and the 16th, icmp-fragment, is enforced by
`stateless::check_icmp_fragment` and folds to the aggregate `screen_drops`
counter. SYN-cookie flood protection (`security flow syn-flood-protection-mode
syn-cookie`) is a separate stateless mechanism, not one of the 16. These are
additional vSRX screen options.

| Feature | Junos Config Path | Description | Priority | Status |
|---------|-------------------|-------------|----------|--------|
| **Session Limiting (source-ip)** | `security screen ids-option ... limit-session source-ip-based N` | Limit max concurrent sessions from single source IP (1-8M). Prevents session table exhaustion. | High | **Done** (#2134) -- the userspace dataplane `SessionTable` keeps a per-source-IP count of PRESENT forward sessions (incremented at the two create sinks -- fresh install AND peer-synced import (#3122) -- decremented at the sole removal sink, evict-on-zero; the in-place HA promote/demote origin flips are count-neutral). **#3122:** the count is origin-agnostic -- HA-peer-synced sessions count too, so the limit stays enforced after a failover (previously synced sessions were excluded, letting a client exceed its cap on the standby-turned-active -- a limit bypass). The limit is enforced at the new-flow / session-MISS decision in `poll_descriptor`: the (limit+1)-th new flow from an over-limit IP is dropped + counted (`session-limit-src`). Pre-#2134 the count was computed but never wired, so the limit was a no-op. **Per-worker cap (#2186):** the count is maintained per-worker (per RX queue), so with RSS the effective admitted cap is `N × configured` where N = number of RX queues/workers (live: `limit 2` admitted 12 on a 6-worker cluster) -- consistent with the rest of the per-worker dataplane, NOT a global cap. Size the configured value as a per-worker ceiling. |
| **Session Limiting (dest-ip)** | `security screen ids-option ... limit-session destination-ip-based N` | Limit max concurrent sessions to single destination IP | High | **Done** (#2134) -- same per-IP `SessionTable` mechanism as source-ip limiting, keyed on the destination IP (`session-limit-dst`). Same per-worker multiplier applies (#2186): effective cap ≈ `N × configured`. |
| **TCP Port Scan Detection** | `security screen ids-option ... tcp port-scan threshold N` | Detect TCP port scanning: `threshold` is the Junos detection WINDOW in microseconds (default 5000); detection fires when one source reaches a FIXED 10 distinct destination ports within that window. | Medium | **Done** (#4114) -- full Junos semantics. The dataplane (`userspace-dp/src/screen/scan.rs`) resets its per-`(zone,src)` distinct-port set each `window_micros` and fires at the fixed `SCAN_DETECT_COUNT` (10). `ip ip-sweep` shares the same tracker and semantics (distinct destination IPs). **Migration note:** #4114 FLIPS the meaning of an existing `threshold` value from a distinct-destination COUNT (over a fixed 10s window — the buggy pre-#4114 xpf shape, which read a Junos `threshold 5000` as a count clamped to never-fire and false-dropped normal browsing at the default) to a MICROSECOND time window. A copied Junos `threshold 5000` now behaves correctly; a legacy xpf count-shaped value (e.g. `threshold 10`) now reads as a 10us window and is flagged by a commit-time advisory (`validateScreenScanSweepWindows`, Junos range [1000, 1000000] — never a hard reject, no-brick). |
| **UDP Port Scan Detection** | `security screen ids-option ... udp port-scan threshold N` | Same as TCP port scan but for UDP | Medium | Missing |
| **UDP Sweep Detection** | `security screen ids-option ... udp udp-sweep threshold N` | Detect UDP sweeps (same port, many destinations) | Low | Missing |
| **TCP Sweep Detection** | `security screen ids-option ... tcp tcp-sweep threshold N` | Detect TCP sweeps (same port, many destinations) | Low | Missing |
| **ICMP Fragment** | `security screen ids-option ... icmp fragment` | Drop any fragmented ICMP/ICMPv6 packet (a fragmentation-based attack signature). | Medium | **Done** (#3316) -- the userspace dataplane (`screen/stateless.rs check_icmp_fragment`) already dropped fragmented ICMP/ICMPv6 when `icmp_fragment` was set, but the Go config→snapshot path was missing (`ICMPScreen` had no field, `compileScreen` ignored the leaf, the schema subtree was open, and `buildScreenSnapshots` never published `ICMPFragment`), so the check was unreachable from config. #3316 adds `ICMPScreen.Fragment`, the `icmp fragment` compiler case, the schema leaf, and the snapshot publish + emit-gate inclusion. |
| **IP Block Fragment** | `security screen ids-option ... ip block-frag` | Block all IP fragments unconditionally | Low | Partial (fragment checks exist but not unconditional block option) |
| **IPv6 Extension Header Filtering** | `security screen ids-option ... ip ipv6-extension-header ...` | Filter/block specific IPv6 extension headers (hop-by-hop, routing, destination, fragment, mobility, no-next) | Medium | Missing |
| **Alarm Without Drop (audit mode)** | `security screen ids-option <name> alarm-without-drop` | Profile-wide audit/log-only mode: a tripped check still ALARMS (logs the attack, counts it) but does NOT drop the packet — the standard vSRX step for tuning screen thresholds against live traffic. | Medium | **Done** (#4170) -- profile-wide flag on `ScreenProfile.AlarmWithoutDrop` (Go + Rust wire). The dataplane verdict consumers (`stage_screen_check` in `poll_stages.rs` for the flowless L3 + flow-path screens, and the scan/sweep + session-limit site in `poll_descriptor`) convert a `ScreenVerdict::Drop` (and the flow-path `SynCookieChallenge`) into a log-only PERMIT alarm carrying the tripped reason (via `emit_screen_alarm_event`, mirroring the #3315 `syn-flood-alarm` path) and FORWARD the packet. The check still runs, counts its sketch/tracker state, and logs; only the drop is suppressed. Applies to every check in the profile including the rate-based flood / SYN-cookie paths. For the SYN-cookie path this required gating the cookie-active marking (`syn_cookie_active_until_secs`) on `!alarm_without_drop` in `check_packet`: audit mode never mints cookies on the wire, so marking the zone cookie-active would arm `validate_syn_cookie_ack_on_session_miss` to DROP every returning session-miss ACK as `Invalid` -- escaping the audit contract. Leaving the zone inactive makes that path return `NotApplicable` so the ACK forwards; the non-audit SYN-cookie flow is unchanged. A profile with ONLY alarm-without-drop and no enabled check is a no-op (not published). |

---

## 10. Security Flow Enhancements

xpf has TCP session timeouts (established, initial, closing, time-wait), UDP/ICMP timeouts, TCP MSS clamping, allow-dns-reply, allow-embedded-icmp, GRE performance acceleration, and flow traceoptions (packet-filter source-prefix / destination-prefix / `protocol` — M8/#2008).

**TCP MSS clamping contexts (#2486).** The userspace AF_XDP forwarding
path enforces three of the four Junos `security flow tcp-mss` contexts,
selected per-packet at frame build (`select_tcp_mss`,
`userspace-dp/src/afxdp/forwarding/mod.rs`):

- `all-tcp` — clamps every forwarded TCP SYN (IPv4 and IPv6); also the
  universal fallback for the contexts below.
- `gre-in` — clamps an inbound GRE-decapped SYN. The decap stage marks
  the inner packet with `GRE_DECAP_INGRESS_FLAG` in `meta_flags` so the
  builder can select this value (fixes the prior silent full-MSS
  blackhole on the GRE return path).
- `gre-out` — clamps a SYN egressing into a native GRE tunnel
  (gre-out value, or the MTU-derived formula; WireGuard uses the
  overhead-aware value, #2299).
- `ipsec-vpn` — **rejected at commit** (`validateTCPMSSRanges`,
  pkg/config/compiler_security.go). IPsec is processed by the
  kernel XFRM stack; the decrypted inner packets re-enter the userspace
  path as plain traffic with no IPsec marker, so no IPsec context reaches
  the MSS clamp. Carrying it as accepted-but-dead config was worse than
  rejecting it; operators should use `all-tcp` to clamp all forwarded
  TCP. Lenient (boot/peer-sync) load warn-loads a legacy `ipsec-vpn`
  value but does NOT enforce it.

Before #2486 only the tunnel-egress (`gre-out` / WG) context was
enforced; `all-tcp` and `gre-in` were accepted on the wire but never
applied (`all-tcp` silently fanned into gre-out only), and `ipsec-vpn`
was dead config.

| Feature | Junos Config Path | Description | Priority | Status |
|---------|-------------------|-------------|----------|--------|
| **SYN Flood Protection Mode** | `security flow syn-flood-protection-mode syn-cookie` | Global SYN flood protection mode: syn-cookie (stateless) or syn-proxy (stateful). Different from per-screen syn-flood thresholds. | Medium | Legacy eBPF done (`8cbf31a`) with BPF helpers, validated_clients LRU, and 4 counters. Userspace SYN-cookie runtime is wired for #1374 with bounded SYN-ACK/RST replies and status counters; final #1477 source-removal evidence still needs to include the SYN-cookie HA/flood artifacts for the exact deletion candidate. `syn-proxy` mode is not implemented. |
| **TCP Strict SYN Check** | `security flow tcp-session strict-syn-check` | Require SYN as first packet for TCP session creation (drop mid-stream pickup) | Medium | **Config-only (#2078)** — the legacy eBPF SYN gate (`2114333`) was retired with the eBPF dataplane (#1373/#1476). The userspace AF_XDP dataplane has no TCP state machine and does not enforce syn-check; the related `no-syn-check` knob is parsed and committed but inert. Commit emits an accepted-only advisory. |
| **TCP No-SYN-Check** | `security flow tcp-session no-syn-check` | Allow mid-stream TCP session pickup (useful after failover or asymmetric routing) | Medium | **Config-only (#2078)** — the legacy BPF `flow_config` `tcp_flags` bit (`2114333`) was retired with the eBPF dataplane (#1373/#1476). The userspace dataplane does not enforce syn-check, so this opt-out is inert. Accepted-but-not-enforced; commit emits an advisory. Intentional parity gap (see #2008 M9). |
| **TCP No-SYN-Check in Tunnel** | `security flow tcp-session no-syn-check-in-tunnel` | Allow mid-stream pickup specifically for tunneled traffic (IPsec, GRE) | Low | **Config-only (#2078)** — the legacy per-interface `IFACE_FLAG_TUNNEL`/`META_FLAG_TUNNEL` path (`2114333`) was eBPF; retired with the dataplane (#1373/#1476). No tunnel-decap session-create signal exists on the userspace path, so the knob is inert. Accepted-but-not-enforced; commit emits an advisory. |
| **TCP RST Invalidate Session** | `security flow tcp-session rst-invalidate-session` | Immediately invalidate session on TCP RST instead of waiting for timeout | Medium | **Config-only (#2078)** — the legacy eBPF teardown (`2114333`, timeout=0/last_seen=0 on RST) was retired with the dataplane (#1373/#1476). The userspace dataplane shortens the session to a 30s closing timeout on RST/FIN but does not invalidate immediately and does not honor this opt-in. Accepted-but-not-enforced; commit emits an advisory. Design rationale: `docs/active-active-new-connections.md` (suppress RST→CLOSED, keep this as the opt-in override). |
| **Force IP Reassembly** | `security flow force-ip-reassembly` | Force reassembly of all IP fragments before processing (protects against fragment-based evasion) | Medium | Missing — the dataplane does NOT reassemble. NOTE (#3291): a non-first fragment is flowless (#2344) but is no longer fail-OPEN — the flowless transit arm now applies zone security policy, the interface input filter, and PBR (`then routing-instance`) on its L3 identity (`l4_present = false`, so port-bearing terms fail closed; `application any`/address/protocol/`is-fragment` match). A `deny-all` zone pair, `from is-fragment then discard`, and `from is-fragment then routing-instance <ri>` now act on non-first fragments. A flow PERMITTED only by an L4-specific term still drops its non-first fragments (no reassembly + no fragment-association cache yet); full reassembly / fragment association is the remaining gap (tracked in #3291). **Fragment-association fail-closed (#4569):** #3291 closed the fail-OPEN twin for a `deny-all` pair, but a non-first fragment could still bypass a *specific* port-bearing DENY followed by a permit — e.g. `deny junos-https from 10.0.0.0/8` then `permit any`: the port-bearing DENY is gated off for `l4_present = false`, so first-match fell through to the permit and the fragment forwarded. The transit zone-policy evaluation now approximates Junos fragment-association: while walking rules in first-match order it remembers the first port-bearing DENY (`deny`/`reject`) whose L3 (zone fixed by the tier bucket + src/dst address) OVERLAPS the fragment but was skipped ONLY because `l4_present = false`; if the walk then lands on a PERMIT (or default-permit) it OVERRIDES to DROP and attributes the `PolicyDeny` event to that DENY. Scoped narrowly — a fragment with NO overlapping skipped DENY still forwards, and the L4 (`l4_present = true`) path is byte-identical. **junos-host parity (#6465):** the same note/override now runs inside the `to-zone junos-host` evaluation (`evaluate_junos_host_policy_l3_aware`) across its exact/from-any/host-scoped-global tiers, so a host-bound non-first fragment overlapping a port-bearing junos-host DENY is DROPPED (attributed to that DENY) instead of falling through to a junos-host permit or the deliver-on-no-match lifeline; the lifeline is untouched for every flow that does not overlap a deny, and the L4 path is byte-identical. **Over-drop trade-off:** a legitimate non-denied-port fragment from the SAME L3 as an overlapping port-bearing DENY is dropped (the Junos security-over-availability default); a fragment-association cache keyed on (src, dst, frag-id) that replays the first-fragment's exact verdict is the deferred principled fix (#4569). **Config-only (#4231):** the `force-ip-reassembly` knob itself is now schema-typed and commit emits an accepted-only advisory instead of the prior silent drop. |
| **Route Change Timeout** | `security flow route-change-timeout N` | Session timeout (6-1800s) applied when route changes to nonexistent route. Prevents sessions hanging on dead routes. | Low | **Config-only (#4231)** — schema-typed leaf; accepted-but-not-enforced (no route-change session flush on the userspace dataplane). Commit emits an accepted-only advisory instead of the prior silent drop. |
| **Aggressive Session Aging** | `security flow aging early-ageout N; high-watermark N; low-watermark N` | Accelerate session timeout when session table exceeds watermark threshold | Medium | **Config-only (#3440)** — the Go-side GC watermark hysteresis (`2114333`, `pkg/conntrack/gc.go`) is real, but the GC sweep is skipped entirely on the userspace AF_XDP dataplane (`daemon_run.go` installs `gc.SkipSweep=true` for the only runtime forwarding path post #1373/#1476). The userspace session expiry (`userspace-dp/src/session/expire.rs`) ages each entry on its own idle timeout only — no watermark-driven shedding. Accepted-but-not-enforced; commit emits an advisory. The schema is now typed (early-ageout `0..86400`, watermarks `0..100`, `low < high`) so invalid values are rejected instead of silently dropped. NOTE: per-application `inactivity-timeout` (#3227) is a separate, fully-enforced knob. |
| **ICMP Session Sync** | `security flow sync-icmp-session` | Synchronize ICMP sessions between HA cluster nodes | Low | **No-op (#4231)** — schema-typed leaf. In Junos this is an OPT-IN; in xpf it has no effect because ICMP sessions are ALREADY synced to the HA peer unconditionally: the session-sync path is protocol-agnostic at every layer (`publish_shared_session` / `snapshot_all_sessions_export` in `userspace-dp` apply no protocol filter; `pkg/cluster` wire serializes any protocol). So ICMP flows already replicate and survive failover regardless of this knob — it cannot be turned off. Commit emits a distinct advisory saying the knob is a no-op because syncing already happens (previously a silent drop). |
| **Multicast Session Timeout** | `security flow multicast-session-lifetime N` | Custom timeout values for multicast flow sessions | Low | **Config-only (#4231)** — schema-typed leaf (seconds); accepted-but-not-enforced. Commit emits an accepted-only advisory instead of the prior silent drop. |
| **Preserve Incoming Fragment Size** | `security flow preserve-incoming-fragment-size` | Maintain original fragment sizes through the device instead of reassemble-and-re-fragment | Low | **Config-only (#4231)** — schema-typed leaf; accepted-but-not-enforced. Commit emits an accepted-only advisory instead of the prior silent drop. |

---

## 11. ALG Enhancements

xpf has ALG disable flags for DNS, FTP, SIP, TFTP. The vSRX supports many more ALGs.

The `security alg <proto> disable` knobs reach the userspace dataplane via
`FlowSnapshot.alg_disable_flags` (#2008 H3/H4): the bitfield is packed by
`pkg/dataplane/userspace.algDisableFlags` (DNS=0x01, FTP=0x02, SIP=0x04,
TFTP=0x08) and read in the session-create path by
`alg_type_for_session` (`userspace-dp/src/afxdp/bpf_map/publish_conntrack.rs`).
A session on a well-known ALG service port (DNS UDP/53, FTP TCP/21, SIP
UDP+TCP/5060) is tagged with its ALG type in the conntrack `alg_type` field
*unless* that ALG is disabled, in which case it is tagged `none`. This matches
the Junos semantics of `alg disable` — the ALG is turned **off**, traffic is
**never dropped**. (xpf does not yet implement the active ALG transforms
themselves — payload doctoring / dynamic pinholes — so a non-disabled ALG only
sets the type; see "DNS ALG with NAT" below.)

The unimplemented ALG protos below (H.323, MGCP, SCCP, MSRPC, SunRPC, PPTP,
RTSP, RSH, IKE-ESP) are **accepted-but-inert (#4232, fable-167 P-4a)**:
`compileALG` recognizes only `dns`/`ftp`/`sip`/`tftp`, so a `security alg
<proto>` stanza for any other proto (bare `disable` or a richer child) was
silently dropped. Commit now emits an accepted-but-inert advisory naming the
unrecognized protos, so an operator knows the stanza has no effect rather than
believing an ALG was configured. A harder allowlist-reject at the `security
alg <proto>` level is the deeper parity move and is deferred.

| Feature | Junos Config Path | Description | Priority | Status |
|---------|-------------------|-------------|----------|--------|
| **H.323 ALG** | `security alg h323 ...` | VoIP: H.323 session tracking, media pinhole management, NAT for H.245/RAS | Low | Missing |
| **MGCP ALG** | `security alg mgcp ...` | VoIP: Media Gateway Control Protocol session awareness | Low | Missing |
| **SCCP ALG** | `security alg sccp ...` | VoIP: Skinny Client Control Protocol (Cisco) session tracking | Low | Missing |
| **MSRPC ALG** | `security alg msrpc ...` | Microsoft RPC dynamic port tracking (Active Directory, Exchange) | Medium | Missing |
| **SunRPC ALG** | `security alg sunrpc ...` | Sun/ONC RPC dynamic port tracking (NFS, NIS) | Low | Missing |
| **PPTP ALG** | `security alg pptp ...` | Point-to-Point Tunneling Protocol GRE call tracking | Low | Missing |
| **RTSP ALG** | `security alg rtsp ...` | Real-Time Streaming Protocol media pinhole management | Low | Missing |
| **RSH ALG** | `security alg rsh ...` | Remote Shell protocol dynamic port tracking | Low | Missing |
| **IKE-ESP NAT** | `security alg ike-esp-nat enable` | IKE/ESP NAT traversal assistance (non-standard NAT-T) | Low | Missing |

---

## 12. Security Logging Enhancements

xpf has security logging with mode (stream/event), format, streams with host/port/severity/facility/category/source-address. These are additional features.

| Feature | Junos Config Path | Description | Priority | Status |
|---------|-------------------|-------------|----------|--------|
| **Structured Syslog Format** | `security log format structured` | Machine-parseable key-value syslog format (RT_FLOW_SESSION_CREATE, etc.) with standardized field names | Medium | Done (vSRX-compatible RT_FLOW format with `[junos@2636.1.1.1.2.129 ...]` SD wrapping) |
| **Binary Log Format** | `security log format binary` | High-performance compact binary log format for off-box collectors — self-framing records (magic+version+length) over UDP/TCP/TLS and local file | Low | Done |
| **Transport Protocol Selection** | `security log stream ... transport protocol tcp/tls` | Send security logs over TCP or TLS instead of UDP for reliable delivery | Medium | Done (TCP and TLS transport implemented) |
| **Per-Policy Logging** | `security policies ... then log session-init session-close` | Emit RT_FLOW SYSLOG session-init/close records ONLY for the policies configured with `then log` | Medium | Done (#2508 — the flags are stamped onto session metadata at install, carried on the userspace-dp SESSION_CREATE/SESSION_CLOSE frames, and gate the SYSLOG/local-log/slog consumers; the global NetFlow/IPFIX session-close exporter (#2460) still observes every close. All key fields: policy-name, app, ingress-iface, client/server split, close-reason, session-id. #2785 closed the HA gap: the per-policy log flags now ride the session-sync wire (open-frame flags bits 1<<3/1<<4 -> `dataplane.LogFlagSessionInit/Close` on the cluster wire -> `SessionSyncRequest.log_session_init/close` -> the synced session's metadata), so a session that fails over to the standby emits the same RT_FLOW SESSION_CREATE/CLOSE records on the new active node. An old peer that omits the fields decodes to false (no per-policy log), bit-identical to pre-#2785 behavior) |
| **Log Event Mode** | `security log mode event` | Route security logs through eventd (control plane) for on-box processing, slower but allows local processing | Low | Done (event mode writes to local file) |
| **Session Aggregation Logs** | `security log ... report` | Aggregate session logs for top-N reporting (top talkers, top applications) | Low | Done (Space-Saving top-K, bounded memory + arrival-order-independent, #3099) |
| **Log Profile** | `security log profile <name> { stream-name; default-profile; category ... }` | Named log-routing profile targeting a stream, with a default-profile designation (#2008 H7) | Low | Done (compiled to `LogConfig.Profiles`; `stream-name` cross-referenced at commit. Per-stream routing is already a Junos superset, so no dispatch change; `category field-extra-name` accepted but not yet used to alter emitted SD) |

---

## 13. PKI / Certificates

xpf uses strongSwan for IPsec. Basic certificate-auth IKE generation exists, but Junos PKI lifecycle management is still not implemented.

| Feature | Junos Config Path | Description | Priority | Status |
|---------|-------------------|-------------|----------|--------|
| **CA Profile Management** | `security pki ca-profile ... ca-identity ... enrollment url ...` | CA certificate profiles with SCEP/CMPv2 enrollment, revocation checking (CRL/OCSP) | Medium | Missing |
| **Local Certificate Management** | `security pki local-certificate ...` | Generate CSRs, load certificates, auto-enrollment, renewal tracking | Medium | Missing |
| **CRL Management** | `security pki ca-profile ... revocation-check crl ...` | Certificate revocation list download, caching, periodic refresh | Low | Missing |
| **Certificate-Based IPsec** | `security ike gateway ... local-certificate ...` | IPsec authentication using X.509 certificates instead of PSK | Medium | Partial (gateway `local-certificate` and pubkey auth compile into swanctl, but xpf still lacks Junos PKI/local-certificate object lifecycle management) |

---

## 14. Routing Enhancements

xpf has static routes, generate/aggregate routes, ECMP, VRFs, GRE tunnels, rib-groups, next-table route leaking, PBR, qualified-next-hop with interface (link-local IPv6), per-instance `rib <name>.inet6.0` IPv6 static routes, and FRR integration (OSPF, BGP, IS-IS, RIP, LLDP). These are additional routing features.

**IPIP tunnels are NOT supported (#4785).** This section previously claimed
"IPIP tunnels (IPv4+IPv6)"; that was never true of the forwarding path. The
userspace dataplane — the only supported runtime — has no IPIP primitive in
either direction: a tunnel endpoint is entered into the decap index only when
its mode classifies as `TunnelKind::Gre`, and `TunnelKind::Unknown` is the
egress encap dispatcher's fail-closed drop arm. A `mode ipip` tunnel was
therefore created, came UP, and passed no traffic at all. Since #4785 half 1 the
configuration is HARD-REJECTED at strict commit / commit-check
(`validateIpipTunnelUnimplementedStrict`) and downgraded to a warning on the
tolerant load / peer-sync path (#1960 no-brick), so the dead tunnel is now an
operator-visible error instead of a silent blackhole. Note an `ip-*` interface
defaults to `mode ipip` even without an explicit `mode` statement. Half 2 of
#4785 implements the decap stage; use `mode gre` or `mode wireguard` until then.

On a chassis cluster the rejection also covers the PEER's effective view. The
strict commit gate compiles only the submitting node, the RAW group tree is what
config-sync sends, and the standby ingests it leniently — so a `mode ipip`
endpoint that only `groups node1` resolves would commit green on node0 and
install on node1 with no strict check anywhere. `ValidatePeerEffectiveStrict`
(`pkg/config/compiler_peer_effective.go`) re-runs the gate against the peer's
effective compile at the ORIGIN's commit. `SyncApply` stays lenient, so a config
already on disk still boots.

**Operator cost.** `compileTreeStrict` evaluates the WHOLE candidate, so a box
whose active config already carries an emitted IPIP endpoint boots fine (the
ingress is lenient) but is then refused on EVERY subsequent commit — including
entirely unrelated ones — until the stanza is deleted. That is inherent to any
whole-candidate strict gate rather than specific to this one, but it is the
visible cost of the change: the first commit after an upgrade is where an
operator meets it.

A stanza that emits NO endpoint is not rejected — there is nothing dead in the
dataplane snapshot — but it can still create a kernel ANCHOR device, because
`collectAppliedTunnels` screens the interface level only on `tunnel source` and
screens units on nothing at all. Those get a standing advisory
(`ipipAnchorOnlyWarnings`) naming the device and the actual reason no endpoint
was emitted, covering interface-level AND unit-level records.

| Feature | Junos Config Path | Description | Priority | Status |
|---------|-------------------|-------------|----------|--------|
| **BFD** | `protocols ospf area ... interface ... bfd-liveness-detection ...` | Bidirectional Forwarding Detection for sub-second failure detection on routing adjacencies. FRR supports BFD natively. | High | **Done** -- OSPF (v2) and OSPFv3 (`protocols ospf3 area ... interface ... bfd-liveness-detection`, renders `ipv6 ospf6 bfd`, #2474) BFD with interval/multiplier via FRR profiles, IS-IS BFD support with optional interval/multiplier, BGP BFD multiplier configurable. |
| **BGP Import Policy** | `protocols bgp ... import <policy>` | Inbound route filtering on a BGP peer (`route-map ... in`). | Medium | **Done (#2490)** — `Import []string` parsed at global/group/neighbor scope (symmetric to `export`), rendered `neighbor <X> route-map <name> in` per neighbor/AF (`bgpEffectiveImport` + `lastNonEmpty`, most-specific-wins). Import has NO redistribute equivalent, so a ref MUST be a defined policy-statement: an undefined/bare-token ref is rejected at commit (lenient-warn on load/peer-sync) and SKIPPED at render (`isDefinedPolicyStatement` guard), never emitting a dangling `route-map in` (the #2473 permit-all leak, inbound side). The same `isDefinedPolicyStatement` guard was added to BOTH `route-map out` emit sites (#2539) so a per-neighbor export — newly parseable as of #2490 — cannot leak permit-all OUTBOUND on the lenient path either. Before #2490 the `import` clause parsed to nothing — a silent no-op. |
| **Graceful Restart** | `routing-options graceful-restart` | Non-stop routing during control plane restart. Keep forwarding while protocols reconverge. FRR supports GR. | Medium | Missing (FRR has GR but xpf doesn't configure it) |
| **Aggregate Routes** | `routing-options aggregate route ...` | Aggregate (summary) routes with policy control, different from generate routes in contributing route behavior | Medium | Partial (generate routes implemented but aggregate semantics differ) |
| **Martian Addresses** | `routing-options martians ... allow/exact/orlonger` | Configure additional martian (reserved) address filtering or allow specific martians | Low | Missing |
| **Forwarding Table Export** | `routing-options forwarding-table export ...` | Apply routing policy to routes exported from routing table to forwarding table. Used for ECMP load-balancing policy. | Medium | Partial (parsed but not fully wired to FRR) |
| **Multipath** | `routing-options multipath` | Protocol-independent load balancing for L3 VPN next-hops | Low | Missing |
| **Maximum ECMP Paths** | `routing-options maximum-ecmp N` | Limit number of ECMP paths installed in forwarding table | Low | Missing |
| **Nonstop Routing** | `routing-options nonstop-routing` | Maintain routing state during Routing Engine switchover | Low | Missing |
| **Multicast (PIM/IGMP)** | `protocols pim ...; protocols igmp ...` | PIM-SM/SSM/DM multicast routing, IGMP group management. vSRX supports multicast. | Medium | Missing |
| **L2 Learning** | `protocols l2-learning ...` | MAC learning and forwarding for transparent/bridge mode | Low | Missing |
| **Source Routing / SRv6** | `source-routing ...` | Segment Routing v6 for traffic engineering | Low | Missing |
| **MPLS / LDP** | `protocols mpls ...; protocols ldp ...` | MPLS label switching. Note: disables flow-based security on SRX. | Low | Missing |
| **Dynamic Tunnels** | `routing-options dynamic-tunnels ...` | Auto-created GRE tunnels for MPLS-over-GRE | Low | Missing |
| **Routing Policy Enhancements** | `policy-options policy-statement ... from protocol bgp ... then metric-type 2` | xpf has basic policy-statements. Missing: `from route-filter-list`, `from interface`, `from neighbor`, `then tag`. **`then as-path-prepend` Done (#2892)** — `then as-path-prepend "<asn> <asn> ..."` (quoted or bracketed list) renders FRR `set as-path prepend <asn> <asn> ...`. **`then community add/delete/set` Done (#2848).** | Medium | Partial (basic from/then exists, several match/action types missing) |
| **Route-filter match-types** | `from route-filter <prefix> {exact\|longer\|orlonger\|upto /n\|prefix-length-range /lo-/hi\|through <p2>}` | Junos route-filter match qualifiers used in import/export policy. | Medium | **Done for exact/longer/orlonger/upto/prefix-length-range; `through` rejected.** `prefix-length-range /lo-/hi` renders FRR `ge lo le hi` (#2525); bounds are validated at commit (low<=high, within family max, >= base prefix). `through <p2>` is a two-prefix radix-path containment that has **no lossless FRR prefix-list (ge/le) equivalent**, so it is **hard-rejected at commit** (lenient-warn on load/peer-sync per #1960) instead of silently degrading. Previously (pre-#2525) `prefix-length-range` and `through` committed but the renderer silently fell through to an open-ended `le 32`/`le 128`, leaking/dropping the configured constraint. |

---

## 15. VPN Enhancements

xpf has IPsec via strongSwan with IKE proposals, gateways, VPNs, XFRM interfaces, NAT-T, DPD modes, local/remote identity, local-certificate auth generation, DF-bit, establish-tunnels, and traffic selectors. These are additional VPN features.

| Feature | Junos Config Path | Description | Priority | Status |
|---------|-------------------|-------------|----------|--------|
| **Policy-Based IPsec VPN** | `security policies ... then permit tunnel ipsec-vpn <vpn>` | Bind an IPsec tunnel to a security policy (traffic matched by the policy enters the tunnel) instead of routing it out a route-based st0/XFRM interface. A top-5 vSRX idiom operators reach for immediately. | Medium | **Missing — rejected at commit (#3114).** xpf supports only route-based (st0/XFRM) IPsec: the `tunnel` modifier under `then permit` is hard-rejected at commit (`validatePolicyThenPermitStrict`, `pkg/config/compiler_policy_then.go`; lenient-warn on load/peer-sync per #1960) because `supportedPolicyThenPermitChildren` is empty and a silently-dropped `then permit` modifier would turn a permit-with-tunnel rule into an unconditional permit (a fail-open). Route the traffic to an st0 unit / XFRM interface bound to the IPsec VPN instead. |
| **SSL VPN / Juniper Secure Connect** | `security remote-access ...` | Client-based SSL VPN for remote access (Windows, Mac, Android, iOS). Web portal login. | Medium | Missing |
| **Remote Access IPsec VPN** | `security ike / ipsec + remote-access or access-profile workflow` | Road-warrior / client remote-access IPsec VPN distinct from site-to-site tunnels. The deployment guide explicitly calls out remote-access IPsec VPN support in addition to site-to-site. | Medium | Missing |
| **Dynamic VPN** | `security dynamic-vpn ...` | Simplified IPsec remote access with web-based client provisioning and access profiles | Medium | Missing |
| **AutoVPN** | `security ike gateway ... dynamic ...` | Auto-provisioned hub-and-spoke IPsec VPN. Hub accepts dynamic spoke connections using DNS names or any. | Medium | Missing |
| **ADVPN** | `security ipsec vpn ... advpn ...` | Auto Discovery VPN: dynamic spoke-to-spoke tunnels created on demand in hub-and-spoke topology | Low | Missing |
| **Group VPN (GVPNv2)** | `security group-vpn ...` | Group key management for multipoint VPNs with single SA for multiple endpoints | Low | Missing |
| **IPsec Traffic Selectors** | `security ipsec vpn ... traffic-selector ...` | Per-tunnel traffic selectors (proxy-IDs) defining which traffic enters the tunnel | Medium | Done (named `traffic-selector` entries compile into multiple child SAs and are reflected in runtime status parsing) |
| **PowerMode IPsec** | `security flow power-mode-ipsec` | VPP + Intel AES-NI acceleration for IPsec throughput. vSRX 3.0 feature. | Low | Missing |
| **IPsec SA Lifetime (kilobytes)** | `security ipsec proposal ... lifetime-kilobytes N` | Rekey based on data volume in addition to time-based lifetime | Low | Missing |
| **Dual-Stack IPsec Tunnels** | Multiple st0 units with inet+inet6 families | Parallel IPv4+IPv6 tunnels over single XFRM interface | Low | Missing |

---

## 16. HA Enhancements

xpf has a broad chassis cluster implementation with redundancy groups, RETH (VRRP-backed, virtual MAC), heartbeat, configurable per-RG gratuitous-arp-count, weight-based failover, session sync (RTO, per-RG aware), config sync, IP monitoring, election logic, VRRP, active/active per-RG service management, fabric forwarding, and ISSU. Remaining gaps are tracked below.

| Feature | Junos Config Path | Description | Priority | Status |
|---------|-------------------|-------------|----------|--------|
| **In-Service Software Upgrade (ISSU)** | `request system software in-service-upgrade ...` | Upgrade software without traffic interruption using cluster failover | Low | Done (`ForceSecondary()` drains all RGs to peer, operator replaces binary + restarts). The command waits (bounded) to OBSERVE the peer take over primary before printing the stop/swap instruction; if the handoff is not confirmed it warns and directs `show chassis cluster status` verification instead of certifying the drain from desired state alone (#5039). |
| **NAT State Synchronization** | `chassis cluster ... nat-state-synchronization` | Sync NAT translation table entries between cluster nodes for seamless failover | Medium | Done (session sync via RTO protocol includes SNAT/DNAT flags and NAT addresses in session_value struct) |
| **IPsec SA Synchronization** | `chassis cluster ... ipsec-session-synchronization` | Sync IPsec Security Associations between nodes. Avoids tunnel re-establishment after failover. | Medium | Done (primary sends active connection names every 30s; new primary re-initiates via `swanctl --initiate`) |
| **DHCP-server Lease Synchronization** | `chassis cluster ... dhcp-lease-synchronization` | Sync Kea DHCP-server lease bindings across the HA pair so a failover keeps client addresses + remaining lifetime and the promoted node never re-hands an in-use address. | Medium | Done (#2239 PATH C — re-instantiates the IPsec-SA-sync pattern over the existing session-sync channel: RG-MASTER reads leases via the Kea `lease_cmds` control socket (memfile fallback) and pushes the full set on a 30s heartbeat + a 2s on-grant change-detect; the BACKUP holds the peer set in xpf memory with Kea STOPPED (VRRP/RG stays the sole who-serves arbiter); on takeover the held leases are pre-seeded into the Kea memfile BEFORE start AND lease{4,6}-add'd after, re-anchored to the local clock (remaining-lifetime, clock-skew-immune). `show chassis cluster statistics` exposes DHCP-lease sent/received/seeded. See [pkg/cluster/README.md](../pkg/cluster/README.md) + [pkg/dhcpserver/README.md](../pkg/dhcpserver/README.md)) |
| **Active/Active Mode** | `chassis cluster redundancy-group N node 0 priority N node 1 priority N` (both nonzero) | Both nodes forward traffic simultaneously for different RGs. Per-RG VRRP service management, per-RG session sync with zone→RG mapping. | Medium | Done (per-RG service mgmt, per-RG session sync, per-RG election all implemented and tested) |
| **Redundant Ethernet (reth) Runtime** | `interfaces reth0 redundant-ether-options ...` | Bondless RETH via VRRP on physical member interfaces, virtual MAC per node (`02:bf:72:CC:RR:NN`), programRethMAC, VIP reconciliation, fabric forwarding (including embedded ICMP redirect for mtr/traceroute through secondary), `.link` files with OriginalName matching, session sync across nodes | Medium | Done (fully implemented and validated in cluster testing) |
| **Primary/Preferred Address per Interface** | `interfaces ... unit ... family inet address ... primary/preferred` | Select which address is used as source for traffic originated by the device. Syslog source address prefers PrimaryAddress, networkd orders primary first. | Low | Done (syslog source address + networkd ordering) |
| **vSRX Dual Fabric Syntax Compatibility (`fab0` + `fab1`)** | `interfaces fab0/fab1 fabric-options member-interfaces ...` | Native vSRX HA syntax models two fabric links. Requires multi-fabric transport/data-plane (not single `fabric-interface`). | High | Partial (parser/compiler/runtime support `fab0` + `fab1` syntax, dual-fabric sync transport, CLI visibility, and eBPF/userspace fabric forwarding; ~~DPDK dual-fabric parity~~ — DPDK retired #1525, moot) |
| **Fabric Link Redundancy** | `chassis cluster ... fabric-options member-interfaces` | Multiple fabric links between cluster nodes for data forwarding resilience. Linux bond/failover behavior should be consistent across runtime and networkd. | Low | Partial (networkd generation and runtime bond mode are inconsistent) |
| **IPv6 Control-Link Heartbeat** | control link (`em0`) with an IPv6 address | The node-to-node UDP heartbeat (port 4784) follows the configured control-link address family. | Low | Done (#4549 F9 — `StartHeartbeat` derives the UDP network from the control-link IP: a v6 control link binds `udp6`, a v4 control link stays `udp4` bit-for-bit; addresses are built with `net.JoinHostPort` so a v6 literal is bracketed. `selectClusterBindAddr` already returns an IPv6 candidate when the peer is IPv6, so this closes the only remaining IPv4-only hop in the heartbeat path. The near-universal deployment is an IPv4 point-to-point control link, so the v6 path is a parity/defense-in-depth item.) |
| **IPsec PSK in-memory zeroize** | n/a (defense-in-depth) | Wipe the IKE/IPsec pre-shared key from process memory after use, mirroring the WireGuard `Zeroizing<[u8;32]>` private key. | Low | Deferred (#4549 F10 — NOT driveable without a large refactor and marginal benefit. `config.Secret` is `type Secret string`; Go strings are immutable and may be interned / GC-copied, so a `Reveal()`-then-wipe is theater (no single owned mutable backing array to zero, and mutating a string via `unsafe` is UB that can corrupt shared copies). A real wipe requires converting `Secret` to `[]byte` with a `Zeroize()` across the whole config tree — 40+ field declarations, `== ""` present/absent checks, and map-key usages all rely on `Secret` staying a comparable string. Even then the PSK is rendered to the swanctl `secrets {}` block and written to disk as plaintext (`0600`, `pkg/ipsec/manager.go`) because strongSwan must read it, so the in-memory heap copy is secondary to the on-disk copy an equally-privileged attacker can already read. Contrast WireGuard: its key is an owned fixed `[u8;32]` loaded straight into the engine, never rendered to a third-party plaintext conf.) |

---

## 17. Firewall Filter Enhancements

xpf has firewall filters with source/dest addresses, prefix-lists (with except), DSCP, protocol, dest/source ports, ICMP type/code, TCP flags, fragment match, actions (accept/reject/discard), routing-instance, log, count, forwarding-class, loss-priority (parse-only/inert — see below), DSCP rewrite, and IPv6 traffic-class matching.

Filter `then reject` is now an **active** reject on the input, lo0
(host-bound) AND output (transit forward / TX/CoS) paths (#2521 + #3608): it
synthesizes a TCP RST (TCP) or ICMP/ICMPv6 admin-prohibited unreachable
(otherwise) using the SAME machinery as policy reject
(`poll_descriptor/reject_reply.rs`), runs the generated reply through #2238
output-filter/CoS/DSCP classification, and counts it on `filter_reject_sent`.
`then discard` stays a silent drop. Previously filter reject collapsed to a
silent drop (fail-closed parity gap). The output-firewall-filter case was
closed in #3608: the TX/CoS classifier carries a `reject` bit alongside the
collapsed `drop` bit, and the transit forward-request builder
(`build_live_forward_request_from_frame`) + the flow-cache-hit fast path
enqueue the reflected reply (original inbound frame → source via the ingress
interface) before dropping, emitting the output filter-log with the truthful
REJECT/DENY outcome (#3615). The only site that still collapses reject→drop is
the deferred-CoS dispatch path, which is unreachable in production (all
`PendingForwardRequest`s resolve CoS inline).

`from protocol <name>` resolution is centralized (#2175) on the same
`appid.ProtocolNumber` source of truth used by security-policy applications
(#2124), so every protocol a policy accepts a firewall filter accepts too: the
L4 subset (`tcp`/`udp`/`icmp`/`icmpv6`), the broader named set
(`gre`/`ospf`/`esp`/`ah`/`sctp`/`vrrp`/`igmp`/`pim`/`egp`/`ipip`/...), Junos
predefined aliases, and any numeric value `0`-`255` (including the deliberate
`0` for HOPOPT). An unrepresentable protocol token is **rejected at commit with
a clear error** naming the offending family/filter/term/token, rather than
silently degrading to "match protocol 0". The operator-visible refusal is
enforced at the config commit-check layer
(`config.validateFilterProtocolsStrict`, lenient warn-only on the load /
peer-sync path so a persisted/synced config still boots — #1960), with the
dataplane compiler (`validateFilterProtocols`) keeping an identical check as a
strictly-more-fail-closed backstop. Because `pkg/appid` imports `pkg/config`,
the commit-check gate INLINE-mirrors the `appid.ProtocolNumber` acceptance set
(it cannot import `appid` — an import cycle); a `pkg/appid` drift-guard test
pins the two together so the duplicated table cannot diverge silently.

The per-packet L4 match conditions — `tcp-flags`, `is-fragment`, `icmp-type`,
`icmp-code` — are wired end-to-end to the userspace dataplane (#2362). Earlier
they were parsed into `config.FirewallFilterTerm` and counted in this list but
silently DROPPED on the snapshot wire, so a term like `from { tcp-flags syn; }
then discard` matched broader than authored (discard-all-TCP). They are now
serialized as explicit `FirewallTermSnapshot` wire fields
(`tcp_flags`/`is_fragment`/`icmp_type`/`icmp_code`, mirrored in
`userspace-dp/src/protocol/security.rs`) and evaluated per packet by the Rust
matcher (`filter::engine::matching::per_packet_l4_matches`). Because none of
these are part of the 5-tuple `SessionKey`, a filter carrying any of them is
cache-sensitive (path (b) of the #1431 runbook): the flow-cache declines, the
on-session decision is re-evaluated per packet, and a config rotation purges the
affected sessions. This holds on BOTH the input/output forwarding-filter leg and
the CoS / TX-selection leg (`from { tcp-flags syn; } then forwarding-class X`):
the TX-selection evaluators thread the same per-packet inputs, so a CoS action
gated on a per-packet condition selects the class only on the matching packets
of a flow, not all of them (the flow-cache decline keeps the precomputed
TX-selection descriptor from being built for such filters). Fragment safety: the
match inputs are built fragment-safe — a NON-FIRST fragment carries no L4 header
at the post-IP offset (its bytes are payload), so the per-packet match inputs
carry an explicit `l4_present = false` flag for it and the matcher gates the
tcp-flags / icmp-type / icmp-code constraints on that flag (NOT on the byte
value). Keying off the value alone is insufficient: 0 is a VALID icmp-type
(echo-reply) and a VALID icmp-code, so a zeroed byte would still spuriously match
`from { icmp-type 0 }` / `from { icmp-code 0 }`. The L3-derived `is-fragment` bit
is NOT gated by `l4_present` and stays true (a non-first fragment IS a fragment).
This prevents a crafted fragment whose payload byte equals a filter's
`icmp-type`/`icmp-code` from spuriously matching (the #2344 non-first-fragment
class). Semantics: `tcp-flags <list>` requires ALL listed flags set
(a non-TCP packet never matches); `is-fragment` matches any IP fragment (IPv4 MF
set OR non-zero offset; IPv6 fragment header present); `icmp-type`/`icmp-code`
match the ICMP/ICMPv6 type/code bytes (a non-ICMP packet never matches).
Limitation: the parser produces a flat flag-name list, so the richer Junos
`tcp-flags "(syn & !ack)"` expression grammar (negation/disjunction/aliases like
`tcp-established`) is not representable — only a conjunction of named flags is
supported; an unrecognized token yields no constraint rather than a match-all.
Named `icmp-type`/`icmp-code` aliases (e.g. `echo-request`) are likewise not
parsed — numeric values only.

`from source-prefix-list <name>` / `destination-prefix-list <name>` (with the
optional `except` modifier) is wired end-to-end to the userspace dataplane
(#2506). Earlier the references were parsed into `config.FirewallFilterTerm`,
counted in this list, and pinned by tests, but the userspace snapshot builder
DROPPED them entirely — a term scoped by a prefix-list reached the dataplane
with NO source/destination address constraint, so e.g. `from
source-prefix-list mgmt except; then discard` became discard-ALL (fail-open for
accept/PBR, fail-closed for discard/reject — action-dependent). The Go snapshot
builder now RESOLVES each reference to its explicit CIDRs via
`cfg.PolicyOptions.PrefixLists` and merges them into the term's address set
(`resolvePrefixListAddrs`, `pkg/dataplane/userspace/filters.go`). The `except`
inversion is carried as the per-direction wire flags
`source_except`/`destination_except` on `FirewallTermSnapshot` (mirrored in
`userspace-dp/src/protocol/security.rs` with `serde(default)` for #1961 wire
parity); the Rust matcher evaluates `(addr ∈ prefixes) XOR except`
(`filter::engine::matching::nets_match_v4`/`nets_match_v6`). An UNDEFINED
prefix-list reference is now **rejected at commit with a clear error** naming
the family/filter/term/prefix-list (`validateFirewallPrefixListReferencesStrict`,
lenient warn-only on the load / peer-sync path so a persisted/synced config
still boots — #1960), mirroring the `then policer` / `then routing-instance`
gates (#2217). Junos semantics: a plain prefix-list reference OR's its prefixes
with any literal `source-address`/`destination-address` entries; `except` means
"match every address NOT in the list".

**Empty-resolution scope (#2506, Copilot):** the per-direction
`source_constrained`/`destination_constrained` wire flags record that the
operator SPECIFIED a scope for the direction (any literal address OR any
prefix-list reference), INDEPENDENT of whether resolution yielded any prefixes.
The Rust matcher derives "constrained" from this explicit flag (OR'd with the
address-length test), NOT from the resolved list length. Without it, a `from
source-prefix-list X` whose X is **defined-but-empty** (passes the strict gate)
or **unresolved on the lenient/peer-sync path** resolves to an empty address
list and the matcher would collapse the direction to match-ANY — accepting all
traffic for `then accept` (fail-open) or dropping wrong scope for `then
discard`. With the explicit flag, the matcher honors the Junos empty-set
semantics: a positive empty scope matches NOTHING (`addr ∈ {}` = none,
fail-closed via the `nets_match` empty guard returning `except` = false); an
`except` empty scope matches ALL (`addr ∉ {}` = all, the guard returns `except`
= true). Cross-family follows for free: a v4-only `... except` list has an empty
v6 vec, and a v6 address is trivially "not in" a v4 list, so the except term
matches v6 (the v4 list does not constrain v6).

Scope: the two clean cases — positive prefix-lists (with or without literal
addresses) and an `except` prefix-list as the SOLE address source for the
direction — are wired through. The MIXED case (literal/positive addresses AND an
`except` prefix-list in the SAME direction of ONE term) has no single
boolean-inversion representation (one direction would need both a positive set
and a negated set). **It is now hard-rejected at commit**
(`validateFilterAddressExceptStrict`, #3359) — Junos rejects the same
combination — so the operator is told to split the term. Before #3359 the
`except` modifier was silently dropped and its prefixes were FOLDED into the
positive set with only a runtime warning; that fold was **fail-OPEN**: a
`discard`/`reject` term no longer dropped the traffic the operator carved out via
`except`, and an `accept` term ADMITTED the prefixes the operator wrote to
exclude. On the tolerant load / peer-sync path (an already-persisted or
peer-synced config — #1960 no-brick) the gate downgrades to a warning and the
runtime is now **positive-wins** (the `except` prefixes are ignored, never folded
in): an `accept` term's admit set is no wider than the operator's positive scope
and a `discard`/`reject` term drops at least the positive set — fail-safe in both
directions. Splitting into two terms is the operator fix; the faithful structured
representation (a positive set AND a negated set per direction) is a documented
follow-up. This is the address-match sibling of the #3297 port-except gate.

**Firewall-filter `then loss-priority` is PARTIAL (parse-only, inert-with-warning, #2507).**
`then loss-priority <low|medium-low|medium-high|high>` is parsed and stored on
the term (`config.FirewallFilterTerm.LossPriority`) but is NOT carried on the
snapshot wire (`FirewallTermSnapshot` has no loss-priority field) and the
userspace dataplane has no per-packet loss-priority consumer: the three-color
policer always meters at `PacketColor::Green` (`apply_term_three_color_policer`)
and color-aware mode stays fail-closed until inherited packet color is carried
through trusted metadata (`userspace-dp/src/filter/README.md`). So the action
commits but does nothing. To avoid a silent QoS no-op, the commit now emits a
WARN-only message naming the family/filter/term
(`validateFilterLossPriorityWarnings`, `pkg/config/compiler_validate_warn.go`),
mirroring the existing CoS classifier/rewrite loss-priority warnings. It is a
warning, never a reject — loss-priority is valid Junos and a hard reject would
brick a config that was previously accepted. Wiring an actual per-packet
loss-priority action onto the egress CoS/drop-profile path is the follow-up;
until then the action is documented as inert.

**`security pre-id-default-policy then log` is PARTIAL (parse-only, inert-with-warning, #2509).**
`security pre-id-default-policy then log session-init/session-close` is parsed
and stored on `config.PreIDDefaultPolicy.LogSessionInit/LogSessionClose` but has
NO consumer in the userspace dataplane after the eBPF retirement (#1373/#1476).
The only reader was the retired eBPF compiler (`pkg/dataplane/compiler.go`,
which mapped the bits to `FlowConfigValue.AppFlags`). Unlike the per-policy
#2508 path — where the admitting policy's log flags are stamped onto session
metadata at install and gate RT_FLOW emission — the userspace runtime has no
pre-identification session-admit path: app-id is best-effort labeling of
already-admitted sessions, not a "default policy admits the session before
app-id resolves, then re-evaluate" pipeline. There is therefore no session to
stamp the pre-id log mode onto, and no field is wired to the dataplane (wiring
one would dead-end in a no-op). To avoid a silent logging no-op, the commit now
emits a WARN-only message naming the configured mode(s)
(`validatePreIDDefaultPolicyLogWarnings`, `pkg/config/compiler_validate_warn.go`),
mirroring the #2507 filter loss-priority / CoS loss-priority warnings. It is a
warning, never a reject — pre-id-default-policy is valid Junos and a hard reject
would brick a config that was previously accepted. Adding a real
pre-identification session-admit + re-evaluation pipeline is the prerequisite
follow-up before this logging signal can be produced.

| Feature | Junos Config Path | Description | Priority | Status |
|---------|-------------------|-------------|----------|--------|
| **Filter change does not revoke established sessions** | `interfaces <if> unit <u> family inet filter input <name>` | Junos firewall filters are stateless and evaluated on EVERY packet, so a newly attached or tightened input filter applies to established flows immediately | Medium | Partial (#5858): the session-hit fast path re-evaluates an input filter only when its match semantics vary per packet (DSCP / per-packet L4 — `interface_input_filter_varies_per_packet`), so a purely STATIC address/protocol/port `then discard` added after a session exists is never rechecked and that flow forwards until it idles out. Note the asymmetry with policies: tightening a POLICY does revoke established sessions at commit (`clearSessionsForPolicyChanges`). The symmetric fix is not safe — an interface-keyed clear would drop every session ingressing the interface, and a purged permitted SNAT flow reinstalls on a different translated port (the PAT allocator hands out a fresh monotonic-cursor port before draining the recycle FIFO) — so the correct fix is per-tuple revalidation that drops only NEWLY-denied sessions, tracked as a dataplane feature. Until then commit emits an advisory naming the affected units and the `clear security flow session interface <name>` remedy. |
| **Filter loss-priority action** | `firewall filter ... term ... then loss-priority <level>` | Mark a packet's packet-loss-priority for downstream drop-profile / congestion behavior | Low | Partial (#2507): parsed and stored, but NOT wired to the snapshot wire and inert in the userspace dataplane (no per-packet loss-priority consumer; three-color policer meters at green only). Commit emits a WARN naming the filter/term that the action is accepted-but-inert. |
| **Pre-ID default-policy logging** | `security pre-id-default-policy then log session-init session-close` | Log sessions admitted under the pre-identification default policy (before app-id resolves) | Medium | Partial (#2509): parsed and stored, but NOT wired to the dataplane and inert in userspace — there is no pre-identification session-admit path (no session to stamp the log mode onto, unlike per-policy #2508). Commit emits a WARN that the action is accepted-but-inert. |
| **Policer (Rate Limiting)** | `firewall policer ... bandwidth-limit N burst-size-limit N` | Token-bucket rate limiter applied to filter terms or interfaces. Single-rate two-color, three-color policers. | High | Partial for #1373: legacy eBPF/~~DPDK~~ (DPDK retired #1525) token-bucket policer support existed. **#4514: single-rate `then policer` is now ENFORCED on the userspace dataplane** — a `then discard` policer is lowered at compile into the metered three-color srTCM runtime (committed bucket = the token bucket, CIR=bandwidth-limit bits/sec, CBS=burst-size-limit), so traffic above the rate is discarded with metering + drop counters + flow-cache re-metering. Before #4514 the single-rate policer was parsed into a `state.policers` map that nothing consumed, so `then policer X` was a silent fail-open of the rate limit. A single-rate policer with a non-discard action (`then loss-priority` / `then forwarding-class`) is metered but its marking is inert. #1375 is closed; unsupported color-aware/non-drop behavior and broader Junos parity remain production/future parity work, not active #1373 source-removal blockers. |
| **Three-Color Policer** | `firewall three-color-policer ...` | RFC 2697/2698 metering with green/yellow/red marking based on CIR/CBS/EBS or CIR/PIR | Medium | Legacy eBPF/~~DPDK~~ (DPDK retired #1525) done; userspace AF_XDP supports color-blind `then discard` with compatible snapshot continuity. A policer with no explicit color statement defaults to color-blind (Junos parity, #4535) and is enforced rather than disarming forwarding. #1375 is closed; remaining color-aware/non-drop action parity plus integration, failover, and performance hardening are production/future parity work, not active #1373 source-removal blockers. |
| **Interface Policer** | `firewall policer ... logical-interface-policer` | Aggregate rate limiting across all protocol families on a logical interface | Low | Missing |
| **Interface ARP Policer (H9)** | `interfaces <if> unit <n> family inet\|inet6 policer arp <name>` | Per-logical-interface ARP rate limiter | Low | Reject-at-commit (#2008 H9): xpf has no per-interface ARP policer, so the stanza is hard-rejected at commit/commit-check (lenient warning on load/peer-sync per #1960) instead of being silently dropped. Real enforcement is a net-new dataplane subsystem. |
| **Interface Static MAC (H10)** | `interfaces <if> [unit <n>] mac <addr>` | Static MAC-address override on a logical/physical interface | Low | Reject-at-commit (#2008 H10): the interface MAC is read-only (cluster RETH MAC is computed deterministically per node via `programRethMAC`), diverging from this Junos override. Hard-rejected at commit (lenient warning on load/peer-sync) instead of silently dropped. |
| **Flexible Match Conditions** | `firewall filter ... term ... from flexible-match-range ...` | Match on arbitrary byte offsets within packet header for custom protocol matching | Low | Done (#3077): the byte-offset match (match-start layer-3) is serialized into the userspace snapshot (`FlexMatchSnapshot` on `FirewallTermSnapshot`) and evaluated in the Rust filter engine — read `length` bytes (1..4) at `offset` from the L3 header, AND with `mask`, require `== value`. Bounds-checked and FAIL-CLOSED (a packet too short for the window, or any path without the frame, does not match). Cache-sensitive (flow-cache declines). Before #3077 it was parsed/compiled for the retired legacy dataplane but DROPPED on the userspace wire, so the constraint vanished and the term matched too broadly (fail-open). Single range per term (the compiler's `break`); `match-start` other than layer-3 is not emitted. #3203 (agy-070 #02/#03/#04) closed three lowering edge cases on top of #3077: (1) byte length now CEIL-rounds (`(BitLength+7)/8`, capped at 4) so a non-multiple-of-8 bit-length such as 12 bits reads 2 bytes instead of truncating to 1 (which silently fail-closed); (2) a malformed/oversized numeric token (byte-offset, bit-length, match-value, match-mask) is now a strict COMMIT error (`validateFilterFlexMatchStrict`, downgraded to a warning on the tolerant load/peer-sync path per #1960) instead of being silently ignored and leaving the field at its zero default (a >32-bit match-value used to become 0x0 and match the WRONG pattern with a clean commit); (3) the default mask is now the low `BitLength` bits for ANY 1..32-bit length (24-bit → 0x00FFFFFF, 12-bit → 0x00000FFF), not 0xFFFFFFFF for every non-8/16 length (which the ceil-byte read could never satisfy). Byte-aligned 8/16/32-bit configs are byte-identical to the #3077 result. #3232 (agy-071 #10) added the `match-start layer-4` base and closed the silent-wrong-offset hole: `match-start` is now carried on the wire (`FlexMatchSnapshot.MatchStart` → Rust `flex_match_start`) — `layer-3` (default, "" on the wire so layer-3 stays byte-identical) reads from the L3 header, `layer-4` reads from the transport header (`meta.l4_offset`, threaded via `TermMatchExtra::flex_l4`, fail-closed on a non-first fragment / meta-only path). `match-start payload` (and any other value) is a valid Junos token but is NOT implemented; it is now a strict COMMIT error (`validateFilterFlexMatchStrict`, downgraded to a warning on the tolerant path) and, defense-in-depth, lowers to `FlexMatchStart::Unsupported` (fail-closed) if it ever reaches the matcher. Before #3232 a `layer-4`/`payload` config committed clean but was silently evaluated at the L3 base — a wrong-offset / security-evasion match. `payload` start (offset from the end of the L4 header) remains unimplemented. |
| **Firewall Filter on lo0** | `interfaces lo0 unit 0 family inet filter input ...` | Host-bound traffic filtering — config parsed, compiled to filter IDs, evaluated natively in xdp_forward for host-bound packets, plus kernel nftables fallback | Medium | Done. #3231 (agy-071 #06/#08/#09) fixed three fail-OPEN lowering bugs in the kernel-nft mirror (`nftRuleFromTerm`, `pkg/daemon/daemon_nft.go`): the lo0 ruleset loads atomically, so any one invalid line rejected the WHOLE table and left the host control-plane filter with no rules. (1) TCP flags lowered the RAW Junos tokens with a comma join (`tcp flags syn,&,!ack`) — invalid nft, and even a plain list (`tcp flags syn,ack`) is a disjunctive set, not the Junos AND-conjunction, with forbidden flags unrepresentable. Now reuses `config.ParseTCPFlagsExpression` to emit the canonical masked-equality form `tcp flags & (mentioned-mask) == required`. (2) `source-port-except` / `destination-port-except` (parsed since #2622/#3205) were DROPPED, so a `discard`-except term blocked the exempt ports and an accept-all-except-SSH term silently permitted SSH; now emits `th sport != …` / `th dport != …`. (3) `is-fragment` emitted IPv4-only `ip frag-off & 0x1fff != 0` unconditionally even in the inet6 chain (an nft syntax error in v6); now family-conditioned — `ip frag-off …` for ip, `exthdr frag exists` for ip6. The atomic-load fail-OPEN behaviour itself (071-07: a rejected ruleset leaves NO lo0 filter, vs fail-closed / lifeline ruleset) is a design question tracked separately, not changed here. |

---

## 18. QoS / Class of Service

Note: The vSRX deployment guide markets CoS as part of the standard feature set, but the user guide also calls out important CoS limitations on vSRX, such as the lack of high-priority SPC queue support. xpf now has a userspace-only CoS path with forwarding-class parsing, scheduler-map binding, interface-bound DSCP classifier attachment, egress shaping, timer-wheel deferred eligibility, and guarantee/surplus queue scheduling, but it is still materially narrower than Junos CoS.

| Feature | Junos Config Path | Description | Priority | Status |
|---------|-------------------|-------------|----------|--------|
| **Forwarding Classes** | `class-of-service forwarding-classes queue <num> <name>;` | Define custom forwarding class names mapped to queue numbers | Low | Done |
| **Scheduler Maps** | `class-of-service scheduler-maps ...` | Associate forwarding classes with schedulers (bandwidth %, priority, buffer) | Low | Done |
| **Schedulers** | `class-of-service schedulers ...` | Define per-queue scheduling parameters (transmit rate, priority, drop profile) | Low | Partial (userspace supports transmit-rate, `transmit-rate exact`, priority, buffer-size, `surplus-sharing` (#915 — non-Junos extension that opts an `exact` queue into surplus-phase participation while keeping its per-queue rate as a guarantee floor), and `equal-flow-enforcement` (#1304 — non-Junos opt-in, mutually exclusive with `surplus-sharing`, that lets shared exact v8 leases suppress faster workers toward the slowest sampled per-active-SFQ-bucket grant rate). `transmit-rate percent <n>` / `transmit-rate remainder` are accepted for vSRX-config import parity (#4228 Gap 2) but ACCEPTED-BUT-INERT — the dataplane consumes an absolute rate and xpf does not yet resolve the percent/remainder against the bound interface's rate (commit advisory). The fuller Junos scheduler/drop-profile model remains missing) |
| **BA Classifiers** | `class-of-service classifiers dscp ...` | Classify incoming traffic by DSCP/802.1p into forwarding classes and loss priorities | Low | Partial (userspace supports DSCP and 802.1p classifier definitions plus interface attachment as fallback queue selectors, but not loss-priority enforcement and not broader non-userspace BA classifier parity) |
| **Rewrite Rules** | `class-of-service rewrite-rules dscp ...` | Rewrite outgoing DSCP/802.1p values. | Low | Partial (userspace supports DSCP rewrite-rule definitions plus interface attachment on shaped egress interfaces, and firewall filters can also set DSCP rewrite directly; 802.1p rewrite and broader parity are still missing) |
| **WRED Drop Profiles** | `class-of-service drop-profiles ...` | Weighted Random Early Detection congestion avoidance per queue | Low | Missing |
| **Traffic Shaping** | `class-of-service interfaces ... shaping-rate ...` | Per-interface output rate shaping | Low | Partial (userspace-only egress shaping with bounded guarantee service, strict-priority surplus selection, same-priority weighted DWRR, non-`exact` surplus borrowing, timer-wheel deferred eligibility, deterministic queue-owner spreading, and per-shaped-egress-interface shared-root budget leasing across queue owners/workers on that same interface. `traffic-control-profiles ... shaping-rate percent <n>` is accepted for vSRX-config import parity (#4228 Gap 2) but ACCEPTED-BUT-INERT — the dataplane enforces an absolute shaping-rate and xpf does not yet resolve a percent against the interface speed (commit advisory); not full Junos CoS parity) |
| **Interface CoS Binding** | `class-of-service interfaces ... scheduler-map ...` | Bind scheduler-map and classifiers to specific interfaces | Low | Partial (userspace supports scheduler-map binding plus DSCP / 802.1p classifier and DSCP rewrite-rule attachment on shaped interfaces, but broader non-userspace semantics are still missing) |

---

## 19. Multi-Tenancy

Logical systems and tenant systems are supported on vSRX starting from Junos 20.1R1.

| Feature | Junos Config Path | Description | Priority | Status |
|---------|-------------------|-------------|----------|--------|
| **Logical Systems (LSYS)** | `logical-systems ...` | Partition device into independent virtual firewalls. Each LSYS has own zones, policies, routing instances, NAT, address books. | Medium | Missing |
| **Tenant Systems (TSYS)** | `tenants ...` | Lightweight multi-tenancy. Single routing instance per tenant but supports higher tenant count. | Medium | Missing |
| **Security Profiles** | `system security-profile ...` | Resource limits per LSYS/TSYS: max sessions, NAT rules, policies, zones, VPNs | Low | Missing |
| **Inter-LSYS Traffic** | `logical-systems ... security policies from-zone ... to-zone ...` | Security policies between logical systems via logical tunnel (lt) interfaces | Low | Missing |

---

## 20. Management & Automation

xpf has gRPC (48+ RPCs), REST API, Junos-style CLI (local + remote), Prometheus metrics, config commit/rollback, and event-options. These are additional management features.

| Feature | Junos Config Path | Description | Priority | Status |
|---------|-------------------|-------------|----------|--------|
| **NETCONF/YANG** | `system services netconf ...` | Standards-based config management (RFC 6241). Enables Ansible, Salt, Terraform, ncclient integration. XML-based RPC. | High | Missing |
| **Configuration Groups** | `groups { name { ... } }; apply-groups name` | Template inheritance for config reuse. Apply common settings to multiple stanzas without duplication. | Medium | Done (general-purpose groups/apply-groups with inheritance priority, `apply-groups-except`, `${node}` variable support, `CompileConfigForNode()` for HA per-node config) |
| **Deactivate Without Delete (`inactive:`)** | `inactive: <statement>` (set via `deactivate <path>`) | Mark any statement deactivated without deleting it: retained in the config DB, shown in `show configuration`, survives commit/reboot, re-enableable — but excluded from compilation/application. The config-management equivalent of commenting code out. | Medium | Done — parse/persist/display/strip (#2008 H1, `pkg/config` `Node.Inactive` + centralized `WithoutInactive` strip before group-expand/compile and schema-validate; re-emitted by all five serializers + `show \| compare`). Reached today by loading config text containing `inactive:`; the `activate` / `deactivate` CLI verbs are a separate increment. |
| **Commit Scripts** | `system scripts commit ...` | Pre-commit validation scripts (SLAX/Python) that enforce config standards and generate warnings/errors | Low | Missing |
| **Op Scripts** | `system scripts op ...` | Custom operational commands via SLAX/Python scripts | Low | Missing |
| **RADIUS Authentication** | `system radius-server ...; system authentication-order radius` | External RADIUS authentication for management access (SSH, CLI, web) | Medium | Missing |
| **TACACS+ Authentication** | `system tacplus-server ...; system authentication-order tacplus` | External TACACS+ authentication with per-command authorization | Medium | Missing |
| **SNMP v3 USM** | `snmp v3 usm local-engine user ...` | Full SNMPv3 with authentication (SHA/MD5) and privacy (AES/DES). xpf parses v3 users but runtime may be incomplete. | Medium | Partial (parsed, needs runtime verification) |
| **SNMP Traps/Notifications** | `snmp trap-group ... targets ...` | SNMP trap generation on events (link up/down, auth failure, etc.). xpf parses trap-groups and sends linkUp/linkDown. | Medium | Partial — SNMPv2c linkUp/linkDown implemented (`pkg/snmp/traps.go` `buildLinkTrap` / `NotifyLinkUp` / `NotifyLinkDown`, OIDs `1.3.6.1.6.3.1.1.5.4` / `.5.3`, sent over UDP/162 to configured targets, wired from `pkg/daemon/daemon_flow.go`). Missing trap classes: authentication-failure, cold/warm-start, HA role change, and policy/security alarms. |
| **J-Web / Full Web GUI** | `system services web-management ...` | Full web-based management UI with dashboard, wizards, monitoring, policy editor. xpf has basic REST API. | Low | Missing |
| **XML/JSON Config Export** | `show configuration | display xml/json` | Export configuration in XML or JSON format for automation tooling | Low | Missing |
| **Junos Telemetry Interface (JTI)** | `services analytics / streaming telemetry` | Push-model streaming telemetry for counters, sensors, and analytics pipelines. Explicitly listed as supported on vSRX in the feature tables. | Low | Missing |
| **Cloud-init / Metadata User-Data Bootstrap** | `N/A (deployment/bootstrap workflow)` | Initialize a vSRX instance from validated Junos configuration passed through cloud metadata or config-drive user-data. Extensively documented for OpenStack, AWS, and GCP. | Medium | Missing |
| **Bootstrap ISO Provisioning** | `N/A (deployment/bootstrap workflow)` | Provision first-boot configuration from a bootstrap ISO image attached as a virtual disk. Documented in the deployment guide for KVM and VMware workflows. | Low | Missing |
| **Junos Space / Security Director** | N/A (external management platform) | Centralized multi-device policy management. Not applicable as a feature of xpf itself. | Low | Missing (N/A) |
| **Rescue Configuration** | `request system configuration rescue save` | Saved fallback configuration that can be loaded on boot if active config fails | Low | **Done.** `request system configuration rescue save`/`delete` are implemented — `SaveRescueConfig`/`DeleteRescueConfig` persist the active config text to `rescue.conf` (owner-only 0600, #4056; DurableState #1894) in `pkg/configstore/store_persist.go`, wired through `pkg/cli/cli_request.go`. |

---

## 21. Interface Enhancements

xpf manages all interfaces with .link/.network files, supports VLANs, tunnel interfaces (GRE, IP-IP, XFRM), DHCP, VRRP, MTU, speed/duplex, disable, per-interface sampling (input/output, per-family), forwarding-options sampling instances with inline-jflow, and per-interface firewall filters.

| Feature | Junos Config Path | Description | Priority | Status |
|---------|-------------------|-------------|----------|--------|
| **Link Aggregation (LAG/ae)** | `interfaces ae0 ...; interfaces ge-0/0/0 gigether-options 802.3ad ae0` | Bundle physical links into aggregate ethernet for bandwidth and redundancy. Different from reth. | Medium | Done (LACP/802.3ad parsing + bond/netdev generation + member enslaving) |
| **Transparent Mode (L2 Bridging)** | `interfaces ... family ethernet-switching; bridge-domains ...` | Layer 2 bridge mode where firewall acts as transparent inline device. Zone-based policies still apply. MAC learning table. | Medium | Missing |
| **Flexible VLAN Tagging** | `interfaces ... flexible-vlan-tagging; encapsulation flexible-ethernet-services` | Q-in-Q (802.1ad), flexible VLAN push/pop/swap operations. xpf has basic 802.1Q single-tag. | Low | Partial (single 802.1Q/802.1ad tag only) — `flexible-vlan-tagging`, `encapsulation flexible-ethernet-services`, and `inner-vlan-id` are PARSED into typed config (`pkg/config/compiler_interfaces.go:74,299`, stored in `InnerVlanID`) but have NO downstream consumer: networkd creates no stacked-VLAN device (only bond/bridge get `.netdev`), and the AF_XDP shim strips exactly ONE tag (`userspace-xdp/src/lib.rs:1091`, `if` not `while`) then XDP_PASSes a double-tagged frame to the kernel (`lib.rs:376` `_` arm → `pass_non_ip_l2_direct`). So QinQ/stacked-VLAN transit is NOT supported in the userspace dataplane (forwarding/CoS-ECN/NAT64/policy/TX). No flexible push/pop/swap. **Honest-posture gate (#2354):** because a committed `inner-vlan-id` is a false promise of firewalled stacked-VLAN transit, `validateUnsupportedInterfaceStanzasAST` (`pkg/config/compiler_interfaces_unsupported.go`, the #2008 H9/H10 doctrine) now HARD-REJECTS `interfaces <if> unit <n> inner-vlan-id <x>` at commit / commit-check and WARNS (does not fail) on the tolerant load / peer-sync path. The gate keys strictly on `inner-vlan-id`, so single 802.1Q / 802.1ad tagging via `vlan-id` (and `flexible-vlan-tagging` WITHOUT an inner tag) stays accepted — that path is correct (#2346). The multi-layer QinQ feature build (two-tag parse/deliver/serialize + networkd stacked netdev + inner-tag zone binding) stays plan-deferred pending operator demand; the 4-PR decomposition lives in issue #2354. (The #2354 `inner-vlan-id` reject has since been generalized to the canonical both-node QinQ gate `validateQinQVLANStackAST`, #5879, covering the `vlan-tags outer/inner` spelling and peer-only-group views.) **Flexible push/pop/swap honesty gate (#6178):** `input-vlan-map` / `output-vlan-map` (per-unit VLAN tag push/pop/swap rewrite) are likewise not in `setSchema` and have no compiler consumer, so a configured rewrite was silently dropped — not a firewall bypass (the frame is still firewalled at its arriving tag depth), but a false promise. `validateVLANMapAST` (`pkg/config/compiler_interfaces_vlanmap.go`) now HARD-REJECTS them at commit / commit-check and WARNS on the tolerant load / peer-sync path (`lenientVLANMap`), mirroring the #5879 both-node doctrine. |
| **Interface Bandwidth** | `interfaces ... bandwidth ...` | Set logical interface bandwidth for OSPF cost calculation and traffic-engineering | Low | Done (parsed and rendered into FRR interface bandwidth) |
| **IRB Interfaces** | `interfaces irb unit N family inet address ...; bridge-domains bd0 { vlan-id-list ...; routing-interface irb.0; }` | Integrated Routing and Bridging: kernel Linux bridge per bridge-domain, IRB addresses on bridge device, zone assignment, .netdev/.network generation | Medium | Done (config parsing, compiler, networkd bridge/member/IRB generation, zone resolution) |
| **Point-to-Point** | `interfaces ... unit ... point-to-point` | Mark interface as point-to-point (affects OSPF network type, ND behavior) | Low | Done (parsed and emitted as FRR OSPF point-to-point where applicable) |
| **Primary/Preferred Address** | `interfaces ... unit ... family inet address ... primary/preferred` | Control which address is used for sourced traffic. Syslog source and networkd ordering implemented; not yet used for all device-originated traffic. | Low | Partial (syslog source + networkd ordering, not all traffic) |
| **Interface Description** | `interfaces ... description "..."` | xpf parses descriptions. Verify they appear in `show interfaces` output. | Low | Done (description displayed in interface output paths) |

---

## 22. System Enhancements

xpf has hostname, domain-name, domain-search, timezone, name-servers, NTP, services (SSH with root-login and key-exchange/`KexAlgorithms`, web-management, DNS), syslog, SNMP, login users/classes (including per-user `authentication encrypted-password` for console login — #1944, see [docs/system-login.md](system-login.md)), root-authentication, archival, internet-options, backup-router, DHCP server (Kea), and ~~DPDK~~ config (DPDK retired #1525, removed in #1527/#1528).

| Feature | Junos Config Path | Description | Priority | Status |
|---------|-------------------|-------------|----------|--------|
| **SSH Key Exchange** | `system services ssh key-exchange ...` | Restrict the SSH key-exchange (KEX) algorithms the firewall offers | Medium | Done (H5/#2008 — repeatable leaf rendered to the sshd `KexAlgorithms` drop-in, `pkg/daemon/daemon_system.go`; drop-in lifecycle hardened in #2062 — removing/emptying the ssh stanza removes the `/etc/ssh/sshd_config.d/xpf.conf` drop-in and reloads so sshd reverts to base-image defaults, and a reload failure after a write reverts the drop-in to its prior content/removes it so a bad config never breaks the next sshd restart) |
| **Syslog File Archive / Rotation** | `system syslog file <name> archive { files <n>; size <bytes>; start-time <t>; transfer-interval <min>; archive-sites <url>; }` | Rotate `/var/log/<name>` at a size threshold, retain N archives, and transfer them off-box on a schedule | Low | Missing — accepted-but-inert with a commit advisory (#7146). The whole block is modeled in `setSchema` and compiled by nothing: #4303 folded `archive` into `compileSystem`'s recognized-modifier skip list, and `applySyslogFiles` writes only an rsyslog drop-in pointing at `/var/log/<name>`. #7146 keeps it unimplemented and makes it LOUD instead of silent — the block is recorded on `SyslogFileConfig` (`ArchiveConfigured` / `ArchiveKnobs`, keywords only) and `ValidateConfig` emits one per-file advisory naming the file and its knobs and stating the logs are NOT archived. Warn, never reject: the stanza commits today and a reject would fail the tolerant load / peer-sync path (#1960). Implementing it needs rotation, size accounting, a transfer schedule, and an `scp` path that would then owe the #4589 leading-dash gate that guards `system archival configuration archive-sites`. See [docs/config-schema.md](config-schema.md) "Syslog file `archive` is accepted-but-inert (#7146)". |
| **RADIUS Server Config** | `system radius-server ... port ... secret ...` | RADIUS server definitions for AAA (authentication, authorization, accounting) | Medium | Missing |
| **TACACS+ Server Config** | `system tacplus-server ... port ... secret ...` | TACACS+ server definitions for per-command authorization | Medium | Missing |
| **Authentication Order** | `system authentication-order [radius tacplus password]` | Control order of authentication methods for management access | Medium | Missing |
| **Auto-Image Upgrade** | `system autoinstallation ...` | Zero-touch provisioning for initial deployment | Low | Missing |
| **Time Zone (wired)** | `system time-zone ...` | xpf applies the configured timezone to the system runtime | Low | Done (daemon updates `/etc/localtime` and `/etc/timezone`) |
| **NTP Threshold Action** | `system ntp threshold ... action ...` | Action when NTP offset exceeds threshold (accept or reject large time jumps) | Low | Done (maps to chrony `logchange` for `accept` and `logchange` + `maxchange` for `reject`, and is shown in operational output) |
| **Master Password** | `system master-password ...` | Encrypted password storage with master key for config secrets | Low | Done (active/candidate/rollback config trees are encrypted at rest with a node-local master key derived using the configured PRF) |
| **DNS Proxy** | `system services dns dns-proxy ...` | DNS proxy/caching server on firewall for client DNS resolution | Low | Missing |
| **DHCP Dynamic DNS** | `system services dhcp-local-server dynamic-dns ...` | Publish forward A/AAAA + reverse PTR records for active DHCP leases and clean them on expire/release/reassign/config-removal | Medium | Done (#1387 — inc-1 config + reconciler + never-delete-non-owned store; inc-2 LIVE RFC 2136 backend via miekg/dns, always-on daemon reconcile loop, NODE-LEVEL HA single-writer gate (MASTER for ≥1 RG), `xpf_dhcp_ddns_*` metrics + `show system services dhcp-server dynamic-dns`; default `replace-owned` is RFC 4701/4703 DHCID-ownership-safe (#2648 — DHCID-marker add via name-not-in-use→DHCID-match two-attempt, DHCID-match-guarded delete; never adopts/deletes a third-party RR); `skip-existing` is the SAME refusal-sentinel-safe (#2660 — a name-already-exists collision returns `errDDNSConflictRefused` so no phantom ownership is recorded and a later release never deletes the third-party RR); live Kea→DNS e2e + `make test-failover`-with-DDNS are lab-gated. See [pkg/dhcpserver/README.md](../pkg/dhcpserver/README.md)). Deferred: Kea D2 backend, explicit forward-zone/reverse-zone/publish-ptr leaves |
| **DHCP Static / Fixed Bindings** | `system services dhcp-local-server group <g> pool <p> static-binding <mac> { fixed-address <ip>; host-name <n>; }` (and the `dhcpv6-local-server` equivalent) | Pin a client (by hardware address) to a fixed/reserved address from the DHCP server | Medium | Done (#2243 — schema-completed + commit-validated `static-binding` typed subtree on both v4/v6 pools; compiles to `DHCPPool.StaticBindings`; renders to Kea per-subnet `reservations` (`hw-address`→`ip-address[es]`+`hostname`); strict commit checks reject malformed/family-mismatched/out-of-subnet/duplicate bindings; HA-consistent via the existing config-sync — no per-lease replication. Dynamic-lease HA sync is the separate companion #2239. See [pkg/dhcpserver/README.md](../pkg/dhcpserver/README.md)) |

---

## 23. Miscellaneous Features

| Feature | Junos Config Path | Description | Priority | Status |
|---------|-------------------|-------------|----------|--------|
| **802.1X Network Access Control** | `protocols dot1x ...` | Port-based network authentication on access ports | Low | Missing |
| **SCTP Protocol Support** | `security policies ... match application junos-sctp` | SCTP-aware firewall with multi-homing and stream tracking | Low | Missing |
| **Geneve Flow Infrastructure / AWS GWLB** | `security tunnel-inspection ... profile ... geneve ...` | Geneve tunnel decapsulation/encapsulation, VNI and vendor-TLV-based policy attachment, and AWS GWLB metadata handling for tunnel-endpoint and transit-router deployment modes. The current repo has no runtime Geneve/GWLB implementation beyond design references. | Low | Missing |
| **VPLS** | `routing-instances ... instance-type vpls` | Virtual Private LAN Service for L2 VPN | Low | Missing |
| **Storm Control** | `forwarding-options storm-control ...` | Broadcast/multicast storm protection | Low | Missing |
| **TAP Mode** | `security forwarding-options ... tap-mode` | Passive monitoring mode (copy of traffic, no inline blocking) | Low | Missing |

---

## Priority Tiers

### Tier 1 - High Priority (Core NGFW / Common vSRX Features)
Features most commonly used in production vSRX deployments:

1. ~~**Proxy ARP/NDP for NAT**~~ - **Done** (proxy ARP with GARP; proxy NDP pneigh install + responder sysctl wired in #2197 item 1; 30s re-assert in #2197 item 2)
2. ~~**Session Limiting (source/dest-ip)**~~ - **Done** on the legacy BPF path (GC sweep + BPF LRU maps + xdp_screen enforcement); userspace admission is tracked in `userspace-dataplane-gaps.md`.
3. ~~**Firewall Filter Policers**~~ - **Legacy done** (token bucket: single-rate, two-rate RFC 2698, single-rate-3c RFC 2697; eBPF + ~~DPDK~~ (DPDK retired #1525)). Userspace supports the color-blind `then discard` three-color slice; #1375 is closed. Remaining color-aware/non-drop and broader Junos parity work is production/future parity, not active #1373 source-removal work.
4. ~~**BFD**~~ - **Done** (OSPF/IS-IS/BGP BFD via FRR profiles)
5. **NETCONF/YANG** - Industry-standard management, enables automation tooling
6. **Unified Policies / AppID** - Foundation of modern NGFW (long-term, high complexity)
7. **IDP/IPS** - Core NGFW feature differentiator (consider Suricata/Snort integration)

### Tier 2 - Medium Priority (Enterprise Features)
Features commonly requested in enterprise deployments:

8. **RADIUS/TACACS+ Authentication** - Enterprise AAA integration
9. **SSL VPN / Remote Access VPN** - Remote worker connectivity
10. **Remote Access IPsec VPN** - Road-warrior IPsec parity beyond site-to-site tunnels
11. **Aggressive Session Aging** - **Config-only (#3440)** — Go-side GC watermark hysteresis exists but is skipped on the userspace AF_XDP dataplane (the only runtime path); accepted-but-not-enforced with a commit advisory + typed/bounded schema. Per-application `inactivity-timeout` (#3227) is the separate, enforced idle-timeout knob.
12. **Graceful Restart** - Non-stop routing (FRR already supports)
13. ~~**Twice NAT**~~ - **Done** (zone-aware static DNAT + post-DNAT SNAT matching + both-leg session visibility)
14. **Transparent Mode (L2)** - Inline transparent firewall deployment
15. ~~**Link Aggregation (LAG)**~~ - **Done**
16. **PKI / Certificate-Based IPsec** - Certificate-based VPN authentication
17. **SecIntel / GeoIP** - Threat intelligence integration
18. **Captive Portal / User Firewall** - User-based access control
19. **Logical Systems (LSYS)** - Multi-tenancy

### Tier 3 - Low Priority (Specialized / Niche)
Features for specific use cases or carrier deployments:

20. Content Security (UTM) - AV/web-filtering (consider ClamAV/rspamd)
21. SSL Proxy - TLS inspection (consider mitmproxy integration)
22. Multicast (PIM/IGMP)
23. MPLS/LDP
24. EVPN/VXLAN
25. Geneve / AWS GWLB - cloud overlay and load-balancer insertion workflows
26. Junos Telemetry Interface (JTI) - push telemetry / analytics pipelines
27. Cloud-init / Bootstrap ISO - cloud and first-boot deployment parity
28. AppQoE
29. DS-Lite/6rd/MAP-E
30. GTP Firewall
31. SD-WAN
32. PowerMode IPsec
33. Class of Service - partial/limited on vSRX, still materially broader than xpf today

---

## Parse-Only Features Summary

These features have config parsing in xpf but no runtime effect.

Note: This includes parse-only knobs that are outside the core category gap
table, so this list count can be higher than the category-level Parse-Only total.

| # | Config Path | Type | Notes |
|---|------------|------|-------|
| 1 | `system license autoupdate url` | SystemConfig.LicenseAutoUpdate | No licensing system |
| 2 | `system syslog file <name> archive { files, size, start-time, transfer-interval, archive-sites, world-readable, no-world-readable }` | SyslogFileConfig.ArchiveConfigured / .ArchiveKnobs | Recorded at compile ONLY so the #7146 commit advisory can name the block; no runtime consumer. No rotation, retention, schedule, or off-box transfer exists for a syslog file — `applySyslogFiles` writes an rsyslog drop-in pointing at `/var/log/<name>` and nothing more. Keywords are recorded, never values (an `archive-sites` URL can embed credentials). |

## Runtime Follow-Up Features Summary

No feature rows currently carry open #1373 runtime follow-up work. Closed
contracts such as #1378 remain documented in their feature rows as closeout
evidence, not as active eBPF source-removal blockers.

---

## Implementation Suggestions for Top Gaps

### Proxy ARP for NAT (Tier 1) -- DONE
- Proxy ARP neighbor entries (NTF_PROXY) for NAT addresses with GARP on addition
- Per-interface `net.ipv4.conf.<if>.proxy_arp` responder sysctl enabled for every
  interface with a proxy entry (#2160). The kernel has two ARP-proxy paths: the
  pneigh (NTF_PROXY) reply branch answers only when the target routes out a
  *different* interface and does NOT require the sysctl; the `arp_fwd_proxy` path
  is gated by the sysctl. So whether the sysctl is load-bearing is route-topology
  dependent -- a same-L2-subnet external address (the #2160 case) is answered by
  neither path until the sysctl is enabled.
- IPv6 (proxy-NDP, #2197 item 1, completing #2160): an IPv6 address under
  `proxy-arp` now installs the kernel v6 NTF_PROXY *neighbor table* entry (the v6
  analogue of `ip -6 neigh add proxy <addr> dev <if>`) in addition to enabling the
  `net.ipv6.conf.<if>.proxy_ndp` sysctl. The kernel answers a v6 NS only with
  forwarding + `proxy_ndp` + a matching v6 pneigh entry (`net/ipv6/ndisc.c`), so
  all three pieces are wired -- v6 static-NAT / NAT64 external proxy is functional
  end-to-end. v6 is `pneigh_lookup`-gated (per-address by construction), so there
  is no v6 over-answer breadth; the narrowing concern below is IPv4-only. A
  v4-mapped (`::ffff:a.b.c.d`) literal classifies as IPv4 and takes the v4 path.
- Periodic re-assert (#2197 item 2): the reconcile is idempotent and also driven
  by an always-on 30s ticker (`proxyARPReassertLoop`, started unconditionally when
  the dataplane is enabled, in both standalone and cluster modes). A kernel link
  DOWN/UP *outside* a config commit (HA RETH member flap, `programRethMAC` link
  cycle) re-defaults the per-interface `proxy_arp`/`proxy_ndp` sysctl; the ticker
  re-asserts the desired state within ~30s so the interface self-heals without an
  operator re-commit. Each tick runs the reconcile under the apply semaphore
  (`d.applySem`, the same lock the commit/config-apply path holds across
  `store.Commit` + `applyConfigLocked`), so a re-assert can never interleave with
  a commit that *removes* a responder and re-install the removed responder from a
  stale pre-commit config snapshot -- it always reconciles the post-commit
  `ActiveConfig` (#4001).
- Removal teardown (#2475 sysctl + #4955 neighbor entry): a commit that drops an
  interface (or its last address) from `proxy-arp` tears down BOTH the leaked
  `proxy_arp`/`proxy_ndp` sysctl AND the installed `NTF_PROXY` neighbor entries.
  The daemon remembers the last-installed `(iface -> families)` set; on each
  reconcile it feeds those prior interfaces back into `ReconcileProxyARP` as the
  `priorIfaceMap`, so the stateless dataplane reconcile lists the removed
  interfaces, finds their `NTF_PROXY` entries absent from the desired set, and
  `NeighDel`s them (#4955) before disabling the sysctl (#2475). Full removal
  (config now has zero entries) still runs the reconcile for exactly this sweep.
  Without it the neighbor entry was orphaned in the kernel and kept answering ARP
  for the retired IPv4 via the route-topology-dependent pneigh branch until a
  link reset/reboot -- attracting traffic to an obsolete translation or a
  reassigned VIP. The add path is also best-effort: a mid-add `NeighSet` failure
  no longer nils out the remembered set, so a later removal can still tear down
  what was installed.
- Breadth tradeoff (IPv4): with the default `medium_id=0`, `proxy_arp=1` makes the
  kernel answer ARP on that interface for ANY target routed out a different
  interface -- broader than Junos `proxy-arp`, which proxies only the listed
  addresses. This is operator-opted-in (they configured proxy-arp on the
  interface) but matters on a WAN/untrust interface. Per-address narrowing
  (#2197 item 3) is **PLAN-DEFER / lab-pending**: the sysctl is load-bearing for
  the same-L2 #2160 case, so dropping it to gain Junos parity would re-break that
  case; any narrowing ships only after a lab repro confirms a pneigh-only
  different-device topology answers without it.
- Config: `set security nat proxy-arp interface <iface> address <addr>` with address range support

### Session Limiting (Tier 1) -- DONE
- GC sweep counts active sessions per source/destination IP, pushes to BPF LRU maps
- xdp_screen enforces limits on TCP SYN
- Config: `set security screen ids-option <name> limit-session source-ip-based <N>` / `destination-ip-based <N>`

### Firewall Filter Policers (Tier 1) -- PARTIAL; #1375 CLOSED
- Token bucket policer with single-rate two-color, two-rate three-color (RFC 2698), and single-rate three-color (RFC 2697) modes
- eBPF parity (DPDK retired #1525); userspace supports the color-blind `then discard`
  three-color slice
- #1375 is closed. Remaining color-aware/non-drop behavior and broader Junos
  parity are production/future parity work, not active #1373 source-removal
  blockers.

### BFD (Tier 1) -- DONE
- OSPF (v2) BFD with interval/multiplier via FRR profiles
- OSPFv3 BFD with interval/multiplier via FRR profiles (renders `ipv6 ospf6 bfd`, #2474)
- IS-IS BFD support with optional interval/multiplier
- BGP BFD multiplier configurable (was hardcoded to 3)

### NETCONF (Tier 1)
- Consider using `openconfig/gnmic` or `netopeer2` for NETCONF server
- Map to existing gRPC RPCs for config get/set
- YANG models can be generated from existing config types

---

## #2008 vSRX config-parity closures (Increment 1, batch 1)

Quick-win gaps from the `#2008` parity audit (stored-but-unenforced / schema
drift) closed in `fix/2008-quickwins-batch1`:

- **M4 `security policy-stats system-wide`** — DONE. Per-policy hit
  counter collection (`collectPolicyCounters` in `pkg/api/metrics_counters.go`)
  is now gated on `cfg.Security.PolicyStatsEnabled`. Previously the flag
  compiled into typed state but counters were always collected; Junos only
  maintains per-policy stats when the knob is enabled (default off).
  **#2118 follow-on (DONE):** M4 gated only the Prometheus collector; the
  text/structured display surfaces read the per-rule counters
  unconditionally, so the surfaces disagreed. All SIX display surfaces are
  now gated on the same knob: Prometheus (`metrics_counters.go`), gRPC text
  `show security policies hit-count` and `... detail`
  (`pkg/grpcapi/server_show_policies_text.go`), the structured gRPC
  `GetPolicies` block (`pkg/grpcapi/server_show_zones.go`), the REST
  `GET /api/v1/security/policies` endpoint (`pkg/api/security.go`), and the
  local CLI `show security policies hit-count` + `... brief` views
  (`pkg/cli/cli_show_security.go`, `pkg/cli/cli_show_security_dispatch.go`).
  When `policy-stats system-wide enable` is absent (the default), all six
  report 0 per-rule counts; when set, they all report the same live counts.
  The raw read primitive (`Manager.ReadPolicyCounters`) and
  `clear security policies hit-count` stay ungated by design. The Rust increment
  (`policy.rs` `try_match_rule` for the first packet, plus the established
  fast-path / flow-cache re-count added in #3073, see below) stays always-on —
  the gate is display-only, so enabling the knob surfaces counts that accrued
  while it was off, and no wire-format change was needed. NOTE: the per-rule hit-count chain itself (increment →
  coordinator snapshot → `policy_rule_counters` wire array → Go
  `ReadPolicyCounters`) was already intact and Go-unit-tested; #2118's "reads
  0" was the display-gate inconsistency above plus the smoke running with the
  knob off (and explicit-deny rows correctly reading 0 because the loss
  cluster config has only explicit permit rules + `default-policy deny-all`,
  so blocked traffic rides the implicit default-deny — which bumps the
  aggregate `policy_deny` counter, not any per-rule counter).
  **#3074 per-policy `then count` override (DONE):** before #3074 the
  per-policy Junos `then count` modifier was parsed/stored (`Policy.Count`,
  `pkg/config/types_security.go`) but carried NO runtime meaning — the six
  display surfaces above gated solely on the system-wide
  `policy-stats system-wide enable` knob, so a `then count` policy reported
  0 unless the operator ALSO enabled the global knob (the issue's "inert
  compatibility" complaint). #3074 makes `then count` a per-policy display
  selector: every surface now admits a rule's counter when
  `statsEnabled || pol.Count` (`||rule.Count`), so a `then count` policy
  reports its packets/bytes independent of the global knob (Junos
  per-policy `count`), while a policy without `then count` keeps the
  pre-#3074 behavior (0 with the knob off). REUSE-not-rebuild decision: the
  Rust per-rule counter is already always-on and per-packet (#3073), and
  the gate was already display-only with no dataplane read of the knob, so
  `then count` needs NO new Rust counter and NO wire field — it is a
  Go-side display selection over the existing #3073 counter, using the
  `Policy.Count` flag already present in the active config. Fail-on-revert
  tests: `pkg/cli/cli_show_policies_thencount_3074_test.go`,
  `pkg/grpcapi/server_show_policies_thencount_3074_test.go`, plus the
  #3074-aware updates to the M4/#2118 gate tests
  (`pkg/api/metrics_test.go`, `pkg/api/policy_counters_test.go`,
  `pkg/grpcapi/server_show_zones_test.go`): a `then count` policy surfaces
  its live counts with the knob OFF; a sibling without it stays 0.
- **Runtime policy-ID namespaces under app-set expansion — #3145 FIXED,
  #3143 found to be a misdiagnosis.** TWO distinct numeric namespaces coexist
  by design, and conflating them is the trap this work clarified:
  - The **dataplane snapshot PolicyID** is span-accumulated:
    `policySetID*MaxRulesPerPolicy + ruleIndex`, where `ruleIndex` advances by
    the application-set expansion count (one slot per expanded term). This
    namespace serves the dataplane and the RT_FLOW/event path and is assigned
    by `walkPolicyRuleSlots` / `buildPolicySnapshots`
    (`pkg/dataplane/userspace/policies.go`).
  - The **per-policy COUNTER read path is name-keyed.** The userspace helper
    reports each rule's packets/bytes under its stable RuleID string
    (`from->to/name`); the expanded rules of a multi-app policy aggregate
    under that one name. `ReadPolicyCounters`'s numeric `policyID` argument is
    only a HANDLE the read callers use to ask "which policy do I want a name
    for", and EVERY production caller (`pkg/api/metrics_counters.go`,
    `pkg/api/security.go`, `pkg/cli/cli_show_security*.go`,
    `pkg/grpcapi/server_show_*.go`) builds that handle as
    `policySetID*MaxRulesPerPolicy + sliceIndex` — the raw position in
    `zpp.Policies`, NOT the expanded `ruleIndex`.

  **#3145 (WRITE side, real bug — FIXED):** `buildPolicySnapshots` advanced
  `ruleIndex` by the expansion count with no `MaxRulesPerPolicy` guard. A set
  whose cumulative expansion pushed a policy's ID past index 255 spilled the
  next policy's snapshot PolicyID into the following set's base namespace,
  mis-attributing RT_FLOW policy IDs and colliding the dataplane/event
  namespace. The legacy guard in `compiler.go` is the retired-eBPF path and
  never fires here. The fix routes ID assignment through `walkPolicyRuleSlots`,
  which enforces the cap fail-closed — a policy whose expansion would require an
  ID at index >= `MaxRulesPerPolicy` (256) is rejected at snapshot build (the
  apply path retains the prior good dataplane state).

  **#3404 (off-by-one in the #3145 cap — FIXED):** the cap originally used `>=`
  (`ruleIndex+span >= MaxRulesPerPolicy`), which rejected a set that EXACTLY
  fills its 256-slot namespace (indices 0..255) even though every ID stays in
  the set's own namespace. The boundary was changed to `>` in both
  `walkPolicyRuleSlots` and the legacy `compiler.go` mirror, so a set with
  exactly 256 rules arms and only the 257th rule (which would need index 256)
  is rejected. Cross-set namespaces stay disjoint: set N's last ID is
  `N*256+255`, set N+1's first is `(N+1)*256`, so the corrected boundary cannot
  let them collide. Boundary tests cover exact-256 accept / 257 reject /
  no-cross-set-collision for both the userspace and legacy paths.

  **#3143 (READ side, misdiagnosis — no functional change):** the issue
  assumed `policyRuleIDForCounter`'s `policyID % MaxRulesPerPolicy` was wrong
  because it read the remainder as a slice index. In fact that exactly matches
  the slice-index handle every counter caller passes, so on master a policy
  AFTER a multi-app policy already resolved to the CORRECT counter. The
  counter store is name-keyed and the legacy `bpfShim` `policy_counters` array
  is never incremented in userspace mode, so the numeric handle never indexes
  a span-accumulated array — there is nothing to "round-trip" against; the
  only requirement is caller/resolver agreement, and both use the slice index.
  An initial attempt to make the resolver span-accumulated was itself a
  regression (it mapped a caller's slice-index handle into the preceding
  expanded policy's span) and was reverted; the resolver retains the
  slice-index decode with an expanded comment documenting the dual namespace.

  **#3474 (READ side, defensive SSOT-alignment on nil slots — FIXED):** two
  consumers of the raw-slice-index counter namespace were the lone holdouts
  that did not agree with the walker + all other callers on how to number a
  NIL slot, so this aligns them. It is DEFENSIVE hardening, NOT a reachable-bug
  fix: a nil `cfg.Security.Policies` set (or a nil rule within a set) is not
  produced by any production config path today — strict and tolerant compile
  share a non-nil-only builder (`compiler_security.go` appends only non-nil
  `compilePolicy()`/`zpp`), HA ships recompiled config TEXT, and persistence
  round-trips the tree — so a normally-compiled config never exercises these
  paths. The alignment matches the existing #3476/#3494 defensive nil-guards.
  - **Resolver set index.** `walkPolicyRuleSlots` and every counter caller
    advance `policySetID` for a nil element of `cfg.Security.Policies`
    (`if zpp == nil { policySetID++; continue }`), but `policyRuleIDForCounter`
    skipped a nil set WITHOUT incrementing its `currentSet`. For a hypothetical
    `cfg.Security.Policies = [nil, {lan->wan,...}]` the callers assign the real
    set `policySetID == 1` while the resolver's set index would lag at 0, never
    match, fall through to the global/empty branch, and return `""`. The fix
    adds `currentSet++` to the resolver's nil branch so the
    resolver/walker/callers can never drift.
  - **REST rule handle.** `pkg/api/security.go` computed the zone-pair counter
    read handle as `policySetID*MaxRulesPerPolicy + len(pi.Rules)` — the
    COMPACTED (nil-skipped) running rule count — whereas the resolver and every
    other caller (`metrics_counters.go` `policyCounterID(policySetID, i)`,
    `cli_show_security*.go`, `server_show_policies_text.go`, and this handler's
    OWN global-policy loop) key off the raw slice index `uint32(i)`. With a nil
    rule before a real rule the compacted count lags the slice index and the
    handle drifts. The fix switches the zone-pair handle to `uint32(i)` so ALL
    counter handles sit on the one raw-slice-index SSOT.

  Regression tests in
  `pkg/dataplane/userspace/policy_namespace_3143_3145_test.go`: the 255/256/257
  -term cap boundary plus a literal spill-collision (#3145, fail-on-revert on
  the cap), and an end-to-end counter test combining app-set expansion with a
  per-policy counter assertion through the slice-index caller handle (the
  coverage the suite lacked — fail-on-revert against a span-accumulated
  resolver). `TestPolicyCounterResolverCountsNilPolicySetsLikeWalkPolicyRuleSlots`
  adds the #3474 nil-leading-slot fixture: it pins the resolver/walker/caller
  agreement on set numbering (fail-on-revert when the nil branch skips without
  `currentSet++`) with a no-nil control proving no regression.
  `pkg/api/security_policy_counter_handle_3474_test.go`
  (`TestPoliciesHandlerCounterHandleUsesRawSliceIndex`) injects a leading nil
  rule and asserts the REST handler reads the raw-slice-index counter handle,
  not the compacted one (fail-on-revert against `len(pi.Rules)`).
- **Per-policy hit-count is PER-PACKET — FIXED (#3073).** Before #3073 the
  per-rule packet/byte counter was incremented exactly once per flow — on the
  cold (session-miss) path inside `policy.rs` `try_match_rule`. The established
  session fast path and the flow-cache hit replay never re-counted the
  admitting rule, so `show security policies hit-count` reflected only the
  FIRST frame of each flow: a permitted TCP session moving millions of packets
  reported `packets=1` and only the first frame's bytes, defeating audits and
  vSRX parity. The fix stamps a stable 1-based hit-counter handle
  (`SessionMetadata::policy_counter_idx`, resolved via
  `PolicyState::hit_counter_by_idx`) onto the session at install and re-counts
  every established packet against the admitting rule on both fast paths
  (`poll_descriptor` session-hit + `flow_cache_hit`). **#3322 update:** that
  1-based handle is POSITIONAL — stable within one snapshot but not across a
  live policy insert/reorder, which renumbers the rule table so the same index
  points at whatever rule now occupies the slot (the original admitting rule
  stops counting; an inserted rule appears to carry established traffic it
  never admitted). #3322 binds the admitting rule's SHARED counter `Arc`
  (`SessionMetadata::policy_counter`) onto the session at install — when the
  index is still correct — and the established fast path prefers that bound
  handle over re-resolving the positional index
  (`PolicyState::resolve_session_hit_counter`). The bound `Arc` is the same
  instance the persistent `PolicyCounterStore` re-hands for a surviving stable
  `rule_id` across snapshot rebuilds, so it follows the admitting rule through
  reorders; when the rule is deleted the bound `Arc` is simply no longer read
  by `counter_snapshots` (count goes nowhere), never a misattribution. The
  bound handle is local derived state (NOT serialized); a peer-synced session
  carries only the positional `policy_counter_idx` and falls back to idx
  resolution at materialize (pre-#3322 behavior; HA requires identical config
  so the idx resolves the same rule at sync time — but a reorder AFTER a synced
  session was created still mis-attributes that session's count on the peer,
  pending a future rule-id-on-wire identity change). The cold path still
  counts the first packet once and `resolve_flow_session_decision` runs no
  policy evaluation, so each packet is counted exactly once. Reverse (reply)
  traffic counts against the same rule via the reverse-companion / shared
  materialize metadata. The per-packet increment is coalesced in a per-worker
  thread-local (`record_policy_hit_counter`) and folded into the shared counter
  once per RX batch — the same technique `filter::record_filter_counter` uses —
  so the hot path never touches the shared counter cacheline per packet. The
  handle is in-process only (rides the shared-session map and worker replicas
  but NOT the cross-node HA `SessionDeltaInfo` wire yet, mirroring the #3056
  `policy_id` deferral): a peer-promoted session counts nothing on the
  promoting node's policy counter until a local re-evaluation re-stamps a
  handle.
- **Per-policy hit-count reset semantics — INTENTIONAL Junos divergence
  (FLAGGED, behavior unchanged).** Junos resets per-policy hit counters on a
  commit that changes the policy. xpf PRESERVES counts across recompile as
  long as the stable `from-zone->to-zone/name` rule identity is unchanged
  (`PolicyCounterStore::reconcile_rules` retains the `Arc<PolicyRuleCounter>`
  by `rule_id`; a renamed/deleted rule loses its count). This is deliberately
  more useful for long-running rules and is left as-is; it is documented here
  rather than changed. Per-policy hit counts are also per-node (node-local),
  not cluster-aggregated, matching Junos per-node behavior.
- **Per-NAT-rule "Translation hits" — FIXED (#2218).** `show security nat
  source rule`, `... destination rule`, and `... static rule` reported
  "Translation hits: 0 packets 0 bytes" for every rule even under live,
  confirmed-translating traffic: the #1476 eBPF retirement deleted the legacy
  XDP per-packet `nat_rule_counters` increments and the Rust forwarder never
  replaced them, so nothing wrote the counter the operator read path
  (`Manager.ReadNATRuleCounter`) still consulted. The fix mirrors the policy
  hit-count chain exactly: the compiler assigns a per-rule `counter_id`
  (`assignNATCounterID`, single SSOT for SNAT/DNAT/static in
  `compiler_nat.go`; DNAT and static had NO counter ID before, so DNAT hits
  never displayed at all), the snapshot builders stamp it onto each rule
  (`SourceNATRuleSnapshot`/`DestinationNATRuleSnapshot`/
  `StaticNATRuleSnapshot.CounterID`), the Rust dataplane keeps an
  `Arc<NatRuleCounter>` per rule (`NatCounterStore`, the NAT analogue of
  `PolicyCounterStore`) and bumps it once per committed translated forward
  flow on the cold (session-miss) path, and the counts ride
  `ProcessStatus.nat_rule_counters` (counter_id/packets/bytes) → the Go
  control plane's `syncBPFCountersLocked` → `Manager.SetNATRuleCounterOffset`
  → the `bpfShim` `nat_rule_counters` offset that `ReadNATRuleCounter` merges.
  INTENTIONAL semantic divergence from vSRX (FLAGGED): xpf counts PER-FLOW
  (one packet + its bytes per new translated flow), not per-transit-packet, so
  the displayed "packets" is the translated-flow count, not the total
  translated packet count; the value is node-local and resets on helper
  restart. The fast (established-flow) transit path adds no per-packet work —
  the increment is cold-path only, allocation-free, a single relaxed atomic.
- **H14 `security flow power-mode-disable`** — DONE (threaded). The parsed
  `cfg.Security.Flow.PowerModeDisable` now reaches the dataplane via
  `FlowSnapshot.PowerModeDisable` (`pkg/dataplane/userspace/protocol.go` +
  `buildFlowSnapshot`) and the Rust `FlowSnapshot`/`ForwardingState`
  (`power_mode_disable`, mirroring `gre_acceleration`). vSRX power-mode is an
  express datapath; the userspace dataplane has a single forwarding path, so
  the flag is carried for config truth/parity and does not currently switch
  packet behavior (there is no express/regular split to select between).
- **`security flow gre-performance-acceleration`** — DONE (threaded, #3360).
  The parsed `cfg.Security.Flow.GREPerformanceAcceleration` reaches the
  dataplane via `FlowSnapshot.GREAcceleration` (`buildFlowSnapshot` +
  `pkg/dataplane/userspace/protocol.go`) and the Rust
  `FlowSnapshot`/`ForwardingState` (`gre_acceleration`, mirroring
  `power_mode_disable`). Before #3360 the bit was deserialized on the Rust side
  and rendered in `show security flow` but never assigned into runtime state —
  a silent config-truth gap (the Go wire comment even claimed "extract GRE key
  into session ports", behavior that never happened). On vSRX the knob extracts
  the GRE key/call-id into the session tuple so multiple GRE tunnels between the
  same endpoints map to distinct sessions; the userspace dataplane keys GRE
  flows on the 5-tuple only, so the flag is now threaded into the Rust
  `ForwardingState` for config truth/parity but is NOT yet read by any
  packet/forwarding path (the field is still `#[allow(dead_code)]`). The
  consumer — GRE key/call-id extraction into the session tuple — is the deferred
  feature, and this is the seam it would read; it is not part of this
  config-truth fix.
- **M9 `security flow tcp-session no-sequence-check`** — DONE (typed). Added
  the schema child (`pkg/config/schema_security.go`), the
  `TCPSessionConfig.NoSequenceCheck` field (`pkg/config/types_security.go`),
  and the compiler case (`pkg/config/compiler_security.go`), at full parity
  with the existing `no-syn-check` / `rst-invalidate-session` presence flags.
  Like those siblings it is typed-config only: the userspace AF_XDP dataplane
  performs no TCP sequence-number window validation today, so there is nothing
  to skip. The field gives commit-time validation + completion and is the seam
  a future sequence-checking dataplane would read. As of #2078 the whole
  `tcp-session` presence-flag family (`no-syn-check`,
  `no-syn-check-in-tunnel`, `rst-invalidate-session`, `no-sequence-check`)
  emits a single accepted-only commit advisory so an operator is not silently
  misled into believing any of these knobs has runtime effect; research #2078
  converged PLAN-KILL on enforcement (the dataplane has no TCP state machine,
  proportionality favours warn-and-document for these LOW, rarely-used knobs).
- **H6 residual — `system login user <name> class` enum validation** — DONE.
  RBAC was already enforced (`pkg/cli/permissions.go`); the remaining hole was
  that the `class` leaf accepted any string at commit and `config-viewer` was
  missing. Added `ValidateEnum` on the `class` schema leaf
  (`pkg/config/schema_system.go`) with the allowed set derived from
  `LoginClassPermissions` (`config.ValidLoginClasses()`), and added a
  `config-viewer` RBAC entry (PermView) so the schema enum and the runtime RBAC
  table cannot drift. Mirrors the SNMP `authorization` enum leaf. See
  `docs/system-login.md`.

## #2008 vSRX config-parity closures (Increment 2)

Tier-2 gaps from the `#2008` parity audit researched in
`docs/research/2008-tier2/plan.md`:

- **M7 `event-options policy attributes-match`** — DONE (literal → regex).
  Junos `attributes-match "<event>.<attribute> matches <pattern>"` is a regex
  match; xpf previously did literal string equality
  (`pkg/eventengine/engine.go` `attributesMatch`). The matcher now treats the
  pattern as an RE2 regex (unanchored = substring, like Junos), compiled once
  at `Apply()` time and cached by pattern string so the event hot path never
  recompiles. Commit-time validation rejects an uncompilable pattern
  (`config.ValidateEventAttributesMatch` via `CompileConfig`,
  `pkg/config/event_options_match.go`). The parse/validate seam
  (`config.ParseEventAttributesMatch`) is shared between the compiler and the
  engine so they cannot drift. **Behavior-change note:** this is NOT
  behavior-preserving for a stored literal containing regex metacharacters —
  but regex IS the correct Junos behavior. **#3756 H14 (bounded parity, DONE):**
  the supported attribute set now also includes the three STATIC per-test config
  strings `target`, `routing-instance`, and `destination-interface` (they are
  stable identifiers already in scope at every `rpm.fireEvent` call site, so no
  hot-path cost and no new taxonomy). This lets a policy match "all probes to
  target X" or "all probes in routing-instance Y". Added to
  `config.EventAttributesKnownFields` (SSOT), the `rpm.Event` struct, and the
  `attributesMatch` runtime switch (kept identical by the drift-guard test).
  **Also pinned (#3756 M1/M2):** `within { trigger on N }` is EDGE-triggered
  (fires on the crossing, re-arms below N) and `within { trigger until N }` is
  the INCLUSIVE N-th (the `until 1` dead-config bug is fixed) — see
  `pkg/eventengine/README.md`. **Still DEFERRED (design recorded, low demand):**
  numeric attributes (`rtt` / `jitter` / loss-threshold — regex-over-a-number
  needs a canonical string FORMAT decision) and a `failure-reason` taxonomy (rpm
  has no failure classifier today — timeout vs unreachable vs setup-error would
  need a new reason enum). Neither is a fail-open hole; both are additive parity
  surface gated on a concrete request. See `pkg/eventengine/README.md`.
- **H13 Stage 1 `forwarding-options allow-dataplane-sleep`** — DONE
  (schema + field + commit warning). The leaf was previously accepted as a
  no-schema-match fall-through and silently dropped by
  `compileForwardingOptions`. Stage 1 adds the typed presence-flag schema leaf
  (`pkg/config/schema_routing.go`), the `ForwardingOptionsConfig.AllowDataplaneSleep`
  field (`pkg/config/types_system.go`), compiler extraction
  (`pkg/config/compiler_services.go`), and a commit warning that the knob is
  accepted but the idle-yield runtime is not yet implemented (the userspace
  workers busy-poll), mirroring the `persist-groups-inheritance` /
  `dns-proxy` accepted-but-unenforced warnings. Stage 2 (actual worker
  idle-yield) is lab-gated and deferred per the research doc — the busy-poll
  cold-start latency sensitivity (#1782) is the reason it needs explicit
  validation before enabling.
