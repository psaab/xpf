# vSRX Feature Gaps — xpf vs Juniper vSRX

Comprehensive gap analysis between xpf and Juniper vSRX. Organized by category.
Last updated: 2026-02-13

> # ⚠️ STALE — DO NOT USE FOR PLANNING OR GAP-REPORTING
>
> Status: Historical snapshot (2026-02-13). Superseded by
> `docs/feature-gaps.md`, `docs/feature-coverage.md`, and
> `docs/authoritative-backlog.md`, which are the authoritative truth for
> any feature's status. The section tables below are preserved for history
> only. A parity review that re-reports a row below as a "gap" without
> cross-checking the authoritative docs will chase phantom gaps.
>
> **Concretely, the following whole sections have SHIPPED since this
> snapshot and their rows below are WRONG:**
>
> - **§5 High Availability — the ENTIRE section (all 8 rows) shipped:**
>   Chassis Cluster, Session Sync, Redundancy Groups, Redundant Ethernet
>   (bondless-RETH runtime), Fabric Links (dual fab0/fab1 + cross-chassis
>   forwarding), ISSU, Graceful Switchover (priority-0 burst, ~1ms
>   takeover), IP Monitoring for Failover (#1827).
> - **§3 Routing:** BFD (OSPF/OSPFv3/IS-IS/BGP), OSPFv3, and BGP import
>   all shipped; the routing-policy row's claims are stale.
> - **§2 NAT:** Twice NAT, NAT Proxy ARP Done; deterministic / address-shifting
>   NAT is Done for BOTH IPv4 subscribers (mode 1) and IPv6/NAPT64 subscribers
>   (mode 2), enforced on the userspace dataplane (#4559).
> - **§4 VPN:** IPsec DPD (#3994) and traffic selectors — Done. (Policy-
>   based IPsec VPN remains a real gap — rejected at commit, #3114; see
>   `docs/feature-gaps.md` §15.)
> - **§6 Management:** apply-groups, System Login Classes (RBAC), SNMP v2c
>   traps (linkUp/Down), SNMPv3 USM (partial), event policies — all
>   shipped or partial (rows say "No").
> - **§7 QoS:** policing, shaping, scheduling, BA classification, rewrite
>   rules — all shipped or partial (rows say "No").
> - **§9 Logging:** structured RT_FLOW syslog, binary streaming, top-K
>   aggregation (#3099), event-mode, `monitor security flow` / packet
>   capture — all Done (rows say "No").
> - **§8 IPv6:** DHCPv6 Prefix Delegation (IA_PD) is wired
>   (`pkg/dhcp/commit.go` / `renew.go`).
> - **§11 + the 16-item "Parse-Only" summary:** primary/preferred address,
>   point-to-point, master-password, NTP threshold action, LAG/ae,
>   `log.mode`, reth/fabric — all now Done. The **only survivor** of that
>   parse-only list is `system license autoupdate url`
>   (`types_system.go:45` `LicenseAutoUpdate`, parsed but not runtime-wired).

---

## 1. Security Features

### 1.1 Application Identification (AppID / AppSecure)
| Feature | Description | Complexity | Parse-only? |
|---------|-------------|-----------|-------------|
| **Application Identification (AppID)** | Deep packet inspection engine that identifies applications regardless of port/protocol using L7 signatures, heuristics, and pattern matching. Foundation for AppFW, AppTrack, AppQoS, APBR. | Complex | `services.application-identification` parsed as bool, not wired |
| **Application Firewall (AppFW)** | Policy enforcement based on detected application identity (allow/deny/rate-limit per-app) | Complex | No — requires AppID engine |
| **Application Tracking (AppTrack)** | Logs and reports on applications traversing the device; generates AppTrack log messages | Medium | No |
| **Application QoS (AppQoS)** | QoS prioritization based on application identity (rate-limit, mark, shape per-app) | Complex | No — requires AppID engine |
| **Advanced Policy-Based Routing (APBR)** | Route traffic based on detected application identity (not just L3/L4 match but L7 app detection) | Complex | No — xpf has filter-based PBR but not app-aware routing |
| **Application Signature Package** | Downloadable/updatable signature database for ~4000+ applications | Complex | No |
| **Pre-ID Default Policy** | Policy applied before application identification completes | Medium | Yes — `PreIDDefaultPolicy` parsed, not wired to BPF |
| **Application System Cache** | Caches app identification results for faster subsequent lookups | Medium | No |

### 1.2 Intrusion Detection & Prevention (IDP/IPS)
| Feature | Description | Complexity | Parse-only? |
|---------|-------------|-----------|-------------|
| **Signature-based IDP** | Pattern matching engine with 8500+ predefined attack signatures | Complex | No |
| **Protocol Anomaly Detection** | Detects protocol violations and non-RFC-compliant traffic | Complex | No |
| **Custom Attack Objects** | User-defined signatures with regex patterns | Complex | No |
| **Attack Object Groups** | Predefined and custom groupings of attack signatures | Medium | No |
| **Dynamic Attack Groups** | Auto-grouping based on filters (severity, category, application) | Medium | No |
| **IDP Policy Rulebases** | IPS rulebase, exempt rulebase, recommended policy | Complex | No |
| **Signature Database Updates** | Automatic download and installation of latest signatures | Medium | No |
| **IDP SSL Inspection** | IDP inspection on decrypted SSL/TLS traffic | Complex | No |

### 1.3 Content Security (UTM)
| Feature | Description | Complexity | Parse-only? |
|---------|-------------|-----------|-------------|
| **Antivirus Scanning** | Signature-based AV scanning (Sophos/Avira engine), file-based and express modes | Complex | No |
| **Antispam** | SMTP spam filtering using Sophos/SBL block lists | Medium | No |
| **Web Filtering** | URL categorization and blocking (Websense/Forcepoint, local, EWF) | Complex | No |
| **Content Filtering** | Block/permit by MIME type, file extension, protocol command, embedded objects | Medium | No |
| **UTM Custom Objects** | MIME patterns, URL patterns, protocol commands | Medium | No |
| **UTM Profiles** | Feature profiles applied via security policies | Medium | No |

### 1.4 SSL/TLS Inspection
| Feature | Description | Complexity | Parse-only? |
|---------|-------------|-----------|-------------|
| **SSL Forward Proxy** | MITM decryption of outbound SSL/TLS for content inspection | Complex | No |
| **SSL Reverse Proxy** | Decrypt inbound SSL for server protection | Complex | No |
| **SSL Decryption Mirroring** | Copy decrypted traffic to analysis tool | Medium | No |
| **Certificate Management** | Root CA generation, trusted CA stores, certificate exemptions | Medium | No |

### 1.5 Advanced Threat Prevention (ATP)
| Feature | Description | Complexity | Parse-only? |
|---------|-------------|-----------|-------------|
| **Malware Sandboxing** | Cloud-based sandbox analysis of unknown files (ATP Cloud) | Complex | No |
| **Encrypted Traffic Insights** | Detect malware in encrypted traffic without decryption (TLS metadata analysis) | Complex | No |
| **SecIntel Threat Feeds** | Curated threat intelligence feeds (C&C, attacker IPs, malicious URLs) | Medium | No — xpf has dynamic address feeds but not Juniper SecIntel integration |
| **GeoIP Filtering** | Block/allow traffic by geographic location of IP addresses | Medium | No |
| **DNS Security** | DNS request inspection, sinkholing, tunneling detection | Medium | No |

### 1.6 User/Identity Firewall
| Feature | Description | Complexity | Parse-only? |
|---------|-------------|-----------|-------------|
| **Integrated User Firewall** | Policy enforcement based on user identity (Active Directory/LDAP integration) | Complex | No |
| **Captive Portal** | Web-based authentication for network access | Complex | No |
| **JIMS Integration** | Juniper Identity Management Service for user-IP mapping | Complex | No |
| **Firewall Authentication** | Pass-through, web redirect, and pass-through with web fallback authentication | Complex | No |
| **User Role-Based Policies** | Security policies based on user roles/groups from directory services | Complex | No |

---

## 2. NAT

| Feature | Description | Complexity | Parse-only? |
|---------|-------------|-----------|-------------|
| **Twice NAT** | Simultaneous source and destination NAT in a single rule | Medium | No — xpf has separate SNAT/DNAT but not combined twice-NAT rules |
| **DNS ALG with NAT** | DNS payload rewriting when NAT changes embedded IP addresses | Medium | No — ALG parsed but DNS payload rewrite not implemented |
| **NAT Rule Ordering** | Explicit rule ordering with priority numbers | Simple | No — xpf uses implicit ordering |
| **NAT Proxy ARP** | Automatic proxy ARP for NAT pool addresses | Simple | No |
| **Overflow Pool** | Fallback pool when primary NAT pool is exhausted | Simple | No |
| **PAT Pool with Address Shifting** | Deterministic NAT (predictable port mapping) | Medium | IPv4 (mode 1) AND IPv6/NAPT64 (mode 2) ENFORCED on userspace (#4559) — subscriber → fixed external IPv4 + port block, reversible for CGN compliance logging (`allocate_deterministic_v4`/`_v6`, `userspace-dp/src/nat/allocator.rs`; mode 2 via the NAT64 forward path on a `/32`-or-`/64` IPv6 host referenced by a `nat64` rule-set). Advisory now scoped to residual unenforceable pools; block-based pool-utilization (#2079) a follow-up. Forward/reverse operator lookup exposed via `show security nat source deterministic-nat` + the `GetNATDeterministic` gRPC RPC + `GET /api/v1/security/nat/deterministic` (#5794) |
| **DS-Lite Concentrator** | IPv4-in-IPv6 softwire for carrier-grade NAT | Complex | No — xpf has NAT64 but not DS-Lite |

---

## 3. Routing

| Feature | Description | Complexity | Parse-only? |
|---------|-------------|-----------|-------------|
| **Multicast Routing (PIM)** | PIM-SM, PIM-DM, PIM-SSM for multicast forwarding | Complex | No |
| **IGMP** | Internet Group Management Protocol for multicast group membership | Medium | No |
| **MPLS** | Label switching (LDP, RSVP-TE) — note: disables flow-based security | Complex | No |
| **BFD** | Bidirectional Forwarding Detection for fast failure detection | Medium | No — FRR supports BFD but xpf doesn't configure it |
| **Routing Policy (import/export)** | Full policy-options with route-maps, prefix-lists, AS-path filters for BGP/OSPF/IS-IS | Medium | Partial — xpf has basic export/redistribute but not full policy-language |
| **Route Flap Damping** | BGP route stability controls | Simple | No |
| **Graceful Restart (GR)** | Non-stop routing during control plane restart | Medium | No — FRR supports GR but xpf doesn't configure it |
| **OSPFv3** | OSPF for IPv6 | Medium | No — xpf configures OSPF (v2) but not OSPFv3 |
| **VXLAN** | Virtual Extensible LAN for overlay networking | Complex | No |
| **EVPN** | Ethernet VPN for data center overlays | Complex | No |
| **Source Routing (SRv6)** | Segment routing over IPv6 | Complex | No |

---

## 4. VPN

| Feature | Description | Complexity | Parse-only? |
|---------|-------------|-----------|-------------|
| **SSL VPN / Juniper Secure Connect** | Client-based SSL VPN for remote access | Complex | No |
| **Dynamic VPN** | Simplified IPsec remote access with web provisioning | Complex | No |
| **Group VPN (GVPNv2)** | Group key management for multipoint VPNs | Complex | No |
| **AutoVPN** | Auto-provisioned hub-and-spoke IPsec VPN | Complex | No |
| **ADVPN (Auto Discovery VPN)** | Dynamic spoke-to-spoke tunnels in hub-and-spoke topology | Complex | No |
| **IPsec Dead Peer Detection (DPD)** | Configurable DPD intervals and actions | Simple | No — strongSwan has DPD but xpf may not configure it |
| **IPsec Anti-Replay** | Sequence number window for replay attack prevention | Simple | No — handled by kernel XFRM but not configurable |
| **IPsec Traffic Selectors** | Per-tunnel traffic selectors (proxy-IDs) | Medium | No |
| **Dual-Stack IPsec** | Parallel IPv4+IPv6 tunnels over single interface | Medium | No |
| **Power-Over-Ethernet VPN Wake** | Wake devices over VPN | Simple | No (N/A for virtual) |

---

## 5. High Availability

| Feature | Description | Complexity | Parse-only? |
|---------|-------------|-----------|-------------|
| **Chassis Cluster** | Active/passive or active/active HA with two devices as one logical unit | Complex | No — xpf has VRRP but not full chassis cluster |
| **Session Synchronization** | Real-time sync of session/NAT/IPsec SA tables between cluster nodes | Complex | No |
| **Redundancy Groups (RG)** | Interface-level failover groups with independent priority | Complex | No |
| **Redundant Ethernet (reth)** | Logical aggregation of interfaces across cluster nodes | Complex | No — `RedundantParent` parsed, not wired |
| **Fabric Links** | Dedicated data/control links between cluster nodes | Complex | No — `FabricMembers` parsed, not wired |
| **In-Service Software Upgrade (ISSU)** | Upgrade software without traffic interruption | Complex | No |
| **Graceful Switchover** | Clean failover with state preservation | Complex | No |
| **IP Monitoring for Failover** | Track remote IP reachability to trigger failover | Medium | No — xpf has RPM probes but not HA failover triggers |

---

## 6. Management & Automation

| Feature | Description | Complexity | Parse-only? |
|---------|-------------|-----------|-------------|
| **NETCONF/YANG** | Standards-based configuration management protocol | Complex | No — xpf has gRPC/REST but not NETCONF |
| **J-Web GUI** | Full web-based management interface with dashboard, wizards, monitoring | Complex | No — xpf has basic REST API |
| **Security Director** | Centralized multi-device policy management (Junos Space) | Complex | No (N/A — cloud/controller feature) |
| **SNMP Traps/Notifications** | SNMP v2c/v3 trap sending on events | Medium | No — xpf has SNMP agent (GET) but no traps |
| **SNMP v3** | SNMPv3 with authentication and encryption | Medium | No — xpf has basic SNMP v2c only |
| **XML API** | `show | display xml` config export/import | Medium | No |
| **Junos Automation (SLAX/Python)** | On-box scripting for event handling, commit scripts, op scripts | Complex | No |
| **Event Policies** | Automatic actions triggered by system events (syslog patterns) | Medium | Partial — xpf has `pkg/eventengine` but unclear feature parity |
| **Commit Scripts** | Pre-commit validation scripts | Medium | No |
| **Op Scripts** | Custom operational commands via scripts | Medium | No |
| **Configuration Groups** | `apply-groups` for config template inheritance | Medium | No |
| **System Login Classes** | Role-based access control with permission bits | Medium | No |
| **AAA (RADIUS/TACACS+)** | External authentication for management access | Medium | No |

---

## 7. QoS / Class of Service

| Feature | Description | Complexity | Parse-only? |
|---------|-------------|-----------|-------------|
| **Traffic Policing** | Token-bucket rate limiting on interfaces (single-rate, two-color, three-color) | Medium | No — xpf has screen rate-limiting but not interface policing |
| **Traffic Shaping** | Per-interface/per-queue output rate shaping | Medium | No |
| **Hierarchical CoS (HCoS)** | Multi-level scheduler/shaper hierarchy | Complex | No |
| **Scheduling** | Weighted round-robin, strict priority, per-queue schedulers | Medium | No |
| **Queue Management (WRED)** | Weighted Random Early Detection for congestion control | Medium | No |
| **Behavior Aggregate Classification** | Classify incoming traffic based on DSCP/802.1p into forwarding classes | Simple | No — xpf has DSCP matching in filters but not full BA classification |
| **Rewrite Rules** | Rewrite DSCP/802.1p markers on egress | Simple | Partial — xpf has forwarding-class DSCP rewrite in filters |
| **CoS for Tunnels** | QoS on GRE/IPsec tunnel traffic | Medium | No |
| **Multifield Classification** | Classify based on L3/L4 fields into forwarding classes | Simple | Partial — via firewall filters |

---

## 8. IPv6 Specific

| Feature | Description | Complexity | Parse-only? |
|---------|-------------|-----------|-------------|
| **DS-Lite** | Dual-Stack Lite softwire concentrator (IPv4-in-IPv6 tunneling + CGNAT) | Complex | No |
| **6rd** | IPv6 Rapid Deployment via IPv4 tunneling | Complex | No |
| **MAP-E/MAP-T** | Mapping of Address and Port (IPv4/IPv6 translation) | Complex | No |
| **IPv6 Firewall Authentication** | User-based auth for IPv6 traffic | Complex | No |
| **DHCPv6 Prefix Delegation** | Full PD support with sub-prefix assignment to downstream routers | Medium | Parsed (`PrefixDelegatingPrefixLen`, `PrefixDelegatingSubPrefLen`, `ClientIATypes`) but not wired |
| **DHCPv6 Relay** | RFC 8415 Relay-Forw / Relay-Reply agent (`forwarding-options dhcp-relay dhcpv6`) | Medium | No — no agent exists; `pkg/dhcprelay` is DHCPv4-only. The stanza is refused at commit and warned on the tolerant path (#9411) |
| **IPv6 Multicast (MLD)** | Multicast Listener Discovery for IPv6 | Medium | No |
| **IPv6 Neighbor Discovery Inspection** | ND security features (RA guard, etc.) | Medium | No |

---

## 9. Logging & Monitoring

| Feature | Description | Complexity | Parse-only? |
|---------|-------------|-----------|-------------|
| **Structured Syslog** | Machine-parseable syslog with key-value pairs (Junos structured format) | Medium | No — xpf has syslog but not structured format |
| **SNMP Traps for Security Events** | Trap generation on IDP/screen/policy events | Medium | No |
| **Security Log Streaming (Binary)** | High-performance binary log format to off-box collector | Medium | No |
| **Session Aggregation/Top Talkers** | Sort/aggregate sessions by bytes, packets, duration | Medium | No — noted in phases.md as a known gap |
| **Packet Capture** | On-box packet capture to file or remote | Medium | No — relies on tcpdump |
| **Flow Tap** | Mirror specific flows to analysis device | Medium | No |
| **AppTrack Logs** | Per-session application identification logs | Medium | No — requires AppID |
| **Log Mode Selection** | Event mode vs stream mode for security logs | Simple | Yes — `LogConfig.Mode` parsed, stream always used |

---

## 10. Multi-Tenancy

| Feature | Description | Complexity | Parse-only? |
|---------|-------------|-----------|-------------|
| **Logical Systems (LSYS)** | Partition device into multiple virtual firewalls with independent routing, zones, policies | Complex | No |
| **Tenant Systems (TSYS)** | Lightweight multi-tenancy (single routing instance per tenant, higher density) | Complex | No |
| **Security Profiles** | Resource allocation/limits per logical/tenant system | Medium | No |
| **Inter-LSYS Traffic** | Policies between logical systems | Medium | No |

---

## 11. Other / Miscellaneous

| Feature | Description | Complexity | Parse-only? |
|---------|-------------|-----------|-------------|
| **Unified Policies** | Single policy combining L3/L4 + L7 app + URL category + user identity | Complex | No — xpf has zone-based policies but not unified (needs AppID) |
| **802.1X Network Access Control** | Port-based authentication | Complex | No |
| **WAN Assurance / SD-WAN** | Mist-driven SD-WAN with SLA-based path selection | Complex | No |
| **Softwire Concentrator** | IPv4-in-IPv6 tunneling (DS-Lite, 6rd) | Complex | No |
| **GPRS/GTP Firewall** | Mobile core security (GTPv1/v2 inspection) | Complex | No (N/A for non-carrier) |
| **SCTP Firewall** | SCTP protocol awareness and security | Medium | No |
| **Configuration Groups (apply-groups)** | Template inheritance for config reuse | Medium | No |
| **System Alarms on License Expiry** | License monitoring and alarming | Simple | No — xpf has no licensing |
| **Interface Redundancy (LAG)** | Link aggregation groups (ae interfaces) | Medium | No — `ae` / `802.3ad` is schema-advertised and commits clean but is inert (no bond, no enslaving, no LACP, `minimum-links` not honoured) and carries an accepted-only advisory (#6544). The `.netdev`/netlink bond generators already exist; only `fabric-options member-interfaces` reaches them. This row is the tracker for wiring `ae` into them. |
| **Storm Control** | Broadcast/multicast storm protection | Simple | No |
| **MACsec** | Layer 2 encryption (802.1AE) | Complex | No |
| **Primary/Preferred Address** | Interface address selection for sourcing traffic | Simple | Yes — `PrimaryAddress`/`PreferredAddress` parsed, not wired |
| **Point-to-Point Interfaces** | Unnumbered/point-to-point link config | Simple | Yes — `PointToPoint` parsed, not wired |
| **Master Password** | Encrypted password storage with master key | Simple | Yes — `MasterPassword` parsed, not wired |
| **License Auto-Update** | Automatic license renewal from Juniper | Simple | Yes — `LicenseAutoUpdate` parsed, not wired |
| **NTP Threshold Action** | Action when NTP offset exceeds threshold | Simple | Yes — `NTPThresholdAction` parsed, not wired |

---

## Summary: Parse-Only Features (config parsed but NOT runtime-wired)

These features exist in the xpf parser/AST but have NO runtime effect:

1. `security.log.mode` — stream vs event mode (always stream)
2. `security.pre-id-default-policy` — needs AppID engine
3. `system.master-password` — encrypted storage
4. `system.license.autoupdate.url` — license management
5. `system.ntp.threshold.action` — NTP action on threshold exceed
6. `interfaces.*.unit.*.family.inet.address.*.primary` — primary address selection
7. `interfaces.*.unit.*.family.inet.address.*.preferred` — preferred address selection
8. `interfaces.*.unit.*.point-to-point` — p2p link type
9. `interfaces.*.gigether-options.redundant-parent` — chassis cluster reth
10. `interfaces.*.fabric-options.member-interfaces` — chassis cluster fabric
11. `interfaces.*.unit.*.family.inet6.dhcpv6-client.client-ia-type` — DHCPv6 IA types
12. `interfaces.*.unit.*.family.inet6.dhcpv6-client.prefix-delegating.preferred-prefix-length` — PD prefix len
13. `interfaces.*.unit.*.family.inet6.dhcpv6-client.prefix-delegating.sub-prefix-length` — PD sub-prefix len
14. `interfaces.*.unit.*.family.inet6.dhcpv6-client.req-option` — DHCPv6 requested options
15. `services.application-identification` — AppID enable flag (no DPI engine)
16. `system.services.web-management.http.interface` / `https.interface` — server binding (always localhost)

---

## Priority Recommendations

### High Value / Medium Complexity (recommended next)
1. **NETCONF/YANG** — industry standard management, enables Ansible/Salt/Terraform integration
2. **SNMP v3 + Traps** — enterprise monitoring integration
3. **Configuration Groups (apply-groups)** — major usability improvement for large configs
4. **DHCPv6 Prefix Delegation** — already parsed, needs runtime wiring
5. **Traffic Policing** — interface-level rate limiting independent of screen
6. **BFD** — fast failure detection (FRR already supports it)
7. **Twice NAT** — common requirement for complex NAT scenarios

### High Value / High Complexity (long-term goals)
1. **Chassis Cluster / Session Sync** — enterprise HA requirement
2. **IDP/IPS** — core NGFW feature (consider Suricata integration)
3. **Application Identification** — foundation for AppFW, AppQoS, APBR, unified policies
4. **SSL Forward/Reverse Proxy** — TLS inspection (consider integration with existing proxy projects)
5. **Content Security (UTM)** — AV/antispam/web filtering (consider ClamAV/rspamd integration)
6. **Logical Systems (LSYS)** — multi-tenancy for service provider use cases

### Low Priority / Carrier-Specific
1. MPLS/LDP/RSVP — disables flow-based security on real SRX anyway
2. GTP Firewall — mobile core specific
3. DS-Lite/6rd/MAP-E — ISP transition technologies
4. EVPN/VXLAN — data center overlay (different use case)
5. SD-WAN — requires cloud controller infrastructure
