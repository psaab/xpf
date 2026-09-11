# Phase Details

## Phase 1-3: Foundation, Stateful Firewall, NAT
- XDP pipeline with tail calls, zone lookup, 5-tuple conntrack
- SNAT with interface masquerade, DNAT with destination pools
- Session creation with dual entries (forward + reverse)

## Phase 3.5: IPv6 Dual-Stack
- Separate BPF maps per address family (v4/v6)
- IPv6 extension header walking in BPF
- `csum_update_16` for incremental IPv6 checksum updates

## Phase 4: TC Egress + Host-Inbound
- TCX attachment for egress pipeline
- 17 host-inbound service flags (ssh, ping, dhcp, dhcpv6, dns, http, https, etc.)
- 10 global counters (rx/tx packets, drops, sessions, screen drops, policy denies)

## Phase 5: Screen/IDS
- 7 stateless checks: land, syn-flood, ping-death, source-route, teardrop, winnuke, ip-sweep
- 3 rate-based checks with per-CPU token buckets
- Screen applied per-zone in xdp_screen

## Phase 6: NAT Port Allocation + ICMP NAT + Source Pools
- Ephemeral port range allocation for SNAT
- ICMP echo ID-based NAT (maps ID like a port)
- Multiple source pools with round-robin IP selection

## Phase 7: Interface Management & Traffic Counters
- Per-interface, per-zone, per-policy packet/byte counters
- Interface config compilation (IPs, zones, host-inbound flags)

## Phase 8: Configuration Management
- `delete` command support, `default-policy` setting
- `show | compare` config diff, `show configuration` display

## Phase 9: Reject + Static NAT + SNAT Fix
- TCP RST generation for REJECT action
- Static 1:1 bidirectional NAT
- Fixed SNAT return path via dnat_table

## Phase 10: Session Close Events, Clear Sessions, DNAT CLI
- BPF ring buffer events for session close (TCP FIN/RST, timeout)
- `clear security flow session` CLI command
- DNAT rule display in CLI

## Phase 11: Observability & CLI
- Syslog client forwarding from ring buffer events
- Event buffer (last N events in memory)
- `show security zones`, `show security address-book` display

## Phase 12: Config Persistence & Reload
- Rollback files saved on commit (up to 50 slots)
- Syslog hot-reload on config changes

## Phase 13: Multi-Address Policy & Multiple SNAT Rules
- Policies matching multiple source/destination addresses
- Up to 8 SNAT rules per zone-pair

## Phase 14: Rollback N + CLI Polish
- `rollback N` command restores Nth previous config
- Tab completion for all CLI commands
- `?` context help, value providers for IPs/interfaces/zones

## Phase 15: TC Egress NAT + Egress Screen
- Shared `xpf_nat.h` between XDP and TC programs
- Egress NAT translation (return traffic)
- Egress screen checks (12 total BPF programs)

## Phase 16: Logging Enhancements & CLI Completion
- Per-rule log flags (session-init, session-close)
- `| match PATTERN` pipe filtering for show commands

## Phase 17: Configurable Session Timeouts + Graceful Shutdown
- Per-protocol-state timeout configuration
- Session filtering (show sessions by source/dest/zone)
- Signal handler for clean daemon shutdown

## Phase 18: Application Sets, Commit Confirmed, Screen Fixes
- Application-sets with recursive expansion (max depth 3)
- `commit confirmed N` with auto-rollback timer
- NAT port range configuration

## Phase 19: Routing, GRE Tunnels, FRR Integration, IPsec
- Static route management (now via FRR)
- GRE tunnel creation via netlink, zone binding
- FRR config generation for OSPF/BGP
- strongSwan config generation for IPsec VPNs

## Phase 20: VLAN Support & Logical Interfaces
- 802.1Q VLAN tagging in BPF (push/pop)
- Trunk port support with multiple VLAN IDs
- Logical interface (unit N with vlan-id) compilation

## Phase 21: DNAT End-to-End Verification
- Protocol match in DNAT rules
- Wildcard port fallback for DNAT
- Critical byte-order fixes (ipToUint32BE -> NativeEndian)

## Phase 22: Built-in DHCP Client + SR-IOV Internet Zone
- DHCPv4 client with lease management and auto-recompile
- DHCPv6 client with DUID persistence (DUID-LL)
- Host-inbound DHCPv6 flag for ICMPv6/UDP 546-547
- SR-IOV PCI passthrough for WAN interface in Incus

## Phase 23: REST API + Prometheus Metrics
- HTTP server on configurable address (default 127.0.0.1:8080)
- Custom Prometheus collector for all counter types
- 17 REST endpoints (health, config, zones, policies, sessions, routes, etc.)

## Phase 24: gRPC API + xpfctl Remote CLI
- Protobuf service definition with 42 RPCs
- Full config management (set, delete, commit, rollback, show compare)
- Session/stats/routes/IPsec/DHCP query RPCs
- Remote tab completion via gRPC streaming
- `cli` binary connects to gRPC for remote management

## Phase 25-27: Nested Address-Sets, Routing Instances, IPv6 RA
- **Phase 25:** Nested address-sets with recursive expansion (max depth 5, cycle detection)
- **Phase 26:** Routing instances using Linux VRF devices (`ip link add type vrf table N`)
  - Per-VRF static routes, OSPF, BGP via FRR
  - Policy-based routing via firewall filter -> VRF table ID
- **Phase 27:** IPv6 Router Advertisements via radvd daemon management

## Phase 28: NAT64 in BPF/XDP (Native Implementation)
- Native BPF/XDP implementation (no Tayga/Jool), per user request for performance
- New BPF program: `bpf/xdp/xdp_nat64.c` (tail call index 6)
- Forward (v6->v4): `bpf_xdp_adjust_head(ctx, 20)` shrinks packet, builds IPv4 header
- Reverse (v4->v6): `bpf_xdp_adjust_head(ctx, -20)` grows packet, restores IPv6
- Incremental checksums: pseudo-header swap (no full-payload iteration)
- ICMP translation: echo request/reply type mapping (128<->8, 129<->0)
- Maps: nat64_configs (ARRAY), nat64_count (ARRAY), nat64_state (HASH)
- Config: `set security nat nat64 rule-set NAME prefix 64:ff9b::/96` + `source-pool POOL`
- **Known:** fails verifier on kernel 6.12 (too complex for xdp_zone), passes on 6.18

## Phase 29: Firewall Filters & DSCP Marking
- Filter evaluation in xdp_main (before zone pipeline)
- DSCP matching in filter terms
- Policy-based routing via VRF table ID assignment
- IPv6 filter support (ICMPv6 type/code matching)

## Phase 30: NetFlow v9 Export
- Event-driven export (session close callback from ring buffer)
- UDP collectors with configurable addresses/ports
- Template refresh at configurable interval
- Wire format: v9 header + template flowset + data flowset

## Phase 31: Dynamic Address Feeds
- HTTP fetcher for external IP/CIDR lists
- Periodic refresh with configurable interval
- CIDR validation and deduplication
- Auto-recompile dataplane on feed update

## Phase 32: DHCPv4/v6 Server
- Kea DHCP server config generation from Junos syntax
- systemctl lifecycle management (start/stop/reload)
- Subnet/pool/option configuration

## Phase 33: RPM Probes & ISP Health Monitoring
- HTTP, ICMP, TCP probe types
- Configurable probe/test intervals
- Threshold-based failure detection (successive-loss count)
- Probe results queryable via CLI and gRPC

## Phase 34: ALG Control & Flow Options
- TCP MSS clamping in BPF (ipsec-vpn and all-tcp modes)
- ALG disable flags (dns, ftp, sip, etc.) stored in flow_config map
- Constant-offset MSS option scanning (verifier-safe)

## Phase 35b: systemd Deployment + Daemon Mode + FRR Unified Routing
- TTY detection via TCGETS ioctl for interactive vs daemon mode
- systemd unit file with LimitMEMLOCK=infinity, Restart=on-failure
- HTTP API always-on by default (127.0.0.1:8080)
- All routes via FRR (static, DHCP-learned, per-VRF)
- Managed section markers in frr.conf for non-destructive updates
- setup.sh: start/stop/restart/logs/journal commands
- Makefile: test-start/stop/restart/logs/journal targets

## Phase 36-38: DHCP Relay, IP-IP Tunnels, RIP/IS-IS, Ping/Traceroute, SNMP, Scheduler, Persistent NAT

## Phase 39-41: NAT Monitoring, CLI Polish, VRRP High Availability

## Phase 42: Performance Profiling & BPF Optimization
- bpf_printk 55%+ CPU → disabled (`e104112`)
- CHECKSUM_PARTIAL NAT fix, cross-zone TCP/ARP fixes
- Per-packet memset/memcpy reduction (`299a536`)
- FIB result caching in sessions (`144a3c2`)
- Per-CPU NAT port partitioning (`7aa77f0`)

## Phase 43: BPF Map & Link Pinning for Hitless Restarts (`513339f`)
- Stateful maps pinned to `/sys/fs/bpf/xpf/`
- XDP/TC links pinned to `/sys/fs/bpf/xpf/links/`
- `link.Update()` for atomic program replacement
- `xpfd cleanup` for full teardown

## Phase 44: Hitless Restart Fixes & Per-Interface Native XDP (`f9edb92`)
- Non-destructive SIGTERM shutdown
- DHCP context decoupling (`context.Background()`)
- Deferred program attachment (after all maps populated)
- Per-interface native/generic XDP with `redirect_capable` map
- 25+ Gbps sustained, zero drops during restarts

## Phase 45: Embedded ICMP Error Handling
- IPv4 embedded ICMP errors (traceroute/mtr through SNAT) (`459f670`)
- IPv6 embedded ICMPv6 error handling (`a958a21`)
- Skip failed VLAN sub-interfaces instead of aborting zone compilation (`d95c503`)
- cpumap infrastructure for multi-CPU XDP distribution (`56fead9`)
- DHCP server support (`dc3f162`)

## Phase 46: IPsec Data-Path Integration — ESP in XDP (`9e911a5`)
- **ESP protocol parsing in BPF:** `PROTO_ESP` (50) in `parse_l4hdr()`, SPI split into src_port/dst_port
- **Host-inbound ESP:** `HOST_INBOUND_ESP` (bit 19), IKE NAT-T port 4500
- **XFRM interface lifecycle:** `ApplyXfrmi()`/`ClearXfrmi()` in routing.go
  - `st0.0` → device `st0`, if_id=1; `st1.0` → `st1`, if_id=2
  - `parseXfrmiName()` helper for stN.unit → (devName, ifID) mapping
- **strongSwan if_id:** `if_id_in`/`if_id_out` in swanctl child SA config
- **Config:** `bind-interface st0.0` on `IPsecVPN`, compiled in `compileIPsec()`
- **Daemon ordering:** VRFs → tunnels → xfrmi (step 1.5) → BPF compile → FRR → IPsec
- **Tests:** TestIPsecBindInterface, TestIPsecBindInterfaceSetSyntax, TestHostInboundIPsec
- Architecture: kernel XFRM handles crypto, BPF handles zone/policy/NAT/forwarding

## Phase 47: REST API Expansion & Prometheus Metrics (`a376dac`–`064e486`)
- 15 additional REST endpoints for full gRPC parity
- Session prefix filtering (source/destination CIDR)
- Expanded Prometheus metrics: session breakdowns (IPv4/IPv6, SNAT/DNAT), NAT pool usage, DHCP lease counts
- Per-policy hit counters (`xpf_policy_hits_total` with zone/rule labels;
  a scoped global policy (#3148/#3286) reports its `from-zone`/`to-zone` on
  the `from_zone`/`to_zone` labels, an unscoped global keeps `*`/`*`)
- Config management endpoints: load override/merge via REST

## Phase 48: VRRP State Detection & Load Commands (`6a07fb5`–`9745c61`)
- VRRP runtime state detection via keepalived data file parsing
- `load override` / `load merge` CLI commands for bulk config import
- Load RPC added to protobuf service definition
- Expanded test config for loss zone

## Phase 49: Syslog Enhancements & ConfigStore Tests (`3c8e442`–`15b2e66`)
- Syslog facility selection (kern, user, local0-7, etc.)
- RPM live probe results exposed via gRPC (not just stored results)
- ConfigStore load tests for override/merge operations
- Full REST API coverage testing

## Phase 50: Unit Test Coverage Expansion (`f4a212a`–`2ea0ddf`)
- FRR package tests: static route generation, OSPF config, BGP config
- Logging package tests: syslog message formatting, event buffer
- Networkd package tests: .link/.network file generation
- IPsec package tests: strongSwan config generation
- radvd package tests: RA config generation
- Scheduler package tests: cron-like scheduling
- Total test count: 50 → 196 (across 12 packages)

## Phase 51: RPM, Show Chassis, System Commands (`b066944`–`b7eb679`)
- RPM live probe results wired into local CLI
- `show chassis hardware` and `show system storage` commands
- `request system zeroize` (factory reset with confirmation)
- Show commands dispatched via ShowText gRPC RPC

## Phase 52: SNMP & Build Version (`bd7d41e`–`fb7aaae`)
- SNMP agent: BER codec, ifTable MIB (interface counters)
- `show version` command with build-time version, commit, build timestamp
- Version info compiled via `-ldflags` at build time
- SNMP unit tests for BER encoding/decoding and MIB handling

## Phase 53: IPsec Gateway & IKE Proposals (`c91a9ae`)
- IPsec gateway address compilation in strongSwan config
- IKE proposal configuration (encryption, hash, DH group)
- Remote CLI show chassis/storage fix (ShowText RPC routing)

## Phase 54: Screen, OSPF, Teardrop (`59f3f00`–`a2e6113`)
- Teardrop screen check (IP fragmentation offset overlap attack detection)
- Bug fix: `IP.TearDrop` not `TCP.TearDrop` in screen config struct
- OSPF export/cost configuration and compilation
- Screen compilation fixes for proper profile ID assignment

## Phase 55: Config Validation & BGP/IS-IS Export (`7cf4273`–`70df70e`)
- Config validation: cross-reference checks (zones, address-books, apps, screens)
- Validation warnings (non-fatal) stored in `Config.Warnings`
- BGP export → FRR `redistribute` mapping (connected, static, ospf)
- IS-IS export → FRR `redistribute` mapping
- BGP neighbor inheritance from group (description, multihop, peer-as override)
- AST schema additions: bgp (local-as, router-id, export, group), rip, isis

## Phase 56: DHCP Server Leases & Test Coverage (`6de466e`–`8b7273e`)
- DHCP server lease display via Kea CSV file parsing
- `show system services dhcp-server` in both local and remote CLI
- gRPC ShowText handler for dhcp-server
- VRRP package tests (config generation, auth, track interface, data file parsing)
- DHCP relay package tests (Option 82 add/strip, interface IPv4 lookup)

## Phase 57: CLI Polish — Junos-Style UX (`d43742d`–`6728254`)
- "Possible completions:" header on all `?` help output
- Dynamic column width based on longest command name
- `resolveCommand()` for Junos-style prefix matching (exact → prefix → ambiguous)
- `formatAmbiguousMatches()` with "'X' is ambiguous" error
- `operationalCommands`, `showCommands`, `showSecurityCommands` lists
- Remote CLI updated with same completion headers

## Phase 58: Zone Names & Display Improvements (`f66c8f0`)
- Sessions and events display zone names instead of numeric IDs
- Reverse zone ID→name map built from `CompileResult.ZoneIDs`
- Protobuf: `ingress_zone_name`/`egress_zone_name` fields on SessionEntry and EventEntry
- All three display paths updated: local CLI, remote CLI, gRPC server
- `show system alarms` command added to both CLIs

## Phase 59: Application Enhancements & Bug Fixes (`ac9354b`)
- Application struct extended: `SourcePort`, `InactivityTimeout`, `ALG`, `Description`
- Multi-term applications: each term becomes separate Application, parent becomes implicit ApplicationSet
- `parseApplicationTerm()` handles inline term syntax with all new fields
- Test fix: flat set syntax tests must use `ParseSetCommand()` + `SetPath()`, NOT `NewParser()`

## Phase 60+: Firewall Filters, ECMP, Route Leaking
- Firewall filter port range matching in BPF (source/destination port ranges in filter terms)
- Per-application inactivity timeout enforced in BPF sessions
- ECMP multipath support via FRR export policy
- Forwarding-class to DSCP rewrite in firewall filters
- Firewall filter hit counters displayed in remote CLI
- next-table inter-VRF route leaking for static routes (via `ip rule`, not FRR)
- Rib-groups wired to runtime (ip rule route leaking), multi-VRF test config (dmz-vr + tunnel-vr)
- Configstore refactored: DB (atomic JSON persistence), Journal (JSONL audit log), History (ring buffer)
- cmdtree package extracted as single source of truth for all CLI trees

## Phase 61: Strict Userspace Forwarding & Minimal Failover (Issues #302-#312)

Gap audit: `docs/archived/userspace-forwarding-and-failover-gap-audit.md` (PR #301)

### Strict Userspace Invariant (#302)
- [x] Define DataplaneMode enum (ebpf_only, userspace_compat, userspace_strict) (#303)
- [x] Ban transit fallback in strict mode (#304)
- [x] Scope PASS_TO_KERNEL to control-plane only (#305)
- [x] XSK liveness fail-closed in strict mode (#306)
- [x] Per-interface entry program + fallback counters in status (#307)

### MAC-Move-Only Failover (#308)
- [x] HA forwarding state inventory (#309)
- [x] Deterministic reverse companions (#310)
- [x] Install fence for HA cutover (#311)
- [x] Reduce helper-local cache dependencies (#312)

## Phase 50: vsrx.conf Feature Parity (in progress)
**Baseline:** 8.47 Gbps (4×BBR trust→untrust), all connectivity tests pass
**Goal:** Close gaps between vsrx.conf features and xpf implementation

### Phase 50a (`aab6dc9`)
- RA managed-config flags + RDNSS DNS server advertisement — **already implemented**
- Unit-level MTU wired to networkd .link files (min of interface + unit MTU)
- Inline JFlow source-address fallback in NetFlow v9 export
- Source-prefix-list `except` — Go constants added, BPF C not yet wired
- Application-set grouping — verified working (recursive expansion, dedup)
- Nested app-set, prefix-list except, destination-prefix-list except tests added

### Phase 50b (`672c173`)
- **BPF filter negate flags:** `FILTER_MATCH_SRC_NEGATE` (1<<8) / `DST_NEGATE` (1<<9) in C headers + both XDP/TC filter eval loops; compiler wires except prefix-lists with per-address negate tracking
- **Qualified next-hop:** FRR static route strips Junos unit suffix (`wan0.0` → `wan0`) for interface names
- **ECMP consistent-hash:** `fib_multipath_hash_policy=1` sysctl for L4 hashing when forwarding-table export policy has `consistent-hash`
- **Policy-based routing:** `ip rule` for firewall filter `routing-instance` action — DSCP→TOS mapping, src/dst address rules, priority 34000-34999
- **PREF64 in radvd:** Already fully wired; added `TestGenerateConfig_NAT64WithLifetime`
- Tests: 3 compiler negate, 5 FRR qualified-next-hop, 15 DSCP-to-TOS, 9 PBR subtests, 1 radvd PREF64

### Phase 50c (`134a5ff`)
- **Screen syn-flood thresholds:** Source/destination thresholds + configurable timeout wired to BPF `screen_config` struct
- **Sampling direction:** Per-interface `SamplingInput`/`SamplingOutput` flags wired to flow export via `ShouldExport()` zone-based filtering
- **Show security screen:** `ids-option <name>` displays config, `statistics zone <zone>` displays BPF flood counters
- **Show security alarms:** `alarms detail` shows config validation warnings + IDS counters
- **Show security flow session summary:** Session counts by type (TCP/UDP/ICMP, SNAT/DNAT, established)
- Tests: 3 screen compilation, 3 sampling export tests

### Bugfix: VLAN interface name stripping (`89a1a5e`)
- Phase 50b stripped ALL dot-suffixes from interface names; VLAN sub-interfaces like `wan0.50` are real kernel names
- Fixed: only strip `.0` suffix (Junos default unit), not VLAN suffixes
- IPv6 default route now correctly uses `dev wan0.50`

### Phase 50d (`3a7e5bd`)
- GRE MSS split gre-in/gre-out in BPF (separate clamping per direction)
- Show interfaces extensive (BPF per-interface counters)
- Instance-type forwarding support in VRF compilation
- NAT source/destination summary display

### Phase 50e (`e95475b`)
- **Route detail:** `show route detail` parses FRR JSON, Junos-style display with protocol/preference/next-hops
- **CoS interface display:** `show class-of-service interface` shows per-interface filter bindings with term match/action
- **BGP neighbor:** `show bgp neighbor <ip>` via FRR vtysh
- **IPsec SA clear:** `request security ipsec sa clear` terminates all IKE SAs
  (global-only; like `request protocols ospf clear` / `... bgp clear` these
  reset the whole process and take NO selector. BOTH the remote CLI
  (`cmd/cli`, #5652) and the local interactive CLI (`pkg/cli`, #5647 residual
  from codex-review-182) reject a scoped-looking suffix — e.g. `... sa clear
  <id>`, `... ospf clear neighbor <ip>` — instead of silently widening it to a
  global reset. The reject runs BEFORE the FRR/strongSwan manager-availability
  gate, so an unrecognized selector is refused, not dropped, #5647)
- **NAT counter clear:** `clear security nat statistics` zeros BPF nat_rule_counters
- **Route summary enhanced:** Per-protocol breakdown (Direct/Local/Static/OSPF/BGP/IS-IS) with inet.0/inet6.0 sections
- **ICMP type/code in CoS:** Filter terms now show icmp-type/icmp-code instead of "match any"
- Tests: 2 FRR route parsing, all remote CLI dispatch wired

### Phase 50f (`74ce11e`)
- **Session application names:** Maps dst port+proto to Junos app names (junos-http, junos-ssh, etc.)
- **Session app filter:** `show security flow session application junos-ssh`
- **OSPF interface/database:** `show ospf interface`, `show ospf database` via FRR
- **ISIS adjacency/routes:** `show isis adjacency`, `show isis routes` via FRR
- **Commit history:** `show system commit` displays commit timestamps from JSONL journal
- **Buffer utilization:** `show system buffers` enhanced with fill percentage per BPF map
- **Security statistics:** Enhanced with per-zone counters
- Proto: Added application field to session request/response, commit summary field
- All commands wired to both local and remote CLI

### Phase 50g (`1740678`)
- **Config stanza completion:** 16 top-level stanzas under `show configuration ?`
- **Dynamic address feed runtime status:** Last-fetch time, prefix count, age display
- **NTP sync status:** chronyc tracking with timedatectl fallback
- **RPM probe min/max/avg RTT + jitter:** Exponential moving average + RFC 3550 jitter
- **Policy-options detail:** Route-filter expansion, per-term from/then display
- **Interface speed/duplex:** Reads from sysfs, shown on link-level line
- **ARP/IPv6 neighbor statistics:** Summary counts + per-interface breakdown

### Phase 50h (`c98f2b1`)
- **Show route terse:** Compact one-line-per-route with protocol tag (S/C/B/O/I/R/D)
- **Clear arp / clear ipv6 neighbors:** Flush kernel neighbor cache
- **NAT source/destination rule detail:** Per-rule hit counters from BPF maps
- **Persistent NAT detail:** Per-binding sessions, timeout, pool info
- **Routing-instances detail:** VRF route counts, static routes, rib-groups
- **DHCP server detail:** Pool config, lease TTL, subnet info

### Phase 50i (`46c881b`)
- **Security zones detail:** Per-zone interfaces, addresses, policy breakdown, traffic stats
- **IPsec statistics:** Active tunnels, per-SA bytes in/out table
- **Screen ids-option detail:** Check thresholds vs defaults table (Value/Default columns)
- Full audit confirmed local↔remote CLI feature parity (all show/clear/request commands wired)

### TC Egress MSS Clamping (`858b695`)
- **tcp-mss gre-out wired to TC egress:** `tc_tcp_mss_clamp()` for sk_buff context
- Called in `tc_conntrack_prog()` on egress SYN packets
- Uses `tcp_mss_gre_out` (with `tcp_mss_ipsec` as fallback minimum)
- Previously only XDP ingress clamped MSS; now both directions match Juniper semantics

### Session Brief & Interface Filter Fix (`e89f475`)
- **Session brief mode:** `show security flow session brief` — compact tabular view
  with columns: ID, Source, Destination, Proto, Zone, NAT, State, Age, Pkts
- **Interface filter fix:** `show security flow session interface trust0` now resolves
  interface name → zone ID for proper filtering (was no-op before)
- cmdtree updated with `brief` and `interface` entries under session
- Wired to both local and remote CLI

## DPDK Dataplane Backend

> [!IMPORTANT]
> Historical sprint records below. The DPDK dataplane backend was
> retired in #1525; the `dpdk_worker/` and `pkg/dataplane/dpdk/`
> trees are removed in #1527/#1528. These sections are preserved
> as the sprint history they were at the time of writing.

### DPDK Phase 1-5: Foundation (`0329a45`–`acec4c9`)
- Extract `DataPlane` interface from concrete eBPF Manager
- Config parsing for `dataplane-type dpdk`
- Full C pipeline logic (all 9 stages: parse, screen, zone, conntrack, policy, nat, nat64, reject, forward)
- CGo shared memory bridge for Go↔DPDK communication
- FIB routing tables, worker lifecycle, pipeline fixes
- Host-inbound, TTL, DNS-reply, IPv6 ext headers gap fixes

### DPDK Phase 6-10: NAT & Routing (`ec193ac`–`3704832`)
- NAT64 reverse, rejection packets, static NAT, SNAT alloc, MSS clamp
- FIB populator, zone tcp-rst, DSCP sentinel, allow-embedded-icmp
- ICMP Time Exceeded, egress screen, VLAN handling, zone counters
- FIB sync wired into daemon, session FIB cache
- DNAT pre-routing, SNAT return-path, IPv6 SNAT, multicast bypass

### DPDK Phase 11-15: Session & Multi-Queue (`48c8872`–`59c3dec`)
- IPv6 conntrack bugs fixed, policy scheduler wired
- Selective counter clearing, NAT port counters, session cleanup
- Multi-queue TX, TX burst batching, log_flags wiring
- Conntrack session entry correctness bugs fixed
- Multi-queue RX, worker heartbeat health check

### DPDK Phase 16-20: GC & Monitoring (`99cf3ed`–`9530e24`)
- C-side session GC on main lcore
- Packet trace facility for live debugging
- Per-packet latency histogram
- Link state monitoring + port statistics
- Enforce SESS_STATE_CLOSED, propagate log_flags

### DPDK Phase 21-23: Counters & Stats (`337c4f7`–`c16d44d`)
- ReadGlobalCounter abstracted to DataPlane interface
- ReadFloodCounters, eliminate all `dp.Map()` calls
- Populate MaxEntries in GetMapStats

### DPDK GRE-out MSS Parity (`d4390c1`)
- Include `tcp_mss_gre_out` in single-pipeline MSS minimum alongside ipsec + gre-in
- Maintains parity with eBPF pipeline (now ingress + egress)

### Sampling Input-Rate to NetFlow Export (`2f68831`)
- **Sampling input-rate wired to NetFlow 1-in-N export:** `sampling input rate N` on interface now controls
  NetFlow export probability — only every Nth session close event is exported
- Previously `SamplingInput`/`SamplingOutput` were parsed but unused; now `SamplingInput` drives export rate
- Moves sampling from "parse-only" to "runtime-wired"

### Show VLANs, PrimaryAddress, Daemon Uptime (`4541fd5`)
- `show vlans` command displays VLAN interface bindings
- `PrimaryAddress`/`PreferredAddress` fields for interface address selection
- Daemon uptime tracking and display

### DPDK Worker Build Fix (`8a4b0c5`)
- Fix DPDK worker build for DPDK 25.11 API changes

### Phase 50j: Screen IDS, Routing Protocol Auth, BFD, Advanced Protocol Features

#### Port-Scan & IP-Sweep Detection (`39f53d7`)
- **Screen IDS port-scan:** TCP SYN tracking per source IP using LRU_HASH map (`port_scan_track`)
- **Screen IDS ip-sweep:** All-packet tracking per source IP using LRU_HASH map (`ip_sweep_track`)
- Configurable thresholds, automatic eviction via LRU, drop when threshold exceeded
- BPF `xdp_screen.c` counting logic, `SCREEN_PORT_SCAN`/`SCREEN_IP_SWEEP` flags
- AST schema + parser + compiler + tests

#### OSPF/BGP Authentication & BFD (`f3f6ff3`)
- **OSPF MD5 auth:** Interface-level `message-digest-key` config → FRR `ip ospf message-digest-key`
- **OSPF simple auth:** Interface-level `authentication-key` → FRR `ip ospf authentication-key`
- **BGP password auth:** Per-neighbor TCP MD5 password → FRR `neighbor X password`
- **BFD for OSPF:** Per-interface `ip ospf bfd` via `bfd-liveness-detection`
- **BFD for BGP:** Per-neighbor `bfd` with configurable `minimum-interval`
- Parser + compiler + FRR generation + 5 tests

#### Area Types, Route-Reflector, IS-IS/RIP Auth, Ops Commands (`060fa52`)
- **OSPF stub/nssa areas:** `area-type stub`/`nssa` with `no-summary` (totally stubby)
- **BGP route-reflector:** `cluster-id` and per-neighbor `route-reflector-client`
- **IS-IS authentication:** Area/domain password (MD5 and cleartext)
- **RIP authentication:** Per-interface MD5 and text-mode auth
- **Operational commands:** `show bfd peers`, `request protocols ospf clear`, `request protocols bgp clear`
- All wired to local CLI, remote CLI, gRPC, cmdtree

#### OSPF Reference-Bandwidth, BGP Graceful-Restart, DPDK Sync (`8f9d4db`)
- **OSPF reference-bandwidth:** `auto-cost reference-bandwidth` in FRR. The leaf is **bits per second** (Junos units) and FRR's directive is **Mbps**; the conversion, the range gate and the k/m/g suffix grammar landed in #9408 — see `docs/config-schema.md` "`protocols ospf reference-bandwidth` — the leaf and the renderer use DIFFERENT UNITS"
- **BGP graceful-restart:** Parsed + compiled to FRR config
- **DPDK struct sync:** `scan_track_key`/`scan_track_value` structs, documented `pad_meta`/`ip_ihl` divergence

#### IS-IS Interface Auth, Wide-Metrics, Overload; BGP Multipath, Default-Originate (`d1e6f12`)
- **IS-IS per-interface auth:** MD5 and cleartext authentication
- **IS-IS wide-metrics-only:** `metric-style wide` in FRR
- **IS-IS overload bit:** `set-overload-bit` in FRR
- **BGP multipath:** `bestpath as-path multipath-relax` for multiple-AS ECMP
- **BGP default-originate:** Per-neighbor default route advertisement
- **BGP log-neighbor-changes:** State change logging

#### OSPF Passive-Interface Default & Network Type (`f58ee41`)
- **OSPF passive-interface default:** `passive` at OSPF protocol level → FRR `passive-interface default`
- **OSPF no-passive override:** Per-interface `passive disable` → FRR `no passive-interface <iface>`
- **OSPF interface network type:** `interface-type <type>` → FRR `ip ospf network <type>`.
  Typed since #8481 against the four spellings vtysh accepts (`broadcast`,
  `non-broadcast`, `point-to-multipoint`, `point-to-point`); the Junos spellings
  `p2p`, `nbma` and `p2mp` are accepted and translated. The token used to be
  passed through unvalidated, so an unrecognised one emitted a line vtysh
  rejects and failed the ENTIRE managed-section reload.
- Parser + compiler + FRR generation + tests

#### Route-Map Attributes, BGP Neighbor Features, OSPFv3, DPDK Sync (`383173c`)
- **Route-map attributes:** `local-preference`, `metric`, `community`, `origin` in policy-statement terms with FRR `set` command generation
- **BGP allow-as-in:** Per-neighbor/group `loops` config for accepting own AS in path
- **BGP remove-private-AS:** Per-neighbor/group private AS stripping
- **OSPFv3:** Full IPv6 OSPF support — types, schema, compiler, FRR generation, daemon/CLI wiring, per-routing-instance support
- **DPDK sync:** `nat_port_counter`, `scan_track` tables, `redirect_capable` map structs

#### Firewall Filter TCP Flags/Fragment, OSPF Metric-Type, BGP Community-Lists (`feceef3`)
- **TCP flags matching:** Filter terms match SYN, ACK, FIN, RST, PSH, URG flags in BPF filter pipeline
- **IP fragment matching:** `is-fragment` filter term for IP fragment detection in BPF
- **OSPF metric-type:** `type-1`/`type-2` in policy-statement route-maps for FRR `set metric-type`
- **BGP community-lists:** Community-list definitions with FRR `bgp community-list` generation
- **Community matching:** Policy-statement `from community` clause for route-map match
- **Interface duplex schema:** Flat set syntax support for duplex config
- Full stack: config types, schema, compiler, BPF filter_rule, DPDK filter.c parity
- Tests: 208 lines of parser tests, 53 lines of FRR tests

#### BGP Dampening, AS-Path Access-Lists, Prefix-Limits, OSPF Virtual-Links, GRE Keepalive (`3176de1`)
- **BGP dampening:** Route flap dampening config → FRR `bgp dampening` parameters
- **AS-path access-lists:** Named AS-path filters → FRR `bgp as-path access-list`
- **BGP prefix-limits:** Per-neighbor max-prefix limits with teardown/warning thresholds
- **OSPF virtual-links:** Inter-area virtual link config → FRR `area X virtual-link Y`
- **GRE keepalive runtime:** Periodic ICMP probes to tunnel endpoints, auto mark down/up after configurable failures, shown in `show interfaces tunnel`
- **Interface disable flag enforcement:** Skip XDP/TC attachment for disabled interfaces, bring them admin-down
- **IS-IS database show:** `show protocols isis database` wired to FRR `show isis database detail`
- **DPDK parity:** port_scan_thresh/ip_sweep_thresh in SetScreenConfig, rte_ipv6_addr migration, memzone anonymous union accessor

### Sprint 11: Protocol Routes, System Info, Interface Ethtool
- **Show protocols routes/database:** OSPF routes, BGP routes/received-routes/advertised-routes wired to FRR vtysh
- **System info commands:** `show system memory` (/proc/meminfo), `show system storage` (df), `show system processes` (ps) — wired to CLI + gRPC
- **Interface speed/duplex application:** ethtool speed/duplex applied on interface UP, graceful error handling for unsupported interfaces (virtio, etc.)
- **Show interfaces extensive:** Detailed per-interface stats from netlink (RX/TX packets, bytes, errors, drops, MTU, MAC, speed, duplex) in CLI + gRPC
- Files: pkg/cli/cli.go, pkg/frr/frr.go, pkg/grpcapi/server.go, pkg/dataplane/compiler.go

### Sprint 12: DHCPv6 Prefix Delegation, Show Route-Map (`c56d305`)
- **DHCPv6 Prefix Delegation (IA_PD):** Full PD support wired to DHCPv6 client
  - `DHCPv6Options` struct: `IATypes` (ia-na, ia-pd), `PDPrefLen` hint, `PDSubLen`, `ReqOptions`, `RAIface`
  - `DelegatedPrefix` struct tracks prefix, lifetimes, obtained time per interface
  - `doDHCPv6()` refactored to return `dhcpv6Result` (lease + delegated prefixes)
  - `buildDHCPv6Modifiers()` constructs IA_PD options with prefix length hints and ORO
  - `extractDelegatedPrefixes()` parses IA_PD options from DHCPv6 reply
  - PD-only mode supported (no IA_NA address required when IA_PD succeeds)
  - Daemon wires config types (`ClientIATypes`, `PrefixDelegatingPrefixLen`, etc.) to DHCP manager
  - Delegated prefixes shown in `show system services dhcp` (local + remote CLI)
  - Protobuf: `DHCPDelegatedPrefix` message, `delegated_prefixes` field on `DHCPLeaseInfo`
  - gRPC server attaches PD info to matching inet6 lease entries
- **Show route-map:** `show route-map` command displays FRR route-map configuration via `vtysh -c "show route-map"`
  - `GetRouteMapList()` added to FRR manager
  - Wired to local CLI, remote CLI, gRPC ShowText
  - cmdtree entry under operational tree
- **DPDK interface disable docs:** Comment clarifying that `LinkSetDown` has no effect on DPDK-bound ports (VFIO/UIO bypasses kernel driver; DPDK ports disabled by excluding from worker poll set)
- Files: pkg/dhcp/dhcp.go, pkg/daemon/daemon.go, pkg/cli/cli.go, pkg/grpcapi/server.go, pkg/frr/frr.go, cmd/cli/main.go, pkg/cmdtree/tree.go, pkg/dataplane/compiler.go, proto/xpf/v1/xpf.proto

### Sprint 13: PD-to-radvd Wiring, TCP Session Timeouts, CoS Handler
- **DHCPv6 PD-to-radvd wiring:** Delegated prefixes from DHCPv6 PD now automatically drive Router Advertisements on downstream interfaces
  - `PDRAMapping` struct: links delegated prefix to target RA interface + sub-prefix length
  - `DelegatedPrefixesForRA()`: returns PD entries with configured `RAIface`
  - `DeriveSubPrefix()`: derives /64 (or configured sub-prefix) from delegated prefix (e.g., /48 → /64)
  - `buildRAConfigs()` in daemon: merges static RA configs with PD-derived prefixes
  - Prefix lifetimes (valid + preferred) propagated from DHCPv6 lease to radvd
  - `radvd.Clear()` called when no RA configs remain (cleanup on PD expiry)
  - Tests: 6 DeriveSubPrefix subtests + DelegatedPrefixesForRA test
  - Files: pkg/dhcp/dhcp.go, pkg/dhcp/dhcp_test.go, pkg/daemon/daemon.go
- **TCP session timeouts (BPF conntrack):** Configurable per-state TCP timeouts wired from config to BPF
- **Show class-of-service handler:** CoS config display wired to CLI/gRPC

### Sprint 14: Web Management Binding, SNMPv3 USM (`73a6e95`)
- **Web management interface binding:** `WebManagementConfig.HTTPInterface`/`HTTPSInterface` now control API server bind address
  - `resolveInterfaceAddr()` resolves interface name → IPv4/IPv6 address
  - Secure default: 127.0.0.1 when no interface configured
  - HTTP and HTTPS bind independently to different interfaces
  - Moves `WebMgmt` from "parse-only" to runtime-wired
  - Files: pkg/daemon/daemon.go, pkg/api/
- **SNMPv3 USM authentication:** Full RFC 3414/3826 User-based Security Model
  - `SNMPv3User` struct: Name, AuthProtocol (md5/sha/sha256), AuthPassword, PrivProtocol (des/aes128), PrivPassword
  - RFC 3414 `passwordToKey()` with engine ID localization
  - Authentication: HMAC-MD5, HMAC-SHA1, HMAC-SHA256
  - Privacy: DES-CBC (RFC 3414), AES-128-CFB (RFC 3826)
  - Engine ID discovery, Get/GetNext/GetBulk v3 request handling
  - Config parsing for `system services snmp v3 usm local-engine user` hierarchy
  - `show snmp v3` CLI command, gRPC snmp-v3 topic, cmdtree entry
  - 740-line pkg/snmp/v3.go with full message encode/decode
  - SNMP agent starts on v3-only config (no v2c communities required)
  - Files: pkg/snmp/v3.go, pkg/snmp/agent.go, pkg/config/types.go, pkg/config/compiler.go, pkg/cli/cli.go, pkg/grpcapi/server.go, pkg/cmdtree/tree.go

### Sprint 15: ALG types, address book clear, NAT persistent, IPFIX, SNMP traps, LAG, rollback compare (`d24795e`)
- **ALGType in SetApplication:** Added ALGType uint8 parameter to DataPlane.SetApplication interface for DPDK parity
- **ClearAddressBook methods:** Added ClearAddressBookV4/V6 to DataPlane interface for clean address book recompile; eBPF iterates+deletes LPM entries, DPDK calls rte_lpm_delete_all
- **NAT persistent pool settings:** Wired PermitAnyRemoteHost and InactivityTimeout from config to BPF maps; per-pool inactivity timeout tracking in conntrack GC; persistent_nat_test.go with table management tests
- **IPFIX (NetFlow v10) export:** Full IPFIX exporter in pkg/flowexport/ipfix.go with template sets, IANA field IDs, configurable template refresh; daemon wiring via startIPFIXExporter/stopIPFIXExporter
- **SNMP trap generation:** Link state traps (linkUp/linkDown) in pkg/snmp/traps.go; monitors netlink for interface state changes; sends SNMPv2c traps with ifIndex/ifAdminStatus/ifOperStatus varbinds
- **LAG bonding:** Wire fabric-options member-interfaces to Linux bonding via netlink; ApplyBonds/ClearBonds in pkg/routing/routing.go
- **Show system rollback compare:** CLI/gRPC command to diff current config against rollback slots
- **Login user management:** Wire system login user config to useradd + SSH authorized_keys management
- Files: pkg/dataplane/{compiler,dataplane,maps,persistent_nat}.go, pkg/daemon/daemon.go, pkg/flowexport/ipfix.go, pkg/snmp/traps.go, pkg/routing/routing.go, pkg/cli/cli.go, pkg/grpcapi/server.go, pkg/conntrack/gc.go
- **SNMP ifXTable (64-bit counters):** RFC 2863 ifHCInOctets/ifHCOutOctets, ifAlias, ifHighSpeed for high-speed interface reporting (`d328a4c`)
- **IPsec NAT-T:** NAT Traversal support in strongSwan config generation, `encapsulation=yes` when nat-traversal enabled, UDP port 4500 (`d328a4c`)
- Files (addl): pkg/snmp/agent.go, pkg/ipsec/ipsec.go, pkg/config/{ast,compiler,types,parser_test}.go

## Sprint 16 (`455e895`)
- **Chassis cluster RETH:** Linux bond devices in active-backup mode for redundant Ethernet; ApplyRethInterfaces/ClearRethInterfaces in routing.go; interface monitors with weight/status tracking
- **System config wiring:** NTP threshold action (FallbackNTP in timesyncd), syslog user destinations (rsyslog :omusrmsg), DNS service (systemd-resolved start/stop), security log mode display
- **Operational commands:** All request system commands verified as already implemented; DPDK struct sync confirmed complete
- Files: pkg/routing/routing.go, pkg/daemon/daemon.go, pkg/dataplane/compiler.go, pkg/grpcapi/server.go

## Sprint 17 (`71f809c`)
- **Port mirroring (SPAN):** Config types + AST + compiler for forwarding-options port-mirroring; BPF mirror_config map (per-interface ARRAY) with struct mirror_config; DataPlane SetMirrorConfig/ClearMirrorConfigs; TC egress clone_redirect; CLI show forwarding-options display; gRPC ShowText handler; parser tests
- **LLDP (IEEE 802.1AB):** Full protocol in pkg/lldp/lldp.go — AF_PACKET TX/RX, TLV encode/decode, neighbor table with TTL expiry; config types in ProtocolsConfig, AST schema, compiler; daemon wiring with Apply/Stop lifecycle; CLI show lldp + show lldp neighbors; gRPC + remote CLI; 12 unit tests
- **HTTP API authentication:** pkg/api/auth.go middleware — Basic Auth, Bearer tokens, X-API-Key; constant-time password comparison; /health + /metrics bypass; config types (APIAuthConfig), AST under web-management api-auth; compiler + daemon wiring (APIAuthConfig → api.AuthConfig); server wiring for HTTP + HTTPS; 11 unit tests
- Files: 24 files, 1879 insertions — pkg/lldp/, pkg/api/auth.go, bpf/{headers,xdp,tc}/, pkg/{config,cli,cmdtree,daemon,dataplane,grpcapi}/

## Sprint 18 (`a101367`)
- **Session sorting/top-talkers:** Sort by bytes or packets (forward+reverse) descending; CLI `show security flow session sort-by bytes/packets`; gRPC ShowText topics `sessions-top:bytes`/`sessions-top:packets`; cmdtree sort-by node
- **Prometheus system metrics:** 6 new gauges — CPU user/system% from /proc/stat, memory total/available from /proc/meminfo, daemon uptime, RSS from /proc/self/statm
- **XML config export:** FormatXML() on ConfigTree; `show configuration | display xml` CLI pipe; gRPC ShowText `config-xml` topic; REST API format=xml
- **Interface speed/duplex:** ethtool -s enforcement via exec.Command; graceful fallback on unsupported interfaces; compiler test
- **REST config export:** GET /api/v1/config/export with format=set|text|json|xml; test with proper configstore lifecycle
- Files: 14 files, 705 insertions — pkg/{api,cli,cmdtree,config,configstore,dataplane,grpcapi}/, cmd/cli/, proto/

## Sprint 19 (`cc06f5f`)
- **apply-groups config inheritance:** ExpandGroups() merges group children into apply-groups sites; cycle detection; FormatSet output; both hierarchical and flat set syntax; 5 parser tests
- **test policy/routing/zone commands:** `test policy from-zone X to-zone Y ...` walks compiled policies; `test routing destination <prefix>` queries FRR; `test security-zone interface <name>` shows zone membership; all wired to gRPC, remote CLI, cmdtree
- **REST API streaming (SSE):** GET /api/v1/events/stream + /api/v1/logs/stream; category/severity filtering; EventBuffer Subscribe/Unsubscribe fan-out; 7 SSE tests
- Files: 12 files, 1884 insertions — pkg/{api,cli,cmdtree,config,grpcapi,logging}/, cmd/cli/

## Sprint 20 (`9ab1004`)
- **Login class RBAC:** LoginClassPermission enum (PermView/PermClear/PermControl/PermConfig/PermAll); LoginClassPermissions map for super-user/operator/read-only; CLI checkPermission() enforcement before command dispatch; backward-compatible (empty class = allow all)
- **show interfaces detail:** New display mode between terse and extensive; shows zone assignment, addresses, speed/duplex, MTU, MAC, traffic counters; single-interface detail (show interfaces trust0 detail); gRPC interfaces-detail topic
- **Config archival + rescue:** Timestamped config backup on commit with rotation (ArchiveConfig/rotateArchives); configurable archive dir and max archives; rescue config save/load/delete; show system configuration rescue; show system users
- Files: 10 files, 824 insertions — pkg/{cli,cmdtree,config,configstore,daemon,grpcapi}/, cmd/cli/

## Sprint 21 (`72e1020`)
- **show security policies detail:** Expanded Junos-style policy view with resolved address book entries, application details, log flags, per-rule BPF hit counters; zone-pair filtering; global policies; gRPC policies-detail topic
- **show firewall filter `<name>`:** Per-filter drill-down showing terms with match conditions (dscp, protocol, ports, tcp-flags, fragment), actions (accept/discard/reject/log/forwarding-class), BPF hit counts; DynamicFn completion for filter names
- **Config annotate:** `annotate <path> "comment"` in configure mode; Annotation field on AST Node; /* comment */ output in FormatText(); Annotate() method in configstore; parser tests. **#3900 injection hardening:** the annotation is emitted verbatim between `/* */`, so a `*/` (or `/*`) in the text would close the comment early and let the trailing text be re-lexed as configuration on the next Format→Parse round-trip (HA config sync, rollback/archive reload). `Store.Annotate` now rejects a comment delimiter up front (`config.ValidateAnnotationText`), the strict commit path (`validateNodesControlChars`) rejects it as a backstop, and the lenient load/peer-sync path (`sanitizeNodesControlChars`/`SanitizeTreeControlChars`) scrubs an already-persisted delimiter in place — mirroring the #1798 control-character two-layer defense (`pkg/config/freetext.go`).
- Files: 8 files, 789 insertions — pkg/{cli,cmdtree,config,configstore,grpcapi}/, cmd/cli/

## Sprint 22 (`26cf1ad`)
- **show interfaces statistics:** Tabular per-interface traffic counters (packets/bytes/errors); clear interfaces statistics
- **Protocol neighbor detail:** show ospf neighbor detail, show bgp neighbor received/advertised-routes, show isis adjacency detail — all via FRR vtysh pass-through
- **System diagnostics:** show task (goroutines, memory, GC, uptime), show system core-dumps (scans /var/crash + coredump), request system reboot/power-off (with confirmation)
- Files: 5 files, 266 insertions — pkg/{cli,cmdtree,frr,grpcapi}/, cmd/cli/

## Sprint 23 (`6af0688`)
- **load set terminal:** Paste multiple set commands in configure mode; ParseSetCommand+SetPath per line; file mode; LoadSet() in configstore with tests
- **Port validation:** validatePortSpec (1-65535, named ports, ranges), validateProtocol (names/numbers 0-255); warnings in compileApplications; 10 test cases
- **show system boot-messages:** journalctl --boot -n 100 via CLI/gRPC
- **configure exclusive:** Mutex-based exclusive config mode; EnterConfigureExclusive/IsExclusiveLocked; prevents concurrent edits
- Files: 10 files, 405 insertions — pkg/{cli,cmdtree,config,configstore,grpcapi}/, cmd/cli/, proto/

## Sprint 24 (`97b36cd`)
- **REST API endpoints:** GET /api/v1/system/buffers (BPF map utilization), GET /api/v1/security/sessions/summary/zone-pairs (per-zone-pair protocol breakdown), GET /api/v1/config/search?q=pattern
- **show system buffers detail:** Sorted by utilization, per-map key/value sizes, filtered to hash/LRU maps
- **Commit descriptions:** commit comment "reason" stores description in history; shown in show system commit history
- **Pipe filters:** | find (print from first match), | count (line count), | last N (tail)
- Files: 11 files, 518 insertions — pkg/{api,cli,cmdtree,configstore,grpcapi}/, cmd/cli/, proto/

## Sprint CC-1/CC-2: Chassis Cluster State Machine & Show Commands (`c0ee579`)
- **New pkg/cluster/ package:** Manager with NodeState enum (primary/secondary/secondary-hold/lost/disabled), RedundancyGroupState tracking, weight-based failover scoring, manual failover/reset
- **Config extensions:** cluster-id, node-id, heartbeat-interval, heartbeat-threshold, preempt flag — AST + compiler + 4 parser tests
- **Show commands:** show chassis cluster status/interfaces/information/statistics — Junos-style output across local CLI, remote CLI, gRPC
- **Request commands:** request chassis cluster failover redundancy-group N / reset — local + remote CLI + gRPC SystemAction
- **Daemon integration:** cluster.Manager created at init, updated on config apply, interface monitor weights fed into state machine
- **15 unit tests** for state transitions, weight calculation, election logic
- Files: 11 files, 1440 insertions — pkg/{cluster,config,cli,cmdtree,daemon,grpcapi}/, cmd/cli/

## Sprint CC-3 through CC-7: Cluster Autofailover, Heartbeat, Session Sync (`6e4d35c`)

### CC-3: Autofailover, Gratuitous ARP, IP Monitoring
- **IP monitoring config:** `IPMonitoring` struct with `GlobalWeight`, `GlobalThreshold`, per-target `IPMonitorTarget` (address + weight)
  - AST schema: `ip-monitoring` → `global-weight`, `global-threshold`, `family inet <addr> weight <N>`
  - Compiler: `compileChassis()` parses both hierarchical and inline key syntax for IP targets
  - Files: pkg/config/{types.go, ast.go, compiler.go}
- **Monitor goroutine (pkg/cluster/monitor.go):** `Monitor` struct with periodic 1s poll loop
  - **Interface monitoring:** Uses `netlink.LinkByName()` to check `OperState`/`Flags`, calls `SetMonitorWeight()` on change
  - **IP monitoring:** ICMP echo probes via `x/net/icmp` with 800ms timeout, `"ip:"` prefix on monitor names to distinguish from interfaces
  - Testable: `nlLinkGetter` and `icmpConn` interfaces for mocking netlink/ICMP
  - `UpdateGroups()` for hot-reconfiguration from UpdateConfig
- **Gratuitous ARP (pkg/cluster/garp.go):** `SendGratuitousARP()` sends raw ARP replies via `AF_PACKET`
  - Builds 42-byte Ethernet+ARP gratuitous reply packet (broadcast dst, own MAC/IP)
  - Configurable count with 100ms inter-packet gap
  - Triggered automatically on primary transition via `sendEvent()` → `triggerGARP()`
  - Per-RG GARP count from config (`garpCounts` map), default 4
  - `htons()` helper for big-endian protocol fields
- **Manager Start/Stop lifecycle:** `m.Start(ctx)` starts monitor; `m.Stop()` halts it
  - `RegisterRethIPs()` stores interface→IP mappings for GARP; called from daemon's `applyConfig()`
  - `triggerGARP()` fires in a goroutine on primary transition (avoids holding lock during I/O)
- **Daemon integration (pkg/daemon/daemon.go):**
  - `d.cluster.Start(ctx)` called after init; `d.cluster.Stop()` on shutdown
  - `applyConfig()` builds `RethIPMapping` list from interfaces with `RedundancyGroup > 0`, registers with cluster manager

## Sprint CC-5: Heartbeat & Peer Communication (Control Links)
- **Heartbeat wire protocol (pkg/cluster/heartbeat.go):**
  - Custom binary protocol: `"BPFX"` magic + version(1) + NodeID + ClusterID(LE16) + per-RG entries
  - `HeartbeatPacket` / `HeartbeatGroup` structs; `MarshalHeartbeat()` / `UnmarshalHeartbeat()`
  - Per-group entry: GroupID(1) + Priority(LE16) + Weight(1) + State(1) = 5 bytes per RG
  - Total header: 9 bytes + N×5 bytes per group
  - Port 4784 (UDP), defaults: 1s interval, 3 missed = peer lost
- **heartbeatSender:** Periodic UDP unicast to peer; calls `m.buildHeartbeat()` to snapshot local state
- **heartbeatReceiver:** Two goroutines: `readLoop()` (packet parsing, cluster ID validation, self-ignore) + `timeoutLoop()` (missed heartbeat → peer lost)
  - `atomic.Int64` for `lastSeen` timestamp (lock-free)
  - `handlePeerHeartbeat()` updates Manager's peer state; `handlePeerTimeout()` marks peer lost
- **Manager peer state fields:** `peerAlive`, `peerNodeID`, `peerGroups map[int]PeerGroupState`
- **Config extensions:** `ControlInterface` (string), `ControlLinkRecovery` (bool) in ClusterConfig
  - AST: `control-interface`, `control-link-recovery`, `control-ports fpc N port N`
- **Election integration:** `UpdateConfig()`, `recalcWeight()`, `ResetFailover()` all use `runElection()` when peer alive, `electSingleNode()` otherwise

## Sprint CC-4: Election Logic (pkg/cluster/election.go)
- **`EffectivePriority(base, weight)`:** `base * weight / 255` — integer-scaled priority
- **`electRG(rg, peerGroup)`:** Full Junos-style election per redundancy group:
  - Peer lost + weight > 0 → primary; weight = 0 → always secondary
  - Peer alive: compare effective priorities
  - **Preempt mode:** Higher effective priority wins immediately
  - **Non-preempt mode:** Incumbent stays unless weight drops to 0
  - **Split-brain:** Both primary → lower node ID wins
  - **Tie-breaking:** Lower node ID wins on equal effective priority
  - Skips disabled and manually failed-over groups
- **`runElection()`:** Iterates all RGs, applies `electRG()`, emits state change events

## Sprint CC-6+7: Session Sync (RTO) & RETH/BPF Integration
- **Session sync protocol (pkg/cluster/sync.go):** TCP-based Real-Time Object replication
  - **Wire format:** `syncHeader` (12 bytes) — `"BPSY"` magic + type(1) + pad(3) + length(LE32)
  - **Message types:** SessionV4(1), SessionV6(2), DeleteV4(3), DeleteV6(4), BulkStart(5), BulkEnd(6), Heartbeat(7)
  - **SessionSync struct:** localAddr/peerAddr, buffered sendCh (4096), TCP listener + connector
  - `QueueSessionV4/V6()`, `QueueDeleteV4/V6()` — non-blocking enqueue with connected check
  - `BulkSync()` — sends entire session table via `dp.IterateSessions()` / `dp.IterateSessionsV6()`
  - `acceptLoop()` / `connectLoop()` — dual-connect (listener + dialer with 5s retry)
  - `receiveLoop()` — framed reads with 30s timeout, keepalive on timeout, 1MB sanity limit
  - `handleMessage()` — DeleteV4/V6 decoded and applied via `dp.DeleteSession()`/`dp.DeleteSessionV6()`; SessionV4/V6 counted (full install pending DataPlane.SetSession interface)
  - `FormatStats()` — Junos-style statistics display
  - `SyncStats` — atomic counters for sent/received/deletes/bulks/errors/connected
- **Session encoding helpers:**
  - `encodeSessionV4Payload()` — full field-by-field encoding: key(16) + state/flags/TCP/reverse(5) + timestamps(16) + timeout/policy(8) + zones(4) + NAT IPs/ports(12) + counters(32) + reverse key(16) + ALG/log(4)
  - `encodeSessionV6Payload()` — same layout with 16-byte IP fields (512-byte buffer)
  - `encodeDeleteV4()`/`encodeDeleteV6()` — header+key only
- **Tests (pkg/cluster/sync_test.go):** 6 tests — header encoding, v4 session encode, v6 delete encode, v6 session encode, stats init, queue-without-connection
- **RETH failover controller (pkg/cluster/reth.go):** `RethController` manages bond member activation
  - `HandleStateChange(event)` — primary → activate (bond + members UP), secondary/lost → deactivate (members DOWN)
  - `RethIPs()` — queries netlink for IPv4 addresses on RETH bond (for GARP)
  - `FormatStatus()` — tabular display of RETH interfaces with RG, status, members
  - `SetMappings()` — updates RETH→RG mappings at runtime

### Key Design Decisions
- **Heartbeat protocol:** Custom binary (not gRPC/protobuf) for minimal overhead and fast parsing in hot path
- **Session sync over TCP (not UDP):** Reliable delivery for session state; TCP keepalive handles connection health
- **Election in Manager (not separate service):** Keeps all cluster state in one mutex-protected struct
- **GARP via AF_PACKET:** Direct raw socket avoids dependency on arping/ip commands
- **Monitor testability:** Interfaces (`nlLinkGetter`, `icmpConn`) allow unit testing without real network

### Files Created/Modified (CC-3 through CC-7)
| File | Lines | Description |
|------|-------|-------------|
| `pkg/cluster/cluster.go` | 708 | **MOD** — Manager: peer state, GARP, heartbeat, monitor lifecycle, FormatStatus/FormatInformation |
| `pkg/cluster/election.go` | 180 | **NEW** — Per-RG election logic (preempt/non-preempt/split-brain) |
| `pkg/cluster/election_test.go` | 425 | **NEW** — Election unit tests incl FormatInformation |
| `pkg/cluster/monitor.go` | 256 | **NEW** — Interface + IP reachability monitoring goroutine |
| `pkg/cluster/monitor_test.go` | 307 | **NEW** — Monitor unit tests with mock netlink/ICMP |
| `pkg/cluster/garp.go` | 90 | **NEW** — Gratuitous ARP raw packet construction + send |
| `pkg/cluster/garp_test.go` | 113 | **NEW** — GARP packet encoding tests |
| `pkg/cluster/heartbeat.go` | 292 | **NEW** — UDP heartbeat wire protocol, sender, receiver |
| `pkg/cluster/heartbeat_test.go` | 206 | **NEW** — Heartbeat marshal/unmarshal tests |
| `pkg/cluster/sync.go` | 704 | **NEW** — TCP session sync (RTO) protocol + encoding |
| `pkg/cluster/sync_test.go` | 165 | **NEW** — Sync encoding/stats tests |
| `pkg/cluster/reth.go` | 178 | **NEW** — RETH bond failover controller |
| `pkg/cluster/reth_test.go` | 64 | **NEW** — RETH controller tests |
| `pkg/config/types.go` | — | **MOD** — IPMonitoring, IPMonitorTarget, ControlInterface, ControlLinkRecovery |
| `pkg/config/ast.go` | — | **MOD** — ip-monitoring, control-interface, control-link-recovery, control-ports schema |
| `pkg/config/compiler.go` | — | **MOD** — compileChassis: IP monitoring targets + control-interface parsing |
| `pkg/config/parser_test.go` | — | **MOD** — 2 IP monitoring tests (hierarchical + set syntax) |
| `pkg/daemon/daemon.go` | — | **MOD** — cluster Start/Stop lifecycle, RETH IP registration in applyConfig |
| `pkg/grpcapi/server.go` | — | **MOD** — chassis-cluster-information uses FormatInformation() |
| **Total cluster pkg** | **4250** | **14 files, 7 new source + 7 new test** |

## Sprint GAP-1/GAP-2: vsrx.conf Feature Gap Closure (`24bcfa1`, `5175d07`, `9c4f820`, `f12d1b2`)

### NAT Enhancements
- **Source-NAT off (exemption):** `source-nat { off; }` in NAT source rules — exempts matching traffic from SNAT
- **DNAT source-address-name:** Match DNAT rules by address-book name, resolved during compilation; AST schema + compiler + validation warning if name not found
- **DNAT destination-port ranges:** `destination-port 20000 to 30000` syntax with `parseDNATPortList()` — handles hierarchical multi-port, single port, set-syntax range; expands to port list for BPF
- **DNAT protocol matching:** `protocol gre` (47) and `protocol icmp6` (58) in DNAT rules; `protocolNumber()` now handles GRE + numeric protocol strings
- **SNAT multiple source-address list parsing:** Bug fix — only first address was captured (task #14, in progress)

### Routing Enhancements
- **IPv6 route leaking (next-table inet6.0):** `rib inet6.0 { static { route ::/0 next-table X.inet6.0; } }` — IPv6 inter-VRF route leaking via `ip -6 rule`
- **Multi-VRF rib-groups (8+ import-ribs):** Scaled up ip rule generation for rib-groups with 8+ import-ribs (e.g., `Other-ISPS` with 8 VRFs)
- **Global interface-routes rib-group:** `routing-options { interface-routes { rib-group { inet X; inet6 Y; } } }` — new `InterfaceRoutesRibGroup`/`InterfaceRoutesRibGroupV6` fields on RoutingOptionsConfig
- **IPv6 rib-group leaking:** `ApplyRibGroupRules()` now handles both `InterfaceRoutesRibGroup` and `InterfaceRoutesRibGroupV6`, creating both IPv4 and IPv6 ip rules per source table
- **BGP family inet/inet6 unicast:** Per-address-family config in BGP groups → FRR `address-family ipv4/ipv6 unicast` blocks
- **Route-filter exact:** Policy-statement route-filter matching → FRR `ip prefix-list` + `route-map match`
- **Next-hop peer-address:** Junos `next-hop peer-address` → FRR `set ip next-hop peer-address` (was incorrectly a no-op)
- **Next-hop self (term-scoped, #5115):** Junos `then next-hop self` lowers to a per-term route-map `set ip/ipv6 next-hop peer-address` clause — in an OUTBOUND route-map `peer-address` resolves to the local session address (= self) and is evaluated per-route, so it rewrites ONLY the term's routes. Earlier revisions emitted the neighbor-wide `neighbor <peer> next-hop-self force` knob, which ran after route selection and rewrote EVERY route advertised to the peer (widening a term-scoped action, #5115). The outbound set-clause still overrides iBGP / route-reflector-reflected next-hops (the #2977 fix), now correctly scoped; a bare `then next-hop self` term (no `from` match) renders a match-all sequence and keeps neighbor-wide effect.
- **Forwarding-table export load-balancing:** ECMP load-balancing policy → FRR settings

### Application Enhancements
- **Source-port ranges in applications:** `source-port 41642-65535` parsed into `SourcePort` field; `parsePortRange()` returns (low, high) boundaries
- **BPF source-port matching:** `app_value` struct extended with `src_port_low`/`src_port_high` (both BPF C + Go); `xdp_policy.c` checks source port range if specified in app match
- **DataPlane interface update:** `SetApplication()` signature extended with `srcPortLow, srcPortHigh uint16`; eBPF + DPDK parity

### IPsec Enhancements
- **df-bit (copy|set|clear):** `set security ipsec vpn X df-bit <mode>` → strongSwan `copy_df`. `copy` and `set` → `copy_df=yes` (outer DF copied from / preserved with inner; strongSwan cannot force outer DF=1, so `set` keeps PMTUD rather than clearing DF). `clear` → `copy_df=no` (outer DF forced to 0 — allow fragmentation of oversized packets into the tunnel). #4015 fixed a set/clear inversion where `set` emitted `copy_df=no` (clearing DF) and `clear` fell through to the default (`copy_df=yes`).
- **establish-tunnels immediately:** Auto-establish at boot → strongSwan `auto=start` (vs `auto=route`)
- **IKE gateway dynamic hostname:** DNS hostname for peer → strongSwan `right=hostname`
- **IKE gateway local-address:** Explicit local address → strongSwan `left=X.X.X.X`
- **IKE policy mode aggressive:** → strongSwan `aggressive=yes`; resolved through gateway→ike-policy chain

### Tunnel Enhancements
- **IP-IP tunnels (ip-0/0/0):** Plain IP-in-IP encapsulation (mode ipip); auto-detected from `ip-` prefix in interface name
- **GRE tunnel routing-instance destination:** Bind tunnel to specific VRF for decapsulated traffic → `ip link set dev grX vrf <vrf-name>`
- **Point-to-point flag:** `unit 0 point-to-point` → `PointToPoint` field on UnitConfig
- **Explicit mode override:** `tunnel mode ipip` on any interface (even `gr-` prefix) is honored

### System & Host-Inbound Enhancements
- **Host-inbound router-discovery:** New `HostInboundRouterDiscovery` flag (bit 20) for `protocols router-discovery`; BPF `host_inbound_flag()` checks ICMP type 9/10 (IRDP Router Advertisement/Solicitation); both eBPF + DPDK parity
- **Host-inbound vrrp:** Added to `HostInboundProtocolFlags` map
- **lo0 filter input:** `Lo0FilterInputV4`/`Lo0FilterInputV6` extracted from lo0 interface config; `applyLo0Filter()` generates nftables rules from firewall filter terms; `nftRuleFromTerm()` maps source/dest addresses, protocols, ports, actions to nft syntax; atomic apply via `nft -f -`; cleanup on empty config
- **system no-redirects:** Sysctl `net.ipv4.conf.all.send_redirects=0` + `accept_redirects=0`
- **system backup-router:** Parsed and stored

### Test Coverage (20+ new test functions)
- `TestIPIPTunnelSetSyntax`, `TestIPIPTunnelExplicitMode` — IP-IP tunnel config + mode auto-detection
- `TestGRETunnelRoutingInstanceDestination` — GRE VRF binding
- `TestPointToPointFlag` — unit point-to-point config
- `TestIPsecAggressiveModeSetSyntax` — Full IPsec feature chain (aggressive, local-address, dynamic hostname, df-bit, establish-tunnels)
- `TestGlobalInterfaceRoutesRibGroup`, `TestGlobalInterfaceRoutesRibGroupSetSyntax` — Global rib-group inet/inet6
- `TestIPv6NextTableStaticRoutes` — IPv6 inter-VRF route leaking
- `TestDNATSourceAddressName`, `TestDNATSourceAddressNameSetSyntax` — DNAT address-book name matching
- `TestDNATPortRange`, `TestDNATPortRangeSetSyntax` — DNAT port range parsing
- `TestDNATProtocolGRE`, `TestDNATProtocolICMP6` — DNAT protocol matching
- `TestNextHopPeerAddress` — FRR next-hop peer-address mapping
- `TestRouteFilterExactFRR` — Route-filter exact → prefix-list generation
- `TestMultiVRFRibGroupLeaking`, `TestIPv6OnlyRibGroupLeaking` — Multi-VRF rib-group leaking detection
- `TestRouterDiscoveryProtocolSetSyntax` — Router-discovery host-inbound protocol
- `TestLo0FilterExtraction`, `TestLo0FilterExtractionSet` — lo0 filter input extraction from interfaces
- `TestHostInboundRouterDiscovery` — Host-inbound flag for router-discovery
- `TestHostInboundRouterDiscoveryFlag` — Bit 20 verification for router-discovery flag
- `TestNat66SourceRules` — Pure IPv6-to-IPv6 SNAT rules

### Bug Fixes
- **SNAT multiple source-address list parsing:** Only first source-address was captured; now loops over `SourceAddresses []string`, creating one BPF rule per address with shared counter ID
- **TC mirror counter race:** `__sync_fetch_and_add(cnt, 1)` return value was used before increment; fixed by reading `*cnt` first then incrementing separately
- **lo0 nftables prefix-list expansion (`5175d07`):** Properly expands source/dest prefix-lists via `prefixLists` map, supports nftables set syntax `{ cidr1, cidr2 }`, separate `reject` vs `drop`, DSCP matching, ICMP type/code, TCP flags, IP fragment detection
- **DPDK source-port byte order (`5175d07`):** DPDK `policy.c` source-port comparison needed byte-order alignment with BPF values
- **Static NAT source-address + NAT64 inet:** `StaticNATRule.SourceAddress` for source matching; `static-nat { inet; }` for NAT64 translation; `NATv6v4Config.NoV6FragHeader` option

### DPDK Parity
- **Source-port range in policy.c:** `app_value.src_port_low/high` checked in `policy_check()`; same logic as xdp_policy.c
- **shared_mem.h:** `HOST_INBOUND_ROUTER_DISCOVERY` (1<<20), `src_port_low/high` in `app_value`
- **forward.c:** IRDP ICMP type 9/10 → `HOST_INBOUND_ROUTER_DISCOVERY`

### Named Port Resolution (`9c4f820`)
- Expanded `resolvePortName()` with 12 additional named ports: domain(53), ftp-data(20), snmptrap(162), pop3(110), imap(143), ldap(389), syslog(514), radacct(1813), radius(1812), ike(500)
- `TestResolvePortName` and `TestResolvePortRangeNamed` tests

### BPF Objects Regenerated
- `make generate` run — all 14 BPF programs (9 XDP + 5 TC) recompiled with new `app_value` struct and host-inbound flags

### Files Modified (52 files, 2052+ insertions)
| File | Changes |
|------|---------|
| `bpf/headers/xpf_maps.h` | `src_port_low/high` in `app_value` |
| `bpf/xdp/xdp_policy.c` | Source port range check in app matching |
| `pkg/config/ast.go` | `source-address-name` schema |
| `pkg/config/compiler.go` | DNAT port ranges, source-address-name, IP-IP mode, global rib-group, lo0 filter |
| `pkg/config/parser_test.go` | 14 new test functions (634 lines) |
| `pkg/config/types.go` | `SourceAddressName`, `Lo0Filter*`, `InterfaceRoutesRibGroup*` |
| `pkg/daemon/daemon.go` | `applyLo0Filter()` call |
| `pkg/dataplane/compiler.go` | Source-port range, DNAT validation, GRE protocol, `parsePortRange()` |
| `pkg/dataplane/dataplane.go` | `SetApplication()` signature extended |
| `pkg/dataplane/dpdk/dpdk_cgo.go` | DPDK source-port parity |
| `pkg/dataplane/dpdk/dpdk_stub.go` | DPDK stub parity |
| `pkg/dataplane/maps.go` | Source-port in `AppValue` → `htons()` |
| `pkg/dataplane/types.go` | `SrcPortLow/High`, `HostInboundRouterDiscovery`, `router-discovery`/`vrrp` protocol flags |
| `pkg/frr/frr.go` | `next-hop peer-address` → FRR fix |
| `pkg/frr/frr_test.go` | `TestNextHopPeerAddress`, `TestRouteFilterExactFRR` |
| `pkg/ipsec/ipsec.go` | Aggressive mode via gateway→ike-policy chain |
| `pkg/ipsec/ipsec_test.go` | IPsec strongSwan config test (114 lines) |
| `pkg/routing/routing.go` | IPv6 rib-group leaking, multi-VRF support |
| `pkg/routing/routing_test.go` | `TestMultiVRFRibGroupLeaking`, `TestIPv6OnlyRibGroupLeaking` |

## Sprint GAP-3: Screen Stats, LLDP Interface Control, Generate Routes (`03310a7`)

### Global Screen Statistics
- `show security screen statistics` without zone filter: `showScreenStatisticsAll()` iterates all zones sorted alphabetically, shows per-zone flood counters (SYN/ICMP/UDP) with screen profile name
- Previously returned "usage" error when no zone specified; now falls through to all-zone display
- Uses `CompileResult.ZoneIDs` for zone enumeration, `ReadFloodCounters()` per zone
- File: pkg/cli/cli.go (46 lines added)

### LLDP Per-Interface Enable/Disable
- Per-interface `disable` control: `protocols lldp interface eth1 { disable; }` or `set protocols lldp interface eth1 disable`
- `LLDPInterface` struct (Name + Disable) replaces plain string in both `config.LLDPConfig` and `lldp.LLDPConfig`
- AST schema: `disable` child node added under `lldp > interface`
- Compiler: `FindChild("disable")` sets `LLDPInterface.Disable = true`
- Runtime: `lldp.Manager.Apply()` skips disabled interfaces with `continue`
- Daemon: converts `config.LLDPInterface` → `lldp.LLDPInterface` in Run()
- CLI + gRPC: `show lldp` displays "(disabled)" label per-interface
- Tests: `TestLLDPPerInterfaceDisable` (hierarchical) + `TestLLDPPerInterfaceDisableSetSyntax` (flat set)
- Files: pkg/config/{ast,compiler,types,parser_test}.go, pkg/lldp/lldp.go, pkg/daemon/daemon.go, pkg/cli/cli.go, pkg/grpcapi/server.go

### Routing-Options Generate Routes
- `routing-options generate route X/Y { policy Z; discard; }` — Junos aggregate/summary route generation
- `GenerateRoute` struct: Prefix, Policy, Discard fields in `RoutingOptionsConfig.GenerateRoutes`
- AST schema: `routing-options > generate > route` with `policy` (args:1) and `discard` children
- Compiler: `compileRoutingOptions()` handles both hierarchical (`FindChild`) and inline key syntax
- FRR wiring: rendered as `ip route <prefix> blackhole` (IPv4) or `ipv6 route <prefix> blackhole` (IPv6)
- `FullConfig.GenerateRoutes` passed from daemon to FRR manager
- gRPC: `showScreenStatisticsAll()` wired to ShowText handler for remote CLI
- Tests: `TestGenerateRoutes` (hierarchical), `TestGenerateRoutesSetSyntax` (flat set), `TestGenerateRoutesFRR` (FRR blackhole output)
- Files: pkg/config/{ast,compiler,types,parser_test}.go, pkg/frr/{frr,frr_test}.go, pkg/daemon/daemon.go

## Sprint CC-8: Two-VM Chassis Cluster Test Environment

### Config System: peer-address
- Added `PeerAddress string` to `ClusterConfig` in `pkg/config/types.go`
- Added `peer-address` schema node (args:1) under chassis cluster in `pkg/config/ast.go`
- Parser: `compileChassis()` handles `peer-address` via `FindChild` + `nodeVal`
- Daemon: `pkg/daemon/daemon.go` wires `StartHeartbeat(localIP, peerAddr)` after cluster init
  - Uses existing `resolveInterfaceAddr()` to get local IP from control interface
  - Only starts heartbeat when both `ControlInterface` and `PeerAddress` are configured

### Cluster Test Environment
- `test/incus/cluster-setup.sh` — manages two-VM HA cluster (xpf-fw0, xpf-fw1)
- Commands: init, create, destroy, deploy [0|1|all], ssh 0|1, status, logs, start/stop/restart
- Networks: xpf-heartbeat, xpf-fabric, xpf-cluster-lan (all L2 bridges, no Incus IP)
- Profile: xpf-cluster (4 CPU, 4GB RAM, 20GB disk)
- SR-IOV VFs from eno6np1 for WAN RETH
- Test container: cluster-lan-host (10.0.60.102/24) on xpf-cluster-lan bridge
- Per-node configs: `test/incus/xpf-cluster-fw{0,1}.conf`
- Makefile targets: cluster-init, cluster-create, cluster-deploy, cluster-destroy, etc.

### IP Addressing
| Link | Subnet | fw0 | fw1 |
|------|--------|-----|-----|
| Heartbeat | 10.99.0.0/30 | 10.99.0.1 | 10.99.0.2 |
| Fabric/Sync | 10.99.1.0/30 | 10.99.1.1 | 10.99.1.2 |
| WAN RETH (reth0) | 172.16.50.0/24 | VIP 172.16.50.10 | |
| LAN RETH (reth1) | 10.0.60.0/24 | VIP 10.0.60.1 | |

### Files
- `test/incus/cluster-setup.sh` (new)
- `test/incus/xpf-cluster-fw0.conf` (new)
- `test/incus/xpf-cluster-fw1.conf` (new)
- `Makefile` (cluster-* targets)
- `pkg/config/types.go` (PeerAddress field)
- `pkg/config/ast.go` (peer-address schema)
- `pkg/config/compiler.go` (peer-address parsing)
- `pkg/daemon/daemon.go` (heartbeat startup wiring)

## Sprint CC-9: Config Sync (Primary→Secondary)

### Overview
Configuration synchronization between chassis cluster nodes. Primary node pushes full config text to secondary after each commit. A secondary **whose read-only gate is armed** rejects every user config mutation. Arming is not universal (#6896): `SetClusterReadOnly(true)` is reached only from the RG0 **transition** handler (see the CC-9 store section below) and `clusterReadOnly` starts `false`, so a node that cold-starts as secondary and never transitions is not gated — tracked as #6890, with #6889 the dropped-event variant. Read this as the design intent, not as a property every secondary has.

### Config Sync Protocol (pkg/cluster/sync.go)
- **New message type:** `syncMsgConfig = 8` — full config text sync from primary to secondary
- **`QueueConfig(configText string)`:** Sends full config text directly on TCP connection (not via sendCh channel — config can be large)
- **`OnConfigReceived func(configText string)`:** Callback field on `SessionSync` struct, set by daemon before `Start()`
  - Called in a goroutine when `syncMsgConfig` received, with full config text as string
- **Payload limit increased:** 1MB → 16MB (`16*1024*1024`) to accommodate large config files
- **Stats:** `ConfigsSent`/`ConfigsReceived` atomic counters added to `SyncStats`
- **FormatStats:** Updated to display config sent/received counts

### Config Store Read-Only Mode (pkg/configstore/store.go) — COMPLETE
- **`clusterReadOnly bool`** field on `Store` struct
- **`SetClusterReadOnly(ro bool)`** — toggles mode (called by daemon on cluster state change)
- **`ClusterReadOnly() bool`** — getter for read-only state
- **`EnterConfigureSession()`** / **`EnterConfigureExclusive()`** — reject with the `ErrClusterReadOnly` sentinel (`"configuration is read-only on the cluster secondary"`, `errors.Is`-comparable) when read-only
- **Every user-session mutating op enforces read-only too (#3893)** — `Set`/`Delete`/`Deactivate`/`Activate`/`Copy`/`Rename`/`Insert`/`Annotate`/`Load*`/`Commit`/`CommitConfirmed`/`Rollback` route through `ensureWritableLocked()` and return `ErrClusterReadOnly` on a secondary, so a session opened before the node went secondary can no longer Set+Commit and diverge the standby. The internal convergence paths (`SyncApply`, `PromoteRollback`) promote `active`/`compiled` directly and are deliberately **not** gated.
- **`SyncApply(content string, chassisPreserve func(*ConfigTree)) (*Config, error)`** — bypasses read-only checks for applying config received from primary
  - Parses config text, calls optional `chassisPreserve` callback to patch tree before compilation
  - Pushes current active to history, promotes new tree, persists to DB
  - Logs `"config_sync"` action to journal
  - Updates candidate if in config mode

### Config Extensions (pkg/config/)
- **`FabricInterface string`** — interface for session/config sync (e.g. "fab0")
- **`FabricPeerAddress string`** — peer's fabric link IP (e.g. "10.99.1.2")
- **`ConfigSync bool`** — enable `configuration-synchronize` (trigger config push on commit)
- AST schema: `fabric-interface` (args:1), `fabric-peer-address` (args:1), `configuration-synchronize` (leaf)

### Daemon Wiring (pkg/daemon/daemon.go) — COMPLETE
- **`sessionSync *cluster.SessionSync`** field on Daemon struct
- **Fabric link initialization:** When `FabricInterface` + `FabricPeerAddress` configured, creates SessionSync on `<fabIP>:4785`
- **`OnConfigReceived` callback:** Wired before `Start()` — calls `handleConfigSync()`
- **`applyAndSync` wrapper:** gRPC `ApplyFn` wraps `applyConfig()` + `syncConfigToPeer()` — every commit triggers config push
- **`syncConfigToPeer()`:** Checks `IsLocalPrimary(0)` + `ConfigSync` enabled → calls `ShowActive()` → `QueueConfig()`
- **`handleConfigSync(configText)`:** Receives config from primary, preserves local `chassis` node, calls `SyncApply()`, applies compiled config
  - Gets local chassis node via `ActiveTree().FindChild("chassis")`
  - Replaces received chassis node with local one (preserves node-id, peer addresses)
  - Falls back to appending local chassis if received config has none
- **`watchClusterEvents(ctx)`:** Goroutine watching `cluster.Events()` channel
  - RG0 → `StatePrimary`: `SetClusterReadOnly(false)` — enable config writes
  - RG0 → `StateSecondary`/`StateSecondaryHold`: `SetClusterReadOnly(true)` — disable config writes
- **Shutdown:** `d.sessionSync.Stop()` before cluster manager stop

### Design Decisions
- **Full config text (not incremental):** Simpler, avoids ordering bugs, config is small relative to sessions
- **Preserves local chassis section:** Each node has unique node-id, peer-address, control-interface
- **16MB payload limit:** Config files rarely exceed a few hundred KB, but generous limit avoids surprises
- **Direct TCP write (not channel):** Config sync is infrequent and large — avoids filling the 4096-entry sendCh buffer
- **Callback pattern:** `OnConfigReceived` decouples sync protocol from config store dependency

### Junos Comparison
- Junos uses `groups { node0 {} node1 {} }` with `apply-groups "${node}"` for per-node config
- xpf uses separate per-node chassis config files instead (simpler, no group inheritance needed)
- In Junos, node1's ge-7/0/X maps to node0's ge-0/0/X (interface numbering offset) — xpf doesn't need this as interface names are consistent

### Files Modified
| File | Changes |
|------|---------|
| `pkg/cluster/sync.go` | `syncMsgConfig=8`, `QueueConfig()`, `OnConfigReceived` callback, 16MB limit, config stats |
| `pkg/configstore/store.go` | `clusterReadOnly`, `SetClusterReadOnly()`/`ClusterReadOnly()`, `SyncApply()`, `ActiveTree()` |
| `pkg/config/types.go` | `FabricInterface`, `FabricPeerAddress`, `ConfigSync` on ClusterConfig |
| `pkg/config/ast.go` | `fabric-interface`, `fabric-peer-address`, `configuration-synchronize` schema nodes |
| `pkg/config/compiler.go` | `compileChassis()` handles fabric-interface, fabric-peer-address, configuration-synchronize |
| `pkg/daemon/daemon.go` | `sessionSync` field, `syncConfigToPeer()`, `handleConfigSync()`, `watchClusterEvents()`, `applyAndSync` wrapper |
| `test/incus/xpf-cluster-fw0.conf` | Added fabric-interface, fabric-peer-address, configuration-synchronize |
| `test/incus/xpf-cluster-fw1.conf` | Added fabric-interface, fabric-peer-address, configuration-synchronize |

## Sprint FF-1: Firewall Filter Enhancements (`b5827da`) — COMPLETE

### Overview
Closed feature gap #17 from docs/feature-gaps.md. Added policer (rate limiting), three-color policer, interface policer, lo0 filter BPF wiring, and flexible match conditions. **46 files changed, ~2481 insertions.** All 5 features fully wired: BPF C + Go types + config compiler + dataplane compiler + tests. All 14 BPF programs pass verifier, 630+ tests pass.

### Feature-Gaps Doc (`b5827da`)
- Created comprehensive `docs/feature-gaps.md` — 23 categories, 177 total gaps identified
- Priority tiers: Tier 1 (core NGFW), Tier 2 (enterprise), Tier 3 (specialized)
- Parse-only features cataloged (9 items)
- Implementation suggestions for top gaps

### AST Schema: Policer & Address-Book (`b5827da`)
- `firewall > policer` schema: `if-exceeding` (bandwidth-limit, burst-size-limit), `then` (discard, loss-priority)
- `firewall > family > filter > term > then > policer` action reference
- `security > address-book` global address-book schema (name → address children)
- Parser tests: `TestPolicerConfig` (hierarchical) + `TestPolicerConfigSetSyntax` (flat set)

### Single-Rate Policer — Token Bucket (COMPLETE)
**Full stack:** BPF C + Go types + config compiler + dataplane compiler + DPDK parity + tests

- **BPF structs (`xpf_common.h`):**
  - `struct policer_config` — `rate_bytes_sec` (u64), `burst_bytes` (u64), `action` (u8), pad[7] = 24 bytes
  - `struct policer_state` — `tokens` (u64), `last_refill_ns` (u64) = 16 bytes
  - `struct filter_rule` extended: `policer_id` (u8) + `pad_rule[3]` at end
  - `MAX_POLICERS = 64`, `POLICER_ACTION_DISCARD = 0`
- **BPF maps (`xpf_maps.h`):**
  - `policer_configs` — ARRAY, 64 entries, policer_id → policer_config (written by userspace)
  - `policer_states` — PERCPU_ARRAY, 64 entries, policer_id → policer_state (lock-free runtime)
- **BPF evaluation (`xpf_helpers.h`):** `evaluate_policer(policer_id, pkt_len)` — token-bucket
  - Overflow-safe refill: `(elapsed/1000) * rate / 1000000` (splits ns→us division)
  - Cap at burst_bytes, deduct pkt_len, return 0 (conform) or 1 (exceed)
  - Called from `evaluate_firewall_filter()` and `evaluate_firewall_filter_output()` when `rule->policer_id > 0`
- **Config types (`pkg/config/types.go`):**
  - `PolicerConfig` struct: Name, BandwidthLimit (bytes/sec), BurstSizeLimit (bytes), ThenAction
  - `FirewallConfig.Policers map[string]*PolicerConfig`
  - `FirewallFilterTerm.Policer string` — reference to policer name
- **Config compiler (`pkg/config/compiler.go`):**
  - `parseBandwidthLimit()` — "1m" → 125000 B/s, "10g" → 1.25 GB/s, "500k" → 62500 B/s (bits→bytes)
  - `parseBurstSizeLimit()` — "15k" → 15000 bytes, "1m" → 1000000 bytes
  - `compileFirewall()` — parses `policer` named instances (if-exceeding, then)
  - `compileFilterThen()` — parses `then policer <name>` reference
- **Dataplane types (`pkg/dataplane/types.go`):**
  - `PolicerConfig` Go struct mirrors C struct (24 bytes)
  - `FilterRule.PolicerID uint8` + `PadRule [3]byte`
  - `MaxPolicers = 64`
- **Dataplane compiler (`pkg/dataplane/compiler.go`):**
  - Sorted policer name → ID assignment (1-based, deterministic)
  - `dp.SetPolicerConfig(polID, bpfCfg)` per policer
  - `expandFilterTerm()` maps `term.Policer` name → PolicerID on FilterRule
- **Dataplane maps (`pkg/dataplane/maps.go`):** `SetPolicerConfig()`, `ClearPolicerConfigs()`
- **DataPlane interface (`dataplane.go`):** `SetPolicerConfig(id, cfg)`, `ClearPolicerConfigs()`
- **DPDK parity:** `dpdk_stub.go` + `dpdk_cgo.go` stubs; `shared_mem.h` struct + pointer fields
- **BPF regenerated:** All 14 programs (9 XDP + 5 TC) recompiled with new maps
- **Tests:** `TestFirewallPolicer` (hierarchical) + `TestFirewallPolicerSetSyntax` (flat set)
  - Validates: bandwidth parsing (1m=125000, 10g=1.25G, 500k=62500), burst parsing (15k=15000, 10k=10000)
  - Validates: policer reference on filter term, both config syntaxes
- **Files changed:** 42 files, ~640 insertions (including bpf2go regeneration)

### lo0 Filter BPF Wiring (COMPLETE)
- **Native BPF evaluation** for host-inbound filtering
- `flow_config` struct: `lo0_filter_v4/v6` (u16), sentinel 0xFFFF = no filter
- `evaluate_filter_by_id()` BPF helper evaluates rules by ID directly
- `xdp_forward.c`: host-bound (`fwd_ifindex == 0`) → reads lo0 filter → evaluate
- Compiler resolves filter names to IDs, writes to flow_config_map

### Flexible Match Conditions (COMPLETE)
- `FlexMatchConfig`: MatchStart (layer-3), ByteOffset, BitLength, Value, Mask
- BPF: `FILTER_MATCH_FLEX (1<<12)`, meta-based evaluation (protocol, src/dst IP by offset)
- AST schema: `flexible-match-range > range` with all sub-fields

### Three-Color Policer (COMPLETE)
- **Config types:** `ThreeColorPolicerConfig` — CIR/CBS/PIR/PBS (uint64), TwoRate/ColorBlind (bool), ThenAction
- **BPF evaluation:** `evaluate_policer()` handles all 3 modes:
  - `POLICER_MODE_SINGLE_RATE=0`: Two-color (original)
  - `POLICER_MODE_TWO_RATE=1`: RFC 2698 — dual buckets (committed + peak), returns 0/1/2
  - `POLICER_MODE_SR3C=2`: RFC 2697 — CIR fills committed, overflow fills excess, returns 0/1/2
- **Dataplane compiler:** Three-color IDs continue after single-rate (sequential 1-based)
  - `bpfCfg.ColorMode` set to `PolicerModeTwoRate` or `PolicerModeSR3C`
  - `bpfCfg.PeakRate/PeakBurst` for PIR/PBS
- **Tests:** `TestThreeColorPolicer` (hierarchical), `TestThreeColorPolicerSetSyntax` (flat set)
  - Validates: CIR/CBS/PIR/PBS parsing (10m→1.25M, 50m→6.25M), TwoRate flag, ColorBlind flag, single-rate mode

### Interface Policer (COMPLETE)
- `LogicalInterfacePolicer` flag on PolicerConfig
- Parsed from `firewall policer <name> { logical-interface-policer; }`
- **Test:** `TestLogicalInterfacePolicer` — validates flag parsed from hierarchical syntax

### Tests Summary (8 new tests)
- **Config parser tests:** `TestFirewallPolicer`, `TestFirewallPolicerSetSyntax`, `TestThreeColorPolicer`, `TestThreeColorPolicerSetSyntax`, `TestLogicalInterfacePolicer`, `TestFlexibleMatchRange`, `TestFlexibleMatchRangeSetSyntax`
- **Dataplane compiler tests:** `TestExpandFilterTermFlexMatch`, `TestExpandFilterTermPolicerAndFlex`

## Sprint IF-1: Interface Enhancements — COMPLETE

### Overview
Closed 6 interface feature gaps from docs/feature-gaps.md section 21. Added LAG/ae bond support, flexible VLAN tagging (QinQ), interface bandwidth for OSPF cost, point-to-point FRR wiring, primary/preferred address ordering in networkd, and interface description display. All tests pass, validated on Incus VM. **Two of those six were later measured to be config-only, not closed:** LAG/ae (#6544, see the corrected subsection below) and flexible VLAN tagging / QinQ (#2354/#5879, now hard-rejected at commit).

### LAG / Link Aggregation (Missing → **Config-only**, corrected #6544)

> [!IMPORTANT]
> This section originally read "Missing → Implemented". It was wrong, and
> #6544 corrects it. `ae` / `802.3ad` is **config-only**: the parse and the
> bond GENERATORS both exist, but nothing connects them, so configuring a LAG
> creates no bond device, enslaves no member, runs no LACP and does not honour
> `minimum-links`. Configuring `ae` now emits an accepted-only advisory
> (`validateLinkAggregationWarnings`). The remaining feature work is tracked in
> the parity matrix (`docs/vsrx-gaps.md`, "Interface Redundancy (LAG)").

- **Config types:** `AggregatedEtherOptions` struct (LACPActive/Passive, LACPPeriodic, LinkSpeed, MinimumLinks), `LAGParent` string on InterfaceConfig — **compiled, and read by nothing**
- **Compiler:** Parses `gigether-options { 802.3ad <ae-name>; }` → LAGParent, `aggregated-ether-options { lacp { active; periodic fast; } ... }` → AggregatedEtherOpts. This part is real and is what the tests below cover.
- **networkd:** the `.netdev` bond generator (Kind=bond, Mode=802.3ad, LACPTransmitRate, MinLinks, TransmitHashPolicy=layer3+4) and the `Bond=<master>` member `.network` generator DO exist — but their only producer is `buildFabricBondModels` (`pkg/dataplane/compiler_iface.go`), which keys on `fabric-options member-interfaces` and hard-codes `active-backup`. An `ae` interface produces no model, so neither generator is ever reached for a LAG.
- **routing:** `ApplyBonds()` likewise reconciles kernel bonds from `FabricMembers` only; `LAGParent` members are never enslaved.
- **Tests:** `TestLAGInterface`, `TestLAGInterfaceSetSyntax` cover the PARSE; `TestGenerateNetdev_Bond`, `TestGenerateNetdev_BondDefaults`, `TestGenerateNetwork_BondMember` cover the GENERATORS in isolation. Neither end asserted that an `ae` config reaches a bond, which is how the "Implemented" claim survived. `compiler_validate_warn_lag_6544_test.go` now pins the accepted-only advisory.

### Flexible VLAN Tagging (Missing → Implemented)
- **Config types:** `FlexibleVlanTagging bool` on InterfaceConfig, `InnerVlanID int` on InterfaceUnit
- **Compiler:** Parses `flexible-vlan-tagging`, `encapsulation flexible-ethernet-services`, `inner-vlan-id <N>` on units
- **Tests:** `TestFlexibleVlanTaggingHierarchical`, `TestFlexibleVlanTaggingSetSyntax`

### Interface Bandwidth (Missing → Implemented)
- **Config types:** `Bandwidth uint64` on InterfaceConfig (stored as bps)
- **Compiler:** `parseBandwidthBps()` — "1g"→1000000000, "100m"→100000000, "500k"→500000
- **FRR:** `InterfaceBandwidths map[string]uint64` → emits `bandwidth <kbps>` in interface stanza for OSPF auto-cost
- **Tests:** `TestInterfaceBandwidth`, `TestInterfaceBandwidthSetSyntax`, `TestInterfaceBandwidthFRR`

### Point-to-Point (Parse-Only → Implemented)
- **Config types:** `PointToPoint bool` on InterfaceUnit
- **FRR:** `InterfacePointToPoint map[string]bool` → emits `ip ospf network point-to-point` when flag set and no explicit OSPF network-type
- **Tests:** `TestInterfacePointToPointAndMTU`, `TestPointToPointFlag`, `TestPointToPointFRR`, `TestBandwidthAndPointToPointCombined`

### Primary/Preferred Address (Parse-Only → Implemented)
- **Config types:** `PrimaryAddress string`, `PreferredAddress string` on InterfaceUnit
- **networkd:** `orderAddresses()` reorders list with PrimaryAddress first; PreferredAddress gets `[Address]` section with `PreferredLifetime=forever`
- **Tests:** `TestPreferredAddress`, `TestGenerateNetwork_PrimaryAddress`, `TestGenerateNetwork_PreferredAddress`

### Interface Description (Partial → Implemented)
- **Display:** gRPC server outputs `Description: <text>` in `show interfaces detail/terse`
- **networkd:** Description passed to systemd-networkd Description field
- **Tests:** `TestInterfaceDescriptionSetSyntax`
- **Existing tests updated:** 3 `expandFilterTerm()` calls updated with `policerIDs` parameter

### Remaining deeper gaps
- RADIUS/TACACS+ authentication
- Multicast routing (PIM/IGMP)

## Sprint HA-8: HA Enhancements — COMPLETE

### Overview
Closed all 6 remaining HA feature gaps from docs/feature-gaps.md section 16 (excluding already-implemented Primary/Preferred Address from IF-1). Added ISSU, NAT state sync (full session install), IPsec SA sync, active/active mode validation, RETH runtime with IPv6 NA, and fabric link redundancy wiring. **21 files changed, ~1293 insertions.** 15 new tests.

### ISSU — In-Service Software Upgrade (Missing → Implemented)
- **`ForceSecondary()`** on Manager — sets weight=0 for all RGs, forces secondary state, drains traffic to peer
  - Requires peer alive (returns error if no peer)
  - Skips disabled RGs, increments failover count
- **CLI:** `request system software in-service-upgrade` — confirmation prompt ("WARNING: This will force this node to secondary"), both local + remote CLI
- **gRPC:** SystemAction `"in-service-upgrade"` → ForceSecondary() → response with instructions to replace binary + restart
- **cmdtree:** `request > system > software > in-service-upgrade` node
- **Tests:** `TestForceSecondary`, `TestForceSecondary_NoPeer`, `TestForceSecondary_SkipsDisabled`

### NAT State Synchronization (Missing → Implemented)
- **Session install via sync:** `decodeSessionV4Payload()` / `decodeSessionV6Payload()` decode wire-format sessions
  - Full field-by-field decode matching `encodeSessionV4Payload` layout
  - Calls `dp.SetSessionV4(key, val)` / `dp.SetSessionV6(key, val)` to write directly to BPF maps
- **DataPlane interface:** `SetSessionV4(key, val)` / `SetSessionV6(key, val)` added to interface
  - eBPF maps: `sm.Update(key, val, ebpf.UpdateAny)` on sessions/sessions_v6 maps
  - DPDK stubs: no-op (TODO: rte_hash_add_key_data)
- **`SetDataPlane(dp)`** method on SessionSync — daemon wires dp after dataplane load
- **Stats:** `SessionsInstalled` counter tracks successful BPF map writes
- **Config:** `NATStateSync bool` on ClusterConfig; AST `nat-state-synchronization` leaf
- **Tests:** `TestDecodeSessionV4RoundTrip`, `TestDecodeSessionV6RoundTrip`, `TestDecodeSessionV4Short`, `TestDecodeSessionV6Short`, `TestSetDataPlane`, `TestHandleMessageDeleteV4`

### IPsec SA Synchronization (Missing → Implemented)
- **New sync message:** `syncMsgIPsecSA = 9` — newline-separated SA names (child SA names; the IKE connection name only for an IKE SA with no child yet — #9511 corrected this line)
  - `encodeIPsecSAPayload()` / `decodeIPsecSAPayload()` — strings.Join/Split with newline separator
  - `QueueIPsecSA(connectionNames)` — sends on TCP sync connection
  - `PeerIPsecSAs()` — returns latest received names (mutex-protected copy)
  - `OnIPsecSAReceived` callback — set by daemon for failover re-initiation
- **IPsec manager:** `ActiveConnectionNames()` queries swanctl --list-sas for active SA names (the child SA name, or the IKE connection name for an IKE SA with no child yet — #9511 corrected this line)
  - `InitiateConnection(name)` calls swanctl --initiate --child <name>
- **Daemon wiring:**
  - `syncIPsecSAPeriodic(ctx)` — 30s ticker on primary, sends active SA names to secondary
  - `reinitiateIPsecSAs()` — on failover to primary, re-initiates all peer's synced connections
  - `watchClusterEvents()` triggers re-initiation on primary transition when `IPsecSASync` enabled
- **Config:** `IPsecSASync bool` on ClusterConfig; AST `ipsec-session-synchronization` leaf
- **Stats:** `IPsecSASent`/`IPsecSAReceived` counters, shown in FormatStats()
- **Tests:** `TestIPsecSAPayloadRoundTrip`, `TestIPsecSAPayloadEmpty`, `TestPeerIPsecSAs`

### DHCP-server Lease Synchronization (#2239, PATH C — re-instantiates the IPsec-SA-sync pattern)
- **Wire:** `syncMsgDHCPLeaseV4=25`/`syncMsgDHCPLeaseV6=26`; `encode/decodeDHCPLeasePayload` (count + length-gated per-lease records, #2170 trailing-field discipline). Additive + config-gated → NO `CurrentHAProtocolVersion` bump (legacy peers ignore via default case).
- **Clock invariant:** leases carry REMAINING LIFETIME, re-anchored to the local clock at seed (`expire = now + remaining`) — immune to peer wall-clock skew (the channel syncs only a monotonic offset).
- **SessionSync:** `QueueDHCPLeases(family, leases)` send; `peerDHCPLeases{4,6}` hold + `PeerDHCPLeases{4,6}()`; `RecordDHCPLeasesSeeded`; receive cases store the full set.
- **Kea side (`pkg/dhcpserver/lease_sync.go`):** control-socket `lease{4,6}-get-all` read (memfile fallback) + `lease{4,6}-add`/`-update` seed + `PreSeedMemfile{4,6}` (pre-Kea-start, closes dup-alloc window). `SetLeaseSyncEnabled` emits the control-socket + `libdhcp_lease_cmds.so` hook only when the knob is set.
- **Daemon wiring:** `syncDHCPLeasesPeriodic` (30s heartbeat + 2s on-grant change-detect, RG-MASTER gated), `seedDHCPLeasesFromPeer` (async takeover seed) + `preSeedDHCPLeaseMemfile`; standby Kea stays STOPPED (`clearRethServicesForRG` unchanged). Gate `dhcpLeaseSyncGateOpen` mirrors `ddnsWriterGateOpen`.
- **Config:** `DHCPLeaseSync bool` on ClusterConfig; AST `dhcp-lease-synchronization` leaf.
- **Stats:** `DHCPLeases{Sent,Received,Seeded}`, shown in `show chassis cluster statistics`.
- **Open-question resolutions:** Q1 incremental on-grant push (2s change-detect); Q3 pre-seed memfile before start; Q4 explicit knob; Q5 v6 DUID/IAID/PD; Q7 full re-push on reconnect (`OnPeerConnected` nudge).

### Active/Active Mode (Partial → Implemented)
- Per-RG primary election already worked (electRG per redundancy group)
- Validated with `TestActiveActive_DifferentPrimariesPerRG`:
  - RG 0: node0 priority=200, node1 priority=100 → node0 primary for RG0
  - RG 1: node0 priority=100, node1 priority=200 → node1 primary for RG1
  - Peer heartbeat with per-RG state confirms complementary configuration
  - `PeerGroupStates()` getter added to Manager

### RETH Runtime (Partial → Implemented)
- **IPv6 support:** `RethIPs()` now uses `netlink.FAMILY_ALL` (was `FAMILY_V4`)
  - Filters out link-local IPv6 (fe80::) — not useful for GARP/NA
- **Gratuitous IPv6 NA:** `SendGratuitousIPv6(iface, ip, count)` in garp.go
  - Raw Ethernet + IPv6 + ICMPv6 Neighbor Advertisement packet (86 bytes)
  - Unsolicited NA with Override flag (RFC 4861 §7.2.6), Target Link-Layer Address option
  - Sent to ff02::1 (all-nodes multicast), MAC 33:33:00:00:00:01
  - `buildUnsolicitedNA()` builds full raw packet
  - `icmpv6Checksum()` computes RFC 4443 §2.3 checksum with pseudo-header
  - AF_PACKET raw socket with ETH_P_IPV6, SockaddrLinklayer
- **triggerGARP() dual-stack:** Dispatches IPv4 → SendGratuitousARP, IPv6 → SendGratuitousIPv6
- **Tests:** `TestBuildUnsolicitedNA` (packet structure), `TestICMPv6Checksum` (known checksum)

### Fabric Link Redundancy (Parse-Only → Implemented)
- Fabric link now carries all sync traffic: session sync, config sync, IPsec SA sync
- `FabricInterface` + `FabricPeerAddress` config drives TCP session sync connection
- Session, config, and IPsec SA messages all flow over the fabric link

### Config & Compiler Changes
- **types.go:** `NATStateSync bool`, `IPsecSASync bool` on ClusterConfig
- **ast.go:** `nat-state-synchronization`, `ipsec-session-synchronization` leaf nodes
- **compiler.go:** `compileChassis()` handles both new config options via `FindChild()`
- **Tests:** `TestChassisClusterSyncOptions` (flat set), `TestChassisClusterSyncOptionsHierarchical`

### Files Modified (21 files, 1293 insertions)
| File | Lines | Description |
|------|-------|-------------|
| `pkg/cluster/sync.go` | +320 | Session decode/install, IPsec SA sync, SetDataPlane, stats |
| `pkg/cluster/sync_test.go` | +227 | 9 new tests (decode, IPsec, DataPlane, delete) |
| `pkg/cluster/cluster.go` | +47 | ForceSecondary, dual-stack GARP, PeerGroupStates |
| `pkg/cluster/cluster_test.go` | +141 | 4 new tests (active/active, ForceSecondary) |
| `pkg/cluster/garp.go` | +132 | SendGratuitousIPv6, buildUnsolicitedNA, icmpv6Checksum |
| `pkg/cluster/garp_test.go` | +133 | IPv6 NA packet/checksum tests |
| `pkg/cluster/reth.go` | +8 | RethIPs dual-stack (FAMILY_ALL, skip link-local) |
| `pkg/daemon/daemon.go` | +71 | SetDataPlane wiring, IPsec SA periodic sync, failover re-initiation |
| `pkg/config/types.go` | +14 | NATStateSync, IPsecSASync fields |
| `pkg/config/ast.go` | +3 | New schema nodes |
| `pkg/config/compiler.go` | +6 | FindChild for sync options |
| `pkg/config/parser_test.go` | +69 | 2 parser tests |
| `pkg/ipsec/ipsec.go` | +24 | ActiveConnectionNames, InitiateConnection |
| `pkg/dataplane/dataplane.go` | +2 | SetSessionV4/V6 interface methods |
| `pkg/dataplane/maps.go` | +18 | SetSessionV4/V6 BPF map writes |
| `pkg/dataplane/dpdk/dpdk_cgo.go` | +10 | DPDK stubs |
| `pkg/dataplane/dpdk/dpdk_stub.go` | +6 | DPDK stubs |
| `pkg/grpcapi/server.go` | +14 | ISSU SystemAction handler |
| `pkg/cli/cli.go` | +40 | ISSU local CLI handler with confirmation |
| `cmd/cli/main.go` | +22 | ISSU remote CLI handler |
| `pkg/cmdtree/tree.go` | +3 | ISSU command tree entry |

## Sprint INC-SYNC: Incremental Session Sync
- **Problem:** Only `BulkSync()` was called on initial TCP connect; sessions created after were never replicated, expired sessions never removed from secondary
- **Three sync mechanisms (additive):**
  1. **Periodic sweep** (1s) — `StartSyncSweep()` iterates sessions, syncs those with `Created >= lastSweepTime`; only runs when primary + connected
  2. **GC delete callbacks** — `OnDeleteV4`/`OnDeleteV6` fields on GC struct; called from `sweep()` for forward entries (even indices); daemon wires to `QueueDeleteV4/V6`
  3. **Ring buffer callback** — `EventReader.AddCallback` for `SESSION_OPEN` events; extracts 5-tuple from raw data, looks up full session via `GetSessionV4/V6`, queues immediately
- **New methods:** `GetSessionV4`/`GetSessionV6` on DataPlane interface (BPF map Lookup)
- **Helper:** `SessionSync.IsConnected()` to avoid `atomic.Bool` value-copy issues
- **Tests:** sync_test.go (5 sweep tests), gc_test.go (4 callback tests)

### Files Changed
| File | Lines | Description |
|------|-------|-------------|
| `pkg/cluster/sync.go` | +75 | `StartSyncSweep`, `syncSweep`, `IsPrimaryFn`, `IsConnected`, `monotonicSeconds` |
| `pkg/conntrack/gc.go` | +10 | `OnDeleteV4`/`OnDeleteV6` callback fields + call sites |
| `pkg/dataplane/dataplane.go` | +2 | `GetSessionV4`/`GetSessionV6` interface methods |
| `pkg/dataplane/maps.go` | +26 | eBPF Lookup implementations |
| `pkg/dataplane/dpdk/dpdk_stub.go` | +7 | DPDK stubs |
| `pkg/dataplane/dpdk/dpdk_cgo.go` | +7 | DPDK CGo stubs |
| `pkg/daemon/daemon.go` | +55 | Wire all 3 sync mechanisms |
| `pkg/cluster/sync_test.go` | +100 | Sweep tests (new sessions, skip reverse, skip not-primary, skip disconnected, v6) |
| `pkg/conntrack/gc_test.go` | +170 | GC callback tests (v4, v6, nil callback, Run integration) |

## Sprint SEC-LOG: Security Logging Enhancements
- **Goal:** Close all security logging feature gaps from feature-gaps.md #12
- **6 features implemented:** Structured syslog, transport selection, per-policy NAT fields, event mode, session aggregation, binary log (N/A)

### Feature 1: NAT Fields in BPF Events + Structured Syslog Format
- Extended `struct event` in BPF with 6 new fields: `nat_src_ip[16]`, `nat_dst_ip[16]`, `nat_src_port`, `nat_dst_port`, `created`
- New BPF helpers: `emit_event_nat4()` and `emit_event_nat6()` — emit events with full NAT translation info from session values
- Updated `xdp_conntrack.c` and `xdp_zone.c` to use NAT-aware emit functions for SESSION_CLOSE events
- Go `Event` struct extended with matching fields; `ringbuf.go` parses NAT fields from offset 72..112
- `EventRecord` extended: `NATSrcAddr`, `NATDstAddr`, `InZoneName`, `OutZoneName`, `ElapsedTime`
- Zone name resolution: `EventReader.SetZoneNames()` maps zone IDs → names (sorted order matches compiler)
- Structured syslog format: `formatStructuredMsg()` emits Junos-compatible `RT_FLOW_SESSION_CREATE`, `RT_FLOW_SESSION_CLOSE`, `RT_FLOW_SESSION_DENY` with all NAT fields, zone names, elapsed time
- Per-stream format override via `client.Format = "structured"` with lazy message caching

### Feature 2: TCP and TLS Transport for Syslog
- `NewSyslogClientTransport(host, port, sourceAddr, protocol, tlsCfg)` — supports "udp", "tcp", "tls"
- TCP/TLS: RFC 6587 octet-counting framing (`"<length> <message>"`)
- Auto-reconnect on write failure (one retry attempt for stream protocols)
- Thread-safe: `sync.Mutex` protects connection state
- `SyslogTransport` struct in config types: `Protocol` + `TLSProfile`
- Compiler parses `transport { protocol tcp; tls-profile ...; }`
- Daemon wires `stream.Transport.Protocol` into `NewSyslogClientTransport`
- Tests: TCP send/receive, TCP reconnect after server restart, TLS with self-signed cert

### Feature 3: Log Event Mode + Session Aggregation
- **Event mode:** `security log mode event` routes logs to `/var/log/xpf/security.log` via `LocalLogWriter`
  - `LocalLogWriter`: append-mode file with rotation (10MB default, 5 rotated files)
  - Severity filtering + category matching (same as SyslogClient)
  - `EventReader.SetLocalWriters()` / `ReplaceLocalWriters()` for goroutine-safe swap
  - Daemon detects `mode == "event"` → clears remote syslog clients, creates local writer
- **Session aggregation:** `security log report` enables periodic top-N reports
  - `SessionAggregator`: tracks per-source and per-dest IP session count + bytes
  - `HandleEvent()` callback wired to `EventReader.AddCallback` — only counts SESSION_CLOSE
  - `Run(ctx)` with configurable flush interval (default 5min)
  - `Flush()` returns top-N entries sorted by bytes, resets counters
  - `flushAndLog()` emits `RT_FLOW_SESSION_AGGREGATE top-source=...` / `top-destination=...`
  - Log output forwarded via `EventReader.ForwardLogMsg()` to all syslog clients + local writers
  - Daemon lifecycle: `applyAggregator()` starts/stops goroutine on config change
  - **Bounded accounting — Space-Saving top-K (#3099):** each direction is a
    Space-Saving (Metwally, Agrawal & El Abbadi 2005) counter set of K =
    `defaultMaxAggKeys` (10000) counters, `streamSummary` in
    `pkg/logging/aggregator.go`. Memory is bounded by K exactly as the prior
    cardinality cap (#2936) bounded it, but the reported top-K is now
    arrival-order independent: a heavy hitter whose first session arrives after
    the set fills evicts the current minimum counter instead of being silently
    dropped. Implementation: a `map[key]*ssCounter` plus a min-heap keyed on
    bytes (heap root = eviction victim), so `Add` is O(log K) on the
    SESSION_CLOSE path. Each counter carries (`bytes`, `bytesErr`) with the
    standard guarantee `bytes - bytesErr <= true_bytes <= bytes`; the session
    count uses the same bookkeeping. Bytes remain the ranking/sort key. The
    overflow (eviction) count per window is still surfaced as the
    `RT_FLOW_SESSION_AGGREGATE dropped-keys ...` warning line — the same
    high-cardinality incident indicator operators relied on; a non-zero value
    now means the top-N is approximate (heavy hitters retained) rather than
    that keys were discarded.

### DPDK Parity
- `dpdk_worker/shared_mem.h`: `struct event` extended with NAT fields (matches BPF layout)
- `dpdk_worker/events.h`: `emit_event()` and `emit_event_with_stats()` zero NAT fields
- `pkg/dataplane/dpdk/dpdk_cgo.go`: CGo bridge copies NAT fields from event ring

### Files Changed
| File | Lines | Description |
|------|-------|-------------|
| `bpf/headers/xpf_common.h` | +6 | NAT fields in `struct event` |
| `bpf/headers/xpf_helpers.h` | +97 | `emit_event_nat4()`, `emit_event_nat6()` |
| `bpf/xdp/xdp_conntrack.c` | ~10 | Use `emit_event_nat6` for SESSION_CLOSE |
| `bpf/xdp/xdp_zone.c` | ~20 | Use `emit_event_nat4/nat6` for SESSION_CLOSE |
| `pkg/config/types.go` | +10 | `SyslogTransport`, `LogConfig.Report` |
| `pkg/config/compiler.go` | +12 | Parse `transport`, `report` |
| `pkg/dataplane/types.go` | +5 | NAT fields in Go `Event` struct |
| `pkg/logging/ringbuf.go` | +218 | NAT parsing, zone names, structured format, local writers, ForwardLogMsg |
| `pkg/logging/syslog.go` | +163 | TCP/TLS transport, reconnect, RFC 6587 framing |
| `pkg/logging/syslog_test.go` | +285 | TCP, TCP reconnect, TLS tests |
| `pkg/logging/eventbuf.go` | +5 | NAT/zone/elapsed fields in EventRecord |
| `pkg/logging/aggregator.go` | +167 | SessionAggregator (new file) |
| `pkg/logging/aggregator_test.go` | new | Aggregator unit tests |
| `pkg/logging/locallog.go` | +148 | LocalLogWriter with rotation (new file) |
| `pkg/logging/locallog_test.go` | new | Local log writer tests |
| `pkg/daemon/daemon.go` | +91 | Zone names, transport wiring, event mode, aggregator lifecycle |
| `pkg/cli/cli.go` | +21 | Zone name map + per-stream format in local CLI |
| `dpdk_worker/shared_mem.h` | +6 | NAT fields in DPDK event struct |
| `dpdk_worker/events.h` | +14 | Zero NAT fields in DPDK emit functions |
| `pkg/dataplane/dpdk/dpdk_cgo.go` | +5 | CGo bridge NAT field copy |

## Sprint APP-FIX: Application Matching & Insert Command (`a0d4d14`–`8818332`)

### Application Matching Fix (`a0d4d14`)
- **Bug 1:** Application terms with no protocol specified (e.g., plex term 26619) silently skipped — compiler now installs both TCP and UDP BPF map entries
- **Bug 2:** Per-app inactivity timeout lost on TCP state changes — added `app_timeout` field to session structs (replaces padding), persisted across state transitions for non-closing states
- Both eBPF and DPDK paths updated (4 conntrack locations each + session creation)

### Insert Command (`8818332`)
- Junos-style `insert <path> before|after <ref>` for reordering ordered config lists
- Supports policies, terms, rules, rule-sets — any sibling in AST children
- Implementation: AST `InsertBefore`/`InsertAfter` → ConfigStore `Insert()` → CLI/gRPC
- Fixed `findNodeWithParent` to prefer full-key matches over partial matches (multi-key nodes like `policy first`, `policy second`)
- Remote CLI sends insert via gRPC `Set()` with server-side path construction
- Tests: policy reordering + firewall filter term reordering + compile verification

## Sprint HA-CONFIG: Single-Config HA Cluster with `${node}` Variable Expansion

### Variable Expansion in apply-groups
- `ExpandGroupsWithVars(vars map[string]string)` — resolves `${varname}` in apply-groups references before group lookup
- `resolveVars()` helper does `strings.ReplaceAll(s, "${"+k+"}", v)` for each var
- Internal `expandGroups()` and `expandGroupsInNodes()` signatures updated to pass `vars` through
- `ExpandGroups()` and `ExpandGroupsTagged()` remain backward-compatible (nil vars)

### CompileConfigForNode
- `CompileConfigForNode(tree, nodeID)` — clones tree, sets `{"node": "node0"}` vars, expands, compiles
- Extracted `compileExpanded()` helper shared by `CompileConfig` and `CompileConfigForNode`

### Configstore nodeID Threading
- `Store.nodeID` field (default -1 = standalone)
- `Store.SetNodeID(id)` setter, `Store.compileTree(tree)` dispatches to `CompileConfigForNode` or `CompileConfig`
- All 6 `config.CompileConfig()` callsites in store replaced with `s.compileTree()`

### Daemon --node Flag
- `--node N` CLI flag on xpfd (default -1)
- `Options.NodeID` → `store.SetNodeID()` in `New()`
- `bootstrapFromFile()` simplified: removed redundant pre-validation compile, relies on store.Commit()

### Single HA Config File
- `docs/ha-cluster.conf` — unified config with `groups { node0 { ... } node1 { ... } }` and `apply-groups "${node}"`
- Deleted `docs/ha-cluster-fw0.conf` and `docs/ha-cluster-fw1.conf`
- vSRX interface naming: fxp0 (mgmt), fxp1 (heartbeat), fab0 (fabric), ge-X/Y/Z (data), rethN (redundant)
- Updated `docs/ha-cluster-test-plan.md` with single-config model and new interface names

## Sprint VRRP-RETH: VRRP-Backed RETH Interfaces

### Overview
Replaced manual GARP-based RETH failover with keepalived VRRP for RETH VIP management. Keepalived now owns all RETH virtual IPs — the cluster state machine drives VRRP priority changes to trigger failover. This eliminates custom GARP logic for RETH interfaces and leverages keepalived's built-in GARP/NA, preemption, and health checking.

### Architecture
- **keepalived manages RETH VIPs:** Each RETH interface with `RedundancyGroup > 0` gets a VRRP instance
- **VRID scheme:** `100 + redundancy_group_id` (avoids collision with user-configured VRRP instances)
- **Priority mapping:** Primary node gets priority 200, secondary gets 100 (via `LocalPriorities()`)
- **Preempt enabled:** Higher-priority node reclaims VIP automatically
- **Bonds stay UP on both nodes:** Unlike old RETH model where secondary deactivated bond members, VRRP requires the underlying interface to be UP on both nodes for keepalived to send advertisements

### Key Functions
- **`vrrp.CollectRethInstances(cfg, localPriority)`** — scans interfaces for `RedundancyGroup > 0`, collects unit addresses as VIPs, returns `[]*Instance` with VRID=100+rgID
- **`vrrp.UpdatePriority(cfg, localPriority)`** — merges user VRRP + RETH VRRP instances, calls `Apply()` to regenerate keepalived.conf and reload
- **`cluster.Manager.LocalPriorities()`** — returns `map[int]int` of rgID→VRRP priority (200 for primary, 100 for secondary)
- **`UpdatePriority()` called on cluster state changes** — `watchClusterEvents()` in daemon triggers keepalived reload when RG state transitions

### networkd Changes
- **Link-local base address for RETH:** When `isVRRPReth` (RedundancyGroup > 0 && cluster node), compiler replaces VIP addresses with `169.254.RG.NODE+1/32` — keepalived needs an IPv4 for VRRP adverts but conflicts when both networkd and keepalived manage the same VIP
- **BondMaster for RETH members:** `RedundantParent` → `BondMaster` in InterfaceConfig → `Bond=rethX` in .network file
- **Skip bond members from reconfigure:** `networkctl reconfigure` skips interfaces with `BondMaster != ""` to prevent ejection from netlink-managed bonds

### Idempotent RETH Bonds (`7151a5b`)
- **No more destroy/recreate:** `ApplyRethInterfaces` checks `MasterIndex` before re-enslaving; only removes stale bonds not in config
- **Debounced VRRP updates:** `watchClusterEvents()` uses 2s `time.AfterFunc` to coalesce rapid cluster events
- **Reload over restart:** `vrrp.Apply()` sends SIGHUP when keepalived is already running; only starts if not running

### SNAT Changes
- **Config-based address lookup for RETH:** When compiling SNAT interface rules, if the egress interface has `RedundancyGroup > 0`, addresses are read from config (`ifCfg.Units[].Addresses`) instead of live interface query (`getInterfaceIP`)
- **Rationale:** VIPs may not be present on the local interface (secondary node), but SNAT rules still need the correct addresses for compilation

### Design Decisions
- **Why keepalived over manual GARP:** keepalived provides standard VRRP protocol compliance, built-in GARP/NA on failover, health checking, and proven reliability — eliminates custom AF_PACKET GARP code for RETH
- **Why bonds stay UP:** VRRP advertisements must flow on the interface; taking bonds down would prevent keepalived from functioning on secondary
- **VRID offset 100:** Provides 100 slots for user VRRP (1-99) and 100+ for RETH, avoiding collisions
- **Why link-local 169.254.x.x base:** Keepalived removes VIPs on FAULT/BACKUP state transitions; using the same address as both static networkd and VRRP VIP caused keepalived to delete the networkd-assigned address, then refuse to start ("no IPv4 address")

## Sprint RETH-BONDLESS: Remove Bond Devices
Remove RETH bond devices — VRRP runs directly on physical member interfaces.

### Key Changes
- **`Config.RethToPhysical()`** — returns `map[rethName]physicalMember` from `RedundantParent` fields
- **`Config.ResolveReth(ref)`** — resolves "reth0" or "reth0.50" to physical member equivalent
- **`vrrp.CollectRethInstances()`** — uses `RethToPhysical()` to resolve keepalived interface to physical member
- **`compiler.go` `resolveInterfaceRef()`** — resolves reth refs in security zone/NAT/DNAT config
- **`networkd`** — no more `Bond=` in .network files; RETH members are regular interfaces
- **`routing.ApplyRethInterfaces()`** — no-op (bonds no longer created)
- **`routing.ClearRethInterfaces()`** — kept for cleaning up legacy bonds from previous deploys
- **`cluster/reth.go`** — removed `activateReth()`/`deactivateReth()`; `HandleStateChange()` brings up physical members directly; `RethIPs()` queries first physical member; `FormatStatus()` shows "Physical" column
- **`cluster/cluster.go`** — removed `RethIPMapping` type, `rethIPs` field, `RegisterRethIPs()`; `triggerGARP()` is no-op (keepalived handles GARP)
- **Daemon** — replaced bond creation with `ClearRethInterfaces()` cleanup call

### Design Rationale
- **Bonds were unnecessary complexity:** VRRP already handles failover; bonds added an extra layer that provided no benefit
- **Keepalived runs on physical interfaces:** No bond device needed — keepalived sends VRRP advertisements directly on the physical member
- **Legacy cleanup:** `ClearRethInterfaces()` removes any bond devices from previous binary versions

## Sprint NPTv6 (`875eeaa`): NPTv6 (RFC 6296) Stateless IPv6 Prefix Translation — COMPLETE

### Overview
NPTv6 (Network Prefix Translation for IPv6) per RFC 6296. Provides stateless, checksum-neutral 1:1 IPv6 prefix rewriting. Translates between internal (ULA) and external (GUA) /48 prefixes without modifying transport-layer checksums, since the adjustment is pre-computed to be checksum-neutral.

### Algorithm (RFC 6296 §3)
1. **Precompute adjustment:** `adj = ~sum(external_prefix) +' sum(internal_prefix)` (one's complement arithmetic, native byte order)
2. **Apply to word[3]:** On inbound, rewrite `dst_addr.s6_addr16[3]` with adjustment; on outbound, rewrite `src_addr.s6_addr16[3]` with inverse adjustment
3. **Checksum-neutral:** Because the adjustment is applied to a single 16-bit word, the IPv6 pseudo-header checksum remains valid — no TCP/UDP/ICMPv6 checksum update needed

### Pipeline Placement
- **Inbound (xdp_zone.c):** After zone lookup, before conntrack — rewrites destination prefix (external→internal)
- **Outbound (xdp_policy.c):** After policy, before dynamic SNAT — rewrites source prefix (internal→external)

### Config Syntax (Junos-compatible)
```
security nat static {
    rule-set nptv6-rs {
        from zone untrust;
        rule nptv6-rule {
            match {
                destination-address 2001:db8:ext::/48;
            }
            then {
                static-nat {
                    nptv6-prefix fd00:internal::/48;
                }
            }
        }
    }
}
```

### BPF Implementation
- **Map:** `nptv6_rules` HASH map (max 128 entries, NO_PREALLOC)
- **Key (`struct nptv6_key`, 8 bytes):** `prefix[6]` (first 48 bits of IPv6) + `direction` (0=INBOUND, 1=OUTBOUND) + pad
- **Value (`struct nptv6_value`, 8 bytes):** `xlat_prefix[6]` (replacement prefix) + `adjustment` (u16, ones'-complement, native byte order)
- **Session flag:** `SESS_FLAG_NPTV6 (1 << 8)` — marks sessions with NPTv6 translation
- **Direction constants:** `NPTV6_INBOUND=0` (external→internal, rewrite dst), `NPTV6_OUTBOUND=1` (internal→external, rewrite src)
- **Helper (`xpf_nat.h`):** `nptv6_translate(addr, nv, direction)` — `__always_inline`
  - Step 1: Rewrite prefix words 0-2 from `xlat_prefix[6]`
  - Step 2: Apply adjustment to word[3] — outbound adds `adj`, inbound adds `~adj`
  - Ones'-complement add with carry: `sum = (sum & 0xFFFF) + (sum >> 16)` (twice)
  - RFC 6296 §3.1: 0xFFFF (negative zero) → 0x0000 (positive zero)
  - No L4 checksum update needed — translation is checksum-neutral

### Config Parsing (pkg/config/)
- **`StaticNATRule.IsNPTv6 bool`** — distinguishes NPTv6 from regular static NAT
- **Compiler:** Handles both hierarchical and flat set syntax:
  - Hierarchical: `static-nat { nptv6-prefix { PREFIX; } }` via `FindChild("nptv6-prefix")`
  - Flat set: `then static-nat nptv6-prefix PREFIX` via `t.Keys[1] == "nptv6-prefix"`
- **Rule.Then** stores the internal prefix string (same field as regular static NAT prefix)

### Go Types
- `NPTv6Key`/`NPTv6Value` in `pkg/dataplane/types.go` — Go mirrors of BPF structs
- `StaticNATRule.IsNPTv6 bool` in `pkg/config/types.go` — reuses existing static NAT structs
- `nptv6Adjustment()` + `compileNPTv6()` in `pkg/dataplane/compiler.go`
- CLI: `show security nat nptv6` in local CLI, remote CLI, gRPC, REST API

### Files Modified
| File | Description |
|------|-------------|
| `bpf/headers/xpf_common.h` | `SESS_FLAG_NPTV6 (1<<8)` |
| `bpf/headers/xpf_maps.h` | `nptv6_rules` map, key/value structs |
| `bpf/headers/xpf_nat.h` | `nptv6_translate()` helper |
| `bpf/xdp/xdp_zone.c` | Inbound NPTv6 lookup + translate |
| `bpf/xdp/xdp_policy.c` | Outbound NPTv6 lookup + translate |
| `pkg/config/types.go` | `StaticNATRule.IsNPTv6` field |
| `pkg/config/compiler.go` | `nptv6-prefix` keyword parsing |
| `pkg/dataplane/compiler.go` | `nptv6Adjustment()`, `compileNPTv6()` |
| `pkg/dataplane/maps.go` | `SetNPTv6Rule()`, `DeleteStaleNPTv6()` |
| `pkg/dataplane/types.go` | `NPTv6Key`, `NPTv6Value` Go structs |
| `pkg/dataplane/loader_ebpf.go` | `nptv6_rules` map registration |
| `pkg/cli/cli.go` | `showNPTv6()` local CLI display |
| `cmd/cli/main.go` | `nptv6` remote CLI dispatch |
| `pkg/grpcapi/server.go` | `nat-nptv6` case |
| `pkg/api/handlers.go` | `nat-nptv6` REST handler |
| `pkg/cmdtree/tree.go` | `nptv6` command node |
| `pkg/dataplane/nptv6_test.go` | Adjustment + checksum neutrality tests |
| `pkg/config/parser_test.go` | Hierarchical + flat set parsing tests |

### NAT64 ICMP Error Translation (`91bdd38`)
- Full IPv4 ICMP error → ICMPv6 error translation (Time Exceeded, Dest Unreach, Param Problem)
- `nat64_icmp_error_4to6()`: bpf_xdp_adjust_head(-40) grows packet, reconstructs IPv6+ICMPv6+embedded IPv6 headers
- NPTv6 INBOUND reverse translation in error path (external→internal prefix)
- Fixed ICMP echo ID stored in nat64_state (use meta->dst_port, not meta->src_port)
- Conntrack embedded handler: META_FLAG_NAT64_ICMP_ERR flag, tail-call to xdp_nat64
- All NAT64 traceroute variants work: mtr (ICMP), mtr -u (UDP), traceroute6

## Sprint VRRP-NATIVE: Native Go VRRPv3 Daemon

Replaced external keepalived daemon with a native Go VRRPv3 implementation (RFC 5798). The new implementation runs entirely within the xpfd process, eliminating the external dependency and enabling real-time event-driven state change notifications.

### What Changed
- **Removed:** keepalived config generation (`generateConfig()`), SIGUSR1 state polling (`dumpAndParse()`), systemd lifecycle management (`systemctl start/stop/reload keepalived`), keepalived data file parsing (`parseDataFile()`), `hasVirtualAddrs()` fallback, `Status()` keepalived status reader
- **Added:** Native VRRPv3 packet codec, RFC 5798 state machine, centralized VRRP manager with raw socket I/O

### New Files
- **`pkg/vrrp/packet.go`** — VRRPv3 packet codec (Marshal/Parse). IPv4 ones-complement checksum and IPv6 pseudo-header checksum. Validates version, type, address count, and checksum on parse.
- **`pkg/vrrp/instance.go`** — Per-VRRP-group state machine goroutine. States: Initialize→Backup→Master. RFC 5798 timers (Master_Down_Interval = 3*Advert + Skew). Handles preempt/non-preempt, priority-0 resignation, VIP add/remove via netlink, GARP/NA on Master transition via `cluster.SendGratuitousARP`/`SendGratuitousIPv6`. Emits `VRRPEvent` on state changes.
- **`pkg/vrrp/manager.go`** — Manages all VRRP instances and shared raw socket (`ip4:112`). Multicast group join/leave (224.0.0.18) per interface. Receiver goroutine dispatches packets by VRID. `UpdateInstances()` diffs desired vs current, adds/removes/restarts instances. `States()` returns instant state map. `Status()` returns formatted multi-line status.

### Refactored File
- **`pkg/vrrp/vrrp.go`** — Stripped to config collection only: `CollectInstances()`, `CollectRethInstances()`. Removed `Apply()`, `UpdatePriority()`, `generateConfig()`, `RuntimeStates()`, `dumpAndParse()`, `parseDataFile()`, `hasVirtualAddrs()`, `Status()`. Package doc changed from "manages keepalived configuration" to "manages native VRRPv3 instances".

### Integration Points
- **Daemon:** `vrrp.NewManager()` + `Start(ctx)`/`Stop()` lifecycle; `watchClusterEvents()` calls `manager.UpdateInstances()` on cluster state changes (replaces `vrrp.UpdatePriority()`)
- **CLI/gRPC/REST:** `manager.States()` for `show vrrp` output; `manager.Status()` for detailed status (replaces `vrrp.RuntimeStates()` + keepalived data file parsing)

### Architecture
```
Manager
  └── per-instance goroutines (each with own raw socket + SO_BINDTODEVICE)
       ├── openSocket() — ip4:112, SO_BINDTODEVICE, join 224.0.0.18
       ├── receiver() — reads multicast, filters self-sent by localIP, dispatches by VRID
       ├── Backup: wait for master-down timer
       ├── Master: send periodic adverts, manage VIPs
       └── Events → daemon (GARP, cluster coordination)
```

### Per-Interface Socket Fix (`70b107c`)
- **Bug:** Shared `ip4:112` socket on `0.0.0.0` didn't reliably receive VRRP multicast on VLAN sub-interfaces (e.g. `ge-0-0-1.50`). Both cluster nodes became MASTER for WAN VLAN VRID.
- **Root cause:** Linux raw socket multicast delivery on VLAN sub-interfaces requires SO_BINDTODEVICE to the specific sub-interface.
- **Fix:** Each vrrpInstance now creates its own raw socket with `SO_BINDTODEVICE` and `JoinGroup` per interface. Removed shared socket from Manager.
- **Self-sent filtering:** Added `localIP` comparison in receiver to skip self-sent packets (RFC 5798 §6.4.2/6.4.3).
- **gRPC fix:** `GetVRRPStatus` now calls both `CollectInstances()` AND `CollectRethInstances()` for cluster RETH VRRP instances (was missing → "No VRRP groups configured").
- **Cleanup:** Stopped/disabled keepalived on xpf-fw0/fw1, removed keepalived.conf, updated code comments.

### Benefits
- **No external dependency:** No keepalived package needed on the firewall
- **Real-time events:** `VRRPEvent` channel delivers instant state change notifications (vs polling keepalived data file)
- **Instant priority updates:** `UpdateInstances()` diffs and restarts only changed instances (vs regenerating keepalived.conf + SIGHUP)
- **Simplified lifecycle:** No systemd service management, PID file reading, or SIGUSR1 signaling
- **TTL=255 validation:** RFC 5798 §5.1.1.3 compliance in receiver
- **Priority-0 resignation:** On graceful shutdown, Master sends priority-0 advert for immediate failover
- **Unified process:** VRRP state machine runs in xpfd — no inter-process coordination needed
- **VLAN sub-interface support:** Per-interface SO_BINDTODEVICE ensures multicast reception on all interface types

## Sprint SYNC-FIX: Session Sync Receiver Reconstruction

### Problem
Session sync had three critical bugs that prevented reliable stateful failover:
1. Forward-only sweep entries had no reverse conntrack entry on the takeover node
2. SNAT sessions lacked dnat_table entries for return traffic pre-routing
3. Monotonic clock skew caused premature GC expiry of synced sessions (in progress)
4. Cold ARP cache on takeover node caused NO_NEIGH drops (in progress)

### Fix 1: Reverse Entry Creation (FIXED)
- `handleMessage()` for SessionV4/V6 now creates reverse entries from forward entries
- Copies forward value, sets `IsReverse=1`, sets `ReverseKey = original key`
- Both v4 and v6 paths updated

### Fix 2: SNAT dnat_table Entry Creation (FIXED)
- For forward sessions with `SessFlagSNAT` (not `SessFlagStaticNAT`):
  - Creates `DNATKey{Protocol, DstIP=NATSrcIP, DstPort=NATSrcPort}`
  - Creates `DNATValue{NewDstIP=SrcIP, NewDstPort=SrcPort}`
- Delete messages now also clean up reverse entries and dnat_table entries (lookup before delete)

### Fix 3: Monotonic Clock Skew (IN PROGRESS — Task #2)
- Proposed: Set `LastSeen = local monotonicSeconds()` when installing synced sessions
- Prevents premature GC expiry when nodes have different uptimes

### Fix 4: NO_NEIGH ARP Warmup (IN PROGRESS — Task #1)
- Proposed: Proactive ARP/NDP warmup after VRRP MASTER transition
- Consider `BPF_FIB_LOOKUP_SKIP_NEIGH` for graceful degradation

### Design Decision: FIB Cache Not Synced
- `fib_ifindex`, `fib_dmac`, `fib_smac`, `fib_gen` zeroed in synced sessions
- Interface indices and MACs differ between nodes — zero forces fresh `bpf_fib_lookup`

### Files Changed
| File | Lines | Description |
|------|-------|-------------|
| `pkg/cluster/sync.go` | ~60 | Reverse entry creation, dnat_table creation/cleanup in handleMessage |
| `docs/sync-protocol.md` | ~120 | Receiver reconstruction docs, known issues, test plan |

## Sprint FABRIC-FWD: Cross-Chassis Fabric Redirect + VRRP Coordinated Preemption

### Problem
After VRRP failback (secondary→primary), synced TCP sessions die because:
1. `bpf_fib_lookup` returns NO_NEIGH/NOT_FWDED on the new primary (peer still has fresh ARP/routes)
2. META_FLAG_KERNEL_ROUTE fallback is slow and unreliable for high-throughput flows
3. VRRP preemption after bulk sync waits for next advertisement timer (~3s), extending disruption
4. RST packets arriving during kernel-route phase poison the conntrack session to CLOSED state

### Fix 1: BPF Fabric Cross-Chassis Redirect
- **New struct:** `fabric_fwd_info` in `bpf/headers/xpf_maps.h` — holds fabric ifindex, src/dst MACs, valid flag
- **New BPF map:** `fabric_fwd` ARRAY(1) — single-entry map populated by userspace with fabric link info
- **New helper:** `try_fabric_redirect()` in `bpf/headers/xpf_helpers.h`:
  - Called in `xdp_zone.c` before META_FLAG_KERNEL_ROUTE fallback (both NO_NEIGH and NOT_FWDED paths)
  - Only activates for existing sessions (has scratch map entry with valid flags)
  - Rewrites L2 headers (fabric src/dst MAC), redirects via `bpf_redirect(fabric_ifindex, 0)`
  - Peer receives pre-NAT original packet, processes through full pipeline with fresh FIB
- **New counter:** `GLOBAL_CTR_FABRIC_REDIRECT = 26`, `GLOBAL_CTR_MAX` bumped to 27
- **Go side:** `FabricFwdInfo` struct + `UpdateFabricFwd()` in `pkg/dataplane/maps.go`
- **Daemon:** `populateFabricFwd()` goroutine in `daemon.go` — resolves fabric interface ifindex, local MAC, peer MAC (via ARP lookup on fabric peer IP); retries every 5s until resolved
- **CLI:** `show security flow statistics` displays "Fabric redirects:" counter
- **REST API:** `GlobalStats` includes `fabric_redirects` field

### Fix 2: VRRP Coordinated Preemption
- **`preemptNowCh`:** Buffered channel (cap 1) added to `vrrpInstance`
- **`triggerPreemptNow()`:** Non-blocking send on `preemptNowCh`
- **StateBackup select:** New case `<-vi.preemptNowCh` → immediate `becomeMaster()` (if preempt enabled)
- **Integration:** `ReleaseSyncHold()` calls `triggerPreemptNow()` on all instances after `restorePreempt()`
- **Effect:** After bulk session sync completes, VRRP transitions to MASTER immediately instead of waiting for next advertisement timer (~3s delay eliminated)
- **Tests:** TestTriggerPreemptNow_NonBlocking, TestPreemptNowCh_Initialized, TestReleaseSyncHold_TriggersPreemptNow

### Fix 3: BPF RST State Protection
- **Problem:** RST packets arriving for kernel-routed sessions update conntrack to CLOSED, but kernel may drop the packet (no route/ARP), leaving a falsely-closed session
- **Fix:** In `handle_ct_hit_v4` and `handle_ct_hit_v6` (`xdp_conntrack.c`): after `ct_tcp_update_state()`, if `new_state == SESS_STATE_CLOSED && meta->flags & META_FLAG_KERNEL_ROUTE`, preserve existing state instead of writing CLOSED
- **Scope:** Both IPv4 and IPv6 paths

### How the Three Fixes Work Together
1. Session synced to secondary via cluster sync (existing flow)
2. VRRP failback: `ReleaseSyncHold()` → `triggerPreemptNow()` → instant MASTER (Fix 2)
3. Traffic arrives at new primary; `bpf_fib_lookup` returns NO_NEIGH/NOT_FWDED
4. `try_fabric_redirect()` sends packet to peer via fabric link (Fix 1) — peer still has ARP/routes
5. If fabric redirect unavailable, META_FLAG_KERNEL_ROUTE fallback kicks in
6. Any RST during kernel-route phase doesn't poison session state (Fix 3)
7. ARP/NDP resolves; subsequent packets use normal FIB path

### Files Changed
| File | Description |
|------|-------------|
| `bpf/headers/xpf_common.h` | `GLOBAL_CTR_FABRIC_REDIRECT=26`, `GLOBAL_CTR_MAX=27` |
| `bpf/headers/xpf_maps.h` | `fabric_fwd_info` struct, `fabric_fwd` ARRAY map |
| `bpf/headers/xpf_helpers.h` | `try_fabric_redirect()` helper function |
| `bpf/xdp/xdp_zone.c` | Calls `try_fabric_redirect()` in NO_NEIGH + NOT_FWDED paths |
| `bpf/xdp/xdp_conntrack.c` | RST state protection under META_FLAG_KERNEL_ROUTE |
| `dpdk_worker/tables.h` | `GLOBAL_CTR_FABRIC_REDIRECT`, `GLOBAL_CTR_MAX` |
| `pkg/dataplane/types.go` | `FabricFwdInfo` Go struct, counter constants |
| `pkg/dataplane/maps.go` | `UpdateFabricFwd()` method |
| `pkg/dataplane/dataplane.go` | `fabric_fwd` map in spec |
| `pkg/daemon/daemon.go` | `populateFabricFwd()` goroutine |
| `pkg/cli/cli.go` | "Fabric redirects:" in flow statistics |
| `pkg/api/types.go` | `FabricRedirects` field in GlobalStats |
| `pkg/api/handlers.go` | Populate fabric_redirects counter |
| `pkg/vrrp/instance.go` | `preemptNowCh`, `triggerPreemptNow()`, StateBackup select |
| `pkg/vrrp/manager.go` | `ReleaseSyncHold()` calls `triggerPreemptNow()` |
| `pkg/vrrp/vrrp_test.go` | Three new tests for coordinated preemption |

## Sprint HA-TIMING: Sub-Second Failover Timing (`ff7821c`)

### Overview
Reduced chassis cluster failover from ~3.2s to <1s and failback from ~6s to ~3s by tuning all control plane timers. The BPF data plane already continued forwarding during daemon restart (pinned links + PROG_ARRAY); all bottlenecks were in VRRP timers, heartbeat detection, session sync reconnection, and event debounce.

### Change 1: Sub-second VRRP advertisement for RETH instances
- **Impact:** Failover from ~3.2s → ~0.8s (single biggest win)
- Changed `Instance.AdvertiseInterval` semantics from seconds to **milliseconds** internally
- RETH instances: 250ms. User-configured VRRP groups: `seconds * 1000`
- masterDownInterval = `3 * 250ms + 56/256 * 250ms = 805ms`
- Wire format: `uint16(ms / 10)` (centiseconds per RFC 5798)
- Priority-0 on clean shutdown: peer skew = `56/256 * 250ms = ~55ms` (near-instant failover)
- **Files:** `pkg/vrrp/vrrp.go`, `pkg/vrrp/instance.go`, `pkg/vrrp/manager.go`, `pkg/vrrp/vrrp_test.go`

### Change 2: Faster session sync connect (5s → 1s retry, immediate first)
- **Impact:** Failback session sync wait from 5-10s → 1-2s
- `connectLoop()` now dials immediately on first iteration, then retries every 1s
- Previously waited 5s before first attempt, then retried every 5s
- **File:** `pkg/cluster/sync.go`

### Change 3: Event debounce from 2s to 500ms
- **Impact:** VRRP priority update 1.5s faster
- `watchClusterEvents()` timer from `2*time.Second` to `500*time.Millisecond`
- **File:** `pkg/daemon/daemon.go`

### Change 4: Sync hold timeout from 30s to 10s
- **Impact:** Faster failback if sync is slow
- `OnBulkSyncReceived` callback already releases hold on completion; this timeout only fires if sync fails entirely
- **File:** `pkg/daemon/daemon.go`

### Change 5: Heartbeat timers (config)
- **Impact:** Heartbeat detection from 3s → 1s
- `heartbeat-interval 200; heartbeat-threshold 5;` (200ms × 5 = 1s detection)
- **Files:** `docs/ha-cluster.conf`, `test/incus/xpf-cluster-fw0.conf`, `test/incus/xpf-cluster-fw1.conf`

### Change 6: systemd RestartSec from 5s to 1s
- **Impact:** 4s faster crash recovery restart
- **File:** `test/incus/xpfd.service`

### Measured Results
| Scenario | Before | After |
|----------|--------|-------|
| Failover (fw0 dies → fw1 takes over) | ~3.2s | ~0.8s |
| Clean daemon stop (priority-0 → peer skew) | ~219ms | ~55ms |
| Failback (fw0 returns → preempts back) | ~5-6s | ~2-3s |

## Sprint HA-REBOOT: Reboot Resilience (`f8353de`, `a4eb2b2`)

### Overview
Fixed two bugs preventing reliable cluster reboot: RETH `.link` files using `MACAddress=` (fails after daemon programs virtual MAC), and VRRP VIPs lost during simultaneous boot when `programRethMAC` link DOWN/UP coincides with VRRP running.

### Bug 1: RETH `.link` files fail to match after reboot (`f8353de`)
- **Symptom:** After reboot, RETH member interfaces not renamed — daemon can't find them by config name
- **Root cause:** Bootstrap `.link` files in `cluster-setup.sh` used `MACAddress=` for RETH members. After daemon programs virtual MAC (`02:bf:72:...`), on reboot the interface starts with physical MAC → `.link` file doesn't match → no rename
- **Fix (two parts):**
  1. **`cluster-setup.sh`:** Changed RETH members (LAN + WAN) from `MACAddress=` to `OriginalName=` (PCI kernel name). Non-RETH interfaces (fxp0/fxp1/fab0) kept `MACAddress=` (their MACs never change)
  2. **`daemon.go`:** Added `ensureRethLinkOriginalName()` — auto-fixes stale `.link` files at runtime. Runs unconditionally for every RETH member after rename block in RETH MAC loop. If `.link` file uses `MACAddress=`, derives kernel name from sysfs and rewrites to `OriginalName=`
- **Helper functions:** `deriveKernelName()` (handles both PCI-direct and virtio-over-PCI via parent directory traversal), `pciAddrFromPath()`, `pciAddrToEnp()`
- **Gotcha:** Virtio interfaces have sysfs device path `virtioN` (not PCI address) — must traverse to parent directory to find PCI bus/slot
- **Files:** `test/incus/cluster-setup.sh`, `pkg/daemon/daemon.go`

### Bug 2: VRRP VIPs lost on simultaneous boot (`a4eb2b2`)
- **Symptom:** After simultaneous reboot of both nodes, fw0 becomes MASTER but missing IPv6 LAN VIP `2001:559:8585:cf01::1/64`
- **Root cause:** Race between VRRP and `programRethMAC`:
  1. DHCP recompile triggers early `applyConfig` → VRRP starts, adds VIPs
  2. Config sync recompile triggers second `applyConfig` → `programRethMAC` does link DOWN/UP → kernel removes ALL addresses including VRRP VIPs
  3. `UpdateInstances()` sees no config change → `continue` → VIPs never re-added
- **Fix:** Added `ReconcileVIPs()` method to `pkg/vrrp/manager.go` — re-adds VIPs and sends GARP on all MASTER instances. Called from `daemon.go` after RETH MAC programming loop (step 2.6b)
- **Files:** `pkg/vrrp/manager.go`, `pkg/daemon/daemon.go`

### Reboot Test Results
| Scenario | Result |
|----------|--------|
| Single node reboot (fw1) | Interfaces correct, VRRP BACKUP, connectivity OK |
| Single node reboot (fw0) | Interfaces correct, VRRP MASTER in ~6s, connectivity OK |
| Simultaneous reboot (both) | Both converge within ~10s, fw0 MASTER, all VIPs present |

## Sprint SYNCOOKIE: SYN Cookie Flood Protection (`8cbf31a`)

### Overview
When `security flow syn-flood-protection-mode syn-cookie` is configured and a zone's SYN rate exceeds its screen threshold, xpf generates SYN-ACK cookies from XDP instead of dropping all SYNs. Validates real sources (not spoofed) before allowing connections through. Zero per-packet overhead once validated.

### Algorithm
1. SYN flood detected → zone's `flood_state.synproxy_active = 1`
2. SYN from unvalidated source → `bpf_tcp_raw_gen_syncookie_ipv4/v6` → SYN-ACK with cookie seq → XDP_TX
3. ACK returns → `bpf_tcp_raw_check_syncookie_ipv4/v6` → valid: add to `validated_clients` LRU → send RST → XDP_TX
4. Client retransmits SYN → source is validated → passes through pipeline normally
5. Zone rate drops below threshold/2 → `synproxy_active = 0`

### BPF Changes
- `SCREEN_SYN_COOKIE (1<<14)` flag in `xpf_common.h`
- 4 new global counters: `GLOBAL_CTR_SYNCOOKIE_SENT/VALID/INVALID/BYPASS` (27-30)
- `flood_state` extended: `__u8 synproxy_active` + `__u8 pad_fs[7]`
- `validated_clients` LRU_HASH map (65536 entries) in `xpf_maps.h`
- 4 `__noinline` functions in `xdp_screen.c`: `send_syncookie_synack_v4/v6`, `validate_syncookie_v4/v6`
- Uses kernel BPF helpers 204-207 (available since 5.19, running 6.18)

### Go Changes
- `FlowConfig.SynFloodProtectionMode` in `pkg/config/types.go`
- `syn-flood-protection-mode` parsing in `pkg/config/compiler.go`
- `ScreenSynCookie` flag + 4 counter constants in `pkg/dataplane/types.go`
- Flag set in `pkg/dataplane/compiler.go` when syn-cookie + syn-flood configured
- 4 syncookie counters in `pkg/grpcapi/server.go` screen stats
- `xpf_screen_syncookie_total{type}` Prometheus metric in `pkg/api/metrics.go`

### DPDK Parity
- `SCREEN_SYN_COOKIE` and counter defines in `dpdk_worker/shared_mem.h` + `tables.h`
- `flood_state` struct updated with `synproxy_active` field

### Verifier Issues Fixed
1. **Variable TCP header length:** `tcph->doff * 4` gives var_off up to 60; helper needs that many validated bytes. Fix: use constant `sizeof(struct tcphdr)` (20) for helper call
2. **Stale packet pointers after helper call:** Compiler reordered MAC reads past BPF helper, losing packet validation. Fix: read MACs after `bpf_xdp_adjust_tail` (packet beginning unchanged by tail truncation)

### Files Modified (39 files, 1015 insertions)
| File | Changes |
|------|---------|
| `bpf/headers/xpf_common.h` | SCREEN_SYN_COOKIE flag, 4 counters, synproxy_active in flood_state, validated_client structs |
| `bpf/headers/xpf_maps.h` | `validated_clients` LRU_HASH map |
| `bpf/xdp/xdp_screen.c` | SYN-ACK generation (v4+v6), cookie validation (v4+v6), synproxy activation, validated bypass |
| `pkg/config/types.go` | `SynFloodProtectionMode` in FlowConfig |
| `pkg/config/compiler.go` | Parse `syn-flood-protection-mode` |
| `pkg/dataplane/compiler.go` | Set `SCREEN_SYN_COOKIE` flag |
| `pkg/dataplane/types.go` | `ScreenSynCookie` constant, 4 counter constants, FloodState struct update |
| `pkg/grpcapi/server.go` | 4 syncookie counters in screen stats |
| `pkg/api/metrics.go` | `xpf_screen_syncookie_total` Prometheus metric |
| `dpdk_worker/shared_mem.h` | SCREEN_SYN_COOKIE, flood_state update |
| `dpdk_worker/tables.h` | 4 counter defines, GLOBAL_CTR_MAX=31 |

## Sprint CGNAT: Deterministic NAT / Carrier-Grade NAT (`74e1d17`)

### Overview
Carrier-grade NAT with deterministic port block allocation. Each subscriber from a configured
host range gets a fixed, algorithmically-computed block of ports on a public IP. Purely
mathematical mapping enables ISP compliance logging without per-session overhead.

### Config
```
set security nat source pool POOL address 203.0.113.1/32 to 203.0.113.4/32
set security nat source pool POOL port deterministic block-size 2016
set security nat source pool POOL port deterministic host address 100.64.0.0/22
```

### BPF Changes
- `nat_pool_alloc_deterministic_v4()` __noinline in `xdp_policy.c`
- Dispatched via `cfg->deterministic` flag (mode 1 = IPv4)
- `nat_pool_config` extended to 24 bytes (deterministic, block_size, host_base, host_count, blocks_per_ip)
- `MAX_NAT_POOL_IPS_PER_POOL` 8 -> 256, `MAX_NAT_POOL_IPS` -> 8192

### Go Changes
- `DeterministicNATConfig` struct (block_size, host_address)
- `PoolUtilizationAlarmConfig` (raise/clear threshold)
- Address range expansion (`expandAddressRange`, max 256 IPs)
- Validation: capacity, mutual exclusion with persistent-nat/address-persistent
- `xpf_nat_pool_deterministic_info` Prometheus gauge
- `deterministic-nat nat-table` CLI command

### Files
18 files changed (426 insertions, 23 deletions)

## Sprint CGNAT-64: Deterministic NAPT64 for IPv6 Subscribers (`439cd3f`)

### Overview
Extended deterministic NAT to support NAT64 traffic. IPv6 subscribers get deterministic
IPv4 SNAT allocation based on their IPv6 source address prefix. Subscriber index derived
from the 32-bit word after the configured prefix (/32 -> word[1], /64 -> word[2]).

### Config
```
set security nat source pool POOL port deterministic block-size 2016
set security nat source pool POOL port deterministic host address 2001:db8::/32
```

### BPF Changes
- New `nat_pool_alloc_deterministic_v6()` in xdp_policy.c
- NAT64 dispatch checks `deterministic==2` before regular allocation
- `nat_pool_config` extended 24 -> 40 bytes (host_prefix_len, host_base_v6[4])

### Go Changes
- IPv6 host prefix validation (/32 or /64 only)
- Compiler mode 2 with IPv6 base address

### DPDK Parity
Inline deterministic v6 allocation in `dpdk_worker/nat64.c`

### Files
14 files changed (199 insertions, 24 deletions)

## VRF-Aware Connectivity Test Suite (`367fa54`)

### Overview
New `make test-connectivity` target with VRF-aware ping helper. Tests standalone (service,
reachability, cross-zone IPv4/IPv6) and cluster (heartbeat, fabric, RETH VIP, cross-zone).

### Key Design
- `ping_vrf_aware()`: tries default table first, then each VRF (`ip vrf show`)
- Auto-detects running instances, skips unavailable tests
- Supports `standalone`, `cluster`, `all` modes

### Files
2 files changed (205 insertions) -- `test/incus/test-connectivity.sh`, `Makefile`

## NAT64 TCP/UDP Fix for CHECKSUM_PARTIAL (`78baec0`)

### Overview
Three interacting bugs prevented NAT64 TCP from working on the HA cluster (generic XDP /
virtio-net). ICMP ping worked but TCP/UDP checksums were corrupted on egress.

### Bug 1: Session Key Corruption (xdp_policy.c)
- `meta->src_ip` was overwritten with SNAT IPv4 address BEFORE `create_session_v6()` used it
  as the session key source, causing sessions to be created with wrong source IPv6 address
- Fix: use `meta->nat_src_ip` as scratch buffer, overwrite `src_ip` only after session creation

### Bug 2: NAT64 Flag Propagation (xdp_conntrack.c, xdp_zone.c)
- On established session hits, `SESS_FLAG_NAT64` was not propagated from session flags to
  `meta->nat_flags`, so `xdp_nat` never dispatched to `xdp_nat64` for existing sessions
- Fix: add `if (sess->flags & SESS_FLAG_NAT64) meta->nat_flags |= SESS_FLAG_NAT64`

### Bug 3: CHECKSUM_PARTIAL Corruption (xdp_nat64.c)
- Generic XDP (virtio-net) preserves `skb->ip_summed=CHECKSUM_PARTIAL` through `bpf_redirect_map`
- From-scratch TCP/UDP checksum was complete, but kernel/NIC finalizes by adding L4 byte sums
  to the existing check field — corrupting the already-correct checksum
- Fix: split checksum into two paths based on `meta->csum_partial`:
  - `csum_partial=1`: write only IPv4 pseudo-header seed (`csum_fold(ph)`, no complement)
  - `csum_partial=0`: compute full from-scratch checksum (`~csum_fold(sum)`)
  - ICMPv4 (no pseudo-header): set `checksum=0` for CHECKSUM_PARTIAL, kernel sums all bytes
- Why NAT44 unaffected: incremental checksum updates are compatible with CHECKSUM_PARTIAL
- Why ICMP ping worked: short echo packets happened to finalize correctly

### Additional Fixes
- NAT64 return-path v6 session update: TCP state machine + counters updated on IPv4 return
  traffic via nat64_state reverse lookup (prevents sessions stuck in SYN_SENT)
- Removed debug code (bpf_printk, XDP_PASS bypass) and unused `csum_v6_to_v4()` function

### Verified
- NAT64 TCP: 3.91 Gbps (`iperf3 -c 64:ff9b::172.16.100.200`)
- NAT64 UDP: 1 Gbps, 0% loss
- NAT64 ICMP: 0% loss
- NAT44 TCP: 4.84 Gbps (no regression)

### Files
10 files changed (188 insertions, 99 deletions)
- `bpf/xdp/xdp_nat64.c` — CHECKSUM_PARTIAL split, debug removal, csum_v6_to_v4 removal
- `bpf/xdp/xdp_conntrack.c` — NAT64 flag propagation + return-path v6 session update
- `bpf/xdp/xdp_policy.c` — Session key corruption fix (nat_src_ip scratch)
- `bpf/xdp/xdp_zone.c` — NAT64 flag propagation
- `docs/ha-cluster.conf` — NAT64 rule-set added to cluster config

## Graceful Startup Retry for Cluster Heartbeat and Sync (`2199e52`)

### Overview
Improved cluster startup resilience. Heartbeat + sync bind retries log at INFO for first
5 attempts (normal startup race), escalating to WARN after 10s. Fabric IP resolution
retried inside goroutine (was single attempt outside, failing permanently).

### Changes
- Heartbeat: INFO first 5, WARN after, 30 attempts at 2s
- Fabric IP: retry loop inside goroutine with ctx.Done() honoring
- Session sync: INFO first 5, WARN after, integrated into fabric goroutine

### Files
1 file changed (53 insertions, 28 deletions) -- `pkg/daemon/daemon.go`

## Sprint FLOW-OPTS: Aggressive Session Aging + TCP Session Options

### Overview
Two flow-level enhancements: aggressive session aging with GC watermark hysteresis for
session table capacity management, and TCP session options (no-syn-check,
no-syn-check-in-tunnel, rst-invalidate-session) in BPF and DPDK datapaths.

### Aggressive Session Aging
- **Config parsing:** `set security flow aging` with high-watermark/low-watermark/early-ageout
- **GC watermark hysteresis:** Go-side GC (`pkg/conntrack/gc.go`) monitors session table
  utilization against high/low watermarks. When utilization exceeds high watermark, early
  ageout override kicks in to aggressively expire sessions. Returns to normal when below
  low watermark.
- **Daemon integration:** `pkg/daemon/daemon.go` passes aging config to GC

### TCP Session Options
- **no-syn-check:** Skip SYN validation for mid-stream TCP pickup (asymmetric routing).
  BPF: `xdp_conntrack.c` creates sessions for non-SYN TCP packets when flag set.
  DPDK: `dpdk_worker/conntrack.c` equivalent logic.
- **no-syn-check-in-tunnel:** Same as no-syn-check but only for tunnel interfaces.
  Per-interface tunnel flag via `iface_zone_value.flags` in `xpf_common.h`.
  BPF: `xdp_zone.c` sets meta tunnel flag from interface flags.
- **rst-invalidate-session:** Immediately close sessions on RST instead of waiting for
  timeout. BPF: `xdp_conntrack.c` transitions to CLOSED on RST when flag set.
  DPDK: `dpdk_worker/conntrack.c` equivalent.

### Config Compilation
- `pkg/config/types.go` — FlowConfig aging + TCP session option fields
- `pkg/config/compiler.go` — Junos AST → typed config compilation for flow options
- `pkg/config/ast.go` — Parser support for flow aging/TCP-session nodes
- `pkg/dataplane/compiler.go` — Typed config → BPF map entries (flow_config map)
- `pkg/dataplane/maps.go` — Flow config map definitions
- `pkg/dataplane/types.go` — BPF-side flow config struct

### Files Changed
- `bpf/headers/xpf_common.h` — flow_config struct, tunnel flag in iface_zone_value.flags, TCP option flags
- `bpf/xdp/xdp_conntrack.c` — no-syn-check + rst-invalidate-session logic
- `bpf/xdp/xdp_policy.c` — flow config flag reads
- `bpf/xdp/xdp_zone.c` — per-interface tunnel flag propagation to meta
- `pkg/conntrack/gc.go` — watermark hysteresis, early ageout override
- `pkg/conntrack/gc_test.go` — tests for watermark aging behavior
- `pkg/daemon/daemon.go` — aging config plumbing to GC
- `pkg/config/types.go` — FlowConfig Go types
- `pkg/config/compiler.go` — flow option compilation
- `pkg/config/ast.go` — parser support
- `pkg/dataplane/compiler.go` — BPF map compilation
- `pkg/dataplane/maps.go` — flow config map
- `pkg/dataplane/types.go` — BPF struct mirror
- `pkg/dataplane/dataplane.go` — flow config loading
- `pkg/dataplane/loader.go` — map pinning
- `dpdk_worker/conntrack.c` — DPDK no-syn-check + rst-invalidate-session
- `dpdk_worker/shared_mem.h` — DPDK shared flow config struct
- `pkg/dataplane/dpdk/dpdk_cgo.go` — CGo flow config bridge
- `pkg/dataplane/dpdk/dpdk_stub.go` — stub for non-DPDK builds

---

## Sprint FEAT-4: Proxy ARP, Session Limiting, BFD Profiles, DPDK Policer

**Commit:** `f0511af` — 54 files changed, +1997/-511 lines
**Date:** 2026-02-25

Four features from feature-gaps.md Tier 1 priority list, reducing gap count 161→155.

### Feature 1: DPDK Policer Parity

eBPF policer (`evaluate_policer()` in `xpf_helpers.h`) already worked. DPDK had structs
and map pointers but stubs for evaluation. Now fully functional.

- **`dpdk_worker/policer.c`** (new) — Ports BPF token bucket to DPDK:
  - `rte_rdtsc()` / `rte_get_tsc_hz()` for timing (TSC ticks instead of ktime_ns)
  - Three modes: POLICER_MODE_SINGLE_RATE, POLICER_MODE_TWO_RATE (RFC 2698),
    POLICER_MODE_SR3C (RFC 2697)
  - Returns 0=conform, 1=exceed, 2=violate
- **`dpdk_worker/filter.c`** — `#include "policer.c"`, policer check after rule match/DSCP rewrite
- **`dpdk_worker/tables.h`** — `MAX_POLICERS 64`
- **`pkg/dataplane/dpdk/dpdk_cgo.go`** — `SetPolicerConfig()` + `ClearPolicerConfigs()`

### Feature 2: BFD via FRR Profiles

Extended existing partial BFD support. OSPF had `BFD bool`, BGP had `BFD bool` +
`BFDInterval int`. Now all three protocols support interval/multiplier via FRR BFD profiles.

- **`pkg/config/types.go`**:
  - `OSPFInterface`: added `BFDInterval int`, `BFDMultiplier int`
  - `ISISInterface`: added `BFD bool`, `BFDInterval int`, `BFDMultiplier int`
  - `BGPNeighbor`: added `BFDMultiplier int`
- **`pkg/config/ast.go`** — `multiplier` child for OSPF/BGP `bfd-liveness-detection`;
  new `bfd-liveness-detection` with `minimum-interval` + `multiplier` for IS-IS interface
  (both default and per-VRF variants)
- **`pkg/config/compiler.go`** — Parse interval/multiplier for OSPF, IS-IS, BGP
  (group-level + per-neighbor). Gotcha: `groupBFDMultiplier` must be propagated to
  neighbor initialization
- **`pkg/frr/frr.go`**:
  - `bfdProfile` struct + `bfdProfileName()` helper (e.g. `xpf-300-3`)
  - OSPF: `ip ospf bfd profile <name>` when interval/multiplier set (plain `ip ospf bfd` otherwise)
  - IS-IS: `isis bfd` per interface, `isis bfd profile <name>` when custom interval
  - BGP: `n.BFDMultiplier` instead of hardcoded `3`
  - Deduplicated BFD profile stanzas generated at end of `generateProtocols()`

### Feature 3: Proxy ARP for NAT

New feature — auto-reply ARP for NAT pool addresses on same L2 segment.

- **`pkg/config/types.go`** — `ProxyARPEntry` struct + `ProxyARP []*ProxyARPEntry` in `NATConfig`
- **`pkg/config/ast.go`** — `proxy-arp` → `interface` (args:1) → `address` (args:1, multi:true)
- **`pkg/config/compiler.go`** — Parse in `compileNAT()`, range expansion via `expandAddressRange()`
- **`pkg/dataplane/proxyarp.go`** (new) — `ReconcileProxyARP(cfg, ifaceMap)`:
  - Builds desired `{ifindex, IP}` set from config
  - Lists existing NTF_PROXY neighbors via `netlink.NeighList()`
  - Adds missing entries with `netlink.NeighSet()` (NTF_PROXY flag)
  - Removes stale entries with `netlink.NeighDel()`
  - Enables the per-interface kernel proxy responder sysctl for every
    interface with a desired entry (#2160): `net.ipv4.conf.<if>.proxy_arp`
    for IPv4, `net.ipv6.conf.<if>.proxy_ndp` for IPv6. The kernel has two
    ARP-proxy paths (net/ipv4/arp.c): the pneigh (NTF_PROXY) reply branch,
    which answers only when the target routes out a *different* interface and
    does NOT consult the sysctl; and the `arp_fwd_proxy` path, which is gated
    by the per-interface sysctl. So whether the sysctl is load-bearing is
    route-topology dependent — a same-L2-subnet external address (the #2160
    case, where the route stays on the ingress device) is answered by neither
    path until the sysctl is enabled, leaving the address unreachable until a
    manual static ARP is added; enabling the sysctl guarantees a reply
    regardless of topology. The procfs interface name is resolved from the
    same ifindex the neighbor entry was installed on (via
    `netlink.LinkByIndex`) so VLAN sub-interface naming stays consistent. The
    write goes through the `proxyARPSysctlSeam` package var (best-effort
    `os.WriteFile`) so unit tests capture it without touching real procfs.
  - Breadth caveat: with the default `medium_id=0`, per-interface
    `proxy_arp=1` makes the kernel (the `arp_fwd_proxy` path) answer ARP on
    that interface for ANY target routed out a different interface — not only
    the configured static-NAT external address. This is BROADER than Junos
    `proxy-arp`, which proxies only the listed addresses. It is an
    operator-opted-in tradeoff (proxy-arp was configured on the interface),
    but the breadth matters on a WAN/untrust interface; narrowing to
    per-address (Junos parity) is tracked in follow-up #2197.
  - Returns `ProxyARPAdded` structs for caller to send GARPs (avoids cluster import cycle)
- **`pkg/daemon/daemon.go`** — Calls `ReconcileProxyARP()` after VRRP VIP reconciliation;
  sends GARPs for newly added entries
- Config: `set security nat proxy-arp interface trust0 address 10.0.1.100/32`
  (a multi-host prefix such as `address 10.0.1.0/29` is expanded to its
  ARP-addressable hosts at compile time, capped at 256 -- #6559)
  or range `address 10.0.1.101/32 to 10.0.1.110/32`

### Feature 4: Per-IP Session Limiting (Screen)

New screen check — prevents session table exhaustion from single source/destination.
Design: Go GC counts → BPF LRU maps → xdp_screen enforcement.

- **BPF C changes:**
  - `xpf_common.h` — `session_limit_src`/`session_limit_dst` in `screen_config`,
    flags `SCREEN_SESSION_LIMIT_SRC (1<<15)` / `SCREEN_SESSION_LIMIT_DST (1<<16)`,
    `GLOBAL_CTR_SCREEN_SESSION_LIMIT`, `session_count_key`/`session_count_value` structs
  - `xpf_maps.h` — `session_count_src`/`session_count_dst` LRU_HASH maps (65536 entries)
  - `xdp_screen.c` — Session limit checks after IP sweep for TCP SYN;
    IPv6 XOR-hashes 4 words to uint32 key
- **Go config:**
  - `types.go` — `LimitSessionScreen` struct in `ScreenProfile`
  - `ast.go` — `limit-session` → `source-ip-based` + `destination-ip-based`
  - `compiler.go` — Parse thresholds in `compileScreen()`
- **Go dataplane:**
  - `types.go` — `SessionLimitSrc`/`SessionLimitDst` in `ScreenConfig`, `SessionCountKey`/
    `SessionCountValue` Go mirror structs
  - `dataplane.go` — `UpdateSessionCountSrc`/`UpdateSessionCountDst`/`ClearSessionCounts` interface
  - `maps.go` — Implementation using ebpf map operations
  - `loader_ebpf.go` — Register new maps from bpf2go objects
  - `compiler.go` — Compile session limit thresholds/flags in screen profiles
- **Conntrack GC (`gc.go`):**
  - `sessionLimitEnabled bool` + `SetSessionLimitEnabled()`
  - During sweep: accumulates `srcCounts`/`dstCounts` maps for forward entries (v4+v6)
  - After sweep: pushes all counts to BPF maps
- **DPDK parity:**
  - `shared_mem.h` — Updated `screen_config`, added count key/value structs + hash tables
  - `screen.c` — Session limit checks via rte_hash lookups
  - `dpdk_cgo.go` — `UpdateSessionCountSrc`/`UpdateSessionCountDst`/`ClearSessionCounts`
  - `dpdk_stub.go` — Stubs
- **`daemon.go`** — Detects session limit config, calls `gc.SetSessionLimitEnabled()`
- Config: `set security screen ids-option untrust-screen limit-session source-ip-based 100`

### Tests Added
- `pkg/config/parser_test.go` — 11 new tests:
  - Proxy ARP: hierarchical, set syntax, single address, bare IP
  - BFD: OSPF interval/multiplier, IS-IS BFD, BGP multiplier (all set syntax)
  - Session limiting: compilation, hierarchical
- `pkg/conntrack/gc_test.go` — Session limit enabled flag test

### Key Gotchas Discovered
- `cfg.Security` and `cfg.Security.NAT` are Go structs (not pointers) — never `!= nil` check,
  use `len(cfg.Security.NAT.ProxyARP) > 0`
- BGP `groupBFDMultiplier` must be explicitly set in neighbor struct initialization
- Per-neighbor BFD parsing needs `switch` (not just `if`) to handle both `minimum-interval`
  and `multiplier` children
- FRR BFD profile name helper must match actual struct name (`bfdProfile` not `bfdProfileParams`)

---

## Sprint HA-NONPREEMPT: Non-Preempt HA (No Auto-Failback on Rejoin)

**Commit:** `de23c78` — Implement non-preempt HA: no auto-failback on rejoin

### Problem
When a firewall node reboots and comes back, it automatically preempted back to primary (higher base priority). Two independent preempt mechanisms existed:
1. **Cluster election** (`election.go`): checked `rg.Preempt` — already supported non-preempt
2. **VRRP instances** (`vrrp.go`): hardcoded `Preempt: true` for all RETH instances — ignored config

Additionally, config sync preserved the entire `chassis` node from the local config, preventing preempt changes from propagating to the secondary node. And manual failover (`ResignRG`) had no mechanism to force VRRP MASTER→BACKUP transitions.

### Goal
Returning node rejoins as secondary and stays there until:
1. Admin triggers `request chassis cluster failover` on the current primary, OR
2. Current primary restarts

Matches Junos behavior when `preempt` is NOT configured on a redundancy group.

### Changes

#### 1. Wire RG preempt config to VRRP instances (`pkg/vrrp/vrrp.go`)
- Built `preemptMap` from RG configs (like existing `garpCounts`)
- Used `preemptMap[rgID]` instead of hardcoded `true` for both VLAN and non-VLAN instance creation

#### 2. Add resign channel to VRRP instances (`pkg/vrrp/instance.go`)
- Added `resignCh chan struct{}` to `vrrpInstance` (alongside existing `preemptNowCh`)
- Initialized as buffered channel of size 1 in `newInstance()`
- MASTER state handler: sends 3× priority-0 adverts then calls `becomeBackup()`
- `triggerResign()` method: non-blocking send (like `triggerPreemptNow()`)

#### 3. Fix VRRP startup masterDown timer race (`pkg/vrrp/instance.go`)
- **Bug:** With 30ms RETH intervals, masterDown timer (~97ms) fires before AF_PACKET receiver starts capturing peer adverts — returning node erroneously becomes MASTER within 85ms
- **Fix:** Extended initial masterDown timer to 3 seconds when `preempt=false` (either from config or sync hold)
- After first received advert, `handleBackupRx` resets to normal short interval — fast failover detection preserved
- **#7579 follow-up:** that shield is one-shot at startup, and the SAME deafness window reopens at sync-hold release (the timer is short again by then). The release path now re-arms the identical interval when it declines to promote; see `masterDownAfterSyncHoldRelease`.

#### 4. Add `ResignRG()` to VRRP Manager (`pkg/vrrp/manager.go`)
- Forces all VRRP instances for a given RG to resign
- Matches by `GroupID == 100 + rgID` (VRID convention)
- Used when cluster state transitions Primary→Secondary

#### 5. Wire cluster Primary→Secondary to VRRP resign (`pkg/daemon/daemon.go`)
- In `watchClusterEvents()`: when `ev.OldState == StatePrimary && ev.NewState == StateSecondary|SecondaryHold`, calls `d.vrrpMgr.ResignRG(ev.GroupID)`
- Happens before debounced VRRP priority update — peer receives priority-0 adverts promptly

#### 6. Fix config sync chassis preservation (`pkg/daemon/daemon.go`)
- **Bug:** `handleConfigSync()` replaced the entire received `chassis` node with the local copy, preserving stale settings (like `preempt;`) on the secondary
- **Root cause:** Per-node settings live in `groups` section (not chassis), and `CompileConfigForNode` handles per-node expansion using local node-id file
- **Fix:** Removed chassis preservation entirely — pass `nil` as chassisPreserve to `SyncApply()`

#### 7. Cluster election guards (`pkg/cluster/`)
- `cluster.go`: Added `peerEverSeen bool` flag, set in `handlePeerHeartbeat()`; `handlePeerNeverSeen()` for timeout when peer never seen
- `election.go`: Non-preempt guard — if `!rg.Preempt && !peerEverSeen && rg.State == StateSecondary`, skip election (stay secondary until peer heartbeat received)
- `heartbeat.go`: Added `startedAt` field; timeout loop calls `handlePeerNeverSeen()` when no heartbeat ever received

#### 8. Remove `preempt` from test configs
- `docs/ha-cluster.conf`, `test/incus/xpf-cluster-fw0.conf`, `test/incus/xpf-cluster-fw1.conf` — removed `preempt;` from all 3 RGs

#### 9. Update failover test (`test/incus/test-failover.sh`)
- Phase 4: Verify fw0 rejoins as **secondary** (not primary) after reboot
- Phase 4b: Manual failover test — `request chassis cluster failover redundancy-group 0` on fw1 → verify fw0 becomes primary and iperf3 survives
- Total: 14 tests (was 13), all pass

### Files Modified (12 files, +336/-55)
| File | Change |
|------|--------|
| `pkg/vrrp/vrrp.go` | Wire RG preempt config to VRRP instances |
| `pkg/vrrp/instance.go` | resignCh, triggerResign(), 3s initial masterDown when !preempt |
| `pkg/vrrp/manager.go` | ResignRG() method |
| `pkg/vrrp/vrrp_test.go` | 5 new tests (preempt wiring, resignCh, ResignRG) |
| `pkg/cluster/cluster.go` | peerEverSeen flag, handlePeerNeverSeen() |
| `pkg/cluster/election.go` | Non-preempt guard in electRG() |
| `pkg/cluster/heartbeat.go` | startedAt field, peer-never-seen detection |
| `pkg/daemon/daemon.go` | Remove chassis preservation, add VRRP resign on Primary→Secondary |
| `docs/ha-cluster.conf` | Remove preempt from all 3 RGs |
| `test/incus/xpf-cluster-fw0.conf` | Remove preempt from all 3 RGs |
| `test/incus/xpf-cluster-fw1.conf` | Remove preempt from all 3 RGs |
| `test/incus/test-failover.sh` | Phase 4b manual failover test |

### Tests Added
- `TestCollectRethInstances_PreemptFromRGConfig` — preempt=true in RG → VRRP Preempt=true
- `TestCollectRethInstances_NoPreemptByDefault` — preempt absent → VRRP Preempt=false
- `TestResignCh_Initialized` — resignCh channel exists and is non-nil
- `TestTriggerResign_NonBlocking` — double triggerResign() doesn't block
- `TestResignRG_SignalsCorrectInstances` — only instances matching the RG get signaled

### Key Gotchas Discovered
- **Config sync chassis preservation was too coarse-grained:** Replacing the entire `chassis` node preserved shared settings (preempt, gratuitous-arp-count) alongside intended per-node settings (node ID, peer addresses). Per-node settings actually live in `groups` section and are expanded at compile time by `CompileConfigForNode`.
- **VRRP masterDown timer fires before AF_PACKET receiver starts:** With 30ms adverts, the ~97ms masterDown interval is too short for the AF_PACKET socket to initialize and receive the first peer advert. Logs showed: instance start → BACKUP → MASTER in 85ms with zero received adverts.
- **RFC 5798 masterDown BACKUP→MASTER transition has no preempt check:** The masterDown handler unconditionally becomes MASTER (correct per spec — masterDown means the current MASTER is gone). Non-preempt must be enforced by ensuring the timer doesn't fire prematurely.
- **Manual failover requires VRRP resign:** Cluster state change alone isn't enough — the VRRP layer continues advertising as MASTER. Must send priority-0 adverts to force peer takeover, especially when peer has preempt=false.

---

## Sprint HA-REMOTE-FAILOVER: Remote Failover via `node <N>` Parameter

**Commit:** `29fc8d2` — Add remote failover via node parameter

### Problem
The `request chassis cluster failover redundancy-group N node <N>` command ignored the `node` parameter entirely. It always called `ManualFailover` on the local node, making it secondary. When the user specified `node 0` on node0 (intending to make node0 primary), the command did the opposite — made node0 secondary. Additionally, `ManualFailover` sets a flag that blocks election from promoting the node, so even after peer resignation both nodes could end up secondary.

### Goal
Match Junos semantics for the `node` parameter:
- `node <local>` → make local node primary (peer must resign)
- `node <peer>` → make peer primary (local resigns)
- No node → local resigns (existing behavior)

### Changes

#### 1. Add `syncMsgFailover` message type (`pkg/cluster/sync.go`)
- New sync message type 10 (one byte payload: rgID)
- `SendFailover(rgID int)` method: sends failover request to peer via fabric TCP connection
- `OnRemoteFailover func(rgID int)` callback: called when peer requests us to resign

#### 2. Add `RequestPeerFailover()` to cluster Manager (`pkg/cluster/cluster.go`)
- Validates RG exists, local isn't already primary, peer is alive
- Clears local `ManualFailover` flag and restores weight via `recalcWeight()` — this is critical because `ManualFailover=true` blocks `electRG()` from promoting the node
- Calls `peerFailoverFn` to send the request via fabric sync

#### 3. Add `SetPeerFailoverFunc()` to cluster Manager (`pkg/cluster/cluster.go`)
- Sets the callback used by `RequestPeerFailover` to send messages
- Wired by daemon: `d.cluster.SetPeerFailoverFunc(d.sessionSync.SendFailover)`

#### 4. Wire `OnRemoteFailover` callback (`pkg/daemon/daemon.go`)
- When peer requests failover, calls `d.cluster.ManualFailover(rgID)` locally
- Peer's ManualFailover → weight=0 → heartbeat propagates → local election promotes self

#### 5. Parse `node <N>` in CLI handlers
- **Local CLI** (`pkg/cli/cli.go`): compares target node with `c.cluster.NodeID()`, calls `RequestPeerFailover` for local target
- **Remote CLI** (`cmd/cli/main.go`): passes `:node<N>` suffix in gRPC action string
- **gRPC server** (`pkg/grpcapi/server.go`): parses `cluster-failover:<rgID>:node<N>`, routes to `RequestPeerFailover` or `ManualFailover`

### Files Modified (6 files, +157/-7)
| File | Change |
|------|--------|
| `pkg/cluster/sync.go` | syncMsgFailover type 10, SendFailover(), OnRemoteFailover |
| `pkg/cluster/cluster.go` | peerFailoverFn, SetPeerFailoverFunc(), RequestPeerFailover() |
| `pkg/daemon/daemon.go` | Wire OnRemoteFailover + SetPeerFailoverFunc callbacks |
| `pkg/cli/cli.go` | Parse `node <N>`, route to RequestPeerFailover for local target |
| `cmd/cli/main.go` | Parse `node <N>`, pass in gRPC action string |
| `pkg/grpcapi/server.go` | Parse `:node<N>` suffix, route accordingly |

### Key Gotchas Discovered
- **ManualFailover flag blocks election:** `electRG()` returns `electNoChange` when `ManualFailover=true`. Simply asking the peer to resign isn't enough — must also clear the local ManualFailover flag and restore weight, otherwise both nodes end up secondary.
- **recalcWeight() runs election:** Calling `recalcWeight()` after clearing `ManualFailover` immediately runs election. If the peer has already resigned (weight=0 in heartbeat), election promotes the local node to primary in the same call.
- **Fabric sync connection may not be ready:** `peerFailoverFn` can be nil if session sync hasn't connected yet. `RequestPeerFailover` checks for this and returns a clear error.

## Sprint AA-1: Active/Active Per-RG Fabric Forwarding (`23f1a3d`)

### Problem
When RGs are split across nodes (RG1/WAN on fw1, RG2/LAN on fw0), traffic entering fw0's LAN must cross the fabric link to exit on fw1's WAN. Previously, `try_fabric_redirect()` only fired on FIB lookup failure, but `bpf_fib_lookup` succeeded (WAN interface still UP on fw0) yet forwarding failed because the VIP/routes were removed.

### Solution: Per-RG Active State Tracking in BPF
- **New `rg_active` ARRAY map** (16 entries, key=u32, value=u8): tracks which RGs are locally active
- **New `rg_id` field** in `iface_zone_value` (renamed from `pad`): links interfaces to their RG
- **New `check_egress_rg_active()` helper**: looks up egress interface's RG in iface_zone_map, checks rg_active[rg_id]

### Three bugs fixed:
1. **RG check inside FIB gen check (root cause):** The RG-active check was nested inside the `fib_gen == fib_gen` cache check. When fib_gen was bumped during failover, the entire block was skipped — RG check never ran. Fix: check RG-active BEFORE fib_gen, using session's cached egress interface.

2. **VRRP resign re-election race:** `ResignRG()` sent priority-0 adverts and entered BACKUP, but the VRRP instance still had priority 200. The ~97ms masterDown timer fired before the debounced priority update (500ms), causing re-election at priority 200. Fix: `ResignRG()` now sets priority=0 BEFORE triggering resign. New `UpdateRGPriority()` immediately restores priority=200 on Primary transition.

3. **VRRP event overriding cluster state:** Brief VRRP MASTER flap during resign race caused `watchVRRPEvents` to call `UpdateRGActive(rg, true)`, overriding the cluster event's `UpdateRGActive(rg, false)`. Fix: in cluster mode, VRRP MASTER event only sets rg_active=true if cluster state agrees (`IsLocalPrimary(rgID)`).

### Files Modified
| File | Change |
|------|--------|
| `bpf/headers/xpf_common.h` | `iface_zone_value.pad` → `rg_id`, `MAX_REDUNDANCY_GROUPS 16` |
| `bpf/headers/xpf_maps.h` | New `rg_active` ARRAY map |
| `bpf/headers/xpf_helpers.h` | New `check_egress_rg_active()` helper |
| `bpf/xdp/xdp_zone.c` | RG check before FIB gen (v4+v6), FIB success path RG check |
| `pkg/dataplane/types.go` | `IfaceZoneValue.Pad` → `RGID` |
| `pkg/dataplane/dataplane.go` | `SetZone` + rgID, `UpdateRGActive` interface method |
| `pkg/dataplane/loader.go` | SetZone RGID field |
| `pkg/dataplane/loader_ebpf.go` | Register `rg_active` map |
| `pkg/dataplane/maps.go` | `UpdateRGActive()` + `BumpFIBGeneration()` impl |
| `pkg/dataplane/compiler.go` | Pass `RedundancyGroup` as rgID to `SetZone` |
| `pkg/daemon/daemon.go` | watchClusterEvents: immediate priority update; watchVRRPEvents: cluster-authoritative guard |
| `pkg/vrrp/manager.go` | ResignRG sets priority=0, new UpdateRGPriority() |
| `pkg/cluster/sync.go` | RG-active update on remote failover events |
| `dpdk_worker/shared_mem.h` | rg_active array, rg_id field |
| `dpdk_worker/main.c` | Forwarding check placeholder |
| `pkg/dataplane/dpdk/dpdk_cgo.go` | UpdateRGActive(), SetZone rgID |
| `pkg/dataplane/dpdk/dpdk_stub.go` | Stub methods |
| `test/incus/test-active-active.sh` | Tuned: -P2 streams, 90s duration, 8s initial wait |

### Test Results
- `make test`: all pass
- `make test-active-active`: 10/10 pass (iperf3 survives RG split + reunification at ~1.6 Gbps via fabric)
- `make test-failover`: 14/14 pass (single-active failover unaffected)
- `make test-connectivity`: 22/23 pass (1 pre-existing)

## Sprint AA-2: New Connections During Active/Active Split (`83c9333`)

### Problem
AA-1 solved existing connections during per-RG split, but NEW TCP/ICMP connections failed with "no route to host". Two interacting failures:

**Forward path (SYN: LAN→internet via fw0):** On fw0 (LAN active, WAN inactive), FIB returned NOT_FWDED (no default route) because FRR withdrew the default route when WAN VIP was removed (next-hop unreachable). Without a route, the packet was dropped instead of fabric-redirected. When fabric redirect did work (FIB failure), the peer's xdp_zone applied wrong security policy because it used fab0's zone ("control") instead of the original ingress zone ("lan").

**Return path (SYN-ACK: server→LAN via fw1):** On fw1 (WAN active, LAN inactive), return traffic for 10.0.60.102 hit the default route and escaped via WAN instead of being fabric-redirected to fw0, because the LAN connected route was gone.

### Solution: Three-Part Fix

**Part 1: Zone-encoded fabric redirect (BPF)**
- `try_fabric_redirect_with_zone()` helper encodes ingress zone in source MAC: `02:bf:72:fe:00:ZZ`
- MAC-based encoding (not VLAN) because Linux bridges strip 802.1Q into `skb->vlan_tci` before generic XDP
- Receiving node detects magic MAC prefix on fabric ingress, uses byte[5] as ingress zone
- Zone-encoded packets get `routing_table=254` (main table) and go through full pipeline
- Plain `FABRIC_FWD` packets (existing sessions) skip policy (peer already validated)

**Part 2: Route fixes for inactive RG subnets**
- `injectBlackholeRoutes(rgID)` on VRRP BACKUP: `blackhole <subnet> metric 4242` via netlink
- `removeBlackholeRoutes(rgID)` on VRRP MASTER: cleanup tracked routes
- FRR blackhole default route (`AD=250`): makes FIB return BLACKHOLE (not NOT_FWDED) when real default is withdrawn, triggering fabric redirect for new connections

**Part 3: BPF pipeline fixes**
- BLACKHOLE handler session guard: skip immediate fabric redirect when session exists — packet needs NAT reversal via conntrack→NAT→forward path first (pre-routing dnat_table rewrites meta but not packet headers)
- Two-pass FIB for sessionless FABRIC_FWD: first FIB in VRF (local delivery detection), second in main table (correct data-plane routing)
- xdp_forward FIB re-check: after NAT reversal in KERNEL_ROUTE path, detect BLACKHOLE and fabric-redirect with correctly rewritten headers
- `fabric_fwd_info.fib_ifindex`: non-VRF ifindex for zone-decoded FIB lookups (BPF_FIB_LOOKUP_TBID still honors l3mdev rules on VRF slaves)

### Key Discoveries
- **VRF routing table mismatch:** fab0 is in VRF mgmt (table 999). Sessionless FABRIC_FWD traffic used VRF table → FIB SUCCESS with wrong egress (management interface). Two-pass FIB: first in VRF (NOT_FWDED for local), then main table (254) for data-plane routing
- **SNAT reverse session key via pre-routing NAT:** `dnat_table` lookup at xdp_zone line 285-311 converts SNAT'd destination back to original client IP BEFORE session lookup. BLACKHOLE handler must NOT fabric-redirect before this conversion (packet headers still have SNAT'd addresses)
- **BPF_FIB_LOOKUP_TBID + VRF:** Even with explicit TBID, kernel honors l3mdev rules when input ifindex belongs to a VRF. Must use non-VRF ifindex for main table lookups

### Files Modified
| File | Change |
|------|--------|
| `bpf/headers/xpf_common.h` | `META_FLAG_FABRIC_FWD`, `FABRIC_ZONE_MAC_MAGIC` |
| `bpf/headers/xpf_helpers.h` | `try_fabric_redirect_with_zone()` helper |
| `bpf/headers/xpf_maps.h` | `fabric_fwd_info.fib_ifindex` field |
| `bpf/xdp/xdp_zone.c` | Zone-encoded MAC detection, FABRIC_FWD flag, session guard on routing_table override, RG check for new connections, BLACKHOLE session guard, two-pass FIB |
| `bpf/xdp/xdp_forward.c` | FIB re-check in KERNEL_ROUTE path (BLACKHOLE→fabric redirect) |
| `pkg/daemon/daemon.go` | Blackhole route injection/removal on VRRP transitions, fib_ifindex population |
| `pkg/dataplane/types.go` | `FabricFwdInfo.FIBIfindex` field |
| `pkg/frr/frr.go` | Cluster mode blackhole default route (AD=250) |
| `dpdk_worker/shared_mem.h` | `FABRIC_ZONE_MAC_MAGIC` constant |
| `dpdk_worker/zone.c` | Zone-encoded MAC detection placeholder |
| `test/incus/test-active-active.sh` | Phase 3b (TCP handshake) + 3c (ping) during split |

### Test Results
- `make test`: all pass
- `make test-connectivity`: 25/25 pass
- `make test-failover`: 14/14 pass
- `make test-active-active`: 14/14 pass (existing iperf3 + new TCP + new ICMP during split)

## Sprint AA-2b: Active/Active Failback Bug Fixes (`1b62df9`, `4bdbefa`)

### Problem 1: TCP stream death during active/active failback (`1b62df9`)
After RG1 failover→failback, 1 of 4 iperf3 streams permanently died (cwnd=1 MSS). Root cause: cluster event handler set `rg_active=true` ~30-60ms BEFORE VRRP MASTER event (which removes blackhole routes). During this window: packets bypass fabric redirect → SNAT applied → hit blackhole → fabric-redirect with SNAT'd headers → peer can't match synced session (original 5-tuple) → dropped.

**Fix:** In cluster event handler, only set `rg_active=true` if VRRP is already MASTER (`rethMasterState[rgID]`). If VRRP is BACKUP (failback case), defer to VRRP MASTER handler (fires after VIP added + blackhole removed).

### Problem 2: SNAT'd KERNEL_ROUTE leak on fabric peer (`4bdbefa`)
Rapid repeated failover cycles permanently killed 2+ iperf3 streams. During failback, ~30ms window where both nodes have `rg_active=false`. Fabric-forwarded packets hit anti-loop, fell through to `META_FLAG_KERNEL_ROUTE` instead of dropping. SNAT applied → kernel received SNAT'd packet in fabric VRF → RSTs/duplicates compound per cycle.

**Fix (BPF):** Drop `META_FLAG_FABRIC_FWD` packets instead of KERNEL_ROUTE fallback in xdp_zone.c (post-FIB RG check + BLACKHOLE handler) and xdp_forward.c (KERNEL_ROUTE XDP_PASS).
**Fix (Go):** Always `BumpFIBGeneration()` on cluster Primary transition, even when deferring rg_active to VRRP MASTER.

### Problem 3: Fabric transit traffic dropped — vrf-mgmt FIB mismatch (`4bdbefa`)
Peer NAT-reverses traffic and plain-fabric-redirects it for local delivery. Traffic arrives on fab0 (VRF mgmt). Without a session match, `routing_table=254` override doesn't apply → FIB uses vrf-mgmt table → UNREACHABLE. Additionally, TC conntrack has no session → TC_ACT_SHOT.

**Fix (BPF xdp_zone):** In BLACKHOLE/UNREACHABLE handler, after fabric redirect fails (anti-loop), check `META_FLAG_FABRIC_FWD` and re-FIB in main table (tbid=254) using `fabric_fwd_info.fib_ifindex` (non-VRF ifindex).
**Fix (BPF tc_conntrack):** Fabric transit bypass — packets from fabric peer skip TC conntrack and tail-call directly to `TC_PROG_FORWARD`.
**Fix (NO_NEIGH):** Zone-encoded redirect for new connections in NO_NEIGH handler preserves ingress zone for policy/SNAT on peer.

### Files Modified
| File | Change |
|------|--------|
| `bpf/xdp/xdp_zone.c` | BLACKHOLE session guard, fabric transit re-FIB, NO_NEIGH zone-encoded redirect, FABRIC_FWD drop instead of KERNEL_ROUTE |
| `bpf/xdp/xdp_forward.c` | FABRIC_FWD drop guard in KERNEL_ROUTE XDP_PASS path |
| `bpf/tc/tc_conntrack.c` | Fabric transit bypass to TC_PROG_FORWARD |
| `pkg/daemon/daemon.go` | Deferred rg_active, rethMasterState tracking, BumpFIBGeneration on Primary |

## Sprint VRRP-Hardening: IPv6 + Reliability Audit (2026-02-28)

### Summary
Code audit of VRRP/HA paths found 8 latent bugs — 1 HIGH (IPv6 split-brain), 5 MEDIUM, 2 LOW. All preventive fixes, none triggered in production. Focus areas: IPv6 VRRP correctness, daemon event handling, cluster monitor reliability.

### Fixes

1. **IPv6 tie-break in handleMasterRx (HIGH):** `.To4()` returned nil for IPv6 → `bytes.Compare(nil,nil)==0` → no tie-break → split-brain. Fixed: dual address-family comparison using `localIPv6`
2. **Non-RETH VRRP guard (MEDIUM):** Standalone VRRP (GroupID<100) produced negative RG IDs → phantom BPF entries. Fixed: `isRethVRID()` guard + `rethVRIDBase` constant
3. **IPv6 VRRP fallback receiver (MEDIUM):** Raw socket fallback was IPv4-only. Added `receiverIPv6()` goroutine + degradation warning
4. **Reconciliation coverage + startup (MEDIUM):** Only iterated `d.rgStates`; no immediate run. Fixed: scan 3 sources (rgStates + cluster groups + VRRP instances), immediate first reconciliation
5. **VRRP event drop logging (LOW):** Silent drops on full channel. Fixed: `slog.Warn` (suppressed during shutdown), buffer 64→256
6. **IPv6 advert checksum/Zone (MEDIUM):** Nil srcIP → bad checksum; Zone on multicast dst → EINVAL. Fixed: warn on nil resolve, removed Zone
7. **Monitor poll() data race (MEDIUM):** localStatuses written outside lock. Fixed: local slice + swap under lock
8. **Monitor netlink fd leak (MEDIUM):** New handle per poll cycle. Fixed: `cachedNlHandle` + `Stop()` close
9. **IPv6 IP monitoring (LOW):** Hardcoded udp4/ICMPv4. Fixed: detect AF, `icmpDialer(network string)`

### Key Patterns Added
- `isRethVRID(vrid int) bool` — guard for RETH vs standalone VRRP (GroupID >= 100)
- `rethVRIDBase = 100` — constant replacing magic number
- VRRP event channel buffer: 64→256 (rapid failover with multiple RETHs)
- IPv6 VRRP destination: don't set Zone when socket has `IPV6_MULTICAST_IF`
- Monitor `cachedNlHandle` pattern: create on first use, close in `Stop()`
- `pollInterfaceMonitors()` returns slice (no shared mutable field)

### Files Modified
| File | Change |
|------|--------|
| `pkg/vrrp/instance.go` | IPv6 tie-break, receiverIPv6(), emitEvent warn, sendPacketIPv6 nil guard + Zone removal |
| `pkg/vrrp/manager.go` | Event channel buffer 64→256 |
| `pkg/vrrp/vrrp_test.go` | 9 new tests (IPv6 tie-break, receiverIPv6, emitEvent, sendPacketIPv6) |
| `pkg/daemon/daemon.go` | isRethVRID guard, rethVRIDBase, reconciliation 3-source scan, immediate first reconcile |
| `pkg/daemon/per_rg_test.go` | 4 new tests (isRethVRID, non-RETH pollution, reconcile cluster/VRRP discovery) |
| `pkg/cluster/monitor.go` | poll() race fix, cachedNlHandle, IPv6 ICMP probes, icmpDialer(network) |
| `pkg/cluster/monitor_test.go` | 4 new tests (IPv6 monitoring, IPv4 network, invalid addr, concurrent race) |

### Test Results
- 817 lines added across 7 files (no files deleted)
- `go build ./...`: pass
- `go test ./pkg/vrrp/... -count=1`: pass
- `go test ./pkg/daemon/... -count=1`: pass
- `go test ./pkg/cluster/... -count=1`: pass

## Sprint SNAT-Interface: Egress IP Selection Fix (2026-02-28)

### Summary
SNAT `interface` mode was broken on RETH interfaces with multiple VLAN sub-interfaces. The compiler built a single NAT pool from all RETH unit addresses, and BPF allocated from it blindly without considering the actual egress interface. This caused packets to be SNAT'd with the wrong VLAN sub-interface IP (e.g., using VLAN 50's IP for traffic egressing VLAN 100).

### Root Cause
The interface-mode SNAT compiler picked a single interface from the to-zone and collected ALL RETH unit addresses into one pool. At runtime, `nat_pool_alloc_v4()` selected from the pool without considering `meta->fwd_ifindex` or `meta->egress_vlan_id`. With multiple VLAN sub-interfaces (e.g., wan0.50 at 172.16.50.6 and wan0.100 at 172.16.100.6), the wrong IP was used.

### Fix
New `snat_egress_ips` BPF HASH map keyed by `(ifindex, vlan_id)` maps to per-interface SNAT IP. The compiler iterates ALL interfaces in the to-zone and populates the map. New BPF functions `nat_pool_alloc_iface_v4/v6()` look up the egress IP from `meta->fwd_ifindex` + `meta->egress_vlan_id`, falling back to pool-based allocation on miss.

Secondary fix: NAT64 source pool auto-assignment. Named pools defined in source NAT config but only referenced from the nat64 section were never assigned pool IDs, causing compile failure and preventing XDP attachment.

### Key Patterns
- **BPF function arg limit:** BPF functions max 5 args. Initial implementation passed 6 (including ifindex and vlan_id separately). Fixed by passing `struct pkt_meta *meta` pointer instead
- **`snat_egress_ips` map:** HASH(256), key `snat_egress_key { __u32 ifindex; __u16 vlan_id; }`, value `snat_egress_value { __be32 ip4; struct in6_addr ip6; }`
- **`interface_mode` flag:** Added to `nat_pool_config` struct — BPF checks this to dispatch to `nat_pool_alloc_iface_v4/v6()` instead of regular pool allocation
- **NAT64 pool auto-assignment:** `NextPoolID` tracking ensures pools referenced only by NAT64 get IDs

### Files Modified
| File | Change |
|------|--------|
| `bpf/headers/xpf_common.h` | Add `interface_mode` to nat_pool_config, snat_egress_key/value structs |
| `bpf/headers/xpf_maps.h` | Add `snat_egress_ips` HASH map |
| `bpf/xdp/xdp_policy.c` | Add `nat_pool_alloc_iface_v4/v6()`, update 3 SNAT call sites |
| `pkg/dataplane/types.go` | Rename Pad2→InterfaceMode, add SNATEgressKey/Value Go types |
| `pkg/dataplane/dataplane.go` | Add SetSNATEgressIP/ClearSNATEgressIPs to DataPlane interface |
| `pkg/dataplane/maps.go` | Implement eBPF map accessors for snat_egress_ips |
| `pkg/dataplane/loader_ebpf.go` | Register snat_egress_ips map + replacements |
| `pkg/dataplane/compiler.go` | Iterate all to-zone interfaces, populate egress map, set InterfaceMode=1, NAT64 pool auto-assign |
| `pkg/dataplane/dpdk/dpdk_cgo.go` | DPDK stub for SetSNATEgressIP/ClearSNATEgressIPs |
| `pkg/dataplane/dpdk/dpdk_stub.go` | DPDK stub for SetSNATEgressIP/ClearSNATEgressIPs |

### Test Results
- 555 lines added, 30 deleted across 38 files (includes bpf2go regenerated bindings)
- `make test`: all pass
- `make test-failover`: 14/14 pass, 8.51 Gbps throughput

## Sprint ha-fixes-2: HA Lifecycle & Reconciliation Hardening (2026-03-01)

5 bugs fixed addressing HA daemon lifecycle, reconciliation, and runtime reconfiguration gaps.

### Fix #84: VRRP watcher daemon context (FIXED)
- `watchVRRPEvents` used `context.Background()` — outlived daemon shutdown
- Changed to daemon `ctx` + shutdown waitgroup; VRRP manager closes events channel on `Stop()`
- **Files:** `pkg/daemon/daemon.go`, `pkg/vrrp/manager.go`

### Fix #92: Stale peer RG entries in heartbeat (FIXED)
- `handlePeerHeartbeat()` never pruned missing RGs — stale entries persisted forever
- Rebuild `peerGroups` from scratch each heartbeat (authoritative map replacement)
- **Files:** `pkg/cluster/cluster.go`

### Fix #86 + #93: reconcileRGState repairs VRRP control + RA/DHCP services (FIXED)
- `reconcileRGState()` only repaired `rg_active` + blackhole routes, not VRRP posture or per-RG services
- Extended to: (1) delay-based VRRP posture correction (10s sustained mismatch before acting), resign when cluster says Secondary but VRRP is MASTER; (2) apply/clear per-RG RA/DHCP services based on active state
- **Critical fix (`8b288f4`):** Posture reconciliation must use `UpdateRGPriority()` NOT `ForceRGMaster()` — ForceRGMaster overrides `preempt=false`, causing the reconcile loop to preempt VRRP on returning nodes after reboot. Only `watchClusterEvents` Secondary→Primary transition may call ForceRGMaster
- Added no-VRRP-instances guard to `CheckVRRPPosture()` — prevents infinite log spam when member interface missing after reboot
- **Files:** `pkg/daemon/daemon.go` (reconcileRGState), `pkg/daemon/rg_state.go` (CheckVRRPPosture, vrrpPostureDelay)

### Fix #87: HA endpoints runtime reconfiguration (FIXED)
- `startClusterComms()` was one-shot at boot — config changes to control/fabric settings were ignored
- Config apply path now detects HA transport config changes, cancels existing comms context, restarts with new settings
- **Files:** `pkg/daemon/daemon.go`

### Key Patterns Learned
- **Reconciliation as safety net:** Event-driven state machines MUST have periodic reconciliation to repair drift from dropped events
- **Reconciliation must not override design intent:** Posture reconciliation should re-send priority updates, NOT force preemption — ForceRGMaster overrides `preempt=false` config, causing unintended VRRP takeover after reboot. Only explicit cluster operations (failover reset) should call ForceRGMaster
- **Authoritative state rebuild:** When receiving peer heartbeats, rebuild state from scratch rather than incremental update to prevent stale entries
- **Context lifecycle:** Goroutines watching daemon events MUST use daemon context and be tracked in shutdown waitgroup
- **Runtime reconfigurability:** One-shot initialization of cluster comms is insufficient — must detect config changes and restart endpoints

## Sprint CC-10: HA Hardening #98-#102

### Fix #98: Neighbor warmup Junos name resolution (FIXED `3425fee`)
- `resolveNeighbors()` → `addByName()` → `LinkByName()` failed silently on Junos names
- Added `resolveJunosIfName()`: `cfg.ResolveReth()` + `config.LinuxIfName()`
- **Files:** `pkg/daemon/daemon.go`

### Fix #99: Sync protocol full-write loop (FIXED `3b63d6b`)
- TCP `Write()` can short-write under backpressure → truncated sync frames
- Added `writeFull()` helper that loops until all bytes sent
- **Files:** `pkg/cluster/sync.go`

### Fix #100: Heartbeat buffer + monitor cap (FIXED `85a79e4`)
- `maxHeartbeatSize` 512→1472 (safe UDP MTU), marshal caps at limit (truncates monitors, preserves RGs), unmarshal handles truncation gracefully
- **Files:** `pkg/cluster/heartbeat.go`

### Fix #101: Context-aware posture delay (FIXED `d12694a`)
- Startup delay 10s (first 30s), steady-state 2s. Added `startedAt` field to `rgStateMachine`
- Reduces real mismatch correction from 10-12s to 2-4s
- **Files:** `pkg/daemon/rg_state.go`

### Fix #102: BPF watchdog fail-closed (FIXED `00de701`)
- `ha_watchdog` BPF ARRAY map, Go writes every 500ms, BPF checks freshness in `check_egress_rg_active()` — >2s stale = inactive
- Ensures forwarding stops within bounded window after SIGKILL/panic
- **Files:** `bpf/headers/xpf_maps.h`, `bpf/headers/xpf_helpers.h`, `pkg/dataplane/maps.go`, `pkg/daemon/daemon.go`

### Fix #103: Per-RG readiness gate for startup takeover (FIXED `91a57cf`)
- Per-RG readiness contract: interfaces exist+up AND VRRP instances running
- Election blocks promotion until readiness sustained for `takeover-hold-time` (**default 0** — shipped at 3s in `91a57cf`, changed to 0 in the bodyless `cd4dbe9`)
- Monitor's `RGInterfaceReady()` treats missing interfaces as not-ready (was silently skipped)
- VRRP manager's `RGVRRPReady()` checks per-RG instance existence
- Daemon reconcile loop wires readiness into cluster manager
- Already-primary nodes never demoted by readiness gate
- Status display shows readiness state, reasons, and (when a hold is
  configured) the remaining takeover hold
- NOT covered by this fix, see #103 / #110: session-sync readiness is not part
  of the takeover gate, and `electSingleNode` deliberately BYPASSES the gate
  when the peer is not alive
- **Files:** `pkg/cluster/cluster.go`, `pkg/cluster/election.go`, `pkg/cluster/monitor.go`, `pkg/vrrp/manager.go`, `pkg/daemon/daemon.go`, `pkg/config/`

## Issue #104: HA Same-L2 Strict Single-Owner VIP Mode

### Problem
In same-L2 HA deployments (both nodes on same broadcast domain), VRRP failover creates a window where **both** nodes send GARP/NA for the same VIPs. The default activation rule `rg_active = clusterPri || anyVrrpMaster` means the cluster primary immediately activates when heartbeat elects it, even before VRRP state settles. This causes:
1. **Duplicate GARP/NA storms** — both nodes announce ownership of VIPs simultaneously
2. **ARP table thrashing** on upstream switches/routers
3. **Brief dual-active window** where both nodes forward traffic for the same VIPs

### Solution: `strict-vip-ownership` per-RG knob

**Config syntax:**
```
set chassis cluster redundancy-group 1 strict-vip-ownership
```

**Behavioral changes when enabled:**
1. **VRRP-only activation** — `rg_active = anyVrrpMaster` (removes `clusterPri ||` from activation rule). Only the VRRP MASTER node activates for that RG, eliminating the dual-active window
2. **GARP suppression on secondary** — `SetGARPSuppression(rgID, !isPrimary)` toggles GARP/NA suppression based on cluster role. Secondary nodes never send GARP even if they briefly become VRRP MASTER during transition
3. **GARP epoch dedup** — `garpEpoch/lastGARPEpoch` atomic counters prevent duplicate GARP bursts from `ReconcileVIPs()` calls within the same BACKUP→MASTER transition
4. **500ms GARP dampening** — `lastGARPTime` atomic Int64 tracks last send; skips if <500ms elapsed. Prevents storms during rapid VRRP flaps

### Implementation (4 commits)

#### Part 1/4: Config knob (`05f5208`)
- `StrictVIPOwnership bool` field in `RedundancyGroup` config type
- Parser: `strict-vip-ownership` keyword in chassis cluster redundancy-group stanza
- **Files:** `pkg/config/types.go`, `pkg/config/compiler.go`

#### Part 2/4: GARP suppression and epoch tracking (`68d5636`)
- `vrrpInstance`: `suppressGARP atomic.Bool`, `garpEpoch atomic.Uint64`, `lastGARPEpoch atomic.Uint64`
- `becomeMaster()`: increments `garpEpoch`, checks `suppressGARP` before starting GARP goroutine
- `sendGARP()`: epoch dedup — skips if `lastGARPEpoch == garpEpoch`
- `ReconcileVIPs()`: respects `suppressGARP` flag
- `Manager.SetGARPSuppression(rgID, suppress)`: toggles suppression for all instances in an RG
- **Files:** `pkg/vrrp/instance.go`, `pkg/vrrp/manager.go`

#### Part 3/4: Daemon activation wiring (`ab6b272`)
- `rgStateMachine`: `strictVIPOwnership bool` field with `SetStrictVIPOwnership()`/`IsStrictVIPOwnership()` accessors
- `reconcileLocked()`: in strict mode, `desired = anyMasterLocked()` (VRRP-only); default: `desired = clusterPri || anyMasterLocked()`
- `startClusterComms()`: propagates `StrictVIPOwnership` from config to RG state machines
- `watchClusterEvents()`: toggles GARP suppression via `vrrpMgr.SetGARPSuppression(ev.GroupID, !isPrimary)` when strict mode enabled
- **Files:** `pkg/daemon/daemon.go`, `pkg/daemon/rg_state.go`

#### Part 4/4: GARP dampening (`a2e826b`)
- `vrrpInstance`: `lastGARPTime atomic.Int64` (Unix nanos)
- `sendGARP()`: checks `time.Since(lastGARPTime) < 500ms` → skip
- Stored after successful GARP burst completion
- Two-layer protection: epoch (same transition) + dampening (across transitions)
- **Files:** `pkg/vrrp/instance.go`

#### Tests (`3f25d1b`)
- Unit tests for strict-vip-ownership: config parsing, rg_state machine strict mode, GARP suppression manager method, epoch dedup, dampening
- **Files:** `pkg/config/compiler_test.go`, `pkg/daemon/rg_state_test.go`, `pkg/vrrp/vrrp_test.go`

### Key Design Decisions
- **Per-RG granularity** — strict mode is per-redundancy-group, not global. Different RGs can have different activation semantics
- **Atomic fields for lockless hot path** — `suppressGARP`, `garpEpoch`, `lastGARPTime` are all atomics, keeping the VRRP fast path lock-free
- **Epoch + dampening = two-layer dedup** — epoch handles reconciliation-triggered duplicates (same transition), dampening handles rapid flap scenarios (different transitions)
- **Suppression toggled by cluster role, not VRRP state** — the cluster event handler (heartbeat-derived) controls suppression, while VRRP controls activation. This decouples the two state machines cleanly

## Sprint Infra: Interface Naming Refactor + DNS + Fabric Overlay (2026-03-05..06)

### Refactor: Move interface naming into xpfd daemon (`e481325`)

Ported PCI enumeration and vSRX-style naming (fxp0, em0, ge-{FPC}-0-{PORT}) from the external `xpf-link-setup` bash script into the daemon itself (`pkg/daemon/linksetup.go`). The daemon now calls `enumerateAndRenameInterfaces()` early in `Run()`, before routing/networkd managers and BPF load. This eliminates cascading rename conflicts, DHCP bootstrap breakage, and duplicate interface management logic.

**Key changes:**
- `linksetup.go`: 318-line Go implementation of PCI enumeration, sorting by bus address, vSRX name assignment
- Fabric member renames (ge-X-0-Y → fab0/fab1) remain config-driven in `applyConfig`
- Standalone: no node-id → fxp0 + ge-0-0-X (no em0); Cluster: node-id 0/1 → fxp0 + em0 + ge-{0,7}-0-X
- Test env scripts simplified — removed ~400 lines of bash interface management

**Files:** `pkg/daemon/linksetup.go` (new), `pkg/daemon/daemon.go`, `pkg/config/compiler.go`, `pkg/config/types.go`, `pkg/config/parser_test.go`, `pkg/dataplane/compiler.go`, `pkg/networkd/networkd.go`, `pkg/networkd/networkd_test.go`, `test/incus/setup.sh`, `test/incus/cluster-setup.sh`, `test/incus/xpf-test.conf`

### Refactor: systemd-resolved DNS drop-in (`11cdf8a`)

Replaced direct `/etc/resolv.conf` writes with `/etc/systemd/resolved.conf.d/xpf.conf` drop-in + `systemctl restart systemd-resolved`. Avoids conflict with systemd-resolved management of resolv.conf.

**Files:** `pkg/daemon/daemon.go`

### Feat: Fabric IPVLAN overlay + single-fabric-per-node (`97c0424`)

Replaced fabric interface rename (ge-0-0-0 → fab0) with IPVLAN L2 overlay. Physical member keeps its ge-X-0-Y name for XDP/TC attachment; fab0/fab1 are IPVLAN interfaces for IP addressing and session sync. This avoids link down/up cycling during rename and preserves PCI identity.

**Key design:**
- Single fabric per node: fab0 on node0 (ge-0-0-0), fab1 on node1 (ge-7-0-0)
- Auto-detect picks local fabric only (not both), fixing blank FabricPeerAddress on node1
- Cluster NIC layout simplified: removed xpf-fabric1 network (single fabric link)
- IPVLAN L2 mode = same broadcast domain as parent, no separate routing needed

**Files:** `pkg/daemon/daemon.go`, `pkg/config/compiler.go`, `pkg/dataplane/compiler.go`, `test/incus/cluster-setup.sh`, test scripts

**Tested:** make test (all pass), make test-failover (14/14 pass, 7.49 Gbps)

### Fix: Embedded ICMP fabric redirect after NAT rewrite (`7c8f243`)

In split-RG cluster, ICMP Time Exceeded from transit routers arrives on the WAN node but must reach the LAN host on the peer node. `handle_embedded_icmp_v4/v6()` was calling `try_fabric_redirect()` BEFORE NAT rewrite — the peer received packets with SNAT'd embedded headers and couldn't match them to any session.

**Fix:** When FIB fails (UNREACHABLE/BLACKHOLE) for the original client, set `META_FLAG_KERNEL_ROUTE` instead of immediate fabric redirect. `xdp_forward`'s KERNEL_ROUTE path re-FIBs using post-NAT packet headers (outer dst rewritten to original client IP), detects UNREACHABLE, and fabric-redirects with correct headers. Also changed `meta_flags` assignment from `=` to `|=` to preserve KERNEL_ROUTE flag when setting `META_FLAG_EMBEDDED_ICMP`.

**Files:** `bpf/xdp/xdp_conntrack.c`
**Tested:** split-RG MTR shows all intermediate hops (was 100% loss), make test-failover 14/14 pass at 7.86 Gbps

### Fix: Embedded ICMP handler NOT_FWDED local delivery (`7158942`)

The embedded ICMP handler treated `NOT_FWDED` (BPF_FIB_LKUP_RET_NOT_FWDED) as an error, but this return code means the destination is local (the firewall itself). For ICMP TE/Destination Unreachable containing packets originally destined for the firewall, this is the correct behavior — deliver locally.

**Files:** `bpf/xdp/xdp_conntrack.c`

## Sprint CC-11: Fabric Health & Reliability (#121-#126) (2026-03-06)

### Summary
Six improvements to fabric forwarding reliability in chassis cluster HA deployments. Focus: stale fabric_fwd entry clearing when paths die, oper-state validation before programming, event-driven fabric refresh via netlink, session sync connection stability with dual fabrics, gRPC/monitor failover across dual fabric addresses, and DPDK fabric redirect limitation documentation.

### Fix #121+#122: Clear stale fabric_fwd entries + oper-state check (FIXED `e02ceeb`)

**Problem (#121):** When a fabric link or neighbor fails, the `fabric_fwd` BPF map retains stale entries (MAC, ifindex, peer IP). BPF `try_fabric_redirect()` uses these entries to redirect packets to a dead path → silent packet drops until the 30s refresh ticker runs.

**Problem (#122):** `populateFabricFwd()` programs `fabric_fwd` entries without checking the fabric interface's operational state. If the interface exists but is operationally DOWN (cable unplugged, peer VM stopped), BPF redirects to a non-functional path.

**Fix (#121):** When fabric link goes DOWN or neighbor entry disappears, write zeroed `FabricFwdInfo` to the BPF map. This causes `try_fabric_redirect()` to fail the ifindex check (`ff->ifindex == 0`) and skip the dead path immediately.

**Fix (#122):** Before programming `fabric_fwd`, check `link.Attrs().OperState` — reject non-UP interfaces. Combined with #121's zeroing, this ensures only healthy paths are ever programmed.

**Key pattern:** Zeroing a BPF map entry is idempotent and cheaper than deleting+re-adding. BPF code already handles zero ifindex as "no entry" — no C changes needed.

### Fix #123: Dual-fabric session sync connection flapping (FIXED `1358477`)

**Problem:** With dual fabrics (fab0 + fab1), the session sync `connectLoop()` rotates between fabric addresses on failure. When one fabric is healthy and the other is down, this causes unnecessary disconnect/reconnect cycles on the working connection — each rotation attempt tears down the existing connection before trying the next address.

**Fix:** Track per-fabric connection state (`fab0Connected`, `fab1Connected`). Prefer fab0 as primary connection. Only attempt secondary (fab1) when primary is down. Don't tear down a working connection to try the other address. On primary recovery, migrate back to fab0 (preferred path) gracefully.

**Key pattern:** Connection affinity with graceful migration — prefer one path but tolerate degraded operation on the backup. Avoid the "grass is greener" anti-pattern where a working connection is killed to try a potentially-better one.

### Fix #124: Event-driven fabric refresh via netlink (FIXED `e02ceeb`)

**Problem:** Fabric path health is only checked on a 30s ticker. When a fabric interface goes DOWN or a neighbor entry changes/disappears, up to 30s of stale forwarding occurs before the next refresh detects the failure.

**Fix:** Subscribe to netlink `LinkUpdate` and `NeighUpdate` channels via `netlink.LinkSubscribe()` and `netlink.NeighSubscribe()`. Filter for fabric interface names and peer IP addresses. On match, trigger immediate `fabric_fwd` refresh via `fabricRefreshCh` (non-blocking channel send). The 30s ticker remains as a safety net.

**Implementation:**
- `monitorFabricState(ctx)` goroutine subscribes to link + neighbor updates
- `triggerFabricRefresh()` non-blocking send to `fabricRefreshCh`
- `fabricIface`/`fabricIface1` and `fabricPeerIP`/`fabricPeerIP1` under `fabricMu` for filter matching
- Clean shutdown via context cancellation → `close(linkDone)` + `close(neighDone)`

**Files:** `pkg/daemon/daemon.go`

### Fix #125: gRPC/monitor dual-address failover (FIXED `e02ceeb`)

**Problem:** In dual-fabric clusters, the gRPC server listens on only one fabric address and the cluster monitor dials only one address. When that fabric path fails, gRPC connectivity and health monitoring are lost even though the other fabric is healthy.

**Fix:** gRPC server listens on both fabric addresses (fab0 + fab1). Monitor dial uses fab0→fab1 fallback — try primary first, fall back to secondary on connection failure or timeout.

### Fix #126: Mark DPDK fabric redirect as unsupported (`dc6f6bd`)

**Problem:** The DPDK dataplane programs fabric port IDs for inbound zone-encoded MAC detection but has no equivalent of the BPF `try_fabric_redirect()` and `try_fabric_redirect_with_zone()` helpers. Users enabling DPDK in HA clusters would get silent packet drops on fabric redirect paths.

**Fix:** Added `slog.Warn` calls in `UpdateFabricFwd()` and `UpdateFabricFwd1()` in DPDK CGo bridge. Clarified the limitation in `dpdk_worker/zone.c` comments. This makes the gap visible in logs rather than silently dropping.

**Files:** `dpdk_worker/zone.c`, `pkg/dataplane/dpdk/dpdk_cgo.go`

### Key Patterns from CC-11
- **Zeroed BPF map entry as tombstone:** Writing `FabricFwdInfo{}` (all zeros) is cheaper than delete+re-add. BPF already treats `ifindex==0` as "no entry" — no C-side changes needed
- **Event-driven + ticker safety net:** Netlink subscriptions for immediate reaction + 30s ticker as fallback. Never rely solely on events (can be lost) or solely on timers (too slow)
- **Connection affinity:** Prefer one path (fab0) but tolerate degraded on backup. Don't tear down working connections to try alternatives
- **Oper-state gating:** Always check `link.Attrs().OperState` before programming forwarding entries — interface existence alone is insufficient
- **IPVLAN L2 overlay for fabric:** Physical member keeps XDP-visible name; IPVLAN child gets fab0/fab1 for IP/sync. Avoids link down/up rename cycling

### Files Modified (Sprint CC-11)
| File | Change |
|------|--------|
| `pkg/daemon/daemon.go` | `monitorFabricState()`, `triggerFabricRefresh()`, fabric oper-state check, stale clearing, `fabricRefreshCh` |
| `dpdk_worker/zone.c` | DPDK fabric redirect limitation comments |
| `pkg/dataplane/dpdk/dpdk_cgo.go` | `slog.Warn` in `UpdateFabricFwd`/`UpdateFabricFwd1` |

### Test Results
- `dc6f6bd` (#126): committed, make test pass
- `1358477` (#123): committed — per-fabric session sync connections
- `e02ceeb` (#121, #122, #124, #125): committed — fabric health + gRPC dual-address failover
- All CC-11 fixes merged to master

---

## Sprint CC-12: IPVLAN Fabric Fixes (#127-#130, 2026-03-06)

Discovered during CC-11 validation: the IPVLAN overlay refactor (`97c0424`) introduced four correctness issues with fabric overlay lifecycle management.

### Context
The IPVLAN overlay design (`97c0424`) keeps physical fabric members visible to XDP/TC (ge-X-0-Y name) while creating IPVLAN L2 children (fab0/fab1) for IP addressing and sync transport. This split introduced gaps in address reconciliation, cleanup, neighbor probing, and compiler auto-detection.

### Fix #127: IPVLAN address reconciliation on restart

**Problem:** `ensureFabricIPVLAN()` returns early when the IPVLAN interface already exists (survives daemon restart), skipping IP address reconciliation. After restart, fab0/fab1 may lack addresses → fabric sync broken.

**Fix:** Remove early return — always check and reconcile addresses on existing IPVLAN interfaces. The function now creates-if-missing AND reconciles-if-existing.

**Key insight:** IPVLAN interfaces survive daemon restart but their addresses may be lost (networkd reload, link cycling). Must treat address config as idempotent.

**Files:** `pkg/daemon/daemon.go`

### Fix #128: Stale IPVLAN overlay cleanup

**Problem:** `CleanupFabricIPVLANs()` was defined but never called. Orphaned fab0/fab1 interfaces persist across config changes, potentially causing address conflicts or stale routes.

**Fix:** Wire `CleanupFabricIPVLANs()` into daemon cleanup and config-change paths. Remove stale overlays when fabric topology changes or daemon runs `xpfd cleanup`.

**Files:** `pkg/daemon/daemon.go`

### Fix #129: Neighbor probe on IPVLAN overlay, not parent

**Problem:** `probeFabricNeighbor()` sends ARP/NDP probe from the physical parent (ge-X-0-Y) which no longer holds the fabric IP address. Probe has wrong source IP → peer ignores → no ARP entry → `bpf_fib_lookup` returns NO_NEIGH → fabric forwarding broken.

**Fix:** Send neighbor probe from the IPVLAN child (fab0/fab1) where the fabric IP actually lives. Probe source IP matches the address, peer responds correctly, ARP entry populates.

**Key insight:** After IPVLAN refactor, physical parent is for XDP/TC attachment only. All IP-level operations (probes, binds, sync) must use the IPVLAN overlay.

**Files:** `pkg/daemon/daemon.go`

### Fix #130: Compiler dual-fabric auto-detection

**Problem:** Fabric auto-detection finds both fabric interfaces but collapses them into `FabricInterface` only. `Fabric1Interface` stays empty → node1 has no fabric forwarding path → unidirectional session sync, broken failover.

**Fix:** Auto-detect distinguishes fab0 vs fab1 based on interface naming or node assignment. Populate both `FabricInterface` and `Fabric1Interface` in compiled config.

**Key insight:** Single-fabric-per-node design means each node creates only its own overlay (fab0 on node0, fab1 on node1). Compiler must still know about BOTH fabrics for the BPF `fabric_fwd` map (dual lookup: try fab0 first, then fab1).

**Files:** `pkg/config/compiler.go`

### Key Patterns from CC-12
- **Idempotent overlay lifecycle:** IPVLAN create-or-reconcile, never assume current state
- **IP operations on overlay, not parent:** After IPVLAN split, all IP-level work (probes, binds, addresses) targets fab0/fab1. Physical parent is XDP/TC attachment only
- **Dual-fabric compiler awareness:** Both FabricInterface and Fabric1Interface must be populated even though each node only creates one overlay. BPF needs both for dual-lookup
- **Cleanup must be wired:** Defining a cleanup function is not enough — it must be called from all relevant lifecycle paths (config change, daemon cleanup, overlay rebuild)

---

## Sprint CC-13: HA Session Sync & Activation Fixes (#131-#134, 2026-03-06)

Four correctness issues in HA session sync and RG activation discovered during extended failover testing with long-lived sessions.

### Context
CC-11/CC-12 fixed fabric health and IPVLAN overlay issues. CC-13 addresses higher-level HA state machine bugs: session sync only at creation (stale sessions on failover), premature RG activation (partial forwarding), latched syncReady (skipped bulk sync on reconnect), and edge-triggered hold timer (missed preemption).

### Fix #131: Session sync refresh for established flows (FIXED `b35bb45`)

**Problem:** Session sync sweep only sends sessions at creation time. Long-lived established sessions (hours/days) are never re-synced. On failover, peer has stale `LastSeen` — GC may purge the session before the failover packet arrives, or TCP state is outdated.

**Fix:** Sweep includes `LastSeen`-based activity detection. Sessions with recent activity since last sweep cycle are re-synced to peer, keeping the peer's session table fresh.

**Key insight:** Session sync must be incremental AND continuous — not just "sync on create, delete on GC". Active sessions need periodic refresh to survive long intervals between failovers.

### Fix #132: RG activation requires all VRRP instances MASTER (FIXED `08c17e3`)

**Problem:** `rg_active` BPF map set to true on the FIRST VRRP instance reaching MASTER for an RG. If the RG has multiple VRRP instances (e.g., multiple RETH interfaces), some interfaces may still be BACKUP with blackhole routes when `rg_active=true` allows traffic through.

**Fix:** Track per-RG VRRP instance count and state. Only set `rg_active=true` and remove blackhole routes when ALL instances for the RG have reached MASTER. Single instance reaching MASTER increments a counter but doesn't trigger activation.

**Key insight:** RG activation is an all-or-nothing decision. Partial MASTER (some interfaces active, some blackholed) causes asymmetric forwarding failures.

### Fix #133: Reset syncReady on peer disconnect/reconnect (FIXED `f5b445e`)

**Problem:** `syncReady` is latched to `true` after the first successful bulk sync and never reset. When peer disconnects and reconnects (e.g., daemon restart, network partition recovery), bulk sync is skipped because `syncReady` is still true. Reconnected peer may have empty/stale session table.

**Fix:** Reset `syncReady` to `false` when all sync connections to peer are lost (total disconnect). Next reconnect triggers fresh bulk sync handshake, ensuring the peer has a complete session table.

**Key insight:** `syncReady` is a per-connection property, not a permanent system state. Each new peer connection must complete bulk sync before incremental sync is meaningful.

### Fix #134: Hold timer scheduled re-election wakeup (FIXED `f5b445e`)

**Problem:** Sync hold timer expiry sets a flag but doesn't schedule a re-election. VRRP priority update (preemption) only happens reactively when other events fire. If no events occur after hold expiry, the node stays BACKUP indefinitely despite having higher priority.

**Fix:** Use `time.AfterFunc` to schedule an explicit re-election evaluation at hold timer expiry. The callback calls `UpdateRGPriority()` which recalculates weight and updates VRRP priority, triggering preemption if appropriate.

**Key insight:** Hold timer expiry is a state transition that must be level-triggered (schedule action), not edge-triggered (set flag and hope someone checks it).

### Key Patterns from CC-13
- **Continuous sync, not just creation sync:** Session sync must refresh active sessions periodically, not just on initial creation. `LastSeen` comparison against last sweep timestamp identifies active sessions
- **All-or-nothing RG activation:** Never partially activate an RG — all VRRP instances must be MASTER before clearing blackholes and setting `rg_active=true`
- **Connection-scoped readiness:** `syncReady` must be reset on disconnect — it tracks the current connection's sync state, not a permanent system property
- **Level-triggered timers:** Hold timer expiry must schedule an action (`time.AfterFunc`), not just set a flag. Edge-triggered flags depend on other events to be observed

---

## Sprint CC-14: Fabric Monitor & Stats Fixes (#135-#137, 2026-03-06)

Three issues with fabric interface monitoring and statistics after the IPVLAN overlay refactor (CC-11/CC-12). The IPVLAN split moved IP/sync to overlay interfaces (fab0/fab1), but monitor commands and BPF TX counters still target the overlay instead of the physical parent.

### Context
After the IPVLAN overlay refactor (`97c0424`, CC-11/CC-12), the fabric topology is:
- Physical parent: `ge-X-0-Y` — carries wire-level traffic, has XDP/TC attached
- IPVLAN overlay: `fab0`/`fab1` — L2 child for IP addresses, sync connections, gRPC

Monitor commands (`monitor interface`, `monitor traffic interface`) and BPF TX counters need wire-level stats from the physical parent, not the overlay.

### Fix #135: monitor interface fab0/fab1 shows IPVLAN overlay stats (FIXED `6fd6124`)

**Problem:** `monitor interface fab0` and `monitor interface fab1` display stats from the IPVLAN overlay interface. These show only local IP traffic (sync, gRPC), missing all XDP/TC redirected traffic that traverses the physical parent.

**Fix:** When the monitored interface is a fabric overlay (fab0/fab1), resolve to the physical parent interface for stats collection. The overlay→parent mapping comes from the IPVLAN relationship.

**Key insight:** IPVLAN children see only their own traffic. Wire-level counters live on the physical parent where XDP/TC programs are attached.

### Fix #136: monitor traffic interface fab0/fab1 tcpdump captures overlay (FIXED `6fd6124`)

**Problem:** `monitor traffic interface fab0` captures packets on the IPVLAN overlay, which only shows sync/gRPC traffic. Wire-level fabric traffic (redirected packets) flows through the physical parent and is invisible on the overlay.

**Fix:** Resolve fabric overlay name to physical parent before starting tcpdump capture. Same parent resolution as #135.

### Fix #137: try_fabric_redirect never calls inc_iface_tx (FIXED `6fd6124`)

**Problem:** `try_fabric_redirect()` in xdp_zone.c uses `bpf_redirect_map` to send packets to the fabric peer, but never increments the per-interface TX counter (`inc_iface_tx`). Fabric TX traffic is undercounted in `show interfaces statistics` and `monitor interface`.

**Fix:** Add `inc_iface_tx(meta, fabric_ifindex)` call before `bpf_redirect_map` return in `try_fabric_redirect()`.

**Key insight:** Every `bpf_redirect_map` exit path must have a corresponding `inc_iface_tx` call, or TX counters diverge from actual forwarded traffic.

### Key Patterns from CC-14
- **IPVLAN overlay vs physical parent:** After IPVLAN split, monitor/stats must target the physical parent for wire-level counters. Overlay only sees its own IP traffic
- **Consistent counter instrumentation:** Every BPF redirect exit path (XDP_REDIRECT via `bpf_redirect_map`) needs `inc_iface_tx` — fabric redirect was missing this
- **Parent resolution pattern:** Fabric overlay→parent mapping should be centralized for reuse by monitor commands, stats, and any future wire-level operations

---

## Sprint CC-15: Fabric Observability (#138-#139, 2026-03-06)

Two issues with fabric redirect observability. XDP-redirected packets bypass the kernel network stack, making tcpdump unreliable for fabric traffic. Additionally, per-link redirect counters are needed to distinguish fab0 vs fab1 traffic volumes and per-zone redirect breakdowns.

### Context
After the IPVLAN overlay refactor (CC-11/CC-12) and monitor fixes (CC-14), fabric redirect traffic is correctly counted at the aggregate level via `inc_iface_tx`. However:
1. `tcpdump` on fabric interfaces (physical parent or overlay) cannot reliably capture XDP-redirected packets — XDP processes packets before `sk_buff` allocation, so `AF_PACKET`-based tools miss them
2. There are no per-link (fab0 vs fab1) or per-zone redirect counters to diagnose asymmetric forwarding or identify which zones generate fabric redirect traffic

### Fix #138: tcpdump unreliable for XDP fabric redirects — document + alternative telemetry (IN PROGRESS)

**Problem:** `monitor traffic interface <fabric>` uses tcpdump (AF_PACKET), which cannot capture XDP-redirected packets. XDP processes packets before `sk_buff` creation, so AF_PACKET never sees them. Users relying on tcpdump for fabric traffic debugging get incomplete or empty captures.

**Fix:** Add CLI warning when `monitor traffic interface` targets a fabric interface, explaining that XDP-redirected traffic is not visible to tcpdump. Point users to BPF counters (`show interfaces statistics`, `show security flow statistics`) and the new per-link redirect counters (#139) as alternative telemetry.

**Key insight:** XDP and tcpdump are fundamentally incompatible for the same traffic — XDP acts before the kernel networking stack. This is a platform limitation, not a bug. The right approach is clear documentation + alternative observability paths.

### Fix #139: Per-link fabric redirect counters in BPF + CLI exposure (IN PROGRESS)

**Problem:** Fabric redirect traffic is counted as a single aggregate TX counter per interface. No way to distinguish:
- How much traffic is redirected to fab0 vs fab1
- Which zones generate fabric redirect traffic
- Whether redirects are symmetric or asymmetric between nodes

**Fix:** Add per-link redirect counters in BPF (fab0/fab1 differentiated, zone-encoded) and expose them through CLI commands (`show chassis cluster statistics` or similar). This provides the granular fabric telemetry that tcpdump cannot offer.

**Key insight:** With XDP bypassing AF_PACKET, BPF-native counters are the only reliable source of fabric redirect telemetry. Per-link + per-zone granularity enables diagnosis of asymmetric forwarding and zone-specific failover patterns.

### Key Patterns from CC-15
- **XDP vs AF_PACKET incompatibility:** XDP processes packets before `sk_buff` allocation — tcpdump/AF_PACKET cannot capture XDP-redirected traffic. This is a fundamental platform constraint, not a bug
- **BPF-native telemetry:** When XDP bypasses kernel networking, BPF maps are the only reliable counters. Per-link and per-zone granularity replaces what tcpdump would have provided
- **Document limitations prominently:** When a tool (tcpdump) silently fails for a specific traffic path, the CLI should warn users proactively rather than letting them discover empty captures

## 2026-03-31: Bulk Issue Resolution + Userspace HA Failover Fix

### Issue Sweep (PR #299)
Closed 21 of 22 open issues in a single session. 4 parallel teams:
- **HA transition guards (#283, #284, #285):** `pendingRGTransitions` per-RG map with defer cleanup, promotion pre-switches to eBPF pipeline
- **Demotion cleanup (#297, #298):** Synchronous alias map deletion from shared_nat/forward_wire sessions, `clear_ha_demotion` on PrepareRGDemotion failure
- **Userspace fixes (#286, #288, #289, #290, #291):** Session refresh pre-filter (reverted in review — cross-RG re-resolution needs full table), static neighbor retry, SNAT ICMP reverse key, XDP shim interface-NAT redirect + counter
- **API scalability (#275):** Cursor-based GetSessions pagination with page_token/page_size, no_enrich flag
- **XDP shim stack fix (#290/#291):** Removed redundant `dst_v6` from `ParsedPacket` (-16 bytes) to fit interface-NAT changes within 512-byte BPF limit

### CC-20: Userspace ctrl enable flushes synced BPF conntrack (FIXED `1a2b0a25`)
**The smoking gun for userspace HA failover session death.** When ctrl transitions disabled→enabled on the new owner, `applyHelperStatusLocked()` flushed ALL BPF conntrack entries including 382 synced sessions from the peer. Fix: track `ctrlDisabledAt` timestamp, only flush sessions created after that point.

**Remaining HA issues identified in investigation docs:**
- (H) Public-side LocalDelivery materialization from shared_promote path
- (F) Fabric transit throughput ceiling for redirected established flows
- Split-RG crash leaves `session sync not ready` stuck
