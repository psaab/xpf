# xpf Project Memory

## Project Overview
- **Goal:** eBPF-based firewall cloning Juniper vSRX capabilities with native Junos configuration syntax
- **Stack:** Go userspace (cilium/ebpf) + C eBPF programs (XDP ingress + TC egress)
- **Architecture plan:** `/home/ps/.claude/plans/glistening-hugging-music.md`
- **Detailed phase notes:** `phases.md`
- **Bug tracker:** `bugs.md`
- **Future optimizations:** `optimizations.md`
- **Sync protocol reference:** `sync-protocol.md`
- **Perf profiling guide:** `profiling.md`

## Build & Deployment
- `make generate` then `make build` for full build (bpf2go + Go binary)
- `make build-ctl` builds remote CLI client (`cli` binary)
- `make proto` regenerates protobuf Go code (needs `PATH=$PATH:$HOME/go/bin`)
- All 14 BPF programs pass verifier on kernel 6.18.9 (9 XDP + 5 TC)
- **Known:** xdp_zone fails verifier on kernel 6.12 (NAT64 loop complexity)
- 880+ tests pass (`make test`) across 30 packages; `make test-deploy` builds, pushes, installs unit, starts
- **ALWAYS deploy to ALL VMs:** `make test-deploy` (xpf-fw) AND `make cluster-deploy` (xpf-fw0 + xpf-fw1)

## Architecture

### BPF Pipeline (Tail Calls)
```
XDP Ingress: main -> screen -> zone(+pre-routing) -> conntrack -> policy -> nat -> nat64 -> forward
TC Egress:   main -> screen_egress -> conntrack -> nat -> forward
```
- Per-CPU array scratch map passes metadata between stages
- Dual session entries (forward + reverse) in HASH map
- NAT uses "meta as desired state" pattern

### Config System
- Three-phase compilation: Junos AST -> typed Go structs -> eBPF map entries
- Candidate/active config with commit model (up to 50 rollback slots)
- Config validation: cross-reference checks for zones, addresses, apps, screens
- `load override`/`load merge` for bulk config import
- `show | display set` for flat set export (FormatSet())
- **${node} variable expansion:** `ExpandGroupsWithVars()` resolves `${node}` in apply-groups references
  - `CompileConfigForNode(tree, nodeID)` — single config for both HA nodes
  - Cluster node ID from `/etc/xpf/node-id` file (file absent = standalone)
  - Configstore `compileTree()` dispatches to correct compiler based on nodeID

### Interface Management (networkd)
- **xpfd manages ALL interfaces** — renames, addresses, DHCP, and brings down unconfigured ones
- `.link` files: MAC→name rename (e.g. enp6s0→ge-0-0-0), prefix `10-xpf-`; RETH members use `OriginalName=` (PCI name) instead of `MACAddress=` for stable boot matching
- `.network` files: addresses, RA disable, VLAN parent, ActivationPolicy=always-down for unmanaged
- Unmanaged interfaces: brought down immediately + ActivationPolicy=always-down for persistence
- DHCP interfaces: daemon's DHCP client manages addresses; address reconciliation skipped
- VRF devices and tunnel interfaces excluded from unmanaged detection (`daemonOwned` map)
- **Boot-time naming:** `enumerateAndRenameInterfaces()` in `pkg/daemon/linksetup.go` runs at daemon start, assigns vSRX names (fxp0, em0, ge-X-0-Y) based on PCI bus order and `/etc/xpf/node-id`
- **Standalone:** no node-id file → fxp0 + ge-0-0-X (no em0). **Cluster:** node-id 0/1 → fxp0 + em0 + ge-{0,7}-0-X

### APIs & CLIs
- **gRPC:** 127.0.0.1:50051 (config, sessions, stats, routes, IPsec, DHCP)
- **HTTP REST:** 127.0.0.1:8080 (health, Prometheus, config, full gRPC parity)
- **Local CLI:** `xpfd` in TTY mode (tab completion, `?` help, pipe filters)
- **Remote CLI:** `cli` binary connects via gRPC
- **Single source of truth:** `pkg/cmdtree/tree.go` defines `OperationalTree` and `ConfigTopLevel`
  - `pkg/cli` imports via type alias `completionNode = cmdtree.Node`
  - `pkg/grpcapi` imports `cmdtree.CompleteFromTree()` directly
  - `cmd/cli` imports `cmdtree.LookupDesc()` and `cmdtree.PrintTreeHelp()`
  - Adding a command to `pkg/cmdtree/tree.go` auto-propagates to ALL CLIs
- **Dynamic completion:** `Node.DynamicFn` provides config-aware tab/? for interfaces, zones, routing instances
- **Junos-style prefix matching:** `resolveCommand()` + `cmdtree.KeysFromTree()` — no hardcoded lists
- **`?` instant help:** readline `Listener` intercepts `?` key, shows help without Enter
- **Tab descriptions:** Multi-match tab shows descriptions above prompt via `cmdtree.WriteHelp()`
- **CLI history:** Persisted to `~/.xpf_history` for the local in-daemon CLI and `~/.xpf_cli_history` for the remote `cli` binary

### Chassis Cluster (HA)
- **State machine:** StateSecondary(0), StatePrimary(1), SecondaryHold(2), Lost(3), Disabled(4); weight-based election
- **VRRP-backed RETH (bondless):** native Go VRRPv3 (`pkg/vrrp/`), 30ms interval (configurable), virtual MAC `02:bf:72:CC:RR:NN`
- **Sync:** TCP RTO on fabric link — 11 msg types (sessions, config, IPsec SA, failover, fence); incremental 1s sweep + GC delete callbacks; `writeMu` serializes ALL conn.Write paths
- **Sync hardening (#69-#73):** connection-specific disconnect (stale goroutine guard), per-RG BulkSync filtering, stale session reconciliation on BulkEnd, peer fencing (`syncMsgFence`), hard-crash test (`make test-ha-crash`)
- **Sync race fixes (#76-#80):** writeMu + single-buffer writeMsg, sync-hold 30s+reason, config authority, fast fabric_fwd ARP probe, fresh config per tick
- **Config sync:** Primary→secondary only; `handleConfigSync()` rejects if `IsLocalPrimary(0)`; `OnPeerConnected` only pushes if RG0 primary
- **Fabric IPVLAN overlay (`97c0424`):** Physical member keeps ge-X-0-Y name (XDP/TC visible); fab0/fab1 are IPVLAN L2 children for IP/sync. Single fabric per node: fab0 on node0, fab1 on node1. **After IPVLAN split:** all IP ops (probes, binds, addresses) on overlay, not parent
- **Fabric forwarding:** `try_fabric_redirect()` in xdp_zone when FIB fails for synced sessions — dual lookup (ff0, ff1), anti-loop on both, try fab0 first then fab1
- **Fabric health (#121-#125):** Zeroed `FabricFwdInfo{}` on link DOWN/neighbor loss; oper-state check before programming; netlink `LinkSubscribe`+`NeighSubscribe` for event-driven refresh; 30s ticker as safety net; gRPC dual-address failover
- **Fabric IPVLAN fixes (#127-#130):** Address reconciliation on restart (not just create), stale overlay cleanup wired in, neighbor probe on overlay not parent, compiler dual-fabric auto-detect
- **Fabric interface recovery:** compiler reads bootstrap `.link` file `OriginalName=` to find unrenamed kernel interfaces (chicken-and-egg fix for first boot)
- **Per-RG:** active/active per-RG primary, per-RG service/session management
- **Timing:** Failover ~60ms (30ms VRRP, masterDown ~97ms); planned shutdown near-instant (priority-0 burst); failback ~130ms; heartbeat 200ms/threshold 5
- **Dual-inactive window fix:** During manual failover, old code had ~25ms where BOTH nodes had `rg_active=false` → all RG traffic XDP_DROP'd → TCP stream death. Fix: Primary sets `rg_active=true` immediately (brief benign dual-active overlap); Secondary defers `rg_active=false` until VRRP BACKUP event
- **zone_ct_update RST guard:** `zone_ct_update_v4/v6()` in xdp_zone.c is the PRIMARY established-session path (fast-path FIB cache hit). Must have same RST→CLOSED suppression as xdp_conntrack
- **Fabric txqueuelen:** virtio-net TX ring max 256 entries; set `txqueuelen=10000` on fabric interface to avoid `bpf_redirect_map` drops under bidirectional load
- **RETH gotchas:** `.link` must use `OriginalName=` (MAC alternates), EAGAIN on UP link MAC set, import cycle workaround
- **Posture reconciliation (#86→#101):** Context-aware delay — 10s during startup (first 30s), 2s steady-state. CRITICAL: use `UpdateRGPriority` NOT `ForceRGMaster`
- **BPF watchdog (#102):** `ha_watchdog` ARRAY map, Go writes every 500ms, BPF checks freshness >2s = inactive. Ensures fail-closed on SIGKILL/panic
- **Misc fixes (#98-#100,#103):** writeFull loops (#99), heartbeat MTU 1472 (#100), neighbor warmup chains (#98), readiness gate (#103)
- **HA sync & activation (#131-#134):** LastSeen-based session refresh (#131), all-instances RG activation (#132), syncReady reset on disconnect (#133), hold timer `time.AfterFunc` wakeup (#134)
- **Fabric monitor resolution (#135-#137):** Monitor commands resolve fab0/fab1 overlay→physical parent for stats/tcpdump; `inc_iface_tx` added to `try_fabric_redirect`
- **Fabric observability (#138-#139):** tcpdump warning for XDP-redirected fabric traffic (AF_PACKET incompatible); per-link redirect counters (fab0/fab1/zone-encoded) in BPF + CLI
- See `bugs.md` (CC-1 through CC-15), `phases.md`, and `sync-protocol.md` for full HA details

### NPTv6 (RFC 6296)
- **Stateless IPv6 prefix translation:** 1:1 /48 prefix rewriting, checksum-neutral
- **Algorithm:** precompute adj, rewrite prefix words 0-2, apply adj to word[3] with carry fold
- **BPF:** `nptv6_rules` HASH (128), key: prefix[6]+direction(u8), value: xlat_prefix[6]+adjustment(u16)
- **Helper:** `nptv6_translate()` in `xpf_nat.h` — inbound adds ~adj, outbound adds adj; 0xFFFF→0x0000
- **Session flag:** `SESS_FLAG_NPTV6 (1<<8)`; config: `StaticNATRule.IsNPTv6 bool`
- **Pipeline:** inbound in xdp_zone (dst rewrite), outbound in xdp_policy (src rewrite)
- **Config:** `then static-nat nptv6-prefix <internal-prefix>` (both hierarchical + flat set)

### Routing
- **FRR is sole route manager** — xpf NEVER directly modifies kernel routes
- Static, DHCP-learned, per-VRF routes all managed via FRR frr.conf
- `systemctl reload frr` triggers diff-based update
- BGP/OSPF/IS-IS export → FRR redistribute mapping
- BGP neighbor inheritance from group (description, multihop, peer-as)
- **next-table route leaking:** Uses `ip rule` (not FRR) — adds `ip rule add to <prefix> lookup <table>` for inter-VRF static route leaking
- **rib-groups route leaking:** Uses `ip rule add from all lookup <table> pref 33000+` for interface-routes rib-group leaking between VRFs
- **PBR:** `ip rule` at priority 34000-34999 for firewall filter `routing-instance` action (DSCP→TOS, src/dst addr)
- **ip rule priority ranges:** rib-groups 33000-33099, PBR 34000-34999 (both after main table at 32766)

## Key Patterns & Gotchas
- `binary.NativeEndian` for BPF `__be32` IP fields — **NEVER BigEndian**
- C struct padding: always match Go struct size to C sizeof (trailing Pad bytes)
- Parser handles both `{ }` hierarchical and flat `set` syntax
- **Flat set tests:** Use `ParseSetCommand()` + `tree.SetPath()`, NOT `NewParser()` (newlines are whitespace in parser)
- IPv6 sessions use `session_v6_scratch` per-CPU map (stack too small)
- **TTL check must exist in BOTH xdp_nat AND xdp_forward:**
  - `xdp_nat`: catches NAT'd traffic before NAT rewrite (preserves original IPs for ICMP TE)
  - `xdp_forward`: catches non-NAT established sessions that skip xdp_nat via conntrack fast-path
  - Conntrack fast-path: `next_prog = XDP_PROG_FORWARD` when no SNAT/DNAT flags (`xdp_conntrack.c:64-66`)
- BPF verifier: branch merges lose packet range — re-read ctx->data after
- BPF verifier: combined stack limit is 512 bytes across call frames
  - All 4 REJECT functions (RST v4/v6, ICMP unreach v4/v6) must be `__noinline`
  - ICMP functions use `session_v4_scratch` map as byte buffer (free at REJECT time)
  - xdp_policy had 528 bytes; fixed by using scratch map fields instead of stack arrays
  - Use meta->nat_src_ip.v6 as scratch buffer for SNAT allocation
- BPF verifier: variable-offset pkt pointer range tracking
  - Verifier only updates `r` (validated range) when `var_off` is narrow (~0xFF)
  - With `var_off=(0x0; 0xffff)` (e.g. from loop-computed offset), verifier refuses to track range after bounds check → `r=0` → all packet accesses fail
  - Fix: use constant-offset from validated pointer, e.g. `(void *)(emb_ip6 + 1)` instead of `data + variable_offset`
  - `__u16` type causes `<<48; s>>48` sign-extension → `smin=-32768` → also fails for pkt pointer math
  - **Narrowing meta offsets:** `meta->l3_offset` (u16) has wide var_off; mask with `& 0x3F` before pkt pointer math (`66833c5`)
- BPF verifier: **pointer bitwise OR prohibited** (`0080cbc`)
  - `if (sv4 || sv6)` where both are pointers → compiler emits `|=` on pointer regs → verifier rejects
  - Fix: use separate `if (ptr != NULL)` checks — NEVER logical OR two BPF pointers
- **CHECKSUM_PARTIAL in generic XDP (NAT64):** (`78baec0`)
  - Generic XDP (virtio-net) preserves `skb->ip_summed=CHECKSUM_PARTIAL` through `bpf_redirect_map`
  - From-scratch checksums get CORRUPTED: kernel/NIC adds L4 byte sum to already-complete value
  - Fix: when `meta->csum_partial`, write only pseudo-header seed (`csum_fold(ph)` WITHOUT complement)
  - ICMPv4 (no pseudo-header): set `checksum=0` for CHECKSUM_PARTIAL, kernel sums all bytes
  - NAT44 unaffected: incremental updates (`csum_update`) are compatible with CHECKSUM_PARTIAL
  - `bpf_xdp_adjust_head(ctx, 20)` doesn't move `skb->csum_start` — L4 header stays at same memory addr
- `iter.Next(&key, nil)` crashes in cilium/ebpf v0.20 — use `var val []byte`
- TTY detection: `unix.IoctlGetTermios(fd, TCGETS)` not `os.ModeCharDevice`
- Interfaces must be brought UP after XDP/TC attachment (netlink.LinkSetUp)
- **`bpf_fib_lookup` TBID + VRF:** Even with `BPF_FIB_LOOKUP_TBID`, kernel honors l3mdev rules when `fib.ifindex` belongs to a VRF. Must use non-VRF ifindex for main table lookups. `fabric_fwd_info.fib_ifindex` stores a non-VRF interface for this.
- `bpf_fib_lookup` NO_NEIGH (rc=7): route exists but no ARP entry
  - STALE entries work fine — only truly absent entries cause NO_NEIGH
  - `arping` doesn't populate kernel ARP with XDP attached — use `ping` instead
  - `skb->ingress_ifindex != 0` in TC identifies kernel-forwarded packets
  - **Existing sessions (`d95a84e`):** META_FLAG_KERNEL_ROUTE + conntrack tail-call — NAT reversal then kernel forwards. In cluster mode, `try_fabric_redirect()` sends to peer via fabric link instead (faster, avoids kernel path)
  - **New connections:** XDP_PASS → kernel resolves ARP/NDP → retransmit goes through full pipeline
  - **RST protection:** conntrack skips state→CLOSED transition when META_FLAG_KERNEL_ROUTE set (kernel may drop the RST, poisoning session)

## Hitless Restart Patterns
- Non-destructive SIGTERM (no FRR/DHCP/VRF cleanup); full teardown via `xpfd cleanup`
- DHCP uses `context.Background()` — prevents address removal on restart
- Deferred `link.Update()` AFTER all compilation; stale pins need `xpfd cleanup` + fresh start
- **PROG_ARRAY pinning (CRITICAL):** `xdp_progs`/`tc_progs` MUST be pinned to survive daemon exit
- Deterministic IDs (sorted keys); populate-before-clear; dnat_table before sessions (`a030446`)
- **Deploy restart:** `systemctl stop` → `xpfd cleanup` → push binary → start. SO_REUSEADDR+SO_REUSEPORT for rebind

## Performance
- **bpf_printk:** NEVER leave in production (55%+ CPU)
- **Throughput:** 25+ Gbps native XDP, 15.6 Gbps virtio-net
- **Cluster failover:** ~60ms (VRRP 30ms, masterDown ~97ms); planned shutdown near-instant; failback ~130ms; reboot→MASTER ~6s
- **Manual failover bug (`6d63020`):** `ManualFailover()` MUST set `rg.Weight=0` — without it, peer stays secondary (sees high weight in heartbeat). `ResetFailover()` uses `recalcWeight()` to restore
- Per-interface XDP: `redirect_capable` map; iavf lacks native XDP, use PF passthrough
- **Profiling:** See `profiling.md` — perf record/report via incus exec; cluster traffic must originate from `cluster-lan-host` (not fw itself)
- **Cluster bottleneck:** `__htab_map_lookup_and_delete_batch` 85.66% CPU — Go-side session sync sweep, not BPF datapath

## Incus Test Environment
- See `test_env.md` for topology; VM: Debian 13, kernel 6.18.9; `sg incus-admin -c "make ..."` for perms
- **Naming:** vSRX-style via `enumerateAndRenameInterfaces()` — PCI passthrough always higher bus than virtio
- **Cluster:** xpf-fw0 (pri 200) + xpf-fw1 (pri 100) + cluster-lan-host; Fabric: 10.99.1.0/30

## SSH / Git Push — `source ~/.sshrc` before `git push`

## Team Pattern (User Preference) — MANDATORY
- **Always spawn:** Feature teammates + Test teammate (REQUIRED) + Docs teammate (REQUIRED)
- Test teammate: `make test` + `make test-deploy` + connectivity tests; never stops until validated
- Docs teammate: updates bugs.md, phases.md, optimizations.md, MEMORY.md continuously
- **Testing focus:** eBPF only (not DPDK) until further notice
- **Code for both:** Always implement for both eBPF and DPDK structs/code

## Workflow
- **Always commit and push** when finishing a task
- **Commit messages must be complete:** use a specific subject and a descriptive
  body covering why the change exists, what changed, and what validation ran.
  Wrap body paragraphs and bullets to readable terminal width, roughly 72
  columns. Avoid vague or checkpoint-style commit messages.
- **Full validation before commit:** `make test` + `make test-deploy` + connectivity tests
- **Cluster changes MUST run failover test:** `make test-failover` + `make test-ha-crash`
- Guard context window — keep messages concise

## Recent Features (see `phases.md` for full details)
- **CC-15 Fabric observability (#138-#139):** tcpdump XDP warning + per-link fabric redirect counters (fab0/fab1/zone-encoded)
- **CC-14 Fabric monitor/stats (#135-#137):** Monitor interface/traffic resolves fab overlay→physical parent; BPF fabric redirect TX counter fix
- **CC-13 HA sync & activation (#131-#134):** Session refresh for established flows, all-instances RG activation, syncReady reset, hold timer wakeup
- **CC-12 IPVLAN fixes (#127-#130):** Address reconciliation, stale cleanup, overlay neighbor probe, dual-fabric compiler
