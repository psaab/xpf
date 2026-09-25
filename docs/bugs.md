# Bugs Found During VM Testing

> [!IMPORTANT]
> DPDK retired in #1525. DPDK references in bug history below are
> historical records of fixes that applied while the DPDK backend
> was live; the backend is removed in #1527/#1528.

## Critical Bugs

### VRRP split-brain — resign re-election + missing RFC 5798 tie-breaking (FIXED)
- **Symptom:** After `request chassis cluster failover redundancy-group 1 node 1` from fw0, both fw0 and fw1 show MASTER for VRRP group 101. Traffic goes to both nodes, causing duplicate packets, session confusion, and eventual connectivity failure
- **Root cause (primary):** After forced resignation (resignCh handler), `becomeBackup()` reset the masterDown timer to `masterDownInterval()` which at priority 0 with 30ms adverts is only ~120ms. The resigned node re-elected itself MASTER before the peer could take over. On VLAN sub-interfaces, multicast VRRP adverts from the peer may not arrive reliably, so even a longer timer wasn't sufficient
- **Root cause (secondary):** `handleMasterRx()` used strict `>` comparison for incoming priority — equal priority adverts were ignored. RFC 5798 §6.4.3 requires tie-breaking by source IP address when priorities are equal
- **Trigger scenario:** Manual failover → resignRG sets priority=0 → becomeBackup → masterDown timer fires at 120ms → re-becomes MASTER at priority 0 → debounced timer restores priority to 100 → split-brain with peer at priority 200
- **Fix (resign timer):** After forced resignation, `masterDownTimer.Stop()` instead of letting it fire. The resigned node only becomes MASTER via `preemptNowCh` (cluster ForceRGMaster after failover reset) or receiving priority-0 from peer. Matches Junos behavior
- **Fix (tie-breaking):** Added `SrcIP net.IP` field to `VRRPPacket` struct, populated from both receiver paths. `handleMasterRx` implements RFC 5798 §6.4.3: when `pkt.Priority == pri`, node with higher source IP stays MASTER
- **Tests:** 7 new unit tests for handleMasterRx covering higher/lower/equal priority, IP tie-breaking, nil SrcIP safety, and priority-0 resign
- **Validated:** Manual failover fw0→fw1 produces clean BACKUP/MASTER split. Failover reset fw1→fw0 works correctly. Stress test: 2 cycles × 30s, 0 dead streams

### Route listener never caught up after a subscription gap (FIXED #9010)
- **Symptom:** After a route subscription ended and was re-established, every route that changed during the gap stayed invisible to the daemon. The helper FIB remained stale until the next route event that happened to arrive — which on a churning box is exactly when it is least likely to arrive promptly
- **Root cause:** `runOneRouteSubscription` opens with `ListExisting:false`, so a NEW subscription replays nothing. The outer loop's resubscribe therefore closed the socket gap without closing the DATA gap. #8915 marks the coalescer from the `ErrorCallback`, but that exists only for a fault during a LIVE subscription: a subscribe that FAILS never installs a callback, and a subscription that simply ends returns before any error is raised. `loop.Mark()` is what the coalescer reads to decide whether to actuate — an unmarked loop sweeps forever and actuates never (#8915 measured 0 actuations across 50 sweeps), and the periodic-floor alternative was considered and declined on #8915
- **Fix:** Mirror the link-state listener's pattern above — each fresh subscription issues a catch-up refresh right after it goes live (`routeListenerCatchUp`, counted by `routeListenerCatchUps`). The route listener was the outlier: `resyncLinkState` has done this for link events since #3950. Marking on the FIRST subscription too is deliberate; a refresh is idempotent and the coalescer debounces, so the cost is one actuation at startup, and special-casing "not the first" would make recovery depend on counting rather than on the invariant
- **Tests:** A cell drives the function production calls (`routeListenerCatchUp`, the seam, as #8915 did for `routeListenerErrorCallback`) and asserts the ACTUATION, with a non-vacuity sweep first. Removing the mark while keeping the counter reds it — the count is not the property
- **Validated:** `pkg/daemon` suite green

### SNMP link-state monitor died permanently on netlink ENOBUFS (FIXED #3950)
- **Symptom:** After a single transient netlink ENOBUFS (kernel receive-buffer overrun under a burst of link events — many interfaces flapping at once), `monitorLinkState` stopped detecting ANY interface up/down change for the rest of the daemon's lifetime. No SNMP linkUp/linkDown traps fired again
- **Root cause:** `monitorLinkState` used `netlink.LinkSubscribe` and returned on the update channel closing (`!ok`). The vishvananda/netlink subscribe goroutine treats ANY receive error as terminal — on `s.Receive()` returning `unix.ENOBUFS` (recoverable: the socket stays usable, some multicast messages were dropped) it calls the ErrorCallback and then `close(ch)`. The pre-fix loop saw the closed channel as end-of-stream and exited the goroutine forever
- **Impact (HA-adjacent):** link-state-driven behavior silently degraded — the standalone SNMP trap path went dark, and the broader class (RETH member link-down tracking, DHCP-on-link-up re-trigger, interface reconcile) loses its link-event source. Note: VRRP interface tracking has its OWN resilient watcher (`pkg/vrrp/track.go` falls back to 1s polling on subscription close), so RETH demotion is not solely dependent on this monitor — but the SNMP trap path was
- **Fix:** Mirror the neighbor listener's resilient resubscribe pattern (`runOneSubscription`). `monitorLinkState` now delegates one subscription lifetime to `runLinkStateSubscription`, which returns `true` on a recoverable channel close (back off `linkStateResubBackoffDefault` = 2s, then resubscribe) and `false` only on context cancellation. Because ENOBUFS means notifications were DROPPED, each fresh subscription runs `resyncLinkState` (a full `LinkList`) right after it goes live and emits catch-up linkUp/linkDown traps for any transition missed during the overflow. `prevOper` persists across resubscribes so the catch-up dedups against last-known state. The production ErrorCallback logs the ENOBUFS
- **Seams (#3950):** `monitorLinkState` reads three overridable `Daemon` fields — `linkStateSubscribe` (subscribe + onErr callback), `linkStateList` (enumerate), `linkStateEmit` (capture transitions) — plus `linkStateResubBackoff`. Production defaults are `defaultLinkStateSubscribe` / `netlink.LinkList` / SNMP trap. Unit tests inject an ENOBUFS then a real event and assert the monitor resubscribes, catches up, and continues (`daemon_linkstate_monitor_3950_test.go`)

### Fabric-state monitor died permanently + leaked a netlink socket on netlink ENOBUFS (FIXED #4031)
- **Symptom:** After a single transient netlink ENOBUFS (a burst of link/neighbor events overruns the fabric monitor's netlink receive buffer), `monitorFabricState` stopped detecting ANY fabric interface up/down or fabric-peer neighbor change for the rest of the daemon's lifetime. A fabric-down that should trigger a failover, or a fabric-up that should resume cross-chassis forwarding, went unobserved — HA mis-behaved (a stale fabric-up assumption blackholes, or a missed fabric-down never fails over). A netlink fd also leaked on every overflow
- **Root cause:** `monitorFabricState` held TWO subscriptions (`netlink.LinkSubscribe` + `netlink.NeighSubscribe`) and returned on EITHER update channel closing (`!ok`). The vishvananda/netlink subscribe goroutine treats ANY receive error as terminal — on a recoverable ENOBUFS it closes the update channel. The pre-fix loop saw that close as end-of-stream and exited the goroutine forever. Worse, the `!ok` return did NOT close the SIBLING subscription's `done` channel, so the sibling's done-watcher goroutine never ran `s.Close()` — the sibling netlink socket fd leaked on every overflow
- **Impact (HA):** fabric link/neighbor-driven `fabric_fwd` refresh (event-driven cross-chassis redirect programming, #124) lost its event source. The 30s `populateFabricFwd` ticker remained as a safety net, so forwarding was not instantly dead, but the sub-second event-driven refresh that keeps cross-chassis redirect current across a VRRP failback was gone, plus an accumulating fd leak
- **Fix (mirrors #3950):** `monitorFabricState` now delegates one subscription lifetime to `runFabricStateSubscription`, which `defer`-closes BOTH `done` channels on every exit path (no sibling leak, the #4031 fd-leak fix) and returns `true` on a recoverable channel close (or a subscribe failure) — the caller backs off `fabricStateResubBackoffDefault` = 2s, then resubscribes — and `false` only on context cancellation. Because ENOBUFS means events were DROPPED, each fresh subscription calls `triggerFabricRefresh` once both sockets are live to re-sync fabric forwarding and catch up on any transition missed during the overflow
- **Seams (#4031):** `runFabricStateSubscription` reads three overridable `Daemon` fields — `fabricLinkSubscribe` / `fabricNeighSubscribe` (start a subscription; default `defaultFabricLinkSubscribe` / `defaultFabricNeighSubscribe`) and `fabricStateResubBackoff`. Unit tests inject a channel close on either the link OR neighbor subscription and assert the monitor resubscribes, releases the sibling socket (no leak), keeps triggering refreshes, and exits cleanly on context cancel (`daemon_fabric_monitor_4031_test.go`)

### DNAT port byte-order double-swap in fabric redirect (FIXED aafe879)
- **Symptom:** `apply_dnat_before_fabric_redirect` in xdp_zone.c wrote wrong port into packet
- **Root cause:** `meta->dst_port` is `__be16` (from `tcp->dest`), but code applied `bpf_htons()` which double-swaps to host byte order
- **Fix:** Use `meta->dst_port` directly (already network byte order)
- **Masked in practice:** Test cluster only uses SNAT, not DNAT — DNAT fabric redirect path rarely triggered
- **Investigation note:** Codex bundled this fix with IPv6 DNAT inline expansion (+56KB .o, +47% xlated BPF). The IPv6 expansion killed all 8 TCP streams during failover despite being dead code — the `__always_inline` expansion at 2 call sites changed compiler register allocation/branch optimization enough to break IPv4 fast-path. IPv6 DNAT fabric redirect must use `__noinline` or separate tail-call

### Failback stream death — rg_active set before routing ready
- **Symptom:** After RG1 failover→failback, 1 of 4 iperf3 streams permanently dies (cwnd=1 MSS), other 3 fine
- **Root cause:** Cluster event handler set `rg_active=true` ~30-60ms BEFORE VRRP MASTER event (which removes blackhole routes). During this window: packets bypass fabric redirect → SNAT applied → hit blackhole → fabric-redirect with SNAT'd headers → peer can't match synced session (original 5-tuple) → dropped
- **Fix:** In cluster event handler, only set `rg_active=true` if VRRP is already MASTER (`rethMasterState[rgID]`). If VRRP is BACKUP (failback case), defer to VRRP MASTER handler (fires after VIP added + blackhole removed). `daemon.go:3633-3660`
- **Doc:** `docs/active-active-new-connections.md` "Bug: Failback Stream Death" section

### TCP stream death from blind RST→CLOSED in BPF conntrack
- **Symptom:** During long-duration high-throughput transfers (iperf3 -P4 -t1200 at ~9 Gbps), individual TCP streams die one by one over time. cwnd collapses to 1 MSS (1.41 KB), RTO escalates to 120s, bytes_sent freezes. Sessions stay "Established" in `show security flow session` but carry zero traffic
- **Root cause:** `ct_tcp_update_state()` blindly transitions ANY session to CLOSED on ANY RST packet (no TCP sequence validation). The CLOSED handler in `handle_ct_hit_v4/v6` drops ALL non-RST data (`XDP_DROP`). Additionally, `last_seen` was updated BEFORE the CLOSED check, so client retransmits kept resetting the GC timer — sessions stuck in CLOSED forever, all data permanently dropped
- **Death spiral:** Spurious RST (packet corruption, out-of-window segment response at high throughput — TCP sequence space wraps every ~23s at 10 Gbps) → session CLOSED → all data XDP_DROP'd → client retransmits keep session alive in GC → stream permanently dead
- **Fix (BPF XDP):** In `xdp_conntrack.c`, suppress RST→CLOSED transition for ESTABLISHED sessions (forward RST to endpoints but keep session ESTABLISHED). Only transition to CLOSED if `rst-invalidate-session` is configured (`FLOW_TCP_RST_INVALIDATE` flag). Guard `last_seen` update with `sess->state != SESS_STATE_CLOSED` to prevent GC bypass
- **Fix (BPF TC):** In `tc_conntrack.c`, guard `last_seen` update with CLOSED check (TC doesn't do TCP state tracking but prevents GC timer reset)
- **Fix (DPDK):** Same pattern in `dpdk_worker/conntrack.c` at all 4 hit paths (v4 fwd/rev, v6 fwd/rev)
- **Evidence:** Per-stream `ss -ti` showed cwnd=1, RTO 120000ms, bytes_sent frozen; drops counter increasing at ~6/s matching retransmit rate; streams died at t=130, 176, 366, 435 (each after ~50-200 GB)

### Rapid repeated failover kills TCP streams — dual-inactive transition window
- **Symptom:** Rapid repeated failover cycles (fw0→fw1→fw0→fw1...) permanently kill 2+ iperf3 streams. cwnd collapsed to 1 MSS, "Broken pipe". Single-cycle works fine. At ~750K pps × 8 streams, 25ms dual-inactive = ~150K dropped packets → TCP BBR cwnd collapse → RTO 120s → permanent stream death
- **Root cause:** During manual failover (RG1: node0→node1), ~25ms window where BOTH nodes have `rg_active[1]=false`: node0 (resigning) sets rg_active=false immediately on Secondary transition; node1 (incoming) waits for VRRP MASTER before setting rg_active=true. During this window, all RG1 traffic is XDP_DROP'd (commit `4bdbefa` drops FABRIC_FWD packets when both nodes inactive)
- **Fix (Go — eliminate dual-inactive window):**
  1. On cluster Primary: set `rg_active=true` immediately + `removeBlackholeRoutes()` (don't wait for VRRP MASTER). Creates brief benign dual-active overlap (~5ms) instead of traffic-killing dual-inactive gap
  2. On cluster Secondary: defer `rg_active=false` if VRRP is still MASTER (`rethMasterState[rgID]`). Let VRRP BACKUP event handle it instead of immediate deactivation
- **Previous fix (now superseded):** Drop `META_FLAG_FABRIC_FWD` packets instead of KERNEL_ROUTE fallback — mitigated symptoms but didn't eliminate the dual-inactive window
- **Doc:** `docs/active-active-new-connections.md` "Bug: Dual-Inactive Transition Window" section

### zone_ct_update RST→CLOSED suppression missing in xdp_zone fast-path
- **Symptom:** Established TCP streams die during active/active failovers despite RST→CLOSED fix in xdp_conntrack. A single spurious RST permanently kills the stream
- **Root cause:** `zone_ct_update_v4/v6()` in `xdp_zone.c` is the PRIMARY code path for established sessions (fast-path FIB cache hit). This function updated TCP state including RST→CLOSED but lacked the `rst-invalidate-session` guard added to `xdp_conntrack.c`. All established traffic hitting the zone fast-path was vulnerable to blind RST
- **Fix:** Add same RST→CLOSED suppression guard to `zone_ct_update_v4()` and `zone_ct_update_v6()` in `xdp_zone.c` — check `flow_config_map` for `FLOW_TCP_RST_INVALIDATE` flag before allowing ESTABLISHED→CLOSED transition
- **Key insight:** Two separate conntrack update paths exist: `xdp_conntrack.c` (full path) and `xdp_zone.c:zone_ct_update` (fast-path). Both must have identical RST handling

### Duplicate daemon corrupts BPF programs/maps via "xpfd show ..."
- **Symptom:** Session sync sends 0 sessions, `show security flow statistics` shows 0 packets/sessions despite active traffic. All iperf3 streams die on first failover because peer has no synced sessions
- **Root cause:** Running `xpfd show chassis cluster status` (or any `xpfd show ...`) via `incus exec` starts a SECOND full daemon process. The binary falls through to `daemon.New()` + `d.Run()` for any arguments not matching `version` or `cleanup`. The second daemon loads a new set of BPF programs with new maps, updates the pinned PROG_ARRAY (shared tail-call dispatch), and re-attaches interfaces. Original daemon's Go code still references old maps → session sync reads empty Set 1 maps, counters show zero
- **Fix:** Add positional argument guard in `cmd/xpfd/main.go` — reject any non-flag first argument that isn't `version` or `cleanup`. Users should use `cli` binary or run `xpfd` interactively on a TTY
- **Key insight:** ALWAYS use `cli` binary for remote show commands, NEVER `xpfd show ...` via non-interactive execution

### Fabric interface txqueuelen drops under bidirectional active/active load
- **Symptom:** `bpf_redirect_map` drops exceeded 1.7% under bidirectional active/active load at ~10 Gbps on virtio-net fabric interface
- **Root cause:** virtio-net fabric interface has max 256-entry TX ring. Default `txqueuelen=1000` insufficient for burst traffic during failover
- **Fix:** Increase fabric interface `txqueuelen` from 1000 to 10000 (eliminates drops)
- **Note:** Mixed XDP mode (per-interface native/generic) was attempted to avoid this but reverted — TC egress BPF programs interfere with XDP_PASS'd packets (reverse the SNAT)

### FABRIC_FWD + no session + vrf-mgmt FIB → UNREACHABLE drops transit traffic (`4bdbefa`)
- **Symptom:** During active/active split, peer NAT-reverses traffic and plain-fabric-redirects it to local node for delivery. Traffic dropped at xdp_zone FIB lookup (UNREACHABLE/BLACKHOLE)
- **Root cause:** Fabric transit traffic arrives on fab0 (VRF mgmt, table 999). `routing_table=254` override only applied when a session matched, but this traffic has no local session (not synced yet — peer just NAT-reversed it). FIB used vrf-mgmt table → UNREACHABLE (no data-plane routes in VRF mgmt)
- **Fix (BPF):** In BLACKHOLE/UNREACHABLE handler, after fabric redirect fails (anti-loop: packet came FROM fabric), check `META_FLAG_FABRIC_FWD` and re-FIB in main table (tbid=254) using `fabric_fwd_info.fib_ifindex` (non-VRF interface). Forward to resolved egress. `xdp_zone.c:942-1020`
- **Fix (TC):** Fabric transit bypass in `tc_conntrack.c:193-210` — packets from fabric peer skip TC conntrack (no local session) and tail-call directly to `TC_PROG_FORWARD`. Trust peer's XDP validation
- **Fix (NO_NEIGH):** Zone-encoded redirect for new connections in NO_NEIGH handler (`xdp_zone.c:855-868`). Preserves ingress zone for policy/SNAT on peer
- **Three sub-problems:**
  1. **Sessionless fabric transit:** Peer NAT-reversed, no session synced → no routing_table=254 override → wrong VRF table → UNREACHABLE. Fix: re-FIB in main table
  2. **TC conntrack drop:** TC egress has no session → TC_ACT_SHOT. Fix: detect fabric ingress, bypass to TC_PROG_FORWARD
  3. **NO_NEIGH zone loss:** New connections via NO_NEIGH used plain redirect → peer saw fab0 zone ("control"). Fix: zone-encoded redirect preserves original ingress zone
- **Doc:** `docs/active-active-new-connections.md`

### Fabric transit auto-forward used wrong FIB result (vrf-mgmt default route)
- **Symptom:** New TCP connections and ICMP ping during active/active split fail. SYN-ACKs never reach LAN client despite being NAT-reversed by peer and fabric-redirected successfully
- **Root cause:** Auto-forward at xdp_zone.c line 710 (`FABRIC_FWD + sv4==NULL → bpf_tail_call(FORWARD)`) used the INITIAL FIB result, which was resolved in vrf-mgmt (fab0's VRF). vrf-mgmt has a DHCP default route → FIB returned SUCCESS with egress=management interface (WRONG). The correct re-FIB at line 839 (table 254 + non-VRF ifindex) was never reached because the auto-forward short-circuited it
- **Fix:** Remove auto-forward block; let code fall through to the re-FIB at line 839 which does a proper `bpf_fib_lookup` with `BPF_FIB_LOOKUP_TBID=254` and `fabric_fwd_info.fib_ifindex`. Also added egress zone resolution to both re-FIB blocks for correct zone counters
- **Key insight:** The auto-forward and re-FIB handle the same case (FABRIC_FWD + no session). Auto-forward was supposed to be an optimization but used the wrong FIB result. Two-pass FIB is essential because unconditional routing_table=254 breaks locally-destined fabric traffic
- **Doc:** `docs/active-active-new-connections.md` "Bug: Fabric Transit Auto-Forward Used Wrong FIB Result"

### NAT64 TCP broken on generic XDP (CHECKSUM_PARTIAL corruption) (`78baec0`)
- **Symptom:** NAT64 TCP (iperf3 via `64:ff9b::`) fails with bad checksum; ICMP ping works
- **Root cause:** Three interacting bugs:
  1. **xdp_policy.c session key corruption:** `meta->src_ip` was overwritten with SNAT IPv4 addr BEFORE `create_session_v6()` used it as session key source. Fix: use `nat_src_ip` as scratch, overwrite `src_ip` after session creation.
  2. **xdp_conntrack.c + xdp_zone.c NAT64 flag propagation:** On established session hits, `SESS_FLAG_NAT64` was not propagated from session flags to `meta->nat_flags`, so `xdp_nat` never dispatched to `xdp_nat64` for existing sessions.
  3. **xdp_nat64.c CHECKSUM_PARTIAL corruption:** Generic XDP (virtio-net) preserves `skb->ip_summed=CHECKSUM_PARTIAL` through `bpf_redirect_map`. From-scratch TCP/UDP checksum was complete, but kernel/NIC finalizes by adding L4 byte sums to the existing check field — corrupting it.
- **Fix for #3:** Split into two paths based on `meta->csum_partial`:
  - `csum_partial=1`: write only IPv4 pseudo-header seed (`csum_fold(ph)` without complement). Kernel's `skb_checksum_help` finalizes by summing L4 bytes + seed.
  - `csum_partial=0`: compute full from-scratch checksum (existing loop + `~csum_fold(sum)`)
  - ICMPv4 (no pseudo-header): set `checksum=0` for CHECKSUM_PARTIAL (kernel sums all ICMP bytes)
- **Why NAT44 wasn't affected:** NAT44 uses incremental checksum updates compatible with CHECKSUM_PARTIAL
- **Why ICMP ping worked:** ICMPv6→ICMPv4 checksum happened to be correct because the from-scratch sum for short ICMP echo packets was finalized correctly
- **Key insight:** `bpf_xdp_adjust_head(ctx, 20)` for IPv6→IPv4 doesn't move `skb->csum_start` — TCP header stays at same memory address, only `skb->data` shifts
- **Files:** `bpf/xdp/xdp_nat64.c`, `bpf/xdp/xdp_conntrack.c`, `bpf/xdp/xdp_policy.c`, `bpf/xdp/xdp_zone.c`

### VRRP manager deadlock on cluster secondary node (`58ad85b`)
- **Symptom:** `show security vrrp` hangs indefinitely on fw1 (cluster secondary)
- **Root cause:** Three interacting bugs:
  1. `File()` puts socket in blocking mode → `recvmsg` syscall blocks indefinitely
  2. `stop()` calls `conn.Close()` AFTER `<-vi.stopped` → waits for receiver that's stuck in `recvmsg`
  3. `UpdateInstances()` holds Manager write lock during `stop()` → all `RLock` callers (gRPC handlers) blocked
- **Race trigger:** DHCP recompile + cluster debounced timer both call `UpdateInstances()` within milliseconds — timer holds write lock, blocks on `stop()`, then DHCP blocks waiting for write lock, then all gRPC handlers block on read lock
- **Fix:** (a) Use `SyscallConn().Control()` instead of `File()` for SO_BINDTODEVICE, (b) `SetReadDeadline(1s)` in receiver, (c) Close socket BEFORE waiting for goroutine exit in `stop()`
- **Bonus fix:** Manager nil panic — `applyConfig()` ran before manager creation; moved eager creation to before first `applyConfig`
- **Files:** `pkg/vrrp/instance.go`, `pkg/vrrp/manager.go`, `pkg/daemon/daemon.go`

### NAT64 ICMP error payload length for truncated embedded packets (`5fa143b`)
- ICMP errors from some routers (directly connected gateways) truncate the embedded original packet
- `nat64_icmp_error_4to6()` computed IPv6 `payload_len` from embedded IPv4 `tot_len` (full original size)
- But the ICMP error only included a portion of the L4 data → IPv6 payload_length exceeded actual data
- tcpdump showed: `[header+payload length 112 > length 96] (invalid)` → packet dropped by receiver
- **Fix:** Cap `emb_l4_len` by `outer_tot_len - 48` (actual data present in ICMP error)
- **Root cause:** `outer_tot_len - outer_hdr(20) - icmp_err(8) - emb_hdr(20)` = actual embedded L4 bytes
- **File:** `bpf/xdp/xdp_nat64.c` lines 782-793

### NAT64 ICMP traceroute echo ID bug (`91bdd38`)
- In `nat64_xlate_6to4()`, `old_sport = meta->src_port` for ICMP stored the SNAT-allocated port, not the original echo ID
- TCP/UDP correctly read `old_sport` from packet header; ICMP had no such override
- `nat64_state.orig_src_port` got the wrong value → ICMP error translation restored wrong echo ID → mtr couldn't match responses
- **Fix:** Added `else if (orig_proto == PROTO_ICMPV6) { old_sport = meta->dst_port; }` — `meta->dst_port` retains original echo ID since policy only changes `src_port`
- **File:** `bpf/xdp/xdp_nat64.c` line 282

### NAT64 to firewall-local IPv4 reinjects untranslated (#10685)
- A NAT64 destination embedding a firewall-owned IPv4 resolved to
  `LocalDelivery` while host-bound policy still judged the IPv6 wire tuple.
  Consequently a v4-keyed `to-zone junos-host` deny missed, a `LocalMiss`
  session was minted, and the original untranslated IPv6 frame was reinjected.
- **Fix:** Drop NAT64 session misses whose extracted IPv4 target resolves to
  `LocalDelivery`, before host-bound gates and session installation. The kernel
  owns no synthetic NAT64 address to receive the untranslated frame.
- **Regression test:** `userspace-dp/src/afxdp/tests_nat64_local_10685.rs`
  drives the actual poll path with a v4-keyed deny and controls that ordinary
  NAT64 transit continues to translate and forward.

### Directed-broadcast forwarding accepts NOARP neighbor (#10690)
- Go neighbor publication/listener and Rust netlink/FIB state handling treated
  `NUD_NOARP` as a resolved peer. A directed-broadcast destination on the selected
  connected subnet could therefore reuse the all-ones Ethernet MAC and bypass
  the intended unicast-only forwarding boundary.
- **Fix:** Reject NOARP neighbor states at Go publication/listener and Rust
  netlink/FIB admission, and remove a prior dynamic row on NOARP transitions.
  A NOARP row cannot supply the all-ones MAC for a unicast-shaped permit.
  No TX policy guard was added; explicit broadcast-rule behavior remains
  outside this neighbor-state fix.
- **Regression tests:** Rust netlink transition and FIB-state classification;
  Go listener and snapshot publication, including NOARP-only and composite
  NUD states.



### Transit forwards martian and non-unicast sources (#10689)
- Transit under an `application any` permit forwarded packets and installed
  forward/reverse sessions when the source was IPv6 multicast, loopback,
  unspecified or link-local, or an IPv4 martian.
- **Fix:** Apply a source-class gate after route resolution and before transit
  policy/session installation, and recheck established-session and FlowCache
  hits before their remaining side effects. IPv4 rejects this-network (`0/8`),
  loopback, link-local, multicast, reserved/broadcast (`240/4`), and connected
  subnet-directed broadcast sources. IPv6 rejects multicast, loopback,
  unspecified and link-local sources. The gate is transit-only: DHCP, NDP and
  DAD packets addressed to the firewall retain their LocalDelivery handling.
- **Regression test:** `userspace-dp/src/afxdp/tests_martian_source_10689.rs`
  exercises the poll path for every listed class under the `nat_snapshot()`
  permit-any policy, including flowless unspecified and fragment traffic, and
  controls that ordinary IPv4/IPv6 unicast sources still forward and install
  sessions. `poll_descriptor/flow_cache_hit_tests.rs` verifies a consumed
  FlowCache hit is dropped before forwarding side effects.


### NAT64 HA imports self-refuse under a dual SNAT reference (#10706)
- A synced NAT64 decision was first booked in the source-NAT pool allocator,
  so the NAT64 allocator's #9021 peer-ownership check saw that same import as
  a conflicting peer and rejected it.
- **Fix:** Keep NAT64 translated tuples exclusively in the NAT64 allocator by
  treating NAT64 decisions as having no source-NAT reservation.
- **Regression test:** `userspace-dp/src/afxdp/tests_nat64_overlap_8115.rs`
  `a_synced_nat64_import_books_only_the_nat64_allocator_under_dual_reference_10706`
  asserts that a shared source-NAT/NAT64 address is occupied only in the NAT64
  allocator after an ordered synced reservation.

### NAT64 reverse path copies Ethernet padding into IPv6 payload (#1641)
- **Severity:** MAJOR — reverse-path packet corruption / L4 checksum failure
- **Symptom:** Every TCP/UDP/ICMPv6 NAT64 reply whose original IPv4
  packet was Ethernet-padded (< 64B on the wire: ACKs, DNS replies,
  short HTTP responses) is dropped by the IPv6 client
- **Root cause:** `translate_v4_to_v6` (userspace-dp Rust path) read
  `l4_payload = packet.get(ihl..)` — every byte from the IPv4 header to
  the end of the slice. The caller passes the whole L3-onward frame,
  including any Ethernet padding the NIC/driver added to reach the
  60-byte minimum. That padding inflated the IPv6 `payload_len` and was
  fed into the recomputed L4 checksum (wrong pseudo-header length), so
  the receiver's checksum verification failed
- **Fix:** Trim the L4 slice to the IPv4 Total Length field
  (`packet[2..4]`), mirroring the forward path which trims to the IPv6
  `payload_len`. Clamp safely: reject `total_len < ihl` or
  `total_len > packet.len()` (malformed/oversized header) before
  slicing, so a crafted header cannot panic or read OOB
- **Regression test:** `nat64_tests.rs`
  `translate_v4_to_v6_trims_ethernet_padding_{tcp,udp_dns}` feed a
  zero-padded 46B L3 slice and assert the translated IPv6 `payload_len`
  excludes the padding and the L4 checksum verifies; plus
  `translate_v4_to_v6_total_len_{larger_than_slice,below_ihl}_returns_none`
  for the malformed-length clamp
- **File:** `userspace-dp/src/nat64.rs`

### NAT64 port allocator reset to offset-0 on config reload (#4518)
- **Severity:** MEDIUM — post-commit reverse-reply mis-demux until the
  pre-reload session ages out
- **Symptom:** A config commit while NAT64 sessions are live let the
  first post-commit flows reuse the LOW translated ports still owned by
  pre-reload sessions. When a colliding port mapped to the same v4
  remote, the (now 1:N) reverse index bucket held two handles and the
  v4→v6 reply mis-demuxed/hijacked until the stale session expired
- **Root cause:** `Nat64State::from_snapshots` built each prefix's
  stateful `PortAllocator` (#4381) FRESH on every forwarding rebuild
  (port-offset 0), dropping the previous allocator and its live
  tuple-ownership set. Source NAT already preserved live allocations
  across reload via `parse_source_nat_rules_with_previous` +
  `previous_allocators`; NAT64 did not
- **Fix:** `from_snapshots_with_previous(snaps, previous)` REUSES the
  previous prefix's Arc-backed `PortAllocator` (live reservations carry
  over) when `(prefix bytes, source pool)` is byte-identical; a changed
  pool (addresses added/removed/reordered) resets to a fresh allocator
  because the round-robin counters are pool-position indexed. The
  reconcile preflight (`build_reconcile_forwarding`) already threads the
  previous live `ForwardingState`, so the caller passes
  `previous.map(|p| &p.nat64)`
- **Relationship:** The COMPLEMENTARY cross-node HA-failover reservation
  sync (`Nat64ReverseInfo` + reserve-on-standby) is tracked in #4512;
  this fix is the same-node reload path only
- **Regression test:** `nat64_tests.rs`
  `nat64_4518_allocator_survives_config_reload` (fail-on-revert: a new
  post-reload flow must not reclaim a live pre-reload port) +
  `nat64_4518_pool_change_resets_allocator` +
  `nat64_4518_new_rule_has_no_previous_to_reuse`
- **File:** `userspace-dp/src/nat64.rs`,
  `userspace-dp/src/afxdp/forwarding_build/mod.rs`

### ipToUint32BE byte order
- `binary.BigEndian.Uint32(ip4)` produced wrong bytes when cilium/ebpf serializes as native-endian
- **Fix:** Use `binary.NativeEndian.Uint32(ip4)` so bytes match raw network order BPF writes to `__be32`
- **Affected:** DNAT, static NAT, NAT pool IPs, NAT64 prefix
- **File:** maps.go

### Family inet/inet6 AST shape
- Hierarchical syntax `family inet { dhcp; }` creates `Node{Keys:["family","inet"]}` — AF name is Keys[1]
- Set-command `set interfaces eth0 unit 0 family inet dhcp` creates the SAME node — `SetPath` descends `compoundKey` like the parser (corrected in #8808; the old claim that it splits into `family` + child `inet` was false)
- A separately BRACED `family { inet { dhcp; } }` is what creates `Node{Keys:["family"]}` with an `inet` child; a brace-elided `family inet dhcp;` creates one packed `Node{Keys:["family","inet","dhcp"]}` (#2419)
- **Fix:** Compiler must handle ALL THREE shapes
- **File:** compiler.go

### SessionValueV6 trailing padding
- C struct is 152 bytes (8-byte aligned due to __u64), Go struct was 148 bytes
- **Fix:** Added `Pad2 [4]byte` to match. Compare `sizeof` in C vs Go `unsafe.Sizeof`
- **Pattern:** When mirroring C structs in Go for cilium/ebpf, always add trailing padding

### Host-inbound bypass in XDP policy
- `bpf_fib_lookup` with broadcast/unicast-to-unknown-IP matches default route
- Sends host-bound packets through policy pipeline where deny-all drops them
- **Fix:** xdp_policy checks `host_inbound_flag()` before denying, tail-calls to xdp_forward with fwd_ifindex=0

## Important Bugs

### tx_ports devmap value size
- Go wrote 4-byte struct (ifindex only) but BPF DEVMAP_HASH expects 8-byte `bpf_devmap_val` (ifindex + prog_fd)
- **File:** loader.go

### SNAT hierarchical syntax
- Config compiler only handled flat `source-nat interface` keys, not hierarchical `source-nat { interface; }` with child nodes
- **Fix:** FindChild() fallback in compiler.go

### Address-book described entry prefix corruption (#2222, FIXED)
- **Symptom:** An address-book `address <name> <prefix>` entry that also carries a `description` resolves to the wrong prefix (or empty) in policies, so a policy keyed on that address matches nothing / fails open to the next policy. Order-dependent and silent — `commit` succeeds with only a non-blocking `address-book "X": invalid address "description"` warning.
- **Root cause:** `compileAddressBook` iterated `global.Children` raw and treated each `address` node independently, keying by `Keys[1]` and blindly reading `Keys[2]` as the prefix. A described address renders as TWO sibling AST nodes in flat-set order — `[address X <prefix>]` (leaf) and `[address X description]` (block) — so the second overwrote `Value` with the literal `"description"`. The hierarchical block form `address X { <prefix>; description "..."; }` has `len(Keys) < 3` and was dropped entirely (0 addresses). Unlike zones / SNAT pools (which merge by name via `namedInstances`), address-book was the only compiler iterating children raw.
- **Fix (pkg/config/compiler_security.go):** Merge all `address` nodes by name; derive the prefix from `Keys[2]` ONLY when it parses as a CIDR/IP (`looksLikeIPOrCIDR`), otherwise from a bare-leaf child (hierarchical block prefix); route `description` into a new `Address.Description` field so a non-prefix sub-stanza can never clobber `Value`. Handles both AST shapes and either sub-stanza ordering.
- **Tests:** `TestAddressBookDescriptionPrefix` (dual-AST × ordering table) + `TestAddressBookDescriptionResolvesInPolicy` in `parser_security_test.go`.

### Address-book empty-prefix entry not warn-flagged (#2229, FIXED)
- **Symptom:** After #2228 an address-book `address <name>` entry with no compilable prefix — either no prefix at all (description-only) or only an as-yet-uncompiled sub-stanza (`dns-name`/`range-address`/`wildcard-address`) — compiles to `Value==""`. This is fail-closed and safe at resolution (`net.ParseCIDR("")` errors → the address matches nothing → policies referencing it deny), so it is NOT a security bug. But `ValidateConfig` only flagged `invalid address` on a NON-empty unparseable `Value`, so a prefix-less entry produced no commit-time warning at all — an operator authoring error (forgetting the prefix) went silent.
- **Root cause:** The address-book warn loop in `compiler_validate_warn.go` guarded the parse with `if entry.Value != ""`, so the empty case fell straight through with no warning.
- **Fix (pkg/config/compiler_validate_warn.go):** Emit a non-blocking warning for an `address` entry whose compiled `Value` is empty — `address-book "X": no usable prefix configured; it will match nothing`. This is a WARNING, never a hard reject: an empty-prefix address never forwarded and rejecting it would brick existing configs. `dns-name`/`range-address`/`wildcard-address` remain uncompiled (separate pre-existing gap) and genuinely resolve to nothing today, so the warning is correct to flag them too.
- **Tests:** `TestAddressBookEmptyValueWarns` (dual-AST: flat-set description-only, hierarchical description-only, flat-set `dns-name` sub-stanza all warn; flat-set + hierarchical valid prefix do NOT warn; commit succeeds in every case) in `parser_security_test.go`.

### Duplicate address-set stanzas drop earlier members (#4706, FIXED)
- **Symptom:** A hand-authored / `load override` config with the SAME `address-set <name>` in two literal `address-set S { ... }` blocks silently loses the earlier block's members — the second stanza wins. A policy matching `S` then matches FEWER addresses than the operator intended (silent narrowing; the firewall permits/denies the wrong set of addresses). `commit` succeeds with no warning.
- **Root cause:** `parseAddressBookEntries` (`compiler_security_addressbook.go`) merged duplicate `address <name>` nodes by name (the #2222 fix) but the sibling `address-set` case built a fresh struct and did `ab.AddressSets[as.Name] = as` — a last-wins overwrite. The hierarchical parser does NOT fold two literal same-name `address-set` blocks into one node (unlike the flat-set `SetPath`, which descends into one existing node and accumulates), so the compiler saw two sibling `address-set S` children and kept only the last. The common flat-set `set ... address-set S ...` path was unaffected (bounding factor). Same asymmetry the `address` path was explicitly hardened against in #2222.
- **Fix (pkg/config/compiler_security_addressbook.go):** Mirror the `address` merge-by-name — fetch-or-create the `AddressSet` by name, then UNION members with first-seen order + dedup matching Junos union-by-name semantics. Nested `address-set` references took the same overwrite path and are fixed too. A single-stanza set compiles identically (no regression). (The dedup was originally `appendUniqueString`, a linear scan; #5826 replaced it with a per-set O(1) map index — same output, O(N) instead of O(N²).)
- **Tests:** `TestDuplicateAddressSetBlocksUnionMembers` / `...UnionNestedRefs` / `...DedupMembers` / `TestSingleAddressSetBlockUnchanged` in `addressbook_dup_addrset_merge_4706_test.go` (RED on revert to last-wins).

### Repeated address-book CONTAINERS replace or ignore earlier entries (#7524, FIXED)
- **Symptom:** A repeated `global` block, a repeated `address-book` block, or a second `security` root each silently lost address-book entries — and, measured at master, they lost DIFFERENT ones. `address-book { global { A } global { B } }` kept **A** (first wins); `address-book { global { A } } address-book { global { B } }` and two `security` roots each kept **B** (last wins). "Replace or ignore earlier entries" is literal: the first shape ignores, the other two replace. `commit` succeeds with no warning. A policy naming the dropped address or address-set compiles against a book that does not contain it and matches a different set of traffic than the operator wrote.
- **Root cause:** `compileAddressBook` (`compiler_security_addressbook.go`) read `node.FindChild("global")` — the FIRST match only — and then did `sec.AddressBook = ab`, a whole-book assignment. `parseStatements` APPENDS a repeated block rather than merging it, and `compileSecurity` iterates every `address-book` sibling and every `security` root, so all three shapes reach the compiler: the first-match read drops the second `global`, and the assignment discards whatever an earlier `address-book` or `security` root had already contributed. #4706 and #4818 fixed the INNER (same-name `address-set`) and SIBLING (member) merge classes; neither reached the CONTAINERS, which is why this survived them.
- **Fix (pkg/config/compiler_security_addressbook.go):** Iterate ALL `global` children and merge into the EXISTING `sec.AddressBook` rather than assigning a fresh one. Lazy allocation is preserved — the book is materialized only when a `global` block exists, so a config with no address-book still compiles to a nil `AddressBook` and every downstream `!= nil` check keeps its meaning ("an address book was configured"). Within a block, later entries with the same NAME still win, which is #4706's semantics, unchanged.
- **Tests:** `TestRepeatedAddressBookContainersMerge7524` (all three container shapes), `TestRepeatedContainersMergeAddressSets7524` (sets travel the same path and are the half that actually widens or narrows a policy — a merge carrying addresses but not sets passes every address-only assertion), `TestNoGlobalBlockLeavesAddressBookNil7524` (the lazy-allocation control, which the obvious "allocate up front then merge" fix breaks while passing every merge cell), and `TestDuplicateNameStillLastWins7524` (without it, the merge could be "fixed" by making duplicates first-wins and nothing else would notice) in `address_book_container_merge_7524_test.go`.

### Address-set member dedup was quadratic (#5826, FIXED)
- **Symptom:** Compiling an address set with N unique members (across repeated same-name stanzas / a large member list) performed O(N²) string comparisons, so a syntactically valid config near the config-size ceiling burned disproportionate CPU during commit / boot / HA config-sync / validation, delaying control-plane convergence.
- **Root cause:** `appendUniqueString` (`compiler_security_addressbook.go`) linearly scanned the FULL existing member slice on EVERY append; `parseAddressBookEntries` called it once per direct `address` and nested `address-set` member — O(N²) for N members.
- **Fix:** `parseAddressBookEntries` keeps a per-address-set membership index — a `map[string]struct{}` for direct-address members and a SEPARATE one for nested-set members — seeded from any existing members (repeated blocks/roots union onto the persisted `*AddressSet`), and appends to the ordered slice only on a first-seen map MISS. O(N) with byte-identical output (first-seen order + exact union-by-name dedup). The index is compiler-local (not persisted / not on the wire); `appendUniqueString` is removed.
- **Tests:** `TestAddressSetDedupFirstSeenOrderAndUnion_5826` / `...NamespacesIndependent_5826` / `...ScalesLinearly_5826` + `BenchmarkParseAddressSetMembers` in `addressset_dedup_5826_test.go`; the #4706 behavior tests stay GREEN (output unchanged). Fail-on-revert: restoring the linear scan blows the scaling test's 3 s budget (N=80000: ~20 s vs ~0.08 s).

### iter.Next(&key, nil) crash
- cilium/ebpf v0.20 panics when iterating non-empty maps with nil value pointer
- **Fix:** Always use `var val []byte; iter.Next(&key, &val)`

### TTY detection for daemon mode
- `os.Stdin.Stat()` with `os.ModeCharDevice` returns true for `/dev/null` (it IS a character device)
- Caused CLI to start under systemd, read EOF from /dev/null, exit immediately
- **Fix:** Use `unix.IoctlGetTermios(fd, unix.TCGETS)` — only succeeds on real terminals

## SR-IOV Bugs

### SR-IOV in Incus VMs
- `nictype: sriov` and `nictype: physical` both fail with `DeviceNotFound` (agent race)
- **Fix:** Use `type: pci` with `address=<BDF>` instead — hot-add after boot
- VFs on enp101s0f0np0 (X710) have individual IOMMU groups so VFIO works

### SR-IOV PCI passthrough pattern
```bash
vf_pci=$(readlink -f /sys/class/net/enp101s0f0v0/device | xargs basename)
incus config device add VM internet pci address=$vf_pci
```
VF appears as enp10s0f0 inside VM (NOT enp10s0 as initially expected).

## Phase 39+ Bugs

### xdp_policy BPF stack overflow (528 > 512 bytes)
- Combined stack of `xdp_policy_prog` + `nat_pool_alloc_v6` was 528 bytes (512 limit)
- Two 16-byte stack arrays in IPv6 SNAT path: `orig_src_ip_save[16]` and `alloc_ip_v6[16]`
- **Fix:** Replace stack arrays with per-CPU scratch map fields:
  - `alloc_ip_v6[16]` → `meta->nat_src_ip.v6` (scratch buffer)
  - `orig_src_ip_save[16]` → direct `meta->src_ip.v6` reads (not yet modified)
- **Commit:** 8162f9f

### uint32ToIP() NAT display bug
- `uint32ToIP()` in server.go used `binary.BigEndian.PutUint32` for rendering
- NAT IPs displayed with swapped octets: `10.2.0.10` instead of `10.0.2.10`
- **Fix:** Changed to `binary.NativeEndian.PutUint32`

### Interfaces not UP after XDP/TC attachment
- XDP/TC attachment doesn't bring interfaces UP
- **Fix:** Added `netlink.LinkSetUp()` after attachment
- Note: use `netlink.LinkByIndex()`, not `*net.Interface` (different types)

### Management DHCP route shadowing FRR
- systemd-networkd installs DHCP default route (distance 0) on enp5s0
- Shadows FRR DHCP-learned routes (distance 200)
- **Fix:** Set `UseRoutes=false` in `/etc/systemd/network/enp5s0.network`

### BPF_FIB_LKUP_RET_NO_NEIGH (rc=7) cold ARP forwarding failure
- `bpf_fib_lookup` returns NO_NEIGH when route exists but no ARP/NDP entry
- Does NOT fill dmac/smac fields — cannot `bpf_redirect_map` with zero MACs
- **Forward path fix:** XDP_PASS original (un-NAT'd) packet at xdp_zone → kernel forwards → triggers ARP → TC drops (no CT match, `ingress_ifindex != 0`)
- **Return path issue:** SNAT'd return packet has local dst IP → kernel delivers locally instead of forwarding → no ARP trigger for original sender
- **Fix:** Periodic ping-based neighbor resolution (every 15s) for DNAT pools, static NAT, gateways, address-book hosts
- STALE ARP entries work fine with `bpf_fib_lookup` (returns SUCCESS)
- **Files:** `xdp_zone.c`, `tc_main.c`, `tc_conntrack.c`, `daemon.go`

### arping doesn't populate kernel ARP table with XDP attached
- `arping` uses PF_PACKET raw sockets for ARP — ARP replies received by arping but NOT by kernel ARP handler when XDP is attached
- **Fix:** Use `ping` instead of `arping` for proactive neighbor resolution — `ping` triggers the kernel's own ARP/NDP resolution before sending ICMP
- Note: only affects arping tool, not ARP protocol itself. Kernel-initiated ARP (from routing decisions) works fine with XDP.

### TC egress: kernel-forwarded packets leak without session
- When XDP_PASS sends a packet to kernel (e.g., NO_NEIGH case), kernel may forward it through TC egress
- Without conntrack match, un-NAT'd packets would leak to destination
- **Fix:** Check `skb->ingress_ifindex != 0` (indicates kernel forwarded, not locally originated) in tc_conntrack → `TC_ACT_SHOT`
- **Files:** `tc_main.c` (propagate ingress_ifindex), `tc_conntrack.c` (drop on CT miss)

## Performance Bugs

### bpf_printk consuming 55%+ CPU (`e104112`)
- Debug tracing left in production BPF → always remove for production

### CHECKSUM_PARTIAL NAT checksum corruption (`0950a1f`)
- Non-complemented update needed for PH seed in CHECKSUM_PARTIAL

### Generic XDP 16% CPU overhead (`f9edb92`)
- All interfaces forced generic because iavf lacks native XDP
- Fix: Per-interface mode selection with `redirect_capable` map

### Cross-CPU NAT port collisions (`7aa77f0`)
- Fix: Per-CPU port counter partitioning

## Hitless Restart Bugs

### Destructive daemon shutdown kills sessions and routes
- `daemon.Close()` called `frr.Clear()`, `dhcp.StopAll()`, `routing.ClearVRFs()`
- Fix: Non-destructive SIGTERM; full teardown only via `xpfd cleanup`

### DHCP context cancellation removes addresses on restart
- DHCP context derived from daemon ctx → cancelled on SIGTERM
- Fix: Use `context.Background()` for DHCP clients

### Premature link.Update() with empty config maps
- Programs replaced before policies/NAT/screen compiled → brief deny-all
- Fix: Defer all `link.Update()` to end of `Compile()`

### Stale generic XDP pinned links after mode change
- `link.Update()` replaces program but NOT attachment mode
- Fix: One-time `xpfd cleanup` + fresh start after structural changes

### PROG_ARRAY entries cleared on daemon exit (CRITICAL)
- Kernel calls `bpf_fd_array_map_clear()` on PROG_ARRAY maps when `usercnt` drops to 0
- `usercnt` tracks userspace references: FDs + pin files
- `xdp_progs` and `tc_progs` were NOT pinned → daemon exit closes all FDs → `usercnt=0` → entries cleared
- Map itself survived (embedded ref from xdp_main_prog via pinned link), but ALL entries gone
- xdp_main tail calls fail → `XDP_PASS` → all traffic bypasses XDP pipeline → kernel forwards raw
- SNAT return traffic (dst=firewall IP) reaches kernel TCP → RST → kills connections
- Forward traffic goes through kernel un-SNAT'd → server RSTs unknown source
- **Fix:** Add `xdp_progs` and `tc_progs` to `pinnedMaps` in `loader_ebpf.go`
- Pin file maintains `usercnt > 0` → entries survive → tail calls work → hitless restart
- On restart, new daemon reuses pinned map and atomically updates entries with new program FDs
- **File:** `pkg/dataplane/loader_ebpf.go`

### Random zone/screen/address/app ID assignment across restarts
- Go `for name := range map` iterates in random order → zone IDs change every restart
- Session entries store zone IDs → stale after restart → policy lookups fail
- **Fix:** Sort map keys before iterating (`slices.Sort(maps.Keys(...))`)
- **File:** `pkg/dataplane/compiler.go`

### Map clearing before repopulation during compile
- `ClearIfaceZoneMap()`, `ClearZonePairPolicies()`, etc. called BEFORE new entries written
- Brief window: running BPF programs see empty maps → packets dropped/misclassified
- **Fix:** Write new entries first (overwrite), then delete stale entries not in new config
- **File:** `pkg/dataplane/compiler.go`, `pkg/dataplane/maps.go`

### TTL expiry check after NAT breaks mtr/traceroute (`df28c91`)
- TTL<=1 check was in `xdp_forward`, AFTER `xdp_nat` had rewritten src IP (SNAT) and MACs
- XDP_PASS delivered modified packet to kernel: wrong dst MAC → silent drop, or ICMP Time Exceeded sent to SNAT'd source (firewall's own WAN IP)
- Hop 1 showed `???` in mtr for both zone-to-zone and zone-to-WAN paths
- **Fix:** Moved TTL check to top of `xdp_nat_prog`, before any NAT rewrite
  - Kernel receives original unmodified packet (correct IPs + MACs)
  - Correctly generates ICMP Time Exceeded from ingress interface IP to original sender
  - Includes ingress VLAN tag push-back for sub-interface delivery
- **Key insight:** TTL must be checked BEFORE NAT, just like real routers (Junos checks TTL before NAT translation)
- **Files:** `bpf/xdp/xdp_nat.c` (added check), `bpf/xdp/xdp_forward.c` (removed redundant checks)

### Non-NAT established sessions skip xdp_nat TTL check
- Conntrack fast-path for established sessions without NAT flags tail-calls directly to `XDP_PROG_FORWARD`, skipping `xdp_nat` entirely
- `xdp_conntrack.c:64-66`: `next_prog = XDP_PROG_FORWARD` when no SNAT/DNAT flags
- xdp_forward had NO TTL check (removed in `df28c91`), so TTL=1 packets got decremented to 0 and forwarded to destination (Linux accepts TTL=0 at final hop)
- Zone-to-WAN mtr worked (SNAT → goes through xdp_nat), zone-to-zone mtr showed destination at hop 1 (no NAT → skips xdp_nat)
- **Fix:** Added TTL/hop_limit check in `xdp_forward` BEFORE MAC rewrite, as safety net for non-NAT path
  - For NAT'd traffic, `xdp_nat` catches TTL<=1 first (before NAT rewrite, correct IPs)
  - For non-NAT traffic, `xdp_forward` catches TTL<=1 (IPs unchanged, correct for ICMP TE)
- **Key insight:** TTL check must exist in BOTH `xdp_nat` (for NAT'd traffic) AND `xdp_forward` (for non-NAT established sessions)
- **Files:** `bpf/xdp/xdp_forward.c` (added TTL check before MAC rewrite)

## Phase 47+ Bugs

### Teardrop screen check field name (`a2e6113`)
- Screen compilation used `TCP.TearDrop` but the field is `IP.TearDrop`
- Teardrop is an IP fragmentation attack, not TCP
- **Fix:** Changed to `screenCfg.IP.TearDrop` in compiler.go
- **File:** `pkg/config/compiler.go`

### SNAT TCP sessions dying on daemon restart (`a030446`)
- SNAT sessions have forward (original→NAT'd) and reverse (NAT'd→original) entries
- On restart, dnat_table was cleared before new entries written
- Return traffic arrived during gap → no dnat_table entry → dropped → TCP RST
- **Fix:** Write dnat_table entries BEFORE clearing session-related maps
- Populate-before-clear pattern extended to dnat_table
- **File:** `pkg/dataplane/compiler.go`

### Flat set syntax test using wrong parser (`ac9354b`)
- `TestMultiTermApplicationSetSyntax` used `NewParser(input)` with flat set commands
- Parser treats newlines as whitespace → all set lines merged into one giant node
- **Fix:** Use `ParseSetCommand()` + `tree.SetPath()` (standard pattern for all flat set tests)
- **Gotcha:** NEVER use `NewParser()` for flat `set` syntax — always use SetPath loop
- **File:** `pkg/config/parser_test.go`

### Show system processes in remote CLI (`be7a24b`)
- Remote CLI's `show system processes` was not dispatched to ShowText RPC
- **Fix:** Added routing to use ShowText("processes") in cmd/cli/main.go

### Show chassis/storage routing in remote CLI (`5d853ca`)
- `show chassis` and `show system storage` not handled in remote CLI
- **Fix:** Added ShowText RPC dispatch for these commands

### uint32ToIP() NAT display byte order (FIXED previously)
- `uint32ToIP()` in server.go used `binary.BigEndian.PutUint32` for rendering
- NAT IPs displayed with swapped octets: `10.2.0.10` instead of `10.0.2.10`
- **Fix:** Changed to `binary.NativeEndian.PutUint32`

## Sprint GAP-1 Bugs

### SNAT multiple source-address list parsing (FIXED, Sprint GAP-1)
- `source-address [ 10.0.1.0/24 10.0.2.0/24 ]` only captured first address
- Compiler used `rule.Match.SourceAddress` (singular) — only first element from bracket list
- **Fix:** Added `SourceAddresses []string` field; compilation now iterates all addresses, creating one BPF rule per source address with shared counter ID
- **File:** `pkg/dataplane/compiler.go`, `pkg/config/types.go`

### BPF source-port range byte-order (FIXED, Sprint GAP-1, task #17)
- `xdp_policy.c` compared `__be16` source port against `app_value.src_port_low/high` stored via `htons()`
- Both `meta->src_port` and map values are in network byte order → comparison is correct (both sides NBO)
- Initially reported as bug but confirmed not an issue since BPF map values written with `htons()` match `meta->src_port` which is also `__be16`

### TC forward mirror counter race (FIXED, Sprint GAP-1)
- `__sync_fetch_and_add(cnt, 1)` return value was used for rate sampling before increment completed
- **Fix:** Read `*cnt` first, then `__sync_fetch_and_add(cnt, 1)` separately
- **File:** `bpf/tc/tc_forward.c`

### SetPath leaf duplication bug (FIXED, `13daf45`)
- `SetPath()` always appended leaf nodes without checking for existing leaves with same keyword
- `set system host-name X` repeatedly → accumulated duplicate entries instead of replacing
- **Root cause:** No distinction between single-value (host-name) and multi-value (source-address) leaves
- **Fix:** Added `multi` flag to `schemaNode` + `children == nil` check:
  - Single-value leaves (`args > 0`, `!multi`, `children == nil`): replace existing leaf by keyword
  - Multi-value leaves (`multi: true`): accumulate (skip exact duplicates)
  - Named containers with children (interface, neighbor): never replace (different values = different entries)
- **File:** `pkg/config/ast.go`

## Sprint VRRP-NATIVE Bugs

### VRRP shared socket misses multicast on VLAN sub-interfaces (FIXED, `70b107c`)
- Shared `ip4:112` raw socket on `0.0.0.0` didn't receive VRRP multicast on VLAN sub-interfaces (e.g. `ge-7-0-1.50`)
- Both cluster nodes became MASTER for VRID 101 (WAN VLAN) — each thought the other was dead
- tcpdump confirmed packets were on the wire; host socket just didn't deliver them
- **Root cause:** Linux raw socket multicast on VLAN sub-interfaces requires `SO_BINDTODEVICE` to the specific sub-interface
- **Fix:** Changed from shared socket in Manager to per-instance sockets with `SO_BINDTODEVICE` + per-interface `JoinGroup(224.0.0.18)`
- **Files:** `pkg/vrrp/manager.go` (removed shared socket), `pkg/vrrp/instance.go` (added per-instance socket+receiver)

### VRRP self-sent packets not filtered (FIXED, `70b107c`)
- Original receiver didn't filter self-sent VRRP advertisements
- Could cause state machine confusion if own multicast packets were received
- RFC 5798 §6.4.2/6.4.3 requires filtering advertisements from own source IP
- **Fix:** Added `localIP` field to vrrpInstance, resolved from interface addresses on socket open; receiver skips packets where `hdr.Src.Equal(vi.localIP)`
- **File:** `pkg/vrrp/instance.go`

### RETH VRRP instances missing from CLI status (FIXED, `70b107c`)
- `show security vrrp` on cluster nodes showed "No VRRP groups configured"
- gRPC `GetVRRPStatus` only called `CollectInstances(cfg)` (user VRRP groups) but NOT `CollectRethInstances(cfg, localPri)` (cluster RETH VRRP instances)
- **Fix:** Added `CollectRethInstances()` call in gRPC handler when cluster manager is available, using `s.cluster.LocalPriorities()` for priority mapping
- **File:** `pkg/grpcapi/server.go`

## Session Sync Bugs

### Forward-only session sync — missing reverse entries (FIXED)
- **Symptom:** After VRRP failover, return traffic on takeover node had no conntrack match → policy evaluation as new connection → dropped
- **Root cause:** Periodic sweep sent only forward entries (`IsReverse==0`). `handleMessage()` installed forward entry only, without creating the reverse entry. Bulk sync sent both, but sweep didn't.
- **Fix:** `handleMessage()` now creates reverse entry from each forward entry: copies value, sets `IsReverse=1`, sets `ReverseKey = original key`, installs via `SetSessionV4/V6(val.ReverseKey, revVal)`
- **File:** `pkg/cluster/sync.go` (`handleMessage()` — syncMsgSessionV4/V6 cases)

### Missing dnat_table entries for SNAT sessions (FIXED)
- **Symptom:** After failover, SNAT return traffic not de-NAT'd. `xdp_zone` couldn't find dnat_table entry for dst rewrite → conntrack lookup used SNAT'd dst IP → miss → new connection → kernel RST
- **Root cause:** SNAT sessions need dnat_table entries for pre-routing dst rewrite on takeover node. dnat_table entries are derived from sessions (not config), so they were never synced.
- **Fix:** `handleMessage()` creates dnat_table entry for each forward SNAT session: `{Protocol, NATSrcIP, NATSrcPort} → {SrcIP, SrcPort}`
- **Also fixed:** Delete messages now clean up reverse entries AND dnat_table entries (lookup before delete)
- **File:** `pkg/cluster/sync.go`

### NO_NEIGH drops synced SNAT sessions after failover (FIXED, `0080cbc`)
- **Symptom:** After VRRP failover, takeover node lacks ARP entries for next hops → `bpf_fib_lookup` returns `NO_NEIGH` (rc=7) → `XDP_PASS` with un-NAT'd packet → kernel sends RST (local dst) or forwards with wrong source
- **Root cause:** ARP/NDP caches are per-node. Secondary never sent traffic to SNAT destinations → cold ARP cache
- **Fix (two parts):**
  1. **BPF:** In `xdp_zone.c`, for existing sessions (sv4/sv6 not NULL) with NO_NEIGH, XDP_DROP instead of XDP_PASS. Dropping is safe because ARP warmup resolves neighbors within ~50ms; TCP retransmits at ~200ms recover the connection.
  2. **Userspace:** `warmNeighborCache()` in `daemon.go` — on VRRP MASTER transition, iterates synced sessions and triggers kernel ARP/NDP resolution via UDP connect to each unique destination IP.
- **Also added:** `SendNDSolicitation()` in `garp.go` for IPv6 neighbor resolution during failover
- **Files:** `bpf/xdp/xdp_zone.c`, `pkg/daemon/daemon.go`, `pkg/cluster/garp.go`

### Monotonic clock skew in GC — premature session expiry (FIXED, `0080cbc`)
- **Symptom:** Synced sessions carry remote node's monotonic timestamps (`Created`, `LastSeen`). If local node uptime > remote uptime: `LastSeen + Timeout < local_now` → premature expiry within seconds
- **Root cause:** `CLOCK_MONOTONIC` is relative to boot time. Node reboots (low timestamp), syncs to long-running peer (high local time) → GC kills synced sessions
- **Fix:** Set `LastSeen = local monotonic time` when installing synced sessions in `handleMessage()`. `Created` kept original for display.
- **File:** `pkg/cluster/sync.go`

### BPF verifier: pointer bitwise OR prohibited (FIXED, `0080cbc`)
- **Symptom:** xdp_zone_prog failed to load with `"R1 bitwise operator |= on pointer prohibited"`
- **Root cause:** `if (sv4 || sv6)` where both are `struct session_*_value *` pointers compiles to a BPF `|=` instruction on pointer registers, which the verifier rejects
- **Cascade failure:** BPF load fail → `d.dp = nil` → `applyConfig` never called → VRF never created → `mgmtVRFInterfaces` empty → `vrfDevice=""` → TCP bind to VRF-only fabric address fails with EADDRNOTAVAIL → session sync never starts
- **Fix:** Changed to separate `if (sv4 != NULL)` and `if (sv6 != NULL)` checks
- **Key insight:** Never use C logical OR (`||`) on two BPF pointer values — the compiler may emit `|=` which the verifier rejects. Use separate NULL checks instead.
- **File:** `bpf/xdp/xdp_zone.c`

### Sync start retry count insufficient (FIXED, `0080cbc`)
- **Symptom:** Original 10 retries (20s) exhausted before VRF was ready on slow starts
- **Fix:** Increased from 10 to 30 retries (60s total) in `startClusterComms()` goroutine
- **File:** `pkg/daemon/daemon.go`

### FIB cache not synced (BY DESIGN — not a bug)
- Session FIB cache fields (`fib_ifindex`, `fib_dmac`, `fib_smac`, `fib_gen`) are zeroed in synced sessions
- Interface indices and MAC addresses differ between cluster nodes
- Zero `fib_ifindex` forces fresh `bpf_fib_lookup` on first packet → correct local FIB cache populated
- No fix needed — this is correct behavior

## HA State Machine Bugs (Sprint ha-fixes)

### Per-RG master state last-event-wins (HIGH — FIXING)
- **Symptom:** VRRP runs per-interface instances but `rethMasterState` (`daemon.go:109`) is `map[int]bool` keyed only by rgID. Last event from any interface overwrites state for the entire RG. If one interface goes BACKUP while another stays MASTER, the RG falsely shows BACKUP
- **Root cause:** `setRethMasterState(rgID, isMaster)` collapses all interfaces into one bool. Multi-interface RGs (e.g. WAN + LAN per RG) can have split state during transient convergence
- **Impact:** Wrong `rg_active` BPF map value → traffic dropped or misrouted during partial convergence
- **Fix:** Change key to `(rgID, interface)` pair. `isRethMasterState(rgID)` returns true only when ALL instances for that RG are MASTER
- **Files:** `pkg/daemon/daemon.go:109` (rethMasterState), `setRethMasterState`, `isRethMasterState`, `snapshotRethMasterState`

### HA state events are lossy (HIGH — FIXING)
- **Symptom:** VRRP event channel (64-buffer, `instance.go:568`) and cluster event channel (64-buffer, `cluster.go:506`) use non-blocking sends (`select { case ch <- event: default: }`). Under load or rapid state transitions, events are silently dropped
- **Impact:** Dropped MASTER→BACKUP or cluster state events leave stale `rg_active` and blackhole route state. Traffic continues flowing to a node that should be inactive, or is dropped on an active node
- **Fix:** Add periodic reconciliation loop (e.g. every 2s) that verifies rg_active and blackhole routes match actual VRRP/cluster state
- **Files:** `pkg/vrrp/instance.go:568`, `pkg/cluster/cluster.go:506`

### rg_active dual-writer race (HIGH — FIXING)
- **Symptom:** `watchClusterEvents` (`daemon.go:3686`) and `watchVRRPEvents` (`daemon.go:3783`) independently call `UpdateRGActive()` from separate goroutines with no sequencing guard. A late cluster event can overwrite a correct VRRP-driven state
- **Impact:** BPF `rg_active` map gets incorrect value → XDP_DROP active traffic or pass inactive traffic
- **Fix:** Create a single per-RG state machine struct that funnels both cluster and VRRP transitions. Replace direct `UpdateRGActive`/`BumpFIBGeneration` calls in both handlers
- **Files:** `pkg/daemon/daemon.go:3686` (watchClusterEvents), `pkg/daemon/daemon.go:3783` (watchVRRPEvents)

### VLAN AF_PACKET filter drops tagged VRRP adverts (MEDIUM — FIXING)
- **Symptom:** AF_PACKET BPF filter in `openAfPacketReceiver` (`manager.go:408`) only checks ethertype 0x0800 at offset 12. 802.1Q-tagged frames have 0x8100 at offset 12 (TPID), actual ethertype at offset 16. Tagged VRRP adverts silently dropped by the socket filter
- **Also:** `ethHeaderLen` hardcoded to 14 in `receiverAfPacket` (`instance.go:414`). VLAN-tagged frames have 18-byte Ethernet+VLAN header → IP header parsed at wrong offset
- **Impact:** VRRP on VLAN interfaces may miss peer adverts → split-brain (mitigated by XDP VLAN tag restoration sending packets through kernel stack, but filter still incorrect)
- **Fix:** Add 802.1Q (0x8100) branch to BPF filter checking ethertype at offset 16. Detect VLAN tag in receiverAfPacket and adjust ethHeaderLen to 18
- **Files:** `pkg/vrrp/manager.go:408`, `pkg/vrrp/instance.go:414`

### ForceRGMaster preempt leak (MEDIUM — FIXING)
- **Symptom:** `ForceRGMaster` (`manager.go:237`) sets `vi.cfg.Preempt=true` temporarily to trigger immediate MASTER transition. Restoration depends on the next debounced `UpdateInstances` call (500ms). During this window, unintended preemption can occur if a higher-priority peer sends adverts
- **Impact:** 500ms preemption window where the instance will preempt based on priority even if `Preempt` was configured as false. May cause unexpected failover in non-preempt HA setups
- **Fix:** Use a `forcePreemptOnce` flag instead of modifying the `Preempt` config field. Consume the flag on first use so it doesn't persist
- **Files:** `pkg/vrrp/manager.go:237`

### Monitor weight changes have no dampening (MEDIUM — FIXING)
- **Symptom:** Interface state changes in `monitor.go:180` immediately trigger `SetMonitorWeight` → `recalcWeight` → election. A flapping interface (up/down/up/down) causes rapid failover oscillation between cluster nodes
- **Impact:** Each state flip triggers a full weight recalculation and potential primary/secondary transition. At 30ms VRRP intervals, each failover costs ~60ms of traffic disruption. Rapid flapping can cause sustained outage
- **Fix:** Add consecutive failure/success thresholds (3 each) and hold-down timer (5s) before allowing state transitions
- **Files:** `pkg/cluster/monitor.go:180`

### Blackhole route tracking is memory-only (LOW — FIXING)
- **Symptom:** `blackholeRoutes` map (`daemon.go:148`) tracks injected RTN_BLACKHOLE routes but is lost on daemon restart. Stale kernel blackhole routes from a previous daemon run survive and cannot be cleaned up — they silently drop traffic matching RETH subnets
- **Impact:** After daemon restart, stale blackhole routes may drop traffic for subnets that should be reachable. Requires manual `ip route del` to fix
- **Fix:** Add startup reconciliation sweep that scans kernel routes for RTN_BLACKHOLE matching RETH subnets and removes them
- **Files:** `pkg/daemon/daemon.go:148` (blackholeRoutes map)

### IPv6 VRRP advertisements (RESOLVED — implemented)
- **Status:** Implemented for both send and receive. `sendAdvert`
  (`pkg/vrrp/instance.go`) sends VRRPv3 IPv6 adverts when IPv6 VIPs are
  present via `sendPacketIPv6` (src: link-local, dst: `ff02::12`, hop
  limit 255, pseudo-header checksum). `receiverIPv6` (ip6:112) and
  `parseAfPacketIPv6` handle receive; the AF_PACKET BPF filter in
  `pkg/vrrp/manager.go` matches ethertype `0x86DD` for both tagged and
  untagged frames. No remaining IPv6 send/receive gap.

## Sprint ha-fixes-2 (2026-03-01) — Issues #84, #86, #87, #92, #93

### VRRP watcher uses background context instead of daemon ctx (#84, FIXED)
- **Symptom:** `watchVRRPEvents` at `daemon.go:582` used `context.Background()` instead of daemon `ctx`. VRRP watcher outlived daemon shutdown, causing goroutine leaks and potential races during restart
- **Fix:** Changed to use daemon `ctx`, added VRRP watcher to shutdown waitgroup. VRRP manager `Stop()` now closes events channel to unblock watchers
- **Files:** `pkg/daemon/daemon.go`, `pkg/vrrp/manager.go`

### reconcileRGState does not repair VRRP control posture (#86, FIXED)
- **Symptom:** If cluster/VRRP events were dropped, VRRP control actions (ResignRG, priority, forced MASTER) were never reconciled. Node could stay in wrong VRRP state indefinitely
- **Initial fix (`74d2693`):** Extended `reconcileRGState()` with delay-based posture check (10s sustained mismatch via `CheckVRRPPosture`). Used `ForceRGMaster` for NeedsMaster case
- **Follow-up fix (`8b288f4`):** ForceRGMaster in reconcile loop caused forwarding bug — overrode `preempt=false` VRRP config after reboot. After SecondaryHold→Primary (initial boot), VRRP should stay BACKUP respecting non-preempt, but posture reconciliation forced preemption 10s later, disrupting traffic. Fix: replace ForceRGMaster with `UpdateRGPriority(rgID, 200)` — re-sends priority without overriding preempt config. Also added no-instances guard to prevent log spam when member interfaces missing
- **Key lesson:** Reconcile loops must NEVER override design intent — only re-send dropped signals, don't force state transitions that bypass configuration (preempt=false)
- **Files:** `pkg/daemon/daemon.go` (reconcileRGState), `pkg/daemon/rg_state.go` (CheckVRRPPosture), `pkg/daemon/rg_state_test.go`

### HA endpoints one-shot — not reconfigured on runtime config changes (#87, FIXED)
- **Symptom:** `startClusterComms()` called once at daemon boot. If cluster control/fabric settings changed at runtime via commit, heartbeat/session-sync endpoints were not restarted with new settings
- **Fix:** Config apply path now detects HA transport config changes (control-interface, peer-address, fabric-interface, fabric-peer-address). If changed, cancels existing cluster comms context and restarts with new settings. Dedicated cancel func for independent restart
- **Files:** `pkg/daemon/daemon.go`

### Stale peer RG entries persist across heartbeats (#92, FIXED)
- **Symptom:** `handlePeerHeartbeat()` updated `peerGroups` entries present in heartbeat but never pruned RGs missing from the packet. If peer removed an RG, local node kept stale state forever → incorrect election decisions
- **Fix:** Rebuild `peerGroups` from scratch each heartbeat (authoritative map replacement) instead of incremental append/update
- **Files:** `pkg/cluster/cluster.go`

### reconcileRGState does not repair RA/DHCP service ownership (#93, FIXED)
- **Symptom:** If VRRP events were dropped, per-RG services (RA/DHCP) were never reconciled. Active node could lack RA/DHCP services, or inactive node could hold them
- **Fix:** Extended `reconcileRGState()` to repair per-RG services: if `tr.Active` → call `applyRethServicesForRG(rgID)` (idempotent); if `!tr.Active` → call `clearRethServicesForRG(rgID)` (idempotent)
- **Files:** `pkg/daemon/daemon.go` (reconcileRGState function)

## Known Open Issues

### Configure mode double echo (FIXED)
- Extra echo characters when typing in configure mode via `incus exec -- cli`
- Was PTY multiplexing issue between incus exec and chzyer/readline

### flow_config_map not found warning (FIXED)
- Was caused by `flow_config_map` not being extracted from zone objects during Load()
- Fixed: `loader_ebpf.go:197` extracts `zoneObjs.FlowConfigMap` into `m.maps`
- Confirmed working: "flow config compiled" with tcp_mss_ipsec=1350 on all recent deploys

### rib-group ip rule priority too high (FIXED)
- `ip rule add from all lookup <table> pref 200` was consulted BEFORE main table (pref 32766)
- If VRF table had a default route, ALL traffic used that default instead of main table routes
- Symptom: firewall couldn't ping anything on trust0/untrust0 — all traffic routed via dmz-vr's default
- **Fix:** Changed ribGroupRulePriority from 200 to 33000 (after main table at 32766)
- Also added legacy cleanup (200-299 range) for migration from old priority

### VLAN interface name stripping in FRR (FIXED, `89a1a5e`)
- Phase 50b qualified next-hop stripped ALL dot-suffixes from interface names
- `wan0.50` (VLAN sub-interface) → `wan0` (wrong device)
- IPv6 default route pointed to `wan0` instead of `wan0.50`, gateway unreachable
- **Fix:** Only strip `.0` suffix (Junos default unit), not VLAN suffixes like `.50`
- **File:** `pkg/frr/frr.go`

### configstore refactor broke initial config loading (FIXED)
- `Store.Load()` reads only from DB (active.json), not from text config file
- On first start (no DB), daemon started with empty config — no FRR routes, no interface management
- **Fix:** `daemon.bootstrapFromFile()` — reads text config, parses, LoadOverride + Commit to seed DB
- Subsequent restarts load from DB normally

### NAT64 three-bug saga (FIXED `1cde2af`)
1. **Zone FIB miss for 64:ff9b::/96**: No kernel IPv6 route for NAT64 prefix → bpf_fib_lookup failed → packet treated as local. Fix: detect nat64_prefix_map in zone's FIB-failed branch, do IPv4 FIB for embedded v4 dst.
2. **Reverse path NO_NEIGH (rc=7)**: After 4→6 xlate, NDP cache empty for client → redirect failed. Fix: accept NO_NEIGH, save ingress MAC before bpf_xdp_adjust_head(-20), XDP_PASS for kernel NDP resolution.
3. **ICMPv6 checksum wrong**: Incremental ICMPv4→ICMPv6 conversion failed (ICMPv4 has no pseudo-header, ICMPv6 does). Fix: from-scratch checksum — zero field, sum IPv6 pseudo-header + all ICMPv6 words.
- **Key lesson:** `bpf_xdp_adjust_head(-20)` invalidates ALL pointers and overwrites old Ethernet header with IPv6 data. Must save MAC before adjust_head.
- **Key lesson:** For ICMP checksum conversion between v4/v6, always use from-scratch recomputation — incremental is too error-prone due to pseudo-header asymmetry.

### NAT64 ICMP traceroute (FIXED `91bdd38`)
Three fixes for mtr/traceroute6 over NAT64 (64:ff9b::/96):
1. **Wrong echo ID in nat64_state**: For ICMPv6 echo, policy sets `meta->src_port = alloc_v4_port` (SNAT'd) but NAT64 used this as `old_sport` for `nat64_state.orig_src_port`. When ICMP errors came back, the translated ICMPv6 embedded packet had the SNAT'd echo ID instead of the original — mtr couldn't match. Fix: use `meta->dst_port` (original echo ID, unchanged by policy) for ICMPv6 protocol.
2. **No ICMP error 4→6 translation**: Added `nat64_icmp_error_4to6()` for full IPv4 ICMP error → ICMPv6 error translation (RFC 7915). Handles Time Exceeded, Dest Unreachable, Param Problem with bpf_xdp_adjust_head(-40) to grow packet.
3. **NPTv6 reverse in error path**: nat64_state stores post-NPTv6 (external prefix) addresses. Added INBOUND NPTv6 lookup in the error translation to reverse back to internal prefix before checksum/routing.
- **Key lesson:** For ICMP echo in NAT64, `meta->src_port` is unreliable after policy stage — always use `meta->dst_port` for the original echo ID.
- **Key lesson:** UDP traceroute worked but ICMP didn't — protocol-specific embedded L4 handling is where bugs hide.

### VRRP split-brain on VLAN sub-interfaces (FIXED, `e018918`)
- **Symptom:** Both cluster nodes became MASTER for VRID 101 (WAN VLAN sub-interface ge-*-0-1.50)
- **Root cause (two parts):**
  1. XDP strips VLAN tags in xdp_main for pipeline processing. VRRP bypass XDP_PASS'd without restoring the tag → kernel delivered to parent interface (no IPv4 config) → silently dropped
  2. Even with tag restored, raw IP sockets (AF_INET SOCK_RAW proto 112) don't receive multicast on VLAN sub-interfaces — kernel counts IpInDelivers but recvmsg never returns the packet (kernel limitation)
- **Fix (two parts):**
  1. Moved VRRP bypass in xdp_zone.c to before zone lookup; push VLAN tag back via `xdp_vlan_tag_push()` before XDP_PASS
  2. VLAN sub-interfaces use AF_PACKET (SOCK_RAW + ETH_P_ALL + PACKET_MR_PROMISC + BPF filter) for receiving. Raw IP socket kept for sending. Non-VLAN interfaces unchanged.
- **Key insight:** AF_PACKET on VLAN sub-interfaces requires PACKET_MR_PROMISC to receive multicast from remote peers. Without it, only locally-generated multicast (IP-layer loopback) is delivered. This matches tcpdump's behavior (always sets PACKET_MR_PROMISC).
- **Key insight:** VIP-aware local IP selection needed — during split-brain both nodes have the VIP, so using VIP as source address causes peer to filter our adverts as "self-sent"
- **Files:** `bpf/xdp/xdp_zone.c`, `pkg/vrrp/instance.go`, `pkg/vrrp/manager.go`

### VRRP failover failure on non-VLAN interfaces + RETH VIP reconciliation (FIXED, `d951626`)
- **Symptom:** When fw0 rebooted, fw1 didn't serve WAN traffic for ~28 seconds. Also, fw1's LAN RETH interface (ge-7-0-0) was stuck as MASTER in split-brain with fw0 after restarts.
- **Root cause (two parts):**
  1. Raw IP sockets (proto 112) with SO_BINDTODEVICE don't reliably receive VRRP multicast in generic XDP mode. AF_PACKET taps fire BEFORE generic XDP in the kernel's receive path (`__netif_receive_skb_core` → ptype_all → do_xdp_generic`). The raw IP socket relies on the packet making it through the full kernel stack after XDP, which is unreliable for multicast.
  2. `reconcileInterfaceAddresses()` in the dataplane compiler was adding RETH VIP addresses (10.0.60.1/24, 172.16.50.6/24) to BACKUP node's physical member interfaces on every config compile, bypassing VRRP's VIP management. BACKUP nodes always had VIPs they shouldn't.
- **Fix (three parts):**
  1. Use AF_PACKET receiver for ALL VRRP instances (not just VLAN sub-interfaces). Removed the `isVLAN` conditional — all interfaces now use AF_PACKET for receiving, raw IP socket for sending only.
  2. Skip `reconcileInterfaceAddresses()` for RETH interfaces (`RedundancyGroup > 0`). The link-local base addresses (169.254.RG.NODE/32) are managed by systemd-networkd via .network files; VIPs are managed by VRRP.
  3. Added `removeVIPs()` in INIT→BACKUP transition to clean up stale VIPs from previous daemon runs.
- **Key insight:** Generic XDP (`xdpgeneric`) processes packets AFTER AF_PACKET taps but BEFORE the IP stack delivers to raw sockets. AF_PACKET is the only reliable way to receive multicast when generic XDP is attached.
- **Key insight:** Group 101 (VLAN, AF_PACKET) stayed BACKUP correctly while group 102 (non-VLAN, raw socket) went to MASTER — proving the raw socket was the problem.
- **Files:** `pkg/vrrp/instance.go`, `pkg/dataplane/compiler.go`

### VRRP failover: upstream router ignores gratuitous ARP (FIXED, `7bcaee9`)
- **Symptom:** After fw1 becomes MASTER, VIPs are added and GARP is sent, but external pings to 172.16.50.6 fail for ~30 seconds. Manual `ping 172.16.50.1` from fw1 fixes it immediately.
- **Root cause:** Upstream router ignores gratuitous ARP Reply packets (opcode 2). Only updates ARP cache from standard ARP traffic (requests/responses to normal queries).
- **Verified:** tcpdump confirmed GARP exits on VLAN 50 with correct MAC/IP; fw1 can ping router after VIP add; after that ping, external pings work.
- **Fix (three parts):**
  1. Send GARP as both ARP Request (opcode 1) AND Reply (opcode 2) — some devices only honor one format. `buildGratuitousARP()` now takes opcode parameter.
  2. After GARP, synchronously send a standard ARP probe to the .1 address of each VIP subnet. The probe's source IP/MAC forces the gateway to update its ARP cache. Uses `net.ParseCIDR()` to compute subnet .1 address; skips if .1 equals our VIP (e.g., 10.0.60.1 LAN gateway).
  3. Promoted GARP/NA error logging from Debug to Warn for visibility.
- **Result:** Failover loss reduced from ~30s to ~3.5s (master-down timer only). External pings resume immediately after fw1 becomes MASTER.
- **Key insight:** Gratuitous ARP is unreliable across vendors. Always follow GARP with a standard ARP Request to the gateway — the ARP protocol guarantees the gateway updates its cache from the request's source fields.
- **Files:** `pkg/cluster/garp.go` (dual GARP + SendARPProbe + buildARPRequest), `pkg/vrrp/instance.go` (integrated gateway probe into sendGARP)

### VRRP gateway ARP probe used the PRIMARY IP, not the VIP, as sender (FIXED, #2152)
- **Symptom:** Against an upstream gateway that ignores gratuitous ARP, VIP-destined traffic stays blackholed for minutes after failover even though the ARP probe fires — defeating the whole point of the probe (the previous `7bcaee9` fix above).
- **Root cause:** `SendARPProbe(iface, targetIP)` did NOT receive the sender IP — it self-resolved it from `ifi.Addrs()`, picking the first non-`169.254.x.x` IPv4. A RETH carries both the node primary (e.g. `10.0.0.2`) and the VRRP VIP (e.g. `10.0.0.100`); the primary is usually added first, so the probe went out with sender = PRIMARY. The gateway refreshed its cache for the primary and learned nothing new about the VIP, so the VIP → MAC binding stayed stale until it aged out. Both the `sendGARP` comment and the `SendARPProbe` loop comment already SAID "use the VIP" — an intent/impl mismatch.
- **Fix:** Make the sender explicit: `SendARPProbe(iface, senderIP, targetIP)`. `vrrp.sendGARP` and `daemon.directSendGARPs` pass the in-scope VIP (`ip.To4()`); the dead self-resolution loop is replaced by the explicit parameter. The NUD_FAILED neighbor-table reprobe in `daemon.cleanFailedNeighbors` is NOT a VIP refresh — it keeps interface-derived (primary) sender semantics via the new `cluster.PrimaryIPv4` helper. Also added the `skip-if-VIP-is-.1` guard to `directSendGARPs` for parity with `sendGARP` (review #2152).
- **Test:** non-tautological — the crafted ARP frame's sender protocol address field (`pkt[28:32]`) is asserted to equal the VIP, via a call-site seam (`vrrp.arpProbeFn` / `cluster.arpProbeSend`) that executes `sendGARP`/`SendARPProbe` and captures the frame. Fails against the pre-fix self-resolve-to-primary behavior. VRRP/HA smoke (`make test-failover`) is run by the integrator.
- **Files:** `pkg/cluster/garp.go` (signature + `PrimaryIPv4` + `arpProbeSend` seam), `pkg/vrrp/instance.go` (sendGARP passes VIP via `arpProbeFn`), `pkg/daemon/daemon_ha_vip.go` (directSendGARPs passes VIP + skip-.1 guard), `pkg/daemon/daemon_neighbor.go` (reprobe uses `PrimaryIPv4`).

### Direct-mode GARP/NA burst follow-up loop was ungated — abdication mid-burst re-poisoned (FIXED, #2898)
- **Symptom (latent):** A direct-mode (no-reth-vrrp / private-rg-election) RG that abdicates within one re-announce burst's `count*50ms` window (~100ms at the default count=3, longer with a higher `gratuitous-arp-count`) keeps broadcasting gratuitous ARP / unsolicited NA for VIPs it no longer owns, briefly re-poisoning neighbor caches toward a node that has already handed the VIP off — the exact blackhole GARP exists to prevent.
- **Root cause:** #2867/#2894 gated the VRRP GARP/NA follow-up loops (`runARPBurstFollowups`/`runNABurstFollowups`) on a `cluster.BurstStillValid` predicate (still-master AND `garpEpoch` unchanged), but the direct-mode re-announce path `daemon.directSendGARPs` called the UNGATED wrappers (`cluster.SendGratuitousARPBurst`/`SendGratuitousIPv6Burst`), so its inner 50ms follow-up loop ran to completion regardless of abdication. Same bug class as #2867, different ownership model — direct-mode tracks `directVIPOwned` + `directAnnounceSeq`, not VRRP `garpEpoch`/state.
- **Fix:** `directSendGARPs` captures `directAnnounceSeq[rgID]` at burst start and builds a `directBurstStillValid(rgID, seq)` predicate returning true only while `directVIPOwned[rgID]` holds AND `directAnnounceSeq[rgID]` is unchanged. It routes every burst through the gated cluster senders (`SendGratuitousARPBurstGated`/`SendGratuitousIPv6BurstGated`) via the `directGARPBurstFn`/`directNABurstFn` seams. Abdication (`applyDirectVIPOwnership` want=false → `cancelDirectAnnounce` bumps the sequence and clears ownership) or a newer announce (sequence bump) stops the remaining follow-up frames. The first (immediate) frame in each cluster burst is sent unconditionally — only follow-ups are gated, mirroring the VRRP path. The predicate takes `directAnnounceMu`/`directVIPMu` only momentarily (between the loop's 50ms sleeps), never across a sleep.
- **Test:** `pkg/daemon/direct_garp_gate_test.go` — `TestDirectSendGARPs_AbdicationStopsFollowups` (recorder-based; abdicate on the first follow-up → at most one follow-up frame total; goes RED to 18 frames if the predicate is reverted to nil/ungated), `TestDirectSendGARPs_OwnedRunsFullBurst` (still-owning RG sends the full burst), `TestDirectBurstStillValid_Transitions` (predicate true while owned+matching, false on supersession or ownership loss). HA VIP announce path — `make test-failover` is run by the integrator.
- **Files:** `pkg/daemon/daemon_ha_vip.go` (`directBurstStillValid` + seams + gated burst routing), `pkg/daemon/direct_garp_gate_test.go`.

### IPv6 VIP unreachable: DAD failure + missing interface + RETH name (FIXED, `d03b29e`)
- **Symptom:** `ping 2001:559:8585:50::6` from host returns "Destination unreachable: Address unreachable"
- **Root cause (three bugs):**
  1. **DAD failure:** Kernel performed Duplicate Address Detection on VRRP IPv6 VIP; failed because secondary still briefly held the address. `ip -6 addr` showed `dadfailed tentative`.
  2. **Missing interface in FRR route:** `compileStaticRoutes()` only checked `prop.Children` for "interface" keyword. Config `next-hop fe80::50 interface reth0.50` has "interface" in `prop.Keys[2]` (leaf node with all keys inline), not in Children. FRR got `ipv6 route ::/0 fe80::50 5` without interface → route installed on parent device instead of VLAN sub-interface.
  3. **RETH→physical name translation:** Even with interface extracted, FRR got `reth0.50` instead of `ge-0-0-1.50`. FRR needs kernel interface names, not Junos RETH names.
- **Fix (three parts):**
  1. Added `unix.IFA_F_NODAD` flag for IPv6 VIPs in VRRP `addVIPs()` — prevents DAD failure
  2. Added inline keys scan in `compileStaticRoutes()`: `for j := 2; j < len(prop.Keys)-1; j++ { if prop.Keys[j] == "interface" { ... } }`
  3. Added `RethMap` to FRR `FullConfig`; `generateStaticRoute()` resolves RETH names to physical names via map lookup + `LinuxIfName()` for slash→dash conversion
- **Verification:** FRR config now shows `ipv6 route ::/0 fe80::50 ge-0-0-1.50 5`; kernel route shows `via fe80::50 dev ge-0-0-1.50`; ping to `2001:559:8585:50::6` works
- **Files:** `pkg/vrrp/instance.go`, `pkg/config/compiler.go`, `pkg/frr/frr.go`, `pkg/frr/frr_test.go`, `pkg/daemon/daemon.go`

### Cluster config sync broken: ${node} parse error + no reverse-sync (FIXED, `64bc9d5`)
- **Symptom:** Config changes committed on primary (fw0) never appeared on secondary (fw1). fw1 log showed: `"cluster: config sync apply failed" err="sync config parse error: line 93, column 14: unexpected character: $"`
- **Root cause (parse error):** `Format()` used `KeyPath()` which joins keys with spaces but doesn't re-quote keys containing special characters. When the original config has `apply-groups "${node}"`, the parser stores the key as `${node}` (without quotes). `Format()` then outputs it unquoted, and the receiving parser fails on `$`.
- **Fix (quoting):** Added `QuotedKeyPath()` and `quoteKey()` to `pkg/config/ast.go`. Keys containing non-identifier characters are wrapped in double quotes. All format output paths (Format, FormatPath, FormatSet, FormatCompare, FormatInheritance) updated.
- **Symptom (reverse-sync):** When fw0 returned after being down, it preempted to primary and pushed its STALE disk config to fw1, overwriting fw1's newer config. No mechanism existed for the returning node to receive config from the node that was running.
- **Root cause:** VRRP preemption via heartbeat is faster (~1s) than TCP sync connection (~3s). By the time `OnPeerConnected` fired on fw1, it was already secondary and `syncConfigToPeer()` returned early (checks `IsLocalPrimary(0)`).
- **Fix (reverse-sync):** Added `OnPeerConnected` callback to `SessionSync`. On reconnect: (a) stable node (running >30s) calls `pushConfigToPeer()` which bypasses the primary check, (b) fresh node (running <30s) skips push to avoid overwriting newer config. Added `startTime` field to Daemon.
- **Files:** `pkg/config/ast.go`, `pkg/config/parser_test.go`, `pkg/cluster/sync.go`, `pkg/daemon/daemon.go`

### RETH .link file overwritten with virtual MAC on DHCP recompile (FIXING)
- **Symptom:** After a DHCP recompile (or any config recompile), the `.link` file for RETH member interfaces was rewritten with `MACAddress=02:bf:72:...` (the virtual MAC). On reboot, the interface starts with its physical MAC, so the `.link` file no longer matches and the interface is not renamed. The daemon then cannot find the interface by its config name.
- **Root cause:** In `pkg/dataplane/compiler.go`, the `isVirtualRethMAC` block had an `if/else if` structure that made `getPermAddr()` and `originalName` recovery mutually exclusive:
  ```go
  if permMAC := getPermAddr(...); permMAC != "" {
      mac = permMAC
  } else if originalName == "" {
      // recover originalName
  }
  ```
  If `getPermAddr()` returned any value (which it does when the virtual MAC is set), the `originalName` recovery path was completely skipped, leaving `originalName=""`. The `.link` file then used `MACAddress=` with the permanent MAC (better than virtual MAC, but still fragile since MACs can change). On a fresh boot where `getPermAddr` returned the physical MAC (virtual not yet set), the `.link` was correct but fragile.
- **Deeper issue:** Even with the permanent MAC, `MACAddress=` matching is unreliable for RETH members because the MAC alternates between physical (at boot, before daemon) and virtual (after daemon programs it). `OriginalName=` matching by kernel PCI name (e.g. `enp6s0`) is stable across reboots.
- **Fix (three parts):**
  1. **compiler.go:** Restructured `isVirtualRethMAC` block to make `originalName` recovery independent of `getPermAddr`. `originalName` recovery always runs first when needed. Added `readOriginalNameFromLink()` (reads existing `.link` file) as first fallback before `getOriginalKernelName()` (reads netlink altnames). Added `findInterfaceByMAC()` to locate RETH members that exist under their kernel name when the config name lookup fails.
  2. **networkd.go:** Added `OriginalName` field to `InterfaceConfig`. `generateLink()` uses `OriginalName=` for matching when set, falling back to `MACAddress=` for non-RETH interfaces.
  3. **daemon.go:** Added `renameRethMember()` (finds interface by RETH virtual MAC, renames it) and `fixRethLinkFile()` (rewrites `.link` with `OriginalName=`). Step 2.6 in `applyConfig` now checks if the RETH member exists under its config name; if not, finds it by MAC and renames it, then fixes the `.link` file.
- **Key insight:** PCI-based kernel names (e.g. `enp6s0`) are stable across reboots and are the correct match criteria for `.link` files on RETH members. `MACAddress=` is unreliable because the MAC is physical at boot time and virtual after the daemon programs it. `OriginalName=` in systemd `.link` files matches the kernel's predictable network interface name before any udev renames.
- **Recovery chain:** `readOriginalNameFromLink()` (existing `.link` file, most reliable) -> `getOriginalKernelName()` (netlink altnames) -> `findInterfaceByMAC()` (scan by RETH virtual MAC when interface not found by name)
- **Files:** `pkg/dataplane/compiler.go`, `pkg/networkd/networkd.go`, `pkg/daemon/daemon.go`

## Reboot/Failover Bugs (Sprint: Hitless Reboot)

These bugs were discovered testing iperf3 (~4.7 Gbps reverse mode) through the cluster while rebooting the primary node (fw0). Each bug manifested as iperf3 dying after ~7 seconds post-reboot.

### VRRP VIPs flushed by networkctl reload (FIXED, `b8bb2d0`)
- **Symptom:** ~7 seconds after boot, VRRP VIPs (172.16.50.6/24, 2001:559:8585:50::6/64) disappeared from ge-0-0-1.50. iperf3 died. `ip addr show ge-0-0-1.50` showed only 169.254.1.1/32 — all VRRP VIPs gone.
- **Root cause:** DHCP lease obtained ~3s after boot triggers `"DHCP address changed, recompiling dataplane"`. Recompile writes .network files and calls `networkctl reload`. networkd asynchronously reconfigures all managed interfaces, removing addresses not in the .network file. VRRP VIPs are "foreign" addresses (added by VRRP, not in .network file) — networkd flushed them.
- **Timeline:** Boot T=0 → initial compile T+2s → DHCP lease T+3s → recompile T+5s → networkctl reload T+5s → VIPs flushed T+7s → iperf3 dies.
- **Fix:** Added `KeepAddresses bool` field to `networkd.InterfaceConfig`. When set, `generateNetwork()` emits `KeepConfiguration=static` in the .network file. systemd-networkd then preserves externally-added static addresses across reloads. Set for all RETH interfaces (both VLAN sub-interfaces and regular) since VRRP manages their VIPs.
- **Files:** `pkg/networkd/networkd.go` (KeepAddresses field, generateNetwork), `pkg/dataplane/compiler.go` (KeepAddresses: isVRRPReth)

### Cluster heartbeat bind failure not retried — permanent dual-MASTER (FIXED, `b8bb2d0`)
- **Symptom:** After simultaneous restart of both nodes (`cluster-deploy` restarts both), both became Primary for all RGs with VRRP priority 200. fw1 log showed: `"failed to start cluster heartbeat" err="listen heartbeat: listen udp4 10.99.0.2:4784: bind: cannot assign requested address"`. Both nodes stayed MASTER permanently.
- **Root cause:** On boot, the control interface (fxp1) is in VRF vrf-mgmt. Its address (10.99.0.1/30 or 10.99.0.2/30) may not be assigned yet when the daemon tries to bind the heartbeat UDP socket. Without heartbeat, the election state machine never runs — both nodes default to Primary (highest priority wins nothing because no one is checking). VRRP gets priority 200 from `LocalPriorities()` which returns 200 for Primary.
- **Fix:** Changed heartbeat startup from single-try to a retry goroutine: 30 attempts, 2s intervals (60s total). Same pattern as existing session sync retry. On bind success, heartbeat starts and election resolves — higher priority node stays Primary, lower becomes Secondary.
- **Key insight:** `cluster-deploy` restarts both nodes simultaneously. Staggered deploys (fw1 first, then fw0) avoid the issue, but the retry makes it robust for any deployment pattern.
- **File:** `pkg/daemon/daemon.go` (heartbeat start section in cluster setup)

### DHCP-triggered recompile rxvlan toggle kills iavf data path (FIXED)
- **Symptom:** iperf3 at ~4.7 Gbps dies exactly at ~7 seconds after fw0 reboot. Consistent across multiple reboots. fw1 (secondary serving traffic via VRRP failover) was fine — only the rebooted node's traffic disrupted.
- **Root cause:** DHCP lease triggers full dataplane recompile. `compileZones()` runs `ethtool -K <iface> rxvlan off` on ALL physical interfaces each recompile (the `attached` map is local, rebuilt every call). On the iavf VF (ge-0-0-1, WAN interface), toggling rxvlan causes a driver reset/reconfiguration that drops in-flight packets. Even though rxvlan was already off, the `ethtool -K rxvlan off` command still triggers the driver path that disrupts the NIC.
- **Timeline:** Matches exactly — DHCP recompile at T+5s, ethtool runs on ge-0-0-1 at T+5s, iperf3 dies at T+7s (2s TCP timeout after packets stop flowing).
- **Fix:** Added `isRxVlanOff()` helper that queries `ethtool -k <iface>` for current rx-vlan-offload state. Only calls `ethtool -K rxvlan off` if it's currently on. On recompile, rxvlan is already off → ethtool set is skipped → no driver disruption.
- **Key insight:** iavf VF driver is sensitive to ethtool feature changes — even a no-op toggle (off→off) causes internal reconfiguration. Always check-before-set for NIC offload features.
- **File:** `pkg/dataplane/compiler.go` (isRxVlanOff helper, conditional in compileZones)

### VRF binding lost after networkctl reconfigure — heartbeat/sync EADDRNOTAVAIL (FIXED, `1360a25`)
- **Symptom:** After rebooting fw0, heartbeat and session sync failed all 30 retries with `EADDRNOTAVAIL`. Both nodes became dual-MASTER. Even after adding `VRF=vrf-mgmt` to .network files (commit `73400d4`), the binding was still lost on reboot.
- **Root cause:** The daemon creates vrf-mgmt via netlink (`routing.CreateVRF()`), not via a `.netdev` file. systemd-networkd considers netlink-created VRF devices "unmanaged" (`networkctl status vrf-mgmt` shows "Network File: n/a", "State: carrier (unmanaged)"). The `VRF=` directive in `.network` files is ignored for unmanaged VRF targets. When `networkctl reconfigure` runs (triggered by DHCP recompile), it strips the VRF master binding from fxp1/fab0.
- **Timeline:** Boot T=0 → initial applyConfig T+2s → VRF created + interfaces bound → DHCP lease T+3s → recompile T+5s → `networkctl reconfigure` strips VRF bindings → heartbeat bind to 10.99.0.1:4784 in VRF fails → EADDRNOTAVAIL for 60s → cluster never forms.
- **Evidence:** `ip -d link show fxp1` showed no `master vrf-mgmt`; `ip route show table 999` was empty; addresses visible in global table but unreachable via `SO_BINDTODEVICE=vrf-mgmt`.
- **Fix:** Added step 2.7 in `applyConfig()` to re-bind management VRF interfaces after every `networkd.Apply()`. This runs after the networkctl reconfigure and restores the VRF membership regardless of what networkd does. The VRF= directive in .network files (from `73400d4`) is kept as a best-effort hint for networkd but the real fix is the explicit re-bind.
- **Key insight:** networkd's `VRF=` directive only works when networkd manages both the interface AND the VRF device. For daemon-created VRFs (via netlink), you must re-bind after any networkctl operation.
- **Files:** `pkg/daemon/daemon.go` (step 2.7 VRF re-bind), `pkg/networkd/networkd.go` (VRFName field), `pkg/dataplane/compiler.go` (VRFName for fxp/fab)

### Per-node RETH virtual MAC — FDB conflicts on shared L2 domain (FIXED, `bc66bba`)
- **Symptom:** After rebooting fw0, WAN connectivity lost entirely. Both nodes had identical RETH virtual MAC `02:bf:72:01:01:00`, causing FDB flapping on the upstream switch/bridge. Packets randomly delivered to wrong node.
- **Root cause:** `RethMAC(clusterID, rgID)` was node-agnostic — both node 0 and node 1 got the same MAC per RETH. When both nodes' physical member interfaces (ge-0-0-1 on fw0, ge-7-0-1 on fw1) are on the same L2 domain (via Incus bridge), the switch sees the same source MAC from two ports and flaps between them.
- **Fix:** Changed `RethMAC(clusterID, rgID)` to `RethMAC(clusterID, rgID, nodeID)`. MAC format changed from `02:bf:72:CC:RR:00` to `02:bf:72:CC:RR:NN`. Each node gets a unique MAC per RETH. VRRP + gratuitous ARP/NA handle failover (the MASTER advertises the VIP, clients use the VIP — the underlying MAC differences are transparent since clients use L3 addresses, not L2 MACs).
- **Key insight:** On real hardware with dedicated L2 segments per node, identical RETH MACs would work. But in virtualized environments (Incus bridges, SR-IOV VFs from same PF), both nodes share L2 → unique MACs required. Per-node MAC is universally safe.
- **Files:** `pkg/cluster/reth.go` (RethMAC signature), `pkg/cluster/reth_test.go`, `pkg/daemon/daemon.go` (programRethMAC calls), `pkg/dataplane/compiler.go` (isVirtualRethMAC)

### Bootstrap .link files use MACAddress= for RETH members — boot failure (FIXED, `f8353de`)
- **Symptom:** After reboot, RETH member interfaces not renamed. Daemon can't find `ge-0-0-0` / `ge-7-0-0` etc. All RETH connectivity lost.
- **Root cause:** `cluster-setup.sh` wrote `.link` files with `MACAddress=` for RETH members. The daemon programs a virtual MAC (`02:bf:72:CC:RR:NN`) at runtime. On reboot, the interface starts with its original physical MAC, so the `.link` file (which had the physical MAC from first boot) might not match if the daemon had rewritten it with the virtual MAC. Even if the physical MAC matched, `MACAddress=` is fundamentally fragile for RETH members because the MAC alternates between physical (boot) and virtual (daemon).
- **Fix (two parts):**
  1. `cluster-setup.sh`: Changed RETH members from `MACAddress=` to `OriginalName=` (PCI kernel name). LAN is always `enp8s0`, WAN discovered dynamically by exclusion. Non-RETH interfaces (fxp0/fxp1/fab0) keep `MACAddress=`.
  2. `daemon.go`: Added `ensureRethLinkOriginalName()` — runs unconditionally for every RETH member, detects and rewrites stale `MACAddress=` to `OriginalName=`. Uses `deriveKernelName()` which handles virtio-over-PCI (sysfs path is `virtioN`, must traverse to parent PCI device).
- **Gotcha:** Virtio interfaces have sysfs device path like `/sys/devices/.../virtio14/net/ge-0-0-0` — the device directory is `virtioN`, not a PCI address. `deriveKernelName()` traverses to parent directory to find the actual PCI address.
- **Files:** `test/incus/cluster-setup.sh`, `pkg/daemon/daemon.go`

### VRRP VIPs lost after programRethMAC on simultaneous boot (FIXED, `a4eb2b2`)
- **Symptom:** After simultaneous reboot of both nodes, fw0 becomes MASTER but missing IPv6 LAN VIP `2001:559:8585:cf01::1/64`. IPv4 VIPs sometimes also missing.
- **Root cause:** Race condition during simultaneous boot:
  1. DHCP recompile triggers early `applyConfig` → VRRP starts, adds VIPs on MASTER instances
  2. Config sync recompile triggers second `applyConfig` → `programRethMAC()` does link DOWN/UP to set virtual MAC → kernel removes ALL addresses including VRRP VIPs
  3. `UpdateInstances()` in second `applyConfig` sees no config change (same priority/preempt/VIPs) → `continue` → VIPs never re-added
- **Timeline:** Boot → DHCP recompile (T+3s) → VRRP MASTER + VIPs → config sync recompile (T+5s) → `programRethMAC` link DOWN/UP → VIPs gone → `UpdateInstances` no-ops
- **Fix:** Added `ReconcileVIPs()` method to `pkg/vrrp/manager.go` — iterates all instances, re-adds VIPs and sends GARP on any that are in MASTER state. Called from `daemon.go` after RETH MAC programming loop (step 2.6b).
- **Key insight:** `programRethMAC` link DOWN/UP is inherently destructive to addresses. Any external address manager (VRRP) must reconcile after MAC programming. `UpdateInstances()` correctly skips unchanged configs — the VIP reconciliation is a separate concern.
- **Files:** `pkg/vrrp/manager.go` (ReconcileVIPs), `pkg/daemon/daemon.go` (call site after step 2.6)

## VRRP Hardening Sprint (2026-02-28)

8 bugs found via code audit of VRRP/HA paths in HEAD b182355. All are preventive fixes — none were triggered in production yet.

### IPv6 tie-break in handleMasterRx uses IPv4-only comparison (FIXED)
- **Severity:** HIGH — causes IPv6 VRRP split-brain
- **Root cause:** `handleMasterRx()` used `pkt.SrcIP.To4()` and `vi.localIP.To4()` for RFC 5798 §6.4.3 tie-break. When both nodes run IPv6 VRRPv3, `.To4()` returns nil → `bytes.Compare(nil, nil) == 0` → tie-break does nothing → both stay MASTER
- **Fix:** Check address family — use `.To4()` for IPv4, `.To16()` with `vi.localIPv6` for IPv6
- **Files:** `pkg/vrrp/instance.go`, `pkg/vrrp/vrrp_test.go`

### Non-RETH VRRP events corrupt HA RG state (FIXED)
- **Severity:** MEDIUM — creates phantom RG entries in BPF maps
- **Root cause:** `watchVRRPEvents()` called `rgIDFromVRID()` for ALL events. Standalone VRRP (GroupID < 100) produced negative RG IDs → phantom BPF map entries
- **Fix:** Added `isRethVRID(vrid)` guard (GroupID >= 100). `rethVRIDBase` constant introduced
- **Files:** `pkg/daemon/daemon.go`, `pkg/daemon/per_rg_test.go`

### IPv6 VRRP receive fallback is IPv4-only (FIXED)
- **Severity:** MEDIUM — IPv6 VRRP silently dead when AF_PACKET unavailable
- **Root cause:** Fallback `receiver()` uses IPv4-only `ip4:112` raw socket. No warning logged
- **Fix:** Added `receiverIPv6()` goroutine reading from `vi.ipv6Conn`. Logs explicit warning about degraded IPv6 reception
- **Files:** `pkg/vrrp/instance.go`, `pkg/vrrp/vrrp_test.go`

### Reconciliation misses drift cases and starts late (FIXED)
- **Severity:** MEDIUM — up to 2s stale rg_active on startup
- **Fix (A):** Reconciliation now collects RG IDs from `d.rgStates`, `d.cluster.GroupStates()`, and VRRP instances
- **Fix (B):** Immediate `reconcileRGState()` call before entering ticker loop
- **Files:** `pkg/daemon/daemon.go`, `pkg/daemon/per_rg_test.go`

### VRRP event drops are silent (FIXED)
- **Severity:** LOW — silent event loss during rapid failover
- **Fix:** `slog.Warn` on drop (suppressed during shutdown). Channel buffer 64→256
- **Files:** `pkg/vrrp/instance.go`, `pkg/vrrp/manager.go`, `pkg/vrrp/vrrp_test.go`

### IPv6 advert checksum/source/Zone handling bugs (FIXED)
- **Severity:** MEDIUM — IPv6 adverts silently fail or get rejected
- **Fix (A):** Warn+log on nil srcIP lazy resolve failure/success
- **Fix (B):** Removed `Zone` from destination IPAddr — socket already has `IPV6_MULTICAST_IF`
- **Files:** `pkg/vrrp/instance.go`, `pkg/vrrp/vrrp_test.go`

### Monitor poll() data race on localStatuses (FIXED)
- **Severity:** MEDIUM — data race between poll() and LocalInterfaceStatuses()
- **Fix:** Build statuses into local slice, swap under lock. `pollInterfaceMonitors()` returns slice
- **Files:** `pkg/cluster/monitor.go`, `pkg/cluster/monitor_test.go`

### Monitor leaks netlink handles every poll cycle (FIXED)
- **Severity:** MEDIUM — 1 fd leaked per second
- **Fix:** `cachedNlHandle` field, created on first use, closed in `Stop()`
- **Files:** `pkg/cluster/monitor.go`, `pkg/cluster/monitor_test.go`

### Monitor.getNlHandle lazy init is unsynchronized (FIXED, #4715)
- **Severity:** LOW-MEDIUM — data race + bounded FD leak
- **Bug:** `getNlHandle()` read/wrote `cachedNlHandle` lock-free while
  `Stop()` nils it under `mu`. Two concurrent lock-free callers
  (`pollInterfaceMonitors` from the poll loop, `RGInterfaceReady` from the
  daemon HA path) each observed `nil` and created a handle — the second
  write overwrote the first, leaking one netlink socket FD — and the write
  raced `Stop()`.
- **Fix:** The check-create-cache now runs under `mon.mu` (test injection
  short-circuits before locking; neither caller holds `mu`, so no deadlock).
  Exactly one handle is created under concurrency; lazy-recreate-after-Stop
  is preserved. Creation is injectable via `newNlHandle` so a counting fake
  proves creations==1 and Close-on-Stop==1 under `-race`.
- **Files:** `pkg/cluster/monitor.go`, `pkg/cluster/monitor_test.go`

### IP monitoring probes are IPv4-only (FIXED)
- **Severity:** LOW — IPv6 monitoring targets silently fail
- **Fix:** Detect IPv4/IPv6, use appropriate socket/types. `icmpDialer` accepts `network string`
- **Files:** `pkg/cluster/monitor.go`, `pkg/cluster/monitor_test.go`

## SNAT Interface-Mode + NAT64 Pool Bugs (2026-02-28)

### SNAT interface-mode uses wrong egress IP on VLAN sub-interfaces (FIXED `f9e408c`)
- **Symptom:** Packets arrived at iperf3 target (172.16.100.200) with un-SNAT'd source 10.0.60.102, or SNAT'd with wrong IP (172.16.50.6 instead of 172.16.100.6). The SNAT rule `source-nat { interface; }` picked a random RETH unit address regardless of actual egress interface
- **Root cause:** The interface-mode SNAT compiler picked a single interface from the to-zone at compile time and built one pool from ALL RETH unit addresses (e.g., both 172.16.50.6 for VLAN 50 and 172.16.100.6 for VLAN 100). At runtime, BPF `nat_pool_alloc_v4()` allocated from the pool without considering the actual egress ifindex+vlan — so a packet egressing VLAN 100 could get SNAT'd with the VLAN 50 IP
- **Fix:** New `snat_egress_ips` BPF HASH map keyed by `(ifindex, vlan_id)` → per-interface SNAT IP. The compiler now iterates ALL interfaces in the to-zone and populates the map with each unit's primary IP. New BPF functions `nat_pool_alloc_iface_v4/v6()` look up `meta->fwd_ifindex` + `meta->egress_vlan_id` to select the correct egress IP, falling back to pool-based allocation if the lookup fails
- **BPF arg limit gotcha:** Initial implementation passed 6 args to the BPF helper (BPF max is 5). Fixed by passing `struct pkt_meta *meta` instead of separate ifindex+vlan args
- **Files:** `xpf_common.h` (interface_mode flag, snat_egress_key/value structs), `xpf_maps.h` (snat_egress_ips map), `xdp_policy.c` (nat_pool_alloc_iface_v4/v6, 3 SNAT call sites), `types.go`, `dataplane.go`, `maps.go`, `loader_ebpf.go`, `compiler.go`, DPDK stubs
- **Validated:** `make test` all pass, `make test-failover` 14/14 pass (8.51 Gbps)

### NAT64 source pool auto-assignment for unreferenced named pools (FIXED `f9e408c`)
- **Symptom:** Compile failure when a named pool was defined in source NAT config but only referenced from the nat64 section (not by any SNAT rule). The pool was never assigned a pool ID, causing XDP programs to fail attachment
- **Root cause:** Pool ID assignment happened only during SNAT rule compilation. Pools referenced exclusively by NAT64 were skipped — they existed in the config but had no ID, so the BPF map population failed
- **Fix:** NAT64 compiler now auto-assigns pool IDs for pools not yet referenced by any SNAT rule, using `NextPoolID` tracking in the compiler
- **Files:** `pkg/dataplane/compiler.go`

### Interface-mode SNAT fallback to pool allocation (FIXED `5781006`, #7)
- **Symptom:** Interface-mode SNAT selected wrong source IP when snat_egress_ips lookup missed
- **Root cause:** `nat_pool_alloc_iface_v4/v6()` fell back to `nat_pool_alloc_v4/v6()` on egress lookup miss, using pool IP instead of interface IP
- **Fix:** Return -1 on miss — interface mode must not fall back to pool. Skip to next SNAT rule
- **Files:** `bpf/xdp/xdp_policy.c`

### DNAT-before-fabric fixed L3/L4 offsets (FIXED `5781006`, #8)
- **Symptom:** DNAT rewrite used wrong packet offsets with VLAN-tagged packets or IPv4 options
- **Root cause:** `apply_dnat_before_fabric_redirect()` used `sizeof(struct ethhdr)` and `sizeof(struct iphdr)` instead of parsed meta offsets
- **Fix:** Use `meta->l3_offset & 0x3F` and `meta->l4_offset & 0xFF` with verifier-safe masking
- **Files:** `bpf/xdp/xdp_zone.c`

### DNAT-before-fabric port-only DNAT skip (FIXED `5781006`, #9)
- **Symptom:** Port-only DNAT (same IP, different port) was skipped because `iph->daddr == meta->dst_ip.v4` short-circuited the entire function
- **Root cause:** Single conditional checked only address, not port
- **Fix:** Separate address and port rewrite paths — address rewrite only when IP differs, port rewrite always when port differs
- **Files:** `bpf/xdp/xdp_zone.c`

### Host-inbound allowlist allowed unknown services (FIXED `5781006`, #10)
- **Symptom:** Unknown services (flag==0) passed through host-inbound allowlist zones; ICMP echo replies and ICMPv6 NDP were blocked
- **Root cause:** (1) `host_inbound_flag()` only classified echo requests (type 8/128), not replies (type 0/129) or NDP (133-136). (2) Allowlist check `flag != 0 && !(flags & flag)` passed unknown services (flag==0) through
- **Fix:** Added echo reply + NDP classification to `host_inbound_flag()`. Changed allowlist to true deny: `flags != ALL && (flag == 0 || !(flags & flag))`
- **Files:** `bpf/headers/xpf_helpers.h`, `bpf/xdp/xdp_forward.c`, `dpdk_worker/forward.c`

### NAT64 SNAT rule shadowing interface-mode rule (FIXED `5781006`)
- **Symptom:** All LAN→WAN traffic SNAT'd to 172.16.50.6 (nat64-pool) instead of correct egress interface IP
- **Root cause:** `nat64-snat` rule-set with `match source-address 0.0.0.0/0` was compiled at rule_idx=0, shadowing the `lan-to-wan` interface-mode rule at rule_idx=1. Also discovered configstore persists config in `.configdb/active.json` — must delete this + `.config.journal` when pushing new config
- **Fix:** Removed unused nat64 config from ha-cluster.conf
- **Files:** `docs/ha-cluster.conf`

## Sprint: HA Hardening #98-#102 (FIXED `00de701`)

### Neighbor warmup skips Junos interface names (FIXED #98)
- **Symptom:** `resolveNeighbors()` silently skipped interface-qualified static next-hops when interface name was in Junos form (`ge-0/0/1`, `reth0.50`) — caused NO_NEIGH drops after failover
- **Root cause:** `addByName()` passed raw Junos names to `netlink.LinkByName()` which fails because Linux doesn't have those names
- **Fix:** Added `resolveJunosIfName()` helper that chains `cfg.ResolveReth()` (reth→physical member) + `config.LinuxIfName()` (slash→dash)
- **Files:** `pkg/daemon/daemon.go`

### Sync protocol short-write frame truncation (FIXED #99)
- **Symptom:** Under TCP backpressure, `conn.Write()` could return `n < len(buf)` with nil error, truncating sync protocol frames → bad magic errors, disconnect/reconnect churn during failover
- **Root cause:** `writeMsg()` and `sendLoop()` both did single `conn.Write()` without checking byte count
- **Fix:** Added `writeFull()` helper that loops until all bytes sent or error
- **Files:** `pkg/cluster/sync.go`

### Heartbeat truncation with large monitor payloads (FIXED #100)
- **Symptom:** With many interface monitors, heartbeat packet exceeds 512-byte read buffer → parse errors → false peer-loss failovers
- **Root cause:** Hard-coded `maxHeartbeatSize=512` too small; `MarshalHeartbeat()` allowed unbounded growth
- **Fix:** Increased buffer to 1472 (safe UDP MTU), `MarshalHeartbeat()` caps at maxHeartbeatSize (truncates monitors, preserves RG groups), `UnmarshalHeartbeat()` handles truncated monitor section gracefully
- **Files:** `pkg/cluster/heartbeat.go`

### Fixed 10s VRRP posture mismatch delay (FIXED #101)
- **Symptom:** VRRP posture correction waited 10s even in steady-state, causing 10-12s connectivity disruptions during failover
- **Root cause:** Single `vrrpPostureDelay = 10s` constant used for all contexts
- **Fix:** Context-aware delay — 10s during startup (first 30s after RG creation), 2s in steady-state. Reduces real mismatch correction from 10-12s to 2-4s
- **Files:** `pkg/daemon/rg_state.go`

### HA fail-closed gap on ungraceful daemon failure (FIXED #102)
- **Symptom:** `kill -9` or panic leaves `rg_active` set → stale forwarding until peer election catches up
- **Root cause:** Graceful shutdown path that clears `rg_active` never runs on ungraceful exit
- **Fix:** BPF `ha_watchdog` ARRAY map written by Go daemon every 500ms with monotonic timestamp. `check_egress_rg_active()` verifies freshness — if >2s stale, treats RG as inactive regardless of `rg_active`. Standalone mode unaffected (watchdog value 0 = skip check)
- **Files:** `bpf/headers/xpf_maps.h`, `bpf/headers/xpf_helpers.h`, `pkg/dataplane/maps.go`, `pkg/daemon/daemon.go`

### HA startup premature primary takeover (FIXED #103)
- **Symptom:** On startup/rejoin, RG election could promote to primary before interfaces/VRRP are ready → transient loss/blackhole during HA transitions
- **Root cause:** No readiness gate before takeover — election promoted on peer-loss/no-peer with weight>0; monitor skipped missing interfaces; VRRP skipped missing interfaces; posture check returned OK with no VRRP instances
- **Fix:** Per-RG readiness contract + hold timer: election blocks promotion until interfaces + VRRP ready for holdTime. Monitor reports missing interfaces as not-ready. VRRP manager reports per-RG instance readiness. Already-primary nodes never demoted. Configurable `takeover-hold-time`, **default 0** (`DefaultTakeoverHoldTime`, `pkg/cluster/manager.go`) — the gate is readiness-only unless an operator sets a hold. It shipped at 3s in `91a57cf` and was changed to 0 in the bodyless `cd4dbe9`; this line said 3s until #103 was re-walked
- **Files:** `pkg/cluster/cluster.go`, `pkg/cluster/election.go`, `pkg/cluster/monitor.go`, `pkg/vrrp/manager.go`, `pkg/daemon/daemon.go`, `pkg/config/types.go`, `pkg/config/ast.go`, `pkg/config/compiler.go`

### warmNeighborCache UDP connect doesn't trigger ARP — double-failover traffic death (FIXED CC-11)
- **Symptom:** After double failover (crash fw0 → fw1 primary → fw0 rejoin → crash fw1 → fw0 primary), traffic permanently dead (0 bytes/sec iperf3). Single failover works fine
- **Root cause:** `warmNeighborCache()` in `daemon.go` used `net.DialTimeout("udp4", ...)` followed by `conn.Close()` without sending any data. For UDP, `connect()` only performs route lookup — it does NOT trigger ARP/NDP resolution. Only sending data (which calls `neigh_resolve_output()` → `arp_solicit()`) triggers ARP
- **Impact chain:** No ARP → `bpf_fib_lookup` returns NO_NEIGH (rc=7) → XDP sets META_FLAG_KERNEL_ROUTE → xdp_conntrack + xdp_nat apply SNAT → xdp_forward XDP_PASS → kernel forwards SNAT'd packet → TC egress drops it (`tc_conntrack.c:217` — SNAT'd 5-tuple doesn't match any session key, `ingress_ifindex != 0`)
- **Why only double failover:** First failover keeps neighbor cache warm from prior traffic. After fw0 rejoins and fw1 crashes, fw0 becomes primary with cold neighbor cache (was secondary, no forwarding). `warmNeighborCache()` was supposed to prime ARP but the no-op UDP connect did nothing
- **Fix:** Send one byte via `conn.Write([]byte{0})` before `conn.Close()` to trigger actual kernel ARP/NDP resolution. Added 200ms sleep after all warmup to allow ARP responses before traffic arrives
- **Secondary issue:** TC egress `ingress_ifindex` guard correctly drops un-NAT'd kernel-forwarded packets, but also drops properly SNAT'd packets from the KERNEL_ROUTE path because the post-SNAT 5-tuple doesn't match session keys. This means the KERNEL_ROUTE fallback is permanently broken for SNAT'd sessions. Proactive neighbor warmup avoids this path entirely
- **Files:** `pkg/daemon/daemon.go`

### Deploy configstore stale config — VRRP backward compat failure (FIXED)
- **Symptom:** After deploying new config via `make cluster-deploy` (which, on the raw path, pushes `xpf.conf`), the daemon still uses the OLD config from `active.json`. Removing `private-rg-election` from `xpf.conf` had no effect — VRRP instances didn't start
- **Root cause:** The configstore DB (`/etc/xpf/.configdb/active.json`) persists the compiled config AST from the previous run. On startup, `Store.Load()` reads from `active.json` first (line 87). The text file `xpf.conf` is only used when `active.json` doesn't exist (bootstrap). The raw deploy pushed new `xpf.conf` but didn't clear `active.json`
- **Fix:** Deploy script (`cluster-setup.sh`) now runs `rm -rf /etc/xpf/.configdb` after pushing new config, forcing the daemon to bootstrap from the fresh `xpf.conf`. (Raw-path behavior; since #9486 the default deb deploy preserves node config and never pushes `xpf.conf`.)
- **Files:** `test/incus/cluster-setup.sh`
- **Test:** `test/incus/test-private-rg.sh full` — enables then disables private-rg-election, verifying VRRP restarts

### IPv6 SNAT missing in ha-cluster.conf — IPv6 TCP return traffic failure
- **Symptom:** IPv6 iperf3 from `cluster-lan-host` to WAN server fails. SYN goes through, server sends SYN-ACK, but SYN-ACK never reaches the client. IPv6 ping works fine
- **Root cause:** The SNAT rule in `ha-cluster.conf` used `source-address 0.0.0.0/0` which only matches IPv4. IPv6 traffic was forwarded without SNAT, exposing the internal cf01::/64 source address. If the upstream router lacks a route back to cf01::/64, the SYN-ACK is lost
- **Fix:** Added `rule snat6 { match { source-address ::/0; } then { source-nat { interface; } } }` to `ha-cluster.conf`
- **Note:** This is a config issue, not a code bug. However, a future improvement could auto-generate dual-stack SNAT rules when `0.0.0.0/0` is specified, or add a config validation warning
- **Files:** `docs/ha-cluster.conf`

## Sprint Infra + CC-11 (2026-03-05..06)

### Embedded ICMP fabric redirect before NAT rewrite — traceroute broken in split-RG (FIXED `7c8f243`)
- **Symptom:** In split-RG cluster (WAN on node0 RG0, LAN on node1 RG1), `mtr`/`traceroute` from LAN host showed 100% loss on all intermediate hops. Only the final destination responded. Direct ping worked fine
- **Root cause:** ICMP Time Exceeded from transit routers arrives on WAN node. `handle_embedded_icmp_v4/v6()` called `try_fabric_redirect()` BEFORE NAT rewrite — peer received packets with SNAT'd embedded headers (source = SNAT pool IP, not original client) and couldn't match them to any session → silent drop
- **Fix:** When FIB fails (UNREACHABLE/BLACKHOLE) for the original client, set `META_FLAG_KERNEL_ROUTE` instead of immediate fabric redirect. `xdp_forward`'s KERNEL_ROUTE path re-FIBs using post-NAT packet headers (outer dst rewritten to original client IP), detects UNREACHABLE, and fabric-redirects with correct headers. Also changed `meta_flags` from `=` to `|=` to preserve KERNEL_ROUTE flag
- **Key insight:** Fabric redirect must happen AFTER NAT rewrite in the embedded ICMP path, not before. The KERNEL_ROUTE→xdp_forward re-FIB path naturally occurs after NAT
- **Files:** `bpf/xdp/xdp_conntrack.c`

### Embedded ICMP NOT_FWDED treated as error instead of local delivery (FIXED `7158942`)
- **Symptom:** ICMP error messages containing packets originally destined for the firewall itself were dropped
- **Root cause:** `handle_embedded_icmp_v4/v6()` treated `NOT_FWDED` (`BPF_FIB_LKUP_RET_NOT_FWDED`) as a failure. This return code means the destination is local — correct behavior for ICMP TE/Dest Unreachable about firewall-destined traffic
- **Fix:** Treat `NOT_FWDED` as success (local delivery) instead of error
- **Files:** `bpf/xdp/xdp_conntrack.c`

### Stale fabric_fwd entries after fabric path failure — 30s silent drop window (FIXED #121, `e02ceeb`)
- **Symptom:** When fabric link goes DOWN or ARP entry expires, `fabric_fwd` BPF map retains stale MAC/ifindex/IP. BPF `try_fabric_redirect()` sends packets to dead path → silent drops for up to 30s until ticker refreshes
- **Root cause:** `populateFabricFwd()` only wrote entries when path was healthy, never cleared them when path failed
- **Fix:** Write zeroed `FabricFwdInfo{}` on fabric link DOWN or neighbor disappearance. BPF treats `ifindex==0` as "no entry" — no C-side changes needed

### fabric_fwd programmed for operationally DOWN interfaces (FIXED #122, `e02ceeb`)
- **Symptom:** Fabric entry programmed even when interface exists but cable is unplugged (OperState != UP) → BPF redirects to non-functional path
- **Root cause:** `populateFabricFwd()` checked interface existence but not operational state
- **Fix:** Check `link.Attrs().OperState` before programming — reject non-UP interfaces

### Dual-fabric session sync connection flapping (FIXED #123, `1358477`)
- **Symptom:** With dual fabrics, session sync `connectLoop()` rotates addresses on any failure. Working connection torn down to try the other address → unnecessary disconnect/reconnect churn
- **Root cause:** Address rotation didn't track per-fabric connection state — treated both addresses as equivalent
- **Fix:** Per-fabric connection tracking with fab0 preference. Don't tear down working connections to try alternatives

### Fabric health only checked on 30s timer (FIXED #124, `e02ceeb`)
- **Symptom:** Up to 30s stale forwarding after fabric interface or neighbor change
- **Root cause:** No event-driven refresh — only 30s periodic ticker
- **Fix:** Netlink `LinkSubscribe()` + `NeighSubscribe()` for immediate fabric_fwd refresh on state changes. 30s ticker remains as safety net

### gRPC/monitor single-address fabric failover (FIXED #125, `e02ceeb`)
- **Symptom:** gRPC server and cluster monitor only used one fabric address. If that fabric path failed, gRPC connectivity and health monitoring lost despite other fabric being healthy
- **Root cause:** Single-address configuration for gRPC listener and monitor dial
- **Fix:** gRPC server listens on both fabric addresses. Monitor dials fab0→fab1 with fallback

### DPDK fabric redirect unsupported (FIXED #126, `dc6f6bd`)
- **Symptom:** DPDK dataplane silently drops packets on fabric redirect paths — no equivalent of BPF `try_fabric_redirect()` helpers
- **Root cause:** DPDK zone.c programs fabric port IDs for inbound detection but lacks the actual redirect logic
- **Fix:** Added `slog.Warn` in `UpdateFabricFwd()`/`UpdateFabricFwd1()` and comments in `dpdk_worker/zone.c` to make the limitation visible

## Sprint CC-12: IPVLAN Fabric Fixes (#127-#130, 2026-03-06)

### IPVLAN address reconciliation skipped — ensureFabricIPVLAN early return (FIXED #127, `673dc0a`)
- **Symptom:** After daemon restart, IPVLAN overlay interface (fab0/fab1) exists but may lack its IP address. Fabric sync and forwarding broken
- **Root cause:** `ensureFabricIPVLAN()` returns early if IPVLAN already exists, skipping address reconciliation. The IPVLAN survives daemon restart but addresses may have been removed (e.g., by networkd reload or link DOWN/UP cycle)
- **Fix:** Remove early return — always reconcile addresses even when IPVLAN already exists

### Stale IPVLAN overlay never cleaned up — CleanupFabricIPVLANs() uncalled (FIXED #128, `673dc0a`)
- **Symptom:** Old/orphaned fab0/fab1 IPVLAN interfaces persist across config changes or topology changes. May cause conflicting addresses or stale routes
- **Root cause:** `CleanupFabricIPVLANs()` was implemented in the codebase but never called from any code path
- **Fix:** Call `CleanupFabricIPVLANs()` at appropriate lifecycle points (config change, daemon shutdown/cleanup)

### Neighbor probe on wrong interface — probeFabricNeighbor uses parent (FIXED #129, `673dc0a`)
- **Symptom:** After IPVLAN overlay refactor, fabric neighbor resolution fails. ARP/NDP probe sent from physical parent interface instead of IPVLAN overlay where the IP address lives
- **Root cause:** `probeFabricNeighbor()` sends the neighbor probe via the physical fabric member (ge-X-0-Y) which no longer has the fabric IP. The IP lives on the IPVLAN child (fab0/fab1). ARP request has wrong source IP → peer ignores or responds to wrong interface
- **Fix:** Send neighbor probe from the IPVLAN overlay interface (fab0/fab1) instead of the physical parent

### Compiler auto-detect collapses dual-fabric into single (FIXED #130, `673dc0a`)
- **Symptom:** In dual-fabric clusters, only `FabricInterface` (fab0) is populated in compiled config. `Fabric1Interface` (fab1) is empty → node1 has no fabric forwarding
- **Root cause:** Fabric auto-detection logic finds both fabric interfaces but collapses them into a single `FabricInterface` field instead of populating both `FabricInterface` and `Fabric1Interface`
- **Fix:** Auto-detect must distinguish fab0 vs fab1 and populate both compiler fields correctly

## Sprint CC-13: HA Session Sync & Activation Fixes (#131-#134, 2026-03-06)

### Session sync only at creation — established flows never refreshed (FIXED #131, `b35bb45`)
- **Symptom:** Long-lived sessions (e.g., persistent TCP connections, long iperf3 runs) are synced once at creation but never updated. If a failover occurs hours later, the peer's synced session has stale `LastSeen` timestamps — GC may have already purged it, or the session state is outdated (e.g., TCP window changes)
- **Root cause:** Session sync sweep only sends sessions when they are first created. Established sessions with ongoing activity are never re-synced to reflect updated `LastSeen`, packet counters, or TCP state
- **Fix:** Sweep includes `LastSeen`-based activity detection — sessions with recent activity (since last sweep) are re-synced to peer. Keeps peer's session table fresh for long-lived flows

### RG activation on ANY single VRRP MASTER — should require ALL instances (FIXED #132, `08c17e3`)
- **Symptom:** RG becomes active when the first VRRP instance transitions to MASTER, even if other instances in the same RG are still BACKUP. This can cause partial forwarding — some interfaces active, others still blackholed
- **Root cause:** `rg_active` BPF map set to true on any single VRRP MASTER event. No check that ALL VRRP instances for the RG are MASTER before clearing blackholes
- **Fix:** Track per-RG VRRP instance states; only set `rg_active=true` and remove blackhole routes when ALL instances for the RG have reached MASTER state

### syncReady latched true forever — never reset on disconnect (FIXED #133, `f5b445e`)
- **Symptom:** After peer disconnects and reconnects, `syncReady` remains true from the first connection. Bulk sync is skipped on reconnect because the system believes sync is already complete. New peer may have stale/empty session table
- **Root cause:** `syncReady` flag is set after initial bulk sync completes but never reset when the sync connection drops
- **Fix:** Reset `syncReady` to false on total peer disconnect (all sync connections lost). Next reconnect triggers fresh bulk sync

### Hold timer edge-triggered — no wakeup at expiry (FIXED #134, `f5b445e`)
- **Symptom:** After sync hold expires, the node doesn't re-evaluate VRRP priority. If the node should preempt (higher priority), it stays BACKUP indefinitely until an external event triggers re-evaluation
- **Root cause:** Hold timer sets a flag on expiry but doesn't schedule a re-election evaluation. The flag is only checked reactively when other events occur
- **Fix:** Use `time.AfterFunc` to schedule an explicit re-election evaluation when the hold timer expires. Ensures timely VRRP preemption after sync completes

## Sprint CC-14: Fabric Monitor & Stats Fixes (#135-#137, 2026-03-06)

### monitor interface fab0/fab1 shows IPVLAN overlay stats (FIXED #135, `6fd6124`)
- **Symptom:** `monitor interface fab0` displays IPVLAN overlay stats (sync/gRPC traffic only), not wire-level fabric traffic. XDP/TC redirected packets traverse the physical parent (ge-X-0-Y) and are invisible on the overlay
- **Root cause:** After IPVLAN overlay refactor (CC-11), monitor commands resolve fab0/fab1 to the IPVLAN child interface. Wire-level counters live on the physical parent where XDP/TC are attached
- **Fix:** Resolve fabric overlay names to physical parent interface for stats collection. Use IPVLAN parent→child relationship for the mapping

### monitor traffic interface fab0/fab1 captures overlay not physical (FIXED #136, `6fd6124`)
- **Symptom:** `monitor traffic interface fab0` tcpdump captures IPVLAN overlay packets (sync/gRPC), missing all XDP/TC redirected fabric traffic
- **Root cause:** Same as #135 — tcpdump attached to IPVLAN overlay instead of physical parent
- **Fix:** Resolve fabric overlay name to physical parent before starting packet capture

### monitor traffic matching truncates multi-token pcap filter to first token (FIXED #4005)
- **Symptom:** `monitor traffic interface ge-0-0-0 matching "tcp port 80"` captures on just `tcp` — the `port 80` narrowing is silently dropped, so the operator's diagnostic capture shows far more traffic than requested. Any multi-token BPF filter (`host 10.0.0.1 and port 443`, `udp and not port 53`) is reduced to its first whitespace token.
- **Root cause:** The operational CLI tokenizes the command line with `strings.Fields` (`cli_dispatch.go`), which splits on whitespace and does NOT honor shell quoting. A quoted filter `"tcp port 80"` therefore reaches `handleMonitorTraffic` as three separate tokens `"tcp`, `port`, `80"`. The old `case "matching"` read only `args[i+1]` (the first token, `"tcp`, with a literal quote) and the remaining tokens fell through the switch and were discarded.
- **Fix:** `parseMonitorTrafficArgs` (`pkg/cli/cli_request.go`) makes the `matching` clause greedy — it consumes every following token up to the next recognized option keyword (`interface`/`count`, none of which are pcap primitives), joins them into one filter expression, and strips a single balanced layer of surrounding quotes via `stripSurroundingQuotes`. `buildMonitorTrafficArgv` passes the full filter to tcpdump as trailing argv tokens, exactly as libpcap consumes a filter. A `count` following the filter is no longer swallowed. Regression guard: `pkg/cli/monitor_traffic_filter_4005_test.go`.

### monitor traffic swallows a keyword as the interface name + value-less count silently unlimited (FIXED #4540)
- **Symptom:** `monitor traffic interface matching tcp port 80` (the interface value omitted) consumed the following grammar keyword `matching` as the interface name — tcpdump then failed with "no such device" or (with a real bareword next) captured on the wrong device unfiltered. Separately, a trailing bare `count` with no value (`... interface ge-0-0-0 count`) silently left the packet count at its `"0"` = unlimited default, ignoring the operator's intent to bound the capture; a non-numeric count reached tcpdump's `-c` and failed opaquely.
- **Root cause:** The `case "interface"` and `case "count"` arms of `parseMonitorTrafficArgs` consumed `args[i+1]` whenever one existed, with no check that it was an actual value rather than another keyword (or absent). `count` additionally defaulted to `"0"` and was never re-validated.
- **Fix:** `parseMonitorTrafficArgs` (`pkg/cli/cli_request.go`) now returns an `error`. The `interface` and `count` arms reject a missing value or a following grammar keyword (`monitorTrafficKeywords`); `count` additionally requires a numeric value (`strconv.Atoi`). `handleMonitorTraffic` returns the error to the operator instead of running a mis-targeted or unbounded capture; a bare `monitor traffic` with no `interface` keyword still prints the usage message. Regression guard: `pkg/cli/monitor_traffic_keyword_4540_test.go`.

### REST writeJSON commits a 200 before encoding — marshal failure yields a truncated 200 not a 500 (FIXED #4541)
- **Symptom:** A REST handler whose response value failed `json.Marshal` sent a `200 OK` status line and `Content-Type: application/json` followed by a truncated/empty body. The client saw a success code over a broken response. Zero current trigger (every response value is a simple typed struct today), but the accepted-Go-idiom class of bug — a robustness gap surfaced by the ps-032 audit.
- **Root cause:** `writeJSON` (`pkg/api/api.go`) set `Content-Type` + `WriteHeader(status)` and only then ran `json.NewEncoder(w).Encode(v)`, ignoring the `Encode` error. Once `WriteHeader(200)` runs the status is committed, so a later encode error cannot be turned into a 500.
- **Fix:** `writeJSON` marshals `v` to a buffer FIRST. On a marshal error it logs and writes `500` with a static `{"success":false,"error":...}` body; on success it writes `Content-Type` + `WriteHeader(status)` + the buffer. The success path is byte-identical to the old `Encoder.Encode` output — `json.Marshal` bytes plus the trailing `'\n'` `Encode` appended. Regression guard: `pkg/api/write_json_4541_test.go`.

### try_fabric_redirect missing inc_iface_tx — TX counters undercount (FIXED #137, `6fd6124`)
- **Symptom:** Fabric TX traffic not counted in `show interfaces statistics` or `monitor interface`. Packets forwarded via `try_fabric_redirect()` in xdp_zone.c bypass TX counter instrumentation
- **Root cause:** `try_fabric_redirect()` calls `bpf_redirect_map` but never calls `inc_iface_tx(meta, fabric_ifindex)` before returning
- **Fix:** Add `inc_iface_tx` call before `bpf_redirect_map` return in `try_fabric_redirect()`

## Sprint CC-15: Fabric Observability (#138-#139, 2026-03-06)

### tcpdump unreliable for XDP fabric redirects (IN PROGRESS #138)
- **Symptom:** `monitor traffic interface <fabric>` shows incomplete or empty captures for fabric redirect traffic. Users see no packets despite active fabric forwarding
- **Root cause:** XDP processes packets before `sk_buff` allocation. tcpdump uses AF_PACKET which hooks into the kernel network stack after `sk_buff` creation. XDP-redirected packets never reach AF_PACKET
- **Fix:** Add CLI warning when `monitor traffic` targets fabric interfaces. Document the XDP/AF_PACKET incompatibility. Point users to BPF counters and per-link redirect stats (#139) as reliable alternatives

### Per-link fabric redirect counters missing (IN PROGRESS #139)
- **Symptom:** No way to see per-link (fab0 vs fab1) or per-zone fabric redirect traffic breakdown. Only aggregate TX counters available via `show interfaces statistics`
- **Root cause:** `try_fabric_redirect()` increments a single per-interface TX counter but has no per-link or per-zone accounting
- **Fix:** Add BPF per-link redirect counters (fab0/fab1 differentiated, zone-encoded) and expose via CLI (`show chassis cluster statistics` or similar)

### Generic XDP CHECKSUM_PARTIAL corruption — TCP/UDP broken after NAT (FIXED `dfd3ebc`)
- **Symptom:** TCP connections through local cluster firewall fail silently. SYN reaches server but checksum is invalid → server drops it. ICMP (ping) works fine. Only affects generic XDP (SKB mode), not native/driver XDP
- **Root cause:** `xdp_main.c` set `meta->native_xdp=1` for ALL interfaces in `redirect_capable` map (value!=0). In generic XDP, skb has `ip_summed=CHECKSUM_PARTIAL` — L4 checksum field contains only the pseudo-header complement. With `native_xdp=1`, `set_l4_csum_flags()` skips CHECKSUM_PARTIAL detection → `csum_partial=0` → NAT code does full incremental checksum updates (`csum_update_4` for IP, `csum_update_2` for port) on what's actually a partial seed → NIC/kernel adds L4 byte sum to corrupted value → invalid final checksum
- **Fix:** Remove the `native_xdp` optimization entirely. Always run CHECKSUM_PARTIAL detection in `set_l4_csum_flags()` (~10-30 extra BPF insns, negligible). Correct for both native and generic XDP
- **Why ICMP worked:** ICMP checksum covers only the ICMP header+payload (no pseudo-header), so SNAT source IP change doesn't affect it. ICMP has no ports to update
- **Key insight:** `redirect_capable` map value 1 was set for ALL non-tunnel interfaces regardless of XDP mode. The `needGeneric` fallback in compiler.go re-ran the generic attach loop but never updated the map values. A second compile cycle (e.g., for fabric interfaces) could also reset values

### Userspace ctrl enable flushes synced BPF conntrack — established sessions die on failover (FIXED `1a2b0a25`)
- **Symptom:** After HA failover to fw1, established iperf3 flows immediately flatline to 0 Gbps and never recover. `show security flow session` on fw1 shows sessions with "HA State: Backup" despite fw1 being primary. Logs show `userspace: flushed stale BPF conntrack on ctrl enable: deleted=382`
- **Root cause:** `applyHelperStatusLocked()` in `pkg/dataplane/userspace/manager.go:3106` flushes ALL entries from the BPF `sessions` and `sessions_v6` maps when ctrl transitions from disabled to enabled. The intent was to remove sessions created by the eBPF pipeline during the ctrl-disabled transition window (which could have conflicting NAT state). But it indiscriminately deleted synced sessions too — the 382 sessions installed by cluster session sync from fw0 were wiped out the instant the userspace dataplane activated on fw1
- **Why sessions showed "HA State: Backup":** With BPF conntrack wiped, the eBPF pipeline couldn't find the sessions. New packets for existing flows hit policy evaluation as "new" connections but the TCP state (no SYN) caused them to be classified as backup/invalid
- **Fix:** Track `ctrlDisabledAt` (CLOCK_BOOTTIME ns, matching BPF's `bpf_ktime_get_ns()`). On ctrl enable, read each session's `Created` timestamp (uint64 at byte offset 8 in the session value). Only flush sessions where `Created > ctrlDisabledAt` (created during the transition window). Sessions synced from the peer have earlier timestamps and survive
- **Key pattern:** BPF session values have a `Created` field populated by `bpf_ktime_get_ns()` at session creation time. This serves as a reliable discriminator between pre-existing synced sessions and newly-created transition sessions
- **Remaining work:** This fix preserves synced sessions but the investigation docs identify additional issues: (H) public-side LocalDelivery materialization from shared_promote path, (F) fabric transit throughput ceiling for redirected flows. These may cause partial throughput loss even with sessions preserved

## Userspace Forwarding & HA Gaps (PR #301, Issues #302-#312)

Audit doc: `docs/archived/userspace-forwarding-and-failover-gap-audit.md`

### Native non-first fragments miss protocol-constrained filters (FIXED #10676)
- **Symptom:** A native non-first fragment carrying the shim's protocol 255 sentinel could bypass input, PBR, output, or lo0 terms constrained to a real protocol.
- **Root cause:** The shared IPv4/IPv6 protocol-bitmap matcher treated 255 as an ordinary protocol value, so it matched none of the concrete-protocol bits.
- **Fix:** Treat 255 as unknown/fragment for protocol predicates while keeping known protocol values exact. Do not recover the inner protocol by parsing fragment payload bytes.
- **Tests:** Native-255 and decapsulated real-protocol pairs cover input, PBR, output, and lo0 filter paths, including exact TCP/UDP controls.

### Native-255 tails bypass the junos-host port-deny override (FIXED #10680)
- **Symptom:** A host-bound non-first fragment carrying protocol 255 bypassed an overlapping junos-host port-specific deny and could reach the host stack.
- **Root cause:** The skipped-deny guard used an exact protocol lookup for L4-constrained application terms, so the native unknown/fragment sentinel had no bucket and the #6465 override never recorded the deny.
- **Fix:** For protocol 255 only, consider L4-constrained terms across concrete protocol buckets when deciding whether a flowless fragment must fail closed. Known decapsulated protocol metadata stays exact.
- **Tests:** Native-255, decapsulated TCP, and decapsulated UDP cells verify deny inheritance and exact protocol behavior; the native/decap pair folds in #10678.

### Fragmented ESP/GRE to interface-NAT split across kernel and helper (FIXED #10677)
- **Symptom:** An ESP/GRE datagram addressed to an interface-NAT endpoint was split: the whole packet or first fragment went to the kernel, while later fragments went to the helper as protocol 255 and were refused, so neither path could reassemble the datagram.
- **Root cause:** The shim's #304 kernel arm matched the parsed protocol. The #7494 no-L4 sentinel replaces the protocol on non-first fragments, so the tail missed the ESP/non-native-GRE interface-NAT arm and fell through to XSK.
- **Fix:** Preserve the wire protocol separately from the sentinel and use it only for the interface-NAT tunnel disposition. ESP tails follow the kernel path in healthy and degraded operation; non-native GRE tails follow the kernel path, while native GRE tails remain on the helper path. The helper's protocol gate and the no-L4 session-miss guarantee remain unchanged.
- **Tests:** Shim truth-table cells cover ESP/GRE heads and tails, native-GRE and non-tunnel controls, and degraded ESP. The helper flowless cell verifies that an interface-NAT GRE tail stamped 255 is still refused while a real GRE protocol is admitted.


### Hybrid userspace/eBPF forwarding model (OPEN #302-#307)
- **Symptom:** In userspace dataplane mode, transit packets can silently fall back to the eBPF pipeline (via XDP_PASS or XSK socket failure) without any indication in counters or logs. The XDP shim program returns XDP_PASS for protocols it does not handle (GRE, ESP), for AF_XDP socket errors, and when PASS_TO_KERNEL is set — all of which bypass the userspace forwarding path entirely
- **Root cause:** No strict enforcement of which packets must go through the userspace path vs the eBPF path. The current `userspace_compat` mode treats eBPF fallback as acceptable, but there is no `userspace_strict` mode that would fail-closed on unexpected fallback
- **Impact:** Policy evaluation, NAT, and session accounting diverge between eBPF and userspace paths. In HA, synced sessions may reference NAT state that only exists in one dataplane, causing post-failover black holes
- **Plan:** Define DataplaneMode enum (#303), ban transit fallback in strict mode (#304), scope PASS_TO_KERNEL to control-plane only (#305), XSK liveness fail-closed (#306), per-interface entry program + fallback counters (#307)

### Silent transit fallback in userspace mode (OPEN #304)
- **Symptom:** Packets matching protocols not handled by the XDP shim (GRE, ESP, or any future protocol) get XDP_PASS and are processed by the kernel/eBPF pipeline instead of the userspace dataplane. No counter tracks these events
- **Root cause:** `xdp_xsk_shim.c` `fallback_to_main()` tail-calls into the eBPF main program for unhandled protocols. If the tail call fails (aya-ebpf limitation), it returns XDP_PASS. Neither path increments a fallback counter
- **Impact:** Users cannot tell whether traffic is being processed by the intended dataplane. Debugging throughput or policy mismatches requires packet captures

### Activation-time reverse companion repair (OPEN #310)
- **Symptom:** After HA failover, the new primary's helper caches may be cold — reverse companion sessions, SNAT pool allocations, and per-interface NAT state may be absent even though forward sessions were synced
- **Root cause:** Session sync transmits the forward session but reverse companion entries are reconstructed locally by `shared_promote`. If the helper caches are empty (daemon restart, ctrl re-enable), reconstruction may produce different NAT mappings or miss entries entirely
- **Impact:** Established connections with SNAT can break if the reverse lookup fails, causing return traffic to miss conntrack and be treated as a new flow
- **Plan:** Deterministic reverse companion generation from forward session state (#310), install fence during cutover (#311), reduce helper-local cache dependencies (#312)
