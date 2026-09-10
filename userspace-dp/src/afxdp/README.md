# userspace-dp/src/afxdp/

Primary #1373 AF_XDP forwarding path. New dataplane hot-path work belongs here
or in the adjacent userspace modules unless a legacy eBPF regression/rollback
need is explicit.

The hot path. Coordinator + per-worker threads + UMEM + RX/TX/fill/
completion rings + frame parsing + session glue + neighbor cache + HA
sync.

## Submodules

- `coordinator/` — spawns and supervises workers, owns the binding
  plan, tracks worker liveness (`#925`), publishes status snapshots,
  receives lifecycle commands from the control socket. `mod.rs` is the
  single entry that owns shared state Arcs; `worker_manager.rs` keeps
  the per-worker handle table.
  - **Worker-liveness clock (`#2332`, Rust sibling of `#1792`):** the
    binding-readiness gate in `coordinator/refresh_bindings.rs` MUST use
    a monotonic-clock freshness verdict, never the wall clock. Each
    worker stamps its heartbeat slot with `monotonic_nanos()`
    (CLOCK_MONOTONIC); `BindingLiveState::snapshot()` computes
    `heartbeat_fresh` via `bpf_map::heartbeat_fresh_mono(last_ns,
    now_mono)` in the same monotonic domain and carries the verdict on
    `BindingLiveSnapshot`. The `last_heartbeat: DateTime<Utc>` field is
    back-projected onto the wall clock for operator display ONLY — a
    forward CLOCK_REALTIME step (NTP `makestep`, VM pause/resume) would
    poison any wall-clock age and falsely mark a healthy worker unready,
    which the control plane can read as a hung worker and turn into a
    spurious VRRP failover / route withdrawal.
- `worker/` — the per-worker poll loop (`mod.rs` runs the dispatch).
- `parser.rs` — pure control-plane parsers (#947) for the two L2/L3
  learning shapes that drive the dynamic-neighbor cache: ARP replies
  (`classify_arp`) and IPv6 Neighbor Advertisements
  (`parse_ndp_neighbor_advert`). The poll-stage learn site
  (`poll_stages.rs::stage_link_layer_classify`) inserts the parsed
  `(ifindex, ip) -> mac` binding into `dynamic_neighbors` AND the kernel
  neighbor table, so these parsers are a MAC->IP write primitive — they
  MUST fail closed on untrusted input.
  - **Cold-outlined learn/program tails (`#6261`):** `classify_arp` and
    `parse_ndp_neighbor_advert` (the EtherType classifier + parser probes)
    stay inline in the hot `stage_link_layer_classify` stage, but the rare
    *accepted* ARP-reply and NDP-NA learn-and-program work (unicast/own-IP
    gates, `#2370` logical-ifindex resolve, `#4475` Override read-before-
    write, `#3048` `insert_if_changed`, `#5288`-limited kernel program) is
    moved into two dedicated `#[cold] #[inline(never)]` handlers,
    `outline_arp_reply_learn_and_program` and
    `outline_ndp_na_learn_and_program`. This is a pure codegen/layout
    change — behavior, gate ordering, and dispositions (ARP recycles, NDP
    continues/transits) are byte-for-byte identical to the pre-#6261 inline
    block; it only keeps the ordinary (non-ARP/NDP) fast path cache-hot.
    `#[cold]` is a layout hint, NOT a rate limiter — ARP/NDP flood bounding
    stays with the `#5288` per-worker `KernelNeighborProgramLimiter`.
  - **MAC-change invalidation (`#3048` / `#5147`):** the learn goes through
    `insert_if_changed`, NOT a plain `insert`, so a MAC change observed
    directly on the wire (e.g. an upstream gateway VRRP failover whose
    ARP reply / NDP NA traverses our XSK) advances that neighbor's
    **per-shard** MAC-change epoch (`ShardedNeighborMap::shard_mac_epochs`,
    indexed by the changed neighbor's shard) and evicts the now-stale
    cached `dst_mac`. Per #5147 the epoch is PER-SHARD, not a single global
    counter: a cached flow stamps the epoch of the specific shard its
    resolved next-hop lives in (`FlowCacheEntry::neighbor_shard`) and
    re-reads only that slot on each hit, so a MAC change to an UNRELATED
    neighbor (a different shard) no longer evicts it — closing the
    attacker-driven map-wide cache-thrash where one on-link IP's MAC flap
    collapsed the whole flow cache. A plain insert would write the new MAC
    first and then SHADOW the kernel-monitor RTM_NEWNEIGH that follows
    `add_kernel_neighbor` (the monitor would see `prior == new` and not
    bump), leaving the flow cache stale until session expiry. See
    `docs/flow-cache-simplification.md` "Neighbor MAC-change invalidation".
  - **Logical-ifindex keying (`#2370`):** the `ifindex` in that
    `(ifindex, ip)` key is the LOGICAL (L3) ifindex, NOT the physical
    ingress port. For a frame arriving on a VLAN sub-interface,
    `meta.ingress_ifindex` is the parent/bind port and
    `meta.ingress_vlan_id` selects the logical interface;
    `stage_link_layer_classify` resolves `(parent, vlan) -> logical` once
    via `resolve_ingress_logical_ifindex` and keys BOTH the
    `dynamic_neighbors` insert and `add_kernel_neighbor` under it. This
    matches the forwarder, which looks up neighbors by the connected-route
    (logical) ifindex (`lookup_neighbor_entry`; routes are stored under
    `iface.ifindex` in `forwarding_build/interfaces.rs`). Keying the
    insert by the physical parent (the pre-#2370 bug) made the just-learned
    entry invisible to the lookup on VLAN sub-interfaces → an avoidable
    MissingNeighbor cold-path probe and first-packet latency. Untagged
    interfaces resolve physical == logical (unchanged); a physical port
    with no matching logical sub-interface falls back to the physical
    ifindex (no drop). Two VLANs on one physical port resolve to distinct
    logical ifindexes, so a same-IP-different-subnet neighbor never
    collides in the cache.
  - **Same SSOT for zone / screen / generated-ICMP keying (`#3021` /
    `#3022` / `#3026`):** every per-ingress map keyed by the LOGICAL unit
    ifindex must resolve `(parent, vlan) -> logical` through
    `resolve_ingress_logical_ifindex` before indexing — not pass the raw
    `meta.ingress_ifindex`. `ifindex_to_zone_id` is keyed by the logical
    unit (`forwarding_build/interfaces.rs:76`); the physical parent ifindex
    only ever inherits its FIRST sub-interface's zone (lines 77-86), so a
    parent carrying multiple VLAN units in distinct zones would evaluate the
    wrong zone for every unit but the first. The three sites now mirror the
    filter (`poll_descriptor/filter.rs`) and CoS (`tx/cos_classify.rs`)
    call sites:
      - **#3021 — forwarding zone-pair:** both `from_zone` derivations in
        `poll_descriptor/mod.rs::poll_binding_process_descriptor` resolve
        the logical ingress ifindex before
        `zone_pair_ids_for_flow_with_override`, so a VLAN sub-interface is
        policed under its OWN ingress zone-pair.
      - **#3022 — screen / SYN-cookie:** `stage_screen_check` and
        `stage_screen_syn_cookie_ack_on_session_miss` resolve the logical
        ifindex before the `ifindex_to_zone_id` lookup, so the correct
        screen profile applies (a parent-zone miss would otherwise SKIP
        screening entirely, or apply the wrong profile).
      - **#3026 / #6102 — generated ICMP error (Time Exceeded + egress-MTU
        Packet-Too-Big):** `icmp.rs`
        (`build_local_time_exceeded_request`) and the TX dispatch PTB path
        (`compute_forwarded_egress_ptb` build + `enqueue_pending_forwards`
        classify) resolve the LOGICAL egress unit ifindex once via the SSOT
        (`resolve_ingress_logical_ifindex`, from the physical
        `ingress_ident.ifindex` + `meta.ingress_vlan_id`) and key the egress
        lookup, the reply BUILD, and the output-filter/CoS classify off THAT,
        NOT the physical `ingress_ident.ifindex` / `target_ifindex` /
        `bind_ifindex`. #6102 fixed the pre-existing gap where both keyed on
        the physical index (the #3026 comment even mislabelled it "the LOGICAL
        egress ifindex"): on a tagged sub-if with no untagged parent the egress
        lookup missed and the generated ICMP was silently dropped (traceroute
        `* * *` / PMTUD blackhole); with a parent it was mis-classified on the
        parent's filter/CoS. `target_ifindex` (physical) is still used for the
        XSK transmit, and the #5856 per-zone rate-limit bucket deliberately
        stays keyed on the PHYSICAL `ingress_ident.ifindex`.
      - **#3035 — generated SYN-cookie / reject reply:**
        `poll_descriptor/cookie_reply.rs` (SYN-cookie SYN-ACK / ACK-RST)
        and `poll_descriptor/reject_reply.rs` (policy/filter `reject` TCP
        RST or ICMP/ICMPv6 unreachable, and zone `tcp-rst`) classify the
        generated reply (CoS queue / DSCP rewrite / output filter) on the
        LOGICAL egress unit ifindex resolved from the physical bind /
        ingress ifindex via the SSOT, NOT the raw physical index. These two
        pre-date #3034 (#2238) and were out of its scope; the physical
        index is still used for the XSK transmit (`egress_ifindex`).
      - **#3976 — non-TCP reject reply BUILD:** the ICMP/ICMPv6
        admin-prohibited unreachable synthesized by `reject_reply.rs`
        (`build_reject_icmp_unreachable`) also keys its egress lookup
        (`forwarding.egress`, for the reply's SOURCE address and the
        `vlan_id` tag fallback) off the LOGICAL unit ifindex — not the raw
        physical `ingress_ifindex`. `forwarding.egress` is keyed by the
        logical unit, so on a VLAN sub-interface (e.g. reth0.80) the
        physical parent had no entry: the build missed, `primary_v4/v6`
        came up None, the builder returned None, and `then reject`
        silently degraded to `then discard`. Even when the parent had an
        entry, the ICMP source and the VLAN tag were the parent's, not the
        sub-if's. The TCP RST build is self-contained (it reflects the
        inbound frame, no egress lookup) and is unaffected; this mirrors
        the Time Exceeded / Packet-Too-Big builders, which resolve the same
        logical unit (#6102 — before that fix they wrongly keyed the physical
        index).
      - **#3609 — per-interface host-inbound override:** the local-delivery
        host-inbound gate (`poll_descriptor/filter.rs::host_inbound_gated_lo0_action`
        → `forwarding::host_inbound_admits_iface`) looks up
        `ifindex_host_inbound` — keyed by the LOGICAL unit ifindex in
        `forwarding_build/interfaces.rs` — with the resolved logical ingress
        ifindex threaded in by each caller (session HIT / MISS / flowless).
        Before #3609 it passed the raw physical `meta.ingress_ifindex`, so a
        host-bound packet on a VLAN sub-interface missed its per-interface
        override and silently fell back to the zone set.
      - **#5139 — flow-cache identity:** the per-worker flow cache
        (`flow_cache.rs`) now carries the LOGICAL ingress ifindex as an
        additional in-set match discriminator (`FlowCacheEntry.
        logical_ingress_ifindex` / `FlowCacheLookup.logical_ingress_ifindex`,
        resolved by `for_packet` the same way the insert path does), so a HIT
        requires the SAME VLAN unit, not just the same physical parent + 5-tuple.
        Before #5139 both lookup and insert keyed only on the physical
        `meta.ingress_ifindex`, so two VLAN units co-parented on one interface
        with the same 5-tuple aliased to one entry and VLAN B replayed VLAN A's
        decision/NAT/egress BEFORE the slow-path zone-pair policy ran
        (cross-zone fail-OPEN). Set placement (`set_index`) and invalidation stay
        keyed on the physical ifindex — the GC / RST-teardown invalidate paths
        drive `invalidate_slot` with `binding.ifindex` and cannot recover the
        logical unit from a bare session key, so keeping those physical keeps
        eviction coherent; invalidate matches physical-only and thus over-evicts
        a co-5-tuple VLAN sibling (safe — a re-miss re-evaluates from policy),
        never stranding a stale entry.
      - **#6227 item 6 / #7198 — NPTv6 embedded-ICMP reverse lookup:**
        `icmp_embed/nat_match_v6.rs::match_outer_v6` resolves the LOGICAL
        ingress unit ifindex before the `ifindex_to_zone_id` lookup that
        gates the NPTv6 reverse (inbound) translation for an embedded
        ICMPv6 error. Before this fix it keyed on the raw physical
        `meta.ingress_ifindex` — the fourth instance of this class (the
        site's own comment already stated the #5176 intent it failed to
        implement: gate on "THIS packet's ingress zone", which on a VLAN
        trunk is the logical unit's zone, not the parent's). On a trunk
        carrying multiple units in different zones, an ICMP error (e.g.
        Packet-Too-Big) for any unit but the trunk's first-configured one
        evaluated the wrong zone; a zone-scoped NPTv6 rule for the real
        zone never matched, so the embedded source stayed untranslated and
        the reverse lookup failed outright — PMTUD black-holing for that
        flow. Confined to this one reverse-lookup site: it does not affect
        policy/screen zone resolution on the forward transit path (the
        sites above already resolve correctly) and gates no permit/deny
        decision.
    Untagged ports resolve physical == logical, so all ten sites are
    no-ops there (non-VLAN behavior preserved).
  - **NA validation (`#2368`, RFC 4861 §7.1.2 / RFC 4443):** before an
    NA learns a Target Link-Layer Address, `parse_ndp_neighbor_advert`
    enforces the §7.1.2 MUSTs — IPv6 Hop Limit == 255 (the off-link
    impersonation gate: a lower hop limit means a router forwarded the
    packet, so it did not originate on-link), ICMPv6 Code == 0, ICMP
    length >= 24, Target Address not multicast, and a valid ICMPv6
    checksum (computed over the IPv6 pseudo-header via the shared
    `frame::checksum16_*` accumulator). Any failure → `None` (no learn),
    so a spoofed/off-link NA cannot poison the cache.
  - **payload_len-bounded option walk (`#2368` B, #2361 class):** the
    NDP option walk (locating the TLLA) is bounded by the IPv6-declared
    packet end (`l3 + 40 + payload_len`, rejected if it overruns the
    frame), NOT the raw Ethernet frame length. A short NA whose declared
    payload covers only the fixed header cannot smuggle a forged TLLA in
    the L2 trailer/padding — trailing slack is never read as a
    link-layer address.
  - **NS scope:** there is NO Neighbor Solicitation learning path in the
    userspace dataplane (NS is never parsed or learned), so #2368 is
    NA-only; there is no sibling NS gap to close here.
  - **ARP fixed-header validation (`#2369`, RFC 826):** the sender MAC
    (`l3+8..14`) and sender IP (`l3+14..18`) sit at offsets that are only
    correct for Ethernet/IPv4 ARP. Before reading them, `classify_arp`
    now requires htype==1 (Ethernet), ptype==0x0800 (IPv4), hlen==6, and
    plen==4 (in addition to opcode==2 reply and a fully-present 28-byte
    body). A crafted opcode-2 ARP declaring a different hardware/protocol
    type or length would otherwise be read at the fixed Ethernet/IPv4
    offsets and the attacker-chosen bytes learned as a MAC->IP binding —
    an on-link neighbor-cache/kernel-table poisoning primitive. Any
    mismatch → `OtherArp` (recycled, never learned), the ARP sibling of
    the #2368 NA fail-closed discipline. Only opcode-2 replies are ever
    learned; ARP requests (opcode 1) classify `OtherArp` and never write
    the cache.
  - **Own-IP anti-poison (`#2851` / `#3182`, RFC 826 / RFC 4861):** the
    learn paths refuse to install a neighbor entry for an address the
    router OWNS, so a host on the local link cannot teach us
    `(ifindex, our_own_ip) -> attacker_mac`. The gate is the
    `ForwardingState::owns_configured_ip(ip)` predicate, applied at three
    sites BEFORE the cache write (so a rejected own-IP neither inserts nor
    bumps the neighbor's per-shard MAC-change epoch):
      - the ARP-reply arm and the NDP-NA arm of `stage_link_layer_classify`
        (`poll_stages.rs`), and
      - the **RX source-MAC learn path** `learn_dynamic_neighbor`
        (`neighbor_dispatch.rs`, the #1787 learn reached via
        `stage_parse_flow_and_learn`), which would otherwise cache
        `(ingress_ifindex, flow.src_ip) -> src_mac` from a transit packet
        whose source IP is spoofed to one of our own IPs.
    **`owns_configured_ip` reads the NAT-DECOUPLED `configured_iface_v*`
    set, NOT `local_v*` (`#3182`).** `local_v4`/`local_v6` exclude the IP of
    any interface whose zone is an interface-mode-SNAT `to_zone`
    (`nat_translated_local_exclusions` routes it into `interface_nat_v*`),
    so under #2851 the router's own WAN/SNAT interface IP (e.g.
    `reth0.80`'s `172.16.80.8`) was NOT protected and an unsolicited
    ARP/NDP/RX-learn claiming it WAS cached. `configured_iface_v4`/
    `configured_iface_v6` capture EVERY configured interface address
    regardless of NAT role (populated in `populate_interfaces` BEFORE the
    NAT-exclusion branch); the predicate OR-s in `local_v*` so the
    late-stage static-NAT-external and DNAT-destination local-delivery
    targets appended to `local_v*` keep their protection too. NAT-translated
    POOL addresses are in neither set, so the gate stays scoped to addresses
    the router actually owns. `local_v*` continues to drive the
    `LocalDelivery` to-self disposition unchanged — only the anti-poison
    predicate switched sets.
  - **Illegitimate source-IP CLASS anti-poison (`#4889`, RFC 826 /
    RFC 4861):** ALL learn paths — including the RX source-MAC path
    (`learn_dynamic_neighbor`) — reject a learn whose learned IP falls in a
    class that can never name a real unicast next-hop: unspecified
    (`0.0.0.0` / `::`), loopback (`127/8` / `::1`), multicast
    (`224/4` / `ff00::/8`), or the IPv4 limited broadcast
    (`255.255.255.255`). The gate is the shared `neighbor_ip_is_learnable`
    predicate (single source of truth for v4+v6, `frame/inspect.rs`),
    applied BEFORE the cache write on the ARP-reply arm (`#2790`), the
    NDP-NA arm (`#2790`), and — as of `#4889` — the RX source-MAC learn
    path. That 5th path derives the neighbor identity from a LIVE transit
    frame's L3 source (`flow.src_ip`), so a normal TCP/UDP packet with a
    unicast source MAC but a spoofed source IP (`127.0.0.1` / `224.0.0.1` /
    `255.255.255.255` / `::1` / `ff02::1` / `0.0.0.0`) would otherwise seed
    an impossible `(ingress_ifindex, spoofed_ip) -> src_mac` entry. Before
    #4889 this path validated only the source-MAC class and the own-IP
    overlap (`#3182`), NOT the source-IP class — closing that gap brings it
    to parity with the L2 advert paths. Rejection is do-not-learn only (the
    packet still forwards); this is a learn-path guard, not a packet filter.
  - **STALE install + NDP Override honor (`#4475`, opus-172 H-2, RFC 4861
    §7.2.5):** the own-IP gate above only protects addresses the router
    OWNS. Every OTHER same-segment next-hop — including the WAN gateway —
    is still learnable from the data path, so an unsolicited advertisement
    (gratuitous ARP reply / unsolicited NA claiming a live next-hop with
    the attacker's MAC) is an on-link neighbor-cache poisoning / MITM
    primitive. Two bounded gates shrink that blast radius:
      - **Kernel entry is installed `NUD_STALE`, not `NUD_REACHABLE`**
        (`neighbor.rs::DATA_PATH_NEIGH_STATE`, consumed by
        `add_kernel_neighbor`). REACHABLE forced the kernel to trust the
        learned binding for the full reachable-time window with NO
        revalidation; STALE keeps the entry usable (STALE entries forward
        immediately) but runs the kernel's normal neighbor-validation state
        machine — a unicast PROBE / upper-layer reachability confirmation
        must succeed before the entry is promoted to REACHABLE, and a
        fire-and-forget poison ages out on its own. This matches Linux
        `arp_accept=0` gratuitous-ARP handling (refresh to STALE, never
        blind-promote) and PRESERVES #3048: a legitimate upstream
        VRRP-failover MAC change observed on the wire still updates the
        binding, just as STALE so the kernel confirms it.
      - **NDP NA honors the Override (O) flag** (`parser.rs`
        `NdpNeighborAdvert::override_flag` → the `stage_link_layer_classify`
        NA arm). An NA with Override=0 is NOT allowed to overwrite a cached
        entry that maps to a DIFFERENT link-layer address; it may only
        create a first-time entry or refresh the same LLA. A legitimate
        link-layer-address-change announcement sets Override=1 (§7.2.6), so
        this blocks the Override=0 hijack subclass while preserving legit
        MAC-change propagation. The check reads the per-worker
        `dynamic_neighbors` snapshot (best-effort; the worker is the sole
        data-path writer for the key) and the STALE install is the second
        line of defense for any residual race.
    ARP replies carry no Override bit, so the ARP arm relies on the STALE
    install (kernel revalidation) rather than a no-overwrite gate — a
    stricter no-overwrite would break gratuitous-ARP gateway failover
    (#3048). **Solicited-only learning** — caching a reply/NA ONLY when it
    answers a probe the router actually sent — is the stronger fix but
    needs a shared pending-solicitation table plumbed from the neighbor
    warmer (`neighbor.rs::neighbor_warmer_loop`'s `last_probed`, today
    confined to the warmer thread and an incomplete record of kernel-driven
    solicitations) into the per-worker learn path; it is DEFERRED as a
    follow-up. STALE + the Override honor already remove the
    forced-REACHABLE hijack window, which was the core of #4475.
  - **Bounded kernel-program rate limit (`#5288`,
    `neighbor_program_limiter.rs`):** `add_kernel_neighbor` allocates
    request/IP `Vec`s, opens a raw `AF_NETLINK` socket, `sendto`s an
    `RTM_NEWNEIGH`, and closes it — ALL ON THE XSK WORKER, per accepted
    advert. Before #5288 the call fired unconditionally, even for a
    same-key/same-MAC repeat whose `insert_if_changed` result was
    discarded, so an attacker streaming valid ARP replies / NAs for a
    non-owned unicast IP drove a `socket()`/`sendto()`/`close()` +
    allocations per frame → forwarding starvation on the affected queues.
    Both `stage_link_layer_classify` learn arms now gate the program
    through a per-worker `KernelNeighborProgramLimiter`
    (`BindingWorker::neigh_program_limiter`): a 64-bucket × 4-way
    set-associative table (256 slots total) recording the last
    `(key -> mac)` each way programmed and when. It **skips** a repeat the
    kernel already holds (proved by an owning way OR by
    `insert_if_changed == false`), **rate-caps** a changed-flood to ≤1
    program per 50 ms per way — which also bounds the AGGREGATE per-worker
    netlink rate to `≤ SLOTS / interval` under a many-distinct-IP flood —
    and does not lose a genuine change: a real MAC change on an owning way
    programs immediately (steady-state re-adverts do not consume the way's
    rate budget), and a change rate-limited amid a flood is retried on the
    next advert (the way keeps the OLD mac, so the binding stays "owed"). A
    genuine change whose key owns no way CLAIMS one — a never-fired way if
    free, else the LRU way, still honoring the rate cap (a way inside its
    interval is never evicted), so a single colliding key can no longer
    starve a victim (#6129): with 4 ways per bucket the victim lands in a
    different way. Residual (bounded, self-healing): up to WAYS (4)
    *churning* colliding keys mapping to one bucket can delay a 5th key's
    kernel program until a way frees; the AF_XDP fast path and userspace
    neighbor map stay correct throughout, and host-path reachability
    self-heals under normal traffic via `NUD_STALE` + on-demand kernel ARP.
    The gate decision (`should_program`) is a pure,
    allocation-free, syscall-free function pinned by fail-on-revert tests.
    Neighbor programming is a LOCAL kernel-table op, NOT HA/session-sync
    state, so the limiter is per-worker with no peer coordination.
    Persistent-socket + off-worker coalescing of the netlink send itself is
    a DEFERRED follow-up (out of #5288 scope).
- `neighbor.rs` — netlink neighbor monitor (`neigh_monitor_thread`),
  startup dump (`initial_neighbor_dump` / `process_dump_batch`), the
  on-demand resolver glue, and `worker::pin_current_thread`. The monitor
  publishes `neighbor_generation` — the epoch counter the on-demand
  resolver snapshots for its guard, and whose value `1` is the
  **"initial baseline acquired" sentinel**.
  - **Generation-1 baseline invariant (`#2919`):** `neighbor_generation`
    is advanced to `1` ONLY when a full v4+v6 startup dump COMPLETES
    (`initial_neighbor_dump` → `Ok`). A failed dump (timeout /
    `WouldBlock` / `NLMSG_ERROR`) acquired no baseline and is NOT
    published as `1`; the monitor retries the full dump on a bounded
    backoff (`INITIAL_DUMP_RETRY_BACKOFF_MS`, `stop`-aware) until one
    pass succeeds. If every retry fails the generation stays `0`
    ("baseline incomplete"); the steady-state per-batch `fetch_add` and
    the ENOBUFS re-dump path then recover the population from `0` rather
    than from a bogus `1`. The publish/skip decision is the pure
    `dump_establishes_baseline` predicate (unit-tested fail-on-revert).
    The pre-#2919 bug stored `1` on BOTH the `Ok` and `Err` arms with no
    retry, so a failed initial dump looked like a completed empty
    baseline and quiet neighbors were stranded until an unrelated later
    event — an avoidable first-packet blackhole after startup / HA
    failover. The seq-0 absorb in `process_dump_batch` (`#2918`) is the
    sibling completeness fix on the success path and is preserved.
- `poll_stages.rs` — sibling of `worker/`, not inside it. Holds the
  per-packet pipeline stages extracted in #946 Phase 1.
  - **#7699 — the PPTP control-segment dispatch.**
    `stage_parse_flow_and_learn` recognises a TCP flow with 1723 on EITHER
    side (`is_pptp_control_flow`) and copies the segment's payload into
    `WorkerContext::pptp_control` (`capture_pptp_control_segment`, `#[cold]`).
    It does NOT parse. The worker's periodic drain
    (`worker_queue::drain_pptp_control_inbox`, called from `loop_body`
    beside the association expiry) parses, installs into the local table and
    broadcasts to the siblings. Three things about this are load-bearing:
    - **Why a stage and not `loop_body`.** No `&mut SessionTable` site in the
      worker loop has a packet frame, and no stage has a mutable session
      table — frame and table are never co-located. Writing through a shared
      handle on `WorkerContext` is the same solution `dynamic_neighbors`
      already uses, under the identical constraint its doc states: *the caller
      does not need visibility into what was learned for the same packet*. An
      association is needed by the GRE data packets that FOLLOW, never by the
      control segment that taught it.
    - **The interval gate lives in `PptpControlInbox::take_pending`, not at
      the call site.** The drain's caller runs at packet rate, so a call-site
      gate is one edit from becoming per-poll work — the defect #8399 shipped
      when the association expiry landed above `expire_stale_entries_ha`'s
      gate. Keeping it in the callee makes "how often" a property of the
      function.
    - **The drain installs locally AND broadcasts.**
      `WorkerContext::peer_worker_commands` EXCLUDES this worker, so a
      broadcast alone teaches everyone but the worker that saw the segment —
      and RSS does not co-locate the control and data channels, so that
      worker is as likely as any to be the one the GRE data lands on.

    Recognising the port is two comparisons on a tuple the stage already
    parsed; COPYING additionally needs the TCP data-offset read
    (`frame::tcp_payload_offset`). "Off the hot path" buys the parse, not the
    test for whether to parse.

    **The DATA-channel resolve is wired** (`gre_discriminator::
    pptp_data_session_flow`, called from `poll_descriptor/mod.rs`). A version-1
    GRE packet resolves `(dst, call_id)` against the association table via
    `PptpAssociations::resolve_and_touch` and gets
    `TunnelDiscriminator::Pptp(handle)`; an unresolved one is counted
    (`unassociated`) and forwarded flowless, never dropped. This paragraph
    previously said the opposite — that the resolve had no production caller —
    which was true when #7699's control-segment dispatch landed and was
    hollowed by #7699's own later data-channel work (#9298 corrected it). The
    `pptp` `alg_type` still does not exist.

  - **#9298 — the QUOTED Call ID, for ICMP errors about a PPTP tunnel.**
    Because the data path above gives a live PPTP call
    `TunnelDiscriminator::Pptp(handle)`, and `SessionKey`'s Hash/Eq include the
    discriminator (#7188), an ICMP error QUOTING such a packet has to arrive at
    the same handle or its lookup misses. It could not:
    `gre_transit_discriminator` returns `Unparseable` for every version-1
    header, deliberately (version 1 re-purposes the 32 bits after the flags as
    `Payload Length | Call ID`, and reading them as an RFC 2890 Key would
    promote a per-packet-varying length into a tunnel identity). #9031 closed
    the RFC 2890 half of the embedded lookup and named this half as remaining.

    The split, mirroring the transit path: `icmp_embed/parse.rs` extracts the
    quoted Call ID as raw BYTES (`EmbeddedV4Header::pptp_call_id` /
    `EmbeddedV6Header::pptp_call_id`, bounded by the quoted datagram's DECLARED
    end per #2361), and `icmp_embed::resolve_quoted_pptp_discriminator` turns
    it into a handle where the association table is in scope. It upgrades ONLY
    `Unparseable` — a correctly-parsed RFC 2890 identity is returned untouched
    — and a Call ID that resolves to nothing STAYS `Unparseable` rather than
    matching anything, because PPTP calls between one address pair are
    distinguished by nothing else. It uses non-touching `resolve`, not
    `resolve_and_touch`: an ICMP error is traffic ABOUT the call, not on it, so
    refreshing on it would let errors keep a dead association alive and hold a
    16-bit id against reuse.

    A miss here is a MISS, not a drop: `try_reverse_embedded_icmp_error`
    returns `NotHandled` and the caller falls through to normal flowless
    enforcement. What the miss costs is the NAT reversal — PMTUD and
    unreachables for the tunnel — which is the same loss #9031 measured for
    keyed GRE.

  The screen and
  SYN-cookie stages decide the L3 offset (14 vs 18) on tag PRESENCE
  (`meta.ingress_vlan_present != 0`), not `vlan_id > 0` — 802.1p
  priority-tagged frames carry a real 802.1Q tag with VID 0, so a
  VID-based test would mis-read the IP header at offset 14 (#2145).
  - **#3064 + #3902 — source-independent screens on the flowless path:**
    `stage_screen_check` resolves the ingress zone BEFORE branching on
    `flow`, and on the flowless branch (`flow == None`) it runs the
    SOURCE-INDEPENDENT screens via `ScreenState::check_flowless_screens`
    against the zone profile: LAND anti-spoof, the three L3-header fragment
    screens (ping-of-death, teardrop, icmp-fragment), ip-source-route, and
    the per-zone ICMP/UDP flood counters. A non-first IP fragment (`#2344`)
    and a non-query ICMP/ICMPv6 control message (`#3290`) are deliberately
    flowless (`parse_session_flow_from_bytes` returns `None` so the payload
    is never parsed as an L4 tuple). #3064 first restored the three fragment
    screens here (before it, the flowless branch short-circuited to `Pass`,
    leaving them DEAD so hostile Teardrop / Ping-of-Death contributions
    transited unscreened). #3902 closes the remaining gap: the flowless
    branch ran ONLY those three fragment screens, so LAND / ip-source-route /
    ICMP flood / UDP flood — which need NO transport flow — were BYPASSED on
    the flowless path (screen fail-open). The branch now derives the REAL L3
    source/destination addresses from the IP header (`flowless_l3_addrs`) so
    LAND (`src_ip == dst_ip`) evaluates correctly instead of on the pre-#3902
    unspecified placeholder (which would have looked like `src == dst` on
    every flowless packet); if the frame is too short to hold the addresses,
    LAND is skipped (`addrs_known == false`) rather than false-dropped. The
    branch still never reads L4 ports or does a session lookup, so the #2344
    flowless fast path is NOT reintroduced. Flow/session-dependent screens
    (TCP-flag bits, the SYN-flood per-source/per-destination sketches,
    scan/sweep, SYN-cookie) require a flow / real TCP header and stay gated
    on the flow-present `check_packet_with_zone_id` path — unchanged, with no
    screen double-run on the flow path. A truncated/unparseable header fails
    CLOSED (drop), matching the flow path (`#2146`).
  - **#4567 — flowless UDP fragment folds into the per-destination-IP flood
    bucket:** the flow-present UDP flood cap keys on `(dst_ip, dst_port)`
    (Junos parity, `#4112` F18), but a non-first fragment carries no L4 port,
    so the flowless caller passes `dst_port == 0`. `udp_flood_drop` now counts
    that port-less fragment via the per-destination-IP `increment(dst_ip)`
    bucket — the SAME abstraction the ICMP flood path uses (`icmp_flood_drop`)
    — instead of `increment_ip_port(dst_ip, 0)`, which parked trailing
    fragments in a stray `(dst_ip, 0)` sentinel-port cell distinct from both
    the datagram's real `(dst_ip, port)` cell and the ICMP per-IP cell. A
    first/atomic fragment or a normal datagram carries its real port and still
    counts at `(dst_ip, dst_port)`, unchanged. Converging a trailing fragment
    onto its datagram's real `(ip, port)` cell would need reassembly context
    xpf lacks, so the per-IP fold is the bounded, honest abstraction (LOW —
    per-port datagram DELIVERY is already capped by first-fragment counting;
    this only keeps trailing-fragment noise in one consistent per-IP cell).
  - **#4155 — no screen rate double-count on fabric-redirected traffic:**
    a packet that ingressed the non-owner node was already screened there
    before being fabric-redirected to the RG owner (`docs/fabric-cross-chassis-fwd.md`).
    Stage 9 sets `FABRIC_INGRESS_FLAG` on `meta.meta_flags`; `stage_screen_check`
    now derives `skip_rate_flood` from it and threads it into
    `check_packet_with_zone_id_opts` / `check_flowless_screens_opts`. When set,
    the stateless per-packet screens (land, ping-of-death, teardrop,
    icmp-fragment, source-route) still run on the owner — they are idempotent —
    but the RATE-based flood counters (icmp/udp/syn-flood + SYN-cookie) are
    skipped so the same packet is not counted twice against the per-zone /
    per-destination thresholds (which would false-trip a flood Drop on a legit
    synced session). The per-`(zone, src)` scan/sweep new-flow counter is
    skipped the same way (`packet_fabric_ingress`) at the session-miss decision
    in `poll_descriptor/mod.rs`; the per-IP session-limit check there still runs.
    The per-destination flood sketches (#4132) are untouched — the fix skips the
    re-count, it does not disable the screen. vSRX parity: screens fire once, on
    the true cluster-ingress node.
  - **#3291 — zone policy / input filter / PBR on the flowless TRANSIT
    arm:** #3064 restored only the *screen* engine on the flowless path;
    zone security policy, the interface input filter, and firewall-filter
    PBR (`then routing-instance`) still ran ONLY inside the
    `if let Some(flow)` arms, so a non-first fragment (or any flowless,
    no-L4 transit packet) was forwarded the moment a route existed — a
    `deny-all` zone pair, a `from is-fragment then discard` filter, and a
    `from is-fragment then routing-instance <ri>` PBR term all silently
    no-op'd (fail-OPEN). The flowless `else` arm of
    `poll_binding_process_descriptor` now builds a synthetic L3-only
    `SessionFlow` (`frame::l3_session_flow_from_meta`, ports forced to 0,
    NEVER inserted into any session index) and runs, in the same order as
    the flow-backed session-miss arm: (1) `evaluate_non_pbr_input_filter`
    (the frame `TermMatchExtra` carries `is_fragment` + `l4_present = false`,
    so an `is-fragment` term matches while tcp-flags / icmp-type / flex
    predicates fail closed); (2) `ingress_route_table_override` PBR, then a
    route lookup against the override table when a PBR term matched — a
    routing-instance term that also carries `reject`/`discard` returns
    `RouteOverride::Drop` (#4392) and the packet is recycled here (silently,
    no reject reply is synthesized on the flowless path), NEVER forwarded into
    the routing instance;
    (3) zone policy via `evaluate_policy_result_l3_aware(.., l4_present =
    false)` — gated to `ForwardCandidate` (transit) so host-inbound
    (#3292) / NoRoute / fabric arms are untouched. The `MissingNeighbor`
    flowless case is enforced separately (#4024): #3291 deferred it to
    "its own cold-path arm", but that arm's #1913 policy gate is
    `if let Some(flow)` and so never fired for a flowless (flow == None)
    packet — a flowless fragment whose next-hop neighbor was unresolved
    was FIB-reinjected and the kernel forwarded it, so a `deny-all` zone
    pair FAILED OPEN for it. The `MissingNeighbor` arm now has an `else`
    (flow == None) branch that rebuilds the L3 tuple
    (`frame::l3_session_flow_from_meta`) and runs the SAME
    `evaluate_policy_result_l3_aware(.., l4_present = false)` gate BEFORE
    the neg-cache probe / `#1769` resolver enqueue / kernel ARP-NDP probe
    / `pending_neigh` buffer / trailing reinject — a deny converts the
    disposition to `PolicyDenied` so the #1913 reinject chokepoint drops
    it fail-closed; a permit stays `MissingNeighbor` and takes the normal
    buffer-and-retry forward path. A non-Permit verdict is a SILENT drop
    (a fragment has no L4 header to synthesize a TCP RST / reject from)
    plus a `PolicyDeny` event. The
    `l4_present = false` flag makes PORT-BEARING application/filter terms
    fail closed (a flowless packet's port 0 can never confirm an
    `application junos-http` or a `destination-port 80` term), while
    `application any` / address / protocol / `is-fragment` terms still
    match — so legitimately-permitted flowless forwarding survives. KNOWN
    LIMITATION: a flow PERMITTED only by an L4-specific term (e.g.
    `application junos-https`) has its non-first fragments fall to the
    default policy (fail-closed drop) until the deferred
    fragment-association-cache stage of the #3291 plan carries the first
    fragment's verdict; tracked as the deferred fragment-association-cache stage of #3291.
  - **#5467 — egress `filter output` on the flowless TX path:** the #3291 gate
    above enforces the INGRESS input filter / PBR / zone policy on a flowless
    packet, but the EGRESS interface `filter output` was evaluated only on the
    flow-keyed TX-selection path (`resolve_cos_tx_selection_*`,
    `afxdp/tx/cos_classify.rs`). A non-first fragment / non-query ICMP packet
    reached that resolver with `flow_key = None` and hit an early return that
    skipped output-filter evaluation entirely — so an egress
    `then discard`/`reject`/`log` term matching such a packet was silently
    bypassed (fail-OPEN). The flowless `None` arm now reconstructs the packet's
    own L3 tuple from the shim-stamped meta (`ForwardPacketMeta::l3_addrs`,
    ports forced to 0) and evaluates the output filter through the SAME entry
    point the flow-keyed path uses (`interface_output_filter_needs_tx_eval` +
    `evaluate_filter_ref_tx_selection_{,runtime_}counted`), collapsing
    `drop`/`reject`/`filter_log` identically. Ports are 0, so a port-BEARING
    output term never matches a fragment (no spurious drop — the #2357/#3290
    guarantee is preserved); only an L3-only term
    (`source-address`/`destination-address`/`protocol`/bare `then`) takes
    effect, and with no matching term the packet still egresses (pass-through
    unchanged). Queue / DSCP-rewrite selection is untouched — this gate ADDS
    enforcement only. A flowless `then reject` is a SILENT drop (the fragment
    has no L4 header to synthesize a reply from, #3615) — `forward_request`
    keeps the reject reply gated on a real L4 flow — but the packet is still
    dropped, and when a `then log` term matched, the filter-log event is
    attributed via the L3-only flow (`frame::l3_session_flow_from_meta`).
  - **#6055 — cached flowless TX arm brought to #5467 parity (latent
    fail-open closed):** the #5467 fix above landed only on
    `resolve_cos_tx_selection_internal` (the non-cached `_at`/queue-id path).
    Its sibling `resolve_cached_cos_tx_selection` (the flow-cache SEED / mirror
    descriptor builder, `afxdp/tx/cos_classify.rs`) kept a flowless
    (`flow_key = None`) arm that returned `drop:false, reject:false,
    filter_log:None` WITHOUT evaluating the output filter. That arm is
    UNREACHABLE for enforcement today (the seed caller always passes a flow
    key; the mirror caller read only `.queue_id`, and since #8367 asks for the
    queue alone), so there is no active bypass — but any future caller reading
    `.drop`/`.reject` from a flowless result would silently reintroduce the
    #5467 fail-open.
    The cached flowless arm now evaluates the output filter through the SAME
    entry the flow-keyed cached arm uses
    (`interface_output_filter_needs_tx_eval` +
    `evaluate_filter_ref_tx_selection_cached`, ports forced to 0) and collapses
    `drop`/`reject`/`filter_log` identically, so an L3-matching egress deny
    FAILS CLOSED at parity with `_at`. The cached eval applies
    `TermMatchExtra::default()` (every per-packet-L4 term fails closed); the
    flow-cache SEED path already declines caching for any filter carrying such
    a term (`interface_output_filter_has_per_packet_l4_match`,
    `afxdp/flow_cache.rs`), so no per-packet-L4 output term ever reaches this
    arm. The `drop` bit is the OUTPUT terminal action only (a three-color
    policer runs at replay via `apply_cached_three_color_policers`), matching
    the flow-keyed arm's #3608 convention. rev5467 MINOR 2 (`port_match` not
    gated on `l4_present`, an over-block that is fail-CLOSED and pre-existing on
    both the #3291 input and this output flowless path) is left as a tracked
    follow-up.
  - **#8367 — the cached flowless arm's tuple must be POST-NAT, and the key is
    now REQUIRED rather than defaulted:** the #6055 arm above evaluated the
    output filter from three INDEPENDENT reads of the ingress `meta` — the
    filter FAMILY (`meta.addr_family`), the matched ADDRESSES
    (`ForwardPacketMeta::from(meta).l3_addrs()`) and the PROTOCOL
    (`meta.protocol`). `meta` is the PRE-NAT tuple for any translated packet,
    and Junos applies an interface `filter output` on the EGRESS interface
    AFTER NAT (#3642), so under plain SNAT/DNAT a `from source-address <pool>`
    term did not match a packet whose on-wire source IS the pool address, and a
    `from source-address <private range>` term matched one that no longer
    carries it. #7656 fixed the same defect on the FRESH flowless arm, but only
    reached this one for NAT64 — and `flow_cache::should_cache` excludes NAT64
    (`&& !decision.nat.nat64`), so the cached arm's entire population is exactly
    the plain SNAT/DNAT case #7656 could not touch. **Measured before changing
    anything, and it changes what the fix is for:** the arm was UNREACHABLE with
    a wrong tuple. `flow_cache.rs` always seeds with a flow key, and
    `mirror_cos_queue_id` — the only caller that reached the flowless arm —
    consumed `.queue_id`, which is computed BEFORE and INDEPENDENTLY of the
    filter block. So this is HARDENING of a trap armed for the next caller, not
    an outage repair, and the trap would have presented as "the output filter
    matched the wrong address" long after the commit that armed it. The arm was
    not simply emptied instead: #6055 populated those fields deliberately so a
    future caller fails CLOSED, and returning "not evaluated" restores exactly
    the fail-open #6055 removed — while a pre-NAT tuple is *confidently wrong*,
    which is worse than either. The fix is therefore a TYPE change rather than
    three patched reads: `CachedTxTuple::{Flow{egress_wire_key,
    ingress_flow_key}, Flowless{wire_l3}}` makes the post-NAT key a REQUIRED
    field of both variants (`resolve_cached_cos_tx_selection{,_prenat,_flowless}`
    take `&SessionKey`, not `Option`), and the mirror path asks for what it
    consumes — `resolve_cached_cos_tx_queue_id`, whose flowless answer is the
    behavior-aggregate lookup alone and therefore byte-identical to what it got
    before. A caller that wants `.drop` must supply the tuple to get it and
    cannot get a wrong one by default. On the FRESH arm nothing changed: it has
    been post-NAT for any NAT since #7656 (`forward_wire_key` rewrites
    `src`/`dst` unconditionally; only family and the ICMP/ICMPv6 swap are gated
    on `nat.nat64`) — but every #7656 cell is NAT64, so that was right by side
    effect and unbound: narrowing `l3_wire_session_flow_from_meta` to
    `if nat.nat64 { forward_wire_key(..) }` left 5251 of 5252 cells green.
    Cells: `flowless_snat_egress_output_filter_matches_the_postnat_tuple_8367`
    (`tests_fragment.rs`, end-to-end interface SNAT, address-bearing terms on
    both the pre- and post-NAT source, flow-bearing positive control, and
    separate assertions for the MATCH site and the log-ATTRIBUTION site — each
    reverts independently),
    `cached_flowless_output_filter_matches_the_postnat_source_8367` and
    `cached_flowless_output_filter_reads_family_and_protocol_from_the_wire_key_8367`
    (`cos_classify_tests.rs`).
  - **#5690 — generic embedded-ICMP NAT reversal on the flowless arm:** an
    inbound non-query ICMP error (Time-Exceeded, Dest-Unreachable, PTB,
    Parameter-Problem, Redirect) referencing a NAT'd flow is itself FLOWLESS
    (#3290 above), so it never entered the flow-backed session-miss arm where
    the reversal was historically wired — the capability was helper-tested but
    DEAD in production (an ICMP error never has a flow). The flowless `else`
    arm now calls `embedded_icmp::try_reverse_embedded_icmp_error` FIRST (before
    the #3291 L3 enforcement): it matches the quoted inner packet against the
    forward NAT session (`try_embedded_icmp_nat_match_from_frame`, #8271 —
    see below), reverse-translates the
    inner tuple + outer destination back to the pre-NAT client, classifies the
    rebuilt frame's egress CoS/output filter with `flow_key = None` (a
    synthesized L3 reply carries no trustworthy 5-tuple), and queues it as a
    `Prebuilt` forward toward the client — or falls through to normal flowless
    enforcement on any miss / no-source-rewrite / unbuildable frame / CoS drop.
    The reversed error NEVER seeds a session or flow-cache entry (`flow_key =
    None`), so the #3290 no-fake-session invariant is preserved, not bypassed.
  - **#6474 — OUTBOUND ICMP error through source NAT is re-NAT'd, not
    leaked (RFC 5508 §4):** an internal host behind SNAT that emits an ICMP
    error about the session's REPLY (e.g. a port-unreachable for a closed
    socket) quotes the PRE-NAT tuple, so the quote's reply key EQUALS the
    forward session's primary key and the session-fallback matched with
    `is_reverse == false`. The #5690 builders only rewrote the outer source
    under `had_dst_nat`, so the error went out with the INTERNAL (pre-NAT)
    source on the wire and a quote the remote cannot associate — silently
    consuming the descriptor so it could not even fall through to clean
    untranslated forwarding. The fallback arms (`nat_match_v4` /
    `nat_match_v6`) now discriminate direction: a reply-key hit with
    `is_reverse == false` on a pure source-NAT flow (`rewrite_src` set, no
    dst NAT) marks the match `outbound_snat`, and
    `build_snat_outbound_icmp_error_{v4,v6}` re-NATs the outer source to
    the SNAT address and the embedded quote's destination address + L4
    port/echo id to the translated value (every affected checksum
    recomputed) — the remote associates the error with its session. A
    DNAT-carrying or no-NAT flow keeps the pre-#6474 behavior bit-for-bit,
    and an error quoting the REPLY wire tuple (as-is hit, `is_reverse ==
    true`) was already declined by the historical `rewrite_src.is_none()`
    gate into clean untranslated flowless forwarding. Both directions ride
    the admitted session like the #5690 inbound reversal (prebuilt forward,
    `flow_key = None`, gated on `allow_embedded_icmp`).
  - **#6472 — NAT64 (cross-family) ICMP error translation on the flowless
    arm:** the RFC 7915 §4.2/§5.2 translators in `nat64.rs` were previously
    reachable only via `build_nat64_forwarded_frame` on the FLOW-BACKED path,
    which an ICMP error never enters — and the #5690 same-family builders
    decline a cross-family `original_src`, so PTB / Time-Exceeded /
    Dest-Unreachable toward a NAT64 session dropped fail-closed (MissingNeighbor
    on the pool address, NoRoute on the synthetic Pref64 destination) and
    PMTUD + traceroute were dead across the boundary despite the #2219 doc
    claim. The flowless arm now tries
    `nat64_icmp_error::try_translate_nat64_icmp_error` FIRST (before the
    #5690 reversal, NOT gated on `allow_embedded_icmp` — translating errors
    for the translator's OWN admitted sessions is core RFC 7915 behavior).
    `icmp_embed::nat64_match` classifies the direction with an RFC 792
    fail-closed consistency gate (the error's outer destination must equal
    the quote's source): an ICMPv4 error quoting the forward wire packet
    matches the installed v4 reverse companion and translates v4→v6 toward
    the client (outer src = Pref64 ∷ error-sender); an ICMPv6 error quoting
    the translated reply and addressed to the synthetic Pref64 destination
    matches the forward session and translates v6→v4 toward the server
    (outer src = the translator's pool address). The embedded quote's L4
    port/echo id is restored to the value the error receiver carries
    (`write_v4_to_v6_icmp_error_into` /
    `write_v6_to_v4_icmp_error_into`: v4→v6 the original client port,
    v6→v4 the translated pool port) — without the restore the error would
    be delivered but unassociable. The translated frame shares the
    extracted `queue_prebuilt_embedded_icmp_error` tail with the #5690 arm
    (HA/fabric finalizer, CoS classify with `flow_key = None`, prebuilt
    forward, never seeds a session).
  - **#9528 — both ICMP-error arms run AFTER the interface input filter and
    the PBR verdict:** each arm `continue`s with the descriptor consumed, and
    each used to run ahead of a gate below it. The #6472 arm ran before the
    input filter, and both ran before `ingress_route_table_override`. So an
    `input` `discard` did not drop a translated error, a `then {
    routing-instance X; discard; }` term could not drop either arm's error,
    and neither term's counter advanced. The flowless `else` arm now builds
    the L3 context, evaluates the non-PBR input filter, then evaluates the PBR
    verdict (`Drop` recycles the frame), and only then tries the #6472 and
    #5690 arms. Both evaluators are HOISTED, not duplicated: the flowless
    transit enforcement below consumes the same `route_table_override`, so
    every term counts once. A non-drop steer is not applied to an error an arm
    queues, which goes to the quoted session's owner (the #6835
    association-hit reasoning). Cells are `*_9528` in
    `tests_embedded_poll_filter.rs`, driven through `poll_binding` with a
    no-filter control each.
  - **#9162 — the embedded-ICMP reply key carries the ROUTING DOMAIN:**
    `icmp_embed::parse::embedded_reply_key` hardcoded `routing_domain: 0`,
    justified by the domain-agnostic convention in `session/key.rs`. THE
    CITATION WAS THE DEFECT: that convention governs the keys an INSTALLED
    session is INDEXED under (`reverse_wire_key` / `reverse_canonical_key`),
    whose probes `reverse_match_key` zeroes to match — it says nothing about a
    key a caller builds and hands to a lookup, which is all
    `embedded_reply_key` produces. #9271 settled the same distinction on the
    install side (the NAT64 reverse companion now carries the forward flow's
    domain); this is its lookup side, and the two must move together.
    Consequences that were live at `483badf39`:
      * **NAT64, both directions, dead in any routing instance.**
        `nat64_match.rs` resolves an INSTALLED session half through
        `lookup_session_across_scopes`, whose four probes (`key_to_handle`,
        `forward_wire_index`, and the two shared maps) are every one
        domain-PRESERVING, and it has no second, domain-agnostic arm. The
        v6→v4 arm (which resolves the forward session, domain-stamped since
        #7160) had been dead since #7160; the v4→v6 arm was correct only
        because the companion was ALSO installed at 0, and #9271 ended that
        accident. `forwards == 0` means the error is DROPPED, so PMTUD and
        traceroute across the NAT64 boundary were dead both ways in a VRF.
      * **The same-family #6474 outbound-SNAT arm** silently disabled in a
        routing instance: the quote's reply key IS the forward session's
        primary key there, so a domain-0 probe missed and the #5690 identity
        reversal put the INTERNAL (pre-NAT) source on the wire instead.
    The fix threads the caller's domain in.
    `nat64_match.rs` now derives it with `ingress_routing_domain` the way
    `nat_match_v4.rs` / `nat_match_v6.rs` already did — that file previously
    contained ZERO `routing_domain` references while both siblings carried
    one, which was the issue's own positive control. Passing a real domain is
    correct in BOTH index families: the exact lookups need it, and the
    reverse-MATCH index (`find_forward_nat_match`,
    `lookup_shared_forward_nat_match`) zeroes the probe ITSELF before hitting
    its bucket and spends the domain on a per-tenant preference, so stamping
    restores the #7160 demux there rather than breaking it. There is
    deliberately NO domain-agnostic retry in the NAT64 arm: the only fallback
    available would be a retry at domain 0, which is not "domain-agnostic" but
    "the DEFAULT instance" — another tenant's sessions. A flow whose error
    arrives in a different domain than the flow resolved declines to ordinary
    flowless enforcement, exactly as before the stamp existed.
- `frame/` — packet parsing (L2 / L3 / L4), checksum helpers, TCP MSS
  clamp. `tests.rs` was relocated out of `mod.rs` in #1046 Phase 1.
  `headers.rs` holds the consolidated outer-header serializers (#1440).
  The Ethernet writers emit an 802.1Q/802.1ad tag on tag *presence*
  via `TxVlanTag` (#2149), not `vlan_id > 0`: a tag is serialized when
  the VID is non-zero OR the PCP/DEI bits are set, so an 802.1p
  priority-tagged VLAN-0 frame (real tag, VID 0, PCP != 0) keeps its
  priority instead of collapsing to untagged. The reflected
  local-origin ICMP error path (`icmp.rs`) carries the inbound TCI
  (PCP + DEI + VID) and TPID through verbatim, so a priority-tagged or
  802.1ad-tagged inbound packet is reflected with its tag intact;
  untagged ingress still falls back to the egress interface's
  configured VID. The egress *config-driven* builders (forwarding,
  GRE/WG outer, TSO) still take a bare VID where VID 0 == untagged is
  the intended semantic (no PCP source on those paths) — `From<u16>`
  reproduces the legacy bytes exactly.
- `umem/` — UMEM memory region: `MmapArea` (raw `mmap`) and the
  `WorkerUmem` / `WorkerUmemPool` per-queue handle + free-frame pool.
  Frames are 4 KB (`UMEM_FRAME_SIZE = 4096`); index is `addr >> 12`.
  #6436 moved the per-binding runtime-state cluster out to
  `binding_state/`; `umem/` is now only the memory region.
- `binding_state/` — `BindingLiveState` per-binding atomics cluster
  (#6436): ring state + forwarding/session/screen/NAT counters,
  cacheline-isolated owner/peer telemetry profiles, the cross-worker
  redirect TX inbox (bounded lock-free MPSC + linearizable admission
  counter + `PendingTxAdmission` RAII token), the latency-histogram
  primitives (`bucket_index_for_ns` + wire-contract bucket counts),
  the HA session-delta RPC-fallback buffer with its #5290
  loss-of-sync latch, and the snapshot/debug-state renderers.
- `tx/` — TX ring management, batched enqueue, TSO segmentation
  (`tx/tcp_segmentation.rs` after PR #1199), per-binding TX counters.
  - `tx/dispatch/` — the per-tick forwarding dispatcher
    (`enqueue_pending_forwards`). **Recycle-on-every-path invariant
    (#2208):** the ingress descriptor is read directly from ingress
    UMEM (the RX ring already released it), so `recycle_ingress_frame`
    — pushing `source_offset` to `pending_fill_frames` → the fill ring
    — is the SOLE path that returns the frame to circulation. Every
    per-request exit MUST recycle exactly once: the loop finalizer does
    this (`if !retained_source_frame`), and `retained_source_frame` is
    true ONLY on the in-place-rewrite branch (where the descriptor IS
    the TX frame and is recycled by `PreparedTxRecycle::fill_on_slot`
    on completion). Exception/build-failure branches must FALL THROUGH
    to the finalizer, never `continue` past it — a bare `continue`
    leaks the descriptor (per-packet UMEM-pool drain → worker stall
    under TX congestion). The two enqueue-failure sites also set
    `build_failed=true; fallback_to_slow_path=true` so the finalizer's
    `handle_forward_build_failure` reinjects the frame to the slow path;
    the two oversized sites set `build_failed=true` only (the frame is
    undeliverable — drop-and-recycle, no reinject).
    **Egress-MTU PTB (#2301):** for a forwarded frame the TCP-segmentation
    path did NOT handle (non-TCP, TCP seg-miss, non-segmentable TCP) the
    dispatcher makes an egress-MTU decision (`icmp_ptb.rs`,
    `forwarded_egress_mtu_decision`) BEFORE building the oversized frame.
    The decision sizes off the IP-DECLARED L3 datagram length (IPv4
    `total_len` / IPv6 `40 + payload_len`, each clamped to the buffer) —
    the SAME length authority the PTB builders quote — NOT the raw AF_XDP
    buffer length, so ethernet padding / trailing bytes never mis-fire or
    mis-size a PTB (#2783); an unparseable/truncated IP header fails open
    to forward. When that declared length exceeds the egress MTU and the
    sender forbade fragmentation (IPv4 DF) or it is IPv6, it generates an
    ICMP
    Frag-Needed (v4 type 3 code 4, next-hop MTU per RFC 1191) / Packet
    Too Big (v6 type 2, MTU per RFC 4443) back out the ingress interface
    and drops the oversized original (`mtu_signalled` keeps
    `retained_source_frame` false → the finalizer recycles the ingress
    descriptor; a suppressed/unbuildable reply is the fail-closed silent
    drop). The reply is built inside the `target_binding` borrow and
    enqueued onto `ingress_binding` once that borrow ends.
    **Post-transform PMTUD (#2330):** the #2301 decision above compares the
    SOURCE frame against the egress MTU, which is correct ONLY for a
    size-preserving plain forward. For the size-CHANGING paths (NAT64,
    native GRE, WireGuard) the on-wire frame grows (encap) or its header
    shrinks/grows (NAT64), so a source-vs-egress comparison is wrong and
    #2301 skipped them entirely — leaving the inner source with NO PMTUD
    signal (a silent blackhole). #2330 derives the INNER-source MTU (the
    largest inner IP packet whose TRANSFORMED frame fits the
    egress/transport MTU) from the #2300/#2331 SSOT helpers
    (`post_transform_inner_mtu` → `native_gre_inner_mtu` for GRE,
    `wg::mss::wg_inner_mtu` for WireGuard, the v6↔v4 ±20 header delta for
    NAT64) and runs the SAME `forwarded_egress_mtu_decision` + builders
    against the inner `source_frame` (which IS the pre-encap / pre-translate
    inner packet, with `meta.addr_family` the inner family). The generated
    PTB carries the INNER MTU and routes through `classify_generated_reply`
    (#2328) at the finalizer, identically to the plain path. This CLOSES the
    PTB signal #2331 deferred: an oversized GRE/WG inner now yields a
    Frag-Needed/PTB instead of a silent `GRE_ENCAP_DF_OVERSIZE_DROPS` /
    `encap_mtu_drops` — and because `mtu_signalled` skips the build entirely,
    there is no double-drop/double-count with those encap guards (a non-DF
    IPv4 inner stays fragmentable → `Forward` → the #2331 drop guard remains
    the backstop). `mtu == 0` (no MTU resolvable / unknown tunnel kind)
    fails open to `Forward`.
    **Per-peer WG underlay (#2845):** for WireGuard the underlay MTU is
    NOT one-per-interface — different peers of one wg endpoint can have
    different endpoints / transport routes / underlay MTUs. The dispatcher
    threads the pre-encap inner destination into `post_transform_inner_mtu`,
    which passes it to `frame::wg_endpoint_physical_outer_mtu`. That helper
    selects the SAME peer the encap path will (`engine.peer_for_dest` —
    AllowedIPs LPM on the inner destination) and resolves the physical
    underlay MTU via THAT peer's endpoint route, so the advertised inner PMTU
    matches the underlay the encap guard will actually admit the packet onto.
    When the inner destination is unavailable, no live engine is present, or
    no peer covers it, it falls back to the first peer with an endpoint (the
    pre-#2845 per-interface behaviour — byte-identical when all peers share
    one underlay). A covering peer with NO endpoint resolves to the
    conservative logical-ifindex MTU rather than borrowing a different peer's
    underlay.
- `icmp_ptb.rs` — #2301 PMTUD error generators for the generic
  forwarder: the egress-MTU decision plus the ICMPv4 Frag-Needed /
  ICMPv6 Packet-Too-Big builders (MTU in the body). Mirrors
  `icmp.rs`'s reflected-error shape (L2 reflect + ingress-sourced outer
  IP + quoted inbound packet) but sets the MTU field; reuses the shared
  header/checksum helpers and the RFC error-suppression gate
  (`reject_icmp_reply_suppressed`, `is_non_first_fragment`,
  `dest_is_multicast_or_broadcast`). Kept separate from `icmp.rs` so the
  diff stays additive. #2314: the PTB gate (`ptb_reply_suppressed`) now
  also drops PTBs triggered by a multicast/broadcast-destined datagram
  (RFC 1812 §4.3.2.7 / RFC 4443 §2.4(e)), sharing the
  `dest_is_multicast_or_broadcast` predicate (`frame/inspect.rs`) with
  `icmp.rs`'s `can_generate_icmp_error_reply` so the PTB, reject, and
  Time Exceeded paths agree on the L3 destination test. #2325: the same
  gate now also drops PTBs triggered by a datagram delivered as a
  link-layer (L2) broadcast/multicast frame, giving the PTB path the same
  L2+L3 suppression the reject / Time-Exceeded path already had — both
  call the shared `l2_dst_is_group_or_broadcast` predicate
  (`frame/inspect.rs`, the IEEE I/G group bit on the destination MAC's
  first octet; all-FF broadcast is a group address). #2367: the gate now
  also drops PTBs triggered by a datagram whose IP SOURCE is not a single
  unicast host (unspecified, loopback, multicast, or — for IPv4 —
  broadcast). The PTB is addressed to the trigger's source, so a forbidden
  source would emit spoofable ICMP backscatter; this is the L3-SOURCE half
  of RFC 1812 §4.3.2.7 / RFC 4443 §2.4(e). Both `ptb_reply_suppressed` and
  `can_generate_icmp_error_reply` now call the shared
  `source_is_invalid_for_icmp_error` predicate (`frame/inspect.rs`), so the
  PTB, reject, and Time-Exceeded paths apply ONE bad-source set (the
  reject gate's inlined source check was refactored to call it, closing
  the forkable per-error-type suppression contract). No new counter: a
  suppressed PTB is folded into the existing fail-closed silent-drop path
  (the oversized original is still dropped via `mtu_signalled`). #2328: a
  PTB that IS generated is now classified by its OWN egress 5-tuple through
  the shared `classify_generated_reply` (`tx/cos_classify.rs`) before the
  enqueue in `tx/dispatch/mod.rs`, exactly like the ICMP/ICMPv6 Time
  Exceeded (#2238), policy-`reject`, and SYN-cookie generators — so an
  output firewall filter `discard`/`reject` / CoS forwarding-class / DSCP
  rewrite keyed on the generated ICMP fires, and the resulting
  `cos_queue_id`/`dscp_rewrite` drive the PTB TxRequest (pre-#2328 it was
  `None`/`None`). An output-filter drop lands on `ptb_output_filter_drops`;
  a parse failure of the built bytes fails CLOSED on
  `generated_reply_classify_parse_errors` (§6.2), never leaking the PTB
  past an output `discard`. #2411: the gate now ALSO drops ICMP errors
  (reject, Time-Exceeded, and PTB) triggered by an IPv4 datagram destined
  to a *subnet-directed* broadcast — the all-ones host of a configured
  connected prefix, e.g. `10.0.1.255` for a connected `10.0.1.0/24`. RFC
  1812 §4.3.2.7 forbids originating an ICMP error to any broadcast,
  directed broadcasts included; but a directed broadcast is a plain
  unicast to the limited-broadcast (`255.255.255.255`) / multicast tests,
  so recognizing it needs the configured subnet MASK. The new shared
  `dest_is_directed_broadcast` predicate (`frame/inspect.rs`) reuses the
  forwarding state's connected-route table (`connected_v4`, the SAME rows
  the FIB lookup scans — no new infrastructure) and suppresses when the
  destination equals `network | !mask` of a connected prefix shorter than
  /31 (a /31 has no broadcast per RFC 3021 and a /32's all-ones host is
  the host itself, so both are skipped to avoid mis-suppressing a
  legitimate unicast). `can_generate_icmp_error_reply` and
  `ptb_reply_suppressed` both take `&ForwardingState` and call it (v4-only
  — IPv6 has no broadcast), so the reject, Time-Exceeded, and PTB paths
  apply ONE directed-broadcast gate. The lookup is a COLD-path scan: it
  runs only when an ICMP error is about to be generated, never on the
  per-packet fast path. No new counter — a suppressed error folds into
  the existing fail-closed silent drop.
  #2487: the SOURCE-side sibling of #2411. A locally generated ICMP error
  is addressed TO the trigger packet's source, so a *subnet-directed
  broadcast* SOURCE (the all-ones host of a connected prefix, e.g.
  `10.0.1.255` for `10.0.1.0/24`) produces an error emitted to that
  directed broadcast — delivered to every host on the segment
  (Smurf-style amplification / backscatter). The limited-broadcast test
  in `source_is_invalid_for_icmp_error` (`is_broadcast()`) only catches
  `255.255.255.255`; a subnet-directed broadcast is a plain unicast to it
  and needs the configured subnet MASK. The new shared
  `src_is_directed_broadcast` predicate (`frame/inspect.rs`) reuses the
  SAME `connected_v4` scan (extracted into the shared
  `v4_addr_is_directed_broadcast` helper that `dest_is_directed_broadcast`
  also now calls) and the SAME `/31`/`/32` prefix-length guards. The IPv4
  arms of `can_generate_icmp_error_reply` and `ptb_reply_suppressed` call
  it alongside the existing source check (v4-only — IPv6 has no
  broadcast), so the reject, Time-Exceeded, and PTB paths apply ONE
  bad-source set covering both the limited and directed broadcast. Same
  cold-path scan, no new counter, fail-closed silent drop.
  #2472: AFTER the RFC suppression + output-classification gates, all three
  locally-generated error reasons (Time Exceeded, PTB/Frag-Needed, and
  policy/filter `reject`) now also pass through a per-reason token-bucket
  RATE LIMITER (`icmp_ratelimit.rs`). Without it, a flood of TTL-1 packets,
  oversized-DF packets, or rejected flows (or a routing loop) made the box
  emit one generated error PER trigger packet, unbounded — a CPU/TX
  amplification sink and a reflection vector (the errors are addressed to the
  trigger's source, which an attacker can spoof). The bucket is
  GLOBAL-PER-REASON (no per-source / per-destination map → no
  attacker-driven state growth), modelled on Linux's `net.ipv4.icmp_msgs_per_sec`
  (a global per-host burst). Each reason has its OWN bucket so a TTL-exceeded
  flood cannot starve PTB or reject (per-reason isolation). Defaults:
  `DEFAULT_RATE_PER_SEC = 1000` tokens/s refill + `DEFAULT_BURST = 1000`
  capacity, PER reason (compile-time; a rate of 0 disables the limiter). The
  check is a single CAS loop over ONE atomic word — a GCRA (Generic Cell Rate
  Algorithm) theoretical-arrival-time, the same single-TAT pattern used by
  `event_stream/producer.rs` — on the cold generated-error path only, never per
  forwarded packet, no allocation. #2955: the limiter previously split its state
  into TWO atomics (a millitoken count + a last-refill timestamp) and CAS-
  committed only the token count, publishing the timestamp as a SEPARATE relaxed
  store. Under multi-worker contention two workers could read the new (lower)
  token count with the stale OLD timestamp and credit the same refill interval
  twice (double-credit), or both observe the first-use (`last_ns == 0`) branch
  and each refill to full burst — OVER-ADMITTING generated errors past the
  configured rate (a DoS-boundary weakening) and corrupting the
  `*_rate_limited_total` counters. Collapsing the state into the single GCRA word
  makes refill and consume commit together in ONE compare-exchange, so the
  admitted rate is hard-capped regardless of interleaving. On bucket-empty the generated reply is DROPPED (the TTL/reject
  paths fail-closed to the silent drop they already perform; the PTB path
  still drops the oversized original via `mtu_signalled`, so it never falls
  through to forward the MTU-violating frame) and a per-reason observable
  counter is bumped — surfaced via the coordinator status as
  `xpf_userspace_time_exceeded_rate_limited_total`,
  `xpf_userspace_packet_too_big_rate_limited_total`, and
  `xpf_userspace_reject_rate_limited_total`. The pre-existing SYN-cookie
  TX-frame budget gate on the reject path STAYS: it is queue protection (it
  keeps the reply ring from starving transit TX), a separate concern from the
  per-reason rate cap. Wired at the three generation sites:
  `icmp::build_local_time_exceeded_request`, the PTB build in
  `tx/dispatch/mod.rs`, and `poll_descriptor::reject_reply::enqueue_reject_reply`
  (covering both policy and filter reject — a single emit path).
- `cos/` — Class-of-Service scheduler: token-bucket admission, MQFQ
  active-bucket selection, fair-share lease (#1229 Phase 6 v8). See
  `docs/per-5-tuple/state.md` for the architectural ceiling.
- `forwarding/` — FIB lookup, next-hop selection, VLAN/GRE encap.
- `event_emit.rs` — fixed-size, non-blocking RT_FLOW event producers
  for userspace policy-deny, screen-drop, logged PBR filter hits, and
  non-PBR input/output/lo0 filter logs. Output filter-log identity is
  carried through live TX selection and cached forwarding so flow-cache
  hits emit the same compiled filter/term/action metadata as live paths.
  Terminal output `discard`/`reject` terms are carried in the TX selection
  descriptor and drop before enqueue; filter-log deny records must not
  describe traffic that still forwards.
  **RT_FLOW reject truthfulness (#3615):** a policy/filter `then reject`
  synthesizes an active TCP RST / ICMP unreachable, but that reply can
  fail-close AFTER the action is decided (TX-frame budget, reject token
  bucket empty, unparseable built frame, or an egress output-filter drop of
  the reflected reply). The deny/reject reply is therefore enqueued FIRST —
  `poll_descriptor::reject_reply::deny_reply_and_emit` (policy) and
  `poll_descriptor::filter::filter_terminal` (input/lo0 filter) — and its
  ACTUAL outcome is threaded into `emit_policy_deny_event` /
  `emit_filter_log_event`, which downgrade the RT_FLOW action REJECT→DENY
  when the reply was suppressed so the forensic log never claims an active
  reject that was not sent. Reply-free paths (flowless fragments, the
  PBR/output-filter forward path — #3608's silent-drop domain — and
  cached-log replay) pass `reject_reply_enqueued = false`. Suppression is
  also counted per SOURCE: `policy_reject_reply_budget_drops` /
  `policy_reject_output_filter_drops` / `policy_reject_rate_limit_drops`
  (policy) vs `filter_reject_reply_budget_drops` /
  `filter_reject_output_filter_drops` / `filter_reject_rate_limit_drops`
  (filter); the parse-error leg `generated_reply_classify_parse_errors`
  stays source-neutral (shared by every generated-reply type). The
  rate-limit split (#3661) attributes an empty-bucket drop to the reply's
  source at the consume site. #3618 made the reject rate-limit bucket PER
  INGRESS (from) ZONE — one `TokenBucket` per configured zone in
  `ForwardingState::reject_buckets`, resolved from the ingress interface's
  zone, with a process-global `REJECT_FALLBACK_BUCKET` for an unzoned/unknown
  zone — so a rejected-flow flood in one zone no longer starves reject
  generation in another. The observable aggregate `reject_rate_limited_total`
  stays a SINGLE atomic bumped on any per-zone deny, so the metric is unchanged
  and `policy`+`filter` still sum to it. #5856 extended the SAME per-zone split
  to the TimeExceeded and PacketTooBig reasons (`ForwardingState::
  time_exceeded_buckets` / `packet_too_big_buckets`, resolved from
  `ingress_ident.ifindex`), so a TTL=1/hop-limit=1 or oversized-DF flood in one
  zone no longer suppresses traceroute / PMTUD replies in another; their
  aggregates (`{time_exceeded,packet_too_big}_rate_limited_total`) are likewise
  single atoms bumped per-zone. See `docs/generated-reply-rate-limit.md`.
  DSCP-matched input/output filters
  are intentionally not flow-cached because DSCP is packet metadata, not
  part of the session cache key; session hits re-evaluate DSCP-sensitive
  input filters per packet.
  **Interface INPUT filter `then count` on cache hits (#3777):** the
  output/TX `then count` handles have been replayed on every flow-cache hit
  since #2573 (`tx_selection.filter_counters`); the INPUT side now mirrors
  that via `RewriteDescriptor::input_filter_counters`, captured once at seed
  by `evaluate_interface_input_filter_counters_cached` and replayed in
  `flow_cache_hit.rs`. A matched routing-instance (PBR) term is EXCLUDED at
  capture (its count is owned by the routing-instance evaluator, #2620), and
  the captured set is deduped against `tx_selection.filter_counters`
  (`retain_absent_from`) so a count-plus-forwarding-class input term the cos
  TX-selection rebuild already folded in is not recorded twice.
  **Per-packet CoS BA classifier on cache hits (#3778):** DSCP / IEEE 802.1p
  behavior-aggregate classifiers pick the egress queue from EACH packet's
  DSCP / PCP, but the flow-cache key excludes both, so the cached TX-selection
  froze the SEED packet's queue. `resolve_cached_cos_tx_selection` now sets
  `CachedTxSelectionDescriptor::ba_reclassify` when the queue was NOT pinned by
  a (5-tuple-stable) filter forwarding-class AND a BA classifier is configured
  on the egress interface; `flow_cache_hit.rs` then re-resolves the queue per
  packet via `reclassify_cached_ba_queue` (one FastMap lookup + two array
  reads, gated by the flag so filter-FC-pinned / default-queue / no-CoS flows
  keep the frozen queue for free). A `then forwarding-class` filter term stays
  cached (its queue is 5-tuple-stable); only the DSCP/PCP-derived queue is
  per-packet. The IEEE 802.1p (PCP) arm of `reclassify_cached_ba_queue` is
  pinned by `txn_flow_cache_hit_reclassifies_ba_pcp_per_packet_4422` (#4422): a
  priority-tagged (VID 0) PCP-0 packet seeds the default queue and a same-5-tuple
  PCP-5 hit must re-classify to the EF queue on an interface carrying ONLY an
  802.1p classifier — the DSCP arm was already pinned by
  `..._ba_dscp_..._3778`.
  **TTL/hop-limit precedes egress accounting on cache hits (#3779):** the
  cache-hit path used to run the output `then count` replay, the policy hit
  counter, the three-color policers, the filter logs, and the terminal drop
  BEFORE the TTL/hop-limit check, so a TTL=1 packet on a red-policer or
  terminal-output-drop cached flow was dropped/charged with NO ICMP Time
  Exceeded (and every expiring packet charged counters/logs for traffic that
  never egressed). The check is now hoisted to the TOP of the hit path (for
  `ForwardCandidate`/`FabricRedirect` dispositions), matching the session-hit /
  session-miss slow paths: a would-expire packet becomes a Time Exceeded reply,
  or — when TE is suppressed (ICMP-of-ICMP, rate limited, output-filter drop of
  the reply) — is dropped, in BOTH cases before any egress counter/policer/log
  moves. `observed_bytes`/active-epoch stamping in `lookup_counted` still counts
  the packet as SEEN (deliberate — it is flow-activity telemetry, not
  forwarded-byte accounting). #3779 pinned this ordering for the output
  `then count` counter;
  `txn_flow_cache_hit_ttl_expired_does_not_charge_three_color_policer_4422`
  (#4422) pins the THREE-COLOR POLICER interaction directly: a TTL=1 cache-hit
  packet leaves the egress output filter's policer green count unchanged, while
  a following live hit increments it once — proving the TTL check precedes
  `apply_cached_three_color_policers`, so an expired packet never drains a token
  bucket meant for real traffic.
  **Cached filter-log replay is seed-captured (first-packet term, #4423 M7):**
  `emit_cached_input_filter_log` / `emit_cached_output_filter_log` replay the
  single `FilterLogMatch` (`cached_descriptor.input_filter_log` /
  `tx_selection.filter_log`) frozen when the flow was cached from its SEED
  packet, so every hit logs the seed's matched `then log` term. This is a
  deliberate caching approximation in the same family as the frozen SEED queue
  (#3778): the flow-cache key excludes DSCP/PCP, so a filter whose `then log`
  term selection turns on a per-packet field (DSCP) logs the seed's term for
  the whole cached flow rather than re-evaluating the filter on each hit. The
  5-tuple-stable common case is exact; re-running the cold-path filter
  evaluation per packet purely to correct a `then log` term would defeat the
  cache. Contrast the `then count` side, which #2573 (output) and #3777 (input)
  fixed to replay EVERY matched counter — a count is a cheap handle bump, a log
  is a full RT_FLOW event, so the count/log asymmetry is intentional. Per-packet
  BA-classifier queue selection is already corrected (#3778, above); the
  per-packet filter-log term is not.
  **DSCP-rewrite `let _` is a benign no-op, not a silent failure (#4423
  M3/M4):** `apply_dscp_rewrite_to_frame` (`frame/mod.rs`) returns `None` when
  the frame has no IPv4/IPv6 DSCP field to rewrite — a non-IP frame (ARP, etc.)
  or one too short to hold its L3 header. The TX-path callers
  (`tx/transmit/rewrite.rs` prepared-TX, `tx/transmit/mod.rs` local-TX, the
  `cos/queue_service/drain.rs` CoS drains) `let _` the result deliberately:
  `assign_local_dscp_rewrite` / `assign_prepared_dscp_rewrite` stamp the
  per-CoS-queue rewrite onto ALL queued items, including any non-IP frame that
  co-resides in a DSCP-rewrite queue, so `None` there is the correct
  "not applicable" outcome — not a dropped/mis-marked IP packet. A blanket
  failure counter would false-positive on every legitimate non-IP frame; the
  only genuine-error subset (an IP frame too short for its own header) is
  unreachable on this path because TX frames are already-parsed forwarded IP
  packets. The frame egresses either way; nothing is dropped.
  Producers must use the event-stream worker handle so rate limiting,
  queue-budget accounting, replay, and daemon callback ACK behavior stay
  centralized in `event_stream/`.
- `session_glue/` — bridges the userspace session table back to the
  BPF session map mirror so the CLI / GC see the same sessions.
- `types/` — shared structs: `BindingPlan`, `BindingStatus`,
  `WorkerRuntimeAtomics`, `SharedCoSQueueLease`, `BatchCounters`, …

    **#8271 — both ICMP-error arms parse the DECAPPED frame.** The NAT64
    ICMP-error arm and the embedded-ICMP reversal arm each CLASSIFY on
    `packet_frame` at the inner `meta.l4_offset`, and each used to hand its
    helper `raw_frame` + `desc` — the still-encapsulated OUTER frame — with the
    INNER `meta`. On a native-GRE-decapped packet those describe different
    packets: `stage_native_gre_decap` rebinds `meta` to the inner frame while
    `desc` still references the un-decapped outer one, so the helper parsed
    outer bytes at inner offsets. This is the #1885/#1902 class; two sibling
    arms of `poll_binding_process_descriptor` were fixed for the identical
    pairing and carry comments saying so, and these two were not. Both helpers
    now take the frame they PARSE (`packet_frame`) and keep `desc` only for
    queueing the original UMEM frame, which is what `desc` is for. The
    `(area, desc)` wrapper `try_embedded_icmp_nat_match` was DELETED rather
    than left unused — its only behaviour was to pair whatever frame `desc`
    pointed at with whatever `meta` it was handed, so removing it removes the
    ability to make the mistake. Guarded by
    `gre_decapped_embedded_icmp_reversal_reads_the_inner_frame_8271` and
    `gre_decapped_nat64_icmp_error_reads_the_inner_frame_8271`
    (`tests_embedded_poll_filter.rs`), both on a VLAN-TAGGED underlay: on an
    untagged one the mis-paired read lands on a valid version nibble and fails
    as a miss, so an untagged fixture passes under the defect for the wrong
    reason.

## Manager-neighbor replace generation envelope (#5864 → #6034)

The Go control plane pushes an authoritative manager-neighbor table to the
helper over the `update_neighbors` control message (handler
`server/handlers/neighbors.rs`, applied by
`Coordinator::apply_manager_neighbors`). This is the "Go-snapshot" neighbor
write path (the fourth MAC→IP write path — the in-process monitor, the
data-path learn, and the on-demand resolver are the others).

- **#5864 clear-on-empty:** an authoritative `neighbor_replace = true` with an
  empty publishable set must CLEAR the table. The Go side dropped `omitempty`
  on `Neighbors`, and the handler applies a clear on absent/`null`/`[]` under
  replace instead of early-returning.
- **#6034 replace-generation envelope + ACK/retry:** each authoritative replace
  carries a monotonically increasing `neighbor_generation`
  (`Manager.neighborReplaceGen`, Go). `apply_manager_neighbors(replace,
  generation, ..)` REJECTS a replace whose `generation <= last applied`
  (`NeighborManager::applied_manager_generation`) — a stale / reordered
  delivery must not clobber a newer table — and returns `false` without
  touching the table. This is defense-in-depth: the single synchronous control
  socket does not itself reorder. The applied generation is ACK'd back in
  `ProcessStatus.manager_neighbor_generation` (distinct from
  `neighbor_generation`, the dynamic ARP/NDP resolver epoch); the Go send path
  advances its cached neighbor view only when the ACK confirms the replace
  landed (`>=` the sent generation), otherwise it RETAINS retry debt and the
  next event-driven / 60s-safety regeneration re-diffs and retries with a
  strictly higher generation. **Backward-compatible:** a `generation == 0`
  (unversioned / pre-#6034) push bypasses the fence and never advances it, and
  an older helper that omits the ACK field decodes 0 on the Go side → "no ACK
  support, assume applied" (pre-#6034 behavior). The retry piggybacks the
  existing regeneration cadence — it adds NO new control-socket caller.

## Worker command-queue poison policy (#1790 → #1807)

Coordinator↔worker commands flow through per-worker
`Mutex<VecDeque<WorkerCommand>>` queues. A worker panic while holding
the lock (contained by the #925 supervisor) poisons the mutex. The
uniform policy lives in `worker_queue.rs` and is mandatory for every
access — do NOT call `.lock()` / `.try_lock()` on these queues
directly:

- `lock_recover` / `try_lock_recover` recover a poisoned lock via
  `into_inner`, **clear the poison** (restoring the fast unpoisoned
  path), and bump the recovery counter surfaced as
  `xpf_userspace_worker_command_queue_poison_recoveries_total`.
- The recovered deque holds the **committed prefix** of every completed
  push — a panic between the pushes of a multi-push section leaves
  exactly the commands pushed before it. Commands are individually
  self-contained, so consumers tolerate partial batches; discarding the
  deque would lose acknowledged HA/session commands.
- `push_bounded` is the ONLY way a command may be enqueued (#6929). It
  refuses at `MAX_PENDING_WORKER_COMMANDS` (4096, matching
  `MAX_PENDING_SESSION_DELTAS`) and bumps the counter surfaced as
  `xpf_userspace_worker_command_queue_drops_total`. Read that counter
  ALONGSIDE the poison counter above, never as a substitute: a poison
  recovery keeps the committed queue and loses nothing, a capacity drop
  discards a command, and the two have opposite remediations.
  - The expected steady-state value is **0**, and not because the queue
    is roomy: what a producer has to outrun is the consumer's
    ~1 µs/command PROCESSING rate, which no control-plane producer
    sustains. A rising counter therefore does not mean "busy" — it means
    a worker has STOPPED draining. `spawn_supervised_worker` catches a
    `worker_loop` panic, sets `runtime_atomics.dead = true` and lets the
    thread exit, but the worker RECORD is never removed and producers
    fan out over `records.values()` with no `dead` check, so they keep
    enqueueing into a queue nothing will drain.
    - #6929 originally justified this as "the consumer drains the WHOLE
      deque in one `core::mem::take` per poll". **That is no longer how
      the drain works** — see the bounded prefix drain below — but the
      conclusion is unchanged, because it never rested on the drain
      granularity. The bounded drain absorbs the same commands/second
      and simply revisits the queue ~16x more often.
  - It refuses the NEWEST rather than evicting the oldest. The queue
    carries ordered state transitions (`UpsertSynced` then
    `DeleteSynced` for one key), so dropping from the front would apply
    a delete whose matching upsert was discarded — inverting the
    worker's view of that key rather than merely making it stale.
  - A source-level guard in `worker_queue_tests.rs` asserts every
    production `push_back` of a `WorkerCommand` under `src/afxdp` goes
    through `push_bounded`. Hand-seeded consumer fixtures
    (`session_glue/tests.rs`, `newflow_contention_tests.rs`) are
    excluded on purpose; they drive the consumer and routing them
    through the cap would change what they exercise.
- `drain_bounded_into` is how a worker consumes that queue (#7201).
  `apply_worker_commands` takes a **bounded prefix** of at most
  `WORKER_COMMAND_DRAIN_BUDGET` (256) commands into a worker-owned
  recycled scratch deque, dispatches those, and leaves the remainder in
  the shared queue for the next poll.
  - **It is a ring-service budget, not a fairness knob.** The worker
    does not touch its AF_XDP RX/TX rings while it dispatches commands,
    so batch size is wall-clock time the rings go unserviced. Draining
    a full 4096-command queue measured **3.85 ms** — a LOWER bound, at
    `session_map_fd = -1` where the `bpf_map_update_elem` calls fail at
    the fd check without paying the kernel-side insert. A 4096-slot RX
    ring (`ring_entries`, `server/lifecycle.rs`) fills in ~1.97 ms at
    25 Gbps with 1500 B frames. The burst arrives at RG activation, the
    moment the node has just become forwarding-authoritative — hence
    "availability defect", not "allocation nit". 256 is the slice
    `sessions.drain_deltas(256)` already uses in the same loop, and
    bounds the unserviced window to ~256 µs.
  - The slice is a contiguous FRONT prefix, so FIFO and every ordering
    group survive a split by construction. The `UpsertSynced` →
    `DeleteSynced` transitions the queue carries are the reason a
    quota-filling or back-taking budget would be wrong.
  - **The backlog signal feeds `did_work`.** `WorkerCommandResults`
    carries `commands_backlogged`, and `worker/loop_body` seeds
    `did_work` from it. This is load-bearing, not bookkeeping:
    `did_work` is otherwise set only by `poll_binding` (packet work), so
    a budget WITHOUT this wiring is a regression rather than a partial
    fix — on a promoted standby with no traffic yet, `idle_iters` passes
    `IDLE_SPIN_ITERS` and each remaining slice waits behind a 1 ms
    `poll(2)`, turning a bounded 3.85 ms stall into ~16 ms of drain. A
    source-level guard pins that seed line.
  - Replacing `core::mem::take(&mut *pending)` also ends the zero-cap
    regrow: the take moved the producers' buffer out and left the shared
    deque at capacity 0, so the producers reallocated it under the lock
    on every pass.
- `try_lock_recover` keeps WouldBlock as a skip (`None`) — only the
  Poisoned arm changes behavior.

History: #1790 added recover-without-clear at the five coordinator
ha.rs sites; #1807 extended recovery to every producer/consumer site
(worker poll peek, `apply_worker_commands`, session replication,
activation prewarm, tunnel install/drain-wait, cross-binding shaped-TX
redirect) and retrofitted the coordinator sites onto the shared
helpers. Before #1807 a single poisoned queue made the worker
permanently deaf (poison read as "no commands") while producers
silently dropped or, for the tunnel drain-wait, spun to timeout.

## Shared-session map poison policy (#2402)

The HA promotion/demotion path reads and mutates three shared-session
maps (`Mutex<FastMap<SessionKey, SyncedSessionEntry>>` — synced, NAT, and
forward-wire) plus their owner-RG indexes. A worker panic while holding
one of these mutexes (contained by the #925 supervisor) poisons it, and
the map still holds every committed insert.

The old access patterns SWALLOWED that poison and lost the data:

- `prewarm_reverse_synced_sessions_for_owner_rgs` used
  `shared_sessions.lock().map(|s| { … }).unwrap_or_default()`. On a
  poisoned lock the `.map` closure was skipped and `unwrap_or_default()`
  substituted EMPTY `(forward_entries, reverse_entries)` — so RG
  activation proceeded as if there were **no sessions to promote** and
  silently dropped every active synced session at the exact moment of
  failover (the #2402 bug).
- `demote_shared_owner_rgs`, `publish_shared_session`,
  `remove_shared_session`, the `lookup_shared_*` helpers,
  `republish_bpf_session_entries_for_owner_rgs`, and the owner-RG index
  maintenance helpers used `if let Ok(..)` / `.lock().ok()` /
  `match .lock() { Err(_) => return }`, each of which silently SKIPPED its
  work (a missed demotion, a dropped publish/remove, a spurious lookup
  miss) on poison.

`shared_ops::lock_shared_recover` replaces those `shared_ops.rs` helpers
with poison
RECOVERY — `into_inner()` to keep the committed map, `clear_poison()` to
restore the fast path, and a bump of `SHARED_SESSION_POISON_RECOVERIES`
plus a sparse journald line so operators see the underlying worker panic.
This mirrors the worker-command-queue policy above (`worker_queue.rs`,
#1807): a contained panic must never void failover — promotion/demotion
proceeds with the existing session data. The unrelated `mode`-mutex
status reads in `state_writer.rs` / `slowpath.rs` keep
`.lock().map(..).unwrap_or_default()` deliberately (a momentary
default-mode status read is harmless and not on the session path).

### The policy binds READS that gate a refusal, not just writes (#5154)

The #2402 sweep covered `shared_ops.rs`, but the coordinator's HA
session-import path (`ha/session_import.rs`) kept three swallowing reads —
`upsert_synced_session` read the stored entry with `.lock().ok()` and the
map length with `.lock().map(..).unwrap_or(0)`, and
`delete_synced_session_gen` read with `.lock().ok()`. Each of those reads
gates a REFUSAL: the #2170 install/delete generation guards and the #5674
aggregate admission bound. Their writes, however, commit through
`publish_shared_session` / `remove_shared_session`, i.e. through
`lock_shared_recover`.

So validation and mutation applied OPPOSITE poison policies. After a
contained worker panic poisoned `sessions.synced`, the reads yielded
"nothing stored, empty map", every guard fell through, and the recovering
write committed the exact operation the guard exists to refuse — a
stale-generation install regressed the stored generation, a stale delete
removed a newer live entry, and an over-ceiling import bypassed the
admission bound. A fail-OPEN on an ordering guard, reached by a path the
#925 supervisor is designed to survive.

Those three reads in `ha/session_import.rs` now use `lock_shared_recover`,
and `upsert_synced_session` takes its stored-entry and length reads under
ONE guard (they were two separate locks, so the ceiling could be evaluated
against a map that had changed between them). Each of the three is pinned
by a test that poisons the mutex and asserts the guard still refuses —
including the #5674 ceiling, which the pre-existing ceiling test could not
cover because it runs on a healthy mutex.

### The policy is now module-wide, and a tripwire holds it there (#6652/#6653/#6654)

Until #6652/#6653/#6654 this section carried a table of "known remaining
sites" and the caveat that the shared-session surface as a whole did NOT
recover uniformly. That caveat is retired: every production access now goes
through `lock_shared_recover`, and
`every_shared_session_lock_in_production_recovers_from_poison_6653`
(`ha_tests.rs`) asserts the predicate directly against the source tree.

The six sites closed, and how each applied the OPPOSITE policy:

| Site | Pattern | Consequence | Issue |
|---|---|---|---|
| `coordinator/mod.rs` `snapshot_shared_session_entries` | `.unwrap_or_default()` | a reconcile crossing a poisoned mutex replays ZERO sessions | #6652 |
| `coordinator/mod.rs` teardown x3 | `if let Ok(..)` — skips | poisoned maps survive teardown | #6653 |
| `types/mod.rs` `SharedSessionOwnerRgIndexes::clear` x4 | `if let Ok(..)` — skips | poisoned indexes survive teardown, tearing them apart from the maps they mirror | #6653 |
| `ha/export.rs` `snapshot_all_sessions_export` | `.map_err(..)` — refuses | the refusal fires by lock order, not by any property of the data | #6654 |
| `ha/tunnel_purge.rs` `purge_remapped_tunnel_sessions` | `let Ok(..) else { return 0 }` | the #1873 R-D remap purge silently does NOTHING, so a live session re-resolves a remapped `tunnel_endpoint_id` into the WRONG tunnel | (sweep) |
| `ha/state.rs` RG-activation log | `.map(len).unwrap_or(0)` | the activation line reports `shared_sessions=0` — the single most misleading number to get wrong in a failover post-mortem | (sweep) |

The last two were **not named by any of the three issues**. They were found
by sweeping the PREDICATE rather than the cited call sites, and the
tunnel-purge one is arguably the most consequential of the six.

Two structural points worth keeping:

- **The nondeterminism is the defect, not the swallowed value.** Every
  recovering path CLEARS the poison, so the poisoned window closes the
  instant any of publish / lookup / remove / prewarm runs. Whether a
  reconcile preserved state, a teardown left a surface populated, or an
  export was refused therefore depended on which thread happened to lock
  first. A guard whose firing depends on scheduling is not a guard.
- **Teardown's asymmetry was worse than a leak.** Teardown is supposed to
  leave every surface empty; poison made it leave them INCONSISTENTLY
  empty — entries present in one map, absent from its siblings and from
  the indexes meant to mirror it. No later code is written to expect that,
  so the next start resolves stale sessions AND the survivors still consume
  the #5674 aggregate admission ceiling, refusing legitimate imports.

Six sites drifted from this policy across five separate issues (#2402,
#1807/#5154, and the three above), which is what says the policy was
carried by convention and convention lost. The tripwire is deliberately
narrow — it searches the exact field paths of the three maps and four
indexes, so it cannot red on unrelated mutexes — and it is
WRAP-INSENSITIVE, collapsing whitespace before matching, because the #6652
site was spelled across four lines and a line-oriented grep would have
walked straight past the very bug it exists for.

The `state_writer.rs` / `slowpath.rs` `mode`-mutex status reads keep
`.lock().map(..).unwrap_or_default()` deliberately, as before: they are not
shared-session surfaces and a momentary default-mode status read is
harmless.

**Direction of the fix — recover the read, do not refuse the write.**
Refusing to mutate on poison is not a coherent alternative here:
`lock_shared_recover` CLEARS poison, so the poisoned window closes the
instant any other shared-session path (publish, lookup, remove, prewarm)
touches the mutex. A refuse-on-poison write would therefore fire or not
fire depending on which thread locked first — a nondeterministic refusal
of legitimate HA session sync — and would wedge session sync on an HA pair
after a panic the supervisor already contained, which is its own outage.
A safety property cannot rest on a flag another thread erases.

Recovering also makes the panic MORE observable at these sites, not less:
`lock_shared_recover` bumps `SHARED_SESSION_POISON_RECOVERIES` and emits
the journald line, whereas the old `.ok()` reads recovered nothing and
logged nothing. Note that counter is still not exported as a Prometheus
metric, unlike its #1807 twin
(`xpf_userspace_worker_command_queue_poison_recoveries_total`) — see #6641.

## WireGuard handshake-session poison policy (#6227 item 5)

`afxdp/wg/handshake_session.rs` holds seven call sites across the
`WgEngine` `reconcile_lock` (peer-table/pending-handshake serialization)
and `cookie_gen` (per-peer initiator cookie state) mutexes. All seven used
`.lock().unwrap()`, so a control-thread panic while holding either lock
(contained by the same #925-class supervision as the worker/shared-session
cases above) poisoned the mutex and PANICKED the next unrelated caller too
— tearing down the tunnel's whole handshake path over one contained panic
that had nothing to do with it.

Mirrors the established policy exactly: a file-local generic
`lock_recover<T>` (`clear_poison()` + `into_inner()`) replaces all seven
sites, bumping `WG_HANDSHAKE_LOCK_POISON_RECOVERIES` and emitting a sparse
journald line on the cold recovery path, same shape as
`worker_queue::lock_recover` (#1807) and `shared_ops::lock_shared_recover`
(#2402). Every caller here is control-thread only (never the AF_XDP poll
worker — see the module doc), so a blocking `lock()` is correct; only the
poison-recovery arm is shared with the crate-wide pattern, not the
`try_lock` shape `worker_queue.rs` uses on its hot path.

## RG-activation prewarm dedup is O(N+M) (#4069)

`prewarm_reverse_synced_sessions_for_owner_rgs` runs on RG activation —
i.e. on the failover critical path (~60ms/~130ms budget). It unions the
forward owner-RG session keys (M) with the narrower reverse-prewarm keys
(N) before restoring forward entries and synthesizing reverse companions.
That union is deduplicated by `merge_owner_rg_candidate_keys`, which seeds
a `FastSet<SessionKey>` from the forward keys once (O(M)) and then probes
each reverse key in O(1) — O(N+M) total. The prior inline dedup used
`candidate_keys.contains(&key)`, a linear scan of the growing forward Vec
once per reverse key (O(N·M)); on a busy cluster with thousands of synced
sessions that quadratic scan measurably slowed how quickly a newly-primary
node fully forwarded. The result set and its order are identical to the old
dedup — forward keys first, then not-yet-seen reverse keys in first-seen
order — only the membership data structure changed. `ha_tests.rs` pins the
order/dedup contract and a large-N (N=M=200k) linear-time guard.

## The reverse-prewarm index is add-only while live, un-filed at removal (#7209)

`reverse_prewarm_sessions` is the one owner-RG index whose buckets are not all
carried on the entry. `reverse_prewarm_owner_rg_candidates` files a peer-synced
session under two RGs: the one its own `metadata.owner_rg_id` names — carried,
so it cannot drift — and the one that owns the egress interface a reply to
`key.src_ip` would leave by, which is **read out of the FIB** and is therefore a
property of *when* the question is asked. Its three siblings (`sessions`,
`nat_sessions`, `forward_wire_sessions`) take their bucket from
`metadata.owner_rg_id` alone, on both the publish and the remove half, so on the
RG axis they are symmetric by construction. (Their *key* is not carried either —
it is derived from `entry.decision.nat` — so a replace that changes the NAT
decision can strand an alias. Different axis, not addressed here.)

**The two directions are not symmetric, and that is the whole design.**
`prewarm_reverse_synced_sessions_for_owner_rgs` re-derives each candidate's
reverse companion under live tables and re-checks `owner_rg_set.contains(..)`
before keeping anything, so an EXTRA bucket costs one discarded re-synthesis. A
MISSING bucket is never checked at all — the key does not enter the candidate
set, so the session is simply not pre-resolved when that RG activates. Over-
filing degrades a scan; under-filing drops reply traffic at a failover.

So: **add-only across a live entry's transitions, and un-file exactly once, at
removal.** A refresh can only ever name the buckets the FIB can resolve *right
now*, which is a strict subset of the truth whenever the FIB is momentarily
blind to the reply path — a RETH member down with the route not yet re-homed, or
`stop_inner` having emptied `forwarding` between a failed reconcile and its
retry. Nothing may be removed on that basis. The un-file needs no `forwarding`
at all, which is what lets it live in `remove_shared_session`, the choke point
every removal goes through — including `purge_translated_synced_hit` and the
LocalDelivery replacement after `take_synced_local`, neither of which calls the
refresh at all.

### This is the second attempt; the first one shipped

Recorded because both failure modes are instructive and the second was
introduced by the fix for the first.

1. **Originally** the removal half recomputed the PREVIOUS entry's candidate set
   against the CURRENT forwarding. Move a route between RGs while a synced
   session is live and the recomputed set names a bucket the key is not in,
   while the bucket it *is* in is never named again — the index is only READ,
   never rebuilt. Permanent strand, unbounded in the number of such sessions, on
   the path #4069 rewrote from O(N·M) to O(N+M) because its *size* measurably
   slowed a newly-primary node.
2. **PR #8479** fixed that by making every refresh un-file from EVERY bucket and
   re-file `candidates(next)`. That removes the strand and introduces its
   inverse: a refresh landing in a blind-FIB window narrows the filing, and
   nothing restores it. Two independent hostile reviews found it by different
   routes. Its own commit message had already named under-filing as "far worse
   than the leak it replaces" — the accept-side cell it shipped covered
   *neighbour* eviction and not *self* eviction, so the guard was aimed one
   step away from the harm the author had correctly identified.
3. **Now**: split the two. Add-only while live (so nothing un-re-derivable is
   ever dropped), authoritative un-file at removal (so the residue a route move
   leaves is bounded by the entry's lifetime rather than the process's).

The cells in `ha_tests.rs` pin both directions plus the paths that reach the
un-file without the delete verb: a deleted session strands nothing after a route
move; a delete does not evict a neighbouring session's key; a refresh under a
blind FIB does not drop a filing it cannot re-derive; a route move ADDS the new
bucket and the delete clears every accumulated one; and `remove_shared_session`
un-files regardless of the stored entry's origin — the leg that matters, because
the delete verb un-files too and masks the mechanism without it.

### Cost, stated rather than asserted

`HashMap::retain` is O(**capacity**), not O(len), and pruning does not shrink the
allocation's high-water capacity. Capacity is bounded by the number of distinct
owner-RG ids ever filed — single digits on a real chassis cluster.

**Two corrections to what this paragraph used to say (#9053).** It claimed the
helper "does not enforce that" and that bounding at the import boundary "is
worth doing and is not done today". **#8486 enforces it at the filing**, and
declined filings are counted (`owner_rg_filings_declined_total`,
`owner_rg_bound_8486_tests.rs`). And it claimed the walk runs "on the **control
thread**". It does not: `remove_shared_session` — the walk's caller — is invoked
from `session_delta.rs:520` and `:530`, **twice per Close delta, on WORKER
threads**. A comment asserting a threading property that is false is how the
next reader concludes a lock is uncontended and stops measuring it, which is
exactly the reader this file exists to inform.

What survives unchanged: the walk runs once per authoritative removal (never per
refresh), and allocates nothing.

## Which of the four blocking calls can leave the ServerState lock (#7209 item 2)

`sync_session` dispatches through the snapshot-wide `ServerState` mutex, and
`apply_snapshot` holds that mutex across four blocking calls. Scope item 2 of
#7209 proposes taking them off the lock with the locked-kick / unlocked-wait
split already used by #2962, #4054 and #5862. **Two of the four can be; two
cannot yet**, and the discriminator is what `Coordinator.forwarding` holds at
that instant — not the duration of the call.

Phase order inside `Coordinator::reconcile`:

| # | phase | `forwarding` there | blocking call | releasable today |
|---|---|---|---|---|
| 1 | `snapshot::preflight_map_fds` | previous table, still installed | BPF map-pin opens | **yes** |
| 2 | `teardown::tear_down` → `stop_inner(false)` | **emptied** | worker `join()` (unbounded) | no |
| 3 | still in `tear_down`, after `stop_inner` | **emptied** | mlx5 quiesce, 500 ms | no |
| 4 | `snapshot::apply_snapshot` assigns `coord.forwarding = new_forwarding` | new table installed | — | — |
| 5 | `bringup::bring_up_workers` | new table | worker-readiness barrier, **10 s** | **yes** |

The map-pin opens run BEFORE the teardown, so a reader in that window sees the
previous, coherent state. The readiness barrier runs AFTER
`apply_snapshot` has installed the new table, so a reader there sees the new
one. Neither exposes an empty table — and the barrier is the call that matters,
because it is the one that can exceed the Go side's 3 s session round-trip
budget and take the rest of a #5380 bulk batch down with it.

### Why phases 2 and 3 were blocked, and what unblocked them

Releasing the lock there exposes `forwarding = ForwardingState::default()` to a
concurrent `sync_session`, and the import's DERIVED state is computed from it:

1. `stop_inner(false)` empties the table but deliberately KEEPS the shared
   synced map (`clear_synced_state` is false for a reconcile), so an import
   landing in the window persists;
2. `synthesized_synced_reverse_entry` has exactly one early return, on
   `is_reverse` — there is no forwarding-dependent `None` arm — so the reverse
   companion is still built, from nothing, and published.

**Leg 3 no longer holds, and removing it is what unblocks these two phases.**
It used to read: *"`replay_synced_sessions` publishes `entry.decision` VERBATIM
and re-queues the entry. It never re-synthesizes, so the reconcile does not
repair it."* That was true when this section was written and is not now. The
replay REBUILDS each forward entry's companion under the live table
(`rederived_reverse_companions`, called from `replay_synced_sessions`) and
repairs **both** surfaces — the shared map, which is the authority a later
prewarm or export reads, and the replayed copy, which is what reaches the
kernel session map and the worker `SessionTable`s. Repairs are counted on
`xpf_userspace_synced_reverse_rederived_total`.

`reconcile` reaches the replay AFTER `snapshot::apply_snapshot` has assigned
`coord.forwarding = new_forwarding`, so the table read there is the new
generation's rather than the emptied one — which is the ordering that makes the
replay a repair point at all, and the same shape #8171 established for the
entries themselves.

So an import taken against a torn-down table is now repaired by the end of the
same reconcile, on every node, without needing an RG activation. Before this,
the only repair was `prewarm_reverse_synced_sessions_for_owner_rgs` at
activation, which a mid-life `apply_snapshot` on an already-ACTIVE node never
reaches — so the wrong reply-path row was permanent for any node that did not
subsequently fail over.

Legs 1 and 2 remain pinned in `ha_tests.rs`
(`stop_inner_empties_the_forwarding_table_that_a_released_lock_would_expose_7209`,
`an_import_under_an_emptied_forwarding_table_publishes_a_dead_reverse_companion_7209`),
and the repair itself by
`the_reconcile_replay_rederives_a_dead_reverse_companion_7209`, which replaced
the characterization cell that pinned the old leg 3. That cell went red the
moment the repair landed, which is what a characterization cell is for.

### Measured cost of the two candidate remedies — shape (ii) was taken

#7209 left item 1's shape open between refusing the companion when its inputs
are absent, and deferring the synthesis to the replay. Implementing each as a
mutation and running the full binary suite separated them, and **shape (ii)
landed on that evidence**:

| shape | cells red |
|---|---|
| (i) refuse the companion when the table cannot resolve it | **8** — the three above plus **six pre-existing**, including four capacity/refusal cells and `sync_session_upsert_reports_a_semantic_refusal_on_the_wire_6785` |
| (ii) re-derive the companion at replay under the live tables | **1** — only the characterization cell written to flip |

Shape (i)'s extra reds are not incidental. `synced_import_cap_for`'s 2x is
load-bearing *because* `synthesized_synced_reverse_entry` returns `Some` for
every non-reverse import — the cap counts ENTRIES and each admitted forward
occupies two. Refusing the companion changes that accounting. (Caveat on the
measurement: the mutant gates on `forwarding.egress.is_empty()`, so it also
fires for every fixture built on a default `Coordinator::new()`; the six reds
are real but their count is a property of the fixture population as much as of
the shape.) Shape (ii) is the one #8171 already established for the entries
themselves, and it is empirically the cheap one.

## Hot-path constants

- `RX_BATCH_SIZE = 64`
- `TX_BATCH_SIZE = 64`
- `MAX_RX_BATCHES_PER_POLL = 4`
- `FILL_WAKE_SAFETY_INTERVAL_NS = 500_000` (lost-wakeup safety net)
- `HEARTBEAT_GRACE_PERIOD_NS = 6 * 1_000_000_000`

These are paired with cache-footprint and CoS-quantum invariants —
const-asserts catch unintentional changes.

## CPU pinning

`worker::pin_current_thread(worker_id)` (in `neighbor.rs`) honors the
inherited systemd `CPUAffinity=` mask. Worker N pins to the N-th
*allowed* CPU in that mask, so `CPUAffinity=2 3 4 5` puts workers
0..3 on CPUs 2..5 — outside the default mask but inside the unit's.
Don't revert to absolute-index pinning; the `CPUAffinity=` test catches
it explicitly.

## Reading order

`coordinator/mod.rs` for ownership and lifecycle, then
`worker/mod.rs` for the dispatch, then the sibling `poll_stages.rs`
for the per-packet stages, then peer modules as needed.
