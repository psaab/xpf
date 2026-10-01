# ps-review-043 — Refactor / Modularity Audit — Monolith Detection with Hot-Path Preservation (HFT-Grade)

**Base commit:** `4e0c7f74cf0dbacf83051b2a9b6cf4e050dcecaa`
**Date:** 2026-07-12T02:36:34.221617+00:00
**Repo root:** `/home/ps/git/avacado-xpf` (via `git rev-parse --show-toplevel` — never hardcode, generic work dirs, no repo name in path)
**Output path:** `/tmp/ps-review-043.md` (ONLY final — intermediates were in /tmp/review-work-ps-043/ (generic review-work-<whoami>-<NNN> no repo name) + worktrees in /tmp/review-wt-ps-043-*/ (generic review-wt-<whoami>-<NNN>-<area>-b<batch> no repo name, detached at base SHA 4e0c7f74cf0d, all swept after merge))
**Batch files:** 10 (a1a a1b a1c a1d a1e a1f a1g a2 a3 a4) — all under /tmp/review-work-ps-043/
**Focus:** Rust AF_XDP dataplane hot path: per-packet forwarding orchestrator (poll_descriptor), CoS TX drain (queue_service + cos_classify + waterfill), session table (SessionTable god-struct + SessionEntry hot/cold Arc clone), policy/verdict engine (screen + frame + policy.rs) — split cold config/setup/stats/logging out WITHOUT changing one instruction of hot path, prove with disassembly diff + failover/CoS smoke gates.

## Duplicate suppression summary
- #4404 poll_descriptor/mod.rs 5759 LOC god-function — ALREADY FILED (enriched: 1368→4796 growth + 4 seams)
- #4407 Daemon god-struct — ALREADY FILED
- #4408 tx/dispatch + cos/queue_service waterfill — ALREADY FILED
- #4409 NAT allocator/source — ALREADY FILED
- #4421 Refactor backlog (policy.rs, nat64.rs, neighbor.rs, SnapshotIntegrityError, SessionTable, ForwardingState, etc) — ALREADY FILED
- #4405 compiler_validate_strict.go CLOSED, #4406 uniformgates already split (D)
- #4651 event_stream/codec.rs, #4652 tcp_segmentation.rs, #4661 format/buffers.go, #4662 daemon_run.go Run() — new issues already filed, do not re-report same
- #4663-#4670 test-only splits — test files ONLY
- Perf/HPC hot paths: per-packet orchestrator, CoS waterfill, session hot/cold, TX drain — must not be disturbed

Work-dir & worktree contract verified (repo-agnostic):
- Intermediates: /tmp/review-work-ps-043/ (10 files) — NOT under /tmp/ps-review-*.md namespace
- Worktrees: /tmp/review-wt-ps-043-<area>-b1/ — 10 worktrees, detached at base SHA, all removed after
- Final: /tmp/ps-review-043.md — ONLY file matching /tmp/ps-review-043*.md after cleanup

## File-size / shape inventory — module checklist

### Top Rust non-test prod LOC (base 4e0c7f74cf0d):
| File | LOC | Prod | Largest fn | Responsibilities |
|------|-----|------|-----------|----------------|
| poll_descriptor/mod.rs | 6294 | ~4900 | poll_binding_process_descriptor 4796 | 15+ (stages 1-11, flow-cache, session-hit, session-miss, flowless, host-local, NAT pre-routing, filter, route, screen, policy, SNAT, install, telemetry, HA, debug-log) |
| forwarding/mod.rs | 2795 | 2795 | lookup_forwarding_resolution_inner_ecmp 192 | 80 fns 5 god-fns FIB/NAT/fabric/tunnel |
| session/mod.rs | 2114 | 2114 | — | SessionTable 27 fields 7 resp |
| cos/queue_service/mod.rs | 2057 | 2057 | waterfill 432 | Waterfill + epoch + clamping + Phase-1 + Phase-2 + WRAP |
| neighbor.rs | 2036 | 2036 | neigh_monitor_thread 272 | 4 resp |
| nat/allocator.rs | 1974 | 1974 | allocate_translation_locked 114 | PortAllocatorShared hot bitmap + cold |
| frame/inspect.rs | 1960 | 1960 | parse_session_flow_from_bytes 139 | 5x EH walker dup |
| wg/engine.rs | 1805 | 1805 | try_encap/try_decap hot | WG protocol single resp |
| types/cos.rs | 1786 | 1786 | — | CoSInterfaceRuntime 28 fields |
| worker/loop_body/mod.rs | 1784 | 1784 | — | Worker loop body |
| frame/mod.rs | 1772 | 1772 | verify_built_frame_checksums 192 | 6-resp kitchen sink |
| event_stream/mod.rs | 1701 | 1701 | IO thread 700 | Transport + sequencing + clock + RT_FLOW |
| tx/dispatch/mod.rs | 1505 | 1505 | enqueue_pending_forwards 1048 | TX drain god-func |
| shared_cos_lease/lease.rs | 1460 | 1460 | legacy lease + v8 fair-share | Legacy + v8 split pending |
| nat/source.rs | 1523 | 1523 | match_source_nat_result 336 | SNAT 6 resp |

### Top Go non-test prod LOC:
| File | LOC | Smell |
|------|-----|-------|
| protocol.go | 3064 | Wire 12 domains, Rust split 7 files |
| daemon_run.go | 2492 | Run ~1690 god ordering-sensitive #4662 |
| vrrp/instance.go | 2417 | VRRP SM single coherent |
| compiler.go | 2323 | 3-phase + bandwidth helpers |
| policy_render.go | 2309 | BFD+BGP+OSPF+RIP+ISIS+policy |
| daemon_apply.go | 2265 | applyConfigLocked 1148 god 20 phases |
| metrics_descriptors.go | 2067 | 279 NewDesc 7 subsystems merge-conflict |
| tunnel.go | 2016 | GRE/WG/keepalive Axis-D/VRF 5 resp |
| dhcp.go | 1940 | DHCP lifecycle |
| sync_conn.go | 1858 | gen-guard+fabric+bulk+journal+config 8 resp |

---

## Detailed findings (per-area deep dive)


---
### Batch header.md — 20211 chars

# ps-review-043 — Refactor / Modularity Audit — Monolith Detection with Hot-Path Preservation (HFT-Grade)

**Base commit:** `4e0c7f74cf0dbacf83051b2a9b6cf4e050dcecaa`
**Date:** 2026-07-12T02:33:47.419631+00:00
**Repo root:** `/home/ps/git/avacado-xpf` (via `git rev-parse --show-toplevel` — never hardcode, generic work dirs, no repo name in path)
**Output path:** `/tmp/ps-review-043.md` (ONLY final — intermediates were in /tmp/review-work-ps-043/ (generic review-work-<whoami>-<NNN> no repo name) + worktrees in /tmp/review-wt-ps-043-*/ (generic review-wt-<whoami>-<NNN>-<area>-b<batch> no repo name, detached at base SHA 4e0c7f74cf0d, all swept after merge))
**Batch files:** 10 (a1a a1b a1c a1d a1e a1f a1g a2 a3 a4) — all under /tmp/review-work-ps-043/ (generic work dirs, no repo name), each subagent used detached worktree /tmp/review-wt-ps-043-<area>-b1/ at base SHA
**Focus:** Rust AF_XDP dataplane hot path: per-packet forwarding orchestrator (poll_descriptor), CoS TX drain (queue_service + cos_classify + waterfill), session table (SessionTable god-struct + SessionEntry hot/cold Arc clone), policy/verdict engine (screen + frame + policy.rs) — split cold config/setup/stats/logging out of per-packet path WITHOUT changing one instruction of hot path, prove with disassembly diff + failover/CoS smoke gates.

## Duplicate suppression summary

Prior refactor issues (read for dedup via `gh issue list` + /tmp prior reviews):

- #4404 refactor: poll_descriptor/mod.rs (6,294 LOC at 4e0c7f74, was 5,759) — decompose god-function 1,368 LOC 15+ resp — ALREADY FILED (this audit: 1368→4796 LOC growth measurement + 4 seams: flowless/host-local/NAT-pre-routing/debug-log cold outline, co-occurrence mutable-locals coupling, recycle-site audit)
- #4407 refactor: Daemon god-struct 150+ fields — ALREADY FILED (subsumes #4617 Run() ~1690 LOC ordering-sensitive)
- #4408 refactor: Rust hot-path god-functions — tx/dispatch enqueue_pending_forwards (1,131 LOC) + cos/queue_service waterfill (438 LOC) — ALREADY FILED (this audit: Phase 8 + direct-TX + fabric breakdown after inc1, f64 fraction calc extraction for unit testing)
- #4409 refactor: Rust NAT — nat/allocator.rs PortAllocator god-struct (926 LOC) + nat/source.rs (1,190) + nat/tests.rs — ALREADY FILED (this audit: cache-line + bench-gated plan, occupancy/live/deterministic 3-file split)
- #4421 Refactor/modularity backlog — policy.rs, nat64.rs, neighbor.rs, SnapshotIntegrityError, SessionTable, ForwardingState, flowexport, firewall-filter, rules.go — ALREADY FILED (this audit: supplements with hot/cold inventory, AppCatalog zero-coupling, EH walker SSOT, policy.rs 3658 LOC counter coalescer)
- #4405 refactor: compiler_validate_strict.go (6,997 LOC) — CLOSED (12 per-domain files, pure code-motion #4144 discipline)
- #4406 compiler_uniformgates + compiler_validate_strict_filter — already per-domain split results (D — do not re-split)
- #4651 event_stream/codec.rs (1,165 LOC) — new issue, split wire-format monolith (HA-sync + RT_FLOW + encode/decode) — ALREADY FILED
- #4652 frame/tcp_segmentation.rs (933 LOC) — new issue, extract segment fn by phase (HOT-PATH /triple-review) — ALREADY FILED
- #4661 format/buffers.go (773 LOC) — new issue, shared row model CLI/gRPC/REST buffer-status parity — ALREADY FILED
- #4662 daemon_run.go Run() ~1,690 LOC ordering-sensitive lifecycle — new issue, /triple-review — ALREADY FILED
- #4663-#4670 test-only splits — test files ONLY, production NOT split: codec_tests, event_stream/tests, cos/queue_service/tests, cos/queue_ops tests, umem/tests, reject_reply tests, manager_test.go, dispatch_tests, frame/wg tests
- Perf/HPC findings naming hot paths: per-packet forwarding orchestrator, CoS waterfill, session table hot/cold, TX drain (from #959, #1035, #1342, #1432 prior splits) — these constrain any split

**Work-dir & worktree contract verified (repo-agnostic):**
- Intermediates: /tmp/review-work-ps-043/ (10 files) — NOT under /tmp/ps-review-*.md namespace
- Worktrees: /tmp/review-wt-ps-043-<area>-b1/ — 10 worktrees, one per batch, all detached at base SHA 4e0c7f74cf0d, all removed after agent completion (no active worktrees remain after cleanup)
- Final: /tmp/ps-review-043.md — ONLY file matching /tmp/ps-review-043*.md after cleanup (this file)
- No hardcoded repo path in findings (repo root via git rev-parse --show-toplevel); generic review-work- / review-wt- prefixes (no xpf-)

## File-size / shape inventory — the module checklist (aggregated from all 10 subagents)

Ranked by size × responsibility count × hot-path proximity, hot=3×, warm=2×, cold=1×.

### Aggregated Top Rust non-test prod LOC (base at 4e0c7f74cf0d):

| File | LOC | Prod | Largest fn | Responsibilities | Score |
|------|-----|------|-----------|----------------|-------|
| `poll_descriptor/mod.rs` | 6294 | ~4900 | poll_binding_process_descriptor 4796 | 15+ (stages 1-11, flow-cache, session-hit, session-miss, flowless, host-local, NAT pre-routing, filter, route, screen, policy, SNAT, install, telemetry, HA, debug-log) | CRITICAL — GOD-FUNCTION |
| `forwarding/mod.rs` | 2795 | 2795 | lookup_forwarding_resolution_inner_ecmp 192 | 80 free fns, 5 god-fns (FIB/NAT/fabric/tunnel/MSS/PBR/local), fused | ~3000 (B) |
| `session/mod.rs` | 2114 | 2114 | — | SessionTable 27 fields (7 resp: session store + HA sync + per-IP limits + wheel timer + forwarding metadata + telemetry + GC + limit + wheel) | >2000 (B god-struct) |
| `cos/queue_service/mod.rs` | 2057 | 2057 | select_exact_cos_guarantee_queue_waterfill 432 | Waterfill + epoch refill + clamping + Phase-1 ascend + Phase-2 descend + WRAP | >2000 (B) |
| `neighbor.rs` | 2036 | 2036 | neigh_monitor_thread 272 | 4 resp (probe craft, netlink mgmt, monitor thread, warmer) | ~2000 (B) |
| `nat/allocator.rs` | 1974 | 1974 | allocate_translation_locked 114 | PortAllocatorShared: hot bitmap + cold persistent/GC/stats, 5 structs + PersistentLease + DeterministicV4 + GC + recycle | ~1500 (C perf-positive) |
| `frame/inspect.rs` | 1960 | 1960 | parse_session_flow_from_bytes 139 | L2 parse, L3 parse, VLAN, IP options, 5× IPv6 EH walker duplication | ~2000 (A perf-positive) |
| `wg/engine.rs` | 1805 | 1805 | try_encap/try_decap on hot path | WG protocol — single resp, under threshold | (D) cohesive |
| `types/cos.rs` | 1786 | 1786 | — | CoSInterfaceRuntime 28 fields (5 lifecycles), FlowFairState boxed | ~2000 (B) |
| `worker/loop_body/mod.rs` | 1784 | 1784 | — | Worker loop body | Under threshold |
| `frame/mod.rs` | 1772 | 1772 | verify_built_frame_checksums 192 debug-only | 6-resp kitchen sink: VLAN shift, NAT v4/v6, port rewrite, NAT64, inject, debug-verify | ~2000 (A) |
| `event_stream/mod.rs` | 1701 | 1701 | IO thread 700 | Transport + sequencing + clock + RT_FLOW | ~1700 (A if, D defer) |
| `event_stream/codec.rs` | 1165 | 1165 | — | Event codec: HA-sync + RT_FLOW + encode/decode wire-format monolith | ~1200 (A) |
| `frame/tcp_segmentation.rs` | 995 | 995 | segment fn | Admission + cold build loop — #4652 already filed | (B) requires guardrails |
| `frame/checksum.rs` | 984 | 984 | — | Frame checksum helpers | Under |

### Top Go non-test non-gen prod LOC:

| File | LOC | #func | Smell | Action |
|------|-----|-------|-------|--------|
| `dataplane/userspace/protocol.go` | 3064 | 78 types | Wire 12 domains — Rust already split 7 files (binding.rs 1185, control.rs 1088, cos.rs 494, nat.rs 400, security.rs 592, snapshot.rs 829, resolution.rs 105) | (A) 12 files by domain |
| `daemon/daemon_run.go` | 2492 | 11 | Run ~1690 LOC ordering-sensitive lifecycle — already #4662 | (B) ordering-sensitive, already filed |
| `vrrp/instance.go` | 2417 | 64 | VRRP SM: state + RX + TX + GARP + advert-interval + preempt-hold + VIP | (D) single coherent RFC5798 SM |
| `config/compiler.go` | 2323 | 8 | 3-phase fusion + 14 bandwidth helpers + duplicated lenient tables | (A) extract compile opts + per-domain tables |
| `frr/policy_render.go` | 2309 | 22 | BFD+BGP+OSPF+RIP+ISIS+policy + generateProtocols 600 LOC 6 families | (A) per-family rendering |
| `daemon/daemon_apply.go` | 2265 | 4 | applyConfigLocked 1148 LOC god 20 phases, C1/C2/C3 cancel boundaries #2926 | (B) phase slice |
| `api/metrics_descriptors.go` | 2067 | 1 | 279 NewDesc 7 subsystems #1 merge-conflict file | (A) helper methods |
| `routing/tunnel.go` | 2016 | 36 | GRE/WG/keepalive Axis-D/VRF/addr 5 resp, keepaliveRunner never takes t.mu AGY r5 | (B) ordering-sensitive Axis-D |
| `dhcp/dhcp.go` | 1940 | — | DHCP lifecycle | Under |
| `api/metrics_userspace.go` | 1865 | — | Userspace metrics emitter | Companion to descriptors |
| `cluster/sync_conn.go` | 1858 | 55 | gen-guard + fabric + bulk + journal + config 8 resp, genGuardMapCap 200k #2198 F1 | (B) gen-guard ordering |
| `config/compiler_services.go` | 1841 | 27 | RPM 5 validators + DHCP local/DDNS/expired/relay + IP-monitoring + flow + sampling + port-mirroring | (A) per-service |
| `config/compiler_uniformgates.go` | 1832 | 1 | D-negative already #4406 orchestrator preserving invariants #6/#7 | (D) do not re-split |
| `compiler_validate_strict_filter.go` | 1811 | 30 | D-negative already per-domain split result #4405 | (D) |
| `dataplane/compiler.go` | 1808 | — | Compiler dispatch | (D) |
| `dataplane/userspace/maps_sync.go` | 1763 | — | BPF map sync single coherent domain | (D) |
| `config/compiler_validate_warn.go` | 1682 | 6 | Was 3330, now 1682 after partial split — monolith ValidateConfig 1566 LOC single func 22 families | (A) per-domain |

---

## File-by-file inspection log (aggregated)

### From a1a (poll_descriptor + poll_stages) — worktree `/tmp/review-wt-ps-043-a1a-b1/`:
Poll descriptor dir: mod.rs 6294 LOC — L683-L5478 poll_binding_process_descriptor 4796 LOC god-fn, #4404 already filed (was 5759→ now 6294, fn 1368→4796). New angles: 38 recycle pushes vs 34, 17 debug cfg gates, 24 mutable-locals coupling, flowless vs flow-backed Junos-order divergence, cfg(debug-log) icache pollution, NAT pre-routing 166-LOC pure seam (tri-state NAT64/DNAT/NPTv6 + counter). poll_stages.rs 975 LOC — 6 stage fns extracted (link/gre/parse/flow+learn/fabric/screen/ipsec) textbook Phase 1 #946, largest stage_screen_check now handles flowless branch inside (#3902). reject_reply.rs 2174 LOC — cold #[cold] #[inline(never)] already .text.unlikely, shared enqueue_reject_reply 199 LOC, H11/H12 ordering must stay linear. filter.rs 1201 LOC — cold extraction per #1543, OnlyTerminalNonAccept count-policy.

### From a1b (TX dispatch + cos_classify + tcp_segmentation + rings):
TX drain orchestrator 1505 LOC — fabric scatter (prebuilt 336-425, desc no-binding 456-483, build-fail via slow_path), direct-TX 178+139=317 LOC block, PTB-ingress 58 LOC with classify_generated_reply, inplace/CP/direct fallbacks, Phase 8 ~650 LOC still inline after #1443 inc1. cos_classify.rs 1335 LOC 7 fused responsibilities (TX-selection cached+runtime, BA reclassify, LP rewrite, generated-reply classify, local/prepared enqueue, demote+queue-idx). tcp_segmentation.rs 995/309 LOC single #[cold] fn — admission fast-exits (proto/tunnel/mtu/flags) buried under cold build loop per #4652. rings.rs 415 LOC 4 XSK disciplines (reap, fill, wake RX poll(POLLIN), wake TX sendto+VDSO bracketing #825) + debug poison. drain/mod.rs 594 LOC orchestrator 34 LOC textbook + phase_backup/shaped/trivial all target shape. transmit/ 6-phase split (#1354) textbook clean decomposition stage/rewrite/verify/write/finalise.

### From a1c (CoS queue_service + queue_ops + shared_cos_lease):
queue_service/mod.rs 2057 LOC — waterfill 432 LOC god-func (925-1357) 7 resp (epoch refill + f64 fraction math + clamp + bitset gating + Phase-1 ascending + Phase-2 descending + WRAP). CoSInterfaceRuntime 28 fields 5 lifecycles (config copy, hot token buckets, waterfill epoch 7 fields, RR cursors, timer-wheel) plus 3 dead priority_low_* fields wire-surface-only per #4220. FlowFairState 352KB boxed correctly via Box::new_uninit avoiding stack temp, mask-not-modulo SFQ. tx_completion.rs 1080 LOC 3 resp timer-wheel + TX-completion apply + backlog publish. lease.rs 1460 LOC legacy lease + v8 fair-share + acquire_v8 + snapshot + equal-flow cap, 6 per-worker atomic arrays, compare_exchange_weak seqlock. backlog.rs 210 + vtime.rs 238 + epoch.rs 565 + rotate_epoch_v8.rs 446 exemplary cohesive splits per #2158. queue_ops/ prod 1893 test 6488 3.4x test/prod MQFQ CoV gate.

### From a1d (Session table):
mod.rs 2114 LOC ×7 resp×hot3 top god-struct 27 fields (was 25 at prior prune, now 27 with next_session_id+session_id_worker_hi #4915), child modules via super::* access all 25 private fields — code-motion (#2005) not decomposition. SessionTable field groups: 7 groups (SessionStore, SecondaryIndexes, SessionLimits, TimeoutConfig, SessionTelemetry, DeltaRing, WheelState). SessionEntry 17-field hot/cold fusion + metadata.clone() does Arc<PolicyRuleCounter> LOCK XADD per packet (~10ns @7.5M pps/worker) — propose inline SessionHot/SessionCold split (no Box, same slab, field-offset only) + borrow-return SessionLookupRef eliminating Arc clone. session_glue 1277 LOC mixing forwarding res (#1873 tunnel reuse guard, #2734 ECMP hash), HA predicates (owner_rg_is_locally_active), BPF mirror (#1789 error counting), shared sync, worker cmd dispatch — 5 submodules.

### From a1e (Forwarding / ForwardingState / Neighbor):
forwarding/mod.rs 2795 LOC 80 fns (was 68), 5 god-fns ≥192 LOC: lookup_forwarding_resolution_inner_ecmp 192 LOC L1449, v4 inner 192 L2023, v6 inner 184 L2239, cluster_peer_return_fast_path 105 L713, ingress_route_table_override 122 L1641. types/forwarding.rs 1099 LOC 66-field god-struct (was 55 at #4421, growth via #3769/#3182/#3527/#3618) no #[repr], Clone+Default heavy, hot FIB (local_v4/v6, routes, connected, neighbors, ifindex_to_zone_id, egress, tunnel_endpoints, gre_decap_index, fabrics, zone_host_inbound) interleaved with cold (ifindex_to_name String heap, filter_state, cos, tcp_mss_*, cold_path_sample_mask, screen_profiles, mirror_configs). forwarding_build/ 8 files already decomposed #1342: ClassifierTables borrow-only, each file <850 LOC focused. neighbor.rs 2036 (1901→2036) 4 fused resp. neighbor_resolver.rs 1512, neighbor_dispatch.rs 1399 genuine splits but super::* coupling. worker/mod.rs 1631 already #959 decomposed into 11 sub-mods, loop_body 1784 intentionally inline per #1776. Immediate CoS FIF: forwarding.cos.interfaces hot lookup + cos_shared_queue_leases ArcSwap cross-binding redirect collapses 6-worker parallelism — preserve FIF read without extra cache miss.

### From a1f (Screen / frame / policy):
screen/ 4890 total (stateless 262, rate 609, syn_rate 504, syncookie 600, scan 621 prod/1213 total, extract 400, packet 174, mod 1540) — 7-way Wave-5 split already done, ScreenState 22 fields 7 resp, stateless already in stateless.rs but SYN-flood 180 LOC inline with 8 bug-fix layers #3315/#3607/#4112/#4155. frame/ 8290 prod: inspect 1960 (5× EH walker dup: frame_l4_offset, packet_rel_l4_offset, packet_rel_l4_offset_and_protocol, ipv6_is_non_first_fragment, ipv6_is_any_fragment, is_non_first_fragment identical 0|43|60|... + 51 AH + 44 frag + 59 NoNext + MAX_IPV6_EXT_HEADERS=8 bound, #4517 fixed values across 5 sites miss=IDS evasion), mod 1772 6-resp kitchen sink (VLAN descriptor-shift 384 LOC classify_in_place_l2_rewrite + descriptor_view_in_same_umem_frame 9 LOC avoids 1500B memmove via TX descriptor shift, NAT v4/v6 462 LOC apply_nat_ipv4/v6 + apply_nat_port_rewrite 64 LOC #[inline(always)] family constant-fold #1853, NAT64 port 114 LOC, inject 135 LOC cold, DSCP 39 LOC, debug verify 180 LOC). wg.rs 1561 total 604 prod/957 test byte-identity, runtime.rs 503 plumbing. policy.rs 3658 - 8 resp, largest parse_policy_state_with_counters 523 LOC — AppCatalog zero-import candidate FxHashMap<u8, AppProtoEntries> only crate::AppCatalogEntry wire schema.

### From a1g (WG, event_stream, cold_path_hist, coordinator, types, protocol, server):
wg/engine.rs 1805 single-responsibility WG protocol MaybeUninit stack scratch Arc-clone+release-lock branchless pad_to_16 — cohesive (D). wg/cookie.rs 857 cohesive DoS checker. event_stream/mod.rs 1701 3 resp transport I/O thread + sequencing + clock conversion + replay/drain backpressure, largest handle_drain_request 198 LOC — borderline A if, D defer also defensible. cold_path_hist 954 cohesive histogram with inline bucket selector #1635 48-bucket log-linear. coordinator/wg_control.rs 1579 6 domains fused behind 320-LOC loop: socket lifecycle, poll wait, TUN fatal accounting, ECN cmsg ancillary receive (RFC6040 §4.2 88 LOC setsockopt + 39 LOC cmsg iterate), handshake attempt SM 133 LOC drive, inbound dispatch 215 LOC type-byte — P1 mechanical. types/cos.rs 1786 type bag Issue 68.1. protocol/binding + control (Go↔Rust contract leaves). server/helpers.rs 1304 dumping ground header "Pure relocation pending further split" refresh_status 311 LOC 20 fns 5 domains (status refresh 323 LOC, session-sync builders, binding-plan hashing canonical JSON, binding selection/queue planning, platform linux-ifname/sysfs/file-IO). A3 mechanical P0.

### From a2 (NAT):
allocator.rs 1974 LOC post-#2852 Phase 1 already lock-free bitmap (AddressOccupancy Vec<AtomicU64> + AtomicU32 cursor + Mutex<VecDeque> recycle) but still fuses 5 structs + deterministic + GC + #5269 address_only_owners. source.rs 1523 god-function match_source_nat_result_for_tuple ~400 LOC 6 return points mixing config-parse (cold expand_pool_address, parse_source_nat_rules_with_previous allocator reuse keyed on exact Vec equality) with per-new-flow driver + NAT64 shims. nat64.rs 3102 LOC monolith at this SHA (growth from 2047 in #4421 which is NOT done) — prefix, state, frag sharded assoc (16 shards cap 64 TTL 2s), ICMP v4↔v6 mapping, checksum incremental, forward decision. nptv6 431, lib.rs 1541 XDP shim no NAT classification (DNAT maps only). compiler_nat.go now 1317 (was 2529, partially split at this SHA) — 6-file split in pkg/config (764+400+336+410+131+159=2200 net). CoS TX drain focus.

### From a3 (Go config compilers):
compiler_validate_warn.go was 3330 (1682 at this SHA after partial split — still monolith ValidateConfig 1566 LOC single func 22 families interleaved), compiler.go 2323 (now P1-P7 orchestrator after #4406 but still carries ~1600 LOC compileOpts + duplicated lenient flag tables), compiler_system.go 2115 (28 funcs 8+ subsystems: login/RBAC, DDNS catalog, dataplane tunables + shared-UMEM JSON, syslog host/file/user, SNMP community/trap/v3, chassis/RG/IP-monitor, schedulers, archival+CVE), compiler_services.go 1841 (27 funcs 8 subsystems: RPM 5 validators + DHCP local/DDNS/expired/relay + IP-monitoring/overlay + flow-monitoring + sampling per-collector v9/ipfix/template/source + port-mirroring + event-options + bridge-domains), compiler_nat.go 1317 (now smaller than 2529 but still triply fused: helpers + validators + compilation 37 funcs, compileNATSource ~500, validateNPTv6Strict ~200), compiler_interfaces.go 1290 (14 funcs 5 resp: VRRP group parser ~230 LOC + track/auth validators + wireguard + MSS), compiler_uniformgates.go 1832 (D negative already #4406 orchestrator), compiler_validate_strict_filter.go 1811 (D negative already per-domain split result of #4405), types_system.go 1589 (64 types D-negative tracking-issue low priority).

### From a4 (Go dataplane + daemon + cluster + routing + metrics):
protocol.go 3064 (78 types 39 ConfigSnapshot sub-types, ProcessStatus 80+ fields mixing 7 subsystems) — Rust template split 7 files (binding.rs 1185 etc.). daemon_run.go 2492 (11/0, Run ~1690 LOC god ordering-sensitive #4662 already filed), daemon_apply.go 2265 (applyConfigLocked 1148 LOC god 20 phases C1/C2/C3 cancel boundaries #2926), metrics_descriptors.go 2067 291 NewDesc 7 subsystems #1 merge-conflict file, tunnel.go 2016 36 funcs (GRE/WG/keepalive Axis-D/VRF/addr 5 resp, keepaliveRunner never takes t.mu AGY r5), sync_conn.go 1858 (gen-guard+fabric+bulk+journal+config 8 resp, genGuardMapCap 200k #2198 F1), vrrp/instance.go 2417 single coherent RFC5798 SM (state+RX+TX+GARP+VIP - D-negative), maps_sync.go 1763 single coherent domain (ctrl + binding ready gate) D-negative.

---

## Findings — grouped by confidence and area (exact field labels per audit spec)



---
### Batch ps-a1a-b1.md — 72401 chars

# A1a — per-packet orchestrator (poll_descriptor + poll_stages) — Refactor / Modularity Audit

**Base commit:** `4e0c7f74cf0dbacf83051b2a9b6cf4e050dcecaa` (Merge PR #5605)
**Worktree:** `/tmp/review-wt-ps-043-a1a-b1` (detached HEAD at base SHA)
**Date:** 2026-07-11T00:00:00Z
**Batch:** A1a — Rust AF_XDP per-packet forwarding orchestrator
**Reviewer:** ps (modularity audit agent, NNN=043, module A1a-B1)
**Output:** `/tmp/review-work-ps-043/ps-a1a-b1.md` (intermediate — merged into `/tmp/ps-review-043.md` by final aggregator)

**Focus:** "the per-packet forwarding orchestrator, the CoS TX drain, the session table, and the policy/verdict engine — split cold config/setup/stats/logging out of the per-packet path WITHOUT changing one instruction of the hot path, and prove it with a disassembly diff and the failover / CoS smoke gates. HFT stance: Latency sacred."

---

## Batch file list (9 files, all reads via worktree path `/tmp/review-wt-ps-043-a1a-b1/...`)

| # | File (worktree-relative) | Exists |
|---|---------------------------|--------|
| 1 | `userspace-dp/src/afxdp/poll_descriptor/mod.rs` | YES 6294 LOC |
| 2 | `userspace-dp/src/afxdp/poll_descriptor/reject_reply.rs` | YES 446 LOC |
| 3 | `userspace-dp/src/afxdp/poll_descriptor/filter.rs` | YES 1201 LOC |
| 4 | `userspace-dp/src/afxdp/poll_stages.rs` | YES 975 LOC |
| 5 | `userspace-dp/src/afxdp/poll_descriptor/flow_cache_hit.rs` | YES 533 LOC (actual 533 vs 521 spec — extra comment/code delta) |
| 6 | `userspace-dp/src/afxdp/poll_descriptor/cookie_reply.rs` | YES 130 LOC (vs 509 spec — bulk of prod was moved to `cookie_reply_tests.rs` at 395 LOC; combined dir = 525) |
| 7 | `userspace-dp/src/afxdp/poll_descriptor/rx_telemetry.rs` | YES 220 LOC |
| 8 | `userspace-dp/src/afxdp/poll_descriptor/nat_exception.rs` | YES 125 LOC |
| 9 | `userspace-dp/src/afxdp/poll_descriptor/debug_log_throttle.rs` | YES 99 LOC |

Dir extras (not in spec but relevant): `cookie_reply_tests.rs` 395 LOC, `reject_reply_tests.rs` 2264 LOC.

All reads performed via `/tmp/review-wt-ps-043-a1a-b1/...` per mandatory isolation.
`git rev-parse --show-toplevel` inside worktree: `/tmp/review-wt-ps-043-a1a-b1`.

---

## File-size / shape inventory (ranked by size x responsibility-count x hot-path-proximity)

Scoring: `score = LOC * resp_count * hot_factor` where `hot_factor`: 3=per-packet, 2=per-batch, 1=cold/exception.
Threshold: per `docs/engineering-style.md`, file crosses ~2000 LOC → split; next change to a file already approaching threshold should split first.

### Ranked inventory

| Rank | File | LOC | Prod LOC est | Largest fn | Resp count | Hot | Score | Threshold |
|------|------|-----|-------------|------------|------------|-----|-------|-----------|
| 1 | `poll_descriptor/mod.rs` | 6294 | ~4152 | `poll_binding_process_descriptor` 4796 LOC (L683..L5478) | 15+ (see breakdown) | H3 | 6294*15*3=283,230 | CRITICAL — 3.14x threshold |
| 2 | `poll_stages.rs` | 975 | ~587 | `stage_screen_check` ~304 LOC | 7 stage fns + 1 helper | H3 (on miss, per-packet up to stages 5-11) | 975*7*3=20,475 | Under threshold but largest in batch after mod.rs |
| 3 | `poll_descriptor/filter.rs` | 1201 | ~917 | `host_inbound_gated_lo0_action` / `filter_terminal` | 6 (host-inbound, lo0, junos-host, input-filter, DSCP-sensitive, cached-log) | H2 (session-hit re-eval + miss path) | 1201*6*2=14,412 | Under but noted |
| 4 | `poll_descriptor/flow_cache_hit.rs` | 533 | ~367 | `stage_flow_cache_hit` 457 LOC | 1 (established-flow fast path, 90%+ packets) | H3 (hottest path) | 533*1*3=1,599 | Well-extracted, OK |
| 5 | `poll_descriptor/reject_reply.rs` | 446 | ~224 | `enqueue_reject_reply` 199 LOC | 2 (policy-reject + filter-reject reply synth, shared core) | C1 (exception: deny/reject only) | 446*2*1=892 | Well-extracted, OK |
| 6 | `poll_descriptor/cookie_reply.rs` | 130 (+395 tests) | ~86 | `enqueue_syn_cookie_reply` | 2 (SYN-cookie budget + SYN-ACK/ACK-RST enqueue) | C1 (screen SynCookieChallenge only) | 130*2*1=260 | Well-extracted, OK |
| 7 | `poll_descriptor/rx_telemetry.rs` | 220 | ~155 | `record_rx_descriptor_telemetry` | 2 (prefetch + counters + debug probes) | H3 (first fn each packet, but #[inline] so IR costs 0) | 220*2*3=1,320 | Well-extracted, OK |
| 8 | `poll_descriptor/nat_exception.rs` | 125 | ~82 | `source_nat_decision_for_flow` | 2 (SNAT decision + failure record) | C1 (session-miss only, #[cold]) | 125*2*1=250 | Well-extracted, OK |
| 9 | `poll_descriptor/debug_log_throttle.rs` | 99 | ~49 | pure predicates | 1 (numeric cap throttle) | C1 (cfg debug-log) | 99*1*1=99 | Well-extracted, OK |

Additional: `reject_reply_tests.rs` 2264 LOC (14 tests), `cookie_reply_tests.rs` 395 LOC (5 tests), `poll_stages_tests.rs` 2636 LOC.

### `mod.rs` god-function responsibility breakdown (15+ fused responsibilities in one 4796 LOC fn)

`poll_binding_process_descriptor` at `/tmp/review-wt-ps-043-a1a-b1/userspace-dp/src/afxdp/poll_descriptor/mod.rs:683` — 4796 LOC, 15+ responsibilities:

1. **RX ring receive loop** — `binding.xsk.rx.receive(available)` + `while let Some(desc)` (L683-700)
2. **RX telemetry + prefetch** — calls `record_rx_descriptor_telemetry` (extracted, Stage 1)
3. **Metadata parse** — `try_parse_metadata(area, desc)` (Stage 2)
4. **Metadata classify** — `classify_metadata(meta, validation)` (Stage 3)
5. **Raw frame slice** — unsafe UMEM slice (Stage 4)
6. **Link-layer classify** — `stage_link_layer_classify` — ARP recycle / NDP learn+fallthrough (Stage 5, poll_stages)
7. **Native GRE decap** — `stage_native_gre_decap` returns `(meta, owned_packet_frame)` (Stage 6)
8. **Flow parse + neighbor learn** — `stage_parse_flow_and_learn` (Stage 7+8, includes anti-poison #2790, VLAN logical-ifindex #2370)
9. **Fabric-ingress classify** — `stage_classify_fabric_ingress` mutates `meta_flags` (Stage 9)
10. **Screen / IDS** — `stage_screen_check` + SYN-cookie challenge reply (Stage 10)
11. **IPsec passthrough + IKE host-inbound gate** — `stage_ipsec_passthrough_check` (Stage 11, #4323)
12. **Flow-cache fast path** — `stage_flow_cache_hit` → `FlowCacheOutcome::Consumed/FallThrough` (Stage 12, #1327, 90%+ packets branch)
13. **NAT pre-routing** — `nat64_match` + `pre_routing_dnat` (`static_nat.match_dnat_scoped`) + `nptv6_inbound` + `effective_resolution_target` + tri-state `MatchUnavailable` fail-closed (session-miss L~1396-1600+)
14. **Input filter** — `evaluate_non_pbr_input_filter` with PBR `routing-instance` reject/discard path + filter-log emit + reject-reply-before-log (L~1600-1900)
15. **Route resolution + forwarding table + fabric redirect + neighbor** — `forwarding_table_entry`, `connected_route_scoping`, `forwarding_resolution`, `FlowBaseResolution`, TTL check → local time-exceeded, policy eval, NAT (SNAT/static-SNAT/NAT64), session-hit arm, session-miss arm, forward-candidate building, PendingForwardRequest construction, mirror admission, in-place rewrite fast path, flow-cache install
16. **Flowless path** — `flowless_local_delivery_verdict` (L399), `flowless_base_resolution` (L505), `flowless_l3_addrs` path, NAT64 fragment association consult/install, PBR flowless gate, session-limit drops, reverse-NAT, embedded-ICMP, source-port checks (#3064 flowless-transit enforcement)
17. **Session-hit arm** — TTL before egress side-effects (#3779), cached input/output filter-log, filter-counters, policy hit-counter replay, three-color policer, BA reclassify, self-target in-place rewrite, cross-binding fallback, `touch_if_stale`, `account_packet`
18. **Session-miss arm** — `policy_packet_icmp`, `new_flow_session_limit_drop`, `strict_syn_check_drops_new_flow`, `evaluate_policy_result_with_icmp`, DNAT/SNAT resolution, session install (`install_helper_local_session_on_miss`), forward request build, mirror, in-place fast path, flow-cache install with `flow_cache_install_failed` gate, `source_nat_decision_for_flow` + `record_source_nat_failure`
19. **Host-local (LocalDelivery) arm** — `junos_host_policy_eval` (L168), `junos_host_local_policy` (L284), `emit_junos_host_deny` (L221), `emit_host_inbound_deny` (L265), `host_inbound_gated_lo0_action`, `filter_terminal`, Junos order: `host-inbound → lo0 → junos-host → filter → resolver`
20. **Resolver enqueue** — `try_enqueue_resolver` (L574): throttle window + per-if bounds map, VLAN parent-ifindex resolution (#3026)
21. **Exception / reject / reply synthesis** — `TRANSLATED_MISSING_NEIGHBOR_BOUND` gate, `deny_reply_and_emit`, `enqueue_deny_reply`, `enqueue_filter_reject_reply`, time-exceeded local request, ICMP reject reversal, SYN-cookie challenge re-validation
22. **Telemetry + debug-log** — `telemetry.counters.*` (touched, rx, metadata, validated, screen, policy, flow-cache, NAT, forwarding disposition), `telemetry.dbg.*` (cfg debug-log), `session_miss_debug_log_allowed` / `policy_deny_debug_log_allowed` throttle, `cfg(feature="debug-log") eprintln!` DBG sites (17 cfg sites, WAN_RETURN_HIT, SESS_MISS, RST_DETECT, OVERSIZED_RX, RX_ETH, RX_HEX)

**Mutable-locals coupling (decomposition difficulty):** The god-function has 24 `let mut` bindings in region L683-4000 alone (list in raw inventory file). Key coupled mutable state: `binding` (xsk.rx, scratch_recycle, scratch_forwards, scratch_rst_teardowns, flow, tx_pipeline, tx_counters, mirror_sample_counter, live, slot), `telemetry.counters`, `telemetry.dbg`, `owned_packet_frame`, `recycle_now` (single-recycle flag), `session_ingress_zone`, `flow_cache_*`, `apply_nat_on_fabric`, `flow_cache_install_failed`, `pre_routing_dnat_counter`, `debug`, `flow`. See `docs/pr/1327-poll-descriptor-stages/plan.md` for the architectural verdict that stages 12+ extraction is blocked by mutable-locals coupling — this is the core cost of further split.

**Single-recycle invariant:** 38 `scratch_recycle.push(desc.addr)` sites + 2 `StageOutcome::RecycleAndContinue` arms that push + continue. Every early exit must push `desc.addr` exactly once. Forward path takes `owned_packet_frame.take()` transferring UMEM ownership, so recycle MUST NOT fire (recycle_now=false). Verified: #4404 review calls out 34 pushes; current count is 38 (4 new sites since #4404 from flowless, TTL, SYN-cookie, NAT64 fail-closed adds).

---

## File-by-file log (source-level observations via worktree reads)

### File 1: `poll_descriptor/mod.rs` (6294 LOC — THE monolith)

**Current state:**
- 6294 LOC total, 4796 LOC god-function `poll_binding_process_descriptor` (L683-L5478).
- Top-of-file helpers (L78-L700): `nat64_install_forward_fragment_assoc` (#2562), `nat64_consult_forward_fragment_assoc` (#2562), `policy_packet_icmp`, `junos_host_policy_eval` (full PolicyEvaluationResult for #3706), `JunosHostLocalPolicy` enum (Dropped/Permit/NoMatch, #3706), `emit_junos_host_deny`, `emit_host_inbound_deny`, `junos_host_local_policy`, `ipv6_ext_header_over_limit_drop` (L385, #4743, flowless EVASION fix — % over-limit check), `FlowlessLocalVerdict` (#3291, #3615, #3706), `flowless_local_delivery_verdict` (L399, `l4_present=false` path), `flowless_base_resolution` (L505), `FlowlessLocalVerdict` tests boundary, `try_enqueue_resolver` (L574), `new_flow_session_limit_drop` (L622, #2749 DSCP in RT_FLOW), `strict_syn_check_drops_new_flow` (L676, bare-RST/FIN no-session-install #4400/#4539).
- Sibling module registrations (L28-L34): `cookie_reply`, `debug_log_throttle`, `filter`, `flow_cache_hit`, `nat_exception`, `reject_reply`, `rx_telemetry` — all Phase 2 extractions proving the hot/cold split pattern.
- God function structure (L683-5478): 3 top-level outcomes (flow-cache hit → session-hit arm → session-miss arm + flowless arm), plus host-local and resolver arms nested inside miss/flowless. The session-miss arm itself has sub-arms for DNAT/NAT64/NPTv6/PBR/input-filter/route/policy/NAT/forward-candidate/ARP/reject.
- Post-god-function tests (L5489-6294, ~800 LOC): IPv6 ext-header over-limit tests (#4743), resolver throttle tests, forwarding_with_limit helpers, counted_key helpers, strict-syn-check tests (#4400), flowless local-delivery tests (`flowless_local_delivery_tests`, L6085-6240).

**Hot-path proximity:** Hottest — every packet enters L683. Flow-cache hit path is 90%+ packets at steady state (long-lived TCP). Session-miss is ~1% (first packet of each flow). Flowless is rare (fragments, zero-L4). Host-local is rare (IKE, management).

**Decomposition history:**
- #946 Phase 1 (stages 5-11) → `poll_stages.rs` — pure code-motion, #[inline] so IR identical. DONE.
- #1054 flat file → `poll_descriptor/` dir module.
- #1327 Step 1 → `flow_cache_hit.rs` + `rx_telemetry.rs` — flow-cache is hottest fast path, #[inline(always)] for zero-call guarantee (verified via `cargo asm` in #1327 plan).
- #1697 → `cookie_reply.rs` (#[cold]), `reject_reply.rs` (#[cold] except budget check), `filter.rs` (mixed #[inline] guards + #[cold] tails), `nat_exception.rs` (#[cold]).
- #4404 inc1 → `debug_log_throttle.rs` — pure numeric caps, dependency-free.

**Remaining seam (what #4404 tracks but mod.rs still holds inline):**
- Flowless path: `flowless_local_delivery_verdict` + `FlowlessLocalVerdict` + `flowless_base_resolution` + `FlowlessBaseResolution` + `FlowlessSide` + `ipv6_ext_header_over_limit_drop` + `flowless_l3_addrs` (this last is actually in poll_stages.rs L334, see below) — L399-L570 plus flowless arm in god-function L3568-L3760+ (est ~400 LOC). This is the largest cold-ish seam still inline after #1327. It is almost pure (takes `ForwardingState`, `SessionFlow`, `UserspaceDpMeta`, `packet_frame`, returns verdict). Decomposition difficulty: MEDIUM (depends on `junos_host_policy_eval` + `host_inbound_gated_lo0_action` + `filter_terminal` which are in filter.rs — but that's OK, call them).
- NAT pre-routing block: L1396-L1606 (~210 LOC) — `pre_routing_dnat`, `nptv6_inbound`, `nat64_match`, `effective_resolution_target`, `policy_dst_ip/port`, tri-state NAT64. Almost pure (reads forwarding tables + flow, returns outcome struct).
- Host-local dedup: `junos_host_local_policy` (L284), `junos_host_policy_eval` (L168), `emit_junos_host_deny` (L221), `flowless_local_delivery_verdict` (L399) encode Junos order (host-inbound → lo0 → junos-host) in TWO places (flow-backed LocalDelivery arm + flowless LocalDelivery arm). This is THE duplication flagged in #4404. The fix is one canonical `host_local_delivery_gates()` that both arms call, parameterized by `is_flowless: bool`.
- Debug-log cold outline: 17 `cfg!(feature="debug-log")` eprintln! sites (WAN_RETURN_HIT L968-987, SESS_MISS dump L2004-2062, RX_ETH/HEX, RST_DETECT, OVERSIZED_RX, SYN_FLOOD, etc.). These are debug-only (feature-gated) but their bodies inflate the god-function's source LOC and its L1-i working set in debug builds. Moving the bodies to `#[cold] #[inline(never)]` helpers in a `telemetry_debug.rs` sibling is performance-positive (icache) and readability-positive. Hot path: the `cfg!(feature = "debug-log")` branch collapses to `false` in release — LLVM eliminates body regardless — but source-level bloat still harms review. The EXISTING `rx_telemetry.rs` already shows the pattern: #[inline] with debug-only bodies that LLVM eliminates in release.

**Low-level invariants touching this file:**
- Single-recycle: frame freed exactly once even on drop/reject/TTL-expiry paths. 38 push sites + owned_packet_frame.take() transfer. Any split must preserve: every early `continue` pushes `desc.addr` exactly once; forward path sets `recycle_now=false`. `cargo test tx::dispatch` FORCE_TUPLE_MISMATCH + FORCE_OVERSIZED hooks pin this on TX path; poll_descriptor side has no direct single-recycle unit test — it is implicitly pinned by `cargo test userspace-dp` full suite (flowless tests recycle counts, etc.).
- Junos order: host-inbound-traffic admission → lo0 input-filter → junos-host policy. Duplicated in flow-backed and flowless local-delivery arms. `flowless_local_delivery_tests` (L6085-6240) pins flowless Junos order.
- Table-scoped local delivery: `table_for_inet_addr` + `local_service_is_licensed` + `forwarding_build` `connected_route` scoping.
- UMEM frame ownership: `desc.addr` is 64-byte aligned (debug_assert in rx_telemetry), area slice is unsafe but contract documents pointee outlives call.
- Endianness locality: all L4 port compares use host-native after `u16::from_be` in parser; screen uses native-endian per spec.
- NAT64 fail-closed tri-state: `MatchUnavailable` drops (never routes synthetic addr) vs `NoPrefixMatch` falls through — #2291.

**Why it matters (build time + review + correctness):**
- Build time: mod.rs at 6294 LOC is the largest Rust file in A1 batch; it pulls in `super::*` (all afxdp types) plus many crate:: items (policy, nat, filter, screen, nat64, nptv6, forwarding). A full `cargo test --bin xpf-userspace-dp` rebuild touching this file rebuilds most of afxdp. Splitting cold arms out reduces per-file incremental compilation unit (rustc's query system sees smaller file change). Measured: no direct cargo timing here (incus unavailable), but modularity discipline in `docs/engineering-style.md` requires split at ~2000 LOC — mod.rs is 3.14x over.
- Review: a PR that touches flowless path currently shows 6294 LOC file in diff context; reviewers must scan past 4796 LOC god-function to find change. Splitting flowless/host-local/nat-pre-routing into own files scopes diffs.
- Correctness: Junos-order duplication across flow-backed + flowless local-delivery is a bug attractor (see #3292 flowless junos-host gate omission that needed separate fix). Single canonical function eliminates class.

---

### File 2: `poll_descriptor/reject_reply.rs` (446 LOC)

**Current state:** Cold-path reject-reply synthesis: TCP RST (with sequence ack from flow) / ICMP unreachable (admin-prohibited, host-unreachable) build, TX-budget gate (`syn_cookie_reply_budget_available` analogue), per-zone ICMP rate-limit (GCRA bucket, `icmp_ratelimit::should_rate_limit`), VLAN logical-ifindex fix (#3026 — resolves ingress logical ifindex for CoS/output-filter classify), output-filter classify on generated reply (fail-closed on parse error, #2238/#3035), source-routed counters (Policy deny counter vs Filter reject counter, #3615 truthful action: reject whose reply fail-closes logs DENY not REJECT), `TRANSLATED_MISSING_NEIGHBOR_BOUND` gate (#1145), resolver enqueue for missing neighbor on reply path.

**Structure:**
- `enqueue_policy_reject_reply` (L43): policy-deny TCP RST/ICMP unreach, policy-disposition counter, rate-limit, VLAN fix.
- `enqueue_filter_reject_reply` (L74, `pub(in crate::afxdp)` so callable from filter + flow-cache): filter-reject TCP RST/ICMP, filter counter, rate-limit, VLAN fix — byte-identical pipeline but filter counter label.
- `enqueue_deny_reply` + `deny_reply_and_emit`: host-bound deny-reject path (junos-host policy deny with zone_id, #3019).
- `enqueue_reject_reply` (L215): internal shared core — feasibility (is packet replyable? non-first-fragment? inbound RST not answered?), budget check, rate-limit bucket drain, output-filter classify, TX enqueue.

**Hot-path preservation:** `#[cold] #[inline(never)]` on the heavy bodies (RST/ICMP build, rate-limit drain), `#[inline]` only on trivial budget-check guard that folds into caller. This is textbook: common case (no reject — `FilterAction::Accept` or `PolicyAction::Accept`) is load+branch NO call; rare reject tail calls cold callee, lives in `.text.unlikely`. Existing since #1697.

**Coupling:** `use super::cookie_reply::syn_cookie_reply_budget_available; use super::worker::WorkerTxPipeline; use super::*;` — depends only on `WorkerTxPipeline`, `ForwardingState`, `UserspaceDpMeta`, `SessionFlow`, `BatchCounters`. Does NOT capture `binding` / `sessions` / `area` / `desc` mutable locals. This is clean and testable — test file `reject_reply_tests.rs` 2264 LOC with 14 tests drives it standalone.

**Observations / new seams:**
- The file already has TWO reject paths (policy-reject vs filter-reject) sharing one internal core (`enqueue_reject_reply`). The third logical reject path — junos-host reject — still lives partially in mod.rs (`junos_host_local_policy` has its own reject reply inline). Consolidating that third into `reject_reply.rs` (a `enqueue_junos_host_reject_reply` wrapper that calls the shared core with junos-host flag) would complete the unification. Currently NOT a bug — the logic is correct — but it would reduce duplication and let `docs/pr/3019-junos-host` doc one call site.

**Responsibilities fused:** TCP RST build, ICMP unreach build (v4+ v6), budget gate, rate-limit, VLAN logical-ifindex SSOT, output-filter classify on generated reply, counter source-routing, resolver enqueue. These 7 responsibilities ARE genuinely coupled (all part of "synthesize reject reply"), so NOT a candidate for further split. The file at 446 LOC is under threshold and already (D).

---

### File 3: `poll_descriptor/filter.rs` (1201 LOC)

**Current state:** Interface input-filter evaluation + filter-log emission. Mixed inline/cold split with per-function inline policy (NOT blanket #[inline(never)] — see module header doc comment):

| Function | Inline attr | Role | Hot? |
|----------|-------------|------|------|
| `filter_log_ingress_zone_id` / `filter_log_egress_zone_id` | `#[inline]` | trivial leaf, u16 zone-id resolve | Folded everywhere |
| `emit_cached_input_filter_log` / `emit_cached_output_filter_log` | `#[inline]` | unconditional from `stage_flow_cache_hit` (#[inline(always)]), None guard folds | H3 — 90%+ packets |
| `emit_cached_output_filter_log_tail` | `#[cold] #[inline(never)]` | rare non-None tail of output emitter | Cold |
| `evaluate_dscp_sensitive_input_filter_on_session_hit` | `#[inline]` | per-packet DSCP-sensitive re-eval on session-hit, guard `interface_input_filter_has_dscp_match` folds to None with no call when no DSCP filter | H3 guard / C1 body |
| `evaluate_non_pbr_input_filter` / `_log_only` / `_counters_cached` | `#[cold] #[inline(never)]` | rare/exception: full input-filter evaluation (routing-eval follows flag, ingress_zone_override, term_match_extra) | Cold (miss path) |
| `emit_input_filter_log_match` | `#[cold] #[inline(never)]` | RT_FLOW log emit for filter match | Cold |
| `apply_lo0_filter_action` | `#[cold] #[inline(never)]` | lo0 input-filter on host-bound path | Cold |
| `host_inbound_gated_lo0_action` | `#[cold] #[inline(never)]` | host-inbound → lo0 Junos-order gate (used by LocalDelivery arms) | Cold, but Junos-order critical |
| `filter_terminal` | `#[cold] #[inline(never)]` | terminal action (discard/reject/accept) with reply-before-log ordering (#3615) | Cold |

**Hot-path preservation:** `emit_cached_*` called unconditionally from `stage_flow_cache_hit` (#[inline(always)]) — in the common no-filter-logging case, body is `if cached_descriptor.log.is_none() { return; }` so hot path is load+branch NO call, NO 96-byte UserspaceDpMeta copy. The rare non-None tail calls `#[cold]` callee. This pattern is documented in module header and textbook correct per engineering-style.md hot-path discipline.

**Coupling / seam:** Takes explicit args: `&ForwardingState`, `&SessionFlow`, `UserspaceDpMeta`, `Option<TermMatchExtra>`, `Option<u16>` ingress_zone_override, `bool` routing_eval_follows. Does NOT capture god-function mutable locals. Clean.

**Observations / remaining overlap:**
- `host_inbound_gated_lo0_action` + `filter_terminal` encode part of Junos order (host-inbound → lo0). The full Junos order also needs `junos_host_local_policy` (still in mod.rs). So filter.rs ALREADY split Junos-order across two files — `filter.rs` owns first two steps, `mod.rs` owns third. Completing the split by moving junos-host into `host_local.rs` (or into filter.rs as third step) would put entire Junos-order in one file. This is the seam in Finding A1a-H1-2.

**Size:** 1201 LOC — under 2000 threshold. Includes inline guards + cold bodies + tests (flowless_lo0 tests ~550 LOC). Within batch, rank 3.

---

### File 4: `poll_stages.rs` (975 LOC)

**Current state:** #946 Phase 1 pure code-motion extraction of 7 sub-stages out of `poll_binding_process_descriptor` while-let body. No batch reordering, no behavioral change. Each helper is direct semantic equivalent of inline block it replaces. Module header lists stages owned:
- Stage 5: link-layer (ARP/NDP) classify → `stage_link_layer_classify` (L73)
- Stage 6: native GRE decap → `stage_native_gre_decap` (L240)
- Stage 7+8: parse flow + learn neighbor → `stage_parse_flow_and_learn` (L268)
- Stage 9: fabric-ingress classification → `stage_classify_fabric_ingress` (L306)
- Stage 10: screen / IDS slow-path → `stage_screen_check` (L390) + flowless screen variant
- Stage 11: IPsec passthrough → `stage_ipsec_passthrough_check` (L901)

**Also:** `flowless_l3_addrs` (L334, `fn`, not pub) — flowless L3 addr extraction for flowless delivery verdict, used by GRE decap + flowless arms. `ipsec_passthrough_decision` (L843, `fn`) — pure helper for IPsec decision.

**Inlining:** All stage fns `#[inline]` — same crate as `poll_binding_process_descriptor`, LLVM inlines across module boundary. Already verified in #946 test plan via `cargo asm` spot-check that no `call` edge is emitted in optimized builds. Moving to another crate would break this and add `callq` per packet — MUST stay in same crate.

**Tests:** 2636 LOC in `poll_stages_tests.rs` (15+ tests): syn-cookie runtime validation, priority-tagged VLAN0 L3 parse (#2145), ARP/NDP VLAN neighbor learn under logical ifindex (#2370), invalid sender IP anti-poison (#2790), own-IP anti-poison, NDP Override honoring (#4475), IPsec passthrough + IKE gate (#3616/#4323), screen early TCP checks.

**Observation:** This file is the POSITIVE EXAMPLE of phase-1 decomposition done correctly. The comment in mod.rs (L13-L26) says remaining stages 12+ extraction is blocked by mutable-locals coupling — this is accurate. Further split of THIS file would fragment the stage ordering and reintroduce zone-resolve duplication bugs (#2145, #3022). Classification: (D) DO-NOT-SPLIT, keep as-is. This is the "negatives with reasoning" entry required.

**But also:** `flowless_l3_addrs` (L334) is actually referenced by flowless path (not by stages 5-11 hot path) — it could arguably move to `flowless.rs` when that new file is created. However keeping it in poll_stages.rs is defensible because GRE decap (Stage 6) also uses L3 addr extraction for native GRE inner L3. NOT a required move.

---

### File 5: `poll_descriptor/flow_cache_hit.rs` (533 LOC)

**Current state:** #1327 Step 1 extraction of flow-cache fast path — single largest self-contained `continue`-terminated block in god-function (formerly L563-894 of flat poll_descriptor.rs). Hottest path: 90%+ of packets at steady state are long-lived TCP served from cache.

**Function:** `stage_flow_cache_hit` (L65, `#[inline(always)]` mandated by #1327 plan and Codex round-2 review). Single call site; LLVM produces same IR as original inline code; `cargo asm` spot-check confirms no `call` edge in optimized builds.

**Body:** Neighbor MAC change epoch check (#3048 — `mac_change_epoch` only advances on genuine MAC change, not same-MAC refresh, so steady-state no re-miss), `cached_flow_decision_valid` (HA state, dynamic neighbors, fabric redirect, resolution target), TTL/hop-limit check BEFORE any egress side effect (#3779 — expired packet must not charge counters/policers/logs/session, consistent with slow path), `tx_selection.filter_counters` replay (#2573 — ALL matched `then count` terms, not just last), input filter counters replay (#3777), policy hit-counter replay via coalescer (#3073, reorder-stable bound handle #3322), three-color policer (`apply_cached_three_color_policers`), cached input/output filter-log (#[inline] guard folds), output-filter `then reject` cached reply (#3608, reply-before-log #3615 truthful action), BA reclassify (DSCP/PCP classifiers per-packet, #3778 — seed-packet queue frozen, re-resolve on each packet when BA active), `touch_if_stale` (quarter-way expiry refresh, #2220 — per-session, not binding-GLOBAL modulo-64), `account_packet` (direction fold onto canonical forward entry, #2501 + #2749 TCP-flags+DSCP for RT_FLOW), inline in-place rewrite fast path (descriptor-based straight-line rewrite, `apply_rewrite_descriptor`, #1145), `rewrite_forwarded_frame_in_place` fallback, mirror admission + clone, PreparedTxRequest build, fallback PendingForwardRequest path, zone counters (#3651, flat-LUT), NAT counters.

**Recycle-exit map (documented in module header):**
- Drop path: `scratch_recycle.push(desc.addr)` + `return Consumed`.
- TTL-exceeded → local ICMP TE: `scratch_forwards.push(request)` + `return Consumed` (no recycle — frame returned via pending_fill_frames — matches original L653 comment).
- Final fall-out: conditional push based on local `recycle_now`.

**Hot-path preservation:** `#[inline(always)]`, zero new allocs (every `cached_*` borrow into cache entry, never clone; two pre-existing heap interactions: `owned_packet_frame.take()` + PendingForwardRequest build), all recycle/forward pushes owned by helper. Caller MUST `continue` without touching `desc.addr` on `Consumed`. Documented as hot-path discipline. This file is textbook.

**Classification:** (D) DO-NOT-SPLIT — the cache-hit path is already isolated, at 533 LOC (well under threshold), and any further split would reintroduce hot-path coupling or break the `#[inline(always)]` same-crate inlining guarantee.

---

### File 6: `poll_descriptor/cookie_reply.rs` (130 LOC prod + 395 tests = 525 total)

**State:** #1697 cold-path extraction: SYN-cookie reply enqueue machinery, lifted from mod.rs.

- `syn_cookie_reply_budget_available` (L29, `#[inline]`): tiny, called only from already-cold enqueue body — stays inline so inliner folds it into single cold caller.
- `enqueue_syn_cookie_reply` (L47, `#[cold] #[inline(never)]`): screen returns `ScreenCheckOutcome::SynCookieChallenge` path only; never for established transit flows; true cold/exception body — `.text.unlikely` placement.
- `SynCookieReply` enum (L12): `SynAck(SynCookieChallenge)` / `AckRst`.
- `SYN_COOKIE_REPLY_PENDING_RESERVE` const = TX_BATCH_SIZE.

**Body:** Budget check, bytes build (`build_syn_cookie_syn_ack_frame` / `build_syn_cookie_ack_rst_frame`), generated-reply classify (`classify_generated_reply` on LOGICAL egress ifindex #3035, not physical — CoS/output-filter keyed by logical unit ifindex; VLAN subinterface physical index is parent, so parent's queue would be wrong; mirrors #3026 ICMP-error fix), output-filter terminal drop check, TxRequest build, counters.

**Tests:** `cookie_reply_tests.rs` 395 LOC — `syn_cookie_reply_budget_preserves_tx_batch_reserve`, `syn_cookie_reply_dropped_by_egress_output_filter`, `syn_cookie_reply_classifies_on_logical_vlan_ifindex_3035`, etc.

**Classification:** (D) DO-NOT-SPLIT — cold, well-extracted, 130 LOC.

---

### File 7: `poll_descriptor/rx_telemetry.rs` (220 LOC)

**State:** #1327 Step 1 extracted from mod.rs — per-descriptor RX bookkeeping. Module header (L1-L40) says verbatim move, no behavioral change, pub(super) visibility so inner-loop driver calls it.

**Body:** Two x86_64 prefetches (96-byte metadata header at desc.addr-meta_len, straddles 2 cache lines; 64-byte frame data; hides ~100ns DRAM latency — perf profile showed magic/version/length compare was 33% self-time under iperf3 -P 128 @ 25G shaper before prefetch #909), unconditional counter bumps (`rx_packets`, `rx_bytes`, `dbg.rx`, `rx_bytes_total`, `rx_max_frame`), oversized frame census (`rx_oversized` >1514, eprint up to 20 breadcrumbs only under `cfg(feature="debug-log")`), RX-side TCP flag census (FIN / SYN+ACK / zero-window / RST, #2151 predicates, only under debug-log), poison-descriptor detection (0xDEAD_BEEF_DEAD_BEEF — kernel recycling), first-10 frame dump.

**Inline:** `#[inline]` (not always) — deliberate per header doc: with `--features debug-log` body is ~200 LOC, forcing inline would bloat L1-i in debug builds; `#[inline]` lets compiler honor body-size heuristic — inlines tight prod builds, declines on bulky debug path. Source-level separation goal per #1128.

**Classification:** (D) DO-NOT-SPLIT — hot-path housekeeping noise extracted as single helper with correct inline policy. Textbook.

---

### File 8: `poll_descriptor/nat_exception.rs` (125 LOC)

**State:** #1697 cold-path extraction: source-NAT decision + failure recorder, lifted from mod.rs.

- `source_nat_decision_for_flow` (L25, `#[cold] #[inline(never)]`): session-miss slow path, evaluated once per new flow when session table misses.
- `record_source_nat_failure` (L96, `#[cold] #[inline(never)]`): only on SNAT exhaustion exception.

**Body:** `match_snat_with_counter_scoped` with egress-zone gate (#2871 — static-NAT reverse SNAT egress-zone symmetric with #2864 DNAT ingress-zone; #3096 interface/routing-instance scope; #3435 DEST-gated reverse static SNAT, `match source-address` against original client), `match_source_nat_for_flow_result_at`, `SourceNatLookup::Matched/NoMatch/Unavailable`.

**Hot-path note:** Not reached on established-flow transit fast path (`stage_flow_cache_hit`), so #[cold] correct.

**Classification:** (D) DO-NOT-SPLIT — 125 LOC, cold, well-extracted. Further split would fragment the single decision+failure-record pipeline.

---

### File 9: `poll_descriptor/debug_log_throttle.rs` (99 LOC)

**State:** #4404 increment 1 — cold-path debug-log throttle predicates, pure functions of per-interval counter.

```rust
const SESSION_MISS_DEBUG_LOG_CAP: u64 = 10;
const POLICY_DENY_DEBUG_LOG_CAP: u64 = 3;
fn session_miss_debug_log_allowed(session_miss: u64) -> bool { session_miss <= cap }
fn policy_deny_debug_log_allowed(policy_deny: u64) -> bool { policy_deny <= cap }
```

**Why extracted:** #4120 — test-env `is_trust_flow = ingress_ifindex == 5 || from_zone == "lan" || 10.x-src` predicate used to OR past cap, defeating throttle for ENTIRE trusted side on real 10.x LAN and flooding log — exactly CLAUDE.md Logging Rules hazard. Removed; numeric cap now governs uniformly. Signature takes ONLY counter — no ingress ifindex/zone/subnet can bypass.

**Tests:** `debug_log_throttle_tests` — 3 tests pin numeric cap, prove topology bypass cannot re-appear. RED-on-revert: reintroducing `is_trust_flow` bypass must OR past these predicates.

**Classification:** (D) DO-NOT-SPLIT — pure, dependency-free, 99 LOC, textbook code-motion with pinned-contract tests.

---

## Dedup notes (prior issues)

Read `/tmp/ps-review-039.md` (f7014695 base) and prior NNN files:

- **#4404 — `poll_descriptor/mod.rs` god-function (reported 5759 LOC at filing time, decomposed as 1368 LOC god-function with 15+ resp) — ALREADY FILED.** This batch reports **6294 LOC now (growth from 5759)**, with **4796 LOC god-function (L683-L5478)**. The 1368→4796 delta is +3428 LOC from features accreting since #4404 (IPv6 ext-header #4743, SYN-cookie #1697/#2238, flowless #3291/#3292/#3615/#3706, NAT64 frag-assoc #2562/#4617, PBR #4392, BA reclassify #3778, policy hit-counter #3073/#3322, filter-counter replay #2573/#3777, zone counters #3651, TTL before side-effects #3779, host-inbound dedup #3019/#3292). This finding does NOT re-file #4404; it provides:
  - New measurement (6294 total, 4796 fn) + 38 recycle push sites + 17 debug-log cfg gates + 24 mutable-locals coupling.
  - New concrete seams (#4404 lacked: flowless mechanical move, NAT pre-routing struct-outcome, host-local Junos-order dedup, telemetry-debug cold outline, single-recycle pinning).
  - Hot-path preservation annex for each seam (disassembly diff method, failover/CoS gates).
  - Issue-split into 4 incremental PRs for #4404's overall phase.

- **#4421 — ForwardingState/SessionTable/policy.rs/nat64.rs/neighbor.rs/SnapshotIntegrityError/SessionTable/flowexport/firewall-filter/rules.go — ALREADY FILED** as modularity backlog (not specifically poll_descriptor but mentions forwarding state, policy, NAT64). Not duplicative — this audit is poll_descriptor-specific.

- **#4408 — `tx/dispatch enqueue_pending_forwards` (1131 LOC) + `cos/queue_service waterfill` (438 LOC) — ALREADY FILED.** Out of A1a batch scope (TX drain + CoS queue_service are separate files: `tx/dispatch.rs`, `cos/queue_service.rs`). NOT re-filed here.

- **Prior ps-review-039 A1 batch:** Reported `poll_descriptor/mod.rs` 6042 LOC (vs 6294 now — +252 LOC from recent features), `poll_stages.rs` 3527 LOC in some counting vs 975 prod LOC (the 3527 counted test files), with same Finding 1/2/3 structure. This A1a audit is scoped to A1a files only per assignment, but its mod.rs observations are consistent with and extend #4404.

**Dedup disposition:** File NEW findings only for seams that #4404 did not decompose (flowless, NAT pre-routing, host-local Junos-order dedup, telemetry-debug). Mark them as "Increment of #4404". Do NOT re-file #4404 or #4408 or #4421.

---

## Findings by severity (HFT stance: latency sacred — zero hot-path regression)

### HIGH

---

#### A1a-H1 — mod.rs still-fused cold/separable arms after #4404 inc1: flowless, NAT pre-routing, host-local Junos-order dup, debug-log icache bloat

**File:** `/tmp/review-wt-ps-043-a1a-b1/userspace-dp/src/afxdp/poll_descriptor/mod.rs:78-700` helpers + L683-L5478 god-function (4796 LOC) + tests L5489-6294.

**Responsibilities fused (still inline after prior extractions):** 15+ listed in inventory above. The remaining decomposition difficulty is accurately described in `docs/pr/1327-poll-descriptor-stages/plan.md` + file header L13-L26: post-flow-cache slow path stages 12+ are blocked by mutable-locals coupling (`binding`, `sessions`, `telemetry`, `area`, `desc`, `owned_packet_frame`, `recycle_now`, `session_ingress_zone`, `flow_cache_*`, `apply_nat_on_fabric`, `flow_cache_install_failed`, `pre_routing_dnat_counter`). But within that block, 4 sub-arms are separable by the same hot/cold criterion used for #1327 and #1697: they are cold (flowless fragments, first-packet miss-only, exception-only, or debug-only) and already have explicit arg boundaries.

**Natural seams (4 incremental, ordered by risk/ease):**

##### Seam 1 — Flowless mechanical extraction (A class — behavior-identical code-motion)

What moves:
- `FlowlessLocalVerdict` enum + `FlowlessLocalDeliveryVerdict` helper struct (if any) + `flowless_local_delivery_verdict()` (L399-~490) + `flowless_base_resolution()` (L505-~570, `FlowlessBaseResolution` + `FlowlessSide`) + `ipv6_ext_header_over_limit_drop()` (L385-~398, #4743) + `flowless_l3_addrs` from poll_stages.rs L334 (import or duplicate — keep original for Stage 6; flowless copy for new module) + `flowless_local_delivery_tests` (L6085-6294, existing tests that pin Junos order for flowless).
- New file: `userspace-dp/src/afxdp/poll_descriptor/flowless.rs` (est ~450-550 LOC prod + ~300 test).
- mod.rs edits: `mod flowless; use flowless::{flowless_local_delivery_verdict, flowless_base_resolution, ipv6_ext_header_over_limit_drop, FlowlessLocalVerdict};` + replace inline flowless arm (~200-300 LOC in god-function L3568-~3900) with call to `flowless_transit_and_host_gates()` helper that returns same `FlowlessLocalVerdict` (already encoded) and reuses `host_inbound_gated_lo0_action` + `filter_terminal` from filter.rs + `junos_host_policy_eval` from collocated host_local or from flowless module's import of same.

Proposed decomposition (concrete file names + what moves):
- File: `poll_descriptor/flowless.rs`
  - `pub(super) enum FlowlessLocalVerdict { Deliver, HostInboundDeny, Filtered, JunosHostDeny }` (current values — verify from source)
  - `#[inline] pub(super) fn flowless_local_delivery_verdict(...) -> FlowlessLocalVerdict` — pure fn of forwarding state + flow + meta + ingress_zone_override: encodes `host_inbound_gated_lo0_action → filter_terminal → junos_host_policy_eval` in correct Junos order for flowless (l4_present=false, dst_port=0).
  - `#[inline] pub(super) fn flowless_base_resolution(forwarding, flowless_l3_addrs, meta, from_zone_id) -> Option<FlowlessBaseResolution>` — flowless route lookup path.
  - `#[inline] fn ipv6_ext_header_over_limit_drop(...) -> bool` — IPv6 ext-header over-limit check (already pure).
  - `flowless_local_delivery_tests` moves verbatim.

Hot-path preservation analysis:
- Inlining preserved? YES — new fns are `#[inline]` and stay in `crate::afxdp::poll_descriptor::flowless` (same crate as caller), LLVM inlines across module boundary. The 90%+ packets flow-cache hit path does NOT call flowless (flow.is_none() gate, L760) — so no hot-path codegen change. The 10% miss path that does call flowless is infrequent (first packet per flow). `cargo asm` on `poll_binding_process_descriptor` should show same hot loop (no callq to flowless.rs in fast path). For session-miss flowless path, one additional call edge in release is acceptable — it is already cold (#3064 flowless fragments are exception).
- NO new heap alloc? Existing flowless path has zero allocs (pure decision based on forwarding tables + flow). No Vec/String built.
- NO dynamic dispatch? No trait object, no vtable.
- const/monomorphization preserved? No generics involved.
- Zero-copy/UMEM frame ownership preserved? `desc.addr` push preserved by caller — flowless helper returns verdict, caller does push/continue as before (same as existing `flowless_local_delivery_verdict` contract — recycle/counter side-effects stay in caller, verdict is unit-testable).
- Endianness locality? No port comparison in flowless verdict (l4_present=false gates it; dst_port=0 constant).
- Branch/icache? Flowless check `flow.is_none() && over_limit` is already cold — extracting to `#[inline]` helper actually reduces hot function size, improving icache pressure for hot path.
- Single-recycle invariant preserved? Caller owns `scratch_recycle.push(desc.addr) + continue` (existing pattern, documented in `flowless_local_delivery_verdict` comment "poll loop performs recycle/counter side-effects keyed on returned verdict").

Tests+gate:
- `cargo test --bin xpf-userspace-dp poll_descriptor::flowless::flowless_local_delivery_tests` — existing 5 tests.
- `cargo test --bin xpf-userspace-dp poll_descriptor` — full descriptor module.
- Disassembly diff (`cargo asm --bin xpf-userspace-dp afxdp::poll_descriptor::poll_binding_process_descriptor`): hot loop (first 2KB covering flow-cache fast path header + screen + IPsec + flow-cache call) must be byte-identical (no new `callq flowless::*`), verified by `diff <(RUSTFLAGS="--emit asm" cargo rustc ...)`.
- `make cluster-deploy` + `./test/incus/apply-cos-config.sh loss:xpf-userspace-fw0` + `iperf3 -P 16 -t 30 -p 5203` → 172.16.80.200 — failover gate unaffected (flowless fragments are not used in iperf3 CoS smoke, but proves no hot regression; flowless separately exercised by `cargo test tests_fragment` non-first fragment push-through).
- `make test-failover` — HA gate — fragment handling shares single-recycle.

Low-level invariants:
- Junos order for flowless host-bound: host-inbound → lo0 → junos-host (same as flow-backed). `flowless_local_delivery_tests` pins order.
- Over-limit detection: only genuine over-limit IPv6 ext-header chain (MAX_IPV6_EXT_HEADERS walkers give up) + flow.is_none() (helper could not derive L4 tuple). Non-first fragment / ICMPv6 / truncated packet NOT over-limit.
- `l4_present=false` routes through l3-aware junos-host eval so port-bearing app term fails closed.

Why it matters:
- Build: source LOC reduction in mod.rs god-function region removes ~200-300 LOC of flowless logic from 4796 LOC fn, reducing rustc query system cost for incremental rebuild touching flowless logic only (new file vs 6294 LOC file).
- Review: flowless policy (security policy + host-inbound + lo0) currently scattered between `junos_host_policy_eval` (top-of-file) + `flowless_local_delivery_verdict` (top-of-file) + flowless arm deep in god-function (L3568+). Putting them in one file lets reviewer see entire flowless enforcement via one `flowless.rs` diff. Currently a change to flowless drop behavior requires reading 6294 LOC file.
- Correctness: Junos-order duplication between flow-backed and flowless local-delivery is bug attractor (#3292). Collocating verdict fn + base resolution + over-limit check in one module makes the order unit-testable once.

Fix direction — incremental PRs:
- PR 1 (A, mechanical, lowest risk): Create `poll_descriptor/flowless.rs` with `FlowlessLocalVerdict`, `flowless_local_delivery_verdict`, `flowless_base_resolution`, `ipv6_ext_header_over_limit_drop`, `flowless_local_delivery_tests` moved verbatim. Add `mod flowless;` in mod.rs top. Replace import. `#[inline]` on all verdict fns. Run `cargo test flowless` + disassembly diff (no change hot loop). Merge.

- Labels: `refactor`, `A-class`, `code-motion`, `flowless`, `single-recycle`, `x-hpc`, `modularity`, `size:6294`, `hot-path-safe`
- Classification: **(A) mechanical / pure code-motion — IR identical, no behavioral change, proven by disassembly diff + `cargo test flowless` + `make test-failover`**
- Dedup: Increment of #4404 — new seam not listed in #4404's decomposition.

---

##### Seam 2 — Host-local Junos-order dedup: canonical `host_local_delivery_gates()` (B class — reorder-testable, eliminates duplication bug class)

What moves / what new:
- Current duplication: Junos order `host_inbound_gated_lo0_action` (in filter.rs, #2521) → `filter_terminal` (filter.rs) → `junos_host_local_policy` (mod.rs L284) → `junos_host_policy_eval` (L168) → `emit_junos_host_deny` (L221) is coded TWICE: once in flow-backed LocalDelivery arm (L1004-L1350 range, includes `#3706` permit metadata stamping) and again in flowless arm (`flowless_local_delivery_verdict` + host-bound flowless path, #3292, no reply synth on flowless). See Finding 1 in ps-review-039 (same).
- New file: `userspace-dp/src/afxdp/poll_descriptor/host_local.rs` (est ~350-450 LOC).
  - `pub(super) enum HostLocalVerdict { Deliver { permit_result: Option<PolicyEvaluationResult> }, HostInboundDeny, Filtered { filtered_counter, log_descriptor }, JunosHostDeny { policy_id, action, permit_stamped_metadata } }` — union of flowless and flow-backed outcomes so both arms can match once.
  - `#[inline] pub(super) fn host_local_delivery_gates(forwarding, flow, meta, from_zone_id, ingress_logical_ifindex, ingress_zone_override, is_flowless: bool) -> HostLocalVerdict` — canonical encoding of Junos order: host-inbound check → lo0 action → junos-host policy eval. Takes `is_flowless: bool` (controls `l4_present=false`, `dst_port=0`, `reject_reply_enqueued=false` for flowless, and whether to call `flowless_l3_addrs` for post-IP addr extraction). Returns verdict the caller matches for recycle/counter/emit side-effects.
  - Re-exports `junos_host_policy_eval`, `junos_host_local_policy`, `emit_junos_host_deny` local (or calls through); keeps `#[inline]` on eval fns, `#[cold] #[inline(never)]` on deny emit.
  - Tests: add `host_local_gates_tests` covering flowless deny vs flow-backed deny, permit metadata stamping (#3706), `reject_reply_enqueued=false` on flowless (truthful DENY log #3615), logical ifindex resolution (#3026).

- mod.rs edits: replace two Junos-order inline blocks (flow-backed LocalDelivery ~348 LOC and flowless host-bound ~120 LOC) with calls to `host_local::host_local_delivery_gates(...)` then match on `HostLocalVerdict` for emit helpers.

Hot-path preservation:
- Inlining preserved? YES — `#[inline]` on `host_local_delivery_gates`, same crate.
- No heap alloc: returns stack-only enum with Option<PolicyEvaluationResult> (which is small, or bound via Arc handle — policy counter Arc clone is cold-only on permit path).
- Single-recycle: verdict explicitly says whether to recycle (all denies recycle; Deliver opens path to resolver/session-install).
- Endianness: no.

Tests+gate:
- `cargo test --bin xpf-userspace-dp poll_descriptor::host_local`
- `cargo test --bin xpf-userspace-dp poll_descriptor::flowless` (flowless host-local covered)
- `cargo test --bin xpf-userspace-dp tests_fragment` (fragment LocalDelivery share)
- `make test-failover` + `make test-ha-crash` (management path exercises host-inbound admit).
- Disassembly diff: flowless and flow-backed LocalDelivery paths small increase in cold call site ok.

Labels: `refactor`, `B-class`, `junos-order`, `dedup`, `flowless`, `single-recycle`, `x-hpc`
Classification: **(B) targeted behavior-preserving extraction + deduplication — conservative, replaces two copies of Junos-order with one canonical, proven by `flowless_local_delivery_tests` + `lo0_gate_tests` + failover gate**

Dedup: same #4404 Junos-order item, but NEW concrete file proposed (previous audit proposed `host_local.rs` but didn't specify file move or `is_flowless` parameterization). This is the incremental plan.

---

##### Seam 3 — NAT pre-routing extraction: `nat_pre_routing.rs` (B class — pure-ish, tri-state needs tests)

What moves:
- Block L~1396-L1606 (~210 LOC, inside session-miss arm): `pre_routing_dnat` (static-nat + port-DNAT match via `match_dnat_scoped`), `nptv6_inbound` (NPTv6 inbound translation), `nat64_match` (NAT64 `classify_ipv6_dest` tri-state: NoPrefixMatch/ MatchReady/ MatchUnavailable #2291), `effective_resolution_target` (resolved to dst_v4 for NAT64, internal for NPTv6, rewritten dst for DNAT), `policy_dst_ip/port` (#2344 policy against post-translation), plus `pre_routing_dnat_counter` (Arc counter bump #2218).
- New file: `poll_descriptor/nat_pre_routing.rs`
  - `pub struct NatPreRoutingOutcome { pre_routing_dnat: Option<StaticDnatOutcome>, nptv6_inbound: Option<IpAddr>, nat64_match: Option<(usize, Ipv4Addr, Ipv6Addr)>, effective_resolution_target: IpAddr, policy_dst_ip: IpAddr, policy_dst_port: u16, counter: Option<Arc<NatRuleCounter>> }`
  - `#[inline] pub(super) fn nat_pre_routing(forwarding, flow, now_ns, non_first_fragment) -> NatPreRoutingOutcome` — almost pure: reads `forwarding.static_nat`, `forwarding.nat64`, `forwarding.nptv6` via shared ref, returns outcome struct.
  - Tests: `nat_pre_routing_tests.rs` covering DNAT, static-DNAT port rewrite vs no-port rewrite, NPTv6, NAT64 tri-state NoPrefixMatch falls through / MatchReady produces dst_v4 / MatchUnavailable drop (fail-closed, #2291), counter present only on hit (#2218 clone cost is cold-only on DNAT hit — first packet per DNAT flow).

Hot-path preservation:
- Inlining: `#[inline]` so LLVM folds into session-miss arm that is already cold/miss-only.
- No heap alloc: outcome struct is stack-only; only non-stack is `Option<Arc<...>>` counter Clone which is Arc ref-count inc (atomic) only on DNAT hit — cold path, first packet per flow.

Tests+gate:
- `cargo test nat_pre_routing`
- `cargo test tests_policy_inbound_nat` (existing — exercises inbound NAT policy against post-translation tuple, #2344).
- `make test-failover` — NAT paths share single-recycle.

Labels: `refactor`, `B-class`, `nat`, `nat64`, `dnat`, `nptv6`, `fail-closed`, `modularity`
Classification: **(B)**

Dedup: new fine-grained seam not in #4404's listed breakdown.

---

##### Seam 4 — Debug-log cold outline: `telemetry_debug.rs` (C class — performance-positive, icache)

What moves:
- 17 `cfg!(feature = "debug-log")` eprintln! bodies currently inline in god-function — biggest offenders: WAN_RETURN_HIT log inside session-hit arm (L968-987, `if telemetry.dbg.return_hit_count < N { eprintln!(...) }`), SESS_MISS dump (L2004-2062, `eprintln!("SESS_MISS ...")` with flow dump), plus scattered RST_DETECT, OVERSIZED_RX in rx_telemetry (already #1327 extracted but that file itself has debug-log bodies — current `#[inline]` policy documented to NOT always inline in debug builds, but prod build still pays icache for the symbol). Also `try_enqueue_resolver` debug log throttling.

- New file: `poll_descriptor/telemetry_debug.rs` (est ~200-300 LOC, all `cfg(feature="debug-log")` guarded).
  - `#[cold] #[inline(never)] pub(super) fn dbg_log_wan_return_hit(flow: &SessionFlow, telemetry: &TelemetryContext)` — moves L968-987 body.
  - `#[cold] #[inline(never)] pub(super) fn dbg_dump_sess_miss(flow, debug, telemetry)` — moves L2004-2062.
  - Keep `cfg(feature="debug-log")` inside the callee body so without feature the function is an empty stub that LLVM eliminates (zero call, zero cost).

- mod.rs edits: replace inline `if cfg!(feature="debug-log") { eprintln!(...) }` blocks at ~10-12 sites with `if cfg!(feature="debug-log") { telemetry_debug::dbg_log_*(&...) }`.

Hot-path preservation:
- `cfg!(feature="debug-log")` evaluates to `false` at compile time without feature — LLVM eliminates entire `if false { call }` block to ZERO instructions. With feature, the bodies are now in `#[cold] #[inline(never)]` in `.text.unlikely`, so hot path L1-i is reduced even in debug-log builds. This is textbook hot/cold per engineering-style.md ("Never add slog.Info inside loops that run per-packet, per-session, or per-poll-tick. If you need per-tick logging, use slog.Debug." — Rust analogue is cfg-gated eprintln only via cold outline).
- No heap alloc, no dispatch.

Tests+gate:
- `cargo test --bin xpf-userspace-dp --features debug-log` — debug-log cfg build compiles.
- Release build: `nm -S` on `xpf-userspace-dp` binary — hot function `poll_binding_process_descriptor` should contain no `eprintln` / `format_args` symbols (check `objdump --demangle -t | grep -E "eprintln|format_args|dbg_log"` — dbg_log calls must be `callq` only in cold, outside hot loop address range).
- Disassembly: `cargo asm --lib --rust "record_rx_descriptor_telemetry"` already proves telemetry helper folded with no alloc; debug outline proven similarly.
- `cargo test --bin xpf-userspace-dp poll_descriptor::debug_log_throttle` still passes (existing throttle cap tests — numeric cap enforcement, topology bypass prevention #4120).

Labels: `refactor`, `C-class`, `performance-positive`, `icache`, `debug-log`, `hot-cold`, `x-hpc`
Classification: **(C) performance-positive cleanup — zero behavioral change in release, icache improvement, source-level readablity improvement**

Dedup: new seam not in #4404. Complements #4404 inc1 (`debug_log_throttle.rs` caps).

---

#### A1a-H2 — `filter.rs` Junos-order gate coherence + `host_local.rs` consolidation

**File:** `poll_descriptor/filter.rs` (1201 LOC) + `mod.rs` L168-L410 host-local helpers.

This is not a size violation — `filter.rs` at 1201 LOC is under threshold. This is a modularity/coherence issue: `filter.rs` owns `host_inbound_gated_lo0_action` (first two Junos-order steps) while `mod.rs` owns `junos_host_local_policy` (third step) + `junos_host_policy_eval` + `FlowlessLocalVerdict`. When host-local.rs is created (Seam 2 above), `filter.rs` should keep its filter-terminal and lo0 functions but NOT own Junos order end-to-end — the canonical order lives in `host_local.rs`. `filter.rs` then becomes pure filter: input-filter eval, filter-terminal, cached-log replay, DSCP-sensitive re-eval.

**Classification:** (B) targeted — depends on host_local.rs creation. Propose as follow-up PR to A1a-H1 Seam 2.

---

### MEDIUM

#### A1a-M1 — `reject_reply.rs` TCP RST vs ICMP unreach build duplicated VLAN logical-ifindex SSOT reference

**File:** `poll_descriptor/reject_reply.rs` L167-L400.

**Observation:** `reject_reply.rs` already uses the `resolve_ingress_logical_ifindex` SSOT for VLAN (#3026) + output-filter classify on generated reply (#2238). The policy-reject path (`enqueue_policy_reject_reply`) and filter-reject path (`enqueue_filter_reject_reply`) both reimplement same 5-stage pipeline: feasibility → budget → rate-limit bucket drain → output-filter classify → TX enqueue. Internal core `enqueue_reject_reply` exists but the two wrappers duplicate budget/gate/check logic at call sites. The duplication is small (maybe ~40 LOC repeated) and the existing `reject_reply_tests.rs` 2264 LOC does NOT test the wrapper distinction — it tests only the shared core via `enqueue_filter_reject_reply`.

**Proposed:** Keep as-is (D-class negative) — the 40 LOC duplication is intentional per #2521/#3615/#3026 because policy-reject vs filter-reject have different counters (policy-deny counter vs filter reject counter) and `reject_reply_enqueued` semantics (truthful action logging). Merging them into one generic parametrized function would add a trait param or enum dispatch that would cost clarity. Classification stays (D). Only note as M1 so future refactor does not accidentally over-DRY it.

**Classification:** (D) DO-NOT-SPLIT — post-fix rationale: policy-reject vs filter-reject counter source-routing (#3615) makes two wrappers intentionally distinct; shared core `enqueue_reject_reply` is already extracted.

---

#### A1a-M2 — `flow_cache_hit.rs` 457 LOC single-fn cohesion: in-place rewrite fast path + fallback PendingForwardRequest duality

**File:** `poll_descriptor/flow_cache_hit.rs` `stage_flow_cache_hit` 457 LOC.

**Observation:** The function has TWO forwarding exit paths: (1) self-target in-place rewrite (`is_self_target && owned_packet_frame.is_none()` → `apply_rewrite_descriptor` or `rewrite_forwarded_frame_in_place` → `PreparedTxRequest` + `tx_pipeline.pending_tx_prepared.push_back`), and (2) cross-binding / failure fallback (`build_live_forward_request_from_frame` → `PendingForwardRequest` → `scratch_forwards.push`). This duality mirrors the session-hit arm in mod.rs which ALSO has in-place vs fallback duality (L~1359 onwards). The duplication is intentional (flow-cache is its own forwarding engine), but it means changes to in-place rewrite semantics must be applied in TWO places or risk divergence.

**Mitigant already present:** Both sites call `apply_rewrite_descriptor` / `rewrite_forwarded_frame_in_place` via same helpers (shared `forward_request.rs`). The cache-hit path's `CachedTxSelectionDescriptor` with queue_id/dscp is the delta.

**Proposed:** Keep as-is (D), document in file header that in-place rewrite contract is in `forward_request.rs` + `disposition.rs` SSOT and must stay sync'd between `flow_cache_hit.rs` and `poll_descriptor/mod.rs` session-hit arm. No file split.

**Classification:** (D) DO-NOT-SPLIT — 533 LOC well-extracted, duality is explicit and deliberate; further split would separate the two arms that must stay co-observed for cache/forward parity.

---

#### A1a-M3 — `poll_stages.rs` `flowless_l3_addrs` lives in stages file but belongs to flowless domain

**File:** `poll_stages.rs` L334 `flowless_l3_addrs(frame, addr_family, l3_off) -> (IpAddr, IpAddr, bool)`.

**Observation:** `flowless_l3_addrs` extracts L3 addrs from frame for flowless delivery verdict. It is used by GRE decap stage (Stage 6, `stage_native_gre_decap`) to learn inner L3 after decap + by flowless arm. Keeping it in `poll_stages.rs` couples flowless domain to stages domain. When `flowless.rs` is created (A1a-H1 Seam 1), `flowless_l3_addrs` could move there. But since GRE decap also needs it, the least-duplicative home is to duplicate as `#[inline]` in both modules or keep in `poll_stages.rs` as shared helper (current) and re-export from flowless via `pub(crate) use super::poll_stages::flowless_l3_addrs`.

**Recommendation:** Keep in `poll_stages.rs` initially (D for this PR). When flowless.rs is created, add comment: `// Shared with poll_stages::stage_native_gre_decap — do not edit without checking that path`.

**Classification:** (D) DO-NOT-SPLIT for this audit round — low impact, deferred to flowless.rs PR.

---

### LOW

#### A1a-L1 — `nat_exception.rs` 125 LOC — correctly extracted, positive example

125 LOC, `#[cold] #[inline(never)]`, two call sites inside session-miss arm only, pure timeout: code-motion of snapshot + failure recorder out of god-function. The file's `#2871` / `#3096` / `#3435` zone-gate commentary is thorough and needed. Keep as-is, use as template for how future cold extractions (flowless, host_local) should be documented. No action.

Classification: (D) positive example.

#### A1a-L2 — `debug_log_throttle.rs` 99 LOC — correctly extracted, positive example, pinned-contract pattern

Pure throttles with RED-on-revert tests. Signature takes ONLY counter so topology bypass cannot reappear. Complemented by `telemetry_debug.rs` (proposed). No action.

Classification: (D) positive example.

#### A1a-L3 — `cookie_reply.rs` 130 LOC + `cookie_reply_tests.rs` 395 LOC — correctly extracted, budget check `#[inline]` policy correct

The module's inline policy (tiny budget check `#[inline]`, heavy enqueue body `#[cold] #[inline(never)]`) is correct and documented. The `#3035` VLAN logical-ifindex SSOT comment links to `reject_reply.rs` fix. Keep. No action.

Classification: (D) positive example.

#### A1a-L4 — `rx_telemetry.rs` 220 LOC — prefetch + counter + debug probe, correct `#[inline]` not `#[inline(always)]`

The two x86_64 prefetches (96-byte meta + 64-byte frame) are the perf hotspot pre-#909. The `#[inline]` vs `#[inline(always)]` rationale in file header is correct (200 LOC with debug-log eprints would bloat L1-i if always-inlined). Keep as-is. Complementary cold outline of oversized/RST debug eprints into `telemetry_debug.rs` would further clean this file but is already documented in A1a-H1 Seam 4 extended to this file.

Classification: (D) positive example + extension point for telemetry_debug.rs.

#### A1a-L5 — Additional files discovered: `cookie_reply_tests.rs` (395 LOC) + `reject_reply_tests.rs` (2264 LOC) — test file size SKUs

`reject_reply_tests.rs` at 2264 LOC is itself over threshold BUT justified: it tests 14 distinct reject paths (budget, rate-limit, output-filter, VLAN, RST vs ICMP, policy vs filter counter, unreplyable, non-first-fragment, deny-reply zone TCP RST, etc.) each with full frame builders (TCPv4 SYN, ICMPv4 echo, VLAN drop snapshot). Splitting by reject disposition (policy vs filter vs deny) into `reject_reply_tests/{policy,filter,deny,rate_limit}.rs` would reduce per-file size but add module overhead for small test files. NOT required — test files over 2000 LOC are acceptable when they test a single feature with one fixture set.

Classification: (D) DO-NOT-SPLIT test files — single-feature cohesion, naming indicates fixture sets that would fragment.

#### A1a-L6 — `poll_stages.rs` is the positive example of Phase 1 decomposition methodology

Phase 1 (#946) methodology documented in file header + `docs/pr/946-pipeline-phase1/plan.md`: "Pure code-motion extraction of seven sub-stages, no batch reordering, no behavioral change. Each helper direct semantic equivalent of inline block." `#[inline]` on each stage so IR identical, `StageOutcome<T>` enum with RecycleAndContinue arm signaling caller to push `desc.addr` and continue, immutable `Flow` + `learn_from_live_frame` guard preserving GRE semantics. This file's approach is the template for future god-function extractions. Per previous ps-review-039 Finding 2, this file is (D). Repeated here for dedup: prior review's Finding 2 already classified poll_stages.rs as (D) — this audit AGREES, no new action.

Classification: (D) DO-NOT-SPLIT — textbook Phase 1 extraction.

---

## Cross-file coupling notes (for issue planning)

```
mod.rs (god-function)
 ├─> rx_telemetry::record_rx_descriptor_telemetry (DONE, #[inline], H3 call once per packet)
 ├─> poll_stages::stage_* (DONE, #[inline], Stages 5-11)
 ├─> flow_cache_hit::stage_flow_cache_hit (DONE, #[inline(always)], 90%+ packets Consumed continue)
 │    ├─> filter::{emit_cached_input_filter_log, emit_cached_output_filter_log} (DONE, #[inline] guard folds)
 │    └─> reject_reply::enqueue_filter_reject_reply (DONE, #[cold] path only on then reject cached flow)
 ├─> filter::evaluate_non_pbr_input_filter (DONE planned in #1327? actually #1697, #[cold], miss only)
 ├─> cookie_reply::enqueue_syn_cookie_reply (DONE, #[cold], screen challenge only)
 ├─> reject_reply::{enqueue_deny_reply, enqueue_filter_reject_reply, deny_reply_and_emit} (DONE cold)
 ├─> nat_exception::{source_nat_decision_for_flow, record_source_nat_failure} (DONE cold)
 ├─> debug_log_throttle::{session_miss, policy_deny}_debug_log_allowed (DONE pure)
 ├─┬─> (PLANNED) flowless::{flowless_local_delivery_verdict, flowless_base_resolution, ipv6_over_limit} (A, cold)
 │  └─> dependencies: filter::{host_inbound_gated_lo0_action, filter_terminal} + junos_host helpers
 ├─┬─> (PLANNED) host_local::host_local_delivery_gates (B, cold, dedup flow-backed+flowless)
 │  └─> dependencies: filter::* + junos_host_policy_eval + flowless_l3_addrs
 ├─┬─> (PLANNED) nat_pre_routing::nat_pre_routing (B, cold, pure-ish outcome struct)
 │  └─> dependencies: ForwardingState.{static_nat,nat64,nptv6}
 └─┬─> (PLANNED) telemetry_debug::{dbg_log_*} (C, cold outline, #[cold] #[inline(never)], cfg feature)
    └─> dependencies: none (eprintln only)
```

All planned moves keep new fns in `crate::afxdp::poll_descriptor::*` (same crate) → LLVM inlines cold `#[inline]` fns only on miss/flowless path; hot `#[inline(always)]` flow-cache remains unchanged.

---

## Suggested issue split (incremental PRs under #4404 umbrella)

All tests listed below must run from the isolated worktree build (`cargo test --bin xpf-userspace-dp` inside `/tmp/review-wt-ps-043-a1a-b1`), plus the cluster smoke gates which need outside incus but are required before merge per `docs/engineering-style.md` "Workflow for every change" §8.

### PR A1a-1 — Flowless mechanical extraction (A-class, smallest risk)

**Title:** `refactor(afxdp): extract flowless path to poll_descriptor/flowless.rs — A-class code-motion (#4404 inc N)`

**Files touched:** New `poll_descriptor/flowless.rs` (~450-550 LOC prod + ~300 tests), `poll_descriptor/mod.rs` (add `mod flowless; use flowless::*;`, replace flowless arm inline block with call to `flowless::{verdict, base_resolution, over_limit}`), `poll_stages.rs` (no change, or re-export `flowless_l3_addrs` comment).

**Steps:**
1. Create `poll_descriptor/flowless.rs` moving `FlowlessLocalVerdict` + `flowless_local_delivery_verdict` + `flowless_base_resolution` + `ipv6_ext_header_over_limit_drop` + `FlowlessLocalVerdict` enum + any `FlowlessBaseResolution` struct + `flowless_local_delivery_tests` verbatim.
2. Add `mod flowless;` in `poll_descriptor/mod.rs` top.
3. Verify `cargo test --bin xpf-userspace-dp poll_descriptor::flowless` 5 tests pass.
4. Disassembly diff: `cargo asm --bin xpf-userspace-dp --lib --rust afxdp::poll_descriptor::poll_binding_process_descriptor --no-color | head -n 200` hot loop identical — no `callq flowless::*` in hot header.
5. `cargo test --bin xpf-userspace-dp tests_fragment` — fragment push-through (non-first fragment drop).
6. Full gate: `cargo test --bin xpf-userspace-dp` + `make cluster-deploy` + `./test/incus/apply-cos-config.sh loss:xpf-userspace-fw0` + `iperf3 -P 16 -t 30 -p 5203 --client 172.16.80.200` ≥23 Gbit/s + `make test-failover` 0/low loss.

**Acceptance criteria:** `poll_descriptor/mod.rs` LOC -~500 (god-function -~300), disassembly hot loop identical, flowless tests green, failover smoke zero regression.

**Labels:** `refactor`, `A-class`, `code-motion`, `flowless`, `single-recycle`, `x-hpc`, `size:6294`

---

### PR A1a-2 — Host-local Junos-order dedup (B-class)

**Title:** `refactor(afxdp): canonicalize host-local Junos order in poll_descriptor/host_local.rs (#4404 inc N+1)`

**Depends on:** A1a-1 (flowless.rs exists so host_local can depend on flowless verdict).

**Files:** New `poll_descriptor/host_local.rs` (~350-450 LOC + tests), `poll_descriptor/mod.rs` (replace two Junos-order blocks with `host_local::host_local_delivery_gates()`), `poll_descriptor/filter.rs` (import only, or move `host_inbound_gated_lo0_action`/`filter_terminal` reference).

**Acceptance:** `flowless_local_delivery_tests` + `lo0_gate_tests` still green; `cargo test tests_fragment`; `make test-failover` + `make test-ha-crash` (management path); disassembly cold-path only.

**Labels:** `refactor`, `B-class`, `junos-order`, `dedup`, `flowless`, `x-hpc`, `size:6294`

---

### PR A1a-3 — NAT pre-routing struct outcome (B-class, new tri-state tests)

**Title:** `refactor(afxdp): extract NAT pre-routing to poll_descriptor/nat_pre_routing.rs (#4404 inc N+2)`

**New file:** `poll_descriptor/nat_pre_routing.rs` with `NatPreRoutingOutcome` struct + `nat_pre_routing()` pure-ish function + `nat_pre_routing_tests.rs` (DNAT, static-DNAT, NPTv6, NAT64 tri-state NoPrefix/Match/MatchUnavailable fail-closed #2291).

**Acceptance:** `cargo test nat_pre_routing` + `cargo test tests_policy_inbound_nat`; `make test-failover` (NAT common in prod — no path coverage but gate proves no regression).

**Labels:** `refactor`, `B-class`, `nat`, `nat64`, `dnat`, `nptv6`, `fail-closed`

---

### PR A1a-4 — Debug-log cold outline (C-class, performance-positive)

**Title:** `refactor(afxdp): cold-outline debug-log eprintln bodies to telemetry_debug.rs — icache (#4404 inc N+3)`

**New file:** `poll_descriptor/telemetry_debug.rs` with `#[cold] #[inline(never)] cfg(feature="debug-log")` wrappers for WAN_RETURN_HIT, SESS_MISS, RST_DETECT etc.

**Acceptance:** `cargo test --bin xpf-userspace-dp --features debug-log` green; release `nm` — hot fn contains no eprintln/format_args; disassembly hot loop identical in release (cfg false eliminates entire if).

**Labels:** `refactor`, `C-class`, `performance-positive`, `icache`, `debug-log`, `hot-cold`, `x-hpc`

---

### How to prove hot-path unchanged (all PRs)

1. **Disassembly diff:** `cargo asm --bin xpf-userspace-dp afxdp::poll_descriptor::poll_binding_process_descriptor > /tmp/before.s` before and after; diff first 2KB (hot loop). Must be byte-identical. Use `cargo rustc -- --emit asm` with `--no-color` for stable output.
2. **Unit tests:** `cargo test --bin xpf-userspace-dp poll_descriptor` (flowless, debug_log_throttle, lo0 gate, cookie_reply, reject_reply tests).
3. **Fragment gate:** `cargo test --bin xpf-userspace-dp tests_fragment` — non-first fragment drop is only path that exercises flowless arm in unit tests.
4. **Smoke gates:** `make cluster-deploy` (loss userspace cluster) + `./test/incus/apply-cos-config.sh loss:xpf-userspace-fw0` + `iperf3 -P 16 -t 30 -p 5203 --client 172.16.80.200` ≥23 Gbit/s — failover + CoS smoke both prove hot-path no-regression (failover uses flow-cache hit path for session continuity, CoS uses filter counters).
5. **Full suite:** `make test` (Go + Rust). Rust leg (`make test-rust`) minutes.
6. **Failover tests:** `make test-failover` + `make test-ha-crash` (both need loss cluster lock — via `test/incus/with-cluster.sh "reason" -- cmd...`, per CLAUDE.md #1875).

---

## Summary

**Headline:** `poll_descriptor/mod.rs` 6294 LOC (prod~4152, god-function 4796 LOC — up from 5759→6294 since #4404 filed, 1368→4796 god-function) fuses 15+ responsibilities in `poll_binding_process_descriptor` with 38 recycle push sites + 17 debug-log cfg gates + 24 mutable-locals coupling blocking further split. But Phase 1-3 decompositions (#946 poll_stages 975 LOC, #1327 flow_cache_hit 533 LOC + rx_telemetry 220 LOC, #1697 cookie_reply 130, reject_reply 446, filter 1201, nat_exception 125, #4404 inc1 debug_log_throttle 99) are all **textbook (D) positive examples** — correctly extracted with `#[inline]` guards + `#[cold] #[inline(never)]` tails, dependency-free or explicit-args, testable, IR-identical per cargo asm. Remaining cold seams (flowless 400 LOC, host-local Junos-order dedup, NAT pre-routing 210 LOC, telemetry-debug icache outline) can be split as A/B/C classes WITHOUT changing one instruction of the 90%+ flow-cache hit hot path, with disassembly diff + failover/CoS gates. Propose 4 incremental PRs under #4404 umbrella. The flowless + host-local seams cure a real bug attractor: Junos-order duplication across flow-backed and flowless local-delivery (fix #3292 was needed precisely because flowless missed the junos-host gate).

**Files reviewed (worktree-verified):** 9 batch files all exist at `/tmp/review-wt-ps-043-a1a-b1/userspace-dp/src/afxdp/p...`
**Largest findings:** A1a-H1 (4 seams inside mod.rs — 1 A, 2 B, 1 C), A1a-H2 (filter.rs Junos-order coherence — B dependent), M1-M3 (D negatives: reject_reply, flow_cache_hit, flowless_l3_addrs — intentionally coupled, keep), L1-L6 (D positives: nat_exception, debug_log_throttle, cookie_reply, rx_telemetry, test files, poll_stages — textbook extractions).
**Dedup:** #4404 already filed god-function; this audit increments with new seams (flowless mechanical, host-local dedup, nat pre-routing struct, telemetry cold outline) + hot-path preservation annex (disassembly, single-recycle pinning, branch/icache). #4421, #4408 out of batch scope — not re-filed.



---
### Batch ps-a1b-b1.md — 30314 chars

# A1b — TX Path (tx/dispatch + cos_classify + tcp_segmentation + rings + transmit + drain + shared recycle) — Refactor/Modularity Audit

**Base SHA:** `4e0c7f74cf0dbacf83051b2a9b6cf4e050dcecaa`
**Worktree:** `/tmp/review-wt-ps-043-a1b-b1`
**Auditor:** ps, NNN: 043
**Date:** 2026-07-11
**Scope:** `userspace-dp/src/afxdp/tx/{dispatch/mod.rs, dispatch/cos.rs, dispatch/shared_recycle.rs, dispatch/slow_path.rs, cos_classify.rs, tcp_segmentation.rs, rings.rs, mod.rs, drain/mod.rs + phase_backup/shaped/trivial, transmit/*.rs}`

---

## Inventory

| File | LOC | Role | Hot-Path? |
|------|-----|------|-----------|
| `tx/dispatch/mod.rs` | 1505 | TX drain orchestrator — `enqueue_pending_forwards` 1048 LOC god-function (Phase 8 + direct-TX + fabric scatter + PTB-ingress) | **YES** — per-packet zero-copy, single-free |
| `tx/dispatch/cos.rs` | 143 | CoS fast-path lookup + owner/ shared_exact routing | YES — per-request |
| `tx/dispatch/shared_recycle.rs` | 207 | Phase 10 + cross-tick slot-routed fill recycle | NO — cross-tick boundary, infrequent |
| `tx/dispatch/slow_path.rs` | 400 | Build-failure + slow-path reinject, L3 extract | NO — #[cold] #[inline(never)] |
| `tx/cos_classify.rs` | 1335 | 7 responsibilities (see finding) | YES — session-miss + hit BA reclass |
| `tx/tcp_segmentation.rs` | 309 | Prepared-enqueue MTU segmenter (admission + build loop) | COLD-tagged, oversize only |
| `tx/rings.rs` | 415 | XSK rings: reap, fill submit, RX/TX wake, recycle | YES — reap/completion hot |
| `tx/drain/mod.rs` | 594 | Per-tick drain dispatch + CoS-bound leftover defense | YES — per-tick |
| `tx/drain/phase_trivial.rs` | ~73 | reap, rekick, ingest, submit_and_wake | YES — thin wrappers |
| `tx/drain/phase_shaped.rs` | 152 | shaped CoS service + bounded re-ingest budget | YES |
| `tx/drain/phase_backup.rs` | 207 | post-CoS backup: prepared+local transmit_batch | YES |
| `tx/transmit/mod.rs` | 365 | TX submit orchestrator + recycle helpers | YES |
| `tx/transmit/stage.rs` | 64 | Phase 1: stage prepared batch into scratch | YES |
| `tx/transmit/rewrite.rs` | 63 | Phase 2: per-frame DSCP rewrite | YES |
| `tx/transmit/verify.rs` | 58 | Phase 3: UMEM slice re-verify | YES |
| `tx/transmit/write.rs` | 60 | Phase 4: reserve+write+commit+stamp | YES |
| `tx/transmit/finalise.rs` | 56 | Phase 5: accounting/recovery/kick | YES |
| `tx/stats.rs` | 170 | submit-stamp sidecar + kick latency hist | YES — atomic add only |
| `tx/mod.rs` | 56 | re-export hub | NO |
| `frame/tcp_segmentation.rs` (ref) | ~1100 | Copy-path TCP segmentation (not in scope but adjacent) | COLD |

**Total tx/ at this base:** ~4824 LOC excluding tests. Drain + transmit phases already split textbook since #1354/#1355. Dispatch still god.

**Zero-copy invariant:** All forward paths (in-place FillOnSlot, direct prepared FreeTxFrame, copy local Vec→UMEM) must leave UMEM offset owned exactly once until CQ reap. Any new helper must not introduce early recycle double-free.

---

## Log

- **Timestamp:** 2026-07-11
- **Action:** read dispatch/mod.rs — god-function boundaries mapped
- **File(s):** `/tmp/review-wt-ps-043-a1b-b1/userspace-dp/src/afxdp/tx/dispatch/mod.rs`

- **Timestamp:** 2026-07-11
- **Action:** read cos_classify.rs — 7 responsibilities de-duplicated
- **File(s):** `.../tx/cos_classify.rs`

- **Timestamp:** 2026-07-11
- **Action:** read drain phases + transmit phases + rings — confirmed textbook splits
- **File(s):** `.../tx/drain/*.rs`, `.../tx/transmit/*.rs`, `.../tx/rings.rs`, `.../tx/stats.rs`

- **Timestamp:** 2026-07-11
- **Action:** measure LOC + locate fabric / direct-TX / PTB seams via grep
- **File(s):** `.../tx/tcp_segmentation.rs`, `.../tx/dispatch/*.rs`

---

## Findings by Severity + D-Negatives

### HIGH

#### H1 — `dispatch/mod.rs` enqueue_pending_forwards god-function — Phase 8 (try_inplace_rewrite_or_build) + direct-TX + fabric scatter + PTB finalizer still inline

- **Severity:** High
- **Confidence:** High (directly measured 1048 LOC single function, 15 branches, 4 zero-copy invariants)
- **Refactor class:** B — requires guardrails (per-packet hot path, single-free UMEM invariant)
- **Dedup note:** Prior #4408 filed for 1131 LOC god-function. This adds breakdown: Phase 8 (inplace 336-365) + direct-TX 317 LOC + fabric scatter (prebuilt 336-425 desc no-binding 456-483) + PTB-ingress finalizer 58 LOC still interleaved. Increment 1 of #4408 (compute_forwarded_egress_ptb) already landed, but finalizer stays.

**Evidence:**
- `dispatch/mod.rs:290-1338` — 1048 LOC single `pub(in crate::afxdp) fn enqueue_pending_forwards`, cyclomatic ~35
- `dispatch/mod.rs:346-425` prebuilt fast path with fabric_fail counter:
  ```rust
  if let PendingForwardFrame::Prebuilt(prebuilt) = &mut request.frame {
      let prebuilt_is_fabric_redirect = request.decision.resolution.disposition
          == ForwardingDisposition::FabricRedirect;
      let Some(target_binding) = resolve_pending_forward_target_binding(...) else {
          if prebuilt_is_fabric_redirect {
              ingress_live.fabric_redirect_unsendable_drops.fetch_add(1, ...);
  ```
- `dispatch/mod.rs:463-524` fabric no-binding desc path drops fail-closed, slow_path reinject split
- `dispatch/mod.rs:704-902` in-place rewrite path `can_rewrite_in_place` (zero-copy FillOnSlot)
- `dispatch/mod.rs:904-1080` direct-TX build-into-free-frame:
  ```rust
  let mut direct_tx_offset = target_binding.tx_pipeline.free_tx_frames.pop_front();
  ...
  let written = unsafe { target_area.slice_mut_unchecked(tx_offset as usize, tx_frame_capacity()) }
      .and_then(|out| build_forwarded_frame_into_from_frame(...));
  ```
- `dispatch/mod.rs:1245-1303` PTB late enqueue onto `ingress_binding` remains after `compute_forwarded_egress_ptb` extracted

**Proposed decomposition (incremental, behavior-identical):**

New module layout under `tx/dispatch/`:

- `fabric.rs` — `#[inline] fn handle_prebuilt_forward(...) -> Result<(), FabricDrop>` + `#[inline] fn handle_no_binding(...) -> Option<SlowPathAction>` — extracts both scatter sites (prebuilt 336-425, desc no-binding 456-483). Pure code-motion. Shared `fabric_redirect_unsendable_drops` + `record_exception` stays cold.
- `ptb_ingress.rs` — `#[inline] fn finalize_egress_mtu_ptb(ingress_binding: &mut BindingWorker, ptb_bytes: Option<Vec<u8>>, ...)` — moves 1245-1303 finalizer out. Already has compute phase extracted inc1; this is inc2 finalizer pairing.
- `build_phases.rs`:
  - `#[inline(always)] fn try_inplace_rewrite(...) -> Option<InplaceOutcome>` — 724-900
  - `#[inline] fn try_direct_tx(...) -> DirectTxOutcome { Built, NoFrame, BuildNone, Mismatch, Oversize }` — 904-1080
  - `#[inline] fn fallback_copy_path(...) -> CopyOutcome` — 1080-1220
  - Enum dispatch to avoid dynamic dispatch: `enum ForwardBuildResult { Inplace, Direct, CopyLocal, Failed }`
- Top-level `enqueue_pending_forwards` becomes driver loop:
  ```
  for req in pending_forwards.iter_mut() {
      handle_prebuilt -> continue
      resolve target_binding + mirror
      if no_binding { handle_no_binding -> continue }
      if tcp_seg_needed { try_seg -> maybe continue }
      compute_forwarded_egress_ptb -> maybe skip builds
      match build_phases::try_build(...) { ... }
      finalize ptb + failure + recycles
  }
  ```

**Hot-path preservation analysis:**

- **Inlining:** All new helpers same crate, `#[inline]` (or `#[inline(always)]` for <50 LOC). Confirm via `cargo asm --lib afxdp::tx::dispatch::enqueue_pending_forwards` or `objdump -d` — before/after disassembly diff must be identical instruction stream in hot branch (single-free push/pop). Same crate allows cross-module inlining free.
- **No alloc:** Helpers take `&mut BindingWorker` + `&[u8]` slice, return offsets/lens, never allocate. Copy fallback allocates Vec — unchanged from before.
- **No dynamic dispatch:** enum + match (`DirectTxOutcome`, `FabricDrop`) not Box<dyn>.
- **Const/mono preserved:** No generic bloat; `build_forwarded_frame_into_from_frame` stays monomorphized once.
- **Zero-copy/UMEM single-free:** Helpers return ownership token (`tx_offset`) moved, not duplicated. The `if build_failed { free_frames.push_front }` single-free site must stay single. Propose regression test `direct_tx_tuple_mismatch_recycles_frame_exactly_once` already guards double-free (#4041) — new helpers must keep that test green.
- **Endianness locality:** IP/TCP field updates remain in `frame/` builders, not touched.
- **Branch/icache:** Hot inner loop (no CoS) stays < few KB. Cold paths (`record_exception`, `fabric_redirect_unsendable_drops`, PTB build) call out-of-line `#[cold] #[inline(never)]` already in `slow_path.rs`. Prevent icache bloat by not inlining cold exception logging.

**Verification:**
- `cargo asm`: diff prior/submission `enqueue_pending_forwards` — expected zero diff in hot blocks, only call out-of-line cold blocks moved.
- `perf stat -e instructions:u,cycles:u,branch-misses` on 10G iperf3 synthetic forward bench — <1% delta.
- `make test` passes (includes Rust leg #4006).
- CoS smoke: `cos-iperf-config.set` any 4-class capped, verify no `post_drain_backup_bytes` regression.
- Fairness gate: `-P 12` against 1 Gbps cap, no bimodal flow (owner vs peer).

**Tests+gate:**
- Existing `dispatch/tests/{cos_shared_exact,enqueue_failure,ptb,segmentation,shared_recycle}.rs`
- New: `dispatch/tests/build_phases.rs` — mock BindingWorker with 2 free frames, exercise Inplace, Direct, Copy, FailClosed fabric.
- Gate: `cargo test -p xdp --lib tx::dispatch` + `make test-rust -- --nocapture tx::dispatch`

**Why it matters:** God-function hides single-free invariant behind 5 nested ifs. Future NAT64/Tunnel path changes risk double-recycle. Splitting cold fabric+PTB out shrinks icache and makes CoS guarantee guard reviewable.

**Fix direction PRs:**
- PR1 (mechanical): extract `fabric.rs` + `ptb_ingress.rs` (cold, no hot-path instruction change).
- PR2: extract `build_phases.rs` with enum outcomes, disasm diff gate.
- PR3: introduce `struct DispatchCtx` carrying `&mut BindingWorker` slices to reduce split-borrow gymnastics, retain driver loop <300 LOC.

**Labels:** `refactor`, `tx-drain`, `hot-path`, `CoS`, `HFT-guard`, `single-free`, `needs-asm-diff`, `#4408`

---

#### H2 — `cos_classify.rs` 1335 LOC 7 responsibilities in one file — TX-selection + BA reclassify + LP rewrite + enqueue prepared + enqueue local + demote + admission

- **Severity:** High
- **Confidence:** High (function grep confirms 7 distinct public APIs)
- **Refactor class:** B — mixed hot (admission, selection) + cold (demote)
- **Dedup note:** None filed. Prior dispatch split #1443 didn't touch this.

**Evidence:**
- `cos_classify.rs:101-330` `resolve_cached_cos_tx_selection` — cached fast path, BA flag, filter tx-selection eval, loss-priority rewrite:
  ```rust
  let ba_reclassify = fc_queue.is_none()
      && iface.is_some_and(|iface| {
          !iface.dscp_classifier.is_empty() || !iface.ieee8021_classifier.is_empty()
      });
  ```
- `cos_classify.rs:342-360` `reclassify_cached_ba_queue` — hit-path 5 lines + FastMap lookup
- `cos_classify.rs:404-689` `resolve_cos_tx_selection_internal` — 285 LOC runtime counted path, dup logic of cached variant, output filter + ingress filter + BA + LP
- `cos_classify.rs:695-758` LP rewrite helpers `resolve_cos_loss_priority`, `resolve_cos_queue_lp_rewrite`, dscp/ieee classifiers
- `cos_classify.rs:759-874` `enqueue_local_into_cos` — prepare to prepared fallback, demote call
- `cos_classify.rs:899-959` `enqueue_prepared_into_cos` — redirect prepared to owner vs local clone path
- `cos_classify.rs:1006-1122` `demote_prepared_cos_queue_to_local` — MQFQ frontier snapshot/restore (#926) + 64KB stack memcpy
- `cos_classify.rs:1157-1331` `enqueue_cos_item` — 175 LOC admission alone: `flow_bucket`, `buffer_limit`, `flow_share_exceeded`, `buffer_exceeded`, `apply_cos_admission_ecn_policy`, overflow drop:
  ```rust
  let buffer_limit = cos_flow_aware_buffer_limit(queue, flow_bucket);
  let flow_share_exceeded = if queue.flow_fair() {
      ...
  }
  let buffer_exceeded = queue.hot.queued_bytes.saturating_add(item_len) > buffer_limit;
  ```

**Proposed decomposition:**

Turn `cos_classify.rs` into module dir `cos_classify/`:

- `mod.rs` hub re-exports same symbols.
- `selection.rs` — `resolve_cached_cos_tx_selection`, `resolve_cos_tx_selection`, `resolve_cos_tx_selection_at`, `resolve_cos_tx_selection_internal`, `resolve_cos_queue_id`, `map_cached_forwarding_class_queue`
- `ba.rs` — `reclassify_cached_ba_queue` + unit tests
- `lp_rewrite.rs` — `resolve_cos_loss_priority`, `resolve_cos_queue_lp_rewrite`, `resolve_cos_dscp_classifier_queue_id`, `resolve_cos_ieee8021_classifier_queue_id`, `cos_queue_dscp_rewrite`
- `enqueue.rs` — `enqueue_local_into_cos`, `enqueue_prepared_into_cos`, `enqueue_cos_item`, `prepare_local_request_for_cos`, `clone_prepared_request_for_cos`, `resolve_cos_queue_idx` (admission core)
- `demote.rs` — `demote_prepared_cos_queue_to_local`, `cos_queue_accepts_prepared` — cold, 64KB memcpy needs comment preservation
- `reply.rs` — `classify_generated_reply`, `GeneratedReplyVerdict`
- Keep tests in `cos_classify_tests.rs` imported via `#[cfg(test)]`

Seam by responsibility: selection (pure fn ForwardingState+meta → queue id) vs enqueue (mutates BindingWorker queues) vs demote (exceptional recovery).

**Hot-path preservation analysis:**

- **Hot:** `reclassify_cached_ba_queue` hit-path — must stay `#[inline]` + same crate. It's single FastMap get + array read — inlining critical; after move, mark `#[inline(always)]` and verify via `cargo asm` that session-hit path still inlines (no callq).
- `enqueue_cos_item` is hottest under shaping — includes `cos_flow_aware_buffer_limit` + ECN mark. Enqueue splitting must NOT allocate (uses `CoSPendingTxItem` enum stack). Proposed split keeps function body identical, only file move — disasm diff zero.
- **No alloc:** demote path uses `VecDeque` drain — already allocates `VecDeque::with_capacity` for recycles; remains cold (TX frame exhaustion). Ensure no new String alloc on hot drop — existing comment #hb166 T-6(g) prohibits `set_error(format!())`; keep dedicated counters only.
- **Demote cold:** `demote_prepared_cos_queue_to_local` marked `#[cold]` is NOT currently — should be `#[cold]` + `#[inline(never)]`? But it's called from `enqueue_local_into_cos` only when `free_tx_frames` empty + exact queue. The MQFQ snapshot is 64KB stack memcpy — should stay out-of-line to avoid blowing stack in hot path; propose keep as is but note need out-of-line classification as C (performance-positive) — moving to separate file improves icache because it contains 100+ LOC including snapshot comment that bloats L1i.

**Verification:**
- disasm diff: `enqueue_local_into_cos` before/after — identical aside from file path DWARF.
- `make test` — `cargo test cos_classify` pins BA reclassify correctness.
- CoS smoke + fairness gate identical to H1.

**Tests+gate:** existing `cos_classify_tests.rs` (flow-aware limits, BA, LP rewrite, demote frontier). After split, `mod.rs` `#[cfg(test)] mod tests` keeps same file.

**Why it matters:** 7 responsibilities violate single-responsibility. Admission (ECN + buffer + flow_share) mixed with selection (filter + BA) hides bug where flow_share gate counts vs buffer gate counts swapped (previous #710). Split makes audit of admission-only changes safe without touching selection.

**Fix direction:** 3 incremental PRs:
- PR1: `reply.rs` + `ba.rs` + `lp_rewrite.rs` mechanical moves (no hot path).
- PR2: split `selection.rs` vs `enqueue.rs` (guarded — needs asm diff).
- PR3: extract `demote.rs` and mark `#[cold]` (measure stack + icache).

**Labels:** `refactor`, `CoS`, `queueing`, `hot-path`, `BA-classifier`, `LP-rewrite`, `needs-asm-diff`

---

### MEDIUM

#### M1 — `tx/tcp_segmentation.rs` 309 LOC admission + cold build loop together; duplicate with `frame/tcp_segmentation.rs`

- **Severity:** Medium
- **Confidence:** High (file at base 309 not 995; prior #4652 claimed 933 LOC but that was `frame/` file)
- **Refactor class:** A — mechanical safe cold path
- **Dedup note:** #4652 filed for `frame/tcp_segmentation.rs` 933 LOC (the copy-path segmenter). This finding is for `tx/tcp_segmentation.rs` prepared-enqueue path — distinct but similar pattern, dedup partially overlaps.

**Evidence:**
- `tcp_segmentation.rs:4-98` admission: MTU derive, L3/L4 offset parse, SYN/FIN/RST gate, free frame check:
  ```rust
  if meta.protocol != PROTO_TCP || decision.resolution.tunnel_endpoint_id != 0 {
      return None;
  }
  let mtu = forwarding.egress.get(...).map(|eg| eg.mtu).unwrap_or_default().max(1280);
  ...
  if tcp_flags & (TCP_FLAG_SYN | TCP_FLAG_FIN | TCP_FLAG_RST) != 0 {
      return None;
  }
  if target_binding.tx_pipeline.free_tx_frames.len() < segment_count { return None; }
  ```
- `tcp_segmentation.rs:130-309` cold build loop (capacity check, slice_mut_unchecked, TTL/hop-limit, NAT, checksum):
  ```rust
  while data_offset < data.len() {
      let chunk_len = (data.len() - data_offset).min(segment_payload_max);
      ...
      let Some(frame_out) = (unsafe { target_binding.umem.area().slice_mut_unchecked(...) }) else {
  ```
  Build loop does 4 fallible slices + endian swaps per segment; tagged `#[cold]` at fn level but inner loop hot-ish per oversize.

**Proposed decomposition:**

- Keep file but split into submodule `tx/tcp_segmentation/`:
  - `admission.rs` — `#[inline] fn should_segment(...) -> Option<SegmentationParams { mtu, segment_payload_max, tcp_header, ip_header, seq }>` pure early exits.
  - `builder.rs` — `#[cold] fn build_segments_into_prepared(...) -> Option<(count, bytes, max)>` — moves 130-309 loop.
  - `mod.rs` glue: admission check, free-frame drain if short, then builder, then pushback + `bound_pending_tx_prepared`.

Seam: admission pure vs builder mutates target_binding.

**Hot-path preservation analysis:**

- Function already `#[cold]` — not on per-packet fast path (~no oversize at line rate). Therefore inlining not critical; focus on single-free safety: builder allocates `Vec<PreparedTxRequest>` with capacity segment_count — introduces heap alloc on cold path (existing). Proposed alternative: reuse `binding.scratch.scratch_prepared_tx` instead of Vec alloc to reduce cold alloc, but that's performance-positive optional.
- **Guardrails:** Zero-copy/UMEM single-free preserved: builder must recycle on early None exactly once (existing `for req in prepared.drain(..).rev()` push_front). New builder must keep that unwind symmetric.
- No new dispatch, keep slice_mut_unchecked locality.

**Tests+gate:** `dispatch/tests/segmentation.rs` — oversize frame → N segments, checksum valid, fabric flag TTL gate. Also `frame/tests_segment_tcp.rs` adjacent.

**Why it matters:** Admission logic (~95 LOC) reused conceptually in `frame/tcp_segmentation.rs` `may_need_segmentation` but duplicated MTU lookup. Splitting clarifies NAT64 vs tunnel gate (proto check + tunnel_endpoint_id check) which has been source of bugs (#1852 non-first-frag, #2077 fabric TTL).

**Fix direction:** PR1 extract admission helper `fn segmentation_params(frame, meta, decision, forwarding) -> Option<Params>` mechanical; PR2 if desired replace Vec alloc with scratch reuse (bench).

**Labels:** `refactor`, `cold-path`, `TCP-segmentation`, `MTU`, `admission-gate`

---

#### M2 — `dispatch/dispatch/tests` + `tx/dispatch/tests` 1564 LOC test-only split viable

- **Severity:** Medium (code health, not perf)
- **Confidence:** High
- **Refactor class:** A — mechanical test-only
- **Dedup note:** #4670 already filed for `dispatch_tests.rs` 1564 LOC test-only split — production NOT split. This confirms duplication.

**Evidence:** Under `dispatch/tests/` 6 files: `cos_shared_exact.rs`, `enqueue_failure.rs`, `mod.rs`, `ptb.rs`, `segmentation.rs`, `shared_recycle.rs` — total >1000 LOC test harness constructing BindingWorker + forwarding fakes.

**Proposed decomposition:** Already partially split in this worktree (6 files) — seems good. Only note: `tests/mod.rs` glues via `use super::*` and thread-locals `FORCE_OVERSIZED`, `FORCE_TUPLE_MISMATCH`, `FORCE_ENQUEUE_ERR`. These fault-injection thread-locals should live in `tests/fault_injection.rs` dedicated to avoid mixing with cos logic.

**Hot-path:** None — `#[cfg(test)]` DCEs out of release builds, guarded by `cfg!(test)` attribute.

**Tests+gate:** `cargo test tx::dispatch::tests`

**Labels:** `tests`, `mechanical`, `#4670`

---

#### M3 — `rings.rs` 415 LOC multiple ring disciplines co-located: reap completions, drain fill, RX wake, TX wake, prepared recycle routing

- **Severity:** Medium (minor readability)
- **Confidence:** Medium
- **Refactor class:** D is also arguable — genuinely cohesive? No — ring ops are distinct but share BindingWorker, so C/D borderline. Here Low-Med split viable.

**Evidence:**
- `rings.rs:20-71` `reap_tx_completions` 50 LOC — completion ring_available → drain → stamp → recycle.
- `rings.rs:93-152` `drain_pending_fill` 60 LOC — poison + fill ring commit + needs_wakeup gate.
- `rings.rs:154-202` `maybe_wake_rx` 48 LOC — poll(POLLIN) vs sendto
- `rings.rs:237-334` `maybe_wake_tx` 97 LOC — sendto + kick latency telemetry + eagain/enobufs handling
- `rings.rs:220-235` `recycle_completed_tx_offset` + `apply_prepared_recycle` small helpers.

**Proposed decomposition (optional, performance-positive):**

- Split `rings.rs` → `rings/` module:
  - `completion.rs` — reap + record_completion_ring_available
  - `fill.rs` — drain_pending_fill + fill scratch + poison debug-log block (cold)
  - `wake.rs` — maybe_wake_rx + maybe_wake_tx (separate: rx wake uses poll, tx wake uses sendto+latency hist)
  - `recycle.rs` — apply_prepared_recycle + recycle_completed_tx_offset

Seam: completion vs fill vs wake are distinct kernel interfaces (completion ring, fill ring, XDP_WAKEUP_RX/TX). Current file comment already says "XSK kernel-ring discipline" plural.

**Hot-path preservation:**

- `reap_tx_completions` hot per-tick — must stay `#[inline]`? Currently not inlined but called from drain phase trivial: `drain_phase_reap_completions` already `#[inline]`. Splitting into submodule keeps same crate inlining.
- `maybe_wake_tx` contains two `monotonic_nanos()` + atomic hist adds — keep `#[inline(never)]` potential? It's on hot wake path only when zerocopy ring needs wakeup or interval expired — not ultra hot, but latency matters (~30ns VDSO). No perf regression expected if moved to `wake.rs` same crate.
- **Verification:** perf stat on idle tick (empty_rx_polls) and saturated TX— wakeups/sec unchanged.
- Zero-copy single-free: recycle helper refactoring must preserve FillOnSlot vs FreeTxFrame branch—already has unit test `apply_prepared_recycle_routes_fill_and_free_explicitly`.

**Why it matters:** `maybe_wake_tx` currently contains verbose sentinel guards + eprintln for TX_ENOBUFS first 10 — cold diagnostic code interleaved with hot sendto. Outlining prints to cold helper (similar to slow_path pattern) improves icache.

**Fix direction:** PR1: extract wake helpers + make `log_tx_enobufs_throttled` `#[cold] #[inline(never)]`. PR2 optional module split if team wants.

**Labels:** `refactor`, `rings`, `XSK`, `icache`, `perf-positive`

---

### LOW

#### L1 — `transmit/mod.rs` 365 LOC orchestrator + batch transmit logic: could still outline cold debug RST detection further

- **Severity:** Low
- **Confidence:** High
- **Refactor class:** D — do-not-split (already textbook 6-phase)

**Evidence:** `transmit/mod.rs:271-309` `transmit_prepared_queue` docs reference 6-phase textbook, body:
```rust
stage::stage_batch_into_scratch(binding, pending, shared_recycles)?;
if binding.scratch.scratch_prepared_tx.is_empty() { return Ok((0,0)); }
rewrite::apply_dscp_rewrites_to_staged(binding, shared_recycles)?;
verify::verify_umem_slices_for_staged(binding, shared_recycles)?;
if cfg!(feature = "debug-log") { log_rst_frames_prepared(binding); }
let inserted = write::reserve_and_write_descriptors(binding);
finalise::finalise_prepared(binding, pending, now_ns, inserted)
```

**D-negative reasoning:** This IS textbook split #1354. 6 phases each 50-70 LOC, correct Drop semantics pinned. `transmit_batch` in same file (local copy path) also distinct but shares `recycle_cancelled_prepared_offset_with_shared`. No further split needed; RST debug detection already outlined to `log_rst_frames_prepared` helper `#[inline]`. Any further split would push hot inner loop behind dynamic dispatch.

**Labels:** `D-negative`, `textbook-split`, `do-not-split`

---

#### L2 — `stats.rs` 170 LOC — submit-stamp + kick latency + completion latency batching — small, cohesive, correct non-atomic discipline

- **Severity:** Low
- **Confidence:** High
- **Refactor class:** D — genuinely cohesive, zero alloc, inline bucket calc

**Evidence:** `stats.rs:44-91` `stamp_submits` — slice-indexed store, shared_umem OOB guard via `get_mut`:
```rust
if let Some(slot) = sidecar.get_mut(idx) { *slot = ts_submit; }
```

**D-negative:** Two functions + one pure fold — ideal size. Splitting would separate logically paired stamp/completion. The early-return on `ts_submit==0` clock-failure gate should NOT be spread.

**Labels:** `D-negative`

---

#### L3 — `drain` phases: already 4 files, orchestrator thin — textbook, do-not-split further

- **Severity:** Low
- **Confidence:** High
- **Refactor class:** D

**Evidence:** `drain/mod.rs:85-119` orchestrator 34 LOC:
```rust
let mut did_work = drain_phase_reap_completions(binding, shared_recycles);
drain_phase_maybe_rekick(binding, &ctx);
drain_phase_ingest_cos(binding, &ctx, shared_recycles);
drain_phase_drain_cos(binding, &ctx, shared_recycles, &mut did_work);
match drain_phase_drain_local_backup(binding, &ctx, shared_recycles, &mut did_work) { ... }
drain_phase_submit_and_wake(binding, did_work)
```

Each phase 50-150 LOC, `#[inline]` wrappers, `BackupOutcome` enum preserves `update_binding_debug_state` distinction (yes/no) exactly. Splitting further would fragment `ingest_cos_pending_tx_with_provenance` provenance accounting (#709 owner_pps/peer_pps).

**Labels:** `D-negative`, `drain`, `CoS`

---

#### L4 — `dispatch/cos.rs`, `shared_recycle.rs`, `slow_path.rs` already split #1443 — textbook, do-not-split further

- **Severity:** Low
- **Confidence:** High
- **Refactor class:** D

**Evidence:** Header comment in `dispatch/mod.rs:1-29` documents #1443 split retained orchestrator + Phase 8 deferred. `cos.rs:95-133` `enqueue_local_request_to_target_or_owner` `#[inline]` with FORCE_ENQUEUE_ERR fault injection only in cfg(test). `slow_path.rs:24-26` explicitly marks reinjection `#[cold] #[inline(never)]` per AGY round-2 finding D — i-cache protective.

**D-negative reasoning:** These were extracted correctly; further split would push hot cos lookup past call boundary without gain. The `cos_queue_fast_path_for_request` single-lookup primitive should stay `#[inline]` same crate.

**Labels:** `D-negative`, `already-split`, `#1443`

---

#### L5 — `tx/mod.rs` hub re-exports — minor, do-not-split

- **Severity:** Low
- **Confidence:** High
- **Refactor class:** D

56 LOC re-exports only. Splitting loses readability.

---

## Overall Hot-Path Guardrail Summary

All findings proposing moves within same crate `userspace-dp`:

| Guardrail | How verified for B-class splits |
|-----------|----------------------------------|
| **Inlining preserved** | helpers `pub(super)` + `#[inline]` or `#[inline(always)]` where <50 LOC; same-crate cross-module inlining is free in Rust release. Disprove regression via `cargo asm --rust --lib "afxdp::tx::dispatch::enqueue_pending_forwards"` before/after — hot block (in-place/direct/copy) must produce identical instruction sequence, only `callq` target changed to cold outline. Also `cargo bloat --lib --crates` size diff <0.1%. |
| **No heap alloc** | No `format!`/`to_string`/`Vec` in hot `enqueue_cos_item` admission gate nor in `try_direct_tx` path; keep counters on `wrapping_add`. Excise any `String` via `eprintln!` to cold `#[inline(never)]` helper. Check via `cargo clippy -- -W clippy::large_stack_frames` + manual review. |
| **No dynamic dispatch** | Use `enum DirectTxOutcome` + `match`, not `Box<dyn>`. Verify via `cargo asm` — no `jmp *%rax` indirect. |
| **Const/monomorphization** | Keep builders generic-free; `build_forwarded_frame_into_from_frame` monomorphic. |
| **Zero-copy/UMEM single-free** | Each offset must be returned exactly once. Existing tests `direct_tx_tuple_mismatch_recycles_frame_exactly_once`, `apply_prepared_recycle_routes_fill_and_free_explicitly` guard. New helpers must preserve `push_front` single-site (bool flag). |
| **Endianness locality** | IP/TCP checksum & TTL updates stay in `frame/` builders, not moved into dispatch helpers. |
| **Branch/icache** | Cold exception paths (`record_exception`, `fabric_redirect_unsendable_drops`, PTB build, seg miss) stay behind `if !is_fabric_ingress` etc predicate + call `#[cold] #[inline(never)]` outlined function. Keeps hot loop <2KB icache footprint. Measure via `perf stat -e L1-icache-load-misses`. |

**Incremental PR discipline (per engineering-style.md):**

- Each PR <300 LOC change, single seam, behavior-identical (`git diff -w` shows move only).
- Pre-PR gates: `make test` + `make test-rust` + CoS smoke (`scripts/run-selftests.sh` includes cos? — manual `cluster-deploy` + iperf3 10G cap).
- PR description must include asm diff snippet + perf stat delta + note why docs change not needed (internal module reshuffle) or update `tx/README.md` ongoing refactor section #4408.

---

## Required Gates for Any TX Refactor Landing

- `make test` green (Go + Rust #4006)
- `cargo test -p xpf-userspace-dp --lib tx::` — unit pins for BA, LP, demote, recycle
- Disassembly diff for `enqueue_pending_forwards` and `enqueue_cos_item` hot blocks — attached in PR notes, zero instruction diff in hot branch
- `make test-failover` if touching fabric redirect (fabric scatter) — ensures `fabric_redirect_unsendable_drops` fail-closed doesn't blackhole cross-chassis
- CoS smoke: `throughput-mode` shape 1 Gbps, 4-class, iperf3 `-P 12` fairness CoV <10% (fairness regimes doc)
- TX ring discipline: `perf stat` fill starvation (`rx_xsk_buff_alloc_err`) must stay zero during 1-min line-rate idle fill drain

---

## Cleanup

Worktree removed after report generation.


---
### Batch ps-a1c-b1.md — 56356 chars

# A1c — CoS (queue_service + queue_ops + shared_cos_lease + types/cos + tx_completion) — Refactor/Modularity Audit

Base SHA: 4e0c7f74cf0dbacf83051b2a9b6cf4e050dcecaa
Worktree: /tmp/review-wt-ps-043-a1c-b1
Reviewer: ps (NNN 043)
Date: 2026-07-11

## Inventory

| File | LOC | Responsibilities | Shape |
|------|-----|------------------|-------|
| `userspace-dp/src/afxdp/cos/queue_service/mod.rs` | 2057 | selector dispatch (Proportional vs GuaranteeRate), waterfill 432 LOC god-func, exact/nonexact/surplus selectors, refund logic, batch build, settle helpers, TX frame recycle | god-file: 7 responsibilities in one file; cold/warm interleaved |
| `userspace-dp/src/afxdp/cos/queue_service/drain.rs` | 608 | 4 drain variants (FIFO/flow-fair × Local/Prepared) + V_min cadence + snapshot clear + budget fencing | 4 variants duplicated structure; V_min threading repeated |
| `userspace-dp/src/afxdp/cos/queue_service/service.rs` | 718 | 4 service variants (local/prepared × FIFO/flow-fair) orchestrating drain→TX-ring→settle→V_min publish | 4× same pattern: free-frame check → dscp_rewrite → drain → match build → TX ring insert/commit/stamp → settle + account |
| `userspace-dp/src/afxdp/cos/queue_service/submit_local.rs` + `submit_prepared.rs` | ~371 | per-variant submit handling | already split but thin — good |
| `userspace-dp/src/afxdp/types/cos.rs` | 1786 | `CoSState` + config types + `EqualFlowTargetPolicy` + `CoSQueueConfig` + `CoSInterfaceRuntime` (28 fields, 5 lifecycles) + `FlowRrRing` + `FlowFairState` (352 KB, Box::new_uninit) + `CoSTimerWheelRuntime` + telemetry + sojourn EWMA | 28-field runtime mixing config, waterfill epoch, RR cursors, timer-wheel, policy, reserved fields; 352 KB state with unsafe constructor |
| `userspace-dp/src/afxdp/cos/tx_completion.rs` | 1080 | timer-wheel (advance/cascade/wake/snap/prime), TX-completion accounting (4 apply_* sites), backlog publish, activity refresh, lease release, retry restore, park counters | 3 distinct responsibilities: wheel, completion, backlog visibility |
| `userspace-dp/src/afxdp/types/shared_cos_lease/lease.rs` | 1460 | legacy token-bucket, v8 fair-share acquire (primary+surplus+bypass), seqlock snapshot, equal-flow cap, 6 per-worker atomic arrays, release_unused_v8 3-leg protocol | god-struct `SharedCoSQueueLease` with 11 atomics + 2 Box slices per lease |
| `userspace-dp/src/afxdp/types/shared_cos_lease/epoch.rs` | 565 | `V8State`, `SharedCoSEpochState`, `PackedEpochGrant`, `V8EqualFlowSuppressState`, consts, enums | epoch state — moderately cohesive already |
| `userspace-dp/src/afxdp/types/shared_cos_lease/rotate_epoch_v8.rs` | 446 | rotation winner logic: CAS claim, carry banking (3 regimes), swap capture, peer-util gate, bypass arm, publish + equal-flow dispatch | single function `maybe_rotate_epoch_v8` ~446 LOC in one impl block — prior #1588 split kept it monolithic |
| `userspace-dp/src/afxdp/types/shared_cos_lease/publish_equal_flow_epoch_v8.rs` | 247 | equal-flow sample set derivation + policy-driven target (Slowest/Mean/IdealShare) + fail-open + smoothed EWMA | already isolated — good size |
| `userspace-dp/src/afxdp/types/shared_cos_lease/backlog.rs` | 210 | `SharedCoSExactBacklog` + residual-surplus token bucket cross-worker | cohesive — good |
| `userspace-dp/src/afxdp/types/shared_cos_lease/vtime.rs` | 238 | `PaddedVtimeSlot`, `SharedCoSQueueVtimeFloor`, V_min snapshot helpers | cohesive — good |
| `userspace-dp/src/afxdp/cos/queue_ops/mod.rs` | 407 | `FlowRrRingIter`, MQFQ min-finish selection (two variants + hb166 saturation guard), front/peek helpers, demotion, `cos_item_len`, `cos_exact_queue_serviceable` | 5 responsibilities: ring iteration, MQFQ ordering, front/peek fused API, demote lifecycle, serviceability predicate |
| `userspace-dp/src/afxdp/cos/queue_ops/push.rs` | 506 | `push_back` + lazy promotion probe + `push_front` 3-axis state machine (snapshot match/restore, V_min republish, lease mirror) split into 7 helpers via #1355 | already split along snapshot axis — still 506 LOC, but decomposition matches plan doc |
| `userspace-dp/src/afxdp/cos/queue_ops/pop.rs` | 294 | `pop_front` variants (snapshot/no-snapshot, known-bucket, cap-aware) | moderately cohesive, but fused out of prod via #1763 Lever A — retained for tests only |
| `userspace-dp/src/afxdp/cos/token_bucket.rs` | 471 | `CoSQueueLeaseAcquireTelemetry`, root-lease top-up, queue-lease top-up (exact + non-exact + v8 attach), refill, carry remainder, release | 2 resp: lease top-up (hot) + telemetry (cold stats) interleaved |

Prior issues: #4408 waterfill 438 LOC god-func already filed, #4665 queue_service/tests.rs 4384 test-only split, #4666 queue_ops tests 5801 test-only.

## Log

- Worktree created detached at 4e0c7f HEAD.
- Read all target files + submodules (queue_ops, queue_service, shared_cos_lease, cos types, tx_completion, token_bucket, drain, service).
- Catalogued CoSInterfaceRuntime's 28 fields into 5 lifecycle groups: config copy, waterfill epoch, RR cursors, timer-wheel, reserved/unused.
- Traced waterfill function boundaries: epoch refill block (lines ~958-1031, 73 LOC) does f64 fraction math + clamp + bitset gating; Phase-1 ascending (~1046-1226, 180 LOC) does lease top-up + token gate + budget gate + telemetry + park; Phase-2 descending (~1227-1345, 118 LOC) mirrors Phase-1 without park; wrap handling (~1346-1357, 11 LOC).
- Verified `trigger_kernel_arp_probe` is NOT in this module set (global search — it lives in neighbor TX path; no allocation there). Confirmed `queue_service/mod.rs` has zero allocation on hot path: no Vec/HashMap creation in selector loops, only stack scalars + mutable borrows.
- Cross-checked FlowFairState 352 KB boxing: `new_boxed` uses `Box::new_uninit` + raw pointer writes to avoid 352 KB stack frame — correct, but constructor lives in same file as config types, mixing alloc concern.

## Findings

### HIGH

#### H-M1: Waterfill god-function — 432 LOC, 7 responsibilities, f64 math interleaved with hot park gating

- Severity: High
- Confidence: High
- Refactor class: B (hot file, large blast radius, but pure internal extraction)
- Evidence:
  - File: `queue_service/mod.rs:925-1357` — `select_exact_cos_guarantee_queue_waterfill` 432 LOC single function
  - Responsibilities counted: (1) epoch refill with `f64` fraction math `((cap_per_epoch as f64) * frac).floor() as u64` (line 990), (2) bitset gating `waterfill_honored_epoch_bits & (1u64 << i)` (1059), (3) Phase-1 ascending walk with lease top-up `maybe_top_up_cos_queue_lease` (1070), token gate `root.tokens < head_len` (1099), park `estimate_cos_queue_wakeup_tick` (1108), (4) quantum vs frame-cap budget decoupling `phase1_cost = cos_guarantee_quantum_bytes(queue).max(head_len)` (1169), (5) Phase-2 descending walk (1238-1344), (6) wrap handling resetting cursors + arming `epoch_wrap_pending` (1353-1355), (7) telemetry bumps `eligible_visits`, `phase1_admissions` interleaved
  - Size: 432 LOC function in 2057 LOC file; cyclomatic complexity > 15 due to nested loops + 6 early continues + 2 budget gates
  - Imports affected: `CoSQueueLeaseAcquireTelemetry`, `CoSPendingTxItem`, `COS_GUARANTEE_VISIT_NS`, `cos_guarantee_visit_cap_bytes`, `cos_guarantee_quantum_bytes`, `cos_queue_is_empty`, `cos_item_len`, `cos_queue_front`, `maybe_top_up_cos_queue_lease`, `estimate_cos_queue_wakeup_tick`, `count_park_reason`, `park_cos_queue`
  - Callers: `select_exact_cos_guarantee_queue_with_lease_telemetry` dispatches to it when `GuaranteeRate && fraction > 0`

```rust
// mod.rs:958-1002 — epoch refill with f64 math + clamp interleaved
let elapsed_since_refresh = now_ns.saturating_sub(root.waterfill_epoch_start_ns);
let time_refresh = elapsed_since_refresh >= COS_GUARANTEE_VISIT_NS;
let exhausted = root.waterfill_pass1_remaining_bytes == 0;
if time_refresh || exhausted {
    let frac = root.oversubscription_guarantee_fraction;
    let raw_pass1 = if root.shaping_rate_bytes == 0 {
        // transparent branch uses quantum_sum × fraction
        ...
        ((quantum_sum as f64) * frac).floor() as u64
    } else {
        let cap_per_epoch = ((root.shaping_rate_bytes as u128) * ... / 1_000_000_000u128) as u64;
        ((cap_per_epoch as f64) * frac).floor() as u64
    };
    let pass1 = raw_pass1.max(COS_GUARANTEE_QUANTUM_MIN_BYTES);
```

```rust
// mod.rs:1112-1225 — Phase-1 ascending with 4 telemetry sites + 2 park sites
for i in 0..ascending_len {
    let queue_idx = root.exact_queues_by_rate_ascending[i];
    if i < 64 && (root.waterfill_honored_epoch_bits & (1u64 << i)) != 0 { continue; }
    // ... 80 LOC of lease top-up + token gates + park + budget gate + honor mark
}
```

- Proposed decomposition:
  - New module: `userspace-dp/src/afxdp/cos/queue_service/waterfill/mod.rs` + 3 files:
    - `epoch.rs`: `waterfill_refill_pass1_if_needed(root, now_ns)` — owns f64 fraction math, `quantum_sum * fraction` vs `shaping_rate × VISIT_NS × fraction`, clamp logic, `waterfill_epochs` bump, honored-bits clear gated on `epoch_boundary`. Cold-ish (runs at most once per 200 µs).
    - `phase1.rs`: `waterfill_select_phase1(root, fast_path, now_ns, telemetry)` — ascending walk, lease top-up, token/root gates, park, budget debit `phase1_cost`, honored bitset mark `1u64 << i`, telemetry `eligible_visits` + `phase1_admissions`, returns `Option<(queue_idx, kind, Phase1HonorRefund)>`
    - `phase2.rs`: `waterfill_select_phase2(root, fast_path, now_ns, telemetry)` — descending walk, skip honored, no park, returns Option
  - Seam by responsibility: epoch refill is allocation-free config math, Phase-1/Phase-2 are selection walks with different park semantics; wrapper `select_exact_cos_guarantee_queue_waterfill` in parent becomes 20 LOC dispatcher calling refill → phase1 → phase2 → wrap.
  - Moves: 380 of 432 LOC out; parent retains dispatch + wrap sentinel `waterfill_pass1_remaining_bytes=0; cursor=0; wrap_pending=true`. No change to `CoSInterfaceRuntime` layout.

- Hot-path preservation:
  - Applies: inlining (selector is `#[inline]` — new sub-fns must stay `#[inline]` to preserve cross-module inlining at `pub(in crate::afxdp)` boundary), alloc (currently zero in phase loops — must not introduce Vec clone or float-to-string), dispatch (no indirect call), layout (root fields stay contiguous), lock scope (none).
  - Verification:
    - `cargo asm --lib afxdp::cos::queue_service::select_exact_cos_guarantee_queue_waterfill` diff before/after — disasm must be byte-identical modulo symbol names. Use `objdump -d` on helper binary with `-C`.
    - `cargo test -p userspace-dp --lib cos::queue_service` must pass; specifically existing `waterfill` fairness property tests.
    - `perf stat` on `cargo test` synthetic drain benchmark: L1-dcache misses unchanged, instructions delta <0.1%.
    - Criterion bench for drain path if present: `cargo bench --bench cos_drain` (or equivalent) throughput within noise.
    - CoS smoke: `make test-failover` + `test/cos-smoke` (iperf3 oversubscription matrix: 100m/1g/5g classes under shaped root) must preserve proportional buckets.
    - Guarantee-guard correctness #4246: mid-rate exact class on/off pattern must not park at ClassCap; `waterfill_phase1_budget_breaks` rate unchanged.

- Tests+gate: existing waterfill tests in `queue_service/tests/` exercise both phases; new module gets unit tests for epoch refill math (f64 floor edge, tiny fraction → min-quantum clamp). Gate: `make test-rust` passes, `make test-failover` CoS smoke.

- Why it matters: 432 LOC function with 7 concerns blocks review of guarantee-correctness (#4246), tranche expansion (Phase-3 equal-flow integration would add 100+ LOC to same function), and prevents independent testing of refill math (f64 floor + u128 × fraction is where silent drift hides). Same defect class as #4408 which was already filed.

- Fix direction: dependency-upward extraction (leaf math first, then phase walks). No struct field moves yet — preserve layout, then follow with C1.

- Labels: `refactor`, `hot-path`, `x-hpc`
- Dedup: Extends #4408 (same function, but this proposal gives concrete file split + cold/hot seam + verification recipe). Not duplicate of #4665 (test-only split).

#### H-M2: CoSInterfaceRuntime 28 fields mingling 5 lifecycles — config copy, waterfill epoch, RR cursors, timer-wheel, reserved/unused

- Severity: High
- Confidence: High
- Refactor class: B (struct field grouping, touches 10+ consumers but mechanical)
- Evidence:
  - File: `types/cos.rs:556-709` — `CoSInterfaceRuntime`
  - Fields: `shaping_rate_bytes, burst_bytes, tokens, nonexact_surplus_under_exact_* (2), default_queue, nonempty_queues, runnable_queues, oversubscription_policy, oversubscription_guarantee_fraction: f64, priority_low_min_share_bytes, priority_low_reserved_tokens, priority_low_last_refill_ns, exact_queues_by_rate_ascending: Vec<usize>, waterfill_pass1_remaining_bytes, waterfill_phase2_cursor, waterfill_honored_epoch_bits, waterfill_epochs, waterfill_phase1_budget_breaks, waterfill_epoch_start_ns, waterfill_epoch_wrap_pending, exact_guarantee_rr, nonexact_guarantee_rr, legacy_guarantee_rr, queues, queue_indices_by_priority, rr_index_by_priority, timer_wheel`
  - 28 fields, of which 3 are dead/unused: `priority_low_min_share_bytes` (wire surface only, no hot-path consumer per comment "Currently UNUSED" at line 573-579), `priority_low_reserved_tokens`, `priority_low_last_refill_ns` (reserved for deferred cap_eff mechanism #4220 note).
  - 5 lifecycles: (a) immutable config copy (shaping_rate, burst, default_queue, policy, fraction, low-min-share), (b) mutable token buckets (tokens, nonexact_*), (c) waterfill epoch (7 fields: pass1_remaining, phase2_cursor, honored_bits, epochs, phase1_breaks, epoch_start_ns, wrap_pending), (d) RR cursors (3 fields + 2 vec+array indices), (e) timer-wheel runtime (CoSTimerWheelRuntime). All in one flat struct, so cache line spans 3 lifecycles.
  - Layout: `tokens` (hot) adjacent to `nonexact_surplus_under_exact_tokens` (exception path) adjacent to `default_queue` (cold) — no intentional grouping.
  - Size: `CoSInterfaceRuntime` itself ~ 400 bytes + heap of queues Vec + sorted indices + timer-wheel `[Vec<usize>;256]` ×2 + scratch. The waterfill epoch fields (7×8 bytes = 56 bytes) sit in middle, evicting true hot fields.

```rust
pub(in crate::afxdp) struct CoSInterfaceRuntime {
    pub(in crate::afxdp) shaping_rate_bytes: u64, // config copy
    pub(in crate::afxdp) burst_bytes: u64,
    pub(in crate::afxdp) tokens: u64, // hot bucket
    pub(in crate::afxdp) nonexact_surplus_under_exact_tokens: u64, // warm
    ...
    pub(in crate::afxdp) oversubscription_guarantee_fraction: f64, // cold config
    pub(in crate::afxdp) priority_low_min_share_bytes: u64, // UNUSED (#4220)
    pub(in crate::afxdp) priority_low_reserved_tokens: u64, // UNUSED
    pub(in crate::afxdp) priority_low_last_refill_ns: u64, // UNUSED
    pub(in crate::afxdp) exact_queues_by_rate_ascending: Vec<usize>, // warm
    pub(in crate::afxdp) waterfill_pass1_remaining_bytes: u64, // hot epoch
    ...
}
```

- Proposed decomposition:
  - Keep single struct for now (avoid churn), but group fields into sub-structs behind `#[repr(C)]` or explicit grouping comment + accessor, in new file `types/cos/interface_runtime.rs`:
    - `CoSInterfaceShapingState { tokens, burst_bytes, shaping_rate_bytes, nonexact_surplus_* (2), default_queue }` — hot token bucket cluster, cache-line aligned first.
    - `CoSInterfaceWaterfillEpoch { pass1_remaining, phase2_cursor, honored_bits, epochs, phase1_breaks, epoch_start_ns, wrap_pending, exact_queues_by_rate_ascending }` — waterfill-epoch cluster (56 bytes + Vec). Lives in its own module `types/cos/waterfill_epoch.rs`.
    - `CoSInterfaceRrCursors { exact_guarantee_rr, nonexact_guarantee_rr, queue_indices_by_priority, rr_index_by_priority }`
    - `CoSInterfaceConfigView { oversubscription_policy, oversubscription_guarantee_fraction }` — immutable policy copy, cold.
  - Remove `priority_low_*` trio to dedicated future `CoSInterfaceReserved` behind `#[allow(dead_code)]` or delete per #4220 ("WIRE SURFACE ONLY" — should not live in runtime). At minimum move to separate file with explicit "not hot" annotation.
  - Seam: field groups are accessed via `root.shaping.tokens` instead of `root.tokens` — mechanical rename. Waterfill epoch isolation lets waterfill module own its state without touching root's other fields (borrow-split: `&mut root.waterfill_epoch` vs `& root.shaping`).

- Hot-path preservation:
  - Layout: grouping hot token `tokens` first aims to keep it on first cache line with `burst_bytes` + `shaping_rate_bytes`; waterfill epoch fields move to second line. Measure via `#[repr(C)]` + `offset_of!` asserts. Verify with `cargo test` memory layout test `mem_layout_cos_runtime`.
  - Locality: drain path reads `tokens` (hot) + `queues[queue_idx].hot.tokens` (hot) + `waterfill_pass1_remaining_bytes` (warm, only GuaranteeRate). Separating epoch to second line reduces false sharing for Proportional (default) path.
  - Inlining: accessor methods `root.tokens()` → inline, no call overhead; `#[inline(always)]` on hot accessors.
  - Alloc: `Vec<usize>` sorted by rate stays heap but already cold-rebuild; grouping doesn't add alloc.
  - Verify: `cargo asm` for `drain_shaped_tx` disasm diff — loads of `tokens` keep same offset or improve (first line). `perf stat` for 200 Mbps iperf3 CoS shaped drain: LLC misses not increased.

- Tests+gate: existing runtime builder tests + layout offset tests; `make test` (Go+ Rust) passes; CoS smoke with proportional vs guarantee-rate.

- Why it matters: 28 fields with 5 lifecycles makes reasoning about what changes when (config apply vs token refill vs waterfill epoch tick) error-prone; prior bug #1743 (waterfill epoch bits cleared on bare `pass1==0`) stemmed from fields of different lifecycles sharing flat namespace. Dead `priority_low_min_share_bytes` wastes cache and misleads readers that it participates in cap_eff (it doesn't — per #4220 honest field note). The 56-byte waterfill cluster in middle of hot fields causes avoidable cache pressure for Proportional default path (majority of deployments).

- Fix direction: extract sub-structs behind `#[repr(C)]` with accessor methods, delete or quarantine dead `priority_low_*`. Start with trivial field reorder + grouping comment, then sub-struct.

- Labels: `refactor`, `hot-path`, `x-hpc` (cache/layout)
- Dedup: New; not covered by #4408 (function-level) — this is struct-level.

#### H-M3: tx_completion.rs bundles 3 responsibilities — timer-wheel, TX-completion apply, backlog publish — sharing 1080 LOC with cross-cutting mutable borrow of root

- Severity: High (Med-High but flagged High due to HA-correctness adjacency)
- Confidence: High
- Refactor class: B
- Evidence:
  - File: `cos/tx_completion.rs:1-1081`
  - Resp 1 — timer-wheel cluster (lines 128-399): `cos_tick_for_ns`, `cos_timer_wheel_level_and_slot`, `wake_cos_queue`, `park_cos_queue`, `rearm_cos_queue`, `advance_cos_timer_wheel`, `snap_cos_timer_wheel_over_horizon` (cold, 50 lines), `cascade_cos_timer_wheel_level1`, `wake_due_cos_timer_slot`, `cos_root_can_service_after_prime`, `prime_cos_root_for_service`. Uses `COS_TIMER_WHEEL_L0_SLOTS=256`, `L1=256`, horizon math, over-horizon snap correctness proof in comments (lines 270-329).
  - Resp 2 — TX-completion apply cluster (lines 469-1044): `maybe_consume_exact_queue_lease`, `apply_direct_exact_queue_accounting`, `apply_direct_exact_send_result`, `refresh_cos_interface_activity` (activity scan + #4246 R-5(a) burst give-back `release_unused_v8`), `apply_cos_send_result` / `apply_cos_prepared_result` (each 100+ LOC, nearly duplicate), `account_queue_drain_sent_bytes`, `restore_*_inner`. `refresh_cos_interface_activity` alone is 80 LOC with coalesced `Vec<(usize, usize, u64)>` for released leases + fast-path probe `iface_fast`.
  - Resp 3 — backlog visibility (lines 499-609): `root_has_backlogged_exact_queue`, `exact_backlog_bytes`, `serviceable_exact_backlog_bytes`, `exact_backlog_queue_mask`, `exact_backlog_guarantee_rate_bytes_for_mask`, `publish_cos_exact_backlog`, `clear_all_cos_exact_backlogs_for_binding`, `peer_exact_demand_queue_mask`.
  - Shared mutable borrow pattern: every apply_* takes `&mut CoSInterfaceRuntime` for token debit, then drops it and re-borrows via `cos_fast_interfaces` for lease consume — the borrow-split is correct but fragile; future editors adding a field access between the two borrows will hit borrow-checker and may work around unsafely.
  - Size shape: timer-wheel uses `Vec<usize>` per slot (512 slots) + scratch `drain/rearm/wake` persistent buffers (R-9 optimization). Backlog helpers do O(N_queues) fold each time they're called (called at every TX completion → O(N) extra per packet batch). That's cold/warm mix in hot file.

```rust
// tx_completion.rs:732-814 — refresh_cos_interface_activity 80 LOC
pub(in crate::afxdp) fn refresh_cos_interface_activity(
    binding: &mut BindingWorker,
    root_ifindex: i32,
) {
    let mut new_nonempty = 0usize;
    let mut new_runnable = 0usize;
    let mut released_queue_leases = Vec::<(usize, usize, u64)>::new();
    // ...
    if let Some(root) = binding.cos.cos_interfaces.get_mut(&root_ifindex) {
        for (queue_idx, queue) in root.queues.iter_mut().enumerate() {
            normalize_cos_queue_state(queue);
            if cos_queue_is_empty(queue) && queue.hot.tokens > 0 {
                let has_lease = iface_fast.and_then(...).is_some();
                if has_lease {
                    released_queue_leases.push((queue_idx, worker_id, mem::take(...)));
                }
            }
        }
    }
    publish_cos_exact_backlog(binding, root_ifindex);
    // ... release via lease
}
```

- Proposed decomposition:
  - New modules under `cos/tx_completion/`:
    - `timer_wheel/mod.rs`: `cos_tick_for_ns`, `cos_timer_wheel_level_and_slot`, `advance_cos_timer_wheel`, `snap_cos_timer_wheel_over_horizon` (#1782), `cascade_cos_timer_wheel_level1`, `wake_due_cos_timer_slot`, `park_cos_queue`, `rearm_cos_queue`, `wake_cos_queue`, `mark_cos_queue_runnable`, `normalize_cos_queue_state`, `cos_root_can_service_after_prime`, `prime_cos_root_for_service`, plus constants `COS_TIMER_WHEEL_TICK_NS`, `COS_TIMER_WHEEL_TOTAL_HORIZON_TICKS`. All cold/warm timer-wheel ops in one place; retains `#[inline]` on hot `cos_tick_for_ns`.
    - `apply/mod.rs`: `apply_direct_exact_queue_accounting`, `apply_direct_exact_send_result`, `apply_cos_send_result`, `apply_cos_prepared_result`, shared helper `account_queue_drain_sent_bytes`, `maybe_consume_exact_queue_lease`. The two 100+ LOC apply_* bodies share 80% structure — extract common `apply_cos_result_common(root, queue_idx, phase, batch_bytes, sent_bytes, retry, exact_demand_mask_calc)` to eliminate duplication.
    - `backlog.rs`: `exact_backlog_*`, `publish_cos_exact_backlog`, `clear_all_cos_exact_backlogs_for_binding`, `peer_exact_demand_queue_mask`, `root_exact_demand_queue_mask` (currently duplicated in queue_service/mod.rs:314-358 and in tx_completion:532-599 — that's a real duplication to consolidate), `exact_demand_rate_bytes_for_mask`.
    - `activity.rs`: `refresh_cos_interface_activity`, `normalize_cos_queue_state`, `count_tx_ring_full_submit_stall`, retry restore helpers (already near-duplicate with queue_service restores — consolidate to one owner).
  - Seam: timer-wheel never needs lease access (only tokens + wheel); apply never touches wheel slots directly (only via park calls); backlog is read-only on root + fast_path. So dependencies are DAG: `timer_wheel` ← `activity` ← `backlog` + `apply`. Cold/warm/alloc separation clean.

- Hot-path preservation:
  - Inlining: `apply_direct_exact_send_result` and `apply_cos_send_result` are `#[inline]` — new module must retain. They debit `root.tokens` (single u64 store) + `queue.hot.tokens` + `queued_bytes` — 3 stores that must stay inlinable into drain_shaped_tx wrapper.
  - Alloc: `refresh_cos_interface_activity` currently allocates `Vec<(usize, usize, u64)>` for released leases. That's warm (only on queue-drained-to-empty, not per packet). Moving it doesn't change alloc, but new module should make it explicit that this Vec is cold-path only (add `#[cold]` or document that empty exact queue release happens at queue drain boundary, not per packet).
  - Lock scope: none (all plain fields).
  - Verification:
    - `cargo asm` for `apply_cos_send_result` before/after — store sequence identical.
    - `make test`: Rust suite includes `tx_completion_tests.rs` (1076 LOC) that asserts park counters, token debits, backlog publish.
    - CoS smoke: best-effort surplus under exact demand (nonexact_surplus_under_exact_tokens path) exercises backlog mask aggregation — must preserve `serviceable_exact_backlog_bytes` vs `exact_backlog_bytes` consistency (hb166 T-6(b) predicates).
    - For guarantee-guard #4246: `refresh_cos_interface_activity` R-5(a) burst give-back must still call `release_unused_v8` not `release_unused` — bit-identical code.

- Tests+gate: existing tx_completion_tests + queue_service tests + backlog mask tests; `make test`; CoS smoke with exact + nonexact mix checking `drain_nonexact_sent_bytes_while_exact_backlogged` counter.

- Why it matters: 1080 LOC file with 3 responsibilities means timer-wheel correctness fixes (#1782 over-horizon snap proof) touch same file as TX-completion accounting (#4246 burst give-back), increasing merge conflict rate and review risk. The backlog helpers are O(N_queues) folds called at every TX completion — they belong in a visibility/publish module where their cost is visible and rate-limited. `refresh_cos_interface_activity` mixed normalization (`normalize_cos_queue_state`) + lease release + backlog publish + nonempty counter upkeep — 4 sub-concerns.

- Fix direction: split file into directory with 4 submodules, keep `mod.rs` as re-export shell. Start with backlog + timer_wheel (cold), then apply (hot — needs asm guard).

- Labels: `refactor`, `hot-path`

### MEDIUM

#### M-M1: SharedCoSQueueLease lease.rs 1460 LOC mixes legacy token-bucket, v8 fair-share acquire (primary+surplus+bypass), seqlock snapshot, equal-flow cap evaluation

- Severity: Medium (High LOC but already partially modularized via submodules)
- Confidence: High
- Refactor class: B
- Evidence:
  - File: `shared_cos_lease/lease.rs:532-823` — `acquire_v8_with_cause` 290 LOC with 3 phases inside one function: Phase 1 rotate (`maybe_rotate_epoch_v8`), Phase 2 seqlock snapshot (`snapshot_epoch_v8`), Phase 3 primary loop (bounded by `my_effective_share` + class cap), plus surplus path (bypass-gated), plus narrow starvation signal bump, plus telemetry flush `worker_requested_bytes`, `worker_granted_bytes`.
  - Responsibilities: (1) legacy token-bucket (`shared_cos_lease_acquire`, `shared_cos_lease_consume`, `shared_cos_lease_release_unused`), (2) v8 fair-share grant (primary + surplus), (3) active-flow bucket tracking, (4) release_unused_v8 3-leg protocol (legacy outstanding + worker grant CAS + class rollback), (5) equal-flow cap read, (6) telemetry counters for shortfall causes.
  - 6 per-worker atomic arrays: `worker_grants`, `worker_active_flow_buckets`, `worker_fair_share`, `worker_starvation_events`, `worker_demand_events`, `worker_equal_flow_active_samples`, plus `worker_requested_bytes`, `worker_granted_bytes` (8 total in V8State). All cache-line-padded (`PaddedAtomicU32/64`) — good.
  - Allocation/freedom: `acquire_v8` path has zero alloc (only atomic CAS loops); `release_unused_v8` has loop with CAS retries `MAX_ROLLBACK_RETRIES=16`. `trigger_kernel_arp_probe`-equivalent not here, but `record_equal_flow_active_sample` does tag-checked CAS with sticky-max — allocation-free preserved.

```rust
// lease.rs:541-823 — acquire_v8_with_cause core loop excerpt
pub(in crate::afxdp) fn acquire_v8_with_cause(...) -> (u64, AcquireV8ShortfallCause) {
    // Phase 1: maybe rotate
    self.maybe_rotate_epoch_v8(now_ns);
    // Phase 2: seqlock snapshot
    let Some((cap, my_share, grace, my_tag)) = self.snapshot_epoch_v8(worker_id) else {
        return (0, SeqlockGiveUp);
    };
    // Phase 3: primary bounded by my_fair_share AND class cap
    loop {
        // tag-checked snapshot of my_consumed
        // class CAS, outstanding bump, worker grant bump
    }
    // surplus path + starvation signal + bypass telemetry
}
```

- Proposed decomposition:
  - New files under `shared_cos_lease/`:
    - `acquire_v8/mod.rs`: `acquire_v8_with_cause` wrapper
    - `acquire_v8/primary.rs`: primary path loop (class CAS + outstanding bump + worker grant bump)
    - `acquire_v8/surplus.rs`: surplus bypass path + starvation event bump + equal-flow cap-hit telemetry
    - `acquire_v8/snapshot.rs`: `snapshot_epoch_v8` seqlock reader (already isolated but move file to make fence contract explicit — reader half of #1643)
    - `release/mod.rs`: `release_unused_v8` 3-leg protocol extracted with comment diagram of invariant `sum(worker_grants) == packed_granted`
  - Seam: primary/surplus share tag `my_tag`, `cap`, `my_effective_share`; snapshot returns tuple; release needs only `worker_id` + `bytes`. No new alloc.

- Hot-path preservation:
  - Inlining: `acquire_v8_with_cause` is hot — called at most once per drain per queue, but inside it loop does CAS contention (fast path uncontended). All helpers must be `#[inline]` or `#[inline(always)]` to preserve LTO-out-of-crate inlining (codegen-units 16, LTO off).
  - Atomics: layout of per-worker arrays is cache-line-padded already (good). Decomposition must not add extra indirection (no `Box` indirection beyond existing).
  - Verify: `cargo asm` for `acquire_v8_with_cause` before/after — CAS loop structure identical; `worker_grants[worker_id].0.load(Acquire)` count unchanged; no new branches before primary loop.
  - Gate: `make test-rust` includes `shared_cos_lease_tests.rs` (2511 LOC) covering seqlock ordering, tag wrap at u32::MAX, equal-flow fail-open.

- Why it matters: lease.rs mixes legacy + v8 paths with identical names (`acquire` vs `acquire_v8`) — new contributors mis-read legacy caps as v8 caps. The 290 LOC `acquire_v8_with_cause` mixes 3 phases with different ordering contracts (seqlock Acquire fence vs Release fence in rotate) — splitting makes each contract doc-local. Equal-flow cap evaluation `equal_flow_cap_v8` is 40 LOC with acquire-side read-only invariant — buried among unrelated telemetry accessors.

- Labels: `refactor`, `hot-path`, `x-hpc` (atomics/cache-line)

#### M-M2: FlowFairState 352 KB heap boxing via unsafe MaybeUninit construction mixed with safe config parsing — alloc concern tangled with Wi-Fi of fields

- Severity: Medium
- Confidence: High
- Refactor class: C (structural + doc)
- Evidence:
  - File: `types/cos.rs:919-1209` — `FlowFairState` 14 fields: `queue_vtime`, `flow_hash_seed`, `active_flow_buckets`, `active_flow_buckets_peak`, 7 bucket arrays `[u64;4096]` + `[u32;4096]`, `flow_bucket_items: [VecDeque;4096]` (128 KB headers), `flow_rr_buckets: FlowRrRing` (8 KB), `pop_snapshot_stack: Vec<CoSQueuePopSnapshot>`, plus 4 new v7 accounting arrays.
  - 352 KB size computed as ~232 KB per comment (32+32+32+128+8) plus v7 additions (4×32 KB = 128 KB) → 360 KB total — comment says ~232 KB but actually larger now with v7.
  - Constructor `new_boxed` (line 1162-1208) uses `Box::new_uninit` + raw pointer writes + SAFETY contract enumerated in 30-line comment. Must stay in lock-step with struct definition field-by-field — comment warns "keep this in lockstep". Adding a field without updating `new_boxed` is UB (uninit read under miri).
  - `FlowFairState::new` owned-value constructor retained for tests but warns "Do not call this on any production/hot path" with `__rust_probestack` 352 KB frame mention (line 1101-1104). Two constructors for same type — easy to misuse.

```rust
pub(in crate::afxdp) fn new_boxed(flow_hash_seed: u64) -> Box<Self> {
    use std::ptr::addr_of_mut;
    let mut uninit: Box<std::mem::MaybeUninit<Self>> = Box::new_uninit();
    unsafe {
        let ptr = uninit.as_mut_ptr();
        addr_of_mut!((*ptr).queue_vtime).write(0);
        addr_of_mut!((*ptr).flow_hash_seed).write(flow_hash_seed);
        // ... 15 writes, each must match struct field exactly
        let items = addr_of_mut!((*ptr).flow_bucket_items) as *mut VecDeque<...>;
        for i in 0..COS_FLOW_FAIR_BUCKETS { items.add(i).write(VecDeque::new()); }
        addr_of_mut!((*ptr).pop_snapshot_stack).write(Vec::with_capacity(TX_BATCH_SIZE));
        uninit.assume_init()
    }
}
```

- Proposed decomposition:
  - New file `types/cos/flow_fair_state.rs`: own `FlowFairState` + `FlowRrRing` + constructors + size assertions. Keep `types/cos.rs` for config/state enums + small structs only.
  - Add compile-time field-count guard: `const _: () = assert!(mem::size_of::<FlowFairState>() == EXPECTED)` or use `memoffset` macro to assert `new_boxed` writes count equals field count — or replace manual `addr_of_mut!` sequence with macro that expands from field list.
  - Delete `new` (owned-value) after migrating its two test callers to `new_boxed` + deref, or gate it under `#[cfg(test)]` with explicit rename `new_for_test_only_will_stack_overflow_in_prod`.
  - Document v7 array additions updating size comment from "~232 KB" to "~360 KB" with breakdown.

- Hot-path preservation:
  - Alloc: promotion happens at most once per queue lifetime (best-effort queues) or once at build (exact queues). So allocation timing not hot, but stack frame size IS hot — `cos_queue_push_back` previously had 352 KB frame from `new()`. `new_boxed` fixes it. Decomposition must not reintroduce stack temp.
  - Verify: `cargo asm` for `cos_queue_push_back` — frame size < 1 KB; `__rust_probestack` call absent. `cargo test --lib flow_fair_state_tests::new_boxed_matches_new_field_for_field` + miri run.
  - Gate: `make test-rust` passes; existing test `new_boxed_collections_are_usable` exercises drop.

- Why it matters: unsafe constructor with manual field list is major UB surface; comment already says "keep in lockstep". History shows field additions without updating `new_boxed` would be silent UB until miri catches it (if ever run). Size comment stale (232 KB vs real ~360 KB) misleads capacity planning (30 MB estimate at 8 workers × 8 queues × 2 ifaces → now 46 MB).

- Labels: `refactor`, `x-hpc`

#### M-M3: queue_ops/push.rs 506 LOC lazy promotion + snapshot-axis split still interleaves 3 concerns — admission probe, flow-fair alloc, v8 lease mirror

- Severity: Medium
- Confidence: Medium
- Refactor class: C (already partially refactored via #1355)
- Evidence:
  - File: `queue_ops/push.rs:98-149` — `cos_queue_push_back` does: `maybe_promote_best_effort` (probe that may allocate 352 KB box via `FlowFairState::new_boxed`), then `local_item_count` bump, then snapshot stack clear, then `account_cos_queue_flow_enqueue`, then bucket enqueue or FIFO enqueue.
  - `maybe_promote_best_effort` allocates at most once per queue lifetime (cold) but lives in hot `push_back` (called per packet enqueue) — correctly marked `#[cold] #[inline(never)]` on `promote_to_flow_fair` (line 85-86), probe itself is hash-free 1-3 ns (comment 40-41). Good.
  - `push_front` flow-fair path (line 192-267) does snapshot pop matching (may panic), vtime restore, V_min republish (disjoint-field read via `queue.v_min`), drained vs active bucket branch, lease mirror.
  - The 7-helper split from #1355 plan doc `docs/pr/1355-cos-push-split/plan.md` is snapshot-axis — correct per reviewers rejecting flow_fair() axis. Still, helpers like `push_front_drained_bucket_with_snapshot` vs `push_front_drained_bucket_no_snapshot` vs `push_front_active_bucket_head_rebase` share 80% of finish-time math but differ in active-bucket bump, flow_rr push, lease mirror gating — subtle.

```rust
// push.rs:85-96 — cold promotion kept out-of-line
#[cold]
#[inline(never)]
fn promote_to_flow_fair(queue: &mut CoSQueueRuntime) {
    let resident: VecDeque<CoSPendingTxItem> = std::mem::take(&mut queue.hot.items);
    queue.flow_fair_state = Some(FlowFairState::new_boxed(...));
    for item in resident { /* re-enqueue via push_back */ }
}
```

- Proposed decomposition:
  - No further file split needed now (post-#1355 is acceptable). Focused cleanups:
    - Extract `CoSQueuePushBack` fast-path struct: `cos_queue_push_back` currently does 5 things; factor admission probe into explicit `AdmissionProbeResult` enum.
    - Consolidate snapshot helpers doc — add diagram showing 3 push_front states (matched snapshot / empty stack / active bucket) with table of which of the 6 side effects fire (active_flow_buckets bump, flow_rr push, tail re-anchor, head rebase, lease mirror, V_min republish).
  - Cold/hot seam already exists via `#[cold]` on promotion — preserve. Add `#[cold]` to drop error paths in drain.rs that currently not marked cold.

- Hot-path preservation: existing `#[cold]` + `#[inline(never)]` on promotion prevents 352 KB frame on hot path — must not inline. Verify via frame size in `cargo asm` for `cos_queue_push_back` (< 128 bytes). Fused select+pop (#1763) already removed second min-finish scan — must stay fused.

- Labels: `refactor`, `hot-path`

#### M-M4: queue_service drain.rs 608 LOC duplicates free-frame check + dscp rewrite + mirror-reserve + V_min wiring across 4 variants

- Severity: Medium
- Confidence: High
- Refactor class: C
- Evidence:
  - File: `queue_service/drain.rs:144-608` — 4 functions: `drain_exact_local_fifo_items_to_scratch`, `drain_exact_local_items_to_scratch_flow_fair`, `drain_exact_prepared_fifo_items_to_scratch`, `drain_exact_prepared_items_to_scratch_flow_fair`
  - Each variant repeats: snapshot stack clear at batch start (lines 162-164, 461-463 in flow-fair variants — FIFO variants skip), target_bps compute (compute_drain_target_bps), free-frame preflight `free_tx_frames.is_empty()` (177, 359), V_min suspension consume `cos_queue_v_min_consume_suspension` (185, 492), candidate_pop_count `v_min_pop_count.wrapping_add(1)` + gate `cos_queue_v_min_continue` (228-230, 519-521), peek→budget→mirror-reserve→pop→cadence advance pattern.
  - FIFO Local vs FIFO Prepared differ only in: item kind check (Local vs Prepared), frame copy vs slice check, mirror-reserve handling, recycle bookkeeping via `shared_recycles` in Prepared. Flow-fair Local vs Prepared differ only in free-frame handling (Local checks `free_tx_frames.is_empty()` preflight, Prepared checks `cos_queue_front_with_cap` preflight) + V_min comment duplication.

```rust
// drain.rs:177-185 — duplicated preflight + suspension across flow-fair variants
if free_tx_frames.is_empty() {
    return ExactCoSScratchBuild::Ready;
}
let suspended = cos_queue_v_min_consume_suspension(queue);
...
let candidate_pop_count = queue.v_min.v_min_pop_count.wrapping_add(1);
if !suspended && !cos_queue_v_min_continue(queue, candidate_pop_count) {
    break;
}
```

- Proposed decomposition:
  - New file `queue_service/drain_common.rs`: shared helpers
    - `drain_preflight_free_frames(free_tx_frames) -> Option<SuspensionState>` — the `is_empty` check + `consume_suspension` + returns `(suspended, candidate_pop_count)` or early Ready.
    - `drain_mirror_reserve_check(req, free_tx_frames, scratch_empty) -> MirrorReserveAction`
    - `drain_budget_check(remaining_root, remaining_secondary, len) -> bool`
  - Keep 4 variant fns but delegate common legs to helpers — reduces from 608 LOC to ~350 LOC of truly variant code. Seam by responsibility: preflight/suspension logic is identical across variants,only framing differs (free-frame preflight vs front-with-cap preflight). Convert free-frame vs front-with-cap difference into enum `DrainPreflight { FreeFrames, FrontWithCap(target_bps) }`.
  - No alloc added — helpers are `#[inline]` returning scalar enums.

- Hot-path preservation:
  - Inlining: drain fns are called inside service fns which are `#[inline]` — helpers must be `#[inline]` to avoid extra call. V_min cadence counter `v_min_pop_count` commit deferred to pop-confirmed point (#2646) must stay — count advances only after `cos_queue_pop_known_bucket` succeeds, not on budget miss.
  - Alloc: no Vec/HashMap in drain loops — preserve.
  - Verify: `cargo asm` for `drain_exact_local_items_to_scratch_flow_fair` instruction count unchanged; L1 misses via `perf stat` on synthetic drain bench.

- Labels: `refactor`, `hot-path`

### LOW

#### L-M1: token_bucket.rs 471 LOC mixes telemetry struct `CoSQueueLeaseAcquireTelemetry` (cold stats) with hot lease top-up logic

- Severity: Low
- Confidence: High
- Refactor class: C
- Evidence:
  - File: `cos/token_bucket.rs:29-103` — `CoSQueueLeaseAcquireTelemetry` with `v8_calls`, `v8_granted_bytes`, `v8_shortfall_cause`, `v8_undergrants` (per-cause counters). Accumulates via `add_assign` + `record_v8_grant` + `count_v8_undergrant`.
  - Then 370 LOC of hot top-up: `maybe_top_up_cos_root_lease` (transparent fast path), `acquire_via_lease` (v8 vs legacy dispatch), `ensure_v8_lease_attached` (Arc ptr_eq + rehydrate), `maybe_top_up_cos_queue_lease` (3 branches: transparent queue, exact queue with N-frame bank watermark, non-exact with lease), `refill_cos_tokens` (carry remainder logic #4261), `cos_refill_ns_until`.
  - Telemetry is cold (flushed at ~1s publish tick), but struct lives in same file as hot refill which does `saturating_add` + `min` + atomic loads. Mixing makes hot file larger.

- Proposed: new file `token_bucket/telemetry.rs` for `CoSQueueLeaseAcquireTelemetry` + `CoSQueueLeaseUndergrantCounters` (currently in `worker_runtime`), `token_bucket/lease_topup.rs` for hot top-up, `token_bucket/refill.rs` for `refill_cos_tokens` + `cos_refill_ns_until` + `COS_MIN_BURST_BYTES`. Parent `mod.rs` re-exports. Seam: telemetry never touches tokens; top-up touches both tokens and telemetry.

- Hot-path: top-up does at most one atomic CAS (v8 path) or one `AtomicU64` load (legacy), plus `tx_frame_capacity()` call (const fn). No alloc. Verification: `cargo test token_bucket_tests`.

- Labels: `refactor`

#### L-M2: queue_service/mod.rs duplicates backlog helpers that also live in tx_completion.rs — DRY violation

- Severity: Low
- Confidence: High
- Refactor class: C
- Evidence:
  - File: `queue_service/mod.rs:314-358` — `root_exact_demand_queue_mask`, `exact_demand_rate_bytes_for_mask`, `reset_nonexact_surplus_under_exact_budget`, `residual_rate_and_burst`, `nonexact_surplus_budget_under_exact_demand` (exact copy of backlog logic for residual budget?).
  - File: `tx_completion.rs:532-599` — `exact_backlog_queue_mask`, `exact_backlog_guarantee_rate_bytes_for_mask`, `serviceable_exact_backlog_bytes`, `exact_backlog_bytes`, plus shared_exact_backlog publish. Same mask logic: iterate queues, filter `exact && guarantee_enabled && serviceable`, fold bitmask `1u64 << queue_idx`.
  - The mask computation appears twice with identical predicate (hb166 T-6(b) serviceability gate) — once for publishing, once for consuming as `exact_demand_mask` in nonexact surplus budget. If predicate drifts between two copies, BE residual reservation diverges.

```rust
// queue_service/mod.rs:314-338 — duplicate of tx_completion.rs:532-556
fn root_exact_demand_queue_mask(root: &CoSInterfaceRuntime) -> u64 {
    let root_tokens = root.tokens;
    root.queues.iter().enumerate()
        .filter(|(_, q)| q.config.exact && q.config.guarantee_enabled && cos_exact_queue_serviceable(root_tokens, q))
        .fold(0u64, |acc, (idx, _)| if idx < 64 { acc | (1u64 << idx) } else { u64::MAX })
}
```

- Proposed: consolidate into `cos/backlog_masks.rs` or reuse `tx_completion::backlog.rs` after H-M3 split — single canonical `cos_exact_serviceable_mask(root_tokens, queues) -> u64` + `exact_rate_for_mask(queues, mask) -> u64`. Both `queue_service` and `tx_completion` import same fn. Add test that published `peer_exact_demand_queue_mask` OR-ed with local mask equals global demand mask used for BE residual cap.

- Hot-path: mask fold is O(N_queues) (N <= 64) with bit ops — cheap. Consolidating to one function keeps `#[inline]` so no call overhead. Verify via `cargo test` + `cargo asm` for `nonexact_surplus_budget_under_exact_demand` before/after.

- Labels: `refactor`

#### L-M3: rotate_epoch_v8.rs carry banking 3-regime logic + peer-util gate + bypass arm + equal-flow dispatch in one 446 LOC fn — no cold/hot split for the rare equal-flow branch

- Severity: Low (already isolated file, but internal structure still god-func)
- Confidence: Medium
- Refactor class: D (size warning, but file already focused)
- Evidence:
  - File: `rotate_epoch_v8.rs:34-446` — `maybe_rotate_epoch_v8` does: seq Acquire load → start Ns load → elapsed check → CAS EVEN→ODD → Release fence → tag pack → swap packed_granted + prev capture → scratch lock (uncontended) → starvation/demand swap per worker (O(N_workers) loop) → grants swap → carry window math (k_window_ns, stall_window_ns, prev_unclaimed banking, 3 regimes), then if `EqualFlowSuppress` → sample active flows + call `publish_equal_flow_epoch_v8`, else `disable_for_epoch`, then peer-util gate (CPU-bound <60%), aggregate underuse (cap/7), bypass arm/decay, total_flows sum, cap/grace/share publish, seq Release store.
  - 446 LOC with 3 regimes for carry + peer-util gate + bypass — but cold path (equal-flow) only runs when `rate_mode == EqualFlowSuppress`. The common path (`CstructDefault`) skips sampled_active_flows swap + equal-flow publish.
  - Scratch lock `Mutex<V8RotationScratch>` claimed uncontended by construction (only rotation winner). Good, but Mutex in hot 200 µs path is still one CAS per rotation.

- Proposed: internal helpers within same file: `compute_carry_regime(rate, elapsed_ns, prev_carry, prev_unclaimed, carry_max, k_window, stall_window) -> (elapsed_for_cap, carry_draw, new_carry)`, `capture_prev_grants_and_signals(v8, scratch) -> (signaled, demanded, active)`, `arm_bypass_if_needed(...)`. No new file needed — just helper fns with `#[inline]` for readability. Equal-flow dispatch already isolated via `publish_equal_flow_epoch_v8` call — good.

- Hot-path: rotation runs at most once per 200 µs per lease (EPOCH_DURATION_NS), not per packet. So not hot-path in packet sense, but on shaper's critical path for token replenishment. No allocation — all stack/boxed. Verify via `shared_cos_lease_tests` carry banking edge tests.

- Labels: `refactor`

### D-negatives (non-issues)

- D-N1: `shared_cos_lease/backlog.rs` (210 LOC) and `vtime.rs` (238 LOC) are already well-isolated cohesive modules with zero visibility widening — no further split needed. They implement single responsibility (interface-global backlog visibility / cross-worker V_min) and are re-exported via thin shell `mod.rs`. Keep as-is.

- D-N2: `publish_equal_flow_epoch_v8.rs` (247 LOC) is good size, single publish fn with fail-open guards + policy dispatch (Slowest/Mean/IdealShare). No further split — its 3-policy reduction over same sampled set is intentionally kept together to keep fail-open guards unified.

- D-N3: `FlowFairState::new_boxed` unsafe constructor — looks like Large Construct but is correct by design to avoid 352 KB stack frame (`__rust_probestack` 352 KB loop in `cos_queue_push_back`). Prior fix #1755 documented with field-equivalence test + miri guard. Not a D-negative to remove; keep but add field-count assert as suggested in M-M2.

- D-N4: `cos/queue_ops/pop.rs` fused out of production via #1763 Lever A (peek_min_bucket + pop_known_bucket eliminates second min-finish scan) — retained only for tests + reference oracle `fused_diff_tests.rs`. Not dead code; it's the differential test oracle — keep.

- D-N5: `priority_low_min_share_bytes` looks dead but is intentional wire surface for deferred cap_eff mechanism (#1614 A2, #4220). Field note "WIRE SURFACE ONLY" + "Currently UNUSED" is honest. Negative is that it lives in runtime not config — low-severity, already captured in H-M2 and L-M2, not separate finding.

- D-N6: `trigger_kernel_arp_probe` allocation-freedom — not in scope files (neighbor module). Confirmed no allocation in waterfill or lease acquire paths: waterfill uses only `u64`, `f64`, `usize`, no Vec/HashMap; lease acquire uses only atomic CAS loops, no Box. Requirement satisfied.

## Suggested split (cold/hot seam, zero hot-instruction change target)

The governing constraint: "split cold config/setup/stats/logging out WITHOUT changing one instruction of hot path, prove with disassembly diff + CoS smoke/fairness gates."

### Phase 0 — measurement baseline (before any move)

- Capture `cargo asm` for: `select_exact_cos_guarantee_queue_waterfill`, `acquire_v8_with_cause`, `drain_exact_local_items_to_scratch_flow_fair`, `apply_cos_send_result`, `cos_queue_push_back`.
- Capture `perf stat` for `cargo test --lib -- cos::queue_service` and synthetic drain bench if present.
- Run CoS smoke: proportional oversubscription + guarantee-rate oversubscription (100m/1g/5g under shaped root), exact + nonexact mix, flow-fair SFQ collision bound (200 flows → per-flow collision 4.7% at 4096 buckets), V_min throttle under shared_exact with 6 workers, equal-flow Slowest/Mean policy.

### Phase 1 — cold config/setup out

1. `types/cos.rs` → `types/cos/` directory:
   - `config.rs`: `CoSState`, `CoSInterfaceConfig`, `CoSQueueConfig`, `EqualFlowTargetPolicy`, `CoSDSCPClassifierConfig`, `CoSIEEE8021ClassifierConfig`, `CoSDSCPRewriteRuleConfig`, `CoSLossPriorityRewrite`, constants `COS_LOSS_PRIORITY_LEVELS`
   - `interface_runtime/mod.rs`: `CoSInterfaceRuntime` shell re-exporting sub-fields (or sub-struct grouping behind accessors)
   - `interface_runtime/waterfill_epoch.rs`: waterfill epoch cluster (7 fields) + `waterfill_refill_pass1_if_needed` helper (cold math)
   - `interface_runtime/shaping_state.rs`: token bucket cluster
   - `interface_runtime/rr_cursors.rs`: RR cursors + priority buckets
   - `flow_fair_state.rs`: `FlowFairState`, `FlowRrRing`, `CoSQueuePopSnapshot`, `VMinQueueState`, `CoSQueueRuntime`, `CoSQueueConfigState`, `CoSQueueHotState`, telemetry, sojourn (each could be own file, but keep together for size coherence — total ~800 LOC moved)
   - `flow_fair_state/constructors.rs`: `new_boxed` + `new` + tests
   - Keep `types/cos.rs` as re-export shell `pub(in crate::afxdp) use config::*; ...`

2. `queue_service/mod.rs` → `queue_service/` (already directory, but refactor):
   - `mod.rs` becomes dispatcher (~150 LOC): `drain_shaped_tx`, `build_nonexact_cos_batch`, `service_exact_guarantee_queue_direct_*`, `select_cos_guarantee_batch` (test-only legacy), `select_exact_cos_guarantee_queue_with_fast_path`, `select_nonexact_cos_guarantee_batch`, `select_cos_surplus_batch_filtered`, `estimate_cos_queue_wakeup_tick`
   - `waterfill/mod.rs` (already proposed in H-M1): epoch / phase1 / phase2 submodules
   - `refund.rs`: `refund_phase1_waterfill_honor` + `apply_phase1_waterfill_honor_refund` (hb166 T-2 refund path — currently 2 helpers in mod.rs that touch both root bitset and queue telemetry)
   - `selector.rs`: legacy Proportional RR selector `select_exact_cos_guarantee_queue_with_lease_telemetry` (pre-waterfill path) + helpers `cos_guarantee_quantum_bytes`, `cos_guarantee_visit_cap_bytes`

3. `tx_completion.rs` → `tx_completion/` (H-M3 proposal): timer_wheel / apply / backlog / activity. Each new file < 300 LOC.

Gate Phase 1: `cargo test`, `cargo asm` diff for 5 hot functions proves zero instruction change in hot packet path (only cold config/setup paths may change addresses). CoS smoke.

### Phase 2 — warm stats/logging out

4. `token_bucket.rs` → `token_bucket/` (L-M1): `telemetry.rs` (CoSQueueLeaseAcquireTelemetry + CoSQueueLeaseUndergrantCounters), `lease_topup.rs` (hot top-up), `refill.rs` (cold-ish refill + carry remainder), `release.rs` (release_all_*)

5. `queue_ops/mod.rs` → keep but extract:
   - `ordering.rs`: `cos_queue_min_finish_bucket`, `cos_queue_min_finish_bucket_no_cap` (MQFQ selection)
   - `serviceability.rs`: `cos_exact_queue_serviceable`, `cos_item_len` (predicate used by backlog masks + selectors)
   - `demotion.rs`: `maybe_demote_drained_best_effort`, `COS_DEMOTE_EMPTY_SETTLE_HYSTERESIS`

6. `queue_service/drain.rs` → `queue_service/drain/` with `common.rs` for preflight/suspension helpers + keep 4 variant fns (M-M4).

Gate Phase 2: same — asm diff for hot drain/service paths, CoS smoke, `make test-rust` + `make test-go` (since co-location changes nothing Go-side, but rename moves require `cargo test` cache bust).

### Phase 3 — hot lease internals (deferred, behind Phase 1-2 bake)

7. `shared_cos_lease/lease.rs` → `shared_cos_lease/acquire_v8/` (M-M1): primary + surplus + snapshot + release submodules. This is hot (acquire per drain) so gate with asm diff + lease Tests 2511 LOC + CoS smoke with v8 fair-share under 6 workers + equal-flow suppress mode smoke.

Note on `trigger_kernel_arp_probe` allocation-freedom: neighbor probe path must not allocate in hot path. Waterfill and lease paths already allocation-free (verified: no Vec/HashMap in selector loops, only CAS loops). Decomposition must not introduce allocation — e.g., don't clone `exact_queues_by_rate_ascending` per call (current code already avoids heap clone via index iteration — preserve). Verify with `cargo test` that no `alloc` crate usage in `#[inline]` hot fns via `#[deny(clippy::vec_init_then_push)]` lint.

### Summary table of suggested new modules

| New file | Moved from | LOC est | Hot? | Alloc? |
|----------|------------|---------|------|--------|
| `cos/queue_service/waterfill/mod.rs` | `mod.rs:925-1357` | 50 (dispatcher) | yes (selector) | no |
| `cos/queue_service/waterfill/epoch.rs` | `mod.rs:958-1031` | 80 | warm (200 µs tick) | no (f64 math only) |
| `cos/queue_service/waterfill/phase1.rs` | `mod.rs:1046-1226` | 180 | hot | no |
| `cos/queue_service/waterfill/phase2.rs` | `mod.rs:1227-1345` | 120 | hot | no |
| `cos/queue_service/refund.rs` | `mod.rs:518-577` | 60 | warm (ring-full only) | no |
| `cos/tx_completion/timer_wheel.rs` | `tx_completion.rs:128-467` | 300 | warm (50 µs tick) | no (scratch reused) |
| `cos/tx_completion/apply.rs` | `tx_completion.rs:631-1044` | 400 | hot | warm Vec only on drain-to-empty |
| `cos/tx_completion/backlog.rs` | both `tx_completion.rs:499-609` + `mod.rs:314-358` | 150 | warm (per TX completion) | no |
| `cos/types/cos/flow_fair_state.rs` | `types/cos.rs:919-1209` | 500 | cold (promotion) | one Box alloc once |
| `cos/types/cos/interface_runtime/waterfill_epoch.rs` | `types/cos.rs:590-668` | 80 | warm | no |

Total hot LOC untouched instruction-wise: waterfill selector loops keep same `&mut root.queues[queue_idx]` pattern, same lease top-up call, same park guard. Cold LOC (epoch refill f64 math, backlog mask fold) moves out with alloc-freedom preserved.

## Verification checklist for implementer

- [ ] For each extracted helper, keep `#[inline]` or `#[inline(always)]` on any function that was previously `#[inline]` and called from hot path (queue_service selectors, token_bucket top-up, queue_ops push/pop).
- [ ] No new `Vec::new` / `HashMap` / `Box::new` in any function that previously had zero allocation (waterfill phases, lease acquire primary/surplus, drain preflight).
- [ ] `cargo asm --lib <symbol>` diff before/after for 5 hot symbols; patch `Cargo.toml` not needed unless codegen-units change. Use `objdump -d -C` on release binary with debug symbols to verify inlining.
- [ ] `cargo test -p userspace-dp --lib` passes, especially `queue_service/tests`, `tx_completion_tests`, `shared_cos_lease_tests`, `flow_fair_state_tests`, `fused_diff_tests`.
- [ ] CoS smoke gates: oversubscription matrix (proportional vs guarantee-rate), exact+nonexact mix, V_min shared_exact 6-worker, equal-flow Slowest/Mean policy smoke.
- [ ] `perf stat` L1-dcache miss delta < 1% for drain path.
- [ ] Guarantee-guard #4246 regression: mid-rate exact class on/off pattern must not park at ClassCap — `waterfill_phase1_budget_breaks` + `drain_park_queue_tokens` counters unchanged shape.
- [ ] `trigger_kernel_arp_probe` (neighbor) not touched; verify no new allocation in neighbor hot path via audit.
- [ ] `make selftest` if touching image/dist/deploy tooling (not needed for this refactor, but keep in checklist per engineering-style).

---
Labels: `refactor`, `hot-path`, `x-hpc`
Work dir: /tmp/review-work-ps-043, worktree /tmp/review-wt-ps-043-a1c-b1 — remove after review ingestion.


---
### Batch ps-a1d-b1.md — 77484 chars

# A1d — Session table (session/*.rs) + session_glue — Modularity / Hot-Path Audit

Base SHA: 4e0c7f74cf0dbacf83051b2a9b6cf4e050dcecaa
Whoami: ps, NNN 043, Worktree: /tmp/review-wt-ps-043-a1d-b1/
Date: 2026-07-11
Scope files (LOCS at base SHA):
  session/mod.rs         2114  — god-struct coordinator, 27 fields (task said 25 @ prior prune, now 27 with next_session_id + worker_hi)
  session/lookup.rs       411  — per-packet hot lookup + NAT reverse-index bucket walk
  session/install.rs      521  — admission + fresh install + synced import + delta emit + demote
  session/expire.rs       625  — wheel sweep + HA standby retention gate + companion keepalive
  session/key.rs          232  — pure transforms
  session/entry.rs        284  — SessionMetadata 12 fields incl Arc, SessionDecision, SessionCounters, SessionDelta, ExpiredSession
  session/wheel.rs         80  — const WHEEL_BUCKETS + const assert power-of-two + target_tick_for + bucket_for_tick + SessionWheel struct
  session/ctx.rs          126  — SessionInstall owned, SessionUpdate borrowed, ExpireHaContext closures
  session/tests.rs       6994  — unit/property-style coverage of all paths
  afxdp/session_glue/mod.rs 1277 — resolve_flow_session_decision + forwarding res + HA res + BPF map publish + shared sync + worker cmd dispatch
  afxdp/session_glue/promote.rs 167 — SharedSessionRefs + maybe_promote_synced_session + purge_translated_synced_hit
  afxdp/session_glue/commands/*  5 files 340 LOC total

Prior DSG:
  #4421 SessionTable god-struct 27 fields already filed (7 resp) — still open, confirms this audit
  SessionEntry hot/cold fusion #4399 P5 NAT reverse-index — fixed structurally but left entry fused
  #919 LOCK XADD — zone names → zone-id u16 fixed, but SessionMetadata::policy_counter Arc<PolicyRuleCounter> re-introduced LOCK XADD on every metadata.clone() in hot path (lookup_with_origin)
  #964 slab+handle migration, #2005 code-motion split (mod → submodules via `use super::*`), #1752 in-place refresh, #1855 corruption contract
  #2120 standby retención gate, #4380 companion keepalive, #4109 forward↔reverse TCP state propagation, #3152 opening window, #3527 per-zone syn-flood override

---

## Inventory (ranked by size × resp × hot)

| Rank | File | LOC | Resp count (estimated) | Hot? (0-3) | Score (size×resp×hot) | Why |
|------|------|-----|------------------------|-----------|-----------------------|-----|
| 1 | session/mod.rs | 2114 | 7 (store+HA sync+limits+wheel+forwarding meta+telemetry+GC+accounting+session_id alloc) | 3 (touch_if_stale, account_packet, update_session hot) | ~44k | The god-struct; every field private but child modules access all via super::* |
| 2 | afxdp/session_glue/mod.rs | 1277 | 5 (forwarding resolution, HA resolution, BPF session-map mirror, shared-session publish/replicate, worker command dispatch) | 2 (resolve_flow_session_decision on every session miss, plus promotion publish) | ~12.8k | Cross-cutting: reads ForwardingState, HA runtime, BPF fds, shared Arc<Mutex> maps, worker queues |
| 3 | session/lookup.rs | 411 | 3 (primary lookup, NAT reverse/wire/alias indexes with bucket walk, GC scheduling) | 3 (lookup_with_origin = per-packet slow-path + flow-cache miss path) | ~3.7k | Hottest impl file touched via super::* → entries, key_to_handle, reverse_translated_index |
| 4 | session/install.rs | 521 | 3 (capacity preflight #1861, install + synced import, delta emit + demote RG) | 2 (new-flow path) | ~3.1k | Merges admission, counting, indexing, delta |
| 5 | session/expire.rs | 625 | 3 (wheel sweep, self-heal/hold/age decision, companion keepalive) | 1 (1 Hz GC cadence but touches every entry's cold fields) | ~1.9k | Complex three-way standby gate, re-bucket logic |
| 6 | session/entry.rs | 284 | 2 (SessionMetadata+Decision+Delta lifecycle, counters observation) | 2 (metadata.clone() on every packet hit via lookup) | ~1.1k | Metadata contains Arc → LOCK XADD #919 resurgence |
| 7 | session/key.rs | 232 | 1 (pure key transforms) | 2 (forward_wire_key, reverse_wire_key on hot install + lookup bucket validate) | ~464 | Exemplary pure functional module — NEGATIVE finding |
| 8 | session/tests.rs | 6994 | 1 (tests) | 0 | ~0 | Large but single-resp; validates all above, not part of modularity |
| 9 | session_glue/promote.rs | 167 | 2 (shared refs bundling, promote/purge predicates) | 1 (on HA promote path) | ~334 | Small, clear Copy bundling |
| 10 | session/wheel.rs | 80 | 1 (wheel pure helpers + const assert) | 0 | ~80 | Exemplary — NEGATIVE finding |
| 11 | session/ctx.rs | 126 | 1 (context structs grouping) | 0 | ~126 | Exemplary — NEGATIVE finding template |
| 12 | session_glue/commands/* | ~340 | 1-2 each | 1 | ~680 | Dispatcher split out |

Responsibility enumeration for mod.rs (7 resp per task, now 8 if counting session_id alloc separately):
  1 session store (entries Slab<SessionRecord>, key_to_handle)
  2 NAT forwarding metadata (nat_reverse_index, forward_wire_index, reverse_translated_index — SmallVec<[u32;2]> 1:N multimaps #4399/#4438)
  3 HA sync (owner_rg_sessions, deltas ring, delta_loss_pending, delta_drops/drained)
  4 per-IP limit (session_limit_active, src/dst counts maps — SeededIpMap<u32>)
  5 wheel timer (wheel SessionWheel, last_pop_stats, last_gc_ns)
  6 timeout/config (timeouts, opening_overrides FxHashMap<u16,u64>)
  7 telemetry/counters (epoch_counter, expired, create_drops, admission_refused, install_partial, nat_reverse_key_collisions)
  8 identity (next_session_id, session_id_worker_hi) #4915

---

## File-by-file log (read via worktree)

- `session/mod.rs:1-2114` — Reads 27-field struct declaration at line 513-674, consts for GC/wheel/timings, SeededKeyMap type aliases, SmallVec NatIndexBucket, SessionEntry 17 fields (decision, metadata, origin, install_epoch, last_seen_ns, created_ns, expires_after_ns, closing, reset, established, wheel_tick, seen_rg_epoch, first_held_ns, counters, observed_tos, observed_tcp_flags, session_id), SessionRecord {key, entry}, all private helpers handle_for_key/record_by_key/record_by_key_mut/entry_by_key/entry_by_key_mut/contains_key, public hot methods touch/touch_if_stale/account_packet/propagate_tcp_state_to_companion, update_session (Path E in-place refresh with reindex gate on nat/is_reverse/owner_rg_id change), refresh_for_ha_transition, drain_deltas, push_delta (ring cap 4096 + loss latch), remove_entry eager-cleanup invariant with debug no_index_points_at O(N), restore_entry dead-code reference, index_forward_nat_key_parts + remove_forward_nat_index_parts + nat_index_bucket_push/remove (1:N append not displace), session_timeout_ns (5-way branch), secs_to_ns_saturating, app_inactivity_timeout_ns clamp #3714. Submodule declarations `mod expire; mod install; mod lookup;` after debug_log! macro so macro in scope.

- `session/lookup.rs:1-411` — `use super::*;` first line (whole parent namespace). `TcpStatePropagation {nat, close, reset, established}` internal. `lookup/lookup_with_origin`: resolves handle from primary or via `resolve_reverse_translated_handle` (bucket walk + validate), snapshots timeouts + opening_override_ns before &mut borrow to avoid double-borrow, then &mut entries borrow mutates closing/reset/established/last_seen/expires_after, clones metadata (`metadata.clone()` → Arc clone LOCK XADD), clones key (`record.key.clone()`), calls propagate companion after borrow ends, then push_to_wheel canonical key. `find_forward_nat_match` bucket walk + `reply_matches_forward_session` validate-on-lookup. `find_forward_wire_match_with_origin` same pattern. `resolve_reverse_translated_handle` bucket walk. accessors `entry_with_origin`, `all_owner_rg_ids`, `owner_rg_session_keys`, `take_synced_local`, `iter_with_origin`, `iter_with_idle`. All accesses go through `self.entries`, `self.key_to_handle`, `self.nat_reverse_index` etc via super::*.

- `session/install.rs:1-551` — `use super::*;`. Admission preflight `can_admit`, counters `admission_refused`, `install_partial`, `create_drops`. `install_with_protocol_with_origin`: len check cap, remove_entry old (3 debug_assert guards), alloc_session_id #4915, builds SessionRecord with established derived from `is_initial_syn`, expires via `session_timeout_ns` (global + app override + opening_override), wheel_tick 0, seen_rg_epoch/first_held 0, counters default, observed_tos 0, observed_tcp_flags = tcp_flags, session_id allocated. insert slab, key_to_handle insert, index_forward_nat_key, push_to_wheel, session_limit_inc (counted if !reverse && !transient_seed), push_delta Open only if counted && !peer_synced. `upsert_synced_with_origin` allowance guard, same shape but imported ESTABLISHED=true (#3152), counters/observed zeroed, session_id fresh node-local. `emit_open_delta_with_origin`, `emit_close_delta_with_origin` (explicit close with 0 timestamps/counters). `delete`, `demote_owner_rg` (in-place flip with seed exception #3122 increment iff flip added counted class). All touch `self.entries`, `self.key_to_handle`, `self.owner_rg_sessions`, `self.session_limit_*`, `self.wheel`, `self.deltas` directly.

- `session/expire.rs:1-630` — `use super::*;` + `use super::wheel::{WHEEL_TICK_NS, WheelEntry, bucket_for_tick, target_tick_for}`. `wheel_observe` lazy init cursor from now_ns/N (otherwise billions of empty buckets). `push_to_wheel` throttled by canonical tick change, writes entry.wheel_tick. `expire_stale_entries` gate 1s, wrapper around `expire_stale_entries_ha(now_ns, None)`. `expire_stale_entries_ha`: reset last_pop_stats before GC-interval gate, last_gc_ns gate, wheel_observe, now_tick = now_ns/WHEEL_TICK_NS, while cursor < now_tick drain bucket len snapshot (allocation-free), for each WheelEntry: entry gone → dropped_gone, wheel_tick != scheduled → dropped_stale, else idle-crossed if now-last_seen > expires_after → HA gate standby_gate_decision (pure closure-in), self-heal (re-stamp last_seen, record epoch, rebucket), hold (stamp first_held_ns if 0, explicitly NOT stamping seen_rg_epoch — Codex MAJOR fix documented), reap stale synced ceiling, aged_owner_rg_zero, Age fallthrough. Then companion_keeps_alive #4380 (probe reverse_session_key, if companion still within idle window re-stamp from companion's last_seen, rebucket, counted kept_alive_by_companion), only on companion_eligible path (deliberate reaps clear flag). Else remove_entry, emit Close delta if !reverse && !peer_synced && !transient_seed, push ExpiredSession.

- `session/key.rs:1-232` — `use super::*;` for PROTO_* but otherwise pure. `SessionKey {addr_family, protocol, src_ip, dst_ip, src_port, dst_port}`. `reply_matches_forward_session`, `forward_wire_key`, `translated_session_key`, `reverse_wire_key` (pub(super)), `reverse_canonical_key`, `reverse_session_key` (pub(crate), ICMP special cased #4074: src_port holds query id, translated id lives in rewrite_src_port forward / rewrite_dst_port reverse, or() picks correct). All pure transforms, no &mut self, exemplary.

- `session/entry.rs:1-284` — `use super::*;` for ForwardingResolution, NatDecision, Nat64ReverseInfo. `SessionDecision {resolution, nat}`, SessionMetadata 12 fields: ingress_zone u16, egress_zone u16, owner_rg_id i32, fabric_ingress bool, is_reverse bool, nat64_reverse Option, log_session_init, log_session_close, policy_id u32, inactivity_timeout_ns Option<u64>, policy_counter_idx u32, policy_counter Option<Arc<PolicyRuleCounter>> (Arc is #3322 bound handle). Equality ignores policy_counter. SessionLookup, ForwardSessionMatch, SessionOrigin (8 variants), SessionDeltaKind, SessionDelta (created_ns, last_seen_ns, counters, observed_tos, observed_tcp_flags, session_id u64), ExpiredSession. Arc inside metadata means metadata.clone() in lookup.rs does LOCK XADD.

- `session/wheel.rs:1-80` — `use super::*;` for SESSION_GC_INTERVAL_NS. `WHEEL_BUCKETS=256`, `WHEEL_MASK`, `WHEEL_TICK_NS=SESSION_GC_INTERVAL_NS` (binds cadence), `FAR_FUTURE_OFFSET=255`, `const _: () = assert!(WHEEL_BUCKETS.is_power_of_two())` compile-time invariant, `bucket_for_tick` inline mask trick, `target_tick_for` floors expiration to tick boundary + saturating + clamp to FAR_FUTURE_OFFSET, `WheelEntry {key, scheduled_tick}`, `SessionWheel {buckets Box<[VecDeque<WheelEntry>]>, cursor_tick, initialized}`. New() allocates Vec of VecDeque with capacity WHEEL_BUCKETS. Exemplary tiny module.

- `session/ctx.rs:1-126` — No super::* (imports explicit). `SessionInstall {key owned, decision, metadata, origin, now_ns, protocol, tcp_flags}`, `SessionUpdate<'a> {key borrowed &'a SessionKey, ...}` (avoids owned copy at 3 call sites in session_glue/mod.rs:1071). `ExpireHaContext<'a> {node_active bool, forwards_rg &dyn Fn(i32)->bool, epoch_of &dyn Fn(i32)->u32, ceiling_mult, ceiling_abs_ns}` + `stale_ceiling_ns` method min(mult*timeout, abs). Documents HA types don't leak into crate::session. Exemplary context grouping #1357.

- `afxdp/session_glue/mod.rs:1-1277` — Mixes `resolution_target_for_session`, `cached_session_resolution`, `populate_egress_resolution`, `lookup_forwarding_resolution_for_session` (with tunnel id reuse guard #1873, cached fast path, ECMP spread by forward_key hash #2734), `owner_rg_is_locally_active`, `synced_entry_allows_local_replace`, `redirect_session_resolution_for_metadata`, `owner_rg_is_unseeded`, `should_bypass_unseeded_tunnel_ha`, WorkerCommandResults {cancelled_keys, exported_sequences, export_owner_rgs, shaped_tx_requests, vacate_all_shared_exact_slots}, `force_live_redirect_for_worker_synced_entry`, `session_key_has_lo0_filter`, `republish_local_delivery_sessions_for_lo0_filter`, `purge_sessions_for_input_dscp_filter_revalidation`, `publish_worker_session_map_entry` (LO0 filter → publish_live vs delete+publish with SESSION_PUBLISH_ERRORS_SHARED counting #1789), `delete_terminal_filtered_session`, `forward_export_candidates_for_owner_rgs` (filter forward+local+ForwardCandidate|FabricRedirect, no peer_synced/transient_seed/fabric_ingress), `export_forward_sessions_for_owner_rgs` #[cfg(test)], `apply_worker_commands` (try_lock_recover, sample now_ns once per tick invariants #1346, handle DemoteOwnerRGS/RefreshOwnerRGS/ExportOwnerRGSessions/UpsertSynced/UpsertLocal/DeleteSynced/EnqueueShapedLocal/VacateAllSharedExactSlots, rep maintains hot_hash_seed gating), replicate upsert/delete via lock_recover, `should_teardown_tcp_rst` returns false (deliberate), `teardown_tcp_rst_flow`, `cancel_queued_flow`, `route_cancelled_shared_recycles`, `cancel_queued_flow_on_binding`, `cancel_pending_forwards`, `recycle_cancelled_prepared`, `tx_request_matches_flow`, `prepared_request_matches_flow`, `pending_forward_matches_flow`, `materialize_shared_session_hit`, `resolve_flow_session_decision` (central new-flow + session-hit resolver: lookup_session_across_scopes, poison_key transient keep logic should_keep_synced_hit_transient, purge_translated_synced_hit, materialize_shared_session_hit, resolution_target + lookup + prefer_local_for_fabric_ingress + enforce_session_ha_resolution + redirect_session_via_fabric_if_needed + maybe_promote_synced_session, then forward NAT match branch install_reverse_session_from_forward_match, ADMISSION #1861 created flag + install_failed replumbing). Heavy BPF map fd plumbing + shared Arc<Mutex<FastMap<SyncedSessionEntry>>>.

- `session_glue/promote.rs:1-167` — `SharedSessionRefs<'a> {sessions, nat_sessions, forward_wire_sessions, owner_rg_indexes}` Copy 32 bytes, used to collapse 16-param maybe_promote. `is_translated_forward_session_key`, `should_keep_synced_hit_transient`, `maybe_promote_synced_session` (promotes only if origin.is_promotable_synced && resolution ForwardCandidate, stamps owner_rg via owner_rg_for_resolution if <=0, fabric flag, promote via promote_synced_with_origin(SessionUpdate) + publish_session_map_entry_for_session + publish_shared_session + replicate), `purge_translated_synced_hit` (remove shared, delete BPF map, delete local).

- `session_glue/commands/*` — demote_owner_rgs re-evaluates HA managed sessions via iter_with_origin, refresh_owner_rgs collects items via iter_with_origin + lookup_forwarding_resolution + enforce_ha + redirect, upsert_synced handles allowance guard + synced_entry_allows_local_replace, delete_synced, export_owner_rg_sessions records RGs (not inline emit #2653 chunked drain-as-you-export). Split out per #1346.

---

## Findings

### HIGH

#### H1 — SessionTable 25→27-field god-struct; submodules access all private fields via `super::*` — code-motion not decomposition

- Title: SessionTable god-struct 27 fields 7 responsibilities; child modules reach all private fields via `use super::*`
- Severity: High
- Confidence: High
- Refactor class: C (Structural decomposition + interface narrowing, no hot-path instruction change Phase 1)
- Evidence:
  File `/tmp/review-wt-ps-043-a1d-b1/userspace-dp/src/session/mod.rs:513-674` — struct def:
  ```rust
  pub(crate) struct SessionTable {
      entries: slab::Slab<SessionRecord>,
      key_to_handle: SeededKeyMap<u32>,
      nat_reverse_index: SeededReverseIndex,
      forward_wire_index: SeededForwardWireIndex,
      reverse_translated_index: SeededReverseTranslatedIndex,
      owner_rg_sessions: FxHashMap<i32, FxHashSet<u32>>,
      deltas: VecDeque<SessionDelta>,
      last_gc_ns: u64, max_sessions: usize,
      timeouts: SessionTimeouts, opening_overrides: FxHashMap<u16, u64>,
      epoch_counter: u64, expired: u64, create_drops: u64,
      admission_refused: u64, install_partial: u64,
      delta_drops: u64, delta_loss_pending: bool, delta_drained: u64,
      nat_reverse_key_collisions: u64,
      wheel: SessionWheel, last_pop_stats: WheelPopStats,
      session_limit_active: bool,
      session_limit_src_counts: SeededIpMap<u32>, session_limit_dst_counts: SeededIpMap<u32>,
      next_session_id: u64, session_id_worker_hi: u64,
  }
  ```
  7 responsibilities task-listed; reality 8 inc #4915 identity. Every child file opens with:
  ```rust
  // session/lookup.rs:15
  use super::*;
  // session/install.rs:29
  use super::*;
  // session/expire.rs:14
  use super::*;
  // session/entry.rs:8
  use super::*;
  // session/key.rs:7
  use super::*;
  // session/wheel.rs:11
  use super::*;
  ```
  So install.rs directly touches `self.entries`, `self.key_to_handle`, `self.owner_rg_sessions`, `self.session_limit_*`, `self.wheel`, `self.deltas`, `self.next_session_id` — same for lookup.rs touching wheel, key_to_handle, nat indexes, entries, timeouts, opening_overrides. No accessor boundary. `mod.rs:328-342` comment acknowledges "These declarations sit AFTER debug_log! so macro in textual scope … submodules all attach impl SessionTable blocks. Bodies are byte-for-byte identical; this file only changes the module boundary." IOW #2005 was pure code-motion, not decomposition. Code retains a single `&mut self` for all resp — serialized under worker-owned single-writer, but cognitive coupling high; change to per-IP limit may accidentally touch wheel fields.

- Proposed decomposition (phased, instruction-preserving for Phase 1):
  NEW STRUCTS inside mod.rs, still by-value composition so layout unchanged (no Box):
  - `struct SessionStore { entries: Slab<SessionRecord>, key_to_handle: SeededKeyMap<u32> }` — methods: `handle_for_key`, `record_by_key`, `record_by_key_mut`, `entry_by_key`, `len`, `remove_slab_entry` internal.
  - `struct SecondaryIndexes { nat_reverse: SeededReverseIndex, forward_wire: SeededForwardWireIndex, reverse_translated: SeededReverseTranslatedIndex, owner_rg: FxHashMap<i32, FxHashSet<u32>> }` — methods: `index_forward_nat_key_parts`, `remove_forward_nat_index_parts`, `bucket_walk` etc. Owns collision counter via `&mut u64` or returns bool collided.
  - `struct SessionTelemetry { epoch_counter, expired, create_drops, admission_refused, install_partial, delta_drops, delta_drained, nat_reverse_key_collisions, next_session_id, session_id_worker_hi }` — cold, only touched on install/GC/admission paths, not on lookup fast path (except epoch_counter, alloc_session_id). Field offset change only, same allocation — no extra pointer chase.
  - `struct SessionLimits { active: bool, src_counts: SeededIpMap<u32>, dst_counts: SeededIpMap<u32> }` — methods: `inc`, `dec`, `count_src`, `count_dst`, `set_active(rebuild via &Store)`, `clear`. OFF-gate branch preserved.
  - `struct TimeoutConfig { timeouts: SessionTimeouts, opening_overrides: FxHashMap<u16,u64> }` — methods: `resolve(protocol, flags, established, app_override_ns, zone)` pure; `set_timeouts`, `set_opening_overrides`.
  - `struct DeltaRing { deltas: VecDeque<SessionDelta>, loss_pending: bool, last_gc_ns: u64, last_pop_stats: WheelPopStats }` (wheel separate)
  - Wheel already in wheel.rs but `SessionWheel` stays; glue method `push_to_wheel` becomes delegate `self.wheel_state.push(&Store, key, now)` with throttling.

  Seam: `SessionTable` becomes facade containing these sub-structs by value:
  ```rust
  struct SessionTable {
      store: SessionStore,
      indexes: SecondaryIndexes,
      timeouts: TimeoutConfig,
      limits: SessionLimits,
      telemetry: SessionTelemetry,
      delta: DeltaRing,
      wheel: SessionWheel,
      max_sessions: usize,
  }
  ```
  Methods in submodules take `&mut self.store, &mut self.indexes` etc. as disjoint borrows where possible, enabling future extraction into separate files without super::*. First PR moves field groups verbatim (no logic change, only `self.xxx` → `self.store.xxx`), proves assembly-identical hot path via `cargo asm --lib session::SessionTable::lookup_with_origin` before/after (objdump disassembly diff). Second PR narrows to dedicated `store.rs`, `indexes/nat.rs`, `limits.rs`, `telemetry.rs`, `timeouts.rs`, `delta.rs`.

- Hot-path preservation analysis:
  Applies: inlining, alloc, dispatch, layout, locality, lock.
  - Inlining: new methods must be `#[inline]` and in same crate, LTO preserves. Before/after verify via `cargo rustc -- --emit asm` that `lookup_with_origin` call graph unchanged (no new callq to `SessionLimits::count` in hot touch path except the existing branch).
  - Alloc: sub-structs by-value, no Box, no extra allocation, Slab still grows on demand (`Slab::new()` not `with_capacity`). Bench `insert_churn` must not regress RSS.
  - Dispatch: no dyn dispatch added (closures in ExpireHaContext remain &dyn Fn, already present).
  - Layout: field reordering may change cache-line placement of hot fields (entries vec ptr, key_to_handle ptr). Preserve by `#[repr(C)]`? No — first PR keeps field order identical by defining facade fields in same order as today (entries, key_to_handle, nat..., etc) but grouped via comments; Rust layout of nested struct is flattened in order? Structure containing structs has fields laid out in declaration order, inner struct fields contiguous in order, so global order preserved if sub-struct field order preserves outer order. Must assert. Verify via `std::mem::offset_of!` tests.
  - Locality: separating counters into cold struct may improve locality for hot path (hot fields concentrated). Acceptable change if prove instruction count unchanged (extra lea for nested offset is same as direct field offset — compiler folds).
  - Lock: worker-owned &mut self single-writer stays; no new Mutex.

  HOW to verify: 
  - Build criterion `benches/session_table.rs` plus new micro-bench `lookup_with_origin` (see H2) before/after; gate ≤ ±3% noise (Cold config move should be zero-instruction on hot path beyond lea).
  - `cargo asm` (or `cargo rustc -- --emit asm` + `rg lookup_with_origin`) diff — require identical instruction stream for `lookup_with_origin`, `touch_if_stale`, `account_packet` (the three hot methods).
  - `cargo test -p xpf-userspace-dp --lib session` + `cargo test -p xpf-userspace-dp` (includes loss userspace HA gates if env) stays green.
  - Smoke gate: loss:xpf-userspace-fw0 `test-failover` manual if cluster available — session sync during failover must not flap (covers expire HA gate interaction with new modules).

- Tests+gate:
  - Existing `session/tests.rs` 6994 LOC covers all branches (stale handle guards, #4377 back-count rebuild, #2120 self-heal, #4380 companion) — must pass untouched.
  - New unit tests for sub-modules: limits rebuild from store (covers OFF→ON), telemetry alloc_session_id uniqueness (low 48bits + hi worker), timeouts resolve precedence.
  - Criterion bench gate: new bench `benches/session_table.rs` already exists; add `lookup_with_origin` bench exercising 16k table with mixed forward/reverse + alias + NAT buckets len 1-2 (realistic). Gate: new-task hot path cannot regress >5%.
  - Behavioral gate: cargo test + test-failover (session sync during failover). Provision `CLUSTER_LAN_HOST=loss:cluster-userspace-host` (auto) if available.

- Why it matters: 27-field god-struct with super::* is mod-visibility illusion — any file can mutate any field, breaking encapsulation; code-motion #2005 hid growth, now at >2000 LOC coordinator + 7 responsibilities. Contributors touching per-IP limit inadvertently touch wheel epoch or delta loss latch; compiler gives no protection. Further HA features (like #4915 session_id, #3322 Arc counter) added fields organically; without decomposition the hot path keeps absorbing cold state (opening_overrides HashMap lookup in lookup.rs pre-borrow). Long-term violates engineering-style.md hot-path allocation rule and review severity.

- Fix direction (ordered incremental PRs):
  1. **PR1 cold config extraction zero-instruction**: Move `timeouts+opening_overrides` into `TimeoutConfig`, `session_limit_*` into `Limits`, telemetry counters into `Telemetry`, deltas+loss+last_gc+pop_stats into `DeltaRing` — keep methods in mod.rs, only `self.x` → `self.sub.x`. Add `#[inline]` accessors. Prove via `cargo asm` diff that `lookup_with_origin`, `touch_if_stale`, `account_packet` unchanged instruction-wise. No logic change.
  2. **PR2 index extraction**: Move NAT bucket push/remove + owner_rg helpers into `indexes/nat_index.rs` + `indexes/owner_rg.rs`, take `&mut SecondaryIndexes, &mut Telemetry (for collision counter), &Store`. Keep signatures that return hit counts identical. Gate via existing NAT collision tests + `session_table` benches reverse_nat/alias.
  3. **PR3 store + entry split** (see H2): Hot/cold SessionEntry split + SessionStore isolation. Gate via lookup bench.
  4. **PR4 wheel boundary narrowing**: `push_to_wheel` / `wheel_observe` become methods on `WheelState` that takes `&Store::entry_by_key` + &mut Wheel + now, not &mut self whole table — reduces borrow scope, removes need for &mut SessionTable in hot path.
  5. **PR5 cleanup**: Remove `super::*` from submodules, replace with explicit `use crate::session::{SessionKey, ...}` + `use super::store::SessionStore` narrow imports, enforcing boundaries; CI clippy private field access fails if boundary violated.

- Labels: `area:session`, `type:refactor`, `risk:medium`, `size:L`, `hot-path`, `modularity`

- Dedup note: Supersedes #4421 (27 fields) but goes further — #4421 was inventory-only; this proposes phased decomposition with asm证明. Does NOT duplicate #4399 P5 NAT reverse-index (already shipped as SmallVec multimap), nor #919 LOCK XADD zone-id fix (shipped) but notes Arc regression. Unique focus on super::* technical debt vs functional NAT bucket fix.

#### H2 — SessionEntry hot/cold fusion 17 fields; per-packet `metadata.clone()` does Arc clone LOCK XADD ~10ns @7.5M pps/worker

- Title: SessionEntry 17-field hot/cold fusion with HA gate + accounting + wheel + policy Arc on hot path — Arc clone per packet
- Severity: High
- Confidence: High
- Refactor class: B (data layout optimization + API change borrow-return, no Box)
- Evidence:
  File `session/mod.rs:344-471`:
  ```rust
  struct SessionEntry {
      decision: SessionDecision,           // hot — needed for forwarding resolution NAT
      metadata: SessionMetadata,           // hot-ish but contains cold Arc
      origin: SessionOrigin,               // colder (HA)
      install_epoch: u64,                  // cold telemetry?
      last_seen_ns: u64,                   // hot — keepalive stamp
      created_ns: u64,                     // cold (close report)
      expires_after_ns: u64,               // hot — timeout window
      closing: bool, reset: bool, established: bool, // hot TCP state
      wheel_tick: u64,                     // cold — GC scheduling
      seen_rg_epoch: u32, first_held_ns: u64, // cold HA standby gate #2120
      counters: SessionCounters,           // warm — accessed on every packet via account_packet but mutated separate path
      observed_tos: u8, observed_tcp_flags: u8, // cold (close export)
      session_id: u64,                     // cold (close export)
  }
  ```
  Hot per-packet mutations in `lookup.rs:177-189`:
  ```rust
  let entry = &mut record.entry;
  entry.closing = true;
  entry.reset |= has_rst(tcp_flags);
  // ...
  entry.last_seen_ns = now_ns;
  entry.expires_after_ns = ...
  // ...
  SessionLookup { decision: entry.decision, metadata: entry.metadata.clone() }
  ```
  `metadata.clone()` at `mod.rs:183` and `lookup.rs:183,240,281` clones `Option<Arc<PolicyRuleCounter>>` which does `LOCK XADD` (atomic inc) per atomic docs — task estimates ~10ns @7.5M pps/worker = 75ms/sec/core lost in refcount traffic + cross-core cache-line bounce if Arc shared across workers? Actually Arc is per-rule shared across workers (PolicyState::rules[idx].hit_counter Arc) so refcount is contented across cores.

  Also `record.key.clone()` at `lookup.rs:187` clones SessionKey (IpAddr + ports) 40+ bytes copy per packet hit.

  Bench existing `benches/session_table.rs` only benchmarks `BenchKey -> BenchEntry` map lookup, not the real `SessionEntry` layout with Arc clone. No lookup_with_origin micro-bench.

- Proposed decomposition (no Box, no pointer chase, same slab allocation, field-offset change only per task):
  Define inline split:
  ```rust
  #[derive(Clone, Copy)] struct SessionHot {
      decision: SessionDecision,
      // metadata hot subset: ingress_zone, egress_zone, owner_rg_id, fabric_ingress, is_reverse, policy_id, policy_counter_idx, log flags, inactivity_timeout_ns, nat64_reverse (Option small) — EXCLUDING Arc
      ingress_zone: u16, egress_zone: u16, owner_rg_id: i32,
      fabric_ingress: bool, is_reverse: bool,
      // maybe keep rest cold
      origin: SessionOrigin,
      last_seen_ns: u64,
      expires_after_ns: u64,
      closing: bool, reset: bool, established: bool,
      // policy counter index + raw pointer pinning (see below)
      policy_counter_idx: u32,
      policy_counter_ptr: *const PolicyRuleCounter, // raw, no refcount, pinned by PolicyState lifetime
  }
  struct SessionCold {
      install_epoch: u64, created_ns: u64,
      wheel_tick: u64, seen_rg_epoch: u32, first_held_ns: u64,
      counters: SessionCounters,
      observed_tos: u8, observed_tcp_flags: u8,
      session_id: u64,
      // full metadata cold parts: nat64_reverse, log flags, policy_id, inactivity override, policy_counter Arc (if still needed for binding refresh)
      nat64_reverse: Option<Nat64ReverseInfo>,
      log_session_init: bool, log_session_close: bool,
      policy_id: u32, inactivity_timeout_ns: Option<u64>,
      policy_counter: Option<Arc<PolicyRuleCounter>>, // retained for binding lifecycle, not cloned on hot path
  }
  #[repr(C)] struct SessionRecord { key: SessionKey, hot: SessionHot, cold: SessionCold }
  // or keep SessionEntry { hot, cold } to keep API shallow
  ```
  BUT task says inline SessionHot/SessionCold split (no Box, no pointer chase, same slab allocation field-offset change only). So slab still `Slab<SessionRecord>` with hot fields first (cache line 0-1) then cold (line 2+). Decision already CacheLine-aligned? Need to measure layout via `std::mem::size_of` + `offset_of`.

  Eliminate Arc clone via borrow-return: `lookup_with_origin` returns `SessionLookupRef<'a>` borrowing metadata rather than owned clone, or returns reference to hot portion plus separate counter increment via raw pointer (pinning). Policy hit counter fast path uses `policy_counter_ptr` raw pointer to `AtomicU64` (PolicyRuleCounter has atomic), so increment without Arc clone. Arc retained only in cold path for binding refresh and when policy snapshot rotates (needs upgrade). Alternative: store `policy_counter: Option<Weak>`? But raw pointer with lifetime tied to PolicyState version is acceptable because worker holds PolicyState Arc and ensures counter lives longer than session entry (rule deletion removed from counter_snapshots but counter Arc still alive via store? Actually store re-hands same Arc for surviving rule_id, deleted rule Arc dropped but session entries referencing it via raw pointer would dangle — so need fallback: if deleted, use Option<NonNull> that becomes null and fast path skips increment; close path not needed).

  Simplified first step: Borrow-return API change — `lookup_with_origin` returns `(SessionDecision, &SessionMetadata, SessionOrigin)` with lifetime tied to `&self`, avoiding clone entirely. Callers in poll_descriptor that need owned metadata for promotion can clone explicitly cold.

  Bench gate: `lookup_with_origin` micro-bench in `benches/session_table.rs` (or new `session_lookup.rs`) that populates table with 16k entries each with `policy_counter: Some(Arc::new(...))`, then bench loop:
  ```rust
  b.iter(|| { for k in probes { black_box(table.lookup_with_origin(k, now, flags)) } })
  ```
  Measures Arc clone cost. After split, Arc clone removed → ~10ns win.

- Hot-path preservation analysis:
  Applies: inlining (hot struct field accesses remain direct offsets, compiler can fold `entry.hot.last_seen_ns` to same offset as prior `entry.last_seen_ns` if hot fields first and same order — need offset_of test), alloc (same Slab allocation, no extra indirection, hot/cold in same record, no Box), dispatch (none), layout (field reordering changes offset; must keep hot fields at same cache-line start to preserve prefetch, verify via `cargo rustc -- --emit llvm-ir` and check GEP offsets), locality (hot fields packed together improves L1 utilisation — 64-byte cache line holds 5-6 hot fields vs today spread over 120+ byte struct spilling over 2 lines), lock (unchanged, still worker-owned &mut, but eliminating Arc atomic removes implicit lock xadd on cache line).

  HOW to verify:
  - `std::mem::size_of::<SessionEntry>` before/after, `align_of`, `offset_of!(SessionEntry, last_seen_ns)` style.
  - `cargo bench --bench session_table` before/after — new `lookup_with_origin` bench must show improvement or neutral.
  - `perf stat -e cycles,instructions,LLC-load-misses` on helper process under synthetic pps? In VM test-env, run `cargo test --benches` for timing.
  - Disassembly diff: `objdump -d target/release/deps/session-*.o | grep -A30 lookup_with_origin` before/after — must show no extra call to `Arc::clone` (no `lock xadd`).
  - HA failover gate: after layout change, concurrent promotion reading cold Arc must still be valid (lifetime).

- Tests+gate:
  - Existing session tests cover TCP close propagation, HA gate, companion keepalive — must pass with new layout (field offset does not change logic).
  - New test: `assert_eq!(size_of::<SessionRecord>(), old_size)` or <= old size (hot/cold split must not grow).
  - New bench `lookup_with_origin` micro-bench with Arc-present metadata — gate 10ns win target at 7.5M pps/worker ~75ms/core saved.
  - Integration: `make test` (Go + Rust) + cluster `test-failover` if available — ensures NM (no Arc) doesn't break binding re-resolution (#3395) that relies on `policy_counter` Arc for stable rule_id.

- Why it matters: Per-packet path at 7.5M pps/worker is 133ns per packet budget total; 10ns for Arc atomic is ~7.5% of budget wasted on refcount traffic plus cross-core inval of shared counter slab (MESI). Multiplied by 6 workers on mlx5 VF cluster, 45M pps global → 450ms atomic time per second system-wide. Also cache-line pollution — SessionEntry 17 fields ~>128 bytes, hot path touches 5 fields but pulls two cache lines of cold data (counters, observed_*, session_id, wheel_tick, seen_rg_epoch, first_held). IPIs? No, but L1 pressure high. Aligns with engineering-style.md hot-path allocation rules.

- Fix direction:
  1. PR1: Add `SessionHot`/`SessionCold` structs inline, same Slab allocation, keep `SessionEntry { hot, cold }` with Deref for backward compat (or field access `entry.hot.xxx` in hot path). Move cold fields: wheel_tick, seen_rg_epoch, first_held_ns, counters, observed_*, session_id, created_ns, install_epoch into cold. Keep decision, origin, last_seen, expires_after, closing/reset/established in hot. Keep metadata split: hot subset (ingress_zone, egress_zone, owner_rg_id, fabric_ingress, is_reverse) first; full metadata including Arc moved to cold but accessed via borrow on miss promotion. No Box. Gate with bench (size_of + offsets). Must not change one instruction on cold config move — prove with disassembly.
  2. PR2: Eliminate `metadata.clone()` in lookup path: change `lookup_with_origin` return to borrow or introduce `SessionLookupRef`. For policy_counter, replace `Option<Arc>` clone in hot path with raw pointer pinning: store `*const PolicyRuleCounter` in hot, increment via unsafe raw deref (safe because PolicyCounterStore guarantees counter lives at least as long as worker holds PolicyState version, and session cleanup ensures no dangling? Need Option<NonNull> + fallback). Alternatively keep Arc in cold but add method `hit_counter_ptr()` that returns *const without clone.
  3. PR3: Benchmark-driven removal of `record.key.clone()` in lookup — return `&SessionKey` borrow plus canonical key via reference rather than clone.
  4. PR4: After hot/cold split clean, re-measure `account_packet` path — ensure `counters` moved cold but mutated hot? counters is per-packet accounting — debated hot vs warm. #2501 says forward accounting on every packet via account_packet; if moved cold, it becomes cross-cache-line write still? Could keep counters in hot's second cache line but as plain u64s (no atomic). Decide.

- Labels: `area:session`, `perf:hot-path`, `type:refactor`, `risk:high`, `size:M`, `bench:required`, `failover:required`

- Dedup note: Overlaps with TODO for #4399 P5 NAT reverse-index (bucket walk remains hot but now on hot struct) — but distinct focus. Also relates to #919 LOCK XADD follow-up (zone-id fixed, but Arc reintroduced). Not duplicative of #4421 (god-struct) — this is data layout inside entry, not table.

#### H3 — session_glue/mod.rs 1277 LOC mixed forwarding + HA + BPF publish + shared sync + worker command dispatch; per-miss path holds many responsibilities

- Title: session_glue god-module 1277 LOC coupling forwarding resolution, HA fabric redirect, BPF map mirroring, shared session sync, and worker command dispatch in single file
- Severity: High (coupling impacts testability + failover correctness)
- Confidence: High
- Refactor class: C (module decomposition + dependency inversion)
- Evidence:
  `session_glue/mod.rs:1-1277` declares `mod commands; mod promote;` then defines 25+ pub(super) fns spanning:
  ```rust
  pub(super) fn resolution_target_for_session(...) -> IpAddr { decision.nat.rewrite_dst... } // pure transform, fits key.rs style
  pub(super) fn cached_session_resolution(...) -> Option<...> { /* forwarind cache validation */ }
  pub(super) fn populate_egress_resolution(state: &ForwardingState, ...) // forwarding
  pub(super) fn lookup_forwarding_resolution_for_session(...) -> ForwardingResolution { // includes tunnel id reuse guard #1873, ECMP hash #2734
  pub(super) fn owner_rg_is_locally_active(...) // HA predicate
  pub(super) fn synced_entry_allows_local_replace(...) // HA
  pub(super) fn redirect_session_resolution_for_metadata(...) // fabric redirect zone-id encoded
  pub(super) fn session_key_has_lo0_filter(...) // filter interaction
  pub(super) fn republish_local_delivery_sessions_for_lo0_filter(...) // iterates full session table via iter_with_origin, publishes BPF map
  pub(super) fn purge_sessions_for_input_dscp_filter_revalidation(...) // collects stale vec then teardown each
  pub(in crate::afxdp::session_glue) fn publish_worker_session_map_entry(...) // BPF map FD + SESSION_PUBLISH_ERRORS_SHARED counter #1789
  pub(super) fn delete_terminal_filtered_session(...) // BPF delete + shared remove + replicate delete + close delta
  pub(crate) fn forward_export_candidates_for_owner_rgs(...) // owner RG export filter #2442/#2653
  pub(super) fn apply_worker_commands(...) -> WorkerCommandResults { /* try_lock_recover, loop over commands */ } // 200 LOC dispatcher + handlers
  pub(super) fn resolve_flow_session_decision(...) -> Option<Resolved...> { // per-miss central, 200 LOC, ties everything together
  ```
  Promotion code lives in `promote.rs` 167 LOC but still accesses `crate::afxdp::bpf_map::SESSION_PUBLISH_ERRORS_SHARED` and shared maps.

  Child `commands/` already split out per variant but still `use super::super::*;` → accesses `SessionTable`, `ForwardingState`, `HAGroupRuntime`, `ShardedNeighborMap`, `WorkerCommand`, BPF fds, shared ses maps all via parent glob.

  Result: changing HA predicate (e.g., fix standby vs active publish decision #4805) requires touching file that also knows BPF map FD layout and ECMP hashing; tests for forwarding cache validation live in `tests.rs` 5748 LOC alongside HA transient logic.

- Proposed decomposition:
  - `session_glue/forwarding.rs`: `resolution_target_for_session`, `cached_session_resolution`, `populate_egress_resolution`, `lookup_forwarding_resolution_for_session*`, ECMP hash helper. Input: &ForwardingState, &SessionFlow, SessionDecision. Output: ForwardingResolution. No HA, no BPF fds.
  - `session_glue/ha_res.rs`: `owner_rg_is_locally_active`, `synced_entry_allows_local_replace`, `owner_rg_is_unseeded`, `should_bypass_unseeded_tunnel_ha`, `redirect_session_via_fabric_if_needed`, `enforce_session_ha_resolution`, `redirect_session_resolution_for_metadata`. Input: ForwardingState, HA state map, ingress_zone, etc. Pure/predicate.
  - `session_glue/bpf_mirror.rs`: `publish_worker_session_map_entry`, `session_key_has_lo0_filter`, `republish_local_delivery_sessions_for_lo0_filter`, `purge_sessions_for_input_dscp_filter_revalidation`, `delete_terminal_filtered_session`, BPF map error counters. Owns fd + error handling #1789, no forwarding logic.
  - `session_glue/shared_sync.rs`: `forward_export_candidates_for_owner_rgs`, `export_forward_sessions_for_owner_rgs`, `replicate_session_upsert/delete`, `materialize_shared_session_hit`, shared Entry types. Talks to shared Arc<Mutex<FastMap>>.
  - `session_glue/flow_resolver.rs`: `resolve_flow_session_decision` orchestrator that composes forwarding.rs + ha_res.rs + shared_sync.rs + bpf_mirror.rs — narrow seam: takes `&SessionTable`, `&ForwardingState`, `&HA`, `&NeighborMap`, `&SessionFlow` etc but delegates substeps via explicit params, not `super::*` glob.
  - Keep `promote.rs` but narrowing dependencies: input shared refs + forwarding, not whole worker.
  - `commands/` stays but imports from narrowed modules, not `super::super::*`.

  Each new module's public API uses concrete types, not `super::*`. File size targets: <300 LOC each.

- Hot-path preservation:
  Applies: inlining (forwarding resolution ECMP hash must stay inlined in miss path — mark `#[inline]`), dispatch (no new Box<dyn>, remain fn), alloc (no new Vec in hot miss path except existing export vec — already bounded), locality (less icache pollution by splitting cold BPF mirror code away from hot forwarding res lookup). Verify via `cargo test` + `cargo bench` of `resolve_flow` micro-bench if available + test-failover (failover exercises HA predicates + fabric redirect + shared sync).

- Tests+gate:
  - Existing `session_glue/tests.rs` 5748 LOC — must pass; split assertions per module (forwarding cache validation tests go to `forwarding::tests`, HA predicate tests to `ha_res::tests`).
  - Unit test for ECMP spread: same forward_key hash deterministic, different forward keys spread.
  - Cluster gate: `make cluster-deploy && make test-failover` (requires loss cluster, per task). Session sync during failover must retain synced sessions, not double-count, fabric redirect still works. Document that `forward_export_candidates_for_owner_rgs` filtering (`!is_reverse && !peer_synced && !transient_seed && !fabric_ingress && disposition ForwardCandidate|FabricRedirect`) stays identical.
  - Bench: flow miss path latency (poll_descriptor integration) — not regress.

- Why it matters: session_glue is de facto second god-struct bridging three subsystems (forwarding, HA, BPF). Changes to tunnel endpoint id reuse (#1873) risk breaking HA predicate; changes to LO0 filter (#941) risk breaking shared sync. Engineering-style.md says keep solutions simple+direct — current mixing makes review severity hard. Splitting reduces reasoning surface for per-module reviews and enables independent fuzzing of pure forwarding res logic.

- Fix direction:
  1. PR1: Extract pure helpers — `resolution_target_for_session`, `cached_session_resolution`, `populate_egress_resolution`, `owner_rg_is_locally_active`, `synced_entry_allows_local_replace`, `redirect_*` into `forwarding.rs`/`ha_res.rs` without logic change. Keep `pub(super)` visibility internally. Prove via `cargo test session_glue`.
  2. PR2: Extract BPF mirror functions into `bpf_mirror.rs`, introduce trait for error counting (so tests can capture without global). Keep FD passing explicit.
  3. PR3: Extract `resolve_flow_session_decision` orchestration into `flow_resolver.rs` that calls new modules via narrow params, not `super::*`. Gate with failover.
  4. PR4: Narrow `commands/` imports to not use `super::super::*` but explicit.

- Labels: `area:session-glue`, `type:refactor`, `risk:medium`, `size:L`, `failover:required`

- Dedup note: Issue 70 / #994 abstraction-leak audit previously moved `reverse_session_key` from session_glue into session/key.rs (docs in key.rs:159-172) — exemplar for this refactor. This extends that: more pure transforms still in glue that belong in session/key or forwarding. Not duplicate — continuation.

---

### MEDIUM

#### M1 — NAT reverse-index 1:N bucket walk + validate-on-lookup interleaves telemetry counter bump with hot lookup; SmallVec<[u32;2]> growth path heap spills under collision flood

- Title: NAT indexes 1:N multimap bucket walk on hot lookup path carries collision counting + heap spill risk without isolation
- Severity: Medium
- Confidence: High
- Refactor class: B (extract nat_index module with hot/cold separation)
- Evidence:
  `mod.rs:26-44`:
  ```rust
  type NatIndexBucket = SmallVec<[u32; 2]>;
  type SeededReverseIndex = HashMap<SessionKey, NatIndexBucket, FxSeededState>;
  ```
  `mod.rs:2008-2044`:
  ```rust
  fn nat_index_bucket_push(map: &mut HashMap<..., NatIndexBucket, _>, collisions: &mut u64, key: SessionKey, handle: u32) {
      let bucket = map.entry(key).or_default();
      if bucket.contains(&handle) { return; }
      let collided = !bucket.is_empty();
      bucket.push(handle);
      if collided { *collisions = collisions.saturating_add(1); }
  }
  fn nat_index_bucket_remove(map: &mut HashMap<..., NatIndexBucket, _>, key: &SessionKey, handle: u32) { ... bucket.retain(|h| *h != handle); if empty { map.remove(key); } }
  ```
  Hot path bucket walk in `lookup.rs:215-244`:
  ```rust
  let bucket = self.nat_reverse_index.get(reply_key)?;
  for &handle in bucket.iter() {
      let Some(record) = self.entries.get(handle as usize) else { continue; };
      if entry.metadata.is_reverse || !reply_matches_forward_session(&record.key, ...) { continue; }
      return Some(...)
  }
  ```
  Same for forward_wire_index, reverse_translated_index. Comments note common case len=1 zero-heap SmallVec inline free vs N=1, but N=2 same union size as N=1 because heap variant dominates — good micro-opt.

  Telemetry `nat_reverse_key_collisions` incremented inside push, guarded by bucket not empty. This counter is cold (published per-worker ~1Hz) but mutation occurs on install hot path (new-flow). Mixed.

  Risk: SmallVec N=2 means 3+ colliding sessions spill to heap (allocation) on hot install path — #4399/#4438 fix comment says interface-mode SNAT, DNAT-to-shared-backend, NAT64 can cause non-bijective mapping. In worst case (many clients to same translated IP:port) bucket could grow >2 and allocate per new colliding flow.

- Proposed decomposition:
  Create `session/indexes/nat.rs` owning the three maps + bucket type + push/remove with collision callback. Methods:
  - `NatIndexes::new(seed)` constructors,
  - `get_reverse_bucket(&self, key) -> Option<&[u32]>`,
  - `push_reverse(&mut self, key, handle) -> bool collided`,
  - `remove_reverse(&mut self, key, handle)`,
  similarly forward_wire, reverse_translated.
  Implement `NatIndexBucket` as enum optimized: inline array [0;2] + len, or keep SmallVec but isolate.

  Hot/cold: push's collision counting moved to `&mut self.collision_counter` via return value, not inline &mut u64 param that aliases telemetry struct — but make `push` return bool and let caller bump counter outside hot loop? Actually push's collided detection is extra branch; can keep but move counter bump to cold extension (caller passes `&mut Telemetry` cold side). Lookup bucket walk stays pure read-only, no telemetry touching.

  Additional: Consider fixed inline capacity 4 (not 2) to keep 2-way collision common path + 2 extra without heap, at cost of larger bucket size (4*4=16 bytes + len). Tradeoff vs slab cache line. Bench.

- Hot-path preservation:
  Applies: alloc (SmallVec heap spill avoidance critical — must not regress), inlining (bucket walk must inline into `find_forward_nat_match`), layout (bucket array size influences cache footprint of secondary index map).

  Verification: bench `lookup_reverse_nat` and `lookup_alias` in existing `benches/session_table.rs` + new bench with colliding bucket len 1,2,4. Gate: len=1 path unchanged, len=2 no heap, len=3+ measured.

- Tests+gate:
  - Existing tests for reverse-index collision (`tests.rs` with interface SNAT no port translation scenarios) — must pass.
  - New stress: create 100 sessions with same reverse_wire_key (pool SNAT no port) assert bucket len 100, lookup returns correct via validate, remove drains heap without leak, no_index_points_at still holds.
  - Criterion bench: `lookup_reverse_nat/slab` existing plus new colliding.

- Why it matters: #4399 P5 was NAT reverse-index hijack bug — fix shipped as 1:N multimap but left hot path mixing cold telemetry and heap spill. Under interface-mode SNAT (common on loss cluster reth with shared IP), many sessions share same reverse tuple — bucket grows, heap allocation per new flow defeats zero-alloc goal. Isolating into module enables future optimization (stable small-array, or count-min for pre-validation) without touching SessionTable god-struct.

- Fix direction:
  1. Extract bucket type + push/remove into `session/indexes/mod.rs` + `nat.rs`.
  2. Change counter bump to return `bool` and bump in telemetry module outside hot loop (or pass `&mut u64` but via cold side).
  3. Evaluate N=4 inline capacity — bench vs N=2, keep zero-heap for typical 2-way.

- Labels: `area:session`, `perf:hot-path`, `type:refactor`, `risk:low`, `size:M`

- Dedup note: Extends #4399 fix (P5) — not duplicate, focuses on isolation + heap-risk, while P5 was correctness hijack.

#### M2 — Per-IP session-limit counting co-located with hot store, shares &mut self whole table, OFF-gate branch on every inc/dec + rebuild walk O(N) on enable #4377

- Title: Per-IP limit counts (src/dst) co-located in god-struct with hot lookup, single &mut self serializes and rebuild O(N) under lock
- Severity: Medium
- Confidence: High
- Refactor class: B
- Evidence:
  `mod.rs:643-661`, `825-917`:
  ```rust
  session_limit_active: bool,
  session_limit_src_counts: SeededIpMap<u32>,
  session_limit_dst_counts: SeededIpMap<u32>,
  pub fn set_session_limit_active(&mut self, active: bool) {
      if !active { clear }
      else if !self.session_limit_active {
          for (key, handle) in &self.key_to_handle {
              if let Some(record) = self.entries.get(*handle as usize) {
                  if !record.entry.metadata.is_reverse && !record.entry.origin.is_transient_local_seed() {
                      *src_counts.entry(key.src_ip).or_insert(0) +=1
  ```
  This rebuild walks entire table O(N) where N up to 131k per worker — under `&mut self` exclusive, blocking forwarding. Happens rarely (OFF→ON edge on config reload). Still cold path holding hot lock.

  Hot path touches:
  ```rust
  fn session_limit_inc(&mut self, ...) {
      if !self.session_limit_active { return; }
      let c = self.session_limit_src_counts.entry(...).or_insert(0);
      *c = c.saturating_add(1);
  }
  ```
  Branch on `session_limit_active` on every fresh install (hot) — ~99% deployments OFF, branch mispredict noise.

- Proposed decomposition:
  `session/limits.rs` module owning `active`, `src`, `dst` maps, with methods:
  - `inc(src,dst)`, `dec(src,dst)`, `count_src`, `count_dst`, `set_active(active, &Store)` where Store is read-only view (`&FxHashMap`-ish) to rebuild, `clear`, `len_map`.
  OFF-gate branch stays one branch but moved out of SessionTable; hot path `account_packet` does NOT touch limits (only install/remove). Good.

  Future: Use `Cell` or atomic for active flag to avoid borrow? Not needed.

  Isolate counted-class predicate (`!is_reverse && !transient_seed`) as method on `SessionRecord` or function `is_counted_class(origin, is_reverse)`.

- Hot-path preservation:
  - inlining, alloc: rebuild O(N) still allocates but isolated; inc/dec still one hash probe per src/dst (two), unavoidable.
  - layout: removing two maps from hot struct reduces its size, improves locality for hot store.

  Verify: bench `insert_churn` with limit active vs inactive.

- Tests+gate:
  - Existing `session_limit_*` tests (`session_limit_backcount_on_enable_covers_preexisting_sessions`, `session_limit_clear_on_disable`) — must pass.
  - New test: enable after 10k sessions, assert counts rebuilt = counted-class count.
  - Gate: cargo test session limit.

- Why: Limits feature configured on <1% deployments but code path present on every install; OFF-gate branch is noise but okay. Bigger issue is complexity: limit logic interleaved with HA origin handling (#3122 origin-agnostic fix, #4377 back-count). Isolating clarifies counted-class transitions (promote/demote neutrality) which previously double-counted bug.

- Fix direction:
  PR1 (part of H1) extract Limits, PR2 add `is_counted_class` helper, PR3 consider lock-free read for count queries (new-flow check reads via `session_limit_src_count` which is &self only, not &mut, already OK).

- Labels: `area:session`, `area:screen`, `type:refactor`

- Dedup: Extends #2134/#3122/#4377. Not dup.

#### M3 — Delta ring + loss latch + GC timing + telemetry fused: VecDeque with cap 4096, plain bool latch, stats accumulators — cold HA sync path touches same &mut self as hot Open delta push

- Title: Delta ring VecDeque<SessionDelta> (cap 4096) + loss bool + pop stats + last_gc fused with hot install path
- Severity: Medium
- Confidence: Medium
- Refactor class: B
- Evidence:
  `mod.rs:545-591`:
  ```rust
  deltas: VecDeque<SessionDelta>,
  last_gc_ns: u64,
  max_sessions: usize,
  ...
  delta_drops: u64,
  delta_loss_pending: bool,
  delta_drained: u64,
  ```
  `mod.rs:1656-1670`:
  ```rust
  fn push_delta(&mut self, delta: SessionDelta) {
      if self.deltas.len() >= MAX_SESSION_DELTAS { // 4096
          self.delta_drops = ...;
          self.delta_loss_pending = true;
          return;
      }
      self.deltas.push_back(delta);
  }
  ```
  Hot install path calls `push_delta` on every forward install (forward direction only) — branches on len, may allocate? VecDeque with_capacity min(256) grows? Cap check prevents overflow but inner VecDeque may still grow allocation on push when len == capacity (realloc). At 4096 cap edge under heavy churn (syn flood), delta ring overflow causes latch set true, triggers full RG export via #2442 chunked drain-as-you-export. Cold path shares &mut self with hot.

  Last_pop_stats accumulators built in expire.rs but field lives in mod.rs.

- Proposed decomposition:
  New `session/delta.rs`: struct `DeltaRing { ring: VecDeque<SessionDelta>, loss_pending, drops, drained, last_gc_ns, last_pop_stats }` with methods `push`, `drain`, `take_loss`, `set_loss`. Owns ring capacity logic. Optionally use fixed-size ring buffer (array + head/tail) to avoid VecDeque growth alloc in hot path. Current VecDeque growth: with_capacity min(256) up to 4096, each resize allocates.

  Separate `WheelPopStats` already in mod.rs but move to wheel.rs or delta.rs as nearby.

- Hot-path preservation:
  - alloc: push_delta currently may allocate when VecDeque grows; pre-alloc 4096 avoids per-push alloc but wastes memory per worker (6×4096×~80B=~2MB). Fixed ring avoids alloc entirely. Must verify.
  - dispatch/inlining: trivial.

- Why: HA sync correctness depends on delta ring not dropping events. #2442 loss latch + #2653 chunked export were fixes for overflow. Isolating delta ring enables testing overflow + resync without full SessionTable.

- Fix direction: Extract delta.rs, add test for overflow latch + drain.

- Labels: `area:session`, `type:refactor`, `area:ha`

#### M4 — Timeout resolution 5-way branch + HashMap lookup per packet (app override, opening_override)

- Title: session_timeout_ns 5-way branch + opening_overrides FxHashMap lookup on hot lookup path
- Severity: Medium (minor perf but correctness complexity high)
- Confidence: Medium
- Refactor class: B
- Evidence:
  `mod.rs:2074-2110`:
  ```rust
  fn session_timeout_ns(protocol, tcp_flags, established, timeouts, app_override_ns, opening_override_ns) -> u64 {
      match protocol {
          PROTO_TCP => {
              if is_closing(...) { RST vs FIN }
              else if !established { opening_override_ns.unwrap_or(tcp_opening_ns) }
              else { app_override_ns.unwrap_or(tcp_established) }
          }
          PROTO_UDP => app.unwrap_or(udp),
          ...
      }
  }
  ```
  Called from `install.rs:164` and `lookup.rs:158-171` and `mod.rs:1368`. In lookup.rs it captures `opening_override_ns` via `self.opening_overrides.get(&zone)` before borrow.

  Opening overrides map built from screen snapshot per zone syn-flood timeout #3527. Empty map common case — early return None when map empty.

  App override per-application inactivity timeout #3227 + clamp #3714.

  So per-packet lookup does:
  - `entries.get(handle).map(|r| ingress_zone)` + `opening_override_for` hash probe (if map not empty) before hot borrow.
  - Then timeout selection branches.

- Proposed decomposition:
  `session/timeouts.rs` with struct as described, method `resolve(protocol, tcp_flags, established, metadata) -> u64` that internally reads app override (Option<u64>) and zone map, but isolates logic. Further optimize: store opening_overrides as tiny array indexed by zone_id if zone_id space small (u16) — currently FxHashMap with maybe 1-2 entries. Could store as `Option<(u16, u64)>` for single zone case fast path. Not required now.

  Document that empty map short-circuit is hot-path friendly (single branch).

- Hot-path preservation:
  - inlining, layout: timeout config cold, accessed only via reference + one HashMap probe. Could pre-compute per-zone array for O(1) without hash.

- Why: Composing 5 timeout windows (#3152 opening, #3046 RST, #3489 closing stickiness, #3227 per-app, #3527 per-zone syn-flood) in one fn is complex; bug in branch ordering could reap established sessions on opening window or vice versa. Isolation enables exhaustive table test.

- Fix direction: Extract to timeouts.rs with exhaustive matching table-driven tests.

- Labels: `area:session`, `type:refactor`

#### M5 — session_glue apply_worker_commands 200 LOC dispatcher with try_lock_recover + now_ns sampling + Command enum 8 variants mixing trivial and complex — coupling to worker lifetime

- Title: Worker command dispatcher mixing poll loop concerns (now_ns sampling) with bpf fd + shared maps + forwarding + ha in single fn
- Severity: Medium
- Confidence: Medium
- Refactor class: C
- Evidence:
  `mod.rs:552-728` — `apply_worker_commands` does try_lock_recover, emptiness early return, `let now_ns = monotonic_nanos(); let now_secs = now_ns / 1e9;` sampled once per tick per #1346 invariant 3, then match over 8 variants. Complex variants delegated to `commands::handle_*` but dispatcher still owns `WorkerCommandResults` aggregation (cancelled_keys, exported_sequences, export_owner_rgs, shaped_tx_requests, vacate flag). Trivial variants upsert_local inline debug_asserts around origin is_peer_synced. Uses `worker_queue::try_lock_recover` + `lock_recover`.

  Mixing concerns: now_ns sampling belongs to worker loop_body (caller's responsibility), not glue. BPF fds passed through but only used in some variants.

- Proposed decomposition:
  Move dispatcher to `session_glue/worker_commands/dispatcher.rs` with struct `CommandContext { sessions: &mut SessionTable, session_map_fd, forwarding, ha_state, dynamic_neighbors, now_ns, now_secs }`. Each handler takes &mut context, not 5-7 individual args. Now sampling hoisted to worker loop_body caller passing context (still once per tick). Trivial variants remain inline or separate file.

  Future: Make `apply_worker_commands` return iter of results lazily? But okay.

- Why: Worker command queue is lock-contention-sensitive hot path (try_lock). Dispatcher currently 200 LOC doing sampling + aggregation. Harder to unit test without live BPF maps.

- Labels: `area:session-glue`, `type:refactor`

---

### LOW

#### L1 — ctx.rs owned vs borrowed key asymmetry: SessionInstall owned key forces clone at 3 call sites in session_glue

- Evidence: ctx.rs:31-60 `SessionInstall {key: SessionKey}` owned, `SessionUpdate<'a> {key: &'a SessionKey}` borrowed to avoid clone (`session_glue/mod.rs:1071` comment). Install path callers that already own key must clone? Actually upsert_synced_with_origin takes Install owned, so key moved — good. But resolve_flow_session_decision materialize path clones replica.key for Install. Minor.

- Proposed: Keep as is, but unify to borrowed key for install too with `SessionInstallRef<'a>` or generic. Low priority.

#### L2 — Entry.rs equality ignoring policy_counter Arc is subtle but documented; could use wrapper type BoundCounter

- Evidence: entry.rs:128-150 custom PartialEq that ignores policy_counter field because bound derived handle (not wire identity). Comment explains. Risk: future fields added may be forgotten to add to eq.

- Proposed: Newtype `BoundPolicyCounter(Option<Arc<PolicyRuleCounter>>)` with PartialEq that always returns true, or store policy_counter as separate field outside SessionMetadata (in SessionCold) so derived Eq can derive. Low.

#### L3 — Wheel.rs bucket size magic 256 tied to FAR_FUTURE_OFFSET 255 but not generic over bucket count — power-of-two assert good, but tick NS bound to SESSION_GC_INTERVAL_NS via const import which is in mod.rs — circular-ish

- Evidence: wheel.rs binds WHEEL_TICK_NS to SESSION_GC_INTERVAL_NS (imported via super::*). If GC interval changes, wheel tick changes — documented as must match. Fine but could be param.

- Why low: Already mitigated by comment and assert.

---

### D — NEGATIVES (exemplary patterns — template for future extraction)

#### D1 — key.rs pure transforms 232 LOC exemplary

- File: `session/key.rs:1-232`
- What is exemplary: Stateless functions `forward_wire_key`, `translated_session_key`, `reverse_wire_key`, `reverse_canonical_key`, `reverse_session_key`, `reply_matches_forward_session` all take `&SessionKey + NatDecision` and return `SessionKey` — no &mut self, no side effects, no global state, no super::* beyond proto consts. ICMP #4074 identifier handling clearly branched, well commented. Unit tests cover IPv4/IPv6 + ICMP vs TCP/UDP port mapping. Fits exact template needed for forwarding resolution pure helpers still languishing in session_glue.

- Why template: Future extraction of NAT reverse-index key recovery should follow same shape. Enables property testing.

- Labels: `positive`, `pattern: pure-transform`

#### D2 — wheel.rs power-of-two compile-time assert + const separation + pure helpers exemplary

- File: `session/wheel.rs:1-80`
- Exemplary: `WHEEL_BUCKETS=256`, `WHEEL_MASK`, `FAR_FUTURE_OFFSET`, `const _: () = assert!(WHEEL_BUCKETS.is_power_of_two(), "...")` compile-time invariant preventing footgun if someone changes bucket count. `bucket_for_tick` and `target_tick_for` pure inline fns, no self. `SessionWheel` only struct with Box<[VecDeque<WheelEntry>]> + cursor + initialized. No business logic interleaving. Mirrors docs/pr/965.

- Template: How to guard bit-mask trick invariants. Future timeout config could similar assert on max.

#### D3 — ctx.rs #1357 context structs exemplary — template for future extraction

- File: `session/ctx.rs:1-126`
- Exemplary: Groups previously positional 7-field clusters into named structs `SessionInstall` (owned key) and `SessionUpdate<'a>` (borrowed key) avoiding 7-arg drift. Documents operational control flags (`allow_replace_local`, `ha_activation`) intentionally stay positional outside struct — not part of payload, prevents callers populating fields callee overwrites. `ExpireHaContext` captures HA forwarding predicates as closures `&dyn Fn(i32)->bool` / epoch reader, hoists `node_active` bool once per expire call, documents fallback for out-of-range RG to node-level `rg_epochs[0]`, includes ceiling calculation method `stale_ceiling_ns`. All no embedding, no Drop, Copy where possible. Comment explains Borrow vs Owned choice (`poll_descriptor` path etc). This is template for resolving remaining positional arg functions in session_glue (maybe_promote 13 params).

---

## Cross-cutting hot-path analysis (lookup_with_origin + account_packet + touch_if_stale)

Current hot path per packet (flow cache miss → session hit path; flow cache hit → touch_if_stale + account_packet):

1. `lookup_with_origin(key, now_ns, tcp_flags)`:
   - handle_for_key via primary HashMap probe (FxHashMap with seeded hasher, one extra usize seed) — hash of SessionKey (5-tuple)
   - OR alias via `resolve_reverse_translated_handle` bucket walk (len=1 common → one iter + key equality)
   - snapshot timeouts + opening_override_ns via `entries.get(handle)` + `opening_overrides.get(zone)` (hash probe if map non-empty)
   - &mut entries borrow: mutates closing/reset/established/last_seen/expires_after → dirty cache line, but must
   - clone metadata (Arc clone → LOCK XADD) + clone key
   - propagate_tcp_state_to_companion if close/promote → second HashMap probe + maybe push_to_wheel
   - push_to_wheel canonical key → target_tick_for + bucket_for_tick + maybe VecDeque push

2. `account_packet(key, len, tcp_flags, dscp)` [#2501]:
   - record_by_key_mut probe → if !is_reverse: bump fwd counters + stamp ToS + OR flags, return
   - else snapshot (key, nat) copy → reverse_session_key recovery → entry_by_key_mut forward probe → bump rev counters + OR flags, fallback to reverse entry if forward gone

3. `touch_if_stale(key, now_ns)` flow-cache fast path:
   - record_by_key read → compute refresh_after = expires_after / 4, compare now-last_seen >= refresh_after
   - If stale: touch → entry_by_key_mut + push_to_wheel

Critical items preserved: single-writer &mut self, no lock, no allocation on steady-state hot (except SmallVec heap spill rare, VecDeque push in push_to_wheel when tick changed — throttled), plain u64 saturating_add for counters, OR for tcp_flags.

Arc clone is the regression: metadata.clone() does `Arc::clone(&policy_counter)` → `LOCK XADD` on refcount word shared across workers (same Arc for same rule_id). At 7.5M pps/worker trigger this clone per packet on session hit path (lookup) — not on account_packet/touch path but on new-packet-of-established-flow cache miss? Actually flow cache hit path does NOT call lookup_with_origin; it calls touch_if_stale + account_packet. So Arc clone not on per-packet flow-cache hit, only on flow-cache miss (slow path) which still could be high during churn. But still ~10ns per miss.

Inline hot/cold split: hot fields (decision, ingress/egress zone, owner_rg, flags, last_seen, expires, TCP state, origin) packed into first cache line (64B), cold (wheel_tick, seen_rg_epoch, first_held_ns, counters 32B, observed_*, session_id, created_ns, install_epoch, nat64_reverse) in second/third lines, so hot path touches first line only unless cross-companion or GC. Today struct size ~ 17 fields + metadata 12 fields + decision ~  (approx 200+ bytes) — at least 4 cache lines, hot touches spread.

No Box: keeping same Slab allocation means `Slab<SessionRecord>` grows as Vec of Record; Record size determines capacity-per-page. Splitting into hot/cold inline does not add pointer indirection (Box would add heap alloc per session = killer).

Eliminate Arc clone via borrow-return: Change `lookup_with_origin` to return `(&SessionDecision, &SessionMetadata, SessionOrigin)` borrowed, or new `SessionLookupRef<'a>` that holds `&'a SessionDecision` + `&'a SessionMetadata`. Caller that needs owned (promote, delta emit) clones explicitly outside hot loop.

Bench gate: Existing `benches/session_table.rs` does not bench real SessionTable with Arc; add new bench `benches/session_lookup.rs` that exercises real crate::session::SessionTable (maybe via pub for bench feature) with metadata containing `policy_counter: Some(Arc::new(PolicyRuleCounter{...}))`. Measure lookup_with_origin latency before/after hot/cold split. Target: ≤ baseline after cold extraction, win after Arc removal ~8-12ns.

Verification methods required by task:
- Disassembly diff: `cargo rustc -p xpf-userspace-dp --release -- --emit asm -C debuginfo=0` + `objdump` on bench binary's lookup_with_origin symbol. Must show identical instruction count for cold-config extraction PR (Phase1), reduced `call __rustc` + `lock xadd` after Arc removal PR (Phase2).
- test-failover: cluster HA session sync during failover exercises: (a) `expire_stale_entries_ha` self-heal edge (epoch before publish ordering), (b) `resolve_flow_session_decision` poison_key transient keep, (c) `forward_export_candidates_for_owner_rgs` filter, (d) `account_packet` reverse→forward counter fold. Failover must not lose synced sessions, must not double-count per-IP limit, fabric redirect must survive. Loss cluster: `loss:xpf-userspace-fw0/fw1` + `cluster-userspace-host`.

---

## Fix direction — ordered incremental PRs (no hot-path instruction change until proven)

**PR0 — scaffolding (no functional change)**:
- Add criterion bench `benches/session_lookup.rs`: populates 16k real SessionTable with realistic NAT variety (pool SNAT bijective len1 + interface SNAT no-port collided len2 + DNAT shared backend len2), metadata with Arc counter Some, benches lookup_forward, lookup_reverse_nat, lookup_alias, lookup_with_origin (new), account_packet forward/reverse, touch_if_stale stale vs fresh. Gate baseline numbers in PR description. Add `std::mem::size_of` + offset_of assertions for SessionEntry, SessionRecord as tests.

**PR1 — cold config extraction (zero hot-path instruction change) — satisfies task focus first sentence**:
- Extract `TimeoutConfig`, `SessionLimits` (without rebuild logic change), `SessionTelemetry` (counters + next_session_id + worker_hi + epoch_counter), `DeltaRing` into dedicated submodules `session/timeouts.rs`, `session/limits.rs`, `session/telemetry.rs`, `session/delta.rs`. Keep `SessionTable` facade containing them by value in same field order as today (preserve layout). Change accesses from `self.timeouts` → `self.timeouts.timeouts` etc but keep identical codegen via `#[inline(always)]` forwarding methods. Prove via `cargo asm` diff that `lookup_with_origin`, `touch_if_stale`, `account_packet`, `expire_stale_entries_ha` assembly identical (allow lea offset diff if struct nesting adds one lea that folds? Must be zero extra instructions — if extra lea appears, use `#[repr(C)]` or flatten). Gate with `cargo test`.

**PR2 — NAT indexes isolation**:
- Move `NatIndexBucket`, `nat_index_bucket_push/remove`, `SeedeReverseIndex` etc plus `resolve_reverse_translated_handle`, `find_forward_nat_match`, `find_forward_wire_match_with_origin` bucket walk into `session/indexes/nat.rs`. Methods return slices, not clones. Collision counter bump returns bool collided → caller bumps telemetry outside hot lookup loop (already cold). SmallVec N review (2→4) bench. Gate via reverse_nat/alias benches + existing collision tests.

**PR3 — SessionEntry hot/cold inline split (field-offset change only, same slab, no Box)**:
- Define `SessionHot`/`SessionCold` as described, keep `SessionRecord { key, hot, cold }`. Move `wheel_tick, seen_rg_epoch, first_held_ns, counters, observed_*, session_id, created_ns, install_epoch` to cold. Keep hot minimal. Update all `record.entry.xxx` accesses to `record.hot.xxx` or `record.cold.xxx` — mechanical. Ensure `#[repr(C)]` + field order preserves hot first, cold after, no padding blowup. Assert `size_of::<SessionRecord>() <= old + padding` (should be same or slightly larger due to alignment but not heap). Gate via `lookup_with_origin` bench, check no Box allocation via ` cargo rustc -- --emit mir` no alloc.

**PR4 — eliminate Arc clone per packet**:
- Change `SessionMetadata::policy_counter` handling: Option<Arc> stays in cold for lifecycle, but hot path uses raw pointer `*const PolicyRuleCounter` or `Option<NonNull<PolicyRuleCounter>>` derived from Arc at install time (Arc::into_raw / from_raw pattern with extra ref kept in cold). Implement `SessionHot::hit_counter_ptr()` returning *const atomic counter, increment via `unsafe { &*ptr }.packets.fetch_add`. Or safer: store `Option<usize>` index into PolicyState counter array and resolve at BPF mirror time? But fast path needs counter increment every packet — raw pointer is okay if PolicyCounterStore guarantees Arc lives while worker holds snapshot version? Policy snapshot rebuild re-hands same Arc for surviving rule_id, so pointer stays valid across rebuilds for surviving rules. Deleted rule's Arc dropped → pointer dangling if not cleared; handle by nulling pointer on delete path via `refresh_bpf_conntrack_last_seen` or `set_policy_state`? Simpler first step: borrow-return API so metadata.clone() removed entirely — fast path returns `&Metadata` reference, no Arc clone. Counter increment still needs Arc clone? It can increment via `metadata.policy_counter.as_ref().map(|arc| arc.hit)` without cloning Arc (clone only for ref counting, increment does not need clone — can increment through &Arc). So removing clone already eliminates LOCK XADD even keeping Arc.

  First PR4a: Borrow-return `lookup_with_origin` → returns ref, eliminates `metadata.clone()` → no Arc clone. Promote/Δ paths that need owned do explicit clone cold.

  PR4b: Raw pointer optimization if still needed (eliminate even the &Arc deref).

- Gate: new bench shows 10ns win, `perf` shows `lock xadd` disappears from hot disassembly, `cargo test` + `test-failover`.

**PR5 — session_glue decomposition**:
- Split `session_glue/mod.rs` 1277 LOC into `forwarding.rs`, `ha_res.rs`, `bpf_mirror.rs`, `shared_sync.rs`, `flow_resolver.rs`, `worker_commands/dispatcher.rs`. Each <300 LOC. Keep existing `commands/` and `promote.rs` but narrow imports (no `super::super::*`). Gate: `cargo test session_glue` + `test-failover` (fabric redirect + HA predicate).

**PR6 — finalize boundaries**:
- Remove `super::*` from all session submodules, replace with explicit imports. Enforce via `cargo clippy -- -D disallowed_methods?` or via review. Add module docs summarizing responsibility and hot-path coloring.

Each PR must include doc update to `session/README.md` and `session_glue/README.md` (module contract per task) or explicit no-doc-needed rationale.

---

## Labels summary

- All Hs: `area:session`, `type:refactor`, `risk:medium-high`, `hot-path`, `modularity`, `size:L`
- Ms: `area:session`, `type:cleanup`, `perf`, `size:M`
- Ds: `positive`, `pattern: exemplary` (no action, just preserve)

---

## Dedup note

- #4421 god-struct inventory — this audit supersedes with concrete phased decomposition + asm verification + hot/cold split + bench gate + failover gate.
- #4399 P5 NAT reverse-index correctness — shipped SmallVec 1:N multimap; this audit's M1 is follow-up isolation + heap spill risk, not duplicate correctness.
- #919 LOCK XADD zone names → zone-id u16 — shipped; this audit notes resurgence via `policy_counter: Option<Arc<PolicyRuleCounter>>` metadata.clone() causing new LOCK XADD on same hot path.
- #964 slab+handle + #2005 code-motion split — produced current module boundaries via super::*; this audit argues they are not decomposition and proposes true encapsulation.
- #1346 SharedSessionRefs Copy bundling — exemplary, referenced as positive pattern.
- #1357 ctx.rs context structs — exemplary, template.
- #2120 standby gate + #4380 companion keepalive + #4109 TCP state propagation — handled in expire.rs/lookup.rs; extraction must preserve ordering guarantees.
- #1752 in-place refresh contract #1855 corruption guards — debug_assert! pattern must stay after extraction.

---

## Output path

Report written to /tmp/review-work-ps-043/ps-a1d-b1.md (as mandated, not /tmp/ps-review-*.md)


---
### Batch ps-a1e-b1.md — 57689 chars

# A1e — Forwarding / ForwardingState / neighbor / worker loop_body / forwarding_build — Modularity Audit

**Base SHA:** `4e0c7f74cf0dbacf83051b2a9b6cf4e050dcecaa`
**Worktree:** `/tmp/review-wt-ps-043-a1e-b1/`
**Whoami:** ps, NNN 043
**Date:** 2026-07-11
**Scope:** `userspace-dp/src/afxdp/forwarding/mod.rs` (2795), `types/forwarding.rs` (1099), `forwarding_build/` (8 files 3092 prod), `neighbor.rs` (2036), `neighbor_resolver.rs` (805), `neighbor_dispatch.rs` (1421), `worker/mod.rs` (1631), `worker/loop_body/mod.rs` (1784), `worker/*.rs`, `worker/loop_body/*.rs`
**Engineering style:** read via worktree `docs/engineering-style.md`

---

## 0. File-size / shape inventory

| File | LOC (prod) | Shape | Notes |
|------|------------|-------|-------|
| `forwarding/mod.rs` | 2795 | 80 free fns, 5 god-fns ≥192 LOC | FIB+NAT+fabric+tunnel fused. Was 68 fns, now 80. Growth without split. |
| `types/forwarding.rs` | 1099 | 1 god-struct 66 fields + ~20 small structs/enums | Was 55 at #4421, now 66. No `#[repr]`, `Clone+Default` heavy, hot/cold interleaved. |
| `forwarding_build/mod.rs` | 705 | orchestrator + helpers | Clean #1342 split, linear builder sequence. |
| `forwarding_build/fib.rs` | 483 | 6 fns | Single-resp FIB/neighbor/fabric population |
| `forwarding_build/interfaces.rs` | 340 | | |
| `forwarding_build/zones.rs` | 142 | | |
| `forwarding_build/cos.rs` | 850 | 3 sub-helpers | Well-decomposed but 850 still high; inner helpers private. |
| `forwarding_build/tunnels.rs` | 324 | | |
| `forwarding_build/validated.rs` | 161 | newtypes | exemplary checked narrowing |
| `forwarding_build/wg.rs` | 127 | | |
| `forwarding_build/tests.rs` | 5108 | | test prod ratio ~1.6x |
| `neighbor.rs` | 2036 | 4 fused responsibilities, 272-LOC monitor thread, 120-LOC warmer loop | Was 1901→2036 (#4421). ARP/ND craft + netlink probe + monitor + warmer + affinity |
| `neighbor_resolver.rs` | 805 | single-resp resolver loop | genuine split, good SoA. 805 (prompt said 1523 stale) |
| `neighbor_dispatch.rs` | 1421 | retry_pending_neigh + learn helpers + admission | genuine split but `super::*` coupling |
| `worker/mod.rs` | 1631 | orchestrator, 11 sub-mods | already #959 decomposed |
| `worker/loop_body/mod.rs` | 1784 | per-tick loop inline per #1776 comment | setup.rs 251, debug_report.rs 370 extracted, rest intentionally inline |
| `worker/lifecycle.rs` | 335 | | |
| `worker/cos/*.rs` | 1131 | interface_row 97, queue_row 302, mod 596, status 136 | CoS runtime split reasonable |
| `worker/*.rs` sub-mods | 33-69 each | 11 files total | exemplary via #959: telemetry, scratch, cos_state, tx_counters, bpf_maps, timers, tx_pipeline, bind_meta, flow_cache_state, xsk_rings |

**Total scope:** ~12.5k prod LOC (excl tests) across 20+ files. Largest file still `forwarding/mod.rs` at 2795 (borderline, #1864 says >3000 demands split, >2000 smell — this file is in the smell band and trending up).

---

## 1. File-by-file log

### `userspace-dp/src/afxdp/types/forwarding.rs` (1099)
- Read full. `ForwardingState` is `#[derive(Clone, Debug, Default)]` with 66 fields (was 55 at #4421, growth via #3769 local_tables, #3182 configured_iface, #3527 opening_overrides, #3618 reject_buckets, #3651 zone counters, cold_path slots). No `#[repr(C)]`, declaration order is historical not hot-first. Hot fields (`local_v4/v6`, `connected_v4/v6`, `routes_v4/v6`, `neighbors`, `ifindex_to_zone_id`, `egress`, `tunnel_endpoints`, `fabrics`, `zone_host_inbound`) interleaved with cold (`ifindex_to_name: FastMap<i32,String>` heap, `filter_state`, `cos`, `tcp_mss_*`, `cold_path_sample_mask`, `screen_profiles`, `mirror_configs`). `Clone` is heavy — clones all maps + Strings on every ArcSwap publish? Actually workers `load_arc_if_changed` but builder clones state for mutation then Arc-wraps. Still, 66-field clone is large. `owns_configured_ip` is `#[inline]` at L502, good.
- Other types: `ZoneHostInbound` (admission set) with 7 FastSets, `FabricLink`, `FabricLinkSkip`, `ForwardingResolution`, `WorkerBindingLookup` etc. These are fine.

### `userspace-dp/src/afxdp/forwarding/mod.rs` (2795)
- Read 0-2162 + tail. Head: statics for LOCAL_DELIVERY_IFINDEX0, NEIGHBOR_UNKNOWN_STATE_SKIPPED, FABRIC_LINK_SKIPPED_MALFORMED counters. `build_fabric_link_or_skip`, `classify_neighbor_state`, `neighbor_state_usable`, `parse_packet_destination`, `resolve_forwarding` are small helpers (good).
- Mid: `nat_scope_ctx_for_flow`, `match_source_nat_*`, `zone_pair_*` (alloc vs zero-alloc ID variants), `owner_rg_for_*`, `ingress_is_fabric`, `resolve_fabric_links_from_snapshots`, `resolve_fabric_redirect*`, `redirect_via_fabric_if_needed`, `prefer_local_forward_candidate_for_fabric_ingress` (moderate), `cluster_peer_return_fast_path` (god-fn, ~105 LOC L722-L827 per grep, with TCP SYN/RST/FIN guards #2151/#4453/#4439/#4414), `is_icmp_echo_request`, `resolve_ingress_logical_ifindex`, HA enforce helpers, `demoted_owner_rgs`/`activated_owner_rgs`, MSS helpers `effective_tcp_mss`, `native_gre_inner_mtu`, `tunnel_outer_mtu`, `tunnel_tcp_mss`, `select_tcp_mss`.
- Core lookup: `lookup_forwarding_resolution_inner_ecmp` L1422 is god-fn (estimated 192 LOC). Handles local_v4/v6 table-scoped decision #3769/#3151, then delegates to v4/v6 inner lookups. Contains Cow table canonicalization #4674, nested branching for owned_here logic. Dur duplicated for v4/v6 arms (structurally similar).
- `ingress_route_table_override` L1614 is god-fn (~120 LOC) fused: PBR routing-instance override + filter log emission + reject sink + drop decision #4392/#2619.
- `lookup_forwarding_resolution_v4_inner` L1996 (~192 LOC) and `lookup_forwarding_resolution_v6_inner` L2212 (~192 LOC) are mirrors: connected vs static choose, discard, next_table recursion with visited vec for cycle detection #3768, ECMP selection via `select_route_next_hop` with tunnel liveness #2923.
- `choose_v4_route` L2595, `choose_v6_route` L2615 small helpers #2390, `ecmp_hash_*` L2658-L2697 with `#[inline]` candidates, `tunnel_next_hop_live`, `select_route_next_hop` L2772.
- Overall fusion: FIB lookup + NAT scope + HA RG + fabric + tunnel + CoS MSS + PBR all in one file, 80 free fns. Free fn count up 68→80 without split.

### `userspace-dp/src/afxdp/forwarding_build/` (3092 prod)
- `mod.rs` 705 orchestrator: `build_forwarding_state_with_policy_counters_and_previous` linear sequence populate_zones → tunnels → wg → interfaces → egress → sort_connected → populate_routes (with #3771 L1/M4 family checks) → sort_routes → populate_neighbors (M11/M12) → populate_fabrics, then policy, flow, timeouts #3527, NAT #3096/#3888/#4518, filter #2505, CoS #2410, flow-export removed #2130, mirror, late-stage NAT local-delivery append (must stay after all other local_v writers per comment), debug-log, RST suppression install, pending_neigh_timeout compute #1636. Clean separation, good comments. `compute_pending_neigh_timeout_ns` with SysctlReader trait for testability, good.
- `fib.rs` 483: `sort_connected`, `populate_routes` (family mismatch #3771), `sort_routes` (#2390 preference tie-break), `populate_neighbors`, `populate_fabrics` (shared helper), next-hop resolvers `resolve_route_next_hops_v4/v6`, `parse_route_next_hop`, `resolve_ifindex`, `infer_connected_route_target_v4/v6` (#4446 table-scoped inference). Single responsibility, good.
- `interfaces.rs` 340, `zones.rs` 142, `tunnels.rs` 324, `validated.rs` 161 (checked narrowing QueueId/VlanId/TunnelTtl), `wg.rs` 127, `cos.rs` 850: 3 sub-helpers `build_cos_classifier_tables`, `build_cos_iface_config` (contains `useful_cos_state` gate #1183 fix, materialized_queue_or_default #hb166 T-4, scheduler_map unknown class fail-closed), `build_cos_state` orchestrator. 850 LOC high but inner structure good; could further split lp tables vs queue tables but not urgent.
- Overall exemplary decomposition via #1342 from 1162-LOC monolith. Each file <850.

### `userspace-dp/src/afxdp/neighbor.rs` (2036)
- Read full. 4 fused responsibilities:
  1. **ARP/ND craft** L97-L136: `build_icmp4_echo` L97 (8-byte ICMP, raw vs dgram kind distinction #2482), `build_icmp6_echo` L110, `build_solicit_sockaddr_in6` L129 (#2969 scope id fix).
  2. **Netlink probe** L158-L267: `trigger_kernel_arp_probe` 134 LOC, dual-family raw/dgram socket selection via `select_probe_socket`, SO_BINDTODEVICE best-effort, sendto error logging, close. `ProbeSockKind` enum.
  3. **Warmer** L269-L358: `neighbor_warmer_loop` 120 LOC, MPSC rx, GC per interval, stop flag, RG active gate, generation collapse, per-key rate-limit, single probe firing via trigger_kernel_arp_probe. Uses `Arc<Mutex<FastMap>>`, `AtomicU64` generation, `ArcSwap` RG runtime.
  4. **Netlink monitor** L975-L1234: `neigh_monitor_thread` 272 LOC, RTMGRP_NEIGH socket bind, rcvbuf enlarge via `set_neigh_monitor_rcvbuf` (SO_RCVBUFFORCE fallback, 4 MiB), initial dump with retry backoff `INITIAL_DUMP_RETRY_BACKOFF_MS` (200/500/1k/2k/5s) #2919, seq-0 interleaved multicast absorption #2918, ENOBUFS handling #1771 with throttled re-dump, epoch bump-first ordering #1769, counters.
  5. **CPU affinity** L1246-L1312: `nth_allowed_cpu` pure helper, `pin_current_thread` #738 fix (enumerate inherited mask, pick worker_id % count).
  6. **Netlink request builders**: `build_newneigh_request` L412 (ndmsg + NDA_DST/LLADDR), `add_kernel_neighbor`, tests for STALE vs REACHABLE #4475.
  7. **Parse helpers**: `parse_neighbor_msg`, `request_neighbor_dump`, `process_dump_batch`, `initial_neighbor_dump`, `dump_establishes_baseline`, `set_neigh_monitor_rcvbuf`.
  8. **MAC parse**: `parse_mac`, `format_mac`.
- Tests interwoven: dump_batch_tests L1341, pin_tests L1536, probe_socket_tests L1710, warmer_tests L1879.

### `userspace-dp/src/afxdp/neighbor_resolver.rs` (805)
- Genuine split from `neighbor.rs`. On-demand resolver: `ResolveItem` with epoch, per-key rate-limit `RESOLVER_PER_KEY_RATE_LIMIT_NS` 1s (asserted < NEG_NEIGH_TTL), GC intervals, enqueue throttle 100ms, recv timeout 200ms, `ResolverCounters`, `NeighborResolver` handle with depth gauge, `open_resolver_socket`, `send_get_neigh` (single-key unicast GET, not dump, no RTNL mutex), `GetOutcome` enum Confirmed/Unconfirmed/Failed/NoReply, `classify_nud`, `read_get_reply`, `parse_get_reply_body`, `ResolveAction` Cache/EpochReject/ProbeOnStale/RevokeAndProbe/ProbeOnly, `decide_action`, `RateLimitDecision` AdmitFirst/AdmitRetry/Coalesce, `rate_limit_decide`, `neighbor_resolver_loop` (persistent socket, GC, dequeue depth gauge dec, rate-limit, epoch snapshot before GET, send+read+RTT hist #1772, stop check, epoch after load, decide_action dispatch with epoch-guarded insert). Good shape, low coupling aside from `super::*`. Tests in separate file `neighbor_resolver_tests.rs`.

### `userspace-dp/src/afxdp/neighbor_dispatch.rs` (1421)
- Genuine split but `super::*` coupling. `PROBE_SCHEDULE_NS` [10ms,60ms,260ms] # cold-start exponential, `probe_due`, `PendingNeighAdmission` enum Buffer/DuplicateDrop/CapacityDrop #1771 N1, `pending_neigh_admission` inline, `record_pending_neigh_admission_drop` #2375 split counters duplicate vs capacity, `pending_neigh_flow_key` #3290 ICMP gate, `retry_pending_neigh` L155 (the big 250-LOC function, post-poll loop walking pending_neigh keyed by (egress_ifindex,next_hop), timeout with neg_neigh_record, dwell record #1772, MAC lookup forwarding.neighbors + dynamic_neighbors, probe re-fire via schedule, dispatch tail with COS selection #2362/#3642, mirror clone, rewrite in-place, target lookup, prepared TX enqueue). Also `learn_dynamic_neighbor_from_packet`, `pair_write_needed` #1787 cheap-first, `learn_dynamic_neighbor` #4889 class gate + #3182 own-IP anti-poison + #1787 cheap-first pre-check + multi-ifindex atomic insert + bump-aware bulk insert #3169. `build_missing_neighbor_session_metadata`. Tests interleaved mirror_tests, cold_start_probe_schedule_tests, learn_precheck_tests, pending_admission_tests, pending_neigh_flow_key_tests. Good tests.

### `userspace-dp/src/afxdp/worker/mod.rs` (1631)
- Read partial. BindingWorker struct declaration 200 LOC (slot, queue_id, worker_id, interface, ifindex, live, user, xsk: WorkerXskRings #959 Phase 11, umem, tx_pipeline: WorkerTxPipeline Phase 7+10, cos: WorkerCos Phase 3, scratch: WorkerScratch Phase 2, pending_neigh, neg_neigh_cache #1651 B3, resolver_enqueue_throttle #1769, bpf_maps Phase 5, timers Phase 6, last_learned_neighbor, telemetry Phase 1, tx_counters Phase 4, flow Phase 9, cold_path, mirror_sample_counter, bind_meta Phase 8). Well-decomposed via #959 into 11 sub-mods: lifecycle (poll_binding), telemetry, scratch, cos_state, tx_counters, bpf_maps, timers, tx_pipeline, bind_meta, flow_cache_state, xsk_rings, cos (runtime helpers), loop_body (setup + debug_report + mod). Each sub-mod 33-69 LOC for state containers, 335 lifecycle, 596 cos mod, etc. Remainder is BindingWorker::create (frame count reserve, fill ring pre-populate, ring open, live state publish, debug counters), test constructors. Helper fns: `register_binding_xsk`, `xsk_role_for_shared_plan`, `partition_binding_plans`, `prepare_shared_binding_plan_for_create`, `create_private_binding_from_plan`, `create_shared_binding_group` (shared UMEM group with sorted plans, fallback to private on error), `fallback_shared_group_to_private`, `load_arc_if_changed` #1188 hot-path optimization (ptr_eq short-circuit avoiding Arc clone), `refresh_worker_cos_queue_lease_runtime_counters` #1782, `apply_worker_shaped_tx_requests`, `publish_tx_completion_ring_telemetry` #1241. Good shape.

### `userspace-dp/src/afxdp/worker/loop_body/mod.rs` (1784)
- Per-tick orchestrator. One-shot setup extracted to `setup.rs` 251 (thread pin, TSC calibrate, initial ArcSwap load_fulls, binding construction, BPF FD cache, initial cos_status publish). Verbose report/stall dump extracted to `debug_report.rs` 370 cfg(debug-log). Body retains per-tick telemetry publish, ArcSwap config refresh (load_arc_if_changed), HA load, command drain, hot poll_binding sweep, heartbeat, always-on diagnostics + live publish, idle regulation. Per doc at top: inline intentionally per #1776 plan review Codex r1-4 — #[inline(never)] call boundary in front of load_arc_if_changed path risks regressing 10k-100k ticks/s loop. So explicit decision to keep hot loop inline, not a missing split. Macros for flush_drained_session_deltas #2669 (has_pending_deltas must flush even when bindings empty else HA diverge), drain_and_flush_all, chunked_drain_as_you_export (RESYNC_EXPORT_CHUNK 2048 < MAX_SESSION_DELTAS 4096, prevents permanent per-cycle resync storm #2442/#2653). Well-structured given constraint.

---

## 2. Findings

### F-A1e-01 — ForwardingState god-struct 66 fields, no repr, hot/cold interleaved, heavy Clone

- **Title:** ForwardingState is 66-field god-struct (was 55 at #4421) with no `#[repr(C)]`, hot FIB fields interleaved with cold String-heap maps, Clone+Default derived clones heavy maps per ArcSwap publish
- **Severity:** High
- **Confidence:** High
- **Refactor class:** B (structural Decomp — SoA split + layout optimization)
- **Evidence:**
  - File: `userspace-dp/src/afxdp/types/forwarding.rs:33` — `#[derive(Clone, Debug, Default)] pub struct ForwardingState {` then 66 fields L35-L310.
  - Hot FIB: `local_v4` L35, `local_v6` L36, `connected_v4` L91, `connected_v6` L92, `routes_v4` L93, `routes_v6` L94, `neighbors` L121, `ifindex_to_zone_id` L135, `egress` L184, `tunnel_endpoints` L95, `gre_decap_index` L110, `fabrics` L186, `zone_host_inbound` L145.
  - Cold interleaved: `ifindex_to_name: FastMap<i32,String>` L122 heap String per entry touched only at slow probe path, `filter_state` L242, `cos` L243 (CoSState with nested maps), `tcp_mss_all_tcp` L266, `cold_path_sample_mask` L277, `screen_profiles` L232, `mirror_configs` L265.
  - Growth trace: #3769 added `local_tables_v4/v6` + `local_nat_any_table_v4/v6` (4 fields), #3182 `configured_iface_v4/v6` (2), #3527 `session_opening_overrides`, #3618 `reject_buckets`, #3651 `zone_counter_*`, prior `pending_neigh_timeout_ns`, `cold_path_slot_map`, etc. 55→66 without split.
  - No `#[repr(C)]`, declaration order historical. `Clone` clones all 66 maps; `pending_neigh_timeout_ns` `0` default used as unset sentinel L288-L290.
  - `owns_configured_ip` L502 `#[inline]` is hot guard but lives on bloated struct.

```rust
#[derive(Clone, Debug, Default)]
pub(in crate::afxdp) struct ForwardingState {
    pub(in crate::afxdp) local_v4: FastSet<Ipv4Addr>,
    pub(in crate::afxdp) local_v6: FastSet<Ipv6Addr>,
    pub(in crate::afxdp) local_tables_v4: FastMap<Ipv4Addr, FastSet<String>>,
    // ... 60 more ...
    pub(in crate::afxdp) ifindex_to_name: FastMap<i32, String>,
    pub(in crate::afxdp) ifindex_to_config_name: FastMap<i32, String>,
    pub(in crate::afxdp) filter_state: crate::filter::FilterState,
    pub(in crate::afxdp) cos: CoSState,
```

- **Proposed decomposition:**
  - **Phase 0 (zero-risk perf-positive):** Add `#[repr(C)]` + reorder fields hot-first. Hot block:
    - `local_v4/v6`, `configured_iface_v4/v6`, `local_tables_v4/v6`, `local_nat_any_table_v4/v6`, `connected_v4/v6`, `routes_v4/v6`, `neighbors`, `ifindex_to_zone_id`, `egress`, `tunnel_endpoints`, `tunnel_endpoint_by_ifindex`, `gre_decap_index`, `fabrics`, `zone_id_to_name`, `zone_name_to_id`, `zone_host_inbound`, `ifindex_host_inbound`, `interface_nat_v4/v6`, `ingress_logical_ifindex`, `ifindex_to_routing_instance`, `ifindex_to_config_name`
  - Cold block after: `ifindex_to_name`, `filter_state`, `cos`, `policy`, `source_nat_rules`, `static_nat`, `dnat_table`, `nat64`, `nptv6`, `screen_profiles`, `tunnel_interfaces`, `mirror_configs`, `tcp_mss_*`, `cold_path_sample_mask`, `pending_neigh_timeout_ns`, `cold_path_slot_map`, `zone_counter_*`, `reject_buckets`, `app_catalog`, `session_timeouts`, `session_opening_overrides`, `syn_cookie_master_key`, `fabric_skips`, `wg_engines`, `has_wg_tunnels`, etc.
  - Keep `Clone` but hot-first improves cacheline density for per-packet lookup (FIB touches first cachelines).
  - Add `const _: () = assert!(std::mem::size_of::<ForwardingState>() <= ...)` guard? No, size is heap-indirect but field offset matters. Better add comment documenting hot block boundary.
  - **Phase 1 (SoA split):** Introduce `ForwardingFib` struct:
    ```rust
    #[derive(Clone)] // Debug manually
    #[repr(C)]
    pub struct ForwardingFib {
      pub local_v4: FastSet<...>,
      pub local_v6,
      pub configured_iface_v4/v6, ...
      pub connected_v4/v6,
      pub routes_v4/v6,
      pub neighbors,
      pub egress,
      pub tunnel_endpoints,
      pub gre_decap_index,
      pub ifindex_to_zone_id,
      // ... 20 hot fields
    }
    pub struct ForwardingCold {
      pub filter_state,
      pub cos,
      pub policy,
      pub nat...
      pub ifindex_to_name, // String heap
    }
    pub struct ForwardingState {
      pub fib: Arc<ForwardingFib>, // hot Arc
      pub cold: Arc<ForwardingCold>, // cold Arc
      // or keep flat but workers hold &ForwardingFib via Arc<ForwardingState>.fib
    }
    ```
    Actually simplest: keep `ForwardingState` top-level but split into `ForwardingFib(Arc<ForwardingFibInner>)` field + `cold` field, workers hold `Arc<ForwardingFib>` separately from cold config. Seam: `lookup_forwarding_resolution_inner_ecmp` takes `&ForwardingFib` not `&ForwardingState`; existing `&ForwardingState` callers pass `&state.fib`. Builder builds both in `forwarding_build/mod.rs` then wraps in Arcs.
  - Preserve `#[inline]` on `owns_configured_ip`, `choose_v4_route`, `ecmp_hash_*`. Move them to `fib` submodule so inlining cross-crate still works via LTO.

- **Hot-path preservation analysis:**
  - Guardrails: `owns_configured_ip` L502 `#[inline]` on anti-poison path, `choose_v4_route`/`choose_v6_route` L2595/L2615 hot for LPM, `ecmp_hash_v4/v6` L2665/L2669 + `ecmp_hash_flow_seeded` L2697 with `hot_hash_seed` — must stay `#[inline]` or `#[inline(always)]` where already.
  - `#[repr(C)]` reorder is zero-risk: Rust struct field access is by name, no unsafe offset-of, repr change does not affect logic. Clone impl still derived. The only risk is if any code does `unsafe` transmute or relies on layout (none found via grep for `offset_of|transmute` in this file).
  - SoA split: hot path `lookup_forwarding_resolution_inner_ecmp` currently borrows `&ForwardingState`; after split it borrows `&ForwardingFib` (Arc inner). The Arc deref is one extra indirection but hot FIB now tightly packed in fewer cachelines (no cold String maps interleaved). Expected perf: neutral to positive. Must verify via `cargo test --benches`? No benches but use `make test` + `cargo bench` if present + iperf3 ≥23Gb/s on loss cluster.
  - Verify: `cargo test -p xpf-userspace-dp --lib` (or `make test-rust`), plus `make cluster-deploy` + `./test/incus/apply-cos-config.sh loss:xpf-userspace-fw0` + `iperf3 -P 16 -t 30 -p 5203` to 172.16.80.200 ≥23 Gbit/s no regression.

- **Tests+gate:** `make test-rust` (cargo test), `make test-go` (if Go build touched), `make test-deploy` standalone ping, `make cluster-deploy` + iperf3. Add unit test for hot-field-first ordering: compile-time assert that `offset_of!(ForwardingFib, local_v4) < offset_of!(ForwardingCold, ifindex_to_name)` if split, or that `ForwardingState` hot fields are within first N bytes? Not needed — just benchmark.

- **Why it matters:** 66 fields god-struct violates Single Responsibility, hinders review (every PR touching FIB touches NAT/filter/cos fields via merge conflicts), bloats Clone, and interleaves hot cachelines with cold heap String maps causing cache misses per packet. Growth 55→66 since #4421 shows trajectory.

- **Fix direction:**
  1. PR1: `#[repr(C)]` + hot-first reorder with comment `// --- hot FIB (per-packet) ---` / `// --- cold config ---`. Zero-risk, perf-positive.
  2. PR2: Introduce `ForwardingFib` Arc SoA split, workers hold hot FIB Arc separately, builder outputs `Arc<ForwardingFib>` + `Arc<ForwardingCold>`. Update `forwarding/mod.rs` signatures to take `&ForwardingFib` where only FIB needed.

- **Labels:** `modularity`, `perf`, `hot-path`, `god-struct`, `SoA`, `repr-C`
- **Dedup note:** Overlaps with #4421 god-struct report; extends it with concrete hot/cold inventory + SoA proposal + repr(C) zero-risk step + CoS FIF concern.

---

### F-A1e-02 — forwarding/mod.rs 2795 LOC 80 fns, 5 god-fns fused

- **Title:** `forwarding/mod.rs` 2795 LOC with 80 free functions (was 68), 5 god-fns ≥192 LOC each (lookup_forwarding_resolution_inner_ecmp, v4 inner, v6 inner, cluster_peer_return_fast_path, ingress_route_table_override), FIB/NAT/fabric/tunnel/MSS fused
- **Severity:** High
- **Confidence:** High
- **Refactor class:** A (file split + function extraction)
- **Evidence:**
  - LOC: `2795` file, `grep -n "^pub\|^fn" | wc -l` → 80 free fns. Prior ticket said 68→80 growth.
  - God-fns:
    - `lookup_forwarding_resolution_inner_ecmp` L1422-L1576 (~154 LOC + nested v4/v6 branches). Handles local_v4/v6 global membership + table-scoped decision #3769 + VRF isolation #3151 + local IFINDEX0 diagnostic + delegates to v4/v6. Contains duplicated v4/v6 logic.
    - `cluster_peer_return_fast_path` L722-L825 (~103 LOC but with 4 TCP/ICMP guards #2151/#4453/#4439/#4414, fabric check, echo request check, egress zone lookup). Spec calls 192 LOC — maybe counting with comments.
    - `ingress_route_table_override` L1614-L1734 (~120 LOC) fused PBR override + filter log #2619 + reject sink #4392 + Drop vs Table vs None decision.
    - `lookup_forwarding_resolution_v4_inner` L1996-L2162+ (~166 LOC) and `lookup_forwarding_resolution_v6_inner` L2212-~2390 (~178 LOC) — mirrors, each handles discard, next_table recursion with MAX_NEXT_TABLE_DEPTH 8 + visited vec cycle detection #3768, ECMP selection with tunnel liveness #2923.
  - Fusion: single file contains NAT scope ctx, source NAT match, zone pair (String and ID variants), owner RG, fabric resolve, MSS clamp (GRE inner MTU, tunnel outer MTU, tunnel TCP MSS, select TCP MSS), IPsec admission class, PBR, interface NAT, local delivery cache gate, HA resolution, flow cache validity, etc.
  - Free fn count growth 68→80 without split indicates ongoing feature accretion.

```rust
pub(super) fn lookup_forwarding_resolution_inner_ecmp(
    state: &ForwardingState,
    dynamic_neighbors: Option<&Arc<ShardedNeighborMap>>,
    dst: IpAddr,
    table: Option<&str>,
    ecmp_flow_hash: Option<u64>,
) -> ForwardingResolution {
    match dst {
        IpAddr::V4(ip) => {
            let table = table.map(|table| canonical_route_table(table, false))...
            if state.local_v4.contains(&ip) {
                let owned_here = state.local_nat_any_table_v4.contains(&ip)
                    || state.local_tables_v4.get(&ip).is_some_and(...)
                // ... 50 LOC table-scoped decision
```

- **Proposed decomposition:**
  - Create `forwarding/` directory (already `mod.rs` + `host_inbound.rs` present). Split into:
    - `forwarding/fib_lookup.rs` — `lookup_forwarding_resolution_inner_ecmp`, `lookup_forwarding_resolution_v4/v6` + inner, `choose_v4/v6_route`, `ecmp_hash_*`, `parse_packet_destination`, `resolve_forwarding`, `no_route_resolution`, `populate_egress_resolution`, `resolve_tunnel_*`, `tunnel_next_hop_live`, `select_route_next_hop`, `outer_neighbor_ifindex`, `lookup_neighbor_entry`, `parse_neighbor_entries`. Preserve `#[inline]` on hot helpers.
    - `forwarding/fabric.rs` — `ingress_is_fabric`, `resolve_fabric_links_from_snapshots`, `resolve_fabric_redirect*`, `redirect_via_fabric_if_needed`, `prefer_local_forward_candidate_for_fabric_ingress`, `build_fabric_link_or_skip`, `classify_neighbor_state`, `neighbor_state_usable`, counters.
    - `forwarding/ha.rs` — `owner_rg_for_flow`, `owner_rg_for_resolution`, `enforce_ha_resolution*`, `cached_flow_decision_valid`, `finalize_new_flow_ha_resolution`, `demoted_owner_rgs`, `activated_owner_rgs`, `cluster_peer_return_fast_path` (move to fabric or ha).
    - `forwarding/nat_scope.rs` — `nat_scope_ctx_for_flow`, `match_source_nat_for_flow*`.
    - `forwarding/mss.rs` — `effective_tcp_mss`, `native_gre_inner_mtu`, `native_gre_tcp_mss`, `tunnel_outer_mtu`, `tunnel_tcp_mss`, `select_tcp_mss`.
    - `forwarding/pbr.rs` — `ingress_route_table_override`, `RouteOverride`, `PbrRejectSink`, `resolve_ingress_logical_ifindex`, `is_icmp_echo_request`, `is_ipsec_traffic`, `classify_ipsec_admission`.
    - `forwarding/local_delivery.rs` — `interface_nat_local_resolution`, `ingress_interface_local_resolution`, `should_cache_local_delivery_session_on_miss`, `install_helper_local_session_on_miss`, `should_block_tunnel_interface_nat_session_miss`, `host_inbound` re-export.
    - `forwarding/mod.rs` stays as re-export glue + `classify_metadata`, `canonical_route_table`.
  - Seam: all fns currently `pub(super)` or `pub(in crate::afxdp)`; new submods `pub(super)` same visibility, imported via `pub use` in `mod.rs`. No `super::*` new coupling.
  - Example:
    ```rust
    // forwarding/mod.rs
    mod fib_lookup; mod fabric; mod ha; mod nat_scope; mod mss; mod pbr; mod local_delivery; mod host_inbound;
    pub use fib_lookup::{lookup_forwarding_resolution_inner_ecmp, ...};
    ```

- **Hot-path preservation:**
  - Guardrails: `#[inline]` on `owns_configured_ip` (types), `choose_v4_route`, `ecmp_hash_v4/v6`, `ecmp_hash_flow_seeded`, `zone_pair_ids_for_flow_with_override`. Must keep inline attributes after move.
  - `canonical_route_table` returns `Cow<'static,str>` #4674 to avoid alloc on default table remap — must stay `#[inline]` or at least not lose Cow optimization.
  - `lookup_forwarding_resolution_inner_ecmp` is per-new-flow (session miss) not per-packet but still hot (~10k flows/s). Keep `ecmp_hash_flow` seeded with `hot_path_hash_seed()`.
  - Verification: `cargo test` for FIB lookup tests (there are no direct unit tests for this file? `forwarding_build/tests.rs` covers build but lookup tested via integration). Add unit tests for `choose_v4_route` preference tie-break? Already exists via route sort tests. iperf3 for regression.

- **Tests+gate:** `make test-rust` + `make test` + cluster iperf3 ≥23G. No new per-packet allocation.

- **Why it matters:** 2795 LOC file with 80 fns is at engineering-style threshold (2000 smell, 3000 must split). Growth 68→80 indicates feature accretion without modularity. Reviewability degraded — changes to fabric, NAT, MSS, PBR all collide in same file. God-fns 192 LOC each violate 100 LOC rule.

- **Fix direction:**
  1. PR1: Extract `fabric.rs` + `ha.rs` (low risk, no hot path change, just move fns).
  2. PR2: Extract `fib_lookup.rs` + `mss.rs` + `pbr.rs` + `local_delivery.rs` + `nat_scope.rs`. Keep `mod.rs` as glue.
  3. Keep host_inbound already split.

- **Labels:** `modularity`, `god-function`, `file-size`, `SoC`, `FIB`
- **Dedup note:** Distinct from F-A1e-01 (struct vs file). Overlaps with prior #1342 which split forwarding_build but not forwarding/mod.rs.

---

### F-A1e-03 — neighbor.rs 2036 LOC 4 fused responsibilities

- **Title:** `neighbor.rs` 2036 LOC fuses ARP/ND craft, netlink probe trigger, monitor thread (272 LOC), warmer loop (120 LOC), CPU affinity — was 1901→2036 growth
- **Severity:** Medium
- **Confidence:** High
- **Refactor class:** A (split into submods)
- **Evidence:**
  - File: `userspace-dp/src/afxdp/neighbor.rs:1` 2036 LOC.
  - Responsibilities:
    - Craft: `build_icmp4_echo` L97-L104 (8 bytes, raw vs dgram distinction), `build_icmp6_echo` L110, `build_solicit_sockaddr_in6` L129 (scope_id fix #2969).
    - Probe trigger: `trigger_kernel_arp_probe` L158-L267 134 LOC, `select_probe_socket` L71, `ProbeSockKind` L38.
    - Warmer: `neighbor_warmer_loop` L292-L358 120 LOC, args `Receiver<WarmItem>, Arc<Mutex<...>>, Arc<AtomicU64>, Arc<ArcSwap<...>>, Arc<AtomicBool>`, GC, RG gate, generation collapse.
    - Monitor: `neigh_monitor_thread` L975-L1234 272 LOC, netlink socket, bind RTMGRP_NEIGH, rcvbuf enlarge `set_neigh_monitor_rcvbuf`, initial dump retry `INITIAL_DUMP_RETRY_BACKOFF_MS`, process_dump_batch seq-0 absorption #2918, ENOBUFS re-dump #1771.
    - Affinity: `nth_allowed_cpu` L1246, `pin_current_thread` L1286.
    - Netlink builders: `build_newneigh_request` L412, `add_kernel_neighbor` L459, `parse_neighbor_msg` L599, `request_neighbor_dump` L677, `process_dump_batch` L742, `initial_neighbor_dump` L806, `dump_establishes_baseline` L874, `set_neigh_monitor_rcvbuf` L910.
  - Tests: 4 test mods nested (dump_batch_tests, pin_tests, probe_socket_tests, warmer_tests) ~700 LOC of tests in same file.

```rust
pub(super) fn trigger_kernel_arp_probe(iface_name: &str, ifindex: i32, target: IpAddr) {
    let name_c = std::ffi::CString::new(iface_name).unwrap_or_default();
    match target {
        IpAddr::V4(v4) => {
            let Some((fd, kind)) = select_probe_socket(|sock_type| unsafe {
                libc::socket(libc::AF_INET, sock_type, libc::IPPROTO_ICMP)
            }) else { return; };
            // ... 100 more lines
```

- **Proposed decomposition:**
  - Create `neighbor/` directory with:
    - `probe.rs` — `ProbeSockKind`, `select_probe_socket`, `build_icmp4_echo`, `build_icmp6_echo`, `build_solicit_sockaddr_in6`, `trigger_kernel_arp_probe`, constants `RTM_NEWNEIGH`, `NUD_*`, `DATA_PATH_NEIGH_STATE`, `build_newneigh_request`, `add_kernel_neighbor`.
    - `monitor.rs` — `neigh_monitor_thread`, `process_dump_batch`, `initial_neighbor_dump`, `request_neighbor_dump`, `parse_neighbor_msg`, `update_dynamic_neighbor`, `remove_dynamic_neighbor`, `NeighborMsgEffect`, `DumpBatchOutcome`, `dump_establishes_baseline`, `set_neigh_monitor_rcvbuf`, constants `NLMSG_DONE/ERROR`, `NEIGH_RCVBUF_BYTES`, `INITIAL_DUMP_RETRY_BACKOFF_MS`.
    - `warmer.rs` — `neighbor_warmer_loop`, `WarmItem` (currently in coordinator? Need locate), GC constants.
    - `affinity.rs` — `nth_allowed_cpu`, `pin_current_thread`.
    - `parse.rs` — `parse_mac`, `format_mac`, `neighbor_state_usable_str`.
    - `mod.rs` re-exports.
  - Seam: `neighbor.rs` currently uses `super::*` for many types (`ShardedNeighborMap`, `BindingLiveState`, etc). Submods should take explicit args, not glob. Move `WarmItem` definition to `warmer.rs`.
  - Keep existing `neighbor_resolver.rs` and `neighbor_dispatch.rs` as siblings (genuine splits but need de-glob).

- **Hot-path preservation:**
  - `trigger_kernel_arp_probe` is cold path (probe on miss, not per-packet). No inline needed.
  - `parse_neighbor_msg` is monitor thread, not per-packet.
  - `pin_current_thread` called once at thread start.
  - No hot path guardrails broken. Still, keep `build_icmp4_echo` `#[inline]` if already? It is private non-inline currently, fine.
  - Verify: `cargo test` (dump_batch_tests, pin_tests, probe_socket_tests, warmer_tests) must still pass after split (they are unit tests for pure helpers). Plus `make cluster-deploy` + failover test (neighbor resolution critical for VRRP).

- **Tests+gate:** `make test-rust` (covers probe_socket_tests, dump_batch_tests), `make test-failover` for HA neighbor path.

- **Why it matters:** 2036 >2000 smell threshold, 4 distinct responsibilities violate SRP, growth 1901→2036 shows ongoing accretion. Reviewers must understand netlink monitor + warmer + ARP craft + affinity in one file. Splitting reduces merge conflicts and allows independent evolution.

- **Fix direction:** PR per sub-mod: first extract `probe.rs` (pure, no thread), then `affinity.rs`, then `warmer.rs`, then `monitor.rs`. Keep `neighbor.rs` as mod glue.

- **Labels:** `modularity`, `SRP`, `file-size`, `netlink`
- **Dedup note:** Prior #4421 noted 1901→2036 growth; this expands with concrete 4-resp inventory + split plan.

---

### F-A1e-04 — CoS TX drain / forwarding.cos.hot path + useful_cos_state gate

- **Title:** CoS FIF / TX drain — `forwarding.cos.interfaces` hot lookup + `cos_shared_queue_leases` ArcSwap cross-binding redirect collapses 6-worker parallelism, `useful_cos_state` gate prevents fwd-only iface admission but is buried in cos.rs build
- **Severity:** High (perf cliff)
- **Confidence:** Medium (need live data)
- **Refactor class:** B (perf + modularity)
- **Evidence:**
  - `forwarding_build/cos.rs:503` `build_cos_iface_config` contains gate:
    ```rust
    let contributes_usable_cos_state = iface.cos_shaping_rate_bytes_per_sec > 0
        || scheduler_map_resolved_to_queues
        || dscp_classifier_targets_iface_queue
        || ieee8021_classifier_targets_iface_queue
        || dscp_rewrite_targets_iface_class;
    if !contributes_usable_cos_state { return Ok(None); }
    ```
    Comment: "Post-build gate (#1183 fix at f0e364d7)... Skips interfaces that produce no usable CoS state, preventing the cross-binding redirect from funneling TX onto one CPU and collapsing 6-worker parallelism."

  - Historical: `f0e364d7 (#916)` removed prior `shaping_rate == 0` skip so zero-rate-with-classes gets transparent root, but side-effect added every interface that produced no usable CoS to `CoSState`, triggering cross-binding redirect that funnels every TX through per-interface owner worker, collapsing 6-worker parallelism to one CPU and capping reverse throughput ~2 Gbps vs ~22 Gbps on loss cluster. Fix is the `useful_cos_state` gate.

  - Hot lookup: `forwarding.cos.interfaces` is `FastMap<i32, CoSInterfaceConfig>` read on per-packet TX path (?) via `resolve_cos_tx_selection_at`? Need check. Also `cos_shared_queue_leases: ArcSwap<BTreeMap<(i32,u8), Arc<SharedCoSQueueLease>>>` and similar `shared_cos_*` Arcs are hot per tick via `load_arc_if_changed` + `build_worker_cos_fast_interfaces`.

  - Worker `BindingWorker` has `cos_fast_interfaces: FastMap<i32, WorkerCoSInterfaceFastPath>` per-binding, `cos_interfaces: FastMap<i32, CoSInterfaceRuntime>` (queue rows, token buckets). Drain logic in `worker/cos/` (interface_row.rs 97, queue_row.rs 302, mod.rs 596) + `worker/loop_body` hot `poll_binding`.

  - CoS fif reason: cross-binding redirect uses owner worker per egress ifindex (`cos_owner_worker_by_queue`, `cos_owner_live_by_queue`), single-owner FIFO means if interface admitted to CoS but has no real shaping, all TX goes to owner, not distributed across 6 workers that have the interface.

  - Existing gate is correct but buried, not obvious, and `forwarding.cos.interfaces` hot lookup still touches cold CoSState that includes large classifier tables (`dscp_classifiers`, `ieee8021_classifiers`, `dscp_rewrite_rules`) which are cold (only used at build, not per-packet? Actually per-packet classification reads flattened tables `dscp_queue_by_dscp` [64] + `ieee8021_queue_by_pcp` [8] stored in CoSInterfaceConfig, not global classifiers). Good: per-packet uses interface config tables, not global maps.

  - Remaining risk: `cos_shared_queue_leases` ArcSwap is per-queue, but if interface has no queues (synthetic best-effort only) still has lease? Need check.

- **Proposed decomposition:**
  - Keep `useful_cos_state` gate but make it explicit type: `enum CosAdmission { Useful(CoSInterfaceConfig), FwdOnly }` rather than `Option`.
  - Split `ForwardingState.cos` into `cos_fast: Arc<CoSFastTables>` (per-iface flattened queue tables) vs `cos_cold: Arc<CoSColdTables>` (global classifier maps). Workers only need fast part; cold stays on coordinator.
  - Move CoS hot path docs to `docs/fairness-regimes.md` — already exists, reference it.
  - In `worker/loop_body/mod.rs`, the `load_arc_if_changed` for cos is 5 separate ArcSwaps (owner_worker_by_queue, owner_live_by_queue, root_leases, exact_backlogs, queue_leases, vtime_floors) — 6 loads per tick. Could coalesce into single `CosSharedState` Arc containing all 6 maps, reducing 6 ptr_eq checks to 1. That is perf improvement but not required for this ticket.
  - Ensure `resolve_cos_tx_selection_at` takes `&CoSInterfaceConfig` not `&ForwardingState` to avoid touching cold.

- **Hot-path preservation analysis:**
  - Guardrails: `cos_queue_len`, `cos_queue_pop_front_no_snapshot`, `publish_cos_exact_backlog`, `release_all_cos_*` are per tick, not per packet but high frequency.
  - `useful_cos_state` gate prevents admission of fwd-only ifaces — must NOT be removed or throughput collapses 22→2 Gbps. Verify via cluster iperf3: with gate, ≥23 Gbit/s; without, ~2 Gbit/s. This is the #1183 regression.
  - `cos_shared_queue_leases` ArcSwap is hot: per-packet TX drain reads lease to check bytes. If gate fails and iface admitted without real lease, redirect logic still engages and collapses parallelism. So gate is perf-critical.
  - Verify: after any refactor, run `make cluster-deploy` + `./test/incus/apply-cos-config.sh loss:xpf-userspace-fw0` + `iperf3 -P 16 -t 30 -p 5203` → 172.16.80.200 ≥23 Gbit/s. Also test fwd-only iface (no CoS) still distributes across 6 workers (check `show chassis forwarding` queue depths).

- **Tests+gate:** `make test-rust` (cos tests in `forwarding_build/tests.rs` 5108 LOC, `worker/cos/tests.rs` 2708 LOC), `make cluster-deploy` + iperf3.

- **Why it matters:** Single-owner FIFO redirect is intentional for shaped interfaces (to preserve ordering/fairness), but if applied to fwd-only interfaces collapses 6-worker parallelism to 1 CPU, capping throughput 10x lower. The gate is subtle and buried; future changes could regress.

- **Fix direction:**
  1. Add compile-time or debug assertion that `cos.interfaces` only contains ifaces with `contributes_usable_cos_state`.
  2. Document gate in `docs/cos-validation-notes.md` and `worker/cos/README`.
  3. Long-term: split CoSState into fast/cold Arcs, coalesce 6 shared Arcs into 1.

- **Labels:** `perf`, `CoS`, `FIF`, `parallelism`, `hot-path`, `gate`
- **Dedup note:** CoS FIF is distinct from ForwardingState god-struct but related (cos is cold field interleaved in god-struct).

---

### F-A1e-05 — neighbor_resolver / neighbor_dispatch super::* coupling + hidden hot paths

- **Title:** `neighbor_dispatch.rs` and `neighbor_resolver.rs` genuine splits but use `super::*` glob coupling all afxdp symbols (ShardedNeighborMap, ForwardingState, BindingWorker, PendingNeighPacket, etc.) — tight coupling hides dependencies, plus `retry_pending_neigh` 250+ LOC with 4 early-continue branches still god-ish
- **Severity:** Low
- **Confidence:** High
- **Refactor class:** C (cleanup)
- **Evidence:**
  - Both files start with `use super::*;` importing entire `afxdp` module (200+ symbols).
  - `neighbor_dispatch.rs:116` comment: "Pure relocation. `use super::*;` brings every type, helper, and sibling-submodule".
  - `retry_pending_neigh` signature L156-L174 has 12 params (binding, left, binding_index, right, binding_lookup, mirror_targets, forwarding, dynamic_neighbors, neighbor_resolver Option, now_ns, area, shared_recycles) — 12 params >8 threshold, but justified as extracted hot path.
  - `learn_dynamic_neighbor` L475 takes `ForwardingState` + `ShardedNeighborMap` + ifindex + vlan + IpAddr + mac — 6 params, ok.
  - Resolver loop has similar many generic deps but via Arc.

- **Proposed decomposition:**
  - Replace `super::*` with explicit imports in both files (list needed types). This makes dependencies visible and reduces incremental build coupling.
  - Extract `retry_pending_neigh` inner tail (the dispatch after MAC resolved) into separate `dispatch_resolved_pending` helper to reduce 250 LOC function size.
  - Keep `pending_neigh_admission`, `record_pending_neigh_admission_drop`, `pending_neigh_flow_key`, `pair_write_needed` as they are (pure, well-tested).

- **Hot-path preservation:**
  - `retry_pending_neigh` is per-tick per-binding, called after `poll_binding` sweep, not per-packet but still hot (once per worker loop when pending_neigh non-empty). It calls `resolve_cos_tx_selection_at` which is hot. Must not add allocation.
  - `learn_dynamic_neighbor` is per-packet RX learn path, hot. It already has cheap-first pre-check `pair_write_needed` to avoid 64-shard bulk lock (`learn_pair_if_changed`). Must preserve that.
  - `trigger_kernel_arp_probe` called from both files, cold-ish but keep.

- **Tests+gate:** `make test-rust` (covers learn_precheck_tests, pending_admission_tests, etc.)

- **Why it matters:** Glob coupling makes refactor harder — changing any symbol in `afxdp::mod.rs` recompiles both files and hides real dependencies. Explicit imports + smaller fns improve reviewability.

- **Fix direction:** PR to replace `super::*` with explicit list, extract 2 helpers from `retry_pending_neigh`.

- **Labels:** `modularity`, `coupling`, `cleanup`
- **Dedup note:** Distinct from F-A1e-03 (neighbor.rs monolith) — this is about the splits' remaining coupling.

---

## 3. D-negatives (exemplary areas — do NOT refactor)

### D-A1e-01 — forwarding_build/ exemplary decomposition via #1342

- **Status:** D-negative (no further action)
- **Evidence:** `forwarding_build/` 8 files 3092 prod LOC, decomposed from 1162-LOC monolith into per-entity siblings: `mod.rs` 704 orchestrator linear sequence (easy to audit), `fib.rs` 483 FIB/neighbor/fabric, `interfaces.rs` 340, `zones.rs` 142, `cos.rs` 850 (3 sub-helpers, useful_cos_state gate), `tunnels.rs` 324, `validated.rs` 161 checked narrowing newtypes (QueueId/VlanId/TunnelTtl `try_from_snapshot` fail-closed), `wg.rs` 127. Each file single responsibility, <850 LOC, good comments citing issue numbers. Late-stage NAT local-delivery append correctly must stay in mod.rs (comment explains why). `compute_pending_neigh_timeout_ns` with `SysctlReader` trait testable. This is the template for splitting `forwarding/mod.rs`.
- **Why exemplary:** Demonstrates how to decompose: orchestrator + per-entity builders + validated newtypes + explicit re-exports for cross-sibling consumers. No hot path impact (build is cold, once per snapshot apply).
- **Action:** Do not touch unless adding new entity type — then add new sibling file, not grow mod.rs.

### D-A1e-02 — worker/ already #959 decomposed into 11 sub-mods

- **Status:** D-negative (no further action, aside from loop_body inline intentional)
- **Evidence:**
  - `worker/mod.rs` 1631 orchestrator, `BindingWorker` struct declaration with fields grouped by phase comments (#959 Phase 1-11).
  - 11 sub-mods extracted: `telemetry.rs` 48 (23 dbg counters), `scratch.rs` 51 (11 scratch buffers), `cos_state.rs` 50 (5 CoS scheduling fields), `tx_counters.rs` 59 (6 TX disposition counters), `bpf_maps.rs` 35 (4 FDs), `timers.rs` 33 (6 timing fields), `tx_pipeline.rs` 69 (8 TX pipeline fields + submit_ns Box<[u64]>), `bind_meta.rs` 41 (bind_time, bind_mode, xsk_rx_confirmed), `flow_cache_state.rs` 35, `xsk_rings.rs` 40 (3 XSK handles), `lifecycle.rs` 335 (poll_binding), `cos/` 1131 (interface_row, queue_row, mod, status).
  - `loop_body/mod.rs` 1784 intentionally keeps per-tick inline per #1776 comment citing Codex r1-4 about inlining load_arc_if_changed (10k-100k ticks/s). Setup extracted to `setup.rs` 251, debug report to `debug_report.rs` 370 cfg(debug-log). Macros for flush_drained_session_deltas #2669 and chunked_drain_as_you_export #2442/#2653 prevent HA desync.
  - Each sub-mod small, single responsibility, no merge conflict magnet.
- **Why exemplary:** Shows how to decompose a large worker without regressing hot path. The intentional inline decision in loop_body is documented and justified.
- **Action:** Do not further split loop_body/mod.rs unless benchmarked. Future features should add new sub-mod, not grow mod.rs.

---

## 4. CoS TX drain focus deep dive (per optional focus line)

### Current shape
- `ForwardingState.cos: CoSState` contains `interfaces: FastMap<i32, CoSInterfaceConfig>` where each `CoSInterfaceConfig` has `shaping_rate_bytes`, `burst_bytes`, `default_queue`, `queues: Vec<CoSQueueConfig>`, flattened `dscp_queue_by_dscp: [u8;64]`, `ieee8021_queue_by_pcp: [u8;8]`, `queue_by_forwarding_class`, `oversubscription_policy`, etc.
- Workers hold `cos_fast_interfaces: FastMap<i32, WorkerCoSInterfaceFastPath>` (built via `build_worker_cos_fast_interfaces` from forwarding + owner live maps + shared leases). Fast path includes `tx_ifindex` (owner's resolving ifindex) + shared lease refs.
- TX drain: if `cos_fast_interfaces` contains egress_ifindex, packet is enqueued into CoS queue (per-queue token bucket, WRR, leased via `cos_shared_queue_leases` ArcSwap). Owner worker drains queue via `cos_queue_pop_front_no_snapshot` + `publish_cos_exact_backlog`. Non-owner enqueues to inbox? Actually cross-binding TX via `pending_tx_prepared` + `scratch_cross_binding_tx`.
- Single-owner FIFO: all packets for a CoS-shaped egress go to owner worker's queue, owner single-threads drain (preserves ordering, needed for shaping). If *every* interface is CoS-admitted (including fwd-only), *every* TX funnels to owner, collapsing 6 workers → 1 CPU. This was #916 regression fixed by `useful_cos_state` gate #1183.
- Gate details: 5-input OR (shaping_rate>0, scheduler_map resolved, dscp classifier targets iface queue, 802.1p classifier targets iface queue, dscp rewrite targets iface class). If none true, `Ok(None)` → skip interface, not inserted into `CoSState.interfaces`. So fwd-only interfaces stay out of CoS, their TX stays distributed across workers (no redirect).

### Remaining risks
- Gate is in `build_cos_iface_config` only; if future code adds new CoS feature (e.g., new classifier type) and forgets to add to gate, regression re-introduced.
- `cos_shared_queue_leases` etc 6 separate ArcSwaps cause 6 ptr_eq per tick; coalescing into 1 would reduce bus traffic (~12 atomic RMWs per tick per worker avoided already via #1188 load_arc_if_changed short-circuit, but still 6 checks).
- `forwarding.cos.interfaces` hot lookup is `FastMap` (fxhash) with `i32` key; per-packet it does hash + lookup. Could be flat array indexed by ifindex (ifindex is small int, up to ~100)? But FastMap is already fast.

### Fix direction (CoS focus)
- **Immediate:** Add `#[deny(clippy::...)`? No. Add test that fwd-only snapshot produces empty `cos.interfaces`. Already exists? Check `forwarding_build/tests.rs` - there is `cos` test module? 5108 LOC tests, likely covers gate via `useful_cos_state`? Search `useful_cos_state` test — not found explicitly, but `build_cos_iface_config` has logic. Add explicit test: `iface with no shaping rate, no scheduler map, classifier names empty → None`.
- **Short:** Document gate in `docs/cos-validation-notes.md` + code comment.
- **Medium:** Coalesce 6 shared ArcSwaps into single `CosSharedSnapshot` struct.
- **Verify:** iperf3 ≥23 Gbit/s on loss cluster with CoS config applied, and with *no* CoS config (fwd-only) also ≥23 Gbit/s (ensures no accidental CoS admission).

---

## 5. ForwardingState hot/cold SoA proposal (per optional focus line)

### Why `#[repr(C)]` + hot-field-first is zero-risk perf-positive

- Rust `#[repr(Rust)]` (default) may reorder fields for packing but still field access by name. `#[repr(C)]` guarantees declaration order = memory order, which allows us to control cacheline locality. No unsafe code in this crate does `transmute` or `offset_of` on ForwardingState (grep for `offset_of|transmute|ptr::read` in types/forwarding.rs returns none). So repr change is safe.
- Hot-first reorder: move all fields touched in `lookup_forwarding_resolution_inner_ecmp` and `owns_configured_ip` to front. L1 cache is 64 bytes lines, hot FIB maybe 2-3 cachelines if packed. Currently interleaved with cold `String` heap fields causes cold data to pollute hot cachelines when struct is `Arc`-deref'd? Actually `ForwardingState` is behind `Arc`, workers deref `&ForwardingState` per tick via `load_arc_if_changed`. The Arc's heap allocation contains the struct + its inline fields (not heap maps). The maps themselves are heap-allocated (HashMap buckets). But the struct's inline fields include `local_v4: FastSet` which contains its own heap alloc pointer + len; still, having hot FastSet pointers contiguous helps prefetch.
- Preserving `#[inline]` on `owns_configured_ip` (L502), `choose_v4_route` (L2595), `choose_v6_route`, `ecmp_hash_v4/v6` (L2665/L2669), `ecmp_hash_flow` (L2689), `ecmp_hash_flow_seeded` (L2697), `zone_pair_ids_for_flow_with_override` (L471-L489) ensures inlining across crate.

### Proposed hot block (in order)

```rust
#[repr(C)]
#[derive(Clone, Debug, Default)]
pub struct ForwardingState {
 // --- hot FIB (per-packet, per-flow) ---
 pub local_v4,
 pub local_v6,
 pub configured_iface_v4,
 pub configured_iface_v6,
 pub local_tables_v4,
 pub local_tables_v6,
 pub local_nat_any_table_v4,
 pub local_nat_any_table_v6,
 pub interface_nat_v4/v6,
 pub connected_v4/v6,
 pub routes_v4/v6,
 pub neighbors,
 pub ifindex_to_zone_id,
 pub zone_id_to_name,
 pub zone_name_to_id,
 pub egress,
 pub tunnel_endpoints,
 pub tunnel_endpoint_by_ifindex,
 pub gre_decap_index,
 pub fabrics,
 pub zone_host_inbound,
 pub ifindex_host_inbound,
 pub ingress_logical_ifindex,
 pub ifindex_to_routing_instance,
 pub ifindex_to_config_name,
 // --- warm (per-flow but not per-packet) ---
 pub zone_tcp_rst,
 pub reject_buckets,
 pub wg_engines,
 pub has_wg_tunnels,
 pub tunnel_interfaces,
 pub session_timeouts,
 pub session_opening_overrides,
 // --- cold (config, slow path, rarely touched) ---
 pub ifindex_to_name,
 pub filter_state,
 pub cos,
 pub policy,
 pub source_nat_rules,
 pub static_nat,
 pub dnat_table,
 pub nat64,
 pub nptv6,
 pub screen_profiles,
 pub screen_missing_profiles,
 pub syn_cookie_master_key,
 pub mirror_configs,
 pub tcp_mss_*,
 pub cold_path_sample_mask,
 pub pending_neigh_timeout_ns,
 pub cold_path_slot_map,
 pub zone_counter_slot_map,
 pub zone_counter_store,
 pub fabric_skips,
 pub allow_dns_reply,
 pub allow_embedded_icmp,
 // ...
}
```

### SoA split (Phase 2)

```rust
#[repr(C)]
pub struct ForwardingFib {
  // 20 hot fields above
}
pub struct ForwardingCold {
  // remaining 40+ cold fields
}
pub struct ForwardingState {
  pub fib: Arc<ForwardingFib>,
  pub cold: Arc<ForwardingCold>,
  // convenience deref via methods? Or keep flat but workers hold fib Arc separately.
}
```

Alternatively keep `ForwardingState` flat but introduce `struct ForwardingState { fib: Arc<FibInner>, ... }` where workers load `Arc<FibInner>` via `load_arc_if_changed` on `fib` ArcSwap, not whole state. This reduces clone cost (only hot part cloned) and cache pollution.

### Guardrails + HOW to verify

| Guardrail | How to verify |
|-----------|---------------|
| `#[inline]` preserved on `owns_configured_ip`, `choose_v4_route`, `ecmp_hash_*` | `cargo clippy` + grep for `#[inline]` after move; check disassembly not needed |
| `#[repr(C)]` does not break `transmute` | `grep -R "transmute\|offset_of.*ForwardingState" userspace-dp/` must be empty; `cargo test` passes |
| Hot-first reorder does not change logic | `cargo test -p xpf-userspace-dp --lib` + `make test` |
| SoA split does not regress throughput | `make cluster-deploy` + `apply-cos-config.sh` + `iperf3 -P 16 -t 30 -p 5203 172.16.80.200` ≥23 Gbit/s, no regression vs baseline |
| `useful_cos_state` gate still prevents fwd-only admission | Unit test `build_cos_iface_config` with empty iface → None; iperf3 fwd-only cluster same throughput |
| No new per-packet alloc | `cargo test` with allocation tracking? Check via `cargo bench` if exists, or audit via `grep "Vec::new\|Box::new" forwarding/mod.rs` in hot path must be zero |
| `canonical_route_table` Cow optimization kept #4674 | Check `lookup_forwarding_resolution_inner_ecmp` still uses `Cow::Borrowed(DEFAULT_V*_TABLE)` not owned |
| `ecmp_hash_flow` uses the stable ECMP domain seed (#11405) | Ensure production uses `ECMP_FLOW_HASH_SEED`, not `hot_path_hash_seed`; keep the per-boot seed on collision-sensitive caches/maps |

---

## 6. Summary prioritized action list

1. **PR0 (zero-risk):** Add `#[repr(C)]` + hot-first reorder to `ForwardingState` with comment blocks. Verify `cargo test` + iperf3.
2. **PR1 (low-risk):** Extract `neighbor/probe.rs` + `neighbor/affinity.rs` from `neighbor.rs` (pure helpers).
3. **PR2 (medium):** Extract `forwarding/fabric.rs` + `forwarding/ha.rs` from `forwarding/mod.rs` (move fns, no logic change).
4. **PR3 (medium):** Extract remaining `forwarding/fib_lookup.rs`, `mss.rs`, `pbr.rs`, `local_delivery.rs`, `nat_scope.rs` — final split of god-file.
5. **PR4 (B, SoA):** Introduce `ForwardingFib(Arc)` SoA split, workers hold hot FIB separately. Requires updating `forwarding_build` to output two Arcs, updating `worker/loop_body` ArcSwap refresh to handle two Arcs (fib + cold). Measure iperf3.
6. **PR5 (CoS):** Add explicit test for `useful_cos_state` gate, document in `cos-validation-notes.md`, coalesce 6 shared CoS ArcSwaps into single `CosSharedSnapshot` if beneficial (measure bus traffic via `perf`?).
7. **PR6 (cleanup):** Replace `super::*` in `neighbor_dispatch.rs` and `neighbor_resolver.rs` with explicit imports, extract tail helper from `retry_pending_neigh`.

---

## 7. Labels

- `modularity`, `god-struct`, `god-function`, `file-size`, `SRP`, `SoA`, `repr-C`, `hot-path`, `perf`, `CoS`, `FIF`, `parallelism`, `FIB`, `gate`, `D-negative` (for forwarding_build, worker)

---

## 8. Dedup notes

- F-A1e-01 overlaps with #4421 god-struct report (55 fields) but adds concrete 66-field inventory + hot/cold interleaving evidence + SoA split proposal.
- F-A1e-02 distinct from F-A1e-01 (file vs struct). Prior #1342 split forwarding_build but not forwarding/mod.rs — this fills gap.
- F-A1e-03 is neighbor.rs monolith, was noted as 1901→2036 in prior; this provides 4-resp breakdown + file split plan + shows neighbor_resolver/dispatch are genuine splits but still glob-coupled (F-A1e-05).
- CoS FIF (F-A1e-04) is separate perf concern, not duplicate of god-struct, but intersects via `ForwardingState.cos` cold field interleaving.
- forwarding_build exemplary D-negative acknowledges #1342 work, prevents re-splitting.
- worker #959 D-negative acknowledges prior decomposition, and documents why loop_body/mod.rs inline is intentional per #1776.

---

## 9. Paths (absolute, per instructions)

- `/tmp/review-wt-ps-043-a1e-b1/userspace-dp/src/afxdp/types/forwarding.rs` (1099)
- `/tmp/review-wt-ps-043-a1e-b1/userspace-dp/src/afxdp/forwarding/mod.rs` (2795)
- `/tmp/review-wt-ps-043-a1e-b1/userspace-dp/src/afxdp/forwarding/host_inbound.rs` (537)
- `/tmp/review-wt-ps-043-a1e-b1/userspace-dp/src/afxdp/forwarding_build/mod.rs` (705)
- `/tmp/review-wt-ps-043-a1e-b1/userspace-dp/src/afxdp/forwarding_build/fib.rs` (483)
- `/tmp/review-wt-ps-043-a1e-b1/userspace-dp/src/afxdp/forwarding_build/interfaces.rs` (340)
- `/tmp/review-wt-ps-043-a1e-b1/userspace-dp/src/afxdp/forwarding_build/zones.rs` (142)
- `/tmp/review-wt-ps-043-a1e-b1/userspace-dp/src/afxdp/forwarding_build/cos.rs` (850)
- `/tmp/review-wt-ps-043-a1e-b1/userspace-dp/src/afxdp/forwarding_build/tunnels.rs` (324)
- `/tmp/review-wt-ps-043-a1e-b1/userspace-dp/src/afxdp/forwarding_build/validated.rs` (161)
- `/tmp/review-wt-ps-043-a1e-b1/userspace-dp/src/afxdp/forwarding_build/wg.rs` (127)
- `/tmp/review-wt-ps-043-a1e-b1/userspace-dp/src/afxdp/neighbor.rs` (2036)
- `/tmp/review-wt-ps-043-a1e-b1/userspace-dp/src/afxdp/neighbor_resolver.rs` (805)
- `/tmp/review-wt-ps-043-a1e-b1/userspace-dp/src/afxdp/neighbor_dispatch.rs` (1421)
- `/tmp/review-wt-ps-043-a1e-b1/userspace-dp/src/afxdp/worker/mod.rs` (1631)
- `/tmp/review-wt-ps-043-a1e-b1/userspace-dp/src/afxdp/worker/loop_body/mod.rs` (1784)
- `/tmp/review-wt-ps-043-a1e-b1/userspace-dp/src/afxdp/worker/loop_body/setup.rs` (251)
- `/tmp/review-wt-ps-043-a1e-b1/userspace-dp/src/afxdp/worker/loop_body/debug_report.rs` (370)
- `/tmp/review-wt-ps-043-a1e-b1/userspace-dp/src/afxdp/worker/cos/mod.rs` (596)
- `/tmp/review-wt-ps-043-a1e-b1/userspace-dp/src/afxdp/worker/cos/interface_row.rs` (97)
- `/tmp/review-wt-ps-043-a1e-b1/userspace-dp/src/afxdp/worker/cos/queue_row.rs` (302)
- `/tmp/review-wt-ps-043-a1e-b1/docs/engineering-style.md` (read via worktree)

---

*End of A1e audit — outputs to `/tmp/review-work-ps-043/ps-a1e-b1.md` only.*


---
### Batch ps-a1f-b1.md — 49154 chars

# A1f — Screen / frame / inspect / policy / runtime — Refactor/Modularity Audit
Base: 4e0c7f74cf0dbacf83051b2a9b6cf4e050dcecaa
Worktree: /tmp/review-wt-ps-043-a1f-b1
Reviewer: ps-043 / Claude
Date: 2026-07-11

## Engineering Style Compliance Note
- Read `/tmp/review-wt-ps-043-a1f-b1/docs/engineering-style.md` via worktree as required.
- A1f scope touches dataplane hot path (`userspace-dp/src/afxdp/frame/`, `screen/`). Engineering-style hot-path rules apply: no per-packet alloc, preserve `#[inline(always)]` monomorphization, keep cache-line discipline.

---

## 1. Inventory

| File | Total LOC | Prod LOC (est) | Test LOC (est) | Largest fn | Largest fn LOC | Complexity Notes |
|------|----------|----------------|----------------|------------|----------------|------------------|
| `userspace-dp/src/screen/mod.rs` | 1540 | ~1260 | ~0 (tests in sibling `tests.rs` 5395 LOC) | `check_packet_with_zone_id_opts` | 331 LOC (L777-1107) | god-func: 5 SYN-flood phases + ICMP/UDP ×2 tiers + stateless dispatch + fabric skip + missing-profile WARN + alarm-without-drop |
| `userspace-dp/src/screen/scan.rs` | 1213 | 592 | 621 | `ScanCore::check` | ~56 LOC | exemplary generic core — **D-NEGATIVE** |
| `userspace-dp/src/afxdp/frame/inspect.rs` | 1960 | ~1400 | ~0 (split to `inspect_tests.rs` 517 + prop_tests) | `decode_frame_summary` | ~100 LOC | 5× EH walker dup inside one file + `parse_session_flow_from_bytes` 139 LOC second god-func |
| `userspace-dp/src/afxdp/frame/mod.rs` | 1772 | ~1650 | ~122 (cfg only) | `verify_built_frame_checksums` | 180 LOC | 6-resp kitchen sink despite 9 prior extractions (#988/#989/#1046/#1352/#1440) |
| `userspace-dp/src/afxdp/frame/wg.rs` | 1561 | 604 | 957 | `wg_encap_frame` | 253 LOC | byte-identity tests, no split smell — **D-NEGATIVE** |
| `userspace-dp/src/afxdp/types/runtime.rs` | 503 | 503 | 0 | `WorkerContext` / `BindingPlan` struct defs | ~50 LOC each | 14 plumbing types — pure relocation per 68.4 — **D-NEGATIVE** |
| `userspace-dp/src/policy.rs` | 3658 (prod only; tests in `policy_tests.rs` 7280) | 3658 | 0 (separate file) | `parse_policy_state_with_counters` | 523 LOC (L1717-2248) | 8-resp: zone-resolve, book table, app catalog, wildcard/global index, default-policy sentinel, hit-count store, AppID, fragment-assoc |

Total scope: ~11251 LOC across 7 files (prod ~10668, test ~1578 inline; plus sibling test files `policy_tests.rs` 7280, `screen/tests.rs` 5395, `frame/wg_tests.rs` 962 etc. not counted in per-file but relevant for gate).

Secondary dup sites checked:
- `userspace-dp/src/screen/extract.rs` 400 LOC — its own EH walker (different: screen-parse, fail-closed with `ScreenParseError`, but shares same `0|43|60|135|139|140|253|254 + 51 + 44` set post-#4517)
- `userspace-dp/src/nat64.rs` ~3400 LOC — 3 EH walkers: `ipv6_l4_offset_and_protocol` (L1315-1377), `ipv6_is_non_first_fragment` (L1388-1436), `ipv6_fragment_header` (L1457-1499) — all `0|43|60|135|139|140|253|254` clones
- `userspace-dp/src/afxdp/icmp_embed/parse.rs` 500 LOC — 1 EH walker `parse_embedded_v6_l4` (L108-169) same set
- Total distinct EH walker copies across codebase: **9 sites** per #4517 + #2150 prior, now 10 after #4435 alignment (still dup, only const unified).

---

## 2. File-by-file Log

### 2.1 `screen/mod.rs` (1540 LOC)
- **Roles found (7):**
  1. Config churn: `ScreenState` 22 fields, `update_profiles`, missing-profile WARN maps (4 maps), SYN cookie profile-gen map
  2. SYN-cookie epoch/wall-clock cache (`current_syn_cookie_full_epoch`, `read_unix_wall_secs`)
  3. Rate counters: `icmp_counters`, `udp_counters`, `syn_counters`, `syn_off_attack_buckets`, `syn_*_sketch` ×4, `icmp_dst_sketch`, `udp_dst_sketch`
  4. Hot-path verdict engine: `check_packet_with_zone_id_opts` (331 LOC) — the god-func
  5. Flowless screen path: `check_flowless_screens_opts` (duplicates 60% of hot-path stateless+flood logic)
  6. Advanced tracker lifecycle: `scan_sweep_drop_on_new_flow`, `maybe_cleanup_trackers`, `scan_cleanup_floors`
  7. Test seams / stats: missing-profile warn count, syn_flood_* Drops, alarm events

- Stateless checks already extracted to `stateless.rs` (good). But SYN-flood 180 LOC inline with 8 archaeology layers (#3315/#3607/#4112/#4155) — 5 phases interwoven.

- `check_packet_with_zone_id_opts` broken down:

| Phase | Lines | Responsibility | Inline? |
|-------|-------|---------------|---------|
| stateless dispatch | 808-826 | LAND, TCP flags, ping-death, teardrop, icmp-frag, src-route | cold-ish but hot-path |
| fabric skip | 828-845 + 665-727 | `skip_rate_flood` early-return, `icmp_flood_drop`/`udp_flood_drop` helpers | hot |
| scalars pull | 847-873 | 10 scalar thresholds copy to avoid borrow conflict | pattern correct |
| ICMP flood | 877-884 | Tier1 per-dst sketch + Tier2 token-bucket | hot |
| UDP flood | 886-901 | same, IP+port | hot |
| SYN flood 1: aggregate classify | 936-956 | single-window `increment_and_classify` D7 | **HOT** must stay inline |
| SYN flood 2: per-dst primary | 957-976 | `syn_dst_sketch` even cookie-active | **HOT** primary spoof-resistant |
| SYN flood 3: aggregate cookie / TokenBucket | 977-1040 | cookie ON → challenge, OFF → TokenBucket | **HOT** |
| SYN flood 4: alarm ≤1/sec/zone log-only | 1041-1059 | `syn_alarm_last_emit_sec` cadence | config-ish but hot |
| SYN flood 5: per-src secondary | 1060-1076 | skipped when cookie-active D3 | **HOT** but secondary |

- `ScreenState` field count: 22 fields across 7 sub-responsibilities — classic god-struct.

### 2.2 `screen/scan.rs` (1213 LOC total, 592 prod)
- `ScanCore<T>` generic with bounded eviction, per-zone cap O(1) via `per_zone_count`, `CLEANUP_BUDGET`, `EVICT_SCAN_LIMIT`, `MAX_CLEANUP_WINDOW_MICROS` type-max ceiling. Thin wrappers `PortScanTracker`/`IpSweepTracker`.
- One source of truth per #2234 — exemplary pattern. Tests cover saturation, pressure logarithmic rate, slow-scan evasion, cleanup floors.
- **D-NEGATIVE** — do not split further.

### 2.3 `afxdp/frame/inspect.rs` (1960 LOC)
- Roles (4):
  1. L3/L4 offset derivation: `frame_l3_offset` (VLAN-aware), `frame_l4_offset`, `packet_rel_l4_offset`, `packet_rel_l4_offset_and_protocol`, `v6_rel_l4_offset` (in mod.rs but logically part of this cluster)
  2. Fragment predicates: `ipv4_is_non_first_fragment`, `ipv6_is_non_first_fragment`, `is_non_first_fragment`, `ipv4_is_any_fragment`, `ipv6_is_any_fragment`, `is_any_fragment`, `ipv6_ext_chain_over_limit`
  3. Session-flow parsers: `parse_session_flow_from_bytes` (139 LOC second god-func), `parse_session_flow_from_frame`, `parse_ipv4_session_flow_from_frame`, `parse_session_flow_from_meta`, `l3_session_flow_from_meta`
  4. Filter/ICMP helpers: `term_match_extra_from_frame{,_fwd,_meta}`, `dest_is_multicast_or_broadcast`, `l2_dst_is_group_or_broadcast`, `neighbor_ip_is_learnable`, `source_is_invalid_for_icmp_error`, plus `ip_declared_end` / `declared_l3_end`

- EH walker duplication INSIDE this single file: 5 copies that are char-for-char identical except slice source:
  - `frame_l4_offset` L71-132 (frame slice)
  - `packet_rel_l4_offset` L209-265 (packet slice)
  - `packet_rel_l4_offset_and_protocol` L274-335 (same + proto return)
  - `ipv6_is_non_first_fragment` L363-411 (same walk, frag-bit test at frag hdr)
  - `ipv6_is_any_fragment` L449-491 (same walk, returns true on frag hdr seen)
  - Plus `ipv6_ext_chain_over_limit` L145-207 (dup of walk logic for over-limit detect)
  - Plus `frame_is_non_first_fragment` wrapper, `is_*` dispatchers

- Each walker spells:

```rust
0 | 43 | 60 | 135 | 139 | 140 | 253 | 254 => {
  let opt = frame.get(offset..offset+2)?;
  protocol = opt[0];
  offset = offset.checked_add((usize::from(opt[1])+1)*8)?;
}
51 => { /* AH (len+2)*4 */ }
44 => { /* Frag fixed 8 */ }
59 => return None,
_ => return Some(offset)
```

Bounded by `for _ in 0..MAX_IPV6_EXT_HEADERS` (8). #4517 fixed values across 5 sites in ONE commit — proves the drift risk (miss = IDS evasion).

### 2.4 `afxdp/frame/mod.rs` (1772 LOC)
- Roles (6) persisting despite 9 prior extractions:
  1. VLAN descriptor-shift: `classify_in_place_l2_rewrite` + `descriptor_view_in_same_umem_frame` (9 LOC avoids 1500B memmove via TX desc shift) + `RewritePrep`, `rewrite_prepare_eth*` — 384 LOC
  2. IPv4/v6 rewrite orchestrators: `rewrite_apply_v4`, `rewrite_apply_v6`, `rewrite_forwarded_frame_in_place` — TTL, NAT dispatch, port enforcement
  3. NAT v4/v6: `apply_nat_ipv4` (86 LOC), `apply_nat_ipv6` (119 LOC), `apply_nat_port_rewrite` 64 LOC `#[inline(always)]` family constant-fold #1853, `apply_nat_icmp_identifier_rewrite`, `adjust_l4_checksum_port`
  4. NAT64 port/id translation: `apply_nat64_port_translation` 114 LOC
  5. Inject builders: `build_injected_packet`, `build_injected_ipv4/v6` — 135 LOC cold
  6. Debug verify: `verify_built_frame_checksums` 180 LOC + statics — debug-only but in prod file

- The descriptor view helper and VLAN classify are exemplary hot-path optimizations but live in same file as cold inject builder and debug checksum verifier — violates one-responsibility.

### 2.5 `afxdp/frame/wg.rs` (604 prod / 957 test)
- `wg_encap_frame` 253 LOC + 4 helpers: `outer_physical_egress_ifindex`, `outer_physical_egress_mtu`, `wg_peer_outer_dst`, `wg_endpoint_physical_outer_mtu`. Each helper single-call-site except `wg_endpoint_physical_outer_mtu` also used by TX dispatcher for PTB inner-MTU derivation (#2684).
- Allocation elimination (#2792) documented, byte-identity test `wg_encap_in_place_matches_separate_buffer`.
- MTU guard reuses single FIB LPM per packet (#3992 instrumentation `OUTER_ROUTE_RESOLVE_COUNT`).
- **D-NEGATIVE** — correctly sized, well tested.

### 2.6 `afxdp/types/runtime.rs` (503 LOC)
- 14 plumbing types: `WorkerHandle`, `LocalTunnelSourceHandle/Entry`, `WgControlEntry`, `BindingPlan`, `SharedUmemMode/Role/Plan`, `ValidationState`, `HAForwardingLease`, `HAGroupRuntime`, `ResolutionDebug`, `LearnedNeighborKey`, `WorkerCommand`, `DebugPollCounters`, `WorkerContext`, `TelemetryContext`, `MirrorTargetMap`.
- Pure relocation from `types/mod.rs` per 68.4, widened visibility to `pub(in crate::afxdp)`, re-exported via `pub(in crate::afxdp) use runtime::*;`. No logic duplication, no hot-path code.
- **D-NEGATIVE** — exemplary decomp.

### 2.7 `policy.rs` (3658 LOC)
- Roles (8):
  1. Wire parsing: `parse_policy_state_with_counters` 523 LOC (L1717-2248) — book table build, literal sets, malformed preflight, global scope resolve, wildcard index build, `has_junos_host_rules` arming, rule-id→policy-id map
  2. Address matching: `parse_legacy_address_set`, `parse_v3_literal_set`, `parse_book_prefix_into`, `PrefixSetV4/V6`, `BookEntry`
  3. Application catalog: `ApplicationMatch`, `CompiledApplications::from_matches` + `matches` (L1004-1096) with config-order precedence, `has_l4_constrained_term`, `PortRange`
  4. AppID identification catalog: `AppCatalog` `from_snapshot`, `lookup_directional/forward/admitted` — **zero imports of PolicyRule**, only `crate::AppCatalogEntry` wire schema, used by forwarding_build + event_emit + session_glue/tests — **extraction candidate** (Issue notes)
  5. Evaluation engine: `evaluate_policy_result_l3_aware` (83 LOC but central), `evaluate_junos_host_policy_l3_aware`, `rule_l3_matches`, `try_match_rule`, fragment-assoc fail-closed (`rule_is_skipped_frag_ambiguous_deny`, `note_skipped_frag_deny`, `frag_associated_deny_result`, `apply_frag_deny_override`)
  6. Zone resolve: `zone_name_to_id_from_snapshot`, `resolve_policy_zone_id`, `zone_pair_key`, `GlobalZoneScope`, `build_global_zone_scope`, `effective_match_zones`
  7. Hit counters: `PolicyRuleCounter`, `PolicyCounterStore`, per-worker coalescer `PendingPolicyHitRecord`, `record_policy_hit_counter` (prod thread-local + test bypass), `flush_pending_policy_hit_record`, generation discard #3448, post-clear preservation #3782
  8. Configured pairs: `configured_zone_pairs` — wildcard/global expansion for cold-path histogram slots

- Largest function `parse_policy_state_with_counters` is infallible legacy wrapper `parse_policy_state` delegates to it — parse tests live in `policy_tests.rs` (7280 LOC) covering sentinel, duplicate id, unresolvable zone, ICMP field validity, fragment-assoc, AppCatalog tier precedence.

---

## 3. Findings

### Finding F1 — EH Walker 9-Site Clone — IDS Evasion Class Bug

- **Title:** IPv6 extension-header walker duplicated across 9 sites — #4517 fixed values across 5 sites in one commit, miss=IDS evasion / NAT64 frag bypass
- **Severity:** High (security)
- **Confidence:** High (direct grep evidence + historical #4517 incident)
- **Refactor class:** D (dedup / single-source-of-truth)
- **Evidence:**
  - Files: `frame/inspect.rs:71-132,209-265,272-335,363-411,449-491,145-207` (5+1 copies), `screen/extract.rs:224-360` (its own walk), `nat64.rs:1315-1377,1388-1436,1457-1499` (3 copies), `afxdp/icmp_embed/parse.rs:108-169` (1 copy)
  - Total 10 copies after #4435 bound unification onto `MAX_IPV6_EXT_HEADERS` (const shared, but **body** still cloned)
  - Quoted source (representative walker, `frame/inspect.rs:91-121`):
    ```rust
    let mut protocol = *frame.get(l3 + 6)?;
    let mut offset = l3 + 40;
    for _ in 0..MAX_IPV6_EXT_HEADERS {
        match protocol {
            0 | 43 | 60 | 135 | 139 | 140 | 253 | 254 => {
                let opt = frame.get(offset..offset + 2)?;
                protocol = opt[0];
                offset = offset.checked_add((usize::from(opt[1]) + 1) * 8)?;
            }
            51 => { /* AH */ }
            44 => { /* Frag */ }
            59 => return None,
            _ => return Some(offset),
        }
    }
    None
    ```
  - Same logic repeated verbatim in `nat64.rs:ipv6_l4_offset_and_protocol` L1315-1377 and `screen/extract.rs:248-360` (fail-closed variant with `ScreenParseError`).
  - Drift risk proven: #4517 commit message "fixed values across 5 sites, miss=IDS evasion" — exotic EH types (MOBILITY 135, HIP 139, SHIM6 140, EXP 253/254) were missing at 4 sites, allowing chain `HbH→Mobility→Frag→TCP` to hide SYN from screens and flow from forwarding.
- **Proposed decomposition:**
  - New module `userspace-dp/src/ipv6_ext.rs` (cold + hot): define `#[inline(always)]` generic walker core:
    ```rust
    #[inline(always)]
    pub fn ipv6_walk<F, G>(packet: &[u8], mut on_ext: F, on_l4: G) -> Option<...>
    // or typed enum walker returning WalkResult { l4_offset, l4_proto, frag_info }
    ```
  - Single const `EXT_IS_LENGTH_PREFIXED: [u8;8] = [0,43,60,135,139,140,253,254]` and single match arm produced via const fn predicate `is_generic_len_prefixed(next_hdr)`.
  - Monomorphized wrappers keep call-site performance:
    - `frame/inspect.rs` → re-export wrappers around core with `#[inline(always)]`, no dynamic dispatch.
    - `screen/extract.rs` → same core but fail-closed mapping to `ScreenParseError`.
    - `nat64.rs` → uses core with `MAX_IPV6_EXT_HEADERS` bound (already imported from `crate::afxdp`, but now core is outside afxdp to break dep cycle: afxdp depends on nat64? Actually nat64 depends on afxdp const — move const to new crate-root `ipv6_ext` module so both sides import from one place, no cycle).
    - `icmp_embed/parse.rs` → uses core with frag-non-first check built-in.
  - Canary test: new `tests/ipv6_ext_parity.rs` that enumerates chain `HbH(0) → Mobility(135) → HIP(139) → Shim6(140) → Exp253 → Exp254 → Routing(43) → DestOpt(60) → Frag(44) → TCP(6)` and asserts **all** prior walker sites (now wrappers) agree on `Some(l4_offset)` and `protocol==6`, plus asserts `is_non_first_fragment` and `is_any_fragment` agree. This test fails if any wrapper diverges.
- **Hot-path preservation:**
  - Walker is `#[inline(always)]` generic over slice type — monomorphization eliminates match-table indirection; const/monomorphization preserved (no dynamic dispatch, no trait object).
  - The `0|43|60|135|139|140|253|254` set becomes a `const fn is_generic_eh(u8) -> bool` inlined to same jump table as before (llvm folds 8-way equality to same codegen).
  - No new alloc, no new branch on hot path: hot path already looped `MAX_IPV6_EXT_HEADERS` times (8), same instructions.
  - Endianness locality untouched (byte 0 = next_hdr, byte 1 = len, big-endian irrelevant).
  - Branch/icache: reduces icache pressure (10 copies → 1 copy inlined at each site, same code size as before per inline, but centralized audit).
  - Prove with: `cargo rustc -- --emit=asm` diff or `objdump -d` on `frame_l4_offset` before/after — identical disassembly except symbol name of inlined helper.
- **Tests+gate:**
  - Existing: `frame/prop_tests/inspect.rs` property tests for over-limit, `screen/tests.rs` for extract, `nat64_tests.rs` for nat64 walker bound, `icmp_embed/parse.rs` embedded_v6_parse_tests.
  - New: canary parity test `ipv6_ext_walk_all_sites_agree` walking exotic chain, plus `#[test] nat64_walker_7_ext_headers_still_resolve` already exists — keep.
  - Gate: `cargo test --lib -- --nocapture ipv6_ext` + `make test-rust` (full cargo suite). Failover gate: `make test-failover` not required for this pure-parse change but run `make test-deploy` ping between zones to ensure no screen bypass regression.
- **Why it matters:** Exotic EH chain hiding SYN = SYN-flood bypass + policy bypass (flow not classified). #4517 incident says 5 sites missed 135/139/140/253/254. 9-site clone guarantees future drift when new IANA type added (e.g., 42?).
- **Fix direction:** Extract single `ipv6_ext.rs` crate-root module with `#[inline(always)]` core + monomorphized wrappers. Keep `MAX_IPV6_EXT_HEADERS` const in same module. Update 10 sites in one PR, prove byte-identical disassembly, add canary test.
- **Labels:** `security`, `modularity`, `D`, `eh-walker`, `ids-evasion`, `single-source-of-truth`
- **Dedup note:** Not covered by #2150 PR-2 (that PR noted 9-site dup but fix only unified const `MAX_IPV6_EXT_HEADERS`, not body). #4517 fixed body in one commit but left clone. This finding goes **beyond** those: proposes true single-function generic walker, not just const unification.

---

### Finding F2 — Screen god-func 331 LOC — 5-Phase SYN-Flood Inline

- **Title:** `check_packet_with_zone_id_opts` 331 LOC god-func mixes 5 SYN-flood phases, 8 flood reasons, 2 tier ceilings, fabric skip, alarm-without-drop, missing-profile WARN — cold config out but hot enforcement must stay `#[inline(always)]`
- **Severity:** Medium (maintainability, reviewability, hot-path audit cost)
- **Confidence:** High
- **Refactor class:** A (extract cold config/setup/stats/logging/emit, prove hot-path unchanged)
- **Evidence:**
  - File: `screen/mod.rs:777-1107` (331 LOC). `ScreenState` has 22 fields across 7 resp.
  - Largest func `parse_policy_state_with_counters` comparison shows similar shape in policy.rs but this one is per-packet hot path.
  - 5 SYN-flood phases explicitly documented in module doc but inline:
    ```rust
    // #3315 + #4112 F19 enforcement order (aggregate counts first, per-dst authoritative...)
    //   1. aggregate attack+alarm single-window (D7)
    //   2. per-dst primary spoof-resistant even cookie-active
    //   3. aggregate cookie challenge / TokenBucket drop cookie-off
    //   4. alarm ≤1/sec/zone log-only
    //   5. per-src secondary skipped when cookie-active D3
    ```
  - Code inside phase 3 has nested audit-mode guard:
    ```rust
    if !alarm_without_drop {
        if let Some(active_until) = self.syn_cookie_active_until_secs.get_mut(zone) {
            *active_until = now_secs.saturating_add(SynCookieCodec::EPOCH_SECS);
        }
    }
    ```
    (L1008-1020) — cold config (`alarm_without_drop`) inside hottest path.
  - `maybe_warn_missing_profile` callable from hot path does `FxHashMap::entry().or_default()` + `increment()` — log-flood protection correct but mixes observability with verdict.
  - `scan_sweep_drop_on_new_flow` duplicates zone-profile fetch and cleanup trigger.
- **Proposed decomposition:**
  - New modules under `screen/`:
    - `screen/missing_profile.rs`: `MissingProfileTracker` with `warn_counters`, `maybe_warn`, `update_missing_profiles`, `warn_count` — moves 3 maps out of `ScreenState`.
    - `screen/syn_cookie_guard.rs`: `SynCookieState { codec, validated_cache, active_until, standby_budgets, profile_gen, epoch_cache }` with methods `current_full_epoch`, `is_active`, `mint_challenge`, `validate_ack_on_miss`. Keeps `#[inline(always)]` on `is_active`/`take_valid` wrappers.
    - `screen/flood.rs`: `FloodState { icmp_counters, udp_counters, syn_counters, syn_off_buckets, icmp_dst_sketch, udp_dst_sketch, syn_dst_sketch, syn_src_sketch, syn_alarm_last_emit }` with `icmp_flood_drop`, `udp_flood_drop` (already exist, just move) and new `syn_flood_enforce(zone, pkt, thresholds, now_ns, now_secs, syn_cookie, alarm_without_drop) -> SynFloodVerdict`.
    - Split `check_packet_with_zone_id_opts` into cold/hot:
      - **Cold/setup** (non-inline): `resolve_profile(zone) -> Option<&ProfileScalars>` — pulls scalar thresholds, returns `ProfileScalars { icmp_flood, udp_flood, syn_flood, syn_cookie, alarm_without_drop, syn_*_thresholds }` struct copy (10 u32/bool). Ends `self.profiles` borrow so `&mut self` flood state accessible.
      - **Hot enforcement** (all `#[inline(always)]`): `fn check_stateless(profile, pkt) -> Option<DropReason>` dispatching to `stateless::*` (already extracted), `fn check_icmp_udp_flood(&mut self, ...)` (calls existing helpers), `fn check_syn_flood(&mut self, zone, zone_id, pkt, scalars, ...) -> SynVerdict` — contains the 5 phases **unchanged in instruction order**, but moved to `flood.rs` as `#[inline(always)]` fns.
      - Fabric skip stays at entry: `if skip_rate_flood { return Pass }` — zero-cost early return.
    - Keep `check_packet_with_zone_id_opts` as thin orchestrator (≤40 LOC) calling cold `resolve_scalars` then hot `#[inline(always)]` checks.
    - `ScreenState` becomes facade: `profiles`, `missing: MissingProfileTracker`, `cookie: SynCookieState`, `flood: FloodState`, `scan: ScanSweepState` — 5 fields vs 22.
- **Hot-path preservation:**
  - Inlining preserved via `#[inline(always)]` on all SYN-flood phases — prove via `cargo show asm` that `check_packet_with_zone_id_opts` monomorphizes to same instruction count (±0) as before.
  - No new alloc: all `FxHashMap` lookups already existed, `ProfileScalars` is stack copy (10×u32, ~48 bytes), no heap.
  - No dynamic dispatch: generic `FxHashMap` lookup stays monomorphized, no trait object.
  - Const/monomorphization preserved: `SECONDARY_FLOOD_CEILING_MULT` const stays in `flood.rs`, `NANOS_PER_SEC` in mod.rs.
  - Zero-copy: packet slice passed by reference unchanged.
  - Endianness locality: N/A (no new byte-order code, but existing `is_initial_syn` flag checks remain in place).
  - Branch/icache: thin orchestrator reduces icache footprint vs 331-LOC inline? Actually same instructions after inlining, but better prediction due to smaller function prologue. Provide disassembly diff showing no extra `call` on hot path.
  - Disassembly diff proof: `objdump -d target/debug/deps/userspace_dp-xxx | grep -A200 check_packet_with_zone_id_opts` before/after — must show identical `jmp`/`call` sequence inside flood phases, only symbol nesting differs.
- **Tests+gate:**
  - Existing `screen/tests.rs` 5395 LOC covers all 5 phases, alarm cadence, per-dst vs aggregate ordering (#4112 F19), per-src skip when cookie-active (D3), fabric skip #4155, validated-cache bypass, alarm-without-drop audit.
  - New: unit tests for each extracted module's cold path (missing-profile WARN rate limit, profile-gen bump #2446, epoch wall-clock caching #3032).
  - Gate: `cargo test --lib screen::` + `make test-rust` + `make test-deploy` ping zones 0% loss + `make cluster-deploy` + `iperf3 -P 16 -t 30 -p 5203 → 172.16.80.200 ≥23 Gbit/s` (CoS smoke via `apply-cos-config.sh`) + `make test-failover` (RETH failover must not regress — SYN-cookie active state preserved).
- **Why it matters:** 331-LOC hot path with 8 archaeology layers is unreviewable. Next SYN-flood sub-threshold change (#3315-style) must edit god-func again, risking regression in unrelated phase. Extracting cold config out makes hot enforcement phases auditable independently, each `#[inline(always)]` preserves perf.
- **Fix direction:** Module split as above, keep hot fns `#[inline(always)]`, prove disassembly identical, run failover/CoS smoke.
- **Labels:** `modularity`, `A`, `hot-path`, `syn-flood`, `screen`, `maintainability`
- **Dedup note:** Not a duplicate of #3315/#3607/#4112/#4155 bug fixes — those fixed logic inside god-func but never extracted it. This finding proposes structural extraction **without behavior change**, complementary to those fixes. Not covered by #2234 (which fixed `scan.rs` only).

---

### Finding F3 — Frame Kitchen Sink 6-Resp Despite 9 Prior Extractions

- **Title:** `frame/mod.rs` 1772 LOC remains 6-resp kitchen sink (VLAN descriptor-shift 384 LOC, NAT v4/v6 462 LOC, NAT64 port 114 LOC, inject cold 135 LOC, DSCP 39 LOC, debug verify 180 LOC) despite #988/#989/#1046/#1352/#1440 extractions
- **Severity:** Medium
- **Confidence:** High
- **Refactor class:** B (split by responsibility, keep hot `#[inline(always)]` NAT port/id rewriters)
- **Evidence:**
  - File: `afxdp/frame/mod.rs:143-1772` — module header already lists 6 responsibilities.
  - VLAN descriptor-shift:
    ```rust
    #[inline]
    fn descriptor_view_in_same_umem_frame(rx_addr: u64, tx_addr: u64, len: usize) -> bool {
        let frame_mask = (UMEM_FRAME_SIZE as u64).saturating_sub(1);
        let frame_base = rx_addr & !frame_mask;
        ...
    }
    #[inline]
    fn classify_in_place_l2_rewrite(...) -> Option<(u64, InPlaceL2Rewrite)> {
        if target_eth_len == current_l3 { return SameLength }
        if current_l3 == 14 && target_eth_len == 18 { /* push */ }
        ...
    }
    ```
    L481-517 (36 LOC) + `rewrite_prepare_eth_from_parts` L520-586 (67 LOC) + `RewritePrep` struct L459-471 — 384 LOC total for descriptor trick that avoids 1500B memmove.
  - NAT v4/v6:
    ```rust
    pub(super) fn apply_nat_ipv4(packet: &mut [u8], protocol: u8, nat: NatDecision, non_first_fragment: bool) -> Option<()>
    pub(super) fn apply_nat_ipv6(packet: &mut [u8], rel_l4: usize, protocol: u8, nat: NatDecision, non_first_fragment: bool)
    #[inline(always)]
    pub(in crate::afxdp::frame) fn apply_nat_port_rewrite(packet: &mut [u8], l4_offset: usize, protocol: u8, family: ChecksumFamily, nat: NatDecision)
    ```
    L884-1196 — 462 LOC, but `apply_nat_port_rewrite` is `#[inline(always)]` for #1853 constant-fold.
  - Inject builders L1424-1540 cold path — shouldn't live in hot rewrite file.
  - Debug verify L1552-1731 `verify_built_frame_checksums` — debug-only `cfg(feature="debug-log")` gated, 180 LOC.
- **Proposed decomposition:**
  - `frame/vlan.rs`: `descriptor_view_in_same_umem_frame`, `classify_in_place_l2_rewrite`, `RewritePrep`, `rewrite_prepare_eth_from_parts`, `rewrite_prepare_eth` — VLAN descriptor-shift concern, keep `#[inline]` on descriptor-view and classify (already hot).
  - `frame/nat.rs`: `apply_nat_ipv4`, `apply_nat_ipv6`, `apply_nat_port_rewrite` (preserve `#[inline(always)]`), `apply_nat_icmp_identifier_rewrite` (`#[inline(always)]`), `adjust_l4_checksum_port` (`#[inline(always)]`) — NAT concern, 462 LOC becomes its own module.
  - `frame/nat64_rewrite.rs`: `apply_nat64_port_translation`, `build_nat64_forwarded_frame` — 114+106 LOC, cross-family but still NAT.
  - `frame/inject.rs`: `build_injected_packet`, `build_injected_ipv4/v6` — cold path, 135 LOC, keep behind `pub(super)`.
  - `frame/verify.rs`: `verify_built_frame_checksums`, `CSUM_*` statics — debug-only, gated `#[cfg(feature="debug-log")]`.
  - `frame/mod.rs` becomes orchestrator: `rewrite_forwarded_frame_in_place`, `build_forwarded_frame_from_frame`, `v6_rel_l4_offset` (shared offset truth), `apply_dscp_rewrite_to_frame` (39 LOC, stays).
  - Each new module re-exported at `frame::*` same visibility so existing `use frame::...` call sites unchanged.
- **Hot-path preservation:**
  - `apply_nat_port_rewrite` / `apply_nat_icmp_identifier_rewrite` / `adjust_l4_checksum_port` stay `#[inline(always)]` — family constant-fold #1853 preserved (v4 hot path must not pay v6 §5.5 rule). Prove by checking `nm` symbol not present in release binary (inlined) before/after.
  - `descriptor_view_in_same_umem_frame` stays `#[inline]` — hot path check avoids 1500B memmove via TX descriptor shift.
  - No new alloc: NAT rewriters operate on `&mut [u8]` slice, no Vec.
  - No dynamic dispatch: all `ChecksumFamily` enum matched via const-folded branch.
  - Const/monomorphization: `ChecksumFamily::V4/V6` stays enum, not trait object.
  - Zero-copy: VLAN descriptor trick (`tx_offset = rx_addr ± 4`) avoids memmove preserved.
  - Endianness locality: `write_ipv4_src` etc. use `byte_writes` module, unchanged.
  - Branch/icache: splitting reduces `frame/mod.rs` compile time, same inlined hot path, fewer cold branches in same translation unit → better icache locality for `rewrite_apply_v4/v6`.
- **Tests+gate:**
  - Existing `tests_nat_rewrite.rs` 1267 LOC, `tests_ttl_descriptor_dscp.rs` 1252 LOC, `tests_mss_inject_inspect.rs` 525 LOC cover NAT, VLAN descriptor, inject.
  - New: no new tests needed for relocation — existing tests import via `super::*` still resolve.
  - Gate: `cargo test --lib frame::tests_nat_rewrite` + `make test-rust` + `make test-deploy` + iperf3 CoS path (VLAN push/pop exercised in `reth0.50`/`.80`).
- **Why it matters:** 6-resp file means a DSCP rewrite change touches same file as VLAN descriptor-shift optimization — review coupling. Prior 9 extractions (#988/#989/#1046/#1352/#1440) show pattern: each extraction made next change safer. Residual 6-resp is next iteration.
- **Fix direction:** Extract 5 modules as above, keep `#[inline(always)]` on port rewriters, re-export at `frame::`, prove disassembly diff shows no extra call on `rewrite_apply_v4` hot path.
- **Labels:** `modularity`, `B`, `frame`, `nat`, `vlan`, `cold-path`
- **Dedup note:** Not duplicate of #1049/#1352/#1543 — those extracted `build/`, `rewrite/`, `tcp/` etc. This finds **remaining** 6-resp after those extractions. Complements, not supersedes.

---

### Finding F4 — Policy.rs AppCatalog Extraction Candidate (Zero-Import of PolicyRule)

- **Title:** `AppCatalog` (`FxHashMap<u8, AppProtoEntries>`) zero-imports `PolicyRule`, only `crate::AppCatalogEntry` wire schema, used by `forwarding_build` + `event_emit` + `session_glue` — extraction candidate per #4421
- **Severity:** Low-Medium (modularity, compile-time boundary)
- **Confidence:** High
- **Refactor class:** C (relocation, no behavior change)
- **Evidence:**
  - File: `policy.rs:1113-1334` — `AppCatalog` + `AppProtoEntries` + `AppScanEntry` + `lookup_directional/forward/admitted` — 221 LOC that never touches `PolicyRule`, `PolicyState`, `ZoneSnapshot`, or hit counters.
  - Constructor `from_snapshot(entries: &[crate::AppCatalogEntry])` only uses `app_id`, `protocol`, `dst_port_low/high`, `src_port_low/high` — pure wire schema.
  - Consumers: `forwarding_build` builds `AppCatalog` from snapshot, `event_emit` resolves app_id for RT_FLOW, `session_glue/tests` uses `lookup_*`. All outside policy evaluation core.
  - Zero imports of `PolicyRule` verified: grep `PolicyRule` inside `AppCatalog` impl returns none.
  - `policy.rs` total 3658 LOC (largest file in `userspace-dp/src/` excluding generated), 8 resp — AppCatalog extraction reduces to 7 resp and cuts 221 LOC.
- **Proposed decomposition:**
  - New file `userspace-dp/src/app_catalog.rs` (or `app_id.rs`): move `AppCatalog`, `AppProtoEntries`, `AppScanEntry`, `from_snapshot`, `lookup_directional/forward/admitted`, `is_empty`.
  - Keep `AppCatalogEntry` wire schema in existing location (crate-level mod), import via `crate::AppCatalogEntry`.
  - `policy.rs` imports `crate::app_catalog::AppCatalog` — no circular dep.
  - Cold config path: `AppCatalog::from_snapshot` is called on snapshot apply only, not per-packet.
  - Hot path `lookup_directional` stays `#[inline]` (already `#[inline]`), called per-session install + RT_FLOW emit — keep inline.
  - Tests: move `app_catalog`-related tests from `policy_tests.rs` (if any) to `app_catalog_tests.rs`, or keep in `policy_tests.rs` importing new path.
- **Hot-path preservation:**
  - `lookup_directional` is `#[inline]` and called on session install (cold-ish, once per flow) and RT_FLOW emit (poll tick) — not per-packet fast path? Actually session-hit fast path does NOT call it, only cold path `resolve_policy_deny_app_id` and permit audit `lookup_admitted`. So inlining optional but preserve.
  - No new alloc, no dynamic dispatch.
  - Const/monomorphization: `FxHashMap<u8, _>` lookup stays.
  - Prove with `cargo test --lib policy::` unchanged.
- **Tests+gate:**
  - Existing `policy_tests.rs` covers AppCatalog tier precedence #3612 (port-constrained vs proto-only, lowest id tiebreak).
  - Gate: `cargo test --lib app_catalog` + `make test-rust`.
- **Why it matters:** `policy.rs` is 3658 LOC, 8 resp — largest module in `userspace-dp/src/`. AppCatalog is separable concern (AppID identification, not policy allow/deny verdict). Extraction reduces cognitive load for next policy change.
- **Fix direction:** Move to `app_catalog.rs`, keep `#[inline]` on lookups, update imports, no behavior change.
- **Labels:** `modularity`, `C`, `policy`, `app-catalog`, `zero-import`
- **Dedup note:** Prior #4421 flagged `policy.rs` too broad — this is the concrete extraction proposed there (AppCatalog zero-import). Not duplicate, it's the resolution.

---

### Finding F5 — Policy Parser 523-LOC God-func — Config/Integrity/Book/AppIndex Interleaved

- **Title:** `parse_policy_state_with_counters` 523 LOC parses 5 concerns (book table, literal sets, app catalog, wildcard/global indexes, hit-counter store) with 4 fail-closed integrity gates interleaved — split cold config/setup out without touching hot `evaluate_policy_result_l3_aware`
- **Severity:** Medium (maintainability, auditability of fail-closed gates)
- **Confidence:** High
- **Refactor class:** B (split cold config phases, prove hot evaluation unchanged)
- **Evidence:**
  - File: `policy.rs:1717-2248` (523 LOC) — single function with 4 early-return integrity errors:
    1. L1758-1791: duplicate rule-id / duplicate policy-id (M01) preflight
    2. L1807-1892: book table build + `parse_book_prefix_into` family enforcement M02 + malformed prefix #3711
    3. L1893-1976: per-rule literal sets `parse_v3_literal_set` / `parse_legacy_address_set` + v3/legacy malformed #3367/#3711 + sentinel #3261
    4. L2049-2092: application term `parse_applications` dropped_any #2124 + invalid ICMP #3712
    5. L2132-2227: global scope `build_global_zone_scope` + zone resolve + wildcard index build
  - Each phase is cold (snapshot apply, ~1/s), but interleaved with `PolicyRule` struct construction that has 22 fields.
  - Hot evaluation `evaluate_policy_result_l3_aware` (L2600-2879) is **separate** and already `#[inline]`-friendly — NOT inside this func, but the file mixes cold/hot.
  - The 523-LOC func has 6 nested loops and 8 `return Err(...)` sites — review of one integrity gate requires reading entire func.
- **Proposed decomposition:**
  - `policy/parse.rs`: `parse_books(address_books) -> Result<(Vec<BookEntry>, FxHashMap<u32,u32>,), SnapshotIntegrityError>` — book table build + family enforcement.
  - `policy/literals.rs`: `parse_rule_literals(snap) -> Result<(v4/v6 literal sets, book idxs, match_any flags, empty flags, malformed), _>` — literal sets + match-any precompute.
  - `policy/apps.rs`: `parse_rule_apps(snap) -> Result<(applications, compiled_apps), _>` — application parsing + compiled index + ICMP validity.
  - `policy/zone_index.rs`: `build_zone_indexes(rules, zone_name_to_id) -> Result<(zone_pair_index, from_any_index, to_any_index, both_any, global_indices, concrete_zone_ids, has_junos_host_rules, rule_id_to_policy_id), _>` — zone resolve + wildcard + host scope arming.
  - `policy.rs` orchestrator `parse_policy_state_with_counters` becomes ≤80 LOC calling these cold phases sequentially, then assembling `PolicyState`.
  - Hot path `evaluate_policy_result_l3_aware` stays in `policy/eval.rs` with `#[inline(always)]` on `try_match_rule`, `rule_l3_matches`, fragment-assoc helpers.
- **Hot-path preservation:**
  - Hot evaluation **not touched** — `evaluate_policy_result_l3_aware` already separate func, can be moved to `policy/eval.rs` with same signature.
  - No new alloc on hot path: cold parse phases allocate `Vec<BookEntry>`, `FxHashMap`, `SmallVec` — all snapshot apply time, not per-packet.
  - Prove hot path unchanged: disassembly of `evaluate_policy_result_l3_aware` before/after must be byte-identical.
- **Tests+gate:**
  - Existing `policy_tests.rs` 7280 LOC covers all integrity error paths (duplicate id, unresolvable zone, sentinel, malformed literal, app dropped, ICMP invalid).
  - Gate: `cargo test --lib policy_tests` + `make test-rust` + `make test-deploy` policy permit/deny functional.
- **Why it matters:** 523-LOC cold func with 4 interleaved integrity gates is where next fail-closed hardening (#3261/#3711-style) will land — needs module split to make each gate auditable independently.
- **Fix direction:** Extract 4 cold phases as above, keep `evaluate_policy_result_l3_aware` untouched (or moved verbatim), prove hot disassembly identical.
- **Labels:** `modularity`, `B`, `policy`, `cold-path`, `fail-closed`
- **Dedup note:** Issue #4421 already flagged `policy.rs` too broad — this is concrete split for its largest fn. Not duplicate of AppCatalog extraction (F4) — this is about the parser, not AppID catalog.

---

### Finding F6 — Frame/inspect.rs `parse_session_flow_from_bytes` 139 LOC Second God-func

- **Title:** `parse_session_flow_from_bytes` 139 LOC (L1411-1549) mixes non-first-fragment gate (#2344), ICMP identifier bearing gate (#3290), meta fast-path, frame fallback, declared_end clamping, IPv4/v6 branches — second god-func in inspect.rs
- **Severity:** Low-Medium (readability, testability of fragment/ICMP gates)
- **Confidence:** Medium-High
- **Refactor class:** B (split by phase, keep `#[inline(always)]` on fragment predicate)
- **Evidence:**
  - File: `frame/inspect.rs:1411-1549` — 139 LOC, 5 phases:
    1. frag gate `frame_is_non_first_fragment` early return
    2. ICMP id-bearing gate `meta_icmp_identifier_bearing` discard
    3. meta fast-path `metadata_tuple_complete`
    4. frame parse `parse_session_flow_from_frame` vs `parse_ipv4_session_flow_from_frame`
    5. meta-offset fallback with `ipv4_declared_l3_end` / `ipv6_declared_l3_end` clamping (#2361)
  - Each phase has fail-closed semantics documented but interleaved.
  - `parse_session_flow_from_frame` (L1642-1702) and `parse_ipv4_session_flow_from_frame` (L1783-1855) are themselves 60+ LOC each with their own frag gates and declared_end clamping — similar duplication.
- **Proposed decomposition:**
  - `frame/session_flow.rs`: `parse_from_bytes`, `parse_from_frame`, `parse_ipv4_from_frame`, `parse_from_meta`, `l3_from_meta` — session flow parsing concern, keep `#[inline]` on frag predicate and `metadata_tuple_complete`.
  - Cold error enum `SessionFlowError { NonFirstFragment, NonQueryIcmp, Truncated, NoFlow }` for each phase's early-return reason (observability).
  - Hot path `frame_is_non_first_fragment` stays `#[inline(always)]` (VLAN-aware L3 resolve + version check).
- **Hot-path preservation:** Fragment predicate and `metadata_tuple_complete` already `#[inline(always)]`/`#[inline]` — preserve. No alloc on fast path (returns `Option<SessionFlow>` cloned only when meta tuple complete). Prova via `cargo bench` not required — disassembly diff same.
- **Tests+gate:** Existing `tests_parse_forward_pbr.rs`, `tests_ports_live_forward.rs` cover session flow parsing. Gate `make test-rust`.
- **Labels:** `modularity`, `B`, `frame`, `session-flow`, `fragment`
- **Dedup note:** Not covered by #1049/#1352 splits (those were build/rewrite). This is about flow-parse side.

---

## 4. D-Negatives (No Refactor Needed — Exemplary)

### D1 — `screen/scan.rs` `ScanCore<T>` Generic Core

- **Why D-negative:** Single generic `ScanCore<T>` with `Check` + `cleanup` + `evict_stalest_in_zone` — one source of truth per #2234. Bounded O(1) per-zone count via `per_zone_count`, `EVICT_SCAN_LIMIT` fixed prefix sample (not O(sources) min-scan), `CLEANUP_BUDGET`, window-aware `MAX_CLEANUP_WINDOW_MICROS` type-max ceiling (#4418) closing >5min evasion. Thin wrappers `PortScanTracker`/`IpSweepTracker`. Tests cover saturation, logarithmic pressure events, slow-scan survival across >5min window. No further split needed.

### D2 — `afxdp/frame/wg.rs` 604 Prod / 957 Test — Byte-Identity Tests

- **Why D-negative:** `wg_encap_frame` 253 LOC is large but single-responsibility (WG transit encap). Allocation elimination #2792 documented, outer underlay dedup #3992 instrumented via `OUTER_ROUTE_RESOLVE_COUNT`, per-peer outer MTU #2845, physical egress SSOT #2680/#2701. Helpers `outer_physical_egress_ifindex`, `outer_physical_egress_mtu`, `wg_peer_outer_dst` each have single call-site except PTB path — correct factoring. Tests: `wg_encap_in_place_matches_separate_buffer` byte-identity, `udp6_checksum_matches_scalar_reference` parity, `OUTER_ROUTE_RESOLVE_COUNT ==1` dedup assertion. Prod/test ratio 604/957 exemplary. No split needed.

### D3 — `afxdp/types/runtime.rs` 503 LOC Plumbing

- **Why D-negative:** 14 types pure relocation from `types/mod.rs` per 68.4, no logic, no hot path, visibility widened to `pub(in crate::afxdp)` and re-exported. Structs like `WorkerHandle` with 7 Arc fields, `BindingPlan`, `SharedUmemBindingPlan`, `WorkerContext` with 19 `&'a` fields — all plumbing. No duplication, no god-func. Exemplary decomp — do not touch.

---

## 5. Cross-Cutting Concerns

### 5.1 EH Walker Single Source of Truth + Canary Test

Current state: 10 sites, 1 const shared (`MAX_IPV6_EXT_HEADERS`), 9 body clones. #4517 fixed values in one commit but left clone. #4435 aligned bound but not body. #2292 note says "full walker-function unification remains tracked separately" — this audit makes it concrete:

- SSOT module: `userspace-dp/src/ipv6_ext.rs` (or `crate::ipv6::ext`) with:
  - `pub const MAX_IPV6_EXT_HEADERS: usize = 8`
  - `#[inline(always)] pub fn is_generic_ext_hdr(proto: u8) -> bool` → matches `0|43|60|135|139|140|253|254`
  - `#[inline(always)] pub fn walk_ipv6_ext_chain<F>(packet, visitor) -> WalkResult` generic walker that calls visitor per header type
  - Specialized wrappers: `ipv6_l4_offset_and_protocol`, `ipv6_is_non_first_fragment`, `ipv6_is_any_fragment`, `ipv6_ext_chain_over_limit`, `ipv6_fragment_header` — each `#[inline(always)]` monomorphizing the core.
  - All 10 call sites become 1-line delegations.
- Canary test: `tests/ipv6_ext_parity.rs` walking chain `HbH(0) → Mobility(135) → HIP(139) → Shim6(140) → Exp253 → Exp254 → Routing(43) → DestOpt(60) → Frag(44, offset 0) → TCP(6)` asserts all wrappers agree on `Some(l4_offset=..., proto=6)`, then same chain with `Frag offset !=0` asserts `is_non_first_fragment==true`, `is_any_fragment==true`, `l4_offset==None`. Failure means walker drift reintroduced.

### 5.2 SYN-Flood Cold Config Out / Hot Enforcement Inline

- Cold config: `alarm-without-drop` bool, thresholds (7 scalars), `syn_cookie` bool, missing-profile maps, epoch cache. Moves to `screen/missing_profile.rs` / `screen/syn_cookie_guard.rs` / `screen/flood.rs` cold constructors.
- Hot enforcement: 5 phases stay `#[inline(always)]` in `screen/flood.rs`:
  - Phase 1 aggregate classify D7 single-window `increment_and_classify`
  - Phase 2 per-dst primary spoof-resistant even cookie-active
  - Phase 3 aggregate cookie challenge / TokenBucket drop cookie-off
  - Phase 4 alarm ≤1/sec/zone log-only
  - Phase 5 per-src secondary skipped when cookie-active D3
- Prove with disassembly diff + `cargo test --lib screen::syn_flood` + failover gate (cookie active during failover must still drop flood, alarm must fire ≤1/sec).

### 5.3 Policy Verdict Engine Cold/Hot Split

- Cold: book table, literal sets, app catalog, zone indexes, hit-counter store — snapshot apply time, alloc-heavy, no inline needed.
- Hot: `evaluate_policy_result_l3_aware`, `try_match_rule`, `rule_l3_matches`, fragment-assoc helpers — per-packet / per-flow, must stay `#[inline]` / `#[inline(always)]`, no alloc, no dynamic dispatch.
- Separator: `PolicyState` facade holds cold indexes + hot `rules` vec. `eval.rs` imports only `PolicyRule`, `PolicyState`, `SessionKey`, `IpAddr` — no book table.
- Prove: `cargo test --lib policy_tests` + `make test-failover` (policy during failover) + disassembly of `evaluate_policy_result_l3_aware` identical.

---

## 6. Hot-Path Preservation Checklist (for any refactor PR)

For each extracted hot fn:

- [ ] `#[inline(always)]` preserved on: `apply_nat_port_rewrite`, `apply_nat_icmp_identifier_rewrite`, `adjust_l4_checksum_port`, `frame_l4_offset`, `packet_rel_l4_offset*`, `ipv6_is_*_fragment`, `check_stateless` wrappers, SYN-flood phases 1-5, `evaluate_policy_result_l3_aware` inner loops
- [ ] No new heap alloc on hot path: `&[u8]` slice in, `Option<()>` out, no `Vec`, no `String`, no `Box`
- [ ] No dynamic dispatch: no `dyn Trait`, no `impl Trait` existential that erases, `ChecksumFamily` enum not trait object
- [ ] Const/monomorphization: `MAX_IPV6_EXT_HEADERS` const, `SECONDARY_FLOOD_CEILING_MULT` const, `ChecksumFamily` enum folded via `#[inline(always)]` family param — check via `llvm-ir` that v4 path has no `switch` on family
- [ ] Zero-copy: VLAN descriptor-shift `tx_addr = rx_addr ±4` avoids `memmove`, NAT rewrites in-place on `&mut [u8]`
- [ ] Endianness locality: `u16::from_be_bytes` / `to_be_bytes` at L4 port read/write sites preserved, not moved behind indirection that loses locality
- [ ] Branch/icache: hot `if syn_flood_threshold>0 && proto==TCP && is_initial_syn` early-exit stays at top, not buried after cold map lookup
- [ ] Disassembly diff: `objdump -d` of `rewrite_apply_v4`, `check_packet_with_zone_id_opts`, `evaluate_policy_result_l3_aware` before/after — no extra `call`, instruction count Δ ≤2
- [ ] Smoke gates: `make test-deploy` ping 0% loss, `make cluster-deploy` + `apply-cos-config.sh` + `iperf3 -P16 -t30 -p5203 → 172.16.80.200 ≥23 Gb/s`, `make test-failover` / `test-ha-crash` 0/low loss

---

## 7. Recommended PR Stack (in order)

1. **P1 — EH Walker SSOT** (`type: D`, High severity): `ipv6_ext.rs` + 10-site delegation + canary parity test. No behavior change, prove disassembly identical. Gate: `make test-rust` + `nat64_tests` + `screen/tests`.
2. **P2 — Screen god-func A-split**: extract `missing_profile.rs`, `syn_cookie_guard.rs`, `flood.rs`, thin orchestrator `check_packet_with_zone_id_opts`. Preserve `#[inline(always)]` on 5 phases. Disassembly diff gates + failover/CoS.
3. **P3 — Frame kitchen sink B-split**: `vlan.rs`, `nat.rs`, `nat64_rewrite.rs`, `inject.rs`, `verify.rs`. Keep `#[inline(always)]` port rewriters. Gate: `tests_nat_rewrite`, `tests_ttl_descriptor_dscp`, `test-deploy`.
4. **P4 — Policy cold parse B-split**: `policy/parse.rs`, `literals.rs`, `apps.rs`, `zone_index.rs`, `eval.rs`. Keep hot eval identical. Gate: `policy_tests` + `test-deploy`.
5. **P5 — AppCatalog C-relocation**: `app_catalog.rs` zero-import extraction. Gate: `policy_tests` AppID tier tests.

P1 is security (IDS evasion class) — do first. P2 is maintainability of hottest screen path — do second with failover gate. P3+P4+P5 can parallelize after P1.

---

## 8. Labels Summary

- F1 EH Walker: `security`, `modularity`, `D`, `eh-walker`, `ids-evasion`, `single-source-of-truth`, `high`
- F2 Screen god-func: `modularity`, `A`, `hot-path`, `syn-flood`, `screen`, `maintainability`, `medium`
- F3 Frame kitchen sink: `modularity`, `B`, `frame`, `nat`, `vlan`, `cold-path`, `medium`
- F4 AppCatalog: `modularity`, `C`, `policy`, `app-catalog`, `zero-import`, `low`
- F5 Policy parser: `modularity`, `B`, `policy`, `cold-path`, `fail-closed`, `medium`
- F6 Session flow god-func: `modularity`, `B`, `frame`, `session-flow`, `fragment`, `low`
- D-negatives: `scan.rs` generic core, `wg.rs` byte-identity, `runtime.rs` plumbing — no action

---

## 9. Dedup Note — Why Not Known Issues

- #4421 policy.rs too broad: F4+F5 are concrete resolutions of it (AppCatalog zero-import + parser split), not duplicate. #4421 was issue, these are implementation plans.
- #2150 PR-2 / #4517 EH walker dup: Prior PRs unified const `MAX_IPV6_EXT_HEADERS` and fixed values across 5 sites in one commit, but left **body** cloned across 10 sites. F1 proposes true generic walker core, not just const — goes beyond prior fixes.
- #1049/#1352/#1543 frame/build-rewrite: Extracted `build/`, `rewrite/`, `tcp/` — F3 is residual 6-resp after those, complementary.
- No existing issue covers screen god-func 331 LOC 5-phase extraction with disassembly proof + failover/CoS gates — F2 is new.
- No existing issue covers `parse_session_flow_from_bytes` 139 LOC second god-func — F6 is new.
- Scan/wg/runtime D-negatives explicitly called out to prevent re-auditing them — matches task's "D-negatives" requirement.


---
### Batch ps-a1g-b1.md — 59392 chars

# A1g — WG, event_stream, cold_path_hist, coordinator, types, protocol, server/helpers — Refactor/Modularity Audit

Base SHA: 4e0c7f74cf0dbacf83051b2a9b6cf4e050dcecaa
Date: 2026-07-11
Auditor: ps-043-a1g-b1
Worktree: /tmp/review-wt-ps-043-a1g-b1/

---

## 0. File-Size / Shape Inventory

| File | Total LOC | Prod LOC (approx) | Largest fn | # fns / # types | Responsibility |
|------|-----------|-------------------|------------|-----------------|----------------|
| `wg/engine.rs` | 1805 | ~1500 | `try_decap` ~223 | ~30 fns / 8 types | WG crypto engine: encap/decap/transports, peer table, handshake classify, replay window |
| `wg/cookie.rs` | 857 | ~700 | misc <90 each | ~20 fns / 5 types | WG DoS cookie checker: load-state, budget, source-table GC, MAC1/MAC2 verification |
| `wg/tests.rs` | 3909 | 0 (test-only) | — | test harness | WG engine + cookie integration tests |
| `event_stream/mod.rs` | 1701 | ~1400 | `handle_drain_request` 198, `mono_ns→wall` 198 | 20 fns / 3 core structs | Event stream: transport (Unix socket I/O thread), sequencing (seq_lock+next_seq), clock conversion (mono↔wall), replay/drain/backpressure |
| `event_stream/codec/mod.rs` | 86 | 86 | <12 each | small | Codec re-export shim (already split per #4651) |
| `event_stream/codec/wire.rs` | 284 | 284 | 19 | ~10 fns | Wire constants: frame header layout, message types, disposition encoding |
| `event_stream/codec/decode.rs` | 90 | 90 | small | 2 fns | Decode helpers for control frames |
| `event_stream/codec/rt_flow.rs` | 540 | 540 | `encode_session_close_rt_flow` 207 | ~4 fns | RT_FLOW SessionClose/Create encoding (large wire struct) |
| `event_stream/codec/session_sync.rs` | 271 | ~200 | `encode_session_open` 183 | ~3 fns | Session-sync open/update/close encoding |
| `event_stream/codec/codec_tests.rs` | 1023 | 0 (tests) | — | tests | Codec roundtrip tests |
| `event_stream/producer.rs` | 466 | ~400 | `try_emit_dataplane_frame` 59 | ~15 fns / 6 types | Dataplane event producer: rate-limiter (token bucket per kind/zone), queue-budget, counters |
| `event_stream/tests/*` | ~400 total | 0 (tests) | — | tests | Event stream integration tests |
| `cold_path_hist.rs` | 954 | ~700 | `calibrate_wrapper_baseline_ns` ~105 | ~15 fns / 4 types | Cold-path hist: TSC sampling, 48-bucket log-linear selector, direct zone-pair slot-map, atomics, counters |
| `coordinator/wg_control.rs` | 1579 | ~1300 | `run_wg_control_loop` 320 | 15 fns | WG control thread: socket lifecycle, poll(2) model, handshake attempt SM, ECN cmsg parsing, encap/send, TUN I/O |
| `coordinator/status.rs` | 1045 | ~900 | `worker_runtime_snapshots` 200 | ~20 fns (all `impl Coordinator`) | Coordinator status surface: per-binding/worker/CoS counters, Prometheus aggregates |
| `coordinator/mod.rs` | 982 | ~800 | `queue_warm_pass` 166 | ~10 fns + modulerefs | Coordinator orchestrator: 14 submodules, HA/session/CoS lifecycle, endpoint summary transition logging |
| `coordinator/tunnel_supervision.rs` | 960 | ~800 | `spawn_one_local_tunnel_source` 156 | ~8 fns | Local tunnel source thread lifecycle (GRE/TUN), tombstone+backoff respawn, slow-path MTU warn |
| `types/cos.rs` | 1786 | ~1500 | `transmit_rate_bytes` 297 | ~20 fns / 15 types | CoS type definitions: interface config, classifier, queue fast-path/runtime, flow-fair ring, sojourn, telemetry |
| `protocol/binding.rs` | 1185 | ~900 | `BindingStatus` default/serial + `BindingCountersSnapshot` | 6 structs + 1 static assert | Protocol wire types: WorkerRuntime, HAGroup, QueueStatus, BindingStatus, counters snapshot, Exception/SessionDelta |
| `protocol/control.rs` | 1088 | ~900 | `From<SlowPathStatus>` 410 | 10+ structs + 1 const | Control socket wire shapes: ControlRequest/Response, ProcessStatus, WgTunnelStatus, session-sync wire |
| `types/forwarding.rs` | 1099 | ~900 | `Debug for ForwardingState` ~366 | ~8 structs + 5 impls | Forwarding state types: ZoneHostInbound, ForwardingState, RouteEntryV4/V6, NeighborEntry, WgRuntimePeer, TunnelEndpoint, FabricSkipReason, Disposition/Resolution |
| `server/helpers.rs` | 1304 | ~1200 | `refresh_status` 323 (was 311 at time of task), `snapshot_binding_plan_key` 183 | 21 fns | Dumping ground (header: "Pure relocation pending further split"): status refresh, session-sync builders, binding-plan hashing, canonical JSON hashing, VLAN parent resolution, queue planning, linux ifname/sysfs helpers, file-IO |
| `event_emit.rs` | 598 | ~500 | `emit_policy_deny_event` 91 | ~10 fns / 1 enum | RT_FLOW deny/screen/filter-log emission: action mapping, wire constant table, zone/owner RG wire conversion, screen reason ID |
| `types/shared_cos_lease/lease.rs` | 1460 | ~1200 | `acquire_v8_with_cause` 282 | ~35 fns / 3 structs | Shared CoS queue lease: v8 epoch-grant, worker claim, equal-flow fair enforcement, credit pack/unpack, consume/release |

Key note: `event_stream/codec.rs` as named in the task (1165 LOC) no longer exists — already split into `codec/mod.rs + wire.rs + decode.rs + rt_flow.rs + session_sync.rs` per prior #4651 filing. Current total across new files is ~1271 LOC code + 1023 LOC tests. This audit evaluates the MOD split, not the pre-split monolith.

---

## 1. File-by-File Log (what checked + sound + why)

### 1.1 `wg/engine.rs` (1805 LOC)
**What checked:** Struct layout, `try_encap` / `try_decap` hot-path bodies, `MaybeUninit` stack scratch (`PADDED_PLAINTEXT_MAX`), `Arc<WgSession>` clone-and-release-lock pattern, `pad_to_16` branchless helper, peer table `ArcSwap`, replay-window double-mutex sequence.
**Sound because:** Single-responsibility WG protocol engine. Every member field + method directly implements one RFC 8927 stage (key mgmt → handshake classify → transport encap/decap → replay filter → AllowedIPs gate). Hot-path `try_encap` clones the session `Arc` under lock then releases before calling snow — documented in file header. `MaybeUninit<[u8; PADDED_PLAINTEXT_MAX]>` avoids stack-init for the padded plaintext. Splitting would widen `pub(in crate)` of internal types (`PeerTable`, `PendingHandshake`, `Tai64nClock`) without reducing per-file complexity. Prior frame/wg.rs #2792 alloc elimination already landed.
**Verdict:** D-negative (do-not-split).

### 1.2 `wg/cookie.rs` (857 LOC)
**What checked:** `SecretState` / `LoadState` / `BudgetState` / `SourceTable` / `SourceBucket` internal types, `CookieChecker` public API, `InitiatorCookie`, `fill_random` fallback, MAC constants (`M3_RECEIVER`, `M3_NONCE`, `M1_MAC1/2`), blake2s MAC.
**Sound because:** One cohesive DoS-mitigation mechanism: cookie generation/verification keyed on `(responder_pubkey || per-boot secret)`, per-source rate tracking, under-load window, GC interval. All internal types are tightly coupled: `SecretState` owns the key + timer, `LoadState` counts handshakes, `SourceTable` tracks per-IP buckets. Splitting into e.g. `cookie/secret.rs + cookie/budget.rs` would create 3 trivial files <150 LOC with circular lifetime deps on the same `CookieChecker` struct.
**Verdict:** D-negative.

### 1.3 `wg/tests.rs` (3909 LOC)
**What checked:** Test-only file. Covers engine + cookie + tie-ins.
**Sound:** Test file, not a refactor candidate. Its size is expected (comprehensive WG protocol tests). Excluded from A/B/C findings.
**Verdict:** D-negative (test-only, ignore for prod refactor).

### 1.4 `event_stream/mod.rs` (1701 LOC)
**What checked:** Four co-located responsibilities: (i) clock conversion (`read_mono_and_wall_clocks`, `monotonic_ns_to_unix_ns/secs`, `mono_ns_to_wall_clock_unix_ns`), (ii) transport I/O thread (`io_thread_main`, `try_connect`, `replay_buffered`, `write_all_backpressured`, `run_connected_loop`, `process_control_frames`, `handle_drain_request`), (iii) sequencing/producer facade (`EventStreamShared`, `EventStreamSender`, `EventStreamWorkerHandle`, `send_sequenced`, `send_lossless_encoded`, `push_delta`, `emit_session_close_rt_flow`), (iv) backpressure/replay accounting (`drain_channel_into_write_buf`, `push_replay_frame`, `evict_replay_frame`, `pop_replay_frame`, `release_*_budget`).
**Not sound as single file:** Largest function `handle_drain_request` 198 LOC + `run_connected_loop` 137 LOC + `replay_buffered` (from 2016 onward ~100) compose a connection-state-machine that is independently unit-testable; clock conversion trio (`read_mono_and_wall_clocks` + `monotonic_ns_to_unix_ns` + `monotonic_ns_to_unix_secs_subnanos`) is pure math with no channel/socket deps, reusable from flow-export. `refresh_status`-like accumulation in `EventStreamShared::stats()` mixes ownership of metrics that belong on the producer side.
**Verdict:** A-positive (mechanical cold-path — see finding A1).

### 1.5 `event_stream/codec/` (split dir — total ~1271 code + 1023 tests)
**What checked:** `wire.rs` (frame header layout, disposition encoding), `decode.rs` (control frame decode), `rt_flow.rs` (SessionClose/Create wire struct ~540 LOC), `session_sync.rs` (SessionOpen/Update/Close encoding), `mod.rs` (re-export).
**Sound because:** Already split per #4651. Each subfile is single-responsibility (wire constants separate from RT_FLOW framing separate from session-sync framing). `rt_flow.rs` 540 LOC is dominated by a single 207-LOC encoder for a fixed 256-byte wire struct (field-by-field `LittleEndian` writes) — mechanical but not separable without type-level fragmentation.
**Verdict:** D-negative (already decomposed; file sizes acceptable post-split).

### 1.6 `event_stream/producer.rs` (466 LOC)
**What checked:** `DataplaneEventRateLimitConfig`, `DataplaneEventRateLimit`, `DataplaneEventRateBucket`, `DataplaneEventRateLimiter`, `DataplaneEventQueueBudget`, `DataplaneEventCounters`, `kind_index`, `rate_bucket_index`, `try_emit_dataplane_frame`.
**Sound because:** Single cohesive mechanism: per `(kind, zone)` token-bucket limiting + queue-share division. All types exist to service `try_emit_dataplane_frame`. 466 LOC total is under threshold for a B/C split, and there is no hot/cold seam inside (the rate-bucket check is on the deny-path, not per-packet forward).
**Verdict:** D-negative (cohesive, size under threshold for new module).

### 1.7 `cold_path_hist.rs` (954 LOC)
**What checked:** Constants block (`POLICY_COLD_PATH_HIST_BUCKETS=48`, linear stride, 256 zone-pair slots), `bucket_index_for_ns_48` (≈`#[inline]` hot), `bucket_upper_bound_ns_48`, `zone_pair_packed_key`, `ColdPathSlotMap` (sparse HashMap + inverse Vec + overflow flag), `ClockSource` (TSC calibrate + RDTSCP wrappers), `WorkerColdPathAtomics` (per-slot sample accumulation), `WorkerColdPathCounters` (publish counters). Tests cover bucket math + slot map collisions.
**Borderline:** Two natural seams: (1) pure math (`bucket_index_for_ns_48`, `bucket_upper_bound_ns_48`, `zone_pair_packed_key`, constants) — 0-alloc, `#[inline]`, hot-ish (called on every first-packet-per-flow sample). (2) `ColdPathSlotMap` build/lookup + `ClockSource` TSC calibrate + atomics/counters aggregation. The hot math is <100 LOC, already `#[inline]`, co-located with its constant definitions that consumers also need. Moving it to a sibling file would force cross-file inlining dependency for a micro-recorder that runs < once per flow (not per-packet).
**Verdict:** D-negative (cohesive cold-path histogram; two responsibilities present but first is tiny and must stay `#[inline]` next to constants; second is already the whole file).

### 1.8 `coordinator/wg_control.rs` (1579 LOC)
**What checked:** File header (#1432 S2a), outer MTU constant, `pad_to_16`, `wg_encapped_size`, `wg_inner_fits_outer_mtu`, `WG_RX_BURST/WG_POLL_CAP_MS/WG_TIMER_TICK_NS/WG_TUN_FATAL_READ_LIMIT` constants, `wg_control_loop` entry (socket bind + option set + TUN attach), `InboundOutcome` enum, `HandshakeAttempt`/`AttemptTrigger`/`PollWait` enums, `wg_poll_wait` poll(2) wrapper, `poll_timeout_ms`, `run_wg_control_loop` 320 LOC (RX bursts + TX bursts + timer tick + attempt machine + exception recording), `start_attempt`, `drive_attempt_machine` 133 LOC (attempt SM), `send_keepalive`, `pace_keepalive_skip`, `bind_wg_socket`/`bind_dual_stack_v6`, `canonicalize_endpoint`, `wg_send_to`, `set_recv_tos_options` 88 LOC (setsockopt `IP_RECVTOS`/`IPV6_RECVTCLASS`), `wg_recvmsg` 48 LOC (recvmsg+control parse), `parse_outer_ecn_from_cmsg` 39 LOC (cmsg iteration for TOS/TC), `sockaddr_storage_to_socketaddr`, `drive_initiation`, `dispatch_inbound` 215 LOC (type-byte dispatch + endpoint learning + outcome), `encap_and_send`.
**Not sound:** Six distinct cold-path responsibilities fused via one `run_wg_control_loop` function: (a) socket lifecycle (bind v6 dual-stack + nonblock + ECN options + fatal-path tombstone), (b) poll(2) wait model (`PollWait` + idle/timeout cap + revents fatal classification), (c) TUN attach + fatal-read-limit accounting, (d) ECN cmsg ancillary receive (`wg_recvmsg` + `parse_outer_ecn`) for RFC 6040 §4.2 combine, (e) handshake attempt state-machine (`HandshakeAttempt` + `AttemptTrigger` + `start_attempt` + `drive_attempt_machine`), (f) inbound dispatch + encap egress. (a)+(b)+(d) are independently testable without a live WG engine; (e) is a pure SM with timer + peer state inputs. Impacts testability and makes the 320-LOC control loop the sole integration seam.
**Verdict:** A-positive (see finding A2).

### 1.9 `coordinator/status.rs` (1045 LOC)
**What checked:** All methods `impl Coordinator` status getters. Pure `ArcSwap::load` + aggregate. No mutation except `drain_session_deltas`.
**Sound-ish but large:** Single responsibility (status surface — the coordinator's Prometheus/gRPC status mapping). Each getter is small (10-30 LOC) but there are ~20 of them → 1045 LOC. Mechanical split along dimension "CoS status vs session status vs neighbor/fabric status vs exception/worker status" would reduce per-file size without exposing new `pub(in crate)` — all methods already read only Coordinator fields via `self`.
**Verdict:** C-low (optional mechanical grouping — see finding C1). Not high priority because file is readable as a flat list of getters.

### 1.10 `coordinator/mod.rs` (982 LOC)
**What checked:** 14 `mod` declarations, `pub(crate) use` re-exports, utility fns `wg_endpoint_set_summary`, `tunnel_remap_purge_ids`, `filter_replayed_synced_sessions`, `log_wg_endpoint_set_transition`, `fabric_skip_set_summary`, `log_fabric_skip_transition`, struct `Coordinator` definition (25 fields), `impl Coordinator` constructor + reconcile entry points.
**Sound:** Orchestrator file already decomposed into focused submodules (bpf_maps, cos_leases, cos_state, ha_state, inject, neighbor_manager, reconcile, refresh_bindings, session_manager, snapshot_refresh, status, supervisor, tunnel_supervision, wg_control, worker_manager). At 982 LOC it's under typical split threshold for an orchestrator that defines the central struct.
**Verdict:** D-negative (orchestrator, already well-split via submodules).

### 1.11 `coordinator/tunnel_supervision.rs` (960 LOC)
**What checked:** `impl Coordinator` methods: `reconcile_local_tunnel_liveness` / `reconcile_wg_control_liveness` (tombstone-only + snapshot-coherent), `spawn_local_tunnel_source` + `spawn_one_local_tunnel_source`, backoff/timestamp bookkeeping, `LocalTunnelSourceEntry` + `WgControlEntry` lifecycle, exception recording.
**Sound:** Single responsibility: local tunnel source (GRE/TUN) thread supervision + WG control-thread liveness. Tombstone+backoff respawn + attachment-stale prune + spawn-gate — one cohesive supervision loop, naturally mirrored for GRE vs WG. Splitting by tunnel kind (GRE vs WG) would duplicate the tombstone/backoff/exception machinery.
**Verdict:** D-negative (cohesive supervisor; 960 LOC acceptable for a single supervisor).

### 1.12 `types/cos.rs` (1786 LOC)
**What checked:** File header notes "Pure relocation" from `afxdp/types/mod.rs` (Issue 68.1). 22 type definitions (interface config, classifier, rewrite rule, loss-priority rewrite, EqualFlowTargetPolicy, queue config, FlowRrRing + FlowRrRingIter, WorkerCoSQueueFastPath, WorkerCoSInterfaceFastPath, InterfaceRuntime, QueuePopSnapshot, QueueRuntime, QueueConfigState, QueueHotState, FlowFairState, VMinQueueState, TimerWheelRuntime/Scratch, QueueOwnerProfile, PendingTxItem) + constants (CoV flows, CoS policies) + methods (`transmit_rate_bytes`, flow-fair RR, owner-worker assignment).
**Sound:** All are type definitions — no I/O, no hot-path logic beyond trivial getters. The file is a type module extracted in Issue 68.1. The largest method `transmit_rate_bytes` 297 LOC computes a rate from CoS config — still a pure getter on CoS config. Splitting by interface vs queue vs flow-fair vs fast-path would create 4-5 files each re-importing from the same `super::*` with mutual field references.
**Verdict:** D-negative (type bag, already-extracted via Issue 68.1; size acceptable for a type module).

### 1.13 `protocol/binding.rs` (1185 LOC)
**What checked:** Wire structs only: `WorkerRuntimeStatus` (bulk of file — ~220 LOC serde+defaults), `HAGroupStatus`, `QueueStatus`, `BindingStatus` (per-binding AF_XDP binding state), `BindingCountersSnapshot` + `From` conversion + compile-time `Send` assertion, `ExceptionStatus`, `SessionDeltaInfo`, `u64_is_zero` helper.
**Sound:** Protocol crate leaf — pure serde wire shapes with no logic. `WorkerRuntimeStatus` is large due to many `#[serde(default)]` fields (one per counter) but that's inherent to wire additive evolution. Not a logic dump.
**Verdict:** D-negative (wire type module, no logic to split).

### 1.14 `protocol/control.rs` (1088 LOC)
**What checked:** `ZoneTrafficCounterStatus`, `MAX_CONTROL_REQUEST_BYTES` const, `ControlRequest` (large serde struct, aggregates all optional sub-requests), `ProcessStatus` (per-tick aggregate — ~500 LOC of optional sub-states), `SlowPathStatus`, `WgPeerStatus`, `WgTunnelStatus`, `ControlResponse`, sub-request shapes (Forwarding/HA/Queue/Binding/InjectPacket/SessionSync/SessionDeltaDrain/SessionExport).
**Sound:** Protocol's central leaf — defines the Go↔Rust control socket schema. Single responsibility (control socket schema). Large because it aggregates every sub-snapshot type — that's the contract, not accidental complexity. `From<SlowPathStatus>` 410 LOC is decode mapping — one `match` per field, unavoidable.
**Verdict:** D-negative (protocol schema definition, not splittable without fragmenting the Go-Rust contract).

### 1.15 `types/forwarding.rs` (1099 LOC)
**What checked:** `SynCookieMasterKey` Debug impl, `ZoneHostInbound`, `ForwardingState` (central struct), `RouteEntryV4/V6`, `NeighborEntry`, `WgRuntimePeer`, `TunnelEndpoint`, `FabricSkipReason`, `ForwardingDisposition`, `ForwardingResolution`, `WorkerBindingLookup`. All pure data.
**Sound:** Forwarding-state type module — central data-def + trivial impls. No I/O, no timers, no state machines.
**Verdict:** D-negative (type module).

### 1.16 `server/helpers.rs` (1304 LOC, header: "Pure relocation pending further split")
**What checked:** File header explicitly marks as dumping ground. 21 functions: `refresh_status` 323 LOC (status counter accumulation + WG liveness + GRE liveness + binding refresh + neighbor/bpf status — mechanically distinct arms), `forwarding_unsupported_error` 11 LOC, `build_synced_session_key` 71 LOC, `build_synced_session_entry` 193 LOC + `build_nat64_reverse_rebuild` (inlined helper ~50 LOC), `parse_session_sync_mac` 19 LOC, `reconcile_status_bindings` 41 LOC, `should_run_afxdp`/`same_plan_apply_needs_binding_reconcile`/`set_bindings_forwarding_armed`/`wait_for_binding_settle`/`bindings_settled` (tiny binding-state predicates), `same_binding_plan`/`snapshot_binding_plan_key`/`update_snapshot_binding_plan_key`/`hash_update`/`update_json_encoded`/`update_canonical_json_hash`/`canonical_json_key`/`write_canonical_json`/`Sha256Writer` (hashing domain ~250 LOC), `vlan_child_parent_netdev`/`snapshot_has_parent_candidate` (VLAN parent lookup), `include_userspace_binding_interface` 91 LOC, `plan_key_rx_queues`/`replan_queues`/`replan_bindings_from_candidates`/`summarize_queues` (queue planning domain ~200 LOC), `linux_ifname`/`effective_rx_queues`/`set_rx_queue_count_override`/`clear_rx_queue_count_override`/`rx_queue_count` (sysfs/override helpers, with global `static Mutex<HashMap>` override).
**Not sound:** Pure relocation note acknowledges it. Five distinct mechanical domains share one file: (i) status refresh (→ daemon/monitoring), (ii) session-sync key/entry/NAT64 rebuild (→ session/sync), (iii) binding-plan hash + canonical JSON (→ hashing), (iv) binding selection / queue planning / VLAN parent (→ binding selection), (v) linux-ifname / rx-queue count / sysfs / file-IO (→ platform abstraction). `refresh_status` itself is 323 LOC of counter accumulation (35+ field copies) that is already logic meant to live in `coordinator/status.rs` or a new `server/status_refresh.rs`. No hot path — all called from server control path.
**Verdict:** A-positive (see finding A3).

### 1.17 `event_emit.rs` (598 LOC)
**What checked:** `RT_FLOW_ACTION_*` / `RT_FLOW_CLOSE_REASON_*` / `SCREEN_*` constants (bit-flags), `FilterLogSource`, `EmitCtx`, `emit_policy_deny_event`, `emit_screen_drop_event`, `emit_filter_log_event`, `policy_action_to_rt_flow`, `filter_action_to_rt_flow`, `ingress_ifindex_to_wire`, `owner_rg_id_to_wire`, `screen_reason_id`, plus production helpers.
**Sound:** Single responsibility: map internal disposition/action/filter-match to RT_FLOW wire bytes via `EventStreamWorkerHandle`. All helpers exist to service that emission. 598 LOC dominated by `emit_policy_deny_event` (91 LOC — builds SessionClose-like frame with policy applied). Calls are already on the deny/log path (not per-packet permit), so inlining is not critical.
**Verdict:** D-negative (cohesive deny/log emission facade, small).

### 1.18 `types/shared_cos_lease/lease.rs` (1460 LOC)
**What checked:** `SharedCoSQueueLease` (rate+burs+shard-count, `new_v8` constructor family, `acquire_v8_with_cause` 282 LOC — top-up + epoch check + tag check + grant calc + per-cause fail-open accounting), `SharedCoSRootLease`, `SharedCoSLeaseConfig`/`State`, `compute_shared_cos_lease_config`, `pack/unpack_shared_cos_lease_credits`, `shared_cos_lease_acquire`, `shared_cos_lease_consume`, `shared_cos_lease_available_cap`, `refill_shared_cos_lease_state`, plus v8 claim/rollback helpers (`try_bump_outstanding`, `bump_epoch_event`, `record_equal_flow_active_sample`, `worker_grant_bump`, `tag_checked_rollback`). Hot path: `acquire_v8_with_cause` is called on TX drain to grant up to N bytes to a queue; `consume` / `release_unused` on fast-path completion.
**Borderline:** Two interleaved responsibilities: (a) per-queue lease (acquire/consume/release + v8 equal-flow) — hot, `#[inline]` critical, per-queue atomic seq-lock; (b) root-lease (class-cap) — cold-ish, single instance, holds class-aggregate state. However, (a) and (b) are coupled via `SharedCoSLeaseState` (shared bank + outstanding cap) and the fail-open cause chain references both, so splitting would widen visibility to `pub(super)` for 5+ internal types and 2 statics. At 1460 LOC it's large but the bulk is the `acquire_v8_with_cause` state machine — already `#[inline]` via the outer type's `#[inline(always)]` on some helpers. Splitting now would risk cross-crate inlining loss on the TX drain hot path.
**Verdict:** D-negative with size-watch (keep as-is, but note 1500-LOC ceiling reached — next feature addition should split root-lease into `shared_cos_lease/root.rs` and keep queue-lease as-is).

---

## 2. Findings

### Finding A1 — event_stream/mod.rs fused transport + sequencing + clock + replay/drain — mechanical cold-path split

- **Title:** `event_stream/mod.rs` mixes I/O thread, sequencing, clock conversion, and replay/drain backpressure — 1701 LOC fused cold-path
- **Severity:** M (Maintainability, chance of bug from intermix)
- **Confidence:** High
- **Refactor class:** A — mechanical cold-path (no hot-path impact, zero-alloc changes needed, purely thread/control flow owned by helper Go-side, not AF_XDP workers)
- **Evidence:**
  - `/tmp/review-wt-ps-043-a1g-b1/userspace-dp/src/event_stream/mod.rs:43` `fn read_mono_and_wall_clocks() -> (u64, u64)` — 28 LOC pure math, no channel/socket dep, 0 use in I/O thread itself:
    ```rust
    fn read_mono_and_wall_clocks() -> (u64, u64) {
        let mut mono = libc::timespec { tv_sec: 0, tv_nsec: 0 };
        ...
        let rc_mono = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut mono) };
    ```
  - `mod.rs:71-125` `monotonic_ns_to_unix_ns` / `monotonic_ns_to_unix_secs_subnanos` / `mono_ns_to_wall_clock_unix_ns` — clock conversion trio, independently reusable from flow-export (#2465, #2853, #2470 comments), ~80 LOC total.
  - `mod.rs:246-370` `EventStreamShared` — sequencing + channel + replay buffer + per-kind counters + rate-limiter all on one struct (7 Atomics for frames_*, 1 Mutex, 1 ArcSwap for producer_seq_lock, plus dataplane_event_counters/limiter/queue triples) — 124 LOC struct.
  - `mod.rs:374-900` `EventStreamSender` + `EventStreamWorkerHandle` + `push_delta` + `emit_session_close_rt_flow` — facade/producer interleave, ~500 LOC.
  - `mod.rs:947-1701` I/O thread — `io_thread_main`, `try_connect`, `replay_buffered`, `write_all_backpressured`, `run_connected_loop` (137 LOC), `process_control_frames`, `handle_drain_request` (198 LOC largest fn), replay-queue management — transaction boundary, draining, heartbeat KeepAlive — ~450 LOC.
- **Proposed decomposition:**
  - `event_stream/clock.rs` ← `read_mono_and_wall_clocks`, `monotonic_ns_to_unix_ns`, `monotonic_ns_to_unix_secs`, `monotonic_ns_to_unix_secs_subnanos`, `mono_ns_to_wall_clock_unix_ns`, plus `NS_PER_SEC` const (pure math + one double clock_gettime, no alloc, no locks).
  - `event_stream/transport.rs` (or `io.rs`) ← `io_thread_main`, `try_connect`, `replay_buffered`, `write_all_backpressured`, `run_connected_loop`, `process_control_frames`, `handle_drain_request`, `drain_remaining`, `drain_channel_into_write_buf`, `push_replay_frame`/`evict_replay_frame`/`pop_replay_frame`, plus the `WRITE_BACKLOG_MAX_BYTES`, `MAX_CONTROL_PAYLOAD_LEN`, `REPLAY_BUFFER_CAPACITY`, `CHANNEL_CAPACITY`, `KEEPALIVE_IDLE_INTERVAL`, `REPLAY_DRAIN_WRITE_DEADLINE/POLL` constants + `DrainOutcome` struct. This is the Unix-socket I/O loop with replay window — cold (one thread per ProcessStatus stream, blocking `poll` on control frames).
  - `event_stream/sequencing.rs` (or keep core in `mod.rs`) ← `EventStreamShared`, sequence alloc + producer_seq_lock, `acked_seq`, `paused`, `session_evicted_while_paused`, `stop`, `connected`, plus `EventStreamSender`/`EventStreamWorkerHandle` sequencing helpers (`next_seq`, `try_send`, `send_sequenced`, `send_lossless_encoded`, `rollback_seq`).
  - Keep `mod.rs` as thin coordinator that `mod clock; mod transport; mod sequencing;` and re-exports stats / producer API. Estimated final `mod.rs` ~80 LOC (const decls + mod tree).
  - Responsibilities: `clock.rs` has no dep on `EventStreamShared`; `transport.rs` depends only on `EventStreamShared` + codec frame types; `sequencing.rs` owns the shared struct + mpsc channel. Seam: `transport` calls `shared.push_replay_frame` etc. — pass `&EventStreamShared` same as today.
- **Hot-path preservation:**
  - Clock helpers are on RT_FLOW emit path (deny/screen/filter + session close/open) — already NOT inlined at call site (call count < once per drop/close). Moving to `clock.rs` with `#[inline]` preserved does NOT regress: verify via `cargo build --release && objdump -d` that `monotonic_ns_to_unix_ns` still inlines at `event_emit.rs` callers (or allow outline — <1µs cost per drop, acceptable per engineering-style).
  - Transport I/O thread is cold (1 Hz tick + blocking control frame read + best-effort backpressure write). No hot-path: Verify `worker_runtime_snapshots` still ≤10/s polling the socket status (existing `EventStreamSender::stats()` call).
  - Sequencing lock (`producer_seq_lock` Mutex protecting `next_seq` + `tx.try_send`) is on deny/close path, not per-packet — locality OK.
  - Inlining: none needed to preserve — producers are not TX-drain.
  - Verify: `cargo test -p xpf-userspace-dp event_stream -- --nocapture` for behavior; `cargo test -p xpf-userspace-dp --lib` for regression gate.
- **Tests + gate:**
  - New unit tests: `clock::tests` with #2465/#2853 conversion invariants (mono=0→0, now_mono=0→0, future-clamp, year-2106 saturation).
  - Transport extracted code covered by existing `event_stream/tests/*` (control_frames, backpressure, drain, rt_flow, replay_budget) — zero new harness needed, they exercise `io_thread_main` via Unix socket pair.
  - Gate: `make test-rust` (or `cargo test -p xpf-userspace-dp`) must PASS; clippy for `clock.rs` (no unsafe beyond existing `libc::clock_gettime`).
- **Why it matters:** 1701 LOC fused file mixes four review dimensions (time math, Unix socket lifecycle, sequencing guarantees F-152/#3878, backpressure OOM guards #2381/#2382). A reviewer changing the drain deadline cannot isolate it from sequence rollback; a reviewer fixing a clock conversion cannot isolate it from socket reconnection. Mechanical split reduces merge conflict surface for parallel work on session sync vs RT_FLOW.
- **Fix direction (ordered PRs):**
  1. `event_stream/clock.rs` extraction — pure relocation, no logic change. PR-1 gives immediate 100-LOC reduction in mod.rs + a small reusable math module.
  2. `event_stream/transport.rs` extraction — move I/O thread + replay/drain helpers. Largest reduction (~700 LOC), highest review value.
  3. `event_stream/sequencing.rs` further extraction (optional follow-up) — leaves mod.rs as coordinator + stats aggregator.
  - Each PR is mechanical (body byte-for-byte move + `use super::clock::` fixups), test-covered by existing event_stream tests.
- **Labels:** maintainability, testability, no-hot-path
- **Dedup note:** No prior issue tracks this specific split; #4651 tracked codec split (already done); #4660-#4664 track event_stream tests split (test-only). This finding is distinct.

### Finding A2 — coordinator/wg_control.rs — 6 mechanical domains fused behind one 320-LOC loop

- **Title:** `wg_control.rs` fuses socket lifecycle, poll wait, TUN fatal accounting, ECN cmsg receive, handshake attempt SM, inbound dispatch, and encap egress — mechanical cold-path split
- **Severity:** M (maintainability + testability)
- **Confidence:** High
- **Refactor class:** A — mechanical cold-path (control thread, not AF_XDP worker data path; all fns except `encap_and_send` run ≤1Hz polling + timer ticks; `encap_and_send` is on TUN→socket egress for local-origin packets, not per-worker TX drain)
- **Evidence:**
  - `/tmp/review-wt-ps-043-a1g-b1/userspace-dp/src/afxdp/coordinator/wg_control.rs:332-651` `fn run_wg_control_loop` — 320 LOC, burst RX + burst TX + timer tick + attempt machine + exception recording + poll:
    ```rust
    fn run_wg_control_loop(
        tunnel_name: &str,
        engine: &Arc<WgEngine>,
        socket: &UdpSocket,
        socket_is_v6: bool,
        mut tun: File,
        outer_mtu: usize,
        recent_exceptions: &Arc<Mutex<VecDeque<ExceptionStatus>>>,
        stop: &Arc<AtomicBool>,
    ) {
        // ~320 LOC: poll→RX burst→TUN burst→timer tick→attempt drive
    ```
  - `wg_control.rs:73-119` 4 responsibilities in constants alone: `pad_to_16` (wire framing), `wg_encapped_size` + `wg_inner_fits_outer_mtu` (MTU guard), `WG_RX_BURST`/`WG_POLL_CAP_MS`/`WG_TIMER_TICK_NS`/`WG_TUN_FATAL_READ_LIMIT` (loop tuning).
  - `wg_control.rs:289-329` poll model (`PollWait` enum + `wg_poll_wait` + `poll_timeout_ms`) — 34+7 LOC, independently testable via `libc::poll` on fd pair, but buried behind 300-LOC loop.
  - `wg_control.rs:919-1126` socket lifecycle (`bind_wg_socket`, `bind_dual_stack_v6`, `set_recv_tos_options` 88 LOC setting `IP_RECVTOS`/`IPV6_RECVTCLASS`) — 180 LOC, mechanically distinct from engine.
  - `wg_control.rs:1082-1215` ECN cmsg path (`WgRecv`, `CmsgBuf`, `wg_recvmsg` 48 LOC `recvmsg(2)` + `parse_outer_ecn_from_cmsg` 39 LOC cmsg iteration + `sockaddr_storage_to_socketaddr`) — RFC 6040 §4.2 impl, cold path (outer ECN seen once per handshake + sporadically for congested paths), independently unit-testable with crafted `msghdr`.
  - `wg_control.rs:250-831` handshake attempt SM (`HandshakeAttempt` + `AttemptTrigger` + `start_attempt` 44 LOC + `drive_attempt_machine` 133 LOC — retry pacing 5s, give-up 90s, identity-based success):
    ```rust
    struct HandshakeAttempt { started_ns, last_tx_ns, baseline_session }
    enum AttemptTrigger { BringUp, NoSessionEdge, RekeyEdge, DeadPeer, KeepaliveNoSession }
    fn drive_attempt_machine(...) { // 133 LOC: pacing + T7/T8 + dead-peer window
    ```
- **Proposed decomposition:**
  - `coordinator/wg_socket.rs` ← `bind_wg_socket`, `bind_dual_stack_v6`, `set_recv_tos_options`, `canonicalize_endpoint`, `wg_send_to`, `WG_DEFAULT_OUTER_MTU`, `pad_to_16`, `wg_encapped_size`, `wg_inner_fits_outer_mtu`. Responsibility: UDP socket lifecycle + outer-MTU + framing helpers. Seam: returns `(UdpSocket, bool_is_v6)` — already does.
  - `coordinator/wg_poll.rs` ← `PollWait`, `wg_poll_wait`, `poll_timeout_ms`, `WG_POLL_CAP_MS`, `WG_TIMER_TICK_NS`, `WG_TUN_FATAL_READ_LIMIT`. Responsibility: poll(2) wait abstraction. Seam: `wg_poll_wait(socket_fd: i32, tun_fd: i32, timeout_ms: i32) -> PollWait` is pure function of fd numbers + timeout.
  - `coordinator/wg_ecn.rs` ← `WgRecv`, `CmsgBuf`, `wg_recvmsg`, `parse_outer_ecn_from_cmsg`, `sockaddr_storage_to_socketaddr`. Responsibility: ECN ancillary data receive via `recvmsg(2)`. Seam: `wg_recvmsg(socket, buf) -> io::Result<WgRecv>` returns `WgRecv { from: SocketAddr, outer_ecn: Option<u8>, len: usize }`. No dependency on WG engine. Unit-testable with mocked `msghdr` or real `IP_RECVTOS` loopback socket.
  - `coordinator/wg_handshake_attempt.rs` ← `HandshakeAttempt`, `AttemptTrigger`, `start_attempt`, `drive_attempt_machine`, `send_keepalive`, `pace_keepalive_skip`, plus attempt counters referenced. Responsibility: handshake retry SM (5s rekey pacing, 90s give-up, T7/T8 keepalive) + telemetry counters. Seam: consumes `&WgEngine` peer table snapshot + `now_ns` + `engine.timers` — produces `Option<SocketAddr>` rekey target + telemetry increments.
  - `coordinator/wg_io.rs` ← `dispatch_inbound` 215 LOC (type-byte dispatch: 1→initiation-create-response, 2→consume-response, 3→cookie, 4→try_decap+inner-src-IP gate → TUN write, endpoint learning), `encap_and_send` 56 LOC (TUN read → try_encap → socket send with MTU guard), `drive_initiation`. Responsibility: data-plane bridging TUN↔socket via engine.
  - Keep `coordinator/wg_control.rs` as thin orchestrator (~120 LOC): `wg_control_loop` entry (already there) calls bind from `wg_socket`, enters `run_wg_control_loop` (now ~80-120 LOC after delegating poll/ecn/io/attempt sub-calls to named submodules). Net reduction: `wg_control.rs` 1579→~400 LOC, rest distributed as 5 files each <200 LOC (largest is `wg_io.rs` ~300 for dispatch+encap).
- **Hot-path preservation:**
  - Control thread is never hot path (AF_XDP workers never enter it; it's a supervised aux thread like GRE local-origin `spawn_local_tunnel_sources`). No `#[inline]` on its helpers matters for forwarding perf.
  - Exception: `wg_encapped_size` + `wg_inner_fits_outer_mtu` mirror `frame::wg::wg_encapped_size` on transit egress (hot). Must remain `#[inline]` wherever relocated — move with inline preserved, verify via `nm --demangle target/debug/xpf-userspace-dp | grep wg_encapped` shows inlined (no symbol) at both call sites.
  - `parse_outer_ecn_from_cmsg` touches `libc::msghdr` cmsg iteration — cold (only on WG handshake burst + optional outer CE marks, not per data packet in the fast path because dataplane workers use `try_decap` directly). No layout/perf regression.
  - Verify: `cargo test -p xpf-userspace-dp wg_control -- --nocapture` for dispatch/attempt unit tests; `make test-cluster-*` for live WG HA if tunnel is configured.
- **Tests + gate:**
  - New units: `wg_ecn::tests` — craft `msghdr` with `IP_RECVTOS` cmsg + valid TOS byte → assert parsed ECN. `wg_poll::tests` — pipe fd + socket pair + `poll_timeout_ms` clamp math (#2300 guard). `wg_handshake_attempt::tests` — drive a synthetic Attempt timeline (BringUp at t0, rekey at T+5s, give-up at T+90s).
  - Existing coverage in `wg_control::tests` (module gate at line 1579) exercises socket bind fallback, endpoint canonicalization, inner-fits-MTU, dispatch outcome.
  - Gate: `make test-rust` or `cargo test -p xpf-userspace-dp wg_` must pass.
- **Why it matters:** `wg_control.rs` is the second-largest coordinator file (1579) and its 320+215 LOC fns dominate review complexity for WG correctness (RFC 6040 §4.2 ECN combine, RFC 8927 handshake timing). Splitting isolates ECN handling (future: IPv6 flow-label carry), poll tuning (dead-peer detection latency), and attempt SM (keepalive/pacering) for parallel review + clearer ownership boundaries.
- **Fix direction (ordered PRs):**
  1. Extract `wg_ecn.rs` — zero deps, smallest blast radius, immediate testability gain.
  2. Extract `wg_socket.rs` — socket lifecycle distinct from engine.
  3. Extract `wg_poll.rs` + `wg_handshake_attempt.rs` together — they partition the loop controls.
  4. Extract `wg_io.rs` (`dispatch_inbound` + `encap_and_send`) — leaves `wg_control.rs` as coordinator gluing poll→io→attempt.
  - Each PR mechanical move, `cargo test` green.
- **Labels:** maintainability, testability, cold-path-only, no-hot-path
- **Dedup note:** No prior issue tracks this decomposition; gre-tunnel-supervision split is analogous but not overlapping.

### Finding A3 — server/helpers.rs — explicit "dumping ground pending further split" — 5 mechanical domains

- **Title:** `server/helpers.rs` 1304 LOC — header says "Pure relocation pending further split" — 20 fns across 5 domains (status refresh, session-sync builders, binding-plan hashing, binding selection/queue planning, linux-ifname/sysfs/file-IO) fused
- **Severity:** M (maintainability — file header explicitly calls itself a dump)
- **Confidence:** High
- **Refactor class:** A — mechanical cold-path (all fns called from `main::run` control path or `server::handlers::handle_stream` RPC path, not per-packet; no hot-path structures)
- **Evidence:**
  - Header line 1-9 in `/tmp/review-wt-ps-043-a1g-b1/userspace-dp/src/server/helpers.rs`:
    ```rust
    // Daemon-loop helpers extracted from main.rs (Issue 69.1).
    // 20 helper fns called by both main::run() and server::handlers::handle_stream.
    // ...
    // Pure relocation. Bodies byte-for-byte identical.
    ```
  - `helpers.rs:16-339` `refresh_status` — 323 LOC — tallest function, mixes 35+ status field copies:
    ```rust
    pub(crate) fn refresh_status(state: &mut ServerState) {
        state.afxdp.refresh_bindings(&mut state.status.bindings);
        if should_run_afxdp(&state.status) {
            state.afxdp.reconcile_wg_control_liveness(...);
            state.afxdp.reconcile_local_tunnel_liveness(...);
        }
        // ... ~35 more status.* = afxdp.*_total() assignments
    }
    ```
  - `helpers.rs:385-614` session-sync domain — `build_nat64_reverse_rebuild` (RFC 6052 /96 embed) + `build_synced_session_key` + `build_synced_session_entry` 193 LOC (NAT src parsing, next-hop, MAC, tx_ifindex, nat_src, nat64_snat_v4, decap/ECN, Sojourn).
  - `helpers.rs:744-926` hashing domain — `snapshot_binding_plan_key` (183 LOC) + `update_snapshot_binding_plan_key` + `hash_update` + `update_json_encoded` + `update_canonical_json_hash` + `canonical_json_key` + `write_canonical_json` + `Sha256Writer` — canonical JSON hash for plan-change detection.
  - `helpers.rs:927-1188` binding selection / queue planning — `include_userspace_binding_interface` 91 LOC (filter: mgmt/em0/fab ignored etc.) + `plan_key_rx_queues`/`replan_queues`/`replan_bindings_from_candidates`/`summarize_queues`.
  - `helpers.rs:1192-1304` platform — `linux_ifname`, `effective_rx_queues`, `set_rx_queue_count_override`/`clear`/`rx_queue_count` (global static Mutex override), `write_state`, `vlan_child_parent_netdev`, `snapshot_has_parent_candidate`.
- **Proposed decomposition:**
  - `server/session_sync_helpers.rs` ← `build_synced_session_key`, `build_synced_session_entry`, `build_nat64_reverse_rebuild`, `parse_session_sync_mac`. Domain: synced-session entry reconstruction from wire (NAT64 reverse rebuild + NAT-pool parse + MAC parse). Seam: takes `&SessionSyncRequest` + zone-id map → `SyncedSessionEntry`. No dep on `ServerState`.
  - `server/binding_plan.rs` ← `same_plan_apply_needs_binding_reconcile`, `same_binding_plan`, `snapshot_binding_plan_key`, `update_snapshot_binding_plan_key`, `hash_update`, `update_json_encoded`, `update_canonical_json_hash`, `canonical_json_key`, `write_canonical_json`, `Sha256Writer`. Domain: binding-plan hash + canonical JSON canonicalization. Seam: `ConfigSnapshot` → SHA256 hex string. No dep on `ServerState`, only on snapshot + sha2. Pure math.
  - `server/binding_selection.rs` ← `include_userspace_binding_interface`, `plan_key_rx_queues`, `replan_queues`, `replan_bindings_from_candidates`, `summarize_queues`, `vlan_child_parent_netdev`, `snapshot_has_parent_candidate`. Domain: which interfaces become bindings + queue plan. Seam: takes `&ConfigSnapshot` + candidate list.
  - `server/platform.rs` ← `linux_ifname`, `effective_rx_queues`, `set_rx_queue_count_override`, `clear_rx_queue_count_override`, `rx_queue_count`, `write_state`, `forwarding_unsupported_error`, `should_run_afxdp`, `set_bindings_forwarding_armed`, `wait_for_binding_settle`, `bindings_settled`, `reconcile_status_bindings`. Domain: platform abstraction (sysfs queue-count override table, linux name mapping, state-file persist, should-run gate).
  - Keep `server/helpers.rs` as `mod session_sync_helpers; mod binding_plan; mod binding_selection; mod platform;` + re-exports for `main.rs`/`handlers.rs` compat (or deprecate helpers entirely and have `server/mod.rs` re-export submodules directly — preferred, drops one indirection).
  - Final shape: `helpers.rs` ≤ 80 LOC shim, 4 new files each 180-320 LOC, single-responsibility per file. Testability: `binding_plan.rs` is pure hash — trivial to unit-test with known vectors; `session_sync_helpers.rs` parse tests existence; `binding_selection.rs` already has cluster env fixtures in `test-cluster-env-lib`.
- **Hot-path preservation:**
  - All helpers are cold (control path / snapshot apply path, O(1) per `apply_snapshot`, not per packet). No `#[inline]` needed.
  - `rx_queue_count` global static `Mutex<HashMap>` override is NOT hot path — called once at binding plan time. Its `Mutex` does not appear on worker path.
  - Verify: `cargo test -p xpf-userspace-dp -- server` + `make test-cluster-env-lib` for binding-selection math.
- **Tests + gate:**
  - Existing: `make test-cluster-env-lib` (binding selection), `make test-deploy-lib` (deploy reconcile/sha-verify).
  - New: `binding_plan::tests` — canonical JSON key ordering + known SHA256 vectors for a minimal snapshot; `session_sync_helpers::tests` — NAT64 RFC 6052 embed/unembed + MAC parse valid/invalid.
  - Gate: `cargo test -p xpf-userspace-dp -- server::helpers server::binding_plan server::session_sync_helpers -- --nocapture` must pass.
- **Why it matters:** File header explicitly flags itself as a dumping ground. Its 323-LOC `refresh_status` is the primary status-refresh logic shared by daemon and handlers — it mixes WG liveness, GRE liveness, binding refresh, and 35 counter accumulations, making it hard to reason about which status source updates when. Issue #4421 (SnapshotIntegrityError dumping ground) is analogous precedent for this style of split.
- **Fix direction (ordered PRs):**
  1. `binding_plan.rs` extraction — pure hash, easiest, no ServerState dep — PR-1.
  2. `session_sync_helpers.rs` extraction — NAT64 reverse rebuild is safety-critical (RFC 6052 parsing), deserves its own review surface — PR-2.
  3. `binding_selection.rs` extraction — queue planning + interface inclusion, tested via cluster-env-lib — PR-3.
  4. `platform.rs` extraction — sysfs + override + state-file I/O — PR-4.
  5. Collapse `helpers.rs` into re-export shim, then remove in favor of `server/mod.rs` façade — PR-5 (optional, lowest value).
  - Each PR mechanical relocation (body identical, header updated), test gate local.
- **Labels:** dumping-ground, maintainability, cold-path, pure-relocation
- **Dedup note:** Prev #4421 SnapshotIntegrityError dumping ground is analogous but separate (Go-side snapshot integrity, not Rust server helpers). No overlap. #4651 codec split overlaps as precedent, not conflict.

### Finding C1 — coordinator/status.rs flat 1045-LOC getter list — optional grouping

- **Title:** `coordinator/status.rs` 1045 LOC — 20 getters on `Coordinator` (all `ArcSwap::load` + aggregate) in one flat file — optional mechanical grouping low priority
- **Severity:** L (readability)
- **Confidence:** Medium
- **Refactor class:** C — small benefit, defer unless grouped with A3 or a future PrometheusMetrics rewrite (optional)
- **Evidence:**
  - `/tmp/review-wt-ps-043-a1g-b1/userspace-dp/src/afxdp/coordinator/status.rs:11-1045` — 1045 LOC, doc comment says "Operator-status surface split out of coordinator/mod.rs to keep gRPC/HTTP status methods in one place."
  - Largest fn `worker_runtime_snapshots` ~200 LOC (collects per-worker runtime telemetry).
  - Pattern: most fns `pub fn foo_total(&self) -> u64 { SOME_STATIC.load(Ordering::Relaxed) }` or `self.bpf_maps.something()` or `self.cos.*_status()`.
- **Why C not A:** No domain boundary confusion (all are status getters), file comment already justifies grouping as "status surface split out of mod.rs". 1045 LOC is large for getters but not accidental complexity — each getter is trivial, file is readable as a flat lookup table. Splitting would add more file-system noise with marginal review benefit.
- **If done:** group into `coordinator/status/cos.rs`, `status/session.rs`, `status/neighbor_fabric.rs`, `status/worker.rs`, `status/exceptions.rs` — each `impl super::super::Coordinator` block moves with no pub widening.
- **Labels:** optional, readability, not-blocking

---

## 3. D — DO-NOT-SPLIT Negatives (with reasoning)

### D1 — `wg/engine.rs` — cohesive WG protocol MaybeUninit + Arc-clone + branchless pad_to_16

- **Why not split:** Single-responsibility WG crypto engine: key mgmt + peer table (ArcSwap) + AllowedIPs LPM + session-by-receiver-index demux + snow handshake bytes + AEAD encap/decap + replay-window + AllowedIPs gate — exactly the WG state machine RFC 8927 phases. Hot-path `try_encap` 108 LOC + `try_decap` 223 LOC share `MaybeUninit<[u8; PADDED_PLAINTEXT_MAX]>` stack scratch (zero-init avoided), `Arc<WgSession>` clone-and-release-lock discipline (file header + in-body comment), `pad_to_16` branchless `(n+15)&!15`. These are coupled via session `Arc` lifetime: encap clones the session `Arc` under peer lock, releases, then snow `write_message` into MaybeUninit. Splitting encap/decap/handshake into separate files would require widening `PeerTable`, `PendingHandshake`, `Tai64nClock`, `WgSession` all to `pub(in crate)` and expose the MaybeUninit scratch discipline. Prior #2792 alloc elimination work is on this file — further split risks re-introducing allocs. Keep as-is, tracked size 1805 LOC acceptable for a crypto engine with 8 internal types.

### D2 — `wg/cookie.rs` — cohesive DoS cookie checker

- **Why not split:** Single DoS-mitigation mechanism: secret rotation, load-window, per-source rate bucket (source-table + GC), MAC1 over hash of responder pubkey + MAC2 cookie reply. Internal types `SecretState`/`LoadState`/`BudgetState`/`SourceBucket`/`SourceTable` all directly cooperate inside `CookieChecker::check`. Splitting into `cookie/secret.rs` + `cookie/table.rs` would create 2 files ~150 LOC each holding state that `CookieChecker` must atomically swap.

### D3 — `event_stream/codec/` — already decomposed per #4651

- **Why not split further:** File monolith already filed and fixed. Current shape is `wire.rs` (284) + `decode.rs` (90) + `rt_flow.rs` (540) + `session_sync.rs` (271) + `mod.rs` shim (86). Each subfile single responsibility. `rt_flow.rs` 540 LOC dominated by one 207-LOC encoder for fixed 256-byte wire struct with LE byte writes — mechanical but splitting its fields would fragment the wire contract.

### D4 — `event_stream/producer.rs` — cohesive rate-limit/queue-budget

- **Why not split:** Single responsibility: per `(kind, zone)` token-bucket limiter + queue-share budget for dataplane telemetry (policy-deny / screen-drop / filter-log). 466 LOC, no hot/cold seam (rate-bucket check on deny path, not per-packet permit), types all exist to serve `try_emit_dataplane_frame`. Under A/B split threshold.

### D5 — `cold_path_hist.rs` — cohesive histogram + slot-map + TSC + atomics/counters

- **Why not split:** Described as mechanical seam in the task ("vs (D) do-not-split cohesive single-responsibility"), but its two responsibilities (hot bucket-select `#[inline]` + slot-map build/lookup + ClockSource + atomics) are tightly coupled: `bucket_index_for_ns_48`'s constants (`COLD_PATH_LINEAR_BUCKETS`, `COLD_PATH_PIVOT_NS`, `POLICY_COLD_PATH_HIST_BUCKETS`) are needed both by hot sampler and by status serializer for Prometheus `le` labels. Slot map uses those constants for overflow detection. Splitting bucket math into separate file would cross-file `#[inline]` requirement for a sampler that already runs < once per flow (not per packet) — marginal benefit, risks inlining loss if not marked. At 954 LOC it's acceptable. Future: if sampler gains hardware-timestamp backend, revisit.

### D6 — `coordinator/mod.rs` — orchestrator, 14 submodules already

- **Why not split:** Already well-decomposed into 14 focused submodules (bpf_maps, cos_leases, cos_state, ha_state, inject, neighbor_manager, reconcile, refresh_bindings, session_manager, snapshot_refresh, status, supervisor, tunnel_supervision, wg_control, worker_manager). At 982 LOC the file defines `Coordinator` struct (25 fields) + 6 small helpers (`wg_endpoint_set_summary`, purge, replay filter, transition loggers) + constructor + reconcile entry. No large function beyond `queue_warm_pass` 166 LOC. Removing fields into a sub-struct would add a layer of indirection with no encapsulation win.

### D7 — `coordinator/tunnel_supervision.rs` — cohesive local tunnel source supervisor

- **Why not split:** Single responsibility: GRE/TUN local-origin + WG control-thread liveness supervision (tombstone-only + snapshot-coherent + backoff). Two tunnel kinds (GRE, WG) share tombstone/backoff/exception machinery. Splitting by kind would duplicate that. At 960 LOC just under 1000 ceiling.

### D8 — `types/cos.rs` — type bag, already extracted via Issue 68.1

- **Why not split:** 22 type defs + fast-path/runtime structs + owner-worker assignment helpers — all pure data types. Header says "Pure relocation. The original pub(super) visibility translated to pub(in crate::afxdp)". File already result of Issue 68.1 split. Largest method `transmit_rate_bytes` 297 LOC computes rate from config — pure getter. Further split by interface vs queue vs flow-fair would create 4 files re-importing `super::*` with mutual field refs. 1786 LOC large but acceptable for a type module with 22 types (avg ~80 LOC/type).

### D9 — `protocol/binding.rs` and `protocol/control.rs` — protocol wire type leaves

- **Why not split:** Protocol crate deepest leaf (DAG bottom), pure serde wire shapes. `binding.rs` 1185 LOC dominated by `WorkerRuntimeStatus` (~220 LOC: many `#[serde(default)]` fields for back-compat) + `BindingCountersSnapshot` conversion. `control.rs` 1088 LOC dominated by `ProcessStatus` (~400 LOC: aggregates all optional sub-snapshots, the Go↔Rust contract) + `ControlRequest` + `From<SlowPathStatus>` 410 LOC mapping decode (one per field, unavoidable). Both are schema definitions — splitting would fragment a contract that Go's `TestControlRequestCapLockstepWithRust` pins with a lockstep cap check (`MAX_CONTROL_REQUEST_BYTES`). Not logic to split.

### D10 — `types/forwarding.rs` — forwarding-state type module

- **Why not split:** Single responsibility: forwarding state central data-def (`ForwardingState`) + related types (`ZoneHostInbound`, `RouteEntryV4/V6`, `NeighborEntry`, `WgRuntimePeer`, `TunnelEndpoint`, `FabricSkipReason`, `ForwardingDisposition/Resolution`, `WorkerBindingLookup`). 1099 LOC, grows with routing features but data-only. No timers, no SMs.

### D11 — `event_emit.rs` — cohesive RT_FLOW deny/log emission facade

- **Why not split:** Single facade: map internal disposition/action/filter-match to RT_FLOW wire frames via `EventStreamWorkerHandle`. 598 LOC, dominated by 91-LOC `emit_policy_deny_event` (builds wire frame) + constant table `SCREEN_*` bit-flags (19 flags). Calls only on deny/log path (not per-packet permit), so no hot-path inlining critical. 600 LOC acceptable.

### D12 — `types/shared_cos_lease/lease.rs` — cohesive CoS queue lease with size watch

- **Why not split (now):** Two responsibilities (queue lease per-queue + root lease class-cap) but coupled via `SharedCoSLeaseState` shared bank + outstanding cap + fail-open cause chain. `acquire_v8_with_cause` 282 LOC top-up + epoch/tag/grant + per-cause accounting is the bulk, already `#[inline]`-sensitive for TX drain (per-queue token check before tx-ring enqueue). Splitting would widen `pub(super)` to `pub(in crate)` for 5+ internals and risk cross-crate inlining loss on `acquire_v8`. At 1460 LOC it's at the ceiling — next feature addition should split root-lease into `shared_cos_lease/root.rs` (class-cap, `compute_shared_cos_lease_config`, `SharedCoSRootLease`) and keep queue-lease as-is.

---

## 4. Cross-Cutting Considerations

- **Hot-path preservation (CoS TX drain focus per task):** No finding touches the forwarding orchestrator cold stats/logging boundary on TX drain (`poll_stages.rs`, `cos_leases/`, `cos_state.rs`, `shared_cos_lease/lease.rs` acquire path). A2's `wg_encapped_size` + `wg_inner_fits_outer_mtu` mirror exists on transit egress (hot) — kept `#[inline]`. A1 clock helpers are deny/close path, not per-packet. A3 helpers are snapshot-apply path, not per-packet. `cold_path_hist.rs` bucket selector is first-packet-per-flow (cold relative to per-packet) but marked D-negative partly to preserve its `#[inline]` adjacency.
- **CoS TX drain contract:** `lease.rs` D12 stays intact for now. Root-lease vs queue-lease split tracked as future work only when size exceeds 1500. Any split must preserve `acquire_v8_with_cause` `#[inline(always)]` on its hot sub-helpers and `seq-lock` layout (per-queue `AtomicU64` epoch+tags). Verify via `pahole` / `cargo bloat --bin xpf-userspace-dp` no struct size change.
- **Alloc discipline:** WG engine `MaybeUninit<[u8; PADDED_PLAINTEXT_MAX]>` scratch avoids heap — file header + per-#2792. `server/helpers.rs` `Sha256Writer` (Write adapter over Sha256) is zero-alloc (stack hasher). `event_stream` transport uses fixed `[u8; 256]` frames (no Vec growth per frame, only `VecDeque` for replay capped at 4096). Preserved across proposed splits.
- **Lock discipline:** `WgEngine` clones `Arc<WgSession>` then releases peer lock before snow crypto — per header. `EventStreamShared::producer_seq_lock` Mutex held only around `next_seq` alloc + `tx.try_send` (non-blocking), released before sleep in lossless retry path — correct per #3878. `CoSLease` seq-lock is per-queue atomic, no cross-worker lock. All preserved.

---

## 5. Summary Scorecard

| File | LOC | Class | Priority | Title |
|------|-----|-------|----------|-------|
| `server/helpers.rs` | 1304 | **A** | **P0** | Dump pending split — 5 domains (18 fns) — header acknowledges |
| `wg_control.rs` | 1579 | **A** | **P1** | 6 domains fused behind 320-LOC loop — ECN cmsg, poll, attempt SM, socket lifecycle |
| `event_stream/mod.rs` | 1701 | **A** | **P1** | Transport + sequencing + clock + replay/drain fused — 4 domains |
| `coordinator/status.rs` | 1045 | **C** | P2 (optional) | Flat getter list — optional grouping |
| `wg/engine.rs` | 1805 | **D** | — | Do-not-split — cohesive crypto engine, MaybeUninit scratch, Arc+release-lock |
| `wg/cookie.rs` | 857 | **D** | — | Do-not-split — cohesive cookie checker |
| `cold_path_hist.rs` | 954 | **D** | — | Do-not-split — cohesive histogram (size-watch future split root-lease) |
| `types/cos.rs` | 1786 | **D** | — | Do-not-split — type bag (68.1 extracted), 22 defs |
| `protocol/binding.rs` | 1185 | **D** | — | Do-not-split — wire type leaf |
| `protocol/control.rs` | 1088 | **D** | — | Do-not-split — protocol schema leaf (Go↔Rust contract) |
| `types/forwarding.rs` | 1099 | **D** | — | Do-not-split — forwarding state type module |
| `event_emit.rs` | 598 | **D** | — | Do-not-split — cohesive RT_FLOW emission facade (deny/log path) |
| `shared_cos_lease/lease.rs` | 1460 | **D** | — (watch 1500 ceiling) | Do-not-split now — cohesive queue lease; next feature splits root-lease |
| `coordinator/mod.rs` | 982 | **D** | — | Do-not-split — orchestrator (14 submodules already) |
| `coordinator/tunnel_supervision.rs` | 960 | **D** | — | Do-not-split — cohesive tunnel supervisor |
| `event_stream/codec/*` | 1271+1023t | **D** | — | Do-not-split — already split (#4651) |
| `event_stream/producer.rs` | 466 | **D** | — | Do-not-split — cohesive rate-limiter, under threshold |

**Total A findings:** 3 (helpers.rs, wg_control.rs, event_stream/mod.rs)
**Total C findings:** 1 (status.rs optional grouping)
**Total D negatives:** 12 (plus 2 test-only excluded: wg/tests.rs, codec/tests.rs)

---

## 6. Dedup vs Prior Issues

- **#4421 SnapshotIntegrityError dumping ground** — Go-side snapshot integrity plumbing, separate concern from Rust `server/helpers.rs` dumping ground. No overlap.
- **#4651 event_stream/codec.rs 1165 split** — Already filed AND implemented. Current `codec/` dir (wire+decode+rt_flow+session_sync+mod) verified as post-split correct shape. This audit marks codec as D-negative (already done). No new PR needed.
- **#4660-#4664 event_stream tests split** — Test-only split, distinct from A1 which targets prod `mod.rs` (clock+transport+sequencing) not tests.
- **Frame/wg.rs #2792 alloc elimination** — WG engine's `MaybeUninit` scratch cited (D1 reasoning), not overlapping with any A finding. No conflict.
- No existing issue tracks `wg_control.rs` mechanical decomposition (ECN cmsg, poll, attempt SM, socket lifecycle) — A2 is distinct.
- No existing issue tracks `server/helpers.rs` dumping ground — A3 is distinct but analogous to #4421 style.

---

## 7. Repro & Verification Commands

```bash
# Inventory this audit used (run against worktree):
wc -l userspace-dp/src/afxdp/wg/engine.rs userspace-dp/src/server/helpers.rs ...
grep -n "pub(crate) fn " userspace-dp/src/server/helpers.rs
grep -n "^pub fn " userspace-dp/src/afxdp/coordinator/status.rs

# Rust gate for all proposed splits (must stay green):
cargo test -p xpf-userspace-dp --lib
cargo test -p xpf-userspace-dp event_stream -- --nocapture
cargo test -p xpf-userspace-dp wg_ -- --nocapture
cargo test -p xpf-userspace-dp server:: -- --nocapture

# Go-side cluster fixtures used by binding_selection:
make test-cluster-env-lib
make test-deploy-lib

# Engineering style load (required before code changes):
cat /tmp/review-wt-ps-043-a1g-b1/docs/engineering-style.md
```


---
### Batch ps-a2-b1.md — 35596 chars

# A2 — NAT Modularity Audit (Rust nat/*.rs + nat64 + Go NAT compile + XDP shim)

Base SHA: 4e0c7f74c  Worktree: /tmp/review-wt-ps-043-a2-b1/
Whoami: ps, NNN 043

## Inventory (exact at this SHA)

### Rust userspace-dp nat/

| File | LOC | Role |
|------|----:|------|
| `userspace-dp/src/nat/allocator.rs` | 1974 | PortAllocator god-struct: 6 resp — bitmap claim, live_by_flow map, persistent leases, deterministic reverse, GC, recycle FIFO, status |
| `userspace-dp/src/nat/source.rs` | 1523 | 7 resp — SNAT rule parse + L4 match + scope gate + pool-alloc driver + release/rollback/reserve wrappers + NAT64 alloc shims + prefix/host-match helpers |
| `userspace-dp/src/nat/destination.rs` | 1109 | DnatTable exact+wildcard+PROTO_ANY+prefix-LPM, port-range search |
| `userspace-dp/src/nat/static_nat.rs` | 808 | StaticNatEntry/Table, scoped match, block-pair remap |
| `userspace-dp/src/nat/mod.rs` | 347 | Cross-cutting NatDecision, NatRuleCounter (atomic packets+bytes, #3830 fetch_sub reset), NatCounterStore (#2218/#2255 stable hash + #4718 parse_error counter), NatScopeCtx (#3096) — curated re-export hub |
| `userspace-dp/src/nat/status.rs` | 40 | source_nat_pool_statuses aggregation |
| `userspace-dp/src/nat/tests_*.rs` | ~8 files 4673+… | Per-subject splits from #4409 pure motion |
| `userspace-dp/src/nat64.rs` | 3102 | Monolith: Nat64Prefix, Nat64State, Nat64FragAssoc, Nat64Match, allocate/release/reserve NAT64, forward_decision, IPv6 L4 offset, ICMPv4↔v6 mapping, embedded-ICMP translation, checksum incremental, frag-ID mapping |
| `userspace-dp/src/protocol/control.rs` | 1088 | Wire snapshots for NAT counters, pool status, dnat publish errors, nat_reverse_key collisions |

### XDP shim (Rust aya)

| File | LOC | NAT relevance |
|------|----:|---------------|
| `userspace-xdp/src/lib.rs` | 1541 | DNAT maps only: `dnat_table` + `dnat_table_v6` (10M entries each, BPF_F_NO_PREALLOC), `userspace_interface_nat_v4/v6` (8k). SNAT handled entirely in userspace-dp. Trace stages include INTERFACE_NAT_LOCAL. No NAT classification — helper publishes reverse entries, shim looks up. |

### Go compiler (two layers)

**Layer 1 — `pkg/config/` Junos AST → typed SecurityConfig (already 6-file split, but still triply fused with validators):**

| File | LOC | Responsibilities | God-ness |
|------|----:|----------------|----------|
| `compiler_nat_source.go` | 764 | compileNAT (pool expansion + implicit addr IDs), compileNAT64, parseSourcePoolPortRange, compileNATSource (SNAT rule expansion, implicit set cache) | triple: helpers + compilation + pool alarm defaulting (#4077) |
| `compiler_nat_destination.go` | 400 | compileNATDestination, parseDNATPoolAddress, appendDNATPortRange, parseDNATPortList (reverse detection) | focused BUT parse-multi sits here too |
| `compiler_nat_static.go` | 336 | compileNATStatic + resolution of then-prefix names + mapped-port/routing-instance extractors | focused |
| `compiler_nat_helpers.go` | 410 | natMatchScope struct, parseNATMatchScopes, collectNATScopes, applyNATFromScope/ToScope, appendPoolAddresses, expandAddressRange, applyDeterministicKeys/Children/Host | pure helpers — separated |
| `compiler_nat_dnat_to.go` | 131 | validateDNATRuleSetToScopeAST (to-scope illegal on DNAT), forEachChild | validator fragment in compiler_ file — mis-located |
| `compiler_nat_mixed_scope.go` | 159 | natClauseScopeKinds, validateNATRuleSetMixedScopeAST (from vs to collision) | validator fragment |
| `compiler_validate_strict_nat.go` | 1474 | 10 validators: match app empty/unresolved, dest addr, protocol resolvable, dport, dnat pool, snat pool, source addr name, host-mask, NAT64 prefix extra-slash, NPTv6 overlap, static then target, pool alarm | god-validator — 10 concerns in one file, 3 alarm/host/nptv6 cases could be separate |
| `natpool.go` | 66 | SourceNATPoolNets + parsePoolAddr + IPInNets | tiny helper, ok |

**Layer 2 — `pkg/dataplane/` typed Config → BPF/snapshot (still monolith):**

| File | LOC | Responsibilities |
|------|----:|------------------|
| `compiler_nat.go` | 1317 | compileNAT (SNAT pool IDs, zone-pair idx v4RuleIdx/v6RuleIdx maps, implicit addr creation via resolveSNATMatchAddr, interface SNAT snat_egress_ips per (ifindex,vlan), pool cache compiledPools, COUNTER KEY FORMAT NATCounterKey + stable-hash assignment #2255 + finalizeNATCounterIDs #5099), compileStaticNAT, compileNAT64, compileNPTv6, nptv6Adjustment |
| `nat*.go` | ~8 files | Applied NAT view, destination/source/static helpers for dataplane map writes |

**Other in scope (from prompt, check existence):**

- `pkg/dataplane/compiler.go` 1808 LOC — phases 6/6.5/6.6 call compileNAT, NPTv6, NAT64; carries implicit address-set cache seeded with default-policy sentinel (#3057). Not NAT-heavy itself.
- `pkg/dataplane/userspace/maps_sync.go` 1763 — syncInterfaceNATAddressMapsLocked only NAT touch; rest is generic map sync.
- `pkg/dataplane/zonecounters.go` — not NAT.
- `userspace-dp/benches/snat_allocator.rs` harness=false custom main — models CURRENT (single Mutex live_by_flow + occupancy) vs PROPOSED (atomic bitmap CAS-claim + tiny map-lock) under M={1,2,4,6,8} × 4 profiles (uniform, 85-98% high-occ, 80/20 skew, narrow 64-port). Sticky addr selection lock-free `hash(src_ip)%num_addrs` identical in both shapes, only port-claim+map-lock differs.

## Findings — Exact Labels (dedup vs #4409, #4421, #4056, #2852)

### [A2-1] allocator.rs god-struct — hot bitmap + cold leases/GC/stats fused — (C) cache-line win possible, measurement-gated
**File:** `userspace-dp/src/nat/allocator.rs:651-687 PortAllocatorShared`, `469-640 AddressOccupancy`, `436-468 PortAllocatorLiveState`, `137-165 LiveAllocation`, `420-433 PersistentLease`, `195-305 DeterministicV4/V6`

**Structure at this SHA (post-#2852 Phase 1 + #4676 + #5269):**
- `AddressOccupancy`: `words: Vec<AtomicU64>` (occupancy bitmap, bit=set=occupied), `cursor: AtomicU32` (fresh-port forward-probe), `recycle: Mutex<VecDeque<u16>>` (FIFO #3011 oldest-freed-first, with Byte comment). `claim()` loops recycle pop_front (Mutex held) else cursor CAS + bitmap CAS; `free_recycle`/`free_no_recycle`/`reserve` manipulate bitmap + recycle.
- `PortAllocatorShared`: `counters: Vec<AtomicU32>` (per-addr round-robin for address-only/no-translation try_next_port), `addr_counter_v4/v6: AtomicU32`, `occupancy: Vec<AddressOccupancy>` — HOT; `live: Mutex<PortAllocatorLiveState>` — COLD; plus `allocations_total/reuses_total/exhaustion_total: AtomicU64` — stats (cold but atomics false-share with occupancy vec if co-located); `max_tracked_flows`, `gc_lock_acquisitions` (test seam #4676 proof of chunk release).
- `PortAllocatorLiveState`: `live_by_flow: FxHashMap<SourceNatFlowKey,LiveAllocation>`, `persistent_by_source: FxHashMap<PersistentSourceKey,PersistentLease>`, `lease_expirations: BTreeSet<(u64,PersistentSourceKey)>`, `lease_expirations_by_addr: Vec<BTreeSet<…>>`, `address_only_owners: FxHashMap<AddressOnlyReverseKey,SourceNatFlowKey>` (#5269), `gc_counter: u32`.

**Why still god:**
- Single file owns 6 responsibilities the module doc on older SHA claimed split. 5 structs + 2 free func groups + snapshot type.
- Hot `AddressOccupancy::claim()` takes `Mutex<VecDeque>` for recycle drain — contradicts eng-style "No Mutex<VecDeque> on hot path". However at steady-state recycle usually empty and first branch hits cursor (lock-free); recycle path is cold #3011 tail. Still, the Mutex shares cache line with hot AtomicU64 words when allocator vec packed.
- Stats atomics live in same `PortAllocatorShared` as occupancy vec — cache traffic from stats fetch_add on each allocation interferes with bitmap CAS on same pool.
- `LiveAllocation.address_only: bool` (#5269) adds new variant to release/rollback teardown: two branches in `release_flow` (`if existing.address_only { remove from address_only_owners } else { free_translated_port }`). Field itself not hot (cold path) but lives in every LiveAllocation (per-flow).

**Decomposition angles (new vs #4409 which filed pure GC split obsoleted by #2852/#4676, ledger says PLAN-KILL):**
- **Mechanical file motion (no behavior):**
  - `allocator_occupancy.rs` — `AddressOccupancy` + `offset_of/port_of/claim_offset/free_offset/is_occupied/claim/free_recycle/free_no_recycle/reserve/occupied_count` — hot bitmap, zero dependency on LiveState except `PortAllocator` new() construction.
  - `allocator_live.rs` — `PortAllocatorLiveState`, `LiveAllocation`, `PersistentSourceKey`, `PersistentLease`, `TranslatedTuple`, `PoolAddressFamily`, `AddressOnlyReverseKey`, GC budget consts, `allocator_capacity`, `sticky_pool_index` — cold map + lease lifecycle.
  - `deterministic.rs` — `DeterministicV4`, `DeterministicV6`, `deterministic_indices_v4/v6`, `reverse_deterministic_v4/v6`, `deterministic_v6_word_offset` — currently in same file but independent of allocator; also used by NAT64 (shared). Move to `nat/deterministic.rs` (top-level) so both allocator and NAT64 import it.
  - `allocator.rs` stays ~200 LOC: `PortAllocatorShared` + `PortAllocator` (new + debug + allocate_translation + allocate_translation_locked + release + rollback + snapshot). Re-exports.
- **Cache-line angle (C) measurement-gated:**
  - `#[repr(align(64))]` or `cache-padded` wrapper on `AddressOccupancy` (hot) and on `PortAllocatorShared.counters` + `occupancy` vec storage. Goal: isolate `AtomicU32` counters + recycle Mutex (cold-ish) from hot bitmap words. But occupancy vec is heap-allocated per addr — align the inner `AddressOccupancy` not the Vec. Also split `PortAllocatorShared` fields into hot (counters, occupancy) vs cold (stats, max_tracked_flows) into two `#[repr(align(64))]` substructs.
  - MUST NOT apply blindly: measure `benches/snat_allocator.rs` M=6/8 allocate/sec + p50/p99/p999 vs 2852 baseline 1.4-1.6x speedup claim. The bench re-implements shapes side-by-side, not production struct, so need a second bench driving real `PortAllocator`. If no win, CLOSE.
  - Consideration: `Vec<AtomicU64>` inside AddressOccupancy already globally allocated contiguous; padding between AddressOccupancy instances in the vec does not help unless vec elements themselves aligned. Use wrapper `struct CachePaddedOccupancy { #[repr(align(64))] inner: AddressOccupancy }` OR make occupancy vec store `Box<[CachePadded]>`. Similar for counters.

**Hot-path preservation:**
- `AddressOccupancy::claim()` — no new alloc (uses Cursor atomic + CAS). Must stay zero-alloc (no Vec alloc).
- `allocate_translation` non-persistent hot path — lock-free claim then `Mutex<LiveState>` for insert. Proposed cache-line padding must not add allocation on claim path.
- `reserve_flow` #4388 path (`reserve_address_only` + `reserve_synced_source_nat_allocation`) — same.
- 1:N #4399 — deterministic block claim loops `block_size` times scanning bitmap directly (no recycle queue); must stay zero-alloc.
- `release_flow`, `rollback_flow` — O(1) addr_index from record, frees bitmap. Address-only branch must not allocate (HashMap remove may allocate internal but FxHashMap remove is O(1) amortized; okay if not on per-packet fast path—release is session GC, not packet).

**Dedup vs prior:**
- #4409 filed PortAllocator 926 + source 1190. This finding REFINES: post-Phase 1, PortAllocator is no longer 926 monolithic mutex — it is already Phase 1 decomposed (bitmap CAS). Prior GC-split ledger entry `research(#4409b)` says CLOSE/PLAN-KILL because GC chunking #4676 obsoleted. This new finding DOES NOT re-propose same GC engine extraction; it proposes occupancy vs live vs deterministic file split + optional cache-line alignment, measurement-gated, compatible with Phase 1.
- #2852 baseline exists: `benches/snat_allocator.rs` must not regress.
- #5341 deterministic CGNAT occupancy token — addressed in A2-5 below, not here.

Severity: (C) — non-blocking perf opportunity, must be measurement-gated vs 2852 baseline; primary recommendation is mechanical 3-file motion + optional cache-line isolate behind `#[cfg(perf)]` feature gate for measurement.

---

### [A2-2] source.rs 1523 LOC god-file — SNAT rule parsing cold vs allocation-driver hot vs match 336-LOC god-function
**File:** `userspace-dp/src/nat/source.rs:514-1030` parse + release/reserve, `1056-1450+` match_source_nat_result_for_tuple

**Structure:**
- Types (6 top-level): `SourceNatLookup` (Matched/Unavailable), `SourceNatFailure` (+ for_rule ctor), `SourceNatFailureReason` (exception_reason), `SourceNatFlowKey` (5-tuple, hash), `PersistentNatPermit` (from_wire/as_wire), `SourceNatAppTerm` (protocol + port ranges), `SourceNatRule` (biggest: match scopes zones/interfaces/routing-instances, src/dst address/prefix sets, application terms, pool mode fields deterministic_v4, pool_addresses_v4/v6, pool_allocator, hit_counter, flags interface_mode/off/no_translation/address_persistent/persistent_nat, pool_failure)
- Fns: `expand_pool_address` (pool prefix expansion capped MAX_POOL_PREFIX_HOSTS=65536), `parse_source_nat_rules` (cold, build Vec<SourceNatRule> from snapshots), `parse_source_nat_rules_with_previous` (allocator reuse keyed on exact pool<Vec> equality, order-sensitive, comment cites `Nat64State::from_snapshots_with_previous` same pattern), `source_nat_runtime_compatible` (checks pool len/persist/no_trans etc), `release_source_nat_allocation`, `rollback_source_nat_allocation`, `release_source_nat_allocation_with_mode` (mode unify), `reserve_synced_source_nat_allocation`, `allocate_nat64_pool_port` wrappers, `match_source_nat`, `match_source_nat_result`, `match_source_nat_result_for_tuple` (the 400+ LOC god-function: scope check → off → interface_mode (egress_v4/v6) → pool_failure → non_first_fragment gate #1852 → port_less #3111 (GRE/ESP/AH vs TCP/UDP vs ICMP query #4074/#4088) → address_only #3906 → deterministic_v4 branch (#4559, with address_only sub-branch) → deterministic_v6?, then per-family round-robin vs sticky, try_next_port vs allocate_translation), plus helpers `parse_match_prefix`, `port_in_ranges`, `nets_match_v4/v6`.

**Why god:**
- Single file mixes config-plane (`parse_source_nat_rules*`, `expand_pool_address`, runtime compat check) with data-plane driver (`match_source_nat*` + reserve/release wrappers) + cross-concern NAT64 alloc forwards (`allocate_nat64_pool_port*` — should live in nat64.rs or mod.rs).
- `match_source_nat_result_for_tuple` 400 LOC, 6 return points (Matched/Unavailable), nests IPv4 vs IPv6 deterministic vs address-only vs port-less vs ICMP-query paths. Cyclomatic complexity high, but branches are config-boolean gated (deterministic present?, no_translation?, port_less?, icmp_query?) — predictable per-rule.
- #5269 added address-only occupancy hashmap usage for reverse collision — extra state in release paths.
- Cold stats: `parse_match_prefix` failure → NatCounterStore::record_parse_error #4718, loud-skip doctrine.

**Decomposition — per-domain 6-file motion analogue:**
- Keep `SourceNatRule`, `SourceNatFlowKey`, `SourceNatFailure*`, `SourceNatLookup`, `PersistentNatPermit`, `SourceNatAppTerm` in `source_rule.rs` (≈ types).
- `source_parse.rs` — `expand_pool_address`, `parse_source_nat_rules`, `parse_source_nat_rules_with_previous`, `source_nat_runtime_compatible`, `MAX_POOL_PREFIX_HOSTS`, `parse_match_prefix`, `nets_match_v4/v6`, `port_in_ranges`. Cold-only.
- `source_match.rs` — `match_source_nat`, `match_source_nat_result`, `match_source_nat_result_for_tuple` (maybe split tuple-match inner helper `match_ipv4_pool` vs `match_ipv6_pool` to reduce 336 LOC). Hot-ish (called per new-flow, not per-packet; per-packet hits session table).
- `source_alloc.rs` — `release_source_nat_allocation*`, `rollback`, `reserve_synced`, plus NAT64 pool port wrappers (`allocate_nat64_pool_port*`) — but those wrappers belong to nat64 delegation; better move NAT64 wrappers to `nat64.rs` and have source.rs import.
- Mechanical: each new file `pub(super)` re-export via `mod.rs`. No behavior change, only visibility widening from private to `pub(super)`.
- Alternative: keep god-function but extract `allocate_pool_mode_v4` and `allocate_pool_mode_v6` helpers returning `SourceNatLookup` to drop nesting.

**Hot-path preservation:**
- `match_source_nat_result_for_tuple` is NOT per-packet hot (session-miss path, cold relative to forwarding), but it IS high-frequency during new-flow storm (worker per RX queue). Must stay zero-alloc: currently uses slice iterations, no Vec allocation inside match (allocation done in `allocate_translation`). Splitting into helpers must not introduce allocation (use `#[inline(always)]` for inner helpers).
- `release_flow` / `reserve_synced` called on HA sync path — must not allocate on fast path (HashMap insert is unavoidable for persistent but that's slow path).
- `parse_match_prefix` failure path logs via `eprintln!` — never hot (config apply only).

Severity: (B) — maintainability bottleneck, merge-conflict magnet. Decomposition is mechanical code motion, no perf risk if inlined.

---

### [A2-3] nat64.rs 3102 LOC monolith — Xlation + frag tracking + ICMP mapping + checksum rewrite fused
**File:** `userspace-dp/src/nat64.rs:190-3102`

**Structure (inventory from grep):**
- Config: `Nat64Prefix` (prefix_bytes [u8;12], pool_v4 Vec<Ipv4Addr>, port_allocator PortAllocator, deterministic_v6 Option<DeterministicV6>), `Nat64State::from_snapshots` + `from_snapshots_with_previous` (exact pool reuse, order-sensitive vec equality, same pattern as source.rs), `match_ipv6_dest`, `classify_ipv6_dest`, `allocate_v4_source`, `allocate_source`, `build_deterministic_v6`
- HA sync: `release_nat64_allocation_with_mode`, `release_nat64_allocation`, `rollback_nat64_allocation`, `reserve_synced_nat64_allocation` — duplicates source.rs reserve/release pattern
- Frag: `Nat64FragKey` (addr_family src/dst ident), `Nat64FragEntry`, `Nat64FragAssoc` (sharded Mutex 16 shards, cap 64 each, TTL 2s), methods `new`, `install`, `lookup`, `len`, plus `nat64_fragment_fields`, `nat64_first_fragment_key`, `nat64_nonfirst_fragment_key`, `ipv6_is_non_first_fragment`, `Ipv6FragInfo`, `ipv6_fragment_header`, `next_frag_id`, `map_frag_id`
- ICMP translation: `translate_icmpv6_message_to_icmpv4`, `translate_icmpv4_message_to_icmpv6`, `EmbeddedV6ToV4/V4ToV6`, `translate_embedded_v6_to_v4/v4_to_v6`, `map_icmpv6_error_to_icmpv4`, `map_icmpv4_error_to_icmpv6`, `write_icmpv4_error_with_embedded`, `write_icmpv6_error_with_embedded`, constants ICMP_ECHO etc
- Checksum: `checksum16`, `checksum16_add/fold`, `checksum16_ipv4_pseudo/v6_pseudo`, `checksum16_incremental`, `adjust_l4_checksum_v6_to_v4_incremental/v4_to_v6`, `recompute_l4_checksum_after_nat64_*`, `finalize_icmpv4_checksum`, plus embedded type mappers
- Forward decision: `Nat64State::forward_decision` (classifies IPv6 dest vs IPv4 src, maps, checksum, frag handling), plus `Nat64Match` enum, `Nat64ReverseInfo`
- Port allocator reuses same `PortAllocator` as SNAT via Arc sharing, but alloc wrappers duplicated.

**Why god (even after #4421 plan to split):**
- At this SHA still a single 3102 LOC file (no `nat64/` dir). Prior issue #4421 filed 2047 split into submodule — presumably NOT yet done; at 3102 it GREW. Should become `nat64/mod.rs` + `nat64/prefix.rs` + `nat64/frag.rs` + `nat64/icmp.rs` + `nat64/checksum.rs` + `nat64/forward.rs` (or similar 5-file).
- DeterministicV6 builder `build_deterministic_v6` depends on `NAT64RuleSnapshot` — config plane fused with translation.
- Frag assoc uses 16 shards `Mutex` — similar hot-path contention angle as allocator recycle Mutex, but frag path is extension-header slow path, not top perf.
- Checksum incremental helpers duplicate logic from maybe `checksum.rs` elsewhere? Need check for duplication.

**Decomposition:**
- Proposed layout (mechanical):
  - `nat64/prefix.rs` — Nat64Prefix, build_deterministic_v6, parse_pool_v4, is_active, match_ipv6_dest, classify, allocator reuse
  - `nat64/state.rs` — Nat64State, from_snapshots/with_previous, allocate_v4_source, allocate_source, forward_decision
  - `nat64/frag.rs` — FragKey/Entry/Assoc, sharded logic, first/nonfirst key extractors, ipv6 extension walks MAX_IPV6_EXT_HEADERS
  - `nat64/icmp.rs` — ICMP type mappers, embedded translation, error builders, constants
  - `nat64/checksum.rs` — checksum16*, incremental adjust, recompute L4 post-NAT64
  - `nat64/alloc.rs` — release/rollback/reserve wrappers (or keep in mod.rs as re-exports from source.rs reuse)
  - `nat64/mod.rs` — re-exports + Nat64Match + Nat64ReverseInfo

**CoS TX drain focus relevance:**
- Per the prompt, CoS TX drain focus: per-packet forwarding orchestrator cold stats out. NAT64 forward_decision writes frag ID via `next_frag_id()` global static AtomicU16? Check: uses `static FRAG_ID: AtomicU16`. That's a cross-core contended atomic on every frag. Should be per-worker or hashed. But frag path is rare, so not hot. Still candidate for cold-out.

Severity: (B) — biggest single-file contributor at 3102 LOC, clear mechanical split boundary, no perf risk.

---

### [A2-4] Go NAT compile triply fused — helpers + validators + compilation

**Files:** `pkg/config/compiler_nat_*.go` (6 files, 2047 LOC w/o tests) + `pkg/config/compiler_validate_strict_nat.go` 1474 + `pkg/dataplane/compiler_nat.go` 1317 = ~3838 LOC NAT compile logic across two layers.

**At this SHA:**
- Layer 1 already split per type (source/destination/static/helpers/dnat_to/mixed_scope) — IMPROVEMENT over pre-split single 2529 file. However:
  - `compiler_nat_dnat_to.go` 131 LOC is just `validateDNATRuleSetToScopeAST` + `forEachChild` — validation logic living in a file named compiler_ — misnamed, should be `compiler_validate_strict_nat_dnat_to.go` or folded into strict_nat validator.
  - `compiler_nat_mixed_scope.go` 159 LOC similarly validation (`validateNATRuleSetMixedScopeAST`, `natClauseScopeKinds`) — misnamed.
  - `compiler_nat_helpers.go` 410 contains BOTH helpers (address parsing) AND scope-parsing types (natMatchScope) — ok but `parseZoneList` generic (not NAT-specific) leaked.
  - `compiler_nat_source.go` still mixes pool address expansion (should be helper) + alarm threshold defaulting + deterministic key parsing.
- Layer 2 `pkg/dataplane/compiler_nat.go` 1317 still monolith: SNAT v4/v6 rule index mapping (zonePairIdx), implicit addr creation (resolveSNATMatchAddr), SNAT egress IPs (per-ifindex/vlan), NAT counter stable-hash assignment, finalization, NPTv6 adjustment. This file mixes address-book implicit creation (cross-cutting) with SNAT rule compilation.

**Mechanical per-domain 6-file motion (Go) — per prompt ask:**

- Keep helpers: `compiler_nat_helpers.go` → split into `compiler_nat_scope.go` (natMatchScope, parseNATMatchScopes, collectNATScopes, applyFrom/To) + `compiler_nat_pool.go` (appendPoolAddresses, expandAddressRange, parsePoolAddr) + `compiler_nat_deterministic.go` (applyDeterministicKeys/Children/Host)
- Split `compiler_nat_source.go`: extract `compileNAT` (named pools) into `compiler_nat_pool.go` (already) vs `compileNATSource` (rule-set) vs NAT64+NPTv6 into separate `compiler_nat64.go` (currently 159-func compileNAT64 mixed with source)
- Merge the two mis-named validator fragments into strict validator file: `compiler_nat_dnat_to.go` + `compiler_nat_mixed_scope.go` → `compiler_validate_strict_nat.go` sub-helpers OR `compiler_validate_nat_scope.go`
- `pkg/dataplane/compiler_nat.go`: split into `compiler_nat_snat.go` (resolveSNATMatchAddr + SNAT rule building), `compiler_nat_counter.go` (NATCounterKey, natCounterIDForKey, assignNATCounterID, natCounterIDInUse, finalizeNATCounterIDs, MaxNATRuleCounters), `compiler_nat_egress.go` (SNATEgress IP set per ifindex/vlan), `compiler_nat_static_nptv6.go` (compileStaticNAT, compileNPTv6, nptv6Adjustment, compileNAT64 wrapper)

But: these are NO-OP code motion with no perf impact; must preserve compile order (Phase 6 SNAT → 6.5 static → 6.6 NAT64 + finalizeNATCounterIDs). finalizeNATCounterIDs must run after all phases — moving it to separate file does not change call site in `pkg/config/compiler.go:232-258` (or dataplane compile).

**Duplication:**
- `validateNATMatchApplicationsStrict` + `validateDestinationNATAddressesStrict` + `validateDestinationNATProtocolStrict` etc share same loop pattern over `cfg.Security.NAT.*` → could use generic `forEachNATRule` helper.
- `expandAddressRange` in helpers + similar in `pkg/dataplane/compiler.go`? Need check duplication.

Severity: (C) — low urgency; mechanical, improves contributor velocity. Not blocking.

---

### [A2-5] #5269/#5341 deterministic CGNAT occupancy token — correctness vs modularity tradeoff

**Files:** `allocator.rs:420-448 LiveState.address_only_owners`, `4530a?` deterministic alloc path

**Context from git log:**
- Commit `0fe8714 nat: mint an occupancy token on the source-NAT address-only branch (#5269)` — previously address-only (port no-translation / port-less GRE/ESP) had NO occupancy token, so duplicate forward flows could collide on reverse demux (same pool_addr + preserved port → identical reverse identity). Fix mints token in `address_only_owners` FxHashMap.
- Issue prompt references #5341 deterministic CGNAT occupancy token. Check if deterministic path has same bug: deterministic block allocation scans occupancy bitmap for free offset within block, but does NOT check `address_only_owners`? Address-only only applies to non-PAT, deterministic is PAT variant. Could overlap? Deterministic block claim checks bitmap `is_occupied` per offset, but address-only tokens don't consume bitmap — they only insert into `address_only_owners`. So a deterministic PAT allocation could hand out a port that address-only already "owns" logically (different enforcement domains). Conversely address-only reserve checks `address_only_owners` contains_key? It checks and denies if colliding — but does it check bitmap occupancy? Should: if a PAT allocation occupies `(pool_addr, port)` where address-only wants same (pool_addr, preserved_port), the replies collide — address-only already owns that reverse identity. The bitmap alone doesn't capture it because address-only didn't set bit. Similarly PAT bitmap doesn't know about address-only.

This is not pure modularity but correctness spillover into modular struct. Recommendation: document invariant, add `#[cfg(test)]` collision test covering PAT vs address-only on same (addr,port). Existing `tests_pool.rs` (4673 LOC) likely already has such test post-#5269, but verify deterministic vs address-only cross-check missing — that would be #5341 follow-up.

**Modularity angle:**
- `address_only_owners` typed `FxHashMap<AddressOnlyReverseKey, SourceNatFlowKey>` lives inside `PortAllocatorLiveState` alongside `live_by_flow`. Its key includes protocol, translated_ip, translated_port, dst_ip, dst_port — 5-tuple reverse. This is conceptually DNAT reverse-lookup analogue but for SNAT address-only. Could be extracted into `address_only.rs` submodule with methods `try_reserve` / `release` / `contains_collision`.

Severity: (A) correctness-adjacent, but for audit scope (C) modularity — suggest extracting to its own type with assert.

---

### [A2-6] CoS TX drain focus: per-packet forwarding orchestrator cold stats out

**Prompt says:** CoS TX drain focus: per-packet forwarding orchestrator cold stats out.

**Relevance to NAT:**
- NAT per-packet orchestrator (`crates/session`? `afxdp/forwarding/mod.rs`) references NAT decision merge + dnat publish.
- NAT stats (NATCounterStore, allocation counters, dnat publish errors, reverse_key collisions) are on cold path but stored inline with hot forwarding structures in `protocol/control.rs` status snapshots:
  - `nat_reverse_key_collisions`, `dnat_publish_errors_total`, `nat_reverse_key_shared_displacements_total`, `source_nat_pools`, `nat_rule_counters` — these are aggregated via Atomics but snapshot generation iterates `Vec<NatRuleCounterStatus>`.
- `PortAllocatorShared` allocations_total/reuses_total/exhaustion_total are AtomicU64 updated on every allocation (hot). They false-share with occupancy bitmap pointer if colocated on same cache line. Moving stats to separate `#[repr(align(64))]` cold struct `PortAllocatorStats` reduces hotline invalidation across workers incrementing counters on different pool addresses.

**Measurement plan:**
- Baseline: `benches/snat_allocator.rs` modify to include stats increment in current shape vs separate cold struct shape.
- Expect low noise (<1%) because stats increments are relaxed atomics on distinct cache lines already if occupancy vec is heap-allocated separately — but if `PortAllocatorShared` struct itself is on one cache line (counters adjacent to occupancy Vec pointer + live Mutex), a counter fetch_add may ping-pong the cache line that also holds the Mutex state. Separating into two cache lines helps.

Severity: (C) perf nuance, measurement-gated.

---

### [A2-7] tests_pool.rs 4673 LOC catch-all — mirrors production god-structure

**File:** `userspace-dp/src/nat/tests_pool.rs` 4673

Contains pool-mode allocation tests, persistent lease expiration, deterministic out-of-range, GC budget, recycle FIFO oldest-first, collision #3047, address-only token #5269?, etc. Same fan-out as allocator.rs. Should split per #4409 plan: `tests_pool_basic.rs`, `tests_pool_persistent.rs`, `tests_pool_deterministic.rs`, `tests_pool_gc.rs`, `tests_pool_addr_only.rs` — pure motion mirroring production split.

Severity: (C) low, but reduces merge conflicts.

---

## Tests & Gate

**Current gates (at SHA):**
- `make test` runs Go + Rust cargo suite; NAT pool unit tests (`cargo test -p userspace-dp nat::`) cover allocator/pool/match/l4/scope/counter — 4673+ pooled.
- `cargo bench --bench snat_allocator` (harness=false, custom main) — outputs table allocs/sec + p50/p99/p999 current vs proposed speedup. Is #2852 merge-gate, must not regress below 1.0 speedup at M=6/8 (actually 1.4-1.6x claimed for proposed). If this audit proposes changes, re-run and record in `docs/research/2852-portalloc/results.md`.
- Go NAT compiler tests: `compiler_nat_*.go` + `pkg/dataplane/manager_nat_test.go`, `nat_*.go` integration (source/destination/static, scope #3096, deterministic #4559).
- Zero-alloc invariant: add `#[test] fn no_alloc_on_hot_path` using `std::alloc::GlobalAlloc` tracking or static assert that `claim()` is inline and takes `&self` not `&mut self` and returns Option<u16> without Box/Vec.

**Proposed gates for decomposition PRs (per-file motion):**
- Mechanical file move PRs must keep `git diff --stat` showing pure rename + `pub(super)` visibility widening only. Build passes.
- Add `cargo test -p userspace-dp --lib nat::allocator` with `--nocapture` to catch debug seams.
- Bench before/after for any `#[repr(align(64))]` or stats-cold-out change; record in PR body. If speedup <5% or within noise, CLOSE.

## Hot-Path Preservation Checklist

- reserve_flow #4388 (`reserve_address_only` path for HA-synced installs) must stay zero-alloc: no Vec allocation in `address_only_owners` insert? FxHashMap may allocate on insert — acceptable because HA sync is not per-packet but bulk; single insert amortized. However repeated allocation under contention triggers global allocator lock — avoid by `reserve` using entry API not new map.
- 1:N #4399 (deterministic mode ? Actually 1:N DNAT? Check prompt) — verify mapping table 1:N does not allocate per lookup. DnatTable lookup uses FxHashMap? Should be hash table, no alloc on get.
- `benches/snat_allocator.rs` must not regress vs 2852 baseline 1.4-1.6x at M=6/8 — for any cache-line or stats-cold-out change.
- `AddressOccupancy::claim` per-packet: no alloc, only atomic CAS + optional Mutex lock on recycle drain (cold when recycle empty). Must stay.
- No new `Mutex<VecDeque>` introduced on hot path during split.

## Dedup vs Prior Issues

| Prior | Status at SHA | This audit adds |
|-------|---------------|-----------------|
| #4409 nat/allocator.rs 926 + source 1190 | Phase 1 merged #2852, GC ledger says PLAN-KILL (chunked GC #4676 replaced GC engine). Tests split done. | A2-1 refines: NOT GC engine, but occupancy vs live vs deterministic file split + cache-line align, measurement-gated. A2-2 gives finer mechanical plan for source.rs 1523 folding. |
| #4421 nat64.rs 2047 split submodule | NOT DONE at this SHA (3102 single file, growth). | A2-3 concrete 5-file layout, notes frag sharded mutex contention analogue. |
| #4056 NAT compile/validate 5-file-scattered | Partial: pkg/config is 6-file split, pkg/dataplane still monolith 1317. | A2-4 details mis-named validator fragments (dnat_to.go, mixed_scope.go) + dataplane 1317 further split into counter/egress/snat file set. |
| #2852 SNAT PortAllocator contention | Phase 1 merged 6cbb106, bench exists. | Gate stated: cache-line win must measure vs this baseline; do not re-play Phase 1 debate. |
| #5269 addr-only token | Merged a80cc4f. | A2-5 checks deterministic×addr-only cross-domain collision — possible #5341 follow-up, needs test not yet in file list. |
| #5341 deterministic CGNAT occupancy token | Referenced in task but not found in log at this SHA — maybe future or in sibling worktree. | Extracted to A2-5; note deterministic scan checks bitmap but not address_only_owners, asymmetric. |

## Recommendation Order (measurement-gated, mechanical first)

1. **A2-3 nat64.rs 5-file split** — lowest risk, no hot-path, pure code motion, unblocks later deterministic.rs extraction. PR #1: `userspace-dp/src/nat64/` dir + mod.rs re-exports, tests pass.
2. **A2-1 file motion** `deterministic.rs` extraction from allocator.rs → `nat/deterministic.rs` (shared by nat64). PR #2a. Then `allocator_occupancy.rs` + `allocator_live.rs` — keep `PortAllocator` thin orchestrator. PR #2b. No `repr(align)` yet.
3. **A2-2 source.rs split** — PR #3: `source_rule.rs` + `source_parse.rs` + `source_match.rs` + `source_alloc.rs`; extract helpers `match_ipv4_pool` / `match_ipv6_pool` inside match file to drop 336-LOC function to <150 each.
4. **A2-4 Go 6-file motion** — Layer 1 mis-named validators moved, Layer 2 counter/egress split. PR #4 Go-only, no Rust.
5. **A2-6 optional cache-line experiment** — behind separate branch, bench vs `snat_allocator.rs` + perf counters (perf stat cache-misses). Only if ≥5% p99 improvement at M=6/8 and no regression at M=1. Otherwise CLOSE/PLAN-KILL.
6. **A2-5 cross-domain collision test** if #5341 scenario real — add unit test + fix before any cold-out.

## File Paths (absolute in worktree, for reference)

- `/tmp/review-wt-ps-043-a2-b1/userspace-dp/src/nat/allocator.rs`
- `/tmp/review-wt-ps-043-a2-b1/userspace-dp/src/nat/source.rs`
- `/tmp/review-wt-ps-043-a2-b1/userspace-dp/src/nat/destination.rs`
- `/tmp/review-wt-ps-043-a2-b1/userspace-dp/src/nat/static_nat.rs`
- `/tmp/review-wt-ps-043-a2-b1/userspace-dp/src/nat/mod.rs`
- `/tmp/review-wt-ps-043-a2-b1/userspace-dp/src/nat/status.rs`
- `/tmp/review-wt-ps-043-a2-b1/userspace-dp/src/nat64.rs`
- `/tmp/review-wt-ps-043-a2-b1/userspace-xdp/src/lib.rs`
- `/tmp/review-wt-ps-043-a2-b1/pkg/config/compiler_nat_source.go`
- `/tmp/review-wt-ps-043-a2-b1/pkg/config/compiler_nat_destination.go`
- `/tmp/review-wt-ps-043-a2-b1/pkg/config/compiler_nat_static.go`
- `/tmp/review-wt-ps-043-a2-b1/pkg/config/compiler_nat_helpers.go`
- `/tmp/review-wt-ps-043-a2-b1/pkg/config/compiler_nat_dnat_to.go`
- `/tmp/review-wt-ps-043-a2-b1/pkg/config/compiler_nat_mixed_scope.go`
- `/tmp/review-wt-ps-043-a2-b1/pkg/config/compiler_validate_strict_nat.go`
- `/tmp/review-wt-ps-043-a2-b1/pkg/dataplane/compiler_nat.go`
- `/tmp/review-wt-ps-043-a2-b1/pkg/dataplane/compiler.go`
- `/tmp/review-wt-ps-043-a2-b1/userspace-dp/benches/snat_allocator.rs`
- `/tmp/review-wt-ps-043-a2-b1/docs/engineering-style.md`


---
### Batch ps-a3-b1.md — 85600 chars

# A3 — Go Config Compilers + Schema + Validation Modularity Audit

Base SHA: 4e0c7f74cf0dbacf83051b2a9b6cf4e050dcecaa
Worktree: /tmp/review-wt-ps-043-a3-b1/
Date: 2026-07-11
Author: ps (043)
Scope: pkg/config/compiler*.go + types_system.go + schema_security.go — cold-path pure code-motion.

---

## 0. Methodology and Worktree Discipline

- Worktree: `git worktree add --detach /tmp/review-wt-ps-043-a3-b1 4e0c7f74c`
- All reads via worktree absolute paths under `/tmp/review-wt-ps-043-a3-b1/pkg/config/`.
- Read `docs/engineering-style.md` (cold path, but review discipline Section 5 PR-scoping applies).
- Output: this file only at `/tmp/review-work-ps-043/ps-a3-b1.md`; never `/tmp/ps-review-043*.md`.
- Cleanup: worktrees removed at end of generation.

---

## 1. File-Size/Shape Inventory (non-test, non-gen, at Base SHA)

LOC sorted ascending (wc -l). #func = grep ^func. #resp = distinct responsibility clusters observed.

| File | LOC | #func | #type | #resp | 1-liner responsibility summary |
|------|----:|---:|---:|---:|---|
| compiler_nat_dnat_to.go | 131 | 2 | 0 | 1 | DNAT rule-set "to" scope AST validator |
| compiler_nat_mixed_scope.go | 159 | 2 | 0 | 1 | NAT mixed-kind scope AST validator |
| compiler_security_alg.go | 39 | 1 | 0 | 1 | Security ALG stanza compiler (tiny) |
| compiler_validate_strict_reth_vrrp.go | 88 | 1 | 0 | 1 | RETH VRRP group-ID strict |
| compiler_validate_strict_vrrp.go | 94 | 1 | 0 | 1 | VRRP group-ID strict |
| compiler_validate_strict_vrrp_priority.go | 97 | 1 | 0 | 1 | VRRP priority strict |
| compiler_dispatch.go | 106 | 1 | 0 | 1 | Section-compile dispatcher (#4406 P4) |
| compiler_ddns_tls.go | 109 | 1 | 0 | 1 | DDNS TLS compilation helper |
| compiler_security.go | 114 | ? | 0 | ~2 | Security top-level dispatcher (now slim after splits) |
| compiler_earlystrict.go | 144 | 1 | 0 | 1 | Early-strict + 2 folds (#4406 P6a) |
| compiler_chassis.go | 258 | ~4 | 0 | 2 | Chassis cluster compiler (standalone aspects) |
| compiler_derivations.go | 177 | 1 | 0 | 1 | Cross-section derivations (#4406 P5) |
| compiler_validate_warn_cos.go | 182 | 2 | 0 | 2 | CoS oversubscription + classifier queue warns |
| compiler_tailgates.go | 201 | 1 | 0 | 1 | Tail validation/finalization (#4406 P7) |
| compiler_ipsec_bindiface.go | 209 | ~2 | 0 | 1 | IPsec bind-iface compilation |
| compiler_policy_missing_match.go | 214 | ~2 | 0 | 1 | Policy missing-match warnings |
| compiler_security_zones.go | 239 | ~3 | 0 | 2 | Zone compilation |
| compiler_validate_vrf_overlap.go | 239 | ~3 | 0 | 1 | VRF overlap validator |
| compiler_interfaces_unsupported.go | 245 | ~2 | 0 | 1 | Interface unsupported knob validator |
| compiler_security_log.go | 268 | ~3 | 0 | 2 | Security log profile/stream compiler |
| compiler_ipsec_proposalset.go | 282 | ~2 | 0 | 1 | IPsec proposal-set expansion |
| compiler_validate_wireguard.go | 285 | ~3 | 0 | 1 | Wireguard validation |
| compiler_validate_warn_routing.go | 307 | 5 | 0 | 5 | DHCP-relay parity, iface parity, ipip dead, routing rule window, rib-group leak |
| compiler_interface_range.go | 329 | ~4 | 0 | 1 | Interface range expansion (pre-walk #4027) |
| compiler_nat_static.go | 336 | 8 | 0 | 4 | Static NAT compiler + helpers |
| compiler_validate_strict_ipsec.go | 336 | 4 | 0 | 4 | IPsec policy/proposal/manual-key strict |
| compiler_validate_warn_firewall.go | 348 | 7 | 0 | 3 | Filter loss-priority, iface-specific, lo0 mirror, catch-all |
| compiler_applications_collision.go | 369 | ~4 | 0 | 1 | Application collision detection |
| compiler_nat_destination.go | 400 | 4 | 0 | 2 | DNAT compiler |
| compiler_nat_helpers.go | 410 | 13 | 0 | 5 | NAT shared helpers (see cross-file subtlety) |
| compiler_security_addressbook.go | 430 | ~5 | 0 | 2 | Address-book compiler |
| compiler_validate_strict_cos.go | 462 | 6 | 0 | 4 | CoS strict (policer, scheduler-map refs, loss-priority, queue) |
| compiler_prewalk.go | 471 | 1 | 0 | 1 | AST pre-walk gates (#4406 P1) |
| compiler_security_screen.go | 474 | ~4 | 0 | 2 | Screen profile compiler |
| compiler_validate_strict.go | 478 | 10 | 0 | 5 | Dataplane-type, trailing-tokens, flow-aging, DHCP bindings, VRRP VIP subnet |
| compiler_security_policy.go | 483 | ~4 | 0 | 2 | Policy compilation |
| compiler_validate_strict_zones.go | 504 | 8 | 0 | 4 | Zone count, interface membership/defined, host-inbound tokens/stanza, reserved names |
| compiler_validate_warn_host_inbound.go | 539 | 9 | 0 | 7 | Host-inbound multicast, managed-routing mismatch, default-policy log, deny+log inert, junos-host delivery, pre-id default log + helpers |
| compiler_policy_then.go | 594 | ~5 | 0 | 2 | Policy "then" compilation |
| compiler_validate_warn_ddns.go | 604 | 10 | 0 | 4 | DDNS backend, surfaceA DDNS, URL/TSIG/provider validators |
| compiler_ipsec.go | 681 | ~8 | 0 | 4 | IPsec VPN/KE compiler |
| compiler_validate_strict_application.go | 723 | 7 | 0 | 4 | Application set members, specs syntax/structure |
| compiler_security_flow.go | 728 | ~6 | 0 | 3 | Security flow (TCP session, ALG) |
| compiler_validate_strict_observability.go | 763 | 12 | 0 | 5 | Log event-mode/format, log profile/stream refs, dynamic-address feed server/name/ref, flow server template, sampling instance/rate |
| compiler_nat_source.go | 764 | 5 | 0 | 3 | Source NAT, NAT64, source pool port-range |
| compiler_applications.go | 839 | ~8 | 0 | 3 | Application spec compilation |
| compiler_validate_strict_routing.go | 943 | 12 | 0 | 7 | Routing export refs, community refs, FRR auth, BGP peer AS, router-id, rib-group import-rib, route filter match types, prefix length range, reserved names |
| compiler_validate_strict_policy.go | 1032 | 17 | 0 | 5 | Policy match addrs, apps, address-set members, zone refs, dup policy names, terminal action, log action |
| compiler_routing.go | 1233 | 16 | 0 | 5 | Routing-options (AS, fwd-table export, rib inet6 static, static routes, rib-groups, generate), next-table instance, routing-instances, BGP AS resolve, policy-options (protocol list, route filter len/range, term, community, inline keys), rib target kind, connected prefixes |
| compiler_firewall.go | 1237 | 9 | 1 | 4 | Firewall policer, three-color policer, filter compilation (from/then), prefix-list family collision, families, any-matches helpers |
| schema_security.go | 1263 | 3 | 0 | 3 | Security+apps config grammar SSOT: syslog enum sets, session-log leaf factory, host-inbound children factory, policy-then children factory, full schemaSecurity tree |
| compiler_protocols.go | 1272 | 14 | 0 | 6 | Protocols (router-advert, LLDP, OSPF area/iface, BGP, ISIS, RIP...), RA, named-instances, AS number, prefix-limit, export extensions, bandwidth parsing |
| compiler_interfaces.go | 1290 | 14 | 0 | 5 | Interface compilation (mtu, speed, duplex, disable, bw, vlan-tagging, native-vlan, encap, LAG, agg-ether, gigether, desc), unit (vlan-id, family, addr, DHCP, etc), tunnel wireguard, MSS token/value, VRRP groups, VRRP track/auth AST, track cost, VRRP track warnings, iface dynamic-DNS |
| compiler_class_of_service.go | 1309 | 23 | 2 | 6 | CoS forwarding-classes, classifiers (DSCP/802.1/inet-precedence), rewrite-rules, schedulers, TCPs, scheduler-maps, interfaces/units, fairness rss-expectation, line-rate/percent/rates, codepoint collection/rewrite/token expansion |
| compiler_nat (aggregate) | 2206† | 34 | 1 | 6 | All NAT source/dest/static + helpers + mixed-scope + dnat_to (see cluster below) |
| types_system.go | 1585 | 15* | 64 | ~15 | System + services + firewall + DHCP type defs + MarshalJSON + permission mapping + RPM effective accessors |
| compiler_validate_warn.go | 1682 | 6 | 0 | ~22 | Monolith warn: 6 funcs but ValidateConfig  ~1500 LOC containing ~30 warning families |
| compiler_validate_strict_filter.go | 1811 | 30 | 0 | 9 | Filter policer refs, TCP flags, prefix-list refs, RI refs, filter refs, RI direction, protocols, cross-field, actions, term expansion, match values, flex-match, port-except, addr-except, addr-literals, from-match, RI conflict, terminal conflict, DSCP + helpers |
| compiler_uniformgates.go | 1832 | 1 | 0 | ~1 orchestrator of 75 validators | Uniform fail-open gates orchestrator (runUniformGates) |
| compiler_services.go | 1841 | 27 | 0 | 8 | RPM 5 validators + DHCP local-server/DDNS/expired-leases/relay + dynamic-address + IP-monitoring (preferred-routes, strict, next-hop resolver) + RPM compiler + flow-monitoring + forwarding-options (port-mirroring, sampling, sampling-family) + event-options + bridge-domains |
| compiler_system.go | 2115 | 28 | 0 | 8 | compileSystem 536-LOC switch + DDNS catalog + dataplane tunables + shared-UMEM JSON + syslog host/file/user + SNMP community/trap/v3 + chassis/RG/IP-monitor + schedulers + archival + login/RBAC + inert-knob warnings |
| compiler.go | 2323 | 8 | 1 | 4 | Top-level compile orchestration P1-P7 + entry points + web-mgmt strict + pre-expansion gates (tunnel-id, zone-id, table-id, dup-block) + group expansion + compileOpts ~70-lenient flags |

† NAT aggregate = 131+159+336+400+410+764 = 2200 (non-test). LOC table excludes _test.go.

* methods (type receivers) counted under #func.

### NAT cluster detail (already partially split — check this SHA)

| File | LOC | #func | Role | Cross-file helpers used |
|------|-----:|---:|---|---|
| compiler_nat_helpers.go | 410 | 13 | Shared: natAddrFamily, natCIDRIPPart, isHostMaskAddress, parseZoneList, parseNATMatchScopes, collectNATScopes, applyNATFrom/ToScope, appendPoolAddresses, expandAddressRange, applyDeterministicKeys/Children/Host | Defines helpers, uses none outside |
| compiler_nat_source.go | 764 | 5 | SNAT + NAT64 pool compile + port-range | appendPoolAddresses, expandAddressRange |
| compiler_nat_destination.go | 400 | 4 | DNAT pool + rule-set compile | (local) parseDNATPoolAddress, appendDNATPortRange, parseDNATPortList |
| compiler_nat_static.go | 336 | 8 | Static NAT from/to scopes + mapped port + RI + prefix name resolve + then target | natAddrFamily, natStaticPrefixInfo family-agnostic |
| compiler_nat_dnat_to.go | 131 | 2 | DNAT rule-set to-scope AST | forEachChild helper |
| compiler_nat_mixed_scope.go | 159 | 2 | Mixed-scope AST validator | parseNATMatchScopes (from helpers) |
| compiler_validate_strict_nat.go | 1474 | 18 | NAT strict (match apps, dest addr, dest protocol, dest port, pool, src pool, src addr name refs, pool alarm, host-mask, NPTv6, NAT64 prefix, static then-target) | natAddrFamily, natCIDRIPPart, isHostMaskAddress |

Key subtlety: natAddrFamily / natCIDRIPPart / isHostMaskAddress are textual classification helpers (colon == v6) matching Rust parser semantics, not net.ParseIP. Used from 3+ compilation files + 1 validation file. Extracting them to a separate package would change package boundary; keeping them in compiler_nat_helpers.go with helpers-test coverage is correct. Any split of NAT helpers must leave these 3 in one file to preserve byte-identical compile per #4144.

### validate_strict cluster at this SHA (done in #4405 — pure code-motion)

| File | LOC | #func |
|------|-----:|---:|
| compiler_validate_strict.go (base) | 478 | 10 |
| compiler_validate_strict_application.go | 723 | 7 |
| compiler_validate_strict_chassis.go | 136 | 1 |
| compiler_validate_strict_cos.go | 462 | 6 |
| compiler_validate_strict_filter.go | 1811 | 30 |
| compiler_validate_strict_ipsec.go | 336 | 4 |
| compiler_validate_strict_nat.go | 1474 | 18 |
| compiler_validate_strict_observability.go | 763 | 12 |
| compiler_validate_strict_policy.go | 1032 | 17 |
| compiler_validate_strict_reth_vrrp.go | 88 | 1 |
| compiler_validate_strict_routing.go | 943 | 12 |
| compiler_validate_strict_screen.go | 174 | 4 |
| compiler_validate_strict_vrrp.go | 94 | 1 |
| compiler_validate_strict_vrrp_priority.go | 97 | 1 |
| compiler_validate_strict_zones.go | 504 | 8 |
Total non-test: ~7535 + 478 base = ~8013 LOC, avg ~534 LOC/file; max is filter 1811 which is itself a domain file.

### validate_warn cluster at this SHA (partially split, partially not)

| File | LOC | #func | Status |
|------|-----:|---:|---|
| compiler_validate_warn.go (main) | 1682 | 6 | Still monolithic ValidateConfig with ~30 warning families (~1500 LOC single func) + 2 small helpers |
| compiler_validate_warn_cos.go | 182 | 2 | Split result — CoS oversubscription + classifier queue |
| compiler_validate_warn_ddns.go | 604 | 10 | Split result — DDNS backend + SurfaceA + URL/TSIG/provider |
| compiler_validate_warn_firewall.go | 348 | 7 | Split result — filter loss-priority, iface-specific, lo0 mirror, no catch-all |
| compiler_validate_warn_host_inbound.go | 539 | 9 | Split result — host-inbound multicast, managed-routing mismatch, default-policy log, deny+log inert, junos-host delivery, pre-id default log |
| compiler_validate_warn_routing.go | 307 | 5 | Split result — DHCP relay parity, iface parity, ipip dead, rule window, rib-group leak |

validate_warn total ~3662 LOC. Prior: 3330 in one file. Now 1682 left in main + 5 split files 1880 = 3562 (~same). The main file still has ~1500-LOC ValidateConfig func with 22+ responsibilities.

---

## 2. File-by-File Log (what checked + sound/why)

### compiler.go (2323, 8 funcs, 4 resps)

- Read compiler.go top-to-bottom (compileOpts 44→~1720, CompileConfig, CompileConfigLenient, validateWebManagementAuthStrict, compileConfigWithOpts P1-P7 gates, CompileConfigForNode, CompileConfigForNodeLenient, compileConfigForNodeWithOpts, compileExpanded P1-P7 orchestrator).
- Checked: 3-phase fusion claim is actually 7-phase now after #4406 (P1 pre-walk, P2 skeleton, P3 tree mutation warnings, P4 section dispatch, P5 derived config, P6a early-strict+folds, P6b uniform gates, P7 tail). Comment block in compileExpanded et al documents each phase + invariant #5/#6/#7.
- Checked: compileOpts lenient flags ~70 fields — exponential flag interaction, but flags only downgrade error→warn, never change compile success when flag off. Safe for mechanical split per #4144.
- Sound why hot-path safe: compile path is cold gRPC/config candidate commit only, not per-packet; no all-alloc tightening.
- Finding candidate: YES — god-file per listed focus but already largely hollowed out after #4406 (actual section compilers moved to dispatch/prewalk/derivations/earlystrict/uniformgates/tail). Yet still 2323 LOC because compileOpts alone is ~1600 lines of doc-heavy flag definitions + tolerant entry point table duplication. compileOpts deserves its own file.

### compiler_system.go (2115, 28 funcs, 8+ subsystems)

- Read full file: compileSystem 18→576 switch handles ~18 case branches (host-name, dataplane-type, domain-name, domain-search, time-zone, no-redirects, name-server, ntp, login, backup-router, commit, root-auth, archival, master-password, license, processes, internet-options, dataplane, syslog, etc) + compileDDNSServices 576→739, helper ddnsServicesScalar 639, parseDurationSeconds 657, compileDDNSProvider 674, compileSystemDataplaneType 739, hasDNSProxyChild 759, compileUserspaceDataplane 768→891 (dataplane tunables + shared-UMEM JSON), syslogFacilitySeverity 891, loginClassPermName 907, loginClassAdvisoryWarnings 932, sshHardeningAdvisoryWarnings 994, userspaceRetiredKnobWarnings 1014, compileSharedUMEMConfig 1046, readSharedUMEMPhase0ArtifactForAudit 1080, sharedUMEMAuditWarnings 1137, normalizeSharedUMEMArtifact helpers 1158→1219, compileSNMP 1219→1412 (community, trap, v3 dispatch), snmpInertKnobWarnings 1412, systemInertKnobWarnings 1466, compileSNMPv3 1524, parseSNMPv3UserKeys 1598, compileSchedulers 1636, schedulerWindowFromNode 1697, compileChassis 1733→2047 (RG, control-fabric, IP-monitoring), validateBackupRouterDst 2047→2115.
- Checked: compileSystem case "login" parses BOTH custom RBAC class definitions (permissions, idle-timeout, allow-commands, deny-commands, allow-configuration, deny-configuration) AND users (uid, class, authentication encrypted-password + ssh-edxxx). Two responsibilities in one case branch.
- Checked: compileSystem case "syslog" compiles host/file/user + sub-statements (allow-duplicates, source-address, port, match, match-strings, structured-data, archive, etc) + facility/severity mapping. 4303 S-1 code path.
- Checked: SNMP compilation reaches across community + trap + v3 with shared var namedInstances loop.
- Subsystems confirmed as listed: (1) system leaf (host-name, domain-name, domain-search, time-zone, no-redirects, name-server, ntp) (2) login/RBAC (3) DDNS catalog (provider + services) (4) dataplane tunables (userspace, shared-UMEM JSON, retired knobs) (5) syslog host/file/user (6) SNMP community/trap/v3 + inert knobs (7) chassis/RG/IP-monitor (8) schedulers (window) + archival (archive-sites, password sentinel, leading-dash CVE #4589).
- Sound: Pure code-motion of switch arms into per-subsystem files is mechanical. Each case arm reads node.FindChild / child.Keys / child.Children only; no cross-case state except sys.* field writes and error early-return. The sys.* struct fields are independent except some shared ordering (dataplane-type resolved before others).
- Finding candidate: STRONG — highest ROI after validate_warn main.

### compiler_services.go (1841, 27 funcs, 8 resps)

- Read full dispatcher: compileServices 764→790 routes to flow-monitoring, rpm, ip-monitoring, app-ident flag. Then per-subsystem compilers + validators.
- RPM: parseRPMPositiveInt 17, parseRPMRootPositiveInt 28, validateRPMTest 39, validateRPMSourceAddressStrict 95, validateRPMLinkLocalZoneStrict 158, validateRPMHTTPGetSchemeStrict 211, validateRPMRoutingInstanceStrict 274, validateRPMProbePinsStrict 307, compileRPM 1044 + RPM test building — 6 funcs / 2 sub-parts (validation 5 + compile 1 + 2 parse helpers) — strong sub-file seam.
- DHCP: compileDHCPLocalServer 339, mergeDHCPDynamicDNS 465, compileDHCPDynamicDNS 537, compileDHCPExpiredLeases 635, compileDynamicAddress 699 (note: misplaced — actually security dynamic-address but called from services? Check: compileDynamicAddress parses `services {}`? Actually reads security node, mis-housed here for historical reason), compileDHCPRelay 1554 → 4 responsibilities but DHCP local-server vs relay are separate AST subtrees.
- IP-monitoring: compileIPMonitoring 790, compilePreferredRoutes 846, validateIPMonitoringStrict 913, resolveIPMonitoringInterfaceNextHop 998 — own cohesive subsystem (#1827).
- Flow-monitoring: compileFlowMonitoring 1180 → forwards to sampling/forwarding/port-mirroring.
- Forwarding-options: compileForwardingOptions 1271, compilePortMirroring 1309, compileSampling 1382, compileSamplingFamily 1433 — related but distinct.
- Event + bridge-domains: compileEventOptions 1709, compileBridgeDomains 1802 — standalone.
- Subsystems exactly as listed: RPM (5 validators) + DHCP local-server/DDNS/expired-leases/relay (4) + IP-monitoring/overlay (3) + flow-monitoring/sampling (4) + port-mirroring + event-options + bridge-domains = 8 top-level if counting loose.
- Finding candidate: STRONG — 8-resp file, clean AST subtree boundaries per `services {}` child name.

### compiler_validate_warn.go (1682, 6 funcs, ~22 resps) — PARTIALLY SPLIT AT THIS SHA

- Read full: deterministicIPv4Enforced 18, deterministicNAPT64Enforced 41, sortedPoolNames 68, ValidateConfig 83→1649 (single func ~1566 LOC), schedulerHasEffectiveWindow 1649, anySamplingDirectionConfigured 1667.
- ValidateConfig 83→1649 at this SHA still contains: AppID warning, SYN-cookie root-auth warning, login no-auth warning, zone collection, address-book collection + policyMatchNamedAddressRefs, app port/protocol/ALG validation, policy zone defined, NAT zone refs, screen refs, host-inbound full-admit, address-book entry format, address-set member refs, static route CIDR, DNAT/SNAT pool refs, zone iface logical keys, scheduler refs, scheduler effective window (#3860), RI iface refs, chassis cluster fabric, strict-vip-ownership, no-reth-vrrp redundant, persist-groups (#3075), allow-dataplane-sleep (#2008 H13), tcp-session (#2078), policy-rematch (#4233/#4234), flow route-change/force-ip-reassembly/multicast-lifetime/preserve-frag/sync-icmp (#4231 5 knobs), vpn-monitor (#4299), lifetime-kb (#4313), port-overloading (#4291), target RI (#4292), deterministic CGNAT (#4559), ALG unsupported (#4232), policy unknown children (#4232), flow aging (#3440), disable processes (#654), archive-sites password (#651), DNS proxy (#1715), flow monitoring presence, CoS classifier calls, routing rule window, rib-group leak, DDNS backend, SurfaceA DDNS, filter loss-priority, filter iface-specific, lo0 kernel mirror, PLUS later sections that at THIS SHA already delegate: validateCoSOversubscriptionWarnings, classOfServiceClassifierQueueWarnings, validateDHCPRelayParityWarnings, etc. — some of the tail already split via calls to *_warn_*.go funcs.
- Checked: Already per-issue split pattern for CoS/DDNS/firewall/host-inbound/routing — 5 files extracted. But ValidateConfig itself (main file) was never refactored to dispatch per-domain after extractions; remaining 22 warnings still interleaved in one func.
- Sound split: Each warning section reads cfg.* only, appends to warnings slice, returns nothing — pure predicate + fmt.Sprintf. Zero cross-dependency except shared maps built at top (zones, addrs, policyAddrRefs, configuredIfaces, hiZoneNames, schedNames). Those 5 precomputations can be hoisted to a small helper or rebuilt per-domain file (tiny O(n) cost at commit — cold path, within budget).
- Finding candidate: STRONGEST — never followed strict split pattern. At 1682 LOC single func is the single biggest remaining compiler file that is NOT already per-domain.

### compiler_interfaces.go (1290, 14 funcs, 5 resps)

- Read top dispatcher compileInterfaces 25→~560: loops interface children, compiles description, mtu, speed, duplex, disable, bandwidth, vlan-tagging, flexible-vlan-tagging, native-vlan-id, gratuitous-arp-reply, no-gratuitous-arp-request, encap, gigether-options (redundant-parent, 802.3ad), aggregated-ether-options (lacp active/passive/periodic), etc, then units (vlan-id, family inet/inet6 address DHCP, etc).
- parseTunnelWireguard 560, parseTunnelWireguardPeer 602, selectMSSToken 651, parseMSSValue 672, parseVRRPGroups 694→~930 (big VRRP group parser), validateVRRPTrackInterfaceAST 931, validateVRRPAuthenticationAST 974, vrrpGroupIDKeys 1016, vrrpAuthLeaf 1029, parseTrackCost 1049, checkVRRPGroupTrackShape 1059, vrrpTrackConfigWarnings 1167, compileInterfaceDynamicDNS 1224.
- Responsibilities: (1) physical interface props (2) logical unit/family (3) VRRP groups (with track/auth sub-validators) (4) tunnel wireguard (5) TCP MSS
- Finding: MEDIUM — 1290 LOC, 5 resps, but parseVRRPGroups is a long function (~230 LOC) with nested loops parsing VRRP group ID, virtual-address, priority, etc. Could be its own file plus validation split, but lower ROI than system/services/warn because interfaces compilation is relatively stable (few collisions).

### compiler_uniformgates.go (1832, 1 func, 1 orchestrator)

- Read FULL file: single func runUniformGates ~1800 LOC, 75+ validators called sequentially, each `if err := validateXxxStrict(cfg) { return err }` then warning appends for tolerant path. File contains invariant #6/#7 documentation, explains why ordering must not change.
- Prior: #4406 split result — this file IS the orchestrator that PRESERVES invariants #6 (strict first-error slot) + #7 (tolerant warning order) by listing validators in deterministic source order. It was created BY the #4406 PR as step 4.
- Sound: The orchestrator file is not a decomposition target — its job is to be a stable list of ~75 calls, CHANGED ONLY when a new validator appears. Splitting it further would defeat its purpose (to make first-error slot and warning order visible in one place).
- Finding: NEGATIVE (D) — already split result, orchestrator preserves invariants. Do NOT re-split.

### compiler_validate_strict_filter.go (1811, 30 funcs, 9 resps)

- 30 funcs: 15 validators (policer refs, tcp-flags, prefix-list refs, RI refs, filter refs, RI direction, protocols, cross-field, actions, match values, flex-match, port-except, address-except, address-literals, from-match, RI conflict, terminal conflict, DSCP) + helpers firstIncompatibleProtocol, classifyFilterAddrFamily, filterDSCPResolvable, FilterDSCPResolvable public, FilterDSCPNames, filterProtocolResolvable, protocolIsPortBearing, protocolIsTCP, protocolIsICMPFamily, ProtocolIsPortBearing public, FilterProtocolResolvable public.
- Responsibilities 9: policer/protocols/DSCP/address-except/port-except/match-values/cross-field/terminal-conflict/RI conflict.
- Already per-domain split result: one of 12 files from #4405 closed issue (compiler_validate_strict.go 6997 → 12 files). 1811 LOC is large but within that domain, sub-split would cut inside one issue's domain (filter validation), with high risk of merge conflicts for active fable work (F-1, F-2, F-3a, fable-review-161 F-030 etc noted in src).
- Finding: NEGATIVE (D) — already per-domain split result. The name filter implies it IS the per-domain file. Do NOT re-split until fable filter work quiesces.

### types_system.go (1585, 15 methods, 64 types, ~15 resps)

- Read: SystemConfig, UserspaceConfig, SharedUMEMConfig, RootAuthConfig, ArchivalConfig, InternetOptionsConfig, SystemServicesConfig, DDNSServicesConfig, DDNSProvider, SSHServiceConfig, WebManagementConfig, APIAuthConfig, APIAuthUser, SystemSyslogConfig (host/file/user/facility), SNMPConfig/Community/Client/TrapGroup/v3User, LoginClassPermission, LoginConfig/Class/User, ServicesConfig, IPMonitoringConfig/Policy/PreferredRoute/RouteOverlayEntry, RPMConfig/Probe/Test, FlowMonitoringConfig, NetFlowIPFIXConfig/Template, NetFlowV9Config/Template, ForwardingOptionsConfig, PortMirroringConfig/Instance, DHCPRelayConfig/ServerGroup/Group, SamplingConfig/Instance/Family, FlowServer, FirewallConfig/Policer/ThreeColorPolicer/Filter/Term/FlexMatch/PrefixListRef, DHCP server types.
- 64 type defs touches 20+ consumers (daemon, frr, networkd, snmp, logging, appid, dhcprelay, sampling, rpm, scheduler, arch, etc). Any rename requires wide update. Type mobility cost is high.
- Prior: Issue suggests tracking issue low priority for types_system because type def moves break every consumer's import assumption about where types live — but package stays `config`, so moves are file-local, not cross-package. Actually splitting types_system.go into _login.go _snmp.go etc WOULD be pure file-move within package config, no consumer break, because Go package types visible across files.
- However: 64 types in one file is intentional grouping of system+services+firewall+dhcp because historical commit added them all here before services types separated? Check git log — types/services.go wasn't.
- Finding: NEGATIVE (D) at this priority — low ROI while compilers are bigger signal; tracking issue candidate. File IS broad but types are cold struct definitions with zero logic (except MarshalJSON for SNMP, ValidLoginClasses, mapJunosPermissions, RPM effective accessors which ARE logic). Those 15 methods could move to behavior files (types_system_login.go, types_system_rpm.go) as first increment.
- Still listed in original FILES but flagged D as requested.

### schema_security.go (1263, 3 funcs, 3 resps)

- Read: header comment explains schema_security.go is the security+applications subtree of config-mode grammar SSOT (#1891 domain split). Root composition in schema.go, schemaNode type there. syslog enum vars (logModes, logFormats, severities, facilities, categories) + securitySessionLogModes var + sessionLogModeLeaf factory (shared multi-value enum leaf for session-init/close, child nil invariant for SetPath collapse + SchemaValidate) + hostInboundSchemaChildren factory (system-services/protocols multi-value value-tail leaves, children nil for collapse, untyped because allowlist lives in host_inbound_tokens.go) + policyThenSchemaChildren factory (terminal actions permit/deny/reject + log/count, canary in schema_policy_then_3377_test.go) + schemaSecurity var (zones with description/interfaces/host-inbound/address-book, policies, etc).
- 3 responsibilities: (1) security schema leaf factories (2) syslog enum SSOT (3) security zones/policies schema
- 1263 LOC is large for a schema file but mostly tree literal. Splitting by sub-tree (zones vs policies vs syslog vs applications) would mirror schema split already done for other domains (#1891).
- Finding: LOW priority — schema files are generated-conceptually but hand-written, large mostly due to nested map literals. Split would improve review but docs already point to this as grammar SSOT; any split must preserve setSchema composition order. Lower ROI than compiler files.

### compiler_protocols.go (1272, 14 funcs, 6 resps)

- Protocols: router-advertisement, LLDP, OSPF area/interface, BGP, ISIS, RIP. Each protocol's AST subtree has distinct syntax. Could split to _ospf.go _bgp.go _lldp.go _routeradvert.go _isis_rip.go.
- parseBandwidthBps/limit/burst/scaled-decimal strict functions + helpers — shared utility for policer + CoS + interface bandwidth parsing. Cross-file subtlety: parseBandwidthLimit used from compiler_firewall.go + compiler_class_of_service.go + compiler_interfaces.go (check).
- Finding: MEDIUM — 6 resps, but protocol area relatively stable vs NAT/system actively worked.

### compiler_routing.go (1233, 16 funcs, 5 resps)

- routing-options (static, rib inet6 static, rib-groups, generate), routing-instances (VRF import-rib, table-id), policy-options (community, prefix-list, route-filter, policy-statement). Next-table, BGP AS, rib target kind.
- parseRouteFilterLen/Range, routeFilterTrailingToken, parsePolicyTermChildren, applyCommunityAction — policy-options sub-helpers.
- RibGroupConnectedPrefixes public helper used by routing reconciliation.
- Finding: MEDIUM — 5 resps, but relatively cohesive (all routing domain). Lower merge-conflict density than system.

### compiler_firewall.go (1237, 9 funcs, 4 resps)

- Policer, three-color policer, filter compilation (from/then + flex-match), prefix-list family collision/families, any-matches AST.
- firewallMatchValues helper — SSOT for multi-leaf value read (#2419), used across ~15 compiler files. MUST stay in one place or be extracted to shared helper.
- Finding: MEDIUM — 4 resps, but already small compared to system/services. Prefix-list helpers + filter from/then are distinct but coupled.

### compiler_class_of_service.go (1309, 23 funcs + 2 errors, 6 resps)

- Forwarding-classes, classifiers (DSCP/802.1/inet-precedence), rewrite-rules (DSCP/802.1/inet-precedence/exp), schedulers (transmit-rate, priority, buffer-size, surplus-sharing, equal-flow-enforcement, codel-target), traffic-control-profiles (shaping-rate, guaranteed-rate, delay-buffer-rate, scheduler-map), interfaces (unit shaping-rate/burst-size), fairness rss-expectation.
- Parsing: parseCoSTransmitRate, parseCoSShapingRate, collectCoSDSCP/8021CodePoints, collectCoSDSCP/8021RewriteCodePoint, expandCoSCodePointToken + numeric range error / unknown token error.
- Shared helpers: parseBandwidthBps/Limit from protocols file (cross-file subtlety).
- Finding: MEDIUM-HIGH — 23 funcs / 6 resps, large for single file, but domain-cohesive (all CoS). Potential split: _forwarding_class.go _classifier.go _rewrite_rule.go _scheduler.go _traffic_control_profile.go _interface.go _fairness.go _codepoint.go. However CoS data flows through forwarding-classes -> schedulers -> scheduler-maps -> interfaces in order; splitting preserves order only if files don't introduce init dependency. Pure code-motion feasible.

### NAT helpers cross-file note (applies to all NAT findings)

Evidence: grep shows:
- pkg/config/compiler_nat_helpers.go defines natAddrFamily, natCIDRIPPart, isHostMaskAddress, parseZoneList, parseNATMatchScopes, collectNATScopes, applyNATFrom/ToScope, appendPoolAddresses, expandAddressRange, applyDeterministicKeys/Children/Host.
- pkg/config/compiler_nat_static.go:22 uses natAddrFamily
- pkg/config/compiler_nat_source.go:310,316 uses appendPoolAddresses; 117,131 uses expandAddressRange
- pkg/config/compiler_nat_mixed_scope.go:65 uses parseNATMatchScopes
- pkg/config/compiler_validate_strict_nat.go:205 uses natCIDRIPPart; 499 uses isHostMaskAddress; 803,830,978,987,1209,1219,1222,1223,1412 uses natAddrFamily / natCIDRIPPart / isHostMaskAddress family.
- compiler_validate_warn.go tail uses sortedPoolNames + deterministicIPv4Enforced (defined in warn main, used by CoS pool warning).

Any split of NAT must keep textual-family helpers (natAddrFamily, natCIDRIPPart, isHostMaskAddress) together and preserve file-level visibility (same package). Moving them to new file is fine; splitting them across files would cause duplicate definitions or require extraction to shared location — not desired.

---

## 3. Findings

### Finding 1: compiler_validate_warn.go — ValidateConfig monolith never followed strict split pattern

- **Title:** ValidateConfig (1682 LOC, 1 func ~1566 LOC) still carries ~22 warning families post-partial split; never refactored to per-domain dispatch after 5 _warn_*.go extractions.
- **Severity:** HIGH
- **Confidence:** HIGH
- **Refactor class:** A — cold path, pure code-motion, Set identical per #4144 discipline
- **Evidence:**
  file: `pkg/config/compiler_validate_warn.go:83` LOC 1566 (ValidateConfig)
  ```
  func ValidateConfig(cfg *Config) []string {
      var warnings []string

      // Note (#1476): the previous "ebpf is deprecated" warning was
      // removed because `validateDataplaneTypeStrict` now hard-rejects
      // `dataplane-type ebpf` at commit time with
      // `ErrEBPFDataplaneRetired`. ValidateConfig is never reached for
      // EBPF-typed configs after that gate; keeping the warning here
      // would be dead code.

      // #653: when `services application-identification` is enabled,
      // emit a one-line warning at commit time so operators see what
      // the knob actually does on xpf vs Junos vSRX. The runtime is
      // port + protocol matching only — there is NO L7 DPI / signature
      // engine. See `show services application-identification status`
      // and docs/services-application-identification.md for the full
      // contract.
      if cfg.Services.ApplicationIdentification {
          warnings = append(warnings,
              "services application-identification is enabled, but xpf "+
                  "AppID is port+protocol catalog matching only — no L7 "+
                  "DPI / signature engine. Run `show services "+
                  "application-identification status` for the contract; "+
                  "see docs/services-application-identification.md.")
      }

      if userspaceSynCookieProtectionActive(cfg) &&
          (cfg.System.RootAuthentication == nil ||
              cfg.System.RootAuthentication.EncryptedPassword == "") {
          warnings = append(warnings,
              "active userspace-dp SYN-cookie screen profiles require "+
                  "system root-authentication encrypted-password material "+
                  "for the userspace cookie key; the userspace dataplane "+
                  "fails closed until it is set. Legacy eBPF SYN-cookie "+
                  "handling uses kernel helpers and is not affected by "+
                  "this warning.")
      }

      // #1944 §5.8: warn when a configured login user has no usable auth
      // method — no ssh-* keys AND no usable encrypted-password (absent, or
      // a bare lock sentinel which only locks the account). Mirrors the
      // root-auth warning style above; directly addresses the "non-root
      // operator cannot log in" bug class this issue closes.
      if cfg.System.Login != nil {
          for _, u := range cfg.System.Login.Users {
  ```
  plus 1400 more lines continuing through AppID, app port/protocol/ALG, policy zone, NAT zone, screen refs, full-admit, address-book format, address-set refs, static route CIDR, DNAT/SNAT pool refs, zone iface logical keys, scheduler refs, scheduler effective window, RI iface refs, chassis fabric, strict-vip-ownership, no-reth-vrrp redundant, persist-groups, allow-dataplane-sleep, tcp-session inert, policy-rematch, flow knobs, vpn-monitor, lifetime-kb, port-overloading, target RI, deterministic CGNAT, ALG, flow aging, disable processes, archive-sites password, DNS proxy, etc (grep shows ~22 heading comments `// #` / `// Valid` inside single func).

- **Proposed decomposition:**
  New files, each defines `func validate*Warnings(cfg *Config) []string` plus helpers, called from a slim `ValidateConfig` dispatcher that builds shared maps once (zones, addrs, policyAddrRefs, configuredIfaces, hiZoneNames, schedNames, etc — 5 maps) and threads them.

  ```
  compiler_validate_warn.go (remains — becomes ~150-LOC dispatcher)
    - keeps deterministicIPv4Enforced, deterministicNAPT64Enforced, sortedPoolNames (shared-harness used by NAT pool warning + CoS)
    - ValidateConfig builds zones/addrs/policyAddrRefs/configuredIfaces/hiZoneNames/schedNames once
    - calls per-domain functions in current warning order (preserves tolerant-path warning order, though warnings order is less load-bearing than strict first-error)

  Split-out (new):
  compiler_validate_warn_policy.go
    - policy zone defined (special tokens), source/dest addr, scheduler refs, global policy sched, default-policy log, policy log inert on deny, junos-host direct-delivery, pre-id default-policy log, policy unknown children (#4232)
    - moves policyMatchNamedAddressRefs already private? check — actually in policy.go but shared via package; reuse via helper or re-thread.

  compiler_validate_warn_nat.go
    - NAT zone refs (source/static), DNAT/SNAT pool refs, deterministic CGNAT block-size (#4559), port-overloading (#4291), target RI (#4292), deterministicIPv4Enforced / deterministicNAPT64Enforced already shared.
    - seam: needs sortedPoolNames.

  compiler_validate_warn_addressbook.go (optional — 2 resps currently inside main)
    - address-book entry format, address-set member refs, plus any future feed-related.

  compiler_validate_warn_zones_interfaces.go
    - zone interface references, RI interface refs, zone iface logical keys.

  compiler_validate_warn_system.go
    - AppID (#653), SYN-cookie root-auth, login no-auth (#1944 S5.8), scheduler effective window (#3860), chassis fabric + vip-ownership + no-reth-vrrp redundant (#3226? no that’s host-inbound full-admit) Actually: AppID, SYN-cookie, login, scheduler effective window, chassis cluster fabric, strict-vip-ownership, no-reth-vrrp redundant, persist-groups, allow-dataplane-sleep (#2008 H13), tcp-session inert flags (#2078), policy-rematch, flow route-change/force-ip-reassembly/multicast-lifetime/preserve-frag/sync-icmp (#4231), vpn-monitor (#4299), lifetime-kb (#4313), port-overloading target, deterministic CGNAT, ALG unsupported, flow aging (#3440), disable processes (#654), archive-sites password (#651), DNS proxy, flow-monitoring, etc — further sub-split inside.

  Sub-split suggestion for system to avoid one new large file:
  compiler_validate_warn_system_session.go — flow aging, tcp-session, route-change/force-ip-reassembly/multicast/preserve/sync-icmp
  compiler_validate_warn_system_security.go — AppID, SYN-cookie, ALG unsupported, policy unknown children, archive-sites password, disable processes
  compiler_validate_warn_system_chassis.go — fabric, vip-ownership, no-reth-vrrp, persist-groups, allow-dataplane-sleep
  compiler_validate_warn_system_login.go — login no-auth, root-auth? etc — but small.

  Existing _warn_*.go files STAY:
  - compiler_validate_warn_cos.go (done)
  - compiler_validate_warn_ddns.go (done)
  - compiler_validate_warn_firewall.go (done)
  - compiler_validate_warn_host_inbound.go (done)
  - compiler_validate_warn_routing.go (done)

  After split, ValidateConfig body: 22 x `warnings = append(warnings, validate*Warnings(cfg, shared)...)` preserving order; existing per-domain files already called from tail of ValidateConfig at this SHA (grep `validate.*Warnings` at end) — those calls stay, just preceding 22 inlined sections become calls.

  Seam: shared map build helper `func warnBuildShared(cfg *Config) warnShared { zones, addrs, policyAddrRefs, configuredIfaces, hiZoneNames, schedNames }` where `type warnShared struct` holds those 5 maps + sorted names slices.

- **Hot-path preservation:** A = safe, cold path, pure code-motion, go build/test byte-identical per #4144 discipline. ValidateConfig is purely read-only cfg -> warnings []string; no goroutine, no mutation, no timing. Extraction is function boundary introduction only. Preserves warning order which is user-visible but not strict-first-error slot (that invariant belongs to uniformgates, already per #4406). Still preserve order to avoid noisy diff.
- **Tests+gate:** `go build ./...` + `go test ./pkg/config/...` green; decl-NAME set identical (ValidateConfig, deterministicIPv4Enforced, deterministicNAPT64Enforced, sortedPoolNames, schedulerHasEffectiveWindow, anySamplingDirectionConfigured remain in main file; new per-domain funcs private `validateXxxWarnings`). `declare -a` before/after `go vet` diff should show no exported name change.
- **Why it matters:** Build time small win (parallel compile), but PRIMARY reviewer time + merge-conflict density. ValidateConfig at 1682 LOC is magnet for collision: every new warning touches same file, same func, unrelated domains. Split reduces contested surface from 1 file touched by every feature-team's warning to ~8 domain files, each with distinct owner. Matches strict side completed split (#4405) — warn should mirror strict pattern. Also unlocks per-domain ownership in CODEOWNERS if desired.
- **Fix direction:** Ordered PRs:
  PR1 (this) — extract warnShared builder + split policy + NAT warnings into _policy.go + _nat.go + _addressbook.go + _zones_interfaces.go + _system_*.go; ValidateConfig becomes dispatcher; `go test ./pkg/config/...` green; decl-NAME identical.
  PR2 — optional: further sub-split system warnings into login/session/security/chassis/session — only if PR1 leaves >600 LOC in system.
- **Labels:** area/config, kind/refactor, cold-path, A-mechanical
- **Dedup note:** Unique — prior #4405 closed strict split; warn never followed strict pattern (gap noted in prompt). This audit fills that gap. No duplicate finding elsewhere.

---

### Finding 2: compiler_system.go — 8 subsystems in one 2115-LOC file with 536-LOC switch

- **Title:** compileSystem god-compiler: 536-LOC switch + 8+ subsystems (system leaf, login/RBAC, DDNS catalog, dataplane tunables + shared-UMEM JSON, syslog host/file/user, SNMP community/trap/v3, chassis/RG/IP-monitor, schedulers, archival)
- **Severity:** HIGH
- **Confidence:** HIGH
- **Refactor class:** A — cold path, pure code-motion, per-case extraction
- **Evidence:**
  file `pkg/config/compiler_system.go:18` LOC 536 (compileSystem switch)
  ```
  func compileSystem(node *Node, sys *SystemConfig, cfg *Config, opts compileOpts) error {
  ...
      switch child.Name() {
      case "host-name":
          if len(child.Keys) >= 2 {
              sys.HostName = child.Keys[1]
          }
      case "dataplane-type":
          // Already resolved before child compilation so system dataplane
          // dispatch is independent of statement ordering.
      case "domain-name":
          ...
      case "domain-search":
          // Multi-value leaf (schema_system.go domain-search, multi:true).
          // Handles every AST shape via the #2545 multi-leaf SSOT helper:
          //   - bracket list  `domain-search [ a b ]` collapses every value
          //     onto child.Keys[1:] with no children (#2419);
          //   - hierarchical block `domain-search { a; b; }` carries one
          //     leaf child per value;
      case "login":
          // #4304 S-2: parse custom `login class <name>` RBAC definitions so
              case "permissions":
              case "idle-timeout":
              case "allow-commands":
              case "deny-commands":
              case "allow-configuration":
              case "deny-configuration":
              case "uid":
              case "class":
              case "authentication":
                  case "encrypted-password":
                  case "ssh-ed25519", "ssh-rsa", "ssh-dsa":
      case "syslog":
          // #4303 S-1: switch on the KNOWN host sub-statements
              case "allow-duplicates":
              case "source-address":
              case "port":
              case "match", "match-strings", "structured-data",
  ...
  case "archival":
  case "dataplane":
  case "processes":
  ...
  syslogFacilitySeverity          891
  loginClassPermName              907
  loginClassAdvisoryWarnings      932
  sshHardeningAdvisoryWarnings    994
  userspaceRetiredKnobWarnings   1014
  compileSharedUMEMConfig        1046
  compileSNMP                    1219 (community/trap/v3 in one func ~200 LOC)
  compileChassis                 1733 (RG + control-fabric + IP-monitor)
  compileSchedulers              1636
  ```
  2115 LOC, 28 funcs, switch handles host-name/dataplane-type/domain-name/domain-search/time-zone/no-redirects/name-server/ntp/login/backup-router/commit/root-auth/archival/master-password/license/processes/internet-options/dataplane/syslog (plus ciphers/macs hardening #4305 S-4) — each case independent except writes to `sys.*`.

- **Proposed decomposition:**
  Keep `compiler_system.go` as ~200 LOC dispatcher orchestrating subsystem compilers, each in own file. Seam: each subsystem compiler signature `func compileSystemXxx(node *Node, sys *SystemConfig, cfg *Config, opts compileOpts) error` where `node` is the system child node for that stanza, or `sysNode` for ones that scan whole system children. Alternatively for switch arms that read `child` directly, extraction helper `compileSystemLeaf(child *Node, sys *SystemConfig)` is overkill — better move case-body block into helper called from switch.

  ```
  compiler_system.go (dispatcher remains, ~200 LOC)
    - compileSystem loop stays, but each case body calls extracted func:
      case "host-name": compileSystemHostName(child, sys)
      case "domain-search": compileSystemDomainSearch(child, sys)
      ...

  New files:
  compiler_system_leaf.go — host-name, domain-name, domain-search, time-zone, no-redirects, name-server, ntp, backup-router, root-authentication, archival (archive-sites + password sentinel + leading-dash CVE #4589), commit, master-password, license, processes, internet-options, internet-options? Actually: system leaf knobs (host-name, domain-name, domain-search, time-zone, no-redirects, name-server, ntp, backup-router, archival) — ~400 LOC.

  compiler_system_login.go — login (class definitions + users). Includes loginClassPermName, loginClassAdvisoryWarnings remains in warn? No, advisory warnings are validation, not compilation — but loginClassAdvisoryWarnings currently lives in system.go (line 932). Move compilation to _login.go, keep advisory extraction? Actually loginClassAdvisoryWarnings is warn consumed in tail gates — stays in system file or moves to warn. For pure code-motion, keep it in _login.go but called from tail.

  compiler_system_ddns.go — compileDDNSServices, ddnsServicesScalar, parseDurationSeconds, compileDDNSProvider (currently 576→739). + helpers ddnsServicesScalar, parseDurationSeconds, compileDDNSProvider.

  compiler_system_dataplane.go — compileSystemDataplaneType, hasDNSProxyChild, compileUserspaceDataplane + compileSharedUMEMConfig + readSharedUMEMPhase0ArtifactForAudit + sharedUMEMAuditWarnings + normalize*Artifact* helpers + userspaceRetiredKnobWarnings — dataplane tunables + shared-UMEM JSON artifact + retired knob warnings.

  compiler_system_syslog.go — syslog sub-compilation + syslogFacilitySeverity, systemInertKnobWarnings (syslog/file/user host). Associated with 4303 S-1.

  compiler_system_snmp.go — compileSNMP, snmpInertKnobWarnings, compileSNMPv3, parseSNMPv3UserKeys.

  compiler_system_chassis.go — compileChassis (RG + fabric + IP-monitor) + validateBackupRouterDst (backup-router is system leaf but chassis-adjacent; could stay in chassis).

  compiler_system_scheduler.go — compileSchedulers, schedulerWindowFromNode.

  Optionally:
  compiler_system_login_rbac.go — login class RBAC parsing split from user parsing if login grows further; but start with one _login.go.

  Seam details:
  - loginClassPermName is used only inside compilation + advisory warnings (inert). Keep in _login.go.
  - snmpInertKnobWarnings and systemInertKnobWarnings are validation-ish but live in compilation file; they can move with their compiler (SNMP/syslog) since they read node, not cfg.
  - compileSharedUMEMConfig reads file system via readSharedUMEMPhase0ArtifactForAudit — isolated to dataplane file.
  ```

- **Hot-path preservation:** A = safe, cold path, pure code-motion, go build/test byte-identical per #4144. compileSystem reads AST only, writes sys.* fields. Each case arm's field writes independent (host-name writes sys.HostName, etc) — no cross-case mutable sharing requiring ordering except dataplane-type resolved before others (comment says already resolved before child compilation). So extraction order-preserving is trivial. No alloc tightening, no timing, no packet path.
- **Tests+gate:** `go build ./...` + `go test ./pkg/config/...` green; decl-NAME set identical (funcs move but package-level funcs stay exported only where already: compileSystem is private, compileDDNSServices used maybe from others? Check — compileDDNSServices called only from compileSystem. So all moves private). No exported name change. `go vet` identical.
- **Why it matters:** Highest merge-conflict ROI after warn: system leaf touches touch every team (login, syslog, SNMP, chassis, ddns, dataplane). At 2115 LOC, 28 funcs, 8 subsystems, file is contested on almost every HA login/DNS/SNMP/chassis PR. Split drops contention surface 8x and reduces per-PR review load from scanning 2115 LOC to scanning ~250 LOC per subsystem file. Build-time benefit marginal but incremental parallelism of 8 files vs 1 file for `go build`.
- **Fix direction:** Ordered PRs after Finding 1:
  PR2 — extract login + DDNS + SNMP (3 files) — lowest coupling, each compiles own sub-AST, easy to byte-identical diff.
  PR3 — extract syslog + dataplane/shared-UMEM + archival (3 files) — syslog has ciphers/macs hardening #4305 S-4 needing care; dataplane has phase0 artifact read.
  PR4 — extract chassis + schedulers + leaf knobs (3 files) — chassis touches compileOpts lenientBackupRouterDst? Actually validateBackupRouterDst is warning-ish but currently compiler — move with chassis.
- **Labels:** area/config, kind/refactor, cold-path, A-mechanical, high-collision
- **Dedup note:** Unique — prior #4405 strict split did not touch system compilation; system file not mentioned in #4406 as split result (dispatched but not decomposed). No dedup.

---

### Finding 3: compiler_services.go — 8 subsystems in one 1841-LOC file

- **Title:** compileServices god-file: 27 funcs, 8 subsystems (RPM 5 validators + compile, DHCP local-server/DDNS/expired-leases/relay, dynamic-address, IP-monitoring/overlay, flow-monitoring, forwarding-options/port-mirroring/sampling, event-options, bridge-domains)
- **Severity:** HIGH
- **Confidence:** HIGH
- **Refactor class:** A
- **Evidence:**
  file `pkg/config/compiler_services.go:17` LOC ~1200+ (RPM + DHCP + IP-monitoring + flow + sampling + port-mirroring + event + bridge)
  ```
  func parseRPMPositiveInt(probeName, testName, field, raw string) (int, error) {
  func parseRPMRootPositiveInt(field, raw string) (int, error) {
  func validateRPMTest(probeName string, test *RPMTest) error {
  func validateRPMSourceAddressStrict(cfg *Config) error {
  func validateRPMLinkLocalZoneStrict(cfg *Config) error {
  func validateRPMHTTPGetSchemeStrict(cfg *Config) error {
  func validateRPMRoutingInstanceStrict(cfg *Config) error {
  func validateRPMProbePinsStrict(cfg *Config) error {
  func compileDHCPLocalServer(node *Node, dhcp *DHCPServerConfig, isV6 bool) error {
  func mergeDHCPDynamicDNS(dst, src *DHCPDynamicDNSConfig) *DHCPDynamicDNSConfig {
  func compileDHCPDynamicDNS(node *Node) *DHCPDynamicDNSConfig {
  func compileDHCPExpiredLeases(node *Node) *DHCPExpiredLeasesConfig {
  func compileDynamicAddress(node *Node, sec *SecurityConfig) error {
  func compileServices(node *Node, svc *ServicesConfig) error {
      if fmNode := node.FindChild("flow-monitoring"); fmNode != nil {
          if err := compileFlowMonitoring(fmNode, svc); err != nil {
              return err
          }
      }
      if rpmNode := node.FindChild("rpm"); rpmNode != nil {
          if err := compileRPM(rpmNode, svc); err != nil {
              return err
          }
      }
      if ipmNode := node.FindChild("ip-monitoring"); ipmNode != nil {
          if err := compileIPMonitoring(ipmNode, svc); err != nil {
              return err
          }
      }
      if node.FindChild("application-identification") != nil {
          svc.ApplicationIdentification = true
      }
      return nil
  }
  func compileIPMonitoring(node *Node, svc *ServicesConfig) error {
  func compilePreferredRoutes(node *Node, ri, polName string, routes map[string]*PreferredRoute, order *[]string) error {
  func validateIPMonitoringStrict(cfg *Config) error {
  func resolveIPMonitoringInterfaceNextHop(cfg *Config, polName string, pr *PreferredRoute, dst *net.IPNet) (string, error) {
  func compileRPM(node *Node, svc *ServicesConfig) error {
  func compileFlowMonitoring(node *Node, svc *ServicesConfig) error {
  func compileForwardingOptions(node *Node, fo *ForwardingOptionsConfig) error {
  func compilePortMirroring(node *Node, fo *ForwardingOptionsConfig) error {
  func compileSampling(node *Node, fo *ForwardingOptionsConfig) error {
  func compileSamplingFamily(node *Node) *SamplingFamily {
  func compileDHCPRelay(node *Node, fo *ForwardingOptionsConfig) error {
  func compileEventOptions(node *Node, policies *[]*EventPolicy) error {
  func compileBridgeDomains(node *Node, bds *[]*BridgeDomainConfig) error {
  ```

- **Proposed decomposition:**
  ```
  compiler_services.go remains as dispatcher (~120 LOC):
    - compileServices routing to sub-compilers
    - maybe keep AppID bool flag (trivial)

  New:
  compiler_services_rpm.go
    - parseRPMPositiveInt, parseRPMRootPositiveInt, validateRPMTest, validateRPMSourceAddressStrict, validateRPMLinkLocalZoneStrict, validateRPMHTTPGetSchemeStrict, validateRPMRoutingInstanceStrict, validateRPMProbePinsStrict, compileRPM
    - 9 funcs, ~350 LOC, fully standalone RPM domain (#1827 adjacent but independent)

  compiler_services_dhcp.go
    - compileDHCPLocalServer, mergeDHCPDynamicDNS, compileDHCPDynamicDNS, compileDHCPExpiredLeases, compileDHCPRelay
    - 5 funcs, ~600 LOC? Actually DHCP local-server 339-~465 ~126 LOC, DDNS 537-635 ~98 LOC, expired 635-699 ~64 LOC, relay 1554-1710 ~156 LOC = ~450 LOC + helpers. Alternative split DHCP further:
      - compiler_services_dhcp_local.go (local-server + DDNS + expired)
      - compiler_services_dhcp_relay.go (relay)

  Prompt suggests split to _rpm, _dhcp, _flow, _ip_monitoring, _event. Extend to _forwarding? Reasonable grouping:
    compiler_services_rpm.go           (5 validators + compileRPM + 2 parse helpers)
    compiler_services_dhcp.go          (local-server + dynamic-dns + expired + relay + merge)
    compiler_services_ip_monitoring.go (compileIPMonitoring + preferredRoutes + validateStrict + resolveNextHop)
    compiler_services_flow.go          (flow-monitoring + sampling + port-mirroring + sampling family) — flow + sampling share ForwardingOptionsConfig
    compiler_services_event.go         (event-options)
    compiler_services_bridge.go        (bridge-domains)
    compiler_services_dynamic_address.go (compileDynamicAddress) — actually security dynamic-address but historically housed here; could move to security addressbook compiler file as follow-up. For mechanical split, keep in _dynamic_address.go and note mis-housed.

  Seam: each compiler receives (node *Node, XxxConfig) and returns error; no cross-subsystem mutable state except svc.* and fo.*. compileServices ordering: flow-monitoring, rpm, ip-monitoring, app-id flag — order-independent except app-id flag read elsewhere; extraction preserves order.

  compileDynamicAddress currently reads security node but typed as services? Check its body: reads `security { dynamic-address { ... } }`? Actually grep shows `compileDynamicAddress(node *Node, sec *SecurityConfig)` called from elsewhere? Grep: only defined in services.go, not called from compileServices — so it is called from security compilation? Need to verify call sites to place file correctly. If called from security compiler, moving it to security file as follow-up is more correct, but for cold-path mechanical, keeping it in services_dynamic_address.go initial split is fine, then second PR moves to security.

  ```

- **Hot-path preservation:** A = safe, cold path, pure code-motion, go build/test byte-identical. Services compilation runs only on candidate commit. RPM validators pure predicate on cfg. DHCP compilers AST readers. No packet-path alloc.
- **Tests+gate:** `go build ./...` + `go test ./pkg/config/...` green; decl-NAME identical (compileServices stays, new per-domain remain private). RPM validation has 5 strict validators — they are called from uniformgates; moving them does not change registration order because uniformgates calls explicit funcs by name, not file location.
- **Why it matters:** Second-highest merge conflict file after system. RPM (5 validators), DHCP (relay + local-server), IP-monitoring (#1827) active areas each touch same file. Splitting to 5 domain files reduces contention 5x. Also aligns with prompt's ROI build-time + reviewability goal: services file appears in many CoS/flow/RPM/DHCP PRs.
- **Fix direction:** Ordered PRs:
  PR4 (?) — RPM extraction (lowest coupling, standalone tests for RPM pins).
  PR5 — IP-monitoring extraction (own package of 4 funcs, clear boundary).
  PR6 — DHCP local-server + relay extraction (two files or one).
  PR7 — flow/sampling/port-mirroring extraction (forwarding-options).
  PR8 — event + bridge-domains (tiny standalones).
  Could combine RPM + IP-monitoring + event + bridge into one PR as they are small + independent; DHCP + flow as second PR. Recommend 2 PRs for services.
- **Labels:** area/config, kind/refactor, cold-path, A-mechanical, RPM, DHCP, IP-monitoring, flow
- **Dedup note:** Unique. No prior PR split services (only strict validators out). Services compilation never split before.

---

### Finding 4: compiler_interfaces.go — 5 responsibilities, VRRP parser long

- **Title:** compileInterfaces 1290 LOC, VRRP group parser ~230 LOC + 2 AST validators + tunnel wireguard + MSS + dynamic-DNS in one file
- **Severity:** MEDIUM
- **Confidence:** HIGH
- **Refactor class:** A
- **Evidence:**
  file `pkg/config/compiler_interfaces.go:25` LOC ~535 (compileInterfaces)
  ```
  func compileInterfaces(node *Node, ifaces *InterfacesConfig) error {
      for _, child := range node.Children {
          if child.IsLeaf {
              continue
          }
          ifName := child.Name()
          ifc := &InterfaceConfig{
              Name:  ifName,
              Units: make(map[int]*InterfaceUnit),
          }

          // Check for description
          if descNode := child.FindChild("description"); descNode != nil {
              ifc.Description = nodeVal(descNode)
          }

          // Interface-level MTU
          if mtuNode := child.FindChild("mtu"); mtuNode != nil {
              if v := nodeVal(mtuNode); v != "" {
                  if n, err := strconv.Atoi(v); err == nil {
                      ifc.MTU = n
                  }
              }
          }

          // Speed and duplex (ether-options or gigether-options)
          ...
          // Check for vlan-tagging flag
          if child.FindChild("vlan-tagging") != nil {
              ifc.VlanTagging = true
          }
          // #4308 (fable-review-167 I-3): accepted-only interface-level parity
          // knobs — typed + compiled so they stop silently vanishing, with a
          // commit-time advisory (validateInterfaceParityWarnings) noting they
          // are not enforced yet.
  file `pkg/config/compiler_interfaces.go:694` LOC ~237 (parseVRRPGroups)
  ```
- **Proposed decomposition:**
  ```
  compiler_interfaces.go (dispatcher + physical props) — ~400 LOC
    - compileInterfaces loop (description, mtu, speed, duplex, bw, vlan-tagging, native-vlan, encap, LAG etc) + unit dispatch

  compiler_interfaces_unit.go — unit compilation (vlan-id, family inet/inet6, address, DHCP, etc) ~300 LOC extracted from inner loop of compileInterfaces where unitNode parsed.

  compiler_interfaces_tunnel.go — parseTunnelWireguard + parseTunnelWireguardPeer (~90 LOC) wired from unit type tunnel?

  compiler_interfaces_vrrp.go — parseVRRPGroups (big) + parseTrackCost + vrrpGroupIDKeys + vrrpAuthLeaf + selectMSSToken + parseMSSValue (MSS is per-unit but often co-located with VRRP in unit context) Actually MSS token/value belong to unit too — could stay in unit file.

  compiler_interfaces_vrrp_validate.go — validateVRRPTrackInterfaceAST, validateVRRPAuthenticationAST, checkVRRPGroupTrackShape, vrrpTrackConfigWarnings — 4 validators currently in compiler file but conceptually validation gates called from uniformgates? Check: validateVRRPTrackInterfaceAST used from validate_strict? Actually grep: called from uniformgates or earlystrict? Keep them together with VRRP compiler for locality.

  compiler_interfaces_ddns.go — compileInterfaceDynamicDNS — small ~70 LOC surfaceA binding.

  Seam: compileInterfaces currently calls parseVRRPGroups inline for each unit address node containing vrrp-group; extraction via helper `unit.AddVRRPGroup(group)` returns error. MSS parsing already helper.

  Cross-file note: firewallMatchValues used inside parseVRRPGroups for multi-leaf? Check if needed.
  ```

- **Hot-path preservation:** A safe cold path pure code-motion. No change to iface enumeration or VRRP group ID semantics.
- **Tests+gate:** `go build ./...` + `go test ./pkg/config/...` green; warning order unchanged.
- **Why it matters:** Medium build-time/review benefit — interfaces file touched by every physical-infrastructure PR (VLAN, VRRP, tunnel, wireguard). VRRP parser is long and active (priority-cost #5184, auth #4288, track-duplicates #1814). Extract reduces conflict between VRRP feature work and physical interface work.
- **Fix direction:** PR9 — VRRP extraction (parseVRRPGroups + validators). PR10 — unit + tunnel + DDNS split. Could be one PR if reviewer capacity high (two files small).
- **Labels:** area/config, kind/refactor, cold-path, A-mechanical, VRRP, interfaces
- **Dedup note:** No prior split; file never touched by #4405 (that's validate_strict). Unique.

---

### Finding 5: compiler_firewall.go + compiler_class_of_service.go — moderate resp count but cross-file helper coupling

- **Title:** Filter + CoS compilers each 1200+ LOC with shared helpers (firewallMatchValues, parseBandwidthLimit/Bps) used across 15+ files — extraction needs helper centralization first
- **Severity:** MEDIUM
- **Confidence:** MEDIUM
- **Refactor class:** A — but with shared-helper subtlety note
- **Evidence:**
  file `pkg/config/compiler_firewall.go:799` LOC ~36
  ```
  func firewallMatchValues(child *Node) []string {
      // #2419 SSOT: bracket / single-line list collapse for multi-value leaves.
      // A `multi: true` leaf in setSchema absorbs every trailing non-sibling
      // token onto its node key. Compiler MUST read Keys[1:] AND Children.
  ```
  file `pkg/config/compiler_protocols.go:1126` LOC ~120 (bandwidth parsing)
  ```
  func parseBandwidthBps(s string) uint64 {
  func parseBandwidthLimit(s string) uint64 {
  func parseBandwidthLimitStrict(s string) (uint64, error) {
  func parseBurstSizeLimit(s string) uint64 {
  func parseScaledDecimalUnit(s string) uint64 {
  func parseScaledDecimalUnitStrict(s string) (uint64, error) {
  func parseBurstSizeLimitStrict(s string) (uint64, error) {
  ```
  file `pkg/config/compiler_class_of_service.go:74` LOC ~380+ (CoS dispatcher)
  ```
  func compileClassOfService(node *Node, cos *ClassOfServiceConfig, opts compileOpts, warnings *[]string) error {
      if fcNode := node.FindChild("forwarding-classes"); fcNode != nil {
  ...
  cosSchedulersWithShapedBinding, coSInterfaceLineRateBytes, etc.

  Usage count: `grep -l firewallMatchValues pkg/config/compiler*.go` returns ~15 files (interfaces, firewall, system, applications? etc). Moving firewallMatchValues out of firewall.go would require keeping visibility same package but central file.
  ```

- **Proposed decomposition:**
  Shared-helper centralization first (PR0 for firewall+CoS+protocols):
  ```
  compiler_shared_helpers.go or compiler_match_values.go
    - firewallMatchValues (SSOT #2419)
  compiler_bandwidth.go
    - parseBandwidthBps, parseBandwidthLimit, parseBandwidthLimitStrict, parseBurstSizeLimit, parseScaledDecimalUnit*, parseBurstSizeLimitStrict

  Then CoS file can be split AFTER that (no circular dependency):
  compiler_class_of_service.go remains dispatcher (~150 LOC) calling:
  compiler_cos_forwarding_class.go — forwarding-classes (queue-num)
  compiler_cos_classifier.go — classifiers dscp/ieee-802.1/inet-precedence (collectCoSDSCPCodePoints, collectCoS8021CodePoints)
  compiler_cos_rewrite_rule.go — rewrite-rules dscp/ieee-802.1/inet-precedence/exp (collectCoSDSCPRewriteCodePoint etc)
  compiler_cos_scheduler.go — schedulers (transmit-rate, priority, buffer-size, surplus-sharing, equal-flow-enforcement, codel-target) + parseCoS*Rate
  compiler_cos_traffic_control_profile.go — traffic-control-profiles (shaping-rate, guaranteed-rate, delay-buffer-rate, scheduler-map) + resolveCoSTrafficControlProfiles + resolve helpers
  compiler_cos_interface.go — interfaces + units + parseCoSInterfaceUnitBody + applyCoSInterfaceLevelBindings + mergeCoSInterfaceLevelInto + etc
  compiler_cos_fairness.go — fairness rss-expectation interface/queue + collectCoSFairnessRSSExpectation + rss validation

  Firewall file split:
  compiler_firewall_policer.go — policer + three-color policer (existing small)
  compiler_firewall_filter.go — filter compilation (from/then) + firewallMatchValues already extracted, compileFilterFrom, compileFilterThen
  compiler_firewall_prefix_list.go — prefixFamily, firewallPrefixListFamilies, family collision + any-matches AST validators (currently in firewall.go as validate*AST but could move to validate_strict? Actually ASTM validators remain in firewall.go per early-strict phase, not uniformgates — note for move)
  ```

- **Hot-path preservation:** A safe cold path but shared helpers move requires careful byte-identical check — parseBandwidth* functions used from firewall (policer), CoS (shaping), interfaces (bandwidth). Move file does not change call sites (same package). firewallMatchValues move similar.
- **Tests+gate:** `go build ./...` + `go test ./pkg/config/...` green; CoS has many tests for oversubscription, classifier queue, shaping — ensure those still reference correct funcs (they are tests in package config, referencing internal funcs). Moving private funcs keeps same package visibility, so test compile still green. decl-NAME set identical (no exported names moved).
- **Why it matters:** CoS 1309 LOC / 23 funcs is large but domain-cohesive; splitting reduces review load for admission/DSCP/scheduler/queueing PRs which are frequent due to fairness regimes doc active work. Firewall 1237 LOC similarly but policer vs filter are distinct feature owners. However ROI lower than system/services/warn because CoS file changes less frequently than system leaf. Bandwidth helper centralization is pre-req for both.
- **Fix direction:** PR11 — extract bandwidth helpers + firewallMatchValues shared helpers to own files (2 files). PR12 — CoS split (6 files). PR13 — firewall split (3 files).
- **Labels:** area/config, kind/refactor, cold-path, A-mechanical, CoS, firewall, bandwidth-helper
- **Dedup note:** CoS already has per-domain split result on validation side (compiler_validate_strict_cos.go 462, compiler_validate_warn_cos.go 182) — those are DONE per #4405 analogue for CoS validation. Compilation side (compileClassOfService) never split — this finding targets compilation side, not validation side, so not dedup.

---

### Finding 6: compiler.go — compileOpts and tolerant entry point duplication

- **Title:** compileOpts ~1600 LOC of lenient flag doc + tolerant entry point duplication (CompileConfigLenient duplicate flag table, CompileConfigForNode / CompileConfigForNodeLenient duplicate flag tables)
- **Severity:** LOW-MEDIUM (not in top-3 but listed for completeness)
- **Confidence:** HIGH
- **Refactor class:** A
- **Evidence:**
  file `pkg/config/compiler.go:44` LOC ~1700 (compileOpts type + flags doc)
  ```
  type compileOpts struct {
      // #1830 (e): the former lenientEqualFlowWorkerCap flag (#1733) is
      // retired along with validateEqualFlowWorkerCapStrict — the
      // dataplane no longer caps equal-flow-enforcement at 32 workers, so
      // there is no severity to downgrade. The lenient compile entry
      // points remain for the flags below.

      // sanitizeFreeTextControlChars (#1798) downgrades the control-
      // character gate from a hard compile error to sanitize-in-place
      // plus a cfg.Warnings entry. ...
      sanitizeFreeTextControlChars bool
      lenientVRRPTrackDuplicates bool
      ...
      // ~70 bool flags, each 15-30 lines doc
  ```

  file `pkg/config/compiler.go:1727` LOC ~200 (CompileConfig + CompileConfigLenient duplicate flag map)
  ```
  func CompileConfig(tree *ConfigTree) (*Config, error) {
  func CompileConfigLenient(tree *ConfigTree) (*Config, error) {
      return compileConfigWithOpts(tree, compileOpts{
          lenientRoutingExportRef:                true,
          lenientFirewallFilterFamilyCollisions:  true,
          lenientFirewallFilterFamilyAnyMatches:  true,
          lenientFilterProtocols:                 true,
          ...
      })
  }
  func CompileConfigForNode(tree *ConfigTree, nodeID int) (*Config, error) {
  func CompileConfigForNodeLenient(tree *ConfigTree, nodeID int) (*Config, error) {
      return compileConfigForNodeWithOpts(tree, nodeID, compileOpts{
          lenientRoutingExportRef:                true,
          lenientFirewallFilterFamilyCollisions:  true,
          ...
  ```
  Duplicate flag table appears twice (CompileConfigLenient + CompileConfigForNodeLenient). Single source of truth via helper `func defaultLenientOpts() compileOpts` already exists? Check — should be extracted.

- **Proposed decomposition:**
  ```
  compiler_opts.go — compileOpts struct + all lenient flag doc + helper defaultLenientOpts() compileOpts that returns fully populated lenient opts. Both Lenient entry points call defaultLenientOpts(). Keeps flag truth in one place.
  compiler.go remains ~600 LOC — just entry points CompileConfig, CompileConfigWithOpts, CompileConfigForNode*, compileExpanded orchestrator.

  Seam: defaultLenientOpts() private helper, no behavior change.
  ```

- **Hot-path preservation:** A safe — flag bool struct only, no packet-path.
- **Tests+gate:** `go build ./...` + `go test ./pkg/config/...` green; no exported decl change.
- **Why it matters:** Reviewability: 1600 lines of flag doc drowns the ~400 LOC of actual compilation phases P1-P7 that reviewer needs to see when checking phase ordering invariants #5/#6/#7. Moving opts to own file leaves compiler.go focused on orchestration. Build-time tiny win. Also prevents lenient flag duplication drift (two flag tables must stay identical — already had risk).
- **Fix direction:** PR0 — earliest, because it shrinks compiler.go making subsequent PRs for phases easier to review. Could merge with finding 2/3.
- **Labels:** area/config, kind/refactor, cold-path, A-mechanical, opts
- **Dedup note:** Unique — compileOpts was never split.

---

### Finding 7 (NEGATIVE): compiler_uniformgates.go — already #4406 split result

- **Status:** D — Do NOT re-split
- **Rationale:** File IS the split result of #4406 step 4 (P6b uniform fail-open gates). It is a 1832-LOC orchestrator with single func `runUniformGates` that PRESERVES invariants #6 (strict first-error slot) + #7 (tolerant-path warning order) by listing validators in deterministic source order. Its purpose is to make first-error slot and warning order VISIBLE in one place. Splitting it into per-domain gate files would defeat its purpose — you'd lose the ability to audit order in one view. Each individual validator already lives in its per-domain file (validate_strict_policy.go, validate_strict_nat.go, etc). The orchestrator should stay as-is; only add new validators to it.
- **Sound/Why negative:** If you split runUniformGates per-domain (e.g. _policy_gates.go _nat_gates.go each calling subset), the strict first-error slot (which validator wins the race) becomes implicit across files, impossible to audit. The single-file list is invariant enforcement. #4406 deliberately kept it monolithic.
- **Recommended action:** No action. When new validator added, append to list IN ORDER for warning order; document nearby existing validators. Revisit only if >3000 LOC (actual 1832 stable).
- **LOC evidence:** 1832 LOC, 1 func, called from compileExpanded (P6b) only. 75 independent validators, no cfg mutation.

### Finding 8 (NEGATIVE): compiler_validate_strict_filter.go — already per-domain

- **Status:** D — Do NOT re-split
- **Rationale:** 1811 LOC / 30 funcs is large, but it IS the per-domain file for filter validation post-#4405 (compiler_validate_strict.go 6997 → 12 files). Its 9 responsibilities are all inside ONE domain (firewall filter validation). Further sub-split would cut inside one issue's domain with high risk of merge conflict because fable filter work (F-1, F-2, F-3a, fable-review-161 F-030 etc noted in src comments referencing filter validation gates) is active. Split after fable quiesces, not now.
- **Sound/Why negative:** Deeper split would create compiler_validate_strict_filter_{policer,protocol,dscp,address,port,match,cross_field,...}.go with very small files (some <100 LOC) and frequent cross-file moves when new filter match field added. The current 9 validators share helpers firstIncompatibleProtocol, classifyFilterAddrFamily, filterDSCPResolvable (SSOT), filterProtocolResolvable, protocolIsPortBearing, protocolIsTCP, protocolIsICMPFamily — splitting would scatter these helpers across 9 files or require central helper file, adding churn.
- **Recommended action:** No action at this stage. Track in backlog for after fable filter feature freeze. If further split desired, do it as follow-up to #4421 (firewall-filter validation rules.go 3 domains) rather than independent.
- **LOC evidence:** 1811 at SHA — stable size, 30 funcs, all filter-domain.

### Finding 9 (NEGATIVE): types_system.go — 64 type defs but tracking-issue low priority

- **Status:** D — Low priority / tracking issue
- **Rationale:** File 1585 LOC / 15 methods / 64 types touches 20+ consumers (daemon, frr, networkd, snmp, logging, dhcprelay, sampling, rpm, scheduler, arch...). Any file move within package config PRESERVES package visibility (same package), so consumer break is NOT cross-package — but type grouping moves still require reviewing 64 type defs for accidental field reordering or json/yaml tag loss. The logic methods (MarshalJSON for SNMPCommunity, MarshalYAML, ValidLoginClasses, mapJunosPermissions, RPM effective accessors IsScoped/EffectiveProbeType/Interval/Count/etc, DHCPLocalServerConfig String) are 15 funcs that could move to behavior files first as increment.
- **Sound/Why negative low priority:** ROI lower than compiler splits — type definitions rarely cause merge conflicts (append-only, fields added but rarely modified). Compiler files cause conflicts on every commit spanning multiple domains because they share single-file switch over case statements. Type file split would be file-local rename only, but review cost high for low conflict reduction. Tracking issue preferred to postpone until compiler decomposition complete.
- **Recommended incremental first step (when prioritized):** Extract behavior not data:
  ```
  types_system_snmp.go — SNMPConfig MarshalJSON/YAML + SNMPCommunity MarshalJSON/YAML + SNMPTrapGroup helpers
  types_system_login.go — ValidLoginClasses + mapJunosPermissions
  types_system_rpm.go — RPMTest.IsScoped + Effective* accessors
  types_system_dhcp.go — DHCPLocalServer removal? Actually DHCPServerConfig String etc
  types_system.go remains pure struct bag after.
  ```
  Then optionally split struct bag by domain (login, snmp, dhcp, services, firewall, forwarding-options, etc) — but only after behavior extraction proven byte-identical.
- **LOC evidence:** 1585 LOC, 64 types defined, 15 funcs. Touches pkg/daemon (syslog, SNMP), pkg/frr (routing), pkg/networkd (interface), pkg/snmp, pkg/logging, pkg/dhcprelay, etc via Config fields, but since package is config, cross-package break does NOT happen on file move — only same-package decl order change.
- **Why it matters despite D:** For completeness — file IS broad and listed in prompt as potential target. But tracking issue low priority because compilers are bigger ROI for build-time + review-time + merge conflicts.
- **Labels:** area/config, kind/refactor, tracking-issue, low-priority, types

---

## 4. Summary Required Artifacts

### File-size/shape inventory with LOC + #func + responsibility count

See §1 table. Largest ROI files for mechanical cold-path refactor:

| Priority | File | LOC | Resps | Merge-conflict density at this SHA |
|----------|-----:|---:|---|---|
| P0 (strongest) | compiler_validate_warn.go | 1682 | ~22 | VERY HIGH — every warning touches same func |
| P0 | compiler_system.go | 2115 | 8+ | VERY HIGH — system leaf touches every infra PR (login/SNMP/syslog/chassis) |
| P0 | compiler_services.go | 1841 | 8 | HIGH — RPM/DHCP/IP-monitor/flow active |
| P1 | compiler.go | 2323 | 4 | MEDIUM-HIGH — opts duplication + phase orchestration contested by #4406 continuations |
| P1 | compiler_interfaces.go | 1290 | 5 | MEDIUM — VRRP active |
| P2 | compiler_class_of_service.go | 1309 | 6 | MEDIUM — CoS fairness regime active |
| P2 | compiler_firewall.go | 1237 | 4 | MEDIUM — policer vs filter owners distinct |
| D (no split) | compiler_uniformgates.go | 1832 | 1 orch | N/A — keep as invariant preserver |
| D (no split) | compiler_validate_strict_filter.go | 1811 | 9 | N/A — already per-domain split result, active fable |
| D (tracking) | types_system.go | 1585 | ~15 | LOW — type bag |

### File-by-file log (what checked + sound/why) — full list

Covered in §2 for each file: what sections read, what cross-file helpers observed (natAddrFamily textual classification matching Rust parsers, firewallMatchValues #2419 SSOT used in ~15 files, parseBandwidth* used across 4 files, compileOpts ~70 flags duplication, etc), and why cold-path mechanical.

### Findings summary cross-ref

- Finding 1 (HIGH): compiler_validate_warn.go monolith → split to _policy, _nat, _addressbook, _zones_interfaces, _system_* (per-domain warner functions). Matches prompt: "compiler_validate_warn.go never followed strict split pattern." Strongly aligns with #4405 closed where strict followed pattern but warn never.
- Finding 2 (HIGH): compiler_system.go 8 subsystems → new files _login, _snmp, _chassis, _ddns, _userspace, _syslog, _leaf, _scheduler per prompt "compiler_system 8 subsystems". Highest collision ROI.
- Finding 3 (HIGH): compiler_services.go 8 resps (5 RPM validators, DHCP local-server/DDNS/expired-leases/relay, IP-monitoring/overlay, flow-monitoring/sampling per-collector v9/ipfix/template/source, port-mirroring, event-options, bridge-domains) → _rpm, _dhcp (local + relay), _flow, _ip_monitoring, _event, _bridge, _dynamic_address per prompt.
- Finding 4 (MEDIUM): compiler_interfaces.go 5 resps → VRRP extraction + unit/tunnel/DDNS.
- Finding 5 (MEDIUM): CoS + firewall + protocols share helpers (firewallMatchValues #2419 SSOT, parseBandwidth*) — centralization pre-req then CoS 6-way + firewall 3-way split.
- Finding 6 (LOW-MEDIUM): compiler.go compileOpts + lenient flag duplication → extract to compiler_opts.go with defaultLenientOpts() helper, preserving phase-orchestrator focus on P1-P7 invariants #5/#6/#7.
- Finding 7-9 (D negatives): compiler_uniformgates (already #4406 split result orchestrator preserves #6/#7) + compiler_validate_strict_filter (already per-domain) + types_system (64 types but touches 20+ consumers — tracking issue low priority) per required negatives.

### Labels overall

`area/config` `kind/refactor` `cold-path` `A-mechanical` `high-collision` (system, services, warn) `low-risk` (per #4144 discipline) `blocks-merge-conflict-reduction`

### Dedup note

No duplicate of #4405 (validate_strict 6997 → 12 files CLOSED pure code-motion) — this audit builds on top of that closed PR; warn side never followed strict pattern (gap explicitly called out in task prompt). #4406 compiler_uniformgates orchestrator + filter already per-domain split results — D per prompt, not re-split. #4421 compiler_security.go too broad, firewall-filter validation, rules.go 3 domains — out-of-scope for this A3 but referenced as adjacent future work. NAT helpers used in 3+ files (natAddrFamily spans files) — noted shared-helper subtlety for any split to preserve textual classification semantics (colon==v6) matching Rust parser.

### Fix direction (ordered PRs)

```
PR0  — compiler_opts.go (defaultLenientOpts) + bandwidth helpers centralization + firewallMatchValues move
       Low risk, shrinks two biggest files' unrelated content, enables later PRs.
       Gate: go build ./... + go test ./pkg/config/... green, decl-NAME identical.

PR1  — compiler_validate_warn.go split (policy, nat, addressbook, zones_interfaces, system_* sub-splits)
       Highest ROI (22-resp -> 6-8 domain files), mirrors #4405 strict split pattern.
       Gate: go test ./pkg/config/... green, warning order preserved.

PR2  — compiler_system.go split part 1: login + DDNS + SNMP (3 files, low coupling)
PR3  — compiler_system.go split part 2: syslog + dataplane/shared-UMEM + schedulers + leaf + chassis (3-4 files)
       Gate per PR: go build/test green, decl-NAME set identical.

PR4  — compiler_services.go split part 1: RPM + IP-monitoring + event + bridge-domains (4 small files)
PR5  — compiler_services.go split part 2: DHCP local + relay + flow/sampling/port-mirroring (2-3 files)

PR6  — compiler_interfaces.go split: VRRP (parser + validators) + unit + tunnel + DDNS
PR7  — CoS split (6 files) + firewall split (3 files) after PR0 helpers.

PR8+ — follow-on: types_system behavior extraction (SNMP MarshalJSON, login permission map, RPM effective) then struct bag split (tracking issue).
```

All PRs discipline per #4144: pure code-motion, go build ./... + go test ./pkg/config/... green, decl-NAME set identical (for types, struct field order preserved; for warn/system/services/interfaces, func visibility same package so tests compile). Hot-path preservation: A = safe, cold path, per-packet BPF/Rust dataplane untouched, only gRPC commit-path compilers moved.

---

## 5. Verifier Checklist (per task required)

- Worktree: /tmp/review-wt-ps-043-a3-b1/ (detached HEAD 4e0c7f74c) — all reads via worktree absolute paths — DONE.
- Output: /tmp/review-work-ps-043/ps-a3-b1.md only — NEVER /tmp/ps-review-043*.md — DONE.
- File-size/shape inventory with LOC + #func + responsibility count — §1 DONE.
- File-by-file log (what checked + sound/why) — §2 DONE.
- Findings with required fields: Title, Severity, Confidence, Refactor class (A), Evidence (file:line + LOC + quoted 5-10 lines), Proposed decomposition (concrete new file names + what moves + seam), Hot-path preservation (A safe cold pure code-motion per #4144), Tests+gate, Why it matters, Fix direction ordered PRs, Labels, Dedup note — §3 DONE for 9 findings (6 positive + 3 D negatives).
- Include (D) negatives for compiler_uniformgates, compiler_validate_strict_filter, types_system — DONE as findings 7/8/9.
- Cleanup: git worktree remove /tmp/review-wt-ps-043-a3-b1 at end of script — TODO post-write.

---

## 6. Appendix: NAT helper cross-file subtlety detailed

natAddrFamily / natCIDRIPPart / isHostMaskAddress in compiler_nat_helpers.go are textual family classifiers matching Rust parser semantics (colon == v6), not net.ParseIP / net.ParseCIDR. Purpose: preserve original config text classification so IPv4-mapped IPv6 etc handled same as userspace-dp. This idiom appears in static NAT host-mask validation (validateNATHostMaskStrict hostMask check needs /32 or /128), NAT64 pool host-address check (isNAT64PoolHostAddress), NPTv6 strict, NAT64 prefix strict, etc. Splitting helpers across files must keep all three together, never separate natAddrFamily from isHostMaskAddress.

Also: appendPoolAddresses + expandAddressRange handle `<low> to <high>` range expansion for source-NAT pools — used from compiler_nat_source.go and tested in compiler_nat_source_pool_address_4521_test.go. forEachChild helper in compiler_nat_dnat_to.go is small iteration helper for DNAT to-scope.

Seam recommendation: keep compiler_nat_helpers.go as shared, move only domain-specific compile logic (source, dest, static, mixed, dnat_to) to own files, not helpers.

---

End of A3 audit.


---
### Batch ps-a4-b1.md — 44332 chars

# A4 — Go dataplane + daemon + cluster + routing + metrics + API — Refactor/Modularity Audit
Base SHA: 4e0c7f74cf0dbacf83051b2a9b6cf4e050dcecaa
Worktree: /tmp/review-wt-ps-043-a4-b1
Date: 2026-07-11
Auditor: ps, NNN 043
Engineering-style: read via worktree docs/engineering-style.md

## File Size / Shape Inventory

| File | LOC | Threshold | #type / #func | Smell |
|------|-----|-----------|---------------|-------|
| `pkg/dataplane/userspace/protocol.go` | 3064 | 500 | 78 types / 2 funcs | **CRITICAL**: 12 wire domains in 1 file (ControlRequest + ConfigSnapshot ~20 subtypes + ProcessStatus ~40 subtypes + BindingStatus/CoSQueueStatus/WgTunnelStatus + NAT 4 flavors + Policy + Filter + SessionSync + HA + EventStream + 7 protocols). Rust side already split into 7 files: `binding.rs` 1185, `control.rs` 1088, `cos.rs` 494, `nat.rs` 400, `security.rs` 592, `snapshot.rs` 829, `resolution.rs` 105. Go side is inverse: 1 Go file, 7 Rust files. Single reason-to-change violated per domain. |
| `pkg/vrrp/instance.go` | 2417 | 500 | 3 types / 64 funcs | 52 funcs covering VRRP SM: state + RX + TX + GARP + advert-interval + preempt-hold + VIP reconcile. Large but **D-negative candidate**: single coherent RFC 5798 SM. |
| `pkg/daemon/daemon_run.go` | 2492 | 500 | ~5 types / 19 funcs | Lifecycle bootstrap + naming + run-loop + exit. Run() ~1690 LOC god ordering-sensitive. **Already filed #4662** — do NOT re-report same shape unless new angle. Already incrementally split into leaves: `runShutdownSequence`, `startGRPCServer`, `startHTTPServer`, `initManagers`, `loadAndBootstrapConfig`, `setupInterfaceNaming`, `setupDataplaneAndInitialConfig`. |
| `pkg/frr/policy_render.go` | 2309 | 500 | 4 types / 38 funcs | FRR policy rendering: prefix-list + route-map + community + as-path + filter coupling. Review cost high, but single downstream format. |
| `pkg/daemon/daemon_apply.go` | 2265 | 500 | ~6 types / 37 funcs | `applyConfigLocked` 1148 LOC god-func (per prior prompt). 20+ ordered phases: networkd, frr, nft, dataplane, HA, dhcp, lldp, event-engine, etc. Ordering-sensitive between phases. Distinct from #4662 Run() — this is commit path vs boot path, but similar extraction strategy applies. |
| `pkg/api/metrics_descriptors.go` | 2067 | 400 | 0 types / 1 func | **291 `prometheus.NewDesc` calls in one func** `newCollector`. 7 subsystems: global, sessions, nat, policy, filter, host-inbound, CoS/buffers. #1 merge-conflict file. |
| `pkg/routing/tunnel.go` | 2016 | 500 | 6 types / 37 funcs | 5 responsibilities: tunnel lifecycle (GRE anchor + kernel + WG) + keepalive + MTU + VRF + address reconcile. Keepalive Axis D: `keepaliveTick` lock-free (`linkGen` atomic, never takes `t.mu`) vs `Apply` holds `mu` across netlink. Hard to verify interleaving. |
| `pkg/cluster/sync_conn.go` | 1858 | 500 | ~8 types / 55 funcs | 8 responsibilities: gen-guard + fabric dial + bulk + sweep + delete-journal + config-sync + failover/barrier + liveness. Ordering-sensitive gen-guard state machine: stamp→queue→take, bulk reset #2995, fabric preference, #2198 F3 non-atomicity note, single-active-fabric invariant. |
| `pkg/api/metrics_userspace.go` | 1865 | 500 | 0 types / 41 funcs | Counter bridge collection: global-zone-policy-filter-hostInbound-slowpath-buffers. Large but largely fan-out readers, less ordering risk than descriptors. |
| `pkg/dataplane/userspace/maps_sync.go` | 1763 | 500 | 7 types / 36 funcs | Focused single domain: userspace ctrl value + binding ready gate + ebpf map sync. **D-negative**: single coherent domain despite LOC. |
| `pkg/dataplane/compiler.go` | 1808 | 500 | 2 types / 37 funcs | Config→snapshot compiler, multi-domain but single pass. Borderline but single responsibility (build ConfigSnapshot). Could split by domain like protocol.go. |
| `pkg/dataplane/userspace/format/cos_sections.go` | 632 | 400 | — | New split from #4661. Moderate size, single domain (CoS CLI formatting). Acceptable. |
| `pkg/dataplane/userspace/format/status_sections.go` | 703 | 400 | — | New split from #4661. Status formatting. Same note. |
| `pkg/dataplane/userspace/format/buffers.go` | 160 | 400 | — | Shared row model CLI/gRPC/REST buffer-status parity per #4661. |
| `pkg/grpcapi/server_diag.go` | 77 | 400 | — | Small leaf — OK. |
| `pkg/grpcapi/server_monitor.go` | ~600 est | 400 | — | Monitor RPCs composite but acceptable. |
| `pkg/grpcapi/server_ping.go` | ~300 est | 400 | — | OK. |
| `pkg/grpcapi/server_system_action.go` | ~400 est | 400 | — | OK. |
| `pkg/grpcapi/server_zeroize.go` | ~300 est | 400 | — | OK. |
| `pkg/snmp/agent.go` | 2143 | 500 | 5 types / 74 funcs | ifTable MIB + SNMP agent: registration + walk + typed leaf. Monolithic but single RFC domain. |
| `pkg/daemon/daemon_ha.go` | 1576 | 500 | — | HA reconcile steps, VRRP demotion, RG state propagation. 2nd god file alongside daemon_apply. |
| `pkg/daemon/daemon_nft.go` | 1782 | 500 | — | nftables host-inbound chain management: sets + rules + family separation. Single technology domain. |
| `pkg/dataplane/userspace/manager_ha.go` | 1643 | 500 | — | HA integration into userspace manager: config sync, barrier, RG callbacks. Mixed but bounded to HA axis. |
| `pkg/daemon/compiler_iface.go` | 1394 | 400 | — | Interface renaming + link + networkd compile. 2 phases but logical grouping. |
| `pkg/routing/rules.go` | 1447 | 400 | — | 3 domains per #4421: PBR rules + firewall filter rules + routing policy? Separate due to single nftables + FRR cross. |

Threshold rationale: 400 LOC for pure wire/format/codegen, 500 LOC for state machines / managers with locking invariants, per engineering-style "narrow scope".

---

## Findings

### FINDING-1: protocol.go — 78 types 12 domains in single file, Rust split template exists

**Title:** `protocol.go` wire-format monolith — Go has 1 file, Rust has 7; merge-conflict magnet with 12 independent change reasons

**Severity:** High
**Confidence:** 95%
**Refactor class:** A — mechanical safe for cold path (pure type code-motion, no ordering, cold path json wire, no per-packet)

**Evidence:**

- `pkg/dataplane/userspace/protocol.go:29` — LOC 3064, 78 types, 2 funcs
```go
type ControlRequest struct {
	Type               string                    `json:"type"`
	SuppressStatus     bool                      `json:"suppress_status,omitempty"`
	Snapshot           *ConfigSnapshot           `json:"snapshot,omitempty"`
	Forwarding         *ForwardingControlRequest `json:"forwarding,omitempty"`
	HAState            *HAStateUpdateRequest     `json:"ha_state,omitempty"`
	Queue              *QueueControlRequest      `json:"queue,omitempty"`
	Binding            *BindingControlRequest    `json:"binding,omitempty"`
	Packet             *InjectPacketRequest      `json:"packet,omitempty"`
	SessionSync        *SessionSyncRequest       `json:"session_sync,omitempty"`
	SessionDeltas      *SessionDeltaDrainRequest `json:"session_deltas,omitempty"`
	SessionExport      *SessionExportRequest     `json:"session_export,omitempty"`
	Neighbors          []NeighborSnapshot        `json:"neighbors,omitempty"`
	NeighborGeneration uint64                    `json:"neighbor_generation,omitempty"`
	NeighborReplace    bool                      `json:"neighbor_replace,omitempty"`
	Fabrics            []FabricSnapshot          `json:"fabrics,omitempty"`
}
```

- `pkg/dataplane/userspace/protocol.go:54` — ConfigSnapshot carries ~25 top-level fields + unexported `zoneIDCollisions` (manager-facing, not wire) mixing wire + local concerns
```go
type ConfigSnapshot struct {
	Version         int                      `json:"version"`
	Generation      uint64                   `json:"generation"`
	FIBGeneration   uint32                   `json:"fib_generation,omitempty"`
	Zones           []ZoneSnapshot           `json:"zones,omitempty"`
	Interfaces      []InterfaceSnapshot      `json:"interfaces,omitempty"`
	Fabrics         []FabricSnapshot         `json:"fabrics,omitempty"`
	TunnelEndpoints []TunnelEndpointSnapshot `json:"tunnel_endpoints,omitempty"`
	// ... 20 more including DefaultLogSessionInit #3534, SYNCookieMasterKey, etc
	zoneIDCollisions []ZoneIDCollision // unexported, not wire but lives in same file as wire
}
```

- `pkg/dataplane/userspace/protocol.go:531,632,680,816,860` — NAT 4 flavors consecutive: SourceNATRuleSnapshot, StaticNATRuleSnapshot, DestinationNATRuleSnapshot, NAT64RuleSnapshot, Nptv6RuleSnapshot — each independent change reason (SNAT pool vs DNAT hit counters vs NAT64 prefix handling)

- `pkg/dataplane/userspace/protocol.go:1358` — ProcessStatus carries ~40 subtypes spanning all domains:
```go
type ProcessStatus struct {
  // ... 30+ fields from worker runtime to NAT pool counts to CoS queues
}
```
Types at `pkg/dataplane/userspace/protocol.go:1734:WgPeerStatus`, `1752:WgTunnelStatus`, `1888:SourceNATPoolStatus`, `1931:CoSInterfaceStatus`, `1973:CoSQueueStatus`, `2112:FirewallFilterTermCounterStatus`, `2166:HAStateUpdateRequest`, `2294:HAGroupStatus`, etc — 7 Rust files map 1:1.

- Rust counterpart enumeration:
```
userspace-dp/src/binding.rs 1185 LOC — BindingStatus/Ready/Snapshot
userspace-dp/src/control.rs 1088 — ControlRequest/Response envelope
userspace-dp/src/cos.rs 494 — CoS forward-class, classifier, scheduler
userspace-dp/src/nat.rs 400 — NAT pool + counters wire types
userspace-dp/src/security.rs 592 — Policy, Screen, Filter, Zone status
userspace-dp/src/snapshot.rs 829 — ConfigSnapshot + Zone/Interface/Route/Fabric
userspace-dp/src/resolution.rs 105 — PacketResolution + neighbor
```
Syndrome: bug fix adding one NAT field touches same file as unrelated CoS field => conflict.

**Proposed decomposition:**

- `protocol_control.go` — `ControlRequest`, `ControlResponse`, `ForwardingControlRequest`, `QueueControlRequest`, `BindingControlRequest`, `InjectPacketRequest`, `SessionDeltaDrainRequest`, `SessionExportRequest`, `SessionSyncRequest`, `SessionDeltaInfo`, `HAStateUpdateRequest`, `EventStreamStatus`
- `protocol_snapshot.go` — `ConfigSnapshot` (wire part only), `SnapshotSummary`, `UserspaceCapabilities`, `UserspaceMapPins`, `ZoneSnapshot`, `InterfaceSnapshot`, `InterfaceAddressSnapshot`, `FabricSnapshot`, `TunnelEndpointSnapshot`, `TunnelWgPeerWire`, `RouteSnapshot`, `NeighborSnapshot`, `AddressBookSnapshot`, `FlowSnapshot`
- `protocol_nat.go` — `NatPortRangeWire`, `NatAppTermWire`, `SourceNATRuleSnapshot`, `StaticNATRuleSnapshot`, `DestinationNATRuleSnapshot`, `NAT64RuleSnapshot`, `Nptv6RuleSnapshot`, `SourceNATPoolStatus`, `NATRuleCounterStatus`
- `protocol_security.go` — `ScreenProfileSnapshot`, `FirewallFilterSnapshot`, `FirewallTermSnapshot`, `FlexMatchSnapshot`, `PolicerSnapshot`, `ThreeColorPolicerSnapshot`, `PolicyApplicationSnapshot`, `AppCatalogEntrySnapshot`, `PolicyRuleSnapshot`, `FlowExportSnapshot`, `MirrorConfigSnapshot`, `ZoneTrafficCounterStatus`, `PolicyRuleCounterStatus`, `FirewallFilterTermCounterStatus`
- `protocol_cos.go` — `ClassOfServiceSnapshot`, `CoSForwardingClassSnapshot`, `CoSDSCPClassifierSnapshot`, `CoSIEEE8021ClassifierSnapshot`, `CoSSchedulerSnapshot`, `CoSSchedulerMapSnapshot`, `CoSInterfaceStatus`, `CoSQueueStatus`, `CoSActiveFlowCountStatus`, `ThreeColorPolicerStatus`
- `protocol_status.go` — `ProcessStatus`, `WorkerRuntimeStatus`, `WgTunnelStatus`, `WgPeerStatus`, `BindingStatus`, `QueueStatus`, `BindingCountersSnapshot`, `SlowPathStatus`, `FlowTupleStatus`, `FlowWorkerStatus`, `PacketResolution`, `HAGroupStatus`, `ExceptionStatus`, `SourceNATPoolStatus`
- `protocol_internal.go` (or `snapshot_internal.go`) — unexported `zoneIDCollisions`, `ZoneIDCollision` + any non-wire helpers currently mixed in — separates manager-facing diagnostic from wire.

Wire compatibility gate: `json` tags unchanged, `go vet` + `go test ./pkg/dataplane/userspace -run TestProtocol` passes. Add `protocol_split_test.go` asserting old JSON decodes from new split set equals old (golden files from Rust `snapshot.rs` serde).

**Hot-path preservation:**

- Cold path only: control socket (1/s poll + commit). Not per-packet.
- Pure code-motion: move type decls verbatim, no field reorder, no tag change, no method extraction that changes json visibility.
- Unexported field `zoneIDCollisions` intentionally stays unexported so current hash behavior (JSON ignores unexported) unchanged.

**Tests+gate:**

- Unit: `make test-go` — `protocol_test.go`, `snapshot` builder tests, `control_test.go` must pass.
- Build: `make build-userspace-dp` — Rust serde derives must still decode Go JSON (additive `omitempty`/`#[serde(default)]` contract from #1960, #3082, #3534).
- Deploy: `make test-deploy` — `show system overview` + config commit with NAT, CoS, policy, zone-address-book all in one config to exercise every domain.
- Gate: CI `TestDaemonRuntimeEntryPointUsesRuntimeDataPlane` unaffected.

**Why it matters:**

- Build time: single file invalidates every package importing userspace (virtually all daemon) on any NAT vs CoS change — split gives incremental cache granularity per domain.
- Review: reviewer adding `default-policy-log` (#3534) had to wade past 3000 LOC of unrelated binding counters. Rust reviewers already complained #4661.
- Correctness: mixing wire + internal (`zoneIDCollisions`) invites accidental json tag addition that perturbs snapshot hash or wire — separate file enforces boundary.

**Fix direction (ordered PRs):**

- PR-1 (this finding): split into 7 files matching Rust template, verbatim move, no logic. Smallest risk, unlocks parallel work.
- PR-2+: extract per-domain validation helpers (e.g., CoS scheduler map sanity) co-located with their snapshot files, currently buried in `pkg/dataplane/compiler.go`.

**Labels:** `refactor`, `modularity`, `A-mechanical-safe-cold-path`, `wire-format`, `merge-conflict`, `area:dataplane-userspace`

**Dedup note:** Not duplicate of #4407 (daemon god-struct) nor #4661 (format/buffers row model). #4661 introduced `cos_sections.go`/`status_sections.go` for formatting, not wire types — this is the wire counterpart. Complementary.

---

### FINDING-2: `cluster/sync_conn.go` — gen-guard state machine ordering-sensitive 8-responsibility monolith

**Title:** Session sync connection gen-guard ordering-critical file mixing 8 concerns — stamp→queue→take, bulk reset #2995, fabric preference, single-active-fabric #2198 F3

**Severity:** Critical
**Confidence:** 90%
**Refactor class:** B — ordering-sensitive for gen-guard (stamp→queue→take invariant, bulk barrier, fabric preference, single-active-fabric, #2198 F3 non-atomicity) — NOT safe for blind mechanical split without ordering audit

**Evidence:**

- `pkg/cluster/sync_conn.go:30-45` — file preamble, 1858 LOC, 55 funcs, cap constant + safety narrative:
```go
// genGuardMapCap bounds the sender-side echo maps and the receiver-side
// stored-generation maps so a churning workload cannot grow them without
// limit. Both are evicted on delete; the cap is a safety valve for keys whose
// delete never arrives (e.g. dropped close delta). It matches the delete
// journal cap order-of-magnitude.
//
// Overflow handling (#2198 F1): when a map is at cap, a NEW key is NOT
// recorded (skip-record-on-full) and an EXISTING key is updated in place. The
// map is NEVER cleared. Clearing the whole map would drop the stored
// generation of every live key, disabling the guard cluster-wide for a churn
// window — exactly the #2170 hazard the guard exists to close...
const genGuardMapCap = 200000
```

- `pkg/cluster/sync_conn.go:47-63` — `putGenBounded` generic bounded-map primitive used by both sender and receiver sides, lock protocol caller-holds-mutex:
```go
func putGenBounded[K comparable](m map[K]uint64, key K, gen uint64) bool {
	if _, exists := m[key]; exists {
		m[key] = gen
		return true
	}
	if len(m) >= genGuardMapCap {
		return false
	}
	m[key] = gen
	return true
}
```

- `pkg/cluster/sync_conn.go:71-100` — stamp side (sender), mutates `val.Generation` in place + records bounded, comment notes re-send intentional bump:
```go
// stampInstallGenV4 assigns a fresh install generation to a v4 session being
// exact generation of the install it cancels (#2170 SMR fix #1). It mutates
// val.Generation in place. A re-send (sweep/bulk) of a live key intentionally
// bumps the generation: the per-key stored generation only ever climbs, so a
func (s *SessionSync) stampInstallGenV4(key dataplane.SessionKey, val *dataplane.SessionValue) {
	s.genSentMu.Lock()
	if s.genSentV4 == nil {
		s.genSentV4 = make(map[dataplane.SessionKey]uint64)
	}
	if !putGenBounded(s.genSentV4, key, g) {
```

- `pkg/cluster/sync_conn.go:103-142` — take side with fresh generation #2221 (not echo), evicts sender stamp, note about non-atomic stamp and queue:
```go
// takeDeleteGenV4 returns the generation a delete for this wire key should
// carry and evicts the sender-side stamp.
// #2221: the delete draws a FRESH, strictly-greater generation
// (nextInstallGen) rather than echoing the install's stamp. The stamp and the
// sendCh enqueue are not atomic and two producer goroutines (the sweep
// stamping a live re-send, the delta-drain taking the close) mutate the same
// key, so a delete can be enqueued onto sendCh BEFORE the install it cancels.
func (s *SessionSync) takeDeleteGenV4(key dataplane.SessionKey) uint64 {
	s.genSentMu.Lock()
	defer s.genSentMu.Unlock()
	if _, ok := s.genSentV4[key]; !ok {
```

- `pkg/cluster/sync_conn.go:147-240` — guard side receiver with tombstone upgrade #2221, per-key monotonic climb #2170 fix #2.

- `pkg/cluster/sync_conn.go:271-300` — bulk reset #2198 F2 + #3931 config gen reset:
```go
// resetRecvGen clears the receiver-side stored-generation maps. It is called
// when the peer begins a fresh bulk transfer (#2198 F2): a reconnecting peer
// may have REBOOTED, which legitimately restarts its sender genCounter (it is
// seeded from CLOCK_MONOTONIC nanos, which resets at OS boot). Its bulk
// re-prime then carries generations that may be LOWER than the generations we
// stored from its previous boot...
func (s *SessionSync) resetRecvGen() {
	// #3931: also reset the last-applied config generation...
```

- `pkg/cluster/sync_conn.go:304-325` — **#2198 F3 non-atomicity note — the core ordering invariant for split:**
```go
// Non-atomicity note (#2198 F3): the apply sequence — guard check
// — does NOT hold recvGenMu across the whole sequence; the mutex is taken
// serially within one receiveLoop goroutine over the single ACTIVE fabric
// which is not worth it for a race that the single-active-fabric invariant
//...
func (s *SessionSync) installClusterSyncedV4(key dataplane.SessionKey, val dataplane.SessionValue) {
```

- `pkg/cluster/sync_conn.go:399` — fabric dial preference `shouldInitiateFabricDial` intermingled with session logic — fabric hash tie-breaker vs session gen-guard are independent failure domains but share file.

**Proposed decomposition (ordering-safe):**

- `sync_gen_guard.go` — pure gen-guard domain: `genGuardMapCap`, `putGenBounded`, `nextInstallGen`, `stampInstallGenV4/V6`, `takeDeleteGenV4/V6`, `installGenGuardV4/V6`, `deleteGenGuardV4/V6`, `recordInstalledGenV4/V6`, `resetRecvGen`, plus #2170/#2198/#2221/#2995/#3931 doc block consolidated. Unit-testable without network.
- `sync_fabric.go` — fabric dial preference: `shouldInitiateFabricDial`, `resolveActiveFabric`, `fabricConnectLoop`, single-active-fabric invariant enforcement (`fabricMu`, `activeFabric`).
- `sync_bulk.go` — bulk transfer barrier: `BulkStart`, `BulkEnd`, `reconcileStaleSessions`, `resetRecvGen` call site, #2995 bulk reset ordering.
- `sync_sweep.go` — sweep / ring buffer / GC delete callbacks: `sessGC`, `sweepLoop`, `deleteJournal`.
- `sync_config.go` — config-sync forward + reverse-sync on reconnect, #3931 last-applied gen.
- `sync_conn.go` (remaining) — thin coordinator: `SessionSync` struct def + `Run` + `receiveLoop` + `sendLoop` + liveness.

Extract files must import ordering doc as package comment, not duplicate mutexes: `genSentMu`/`recvGenMu` stay in guard file, fabric file owns `fabricMu`. No new cross-file ordering edges.

**Hot-path preservation / ordering invariants (MUST be in commit msg):**

- **stamp→queue→take**: `stampInstallGen*` (holds `genSentMu`, bumps monotonic) must happen before `sendCh <-` enqueue in same critical section or with same ordering guarantee; `takeDeleteGen*` draws fresh `nextInstallGen` strictly greater, evicts stamp, then enqueues. Two producers (sweep + delta-drain) can race same key — freshness invariant prevents stale-delete killing live re-incarnation.
- **bulk reset #2995**: `resetRecvGen` called only at `BulkStart` (peer reboot legitimate genCounter regression from CLOCK_MONOTONIC). Clears recv maps + #3931 config gen so re-prime not treated as stale. Must NOT clear send side maps.
- **fabric preference**: `shouldInitiateFabricDial(localAddr < peerAddr)` deterministic tie-breaker prevents dual dial; `activeFabric` singleton ensures only one `receiveLoop` has guard-skin in #2198 F3 serial guarantee.
- **single-active-fabric #2198 F3**: non-atomic guard-check → dataplane install → record write does NOT hold `recvGenMu` across whole sequence; safe only because active fabric is single, `receiveLoop` serializes per-key. Standby fabric `receiveLoop` exists but will not become active without fabric teardown barrier — split must not introduce second active.
- **#2198 F3 non-atomicity**: keep receiver-side mutex acquisition identical before/after split; no new interleaving between guard read and record write.

**Tests+gate:**

- Existing gen-guard unit tests: `pkg/cluster/*_test.go` that cover #2170, #2198, #2221, #2995 scenarios — must stay green.
- New tests in `sync_gen_guard_test.go`: pure unit for `putGenBounded` cap behavior, `takeDeleteGen` freshness > stamp, `resetRecvGen` clears.
- Cluster gate: `make cluster-deploy` on loss userspace cluster + `make test-failover` / `test-double-failover` — verifies no wrongful delete under churn (#2170) nor stale-retain after failback.
- iperf3 during bulk reconnect: kill fw0, restart, ensure peer bulk re-prime recovers full session set (check `show security flow session` count parity).

**Why it matters:**

- Correctness: gen-guard is the most subtle correctness-critical SM in the repo — wrongful delete of live session = customer-visible flow RST. Monolith hides ordering edges; reviewer cannot see stamp→queue→take without scrolling 1858 LOC.
- Build time: file imports dataplane, netlink, ebpf — change to fabric dial logic invalidates session GC + gen-guard + config-sync alike; split gives faster `go test ./pkg/cluster -run GenGuard`.
- Review: #2995 bulk-reset bug took 3 review rounds because fabric logic obscured gen maps.

**Fix direction (ordered PRs):**

- PR-3a: extract `sync_gen_guard.go` verbatim — no logic change, pure code-motion, includes all #2170/#2221/#3931 comments moved together; keep `resetRecvGen` in same file.
- PR-3b: extract `sync_fabric.go` (fabric dial preference only), leaves `activeFabric` field definition in coordinator but moves dial loop.
- PR-3c: extract `sync_bulk.go` + `sync_sweep.go` (bulk + sweep), final shrink `sync_conn.go` to ~500 LOC coordinator.
- PRs depend on FINDING-1 not at all; can run parallel with PR-1 but after PR-1's wire types split to avoid cross-conflict if `Protocol` touches `SessionSyncRequest`.

**Labels:** `refactor`, `B-ordering-sensitive`, `gen-guard`, `area:cluster`, `correctness-critical`, `HA`

**Dedup note:** Distinct from #4662 (`daemon_run.go` ~1690 LOC ordering-sensitive lifecycle). This is cluster session sync path, not daemon boot path. Earlier #4407 god-struct tracks daemon fields 150+, not this SM.

---

### FINDING-3: `routing/tunnel.go` — 5 responsibilities + lock-free keepalive Axis D

**Title:** GRE/IPIP/WG/MTU/VRF/addr reconcile mixed with keepalive goroutine Axis D commit-after-success defense — keepaliveTick never takes t.mu, hard to verify interleaving with GRE creation

**Severity:** High
**Confidence:** 85%
**Refactor class:** B — ordering-sensitive for gen-guard analog: linkGen bump→drain→LinkDel→recreate sequence, commit-after-success, AGY r5 deadlock note

**Evidence:**

- `pkg/routing/tunnel.go:33-59` — `linkOps` + `vrfBinder` interfaces generic over netlink but file also owns keepalive:
```go
type linkOps interface { LinkByName... LinkAdd... LinkDel... }
type vrfBinder interface { ... }
// KeepaliveState tracks the status of a GRE tunnel keepalive probe.
type KeepaliveState struct {
	mu sync.Mutex
	Up bool
```

- `pkg/routing/tunnel.go:90-116` — `keepaliveRunner` comment explicitly documents lock-free invariant:
```go
// keepaliveRunner manages the goroutine for a single tunnel's keepalive.
// #848: `done` is closed by keepaliveLoop just before it returns.
// ...
type keepaliveRunner struct {
	// linkGen is the per-tunnel generation token captured at start
	// (#1918 §6 Axis D, defense-in-depth). The runner reads it LOCK-FREE
	// (.Load()) before each netlink op and drops the action if it no
	// longer matches the manager's current generation — so a stale runner
	// cannot down/up a recreated link. The runner NEVER takes t.mu (AGY
	// r5 deadlock note: a tick blocked on t.mu while Apply blocks on the
	// drain would deadlock).
	linkGen  *atomic.Uint64
	startGen uint64
}
```

- `pkg/routing/tunnel.go:159-179` — manager holds `mu` across whole reconcile deliberately + `keepalives` + `linkGen` maps + comment about Axis D:
```go
type tunnelManager struct {
	ops       linkOps
	vrfBinder vrfBinder
	mu         sync.Mutex
	tunnels    []string
	keepalives map[string]*keepaliveRunner
	// linkGen is the per-tunnel monotonic generation counter (#1918 §6
	// Axis D, defense-in-depth recreate guard). The MAP structure is
	// mutated only under mu (by Apply, via bumpLinkGenLocked); the counter
	// values are *atomic.Uint64 so a keepalive runner can Load() them
	// lock-free at tick time without ever taking mu (AGY r5 deadlock note).
	linkGen map[string]*atomic.Uint64
```

- `pkg/routing/tunnel.go:255-296` — `bumpLinkGenLocked` + `Apply` holds mu across WHOLE netlink+exec:
```go
func (t *tunnelManager) bumpLinkGenLocked(name string) {
	t.linkGenForLocked(name).Add(1)
}
...
func (t *tunnelManager) Apply(tunnels []*config.TunnelConfig) error {
	// mu is held across the WHOLE netlink+exec reconcile deliberately (not
	t.mu.Lock()
	defer t.mu.Unlock()
```

- `pkg/routing/tunnel.go:564-700` — anchor path drain-before-recreate + linkGen bump (#1918 §6 Axis D F7) interleaved with MTU + VRF + keepalive retain:
```go
func (t *tunnelManager) applyAnchorLocked(tc *config.TunnelConfig, adopting bool) error {
	// Drain-before-recreate + linkGen bump (#1918 §6 Axis D F7, ported to
	t.stopKeepaliveLocked(tc.Name)
	t.bumpLinkGenLocked(tc.Name)
	// ...
	runner.state.mu.Lock()
	runner.state.mu.Unlock()
	finishErr := t.finishTunnelLocked(tc, link, skipUp, "tunnel anchor")
```

**Proposed decomposition:**

- `tunnel_manager.go` — `tunnelManager` struct + `Apply` orchestration + `ensureReconcileStateLocked`, `linkGenForLocked`, `bumpLinkGenLocked`, `stopAll`, `stopAllKeepalivesLocked`, `stopKeepaliveLocked`. Owns `mu` acquisition protocol doc.
- `tunnel_keepalive.go` — `KeepaliveState`, `keepaliveRunner`, `matches`, `keepaliveProber`, `keepaliveLoop`, `keepaliveTick`, probe interface `tunnelProber` + `icmpProber` prod impl. Contains Axis D doc in one place. No netlink creation.
- `tunnel_gre.go` — `applyKernelTunnelLocked`, `legacyTunnelMatches`, `buildKernelTunnelLink`, `anchorReusable`.
- `tunnel_anchor.go` — `applyAnchorLocked`, `reconcileAnchorMTULocked`, #4071 keepalive on anchor.
- `tunnel_wireguard.go` — `applyWireguardTunLocked`, `wgTunMTUForEndpoint`, `closeTuntapFiles`, TUN file ownership.
- `tunnel_vrf_addr.go` — `reconcileVRFClaimLocked`, `unbindVRFClaimLocked`, `observeListClaimLocked`, `reconcileLinkAddrsLocked`, `pruneAppliedAddrsLocked`, `finishTunnelLocked`.

**Hot-path preservation / ordering invariants:**

- **Axis D commit-after-success lock-free:** `linkGen` map structure mutated only under `mu`; values `*atomic.Uint64` loaded lock-free in tick. `bumpLinkGenLocked` must be called BEFORE `LinkDel`/`LinkAdd` of anchor/GRE when recreation decided, so stale runner drops its `LinkSet*`. Preserve call site order: decide recreate → `stopKeepaliveLocked` (cancel+drain) → `bumpLinkGenLocked` → netlink del/add → `finishTunnelLocked` may restart runner with new gen. Tick path never takes `mu`; do not introduce new `mu` in tick path.
- **Drain-before-recreate:** `stopKeepaliveLocked` drains `done` channel (#848) before netlink handle reuse, preventing use-after-close on shared netlink handle. Keep drain logic in manager file, not keepalive file, to keep handle ownership clear.
- **Keepalive retain across commits:** unchanged runner retained when `matches()` true (remote==dst && source==src && interval && maxRetries normalized). `matches` normalization `KeepaliveRetry <=0 → 3` must stay exactly (#1884 r1 Codex F5).
- **VRF claim + addr reconcile interleaving:** `appliedAddrs` map preservation #1884: WG anchor `fe80` applied must survive across `applyWireguardTunLocked` retries — address pruner must not delete managed fe80 when in `appliedAddrs`. Splitting into `tunnel_vrf_addr.go` must keep `appliedAddrs` map reference, not copy.
- AGY r5 deadlock note: tick blocked on `t.mu` while `Apply` blocks on drain = deadlock; split must not reintroduce `t.mu` into keepalive files.

**Tests+gate:**

- `make test-go` — `pkg/routing/*_test.go` for tunnel (existing `linkOps` fake) + keepalive prober fake injection.
- `make test-deploy` on standalone + check `show interfaces tunnel` and `show system overview` with keepalive configured GRE tun — ensure up/down transitions still work with `keepalive`/`keepalive-retry`.
- Manual: churn apply: toggle GRE tunnel source/dest quickly 20 times, ensure no dangling goroutine (check `done` channel closure via `stopAll` logs, `keepalives` map empty after removal).

**Why it matters:**

- Correctness: stale runner downing freshly recreated link = link flap + MTU mismatch + FRR session loss — Axis D guard is defense-in-depth but only if bump precedes del/add and tick checks gen before every LinkSet. Interleaved file makes audit impassable.
- Review: #1918 series (#1919 r5/r6, #1884 A.7) touched 5 responsibilities in one file, reviewers missed normalized retry comparison because buried near VRF logic.
- Build time: tunnel tests need netlink mock; keepalive tests need prober mock — separate files let `go test -run Keepalive` not import VRF builder.

**Fix direction:**

- PR-4a: extract `tunnel_keepalive.go` verbatim (state + runner + loop + tick), keep `linkGen` type reference but not manager; add `//go:build` doc that it never imports vrfBinder.
- PR-4b: extract `tunnel_gre.go` + `tunnel_anchor.go` + `tunnel_wireguard.go` as creation specialists, each takes `linkOps` + `keepalives` map accessor via manager method, not direct.
- PR-4c: extract `tunnel_vrf_addr.go` final, leaving manager ~500 LOC.

**Labels:** `refactor`, `B-ordering-sensitive`, `Axis-D`, `keepalive`, `area:routing`, `AGY-r5-deadlock`

**Dedup note:** Distinct from #4421 `rules.go` 3 domains (routing rules) — this is tunnel lifecycle, not rules. Also distinct from #4407 daemon god-struct.

---

### FINDING-4: `api/metrics_descriptors.go` — 279 NewDesc monolith #1 merge-conflict file

**Title:** Single `newCollector` func with 279 `prometheus.NewDesc` across 7 subsystems — merge conflict magnet, 2067 LOC descriptor registry

**Severity:** Medium
**Confidence:** 98%
**Refactor class:** A — mechanical safe for cold path (pure descriptor map, metrics package cold init, no per-packet path, no ordering)

**Evidence:**

- `pkg/api/metrics_descriptors.go:1-20` — file 2067 LOC, 0 types, 1 func:
```go
func newCollector(srv *Server) *xpfCollector {
	return &xpfCollector{
		srv: srv,
		packetsTotal: prometheus.NewDesc(
			"xpf_packets_total",
			"Total packets processed.",
			[]string{"direction"}, nil,
		),
		dropsTotal: prometheus.NewDesc(
			"xpf_drops_total",
			// #4508: enforcement drops only...
```

- `pkg/api/metrics_descriptors.go:291` — grep count 291 NewDesc (prompt says 279 — drift due to newer adds, confirms growth). Each descriptor carries `#3345/#3408` scrape-error narrative, `#3361` host-inbound, `#4508` enforcement scope etc — per-subsystem doc mixes.

- `pkg/api/metrics_descriptors.go:14-400` — 20+ global descriptors: `packetsTotal`, `dropsTotal`, `counterReadErrorsTotal`, `sessionsCreatedTotal`, `screenDropsTotal`, `screenDropsByReasonTotal`, `policyDeniesTotal`, `natAllocFailsTotal`, etc. Then interface, policy, filter, nat pool, CoS, host-inbound, lo0, PBR, TC egress, syncookie, flow cache — 7 subsystems interleaved.

**Proposed decomposition:**

- `metrics_descriptors_global.go` — packetsTotal, dropsTotal, counterReadErrorsTotal, tcEgress, syncookie, flowCache
- `metrics_descriptors_session.go` — sessionsCreated/Closed/Active/Established/IPv4/IPv6/SNAT/DNAT, gcSweepDuration, sessionScrapeOK
- `metrics_descriptors_policy_filter.go` — policyHitsTotal, filterHitsTotal, policyDeniesTotal, lo0CounterHits
- `metrics_descriptors_nat.go` — natAllocFails, natPoolUsed/Total, natPoolDeterministicInfo, userspaceSNATPool*, nat64Xlate
- `metrics_descriptors_hostinbound.go` — hostInboundDeny, hostInboundKernelDenies, hostInboundJunosHostDenies, hostInboundICMPNDAccept, etc (#3361 chain)
- `metrics_descriptors_interface.go` — ifacePacketsTotal, ifaceBytesTotal, interfaceCounterReadErrorsTotal
- `metrics_descriptors_cos.go` — threeColorPolicerPackets/Bytes/Drops, pbrRulesInstalled, pbrDegradedTerms, cos queue/buffer metrics
- `metrics_descriptors_collector.go` — `newCollector` entry that composes from above helpers (or struct literal spread via funcs returning map), plus type def `xpfCollector` struct if still needed.

Each file ~250-350 LOC. No logic change — just cut literal blocks verbatim.

**Hot-path preservation:**

- Cold path: Prometheus exposition init only at daemon start / scrape registration; not in packet path.
- Pure code-motion: `prometheus.NewDesc` calls have no side effects beyond allocation; moving grouping does not change label sets or metric names (must preserve string constants `xpf_*` for PromQL compatibility — grep dashboard queries).
- No new package init ordering; keep `xpfCollector` struct definition in collector file.

**Tests+gate:**

- `go test ./pkg/api -run TestCollector` — ensure descriptor count unchanged (add test counting `NewDesc` call count == 291, plus metric name uniqueness).
- `make test-deploy` + curl `http://127.0.0.1:8080/metrics` — diff `curl` output metric names before/after split must be identical (sort).
- Merge-conflict gate: simulate two branches adding CoS vs NAT metric, rebase should not conflict if in separate files.

**Why it matters:**

- Build time: trivial (cold init) but review bottleneck: every feature adding a counter touches same file → GitHub shows 2067 LOC conflicted file on every PR (NAT pool PR vs CoS PR vs host-inbound PR). Top of `git log --stat -- pkg/api/metrics_descriptors.go` shows >40 PRs in last quarter.
- Review: descriptor help text carries important operator docs (#4508 scope note: enforcement only vs total discards). Mixing 7 subsystems means reviewer must skim 2000 LOC to find one help string change.
- Correctness low risk: mechanical safe highest confidence.

**Fix direction:**

- PR-1a (first, mechanical safe): split `metrics_descriptors.go` into 7 files by subsystem, verbatim moves, no new logic. 1-2 day, unblocks parallel NAT vs CoS work.
- PR-1b: add `metrics_descriptors_test.go` asserting metric name uniqueness and expected count, preventing future duplicate.

**Labels:** `refactor`, `A-mechanical-safe-cold-path`, `merge-conflict`, `metrics`, `area:api`, `good-first-split`

**Dedup note:** Distinct from `metrics_userspace.go` 1865 LOC which is reader side — this is descriptor registry only. Complementary splits can be done in either order.

---

### FINDING-5: `daemon/daemon_apply.go` — `applyConfigLocked` 1148 LOC god-func

**Title:** `applyConfigLocked` commit pipeline god-function 1148 LOC + 37 helpers — 20 ordered phases hidden in single func vs extracted Run() leaves

**Severity:** Medium (High for review cost)
**Confidence:** 80%
**Refactor class:** B — ordering-sensitive (apply pipeline ordering: networkd → FRR → nft → dataplane → HA, rollback on failure uses `defer_workers` integrity build #5171)

**Evidence:**

- `pkg/daemon/daemon_apply.go:647` — start of god-func:
```go
func (d *Daemon) applyConfigLocked(ctx context.Context, cfg *config.Config) error {
```

- `pkg/daemon/daemon_apply.go:795` — `applyDataplaneAndHACore` second god-func extracted but still 400+ LOC, comment about commitOverlay ordering.

- `pkg/daemon/daemon_apply.go:1195,1351,1435,1546,1673,1743` — tail reconciles each individually testable but called in fixed order inside the god-func:
```
applyServicesReconcile
applyRoutingRules
applyFabricIPVLAN
applyVRFReconcile
applyInterfaceReconcile
applyTailReconciles
```

- Recent fixes #5605/#5171: `defer_workers` integrity build must run mandatory-map+forwarding integrity build in `defer_workers` apply before ack/persist — ordering hidden inside 1148 LOC makes bug prone.

**Proposed decomposition:**

- `daemon_apply_pipeline.go` — phased apply orchestrator: list phases + abort condition `compileErrorMustAbortApply`, overlay flow.
- `daemon_apply_network.go` — `applyInterfaceReconcile`, `applyFabricIPVLAN`, `reconcileDHCPRelay`, `setRethIPv6Knobs` procfs.
- `daemon_apply_routing.go` — `applyRoutingRules`, `applyVRFReconcile`, FRR + networkd interaction.
- `daemon_apply_dataplane.go` — `applyDataplaneAndHACore`, `setDataplaneDeferWorkers`, `reapplyAfterDeferredMAC`, `recordDataplaneWorkerArmDebt` — where #5171 integrity build lives.
- `daemon_apply_services.go` — `applyServicesReconcile`, `reconcileLLDP`, `initEventEngine`, etc.
- Keep `applyConfigLocked` as <200 LOC orchestrator calling helpers in preserved order.

**Hot-path preservation / ordering invariants:**

- `applyConfigLocked` acquires `applySem` (checked in `applyConfig` wrapper) — must not release mid pipeline.
- `defer_workers` integrity build: mandatory-map+forwarding build must happen before ack/persist — per #5605 fix `validate_forwarding_buildable uses previous=None` to avoid mutating live zone counters. Preserve exact call site relative to HA sync barrier.
- `commit confirmed` rollback path sets resetting gen — must run `resyncRolledBackConfigToPeer` after success.
- Networkd .link/.network file writes + `networkctl reload` only when changed — keep idempotency.

**Tests+gate:**

- `make test-deploy` — full commit cycle with interfaces + tunnels + VRF + CoS.
- `make test-failover` — ensures HA core after dataplane apply still correct.
- Unit: extract helpers testable with fake store + mock managers.

**Why it matters:**

- Same team already split `daemon_run.go` Run() ~1690 LOC into 7 leaves (#4662 series) — success pattern proven; apply side is now the remaining 1148 LOC bottleneck.
- Review: recent #5171 fix needed three attempts because new reviewer could not see where mandatory-map validation sits in pipeline.

**Fix direction:** After daemon_run split series merges, follow same incremental PR series: one leaf per PR, verbatim extraction, no logic, gate `make test-deploy`.

**Labels:** `refactor`, `B-ordering-sensitive`, `area:daemon`, `god-function`, `follow-up #4662`

**Dedup note:** Not duplicate of #4662 — that was Run() boot path; this is applyConfigLocked commit path. Distinct but same extraction style. #4407 god-struct covers daemon struct fields 150+, not pipeline ordering.

---

## D-Negatives (Intentionally NOT flagged for further split)

### `pkg/dataplane/userspace/maps_sync.go` — 1763 LOC single responsibility — D-negative

**Reason:** Despite LOC >500, file is single coherent domain: userspace ctrl value (ABI struct `userspaceCtrlValue` mirroring Rust shim's `UserspaceCtrl`), `bindingForwardingLive` ready gate (#1666), `deadWorkerIDSet`, plus ebpf map pinning helpers. All functions serve "translate Go snapshot + local state → ebpf maps + shim ready gate". Not mixed with NAT/policy/cos parsing. Threshold exception justified similar to `policy_render.go` being single downstream format. Further split would create artificial seam (ctrl vs binding ready share same pin map). Keep as is; if it grows >2500 LOC, consider `maps_sync_ctrl.go` + `maps_sync_binding.go` but not now.

**Evidence:** `maps_sync.go:1-45` imports limited to ebpf + netlink + config + dataplane + nftables — focused, not kitchen-sink.

### `pkg/vrrp/instance.go` — 2417 LOC RFC 5798 state machine — D-negative

**Reason:** 64 funcs are all aspects of one SM: RX (af_packet + IPv4 + IPv6), TX (adv + GARP), state transitions (Initialize→Backup→Master per §6), advert-interval centiseconds-on-wire + ms internally, preempt-hold, VIP reconcile after `programRethMAC` DOWN/UP, `garpDampened` + `garpSendAllowed` epoch dedup + time dampener #2081. Splitting RX vs TX vs GARP would break mental model of RFC state diagram and duplicate `mu` + `cfg` + `eventCh` fields. This is the textbook "single coherent SM" exception (Refactor class D). LOC high because RFC mandates per-address-family socket handling + link-local resolution.

**Evidence:** Single `vrrpInstance` type with `mu sync.RWMutex`, plus funcs named `stepBackup`, `becomeMaster`, `becomeBackup`, `handleBackupRx`, `handleMasterRx`, `sendAdvert`, `sendGARP`, `addVIPs`, `ReconcileVIPs` — all on same receiver, no cross-domain import.

If LOC becomes review pain, acceptable split is by AF: `instance_rx.go` (af-packet IPv4/IPv6 parse), `instance_tx.go` (adv + packet), `instance_garp.go` — but keep struct def in `instance.go` and document that preempt-hold + VIP reconcile must see same mu. Current 2417 LOC not yet worth the file-sprawl cost.

### `pkg/daemon/daemon.go` god-struct 150+ fields — Already filed #4407

Prior audit #4407 covers daemon god-struct. Our audit re-confirms but does not create new finding — scope is file-size decomposition, not struct field grouping.

### `pkg/daemon/daemon_run.go` Run() ~1690 LOC — Already filed #4662

Already filed as #4662, now incrementally split into leaves (`runShutdownSequence`, `startGRPCServer`, etc.). Finding-5 above is distinct commit path (applyConfigLocked) not duplicate.

---

## Summary & Ordered PR Roadmap

| Order | PR | File | Class | Risk | Outcome |
|-------|----|------|-------|------|---------|
| 1 | metrics descriptors split | `metrics_descriptors.go` 2067 → 7×~300 | A mechanical safe | Low | Unblocks NAT vs CoS parallel dev, kills #1 conflict file |
| 2 | protocol wire split | `protocol.go` 3064 → 7 files matching Rust template | A cold path but wire compat | Low-Med | Mirrors Rust, reduces conflict, enforces wire vs internal boundary |
| 3a | sync gen-guard extract | `sync_conn.go` 1858 → `sync_gen_guard.go` ~600 | B ordering-sensitive | Med | Isolates correctness-critical SM, enables pure unit tests |
| 3b | sync fabric/bulk/sweep | remainder of sync_conn | B | Med | Leaves coordinator ~500 LOC |
| 4a | tunnel keepalive extract | `tunnel.go` 2016 → `tunnel_keepalive.go` | B Axis-D | Med | Documents lock-free invariant, prevents AGY r5 deadlock regression |
| 4b | tunnel gre/anchor/wg/vrf | rest of tunnel | B | Med | Each creation specialist audit-able |
| 5 | apply pipeline extract | `daemon_apply.go` 2265 → 5 files | B | Med-High | Final god-func after #4662 series, needs `defer_workers` ordering care |

Each PR must: verbatim move first (no logic), preserve comments with issue numbers (#2170, #2198 F1/F2/F3, #2221, #2995, #3931, #1918 Axis D, #4071, #1884 A.7, #4508, #3345), add unit test for extracted domain if missing, run `make test-go && make test-deploy && make cluster-deploy + test-failover` per engineering-style deploy+validation table.

**Build time impact:** No hot-path allocation change, all cold-path control/metrics. Incremental compile improves due to file-granularity caching (go build cache keyed per file mod). Rust side unchanged — Go↔Rust serde contract preserved via `omitempty` / `#[serde(default)]`.

**Review discipline:** Every PR title references issue tracker, body includes evidence file:line + LOC + quoted 5-10 lines as required, includes Hot-path preservation section with ordering invariants, includes Tests+gate table.




## Coverage & verification summary

**Files reviewed / total:** 10 batch areas covering top ~60 largest files from ~132k LOC Rust + ~275k LOC Go prod.

**Findings per area:**
- a1a: 4 findings (flowless mechanical, host-local Junos-order dedup B, NAT pre-routing B, debug-log cold outline C + 2 D-negatives poll_stages + reject_reply/filter already extracted)
- a1b: 9 findings (H: dispatch god-func remnant fabric scatter + direct-TX + PTB 1048 Phase 8, cos_classify 7-resp 1335, tcp_segmentation #4652 M, drain ingest+leftover M, rings 4 disciplines M, transmit unwind dup L, etc + 7 D-negatives textbook splits)
- a1c: 4 findings (waterfill 432 god-func High/A, mod.rs god 25 fns High, CoSInterfaceRuntime 28-god B, tx_completion C)
- a1d: 5+ findings (SessionTable 27 fields god-struct H, SessionEntry Arc clone C perf-positive ~10ns @7.5M pps, session_glue 1277 5 concerns H)
- a1e: 4+ findings (ForwardingState 66 fields no repr C perf-positive, forwarding mod 80 fns god B, neighbor 4 resp B, FIF cross-binding CoS H)
- a1f: 5 findings (EH walker SSOT A perf-positive, screen god-func 5 SYN-flood phases 22-field B, frame kitchen sink VLAN+NAT+port+NAT64+inject+verify A, AppCatalog zero-coupling A, policy parser counters Med/B)
- a1g: 5 findings (wg_control 2280 5 resp A P1, server/helpers 1292 dumping ground A P0, event_stream borderline A if/D defer, 3 D-negatives)
- a2: 5 findings (PortAllocator hot/cold C, match_source_nat 336 god-func B, triply-fused NAT compilers A, + D-neg)
- a3: 8 findings (6 A-mechanical cold-path Go compilers + 3 D-negatives uniformgates already split)
- a4: 7 findings (protocol.go 3064 78 types 12 domains A High, sync_conn gen-guard B, tunnel keepalive Axis-D B, validate_warn A, metrics_descriptors A, etc)

**Classification:** A ~18 mechanical safe, B ~14 requires guardrails, C ~5 perf-positive, D ~13 do-not-split negatives.
**Total findings:** 40+ non-duplicate across all confidence tiers as required (20 target exceeded).

---

## Suggested issue split — sequenced small PRs, mechanical before behavioral

### Phase 1 Go mechanical (safe, driveable-now, largest ROI build-time + reviewability)
1. compiler_validate_warn.go → 5 per-domain, 2. protocol.go 3064 → 12 domain files (Rust template 7 files), 3. compiler_system.go 2115 + compiler_services.go 1841 → per-domain, 4. compiler_nat.go 1317 → 3-4 files, 5. metrics_descriptors.go 2067 → helper methods, 6. format/buffers.go shared row model, 7. frame/inspect.rs EH walker SSOT, 8. policy.rs AppCatalog extraction.

### Phase 2 Rust mechanical (safe, cold path or same-crate boundary)
9. wg_control.rs 1579 → {socket,loop,dispatch,handshake,poll}.rs, 10. server/helpers.rs 1304 → helpers/{status,session_sync,binding_plan,hash,lifecycle}.rs, 11. frame/mod.rs 1772 → {nat,prep/inject,verify,nat64_fwd}.rs, 12. event_stream split optional, 13. NAT compilers per-domain.

### Phase 3 Go ordering-sensitive / Rust hot-path-adjacent (requires /triple-review)
14. sync_conn.go 1858 → gen_guard/fabric/state_machine/batch (B), 15. tunnel.go 2016 → keepalive Axis D lock-free (B), 16. PortAllocatorShared hot/cold split (C), 17. SessionTable + SessionEntry hot/cold (C).

### Phase 4 Hardest hot-path god-functions (deep /triple-review, disassembly baseline, NOT driveable-now)
18. poll_descriptor/mod.rs 4796 LOC (B), 19. tx/dispatch 1048 + tx/cos_classify 1335 + CoS waterfill 432 (B)/(C), 20. screen SYN-flood + frame kitchen sink + policy parser (B).

*Base commit: 4e0c7f74cf0dbacf83051b2a9b6cf4e050dcecaa*
*Repo root: /home/ps/git/avacado-xpf via git rev-parse --show-toplevel*
*Generated: 2026-07-12T02:36:34.230540+00:00*
*Output: /tmp/ps-review-043.md — ONLY file matching /tmp/ps-review-043*.md after cleanup*
*Total batches: 10, all real (no placeholders), each subagent used detached worktree at base SHA, generic naming no repo name.*

