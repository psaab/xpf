1. High: §3.3 is materially wrong. The plan says synced sessions “don’t re-resolve,” but the Rust path explicitly re-resolves them with local egress data.
   `userspace-dp/src/afxdp/session_glue/commands/upsert_synced.rs:3-6` says “re-resolve the synced forward session with local egress.”
   `userspace-dp/src/afxdp/session_glue/commands/upsert_synced.rs:39-44` calls `lookup_forwarding_resolution_for_session(...)`.
   `userspace-dp/src/afxdp/session_glue/commands/upsert_synced.rs:55-60` overwrites `entry.decision.resolution = re_resolved`.
   `userspace-dp/src/afxdp/session_glue/mod.rs:122-134` disables the cached fast path for peer-synced sessions.
   `docs/multi-wan.md:231-234` also documents the exception: peer-synced and tunnel-backed sessions re-resolve. Mandatory revision: rewrite §3.3. `SessionSyncRequest` does carry `egress_ifindex`, `next_hop`, and `neighbor_mac` at `userspace-dp/src/protocol/control.rs:512-523`, but those are not proof that synced sessions “never re-resolve.”

2. Medium: §3.1’s central “no userspace ECMP” claim is verified, but its wording is too broad if it says there is no flow hash anywhere. Route resolution has no ECMP selector.
   `userspace-dp/src/afxdp/forwarding_build/fib.rs:161-164` uses `route.next_hops.first()` for IPv4.
   `userspace-dp/src/afxdp/forwarding_build/fib.rs:195-198` uses `route.next_hops.first()` for IPv6.
   `userspace-dp/src/afxdp/types/forwarding.rs:123-140` has one `next_hop` field per `RouteEntryV4/V6`.
   `userspace-dp/src/afxdp/forwarding/mod.rs:1198-1221` and `:1356-1369` use first matching route entry, then `choose_*_route`.
   But there are non-route flow hashes: `userspace-dp/src/afxdp/worker/mod.rs:237-274` computes `fabric_queue_hash`, and `userspace-dp/src/afxdp/types/forwarding.rs:396-405` maps that hash to a fabric target. Mandatory revision: say “no flow hash in route next-hop selection,” not “no flow hash anywhere.”

3. I found no alternate per-flow multipath selector in PBR, tunnels, NAT64, fabric redirect, or flow-cache install.
   PBR returns only a table override: `userspace-dp/src/afxdp/forwarding/mod.rs:984-989`.
   The override is fed back into normal lookup: `userspace-dp/src/afxdp/poll_descriptor/mod.rs:656-661`.
   Tunnels recurse through the same route lookup: `userspace-dp/src/afxdp/forwarding/mod.rs:1511-1527`.
   SNAT uses the already-resolved egress: `userspace-dp/src/afxdp/poll_descriptor/mod.rs:1158-1167`.
   Flow cache stores the chosen decision: `userspace-dp/src/afxdp/poll_descriptor/mod.rs:1992-2017`.

4. §3.2 is verified: FRR/kernel can ECMP while userspace dp takes next-hop zero.
   `pkg/frr/config_render.go:82-85` says multiple next-hops produce one FRR line each and FRR creates ECMP.
   `pkg/frr/config_render.go:125-127` loops over `sr.NextHops`.
   `pkg/frr/config_render.go:163-167` emits one `ip route` / `ipv6 route` per next-hop.
   `pkg/config/types_routing.go:99-105` defines `NextHops []NextHopEntry` as “multiple next-hops = ECMP.”
   Userspace does not ingest kernel ECMP state: `pkg/dataplane/dataplane.go:391-397` says `StartFIBSync` is a no-op for in-tree backends, and `pkg/dataplane/userspace/routes.go:14-19` builds FIB from config/connected/leak/overlay inputs.

5. The snapshot-order concern in §3.3 is mostly verified, separate from the bad sync-session conclusion.
   `pkg/config/compiler_routing.go:243-247` merges duplicate destinations by appending `route.NextHops`.
   `pkg/config/parser_routing_test.go:179-183` asserts next-hop order.
   `pkg/dataplane/userspace/routes.go:143-151` sorts route snapshots only by table/family/destination via `sort.Slice`, so equal keys have the instability edge the plan flags.

6. §3.4 is verified: there is no source-level actuation surface for health-gated weighted ECMP without Rust route-resolution work.
   `pkg/config/types_routing.go:93-105` has address/interface next-hop fields, no weight.
   `pkg/config/types_system.go:339-359` overlay entries have a single `NextHop`, not weighted next-hop sets.
   `pkg/ipmon/ipmon.go:351-358` creates one overlay winner per prefix.
   `pkg/frr/config_render.go:283-288` renders preferred routes as one `NextHopEntry`.
   `pkg/dataplane/userspace/routes.go:172-177` converts overlay to a single-element `NextHops` list.

7. §3.5/§11 value reasoning is directionally correct, but needs a clearer operator-facing close-out. Direct sessions pin resolved uplink.
   `userspace-dp/src/afxdp/session_glue/mod.rs:104-107` returns cached resolution for direct sessions.
   `docs/multi-wan.md:220-230` says flow-cache invalidation does not touch the session table and established local sessions stay pinned.
   The shipped operator story is FBF, not weighted ECMP: `docs/multi-wan.md:92-124` shows policy-selected uplinks and fallback; `docs/multi-wan.md:149-152` adds counters. Weighted hashing would redistribute only new direct flows, so the kill is justified at two uplinks unless a separate equal-cost load-balance parity demand appears.

8. Closing #1827 is acceptable only with explicit wording. Do not close it as if load-sharing shipped.
   `docs/multi-wan.md:3-9` still says “Health-gated load-sharing is a later PR.”
   The plan’s `docs/research/1827-pr4-loadshare/plan.md:199-203` makes that doc update optional. That is not acceptable for closure. Mandatory revision: update close-out/docs to say PR-4 was killed by research criteria, PR-1..3 completed the multi-WAN operator deliverables, and equal-cost/weighted per-flow load-balance parity remains unimplemented unless filed separately.

PLAN-NEEDS-REVISION

Codex session ID: 019eb4e7-ecf1-7430-826c-adf677681fae
Resume in Codex: codex resume 019eb4e7-ecf1-7430-826c-adf677681fae
