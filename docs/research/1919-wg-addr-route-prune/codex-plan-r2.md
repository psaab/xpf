Reading additional input from stdin...
OpenAI Codex v0.139.0
--------
workdir: /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
model: gpt-5.5
provider: openai
approval: never
sandbox: read-only
reasoning effort: xhigh
reasoning summaries: none
session id: 019ed4ab-fb99-7e41-a2e1-49f4b08a62e5
--------
user
You previously reviewed r1 of this plan and returned PLAN-NEEDS-MAJOR with three findings: (1) the retry signal via len(remaining)>0 from reconcileLinkAddrsLocked is broken for non-link-local addresses; (2) any LinkByName failure dropping tracking strands transient errors; (3) the "manager-applied addresses only" overclaim. This is r2 — re-review the REVISED plan at docs/research/1919-wg-addr-route-prune/plan.md against the real source in this worktree.

Verify the three r1 findings are correctly resolved:
1. r2 §4/§5 now adds a dedicated pruneAppliedAddrsLocked(link,name,applied) helper returning the failed-AddrDel set across ALL families, leaving reconcileLinkAddrsLocked untouched. Trace the proposed helper: does it correctly record non-link-local AddrDel failures? Is the AddrList-error fallback (return applied as failed) sound? Does it keep the autoconf-fe80 gate?
2. r2 §5 now gates LinkByName failure on isLinkNotFound (pkg/routing/vrf.go:151): not-found drops tracking, transient retains+retries. Correct?
3. r2 §4b now states the prune deletes ALL non-link-local stale addresses (matching steady-state reconcile), not applied-only. Accurate?

Also re-check: idempotency across add/remove/remove-again with the new nextWG logic; the clearLocked + ensureReconcileStateLocked wgConfigured wiring; tests §6 (non-link-local retry test #4, transient-lookup test #6, restart-boundary #8); FRR §1a connected-route nuance; VRF §4a A1 + the routing-instance-removed residual nit.

Confirm whether the plan is now PLAN-READY or if any finding remains. Output a single verdict: PLAN-READY / PLAN-READY-WITH-NITS / PLAN-NEEDS-MAJOR / PLAN-KILL, with file:line evidence for any remaining finding. Do not invent new blockers without a source-grounded counterexample.
codex
I’ll re-read the revised plan and the referenced source paths, then trace each claimed invariant against the implementation rather than treating the plan text as self-validating.
exec
/bin/bash -lc 'pwd && git status --short && git rev-parse --short HEAD' in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
8daf7e889

exec
/bin/bash -lc "nl -ba docs/research/1919-wg-addr-route-prune/plan.md | sed -n '1,260p'" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
     1	# Plan-of-action — #1919: WireGuard tunnel removal leaks kernel addresses (+ FRR routes claim)
     2	
     3	- **Issue**: #1919 — routing: removing a WireGuard tunnel leaks its kernel
     4	  addresses + FRR routes (persistent wgN bypasses address reconcile)
     5	- **Revision**: r2 (post-r1 triple review — Claude SMR + Codex + AGY all
     6	  PLAN-NEEDS-MAJOR; three converged findings folded in)
     7	- **Branch**: `research/1919-wg-addr-route-prune` off `origin/master`
     8	  @ `ee3f336d3` (post-#1918, post-#1947)
     9	- **Status**: PLAN DRAFT — research-only; STOP at PLAN-READY
    10	- **Contract**: `/research`, NOT `/engineer`. No PR, no production source
    11	  touched. Deliverable = converged plan + 3 verdicts + issue comment.
    12	
    13	---
    14	
    15	## 1. Problem statement
    16	
    17	WireGuard TUN devices are intentionally **persistent** (#1432 S2a). In
    18	`pkg/routing/tunnel.go`, the reconcile-in-place `Apply` excludes
    19	`wireguard`-mode tunnels from the `desired` set and from `ownedNames`:
    20	
    21	```go
    22	// Apply, line 168-175
    23	desired := make(map[string]bool, len(tunnels))
    24	for _, tc := range tunnels {
    25	    if tc.Mode != "wireguard" {        // WG excluded from removal diff
    26	        desired[tc.Name] = true
    27	    }
    28	}
    29	```
    30	
    31	This is **correct** for the link itself — it avoids flapping `wgN` and
    32	tearing the live peer/session on every commit (#1432 S2a, AGY Hazard B).
    33	
    34	The bug: a WG tunnel's **addresses** are reconciled only inside
    35	`applyWireguardTunLocked` (`tunnel.go:880`), which runs once per **still-
    36	configured** WG tunnel via the per-tunnel loop:
    37	
    38	```go
    39	// Apply, line 208-219
    40	for _, tc := range tunnels {          // tunnels = CURRENT config only
    41	    if tc.Mode == "wireguard" {
    42	        if err := t.applyWireguardTunLocked(tc); err != nil { ... }
    43	        continue
    44	    }
    45	    ...
    46	}
    47	```
    48	
    49	When an operator **removes** a WG tunnel from config:
    50	
    51	- The `wgN` link is correctly kept (persistent), but
    52	- `tc` for it is **absent** from `tunnels`, so `applyWireguardTunLocked`
    53	  / `reconcileLinkAddrsLocked` is **never called for it again**, and
    54	- It is **not in `ownedNames`**, so the `Apply` removal loop
    55	  (`tunnel.go:188-204`) never visits it either.
    56	
    57	Net: the kernel IP addresses this manager previously assigned to that
    58	wgN device (e.g. `172.16.0.1/30`) are **never reconciled away** — they
    59	persist on the live persistent device forever (until `ip link del wgN`
    60	or daemon restart). The in-code comment at `tunnel.go:790-794` already
    61	acknowledges this as a known S2a limitation (AGY M1) deferred to #1434.
    62	
    63	### 1a. The FRR-route claim — IMPORTANT scoping correction
    64	
    65	The issue title says "+ FRR routes". Investigation (§3) shows the FRR
    66	managed section is **regenerated declaratively and fully every commit**
    67	(`pkg/frr/manager.go:writeManagedSection` strips the entire
    68	`! BEGIN BPFRX MANAGED CONFIG` … `! END` block and rewrites it from
    69	`assembleFRRConfig`, then `frr-reload.py --reload` does a full diff). And
    70	WireGuard config **does not synthesize any FRR routes** — `WgAllowedIPs`
    71	are a decap inner-src gate only (`types_routing.go:328`), not LPM/routing,
    72	and `assembleFRRConfig` (`daemon_ipmon.go:89-153`) never reads tunnel or
    73	WG config. So **explicitly-configured static routes** that point at a wgN
    74	interface are owned by `routing-options static`/`routing-instances`, and
    75	when the operator removes those route statements, the full-rewrite +
    76	`frr-reload.py --reload` full diff withdraws them on the next commit.
    77	
    78	**Two sub-cases must be stated precisely** (a reviewer-critical
    79	distinction — do not overclaim a leak that does not exist):
    80	
    81	- **(A) Operator removes the static route stanza too** → FRR withdraws
    82	  it via the normal declarative path. **No FRR leak.** The route would,
    83	  however, be left pointing at a still-up wgN carrying stale addresses
    84	  until this fix prunes the addresses — but the route object itself is
    85	  withdrawn by FRR.
    86	- **(B) Operator removes ONLY the `tunnel`/WG stanza but leaves a
    87	  `routing-options static route … next-hop <wgN-addr>` referencing the
    88	  pruned address** → the static route stays in FRR (still configured),
    89	  now dangling toward an interface whose connected address we just
    90	  removed. This is **operator misconfiguration**, not a manager leak;
    91	  FRR/kernel will mark the route unreachable once the connected prefix
    92	  is gone. The plan does NOT chase this — withdrawing operator-owned
    93	  static routes the operator still has in config would be wrong.
    94	
    95	**Plan conclusion on FRR routes**: the genuine, in-scope leak is
    96	**kernel addresses on the persistent wgN device**, plus the **kernel
    97	connected route** that the kernel auto-installs for each address (the
    98	connected route is removed automatically by the kernel when its address
    99	is `AddrDel`'d — it is not a separate object we manage). There is **no
   100	manager-owned FRR route to withdraw**. The plan will (a) fix the address
   101	leak, and (b) document in the PR + module docs that FRR static routes are
   102	operator-owned and self-heal via the declarative path, closing the "FRR
   103	routes" portion of the issue by clarification rather than code.
   104	
   105	A reviewer who insists on an FRR code path must produce a concrete code
   106	location where WG config synthesizes a managed-section route. None was
   107	found — confirmed independently by all three r1 reviewers. Grep evidence:
   108	`assembleFRRConfig` (`daemon_ipmon.go:89-153`, the SOLE production
   109	FullConfig constructor — guarded by `frr_fullconfig_guard_test.go`) reads
   110	only `RoutingOptions.{StaticRoutes,Inet6StaticRoutes,GenerateRoutes}` +
   111	per-instance static routes + protocols/DHCP/policy/interface-hints —
   112	never tunnel/WG config; `WgAllowedIPs` is decap-only
   113	(`types_routing.go:325-332`, confirmed in `userspace-dp` wg engine.rs —
   114	AllowedIPs is a decap inner-src gate, not egress LPM).
   115	
   116	**r1 nuance (Codex/AGY)**: FRR CAN redistribute the kernel **connected**
   117	route of a wgN address if a `direct`→`connected` redistribution policy is
   118	configured (`policy_render.go:62`). But that route exists ONLY because of
   119	the leaked kernel connected route, which is auto-removed by the kernel the
   120	instant its address is `AddrDel`'d. So fixing the address leak ALSO
   121	removes any redistributed-connected FRR route — no separate FRR
   122	withdrawal hook is needed. This strengthens, not weakens, the "address
   123	prune is the complete fix" conclusion. If a reviewer produces a WG→FRR
   124	**static** route path, this plan escalates to add a withdrawal hook;
   125	none exists today.
   126	
   127	---
   128	
   129	## 2. Affected code (walked)
   130	
   131	| Location | Role |
   132	|---|---|
   133	| `pkg/routing/tunnel.go:163-233` `Apply` | reconcile entry; builds `desired`/`next`/`oldOwned`; WG excluded from diff |
   134	| `pkg/routing/tunnel.go:188-204` removal loop | deletes non-WG tunnels gone from config; `delete(appliedAddrs,name)` |
   135	| `pkg/routing/tunnel.go:208-230` per-tunnel loop | runs `applyWireguardTunLocked` ONLY for still-configured WG |
   136	| `pkg/routing/tunnel.go:798-890` `applyWireguardTunLocked` | create/reuse wgN; MTU; `reconcileLinkAddrsLocked`; VRF bind |
   137	| `pkg/routing/tunnel.go:584-645` `reconcileLinkAddrsLocked` | symmetric add/del against desired addr set; link-local gate; returns new applied set |
   138	| `pkg/routing/tunnel.go:104-134` `tunnelManager` fields | `ownedNames`, `appliedAddrs[name]`, `appliedRI[name]` |
   139	| `pkg/routing/tunnel.go:666-722` `reconcileVRFClaimLocked` | VRF claim/unbind (WG also binds VRF at :883-888 but NOT via this reconcile) |
   140	| `pkg/routing/tunnel.go:1086-1113` `clearLocked` | delete-everything path (ClearTunnels); does NOT delete WG (not in tunnels/ownedNames) |
   141	| `pkg/config/types_routing.go:292-335` `TunnelConfig` | WG fields; `WgAllowedIPs` decap-only |
   142	| `pkg/daemon/daemon_ipmon.go:89-153` `assembleFRRConfig` | sole FRR FullConfig constructor; no tunnel/WG input |
   143	| `pkg/frr/manager.go:487-545` `writeManagedSection` | declarative full strip+rewrite of managed block |
   144	| `pkg/routing/tunnel_reconcile_test.go` | existing WG tests: only link-local cases (356/390/410); NO removal test |
   145	
   146	### Blast radius
   147	
   148	- One file edited (`pkg/routing/tunnel.go`), one test file extended
   149	  (`pkg/routing/tunnel_reconcile_test.go`), plus module-doc note.
   150	- The fix is confined to the WG branch of `Apply`. It must NOT touch the
   151	  GRE/IPIP removal diff (already correct) nor the still-configured WG
   152	  apply (already reconciles addresses correctly via :880).
   153	- No wire-protocol change, no userspace-dp change, no FRR change.
   154	- Interaction with #1918 (merged, PR #1947): #1918 added `probeICMP`
   155	  real-liveness to the **GRE keepalive** path (`keepaliveLoop`,
   156	  `probeICMP` at :1024). WG tunnels never run keepalives
   157	  (`applyWireguardTunLocked` never calls `startKeepalive`). So the #1918
   158	  change does not interact with this fix; the rebase is clean (plan
   159	  already branched off post-#1918 master @ ee3f336d3). No conflict.
   160	
   161	---
   162	
   163	## 3. Root cause (precise)
   164	
   165	Two facts combine:
   166	
   167	1. WG names are deliberately excluded from `ownedNames` and `desired`
   168	   (`tunnel.go:172`), so the removal loop that prunes addresses for
   169	   GRE/IPIP-style tunnels (via `delete(appliedAddrs,name)` + `LinkDel`)
   170	   never fires for WG, AND
   171	2. address reconciliation for WG happens *only* inside
   172	   `applyWireguardTunLocked`, which is driven by the **current config
   173	   list** (`tunnels` arg) — so a removed WG tunnel is simply never
   174	   visited by any address-reconciling code again.
   175	
   176	The persistent-device design (correct) and the address-reconcile-only-
   177	when-configured design (correct for live tunnels) have a **gap exactly
   178	at removal**: nobody owns "this WG device used to be configured, is now
   179	gone from config, but the link must stay — strip its addresses."
   180	
   181	The `appliedAddrs[name]` map is the key asset already in place: it
   182	records exactly which addresses **this manager** applied to each device.
   183	On removal we want to reconcile that device against an **empty desired
   184	address set**, which `reconcileLinkAddrsLocked(link, name, nil,
   185	appliedAddrs[name], …)` already does correctly (delete present-and-not-
   186	wanted, respecting the link-local applied gate). We just need to *call*
   187	it on removal and then drop the tracking entry.
   188	
   189	---
   190	
   191	## 4. Design — Path Options
   192	
   193	The branch point is **how the manager detects "a WG tunnel was removed"
   194	and how it prunes addresses while keeping the link**.
   195	
   196	### Path A — Track previously-configured WG names; diff on removal (RECOMMENDED)
   197	
   198	Add a dedicated WG ownership set `wgConfigured map[string]bool` (analogous
   199	to `ownedNames` but WG-only, and **never** feeding the `LinkDel` removal
   200	loop). Each `Apply`:
   201	
   202	1. Build `wgDesired` = set of `tc.Name` for current `Mode=="wireguard"`.
   203	2. **Prune phase** (new), run alongside the existing GRE removal loop:
   204	   for each `name` in the **old** `wgConfigured` not in `wgDesired`:
   205	   - look up the link (`LinkByName`):
   206	     - On **success**: call the **new dedicated prune helper**
   207	       `pruneAppliedAddrsLocked(link, name, t.appliedAddrs[name])`
   208	       (see r2 design note below). It deletes every present non-link-
   209	       local address (matching the steady-state reconcile's
   210	       non-link-local semantics) plus configured/applied link-locals,
   211	       honoring the same autoconf-fe80 gate, and **returns the set of
   212	       addresses whose `AddrDel` FAILED across ALL families**. **Keep
   213	       the link** — never `LinkDel` (#1432 invariant).
   214	     - If the returned failed-set is **non-empty**: retain
   215	       `t.appliedAddrs[name] = failedSet` and `nextWG[name] = true`
   216	       (retry next apply — mirrors GRE removal-retry at :194-198).
   217	     - If the failed-set is empty (clean prune): `delete(t.appliedAddrs,
   218	       name)` and DROP `name` from `nextWG`.
   219	     - On **`LinkByName` error**: gate on `isLinkNotFound(err)`
   220	       (`pkg/routing/vrf.go:151`). If **not-found** (device genuinely
   221	       gone via manual `ip link del`): `delete(t.appliedAddrs, name)`
   222	       and drop. If a **transient** error (EBUSY/netlink/timeout):
   223	       RETAIN `nextWG[name] = true` and keep `appliedAddrs[name]` so the
   224	       next apply retries — do NOT drop tracking on a transient lookup
   225	       failure (r1 Codex/AGY MAJOR: dropping would forget a still-leaked
   226	       address forever).
   227	   - VRF residual: left as-is (see §4a A1).
   228	3. After the per-tunnel apply loop, set `t.wgConfigured = nextWG`
   229	   (= `wgDesired` ∪ retained-for-retry names).
   230	
   231	#### r2 design note — why a dedicated `pruneAppliedAddrsLocked`, NOT `reconcileLinkAddrsLocked(…, nil, …)`
   232	
   233	r1 review (all three reviewers, MAJOR) proved the original idea —
   234	inferring "AddrDel failed, retry" from `len(remaining)>0` of
   235	`reconcileLinkAddrsLocked` — is **broken**: that function only records a
   236	failed delete into its returned `newApplied` when the address is
   237	**link-local** (`tunnel.go:618`); a failed `AddrDel` of a regular v4/v6
   238	address returns an **empty** set, so the retry signal never fires and the
   239	leaked address is silently dropped from tracking and never retried.
   240	
   241	Two ways to fix; r2 chooses (b):
   242	
   243	- **(a)** change `reconcileLinkAddrsLocked` to also record non-link-local
   244	  failed deletes — REJECTED: that function's return contract is consumed
   245	  by the GRE/anchor/still-configured-WG callers and is carefully
   246	  specified per #1884/#1905; widening its semantics risks rippling into
   247	  those paths.
   248	- **(b CHOSEN)** add a small, removal-only helper
   249	  `pruneAppliedAddrsLocked(link, name, applied) (failed map[string]bool)`
   250	  that:
   251	  1. `AddrList`s the device,
   252	  2. for each present address: skip autoconf/foreign link-local
   253	     (`a.IP.IsLinkLocalUnicast() && (applied==nil || !applied[key])` —
   254	     identical gate to `reconcileLinkAddrsLocked:611`), otherwise
   255	     `AddrDel`,
   256	  3. on `AddrDel` failure record `failed[key]=true` for **every** family
   257	     (the fix — not just link-local),
   258	  4. returns `failed`.
   259	  `reconcileLinkAddrsLocked` is left **untouched** (frozen contract).
   260	

exec
/bin/bash -lc 'rg -n "reconcileLinkAddrsLocked|pruneAppliedAddrsLocked|ensureReconcileStateLocked|clearLocked|wgConfigured|LinkByName|isLinkNotFound|routing-instance-removed|AddrDel|AddrList|autoconf|fe80|link-local|restart" .' in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
./Makefile:14:.PHONY: all generate generate-userspace-xdp build-userspace-xdp build build-ctl build-userspace-dp build-userspace-dp-debug-log proto install clean test audit-check test-connectivity test-failover test-double-failover test-active-active test-stress-failover test-ha-crash test-chained-crash test-private-rg test-restart-connectivity
./Makefile:156:.PHONY: test-env-init test-vm standalone-test-vm test-ct test-deploy test-ssh test-destroy test-status test-start test-stop test-restart test-logs test-journal
./Makefile:187:test-restart:
./Makefile:188:	./test/incus/setup.sh restart
./Makefile:230:# Restart connectivity regression test (verify no transient loss during daemon restart — requires cluster + iperf3 server)
./Makefile:231:test-restart-connectivity:
./Makefile:232:	BPFRX_CLUSTER_ENV=$(CLUSTER_ENV) ./test/incus/test-restart-connectivity.sh
./Makefile:247:.PHONY: cluster-init cluster-create cluster-deploy cluster-destroy cluster-status cluster-ssh cluster-logs cluster-start cluster-stop cluster-restart
./Makefile:248:.PHONY: userspace-cluster-init userspace-cluster-create userspace-cluster-deploy userspace-cluster-destroy userspace-cluster-status userspace-cluster-ssh userspace-cluster-logs userspace-cluster-start userspace-cluster-stop userspace-cluster-restart
./Makefile:277:cluster-restart:
./Makefile:278:	$(CLUSTER_SETUP) restart $(NODE)
./Makefile:289:userspace-cluster-restart: cluster-restart
./Makefile:292:.PHONY: loss-cluster-init loss-cluster-create loss-cluster-deploy loss-cluster-destroy loss-cluster-status loss-cluster-ssh loss-cluster-logs loss-cluster-start loss-cluster-stop loss-cluster-restart
./Makefile:321:loss-cluster-restart:
./Makefile:322:	$(LOSS_CLUSTER_SETUP) restart $(NODE)
./CLAUDE.md:77:make test-restart    # systemctl restart xpfd
./CLAUDE.md:108:make CLUSTER_ENV= cluster-deploy  # Build + push to both legacy VMs + restart
./CLAUDE.md:112:make CLUSTER_ENV= test-restart-connectivity # Verify restart behavior on local regression cluster
./README.md:263:make test-deploy        # Build + deploy + restart service
./userspace-xdp/src/lib.rs:535:    // link-local control plane. Prefer cpumap delivery when available,
./testing-docs/ha-cluster.md:18:`deploy all` already performs a rolling restart. Use
./testing-docs/ha-cluster.md:19:`./test/incus/cluster-setup.sh restart all` only when you are explicitly
./testing-docs/ha-cluster.md:20:testing restart behavior without rebuilding.
./testing-docs/ha-cluster.md:61:## Test 3: Restart Connectivity (`make test-restart-connectivity`)
./testing-docs/ha-cluster.md:63:**What it tests**: Zero packet loss during daemon restart on the primary.
./testing-docs/ha-cluster.md:67:2. Restart xpfd on primary (systemctl restart)
./testing-docs/ha-cluster.md:68:3. Count lost pings during restart window
./testing-docs/ha-cluster.md:72:make test-restart-connectivity
./testing-docs/ha-cluster.md:243:- [ ] After `systemctl restart xpfd` on primary: connectivity recovers within 40s
./testing-docs/failover-testing.md:489:### First probe after restart fails, second succeeds
./testing-docs/failover-testing.md:521:./test/incus/cluster-setup.sh restart all
./testing-docs/README.md:63:- `test/incus/cluster-setup.sh deploy all` builds, pushes, and restarts
./testing-docs/README.md:64:  `xpfd` in a rolling sequence. Do not add an extra manual restart unless you
./testing-docs/README.md:65:  are explicitly testing restart behavior.
./testing-docs/regression-checklist.md:67:- [ ] After restart: host gets IPv6 default route via RA within 30s
./testing-docs/regression-checklist.md:68:- [ ] `ip -6 route show default` on host — exists via stable link-local
./pkg/ra/README.md:39:  the kernel's own duplicate-address detection on the link-local
./testing-docs/userspace-dataplane.md:34:`deploy all` already performs the rolling stop/cleanup/push/restart sequence.
./testing-docs/userspace-dataplane.md:35:Do not manually restart both nodes immediately afterward unless the point of the
./testing-docs/userspace-dataplane.md:36:test is specifically restart behavior.
./testing-docs/userspace-dataplane.md:45:incus exec loss:xpf-userspace-fw0 -- systemctl restart xpfd
./testing-docs/userspace-dataplane.md:56:**Automated** (20 restart cycles):
./testing-docs/userspace-dataplane.md:59:  incus exec loss:xpf-userspace-fw0 -- systemctl restart xpfd
./testing-docs/userspace-dataplane.md:148:**What it tests**: Host receives IPv6 default route via RA after daemon restart.
./testing-docs/userspace-dataplane.md:151:incus exec loss:xpf-userspace-fw0 -- systemctl restart xpfd
./testing-docs/userspace-dataplane.md:156:**Pass criteria**: Default route exists via `fe80::bf72:16:2` (stable link-local).
./testing-docs/userspace-dataplane.md:172:**What it tests**: Host can resolve the firewall's link-local via NDP, and host-bound packets (ping to VIP) are delivered to the kernel.
./testing-docs/ha-failover-validation.md:62:| `2e237a7e` | Suppress stable link-local EADDRNOTAVAIL log spam | `reconcile.go` |
./testing-docs/ha-failover-validation.md:82:   timeout restarted on each rebind and ctrl never enabled. Fixed by
./testing-docs/ha-failover-validation.md:143:### 1.7 `2e237a7e` -- Suppress stable link-local log spam
./testing-docs/ha-failover-validation.md:145:The reconcile tick removes stable link-locals from inactive RG
./testing-docs/ha-failover-validation.md:146:interfaces. When the address does not exist, `netlink.AddrDel` returns
./testing-docs/ha-failover-validation.md:276:default via fe80::bf:72ff:fe02:0102 dev eth0 ...
./testing-docs/performance.md:14:2. Deploy or restart the exact tree you want to measure.
./testing-docs/performance.md:142:For zero-copy restart/bootstrap issues, compare:
./testing-docs/performance.md:145:- daemon restart only
./testing-docs/ha-failover-during-iperf3.md:10:- Stable link-local handoff (IPv6 router identity)
./testing-docs/ha-failover-during-iperf3.md:123:1. **Stable link-local NDP race** — after RG2 failover, the new primary
./testing-docs/ha-failover-during-iperf3.md:124:   must have `fe80::bf72:CC:RR` and the old primary must NOT. If both
./testing-docs/standalone-vm.md:11:make test-deploy       # Build + push + restart
./pkg/ra/sender.go:35:	// after daemon restart, failover, or link flap.
./pkg/ra/sender.go:66:// Ensures a link-local address exists (RETH interfaces suppress auto
./pkg/ra/sender.go:67:// link-local via addr_gen_mode=1, so we add one explicitly with NODAD).
./pkg/ra/sender.go:70:		slog.Warn("ra: failed to ensure link-local", "interface", s.iface.Name, "err", err)
./pkg/ra/sender.go:73:	// Determine NDP bind address: use explicitly configured link-local if set,
./pkg/ra/sender.go:74:	// otherwise default to any link-local on the interface.
./pkg/ra/sender.go:88:		// Re-read interface (link-local may appear after addr add).
./pkg/ra/sender.go:133:	// relearn a default router after xpfd restarts or HA role changes.
./pkg/ra/sender.go:366:// ensureLinkLocal checks whether the interface has a link-local IPv6 address.
./pkg/ra/sender.go:368:// automatic link-local generation, but the RA sender needs one for its NDP
./pkg/ra/sender.go:369:// socket. If no link-local exists, this computes one via EUI-64 from the
./pkg/ra/sender.go:372:	link, err := netlink.LinkByName(iface.Name)
./pkg/ra/sender.go:376:	addrs, err := netlink.AddrList(link, netlink.FAMILY_V6)
./pkg/ra/sender.go:386:	// No link-local. Set addr_gen_mode=0 (EUI-64) so kernel generates one
./pkg/ra/sender.go:393:	// Disable DAD for the link-local — virtual MAC may conflict with peer.
./pkg/ra/sender.go:397:	// Toggle link to trigger link-local generation.
./pkg/ra/sender.go:407:		addrs, _ = netlink.AddrList(link, netlink.FAMILY_V6)
./pkg/ra/sender.go:412:					netlink.AddrDel(link, &a)
./pkg/ra/sender.go:416:				slog.Info("ra: added link-local for RA sender",
./pkg/ra/sender.go:423:	return fmt.Errorf("link-local did not appear after addr_gen_mode=0 + link toggle")
./pkg/ra/ra.go:36:		return m.clearLocked()
./pkg/ra/ra.go:64:			slog.Info("ra: restarting sender", "interface", name)
./pkg/ra/ra.go:116:// restarts but the original startup burst was lost during the link DOWN.
./pkg/ra/ra.go:181:	return m.clearLocked()
./pkg/ra/ra.go:184:func (m *Manager) clearLocked() error {
./docs/userspace-performance-plan.md:359:- After restart, BPF map reflects only active synced sessions
./docs/userspace-xdp-pass-bootstrap-and-ipv6.md:5:**Related issues:** Zero-copy fill ring starvation, IPv6 forwarding broken on VLAN interfaces, 40s restart gap
./docs/userspace-xdp-pass-bootstrap-and-ipv6.md:9:After daemon restart on the userspace HA cluster (`loss:xpf-userspace-fw0/fw1`), three problems existed:
./docs/userspace-xdp-pass-bootstrap-and-ipv6.md:11:1. **IPv4 forwarding dead for 40+ seconds** after restart, even though VRRP election should provide failover in ~1s
./docs/userspace-xdp-pass-bootstrap-and-ipv6.md:61:**Fix:** `syncLocalAddressMapsLocked()` in `manager.go` now enumerates ALL kernel addresses via `netlink.AddrList(nil, family)`, including dynamically added VIPs. This runs periodically in the status update loop.
./docs/userspace-xdp-pass-bootstrap-and-ipv6.md:83:The readiness gate blocked VRRP election until the peer's bulk session sync was received. The timeout was 30 seconds. In a restart scenario, the peer is clearly alive (heartbeat received within ~1s), but the reverse bulk sync from the peer can take 10-30+ seconds depending on TCP reconnection timing.
./docs/userspace-xdp-pass-bootstrap-and-ipv6.md:98:With both nodes running the new code, fw1 takes over in ~2.25s and forwards traffic while fw0 restarts. When fw0 comes back (after ~14s), it preempts fw1 and resumes as primary.
./docs/userspace-xdp-pass-bootstrap-and-ipv6.md:127:# Restart test: start ping, restart fw0, measure gap
./cmd/cli/shared.go:225:		// would leak the daemon-side config lock until daemon restart.
./docs/userspace-cold-start-fix-plan.md:37:Until we do that, cold start remains sensitive to timing and restart order.
./docs/userspace-cold-start-fix-plan.md:166:post-restart behavior harder to reason about.
./docs/userspace-cold-start-fix-plan.md:383:1. daemon restart with empty/stale neighbor table
./docs/userspace-cold-start-fix-plan.md:386:4. HA restart with VIP delay
./pkg/dataplane/dataplane.go:412:	// Hitless restart: delete stale entries
./docs/fabric-cross-chassis-fwd.md:58:- Fabric interface ifindex + local MAC via `netlink.LinkByName()`
./docs/testing-procedures.md:12:| Restart | `make test-restart-connectivity` | ~30s | Shutdown/startup changes |
./docs/testing-procedures.md:100:### 6. Restart Connectivity Test (`make test-restart-connectivity`)
./docs/testing-procedures.md:102:Validates zero packet loss during daemon restart (hitless restart).
./docs/testing-procedures.md:109:**Workaround:** Manually run `rm -rf /etc/xpf/.configdb` on VMs before restart.
./docs/testing-procedures.md:122:2. If stale: `rm -rf /etc/xpf/.configdb && systemctl restart xpfd`
./docs/testing-procedures.md:136:4. Force reconcile: `systemctl restart xpfd`
./pkg/dataplane/loader_userspace_shim.go:35:// pinnedMaps lists maps that survive daemon restarts via BPF
./userspace-dp/src/protocol/control.rs:167:    /// (fatal — warming disabled until restart). Both are the only
./scripts/image/incus-agent-setup:30:    # This will typically be true during restart in the case of a cdrom-based setup.
./docs/testing.md:92:make test-deploy    # build -> push -> install -> restart
./docs/testing.md:140:| During hitless restart | ~25 Gbps | zero drop across 3 restarts |
./docs/testing.md:203:Daemon restart with zero session loss and zero packet loss via legacy BPF
./docs/testing.md:220:# 3. While iperf3 is running, restart daemon multiple times
./docs/testing.md:221:sg incus-admin -c 'incus exec xpf-fw -- systemctl restart xpfd'
./docs/testing.md:223:sg incus-admin -c 'incus exec xpf-fw -- systemctl restart xpfd'
./docs/testing.md:225:sg incus-admin -c 'incus exec xpf-fw -- systemctl restart xpfd'
./docs/testing.md:238:- Sessions visible in CLI after restart
./docs/testing.md:242:- 3 restarts during 40-second iperf3: 25.3 Gbps average, zero drops
./docs/testing.md:243:- Sessions survived all restarts
./docs/testing.md:256:├── sessions          # IPv4 conntrack (survives restart)
./docs/testing.md:257:├── sessions_v6       # IPv6 conntrack (survives restart)
./docs/testing.md:258:├── dnat_table        # Reverse DNAT mappings (survives restart)
./docs/testing.md:259:├── dnat_table_v6     # IPv6 reverse DNAT (survives restart)
./docs/testing.md:260:├── nat64_state       # NAT64 session state (survives restart)
./docs/testing.md:261:└── nat_port_counters # SNAT port tracking (survives restart)
./docs/testing.md:281:The flow below describes the pre-#1476 daemon-restart behaviour for the
./docs/testing.md:283:userspace dataplane (`userspace-dp`) handles restart via shim-only
./docs/testing.md:426:- IPv6 default route via link-local gateway
./docs/testing.md:483:# Expected: "ipv6 route ::/0 fe80::50 ge-0-0-1.50 5"
./docs/testing.md:485:# Expected: "via fe80::50 dev ge-0-0-1.50" (NOT dev ge-0-0-1)
./docs/testing.md:551:Tests that transit traffic (SNAT'd through firewall) survives daemon restart with
./docs/testing.md:555:**Background:** After restart, FIB cache in session entries is stale. `bpf_fib_lookup`
./docs/testing.md:564:# After 5 seconds, restart primary
./docs/testing.md:566:sg incus-admin -c 'incus exec xpf-fw0 -- systemctl restart xpfd'
./docs/testing.md:570:# IPv6: ping gateway through restart
./docs/testing.md:573:sg incus-admin -c 'incus exec xpf-fw0 -- systemctl restart xpfd'
./docs/testing.md:578:1. BPF programs are pinned — they keep processing packets during restart
./pkg/dataplane/maps_nat.go:404:// random offset. This prevents SNAT port reuse after daemon restart — without
./pkg/dataplane/maps_nat.go:406:// servers may still have in ESTABLISHED state from pre-restart sessions.
./docs/image-validation.md:256:#         for RG1/RG2; no session loss for the synced flows. Then restart
./userspace-dp/src/protocol/binding.rs:109:    /// restart the daemon for the dead worker's bindings to recover.
./scripts/image/bake.py:315:        # #1930 INC-0: the needrestart blacklist for xpfd is ALREADY shipped by
./scripts/image/bake.py:316:        # the package (debian/xpf.needrestart -> /etc/needrestart/conf.d/xpf.conf,
./scripts/image/bake.py:318:        # ($nrconf{override_rc}{qr(...)} = 0), which preserves needrestart's
./scripts/image/bake.py:321:        # /etc/needrestart/conf.d before the .deb creates it would fail the bake.
./docs/userspace-fabric-redirect-fix.md:57:   redirect without stopping/restarting workers (no full reconcile).
./pkg/dataplane/loader.go:456:// On restart, reuses a previously pinned link and atomically replaces the program.
./pkg/dataplane/loader.go:536:	// Pin the link for future restarts.
./pkg/dataplane/loader.go:1012:// On restart, reuses a previously pinned link and atomically replaces the program.
./pkg/dataplane/loader.go:1049:	// Pin the link for future restarts.
./pkg/dataplane/loader.go:1137:// hitless restarts — sessions survive and XDP/TC programs keep running.
./pkg/dataplane/loader.go:1161:// the dataplane — use when decommissioning, not during normal restarts.
./docs/feature-gaps.md:263:xpf has static routes, generate/aggregate routes, ECMP, VRFs, GRE tunnels, IPIP tunnels (IPv4+IPv6), rib-groups, next-table route leaking, PBR, qualified-next-hop with interface (link-local IPv6), per-instance `rib <name>.inet6.0` IPv6 static routes, and FRR integration (OSPF, BGP, IS-IS, RIP, LLDP). These are additional routing features.
./docs/feature-gaps.md:268:| **Graceful Restart** | `routing-options graceful-restart` | Non-stop routing during control plane restart. Keep forwarding while protocols reconverge. FRR supports GR. | Medium | Missing (FRR has GR but xpf doesn't configure it) |
./docs/feature-gaps.md:309:| **In-Service Software Upgrade (ISSU)** | `request system software in-service-upgrade ...` | Upgrade software without traffic interruption using cluster failover | Low | Done (`ForceSecondary()` drains all RGs to peer, operator replaces binary + restarts) |
./docs/session-sync-architecture.md:263:When the event stream is disconnected (helper restart, startup race), the
./docs/dpdk-dataplane.md:601:**Problem:** DPDK process restart loses all NIC state.
./docs/dpdk-dataplane.md:603:- Use hugepage-backed shared memory (survives process restart)
./docs/dpdk-dataplane.md:606:- Brief packet loss during worker restart (unavoidable)
./scripts/image/validate.py:243:        incus("restart", "xpf-image-b")
./docs/cos/cos-traffic-shaping-review-v1.md:469:- worker restart
./docs/phases.md:175:- setup.sh: start/stop/restart/logs/journal commands
./docs/phases.md:176:- Makefile: test-start/stop/restart/logs/journal targets
./docs/phases.md:200:- 25+ Gbps sustained, zero drops during restarts
./docs/phases.md:520:- **BGP graceful-restart:** Parsed + compiled to FRR config
./docs/phases.md:711:  - **Interface monitoring:** Uses `netlink.LinkByName()` to check `OperState`/`Flags`, calls `SetMonitorWeight()` on change
./docs/phases.md:957:- Commands: init, create, destroy, deploy [0|1|all], ssh 0|1, status, logs, start/stop/restart
./docs/phases.md:1197:- **gRPC:** SystemAction `"in-service-upgrade"` → ForceSecondary() → response with instructions to replace binary + restart
./docs/phases.md:1239:  - Filters out link-local IPv6 (fe80::) — not useful for GARP/NA
./docs/phases.md:1270:| `pkg/cluster/reth.go` | +8 | RethIPs dual-stack (FAMILY_ALL, skip link-local) |
./docs/phases.md:1331:- Tests: TCP send/receive, TCP reconnect after server restart, TLS with self-signed cert
./docs/phases.md:1446:- **Reload over restart:** `vrrp.Apply()` sends SIGHUP when keepalived is already running; only starts if not running
./docs/phases.md:1456:- **Why link-local 169.254.x.x base:** Keepalived removes VIPs on FAULT/BACKUP state transitions; using the same address as both static networkd and VRRP VIP caused keepalived to delete the networkd-assigned address, then refuse to start ("no IPv4 address")
./docs/phases.md:1578:- **`pkg/vrrp/manager.go`** — Manages all VRRP instances and shared raw socket (`ip4:112`). Multicast group join/leave (224.0.0.18) per interface. Receiver goroutine dispatches packets by VRID. `UpdateInstances()` diffs desired vs current, adds/removes/restarts instances. `States()` returns instant state map. `Status()` returns formatted multi-line status.
./docs/phases.md:1609:- **Instant priority updates:** `UpdateInstances()` diffs and restarts only changed instances (vs regenerating keepalived.conf + SIGHUP)
./docs/phases.md:1722:Reduced chassis cluster failover from ~3.2s to <1s and failback from ~6s to ~3s by tuning all control plane timers. The BPF data plane already continued forwarding during daemon restart (pinned links + PROG_ARRAY); all bottlenecks were in VRRP timers, heartbeat detection, session sync reconnection, and event debounce.
./docs/phases.md:1755:- **Impact:** 4s faster crash recovery restart
./docs/phases.md:2165:2. Current primary restarts
./docs/phases.md:2529:- Config apply path now detects HA transport config changes, cancels existing comms context, restarts with new settings
./docs/phases.md:2537:- **Runtime reconfigurability:** One-shot initialization of cluster comms is insufficient — must detect config changes and restart endpoints
./docs/phases.md:2542:- `resolveNeighbors()` → `addByName()` → `LinkByName()` failed silently on Junos names
./docs/phases.md:2651:Replaced direct `/etc/resolv.conf` writes with `/etc/systemd/resolved.conf.d/xpf.conf` drop-in + `systemctl restart systemd-resolved`. Avoids conflict with systemd-resolved management of resolv.conf.
./docs/phases.md:2766:### Fix #127: IPVLAN address reconciliation on restart
./docs/phases.md:2768:**Problem:** `ensureFabricIPVLAN()` returns early when the IPVLAN interface already exists (survives daemon restart), skipping IP address reconciliation. After restart, fab0/fab1 may lack addresses → fabric sync broken.
./docs/phases.md:2772:**Key insight:** IPVLAN interfaces survive daemon restart but their addresses may be lost (networkd reload, link cycling). Must treat address config as idempotent.
./docs/phases.md:2837:**Problem:** `syncReady` is latched to `true` after the first successful bulk sync and never reset. When peer disconnects and reconnects (e.g., daemon restart, network partition recovery), bulk sync is skipped because `syncReady` is still true. Reconnected peer may have empty/stale session table.
./docs/optimizations.md:187:- 1s (was 5s) — faster crash recovery restart
./pkg/dataplane/compiler.go:75:	// ifCache avoids redundant net.InterfaceByName and netlink.LinkByName
./pkg/dataplane/compiler.go:116:// cachedLinkByName returns a cached netlink.Link, performing the
./pkg/dataplane/compiler.go:118:func (r *CompileResult) cachedLinkByName(name string) (netlink.Link, error) {
./pkg/dataplane/compiler.go:122:	link, err := netlink.LinkByName(name)
./pkg/dataplane/compiler.go:150:// The isRecompile flag triggers FIB generation bump for hitless restarts.
./pkg/dataplane/compiler.go:180:	// Sort names for deterministic IDs across restarts — existing sessions
./pkg/dataplane/compiler.go:452:	// Process individual addresses (sorted for deterministic IDs across restarts)
./pkg/dataplane/compiler.go:637:// resolveAddrList resolves a list of address names to a single address ID.
./pkg/dataplane/compiler.go:641:func resolveAddrList(dp DataPlane, names []string, result *CompileResult) (uint32, error) {
./pkg/dataplane/compiler.go:809:			srcID, err := resolveAddrList(dp, pol.Match.SourceAddresses, result)
./pkg/dataplane/compiler.go:816:			dstID, err := resolveAddrList(dp, pol.Match.DestinationAddresses, result)
./pkg/dataplane/compiler.go:941:			srcID, err := resolveAddrList(dp, pol.Match.SourceAddresses, result)
./pkg/dataplane/compiler.go:947:			dstID, err := resolveAddrList(dp, pol.Match.DestinationAddresses, result)
./pkg/dataplane/compiler.go:1616:		link, err = result.cachedLinkByName(ifName)
./pkg/dataplane/compiler.go:1618:		link, err = netlink.LinkByName(ifName)
./pkg/dataplane/compiler.go:1669:		link, err = result.cachedLinkByName(ifName)
./pkg/dataplane/compiler.go:1671:		link, err = netlink.LinkByName(ifName)
./test/incus/setup.sh:307:	incus restart "$INSTANCE_NAME"
./test/incus/setup.sh:451:cmd_restart() {
./test/incus/setup.sh:452:	incus exec "$INSTANCE_NAME" -- systemctl restart xpfd
./test/incus/setup.sh:453:	info "xpfd restarted"
./test/incus/setup.sh:494:	echo "Usage: $0 {init|create-vm|create-ct|destroy|deploy|ssh|status|start|stop|restart|logs|journal}"
./test/incus/setup.sh:506:	echo "  restart     Restart xpfd service"
./test/incus/setup.sh:522:	restart)    cmd_restart ;;
./debian/xpf.postinst:105:                    # restarts. But a flip/daemon-reload error between STOP
./debian/xpf.postinst:110:                        echo "xpf: unit not active after a failed cut-over; restarting" >&2
./debian/xpf.postinst:112:                            echo "xpf: WARNING could not restart xpfd; run: xpfd upgrade" >&2
./docs/xpf-userspace-fw-deploy-verification.md:139:  helper died and isn't being restarted.
./docs/development-workflow.md:234:  retransmits after any daemon restart.
./docs/archived/userspace-failover-hardening-plan.md:414:- The node restarts cluster heartbeat after VRF rebind.
./docs/archived/userspace-failover-hardening-plan.md:420:- That recompile restarts cluster transport and destabilizes sync/fabric readiness while the survivor is already primary.
./docs/archived/userspace-failover-hardening-plan.md:498:  restarting cluster comms.
./docs/archived/userspace-failover-hardening-plan.md:559:- cluster heartbeat restart
./docs/archived/userspace-failover-hardening-plan.md:994:  daemon restart occurs
./docs/userspace-afxdp-idle-softirq-starvation.md:29:### 2. Shared-UMEM restart regression
./docs/userspace-afxdp-idle-softirq-starvation.md:35:After the spare-frame change, the same worker used `28672` descriptors. mlx5 then rejected `fq/cq` creation with `EINVAL`, so the helper came up disarmed or unbound after restart.
./docs/userspace-afxdp-idle-softirq-starvation.md:37:Symptoms of the restart regression:
./docs/in-place-upgrade.md:92:   (60s default). The cut just restarted xpfd, so the local gRPC socket
./docs/in-place-upgrade.md:132:raw push+restart path (and `XPF_DEPLOY_FAST`) is unchanged for the dev
./docs/in-place-upgrade.md:163:- **No true zero-gap standalone restart.** The helper is an `exec.Command`
./docs/test_env.md:48:- Static IPv6: 2001:559:8585:50::5/64, default route via fe80::50 on enp10s0f0np0.50
./docs/test_env.md:275:1. **Hitless restart with VRF**: VRF device and interface binding survive restart
./docs/test_env.md:296:# Start iperf3, restart daemon 3x during, verify zero drops
./docs/test_env.md:298:for i in 1 2 3; do sleep 8; sg incus-admin -c 'incus exec xpf-fw -- systemctl restart xpfd'; done
./docs/test_env.md:371:./cluster-setup.sh start|stop|restart [0|1|all]
./docs/test_env.md:381:7. Preempt: restart fw0 → fw0 reclaims primary
./docs/test_env.md:438:# Expected: "ipv6 route ::/0 fe80::50 ge-0-0-1.50 5"
./docs/test_env.md:441:# Expected: "via fe80::50 dev ge-0-0-1.50" (NOT dev ge-0-0-1)
./docs/test_env.md:557:sg incus-admin -c 'incus restart xpf-fw1'
./docs/test_env.md:564:sg incus-admin -c 'incus restart xpf-fw0'
./docs/test_env.md:571:sg incus-admin -c 'incus restart xpf-fw0' &
./docs/test_env.md:572:sg incus-admin -c 'incus restart xpf-fw1' &
./docs/test_env.md:596:make test-start/stop/restart  # Service lifecycle
./docs/session-history.md:172:### Prompt 14: Hitless restarts (daemon restart should not drop sessions)
./docs/session-history.md:212:### Prompt 17: VRF routing, systemd-networkd, hitless restart hardening
./docs/session-history.md:220:**SNAT Session Fix** (`a030446`): SNAT TCP sessions were dying on daemon restart. Root cause: `dnat_table` entries needed to be written BEFORE clearing sessions so existing sessions could still resolve their DNAT state.
./docs/session-history.md:430:**Routing Enhancements** (`060fa52` -- `383173c`): OSPF area types, route-reflector, reference-bandwidth, BGP graceful-restart, IS-IS wide-metrics/overload, BGP multipath/default-originate, passive-interface default, network type, route-map attributes, OSPFv3.
./docs/session-history.md:591:**VRRP Fixes** (`7151a5b`): Idempotent bond creation, link-local base addresses (169.254.RG.NODE/32).
./docs/session-history.md:740:- Hitless restarts: zero packet drops
./debian/rules:80:	install -d debian/xpf/etc/needrestart/conf.d
./debian/rules:81:	install -m 0644 debian/xpf.needrestart \
./debian/rules:82:	                debian/xpf/etc/needrestart/conf.d/xpf.conf
./debian/rules:114:# Disable the auto-restart-on-upgrade block dh_installsystemd would
./debian/rules:118:# documented directive (--no-restart-on-upgrade is a deprecated alias).
./docs/session-sync-design.md:549:restart. Events accumulated during pause are flushed in order.
./docs/memory.md:80:- **Fabric IPVLAN fixes (#127-#130):** Address reconciliation on restart (not just create), stale overlay cleanup wired in, neighbor probe on overlay not parent, compiler dual-fabric auto-detect
./docs/memory.md:162:- DHCP uses `context.Background()` — prevents address removal on restart
./docs/memory.md:166:- **Deploy restart:** `systemctl stop` → `xpfd cleanup` → push binary → start. SO_REUSEADDR+SO_REUSEPORT for rebind
./docs/archived/ha-forwarding-state-inventory.md:278:- **Impact if missing:** No impact on correctness -- allocator restarts
./docs/reth-mac.md:7:1. **IPv6 link-local addresses differ** -- EUI-64 link-local (`fe80::...`) is derived from MAC. After failover, the new primary has a different link-local address, breaking neighbor caches on LAN hosts.
./docs/reth-mac.md:8:2. **Neighbor cache invalidation** -- Clients must update both VIP->MAC and gateway link-local->MAC mappings. Unsolicited NA only covers the VIP.
./docs/reth-mac.md:13:Program a deterministic virtual MAC on RETH physical member interfaces at daemon startup. Both nodes present the same MAC for each RETH, making IPv6 link-local addresses identical and eliminating neighbor cache issues.
./docs/reth-mac.md:31:- reth0 (RG1): `02:bf:72:01:01:00` -> link-local `fe80::bf:72ff:fe01:100`
./docs/reth-mac.md:32:- reth1 (RG2): `02:bf:72:01:02:00` -> link-local `fe80::bf:72ff:fe01:200`
./docs/reth-mac.md:66:- **IPv6 link-local**: both nodes derive the same `fe80::bf:72ff:fe01:RR00` -- seamless failover
./debian/xpf.needrestart:1:# xpf (#1917 §6.3c): keep needrestart from auto-restarting xpfd.
./debian/xpf.needrestart:3:# Ubuntu server installs needrestart by default; at the end of an apt
./debian/xpf.needrestart:5:# auto-restarts their services. That would cut the dataplane mid-apt
./debian/xpf.needrestart:11:#      running binary is not deleted and needrestart has nothing to
./debian/xpf.needrestart:14:#      future layout exposes a deleted-binary condition, needrestart
./debian/xpf.needrestart:15:#      never restarts the dataplane. The verified cut-over is driven
./debian/xpf.needrestart:17:#      needrestart.
./docs/research/1919-wg-addr-route-prune/claude-smr-plan-r1.md:9:## F1 (MAJOR, CORRECTNESS) — the AddrDel-failure retry signal is broken for non-link-local addresses
./docs/research/1919-wg-addr-route-prune/claude-smr-plan-r1.md:11:The plan (§5) detects "AddrDel failed, retain for retry" via:
./docs/research/1919-wg-addr-route-prune/claude-smr-plan-r1.md:13:remaining := t.reconcileLinkAddrsLocked(link, name, nil, t.appliedAddrs[name], "wireguard tun")
./docs/research/1919-wg-addr-route-prune/claude-smr-plan-r1.md:17:But `reconcileLinkAddrsLocked` (`tunnel.go:584-645`) builds `newApplied`
./docs/research/1919-wg-addr-route-prune/claude-smr-plan-r1.md:18:as: successful **adds** + **present-and-wanted** + **link-local whose
./docs/research/1919-wg-addr-route-prune/claude-smr-plan-r1.md:24:  || !applied[key])` → skip. Otherwise `AddrDel`. **On AddrDel failure**
./docs/research/1919-wg-addr-route-prune/claude-smr-plan-r1.md:25:  the ONLY path that records into `newApplied` is the link-local guard at
./docs/research/1919-wg-addr-route-prune/claude-smr-plan-r1.md:28:  if delErr := t.ops.AddrDel(link, &a); delErr != nil {
./docs/research/1919-wg-addr-route-prune/claude-smr-plan-r1.md:35:  A **regular (non-fe80) address whose AddrDel failed is NOT recorded**.
./docs/research/1919-wg-addr-route-prune/claude-smr-plan-r1.md:38:**Therefore**: when AddrDel of a normal v4/v6 address (e.g.
./docs/research/1919-wg-addr-route-prune/claude-smr-plan-r1.md:39:`172.16.0.1/30`) fails during the prune, `reconcileLinkAddrsLocked`
./docs/research/1919-wg-addr-route-prune/claude-smr-plan-r1.md:50:not carry non-link-local delete failures.
./docs/research/1919-wg-addr-route-prune/claude-smr-plan-r1.md:55:  the prune `reconcileLinkAddrsLocked` call, **re-list** the link's
./docs/research/1919-wg-addr-route-prune/claude-smr-plan-r1.md:62:  `reconcileLinkAddrsLocked`'s asymmetric return contract.
./docs/research/1919-wg-addr-route-prune/claude-smr-plan-r1.md:64:  `reconcileLinkAddrsLocked`) that deletes every manager-applied address
./docs/research/1919-wg-addr-route-prune/claude-smr-plan-r1.md:66:  link-local). Keep `reconcileLinkAddrsLocked` untouched (it has a
./docs/research/1919-wg-addr-route-prune/claude-smr-plan-r1.md:72:Recommend **F1-b** — a small `pruneAppliedAddrsLocked(link, name)` that
./docs/research/1919-wg-addr-route-prune/claude-smr-plan-r1.md:81:(`AddrList`), not by iterating `appliedAddrs[name]`. So the prune will
./docs/research/1919-wg-addr-route-prune/claude-smr-plan-r1.md:82:attempt to delete EVERY non-link-local address currently on the device,
./docs/research/1919-wg-addr-route-prune/claude-smr-plan-r1.md:89:blocker, but the plan should STATE that the prune deletes all non-fe80
./docs/research/1919-wg-addr-route-prune/claude-smr-plan-r1.md:93:owns the full non-link-local set). Add one sentence to §5.
./docs/research/1919-wg-addr-route-prune/claude-smr-plan-r1.md:116:`clearLocked` (`:1086-1113`) resets `ownedNames/appliedAddrs/appliedRI`
./docs/research/1919-wg-addr-route-prune/claude-smr-plan-r1.md:117:to nil. The plan adds `wgConfigured=nil` there — required, else a
./docs/research/1919-wg-addr-route-prune/claude-smr-plan-r1.md:120:`ensureReconcileStateLocked` (`:139-152`) must init `wgConfigured` — plan
./docs/research/1919-wg-addr-route-prune/claude-smr-plan-r1.md:130:## F7 (MINOR) — restart-adoption boundary R5 acceptable but undertested
./docs/research/1919-wg-addr-route-prune/claude-smr-plan-r1.md:133:`wgConfigured` starts empty) is a real boundary. It is consistent with
./docs/research/1919-wg-addr-route-prune/claude-smr-plan-r1.md:138:AddrDel) so the deferral is encoded, not just prose. Add to §6.
./docs/research/1919-wg-addr-route-prune/claude-smr-plan-r1.md:154:retry-on-AddrDel-failure signal is wired to a return value
./docs/research/1919-wg-addr-route-prune/claude-smr-plan-r1.md:155:(`reconcileLinkAddrsLocked`'s `newApplied`) that does not record failed
./docs/research/1919-wg-addr-route-prune/claude-smr-plan-r1.md:156:deletes of non-link-local addresses, so a transient AddrDel failure
./docs/research/1919-wg-addr-route-prune/claude-smr-plan-r1.md:159:all-family failed-delete set, and add the F7 restart-boundary test and
./docs/per-5-tuple/state.md:399:interface names can be renamed or absent during dataplane restarts.
./docs/wg-interop-runbook.md:65:## The restart runbook (TAI64N)
./docs/wg-interop-runbook.md:69:its own after an xpfd restart, flush the kernel peer's WG state** so
./docs/wg-interop-runbook.md:81:sane NTP clock a restart usually recovers WITHOUT the flush
./docs/wg-interop-runbook.md:82:(post-restart timestamps are naturally higher). The flush guards the
./docs/wg-interop-runbook.md:118:| WG tunnel removed from config leaks the wgN TUN until `ip link del`/restart | S2a persistent-TUN tradeoff | S6; harness teardown deletes it |
./docs/wg-interop-runbook.md:146:  xpfd restart/deploy, fw0 comes up SECONDARY on ALL redundancy groups
./docs/wg-interop-runbook.md:160:  harness preflight self-cleans the leaked TUN and P1 restarts xpfd if
./docs/bug-heartbeat-vrf-rebind-split-brain.md:56:00:09:00.750  restarting heartbeat after VRF rebind
./docs/bug-heartbeat-vrf-rebind-split-brain.md:64:### Addendum (#1792, 2026-06): restart-window liveness hardening
./docs/bug-heartbeat-vrf-rebind-split-brain.md:69:1. **Peer side — no grace during our restart.** The bind-retry loop can
./docs/bug-heartbeat-vrf-rebind-split-brain.md:79:   mid-restart still fails over. **Residual gap:** if the sync TCP
./docs/bug-heartbeat-vrf-rebind-split-brain.md:80:   connection is also down or silent for >2 s during a >500 ms restart,
./docs/bug-heartbeat-vrf-rebind-split-brain.md:87:2. **Local side — peer death during restart was never detected.** The
./docs/bug-heartbeat-vrf-rebind-split-brain.md:92:   in-process restart), so a peer that dies while our sockets are down
./docs/bug-heartbeat-vrf-rebind-split-brain.md:93:   is detected once the post-restart 30 s startup grace expires. The
./docs/bug-heartbeat-vrf-rebind-split-brain.md:148:config. On restarts where the RETH MAC was already set (from previous boot),
./docs/bug-heartbeat-vrf-rebind-split-brain.md:218:   link-local multicast) on the fabric overlay. This is more reliable than
./docs/bug-heartbeat-vrf-rebind-split-brain.md:224:   interface. Finds any non-local link-local neighbor entry — that's the
./docs/bug-heartbeat-vrf-rebind-split-brain.md:247:3. fw0 recovers, heartbeat restarts correctly (Bug 1: fixed). But fabric never
./docs/userspace-xdp-mode-and-cold-start-findings.md:131:- the cleanest live repro for `#288` is a helper restart where the kernel still
./docs/userspace-xdp-mode-and-cold-start-findings.md:134:- in the current lab, the restart sequence has not preserved that neighbor
./pkg/dataplane/compiler_test.go:620:			1: {Addresses: []string{"10.0.2.1/24", "fe80::1/64"}}, // link-local, not global
./pkg/dataplane/compiler_test.go:628:	// fe80::1 is link-local, should be skipped
./pkg/dataplane/compiler_test.go:630:		t.Errorf("v6 count = %d, want 0 (link-local skipped)", len(v6))
./test/incus/step1-histogram-classify.py:230:    # Catches daemon restarts, counter resets, and corruption that would
./docs/research/1919-wg-addr-route-prune/agy-plan-r1.md:11:### (1) Retry Signal for Regular Addresses on AddrDel Failure (Broken)
./docs/research/1919-wg-addr-route-prune/agy-plan-r1.md:14:  remaining := t.reconcileLinkAddrsLocked(link, name, nil, t.appliedAddrs[name], "wireguard tun")
./docs/research/1919-wg-addr-route-prune/agy-plan-r1.md:17:      nextWG[name] = true // AddrDel failed → retry next apply
./docs/research/1919-wg-addr-route-prune/agy-plan-r1.md:23:  if delErr := t.ops.AddrDel(link, &a); delErr != nil {
./docs/research/1919-wg-addr-route-prune/agy-plan-r1.md:30:* **Verdict**: **CONFIRMED (Broken)**. If `AddrDel` fails for a regular (non-link-local) address, `newApplied[key] = true` is skipped at line 618. The address is omitted from `newApplied` (which is returned as `remaining`). Consequently, `len(remaining)` will be `0` (unless a link-local delete also failed), and the prune loop will execute `delete(t.appliedAddrs, name)` and skip adding `name` to `nextWG`. The retry signal for regular addresses is broken.
./docs/research/1919-wg-addr-route-prune/agy-plan-r1.md:32:### (2) Handling of LinkByName Failures (Defective)
./docs/research/1919-wg-addr-route-prune/agy-plan-r1.md:35:  if link, err := t.ops.LinkByName(name); err == nil {
./docs/research/1919-wg-addr-route-prune/agy-plan-r1.md:40:* **Source Reality**: [pkg/routing/vrf.go:155](file:///home/ps/git/bpfrx/pkg/routing/vrf.go#L155) provides `isLinkNotFound(err)` to isolate link absence.
./docs/research/1919-wg-addr-route-prune/agy-plan-r1.md:41:* **Verdict**: **CONFIRMED (Defective)**. Any transient error (e.g. netlink buffer exhaustion, timeout) from `LinkByName` causes the code to jump to `delete(t.appliedAddrs, name)` and drop the tracking entry without retry. Because the persistent `wgN` link survives, the addresses survive on the interface but are forgotten by the daemon.
./docs/research/1919-wg-addr-route-prune/agy-plan-r1.md:44:  link, err := t.ops.LinkByName(name)
./docs/research/1919-wg-addr-route-prune/agy-plan-r1.md:46:      if !isLinkNotFound(err) {
./docs/research/1919-wg-addr-route-prune/agy-plan-r1.md:57:  - §4 Path A: "...strips manager-applied addresses (empty desired set), honoring the link-local applied gate..."
./docs/research/1919-wg-addr-route-prune/agy-plan-r1.md:62:      // Kernel-managed or foreign link-local: never delete.
./docs/research/1919-wg-addr-route-prune/agy-plan-r1.md:66:* **Verdict**: **CONFIRMED (Overclaim)**. The `applied` check only gates link-local unicast addresses. For any regular (non-link-local) address on the interface, the gate is bypassed. Running `reconcileLinkAddrsLocked(..., nil, ...)` deletes ALL stale non-link-local addresses on the link, whether they were manager-applied or manually configured.
./docs/research/1919-wg-addr-route-prune/agy-plan-r1.md:79:* **Plan Claim**: §8 R5: "on a fresh daemon, `wgConfigured` is empty... same restart-adoption limitation the rest of the file has."
./docs/research/1919-wg-addr-route-prune/agy-plan-r1.md:80:* **Source Reality**: [pkg/routing/tunnel.go:139-152](file:///home/ps/git/bpfrx/pkg/routing/tunnel.go#L139-L152) (`ensureReconcileStateLocked`) initializes empty maps.
./docs/research/1919-wg-addr-route-prune/agy-plan-r1.md:81:* **Verdict**: **OK**. The restart limitation is identical to the rest of the file: tunnels removed while the daemon is down are not in memory, so they are not pruned. This is consistent with existing GRE/IPIP adoption limitations.
./docs/embedded-radvd.md:71:   crashes between write and reload, a stale config persists across restart.
./docs/embedded-radvd.md:245:    1. Open ndp.Conn on interface (link-local address)
./docs/embedded-radvd.md:344:The RA sender must respond with a unicast RA to the solicitor's link-local address (or
./docs/embedded-radvd.md:458:with the router's link-local address.
./docs/userspace-dataplane-architecture.md:369:  helper restart does not. #1449 closes HA behavior as an explicit userspace
./docs/userspace-dataplane-architecture.md:467:still owns helper-restart persistence and the documented mixed-backend rollback
./docs/userspace-dataplane-architecture.md:688:  synchronized. Helper-restart reset and mixed-backend selector parity are
./docs/userspace-dataplane-architecture.md:697:  state, HA/restart continuity, non-drop color actions, and broader perf
./docs/fabric-bridge-tuning.md:68:# Reduce aging time (faster FDB convergence on VM restart)
./docs/userspace-dataplane-gaps.md:44:| Source NAT (pool mode) | Implemented with scoped caveats | IPv4/IPv6 pool address and port allocation. Global `source address-persistent` uses the documented userspace-v1 SHA-256 source-IP hash and is stable only within the AF_XDP backend, pool family, pool order, and pool size. Legacy eBPF uses C-word IPv4 modulo / IPv6 lane-XOR selection (DPDK retired #1525), so new-flow pool address parity is not promised across retained backend transitions. Pool-mode rules with missing pools, empty pools, invalid port ranges, malformed addresses, no address for the packet family, or exhausted live translated tuples fail-closed at the `poll_descriptor.rs` source-NAT call sites before session creation or forwarding, with recent-exception reasons such as `source_nat_pool_missing`, `source_nat_pool_empty`, `source_nat_pool_invalid_port_range`, and `source_nat_pool_exhausted`. Per-pool `persistent-nat` now has snapshot fields and runtime lease reuse keyed by source tuple `(protocol, source IP, source port)` to translated tuple. The lease table is bounded in helper memory, survives compatible in-process snapshot refreshes, and expires after the configured inactivity timeout once no live flow uses the lease. It does not consult Go `PersistentNATTable` and does not survive helper restart. The closed #1449 contract gates HA behavior explicitly: HA configs that reference persistent source-NAT pools are not admitted because leases are not synchronized, and status reports `userspace persistent-nat source pool leases are not HA-synchronized`. Userspace status, CLI summary, and Prometheus expose live-flow, used-port, persistent-lease, allocation, reuse, and exhaustion counters for admitted non-HA pools. |
./docs/userspace-dataplane-gaps.md:51:| Three-color policers | Implemented with caveats | srTCM/trTCM runtime, forwarding-path and flow-cache-hit metering, red drops for `then discard`, status/CLI/Prometheus counters, and compatible in-process snapshot continuity. Unsupported color-aware, non-`discard`, and malformed snapshots now fail closed in Rust if they bypass Go admission. Sharded state, HA/restart continuity decision, full non-drop action propagation, and integration evidence remain production hardening work, not active feature-gap blockers. |
./docs/userspace-dataplane-gaps.md:107:documented contracts: helper restart resets helper-local persistent-NAT
./docs/userspace-dataplane-gaps.md:180:Keep #1377, #1448, #1449, and #1450 closed. SNAT helper-restart reset
./docs/engineering-style.md:399:  | `cluster-setup.sh` deploy/start/stop/restart/create/destroy/init | self-locks (re-execs through `with-cluster.sh`; the build stays outside the lock) |
./docs/engineering-style.md:418:  - **Never hand-roll binary deploys** (`incus file push` + restart
./docs/next-features/dns-proxy.md:216:- failover should restart or rebind the proxy cleanly when ownership changes
./docs/feature-coverage.md:123:| Source NAT (interface + pool) | Interface and pool mode yes; userspace `address-persistent` uses a documented userspace-v1 hash. Non-HA per-pool `persistent-nat` lease reuse and pool exhaustion counters are implemented in helper-local runtime state; HA/restart persistence and cross-backend new-flow parity remain outside the current contract |
./docs/feature-coverage.md:144:non-drop action, and HA/restart continuity work is production hardening
./docs/userspace-libxdp-migration.md:183:### 2026-03-24: repeated lifecycle containment around XSK restart
./docs/userspace-libxdp-migration.md:192:- even with wrapper fixes underway, restart and link-cycle stability was still
./docs/userspace-libxdp-migration.md:197:ownership and restart behavior around the bridge was still not settled.
./docs/userspace-libxdp-migration.md:275:- runtime liveness, startup gating, and restart behavior
./docs/userspace-libxdp-migration.md:325:- restart and rebind behavior
./docs/userspace-libxdp-migration.md:327:- zero-copy restart behavior on `mlx5`
./docs/userspace-libxdp-migration.md:362:- kernel/driver restart behavior
./docs/userspace-libxdp-migration.md:385:4. Keep treating any remaining zero-copy restart issue as a separate runtime
./docs/dns-ownership.md:57:stable across daemon restarts regardless of internal lease map ordering.
./docs/dns-ownership.md:86:  renewal (and the next daemon restart) restores it.
./docs/dns-ownership.md:97:- `applySystemDNS` wrote a systemd-resolved drop-in and restarted
./docs/next-features/control-link-only-reth-ownership.md:139:- Peer crash/restart and daemon restart.
./docs/authoritative-backlog.md:103:- Sprint #68: HA fail-closed default + `set chassis cluster hitless-restart` opt-in
./test/incus/wg-interop.sh:57:# Recovery-restart taint counter (Codex PR-review finding 2): the
./test/incus/wg-interop.sh:58:# wedged-apply / leaked-port xpfd restarts keep a run going for
./test/incus/wg-interop.sh:59:# triage, but a restart-recovered run must NOT be presented as clean
./test/incus/wg-interop.sh:166:# After any xpfd restart/deploy fw0 comes up SECONDARY on ALL
./test/incus/wg-interop.sh:174:# EVERY RG to node0 (an xpfd restart on fw0 — including this
./test/incus/wg-interop.sh:175:# harness's own recovery restarts — leaves them all on node1).
./test/incus/wg-interop.sh:263:        warn "$1: cannot read deployed software version (daemon mid-restart?)"
./test/incus/wg-interop.sh:316:    # (#1866); P1's restart fallback handles fw0. On fw1 it is a
./test/incus/wg-interop.sh:389:systemctl restart systemd-networkd; sleep 2"
./test/incus/wg-interop.sh:401:# wgref from scratch — it is ALSO the restart-runbook flush procedure
./test/incus/wg-interop.sh:523:    # restart xpfd for a deterministic clean slate.
./test/incus/wg-interop.sh:526:        warn "EVIDENCE-TAINT: leaked WG control thread pins :${WG_LISTEN_PORT} (#1866) — restarting xpfd"
./test/incus/wg-interop.sh:527:        ish "${FW0}" 'systemctl restart xpfd'
./test/incus/wg-interop.sh:529:        ish "${FW0}" 'systemctl is-active xpfd' | grep -q active || fail "P1: xpfd restart failed"
./test/incus/wg-interop.sh:530:        ensure_wg_mastership "p1-leak" || fail "P1: WG VIP not restored after leak-recovery restart + failback"
./test/incus/wg-interop.sh:547:        # A daemon restart re-applies from the DB at boot, which is
./test/incus/wg-interop.sh:550:        warn "EVIDENCE-TAINT: P1 commit landed but wg0/:${WG_LISTEN_PORT} never appeared — restarting xpfd (wedged apply)"
./test/incus/wg-interop.sh:551:        ish "${FW0}" 'systemctl restart xpfd'
./test/incus/wg-interop.sh:553:        ish "${FW0}" 'systemctl is-active xpfd' | grep -q active || fail "P1: xpfd restart failed"
./test/incus/wg-interop.sh:554:        ensure_wg_mastership "p1-wedge" || fail "P1: WG VIP not restored after wedge-recovery restart + failback"
./test/incus/wg-interop.sh:555:        peer_wg_setup ""   # restart runbook: flush the peer after an xpfd restart
./test/incus/wg-interop.sh:559:                ok=1; log "P1: wg0 up after wedge-recovery restart (t=${t}s)"; break
./test/incus/wg-interop.sh:564:    [ "$ok" = 1 ] || fail "P1: wg0 TUN/:${WG_LISTEN_PORT} not up on fw0 (even after restart)"
./test/incus/wg-interop.sh:726:# P6 — restart recovery + restart runbook.
./test/incus/wg-interop.sh:728:    log "P6: restore initiator config, restart xpfd, runbook flush"
./test/incus/wg-interop.sh:743:    wait_handshake_data_driven "${WG_HANDSHAKE_TIMEOUT_S}" "P6-pre" || fail "P6: pre-restart handshake failed"
./test/incus/wg-interop.sh:744:    # Negative control: restart WITHOUT flushing the peer. TAI64N is
./test/incus/wg-interop.sh:747:    ish "${FW0}" 'systemctl restart xpfd'
./test/incus/wg-interop.sh:749:    ish "${FW0}" 'systemctl is-active xpfd' | grep -q active || fail "P6: xpfd failed to restart"
./test/incus/wg-interop.sh:750:    ensure_wg_mastership "p6" || fail "P6: WG VIP not restored after restart + failback"
./test/incus/wg-interop.sh:781:        || fail "P6: tunnel traffic dead after restart"
./test/incus/wg-interop.sh:782:    pass "P6 restart recovery (${mode})"
./test/incus/wg-interop.sh:870:            warn "${TAINTS} recovery restart(s) used — evidence TAINTED; rerun clean for merge evidence"
./docs/junos-cli-reference.md:686:                                            fe80::8/64
./docs/junos-cli-reference.md:691:                                            fe80::210:dbff:feff:1000/64
./docs/junos-cli-reference.md:694:                                   inet6    fe80::86c1:c10f:fc03:5100
./docs/next-features/vsrx-fabric-fab0-fab1-syntax-compat.md:46:  - fails over sync/config-channel transport between links without restarting cluster state.
./docs/xdp-io-uring-userspace-dataplane.md:138:- a separate native process is easier to pin, restart, rate-limit, and observe
./docs/xdp-io-uring-userspace-dataplane.md:708:- dataplane survives daemon restart
./docs/xdp-io-uring-userspace-dataplane.md:866:- makes restart semantics simpler: control plane can survive while dataplane is restarted
./docs/next-features/ipv6-ha-failover-parity.md:15:- #192: per-node RETH MAC and link-local identity make IPv6 failover weaker than IPv4
./docs/next-features/ipv6-ha-failover-parity.md:34:- default-router role moves separately through Router Advertisements sourced from the interface link-local address
./docs/next-features/ipv6-ha-failover-parity.md:48:- `pkg/daemon/daemon.go`: programs per-node RETH MACs and re-adds link-local addresses
./docs/next-features/ipv6-ha-failover-parity.md:50:Because the MAC differs per node, the derived link-local address also differs per node.
./docs/next-features/ipv6-ha-failover-parity.md:71:The RA sender uses the interface link-local address:
./docs/next-features/ipv6-ha-failover-parity.md:79:- `pkg/daemon/daemon.go`: inactive RG startup-goodbye comments explain that hosts see each node as a separate IPv6 router because each node has a distinct link-local identity
./docs/next-features/ipv6-ha-failover-parity.md:151:- the IPv6 link-local router identity
./docs/next-features/ipv6-ha-failover-parity.md:170:That would make shared MAC and shared link-local more realistic, but it is a larger control-plane and interface-ownership change.
./docs/bugs.md:276:### DHCP context cancellation removes addresses on restart
./docs/bugs.md:297:- Pin file maintains `usercnt > 0` → entries survive → tail calls work → hitless restart
./docs/bugs.md:298:- On restart, new daemon reuses pinned map and atomically updates entries with new program FDs
./docs/bugs.md:301:### Random zone/screen/address/app ID assignment across restarts
./docs/bugs.md:302:- Go `for name := range map` iterates in random order → zone IDs change every restart
./docs/bugs.md:303:- Session entries store zone IDs → stale after restart → policy lookups fail
./docs/bugs.md:343:### SNAT TCP sessions dying on daemon restart (`a030446`)
./docs/bugs.md:345:- On restart, dnat_table was cleared before new entries written
./docs/bugs.md:512:- **Symptom:** `blackholeRoutes` map (`daemon.go:148`) tracks injected RTN_BLACKHOLE routes but is lost on daemon restart. Stale kernel blackhole routes from a previous daemon run survive and cannot be cleaned up — they silently drop traffic matching RETH subnets
./docs/bugs.md:513:- **Impact:** After daemon restart, stale blackhole routes may drop traffic for subnets that should be reachable. Requires manual `ip route del` to fix
./docs/bugs.md:520:  present via `sendPacketIPv6` (src: link-local, dst: `ff02::12`, hop
./docs/bugs.md:529:- **Symptom:** `watchVRRPEvents` at `daemon.go:582` used `context.Background()` instead of daemon `ctx`. VRRP watcher outlived daemon shutdown, causing goroutine leaks and potential races during restart
./docs/bugs.md:541:- **Symptom:** `startClusterComms()` called once at daemon boot. If cluster control/fabric settings changed at runtime via commit, heartbeat/session-sync endpoints were not restarted with new settings
./docs/bugs.md:542:- **Fix:** Config apply path now detects HA transport config changes (control-interface, peer-address, fabric-interface, fabric-peer-address). If changed, cancels existing cluster comms context and restarts with new settings. Dedicated cancel func for independent restart
./docs/bugs.md:584:- Subsequent restarts load from DB normally
./docs/bugs.md:614:- **Symptom:** When fw0 rebooted, fw1 didn't serve WAN traffic for ~28 seconds. Also, fw1's LAN RETH interface (ge-7-0-0) was stuck as MASTER in split-brain with fw0 after restarts.
./docs/bugs.md:620:  2. Skip `reconcileInterfaceAddresses()` for RETH interfaces (`RedundancyGroup > 0`). The link-local base addresses (169.254.RG.NODE/32) are managed by systemd-networkd via .network files; VIPs are managed by VRRP.
./docs/bugs.md:642:  2. **Missing interface in FRR route:** `compileStaticRoutes()` only checked `prop.Children` for "interface" keyword. Config `next-hop fe80::50 interface reth0.50` has "interface" in `prop.Keys[2]` (leaf node with all keys inline), not in Children. FRR got `ipv6 route ::/0 fe80::50 5` without interface → route installed on parent device instead of VLAN sub-interface.
./docs/bugs.md:648:- **Verification:** FRR config now shows `ipv6 route ::/0 fe80::50 ge-0-0-1.50 5`; kernel route shows `via fe80::50 dev ge-0-0-1.50`; ping to `2001:559:8585:50::6` works
./docs/bugs.md:692:- **Symptom:** After simultaneous restart of both nodes (`cluster-deploy` restarts both), both became Primary for all RGs with VRRP priority 200. fw1 log showed: `"failed to start cluster heartbeat" err="listen heartbeat: listen udp4 10.99.0.2:4784: bind: cannot assign requested address"`. Both nodes stayed MASTER permanently.
./docs/bugs.md:695:- **Key insight:** `cluster-deploy` restarts both nodes simultaneously. Staggered deploys (fw1 first, then fw0) avoid the issue, but the retry makes it robust for any deployment pattern.
./docs/bugs.md:846:- **Root cause:** `addByName()` passed raw Junos names to `netlink.LinkByName()` which fails because Linux doesn't have those names
./docs/bugs.md:894:- **Test:** `test/incus/test-private-rg.sh full` — enables then disables private-rg-election, verifying VRRP restarts
./docs/bugs.md:951:- **Symptom:** After daemon restart, IPVLAN overlay interface (fab0/fab1) exists but may lack its IP address. Fabric sync and forwarding broken
./docs/bugs.md:952:- **Root cause:** `ensureFabricIPVLAN()` returns early if IPVLAN already exists, skipping address reconciliation. The IPVLAN survives daemon restart but addresses may have been removed (e.g., by networkd reload or link DOWN/UP cycle)
./docs/bugs.md:1053:- **Root cause:** Session sync transmits the forward session but reverse companion entries are reconstructed locally by `shared_promote`. If the helper caches are empty (daemon restart, ctrl re-enable), reconstruction may produce different NAT mappings or miss entries entirely
./userspace-dp/src/nat/tests.rs:1229:fn pool_snat_persistent_helper_restart_resets_lease_state() {
./userspace-dp/src/nat/tests.rs:1241:    // A helper restart has no previous in-process allocator to reuse. The
./userspace-dp/src/nat/tests.rs:1244:    let restarted = parse_source_nat_rules(&[snapshot]);
./userspace-dp/src/nat/tests.rs:1245:    let reset = source_nat_pool_statuses(&restarted);
./userspace-dp/src/nat/tests.rs:1253:    let fresh = expect_snat_decision(tuple_snat_lookup(&restarted, 12345, "1.1.1.1", 443, 3));
./userspace-dp/src/nat/tests.rs:1257:    let after_fresh = source_nat_pool_statuses(&restarted);
./userspace-dp/src/nat/tests.rs:1263:    assert_persistent_expiry_indexes_consistent(&restarted[0]);
./docs/ha-cluster-test-plan.md:207:| eth0 | xpf-clan | 10.0.60.102/24 | SLAAC + DHCPv6 | 10.0.60.1 / fe80::... (RA) |
./docs/ha-cluster-test-plan.md:414:make cluster-start/stop/restart  # Service lifecycle (NODE=0|1|all)
./docs/ha-cluster-test-plan.md:420:2. Add SR-IOV VF via PCI passthrough (stop VM → add device → restart)
./docs/ha-cluster-test-plan.md:687:# Expected: Router Advertisement from fe80::... with prefix 2001:559:8585:cf01::/64
./docs/ha-cluster-test-plan.md:701:**Objective:** Verify transit traffic survives primary restart and full failover
./docs/ha-cluster-test-plan.md:705:- **LOCAL/NOT_FWDED:** After daemon restart, existing sessions have stale FIB
./docs/ha-cluster-test-plan.md:719:incus exec xpf-fw0 -- systemctl restart xpfd
./docs/ha-cluster-test-plan.md:720:# Expected: 28-29/30 received (1-2 packets lost during restart)
./docs/ha-cluster-test-plan.md:725:incus exec xpf-fw0 -- systemctl restart xpfd
./docs/ha-cluster-test-plan.md:781:- Hitless restart (systemctl restart): <= 2 packets lost (ping)
./docs/ha-cluster-test-plan.md:804:1. Legacy BPF programs pinned at `/sys/fs/bpf/xpf/` survive daemon restart
./docs/ha-cluster-test-plan.md:806:3. After restart, FIB cache in session entries is stale (`fib_gen` mismatch)
./docs/ha-cluster-test-plan.md:1081:make cluster-deploy  # re-push config + restart
./docs/ha-cluster-test-plan.md:1088:**Problem:** After daemon restart or VRRP failover, existing sessions had stale FIB
./docs/ha-cluster-test-plan.md:1103:**Result:** Hitless restart loses only 1-2 packets (ARP/NDP warmup delay) instead of
./docs/ha-cluster-test-plan.md:1126:  default routes (ECMP). Traffic hitting the BACKUP's link-local was blackholed.
./docs/install-images.md:63:   background apt; a `needrestart` blacklist keeps an apt run from
./docs/install-images.md:64:   restarting xpfd mid-transaction**, purge of cloud-init
./docs/install-images.md:77:   and never restarts xpfd (`dh_installsystemd --no-stop-on-upgrade` + a
./docs/install-images.md:78:   `needrestart` blacklist); the verified in-place cut-over is a separate
./test/incus/retire_ebpf_artifact_schema_test.py:166:    write_text(root, "ha-test-restart-connectivity.log")
./docs/vsrx-gaps.md:101:| **Graceful Restart (GR)** | Non-stop routing during control plane restart | Medium | No — FRR supports GR but xpf doesn't configure it |
./docs/vpp-dataplane-assessment.md:32:hitless restart capability. For xpf's current scale (25 Gbps XDP, 15.6 Gbps
./docs/vpp-dataplane-assessment.md:208:2. **Crash resilience**: Pinned BPF maps and links survive daemon restart; VPP crash
./docs/vpp-dataplane-assessment.md:235:- Loss of hitless restart (VPP crash = forwarding stops).
./docs/vpp-dataplane-assessment.md:301:- Keep all existing XDP code, tests, hitless restart.
./docs/vpp-dataplane-assessment.md:418:| Restart             | Full restart, sessions lost          | Full restart               | Hitless (pinned maps)   |
./docs/vpp-dataplane-assessment.md:457:3. **Loss of hitless restart**: VPP crash or restart means forwarding stops entirely.
./docs/vpp-dataplane-assessment.md:458:   xpf's pinned BPF maps/links provide zero-downtime restarts -- this is a
./docs/vpp-dataplane-assessment.md:490:The existing XDP pipeline at 25+ Gbps with hitless restart, verifier-checked safety,
./docs/vpp-dataplane-assessment.md:791:VPP WireGuard has known stability issues (CSIT crashes). Loss of hitless restart.
./docs/vpp-dataplane-assessment.md:877:| IPv6 VIPs                   | Yes (link-local src) | Partial (xpf doesn't use) |
./docs/vpp-dataplane-assessment.md:1064:    link, _ := netlink.LinkByName(iface)
./docs/vpp-dataplane-assessment.md:1072:    link, _ := netlink.LinkByName(iface)
./docs/vpp-dataplane-assessment.md:1075:        netlink.AddrDel(link, addr)
./docs/vpp-dataplane-assessment.md:1089:| **IPv6 VRRP**               | Native VRRPv3 with link-local src     | Supported but unused by xpf         |
./docs/research/1884-tunnel-flap/agy-plan-r4.md:8:   - **Finding:** The plan states: *“resolve `t.ops.LinkByName(appliedRI[name])` and require its `Index` == `link.Attrs().MasterIndex`.”*
./docs/research/1884-tunnel-flap/agy-plan-r4.md:9:   - **Defect:** `appliedRI[name]` stores the logical routing instance name (e.g. `"red"`), but the Linux VRF interface name created by the daemon is prefixed with `"vrf-"` (e.g. `"vrf-red"`) in [BindInterfaceToVRF](file:///home/ps/git/bpfrx/pkg/routing/vrf.go#L127). Looking up the bare routing instance name via `LinkByName` will return a "link not found" error, meaning the lookup fails.
./docs/research/1884-tunnel-flap/agy-plan-r4.md:27:   - **Defect:** If `LinkSetNoMaster` or `LinkByName` fails due to a transient netlink error, the binding remains in the kernel but `appliedRI[name]` is cleared anyway.
./docs/pr/line-rate-investigation/step1-plan.md:897:| I8 | Four `xpf-userspace-worker-*` TIDs present via `ps -eLo pid,tid,comm` BEFORE `perf stat` attach and daemon unit `ActiveEnterTimestamp` unchanged between cell pre/post; addresses Codex MEDIUM #7 (wrong `pgrep -f` + restart during window) | `perf stat --per-thread` attachment is only valid for a quiescent worker set |
./test/incus/cluster-setup.sh:26:#   ./test/incus/cluster-setup.sh restart [0|1|all]  # Restart xpfd service
./test/incus/cluster-setup.sh:153:	info "Disabling IPv6 RA/autoconf on host parent $parent..."
./test/incus/cluster-setup.sh:156:		"net.ipv6.conf.${parent}.autoconf=0" \
./test/incus/cluster-setup.sh:413:	# Wait for agent again after restart
./test/incus/cluster-setup.sh:484:	incus restart "$(r "$vm")"
./test/incus/cluster-setup.sh:533:	incus restart "$rinst"
./test/incus/cluster-setup.sh:565:	incus exec "$rinst" -- systemctl restart systemd-networkd
./test/incus/cluster-setup.sh:620:	# restart for the tight dev inner loop (no deb rebuild, no verified
./test/incus/cluster-setup.sh:738:# the primary restarts.
./test/incus/cluster-setup.sh:1006:cmd_restart() {
./test/incus/cluster-setup.sh:1009:		0)   incus exec "$(r "$VM0")" -- systemctl restart xpfd; info "xpfd restarted on $VM0" ;;
./test/incus/cluster-setup.sh:1010:		1)   incus exec "$(r "$VM1")" -- systemctl restart xpfd; info "xpfd restarted on $VM1" ;;
./test/incus/cluster-setup.sh:1011:		all) incus exec "$(r "$VM0")" -- systemctl restart xpfd; incus exec "$(r "$VM1")" -- systemctl restart xpfd; info "xpfd restarted on both VMs" ;;
./test/incus/cluster-setup.sh:1012:		*)   die "Usage: $0 restart [0|1|all]" ;;
./test/incus/cluster-setup.sh:1019:	echo "Usage: $0 {init|create|destroy|deploy|ssh|status|logs|journal|start|stop|restart} [args]"
./test/incus/cluster-setup.sh:1032:	echo "  restart [0|1|all]    Restart xpfd service (default: all)"
./test/incus/cluster-setup.sh:1038:# instances; start/stop/restart flip the daemon and VRRP mastership).
./test/incus/cluster-setup.sh:1053:	restart)    require_cluster_cell restart "${2:-all}"; cmd_restart "${2:-all}" ;;
./docs/ha-no-hitless-restart.md:9:In chassis cluster (HA) mode, hitless restart is the wrong default.
./docs/ha-no-hitless-restart.md:15:Hitless restart is valuable for standalone upgrades, but HA has different
./docs/ha-no-hitless-restart.md:28:That is desirable for standalone hitless restart, but risky as the default in
./docs/ha-no-hitless-restart.md:35:1. Disable hitless-restart semantics by default.
./docs/ha-no-hitless-restart.md:46:- Standalone mode continues to support hitless restart.
./docs/research/1884-tunnel-flap/claude-smr-plan-r7.md:25:  `LinkByName("vrf-"+RIListMember)` on the veto branch is one netlink
./docs/research/1884-tunnel-flap/claude-smr-plan-r7.md:31:restart) and found no remaining transition that strands a master we
./userspace-dp/src/afxdp/types/cos.rs:826:    // bucket accounting), but is unpredictable across restarts and nodes.
./userspace-dp/src/afxdp/types/cos.rs:831:    /// non-decreasing; resets only on daemon restart (queue
./docs/research/1884-tunnel-flap/claude-smr-plan-r4.md:13:  commit ⇒ `LinkByName(appliedRI[name])` fails (old VRF gone) ⇒ no
./docs/research/1884-tunnel-flap/claude-smr-plan-r4.md:32:  appliedRI lifecycle (removal, clearLocked) now matches appliedAddrs
./docs/pr/line-rate-investigation/step0-rx-steer-missed-investigation.md:92:  Journal confirms repeated daemon restarts over the past 5 h with
./docs/pr/line-rate-investigation/step0-rx-steer-missed-investigation.md:96:  counter; multiple daemon restarts easily explain 55 M.
./docs/research/1884-tunnel-flap/agy-plan-r9.md:48:   - Under Cell 2 (stale claim, foreign master `vrf-X` in the kernel), the identity check `LinkByName("vrf-" + appliedRI[name]).Index == link.Attrs().MasterIndex` fails. The unbind step is bypassed, and the claim is cleared. No foreign master is ever unbound.
./docs/research/1884-tunnel-flap/agy-plan-r9.md:57:    if link, err := t.ops.LinkByName(name); err == nil {
./docs/research/1884-tunnel-flap/agy-plan-r9.md:65:* **Defect**: If `LinkByName` returns a **transient** error (e.g. netlink busy or buffer overflow), `err == nil` is false. The code will skip the `LinkDel` attempt but will also **not** set `next[name] = true` and will delete the tracking maps for `appliedAddrs` and `appliedRI`. Consequently, the manager orphans the tunnel interface in the kernel and ceases tracking it.
./docs/research/1884-tunnel-flap/agy-plan-r9.md:66:* **Fix**: Use `isLinkNotFound(err)` from [vrf.go:L155](file:///home/ps/git/bpfrx/pkg/routing/vrf.go#L155) to prune tracking only on explicit not-found or success:
./docs/research/1884-tunnel-flap/agy-plan-r9.md:68:  link, err := t.ops.LinkByName(name)
./docs/research/1884-tunnel-flap/agy-plan-r9.md:75:  } else if !isLinkNotFound(err) {
./docs/operations/worker-supervisor.md:35:  only by daemon restart.
./docs/operations/worker-supervisor.md:121:   an operation roughly equivalent to a daemon restart, but
./pkg/dataplane/userspace/manager_ha.go:592:// as the delta so counters don't undercount after helper restarts.
./docs/research/1884-tunnel-flap/codex-plan-r3.md:11:This needs a master-identity check before `LinkSetNoMaster`: only unbind if the current master is still the VRF that the tunnel manager previously bound. Also specify `appliedRI` cleanup on deletion/Clear; A.1 deletes `appliedAddrs` only ([plan.md](/home/ps/git/bpfrx/.claude/worktrees/1884-research/docs/research/1884-tunnel-flap/plan.md:188)), and `clearLocked` cleanup names only `ownedNames`/`appliedAddrs` ([plan.md](/home/ps/git/bpfrx/.claude/worktrees/1884-research/docs/research/1884-tunnel-flap/plan.md:198)).
./docs/research/1884-tunnel-flap/codex-plan-r3.md:20:- F4: closed by retaining failed link-local deletes: “`stale-delete FAILED`” and “`keep it tracked until AddrDel succeeds or ... absent`” ([plan.md](/home/ps/git/bpfrx/.claude/worktrees/1884-research/docs/research/1884-tunnel-flap/plan.md:304)).
./docs/research/1884-tunnel-flap/codex-plan-r3.md:27:3. ownedNames growth is bounded. `next` starts as desired only, and a removed name is retained only when `LinkByName` succeeds and `LinkDel` fails ([plan.md](/home/ps/git/bpfrx/.claude/worktrees/1884-research/docs/research/1884-tunnel-flap/plan.md:170)). If the link is gone on the next apply, no retention path fires, so `t.ownedNames = next` drops it ([plan.md](/home/ps/git/bpfrx/.claude/worktrees/1884-research/docs/research/1884-tunnel-flap/plan.md:190)).
./docs/research/1884-tunnel-flap/codex-plan-r3.md:29:5. No r1 closure is reopened by the MTU/AddrDel/ownedNames folds. The only blocker I found is the new `appliedRI` lifecycle hole above.
./userspace-dp/src/afxdp/types/runtime.rs:59:    /// tunnel name. Attachment drift is the ONLY restart condition.
./docs/research/1884-tunnel-flap/codex-plan-r2.md:7:1. A.3 adoption is broken if implemented literally. A.1 assigns `t.ownedNames = desired` before the per-tunnel loop, then A.3 defines adoption as `not in t.ownedNames`. That makes every desired tunnel “owned” before the anchor branch runs, so restart adoption, WG→GRE, and foreign-compatible TUN adoption do not trigger MTU normalization. Evidence: [plan.md:153](/home/ps/git/bpfrx/.claude/worktrees/1884-research/docs/research/1884-tunnel-flap/plan.md:153), [plan.md:166](/home/ps/git/bpfrx/.claude/worktrees/1884-research/docs/research/1884-tunnel-flap/plan.md:166), [plan.md:213](/home/ps/git/bpfrx/.claude/worktrees/1884-research/docs/research/1884-tunnel-flap/plan.md:213), [plan.md:324](/home/ps/git/bpfrx/.claude/worktrees/1884-research/docs/research/1884-tunnel-flap/plan.md:324). Fix: snapshot `oldOwned := t.ownedNames` before overwriting, and use `oldOwned` for adoption decisions.
./docs/research/1884-tunnel-flap/codex-plan-r2.md:13:4. `appliedAddrs` can forget a configured link-local that still exists. A.4 deletes stale link-local only if it is in `applied`, then updates `appliedAddrs[name]` to addresses “now ensured.” If `AddrDel` fails for a removed configured `fe80`, the address remains present but is no longer configured, so it drops out of `applied` and future applies skip it forever. Evidence: [plan.md:242](/home/ps/git/bpfrx/.claude/worktrees/1884-research/docs/research/1884-tunnel-flap/plan.md:242), [plan.md:251](/home/ps/git/bpfrx/.claude/worktrees/1884-research/docs/research/1884-tunnel-flap/plan.md:251), current best-effort delete pattern at [tunnel.go:453](/home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/routing/tunnel.go:453). Keep failed-delete applied LLs tracked until they are absent or deletion succeeds.
./docs/research/1884-tunnel-flap/codex-plan-r2.md:33:2. Yes. `AddrDel` failure is the concrete hole; `AddrAdd` failure on introduction is acceptable if only successful adds enter `appliedAddrs`.
./docs/junos-config-display-reference.md:1009:    address fe80::351/6;
./docs/research/1884-tunnel-flap/claude-smr-plan-r6.md:33:Residuals remain as documented in §10 (restart-window stale master /
./docs/research/1884-tunnel-flap/claude-smr-plan-r1.md:4:fail the restart-adoption contract for the reasons the plan gives), but
./docs/research/1884-tunnel-flap/claude-smr-plan-r1.md:103:  by resetting `state.Up = true` on every restart. Correct fix (AGY
./test/incus/test-chained-crash.sh:10:# The stopped VM must be explicitly restarted with `incus start`.
./test/incus/test-chained-crash.sh:17:#   Phase 2: fw0 restart → fw0 rejoins as secondary, session sync established
./test/incus/test-chained-crash.sh:19:#   Phase 4: fw1 restart → cluster stable, both nodes healthy
./test/incus/test-chained-crash.sh:349:restart_time=$(wait_for_xpfd "$FW0" "$VM_RESTART_WAIT" || true)
./test/incus/test-chained-crash.sh:350:if [[ -n "$restart_time" ]]; then
./test/incus/test-chained-crash.sh:351:	pass "phase2: fw0 xpfd restarted (${restart_time}s)"
./test/incus/test-chained-crash.sh:353:	fail "phase2: fw0 xpfd did not restart within ${VM_RESTART_WAIT}s"
./test/incus/test-chained-crash.sh:466:restart_time=$(wait_for_xpfd "$FW1" "$VM_RESTART_WAIT" || true)
./test/incus/test-chained-crash.sh:467:if [[ -n "$restart_time" ]]; then
./test/incus/test-chained-crash.sh:468:	pass "phase4: fw1 xpfd restarted (${restart_time}s)"
./test/incus/test-chained-crash.sh:470:	fail "phase4: fw1 xpfd did not restart within ${VM_RESTART_WAIT}s"
./docs/research/1884-tunnel-flap/claude-smr-plan-r3.md:27:- **appliedAddrs AddrDel-failure retention (F4) / ownedNames
./docs/research/1884-tunnel-flap/claude-smr-plan-r3.md:54:   `LinkByName == nil-err` branch on a failed LinkDel; a name whose
./pkg/dataplane/userspace/process.go:34:		slog.Warn("userspace dataplane helper unhealthy, restarting")
./pkg/dataplane/userspace/process.go:309:			"userspace: restarting helper for binding plan change",
./pkg/dataplane/userspace/process.go:316:			return fmt.Errorf("restart userspace helper for binding plan change: %w", err)
./pkg/dataplane/userspace/process.go:592:		link, err := netlink.LinkByName(linuxName)
./pkg/dataplane/userspace/process.go:673:		link, err := netlink.LinkByName(ifName)
./pkg/dataplane/userspace/process.go:698:	// like .200 that were previously known but got purged on restart.
./pkg/dataplane/userspace/process.go:840:			link, err := netlink.LinkByName(linuxName)
./pkg/dataplane/userspace/process.go:1034:	// restarts from scratch after rebind.  Without this, ctrl stays
./pkg/dataplane/userspace/process.go:1039:	// count from the FIRST prewarm, not restart on every link cycle.
./docs/research/1884-tunnel-flap/claude-smr-plan-r2.md:61:- **ownedNames vs Clear()**: `Apply → ClearTunnels → Apply` — clearLocked
./docs/research/1884-tunnel-flap/claude-smr-plan-r2.md:70:  identical to today's clearLocked-by-name behavior — no regression.
./docs/research/1884-tunnel-flap/claude-smr-plan-r2.md:82:- **Q2 (fe80 AddrAdd transient failure)**: the address is then absent
./docs/research/1884-tunnel-flap/agy-plan-r1.md:52:2. It seeds an existing tunnel interface with `Index: 42` and configures `ops.hiddenUntil[name] = 1` and `ops.addExisting = true` to mock a transient race (where the initial `LinkByName` misses, but `LinkAdd` fails with `EEXIST` because the link was created concurrently).
./docs/research/1884-tunnel-flap/agy-plan-r1.md:53:3. Under the proposed A.3 design, the first `LinkByName` will miss, `mustCreate` will be `true`, and `LinkAdd` will run and fail with `EEXIST`. The code will log a warning and exit the loop iteration via `continue`.
./docs/research/1884-tunnel-flap/agy-plan-r1.md:62:#### Q1: Is removing `clearLocked()` from `Apply` safe for ALL callers?
./docs/research/1884-tunnel-flap/agy-plan-r1.md:65:* **Reasoning**: `clearLocked()` in [pkg/routing/tunnel.go:659-674](file:///home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/routing/tunnel.go#L659-L674) only iterates over the `t.tunnels` tracked slice. It does not perform a wild kernel scan. 
./docs/research/1884-tunnel-flap/agy-plan-r1.md:67:  - For the CLI: `t.tunnels` is empty at startup, making `clearLocked()` a no-op anyway. 
./docs/research/1884-tunnel-flap/codex-plan-r5.md:5:The r4 blocker is closed for the immediate same-apply stanza-to-list move: A.5 now adds `tc.RIListMember` as an unbind veto, populated with the same `LinuxIfName` + `.0` strip and forwarding-instance skip used by step 0a ([plan.md](/home/ps/git/bpfrx/.claude/worktrees/1884-research/docs/research/1884-tunnel-flap/plan.md:347), [daemon_apply.go](/home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/daemon/daemon_apply.go:216)). The `vrf-` identity lookup is also correct against `BindInterfaceToVRF` ([plan.md](/home/ps/git/bpfrx/.claude/worktrees/1884-research/docs/research/1884-tunnel-flap/plan.md:365), [vrf.go](/home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/routing/vrf.go:126)), and transient `LinkByName` / `LinkSetNoMaster` retention is explicitly folded ([plan.md](/home/ps/git/bpfrx/.claude/worktrees/1884-research/docs/research/1884-tunnel-flap/plan.md:373)).
./test/incus/test-ha-crash.sh:26:#   Phase 3: Multi-cycle crash (3 cycles force-stop/restart)
./test/incus/test-ha-crash.sh:53:DAEMON_RESTART_WAIT=30                      # max seconds for xpfd to restart
./test/incus/test-ha-crash.sh:324:restart_time=$(wait_for_xpfd "$FW0" "$VM_RESTART_WAIT" || true)
./test/incus/test-ha-crash.sh:325:if [[ -n "$restart_time" ]]; then
./test/incus/test-ha-crash.sh:326:	pass "phase1: fw0 xpfd restarted (${restart_time}s)"
./test/incus/test-ha-crash.sh:328:	fail "phase1: fw0 xpfd did not restart within ${VM_RESTART_WAIT}s"
./test/incus/test-ha-crash.sh:432:restart_time=$(wait_for_xpfd "$FW0" "$DAEMON_RESTART_WAIT" || true)
./test/incus/test-ha-crash.sh:433:if [[ -n "$restart_time" ]]; then
./test/incus/test-ha-crash.sh:434:	pass "phase2: xpfd restarted (${restart_time}s)"
./test/incus/test-ha-crash.sh:436:	fail "phase2: xpfd did not restart within ${DAEMON_RESTART_WAIT}s"
./test/incus/test-ha-crash.sh:445:	pass "phase2: fw0 rejoined as secondary after daemon restart"
./test/incus/test-ha-crash.sh:482:# Phase 3: Multi-cycle crash (repeated force-stop/restart)
./test/incus/test-ha-crash.sh:529:	restart_time=$(wait_for_xpfd "$FW0" "$VM_RESTART_WAIT" || true)
./test/incus/test-ha-crash.sh:530:	if [[ -n "$restart_time" ]]; then
./test/incus/test-ha-crash.sh:531:		pass "phase3-cycle${cycle}: fw0 restarted (${restart_time}s)"
./test/incus/test-ha-crash.sh:533:		fail "phase3-cycle${cycle}: fw0 did not restart within ${VM_RESTART_WAIT}s"
./docs/research/1884-tunnel-flap/codex-plan-r1.md:7:1. Keepalive retention breaks the DOWN state. A.7 keeps an unchanged runner alive, but `Apply` still brings the reused link up. Once `KeepaliveState.Up` is already false, `keepaliveLoop` only increments failures and never calls `LinkSetDown` again because the down action is gated by `state.Up` being true: [pkg/routing/tunnel.go:587](/home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/routing/tunnel.go:587), [pkg/routing/tunnel.go:593](/home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/routing/tunnel.go:593). Counterexample: keepalive downs tunnel, unrelated commit reuses anchor and calls `LinkSetUp`, runner remains `Up=false`, future failed probes do not down it again. Fix: skip `LinkSetUp` when retaining a down runner, or restart/reset the runner deliberately. Also stop/drain before any real recreate; today destructive apply drains first via [pkg/routing/tunnel.go:97](/home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/routing/tunnel.go:97) and [pkg/routing/tunnel.go:660](/home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/routing/tunnel.go:660).
./docs/research/1884-tunnel-flap/codex-plan-r1.md:9:2. The shared address reconciler would leak configured `fe80::` tunnel addresses after removal. The plan copies WG’s “skip link-local” behavior, and WG currently never deletes stale link-local addresses: [pkg/routing/tunnel.go:452](/home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/routing/tunnel.go:452). But GRE unit tunnel addresses are populated from unit config: [pkg/config/compiler_interfaces.go:648](/home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/config/compiler_interfaces.go:648), and tests include configured `fe80::8/64`: [pkg/config/parser_cluster_test.go:1143](/home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/config/parser_cluster_test.go:1143). A removed configured link-local would persist forever under reuse. Do not blanket-skip link-local for GRE/IPIP anchors.
./docs/research/1884-tunnel-flap/codex-plan-r1.md:15:5. Keepalive identity must be normalized. Config says `KeepaliveRetry == 0` means default 3: [pkg/config/types_routing.go:302](/home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/config/types_routing.go:302). `startKeepalive` applies that default before storing state: [pkg/routing/tunnel.go:533](/home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/routing/tunnel.go:533), [pkg/routing/tunnel.go:541](/home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/routing/tunnel.go:541). If identity compares raw `0` against stored `3`, unchanged config restarts every apply.
./docs/research/1884-tunnel-flap/agy-plan-r3.md:48:*   **(F4) failed-AddrDel Retention:** Sound. Keeping failed-delete link-locals in `appliedAddrs` ensures they are cleaned up on a retry rather than orphaned.
./docs/research/1884-tunnel-flap/agy-plan-r3.md:76:    2.  On the next apply, if the link was deleted out-of-band, the manager calls `t.ops.LinkByName(name)` ([pkg/routing/tunnel.go:179](file:///home/ps/git/bpfrx/pkg/routing/tunnel.go#L179)).
./docs/research/1884-tunnel-flap/agy-plan-r3.md:77:    3.  Since the link is gone, `LinkByName` returns `err != nil`. The `err == nil` block containing the `LinkDel` retry and the `next[name] = true` retention is skipped.
./docs/research/1884-tunnel-flap/claude-smr-code-r1.md:11:`applyAnchorLocked`: LinkByName → existing TUN(NO_PI, persistent) ⇒
./docs/research/1884-tunnel-flap/claude-smr-code-r1.md:14:IFF_UP on an up link emits no netdev event), AddrList ⇒ want==existing
./docs/research/1884-tunnel-flap/claude-smr-code-r1.md:15:⇒ zero AddrAdd/AddrDel; claim: stanza/list per config — observation
./docs/research/1884-tunnel-flap/claude-smr-code-r1.md:16:path issues only LinkByName reads. NET: zero LinkDel/LinkAdd/Addr
./docs/research/1884-tunnel-flap/claude-smr-code-r1.md:33:(IKey/OKey) ⇒ delete+recreate + keepalive restart via the `created`
./docs/research/1884-tunnel-flap/claude-smr-code-r1.md:36:**T3 — daemon restart ⇒ adopted, not flapped.** ownedNames empty ⇒
./docs/research/1884-tunnel-flap/claude-smr-code-r1.md:41:identical across `systemctl restart xpfd` — the list-bind retention
./docs/research/1884-tunnel-flap/claude-smr-code-r1.md:61:  LinkByName error and LinkSetNoMaster failure.
./docs/research/1884-tunnel-flap/claude-smr-code-r1.md:67:  after successful/no-op removal; clearLocked resets all three maps.
./docs/pr/1612-scale-target-measurement/claude-smr-plan-r3.md:8:   through `systemctl restart xpfd` (no `Environment=` in unit file).
./test/incus/retire_ebpf_artifact_schema.py:61:    "ha-test-restart-connectivity",
./test/incus/retire_ebpf_artifact_schema.py:554:        self.require_file("ha-test-restart-connectivity.log")
./docs/research/1884-tunnel-flap/agy-plan-r2.md:52:    *   **Resolution:** The v2 plan (A.3) preserves this by doing exactly one re-lookup via `t.ops.LinkByName(tc.Name)` when `LinkAdd` fails. If `anchorReusable(existing)` passes, it adopts the link (`link = existing`) and continues. If it is not reusable or doesn't exist, it logs a warning and continues without an infinite loop.
./docs/research/1884-tunnel-flap/agy-plan-r2.md:59:    *   **Analysis:** No issues found. Because `Apply` ([tunnel.go:94-310](file:///home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/routing/tunnel.go#L94-L310)) does not return early on individual tunnel errors (it logs warnings and calls `continue`), `ownedNames` is guaranteed to be updated to the new `desired` set on every apply. When `Clear()` / `clearLocked()` is called, it correctly clears `ownedNames` and `appliedAddrs`.
./docs/research/1884-tunnel-flap/agy-plan-r2.md:60:*   **`applied-set` link-local rule (A.4):**
./docs/research/1884-tunnel-flap/agy-plan-r2.md:67:    *   **Analysis:** Structurally sound. Defaulting `maxRetries <= 0` to `3` before comparison avoids comparing a config `0` against a running `3`, preventing runner restarts on every commit.
./docs/research/1884-tunnel-flap/agy-plan-r2.md:79:*   **Q2: Any hole where a CONFIGURED fe80 is absent from `appliedAddrs` at removal time other than the documented daemon-restart residual? Is best-effort acceptable?**
./docs/research/1884-tunnel-flap/reviewer-ids.md:27:restart adoption with `master vrf-sfmix` retained, service active.
./docs/research/1921-virtio-mq-bind/claude-smr-plan-r1.md:82:`systemctl restart xpfd`), not by re-baking. Note this does not exercise the
./docs/pr/1612-scale-target-measurement/plan.md:40:| HIGH 1: `XPF_COLD_PATH_SAMPLE_MASK` env-override won't propagate through `systemctl restart` (no `Environment=` in xpfd.service) | v2 §1.3 | Replace env-override with a daemon CLI flag `--cold-path-sample-mask <N>` parsed by `cmd/xpfd/main.go` and threaded into the userspace-dp control-socket bootstrap. Harness sets it via `systemctl edit --force --full xpfd.service` drop-in OR via `cli configure` config knob (preferred — survives daemon restarts). | §1.3 + §7 |
./docs/pr/1612-scale-target-measurement/plan.md:212:     daemon restarts) OR via `systemctl edit --force --full
./docs/research/1921-virtio-mq-bind/agy-plan-r1.md:13:   on helper restart / same-plan rebind. The busy-bindings watchdog
./docs/pr/line-rate-investigation/step1-evidence/no-cos/p5203-fwd/dmesg-tail.txt:14:[Tue Apr 21 02:57:36 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/line-rate-investigation/step1-evidence/no-cos/p5203-fwd/dmesg-tail.txt:15:[Tue Apr 21 02:57:36 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/line-rate-investigation/step1-evidence/no-cos/p5203-fwd/dmesg-tail.txt:16:[Tue Apr 21 02:57:36 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/line-rate-investigation/step1-evidence/no-cos/p5203-fwd/dmesg-tail.txt:17:[Tue Apr 21 02:57:36 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/line-rate-investigation/step1-evidence/no-cos/p5203-fwd/dmesg-tail.txt:18:[Tue Apr 21 02:57:36 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/line-rate-investigation/step1-evidence/no-cos/p5203-fwd/dmesg-tail.txt:19:[Tue Apr 21 02:57:36 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/line-rate-investigation/step1-evidence/no-cos/p5203-fwd/dmesg-tail.txt:20:[Tue Apr 21 02:57:36 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/line-rate-investigation/step1-evidence/no-cos/p5203-fwd/dmesg-tail.txt:21:[Tue Apr 21 02:57:36 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/line-rate-investigation/step1-evidence/no-cos/p5203-fwd/dmesg-tail.txt:22:[Tue Apr 21 02:57:36 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/line-rate-investigation/step1-evidence/no-cos/p5203-fwd/dmesg-tail.txt:23:[Tue Apr 21 02:57:36 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/line-rate-investigation/step1-evidence/no-cos/p5203-fwd/dmesg-tail.txt:25:[Tue Apr 21 02:57:42 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/line-rate-investigation/step1-evidence/no-cos/p5203-fwd/dmesg-tail.txt:26:[Tue Apr 21 02:57:42 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/line-rate-investigation/step1-evidence/no-cos/p5203-fwd/dmesg-tail.txt:27:[Tue Apr 21 02:57:42 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/line-rate-investigation/step1-evidence/no-cos/p5203-fwd/dmesg-tail.txt:28:[Tue Apr 21 02:57:42 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/line-rate-investigation/step1-evidence/no-cos/p5203-fwd/dmesg-tail.txt:29:[Tue Apr 21 02:57:42 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/line-rate-investigation/step1-evidence/no-cos/p5203-fwd/dmesg-tail.txt:30:[Tue Apr 21 02:57:42 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/line-rate-investigation/step1-evidence/no-cos/p5203-fwd/dmesg-tail.txt:31:[Tue Apr 21 02:57:42 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/line-rate-investigation/step1-evidence/no-cos/p5203-fwd/dmesg-tail.txt:32:[Tue Apr 21 02:57:42 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/line-rate-investigation/step1-evidence/no-cos/p5203-fwd/dmesg-tail.txt:33:[Tue Apr 21 02:57:42 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/line-rate-investigation/step1-evidence/no-cos/p5203-fwd/dmesg-tail.txt:34:[Tue Apr 21 02:57:42 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./pkg/config/parser_ast_test.go:1935:                address fe80::1/64;
./docs/research/1884-tunnel-flap/plan.md:21:1. `clearLocked()` (tunnel.go:97) deletes EVERY tracked tunnel link and
./docs/research/1884-tunnel-flap/plan.md:49:symmetrically, and is deliberately untracked so `clearLocked` cannot
./docs/research/1884-tunnel-flap/plan.md:119:- Fails the daemon-restart contract ("anchors adopted, not flapped"):
./docs/research/1884-tunnel-flap/plan.md:120:  after restart the hash cache is empty, so the first applyConfig
./docs/research/1884-tunnel-flap/plan.md:127:the restart contract fails identically to B. Rejected.
./docs/research/1884-tunnel-flap/plan.md:130:`IFLA_IFALIAS` on created anchors would give restart-stable ownership
./docs/research/1884-tunnel-flap/plan.md:159:`Apply` no longer calls `clearLocked()`. The manager tracks
./docs/research/1884-tunnel-flap/plan.md:185:    if link, err := t.ops.LinkByName(name); err == nil {
./docs/research/1884-tunnel-flap/plan.md:195:    delete(t.appliedRI, name)    // [r3] ditto; clearLocked clears both
./docs/research/1884-tunnel-flap/plan.md:203:between applies — identical to today's clearLocked-by-name behavior
./docs/research/1884-tunnel-flap/plan.md:205:`Clear()`/`clearLocked()` keep delete-everything semantics (clearLocked
./docs/research/1884-tunnel-flap/plan.md:213:branch starts from `LinkByName` and decides reuse vs recreate itself.
./docs/research/1884-tunnel-flap/plan.md:241:link, err := t.ops.LinkByName(tc.Name)
./docs/research/1884-tunnel-flap/plan.md:250:        if existing, lkErr := t.ops.LinkByName(tc.Name); lkErr == nil && anchorReusable(existing) {
./docs/research/1884-tunnel-flap/plan.md:258:// when reusing a TUN this manager did NOT own at last apply (restart
./docs/research/1884-tunnel-flap/plan.md:319:`reconcileLinkAddrsLocked(link, name string, addrs []string, applied map[string]bool)`:
./docs/research/1884-tunnel-flap/plan.md:321:- delete present-but-unconfigured NON-link-local addresses (drift
./docs/research/1884-tunnel-flap/plan.md:326:  skip ALL link-local deletion, current WG semantics — guard is
./docs/research/1884-tunnel-flap/plan.md:328:  note]). Blanket-skipping link-local (the WG
./docs/research/1884-tunnel-flap/plan.md:329:  precedent, tunnel.go:452-453) would leak CONFIGURED fe80 addresses
./docs/research/1884-tunnel-flap/plan.md:330:  forever once removed from config (GRE unit tunnels DO configure fe80
./docs/research/1884-tunnel-flap/plan.md:332:  parser_cluster_test.go:1143 `fe80::8/64`), while deleting ALL stale
./docs/research/1884-tunnel-flap/plan.md:333:  link-local would tear down the kernel's autoconf fe80 (which the WG
./docs/research/1884-tunnel-flap/plan.md:336:  or already-present adds of configured addresses) **∪ link-local
./docs/research/1884-tunnel-flap/plan.md:340:  tracked until `AddrDel` succeeds or the address is observed absent.
./docs/research/1884-tunnel-flap/plan.md:347:Restart residual: `appliedAddrs` is not persisted; a configured fe80
./docs/research/1884-tunnel-flap/plan.md:395:  `t.ops.LinkByName("vrf-" + appliedRI[name])` — the `vrf-` prefix is
./docs/research/1884-tunnel-flap/plan.md:454:  VRF device NOT-FOUND (`isLinkNotFound`-class, vrf.go:144-163 — the
./docs/research/1884-tunnel-flap/plan.md:456:  remains). On TRANSIENT errors — `LinkByName` non-not-found error,
./docs/research/1884-tunnel-flap/plan.md:461:`clearLocked` also `delete(t.appliedRI, name)` alongside
./docs/research/1884-tunnel-flap/plan.md:470:until the operator intervenes (same restart-residual class as §10).
./docs/research/1884-tunnel-flap/plan.md:494:+ keepalive restart per A.7.
./docs/research/1884-tunnel-flap/plan.md:505:  `0` against stored `3` would restart the runner every apply
./docs/research/1884-tunnel-flap/plan.md:520:  restart). Recovery still works: a succeeding probe takes the
./docs/research/1884-tunnel-flap/plan.md:523:**A.8 — daemon-restart adoption falls out.** After restart `ownedNames`
./docs/research/1884-tunnel-flap/plan.md:528:restarts with stable ifindex.
./docs/research/1884-tunnel-flap/plan.md:552:drain + map delete) + `reconcileLinkAddrsLocked` + `anchorReusable`
./docs/research/1884-tunnel-flap/plan.md:558:  LinkSetUp/AddrAdd/AddrList/LinkSetMTU on a reused/adopted link uses
./docs/research/1884-tunnel-flap/plan.md:559:  the `LinkByName`-returned object (real ifindex), never a fresh
./docs/research/1884-tunnel-flap/plan.md:573:- **clearLocked semantics for explicit Clear()/shutdown unchanged**.
./docs/research/1884-tunnel-flap/plan.md:597:AddrDel recording + AddrList over recorded addrs + seedable
./docs/research/1884-tunnel-flap/plan.md:601:2. Fresh manager + seeded compatible TUN (restart adoption) → reused,
./docs/research/1884-tunnel-flap/plan.md:616:5. Address edit → AddrAdd new + AddrDel stale; configured fe80 removed
./docs/research/1884-tunnel-flap/plan.md:617:   → deleted (in appliedAddrs); foreign/kernel fe80 never deleted;
./docs/research/1884-tunnel-flap/plan.md:618:   fe80 stale-delete failure → stays in appliedAddrs and is retried
./docs/research/1884-tunnel-flap/plan.md:641:   LinkByName/LinkSetNoMaster failure → entry RETAINED and unbind
./docs/research/1884-tunnel-flap/plan.md:659:   runner survives, no restart; changed interval → restarted; runner
./docs/research/1884-tunnel-flap/plan.md:661:   restarted after recreate.
./docs/research/1884-tunnel-flap/plan.md:678:- `systemctl restart xpfd`: anchor adopted (ifindex stable across
./docs/research/1884-tunnel-flap/plan.md:679:  restart), local-origin traffic resumes.
./docs/research/1884-tunnel-flap/plan.md:685:- WG configured-link-local stale-address leak (same class as Codex r1
./docs/research/1884-tunnel-flap/plan.md:692:  `appliedAddrs` link-local across restart. Separate issue if it bites.
./docs/research/1884-tunnel-flap/plan.md:722:best-effort + AddrDel-failure retention; A.6 field list; ownedNames
./test/incus/test-double-failover.sh:228:	pass "fw0 xpfd restarted after reboot"
./docs/research/1921-virtio-mq-bind/plan.md:420:  (`scp` + `systemctl restart xpfd`), NOT by re-baking the image (too slow; the
./docs/research/1884-tunnel-flap/agy-plan-r5.md:41:I will view the current address reconciliation logic for WireGuard in `pkg/routing/tunnel.go` around line 430 to verify the link-local behavior.
./docs/research/1884-tunnel-flap/agy-plan-r5.md:93:* **Lapse-on-Transient-Failure:** The claim-lapse rule ensures that transient netlink failures (such as `LinkByName` or `LinkSetNoMaster` errors) preserve the `appliedRI` claim, enabling automatic retries in subsequent apply runs.
./docs/research/1884-tunnel-flap/agy-plan-r5.md:94:* **Keepalive Normalization & Thread-Safety:** Normalizing `maxRetries <= 0` to `3` prior to comparison correctly prevents unnecessary restarts. Reading `state.Up` under `state.mu` lock is thread-safe.
./docs/research/1884-tunnel-flap/agy-plan-r5.md:95:* **WireGuard Extraction Hygiene:** Passing a `nil` `applied` map to `reconcileLinkAddrsLocked` correctly preserves the WireGuard branch's pre-existing behavior of skipping link-local deletions.
./docs/research/1884-tunnel-flap/agy-plan-r7.md:61:Using `LinkByName(appliedRI[name]).Index == link.Attrs().MasterIndex` is a highly resilient test.
./docs/userspace-cold-start-resolution.md:18:After daemon restart or when encountering a new destination host, the
./docs/userspace-cold-start-resolution.md:49:on daemon restart.
./test/incus/wg-interop.env:43:                               # xpfd restart the LAN VIP can lag mastership restoration;
./pkg/dataplane/userspace/manager.go:602:			"userspace: restarting helper during XSK startup for binding plan change",
./pkg/dataplane/userspace/manager.go:830:// above). It must NOT call Compile (which detaches links / restarts
./pkg/config/compiler_protocols.go:196:			case "graceful-restart":
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:19:- pkg/routing/tunnel.go (Apply ~163, applyWireguardTunLocked ~798, reconcileLinkAddrsLocked ~584, clearLocked ~1086, tunnelManager fields ~104)
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:25:1. Is Path A's wgConfigured diff correct and idempotent? Walk the prune loop across 3 commits (add, remove, remove-again). Does it ever double-prune or strand tracking?
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:27:3. The retain-for-retry on AddrDel failure uses len(remaining)>0 from reconcileLinkAddrsLocked. But reconcileLinkAddrsLocked returns newApplied = successful-adds + present-and-wanted + failed-delete-link-locals. With an EMPTY desired set (nil addrs), what does it actually return on a failed AddrDel of a NON-link-local address? Trace tunnel.go:595-644 carefully — does a failed AddrDel of a regular (non-fe80) address get recorded in newApplied at all? If NOT, the retry signal is broken. THIS IS THE KEY CORRECTNESS QUESTION.
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:34:I’ll review this as a plan audit only. I’m going to ground every objection in the local source and pay special attention to the AddrDel retry trace the plan depends on.
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:48:    90		// unchanged runner alive across applies instead of restarting it
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:69:   111	// against the stored default 3 would restart the runner every apply).
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:71:   113	// change must restart the runner so the probe binds the new endpoint.
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:136:   178		// ensured (successful adds + present-and-wanted + link-local whose
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:138:   180		// configured fe80 we applied is removable; the kernel's autoconf
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:139:   181		// fe80 is never touched.
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:151:   193	// ensureReconcileStateLocked lazily initializes the reconcile maps so
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:154:   196	func (t *tunnelManager) ensureReconcileStateLocked() {
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:195:   566		e, lookupErr := t.ops.LinkByName(tc.Name)
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:200:   571		case isLinkNotFound(lookupErr):
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:233:   604					// recreated — the restarted runner captures the just-bumped
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:348:   838		vrf, err := t.ops.LinkByName("vrf-" + claim)
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:350:   840			if isLinkNotFound(err) {
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:389:   879		vrf, err := t.ops.LinkByName("vrf-" + tc.RIListMember)
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:463:   332		if !ops.hasAddr("gr-0-0-0", "fe80::8/64") {
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:468:   337		delete(ops.addrDelFail, "gr-0-0-0|fe80::8/64")
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:472:   341		if ops.hasAddr("gr-0-0-0", "fe80::8/64") {
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:473:   342			t.Fatal("failed-delete fe80 not retried (dropped from appliedAddrs)")
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:483:   352	// A CONFIGURED fe80 on the persistent wgN TUN, later removed from
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:485:   354	// nil applied-set sentinel) — while the kernel's autoconf fe80 on the
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:490:   359		if err := tm.Apply([]*config.TunnelConfig{wgTC("10.77.0.1/24", "fe80::8/64")}); err != nil {
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:493:   362		if !ops.hasAddr("wg0", "fe80::8/64") {
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:494:   363			t.Fatal("configured fe80 not applied")
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:496:   365		// Simulate the kernel's autoconf link-local appearing too.
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:497:   366		kernelLL, _ := netlink.ParseAddr("fe80::5054:ff:fe12:3456/64")
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:503:   372		if ops.hasAddr("wg0", "fe80::8/64") {
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:504:   373			t.Fatal("configured fe80 leaked after removal from config (#1905)")
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:506:   375		if !ops.hasAddr("wg0", "fe80::5054:ff:fe12:3456/64") {
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:507:   376			t.Fatal("kernel autoconf fe80 was deleted")
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:518:   387	// Adoption pass: an fe80 already on the device before this manager's
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:519:   388	// first apply (daemon restart over a persistent wgN) is untracked and
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:524:   393		preLL, _ := netlink.ParseAddr("fe80::dead/64")
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:532:   401			if !ops.hasAddr("wg0", "fe80::dead/64") {
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:533:   402				t.Fatalf("pre-existing fe80 deleted on apply %d", i+1)
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:538:   407	// Failed fe80 stale-delete on the WG branch stays tracked and is
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:544:   413		if err := tm.Apply([]*config.TunnelConfig{wgTC("fe80::8/64")}); err != nil {
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:548:   417		ops.addrDelFail["wg0|fe80::8/64"] = errors.New("EBUSY")
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:552:   421		if !ops.hasAddr("wg0", "fe80::8/64") {
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:556:   425		delete(ops.addrDelFail, "wg0|fe80::8/64")
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:560:   429		if ops.hasAddr("wg0", "fe80::8/64") {
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:561:   430			t.Fatal("failed-delete fe80 not retried (dropped from appliedAddrs)")
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:647:    52	  / `reconcileLinkAddrsLocked` is **never called for it again**, and
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:654:    59	or daemon restart). The in-code comment at `tunnel.go:790-794` already
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:693:    98	is `AddrDel`'d — it is not a separate object we manage). There is **no
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:714:   119	| `pkg/routing/tunnel.go:798-890` `applyWireguardTunLocked` | create/reuse wgN; MTU; `reconcileLinkAddrsLocked`; VRF bind |
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:715:   120	| `pkg/routing/tunnel.go:584-645` `reconcileLinkAddrsLocked` | symmetric add/del against desired addr set; link-local gate; returns new applied set |
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:718:   123	| `pkg/routing/tunnel.go:1086-1113` `clearLocked` | delete-everything path (ClearTunnels); does NOT delete WG (not in tunnels/ownedNames) |
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:722:   127	| `pkg/routing/tunnel_reconcile_test.go` | existing WG tests: only link-local cases (356/390/410); NO removal test |
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:762:   167	address set**, which `reconcileLinkAddrsLocked(link, name, nil,
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:764:   169	wanted, respecting the link-local applied gate). We just need to *call*
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:776:   181	Add a dedicated WG ownership set `wgConfigured map[string]bool` (analogous
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:782:   187	   for each `name` in the **old** `wgConfigured` not in `wgDesired`:
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:783:   188	   - look up the link (`LinkByName`); if found, call
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:784:   189	     `reconcileLinkAddrsLocked(link, name, nil, t.appliedAddrs[name],
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:786:   191	     set), honoring the link-local applied gate (kernel autoconf fe80
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:791:   196	     commit finds `name` no longer in old `wgConfigured`, so no-op).
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:792:   197	   - If `LinkByName` fails (device already gone — manual `ip link del`),
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:794:   199	   - If `reconcileLinkAddrsLocked` leaves residual tracked addresses
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:795:   200	     because an `AddrDel` failed, **retain** the name in the next
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:796:   201	     `wgConfigured` so the next commit retries (mirrors GRE
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:799:   204	3. After the per-tunnel apply loop, set `t.wgConfigured = wgDesired`
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:803:   208	`reconcileLinkAddrsLocked` and `appliedAddrs` verbatim; idempotent;
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:806:   211	**Cons**: one more reconcile map to keep in sync across `clearLocked`
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:807:   212	(must reset it too) and `ensureReconcileStateLocked` (must lazily init).
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:827:   232	exact assets (`appliedAddrs`, `reconcileLinkAddrsLocked`) the manager
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:889:   251	// instead of being restarted every apply.
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:893:   255		t.ensureReconcileStateLocked()
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:920:   282			if link, err := t.ops.LinkByName(name); err == nil {
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:948:   310			// apply (daemon restart, wireguard→gre same-name flip, foreign
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:992:   354		if existing, lookupErr := t.ops.LinkByName(tc.Name); lookupErr == nil {
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1004:   705		t.appliedAddrs[tc.Name] = t.reconcileLinkAddrsLocked(
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1010:   711	// reconcileLinkAddrsLocked symmetrically reconciles a link's addresses
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1012:   713	// present-but-unconfigured — EXCEPT link-local addresses, which are
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1014:   715	// gate). The kernel's autoconf fe80 must never be deleted, while a
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1015:   716	// CONFIGURED fe80 removed from config must not leak forever (#1884 r1
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1017:   718	// first apply for a link this manager has not tracked yet — restart
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1018:   719	// adoption) means no link-local deletion at all.
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1021:   722	// link-local addresses whose stale-delete FAILED (kept tracked so the
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1023:   724	func (t *tunnelManager) reconcileLinkAddrsLocked(link netlink.Link, name string, addrs []string, applied map[string]bool, kind string) map[string]bool {
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1036:   737		if list, listErr := t.ops.AddrList(link, netlink.FAMILY_ALL); listErr == nil {
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1051:   752					// Kernel-managed or foreign link-local: never delete.
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1054:   755				if delErr := t.ops.AddrDel(link, &a); delErr != nil {
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1138:   838		vrf, err := t.ops.LinkByName("vrf-" + claim)
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1140:   840			if isLinkNotFound(err) {
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1179:   879		vrf, err := t.ops.LinkByName("vrf-" + tc.RIListMember)
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1227:   927	// in t.tunnels: clearLocked must not delete it on reload (AGY Hazard B
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1232:   931	// tunnel REMOVED from the config is not torn down by clearLocked and
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1233:   932	// leaks until `ip link del` or daemon restart. S2a single-tunnel scope
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1241:   940		link, err := t.ops.LinkByName(tc.Name)
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1312:  1011		// the same configured-vs-autoconf link-local split as the GRE/IPIP
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1313:  1012		// branch: a CONFIGURED fe80 later removed from config is deleted
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1314:  1013		// (this manager applied it), while the kernel's autoconf fe80 — and
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1315:  1014		// any fe80 already present before this daemon's first apply
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1316:  1015		// (restart adoption pass, applied == nil) — is never touched.
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1321:  1020		t.appliedAddrs[tc.Name] = t.reconcileLinkAddrsLocked(
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1374:  1152	//  3. LinkByName; on error do nothing (Up unchanged → retried next tick).
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1444:  1222		link, err := t.ops.LinkByName(tunnelName)
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1596:   264	// wgConfigured: WG tunnel names configured at the LAST Apply (plus
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1600:   268	wgConfigured map[string]bool
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1603:   271	`ensureReconcileStateLocked`: add `if t.wgConfigured == nil { … }`.
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1611:   279	oldWG := t.wgConfigured
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1617:   285	    if link, err := t.ops.LinkByName(name); err == nil {
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1618:   286	        remaining := t.reconcileLinkAddrsLocked(link, name, nil,
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1622:   290	            nextWG[name] = true // AddrDel failed → retry next apply
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1630:   298	t.wgConfigured = nextWG
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1637:   305	`clearLocked`: add `t.wgConfigured = nil` to the reset block (:1109).
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1646:   314	contains the removed name (we set `t.wgConfigured = nextWG` which only
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1649:   317	failed-AddrDel prune keeps it in `nextWG` → retried until clean. ✔
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1658:   326	   tunnel carrying `172.16.0.1/30` (+ optional fe80 configured) → assert
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1660:   328	   (a) link is NOT deleted (no LinkDel for wgN), (b) AddrDel called for
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1661:   329	   `172.16.0.1/30`, (c) configured fe80 deleted, kernel autoconf fe80
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1662:   330	   untouched (reuse the link-local gate test fixtures at :349-435).
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1664:   332	   → assert NO further AddrDel / LinkByName churn for the pruned name
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1666:   334	4. **`TestWireguardRemovalAddrDelFailureRetried`**: fake AddrDel returns
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1668:   336	   Apply retries AddrDel.
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1669:   337	5. **`TestWireguardRemovalDeviceAlreadyGone`**: LinkByName returns
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1677:   345	All tests assert via the fake's recorded `AddrAdd`/`AddrDel`/`LinkDel`
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1711:   379	  `appliedAddrs[name]` (manager-applied) are eligible; foreign/autoconf
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1712:   380	  link-local is gated out by `reconcileLinkAddrsLocked`.
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1715:   383	- **R3 — retry storms on persistent AddrDel failure**: bounded by the
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1717:   385	  most one AddrDel attempt per residual address.
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1719:   387	- **R5 — interaction with restart adoption** (`appliedAddrs == nil`):
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1720:   388	  on a fresh daemon, `wgConfigured` is empty, so a WG tunnel removed
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1722:   390	  This is the **same restart-adoption limitation** the rest of the file
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1724:   392	  known boundary; full restart-time WG reconciliation is #1434 scope.
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1725:   393	  (A reviewer may ask for a restart-time sweep — explicitly defer.)
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1745:   413	  to remove/replace the "leaks until ip link del or daemon restart"
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1748:   416	  (restart-time removal, VRF residual, link+peer kept).
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1791:   459	t.appliedAddrs[tc.Name] = t.reconcileLinkAddrsLocked(
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1798:   466	// tunnel REMOVED from the config is not torn down by clearLocked and
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1799:   467	// leaks until `ip link del` or daemon restart. S2a single-tunnel scope
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1813:   456		// never retry until the next commit or restart. ensureRetryLocked
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:2021:The key retry suspicion is real in source: `reconcileLinkAddrsLocked` only re-tracks failed stale deletes for link-local addresses. I’m checking the wider call graph now to make sure the verdict also covers FRR, VRF, restart adoption, and keepalive claims accurately.
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:2028:pkg/daemon/daemon_ra.go:84:				// RETH HA startup installs a stable router link-local on the active
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:2459:pkg/routing/tunnel.go:672:	restartKA := tc.Keepalive > 0 && (!hasRunner || created || !runner.matches(tc))
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:2460:pkg/routing/tunnel.go:674:	if tc.Keepalive > 0 && hasRunner && !restartKA {
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:2503:pkg/routing/tunnel_reconcile_test.go:779:	tc.KeepaliveRetry = 0 // normalizes to 3 — must not restart per apply
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:2529:pkg/routing/tunnel_keepalive_test.go:271:func TestKeepaliveLinkByNameErrorNoLatch(t *testing.T) {
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:2601:pkg/routing/README.md:95:  not own at the last apply (restart adoption; wireguard→gre same-name
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:2614:pkg/routing/tunnel.go:310:		// apply (daemon restart, wireguard→gre same-name flip, foreign
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:2642:pkg/routing/tunnel_reconcile_test.go:301:	if err := tm.Apply([]*config.TunnelConfig{anchorTC("gr-0-0-0", "fe80::8/64")}); err != nil {
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:2644:pkg/routing/tunnel_reconcile_test.go:324:	if err := tm.Apply([]*config.TunnelConfig{anchorTC("gr-0-0-0", "fe80::8/64")}); err != nil {
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:2648:pkg/routing/tunnel_reconcile_test.go:359:	if err := tm.Apply([]*config.TunnelConfig{wgTC("10.77.0.1/24", "fe80::8/64")}); err != nil {
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:2651:pkg/routing/tunnel_reconcile_test.go:413:	if err := tm.Apply([]*config.TunnelConfig{wgTC("fe80::8/64")}); err != nil {
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:4033:   237		Gateway   string // "10.0.2.1" or "fe80::1"
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:4034:   238		Interface string // needed for IPv6 link-local gateways
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:4405:pkg/config/types_routing.go:96:	Interface string // outgoing interface (for IPv6 link-local)
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:4745:    95		Address   string // IP address (e.g. "10.0.1.1" or "fe80::1")
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:4746:    96		Interface string // outgoing interface (for IPv6 link-local)
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:5344:/bin/bash -lc "rg -n \"func \\(t \\*tunnelManager\\) clearLocked|clearLocked\\(\" pkg/routing/tunnel.go" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:5346:1357:	return t.clearLocked()
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:5347:1368:func (t *tunnelManager) clearLocked() error {
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:5369:  1357		return t.clearLocked()
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:5372:  1360	// clearLocked is the lock-free body of Clear. Caller must hold mu.
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:5380:  1368	func (t *tunnelManager) clearLocked() error {
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:5390:  1378			link, err := t.ops.LinkByName(name)
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:5406:  1394		// clearLocked drains every keepalive runner first
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:5426:  1414			link, err := t.ops.LinkByName(name)
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:5450:  1437			addrs, err := t.ops.AddrList(link, netlink.FAMILY_ALL)
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:5532:  1357		return t.clearLocked()
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:5535:  1360	// clearLocked is the lock-free body of Clear. Caller must hold mu.
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:5543:  1368	func (t *tunnelManager) clearLocked() error {
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:5553:  1378			link, err := t.ops.LinkByName(name)
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:5583:    95	  not own at the last apply (restart adoption; wireguard→gre same-name
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:5593:   105	  deleted only if recorded in `appliedAddrs` (a configured fe80 we
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:5594:   106	  applied), never the kernel's autoconf fe80; failed LL deletes stay
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:5611:   123	  the link admin UP). A change to the tunnel SOURCE restarts the runner
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:5621:I’m also checking the fake netlink harness because the plan’s proposed retry test must actually catch the non-link-local failure bug. The existing tests only prove the link-local retry path, not the regular address case this plan needs.
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:5737:   113	// --- §9 test 2: restart adoption + MTU ownership ---------------------
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:5744:   120		// Fresh manager (ownedNames empty) = restart adoption; tc.MTU == 0
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:5745:   120		// Fresh manager (ownedNames empty) = restart adoption; tc.MTU == 0
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:5848:/bin/bash -lc 'rg -n "addrDelFail|AddrDel|addrAdd|delNames|LinkByName|seedAnchor|newFakeLinkOps|type fake" pkg/routing/tunnel_reconcile_test.go | head -n 140' in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:5875:328:	ops.addrDelFail["gr-0-0-0|fe80::8/64"] = errors.New("EBUSY")
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:5876:337:	delete(ops.addrDelFail, "gr-0-0-0|fe80::8/64")
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:5883:417:	ops.addrDelFail["wg0|fe80::8/64"] = errors.New("EBUSY")
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:5884:425:	delete(ops.addrDelFail, "wg0|fe80::8/64")
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:5894:684:// kernelShapedGre mimics what LinkByName returns for a GRE device the
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:5908:892:		t.Fatalf("restart adoption recreated the anchor: %v", ops.delNames)
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:5972:   274	// --- §9 test 5: address reconcile + link-local rules ------------------
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:5998:   300		// Apply with a CONFIGURED fe80 — recorded in appliedAddrs.
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:5999:   301		if err := tm.Apply([]*config.TunnelConfig{anchorTC("gr-0-0-0", "fe80::8/64")}); err != nil {
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6002:   304		// Simulate the kernel's autoconf link-local appearing too.
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6003:   305		kernelLL, _ := netlink.ParseAddr("fe80::5054:ff:fe12:3456/64")
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6006:   308		// Remove the configured fe80: it must be deleted (it is ours), the
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6007:   309		// kernel's autoconf fe80 must survive (r1 Codex F2 split).
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6011:   313		if ops.hasAddr("gr-0-0-0", "fe80::8/64") {
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6012:   314			t.Fatal("configured fe80 leaked after removal from config")
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6014:   316		if !ops.hasAddr("gr-0-0-0", "fe80::5054:ff:fe12:3456/64") {
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6015:   317			t.Fatal("kernel autoconf fe80 was deleted")
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6022:   324		if err := tm.Apply([]*config.TunnelConfig{anchorTC("gr-0-0-0", "fe80::8/64")}); err != nil {
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6026:   328		ops.addrDelFail["gr-0-0-0|fe80::8/64"] = errors.New("EBUSY")
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6033:   300		// Apply with a CONFIGURED fe80 — recorded in appliedAddrs.
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6034:   301		if err := tm.Apply([]*config.TunnelConfig{anchorTC("gr-0-0-0", "fe80::8/64")}); err != nil {
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6037:   304		// Simulate the kernel's autoconf link-local appearing too.
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6038:   305		kernelLL, _ := netlink.ParseAddr("fe80::5054:ff:fe12:3456/64")
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6041:   308		// Remove the configured fe80: it must be deleted (it is ours), the
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6042:   309		// kernel's autoconf fe80 must survive (r1 Codex F2 split).
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6046:   313		if ops.hasAddr("gr-0-0-0", "fe80::8/64") {
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6047:   314			t.Fatal("configured fe80 leaked after removal from config")
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6049:   316		if !ops.hasAddr("gr-0-0-0", "fe80::5054:ff:fe12:3456/64") {
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6050:   317			t.Fatal("kernel autoconf fe80 was deleted")
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6057:   324		if err := tm.Apply([]*config.TunnelConfig{anchorTC("gr-0-0-0", "fe80::8/64")}); err != nil {
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6061:   328		ops.addrDelFail["gr-0-0-0|fe80::8/64"] = errors.New("EBUSY")
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6065:   332		if !ops.hasAddr("gr-0-0-0", "fe80::8/64") {
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6070:   337		delete(ops.addrDelFail, "gr-0-0-0|fe80::8/64")
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6074:   341		if ops.hasAddr("gr-0-0-0", "fe80::8/64") {
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6075:   342			t.Fatal("failed-delete fe80 not retried (dropped from appliedAddrs)")
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6086:/bin/bash -lc "rg -n \"type fakeLinkOps|func newFakeLinkOps|func \\(f \\*fakeLinkOps\\) AddrDel|func \\(f \\*fakeLinkOps\\) AddrAdd|addrDelFail|addrDels\" pkg/routing -g'*.go'" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6089:pkg/routing/iface_reuse_test.go:40:	// addrDelFail["name|ipnet"] makes AddrDel fail for that address on
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6096:pkg/routing/iface_reuse_test.go:143:func (f *fakeLinkOps) AddrDel(l netlink.Link, a *netlink.Addr) error {
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6101:pkg/routing/tunnel_reconcile_test.go:328:	ops.addrDelFail["gr-0-0-0|fe80::8/64"] = errors.New("EBUSY")
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6102:pkg/routing/tunnel_reconcile_test.go:337:	delete(ops.addrDelFail, "gr-0-0-0|fe80::8/64")
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6103:pkg/routing/tunnel_reconcile_test.go:417:	ops.addrDelFail["wg0|fe80::8/64"] = errors.New("EBUSY")
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6104:pkg/routing/tunnel_reconcile_test.go:425:	delete(ops.addrDelFail, "wg0|fe80::8/64")
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6107:/bin/bash -lc 'rg -n "type fakeLinkOps|addrDelFail|AddrDel" pkg/routing/*test*.go' in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6109:pkg/routing/tunnel_reconcile_test.go:328:	ops.addrDelFail["gr-0-0-0|fe80::8/64"] = errors.New("EBUSY")
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6110:pkg/routing/tunnel_reconcile_test.go:337:	delete(ops.addrDelFail, "gr-0-0-0|fe80::8/64")
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6111:pkg/routing/tunnel_reconcile_test.go:417:	ops.addrDelFail["wg0|fe80::8/64"] = errors.New("EBUSY")
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6112:pkg/routing/tunnel_reconcile_test.go:425:	delete(ops.addrDelFail, "wg0|fe80::8/64")
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6113:pkg/routing/tunnel_keepalive_test.go:91:func (o *kaOps) AddrDel(netlink.Link, *netlink.Addr) error      { return nil }
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6115:pkg/routing/iface_reuse_test.go:40:	// addrDelFail["name|ipnet"] makes AddrDel fail for that address on
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6117:pkg/routing/iface_reuse_test.go:48:	// AddrAdd/AddrDel/AddrList for the #1884 reconcile tests.
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6119:pkg/routing/iface_reuse_test.go:143:func (f *fakeLinkOps) AddrDel(l netlink.Link, a *netlink.Addr) error {
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6134:The fake supports exactly the failure injection needed (`addrDelFail["name|ipnet"]`). A test with `10.x/…`, not only `fe80`, would expose that the proposed `len(remaining)>0` retry signal never fires.
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6160:    23		// byNameErrAfter, when > 0, makes LinkByName return an error once it
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6166:    29		// hiddenUntil[name] = k makes LinkByName report not-found for the
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6177:    40		// addrDelFail["name|ipnet"] makes AddrDel fail for that address on
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6178:    41		// that link (#1884 link-local retention tests).
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6185:    48		// AddrAdd/AddrDel/AddrList for the #1884 reconcile tests.
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6210:    73	func (f *fakeLinkOps) LinkByName(name string) (netlink.Link, error) {
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6280:   143	func (f *fakeLinkOps) AddrDel(l netlink.Link, a *netlink.Addr) error {
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6297:   160	func (f *fakeLinkOps) AddrList(l netlink.Link, family int) ([]netlink.Addr, error) {
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6339:   672		restartKA := tc.Keepalive > 0 && (!hasRunner || created || !runner.matches(tc))
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6341:   674		if tc.Keepalive > 0 && hasRunner && !restartKA {
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6350:   683			if restartKA {
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6372:   705		t.appliedAddrs[tc.Name] = t.reconcileLinkAddrsLocked(
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6378:   711	// reconcileLinkAddrsLocked symmetrically reconciles a link's addresses
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6380:   713	// present-but-unconfigured — EXCEPT link-local addresses, which are
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6382:   715	// gate). The kernel's autoconf fe80 must never be deleted, while a
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6383:   716	// CONFIGURED fe80 removed from config must not leak forever (#1884 r1
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6385:   718	// first apply for a link this manager has not tracked yet — restart
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6386:   719	// adoption) means no link-local deletion at all.
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6389:   722	// link-local addresses whose stale-delete FAILED (kept tracked so the
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6391:   724	func (t *tunnelManager) reconcileLinkAddrsLocked(link netlink.Link, name string, addrs []string, applied map[string]bool, kind string) map[string]bool {
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6404:   737		if list, listErr := t.ops.AddrList(link, netlink.FAMILY_ALL); listErr == nil {
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6419:   752					// Kernel-managed or foreign link-local: never delete.
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6422:   755				if delErr := t.ops.AddrDel(link, &a); delErr != nil {
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6459:  1020		t.appliedAddrs[tc.Name] = t.reconcileLinkAddrsLocked(
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6475:   255		t.ensureReconcileStateLocked()
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6502:   282			if link, err := t.ops.LinkByName(name); err == nil {
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6530:   310			// apply (daemon restart, wireguard→gre same-name flip, foreign
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6565:   566		e, lookupErr := t.ops.LinkByName(tc.Name)
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6570:   571		case isLinkNotFound(lookupErr):
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6589:/bin/bash -lc "rg -n \"func isLinkNotFound|isLinkNotFound\\(\" pkg/routing -g'*.go'" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6591:pkg/routing/vrf.go:155:func isLinkNotFound(err error) bool {
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6592:pkg/routing/vrf.go:206:			if !isLinkNotFound(kerErr) {
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6593:pkg/routing/vrf.go:263:			if !isLinkNotFound(err) {
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6594:pkg/routing/routing_test.go:39:	// Return the real netlink not-found error so isLinkNotFound()
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6595:pkg/routing/tunnel.go:571:	case isLinkNotFound(lookupErr):
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6596:pkg/routing/tunnel.go:840:		if isLinkNotFound(err) {
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6599:/bin/bash -lc 'rg --files pkg/routing | xargs rg -n "isLinkNotFound|not found|ErrNotFound"' in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6601:pkg/routing/tunnel.go:571:	case isLinkNotFound(lookupErr):
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6602:pkg/routing/tunnel.go:840:		if isLinkNotFound(err) {
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6610:pkg/routing/routing_test.go:39:	// Return the real netlink not-found error so isLinkNotFound()
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6617:pkg/routing/vrf.go:151:// isLinkNotFound reports whether err is a "link not found" error
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6618:pkg/routing/vrf.go:155:func isLinkNotFound(err error) bool {
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6619:pkg/routing/vrf.go:206:			if !isLinkNotFound(kerErr) {
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6620:pkg/routing/vrf.go:263:			if !isLinkNotFound(err) {
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6632:   181	Add a dedicated WG ownership set `wgConfigured map[string]bool` (analogous
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6638:   187	   for each `name` in the **old** `wgConfigured` not in `wgDesired`:
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6639:   188	   - look up the link (`LinkByName`); if found, call
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6640:   189	     `reconcileLinkAddrsLocked(link, name, nil, t.appliedAddrs[name],
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6642:   191	     set), honoring the link-local applied gate (kernel autoconf fe80
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6647:   196	     commit finds `name` no longer in old `wgConfigured`, so no-op).
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6648:   197	   - If `LinkByName` fails (device already gone — manual `ip link del`),
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6650:   199	   - If `reconcileLinkAddrsLocked` leaves residual tracked addresses
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6651:   200	     because an `AddrDel` failed, **retain** the name in the next
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6652:   201	     `wgConfigured` so the next commit retries (mirrors GRE
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6655:   204	3. After the per-tunnel apply loop, set `t.wgConfigured = wgDesired`
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6663:   279	oldWG := t.wgConfigured
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6669:   285	    if link, err := t.ops.LinkByName(name); err == nil {
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6670:   286	        remaining := t.reconcileLinkAddrsLocked(link, name, nil,
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6674:   290	            nextWG[name] = true // AddrDel failed → retry next apply
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6682:   298	t.wgConfigured = nextWG
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6685:   314	contains the removed name (we set `t.wgConfigured = nextWG` which only
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6688:   317	failed-AddrDel prune keeps it in `nextWG` → retried until clean. ✔
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6690:   334	4. **`TestWireguardRemovalAddrDelFailureRetried`**: fake AddrDel returns
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6692:   336	   Apply retries AddrDel.
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6703:   151	// isLinkNotFound reports whether err is a "link not found" error
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6707:   155	func isLinkNotFound(err error) bool {
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6727:   282			if link, err := t.ops.LinkByName(name); err == nil {
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6741:/bin/bash -lc "rg -n \"LinkByName\\(name\\)|LinkByName\\(tc.Name\\)|lookup failed transiently|transient lookup|not-found\" docs/research/1919-wg-addr-route-prune/plan.md pkg/routing/tunnel.go" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6743:pkg/routing/tunnel.go:282:		if link, err := t.ops.LinkByName(name); err == nil {
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6744:pkg/routing/tunnel.go:354:	if existing, lookupErr := t.ops.LinkByName(tc.Name); lookupErr == nil {
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6745:pkg/routing/tunnel.go:384:			existing, lkErr := t.ops.LinkByName(tc.Name)
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6746:pkg/routing/tunnel.go:566:	e, lookupErr := t.ops.LinkByName(tc.Name)
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6749:pkg/routing/tunnel.go:940:	link, err := t.ops.LinkByName(tc.Name)
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6750:pkg/routing/tunnel.go:1378:		link, err := t.ops.LinkByName(name)
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6751:pkg/routing/tunnel.go:1414:		link, err := t.ops.LinkByName(name)
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6752:docs/research/1919-wg-addr-route-prune/plan.md:285:    if link, err := t.ops.LinkByName(name); err == nil {
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6770:   122	// (LinkByName + LinkSetMaster) and touches no vrfManager field. That
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6777:   129		iface, err := v.ops.LinkByName(ifaceName)
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6781:   133		vrf, err := v.ops.LinkByName(vrfName)
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6797:   174	// v.vrfs (handles the post-restart case). #847 orphan reap: any
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6803:   180	// (LinkByName / LinkSetUp) fails, the VRF is still recorded in the
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6818:   178		// ensured (successful adds + present-and-wanted + link-local whose
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6820:   180		// configured fe80 we applied is removable; the kernel's autoconf
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6821:   181		// fe80 is never touched.
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6863:   838		vrf, err := t.ops.LinkByName("vrf-" + claim)
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6865:   840			if isLinkNotFound(err) {
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6888:  1020		t.appliedAddrs[tc.Name] = t.reconcileLinkAddrsLocked(
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6952:pkg/routing/vrf.go:122:// (LinkByName + LinkSetMaster) and touches no vrfManager field. That
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6961:- **MAJOR: Path A’s retry signal is broken for regular addresses.** The plan’s removal sketch relies on `len(remaining)>0` after `reconcileLinkAddrsLocked(..., nil, ...)` to retain `wgConfigured` for retry ([plan.md:285](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/docs/research/1919-wg-addr-route-prune/plan.md:285), [plan.md:288](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/docs/research/1919-wg-addr-route-prune/plan.md:288)). But source only re-adds a failed stale delete to `newApplied` if the address is link-local: `if a.IP.IsLinkLocalUnicast() { newApplied[key] = true }` ([tunnel.go:755](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/tunnel.go:755), [tunnel.go:758](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/tunnel.go:758)). With empty desired addrs, a failed `AddrDel` for `172.16.0.1/30` returns an empty map, so Path A deletes tracking and does not retry ([plan.md:293](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/docs/research/1919-wg-addr-route-prune/plan.md:293)). The fake confirms failed `AddrDel` leaves the address present ([iface_reuse_test.go:143](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/iface_reuse_test.go:143)). This must be fixed before implementation. The proposed retry test must use a non-link-local address, not only `fe80`.
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6963:- **MAJOR/MEDIUM: Path A can also strand tracking on transient `LinkByName` failure.** The plan treats any lookup failure as “device already gone” and drops tracking ([plan.md:197](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/docs/research/1919-wg-addr-route-prune/plan.md:197), [plan.md:285](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/docs/research/1919-wg-addr-route-prune/plan.md:285)). Source explicitly says only not-found is absence; EBUSY/transport errors are transient and must not be treated as gone ([vrf.go:151](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/vrf.go:151), [tunnel.go:558](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/tunnel.go:558)). For WG removal, a transient lookup error would drop `appliedAddrs` and `wgConfigured`, leaving stale addresses with no future retry.
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6965:- **MEDIUM: The plan overclaims “manager-applied addresses only.”** `appliedAddrs` only gates stale link-local deletion. For non-link-local stale addresses, `reconcileLinkAddrsLocked` deletes them regardless of whether they are in `applied` ([tunnel.go:751](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/tunnel.go:751), [tunnel.go:755](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/tunnel.go:755)). That may match existing configured-WG behavior, but the plan should stop claiming the removal path is strictly applied-address scoped unless it adds an explicit filter.
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6971:- **Restart adoption boundary is acceptable to defer.** The proposed `wgConfigured` and existing `appliedAddrs` are in-memory reconcile state ([tunnel.go:176](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/tunnel.go:176)). A daemon that restarts after config removal has no old WG membership to diff. That limitation is real, but consistent with the chosen tracked-only design.
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6975:Clean add → remove → remove-again is idempotent only when all deletes and lookup succeed. The non-link-local `AddrDel` failure path breaks the plan’s central retry invariant, so this is not ready.
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6982:- **MAJOR: Path A’s retry signal is broken for regular addresses.** The plan’s removal sketch relies on `len(remaining)>0` after `reconcileLinkAddrsLocked(..., nil, ...)` to retain `wgConfigured` for retry ([plan.md:285](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/docs/research/1919-wg-addr-route-prune/plan.md:285), [plan.md:288](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/docs/research/1919-wg-addr-route-prune/plan.md:288)). But source only re-adds a failed stale delete to `newApplied` if the address is link-local: `if a.IP.IsLinkLocalUnicast() { newApplied[key] = true }` ([tunnel.go:755](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/tunnel.go:755), [tunnel.go:758](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/tunnel.go:758)). With empty desired addrs, a failed `AddrDel` for `172.16.0.1/30` returns an empty map, so Path A deletes tracking and does not retry ([plan.md:293](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/docs/research/1919-wg-addr-route-prune/plan.md:293)). The fake confirms failed `AddrDel` leaves the address present ([iface_reuse_test.go:143](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/iface_reuse_test.go:143)). This must be fixed before implementation. The proposed retry test must use a non-link-local address, not only `fe80`.
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6984:- **MAJOR/MEDIUM: Path A can also strand tracking on transient `LinkByName` failure.** The plan treats any lookup failure as “device already gone” and drops tracking ([plan.md:197](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/docs/research/1919-wg-addr-route-prune/plan.md:197), [plan.md:285](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/docs/research/1919-wg-addr-route-prune/plan.md:285)). Source explicitly says only not-found is absence; EBUSY/transport errors are transient and must not be treated as gone ([vrf.go:151](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/vrf.go:151), [tunnel.go:558](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/tunnel.go:558)). For WG removal, a transient lookup error would drop `appliedAddrs` and `wgConfigured`, leaving stale addresses with no future retry.
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6986:- **MEDIUM: The plan overclaims “manager-applied addresses only.”** `appliedAddrs` only gates stale link-local deletion. For non-link-local stale addresses, `reconcileLinkAddrsLocked` deletes them regardless of whether they are in `applied` ([tunnel.go:751](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/tunnel.go:751), [tunnel.go:755](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/tunnel.go:755)). That may match existing configured-WG behavior, but the plan should stop claiming the removal path is strictly applied-address scoped unless it adds an explicit filter.
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6992:- **Restart adoption boundary is acceptable to defer.** The proposed `wgConfigured` and existing `appliedAddrs` are in-memory reconcile state ([tunnel.go:176](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/tunnel.go:176)). A daemon that restarts after config removal has no old WG membership to diff. That limitation is real, but consistent with the chosen tracked-only design.
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6996:Clean add → remove → remove-again is idempotent only when all deletes and lookup succeed. The non-link-local `AddrDel` failure path breaks the plan’s central retry invariant, so this is not ready.
./test/incus/step1-capture.sh:252:# I8: record daemon ActiveEnterTimestamp for the worker-restart check.
./test/incus/step1-capture.sh:430:# I8 — daemon did not restart mid-cell.
./test/incus/step1-capture.sh:432:	add_fail "I8: daemon restarted mid-cell ($DAEMON_START_PRE -> $DAEMON_START_POST)"
./pkg/dataplane/userspace/cosfmt.go:194:		// tabs restarts tabwriter's contiguous-column grouping — so we
./docs/research/1881-gre-frozen-state/claude-smr-plan-r1.md:139:  operational correctness (restart-required staleness, runtime
./docs/research/1880-boot-budget/codex-plan-r2.md:6:   today's stale removals converge only via the FRR murder+restart that
./test/incus/test-restart-connectivity.sh:2:# xpf restart connectivity regression test
./test/incus/test-restart-connectivity.sh:4:# Validates that daemon restart in HA mode does not cause transient
./test/incus/test-restart-connectivity.sh:14:#   3. Assert ≤ MAX_LOST_PINGS lost during restart (default: 2)
./test/incus/test-restart-connectivity.sh:18:#   ./test/incus/test-restart-connectivity.sh
./test/incus/test-restart-connectivity.sh:19:#   RESTART_CYCLES=5 MAX_LOST_PINGS=1 ./test/incus/test-restart-connectivity.sh
./test/incus/test-restart-connectivity.sh:39:PRE_RESTART_PINGS=6                          # pings before restart (3s)
./test/incus/test-restart-connectivity.sh:45:PING_LOG="/tmp/xpf-restart-ping.log"
./test/incus/test-restart-connectivity.sh:144:	info "Cycle ${cycle}/${RESTART_CYCLES}: restart xpfd on fw0 while pinging"
./test/incus/test-restart-connectivity.sh:154:	# Wait for a few pings to succeed before restart (3s)
./test/incus/test-restart-connectivity.sh:158:	incus exec "$FW0" -- systemctl restart xpfd 2>/dev/null || true
./test/incus/test-restart-connectivity.sh:160:	# Wait for ping to finish (~22s total ping time minus 3s pre-restart + 5s buffer)
./docs/research/1881-gre-frozen-state/agy-plan-r1.md:9:Each of the six failures (`F1` through `F6`) is **verified as fully reachable** under the current master branch without daemon restarts or full binding plan changes:
./docs/research/1881-gre-frozen-state/agy-plan-r1.md:34:    Yes, `(logical_ifindex, resolved name)` is a complete and robust restart condition. Under Linux, if a TUN interface is deleted via `LinkDel` ([pkg/routing/tunnel.go:114](file:///home/ps/git/bpfrx/.claude/worktrees/1881-research/pkg/routing/tunnel.go#L114)) and recreated with the same name, any existing open file descriptor associated with the deleted link is invalidated by the kernel. Subsequent operations on the old fd fail with fatal errors (`EBADFD` / `ENODEV`). The thread will detect the failure via [local_tunnel_io_error_is_fatal](file:///home/ps/git/bpfrx/.claude/worktrees/1881-research/userspace-dp/src/afxdp/tunnel.rs#L7), exit its loop, and be reaped by the coordinator's finished-sweep (Pass 1). The next apply or status poll (1/s) will then spawn a new thread with the new fd. This recovery window is sub-millisecond during config apply, and at most ~1s during idle, which is completely acceptable for a cold path. No fd-generation check is required.
./docs/research/1881-gre-frozen-state/agy-plan-r1.md:37:    Stopping GRE local-origin threads on a disarmed same-plan refresh is correct. When userspace-dp is disarmed, workers are stopped, so there is no path to transmit enqueued packets. More importantly, during In-Service Software Upgrades (ISSU) or daemon restarts, keeping the TUN file descriptor open in a disarmed helper would block the incoming daemon instance from taking exclusive ownership of the TUN device, causing bind failures and upgrade locks. Releasing these file descriptors is necessary.
./docs/research/1880-boot-budget/claude-smr-plan-r1.md:12:  empty → auto-restart. Deterministic, not raced.
./docs/research/1880-boot-budget/claude-smr-plan-r1.md:72:  exercised by every deploy restart and by `test-restart-connectivity`;
./test/incus/test-failover.sh:245:	pass "fw0 xpfd restarted after reboot"
./test/incus/xpf-test.conf:457:            next-hop fe80::50 {
./pkg/dataplane/userspace/protocol.go:638:	// warmer worker thread died (fatal — warming disabled until restart).
./pkg/dataplane/userspace/protocol.go:1142:	// today — cleared only by daemon restart. Phase 2 surfaces this
./docs/research/1881-gre-frozen-state/plan.md:124:| # | Operation | Stale behavior until daemon restart / full binding reconcile |
./docs/research/1881-gre-frozen-state/plan.md:131:| F6 | Thread death (TUN open failure at bring-up race, panic, fatal io error) | Permanently dead until restart — `supervisor.rs:42`: "that tunnel's local-origin packet stream stops". No respawn exists today. |
./docs/research/1881-gre-frozen-state/plan.md:140:  local-origin path without a daemon restart (Junos parity — vSRX
./docs/research/1881-gre-frozen-state/plan.md:146:  restart (AGY round-1 Q7). Not an arbitrary-party mis-encap (the
./docs/research/1881-gre-frozen-state/plan.md:148:  effect only at restart is security-relevant;
./docs/research/1881-gre-frozen-state/plan.md:199:- **Path C — restart all GRE threads on every refresh.** Heavy:
./docs/research/1881-gre-frozen-state/plan.md:204:  general mechanism (restart remains the targeted remedy for
./docs/research/1881-gre-frozen-state/plan.md:208:  state through the ArcSwap (no restart on content/route/CoS
./docs/research/1881-gre-frozen-state/plan.md:211:  and periodic liveness, restarting a thread ONLY when its TUN
./docs/research/1881-gre-frozen-state/plan.md:310:through the ArcSwap and need no restart):
./docs/research/1881-gre-frozen-state/plan.md:346:     `attachment_changed` (restart is the only remedy — the TUN fd
./docs/research/1881-gre-frozen-state/plan.md:376:(skip both stores if no entry was added/removed/restarted).
./docs/research/1881-gre-frozen-state/plan.md:449:  plan-scoped; full reconcile already restarts these threads).
./docs/research/1881-gre-frozen-state/plan.md:541:     `attachment_changed` restart (Codex R5);
./docs/research/1881-gre-frozen-state/plan.md:573:WITHOUT daemon restart; (b) commit an underlay route change and
./docs/research/1919-wg-addr-route-prune/plan.md:53:  / `reconcileLinkAddrsLocked` is **never called for it again**, and
./docs/research/1919-wg-addr-route-prune/plan.md:60:or daemon restart). The in-code comment at `tunnel.go:790-794` already
./docs/research/1919-wg-addr-route-prune/plan.md:99:is `AddrDel`'d — it is not a separate object we manage). There is **no
./docs/research/1919-wg-addr-route-prune/plan.md:120:instant its address is `AddrDel`'d. So fixing the address leak ALSO
./docs/research/1919-wg-addr-route-prune/plan.md:136:| `pkg/routing/tunnel.go:798-890` `applyWireguardTunLocked` | create/reuse wgN; MTU; `reconcileLinkAddrsLocked`; VRF bind |
./docs/research/1919-wg-addr-route-prune/plan.md:137:| `pkg/routing/tunnel.go:584-645` `reconcileLinkAddrsLocked` | symmetric add/del against desired addr set; link-local gate; returns new applied set |
./docs/research/1919-wg-addr-route-prune/plan.md:140:| `pkg/routing/tunnel.go:1086-1113` `clearLocked` | delete-everything path (ClearTunnels); does NOT delete WG (not in tunnels/ownedNames) |
./docs/research/1919-wg-addr-route-prune/plan.md:144:| `pkg/routing/tunnel_reconcile_test.go` | existing WG tests: only link-local cases (356/390/410); NO removal test |
./docs/research/1919-wg-addr-route-prune/plan.md:184:address set**, which `reconcileLinkAddrsLocked(link, name, nil,
./docs/research/1919-wg-addr-route-prune/plan.md:186:wanted, respecting the link-local applied gate). We just need to *call*
./docs/research/1919-wg-addr-route-prune/plan.md:198:Add a dedicated WG ownership set `wgConfigured map[string]bool` (analogous
./docs/research/1919-wg-addr-route-prune/plan.md:204:   for each `name` in the **old** `wgConfigured` not in `wgDesired`:
./docs/research/1919-wg-addr-route-prune/plan.md:205:   - look up the link (`LinkByName`):
./docs/research/1919-wg-addr-route-prune/plan.md:207:       `pruneAppliedAddrsLocked(link, name, t.appliedAddrs[name])`
./docs/research/1919-wg-addr-route-prune/plan.md:210:       non-link-local semantics) plus configured/applied link-locals,
./docs/research/1919-wg-addr-route-prune/plan.md:211:       honoring the same autoconf-fe80 gate, and **returns the set of
./docs/research/1919-wg-addr-route-prune/plan.md:212:       addresses whose `AddrDel` FAILED across ALL families**. **Keep
./docs/research/1919-wg-addr-route-prune/plan.md:219:     - On **`LinkByName` error**: gate on `isLinkNotFound(err)`
./docs/research/1919-wg-addr-route-prune/plan.md:228:3. After the per-tunnel apply loop, set `t.wgConfigured = nextWG`
./docs/research/1919-wg-addr-route-prune/plan.md:231:#### r2 design note — why a dedicated `pruneAppliedAddrsLocked`, NOT `reconcileLinkAddrsLocked(…, nil, …)`
./docs/research/1919-wg-addr-route-prune/plan.md:234:inferring "AddrDel failed, retry" from `len(remaining)>0` of
./docs/research/1919-wg-addr-route-prune/plan.md:235:`reconcileLinkAddrsLocked` — is **broken**: that function only records a
./docs/research/1919-wg-addr-route-prune/plan.md:237:**link-local** (`tunnel.go:618`); a failed `AddrDel` of a regular v4/v6
./docs/research/1919-wg-addr-route-prune/plan.md:243:- **(a)** change `reconcileLinkAddrsLocked` to also record non-link-local
./docs/research/1919-wg-addr-route-prune/plan.md:249:  `pruneAppliedAddrsLocked(link, name, applied) (failed map[string]bool)`
./docs/research/1919-wg-addr-route-prune/plan.md:251:  1. `AddrList`s the device,
./docs/research/1919-wg-addr-route-prune/plan.md:252:  2. for each present address: skip autoconf/foreign link-local
./docs/research/1919-wg-addr-route-prune/plan.md:254:     identical gate to `reconcileLinkAddrsLocked:611`), otherwise
./docs/research/1919-wg-addr-route-prune/plan.md:255:     `AddrDel`,
./docs/research/1919-wg-addr-route-prune/plan.md:256:  3. on `AddrDel` failure record `failed[key]=true` for **every** family
./docs/research/1919-wg-addr-route-prune/plan.md:257:     (the fix — not just link-local),
./docs/research/1919-wg-addr-route-prune/plan.md:259:  `reconcileLinkAddrsLocked` is left **untouched** (frozen contract).
./docs/research/1919-wg-addr-route-prune/plan.md:265:`appliedAddrs` + the link-local gate; idempotent; link preserved; the new
./docs/research/1919-wg-addr-route-prune/plan.md:270:across `clearLocked` (reset) and `ensureReconcileStateLocked` (lazy init).
./docs/research/1919-wg-addr-route-prune/plan.md:290:exact assets (`appliedAddrs`, `reconcileLinkAddrsLocked`) the manager
./docs/research/1919-wg-addr-route-prune/plan.md:299:deletes **every present non-link-local address** on the device
./docs/research/1919-wg-addr-route-prune/plan.md:300:(`AddrDel` for all of them), and for **link-local** it deletes only the
./docs/research/1919-wg-addr-route-prune/plan.md:301:configured/applied ones (autoconf/foreign fe80 gated out). The
./docs/research/1919-wg-addr-route-prune/plan.md:302:`appliedAddrs[name]` set gates link-local deletion ONLY — it does NOT
./docs/research/1919-wg-addr-route-prune/plan.md:303:restrict non-link-local deletion. This is **identical** to the
./docs/research/1919-wg-addr-route-prune/plan.md:304:steady-state reconcile (`reconcileLinkAddrsLocked` deletes all present-
./docs/research/1919-wg-addr-route-prune/plan.md:305:but-unwanted non-link-local addresses regardless of `applied`), so the
./docs/research/1919-wg-addr-route-prune/plan.md:308:operator manually `ip addr add`'d a non-fe80 address to a configured wgN,
./docs/research/1919-wg-addr-route-prune/plan.md:311:"the manager owns the device's non-link-local address set" behavior, not
./docs/research/1919-wg-addr-route-prune/plan.md:352:// wgConfigured: WG tunnel names configured at the LAST Apply (plus
./docs/research/1919-wg-addr-route-prune/plan.md:356:wgConfigured map[string]bool
./docs/research/1919-wg-addr-route-prune/plan.md:359:`ensureReconcileStateLocked`: add `if t.wgConfigured == nil { … }`.
./docs/research/1919-wg-addr-route-prune/plan.md:361:New helper (removal-only; leaves `reconcileLinkAddrsLocked` untouched):
./docs/research/1919-wg-addr-route-prune/plan.md:363:// pruneAppliedAddrsLocked deletes the addresses this manager owns from a
./docs/research/1919-wg-addr-route-prune/plan.md:365:// present non-link-local address, plus configured/applied link-locals;
./docs/research/1919-wg-addr-route-prune/plan.md:366:// the kernel autoconf/foreign fe80 is never touched (same gate as
./docs/research/1919-wg-addr-route-prune/plan.md:367:// reconcileLinkAddrsLocked). Returns the set of addresses whose AddrDel
./docs/research/1919-wg-addr-route-prune/plan.md:370:func (t *tunnelManager) pruneAppliedAddrsLocked(link netlink.Link, name string, applied map[string]bool) map[string]bool {
./docs/research/1919-wg-addr-route-prune/plan.md:372:    list, err := t.ops.AddrList(link, netlink.FAMILY_ALL)
./docs/research/1919-wg-addr-route-prune/plan.md:385:            continue // kernel autoconf / foreign link-local: never delete
./docs/research/1919-wg-addr-route-prune/plan.md:387:        if delErr := t.ops.AddrDel(link, &a); delErr != nil {
./docs/research/1919-wg-addr-route-prune/plan.md:406:oldWG := t.wgConfigured
./docs/research/1919-wg-addr-route-prune/plan.md:411:    link, err := t.ops.LinkByName(name)
./docs/research/1919-wg-addr-route-prune/plan.md:413:        if isLinkNotFound(err) {
./docs/research/1919-wg-addr-route-prune/plan.md:421:    failed := t.pruneAppliedAddrsLocked(link, name, t.appliedAddrs[name])
./docs/research/1919-wg-addr-route-prune/plan.md:424:        nextWG[name] = true // AddrDel failed → retry next apply
./docs/research/1919-wg-addr-route-prune/plan.md:431://     via applyWireguardTunLocked → reconcileLinkAddrsLocked at :880) ...
./docs/research/1919-wg-addr-route-prune/plan.md:432:t.wgConfigured = nextWG
./docs/research/1919-wg-addr-route-prune/plan.md:439:`nextWG` → next `Apply` is a no-op for it (idempotent ✔). On AddrDel/
./docs/research/1919-wg-addr-route-prune/plan.md:442:`clearLocked`: add `t.wgConfigured = nil` to the reset block (:1109).
./docs/research/1919-wg-addr-route-prune/plan.md:451:contains the removed name (we set `t.wgConfigured = nextWG` which only
./docs/research/1919-wg-addr-route-prune/plan.md:454:failed-AddrDel prune keeps it in `nextWG` → retried until clean. ✔
./docs/research/1919-wg-addr-route-prune/plan.md:463:   tunnel carrying `172.16.0.1/30` (+ optional fe80 configured) → assert
./docs/research/1919-wg-addr-route-prune/plan.md:465:   (a) link is NOT deleted (no LinkDel for wgN), (b) AddrDel called for
./docs/research/1919-wg-addr-route-prune/plan.md:466:   `172.16.0.1/30`, (c) configured fe80 deleted, kernel autoconf fe80
./docs/research/1919-wg-addr-route-prune/plan.md:467:   untouched (reuse the link-local gate test fixtures at :349-435).
./docs/research/1919-wg-addr-route-prune/plan.md:469:   → assert NO further AddrDel / LinkByName churn for the pruned name
./docs/research/1919-wg-addr-route-prune/plan.md:471:4. **`TestWireguardRemovalAddrDelFailureRetried`**: fake AddrDel returns
./docs/research/1919-wg-addr-route-prune/plan.md:472:   error on first removal Apply for a **non-link-local** address
./docs/research/1919-wg-addr-route-prune/plan.md:474:   regular-address case, not only fe80) → assert name retained in
./docs/research/1919-wg-addr-route-prune/plan.md:475:   tracking, second removal Apply retries AddrDel, third (success) drops
./docs/research/1919-wg-addr-route-prune/plan.md:477:5. **`TestWireguardRemovalDeviceNotFoundDropsTracking`**: LinkByName
./docs/research/1919-wg-addr-route-prune/plan.md:480:6. **`TestWireguardRemovalTransientLookupRetained`**: LinkByName returns
./docs/research/1919-wg-addr-route-prune/plan.md:484:   `linkOps` to support an injectable non-not-found LinkByName error.
./docs/research/1919-wg-addr-route-prune/plan.md:489:   FRESH manager (empty `wgConfigured`) with a wgN carrying addresses
./docs/research/1919-wg-addr-route-prune/plan.md:490:   present in the kernel + an empty tunnel list → assert NO AddrDel
./docs/research/1919-wg-addr-route-prune/plan.md:491:   (the manager only prunes what it tracked applying; restart-time
./docs/research/1919-wg-addr-route-prune/plan.md:495:   `reconcileLinkAddrsLocked` is NOT modified).
./docs/research/1919-wg-addr-route-prune/plan.md:497:All tests assert via the fake's recorded `AddrAdd`/`AddrDel`/`LinkDel`
./docs/research/1919-wg-addr-route-prune/plan.md:537:  the prune deletes ALL present non-link-local addresses (the manager
./docs/research/1919-wg-addr-route-prune/plan.md:538:  owns the device's non-link-local set, same as steady-state reconcile),
./docs/research/1919-wg-addr-route-prune/plan.md:539:  and only configured/applied link-locals; the kernel autoconf/foreign
./docs/research/1919-wg-addr-route-prune/plan.md:540:  fe80 is gated out by the shared link-local check.
./docs/research/1919-wg-addr-route-prune/plan.md:543:- **R3 — retry storms on persistent AddrDel failure**: bounded by the
./docs/research/1919-wg-addr-route-prune/plan.md:545:  most one AddrDel attempt per residual address.
./docs/research/1919-wg-addr-route-prune/plan.md:547:- **R5 — interaction with restart adoption** (`appliedAddrs == nil`):
./docs/research/1919-wg-addr-route-prune/plan.md:548:  on a fresh daemon, `wgConfigured` is empty, so a WG tunnel removed
./docs/research/1919-wg-addr-route-prune/plan.md:550:  This is the **same restart-adoption limitation** the rest of the file
./docs/research/1919-wg-addr-route-prune/plan.md:552:  known boundary; full restart-time WG reconciliation is #1434 scope.
./docs/research/1919-wg-addr-route-prune/plan.md:553:  (A reviewer may ask for a restart-time sweep — explicitly defer.)
./docs/research/1919-wg-addr-route-prune/plan.md:573:  to remove/replace the "leaks until ip link del or daemon restart"
./docs/research/1919-wg-addr-route-prune/plan.md:576:  (restart-time removal, VRF residual, link+peer kept).
./docs/research/1919-wg-addr-route-prune/plan.md:619:t.appliedAddrs[tc.Name] = t.reconcileLinkAddrsLocked(
./docs/research/1919-wg-addr-route-prune/plan.md:626:// tunnel REMOVED from the config is not torn down by clearLocked and
./docs/research/1919-wg-addr-route-prune/plan.md:627:// leaks until `ip link del` or daemon restart. S2a single-tunnel scope
./docs/research/1880-boot-budget/plan.md:66:restarts watchfrr** ("restart watchfrr to pick up added daemons":
./docs/research/1880-boot-budget/plan.md:97:- (a) **FRR is SIGKILLed ~2min after every commit/deploy** and auto-restarts.
./docs/research/1880-boot-budget/plan.md:99:  restart re-reads frr.conf (which xpfd keeps current).
./docs/research/1880-boot-budget/plan.md:104:  restart accidentally applies the full config. Route deletions can take up
./docs/research/1880-boot-budget/plan.md:148:  murder+restart that Path A removes — so a degraded fallback must not
./docs/research/1880-boot-budget/plan.md:300:   2-minute FRR restart.
./docs/research/1880-boot-budget/claude-smr-plan-r2.md:6:depends on the very FRR murder+restart Path A deletes). That is the
./docs/research/1880-boot-budget/claude-smr-plan-r2.md:11:  fallback persistence is indefinite on an idle config — no restart, no
./pkg/dataplane/userspace/neighbors.go:143:			link, err := netlink.LinkByName(linuxName)
./pkg/dataplane/userspace/neighbors.go:185:			link, err := netlink.LinkByName(linuxName)
./userspace-dp/src/afxdp/worker_runtime.rs:241:    /// cleared only by daemon restart. Phase 2 added the
./pkg/config/parser_routing_test.go:1504:	cmds := []string{"set protocols bgp local-as 65001", "set protocols bgp graceful-restart", "set protocols bgp group external peer-as 65002", "set protocols bgp group external neighbor 10.0.0.2"}
./pkg/config/parser_routing_test.go:3138:	lines := []string{"set routing-options static route ::/0 qualified-next-hop fe80::2d0:f6ff:feda:c180 interface reth2.0"}
./pkg/config/parser_routing_test.go:3163:	if nh.Address != "fe80::2d0:f6ff:feda:c180" {
./pkg/config/parser_routing_test.go:3164:		t.Errorf("Address = %q, want fe80::2d0:f6ff:feda:c180", nh.Address)
./pkg/config/parser_routing_test.go:3176:            qualified-next-hop fe80::2d0:f6ff:feda:c180 {
./pkg/config/parser_routing_test.go:3200:	if nh.Address != "fe80::2d0:f6ff:feda:c180" {
./pkg/config/parser_routing_test.go:3201:		t.Errorf("Address = %q, want fe80::2d0:f6ff:feda:c180", nh.Address)
./pkg/config/parser_routing_test.go:3210:	lines := []string{"set routing-instances ATT instance-type virtual-router", "set routing-instances ATT routing-options rib ATT.inet6.0 static route ::/0 qualified-next-hop fe80::2d0:f6ff:feda:c180 interface reth2.0"}
./pkg/config/parser_routing_test.go:3242:	if nh.Address != "fe80::2d0:f6ff:feda:c180" {
./pkg/config/parser_routing_test.go:3243:		t.Errorf("Address = %q, want fe80::2d0:f6ff:feda:c180", nh.Address)
./_Log.md:2477:    restart even before Chain A (#1526) blocks the commit. Addressed
./_Log.md:3463:  - **Action**: Issue #467 — Fix bulk-prime retry loop not restarting after failed demotion barrier. `prepareUserspaceRGDemotionWithTimeout` stopped the retry loop by advancing `syncPrimeRetryGen` before waiting on barriers, but on barrier failure returned without restarting the loop, stranding the peer in an unprimed state. Added a defer that restarts `startSessionSyncPrimeRetry` on failure when peer is still connected and not yet primed.
./_Log.md:5087:  (start new / stop removed / restart option-changed; diff keys NEVER on
./_Log.md:5093:  Tests: reconcile add/remove/option-change-restart/DUID-change-restart/
./_Log.md:5094:  lease-change-no-restart, terminal-exit deregister + restartable, StopAll
./_Log.md:5096:  lease-change-no-restart. README reconcile-lifecycle section added.
./_Log.md:5154:  mapping, LinkByName seeding), UpdateInstances compares + in-place
./_Log.md:5228:  regenerate Kea configs (master-RG filtered) and restart only active units,
./_Log.md:5328:  - **Action**: PR-1a tests (pin assignment/same-target-two-uplinks/cap/band-cleanup-on-restart; prober seam pass/v6/timeout/foreign-reply/sockopts; transition hook; flat-set+hierarchical parse; validation rejections; reconcileRPM hash gating) + README updates (pkg/rpm, pkg/routing). All green.
./_Log.md:5432:  - **Action**: #1736 live bring-up found + fixed two S2a datapath bugs (v4-mapped learned-endpoint MTU-guard inflation; EINVAL on v4 sendto over the dual-stack socket via wg_send_to), filed #1865 (WG telemetry) + #1866 (removal leaks control thread/port), hardened harness (node0-primary wait, fresh keys, leak restart fallback, 90s handshake budget), runbook updated with live shared-cluster hazards.
./_Log.md:5569:  **Action**: #1904 + #1905 combined /engineer lane (both filed from the #1884 research). #1904: shared riMemberLinuxName now resolves RI tunnel list members through cfg.TunnelNameMap() (compiler-assigned TunnelConfig.Name verbatim — exact device-name parity by construction), so unit>0 members like gr-0/0/0.1 bind the real uN device (gr-0-0-0u1); non-tunnel refs keep the literal transform byte-identically. #1905: applyWireguardTunLocked passes/stores t.appliedAddrs like the GRE branch, so a CONFIGURED fe80 removed from config reconciles away while kernel-autonomous fe80s are never touched. Live on loss userspace cluster: 10/10 PASS (gr-0-0-1u1 master vrf-vrf1904; configured fe80 removed, foreign fe80::beef + kernel stable-privacy LL survive). go build/test/-race clean.
./_Log.md:5625:- **Action**: Implemented increment A (packaging only) of #1917; subsumes #1923. Added debian/ (control, rules, changelog, source/format, xpf.postinst/postrm, xpf.needrestart), `make deb` target, and changed scripts/image/bake.py to build+install the .deb instead of --copy-in. Addressed round-1 AGY (7) + Codex (incl. HIGH ExecStartPre) findings. End-to-end bake validation PASS (Scenario A/B/C). 
./_Log.md:5626:- **File(s)**: debian/control, debian/rules, debian/changelog, debian/source/format, debian/xpf.postinst, debian/xpf.postrm, debian/xpf.needrestart, debian/.gitignore, Makefile, scripts/image/bake.py, docs/install-images.md, docs/pr/1917a-xpf-deb/reviewer-ids.md
./_Log.md:5655:- **Action**: Copilot formal review fixes — fail-closed msg points at .configdb/active.json; postinst restart safety-net on cut-over failure; cutover Options doc (UnitAlreadyStopped). Other Copilot findings already fixed in r1-r5.
./_Log.md:5696:  - **Action**: #1930 INC-0 (PR-1 first slice) — image kernel hold + apt safety. bake.py now `apt-mark hold`s the installed linux-* set (dpkg-query enumeration, not a bare glob; HARD-ASSERTs ≥2 held), writes an unattended-upgrades Package-Blacklist for linux-*, and a needrestart blacklist for xpfd + the runtime version dirs. Closes the "unattended apt moves the verifier floor" hole with no daemon code.
./_Log.md:5700:  - **Action**: #1930 INC-0 review round 1 (Codex) fixes — (1) DROPPED the bake-written /etc/needrestart/conf.d/99-xpf.conf: the package already ships the correct APPEND-form snippet (debian/xpf.needrestart -> .../xpf.conf via the .deb install); my whole-hash assignment would have wiped needrestart defaults and the write preceded the dir's creation. (2) Hardened the kernel-hold shell: `set -e` makes apt-mark failure fatal, and per-package verification against `apt-mark showhold` replaces the count>=2 check (a pre-existing unrelated hold could false-pass the count). Verified success + partial-hold cases.
./docs/issues/issue-history.md:1472:## #68 — HA mode: disable hitless restart semantics by default [CLOSED] (closed 2026-03-02)
./docs/issues/issue-history.md:1475:In HA (`chassis cluster`) mode, the daemon currently preserves dataplane state for hitless restart. That behavior is useful for standalone upgrades, but in HA it can keep forwarding active on a node whose control plane is down/hung, which increases split-brain risk during failover.
./docs/issues/issue-history.md:1487:1. Disable hitless-restart semantics by default.
./docs/issues/issue-history.md:1493:In HA, correctness and deterministic failover are more important than preserving local forwarding through daemon restarts.
./docs/issues/issue-history.md:1498:- Standalone mode still supports hitless restart behavior.
./docs/issues/issue-history.md:1671:## #74 — Investigation: transient 10-30s loss to 172.16.100.247 after deploy restart [CLOSED] (closed 2026-03-02)
./docs/issues/issue-history.md:1674:After deploy restart in HA environment, traffic from `cluster-lan-host` to `172.16.100.247` can fail for ~10-30 seconds, then recover on its own.
./docs/issues/issue-history.md:1677:- `ping 172.16.100.247` from `cluster-lan-host` times out immediately after restart.
./docs/issues/issue-history.md:1682:- Likely in ARP/neighbor/FIB convergence path during restart/failover handoff.
./docs/issues/issue-history.md:1687:2. Capture packets (ARP + ICMP + relevant routed path) on ingress/egress interfaces during the first 30s after restart.
./docs/issues/issue-history.md:1693:4. Verify whether `warmNeighborCache()` includes and successfully primes this exact destination path in restart scenarios.
./docs/issues/issue-history.md:1697:- Add deterministic fix and regression test so restart does not cause temporary loss to `172.16.100.247`.
./docs/issues/issue-history.md:1706:## #75 — HA restart: neighbor prewarm runs before VRRP VIP ownership, causing 10-30s transient WAN loss [CLOSED] (closed 2026-03-02)
./docs/issues/issue-history.md:1709:Transient `cluster-lan-host -> 172.16.100.247` loss (~10-30s) after deploy restart is caused by **neighbor prewarm running too early** in HA startup.
./docs/issues/issue-history.md:1712:1. In HA/VRRP-backed RETH, networkd uses a link-local placeholder address (not the WAN/LAN VIP) until VRRP MASTER adds real VIPs:
./docs/issues/issue-history.md:1730:- Immediate post-restart internet connectivity from LAN can fail transiently.
./docs/issues/issue-history.md:1736:3. Add restart regression test:
./docs/issues/issue-history.md:1812:- In large-session restart tests, preemption does not occur before bulk sync completion unless operator-configured fallback policy allows it.
./docs/issues/issue-history.md:1911:- New NAT/route/address-book targets are warmed without daemon restart.
./docs/issues/issue-history.md:1920:Cluster comms startup uses fixed retry budgets (30 attempts x 2s) for heartbeat and session sync. If retries exhaust during slow interface/VRF bring-up, HA comms never recover until daemon restart.
./docs/issues/issue-history.md:1934:- Requires manual daemon restart to recover.
./docs/issues/issue-history.md:1943:- Heartbeat/session sync eventually come up without manual restart.
./docs/issues/issue-history.md:2130:- Runtime config apply updates cluster state/config but does not restart comms endpoints:
./docs/issues/issue-history.md:2134:- Changes to `control-interface`, `peer-address`, `fabric-interface`, or `fabric-peer-address` may not take effect until daemon restart.
./docs/issues/issue-history.md:2144:- HA transport endpoint changes apply without daemon restart.
./docs/issues/issue-history.md:2375:- Lifecycle leaks/races during teardown/restart paths.
./docs/issues/issue-history.md:2377:- Harder to guarantee clean fail-closed behavior under repeated restart/failover testing.
./docs/issues/issue-history.md:2395:When a node restarts and rejoins an HA cluster, VRRP preemption suppression (`sync hold`) can be applied too late or can be unintentionally bypassed. This allows a returning high-priority node to preempt before session state is synchronized, causing transient connection drops during failover/rejoin.
./docs/issues/issue-history.md:2424:- During restart/rejoin with active peer, returning node does not preempt until bulk sync completion (or hold timeout fallback).
./docs/issues/issue-history.md:2441:- `netlink.LinkByName(ifName)` directly in `addByName` ([`pkg/daemon/daemon.go:1891-1899`](pkg/daemon/daemon.go#L1891-L1899))
./docs/issues/issue-history.md:2443:`nh.Interface` is parsed from config in Junos naming, and may also be a RETH logical name. `LinkByName` then fails silently, so the target is never probed.
./docs/issues/issue-history.md:2446:1. Configure static route with interface-qualified next-hop, e.g. IPv6 link-local:
./docs/issues/issue-history.md:2447:   - `set routing-options static route ::/0 next-hop fe80::1 interface reth0.50`
./docs/issues/issue-history.md:2448:2. Trigger HA failover/restart.
./docs/issues/issue-history.md:2452:`resolveNeighbors()` should normalize/resolve interface names before `LinkByName`:
./docs/issues/issue-history.md:2718:- Select active sync transport and fail over without cluster restart.
./docs/issues/issue-history.md:2895:4. Test coverage for failover continuity with control-link sync (including link flap/restart cases).
./docs/issues/issue-history.md:3388:- I did not find any `SetSyncReady(false)` path on sync disconnect, cluster comms restart, or peer reconnect.
./docs/issues/issue-history.md:3391:- Reset `syncReady=false` whenever the sync transport fully disconnects or cluster comms are restarted.
./docs/issues/issue-history.md:4272:The readiness gate still treats `LinkByName` failure in `RGInterfaceReady()` as "belongs to the peer" and skips it.
./docs/issues/issue-history.md:4341:- This becomes more visible because the current RETH design uses per-node MAC/link-local identity.
./docs/issues/issue-history.md:4360:## #192 — HA IPv6 failover: per-node RETH MAC/link-local identity makes failover weaker than IPv4 [CLOSED] (closed 2026-03-09)
./docs/issues/issue-history.md:4363:IPv6 HA failover still changes router identity because RETH uses per-node MACs, which means per-node link-local addresses. The code relies on goodbye RA and new RA startup to move the default-router role, but that is fundamentally weaker than IPv4 and does not help on hard crash failover.
./docs/issues/issue-history.md:4367:- `pkg/ra/sender.go` sends RA from the interface link-local
./docs/issues/issue-history.md:4378:With per-node MAC/link-local identities, hosts can retain the dead router's old link-local default route while the new primary advertises a different one.
./docs/issues/issue-history.md:5256:If the helper process restarts and its local event-stream sequence restarts from 1, the daemon still carries forward the old:
./docs/issues/issue-history.md:5267:After a helper restart, the daemon can therefore:
./docs/issues/issue-history.md:5278:Reset daemon-side event-stream watermarks on a fresh helper connection, or explicitly negotiate connection epochs so sequence/drain/ack state cannot bleed across helper restarts.
./docs/issues/issue-history.md:5281:A helper restart during or before HA failover can leave the demotion drain path and replay/ack bookkeeping working against stale sequence numbers, which is exactly the wrong place to be unsound.
./docs/issues/issue-history.md:5766:- Current `master` repeatedly logs the global fallback on restart.
./docs/issues/issue-history.md:7371:3. **Startup/reconnect** — Node joins cluster (boot, restart, partition recovery). Needs full session table from peer. This is the ONLY case where bulk sync should run.
./docs/issues/issue-history.md:7587:`monitor interface traffic` needs a second step beyond the new all-interface realtime table: it should behave more like `bwm-ng` when running interactively so operators can quickly pivot views without restarting the command.
./docs/issues/issue-history.md:7645:# Deploy and restart
./docs/issues/issue-history.md:8118:## #467 — Failed userspace demotion prep stops the peer bootstrap retry loop and never restarts it [CLOSED] (closed 2026-04-05)
./docs/issues/issue-history.md:8121:`prepareUserspaceRGDemotionWithTimeout()` stops the session-sync bulk-prime retry loop before it waits on demotion barriers, but if the barrier wait fails it returns without restarting that retry loop.
./docs/issues/issue-history.md:8206:`systemctl restart bpfrxd` on fw1 re-registers the XSK bindings.
./docs/issues/issue-history.md:9031:## #540 — session sync can stay disconnected after standby restart on loss [CLOSED] (closed 2026-04-07)
./docs/issues/issue-history.md:9034:On the loss userspace cluster, restarting the secondary can leave `show chassis cluster status` stuck at `Transfer ready: no (session sync disconnected)` on the standby even though the primary is otherwise healthy.
./docs/issues/issue-history.md:9037:Session sync currently treats an established outbound TCP socket as connected until the kernel tears it down. When the passive node restarts, the active node can keep the stale socket long enough that it never redials promptly. Because only one side initiates the session-sync TCP connection, the standby stays disconnected.
./docs/issues/issue-history.md:9047:After a standby restart, the primary should actively prove reverse-path liveness and reconnect session sync without leaving the standby stuck disconnected.
./docs/issues/issue-history.md:9468:## #580 — standby userspace helper can wedge with XSK bindings stuck busy after restart [CLOSED] (closed 2026-04-07)
./docs/issues/issue-history.md:9471:After the restart/deploy cycle on `loss`, standby `fw0` can get stuck with userspace forwarding armed but no XSK bindings ever becoming ready, which blocks explicit failover back to that node.
./docs/issues/issue-history.md:9489:- HA failover/failback testing cannot proceed reliably after restart/deploy because the standby dataplane never finishes rebinding.
./docs/issues/issue-history.md:9492:A standby helper restart should fully rebind XSKs and become takeover-ready once the helper is armed.
./docs/issues/issue-history.md:9835:On the `loss` userspace HA cluster, restarting the standby on April 8, 2026 caused the primary to reconnect session sync successfully, immediately push config to the returning peer, and then lose the new sync connection again a few seconds later.
./docs/issues/issue-history.md:9843:- that no-op apply still triggers disruptive management VRF / heartbeat restart work
./docs/issues/issue-history.md:9856:- `cluster: restarting heartbeat after VRF rebind`
./docs/issues/issue-history.md:9891:- Fabric forwarding flaps were reproduced when `LinkByName` / neighbor resolution briefly missed but a cached `fabric_fwd` entry already existed.
./docs/issues/issue-history.md:10112:That blocks the exact safety gate we want for rolling upgrades: prove the upgraded standby can participate in HA transfer/failover before restarting the old primary.
./docs/issues/issue-history.md:10865:- repeatable collision hot spots across restarts and nodes
./docs/issues/issue-history.md:12297:- The slot allocator has to survive daemon restart and HA failover — slot IDs either persist or the compile-time step re-assigns deterministically.
./docs/issues/issue-history.md:14114:- [ ] Feature-flag / kill-switch so the gate can be disabled at runtime without a daemon restart — so future regressions can be mitigated in production without waiting for a redeploy.
./docs/issues/issue-history.md:14161:Meanwhile, node1 holds a zombie ESTAB socket from a pre-restart node0 PID:
./docs/issues/issue-history.md:14218:## #847 — Cross-restart VRF leak: renamed routing instances leave stale vrf-<old-name> [CLOSED] (closed 2026-04-25)
./docs/issues/issue-history.md:14222:When a routing instance is renamed (or deleted from config) while xpfd is stopped, the old \`vrf-<oldname>\` device persists in the kernel across the restart. The new xpfd process has an empty \`m.vrfs\` slice on startup. Its first \`ReconcileVRFs\` call sees the stale VRF, finds it's not in the desired set, and leaves it alone (not in desired = never touch). The VRF leaks until someone runs \`xpfd cleanup\`.
./docs/issues/issue-history.md:14226:Same behavior on \`master\`: \`ClearVRFs\` is a no-op when \`m.vrfs\` is empty (first apply after restart), so the rename produces the same leak today. PR #845 (#844) preserves the behavior — doesn't regress, doesn't fix.
./docs/issues/issue-history.md:14242:Not in scope for PR #845. Adoption of \*current-config\* pre-existing VRFs is already in #845 (fixes the post-restart vrf-mgmt case). This issue is about \*old-config\* VRFs from before a rename.
./docs/issues/issue-history.md:15166:All collected with \`xpfd cleanup\` + restart + the existing production config:
./docs/issues/issue-history.md:15943:- Has no automatic respawn — daemon must be manually restarted to recover.
./docs/issues/issue-history.md:17159:- Hitless-restart machinery (PROG_ARRAY pinning, deferred cleanup)
./docs/issues/issue-history.md:17165:- `daemon/restart.go` — hitless-restart bookkeeping
./docs/issues/issue-history.md:17682:Forwarding stays broken until xpfd is restarted, which rebuilds the
./docs/issues/issue-history.md:19025:- Clear empty/rebuilding state during HA restart rather than stale mappings.
./docs/issues/issue-history.md:21683:| #1448 | Preserve persistent SNAT leases across helper restart, or explicitly document reset behavior. |
./docs/issues/issue-history.md:22073:- `pkg/dhcpserver/dhcpserver.go` renders `/etc/kea/kea-dhcp{4,6}.conf` and restarts `kea-dhcp{4,6}-server`.
./docs/issues/issue-history.md:22091:5. Work across daemon restart and HA failover.
./docs/issues/issue-history.md:22631:## #1448 — SNAT pools: preserve persistent leases across helper restart [CLOSED] (closed 2026-05-21)
./docs/issues/issue-history.md:22633:## Context\n\n#1377's original eBPF-retirement blocker is closed by #1427 and #1446: userspace no longer silently degrades address-persistent pool mode, persistent leases are tracked in-process, allocator cleanup is bounded, and exhaustion/counter visibility exists.\n\nThis follow-up tracks a separate production-hardening concern that was deliberately kept outside the #1377 closeout contract: preserving helper-local persistent-NAT leases across userspace helper restart.\n\n## Problem\n\nThe current userspace persistent SNAT lease table is in-process runtime state. A helper restart can lose helper-local lease memory even if the config remains byte-identical. That is fail-safe for correctness but operator-visible for deployments expecting long-lived persistent-NAT affinity across helper lifecycle events.\n\n## Desired Contract\n\n- Define whether persistent leases are expected to survive helper restart.\n- If yes, persist or replay enough lease state to rebuild the lease table without reusing translated tuples unsafely.\n- If no, document the restart boundary explicitly in the #1377/#1373 retirement docs and expose counters/logs that make reset behavior auditable.\n\n## Validation\n\n- Regression test: establish persistent lease, restart helper, establish a new flow from the same persistent source, and assert the documented behavior.\n- If state is persisted/replayed, prove translated tuple ownership and live-flow rollback remain correct.\n\nFollow-up split from #1377 after #1427 and #1446.
./docs/issues/issue-history.md:23267:- HA failover, crash, restart, and route-advertisement gates from the
./docs/issues/issue-history.md:23288:- `docs/userspace-dataplane-gaps.md:167-180` says the highest-value remaining work is to finish the #1377 disposition around helper restart, HA synchronization, and cross-backend selector parity.
./docs/issues/issue-history.md:23309:- Any remaining SNAT restart/HA/cross-backend text is framed as the closed/documented contract or as non-blocking historical context.
./docs/issues/issue-history.md:25044:Found during #1530 Phase B validation Run 1 on the loss userspace cluster at master `936b076d` (the #1528 DPDK Phase-3 mechanical removal merge). All workers on fw0 segfaulted at the same offset across three consecutive helper restarts; fw1 with the same binary hash never reproduced. Bisect agent `a4b4b8581f6b96e00` returned NO-LOCALIZATION after sweeping the retirement-chain merge window — the crash is environmental + timing-dependent rather than tied to any specific commit.
./docs/issues/issue-history.md:25102:- Helper restart on fresh boot brings up workers in a state that takes one matrix iteration to stabilize
./docs/issues/pr-history.md:344:This fixes a VRRP sync-hold race during node restart/rejoin where a returning node could preempt before session sync was complete.
./docs/issues/pr-history.md:985:- a separate native process is cleaner for CPU pinning, restart isolation, and avoiding cgo-heavy hot loops under the Go scheduler
./docs/issues/pr-history.md:3521:- [x] Transit connectivity after restart: working
./docs/issues/pr-history.md:3695:- **Always re-install**: Removed the `slices.Equal` dedup check in `syncInterfaceNATAddressMapsLocked` so nftables rules are re-installed on every compile, guaranteeing both HA nodes always have rules even after daemon restart.
./docs/issues/pr-history.md:3860:## PR #470 — fix: restart bulk-prime retry loop after failed demotion barrier [MERGED] (merged 2026-04-05)
./docs/issues/pr-history.md:3862:Branch: `fix/467-retry-loop-restart`
./docs/issues/pr-history.md:3865:- `prepareUserspaceRGDemotionWithTimeout()` stops the bulk-prime retry loop before waiting on barriers, but on failure returns without restarting it — stranding the peer in an unprimed state
./docs/issues/pr-history.md:3866:- Adds a defer that restarts `startSessionSyncPrimeRetry()` on failure when the peer is still connected and not yet bulk-primed
./docs/issues/pr-history.md:3867:- The restarted loop uses the same generation counter, so it cancels normally on subsequent demotion attempts or disconnects
./docs/issues/pr-history.md:3972:- restart the server stream when `c`, `p`, `b`, `d`, or `r` changes the requested summary mode, and exit on the existing quit keys
./docs/issues/pr-history.md:4490:- skip bare link-local IPv6 addresses that cannot be listened on without a zone
./docs/issues/pr-history.md:4492:- add regression coverage for IPv4, IPv6, host:port peers, and link-local-only interfaces
./docs/issues/pr-history.md:4557:- remove stale direct VIPs and stable link-local ownership when the node no longer owns the RG
./docs/issues/pr-history.md:4685:## PR #541 — fix: re-establish session sync after standby restart [MERGED] (merged 2026-04-07)
./docs/issues/pr-history.md:4701:- restarted `bpfrxd` on `bpfrx-userspace-fw1` and confirmed the primary re-dialed session sync and the standby recovered `Transfer ready: yes` instead of staying disconnected
./docs/issues/pr-history.md:4849:  - **daemon_ha_vip.go** (24 funcs, 555 lines): VIP ownership, GARP/NA scheduling, stable link-local, readiness checks
./docs/issues/pr-history.md:5289:- live on `loss`: deploy branch, restart `bpfrxd` on `bpfrx-userspace-fw1`, confirm both nodes return to `Transfer ready: yes`
./docs/issues/pr-history.md:5290:- live on `loss`: standby journal shows `cluster: skipping config sync apply (config already matches active)` and does not log `restarting heartbeat after VRF rebind` for that reconnect
./docs/issues/pr-history.md:5722:## PR #636 — daemon: bind RETH RA to stable link-local [MERGED] (merged 2026-04-13)
./docs/issues/pr-history.md:5724:Branch: `pr/ha-ra-stable-link-local-source`
./docs/issues/pr-history.md:5727:- bind RA senders on HA RETH interfaces to the stable router link-local when no explicit RA source link-local is configured
./docs/issues/pr-history.md:5728:- keep explicit configured link-local addresses taking precedence
./docs/issues/pr-history.md:5729:- stop skipping RA source-link-local selection for static RA configs when DHCP-PD is not in use
./docs/issues/pr-history.md:5730:- add daemon tests for both the stable-link-local and explicit-link-local cases
./docs/issues/pr-history.md:5736:ra: failed to send RA ... fe80::bf:72ff:fe16:200%ge-0-0-1->ff02::1%ge-0-0-1: sendmsg: invalid argument
./docs/issues/pr-history.md:5739:The root cause was that the RA sender auto-selected a transient EUI-64 link-local, while HA reconcile had already removed that address and installed the stable router link-local on the active RETH member. The sender then kept trying to transmit from an address the interface no longer owned.
./docs/issues/pr-history.md:5745:- post-deploy `show ipv6 router-advertisement` on `fw0` now reports source `fe80::bf72:16:2%ge-0-0-1`
./docs/issues/pr-history.md:5747:- `cluster-userspace-host` recovered IPv6 default route via `fe80::bf72:16:2` and successful IPv6 ping to `2607:f8b0:4005:814::200e`
./docs/issues/pr-history.md:5757:- disable IPv6 RA/autoconf on the host-side SR-IOV LAN parent before create/deploy
./docs/issues/pr-history.md:5764:- applied the runtime equivalent on `loss`: disabled `accept_ra`/`autoconf` on `mlx1` and flushed dynamic global IPv6 state
./docs/issues/pr-history.md:5765:- after the fix on `loss`, the same route resolves via `fe80::100 dev ix0` and `ping -6 -c 5 2001:559:8585:ef00:1266:6aff:fe0b:d017` succeeds
./docs/issues/pr-history.md:6615:- restarted secondary first, then primary
./docs/issues/pr-history.md:6861:- preserves determinism inside one runtime instance (required for correct enqueue/dequeue bucket accounting) while making the bucket mapping unpredictable across restarts and nodes
./docs/issues/pr-history.md:6866:PR #692's SFQ gives 5201 flow fairness inside one queue but the bucket mapping is still a pure function of the 5-tuple. That is externally probeable: a hostile or just unlucky source that can vary ports can steer flows into a small number of buckets and degrade fairness on purpose, and collision hot spots repeat across restarts and across HA nodes.
./docs/issues/pr-history.md:6966:Helper SHA `b4c8bfa9e56e399b63c3261b2455eabd73cb8a9c1b44eb2b616781f6b8c8043a` rolled out to `xpf-userspace-fw0` and `xpf-userspace-fw1`; xpfd restarted on both nodes.
./docs/issues/pr-history.md:9403:- Applied at daemon startup **and on every `applyConfig`** (reconcile path), so changes to `system dataplane workers` and the new kill switch take effect without a restart.
./docs/issues/pr-history.md:9476:**Crash persistence** (round-2 BLOCKER): `priorHostTunables` is in-memory only. Documented on the struct itself: the host-scope values are idempotent across daemon restarts, so a crash-recovery identity restore is harmless. A persisted snapshot was rejected as cost-without-benefit.
./docs/issues/pr-history.md:10284:- 9 behaviour-matrix rows (create, preserve, delete, add+remove+preserve, table-mismatch recreate, post-restart adoption with matching / mismatching table).
./docs/issues/pr-history.md:10287:- 2 transient-lookup scenarios: transient LinkByName on tracked-not-desired VRF (delete loop) and on tracked-and-desired VRF (the critical #844-class bug). Both must retain ownership.
./docs/issues/pr-history.md:11047:Extends \`reconcileVRFs\` with a final pass that enumerates kernel \`vrf-*\` devices and deletes any that are neither in \`desired\` nor already in \`tracked\`. Closes the cross-restart leak when a routing-instance rename or deletion happens while xpfd is stopped.
./docs/issues/pr-history.md:11051:Per the #844 plan's explicit "out of scope" follow-up: after a daemon restart, \`m.vrfs\` is empty. The existing "tracked-but-not-desired" deletion loop can't catch a stale \`vrf-<oldname>\` because it isn't in tracked. ReconcileVRFs's adoption rule for "not in desired" is "leave alone." VRF leaked until manual \`xpfd cleanup\`.
./docs/issues/pr-history.md:11074:- [ ] Manual: rename a routing instance, restart, verify the old VRF gets reaped.
./docs/issues/pr-history.md:11423:- #925 — panic supervision (parent-side helper restart in `xpfd`, plus `catch_unwind` on helper side).
./docs/issues/pr-history.md:12036:Wraps the `worker_loop` spawn closure with `std::panic::catch_unwind` so a panicking worker is detected and reported instead of dying silently. Phase 1 is **detection only** — operators see DEAD in `cli show chassis forwarding` and must restart the daemon to recover the dead worker's bindings. Respawn / sticky-failure / HA-trigger are explicitly Phase 2+.
./docs/issues/pr-history.md:12049:`worker_loop` takes owned values + `Arc`s only — no `&mut` parameters that could leave invariants broken across an unwind (Codex confirmed worker-local `&mut` borrows don't escape the catch boundary). Shared `Arc<Mutex<…>>` state may become poisoned, but the codebase is already poison-tolerant: #949's `into_inner` policy covers `dynamic_neighbors`; session maps and worker command queues use `if let Ok` skip-on-poison and silently drop on poison. This PR does NOT fix that — it just reports the panic that caused it. Operators see DEAD and restart the daemon.
./docs/issues/pr-history.md:12067:- [ ] Optional manual injection: hot-patch a panic into `worker_loop`, restart, observe `cli show chassis forwarding` showing DEAD. Not gated.
./docs/issues/pr-history.md:18970:forwarding until xpfd restart.
./docs/issues/pr-history.md:20208:Retroactive triple-review of PR #1251 returned **NEEDS-FOLLOWUP-MAJOR** from Gemini Pro 3 (\`task-moz8g3zg-jkqdrv\`). Codex review (\`task-moz8o6y7-st6xoz\`) was lost when the Codex runtime restarted; Gemini's findings stand on their own. Three concrete fixes here.
./docs/issues/pr-history.md:22140:- Document that daemon scheduler tick/restart/failover republish and missing-scheduler commit errors remain gates.
./docs/issues/pr-history.md:22275:- `bash -n test/incus/cluster-env.sh test/incus/cluster-setup.sh test/incus/test-connectivity.sh test/incus/test-failover.sh test/incus/test-double-failover.sh test/incus/test-active-active.sh test/incus/test-stress-failover.sh test/incus/test-ha-crash.sh test/incus/test-chained-crash.sh test/incus/test-restart-connectivity.sh test/incus/test-private-rg.sh`
./docs/issues/pr-history.md:22277:- `make -n cluster-status userspace-cluster-status loss-cluster-status test-failover test-ha-crash test-restart-connectivity`
./docs/issues/pr-history.md:22719:  from HA/process-restart token sync and non-drop/color-aware parity
./docs/issues/pr-history.md:22922:- helper restart persistence and HA lease synchronization are not supported; HA configs using persistent source-NAT pools are gated
./docs/issues/pr-history.md:23143:  non-goals around helper-restart persistence, HA lease sync, and
./docs/issues/pr-history.md:23414:## PR #1469 — Document SNAT restart reset boundary [MERGED] (merged 2026-05-21)
./docs/issues/pr-history.md:23416:Branch: `codex/1448-snat-restart-boundary`
./docs/issues/pr-history.md:23420:#1448 asks whether userspace persistent SNAT leases survive helper restart.
./docs/issues/pr-history.md:23421:This PR closes the issue by making restart a documented reset boundary instead
./docs/issues/pr-history.md:23428:  while helper cold start, restart, replan, and pool-shape edits reset live
./docs/issues/pr-history.md:23434:  in-process refresh preserves persistent lease state, while restart with the
./docs/issues/pr-history.md:23737:- Keep helper restart, HA persistent-lease gating, and cross-backend selector divergence documented as current userspace contract limits.
./docs/issues/pr-history.md:23746:- SNAT limitation grep confirming helper restart, HA, and cross-backend selector limits remain documented.
./docs/issues/pr-history.md:23750:Adversarial pass checked for the previous contradiction: the docs no longer describe SNAT helper-restart persistence, HA lease sync, or cross-backend selector parity as work that must close #1377, while still keeping those limitations visible so operators do not infer stronger persistent-NAT guarantees than the runtime provides.
./docs/research/1888-wg-timers/plan.md:456:(`pending` entries live until response/re-add/restart,
./docs/research/1888-wg-timers/plan.md:464:(#1872) resetting the thread-local window merely restarts an attempt cycle —
./docs/research/1888-wg-timers/plan.md:785:   respawn restarting the attempt cycle is benign (and is today's behavior).
./pkg/config/schema_routing.go:120:		"graceful-restart": {desc: "Graceful restart", children: nil},
./pkg/config/schema_routing.go:359:			"graceful-restart": {desc: "Graceful restart", children: nil},
./pkg/dataplane/userspace/manager_test.go:1980:			Inet6StaticRoutes: []*config.StaticRoute{{Destination: "::/0", NextHops: []config.NextHopEntry{{Address: "fe80::1", Interface: "ge-0/0/0.0"}}}},
./pkg/dataplane/userspace/manager_test.go:2272:				{Family: "inet6", Address: "fe80::1/64", Scope: int(netlink.SCOPE_LINK)},
./pkg/dataplane/userspace/manager_test.go:2427:					{Family: "inet6", Address: "fe80::1/128"},
./pkg/dataplane/userspace/manager_test.go:2444:			{Family: "inet", Address: "fe80::20/64"},
./pkg/dataplane/userspace/manager_test.go:2446:			{Family: "inet6", Address: "fe80::10/64"},
./pkg/dataplane/userspace/manager_test.go:3436:		{Family: "inet6", Address: "fe80::1/128", Scope: 253},
./pkg/dataplane/userspace/manager_test.go:3452:		"inet6/fe80::1/128":            true,
./userspace-dp/src/afxdp/sharded_neighbor_tests.rs:178:                0xfe80,
./userspace-dp/src/afxdp/coordinator/README.md:51:- WG threads restart when the engine Arc identity OR attachment
./userspace-dp/src/afxdp/coordinator/README.md:52:  changes; GRE threads restart ONLY on attachment drift — endpoint
./pkg/config/types_system.go:283:	PermControl                             // restart/request commands
./userspace-dp/src/afxdp/coordinator/mod.rs:179:    /// spawn with backoff); content changes never restart a thread —
./userspace-dp/src/afxdp/coordinator/mod.rs:682:                             proactive neighbor warming is DISABLED until restart"
./pkg/dataplane/userspace/interfaces.go:375:	if link, err := netlink.LinkByName(linuxName); err == nil && link != nil {
./pkg/dataplane/userspace/interfaces.go:453:	addrs, err := netlink.AddrList(link, netlink.FAMILY_ALL)
./userspace-dp/src/afxdp/coordinator/tests.rs:2363:    // The coherent apply with B then restarts cleanly (engine changed
./userspace-dp/src/afxdp/coordinator/tests.rs:2397:/// restart the thread on the new TUN attachment (the reused engine Arc
./userspace-dp/src/afxdp/coordinator/tests.rs:2400:fn wg1866_apply_time_rename_restarts_thread_on_new_attachment() {
./userspace-dp/src/afxdp/coordinator/tests.rs:2407:    // attachment-aware stale prune must restart the thread.
./userspace-dp/src/afxdp/coordinator/tests.rs:2580:/// same id + same attachment) must NOT restart the thread — the live
./userspace-dp/src/afxdp/coordinator/tests.rs:2604:/// restart condition — the TUN fd is bound to the old netdev.
./userspace-dp/src/afxdp/coordinator/tests.rs:2606:fn gre1881_attachment_change_restarts_thread() {
./pkg/dataplane/userspace/statusfmt.go:571:			// must restart the daemon to recover the worker's bindings.
./pkg/config/schema_validate_interfaces_test.go:82:		accept:   []string{"2001:db8::1/64", "::1/128", "fe80::1/64"},
./userspace-dp/src/afxdp/umem/mod.rs:202:/// a surviving offset across a restart, or a `monotonic_nanos() == 0`
./userspace-dp/src/afxdp/umem/mod.rs:454:    /// race during config reload or helper restart. Subset of
./userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs:485:    ///      rename with an unchanged crypto identity must restart the
./pkg/config/compiler_services.go:465://     RA-discovered link-locals and the snapshot RouteSnapshot has no
./pkg/config/compiler_services.go:499:		return "", fmt.Errorf("services ip-monitoring policy %q route %s: interface-typed next-hop %q is inet-only (DHCPv6 gateways are RA-derived link-locals; inet6 support is a follow-up)",
./docs/pr/805-rss-refresh/plan.md:340:  commit (or restart the daemon). This change does NOT add a
./pkg/dataplane/userspace/maps_sync.go:59:// daemon restart, so it never spuriously fires for a live worker.
./pkg/dataplane/userspace/maps_sync.go:372:		// The VRRP election + VIP add takes ~10-14s after restart.
./pkg/dataplane/userspace/maps_sync.go:873:	// across daemon restarts (idempotent). Any other failure must be
./pkg/dataplane/userspace/maps_sync.go:968:	// Use AddrList(nil, ...) to enumerate ALL addresses on the system.
./pkg/dataplane/userspace/maps_sync.go:970:		addrs, err := netlink.AddrList(nil, family)
./userspace-dp/src/afxdp/frame/tests.rs:5583:/// emitting until restart.
./userspace-dp/src/afxdp/wg/tests.rs:1738:    /// leak until process restart.
./userspace-dp/src/afxdp/umem/tests.rs:566:    // a cross-restart leftover, or a `monotonic_nanos() == 0`
./pkg/config/parser_rpm_pin_test.go:105:				"set services rpm probe P test t next-hop fe80::1",
./docs/pr/1706-routing-latent-defects/plan.md:60:    if existing, lookupErr := t.ops.LinkByName(tc.Name); lookupErr == nil {   // :122
./docs/pr/1706-routing-latent-defects/plan.md:85:`LinkByName(base.Name)` (link_linux.go:77-83). The fresh `anchor` DOES
./docs/pr/1706-routing-latent-defects/plan.md:116:### Defect 2 — xfrm double LinkByName + LinkSetUp(nil) panic risk
./docs/pr/1706-routing-latent-defects/plan.md:119:if _, err := x.ops.LinkByName(ifName); err == nil {  // :44 first lookup, link discarded
./docs/pr/1706-routing-latent-defects/plan.md:120:    link, _ := x.ops.LinkByName(ifName)               // :45 second lookup, error ignored
./docs/pr/1706-routing-latent-defects/plan.md:125:If the second `LinkByName` transiently fails (EINVAL/EBUSY/etc.), `link`
./docs/pr/1706-routing-latent-defects/plan.md:134:if link, err := x.ops.LinkByName(ifName); err == nil {
./docs/pr/1706-routing-latent-defects/plan.md:247:  assert LinkByName called exactly ONCE on the already-exists path and
./docs/pr/812-tx-latency-histogram/plan.md:203:crash restart within the same UMEM) must NOT inflate the histogram.
./docs/pr/812-tx-latency-histogram/plan.md:954:   (e.g., pre-#812 frame offset that survived a restart)
./docs/pr/812-tx-latency-histogram/plan.md:1141:If a revert itself fails (hitless-restart property violated), fall
./docs/pr/812-tx-latency-histogram/plan.md:1143:survives a rolling restart (`MEMORY.md` — "Hitless Restart Patterns").
./userspace-dp/src/afxdp/wg/handshake_session.rs:152:        // drain this entry — it would leak until response / re-add / restart.
./pkg/dataplane/compiler_iface.go:99:	parent, err := netlink.LinkByName(parentName)
./pkg/dataplane/compiler_iface.go:107:	existing, err := netlink.LinkByName(subName)
./pkg/dataplane/compiler_iface.go:129:	link, err := netlink.LinkByName(subName)
./pkg/dataplane/compiler_iface.go:176:// Link-local (fe80::/10) addresses are left untouched since the kernel manages them.
./pkg/dataplane/compiler_iface.go:178:	link, err := netlink.LinkByName(ifaceName)
./pkg/dataplane/compiler_iface.go:198:	existing, err := netlink.AddrList(link, netlink.FAMILY_ALL)
./pkg/dataplane/compiler_iface.go:206:	// Remove stale addresses (skip link-local)
./pkg/dataplane/compiler_iface.go:218:			if err := netlink.AddrDel(link, addr); err != nil {
./pkg/dataplane/compiler_iface.go:370:						if nl, err := result.cachedLinkByName(subName); err == nil {
./pkg/dataplane/compiler_iface.go:572:					if nl, err := result.cachedLinkByName(physName); err == nil {
./pkg/dataplane/compiler_iface.go:692:	// networkd .network file gets a link-local base address (169.254.RG.NODE/32)
./pkg/dataplane/compiler_iface.go:891:							// Replace VIP addresses with a link-local base for VRRP.
./pkg/dataplane/compiler_iface.go:945:				// link-local base; native VRRP manages the actual VIPs.
./pkg/dataplane/compiler_iface.go:1172:		// Bring down and remove all non-link-local addresses immediately.
./pkg/dataplane/compiler_iface.go:1175:		addrs, _ := netlink.AddrList(nl, netlink.FAMILY_ALL)
./pkg/dataplane/compiler_iface.go:1180:			if err := netlink.AddrDel(nl, &addrs[i]); err == nil {
./userspace-dp/src/afxdp/worker/mod.rs:191:    /// restart and intentionally not synchronized across workers.
./userspace-dp/src/afxdp/worker/mod.rs:407:                // any stray pre-existing offset in flight (cross-restart
./pkg/config/compiler_routing.go:200:				// Check children for interface (needed for IPv6 link-local next-hops)
./pkg/config/compiler_routing.go:206:				// Also check inline keys: "next-hop fe80::50 interface reth0.50"
./pkg/config/parser_cluster_test.go:345:	sets := []string{"set chassis cluster cluster-id 1", "set chassis cluster node 0", "set chassis cluster hitless-restart"}
./pkg/config/parser_cluster_test.go:371:        hitless-restart;
./pkg/config/parser_cluster_test.go:1143:	cmds := []string{"set interfaces gr-0/0/0 unit 0 point-to-point", "set interfaces gr-0/0/0 unit 0 tunnel source 209.237.133.186", "set interfaces gr-0/0/0 unit 0 tunnel destination 107.161.208.15", "set interfaces gr-0/0/0 unit 0 tunnel routing-instance destination Atherton-Fiber", "set interfaces gr-0/0/0 unit 0 family inet mtu 1456", "set interfaces gr-0/0/0 unit 0 family inet address 10.255.192.22/30", "set interfaces gr-0/0/0 unit 1 point-to-point", "set interfaces gr-0/0/0 unit 1 tunnel source 2602:fd41:20:5::351", "set interfaces gr-0/0/0 unit 1 tunnel destination 2602:ffd3:0:2::7", "set interfaces gr-0/0/0 unit 1 tunnel routing-instance destination Atherton-Fiber", "set interfaces gr-0/0/0 unit 1 family inet mtu 1456", "set interfaces gr-0/0/0 unit 1 family inet address 10.255.192.34/30", "set interfaces gr-0/0/0 unit 1 family inet6 mtu 1436", "set interfaces gr-0/0/0 unit 1 family inet6 address fe80::8/64", "set interfaces gr-0/0/0 unit 1 family inet6 address fc00::e/126"}
./pkg/config/types_routing.go:95:	Address   string // IP address (e.g. "10.0.1.1" or "fe80::1")
./pkg/config/types_routing.go:96:	Interface string // outgoing interface (for IPv6 link-local)
./pkg/config/types_routing.go:201:	SourceLinkLocal string   // explicit link-local to use as RA source (overrides auto-selected)
./pkg/config/types_routing.go:257:	GracefulRestart      bool   // enable graceful restart
./userspace-dp/src/afxdp/cos/queue_ops/push.rs:293:///      until the daemon is restarted via config change
./userspace-dp/src/afxdp/cos/queue_ops/push.rs:299:///      parent-side restart in xpfd) tracked in #925.
./pkg/config/schema_chassis.go:25:		// link-local (reth.go:124) — 256+ would silently alias MACs.
./pkg/config/schema_chassis.go:135:		"hitless-restart": {desc: "Keep dataplane forwarding active during daemon shutdown (HA default is fail-closed)", children: nil},
./userspace-dp/src/afxdp/wg/engine.rs:284:    /// In-process strict monotonicity; cross-restart persistence is a
./userspace-dp/src/afxdp/wg/engine.rs:591:        // consumed index) would leak until process restart, and a stale
./userspace-dp/src/afxdp/wg/engine.rs:1314:            IpAddr::V6(v6) => assert_eq!(v6.segments()[0], 0xfe80),
./userspace-dp/src/afxdp/wg/tai64n.rs:48://! Cross-restart persistence (so the clock never regresses after an xpf
./userspace-dp/src/afxdp/wg/tai64n.rs:49://! restart with a skewed wall clock) is the control plane's job and is
./userspace-dp/src/afxdp/wg/tai64n.rs:196:    /// control plane (#1703 S6) can prevent cross-restart regression. The
./userspace-dp/src/afxdp/worker/loop_body/mod.rs:205:                // watch. The in-process counters reset on every restart
./pkg/dataplane/maps_stale.go:9:// Hitless-restart stale-cleanup map accessors.
./userspace-dp/src/afxdp/coordinator/snapshot_refresh.rs:201:        // stops, or restarts the matching UDP/TUN control thread.
./pkg/monitoriface/monitor.go:174:	link, err := netlink.LinkByName(name)
./pkg/monitoriface/monitor.go:497:	link, err := netlink.LinkByName(kernelName)
./userspace-dp/src/afxdp/cos/queue_service/mod.rs:835:    // across epochs rather than restarting at the largest (the
./pkg/configstore/store.go:81:	// (never-committed), NOT committed=1 — otherwise a restart would
./pkg/configstore/store.go:306:// (#1799). While true, a daemon restart would load a STALE config;
./pkg/configstore/store.go:322:	slog.Error("active config persist failed — running config is not durable; restart would load stale config",
./pkg/configstore/store.go:1070:// to the previous config on daemon restart.
./pkg/configstore/store.go:1360:	// otherwise a subsequent restart would classify committed-empty =>
./pkg/configstore/store.go:1363:	// never-committed without a restart.
./pkg/rpm/README.md:28:  without a probe restart).
./pkg/frr/vtysh.go:30:// mid-restart) would hang those gRPC/CLI handlers indefinitely, the
./pkg/frr/vtysh.go:39:// restarts watchfrr, which is the Type=forking unit's MainPID, so every
./pkg/rpm/pin_hold_test.go:147:	// transitions to pass without any probe restart.
./userspace-dp/src/afxdp/cos/queue_service/tests.rs:3079:    // next call would restart the descending walk from the largest class and
./pkg/configstore/persist_failure_test.go:7:// no history/journal/rollback-file side effects. A restart after a
./pkg/configstore/persist_failure_test.go:110:// after a failed operator commit, a daemon restart serves the PREVIOUS
./pkg/configstore/persist_failure_test.go:138:		t.Error("restart lost the previously committed config")
./pkg/configstore/persist_failure_test.go:141:		t.Error("restart loaded the failed (never-committed) config")
./pkg/frr/manager.go:237:	Gateway   string // "10.0.2.1" or "fe80::1"
./pkg/frr/manager.go:238:	Interface string // needed for IPv6 link-local gateways
./pkg/frr/manager.go:456:	// never retry until the next commit or restart. ensureRetryLocked
./pkg/frr/manager.go:573:// `systemctl reload frr`. On FRR 10.6 the unit's ExecReload restarts
./pkg/frr/README.md:79:  for link-local resolution — link-local addresses alone are ambiguous to
./pkg/frr/README.md:94:  (frrinit.sh reload) unconditionally restarts watchfrr, the
./pkg/rpm/rpm.go:180:// tick — no probe restart required. On a config change the daemon
./pkg/configstore/README.md:52:previous on-disk config at the next restart. The contract is now
./pkg/configstore/README.md:62:  rename atomic, the old active survives on disk — a restart after a
./pkg/configstore/README.md:67:  the in-memory promotion completes means a restart loads the NEW tree
./pkg/configstore/README.md:71:  that REPORTED success and silently reverted on restart. A
./pkg/configstore/README.md:133:config to the dataplane. A subsequent restart therefore re-classifies into
./pkg/frr/policy_render.go:260:			b.WriteString(" bgp graceful-restart\n")
./docs/pr/1476-mechanical-bpf-removal/plan.md:409:| `docs/testing.md:281` | **(v3 — Codex r3 F5 NEW)** Step describing restart-time map preservation refers to `loadAllObjects()`. Update to reference `loadUserspaceShimObjects()` or remove the legacy-only step (depends on whether the runbook is still relevant post-retirement). |
./pkg/frr/frr_test.go:87:		NextHops:    []config.NextHopEntry{{Address: "fe80::1", Interface: "trust0"}},
./pkg/frr/frr_test.go:90:	want := "ipv6 route 2001:db8::/32 fe80::1 trust0\n"
./pkg/frr/frr_test.go:1050:			{Address: "fe80::2d0:f6ff:feda:c180", Interface: "wan0.0"},
./pkg/frr/frr_test.go:1054:	want := "ipv6 route ::/0 fe80::2d0:f6ff:feda:c180 wan0 vrf ATT\n"
./pkg/frr/frr_test.go:1077:		NextHops:    []config.NextHopEntry{{Address: "fe80::1", Interface: "trust0"}},
./pkg/frr/frr_test.go:1080:	want := "ipv6 route 2001:db8::/32 fe80::1 trust0\n"
./pkg/frr/frr_test.go:1090:		NextHops:    []config.NextHopEntry{{Address: "fe80::50", Interface: "wan0.50"}},
./pkg/frr/frr_test.go:1094:	want := "ipv6 route ::/0 fe80::50 wan0.50\n"
./pkg/frr/frr_test.go:1108:		NextHops:    []config.NextHopEntry{{Address: "fe80::50", Interface: "reth0.50"}},
./pkg/frr/frr_test.go:1111:	want := "ipv6 route ::/0 fe80::50 ge-0-0-1.50\n"
./pkg/frr/frr_test.go:1766:	if !strings.Contains(got, "bgp graceful-restart\n") {
./pkg/frr/frr_test.go:1767:		t.Errorf("missing graceful-restart in:\n%s", got)
./pkg/frr/frr_test.go:2549:			{Destination: "::/0", NextHops: []config.NextHopEntry{{Address: "fe80::1", Interface: "wan0"}}},
./pkg/frr/frr_test.go:2553:			{Gateway: "fe80::gw", Interface: "eth0", IsIPv6: true}, // IPv6 — should be suppressed
./pkg/frr/frr_test.go:2563:	if strings.Contains(got, "fe80::gw") {
./pkg/frr/frr_test.go:2578:						NextHops:    []config.NextHopEntry{{Address: "fe80::2d0:f6ff:feda:c180", Interface: "wan0"}},
./pkg/frr/frr_test.go:2587:	if !strings.Contains(got, "ipv6 route ::/0 fe80::2d0:f6ff:feda:c180 wan0 vrf vrf-ATT") {
./docs/pr/line-rate-investigation/step1-evidence/no-cos/p5202-fwd/dmesg-tail.txt:14:[Tue Apr 21 02:57:36 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/line-rate-investigation/step1-evidence/no-cos/p5202-fwd/dmesg-tail.txt:15:[Tue Apr 21 02:57:36 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/line-rate-investigation/step1-evidence/no-cos/p5202-fwd/dmesg-tail.txt:16:[Tue Apr 21 02:57:36 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/line-rate-investigation/step1-evidence/no-cos/p5202-fwd/dmesg-tail.txt:17:[Tue Apr 21 02:57:36 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/line-rate-investigation/step1-evidence/no-cos/p5202-fwd/dmesg-tail.txt:18:[Tue Apr 21 02:57:36 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/line-rate-investigation/step1-evidence/no-cos/p5202-fwd/dmesg-tail.txt:19:[Tue Apr 21 02:57:36 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/line-rate-investigation/step1-evidence/no-cos/p5202-fwd/dmesg-tail.txt:20:[Tue Apr 21 02:57:36 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/line-rate-investigation/step1-evidence/no-cos/p5202-fwd/dmesg-tail.txt:21:[Tue Apr 21 02:57:36 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/line-rate-investigation/step1-evidence/no-cos/p5202-fwd/dmesg-tail.txt:22:[Tue Apr 21 02:57:36 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/line-rate-investigation/step1-evidence/no-cos/p5202-fwd/dmesg-tail.txt:23:[Tue Apr 21 02:57:36 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/line-rate-investigation/step1-evidence/no-cos/p5202-fwd/dmesg-tail.txt:25:[Tue Apr 21 02:57:42 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/line-rate-investigation/step1-evidence/no-cos/p5202-fwd/dmesg-tail.txt:26:[Tue Apr 21 02:57:42 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/line-rate-investigation/step1-evidence/no-cos/p5202-fwd/dmesg-tail.txt:27:[Tue Apr 21 02:57:42 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/line-rate-investigation/step1-evidence/no-cos/p5202-fwd/dmesg-tail.txt:28:[Tue Apr 21 02:57:42 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/line-rate-investigation/step1-evidence/no-cos/p5202-fwd/dmesg-tail.txt:29:[Tue Apr 21 02:57:42 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/line-rate-investigation/step1-evidence/no-cos/p5202-fwd/dmesg-tail.txt:30:[Tue Apr 21 02:57:42 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/line-rate-investigation/step1-evidence/no-cos/p5202-fwd/dmesg-tail.txt:31:[Tue Apr 21 02:57:42 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/line-rate-investigation/step1-evidence/no-cos/p5202-fwd/dmesg-tail.txt:32:[Tue Apr 21 02:57:42 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/line-rate-investigation/step1-evidence/no-cos/p5202-fwd/dmesg-tail.txt:33:[Tue Apr 21 02:57:42 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/line-rate-investigation/step1-evidence/no-cos/p5202-fwd/dmesg-tail.txt:34:[Tue Apr 21 02:57:42 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./pkg/frr/manager_reload_test.go:261:// commit or restart).
./pkg/configstore/marker_test.go:167:// committed=1. Otherwise a restart misclassifies the rolled-back box as
./pkg/configstore/marker_test.go:237:// first-commit rollback) must survive a daemon restart as never-committed.
./pkg/configstore/marker_test.go:274:	// Simulate a daemon restart: a fresh store loading the same DB must
./pkg/configstore/marker_test.go:285:		t.Fatal("restart Load of never-committed DB: EverCommitted=true; want false (would re-enable takeover)")
./userspace-dp/src/afxdp/neighbor_resolver.rs:121:    /// resolution disabled until daemon restart).
./userspace-dp/src/afxdp/parser_tests.rs:102:    // ICMPv6 NA: type=136, code=0, checksum=0xffff, flags=0, target=fe80::abcd:ef01:0:42
./userspace-dp/src/afxdp/parser_tests.rs:126:        IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0xabcd, 0xef01, 0, 0x42)),
./pkg/logging/syslog_test.go:264:	// Accept first connection and close it to simulate server restart
./pkg/daemon/daemon.go:94:	// (without restarting probes) on hash-gated reconcileRPM calls AND
./pkg/daemon/daemon.go:261:	// goroutines. Set when cluster comms are started, called to restart them
./pkg/daemon/daemon.go:267:	// detect changes that require a comms restart (#87).
./pkg/daemon/daemon.go:277:	// This covers restart/redeploy of an already-active direct-mode RG,
./pkg/daemon/daemon.go:314:	// netlink.LinkByName; overridden in tests.
./pkg/daemon/daemon.go:431:		linkByNameFn:               netlink.LinkByName,
./pkg/ipsec/ipsec.go:368:		action = "restart"
./pkg/ipsec/ipsec.go:371:			action = "restart"
./pkg/ipsec/ipsec.go:377:			action = "restart"
./pkg/ipsec/ipsec.go:383:			action = "restart"
./pkg/ipsec/ipsec_test.go:444:		{"DPD action", "dpd_action = restart"},
./pkg/config/schema_validators.go:221:// pkg/dataplane/userspace/interfaces.go:391; RETH link-local checks:
./pkg/daemon/daemon_ra.go:66:	// Detect explicitly configured link-local addresses on RA interfaces.
./pkg/daemon/daemon_ra.go:67:	// If a user configures e.g. fe80::face/64 on a RETH interface, the RA
./pkg/daemon/daemon_ra.go:84:				// RETH HA startup installs a stable router link-local on the active
./pkg/daemon/daemon_ra.go:86:				// transient EUI-64 link-local which can later be removed by HA reconcile.
./pkg/daemon/vip_readiness_test.go:28:// mockLinkByName returns a function that resolves interfaces from a map.
./pkg/daemon/vip_readiness_test.go:29:func mockLinkByName(links map[string]*testLink) func(string) (netlink.Link, error) {
./pkg/daemon/vip_readiness_test.go:71:	ready, reasons := checkVIPReadinessForConfig(cfg, 0, mockLinkByName(links))
./pkg/daemon/vip_readiness_test.go:100:	ready, reasons := checkVIPReadinessForConfig(cfg, 0, mockLinkByName(links))
./pkg/daemon/vip_readiness_test.go:131:	ready, reasons := checkVIPReadinessForConfig(cfg, 0, mockLinkByName(links))
./pkg/daemon/vip_readiness_test.go:154:	ready, reasons := checkVIPReadinessForConfig(cfg, 0, mockLinkByName(links))
./pkg/daemon/vip_readiness_test.go:182:	ready, reasons := checkVIPReadinessForConfig(cfg, 0, mockLinkByName(links))
./pkg/daemon/vip_readiness_test.go:218:	ready, reasons := checkVIPReadinessForConfig(cfg, 0, mockLinkByName(links))
./pkg/daemon/vip_readiness_test.go:247:	ready, reasons := checkVIPReadinessForConfig(cfg, 0, mockLinkByName(links))
./pkg/daemon/vip_readiness_test.go:294:		linkByNameFn: mockLinkByName(map[string]*testLink{"ge-0-0-0": newTestLink("ge-0-0-0", true)}),
./docs/pr/814-max-interfaces/plan.md:397:- `systemctl is-active xpfd` returns `active` on fw0; no restart
./pkg/flowexport/README.md:46:- NetFlow v9 templates refresh every 60 s. If a collector restarts and
./pkg/daemon/bootstrap.go:22:// recorded kernel name (enp5s0) into fxp0, AND survives daemon restarts and
./pkg/daemon/bootstrap.go:81:// stable across restarts given the same on-disk state.
./pkg/daemon/bootstrap.go:108:	// restart Store.Load compiles that empty tree into a NON-nil
./pkg/daemon/bootstrap.go:246:// it survives the rename to fxp0 and daemon restarts (invariant 2). The file
./pkg/daemon/bootstrap.go:353:	if link, err := netlink.LinkByName(name); err == nil {
./pkg/daemon/bootstrap.go:383:			if link, err := netlink.LinkByName(name); err == nil &&
./pkg/daemon/bootstrap.go:439://     protected set survives rename/restart/rollback,
./pkg/daemon/bootstrap.go:584:	link, err := netlink.LinkByName(name)
./pkg/daemon/bootstrap.go:588:	addrs, _ := netlink.AddrList(link, netlink.FAMILY_ALL)
./pkg/daemon/bootstrap.go:631:	link, err := netlink.LinkByName(name)
./pkg/daemon/bootstrap.go:635:	addrs, _ := netlink.AddrList(link, netlink.FAMILY_ALL)
./pkg/daemon/daemon_ha_fabric.go:23:	parentLink, err := netlink.LinkByName(parent)
./pkg/daemon/daemon_ha_fabric.go:41:	if existing, err := netlink.LinkByName(name); err == nil {
./pkg/daemon/daemon_ha_fabric.go:66:	link, err := netlink.LinkByName(name)
./pkg/daemon/daemon_ha_fabric.go:114:	existing, err := netlink.AddrList(link, netlink.FAMILY_ALL)
./pkg/daemon/daemon_ha_fabric.go:126:			if err := netlink.AddrDel(link, &a); err != nil {
./pkg/daemon/daemon_ha_fabric.go:153:		if link, err := netlink.LinkByName(name); err == nil {
./pkg/daemon/daemon_ha_fabric.go:241:	link, err := netlink.LinkByName(fabIface)
./pkg/daemon/daemon_ha_fabric.go:310:// multicast) on the given interface. All link-local nodes respond, populating
./pkg/daemon/daemon_ha_fabric.go:325:	// ff02::1 — all-nodes link-local multicast
./pkg/daemon/daemon_ha_fabric.go:395:	link, err := netlink.LinkByName(fabIface)
./pkg/daemon/daemon_ha_fabric.go:432:		if ol, err := netlink.LinkByName(overlay); err == nil {
./pkg/daemon/daemon_ha_fabric.go:634:	link, err := netlink.LinkByName(fabIface)
./pkg/daemon/daemon_ha_fabric.go:669:		if ol, err := netlink.LinkByName(overlay); err == nil {
./docs/pr/814-max-interfaces/validation.md:32:- `dmesg` grep for `mlx5|bpf|oom|allocation failure`: no new errors (only expected link up/down around restart)
./pkg/daemon/daemon_rpm.go:4:// never re-applied on commit: probe config changes required a restart.
./pkg/daemon/daemon_rpm.go:266:// live goroutines). No probe restart. Caller holds rpmMu.
./pkg/daemon/daemon_rpm.go:298:// the daemon shuts down; reconcileRPM restarts it if pins fail again.
./pkg/daemon/daemon_rpm.go:336:// is failed, the install is retried with no probe restart (the
./pkg/daemon/daemon_ha_vip.go:30:		linkByName = netlink.LinkByName
./pkg/daemon/daemon_ha_vip.go:209:			linkByName = netlink.LinkByName
./pkg/daemon/daemon_ha_vip.go:259:			linkByName = netlink.LinkByName
./pkg/daemon/daemon_ha_vip.go:270:			if err := netlink.AddrDel(link, addr); err != nil {
./pkg/daemon/daemon_ha_vip.go:283:// addStableRethLinkLocal adds the stable router link-local address to all
./pkg/daemon/daemon_ha_vip.go:307:		// Skip interfaces with an explicitly configured link-local address —
./pkg/daemon/daemon_ha_vip.go:333:	link, err := netlink.LinkByName(ifName)
./pkg/daemon/daemon_ha_vip.go:343:			slog.Warn("failed to add stable link-local", "iface", ifName, "addr", ll, "err", err)
./pkg/daemon/daemon_ha_vip.go:346:		slog.Info("added stable router link-local", "iface", ifName, "addr", ll)
./pkg/daemon/daemon_ha_vip.go:350:// removeStableRethLinkLocal removes the stable router link-local address
./pkg/daemon/daemon_ha_vip.go:391:	link, err := netlink.LinkByName(ifName)
./pkg/daemon/daemon_ha_vip.go:398:	if err := netlink.AddrDel(link, addr); err != nil {
./pkg/daemon/daemon_ha_vip.go:400:			slog.Warn("failed to remove stable link-local", "iface", ifName, "addr", ll, "err", err)
./pkg/daemon/daemon_ha_vip.go:403:		slog.Info("removed stable router link-local", "iface", ifName, "addr", ll)
./pkg/daemon/daemon_ha_vip.go:520:	// Send NA burst for router link-local so hosts update neighbor cache for
./pkg/daemon/daemon_ha_vip.go:522:	// link-local if present, otherwise the auto-generated stable LL.
./pkg/daemon/daemon_ha_vip.go:532:			// Use configured link-local if present, otherwise stable LL.
./pkg/daemon/daemon_ha_vip.go:552:					slog.Warn("directSendGARPs: router link-local NA failed",
./pkg/daemon/daemon_ha_vip.go:563:							slog.Warn("directSendGARPs: router link-local NA failed",
./pkg/daemon/daemon_dns.go:40:// resolved drop-in + restarted resolved; applyDNSService disabled
./pkg/daemon/daemon_dns.go:201:	// content, skip the rewrite (and the restart churn it would imply).
./pkg/daemon/daemon_system.go:56:		if link, err := netlink.LinkByName(ifName); err == nil {
./pkg/daemon/daemon_system.go:237:// reconcileDNS. The former applySystemDNS (resolved drop-in + restart),
./pkg/daemon/daemon_system.go:238:// restartResolved, and applyDNSService (disable resolved) were removed —
./pkg/daemon/daemon_system.go:329:		{"systemctl", "restart", "chrony"},
./pkg/daemon/daemon_system.go:330:		{"systemctl", "restart", "chronyd"},
./pkg/daemon/daemon_system.go:341:	slog.Warn("failed to reload chrony threshold config; change will apply on next chronyd restart")
./pkg/daemon/daemon_system.go:645:		if out, err := runCommandTimeout("systemctl", "restart", "rsyslog"); err != nil {
./pkg/daemon/daemon_system.go:646:			slog.Error("failed to restart rsyslog",
./docs/pr/1917b-inplace-upgrade-mechanism/reviewer-ids.md:62:COMMENTED — 16 inline comments. Overlapped r1-r5 (DrainComplete strong predicate, ResetFailover all-RGs, LocalPrimary, PeerTakeoverReady, deploy grep, --unit health — ALL already fixed). Net-new Copilot items fixed in commit 8b222491: fail-closed msg path (.configdb/active.json), postinst restart safety-net, cutover Options doc.
./pkg/daemon/dhcp_reconcile_test.go:136:	// silent no-op until daemon restart).
./pkg/daemon/dhcp_reconcile_test.go:154:// active config but NEW lease state. The reconcile must not restart any
./pkg/daemon/dhcp_reconcile_test.go:156:// lease change -> callback -> applyConfig -> restart -> lease change.
./pkg/daemon/dhcp_reconcile_test.go:187:			t.Errorf("client %s restarted by lease-change reconcile", k)
./pkg/networkd/networkd_test.go:110:	// But should still have link-local and RA settings
./pkg/daemon/daemon_run.go:372:			// daemon never leaks stale probe pins across restarts.
./userspace-dp/src/filter/README.md:105:  failover and process restart still rebuild from configured bursts until a
./pkg/daemon/daemon_apply.go:273:	// a daemon restart) are also reaped. Operators MUST NOT
./pkg/daemon/daemon_apply.go:435:				if link, err := netlink.LinkByName(fabLinux); err == nil {
./pkg/daemon/daemon_apply.go:488:		if link, err := netlink.LinkByName(name); err == nil {
./pkg/daemon/daemon_apply.go:512:			link, err := netlink.LinkByName(linuxName)
./pkg/daemon/daemon_apply.go:629:			if _, err := netlink.LinkByName(linuxName); err != nil {
./pkg/daemon/daemon_apply.go:647:			// Suppress auto link-local generation on RETH member interfaces.
./pkg/daemon/daemon_apply.go:648:			// The virtual MAC triggers a kernel-generated link-local (fe80::...)
./pkg/daemon/daemon_apply.go:650:			// VIPs are managed explicitly; auto link-locals are unnecessary.
./pkg/daemon/daemon_apply.go:661:				// in NotifyLinkCycle will restart them.
./pkg/daemon/daemon_apply.go:670:			// Re-add link-local if this parent interface has IPv6 on unit 0.
./pkg/daemon/daemon_apply.go:671:			// NDP Neighbor Solicitation requires a link-local source address.
./pkg/daemon/daemon_apply.go:691:			if parentLink, err := netlink.LinkByName(linuxName); err == nil {
./pkg/daemon/daemon_apply.go:699:					// Suppress auto link-local on VLAN sub-interfaces too.
./pkg/daemon/daemon_apply.go:712:					// Re-add link-local if this VLAN sub-interface has IPv6.
./pkg/daemon/daemon_apply.go:726:	// 2.6b. Reconcile VRRP VIPs and stable link-locals after RETH MAC
./pkg/daemon/daemon_apply.go:729:	// including VRRP VIPs and stable link-locals.
./pkg/daemon/daemon_apply.go:731:		// Direct mode: re-add VIPs + stable link-locals for each RG
./pkg/daemon/daemon_apply.go:744:		// Re-add stable link-locals for active RGs after MAC bounce.
./pkg/daemon/daemon_apply.go:776:	// NOTE: stable link-local cleanup for secondary RGs is handled by
./pkg/daemon/daemon_apply.go:827:		// invalidates the heartbeat UDP sockets. Without this restart,
./pkg/daemon/daemon_apply.go:910:	// link-local), so both nodes appear as separate routers to hosts.
./pkg/daemon/daemon_apply.go:914:	// Stable link-local cleanup: handled by reconcile after election.
./pkg/daemon/daemon_apply.go:929:	// dhcp-server stanza (or restarting xpfd over a stale Kea left by
./pkg/daemon/daemon_apply.go:940:	// clear-if-active), and restarts only units that are currently
./pkg/daemon/daemon_apply.go:944:	// Fail-closed on commit (#1778/#1835 F3): restart/stop failures
./pkg/daemon/daemon_apply.go:976:	// lost it, restart clients whose options changed. The diff keys on
./pkg/daemon/daemon_apply.go:979:	// (onDHCPAddressChange) cannot restart clients in a loop. Runs after
./pkg/daemon/daemon_apply.go:999:	// the prior applySystemDNS (resolved drop-in + restart) and
./pkg/daemon/daemon_apply.go:1097:	// 20. Detect cluster transport config changes and restart comms (#87).
./pkg/daemon/daemon_apply.go:1098:	// Only restart if comms were previously started (activeClusterTransport
./pkg/daemon/daemon_apply.go:1103:			slog.Info("cluster: transport config changed, restarting comms",
./pkg/daemon/daemon_apply.go:1131:		// of the Step-0 knobs takes effect without a restart.
./pkg/daemon/daemon_apply.go:1167:	// has run; surface the Kea restart/stop failure through the commit.
./pkg/daemon/daemon_rpm_test.go:98:// reconciles retry ONLY the pin install (no probe restart), and the
./docs/pr/1732-waterfill-persistent-honored/plan.md:191:plan v1 MISSED. Phase 1 always restarts at the smallest ascending queue
./docs/pr/1732-waterfill-persistent-honored/plan.md:503:  restarts at the smallest queue and returns on honor, the smallest queue
./pkg/daemon/daemon_cluster_bind.go:84:		// link-local IPv6 addresses because the resulting listen address lacks
./pkg/daemon/daemon_cluster_bind.go:86:		// configured control/fabric address family instead of racing on fe80::.
./pkg/daemon/daemon_cluster_bind.go:116:// peer and skips unscoped link-local IPv6 addresses.
./pkg/daemon/daemon_dhcp.go:101:// restart the affected client. Called from applyConfigLocked on every
./pkg/daemon/host_tunables.go:532://     idempotent across daemon restarts — if xpfd crashes with
./pkg/daemon/host_tunables.go:666:// and netdev_budget are stable across restarts so this is harmless).
./pkg/daemon/rg_state.go:44:	// hitless restart).
./pkg/daemon/rg_state.go:289:// transient states like sync-hold, VRRP election, and hitless restart.
./pkg/config/compiler_system.go:969:	if clusterNode.FindChild("hitless-restart") != nil {
./pkg/daemon/daemon_neighbor.go:21:// xpfd restart. The replacement is event-driven: see
./pkg/daemon/daemon_neighbor.go:94:		link, err := netlink.LinkByName(resolved)
./pkg/daemon/daemon_neighbor.go:134:					link, err := netlink.LinkByName(linuxName)
./pkg/api/metrics_descriptors.go:255:				"(a daemon restart would load a stale config, #1799); 0 "+
./pkg/api/metrics_descriptors.go:726:				"daemon restart in Phase 1 (#925).",
./pkg/api/metrics_descriptors.go:1044:			"Proactive neighbor-warm requests dropped because the warmer worker thread died; warming is disabled until daemon restart (#1636).",
./pkg/api/metrics_descriptors.go:1082:			"On-demand neighbor-resolver enqueue attempts dropped because the resolver worker thread died; on-demand resolution is disabled until daemon restart (#1769).",
./docs/pr/1698-routing-domain-managers/plan.md:214:a pure netlink op — `LinkByName` + `LinkSetMasterByIndex` — and touches
./docs/pr/1698-routing-domain-managers/plan.md:232:  `LinkByName`/`LinkAdd`/`LinkDel`/`LinkSetUp`/`LinkList`. Note
./docs/pr/1698-routing-domain-managers/plan.md:234:  and `LinkByName`; fold `LinkSetMaster` into the VRF domain's ops surface.
./docs/pr/1698-routing-domain-managers/plan.md:236:  `LinkByName`/`LinkAdd`/`LinkDel`/`LinkSetUp`/`LinkSetDown`/`AddrAdd`/
./docs/pr/1698-routing-domain-managers/plan.md:237:  `AddrList`/**`LinkSetMaster`** (NOT `LinkSetMasterByIndex` — the code at
./docs/pr/1698-routing-domain-managers/plan.md:238:  routing.go:429 uses `LinkSetMaster(link, master)`). `AddrList` is used
./docs/pr/1698-routing-domain-managers/plan.md:246:  `LinkByIndex`/`LinkByName` (verified: routing.go:442, 480, 1045, 1106;
./docs/pr/1698-routing-domain-managers/plan.md:255:- `monitorManager` needs `LinkByName` (`ApplyInterfaceMonitors`,
./docs/pr/800-workers-queues/investigation.md:62:numbers: a fresh daemon-restart state with cold queue dispatch
./docs/pr/800-workers-queues/investigation.md:100:until the next daemon restart with a different worker count.
./pkg/daemon/daemon_reth.go:46:	link, err := netlink.LinkByName(ifName)
./pkg/daemon/daemon_reth.go:167:	link, err := netlink.LinkByName(ifName)
./pkg/daemon/daemon_reth.go:200:// clearDadFailed removes any dadfailed link-local IPv6 addresses and re-adds
./pkg/daemon/daemon_reth.go:204:	link, err := netlink.LinkByName(ifName)
./pkg/daemon/daemon_reth.go:208:	addrs, err := netlink.AddrList(link, netlink.FAMILY_V6)
./pkg/daemon/daemon_reth.go:220:		netlink.AddrDel(link, &addr)
./pkg/daemon/daemon_reth.go:223:			slog.Warn("failed to re-add link-local with NODAD", "iface", ifName, "err", err)
./pkg/daemon/daemon_reth.go:225:			slog.Info("cleared dadfailed link-local", "iface", ifName, "addr", addr.IP)
./pkg/daemon/daemon_reth.go:230:// removeAutoLinkLocal removes the kernel auto-generated link-local IPv6 address
./pkg/daemon/daemon_reth.go:231:// from a RETH member interface. With addr_gen_mode=1 set, no new link-local will
./pkg/daemon/daemon_reth.go:234:	link, err := netlink.LinkByName(ifName)
./pkg/daemon/daemon_reth.go:238:	addrs, err := netlink.AddrList(link, netlink.FAMILY_V6)
./pkg/daemon/daemon_reth.go:244:			// Preserve stable router link-locals managed by addStableRethLinkLocal.
./pkg/daemon/daemon_reth.go:248:			if err := netlink.AddrDel(link, &addr); err == nil {
./pkg/daemon/daemon_reth.go:249:				slog.Info("removed auto link-local from RETH member", "iface", ifName, "addr", addr.IP)
./pkg/daemon/daemon_reth.go:255:// ensureRethLinkLocal adds a link-local IPv6 address to a RETH member
./pkg/daemon/daemon_reth.go:258:// link-local source address for NDP Neighbor Solicitations when forwarding
./pkg/daemon/daemon_reth.go:262:// Computes EUI-64 link-local from the interface MAC and adds it with NODAD.
./pkg/daemon/daemon_reth.go:264:	link, err := netlink.LinkByName(ifName)
./pkg/daemon/daemon_reth.go:272:	// Check if link-local already exists.
./pkg/daemon/daemon_reth.go:273:	addrs, err := netlink.AddrList(link, netlink.FAMILY_V6)
./pkg/daemon/daemon_reth.go:283:	// Compute EUI-64 link-local from MAC.
./pkg/daemon/daemon_reth.go:291:		slog.Warn("failed to add link-local to RETH interface",
./pkg/daemon/daemon_reth.go:294:		slog.Info("added link-local for NDP on RETH interface",
./pkg/daemon/daemon_reth.go:300:// explicitly configured link-local IPv6 address (fe80::/10) on the given unit.
./pkg/daemon/daemon_ha_sync.go:388:	// be restarted on config change (#87) without cancelling the daemon ctx.
./pkg/daemon/daemon_ha_sync.go:683:			// #1792: while our heartbeat sockets restart (VRF rebind),
./pkg/daemon/daemon_ha_sync.go:685:			// traffic so a >500ms restart does not fire a false
./pkg/daemon/daemon_ha_sync.go:707:						"remediation", "set system dataplane-type userspace and restart xpfd",
./pkg/daemon/daemon_ha_sync.go:829:// restarted with new transport settings (#87). Cancels the comms sub-context
./pkg/daemon/daemon_ha_sync.go:849:// changes that require restarting cluster comms.
./pkg/api/README.md:23:  a restart would load a stale config). The same state is exported as
./pkg/daemon/rss_indirection.go:25:// `rss-indirection enable|disable` knob take effect without a restart.
./pkg/daemon/rss_indirection.go:148:		// runtime reverts the table without a daemon restart.
./pkg/daemon/rss_indirection.go:269:	// daemon restarts and avoids spurious NIC churn during reconcile.
./pkg/daemon/README.md:86:  PCI, survives rename/restart/rollback), and — only if that NIC is
./pkg/daemon/README.md:98:  the never-committed marker so a restart re-enters bootstrap.
./pkg/cli/cli_request.go:956:	fmt.Println("You may now replace the binary and restart the service:")
./pkg/api/health.go:11:// or the running active config failed to persist to disk (a restart
./pkg/api/health.go:38:			writeJSON(w, http.StatusServiceUnavailable, Response{Success: false, Data: payload, Error: "active configuration failed to persist to disk; restart would load stale config"})
./pkg/daemon/interface_addr_test.go:20:		mustIPNet(t, "fe80::1266:6aff:fe30:ad1c/64"),
./pkg/daemon/interface_addr_test.go:64:		mustIPNet(t, "fe80::1266:6aff:fe30:ad1c/64"),
./pkg/daemon/daemon_flow.go:64:		link, err := nlh.LinkByName(lease.Interface)
./pkg/daemon/daemon_ha.go:632:		// sync-hold, election timers, hitless restart). Skip entirely
./pkg/daemon/daemon_ha.go:667:		// avoid thrashing restarts every reconcile tick.
./pkg/daemon/daemon_ha.go:676:		// Stable link-local: ensure correct on EVERY reconcile tick.
./pkg/daemon/daemon_ha.go:677:		// The kernel preserves NODAD addresses across daemon restarts,
./pkg/daemon/daemon_ha.go:693:		// MAC producing a distinct link-local, so hosts see each node
./pkg/daemon/daemon_ha.go:836:// daemon run. The in-memory blackholeRoutes map is lost on restart, so any
./pkg/daemon/linksetup.go:118:// changes and the enable/disable knob both take effect without a restart.
./pkg/daemon/linksetup.go:324:	link, err := netlink.LinkByName(oldName)
./pkg/daemon/bootstrap_test.go:28:		// AGY r1 CRITICAL: post-first-commit-rollback restart. The empty tree
./pkg/daemon/bootstrap_test.go:32:		{"post-rollback-restart-empty-compiled", true, false, false, bootClassBootstrap},
./pkg/daemon/ra_source_test.go:57:						0: {Addresses: []string{"fe80::face/64", "2001:559:8585:ef00::1/64"}},
./pkg/daemon/ra_source_test.go:73:	if ras[0].SourceLinkLocal != "fe80::face" {
./pkg/daemon/ra_source_test.go:74:		t.Fatalf("SourceLinkLocal = %q, want fe80::face", ras[0].SourceLinkLocal)
./pkg/api/server.go:76:	// background retry has not yet succeeded — a daemon restart would
./pkg/api/server.go:324:// ECDSA P-256 certificate is generated and persisted for reuse across restarts.
./pkg/api/server.go:363:	// Persist for reuse across restarts
./pkg/daemon/daemon_ipmon.go:218:	// no Compile, no helper restart).
./pkg/daemon/daemon_ipmon.go:291:// restarted probes' results (all unknown ⇒ baseline first), and the
./pkg/daemon/daemon_neighbor_listener.go:228:// which makes O(N) netlink LinkByName calls per N configured
./pkg/daemon/daemon_neighbor_listener.go:501:		if link, err := netlink.LinkByName(fabricOverlay); err == nil {
./pkg/daemon/daemon_neighbor_listener.go:506:		if link, err := netlink.LinkByName(fabricOverlay1); err == nil {
./pkg/cli/cli_helpers.go:92:				link, err := netlink.LinkByName(linuxName)
./pkg/daemon/daemon_ha_userspace.go:976:	// If the barrier fails, restart the retry loop so the peer can still
./pkg/daemon/daemon_ha_userspace.go:977:	// receive its cold-start bootstrap. Only suppress the restart when
./pkg/daemon/daemon_ha_userspace.go:993:		slog.Info("cluster: restarting bulk-prime retry loop after failed demotion prep",
./pkg/api/metrics_userspace.go:211:// worker died and proactive warming is off until daemon restart.
./pkg/api/metrics.go:87:	// yet succeeded (restart would load a stale config).
./pkg/api/metrics.go:216:	// 0 = healthy. Set-only in Phase 1 (cleared by daemon restart).
./pkg/api/health_test.go:113:// operator probe surfaces that a restart would load a stale config.
./pkg/dhcpserver/README.md:15:  regenerates the Kea config and restarts the unit; for each
./pkg/dhcpserver/README.md:19:  **Fail-closed:** restart failures (and failures to stop an active
./pkg/dhcpserver/README.md:41:  families but restarts only units that are currently active; clears
./pkg/dhcpserver/README.md:49:  (authoritative; survives daemon restarts).
./pkg/dhcpserver/README.md:74:  `Apply`/`Clear` after restart. Every `systemctl` shell-out is
./pkg/dhcpserver/README.md:82:  regenerated, but units restart only if currently active (this node
./pkg/dhcp/reconcile.go:33:// run goroutine at start, so a change requires a restart).
./pkg/dhcp/reconcile.go:61:// changed are restarted, and missing clients are started.
./pkg/dhcp/reconcile.go:67:// would restart the client on every lease event and loop forever
./pkg/dhcp/reconcile.go:86:	// is about to be restarted by the fingerprint mismatch anyway.
./docs/pr/1873-tunnel-ids/plan.md:395:  restarts, link state, or commit ordering. During a config-sync
./docs/pr/1873-tunnel-ids/plan.md:398:- *Restart*: pure function ⇒ stable across daemon/helper restarts; no
./docs/pr/1873-tunnel-ids/plan.md:467:become a function of per-node commit HISTORY: a node that restarted
./docs/pr/1873-tunnel-ids/plan.md:622:  destination is ignored by the origin thread until restart. That
./pkg/dhcpserver/dhcpserver_test.go:19:// invocation as a joined string ("restart kea-dhcp4-server").
./pkg/dhcpserver/dhcpserver_test.go:92:// while the other family restarts normally.
./pkg/dhcpserver/dhcpserver_test.go:99:	if !calledWith(*calls, "restart "+kea4Svc) {
./pkg/dhcpserver/dhcpserver_test.go:100:		t.Errorf("expected restart of %s, got %v", kea4Svc, *calls)
./pkg/dhcpserver/dhcpserver_test.go:119:// Fail-closed (#1778): a Kea restart failure must fail Apply so the
./pkg/dhcpserver/dhcpserver_test.go:122:	m, _ := testManager(t, map[string]bool{}, "restart "+kea4Svc)
./pkg/dhcpserver/dhcpserver_test.go:125:		t.Fatal("expected error from failed restart, got nil")
./pkg/dhcpserver/dhcpserver_test.go:155:// IsRunning reflects systemd state, surviving daemon restarts.
./pkg/dhcpserver/dhcpserver_test.go:245:	if calledWith(*calls, "restart "+kea4Svc) {
./pkg/dhcpserver/dhcpserver_test.go:246:		t.Errorf("must not restart kea4 after generate failure: %v", *calls)
./pkg/dhcpserver/dhcpserver_test.go:371:// address matching (clients use link-local sources), so a
./pkg/dhcpserver/dhcpserver_test.go:472:// v4 config was on disk when each restart ran (the worker writes the
./pkg/dhcpserver/dhcpserver_test.go:473:// config before restarting, so this observes exactly which desired
./pkg/dhcpserver/dhcpserver_test.go:566:// always regenerate the Kea config and restart ONLY units that are
./pkg/dhcpserver/dhcpserver_test.go:569:// transition, with no restart.
./pkg/dhcpserver/dhcpserver_test.go:571:	t.Run("active unit restarted with rewritten config", func(t *testing.T) {
./pkg/dhcpserver/dhcpserver_test.go:579:		if !calledWith(*calls, "restart "+kea4Svc) {
./pkg/dhcpserver/dhcpserver_test.go:580:			t.Errorf("active unit must restart on cluster commit, got %v", *calls)
./pkg/dhcpserver/dhcpserver_test.go:584:	t.Run("inactive unit gets config only, no restart", func(t *testing.T) {
./pkg/dhcpserver/dhcpserver_test.go:593:			t.Errorf("inactive unit must not restart on cluster commit, got %v", *calls)
./pkg/dhcpserver/dhcpserver_test.go:597:	t.Run("restart failure on active unit fails the commit", func(t *testing.T) {
./pkg/dhcpserver/dhcpserver_test.go:598:		m, _ := testManager(t, map[string]bool{kea4Svc: true}, "restart "+kea4Svc)
./pkg/dhcpserver/dhcpserver_test.go:601:			t.Fatalf("want fail-closed restart error naming the unit, got %v", err)
./pkg/dhcpserver/dhcpserver_test.go:646:	// regenerates config and restarts).
./pkg/dhcpserver/dhcpserver_test.go:664:	restarts := 0
./pkg/dhcpserver/dhcpserver_test.go:666:		if c == "restart "+kea4Svc {
./pkg/dhcpserver/dhcpserver_test.go:667:			restarts++
./pkg/dhcpserver/dhcpserver_test.go:670:	if restarts != 1 {
./pkg/dhcpserver/dhcpserver_test.go:671:		t.Errorf("apply count: want exactly the sync commit's restart, got %d (%v)", restarts, *calls)
./pkg/dhcpserver/dhcpserver_test.go:696:		t.Errorf("want 2 restarts (sync + newer async), got %d: %v", got, *calls)
./pkg/dhcpserver/dhcpserver_test.go:725:	<-applied                                      // worker blocked in prime's restart
./pkg/cli/cli_show_interfaces.go:170:		link, nlErr := netlink.LinkByName(physName)
./pkg/cli/cli_show_interfaces.go:371:							if strings.HasPrefix(a, "fe80:") {
./pkg/cli/cli_show_interfaces.go:484:		addrs, _ := netlink.AddrList(link, netlink.FAMILY_ALL)
./pkg/cli/cli_show_interfaces.go:958:		addrs, _ := netlink.AddrList(link, netlink.FAMILY_ALL)
./pkg/cli/cli_show_interfaces.go:978:					if strings.HasPrefix(a, "fe80:") {
./pkg/dhcpserver/test_seams.go:17://     (restart/stop). Return nil for success.
./pkg/fwdstatus/sampler_test.go:120:// Counter decrease (e.g. userspace-dp restart reset the cumulative
./pkg/cli/cli_show_routing.go:649:		// Skip link-local multicast and unresolved entries without MACs
./pkg/vrrp/manager.go:249:			// VIPs changed — must restart instance.
./pkg/vrrp/manager.go:250:			slog.Info("vrrp: restarting instance", "key", existing.key(),
./pkg/vrrp/manager.go:417:	link, err := netlink.LinkByName(name)
./pkg/dhcp/commit.go:104://     firing is never a restart-loop hazard — only recompile churn.
./pkg/fwdstatus/sampler.go:199:		// restart or a brief Status() miscarriage can reset the
./pkg/dhcp/test_seams.go:55:// this to assert a reconcile did (or did not) restart a client.
./pkg/dhcpserver/dhcpserver.go:65:		// #1835): a previous daemon or external restart job can be
./pkg/dhcpserver/dhcpserver.go:158:// the Kea config and restarts the unit; for each family that is NOT
./pkg/dhcpserver/dhcpserver.go:163:// Fail-closed (#1778): a restart failure (or a failure to stop an
./pkg/dhcpserver/dhcpserver.go:176:// next VRRP transition — but the unit is restarted only when systemd
./pkg/dhcpserver/dhcpserver.go:182:// Fail-closed like Apply: generate/restart/stop failures are returned
./pkg/dhcpserver/dhcpserver.go:193:// OVER a later synchronous commit's fresh config). restartInactive
./pkg/dhcpserver/dhcpserver.go:194:// selects whether a configured family's unit is restarted
./pkg/dhcpserver/dhcpserver.go:197:func (m *Manager) apply(gen uint64, cfg *config.DHCPServerConfig, restartInactive bool) error {
./pkg/dhcpserver/dhcpserver.go:219:		} else if restartInactive || m.unitActive(kea4Svc) {
./pkg/dhcpserver/dhcpserver.go:220:			if err := m.runSystemctl("restart", kea4Svc); err != nil {
./pkg/dhcpserver/dhcpserver.go:221:				errs = append(errs, fmt.Errorf("restart %s: %w", kea4Svc, err))
./pkg/dhcpserver/dhcpserver.go:231:		} else if restartInactive || m.unitActive(kea6Svc) {
./pkg/dhcpserver/dhcpserver.go:232:			if err := m.runSystemctl("restart", kea6Svc); err != nil {
./pkg/dhcpserver/dhcpserver.go:233:				errs = append(errs, fmt.Errorf("restart %s: %w", kea6Svc, err))
./pkg/dhcpserver/dhcpserver.go:349:// (authoritative — survives xpfd restarts, unlike the pre-#1778
./pkg/dhcpserver/dhcpserver.go:602:			// matching the way v4 can (clients talk from link-local
./pkg/vrrp/README.md:73:  state is seeded with `netlink.LinkByName` at instance create/update
./pkg/dhcp/README.md:5:restarts so the same client identifier returns to the same lease.
./pkg/dhcp/README.md:32:  removed ones, restart clients whose option identity changed. Called
./pkg/dhcp/README.md:53:  (options are read at goroutine start, so a restart is required).
./pkg/dhcp/README.md:57:  restart its client and loop forever. There is a regression test
./pkg/dhcp/README.md:58:  proving a lease change does not restart clients
./pkg/dhcp/README.md:66:  cancellation, DHCPv4 max-retransmissions, DHCPv6 link-local abort —
./pkg/dhcp/README.md:101:  so a fire is never a restart-loop hazard — only recompile churn.
./pkg/dhcp/reconcile_test.go:143:	// restart the client (#1793 / plan §5.4 item 1).
./pkg/dhcp/reconcile_test.go:152:		t.Fatal("client handle unchanged — option change did not restart client")
./pkg/dhcp/reconcile_test.go:171:// TestReconcileLeaseChangeDoesNotRestart is the no-restart-on-lease-change
./pkg/dhcp/reconcile_test.go:175:// would restart the client and loop forever. A reconcile with an
./pkg/dhcp/reconcile_test.go:200:	// And again with a different address — still no restart.
./pkg/dhcp/reconcile_test.go:212:			t.Errorf("client %s restarted on lease-only change", k)
./pkg/dhcp/reconcile_test.go:221:// DHCPv6 link-local abort) must deregister itself so a later Start for
./pkg/dhcp/reconcile_test.go:282:// from config. Renew must then NOT restart the client — restarting
./pkg/dhcp/reconcile_test.go:328:	// The client must NOT have been restarted: exactly the original
./pkg/dhcp/reconcile_test.go:376:	// And the Renew guard therefore cannot restart: no client, no
./docs/pr/line-rate-investigation/step0-audit.md:329:2. **Worker count 4 → 6** (systemd unit edit + restart, unlocks
./pkg/vrrp/instance.go:63:	localIPv6        net.IP // our link-local IPv6 address (source for IPv6 VRRP adverts)
./pkg/vrrp/instance.go:174:	// Deterministic IPv6 link-local selection: sort candidates and
./pkg/vrrp/instance.go:176:	// is used even when the interface has multiple link-locals.
./pkg/vrrp/instance.go:199:// in-place without restarting.
./pkg/vrrp/instance.go:1014:// Source: link-local address, Destination: ff02::12, Hop Limit: 255.
./pkg/vrrp/instance.go:1022:		// Lazy resolve: deterministically select the lowest link-local
./pkg/vrrp/instance.go:1024:		// link-local at openSocket() time (e.g. DAD still running).
./pkg/vrrp/instance.go:1037:			slog.Info("vrrp: late-resolved IPv6 link-local address",
./pkg/vrrp/instance.go:1041:			slog.Warn("vrrp: no link-local IPv6 address, skipping IPv6 advert",
./pkg/vrrp/instance.go:1043:			return fmt.Errorf("no link-local IPv6 address on %s", vi.cfg.Interface)
./pkg/vrrp/instance.go:1069:	link, err := netlink.LinkByName(vi.cfg.Interface)
./pkg/vrrp/instance.go:1101:	link, err := netlink.LinkByName(vi.cfg.Interface)
./pkg/vrrp/instance.go:1112:		if err := netlink.AddrDel(link, addr); err != nil {
./pkg/vrrp/instance.go:1203:// link-local IPv6 address on the interface. Sorting ensures the same
./pkg/vrrp/instance.go:1205:// even when multiple link-locals exist (e.g. after MAC changes).
./docs/pr/line-rate-investigation/step1-plan-review.md:66:The plan obtains `WORKER_PIDS` with `pgrep -f 'xpf-userspace-w'` (`docs/pr/line-rate-investigation/step1-plan.md:137-142`), but workers are named `xpf-userspace-worker-{id}` in the Rust thread builder (`userspace-dp/src/afxdp/coordinator.rs:693-695`). `pgrep -f` matches command line, not thread name, so this can easily produce an empty list or the wrong scope; even if corrected, a daemon restart or worker respawn mid-window invalidates the attachment and the plan has no invariant that catches that.
./docs/pr/line-rate-investigation/step1-plan-review.md:68:Concrete mitigation: collect TIDs from `ps -eLo pid,tid,comm,args` or `pgrep -w` against the actual thread name, assert exactly four live worker TIDs before capture, and invalidate the cell on any daemon restart.
./pkg/dhcp/dhcp.go:57:	// client must be restarted. It NEVER includes lease or address
./pkg/dhcp/dhcp.go:262:	// StopAll) cancels a client. During graceful restart (SIGTERM), the
./pkg/dhcp/dhcp.go:282:		// retransmissions, DHCPv6 link-local abort — not just Renew,
./pkg/dhcp/dhcp.go:310:// mid-exchange, DHCPv4 max-retransmission, DHCPv6 link-local abort) —
./pkg/dhcp/dhcp.go:345:// Renew restarts the DHCP client for the specified interface and address
./pkg/dhcp/dhcp.go:367:		// done guarantees finishClient has completed before restart.
./pkg/dhcp/dhcp.go:379:			slog.Info("DHCP: renew skipped restart; client removed from config",
./pkg/dhcp/dhcp.go:842:	// Wait for link-local address
./pkg/dhcp/dhcp.go:844:		slog.Warn("DHCPv6: no link-local address, aborting",
./pkg/dhcp/dhcp.go:1245:// discoverIPv6Router finds the link-local address of an IPv6 router on the
./pkg/dhcp/dhcp.go:1250:	link, err := m.nlHandle.LinkByName(ifaceName)
./pkg/dhcp/dhcp.go:1288:// waitForLinkLocal waits until the interface has a link-local IPv6 address.
./pkg/dhcp/dhcp.go:1299:			return fmt.Errorf("timeout waiting for link-local on %s", ifaceName)
./pkg/dhcp/dhcp.go:1328:	link, err := m.nlHandle.LinkByName(ifaceName)
./pkg/dhcp/dhcp.go:1351:	link, err := m.nlHandle.LinkByName(ifaceName)
./pkg/dhcp/dhcp.go:1359:	if err := m.nlHandle.AddrDel(link, addr); err != nil {
./docs/pr/1709-wireguard-s1-wire-protocol-compliance/plan.md:56:   monotonicity *within a process*; cross-restart disk persistence is deferred
./docs/pr/1709-wireguard-s1-wire-protocol-compliance/plan.md:257:in-process strict monotonicity via a `Mutex<[u8;12]>`; cross-restart disk
./docs/pr/1709-wireguard-s1-wire-protocol-compliance/plan.md:348:    /// Seed from a persisted high-water mark (control-plane restart, S6).
./docs/pr/1709-wireguard-s1-wire-protocol-compliance/plan.md:367:operational note (an NTP step-back or rapid restart of an *integrated* xpf
./docs/pr/1709-wireguard-s1-wire-protocol-compliance/plan.md:369:and is captured as an **S2 testing runbook item**: when restarting xpf during
./docs/pr/1709-wireguard-s1-wire-protocol-compliance/plan.md:688:  mutex; never regresses within a process. Cross-restart persistence hook
./docs/pr/1709-wireguard-s1-wire-protocol-compliance/plan.md:709:| TAI64N monotonicity / self-DoS | **MED** | Mitigated by mutex-guarded strictly-increasing clock + the `tai64n_strictly_monotonic` test. Cross-restart persistence deferred (documented). |
./docs/pr/1709-wireguard-s1-wire-protocol-compliance/plan.md:961:| 10 | NTP step-back / restart self-DoS during integrated testing | AGY-3 | DOC | S2 runbook item (flush peer WG state); durable fix = S6 disk persist. |
./docs/pr/1709-wireguard-s1-wire-protocol-compliance/plan.md:978:  reservation; epoch offset + nanos whitening correct; NTP/restart self-DoS
./docs/pr/1527-dpdk-boot-decouple/reviewer-ids.md:11:- Copilot inline review on PR: posted 2026-05-25T05:32:08Z with 1 inline comment on `dataplane.go:155-164` (fatal-at-startup brick-restart concern). Addressed by `a00d9111`.
./docs/pr/1527-dpdk-boot-decouple/reviewer-ids.md:67:(d.dp = nil safety, branch ordering), (h) scope-creep into #1528, (i) restart-race
./docs/pr/1527-dpdk-boot-decouple/plan.md:21:   on the next restart for any node that still had a persisted
./docs/pr/1527-dpdk-boot-decouple/plan.md:78:restart.
./docs/pr/1527-dpdk-boot-decouple/plan.md:447:   `os.Exit(1)` loop on restart — the daemon stays up and is
./pkg/vrrp/vrrp_test.go:365:	srcIP := net.ParseIP("fe80::1")
./pkg/vrrp/vrrp_test.go:1196:	vi.localIPv6 = net.ParseIP("fe80::1") // lower IPv6
./pkg/vrrp/vrrp_test.go:1206:		SrcIP:    net.ParseIP("fe80::2"), // higher IPv6
./pkg/vrrp/vrrp_test.go:1222:	vi.localIPv6 = net.ParseIP("fe80::2") // higher IPv6
./pkg/vrrp/vrrp_test.go:1232:		SrcIP:    net.ParseIP("fe80::1"), // lower IPv6
./pkg/vrrp/vrrp_test.go:1536:	srcIP := net.ParseIP("fe80::1")
./pkg/vrrp/vrrp_test.go:1568:	srcIP := net.ParseIP("fe80::1")
./pkg/vrrp/vrrp_test.go:1591:	srcIP := net.ParseIP("fe80::1")
./pkg/vrrp/vrrp_test.go:1754:	vi.localIPv6 = net.ParseIP("fe80::1")
./pkg/vrrp/vrrp_test.go:1757:	srcIP := net.ParseIP("fe80::2")
./pkg/vrrp/vrrp_test.go:1852:	// localIPv6 is nil and interface has no link-local → should error.
./pkg/vrrp/vrrp_test.go:1870:	if !strings.Contains(err.Error(), "no link-local IPv6") {
./pkg/vrrp/vrrp_test.go:1883:	vi.localIPv6 = net.ParseIP("fe80::1")
./docs/pr/line-rate-investigation/step1-evidence/no-cos/p5201-fwd/dmesg-tail.txt:14:[Tue Apr 21 02:57:36 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/line-rate-investigation/step1-evidence/no-cos/p5201-fwd/dmesg-tail.txt:15:[Tue Apr 21 02:57:36 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/line-rate-investigation/step1-evidence/no-cos/p5201-fwd/dmesg-tail.txt:16:[Tue Apr 21 02:57:36 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/line-rate-investigation/step1-evidence/no-cos/p5201-fwd/dmesg-tail.txt:17:[Tue Apr 21 02:57:36 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/line-rate-investigation/step1-evidence/no-cos/p5201-fwd/dmesg-tail.txt:18:[Tue Apr 21 02:57:36 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/line-rate-investigation/step1-evidence/no-cos/p5201-fwd/dmesg-tail.txt:19:[Tue Apr 21 02:57:36 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/line-rate-investigation/step1-evidence/no-cos/p5201-fwd/dmesg-tail.txt:20:[Tue Apr 21 02:57:36 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/line-rate-investigation/step1-evidence/no-cos/p5201-fwd/dmesg-tail.txt:21:[Tue Apr 21 02:57:36 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/line-rate-investigation/step1-evidence/no-cos/p5201-fwd/dmesg-tail.txt:22:[Tue Apr 21 02:57:36 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/line-rate-investigation/step1-evidence/no-cos/p5201-fwd/dmesg-tail.txt:23:[Tue Apr 21 02:57:36 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/line-rate-investigation/step1-evidence/no-cos/p5201-fwd/dmesg-tail.txt:25:[Tue Apr 21 02:57:42 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/line-rate-investigation/step1-evidence/no-cos/p5201-fwd/dmesg-tail.txt:26:[Tue Apr 21 02:57:42 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/line-rate-investigation/step1-evidence/no-cos/p5201-fwd/dmesg-tail.txt:27:[Tue Apr 21 02:57:42 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/line-rate-investigation/step1-evidence/no-cos/p5201-fwd/dmesg-tail.txt:28:[Tue Apr 21 02:57:42 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/line-rate-investigation/step1-evidence/no-cos/p5201-fwd/dmesg-tail.txt:29:[Tue Apr 21 02:57:42 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/line-rate-investigation/step1-evidence/no-cos/p5201-fwd/dmesg-tail.txt:30:[Tue Apr 21 02:57:42 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/line-rate-investigation/step1-evidence/no-cos/p5201-fwd/dmesg-tail.txt:31:[Tue Apr 21 02:57:42 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/line-rate-investigation/step1-evidence/no-cos/p5201-fwd/dmesg-tail.txt:32:[Tue Apr 21 02:57:42 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/line-rate-investigation/step1-evidence/no-cos/p5201-fwd/dmesg-tail.txt:33:[Tue Apr 21 02:57:42 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/line-rate-investigation/step1-evidence/no-cos/p5201-fwd/dmesg-tail.txt:34:[Tue Apr 21 02:57:42 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./pkg/grpcapi/server_show_interfaces.go:324:							if strings.HasPrefix(a, "fe80:") {
./docs/pr/1930-inc2-ha-kernel-roll/agy-review-r3.md:21:    *   *Fail-Safe Evaluation:* This is the correct fail-safe behavior. Under a write failure on `/var/lib/xpf` (which also breaks journal persistence), the node is degraded. Blockading local takeover and leaving the peer primary is the safest outcome. If the operator rectifies the disk issue, the hold can be cleared by rebooting or restarting `xpfd`, which will boot with a cleared journal (`IsArmed() == false`) and not set the hold.
./docs/pr/1930-inc2-ha-kernel-roll/agy-review-r3.md:54:    *   *Risk:* Low. On a successful roll, `reconcileKernelUpgradeHold` has already cleared the hold 5 seconds post-boot. If the roll fails, keeping the hold is the correct fail-safe behavior. The only minor side effect is that if an operator manually triggers `rejoin` on a node where the marker write failed, the hold is not cleared through gRPC and requires a daemon restart (`systemctl restart xpfd`) to resolve.
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5204-fwd/dmesg-tail.txt:17:[Tue Apr 21 02:57:36 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5204-fwd/dmesg-tail.txt:18:[Tue Apr 21 02:57:36 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5204-fwd/dmesg-tail.txt:19:[Tue Apr 21 02:57:36 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5204-fwd/dmesg-tail.txt:20:[Tue Apr 21 02:57:36 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5204-fwd/dmesg-tail.txt:21:[Tue Apr 21 02:57:36 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5204-fwd/dmesg-tail.txt:22:[Tue Apr 21 02:57:36 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5204-fwd/dmesg-tail.txt:23:[Tue Apr 21 02:57:36 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5204-fwd/dmesg-tail.txt:24:[Tue Apr 21 02:57:36 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5204-fwd/dmesg-tail.txt:25:[Tue Apr 21 02:57:36 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5204-fwd/dmesg-tail.txt:26:[Tue Apr 21 02:57:36 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5204-fwd/dmesg-tail.txt:28:[Tue Apr 21 02:57:42 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5204-fwd/dmesg-tail.txt:29:[Tue Apr 21 02:57:42 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5204-fwd/dmesg-tail.txt:30:[Tue Apr 21 02:57:42 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5204-fwd/dmesg-tail.txt:31:[Tue Apr 21 02:57:42 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5204-fwd/dmesg-tail.txt:32:[Tue Apr 21 02:57:42 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5204-fwd/dmesg-tail.txt:33:[Tue Apr 21 02:57:42 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5204-fwd/dmesg-tail.txt:34:[Tue Apr 21 02:57:42 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5204-fwd/dmesg-tail.txt:35:[Tue Apr 21 02:57:42 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5204-fwd/dmesg-tail.txt:36:[Tue Apr 21 02:57:42 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5204-fwd/dmesg-tail.txt:37:[Tue Apr 21 02:57:42 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5202-rev/dmesg-tail.txt:17:[Tue Apr 21 02:57:36 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5202-rev/dmesg-tail.txt:18:[Tue Apr 21 02:57:36 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5202-rev/dmesg-tail.txt:19:[Tue Apr 21 02:57:36 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5202-rev/dmesg-tail.txt:20:[Tue Apr 21 02:57:36 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5202-rev/dmesg-tail.txt:21:[Tue Apr 21 02:57:36 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5202-rev/dmesg-tail.txt:22:[Tue Apr 21 02:57:36 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5202-rev/dmesg-tail.txt:23:[Tue Apr 21 02:57:36 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5202-rev/dmesg-tail.txt:24:[Tue Apr 21 02:57:36 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5202-rev/dmesg-tail.txt:25:[Tue Apr 21 02:57:36 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5202-rev/dmesg-tail.txt:26:[Tue Apr 21 02:57:36 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5202-rev/dmesg-tail.txt:28:[Tue Apr 21 02:57:42 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5202-rev/dmesg-tail.txt:29:[Tue Apr 21 02:57:42 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5202-rev/dmesg-tail.txt:30:[Tue Apr 21 02:57:42 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5202-rev/dmesg-tail.txt:31:[Tue Apr 21 02:57:42 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5202-rev/dmesg-tail.txt:32:[Tue Apr 21 02:57:42 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5202-rev/dmesg-tail.txt:33:[Tue Apr 21 02:57:42 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5202-rev/dmesg-tail.txt:34:[Tue Apr 21 02:57:42 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5202-rev/dmesg-tail.txt:35:[Tue Apr 21 02:57:42 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5202-rev/dmesg-tail.txt:36:[Tue Apr 21 02:57:42 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5202-rev/dmesg-tail.txt:37:[Tue Apr 21 02:57:42 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./pkg/grpcapi/server_helpers.go:27:	link, err := netlink.LinkByName(name)
./pkg/grpcapi/server_show_interfaces_text.go:129:		addrs, _ := netlink.AddrList(link, netlink.FAMILY_ALL)
./pkg/grpcapi/server_show_interfaces_text.go:218:		addrs, _ := netlink.AddrList(link, netlink.FAMILY_ALL)
./docs/pr/1432-wg-s2a-datapath-socket-config/plan.md:423:- **TAI64N restart** (S1 §5.2): in-process only until S6; S2b runbook flushes
./docs/pr/1432-wg-s2a-datapath-socket-config/plan.md:424:  the peer on xpf restart.
./pkg/cluster/manager.go:156:	hbLocalAddr      string // last StartHeartbeat localAddr (for restart)
./pkg/cluster/manager.go:157:	hbPeerAddr       string // last StartHeartbeat peerAddr (for restart)
./pkg/cluster/manager.go:158:	hbVRFDevice      string // last StartHeartbeat vrfDevice (for restart)
./docs/pr/1381-dataplane-interface-split/plan.md:467:- Lifetime ordering: `Close`, `Teardown`, helper restart, and HA demotion must
./docs/pr/1381-dataplane-interface-split/plan.md:532:- Cold restart with stale pins present: startup must either ignore removed
./pkg/cluster/monitor_test.go:26:func (h *mockNlHandle) LinkByName(name string) (netlink.Link, error) {
./pkg/cluster/sync_conn.go:589:// heartbeat-socket restart window (Manager.RestartHeartbeat): while our UDP
./docs/pr/line-rate-investigation/step1-evidence/no-cos/p5204-fwd/dmesg-tail.txt:14:[Tue Apr 21 02:57:36 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/line-rate-investigation/step1-evidence/no-cos/p5204-fwd/dmesg-tail.txt:15:[Tue Apr 21 02:57:36 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/line-rate-investigation/step1-evidence/no-cos/p5204-fwd/dmesg-tail.txt:16:[Tue Apr 21 02:57:36 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/line-rate-investigation/step1-evidence/no-cos/p5204-fwd/dmesg-tail.txt:17:[Tue Apr 21 02:57:36 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/line-rate-investigation/step1-evidence/no-cos/p5204-fwd/dmesg-tail.txt:18:[Tue Apr 21 02:57:36 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/line-rate-investigation/step1-evidence/no-cos/p5204-fwd/dmesg-tail.txt:19:[Tue Apr 21 02:57:36 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/line-rate-investigation/step1-evidence/no-cos/p5204-fwd/dmesg-tail.txt:20:[Tue Apr 21 02:57:36 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/line-rate-investigation/step1-evidence/no-cos/p5204-fwd/dmesg-tail.txt:21:[Tue Apr 21 02:57:36 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/line-rate-investigation/step1-evidence/no-cos/p5204-fwd/dmesg-tail.txt:22:[Tue Apr 21 02:57:36 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/line-rate-investigation/step1-evidence/no-cos/p5204-fwd/dmesg-tail.txt:23:[Tue Apr 21 02:57:36 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/line-rate-investigation/step1-evidence/no-cos/p5204-fwd/dmesg-tail.txt:25:[Tue Apr 21 02:57:42 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/line-rate-investigation/step1-evidence/no-cos/p5204-fwd/dmesg-tail.txt:26:[Tue Apr 21 02:57:42 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/line-rate-investigation/step1-evidence/no-cos/p5204-fwd/dmesg-tail.txt:27:[Tue Apr 21 02:57:42 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/line-rate-investigation/step1-evidence/no-cos/p5204-fwd/dmesg-tail.txt:28:[Tue Apr 21 02:57:42 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/line-rate-investigation/step1-evidence/no-cos/p5204-fwd/dmesg-tail.txt:29:[Tue Apr 21 02:57:42 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/line-rate-investigation/step1-evidence/no-cos/p5204-fwd/dmesg-tail.txt:30:[Tue Apr 21 02:57:42 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/line-rate-investigation/step1-evidence/no-cos/p5204-fwd/dmesg-tail.txt:31:[Tue Apr 21 02:57:42 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/line-rate-investigation/step1-evidence/no-cos/p5204-fwd/dmesg-tail.txt:32:[Tue Apr 21 02:57:42 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/line-rate-investigation/step1-evidence/no-cos/p5204-fwd/dmesg-tail.txt:33:[Tue Apr 21 02:57:42 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/line-rate-investigation/step1-evidence/no-cos/p5204-fwd/dmesg-tail.txt:34:[Tue Apr 21 02:57:42 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/line-rate-investigation/step1-evidence/halt-1776832956/journalctl-xpfd.txt:127:Apr 22 04:41:31 xpf-userspace-fw0 xpfd[501375]: time=2026-04-22T04:41:31.342Z level=INFO msg="fabric IPVLAN: removed stale address" name=fab0 addr=fe80::1066:6a00:1fe:d955/64
./docs/pr/line-rate-investigation/step1-evidence/halt-1776832956/journalctl-xpfd.txt:186:Apr 22 04:41:32 xpf-userspace-fw0 xpfd[501375]: time=2026-04-22T04:41:32.018Z level=INFO msg="removed auto link-local from RETH member" iface=ge-0-0-1 addr=fe80::bf:72ff:fe16:200
./docs/pr/line-rate-investigation/step1-evidence/halt-1776832956/journalctl-xpfd.txt:192:Apr 22 04:41:32 xpf-userspace-fw0 xpfd[501375]: time=2026-04-22T04:41:32.024Z level=INFO msg="cluster: restarting heartbeat after VRF rebind" local=10.99.12.1 peer=10.99.12.2 vrf=vrf-mgmt
./pkg/cluster/hooks.go:80:// UDP heartbeats are silent during the restart (#1792).
./pkg/cluster/monitor.go:76:// nlLinkGetter abstracts netlink.Handle.LinkByName for testing.
./pkg/cluster/monitor.go:78:	LinkByName(name string) (netlink.Link, error)
./pkg/cluster/monitor.go:255:		link, err := nlh.LinkByName(linuxName)
./pkg/cluster/monitor.go:443:			link, err := nlh.LinkByName(linuxName)
./pkg/cluster/monitor.go:489:func (n *noopNlHandle) LinkByName(name string) (netlink.Link, error) {
./pkg/cluster/heartbeat_liveness_test.go:95:// restart protections: the notify hook fires before teardown, the
./pkg/cluster/heartbeat_liveness_test.go:96:// replacement receiver inherits the pre-restart lastSeen (so a peer that
./pkg/cluster/heartbeat_liveness_test.go:97:// dies during the restart window is still detected), and the receiver
./pkg/cluster/heartbeat_liveness_test.go:135:		t.Errorf("lastSeen seed = %d, want %d (pre-restart timestamp must carry over)", got, seed)
./pkg/cluster/heartbeat_liveness_test.go:138:		t.Errorf("restart notify hook called %d times, want >= 1", n)
./pkg/cluster/heartbeat_liveness_test.go:141:		t.Errorf("startedAt = %v not re-armed (before restart at %v)", newRecv.startedAt, beforeRestart)
./pkg/cluster/heartbeat_liveness_test.go:153:		t.Fatal("notify hook fired for a no-op restart")
./pkg/cluster/garp_test.go:263:		&net.IPNet{IP: net.ParseIP("fe80::1"), Mask: net.CIDRMask(64, 128)},
./pkg/cluster/garp_test.go:275:		&net.IPNet{IP: net.ParseIP("fe80::1234"), Mask: net.CIDRMask(64, 128)},
./pkg/cluster/garp_test.go:278:	want := net.ParseIP("fe80::1234")
./docs/pr/900-100e100m-harness/plan.md:306:   after-snapshot. Indicates daemon restart mid-rep.
./docs/pr/1760-collision-counter/plan.md:360:   a worker restart replacing its atomics?
./docs/pr/1621-cold-path-wire-prometheus/plan.md:83:  worker-local and gets discarded every restart.
./pkg/cluster/heartbeat_manager.go:72:// after a restart (even if old sockets linger from a killed process).
./pkg/cluster/heartbeat_manager.go:79:				// Allow immediate rebind after restart — the kernel may
./pkg/cluster/heartbeat_manager.go:112:// RestartHeartbeat stops and restarts the heartbeat with the same parameters.
./pkg/cluster/heartbeat_manager.go:118:// The restart window (worst case ~5s of bind retries) is longer than the
./pkg/cluster/heartbeat_manager.go:129://     mid-restart still fails over.
./pkg/cluster/heartbeat_manager.go:133://     sockets are down is still detected once the post-restart 30s startup
./pkg/cluster/heartbeat_manager.go:136://     no-op once peerEverSeen is set — and a peer death during the restart
./pkg/cluster/heartbeat_manager.go:153:	// (CLOCK_MONOTONIC nanos — comparable across an in-process restart).
./pkg/cluster/heartbeat_manager.go:159:	slog.Info("cluster: restarting heartbeat after VRF rebind",
./pkg/cluster/heartbeat_manager.go:172:			slog.Warn("cluster: heartbeat restart bind failed, retrying",
./pkg/cluster/heartbeat_manager.go:182:		// Seed the replacement receiver with the pre-restart timestamp
./pkg/cluster/heartbeat_manager.go:194:	slog.Error("cluster: heartbeat restart failed after retries")
./pkg/cluster/garp.go:192:			// Skip link-local 169.254.x.x addresses — use the VIP.
./pkg/cluster/garp.go:248:// neighbor cache, but falls back to link-local if no other IPv6 exists.
./pkg/cluster/garp.go:433:	// default route through this link-local address across failover.
./pkg/cluster/reth.go:68:			link, err := rc.nlHandle.LinkByName(member)
./pkg/cluster/reth.go:85:			link, err := rc.nlHandle.LinkByName(m.Members[0])
./pkg/cluster/reth.go:89:			addrs, err := rc.nlHandle.AddrList(link, netlink.FAMILY_ALL)
./pkg/cluster/reth.go:116:// StableRethLinkLocal returns a deterministic link-local IPv6 address shared
./pkg/cluster/reth.go:119:// Format: fe80::bf:72:CC:RR (clusterID, rgID — no nodeID component).
./pkg/cluster/reth.go:120:// This address sorts lower than EUI-64 link-locals derived from per-node
./pkg/cluster/reth.go:128:// link-local pattern (fe80::00:00:bf:72:...).
./pkg/cluster/reth.go:156:			link, err := rc.nlHandle.LinkByName(m.Members[0])
./docs/pr/1863-realization-gap/claude-smr-code-r1.md:43:   Arc → `worker_requested/granted_bytes` restart at 0 → the
./pkg/grpcapi/server_diag.go:754:				"You may now replace the binary and restart the service:\n" +
./docs/pr/1636-cold-connect-mitigation/plan.md:135:- After daemon restart / reboot, every distinct egress next-hop costs
./docs/pr/1636-cold-connect-mitigation/plan.md:144:plus a meaningful improvement to restart/failover impressions.
./docs/pr/1636-cold-connect-mitigation/plan.md:306:Applied at xpfd start via `systemctl reload-or-restart systemd-sysctl`
./docs/pr/1636-cold-connect-mitigation/plan.md:582:                 proactive neighbor warming is DISABLED until restart"
./pkg/grpcapi/server_cluster.go:46:				link, err := netlink.LinkByName(linuxName)
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5202-fwd/dmesg-tail.txt:15:[Tue Apr 21 16:54:08 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5202-fwd/dmesg-tail.txt:17:[Tue Apr 21 16:54:08 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5202-fwd/dmesg-tail.txt:19:[Tue Apr 21 17:27:49 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5202-fwd/dmesg-tail.txt:21:[Tue Apr 21 17:27:49 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./pkg/routing/routes.go:34:	LinkByName(name string) (netlink.Link, error)
./pkg/routing/routes.go:86:	link, err := rr.ops.LinkByName(devName)
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5201-rev/dmesg-tail.txt:17:[Tue Apr 21 02:57:36 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5201-rev/dmesg-tail.txt:18:[Tue Apr 21 02:57:36 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5201-rev/dmesg-tail.txt:19:[Tue Apr 21 02:57:36 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5201-rev/dmesg-tail.txt:20:[Tue Apr 21 02:57:36 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5201-rev/dmesg-tail.txt:21:[Tue Apr 21 02:57:36 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5201-rev/dmesg-tail.txt:22:[Tue Apr 21 02:57:36 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5201-rev/dmesg-tail.txt:23:[Tue Apr 21 02:57:36 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5201-rev/dmesg-tail.txt:24:[Tue Apr 21 02:57:36 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5201-rev/dmesg-tail.txt:25:[Tue Apr 21 02:57:36 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5201-rev/dmesg-tail.txt:26:[Tue Apr 21 02:57:36 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5201-rev/dmesg-tail.txt:28:[Tue Apr 21 02:57:42 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5201-rev/dmesg-tail.txt:29:[Tue Apr 21 02:57:42 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5201-rev/dmesg-tail.txt:30:[Tue Apr 21 02:57:42 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5201-rev/dmesg-tail.txt:31:[Tue Apr 21 02:57:42 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5201-rev/dmesg-tail.txt:32:[Tue Apr 21 02:57:42 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5201-rev/dmesg-tail.txt:33:[Tue Apr 21 02:57:42 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5201-rev/dmesg-tail.txt:34:[Tue Apr 21 02:57:42 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5201-rev/dmesg-tail.txt:35:[Tue Apr 21 02:57:42 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5201-rev/dmesg-tail.txt:36:[Tue Apr 21 02:57:42 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5201-rev/dmesg-tail.txt:37:[Tue Apr 21 02:57:42 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./pkg/routing/bond.go:28:	if err := b.clearLocked(); err != nil {
./pkg/routing/bond.go:44:		if existing, err := b.ops.LinkByName(bondName); err == nil {
./pkg/routing/bond.go:68:		bondLink, err := b.ops.LinkByName(bondName)
./pkg/routing/bond.go:75:			memberLink, err := b.ops.LinkByName(linuxName)
./pkg/routing/bond.go:110:	return b.clearLocked()
./pkg/routing/bond.go:113:// clearLocked is the lock-free body of Clear. Caller must hold mu.
./pkg/routing/bond.go:115:func (b *bondManager) clearLocked() error {
./pkg/routing/bond.go:117:		link, err := b.ops.LinkByName(name)
./docs/pr/913-mqfq-vtime/findings.md:26:- **#925**: panic supervision (parent-side helper restart in
./pkg/routing/vrf.go:23:	LinkByName(string) (netlink.Link, error)
./pkg/routing/vrf.go:29:	// over from a routing-instance rename across a daemon restart).
./pkg/routing/vrf.go:61:	if existing, err := v.ops.LinkByName(vrfName); err == nil {
./pkg/routing/vrf.go:103://     a daemon restart, where v.vrfs was empty after the restart):
./pkg/routing/vrf.go:122:// (LinkByName + LinkSetMaster) and touches no vrfManager field. That
./pkg/routing/vrf.go:129:	iface, err := v.ops.LinkByName(ifaceName)
./pkg/routing/vrf.go:133:	vrf, err := v.ops.LinkByName(vrfName)
./pkg/routing/vrf.go:151:// isLinkNotFound reports whether err is a "link not found" error
./pkg/routing/vrf.go:155:func isLinkNotFound(err error) bool {
./pkg/routing/vrf.go:174:// v.vrfs (handles the post-restart case). #847 orphan reap: any
./pkg/routing/vrf.go:180:// (LinkByName / LinkSetUp) fails, the VRF is still recorded in the
./pkg/routing/vrf.go:203:		link, kerErr := ops.LinkByName(vrfName)
./pkg/routing/vrf.go:206:			if !isLinkNotFound(kerErr) {
./pkg/routing/vrf.go:261:		link, err := ops.LinkByName(existing)
./pkg/routing/vrf.go:263:			if !isLinkNotFound(err) {
./pkg/routing/vrf.go:282:	// daemon restart, the old vrf-<oldname> persists in the kernel
./pkg/routing/vrf.go:342:	link, err := ops.LinkByName(vrfName)
./docs/pr/913-mqfq-vtime/plan.md:280:        //     daemon is restarted via config change or manual
./docs/pr/913-mqfq-vtime/plan.md:465:| R2 | + std::process::exit(1) on panic | xpfd runs xpf-userspace-dp as a CHILD HELPER (`pkg/dataplane/userspace/process.go:72`) without auto-restart on unexpected exit; helper death is detected only on next status-poll failure and recovered only on next `applyConfigLocked` (Codex R4). exit(1) just kills the helper without triggering recovery. |
./docs/pr/913-mqfq-vtime/plan.md:466:| R3 | + Gemini's stderr flush + Codex's documented map cleanup | Same R4 finding: exit(1) is not actually triggering systemd restart. |
./docs/pr/913-mqfq-vtime/plan.md:487:5. Next config change OR a manual daemon restart triggers
./docs/pr/913-mqfq-vtime/plan.md:500:  of unexpected exit; auto-restart with map cleanup.
./docs/pr/913-mqfq-vtime/plan.md:502:  supervision so panic → controlled exit → parent restart.
./docs/pr/913-mqfq-vtime/plan.md:606:| Bucket-mismatch invariant violation (believed-unreachable per §3.4 cleanup) | n/a (pop side captures snapshot) | `assert!(false)` — worker thread panics; all bindings served by that worker stall until daemon restart |
./docs/pr/913-mqfq-vtime/plan.md:826:  manual daemon restart. See §3.6 for the full scope-decision
./docs/pr/913-mqfq-vtime/plan.md:953:| (R7-1) Hard-panic worker wording: workers are plain spawned threads in `coordinator.rs:696`; no `catch_unwind`, no automatic respawn. "Contained TX outage" wording was misleading. | Codex R7 + Gemini MAJOR #1 (initially escalated, R8 reverted) | **R8 reverted**: graceful recovery (clear-stack + degrade) was found to compound corruption (Codex R8 #1, Gemini R8 #1). For an unreachable invariant, panic is the right primitive — it's loud and debuggable; silent fairness drift is not. Updated wording: workers panic, binding traffic stalls until restart, supervisor work is separate. | §3.3 |
./docs/pr/913-mqfq-vtime/plan.md:957:| (G-1) `assert!(false)` panic in worker = dataplane outage on 1/N flows. No supervisor mechanism. | Gemini MAJOR #1 (initial), reversed in R8 | R8 finding: graceful recovery introduced silent fairness drift worse than the panic. Reverted to `assert!(false)`. Documented production failure mode honestly: panic, binding stall, daemon restart. Supervisor is future work. The trade chosen: loud-and-debuggable > silent-and-corrupt. | §3.3 |
./docs/pr/913-mqfq-vtime/plan.md:971:| (R8-1) Graceful recovery clears stack → remaining rollback items take aggregate `vtime -= item_len` despite their pops using `max(vtime, served_finish)` → `queue_vtime` can REGRESS below pre-batch frontier → future flows anchor too early. | Codex R8 + Gemini R8 (converged) | **Reverted to `assert!(false)` hard-panic.** For an unreachable invariant violation, loud-and-debuggable > silent-and-corrupt. Documented production failure mode honestly: worker thread panics, binding traffic stalls, daemon restart needed; supervisor work is separate. | §3.3 |
./docs/pr/913-mqfq-vtime/plan.md:1042:not containment. Operators see the panic, decide to restart;
./docs/pr/913-mqfq-vtime/plan.md:1097:| (R14-1) "Commands accumulate harmlessly" is FALSE — VecDeque has no capacity bound; producers use plain `push_back`; dead worker queue grows until restart or OOM. | Codex R14 #1 + Gemini R14 | §3.6.2 rewritten: "**accumulate without bound** until the daemon restarts" → **accepted unbounded-memory-growth risk in #913**, deferred to #925. R15 refinement: there is no hard upper bound; only an operational expectation (typical control-plane rate ≪ 1 MB/s; minute-scale operator response → ~tens of MB). Pathological producer loops or delayed restart leave growth unbounded. | §3.6.2 |
./docs/pr/913-mqfq-vtime/plan.md:1100:| (R14-4) Residual dispatch-bypass mentions at §3.3:278, §8:966/:988, §21 contradict detection-only. | Codex R14 #4 | All four sites rewritten to describe detection-only flow without bypass language. §3.3 comment block: "producers continue pushing to dead worker's queue; commands accumulate unbounded until daemon restart". §8 trade-off: "No dispatch-bypass / containment in #913 (deferred to #925)". §21 row: detection-only, no containment claim. | §3.3, §8, §21 |
./docs/pr/913-mqfq-vtime/plan.md:1112:| (R15-1) "Bounding worst-case OOM growth to tens of MB" overclaims a hard bound; pathological producer loops or delayed restart are unbounded. | Codex R15 #1 | §3.6.2 rewritten: "**no hard upper bound** on accumulated memory; only an operational expectation". Tens-of-MB figure presented as a typical operator-response scenario, not a worst-case bound. §23 R14-1 row updated similarly. | §3.6.2, §23 |
./pkg/routing/routing_test.go:34:func (f *fakeVRFOps) LinkByName(name string) (netlink.Link, error) {
./pkg/routing/routing_test.go:39:	// Return the real netlink not-found error so isLinkNotFound()
./pkg/routing/routing_test.go:185:			// Post-restart scenario: VRF survived the daemon exit and
./pkg/routing/routing_test.go:188:			// no LinkAdd, no LinkDel. LinkByName fires once for the
./pkg/routing/routing_test.go:200:			// Post-restart with table mismatch — xpfd is authoritative
./pkg/routing/routing_test.go:237:				t.Errorf("LinkByName count = %d, want %d", ops.byNameHits, tc.wantByNameHits)
./pkg/routing/routing_test.go:448:// not-found error from LinkByName during delete (tracked-but-not-
./pkg/routing/routing_test.go:456:		t.Fatal("expected error from transient LinkByName failure, got nil")
./pkg/routing/routing_test.go:473:// (we created it earlier), and LinkByName returns a transient
./pkg/routing/routing_test.go:484:		t.Fatal("expected error from transient LinkByName failure, got nil")
./pkg/routing/routing_test.go:499:// transientLookupOps fails LinkByName for a specific name with a
./pkg/routing/routing_test.go:506:func (t *transientLookupOps) LinkByName(name string) (netlink.Link, error) {
./pkg/routing/routing_test.go:1121:// in `desired` and weren't in `tracked`. Covers the cross-restart
./pkg/routing/routing_test.go:1122:// rename leak: m.vrfs is empty after restart, so the existing
./docs/pr/1930-inc0-kernel-hold/agy-review-r1.md:84:  - **#1917 upgrade**: The in-place upgrade mechanism (`xpfd upgrade` in `postinst`) manages daemon staging/restart and does not trigger or require OS kernel package upgrades. It is completely safe.
./docs/pr/1930-inc0-kernel-hold/agy-review-r1.md:88:## 5. needrestart Bake-Write Removal Confirmation
./docs/pr/1930-inc0-kernel-hold/agy-review-r1.md:91:- The proposed inline write of `/etc/needrestart/conf.d/99-xpf.conf` has been successfully **DROPPED** from `bake.py`.
./docs/pr/1930-inc0-kernel-hold/agy-review-r1.md:92:- Instead, the needrestart override snippet is properly shipped in the package payload via `debian/rules`:
./docs/pr/1930-inc0-kernel-hold/agy-review-r1.md:94:  install -d debian/xpf/etc/needrestart/conf.d
./docs/pr/1930-inc0-kernel-hold/agy-review-r1.md:95:  install -m 0644 debian/xpf.needrestart \
./docs/pr/1930-inc0-kernel-hold/agy-review-r1.md:96:                  debian/xpf/etc/needrestart/conf.d/xpf.conf
./docs/pr/1930-inc0-kernel-hold/agy-review-r1.md:98:- This uses the clean append form (`$nrconf{override_rc}{qr(^xpfd\.service$)} = 0;` inside [debian/xpf.needrestart](file:///home/ps/git/bpfrx/.claude/worktrees/1930-eng/debian/xpf.needrestart)) which preserves needrestart's defaults instead of doing a destructive whole-hash overwrite at bake time.
./docs/pr/1930-inc0-kernel-hold/agy-review-r1.md:113:The kernel hold implementation is shell-safe, robustly verifies both successful and failed holds, covers all installed kernel meta-packages and concrete version packages, and successfully blocks unattended upgrades from moving the kernel verifier floor. The dropped needrestart inline bake-write has been verified to be fully removed and correctly packaged in the Debian package payload instead.
./pkg/routing/README.md:95:  not own at the last apply (restart adoption; wireguard→gre same-name
./pkg/routing/README.md:105:  deleted only if recorded in `appliedAddrs` (a configured fe80 we
./pkg/routing/README.md:106:  applied), never the kernel's autoconf fe80; failed LL deletes stay
./pkg/routing/README.md:123:  the link admin UP). A change to the tunnel SOURCE restarts the runner
./pkg/routing/README.md:164:  `LinkByName`/`LinkSet*` error leaves `Up` unchanged so the transition
./docs/pr/1930-inc0-kernel-hold/reviewer-ids.md:5:| r1 | Codex | foreground codex exec (read-only) | REQUEST-CHANGES (needrestart hash-clobber HIGH; hold false-pass MED) |
./docs/pr/1930-inc0-kernel-hold/reviewer-ids.md:6:| r1-fix | (author) | commit 65ac48cdb | dropped bake needrestart write; per-package hold verify |
./docs/pr/835-slice-d-rss/codex-plan-review.md:40:Finding: The plan regresses behavior that already exists and still leaves "disable" undefined. It says the goroutine reads `rssEnabled/allowed` at startup and that "config reloads require a daemon restart," but current code already re-applies RSS on every config commit and restores default RSS immediately when disabled. The plan never says whether runtime disable stops the rebalance goroutine, prevents future writes, or restores the default table.
./docs/pr/835-slice-d-rss/codex-plan-review.md:42:Evidence: `docs/pr/835-slice-d-rss/plan.md:216-227` claims startup-only state plus restart-on-reload. Current code contradicts that: `pkg/daemon/linksetup.go:117-133`, `pkg/daemon/daemon.go:2351-2394`, and `pkg/daemon/rss_indirection.go:127-147,191-223` show commit-time reapply plus immediate `ethtool -X <iface> default` restore.
./docs/pr/835-slice-d-rss/codex-plan-review.md:44:Remediation: Reuse the existing reconcile semantics. Config changes must either restart the loop with new state or feed it updated state; runtime disable must immediately restore defaults and suppress further rebalance writes.
./docs/pr/835-slice-d-rss/codex-plan-review.md:85:Finding: The document overclaims and under-specifies in the same places. It asserts restart-only config behavior that current code already disproves, claims no lock contention while ignoring the existing reconcile caller, claims 3-4 step convergence with no proof, and uses "conntrack" as a magic word for NIC steering behavior. It also leans on the current D3 implementation without giving the file:line citations needed to show the intended integration points cleanly.
./docs/pr/835-slice-d-rss/codex-plan-review.md:106:**Finding 5 — runtime disable / restart requirement: NOT RESOLVED**. `§4.5b` says `Config reload → both paths reconcile without requiring a daemon restart` and that the kill switch makes the loop `a no-op until re-enabled`, but `§4.6` still says `config reloads require a daemon restart`, and `§8 R4` repeats `until daemon restart.` The loop pseudocode in `§4.5` also never shows the promised epoch or `rssEnabled` check. The exact suppression latency is therefore ambiguous; the best you can infer from the prose is `next tick`, but the document does not pin it.
./docs/pr/835-slice-d-rss/codex-plan-review.md:116:**Finding 10 — plan quality: NOT RESOLVED**. `§8a` claims `overclaims tightened throughout`, but the document still contains direct contradictions. The first `§4.4` says `No fallback in this PR`, the second `§4.4` says `Fallback... individual slot writes`; `§4.5b` withdraws restart-only reload behavior, while `§4.6` and `§8 R4` reassert it; `§4.5d` says `§6.1 pre-flight adds a 10-sample baseline read`, but `§6.1` does not. This is still a merged draft, not a clean R2 plan.
./docs/pr/835-slice-d-rss/codex-plan-review.md:134:- `R1-F5`: `PARTIALLY RESOLVED` — `§4.6` resolves runtime disable (`rssEnabled` atomic, `≤ 1 s` suppression latency, no restart required), but config-reload interface-set updates remain ambiguous because the goroutine is started `exactly once` in `§3.2`, iterates `allowed` in `§4.5`, and `§4.6` only mentions epoch bumps, not allowlist replacement.
./docs/pr/835-slice-d-rss/codex-plan-review.md:259:2. `§3.2`, `§4.5`, `§5.6`, `§5.7` | The plan still does not pin the live-reload invariants for `allowed` and `workers` with tests. `§3.2` / `daemon.go` promise reload-driven allowlist and worker-count changes are picked up without restart (plan lines 105-109, 122-127), and `§4.5` says the loop reads live state on every tick (lines 359-365). But `§5.6` only tests runtime disable (`TestLoop_SkipsOnRSSDisabled`, lines 639-641), and `§5.7` only has a static `workers > ringCount` test (lines 659-660). There is no test that an allowlist removal/add or worker-count change on config reload is observed on the next tick. A bug that still live-loads `rssEnabled` but snapshots `allowed` or `workers` at goroutine start could pass the current suite. | Fix: add explicit reload tests for allowlist change and worker-count change being observed without restarting the loop.
./docs/pr/1930-inc0-kernel-hold/claude-smr-review-r1.md:9:u-u presence, the .deb's own needrestart snippet).
./docs/pr/1930-inc0-kernel-hold/claude-smr-review-r1.md:25:- **needrestart:** the bake-written file is GONE (replaced by an explanatory
./docs/pr/1930-inc0-kernel-hold/claude-smr-review-r1.md:26:  comment); the package-owned append-form snippet (`debian/xpf.needrestart` →
./docs/pr/1930-inc0-kernel-hold/claude-smr-review-r1.md:27:  `/etc/needrestart/conf.d/xpf.conf`, `debian/rules:73-75`) is the single source.
./docs/pr/1930-inc0-kernel-hold/claude-smr-review-r1.md:57:the needrestart concern is correctly delegated to the existing package snippet.
./docs/pr/835-slice-d-rss/plan.md:127:    needing to be restarted. Resolves R3 new-issue #4.
./docs/pr/835-slice-d-rss/plan.md:234:  Counter resets happen on driver restart / link down-up; very
./docs/pr/835-slice-d-rss/plan.md:534:disable is observed. Kill-switch + daemon-restart is NO LONGER
./docs/pr/835-slice-d-rss/plan.md:537:the R2 draft's "config reloads require a daemon restart" claim.
./docs/pr/835-slice-d-rss/plan.md:727:     systemctl restart xpfd; sleep 3; \
./docs/pr/835-slice-d-rss/plan.md:832:  restarts? **Draft:** No — seed to equal each run. Persistence
./docs/pr/835-slice-d-rss/plan.md:847:| R1-5 kill switch / reload regression | HIGH | §4.6 (runtime disable via atomic; no restart needed) |
./pkg/routing/tunnel.go:22:	LinkByName(name string) (netlink.Link, error)
./pkg/routing/tunnel.go:32:	AddrDel(netlink.Link, *netlink.Addr) error
./pkg/routing/tunnel.go:33:	AddrList(netlink.Link, int) ([]netlink.Addr, error)
./pkg/routing/tunnel.go:90:	// unchanged runner alive across applies instead of restarting it
./pkg/routing/tunnel.go:111:// against the stored default 3 would restart the runner every apply).
./pkg/routing/tunnel.go:113:// change must restart the runner so the probe binds the new endpoint.
./pkg/routing/tunnel.go:178:	// ensured (successful adds + present-and-wanted + link-local whose
./pkg/routing/tunnel.go:180:	// configured fe80 we applied is removable; the kernel's autoconf
./pkg/routing/tunnel.go:181:	// fe80 is never touched.
./pkg/routing/tunnel.go:193:// ensureReconcileStateLocked lazily initializes the reconcile maps so
./pkg/routing/tunnel.go:196:func (t *tunnelManager) ensureReconcileStateLocked() {
./pkg/routing/tunnel.go:251:// instead of being restarted every apply.
./pkg/routing/tunnel.go:255:	t.ensureReconcileStateLocked()
./pkg/routing/tunnel.go:282:		if link, err := t.ops.LinkByName(name); err == nil {
./pkg/routing/tunnel.go:310:		// apply (daemon restart, wireguard→gre same-name flip, foreign
./pkg/routing/tunnel.go:354:	if existing, lookupErr := t.ops.LinkByName(tc.Name); lookupErr == nil {
./pkg/routing/tunnel.go:384:			existing, lkErr := t.ops.LinkByName(tc.Name)
./pkg/routing/tunnel.go:566:	e, lookupErr := t.ops.LinkByName(tc.Name)
./pkg/routing/tunnel.go:571:	case isLinkNotFound(lookupErr):
./pkg/routing/tunnel.go:604:				// recreated — the restarted runner captures the just-bumped
./pkg/routing/tunnel.go:672:	restartKA := tc.Keepalive > 0 && (!hasRunner || created || !runner.matches(tc))
./pkg/routing/tunnel.go:674:	if tc.Keepalive > 0 && hasRunner && !restartKA {
./pkg/routing/tunnel.go:683:		if restartKA {
./pkg/routing/tunnel.go:705:	t.appliedAddrs[tc.Name] = t.reconcileLinkAddrsLocked(
./pkg/routing/tunnel.go:711:// reconcileLinkAddrsLocked symmetrically reconciles a link's addresses
./pkg/routing/tunnel.go:713:// present-but-unconfigured — EXCEPT link-local addresses, which are
./pkg/routing/tunnel.go:715:// gate). The kernel's autoconf fe80 must never be deleted, while a
./pkg/routing/tunnel.go:716:// CONFIGURED fe80 removed from config must not leak forever (#1884 r1
./pkg/routing/tunnel.go:718:// first apply for a link this manager has not tracked yet — restart
./pkg/routing/tunnel.go:719:// adoption) means no link-local deletion at all.
./pkg/routing/tunnel.go:722:// link-local addresses whose stale-delete FAILED (kept tracked so the
./pkg/routing/tunnel.go:724:func (t *tunnelManager) reconcileLinkAddrsLocked(link netlink.Link, name string, addrs []string, applied map[string]bool, kind string) map[string]bool {
./pkg/routing/tunnel.go:737:	if list, listErr := t.ops.AddrList(link, netlink.FAMILY_ALL); listErr == nil {
./pkg/routing/tunnel.go:752:				// Kernel-managed or foreign link-local: never delete.
./pkg/routing/tunnel.go:755:			if delErr := t.ops.AddrDel(link, &a); delErr != nil {
./pkg/routing/tunnel.go:838:	vrf, err := t.ops.LinkByName("vrf-" + claim)
./pkg/routing/tunnel.go:840:		if isLinkNotFound(err) {
./pkg/routing/tunnel.go:879:	vrf, err := t.ops.LinkByName("vrf-" + tc.RIListMember)
./pkg/routing/tunnel.go:927:// in t.tunnels: clearLocked must not delete it on reload (AGY Hazard B
./pkg/routing/tunnel.go:931:// tunnel REMOVED from the config is not torn down by clearLocked and
./pkg/routing/tunnel.go:932:// leaks until `ip link del` or daemon restart. S2a single-tunnel scope
./pkg/routing/tunnel.go:940:	link, err := t.ops.LinkByName(tc.Name)
./pkg/routing/tunnel.go:1011:	// the same configured-vs-autoconf link-local split as the GRE/IPIP
./pkg/routing/tunnel.go:1012:	// branch: a CONFIGURED fe80 later removed from config is deleted
./pkg/routing/tunnel.go:1013:	// (this manager applied it), while the kernel's autoconf fe80 — and
./pkg/routing/tunnel.go:1014:	// any fe80 already present before this daemon's first apply
./pkg/routing/tunnel.go:1015:	// (restart adoption pass, applied == nil) — is never touched.
./pkg/routing/tunnel.go:1020:	t.appliedAddrs[tc.Name] = t.reconcileLinkAddrsLocked(
./pkg/routing/tunnel.go:1152://  3. LinkByName; on error do nothing (Up unchanged → retried next tick).
./pkg/routing/tunnel.go:1222:	link, err := t.ops.LinkByName(tunnelName)
./pkg/routing/tunnel.go:1357:	return t.clearLocked()
./pkg/routing/tunnel.go:1360:// clearLocked is the lock-free body of Clear. Caller must hold mu.
./pkg/routing/tunnel.go:1368:func (t *tunnelManager) clearLocked() error {
./pkg/routing/tunnel.go:1378:		link, err := t.ops.LinkByName(name)
./pkg/routing/tunnel.go:1394:	// clearLocked drains every keepalive runner first
./pkg/routing/tunnel.go:1414:		link, err := t.ops.LinkByName(name)
./pkg/routing/tunnel.go:1437:		addrs, err := t.ops.AddrList(link, netlink.FAMILY_ALL)
./pkg/routing/tunnel_reconcile_test.go:113:// --- §9 test 2: restart adoption + MTU ownership ---------------------
./pkg/routing/tunnel_reconcile_test.go:120:	// Fresh manager (ownedNames empty) = restart adoption; tc.MTU == 0
./pkg/routing/tunnel_reconcile_test.go:274:// --- §9 test 5: address reconcile + link-local rules ------------------
./pkg/routing/tunnel_reconcile_test.go:300:	// Apply with a CONFIGURED fe80 — recorded in appliedAddrs.
./pkg/routing/tunnel_reconcile_test.go:301:	if err := tm.Apply([]*config.TunnelConfig{anchorTC("gr-0-0-0", "fe80::8/64")}); err != nil {
./pkg/routing/tunnel_reconcile_test.go:304:	// Simulate the kernel's autoconf link-local appearing too.
./pkg/routing/tunnel_reconcile_test.go:305:	kernelLL, _ := netlink.ParseAddr("fe80::5054:ff:fe12:3456/64")
./pkg/routing/tunnel_reconcile_test.go:308:	// Remove the configured fe80: it must be deleted (it is ours), the
./pkg/routing/tunnel_reconcile_test.go:309:	// kernel's autoconf fe80 must survive (r1 Codex F2 split).
./pkg/routing/tunnel_reconcile_test.go:313:	if ops.hasAddr("gr-0-0-0", "fe80::8/64") {
./pkg/routing/tunnel_reconcile_test.go:314:		t.Fatal("configured fe80 leaked after removal from config")
./pkg/routing/tunnel_reconcile_test.go:316:	if !ops.hasAddr("gr-0-0-0", "fe80::5054:ff:fe12:3456/64") {
./pkg/routing/tunnel_reconcile_test.go:317:		t.Fatal("kernel autoconf fe80 was deleted")
./pkg/routing/tunnel_reconcile_test.go:324:	if err := tm.Apply([]*config.TunnelConfig{anchorTC("gr-0-0-0", "fe80::8/64")}); err != nil {
./pkg/routing/tunnel_reconcile_test.go:328:	ops.addrDelFail["gr-0-0-0|fe80::8/64"] = errors.New("EBUSY")
./pkg/routing/tunnel_reconcile_test.go:332:	if !ops.hasAddr("gr-0-0-0", "fe80::8/64") {
./pkg/routing/tunnel_reconcile_test.go:337:	delete(ops.addrDelFail, "gr-0-0-0|fe80::8/64")
./pkg/routing/tunnel_reconcile_test.go:341:	if ops.hasAddr("gr-0-0-0", "fe80::8/64") {
./pkg/routing/tunnel_reconcile_test.go:342:		t.Fatal("failed-delete fe80 not retried (dropped from appliedAddrs)")
./pkg/routing/tunnel_reconcile_test.go:352:// A CONFIGURED fe80 on the persistent wgN TUN, later removed from
./pkg/routing/tunnel_reconcile_test.go:354:// nil applied-set sentinel) — while the kernel's autoconf fe80 on the
./pkg/routing/tunnel_reconcile_test.go:359:	if err := tm.Apply([]*config.TunnelConfig{wgTC("10.77.0.1/24", "fe80::8/64")}); err != nil {
./pkg/routing/tunnel_reconcile_test.go:362:	if !ops.hasAddr("wg0", "fe80::8/64") {
./pkg/routing/tunnel_reconcile_test.go:363:		t.Fatal("configured fe80 not applied")
./pkg/routing/tunnel_reconcile_test.go:365:	// Simulate the kernel's autoconf link-local appearing too.
./pkg/routing/tunnel_reconcile_test.go:366:	kernelLL, _ := netlink.ParseAddr("fe80::5054:ff:fe12:3456/64")
./pkg/routing/tunnel_reconcile_test.go:372:	if ops.hasAddr("wg0", "fe80::8/64") {
./pkg/routing/tunnel_reconcile_test.go:373:		t.Fatal("configured fe80 leaked after removal from config (#1905)")
./pkg/routing/tunnel_reconcile_test.go:375:	if !ops.hasAddr("wg0", "fe80::5054:ff:fe12:3456/64") {
./pkg/routing/tunnel_reconcile_test.go:376:		t.Fatal("kernel autoconf fe80 was deleted")
./pkg/routing/tunnel_reconcile_test.go:387:// Adoption pass: an fe80 already on the device before this manager's
./pkg/routing/tunnel_reconcile_test.go:388:// first apply (daemon restart over a persistent wgN) is untracked and
./pkg/routing/tunnel_reconcile_test.go:393:	preLL, _ := netlink.ParseAddr("fe80::dead/64")
./pkg/routing/tunnel_reconcile_test.go:401:		if !ops.hasAddr("wg0", "fe80::dead/64") {
./pkg/routing/tunnel_reconcile_test.go:402:			t.Fatalf("pre-existing fe80 deleted on apply %d", i+1)
./pkg/routing/tunnel_reconcile_test.go:407:// Failed fe80 stale-delete on the WG branch stays tracked and is
./pkg/routing/tunnel_reconcile_test.go:413:	if err := tm.Apply([]*config.TunnelConfig{wgTC("fe80::8/64")}); err != nil {
./pkg/routing/tunnel_reconcile_test.go:417:	ops.addrDelFail["wg0|fe80::8/64"] = errors.New("EBUSY")
./pkg/routing/tunnel_reconcile_test.go:421:	if !ops.hasAddr("wg0", "fe80::8/64") {
./pkg/routing/tunnel_reconcile_test.go:425:	delete(ops.addrDelFail, "wg0|fe80::8/64")
./pkg/routing/tunnel_reconcile_test.go:429:	if ops.hasAddr("wg0", "fe80::8/64") {
./pkg/routing/tunnel_reconcile_test.go:430:		t.Fatal("failed-delete fe80 not retried (dropped from appliedAddrs)")
./pkg/routing/tunnel_reconcile_test.go:684:// kernelShapedGre mimics what LinkByName returns for a GRE device the
./pkg/routing/tunnel_reconcile_test.go:779:	tc.KeepaliveRetry = 0 // normalizes to 3 — must not restart per apply
./pkg/routing/tunnel_reconcile_test.go:794:		t.Fatal("unchanged keepalive was restarted (r1 Codex F5 normalization)")
./pkg/routing/tunnel_reconcile_test.go:797:	// Changed interval ⇒ restart.
./pkg/routing/tunnel_reconcile_test.go:804:		t.Fatal("changed keepalive interval did not restart the runner")
./pkg/routing/tunnel_reconcile_test.go:874:// --- restart adoption end-to-end --------------------------------------
./pkg/routing/tunnel_reconcile_test.go:885:	// "Daemon restart": a brand-new manager over the same kernel state
./pkg/routing/tunnel_reconcile_test.go:892:		t.Fatalf("restart adoption recreated the anchor: %v", ops.delNames)
./pkg/routing/tunnel_reconcile_test.go:895:		t.Fatal("restart adoption replaced the link object")
./docs/pr/1881-gre-frozen-state/agy-code-r2.md:92:test afxdp::coordinator::tests::gre1881_attachment_change_restarts_thread ... ok
./pkg/routing/probe_pin.go:135:	LinkByName(name string) (netlink.Link, error)
./pkg/routing/probe_pin.go:189:		link, err := p.ops.LinkByName(pin.Interface)
./docs/pr/1893-configstore-durability/plan.md:94:systemd restart semantics (`RestartSec=1`) unchanged.
./docs/pr/1893-configstore-durability/plan.md:224:  `.configdb` aside + make `/etc/xpf` read-only, restart xpfd, prove
./docs/pr/1229-cross-worker-vtime/phase6-fair-lease.md:24:  accounting transitions, lease replacement, worker restart.
./docs/pr/1866-wg-teardown/plan.md:92:no timers) — tunnel dead until an xpfd restart. The #1736 harness works
./docs/pr/1866-wg-teardown/plan.md:93:around it (fresh keys per run + port-release check + xpfd-restart
./docs/pr/1866-wg-teardown/plan.md:102:tunnel that can become permanently dead until daemon restart), not a perf
./docs/pr/1866-wg-teardown/plan.md:176:  mod.rs:262), or a daemon restart** (Codex 4 / SMR F2 precision) — none
./docs/pr/1866-wg-teardown/plan.md:412:stop→join→clear ordering (clearing removes tombstones too — restart from
./docs/pr/1866-wg-teardown/plan.md:505:6e. **Apply-time rename restarts the thread (D5 regression,
./docs/pr/1866-wg-teardown/plan.md:528:restart should become UNNECESSARY (taint counter stays 0). Standalone VM
./docs/pr/1881-gre-frozen-state/claude-smr-code-r1.md:77:tunnel commit restarts every GRE local-origin thread (fatal-read exit
./docs/pr/1229-cross-worker-vtime/phase5-cluster-smoke.md:3:After daemon restart following Phase 4 deploy, the symmetric Toeplitz key
./docs/pr/1229-cross-worker-vtime/phase5-cluster-smoke.md:5:reset by xpfd restart since `taskset -pc` is per-PID). Re-applied both
./docs/pr/1686-maps-domain-split/plan.md:36:  (post-write hitless-restart stale reconcile, avoiding clear-then-repopulate
./docs/pr/1686-maps-domain-split/plan.md:46:flow config, HA/fabric, hitless-restart stale cleanup, map stats) behind one
./docs/pr/1686-maps-domain-split/plan.md:221:   *all* domains. Is a single hitless-restart file cohesive (one responsibility:
./pkg/routing/iface_reuse_test.go:23:	// byNameErrAfter, when > 0, makes LinkByName return an error once it
./pkg/routing/iface_reuse_test.go:29:	// hiddenUntil[name] = k makes LinkByName report not-found for the
./pkg/routing/iface_reuse_test.go:40:	// addrDelFail["name|ipnet"] makes AddrDel fail for that address on
./pkg/routing/iface_reuse_test.go:41:	// that link (#1884 link-local retention tests).
./pkg/routing/iface_reuse_test.go:48:	// AddrAdd/AddrDel/AddrList for the #1884 reconcile tests.
./pkg/routing/iface_reuse_test.go:73:func (f *fakeLinkOps) LinkByName(name string) (netlink.Link, error) {
./pkg/routing/iface_reuse_test.go:143:func (f *fakeLinkOps) AddrDel(l netlink.Link, a *netlink.Addr) error {
./pkg/routing/iface_reuse_test.go:160:func (f *fakeLinkOps) AddrList(l netlink.Link, family int) ([]netlink.Addr, error) {
./pkg/routing/iface_reuse_test.go:243:	// Make any SECOND LinkByName for this name fail — under the old
./pkg/routing/iface_reuse_test.go:257:		t.Errorf("expected exactly 1 LinkByName for %s on the already-exists path, got %d "+
./docs/pr/1881-gre-frozen-state/agy-code-r1.md:77:- `gre1881_attachment_change_restarts_thread` & `gre1881_mode_flip_to_wireguard_prunes_gre_entry` verify attachment drift and mode flip restarts.
./pkg/routing/monitor.go:43:			link, err := mm.ops.LinkByName(linuxName)
./docs/pr/1540-rest-api-split/reviewer-ids.md:4:long-running sessions or harness restarts can resume by fetching
./pkg/routing/probe_pin_test.go:91:func (f *fakeProbePinOps) LinkByName(name string) (netlink.Link, error) {
./pkg/routing/probe_pin_test.go:109:			"v6": {Name: "v6", Target: "2001:db8::1", NextHop: "fe80::1", DestinationInterface: "ge-0/0/3.0"},
./pkg/routing/probe_pin_test.go:221:	// Band/table cleanup on restart (#1827 §4.2.4 named test): stale
./docs/pr/1666-ready-gate/plan.md:250:rather than deferred. `Dead` is set-only until daemon restart (#925), so
./pkg/routing/tunnel_keepalive_test.go:50:// of them (for lock-scope / drain tests), and can fail LinkByName.
./pkg/routing/tunnel_keepalive_test.go:71:func (o *kaOps) LinkByName(name string) (netlink.Link, error) {
./pkg/routing/tunnel_keepalive_test.go:91:func (o *kaOps) AddrDel(netlink.Link, *netlink.Addr) error      { return nil }
./pkg/routing/tunnel_keepalive_test.go:92:func (o *kaOps) AddrList(netlink.Link, int) ([]netlink.Addr, error) {
./pkg/routing/tunnel_keepalive_test.go:270:// --- §9 LinkByName error on transition: Up not latched, retried ---
./pkg/routing/tunnel_keepalive_test.go:271:func TestKeepaliveLinkByNameErrorNoLatch(t *testing.T) {
./pkg/routing/tunnel_keepalive_test.go:279:	// LinkByName keeps failing → no down committed, Up stays true.
./pkg/routing/tunnel_keepalive_test.go:281:		t.Fatal("Up must not latch false on LinkByName error")
./pkg/routing/tunnel_keepalive_test.go:364:	tm.ensureReconcileStateLocked()
./pkg/routing/tunnel_keepalive_test.go:406:	// matches(): a source-only change must restart the runner.
./pkg/routing/tunnel_keepalive_test.go:423:// --- Finding 1 (Codex PR #1947 r1 HIGH): a TRANSIENT LinkByName error
./pkg/routing/tunnel_keepalive_test.go:435:	tm.ensureReconcileStateLocked()
./pkg/routing/tunnel_keepalive_test.go:474:	tm.ensureReconcileStateLocked()
./pkg/routing/tunnel_keepalive_test.go:527:// — the runner is restarted against the surviving link. ---
./pkg/routing/tunnel_keepalive_test.go:536:	tm.ensureReconcileStateLocked()
./pkg/routing/tunnel_keepalive_test.go:538:	// Seed a live keepalive runner. LinkByName returns a *netlink.Dummy,
./pkg/routing/tunnel_keepalive_test.go:561:		t.Fatal("LinkDel failure on recreate must restart the keepalive, not leave it absent")
./pkg/routing/tunnel_keepalive_test.go:563:	// Drain the restarted runner so the goroutine does not leak into other
./pkg/routing/xfrm.go:27:	if err := x.clearLocked(); err != nil {
./pkg/routing/xfrm.go:44:		// lookup: calling LinkByName a second time and ignoring its
./pkg/routing/xfrm.go:48:		if link, err := x.ops.LinkByName(ifName); err == nil {
./pkg/routing/xfrm.go:81:		link, err := x.ops.LinkByName(ifName)
./pkg/routing/xfrm.go:104:	return x.clearLocked()
./pkg/routing/xfrm.go:107:// clearLocked is the lock-free body of Clear. Caller must hold mu.
./pkg/routing/xfrm.go:109:func (x *xfrmManager) clearLocked() error {
./pkg/routing/xfrm.go:111:		link, err := x.ops.LinkByName(name)
./pkg/upgrade/cutover.go:101:					r.logf("upgrade: WARN failed to restart unit after stale-stop recovery: %v", startErr)
./docs/pr/816-step1-rerun/methodology-findings-review.md:99:reason from `control-status-pre.json` (daemon restart timing,
./docs/pr/1875-cluster-ownership/plan.md:23:were replaced and xpfd restarted at ~5-10 minute cadence. Consequences
./docs/pr/1875-cluster-ownership/plan.md:32:- Every foreign restart flipped VRRP mastership and wiped CoS.
./docs/pr/1875-cluster-ownership/plan.md:208:Mutating verbs are `deploy`, `start`, `stop`, `restart`, `create`,
./docs/pr/1875-cluster-ownership/plan.md:236:(start/stop/restart/create/destroy/init) re-exec the same way without
./pkg/upgrade/rolling.go:158:	//    restarted xpfd, so the local gRPC socket is unavailable for the
./pkg/upgrade/rolling.go:193:// restarts after a cut); the deadline is the backstop that still bounds it.
./docs/pr/925-worker-supervisor/plan.md:77:bindings, drain its command queue, trigger HA, or restart the
./docs/pr/925-worker-supervisor/plan.md:79:`cli show chassis forwarding`, then must manually restart the daemon
./docs/pr/925-worker-supervisor/plan.md:244:restarted. This PR does NOT fix that. Phase 1 is "detection only":
./docs/pr/925-worker-supervisor/plan.md:246:- Operator restarts the daemon to recover.
./docs/pr/925-worker-supervisor/plan.md:279:shard becomes a black hole. **Operator action**: restart the
./docs/pr/925-worker-supervisor/plan.md:447:   into `worker_loop` (or use a feature-flagged build), restart the
./docs/pr/1896-journal/reviewer-ids.md:38:- systemctl restart over the rotated journal: active, history intact
./docs/pr/1896-journal/plan.md:200:`show system commit` correct + fast; rollback 1 works; restart boots
./docs/pr/816-step1-rerun/path-decision.md:135:- Both paths together avoid the "throw away the result, restart" outcome
./docs/pr/844-vrf-idempotent/plan.md:63:// prior xpfd instance without cleanup — are visible via LinkByName
./docs/pr/844-vrf-idempotent/plan.md:106:`LinkByName` netlink calls, not just the slice updates. Dropping
./docs/pr/844-vrf-idempotent/plan.md:271:care about but which the daemon did not create (`LinkByName`
./docs/pr/844-vrf-idempotent/plan.md:283:### Cross-restart VRF leaks (pre-existing, not fixed here)
./docs/pr/844-vrf-idempotent/plan.md:285:After a daemon restart `m.vrfs` is empty. If a routing instance
./docs/pr/844-vrf-idempotent/plan.md:294:`applyConfig` after restart creates the new VRF without touching
./docs/pr/844-vrf-idempotent/plan.md:331:   LinkDel, LinkByName calls. Keep the tests hermetic — no real
./docs/pr/844-vrf-idempotent/plan.md:356:- **Cross-restart VRF adoption.** Enumerate `vrf-*` devices on
./pkg/upgrade/rolling_test.go:30:	// local socket refuses connections while xpfd restarts. After that the
./pkg/upgrade/rolling_test.go:145:// wait survives the gRPC-startup gap. The cut restarts xpfd, so the local
./docs/pr/816-step1-rerun/evidence/no-cos/p5203-fwd/dmesg-tail.txt:2:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/no-cos/p5203-fwd/dmesg-tail.txt:3:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/no-cos/p5203-fwd/dmesg-tail.txt:4:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/no-cos/p5203-fwd/dmesg-tail.txt:5:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/no-cos/p5203-fwd/dmesg-tail.txt:6:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/no-cos/p5203-fwd/dmesg-tail.txt:7:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/no-cos/p5203-fwd/dmesg-tail.txt:8:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/no-cos/p5203-fwd/dmesg-tail.txt:9:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/no-cos/p5203-fwd/dmesg-tail.txt:10:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/no-cos/p5203-fwd/dmesg-tail.txt:11:[Tue Apr 21 16:49:21 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/no-cos/p5203-fwd/dmesg-tail.txt:13:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/816-step1-rerun/evidence/no-cos/p5203-fwd/dmesg-tail.txt:14:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/no-cos/p5203-fwd/dmesg-tail.txt:15:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/no-cos/p5203-fwd/dmesg-tail.txt:16:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/no-cos/p5203-fwd/dmesg-tail.txt:17:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/no-cos/p5203-fwd/dmesg-tail.txt:18:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/816-step1-rerun/evidence/no-cos/p5203-fwd/dmesg-tail.txt:19:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/no-cos/p5203-fwd/dmesg-tail.txt:20:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/no-cos/p5203-fwd/dmesg-tail.txt:21:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/816-step1-rerun/evidence/no-cos/p5203-fwd/dmesg-tail.txt:22:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/no-cos/p5203-fwd/dmesg-tail.txt:38:[Tue Apr 21 16:54:08 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/no-cos/p5203-fwd/dmesg-tail.txt:40:[Tue Apr 21 16:54:08 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/no-cos/p5203-fwd/dmesg-tail.txt:42:[Tue Apr 21 17:27:49 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/no-cos/p5203-fwd/dmesg-tail.txt:44:[Tue Apr 21 17:27:49 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/1904-routing-followups/reviewer-ids.md:27:fe80 reconciles away while foreign + kernel stable-privacy fe80
./docs/pr/1521-maps-sync-decouple/plan.md:408:   stop xpfd on both nodes, clear any pinned maps, restart, verify
./docs/pr/1521-maps-sync-decouple/plan.md:472:   as "deploy + restart + verify HA peering converges" which the
./docs/pr/1904-routing-followups/plan.md:59:## Defect 2 (#1905) — WG tun leaks configured link-local addresses removed from config
./docs/pr/1904-routing-followups/plan.md:61:`applyWireguardTunLocked` calls the shared `reconcileLinkAddrsLocked`
./docs/pr/1904-routing-followups/plan.md:62:with the `nil` applied-set sentinel, which skips ALL link-local
./docs/pr/1904-routing-followups/plan.md:63:deletion ("the kernel manages fe80"). A CONFIGURED fe80 on a wgN
./docs/pr/1904-routing-followups/plan.md:75:t.appliedAddrs[tc.Name] = t.reconcileLinkAddrsLocked(
./docs/pr/1904-routing-followups/plan.md:79:The shared helper already implements the configured-vs-autoconf
./docs/pr/1904-routing-followups/plan.md:83:- First apply after daemon restart (adoption): `appliedAddrs[wg0]` is
./docs/pr/1904-routing-followups/plan.md:84:  nil → no link-local deletion that pass; configured fe80s are
./docs/pr/1904-routing-followups/plan.md:86:  A pre-existing/foreign fe80 is never recorded, never deleted.
./docs/pr/1904-routing-followups/plan.md:97:`Apply` calls `ensureReconcileStateLocked` before the per-tunnel loop,
./docs/pr/1904-routing-followups/plan.md:102:- Configured fe80 removed from config reconciles away; kernel
./docs/pr/1904-routing-followups/plan.md:103:  autoconf fe80 on the same wgN survives; the non-LL address stays.
./docs/pr/1904-routing-followups/plan.md:104:- Adoption pass: fe80 present on the device before the first apply is
./docs/pr/1904-routing-followups/plan.md:106:- Failed fe80 delete is retained in the applied set and retried on
./docs/pr/1904-routing-followups/plan.md:115:  vrf-<ri>` in `ip link`; (b) configure an fe80 on a wg tun, commit,
./docs/pr/1904-routing-followups/plan.md:116:  remove, commit → address gone; kernel-autonomous fe80 untouched.
./docs/pr/1904-routing-followups/plan.md:122:`reconcileLinkAddrsLocked`) — all updated in place. No standalone
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5203-fwd/dmesg-tail.txt:17:[Tue Apr 21 02:57:36 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5203-fwd/dmesg-tail.txt:18:[Tue Apr 21 02:57:36 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5203-fwd/dmesg-tail.txt:19:[Tue Apr 21 02:57:36 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5203-fwd/dmesg-tail.txt:20:[Tue Apr 21 02:57:36 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5203-fwd/dmesg-tail.txt:21:[Tue Apr 21 02:57:36 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5203-fwd/dmesg-tail.txt:22:[Tue Apr 21 02:57:36 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5203-fwd/dmesg-tail.txt:23:[Tue Apr 21 02:57:36 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5203-fwd/dmesg-tail.txt:24:[Tue Apr 21 02:57:36 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5203-fwd/dmesg-tail.txt:25:[Tue Apr 21 02:57:36 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5203-fwd/dmesg-tail.txt:26:[Tue Apr 21 02:57:36 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5203-fwd/dmesg-tail.txt:28:[Tue Apr 21 02:57:42 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5203-fwd/dmesg-tail.txt:29:[Tue Apr 21 02:57:42 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5203-fwd/dmesg-tail.txt:30:[Tue Apr 21 02:57:42 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5203-fwd/dmesg-tail.txt:31:[Tue Apr 21 02:57:42 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5203-fwd/dmesg-tail.txt:32:[Tue Apr 21 02:57:42 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5203-fwd/dmesg-tail.txt:33:[Tue Apr 21 02:57:42 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5203-fwd/dmesg-tail.txt:34:[Tue Apr 21 02:57:42 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5203-fwd/dmesg-tail.txt:35:[Tue Apr 21 02:57:42 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5203-fwd/dmesg-tail.txt:36:[Tue Apr 21 02:57:42 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5203-fwd/dmesg-tail.txt:37:[Tue Apr 21 02:57:42 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/949-sharded-locks/plan.md:31:thread and leave the binding dead until daemon restart.
./docs/pr/925-phase2/plan.md:150:                "restart (Phase 1 has no automatic respawn).",
./docs/pr/925-phase2/plan.md:178:in principle — only daemon restart clears it today, but a future
./docs/pr/925-phase2/plan.md:189:daemon restart; Phase 2 (this PR) adds Prometheus exposure but does
./docs/pr/925-phase2/plan.md:274:  restart clears it. The gauge will therefore read `1` until
./docs/pr/925-phase2/plan.md:275:  process restart even after the panic-causing condition is
./docs/pr/1713-resolved-dns-renderer/plan.md:90:  `restartResolved()`.
./docs/pr/1713-resolved-dns-renderer/plan.md:176:`restartResolved()` behavior exactly as today:
./docs/pr/1713-resolved-dns-renderer/plan.md:193:			restartResolved()
./docs/pr/1713-resolved-dns-renderer/plan.md:210:	restartResolved()
./docs/pr/1713-resolved-dns-renderer/plan.md:227:- `restartResolved()`, drop-in path constant, file mode 0644, dir 0755,
./docs/pr/1713-resolved-dns-renderer/plan.md:245:  `restartResolved()` only fires on actual change or removal.
./docs/pr/1713-resolved-dns-renderer/plan.md:246:- **No new restart churn.** Combining domains changes the rendered bytes
./docs/pr/1769-neighbor-resolver/plan.md:125:"25 clean runs then stuck, no restart, self-heals minutes later"
./docs/pr/1769-neighbor-resolver/plan.md:134:  stuck state self-recovered with NO daemon restart when the kernel
./docs/pr/1769-neighbor-resolver/plan.md:151:ge-0-0-2.80` (forces re-resolution + RTM events), `systemctl restart
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5203-rev/dmesg-tail.txt:17:[Tue Apr 21 02:57:36 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5203-rev/dmesg-tail.txt:18:[Tue Apr 21 02:57:36 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5203-rev/dmesg-tail.txt:19:[Tue Apr 21 02:57:36 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5203-rev/dmesg-tail.txt:20:[Tue Apr 21 02:57:36 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5203-rev/dmesg-tail.txt:21:[Tue Apr 21 02:57:36 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5203-rev/dmesg-tail.txt:22:[Tue Apr 21 02:57:36 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5203-rev/dmesg-tail.txt:23:[Tue Apr 21 02:57:36 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5203-rev/dmesg-tail.txt:24:[Tue Apr 21 02:57:36 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5203-rev/dmesg-tail.txt:25:[Tue Apr 21 02:57:36 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5203-rev/dmesg-tail.txt:26:[Tue Apr 21 02:57:36 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5203-rev/dmesg-tail.txt:28:[Tue Apr 21 02:57:42 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5203-rev/dmesg-tail.txt:29:[Tue Apr 21 02:57:42 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5203-rev/dmesg-tail.txt:30:[Tue Apr 21 02:57:42 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5203-rev/dmesg-tail.txt:31:[Tue Apr 21 02:57:42 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5203-rev/dmesg-tail.txt:32:[Tue Apr 21 02:57:42 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5203-rev/dmesg-tail.txt:33:[Tue Apr 21 02:57:42 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5203-rev/dmesg-tail.txt:34:[Tue Apr 21 02:57:42 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5203-rev/dmesg-tail.txt:35:[Tue Apr 21 02:57:42 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5203-rev/dmesg-tail.txt:36:[Tue Apr 21 02:57:42 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5203-rev/dmesg-tail.txt:37:[Tue Apr 21 02:57:42 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/963-frame-editor-redux/design.md:527:Per Codex round-2 review (task-monpt1na cancelled at 57m, restarted as a957d243caeee5471):
./docs/pr/1879-pathc/deploy-delta-reviewer-ids.md:113:  rolling-failover for dataplane restart, control-plane-only hot-restart,
./docs/pr/1879-pathc/deploy-delta-reviewer-ids.md:250:2. Tier-3: `incus restart fw1` restarts the SECONDARY (ha-pair.conf:
./docs/pr/1197-neighbor-snapshot/codex-review-v1.md:20:5. IPv6 is in scope whether the plan wants it or not. Current code loops over v4 and v6 and snapshot preinstall sets both as `NUD_REACHABLE`. `SnapshotNeighbors()` drops state/router/link-local detail. A v4-only fix leaves the same stale-injection class for NDP.
./docs/pr/1918-probe-real-liveness/reviewer-ids.md:9:| Codex | `019ed45c-9636-7f23-99e3-66c82177728f` (agent `a2de27069d925925a`) | CHANGES-REQUESTED | Two HIGH: (1) transient LinkByName treated as absent → drains live runner + EEXIST; (2) WriteTo ENOBUFS misclassified as Dead. Both fixed in `22e4c6b72`. |
./docs/pr/1918-probe-real-liveness/reviewer-ids.md:31:## Round 4 (final rev @ 81088afa0 — Copilot r3 fix: restart KA on LinkDel failure)
./docs/pr/1918-probe-real-liveness/reviewer-ids.md:35:| Codex | `bghcy9ovw` (thread 019ed47d-f600...) | MERGE-READY — restart correct, no F7 regression, gen captured, no deadlock, test correct, no new bugs |
./docs/pr/1918-probe-real-liveness/reviewer-ids.md:36:| AGY | covered by r2 (production delta is the LinkDel-failure restart only; F7 ordering preserved) | clean |
./docs/pr/1918-probe-real-liveness/reviewer-ids.md:37:| Claude SMR | in-conversation | clean — drain still precedes the recreate ATTEMPT; restart only on the not-recreated survivor path |
./docs/pr/wireguard-clean/plan.md:37:13. **Replay-window wipes on control-plane restart.**
./docs/pr/wireguard-clean/plan.md:229:### Replay-state across restart
./docs/pr/wireguard-clean/plan.md:232:restarts, in-flight sessions are torn down by the engine init path,
./docs/pr/wireguard-clean/plan.md:235:control socket so we survive restart without rekey.
./docs/pr/wireguard-clean/plan.md:494:- Persistent replay window across control-plane restart.
./docs/pr/1197-neighbor-snapshot/plan.md:19:restart.
./docs/pr/1197-neighbor-snapshot/plan.md:239:// via current LinkByName excludes the old ifindex, so an
./docs/pr/bug-batch-866-867-916-925/design.md:215:operator must restart the daemon.
./docs/pr/bug-batch-866-867-916-925/design.md:305:permanent loss until daemon restart. Either could justify a
./docs/pr/1197-neighbor-snapshot/codex-review-v5.md:18:3. `MonitoredInterfaceLinkIndexes(cfg)` prevents source-code drift, but not runtime ifindex drift. If a link/VLAN disappears, recomputing by current `LinkByName` can exclude the old ifindex, so a `RTM_DELNEIGH` for the old ifindex may be ignored until the 60s safety regen. Add one of: cached previous monitored ifindexes, link subscription-triggered regen, or snapshot-key fallback for delete events.
./docs/pr/1526-dpdk-reject/plan.md:381:userspace` or remove the line, then restart the daemon and let
./docs/pr/1526-dpdk-reject/plan.md:496:    config containing `dataplane-type dpdk`, restart daemon,
./docs/pr/1736-wg-interop/agy-code-r2.md:102:- **Analysis**: Any fallback to recovery restarts (leaked control thread or wedged apply) increments `TAINTS`. At the end of the `all` runner, the script issues a warning and exits with code `2` if `TAINTS` > 0. This prevents recovered runs from falsely passing merge verification.
./docs/pr/816-step1-rerun/evidence/no-cos/p5202-fwd/dmesg-tail.txt:2:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/no-cos/p5202-fwd/dmesg-tail.txt:3:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/no-cos/p5202-fwd/dmesg-tail.txt:4:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/no-cos/p5202-fwd/dmesg-tail.txt:5:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/no-cos/p5202-fwd/dmesg-tail.txt:6:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/no-cos/p5202-fwd/dmesg-tail.txt:7:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/no-cos/p5202-fwd/dmesg-tail.txt:8:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/no-cos/p5202-fwd/dmesg-tail.txt:9:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/no-cos/p5202-fwd/dmesg-tail.txt:10:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/no-cos/p5202-fwd/dmesg-tail.txt:11:[Tue Apr 21 16:49:21 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/no-cos/p5202-fwd/dmesg-tail.txt:13:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/816-step1-rerun/evidence/no-cos/p5202-fwd/dmesg-tail.txt:14:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/no-cos/p5202-fwd/dmesg-tail.txt:15:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/no-cos/p5202-fwd/dmesg-tail.txt:16:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/no-cos/p5202-fwd/dmesg-tail.txt:17:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/no-cos/p5202-fwd/dmesg-tail.txt:18:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/816-step1-rerun/evidence/no-cos/p5202-fwd/dmesg-tail.txt:19:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/no-cos/p5202-fwd/dmesg-tail.txt:20:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/no-cos/p5202-fwd/dmesg-tail.txt:21:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/816-step1-rerun/evidence/no-cos/p5202-fwd/dmesg-tail.txt:22:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/no-cos/p5202-fwd/dmesg-tail.txt:38:[Tue Apr 21 16:54:08 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/no-cos/p5202-fwd/dmesg-tail.txt:40:[Tue Apr 21 16:54:08 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/no-cos/p5202-fwd/dmesg-tail.txt:42:[Tue Apr 21 17:27:49 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/no-cos/p5202-fwd/dmesg-tail.txt:44:[Tue Apr 21 17:27:49 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/1895-probe-pin/plan.md:100:`rpmMu`), the pin install is retried with no probe restart (probe
./docs/pr/1895-probe-pin/plan.md:131:resumes normally — no probe restart needed.
./docs/pr/1895-probe-pin/plan.md:174:  restarts on unrelated commits; the retry path deliberately does NOT
./docs/pr/1736-wg-interop/plan.md:68:| TAI64N monotonicity across restart | **in-process only** (disk persistence = S6) | issue body restart-runbook requirement |
./docs/pr/1736-wg-interop/plan.md:113:leaks the TUN until `ip link del`/restart (S2a known limitation, AGY M1) —
./docs/pr/1736-wg-interop/plan.md:191:handshake + ping, skip >MTU/rekey/restart phases.
./docs/pr/1736-wg-interop/plan.md:215:   generation/conversion (hex↔base64), the **restart runbook** (flush peer WG
./docs/pr/1736-wg-interop/plan.md:216:   state after any xpfd restart — TAI64N high-water is in-process only),
./docs/pr/1736-wg-interop/plan.md:279:  control-thread restart (`coordinator/mod.rs:508`), NOT an in-place role
./docs/pr/1736-wg-interop/plan.md:280:  flip (Codex r1 F4). Flush peer WG state (restart-runbook procedure) and
./docs/pr/1736-wg-interop/plan.md:318:- **P6 restart recovery (restart runbook)**: restore the initiator config
./docs/pr/1736-wg-interop/plan.md:320:  monotonicity can bite); `systemctl restart xpfd` on fw0; apply the
./docs/pr/1736-wg-interop/plan.md:321:  issue's restart runbook on the peer (`ip link del wgref; ip link add
./docs/pr/1736-wg-interop/plan.md:324:  negative control FIRST: restart xpfd WITHOUT flushing the peer and
./docs/pr/1736-wg-interop/plan.md:327:  the post-restart timestamps are naturally HIGHER and the peer will
./docs/pr/1736-wg-interop/plan.md:464:   engine + thread restart (identity tuple), asserted as a fresh handshake.
./docs/pr/1736-wg-interop/plan.md:519:    restart-without-flush normally succeeds; observe-and-record, flush
./docs/pr/1736-wg-interop/agy-code-r1.md:108:2. **Infrastructure Failures**: The actual execution runs of the test harness on the shared loss cluster (recorded in `/tmp/wg-final/summary.txt` and `/tmp/wg-ev/summary.txt`) failed to complete a full run due to HA cluster issues (e.g. node0 not regaining primary status after recovery restarts). 
./docs/pr/1635-cold-path-hist-redesign/claude-smr-plan-r1.md:171:lifetime; restarting the daemon may remap." This matches `feedback_smoke_v4_and_v6`
./docs/pr/867-ack-ip-sweep/plan.md:153:overstated daemon-restart risk. Normal eBPF restarts preserve
./docs/pr/867-ack-ip-sweep/plan.md:159:restart, the FIRST ACK of each established flow misses CT, hits
./docs/pr/867-ack-ip-sweep/plan.md:162:and bypass the hook entirely. Maximum extra increments per restart
./docs/pr/867-ack-ip-sweep/plan.md:163:= N (number of distinct established flows at restart time), not
./docs/pr/867-ack-ip-sweep/plan.md:446:- **Daemon restart / session loss (corrected v2)**: normal
./docs/pr/867-ack-ip-sweep/plan.md:447:  eBPF restarts preserve pinned `sessions` / `sessions_v6` /
./docs/pr/867-ack-ip-sweep/plan.md:451:  even when sessions ARE lost: after restart, the FIRST ACK of
./docs/pr/867-ack-ip-sweep/plan.md:456:  extra increments per restart = N (number of distinct established
./docs/pr/867-ack-ip-sweep/plan.md:457:  flows at restart), not unbounded. (Per Gemini Pro 3 round-1.)
./docs/pr/867-ack-ip-sweep/plan.md:479:| Behavioral regression | **MED** | New drop path on conntrack-miss. False-positive possible on daemon restart / asymmetric routing — both already-known properties of the existing screen-stage sweep, just now reachable for ACK shape. |
./docs/pr/867-ack-ip-sweep/plan.md:600:2. **Daemon-restart false positive**: post-restart, established
./docs/pr/1635-cold-path-hist-redesign/agy-plan-r1.md:36:  * If a long-running daemon sees 128 distinct pairs *over its lifetime*, it will hit the overflow threshold and permanently freeze/drop metrics for all new zone-pairs, requiring a manual `systemctl restart xpfd`. This is a severe operational hazard.
./docs/pr/803-tunables/evidence/repro-matched-5run.sh:43:# applyStep0Tunables() — no daemon restart needed. A restart would
./docs/pr/803-tunables/evidence/repro-matched-5run.sh:75:    # exists with different ownership (seen after daemon restarts).
./docs/pr/797-d3/go-review.md:65:restart cycles are frequent (`make test-deploy`) so this matters.
./docs/pr/797-d3/codex-review.md:23:`Daemon.Run()` reads `cfg.System.UserspaceDataplane.Workers` once and passes it into `enumerateAndRenameInterfaces()` once (`pkg/daemon/daemon.go:453-467`). Separately, the userspace helper treats `workers` as part of the binding-plan key and restarts itself when that plan changes (`pkg/dataplane/userspace/maps_sync.go:1173-1179`, `pkg/dataplane/userspace/process.go:285-295`). If workers change from 4 to 6, the helper can restart for six workers while a stale `[1 1 1 1 0 0]` table still starves queues 4 and 5.
./docs/pr/797-d3/codex-review.md:45:The code applies weights on startup (`pkg/daemon/rss_indirection.go:161-178`) but skips for `workers == 1` and `workers >= queues` (`pkg/daemon/rss_indirection.go:106-109`, `193-205`), and the only call site is the startup path (`pkg/daemon/linksetup.go:100-104`). A concrete failure mode is: start once with 4 workers on a 6-queue mlx5 and apply `[1 1 1 1 0 0]`; then restart with 1 worker or 6 workers and the code now skips, leaving the old restricted table in place. That contradicts the file’s own “single worker — keep default RSS” rationale (`pkg/daemon/rss_indirection.go:92-96`).
./docs/pr/797-d3/codex-review.md:113:But daemon interactive mode still bypasses that path. In interactive mode the daemon creates a local CLI (`pkg/daemon/daemon.go:1076-1079`); CLI commits call `c.applyToDataplane(compiled)` directly (`pkg/cli/cli_config.go:170-239`), and `applyToDataplane()` compiles the dataplane but never calls `d.applyConfig()` or `reapplyRSSIndirection()` (`pkg/cli/cli.go:1407-1434`; `reapplyRSSIndirection` not found under `pkg/cli`). Worker-count changes are still real dataplane changes on that path because the userspace helper restart key includes `Workers` (`pkg/dataplane/userspace/process.go:24-35`, `957-964`) and the binding-plan key includes `workers=%d` (`pkg/dataplane/userspace/maps_sync.go:1173-1204`). So a live `set system dataplane workers N` committed from the in-process CLI still skips the D3 reapply.
./docs/pr/797-d3/validation.md:50:a daemon restart.
./docs/pr/816-step1-rerun/evidence/no-cos/p5201-fwd/dmesg-tail.txt:2:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/no-cos/p5201-fwd/dmesg-tail.txt:3:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/no-cos/p5201-fwd/dmesg-tail.txt:4:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/no-cos/p5201-fwd/dmesg-tail.txt:5:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/no-cos/p5201-fwd/dmesg-tail.txt:6:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/no-cos/p5201-fwd/dmesg-tail.txt:7:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/no-cos/p5201-fwd/dmesg-tail.txt:8:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/no-cos/p5201-fwd/dmesg-tail.txt:9:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/no-cos/p5201-fwd/dmesg-tail.txt:10:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/no-cos/p5201-fwd/dmesg-tail.txt:11:[Tue Apr 21 16:49:21 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/no-cos/p5201-fwd/dmesg-tail.txt:13:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/816-step1-rerun/evidence/no-cos/p5201-fwd/dmesg-tail.txt:14:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/no-cos/p5201-fwd/dmesg-tail.txt:15:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/no-cos/p5201-fwd/dmesg-tail.txt:16:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/no-cos/p5201-fwd/dmesg-tail.txt:17:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/no-cos/p5201-fwd/dmesg-tail.txt:18:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/816-step1-rerun/evidence/no-cos/p5201-fwd/dmesg-tail.txt:19:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/no-cos/p5201-fwd/dmesg-tail.txt:20:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/no-cos/p5201-fwd/dmesg-tail.txt:21:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/816-step1-rerun/evidence/no-cos/p5201-fwd/dmesg-tail.txt:22:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/no-cos/p5201-fwd/dmesg-tail.txt:38:[Tue Apr 21 16:54:08 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/no-cos/p5201-fwd/dmesg-tail.txt:40:[Tue Apr 21 16:54:08 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/no-cos/p5201-fwd/dmesg-tail.txt:42:[Tue Apr 21 17:27:49 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/no-cos/p5201-fwd/dmesg-tail.txt:44:[Tue Apr 21 17:27:49 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/827-p3-captures/plan.md:145:  between snap[<s-1>] and snap[<s>]")`. Catches daemon restarts,
./docs/pr/827-p3-captures/plan.md:375:    decreases (daemon restart signature); raises.
./docs/pr/827-p3-captures/plan.md:542:- **R4 — non-monotonic counters (daemon restart during a run).**
./docs/pr/1373-retire-ebpf-dataplane/plan-1378-policy-schedulers.md:105:  it is republished after config load, daemon restart, and scheduler state
./docs/pr/1373-retire-ebpf-dataplane/plan-1375-three-color-policers.md:40:- Decide whether #1373 needs HA/process-restart token continuity. Current
./docs/pr/1373-retire-ebpf-dataplane/plan-1375-three-color-policers.md:98:  for the name-derived policer ID; failover or process restart may restart
./docs/pr/1373-retire-ebpf-dataplane/plan-1375-three-color-policers.md:118:  failover/restart continuity remains out of scope until userspace owns a
./docs/pr/1373-retire-ebpf-dataplane/plan-1380-userspace-buffers.md:66:  commands so failover and helper restart do not report contradictory totals.
./docs/pr/1373-retire-ebpf-dataplane/README.md:25:| #1377 persistent SNAT pool address selection | [plan-1377-snat-pools.md](plan-1377-snat-pools.md) | Closed | Userspace-v1 selector, unusable-pool fail-closed runtime, helper-local persistent-NAT lease reuse, per-pool allocator sharing, and allocator counters landed. #1448, #1449, and #1450 are closed documented contracts for helper restart reset, HA admission gating, and backend-specific selector behavior. |
./docs/pr/1373-retire-ebpf-dataplane/README.md:219:`BPF_F_NO_PREALLOC` contract so a legacy-to-shim restart can reuse existing
./docs/pr/1373-retire-ebpf-dataplane/README.md:226:incompatible pin path named in the error, restart `xpfd`, and verify the map was
./docs/pr/1922-pr2-bootstrap/reviewer-ids.md:97:  bootstrap, takeover, Item-1b rollback, and restart — never brought down.
./docs/pr/1922-pr2-bootstrap/reviewer-ids.md:122:required for a post-first-commit-rollback box to stay bootstrap across restart:
./docs/pr/1922-pr2-bootstrap/reviewer-ids.md:127:   first. Test: `post-rollback-restart-empty-compiled`.
./docs/pr/1373-retire-ebpf-dataplane/final-validation/README.md:129:ha-test-restart-connectivity.log
./docs/pr/1373-retire-ebpf-dataplane/smoke-gates.md:13:cluster for destructive failover, crash, and restart testing.
./docs/pr/1373-retire-ebpf-dataplane/smoke-gates.md:416:These gates are destructive. They reboot, force-stop, fail over, or restart
./docs/pr/1373-retire-ebpf-dataplane/smoke-gates.md:430:BPFRX_CLUSTER_ENV="$BPFRX_CLUSTER_ENV" make test-restart-connectivity \
./docs/pr/1373-retire-ebpf-dataplane/smoke-gates.md:431:  2>&1 | tee "$ARTIFACT_ROOT/ha-test-restart-connectivity.log"
./docs/pr/1373-retire-ebpf-dataplane/final-validation/manifest.schema.json:136:              "ha-test-restart-connectivity",
./docs/pr/1373-retire-ebpf-dataplane/plan-1376-port-mirroring.md:50:- Runtime sampling counters are local per binding and reset on worker restart or
./docs/pr/1373-retire-ebpf-dataplane/plan.md:24:| #1377 | Userspace-v1 address-persistent SNAT selection, fail-closed pool runtime, helper-local per-pool `persistent-nat`, live-port exhaustion observability, and allocator counters are implemented. #1448, #1449, and #1450 are closed as documented helper-restart, HA-gate, and cross-backend selector contracts, not active #1373/#1451 blockers. |
./docs/pr/1373-retire-ebpf-dataplane/plan.md:98:3. restart/re-apply `xpfd` so the manager selects the eBPF backend and legacy
./docs/pr/1373-retire-ebpf-dataplane/plan-1377-snat-pools.md:37:  same binding-plan entries and the allocator key is unchanged. Helper restart,
./docs/pr/1373-retire-ebpf-dataplane/plan-1377-snat-pools.md:199:- helper restart, helper cold start, and binding-plan changes that force helper
./docs/pr/1373-retire-ebpf-dataplane/plan-1377-snat-pools.md:242:`exhaustions_total`; after helper restart or replan these values start again
./docs/pr/1373-retire-ebpf-dataplane/plan-1377-snat-pools.md:399:- Helper-restart lease replay beyond the documented reset boundary.
./docs/pr/1373-retire-ebpf-dataplane/plan-1377-snat-pools.md:409:- Do not claim helper-restart or HA persistence for per-pool `persistent-nat`.
./docs/pr/803-tunables/codex-review.md:159:(cpu-governor, netdev_budget) are idempotent across daemon restarts,
./docs/pr/816-step1-rerun/evidence/no-cos/p5204-fwd/dmesg-tail.txt:2:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/no-cos/p5204-fwd/dmesg-tail.txt:3:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/no-cos/p5204-fwd/dmesg-tail.txt:4:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/no-cos/p5204-fwd/dmesg-tail.txt:5:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/no-cos/p5204-fwd/dmesg-tail.txt:6:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/no-cos/p5204-fwd/dmesg-tail.txt:7:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/no-cos/p5204-fwd/dmesg-tail.txt:8:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/no-cos/p5204-fwd/dmesg-tail.txt:9:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/no-cos/p5204-fwd/dmesg-tail.txt:10:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/no-cos/p5204-fwd/dmesg-tail.txt:11:[Tue Apr 21 16:49:21 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/no-cos/p5204-fwd/dmesg-tail.txt:13:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/816-step1-rerun/evidence/no-cos/p5204-fwd/dmesg-tail.txt:14:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/no-cos/p5204-fwd/dmesg-tail.txt:15:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/no-cos/p5204-fwd/dmesg-tail.txt:16:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/no-cos/p5204-fwd/dmesg-tail.txt:17:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/no-cos/p5204-fwd/dmesg-tail.txt:18:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/816-step1-rerun/evidence/no-cos/p5204-fwd/dmesg-tail.txt:19:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/no-cos/p5204-fwd/dmesg-tail.txt:20:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/no-cos/p5204-fwd/dmesg-tail.txt:21:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/816-step1-rerun/evidence/no-cos/p5204-fwd/dmesg-tail.txt:22:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/no-cos/p5204-fwd/dmesg-tail.txt:38:[Tue Apr 21 16:54:08 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/no-cos/p5204-fwd/dmesg-tail.txt:40:[Tue Apr 21 16:54:08 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/no-cos/p5204-fwd/dmesg-tail.txt:42:[Tue Apr 21 17:27:49 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/no-cos/p5204-fwd/dmesg-tail.txt:44:[Tue Apr 21 17:27:49 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5201-fwd/dmesg-tail.txt:15:[Tue Apr 21 16:54:08 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5201-fwd/dmesg-tail.txt:17:[Tue Apr 21 16:54:08 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5201-fwd/dmesg-tail.txt:19:[Tue Apr 21 17:27:49 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5201-fwd/dmesg-tail.txt:21:[Tue Apr 21 17:27:49 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/with-cos/p5202-rev/dmesg-tail.txt:5:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/with-cos/p5202-rev/dmesg-tail.txt:6:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/with-cos/p5202-rev/dmesg-tail.txt:7:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/with-cos/p5202-rev/dmesg-tail.txt:8:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/with-cos/p5202-rev/dmesg-tail.txt:9:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/with-cos/p5202-rev/dmesg-tail.txt:10:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/with-cos/p5202-rev/dmesg-tail.txt:11:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/with-cos/p5202-rev/dmesg-tail.txt:12:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/with-cos/p5202-rev/dmesg-tail.txt:13:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/with-cos/p5202-rev/dmesg-tail.txt:14:[Tue Apr 21 16:49:21 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/with-cos/p5202-rev/dmesg-tail.txt:16:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/816-step1-rerun/evidence/with-cos/p5202-rev/dmesg-tail.txt:17:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/with-cos/p5202-rev/dmesg-tail.txt:18:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/with-cos/p5202-rev/dmesg-tail.txt:19:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/with-cos/p5202-rev/dmesg-tail.txt:20:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/with-cos/p5202-rev/dmesg-tail.txt:21:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/816-step1-rerun/evidence/with-cos/p5202-rev/dmesg-tail.txt:22:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/with-cos/p5202-rev/dmesg-tail.txt:23:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/with-cos/p5202-rev/dmesg-tail.txt:24:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/816-step1-rerun/evidence/with-cos/p5202-rev/dmesg-tail.txt:25:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/with-cos/p5202-rev/dmesg-tail.txt:41:[Tue Apr 21 16:54:08 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/with-cos/p5202-rev/dmesg-tail.txt:43:[Tue Apr 21 16:54:08 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/with-cos/p5202-rev/dmesg-tail.txt:45:[Tue Apr 21 17:27:49 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/with-cos/p5202-rev/dmesg-tail.txt:47:[Tue Apr 21 17:27:49 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run3/dmesg-tail.txt:2:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run3/dmesg-tail.txt:3:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run3/dmesg-tail.txt:4:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run3/dmesg-tail.txt:5:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run3/dmesg-tail.txt:6:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run3/dmesg-tail.txt:7:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run3/dmesg-tail.txt:8:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run3/dmesg-tail.txt:9:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run3/dmesg-tail.txt:10:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run3/dmesg-tail.txt:11:[Tue Apr 21 16:49:21 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run3/dmesg-tail.txt:13:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run3/dmesg-tail.txt:14:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run3/dmesg-tail.txt:15:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run3/dmesg-tail.txt:16:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run3/dmesg-tail.txt:17:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run3/dmesg-tail.txt:18:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run3/dmesg-tail.txt:19:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run3/dmesg-tail.txt:20:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run3/dmesg-tail.txt:21:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run3/dmesg-tail.txt:22:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run3/dmesg-tail.txt:38:[Tue Apr 21 16:54:08 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run3/dmesg-tail.txt:40:[Tue Apr 21 16:54:08 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run3/dmesg-tail.txt:42:[Tue Apr 21 17:27:49 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run3/dmesg-tail.txt:44:[Tue Apr 21 17:27:49 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5204-rev/dmesg-tail.txt:17:[Tue Apr 21 02:57:36 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5204-rev/dmesg-tail.txt:18:[Tue Apr 21 02:57:36 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5204-rev/dmesg-tail.txt:19:[Tue Apr 21 02:57:36 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5204-rev/dmesg-tail.txt:20:[Tue Apr 21 02:57:36 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5204-rev/dmesg-tail.txt:21:[Tue Apr 21 02:57:36 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5204-rev/dmesg-tail.txt:22:[Tue Apr 21 02:57:36 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5204-rev/dmesg-tail.txt:23:[Tue Apr 21 02:57:36 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5204-rev/dmesg-tail.txt:24:[Tue Apr 21 02:57:36 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5204-rev/dmesg-tail.txt:25:[Tue Apr 21 02:57:36 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5204-rev/dmesg-tail.txt:26:[Tue Apr 21 02:57:36 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5204-rev/dmesg-tail.txt:28:[Tue Apr 21 02:57:42 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5204-rev/dmesg-tail.txt:29:[Tue Apr 21 02:57:42 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5204-rev/dmesg-tail.txt:30:[Tue Apr 21 02:57:42 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5204-rev/dmesg-tail.txt:31:[Tue Apr 21 02:57:42 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5204-rev/dmesg-tail.txt:32:[Tue Apr 21 02:57:42 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5204-rev/dmesg-tail.txt:33:[Tue Apr 21 02:57:42 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5204-rev/dmesg-tail.txt:34:[Tue Apr 21 02:57:42 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5204-rev/dmesg-tail.txt:35:[Tue Apr 21 02:57:42 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5204-rev/dmesg-tail.txt:36:[Tue Apr 21 02:57:42 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/line-rate-investigation/step1-evidence/with-cos/p5204-rev/dmesg-tail.txt:37:[Tue Apr 21 02:57:42 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/with-cos/p5201-rev/dmesg-tail.txt:5:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/with-cos/p5201-rev/dmesg-tail.txt:6:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/with-cos/p5201-rev/dmesg-tail.txt:7:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/with-cos/p5201-rev/dmesg-tail.txt:8:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/with-cos/p5201-rev/dmesg-tail.txt:9:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/with-cos/p5201-rev/dmesg-tail.txt:10:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/with-cos/p5201-rev/dmesg-tail.txt:11:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/with-cos/p5201-rev/dmesg-tail.txt:12:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/with-cos/p5201-rev/dmesg-tail.txt:13:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/with-cos/p5201-rev/dmesg-tail.txt:14:[Tue Apr 21 16:49:21 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/with-cos/p5201-rev/dmesg-tail.txt:16:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/816-step1-rerun/evidence/with-cos/p5201-rev/dmesg-tail.txt:17:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/with-cos/p5201-rev/dmesg-tail.txt:18:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/with-cos/p5201-rev/dmesg-tail.txt:19:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/with-cos/p5201-rev/dmesg-tail.txt:20:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/with-cos/p5201-rev/dmesg-tail.txt:21:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/816-step1-rerun/evidence/with-cos/p5201-rev/dmesg-tail.txt:22:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/with-cos/p5201-rev/dmesg-tail.txt:23:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/with-cos/p5201-rev/dmesg-tail.txt:24:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/816-step1-rerun/evidence/with-cos/p5201-rev/dmesg-tail.txt:25:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/with-cos/p5201-rev/dmesg-tail.txt:41:[Tue Apr 21 16:54:08 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/with-cos/p5201-rev/dmesg-tail.txt:43:[Tue Apr 21 16:54:08 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/with-cos/p5201-rev/dmesg-tail.txt:45:[Tue Apr 21 17:27:49 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/with-cos/p5201-rev/dmesg-tail.txt:47:[Tue Apr 21 17:27:49 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/with-cos/p5203-fwd/dmesg-tail.txt:5:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/with-cos/p5203-fwd/dmesg-tail.txt:6:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/with-cos/p5203-fwd/dmesg-tail.txt:7:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/with-cos/p5203-fwd/dmesg-tail.txt:8:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/with-cos/p5203-fwd/dmesg-tail.txt:9:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/with-cos/p5203-fwd/dmesg-tail.txt:10:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/with-cos/p5203-fwd/dmesg-tail.txt:11:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/with-cos/p5203-fwd/dmesg-tail.txt:12:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/with-cos/p5203-fwd/dmesg-tail.txt:13:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/with-cos/p5203-fwd/dmesg-tail.txt:14:[Tue Apr 21 16:49:21 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/with-cos/p5203-fwd/dmesg-tail.txt:16:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/816-step1-rerun/evidence/with-cos/p5203-fwd/dmesg-tail.txt:17:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/with-cos/p5203-fwd/dmesg-tail.txt:18:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/with-cos/p5203-fwd/dmesg-tail.txt:19:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/with-cos/p5203-fwd/dmesg-tail.txt:20:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/with-cos/p5203-fwd/dmesg-tail.txt:21:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/816-step1-rerun/evidence/with-cos/p5203-fwd/dmesg-tail.txt:22:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/with-cos/p5203-fwd/dmesg-tail.txt:23:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/with-cos/p5203-fwd/dmesg-tail.txt:24:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/816-step1-rerun/evidence/with-cos/p5203-fwd/dmesg-tail.txt:25:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/with-cos/p5203-fwd/dmesg-tail.txt:41:[Tue Apr 21 16:54:08 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/with-cos/p5203-fwd/dmesg-tail.txt:43:[Tue Apr 21 16:54:08 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/with-cos/p5203-fwd/dmesg-tail.txt:45:[Tue Apr 21 17:27:49 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/with-cos/p5203-fwd/dmesg-tail.txt:47:[Tue Apr 21 17:27:49 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/with-cos/p5201-fwd/dmesg-tail.txt:5:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/with-cos/p5201-fwd/dmesg-tail.txt:6:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/with-cos/p5201-fwd/dmesg-tail.txt:7:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/with-cos/p5201-fwd/dmesg-tail.txt:8:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/with-cos/p5201-fwd/dmesg-tail.txt:9:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/with-cos/p5201-fwd/dmesg-tail.txt:10:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/with-cos/p5201-fwd/dmesg-tail.txt:11:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/with-cos/p5201-fwd/dmesg-tail.txt:12:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/with-cos/p5201-fwd/dmesg-tail.txt:13:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/with-cos/p5201-fwd/dmesg-tail.txt:14:[Tue Apr 21 16:49:21 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/with-cos/p5201-fwd/dmesg-tail.txt:16:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/816-step1-rerun/evidence/with-cos/p5201-fwd/dmesg-tail.txt:17:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/with-cos/p5201-fwd/dmesg-tail.txt:18:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/with-cos/p5201-fwd/dmesg-tail.txt:19:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/with-cos/p5201-fwd/dmesg-tail.txt:20:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/with-cos/p5201-fwd/dmesg-tail.txt:21:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/816-step1-rerun/evidence/with-cos/p5201-fwd/dmesg-tail.txt:22:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/with-cos/p5201-fwd/dmesg-tail.txt:23:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/with-cos/p5201-fwd/dmesg-tail.txt:24:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/816-step1-rerun/evidence/with-cos/p5201-fwd/dmesg-tail.txt:25:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/with-cos/p5201-fwd/dmesg-tail.txt:41:[Tue Apr 21 16:54:08 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/with-cos/p5201-fwd/dmesg-tail.txt:43:[Tue Apr 21 16:54:08 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/with-cos/p5201-fwd/dmesg-tail.txt:45:[Tue Apr 21 17:27:49 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/with-cos/p5201-fwd/dmesg-tail.txt:47:[Tue Apr 21 17:27:49 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/with-cos/p5202-fwd/dmesg-tail.txt:5:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/with-cos/p5202-fwd/dmesg-tail.txt:6:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/with-cos/p5202-fwd/dmesg-tail.txt:7:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/with-cos/p5202-fwd/dmesg-tail.txt:8:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/with-cos/p5202-fwd/dmesg-tail.txt:9:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/with-cos/p5202-fwd/dmesg-tail.txt:10:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/with-cos/p5202-fwd/dmesg-tail.txt:11:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/with-cos/p5202-fwd/dmesg-tail.txt:12:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/with-cos/p5202-fwd/dmesg-tail.txt:13:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/with-cos/p5202-fwd/dmesg-tail.txt:14:[Tue Apr 21 16:49:21 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/with-cos/p5202-fwd/dmesg-tail.txt:16:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/816-step1-rerun/evidence/with-cos/p5202-fwd/dmesg-tail.txt:17:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/with-cos/p5202-fwd/dmesg-tail.txt:18:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/with-cos/p5202-fwd/dmesg-tail.txt:19:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/with-cos/p5202-fwd/dmesg-tail.txt:20:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/with-cos/p5202-fwd/dmesg-tail.txt:21:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/816-step1-rerun/evidence/with-cos/p5202-fwd/dmesg-tail.txt:22:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/with-cos/p5202-fwd/dmesg-tail.txt:23:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/with-cos/p5202-fwd/dmesg-tail.txt:24:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/816-step1-rerun/evidence/with-cos/p5202-fwd/dmesg-tail.txt:25:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/with-cos/p5202-fwd/dmesg-tail.txt:41:[Tue Apr 21 16:54:08 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/with-cos/p5202-fwd/dmesg-tail.txt:43:[Tue Apr 21 16:54:08 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/with-cos/p5202-fwd/dmesg-tail.txt:45:[Tue Apr 21 17:27:49 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/with-cos/p5202-fwd/dmesg-tail.txt:47:[Tue Apr 21 17:27:49 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run1/dmesg-tail.txt:2:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run1/dmesg-tail.txt:3:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run1/dmesg-tail.txt:4:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run1/dmesg-tail.txt:5:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run1/dmesg-tail.txt:6:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run1/dmesg-tail.txt:7:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run1/dmesg-tail.txt:8:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run1/dmesg-tail.txt:9:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run1/dmesg-tail.txt:10:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run1/dmesg-tail.txt:11:[Tue Apr 21 16:49:21 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run1/dmesg-tail.txt:13:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run1/dmesg-tail.txt:14:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run1/dmesg-tail.txt:15:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run1/dmesg-tail.txt:16:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run1/dmesg-tail.txt:17:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run1/dmesg-tail.txt:18:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run1/dmesg-tail.txt:19:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run1/dmesg-tail.txt:20:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run1/dmesg-tail.txt:21:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run1/dmesg-tail.txt:22:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run1/dmesg-tail.txt:38:[Tue Apr 21 16:54:08 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run1/dmesg-tail.txt:40:[Tue Apr 21 16:54:08 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run1/dmesg-tail.txt:42:[Tue Apr 21 17:27:49 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run1/dmesg-tail.txt:44:[Tue Apr 21 17:27:49 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run4/dmesg-tail.txt:2:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run4/dmesg-tail.txt:3:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run4/dmesg-tail.txt:4:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run4/dmesg-tail.txt:5:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run4/dmesg-tail.txt:6:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run4/dmesg-tail.txt:7:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run4/dmesg-tail.txt:8:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run4/dmesg-tail.txt:9:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run4/dmesg-tail.txt:10:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run4/dmesg-tail.txt:11:[Tue Apr 21 16:49:21 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run4/dmesg-tail.txt:13:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run4/dmesg-tail.txt:14:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run4/dmesg-tail.txt:15:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run4/dmesg-tail.txt:16:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run4/dmesg-tail.txt:17:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run4/dmesg-tail.txt:18:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run4/dmesg-tail.txt:19:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run4/dmesg-tail.txt:20:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run4/dmesg-tail.txt:21:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run4/dmesg-tail.txt:22:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run4/dmesg-tail.txt:38:[Tue Apr 21 16:54:08 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run4/dmesg-tail.txt:40:[Tue Apr 21 16:54:08 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run4/dmesg-tail.txt:42:[Tue Apr 21 17:27:49 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run4/dmesg-tail.txt:44:[Tue Apr 21 17:27:49 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run3/dmesg-tail.txt:5:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run3/dmesg-tail.txt:6:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run3/dmesg-tail.txt:7:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run3/dmesg-tail.txt:8:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run3/dmesg-tail.txt:9:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run3/dmesg-tail.txt:10:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run3/dmesg-tail.txt:11:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run3/dmesg-tail.txt:12:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run3/dmesg-tail.txt:13:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run3/dmesg-tail.txt:14:[Tue Apr 21 16:49:21 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run3/dmesg-tail.txt:16:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run3/dmesg-tail.txt:17:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run3/dmesg-tail.txt:18:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run3/dmesg-tail.txt:19:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run3/dmesg-tail.txt:20:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run3/dmesg-tail.txt:21:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run3/dmesg-tail.txt:22:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run3/dmesg-tail.txt:23:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run3/dmesg-tail.txt:24:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run3/dmesg-tail.txt:25:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run3/dmesg-tail.txt:41:[Tue Apr 21 16:54:08 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run3/dmesg-tail.txt:43:[Tue Apr 21 16:54:08 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run3/dmesg-tail.txt:45:[Tue Apr 21 17:27:49 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run3/dmesg-tail.txt:47:[Tue Apr 21 17:27:49 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/with-cos/p5203-rev/dmesg-tail.txt:5:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/with-cos/p5203-rev/dmesg-tail.txt:6:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/with-cos/p5203-rev/dmesg-tail.txt:7:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/with-cos/p5203-rev/dmesg-tail.txt:8:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/with-cos/p5203-rev/dmesg-tail.txt:9:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/with-cos/p5203-rev/dmesg-tail.txt:10:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/with-cos/p5203-rev/dmesg-tail.txt:11:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/with-cos/p5203-rev/dmesg-tail.txt:12:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/with-cos/p5203-rev/dmesg-tail.txt:13:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/with-cos/p5203-rev/dmesg-tail.txt:14:[Tue Apr 21 16:49:21 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/with-cos/p5203-rev/dmesg-tail.txt:16:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/816-step1-rerun/evidence/with-cos/p5203-rev/dmesg-tail.txt:17:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/with-cos/p5203-rev/dmesg-tail.txt:18:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/with-cos/p5203-rev/dmesg-tail.txt:19:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/with-cos/p5203-rev/dmesg-tail.txt:20:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/with-cos/p5203-rev/dmesg-tail.txt:21:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/816-step1-rerun/evidence/with-cos/p5203-rev/dmesg-tail.txt:22:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/with-cos/p5203-rev/dmesg-tail.txt:23:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/with-cos/p5203-rev/dmesg-tail.txt:24:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/816-step1-rerun/evidence/with-cos/p5203-rev/dmesg-tail.txt:25:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/with-cos/p5203-rev/dmesg-tail.txt:41:[Tue Apr 21 16:54:08 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/with-cos/p5203-rev/dmesg-tail.txt:43:[Tue Apr 21 16:54:08 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/with-cos/p5203-rev/dmesg-tail.txt:45:[Tue Apr 21 17:27:49 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/with-cos/p5203-rev/dmesg-tail.txt:47:[Tue Apr 21 17:27:49 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/with-cos/p5204-rev/dmesg-tail.txt:5:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/with-cos/p5204-rev/dmesg-tail.txt:6:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/with-cos/p5204-rev/dmesg-tail.txt:7:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/with-cos/p5204-rev/dmesg-tail.txt:8:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/with-cos/p5204-rev/dmesg-tail.txt:9:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/with-cos/p5204-rev/dmesg-tail.txt:10:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/with-cos/p5204-rev/dmesg-tail.txt:11:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/with-cos/p5204-rev/dmesg-tail.txt:12:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/with-cos/p5204-rev/dmesg-tail.txt:13:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/with-cos/p5204-rev/dmesg-tail.txt:14:[Tue Apr 21 16:49:21 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/with-cos/p5204-rev/dmesg-tail.txt:16:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/816-step1-rerun/evidence/with-cos/p5204-rev/dmesg-tail.txt:17:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/with-cos/p5204-rev/dmesg-tail.txt:18:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/with-cos/p5204-rev/dmesg-tail.txt:19:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/with-cos/p5204-rev/dmesg-tail.txt:20:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/with-cos/p5204-rev/dmesg-tail.txt:21:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/816-step1-rerun/evidence/with-cos/p5204-rev/dmesg-tail.txt:22:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/with-cos/p5204-rev/dmesg-tail.txt:23:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/with-cos/p5204-rev/dmesg-tail.txt:24:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/816-step1-rerun/evidence/with-cos/p5204-rev/dmesg-tail.txt:25:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/with-cos/p5204-rev/dmesg-tail.txt:41:[Tue Apr 21 16:54:08 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/with-cos/p5204-rev/dmesg-tail.txt:43:[Tue Apr 21 16:54:08 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/with-cos/p5204-rev/dmesg-tail.txt:45:[Tue Apr 21 17:27:49 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/with-cos/p5204-rev/dmesg-tail.txt:47:[Tue Apr 21 17:27:49 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run5/dmesg-tail.txt:5:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run5/dmesg-tail.txt:6:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run5/dmesg-tail.txt:7:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run5/dmesg-tail.txt:8:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run5/dmesg-tail.txt:9:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run5/dmesg-tail.txt:10:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run5/dmesg-tail.txt:11:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run5/dmesg-tail.txt:12:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run5/dmesg-tail.txt:13:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run5/dmesg-tail.txt:14:[Tue Apr 21 16:49:21 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run5/dmesg-tail.txt:16:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run5/dmesg-tail.txt:17:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run5/dmesg-tail.txt:18:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run5/dmesg-tail.txt:19:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run5/dmesg-tail.txt:20:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run5/dmesg-tail.txt:21:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run5/dmesg-tail.txt:22:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run5/dmesg-tail.txt:23:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run5/dmesg-tail.txt:24:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run5/dmesg-tail.txt:25:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run5/dmesg-tail.txt:41:[Tue Apr 21 16:54:08 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run5/dmesg-tail.txt:43:[Tue Apr 21 16:54:08 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run5/dmesg-tail.txt:45:[Tue Apr 21 17:27:49 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run5/dmesg-tail.txt:47:[Tue Apr 21 17:27:49 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run1/dmesg-tail.txt:5:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run1/dmesg-tail.txt:6:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run1/dmesg-tail.txt:7:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run1/dmesg-tail.txt:8:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run1/dmesg-tail.txt:9:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run1/dmesg-tail.txt:10:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run1/dmesg-tail.txt:11:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run1/dmesg-tail.txt:12:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run1/dmesg-tail.txt:13:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run1/dmesg-tail.txt:14:[Tue Apr 21 16:49:21 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run1/dmesg-tail.txt:16:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run1/dmesg-tail.txt:17:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run1/dmesg-tail.txt:18:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run1/dmesg-tail.txt:19:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run1/dmesg-tail.txt:20:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run1/dmesg-tail.txt:21:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run1/dmesg-tail.txt:22:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run1/dmesg-tail.txt:23:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run1/dmesg-tail.txt:24:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run1/dmesg-tail.txt:25:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run1/dmesg-tail.txt:41:[Tue Apr 21 16:54:08 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run1/dmesg-tail.txt:43:[Tue Apr 21 16:54:08 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run1/dmesg-tail.txt:45:[Tue Apr 21 17:27:49 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run1/dmesg-tail.txt:47:[Tue Apr 21 17:27:49 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run2/dmesg-tail.txt:2:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run2/dmesg-tail.txt:3:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run2/dmesg-tail.txt:4:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run2/dmesg-tail.txt:5:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run2/dmesg-tail.txt:6:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run2/dmesg-tail.txt:7:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run2/dmesg-tail.txt:8:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run2/dmesg-tail.txt:9:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run2/dmesg-tail.txt:10:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run2/dmesg-tail.txt:11:[Tue Apr 21 16:49:21 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run2/dmesg-tail.txt:13:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run2/dmesg-tail.txt:14:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run2/dmesg-tail.txt:15:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run2/dmesg-tail.txt:16:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run2/dmesg-tail.txt:17:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run2/dmesg-tail.txt:18:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run2/dmesg-tail.txt:19:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run2/dmesg-tail.txt:20:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run2/dmesg-tail.txt:21:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run2/dmesg-tail.txt:22:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run2/dmesg-tail.txt:38:[Tue Apr 21 16:54:08 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run2/dmesg-tail.txt:40:[Tue Apr 21 16:54:08 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run2/dmesg-tail.txt:42:[Tue Apr 21 17:27:49 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run2/dmesg-tail.txt:44:[Tue Apr 21 17:27:49 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run5/dmesg-tail.txt:2:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run5/dmesg-tail.txt:3:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run5/dmesg-tail.txt:4:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run5/dmesg-tail.txt:5:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run5/dmesg-tail.txt:6:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run5/dmesg-tail.txt:7:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run5/dmesg-tail.txt:8:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run5/dmesg-tail.txt:9:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run5/dmesg-tail.txt:10:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run5/dmesg-tail.txt:11:[Tue Apr 21 16:49:21 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run5/dmesg-tail.txt:13:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run5/dmesg-tail.txt:14:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run5/dmesg-tail.txt:15:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run5/dmesg-tail.txt:16:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run5/dmesg-tail.txt:17:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run5/dmesg-tail.txt:18:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run5/dmesg-tail.txt:19:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run5/dmesg-tail.txt:20:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run5/dmesg-tail.txt:21:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run5/dmesg-tail.txt:22:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run5/dmesg-tail.txt:38:[Tue Apr 21 16:54:08 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run5/dmesg-tail.txt:40:[Tue Apr 21 16:54:08 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run5/dmesg-tail.txt:42:[Tue Apr 21 17:27:49 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-no-cos/run5/dmesg-tail.txt:44:[Tue Apr 21 17:27:49 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/with-cos/p5204-fwd/dmesg-tail.txt:5:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/with-cos/p5204-fwd/dmesg-tail.txt:6:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/with-cos/p5204-fwd/dmesg-tail.txt:7:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/with-cos/p5204-fwd/dmesg-tail.txt:8:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/with-cos/p5204-fwd/dmesg-tail.txt:9:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/with-cos/p5204-fwd/dmesg-tail.txt:10:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/with-cos/p5204-fwd/dmesg-tail.txt:11:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/with-cos/p5204-fwd/dmesg-tail.txt:12:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/with-cos/p5204-fwd/dmesg-tail.txt:13:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/with-cos/p5204-fwd/dmesg-tail.txt:14:[Tue Apr 21 16:49:21 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/with-cos/p5204-fwd/dmesg-tail.txt:16:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/816-step1-rerun/evidence/with-cos/p5204-fwd/dmesg-tail.txt:17:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/with-cos/p5204-fwd/dmesg-tail.txt:18:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/with-cos/p5204-fwd/dmesg-tail.txt:19:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/with-cos/p5204-fwd/dmesg-tail.txt:20:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/with-cos/p5204-fwd/dmesg-tail.txt:21:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/816-step1-rerun/evidence/with-cos/p5204-fwd/dmesg-tail.txt:22:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/with-cos/p5204-fwd/dmesg-tail.txt:23:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/with-cos/p5204-fwd/dmesg-tail.txt:24:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/816-step1-rerun/evidence/with-cos/p5204-fwd/dmesg-tail.txt:25:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/with-cos/p5204-fwd/dmesg-tail.txt:41:[Tue Apr 21 16:54:08 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/with-cos/p5204-fwd/dmesg-tail.txt:43:[Tue Apr 21 16:54:08 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/with-cos/p5204-fwd/dmesg-tail.txt:45:[Tue Apr 21 17:27:49 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/with-cos/p5204-fwd/dmesg-tail.txt:47:[Tue Apr 21 17:27:49 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run2/dmesg-tail.txt:5:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run2/dmesg-tail.txt:6:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run2/dmesg-tail.txt:7:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run2/dmesg-tail.txt:8:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run2/dmesg-tail.txt:9:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run2/dmesg-tail.txt:10:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run2/dmesg-tail.txt:11:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run2/dmesg-tail.txt:12:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run2/dmesg-tail.txt:13:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run2/dmesg-tail.txt:14:[Tue Apr 21 16:49:21 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run2/dmesg-tail.txt:16:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run2/dmesg-tail.txt:17:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run2/dmesg-tail.txt:18:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run2/dmesg-tail.txt:19:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run2/dmesg-tail.txt:20:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run2/dmesg-tail.txt:21:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run2/dmesg-tail.txt:22:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run2/dmesg-tail.txt:23:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run2/dmesg-tail.txt:24:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run2/dmesg-tail.txt:25:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run2/dmesg-tail.txt:41:[Tue Apr 21 16:54:08 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run2/dmesg-tail.txt:43:[Tue Apr 21 16:54:08 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run2/dmesg-tail.txt:45:[Tue Apr 21 17:27:49 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run2/dmesg-tail.txt:47:[Tue Apr 21 17:27:49 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run4/dmesg-tail.txt:5:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run4/dmesg-tail.txt:6:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run4/dmesg-tail.txt:7:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run4/dmesg-tail.txt:8:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run4/dmesg-tail.txt:9:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run4/dmesg-tail.txt:10:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run4/dmesg-tail.txt:11:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run4/dmesg-tail.txt:12:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run4/dmesg-tail.txt:13:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run4/dmesg-tail.txt:14:[Tue Apr 21 16:49:21 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run4/dmesg-tail.txt:16:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run4/dmesg-tail.txt:17:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run4/dmesg-tail.txt:18:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run4/dmesg-tail.txt:19:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run4/dmesg-tail.txt:20:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run4/dmesg-tail.txt:21:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run4/dmesg-tail.txt:22:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run4/dmesg-tail.txt:23:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run4/dmesg-tail.txt:24:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run4/dmesg-tail.txt:25:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run4/dmesg-tail.txt:41:[Tue Apr 21 16:54:08 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run4/dmesg-tail.txt:43:[Tue Apr 21 16:54:08 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run4/dmesg-tail.txt:45:[Tue Apr 21 17:27:49 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/rev-with-cos/run4/dmesg-tail.txt:47:[Tue Apr 21 17:27:49 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run3/dmesg-tail.txt:5:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run3/dmesg-tail.txt:6:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run3/dmesg-tail.txt:7:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run3/dmesg-tail.txt:8:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run3/dmesg-tail.txt:9:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run3/dmesg-tail.txt:10:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run3/dmesg-tail.txt:11:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run3/dmesg-tail.txt:12:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run3/dmesg-tail.txt:13:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run3/dmesg-tail.txt:14:[Tue Apr 21 16:49:21 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run3/dmesg-tail.txt:16:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run3/dmesg-tail.txt:17:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run3/dmesg-tail.txt:18:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run3/dmesg-tail.txt:19:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run3/dmesg-tail.txt:20:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run3/dmesg-tail.txt:21:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run3/dmesg-tail.txt:22:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run3/dmesg-tail.txt:23:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run3/dmesg-tail.txt:24:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run3/dmesg-tail.txt:25:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run3/dmesg-tail.txt:41:[Tue Apr 21 16:54:08 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run3/dmesg-tail.txt:43:[Tue Apr 21 16:54:08 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run3/dmesg-tail.txt:45:[Tue Apr 21 17:27:49 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run3/dmesg-tail.txt:47:[Tue Apr 21 17:27:49 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run1/dmesg-tail.txt:5:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run1/dmesg-tail.txt:6:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run1/dmesg-tail.txt:7:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run1/dmesg-tail.txt:8:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run1/dmesg-tail.txt:9:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run1/dmesg-tail.txt:10:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run1/dmesg-tail.txt:11:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run1/dmesg-tail.txt:12:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run1/dmesg-tail.txt:13:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run1/dmesg-tail.txt:14:[Tue Apr 21 16:49:21 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run1/dmesg-tail.txt:16:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run1/dmesg-tail.txt:17:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run1/dmesg-tail.txt:18:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run1/dmesg-tail.txt:19:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run1/dmesg-tail.txt:20:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run1/dmesg-tail.txt:21:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run1/dmesg-tail.txt:22:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run1/dmesg-tail.txt:23:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run1/dmesg-tail.txt:24:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run1/dmesg-tail.txt:25:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run1/dmesg-tail.txt:41:[Tue Apr 21 16:54:08 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run1/dmesg-tail.txt:43:[Tue Apr 21 16:54:08 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run1/dmesg-tail.txt:45:[Tue Apr 21 17:27:49 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run1/dmesg-tail.txt:47:[Tue Apr 21 17:27:49 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run2/dmesg-tail.txt:5:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run2/dmesg-tail.txt:6:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run2/dmesg-tail.txt:7:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run2/dmesg-tail.txt:8:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run2/dmesg-tail.txt:9:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run2/dmesg-tail.txt:10:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run2/dmesg-tail.txt:11:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run2/dmesg-tail.txt:12:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run2/dmesg-tail.txt:13:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run2/dmesg-tail.txt:14:[Tue Apr 21 16:49:21 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run2/dmesg-tail.txt:16:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run2/dmesg-tail.txt:17:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run2/dmesg-tail.txt:18:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run2/dmesg-tail.txt:19:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run2/dmesg-tail.txt:20:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run2/dmesg-tail.txt:21:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run2/dmesg-tail.txt:22:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run2/dmesg-tail.txt:23:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run2/dmesg-tail.txt:24:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run2/dmesg-tail.txt:25:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run2/dmesg-tail.txt:41:[Tue Apr 21 16:54:08 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run2/dmesg-tail.txt:43:[Tue Apr 21 16:54:08 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run2/dmesg-tail.txt:45:[Tue Apr 21 17:27:49 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run2/dmesg-tail.txt:47:[Tue Apr 21 17:27:49 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run5/dmesg-tail.txt:5:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run5/dmesg-tail.txt:6:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run5/dmesg-tail.txt:7:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run5/dmesg-tail.txt:8:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run5/dmesg-tail.txt:9:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run5/dmesg-tail.txt:10:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run5/dmesg-tail.txt:11:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run5/dmesg-tail.txt:12:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run5/dmesg-tail.txt:13:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run5/dmesg-tail.txt:14:[Tue Apr 21 16:49:21 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run5/dmesg-tail.txt:16:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run5/dmesg-tail.txt:17:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run5/dmesg-tail.txt:18:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run5/dmesg-tail.txt:19:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run5/dmesg-tail.txt:20:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run5/dmesg-tail.txt:21:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run5/dmesg-tail.txt:22:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run5/dmesg-tail.txt:23:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run5/dmesg-tail.txt:24:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run5/dmesg-tail.txt:25:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run5/dmesg-tail.txt:41:[Tue Apr 21 16:54:08 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run5/dmesg-tail.txt:43:[Tue Apr 21 16:54:08 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run5/dmesg-tail.txt:45:[Tue Apr 21 17:27:49 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run5/dmesg-tail.txt:47:[Tue Apr 21 17:27:49 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run4/dmesg-tail.txt:5:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run4/dmesg-tail.txt:6:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run4/dmesg-tail.txt:7:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run4/dmesg-tail.txt:8:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run4/dmesg-tail.txt:9:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run4/dmesg-tail.txt:10:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run4/dmesg-tail.txt:11:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run4/dmesg-tail.txt:12:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run4/dmesg-tail.txt:13:[Tue Apr 21 16:49:20 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run4/dmesg-tail.txt:14:[Tue Apr 21 16:49:21 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run4/dmesg-tail.txt:16:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run4/dmesg-tail.txt:17:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run4/dmesg-tail.txt:18:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run4/dmesg-tail.txt:19:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run4/dmesg-tail.txt:20:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run4/dmesg-tail.txt:21:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run4/dmesg-tail.txt:22:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.50!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run4/dmesg-tail.txt:23:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run4/dmesg-tail.txt:24:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run4/dmesg-tail.txt:25:[Tue Apr 21 16:49:26 2026] ICMPv6: NA: 02:bf:72:16:01:01 advertised our address fe80::bf72:16:1 on ge-0-0-2.80!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run4/dmesg-tail.txt:41:[Tue Apr 21 16:54:08 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run4/dmesg-tail.txt:43:[Tue Apr 21 16:54:08 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run4/dmesg-tail.txt:45:[Tue Apr 21 17:27:49 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!
./docs/pr/816-step1-rerun/evidence/baseline/fwd-with-cos/run4/dmesg-tail.txt:47:[Tue Apr 21 17:27:49 2026] ICMPv6: NA: 02:bf:72:16:02:01 advertised our address fe80::bf72:16:2 on ge-0-0-1!

codex
The first pass confirms the revised plan text includes the new helper and the LinkByName error split. I’m narrowing now to the actual tunnel/VRF/FRR code and the test-plan section so I can check whether the proposed behavior matches the current contracts.
exec
/bin/bash -lc "nl -ba pkg/routing/tunnel.go | sed -n '90,245p'" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
    90		// unchanged runner alive across applies instead of restarting it
    91		// (which would reset probe state every commit).
    92		remote     string
    93		source     string // tunnel local endpoint IP probed-from (#1918 §5c)
    94		interval   int
    95		maxRetries int // normalized: <=0 config value stored as 3
    96	
    97		// linkGen is the per-tunnel generation token captured at start
    98		// (#1918 §6 Axis D, defense-in-depth). The runner reads it LOCK-FREE
    99		// (.Load()) before each netlink op and drops the action if it no
   100		// longer matches the manager's current generation — so a stale runner
   101		// cannot down/up a recreated link. The runner NEVER takes t.mu (AGY
   102		// r5 deadlock note: a tick blocked on t.mu while Apply blocks on the
   103		// drain would deadlock).
   104		linkGen  *atomic.Uint64
   105		startGen uint64
   106	}
   107	
   108	// matches reports whether the runner's identity equals the config's
   109	// NORMALIZED keepalive parameters. KeepaliveRetry <= 0 normalizes to 3
   110	// BEFORE comparison (#1884 r1 Codex F5: comparing a raw config 0
   111	// against the stored default 3 would restart the runner every apply).
   112	// The tunnel SOURCE is part of the identity (#1918 §5c): a source-only
   113	// change must restart the runner so the probe binds the new endpoint.
   114	func (r *keepaliveRunner) matches(tc *config.TunnelConfig) bool {
   115		retries := tc.KeepaliveRetry
   116		if retries <= 0 {
   117			retries = 3
   118		}
   119		return r.remote == tc.Destination &&
   120			r.source == tc.Source &&
   121			r.interval == tc.Keepalive &&
   122			r.maxRetries == retries
   123	}
   124	
   125	// TunnelStatus holds the status of a tunnel interface.
   126	type TunnelStatus struct {
   127		Name        string
   128		Source      string
   129		Destination string
   130		State       string // "up" or "down"
   131		Addresses   []string
   132		// KeepaliveUp is tri-state (#1918): non-nil true/false when liveness is
   133		// KNOWN (probe succeeded/failed), and nil when EITHER no keepalive is
   134		// configured OR liveness is currently UNKNOWN (ProbeUnsupported —
   135		// hold-on-unknown). The two nil cases are distinguished by
   136		// KeepaliveInfo: "" → not configured; "unknown (...)" → configured but
   137		// liveness unknown.
   138		KeepaliveUp   *bool
   139		KeepaliveInfo string // human-readable keepalive status
   140	}
   141	
   142	// tunnelManager owns GRE/IPIP tunnel lifecycle and per-tunnel keepalive
   143	// goroutines. The mu field replaces the tunnel slice of the former
   144	// shared Manager.ifaceMu; keepalives belong to this domain (their only
   145	// user is tunnel apply/clear), so mu protects both tunnels and the
   146	// keepalives map as one cohesive critical section.
   147	type tunnelManager struct {
   148		ops       linkOps
   149		vrfBinder vrfBinder
   150	
   151		// prober performs the keepalive ICMP echo. nil → the production
   152		// icmpProber (lazily resolved by keepaliveProber). Tests inject a
   153		// deterministic fake (#1918).
   154		prober tunnelProber
   155	
   156		mu         sync.Mutex
   157		tunnels    []string                    // tunnels successfully applied this round (GetStatus source)
   158		keepalives map[string]*keepaliveRunner // tunnel name -> runner
   159	
   160		// linkGen is the per-tunnel monotonic generation counter (#1918 §6
   161		// Axis D, defense-in-depth recreate guard). The MAP structure is
   162		// mutated only under mu (by Apply, via bumpLinkGenLocked); the counter
   163		// values are *atomic.Uint64 so a keepalive runner can Load() them
   164		// lock-free at tick time without ever taking mu (AGY r5 deadlock
   165		// note). Apply bumps the counter on a tunnel link create/recreate so a
   166		// stale runner captured at the old generation drops its LinkSet*.
   167		linkGen map[string]*atomic.Uint64
   168	
   169		// Reconcile-in-place state (#1884). All lazily initialized by Apply.
   170		//
   171		// ownedNames: ALL non-WireGuard tunnel names from the LAST Apply's
   172		// DESIRED set (plus names whose removal LinkDel failed, retained for
   173		// retry). The removal diff and the adoption decision both key off
   174		// this — NOT off the success-tracked t.tunnels, whose
   175		// failure-continue paths can leave a live kernel link untracked.
   176		ownedNames map[string]bool
   177		// appliedAddrs: per tunnel, the address set this manager itself
   178		// ensured (successful adds + present-and-wanted + link-local whose
   179		// stale-delete failed). Gates stale LINK-LOCAL deletion: a
   180		// configured fe80 we applied is removable; the kernel's autoconf
   181		// fe80 is never touched.
   182		appliedAddrs map[string]map[string]bool
   183		// appliedRI: per tunnel, the routing-instance whose VRF this
   184		// manager successfully bound — or directly OBSERVED as the link's
   185		// master for a step-0a `routing-instances <ri> interface` list
   186		// bind. Invariant (#1884 r6-r8): a claim is only ever written from
   187		// a successful bind or a master observation, never an intent.
   188		// Unbind on config-wants-none is identity-gated against
   189		// vrf-<claim>.
   190		appliedRI map[string]string
   191	}
   192	
   193	// ensureReconcileStateLocked lazily initializes the reconcile maps so
   194	// directly-constructed managers (tests, façade) need no constructor
   195	// changes. Caller MUST hold mu.
   196	func (t *tunnelManager) ensureReconcileStateLocked() {
   197		if t.ownedNames == nil {
   198			t.ownedNames = map[string]bool{}
   199		}
   200		if t.appliedAddrs == nil {
   201			t.appliedAddrs = map[string]map[string]bool{}
   202		}
   203		if t.appliedRI == nil {
   204			t.appliedRI = map[string]string{}
   205		}
   206		if t.keepalives == nil {
   207			t.keepalives = map[string]*keepaliveRunner{}
   208		}
   209		if t.linkGen == nil {
   210			t.linkGen = map[string]*atomic.Uint64{}
   211		}
   212	}
   213	
   214	// linkGenForLocked returns the (lazily created) generation counter for a
   215	// tunnel name. Caller MUST hold mu.
   216	func (t *tunnelManager) linkGenForLocked(name string) *atomic.Uint64 {
   217		g, ok := t.linkGen[name]
   218		if !ok {
   219			g = &atomic.Uint64{}
   220			t.linkGen[name] = g
   221		}
   222		return g
   223	}
   224	
   225	// bumpLinkGenLocked advances a tunnel's generation token. Called by
   226	// Apply whenever it CREATES or RECREATES the kernel link for a tunnel,
   227	// so any keepalive runner still holding the previous generation drops
   228	// its netlink op (#1918 §6 Axis D defense-in-depth). Caller MUST hold
   229	// mu.
   230	func (t *tunnelManager) bumpLinkGenLocked(name string) {
   231		t.linkGenForLocked(name).Add(1)
   232	}
   233	
   234	// keepaliveProber resolves the prober used by keepalive goroutines: the
   235	// injected test fake when set, else the production datagram-ICMP prober.
   236	func (t *tunnelManager) keepaliveProber() tunnelProber {
   237		if t.prober != nil {
   238			return t.prober
   239		}
   240		return icmpProber{}
   241	}
   242	
   243	// Apply reconciles the kernel tunnel devices against the desired
   244	// config WITHOUT the historical clear-all + delete-and-recreate
   245	// (#1884): an untouched tunnel keeps its netdev (stable ifindex — no

exec
/bin/bash -lc "nl -ba pkg/routing/tunnel.go | sed -n '760,910p'" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
   760					}
   761				} else {
   762					slog.Info("removed stale "+kind+" address",
   763						"name", name, "addr", key)
   764				}
   765			}
   766		}
   767		for _, addrStr := range addrs {
   768			addr, parseErr := netlink.ParseAddr(addrStr)
   769			if parseErr != nil {
   770				continue
   771			}
   772			key := addr.IPNet.String()
   773			if existing[key] {
   774				newApplied[key] = true
   775				continue
   776			}
   777			if addErr := t.ops.AddrAdd(link, addr); addErr != nil {
   778				slog.Warn("failed to add "+kind+" address",
   779					"name", name, "addr", addrStr, "err", addErr)
   780			} else {
   781				newApplied[key] = true
   782			}
   783		}
   784		return newApplied
   785	}
   786	
   787	// reconcileVRFClaimLocked runs the #1884 A.5 ordered claim procedure.
   788	// The claim invariant (r6-r8): t.appliedRI[name] is only ever written
   789	// from a SUCCESSFUL BindInterfaceToVRF or a direct observation of the
   790	// link's master — never from intent — so the identity-gated unbind
   791	// below can neither strand a master we own nor touch one we do not.
   792	//
   793	//  1. stanza RI nonempty: bind; on success claim = stanza RI (stanza
   794	//     wins over a coexisting 0a list bind — today's effective apply
   795	//     order); on failure fall through to observation.
   796	//  2. stanza failed or empty, RIListMember nonempty: never unbind (0a
   797	//     owns list binds — the VETO); claim transfers to the list RI only
   798	//     when the observed master IS vrf-<RIListMember>, else the prior
   799	//     claim is retained.
   800	//  3. config wants no RI: identity-gated unbind of vrf-<claim>. Claim
   801	//     clears on successful unbind / identity mismatch (master not
   802	//     ours) / VRF device not-found (kernel already freed the slaves);
   803	//     it is RETAINED on transient errors so the next apply retries.
   804	//
   805	// Caller MUST hold mu.
   806	func (t *tunnelManager) reconcileVRFClaimLocked(tc *config.TunnelConfig, link netlink.Link) {
   807		name := tc.Name
   808		if tc.RoutingInstance != "" {
   809			if err := t.vrfBinder.BindInterfaceToVRF(name, tc.RoutingInstance); err != nil {
   810				slog.Warn("failed to bind tunnel to VRF",
   811					"name", name, "vrf", tc.RoutingInstance, "err", err)
   812				// r7/r8: a FAILED bind must not blind-write the claim (the
   813				// kernel may still carry the previous master, or a 0a list
   814				// bind). Observation may take the claim; else retain.
   815				t.observeListClaimLocked(tc, link)
   816				return
   817			}
   818			t.appliedRI[name] = tc.RoutingInstance
   819			return
   820		}
   821		if tc.RIListMember != "" {
   822			// Unbind VETO: a stanza→list move must never strip the 0a
   823			// bind (r4 convergent counterexample).
   824			t.observeListClaimLocked(tc, link)
   825			return
   826		}
   827	
   828		claim := t.appliedRI[name]
   829		if claim == "" {
   830			return
   831		}
   832		master := link.Attrs().MasterIndex
   833		if master == 0 {
   834			// Nothing is bound — whatever we once bound is already gone.
   835			delete(t.appliedRI, name)
   836			return
   837		}
   838		vrf, err := t.ops.LinkByName("vrf-" + claim)
   839		if err != nil {
   840			if isLinkNotFound(err) {
   841				// The VRF device is gone; deleting a master frees its
   842				// slaves, so the current master cannot be ours.
   843				delete(t.appliedRI, name)
   844				return
   845			}
   846			// Transient lookup error: retain the claim, retry next apply.
   847			return
   848		}
   849		if vrf.Attrs().Index != master {
   850			// Master is not the VRF we bound (someone else's bind).
   851			delete(t.appliedRI, name)
   852			return
   853		}
   854		if err := t.ops.LinkSetNoMaster(link); err != nil {
   855			slog.Warn("failed to unbind tunnel from VRF",
   856				"name", name, "vrf", claim, "err", err)
   857			return // retain claim; retry next apply
   858		}
   859		slog.Info("tunnel unbound from routing-instance",
   860			"name", name, "vrf", claim)
   861		delete(t.appliedRI, name)
   862	}
   863	
   864	// observeListClaimLocked transfers the appliedRI claim to the
   865	// routing-instance list member ONLY when the link's current master is
   866	// OBSERVED to be that RI's VRF device (#1884 r6/r8: a blind transfer
   867	// after a failed 0a bind would record an RI the kernel never took and
   868	// later strand the real master on a mismatch-clear). On any
   869	// non-observation the previous nonempty claim is retained. Caller MUST
   870	// hold mu.
   871	func (t *tunnelManager) observeListClaimLocked(tc *config.TunnelConfig, link netlink.Link) {
   872		if tc.RIListMember == "" {
   873			return
   874		}
   875		master := link.Attrs().MasterIndex
   876		if master == 0 {
   877			return // 0a bind absent or failed: no observation, retain prior
   878		}
   879		vrf, err := t.ops.LinkByName("vrf-" + tc.RIListMember)
   880		if err != nil {
   881			return // retain prior claim
   882		}
   883		if vrf.Attrs().Index == master {
   884			t.appliedRI[tc.Name] = tc.RIListMember
   885		}
   886	}
   887	
   888	// WG per-packet outer overhead (must mirror userspace-dp
   889	// afxdp/wg/mod.rs WG_OVERHEAD_V4/V6): outer IP + UDP(8) + WG data
   890	// header(16) + Poly1305 tag(16). Plus up to 15 bytes of §5.4.6 pad.
   891	const (
   892		wgOverheadV4 = 20 + 8 + 16 + 16 // 60
   893		wgOverheadV6 = 40 + 8 + 16 + 16 // 80
   894		wgPadWorst   = 15
   895	)
   896	
   897	// wgTunMTUForEndpoint computes the inner (wgN) MTU cap (#1432 S2a, AGY
   898	// Hazard A / H2). The kernel must never hand the WG control thread a
   899	// plaintext packet that, once encapped with the worst-case overhead
   900	// plus §5.4.6 pad, exceeds the outer MTU and forces outer IP
   901	// fragmentation. The overhead depends on the outer IP family (the WG
   902	// peer endpoint address): IPv6-outer is 20 bytes larger. The outer MTU
   903	// is assumed to be a standard 1500 (S2a single-tunnel); the control
   904	// thread also enforces an exact pad-aware guard (wg_control.rs), so this
   905	// is the first line, not the only one.
   906	func wgTunMTUForEndpoint(tc *config.TunnelConfig) int {
   907		const outerMTU = 1500
   908		// A configured v4 endpoint uses the v4 overhead; a v6 endpoint (or a
   909		// responder-only/roaming endpoint with no configured address, which
   910		// the Rust control thread may LEARN as v6 — Codex r4 MAJOR) uses the

exec
/bin/bash -lc "nl -ba pkg/routing/tunnel.go | sed -n '560,730p'" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
   560		// (EBUSY / transport hiccup) is TRANSIENT — it does NOT mean the link
   561		// is gone, so we must NOT drain the live keepalive runner and must NOT
   562		// fall through to a LinkAdd that would EEXIST. Abort and retry next
   563		// apply, exactly like a transient LinkDel failure below.
   564		willRecreate := false
   565		var existing netlink.Link
   566		e, lookupErr := t.ops.LinkByName(tc.Name)
   567		switch {
   568		case lookupErr == nil:
   569			existing = e
   570			willRecreate = !legacyTunnelMatches(e, desired)
   571		case isLinkNotFound(lookupErr):
   572			// Absent → the LinkAdd below is a (re)create.
   573			willRecreate = true
   574		default:
   575			// Transient lookup error: leave the runner and any live link
   576			// untouched; retry on the next apply.
   577			slog.Warn("tunnel lookup failed transiently; deferring apply",
   578				"name", tc.Name, "err", lookupErr)
   579			return
   580		}
   581		if willRecreate {
   582			// Drain the stale runner first; bump the generation so any runner
   583			// that somehow survives (future code paths) drops its netlink op.
   584			t.stopKeepaliveLocked(tc.Name)
   585			t.bumpLinkGenLocked(tc.Name)
   586		}
   587	
   588		var link netlink.Link
   589		created := false
   590		if existing != nil {
   591			if !willRecreate {
   592				link = existing // kernel-fetched, real ifindex (#1706)
   593				slog.Debug("tunnel reused", "name", tc.Name)
   594			} else {
   595				if delErr := t.ops.LinkDel(existing); delErr != nil {
   596					slog.Warn("failed to replace existing tunnel link",
   597						"name", tc.Name, "existing_type", existing.Type(), "err", delErr)
   598					// The recreate failed but the OLD link is still live. We
   599					// already drained its keepalive runner before the LinkDel
   600					// (F7 ordering). Restart it against the surviving link so a
   601					// transient LinkDel failure does not silently leave the
   602					// tunnel running with NO keepalive until the next successful
   603					// apply (Copilot PR #1947 r3). Safe because the link was NOT
   604					// recreated — the restarted runner captures the just-bumped
   605					// generation and probes the same device.
   606					if tc.Keepalive > 0 {
   607						t.startKeepalive(tc.Name, tc.Source, tc.Destination, tc.Keepalive, tc.KeepaliveRetry)
   608					}
   609					return
   610				}
   611				slog.Info("replaced tunnel link with changed parameters",
   612					"name", tc.Name, "existing_type", existing.Type())
   613			}
   614		}
   615		if link == nil {
   616			if addErr := t.ops.LinkAdd(desired); addErr != nil {
   617				slog.Warn("failed to create tunnel",
   618					"name", tc.Name, "mode", tc.Mode, "err", addErr)
   619				return
   620			}
   621			link = desired
   622			created = true
   623	
   624			// IPv6 GRE: disable encaplimit to avoid adding an IPv6
   625			// Destination Options extension header. Many transit networks
   626			// drop IPv6 packets with extension headers (RFC 7872). Runs
   627			// only on a real (re)create — it is a per-create device attr
   628			// and the 15s-bounded exec must not run per commit (#1884).
   629			if isIPv6 && (tc.Mode == "gre" || tc.Mode == "") {
   630				// Timeout-bounded (#1794/#1800): Apply runs under
   631				// applyConfigLocked's applySem (daemon_apply.go
   632				// ApplyTunnels), so a wedged `ip` would block every commit.
   633				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
   634				ipCmd := exec.CommandContext(ctx, "ip", "link", "set", tc.Name,
   635					"type", "ip6gre", "encaplimit", "none")
   636				// WaitDelay caps the post-SIGKILL pipe-drain window.
   637				ipCmd.WaitDelay = 5 * time.Second
   638				out, err := ipCmd.CombinedOutput()
   639				cancel()
   640				if err != nil {
   641					slog.Warn("failed to set tunnel encaplimit",
   642						"name", tc.Name, "err", err, "output", string(out))
   643				}
   644			}
   645			if tc.MTU > 0 {
   646				if mtuErr := t.ops.LinkSetMTU(link, tc.MTU); mtuErr != nil {
   647					slog.Warn("failed to set tunnel mtu",
   648						"name", tc.Name, "mtu", tc.MTU, "err", mtuErr)
   649				}
   650			}
   651			slog.Info("tunnel created", "name", tc.Name,
   652				"src", tc.Source, "dst", tc.Destination)
   653		} else if tc.MTU > 0 && link.Attrs().MTU != tc.MTU {
   654			// Config-owned MTU reconcile on reuse (#1884 r5). No
   655			// adoption-default normalization here: kernel GRE/IPIP devices
   656			// have protocol-specific default MTUs (1476/1462/...), not the
   657			// TUN 1500.
   658			if mtuErr := t.ops.LinkSetMTU(link, tc.MTU); mtuErr != nil {
   659				slog.Warn("failed to set tunnel mtu",
   660					"name", tc.Name, "mtu", tc.MTU, "err", mtuErr)
   661			}
   662		}
   663	
   664		// Keepalive reconcile (#1884 A.7, LEGACY BRANCH ONLY — anchors
   665		// never run probes). Identity-unchanged runners are retained so
   666		// probe state survives commits; the retained-and-DOWN case must
   667		// skip LinkSetUp below: keepaliveLoop's down-transition is gated
   668		// on state.Up==true, so re-upping the link here would strand it
   669		// admin UP forever while probes keep failing (r1 Codex F1 + AGY
   670		// converged trace).
   671		runner, hasRunner := t.keepalives[tc.Name]
   672		restartKA := tc.Keepalive > 0 && (!hasRunner || created || !runner.matches(tc))
   673		skipUp := false
   674		if tc.Keepalive > 0 && hasRunner && !restartKA {
   675			runner.state.mu.Lock()
   676			skipUp = !runner.state.Up
   677			runner.state.mu.Unlock()
   678		}
   679	
   680		t.finishTunnelLocked(tc, link, skipUp, "tunnel")
   681	
   682		if tc.Keepalive > 0 {
   683			if restartKA {
   684				// startKeepalive stops+drains any predecessor itself;
   685				// runs AFTER a recreate so the fresh runner probes the
   686				// new device. tc.Source is the bind endpoint (#1918 §5c).
   687				t.startKeepalive(tc.Name, tc.Source, tc.Destination, tc.Keepalive, tc.KeepaliveRetry)
   688			}
   689		} else if hasRunner {
   690			t.stopKeepaliveLocked(tc.Name)
   691		}
   692	}
   693	
   694	// finishTunnelLocked is the shared apply tail: admin-up (unless a
   695	// retained keepalive runner holds the tunnel down), symmetric address
   696	// reconciliation, VRF claim reconcile, and success tracking. Caller
   697	// MUST hold mu; link is the kernel-fetched (or just-created) device.
   698	func (t *tunnelManager) finishTunnelLocked(tc *config.TunnelConfig, link netlink.Link, skipUp bool, kind string) {
   699		if skipUp {
   700			slog.Debug("skipping link up: keepalive holds tunnel down",
   701				"name", tc.Name)
   702		} else if err := t.ops.LinkSetUp(link); err != nil {
   703			slog.Warn("failed to bring up "+kind, "name", tc.Name, "err", err)
   704		}
   705		t.appliedAddrs[tc.Name] = t.reconcileLinkAddrsLocked(
   706			link, tc.Name, tc.Addresses, t.appliedAddrs[tc.Name], kind)
   707		t.reconcileVRFClaimLocked(tc, link)
   708		t.tunnels = append(t.tunnels, tc.Name)
   709	}
   710	
   711	// reconcileLinkAddrsLocked symmetrically reconciles a link's addresses
   712	// against the configured set: add configured-but-missing, delete
   713	// present-but-unconfigured — EXCEPT link-local addresses, which are
   714	// deleted only when this manager itself applied them (`applied`
   715	// gate). The kernel's autoconf fe80 must never be deleted, while a
   716	// CONFIGURED fe80 removed from config must not leak forever (#1884 r1
   717	// Codex F2; extended to the WG branch in #1905). applied == nil (the
   718	// first apply for a link this manager has not tracked yet — restart
   719	// adoption) means no link-local deletion at all.
   720	//
   721	// Returns the new applied set: successful adds + present-and-wanted +
   722	// link-local addresses whose stale-delete FAILED (kept tracked so the
   723	// next apply retries — r2 Codex F4).
   724	func (t *tunnelManager) reconcileLinkAddrsLocked(link netlink.Link, name string, addrs []string, applied map[string]bool, kind string) map[string]bool {
   725		want := make(map[string]bool, len(addrs))
   726		for _, addrStr := range addrs {
   727			addr, parseErr := netlink.ParseAddr(addrStr)
   728			if parseErr != nil {
   729				slog.Warn("invalid "+kind+" address",
   730					"name", name, "addr", addrStr, "err", parseErr)

exec
/bin/bash -lc "nl -ba docs/research/1919-wg-addr-route-prune/plan.md | sed -n '260,560p'" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
   260	
   261	This makes the retry signal correct **by construction** for all families
   262	and keeps the steady-state reconcile contract stable.
   263	
   264	**Pros**: symmetric with the existing `ownedNames` retry pattern; reuses
   265	`appliedAddrs` + the link-local gate; idempotent; link preserved; the new
   266	helper is ~15 lines and isolates removal-prune failure tracking from the
   267	steady-state reconcile contract.
   268	
   269	**Cons**: one new small helper + one new reconcile map to keep in sync
   270	across `clearLocked` (reset) and `ensureReconcileStateLocked` (lazy init).
   271	
   272	### Path B — Flush all addresses on any wgN that is up-but-unconfigured
   273	
   274	On each `Apply`, enumerate kernel links, find TUN devices matching the
   275	WG naming whose name is not in `wgDesired`, and flush manager-applied
   276	addresses. Rejected: requires WG-name heuristics (no stable WG-only
   277	marker on the netdev), risks touching foreign/adopted devices, and
   278	duplicates the `appliedAddrs` bookkeeping Path A already has. Higher
   279	blast radius, weaker safety.
   280	
   281	### Path C — Tear the link too on removal
   282	
   283	Rejected explicitly by #1432 S2a (AGY Hazard B): deleting wgN tears the
   284	live peer/session and flaps the device. The issue itself says keep the
   285	link. Out of scope; #1434 owns full teardown grammar.
   286	
   287	### Recommendation
   288	
   289	**Path A.** It is the minimal, symmetric, idempotent fix that reuses the
   290	exact assets (`appliedAddrs`, `reconcileLinkAddrsLocked`) the manager
   291	already maintains, keeps the persistent link per #1432, and adds one
   292	narrowly-scoped state map with the same retry discipline as the existing
   293	GRE removal loop.
   294	
   295	### 4b. Prune scope — what addresses get deleted (r2 correction)
   296	
   297	r1 review (all three) flagged that the plan said "manager-applied
   298	addresses only". That is **wrong** and now corrected: the removal prune
   299	deletes **every present non-link-local address** on the device
   300	(`AddrDel` for all of them), and for **link-local** it deletes only the
   301	configured/applied ones (autoconf/foreign fe80 gated out). The
   302	`appliedAddrs[name]` set gates link-local deletion ONLY — it does NOT
   303	restrict non-link-local deletion. This is **identical** to the
   304	steady-state reconcile (`reconcileLinkAddrsLocked` deletes all present-
   305	but-unwanted non-link-local addresses regardless of `applied`), so the
   306	removal prune is consistent with how the manager already treats the
   307	device while configured. Consequence to STATE in the PR + docs: if an
   308	operator manually `ip addr add`'d a non-fe80 address to a configured wgN,
   309	that address would also be removed on tunnel-removal prune — exactly as
   310	it would be removed on any steady-state reconcile today. This is intended
   311	"the manager owns the device's non-link-local address set" behavior, not
   312	a new hazard. (If reviewers want strict applied-only deletion, the helper
   313	can intersect with `applied`, but that would DIVERGE from steady-state
   314	semantics and risk leaving a manager-applied address behind if it fell
   315	out of `applied` tracking — not recommended.)
   316	
   317	### 4a. VRF unbind on WG removal — scope decision
   318	
   319	`applyWireguardTunLocked` VRF-binds at `:883-888` but does NOT use
   320	`reconcileVRFClaimLocked`/`appliedRI` (it binds directly, no claim
   321	tracked). So a removed WG tunnel that was VRF-bound leaves the link
   322	enslaved to `vrf-<ri>`. Two choices:
   323	
   324	- **A1 (recommended for this PR)**: prune **addresses only**; leave the
   325	  VRF master as-is. Rationale: the link persists by design; its VRF
   326	  membership is a property of the persistent device, not a leaked
   327	  address; and there is no `appliedRI` claim to safely identity-gate an
   328	  unbind (unbinding blind would risk stripping a master we do not own —
   329	  the exact hazard `reconcileVRFClaimLocked` was built to avoid). Note
   330	  this explicitly as a documented residual, tracked under #1434.
   331	- **A2**: extend WG to use `appliedRI`/`reconcileVRFClaimLocked` so
   332	  removal can identity-gated-unbind. Larger change; couples this fix to
   333	  the VRF-claim machinery WG deliberately bypasses. Defer.
   334	
   335	Decision: **A1** — addresses only, VRF residual documented. If a
   336	reviewer demands VRF unbind, escalate to A2 as a follow-up, not this PR.
   337	
   338	**r2 nit (AGY)**: a RELATED pre-existing gap to call out (NOT introduced
   339	by this PR, NOT fixed by it): a WG tunnel that STAYS configured but has
   340	its `routing-instance` removed also never unbinds (`applyWireguardTunLocked`
   341	binds at `:883-888` but has no unbind-on-empty path). This is the same
   342	root cause (WG bypasses `reconcileVRFClaimLocked`/`appliedRI`) and is in
   343	scope for the A2 / #1434 VRF follow-up, not this address-leak fix.
   344	Document both VRF residuals together so the follow-up has a clear target.
   345	
   346	---
   347	
   348	## 5. Detailed implementation sketch (Path A)
   349	
   350	State (add to `tunnelManager`):
   351	```go
   352	// wgConfigured: WG tunnel names configured at the LAST Apply (plus
   353	// names whose address prune left residual tracked addrs, retained for
   354	// retry). NEVER feeds the LinkDel removal loop — WG links persist
   355	// (#1432 S2a). Drives the WG address-prune-on-removal diff (#1919).
   356	wgConfigured map[string]bool
   357	```
   358	
   359	`ensureReconcileStateLocked`: add `if t.wgConfigured == nil { … }`.
   360	
   361	New helper (removal-only; leaves `reconcileLinkAddrsLocked` untouched):
   362	```go
   363	// pruneAppliedAddrsLocked deletes the addresses this manager owns from a
   364	// link being pruned (WG removal), keeping the link. Deletes every
   365	// present non-link-local address, plus configured/applied link-locals;
   366	// the kernel autoconf/foreign fe80 is never touched (same gate as
   367	// reconcileLinkAddrsLocked). Returns the set of addresses whose AddrDel
   368	// FAILED — across ALL families — so the caller can retain+retry. Caller
   369	// MUST hold mu.
   370	func (t *tunnelManager) pruneAppliedAddrsLocked(link netlink.Link, name string, applied map[string]bool) map[string]bool {
   371	    failed := map[string]bool{}
   372	    list, err := t.ops.AddrList(link, netlink.FAMILY_ALL)
   373	    if err != nil {
   374	        // Could not enumerate — treat as "all still present": retain the
   375	        // tracked set so the next apply retries. (If applied is empty,
   376	        // returns empty → caller drops, which is correct: nothing to do.)
   377	        for k := range applied { failed[k] = true }
   378	        return failed
   379	    }
   380	    for i := range list {
   381	        a := list[i]
   382	        if a.IP == nil { continue } // unclassifiable: never delete
   383	        key := a.IPNet.String()
   384	        if a.IP.IsLinkLocalUnicast() && (applied == nil || !applied[key]) {
   385	            continue // kernel autoconf / foreign link-local: never delete
   386	        }
   387	        if delErr := t.ops.AddrDel(link, &a); delErr != nil {
   388	            slog.Warn("failed to prune wireguard tun address",
   389	                "name", name, "addr", key, "err", delErr)
   390	            failed[key] = true // ALL families (the r1-MAJOR fix)
   391	        } else {
   392	            slog.Info("pruned wireguard tun address (removed from config)",
   393	                "name", name, "addr", key)
   394	        }
   395	    }
   396	    return failed
   397	}
   398	```
   399	
   400	`Apply` (prune phase + state, GRE loop & per-tunnel loop unchanged):
   401	```go
   402	wgDesired := map[string]bool{}
   403	for _, tc := range tunnels {
   404	    if tc.Mode == "wireguard" { wgDesired[tc.Name] = true }
   405	}
   406	oldWG := t.wgConfigured
   407	nextWG := map[string]bool{}
   408	for n := range wgDesired { nextWG[n] = true }
   409	for name := range oldWG {
   410	    if wgDesired[name] { continue }
   411	    link, err := t.ops.LinkByName(name)
   412	    if err != nil {
   413	        if isLinkNotFound(err) {
   414	            delete(t.appliedAddrs, name) // device genuinely gone; drop
   415	        } else {
   416	            // transient lookup error: retain + retry (r1 Codex/AGY MAJOR)
   417	            nextWG[name] = true
   418	        }
   419	        continue
   420	    }
   421	    failed := t.pruneAppliedAddrsLocked(link, name, t.appliedAddrs[name])
   422	    if len(failed) > 0 {
   423	        t.appliedAddrs[name] = failed
   424	        nextWG[name] = true // AddrDel failed → retry next apply
   425	        continue
   426	    }
   427	    delete(t.appliedAddrs, name) // clean prune; drop tracking
   428	}
   429	// ... existing GRE removal loop unchanged ...
   430	// ... per-tunnel apply loop unchanged (still-configured WG re-tracked
   431	//     via applyWireguardTunLocked → reconcileLinkAddrsLocked at :880) ...
   432	t.wgConfigured = nextWG
   433	```
   434	
   435	Note: `nextWG` starts as `wgDesired`; the per-tunnel loop already
   436	re-applies still-configured WG (no change there). The prune loop runs
   437	against `oldWG` so it sees exactly the names that disappeared. On a clean
   438	prune the name is in neither `wgDesired` nor retained → dropped from
   439	`nextWG` → next `Apply` is a no-op for it (idempotent ✔). On AddrDel/
   440	transient-lookup failure the name is retained in `nextWG` and retried.
   441	
   442	`clearLocked`: add `t.wgConfigured = nil` to the reset block (:1109).
   443	ClearTunnels still does not delete WG links (unchanged) — but on a full
   444	clear the operator intent is teardown; whether ClearTunnels should now
   445	also flush WG addresses is a **secondary decision** (§7 open question).
   446	Default: leave ClearTunnels behavior unchanged (it never managed WG
   447	addresses before); only reset the tracking map so a post-Clear Apply
   448	re-adopts cleanly.
   449	
   450	Idempotency proof: after the prune commit, `oldWG` (next round) no longer
   451	contains the removed name (we set `t.wgConfigured = nextWG` which only
   452	carries retained-for-retry names). A clean prune drops the name entirely
   453	→ next `Apply` sees it in neither `oldWG` nor `wgDesired` → no-op. A
   454	failed-AddrDel prune keeps it in `nextWG` → retried until clean. ✔
   455	
   456	---
   457	
   458	## 6. Tests (new, in `tunnel_reconcile_test.go`)
   459	
   460	Using the existing fake `linkOps` harness:
   461	
   462	1. **`TestWireguardRemovedFromConfigPrunesAddresses`**: Apply with a WG
   463	   tunnel carrying `172.16.0.1/30` (+ optional fe80 configured) → assert
   464	   AddrAdd called. Apply again with empty tunnel list → assert
   465	   (a) link is NOT deleted (no LinkDel for wgN), (b) AddrDel called for
   466	   `172.16.0.1/30`, (c) configured fe80 deleted, kernel autoconf fe80
   467	   untouched (reuse the link-local gate test fixtures at :349-435).
   468	3. **`TestWireguardRemovalPruneIdempotent`**: third Apply (still empty)
   469	   → assert NO further AddrDel / LinkByName churn for the pruned name
   470	   (name dropped from tracking).
   471	4. **`TestWireguardRemovalAddrDelFailureRetried`**: fake AddrDel returns
   472	   error on first removal Apply for a **non-link-local** address
   473	   (`172.16.0.1/30` — r1 review: the retry MUST be proven for the
   474	   regular-address case, not only fe80) → assert name retained in
   475	   tracking, second removal Apply retries AddrDel, third (success) drops
   476	   it. This test is the direct regression guard for the r1 MAJOR.
   477	5. **`TestWireguardRemovalDeviceNotFoundDropsTracking`**: LinkByName
   478	   returns a not-found error on removal → assert no panic, tracking
   479	   dropped, no-op next apply.
   480	6. **`TestWireguardRemovalTransientLookupRetained`**: LinkByName returns
   481	   a NON-not-found (transient) error on removal → assert name RETAINED
   482	   in tracking and a subsequent Apply (link now resolvable) prunes the
   483	   address. (Direct guard for r1 Codex/AGY MAJOR #2.) Requires the fake
   484	   `linkOps` to support an injectable non-not-found LinkByName error.
   485	7. **`TestWireguardReAddAfterRemovalTracksFresh`**: add → remove (prune)
   486	   → re-add same name with a NEW address → assert new addr applied and
   487	   old addr not re-leaked (appliedAddrs correctly reset/repopulated).
   488	8. **`TestWireguardRemovedWhileDaemonDownNotPruned`** (R5 boundary): on a
   489	   FRESH manager (empty `wgConfigured`) with a wgN carrying addresses
   490	   present in the kernel + an empty tunnel list → assert NO AddrDel
   491	   (the manager only prunes what it tracked applying; restart-time
   492	   removal is #1434 scope). Encodes the deferral.
   493	9. **Regression guard**: existing `TestWireguardConfiguredLinkLocalRemoved`
   494	   and friends must still pass (still-configured reconcile unchanged;
   495	   `reconcileLinkAddrsLocked` is NOT modified).
   496	
   497	All tests assert via the fake's recorded `AddrAdd`/`AddrDel`/`LinkDel`
   498	call logs. No live netlink.
   499	
   500	---
   501	
   502	## 7. Open questions / decisions for reviewer
   503	
   504	> r2 status: the three r1 MAJOR/MED findings (broken retry signal,
   505	> transient-lookup drop, applied-only overclaim) are RESOLVED in §4/§5/§4b
   506	> above. The items below are residual design choices, all with a stated
   507	> default.
   508	
   509	
   510	1. **ClearTunnels + WG addresses**: should the explicit delete-everything
   511	   path also flush WG addresses (and/or delete the WG link)? Current
   512	   plan: NO change to ClearTunnels link behavior; only reset the new
   513	   tracking map. Rationale: ClearTunnels never managed WG before; #1434
   514	   owns teardown. Reviewer may want ClearTunnels to flush WG addresses
   515	   for symmetry — call it.
   516	2. **VRF unbind on WG removal** (§4a): A1 (addresses only) vs A2 (full
   517	   VRF-claim adoption for WG). Plan: A1, residual documented.
   518	3. **FRR routes** (§1a): plan asserts there is NO manager-owned FRR
   519	   route for WG to withdraw and closes that sub-claim by clarification.
   520	   Reviewer must produce a concrete WG→FRR-route code path to reopen it.
   521	4. **Live peer/session**: removal keeps the link AND (per current code)
   522	   the Rust wg_control thread keeps attached. Confirm intended:
   523	   pruning the inner addresses while the peer stays attached means the
   524	   device is up but unaddressed. Issue text says "keep the persistent
   525	   wgN link (and the live peer/session if that's intended — clarify)".
   526	   Plan position: keep link + peer attached (don't touch Rust); only
   527	   strip the Go-managed kernel addresses. This matches #1432 S2a's
   528	   "persistent device" intent and #1434's ownership of full teardown.
   529	
   530	---
   531	
   532	## 8. Risks & mitigations
   533	
   534	- **R1 — pruning an address still in use by a live flow**: removing a WG
   535	  tunnel from config IS the operator declaring it gone; stripping its
   536	  addresses is the intended effect. Scope (corrected per r1 review, §4b):
   537	  the prune deletes ALL present non-link-local addresses (the manager
   538	  owns the device's non-link-local set, same as steady-state reconcile),
   539	  and only configured/applied link-locals; the kernel autoconf/foreign
   540	  fe80 is gated out by the shared link-local check.
   541	- **R2 — touching the wrong device** (Path B hazard): avoided by Path A
   542	  keying off the exact tracked name set, not netdev heuristics.
   543	- **R3 — retry storms on persistent AddrDel failure**: bounded by the
   544	  same retain-and-retry pattern GRE removal uses; each Apply does at
   545	  most one AddrDel attempt per residual address.
   546	- **R4 — interaction with #1918**: none (WG has no keepalive). Verified.
   547	- **R5 — interaction with restart adoption** (`appliedAddrs == nil`):
   548	  on a fresh daemon, `wgConfigured` is empty, so a WG tunnel removed
   549	  while the daemon was DOWN is not in `oldWG` → not pruned by this fix.
   550	  This is the **same restart-adoption limitation** the rest of the file
   551	  has (the manager only prunes what it tracked applying). Document as a
   552	  known boundary; full restart-time WG reconciliation is #1434 scope.
   553	  (A reviewer may ask for a restart-time sweep — explicitly defer.)
   554	
   555	---
   556	
   557	## 9. Validation plan
   558	
   559	- `make test` — Go unit tests (new + existing routing tests).
   560	- `go test ./pkg/routing/...` focused run.

exec
/bin/bash -lc "nl -ba pkg/routing/tunnel.go | sed -n '1060,1130p'" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
  1060		t.keepalives = make(map[string]*keepaliveRunner)
  1061		for name, runner := range runners {
  1062			runner.cancel()
  1063			<-runner.done
  1064			slog.Debug("stopped keepalive", "tunnel", name)
  1065		}
  1066	}
  1067	
  1068	// stopKeepaliveLocked cancels, drains, and REMOVES the keepalive
  1069	// runner for one tunnel, if any. Removing the map entry matters
  1070	// (#1884 SMR2-2): a cancelled runner left behind would make
  1071	// GetKeepaliveState report a dead probe and would let the apply
  1072	// reconcile "retain" a corpse. Caller MUST hold mu.
  1073	func (t *tunnelManager) stopKeepaliveLocked(name string) {
  1074		runner, ok := t.keepalives[name]
  1075		if !ok {
  1076			return
  1077		}
  1078		runner.cancel()
  1079		<-runner.done
  1080		delete(t.keepalives, name)
  1081		slog.Debug("stopped keepalive", "tunnel", name)
  1082	}
  1083	
  1084	// startKeepalive starts a keepalive probe goroutine for a tunnel.
  1085	// source is the tunnel local endpoint IP the probe binds to (#1918
  1086	// §5c); "" → wildcard. Caller MUST hold mu.
  1087	func (t *tunnelManager) startKeepalive(tunnelName, source, remoteAddr string, interval, maxRetries int) {
  1088		// Stop existing keepalive for this tunnel if any. Drain on done
  1089		// so the replacement doesn't race the old goroutine on the handle.
  1090		t.stopKeepaliveLocked(tunnelName)
  1091	
  1092		if maxRetries <= 0 {
  1093			maxRetries = 3
  1094		}
  1095	
  1096		state := &KeepaliveState{
  1097			Up:         true,
  1098			RemoteAddr: remoteAddr,
  1099			SourceAddr: source,
  1100			Interval:   interval,
  1101			MaxRetries: maxRetries,
  1102		}
  1103	
  1104		// Capture the current generation token (#1918 §6 Axis D
  1105		// defense-in-depth). The runner reads it LOCK-FREE — it never takes
  1106		// t.mu — so an Apply blocked on the drain can never deadlock a tick.
  1107		gen := t.linkGenForLocked(tunnelName)
  1108		startGen := gen.Load()
  1109	
  1110		ctx, cancel := context.WithCancel(context.Background())
  1111		done := make(chan struct{})
  1112		t.keepalives[tunnelName] = &keepaliveRunner{
  1113			cancel:     cancel,
  1114			state:      state,
  1115			done:       done,
  1116			remote:     remoteAddr,
  1117			source:     source,
  1118			interval:   interval,
  1119			maxRetries: maxRetries,
  1120			linkGen:    gen,
  1121			startGen:   startGen,
  1122		}
  1123	
  1124		prober := t.keepaliveProber()
  1125		go t.keepaliveLoop(ctx, done, tunnelName, state, prober, gen, startGen)
  1126		slog.Info("started keepalive", "tunnel", tunnelName,
  1127			"source", source, "remote", remoteAddr, "interval", interval, "retries", maxRetries)
  1128	}
  1129	
  1130	// keepaliveProbeDeadline returns the per-probe round-trip budget: a

exec
/bin/bash -lc "nl -ba pkg/routing/vrf.go | sed -n '130,170p'" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
   130		if err != nil {
   131			return fmt.Errorf("interface %s not found: %w", ifaceName, err)
   132		}
   133		vrf, err := v.ops.LinkByName(vrfName)
   134		if err != nil {
   135			return fmt.Errorf("VRF %s not found: %w", vrfName, err)
   136		}
   137		if err := v.ops.LinkSetMaster(iface, vrf); err != nil {
   138			return fmt.Errorf("bind %s to VRF %s: %w", ifaceName, vrfName, err)
   139		}
   140		slog.Info("interface bound to VRF", "interface", ifaceName, "vrf", vrfName)
   141		return nil
   142	}
   143	
   144	// errLinkNotFound is an internal sentinel wrapper used when the
   145	// manager generates its own "not found" errors (e.g. from fakes in
   146	// tests, or from any path not going through the netlink library).
   147	// netlink.LinkNotFoundError cannot be constructed outside the
   148	// netlink package because its embedded error field is unexported.
   149	type errLinkNotFound struct{ error }
   150	
   151	// isLinkNotFound reports whether err is a "link not found" error
   152	// from either the netlink library or the internal sentinel. Other
   153	// errors (EINVAL, EBUSY, transport failure) must NOT be treated as
   154	// absence.
   155	func isLinkNotFound(err error) bool {
   156		if err == nil {
   157			return false
   158		}
   159		var nlNotFound netlink.LinkNotFoundError
   160		if errors.As(err, &nlNotFound) {
   161			return true
   162		}
   163		var internal errLinkNotFound
   164		return errors.As(err, &internal)
   165	}
   166	
   167	// reconcileVRFs is the pure core of Reconcile, parameterised on a
   168	// vrfOps so tests can inject a fake. Returns the new tracked set and
   169	// the first error encountered (others are logged).
   170	//

exec
/bin/bash -lc "nl -ba pkg/routing/tunnel.go | sed -n '724,786p'" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
   724	func (t *tunnelManager) reconcileLinkAddrsLocked(link netlink.Link, name string, addrs []string, applied map[string]bool, kind string) map[string]bool {
   725		want := make(map[string]bool, len(addrs))
   726		for _, addrStr := range addrs {
   727			addr, parseErr := netlink.ParseAddr(addrStr)
   728			if parseErr != nil {
   729				slog.Warn("invalid "+kind+" address",
   730					"name", name, "addr", addrStr, "err", parseErr)
   731				continue
   732			}
   733			want[addr.IPNet.String()] = true
   734		}
   735		newApplied := make(map[string]bool, len(want))
   736		existing := map[string]bool{}
   737		if list, listErr := t.ops.AddrList(link, netlink.FAMILY_ALL); listErr == nil {
   738			for i := range list {
   739				a := list[i]
   740				key := a.IPNet.String()
   741				existing[key] = true
   742				if want[key] {
   743					continue
   744				}
   745				if a.IP == nil {
   746					// Defensive: the pre-#1884 WG block only deleted
   747					// addresses with a non-nil IP; keep that byte-identical
   748					// (and never delete something we cannot classify).
   749					continue
   750				}
   751				if a.IP.IsLinkLocalUnicast() && (applied == nil || !applied[key]) {
   752					// Kernel-managed or foreign link-local: never delete.
   753					continue
   754				}
   755				if delErr := t.ops.AddrDel(link, &a); delErr != nil {
   756					slog.Warn("failed to remove stale "+kind+" address",
   757						"name", name, "addr", key, "err", delErr)
   758					if a.IP != nil && a.IP.IsLinkLocalUnicast() {
   759						newApplied[key] = true // retry next apply
   760					}
   761				} else {
   762					slog.Info("removed stale "+kind+" address",
   763						"name", name, "addr", key)
   764				}
   765			}
   766		}
   767		for _, addrStr := range addrs {
   768			addr, parseErr := netlink.ParseAddr(addrStr)
   769			if parseErr != nil {
   770				continue
   771			}
   772			key := addr.IPNet.String()
   773			if existing[key] {
   774				newApplied[key] = true
   775				continue
   776			}
   777			if addErr := t.ops.AddrAdd(link, addr); addErr != nil {
   778				slog.Warn("failed to add "+kind+" address",
   779					"name", name, "addr", addrStr, "err", addErr)
   780			} else {
   781				newApplied[key] = true
   782			}
   783		}
   784		return newApplied
   785	}
   786	

exec
/bin/bash -lc "rg -n \"func \\(t \\*tunnelManager\\) clearLocked|clearLocked\\(\" pkg/routing/tunnel.go pkg/routing/*.go" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
pkg/routing/xfrm.go:27:	if err := x.clearLocked(); err != nil {
pkg/routing/xfrm.go:104:	return x.clearLocked()
pkg/routing/xfrm.go:109:func (x *xfrmManager) clearLocked() error {
pkg/routing/bond.go:28:	if err := b.clearLocked(); err != nil {
pkg/routing/bond.go:110:	return b.clearLocked()
pkg/routing/bond.go:115:func (b *bondManager) clearLocked() error {
pkg/routing/tunnel.go:1357:	return t.clearLocked()
pkg/routing/tunnel.go:1368:func (t *tunnelManager) clearLocked() error {
pkg/routing/tunnel.go:1357:	return t.clearLocked()
pkg/routing/tunnel.go:1368:func (t *tunnelManager) clearLocked() error {

exec
/bin/bash -lc "nl -ba pkg/routing/tunnel.go | sed -n '243,360p'" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
   243	// Apply reconciles the kernel tunnel devices against the desired
   244	// config WITHOUT the historical clear-all + delete-and-recreate
   245	// (#1884): an untouched tunnel keeps its netdev (stable ifindex — no
   246	// FRR route churn, no userspace-dp TUN-reader death per commit, see
   247	// #1881), tunnels removed from config are deleted via a set-diff
   248	// against the previous desired set, and a device is recreated only
   249	// when the existing kernel link is genuinely incompatible. Keepalive
   250	// probes (legacy non-anchor branch only) are reconciled by identity
   251	// instead of being restarted every apply.
   252	func (t *tunnelManager) Apply(tunnels []*config.TunnelConfig) error {
   253		t.mu.Lock()
   254		defer t.mu.Unlock()
   255		t.ensureReconcileStateLocked()
   256	
   257		desired := make(map[string]bool, len(tunnels))
   258		for _, tc := range tunnels {
   259			// WireGuard TUNs stay untracked/persistent (#1432 S2a, AGY
   260			// Hazard B) and are excluded from the removal diff.
   261			if tc.Mode != "wireguard" {
   262				desired[tc.Name] = true
   263			}
   264		}
   265	
   266		// oldOwned is the ENTRY-TIME ownership snapshot — the adoption
   267		// authority for the per-tunnel loop below (#1884 r2 Codex F1: the
   268		// rewritten set would mark every desired tunnel "owned" and make
   269		// adoption unreachable). next starts as the desired set; removal
   270		// failures retain their names so the next Apply retries instead of
   271		// orphaning a live link (r2 Codex F5).
   272		oldOwned := t.ownedNames
   273		next := make(map[string]bool, len(desired))
   274		for name := range desired {
   275			next[name] = true
   276		}
   277		for name := range oldOwned {
   278			if desired[name] {
   279				continue
   280			}
   281			t.stopKeepaliveLocked(name)
   282			if link, err := t.ops.LinkByName(name); err == nil {
   283				if delErr := t.ops.LinkDel(link); delErr != nil {
   284					slog.Warn("failed to delete removed tunnel",
   285						"name", name, "err", delErr)
   286					next[name] = true // retain ownership; retry next apply
   287					continue
   288				}
   289				slog.Info("tunnel removed", "name", name)
   290			}
   291			delete(t.appliedAddrs, name)
   292			delete(t.appliedRI, name)
   293		}
   294		t.ownedNames = next
   295		t.tunnels = nil // success-tracked (GetStatus); rebuilt below
   296	
   297		for _, tc := range tunnels {
   298			// WireGuard TUNs are persistent (#1432 S2a, AGY Hazard B): never
   299			// delete-and-recreate on reload — that would flap wgN and destroy
   300			// its addresses + FRR routes every commit. applyWireguardTunLocked
   301			// reuses an existing wgN in place.
   302			if tc.Mode == "wireguard" {
   303				if err := t.applyWireguardTunLocked(tc); err != nil {
   304					slog.Warn("failed to apply wireguard tunnel",
   305						"name", tc.Name, "err", err)
   306				}
   307				continue
   308			}
   309			// Adoption = this manager did NOT own the name at the last
   310			// apply (daemon restart, wireguard→gre same-name flip, foreign
   311			// but compatible TUN). Decided from the entry-time snapshot for
   312			// BOTH the plain-reuse and the LinkAdd-EEXIST paths.
   313			adopting := !oldOwned[tc.Name]
   314			if tc.AnchorOnly {
   315				t.applyAnchorLocked(tc, adopting)
   316				continue
   317			}
   318			t.applyKernelTunnelLocked(tc)
   319		}
   320	
   321		return nil
   322	}
   323	
   324	// anchorReusable reports whether an existing link can serve as the
   325	// userspace-dp TUN anchor in place (#1884 A.3): it must be a TUN (not
   326	// TAP/dummy/gre), carry NO_PI (the Rust side opens IFF_TUN|IFF_NO_PI —
   327	// userspace-dp/src/slowpath.rs; a PI-enabled foreign TUN would break
   328	// attach where recreate heals it), and be persistent (a non-persistent
   329	// TUN held alive only by a foreign fd would evaporate when that fd
   330	// closes). Kernel readback reconstructs Mode/NO_PI/persist via
   331	// IFLA_TUN_*; the obsolete ONE_QUEUE flag is not reported and not
   332	// checked.
   333	func anchorReusable(link netlink.Link) bool {
   334		tt, ok := link.(*netlink.Tuntap)
   335		if !ok || tt.Mode != netlink.TUNTAP_MODE_TUN {
   336			return false
   337		}
   338		if tt.Flags&netlink.TUNTAP_NO_PI == 0 {
   339			return false
   340		}
   341		return !tt.NonPersist
   342	}
   343	
   344	// applyAnchorLocked reconciles one AnchorOnly TUN device (the
   345	// production userspace-dp path). Caller MUST hold mu.
   346	func (t *tunnelManager) applyAnchorLocked(tc *config.TunnelConfig, adopting bool) {
   347		// A leftover keepalive runner (legacy→anchor mode change) must not
   348		// keep probing: anchors never run keepalives (probes LinkSetDown
   349		// the device on failure — a behavior the anchor path never had).
   350		t.stopKeepaliveLocked(tc.Name)
   351	
   352		var link netlink.Link
   353		created := false
   354		if existing, lookupErr := t.ops.LinkByName(tc.Name); lookupErr == nil {
   355			if anchorReusable(existing) {
   356				// Operate on the kernel-fetched link (real ifindex and
   357				// attributes), never a fresh ifindex-less struct (#1706).
   358				link = existing
   359				slog.Debug("tunnel anchor reused", "name", tc.Name)
   360			} else {

exec
/bin/bash -lc 'rg -n "writeManagedSection|assembleFRRConfig|WgAllowedIPs|AllowedIPs|direct|connected|redistribute|FullConfig" pkg/frr pkg/daemon pkg/config userspace-dp/src | head -n 120' in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
exec
/bin/bash -lc "nl -ba pkg/routing/tunnel_reconcile_test.go | sed -n '1,520p'" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
pkg/frr/vtysh.go:50:// frrExecutor is the package-private indirection that all vtysh and
pkg/frr/vtysh.go:103:// kills only the direct python process, which could leave a child
userspace-dp/src/protocol/control.rs:154:    // #710: cluster-wide aggregate of cross-worker CoS redirects that
userspace-dp/src/protocol/control.rs:165:    /// full (transient saturation under route churn); `warm_disconnected`
userspace-dp/src/protocol/control.rs:173:    #[serde(rename = "neighbor_warm_disconnected_total", default)]
userspace-dp/src/protocol/control.rs:174:    pub neighbor_warm_disconnected_total: u64,
userspace-dp/src/protocol/control.rs:251:    #[serde(rename = "neighbor_resolver_disconnected_total", default)]
userspace-dp/src/protocol/control.rs:252:    pub neighbor_resolver_disconnected_total: u64,
userspace-dp/src/protocol/control.rs:386:    #[serde(rename = "event_stream_connected", default)]
userspace-dp/src/protocol/control.rs:387:    pub event_stream_connected: bool,
pkg/frr/fbf_table_render_test.go:83:	fc := &FullConfig{
pkg/frr/fbf_table_render_test.go:144:	fc := &FullConfig{
userspace-dp/src/protocol/cos.rs:118:    /// unset-config wire stays byte-identical in BOTH directions
userspace-dp/src/protocol/cos.rs:345:    #[serde(rename = "redirect_acquire_hist", default)]
userspace-dp/src/protocol/cos.rs:346:    pub redirect_acquire_hist: Vec<u64>,
userspace-dp/src/slowpath.rs:223:            Err(TrySendError::Disconnected(req)) => {
userspace-dp/src/protocol/binding.rs:185:    /// be false with the direct slot map; true = builder bug).
userspace-dp/src/protocol/binding.rs:192:    /// 0..=64 direct-table range. Surfaced so operators see when a
userspace-dp/src/protocol/binding.rs:475:    // redirect-inbox overflow path in `BindingLiveState::enqueue_tx` /
userspace-dp/src/protocol/binding.rs:476:    // `enqueue_tx_owned`. Indicates the owner is not draining redirects
userspace-dp/src/protocol/binding.rs:477:    // fast enough for the rate of incoming redirects from non-owner
userspace-dp/src/protocol/binding.rs:479:    #[serde(rename = "redirect_inbox_overflow_drops", default)]
userspace-dp/src/protocol/binding.rs:480:    pub redirect_inbox_overflow_drops: u64,
userspace-dp/src/protocol/binding.rs:483:    // cannot ingest redirected traffic into CoS as fast as it arrives
userspace-dp/src/protocol/binding.rs:492:    // the flow-fair admission / redirect-inbox / pending-FIFO drops.
userspace-dp/src/protocol/binding.rs:539:    #[serde(rename = "direct_tx_packets", default)]
userspace-dp/src/protocol/binding.rs:540:    pub direct_tx_packets: u64,
userspace-dp/src/protocol/binding.rs:553:    #[serde(rename = "direct_tx_no_frame_fallback_packets", default)]
userspace-dp/src/protocol/binding.rs:554:    pub direct_tx_no_frame_fallback_packets: u64,
userspace-dp/src/protocol/binding.rs:555:    #[serde(rename = "direct_tx_build_fallback_packets", default)]
userspace-dp/src/protocol/binding.rs:556:    pub direct_tx_build_fallback_packets: u64,
userspace-dp/src/protocol/binding.rs:557:    #[serde(rename = "direct_tx_disallowed_fallback_packets", default)]
userspace-dp/src/protocol/binding.rs:558:    pub direct_tx_disallowed_fallback_packets: u64,
userspace-dp/src/protocol/binding.rs:1040:    #[serde(rename = "fabric_redirect", default)]
userspace-dp/src/protocol/binding.rs:1041:    pub fabric_redirect: bool,
pkg/frr/manager.go:5://     orchestration + writeManagedSection + reload.
pkg/frr/manager.go:10://     ISIS, policy-options, redistribute, BFD profile
pkg/frr/manager.go:242:// FullConfig holds the complete routing config for a single FRR apply.
pkg/frr/manager.go:243:type FullConfig struct {
pkg/frr/manager.go:296:	// zone-encoded fabric redirect for new connections.  The real default
pkg/frr/manager.go:304:	// pkg/ipmon, supplied by the daemon's assembleFRRConfig for BOTH
pkg/frr/manager.go:313:// here. They built a partial FullConfig inline, bypassing the daemon's
pkg/frr/manager.go:314:// assembleFRRConfig — the sole production FullConfig constructor — so
pkg/frr/manager.go:318:// must go through the daemon's assembleFRRConfig; pkg/daemon's
pkg/frr/manager.go:319:// TestFRRFullConfigConstructedOnlyByAssembler guard enforces this.
pkg/frr/manager.go:341:func (m *Manager) ApplyFull(fc *FullConfig) error {
pkg/frr/manager.go:388:	// 6. Cluster mode: blackhole default route as fallback for fabric redirect.
pkg/frr/manager.go:465:	if err := m.writeManagedSection(section); err != nil {
pkg/frr/manager.go:487:// writeManagedSection replaces the xpf-managed section in frr.conf.
pkg/frr/manager.go:489:func (m *Manager) writeManagedSection(section string) error {
pkg/frr/manager.go:537:	// Write atomically: a temp file in the same directory followed by rename,
pkg/frr/manager.go:551:// handled in writeManagedSection).
pkg/frr/manager.go:563:// parent-directory fsync that was missing here, making the rename
pkg/frr/manager.go:640://     the slow cadence directly.
userspace-dp/src/main_tests.rs:275:    // userspace DP can transmit fabric-redirect packets.
userspace-dp/src/main.rs:5:// binary includes it directly via `#[path]`. No production code in main.rs
pkg/frr/README.md:9:kernel routes — and it doesn't, directly. It writes config and reloads
pkg/frr/README.md:26:| `manager.go` | `Manager` struct + lifecycle (`New`, `ApplyFull`, `Clear`, `writeManagedSection`, `reload`), top-level types (`InstanceConfig`, `DHCPRoute`, `FullConfig`), package constants, and the zero-value-safe `executor()` accessor. The legacy `Apply`/`ApplyWithInstances` partial constructors were deleted (#1827 AGY F1, PR #1843): they bypassed `assembleFRRConfig` and would have wiped an active failover overlay. |
pkg/frr/README.md:37:- `ApplyFull(fc *FullConfig) error` — `manager.go`. Apply full config
pkg/frr/README.md:39:- `FullConfig`, `InstanceConfig`, `DHCPRoute` — `manager.go`.
pkg/frr/README.md:48:`FullConfig.PreferredRoutes` (#1827) carries the ip-monitoring
pkg/frr/README.md:49:effective-route overlay; the daemon's `assembleFRRConfig` is the sole
pkg/frr/README.md:50:`FullConfig` constructor for both the full apply path and the
pkg/frr/README.md:97:  ends with systemd SIGKILLing all FRR daemons. The direct invocation
pkg/config/parser_ast_test.go:2777:// CompileConfig directly, Store.CommitCheck (raw), or Store.Commit
pkg/config/parser_ast_test.go:3042:	// Default: omitting rss-indirection leaves RSSIndirectionDisabled at
pkg/config/parser_ast_test.go:3045:	if dp.RSSIndirectionDisabled {
pkg/config/parser_ast_test.go:3046:		t.Errorf("RSSIndirectionDisabled = true by default, want false")
pkg/config/parser_ast_test.go:3235:// #797 HIGH/MEDIUM: operator must be able to toggle D3 RSS indirection
pkg/config/parser_ast_test.go:3236:// via a first-class config knob. Setting `rss-indirection disable`
pkg/config/parser_ast_test.go:3237:// must compile to RSSIndirectionDisabled=true; `enable` (or anything
pkg/config/parser_ast_test.go:3239:func TestUserspaceDataplaneRSSIndirectionDisable(t *testing.T) {
pkg/config/parser_ast_test.go:3245:		{"disable_sets_true", "set system dataplane rss-indirection disable", true},
pkg/config/parser_ast_test.go:3246:		{"enable_leaves_false", "set system dataplane rss-indirection enable", false},
pkg/config/parser_ast_test.go:3276:			if dp.RSSIndirectionDisabled != tc.want {
pkg/config/parser_ast_test.go:3277:				t.Fatalf("RSSIndirectionDisabled=%v, want %v",
pkg/config/parser_ast_test.go:3278:					dp.RSSIndirectionDisabled, tc.want)
pkg/config/parser_ast_test.go:3286:// dataplane` alongside the existing rss-indirection switch.
pkg/config/parser_ast_test.go:3477:	cmds := []string{"set policy-options community MY-COMM members 65000:100", "set policy-options community MY-COMM members 65000:200", "set policy-options community NO-EXPORT members no-export", "set policy-options policy-statement OSPF-EXPORT term t1 from protocol direct", "set policy-options policy-statement OSPF-EXPORT term t1 from community MY-COMM", "set policy-options policy-statement OSPF-EXPORT term t1 then metric-type 1", "set policy-options policy-statement OSPF-EXPORT term t1 then metric 100", "set policy-options policy-statement OSPF-EXPORT term t1 then accept", "set policy-options policy-statement OSPF-EXPORT term t2 then metric-type 2", "set policy-options policy-statement OSPF-EXPORT term t2 then reject"}
pkg/config/parser_ast_test.go:3517:	if t1.FromProtocol != "direct" {
pkg/config/parser_ast_test.go:3518:		t.Errorf("t1 from protocol = %q, want direct", t1.FromProtocol)
userspace-dp/src/protocol/tests.rs:831:// both directions of the contract here.
userspace-dp/src/protocol/tests.rs:1211:// connected/seq/acked). The matching Go decode tests live in
userspace-dp/src/protocol/tests.rs:1358:        event_stream_connected: true,
userspace-dp/src/protocol/tests.rs:1365:    assert_eq!(value["event_stream_connected"], true);
userspace-dp/src/nat64_tests.rs:557:// in BOTH directions. Before the fix the IPv4 TOS byte / IPv6 traffic class was
userspace-dp/src/nat64_tests.rs:642:    // Translate the IPv4 packet back to IPv6 (reply direction reuses the same
userspace-dp/src/server/helpers.rs:53:    let (warm_drops, warm_disconnected) = state.afxdp.neighbor_warm_counters();
userspace-dp/src/server/helpers.rs:55:    state.status.neighbor_warm_disconnected_total = warm_disconnected;
userspace-dp/src/server/helpers.rs:109:    state.status.neighbor_resolver_disconnected_total = r.disconnected;
userspace-dp/src/server/helpers.rs:255:        state.status.event_stream_connected = es_stats.connected;
userspace-dp/src/server/helpers.rs:724:        // fabric-redirect packets via XSK TX (and receive fabric ingress).
pkg/frr/policy_render.go:56:// knownRedistProtocols are the FRR redistribute protocol keywords.
pkg/frr/policy_render.go:58:	"connected": true, "static": true, "ospf": true, "bgp": true,
pkg/frr/policy_render.go:62:// resolveRedistribute converts a Junos export value into FRR redistribute commands.
pkg/frr/policy_render.go:63:// If the value is a known protocol name, it emits a bare "redistribute <proto>".
pkg/frr/policy_render.go:65:// "redistribute <proto> route-map <name>" for each.
pkg/frr/policy_render.go:68:		return fmt.Sprintf(" redistribute %s\n", export)
pkg/frr/policy_render.go:77:					if proto == "direct" {
pkg/frr/policy_render.go:78:						proto = "connected"
pkg/frr/policy_render.go:91:					fmt.Fprintf(&sb, " redistribute %s route-map %s\n", proto, export)
pkg/frr/policy_render.go:98:	// Fallback: treat as bare redistribute (best-effort)
pkg/frr/policy_render.go:99:	return fmt.Sprintf(" redistribute %s\n", export)
pkg/frr/policy_render.go:152:				// instance (#1712). passive-interface directives are
pkg/frr/policy_render.go:643:				if proto == "direct" {
pkg/frr/policy_render.go:644:					proto = "connected"
userspace-dp/src/protocol/snapshot.rs:359:    /// this as the encap key — not AllowedIPs LPM. See plan §
userspace-dp/src/protocol/snapshot.rs:363:    /// Peer AllowedIPs, as CIDR strings. Only consulted on the
userspace-dp/src/server/README.md:68:`pkg/daemon/rss_indirection.go` reshapes RSS indirection only on
pkg/config/compiler_interfaces.go:312:			//   Keys=["family","inet"], children are address/dhcp directly
pkg/config/compiler_interfaces.go:712:				tc.WgAllowedIPs = append(tc.WgAllowedIPs, v)
pkg/config/compiler_interfaces.go:763://   - an orphan `priority-cost` child directly under the vrrp-group
pkg/frr/config_render.go:28:func (m *Manager) generateInterfaceSettings(fc *FullConfig) string {
pkg/frr/config_render.go:175:func renderGenerateRoutes(b *strings.Builder, fc *FullConfig) {
pkg/frr/config_render.go:193:func renderDHCPDefaults(b *strings.Builder, fc *FullConfig) {
pkg/frr/config_render.go:237:func renderBackupRouter(b *strings.Builder, fc *FullConfig) {
pkg/frr/config_render.go:261:func (m *Manager) renderPreferredRoutes(b *strings.Builder, fc *FullConfig) {
pkg/frr/config_render.go:297:// fabric redirect for new connections. AD=250 ensures real defaults (AD=5,
pkg/frr/config_render.go:299:func renderClusterModeDefaults(b *strings.Builder, fc *FullConfig) {
pkg/frr/config_render.go:318:func resolveECMP(fc *FullConfig) int {

 succeeded in 0ms:
     1	package routing
     2	
     3	import (
     4		"errors"
     5		"net"
     6		"testing"
     7	
     8		"github.com/psaab/xpf/pkg/config"
     9		"github.com/vishvananda/netlink"
    10	)
    11	
    12	// #1884 reconcile-in-place tests. tunnelManager.Apply must not delete
    13	// and recreate untouched tunnel devices on every apply (the gr-X flap
    14	// that killed the userspace-dp TUN readers per commit); removals are a
    15	// set-diff against the previous DESIRED set; reuse paths explicitly
    16	// reconcile addresses, VRF claims, MTU, and keepalives.
    17	
    18	// fakeVRFBinder mimics vrfManager.BindInterfaceToVRF against the
    19	// fakeLinkOps store: a successful bind sets the interface's
    20	// MasterIndex to the vrf-<ri> device's index (the daemon-prefixed VRF
    21	// naming, vrf.go BindInterfaceToVRF).
    22	type fakeVRFBinder struct {
    23		ops  *fakeLinkOps
    24		fail map[string]error // ri name -> bind error injection
    25	}
    26	
    27	func (b *fakeVRFBinder) BindInterfaceToVRF(ifaceName, instanceName string) error {
    28		if err, ok := b.fail[instanceName]; ok {
    29			return err
    30		}
    31		iface, ok := b.ops.links[ifaceName]
    32		if !ok {
    33			return errors.New("interface not found")
    34		}
    35		vrf, ok := b.ops.links["vrf-"+instanceName]
    36		if !ok {
    37			return errors.New("vrf not found")
    38		}
    39		iface.Attrs().MasterIndex = vrf.Attrs().Index
    40		return nil
    41	}
    42	
    43	func newReconcileManager(ops *fakeLinkOps) (*tunnelManager, *fakeVRFBinder) {
    44		binder := &fakeVRFBinder{ops: ops, fail: map[string]error{}}
    45		return &tunnelManager{
    46			ops:        ops,
    47			vrfBinder:  binder,
    48			keepalives: map[string]*keepaliveRunner{},
    49		}, binder
    50	}
    51	
    52	func seedVRF(ops *fakeLinkOps, ri string, index int) {
    53		ops.links["vrf-"+ri] = &netlink.Vrf{
    54			LinkAttrs: netlink.LinkAttrs{Name: "vrf-" + ri, Index: index},
    55		}
    56	}
    57	
    58	// seedAnchor seeds a kernel-shaped reusable anchor TUN.
    59	func seedAnchor(ops *fakeLinkOps, name string, index, mtu int) *netlink.Tuntap {
    60		tt := &netlink.Tuntap{
    61			LinkAttrs: netlink.LinkAttrs{Name: name, Index: index, MTU: mtu},
    62			Mode:      netlink.TUNTAP_MODE_TUN,
    63			Flags:     netlink.TUNTAP_NO_PI,
    64		}
    65		ops.links[name] = tt
    66		return tt
    67	}
    68	
    69	func anchorTC(name string, addrs ...string) *config.TunnelConfig {
    70		return &config.TunnelConfig{Name: name, AnchorOnly: true, Addresses: addrs}
    71	}
    72	
    73	// --- §9 test 1: untouched tunnel ⇒ untouched netdev -----------------
    74	
    75	func TestTunnelApplySecondApplyNoChurn(t *testing.T) {
    76		ops := newFakeLinkOps()
    77		tm, _ := newReconcileManager(ops)
    78		tcs := []*config.TunnelConfig{anchorTC("gr-0-0-0", "10.1.2.3/32")}
    79	
    80		if err := tm.Apply(tcs); err != nil {
    81			t.Fatalf("Apply 1: %v", err)
    82		}
    83		if len(ops.delNames) != 0 {
    84			t.Fatalf("first apply deleted links: %v", ops.delNames)
    85		}
    86		created := ops.links["gr-0-0-0"]
    87		if created == nil {
    88			t.Fatal("anchor not created")
    89		}
    90		addAddsAfterFirst := len(ops.addrLinks)
    91	
    92		if err := tm.Apply(tcs); err != nil {
    93			t.Fatalf("Apply 2: %v", err)
    94		}
    95		if len(ops.delNames) != 0 {
    96			t.Fatalf("second apply deleted links (the #1884 flap): %v", ops.delNames)
    97		}
    98		if ops.links["gr-0-0-0"] != created {
    99			t.Fatal("second apply replaced the anchor link object")
   100		}
   101		if got := len(ops.addrLinks); got != addAddsAfterFirst {
   102			t.Fatalf("second apply re-added addresses: AddrAdd count %d, want %d",
   103				got, addAddsAfterFirst)
   104		}
   105		if got := len(ops.addrDels["gr-0-0-0"]); got != 0 {
   106			t.Fatalf("second apply deleted addresses: %v", ops.addrDels["gr-0-0-0"])
   107		}
   108		if got := len(ops.mtuSet["gr-0-0-0"]); got != 0 {
   109			t.Fatalf("owned reuse with unconfigured MTU wrote MTU: %v", ops.mtuSet["gr-0-0-0"])
   110		}
   111	}
   112	
   113	// --- §9 test 2: restart adoption + MTU ownership ---------------------
   114	
   115	func TestTunnelAnchorRestartAdoptionNormalizesMTU(t *testing.T) {
   116		ops := newFakeLinkOps()
   117		seedAnchor(ops, "gr-0-0-0", 42, 1420) // WG-leftover-ish MTU
   118		tm, _ := newReconcileManager(ops)
   119	
   120		// Fresh manager (ownedNames empty) = restart adoption; tc.MTU == 0
   121		// ⇒ one-time normalization to the TUN default.
   122		if err := tm.Apply([]*config.TunnelConfig{anchorTC("gr-0-0-0")}); err != nil {
   123			t.Fatalf("Apply: %v", err)
   124		}
   125		if len(ops.delNames) != 0 {
   126			t.Fatalf("adoption recreated the anchor: %v", ops.delNames)
   127		}
   128		if got := ops.mtuSet["gr-0-0-0"]; len(got) != 1 || got[0] != 1500 {
   129			t.Fatalf("adoption MTU writes = %v, want exactly [1500]", got)
   130		}
   131	
   132		// Owned reuse, tc.MTU == 0, MTU drifted out-of-band ⇒ NOT touched.
   133		ops.links["gr-0-0-0"].Attrs().MTU = 1400
   134		if err := tm.Apply([]*config.TunnelConfig{anchorTC("gr-0-0-0")}); err != nil {
   135			t.Fatalf("Apply 2: %v", err)
   136		}
   137		if got := ops.mtuSet["gr-0-0-0"]; len(got) != 1 {
   138			t.Fatalf("owned reuse with tc.MTU==0 wrote MTU: %v", got)
   139		}
   140	}
   141	
   142	func TestTunnelAnchorConfiguredMTUReconciledOnReuse(t *testing.T) {
   143		ops := newFakeLinkOps()
   144		seedAnchor(ops, "gr-0-0-0", 42, 1420)
   145		tm, _ := newReconcileManager(ops)
   146	
   147		tc := anchorTC("gr-0-0-0")
   148		tc.MTU = 9000
   149		if err := tm.Apply([]*config.TunnelConfig{tc}); err != nil {
   150			t.Fatalf("Apply: %v", err)
   151		}
   152		if got := ops.mtuSet["gr-0-0-0"]; len(got) != 1 || got[0] != 9000 {
   153			t.Fatalf("adoption with config MTU writes = %v, want [9000]", got)
   154		}
   155	
   156		// Owned reuse with config MTU and drift ⇒ reconciled (the compiler
   157		// stage only restores ZONED interfaces; unzoned tunnels have no
   158		// other MTU writer).
   159		ops.links["gr-0-0-0"].Attrs().MTU = 1400
   160		if err := tm.Apply([]*config.TunnelConfig{tc}); err != nil {
   161			t.Fatalf("Apply 2: %v", err)
   162		}
   163		if got := ops.mtuSet["gr-0-0-0"]; len(got) != 2 || got[1] != 9000 {
   164			t.Fatalf("owned reuse with config MTU writes = %v, want [9000 9000]", got)
   165		}
   166	}
   167	
   168	func TestTunnelAnchorCreateAppliesConfigMTU(t *testing.T) {
   169		ops := newFakeLinkOps()
   170		tm, _ := newReconcileManager(ops)
   171		tc := anchorTC("gr-0-0-0")
   172		tc.MTU = 9000
   173		if err := tm.Apply([]*config.TunnelConfig{tc}); err != nil {
   174			t.Fatalf("Apply: %v", err)
   175		}
   176		if got := ops.mtuSet["gr-0-0-0"]; len(got) != 1 || got[0] != 9000 {
   177			t.Fatalf("create with config MTU writes = %v, want [9000]", got)
   178		}
   179	}
   180	
   181	// --- §9 test 3: incompatible existing links are recreated ------------
   182	
   183	func TestTunnelAnchorIncompatibleLinksRecreated(t *testing.T) {
   184		cases := []struct {
   185			name string
   186			link netlink.Link
   187		}{
   188			{"dummy", &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "gr-0-0-0", Index: 9}}},
   189			{"pi-tun", &netlink.Tuntap{
   190				LinkAttrs: netlink.LinkAttrs{Name: "gr-0-0-0", Index: 9},
   191				Mode:      netlink.TUNTAP_MODE_TUN, // no NO_PI flag
   192			}},
   193			{"tap", &netlink.Tuntap{
   194				LinkAttrs: netlink.LinkAttrs{Name: "gr-0-0-0", Index: 9},
   195				Mode:      netlink.TUNTAP_MODE_TAP,
   196				Flags:     netlink.TUNTAP_NO_PI,
   197			}},
   198			{"non-persistent", &netlink.Tuntap{
   199				LinkAttrs:  netlink.LinkAttrs{Name: "gr-0-0-0", Index: 9},
   200				Mode:       netlink.TUNTAP_MODE_TUN,
   201				Flags:      netlink.TUNTAP_NO_PI,
   202				NonPersist: true,
   203			}},
   204		}
   205		for _, tcase := range cases {
   206			t.Run(tcase.name, func(t *testing.T) {
   207				ops := newFakeLinkOps()
   208				ops.links["gr-0-0-0"] = tcase.link
   209				tm, _ := newReconcileManager(ops)
   210				if err := tm.Apply([]*config.TunnelConfig{anchorTC("gr-0-0-0")}); err != nil {
   211					t.Fatalf("Apply: %v", err)
   212				}
   213				if len(ops.delNames) != 1 || ops.delNames[0] != "gr-0-0-0" {
   214					t.Fatalf("incompatible link not deleted: delNames=%v", ops.delNames)
   215				}
   216				if ops.links["gr-0-0-0"] == tcase.link {
   217					t.Fatal("incompatible link not replaced")
   218				}
   219				if _, ok := ops.links["gr-0-0-0"].(*netlink.Tuntap); !ok {
   220					t.Fatalf("replacement is %T, want *netlink.Tuntap", ops.links["gr-0-0-0"])
   221				}
   222			})
   223		}
   224	}
   225	
   226	// --- §9 test 4: removal diff + retention on failed delete ------------
   227	
   228	func TestTunnelRemovedFromConfigDeleted(t *testing.T) {
   229		ops := newFakeLinkOps()
   230		tm, _ := newReconcileManager(ops)
   231		both := []*config.TunnelConfig{anchorTC("gr-0-0-0"), anchorTC("gr-0-0-1")}
   232		if err := tm.Apply(both); err != nil {
   233			t.Fatalf("Apply 1: %v", err)
   234		}
   235		keepA := ops.links["gr-0-0-0"]
   236	
   237		if err := tm.Apply(both[:1]); err != nil {
   238			t.Fatalf("Apply 2: %v", err)
   239		}
   240		if _, ok := ops.links["gr-0-0-1"]; ok {
   241			t.Fatal("removed tunnel gr-0-0-1 still exists")
   242		}
   243		if ops.links["gr-0-0-0"] != keepA {
   244			t.Fatal("survivor gr-0-0-0 was churned by the removal")
   245		}
   246	}
   247	
   248	func TestTunnelRemovalRetriedAfterFailedDelete(t *testing.T) {
   249		ops := newFakeLinkOps()
   250		tm, _ := newReconcileManager(ops)
   251		both := []*config.TunnelConfig{anchorTC("gr-0-0-0"), anchorTC("gr-0-0-1")}
   252		if err := tm.Apply(both); err != nil {
   253			t.Fatalf("Apply 1: %v", err)
   254		}
   255	
   256		ops.delFail["gr-0-0-1"] = errors.New("EBUSY")
   257		if err := tm.Apply(both[:1]); err != nil {
   258			t.Fatalf("Apply 2: %v", err)
   259		}
   260		if _, ok := ops.links["gr-0-0-1"]; !ok {
   261			t.Fatal("link unexpectedly gone despite failed delete")
   262		}
   263	
   264		// Ownership retained ⇒ the NEXT apply retries and succeeds.
   265		delete(ops.delFail, "gr-0-0-1")
   266		if err := tm.Apply(both[:1]); err != nil {
   267			t.Fatalf("Apply 3: %v", err)
   268		}
   269		if _, ok := ops.links["gr-0-0-1"]; ok {
   270			t.Fatal("removal not retried after ownership retention (r2 Codex F5)")
   271		}
   272	}
   273	
   274	// --- §9 test 5: address reconcile + link-local rules ------------------
   275	
   276	func TestTunnelAddressEditReconcilesInPlace(t *testing.T) {
   277		ops := newFakeLinkOps()
   278		tm, _ := newReconcileManager(ops)
   279		if err := tm.Apply([]*config.TunnelConfig{anchorTC("gr-0-0-0", "10.1.2.3/32")}); err != nil {
   280			t.Fatalf("Apply 1: %v", err)
   281		}
   282		if err := tm.Apply([]*config.TunnelConfig{anchorTC("gr-0-0-0", "10.9.9.9/32")}); err != nil {
   283			t.Fatalf("Apply 2: %v", err)
   284		}
   285		if len(ops.delNames) != 0 {
   286			t.Fatalf("address edit recreated the link: %v", ops.delNames)
   287		}
   288		if ops.hasAddr("gr-0-0-0", "10.1.2.3/32") {
   289			t.Fatal("stale address not removed")
   290		}
   291		if !ops.hasAddr("gr-0-0-0", "10.9.9.9/32") {
   292			t.Fatal("new address not added")
   293		}
   294	}
   295	
   296	func TestTunnelLinkLocalRules(t *testing.T) {
   297		ops := newFakeLinkOps()
   298		tm, _ := newReconcileManager(ops)
   299	
   300		// Apply with a CONFIGURED fe80 — recorded in appliedAddrs.
   301		if err := tm.Apply([]*config.TunnelConfig{anchorTC("gr-0-0-0", "fe80::8/64")}); err != nil {
   302			t.Fatalf("Apply 1: %v", err)
   303		}
   304		// Simulate the kernel's autoconf link-local appearing too.
   305		kernelLL, _ := netlink.ParseAddr("fe80::5054:ff:fe12:3456/64")
   306		ops.addrs["gr-0-0-0"] = append(ops.addrs["gr-0-0-0"], *kernelLL)
   307	
   308		// Remove the configured fe80: it must be deleted (it is ours), the
   309		// kernel's autoconf fe80 must survive (r1 Codex F2 split).
   310		if err := tm.Apply([]*config.TunnelConfig{anchorTC("gr-0-0-0")}); err != nil {
   311			t.Fatalf("Apply 2: %v", err)
   312		}
   313		if ops.hasAddr("gr-0-0-0", "fe80::8/64") {
   314			t.Fatal("configured fe80 leaked after removal from config")
   315		}
   316		if !ops.hasAddr("gr-0-0-0", "fe80::5054:ff:fe12:3456/64") {
   317			t.Fatal("kernel autoconf fe80 was deleted")
   318		}
   319	}
   320	
   321	func TestTunnelLinkLocalDeleteFailureRetried(t *testing.T) {
   322		ops := newFakeLinkOps()
   323		tm, _ := newReconcileManager(ops)
   324		if err := tm.Apply([]*config.TunnelConfig{anchorTC("gr-0-0-0", "fe80::8/64")}); err != nil {
   325			t.Fatalf("Apply 1: %v", err)
   326		}
   327	
   328		ops.addrDelFail["gr-0-0-0|fe80::8/64"] = errors.New("EBUSY")
   329		if err := tm.Apply([]*config.TunnelConfig{anchorTC("gr-0-0-0")}); err != nil {
   330			t.Fatalf("Apply 2: %v", err)
   331		}
   332		if !ops.hasAddr("gr-0-0-0", "fe80::8/64") {
   333			t.Fatal("address gone despite injected delete failure")
   334		}
   335	
   336		// Failed delete keeps the LL tracked (r2 Codex F4) ⇒ retried.
   337		delete(ops.addrDelFail, "gr-0-0-0|fe80::8/64")
   338		if err := tm.Apply([]*config.TunnelConfig{anchorTC("gr-0-0-0")}); err != nil {
   339			t.Fatalf("Apply 3: %v", err)
   340		}
   341		if ops.hasAddr("gr-0-0-0", "fe80::8/64") {
   342			t.Fatal("failed-delete fe80 not retried (dropped from appliedAddrs)")
   343		}
   344	}
   345	
   346	// --- #1905: WG branch shares the applied-address record ---------------
   347	
   348	func wgTC(addrs ...string) *config.TunnelConfig {
   349		return &config.TunnelConfig{Name: "wg0", Mode: "wireguard", Addresses: addrs}
   350	}
   351	
   352	// A CONFIGURED fe80 on the persistent wgN TUN, later removed from
   353	// config, must be reconciled away (pre-#1905 it leaked forever via the
   354	// nil applied-set sentinel) — while the kernel's autoconf fe80 on the
   355	// same device survives, exactly the GRE-branch split.
   356	func TestWireguardConfiguredLinkLocalRemoved(t *testing.T) {
   357		ops := newFakeLinkOps()
   358		tm, _ := newReconcileManager(ops)
   359		if err := tm.Apply([]*config.TunnelConfig{wgTC("10.77.0.1/24", "fe80::8/64")}); err != nil {
   360			t.Fatalf("Apply 1: %v", err)
   361		}
   362		if !ops.hasAddr("wg0", "fe80::8/64") {
   363			t.Fatal("configured fe80 not applied")
   364		}
   365		// Simulate the kernel's autoconf link-local appearing too.
   366		kernelLL, _ := netlink.ParseAddr("fe80::5054:ff:fe12:3456/64")
   367		ops.addrs["wg0"] = append(ops.addrs["wg0"], *kernelLL)
   368	
   369		if err := tm.Apply([]*config.TunnelConfig{wgTC("10.77.0.1/24")}); err != nil {
   370			t.Fatalf("Apply 2: %v", err)
   371		}
   372		if ops.hasAddr("wg0", "fe80::8/64") {
   373			t.Fatal("configured fe80 leaked after removal from config (#1905)")
   374		}
   375		if !ops.hasAddr("wg0", "fe80::5054:ff:fe12:3456/64") {
   376			t.Fatal("kernel autoconf fe80 was deleted")
   377		}
   378		if !ops.hasAddr("wg0", "10.77.0.1/24") {
   379			t.Fatal("configured non-LL address lost")
   380		}
   381		// The persistent device must not have been recreated by any of this.
   382		if len(ops.delNames) != 0 {
   383			t.Fatalf("wg0 was deleted/recreated: %v", ops.delNames)
   384		}
   385	}
   386	
   387	// Adoption pass: an fe80 already on the device before this manager's
   388	// first apply (daemon restart over a persistent wgN) is untracked and
   389	// must never be deleted, even once it is absent from config.
   390	func TestWireguardForeignLinkLocalNeverDeleted(t *testing.T) {
   391		ops := newFakeLinkOps()
   392		seedAnchor(ops, "wg0", 7, 1412)
   393		preLL, _ := netlink.ParseAddr("fe80::dead/64")
   394		ops.addrs["wg0"] = append(ops.addrs["wg0"], *preLL)
   395		tm, _ := newReconcileManager(ops)
   396	
   397		for i := 0; i < 2; i++ { // adoption pass AND a tracked second pass
   398			if err := tm.Apply([]*config.TunnelConfig{wgTC("10.77.0.1/24")}); err != nil {
   399				t.Fatalf("Apply %d: %v", i+1, err)
   400			}
   401			if !ops.hasAddr("wg0", "fe80::dead/64") {
   402				t.Fatalf("pre-existing fe80 deleted on apply %d", i+1)
   403			}
   404		}
   405	}
   406	
   407	// Failed fe80 stale-delete on the WG branch stays tracked and is
   408	// retried on the next apply (parity with the GRE-branch r2 Codex F4
   409	// retry).
   410	func TestWireguardLinkLocalDeleteFailureRetried(t *testing.T) {
   411		ops := newFakeLinkOps()
   412		tm, _ := newReconcileManager(ops)
   413		if err := tm.Apply([]*config.TunnelConfig{wgTC("fe80::8/64")}); err != nil {
   414			t.Fatalf("Apply 1: %v", err)
   415		}
   416	
   417		ops.addrDelFail["wg0|fe80::8/64"] = errors.New("EBUSY")
   418		if err := tm.Apply([]*config.TunnelConfig{wgTC()}); err != nil {
   419			t.Fatalf("Apply 2: %v", err)
   420		}
   421		if !ops.hasAddr("wg0", "fe80::8/64") {
   422			t.Fatal("address gone despite injected delete failure")
   423		}
   424	
   425		delete(ops.addrDelFail, "wg0|fe80::8/64")
   426		if err := tm.Apply([]*config.TunnelConfig{wgTC()}); err != nil {
   427			t.Fatalf("Apply 3: %v", err)
   428		}
   429		if ops.hasAddr("wg0", "fe80::8/64") {
   430			t.Fatal("failed-delete fe80 not retried (dropped from appliedAddrs)")
   431		}
   432	}
   433	
   434	// --- §9 test 6: appliedRI claim state machine -------------------------
   435	
   436	func TestTunnelVRFStanzaBindAndUnbind(t *testing.T) {
   437		ops := newFakeLinkOps()
   438		seedVRF(ops, "red", 100)
   439		tm, _ := newReconcileManager(ops)
   440	
   441		tc := anchorTC("gr-0-0-0")
   442		tc.RoutingInstance = "red"
   443		if err := tm.Apply([]*config.TunnelConfig{tc}); err != nil {
   444			t.Fatalf("Apply 1: %v", err)
   445		}
   446		if got := ops.links["gr-0-0-0"].Attrs().MasterIndex; got != 100 {
   447			t.Fatalf("stanza bind did not enslave: master=%d", got)
   448		}
   449	
   450		// Stanza removed, no list ⇒ identity-gated unbind of OUR master.
   451		if err := tm.Apply([]*config.TunnelConfig{anchorTC("gr-0-0-0")}); err != nil {
   452			t.Fatalf("Apply 2: %v", err)
   453		}
   454		if len(ops.noMaster) != 1 || ops.noMaster[0] != "gr-0-0-0" {
   455			t.Fatalf("expected exactly one LinkSetNoMaster, got %v", ops.noMaster)
   456		}
   457		if tm.appliedRI["gr-0-0-0"] != "" {
   458			t.Fatalf("claim not cleared after unbind: %q", tm.appliedRI["gr-0-0-0"])
   459		}
   460	
   461		// Idempotent: nothing further to unbind.
   462		if err := tm.Apply([]*config.TunnelConfig{anchorTC("gr-0-0-0")}); err != nil {
   463			t.Fatalf("Apply 3: %v", err)
   464		}
   465		if len(ops.noMaster) != 1 {
   466			t.Fatalf("unbind not idempotent: %v", ops.noMaster)
   467		}
   468	}
   469	
   470	func TestTunnelVRFStanzaToListSameVRFVetoed(t *testing.T) {
   471		ops := newFakeLinkOps()
   472		seedVRF(ops, "red", 100)
   473		tm, _ := newReconcileManager(ops)
   474	
   475		tc := anchorTC("gr-0-0-0")
   476		tc.RoutingInstance = "red"
   477		if err := tm.Apply([]*config.TunnelConfig{tc}); err != nil {
   478			t.Fatalf("Apply 1: %v", err)
   479		}
   480	
   481		// Same commit moves the SAME VRF from stanza to RI interface list;
   482		// step 0a (here: still-enslaved master) bound it before
   483		// ApplyTunnels. The veto must not strip it (r4 convergent).
   484		listTC := anchorTC("gr-0-0-0")
   485		listTC.RIListMember = "red"
   486		if err := tm.Apply([]*config.TunnelConfig{listTC}); err != nil {
   487			t.Fatalf("Apply 2: %v", err)
   488		}
   489		if len(ops.noMaster) != 0 {
   490			t.Fatalf("stanza→list move unbound the 0a bind: %v", ops.noMaster)
   491		}
   492		if tm.appliedRI["gr-0-0-0"] != "red" {
   493			t.Fatalf("claim not transferred to list RI: %q", tm.appliedRI["gr-0-0-0"])
   494		}
   495	
   496		// List membership removed too ⇒ the transferred claim unbinds (the
   497		// v5 clear-on-veto leak, r5 convergent counterexample).
   498		if err := tm.Apply([]*config.TunnelConfig{anchorTC("gr-0-0-0")}); err != nil {
   499			t.Fatalf("Apply 3: %v", err)
   500		}
   501		if len(ops.noMaster) != 1 {
   502			t.Fatalf("stanza→list→removed did not unbind: %v", ops.noMaster)
   503		}
   504	}
   505	
   506	func TestTunnelVRFForeignMasterNeverUnbound(t *testing.T) {
   507		ops := newFakeLinkOps()
   508		seedVRF(ops, "blue", 200)
   509		anchor := seedAnchor(ops, "gr-0-0-0", 42, 1500)
   510		anchor.Attrs().MasterIndex = 200 // 0a-style bind, not ours
   511		tm, _ := newReconcileManager(ops)
   512	
   513		// Fresh manager, no stanza, no list: appliedRI empty ⇒ the foreign
   514		// master must not be touched (r2 Codex F3).
   515		if err := tm.Apply([]*config.TunnelConfig{anchorTC("gr-0-0-0")}); err != nil {
   516			t.Fatalf("Apply: %v", err)
   517		}
   518		if len(ops.noMaster) != 0 {
   519			t.Fatalf("foreign master was unbound: %v", ops.noMaster)
   520		}

codex
The real source still has the old `reconcileLinkAddrsLocked` behavior: non-link-local delete failures are not recorded, while link-local failures are. That makes the r2 choice to isolate removal-prune retry state in a new helper necessary and directionally consistent; I’m checking now for edge cases in that helper sketch and state wiring.
exec
/bin/bash -lc "nl -ba pkg/frr/manager.go | sed -n '240,330p;487,545p'" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
   240	}
   241	
   242	// FullConfig holds the complete routing config for a single FRR apply.
   243	type FullConfig struct {
   244		OSPF              *config.OSPFConfig
   245		OSPFv3            *config.OSPFv3Config
   246		BGP               *config.BGPConfig
   247		RIP               *config.RIPConfig
   248		ISIS              *config.ISISConfig
   249		StaticRoutes      []*config.StaticRoute
   250		Inet6StaticRoutes []*config.StaticRoute // rib inet6.0 static routes
   251		GenerateRoutes    []*config.GenerateRoute
   252		DHCPRoutes        []DHCPRoute
   253		Instances         []InstanceConfig
   254		PolicyOptions     *config.PolicyOptionsConfig
   255	
   256		// ForwardingTableExport is the export policy for the forwarding table (ECMP).
   257		ForwardingTableExport string
   258	
   259		// BackupRouter is the fallback default gateway (system backup-router).
   260		// Installed with admin distance 250 so it's only used when all other defaults fail.
   261		BackupRouter    string // next-hop IP (e.g. "192.168.50.1")
   262		BackupRouterDst string // destination prefix (e.g. "192.168.0.0/16"), default "0.0.0.0/0"
   263	
   264		// InterfaceBandwidths maps interface names to bandwidth in bits per second.
   265		// FRR emits "bandwidth <kbps>" in interface blocks (used by OSPF auto-cost).
   266		InterfaceBandwidths map[string]uint64
   267	
   268		// InterfacePointToPoint maps interface names to point-to-point flag.
   269		// When true and no explicit OSPF network-type is set, emits "ip ospf network point-to-point".
   270		InterfacePointToPoint map[string]bool
   271	
   272		// RethMap maps reth name → physical member name (e.g. "reth0" → "ge-0-0-1").
   273		// Used to translate RETH interface names in static routes to kernel names.
   274		RethMap map[string]string
   275	
   276		// IPv6NextHopInterfaces maps VRF name -> IPv6 next-hop -> interface for
   277		// global and per-instance static routes that omit an explicit interface.
   278		// Values may still be logical interface names (for example, "reth0.50");
   279		// any later translation to kernel/physical names is handled separately via
   280		// RethMap. The global table uses the empty-string VRF key.
   281		IPv6NextHopInterfaces map[string]map[string]string
   282	
   283		// ConsistentHash is set when the forwarding-table export policy uses
   284		// "load-balance consistent-hash". The daemon should set
   285		// net.ipv4.fib_multipath_hash_policy=1 for L4 ECMP hashing.
   286		//
   287		// NOTE: ApplyFull mutates this field as a side effect of resolveECMP().
   288		// See resolveECMP() in config_render.go.
   289		ConsistentHash bool
   290	
   291		// ClusterMode adds a blackhole default route with high admin distance
   292		// (250) as a safety net for active/active per-RG failover.  When the
   293		// WAN VIP moves to the peer, FRR withdraws the real default route
   294		// (next-hop unreachable).  The blackhole default makes bpf_fib_lookup
   295		// return BPF_FIB_LKUP_RET_BLACKHOLE instead of NOT_FWDED, triggering
   296		// zone-encoded fabric redirect for new connections.  The real default
   297		// route (AD 5 or 200) always takes priority when present.
   298		ClusterMode bool
   299	
   300		// PreferredRoutes is the ip-monitoring effective-route overlay
   301		// (#1827 PR-1b): winner-resolved injected routes rendered as
   302		// DISTANCE-1 statics (Static/1 — beats static AD 5 and DHCP AD
   303		// 200; that is what makes them "preferred"). Runtime state from
   304		// pkg/ipmon, supplied by the daemon's assembleFRRConfig for BOTH
   305		// the full apply path and the routes-only actuator, so an
   306		// unrelated operator commit can never wipe an active failover
   307		// route.
   308		PreferredRoutes []config.RouteOverlayEntry
   309	}
   310	
   311	// NOTE (#1827, AGY review on PR #1843 F1): the legacy Apply(ospf, bgp)
   312	// and ApplyWithInstances(...) convenience constructors were DELETED
   313	// here. They built a partial FullConfig inline, bypassing the daemon's
   314	// assembleFRRConfig — the sole production FullConfig constructor — so
   315	// any caller reaching them would have wiped an active ip-monitoring
   316	// failover overlay (PreferredRoutes) from the managed section. They
   317	// had zero callers (production or test) at removal time. New callers
   318	// must go through the daemon's assembleFRRConfig; pkg/daemon's
   319	// TestFRRFullConfigConstructedOnlyByAssembler guard enforces this.
   320	
   321	// ApplyFull generates the complete FRR config including static routes,
   322	// DHCP-learned defaults, per-VRF routes, and dynamic protocols, then
   323	// reloads FRR.
   324	//
   325	// Emission order (preserved as a contract — many FRR parsers depend on
   326	// it; in particular, interface bandwidth must precede OSPF so auto-cost
   327	// picks it up):
   328	//
   329	//  1. global static routes
   330	//  2. generate-routes (blackhole)
   487	// writeManagedSection replaces the xpf-managed section in frr.conf.
   488	// If section is empty, the managed block is removed entirely.
   489	func (m *Manager) writeManagedSection(section string) error {
   490		existing, err := os.ReadFile(m.frrConf)
   491		if err != nil {
   492			if os.IsNotExist(err) {
   493				existing = []byte("log syslog informational\n")
   494			} else {
   495				return fmt.Errorf("read frr.conf: %w", err)
   496			}
   497		}
   498	
   499		// Strip existing managed section.
   500		//
   501		// A correct file has a begin marker followed by an end marker. But a
   502		// prior torn write (os.WriteFile is not atomic — a crash or disk-full
   503		// mid-write can truncate after the begin marker) can leave an orphaned
   504		// markerBegin with no markerEnd. If we only stripped on the both-found
   505		// case, the orphan would survive: we would append a second managed block,
   506		// leaving two begin markers. The next write's strings.Index(markerEnd)
   507		// then matches the new block's end while content[:start] cuts from the
   508		// orphaned begin — deleting everything between them, which may include
   509		// unrelated FRR config the operator appended. So we treat a begin with no
   510		// end as a corrupt tail and discard it to EOF.
   511		content := string(existing)
   512		if start := strings.Index(content, markerBegin); start >= 0 {
   513			if end := strings.Index(content, markerEnd); end >= 0 {
   514				end += len(markerEnd)
   515				// Also consume the trailing newline
   516				if end < len(content) && content[end] == '\n' {
   517					end++
   518				}
   519				content = content[:start] + content[end:]
   520			} else {
   521				// Orphaned begin marker (torn write): discard from the begin
   522				// marker to EOF. Whatever followed an unterminated managed block
   523				// is xpf-generated partial config that must not be preserved, and
   524				// keeping the orphan begin would cause the next write to over-cut.
   525				content = content[:start]
   526			}
   527		}
   528	
   529		// Append new managed section
   530		if section != "" {
   531			content = strings.TrimRight(content, "\n") + "\n"
   532			content += markerBegin + "\n"
   533			content += section
   534			content += markerEnd + "\n"
   535		}
   536	
   537		// Write atomically: a temp file in the same directory followed by rename,
   538		// so a crash or disk-full can never leave frr.conf half-written (which is
   539		// what creates the orphaned-begin-marker state handled above in the first
   540		// place). rename(2) within a filesystem is atomic.
   541		if err := atomicWriteFile(m.frrConf, []byte(content), 0644); err != nil {
   542			return fmt.Errorf("write frr.conf: %w", err)
   543		}
   544		return nil
   545	}

exec
/bin/bash -lc "nl -ba pkg/routing/tunnel_reconcile_test.go | sed -n '520,1040p'" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
   520		}
   521	}
   522	
   523	func TestTunnelVRFDifferentVRFReplacementMismatchClears(t *testing.T) {
   524		ops := newFakeLinkOps()
   525		seedVRF(ops, "red", 100)
   526		seedVRF(ops, "blue", 200)
   527		tm, _ := newReconcileManager(ops)
   528	
   529		tc := anchorTC("gr-0-0-0")
   530		tc.RoutingInstance = "red"
   531		if err := tm.Apply([]*config.TunnelConfig{tc}); err != nil {
   532			t.Fatalf("Apply 1: %v", err)
   533		}
   534	
   535		// Commit 2: stanza removed; a 0a list bind to a DIFFERENT VRF
   536		// already re-mastered the link this apply. Observation transfers
   537		// the claim to blue (master observed).
   538		ops.links["gr-0-0-0"].Attrs().MasterIndex = 200
   539		listTC := anchorTC("gr-0-0-0")
   540		listTC.RIListMember = "blue"
   541		if err := tm.Apply([]*config.TunnelConfig{listTC}); err != nil {
   542			t.Fatalf("Apply 2: %v", err)
   543		}
   544		if len(ops.noMaster) != 0 {
   545			t.Fatalf("replacement bind was unbound: %v", ops.noMaster)
   546		}
   547		if tm.appliedRI["gr-0-0-0"] != "blue" {
   548			t.Fatalf("claim = %q, want blue", tm.appliedRI["gr-0-0-0"])
   549		}
   550	
   551		// Commit 3: list removed ⇒ unbind blue via the transferred claim.
   552		if err := tm.Apply([]*config.TunnelConfig{anchorTC("gr-0-0-0")}); err != nil {
   553			t.Fatalf("Apply 3: %v", err)
   554		}
   555		if len(ops.noMaster) != 1 {
   556			t.Fatalf("transferred claim did not unbind: %v", ops.noMaster)
   557		}
   558	}
   559	
   560	func TestTunnelVRFStanzaBindFailureRetainsClaim(t *testing.T) {
   561		ops := newFakeLinkOps()
   562		seedVRF(ops, "red", 100)
   563		seedVRF(ops, "blue", 200)
   564		tm, binder := newReconcileManager(ops)
   565	
   566		tc := anchorTC("gr-0-0-0")
   567		tc.RoutingInstance = "red"
   568		if err := tm.Apply([]*config.TunnelConfig{tc}); err != nil {
   569			t.Fatalf("Apply 1: %v", err)
   570		}
   571	
   572		// Commit 2: stanza re-bind red→blue FAILS; kernel stays on vrf-red.
   573		// A blind claim=blue would mismatch-clear later and strand red
   574		// (r7 Codex). The claim must stay red.
   575		binder.fail["blue"] = errors.New("vrf lookup failed")
   576		tc2 := anchorTC("gr-0-0-0")
   577		tc2.RoutingInstance = "blue"
   578		if err := tm.Apply([]*config.TunnelConfig{tc2}); err != nil {
   579			t.Fatalf("Apply 2: %v", err)
   580		}
   581		if tm.appliedRI["gr-0-0-0"] != "red" {
   582			t.Fatalf("claim = %q after failed re-bind, want red", tm.appliedRI["gr-0-0-0"])
   583		}
   584	
   585		// Commit 3: RI removed entirely ⇒ red (still the real master) is
   586		// unbound via the retained claim.
   587		if err := tm.Apply([]*config.TunnelConfig{anchorTC("gr-0-0-0")}); err != nil {
   588			t.Fatalf("Apply 3: %v", err)
   589		}
   590		if len(ops.noMaster) != 1 {
   591			t.Fatalf("retained claim did not unbind red: %v", ops.noMaster)
   592		}
   593	}
   594	
   595	func TestTunnelVRFOverlapStanzaFailObservesList(t *testing.T) {
   596		ops := newFakeLinkOps()
   597		seedVRF(ops, "red", 100)
   598		seedVRF(ops, "blue", 200)
   599		seedVRF(ops, "green", 300)
   600		tm, binder := newReconcileManager(ops)
   601	
   602		tc := anchorTC("gr-0-0-0")
   603		tc.RoutingInstance = "red"
   604		if err := tm.Apply([]*config.TunnelConfig{tc}); err != nil {
   605			t.Fatalf("Apply 1: %v", err)
   606		}
   607	
   608		// Commit 2: stanza blue (bind FAILS) + RI-list green, where 0a
   609		// already bound green this apply. The observation fallback must
   610		// take the claim to green (r8 Codex overlap counterexample).
   611		binder.fail["blue"] = errors.New("bind failed")
   612		ops.links["gr-0-0-0"].Attrs().MasterIndex = 300
   613		tc2 := anchorTC("gr-0-0-0")
   614		tc2.RoutingInstance = "blue"
   615		tc2.RIListMember = "green"
   616		if err := tm.Apply([]*config.TunnelConfig{tc2}); err != nil {
   617			t.Fatalf("Apply 2: %v", err)
   618		}
   619		if tm.appliedRI["gr-0-0-0"] != "green" {
   620			t.Fatalf("claim = %q, want green (observation fallback)", tm.appliedRI["gr-0-0-0"])
   621		}
   622	
   623		// Commit 3: everything removed ⇒ green unbound.
   624		if err := tm.Apply([]*config.TunnelConfig{anchorTC("gr-0-0-0")}); err != nil {
   625			t.Fatalf("Apply 3: %v", err)
   626		}
   627		if len(ops.noMaster) != 1 {
   628			t.Fatalf("observed claim did not unbind green: %v", ops.noMaster)
   629		}
   630	}
   631	
   632	func TestTunnelVRFListVetoWithFailedBindNoClaim(t *testing.T) {
   633		ops := newFakeLinkOps()
   634		seedVRF(ops, "blue", 200)
   635		tm, _ := newReconcileManager(ops)
   636	
   637		// List member configured but 0a's bind failed (master 0) and there
   638		// is no prior claim ⇒ no claim may be invented (r6 Codex).
   639		tc := anchorTC("gr-0-0-0")
   640		tc.RIListMember = "blue"
   641		if err := tm.Apply([]*config.TunnelConfig{tc}); err != nil {
   642			t.Fatalf("Apply: %v", err)
   643		}
   644		if got := tm.appliedRI["gr-0-0-0"]; got != "" {
   645			t.Fatalf("claim invented from intent: %q", got)
   646		}
   647	}
   648	
   649	func TestTunnelVRFUnbindFailureRetained(t *testing.T) {
   650		ops := newFakeLinkOps()
   651		seedVRF(ops, "red", 100)
   652		tm, _ := newReconcileManager(ops)
   653	
   654		tc := anchorTC("gr-0-0-0")
   655		tc.RoutingInstance = "red"
   656		if err := tm.Apply([]*config.TunnelConfig{tc}); err != nil {
   657			t.Fatalf("Apply 1: %v", err)
   658		}
   659	
   660		ops.noMasterErr = errors.New("ENODEV")
   661		if err := tm.Apply([]*config.TunnelConfig{anchorTC("gr-0-0-0")}); err != nil {
   662			t.Fatalf("Apply 2: %v", err)
   663		}
   664		if tm.appliedRI["gr-0-0-0"] != "red" {
   665			t.Fatalf("claim lost on transient unbind failure: %q (r4 AGY F4)",
   666				tm.appliedRI["gr-0-0-0"])
   667		}
   668	
   669		ops.noMasterErr = nil
   670		if err := tm.Apply([]*config.TunnelConfig{anchorTC("gr-0-0-0")}); err != nil {
   671			t.Fatalf("Apply 3: %v", err)
   672		}
   673		if len(ops.noMaster) != 1 {
   674			t.Fatalf("unbind not retried after transient failure: %v", ops.noMaster)
   675		}
   676	}
   677	
   678	// --- §9 test 7: legacy non-anchor compare-then-decide -----------------
   679	
   680	func legacyTC(name, src, dst string) *config.TunnelConfig {
   681		return &config.TunnelConfig{Name: name, Mode: "gre", Source: src, Destination: dst}
   682	}
   683	
   684	// kernelShapedGre mimics what LinkByName returns for a GRE device the
   685	// previous apply created: 4-byte v4 IPs, defaulted TTL, plus
   686	// kernel-populated fields that must NOT participate in the comparison.
   687	func kernelShapedGre(name string, index int, local, remote string, key uint32) *netlink.Gretun {
   688		g := &netlink.Gretun{
   689			LinkAttrs: netlink.LinkAttrs{Name: name, Index: index},
   690			Local:     net.ParseIP(local).To4(),
   691			Remote:    net.ParseIP(remote).To4(),
   692			Ttl:       64,
   693			PMtuDisc:  1,
   694			Tos:       0,
   695		}
   696		if key > 0 {
   697			g.IKey = key
   698			g.OKey = key
   699		}
   700		return g
   701	}
   702	
   703	func TestLegacyTunnelUnchangedReused(t *testing.T) {
   704		ops := newFakeLinkOps()
   705		existing := kernelShapedGre("gr-0-0-0", 42, "192.0.2.1", "192.0.2.2", 0)
   706		ops.links["gr-0-0-0"] = existing
   707		tm, _ := newReconcileManager(ops)
   708	
   709		if err := tm.Apply([]*config.TunnelConfig{legacyTC("gr-0-0-0", "192.0.2.1", "192.0.2.2")}); err != nil {
   710			t.Fatalf("Apply: %v", err)
   711		}
   712		if len(ops.delNames) != 0 {
   713			t.Fatalf("identical legacy tunnel was recreated: %v", ops.delNames)
   714		}
   715		if ops.links["gr-0-0-0"] != netlink.Link(existing) {
   716			t.Fatal("legacy tunnel link replaced despite identical attrs")
   717		}
   718		if len(ops.setUpLinks) != 1 || ops.setUpLinks[0].Attrs().Index != 42 {
   719			t.Fatal("LinkSetUp did not run on the kernel-fetched link")
   720		}
   721	}
   722	
   723	func TestLegacyTunnelChangedAttrsRecreated(t *testing.T) {
   724		cases := []struct {
   725			name string
   726			tc   *config.TunnelConfig
   727		}{
   728			{"destination-change", legacyTC("gr-0-0-0", "192.0.2.1", "192.0.2.99")},
   729			{"family-flip", legacyTC("gr-0-0-0", "2001:db8::1", "2001:db8::2")},
   730			{"key-added", func() *config.TunnelConfig {
   731				tc := legacyTC("gr-0-0-0", "192.0.2.1", "192.0.2.2")
   732				tc.Key = 7
   733				return tc
   734			}()},
   735			{"ttl-change", func() *config.TunnelConfig {
   736				tc := legacyTC("gr-0-0-0", "192.0.2.1", "192.0.2.2")
   737				tc.TTL = 32
   738				return tc
   739			}()},
   740		}
   741		for _, tcase := range cases {
   742			t.Run(tcase.name, func(t *testing.T) {
   743				ops := newFakeLinkOps()
   744				ops.links["gr-0-0-0"] = kernelShapedGre("gr-0-0-0", 42, "192.0.2.1", "192.0.2.2", 0)
   745				tm, _ := newReconcileManager(ops)
   746				if err := tm.Apply([]*config.TunnelConfig{tcase.tc}); err != nil {
   747					t.Fatalf("Apply: %v", err)
   748				}
   749				if len(ops.delNames) != 1 {
   750					t.Fatalf("changed attrs did not recreate: delNames=%v", ops.delNames)
   751				}
   752			})
   753		}
   754	}
   755	
   756	func TestLegacyTunnelKernelPopulatedFieldsIgnored(t *testing.T) {
   757		ops := newFakeLinkOps()
   758		g := kernelShapedGre("gr-0-0-0", 42, "192.0.2.1", "192.0.2.2", 0)
   759		g.PMtuDisc = 1
   760		g.Tos = 4 // kernel/operator-populated; NOT config-driven
   761		ops.links["gr-0-0-0"] = g
   762		tm, _ := newReconcileManager(ops)
   763	
   764		if err := tm.Apply([]*config.TunnelConfig{legacyTC("gr-0-0-0", "192.0.2.1", "192.0.2.2")}); err != nil {
   765			t.Fatalf("Apply: %v", err)
   766		}
   767		if len(ops.delNames) != 0 {
   768			t.Fatal("kernel-populated field difference re-flapped the tunnel (A.6 exclusion list)")
   769		}
   770	}
   771	
   772	// --- §9 test 8: keepalive identity reconcile (legacy branch only) -----
   773	
   774	func TestLegacyKeepaliveRunnerRetainedAcrossApplies(t *testing.T) {
   775		ops := newFakeLinkOps()
   776		tm, _ := newReconcileManager(ops)
   777		tc := legacyTC("gr-0-0-0", "192.0.2.1", "192.0.2.2")
   778		tc.Keepalive = 60
   779		tc.KeepaliveRetry = 0 // normalizes to 3 — must not restart per apply
   780	
   781		if err := tm.Apply([]*config.TunnelConfig{tc}); err != nil {
   782			t.Fatalf("Apply 1: %v", err)
   783		}
   784		runner1 := tm.keepalives["gr-0-0-0"]
   785		if runner1 == nil {
   786			t.Fatal("keepalive not started")
   787		}
   788		defer tm.stopAll()
   789	
   790		if err := tm.Apply([]*config.TunnelConfig{tc}); err != nil {
   791			t.Fatalf("Apply 2: %v", err)
   792		}
   793		if tm.keepalives["gr-0-0-0"] != runner1 {
   794			t.Fatal("unchanged keepalive was restarted (r1 Codex F5 normalization)")
   795		}
   796	
   797		// Changed interval ⇒ restart.
   798		tc2 := legacyTC("gr-0-0-0", "192.0.2.1", "192.0.2.2")
   799		tc2.Keepalive = 30
   800		if err := tm.Apply([]*config.TunnelConfig{tc2}); err != nil {
   801			t.Fatalf("Apply 3: %v", err)
   802		}
   803		if tm.keepalives["gr-0-0-0"] == runner1 {
   804			t.Fatal("changed keepalive interval did not restart the runner")
   805		}
   806	
   807		// Keepalive removed ⇒ stopped and map entry deleted (SMR2-2).
   808		tc3 := legacyTC("gr-0-0-0", "192.0.2.1", "192.0.2.2")
   809		if err := tm.Apply([]*config.TunnelConfig{tc3}); err != nil {
   810			t.Fatalf("Apply 4: %v", err)
   811		}
   812		if tm.GetKeepaliveState("gr-0-0-0") != nil {
   813			t.Fatal("keepalive state survives after keepalive removed from config")
   814		}
   815	}
   816	
   817	func TestLegacyKeepaliveDownSkipsLinkSetUp(t *testing.T) {
   818		ops := newFakeLinkOps()
   819		tm, _ := newReconcileManager(ops)
   820		tc := legacyTC("gr-0-0-0", "192.0.2.1", "192.0.2.2")
   821		tc.Keepalive = 60
   822	
   823		if err := tm.Apply([]*config.TunnelConfig{tc}); err != nil {
   824			t.Fatalf("Apply 1: %v", err)
   825		}
   826		defer tm.stopAll()
   827		upsAfterFirst := len(ops.setUpLinks)
   828	
   829		// Keepalive marked the tunnel down. An unrelated re-apply must NOT
   830		// LinkSetUp the reused link: keepaliveLoop's down-transition is
   831		// gated on state.Up==true, so re-upping would strand the link admin
   832		// UP forever while probes keep failing (r1 Codex F1 + AGY trace).
   833		runner := tm.keepalives["gr-0-0-0"]
   834		runner.state.mu.Lock()
   835		runner.state.Up = false
   836		runner.state.mu.Unlock()
   837	
   838		if err := tm.Apply([]*config.TunnelConfig{tc}); err != nil {
   839			t.Fatalf("Apply 2: %v", err)
   840		}
   841		if got := len(ops.setUpLinks); got != upsAfterFirst {
   842			t.Fatalf("LinkSetUp ran on a keepalive-down tunnel: %d ups, want %d",
   843				got, upsAfterFirst)
   844		}
   845	}
   846	
   847	// --- §9 test 9: EEXIST race adoption does not write MTU on owned names
   848	
   849	func TestTunnelAnchorEEXISTRaceOnOwnedNameNoMTUWrite(t *testing.T) {
   850		ops := newFakeLinkOps()
   851		tm, _ := newReconcileManager(ops)
   852		tcs := []*config.TunnelConfig{anchorTC("gr-0-0-0")}
   853		if err := tm.Apply(tcs); err != nil {
   854			t.Fatalf("Apply 1: %v", err)
   855		}
   856		// Force the transient race: the reuse-first lookup misses once, the
   857		// LinkAdd fails EEXIST, the fallback lookup adopts the existing
   858		// link. The name is OWNED, so the adoption MTU normalization must
   859		// NOT fire (r2 Codex F1 / SMR2-1).
   860		existing := ops.links["gr-0-0-0"].(*netlink.Tuntap)
   861		existing.Attrs().MTU = 1400
   862		ops.byNameCount["gr-0-0-0"] = 0
   863		ops.hiddenUntil["gr-0-0-0"] = 1
   864		ops.addExisting = true
   865	
   866		if err := tm.Apply(tcs); err != nil {
   867			t.Fatalf("Apply 2: %v", err)
   868		}
   869		if got := len(ops.mtuSet["gr-0-0-0"]); got != 0 {
   870			t.Fatalf("EEXIST reuse on an OWNED name wrote MTU: %v", ops.mtuSet["gr-0-0-0"])
   871		}
   872	}
   873	
   874	// --- restart adoption end-to-end --------------------------------------
   875	
   876	func TestTunnelRestartAdoptionStableLink(t *testing.T) {
   877		ops := newFakeLinkOps()
   878		tm1, _ := newReconcileManager(ops)
   879		tcs := []*config.TunnelConfig{anchorTC("gr-0-0-0", "10.1.2.3/32")}
   880		if err := tm1.Apply(tcs); err != nil {
   881			t.Fatalf("Apply (manager 1): %v", err)
   882		}
   883		link := ops.links["gr-0-0-0"]
   884	
   885		// "Daemon restart": a brand-new manager over the same kernel state
   886		// adopts the anchor without recreating it.
   887		tm2, _ := newReconcileManager(ops)
   888		if err := tm2.Apply(tcs); err != nil {
   889			t.Fatalf("Apply (manager 2): %v", err)
   890		}
   891		if len(ops.delNames) != 0 {
   892			t.Fatalf("restart adoption recreated the anchor: %v", ops.delNames)
   893		}
   894		if ops.links["gr-0-0-0"] != link {
   895			t.Fatal("restart adoption replaced the link object")
   896		}
   897	}
   898	
   899	// --- Codex PR-r1 coverage adds: remaining claim cells + Clear union --
   900	
   901	func TestTunnelVRFListOnlyBindThenRemovedUnbinds(t *testing.T) {
   902		ops := newFakeLinkOps()
   903		seedVRF(ops, "blue", 200)
   904		tm, _ := newReconcileManager(ops)
   905	
   906		// List-ONLY tunnel (never stanza-bound): 0a bound it; observation
   907		// records the claim.
   908		tc := anchorTC("gr-0-0-0")
   909		tc.RIListMember = "blue"
   910		if err := tm.Apply([]*config.TunnelConfig{tc}); err != nil {
   911			t.Fatalf("Apply 1: %v", err)
   912		}
   913		ops.links["gr-0-0-0"].Attrs().MasterIndex = 200 // 0a bind
   914		if err := tm.Apply([]*config.TunnelConfig{tc}); err != nil {
   915			t.Fatalf("Apply 2: %v", err)
   916		}
   917		if tm.appliedRI["gr-0-0-0"] != "blue" {
   918			t.Fatalf("observed list claim = %q, want blue", tm.appliedRI["gr-0-0-0"])
   919		}
   920	
   921		// List membership removed ⇒ unbind via the observed claim.
   922		if err := tm.Apply([]*config.TunnelConfig{anchorTC("gr-0-0-0")}); err != nil {
   923			t.Fatalf("Apply 3: %v", err)
   924		}
   925		if len(ops.noMaster) != 1 {
   926			t.Fatalf("list-only removal did not unbind: %v", ops.noMaster)
   927		}
   928	}
   929	
   930	func TestTunnelVRFStanzaSuccessWinsOverList(t *testing.T) {
   931		ops := newFakeLinkOps()
   932		seedVRF(ops, "red", 100)
   933		seedVRF(ops, "blue", 200)
   934		tm, _ := newReconcileManager(ops)
   935	
   936		// Both knobs present, stanza bind SUCCEEDS ⇒ stanza wins the claim
   937		// (today's effective 0a-then-tunnel-apply order).
   938		tc := anchorTC("gr-0-0-0")
   939		tc.RoutingInstance = "red"
   940		tc.RIListMember = "blue"
   941		if err := tm.Apply([]*config.TunnelConfig{tc}); err != nil {
   942			t.Fatalf("Apply: %v", err)
   943		}
   944		if tm.appliedRI["gr-0-0-0"] != "red" {
   945			t.Fatalf("claim = %q, want red (stanza wins on success)", tm.appliedRI["gr-0-0-0"])
   946		}
   947		if got := ops.links["gr-0-0-0"].Attrs().MasterIndex; got != 100 {
   948			t.Fatalf("master = %d, want vrf-red 100", got)
   949		}
   950	}
   951	
   952	func TestTunnelVRFNotFoundClearsClaim(t *testing.T) {
   953		ops := newFakeLinkOps()
   954		seedVRF(ops, "red", 100)
   955		tm, _ := newReconcileManager(ops)
   956	
   957		tc := anchorTC("gr-0-0-0")
   958		tc.RoutingInstance = "red"
   959		if err := tm.Apply([]*config.TunnelConfig{tc}); err != nil {
   960			t.Fatalf("Apply 1: %v", err)
   961		}
   962	
   963		// VRF device deleted out-of-band (kernel frees slaves; the fake
   964		// mirrors that by zeroing the master). Claim must CLEAR via the
   965		// not-found leg, with no unbind issued.
   966		delete(ops.links, "vrf-red")
   967		ops.links["gr-0-0-0"].Attrs().MasterIndex = 100 // stale-looking master
   968		if err := tm.Apply([]*config.TunnelConfig{anchorTC("gr-0-0-0")}); err != nil {
   969			t.Fatalf("Apply 2: %v", err)
   970		}
   971		if len(ops.noMaster) != 0 {
   972			t.Fatalf("unbind issued despite VRF not-found: %v", ops.noMaster)
   973		}
   974		if got := tm.appliedRI["gr-0-0-0"]; got != "" {
   975			t.Fatalf("claim not cleared on VRF not-found: %q", got)
   976		}
   977	}
   978	
   979	func TestTunnelVRFTransientLookupRetainsClaim(t *testing.T) {
   980		ops := newFakeLinkOps()
   981		seedVRF(ops, "red", 100)
   982		tm, _ := newReconcileManager(ops)
   983	
   984		tc := anchorTC("gr-0-0-0")
   985		tc.RoutingInstance = "red"
   986		if err := tm.Apply([]*config.TunnelConfig{tc}); err != nil {
   987			t.Fatalf("Apply 1: %v", err)
   988		}
   989	
   990		// Drive the unbind decision directly with a TRANSIENT (plain,
   991		// non-not-found) error on the vrf-red lookup: byNameErrAfter is a
   992		// global threshold, so pre-load vrf-red's per-name counter past it
   993		// while the helper performs no other lookups (the tunnel link is
   994		// passed in). Claim must be RETAINED, no unbind issued.
   995		link := ops.links["gr-0-0-0"]
   996		ops.byNameCount["vrf-red"] = 99
   997		ops.byNameErrAfter = 1
   998		tm.mu.Lock()
   999		tm.reconcileVRFClaimLocked(anchorTC("gr-0-0-0"), link)
  1000		tm.mu.Unlock()
  1001		if got := tm.appliedRI["gr-0-0-0"]; got != "red" {
  1002			t.Fatalf("claim lost on transient lookup error: %q", got)
  1003		}
  1004		if len(ops.noMaster) != 0 {
  1005			t.Fatalf("unbind issued despite transient lookup error: %v", ops.noMaster)
  1006		}
  1007	
  1008		// Error clears ⇒ retry unbinds.
  1009		ops.byNameErrAfter = 0
  1010		tm.mu.Lock()
  1011		tm.reconcileVRFClaimLocked(anchorTC("gr-0-0-0"), link)
  1012		tm.mu.Unlock()
  1013		if len(ops.noMaster) != 1 {
  1014			t.Fatalf("unbind not retried after transient lookup error: %v", ops.noMaster)
  1015		}
  1016	}
  1017	
  1018	func TestClearTunnelsDeletesOwnershipUnion(t *testing.T) {
  1019		ops := newFakeLinkOps()
  1020		tm, _ := newReconcileManager(ops)
  1021	
  1022		// Apply where the second tunnel FAILS mid-apply (non-TUN collision
  1023		// whose LinkDel fails): it stays in ownedNames but never reaches
  1024		// t.tunnels.
  1025		ops.links["gr-0-0-1"] = &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "gr-0-0-1", Index: 9}}
  1026		ops.delFail["gr-0-0-1"] = errors.New("EBUSY")
  1027		tcs := []*config.TunnelConfig{anchorTC("gr-0-0-0"), anchorTC("gr-0-0-1")}
  1028		if err := tm.Apply(tcs); err != nil {
  1029			t.Fatalf("Apply: %v", err)
  1030		}
  1031	
  1032		// ClearTunnels must delete EVERYTHING it owns — including the
  1033		// failed-apply name once deletable (Codex PR r1 MINOR: union of
  1034		// t.tunnels and ownedNames, not the success list alone).
  1035		delete(ops.delFail, "gr-0-0-1")
  1036		if err := tm.Clear(); err != nil {
  1037			t.Fatalf("Clear: %v", err)
  1038		}
  1039		if _, ok := ops.links["gr-0-0-0"]; ok {
  1040			t.Fatal("Clear left the successful tunnel behind")

exec
/bin/bash -lc "nl -ba pkg/routing/tunnel.go | sed -n '1340,1415p'" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
  1340	// *KeepaliveState pointer is safe to dereference outside the lock —
  1341	// Go GC keeps the value alive even if a subsequent stopAll removes it
  1342	// from the map.
  1343	func (t *tunnelManager) GetKeepaliveState(tunnelName string) *KeepaliveState {
  1344		t.mu.Lock()
  1345		defer t.mu.Unlock()
  1346		runner, ok := t.keepalives[tunnelName]
  1347		if !ok {
  1348			return nil
  1349		}
  1350		return runner.state
  1351	}
  1352	
  1353	// Clear removes all previously created tunnel interfaces.
  1354	func (t *tunnelManager) Clear() error {
  1355		t.mu.Lock()
  1356		defer t.mu.Unlock()
  1357		return t.clearLocked()
  1358	}
  1359	
  1360	// clearLocked is the lock-free body of Clear. Caller must hold mu.
  1361	// Apply no longer uses it (#1884 reconcile-in-place); it remains the
  1362	// explicit delete-everything path for ClearTunnels. It deletes the
  1363	// UNION of the success-tracked list and the ownership set: a
  1364	// per-tunnel apply failure leaves the name in ownedNames but not in
  1365	// t.tunnels (failure-continue before finishTunnelLocked), and the
  1366	// delete-everything contract must still cover that live link (Codex
  1367	// PR #1903 r1 MINOR).
  1368	func (t *tunnelManager) clearLocked() error {
  1369		t.stopAllKeepalivesLocked()
  1370		names := make(map[string]bool, len(t.tunnels)+len(t.ownedNames))
  1371		for _, name := range t.tunnels {
  1372			names[name] = true
  1373		}
  1374		for name := range t.ownedNames {
  1375			names[name] = true
  1376		}
  1377		for name := range names {
  1378			link, err := t.ops.LinkByName(name)
  1379			if err != nil {
  1380				continue // already gone
  1381			}
  1382			if err := t.ops.LinkDel(link); err != nil {
  1383				slog.Warn("failed to delete tunnel", "name", name, "err", err)
  1384			} else {
  1385				slog.Info("tunnel removed", "name", name)
  1386			}
  1387		}
  1388		t.tunnels = nil
  1389		// Reset the reconcile state with the devices: a post-Clear Apply
  1390		// adopts whatever survives instead of trusting stale ownership.
  1391		t.ownedNames = nil
  1392		t.appliedAddrs = nil
  1393		t.appliedRI = nil
  1394		// clearLocked drains every keepalive runner first
  1395		// (stopAllKeepalivesLocked above), so no live runner holds a stale
  1396		// linkGen pointer; dropping the map is safe and prevents removed names
  1397		// from leaking generation counters (#1918).
  1398		t.linkGen = nil
  1399		return nil
  1400	}
  1401	
  1402	// GetStatus returns the status of managed tunnel interfaces.
  1403	func (t *tunnelManager) GetStatus() ([]TunnelStatus, error) {
  1404		// #848: snapshot tunnel names under mu, then iterate without the
  1405		// lock so a long netlink probe can't block applyConfig.
  1406		t.mu.Lock()
  1407		names := append([]string(nil), t.tunnels...)
  1408		t.mu.Unlock()
  1409	
  1410		var result []TunnelStatus
  1411		for _, name := range names {
  1412			ts := TunnelStatus{Name: name, State: "down"}
  1413	
  1414			link, err := t.ops.LinkByName(name)
  1415			if err != nil {

exec
/bin/bash -lc "nl -ba pkg/daemon/daemon_ipmon.go | sed -n '70,170p'" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
    70	// set, so entries whose policy was removed or whose preferred-route
    71	// spec was edited must be dropped here — otherwise the commit would
    72	// republish the stale overlay to FRR and the snapshot until the
    73	// delayed actuator caught up. Unrelated commits (policy spec
    74	// unchanged) keep the active overlay intact (AGY r2-2).
    75	func (d *Daemon) commitOverlayForConfig(cfg *config.Config) []config.RouteOverlayEntry {
    76		if cfg == nil {
    77			return nil
    78		}
    79		return ipmon.FilterOverlayForConfig(d.ipmonActiveOverlay(), cfg.Services.IPMonitoring)
    80	}
    81	
    82	// assembleFRRConfig builds the complete frr.FullConfig for the given
    83	// compiled config plus the ip-monitoring overlay. It is the sole
    84	// constructor for BOTH the full apply path and the routes-only
    85	// actuator (the complete contract: static routes, generate-routes,
    86	// DHCP routes, policy export, backup-router, interface hints, RethMap,
    87	// IPv6 next-hop interfaces, ClusterMode, per-VRF instances, and the
    88	// overlay's PreferredRoutes).
    89	func (d *Daemon) assembleFRRConfig(cfg *config.Config, overlay []config.RouteOverlayEntry) *frr.FullConfig {
    90		// Collect interface bandwidths and point-to-point flags for FRR.
    91		ifaceBandwidths := make(map[string]uint64)
    92		ifaceP2P := make(map[string]bool)
    93		for name, ifc := range cfg.Interfaces.Interfaces {
    94			linuxName := config.LinuxIfName(name)
    95			if ifc.Bandwidth > 0 {
    96				ifaceBandwidths[linuxName] = ifc.Bandwidth
    97			}
    98			for _, unit := range ifc.Units {
    99				if unit.PointToPoint {
   100					ifaceP2P[linuxName] = true
   101				}
   102			}
   103		}
   104	
   105		fc := &frr.FullConfig{
   106			OSPF:                  cfg.Protocols.OSPF,
   107			OSPFv3:                cfg.Protocols.OSPFv3,
   108			BGP:                   cfg.Protocols.BGP,
   109			RIP:                   cfg.Protocols.RIP,
   110			ISIS:                  cfg.Protocols.ISIS,
   111			StaticRoutes:          cfg.RoutingOptions.StaticRoutes,
   112			Inet6StaticRoutes:     cfg.RoutingOptions.Inet6StaticRoutes,
   113			GenerateRoutes:        cfg.RoutingOptions.GenerateRoutes,
   114			DHCPRoutes:            d.collectDHCPRoutes(),
   115			PolicyOptions:         &cfg.PolicyOptions,
   116			ForwardingTableExport: cfg.RoutingOptions.ForwardingTableExport,
   117			BackupRouter:          cfg.System.BackupRouter,
   118			BackupRouterDst:       cfg.System.BackupRouterDst,
   119			InterfaceBandwidths:   ifaceBandwidths,
   120			InterfacePointToPoint: ifaceP2P,
   121			RethMap:               cfg.RethToPhysical(),
   122			IPv6NextHopInterfaces: inferIPv6StaticNextHopInterfaces(cfg),
   123			ClusterMode:           d.cluster != nil,
   124			PreferredRoutes:       overlay,
   125		}
   126		for _, ri := range cfg.RoutingInstances {
   127			vrfName := "vrf-" + ri.Name
   128			tableID := 0
   129			if ri.InstanceType == "forwarding" {
   130				// Forwarding instances have no VRF device; their statics
   131				// render into the instance's dedicated kernel table so the
   132				// kernel agrees with the FBF/PBR ip rules AND the userspace
   133				// dataplane's `<ri>.inet.0` snapshot table (#1827 PR-2
   134				// divergence fix — previously these leaked into the default
   135				// table).
   136				vrfName = ""
   137				tableID = ri.TableID
   138			}
   139			fc.Instances = append(fc.Instances, frr.InstanceConfig{
   140				Name:              ri.Name,
   141				VRFName:           vrfName,
   142				TableID:           tableID,
   143				OSPF:              ri.OSPF,
   144				OSPFv3:            ri.OSPFv3,
   145				BGP:               ri.BGP,
   146				RIP:               ri.RIP,
   147				ISIS:              ri.ISIS,
   148				StaticRoutes:      ri.StaticRoutes,
   149				Inet6StaticRoutes: ri.Inet6StaticRoutes,
   150			})
   151		}
   152		return fc
   153	}
   154	
   155	// applyFRRConfig applies an assembled FullConfig and handles the
   156	// shared post-ApplyFull consistent-hash sysctl. Both the full apply
   157	// path and the actuator go through here.
   158	func (d *Daemon) applyFRRConfig(fc *frr.FullConfig) {
   159		if d.frr == nil {
   160			return
   161		}
   162		// Warn-and-continue on FRR reload problems: an FRR hiccup must not
   163		// fail an otherwise-valid commit. Degraded (#1880) means the config
   164		// WAS applied additively and the manager's retry loop owns
   165		// convergence of stale-config removal; the gauge
   166		// xpf_frr_reload_degraded is 1 until it converges.
   167		if err := d.frr.ApplyFull(fc); err != nil {
   168			if errors.Is(err, frr.ErrFRRReloadDegraded) {
   169				slog.Warn("FRR reload degraded: additive vtysh -f applied; stale-config removal deferred to the in-manager retry", "err", err)
   170			} else {

exec
/bin/bash -lc "nl -ba pkg/routing/tunnel.go | sed -n '900,1010p'" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
   900	// plus §5.4.6 pad, exceeds the outer MTU and forces outer IP
   901	// fragmentation. The overhead depends on the outer IP family (the WG
   902	// peer endpoint address): IPv6-outer is 20 bytes larger. The outer MTU
   903	// is assumed to be a standard 1500 (S2a single-tunnel); the control
   904	// thread also enforces an exact pad-aware guard (wg_control.rs), so this
   905	// is the first line, not the only one.
   906	func wgTunMTUForEndpoint(tc *config.TunnelConfig) int {
   907		const outerMTU = 1500
   908		// A configured v4 endpoint uses the v4 overhead; a v6 endpoint (or a
   909		// responder-only/roaming endpoint with no configured address, which
   910		// the Rust control thread may LEARN as v6 — Codex r4 MAJOR) uses the
   911		// larger v6 overhead so the kernel never hands the control thread an
   912		// inner packet that the v6-aware encap guard would then drop.
   913		overhead := wgOverheadV6
   914		if tc.WgEndpoint != "" {
   915			if host, _, err := net.SplitHostPort(tc.WgEndpoint); err == nil {
   916				if ip := net.ParseIP(host); ip != nil && ip.To4() != nil {
   917					overhead = wgOverheadV4
   918				}
   919			}
   920		}
   921		return outerMTU - overhead - wgPadWorst
   922	}
   923	
   924	// applyWireguardTunLocked creates (or reuses) the persistent wgN TUN
   925	// netdev for a WireGuard tunnel endpoint and configures its MTU,
   926	// addresses, and VRF binding. The device is intentionally NOT tracked
   927	// in t.tunnels: clearLocked must not delete it on reload (AGY Hazard B
   928	// — flapping wgN destroys its addresses and FRR routes every commit).
   929	//
   930	// Known S2a limitation (AGY M1): because the device is untracked, a WG
   931	// tunnel REMOVED from the config is not torn down by clearLocked and
   932	// leaks until `ip link del` or daemon restart. S2a single-tunnel scope
   933	// accepts this in exchange for reload stability; multi-instance teardown
   934	// is owned by the S6 grammar work (#1434).
   935	//
   936	// The Rust control thread (coordinator/wg_control.rs) attaches to this
   937	// persistent device by name.
   938	func (t *tunnelManager) applyWireguardTunLocked(tc *config.TunnelConfig) error {
   939		mtu := wgTunMTUForEndpoint(tc)
   940		link, err := t.ops.LinkByName(tc.Name)
   941		// Copilot C3: only reuse an existing link if it is actually a TUN/TAP.
   942		// A name collision with some other interface type (e.g. a leftover
   943		// dummy) must be deleted and recreated, not mutated — otherwise we'd
   944		// bring up + address + VRF-bind the wrong device, and the Rust side's
   945		// open_tun on the same name would then fail.
   946		mustCreate := err != nil
   947		if err == nil {
   948			tt, isTuntap := link.(*netlink.Tuntap)
   949			if !isTuntap || tt.Mode != netlink.TUNTAP_MODE_TUN {
   950				// Not a TUN (a TAP, or some other type entirely). The Rust
   951				// side opens it with IFF_TUN, so a TAP would fail there;
   952				// delete + recreate as a TUN rather than mutate the wrong
   953				// device (Codex r3 MINOR).
   954				slog.Info("replacing non-TUN link before wireguard tun create",
   955					"name", tc.Name, "type", link.Type())
   956				if delErr := t.ops.LinkDel(link); delErr != nil {
   957					return fmt.Errorf("replace non-tun wireguard link %s: %w", tc.Name, delErr)
   958				}
   959				mustCreate = true
   960			}
   961		}
   962		if mustCreate {
   963			// Create a persistent TUN. NonPersist:false keeps the netdev
   964			// alive after the creating fd closes, so a reload that does not
   965			// touch this device leaves it (and its routes) intact.
   966			tun := &netlink.Tuntap{
   967				LinkAttrs:  netlink.LinkAttrs{Name: tc.Name, MTU: mtu},
   968				Mode:       netlink.TUNTAP_MODE_TUN,
   969				Flags:      netlink.TUNTAP_NO_PI,
   970				Queues:     1,
   971				NonPersist: false,
   972			}
   973			if addErr := t.ops.LinkAdd(tun); addErr != nil {
   974				return fmt.Errorf("create wireguard tun %s: %w", tc.Name, addErr)
   975			}
   976			closeTuntapFiles(tun.Fds)
   977			link = tun
   978			// vishvananda/netlink creates a TUN via TUNSETIFF and may return
   979			// before the generic LinkAttrs.MTU is applied, leaving the kernel
   980			// device at its default MTU on first apply (Codex r4 MAJOR).
   981			// Set the MTU explicitly after create so the inner cap is live
   982			// immediately, not only after a later reload.
   983			if mtuErr := t.ops.LinkSetMTU(link, mtu); mtuErr != nil {
   984				slog.Warn("failed to set wireguard tun mtu on create",
   985					"name", tc.Name, "mtu", mtu, "err", mtuErr)
   986			}
   987			slog.Info("wireguard tun created", "name", tc.Name, "mtu", mtu)
   988		} else {
   989			// Reuse in place; reconcile the MTU if the config changed it
   990			// (AGY M4 / Copilot C4 — a stale MTU on reuse, including a
   991			// pre-created device, would otherwise persist).
   992			if link.Attrs().MTU != mtu {
   993				if mtuErr := t.ops.LinkSetMTU(link, mtu); mtuErr != nil {
   994					slog.Warn("failed to update wireguard tun mtu",
   995						"name", tc.Name, "mtu", mtu, "err", mtuErr)
   996				} else {
   997					slog.Info("wireguard tun mtu updated", "name", tc.Name, "mtu", mtu)
   998				}
   999			}
  1000			slog.Debug("wireguard tun reused", "name", tc.Name)
  1001		}
  1002	
  1003		if err := t.ops.LinkSetUp(link); err != nil {
  1004			slog.Warn("failed to bring up wireguard tun", "name", tc.Name, "err", err)
  1005		}
  1006	
  1007		// Symmetric address reconciliation (Copilot C5): because the device
  1008		// is persistent and never recreated, addresses removed from the config
  1009		// would otherwise survive every reload and keep being routed. Shared
  1010		// helper (#1884) with the per-link applied-address record (#1905) —

exec
/bin/bash -lc "nl -ba pkg/frr/policy_render.go | sed -n '56,100p;630,650p'" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
    56	// knownRedistProtocols are the FRR redistribute protocol keywords.
    57	var knownRedistProtocols = map[string]bool{
    58		"connected": true, "static": true, "ospf": true, "bgp": true,
    59		"rip": true, "isis": true, "kernel": true,
    60	}
    61	
    62	// resolveRedistribute converts a Junos export value into FRR redistribute commands.
    63	// If the value is a known protocol name, it emits a bare "redistribute <proto>".
    64	// If it matches a policy-statement, it extracts protocols from the terms and emits
    65	// "redistribute <proto> route-map <name>" for each.
    66	func (m *Manager) resolveRedistribute(export string, po *config.PolicyOptionsConfig) string {
    67		if knownRedistProtocols[export] {
    68			return fmt.Sprintf(" redistribute %s\n", export)
    69		}
    70	
    71		if po != nil && po.PolicyStatements != nil {
    72			if ps, ok := po.PolicyStatements[export]; ok {
    73				protocols := make(map[string]bool)
    74				for _, term := range ps.Terms {
    75					if term.FromProtocol != "" {
    76						proto := term.FromProtocol
    77						if proto == "direct" {
    78							proto = "connected"
    79						}
    80						protocols[proto] = true
    81					}
    82				}
    83				if len(protocols) > 0 {
    84					sorted := make([]string, 0, len(protocols))
    85					for p := range protocols {
    86						sorted = append(sorted, p)
    87					}
    88					sort.Strings(sorted)
    89					var sb strings.Builder
    90					for _, proto := range sorted {
    91						fmt.Fprintf(&sb, " redistribute %s route-map %s\n", proto, export)
    92					}
    93					return sb.String()
    94				}
    95			}
    96		}
    97	
    98		// Fallback: treat as bare redistribute (best-effort)
    99		return fmt.Sprintf(" redistribute %s\n", export)
   100	}
   630					if strings.Contains(term.RouteFilters[0].Prefix, ":") {
   631						fmt.Fprintf(&b, " match ipv6 address prefix-list %s\n", plName)
   632					} else {
   633						fmt.Fprintf(&b, " match ip address prefix-list %s\n", plName)
   634					}
   635				}
   636	
   637				if term.PrefixList != "" {
   638					fmt.Fprintf(&b, " match ip address prefix-list %s\n", term.PrefixList)
   639				}
   640	
   641				if term.FromProtocol != "" {
   642					proto := term.FromProtocol
   643					if proto == "direct" {
   644						proto = "connected"
   645					}
   646					fmt.Fprintf(&b, " match source-protocol %s\n", proto)
   647				}
   648	
   649				if term.FromCommunity != "" {
   650					fmt.Fprintf(&b, " match community %s\n", term.FromCommunity)

exec
/bin/bash -lc "nl -ba pkg/routing/tunnel.go | sed -n '1007,1048p'" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
  1007		// Symmetric address reconciliation (Copilot C5): because the device
  1008		// is persistent and never recreated, addresses removed from the config
  1009		// would otherwise survive every reload and keep being routed. Shared
  1010		// helper (#1884) with the per-link applied-address record (#1905) —
  1011		// the same configured-vs-autoconf link-local split as the GRE/IPIP
  1012		// branch: a CONFIGURED fe80 later removed from config is deleted
  1013		// (this manager applied it), while the kernel's autoconf fe80 — and
  1014		// any fe80 already present before this daemon's first apply
  1015		// (restart adoption pass, applied == nil) — is never touched.
  1016		// Because the wgN device persists when removed from config (S2a,
  1017		// see above), its appliedAddrs entry is retained with it so a later
  1018		// re-add keeps accurate tracking; S6 teardown (#1434) owns deleting
  1019		// both.
  1020		t.appliedAddrs[tc.Name] = t.reconcileLinkAddrsLocked(
  1021			link, tc.Name, tc.Addresses, t.appliedAddrs[tc.Name], "wireguard tun")
  1022	
  1023		if tc.RoutingInstance != "" {
  1024			if bindErr := t.vrfBinder.BindInterfaceToVRF(tc.Name, tc.RoutingInstance); bindErr != nil {
  1025				slog.Warn("failed to bind wireguard tun to VRF",
  1026					"name", tc.Name, "vrf", tc.RoutingInstance, "err", bindErr)
  1027			}
  1028		}
  1029		return nil
  1030	}
  1031	
  1032	// closeTuntapFiles closes the file descriptors returned by a Tuntap
  1033	// LinkAdd so they are not leaked.
  1034	func closeTuntapFiles(files []*os.File) {
  1035		for _, file := range files {
  1036			if file != nil {
  1037				_ = file.Close()
  1038			}
  1039		}
  1040	}
  1041	
  1042	// stopAll cancels all running keepalive goroutines and waits for them
  1043	// to exit. Acquires mu.
  1044	//
  1045	// #848: draining (not just cancelling) is required because
  1046	// keepaliveLoop touches the netlink handle on bring-up/down. The
  1047	// façade Close() then closes the handle, so any in-flight tick that
  1048	// hadn't yet checked ctx.Done() would use-after-close. The done

exec
/bin/bash -lc "nl -ba pkg/config/types_routing.go | sed -n '280,340p'" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
exec
/bin/bash -lc "nl -ba userspace-dp/src/protocol/snapshot.rs | sed -n '340,375p'" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
   340	    // See docs/pr/wireguard-clean/plan.md for the design.
   341	    #[serde(rename = "wg_listen_port", default)]
   342	    pub wg_listen_port: u16,
   343	    /// Local static private key for the WG interface, hex-encoded
   344	    /// (64 chars for 32 bytes). Empty when `mode != "wireguard"`.
   345	    ///
   346	    /// This field is intentionally `skip_serializing` so it CANNOT
   347	    /// be written back out via any `serde_json` round-trip. The
   348	    /// userspace dataplane persists a JSON snapshot of `ServerState`
   349	    /// to disk via `server::helpers::write_state`, which used to
   350	    /// include this private key in plaintext (Copilot inline review
   351	    /// caught this on the final pre-merge round). Deserialization
   352	    /// still works — the control plane delivers the key on the
   353	    /// control socket via the `default` path. The custom Debug impl
   354	    /// on `TunnelEndpointSnapshot` redacts this field to keep any
   355	    /// future accidental `{:?}` log line from leaking key material.
   356	    #[serde(rename = "wg_local_privkey_hex", default, skip_serializing)]
   357	    pub wg_local_privkey_hex: String,
   358	    /// Peer's static public key, hex-encoded. The WG engine uses
   359	    /// this as the encap key — not AllowedIPs LPM. See plan §
   360	    /// "Engine keying" for why this matters.
   361	    #[serde(rename = "wg_peer_pubkey_hex", default)]
   362	    pub wg_peer_pubkey_hex: String,
   363	    /// Peer AllowedIPs, as CIDR strings. Only consulted on the
   364	    /// decap path (inner src-IP gate); never used to choose a peer
   365	    /// on egress.
   366	    #[serde(rename = "wg_allowed_ips", default)]
   367	    pub wg_allowed_ips: Vec<String>,
   368	    /// Optional peer endpoint (`IP:port`) for initiator-role
   369	    /// handshakes. Empty for responder-only.
   370	    #[serde(rename = "wg_endpoint", default)]
   371	    pub wg_endpoint: String,
   372	    /// Optional persistent keepalive in seconds. 0 = off.
   373	    #[serde(rename = "wg_keepalive_secs", default)]
   374	    pub wg_keepalive_secs: u16,
   375	}

 succeeded in 0ms:
   280		AuthPassword         string   // TCP MD5 password for BGP session
   281		BFD                  bool     // enable BFD for this neighbor
   282		BFDInterval          int      // BFD minimum interval in ms (0 = default 300)
   283		BFDMultiplier        int      // BFD detect-multiplier (0 = default 3)
   284		RouteReflectorClient bool     // mark as route-reflector client
   285		DefaultOriginate     bool     // advertise default route to this neighbor
   286		AllowASIn            int      // allow own AS in path N times (0 = disabled)
   287		RemovePrivateAS      bool     // strip private AS numbers from updates
   288		PrefixLimitInet      int      // max IPv4 prefixes (0 = unlimited)
   289		PrefixLimitInet6     int      // max IPv6 prefixes (0 = unlimited)
   290	}
   291	
   292	// TunnelConfig defines a GRE, IPIP, or other tunnel interface.
   293	type TunnelConfig struct {
   294		Name            string   // Linux interface name (e.g. "gr-0-0-0", "ip-0-0-0")
   295		Mode            string   // "gre" or "ipip"
   296		Source          string   // local tunnel endpoint IP
   297		Destination     string   // remote tunnel endpoint IP
   298		Key             uint32   // GRE key, 0 = none
   299		TTL             int      // tunnel TTL, 0 = default 64
   300		Addresses       []string // IPs to assign to tunnel interface (CIDR)
   301		RoutingInstance string   // destination routing-instance (VRF)
   302		Keepalive       int      // keepalive interval in seconds (0 = disabled)
   303		KeepaliveRetry  int      // number of missed keepalives before declaring down (0 = default 3)
   304		AnchorOnly      bool     // create a dummy anchor instead of a kernel tunnel device
   305	
   306		// MTU is the config-desired link MTU for the tunnel device (#1884):
   307		// the owning interface's `mtu` statement (unit-level overrides
   308		// interface-level for unit tunnels, mirroring compiler_iface
   309		// precedence). 0 means unconfigured — the tunnel manager then never
   310		// writes MTU except the one-time TUN-default normalization when
   311		// ADOPTING an anchor it did not create (wireguard→gre same-name flip
   312		// repair). Populated by collectAppliedTunnels; the legacy
   313		// standalone-CLI apply path leaves it 0.
   314		MTU int
   315	
   316		// RIListMember is the routing-instance whose `interface` LIST names
   317		// this tunnel (after the daemon step-0a name normalization), or ""
   318		// (#1884). It is NOT a bind instruction — daemon_apply step 0a owns
   319		// list binds. The tunnel manager uses it as (a) an unbind VETO so a
   320		// stanza→list move never strips the 0a bind, and (b) the
   321		// observation-fallback claim target for later unbind-on-removal.
   322		// Populated by collectAppliedTunnels; the legacy CLI path leaves "".
   323		RIListMember string
   324	
   325		// WireGuard (#1432 S2a). Populated only when Mode == "wireguard".
   326		// Minimal generic surface (the #1703 "generic stanza") — not the
   327		// full Junos wireguard grammar (S6). The engine keys encap on
   328		// WgPeerPubkeyHex, NOT AllowedIPs LPM (cryptokey-routing safety).
   329		WgListenPort      uint16   // local UDP listen port for inbound WG
   330		WgLocalPrivkeyHex string   // local static X25519 private key (hex, 64 chars)
   331		WgPeerPubkeyHex   string   // peer static X25519 public key (hex)
   332		WgAllowedIPs      []string // peer AllowedIPs (CIDR); decap inner-src gate only
   333		WgEndpoint        string   // optional peer endpoint IP:port (initiator role)
   334		WgKeepaliveSecs   uint16   // optional persistent-keepalive seconds (0 = off)
   335	}
   336	
   337	// String redacts WgLocalPrivkeyHex so a `%v`/`%s`/slog format of a
   338	// TunnelConfig never leaks the WireGuard private key (#1432 S2a privkey
   339	// hygiene, AGY M2). The Rust side already zeroizes + redacts its copy;
   340	// this closes the Go-side cleartext-log exposure.

exec
/bin/bash -lc "rg -n \"type linkOps|func \\(.*\\) AddrList|AddrDel|byNameErr|hiddenUntil|addrDelFail|newFakeLinkOps|errLinkNotFound|LinkByName\" pkg/routing -g '*test.go' -g '*.go'" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
pkg/routing/routes.go:34:	LinkByName(name string) (netlink.Link, error)
pkg/routing/routes.go:86:	link, err := rr.ops.LinkByName(devName)
pkg/routing/bond.go:44:		if existing, err := b.ops.LinkByName(bondName); err == nil {
pkg/routing/bond.go:68:		bondLink, err := b.ops.LinkByName(bondName)
pkg/routing/bond.go:75:			memberLink, err := b.ops.LinkByName(linuxName)
pkg/routing/bond.go:117:		link, err := b.ops.LinkByName(name)
pkg/routing/vrf.go:23:	LinkByName(string) (netlink.Link, error)
pkg/routing/vrf.go:61:	if existing, err := v.ops.LinkByName(vrfName); err == nil {
pkg/routing/vrf.go:122:// (LinkByName + LinkSetMaster) and touches no vrfManager field. That
pkg/routing/vrf.go:129:	iface, err := v.ops.LinkByName(ifaceName)
pkg/routing/vrf.go:133:	vrf, err := v.ops.LinkByName(vrfName)
pkg/routing/vrf.go:144:// errLinkNotFound is an internal sentinel wrapper used when the
pkg/routing/vrf.go:149:type errLinkNotFound struct{ error }
pkg/routing/vrf.go:163:	var internal errLinkNotFound
pkg/routing/vrf.go:180:// (LinkByName / LinkSetUp) fails, the VRF is still recorded in the
pkg/routing/vrf.go:203:		link, kerErr := ops.LinkByName(vrfName)
pkg/routing/vrf.go:261:		link, err := ops.LinkByName(existing)
pkg/routing/vrf.go:342:	link, err := ops.LinkByName(vrfName)
pkg/routing/xfrm.go:44:		// lookup: calling LinkByName a second time and ignoring its
pkg/routing/xfrm.go:48:		if link, err := x.ops.LinkByName(ifName); err == nil {
pkg/routing/xfrm.go:81:		link, err := x.ops.LinkByName(ifName)
pkg/routing/xfrm.go:111:		link, err := x.ops.LinkByName(name)
pkg/routing/routing_test.go:34:func (f *fakeVRFOps) LinkByName(name string) (netlink.Link, error) {
pkg/routing/routing_test.go:41:	return nil, errLinkNotFound{errors.New("link not found")}
pkg/routing/routing_test.go:188:			// no LinkAdd, no LinkDel. LinkByName fires once for the
pkg/routing/routing_test.go:237:				t.Errorf("LinkByName count = %d, want %d", ops.byNameHits, tc.wantByNameHits)
pkg/routing/routing_test.go:448:// not-found error from LinkByName during delete (tracked-but-not-
pkg/routing/routing_test.go:456:		t.Fatal("expected error from transient LinkByName failure, got nil")
pkg/routing/routing_test.go:473:// (we created it earlier), and LinkByName returns a transient
pkg/routing/routing_test.go:484:		t.Fatal("expected error from transient LinkByName failure, got nil")
pkg/routing/routing_test.go:499:// transientLookupOps fails LinkByName for a specific name with a
pkg/routing/routing_test.go:506:func (t *transientLookupOps) LinkByName(name string) (netlink.Link, error) {
pkg/routing/routing_test.go:514:	return nil, errLinkNotFound{errors.New("link not found")}
pkg/routing/iface_reuse_test.go:23:	// byNameErrAfter, when > 0, makes LinkByName return an error once it
pkg/routing/iface_reuse_test.go:27:	byNameErrAfter int
pkg/routing/iface_reuse_test.go:29:	// hiddenUntil[name] = k makes LinkByName report not-found for the
pkg/routing/iface_reuse_test.go:34:	hiddenUntil map[string]int
pkg/routing/iface_reuse_test.go:40:	// addrDelFail["name|ipnet"] makes AddrDel fail for that address on
pkg/routing/iface_reuse_test.go:42:	addrDelFail map[string]error
pkg/routing/iface_reuse_test.go:48:	// AddrAdd/AddrDel/AddrList for the #1884 reconcile tests.
pkg/routing/iface_reuse_test.go:60:func newFakeLinkOps() *fakeLinkOps {
pkg/routing/iface_reuse_test.go:64:		hiddenUntil: map[string]int{},
pkg/routing/iface_reuse_test.go:66:		addrDelFail: map[string]error{},
pkg/routing/iface_reuse_test.go:73:func (f *fakeLinkOps) LinkByName(name string) (netlink.Link, error) {
pkg/routing/iface_reuse_test.go:75:	if f.byNameErrAfter > 0 && f.byNameCount[name] > f.byNameErrAfter {
pkg/routing/iface_reuse_test.go:78:	if hide, ok := f.hiddenUntil[name]; ok && f.byNameCount[name] <= hide {
pkg/routing/iface_reuse_test.go:79:		return nil, errLinkNotFound{errors.New("link not found")}
pkg/routing/iface_reuse_test.go:84:	return nil, errLinkNotFound{errors.New("link not found")}
pkg/routing/iface_reuse_test.go:143:func (f *fakeLinkOps) AddrDel(l netlink.Link, a *netlink.Addr) error {
pkg/routing/iface_reuse_test.go:146:	if err, ok := f.addrDelFail[name+"|"+key]; ok {
pkg/routing/iface_reuse_test.go:160:func (f *fakeLinkOps) AddrList(l netlink.Link, family int) ([]netlink.Addr, error) {
pkg/routing/iface_reuse_test.go:185:	ops := newFakeLinkOps()
pkg/routing/iface_reuse_test.go:201:	ops.hiddenUntil[name] = 1
pkg/routing/iface_reuse_test.go:233:	ops := newFakeLinkOps()
pkg/routing/iface_reuse_test.go:243:	// Make any SECOND LinkByName for this name fail — under the old
pkg/routing/iface_reuse_test.go:246:	ops.byNameErrAfter = 1
pkg/routing/iface_reuse_test.go:257:		t.Errorf("expected exactly 1 LinkByName for %s on the already-exists path, got %d "+
pkg/routing/tunnel.go:21:type linkOps interface {
pkg/routing/tunnel.go:22:	LinkByName(name string) (netlink.Link, error)
pkg/routing/tunnel.go:32:	AddrDel(netlink.Link, *netlink.Addr) error
pkg/routing/tunnel.go:282:		if link, err := t.ops.LinkByName(name); err == nil {
pkg/routing/tunnel.go:354:	if existing, lookupErr := t.ops.LinkByName(tc.Name); lookupErr == nil {
pkg/routing/tunnel.go:384:			existing, lkErr := t.ops.LinkByName(tc.Name)
pkg/routing/tunnel.go:566:	e, lookupErr := t.ops.LinkByName(tc.Name)
pkg/routing/tunnel.go:755:			if delErr := t.ops.AddrDel(link, &a); delErr != nil {
pkg/routing/tunnel.go:838:	vrf, err := t.ops.LinkByName("vrf-" + claim)
pkg/routing/tunnel.go:879:	vrf, err := t.ops.LinkByName("vrf-" + tc.RIListMember)
pkg/routing/tunnel.go:940:	link, err := t.ops.LinkByName(tc.Name)
pkg/routing/tunnel.go:1152://  3. LinkByName; on error do nothing (Up unchanged → retried next tick).
pkg/routing/tunnel.go:1222:	link, err := t.ops.LinkByName(tunnelName)
pkg/routing/tunnel.go:1378:		link, err := t.ops.LinkByName(name)
pkg/routing/tunnel.go:1414:		link, err := t.ops.LinkByName(name)
pkg/routing/probe_pin_test.go:91:func (f *fakeProbePinOps) LinkByName(name string) (netlink.Link, error) {
pkg/routing/probe_pin.go:135:	LinkByName(name string) (netlink.Link, error)
pkg/routing/probe_pin.go:189:		link, err := p.ops.LinkByName(pin.Interface)
pkg/routing/monitor.go:43:			link, err := mm.ops.LinkByName(linuxName)
pkg/routing/tunnel_keepalive_test.go:50:// of them (for lock-scope / drain tests), and can fail LinkByName.
pkg/routing/tunnel_keepalive_test.go:60:	byNameErr error
pkg/routing/tunnel_keepalive_test.go:71:func (o *kaOps) LinkByName(name string) (netlink.Link, error) {
pkg/routing/tunnel_keepalive_test.go:74:	if o.byNameErr != nil {
pkg/routing/tunnel_keepalive_test.go:75:		return nil, o.byNameErr
pkg/routing/tunnel_keepalive_test.go:91:func (o *kaOps) AddrDel(netlink.Link, *netlink.Addr) error      { return nil }
pkg/routing/tunnel_keepalive_test.go:92:func (o *kaOps) AddrList(netlink.Link, int) ([]netlink.Addr, error) {
pkg/routing/tunnel_keepalive_test.go:270:// --- §9 LinkByName error on transition: Up not latched, retried ---
pkg/routing/tunnel_keepalive_test.go:271:func TestKeepaliveLinkByNameErrorNoLatch(t *testing.T) {
pkg/routing/tunnel_keepalive_test.go:273:	ops.byNameErr = errors.New("transient netlink error")
pkg/routing/tunnel_keepalive_test.go:279:	// LinkByName keeps failing → no down committed, Up stays true.
pkg/routing/tunnel_keepalive_test.go:281:		t.Fatal("Up must not latch false on LinkByName error")
pkg/routing/tunnel_keepalive_test.go:292:	ops.byNameErr = nil
pkg/routing/tunnel_keepalive_test.go:423:// --- Finding 1 (Codex PR #1947 r1 HIGH): a TRANSIENT LinkByName error
pkg/routing/tunnel_keepalive_test.go:429:	ops.byNameErr = errors.New("transient netlink transport error") // NOT a LinkNotFound
pkg/routing/tunnel_keepalive_test.go:538:	// Seed a live keepalive runner. LinkByName returns a *netlink.Dummy,
pkg/routing/tunnel_reconcile_test.go:76:	ops := newFakeLinkOps()
pkg/routing/tunnel_reconcile_test.go:116:	ops := newFakeLinkOps()
pkg/routing/tunnel_reconcile_test.go:143:	ops := newFakeLinkOps()
pkg/routing/tunnel_reconcile_test.go:169:	ops := newFakeLinkOps()
pkg/routing/tunnel_reconcile_test.go:207:			ops := newFakeLinkOps()
pkg/routing/tunnel_reconcile_test.go:229:	ops := newFakeLinkOps()
pkg/routing/tunnel_reconcile_test.go:249:	ops := newFakeLinkOps()
pkg/routing/tunnel_reconcile_test.go:277:	ops := newFakeLinkOps()
pkg/routing/tunnel_reconcile_test.go:297:	ops := newFakeLinkOps()
pkg/routing/tunnel_reconcile_test.go:322:	ops := newFakeLinkOps()
pkg/routing/tunnel_reconcile_test.go:328:	ops.addrDelFail["gr-0-0-0|fe80::8/64"] = errors.New("EBUSY")
pkg/routing/tunnel_reconcile_test.go:337:	delete(ops.addrDelFail, "gr-0-0-0|fe80::8/64")
pkg/routing/tunnel_reconcile_test.go:357:	ops := newFakeLinkOps()
pkg/routing/tunnel_reconcile_test.go:391:	ops := newFakeLinkOps()
pkg/routing/tunnel_reconcile_test.go:411:	ops := newFakeLinkOps()
pkg/routing/tunnel_reconcile_test.go:417:	ops.addrDelFail["wg0|fe80::8/64"] = errors.New("EBUSY")
pkg/routing/tunnel_reconcile_test.go:425:	delete(ops.addrDelFail, "wg0|fe80::8/64")
pkg/routing/tunnel_reconcile_test.go:437:	ops := newFakeLinkOps()
pkg/routing/tunnel_reconcile_test.go:471:	ops := newFakeLinkOps()
pkg/routing/tunnel_reconcile_test.go:507:	ops := newFakeLinkOps()
pkg/routing/tunnel_reconcile_test.go:524:	ops := newFakeLinkOps()
pkg/routing/tunnel_reconcile_test.go:561:	ops := newFakeLinkOps()
pkg/routing/tunnel_reconcile_test.go:596:	ops := newFakeLinkOps()
pkg/routing/tunnel_reconcile_test.go:633:	ops := newFakeLinkOps()
pkg/routing/tunnel_reconcile_test.go:650:	ops := newFakeLinkOps()
pkg/routing/tunnel_reconcile_test.go:684:// kernelShapedGre mimics what LinkByName returns for a GRE device the
pkg/routing/tunnel_reconcile_test.go:704:	ops := newFakeLinkOps()
pkg/routing/tunnel_reconcile_test.go:743:			ops := newFakeLinkOps()
pkg/routing/tunnel_reconcile_test.go:757:	ops := newFakeLinkOps()
pkg/routing/tunnel_reconcile_test.go:775:	ops := newFakeLinkOps()
pkg/routing/tunnel_reconcile_test.go:818:	ops := newFakeLinkOps()
pkg/routing/tunnel_reconcile_test.go:850:	ops := newFakeLinkOps()
pkg/routing/tunnel_reconcile_test.go:863:	ops.hiddenUntil["gr-0-0-0"] = 1
pkg/routing/tunnel_reconcile_test.go:877:	ops := newFakeLinkOps()
pkg/routing/tunnel_reconcile_test.go:902:	ops := newFakeLinkOps()
pkg/routing/tunnel_reconcile_test.go:931:	ops := newFakeLinkOps()
pkg/routing/tunnel_reconcile_test.go:953:	ops := newFakeLinkOps()
pkg/routing/tunnel_reconcile_test.go:980:	ops := newFakeLinkOps()
pkg/routing/tunnel_reconcile_test.go:991:	// non-not-found) error on the vrf-red lookup: byNameErrAfter is a
pkg/routing/tunnel_reconcile_test.go:997:	ops.byNameErrAfter = 1
pkg/routing/tunnel_reconcile_test.go:1009:	ops.byNameErrAfter = 0
pkg/routing/tunnel_reconcile_test.go:1019:	ops := newFakeLinkOps()

codex
State wiring in the plan maps cleanly onto the current manager layout: `Apply` already has the old/next ownership pattern, `ensureReconcileStateLocked` is the lazy-init point, and `clearLocked` resets reconcile maps. I’m checking the fake harness and the FRR/VRF claims for any source-grounded residuals before choosing the verdict.
exec
/bin/bash -lc "nl -ba pkg/routing/iface_reuse_test.go | sed -n '1,180p'" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
     1	package routing
     2	
     3	import (
     4		"errors"
     5		"testing"
     6	
     7		"github.com/psaab/xpf/pkg/config"
     8		"github.com/vishvananda/netlink"
     9	)
    10	
    11	// fakeLinkOps is an in-memory linkOps for the #1706 tunnel/xfrm reuse
    12	// tests. It records which link object LinkSetUp/AddrAdd were invoked
    13	// against so the tests can prove the apply paths operate on the
    14	// kernel-fetched (indexed) link rather than a freshly-constructed,
    15	// ifindex-less one. LinkAdd can be made to fail (EEXIST) to drive the
    16	// "already exists" branches.
    17	type fakeLinkOps struct {
    18		links map[string]netlink.Link // name -> seeded existing link
    19	
    20		// addExisting makes LinkAdd report the link already exists.
    21		addExisting bool
    22	
    23		// byNameErrAfter, when > 0, makes LinkByName return an error once it
    24		// has been called this many times for the same name (used to drive a
    25		// transient second-lookup failure under the OLD double-lookup code).
    26		byNameCount    map[string]int
    27		byNameErrAfter int
    28	
    29		// hiddenUntil[name] = k makes LinkByName report not-found for the
    30		// first k calls, then return the seeded link. Models a link that the
    31		// pre-loop delete lookup misses but that exists by the time LinkAdd's
    32		// EEXIST fallback lookup runs — the only way the tunnel reuse path
    33		// (goto anchorReady) is reached.
    34		hiddenUntil map[string]int
    35	
    36		// delFail[name] makes LinkDel fail for that link name (#1884
    37		// removal-retention tests).
    38		delFail map[string]error
    39	
    40		// addrDelFail["name|ipnet"] makes AddrDel fail for that address on
    41		// that link (#1884 link-local retention tests).
    42		addrDelFail map[string]error
    43	
    44		// noMasterErr makes LinkSetNoMaster fail (claim retention tests).
    45		noMasterErr error
    46	
    47		// addrs is the per-link kernel address store backing
    48		// AddrAdd/AddrDel/AddrList for the #1884 reconcile tests.
    49		addrs map[string][]netlink.Addr
    50	
    51		// Recorded ops.
    52		setUpLinks []netlink.Link
    53		addrLinks  []netlink.Link
    54		delNames   []string
    55		noMaster   []string
    56		mtuSet     map[string][]int
    57		addrDels   map[string][]string
    58	}
    59	
    60	func newFakeLinkOps() *fakeLinkOps {
    61		return &fakeLinkOps{
    62			links:       map[string]netlink.Link{},
    63			byNameCount: map[string]int{},
    64			hiddenUntil: map[string]int{},
    65			delFail:     map[string]error{},
    66			addrDelFail: map[string]error{},
    67			addrs:       map[string][]netlink.Addr{},
    68			mtuSet:      map[string][]int{},
    69			addrDels:    map[string][]string{},
    70		}
    71	}
    72	
    73	func (f *fakeLinkOps) LinkByName(name string) (netlink.Link, error) {
    74		f.byNameCount[name]++
    75		if f.byNameErrAfter > 0 && f.byNameCount[name] > f.byNameErrAfter {
    76			return nil, errors.New("transient netlink error")
    77		}
    78		if hide, ok := f.hiddenUntil[name]; ok && f.byNameCount[name] <= hide {
    79			return nil, errLinkNotFound{errors.New("link not found")}
    80		}
    81		if l, ok := f.links[name]; ok {
    82			return l, nil
    83		}
    84		return nil, errLinkNotFound{errors.New("link not found")}
    85	}
    86	
    87	func (f *fakeLinkOps) LinkAdd(l netlink.Link) error {
    88		if f.addExisting {
    89			return errors.New("file exists")
    90		}
    91		f.links[l.Attrs().Name] = l
    92		return nil
    93	}
    94	
    95	func (f *fakeLinkOps) LinkDel(l netlink.Link) error {
    96		name := l.Attrs().Name
    97		if err, ok := f.delFail[name]; ok {
    98			return err
    99		}
   100		f.delNames = append(f.delNames, name)
   101		delete(f.links, name)
   102		delete(f.addrs, name)
   103		return nil
   104	}
   105	
   106	func (f *fakeLinkOps) LinkSetUp(l netlink.Link) error {
   107		// Mirror the real netlink handle: dereferencing a nil link panics.
   108		// A correct caller never passes nil here.
   109		_ = l.Attrs()
   110		f.setUpLinks = append(f.setUpLinks, l)
   111		return nil
   112	}
   113	
   114	func (f *fakeLinkOps) LinkSetDown(l netlink.Link) error      { return nil }
   115	func (f *fakeLinkOps) LinkSetMaster(l, m netlink.Link) error { return nil }
   116	
   117	func (f *fakeLinkOps) LinkSetNoMaster(l netlink.Link) error {
   118		if f.noMasterErr != nil {
   119			return f.noMasterErr
   120		}
   121		f.noMaster = append(f.noMaster, l.Attrs().Name)
   122		l.Attrs().MasterIndex = 0
   123		return nil
   124	}
   125	
   126	func (f *fakeLinkOps) LinkSetMTU(l netlink.Link, mtu int) error {
   127		name := l.Attrs().Name
   128		f.mtuSet[name] = append(f.mtuSet[name], mtu)
   129		l.Attrs().MTU = mtu
   130		return nil
   131	}
   132	
   133	func (f *fakeLinkOps) LinkList() ([]netlink.Link, error) { return nil, nil }
   134	
   135	func (f *fakeLinkOps) AddrAdd(l netlink.Link, a *netlink.Addr) error {
   136		_ = l.Attrs()
   137		f.addrLinks = append(f.addrLinks, l)
   138		name := l.Attrs().Name
   139		f.addrs[name] = append(f.addrs[name], *a)
   140		return nil
   141	}
   142	
   143	func (f *fakeLinkOps) AddrDel(l netlink.Link, a *netlink.Addr) error {
   144		name := l.Attrs().Name
   145		key := a.IPNet.String()
   146		if err, ok := f.addrDelFail[name+"|"+key]; ok {
   147			return err
   148		}
   149		f.addrDels[name] = append(f.addrDels[name], key)
   150		kept := f.addrs[name][:0]
   151		for _, existing := range f.addrs[name] {
   152			if existing.IPNet.String() != key {
   153				kept = append(kept, existing)
   154			}
   155		}
   156		f.addrs[name] = kept
   157		return nil
   158	}
   159	
   160	func (f *fakeLinkOps) AddrList(l netlink.Link, family int) ([]netlink.Addr, error) {
   161		return append([]netlink.Addr(nil), f.addrs[l.Attrs().Name]...), nil
   162	}
   163	
   164	// hasAddr reports whether the fake kernel store holds ipnet on name.
   165	func (f *fakeLinkOps) hasAddr(name, ipnet string) bool {
   166		for _, a := range f.addrs[name] {
   167			if a.IPNet.String() == ipnet {
   168				return true
   169			}
   170		}
   171		return false
   172	}
   173	
   174	// noopVRFBinder satisfies vrfBinder without touching netlink.
   175	type noopVRFBinder struct{}
   176	
   177	func (noopVRFBinder) BindInterfaceToVRF(ifaceName, instanceName string) error { return nil }
   178	
   179	// TestTunnelAnchorReuseUsesExistingLink covers #1706 defect 1: when an
   180	// anchor-only TUN already exists, the reuse path (LinkAdd fails, lookup

exec
/bin/bash -lc "nl -ba pkg/routing/tunnel.go | sed -n '1,40p'" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
     1	package routing
     2	
     3	import (
     4		"context"
     5		"fmt"
     6		"log/slog"
     7		"net"
     8		"os"
     9		"os/exec"
    10		"sync"
    11		"sync/atomic"
    12		"time"
    13	
    14		"github.com/psaab/xpf/pkg/config"
    15		"github.com/vishvananda/netlink"
    16	)
    17	
    18	// linkOps is the narrow netlink surface the interface domains
    19	// (tunnel, xfrm, bond, reth) use for link/address lifecycle. Satisfied
    20	// by *netlink.Handle in production; tests substitute a fake.
    21	type linkOps interface {
    22		LinkByName(name string) (netlink.Link, error)
    23		LinkAdd(netlink.Link) error
    24		LinkDel(netlink.Link) error
    25		LinkSetUp(netlink.Link) error
    26		LinkSetDown(netlink.Link) error
    27		LinkSetMaster(netlink.Link, netlink.Link) error
    28		LinkSetNoMaster(netlink.Link) error
    29		LinkSetMTU(netlink.Link, int) error
    30		LinkList() ([]netlink.Link, error)
    31		AddrAdd(netlink.Link, *netlink.Addr) error
    32		AddrDel(netlink.Link, *netlink.Addr) error
    33		AddrList(netlink.Link, int) ([]netlink.Addr, error)
    34	}
    35	
    36	// vrfBinder is the cross-domain dependency tunnel apply needs to bind a
    37	// tunnel interface to a routing-instance VRF. Satisfied by *vrfManager.
    38	// BindInterfaceToVRF takes no lock, so calling it while holding the
    39	// tunnel lock introduces no lock-ordering cycle (see vrf.go).
    40	type vrfBinder interface {

exec
/bin/bash -lc "rg -n \"collectAppliedTunnels|RoutingInstance|RIListMember|Mode == \\\"wireguard\\\"|wireguard\" pkg/daemon pkg/routing pkg/config -g '*.go'" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
pkg/routing/routes.go:143:func (rr *routeReader) GetAllTableRoutes(instances []*config.RoutingInstanceConfig) ([]TableRoutes, error) {
pkg/routing/rules.go:50:func (n *nextTableManager) Apply(routes []*config.StaticRoute, instances []*config.RoutingInstanceConfig) error {
pkg/routing/rules.go:156:func (rg *ribGroupManager) Apply(ribGroups map[string]*config.RibGroup, instances []*config.RoutingInstanceConfig) error {
pkg/routing/rules.go:382:func BuildPBRRules(fw *config.FirewallConfig, instances []*config.RoutingInstanceConfig) []PBRRule {
pkg/routing/rules.go:409:		if term.RoutingInstance == "" {
pkg/routing/rules.go:412:		tableID, ok := tableIDs[term.RoutingInstance]
pkg/routing/rules.go:416:				"instance", term.RoutingInstance)
pkg/routing/rules.go:453:					Instance: term.RoutingInstance,
pkg/routing/routing_test.go:572:	instances := []*config.RoutingInstanceConfig{
pkg/routing/routing_test.go:643:	instances := []*config.RoutingInstanceConfig{
pkg/routing/routing_test.go:657:							RoutingInstance: "Comcast-GigabitPro",
pkg/routing/routing_test.go:662:							RoutingInstance: "ATT",
pkg/routing/routing_test.go:717:							RoutingInstance: "ATT",
pkg/routing/routing_test.go:748:							RoutingInstance: "Comcast-GigabitPro",
pkg/routing/routing_test.go:773:							RoutingInstance: "ATT",
pkg/routing/routing_test.go:797:							RoutingInstance: "ATT",
pkg/routing/routing_test.go:820:							RoutingInstance: "NonExistent",
pkg/routing/routing_test.go:847:							RoutingInstance: "ATT",
pkg/routing/routing_test.go:873:							RoutingInstance: "ATT",
pkg/routing/routing_test.go:1057:	instances := []*config.RoutingInstanceConfig{
pkg/routing/routing_test.go:1098:	instances := []*config.RoutingInstanceConfig{
pkg/config/parser_cluster_test.go:1184:	if unit0.Tunnel.RoutingInstance != "Atherton-Fiber" {
pkg/config/parser_cluster_test.go:1185:		t.Errorf("unit 0 Tunnel.RoutingInstance = %q, want Atherton-Fiber", unit0.Tunnel.RoutingInstance)
pkg/config/parser_cluster_test.go:1206:	if unit1.Tunnel.RoutingInstance != "Atherton-Fiber" {
pkg/config/parser_cluster_test.go:1207:		t.Errorf("unit 1 RoutingInstance = %q, want Atherton-Fiber", unit1.Tunnel.RoutingInstance)
pkg/config/parser_ast_test.go:965:	if tcpTest.RoutingInstance != "att-vr" {
pkg/config/parser_ast_test.go:966:		t.Errorf("routing-instance: got %q, want att-vr", tcpTest.RoutingInstance)
pkg/config/parser_ast_test.go:1317:	if len(cfg3.RoutingInstances) != 1 {
pkg/config/parser_ast_test.go:1318:		t.Errorf("expected 1 routing instance, got %d", len(cfg3.RoutingInstances))
pkg/config/parser_ast_test.go:1320:	ri := cfg3.RoutingInstances[0]
pkg/config/parser_ast_test.go:1972:	if unit0.Tunnel.RoutingInstance != "my-vrf" {
pkg/config/parser_ast_test.go:1973:		t.Errorf("tunnel routing-instance = %q, want my-vrf", unit0.Tunnel.RoutingInstance)
pkg/config/parser_ast_test.go:2241:func TestMultipleRoutingInstances(t *testing.T) {
pkg/config/parser_ast_test.go:2281:	if len(cfg.RoutingInstances) != 2 {
pkg/config/parser_ast_test.go:2282:		t.Fatalf("RoutingInstances = %d, want 2", len(cfg.RoutingInstances))
pkg/config/parser_ast_test.go:2284:	for _, ri := range cfg.RoutingInstances {
pkg/config/parser_ast_test.go:2289:	var dmzVR *RoutingInstanceConfig
pkg/config/parser_ast_test.go:2291:	for _, ri := range cfg.RoutingInstances {
pkg/config/parser_ast_test.go:2322:	var tunnelVR *RoutingInstanceConfig
pkg/config/parser_ast_test.go:2324:	for _, ri := range cfg.RoutingInstances {
pkg/config/parser_ast_test.go:2338:func TestMultipleRoutingInstancesSetSyntax(t *testing.T) {
pkg/config/parser_ast_test.go:2354:	if len(cfg.RoutingInstances) != 2 {
pkg/config/parser_ast_test.go:2355:		t.Fatalf("RoutingInstances = %d, want 2", len(cfg.RoutingInstances))
pkg/config/parser_ast_test.go:2357:	var dmzVR *RoutingInstanceConfig
pkg/config/parser_ast_test.go:2359:	for _, ri := range cfg.RoutingInstances {
pkg/routing/tunnel.go:261:		if tc.Mode != "wireguard" {
pkg/routing/tunnel.go:302:		if tc.Mode == "wireguard" {
pkg/routing/tunnel.go:304:				slog.Warn("failed to apply wireguard tunnel",
pkg/routing/tunnel.go:310:		// apply (daemon restart, wireguard→gre same-name flip, foreign
pkg/routing/tunnel.go:424://     default 1500 — repairs the wireguard→gre same-name flip, where
pkg/routing/tunnel.go:796://  2. stanza failed or empty, RIListMember nonempty: never unbind (0a
pkg/routing/tunnel.go:798://     when the observed master IS vrf-<RIListMember>, else the prior
pkg/routing/tunnel.go:808:	if tc.RoutingInstance != "" {
pkg/routing/tunnel.go:809:		if err := t.vrfBinder.BindInterfaceToVRF(name, tc.RoutingInstance); err != nil {
pkg/routing/tunnel.go:811:				"name", name, "vrf", tc.RoutingInstance, "err", err)
pkg/routing/tunnel.go:818:		t.appliedRI[name] = tc.RoutingInstance
pkg/routing/tunnel.go:821:	if tc.RIListMember != "" {
pkg/routing/tunnel.go:872:	if tc.RIListMember == "" {
pkg/routing/tunnel.go:879:	vrf, err := t.ops.LinkByName("vrf-" + tc.RIListMember)
pkg/routing/tunnel.go:884:		t.appliedRI[tc.Name] = tc.RIListMember
pkg/routing/tunnel.go:954:			slog.Info("replacing non-TUN link before wireguard tun create",
pkg/routing/tunnel.go:957:				return fmt.Errorf("replace non-tun wireguard link %s: %w", tc.Name, delErr)
pkg/routing/tunnel.go:974:			return fmt.Errorf("create wireguard tun %s: %w", tc.Name, addErr)
pkg/routing/tunnel.go:984:			slog.Warn("failed to set wireguard tun mtu on create",
pkg/routing/tunnel.go:987:		slog.Info("wireguard tun created", "name", tc.Name, "mtu", mtu)
pkg/routing/tunnel.go:994:				slog.Warn("failed to update wireguard tun mtu",
pkg/routing/tunnel.go:997:				slog.Info("wireguard tun mtu updated", "name", tc.Name, "mtu", mtu)
pkg/routing/tunnel.go:1000:		slog.Debug("wireguard tun reused", "name", tc.Name)
pkg/routing/tunnel.go:1004:		slog.Warn("failed to bring up wireguard tun", "name", tc.Name, "err", err)
pkg/routing/tunnel.go:1021:		link, tc.Name, tc.Addresses, t.appliedAddrs[tc.Name], "wireguard tun")
pkg/routing/tunnel.go:1023:	if tc.RoutingInstance != "" {
pkg/routing/tunnel.go:1024:		if bindErr := t.vrfBinder.BindInterfaceToVRF(tc.Name, tc.RoutingInstance); bindErr != nil {
pkg/routing/tunnel.go:1025:			slog.Warn("failed to bind wireguard tun to VRF",
pkg/routing/tunnel.go:1026:				"name", tc.Name, "vrf", tc.RoutingInstance, "err", bindErr)
pkg/daemon/daemon_neighbor.go:172:	for _, ri := range cfg.RoutingInstances {
pkg/routing/tunnel_reconcile_test.go:349:	return &config.TunnelConfig{Name: "wg0", Mode: "wireguard", Addresses: addrs}
pkg/routing/tunnel_reconcile_test.go:442:	tc.RoutingInstance = "red"
pkg/routing/tunnel_reconcile_test.go:476:	tc.RoutingInstance = "red"
pkg/routing/tunnel_reconcile_test.go:485:	listTC.RIListMember = "red"
pkg/routing/tunnel_reconcile_test.go:530:	tc.RoutingInstance = "red"
pkg/routing/tunnel_reconcile_test.go:540:	listTC.RIListMember = "blue"
pkg/routing/tunnel_reconcile_test.go:567:	tc.RoutingInstance = "red"
pkg/routing/tunnel_reconcile_test.go:577:	tc2.RoutingInstance = "blue"
pkg/routing/tunnel_reconcile_test.go:603:	tc.RoutingInstance = "red"
pkg/routing/tunnel_reconcile_test.go:614:	tc2.RoutingInstance = "blue"
pkg/routing/tunnel_reconcile_test.go:615:	tc2.RIListMember = "green"
pkg/routing/tunnel_reconcile_test.go:640:	tc.RIListMember = "blue"
pkg/routing/tunnel_reconcile_test.go:655:	tc.RoutingInstance = "red"
pkg/routing/tunnel_reconcile_test.go:909:	tc.RIListMember = "blue"
pkg/routing/tunnel_reconcile_test.go:939:	tc.RoutingInstance = "red"
pkg/routing/tunnel_reconcile_test.go:940:	tc.RIListMember = "blue"
pkg/routing/tunnel_reconcile_test.go:958:	tc.RoutingInstance = "red"
pkg/routing/tunnel_reconcile_test.go:985:	tc.RoutingInstance = "red"
pkg/config/compiler_interfaces.go:192:						tc.RoutingInstance = nodeVal(destNode)
pkg/config/compiler_interfaces.go:194:						tc.RoutingInstance = v
pkg/config/compiler_interfaces.go:196:				case "wireguard":
pkg/config/compiler_interfaces.go:251:							tc.RoutingInstance = nodeVal(destNode)
pkg/config/compiler_interfaces.go:253:							tc.RoutingInstance = v
pkg/config/compiler_interfaces.go:283:					case "wireguard":
pkg/config/compiler_interfaces.go:664:// `wireguard { ... }` node under a tunnel stanza (#1432 S2a). The
pkg/config/compiler_interfaces.go:668://	    mode wireguard;
pkg/config/compiler_interfaces.go:669://	    wireguard {
pkg/config/compiler_interfaces.go:681:// This is intentionally narrower than the eventual Junos wireguard
pkg/routing/routing.go:134:func (m *Manager) GetAllTableRoutes(instances []*config.RoutingInstanceConfig) ([]TableRoutes, error) {
pkg/routing/routing.go:171:func (m *Manager) ApplyNextTableRules(routes []*config.StaticRoute, instances []*config.RoutingInstanceConfig) error {
pkg/routing/routing.go:176:func (m *Manager) ApplyRibGroupRules(ribGroups map[string]*config.RibGroup, instances []*config.RoutingInstanceConfig) error {
pkg/config/schema_routing.go:295:var schemaRoutingInstances = &schemaNode{desc: "Routing instance configuration", wildcard: &schemaNode{desc: "Routing instance name", placeholder: "<instance-name>", children: map[string]*schemaNode{
pkg/config/compiler_firewall.go:417:				term.RoutingInstance = child.Keys[1]
pkg/config/tunnelid.go:129:// explicit `mode wireguard` — the exact extraction the compiler uses
pkg/config/tunnelid.go:133:// is only ever gre/ipip, so wireguard is always explicit.
pkg/config/tunnelid.go:139:		if prop.Name() == "mode" && len(prop.Keys) >= 2 && prop.Keys[1] == "wireguard" {
pkg/routing/rules_test.go:91:	instances := []*config.RoutingInstanceConfig{
pkg/routing/rules_test.go:145:	instances := []*config.RoutingInstanceConfig{
pkg/routing/rules_test.go:185:	instances := []*config.RoutingInstanceConfig{{Name: "dmz-vr", TableID: 101}}
pkg/routing/rules_test.go:232:	mkConfig := func(n int) (map[string]*config.RibGroup, []*config.RoutingInstanceConfig) {
pkg/routing/rules_test.go:234:		instances := make([]*config.RoutingInstanceConfig, n)
pkg/routing/rules_test.go:242:			instances[i] = &config.RoutingInstanceConfig{
pkg/config/schema.go:24://	schema_interfaces.go  interfaces (+ tunnel/wireguard constructors)
pkg/config/schema.go:122:	"routing-instances":  schemaRoutingInstances,
pkg/config/compiler.go:277:			if err := compileRoutingInstances(node, cfg); err != nil {
pkg/config/compiler.go:922:	for _, ri := range cfg.RoutingInstances {
pkg/config/compiler.go:1323:	for _, inst := range cfg.RoutingInstances {
pkg/config/fbf_fixture_test.go:50:	var fbf *RoutingInstanceConfig
pkg/config/fbf_fixture_test.go:51:	for _, ri := range cfg.RoutingInstances {
pkg/config/fbf_fixture_test.go:65:	if v4 == nil || len(v4.Terms) != 2 || v4.Terms[0].RoutingInstance != "ISP-B" ||
pkg/config/fbf_fixture_test.go:70:	if v6 == nil || len(v6.Terms) != 2 || v6.Terms[0].RoutingInstance != "ISP-B" {
pkg/config/fbf_fixture_test.go:85:	if pr := pol.PreferredRoutes[0]; pr.RoutingInstance != "ISP-B" ||
pkg/daemon/daemon_apply.go:291:		for _, ri := range cfg.RoutingInstances {
pkg/daemon/daemon_apply.go:314:	// Name normalization is shared with collectAppliedTunnels'
pkg/daemon/daemon_apply.go:315:	// RIListMember scan via riMemberLinuxName (#1884) so the tunnel
pkg/daemon/daemon_apply.go:323:		for _, ri := range cfg.RoutingInstances {
pkg/daemon/daemon_apply.go:359:		if err := d.routing.ApplyTunnels(collectAppliedTunnels(cfg)); err != nil {
pkg/daemon/daemon_apply.go:859:		if err := d.routing.ApplyNextTableRules(allRoutes, cfg.RoutingInstances); err != nil {
pkg/daemon/daemon_apply.go:866:		if err := d.routing.ApplyRibGroupRules(cfg.RoutingOptions.RibGroups, cfg.RoutingInstances); err != nil {
pkg/daemon/daemon_apply.go:873:		pbrRules := routing.BuildPBRRules(&cfg.Firewall, cfg.RoutingInstances)
pkg/config/types_system.go:337:	RoutingInstance string // "" = master; may target instance-type forwarding (FBF, #1827 PR-2)
pkg/config/types_system.go:366:	RoutingInstance string // "" = master table
pkg/config/types_system.go:407:// (compileRoutingInstances). The ip-rule priority band 50-99 sits below
pkg/config/types_system.go:433:	RoutingInstance      string
pkg/config/types_system.go:645:	RoutingInstance   string          // routing-instance name (policy-based routing)
pkg/daemon/tunnel_anchor_test.go:24:	tunnels := collectAppliedTunnels(cfg)
pkg/daemon/tunnel_anchor_test.go:46:	tunnels := collectAppliedTunnels(cfg)
pkg/daemon/tunnel_anchor_test.go:69:	tunnels := collectAppliedTunnels(cfg)
pkg/daemon/tunnel_anchor_test.go:79:// and the Source!="" screen in collectAppliedTunnels must not drop it —
pkg/daemon/tunnel_anchor_test.go:89:				Mode:            "wireguard",
pkg/daemon/tunnel_anchor_test.go:96:	tunnels := collectAppliedTunnels(cfg)
pkg/daemon/tunnel_anchor_test.go:98:		t.Fatalf("len(tunnels) = %d, want 1 (wireguard tunnel without source was dropped)", len(tunnels))
pkg/daemon/tunnel_anchor_test.go:100:	if tunnels[0].Mode != "wireguard" || tunnels[0].Name != "wg0" {
pkg/daemon/tunnel_anchor_test.go:104:	// wireguard exemption must not weaken the half-configured-GRE gate.
pkg/daemon/tunnel_anchor_test.go:108:	if got := len(collectAppliedTunnels(cfg)); got != 1 {
pkg/daemon/tunnel_anchor_test.go:113:// #1884: collectAppliedTunnels must plumb the config-desired MTU
pkg/daemon/tunnel_anchor_test.go:116:func TestCollectAppliedTunnelsPopulatesMTUAndRIListMember(t *testing.T) {
pkg/daemon/tunnel_anchor_test.go:152:	cfg.RoutingInstances = []*config.RoutingInstanceConfig{
pkg/daemon/tunnel_anchor_test.go:158:	tunnels := collectAppliedTunnels(cfg)
pkg/daemon/tunnel_anchor_test.go:174:	if got := byName["gr-0-0-0"].RIListMember; got != "red" {
pkg/daemon/tunnel_anchor_test.go:175:		t.Errorf("RIListMember = %q, want red", got)
pkg/daemon/tunnel_anchor_test.go:177:	if got := byName["gr-0-0-1"].RIListMember; got != "" {
pkg/daemon/tunnel_anchor_test.go:178:		t.Errorf("RIListMember = %q for unlisted tunnel, want empty", got)
pkg/daemon/tunnel_anchor_test.go:182:	if got := byName["gr-0-0-1u1"].RIListMember; got != "blue" {
pkg/daemon/tunnel_anchor_test.go:183:		t.Errorf("unit>0 RIListMember = %q, want blue", got)
pkg/daemon/daemon_run.go:87:// the RIListMember scan in collectAppliedTunnels (#1884): the tunnel
pkg/daemon/daemon_run.go:116:func collectAppliedTunnels(cfg *config.Config) []*config.TunnelConfig {
pkg/daemon/daemon_run.go:124:	// 0a's last-bind-wins iteration). Feeds TunnelConfig.RIListMember.
pkg/daemon/daemon_run.go:127:	for _, ri := range cfg.RoutingInstances {
pkg/daemon/daemon_run.go:144:		// this, `interfaces wgN tunnel mode wireguard` compiled and fed
pkg/daemon/daemon_run.go:151:		if ifc.Tunnel != nil && (ifc.Tunnel.Source != "" || ifc.Tunnel.Mode == "wireguard") {
pkg/daemon/daemon_run.go:155:			tc.RIListMember = riListMember[tc.Name]
pkg/daemon/daemon_run.go:170:			tc.RIListMember = riListMember[tc.Name]
pkg/daemon/daemon_run.go:1694:	for _, ri := range cfg.RoutingInstances {
pkg/daemon/daemon_run.go:1731:	for _, ri := range cfg.RoutingInstances {
pkg/daemon/daemon_ipmon_test.go:137:	cfg.RoutingInstances = []*config.RoutingInstanceConfig{
pkg/config/parser_security_test.go:158:	if dscpFilter.Terms[0].RoutingInstance != "Comcast-GigabitPro" {
pkg/config/parser_security_test.go:159:		t.Errorf("expected routing-instance Comcast-GigabitPro, got %q", dscpFilter.Terms[0].RoutingInstance)
pkg/config/parser_security_test.go:196:	if len(cfg.RoutingInstances) != 2 {
pkg/config/parser_security_test.go:197:		t.Errorf("expected 2 routing instances, got %d", len(cfg.RoutingInstances))
pkg/config/parser_security_test.go:256:	if term.RoutingInstance != "sfmix" {
pkg/config/parser_security_test.go:257:		t.Errorf("expected routing-instance sfmix, got %q", term.RoutingInstance)
pkg/config/parser_routing_test.go:402:func TestRoutingInstances(t *testing.T) {
pkg/config/parser_routing_test.go:420:	if len(cfg.RoutingInstances) != 2 {
pkg/config/parser_routing_test.go:421:		t.Fatalf("expected 2 routing instances, got %d", len(cfg.RoutingInstances))
pkg/config/parser_routing_test.go:423:	var comcast, att *RoutingInstanceConfig
pkg/config/parser_routing_test.go:425:	for _, ri := range cfg.RoutingInstances {
pkg/config/parser_routing_test.go:497:	if len(hierCfg.RoutingInstances) != 1 {
pkg/config/parser_routing_test.go:498:		t.Fatalf("hierarchical: expected 1 instance, got %d", len(hierCfg.RoutingInstances))
pkg/config/parser_routing_test.go:500:	if hierCfg.RoutingInstances[0].Name != "Comcast-GigabitPro" {
pkg/config/parser_routing_test.go:501:		t.Errorf("hierarchical instance name: %s", hierCfg.RoutingInstances[0].Name)
pkg/config/parser_routing_test.go:534:	if len(cfg.RoutingInstances) != 2 {
pkg/config/parser_routing_test.go:535:		t.Fatalf("expected 2 routing instances, got %d", len(cfg.RoutingInstances))
pkg/config/parser_routing_test.go:537:	var fwd, vr *RoutingInstanceConfig
pkg/config/parser_routing_test.go:538:	for _, ri := range cfg.RoutingInstances {
pkg/config/parser_routing_test.go:581:	var fwd2 *RoutingInstanceConfig
pkg/config/parser_routing_test.go:582:	for _, ri := range cfg2.RoutingInstances {
pkg/config/parser_routing_test.go:650:func TestRoutingInstanceWithZone(t *testing.T) {
pkg/config/parser_routing_test.go:684:	if len(cfg.RoutingInstances) != 1 {
pkg/config/parser_routing_test.go:685:		t.Fatalf("expected 1 routing instance, got %d", len(cfg.RoutingInstances))
pkg/config/parser_routing_test.go:687:	ri := cfg.RoutingInstances[0]
pkg/config/parser_routing_test.go:1001:func TestRoutingInstanceInterfaceRoutesRibGroup(t *testing.T) {
pkg/config/parser_routing_test.go:1024:	if len(cfg.RoutingInstances) != 1 {
pkg/config/parser_routing_test.go:1025:		t.Fatalf("RoutingInstances = %d, want 1", len(cfg.RoutingInstances))
pkg/config/parser_routing_test.go:1027:	ri := cfg.RoutingInstances[0]
pkg/config/parser_routing_test.go:2340:func TestGRETunnelRoutingInstanceDestination(t *testing.T) {
pkg/config/parser_routing_test.go:2364:	if tc.RoutingInstance != "dmz-vr" {
pkg/config/parser_routing_test.go:2365:		t.Errorf("RoutingInstance = %q, want %q", tc.RoutingInstance, "dmz-vr")
pkg/config/parser_routing_test.go:2961:func TestIPIPTunnelWithRoutingInstance(t *testing.T) {
pkg/config/parser_routing_test.go:2994:	if unit0.Tunnel.RoutingInstance != "Atherton-Fiber" {
pkg/config/parser_routing_test.go:2995:		t.Errorf("RoutingInstance = %q, want Atherton-Fiber", unit0.Tunnel.RoutingInstance)
pkg/config/parser_routing_test.go:3037:// name would make step 0a / the RIListMember veto / ResolveKernelIfName
pkg/config/parser_routing_test.go:3076:// gate must not drop them (the #1736 collectAppliedTunnels twin). All
pkg/config/parser_routing_test.go:3080:		"set interfaces wg0 tunnel mode wireguard",
pkg/config/parser_routing_test.go:3081:		"set interfaces wg0 tunnel wireguard listen-port 51820",
pkg/config/parser_routing_test.go:3208:func TestRoutingInstanceRibInet6(t *testing.T) {
pkg/config/parser_routing_test.go:3224:	if len(cfg.RoutingInstances) != 1 {
pkg/config/parser_routing_test.go:3225:		t.Fatalf("got %d routing instances, want 1", len(cfg.RoutingInstances))
pkg/config/parser_routing_test.go:3227:	ri := cfg.RoutingInstances[0]
pkg/config/parser_routing_test.go:3250:// #1432 S2a: the minimal `tunnel wireguard { ... }` stanza compiles to
pkg/config/parser_routing_test.go:3254:		"set interfaces wg0 tunnel mode wireguard",
pkg/config/parser_routing_test.go:3255:		"set interfaces wg0 tunnel wireguard listen-port 51820",
pkg/config/parser_routing_test.go:3256:		"set interfaces wg0 tunnel wireguard private-key a01010101010101010101010101010101010101010101010101010101010101a",
pkg/config/parser_routing_test.go:3257:		"set interfaces wg0 tunnel wireguard peer public-key b02020202020202020202020202020202020202020202020202020202020202b",
pkg/config/parser_routing_test.go:3258:		"set interfaces wg0 tunnel wireguard peer allowed-ips 10.0.0.0/24",
pkg/config/parser_routing_test.go:3259:		"set interfaces wg0 tunnel wireguard peer allowed-ips 10.0.1.0/24",
pkg/config/parser_routing_test.go:3260:		"set interfaces wg0 tunnel wireguard peer endpoint 203.0.113.1:51820",
pkg/config/parser_routing_test.go:3261:		"set interfaces wg0 tunnel wireguard peer persistent-keepalive 25",
pkg/config/parser_routing_test.go:3282:	if tc.Mode != "wireguard" {
pkg/config/parser_routing_test.go:3283:		t.Errorf("Mode = %q, want wireguard", tc.Mode)
pkg/daemon/daemon_ipmon.go:126:	for _, ri := range cfg.RoutingInstances {
pkg/config/schema_validate_interfaces_test.go:147:		name:     "wireguard-listen-port",
pkg/config/schema_validate_interfaces_test.go:149:		template: "set interfaces wg-0-0-0 tunnel wireguard listen-port %s",
pkg/config/schema_validate_interfaces_test.go:154:		name:     "wireguard-persistent-keepalive",
pkg/config/schema_validate_interfaces_test.go:156:		template: "set interfaces wg-0-0-0 tunnel wireguard peer persistent-keepalive %s",
pkg/config/parser_ipmonitoring_test.go:50:	if master.RoutingInstance != "" || master.Destination != "0.0.0.0/0" ||
pkg/config/parser_ipmonitoring_test.go:55:	if ri.RoutingInstance != "ISP-B" || ri.NextHop != "172.16.80.1" {
pkg/config/parser_ipmonitoring_test.go:120:	if pol.PreferredRoutes[1].RoutingInstance != "ISP-B" {
pkg/config/schema_interfaces.go:5:// tunnel/wireguard subtree constructors it composes. The root
pkg/config/schema_interfaces.go:347:		"wireguard": wireguardSchemaNode(),
pkg/config/schema_interfaces.go:351:// wireguardSchemaNode returns the config-mode schema subtree for the
pkg/config/schema_interfaces.go:352:// `tunnel wireguard { ... }` stanza (#1432 S2a). Minimal generic
pkg/config/schema_interfaces.go:363:func wireguardSchemaNode() *schemaNode {
pkg/daemon/ipv6_static_nexthop_test.go:88:		RoutingInstances: []*config.RoutingInstanceConfig{
pkg/config/compiler_routing.go:274:func compileRoutingInstances(node *Node, cfg *Config) error {
pkg/config/compiler_routing.go:283:		ri := &RoutingInstanceConfig{
pkg/config/compiler_routing.go:341:		cfg.RoutingInstances = append(cfg.RoutingInstances, ri)
pkg/config/tunnelid_test.go:44:		"set interfaces wg1408 unit 0 tunnel mode wireguard",
pkg/config/tunnelid_test.go:45:		"set interfaces wg78 unit 0 tunnel mode wireguard",
pkg/config/tunnelid_test.go:63:		"set interfaces wg1408 unit 0 tunnel mode wireguard",
pkg/config/tunnelid_test.go:64:		"set interfaces wg78 unit 0 tunnel mode wireguard",
pkg/config/tunnelid_test.go:88:		"set groups node1 interfaces wg1408 unit 0 tunnel mode wireguard",
pkg/config/tunnelid_test.go:89:		"set interfaces wg78 unit 0 tunnel mode wireguard",
pkg/config/tunnelid_test.go:113:		"set interfaces wg0 tunnel mode wireguard",
pkg/config/tunnelid_test.go:116:		"set interfaces wg341 tunnel mode wireguard",
pkg/config/tunnelid_test.go:136:		"set interfaces wg0 tunnel mode wireguard",
pkg/config/tunnelid_test.go:138:		"set interfaces wg341 tunnel mode wireguard",
pkg/config/tunnelid_test.go:164:		"set interfaces wg0 tunnel mode wireguard",
pkg/config/tunnelid_test.go:166:		"set interfaces wg34524 unit 0 tunnel mode wireguard",
pkg/config/tunnelid_test.go:179:		"set interfaces wg0 unit 01 tunnel mode wireguard",
pkg/config/tunnelid_test.go:180:		"set interfaces wg341 tunnel mode wireguard",
pkg/config/tunnelid_test.go:206:		"set interfaces wg1408 unit 00 tunnel mode wireguard",
pkg/config/tunnelid_test.go:208:		"set interfaces wg78 unit 0 tunnel mode wireguard",
pkg/config/tunnelid_test.go:217:		"set interfaces wg1408 unit 0 tunnel mode wireguard",
pkg/config/tunnelid_test.go:218:		"set interfaces wg78 unit 0 tunnel mode wireguard",
pkg/config/tunnelid_test.go:229:		"set interfaces wg1408 tunnel mode wireguard",
pkg/config/tunnelid_test.go:232:		"set interfaces wg78 unit 0 tunnel mode wireguard",
pkg/config/tunnelid_test.go:243:		"set interfaces wg0 unit 0 tunnel mode wireguard",
pkg/config/compiler_services.go:101:		for _, ri := range cfg.RoutingInstances {
pkg/config/compiler_services.go:328:			r = &PreferredRoute{RoutingInstance: ri, Destination: rInst.name}
pkg/config/compiler_services.go:395:	instances := make(map[string]*RoutingInstanceConfig)
pkg/config/compiler_services.go:396:	for _, ri := range cfg.RoutingInstances {
pkg/config/compiler_services.go:438:			if pr.RoutingInstance != "" {
pkg/config/compiler_services.go:439:				if _, ok := instances[pr.RoutingInstance]; !ok {
pkg/config/compiler_services.go:441:						name, pr.Destination, pr.RoutingInstance)
pkg/config/compiler_services.go:565:					test.RoutingInstance = nodeVal(prop)
pkg/config/parser_fbf_test.go:23:	var fbf *RoutingInstanceConfig
pkg/config/parser_fbf_test.go:24:	for _, ri := range cfg.RoutingInstances {
pkg/config/parser_fbf_test.go:54:	if steer.RoutingInstance != "ISP-B" {
pkg/config/parser_fbf_test.go:55:		t.Fatalf("steer term routing-instance = %q, want ISP-B", steer.RoutingInstance)
pkg/config/parser_fbf_test.go:75:	if pr.RoutingInstance != "ISP-B" || pr.Destination != "0.0.0.0/0" || pr.NextHop != "172.16.80.1" {
pkg/config/parser_rpm_pin_test.go:156:	cfg.RoutingInstances = []*RoutingInstanceConfig{
pkg/config/parser_rpm_pin_test.go:164:	cfg.RoutingInstances[0].TableID = 100
pkg/config/types_routing.go:301:	RoutingInstance string   // destination routing-instance (VRF)
pkg/config/types_routing.go:311:	// ADOPTING an anchor it did not create (wireguard→gre same-name flip
pkg/config/types_routing.go:312:	// repair). Populated by collectAppliedTunnels; the legacy
pkg/config/types_routing.go:316:	// RIListMember is the routing-instance whose `interface` LIST names
pkg/config/types_routing.go:322:	// Populated by collectAppliedTunnels; the legacy CLI path leaves "".
pkg/config/types_routing.go:323:	RIListMember string
pkg/config/types_routing.go:325:	// WireGuard (#1432 S2a). Populated only when Mode == "wireguard".
pkg/config/types_routing.go:327:	// full Junos wireguard grammar (S6). The engine keys encap on
pkg/config/types_routing.go:357:// RoutingInstanceConfig represents a VRF-based routing instance.
pkg/config/types_routing.go:358:type RoutingInstanceConfig struct {
pkg/config/types.go:274:	RoutingInstances  []*RoutingInstanceConfig
pkg/config/types.go:310:// `source` (the #1736 collectAppliedTunnels twin — the persistent wgN
pkg/config/types.go:317:			(ifc.Tunnel.Source != "" || ifc.Tunnel.Mode == "wireguard")
pkg/config/compiler_routing_rules_test.go:21:	mkRibGroupInstances := func(n int) []*RoutingInstanceConfig {
pkg/config/compiler_routing_rules_test.go:22:		insts := make([]*RoutingInstanceConfig, n)
pkg/config/compiler_routing_rules_test.go:24:			insts[i] = &RoutingInstanceConfig{InterfaceRoutesRibGroup: "leak"}
pkg/config/compiler_routing_rules_test.go:53:		cfg := &Config{RoutingInstances: mkRibGroupInstances(50)}
pkg/config/compiler_routing_rules_test.go:61:		cfg := &Config{RoutingInstances: mkRibGroupInstances(51)}
pkg/config/compiler_routing_rules_test.go:72:		insts := make([]*RoutingInstanceConfig, 60)
pkg/config/compiler_routing_rules_test.go:74:			insts[i] = &RoutingInstanceConfig{} // no rib-group reference
pkg/config/compiler_routing_rules_test.go:76:		cfg := &Config{RoutingInstances: insts}
pkg/config/compiler_routing_rules_test.go:84:		insts := make([]*RoutingInstanceConfig, 51)
pkg/config/compiler_routing_rules_test.go:86:			insts[i] = &RoutingInstanceConfig{InterfaceRoutesRibGroupV6: "leak6"}
pkg/config/compiler_routing_rules_test.go:88:		cfg := &Config{RoutingInstances: insts}
pkg/config/compiler_routing_rules_test.go:108:		cfg.RoutingInstances = append(cfg.RoutingInstances,
pkg/config/compiler_routing_rules_test.go:109:			&RoutingInstanceConfig{InterfaceRoutesRibGroup: "leak"})

exec
/bin/bash -lc "rg -n \"ApplyFull\\(|frr\\.Apply|assembleFRRConfig|frrFullConfig\" pkg/daemon pkg/frr -g '*.go'" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
pkg/frr/fbf_table_render_test.go:107:	if err := m.ApplyFull(fc); err != nil {
pkg/frr/fbf_table_render_test.go:158:	if err := m.ApplyFull(fc); err != nil {
pkg/frr/manager.go:304:	// pkg/ipmon, supplied by the daemon's assembleFRRConfig for BOTH
pkg/frr/manager.go:314:// assembleFRRConfig — the sole production FullConfig constructor — so
pkg/frr/manager.go:318:// must go through the daemon's assembleFRRConfig; pkg/daemon's
pkg/frr/manager.go:341:func (m *Manager) ApplyFull(fc *FullConfig) error {
pkg/frr/preferred_routes_test.go:41:	if err := m.ApplyFull(fc); err != nil {
pkg/frr/preferred_routes_test.go:90:	if err := m.ApplyFull(fc); err != nil {
pkg/frr/preferred_routes_test.go:99:	if err := m.ApplyFull(&FullConfig{}); err != nil {
pkg/frr/preferred_routes_test.go:100:		t.Fatalf("ApplyFull(empty): %v", err)
pkg/daemon/daemon_apply.go:836:	// assembleFRRConfig is the SOLE frr.FullConfig constructor, shared
pkg/daemon/daemon_apply.go:843:		d.applyFRRConfig(d.assembleFRRConfig(cfg, commitOverlay))
pkg/frr/frr_test.go:1199:	_ = m.ApplyFull(fc)
pkg/frr/frr_test.go:1223:	_ = m.ApplyFull(fc)
pkg/frr/frr_test.go:2391:	_ = m.ApplyFull(fc) // reload may fail without vtysh
pkg/frr/frr_test.go:2506:	_ = m.ApplyFull(fc)
pkg/frr/frr_test.go:2532:	_ = m.ApplyFull(fc)
pkg/frr/frr_test.go:2556:	_ = m.ApplyFull(fc)
pkg/frr/frr_test.go:2584:	_ = m.ApplyFull(fc)
pkg/frr/manager_reload_test.go:247:	err := m.ApplyFull(&FullConfig{ClusterMode: true})
pkg/daemon/daemon_ipmon_test.go:112:	fc := d.assembleFRRConfig(cfg, d.ipmonActiveOverlay())
pkg/daemon/daemon_ipmon_test.go:124:	fc = d.assembleFRRConfig(cfg, d.ipmonActiveOverlay())
pkg/daemon/daemon_ipmon_test.go:145:	fc := d.assembleFRRConfig(cfg, nil)
pkg/daemon/daemon_ipmon.go:6://  1. assembleFRRConfig — the SOLE frr.FullConfig constructor, shared
pkg/daemon/daemon_ipmon.go:82:// assembleFRRConfig builds the complete frr.FullConfig for the given
pkg/daemon/daemon_ipmon.go:89:func (d *Daemon) assembleFRRConfig(cfg *config.Config, overlay []config.RouteOverlayEntry) *frr.FullConfig {
pkg/daemon/daemon_ipmon.go:167:	if err := d.frr.ApplyFull(fc); err != nil {
pkg/daemon/daemon_ipmon.go:215:	d.applyFRRConfig(d.assembleFRRConfig(cfg, overlay))
pkg/daemon/frr_fullconfig_guard_test.go:13:// frrFullConfigAllowlist is the closed set of production files allowed
pkg/daemon/frr_fullconfig_guard_test.go:15:// assembleFRRConfig the SOLE production constructor (one overlay, one
pkg/daemon/frr_fullconfig_guard_test.go:20:// frr.Apply/ApplyWithInstances bypasses were deleted under the same
pkg/daemon/frr_fullconfig_guard_test.go:22:var frrFullConfigAllowlist = map[string]string{
pkg/daemon/frr_fullconfig_guard_test.go:24:	"pkg/daemon/daemon_ipmon.go": "assembleFRRConfig — the sole production constructor",
pkg/daemon/frr_fullconfig_guard_test.go:30:	// daemon's assembleFRRConfig instead.
pkg/daemon/frr_fullconfig_guard_test.go:64:			if _, allowed := frrFullConfigAllowlist[rel]; allowed {
pkg/daemon/frr_fullconfig_guard_test.go:106:		t.Fatalf("frr.FullConfig constructed outside assembleFRRConfig in production code:\n  %s\n"+
pkg/daemon/frr_fullconfig_guard_test.go:107:			"assembleFRRConfig (pkg/daemon/daemon_ipmon.go) is the SOLE production\n"+

exec
/bin/bash -lc "rg -n \"WireGuard|wireguard|wg\" pkg/frr pkg/daemon -g '*.go'" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
pkg/daemon/neighbor_periodic_guard_test.go:94:	var wg sync.WaitGroup
pkg/daemon/neighbor_periodic_guard_test.go:95:	wg.Add(1)
pkg/daemon/neighbor_periodic_guard_test.go:98:		wg.Done()
pkg/daemon/neighbor_periodic_guard_test.go:100:	wg.Wait()
pkg/daemon/apply_serialize_test.go:57:	var wg sync.WaitGroup
pkg/daemon/apply_serialize_test.go:58:	wg.Add(callers)
pkg/daemon/apply_serialize_test.go:61:			defer wg.Done()
pkg/daemon/apply_serialize_test.go:65:	wg.Wait()
pkg/daemon/daemon_run.go:140:		// WireGuard tunnels carry no GRE-style local `source` (the peer
pkg/daemon/daemon_run.go:144:		// this, `interfaces wgN tunnel mode wireguard` compiled and fed
pkg/daemon/daemon_run.go:146:		// so the persistent wgN TUN was never created and the Rust
pkg/daemon/daemon_run.go:151:		if ifc.Tunnel != nil && (ifc.Tunnel.Source != "" || ifc.Tunnel.Mode == "wireguard") {
pkg/daemon/daemon_run.go:638:	var wg sync.WaitGroup
pkg/daemon/daemon_run.go:697:		wg.Add(1)
pkg/daemon/daemon_run.go:699:			defer wg.Done()
pkg/daemon/daemon_run.go:710:			wg.Add(1)
pkg/daemon/daemon_run.go:712:				defer wg.Done()
pkg/daemon/daemon_run.go:795:			wg.Add(1)
pkg/daemon/daemon_run.go:797:				defer wg.Done()
pkg/daemon/daemon_run.go:951:		wg.Add(1)
pkg/daemon/daemon_run.go:953:			defer wg.Done()
pkg/daemon/daemon_run.go:959:			wg.Add(1)
pkg/daemon/daemon_run.go:961:				defer wg.Done()
pkg/daemon/daemon_run.go:973:			wg.Add(1)
pkg/daemon/daemon_run.go:975:				defer wg.Done()
pkg/daemon/daemon_run.go:981:			wg.Add(1)
pkg/daemon/daemon_run.go:983:				defer wg.Done()
pkg/daemon/daemon_run.go:1118:		wg.Add(1)
pkg/daemon/daemon_run.go:1120:			defer wg.Done()
pkg/daemon/daemon_run.go:1230:		wg.Add(1)
pkg/daemon/daemon_run.go:1232:			defer wg.Done()
pkg/daemon/daemon_run.go:1368:	wg.Wait()
pkg/daemon/tunnel_anchor_test.go:78:// #1736 S2b regression: a WireGuard tunnel has no GRE-style `source`,
pkg/daemon/tunnel_anchor_test.go:80:// otherwise the persistent wgN TUN is never created and the userspace
pkg/daemon/tunnel_anchor_test.go:86:		"wg0": {
pkg/daemon/tunnel_anchor_test.go:88:				Name:            "wg0",
pkg/daemon/tunnel_anchor_test.go:89:				Mode:            "wireguard",
pkg/daemon/tunnel_anchor_test.go:98:		t.Fatalf("len(tunnels) = %d, want 1 (wireguard tunnel without source was dropped)", len(tunnels))
pkg/daemon/tunnel_anchor_test.go:100:	if tunnels[0].Mode != "wireguard" || tunnels[0].Name != "wg0" {
pkg/daemon/tunnel_anchor_test.go:104:	// wireguard exemption must not weaken the half-configured-GRE gate.
pkg/daemon/rollback_serialize_test.go:100:	var wg sync.WaitGroup
pkg/daemon/rollback_serialize_test.go:101:	wg.Add(2)
pkg/daemon/rollback_serialize_test.go:103:		defer wg.Done()
pkg/daemon/rollback_serialize_test.go:107:		defer wg.Done()
pkg/daemon/rollback_serialize_test.go:110:	wg.Wait()
pkg/daemon/rollback_serialize_test.go:196:		var wg sync.WaitGroup
pkg/daemon/rollback_serialize_test.go:197:		wg.Add(2)
pkg/daemon/rollback_serialize_test.go:199:			defer wg.Done()
pkg/daemon/rollback_serialize_test.go:203:			defer wg.Done()
pkg/daemon/rollback_serialize_test.go:206:		wg.Wait()

codex
The FRR route scoping in r2 is supported by the source I checked: the production `FullConfig` constructor does not read tunnels/WG, while policy rendering can redistribute `direct` as `connected`. That matches the revised connected-route nuance: pruning the kernel address removes the connected route source rather than requiring a separate FRR withdrawal path.
exec
/bin/bash -lc "nl -ba pkg/daemon/daemon_run.go | sed -n '116,175p'" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
   116	func collectAppliedTunnels(cfg *config.Config) []*config.TunnelConfig {
   117		if cfg == nil {
   118			return nil
   119		}
   120		anchorOnly := dataplane.EffectiveType(cfg.System.DataplaneType) == dataplane.TypeUserspace
   121		// Linux interface name -> routing-instance whose `interface` list
   122		// names it, mirroring the step-0a bind loop (forwarding instances
   123		// skipped; shared normalization; later entries overwrite, matching
   124		// 0a's last-bind-wins iteration). Feeds TunnelConfig.RIListMember.
   125		riListMember := map[string]string{}
   126		tunMap := cfg.TunnelNameMap()
   127		for _, ri := range cfg.RoutingInstances {
   128			if ri == nil || ri.InstanceType == "forwarding" {
   129				continue
   130			}
   131			for _, ifaceName := range ri.Interfaces {
   132				riListMember[riMemberLinuxName(tunMap, ifaceName)] = ri.Name
   133			}
   134		}
   135		var tunnels []*config.TunnelConfig
   136		for _, ifc := range cfg.Interfaces.Interfaces {
   137			if ifc == nil {
   138				continue
   139			}
   140			// WireGuard tunnels carry no GRE-style local `source` (the peer
   141			// lives in WgEndpoint; the local side is just a listen port), so
   142			// the Source!="" gate that screens half-configured GRE/IPIP
   143			// stanzas must not drop them. Found live in #1736 S2b: without
   144			// this, `interfaces wgN tunnel mode wireguard` compiled and fed
   145			// the dataplane snapshot, but applyWireguardTunLocked never ran,
   146			// so the persistent wgN TUN was never created and the Rust
   147			// control thread's open_tun failed. The dataplane side already
   148			// special-cases the missing source
   149			// (pkg/dataplane/userspace/tunnels.go); this is the routing-side
   150			// twin.
   151			if ifc.Tunnel != nil && (ifc.Tunnel.Source != "" || ifc.Tunnel.Mode == "wireguard") {
   152				tc := *ifc.Tunnel
   153				tc.AnchorOnly = anchorOnly
   154				tc.MTU = ifc.MTU
   155				tc.RIListMember = riListMember[tc.Name]
   156				tunnels = append(tunnels, &tc)
   157			}
   158			for _, unit := range ifc.Units {
   159				if unit == nil || unit.Tunnel == nil {
   160					continue
   161				}
   162				tc := *unit.Tunnel
   163				tc.AnchorOnly = anchorOnly
   164				// Unit-level MTU overrides interface-level, mirroring the
   165				// compiler_iface precedence (#1884).
   166				tc.MTU = ifc.MTU
   167				if unit.MTU > 0 {
   168					tc.MTU = unit.MTU
   169				}
   170				tc.RIListMember = riListMember[tc.Name]
   171				tunnels = append(tunnels, &tc)
   172			}
   173		}
   174		return tunnels
   175	}

exec
/bin/bash -lc "nl -ba pkg/daemon/daemon_apply.go | sed -n '280,365p;828,846p'" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
   280		const mgmtVRFName = "mgmt"
   281		const mgmtTableID = 999
   282		mgmtIfaces := make(map[string]bool)
   283		for name := range cfg.Interfaces.Interfaces {
   284			if strings.HasPrefix(name, "fxp") || strings.HasPrefix(name, "fab") || strings.HasPrefix(name, "em") {
   285				mgmtIfaces[config.LinuxIfName(name)] = true
   286			}
   287		}
   288	
   289		if d.routing != nil {
   290			var desired []routing.VRFSpec
   291			for _, ri := range cfg.RoutingInstances {
   292				if ri.InstanceType == "forwarding" {
   293					slog.Info("forwarding instance, skipping VRF creation",
   294						"instance", ri.Name)
   295					continue
   296				}
   297				desired = append(desired, routing.VRFSpec{
   298					Name:    ri.Name,
   299					TableID: ri.TableID,
   300				})
   301			}
   302			if len(mgmtIfaces) > 0 {
   303				desired = append(desired, routing.VRFSpec{
   304					Name:    mgmtVRFName,
   305					TableID: mgmtTableID,
   306				})
   307			}
   308			if err := d.routing.ReconcileVRFs(desired); err != nil {
   309				slog.Warn("failed to reconcile VRFs", "err", err)
   310			}
   311		}
   312	
   313		// 0a. Bind routing-instance interfaces to their VRFs.
   314		// Name normalization is shared with collectAppliedTunnels'
   315		// RIListMember scan via riMemberLinuxName (#1884) so the tunnel
   316		// manager's unbind veto can never diverge from what this loop
   317		// actually binds. Tunnel list members resolve through
   318		// cfg.TunnelNameMap() (#1904) so a unit>0 entry like gr-0/0/0.1
   319		// binds the real per-unit device (gr-0-0-0u1), not the literal
   320		// ".1" name.
   321		if d.routing != nil {
   322			tunMap := cfg.TunnelNameMap()
   323			for _, ri := range cfg.RoutingInstances {
   324				if ri.InstanceType == "forwarding" {
   325					continue
   326				}
   327				for _, ifaceName := range ri.Interfaces {
   328					linuxName := riMemberLinuxName(tunMap, ifaceName)
   329					if err := d.routing.BindInterfaceToVRF(linuxName, ri.Name); err != nil {
   330						slog.Warn("failed to bind interface to VRF",
   331							"interface", ifaceName, "linux", linuxName,
   332							"instance", ri.Name, "err", err)
   333					}
   334				}
   335			}
   336		}
   337	
   338		// 0b. Bind management interfaces (fxp*/fab*/em*) to vrf-mgmt, but
   339		// only if ReconcileVRFs actually got vrf-mgmt into the managed set.
   340		// If reconcile errored out before vrf-mgmt could be created,
   341		// downstream code (applyMgmtVRFRoutes, HA sync) would otherwise
   342		// run against a non-existent VRF.
   343		d.mgmtVRFInterfaces = nil
   344		if d.routing != nil && len(mgmtIfaces) > 0 && d.routing.IsManagedVRF(mgmtVRFName) {
   345			d.mgmtVRFInterfaces = mgmtIfaces
   346			for ifName := range mgmtIfaces {
   347				if err := d.routing.BindInterfaceToVRF(ifName, mgmtVRFName); err != nil {
   348					slog.Warn("failed to bind interface to management VRF",
   349						"interface", ifName, "err", err)
   350				}
   351			}
   352		}
   353	
   354		// 0.6. Program default routes in the management VRF for DHCP leases.
   355		d.applyMgmtVRFRoutes()
   356	
   357		// 1. Create tunnel interfaces (interface-level + per-unit tunnels)
   358		if d.routing != nil {
   359			if err := d.routing.ApplyTunnels(collectAppliedTunnels(cfg)); err != nil {
   360				slog.Warn("failed to apply tunnels", "err", err)
   361			}
   362		}
   363	
   364		// 1.5. Create xfrmi interfaces for IPsec VPN tunnels.
   365		// Must happen before BPF compilation so compileZones() can discover
   828			// the recovering node stops receiving peer heartbeats and declares
   829			// split-brain after the grace period expires.
   830			if d.cluster != nil {
   831				d.cluster.RestartHeartbeat()
   832			}
   833		}
   834	
   835		// 3. Apply all routes + dynamic protocols via FRR.
   836		// assembleFRRConfig is the SOLE frr.FullConfig constructor, shared
   837		// with the ip-monitoring routes-only actuator (#1827) — the full
   838		// apply consumes the same (config-filtered) overlay computed in
   839		// step 1.95, so an operator commit while a policy is FAILED
   840		// preserves a still-valid injected failover route and drops
   841		// removed/edited entries on the commit itself.
   842		if d.frr != nil {
   843			d.applyFRRConfig(d.assembleFRRConfig(cfg, commitOverlay))
   844		}
   845	
   846		// 3b. Apply next-table policy routing rules (ip rule)

exec
/bin/bash -lc "nl -ba pkg/daemon/frr_fullconfig_guard_test.go | sed -n '1,120p'" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
exec
/bin/bash -lc 'rg -n "routing-instance-removed|VRF residual|ClearTunnels|pruneAppliedAddrsLocked|TestWireguardRemoval|PLAN-READY|PLAN-NEEDS|TODO|MUST|Open questions" docs/research/1919-wg-addr-route-prune/plan.md' in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
6:  PLAN-NEEDS-MAJOR; three converged findings folded in)
9:- **Status**: PLAN DRAFT — research-only; STOP at PLAN-READY
140:| `pkg/routing/tunnel.go:1086-1113` `clearLocked` | delete-everything path (ClearTunnels); does NOT delete WG (not in tunnels/ownedNames) |
207:       `pruneAppliedAddrsLocked(link, name, t.appliedAddrs[name])`
227:   - VRF residual: left as-is (see §4a A1).
231:#### r2 design note — why a dedicated `pruneAppliedAddrsLocked`, NOT `reconcileLinkAddrsLocked(…, nil, …)`
249:  `pruneAppliedAddrsLocked(link, name, applied) (failed map[string]bool)`
335:Decision: **A1** — addresses only, VRF residual documented. If a
344:Document both VRF residuals together so the follow-up has a clear target.
363:// pruneAppliedAddrsLocked deletes the addresses this manager owns from a
369:// MUST hold mu.
370:func (t *tunnelManager) pruneAppliedAddrsLocked(link netlink.Link, name string, applied map[string]bool) map[string]bool {
421:    failed := t.pruneAppliedAddrsLocked(link, name, t.appliedAddrs[name])
443:ClearTunnels still does not delete WG links (unchanged) — but on a full
444:clear the operator intent is teardown; whether ClearTunnels should now
446:Default: leave ClearTunnels behavior unchanged (it never managed WG
468:3. **`TestWireguardRemovalPruneIdempotent`**: third Apply (still empty)
471:4. **`TestWireguardRemovalAddrDelFailureRetried`**: fake AddrDel returns
473:   (`172.16.0.1/30` — r1 review: the retry MUST be proven for the
477:5. **`TestWireguardRemovalDeviceNotFoundDropsTracking`**: LinkByName
480:6. **`TestWireguardRemovalTransientLookupRetained`**: LinkByName returns
502:## 7. Open questions / decisions for reviewer
510:1. **ClearTunnels + WG addresses**: should the explicit delete-everything
512:   plan: NO change to ClearTunnels link behavior; only reset the new
513:   tracking map. Rationale: ClearTunnels never managed WG before; #1434
514:   owns teardown. Reviewer may want ClearTunnels to flush WG addresses
576:  (restart-time removal, VRF residual, link+peer kept).
588:target: all three (Claude SMR + Codex + AGY) PLAN-READY on the final rev.

 succeeded in 0ms:
     1	package daemon
     2	
     3	import (
     4		"go/ast"
     5		"go/parser"
     6		"go/token"
     7		"os"
     8		"path/filepath"
     9		"strings"
    10		"testing"
    11	)
    12	
    13	// frrFullConfigAllowlist is the closed set of production files allowed
    14	// to construct frr.FullConfig composite literals. The #1827 plan made
    15	// assembleFRRConfig the SOLE production constructor (one overlay, one
    16	// constructor, two triggers): any other construction site bypasses the
    17	// ip-monitoring effective-route overlay, so an active failover route
    18	// would be silently wiped from the FRR managed section the next time
    19	// that caller ran (AGY review on PR #1843, finding F1 — the legacy
    20	// frr.Apply/ApplyWithInstances bypasses were deleted under the same
    21	// finding).
    22	var frrFullConfigAllowlist = map[string]string{
    23		// The assembler itself.
    24		"pkg/daemon/daemon_ipmon.go": "assembleFRRConfig — the sole production constructor",
    25		// Legacy standalone-CLI fallback: per the file's package comment,
    26		// production xpfd always wires applyConfigFn so this path is
    27		// skipped; it exists only for a CLI spawned without a daemon
    28		// (no ipmon engine, hence no overlay to preserve). Pre-dates
    29		// #1827. Do NOT add new entries here — route through the
    30		// daemon's assembleFRRConfig instead.
    31		"pkg/cli/apply.go": "legacy standalone-CLI fallback (skipped when the daemon wires applyConfigFn)",
    32	}
    33	
    34	// TestFRRFullConfigConstructedOnlyByAssembler walks every production
    35	// (non-test) .go file under pkg/ and cmd/ and fails if a
    36	// frr.FullConfig (or, inside pkg/frr, a bare FullConfig) composite
    37	// literal appears outside the allowlist. Follows the
    38	// legacy_dataplane_canary_test.go AST-guard precedent.
    39	func TestFRRFullConfigConstructedOnlyByAssembler(t *testing.T) {
    40		t.Parallel()
    41	
    42		repoRoot := filepath.Join("..", "..")
    43		fset := token.NewFileSet()
    44		var offenders []string
    45	
    46		for _, top := range []string{"pkg", "cmd"} {
    47			root := filepath.Join(repoRoot, top)
    48			err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
    49				if err != nil {
    50					return err
    51				}
    52				if d.IsDir() {
    53					return nil
    54				}
    55				name := d.Name()
    56				if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
    57					return nil
    58				}
    59				rel, relErr := filepath.Rel(repoRoot, path)
    60				if relErr != nil {
    61					return relErr
    62				}
    63				rel = filepath.ToSlash(rel)
    64				if _, allowed := frrFullConfigAllowlist[rel]; allowed {
    65					return nil
    66				}
    67	
    68				file, perr := parser.ParseFile(fset, path, nil, parser.AllErrors)
    69				if perr != nil {
    70					t.Fatalf("parse %s: %v", rel, perr)
    71				}
    72				inFRRPackage := strings.HasPrefix(rel, "pkg/frr/")
    73	
    74				ast.Inspect(file, func(n ast.Node) bool {
    75					cl, ok := n.(*ast.CompositeLit)
    76					if !ok {
    77						return true
    78					}
    79					switch typ := cl.Type.(type) {
    80					case *ast.SelectorExpr:
    81						// frr.FullConfig{...} (any import alias would
    82						// still name the type FullConfig).
    83						if typ.Sel != nil && typ.Sel.Name == "FullConfig" {
    84							pos := fset.Position(cl.Pos())
    85							offenders = append(offenders,
    86								rel+":"+itoa(pos.Line)+": frr.FullConfig composite literal")
    87						}
    88					case *ast.Ident:
    89						// Bare FullConfig{...} inside pkg/frr itself.
    90						if inFRRPackage && typ.Name == "FullConfig" {
    91							pos := fset.Position(cl.Pos())
    92							offenders = append(offenders,
    93								rel+":"+itoa(pos.Line)+": FullConfig composite literal")
    94						}
    95					}
    96					return true
    97				})
    98				return nil
    99			})
   100			if err != nil {
   101				t.Fatalf("walk %s: %v", root, err)
   102			}
   103		}
   104	
   105		if len(offenders) > 0 {
   106			t.Fatalf("frr.FullConfig constructed outside assembleFRRConfig in production code:\n  %s\n"+
   107				"assembleFRRConfig (pkg/daemon/daemon_ipmon.go) is the SOLE production\n"+
   108				"constructor (#1827): it injects the ip-monitoring effective-route overlay\n"+
   109				"(PreferredRoutes), so a bypassing construction site silently wipes an\n"+
   110				"active failover route from the FRR managed section. Route the new caller\n"+
   111				"through the daemon's assembler (AGY review on PR #1843, F1).",
   112				strings.Join(offenders, "\n  "))
   113		}
   114	}

exec
/bin/bash -lc "nl -ba docs/research/1919-wg-addr-route-prune/plan.md | sed -n '557,620p'" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
   557	## 9. Validation plan
   558	
   559	- `make test` — Go unit tests (new + existing routing tests).
   560	- `go test ./pkg/routing/...` focused run.
   561	- `go vet ./pkg/routing/...`.
   562	- No smoke required for a control-plane address-reconcile change with no
   563	  dataplane/wire impact — but a manual incus check (configure WG tunnel
   564	  with an address, `ip addr show wgN`, remove from config + commit,
   565	  confirm address gone and link still present) is the acceptance demo
   566	  for the PR description. (Optional at `/engineer` time.)
   567	
   568	---
   569	
   570	## 10. Module-doc updates (part of the contract)
   571	
   572	- Update the `applyWireguardTunLocked` doc comment (`tunnel.go:784-797`)
   573	  to remove/replace the "leaks until ip link del or daemon restart"
   574	  S2a-limitation note (AGY M1) — it is now resolved for the
   575	  config-removal-while-running case; restate the remaining boundaries
   576	  (restart-time removal, VRF residual, link+peer kept).
   577	- Update any `docs/` tunnel/wireguard module doc that states the leak as
   578	  a known limitation. Grep `docs/` for "S2a", "wireguard", "AGY M1",
   579	  "leak" during `/engineer`; if none reference it, say so in review notes.
   580	- PR body: explicitly scope the "FRR routes" claim per §1a (clarified,
   581	  not code-fixed) so the issue's title is fully addressed.
   582	
   583	---
   584	
   585	## 11. Reviewer ledger
   586	
   587	See `reviewer-ids.md` for Codex / AGY task IDs per round. Convergence
   588	target: all three (Claude SMR + Codex + AGY) PLAN-READY on the final rev.
   589	
   590	---
   591	
   592	## Appendix — verbatim key code
   593	
   594	`Apply` WG exclusion (`tunnel.go:168-175`):
   595	```go
   596	desired := make(map[string]bool, len(tunnels))
   597	for _, tc := range tunnels {
   598	    if tc.Mode != "wireguard" {
   599	        desired[tc.Name] = true
   600	    }
   601	}
   602	```
   603	
   604	WG apply branch (`tunnel.go:208-219`):
   605	```go
   606	for _, tc := range tunnels {
   607	    if tc.Mode == "wireguard" {
   608	        if err := t.applyWireguardTunLocked(tc); err != nil {
   609	            slog.Warn("failed to apply wireguard tunnel", "name", tc.Name, "err", err)
   610	        }
   611	        continue
   612	    }
   613	    ...
   614	}
   615	```
   616	
   617	WG address reconcile (the asset we reuse on removal) (`tunnel.go:880-881`):
   618	```go
   619	t.appliedAddrs[tc.Name] = t.reconcileLinkAddrsLocked(
   620	    link, tc.Name, tc.Addresses, t.appliedAddrs[tc.Name], "wireguard tun")

exec
/bin/bash -lc 'git diff -- docs/research/1919-wg-addr-route-prune/plan.md pkg/routing/tunnel.go pkg/routing/tunnel_reconcile_test.go pkg/routing/vrf.go pkg/daemon/daemon_ipmon.go pkg/frr/manager.go pkg/frr/policy_render.go' in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
exec
/bin/bash -lc 'git status --short docs/research/1919-wg-addr-route-prune/plan.md pkg/routing/tunnel.go pkg/routing/tunnel_reconcile_test.go pkg/routing/vrf.go pkg/daemon/daemon_ipmon.go pkg/frr/manager.go pkg/frr/policy_render.go' in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
codex
PLAN-NEEDS-MAJOR

Remaining finding: `AddrList` error fallback is not sound under r2’s “delete all non-link-local” contract. The plan says prune deletes every present non-link-local address, not just `applied` ([plan.md](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/docs/research/1919-wg-addr-route-prune/plan.md:295)), matching current reconcile where `applied` gates only link-local deletion ([tunnel.go](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/tunnel.go:737), [tunnel.go](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/tunnel.go:751)). But on `AddrList` failure the helper returns only `applied`, and explicitly returns empty/drop when `applied` is empty ([plan.md](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/docs/research/1919-wg-addr-route-prune/plan.md:370), [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/docs/research/1919-wg-addr-route-prune/plan.md:421)). Counterexample: stale non-link-local exists on removed `wgN`, `applied` is empty, transient `AddrList` fails; caller drops `wgConfigured`, so no retry and the stale address remains.
tokens used
105,076
PLAN-NEEDS-MAJOR

Remaining finding: `AddrList` error fallback is not sound under r2’s “delete all non-link-local” contract. The plan says prune deletes every present non-link-local address, not just `applied` ([plan.md](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/docs/research/1919-wg-addr-route-prune/plan.md:295)), matching current reconcile where `applied` gates only link-local deletion ([tunnel.go](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/tunnel.go:737), [tunnel.go](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/tunnel.go:751)). But on `AddrList` failure the helper returns only `applied`, and explicitly returns empty/drop when `applied` is empty ([plan.md](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/docs/research/1919-wg-addr-route-prune/plan.md:370), [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/docs/research/1919-wg-addr-route-prune/plan.md:421)). Counterexample: stale non-link-local exists on removed `wgN`, `applied` is empty, transient `AddrList` fails; caller drops `wgConfigured`, so no retry and the stale address remains.
