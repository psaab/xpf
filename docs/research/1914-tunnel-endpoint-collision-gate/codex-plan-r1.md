Reading prompt from stdin...
OpenAI Codex v0.139.0
--------
workdir: /home/ps/git/bpfrx/.claude/worktrees/1914-research-tunnel-collision
model: gpt-5.5
provider: openai
approval: never
sandbox: workspace-write [workdir, /tmp, $TMPDIR]
reasoning effort: xhigh
reasoning summaries: none
session id: 019ed594-30d5-7dd2-85e0-ec9c75de417a
--------
user
You are a HOSTILE plan reviewer. Repo: /home/ps/git/bpfrx/.claude/worktrees/1914-research-tunnel-collision (a git worktree, branch research/1914-tunnel-endpoint-collision-gate). Review the plan doc at docs/research/1914-tunnel-endpoint-collision-gate/plan.md for GitHub issue #1914.

Context: #1914 is a DESIGN DECISION issue. validateTunnelEndpointIDCollisionAST (pkg/config/tunnelid.go) is the #1873 R-B commit-time tunnel-endpoint-id collision gate. It runs PRE-expansion on the union of interfaces + groups so both HA nodes accept/reject identically. Two defects: (A High) wildcard apply-groups refs are hashed literally (<*>.0=50477) so a real post-expansion collision (wg78.0 & wg1408.0 both fold to 824) FALSELY PASSES the commit gate and lands on the runtime usedIDs drop; (B Medium) src/dst-incomplete non-WG tunnels are over-registered (gate registers gr-0/0/0.0 that the builder's addEndpoint drops, risking a phantom false-REJECT at 1/65535 per pair).

Read these files to ground your review:
- pkg/config/tunnelid.go (gate + collector + hash)
- pkg/config/ast_groups.go (ExpandGroups, mergeNodes wildcard semantics — note wildcard merges onto EXISTING dst interfaces only, does not synthesize)
- pkg/config/compiler.go (CompileConfig / CompileConfigForNode call sites lines ~109-195)
- pkg/dataplane/userspace/tunnels.go (buildTunnelEndpointSnapshots / addEndpoint — the src/dst gate at :62 and usedIDs belt at :101)
- pkg/config/tunnelid_test.go (the 13-test regression contract with frozen folds)

Your job: HOSTILELY verify the plan. Specifically interrogate:
1. The HA-symmetry claim of Path 1 (three-view union: pre-expansion ∪ post-expand-node0 ∪ post-expand-node1, all from the SAME candidate). Is the union truly a pure function of config on both nodes? Find any path where node0 and node1 could diverge.
2. The crux open question O1: keeping view 1 (pre-expansion) presence-only re-introduces Defect B's phantom for un-applied-group refs; narrowing view 1 to drop incomplete non-WG risks under-registering a group-supplied src/dst in an UN-APPLIED group. Is there a config where Path 1 still false-ACCEPTS or false-REJECTS? Construct it or confirm none exists.
3. The SSOT name-emitter factoring (O3) — package layering: emitter must live in pkg/config (gate caller) but mirror pkg/dataplane/userspace builder. Is the import direction sound (builder already imports config)? Any cycle?
4. Cost: two extra expand+compile passes per commit. Acceptable? Any correctness hazard from compiling twice (mutation of shared tree)? Note compiler.go already Clone()s before expand.
5. Does the recommended split (Path 1 for A, document/Path-4 for B residual) actually leave any real false-accept? A false-accept is strictly worse than a false-reject here.

Do NOT KILL the plan without a concrete counter-example with quoted lines. Output: PLAN-READY / PLAN-NEEDS-REVISION / PLAN-KILL, then numbered findings each with severity + file:line evidence + concrete fix. Be specific and adversarial.

codex
I’ll ground this in the actual implementation and the plan text, then I’ll evaluate the HA and false-accept/false-reject claims against concrete code paths.
exec
/bin/bash -lc "nl -ba docs/research/1914-tunnel-endpoint-collision-gate/plan.md | sed -n '1,260p'" in /home/ps/git/bpfrx/.claude/worktrees/1914-research-tunnel-collision
 succeeded in 0ms:
     1	# Plan of Action — #1914: tunnel-endpoint collision gate, wildcard apply-groups false accept + src/dst-incomplete over-registration
     2	
     3	- **Issue:** #1914
     4	- **Mode:** `/research` — STOP at PLAN-READY. No PR, no production code.
     5	- **Revision:** r1 (draft)
     6	- **Branch:** `research/1914-tunnel-endpoint-collision-gate`
     7	- **Base:** `origin/master` @ `26e4a112d`
     8	- **Author:** Claude (research driver)
     9	
    10	---
    11	
    12	## 1. Problem statement
    13	
    14	`validateTunnelEndpointIDCollisionAST` (`pkg/config/tunnelid.go:162`) is the
    15	#1873 R-B commit-time gate that fails a commit when two tunnel-endpoint
    16	interface names fold to the same 16-bit `StableTunnelEndpointID`. It runs
    17	on the **pre-expansion** AST (before `ExpandGroups`) by design: it collects
    18	the **union** of tunnel names from `interfaces` and every `groups` block so
    19	both HA nodes accept/reject identically (pre-expansion union is a pure
    20	function of the candidate config, so node0 and node1 compute the same
    21	verdict regardless of which `${node}`-scoped group each would actually
    22	apply).
    23	
    24	Two defects, both **pre-existing since #1873 R-B landed** (PR #1882) and
    25	neither widened nor narrowed by PR #1910/#1904. Found by Codex r6 during
    26	PR #1910 review.
    27	
    28	### 1.1 Defect A — wildcard apply-groups false accept (High)
    29	
    30	`collectTunnelEndpointNamesAST` hashes the **literal** group-AST interface
    31	name. A wildcard group:
    32	
    33	```
    34	set groups wgtun interfaces <*> unit 0 tunnel mode wireguard
    35	set interfaces wg78   apply-groups wgtun
    36	set interfaces wg1408 unit 0 tunnel mode wireguard
    37	```
    38	
    39	registers the gate ref `<*>.0` (id **50477**), never the concrete
    40	post-expansion `wg78.0` (id **824**). The literal `wg1408.0` registers id
    41	**824**. The gate sees `{<*>.0=50477, wg1408.0=824}` — no collision —
    42	and **accepts the commit**. But `ExpandGroups`' wildcard merge
    43	(`mergeNodes`, `ast_groups.go:236`) splices the `unit 0 tunnel mode
    44	wireguard` body onto the **existing** `wg78` interface container, so the
    45	typed compiler emits `wg78.0` AND `wg1408.0`, **both fold to 824**. The
    46	snapshot builder's `usedIDs` belt (`tunnels.go:101`) then drops the
    47	later-sorting one with a loud `slog.Error` — a deterministic runtime drop
    48	instead of a commit rejection.
    49	
    50	**Confirmed empirically** (this research, throwaway test against master):
    51	the above three-line config compiles clean with zero warnings; both
    52	`wg78.unit0` and `wg1408.unit0` carry wireguard `TunnelConfig` in the typed
    53	`cfg.Interfaces.Interfaces` map. Folds verified live: `<*>.0`=50477,
    54	`wg78.0`=`wg1408.0`=824.
    55	
    56	**Severity rationale:** a real builder-emitted collision escapes the
    57	strict commit gate. The runtime belt keeps both nodes consistent (same
    58	deterministic drop), so it is not a split-brain / TCP-death class bug — it
    59	is a "loud silent" drop: one tunnel never installs and the operator only
    60	learns from `slog.Error`, not a commit error. Wildcard WG groups are rare;
    61	the per-pair fold-collision probability is 1/65535.
    62	
    63	### 1.2 Defect B — src/dst-incomplete non-WG tunnels over-registered (Medium)
    64	
    65	`collectTunnelEndpointNamesAST` registers a ref from **tunnel-node
    66	presence alone**. But the builder's `addEndpoint` (`tunnels.go:62`) drops
    67	any **non-WireGuard** tunnel whose `Source` or `Destination` is empty:
    68	
    69	```go
    70	if !isWireguard && (tunnel.Source == "" || tunnel.Destination == "") {
    71	    return
    72	}
    73	```
    74	
    75	So a half-configured GRE (`set interfaces gr-0/0/0 unit 0 tunnel mode
    76	gre`, no source/dest) registers a gate ref the builder will never emit.
    77	**Confirmed empirically:** the gate registers `gr-0/0/0.0` for exactly
    78	this shape. If that phantom ref collides (1/65535 per pair) with a *real*
    79	emitted ref, the commit is **falsely rejected** — the operator cannot
    80	commit a config the builder would have accepted.
    81	
    82	**Why it is conservative-by-design today:** AST-level src/dst presence
    83	cannot be judged reliably pre-expansion, because apply-groups can SUPPLY
    84	the source/destination later. A pre-expansion collector that modeled the
    85	src/dst gate would **under-register** (false ACCEPT — strictly worse than a
    86	false REJECT). So the current over-register is the safe direction given
    87	the pre-expansion constraint. Item B is only fully fixable if the collector
    88	sees an expanded view (couples to Defect A's fix).
    89	
    90	---
    91	
    92	## 2. Current behavior walk (code-grounded)
    93	
    94	| Layer | Function | File:line | Sees groups? | src/dst gate? | wildcard? |
    95	|-------|----------|-----------|--------------|---------------|-----------|
    96	| Commit gate | `validateTunnelEndpointIDCollisionAST` | `tunnelid.go:162` | union, **pre-expansion** | no | hashes `<*>` literally |
    97	| Gate collector | `collectTunnelEndpointNamesAST` | `tunnelid.go:61` | per-block | no (presence-only) | literal name |
    98	| Hash | `StableTunnelEndpointID` | `tunnelid.go:25` | — | — | — |
    99	| Expansion | `ExpandGroups` / `mergeNodes` | `ast_groups.go:13,225` | resolves | — | wildcard merges onto **existing** dst ifaces only |
   100	| Builder | `buildTunnelEndpointSnapshots` / `addEndpoint` | `tunnels.go:13,54` | **post-expansion typed cfg** | **yes** (drops incomplete non-WG) | n/a (concrete names) |
   101	| Runtime belt | `usedIDs` map | `tunnels.go:101` | — | — | deterministic later-sorting drop + `slog.Error` |
   102	
   103	**Key asymmetry:** the gate runs on pre-expansion union AST; the builder
   104	runs on the post-expansion **typed** `cfg.Interfaces.Interfaces`. The gate
   105	therefore cannot see (a) wildcard-expanded concrete names, nor (b)
   106	group-supplied source/destination. The builder sees both but only fails
   107	"loudly silent" via the belt.
   108	
   109	**Important wildcard semantics fact** (proven by reading `mergeNodes`,
   110	`ast_groups.go:236-245`): a wildcard apply-group merges its body onto
   111	interface containers **already present** in the dst tree — it does NOT
   112	synthesize new interfaces. So the post-expansion concrete name set is
   113	exactly `{ interfaces that (a) exist in the candidate AND (b) reference the
   114	wildcard group via apply-groups }`. This bounds the cardinality and makes
   115	post-expansion enumeration tractable.
   116	
   117	**HA-symmetry invariant (the thing #1873 chose pre-expansion to protect):**
   118	the accept/reject verdict must be a pure function of the candidate config
   119	(identical bytes on both nodes ⇒ identical verdict), so config-sync never
   120	splits (originator accepts, peer rejects). Any fix MUST preserve this. A
   121	naive "expand for *this* node then collect" breaks it, because `${node}`
   122	resolves differently on node0 vs node1.
   123	
   124	---
   125	
   126	## 3. Design space — Multiple Path Options
   127	
   128	This is a **design-decision** issue (the issue body says so). Four viable
   129	paths, with the HA-symmetry invariant as the hard constraint.
   130	
   131	### Path 1 — Union of {pre-expansion} ∪ {post-expansion node0} ∪ {post-expansion node1}, all computed from the same candidate tree (RECOMMENDED)
   132	
   133	Collect gate names from THREE views, all derived from the SAME candidate
   134	AST on both nodes:
   135	
   136	1. the existing pre-expansion union (unchanged — preserves the
   137	   group-scoped-collision coverage that
   138	   `TestTunnelEndpointIDCollisionAcrossGroupsIsSymmetric` pins), PLUS
   139	2. the concrete tunnel names the builder would emit after expanding for
   140	   node0, PLUS
   141	3. the concrete tunnel names the builder would emit after expanding for
   142	   node1.
   143	
   144	Because (2) and (3) are *both* computed on *both* nodes from the *same*
   145	candidate config, the union is still a pure function of config ⇒ still
   146	symmetric. node0 expanding "what would node1 see" is deterministic (it is
   147	just `ExpandGroupsWithVars(node1)` on the shared candidate). The gate
   148	rejects if ANY of the three views contains a fold collision.
   149	
   150	To make (2)/(3) faithful to the builder — including the src/dst gate
   151	(Defect B), the WG single-lowest-unit pick, the leading-zero/overflow unit
   152	canonicalization, and last-wins duplicate-unit — the cleanest realization
   153	is to **reuse the actual builder path**: for each node, clone → expand →
   154	`CompileConfig*` → `buildTunnelEndpointSnapshots` → read back the emitted
   155	endpoint names, OR factor the name-emission out of `addEndpoint` into a
   156	pure `config`-package helper the builder also calls (single source of
   157	truth). See §4 for the SSOT factoring.
   158	
   159	- **Defect A:** FIXED — post-expansion views contain `wg78.0`, collision
   160	  with `wg1408.0` detected → commit rejected.
   161	- **Defect B:** FIXED — views are built through the real src/dst gate, so
   162	  incomplete non-WG tunnels are not registered (and group-supplied src/dst
   163	  IS modeled, because expansion ran first). No phantom refs.
   164	- **HA-symmetry:** PRESERVED — all three views are pure functions of the
   165	  shared candidate config; both nodes compute the identical union.
   166	- **Complexity:** Medium-high. Needs the builder's name-emission logic
   167	  reachable from the gate (SSOT factoring) and two extra expand+compile
   168	  passes at commit time (cost: commit is not hot-path; acceptable).
   169	- **Risk:** the pre-expansion union (view 1) must STAY, or a collision
   170	  hidden entirely in an un-applied `groups node1` block (no apply-groups on
   171	  either node — see the existing symmetry test) would stop being caught.
   172	  Keep all three; the union is monotone (more refs ⇒ stricter), so adding
   173	  views can only ADD rejects, never remove the existing ones. That makes
   174	  Defect-B's de-registration the ONLY direction that could *relax* a
   175	  reject — and it only relaxes phantom (never-emitted) refs, which is
   176	  correct.
   177	
   178	  Subtle interaction: view 1 (pre-expansion, presence-only) STILL
   179	  over-registers incomplete GRE refs. So keeping view 1 unchanged does NOT
   180	  fix Defect B by itself — view 1 would still phantom-reject. **Resolution:**
   181	  view 1's role narrows to "catch group-scoped collisions invisible to any
   182	  single node's expansion"; to avoid re-introducing the Defect-B phantom,
   183	  view 1 must ALSO be built through a src/dst-aware collector — but
   184	  pre-expansion it cannot judge group-supplied src/dst. **This is the crux
   185	  the reviewers must rule on** (see §3.5 open question O1). The honest
   186	  framing: Path 1 fixes A cleanly; fixing B fully requires either dropping
   187	  view 1's incomplete-GRE refs (re-opening the theoretical group-supplied
   188	  under-register — but views 2/3 now cover the applied cases) or accepting
   189	  that view 1 still over-registers for the *un-applied-group* corner only.
   190	
   191	### Path 2 — Expand wildcards inside the collision pass only
   192	
   193	Keep the gate pre-expansion but teach `collectTunnelEndpointNamesAST` to
   194	resolve `<*>` group refs against the set of interfaces that apply that
   195	group, producing concrete names — a narrow, gate-local mini-expander.
   196	
   197	- **Defect A:** FIXED for the wildcard case.
   198	- **Defect B:** NOT fixed (still presence-only).
   199	- **HA-symmetry:** PRESERVED if the mini-expander is a pure function of the
   200	  candidate (it is).
   201	- **Complexity:** Medium, but introduces a SECOND expansion implementation
   202	  that must track `mergeNodes` wildcard semantics forever (drift risk —
   203	  exactly the class of bug #1910 r2-r6 kept finding when the gate's unit
   204	  logic drifted from the builder's). **Anti-pattern per the repo's own
   205	  history.** Rejected unless Path 1's cost is prohibitive.
   206	
   207	### Path 3 — Gate only complete src+dst tunnels (Defect B narrow fix)
   208	
   209	For non-WG tunnels, register a gate ref only when source AND destination
   210	are present in the AST (mirror the builder's gate).
   211	
   212	- **Defect A:** NOT fixed.
   213	- **Defect B:** PARTIALLY fixed — but pre-expansion it cannot see
   214	  group-supplied src/dst, so it would UNDER-register (false ACCEPT) when a
   215	  group supplies the missing endpoint. The issue body explicitly calls this
   216	  out as "worse than" the current over-register. Rejected as a standalone
   217	  fix.
   218	
   219	### Path 4 — Accept as documented limitation (do nothing structural)
   220	
   221	Document both gaps in `tunnelid.go` + an operator doc, lean on the runtime
   222	`usedIDs` belt + `slog.Error`, and add a metric/log so the silent drop is
   223	observable. Optionally add a `commit` warning that says "wildcard
   224	apply-groups tunnel refs are not collision-checked at commit; a collision
   225	will be dropped at runtime."
   226	
   227	- **Defect A:** UNFIXED, documented.
   228	- **Defect B:** UNFIXED, documented.
   229	- **HA-symmetry:** trivially preserved (no change).
   230	- **Complexity:** Trivial. Honest about the 1/65535 × rare-feature joint
   231	  probability.
   232	- **Risk:** leaves a real (if rare) false-accept. Acceptable ONLY if the
   233	  reviewers judge the joint probability (wildcard WG group × 16-bit fold
   234	  collision) negligible and the runtime belt sufficient.
   235	
   236	---
   237	
   238	## 3.5 Open questions for the reviewers (design decision inputs)
   239	
   240	- **O1 (crux):** In Path 1, does view 1 (pre-expansion union) stay
   241	  presence-only (keeps Defect B's phantom for *un-applied-group* refs) or
   242	  also get the src/dst gate (risk: under-register for group-supplied src/dst
   243	  in un-applied groups)? Recommendation: keep view 1 presence-only but
   244	  scoped to the WG/complete cases the builder can emit without expansion,
   245	  and rely on views 2/3 for everything an apply-group touches. Reviewers
   246	  must confirm this does not re-open a false-accept.
   247	- **O2:** Is the two-extra-expand-and-compile cost at commit acceptable, or
   248	  should the gate read back `buildTunnelEndpointSnapshots` output directly
   249	  (requires the gate to live where it can call the builder — package layer
   250	  question: `config` vs `dataplane/userspace`)?
   251	- **O3:** Should the name-emission logic be factored into ONE pure function
   252	  (SSOT) so the gate and `addEndpoint` can never drift again (the #1910
   253	  r2-r6 drift class)? Strong recommendation: yes.
   254	- **O4:** Is Defect B worth fixing at all, or is the phantom-reject (1/65535
   255	  × half-configured-tunnel-that-also-collides) so rare that Path 4 for B +
   256	  Path 1 for A is the right split?
   257	
   258	---
   259	
   260	## 4. Recommended approach (subject to reviewer convergence)

exec
/bin/bash -lc "nl -ba pkg/config/tunnelid.go | sed -n '1,260p'" in /home/ps/git/bpfrx/.claude/worktrees/1914-research-tunnel-collision
 succeeded in 0ms:
     1	package config
     2	
     3	import (
     4		"fmt"
     5		"hash/fnv"
     6		"sort"
     7		"strconv"
     8	)
     9	
    10	// StableTunnelEndpointID maps a tunnel interface name (unit-qualified,
    11	// e.g. "wg0.0", "gr-0/0/0.0") to a stable nonzero u16 tunnel-endpoint
    12	// id: FNV-1a 64 xor-folded to 16 bits, mapped into [1, 0xFFFF].
    13	//
    14	// THE FOLD IS WIRE-ADJACENT AND MUST NEVER CHANGE (#1873): tunnel
    15	// endpoint ids cross the cluster as bare numbers (SessionValue.FibGen
    16	// in pkg/cluster/sync_protocol.go), and both HA nodes must compute
    17	// identical ids from identical config. The id is a pure function of
    18	// the interface NAME alone — never of runtime state, the rest of the
    19	// tunnel set, or allocation history — so adding or removing one
    20	// tunnel can never renumber another (the positional-id defect this
    21	// replaces), and both nodes agree by construction.
    22	//
    23	// 0 is never returned: id 0 means "not a tunnel" across the
    24	// dataplane.
    25	func StableTunnelEndpointID(name string) uint16 {
    26		h := fnv.New64a()
    27		_, _ = h.Write([]byte(name))
    28		s := h.Sum64()
    29		folded := uint16(s) ^ uint16(s>>16) ^ uint16(s>>32) ^ uint16(s>>48)
    30		return folded%0xFFFF + 1
    31	}
    32	
    33	// collectTunnelEndpointNamesAST appends the unit-qualified tunnel
    34	// endpoint names declared under one "interfaces" hierarchy node,
    35	// mirroring buildTunnelEndpointSnapshots naming exactly:
    36	//
    37	//   - interface-level tunnel, no COMPILABLE units -> "name"
    38	//   - interface-level WIREGUARD tunnel with units -> "name.N" of the
    39	//     lowest numeric unit only (one persistent TUN = one endpoint,
    40	//     #1910 r2/r3 Codex) — registering every unit would model ids the
    41	//     builder never publishes and could falsely reject a commit on a
    42	//     collision involving a never-emitted ref
    43	//   - interface-level non-WG tunnel with units    -> "name.N" per unit
    44	//   - unit-level tunnel                           -> "name.N"
    45	//
    46	// Every registered ref is the CANONICAL decimal form "%s.%d" of an
    47	// Atoi-parsed unit number, because that is all the builder can ever
    48	// emit: the typed compiler skips any unit whose name fails
    49	// strconv.Atoi (compiler_interfaces.go), so iface.Units holds ints
    50	// and the builder formats "%s.%d". Hashing a raw spelling diverges
    51	// both ways (#1910 r4/r5 Codex): `unit 01` must hash as "wg0.1" or
    52	// the gate misses a real collision on the emitted ref, and an
    53	// overflow-only spelling like `unit 999…9` must NOT register a raw
    54	// ref the builder cannot emit — with every unit unparseable,
    55	// iface.Units is empty and the builder emits the BARE interface ref,
    56	// so the gate registers the bare name in that case too.
    57	//
    58	// Handles both AST shapes (hierarchical merged keys and flat-set
    59	// single-key chains) via the same namedInstances helper the compiler
    60	// uses for unit nodes.
    61	func collectTunnelEndpointNamesAST(ifacesNode *Node, out map[string]struct{}) {
    62		if ifacesNode == nil {
    63			return
    64		}
    65		for _, iface := range ifacesNode.Children {
    66			if iface.IsLeaf {
    67				continue
    68			}
    69			name := iface.Name()
    70			if name == "" {
    71				continue
    72			}
    73			tunnelNode := iface.FindChild("tunnel")
    74			hasIfaceTunnel := tunnelNode != nil
    75			units := namedInstances(iface.FindChildren("unit"))
    76			// Mirror the typed compiler's unit admission: only
    77			// Atoi-parseable names become InterfaceUnit entries, and a
    78			// duplicate spelling of the same number (`unit 00` then
    79			// `unit 0`) OVERWRITES — the compiler does
    80			// `ifc.Units[unitNum] = unit` per instance, so the LAST
    81			// declared instance wins and only ITS tunnel node counts
    82			// (#1910 r6 Codex: sticky-OR here would falsely reject a
    83			// collision on a ref whose tunnel lives only on an
    84			// overwritten earlier instance).
    85			unitNums := make([]int, 0, len(units))
    86			unitTunnel := make(map[int]bool, len(units))
    87			for _, unit := range units {
    88				n, err := strconv.Atoi(unit.name)
    89				if err != nil {
    90					continue
    91				}
    92				if _, seen := unitTunnel[n]; !seen {
    93					unitNums = append(unitNums, n)
    94				}
    95				unitTunnel[n] = unit.node.FindChild("tunnel") != nil
    96			}
    97			if hasIfaceTunnel {
    98				if len(unitNums) == 0 {
    99					// No unit compiles (none declared, or none parses):
   100					// the builder sees len(iface.Units)==0 and emits the
   101					// bare interface ref.
   102					out[name] = struct{}{}
   103					continue
   104				}
   105				if astTunnelModeWireguard(tunnelNode) {
   106					lowest := unitNums[0]
   107					for _, n := range unitNums[1:] {
   108						if n < lowest {
   109							lowest = n
   110						}
   111					}
   112					out[fmt.Sprintf("%s.%d", name, lowest)] = struct{}{}
   113					continue
   114				}
   115				for _, n := range unitNums {
   116					out[fmt.Sprintf("%s.%d", name, n)] = struct{}{}
   117				}
   118				continue
   119			}
   120			for _, n := range unitNums {
   121				if unitTunnel[n] {
   122					out[fmt.Sprintf("%s.%d", name, n)] = struct{}{}
   123				}
   124			}
   125		}
   126	}
   127	
   128	// astTunnelModeWireguard reports whether a tunnel AST node carries an
   129	// explicit `mode wireguard` — the exact extraction the compiler uses
   130	// for TunnelConfig.Mode (prop Keys[1], compiler_interfaces.go), so the
   131	// collision gate's single-endpoint selection matches the compiled
   132	// outcome by construction. The compiler's prefix-derived default mode
   133	// is only ever gre/ipip, so wireguard is always explicit.
   134	func astTunnelModeWireguard(tunnelNode *Node) bool {
   135		if tunnelNode == nil {
   136			return false
   137		}
   138		for _, prop := range tunnelNode.Children {
   139			if prop.Name() == "mode" && len(prop.Keys) >= 2 && prop.Keys[1] == "wireguard" {
   140				return true
   141			}
   142		}
   143		return false
   144	}
   145	
   146	// validateTunnelEndpointIDCollisionAST checks the UNION of tunnel
   147	// endpoint names across the main "interfaces" hierarchy AND every
   148	// "groups" block for StableTunnelEndpointID collisions (#1873 R-B).
   149	//
   150	// The union (rather than the per-node effective config) keeps the
   151	// accept/reject decision identical on both chassis-cluster nodes: a
   152	// collision involving a `groups node0`-scoped tunnel must fail commit
   153	// on node1 too, or config-sync would split (originator accepts, peer
   154	// rejects). It runs on the PRE-expansion tree because ExpandGroups
   155	// removes the groups stanza.
   156	//
   157	// Strict (commit / commit-check) returns an error; lenient (load /
   158	// peer-sync of an already-active config) returns a warning so an
   159	// upgraded node still boots — the snapshot builder independently
   160	// drops the later-sorting collider (fail-closed belt-and-braces in
   161	// buildTunnelEndpointSnapshots).
   162	func validateTunnelEndpointIDCollisionAST(tree *ConfigTree, lenient bool) ([]string, error) {
   163		names := make(map[string]struct{})
   164		collectTunnelEndpointNamesAST(tree.FindChild("interfaces"), names)
   165		for _, child := range tree.Children {
   166			if child.Name() != "groups" {
   167				continue
   168			}
   169			for _, group := range child.Children {
   170				// Node{Keys:["groups","node0"]} merges the group name
   171				// into Keys[1]; the children are then the group body.
   172				if len(child.Keys) >= 2 {
   173					collectTunnelEndpointNamesAST(child.FindChild("interfaces"), names)
   174					break
   175				}
   176				collectTunnelEndpointNamesAST(group.FindChild("interfaces"), names)
   177			}
   178		}
   179		if len(names) < 2 {
   180			return nil, nil
   181		}
   182		sorted := make([]string, 0, len(names))
   183		for name := range names {
   184			sorted = append(sorted, name)
   185		}
   186		sort.Strings(sorted)
   187		byID := make(map[uint16]string, len(sorted))
   188		var warnings []string
   189		for _, name := range sorted {
   190			id := StableTunnelEndpointID(name)
   191			owner, taken := byID[id]
   192			if !taken {
   193				byID[id] = name
   194				continue
   195			}
   196			msg := fmt.Sprintf(
   197				"tunnel endpoint id collision between %q and %q (both fold to %d) — rename one interface (#1873)",
   198				owner, name, id)
   199			if !lenient {
   200				return nil, fmt.Errorf("interfaces: %s", msg)
   201			}
   202			warnings = append(warnings, msg+
   203				"; the later-sorting tunnel is NOT installed in the dataplane")
   204		}
   205		return warnings, nil
   206	}

exec
/bin/bash -lc 'pwd && git rev-parse --abbrev-ref HEAD && git rev-parse HEAD' in /home/ps/git/bpfrx/.claude/worktrees/1914-research-tunnel-collision
 succeeded in 0ms:
/home/ps/git/bpfrx/.claude/worktrees/1914-research-tunnel-collision
research/1914-tunnel-endpoint-collision-gate
1eb77314bf21ecbd57b52eeb29f98412a8cf8464

codex
The plan already admits its weak spot around view 1. I’m going through the expansion and builder code now to decide whether that is just an open question or an actual blocking flaw.
exec
/bin/bash -lc "nl -ba docs/research/1914-tunnel-endpoint-collision-gate/plan.md | sed -n '260,620p'" in /home/ps/git/bpfrx/.claude/worktrees/1914-research-tunnel-collision
 succeeded in 0ms:
   260	## 4. Recommended approach (subject to reviewer convergence)
   261	
   262	**Path 1 for Defect A** (the High-severity false accept), with the
   263	name-emission SSOT factoring (O3 = yes). **Path 4 (document) for Defect B**
   264	UNLESS Path 1's expanded views fix it for free — which they do for any
   265	apply-group-touched interface; the residual is only the un-applied-group
   266	incomplete-GRE phantom, which Path 1 view 1 can shed by registering non-WG
   267	refs only when src+dst are present *in the expanded node views* (views
   268	2/3), and keeping view 1 to WG + already-complete refs.
   269	
   270	Concretely, the recommended shape:
   271	
   272	1. **Factor a pure SSOT name emitter** in `pkg/config`: a function that,
   273	   given a typed `*config.Config` (post-expansion), returns the exact set
   274	   of unit-qualified endpoint names `buildTunnelEndpointSnapshots` would
   275	   emit — same WG-lowest-unit pick, same src/dst gate, same canonical
   276	   decimal formatting, same last-wins. `addEndpoint`/`buildTunnelEndpointSnapshots`
   277	   then consume this helper so there is ONE name-emission truth.
   278	   (Package note: the builder lives in `pkg/dataplane/userspace`; the
   279	   emitter must live in `pkg/config` so the gate can call it without an
   280	   import cycle. The builder already imports `pkg/config`, so this is the
   281	   correct direction.)
   282	2. **Gate computes the union** of: pre-expansion group/interface union (view
   283	   1, narrowed to WG + complete non-WG refs to drop the Defect-B phantom)
   284	   ∪ emitter(compile(expand(candidate, node0))) ∪
   285	   emitter(compile(expand(candidate, node1))).
   286	3. **Reject** if any fold collision appears in the union. Strict path
   287	   errors; lenient path warns (unchanged severity split).
   288	
   289	This is fully symmetric (every input is the shared candidate config),
   290	fixes A, and fixes B for every operationally reachable case while keeping
   291	the #1873 group-scoped-symmetry guarantee.
   292	
   293	---
   294	
   295	## 5. Blast radius
   296	
   297	- `pkg/config/tunnelid.go` — gate + collector (rewrite collector path /
   298	  add SSOT emitter call). ~80 LOC.
   299	- `pkg/dataplane/userspace/tunnels.go` — `addEndpoint`/builder consume the
   300	  new SSOT emitter (mechanical; no behavior change to emitted snapshots).
   301	- `pkg/config/tunnelid_test.go` — existing 13 tests are the regression
   302	  contract; ADD wildcard-false-accept + incomplete-GRE-phantom cases. All
   303	  existing folds (`824`, `14730`, `17799`, `50477`) stay frozen.
   304	- No wire/protocol change. No HA sync-protocol change (the id fold is
   305	  untouched — `StableTunnelEndpointID` MUST stay byte-frozen, #1873).
   306	- Commit-path only (not hot-path). Two extra expand+compile passes per
   307	  commit/commit-check is acceptable cost.
   308	
   309	---
   310	
   311	## 6. Test plan
   312	
   313	1. **Regression (must stay green):** all 13 existing `tunnelid_test.go`
   314	   tests, including the frozen-fold pins and the group-symmetry test.
   315	2. **Defect A:** the §1.1 three-line wildcard config must now FAIL strict
   316	   commit with a `wg78.0`/`wg1408.0` + `824` + `collision` + `rename`
   317	   error; must WARN (not error) on the lenient path.
   318	3. **Defect A symmetry:** the wildcard config must reject identically under
   319	   `CompileConfigForNode(tree, 0)` and `CompileConfigForNode(tree, 1)`.
   320	4. **Defect B:** a half-configured GRE (no src/dst) that folds onto a real
   321	   emitted ref must NOT falsely reject (phantom shed); a COMPLETE GRE that
   322	   genuinely collides must still reject.
   323	5. **No false positives:** the existing non-colliding multi-tunnel config
   324	   stays clean; a WG wildcard group applied to a single interface (no
   325	   second colliding ref) compiles clean.
   326	6. **SSOT parity:** a differential test asserting the gate's emitted-name
   327	   set equals `buildTunnelEndpointSnapshots`' emitted-name set for a corpus
   328	   of tunnel configs (the anti-drift guard that O3 is about).
   329	7. `make test` for `pkg/config` + `pkg/dataplane/userspace`.
   330	
   331	No cluster smoke needed at /research time. At /engineer time: a failover
   332	smoke is NOT required (commit-path-only change, no dataplane/VRRP/sync
   333	code), but a `make test` + a manual two-node commit-symmetry check on the
   334	loss cluster confirms the gate rejects identically.
   335	
   336	## 7. Rollback
   337	
   338	Pure revert — single PR, no migration, no persisted-state change. The id
   339	fold is untouched so no node renumbering on rollback.
   340	
   341	## 8. HA / cluster considerations
   342	
   343	The whole point of the design is HA symmetry. The recommended Path 1 keeps
   344	the verdict a pure function of the candidate config. `StableTunnelEndpointID`
   345	is byte-frozen and untouched — no `SessionValue.FibGen` wire change, no
   346	cross-node renumbering. The new logic adds expand-for-node0 + expand-for-node1
   347	passes that BOTH run on BOTH nodes, so the union is identical everywhere.
   348	
   349	## 9. Observability / docs
   350	
   351	- Keep the runtime `usedIDs` `slog.Error` belt (defense in depth even after
   352	  the gate closes A).
   353	- Update the doc comments on `validateTunnelEndpointIDCollisionAST` and
   354	  `collectTunnelEndpointNamesAST` to describe the three-view union.
   355	- If Path 4 is chosen for B, add an operator note that incomplete non-WG
   356	  tunnels are conservatively registered.
   357	
   358	## 10. Alternatives considered (summary)
   359	
   360	See §3. Path 2 (gate-local mini-expander) rejected for drift risk; Path 3
   361	(complete-only, standalone) rejected for under-register; Path 4 (document
   362	only) acceptable ONLY for Defect B's residual, not for the High Defect A.
   363	
   364	## 11. Reviewer convergence ledger
   365	
   366	See `reviewer-ids.md`. Target: 3-way PLAN-READY (Claude SMR + Codex + AGY)
   367	on the final rev. Round verdicts recorded per round below.
   368	
   369	| Round | Claude SMR | Codex | AGY |
   370	|-------|-----------|-------|-----|
   371	| r1 | pending | pending | pending |

exec
/bin/bash -lc "nl -ba pkg/config/ast_groups.go | sed -n '1,340p'" in /home/ps/git/bpfrx/.claude/worktrees/1914-research-tunnel-collision
 succeeded in 0ms:
     1	package config
     2	
     3	import (
     4		"fmt"
     5		"strings"
     6	)
     7	
     8	// ExpandGroups resolves all "apply-groups" references in the tree.
     9	// It collects group definitions from the "groups" stanza, then for each
    10	// "apply-groups <name>" node, clones the referenced group's children and
    11	// merges them into the parent. After expansion, both "groups" and
    12	// "apply-groups" nodes are removed from the tree.
    13	func (t *ConfigTree) ExpandGroups() error {
    14		return t.expandGroups(false, nil)
    15	}
    16	
    17	// ExpandGroupsTagged is like ExpandGroups but tags each inherited node
    18	// with InheritedFrom set to the group name, for "| display inheritance".
    19	func (t *ConfigTree) ExpandGroupsTagged() error {
    20		return t.expandGroups(true, nil)
    21	}
    22	
    23	// ExpandGroupsWithVars is like ExpandGroups but resolves ${var} references
    24	// in apply-groups names before lookup. This supports Junos-style per-node
    25	// group selection, e.g. apply-groups "${node}" with vars {"node": "node0"}.
    26	func (t *ConfigTree) ExpandGroupsWithVars(vars map[string]string) error {
    27		return t.expandGroups(false, vars)
    28	}
    29	
    30	// resolveVars replaces ${key} placeholders in s with values from vars.
    31	func resolveVars(s string, vars map[string]string) string {
    32		if vars == nil {
    33			return s
    34		}
    35		for k, v := range vars {
    36			s = strings.ReplaceAll(s, "${"+k+"}", v)
    37		}
    38		return s
    39	}
    40	
    41	func (t *ConfigTree) expandGroups(tagInherited bool, vars map[string]string) error {
    42		// Collect group definitions: groups { <name> { ... } }
    43		groups := make(map[string]*Node)
    44		for _, child := range t.Children {
    45			if child.Name() == "groups" {
    46				for _, g := range child.Children {
    47					if len(g.Keys) < 1 {
    48						continue
    49					}
    50					name := g.Keys[0]
    51					if len(g.Keys) > 1 {
    52						name = g.Keys[1]
    53					}
    54					groups[name] = g
    55				}
    56			}
    57		}
    58	
    59		// If no groups defined, just strip any stale apply-groups references.
    60		if len(groups) == 0 {
    61			return t.stripApplyGroups(vars)
    62		}
    63	
    64		// Recursively resolve apply-groups at all levels.
    65		// The nil ancestorPath means we're at the top level.
    66		if err := expandGroupsRecursive(&t.Children, groups, nil, nil, tagInherited, vars); err != nil {
    67			return err
    68		}
    69	
    70		// Remove the "groups" stanza itself.
    71		filtered := make([]*Node, 0, len(t.Children))
    72		for _, child := range t.Children {
    73			if child.Name() != "groups" {
    74				filtered = append(filtered, child)
    75			}
    76		}
    77		t.Children = filtered
    78	
    79		return nil
    80	}
    81	
    82	// tagNodesInherited recursively sets InheritedFrom on all nodes.
    83	func tagNodesInherited(nodes []*Node, groupName string) {
    84		for _, n := range nodes {
    85			n.InheritedFrom = groupName
    86			tagNodesInherited(n.Children, groupName)
    87		}
    88	}
    89	
    90	// stripApplyGroups walks the tree after group expansion and returns an error
    91	// if any apply-groups node still references an undefined group. vars is used
    92	// to resolve ${var} placeholders in group names for error messages.
    93	func (t *ConfigTree) stripApplyGroups(vars map[string]string) error {
    94		return stripApplyGroupsInNodes(t.Children, vars)
    95	}
    96	
    97	func stripApplyGroupsInNodes(nodes []*Node, vars map[string]string) error {
    98		for _, child := range nodes {
    99			if child.Name() == "apply-groups" {
   100				name := ""
   101				if len(child.Keys) > 1 {
   102					name = resolveVars(child.Keys[1], vars)
   103				}
   104				return fmt.Errorf("apply-groups references undefined group %q", name)
   105			}
   106			if !child.IsLeaf {
   107				if err := stripApplyGroupsInNodes(child.Children, vars); err != nil {
   108					return err
   109				}
   110			}
   111		}
   112		return nil
   113	}
   114	
   115	// walkGroupToContext walks a group definition's tree to match the ancestor
   116	// context path. Each element of ancestorPath is the Keys slice of a parent
   117	// node from root to the current level. Returns the children of the deepest
   118	// matching node, or nil if the group has no matching subtree.
   119	// Supports <*> wildcard matching in group keys.
   120	func walkGroupToContext(groupChildren []*Node, ancestorPath [][]string) []*Node {
   121		current := groupChildren
   122		for _, pathKeys := range ancestorPath {
   123			var next []*Node
   124			for _, child := range current {
   125				if child.IsLeaf {
   126					continue
   127				}
   128				// Exact match or wildcard match (group keys may contain <*>).
   129				if keysEqual(child.Keys, pathKeys) || keysMatchWildcard(pathKeys, child.Keys) {
   130					next = child.Children
   131					break
   132				}
   133			}
   134			if next == nil {
   135				return nil // group doesn't have matching subtree at this context
   136			}
   137			current = next
   138		}
   139		return current
   140	}
   141	
   142	// expandGroupsRecursive processes apply-groups nodes within a node list,
   143	// then recurses into all children to handle nested apply-groups.
   144	// ancestorPath tracks the key path from root to the current level, enabling
   145	// groups to be walked down to the matching context for nested apply-groups.
   146	// seen tracks group names being expanded to detect circular references.
   147	// If tagInherited is true, merged nodes get InheritedFrom set to the group name.
   148	// vars provides ${var} replacements for group names (may be nil).
   149	func expandGroupsRecursive(nodes *[]*Node, groups map[string]*Node, ancestorPath [][]string, seen map[string]bool, tagInherited bool, vars map[string]string) error {
   150		// First, collect apply-groups references at this level.
   151		// Support bracket-list syntax: apply-groups [ name1 name2 ] produces
   152		// Keys = ["apply-groups", "name1", "name2"].
   153		var applyNames []string
   154		for _, n := range *nodes {
   155			if n.Name() == "apply-groups" {
   156				for _, key := range n.Keys[1:] {
   157					applyNames = append(applyNames, resolveVars(key, vars))
   158				}
   159			}
   160		}
   161	
   162		// Expand each referenced group.
   163		for _, name := range applyNames {
   164			g, ok := groups[name]
   165			if !ok {
   166				return fmt.Errorf("apply-groups references undefined group %q", name)
   167			}
   168	
   169			if seen == nil {
   170				seen = make(map[string]bool)
   171			}
   172			if seen[name] {
   173				return fmt.Errorf("apply-groups circular reference: group %q", name)
   174			}
   175			seen[name] = true
   176	
   177			// Walk the group tree to match the current context path.
   178			var srcChildren []*Node
   179			if len(ancestorPath) == 0 {
   180				// Top-level: merge group's direct children.
   181				srcChildren = g.Children
   182			} else {
   183				srcChildren = walkGroupToContext(g.Children, ancestorPath)
   184			}
   185	
   186			if srcChildren != nil {
   187				cloned := cloneNodes(srcChildren)
   188				if tagInherited {
   189					tagNodesInherited(cloned, name)
   190				}
   191				mergeNodes(nodes, cloned)
   192			}
   193	
   194			delete(seen, name)
   195		}
   196	
   197		// Remove apply-groups nodes.
   198		filtered := make([]*Node, 0, len(*nodes))
   199		for _, n := range *nodes {
   200			if n.Name() != "apply-groups" {
   201				filtered = append(filtered, n)
   202			}
   203		}
   204		*nodes = filtered
   205	
   206		// Recurse into children to handle nested apply-groups.
   207		for _, n := range *nodes {
   208			if !n.IsLeaf && len(n.Children) > 0 {
   209				childPath := make([][]string, len(ancestorPath)+1)
   210				copy(childPath, ancestorPath)
   211				childPath[len(ancestorPath)] = n.Keys
   212				if err := expandGroupsRecursive(&n.Children, groups, childPath, seen, tagInherited, vars); err != nil {
   213					return err
   214				}
   215			}
   216		}
   217	
   218		return nil
   219	}
   220	
   221	// mergeNodes merges src nodes into dst. For container nodes with matching keys,
   222	// children are merged recursively. For leaf nodes or new containers, they are
   223	// appended (group values don't override existing explicit config — existing
   224	// config takes precedence via ordering, since the compiler uses first-match).
   225	func mergeNodes(dst *[]*Node, src []*Node) {
   226		for _, s := range src {
   227			if s.IsLeaf {
   228				// Only add leaf if no matching leaf exists.
   229				if !hasMatchingLeaf(*dst, s.Keys) {
   230					*dst = append(*dst, s)
   231				}
   232				continue
   233			}
   234	
   235			// Check if source keys contain wildcards (<*>).
   236			if keysContainWildcard(s.Keys) {
   237				// Wildcard merge: apply to all matching containers in dst.
   238				for _, d := range *dst {
   239					if !d.IsLeaf && keysMatchWildcard(d.Keys, s.Keys) {
   240						cloned := cloneNodes(s.Children)
   241						mergeNodes(&d.Children, cloned)
   242					}
   243				}
   244				continue
   245			}
   246	
   247			// Container node: find matching container in dst.
   248			found := false
   249			for _, d := range *dst {
   250				if !d.IsLeaf && keysEqual(d.Keys, s.Keys) {
   251					// Merge children recursively.
   252					mergeNodes(&d.Children, s.Children)
   253					found = true
   254					break
   255				}
   256			}
   257			if !found {
   258				*dst = append(*dst, s)
   259			}
   260		}
   261	}
   262	
   263	// keysContainWildcard returns true if any key is the Junos wildcard "<*>".
   264	func keysContainWildcard(keys []string) bool {
   265		for _, k := range keys {
   266			if k == "<*>" {
   267				return true
   268			}
   269		}
   270		return false
   271	}
   272	
   273	// keysMatchWildcard checks if dst keys match src keys where "<*>" matches
   274	// any value. Both slices must have the same length.
   275	func keysMatchWildcard(dst, src []string) bool {
   276		if len(dst) != len(src) {
   277			return false
   278		}
   279		for i := range src {
   280			if src[i] != "<*>" && src[i] != dst[i] {
   281				return false
   282			}
   283		}
   284		return true
   285	}
   286	
   287	// hasMatchingLeaf returns true if nodes contains a leaf whose first key
   288	// matches. This prevents group values from overriding explicit config
   289	// (e.g., if "host-name explicit" already exists, "host-name group" is skipped).
   290	func hasMatchingLeaf(nodes []*Node, keys []string) bool {
   291		if len(keys) == 0 {
   292			return false
   293		}
   294		for _, n := range nodes {
   295			if n.IsLeaf && len(n.Keys) > 0 && n.Keys[0] == keys[0] {
   296				return true
   297			}
   298		}
   299		return false
   300	}

exec
/bin/bash -lc "nl -ba pkg/config/compiler.go | sed -n '1,260p'" in /home/ps/git/bpfrx/.claude/worktrees/1914-research-tunnel-collision
 succeeded in 0ms:
     1	package config
     2	
     3	import (
     4		"errors"
     5		"fmt"
     6		"net"
     7		"strconv"
     8		"strings"
     9	)
    10	
    11	// ErrDPDKDataplaneRetired is the sentinel error returned at commit
    12	// time when a configuration sets `system dataplane-type dpdk`. External
    13	// API consumers (gRPC orchestration, REST wrappers, CLI tooling) can
    14	// match this with errors.Is rather than substring-searching the wrapped
    15	// error text. The wrapped form is preserved verbatim so the operator-
    16	// facing migration message remains stable; see #1525.
    17	//
    18	// Mirrors the runtime-side dataplane.ErrDPDKBackendRetired sentinel
    19	// introduced by #1527 so the config-time and runtime layers both expose
    20	// structured rejections.
    21	var ErrDPDKDataplaneRetired = errors.New(
    22		"the DPDK dataplane backend has been retired; " +
    23			"use 'set system dataplane-type userspace' " +
    24			"(see #1525)")
    25	
    26	// ErrEBPFDataplaneRetired is the sentinel error returned at commit
    27	// time when a configuration sets `system dataplane-type ebpf`. The
    28	// parse path still accepts the token as a legal value so that
    29	// `load merge` / `load override` of a pre-retirement configuration
    30	// does not syntax-error; this strict validator is what tells the
    31	// operator to migrate.
    32	//
    33	// Mirrors the runtime-side dataplane.ErrEBPFBackendRetired sentinel
    34	// introduced by #1476 so the config-time and runtime layers both
    35	// expose structured rejections. The verbatim message must remain
    36	// stable for downstream tooling that matches by text.
    37	var ErrEBPFDataplaneRetired = errors.New(
    38		"the legacy eBPF dataplane backend has been retired; " +
    39			"use 'set system dataplane-type userspace' " +
    40			"(see #1373)")
    41	
    42	// compileOpts carries per-call compilation policy. It is threaded into
    43	// compileExpanded so the strict commit path and the tolerant
    44	// load/peer-sync path can share the identical compile + group-expansion
    45	// pipeline while differing on a single, narrow validator's severity.
    46	type compileOpts struct {
    47		// #1830 (e): the former lenientEqualFlowWorkerCap flag (#1733) is
    48		// retired along with validateEqualFlowWorkerCapStrict — the
    49		// dataplane no longer caps equal-flow-enforcement at 32 workers, so
    50		// there is no severity to downgrade. The lenient compile entry
    51		// points remain for the flags below.
    52	
    53		// sanitizeFreeTextControlChars (#1798) downgrades the control-
    54		// character gate from a hard compile error to sanitize-in-place
    55		// plus a cfg.Warnings entry. The strict commit / commit-check path
    56		// rejects any value or annotation containing ASCII control
    57		// characters — the lexer maps "\n" inside a quoted string to a
    58		// real newline, which injects arbitrary directives into generated
    59		// networkd/FRR/strongSwan files. The tolerant load / peer-sync /
    60		// peer-display paths must instead scrub the value and keep going
    61		// so an already-persisted bad config cannot blackout-boot a node
    62		// or alarm-loop HA config sync. This check deliberately does NOT
    63		// live in SchemaValidate: the tolerant paths need the value scrubbed
    64		// in place, which the read-only schema walk cannot do (and since
    65		// #1319 PR 2 SchemaValidate violations are themselves downgraded to
    66		// warnings on the tolerant paths — see configstore.compileTreeLenient).
    67		// See freetext.go for the full three-layer design.
    68		sanitizeFreeTextControlChars bool
    69	
    70		// lenientVRRPTrackDuplicates (#1814) downgrades the duplicate
    71		// `track-interface` gate (more than one track-interface statement
    72		// inside a single vrrp-group) from a hard compile error to a
    73		// cfg.Warnings entry with deterministic first-wins pruning of the
    74		// extras. Set ONLY on the tolerant load / peer-sync paths
    75		// (CompileConfigLenient / CompileConfigForNodeLenient) so an
    76		// already-persisted or peer-synced config still boots; candidate
    77		// commit / commit-check stay strict and hard-reject new operator
    78		// edits. Like the other lenient gates, this check deliberately does
    79		// NOT live in SchemaValidate: pruning the duplicates is an AST-level
    80		// compile decision the read-only schema walk cannot make (and since
    81		// #1319 PR 2 SchemaValidate violations only warn on tolerant paths).
    82		lenientVRRPTrackDuplicates bool
    83	}
    84	
    85	// CompileConfig converts a parsed ConfigTree AST into a typed Config struct.
    86	// It clones the tree before expansion so the original tree is not mutated.
    87	func CompileConfig(tree *ConfigTree) (*Config, error) {
    88		return compileConfigWithOpts(tree, compileOpts{})
    89	}
    90	
    91	// CompileConfigLenient is CompileConfig with the tolerant-path
    92	// downgrades enabled (#1798 control-char sanitize-in-place, lenient
    93	// VRRP track duplicates). Use on TOLERANT paths that compile an
    94	// already-active / already-persisted config the operator did not just
    95	// author — e.g. Store.Load of a persisted config — so an upgraded node
    96	// boots through. MUST NOT be used on the candidate-commit path:
    97	// commit / commit-check use the strict CompileConfig so new operator
    98	// edits hard-reject. The node-aware sibling CompileConfigForNodeLenient
    99	// covers the cluster paths (Store.SyncApply, peer-interface display).
   100	// (The former #1733 equal-flow worker-cap downgrade was retired in
   101	// #1830 (e) — the dataplane no longer caps equal-flow at 32 workers.)
   102	func CompileConfigLenient(tree *ConfigTree) (*Config, error) {
   103		return compileConfigWithOpts(tree, compileOpts{
   104			sanitizeFreeTextControlChars: true,
   105			lenientVRRPTrackDuplicates:   true,
   106		})
   107	}
   108	
   109	func compileConfigWithOpts(tree *ConfigTree, opts compileOpts) (*Config, error) {
   110		// #1873 R-B: tunnel-endpoint id collision gate. Runs on the
   111		// PRE-expansion tree (ExpandGroups removes the groups stanza) so
   112		// the check covers the UNION of tunnel names across all groups —
   113		// both cluster nodes accept/reject identically. Strict paths
   114		// hard-reject; lenient paths warn (see tunnelid.go).
   115		tunnelIDWarnings, tunnelIDErr := validateTunnelEndpointIDCollisionAST(
   116			tree, opts.sanitizeFreeTextControlChars)
   117		if tunnelIDErr != nil {
   118			return nil, tunnelIDErr
   119		}
   120	
   121		// Clone the tree before expanding groups — the caller's tree must retain
   122		// groups and apply-groups nodes for display (show configuration groups).
   123		tree = tree.Clone()
   124		usedNodeFallback := false
   125	
   126		// Expand groups before compilation — resolve all apply-groups references.
   127		if err := tree.ExpandGroups(); err != nil {
   128			if strings.Contains(err.Error(), `undefined group "${node}"`) {
   129				vars := map[string]string{"node": "node0"}
   130				if err2 := tree.ExpandGroupsWithVars(vars); err2 != nil {
   131					return nil, fmt.Errorf("apply-groups: %w", err2)
   132				}
   133				usedNodeFallback = true
   134			} else {
   135				return nil, fmt.Errorf("apply-groups: %w", err)
   136			}
   137		}
   138	
   139		cfg, err := compileExpanded(tree, opts)
   140		if err != nil {
   141			return nil, err
   142		}
   143		if usedNodeFallback {
   144			cfg.Warnings = append(cfg.Warnings, `apply-groups "${node}" resolved using default node0 context during generic compile`)
   145		}
   146		cfg.Warnings = append(cfg.Warnings, tunnelIDWarnings...)
   147		return cfg, nil
   148	}
   149	
   150	// CompileConfigForNode is like CompileConfig but resolves ${node} variables
   151	// in apply-groups names before lookup. nodeID selects which per-node group
   152	// to apply (e.g. nodeID=0 maps "node" -> "node0", so apply-groups "${node}"
   153	// resolves to group "node0"). This supports a single shared config for both
   154	// nodes in a chassis cluster.
   155	func CompileConfigForNode(tree *ConfigTree, nodeID int) (*Config, error) {
   156		return compileConfigForNodeWithOpts(tree, nodeID, compileOpts{})
   157	}
   158	
   159	// CompileConfigForNodeLenient is CompileConfigForNode with the
   160	// tolerant-path downgrades enabled (see CompileConfigLenient). Use on
   161	// node-aware TOLERANT paths that compile an already-active / peer-synced
   162	// config the local operator did not just author: Store.SyncApply (HA
   163	// peer-sync ingress) and the read-only peer-interface display re-compiles
   164	// (cli_show_interfaces.go, server_show_interfaces.go). MUST NOT be used on
   165	// the candidate-commit path — see CompileConfigLenient.
   166	func CompileConfigForNodeLenient(tree *ConfigTree, nodeID int) (*Config, error) {
   167		return compileConfigForNodeWithOpts(tree, nodeID, compileOpts{
   168			sanitizeFreeTextControlChars: true,
   169			lenientVRRPTrackDuplicates:   true,
   170		})
   171	}
   172	
   173	func compileConfigForNodeWithOpts(tree *ConfigTree, nodeID int, opts compileOpts) (*Config, error) {
   174		// #1873 R-B: union-of-groups tunnel id collision gate — see
   175		// compileConfigWithOpts. Pre-expansion on purpose.
   176		tunnelIDWarnings, tunnelIDErr := validateTunnelEndpointIDCollisionAST(
   177			tree, opts.sanitizeFreeTextControlChars)
   178		if tunnelIDErr != nil {
   179			return nil, tunnelIDErr
   180		}
   181	
   182		tree = tree.Clone()
   183	
   184		vars := map[string]string{"node": fmt.Sprintf("node%d", nodeID)}
   185		if err := tree.ExpandGroupsWithVars(vars); err != nil {
   186			return nil, fmt.Errorf("apply-groups: %w", err)
   187		}
   188	
   189		cfg, err := compileExpanded(tree, opts)
   190		if err != nil {
   191			return nil, err
   192		}
   193		cfg.Warnings = append(cfg.Warnings, tunnelIDWarnings...)
   194		return cfg, nil
   195	}
   196	
   197	// compileExpanded compiles an already-expanded (groups resolved) ConfigTree
   198	// into a typed Config. Shared by CompileConfig and CompileConfigForNode.
   199	func compileExpanded(tree *ConfigTree, opts compileOpts) (*Config, error) {
   200		// #1798 free-text control-character gate. Strict (commit /
   201		// commit-check): hard-reject. Lenient (load / peer-sync / peer
   202		// display): scrub in place on this already-cloned tree and warn.
   203		// Runs on the group-expanded tree so values inherited via
   204		// apply-groups are covered, and BEFORE section compilation so the
   205		// lenient path's typed Config is built from the scrubbed values.
   206		var ctrlCharWarnings []string
   207		if opts.sanitizeFreeTextControlChars {
   208			for _, p := range sanitizeNodesControlChars(tree.Children, "") {
   209				ctrlCharWarnings = append(ctrlCharWarnings, fmt.Sprintf(
   210					"sanitized control characters in configuration value at %q (#1798)", p))
   211			}
   212		} else if err := validateNodesControlChars(tree.Children, ""); err != nil {
   213			return nil, err
   214		}
   215	
   216		// #1814 VRRP track-interface AST pre-walk. Runs on the group-expanded
   217		// tree (so apply-groups-inherited statements are covered) and BEFORE
   218		// section compilation so the lenient path's first-wins pruning is
   219		// what the compiler actually sees. Strict (commit / commit-check):
   220		// duplicate track-interface inside one vrrp-group hard-rejects.
   221		// Lenient (load / peer-sync): prune to the first + warn. Shape-only
   222		// warnings (nested+sibling both present, orphan priority-cost) come
   223		// from here too — the typed config cannot distinguish them
   224		// post-compile.
   225		trackWarnings, err := validateVRRPTrackInterfaceAST(tree.Children, "", opts.lenientVRRPTrackDuplicates)
   226		if err != nil {
   227			return nil, err
   228		}
   229	
   230		cfg := &Config{
   231			Security: SecurityConfig{
   232				Zones:  make(map[string]*ZoneConfig),
   233				Screen: make(map[string]*ScreenProfile),
   234			},
   235			Interfaces: InterfacesConfig{
   236				Interfaces: make(map[string]*InterfaceConfig),
   237			},
   238			Applications: ApplicationsConfig{
   239				Applications:    make(map[string]*Application),
   240				ApplicationSets: make(map[string]*ApplicationSet),
   241			},
   242			ClassOfService: &ClassOfServiceConfig{
   243				ForwardingClasses: make(map[string]*CoSForwardingClass),
   244				DSCPClassifiers:   make(map[string]*CoSDSCPClassifier),
   245				DSCPRewriteRules:  make(map[string]*CoSDSCPRewriteRule),
   246				Schedulers:        make(map[string]*CoSScheduler),
   247				SchedulerMaps:     make(map[string]*CoSSchedulerMap),
   248				Interfaces:        make(map[string]*CoSInterface),
   249			},
   250		}
   251		cfg.Warnings = append(cfg.Warnings, ctrlCharWarnings...)
   252		cfg.Warnings = append(cfg.Warnings, trackWarnings...)
   253	
   254		for _, node := range tree.Children {
   255			switch node.Name() {
   256			case "security":
   257				if err := compileSecurity(node, &cfg.Security); err != nil {
   258					return nil, fmt.Errorf("security: %w", err)
   259				}
   260			case "interfaces":

exec
/bin/bash -lc "nl -ba pkg/dataplane/userspace/tunnels.go | sed -n '1,220p'" in /home/ps/git/bpfrx/.claude/worktrees/1914-research-tunnel-collision
 succeeded in 0ms:
     1	package userspace
     2	
     3	import (
     4		"fmt"
     5		"log/slog"
     6		"net"
     7		"sort"
     8		"strings"
     9	
    10		"github.com/psaab/xpf/pkg/config"
    11	)
    12	
    13	func buildTunnelEndpointSnapshots(cfg *config.Config, interfaces []InterfaceSnapshot) []TunnelEndpointSnapshot {
    14		if cfg == nil || len(cfg.Interfaces.Interfaces) == 0 {
    15			return nil
    16		}
    17		ifaceByName := make(map[string]InterfaceSnapshot, len(interfaces))
    18		rgByAddress := make(map[string]int)
    19		for _, iface := range interfaces {
    20			if iface.Name == "" || iface.Ifindex <= 0 {
    21				continue
    22			}
    23			ifaceByName[iface.Name] = iface
    24			if iface.RedundancyGroup <= 0 {
    25				continue
    26			}
    27			for _, addr := range iface.Addresses {
    28				ip, _, err := net.ParseCIDR(addr.Address)
    29				if err != nil || ip == nil {
    30					continue
    31				}
    32				rgByAddress[ip.String()] = iface.RedundancyGroup
    33			}
    34		}
    35		if len(ifaceByName) == 0 {
    36			return nil
    37		}
    38		names := make([]string, 0, len(cfg.Interfaces.Interfaces))
    39		for name := range cfg.Interfaces.Interfaces {
    40			names = append(names, name)
    41		}
    42		sort.Strings(names)
    43		out := make([]TunnelEndpointSnapshot, 0)
    44		// #1873: ids are content-derived (config.StableTunnelEndpointID of
    45		// the unit-qualified interface name), NOT positional — adding or
    46		// removing one tunnel can never renumber another, and both HA
    47		// nodes compute identical ids from identical config. usedIDs is
    48		// the fail-closed belt-and-braces behind the commit-time collision
    49		// gate (validateTunnelEndpointIDCollisionAST): a snapshot must
    50		// never carry two rows with one id, so the later-sorting collider
    51		// is dropped loudly. Iteration is sorted (names + unit numbers),
    52		// so the drop is deterministic.
    53		usedIDs := make(map[uint16]string)
    54		addEndpoint := func(ifName string, tunnel *config.TunnelConfig) {
    55			if tunnel == nil {
    56				return
    57			}
    58			// WireGuard endpoints carry the peer in WgEndpoint and need no
    59			// Source/Destination (#1432 S2a); a WG endpoint configured with
    60			// only WgEndpoint must not be dropped by the GRE source/dest gate.
    61			isWireguard := tunnel.Mode == "wireguard"
    62			if !isWireguard && (tunnel.Source == "" || tunnel.Destination == "") {
    63				return
    64			}
    65			iface, ok := ifaceByName[ifName]
    66			if !ok {
    67				return
    68			}
    69			outerFamily := "inet"
    70			transportTable := "inet.0"
    71			if dst := net.ParseIP(tunnel.Destination); dst != nil && dst.To4() == nil {
    72				outerFamily = "inet6"
    73				transportTable = "inet6.0"
    74			} else if src := net.ParseIP(tunnel.Source); src != nil && src.To4() == nil {
    75				outerFamily = "inet6"
    76				transportTable = "inet6.0"
    77			}
    78			if tunnel.RoutingInstance != "" {
    79				if outerFamily == "inet6" {
    80					transportTable = tunnel.RoutingInstance + ".inet6.0"
    81				} else {
    82					transportTable = tunnel.RoutingInstance + ".inet.0"
    83				}
    84			}
    85			redundancyGroup := iface.RedundancyGroup
    86			if redundancyGroup <= 0 {
    87				if src := net.ParseIP(tunnel.Source); src != nil {
    88					redundancyGroup = rgByAddress[src.String()]
    89				}
    90			}
    91			// For WG the outer family follows the peer endpoint address
    92			// (the Source/Destination heuristic above sees empty strings).
    93			if isWireguard && tunnel.WgEndpoint != "" {
    94				if host, _, err := net.SplitHostPort(tunnel.WgEndpoint); err == nil {
    95					if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
    96						outerFamily = "inet6"
    97					}
    98				}
    99			}
   100			id := config.StableTunnelEndpointID(ifName)
   101			if owner, taken := usedIDs[id]; taken {
   102				slog.Error("tunnel endpoint id collision — dropping later-sorting tunnel (#1873)",
   103					"kept", owner, "dropped", ifName, "id", id)
   104				return
   105			}
   106			snap := TunnelEndpointSnapshot{
   107				ID:              id,
   108				Interface:       ifName,
   109				LinuxName:       iface.LinuxName,
   110				Ifindex:         iface.Ifindex,
   111				Zone:            iface.Zone,
   112				RedundancyGroup: redundancyGroup,
   113				MTU:             iface.MTU,
   114				Mode:            tunnel.Mode,
   115				OuterFamily:     outerFamily,
   116				Source:          tunnel.Source,
   117				Destination:     tunnel.Destination,
   118				Key:             tunnel.Key,
   119				TTL:             tunnel.TTL,
   120				TransportTable:  transportTable,
   121			}
   122			if isWireguard {
   123				snap.WgListenPort = tunnel.WgListenPort
   124				snap.WgLocalPrivkeyHex = tunnel.WgLocalPrivkeyHex
   125				snap.WgPeerPubkeyHex = tunnel.WgPeerPubkeyHex
   126				snap.WgAllowedIPs = tunnel.WgAllowedIPs
   127				snap.WgEndpoint = tunnel.WgEndpoint
   128				snap.WgKeepaliveSecs = tunnel.WgKeepaliveSecs
   129			}
   130			out = append(out, snap)
   131			usedIDs[id] = ifName
   132		}
   133		for _, name := range names {
   134			iface := cfg.Interfaces.Interfaces[name]
   135			if iface == nil {
   136				continue
   137			}
   138			if iface.Tunnel != nil {
   139				if len(iface.Units) == 0 {
   140					addEndpoint(name, iface.Tunnel)
   141					continue
   142				}
   143				unitNums := make([]int, 0, len(iface.Units))
   144				for unitNum := range iface.Units {
   145					unitNums = append(unitNums, unitNum)
   146				}
   147				sort.Ints(unitNums)
   148				if iface.Tunnel.Mode == "wireguard" {
   149					// Interface-level WireGuard is ONE persistent TUN with
   150					// ONE listen port shared by every unit (#1910 r2 Codex
   151					// High): now that TunnelNameMap resolves every unit ref
   152					// of an interface-level wg to the base device, per-unit
   153					// emission would produce N live endpoints with the SAME
   154					// ifindex + listen port — the Rust side overwrites
   155					// tunnel_endpoint_by_ifindex with the later id and the
   156					// second control thread tombstones on the duplicate UDP
   157					// bind, so routes can select an engine whose control
   158					// thread never came up. Emit exactly one endpoint,
   159					// keyed by the LOWEST CONFIGURED unit ref — a pure
   160					// function of config, never of runtime snapshot rows,
   161					// so both HA nodes compute the same endpoint id from
   162					// the same config (#1873) and the commit-time collision
   163					// gate (collectTunnelEndpointNamesAST) can mirror the
   164					// selection exactly. The common single-unit-0 shape
   165					// keeps its existing stable id. Rows for every unit of
   166					// an interface-level wg share one LinuxName/ifindex, so
   167					// row presence is all-or-nothing: if the device is
   168					// absent, addEndpoint drops the ref like it always did.
   169					addEndpoint(fmt.Sprintf("%s.%d", name, unitNums[0]), iface.Tunnel)
   170					continue
   171				}
   172				for _, unitNum := range unitNums {
   173					addEndpoint(fmt.Sprintf("%s.%d", name, unitNum), iface.Tunnel)
   174				}
   175				continue
   176			}
   177			if len(iface.Units) == 0 {
   178				continue
   179			}
   180			unitNums := make([]int, 0, len(iface.Units))
   181			for unitNum := range iface.Units {
   182				unitNums = append(unitNums, unitNum)
   183			}
   184			sort.Ints(unitNums)
   185			for _, unitNum := range unitNums {
   186				unit := iface.Units[unitNum]
   187				if unit == nil || unit.Tunnel == nil {
   188					continue
   189				}
   190				addEndpoint(fmt.Sprintf("%s.%d", name, unitNum), unit.Tunnel)
   191			}
   192		}
   193		return out
   194	}
   195	
   196	// wgEndpointSetSummary returns a canonical "id:iface:port@ifindex"
   197	// summary of the snapshot's WireGuard endpoint set (#1866 D3). Used by
   198	// logWgEndpointSetTransitionLocked to emit a publish-boundary log line
   199	// whenever the WG endpoint set the helper is being given changes —
   200	// paired with the Rust-side apply-boundary log, one journal capture
   201	// disambiguates "Go published a stale set" from "Rust skipped the
   202	// prune" if a teardown leak ever recurs.
   203	func wgEndpointSetSummary(snap *ConfigSnapshot) string {
   204		if snap == nil {
   205			return ""
   206		}
   207		parts := make([]string, 0, len(snap.TunnelEndpoints))
   208		for _, ep := range snap.TunnelEndpoints {
   209			if ep.Mode != "wireguard" {
   210				continue
   211			}
   212			parts = append(parts, fmt.Sprintf("%d:%s:%d@%d", ep.ID, ep.Interface, ep.WgListenPort, ep.Ifindex))
   213		}
   214		sort.Strings(parts)
   215		return strings.Join(parts, ",")
   216	}
   217	
   218	// logWgEndpointSetTransitionLocked logs (Info, state-transition-only)
   219	// when the WG endpoint set of an outgoing snapshot differs from the
   220	// previously published one, then records the new set. Call after a

exec
/bin/bash -lc "nl -ba pkg/config/tunnelid_test.go | sed -n '1,360p'" in /home/ps/git/bpfrx/.claude/worktrees/1914-research-tunnel-collision
 succeeded in 0ms:
     1	package config
     2	
     3	import (
     4		"strings"
     5		"testing"
     6	)
     7	
     8	// Hash-freeze pins (#1873): StableTunnelEndpointID is wire-adjacent —
     9	// both HA nodes must compute identical ids from identical config, so
    10	// the fold may NEVER change. If this test fails, you changed the fold;
    11	// revert. (The literal values were computed once and frozen.)
    12	func TestStableTunnelEndpointIDHashFreeze(t *testing.T) {
    13		pins := map[string]uint16{
    14			// Ordinary names.
    15			"wg0.0":      16091,
    16			"gr-0/0/0.0": 44687,
    17			// The verified colliding pair (Codex plan-review r1): both
    18			// fold to 824. Pinned so the collision-handling tests below
    19			// stay grounded in a REAL collision under the frozen fold.
    20			"wg1408.0": 824,
    21			"wg78.0":   824,
    22		}
    23		for name, want := range pins {
    24			if got := StableTunnelEndpointID(name); got != want {
    25				t.Fatalf("StableTunnelEndpointID(%q) = %d, want %d — the fold is frozen (#1873)", name, got, want)
    26			}
    27		}
    28	}
    29	
    30	// id 0 means "not a tunnel" everywhere; the mapping must never emit it.
    31	func TestStableTunnelEndpointIDNeverZero(t *testing.T) {
    32		names := []string{"", "wg0", "wg0.0", "gr-0/0/0.0", "a", "zz.4094"}
    33		for _, name := range names {
    34			if got := StableTunnelEndpointID(name); got == 0 {
    35				t.Fatalf("StableTunnelEndpointID(%q) = 0", name)
    36			}
    37		}
    38	}
    39	
    40	// R-B: a config whose tunnel names fold to the same id must fail
    41	// commit compilation (strict path) with a two-name remediation error.
    42	func TestTunnelEndpointIDCollisionFailsCommit(t *testing.T) {
    43		tree := buildTree(t, []string{
    44			"set interfaces wg1408 unit 0 tunnel mode wireguard",
    45			"set interfaces wg78 unit 0 tunnel mode wireguard",
    46		})
    47		_, err := CompileConfig(tree)
    48		if err == nil {
    49			t.Fatalf("CompileConfig accepted a colliding tunnel pair")
    50		}
    51		for _, want := range []string{"wg1408.0", "wg78.0", "collision", "rename"} {
    52			if !strings.Contains(err.Error(), want) {
    53				t.Fatalf("collision error %q does not mention %q", err.Error(), want)
    54			}
    55		}
    56	}
    57	
    58	// R-B lenient: an already-active config with a collision must still
    59	// compile on the tolerant load/peer-sync paths (warn, not reject) so
    60	// an upgraded node boots.
    61	func TestTunnelEndpointIDCollisionLenientWarns(t *testing.T) {
    62		tree := buildTree(t, []string{
    63			"set interfaces wg1408 unit 0 tunnel mode wireguard",
    64			"set interfaces wg78 unit 0 tunnel mode wireguard",
    65		})
    66		cfg, err := CompileConfigLenient(tree)
    67		if err != nil {
    68			t.Fatalf("CompileConfigLenient rejected a colliding pair: %v", err)
    69		}
    70		found := false
    71		for _, w := range cfg.Warnings {
    72			if strings.Contains(w, "collision") && strings.Contains(w, "wg1408.0") {
    73				found = true
    74			}
    75		}
    76		if !found {
    77			t.Fatalf("lenient compile carried no collision warning: %v", cfg.Warnings)
    78		}
    79	}
    80	
    81	// R-B union-of-groups symmetry (Claude SMR plan r2): a collision
    82	// involving a `groups nodeN`-scoped tunnel must fail commit on BOTH
    83	// nodes — including the node whose effective config never applies the
    84	// group — or config-sync would split (originator accepts, peer
    85	// rejects).
    86	func TestTunnelEndpointIDCollisionAcrossGroupsIsSymmetric(t *testing.T) {
    87		tree := buildTree(t, []string{
    88			"set groups node1 interfaces wg1408 unit 0 tunnel mode wireguard",
    89			"set interfaces wg78 unit 0 tunnel mode wireguard",
    90			// No apply-groups: node0's EFFECTIVE config never contains
    91			// wg1408 — the union check must still reject.
    92		})
    93		if _, err := CompileConfigForNode(tree, 0); err == nil {
    94			t.Fatalf("node0 compile accepted a collision hidden in groups node1")
    95		}
    96		if _, err := CompileConfigForNode(tree, 1); err == nil {
    97			t.Fatalf("node1 compile accepted a collision hidden in groups node1")
    98		}
    99	}
   100	
   101	// #1910 r3 Codex: the collision gate must not model endpoint ids the
   102	// snapshot builder never publishes. An interface-level WireGuard
   103	// tunnel with units emits exactly ONE endpoint (lowest unit ref), so
   104	// a collision involving a higher, never-emitted unit ref must not
   105	// reject the commit. Real collision under the frozen fold:
   106	// StableTunnelEndpointID("wg0.1") == StableTunnelEndpointID("wg341")
   107	// == 14730, but only "wg0.0" (16091) and "wg341" are published.
   108	func TestTunnelEndpointIDNoFalsePositiveOnNonEmittedWGUnit(t *testing.T) {
   109		if a, b := StableTunnelEndpointID("wg0.1"), StableTunnelEndpointID("wg341"); a != b || a != 14730 {
   110			t.Fatalf("precondition: wg0.1=%d wg341=%d, want both 14730 (frozen fold)", a, b)
   111		}
   112		tree := buildTree(t, []string{
   113			"set interfaces wg0 tunnel mode wireguard",
   114			"set interfaces wg0 unit 0 family inet address 10.70.0.1/30",
   115			"set interfaces wg0 unit 1 family inet address 10.70.0.5/30",
   116			"set interfaces wg341 tunnel mode wireguard",
   117		})
   118		cfg, err := CompileConfig(tree)
   119		if err != nil {
   120			t.Fatalf("CompileConfig rejected a config whose only id collision is on a never-emitted WG unit ref: %v", err)
   121		}
   122		for _, w := range cfg.Warnings {
   123			if strings.Contains(w, "collision") {
   124				t.Fatalf("unexpected collision warning: %q", w)
   125			}
   126		}
   127	}
   128	
   129	// #1910 r4 Codex: a non-canonical numeric unit spelling (`unit 01`)
   130	// compiles to unit 1 and the builder emits/hashes the canonical
   131	// "wg0.1" — the gate must hash the SAME canonical ref, or it misses
   132	// the frozen wg0.1/wg341 collision (14730) and the runtime usedIDs
   133	// belt silently drops an endpoint instead of failing the commit.
   134	func TestTunnelEndpointIDLeadingZeroUnitStillCollides(t *testing.T) {
   135		tree := buildTree(t, []string{
   136			"set interfaces wg0 tunnel mode wireguard",
   137			"set interfaces wg0 unit 01 family inet address 10.70.0.1/30",
   138			"set interfaces wg341 tunnel mode wireguard",
   139		})
   140		_, err := CompileConfig(tree)
   141		if err == nil {
   142			t.Fatalf("CompileConfig accepted a builder-emitted collision hidden behind a leading-zero unit spelling (wg0.01 -> emits wg0.1, collides with wg341)")
   143		}
   144		for _, want := range []string{"wg0.1", "wg341", "collision"} {
   145			if !strings.Contains(err.Error(), want) {
   146				t.Fatalf("collision error %q does not mention %q", err.Error(), want)
   147			}
   148		}
   149	}
   150	
   151	// #1910 r5 Codex: an interface-level WG tunnel whose ONLY unit
   152	// spelling overflows strconv.Atoi compiles with iface.Units empty, so
   153	// the builder emits the BARE interface ref — the gate must hash that
   154	// bare ref, not the raw overflow spelling (which hashes elsewhere and
   155	// would let a real builder-emitted collision pass strict compile,
   156	// landing on the runtime usedIDs drop instead of failing commit).
   157	// Frozen collision: StableTunnelEndpointID("wg0") ==
   158	// StableTunnelEndpointID("wg34524.0") == 17799.
   159	func TestTunnelEndpointIDOverflowOnlyUnitHashesBareRef(t *testing.T) {
   160		if a, b := StableTunnelEndpointID("wg0"), StableTunnelEndpointID("wg34524.0"); a != b || a != 17799 {
   161			t.Fatalf("precondition: wg0=%d wg34524.0=%d, want both 17799 (frozen fold)", a, b)
   162		}
   163		tree := buildTree(t, []string{
   164			"set interfaces wg0 tunnel mode wireguard",
   165			"set interfaces wg0 unit 99999999999999999999999999999999999999 family inet address 10.70.2.1/30",
   166			"set interfaces wg34524 unit 0 tunnel mode wireguard",
   167		})
   168		if _, err := CompileConfig(tree); err == nil {
   169			t.Fatalf("CompileConfig accepted a builder-emitted collision hidden behind an overflow-only unit spelling (wg0 emits bare ref, collides with wg34524.0)")
   170		}
   171	}
   172	
   173	// The same canonicalization must hold on the per-unit branches: a
   174	// UNIT-LEVEL tunnel declared as `unit 01` compiles to unit 1 and the
   175	// builder emits "wg0.1" — the gate must hash the canonical ref there
   176	// too, or it misses the frozen wg0.1/wg341 collision (14730).
   177	func TestTunnelEndpointIDUnitLevelLeadingZeroStillCollides(t *testing.T) {
   178		tree := buildTree(t, []string{
   179			"set interfaces wg0 unit 01 tunnel mode wireguard",
   180			"set interfaces wg341 tunnel mode wireguard",
   181		})
   182		_, err := CompileConfig(tree)
   183		if err == nil {
   184			t.Fatalf("CompileConfig accepted a builder-emitted collision hidden behind a unit-level leading-zero spelling (wg0.01 -> emits wg0.1, collides with wg341)")
   185		}
   186		for _, want := range []string{"wg0.1", "wg341", "collision"} {
   187			if !strings.Contains(err.Error(), want) {
   188				t.Fatalf("collision error %q does not mention %q", err.Error(), want)
   189			}
   190		}
   191	}
   192	
   193	// #1910 r6 Codex: duplicate spellings of the same unit number must
   194	// follow the typed compiler's LAST-WINS overwrite
   195	// (ifc.Units[unitNum] = unit per instance). When `unit 00` carries
   196	// the tunnel but a later `unit 0` re-declares the unit without one,
   197	// the compiled unit has no tunnel and the builder emits nothing — the
   198	// gate must not register the ref (false reject). When the order is
   199	// reversed the tunnel-carrying instance wins and the collision is
   200	// real.
   201	func TestTunnelEndpointIDDuplicateUnitSpellingLastWins(t *testing.T) {
   202		// Tunnel on the OVERWRITTEN earlier instance: no endpoint emitted,
   203		// so the wg1408.0/wg78.0 collision (both refs would collide if
   204		// emitted) must NOT reject the commit.
   205		tree := buildTree(t, []string{
   206			"set interfaces wg1408 unit 00 tunnel mode wireguard",
   207			"set interfaces wg1408 unit 0 family inet address 10.70.3.1/30",
   208			"set interfaces wg78 unit 0 tunnel mode wireguard",
   209		})
   210		if _, err := CompileConfig(tree); err != nil {
   211			t.Fatalf("CompileConfig rejected a collision on a ref whose tunnel lives only on an overwritten duplicate unit instance: %v", err)
   212		}
   213		// Tunnel on the LAST instance: the unit compiles with the tunnel,
   214		// the builder emits wg1408.0, and the collision must reject.
   215		tree = buildTree(t, []string{
   216			"set interfaces wg1408 unit 00 family inet address 10.70.3.1/30",
   217			"set interfaces wg1408 unit 0 tunnel mode wireguard",
   218			"set interfaces wg78 unit 0 tunnel mode wireguard",
   219		})
   220		if _, err := CompileConfig(tree); err == nil {
   221			t.Fatalf("CompileConfig accepted a real collision whose tunnel lives on the last duplicate unit instance (wg1408.0 vs wg78.0)")
   222		}
   223	}
   224	
   225	// And the inverse: a collision on the EMITTED lowest unit ref of an
   226	// interface-level WG tunnel must still be rejected.
   227	func TestTunnelEndpointIDCollisionOnEmittedWGUnitStillRejected(t *testing.T) {
   228		tree := buildTree(t, []string{
   229			"set interfaces wg1408 tunnel mode wireguard",
   230			"set interfaces wg1408 unit 0 family inet address 10.70.1.1/30",
   231			"set interfaces wg1408 unit 1 family inet address 10.70.1.5/30",
   232			"set interfaces wg78 unit 0 tunnel mode wireguard",
   233		})
   234		if _, err := CompileConfig(tree); err == nil {
   235			t.Fatalf("CompileConfig accepted a collision on the emitted lowest unit ref (wg1408.0 vs wg78.0)")
   236		}
   237	}
   238	
   239	// Non-colliding multi-tunnel configs must compile clean (no false
   240	// positives from the gate).
   241	func TestTunnelEndpointIDNoFalsePositive(t *testing.T) {
   242		tree := buildTree(t, []string{
   243			"set interfaces wg0 unit 0 tunnel mode wireguard",
   244			"set groups node0 interfaces gr-0/0/0 unit 0 tunnel mode gre",
   245			"set groups node0 interfaces gr-0/0/0 unit 0 tunnel source 10.0.0.1",
   246			"set groups node0 interfaces gr-0/0/0 unit 0 tunnel destination 10.0.0.2",
   247		})
   248		cfg, err := CompileConfig(tree)
   249		if err != nil {
   250			t.Fatalf("CompileConfig rejected a non-colliding config: %v", err)
   251		}
   252		for _, w := range cfg.Warnings {
   253			if strings.Contains(w, "tunnel endpoint id collision") {
   254				t.Fatalf("unexpected collision warning: %q", w)
   255			}
   256		}
   257	}

exec
/bin/bash -lc "rg -n \"buildTunnelEndpointSnapshots|addEndpoint|StableTunnelEndpointID|validateTunnelEndpointIDCollisionAST|CompileConfigForNode|CompileConfig\\(\" pkg -g'*.go'" in /home/ps/git/bpfrx/.claude/worktrees/1914-research-tunnel-collision
 succeeded in 0ms:
pkg/dataplane/loader.go:161:	result, err := CompileConfig(compilerDP, cfg, m.lastCompile != nil)
pkg/dataplane/compiler.go:151:func CompileConfig(dp DataPlane, cfg *config.Config, isRecompile bool) (*CompileResult, error) {
pkg/dataplane/compiler.go:306:	result, err := CompileConfig(m, cfg, m.lastCompile != nil)
pkg/cli/cli_show_interfaces.go:583:				peerCfg, err := config.CompileConfigForNodeLenient(tree, peerNodeID)
pkg/config/parser_ast_test.go:75:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:176:func TestCompileConfig(t *testing.T) {
pkg/config/parser_ast_test.go:215:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:377:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:458:	cfg2, err := CompileConfig(tree2)
pkg/config/parser_ast_test.go:552:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:639:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:738:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:774:	cfg2, err := CompileConfig(tree2)
pkg/config/parser_ast_test.go:815:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:899:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:982:	cfg2, err := CompileConfig(tree2)
pkg/config/parser_ast_test.go:1033:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:1069:	cfg2, err := CompileConfig(tree2)
pkg/config/parser_ast_test.go:1107:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:1185:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:1245:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:1273:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:1295:	cfg2, err := CompileConfig(tree2)
pkg/config/parser_ast_test.go:1313:	cfg3, err := CompileConfig(tree3)
pkg/config/parser_ast_test.go:1358:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:1437:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:1487:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:1526:	_, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:1553:	_, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:1583:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:1649:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:1684:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:1718:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:1816:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:1838:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:1887:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:1945:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:1992:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:2056:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:2114:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:2181:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:2222:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:2277:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:2350:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:2399:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:2434:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:2588:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:2610:	cfg2, err2 := CompileConfig(tree2)
pkg/config/parser_ast_test.go:2685:	_, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:2716:	_, err = CompileConfig(tree)
pkg/config/parser_ast_test.go:2763:			_, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:2799:	_, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:2822:	_, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:2875:	_, polErr := CompileConfig(tree1)
pkg/config/parser_ast_test.go:2905:	_, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:2939:	_, err := CompileConfigForNode(tree, 0)
pkg/config/parser_ast_test.go:2941:		t.Fatal("CompileConfigForNode succeeded for apply-groups-injected dpdk")
pkg/config/parser_ast_test.go:2944:		t.Fatalf("CompileConfigForNode error = %q, want substring %q", err.Error(), dpdkRetirementSubstr)
pkg/config/parser_ast_test.go:2967:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:2995:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:3016:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:3072:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:3129:	_, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:3199:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:3268:			cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:3310:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:3360:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:3394:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:3426:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:3454:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:3488:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:3553:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:3626:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:3658:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:3693:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:3711:	_, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:3736:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:3757:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:3810:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:3863:	_, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:3913:func TestCompileConfigForNode(t *testing.T) {
pkg/config/parser_ast_test.go:3925:	cfg0, err := CompileConfigForNode(tree, 0)
pkg/config/parser_ast_test.go:3927:		t.Fatalf("CompileConfigForNode(0): %v", err)
pkg/config/parser_ast_test.go:3935:	cfg1, err := CompileConfigForNode(tree, 1)
pkg/config/parser_ast_test.go:3937:		t.Fatalf("CompileConfigForNode(1): %v", err)
pkg/config/parser_ast_test.go:3953:func TestCompileConfigForNodeBackwardCompat(t *testing.T) {
pkg/config/parser_ast_test.go:3965:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:3967:		t.Fatalf("CompileConfig() unexpected error: %v", err)
pkg/config/parser_ast_test.go:4060:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:4180:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:4267:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:4350:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:4419:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:4447:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:4475:	cfg, err := CompileConfigForNode(tree, 0)
pkg/config/parser_ast_test.go:4504:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:4673:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:4695:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:4717:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:4775:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:4823:	cfg, cerr := CompileConfig(tree)
pkg/config/parser_ast_test.go:4880:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:4983:			_, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:5014:	_, compileErr := CompileConfig(tree)
pkg/config/parser_ast_test.go:5040:	cfg, cerr := CompileConfig(tree)
pkg/dataplane/userspace/tunnels_test.go:31:	endpoints := buildTunnelEndpointSnapshots(withWg, interfaces)
pkg/dataplane/userspace/tunnels_test.go:43:	endpoints = buildTunnelEndpointSnapshots(removed, interfaces)
pkg/dataplane/userspace/tunnels_test.go:85:	endpoints := buildTunnelEndpointSnapshots(cfg, interfaces)
pkg/dataplane/userspace/tunnels_test.go:93:	if want := config.StableTunnelEndpointID("wg0.0"); ep.ID != want {
pkg/dataplane/userspace/tunnels_test.go:106:	endpoints = buildTunnelEndpointSnapshots(cfg, withoutUnit0)
pkg/dataplane/userspace/tunnels_test.go:195:	idsAll := endpointIDsByInterface(buildTunnelEndpointSnapshots(cfgAll, ifAll))
pkg/dataplane/userspace/tunnels_test.go:203:	idsRm := endpointIDsByInterface(buildTunnelEndpointSnapshots(cfgRm, ifRm))
pkg/dataplane/userspace/tunnels_test.go:212:	idsAdd := endpointIDsByInterface(buildTunnelEndpointSnapshots(cfgAdd, ifAdd))
pkg/dataplane/userspace/tunnels_test.go:221:		if want := config.StableTunnelEndpointID(name); id != want {
pkg/dataplane/userspace/tunnels_test.go:232:	idsAll := endpointIDsByInterface(buildTunnelEndpointSnapshots(cfg, ifAll))
pkg/dataplane/userspace/tunnels_test.go:242:	idsFlap := endpointIDsByInterface(buildTunnelEndpointSnapshots(cfg, ifFlap))
pkg/dataplane/userspace/tunnels_test.go:259:	endpoints := buildTunnelEndpointSnapshots(cfg, ifAll)
pkg/dataplane/userspace/tunnels_test.go:267:	if endpoints[0].ID != config.StableTunnelEndpointID("wg1408.0") {
pkg/dataplane/userspace/tunnels_test.go:268:		t.Fatalf("kept id %d, want %d", endpoints[0].ID, config.StableTunnelEndpointID("wg1408.0"))
pkg/dataplane/userspace/tunnels.go:13:func buildTunnelEndpointSnapshots(cfg *config.Config, interfaces []InterfaceSnapshot) []TunnelEndpointSnapshot {
pkg/dataplane/userspace/tunnels.go:44:	// #1873: ids are content-derived (config.StableTunnelEndpointID of
pkg/dataplane/userspace/tunnels.go:49:	// gate (validateTunnelEndpointIDCollisionAST): a snapshot must
pkg/dataplane/userspace/tunnels.go:54:	addEndpoint := func(ifName string, tunnel *config.TunnelConfig) {
pkg/dataplane/userspace/tunnels.go:100:		id := config.StableTunnelEndpointID(ifName)
pkg/dataplane/userspace/tunnels.go:140:				addEndpoint(name, iface.Tunnel)
pkg/dataplane/userspace/tunnels.go:168:				// absent, addEndpoint drops the ref like it always did.
pkg/dataplane/userspace/tunnels.go:169:				addEndpoint(fmt.Sprintf("%s.%d", name, unitNums[0]), iface.Tunnel)
pkg/dataplane/userspace/tunnels.go:173:				addEndpoint(fmt.Sprintf("%s.%d", name, unitNum), iface.Tunnel)
pkg/dataplane/userspace/tunnels.go:190:			addEndpoint(fmt.Sprintf("%s.%d", name, unitNum), unit.Tunnel)
pkg/config/compiler_equal_flow_target_policy_test.go:27:	cfg, err := CompileConfig(tree)
pkg/config/compiler_equal_flow_target_policy_test.go:64:	cfg, err := CompileConfig(tree)
pkg/dataplane/userspace/builder.go:42:		TunnelEndpoints:    buildTunnelEndpointSnapshots(cfg, interfaces),
pkg/config/freetext_test.go:53:	_, err := CompileConfig(tree)
pkg/config/freetext_test.go:65:func TestCompileConfigForNodeRejectsNewlineDescription(t *testing.T) {
pkg/config/freetext_test.go:67:	if _, err := CompileConfigForNode(tree, 0); err == nil {
pkg/config/freetext_test.go:68:		t.Fatal("strict CompileConfigForNode must reject a description containing a newline")
pkg/config/freetext_test.go:85:	if _, err := CompileConfig(tree); err == nil {
pkg/config/freetext_test.go:100:	_, err = CompileConfig(tree)
pkg/config/freetext_test.go:156:	if _, err := CompileConfig(tree); err != nil {
pkg/config/parser_ipmonitoring_test.go:32:	cfg, err := CompileConfig(tree)
pkg/config/parser_ipmonitoring_test.go:106:	cfg, err := CompileConfig(tree)
pkg/config/parser_ipmonitoring_test.go:190:			_, err := CompileConfig(tree)
pkg/config/parser_ipmonitoring_test.go:228:	cfg, err := CompileConfig(tree)
pkg/config/parser_ipmonitoring_test.go:286:	cfg, err := CompileConfig(tree)
pkg/config/parser_ipmonitoring_test.go:316:			cfg, err := CompileConfig(buildTree(t, lines))
pkg/config/parser_ipmonitoring_test.go:405:			_, err := CompileConfig(buildTree(t, tc.lines))
pkg/config/parser_ipmonitoring_test.go:425:	cfg, err := CompileConfig(buildTree(t, lines))
pkg/config/compiler_equal_flow_worker_cap_test.go:66:		cfg, err := CompileConfig(tree)
pkg/config/compiler_equal_flow_worker_cap_test.go:68:			t.Fatalf("CompileConfig(workers %s + equal-flow) returned error "+
pkg/config/compiler_equal_flow_worker_cap_test.go:96:		cfg, err := CompileConfigForNode(tree, node)
pkg/config/compiler_equal_flow_worker_cap_test.go:104:		cfgL, err := CompileConfigForNodeLenient(tree, node)
pkg/config/tunnelid.go:10:// StableTunnelEndpointID maps a tunnel interface name (unit-qualified,
pkg/config/tunnelid.go:25:func StableTunnelEndpointID(name string) uint16 {
pkg/config/tunnelid.go:35:// mirroring buildTunnelEndpointSnapshots naming exactly:
pkg/config/tunnelid.go:146:// validateTunnelEndpointIDCollisionAST checks the UNION of tunnel
pkg/config/tunnelid.go:148:// "groups" block for StableTunnelEndpointID collisions (#1873 R-B).
pkg/config/tunnelid.go:161:// buildTunnelEndpointSnapshots).
pkg/config/tunnelid.go:162:func validateTunnelEndpointIDCollisionAST(tree *ConfigTree, lenient bool) ([]string, error) {
pkg/config/tunnelid.go:190:		id := StableTunnelEndpointID(name)
pkg/config/parser_class_of_service_test.go:58:	cfg, err := CompileConfig(tree)
pkg/config/parser_class_of_service_test.go:119:	cfg, err := CompileConfig(tree)
pkg/config/parser_class_of_service_test.go:186:	cfg, err := CompileConfig(tree)
pkg/config/parser_class_of_service_test.go:222:	_, err := CompileConfig(tree)
pkg/config/parser_class_of_service_test.go:253:	if _, err := CompileConfig(tree); err != nil {
pkg/config/parser_class_of_service_test.go:297:			_, err := CompileConfig(tree)
pkg/config/parser_class_of_service_test.go:325:	_, err := CompileConfig(tree)
pkg/config/parser_class_of_service_test.go:356:	_, err := CompileConfig(tree)
pkg/config/parser_class_of_service_test.go:385:	if _, err := CompileConfig(tree); err != nil {
pkg/config/parser_class_of_service_test.go:406:	cfg, err := CompileConfig(tree)
pkg/config/parser_class_of_service_test.go:464:	cfg, err := CompileConfig(tree)
pkg/config/parser_class_of_service_test.go:505:	_, err := CompileConfig(tree)
pkg/config/parser_class_of_service_test.go:528:	cfg, err := CompileConfig(tree)
pkg/config/parser_class_of_service_test.go:560:	_, err := CompileConfig(tree)
pkg/config/parser_class_of_service_test.go:588:	cfg, err := CompileConfig(tree)
pkg/config/parser_class_of_service_test.go:681:	cfg, err := CompileConfig(tree)
pkg/config/parser_class_of_service_test.go:717:	cfg, err := CompileConfig(tree)
pkg/config/parser_class_of_service_test.go:754:	cfg, err := CompileConfig(tree)
pkg/config/parser_class_of_service_test.go:807:	cfg, err := CompileConfig(tree)
pkg/config/parser_class_of_service_test.go:844:	cfg, err := CompileConfig(tree)
pkg/config/parser_class_of_service_test.go:902:	cfg, err := CompileConfig(tree)
pkg/config/parser_class_of_service_test.go:949:	cfg, err := CompileConfig(tree)
pkg/config/parser_class_of_service_test.go:1043:	cfg, err := CompileConfig(tree)
pkg/config/parser_class_of_service_test.go:1119:	cfg, err := CompileConfig(tree)
pkg/config/parser_class_of_service_test.go:1180:	cfg, err := CompileConfig(tree)
pkg/config/parser_class_of_service_test.go:1241:	cfg, err := CompileConfig(tree)
pkg/config/parser_class_of_service_test.go:1278:	cfg, err := CompileConfig(tree)
pkg/config/parser_class_of_service_test.go:1326:	_, err := CompileConfig(tree)
pkg/config/parser_class_of_service_test.go:1372:	cfg, err := CompileConfig(tree)
pkg/config/parser_class_of_service_test.go:1418:	_, err := CompileConfig(tree)
pkg/config/parser_class_of_service_test.go:1461:	_, err := CompileConfig(tree)
pkg/config/tunnelid_test.go:8:// Hash-freeze pins (#1873): StableTunnelEndpointID is wire-adjacent —
pkg/config/tunnelid_test.go:12:func TestStableTunnelEndpointIDHashFreeze(t *testing.T) {
pkg/config/tunnelid_test.go:24:		if got := StableTunnelEndpointID(name); got != want {
pkg/config/tunnelid_test.go:25:			t.Fatalf("StableTunnelEndpointID(%q) = %d, want %d — the fold is frozen (#1873)", name, got, want)
pkg/config/tunnelid_test.go:31:func TestStableTunnelEndpointIDNeverZero(t *testing.T) {
pkg/config/tunnelid_test.go:34:		if got := StableTunnelEndpointID(name); got == 0 {
pkg/config/tunnelid_test.go:35:			t.Fatalf("StableTunnelEndpointID(%q) = 0", name)
pkg/config/tunnelid_test.go:47:	_, err := CompileConfig(tree)
pkg/config/tunnelid_test.go:93:	if _, err := CompileConfigForNode(tree, 0); err == nil {
pkg/config/tunnelid_test.go:96:	if _, err := CompileConfigForNode(tree, 1); err == nil {
pkg/config/tunnelid_test.go:106:// StableTunnelEndpointID("wg0.1") == StableTunnelEndpointID("wg341")
pkg/config/tunnelid_test.go:109:	if a, b := StableTunnelEndpointID("wg0.1"), StableTunnelEndpointID("wg341"); a != b || a != 14730 {
pkg/config/tunnelid_test.go:118:	cfg, err := CompileConfig(tree)
pkg/config/tunnelid_test.go:140:	_, err := CompileConfig(tree)
pkg/config/tunnelid_test.go:157:// Frozen collision: StableTunnelEndpointID("wg0") ==
pkg/config/tunnelid_test.go:158:// StableTunnelEndpointID("wg34524.0") == 17799.
pkg/config/tunnelid_test.go:160:	if a, b := StableTunnelEndpointID("wg0"), StableTunnelEndpointID("wg34524.0"); a != b || a != 17799 {
pkg/config/tunnelid_test.go:168:	if _, err := CompileConfig(tree); err == nil {
pkg/config/tunnelid_test.go:182:	_, err := CompileConfig(tree)
pkg/config/tunnelid_test.go:210:	if _, err := CompileConfig(tree); err != nil {
pkg/config/tunnelid_test.go:220:	if _, err := CompileConfig(tree); err == nil {
pkg/config/tunnelid_test.go:234:	if _, err := CompileConfig(tree); err == nil {
pkg/config/tunnelid_test.go:248:	cfg, err := CompileConfig(tree)
pkg/config/vrrp_track_test.go:92:	cfg, err := CompileConfig(parseHier(t, trackNestedHier))
pkg/config/vrrp_track_test.go:114:	cfg, err := CompileConfig(tree)
pkg/config/vrrp_track_test.go:128:	cfg, err := CompileConfig(parseHier(t, `interfaces {
pkg/config/vrrp_track_test.go:162:	cfg, err := CompileConfig(tree)
pkg/config/vrrp_track_test.go:219:			cfg, err := CompileConfig(parseHier(t, text))
pkg/config/vrrp_track_test.go:256:	_, err := CompileConfig(parseHier(t, trackDuplicateHier))
pkg/config/vrrp_track_test.go:283:	cfg, err := CompileConfig(parseHier(t, `interfaces {
pkg/config/vrrp_track_test.go:311:	cfg, err := CompileConfig(parseHier(t, `interfaces {
pkg/config/vrrp_track_test.go:335:	cfg, err := CompileConfig(parseHier(t, `interfaces {
pkg/config/vrrp_track_test.go:359:	cfg, err := CompileConfig(parseHier(t, `interfaces {
pkg/config/vrrp_track_test.go:400:	cfg, err := CompileConfig(flatTree)
pkg/config/vrrp_track_test.go:402:		t.Fatalf("CompileConfig(replayed): %v", err)
pkg/config/vrrp_track_test.go:428:	if _, err := CompileConfig(parseHier(t, text)); err == nil {
pkg/config/vrrp_track_test.go:467:		if _, err := CompileConfig(parseHier(t, text)); err == nil {
pkg/config/vrrp_track_test.go:507:	if _, err := CompileConfig(tree); err == nil {
pkg/config/compiler_retired_dataplane_knobs_test.go:35:	cfg, err := CompileConfig(tree)
pkg/config/compiler_retired_dataplane_knobs_test.go:54:	cfg, err := CompileConfig(tree)
pkg/config/schema_validate_test.go:321:	cfg, err := config.CompileConfig(tree)
pkg/config/schema_validate_test.go:358:	cfg, err := config.CompileConfig(tree)
pkg/dataplane/userspace/manager_test.go:2305:	endpoints := buildTunnelEndpointSnapshots(cfg, []InterfaceSnapshot{
pkg/dataplane/userspace/manager_test.go:2318:	if want := config.StableTunnelEndpointID("gr-0/0/0.0"); endpoints[0].ID != want {
pkg/dataplane/userspace/manager_test.go:2351:	endpoints := buildTunnelEndpointSnapshots(cfg, []InterfaceSnapshot{
pkg/dataplane/userspace/manager_test.go:2385:	endpoints := buildTunnelEndpointSnapshots(cfg, []InterfaceSnapshot{
pkg/dataplane/userspace/manager_test.go:5345:	endpoints := buildTunnelEndpointSnapshots(cfg, []InterfaceSnapshot{
pkg/dataplane/userspace/manager_test.go:5389:	endpoints := buildTunnelEndpointSnapshots(cfg, []InterfaceSnapshot{
pkg/config/parser_system_test.go:18:	cfg, err := CompileConfig(tree)
pkg/config/parser_system_test.go:53:	cfg, err := CompileConfig(tree)
pkg/config/parser_system_test.go:111:	cfg, err := CompileConfig(tree)
pkg/config/parser_system_test.go:184:	cfg, err := CompileConfig(tree)
pkg/config/parser_system_test.go:238:	cfg2, err := CompileConfig(tree2)
pkg/config/parser_system_test.go:264:	cfg, err := CompileConfig(tree)
pkg/config/parser_system_test.go:350:	cfg, err := CompileConfig(tree)
pkg/config/parser_system_test.go:459:			cfg, err := CompileConfig(tree)
pkg/config/parser_system_test.go:495:		cfg, err := CompileConfig(tree)
pkg/config/parser_system_test.go:554:	cfg, err := CompileConfig(tree)
pkg/config/parser_system_test.go:603:	cfg, err := CompileConfig(tree)
pkg/config/parser_system_test.go:639:	cfg, err := CompileConfig(tree)
pkg/config/parser_system_test.go:688:	cfg, err := CompileConfig(tree)
pkg/config/parser_system_test.go:738:	cfg, err := CompileConfig(tree)
pkg/config/parser_system_test.go:800:	cfg, err := CompileConfig(tree)
pkg/config/parser_system_test.go:845:	cfg, err := CompileConfig(tree)
pkg/config/parser_system_test.go:895:	cfg, err := CompileConfig(tree)
pkg/config/parser_system_test.go:936:	cfg, err := CompileConfig(tree)
pkg/config/parser_system_test.go:999:	cfg, err := CompileConfig(tree)
pkg/config/parser_system_test.go:1056:	cfg, err := CompileConfig(tree)
pkg/config/parser_system_test.go:1082:	cfg, err := CompileConfig(tree)
pkg/config/parser_system_test.go:1105:	cfg, err := CompileConfig(tree)
pkg/config/parser_system_test.go:1134:		cfg, err := CompileConfig(tree)
pkg/config/parser_system_test.go:1171:	cfg, err := CompileConfig(tree)
pkg/config/parser_system_test.go:1206:	cfg, err := CompileConfig(tree)
pkg/config/parser_system_test.go:1234:	cfg, err := CompileConfig(tree)
pkg/config/parser_system_test.go:1261:	cfg, err := CompileConfig(tree)
pkg/config/parser_system_test.go:1300:	cfg, err := CompileConfig(tree)
pkg/config/parser_system_test.go:1340:	cfg, err := CompileConfig(tree)
pkg/config/parser_system_test.go:1379:	cfg, err := CompileConfig(tree)
pkg/config/parser_system_test.go:1406:	cfg, err := CompileConfig(tree)
pkg/config/parser_system_test.go:1429:	cfg, err := CompileConfig(tree)
pkg/config/parser_system_test.go:1465:	_, err := CompileConfig(tree)
pkg/config/parser_system_test.go:1495:			cfg, err := CompileConfig(tree)
pkg/config/parser_system_test.go:1524:		_, err := CompileConfig(tree)
pkg/config/parser_system_test.go:1544:		_, err := CompileConfig(tree)
pkg/config/parser_system_test.go:1564:		_, err := CompileConfig(tree)
pkg/config/compiler_test.go:54:	_, err := CompileConfig(tree)
pkg/config/compiler_test.go:122:	_, err := CompileConfig(tree)
pkg/config/compiler_test.go:214:	_, err := CompileConfig(tree)
pkg/config/compiler.go:75:	// (CompileConfigLenient / CompileConfigForNodeLenient) so an
pkg/config/compiler.go:87:func CompileConfig(tree *ConfigTree) (*Config, error) {
pkg/config/compiler.go:98:// edits hard-reject. The node-aware sibling CompileConfigForNodeLenient
pkg/config/compiler.go:115:	tunnelIDWarnings, tunnelIDErr := validateTunnelEndpointIDCollisionAST(
pkg/config/compiler.go:150:// CompileConfigForNode is like CompileConfig but resolves ${node} variables
pkg/config/compiler.go:155:func CompileConfigForNode(tree *ConfigTree, nodeID int) (*Config, error) {
pkg/config/compiler.go:159:// CompileConfigForNodeLenient is CompileConfigForNode with the
pkg/config/compiler.go:166:func CompileConfigForNodeLenient(tree *ConfigTree, nodeID int) (*Config, error) {
pkg/config/compiler.go:176:	tunnelIDWarnings, tunnelIDErr := validateTunnelEndpointIDCollisionAST(
pkg/config/compiler.go:198:// into a typed Config. Shared by CompileConfig and CompileConfigForNode.
pkg/config/schema_validate_interfaces_test.go:311:	cfg, err := config.CompileConfig(tree)
pkg/config/fbf_fixture_test.go:42:	cfg, err := CompileConfig(tree)
pkg/config/freetext.go:16://   - The STRICT compile path (CompileConfig / CompileConfigForNode,
pkg/config/freetext.go:28://     CompileConfigForNodeLenient — Store.Load, Store.SyncApply, and
pkg/config/parser_fbf_test.go:97:	cfg, err := CompileConfig(tree)
pkg/config/parser_fbf_test.go:168:	cfg, err := CompileConfig(tree)
pkg/config/login_password_test.go:78:	cfg, err := CompileConfig(tree)
pkg/config/login_password_test.go:114:	cfg, err := CompileConfig(tree)
pkg/grpcapi/server_show_interfaces.go:442:				peerCfg, err := config.CompileConfigForNodeLenient(tree, peerNodeID)
pkg/config/parser_rpm_pin_test.go:33:	cfg, err := CompileConfig(tree)
pkg/config/parser_rpm_pin_test.go:63:	cfg, err := CompileConfig(tree)
pkg/config/parser_rpm_pin_test.go:122:			_, err := CompileConfig(tree)
pkg/config/parser_rpm_pin_test.go:143:	_, err := CompileConfig(tree)
pkg/config/sqm_cookbook_fixture_test.go:73:	cfg, err := CompileConfig(tree)
pkg/config/sqm_cookbook_fixture_test.go:75:		t.Fatalf("CompileConfig(sqm cookbook fixture): %v", err)
pkg/config/parser_services_test.go:29:		cfg, err := CompileConfig(tree)
pkg/config/parser_services_test.go:78:		cfg, err := CompileConfig(tree)
pkg/config/parser_services_test.go:199:			_, err := CompileConfig(tree)
pkg/config/parser_services_test.go:204:				t.Fatalf("CompileConfig() error = %v, want substring %q", err, tc.wantErr)
pkg/config/parser_services_test.go:232:	cfg, err := CompileConfig(tree)
pkg/config/parser_services_test.go:270:	cfg, err := CompileConfig(tree)
pkg/config/parser_services_test.go:331:	cfg, err := CompileConfig(tree)
pkg/config/parser_services_test.go:387:	cfg, err := CompileConfig(tree)
pkg/config/parser_services_test.go:439:	cfg, err := CompileConfig(tree)
pkg/config/parser_services_test.go:463:	cfg, err := CompileConfig(tree)
pkg/config/parser_services_test.go:511:	cfg, err := CompileConfig(tree)
pkg/config/parser_services_test.go:572:	cfg, err := CompileConfig(tree)
pkg/config/parser_services_test.go:632:	cfg, err := CompileConfig(tree)
pkg/config/parser_services_test.go:673:	cfg, err := CompileConfig(tree)
pkg/config/parser_services_test.go:721:	cfg, err := CompileConfig(tree)
pkg/config/parser_services_test.go:763:	cfg, err := CompileConfig(tree)
pkg/config/parser_services_test.go:795:	cfg, err := CompileConfig(tree)
pkg/config/parser_services_test.go:838:	cfg, err := CompileConfig(tree)
pkg/config/parser_services_test.go:864:	cfg, err := CompileConfig(tree)
pkg/config/parser_services_test.go:887:	cfg, err := CompileConfig(tree)
pkg/config/parser_services_test.go:913:	cfg, err := CompileConfig(tree)
pkg/config/parser_services_test.go:961:	cfg, err := CompileConfig(tree)
pkg/config/parser_services_test.go:1028:	cfg, err := CompileConfig(tree)
pkg/config/parser_services_test.go:1081:	cfg, err := CompileConfig(tree)
pkg/config/parser_services_test.go:1127:	cfg, err := CompileConfig(tree)
pkg/config/parser_services_test.go:1165:	cfg, err := CompileConfig(tree)
pkg/config/parser_cluster_test.go:32:	cfg, err := CompileConfig(tree)
pkg/config/parser_cluster_test.go:83:	cfg, err := CompileConfig(tree)
pkg/config/parser_cluster_test.go:135:	cfg, err := CompileConfig(tree)
pkg/config/parser_cluster_test.go:189:	cfg, err := CompileConfig(tree)
pkg/config/parser_cluster_test.go:243:	cfg, err := CompileConfig(tree)
pkg/config/parser_cluster_test.go:277:	cfg, err := CompileConfig(tree)
pkg/config/parser_cluster_test.go:308:	cfg, err := CompileConfig(tree)
pkg/config/parser_cluster_test.go:331:	cfg, err := CompileConfig(tree)
pkg/config/parser_cluster_test.go:355:	cfg, err := CompileConfig(tree)
pkg/config/parser_cluster_test.go:378:	cfg, err := CompileConfig(tree)
pkg/config/parser_cluster_test.go:400:	cfg, err := CompileConfig(tree)
pkg/config/parser_cluster_test.go:424:	cfg, err := CompileConfig(tree)
pkg/config/parser_cluster_test.go:447:	cfg, err := CompileConfig(tree)
pkg/config/parser_cluster_test.go:469:	cfg, err := CompileConfig(tree)
pkg/config/parser_cluster_test.go:506:	cfg, err := CompileConfig(tree)
pkg/config/parser_cluster_test.go:552:	cfg, err := CompileConfig(tree)
pkg/config/parser_cluster_test.go:607:	cfg, err := CompileConfig(tree)
pkg/config/parser_cluster_test.go:638:	cfg, err := CompileConfig(tree)
pkg/config/parser_cluster_test.go:670:	cfg, err := CompileConfig(tree)
pkg/config/parser_cluster_test.go:697:	cfg, err := CompileConfig(tree)
pkg/config/parser_cluster_test.go:720:	cfg, err := CompileConfig(tree)
pkg/config/parser_cluster_test.go:742:	cfg, err := CompileConfig(tree)
pkg/config/parser_cluster_test.go:766:	cfg, err := CompileConfig(tree)
pkg/config/parser_cluster_test.go:789:	cfg, err := CompileConfig(tree)
pkg/config/parser_cluster_test.go:811:	cfg, err := CompileConfig(tree)
pkg/config/parser_cluster_test.go:834:	cfg, err := CompileConfig(tree)
pkg/config/parser_cluster_test.go:947:	cfg, err := CompileConfig(tree)
pkg/config/parser_cluster_test.go:979:	cfg, err := CompileConfig(tree)
pkg/config/parser_cluster_test.go:1011:	cfg, err := CompileConfig(tree)
pkg/config/parser_cluster_test.go:1039:	cfg, err := CompileConfig(tree)
pkg/config/parser_cluster_test.go:1070:	cfg, err := CompileConfig(tree)
pkg/config/parser_cluster_test.go:1101:	cfg, err := CompileConfig(tree)
pkg/config/parser_cluster_test.go:1129:	cfg, err := CompileConfig(tree)
pkg/config/parser_cluster_test.go:1154:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:22:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:144:	cfg2, err := CompileConfig(tree2)
pkg/config/parser_routing_test.go:168:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:203:	hierCfg, err := CompileConfig(hierTree)
pkg/config/parser_routing_test.go:228:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:269:	hierCfg, err := CompileConfig(hierTree)
pkg/config/parser_routing_test.go:310:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:371:	cfg2, err := CompileConfig(tree2)
pkg/config/parser_routing_test.go:416:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:493:	hierCfg, err := CompileConfig(hierTree)
pkg/config/parser_routing_test.go:530:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:577:	cfg2, err := CompileConfig(tree2)
pkg/config/parser_routing_test.go:607:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:680:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:734:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:778:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:817:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:871:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:902:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:925:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:975:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:1020:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:1048:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:1092:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:1120:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:1151:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:1177:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:1214:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:1257:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:1291:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:1319:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:1361:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:1389:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:1408:	cfg2, err := CompileConfig(tree2)
pkg/config/parser_routing_test.go:1429:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:1477:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:1515:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:1540:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:1568:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:1596:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:1624:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:1649:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:1677:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:1705:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:1733:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:1761:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:1819:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:1860:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:1897:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:1935:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:1964:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:2000:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:2033:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:2069:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:2103:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:2138:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:2176:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:2211:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:2254:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:2285:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:2323:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:2352:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:2381:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:2420:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:2456:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:2492:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:2535:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:2574:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:2616:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:2651:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:2696:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:2748:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:2806:	cfg, err := CompileConfig(tree2)
pkg/config/parser_routing_test.go:2837:	_, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:2872:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:2904:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:2939:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:2973:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:3017:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:3058:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:3095:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:3120:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:3148:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:3188:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:3220:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:3273:	cfg, err := CompileConfig(tree)
pkg/config/dual_ast_differential_test.go:862:	hierCfg, err := CompileConfig(hierTree)
pkg/config/dual_ast_differential_test.go:866:	flatCfg, err := CompileConfig(flatTree)
pkg/configstore/store.go:127:	// -1 means non-cluster (use CompileConfig), >= 0 means use CompileConfigForNode.
pkg/configstore/store.go:451:		return config.CompileConfigForNode(tree, nodeID)
pkg/configstore/store.go:453:	return config.CompileConfig(tree)
pkg/configstore/store.go:458:// CompileConfigForNodeLenient: #1798 control-char sanitize, lenient
pkg/configstore/store.go:493:		return config.CompileConfigForNodeLenient(tree, s.nodeID)
pkg/config/parser_security_test.go:20:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:52:	cfg2, err := CompileConfig(tree2)
pkg/config/parser_security_test.go:141:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:210:	cfg2, err := CompileConfig(tree2)
pkg/config/parser_security_test.go:238:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:296:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:324:	cfg2, err := CompileConfig(tree2)
pkg/config/parser_security_test.go:360:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:420:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:451:	cfg2, err := CompileConfig(tree2)
pkg/config/parser_security_test.go:476:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:510:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:568:	cfg, cerr := CompileConfig(tree)
pkg/config/parser_security_test.go:620:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:682:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:730:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:794:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:862:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:944:	cfg2, err := CompileConfig(tree2)
pkg/config/parser_security_test.go:1009:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:1043:	cfg2, err := CompileConfig(tree2)
pkg/config/parser_security_test.go:1077:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:1114:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:1150:	cfg2, err := CompileConfig(tree2)
pkg/config/parser_security_test.go:1225:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:1270:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:1344:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:1385:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:1436:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:1477:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:1563:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:1680:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:1723:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:1754:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:1789:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:1871:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:1914:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:1950:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:1999:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:2031:	cfg2, err := CompileConfig(tree2)
pkg/config/parser_security_test.go:2064:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:2104:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:2161:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:2193:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:2247:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:2283:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:2332:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:2364:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:2392:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:2419:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:2437:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:2472:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:2518:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:2560:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:2616:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:2652:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:2675:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:2728:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:2824:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:2869:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:2925:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:2962:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:3012:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:3058:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:3106:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:3145:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:3200:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:3237:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:3283:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:3318:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:3358:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:3410:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:3491:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:3526:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:3571:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:3602:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:3639:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:3676:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:3712:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:3749:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:3800:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:3862:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:3916:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:3950:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:4009:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:4047:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:4091:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:4129:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:4163:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:4187:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:4226:	cfg, cerr := CompileConfig(tree)
pkg/config/parser_security_test.go:4268:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:4306:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:4342:	cfg, err := CompileConfig(tree)
pkg/config/schema_validate_chassis_test.go:261:	cfg, err := config.CompileConfig(tree)
pkg/configstore/dataplane_retire_test.go:28:	cfg, err := config.CompileConfig(tree)
pkg/configstore/dataplane_retire_test.go:118:	// the retirement validator. CompileConfigForNode forces the
pkg/configstore/dataplane_retire_test.go:120:	cfg, err := config.CompileConfigForNode(tree, 0)
pkg/configstore/dataplane_retire_test.go:122:		t.Fatalf("CompileConfigForNode after rewrite (apply-groups ebpf): %v", err)
pkg/configstore/dataplane_retire_test.go:156:	cfg, err := config.CompileConfigForNode(tree, 0)
pkg/configstore/dataplane_retire_test.go:158:		t.Fatalf("CompileConfigForNode after rewrite (apply-groups dpdk): %v", err)
pkg/configstore/dataplane_retire_test.go:196:	cfg, err := config.CompileConfig(tree)
pkg/configstore/dataplane_retire_test.go:243:	cfg, err := config.CompileConfigForNode(tree, 0)
pkg/configstore/dataplane_retire_test.go:245:		t.Fatalf("CompileConfigForNode after rewrite (split groups): %v", err)

codex
The key code shape matches the issue: expansion mutates clones, wildcard merges only into existing destination containers, and the runtime emission is stricter than the AST collector because of the non-WG source/destination drop. I’m checking package boundaries and possible recursion/cycle hazards before I write the verdict.
exec
/bin/bash -lc "nl -ba pkg/configstore/store.go | sed -n '420,510p'" in /home/ps/git/bpfrx/.claude/worktrees/1914-research-tunnel-collision
 succeeded in 0ms:
   420	
   421	// compileTree compiles a config tree using the appropriate method based on
   422	// whether the store is in cluster mode (nodeID >= 0) or standalone.
   423	//
   424	// Order of operations (#1319): the typed-leaf SchemaValidate gate runs
   425	// BEFORE compile, but against the same apply-groups-expanded view the
   426	// compiler consumes. Running on the raw candidate tree would let invalid
   427	// typed leaves inside `groups { ... }` bypass the gate while still reaching
   428	// the compiler after expansion. We still validate at commit time rather
   429	// than at `set` time so the candidate-edit flow stays permissive —
   430	// operators can stage half-typed values without each `set` line being
   431	// rejected — and `commit check` is the one place that fails loud on garbage
   432	// like `transmit-rate asd`. The tolerant Load/SyncApply ingress goes through
   433	// compileTreeLenient below, which downgrades the same gate to a warning
   434	// (#1319 PR 2 boot safety). cfg is nil at this point because we haven't
   435	// compiled yet; the typed-leaf validators shipped so far don't need it.
   436	func (s *Store) compileTree(tree *config.ConfigTree) (*config.Config, error) {
   437		return compileTreeStrict(tree, s.nodeID)
   438	}
   439	
   440	// compileTreeStrict is the package-level strict commit-check pipeline
   441	// (typed-leaf SchemaValidate gate on the apply-groups-expanded view,
   442	// then strict compile). It backs both Store.compileTree (every
   443	// operator-driven commit / commit-check) and CheckText (check.go —
   444	// the #1879 `xpfd check-config` day-0 validation gate), so the two
   445	// callers can never drift apart.
   446	func compileTreeStrict(tree *config.ConfigTree, nodeID int) (*config.Config, error) {
   447		if err := schemaValidateExpandedTreeForNode(tree, nodeID); err != nil {
   448			return nil, err
   449		}
   450		if nodeID >= 0 {
   451			return config.CompileConfigForNode(tree, nodeID)
   452		}
   453		return config.CompileConfig(tree)
   454	}
   455	
   456	// compileTreeLenient is compileTree with the tolerant-path validator
   457	// downgrades enabled (config.CompileConfigLenient /
   458	// CompileConfigForNodeLenient: #1798 control-char sanitize, lenient
   459	// VRRP track duplicates). It is used ONLY by the passive load
   460	// (Store.Load) and HA peer-sync (Store.SyncApply) ingress paths, NOT by
   461	// any operator-driven candidate commit / commit-check path.
   462	//
   463	// Rationale: Store.Load and Store.SyncApply compile a config the operator
   464	// did NOT just author — a persisted active config on local boot, or a
   465	// config pushed from a possibly-un-upgraded cluster primary. A strict
   466	// reject here would (a) fail Store.Load on an upgraded node carrying a
   467	// legacy config, leaving the daemon with no active config (operational
   468	// blackout), and (b) fail Store.SyncApply on an upgraded standby
   469	// receiving such a config from an un-upgraded primary, alarm-looping HA
   470	// config sync. The operator's next strict candidate commit rejects it.
   471	//
   472	// (The original #1733 equal-flow worker-cap downgrade that motivated
   473	// this split was retired in #1830 (e) — the dataplane no longer caps
   474	// equal-flow-enforcement at 32 workers.)
   475	func (s *Store) compileTreeLenient(tree *config.ConfigTree) (*config.Config, error) {
   476		// #1319 PR 2: the typed-leaf SchemaValidate gate is STRICT only on the
   477		// operator-driven commit / commit-check path (compileTree). Here — the
   478		// tolerant Store.Load / Store.SyncApply ingress for configs the
   479		// operator did NOT just author — a violation downgrades to a warning.
   480		// A persisted config written by an older binary (pre-gate, or before a
   481		// leaf's range was typed/tightened) may carry values the current gate
   482		// rejects; hard-failing would blackout-boot the node (Load) or
   483		// alarm-loop HA config sync (SyncApply), even though the compiler
   484		// accepted the value when it was committed and still compiles it the
   485		// same way today. This is the same doctrine as the #1733/#1798/#1814
   486		// lenient compile gates (see freetext.go); the operator's next strict
   487		// commit rejects the stale value loudly.
   488		if err := s.schemaValidateExpandedTree(tree); err != nil {
   489			slog.Warn("typed-leaf schema violation in tolerated config; continuing (a strict commit would reject this)",
   490				"err", err, "issue", "#1319")
   491		}
   492		if s.nodeID >= 0 {
   493			return config.CompileConfigForNodeLenient(tree, s.nodeID)
   494		}
   495		return config.CompileConfigLenient(tree)
   496	}
   497	
   498	func (s *Store) schemaValidateExpandedTree(tree *config.ConfigTree) error {
   499		return schemaValidateExpandedTreeForNode(tree, s.nodeID)
   500	}
   501	
   502	func schemaValidateExpandedTreeForNode(tree *config.ConfigTree, nodeID int) error {
   503		if tree == nil {
   504			return nil
   505		}
   506		expanded := tree.Clone()
   507		if nodeID >= 0 {
   508			vars := map[string]string{"node": fmt.Sprintf("node%d", nodeID)}
   509			if err := expanded.ExpandGroupsWithVars(vars); err != nil {
   510				return fmt.Errorf("apply-groups: %w", err)

exec
/bin/bash -lc "rg -n \"type Config struct|type InterfaceConfig|type InterfaceUnit|type TunnelConfig|func compileInterfaces|TunnelConfig\" pkg/config -g'*.go'" in /home/ps/git/bpfrx/.claude/worktrees/1914-research-tunnel-collision
 succeeded in 0ms:
pkg/config/types_routing.go:292:// TunnelConfig defines a GRE, IPIP, or other tunnel interface.
pkg/config/types_routing.go:293:type TunnelConfig struct {
pkg/config/types_routing.go:338:// TunnelConfig never leaks the WireGuard private key (#1432 S2a privkey
pkg/config/types_routing.go:341:func (tc *TunnelConfig) String() string {
pkg/config/types_routing.go:349:	return fmt.Sprintf("TunnelConfig{Name:%s Mode:%s Source:%s Destination:%s "+
pkg/config/types.go:268:type Config struct {
pkg/config/types.go:302:// tunnel stanza always maps to its compiler-assigned TunnelConfig.Name
pkg/config/compiler_interfaces.go:25:func compileInterfaces(node *Node, ifaces *InterfacesConfig) error {
pkg/config/compiler_interfaces.go:147:			tc := &TunnelConfig{
pkg/config/compiler_interfaces.go:233:				tc := &TunnelConfig{Name: linuxName, Mode: defaultMode}
pkg/config/compiler_interfaces.go:684:func parseTunnelWireguard(tc *TunnelConfig, wgNode *Node) {
pkg/config/compiler_interfaces.go:703:func parseTunnelWireguardPeer(tc *TunnelConfig, peerNode *Node) {
pkg/config/parser_cluster_test.go:1142:func TestPerUnitTunnelConfig(t *testing.T) {
pkg/config/types_test.go:203:					Tunnel: &TunnelConfig{Source: "10.0.0.1", Destination: "10.0.0.2"},
pkg/config/types_test.go:222:						0: {Number: 0, Tunnel: &TunnelConfig{Name: "gr-0-0-0", Source: "10.0.0.1"}},
pkg/config/types_test.go:223:						1: {Number: 1, Tunnel: &TunnelConfig{Name: "gr-0-0-0u1", Source: "10.0.0.3"}},
pkg/config/types_test.go:243:					50: {Number: 50, VlanID: 999, Tunnel: &TunnelConfig{Name: "gr-foo"}},
pkg/config/types_test.go:304:					Tunnel: &TunnelConfig{Source: "2001:db8::1", Destination: "2001:db8::2"},
pkg/config/types_interfaces.go:12:type InterfaceConfig struct {
pkg/config/types_interfaces.go:31:	Tunnel              *TunnelConfig // non-nil for tunnel interfaces (gre0, etc.)
pkg/config/types_interfaces.go:44:type InterfaceUnit struct {
pkg/config/types_interfaces.go:66:	Tunnel           *TunnelConfig         // per-unit tunnel config (for multi-unit GRE/IPIP)
pkg/config/tunnelid.go:130:// for TunnelConfig.Mode (prop Keys[1], compiler_interfaces.go), so the
pkg/config/parser_routing_test.go:3251:// the TunnelConfig Wg* fields via parseTunnelWireguard.

exec
/bin/bash -lc "rg -n \"github.com/psaab/xpf/pkg/(dataplane|config|dataplane/userspace)\" pkg/config pkg/dataplane/userspace -g'*.go'" in /home/ps/git/bpfrx/.claude/worktrees/1914-research-tunnel-collision
 succeeded in 0ms:
pkg/dataplane/userspace/manager_ha.go:15:	"github.com/psaab/xpf/pkg/config"
pkg/dataplane/userspace/manager_ha.go:16:	"github.com/psaab/xpf/pkg/dataplane"
pkg/dataplane/userspace/routes.go:10:	"github.com/psaab/xpf/pkg/config"
pkg/dataplane/userspace/filters.go:8:	"github.com/psaab/xpf/pkg/config"
pkg/dataplane/userspace/filters.go:9:	"github.com/psaab/xpf/pkg/dataplane"
pkg/dataplane/userspace/route_overlay_test.go:12:	"github.com/psaab/xpf/pkg/config"
pkg/dataplane/userspace/process.go:19:	"github.com/psaab/xpf/pkg/config"
pkg/dataplane/userspace/policycounters.go:6:	"github.com/psaab/xpf/pkg/config"
pkg/dataplane/userspace/policycounters.go:7:	"github.com/psaab/xpf/pkg/dataplane"
pkg/dataplane/userspace/manager.go:21:	"github.com/psaab/xpf/pkg/config"
pkg/dataplane/userspace/manager.go:22:	"github.com/psaab/xpf/pkg/dataplane"
pkg/dataplane/userspace/manager.go:23:	dpruntime "github.com/psaab/xpf/pkg/dataplane/runtime"
pkg/dataplane/userspace/cos.go:6:	"github.com/psaab/xpf/pkg/config"
pkg/dataplane/userspace/legacy_dataplane_test.go:8:	"github.com/psaab/xpf/pkg/dataplane"
pkg/dataplane/userspace/cosfmt.go:11:	"github.com/psaab/xpf/pkg/config"
pkg/dataplane/userspace/policies.go:12:	"github.com/psaab/xpf/pkg/config"
pkg/dataplane/userspace/policies.go:13:	"github.com/psaab/xpf/pkg/dataplane"
pkg/dataplane/userspace/zones.go:8:	"github.com/psaab/xpf/pkg/config"
pkg/dataplane/userspace/manager_test.go:23:	"github.com/psaab/xpf/pkg/config"
pkg/dataplane/userspace/manager_test.go:24:	"github.com/psaab/xpf/pkg/dataplane"
pkg/dataplane/userspace/xdp_shim_decouple_test.go:15:	"github.com/psaab/xpf/pkg/config"
pkg/dataplane/userspace/xdp_shim_decouple_test.go:16:	"github.com/psaab/xpf/pkg/dataplane"
pkg/dataplane/userspace/runtime_delta.go:7:	dpruntime "github.com/psaab/xpf/pkg/dataplane/runtime"
pkg/dataplane/userspace/mirrors.go:8:	"github.com/psaab/xpf/pkg/config"
pkg/dataplane/userspace/cosfmt_test.go:8:	"github.com/psaab/xpf/pkg/config"
pkg/dataplane/userspace/builder.go:9:	"github.com/psaab/xpf/pkg/config"
pkg/dataplane/userspace/builder.go:10:	"github.com/psaab/xpf/pkg/dataplane"
pkg/dataplane/userspace/snapshot_allowlist_test.go:9:	"github.com/psaab/xpf/pkg/config"
pkg/dataplane/userspace/manager_coupling_test.go:10:	"github.com/psaab/xpf/pkg/dataplane"
pkg/dataplane/userspace/tunnels_test.go:7:	"github.com/psaab/xpf/pkg/config"
pkg/dataplane/userspace/eventstream_test.go:17:	"github.com/psaab/xpf/pkg/dataplane"
pkg/dataplane/userspace/interfaces_test.go:7:	"github.com/psaab/xpf/pkg/config"
pkg/dataplane/userspace/fairness.go:7:	"github.com/psaab/xpf/pkg/config"
pkg/dataplane/userspace/eventstream.go:15:	"github.com/psaab/xpf/pkg/dataplane"
pkg/dataplane/userspace/maps_sync_cap_test.go:14:	"github.com/psaab/xpf/pkg/config"
pkg/dataplane/userspace/maps_sync_cap_test.go:15:	"github.com/psaab/xpf/pkg/dataplane"
pkg/dataplane/userspace/tunnels.go:10:	"github.com/psaab/xpf/pkg/config"
pkg/config/schema_validate_test.go:13:	"github.com/psaab/xpf/pkg/config"
pkg/dataplane/userspace/fabric.go:7:	"github.com/psaab/xpf/pkg/config"
pkg/dataplane/userspace/protocol.go:7:	"github.com/psaab/xpf/pkg/config"
pkg/dataplane/userspace/flow.go:3:import "github.com/psaab/xpf/pkg/config"
pkg/dataplane/userspace/userspace_boot_canary_test.go:7:	"github.com/psaab/xpf/pkg/dataplane"
pkg/config/schema_validate_chassis_test.go:18:	"github.com/psaab/xpf/pkg/config"
pkg/dataplane/userspace/legacy_dataplane.go:9:	"github.com/psaab/xpf/pkg/config"
pkg/dataplane/userspace/legacy_dataplane.go:10:	"github.com/psaab/xpf/pkg/dataplane"
pkg/dataplane/userspace/legacy_dataplane.go:11:	dpruntime "github.com/psaab/xpf/pkg/dataplane/runtime"
pkg/dataplane/userspace/fbf_snapshot_test.go:6:	"github.com/psaab/xpf/pkg/config"
pkg/dataplane/userspace/configstore_helper_test.go:6:	"github.com/psaab/xpf/pkg/configstore"
pkg/config/schema_validate_interfaces_test.go:16:	"github.com/psaab/xpf/pkg/config"
pkg/dataplane/userspace/screens.go:8:	"github.com/psaab/xpf/pkg/config"
pkg/dataplane/userspace/nat_per_uplink_test.go:13:	"github.com/psaab/xpf/pkg/config"
pkg/dataplane/userspace/runtime_delta_test.go:10:	"github.com/psaab/xpf/pkg/dataplane"
pkg/dataplane/userspace/runtime_delta_test.go:11:	dpruntime "github.com/psaab/xpf/pkg/dataplane/runtime"
pkg/dataplane/userspace/address_book_test.go:10:	"github.com/psaab/xpf/pkg/config"
pkg/dataplane/userspace/interfaces.go:11:	"github.com/psaab/xpf/pkg/config"
pkg/dataplane/userspace/nat.go:8:	"github.com/psaab/xpf/pkg/config"
pkg/dataplane/userspace/neighbors.go:9:	"github.com/psaab/xpf/pkg/config"
pkg/dataplane/userspace/maps_sync.go:17:	"github.com/psaab/xpf/pkg/config"
pkg/dataplane/userspace/maps_sync.go:18:	"github.com/psaab/xpf/pkg/dataplane"

exec
/bin/bash -lc "sed -n '1,40p' pkg/dataplane/userspace/*.go | rg -n \""'^import|github.com/psaab/xpf/pkg/config|package userspace|github.com/psaab/xpf/pkg/dataplane/userspace|pkg/dataplane"' in /home/ps/git/bpfrx/.claude/worktrees/1914-research-tunnel-collision
 succeeded in 0ms:
5:package userspace
7:import (
10:	"github.com/psaab/xpf/pkg/config"

exec
/bin/bash -lc "nl -ba pkg/config/types_interfaces.go | sed -n '1,95p' && nl -ba pkg/config/types_routing.go | sed -n '292,338p'" in /home/ps/git/bpfrx/.claude/worktrees/1914-research-tunnel-collision
 succeeded in 0ms:
     1	package config
     2	
     3	// Physical and logical interface configuration: units, VRRP, DHCPv4/v6
     4	// client options, and aggregated-ether (LAG) options.
     5	
     6	// InterfacesConfig holds interface configuration.
     7	type InterfacesConfig struct {
     8		Interfaces map[string]*InterfaceConfig
     9	}
    10	
    11	// InterfaceConfig represents a network interface.
    12	type InterfaceConfig struct {
    13		Name                string
    14		Description         string                  // free-text interface description
    15		MTU                 int                     // interface-level MTU (overridden by unit MTU)
    16		Speed               string                  // interface speed (e.g. "1g", "10g", "auto")
    17		Duplex              string                  // "full", "half", "auto"
    18		VlanTagging         bool                    // 802.1Q trunk mode
    19		FlexibleVlanTagging bool                    // flexible 802.1Q VLAN tagging (QinQ)
    20		Encapsulation       string                  // physical link-layer encapsulation (e.g. "flexible-ethernet-services")
    21		Bandwidth           uint64                  // interface bandwidth in bits per second
    22		Disable             bool                    // administratively disabled
    23		RedundantParent     string                  // gigether-options redundant-parent (HA)
    24		LAGParent           string                  // gigether-options 802.3ad <ae-name> (LAG member binding)
    25		RedundancyGroup     int                     // redundant-ether-options redundancy-group (0 = none)
    26		FabricMembers       []string                // fabric-options member-interfaces
    27		LocalFabricMember   string                  // resolved local member for this node (vSRX fabric-options mode)
    28		BondMode            string                  // bond mode: "active-backup" for fabric, "802.3ad" for ae
    29		AggregatedEtherOpts *AggregatedEtherOptions // ae interface options (LACP, etc.)
    30		Units               map[int]*InterfaceUnit
    31		Tunnel              *TunnelConfig // non-nil for tunnel interfaces (gre0, etc.)
    32	}
    33	
    34	// AggregatedEtherOptions defines LAG/ae interface parameters.
    35	type AggregatedEtherOptions struct {
    36		LACPActive   bool   // LACP active mode
    37		LACPPassive  bool   // LACP passive mode
    38		LACPPeriodic string // LACP periodic timer: "fast" or "slow"
    39		LinkSpeed    string // required member link speed (e.g. "1g", "10g")
    40		MinimumLinks int    // minimum active member links before bundle goes down
    41	}
    42	
    43	// InterfaceUnit represents a logical unit on an interface.
    44	type InterfaceUnit struct {
    45		Number           int
    46		Description      string           // free-text unit description
    47		VlanID           int              // 0 = native/untagged, >0 = 802.1Q tagged
    48		InnerVlanID      int              // inner VLAN tag for QinQ (flexible-vlan-tagging)
    49		PointToPoint     bool             // point-to-point link (for tunnels)
    50		Addresses        []string         // CIDR notation
    51		PrimaryAddress   string           // address marked as primary
    52		PreferredAddress string           // address marked as preferred
    53		MTU              int              // family-level MTU (0 = default)
    54		DHCP             bool             // family inet { dhcp; }
    55		DHCPOptions      *DHCPInetOptions // dhcp sub-options (lease-time, etc.)
    56		DHCPv6           bool             // family inet6 { dhcpv6; }
    57		DHCPv6Client     *DHCPv6ClientConfig
    58		DADDisable       bool                  // family inet6 { dad-disable; }
    59		SamplingInput    bool                  // family inet/inet6 { sampling { input; } }
    60		SamplingOutput   bool                  // family inet/inet6 { sampling { output; } }
    61		FilterInputV4    string                // family inet { filter { input NAME; } }
    62		FilterOutputV4   string                // family inet { filter { output NAME; } }
    63		FilterInputV6    string                // family inet6 { filter { input NAME; } }
    64		FilterOutputV6   string                // family inet6 { filter { output NAME; } }
    65		VRRPGroups       map[string]*VRRPGroup // keyed by address (CIDR), each address can have VRRP groups
    66		Tunnel           *TunnelConfig         // per-unit tunnel config (for multi-unit GRE/IPIP)
    67	}
    68	
    69	// VRRPGroup defines a VRRP (Virtual Router Redundancy Protocol) group.
    70	type VRRPGroup struct {
    71		ID                 int
    72		VirtualAddresses   []string // virtual IP addresses
    73		Priority           int      // 1-255, default 100
    74		Preempt            bool
    75		AcceptData         bool
    76		AdvertiseInterval  int    // seconds, default 1
    77		AuthType           string // "md5" or ""
    78		AuthKey            string
    79		TrackInterface     string // lower priority if interface is down
    80		TrackPriorityDelta int    // how much to lower priority
    81	}
    82	
    83	// DHCPv6ClientConfig holds DHCPv6 client options (dhcpv6-client stanza).
    84	type DHCPv6ClientConfig struct {
    85		DUIDType                   string   // "duid-ll" or "duid-llt"
    86		ClientType                 string   // "stateful" or "stateless"
    87		ClientIATypes              []string // "ia-pd", "ia-na"
    88		PrefixDelegatingPrefixLen  int      // preferred-prefix-length (0 = not set)
    89		PrefixDelegatingSubPrefLen int      // sub-prefix-length (0 = not set)
    90		ReqOptions                 []string // dns-server, domain-name, etc.
    91		UpdateRAInterface          string   // update-router-advertisement interface
    92	}
    93	
    94	// DHCPInetOptions holds DHCPv4 client options for family inet dhcp stanza.
    95	type DHCPInetOptions struct {
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

codex
One important implementation constraint is emerging: a config-package emitter can exactly enumerate candidate endpoint names from typed config, but it cannot clone the runtime builder wholesale because the runtime also filters by live interface snapshots. For the commit gate we only want config-emitted names, not current OS presence.
exec
/bin/bash -lc "nl -ba pkg/config/compiler_interfaces.go | sed -n '660,740p'" in /home/ps/git/bpfrx/.claude/worktrees/1914-research-tunnel-collision
 succeeded in 0ms:
   660		return nil
   661	}
   662	
   663	// parseTunnelWireguard fills the WireGuard fields on tc from a
   664	// `wireguard { ... }` node under a tunnel stanza (#1432 S2a). The
   665	// minimal generic grammar is:
   666	//
   667	//	tunnel {
   668	//	    mode wireguard;
   669	//	    wireguard {
   670	//	        listen-port 51820;
   671	//	        private-key <64-hex>;
   672	//	        peer {
   673	//	            public-key <64-hex>;
   674	//	            allowed-ips <cidr>;   # repeatable
   675	//	            endpoint <ip:port>;
   676	//	            persistent-keepalive <secs>;
   677	//	        }
   678	//	    }
   679	//	}
   680	//
   681	// This is intentionally narrower than the eventual Junos wireguard
   682	// grammar (S6); it compiles to the TunnelEndpointSnapshot Wg* DTO
   683	// fields without committing to that surface.
   684	func parseTunnelWireguard(tc *TunnelConfig, wgNode *Node) {
   685		for _, prop := range wgNode.Children {
   686			switch prop.Name() {
   687			case "listen-port":
   688				if v := nodeVal(prop); v != "" {
   689					if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 65535 {
   690						tc.WgListenPort = uint16(n)
   691					}
   692				}
   693			case "private-key":
   694				if v := nodeVal(prop); v != "" {
   695					tc.WgLocalPrivkeyHex = v
   696				}
   697			case "peer":
   698				parseTunnelWireguardPeer(tc, prop)
   699			}
   700		}
   701	}
   702	
   703	func parseTunnelWireguardPeer(tc *TunnelConfig, peerNode *Node) {
   704		for _, prop := range peerNode.Children {
   705			switch prop.Name() {
   706			case "public-key":
   707				if v := nodeVal(prop); v != "" {
   708					tc.WgPeerPubkeyHex = v
   709				}
   710			case "allowed-ips":
   711				if v := nodeVal(prop); v != "" {
   712					tc.WgAllowedIPs = append(tc.WgAllowedIPs, v)
   713				}
   714			case "endpoint":
   715				if v := nodeVal(prop); v != "" {
   716					tc.WgEndpoint = v
   717				}
   718			case "persistent-keepalive":
   719				if v := nodeVal(prop); v != "" {
   720					if n, err := strconv.Atoi(v); err == nil && n >= 0 && n <= 65535 {
   721						tc.WgKeepaliveSecs = uint16(n)
   722					}
   723				}
   724			}
   725		}
   726	}
   727	
   728	// parseMSSValue extracts MSS value from either "node { mss VALUE; }" or "node VALUE;" syntax.
   729	func parseMSSValue(node *Node) int {
   730		// Hierarchical: ipsec-vpn { mss 1360; } or gre-in { mss 1360; }
   731		mssChild := node.FindChild("mss")
   732		if mssChild != nil && len(mssChild.Keys) >= 2 {
   733			if v, err := strconv.Atoi(mssChild.Keys[1]); err == nil {
   734				return v
   735			}
   736		}
   737		// Flat: ipsec-vpn 1360; (set syntax)
   738		if len(node.Keys) >= 2 {
   739			if v, err := strconv.Atoi(node.Keys[1]); err == nil {
   740				return v

exec
/bin/bash -lc "nl -ba pkg/config/compiler_interfaces.go | sed -n '1,280p'" in /home/ps/git/bpfrx/.claude/worktrees/1914-research-tunnel-collision
 succeeded in 0ms:
     1	package config
     2	
     3	import (
     4		"fmt"
     5		"sort"
     6		"strconv"
     7		"strings"
     8	)
     9	
    10	// vrrpGroupPropertyKeywords are the property keywords recognized inside
    11	// a vrrp-group block. Used to delimit multi-value runs (virtual-address)
    12	// when properties are packed into a single node's Keys (#1813).
    13	var vrrpGroupPropertyKeywords = map[string]bool{
    14		"virtual-address":     true,
    15		"priority":            true,
    16		"preempt":             true,
    17		"accept-data":         true,
    18		"advertise-interval":  true,
    19		"authentication-type": true,
    20		"authentication-key":  true,
    21		"track-interface":     true,
    22		"track-priority-cost": true,
    23	}
    24	
    25	func compileInterfaces(node *Node, ifaces *InterfacesConfig) error {
    26		for _, child := range node.Children {
    27			if child.IsLeaf {
    28				continue
    29			}
    30			ifName := child.Name()
    31			ifc := &InterfaceConfig{
    32				Name:  ifName,
    33				Units: make(map[int]*InterfaceUnit),
    34			}
    35	
    36			// Check for description
    37			if descNode := child.FindChild("description"); descNode != nil {
    38				ifc.Description = nodeVal(descNode)
    39			}
    40	
    41			// Interface-level MTU
    42			if mtuNode := child.FindChild("mtu"); mtuNode != nil {
    43				if v := nodeVal(mtuNode); v != "" {
    44					if n, err := strconv.Atoi(v); err == nil {
    45						ifc.MTU = n
    46					}
    47				}
    48			}
    49	
    50			// Speed and duplex (ether-options or gigether-options)
    51			if speedNode := child.FindChild("speed"); speedNode != nil {
    52				ifc.Speed = nodeVal(speedNode)
    53			}
    54			if duplexNode := child.FindChild("duplex"); duplexNode != nil {
    55				ifc.Duplex = nodeVal(duplexNode)
    56			}
    57			if child.FindChild("disable") != nil {
    58				ifc.Disable = true
    59			}
    60	
    61			// Interface bandwidth (bits per second)
    62			if bwNode := child.FindChild("bandwidth"); bwNode != nil {
    63				if v := nodeVal(bwNode); v != "" {
    64					ifc.Bandwidth = parseBandwidthBps(v)
    65				}
    66			}
    67	
    68			// Check for vlan-tagging flag
    69			if child.FindChild("vlan-tagging") != nil {
    70				ifc.VlanTagging = true
    71			}
    72	
    73			// Check for flexible-vlan-tagging flag (QinQ)
    74			if child.FindChild("flexible-vlan-tagging") != nil {
    75				ifc.FlexibleVlanTagging = true
    76			}
    77	
    78			// Check for encapsulation
    79			if encapNode := child.FindChild("encapsulation"); encapNode != nil {
    80				ifc.Encapsulation = nodeVal(encapNode)
    81			}
    82	
    83			// Check for gigether-options redundant-parent and 802.3ad LAG member
    84			if goNode := child.FindChild("gigether-options"); goNode != nil {
    85				if rpNode := goNode.FindChild("redundant-parent"); rpNode != nil {
    86					ifc.RedundantParent = nodeVal(rpNode)
    87				}
    88				if adNode := goNode.FindChild("802.3ad"); adNode != nil {
    89					ifc.LAGParent = nodeVal(adNode)
    90				}
    91			}
    92	
    93			// Check for aggregated-ether-options (LAG/ae interface)
    94			if aeoNode := child.FindChild("aggregated-ether-options"); aeoNode != nil {
    95				opts := &AggregatedEtherOptions{}
    96				if lacpNode := aeoNode.FindChild("lacp"); lacpNode != nil {
    97					if lacpNode.FindChild("active") != nil {
    98						opts.LACPActive = true
    99					}
   100					if lacpNode.FindChild("passive") != nil {
   101						opts.LACPPassive = true
   102					}
   103					if periodicNode := lacpNode.FindChild("periodic"); periodicNode != nil {
   104						opts.LACPPeriodic = nodeVal(periodicNode)
   105					}
   106				}
   107				if lsNode := aeoNode.FindChild("link-speed"); lsNode != nil {
   108					opts.LinkSpeed = nodeVal(lsNode)
   109				}
   110				if mlNode := aeoNode.FindChild("minimum-links"); mlNode != nil {
   111					if v := nodeVal(mlNode); v != "" {
   112						opts.MinimumLinks, _ = strconv.Atoi(v)
   113					}
   114				}
   115				ifc.AggregatedEtherOpts = opts
   116			}
   117	
   118			// Check for redundant-ether-options redundancy-group
   119			if reoNode := child.FindChild("redundant-ether-options"); reoNode != nil {
   120				if rgNode := reoNode.FindChild("redundancy-group"); rgNode != nil {
   121					if v, err := strconv.Atoi(nodeVal(rgNode)); err == nil {
   122						ifc.RedundancyGroup = v
   123					}
   124				}
   125			}
   126	
   127			// Check for fabric-options member-interfaces
   128			if foNode := child.FindChild("fabric-options"); foNode != nil {
   129				if miNode := foNode.FindChild("member-interfaces"); miNode != nil {
   130					for _, m := range miNode.Children {
   131						ifc.FabricMembers = append(ifc.FabricMembers, m.Name())
   132					}
   133				}
   134				if len(ifc.FabricMembers) > 0 {
   135					ifc.BondMode = "active-backup"
   136				}
   137			}
   138	
   139			// Check for interface-level tunnel configuration
   140			tunnelNode := child.FindChild("tunnel")
   141			if tunnelNode != nil {
   142				// Default mode based on interface name prefix: ip-X/X/X → ipip, gr-X/X/X → gre
   143				defaultMode := "gre"
   144				if strings.HasPrefix(ifName, "ip-") {
   145					defaultMode = "ipip"
   146				}
   147				tc := &TunnelConfig{
   148					Name: LinuxIfName(ifName),
   149					Mode: defaultMode,
   150				}
   151				for _, prop := range tunnelNode.Children {
   152					switch prop.Name() {
   153					case "source":
   154						if len(prop.Keys) >= 2 {
   155							tc.Source = prop.Keys[1]
   156						}
   157					case "destination":
   158						if len(prop.Keys) >= 2 {
   159							tc.Destination = prop.Keys[1]
   160						}
   161					case "mode":
   162						if len(prop.Keys) >= 2 {
   163							tc.Mode = prop.Keys[1]
   164						}
   165					case "key":
   166						if len(prop.Keys) >= 2 {
   167							if v, err := strconv.Atoi(prop.Keys[1]); err == nil {
   168								tc.Key = uint32(v)
   169							}
   170						}
   171					case "ttl":
   172						if len(prop.Keys) >= 2 {
   173							if v, err := strconv.Atoi(prop.Keys[1]); err == nil {
   174								tc.TTL = v
   175							}
   176						}
   177					case "keepalive":
   178						if v := nodeVal(prop); v != "" {
   179							if n, err := strconv.Atoi(v); err == nil {
   180								tc.Keepalive = n
   181							}
   182						}
   183					case "keepalive-retry":
   184						if v := nodeVal(prop); v != "" {
   185							if n, err := strconv.Atoi(v); err == nil {
   186								tc.KeepaliveRetry = n
   187							}
   188						}
   189					case "routing-instance":
   190						// routing-instance { destination <name>; }
   191						if destNode := prop.FindChild("destination"); destNode != nil {
   192							tc.RoutingInstance = nodeVal(destNode)
   193						} else if v := nodeVal(prop); v != "" {
   194							tc.RoutingInstance = v
   195						}
   196					case "wireguard":
   197						parseTunnelWireguard(tc, prop)
   198					}
   199				}
   200				ifc.Tunnel = tc
   201			}
   202	
   203			for _, unitInst := range namedInstances(child.FindChildren("unit")) {
   204				unitNum, err := strconv.Atoi(unitInst.name)
   205				if err != nil {
   206					continue
   207				}
   208				unit := &InterfaceUnit{Number: unitNum}
   209	
   210				// Parse description on unit
   211				if descNode := unitInst.node.FindChild("description"); descNode != nil {
   212					unit.Description = nodeVal(descNode)
   213				}
   214	
   215				// Parse point-to-point flag
   216				if unitInst.node.FindChild("point-to-point") != nil {
   217					unit.PointToPoint = true
   218				}
   219	
   220				// Parse tunnel config at unit level (gr-0/0/0 unit N { tunnel { ... } })
   221				if tunnelNode := unitInst.node.FindChild("tunnel"); tunnelNode != nil {
   222					defaultMode := "gre"
   223					if strings.HasPrefix(ifName, "ip-") {
   224						defaultMode = "ipip"
   225					}
   226					// Per-unit tunnel: each unit with its own tunnel config gets
   227					// a separate Linux interface. Unit 0 uses the base name,
   228					// unit N>0 appends "uN".
   229					linuxName := LinuxIfName(ifName)
   230					if unitNum > 0 {
   231						linuxName = linuxName + "u" + strconv.Itoa(unitNum)
   232					}
   233					tc := &TunnelConfig{Name: linuxName, Mode: defaultMode}
   234					// Inherit from interface-level tunnel if present
   235					if ifc.Tunnel != nil {
   236						*tc = *ifc.Tunnel
   237						tc.Name = linuxName
   238					}
   239					for _, prop := range tunnelNode.Children {
   240						switch prop.Name() {
   241						case "source":
   242							if v := nodeVal(prop); v != "" {
   243								tc.Source = v
   244							}
   245						case "destination":
   246							if v := nodeVal(prop); v != "" {
   247								tc.Destination = v
   248							}
   249						case "routing-instance":
   250							if destNode := prop.FindChild("destination"); destNode != nil {
   251								tc.RoutingInstance = nodeVal(destNode)
   252							} else if v := nodeVal(prop); v != "" {
   253								tc.RoutingInstance = v
   254							}
   255						case "mode":
   256							if v := nodeVal(prop); v != "" {
   257								tc.Mode = v
   258							}
   259						case "key":
   260							if v := nodeVal(prop); v != "" {
   261								if n, err := strconv.Atoi(v); err == nil {
   262									tc.Key = uint32(n)
   263								}
   264							}
   265						case "ttl":
   266							if v := nodeVal(prop); v != "" {
   267								if n, err := strconv.Atoi(v); err == nil {
   268									tc.TTL = n
   269								}
   270							}
   271						case "keepalive":
   272							if v := nodeVal(prop); v != "" {
   273								if n, err := strconv.Atoi(v); err == nil {
   274									tc.Keepalive = n
   275								}
   276							}
   277						case "keepalive-retry":
   278							if v := nodeVal(prop); v != "" {
   279								if n, err := strconv.Atoi(v); err == nil {
   280									tc.KeepaliveRetry = n

exec
/bin/bash -lc "nl -ba pkg/config/parser_ast_test.go | sed -n '3910,3985p'" in /home/ps/git/bpfrx/.claude/worktrees/1914-research-tunnel-collision
 succeeded in 0ms:
  3910		}
  3911	}
  3912	
  3913	func TestCompileConfigForNode(t *testing.T) {
  3914		tree := &ConfigTree{}
  3915		setCommands := []string{`set groups node0 system host-name fw0`, `set groups node0 chassis cluster node 0`, `set groups node0 interfaces hb0 unit 0 family inet address 10.99.0.1/30`, `set groups node1 system host-name fw1`, `set groups node1 chassis cluster node 1`, `set groups node1 interfaces hb0 unit 0 family inet address 10.99.0.2/30`, `set apply-groups "${node}"`, `set chassis cluster cluster-id 1`}
  3916		for _, cmd := range setCommands {
  3917			path, err := ParseSetCommand(cmd)
  3918			if err != nil {
  3919				t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
  3920			}
  3921			if err := tree.SetPath(path); err != nil {
  3922				t.Fatalf("SetPath(%v): %v", path, err)
  3923			}
  3924		}
  3925		cfg0, err := CompileConfigForNode(tree, 0)
  3926		if err != nil {
  3927			t.Fatalf("CompileConfigForNode(0): %v", err)
  3928		}
  3929		if cfg0.System.HostName != "fw0" {
  3930			t.Errorf("node0 hostname = %q, want fw0", cfg0.System.HostName)
  3931		}
  3932		if cfg0.Chassis.Cluster == nil || cfg0.Chassis.Cluster.NodeID != 0 {
  3933			t.Errorf("node0 NodeID = %v, want 0", cfg0.Chassis.Cluster)
  3934		}
  3935		cfg1, err := CompileConfigForNode(tree, 1)
  3936		if err != nil {
  3937			t.Fatalf("CompileConfigForNode(1): %v", err)
  3938		}
  3939		if cfg1.System.HostName != "fw1" {
  3940			t.Errorf("node1 hostname = %q, want fw1", cfg1.System.HostName)
  3941		}
  3942		if cfg1.Chassis.Cluster == nil || cfg1.Chassis.Cluster.NodeID != 1 {
  3943			t.Errorf("node1 NodeID = %v, want 1", cfg1.Chassis.Cluster)
  3944		}
  3945		if tree.FindChild("groups") == nil {
  3946			t.Error("groups node stripped from original tree")
  3947		}
  3948		if tree.FindChild("apply-groups") == nil {
  3949			t.Error("apply-groups node stripped from original tree")
  3950		}
  3951	}
  3952	
  3953	func TestCompileConfigForNodeBackwardCompat(t *testing.T) {
  3954		tree := &ConfigTree{}
  3955		setCommands := []string{`set groups node0 system host-name fw0`, `set apply-groups "${node}"`}
  3956		for _, cmd := range setCommands {
  3957			path, err := ParseSetCommand(cmd)
  3958			if err != nil {
  3959				t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
  3960			}
  3961			if err := tree.SetPath(path); err != nil {
  3962				t.Fatalf("SetPath(%q): %v", cmd, err)
  3963			}
  3964		}
  3965		cfg, err := CompileConfig(tree)
  3966		if err != nil {
  3967			t.Fatalf("CompileConfig() unexpected error: %v", err)
  3968		}
  3969		if cfg.System.HostName != "fw0" {
  3970			t.Fatalf("hostname = %q, want fw0", cfg.System.HostName)
  3971		}
  3972		found := false
  3973		for _, w := range cfg.Warnings {
  3974			if strings.Contains(w, `"${node}"`) && strings.Contains(w, "node0") {
  3975				found = true
  3976			}
  3977		}
  3978		if !found {
  3979			t.Fatalf("expected node placeholder warning, got %v", cfg.Warnings)
  3980		}
  3981	}
  3982	
  3983	func TestExpandGroupsWithVarsNilPreservesBackwardCompat(t *testing.T) {
  3984		tree := &ConfigTree{}
  3985		setCommands := []string{"set groups common system host-name test-fw", "set apply-groups common"}

codex
The plan’s “use CompileConfig* from inside the gate” wording is unsafe as written: the public compile entrypoints run the tunnel gate before expansion, so a literal implementation would recurse. The plan can still work, but it needs to say “clone/expand/compileExpanded or a tunnel-only extractor,” not “CompileConfig*.”
exec
/bin/bash -lc "nl -ba pkg/config/ast.go | sed -n '1,240p'" in /home/ps/git/bpfrx/.claude/worktrees/1914-research-tunnel-collision
 succeeded in 0ms:
     1	package config
     2	
     3	import (
     4		"fmt"
     5		"strings"
     6	)
     7	
     8	// Node represents a node in the Junos configuration tree.
     9	// It is either a leaf (terminated by ;) or a block (containing children in {}).
    10	type Node struct {
    11		// Keys is the sequence of identifiers forming this node's identity.
    12		// Examples:
    13		//   "security" -> ["security"]
    14		//   "security-zone trust" -> ["security-zone", "trust"]
    15		//   "from-zone trust to-zone untrust" -> ["from-zone", "trust", "to-zone", "untrust"]
    16		//   "address 10.0.1.0/24" -> ["address", "10.0.1.0/24"]
    17		Keys []string
    18	
    19		// Children are the nodes within this block's braces.
    20		// nil for leaf nodes.
    21		Children []*Node
    22	
    23		// IsLeaf is true when the node is terminated by ; (no block body).
    24		IsLeaf bool
    25	
    26		// Annotation is a user comment set via the "annotate" command.
    27		Annotation string
    28	
    29		// InheritedFrom is the group name this node was inherited from.
    30		// Set during ExpandGroups when tagInherited is true.
    31		InheritedFrom string
    32	
    33		// Line/Column where this node starts (for error reporting).
    34		Line   int
    35		Column int
    36	}
    37	
    38	// Name returns the first key of the node.
    39	func (n *Node) Name() string {
    40		if len(n.Keys) == 0 {
    41			return ""
    42		}
    43		return n.Keys[0]
    44	}
    45	
    46	// KeyPath returns the full key path as a single string (unquoted).
    47	// Used for map lookups and comparison. For display/format output, use QuotedKeyPath.
    48	func (n *Node) KeyPath() string {
    49		return strings.Join(n.Keys, " ")
    50	}
    51	
    52	// QuotedKeyPath returns the key path with keys quoted if they contain
    53	// characters that aren't valid bare identifiers (e.g. ${node}).
    54	func (n *Node) QuotedKeyPath() string {
    55		parts := make([]string, len(n.Keys))
    56		for i, k := range n.Keys {
    57			parts[i] = quoteKey(k)
    58		}
    59		return strings.Join(parts, " ")
    60	}
    61	
    62	// quoteKey wraps a key in double quotes if it contains characters that
    63	// are not valid in bare Junos identifiers.
    64	func quoteKey(s string) string {
    65		if s == "" {
    66			return `""`
    67		}
    68		for i := 0; i < len(s); i++ {
    69			if !isIdentChar(s[i]) {
    70				// Escape any internal quotes.
    71				return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
    72			}
    73		}
    74		return s
    75	}
    76	
    77	// FindChild returns the first child whose first key matches name.
    78	func (n *Node) FindChild(name string) *Node {
    79		for _, child := range n.Children {
    80			if len(child.Keys) > 0 && child.Keys[0] == name {
    81				return child
    82			}
    83		}
    84		return nil
    85	}
    86	
    87	// FindChildren returns all children whose first key matches name.
    88	func (n *Node) FindChildren(name string) []*Node {
    89		var result []*Node
    90		for _, child := range n.Children {
    91			if len(child.Keys) > 0 && child.Keys[0] == name {
    92				result = append(result, child)
    93			}
    94		}
    95		return result
    96	}
    97	
    98	// ConfigTree is the root of a parsed configuration.
    99	type ConfigTree struct {
   100		Children []*Node
   101	}
   102	
   103	// FindChild returns the first top-level child matching name.
   104	func (t *ConfigTree) FindChild(name string) *Node {
   105		for _, child := range t.Children {
   106			if len(child.Keys) > 0 && child.Keys[0] == name {
   107				return child
   108			}
   109		}
   110		return nil
   111	}
   112	
   113	// Clone creates a deep copy of the config tree.
   114	func (t *ConfigTree) Clone() *ConfigTree {
   115		if t == nil {
   116			return nil
   117		}
   118		return &ConfigTree{
   119			Children: cloneNodes(t.Children),
   120		}
   121	}
   122	
   123	func cloneNodes(nodes []*Node) []*Node {
   124		if nodes == nil {
   125			return nil
   126		}
   127		result := make([]*Node, len(nodes))
   128		for i, n := range nodes {
   129			result[i] = &Node{
   130				Keys:          append([]string(nil), n.Keys...),
   131				Children:      cloneNodes(n.Children),
   132				IsLeaf:        n.IsLeaf,
   133				Annotation:    n.Annotation,
   134				InheritedFrom: n.InheritedFrom,
   135				Line:          n.Line,
   136				Column:        n.Column,
   137			}
   138		}
   139		return result
   140	}
   141	
   142	// navigatePath walks the tree following path components and returns matching nodes.
   143	// When multiple sibling nodes share the same key prefix (e.g., path ["from-zone","untrust"]
   144	// matching both ["from-zone","untrust","to-zone","trust"] and
   145	// ["from-zone","untrust","to-zone","dmz"]), all matches are returned.
   146	func navigatePath(nodes []*Node, path []string) []*Node {
   147		current := nodes
   148		i := 0
   149		for i < len(path) {
   150			keyword := path[i]
   151			// Try multi-key match (keyword + argument pairs).
   152			if i+1 < len(path) {
   153				var matched []*Node
   154				for _, n := range current {
   155					if len(n.Keys) >= 2 && n.Keys[0] == keyword && n.Keys[1] == path[i+1] {
   156						matched = append(matched, n)
   157					}
   158				}
   159				if len(matched) > 0 {
   160					consumed := 2
   161					// Continue consuming additional key-value pairs from the path
   162					// that match the node's remaining keys. E.g., path
   163					// ["from-zone","untrust","to-zone","trust"] consumes all 4 keys
   164					// of node Keys=["from-zone","untrust","to-zone","trust"].
   165					for consumed < len(matched[0].Keys) && i+consumed+1 < len(path) {
   166						nextKey := path[i+consumed]
   167						nextVal := path[i+consumed+1]
   168						var filtered []*Node
   169						for _, n := range matched {
   170							if len(n.Keys) > consumed+1 && n.Keys[consumed] == nextKey && n.Keys[consumed+1] == nextVal {
   171								filtered = append(filtered, n)
   172							}
   173						}
   174						if len(filtered) == 0 {
   175							break
   176						}
   177						matched = filtered
   178						consumed += 2
   179					}
   180					i += consumed
   181					if i >= len(path) {
   182						return matched
   183					}
   184					current = matched[0].Children
   185					continue
   186				}
   187			}
   188			// Single-key match.
   189			found := false
   190			for _, n := range current {
   191				if len(n.Keys) > 0 && n.Keys[0] == keyword {
   192					i++
   193					if i >= len(path) {
   194						return []*Node{n}
   195					}
   196					current = n.Children
   197					found = true
   198					break
   199				}
   200			}
   201			if !found {
   202				return nil
   203			}
   204		}
   205		return nil
   206	}
   207	
   208	// matchNodeKeys checks if a node's Keys match path elements starting at pos.
   209	// Returns the number of path elements consumed (len(node.Keys)) on match, 0 otherwise.
   210	func matchNodeKeys(n *Node, path []string, pos int) int {
   211		if len(n.Keys) == 0 || pos >= len(path) {
   212			return 0
   213		}
   214		if n.Keys[0] != path[pos] {
   215			return 0
   216		}
   217		// First key matches; check remaining keys fit within path
   218		nk := len(n.Keys)
   219		if pos+nk > len(path) {
   220			// Partial match: node has more keys than remaining path.
   221			// Accept if we're at the last path segment (allows matching by first key only).
   222			return 1
   223		}
   224		for j := 1; j < nk; j++ {
   225			if n.Keys[j] != path[pos+j] {
   226				return 1 // first key matched but subsequent didn't; still a 1-key match
   227			}
   228		}
   229		return nk
   230	}
   231	
   232	// navigateToNode walks the tree following path, returning the target node.
   233	// Multi-key nodes consume multiple path elements at once.
   234	func navigateToNode(children []*Node, path []string) (*Node, error) {
   235		var current *Node
   236		pos := 0
   237		for pos < len(path) {
   238			found := false
   239			for _, child := range children {
   240				consumed := matchNodeKeys(child, path, pos)

exec
/bin/bash -lc "rg -n \"func \\(.*\\) Clone|func cloneNodes|type Node|type ConfigTree|func \\(.*\\) FindChild|func namedInstances\" pkg/config -g'*.go'" in /home/ps/git/bpfrx/.claude/worktrees/1914-research-tunnel-collision
 succeeded in 0ms:
pkg/config/compiler_protocols.go:724:func namedInstances(nodes []*Node) []struct {
pkg/config/ast.go:10:type Node struct {
pkg/config/ast.go:78:func (n *Node) FindChild(name string) *Node {
pkg/config/ast.go:88:func (n *Node) FindChildren(name string) []*Node {
pkg/config/ast.go:99:type ConfigTree struct {
pkg/config/ast.go:104:func (t *ConfigTree) FindChild(name string) *Node {
pkg/config/ast.go:114:func (t *ConfigTree) Clone() *ConfigTree {
pkg/config/ast.go:123:func cloneNodes(nodes []*Node) []*Node {

exec
/bin/bash -lc "rg -n \"func nodeVal|func namedInstances|FindChildren|FindChild\" pkg/config -g'*.go'" in /home/ps/git/bpfrx/.claude/worktrees/1914-research-tunnel-collision
 succeeded in 0ms:
pkg/config/parser_ast_test.go:138:	secNode := tree.FindChild("security")
pkg/config/parser_ast_test.go:142:	zonesNode := secNode.FindChild("zones")
pkg/config/parser_ast_test.go:146:	trustZones := zonesNode.FindChildren("security-zone")
pkg/config/parser_ast_test.go:156:	ifacesNode := trustZones[0].FindChild("interfaces")
pkg/config/parser_ast_test.go:163:	polNode := secNode.FindChild("policies")
pkg/config/parser_ast_test.go:167:	zpNode := polNode.FindChild("from-zone")
pkg/config/parser_ast_test.go:2647:	sys := tree.FindChild("system")
pkg/config/parser_ast_test.go:2651:	dpType := sys.FindChild("dataplane-type")
pkg/config/parser_ast_test.go:2755:			system := tree.FindChild("system")
pkg/config/parser_ast_test.go:2759:			if got := len(system.FindChildren("dataplane-type")); got != 2 {
pkg/config/parser_ast_test.go:3860:	if tree.FindChild("groups") == nil {
pkg/config/parser_ast_test.go:3867:	if tree.FindChild("groups") == nil {
pkg/config/parser_ast_test.go:3870:	if tree.FindChild("apply-groups") == nil {
pkg/config/parser_ast_test.go:3945:	if tree.FindChild("groups") == nil {
pkg/config/parser_ast_test.go:3948:	if tree.FindChild("apply-groups") == nil {
pkg/config/parser_ast_test.go:4028:	if tree.FindChild("groups") == nil {
pkg/config/tunnelid.go:73:		tunnelNode := iface.FindChild("tunnel")
pkg/config/tunnelid.go:75:		units := namedInstances(iface.FindChildren("unit"))
pkg/config/tunnelid.go:95:			unitTunnel[n] = unit.node.FindChild("tunnel") != nil
pkg/config/tunnelid.go:164:	collectTunnelEndpointNamesAST(tree.FindChild("interfaces"), names)
pkg/config/tunnelid.go:173:				collectTunnelEndpointNamesAST(child.FindChild("interfaces"), names)
pkg/config/tunnelid.go:176:			collectTunnelEndpointNamesAST(group.FindChild("interfaces"), names)
pkg/config/compiler_nat.go:17:	srcNode := node.FindChild("source")
pkg/config/compiler_nat.go:24:	dstNode := node.FindChild("destination")
pkg/config/compiler_nat.go:31:	staticNode := node.FindChild("static")
pkg/config/compiler_nat.go:38:	nat64Node := node.FindChild("nat64")
pkg/config/compiler_nat.go:46:	v6v4Node := node.FindChild("natv6v4")
pkg/config/compiler_nat.go:49:		if v6v4Node.FindChild("no-v6-frag-header") != nil {
pkg/config/compiler_nat.go:55:	proxyNode := node.FindChild("proxy-arp")
pkg/config/compiler_nat.go:57:		for _, inst := range namedInstances(proxyNode.FindChildren("interface")) {
pkg/config/compiler_nat.go:74:				toChild := prop.FindChild("to")
pkg/config/compiler_nat.go:105:	for _, inst := range namedInstances(node.FindChildren("rule-set")) {
pkg/config/compiler_nat.go:195:	if node.FindChild("address-persistent") != nil {
pkg/config/compiler_nat.go:200:	for _, inst := range namedInstances(node.FindChildren("pool")) {
pkg/config/compiler_nat.go:335:	if alarmNode := node.FindChild("pool-utilization-alarm"); alarmNode != nil {
pkg/config/compiler_nat.go:426:	for _, rsInst := range namedInstances(node.FindChildren("rule-set")) {
pkg/config/compiler_nat.go:446:		for _, ruleInst := range namedInstances(rsInst.node.FindChildren("rule")) {
pkg/config/compiler_nat.go:449:			matchNode := ruleInst.node.FindChild("match")
pkg/config/compiler_nat.go:501:			thenNode := ruleInst.node.FindChild("then")
pkg/config/compiler_nat.go:519:						} else if t.FindChild("interface") != nil {
pkg/config/compiler_nat.go:522:						} else if t.FindChild("off") != nil {
pkg/config/compiler_nat.go:525:						} else if poolNode := t.FindChild("pool"); poolNode != nil {
pkg/config/compiler_nat.go:560:	for _, inst := range namedInstances(node.FindChildren("pool")) {
pkg/config/compiler_nat.go:580:	for _, rsInst := range namedInstances(node.FindChildren("rule-set")) {
pkg/config/compiler_nat.go:599:		for _, ruleInst := range namedInstances(rsInst.node.FindChildren("rule")) {
pkg/config/compiler_nat.go:602:			matchNode := ruleInst.node.FindChild("match")
pkg/config/compiler_nat.go:647:			thenNode := ruleInst.node.FindChild("then")
pkg/config/compiler_nat.go:654:						} else if poolNode := t.FindChild("pool"); poolNode != nil {
pkg/config/compiler_nat.go:694:				toChild := m.FindChild("to")
pkg/config/compiler_nat.go:745:	for _, rsInst := range namedInstances(node.FindChildren("rule-set")) {
pkg/config/compiler_nat.go:759:		for _, ruleInst := range namedInstances(rsInst.node.FindChildren("rule")) {
pkg/config/compiler_nat.go:762:			matchNode := ruleInst.node.FindChild("match")
pkg/config/compiler_nat.go:774:			thenNode := ruleInst.node.FindChild("then")
pkg/config/compiler_nat.go:782:						} else if np := t.FindChild("nptv6-prefix"); np != nil {
pkg/config/compiler_nat.go:788:						} else if pn := t.FindChild("prefix"); pn != nil {
pkg/config/compiler_nat.go:790:						} else if t.FindChild("inet") != nil || (len(t.Keys) >= 2 && t.Keys[1] == "inet") {
pkg/config/schema_validate_test.go:414:	if tree.FindChild("class-of-service") == nil {
pkg/config/compiler_interfaces.go:37:		if descNode := child.FindChild("description"); descNode != nil {
pkg/config/compiler_interfaces.go:42:		if mtuNode := child.FindChild("mtu"); mtuNode != nil {
pkg/config/compiler_interfaces.go:51:		if speedNode := child.FindChild("speed"); speedNode != nil {
pkg/config/compiler_interfaces.go:54:		if duplexNode := child.FindChild("duplex"); duplexNode != nil {
pkg/config/compiler_interfaces.go:57:		if child.FindChild("disable") != nil {
pkg/config/compiler_interfaces.go:62:		if bwNode := child.FindChild("bandwidth"); bwNode != nil {
pkg/config/compiler_interfaces.go:69:		if child.FindChild("vlan-tagging") != nil {
pkg/config/compiler_interfaces.go:74:		if child.FindChild("flexible-vlan-tagging") != nil {
pkg/config/compiler_interfaces.go:79:		if encapNode := child.FindChild("encapsulation"); encapNode != nil {
pkg/config/compiler_interfaces.go:84:		if goNode := child.FindChild("gigether-options"); goNode != nil {
pkg/config/compiler_interfaces.go:85:			if rpNode := goNode.FindChild("redundant-parent"); rpNode != nil {
pkg/config/compiler_interfaces.go:88:			if adNode := goNode.FindChild("802.3ad"); adNode != nil {
pkg/config/compiler_interfaces.go:94:		if aeoNode := child.FindChild("aggregated-ether-options"); aeoNode != nil {
pkg/config/compiler_interfaces.go:96:			if lacpNode := aeoNode.FindChild("lacp"); lacpNode != nil {
pkg/config/compiler_interfaces.go:97:				if lacpNode.FindChild("active") != nil {
pkg/config/compiler_interfaces.go:100:				if lacpNode.FindChild("passive") != nil {
pkg/config/compiler_interfaces.go:103:				if periodicNode := lacpNode.FindChild("periodic"); periodicNode != nil {
pkg/config/compiler_interfaces.go:107:			if lsNode := aeoNode.FindChild("link-speed"); lsNode != nil {
pkg/config/compiler_interfaces.go:110:			if mlNode := aeoNode.FindChild("minimum-links"); mlNode != nil {
pkg/config/compiler_interfaces.go:119:		if reoNode := child.FindChild("redundant-ether-options"); reoNode != nil {
pkg/config/compiler_interfaces.go:120:			if rgNode := reoNode.FindChild("redundancy-group"); rgNode != nil {
pkg/config/compiler_interfaces.go:128:		if foNode := child.FindChild("fabric-options"); foNode != nil {
pkg/config/compiler_interfaces.go:129:			if miNode := foNode.FindChild("member-interfaces"); miNode != nil {
pkg/config/compiler_interfaces.go:140:		tunnelNode := child.FindChild("tunnel")
pkg/config/compiler_interfaces.go:191:					if destNode := prop.FindChild("destination"); destNode != nil {
pkg/config/compiler_interfaces.go:203:		for _, unitInst := range namedInstances(child.FindChildren("unit")) {
pkg/config/compiler_interfaces.go:211:			if descNode := unitInst.node.FindChild("description"); descNode != nil {
pkg/config/compiler_interfaces.go:216:			if unitInst.node.FindChild("point-to-point") != nil {
pkg/config/compiler_interfaces.go:221:			if tunnelNode := unitInst.node.FindChild("tunnel"); tunnelNode != nil {
pkg/config/compiler_interfaces.go:250:						if destNode := prop.FindChild("destination"); destNode != nil {
pkg/config/compiler_interfaces.go:291:			if vlanNode := unitInst.node.FindChild("vlan-id"); vlanNode != nil {
pkg/config/compiler_interfaces.go:300:			if ivNode := unitInst.node.FindChild("inner-vlan-id"); ivNode != nil {
pkg/config/compiler_interfaces.go:313:			for _, familyNode := range unitInst.node.FindChildren("family") {
pkg/config/compiler_interfaces.go:327:						for _, addrInst := range namedInstances(afNode.FindChildren("address")) {
pkg/config/compiler_interfaces.go:330:							if addrInst.node.FindChild("primary") != nil {
pkg/config/compiler_interfaces.go:333:							if addrInst.node.FindChild("preferred") != nil {
pkg/config/compiler_interfaces.go:343:							for _, vrrpInst := range namedInstances(addrInst.node.FindChildren("vrrp-group")) {
pkg/config/compiler_interfaces.go:482:										if pc := prop.FindChild("priority-cost"); pc != nil {
pkg/config/compiler_interfaces.go:512:						if dhcpNode := afNode.FindChild("dhcp"); dhcpNode != nil {
pkg/config/compiler_interfaces.go:537:						if mtuNode := afNode.FindChild("mtu"); mtuNode != nil {
pkg/config/compiler_interfaces.go:544:						if sampNode := afNode.FindChild("sampling"); sampNode != nil {
pkg/config/compiler_interfaces.go:545:							if sampNode.FindChild("input") != nil {
pkg/config/compiler_interfaces.go:548:							if sampNode.FindChild("output") != nil {
pkg/config/compiler_interfaces.go:552:						if filterNode := afNode.FindChild("filter"); filterNode != nil {
pkg/config/compiler_interfaces.go:553:							if inputNode := filterNode.FindChild("input"); inputNode != nil {
pkg/config/compiler_interfaces.go:556:							if outputNode := filterNode.FindChild("output"); outputNode != nil {
pkg/config/compiler_interfaces.go:561:						for _, addrInst := range namedInstances(afNode.FindChildren("address")) {
pkg/config/compiler_interfaces.go:563:							if addrInst.node.FindChild("primary") != nil && unit.PrimaryAddress == "" {
pkg/config/compiler_interfaces.go:566:							if addrInst.node.FindChild("preferred") != nil && unit.PreferredAddress == "" {
pkg/config/compiler_interfaces.go:570:						if afNode.FindChild("dhcpv6") != nil {
pkg/config/compiler_interfaces.go:573:						if afNode.FindChild("dad-disable") != nil {
pkg/config/compiler_interfaces.go:576:						if mtuNode := afNode.FindChild("mtu"); mtuNode != nil {
pkg/config/compiler_interfaces.go:585:						if sampNode := afNode.FindChild("sampling"); sampNode != nil {
pkg/config/compiler_interfaces.go:586:							if sampNode.FindChild("input") != nil {
pkg/config/compiler_interfaces.go:589:							if sampNode.FindChild("output") != nil {
pkg/config/compiler_interfaces.go:593:						if filterNode := afNode.FindChild("filter"); filterNode != nil {
pkg/config/compiler_interfaces.go:594:							if inputNode := filterNode.FindChild("input"); inputNode != nil {
pkg/config/compiler_interfaces.go:597:							if outputNode := filterNode.FindChild("output"); outputNode != nil {
pkg/config/compiler_interfaces.go:601:						if dcNode := afNode.FindChild("dhcpv6-client"); dcNode != nil {
pkg/config/compiler_interfaces.go:607:									if dtNode := prop.FindChild("duid-type"); dtNode != nil {
pkg/config/compiler_interfaces.go:620:									if plNode := prop.FindChild("preferred-prefix-length"); plNode != nil {
pkg/config/compiler_interfaces.go:625:									if slNode := prop.FindChild("sub-prefix-length"); slNode != nil {
pkg/config/compiler_interfaces.go:635:									if ifNode := prop.FindChild("interface"); ifNode != nil {
pkg/config/compiler_interfaces.go:731:	mssChild := node.FindChild("mss")
pkg/config/compiler_interfaces.go:814:	tracks := vg.FindChildren("track-interface")
pkg/config/compiler_interfaces.go:846:	if len(tracks) == 1 && tracks[0].FindChild("priority-cost") != nil && vg.FindChild("track-priority-cost") != nil {
pkg/config/compiler_interfaces.go:849:	if vg.FindChild("priority-cost") != nil {
pkg/config/compiler_interfaces.go:872:		for _, pc := range tr.FindChildren("priority-cost") {
pkg/config/compiler_interfaces.go:880:	for _, tpc := range vg.FindChildren("track-priority-cost") {
pkg/config/compiler_security.go:57:			for _, hostInst := range namedInstances(child.FindChildren("host")) {
pkg/config/compiler_security.go:68:			if sw := child.FindChild("system-wide"); sw != nil {
pkg/config/compiler_security.go:73:			if thenNode := child.FindChild("then"); thenNode != nil {
pkg/config/compiler_security.go:74:				if logNode := thenNode.FindChild("log"); logNode != nil {
pkg/config/compiler_security.go:75:					if logNode.FindChild("session-init") != nil {
pkg/config/compiler_security.go:78:					if logNode.FindChild("session-close") != nil {
pkg/config/compiler_security.go:89:	for _, inst := range namedInstances(node.FindChildren("security-zone")) {
pkg/config/compiler_security.go:149:			for _, polInst := range namedInstances(child.FindChildren("policy")) {
pkg/config/compiler_security.go:169:					tzNode := fzSub.FindChild("to-zone")
pkg/config/compiler_security.go:185:				for _, polInst := range namedInstances(zp.policyNode.FindChildren("policy")) {
pkg/config/compiler_security.go:203:	matchNode := polInst.node.FindChild("match")
pkg/config/compiler_security.go:235:	thenNode := polInst.node.FindChild("then")
pkg/config/compiler_security.go:261:	if descNode := polInst.node.FindChild("description"); descNode != nil {
pkg/config/compiler_security.go:264:	if snNode := polInst.node.FindChild("scheduler-name"); snNode != nil {
pkg/config/compiler_security.go:272:	for _, inst := range namedInstances(node.FindChildren("ids-option")) {
pkg/config/compiler_security.go:275:		icmpNode := inst.node.FindChild("icmp")
pkg/config/compiler_security.go:295:		ipNode := inst.node.FindChild("ip")
pkg/config/compiler_security.go:319:		tcpNode := inst.node.FindChild("tcp")
pkg/config/compiler_security.go:375:		udpNode := inst.node.FindChild("udp")
pkg/config/compiler_security.go:393:		limitNode := inst.node.FindChild("limit-session")
pkg/config/compiler_security.go:418:	globalNode := node.FindChild("global")
pkg/config/compiler_security.go:468:	if modeNode := node.FindChild("mode"); modeNode != nil {
pkg/config/compiler_security.go:471:	if fmtNode := node.FindChild("format"); fmtNode != nil {
pkg/config/compiler_security.go:474:	if srcNode := node.FindChild("source-interface"); srcNode != nil {
pkg/config/compiler_security.go:477:	if node.FindChild("report") != nil {
pkg/config/compiler_security.go:481:	for _, inst := range namedInstances(node.FindChildren("stream")) {
pkg/config/compiler_security.go:545:	if agingNode := node.FindChild("aging"); agingNode != nil {
pkg/config/compiler_security.go:565:	tcpNode := node.FindChild("tcp-session")
pkg/config/compiler_security.go:601:	udpNode := node.FindChild("udp-session")
pkg/config/compiler_security.go:612:	icmpNode := node.FindChild("icmp-session")
pkg/config/compiler_security.go:624:	mssNode := node.FindChild("tcp-mss")
pkg/config/compiler_security.go:651:	if node.FindChild("allow-dns-reply") != nil {
pkg/config/compiler_security.go:656:	if node.FindChild("allow-embedded-icmp") != nil {
pkg/config/compiler_security.go:661:	if node.FindChild("gre-performance-acceleration") != nil {
pkg/config/compiler_security.go:666:	if node.FindChild("power-mode-disable") != nil {
pkg/config/compiler_security.go:671:	if spNode := node.FindChild("syn-flood-protection-mode"); spNode != nil {
pkg/config/compiler_security.go:678:	if toNode := node.FindChild("traceoptions"); toNode != nil {
pkg/config/compiler_security.go:680:		if fileNode := toNode.FindChild("file"); fileNode != nil {
pkg/config/compiler_security.go:695:			if sNode := fileNode.FindChild("size"); sNode != nil {
pkg/config/compiler_security.go:702:			if fNode := fileNode.FindChild("files"); fNode != nil {
pkg/config/compiler_security.go:710:		for _, flagNode := range toNode.FindChildren("flag") {
pkg/config/compiler_security.go:715:		for _, pfInst := range namedInstances(toNode.FindChildren("packet-filter")) {
pkg/config/compiler_security.go:717:			if spNode := pfInst.node.FindChild("source-prefix"); spNode != nil {
pkg/config/compiler_security.go:720:			if dpNode := pfInst.node.FindChild("destination-prefix"); dpNode != nil {
pkg/config/compiler_security.go:732:	if dnsNode := node.FindChild("dns"); dnsNode != nil {
pkg/config/compiler_security.go:733:		if dnsNode.FindChild("disable") != nil {
pkg/config/compiler_security.go:737:	if ftpNode := node.FindChild("ftp"); ftpNode != nil {
pkg/config/compiler_security.go:738:		if ftpNode.FindChild("disable") != nil {
pkg/config/compiler_security.go:742:	if sipNode := node.FindChild("sip"); sipNode != nil {
pkg/config/compiler_security.go:743:		if sipNode.FindChild("disable") != nil {
pkg/config/compiler_security.go:747:	if tftpNode := node.FindChild("tftp"); tftpNode != nil {
pkg/config/compiler_security.go:748:		if tftpNode.FindChild("disable") != nil {
pkg/config/vrrp_track_test.go:486:// where only the SECOND is invalid must still strict-reject (FindChild
pkg/config/compiler_protocols.go:13:	raNode := node.FindChild("router-advertisement")
pkg/config/compiler_protocols.go:20:	lldpNode := node.FindChild("lldp")
pkg/config/compiler_protocols.go:28:					if child.FindChild("disable") != nil {
pkg/config/compiler_protocols.go:51:	ospfNode := node.FindChild("ospf")
pkg/config/compiler_protocols.go:77:		for _, areaInst := range namedInstances(ospfNode.FindChildren("area")) {
pkg/config/compiler_protocols.go:80:			for _, ifInst := range namedInstances(areaInst.node.FindChildren("interface")) {
pkg/config/compiler_protocols.go:140:			if atNode := areaInst.node.FindChild("area-type"); atNode != nil {
pkg/config/compiler_protocols.go:145:						if atChild.FindChild("no-summaries") != nil {
pkg/config/compiler_protocols.go:150:						if atChild.FindChild("no-summaries") != nil {
pkg/config/compiler_protocols.go:158:			for _, vlInst := range namedInstances(areaInst.node.FindChildren("virtual-link")) {
pkg/config/compiler_protocols.go:164:				if taNode := vlInst.node.FindChild("transit-area"); taNode != nil {
pkg/config/compiler_protocols.go:176:	bgpNode := node.FindChild("bgp")
pkg/config/compiler_protocols.go:247:		for _, groupInst := range namedInstances(bgpNode.FindChildren("group")) {
pkg/config/compiler_protocols.go:447:	ospf3Node := node.FindChild("ospf3")
pkg/config/compiler_protocols.go:464:		for _, areaInst := range namedInstances(ospf3Node.FindChildren("area")) {
pkg/config/compiler_protocols.go:467:			for _, ifInst := range namedInstances(areaInst.node.FindChildren("interface")) {
pkg/config/compiler_protocols.go:488:	ripNode := node.FindChild("rip")
pkg/config/compiler_protocols.go:530:	isisNode := node.FindChild("isis")
pkg/config/compiler_protocols.go:622:	for _, inst := range namedInstances(node.FindChildren("interface")) {
pkg/config/compiler_protocols.go:666:				if ltNode := prop.FindChild("lifetime"); ltNode != nil {
pkg/config/compiler_protocols.go:724:func namedInstances(nodes []*Node) []struct {
pkg/config/compiler_protocols.go:756:	unicast := famNode.FindChild("unicast")
pkg/config/compiler_protocols.go:760:	pl := unicast.FindChild("prefix-limit")
pkg/config/compiler_protocols.go:764:	mx := pl.FindChild("maximum")
pkg/config/schema_walk.go:159:		fcNode := node.FindChild("forwarding-classes")
pkg/config/schema_walk.go:163:		for _, queueNode := range fcNode.FindChildren("queue") {
pkg/config/schema_walk.go:185:				if cos := group.FindChild("class-of-service"); cos != nil {
pkg/config/compiler_firewall.go:20:	for _, polInst := range namedInstances(node.FindChildren("policer")) {
pkg/config/compiler_firewall.go:26:		ifExceeding := polInst.node.FindChild("if-exceeding")
pkg/config/compiler_firewall.go:42:		thenNode := polInst.node.FindChild("then")
pkg/config/compiler_firewall.go:57:		if polInst.node.FindChild("logical-interface-policer") != nil {
pkg/config/compiler_firewall.go:68:	for _, tcpInst := range namedInstances(node.FindChildren("three-color-policer")) {
pkg/config/compiler_firewall.go:78:		singleRates := tcpInst.node.FindChildren("single-rate")
pkg/config/compiler_firewall.go:84:			if sr.FindChild("color-blind") != nil {
pkg/config/compiler_firewall.go:88:			if sr.FindChild("color-aware") != nil {
pkg/config/compiler_firewall.go:109:		twoRates := tcpInst.node.FindChildren("two-rate")
pkg/config/compiler_firewall.go:115:			if tr.FindChild("color-blind") != nil {
pkg/config/compiler_firewall.go:119:			if tr.FindChild("color-aware") != nil {
pkg/config/compiler_firewall.go:144:		if thenNode := tcpInst.node.FindChild("then"); thenNode != nil {
pkg/config/compiler_firewall.go:158:	for _, familyNode := range node.FindChildren("family") {
pkg/config/compiler_firewall.go:187:			for _, filterInst := range namedInstances(afNode.FindChildren("filter")) {
pkg/config/compiler_firewall.go:190:				for _, termInst := range namedInstances(filterInst.node.FindChildren("term")) {
pkg/config/compiler_firewall.go:197:					fromNode := termInst.node.FindChild("from")
pkg/config/compiler_firewall.go:202:					thenNode := termInst.node.FindChild("then")
pkg/config/compiler_firewall.go:317:			for _, rangeInst := range namedInstances(child.FindChildren("range")) {
pkg/config/ast.go:77:// FindChild returns the first child whose first key matches name.
pkg/config/ast.go:78:func (n *Node) FindChild(name string) *Node {
pkg/config/ast.go:87:// FindChildren returns all children whose first key matches name.
pkg/config/ast.go:88:func (n *Node) FindChildren(name string) []*Node {
pkg/config/ast.go:103:// FindChild returns the first top-level child matching name.
pkg/config/ast.go:104:func (t *ConfigTree) FindChild(name string) *Node {
pkg/config/compiler.go:1484:	for _, inst := range namedInstances(node.FindChildren("application")) {
pkg/config/compiler.go:1537:	for _, inst := range namedInstances(node.FindChildren("application-set")) {
pkg/config/compiler.go:1726:func nodeVal(n *Node) string {
pkg/config/compiler_class_of_service.go:36:	if fcNode := node.FindChild("forwarding-classes"); fcNode != nil {
pkg/config/compiler_class_of_service.go:82:		for _, queueNode := range fcNode.FindChildren("queue") {
pkg/config/compiler_class_of_service.go:122:	if classifiersNode := node.FindChild("classifiers"); classifiersNode != nil {
pkg/config/compiler_class_of_service.go:123:		for _, inst := range namedInstances(classifiersNode.FindChildren("dscp")) {
pkg/config/compiler_class_of_service.go:125:			for _, fcNode := range inst.node.FindChildren("forwarding-class") {
pkg/config/compiler_class_of_service.go:133:				for _, lpNode := range fcNode.FindChildren("loss-priority") {
pkg/config/compiler_class_of_service.go:156:		for _, inst := range namedInstances(classifiersNode.FindChildren("ieee-802.1")) {
pkg/config/compiler_class_of_service.go:158:			for _, fcNode := range inst.node.FindChildren("forwarding-class") {
pkg/config/compiler_class_of_service.go:166:				for _, lpNode := range fcNode.FindChildren("loss-priority") {
pkg/config/compiler_class_of_service.go:191:	if rewriteRulesNode := node.FindChild("rewrite-rules"); rewriteRulesNode != nil {
pkg/config/compiler_class_of_service.go:192:		for _, inst := range namedInstances(rewriteRulesNode.FindChildren("dscp")) {
pkg/config/compiler_class_of_service.go:194:			for _, fcNode := range inst.node.FindChildren("forwarding-class") {
pkg/config/compiler_class_of_service.go:202:				for _, lpNode := range fcNode.FindChildren("loss-priority") {
pkg/config/compiler_class_of_service.go:227:	for _, inst := range namedInstances(node.FindChildren("schedulers")) {
pkg/config/compiler_class_of_service.go:271:	for _, inst := range namedInstances(node.FindChildren("scheduler-maps")) {
pkg/config/compiler_class_of_service.go:284:			} else if schedNode := child.FindChild("scheduler"); schedNode != nil {
pkg/config/compiler_class_of_service.go:295:	for _, inst := range namedInstances(node.FindChildren("interfaces")) {
pkg/config/compiler_class_of_service.go:300:		for _, unitNode := range inst.node.FindChildren("unit") {
pkg/config/compiler_class_of_service.go:309:			if shapingNode := unitNode.FindChild("shaping-rate"); shapingNode != nil {
pkg/config/compiler_class_of_service.go:313:				if burstNode := shapingNode.FindChild("burst-size"); burstNode != nil {
pkg/config/compiler_class_of_service.go:319:			if schedMapNode := unitNode.FindChild("scheduler-map"); schedMapNode != nil {
pkg/config/compiler_class_of_service.go:322:			if classifiersNode := unitNode.FindChild("classifiers"); classifiersNode != nil {
pkg/config/compiler_class_of_service.go:323:				if dscpNode := classifiersNode.FindChild("dscp"); dscpNode != nil {
pkg/config/compiler_class_of_service.go:326:				if ieeeNode := classifiersNode.FindChild("ieee-802.1"); ieeeNode != nil {
pkg/config/compiler_class_of_service.go:330:			if rewriteRulesNode := unitNode.FindChild("rewrite-rules"); rewriteRulesNode != nil {
pkg/config/compiler_class_of_service.go:331:				if dscpNode := rewriteRulesNode.FindChild("dscp"); dscpNode != nil {
pkg/config/compiler_class_of_service.go:343:			if oversubNode := unitNode.FindChild("oversubscription-policy"); oversubNode != nil {
pkg/config/compiler_class_of_service.go:360:				} else if grNode := oversubNode.FindChild("guarantee-rate"); grNode != nil {
pkg/config/compiler_class_of_service.go:379:				} else if oversubNode.FindChild("proportional") != nil {
pkg/config/compiler_class_of_service.go:386:			if minShareNode := unitNode.FindChild("priority-low-min-share"); minShareNode != nil {
pkg/config/compiler_class_of_service.go:403:	if fairnessNode := node.FindChild("fairness"); fairnessNode != nil {
pkg/config/compiler_class_of_service.go:404:		if rssNode := fairnessNode.FindChild("rss-expectation"); rssNode != nil {
pkg/config/compiler_class_of_service.go:406:			for _, ifindexNode := range rssNode.FindChildren("ifindex") {
pkg/config/compiler_class_of_service.go:414:				for _, queueNode := range ifindexNode.FindChildren("queue") {
pkg/config/compiler_class_of_service.go:469:		return set(kind, queueNode.FindChildren(kind), func(*Node) string { return kind })
pkg/config/compiler_class_of_service.go:474:			nodes = append(nodes, queueNode.FindChildren(name)...)
pkg/config/compiler_class_of_service.go:511:	if node.FindChild("exact") != nil {
pkg/config/compiler_class_of_service.go:529:	for _, child := range node.FindChildren("code-points") {
pkg/config/compiler_class_of_service.go:567:	for _, child := range node.FindChildren("code-points") {
pkg/config/compiler_class_of_service.go:587:	for _, child := range node.FindChildren("code-point") {
pkg/config/compiler_class_of_service.go:595:	for _, child := range node.FindChildren("code-points") {
pkg/config/compiler_routing.go:11:	if asNode := node.FindChild("autonomous-system"); asNode != nil {
pkg/config/compiler_routing.go:20:	if ftNode := node.FindChild("forwarding-table"); ftNode != nil {
pkg/config/compiler_routing.go:21:		if expNode := ftNode.FindChild("export"); expNode != nil {
pkg/config/compiler_routing.go:28:	for _, ribNode := range node.FindChildren("rib") {
pkg/config/compiler_routing.go:31:			if ribStatic := ribNode.FindChild("static"); ribStatic != nil {
pkg/config/compiler_routing.go:37:	staticNode := node.FindChild("static")
pkg/config/compiler_routing.go:43:	if rgNode := node.FindChild("rib-groups"); rgNode != nil {
pkg/config/compiler_routing.go:47:		for _, inst := range namedInstances(rgNode.FindChildren("")) {
pkg/config/compiler_routing.go:49:			if irNode := inst.node.FindChild("import-rib"); irNode != nil {
pkg/config/compiler_routing.go:70:			if irNode := child.FindChild("import-rib"); irNode != nil {
pkg/config/compiler_routing.go:86:	if genNode := node.FindChild("generate"); genNode != nil {
pkg/config/compiler_routing.go:87:		for _, routeNode := range genNode.FindChildren("route") {
pkg/config/compiler_routing.go:93:			if policyNode := routeNode.FindChild("policy"); policyNode != nil {
pkg/config/compiler_routing.go:96:			if routeNode.FindChild("discard") != nil {
pkg/config/compiler_routing.go:116:	if irNode := node.FindChild("interface-routes"); irNode != nil {
pkg/config/compiler_routing.go:117:		if rgNode := irNode.FindChild("rib-group"); rgNode != nil {
pkg/config/compiler_routing.go:150:	for _, routeInst := range namedInstances(staticNode.FindChildren("route")) {
pkg/config/compiler_routing.go:232:				if ifNode := prop.FindChild("interface"); ifNode != nil {
pkg/config/compiler_routing.go:307:				if irNode := prop.FindChild("interface-routes"); irNode != nil {
pkg/config/compiler_routing.go:308:					if rgNode := irNode.FindChild("rib-group"); rgNode != nil {
pkg/config/compiler_routing.go:358:	for _, inst := range namedInstances(node.FindChildren("prefix-list")) {
pkg/config/compiler_routing.go:369:	for _, inst := range namedInstances(node.FindChildren("community")) {
pkg/config/compiler_routing.go:392:	for _, child := range node.FindChildren("as-path") {
pkg/config/compiler_routing.go:414:	for _, inst := range namedInstances(node.FindChildren("policy-statement")) {
pkg/config/compiler_system.go:61:			for _, ntpChild := range child.FindChildren("server") {
pkg/config/compiler_system.go:66:			if thNode := child.FindChild("threshold"); thNode != nil {
pkg/config/compiler_system.go:77:				if actNode := thNode.FindChild("action"); actNode != nil {
pkg/config/compiler_system.go:83:			for _, userInst := range namedInstances(child.FindChildren("user")) {
pkg/config/compiler_system.go:121:			if dstNode := child.FindChild("destination"); dstNode != nil && len(dstNode.Keys) >= 2 {
pkg/config/compiler_system.go:130:			if child.FindChild("persist-groups-inheritance") != nil {
pkg/config/compiler_system.go:150:			if cfgNode := child.FindChild("configuration"); cfgNode != nil {
pkg/config/compiler_system.go:151:				if cfgNode.FindChild("transfer-on-commit") != nil {
pkg/config/compiler_system.go:154:				if tiNode := cfgNode.FindChild("transfer-interval"); tiNode != nil {
pkg/config/compiler_system.go:159:				for _, asNode := range cfgNode.FindChildren("archive-sites") {
pkg/config/compiler_system.go:193:							if site.FindChild("password") != nil {
pkg/config/compiler_system.go:210:			if prfNode := child.FindChild("pseudorandom-function"); prfNode != nil {
pkg/config/compiler_system.go:214:			if auNode := child.FindChild("autoupdate"); auNode != nil {
pkg/config/compiler_system.go:215:				if urlNode := auNode.FindChild("url"); urlNode != nil {
pkg/config/compiler_system.go:221:				if proc.FindChild("disable") != nil || nodeVal(proc) == "disable" {
pkg/config/compiler_system.go:227:			if child.FindChild("no-ipv6-reject-zero-hop-limit") != nil {
pkg/config/compiler_system.go:261:			for _, slInst := range namedInstances(child.FindChildren("host")) {
pkg/config/compiler_system.go:278:			for _, fileInst := range namedInstances(child.FindChildren("file")) {
pkg/config/compiler_system.go:289:			for _, userInst := range namedInstances(child.FindChildren("user")) {
pkg/config/compiler_system.go:302:	svcNode := node.FindChild("services")
pkg/config/compiler_system.go:304:		dhcpNode := svcNode.FindChild("dhcp-local-server")
pkg/config/compiler_system.go:310:		dhcp6Node := svcNode.FindChild("dhcpv6-local-server")
pkg/config/compiler_system.go:317:		if sshNode := svcNode.FindChild("ssh"); sshNode != nil {
pkg/config/compiler_system.go:322:			if rl := sshNode.FindChild("root-login"); rl != nil && len(rl.Keys) >= 2 {
pkg/config/compiler_system.go:327:		if dnsNode := svcNode.FindChild("dns"); dnsNode != nil {
pkg/config/compiler_system.go:337:		if wmNode := svcNode.FindChild("web-management"); wmNode != nil {
pkg/config/compiler_system.go:342:			if httpNode := wmNode.FindChild("http"); httpNode != nil {
pkg/config/compiler_system.go:344:				if ifNode := httpNode.FindChild("interface"); ifNode != nil {
pkg/config/compiler_system.go:348:			if httpsNode := wmNode.FindChild("https"); httpsNode != nil {
pkg/config/compiler_system.go:350:				if httpsNode.FindChild("system-generated-certificate") != nil {
pkg/config/compiler_system.go:353:				if ifNode := httpsNode.FindChild("interface"); ifNode != nil {
pkg/config/compiler_system.go:357:			if authNode := wmNode.FindChild("api-auth"); authNode != nil {
pkg/config/compiler_system.go:359:				for _, inst := range namedInstances(authNode.FindChildren("user")) {
pkg/config/compiler_system.go:360:					if pwNode := inst.node.FindChild("password"); pwNode != nil {
pkg/config/compiler_system.go:367:				for _, ch := range authNode.FindChildren("api-key") {
pkg/config/compiler_system.go:375:	snmpNode := node.FindChild("snmp")
pkg/config/compiler_system.go:759:	usmNode := node.FindChild("usm")
pkg/config/compiler_system.go:763:	engineNode := usmNode.FindChild("local-engine")
pkg/config/compiler_system.go:787:				if pw := prop.FindChild("authentication-password"); pw != nil {
pkg/config/compiler_system.go:792:				if pw := prop.FindChild("authentication-password"); pw != nil {
pkg/config/compiler_system.go:797:				if pw := prop.FindChild("authentication-password"); pw != nil {
pkg/config/compiler_system.go:802:				if pw := prop.FindChild("privacy-password"); pw != nil {
pkg/config/compiler_system.go:807:				if pw := prop.FindChild("privacy-password"); pw != nil {
pkg/config/compiler_system.go:856:	for _, inst := range namedInstances(node.FindChildren("scheduler")) {
pkg/config/compiler_system.go:880:	clusterNode := node.FindChild("cluster")
pkg/config/compiler_system.go:887:	if n := clusterNode.FindChild("cluster-id"); n != nil {
pkg/config/compiler_system.go:894:	if n := clusterNode.FindChild("node"); n != nil {
pkg/config/compiler_system.go:901:	if rcNode := clusterNode.FindChild("reth-count"); rcNode != nil {
pkg/config/compiler_system.go:908:	if n := clusterNode.FindChild("heartbeat-interval"); n != nil {
pkg/config/compiler_system.go:915:	if n := clusterNode.FindChild("heartbeat-threshold"); n != nil {
pkg/config/compiler_system.go:922:	if clusterNode.FindChild("control-link-recovery") != nil {
pkg/config/compiler_system.go:925:	if n := clusterNode.FindChild("control-interface"); n != nil {
pkg/config/compiler_system.go:930:	if n := clusterNode.FindChild("peer-address"); n != nil {
pkg/config/compiler_system.go:935:	if n := clusterNode.FindChild("fabric-interface"); n != nil {
pkg/config/compiler_system.go:940:	if n := clusterNode.FindChild("fabric-peer-address"); n != nil {
pkg/config/compiler_system.go:945:	if n := clusterNode.FindChild("fabric1-interface"); n != nil {
pkg/config/compiler_system.go:950:	if n := clusterNode.FindChild("fabric1-peer-address"); n != nil {
pkg/config/compiler_system.go:955:	if clusterNode.FindChild("configuration-synchronize") != nil {
pkg/config/compiler_system.go:958:	if clusterNode.FindChild("nat-state-synchronization") != nil {
pkg/config/compiler_system.go:961:	if clusterNode.FindChild("ipsec-session-synchronization") != nil {
pkg/config/compiler_system.go:964:	if n := clusterNode.FindChild("reth-advertise-interval"); n != nil {
pkg/config/compiler_system.go:971:	if clusterNode.FindChild("hitless-restart") != nil {
pkg/config/compiler_system.go:974:	if clusterNode.FindChild("no-reth-vrrp") != nil {
pkg/config/compiler_system.go:980:	if clusterNode.FindChild("no-private-rg-election") != nil {
pkg/config/compiler_system.go:983:	if n := clusterNode.FindChild("peer-fencing"); n != nil {
pkg/config/compiler_system.go:988:	if n := clusterNode.FindChild("takeover-hold-time"); n != nil {
pkg/config/compiler_system.go:996:	for _, rgInst := range namedInstances(clusterNode.FindChildren("redundancy-group")) {
pkg/config/compiler_system.go:1025:				if priNode := child.FindChild("priority"); priNode != nil {
pkg/config/compiler_system.go:1055:					if wNode := ifChild.FindChild("weight"); wNode != nil {
pkg/config/compiler_system.go:1066:				if gwNode := child.FindChild("global-weight"); gwNode != nil {
pkg/config/compiler_system.go:1073:				if gtNode := child.FindChild("global-threshold"); gtNode != nil {
pkg/config/compiler_system.go:1089:						inetNode = familyNode.FindChild("inet")
pkg/config/compiler_system.go:1106:						if wNode := addrChild.FindChild("weight"); wNode != nil {
pkg/config/compiler_ipsec.go:20:	for _, inst := range namedInstances(node.FindChildren("proposal")) {
pkg/config/compiler_ipsec.go:47:	for _, inst := range namedInstances(node.FindChildren("policy")) {
pkg/config/compiler_ipsec.go:73:	for _, inst := range namedInstances(node.FindChildren("gateway")) {
pkg/config/compiler_ipsec.go:197:	for _, inst := range namedInstances(node.FindChildren("proposal")) {
pkg/config/compiler_ipsec.go:222:	for _, inst := range namedInstances(node.FindChildren("policy")) {
pkg/config/compiler_ipsec.go:247:	for _, inst := range namedInstances(node.FindChildren("gateway")) {
pkg/config/compiler_ipsec.go:327:	for _, inst := range namedInstances(node.FindChildren("vpn")) {
pkg/config/compiler_ipsec.go:363:		for _, tsInst := range namedInstances(inst.node.FindChildren("traffic-selector")) {
pkg/config/compiler_services.go:124:	for _, groupInst := range namedInstances(node.FindChildren("group")) {
pkg/config/compiler_services.go:184:	for _, inst := range namedInstances(node.FindChildren("feed-server")) {
pkg/config/compiler_services.go:224:	for _, inst := range namedInstances(node.FindChildren("address-name")) {
pkg/config/compiler_services.go:226:		if profile := inst.node.FindChild("profile"); profile != nil {
pkg/config/compiler_services.go:242:	if fmNode := node.FindChild("flow-monitoring"); fmNode != nil {
pkg/config/compiler_services.go:247:	if rpmNode := node.FindChild("rpm"); rpmNode != nil {
pkg/config/compiler_services.go:252:	if ipmNode := node.FindChild("ip-monitoring"); ipmNode != nil {
pkg/config/compiler_services.go:257:	if node.FindChild("application-identification") != nil {
pkg/config/compiler_services.go:270:	for _, polInst := range namedInstances(node.FindChildren("policy")) {
pkg/config/compiler_services.go:282:				if c := prop.FindChild("rpm-probe"); c != nil {
pkg/config/compiler_services.go:288:				for _, prNode := range prop.FindChildren("preferred-route") {
pkg/config/compiler_services.go:292:					for _, riInst := range namedInstances(prNode.FindChildren("routing-instance")) {
pkg/config/compiler_services.go:324:	for _, rInst := range namedInstances(node.FindChildren("route")) {
pkg/config/compiler_services.go:525:	if probeLimitNode := node.FindChild("probe-limit"); probeLimitNode != nil {
pkg/config/compiler_services.go:535:	for _, probeInst := range namedInstances(node.FindChildren("probe")) {
pkg/config/compiler_services.go:541:		for _, testInst := range namedInstances(probeInst.node.FindChildren("test")) {
pkg/config/compiler_services.go:555:					} else if urlChild := prop.FindChild("url"); urlChild != nil {
pkg/config/compiler_services.go:557:					} else if addrChild := prop.FindChild("address"); addrChild != nil {
pkg/config/compiler_services.go:646:	if v9Node := node.FindChild("version9"); v9Node != nil {
pkg/config/compiler_services.go:650:		for _, tmplInst := range namedInstances(v9Node.FindChildren("template")) {
pkg/config/compiler_services.go:672:					if secNode := prop.FindChild("seconds"); secNode != nil {
pkg/config/compiler_services.go:688:	if ipfixNode := node.FindChild("version-ipfix"); ipfixNode != nil {
pkg/config/compiler_services.go:692:		for _, tmplInst := range namedInstances(ipfixNode.FindChildren("template")) {
pkg/config/compiler_services.go:714:					if secNode := prop.FindChild("seconds"); secNode != nil {
pkg/config/compiler_services.go:735:	sampNode := node.FindChild("sampling")
pkg/config/compiler_services.go:742:	relayNode := node.FindChild("dhcp-relay")
pkg/config/compiler_services.go:750:	if famNode := node.FindChild("family"); famNode != nil {
pkg/config/compiler_services.go:751:		if inet6Node := famNode.FindChild("inet6"); inet6Node != nil {
pkg/config/compiler_services.go:752:			if modeNode := inet6Node.FindChild("mode"); modeNode != nil {
pkg/config/compiler_services.go:758:	if pmNode := node.FindChild("port-mirroring"); pmNode != nil {
pkg/config/compiler_services.go:772:	for _, inst := range namedInstances(node.FindChildren("instance")) {
pkg/config/compiler_services.go:775:		if inputNode := inst.node.FindChild("input"); inputNode != nil {
pkg/config/compiler_services.go:776:			if rateNode := inputNode.FindChild("rate"); rateNode != nil {
pkg/config/compiler_services.go:783:			if ingressNode := inputNode.FindChild("ingress"); ingressNode != nil {
pkg/config/compiler_services.go:794:		if outputNode := inst.node.FindChild("output"); outputNode != nil {
pkg/config/compiler_services.go:795:			if ifNode := outputNode.FindChild("interface"); ifNode != nil {
pkg/config/compiler_services.go:812:	for _, sampInst := range namedInstances(node.FindChildren("instance")) {
pkg/config/compiler_services.go:815:		inputNode := sampInst.node.FindChild("input")
pkg/config/compiler_services.go:828:		for _, familyNode := range sampInst.node.FindChildren("family") {
pkg/config/compiler_services.go:861:	outputNode := node.FindChild("output")
pkg/config/compiler_services.go:888:						if tmplNode := prop.FindChild("template"); tmplNode != nil {
pkg/config/compiler_services.go:904:			if saNode := child.FindChild("source-address"); saNode != nil {
pkg/config/compiler_services.go:925:	for _, sgInst := range namedInstances(node.FindChildren("server-group")) {
pkg/config/compiler_services.go:943:	for _, gInst := range namedInstances(node.FindChildren("group")) {
pkg/config/compiler_services.go:999:	for _, pInst := range namedInstances(node.FindChildren("policy")) {
pkg/config/compiler_services.go:1024:				if trigNode := child.FindChild("trigger"); trigNode != nil {
pkg/config/compiler_services.go:1039:					if onNode := trigNode.FindChild("on"); onNode != nil {
pkg/config/compiler_services.go:1046:					if untilNode := trigNode.FindChild("until"); untilNode != nil {
pkg/config/compiler_services.go:1062:				if ccNode := child.FindChild("change-configuration"); ccNode != nil {
pkg/config/compiler_services.go:1063:					if cmdsNode := ccNode.FindChild("commands"); cmdsNode != nil {
pkg/config/compiler_services.go:1089:		for _, vlanNode := range child.FindChildren("vlan-id-list") {
pkg/config/compiler_services.go:1105:		if riNode := child.FindChild("routing-interface"); riNode != nil {
pkg/config/compiler_services.go:1110:		if dtNode := child.FindChild("domain-type"); dtNode != nil {

codex
I also found the existing generic `${node}` fallback test: `CompileConfig` succeeds with only `groups node0` and warns that it defaulted to node0. A mandatory node1 speculative expansion would break that unless the plan defines how expansion errors are treated.
exec
/bin/bash -lc "nl -ba pkg/config/compiler_protocols.go | sed -n '724,750p'" in /home/ps/git/bpfrx/.claude/worktrees/1914-research-tunnel-collision
 succeeded in 0ms:
   724	func namedInstances(nodes []*Node) []struct {
   725		name string
   726		node *Node
   727	} {
   728		var result []struct {
   729			name string
   730			node *Node
   731		}
   732		for _, child := range nodes {
   733			if len(child.Keys) >= 2 {
   734				result = append(result, struct {
   735					name string
   736					node *Node
   737				}{child.Keys[1], child})
   738			} else {
   739				for _, sub := range child.Children {
   740					result = append(result, struct {
   741						name string
   742						node *Node
   743					}{sub.Name(), sub})
   744				}
   745			}
   746		}
   747		return result
   748	}
   749	
   750	// nodeVal returns the value for a property node, handling both AST shapes.

exec
/bin/bash -lc "nl -ba pkg/configstore/store.go | sed -n '500,545p'" in /home/ps/git/bpfrx/.claude/worktrees/1914-research-tunnel-collision
 succeeded in 0ms:
   500	}
   501	
   502	func schemaValidateExpandedTreeForNode(tree *config.ConfigTree, nodeID int) error {
   503		if tree == nil {
   504			return nil
   505		}
   506		expanded := tree.Clone()
   507		if nodeID >= 0 {
   508			vars := map[string]string{"node": fmt.Sprintf("node%d", nodeID)}
   509			if err := expanded.ExpandGroupsWithVars(vars); err != nil {
   510				return fmt.Errorf("apply-groups: %w", err)
   511			}
   512			// Pass the PRE-expansion candidate as the cross-reference
   513			// definitions source: expansion removes the groups stanza, and
   514			// definitions living only in un-applied peer-node groups must
   515			// keep satisfying shared-section references (#1319 PR 3).
   516			return config.SchemaValidateWithDefinitions(expanded, tree, nil)
   517		}
   518		if err := expanded.ExpandGroups(); err != nil {
   519			if strings.Contains(err.Error(), `undefined group "${node}"`) {
   520				vars := map[string]string{"node": "node0"}
   521				if err2 := expanded.ExpandGroupsWithVars(vars); err2 != nil {
   522					return fmt.Errorf("apply-groups: %w", err2)
   523				}
   524			} else {
   525				return fmt.Errorf("apply-groups: %w", err)
   526			}
   527		}
   528		return config.SchemaValidateWithDefinitions(expanded, tree, nil)
   529	}
   530	
   531	// SyncApply applies a config received from the cluster primary.
   532	// Bypasses cluster read-only checks. The chassisPreserve function, if set,
   533	// lets the caller patch the parsed tree before compiling (e.g. to preserve
   534	// local chassis cluster settings).
   535	func (s *Store) SyncApply(content string, chassisPreserve func(*config.ConfigTree)) (*config.Config, error) {
   536		s.mu.Lock()
   537		defer s.mu.Unlock()
   538	
   539		tree, errs := config.NewParser(content).Parse()
   540		if len(errs) > 0 {
   541			return nil, fmt.Errorf("sync config parse error: %v", errs[0])
   542		}
   543	
   544		// Let caller patch the tree (e.g. preserve local chassis cluster settings).
   545		if chassisPreserve != nil {

exec
/bin/bash -lc "rg -n \"GOCACHE|go test|GOFLAGS\" Makefile go.mod .github scripts -g'*'" in /home/ps/git/bpfrx/.claude/worktrees/1914-research-tunnel-collision
 exited 1 in 0ms:
codex
PLAN-NEEDS-REVISION

1. **High — The proposed builder reuse path would hide the collision it is supposed to detect.**  
   Evidence: plan.md:153-155 proposes `CompileConfig*` -> `buildTunnelEndpointSnapshots` -> read names. But `CompileConfig` / `CompileConfigForNode` call `validateTunnelEndpointIDCollisionAST` first at `pkg/config/compiler.go:109-117` and `:173-178`, so calling them from the gate recurses. Worse, `buildTunnelEndpointSnapshots` drops the later collider via `usedIDs` at `pkg/dataplane/userspace/tunnels.go:100-105`; reading back emitted snapshots would see only one of `wg1408.0` / `wg78.0`, so Defect A can still false-ACCEPT.  
   Fix: factor a `pkg/config` helper that returns pre-`usedIDs` endpoint candidates from typed config. Builder applies runtime interface filtering and `usedIDs` after that. Gate hashes all candidates before any drop.

2. **High — O1 is not resolved; the recommended view-1 narrowing changes the #1873 group-union invariant.**  
   Evidence: current collector registers any tunnel-node presence at `pkg/config/tunnelid.go:73-74` and unit refs at `:120-123`; builder drops incomplete non-WG at `pkg/dataplane/userspace/tunnels.go:61-64`. Keeping presence-only gives a false reject:
   ```text
   set groups latent interfaces wg1408 unit 0 tunnel mode gre
   set interfaces wg78 unit 0 tunnel mode wireguard
   ```
   No group is applied, so builder emits only `wg78.0`, but view 1 registers `wg1408.0`; both fold to 824.

   Narrowing view 1 to complete-only can under-register latent group composition:
   ```text
   set groups src interfaces wg1408 unit 0 tunnel source 10.0.0.1
   set groups dst interfaces wg1408 unit 0 tunnel destination 10.0.0.2
   set groups latent interfaces wg1408 apply-groups [ src dst ]
   set groups latent interfaces wg1408 unit 0 tunnel mode gre
   set interfaces wg78 unit 0 tunnel mode wireguard
   ```
   If `latent` were applied, expansion can supply src/dst through nested `apply-groups`; wildcard/group expansion is handled recursively at `pkg/config/ast_groups.go:149-159` and `:206-215`. With no top-level application, views 2/3 do not see it, and narrowed raw view 1 drops all three partial groups.  
   Fix: explicitly choose the invariant. Either keep view 1 presence-only and document the residual false rejects, or define a separate latent-group analysis. Do not claim both “B fixed” and “un-applied group coverage preserved” without specifying this.

3. **Medium — Speculative node-view error handling is undefined and can break existing fallback behavior.**  
   Evidence: generic `CompileConfig` falls back to node0 for undefined `"${node}"` at `pkg/config/compiler.go:127-134`; `TestCompileConfigForNodeBackwardCompat` expects this at `pkg/config/parser_ast_test.go:3953-3980`. Path 1 unconditionally adds node0 and node1 expansion views at plan.md:282-285. A config with only `groups node0` and `apply-groups "${node}"` makes the node1 speculative view fail.  
   Fix: pass compile mode/node scope into the gate, and specify whether speculative node-view expansion errors are fatal, skipped, or downgraded. Cluster strict mode may reasonably reject both; generic mode must preserve the existing node0 fallback.

4. **Medium — Package direction is sound, but the SSOT boundary must be sharper.**  
   Evidence: userspace already imports config at `pkg/dataplane/userspace/tunnels.go:10`; config must not import userspace, so a config-package emitter avoids a cycle. But `buildTunnelEndpointSnapshots` also depends on live `InterfaceSnapshot` rows and drops missing interfaces at `pkg/dataplane/userspace/tunnels.go:13` and `:65-68`; that is not config-pure.  
   Fix: emitter should be `config`-only and return candidate names/tunnels from `*config.Config`. Runtime snapshot enrichment stays in userspace.

5. **Info — The HA-symmetry claim is conditionally correct.**  
   Evidence: `ExpandGroupsWithVars` is driven by explicit vars at `pkg/config/ast_groups.go:23-28`; compile entrypoints clone before expansion at `pkg/config/compiler.go:121-123` and `:182-185`; wildcard merge is deterministic over existing destination containers at `pkg/config/ast_groups.go:235-244`. I do not see a node0/node1 divergence if both nodes compute the same fixed `{pre,node0,node1}` views from the same candidate and handle errors identically.

Cost is acceptable; mutation is not the blocker because `Clone()` is deep at `pkg/config/ast.go:113-140`. The blockers are pre-belt candidate enumeration, recursion avoidance, and explicit O1/error semantics.
tokens used
108,314
PLAN-NEEDS-REVISION

1. **High — The proposed builder reuse path would hide the collision it is supposed to detect.**  
   Evidence: plan.md:153-155 proposes `CompileConfig*` -> `buildTunnelEndpointSnapshots` -> read names. But `CompileConfig` / `CompileConfigForNode` call `validateTunnelEndpointIDCollisionAST` first at `pkg/config/compiler.go:109-117` and `:173-178`, so calling them from the gate recurses. Worse, `buildTunnelEndpointSnapshots` drops the later collider via `usedIDs` at `pkg/dataplane/userspace/tunnels.go:100-105`; reading back emitted snapshots would see only one of `wg1408.0` / `wg78.0`, so Defect A can still false-ACCEPT.  
   Fix: factor a `pkg/config` helper that returns pre-`usedIDs` endpoint candidates from typed config. Builder applies runtime interface filtering and `usedIDs` after that. Gate hashes all candidates before any drop.

2. **High — O1 is not resolved; the recommended view-1 narrowing changes the #1873 group-union invariant.**  
   Evidence: current collector registers any tunnel-node presence at `pkg/config/tunnelid.go:73-74` and unit refs at `:120-123`; builder drops incomplete non-WG at `pkg/dataplane/userspace/tunnels.go:61-64`. Keeping presence-only gives a false reject:
   ```text
   set groups latent interfaces wg1408 unit 0 tunnel mode gre
   set interfaces wg78 unit 0 tunnel mode wireguard
   ```
   No group is applied, so builder emits only `wg78.0`, but view 1 registers `wg1408.0`; both fold to 824.

   Narrowing view 1 to complete-only can under-register latent group composition:
   ```text
   set groups src interfaces wg1408 unit 0 tunnel source 10.0.0.1
   set groups dst interfaces wg1408 unit 0 tunnel destination 10.0.0.2
   set groups latent interfaces wg1408 apply-groups [ src dst ]
   set groups latent interfaces wg1408 unit 0 tunnel mode gre
   set interfaces wg78 unit 0 tunnel mode wireguard
   ```
   If `latent` were applied, expansion can supply src/dst through nested `apply-groups`; wildcard/group expansion is handled recursively at `pkg/config/ast_groups.go:149-159` and `:206-215`. With no top-level application, views 2/3 do not see it, and narrowed raw view 1 drops all three partial groups.  
   Fix: explicitly choose the invariant. Either keep view 1 presence-only and document the residual false rejects, or define a separate latent-group analysis. Do not claim both “B fixed” and “un-applied group coverage preserved” without specifying this.

3. **Medium — Speculative node-view error handling is undefined and can break existing fallback behavior.**  
   Evidence: generic `CompileConfig` falls back to node0 for undefined `"${node}"` at `pkg/config/compiler.go:127-134`; `TestCompileConfigForNodeBackwardCompat` expects this at `pkg/config/parser_ast_test.go:3953-3980`. Path 1 unconditionally adds node0 and node1 expansion views at plan.md:282-285. A config with only `groups node0` and `apply-groups "${node}"` makes the node1 speculative view fail.  
   Fix: pass compile mode/node scope into the gate, and specify whether speculative node-view expansion errors are fatal, skipped, or downgraded. Cluster strict mode may reasonably reject both; generic mode must preserve the existing node0 fallback.

4. **Medium — Package direction is sound, but the SSOT boundary must be sharper.**  
   Evidence: userspace already imports config at `pkg/dataplane/userspace/tunnels.go:10`; config must not import userspace, so a config-package emitter avoids a cycle. But `buildTunnelEndpointSnapshots` also depends on live `InterfaceSnapshot` rows and drops missing interfaces at `pkg/dataplane/userspace/tunnels.go:13` and `:65-68`; that is not config-pure.  
   Fix: emitter should be `config`-only and return candidate names/tunnels from `*config.Config`. Runtime snapshot enrichment stays in userspace.

5. **Info — The HA-symmetry claim is conditionally correct.**  
   Evidence: `ExpandGroupsWithVars` is driven by explicit vars at `pkg/config/ast_groups.go:23-28`; compile entrypoints clone before expansion at `pkg/config/compiler.go:121-123` and `:182-185`; wildcard merge is deterministic over existing destination containers at `pkg/config/ast_groups.go:235-244`. I do not see a node0/node1 divergence if both nodes compute the same fixed `{pre,node0,node1}` views from the same candidate and handle errors identically.

Cost is acceptable; mutation is not the blocker because `Clone()` is deep at `pkg/config/ast.go:113-140`. The blockers are pre-belt candidate enumeration, recursion avoidance, and explicit O1/error semantics.
