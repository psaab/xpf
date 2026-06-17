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
session id: 019ed5a0-f5cf-7331-b1d4-608b7fb08a75
--------
user
FINAL round (r3) on issue #1914. You reviewed r1 and r2. In r2 you returned PLAN-NEEDS-REVISION with TWO precision bugs: F1(High) "Defect B fixed for applied-group cases" is false — view 1 includes every group with no src/dst check so an applied incomplete GRE (gr-0/0/0.0/wg29715.0 both fold 44687) still false-rejects, so Defect B is document-only ENTIRELY; F2(Medium) the emitter must return {Name, *TunnelConfig} not bare names because the builder needs the TunnelConfig for snapshot fields. You confirmed r1's F1(recursion)/F3(error)/F4(boundary)/O1(symmetry) were all resolved.

The plan is revised to r3. Read docs/research/1914-tunnel-endpoint-collision-gate/plan.md (repo /home/ps/git/bpfrx/.claude/worktrees/1914-research-tunnel-collision, branch research/1914-tunnel-endpoint-collision-gate). Verify your r2 F1 and F2 are now correctly stated:
1. §3.5-O1, §3.5-O4, the Path-1 summary (§3), and §6.4 — do they now consistently say Defect B is document-only for ALL cases (main/applied/un-applied), and does §6.4 pin the residual as INTENTIONAL (config still rejects) rather than asserting it must NOT reject?
2. §4.1 — does the emitter now return {Name, *TunnelConfig} and explain the builder needs the TunnelConfig?
3. Re-confirm nothing in r3 regressed the already-resolved items (recursion-free compileInterfaces path, error->empty-set per-node, config-pure emitter, HA symmetry, frozen fold untouched).

This is /research. Output PLAN-READY if the plan is now internally consistent and sound with no remaining fatal/precision issue, else PLAN-NEEDS-REVISION with quoted file:line. Do not require written production code.

codex
I’ll inspect the r3 plan in place and check the specific sections against the two r2 findings plus the previously resolved invariants.
exec
/bin/bash -lc "nl -ba docs/research/1914-tunnel-endpoint-collision-gate/plan.md | sed -n '1,260p'" in /home/ps/git/bpfrx/.claude/worktrees/1914-research-tunnel-collision
 succeeded in 0ms:
     1	# Plan of Action — #1914: tunnel-endpoint collision gate, wildcard apply-groups false accept + src/dst-incomplete over-registration
     2	
     3	- **Issue:** #1914
     4	- **Mode:** `/research` — STOP at PLAN-READY. No PR, no production code.
     5	- **Revision:** r3 (r2 corrected after Codex r2 caught two precision bugs:
     6	  Defect B is NOT fixed by an unchanged view 1 even for applied groups — it
     7	  is document-only entirely; and the SSOT emitter must return `{Name,
     8	  *TunnelConfig}` not bare names so the builder can populate snapshot fields)
     9	- **Branch:** `research/1914-tunnel-endpoint-collision-gate`
    10	- **Base:** `origin/master` @ `26e4a112d`
    11	- **Author:** Claude (research driver)
    12	
    13	---
    14	
    15	## 1. Problem statement
    16	
    17	`validateTunnelEndpointIDCollisionAST` (`pkg/config/tunnelid.go:162`) is the
    18	#1873 R-B commit-time gate that fails a commit when two tunnel-endpoint
    19	interface names fold to the same 16-bit `StableTunnelEndpointID`. It runs
    20	on the **pre-expansion** AST (before `ExpandGroups`) by design: it collects
    21	the **union** of tunnel names from `interfaces` and every `groups` block so
    22	both HA nodes accept/reject identically (pre-expansion union is a pure
    23	function of the candidate config, so node0 and node1 compute the same
    24	verdict regardless of which `${node}`-scoped group each would actually
    25	apply).
    26	
    27	Two defects, both **pre-existing since #1873 R-B landed** (PR #1882) and
    28	neither widened nor narrowed by PR #1910/#1904. Found by Codex r6 during
    29	PR #1910 review.
    30	
    31	### 1.1 Defect A — wildcard apply-groups false accept (High)
    32	
    33	`collectTunnelEndpointNamesAST` hashes the **literal** group-AST interface
    34	name. A wildcard group:
    35	
    36	```
    37	set groups wgtun interfaces <*> unit 0 tunnel mode wireguard
    38	set interfaces wg78   apply-groups wgtun
    39	set interfaces wg1408 unit 0 tunnel mode wireguard
    40	```
    41	
    42	registers the gate ref `<*>.0` (id **50477**), never the concrete
    43	post-expansion `wg78.0` (id **824**). The literal `wg1408.0` registers id
    44	**824**. The gate sees `{<*>.0=50477, wg1408.0=824}` — no collision —
    45	and **accepts the commit**. But `ExpandGroups`' wildcard merge
    46	(`mergeNodes`, `ast_groups.go:236`) splices the `unit 0 tunnel mode
    47	wireguard` body onto the **existing** `wg78` interface container, so the
    48	typed compiler emits `wg78.0` AND `wg1408.0`, **both fold to 824**. The
    49	snapshot builder's `usedIDs` belt (`tunnels.go:101`) then drops the
    50	later-sorting one with a loud `slog.Error` — a deterministic runtime drop
    51	instead of a commit rejection.
    52	
    53	**Confirmed empirically** (this research, throwaway test against master):
    54	the above three-line config compiles clean with zero warnings; both
    55	`wg78.unit0` and `wg1408.unit0` carry wireguard `TunnelConfig` in the typed
    56	`cfg.Interfaces.Interfaces` map. Folds verified live: `<*>.0`=50477,
    57	`wg78.0`=`wg1408.0`=824.
    58	
    59	**Severity rationale:** a real builder-emitted collision escapes the
    60	strict commit gate. The runtime belt keeps both nodes consistent (same
    61	deterministic drop), so it is not a split-brain / TCP-death class bug — it
    62	is a "loud silent" drop: one tunnel never installs and the operator only
    63	learns from `slog.Error`, not a commit error. Wildcard WG groups are rare;
    64	the per-pair fold-collision probability is 1/65535.
    65	
    66	### 1.2 Defect B — src/dst-incomplete non-WG tunnels over-registered (Medium)
    67	
    68	`collectTunnelEndpointNamesAST` registers a ref from **tunnel-node
    69	presence alone**. But the builder's `addEndpoint` (`tunnels.go:62`) drops
    70	any **non-WireGuard** tunnel whose `Source` or `Destination` is empty:
    71	
    72	```go
    73	if !isWireguard && (tunnel.Source == "" || tunnel.Destination == "") {
    74	    return
    75	}
    76	```
    77	
    78	So a half-configured GRE (`set interfaces gr-0/0/0 unit 0 tunnel mode
    79	gre`, no source/dest) registers a gate ref the builder will never emit.
    80	**Confirmed empirically:** the gate registers `gr-0/0/0.0` for exactly
    81	this shape. If that phantom ref collides (1/65535 per pair) with a *real*
    82	emitted ref, the commit is **falsely rejected** — the operator cannot
    83	commit a config the builder would have accepted.
    84	
    85	**Why it is conservative-by-design today:** AST-level src/dst presence
    86	cannot be judged reliably pre-expansion, because apply-groups can SUPPLY
    87	the source/destination later. A pre-expansion collector that modeled the
    88	src/dst gate would **under-register** (false ACCEPT — strictly worse than a
    89	false REJECT). So the current over-register is the safe direction given
    90	the pre-expansion constraint. Item B is only fully fixable if the collector
    91	sees an expanded view (couples to Defect A's fix).
    92	
    93	---
    94	
    95	## 2. Current behavior walk (code-grounded)
    96	
    97	| Layer | Function | File:line | Sees groups? | src/dst gate? | wildcard? |
    98	|-------|----------|-----------|--------------|---------------|-----------|
    99	| Commit gate | `validateTunnelEndpointIDCollisionAST` | `tunnelid.go:162` | union, **pre-expansion** | no | hashes `<*>` literally |
   100	| Gate collector | `collectTunnelEndpointNamesAST` | `tunnelid.go:61` | per-block | no (presence-only) | literal name |
   101	| Hash | `StableTunnelEndpointID` | `tunnelid.go:25` | — | — | — |
   102	| Expansion | `ExpandGroups` / `mergeNodes` | `ast_groups.go:13,225` | resolves | — | wildcard merges onto **existing** dst ifaces only |
   103	| Builder | `buildTunnelEndpointSnapshots` / `addEndpoint` | `tunnels.go:13,54` | **post-expansion typed cfg** | **yes** (drops incomplete non-WG) | n/a (concrete names) |
   104	| Runtime belt | `usedIDs` map | `tunnels.go:101` | — | — | deterministic later-sorting drop + `slog.Error` |
   105	
   106	**Key asymmetry:** the gate runs on pre-expansion union AST; the builder
   107	runs on the post-expansion **typed** `cfg.Interfaces.Interfaces`. The gate
   108	therefore cannot see (a) wildcard-expanded concrete names, nor (b)
   109	group-supplied source/destination. The builder sees both but only fails
   110	"loudly silent" via the belt.
   111	
   112	**Important wildcard semantics fact** (proven by reading `mergeNodes`,
   113	`ast_groups.go:236-245`): a wildcard apply-group merges its body onto
   114	interface containers **already present** in the dst tree — it does NOT
   115	synthesize new interfaces. So the post-expansion concrete name set is
   116	exactly `{ interfaces that (a) exist in the candidate AND (b) reference the
   117	wildcard group via apply-groups }`. This bounds the cardinality and makes
   118	post-expansion enumeration tractable.
   119	
   120	**HA-symmetry invariant (the thing #1873 chose pre-expansion to protect):**
   121	the accept/reject verdict must be a pure function of the candidate config
   122	(identical bytes on both nodes ⇒ identical verdict), so config-sync never
   123	splits (originator accepts, peer rejects). Any fix MUST preserve this. A
   124	naive "expand for *this* node then collect" breaks it, because `${node}`
   125	resolves differently on node0 vs node1.
   126	
   127	---
   128	
   129	## 3. Design space — Multiple Path Options
   130	
   131	This is a **design-decision** issue (the issue body says so). Four viable
   132	paths, with the HA-symmetry invariant as the hard constraint.
   133	
   134	### Path 1 — Union of {pre-expansion} ∪ {post-expansion node0} ∪ {post-expansion node1}, all computed from the same candidate tree (RECOMMENDED)
   135	
   136	Collect gate names from THREE views, all derived from the SAME candidate
   137	AST on both nodes:
   138	
   139	1. the existing pre-expansion union (unchanged — preserves the
   140	   group-scoped-collision coverage that
   141	   `TestTunnelEndpointIDCollisionAcrossGroupsIsSymmetric` pins), PLUS
   142	2. the concrete tunnel names the builder would emit after expanding for
   143	   node0, PLUS
   144	3. the concrete tunnel names the builder would emit after expanding for
   145	   node1.
   146	
   147	Because (2) and (3) are *both* computed on *both* nodes from the *same*
   148	candidate config, the union is still a pure function of config ⇒ still
   149	symmetric. node0 expanding "what would node1 see" is deterministic (it is
   150	just `ExpandGroupsWithVars(node1)` on the shared candidate). The gate
   151	rejects if ANY of the three views contains a fold collision.
   152	
   153	Because (2) and (3) are *both* computed on *both* nodes from the *same*
   154	candidate config, the union is still a pure function of config ⇒ still
   155	symmetric. The realization is the SSOT emitter in §4.1 (a recursion-free,
   156	config-pure, pre-`usedIDs` helper), NOT a re-call of `CompileConfig*` (that
   157	recurses — see §3.5-O2). See §4 for the full reconciled shape.
   158	
   159	- **Defect A:** FIXED — post-expansion views contain the concrete `wg78.0`,
   160	  collision with `wg1408.0` (824) detected → commit rejected.
   161	- **Defect B:** NOT fixed — document-only (see §3.5-O1/O4). View 1 stays
   162	  presence-only (required so the Defect-A fix does not re-open a
   163	  false-accept), so the incomplete-non-WG phantom persists for all cases.
   164	- **HA-symmetry:** PRESERVED — all three views are pure functions of the
   165	  shared candidate config; both nodes compute the identical union (with
   166	  identical per-node-expansion-error→empty-set handling, §4.3).
   167	- **Complexity:** Medium. SSOT emitter + two extra clone+`compileInterfaces`
   168	  passes per commit (not hot-path; `Clone()` is deep so no mutation).
   169	- **Risk:** view 1 MUST stay byte-identical, or an un-applied-group
   170	  cross-node collision (the `TestTunnelEndpointIDCollisionAcrossGroupsIsSymmetric`
   171	  guarantee) stops being caught, AND narrowing it to src/dst-aware
   172	  re-opens a false-accept (split-supply / un-applied nested-apply-groups —
   173	  proven in §3.5-O1). The union is monotone over view 1 (adding views 2/3
   174	  only ADDS rejects), so the existing reject set is strictly preserved.
   175	
   176	### Path 2 — Expand wildcards inside the collision pass only
   177	
   178	Keep the gate pre-expansion but teach `collectTunnelEndpointNamesAST` to
   179	resolve `<*>` group refs against the set of interfaces that apply that
   180	group, producing concrete names — a narrow, gate-local mini-expander.
   181	
   182	- **Defect A:** FIXED for the wildcard case.
   183	- **Defect B:** NOT fixed (still presence-only).
   184	- **HA-symmetry:** PRESERVED if the mini-expander is a pure function of the
   185	  candidate (it is).
   186	- **Complexity:** Medium, but introduces a SECOND expansion implementation
   187	  that must track `mergeNodes` wildcard semantics forever (drift risk —
   188	  exactly the class of bug #1910 r2-r6 kept finding when the gate's unit
   189	  logic drifted from the builder's). **Anti-pattern per the repo's own
   190	  history.** Rejected unless Path 1's cost is prohibitive.
   191	
   192	### Path 3 — Gate only complete src+dst tunnels (Defect B narrow fix)
   193	
   194	For non-WG tunnels, register a gate ref only when source AND destination
   195	are present in the AST (mirror the builder's gate).
   196	
   197	- **Defect A:** NOT fixed.
   198	- **Defect B:** PARTIALLY fixed — but pre-expansion it cannot see
   199	  group-supplied src/dst, so it would UNDER-register (false ACCEPT) when a
   200	  group supplies the missing endpoint. The issue body explicitly calls this
   201	  out as "worse than" the current over-register. Rejected as a standalone
   202	  fix.
   203	
   204	### Path 4 — Accept as documented limitation (do nothing structural)
   205	
   206	Document both gaps in `tunnelid.go` + an operator doc, lean on the runtime
   207	`usedIDs` belt + `slog.Error`, and add a metric/log so the silent drop is
   208	observable. Optionally add a `commit` warning that says "wildcard
   209	apply-groups tunnel refs are not collision-checked at commit; a collision
   210	will be dropped at runtime."
   211	
   212	- **Defect A:** UNFIXED, documented.
   213	- **Defect B:** UNFIXED, documented.
   214	- **HA-symmetry:** trivially preserved (no change).
   215	- **Complexity:** Trivial. Honest about the 1/65535 × rare-feature joint
   216	  probability.
   217	- **Risk:** leaves a real (if rare) false-accept. Acceptable ONLY if the
   218	  reviewers judge the joint probability (wildcard WG group × 16-bit fold
   219	  collision) negligible and the runtime belt sufficient.
   220	
   221	---
   222	
   223	## 3.5 Resolved design questions (after r1 three-way review)
   224	
   225	All four r1 reviewers (Claude SMR + Codex + AGY) converged on the answers
   226	below; they are now design decisions, not open questions.
   227	
   228	- **O1 (crux) — RESOLVED: view 1 stays byte-identical (presence-only
   229	  union).** Both the "narrow view 1 to complete-only" and "make view 1
   230	  src/dst-aware" ideas are provably unsound:
   231	  - Split-supply (Claude SMR, proven): `set interfaces gr-0/0/9 unit 0
   232	    tunnel mode gre` with src/dst supplied by an applied group → a
   233	    complete-only pre-expansion view 1 UNDER-registers (the literal AST has
   234	    no src/dst), missing a real emitted ref.
   235	  - Un-applied nested-apply-groups group (AGY F3 + Codex F2, proven shape):
   236	    `groups group-c interfaces gr-0/0/0 unit 0 {tunnel mode gre;
   237	    apply-groups my-group}` where `my-group` supplies src/dst, `group-c`
   238	    un-applied → a complete-only view 1 drops `gr-0/0/0.0`, views 2/3 never
   239	    expand the un-applied group, the ref is registered NOWHERE → **false
   240	    ACCEPT**, violating the #1873 group-symmetry invariant.
   241	
   242	  Therefore view 1 MUST remain the existing presence-only union, AND
   243	  because view 1 includes EVERY group (applied or not — `tunnelid.go:165`)
   244	  and registers tunnel presence with no src/dst check (`tunnelid.go:73,120`),
   245	  **Defect B is NOT fixed by this design at all — it is document-only,
   246	  entirely** (Codex r2 F1). Concrete proof (verified): `set groups g
   247	  interfaces gr-0/0/0 unit 0 tunnel mode gre` + `set apply-groups g` + `set
   248	  interfaces wg29715 unit 0 tunnel mode wireguard` — `gr-0/0/0.0` and
   249	  `wg29715.0` both fold to 44687; view 1 registers the incomplete-GRE
   250	  phantom even though it is APPLIED, the builder drops it (`tunnels.go:61`),
   251	  and the union still false-REJECTS. Views 2/3 correctly exclude it, but
   252	  view 1's union with them cannot un-register what view 1 added. So the
   253	  earlier r2 claim "Defect B fixed for applied-group cases" was WRONG.
   254	  Defect B's phantom false-reject (any config — main, applied group, or
   255	  un-applied group — with an incomplete non-WG tunnel that folds onto a
   256	  real ref) is accepted as a documented limitation (Path 4 for B), backed
   257	  by the runtime belt. Fixing it would require narrowing view 1, which
   258	  provably re-opens a false-ACCEPT (above) — strictly worse.
   259	- **O2 — RESOLVED: NO double-`CompileConfig`.** Reading back
   260	  `buildTunnelEndpointSnapshots` is WRONG for two independent reasons the

exec
/bin/bash -lc "pwd && git branch --show-current && git rev-parse --short HEAD && rg -n \"3\\.5-O1|3\\.5-O4|Path 1|Path-1|Defect B|6\\.4|4\\.1|Name, \\*TunnelConfig|TunnelConfig|compileInterfaces|recursion|empty-set|per-node|config-pure|symmetry|fold\" docs/research/1914-tunnel-endpoint-collision-gate/plan.md" in /home/ps/git/bpfrx/.claude/worktrees/1914-research-tunnel-collision
exec
/bin/bash -lc "nl -ba docs/research/1914-tunnel-endpoint-collision-gate/plan.md | sed -n '260,620p'" in /home/ps/git/bpfrx/.claude/worktrees/1914-research-tunnel-collision
 succeeded in 0ms:
/home/ps/git/bpfrx/.claude/worktrees/1914-research-tunnel-collision
research/1914-tunnel-endpoint-collision-gate
65bfcec5a
6:  Defect B is NOT fixed by an unchanged view 1 even for applied groups — it
8:  *TunnelConfig}` not bare names so the builder can populate snapshot fields)
19:interface names fold to the same 16-bit `StableTunnelEndpointID`. It runs
48:typed compiler emits `wg78.0` AND `wg1408.0`, **both fold to 824**. The
55:`wg78.unit0` and `wg1408.unit0` carry wireguard `TunnelConfig` in the typed
64:the per-pair fold-collision probability is 1/65535.
66:### 1.2 Defect B — src/dst-incomplete non-WG tunnels over-registered (Medium)
106:**Key asymmetry:** the gate runs on pre-expansion union AST; the builder
120:**HA-symmetry invariant (the thing #1873 chose pre-expansion to protect):**
132:paths, with the HA-symmetry invariant as the hard constraint.
134:### Path 1 — Union of {pre-expansion} ∪ {post-expansion node0} ∪ {post-expansion node1}, all computed from the same candidate tree (RECOMMENDED)
151:rejects if ANY of the three views contains a fold collision.
155:symmetric. The realization is the SSOT emitter in §4.1 (a recursion-free,
156:config-pure, pre-`usedIDs` helper), NOT a re-call of `CompileConfig*` (that
161:- **Defect B:** NOT fixed — document-only (see §3.5-O1/O4). View 1 stays
164:- **HA-symmetry:** PRESERVED — all three views are pure functions of the
166:  identical per-node-expansion-error→empty-set handling, §4.3).
167:- **Complexity:** Medium. SSOT emitter + two extra clone+`compileInterfaces`
173:  proven in §3.5-O1). The union is monotone over view 1 (adding views 2/3
183:- **Defect B:** NOT fixed (still presence-only).
184:- **HA-symmetry:** PRESERVED if the mini-expander is a pure function of the
190:  history.** Rejected unless Path 1's cost is prohibitive.
192:### Path 3 — Gate only complete src+dst tunnels (Defect B narrow fix)
198:- **Defect B:** PARTIALLY fixed — but pre-expansion it cannot see
213:- **Defect B:** UNFIXED, documented.
214:- **HA-symmetry:** trivially preserved (no change).
218:  reviewers judge the joint probability (wildcard WG group × 16-bit fold
240:    ACCEPT**, violating the #1873 group-symmetry invariant.
245:  **Defect B is NOT fixed by this design at all — it is document-only,
249:  `wg29715.0` both fold to 44687; view 1 registers the incomplete-GRE
253:  earlier r2 claim "Defect B fixed for applied-group cases" was WRONG.
254:  Defect B's phantom false-reject (any config — main, applied group, or
255:  un-applied group — with an incomplete non-WG tunnel that folds onto a
267:  candidate names BEFORE any `usedIDs` drop, via a recursion-free path
269:- **O3 — RESOLVED: yes, factor an SSOT emitter, config-pure.** The emitter
279:- **O4 — RESOLVED: Defect B is document-only, entirely** (corrected after
285:  non-WG tunnel whose unit-ref folds onto a real emitted ref (1/65535 per
294:**Path 1 for Defect A** (the High false accept) via a recursion-free,
295:pre-`usedIDs` three-view union; **Defect B is document-only, entirely**
297:it is mutually exclusive with the Defect-A fix, see §3.5-O1/O4). Concrete,
300:### 4.1 SSOT emitter (config-pure, pre-`usedIDs`, returns Name+Tunnel)
304:builder would emit — each as a `{Name string, Tunnel *config.TunnelConfig}`
305:pair (Codex r2 F2: the builder needs the matching `*TunnelConfig` to
314:already resolved by `compileInterfaces` when it builds the int-keyed
327:### 4.2 Gate computes a recursion-free three-view union
333:  Preserves the #1873 un-applied cross-node symmetry guarantee
337:  `ExpandGroupsWithVars({node:node0})` → `compileInterfaces` (the
340:  `EmitTunnelEndpointNames`. **Never calls `CompileConfig*`** → no recursion
345:Union = V1 ∪ V2 ∪ V3. Reject (strict) / warn (lenient) on any fold
346:collision in the union. The fold and severity split are unchanged.
357:separate, already-handled condition on the real per-node compile path —
364:compute identical V1∪V2∪V3 and apply identical error-to-empty-set
365:handling), so HA symmetry holds (Codex Info F5: confirmed no node0/node1
372:- `pkg/config/tunnelid.go` — gate gains views 2/3 (clone+expand+`compileInterfaces`+emitter
383:  parity. All existing folds (`824`, `14730`, `17799`, `50477`) stay frozen.
386:- Commit-path only (not hot-path). Two extra clone+expand+`compileInterfaces`
395:   tests, including the frozen-fold pins and the group-symmetry test.
399:3. **Defect A symmetry:** the wildcard config must reject identically under
401:4. **Defect B (document-only — pin CURRENT behavior):** a half-configured
402:   non-WG tunnel (no src/dst) whose unit-ref folds onto a real emitted ref
413:7. **No-recursion regression:** a test that the gate on a wildcard/multi-node
414:   config returns in bounded time (guards against the Finding-2 recursion
423:code), but a `make test` + a manual two-node commit-symmetry check on the
429:fold is untouched so no node renumbering on rollback.
433:The whole point of the design is HA symmetry. The recommended Path 1 keeps
452:only) acceptable ONLY for Defect B's residual, not for the High Defect A.
467:Codex r2 confirmed the r2 design core (recursion-free path, error-handling,
468:boundary, O1 symmetry, Defect-A fix) but caught two precision bugs in the
471:- **Defect B is document-only, ENTIRELY** (not "fixed for applied-group
473:  incomplete GRE (`gr-0/0/0.0`/`wg29715.0` both fold 44687) still
474:  false-rejects. r3 §3.5-O1/O4 + §4 + §6.4 corrected; §6.4 now pins the
476:- **SSOT emitter returns `{Name, *TunnelConfig}`** (not bare names) — the
477:  builder needs the TunnelConfig to populate snapshot fields. r3 §4.1.
486:  recursion + the `usedIDs` belt already dropped one collider. r2 §4.1/4.2
487:  fix: config-pure pre-`usedIDs` emitter + gate-free `compileInterfaces`.
490:  proven shapes). r2 §3.5-O1 + §4.2 fix: view 1 stays presence-only;
493:  `${node}` group must not fail the gate. r2 §4.3 fix: error→empty-set.
494:- **Emitter is config-pure, not snapshot-identical (Codex F4, AGY F4):**
495:  builder intersects runtime ifaces after the emitter. r2 §4.1 states the

 succeeded in 0ms:
   260	  `buildTunnelEndpointSnapshots` is WRONG for two independent reasons the
   261	  reviewers proved: (a) `CompileConfig*` call the gate FIRST
   262	  (`compiler.go:115-119`, `:176-180`) → calling them from the gate
   263	  **recurses to stack overflow** (AGY F2 Critical, Codex F1); (b) the
   264	  builder's `usedIDs` belt (`tunnels.go:100-105`) has ALREADY DROPPED one
   265	  of the colliding pair, so the gate would see only one ref and Defect A
   266	  would STILL false-accept (Codex F1 High). The gate must enumerate
   267	  candidate names BEFORE any `usedIDs` drop, via a recursion-free path
   268	  (§4).
   269	- **O3 — RESOLVED: yes, factor an SSOT emitter, config-pure.** The emitter
   270	  lives in `pkg/config` (no import cycle — `pkg/dataplane/userspace`
   271	  already imports `pkg/config`). It returns the **configured** candidate
   272	  endpoint-name set from a typed `*config.Config`; it does NOT see runtime
   273	  `InterfaceSnapshot` rows (those don't exist at commit). The builder
   274	  consumes the emitter and THEN intersects with runtime ifaces + applies
   275	  `usedIDs` (AGY F4, Codex F4). The emitter is the SSOT for NAME emission
   276	  only; runtime filtering stays in the builder. Mandatory: the builder is
   277	  refactored to call the emitter (not a parallel copy) + a differential
   278	  parity test guards drift (the #1910 r2-r6 drift class).
   279	- **O4 — RESOLVED: Defect B is document-only, entirely** (corrected after
   280	  Codex r2 F1). Because view 1 stays unchanged (required to fix Defect A
   281	  without re-opening a false-accept, see O1), the incomplete-non-WG phantom
   282	  false-reject persists for ALL cases — main config, applied group, AND
   283	  un-applied group. Fixing it is mutually exclusive with the Defect-A fix
   284	  under the pre-expansion-union design. The residual requires an incomplete
   285	  non-WG tunnel whose unit-ref folds onto a real emitted ref (1/65535 per
   286	  pair) — a rare, operator-visible-at-runtime (`slog.Error` belt) condition.
   287	  Accepted + documented; the remediation is the same "rename one interface"
   288	  the error already prints.
   289	
   290	---
   291	
   292	## 4. Recommended approach (RECONCILED with r1 three-way review)
   293	
   294	**Path 1 for Defect A** (the High false accept) via a recursion-free,
   295	pre-`usedIDs` three-view union; **Defect B is document-only, entirely**
   296	(view 1 stays unchanged, so the incomplete-non-WG phantom persists — fixing
   297	it is mutually exclusive with the Defect-A fix, see §3.5-O1/O4). Concrete,
   298	reviewer-corrected shape:
   299	
   300	### 4.1 SSOT emitter (config-pure, pre-`usedIDs`, returns Name+Tunnel)
   301	
   302	Add a `pkg/config` emitter that, given a typed, already-expanded
   303	`*config.Config`, returns the exact set of CONFIGURED tunnel endpoints the
   304	builder would emit — each as a `{Name string, Tunnel *config.TunnelConfig}`
   305	pair (Codex r2 F2: the builder needs the matching `*TunnelConfig` to
   306	populate snapshot fields at `tunnels.go:106-129`, so a names-only return is
   307	insufficient). The emitter applies the same non-WG src/dst gate (drop if
   308	src or dst empty, `tunnels.go:61`), the same WG single-lowest-unit pick
   309	(`tunnels.go:148-170`), and the same `%s.%d` canonical formatting. It does
   310	**NOT** apply the `usedIDs` collision drop and does **NOT** consult runtime
   311	`InterfaceSnapshot` rows (AGY F4, Codex F4 — those don't exist at commit).
   312	
   313	Note: the leading-zero / overflow / last-wins unit canonicalization is
   314	already resolved by `compileInterfaces` when it builds the int-keyed
   315	`Units` map, so the emitter inherits it for free and does NOT re-implement
   316	the AST-level logic the gate's view-1 collector carries.
   317	
   318	`buildTunnelEndpointSnapshots` is refactored to call the emitter for its
   319	`{Name, Tunnel}` set, then intersect with runtime `ifaceByName`, then apply
   320	`usedIDs`. One emission truth; runtime filtering + drop stay in the builder.
   321	The gate (views 2/3) uses only the `Name` field of the emitter output. A
   322	differential parity test (`tunnelid_test.go`) asserts the emitter's
   323	`{Name,Tunnel}` set == the builder's configured set (pre runtime-intersect,
   324	pre `usedIDs`) over a tunnel-config corpus (kills the #1910 r2-r6 drift
   325	class).
   326	
   327	### 4.2 Gate computes a recursion-free three-view union
   328	
   329	`validateTunnelEndpointIDCollisionAST` builds:
   330	
   331	- **View 1 — pre-expansion presence union (UNCHANGED).** Exactly today's
   332	  `collectTunnelEndpointNamesAST` over `interfaces` ∪ every `groups` block.
   333	  Preserves the #1873 un-applied cross-node symmetry guarantee
   334	  (`TestTunnelEndpointIDCollisionAcrossGroupsIsSymmetric`). Keeps its
   335	  Defect-B over-registration (accepted residual).
   336	- **View 2 — post-expansion node0 emitted names.** `tree.Clone()` →
   337	  `ExpandGroupsWithVars({node:node0})` → `compileInterfaces` (the
   338	  gate-free interfaces sub-compiler, `compiler_interfaces.go:25`, which does
   339	  NOT call the collision gate) into a throwaway `InterfacesConfig` →
   340	  `EmitTunnelEndpointNames`. **Never calls `CompileConfig*`** → no recursion
   341	  (AGY F2, Codex F1).
   342	- **View 3 — post-expansion node1 emitted names.** Same, with
   343	  `{node:node1}`.
   344	
   345	Union = V1 ∪ V2 ∪ V3. Reject (strict) / warn (lenient) on any fold
   346	collision in the union. The fold and severity split are unchanged.
   347	
   348	### 4.3 Per-node expansion errors are NON-FATAL (Claude SMR F2, Codex F3, AGY F1)
   349	
   350	If `ExpandGroupsWithVars({node:nodeN})` fails (e.g. config defines only
   351	`groups node0` and references `${node}`, so the node1 expansion hits
   352	`undefined group "node1"` — `ast_groups.go:163-167`), that node's view
   353	contributes the **empty set** to the union; it MUST NOT become the gate's
   354	verdict. Rationale: the existing generic `CompileConfig` already falls back
   355	to node0 for undefined `${node}` (`compiler.go:127-134`,
   356	`TestCompileConfigForNodeBackwardCompat`), and an undefined peer group is a
   357	separate, already-handled condition on the real per-node compile path —
   358	the collision gate must not turn it into a spurious commit failure for a
   359	config valid on the local node. View 1 still covers any collision in the
   360	un-expandable group (presence union), so dropping the failed node's view
   361	loses no real coverage.
   362	
   363	This keeps the verdict a pure function of the candidate config (both nodes
   364	compute identical V1∪V2∪V3 and apply identical error-to-empty-set
   365	handling), so HA symmetry holds (Codex Info F5: confirmed no node0/node1
   366	divergence under this construction).
   367	
   368	---
   369	
   370	## 5. Blast radius
   371	
   372	- `pkg/config/tunnelid.go` — gate gains views 2/3 (clone+expand+`compileInterfaces`+emitter
   373	  per node, non-fatal on expansion error) + the new `EmitTunnelEndpointNames`
   374	  SSOT emitter. View 1 collector UNCHANGED. ~120 LOC.
   375	- `pkg/dataplane/userspace/tunnels.go` — `buildTunnelEndpointSnapshots`
   376	  refactored to source its configured-name set from `EmitTunnelEndpointNames`,
   377	  then intersect runtime ifaces + apply `usedIDs` (no change to the emitted
   378	  snapshot rows — parity-tested).
   379	- `pkg/config/tunnelid_test.go` — existing 13 tests are the regression
   380	  contract (all stay green); ADD: wildcard-false-accept rejects (strict) /
   381	  warns (lenient) / symmetric across nodes; un-applied-`${node}`-group does
   382	  NOT spuriously fail (Finding-2 regression); emitter↔builder differential
   383	  parity. All existing folds (`824`, `14730`, `17799`, `50477`) stay frozen.
   384	- No wire/protocol change. No HA sync-protocol change (`StableTunnelEndpointID`
   385	  MUST stay byte-frozen, #1873).
   386	- Commit-path only (not hot-path). Two extra clone+expand+`compileInterfaces`
   387	  passes per commit/commit-check; `Clone()` is a deep copy
   388	  (`ast.go:113-140`, Codex F-cost) so the candidate is never mutated.
   389	
   390	---
   391	
   392	## 6. Test plan
   393	
   394	1. **Regression (must stay green):** all 13 existing `tunnelid_test.go`
   395	   tests, including the frozen-fold pins and the group-symmetry test.
   396	2. **Defect A:** the §1.1 three-line wildcard config must now FAIL strict
   397	   commit with a `wg78.0`/`wg1408.0` + `824` + `collision` + `rename`
   398	   error; must WARN (not error) on the lenient path.
   399	3. **Defect A symmetry:** the wildcard config must reject identically under
   400	   `CompileConfigForNode(tree, 0)` and `CompileConfigForNode(tree, 1)`.
   401	4. **Defect B (document-only — pin CURRENT behavior):** a half-configured
   402	   non-WG tunnel (no src/dst) whose unit-ref folds onto a real emitted ref
   403	   STILL rejects (the accepted residual; view 1 unchanged). This test pins
   404	   the limitation so a future reader knows it is intentional, not a bug;
   405	   the doc comment + `slog.Error` belt are the operator's recourse. A
   406	   COMPLETE GRE that genuinely collides must of course still reject.
   407	5. **No false positives:** the existing non-colliding multi-tunnel config
   408	   stays clean; a WG wildcard group applied to a single interface (no
   409	   second colliding ref) compiles clean.
   410	6. **SSOT parity:** a differential test asserting `EmitTunnelEndpointNames(cfg)`
   411	   equals the builder's configured-name set (before runtime-iface intersect
   412	   + `usedIDs`) for a corpus of tunnel configs (the anti-drift guard, O3).
   413	7. **No-recursion regression:** a test that the gate on a wildcard/multi-node
   414	   config returns in bounded time (guards against the Finding-2 recursion
   415	   if a future edit reintroduces a `CompileConfig*` call from the gate).
   416	8. **Non-fatal peer-group:** `groups node0 ... ; apply-groups "${node}"`
   417	   with NO `groups node1` must COMMIT cleanly (view 3 contributes empty,
   418	   not an error) — the Finding-2/Codex-F3/AGY-F1 regression.
   419	9. `make test` for `pkg/config` + `pkg/dataplane/userspace`.
   420	
   421	No cluster smoke needed at /research time. At /engineer time: a failover
   422	smoke is NOT required (commit-path-only change, no dataplane/VRRP/sync
   423	code), but a `make test` + a manual two-node commit-symmetry check on the
   424	loss cluster confirms the gate rejects identically.
   425	
   426	## 7. Rollback
   427	
   428	Pure revert — single PR, no migration, no persisted-state change. The id
   429	fold is untouched so no node renumbering on rollback.
   430	
   431	## 8. HA / cluster considerations
   432	
   433	The whole point of the design is HA symmetry. The recommended Path 1 keeps
   434	the verdict a pure function of the candidate config. `StableTunnelEndpointID`
   435	is byte-frozen and untouched — no `SessionValue.FibGen` wire change, no
   436	cross-node renumbering. The new logic adds expand-for-node0 + expand-for-node1
   437	passes that BOTH run on BOTH nodes, so the union is identical everywhere.
   438	
   439	## 9. Observability / docs
   440	
   441	- Keep the runtime `usedIDs` `slog.Error` belt (defense in depth even after
   442	  the gate closes A).
   443	- Update the doc comments on `validateTunnelEndpointIDCollisionAST` and
   444	  `collectTunnelEndpointNamesAST` to describe the three-view union.
   445	- If Path 4 is chosen for B, add an operator note that incomplete non-WG
   446	  tunnels are conservatively registered.
   447	
   448	## 10. Alternatives considered (summary)
   449	
   450	See §3. Path 2 (gate-local mini-expander) rejected for drift risk; Path 3
   451	(complete-only, standalone) rejected for under-register; Path 4 (document
   452	only) acceptable ONLY for Defect B's residual, not for the High Defect A.
   453	
   454	## 11. Reviewer convergence ledger
   455	
   456	See `reviewer-ids.md`. Target: 3-way PLAN-READY (Claude SMR + Codex + AGY)
   457	on the final rev. Round verdicts recorded per round below.
   458	
   459	| Round | Claude SMR | Codex | AGY |
   460	|-------|-----------|-------|-----|
   461	| r1 | PLAN-NEEDS-REVISION | PLAN-NEEDS-REVISION | PLAN-NEEDS-REVISION |
   462	| r2 | PLAN-READY | PLAN-NEEDS-REVISION (2 precision bugs) | pending |
   463	| r3 | pending | pending | pending |
   464	
   465	### r2 → r3 correction (Codex r2)
   466	
   467	Codex r2 confirmed the r2 design core (recursion-free path, error-handling,
   468	boundary, O1 symmetry, Defect-A fix) but caught two precision bugs in the
   469	plan TEXT, both verified against the code:
   470	
   471	- **Defect B is document-only, ENTIRELY** (not "fixed for applied-group
   472	  cases"). View 1 includes every group with no src/dst check, so an APPLIED
   473	  incomplete GRE (`gr-0/0/0.0`/`wg29715.0` both fold 44687) still
   474	  false-rejects. r3 §3.5-O1/O4 + §4 + §6.4 corrected; §6.4 now pins the
   475	  residual as intentional.
   476	- **SSOT emitter returns `{Name, *TunnelConfig}`** (not bare names) — the
   477	  builder needs the TunnelConfig to populate snapshot fields. r3 §4.1.
   478	
   479	### r1 convergence summary
   480	
   481	All three reviewers independently converged on the same core defects in r1
   482	(strong signal the diagnosis was right and the recommended fix was wrong):
   483	
   484	- **Recursion + pre-drop enumeration (Codex F1 High, AGY F2 Critical):**
   485	  the gate cannot reuse `CompileConfig*`/`buildTunnelEndpointSnapshots` —
   486	  recursion + the `usedIDs` belt already dropped one collider. r2 §4.1/4.2
   487	  fix: config-pure pre-`usedIDs` emitter + gate-free `compileInterfaces`.
   488	- **O1 crux (all three):** view 1 cannot be narrowed without re-opening a
   489	  false-accept (split-supply + un-applied nested-apply-groups, both with
   490	  proven shapes). r2 §3.5-O1 + §4.2 fix: view 1 stays presence-only;
   491	  Defect-B residual documented.
   492	- **Peer-group expansion error (SMR F2, Codex F3, AGY F1):** undefined
   493	  `${node}` group must not fail the gate. r2 §4.3 fix: error→empty-set.
   494	- **Emitter is config-pure, not snapshot-identical (Codex F4, AGY F4):**
   495	  builder intersects runtime ifaces after the emitter. r2 §4.1 states the
   496	  boundary.

codex
PLAN-READY

r3 correctly fixes both r2 precision bugs.

Defect B is now consistently document-only for main, applied, and un-applied cases: see lines 161-163, 242-258, 279-288, 294-297, and 401-405. §6.4 explicitly pins the current false-reject as intentional: “STILL rejects”.

§4.1 now returns `{Name string, Tunnel *config.TunnelConfig}` and states the builder needs `*TunnelConfig` for snapshot fields at lines 302-320.

No regression found in the previously resolved items: recursion-free `compileInterfaces` path, per-node expansion error to empty-set, config-pure emitter boundary, HA symmetry, and frozen fold unchanged are all still stated correctly.
tokens used
19,240
PLAN-READY

r3 correctly fixes both r2 precision bugs.

Defect B is now consistently document-only for main, applied, and un-applied cases: see lines 161-163, 242-258, 279-288, 294-297, and 401-405. §6.4 explicitly pins the current false-reject as intentional: “STILL rejects”.

§4.1 now returns `{Name string, Tunnel *config.TunnelConfig}` and states the builder needs `*TunnelConfig` for snapshot fields at lines 302-320.

No regression found in the previously resolved items: recursion-free `compileInterfaces` path, per-node expansion error to empty-set, config-pure emitter boundary, HA symmetry, and frozen fold unchanged are all still stated correctly.
