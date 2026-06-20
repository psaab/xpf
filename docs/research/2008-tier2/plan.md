# #2008 Tier-2 parity gaps — research + recommended Increment-2

Companion-free `/research` for the **Tier-2** rows of the #2008 parity triage
(`docs/research/2008-parity-triage/triage.md`): **M1, M5, M6, M7, H13**. The
triage classified these as "needs `/research` first" (vs the six Increment-1
quick wins, which have already shipped — see below). This doc per-gap-researches
each, source-verified against `origin/master` HEAD `28f71b4ec`, and recommends
an **Increment-2** ship list with explicit decisions for the large/lab items.

> No production source touched. No Codex/AGY. STOP at this doc + the hostile
> Claude-SMR self-review (`claude-smr-r1.md`).

## Baseline / what already shipped (subtracted, source-verified)

Increment-1 + H1 are merged on master — confirmed by `git log` and grep:

| Item | Evidence on master |
|---|---|
| H1 `inactive:` | `Node.Inactive` + `WithoutInactive` strip (shipped pre-triage, PR #2042) |
| M4 policy-stats gate | `908e874c2 #2008 M4: gate policy-stats counter collection on the config knob` |
| H14 power-mode-disable | `f5ae96fa3 ... thread power-mode-disable into FlowSnapshot (Go + Rust)`; `forwarding_build/mod.rs:178 state.power_mode_disable = snapshot.flow.power_mode_disable` |
| M9 tcp-session no-sequence-check | `8c2a0c3c8 #2008 M9: add security flow tcp-session no-sequence-check` |
| H6 login class enum | `8f6f4ccf3 #2008 H6: enum-validate system login class at commit` |
| M8 traceopt packet-filter protocol | `c51b0c96f config,logging: trace packet-filter protocol match (M8, #2008)` |
| H5 ssh key-exchange | `b48ff2a93 config,daemon: ssh key-exchange → sshd KexAlgorithms (H5, #2008)` |

All five Tier-2 gaps below are confirmed **still un-shipped** on master (grep
citations in each section).

> Important re-scoping note that the triage's per-row sketches predate: several
> issue-body line citations (`publish_conntrack.rs:105`, `policy.rs:569`,
> `xdp_policy.c:resolve_pkt_app_id`) point at the **legacy eBPF path that was
> deleted in #1476**. The real residuals live in the **userspace** dataplane.
> Each section below re-grounds the gap on current userspace source.

---

## M5 — application-identification: app_id never stamped on userspace sessions

**Junos feature.** `services application-identification` plus the `applications`
catalog give each session an identified application (`app_id` → name), surfaced
in `show security flow session` and usable downstream (dynamic-application
policy, AppTrack). The L7 DPI engine is explicitly out of scope (#653,
`docs/services-application-identification.md`); the in-scope piece is the
**L3/L4 catalog classification**: stamp the matched catalog `app_id` on the
session so `show` resolves a real name instead of a port guess.

**Exact xpf gap (source-verified, master).**

- The Go control plane *builds* the catalog: `pkg/dataplane/compiler.go:526-545`
  populates `AppNames map[uint16]string` (app_id → name).
- `show` paths already *consume* a per-session app_id:
  `pkg/grpcapi/server_sessions.go:149,195,602,625` and `server_show_flow.go`
  call `appid.ResolveSessionName(appNames, cfg, proto, dstPort, val.AppID)`.
- **But the userspace dataplane never assigns app_id.** It is hardcoded:
  `userspace-dp/src/afxdp/bpf_map/publish_conntrack.rs:175` and `:277`
  (`app_id: 0`) for both v4 and v6 session publishes.
- **And the catalog is never shipped to Rust.** `grep -r AppNames|app_catalog`
  in `userspace-dp/` and `pkg/dataplane/userspace/` returns nothing. The
  userspace policy engine has `CompiledApplications` (`policy.rs:288-349`) but
  it is a **boolean** matcher ("does this 5-tuple match the policy's
  application set?") — it carries no per-app numeric id.

Net effect: end-to-end the AppID chain is dead in the userspace path —
`val.AppID` is always 0, so every session resolves to a built-in port guess
(AppID disabled) or `UNKNOWN` (AppID enabled). The `AppNames` map, the
`ResolveSessionName` plumbing, and the catalog compile are present but inert.
`docs/feature-gaps.md:71` overstates ("real runtime AppID plumbing for L3/L4
application catalog classification") relative to what the userspace path
actually does — that doc line is stale and should be corrected as part of M5.

**Affected packages.** `pkg/dataplane/userspace/protocol.go` (new wire field:
catalog snapshot), `pkg/dataplane/compiler.go` / `apply.go` (already have
`AppNames`; emit a catalog snapshot), `userspace-dp/src/protocol/*` (decode
catalog), `userspace-dp/src/policy.rs` (catalog → app_id lookup), the
session-create path that calls `publish_v4_session`/`publish_v6_session`
(`userspace-dp/src/afxdp/bpf_map/mod.rs:225-290`) to thread the resolved
`app_id` into `publish_conntrack.rs` instead of `0`. Plus the HA session-sync
value already carries app_id (`mod.rs:159,206 app_id: u16`), so no wire-format
change there.

**Design approach.**
1. Ship the catalog to the userspace dp as an ordered list of
   `(protocol, dst_port_low, dst_port_high, src_port_low, src_port_high) → app_id`
   (the same shape the legacy `applications`/`app_ranges` BPF maps had, per
   `docs/services-application-identification.md:39-49`). Carry it in the
   security/policy snapshot.
2. In the session-create path, resolve the app_id (exact-port set first, then
   range scan — mirror `CompiledApplications::matches` but return the id, not a
   bool) and thread it into `publish_v4_session`/`publish_v6_session`.
3. Both directions of a session must resolve to the **same** app_id (service
   port is dst on forward, src on reverse) — same symmetry the H3/H4 alg_type
   work already handles; reuse that on-port logic shape.
4. Correct `docs/feature-gaps.md:71` and `docs/services-application-identification.md`
   to describe the *userspace* path (the existing doc describes the deleted
   eBPF `xdp_policy.c` path).

**Effort: M.** Multi-file Go→Rust thread + a new snapshot field + a
session-create lookup. No new subsystem; the consumer (`ResolveSessionName`)
already exists. This is the classic "stored-but-never-enforced" pattern and is
self-contained, but it is **not** a single-leaf quick win — it spans the wire
protocol and the Rust session-create hot path.

**Value: corr (feature fidelity).** Today `show ... session` lies about the
application on the userspace dataplane. Security value is indirect (no policy
currently matches on app_id), so this is correctness/observability, not a
security primitive.

**Disposition: feasible-increment (medium).** Recommended as the headline
Increment-2 item: it lights up an already-built, already-consumed plumbing
chain that is currently 100% dead, and it's bounded (no L7 DPI). Ship as one PR
with a mutation-verify Rust test (drop the lookup → app_id regresses to 0) plus
a Go round-trip test for the new catalog wire field.

---

## M6 — stateful ALG runtime transforms (pinholes / payload+NAT rewrite)

**Junos feature.** Active ALGs (FTP, TFTP, SIP, DNS-with-NAT, …) inspect the
control channel and (a) open **dynamic pinholes** for the negotiated data
channel and (b) **rewrite embedded addresses/ports** when NAT changes the
L3/L4 tuple (FTP `PORT`/`PASV`, SIP SDP, DNS A/AAAA doctoring). This is
distinct from `alg disable` (H3/H4 — turn the ALG *off*).

**Exact xpf gap (source-verified, master).**

- H3/H4 shipped the **classification** half: `alg_type_for_session`
  (`publish_conntrack.rs:63-92`) derives FTP/SIP/DNS alg_type from the service
  port and honors the disable bitfield, writing it into the conntrack value.
- **No consumer reads alg_type.** `grep alg_type userspace-dp/src` shows only
  the writer + tests; there is no pinhole creation, no expected-child-session,
  no payload rewrite. `grep -i 'pinhole|expected_session|child_session|
  data_channel|secondary_flow'` in `userspace-dp/src` returns nothing.
- `docs/feature-gaps.md:234-236` states this explicitly: "xpf does not yet
  implement the active ALG transforms themselves — payload doctoring / dynamic
  pinholes — so a non-disabled ALG only sets the type."

**Affected packages / surface.** This is net-new dataplane state:
`userspace-dp/src/afxdp/` session-create + forwarding path (control-channel
payload parse, expected-flow table, NAT rewrite on data channel), plus per-ALG
parsers. Each ALG (FTP/TFTP/SIP/DNS) is its own protocol grammar.

**Design approach (option-level — needs explicit decision).**
- **Per-ALG, incremental.** TFTP is the smallest (single UDP request opens one
  return pinhole, no payload rewrite). FTP active/passive needs control-channel
  TCP reassembly + `PORT`/`227` parse + NAT-aware rewrite. SIP needs SDP
  parsing. DNS-with-NAT needs A/AAAA doctoring. Recommend **scoping each ALG as
  its own issue** rather than an M6 umbrella.
- **Expected-flow (pinhole) infrastructure first.** All ALGs share a
  "create a short-lived expected session keyed on the negotiated tuple" need —
  that infra (a pinhole table consulted at session-create, with TTL + NAT
  binding) is the reusable foundation and should be the first sub-PR, validated
  with the simplest consumer (TFTP).

**Effort: L.** New stateful subsystem in the Rust hot path; control-channel
parsing; NAT-coupled rewrite; needs lab validation per ALG.

**Value: corr.** Without it, NAT + FTP/SIP/TFTP data channels break (a real
functional gap), but it is feature-completeness, not a silent-security-drop.

**Disposition: large-needs-design.** **Defer to a dedicated tracking issue**
(or split into per-ALG issues with a shared pinhole-infra sub-PR first). NOT an
Increment-2 candidate. Decision needed: do we want ALG transforms at all on the
userspace dp, or do we accept the documented limitation and just ensure
`alg disable` (shipped) + commit-warn for the unimplemented active transforms?
Recommend: file the issue, lead with TFTP+pinhole-infra, gate on whether any
real config relies on NAT'd FTP/SIP.

---

## M7 — event-policy attributes-match (regex + broader field extraction)

**Junos feature.** `event-options policy <p> attributes-match
"<event>.<attr> matches <pattern>"` filters event triggering on a **regex**
match against any event attribute.

**Exact xpf gap (source-verified, master).**

- `pkg/eventengine/engine.go:128-160 attributesMatch()` does literal string
  equality (`if value != pattern { return false }`, line 155) — not regex.
- Only two fields are extractable: `test-owner` and `test-name`
  (`engine.go:146-153` switch; `default: continue` silently ignores any other
  field). The event struct `pkg/rpm/rpm.go:95-99` only carries
  `Name/TestOwner/TestName`, so there are genuinely only those two attributes
  available today.
- Schema: `pkg/config/schema_system.go:659` `attributes-match` has
  `children: nil` (accepts any string) — parse/store is fine
  (`config.EventPolicy.AttributesMatch []string`, `types_chassis.go:153`).

**Affected packages.** `pkg/eventengine/engine.go` (the matcher);
`pkg/rpm/rpm.go` (event attribute surface, if widening fields).

**Design approach.**
1. Replace literal `value != pattern` with `regexp.Compile` (compile-once at
   `Apply()` time, cache compiled patterns; on compile error, log + treat as
   non-matching or reject at commit — prefer **commit-time validation** of the
   pattern via a schema validator so a bad regex never reaches the engine).
2. Field extraction: the `default: continue` whitelist is the real bound. With
   the current 3-field event there is little to widen, but the design should
   make the field→value map data-driven (a `map[string]string` on the event)
   so adding attributes later doesn't touch the matcher. Whether to widen the
   event attribute set is a **separate, smaller question** — the regex upgrade
   stands alone.

**Effort: S–M.** The regex swap + compile-cache is S. "Broader field
extraction" is the part that grows it: with only 3 event fields it's nearly a
no-op today, so scope M7 to **regex matching + commit-time pattern validation**
and explicitly defer field-widening until there are more attributes to expose.

**Value: corr.** Event-policy automation silently under-fires when an operator
writes a regex (e.g. `.*failed`) expecting Junos semantics and gets literal
equality. Bounded blast radius (event-options is opt-in automation).

**Disposition: feasible-increment (small, scoped to regex).** Recommend for
Increment-2 as the smallest item: swap literal→regex with compile-cache + a
schema/commit validator for the pattern, keep the field set as-is, document the
3-field limitation. Add a test that `.*` / anchored patterns match/don't-match
correctly and that an invalid regex is rejected at commit.

---

## M1 — commit persist-groups-inheritance (daemon persistence)

**Junos feature.** `set system commit persist-groups-inheritance` persists the
expanded result of `apply-groups` inheritance so that subsequent commits and
`show configuration` reflect inherited values without re-expanding, and the
inheritance survives across reboots/upgrades deterministically.

**Exact xpf gap (source-verified, master).**

- Parsed + stored: `compiler_system.go:126-131` sets
  `sys.PersistGroupsInheritance = true`; `types_system.go:47` documents
  "syntax accepted, runtime no-op".
- Commit-warned but never enforced: `compiler.go:1280-1281` emits
  "configured but group inheritance persistence is not implemented".

**Affected packages.** `pkg/configstore` (persistence of expanded/inherited
config), `pkg/config` (group expansion is already done at compile;
persistence of the *expanded* form is the new behavior).

**Design approach (needs design).** Junos's semantics are subtle: it changes
*when/how* inheritance is materialized and persisted. xpf already expands
groups at compile time deterministically, so the practical question is **what
observable behavior actually differs** for an xpf operator — and whether any
real config depends on it. Options:
- **(a) Implement persistence**: store the expanded-inheritance form in the
  configstore so `show configuration` and rollback reflect it identically to
  Junos. Real work in `pkg/configstore` + interaction with the rollback DB.
- **(b) Accept as no-op + keep the commit warning** (current behavior) if no
  real divergence is observable on xpf's expansion model.
- **(c) Schema-formalize + commit-warn upgrade**: make the no-op explicit and
  truthful (it already warns).

**Effort: M (if implemented).** configstore-side persistence refactor with
rollback-DB interaction.

**Value: corr (low, possibly cosmetic on xpf).** xpf's eager deterministic
group expansion may already give the operator-visible result; the persist knob
is largely a Junos internal-materialization detail. This is the weakest-value
item in the set.

**Disposition: large-needs-design / likely defer.** Recommend **NOT** in
Increment-2. Decision needed: confirm (via a concrete apply-groups config diff
test) whether xpf's behavior already matches Junos's persisted result. If yes →
downgrade to "accepted no-op with commit warning" (current state is fine; close
as wont-fix-with-warning). If a real divergence is found → file a configstore
persistence issue. Lowest priority of the five.

---

## H13 — forwarding-options allow-dataplane-sleep

**Junos feature.** `set forwarding-options allow-dataplane-sleep` permits the
dataplane to enter a low-power/idle state (yield CPU when there is no traffic)
instead of busy-spinning — a power/CPU tradeoff knob.

**Exact xpf gap (source-verified, master).**

- Entirely absent: `grep allow-dataplane-sleep|AllowDataplaneSleep|
  dataplane_sleep` across `pkg/` and `userspace-dp/src/` returns nothing.
- Accepted as a fall-through leaf only: `compileForwardingOptions`
  (`compiler_services.go:883-914`) handles sampling / dhcp-relay / family /
  port-mirroring and **ignores** any `allow-dataplane-sleep` child;
  `schemaForwardingOptions` (`schema_routing.go:324`) has no such child (commit
  accepts it via the no-schema-match leaf path, `ast_edit.go:151-165`).

**Affected packages.** `pkg/config/schema_routing.go` + `types.go`
(`ForwardingOptionsConfig`) + `compiler_services.go` (schema leaf + field);
`pkg/dataplane/userspace/protocol.go` (wire flag); `userspace-dp/src/afxdp/`
poll loop (the **runtime semantics**).

**The runtime-semantics question (the reason this is Tier-2).** The xpf
userspace dataplane workers **busy-poll** (interrupt mode with `SO_BUSY_POLL`,
`docs/userspace-dataplane-architecture.md:576,616`; poll loop in
`poll_descriptor/mod.rs`). "Dataplane sleep" maps onto poll-mode / NAPI-defer /
idle-yield behavior. Whether to actually let workers sleep when idle is a
**performance/latency tradeoff that needs a deliberate decision and lab
validation** — exactly why the triage flagged it borderline. Sleeping idle
workers trades wake latency (first-packet jitter) for lower idle CPU; the loss
cluster's cold-start work (#1782, `docs/userspace-cold-start-resolution.md`)
shows first-packet latency is already a sensitive area here.

**Design approach (two-stage, recommended).**
- **Stage 1 (Increment-2 candidate, S): schema + field + truthful commit
  warning.** Add the typed bool leaf to schema, the `AllowDataplaneSleep` field
  to `ForwardingOptionsConfig`, compiler extraction, and a commit warning
  ("accepted; idle-yield not yet implemented — workers busy-poll"). This closes
  the **silent-drop** (commit currently accepts a leaf that vanishes with no
  feedback) and gives truth-in-commit. Mirrors the existing
  persist-groups-inheritance warning pattern. No dataplane risk.
- **Stage 2 (deferred, M, lab): actual idle-yield runtime.** Thread the flag to
  the worker poll loop (H14's `FlowSnapshot`/`ForwardingState` thread is the
  model) and implement conditional yield-when-idle. **Requires lab validation**
  (idle CPU drop AND first-packet latency regression check on the loss
  cluster). Decision needed before doing this: is idle-CPU on the appliance a
  real operator concern, or is busy-poll-always acceptable? Given the cold-start
  latency sensitivity, default to Stage 1 only unless an operator asks.

**Effort: S (Stage 1) / M+lab (Stage 2).**
**Value: corr (Stage 1 closes a silent-drop; Stage 2 is a power/latency
tradeoff).**

**Disposition: feasible-increment for Stage 1 (schema + warn); Stage 2 is
lab/needs-design (defer).** Recommend Stage 1 in Increment-2; file Stage 2 as a
separate issue gated on an explicit "do we want idle-yield" decision.

---

## Recommended Increment-2 (ship as small PRs, priority order)

The self-contained, decision-free items, smallest/safest first:

1. **M7 (scoped) — event-policy regex matching + commit-time pattern
   validation.** Smallest, fully self-contained (one package). Swap literal
   equality → cached `regexp`, validate the pattern at commit, keep the 3-field
   surface, document the limitation. **S, corr.**
2. **H13 Stage 1 — schema leaf + `AllowDataplaneSleep` field + commit warning.**
   Closes a silent-drop; no dataplane risk. **S, corr.**
3. **M5 — stamp catalog app_id on userspace sessions (Go→Rust catalog snapshot
   + session-create lookup).** Headline correctness win: lights up the
   already-built, currently-dead AppID resolution chain. Also fix the stale
   `feature-gaps.md`/`services-application-identification.md` lines. **M, corr.**
   Ship after 1–2 because it touches the wire protocol + Rust hot path and
   wants a smoke run.

Each is independently issue-able and reviewable. 1–2 are pure control-plane;
3 needs a userspace-dp smoke (session shows correct app name).

## Large / lab / defer / decision-needed

- **M6 stateful ALG transforms — large-needs-design. DEFER.** File a dedicated
  issue; lead with shared pinhole/expected-flow infra + TFTP as the first
  consumer; gate on whether any real config needs NAT'd FTP/SIP. Decision:
  implement vs accept-documented-limitation + commit-warn.
- **H13 Stage 2 idle-yield — lab/needs-design. DEFER.** Separate issue, gated on
  an explicit "do we want idle CPU savings at the cost of first-packet latency"
  decision; must be lab-validated on the loss cluster against the #1782
  cold-start latency baseline.
- **M1 persist-groups-inheritance — large-needs-design / likely reject.**
  Lowest value; xpf's eager group expansion may already match Junos's persisted
  result. Decision: prove equivalence with an apply-groups diff test → if equal,
  keep current no-op-with-warning (effectively reject); if divergent, file a
  configstore persistence issue. NOT Increment-2.

## Cross-cutting (carried from triage, still valid)

Extend the existing commit-warning mechanism into an **"accepted-but-unenforced"
lint** so every stored-not-enforced/silent-drop gap (H13 Stage-1 warn, M1 warn,
M6 active-transform warn) surfaces a commit warning until implemented. Several
Increment-2 items (H13 Stage 1) already follow this shape; standardizing it is
itself a small, high-leverage PR.
