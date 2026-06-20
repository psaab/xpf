# #2008 Tier-3 parity gaps — research + recommended dispositions

Companion-free `/research` for the **Tier-3** rows of the #2008 parity triage
(`docs/research/2008-parity-triage/triage.md`): **H7** (security log profile /
stream config) and **H12** (DNS proxy / forwarder daemon). The triage flagged
both as "standalone, own issue, possibly multi-PR" net-new subsystems. This doc
per-gap-researches each, source-verified against `origin/master` HEAD
`ec46efbc7`, and recommends a disposition with a concrete Increment-1 where
feasible.

> No production source touched. No Codex/AGY. STOP at this doc + the hostile
> Claude-SMR self-review (`claude-smr-r1.md`).

## Both gaps confirmed still un-shipped on master (grep citations)

| Gap | Evidence it is still open on `ec46efbc7` |
|---|---|
| H7 security log profile | `pkg/config/schema_security.go:187-215` — the `log` node has `mode`/`format`/`source-interface`/`stream`; **no `profile`/`default-profile` child**. `grep -n 'default-profile\|DefaultProfile\|profile' pkg/config/{schema_security,compiler_security,types_security}.go` → only the unrelated feeds `profile` (`schema_security.go:425`). |
| H12 dns-proxy | `pkg/config/compiler.go:1341-1343` still emits `"system services dns dns-proxy configured but DNS proxy/forwarder runtime is not implemented"`; `pkg/config/types_system.go:194` carries only `DNSProxyConfigured bool` (sub-tree discarded). |

Neither shipped in Increment-1/Increment-2 (those covered H1/H5/H6/H14/M4/M8/M9
and the Tier-2 M5/M6/M7/H13 research — see `docs/research/2008-tier2/plan.md`).

---

## H7 — `security log profile` / per-stream profile config

### Junos feature

Junos `security log` has two distinct sub-trees:

1. **`stream <name> { ... }`** — a destination: `host`/`port`/`severity`/
   `category`/`format`/`source-address`/`transport { protocol; tls-profile; }`.
2. **`profile`-style routing knobs** — chiefly `default-profile`, plus the
   notion that the global `log { mode; format; source-interface; }` settings
   form an implicit default that streams inherit. In Junos, the operationally
   meaningful piece of "profile" that real configs use is **the inheritance/
   default surface** (a stream inherits global `format`/`source-interface` and
   `severity` unless it overrides), and the `default-profile` directive naming
   which stream catches events not otherwise routed.

The triage row (`triage.md:32`) and the issue (`H7`) phrase it as
"`security log profile` (stream-name/category/default-profile) — whole stanza
absent."

### Current xpf state (source-verified, master)

This is the key finding: **xpf already implements the substance of the Junos
"profile" surface under its `stream` node.** The audit row overstates the gap.

- **Config model is complete for streams.** `pkg/config/types_security.go:129-155`
  defines `LogConfig{ Mode, Format, SourceInterface, Streams map[string]*SyslogStream, Report }`
  and `SyslogStream{ Name, Host, Port, Severity, Facility, Format, Category,
  SourceAddress, Transport{ Protocol, TLSProfile } }`. The compiler
  (`compiler_security.go:494-573`, `compileLog`) fills all of these from both
  hierarchical and flat-set AST shapes; the schema (`schema_security.go:187-215`)
  declares every leaf (and after H8, the `transport` enum is validated).
- **Per-stream routing already works at runtime.** `daemon_system.go:96-137`
  (`applySecurityLogging`) builds one `*SyslogClient` per stream, setting
  `MinSeverity`/`Facility`/`Categories`/`Format`/`SourceAddress`/`Protocol`
  individually. The event dispatcher (`ringbuf.go:520-547`) broadcasts each
  RT_FLOW record to every client and filters per-client via
  `ShouldSendEvent(severity, catBit)` (`syslog.go:256-262`). So **different
  streams with different category/severity filters already route different
  event classes to different syslog servers** — the operational point of Junos
  per-stream profiles.
- **Categories implemented:** `Session`/`Policy`/`Screen`/`Firewall`
  (`syslog.go:55-62`, mapped from event type in `ringbuf.go:693-707`).
- **Event mode** (local file) is handled at `daemon_system.go:64-79`.

What is genuinely **absent**:
- The literal `profile` / `default-profile` **keywords** under `security log`
  (no schema child, no type field, no compiler case). A config that uses
  `set security log default-profile <name>` does not parse-error (it falls
  through the no-schema-match leaf path) but is silently discarded — the
  **silent-drop** class.
- Any "implicit-default fallthrough" semantics: today every stream is an
  independent filtered subscriber (OR-of-streams). There is no notion of "send
  to the default-profile stream only if no other stream matched." In practice
  xpf's model is a superset (all matching streams get the event), so the
  visible-behavior delta is limited to configs that deliberately rely on
  Junos's catch-all-vs-specific routing — uncommon in firewall syslog configs.

### Design options

**Option A — `default-profile` as a validated alias (recommended Increment-1, S).**
Add `default-profile` as a typed leaf under `security log` whose value must name
an existing `stream`. Semantics in xpf: it designates which stream's global
inheritance applies and is accepted/validated rather than silently dropped.
Because xpf already broadcasts to all matching streams, `default-profile` maps
cleanly onto "the stream that receives events with no explicit category filter"
— i.e. validate that the named stream exists and (optionally) that it has an
empty/`all` category so it genuinely acts as a catch-all; warn otherwise. This
closes the silent-drop and gives commit-time validation + completion. ~40-70
LOC: one `schemaNode` leaf with a `ValidateStreamName`-style cross-reference
validator (mirror the existing `ValueHintStreamName`), one `DefaultProfile
string` field on `LogConfig`, one compiler line, a commit-check that the
referenced stream exists, and a parser/compiler round-trip test. No runtime/
dataplane change — `applySecurityLogging` already does the right thing.

**Option B — full Junos profile object + catch-all routing semantics (M, low
value).** Introduce a first-class `profile` object distinct from `stream`, and
rework `ringbuf.go` dispatch to implement "default-profile catches only
unmatched events." This is a behavior change to a working broadcast model for a
semantic almost no real firewall syslog config depends on, and it risks
regressing the current (correct, Junos-superset) per-stream routing. Not
recommended.

**Option C — reject-at-commit (fallback if A is descoped).** If we choose not to
implement `default-profile`, at minimum surface a commit warning
("`security log default-profile` accepted but not implemented") via the existing
warning mechanism, converting the silent-drop into truth-in-commit. Strictly
worse than A for the same review surface, so A is preferred.

### Effort / value / disposition

- **Effort: S** (Option A — schema leaf + field + compiler + cross-ref
  validator + test; no daemon/dataplane change).
- **Value: corr** (closes a silent-drop; restores commit-time validation and
  `?` completion for `default-profile`; the *runtime* routing is already
  Junos-superset).
- **Disposition: FEASIBLE-INCREMENT (small).** H7 is **not** a net-new
  subsystem — the audit row's "whole stanza absent" is inaccurate; the stream
  machinery (the substance of profiles) already exists end-to-end. The residual
  is a single validated alias leaf. Recommend Option A as Increment-1.

### Increment-1 (H7) — concrete scope

1. `pkg/config/types_security.go`: add `DefaultProfile string` to `LogConfig`.
2. `pkg/config/schema_security.go`: add a `default-profile` child under the
   `log` node, `args: 1`, `valueHint: ValueHintStreamName`, with a validator
   that resolves against configured stream names (follow the existing
   `ValueHintStreamName` completion + a `schema_walk` cross-reference check, or
   a compiler-side check if the validator can't see siblings — see the
   `tls-profile`/zone cross-ref precedent).
3. `pkg/config/compiler_security.go` (`compileLog`): extract `default-profile`
   into `sec.Log.DefaultProfile`. Do the **stream-existence cross-reference in
   the compiler**, not a schema validator — `schema_walk.go` per-leaf validators
   do not see sibling nodes, and `compileLog` already has the full stream map in
   scope, so it is a one-line map-membership check. If it names a stream that
   does not exist, emit a commit warning (or error — match the project's
   existing cross-ref severity for syslog/`source-interface`).
   **Before fixing the leaf's meaning, confirm the exact Junos semantics of
   `default-profile`** (a routing catch-all target vs a named *format/structured-
   data profile* applied across streams). The plan's "no runtime change"
   property holds under either reading — if it is a format selector, resolve it
   to the global `format`/source-inheritance xpf already applies; if a routing
   target, validate it names a stream. Pin the meaning from a real imported
   config before writing the compiler case.
4. Tests: `parser_security_test.go` (or the existing security-log test file) —
   flat-set + hierarchical round-trip; default-profile naming an existing stream
   (accepted), naming a missing stream (warned/errored).
5. Docs: note in the security-logging doc / `docs/config-schema.md` that
   `default-profile` is validated and that xpf's per-stream routing is a Junos
   superset (all matching streams receive the event), so `default-profile`
   functions as a validated catch-all designation rather than altering dispatch.

Optional follow-up (separate, only if a real config needs it): map a richer
`profile` object. File only if an imported config exercises it; otherwise the
alias is sufficient parity for the audited surface.

---

## H12 — `system services dns dns-proxy` / DNS forwarder daemon

### Junos feature

`system services dns dns-proxy` makes the firewall a client-facing DNS
forwarder/cache: listen on selected interfaces, forward queries to configured
upstream `forwarders`, append a `default-domain` for unqualified names, optional
split-horizon `view`s, optional `propagate-setting`, and a cache. The audit
(`H12`) and triage (`triage.md:35,74`) classify it as a **net-new daemon (UDP+
TCP/53, domain-routed forwarders, cache)**.

### Current xpf state (source-verified, master)

- **Config is accepted but reduced to a boolean.** `compiler_system.go:332-340`
  detects `dns-proxy` via `hasDNSProxyChild` (`compiler_system.go:410-417`, a
  presence check) and sets `sys.Services.DNSProxyConfigured = true`
  (`types_system.go:194`). The entire sub-tree (`default-domain`, `forwarders`,
  `view`, `interface`) is **discarded** — the parser accepts it
  (`parser_system_test.go:1153-1189` shows `dns-proxy { default-domain *;
  forwarders { 1.1.1.1; } }` parsing) but the compiler reads none of it.
- **Commit warning** at `compiler.go:1341-1343`. This is the
  "stored-as-a-bool-then-warned" pattern — better than a silent drop, but no
  runtime.
- **No DNS forwarder/listener exists.** No `dnsmasq`/`unbound` management; no
  `net.ListenUDP`/`ListenPacket` on :53 anywhere in `pkg/`.
- **DNS resolution today is host-resolver only.** `pkg/daemon/daemon_dns.go`
  (`dnsReconciler`, `reconcileDNSLocked`) is the single writer of
  `/etc/resolv.conf`, merging static `system name-server` + DHCPv4/v6-learned
  nameservers, and it **disables + masks `systemd-resolved`** on every reconcile
  (per `docs/dns-ownership.md`). So the firewall has no client-facing DNS
  listener — it only configures its own stub resolver.

### A design doc already exists (de-risks H12 significantly)

`docs/next-features/dns-proxy.md` (tracking issue **#660, now CLOSED**;
import-compat **#659 MERGED**) is a complete 6-phase plan:
- Phase 0 (done): import-compat warnings.
- Phase 1: explicit config model (`DefaultDomain`, `Forwarders`, listen
  metadata) replacing the bool.
- Phase 2: an **xpfd-managed `unbound`** renderer/manager (the doc's
  recommended daemon).
- Phase 3: retire `systemd-resolved` entirely; xpf-managed runtime owns both
  client-facing DNS *and* host DNS.
- Phase 4: lab bind/query validation.
- Phase 5: HA listener-follows-RG-ownership.
- Phase 6: `show services dns-proxy` observability.

This is the canonical scope. H12 under #2008 is **resurrecting #660's plan**,
not designing from scratch.

### Reusable infrastructure (lowers the per-phase cost)

- **`pkg/dhcpserver/` (Kea)** is the near-exact analog for Phase 2: a `Manager`
  with `Apply(cfg)`/`Clear()`, deterministic config rendering via
  `fsatomic.WriteFileAtomic`, lifecycle via `systemctl` with a 15s timeout, plus
  HA `ApplyAsync`/`ApplyClusterCommit` (MASTER-only). An `unbound` manager is a
  structural copy. `pkg/ipsec/manager.go` (swanctl) and `pkg/frr/manager.go`
  (managed-section) are smaller precedents.
- **`github.com/miekg/dns v1.1.72`** is already in `go.mod`/`go.sum` but unused
  — making a *native Go* forwarder feasible if we want to avoid an external
  daemon dependency.
- **UDP/socket precedents** if going native: `pkg/snmp/agent.go`
  (`net.ListenUDP` :161), `pkg/vrrp/manager.go` (`net.ListenPacket`),
  `pkg/dhcprelay/relay.go` (VRF-aware `SO_BINDTODEVICE`).
- **`daemon_dns.go`** already owns `/etc/resolv.conf` and resolved-masking — the
  Phase-3 transition has a single, well-understood writer to refactor.

### Effort / value / disposition

- **Effort: L** — net-new subsystem. Even the doc's own minimal path is ~2 PRs
  to first runtime (config model, then `unbound` manager + apply integration),
  and the full Phase 1-6 (HA + resolved-retirement + observability) is a 4-6 PR,
  multi-week project per `docs/next-features/dns-proxy.md`.
- **Value: corr** — feature fidelity for vSRX import. Note: **no audited
  `vsrx.conf`/`vsrx-ha.conf` snippet in this repo actually configures
  `dns-proxy`** (the H12 example comes from `parser_system_test.go`, not a real
  imported config). The current commit-warning already gives operators
  truth-in-commit, so the marginal value of a full daemon over the existing
  warning is **moderate, demand-driven**, not a security or correctness
  emergency.
- **Disposition: PLAN-DEFER (large) — with a feasible thin first step.** Do not
  attempt the full daemon as one PR. The honest recommendation:
  - **Keep the existing commit warning** as the operator-truth backstop (it is
    correct and already shipped).
  - **Only proceed past Phase 1 if a real imported config or an operator
    requests client-facing DNS proxy.** Absent that demand, the daemon is a
    multi-week subsystem for a config knob with no exercising config in-repo.
  - If we want to make *measurable* parity progress now without the daemon, the
    safe, bounded first step is the config-model half of Phase 1 (below).

### Optional Increment-1 (H12, S) — config-model-only, decision-gated

Only worth doing if we want to retire the "discards the sub-tree" silent loss
ahead of the daemon. Strictly the config half of the doc's Phase 1:

1. Replace `DNSProxyConfigured bool` with a `DNSProxyConfig` struct on
   `SystemServicesConfig` (`types_system.go`): `Enabled bool`, `DefaultDomain
   string`, `Forwarders []string`.
2. `compiler_system.go`: parse `default-domain` + `forwarders { <ip>; ... }`
   (validate IPs), keep recording presence; **keep emitting the runtime warning**
   (now: "config model captured; forwarder runtime not yet implemented") since
   there is still no listener.
3. Schema: declare `dns-proxy` children (`default-domain`, `forwarders`) for
   completion + commit-time IP validation.
4. Tests: flat + hierarchical, multiple forwarders, inactive subtree, the
   `parser_system_test.go` snippet.

**Effort S, value corr (closes the sub-tree silent-drop + adds IP validation).**
This is genuinely optional: it does not deliver DNS-proxy behavior, only stops
discarding the operator's forwarders/default-domain and validates them. Recommend
**only** bundling it as the opening PR *if* the daemon work is greenlit; doing it
standalone leaves a parsed-but-still-warned config, which is marginal over
today's bool+warning. **Default recommendation: DEFER the whole of H12 (keep the
warning) until there is demand; if greenlit, follow the existing
`docs/next-features/dns-proxy.md` phase plan with `unbound`.**

---

## Recommended Tier-3 dispositions (summary)

| Gap | Disposition | Increment-1 | Effort | Value |
|---|---|---|---|---|
| **H7** security log profile | **FEASIBLE-INCREMENT (small)** | `default-profile` validated alias leaf (Option A) — schema + `LogConfig.DefaultProfile` + compiler cross-ref + tests; **no runtime change** (per-stream routing already Junos-superset) | S | corr |
| **H12** dns-proxy daemon | **PLAN-DEFER (large), demand-gated** | None by default (keep commit warning). Optional config-model-only opener (`DNSProxyConfig` struct + forwarder/default-domain parse + IP validation) only if the `unbound` daemon (per `docs/next-features/dns-proxy.md`, #660) is greenlit | L (full); S (optional config-only opener) | corr (demand-driven) |

### Recommended next increment

Ship **H7 Option A** as a small standalone PR (closes a silent-drop + restores
validation/completion, no dataplane risk). **Defer H12** — the existing
commit warning is the correct backstop; reopen `docs/next-features/dns-proxy.md`
(#660) only on real demand for a client-facing DNS forwarder, then proceed
phase-by-phase with `unbound`.

### Cross-cutting (carried from triage/Tier-2, still valid)

Both H7's silent-drop (`default-profile`) and H12's discarded sub-tree are
instances of the "accepted-but-unenforced / silently-dropped" class the triage's
cross-cutting recommendation targets. H7 Option A converts its case to validated;
H12's optional config-only opener would convert its case to parsed-and-validated.
The standing recommendation to formalize an "accepted-but-unenforced" commit lint
still applies as the cheapest truth-in-commit mechanism for whatever is not yet
implemented.
