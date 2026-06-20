# #2008 vSRX parity — remaining-gap triage (quick-win first)

Companion-free triage of the **remaining** confirmed gaps in #2008 after the
Tier-1 / Tier-1.5 / H1 work already merged. This is a prioritized quick-win
plan, **not** a single implementation plan. Each quick win is intended to ship
as its own small PR.

## Method / baseline

- Worktree off `origin/master` (HEAD `3fa0af3b5`, merge of #2054).
- Started from the 27 confirmed gaps in #2008, then **subtracted what already
  shipped** (verified by grepping master, not by trusting the issue body):
  - Tier-1 + Tier-1.5 (7 PRs, master `a75c970d8`): **H17, H2, H11, H3, H4,
    H18, H15, H8, M2, M3, H16** — all verified present in source.
  - Tier-2 **H1 `inactive:`** — shipped via PR #2042 (`Node.Inactive` +
    `WithoutInactive` strip verified in `pkg/config/ast.go`).
  - The **RA min/max-advertisement-interval** LOW schema leaves shipped too
    (`pkg/config/schema_routing.go:272` + dedicated `schema_validate_2008_test.go`).
- **Re-graded H6** down to a small residual: an RBAC layer already exists
  (`pkg/cli/permissions.go`, `config.LoginClassPermissions`, dispatch-layer
  `checkPermission`, `SetUserClass` wiring in `daemon_run.go`) predating the
  audit (#1444/#1566). The only real remaining gap is **commit-time
  enum-validation of the `class` value** (schema accepts any string) and a
  missing `config-viewer` class — a schema/enum quick win, not a research item.

### Per-gap source verification (remaining set)

| Gap | Verified-still-a-gap evidence (master) |
|---|---|
| H5 ssh key-exchange | no `key-exchange`/`KexAlgorithms` in `pkg/config` or `pkg/networkd` |
| H6 (residual) | RBAC enforced in `pkg/cli/permissions.go`; class value not enum-validated at commit; no `config-viewer` class |
| H7 security log profile | only `stream` in `schema_security.go`; no `profile`/`default-profile`/`stream-name` stanza |
| H9 interface ARP policer | no `arp-policer`/`ARPPolicer` anywhere in `pkg/config` |
| H10 interface static MAC | `ValueMAC` exists only for device-map identity; no per-interface MAC override field/compile |
| H12 dns-proxy | `compiler.go:1306` still emits "DNS proxy/forwarder runtime is not implemented" warning |
| H13 allow-dataplane-sleep | no `allow-dataplane-sleep`/`AllowDataplaneSleep` in config or `protocol.go` |
| H14 flow power-mode-disable | parsed (`PowerModeDisable`) but absent from `FlowSnapshot` (`protocol.go`) + no Rust reader |
| M1 persist-groups-inheritance | parsed + commit-warned; no daemon persistence (`types_system.go`) |
| M4 policy-stats | `PolicyStatsEnabled` set in compiler, **never read** outside config (counters still unconditional) |
| M5 application-identification app_id | `app_id: 0` hardcoded at `publish_conntrack.rs:175,277`; no policy-eval assignment |
| M6 ALG runtime transforms | `alg_type` derived (H3/H4) but no stateful pinhole/NAT-rewrite consumer |
| M7 event-policy attributes-match | `engine.go` does literal `value != pattern`; only test-owner/test-name fields; no regex |
| M8 traceoptions packet-filter protocol | `packet-filter` schema has src/dst children only; no `protocol` child/extract/filter |
| M9 tcp-session no-sequence-check | no `no-sequence-check`/`NoSequenceCheck` field or compiler case |

**Remaining (non-shipped) gaps: 15** (H5, H6-residual, H7, H9, H10, H12,
H13, H14, M1, M4, M5, M6, M7, M8, M9).

## Ranked triage table

Effort: **S** = config-schema leaf + compiler wiring (+ maybe a one-line
Go→Rust thread to existing dataplane behavior); **M** = multi-file thread or
new runtime consumer; **L** = new subsystem / cross-cutting redesign or
needs lab semantics.

Value: **sec** = security/correctness divergence (commit accepts, intent
lost); **corr** = correctness/feature-fidelity; **cos** = cosmetic /
truth-in-commit only.

| Rank | Gap | Effort | Value | Quick-win? | Notes |
|---|---|---|---|---|---|
| 1 | **M4 policy-stats gate** | S | sec/corr | **YES** | Gate counter collection on `PolicyStatsEnabled`, OR reject at commit. Self-contained in `pkg/api/metrics_counters.go` + compiler. No dataplane change. |
| 2 | **H14 power-mode-disable** | S | corr | **YES** | Thread `PowerModeDisable` into `FlowSnapshot` exactly like `GREAcceleration` (Go: `protocol.go` + `buildFlowSnapshot`/`daemon_apply.go`; Rust: read flag). Pattern already exists in-tree. |
| 3 | **M9 tcp-session no-sequence-check** | S | sec | **YES** | Schema child on `tcp-session` + `NoSequenceCheck` bool + compiler case + thread into existing TCP-state path (sibling of existing tcp-session flags). |
| 4 | **H6 residual: class enum-validate** | S | sec | **YES** | Add `ValidateEnum` on `login class` (super-user/operator/read-only/+config-viewer) like the SNMP-authorization enum already in `schema_system.go:614`. RBAC enforcement already exists. |
| 5 | **M8 traceopt packet-filter protocol** | S | corr | **YES** | Add `protocol` child + extract + `matchFilters()` compare in `pkg/logging/trace.go` (mirrors existing src/dst-prefix handling). |
| 6 | **H5 ssh key-exchange** | S | sec | YES | Typed leaf → `SSHServiceConfig` → render sshd `KexAlgorithms`. Self-contained but touches sshd render path; slightly larger surface than 1–5. |
| 7 | **H13 allow-dataplane-sleep** | S/M | corr | borderline | Schema bool + field is trivial; the *runtime* sleep behavior is the unknown — confirm intended dataplane semantics before claiming enforcement. Could ship as schema+warn first. |
| 8 | **M1 persist-groups-inheritance** | M | corr | no | Daemon-side group-membership persistence refactor. Design first. |
| 9 | **M7 event-policy regex** | M | corr | no | `regexp.Compile` + broader field extraction; remove hardcoded field whitelist. Bounded but more than a leaf. |
| 10 | **M5 application-identification app_id** | M/L | corr | no | Spans policy eval → session create → Rust shim `app_id` preservation. Needs result-plumbing design. |
| 11 | **M6 ALG runtime transforms** | L | corr | no | Stateful pinholes / NAT rewrite (SIP/TFTP/FTP-data). Full design; distinct from H3/H4 *disable*. |
| 12 | **H7 security log profile** | L | corr | no | Net-new config tree + log routing subsystem. |
| 13 | **H12 dns-proxy / forwarder** | L | corr | no | Net-new daemon (UDP+TCP/53, domain-routed forwarders, cache). |
| 14 | **H9 interface ARP policer** | M | corr | DEFER | Interface-granularity rate-limiting not in dataplane. Decide: implement as xpf extension OR reject-at-commit (better than silent ignore). |
| 15 | **H10 interface static MAC** | S(config)/— | — | DEFER/REJECT | Diverges from Junos read-only MAC + conflicts with deterministic cluster-MAC design. Recommend **explicit commit rejection with a clear error**, not silent ignore. |

## Increment 1 — quick wins (ship as separate small PRs)

The 6 smallest, highest-value, self-contained items. Each compiles to existing
dataplane behavior or a single existing pattern, with no cross-cutting design:

1. **M4 — gate policy-stats** (`pkg/api/metrics_counters.go` + compiler).
   Honors `policy-stats` enable/disable instead of collecting unconditionally;
   eliminates a stored-but-unenforced security/observability divergence.
2. **H14 — power-mode-disable into FlowSnapshot** (clone the `GREAcceleration`
   thread-through, Go + Rust). Pattern is already in the tree.
3. **M9 — tcp-session no-sequence-check** (schema child + `NoSequenceCheck`
   bool + compiler case + dataplane skip-seq-validation). Security-relevant
   TCP-state knob.
4. **H6 residual — login `class` enum validation** (`ValidateEnum` +
   `config-viewer` class). RBAC already enforced; this closes the
   commit-accepts-any-string hole. Reuses the existing SNMP-auth enum pattern.
5. **M8 — traceoptions packet-filter `protocol`** (schema child + extract +
   `matchFilters` compare in `pkg/logging/trace.go`).
6. **H5 — ssh key-exchange** (typed leaf → `SSHServiceConfig` → sshd
   `KexAlgorithms` render). Security-hardening leaf; slightly larger than 1–5
   but still self-contained — ship last in the increment or split out if the
   sshd-render touch grows.

Each is independently issue-able and reviewable. Recommended PR order is the
list order (1–4 are pure thread-throughs; 5–6 touch a render/match path).

## Tier-2 (needs `/research` first)

- **M1** persist-groups-inheritance (daemon persistence design).
- **M5** application-identification app_id (policy-eval → session → shim plumbing).
- **M6** stateful ALG transforms (multi-protocol pinhole/NAT design).
- **M7** event-policy regex (bounded, but design the field-extraction surface).
- **H13** if dataplane-sleep runtime semantics are non-trivial (else it joins
  Increment 1 as schema+warn).

## Tier-3 (standalone, own issue, possibly multi-PR)

- **H7** security log profile stanza (net-new config tree + log routing).
- **H12** DNS proxy/forwarder daemon (net-new subsystem).

## Defer / accept (decide explicitly, do not silently ignore)

- **H9** ARP policer — implement as xpf extension *or* reject at commit.
- **H10** static MAC — recommend **reject at commit** (diverges from Junos
  read-only MAC; conflicts with deterministic cluster-MAC). Better than the
  current silent ignore.
- LOW "compiled-not-enforced" cluster (`no-redirects` is now handled in
  `daemon_system.go`; `master-password`/`license autoupdate`/`processes
  disable` are compiled, some commit-warned) — finish the sysctl/process hooks
  in one cleanup PR or downgrade the rest to commit-warnings.

## Cross-cutting recommendation (from the issue, still valid)

Extend the existing commit-warning mechanism (dns-proxy /
persist-groups-inheritance) into an **"accepted-but-unenforced" lint** so every
stored-not-enforced gap surfaces a commit warning until implemented. Gives
operators truth-in-commit independent of the per-feature work. Could itself be
an Increment-1-adjacent PR.

---

## Claude SMR self-review

**Confidence: high on the shipped/remaining split, medium on a few effort
grades.**

- **Shipped-vs-remaining is source-verified**, not issue-trusted. Every
  "shipped" claim was grepped in master (H1 `Node.Inactive`, M2/M3/H8 schema
  children, H16 NAT64, RA leaves). Every "remaining" gap has a concrete
  master-source citation in the verification table. This is the
  highest-confidence part.
- **H6 was re-graded** from the issue's Tier-2 RBAC-research framing down to a
  schema-enum quick win, because `pkg/cli/permissions.go` already enforces
  class-based RBAC. I am confident the enforcement exists; I did **not**
  exhaustively audit whether every privileged command path routes through
  `checkPermission` (dispatch-layer hook at `cli_dispatch.go:224` covers
  top-level verbs — config-mode/internal paths not fully traced). If a deeper
  audit finds enforcement holes, H6 grows back toward Tier-2. Flagging this as
  the one re-grade that could move.
- **Effort grades I'm least sure of:** H13 (S vs M hinges entirely on what
  "dataplane sleep" must actually do at runtime — I could not confirm the
  intended semantics, hence "borderline / schema+warn first"); H5 (S, but the
  sshd-render touch could surface ordering/template subtleties). M5/M6 firmly L
  by inspection of the plumbing distance.
- **Could not classify with certainty:** the exact runtime semantics of **H13
  allow-dataplane-sleep** and **H14 power-mode-disable** beyond "thread the
  flag" — H14's Go/Rust plumbing is a clear clone of `GREAcceleration` (so
  effort is S), but the *behavioral* effect on the Rust side still needs the
  intended semantics confirmed before a PR claims true enforcement vs
  schema-plumbing-only. Both are in Increment 1 / borderline on that basis;
  reviewers should confirm the Rust-side behavior contract.
- **Scope discipline:** I deliberately did not re-open the 20 refuted
  candidates or the broader `/deep-research` sweep the issue references —
  staying inside the 27 confirmed set as instructed.
