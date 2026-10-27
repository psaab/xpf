---
name: deep-review
description: Review firewall source and validation coverage, prioritize consequential defects, and produce a private evidence-backed report. Supports full, focused, and change-based reviews with isolated worktrees.
user-invocable: true
---

# Deep review

Prioritize consequential defects in supported firewall behavior. Choose review
work using impact, reachability, change history, and uncertainty. Distinguish
inventory coverage, refuted hypotheses, and verified behavior. Preserve unresolved
high-impact questions, and give every confirmed finding an acceptance criterion
for its fix. File counts and finding counts are bookkeeping, not success targets.
Use domain-specialist expertise and an adversarial defensive perspective: question
whether the implementation preserves its protections under untrusted influence,
state transitions, and failure, not only whether the intended path works.

Read [the shared review contract](references/review-contract.md) before discovery
or triage. It owns severity, evidence, dispositions, report fields, and completion
criteria shared by this skill, `review-triage`, and code-finding research.
Use [review lifecycle and progress](references/review-lifecycle.md) for source
registration and repeat-safe handoff to research. Active reports use
`/var/tmp/deep-review-reports/`, work/state use `/var/tmp/deep-review-work/`,
and completed source/result pairs use `/var/tmp/deep-review-finished/`.

## Host isolation (2026-10-26)

Review is read-only and never needs host mutation: do NOT run
kernel/root test cells, live daemons, or deploy harnesses on
the workstation to "verify" a finding. Classify needed
validation as U (hermetic, run it), N (netns, `unshare -rn`
forcing leg), R/F (privileged/live-daemon, Incus VM leg), or
V (cluster harness, Incus) and record unrun classes as
NOT-EXAMINED with the VM target. New kernel-reachable tests
found in review must declare their class; flag undeclared ones.

## Scope and modes

- `/deep-review`: inventory the full live product and prioritize review depth
  across it. Report any inventory items or behaviors not actually inspected.
- `/deep-review --area A3 --focus "config compiler"`: constrain discovery to the
  selected area, reading dependencies needed to assess its contracts.
- `/deep-review focus on zone policies only`: honor the explicit restriction.
  A focus without a restriction changes priority within the selected scope.
- `/deep-review --since <sha>`: review changes from that commit to the pinned
  base, their relevant callers/consumers, and related fix residuals. Validate the
  commit and range; an invalid or ambiguous range is not a full-tree request.
- `--batch-size N`: maximum production files per batch (default 150), not a
  depth target. Split further by contract, complexity, and available context.
- `--name "HA failover"`: human-readable review name for the report and issue
  provenance. If omitted, derive a short descriptive name from effective scope
  and focus (`full-firewall` for an unfocused full run). Record its safe
  `REVIEW_SLUG` using the shared naming rules; the name never changes scope.

Parse arguments as data; never interpolate free-form context into shell code.
Record the effective mode, scope, focus, exclusions, and any user time/effort
limit in the report. Delta and area modes override full-tree instructions.
Every run writes a findings report under `/var/tmp/deep-review-reports/`,
including runs with no confirmed
findings or no issues filed. The report records coverage and unresolved work;
an empty findings list is not a reason to skip it.

This is a defensive source review and report workflow. It does not authorize
exploitation, deployments, shared-cluster mutations, source fixes, issue filing,
or messages. Carry forward actual session authorization for separately requested
actions. Use existing tests and bounded local assertions with benign fixtures;
temporary test-only changes belong in owned scratch worktrees and must be
preserved as evidence before cleanup. A required live check without authorization
or prerequisites becomes a named validation task, not an improvised probe.

## 1. Pin the target and allocate the run

1. Discover the repository with `git rev-parse --show-toplevel`. Read
   `AGENTS.md`, `CLAUDE.md`, relevant engineering guidance, and the selected
   modules' current architecture/operator docs. Give each worker the particular
   documents its contracts require; a one-paragraph summary is not a substitute.
2. Record repository identity (credential-free remote identity, or a local
   identity), checkout path, and immutable base SHA. Use the requested revision
   or current HEAD. Do not pull, rebase, or alter the control checkout for review.
3. Resolve the comparison branch from the task or repository's remote default
   branch. Use a branch upstream only when it matches that intended target;
   record its repository, ref, SHA, and fetch time. Refresh remote refs when
   available without moving the base. If comparison is unavailable, record that
   limitation; never claim current-tip verification.
4. Ensure `/var/tmp/deep-review-reports/` (final reports) and
   `/var/tmp/deep-review-work/`
   (working storage) are real directories, creating them if absent; do not
   follow a substituted symlink or overwrite an occupied path. Allocate the run
   with `mktemp -d /var/tmp/deep-review-work/review-work.XXXXXXXXXX`. Its unique
   basename is the run ID. Keep worktrees, drafts, logs, manifests, test fixtures,
   build/temp directories and retained evidence inside this owned run directory.
   Give workers these paths explicitly; set task-local `TMPDIR` and relevant
   build/cache output paths there so tool defaults do not scatter scratch in
   `/tmp` or the control checkout. Record owned paths in the manifest; the
   future report sequence number must not allocate shared scratch resources.
5. Establish the coordinator's identity using the shared contract's model
   identity and naming rules. Record `MODEL_RAW`, `MODEL_SOURCE`, `MODEL_HOST`
   and `WHOAMI` in the manifest and report header before assigning work.
   `WHOAMI` is derived from the evidenced model, not a historical report family
   or the Unix username. Preserve full GPT model/version names when exposed;
   GPT must never become `muse-spark` for "compatibility". Unknown identity is
   explicit, not a reason to reuse a previous run's prefix.
6. The coordinator creates each detached worker worktree from the pinned base
   under the unique run directory, following `AGENTS.md` ownership rules.
   Before work starts, the worker reports its path, SHA, and assigned scope.
   A pre-existing path is not evidence that it is stale: allocate a new owned
   path rather than forcing removal. All source evidence names its revision.

## 2. Inventory the product and select high-value work

Start from `git ls-files -z`, not a source-extension allowlist. Classify runtime
source, tests/harnesses, schemas, build inputs, package hooks, service units,
deployment scripts, and relevant configuration. Account for generated outputs
through their generators and consumers. Record exclusions with evidence.

Do not infer retirement from a directory name or historical comment. Confirm
current build inclusion, callers, and operational role. The retired eBPF/DPDK
forwarders are historical; the AF_XDP shim, retained shared headers, Go shim
loader, nftables host enforcement, and appliance lifecycle still need assessment.

Keep stable area IDs for ownership and `--area`; refresh actual paths/counts:

| Area | Source responsibility |
| --- | --- |
| A1 | Rust packet path, parser/frame/UMEM, worker/queues/CoS, sessions, policy/filter/screens, control protocol/server/event stream, WireGuard, and `userspace-xdp/` |
| A2 | Rust NAT, NAT64, NPTv6, translation and allocation lifecycle |
| A3 | Go `pkg/config/`, `pkg/cmdtree/`, `pkg/appid/`: schema, parser and compilation |
| A4 | `pkg/configstore/`, `pkg/fsatomic/`: persistence, crypto-at-rest, commit/rollback |
| A5 | `pkg/cluster/`, `pkg/vrrp/`, `pkg/ra/`, `pkg/conntrack/`: HA and synchronization |
| A6 | `pkg/dataplane/` and `pkg/dataplane/userspace/`: shim loading, snapshots, control messages and apply |
| A7 | `pkg/daemon/`, `pkg/nftables/`, `pkg/networkd/`, `pkg/devicemap/`, routing/FRR/IPsec: host enforcement and lifecycle |
| A8 | `pkg/authz/`, `pkg/grpcapi/`, `pkg/api/`, `proto/`: identity, authorization, API contracts |
| A9 | Telemetry, flow export, logging, SNMP, probes, feeds, event automation and monitoring |
| A10 | DHCP/DDNS/services, policy simulator, CLI, `cmd/`, packaging, image/upgrade/deploy/build tooling |

These file areas also require the cross-cutting kernel/NIC, networking, and
high-performance experts defined below; A1 and A7 do not subsume that expertise.

Assign unmapped files explicitly. Test files include Rust `tests.rs`,
`*_tests.rs`, `tests_*`, Go `*_test.go`, Python tests, and shell harnesses;
production and test code may also coexist in one file. Counts alone do not
determine classification.

Build a short ranked worklist: documented behavior/invariant, reachable
operational context, potential impact, recent change or residual, uncertainty,
existing evidence, next useful check, and owner. History informs priority but
does not prove twice-silent code is sound. Reserve review capacity for critical
under-verified behavior and for independent checks of dispositions.

Run a validation-assurance workstream alongside source review. Inspect whether
the relevant tests/harnesses are invoked, exercise production code, have valid
oracles, and can fail. Use `make harness-census` and
`test/incus/HARNESSES.unreached` for registration evidence; neither proves a live
test ran. Prioritize actual missing gates separately from intentional manual
diagnostics. Keep test/harness coverage visible rather than declaring it
low-value supporting material.

### Required specialist personas and checklists

Area ownership is not a substitute for expertise. Include the applicable persona
and technical checklist in every assignment, including work done by the
coordinator. These are required review perspectives, not claims of credentials.
For cross-area contracts, combine the relevant expertise; a directory boundary
must not cut off a validation or lifecycle argument. Select checks relevant to
the actual behavior, and record consequential omissions or missing expertise.

- **A1 — Senior Rust systems engineer.** Check unsafe ownership, lifetimes,
  aliasing and UMEM/frame reuse; packet parse/rewrite bounds and checksum
  correctness; integer overflow, narrowing `as` casts and byte order; lock-free
  queues, atomic ordering and worker handoff; cache-line/HPC invariants and
  hot-path allocation. Examine fail-closed parsing, policy/session cache validity,
  and resource reclamation across the AF_XDP shim and userspace boundary.
- **A2 — NAT/CGNAT specialist.** Check port allocation ownership, exhaustion and
  reclamation; twice-NAT ordering; forward/reverse NAT, NAT64 and NPTv6
  translation; checksum and embedded-ICMP reversal; fragment handling; zone/VRF
  identity in mappings. Follow HA port reservations on synchronized sessions,
  collision prevention, expiry and recovery, not just first-packet translation.
- **A3 — Parser/compiler engineer.** Check Junos AST dual shapes and bracketed
  lists (#2419); strict-versus-lenient gates; typed-leaf schema validation;
  `Atoi`/length-to-`uint16`/`uint32` narrowing; malformed-input rejection and
  recursion/resource caps. Follow accepted match dimensions and defaults through
  compilation to their consumers; parse success alone does not prove enforcement.
- **A4 — Storage/crypto engineer.** Check durable temp-write, fsync, rename and
  directory-sync ordering; AES-GCM/HKDF, nonce uniqueness and error handling;
  commit/rollback and commit-confirmed timer ownership; journal torn-tail
  recovery, envelope compatibility and secret redaction. Include `fsatomic`
  consumers and distinguish persisted, acknowledged and actually applied state.
- **A5 — Distributed-systems/HA engineer.** Check failover timing, fencing,
  split-brain and dual-primary prevention; VRID/priority arithmetic and `uint8`
  wraps; session-sync framing, peer identity, wire compatibility and anti-replay;
  cold-boot ordering, lock discipline and data races; dual-stack tie-breaks. Follow stale
  generations, ownership transfer, rejoin and resource accounting across peers.
- **A6 — Control-plane engineer.** Trace typed configuration into dataplane
  messages, snapshots and map writes; check pool/binding index arithmetic and
  caps, event-stream framing and write serialization, generation acknowledgement,
  HA integration and partial-apply safety. Verify that Go/Rust field meanings,
  defaults and rejection behavior agree and rollback restores the intended state.
- **A7 — Linux systems engineer.** Check systemd/interface lifecycle, netlink,
  device identity and namespace/VRF isolation; nftables host enforcement;
  FRR/strongSwan configuration generation and safe command/argument boundaries;
  IPsec apply/teardown ordering and route isolation. Include startup, reload and
  failure cleanup, with management recovery and host-inbound protection explicit.
- **A8 — API/security engineer.** Check untrusted RPC/HTTP fields, authentication
  and authorization at dispatch and resource access, allowlists, principal
  propagation, integer/format handling and command/data separation. Account for
  unbounded scans/streams, cancellation, resource leaks and graceful shutdown;
  authentication alone does not establish permission or bounded resource use.
- **A9 — Telemetry engineer.** Check NetFlow/IPFIX/SNMP wire encoders and length
  fields; SNMPv3 IV/salt handling and RNG failures; goroutine/fd lifecycle;
  log-record accuracy, secret handling and backoff/retry overflow. Follow
  untrusted feed/event inputs, collector backpressure and telemetry failure
  isolation so observability cannot silently misstate or impair enforcement.
- **A10 — Protocol and tooling engineer.** Check DHCPv4/v6 and relay semantics;
  DDNS backend ownership (`PrevAddr` and foreign-record safety); simulator versus
  dataplane verdicts against an independent oracle; CLI dispatch and show-output
  correctness. Review Python/shell signing, image, package, upgrade and deployment
  tooling for integrity/authenticity checks, TOCTOU, path/scheme validation and
  recovery.

### Required cross-cutting experts

Retain A1–A10 as file-area IDs. The following are additional review roles, not
new `--area` values or disjoint file batches. Full reviews assign all three;
focused and change-based reviews assign those implicated by the selected
contracts, dependencies or workloads without expanding the requested scope.
Record applicability, named reviewer, affected areas, contract, and expected
evidence in the worklist. Record a reason for non-applicability or an explicit
coverage gap when relevant expertise cannot be supplied.

One reviewer may cover multiple roles, but each role's scope and conclusions
remain explicit; that does not count as independent verification. Include the
applicable cross-cutting checklist in each assignment. Do not discharge these
roles with an A1/A7 label or a generic `HPC/invariant check` sentence.

- **Linux kernel and NIC datapath expert.** Own the kernel/driver/userspace
  contract across A1, A6, A7 and their consumers: AF_XDP/XDP and libxdp/libbpf
  interfaces; RX/TX/fill/completion rings, descriptor publication and UMEM
  ownership/reclamation; mapped-memory and socket/map lifetime through setup,
  failure and teardown. Review `need_wakeup`, NAPI/busy-poll and interrupt/error
  paths, queue/RSS configuration, native/generic attach and zero-copy/copy modes,
  and the checksum, VLAN and segmentation offloads actually used. Follow
  redirect/drop/host-stack handoff and netfilter/nftables interaction without
  assuming userspace and kernel paths enforce identical protections.
  Challenge whether ring pressure, partial attachment, interface churn or driver
  fallback preserves ownership, forward progress and enforcement. Ground
  dependency claims in the relevant kernel, driver and library versions; an old
  workaround or historical BPF path is not the current kernel contract. Read
  `userspace-dp/src/afxdp/umem/README.md`, the relevant worker/FFI/shim docs and
  `pkg/dataplane/README.md`, then verify the participating source and modes.
- **Network protocols and firewall architecture expert.** Own packet semantics
  across A1/A2/A3/A5/A6/A7 and relevant services: Ethernet/VLAN, ARP/IPv6 neighbor
  discovery, IPv4/IPv6, TCP/UDP/ICMP, fragment and extension-header handling,
  MTU/PMTUD and generated errors. Follow supported tunnel encapsulation and
  decapsulation, routing/neighbor decisions, NAT, policy and session state in
  both directions, including asymmetric paths and HA transitions. Check that
  zone/VRF/interface identity and policy meaning survive transformations and
  cached/fast-path decisions. Challenge assumptions about packet completeness,
  classification, state freshness and the authority of control traffic; preserve
  both denied-traffic protection and permitted-traffic correctness. Read the
  relevant forwarding, NAT, routing, tunnel and HA contracts and cite applicable
  protocol requirements. Do not invent support promises or accept simulator/
  runtime agreement as an independent protocol oracle.
- **High-performance systems coding expert.** Own cost and scalability across
  packet processing, new-flow installation, shared state, HA replication,
  control updates and telemetry, not only Rust micro-optimizations. Review
  allocations, copies, syscalls, data layout and working-set size; cache locality,
  false sharing, NUMA and CPU/queue affinity; lock/atomic contention, memory
  ordering and reclamation; hash/index behavior, batching and amortized work.
  Account for growth with flows, rules, workers and peers, including fan-out,
  cancellation, expiry and recovery. Challenge whether pressure, queue skew or
  slow consumers violate bounded work, backpressure, scheduling fairness or
  management responsiveness. Preserve correctness and isolation in proposed
  optimization directions; "lock-free", "zero-copy" and "branchless" are not
  performance evidence. Read `docs/engineering-style.md`, relevant worker/queue
  docs and `docs/userspace-newflow-ceiling.md`. Use the shared workload/evidence
  requirements to distinguish source cost bounds from measured bottlenecks,
  hardware effects and end-to-end improvement.

The validation-assurance assignment also needs a **test/reliability engineer**
perspective: test registration and selection, production-path and artifact
identity, independent oracles, meaningful failure observations, concurrency and
lifecycle coverage, and false-green results. A specialist checklist guides
inspection; completing its wording is not evidence that a behavior is safe.

## 3. Review contracts, transitions, and specific sites

Assign a reviewer the whole behavior chain even when its files span areas:
configuration -> typed compilation -> wire representation -> runtime consumer ->
cached state and kernel effects. File-batch owners still report inspection
coverage. Contract owners can follow callers, shared types, consumers, and
lifecycle dependencies beyond a batch; name overlap so it is coordinated.

Start each assignment with the shared contract's adversarial discovery analysis:
the protection owed, trust boundary, actor's actual influence, and assumptions
the implementation depends on. Carry those questions through the whole behavior
chain, even when no candidate finding results. This is distinct from the later
refutation of candidate findings. Retain the analysis and unresolved assumptions
in the inspection log, and attach the relevant analysis to each candidate.

Select relevant cases from the shared contract's behavior and workload matrix.
Use documented semantics as the oracle; surface ambiguity rather than silently
changing product invariants. Compare independent implementations only alongside
an assertion of the property each independently owes.

Pattern censuses are discovery aids, with a ledger of enumerated sites,
languages/syntax covered, checks performed, exclusions, and unknowns. Useful
examples are narrowing conversions, lost config dimensions, unchecked optional
values, and incomplete error handling. Include Rust conversion/optional-value
forms when that language is in scope. A grep with no hits does not discharge a
bug class. Batch reviewers may reuse a specific verified site/invariant at the
same revision, but must not skip an entire pattern by name.

For recent-fix review, record a historical window (previous reviewed SHA,
`--since`, or an explicitly selected set of relevant fixes). Inspect each fix's
own parent-to-fix change, affected contract, sibling consumers, and regression
guard. Do not substitute `base..comparison-tip`: after a fresh checkout that
range may be empty despite many recent fixes. Reassess related dismissed claims
when their supporting assumptions or dependencies changed.

Use bounded assignments and the available concurrency; do not assume a named
agent host/tool is installed. Follow `AGENTS.md` when delegating and give each
worker the run manifest, scope, specialist persona and applicable checklist,
cross-cutting expert ownership, behavior contract, adversarial questions,
relevant history, and report location.
Limit simultaneous builds to available resources. Reallocate effort when the
next useful step needs evidence a batch cannot supply. Preserve unfinished work
and its next check; do not manufacture a negative result to complete a checklist.

## 4. Independently verify and reconcile

Refresh the selected comparison ref once for merge and pin that SHA for all
decisions. Apply the shared contract to every candidate, including dependencies
that establish reachability or safety; an unchanged evidence file alone is
insufficient. Independently check high-impact material findings and a
risk-selected sample of NEG/DUP/STALE/COHORT decisions. Log the checks and gaps.
The verifier challenges both the evidence for a defect and the evidence for
safety, including whether a cited guard covers the stated actor and all relevant
paths/transitions. Specialist discovery and independent refutation are separate
responsibilities; neither replaces the other.

Use prior final reports from `/var/tmp/deep-review-reports/`, completed history
from `/var/tmp/deep-review-finished/`, legacy `/tmp/` reports, durable
`docs/reviews/` records, and relevant issue/PR history as leads. Read finished
originals and their research-result ledgers: an archive location is not proof of
a fix or permanent dismissal. Follow [finished-review archival](references/finished-archive.md)
to resolve relocated paths and partial active/archive copies by source identity.
Read the source's lifecycle record and completed research checkpoints as well as
its reports: distinguish not yet researched, in progress, blocked and completed.
That state prevents duplicate report processing; it does not exempt changed code
or an unresolved protection question from this discovery scope.
Check repository identity before deduplication. Paginate needed
history, include relevant closed issues and fixing PRs, record freshness/limits,
and search candidate-specific bodies and acceptance criteria. A title match,
a closed issue, or an old report disposition does not decide the new claim.

## 5. Publish the report and hand off fixes

Write one self-contained draft inside the run directory using the shared
contract's header, per-finding fields (including Adversarial analysis and Probe),
inspection log, filing ledger, and counts. Clearly distinguish confirmed findings,
unresolved high-impact questions, verification gaps, and suggested implementation
work.
A review report is not an issue filing: say "recommended for filing" unless
actual issue IDs exist.

Write `/var/tmp/deep-review-reports/<WHOAMI>-review-<REVIEW_SLUG>-NNN.md`, for example
`/var/tmp/deep-review-reports/gpt-5.6-sol-review-ha-failover-001.md` only when
that model is evidenced.
Use the shared filing/provenance contract to mark each finding's actual issue
status, originating model, issue URL and verified origin tags. When filing is
authorized during the run, reconcile that ledger before freezing the report;
acquire any required source processing claims before the contract's shared
repository filing mutex, then any per-report lock,
and hold it through filing, readback and publication. A finding discovered here
uses `source:deep-review`; later research does not replace its source/model credit.
When filing happens later, return the self-contained triage result with the
updated ledger alongside the unchanged original. Never label drafts or existing
issues as newly opened.

The filename shape remains recognizable as a review; it does not justify
another model's prefix. Use the identity established for this run, never an
inherited shell `WHOAMI` or a prior report's family.
Before publication, independently re-derive `WHOAMI` from the recorded identity
and `REVIEW_SLUG` from the review name. Check that the manifest, report header
and final basename agree. A mismatch blocks publication until reconciled;
no "compatibility family" override exists.
Determine the next number from exact final basenames in
`/var/tmp/deep-review-reports/`, `/var/tmp/deep-review-finished/` and the legacy
`/tmp/` location for that
`WHOAMI` and `REVIEW_SLUG` at
publication time. A new model/review pair can begin at 001;
deduplication still reads named and legacy reports across all model prefixes.
Read [report storage and publication](references/report-storage.md) before
publishing. Both roots are under `/var/tmp`; verify filesystem identity before
using a hard link. Publish atomically create-if-absent, never
copy into a visible final pathname or overwrite a collision. Update the draft's
output-path header before retrying another number. Keep published reports and
their source drafts immutable. Only complete finals belong in
`/var/tmp/deep-review-reports/`; all named working files remain under the owned
`/var/tmp/deep-review-work/` run.
Do not relocate reports during discovery or create compatibility aliases.
Completed research later archives the source and result through the shared
finished-review procedure; discovery must keep consulting those archived records.

Verify the published report is complete and the artifact references resolve.
Register the verified source and hash as `PENDING` in
`/var/tmp/deep-review-work/state/reviews/<review-key>.json` through the lifecycle
contract. Reconcile an existing record rather than resetting its progress. If
publication succeeds but registration does not, return the exact pending state
write; consumers recover it from the verified source, not a duplicate report.
Preserve test-only diffs, outputs, manifest, and supporting evidence until
archived or handed off; include the decisive evidence inline so the report does
not depend on a worker checkout. Cleanup only recorded owned worktrees, using
normal `git worktree remove` after preserving evidence. If removal would require
force, retain the path and explain why. Never sweep other runs by glob.

For each actionable finding, provide the expected behavior, fix direction,
regression acceptance criterion, affected consumers, and remaining validation.
Release-oriented runs also track whether a verified source fix has reached the
in-scope release. Further implementation/publication follows the authorized
engineering workflow.

## Maintaining this skill

When revising discovery or triage, use the shared contract's decision walkthrough.
Use its held-out evaluation before claiming improved defect recall. Formatting
validation alone does not establish that improvement. Report which behavioral
checks ran and which claims remain unmeasured.
