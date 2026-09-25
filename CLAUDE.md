# xpf - Junos-Style Firewall With AF_XDP Userspace Dataplane

> Dataplane notice (#1373, complete): the eBPF dataplane retirement is done.
> The Rust AF_XDP userspace dataplane is the only runtime forwarding path.
> The legacy BPF source was deleted in #1476; explicit `system dataplane-type
> ebpf` is hard-rejected at commit (`ErrEBPFDataplaneRetired`, `pkg/config`
> compiler) and at runtime (`ErrEBPFBackendRetired`, `pkg/dataplane/dataplane.go`).

## Working Style
- Think before acting. Read existing files before writing code.
- Be concise in output but thorough in reasoning.
- Prefer editing over rewriting whole files.
- Do not re-read files you have already read.
- Test your code before declaring done.
- When modifying code or changing behavior, update the relevant module
  documentation in the corresponding Markdown files as part of the same work.
  Treat README/design/state/operator docs as part of the module contract; if no
  docs change is needed, say why in the review notes.
- Write complete commit messages. Use a specific subject plus a body that
  describes the reason for the change, the important implementation details,
  and the validation performed. Wrap body paragraphs and bullets to readable
  terminal width, roughly 72 columns. Do not use terse checkpoint-style messages
  for production work.
- No sycophantic openers or closing fluff.
- Keep solutions simple and direct.
- When working with many teams, don't let the context windows get too large.

**Read `docs/engineering-style.md` before writing non-trivial code or
reviewing a PR.** It encodes the coding and review discipline this
project has settled on — hot-path allocation rules, review severity,
compile-time invariants, PR discipline, and the project-specific
gotchas that repeatedly bite (deploy wipes CoS, iperf3 target, etc.).

## Required Reading

Read these BEFORE starting work, not after getting stuck. They are the
contract; a PR that violates one of them gets sent back regardless of
whether the code is correct.

| File | Read it when | What it governs |
|------|--------------|-----------------|
| `docs/engineering-style.md` | before ANY non-trivial code or PR review | hot-path allocation rules, review severity, compile-time invariants, PR discipline, shared-cluster protocol, the project gotchas that repeatedly bite (deploy wipes CoS, iperf3 target, etc.) |
| `~/.claude/RTK.md` | before running shell commands in bulk | the `rtk` token-optimizing CLI proxy. A hook transparently rewrites most commands (`git status` → `rtk git status`), but the meta commands (`rtk gain`, `rtk discover`, `rtk proxy <cmd>`) must be invoked directly. Use `rtk proxy <cmd>` when you need UNFILTERED output for debugging — filtered output has dropped the line you are looking for more than once. |
| `AGENTS.md` | before splitting work across agents | orchestrator / architect / implementor role boundaries, worktree assignment, overlap prevention, and the rule that agents keep working until they hit a real stopping point |
| `COMMITAGENT.md` | before driving a stacked branch series | stack ownership, narrow helper roles, and the commit/stack discipline |
| `README.md` | when touching a public-facing surface | what the product claims to do; a behaviour change that contradicts it is a docs bug too |
| `docs/config-schema.md` | before adding a config-mode leaf | `setSchema` typed leaves, multi-value leaves, bracketed-list collapse (#2419 class) |
| the module's own `README.md` / `docs/*.md` | in the SAME change as the code | updating them is part of the contract, not follow-up work. If none is needed, say why in the review notes. |

Sub-agents inherit this file automatically, but NOT the reasoning behind
it. When dispatching a lane, name the specific documents its task
touches — a brief that says "read engineering-style.md" is followed; one
that assumes the agent already did is not.

## Logging Rules
- Maintain a log of all major actions in **`docs/log/<issue>.md`** — one file per
  issue or PR. Do **NOT** append to the repository-root `_Log.md`; it is the
  historical record up to #6874 and is now closed to new entries.
  - Why: `_Log.md` was an append-only file every lane wrote to, so every branch
    touched the same trailing region. That made it an **O(n^2) serialization
    point** — merging one PR flipped every other open PR to CONFLICTING, and
    resolving one did not help the others. Measured on a 30-PR board: 19 of 30
    flipped within seconds of one merge, with `_Log.md` the ONLY conflicting
    path on every branch sampled.
  - A `merge=union` driver is NOT the fix and must not be added for this file:
    it fuses two same-minute entries into one malformed entry and exits 0. See
    `docs/log/README.md` for the measurement.
- Use YAML or Markdown bullet points for structure:
    - **Timestamp**: [Time]
    - **Action**: [Brief Description]
    - **File(s)**: [Modified Files]
- Log every `[Write|Edit]` action.
- **Go**: Use `slog.Debug` for high-frequency/diagnostic messages (HA watchdog sync, per-session traces). Use `slog.Info` only for state transitions and one-time events. HA watchdog sync was flooding at 15 req/s with `slog.Info` — caused 35K+ log lines per session and drowned real diagnostics.
- **Rust helper**: `eprintln!("xpf-ha: ...")` goes to journald via stderr. Use sparingly — remove debug eprints before committing. Keep per-worker `RefreshOwnerRGs`/`FlushFlowCaches` logs (they fire rarely, only on RG transitions).
- **Never** add `slog.Info` inside loops that run per-packet, per-session, or per-poll-tick. If you need per-tick logging, use `slog.Debug`.
- **Control socket contention**: The userspace helper control socket is shared by status poll (1/s), HA sync, session installs, snapshot sync, and forwarding sync. High-frequency callers MUST be throttled. Adding a new control socket request at >1/s will starve session installs during bulk sync.

## What This Is
A Junos-style firewall that clones Juniper vSRX capabilities using native
Junos configuration syntax. The primary dataplane target is the Rust AF_XDP
userspace helper (`userspace-dp`) driven by the Go control plane. The eBPF
dataplane retirement (#1373) is complete: the legacy XDP/TC source was deleted
in #1476 and the eBPF backend is hard-rejected at commit and runtime — the
userspace helper is the only runtime forwarding path.

## Quick Start
```bash
make generate        # Rebuild retained Rust AF_XDP shim — ONLY needed when
                     # userspace-xdp/ source changed; pinned toolchain +
                     # kernel-verifier gate (#1864, see pkg/dataplane/README.md)
make build           # Build xpfd daemon (uses the git-tracked shim .o — does
                     # NOT require make generate)
make build-ctl       # Build remote CLI client
make build-userspace-dp # Build the primary Rust AF_XDP dataplane helper
make test            # Run BOTH the Go suite AND the Rust userspace-dp
                     # cargo suite (#4006) — a Rust dataplane regression
                     # fails `make test`. `make test-go` / `make test-rust`
                     # run one leg. The Rust leg needs cargo (~minutes).
make selftest        # Run ALL day-0/image/dist/deploy self-tests
                     # (scripts/run-selftests.sh) in one fast hermetic pass —
                     # grow-root, bake sign-order, dist roundtrip, validate.py
                     # helpers, xpf-deploy mixed-base HA gate. Tool-gated legs
                     # SKIP. Run before touching image/day-0/dist/deploy tooling.
make harness-census  # Reachability census over the RUNNABLE harnesses, one
                     # layer above `make selftest` (#8302). Every harness under
                     # test/incus/ + scripts/userspace-*.sh must be INVOKED by a
                     # Makefile recipe (directly or transitively) or declared in
                     # test/incus/HARNESSES.unreached with a reason — a comment,
                     # a similarly-named target, a `bash -n` lint and a bare path
                     # in a lint list all do NOT count. Hermetic, <1 s; also runs
                     # inside `make selftest`.
make test-harness-census-lib # Self-test the census itself (mutation cells: a
                     # census with a broken matcher reports a CLEAN BOARD, so
                     # each defence is asserted by a fixture AND by a mutation
                     # that must flip it). Hermetic.
```

## Test Environment (Incus VM)
```bash
make test-env-init   # One-time: install incus, create networks + profiles
make test-vm         # Create Ubuntu 26.04 VM with FRR, strongSwan
make test-deploy     # Build -> push xpfd+cli+helper (each sha256-verified ==
                     #   local build) + config + unit -> systemctl enable --now,
                     #   then assert the RUNNING xpfd == pushed build + base-unit
                     #   ExecStart (reconciles stale #1917 version pins / dangling
                     #   sbin symlinks, #2162/#2176). Override target instance with
                     #   XPF_INSTANCE=<name> (default xpf-fw).
make test-deploy-lib # Self-test the deploy reconcile/sha-verify helpers (no VM)
make test-mutate-lib # Self-test the mutation-harness scoring library
                     #   (scripts/mutate-lib.sh). Hermetic — fixture logs, no
                     #   repo/compiler/cluster. The cell that matters is the
                     #   REFUSAL one: a runner gating in ONE language scores
                     #   every cross-language mutation as an ESCAPE, because
                     #   nothing it ran could have failed — and an escape is a
                     #   claim that the code is untested. Also pins the VOID
                     #   cases, which are neither kill nor escape — a build
                     #   break, a run that collected nothing, and a full disk
                     #   (which reds NAMED tests and reads like a regression)
                     #   — and separately two misreads that LOSE a real kill:
                     #   a -race failure emits no `--- FAIL` line at all, and
                     #   `make`'s echoed Makefile comments are not a build
                     #   break.
                     #   #7611 added the FIFTH void shape, a HANG, which is the
                     #   worst: the other four each leave a trace (a compiler
                     #   diagnostic, an unchanged tree, a panic trace, a DATA
                     #   RACE banner) and a hang leaves none — and its blast
                     #   radius exceeds its own cell, because the budget it
                     #   burns belonged to every LATER cell, so one hang can be
                     #   recorded as a screen full of escapes nobody earned.
                     #   mutate.sh bounds each cell (MUTATE_CELL_TIMEOUT) and
                     #   treats an unfinished run as VOID; go's own -timeout
                     #   panic is the informative signal because its goroutine
                     #   dump NAMES the stuck test. Never score a run that
                     #   consumed its whole budget.
                     #   #8213: `^--- FAIL` is itself UNSOUND — parallel
                     #   `go test -v` interleaves MID-LINE, so a real
                     #   `--- FAIL` can land off column 0 and the cell scores
                     #   as an ESCAPE, which argues for weakening the TEST.
                     #   Counting is now splice-tolerant; ATTRIBUTION is not
                     #   fixable by counting at all (a spliced kill beside an
                     #   unrelated clean failure scores KILLED for the WRONG
                     #   test, with rc and count agreeing). Score
                     #   `go test -json` on Action=="fail" and compare the
                     #   NAME against the cell's target.
make test-cluster-lock-lib # Self-test the #1875 lock + #4020 destructive-smoke
                     #   lock preamble (no cluster — private lock path, mocked incus)
make test-cos-apply-lib # Self-test the #6440 CoS-apply CLI-transcript gate:
                     #   the piped-stdin CLI is a REPL that prints "error: ..."
                     #   and still exits 0, so apply-cos-config.sh verifies the
                     #   CLI's success markers, not the session exit status.
                     #   Hermetic (mocked incus) + the Go marker contract.
make test-fbf-steering-lib # Self-test the #6936 FBF two-upstream steering
                     #   verdicts. The defect it guards is a NEGATIVE CELL
                     #   THAT FAILS TO A HEALTHY VALUE: the main-table
                     #   pollution check counted matches, so "no leak" and
                     #   "the probe returned nothing" both scored 0 = PASS.
                     #   The verdict is now TOTAL and the selftest table
                     #   carries the probe-blind middle row. Hermetic + the
                     #   Go predicate that every config-committing smoke uses
                     #   the #6440 marker gate.
make test-host-inbound-lib # Self-test the #6936 ON-WIRE host-inbound
                     #   verdicts. A probe CANNOT observe a deny — it observes
                     #   SILENCE, and "the firewall dropped it" and "my prober
                     #   never reached the firewall" are the same reading. So
                     #   every DENY cell is scored against a positive control
                     #   at the SAME ADDRESS in the SAME run, and the selftest
                     #   carries the middle row (same expectation, same
                     #   observation, only the control differs). Hermetic.
make test-host-inbound / test-host-inbound-failover # The smoke itself
                     #   (loss cluster). Covers host-inbound on a TAGGED VLAN
                     #   sub-unit and admission UNCHANGED across an RG
                     #   failover. Commits NOTHING — it reads the committed
                     #   config, derives its probe targets from it, and
                     #   refuses to run if the zone posture went stale.
make test-cluster-env-lib # Self-test the cluster-env resolver (#5024): $FW0/
                     #   $FW1/$CLUSTER_LAN_HOST derive from each env's VM0/VM1/
                     #   LAN_HOST and get INCUS_REMOTE-qualified (no cluster)
make test-iperf-throughput-lib # Self-test the #6897 iperf3 throughput parse +
                     #   verdict used by test-failover.sh. The defect it guards
                     #   is a MISSING CELL, not a wrong number: the old parse
                     #   matched only "Gbits", so a sub-Gbit run matched neither
                     #   the pass nor the fail branch and the gate emitted
                     #   NOTHING while still summarising "0 failed". Hermetic.
make test-newflow-ceiling-lib # Self-test the #4800 connection-rate analysis
                     #   layer (synthetic snapshot pairs -> new-flows/sec +
                     #   which contention site saturated), the newflow-gen
                     #   generator crate, which lives outside the dataplane
                     #   workspaces so root `cargo test` does not reach it,
                     #   AND the #6962 harness NODE SELECTION. That defect
                     #   was an unanchored `grep -qi "primary"` over `show
                     #   chassis cluster status`, which prints BOTH nodes'
                     #   rows on whichever node you ask — so it matched the
                     #   PEER's row and always chose $FW0. It failed to a
                     #   PLAUSIBLE VALUE (a node name), not to an error. The
                     #   fixtures give the two nodes DIFFERENT states, the
                     #   only shape in which the anchor is observable.
                     #   Hermetic — no cluster. See
                     #   docs/userspace-newflow-ceiling.md
make test-ssh        # Shell into VM
make test-status     # Instance + service + network info
make test-logs       # journalctl -u xpfd -n 50
make test-journal    # journalctl -u xpfd -f (follow)
make test-start      # systemctl start xpfd
make test-stop       # systemctl stop xpfd
make test-restart    # systemctl restart xpfd
make test-destroy    # Tear down VM
```

If `incus` commands fail with permission errors, use `sg incus-admin -c "make ..."`.

**Ubuntu 26.04 parity (#1943):** the test VM uses `images:ubuntu/26.04/cloud`
to match the production appliance base (`scripts/image/bake.py`). Pin a
different Ubuntu release with `XPF_BASE_RELEASE=<rel> make test-vm` (the test VM
tracks whatever release production was last baked at — a deliberate, reviewed
bump, not auto-latest). The `xpf-vm` profile sets `security.secureboot: "true"`
so shim->grub->kernel + AF_XDP-shim-under-Secure-Boot is the default posture.
A vanilla Secure-Boot VM does NOT exercise the #1930 A4 kernel promote/rollback
channel — that needs the baked qcow2 (the `xpf-uefi-slots`/`09_xpf` A/B-ESP
substrate lives only in `bake.py` output). Rollback to Debian is `git revert`,
not a runtime `IMAGE_VM` override (the scripts now use Ubuntu package names + a
>= 6.18 kernel floor).

## Cluster Test Environment (Two-VM HA)

**Smoke tests run ONLY on the loss userspace cluster** (`loss:xpf-userspace-fw0/fw1`).
The Makefile `cluster-*` targets now default to that userspace cluster via
`test/incus/loss-userspace-cluster.env`. Use `loss-cluster-*` only for the
older loss cluster, and set `CLUSTER_ENV=` only when intentionally exercising
the original local `xpf-fw0/xpf-fw1` regression environment.

**Cluster ownership (#1875):** the loss cluster is SHARED. Deploys,
`apply-cos-config.sh`, AND the destructive HA smoke targets
(`test-failover` / `test-ha-crash` / `test-double-failover` /
`test-stress-failover` / `test-chained-crash` / `test-active-active` /
`test-restart-connectivity` / `test-private-rg` — they reboot /
force-stop / fail over a node) self-lock `/tmp/xpf-cluster.lock` via the
`cluster-cell.sh` preamble (#4020), so a reboot QUEUES behind another
agent's deploy/smoke instead of colliding — wait, NEVER kill another
holder, NEVER `rm` the lock file. Wrap multi-command work in a lock
cell: `./test/incus/with-cluster.sh "purpose" -- cmd...`. NEVER
hand-roll `incus file push` binary deploys — they bypass the lock and
the verify-dataplane gate. `make test-cluster-lock-lib` self-tests the
lock (no cluster). Full protocol: `docs/engineering-style.md`.

```bash
# === SMOKE (loss userspace cluster, default for all userspace-dp validation) ===
make cluster-deploy
make cluster-ssh NODE=0
./test/incus/apply-cos-config.sh loss:xpf-userspace-fw0   # deploy wipes CoS — re-apply

# === LEGACY (local xpf-fw0/1, regression-only — do NOT use for smoke) ===
make CLUSTER_ENV= cluster-init    # Create networks + profile for local HA cluster
make CLUSTER_ENV= cluster-create  # Launch xpf-fw0, xpf-fw1, cluster-lan-host
make CLUSTER_ENV= cluster-deploy  # Build + push to both legacy VMs + restart
make CLUSTER_ENV= cluster-destroy # Tear down legacy cluster VMs
make CLUSTER_ENV= test-failover             # Reboot fw0 during iperf3 — local regression
make CLUSTER_ENV= test-ha-crash             # Force-stop/daemon-stop/multi-cycle crash recovery
make CLUSTER_ENV= test-restart-connectivity # Verify restart behavior on local regression cluster
```

Or use `test/incus/cluster-setup.sh` directly with `BPFRX_CLUSTER_ENV` set:
`{init|create|deploy all|destroy|ssh 0|1|status|logs 0|1}`.

**IMPORTANT:** Any change touching cluster, VRRP, session sync, or failover code MUST pass `make test-failover` before commit.

`make test-failover` (and the sibling HA smoke targets) run on the loss
userspace cluster by default and need **no** `CLUSTER_LAN_HOST` override —
`cluster-env.sh` derives the LAN host from the env's `LAN_HOST`
(`cluster-userspace-host`) and remote-qualifies every instance ref with
`INCUS_REMOTE` (`loss:`), so `$CLUSTER_LAN_HOST` resolves to
`loss:cluster-userspace-host` on its own (#5024). A **bare** override is
still remote-qualified (`CLUSTER_LAN_HOST=cluster-userspace-host` →
`loss:cluster-userspace-host`); `make test-cluster-env-lib` guards this.

## Architecture

> [!IMPORTANT]
> DPDK dataplane retired in #1525. Do not add new DPDK code. The
> `dpdk_worker/` C tree and `pkg/dataplane/dpdk/` Go manager are
> removed in #1527/#1528.

The legacy BPF pipeline source was deleted in #1476 (mechanical source
removal phase of the #1373 eBPF retirement umbrella). All new
packet-forwarding work happens in `userspace-dp` and its `userspace-xdp`
AF_XDP shim. The historical 14-program tail-call pipeline (XDP ingress
main → screen → zone → conntrack → policy → nat → nat64 → forward; TC
egress main → screen_egress → conntrack → nat → forward) is preserved
in git history; `git log -- bpf/xdp/ bpf/tc/` walks the deleted source.

### Key Design Patterns (retained Rust AF_XDP shim + userspace-dp)
- **Userspace AF_XDP shim** (`userspace-xdp/src/lib.rs`): per-CPU
  binding arrays steer packets from native XDP to userspace queues.
- **Dual session entries** (forward + reverse) in the shared conntrack
  HASH map continue to back HA session-sync.
- **Three-phase config compilation**: Junos AST → typed Go structs →
  userspace-dp control messages (no eBPF map writes after #1476).
- **FRR-managed routing**: all routes (static, DHCP, per-VRF) via
  managed section in `/etc/frr/frr.conf`.
- **Full interface management**: xpfd owns ALL interfaces on the
  firewall — renames them via `.link` files, configures addresses/DHCP
  via `.network` files, and brings down unconfigured interfaces.

### APIs
- **gRPC** on 127.0.0.1:50051 — 48+ RPCs (config, sessions, stats, routes, IPsec, DHCP, cluster). Per-principal authorized server-side since #5278: a `stats.Handler` resolves the connection's peer UID at connection setup and unary+stream interceptors evaluate the caller's `system login` class (shared `pkg/authz` decision) before any handler runs. Unmapped method = deny; the fabric listener keeps its own #4107/#4122 chain
- **HTTP REST** on 127.0.0.1:8080 — health, Prometheus metrics, config endpoints
- **CLI** — Interactive Junos-style with tab completion, `?` help, `| match` pipe
- **Remote CLI** — `cli` binary connects via gRPC
- **Command Trees (two-SSOT split, #1319)** — `pkg/cmdtree/tree.go` is the single source of truth for the **operational** tree (`run`/`show`/`clear`/`request`/...): tab completion + `?` help across local CLI, remote CLI, and gRPC. The **config-mode `set`/`delete`/`show`/`edit` grammar** (structural completion, flat-set token grouping, value-slot `?` completion, AND commit-check typed-leaf validation) is owned by `config.setSchema` in `pkg/config/schema.go` (completion helpers in `pkg/config/schema_complete.go`) + `config.SchemaValidate` in `pkg/config/schema_walk.go` — NOT cmdtree. Config-mode completers route `set` paths through `config.CompleteSetPathWithValues`. Add a config-mode typed leaf by editing `setSchema` (see `docs/config-schema.md`); add an operational command by editing cmdtree.

## Code Layout
| Path | Description |
|------|-------------|
| `bpf/headers/*.h` | Shared C structs (common, maps, helpers, conntrack, nat) consumed by the retained Rust AF_XDP shim build (`MAX_INTERFACES`) and userspace-dp parity tests. The legacy `bpf/xdp/*.c` and `bpf/tc/*.c` source were deleted in #1476. |
| `pkg/config/` | Junos parser, AST, typed config, compiler |
| `pkg/cmdtree/` | Single source of truth for all CLI command trees |
| `pkg/configstore/` | Candidate/active/commit/rollback, atomic DB persistence, JSONL audit journal |
| `pkg/dataplane/` | Manager type (kept for Manager.LoadUserspaceShim + accessors), retained Rust AF_XDP shim loader in `loader_userspace_shim.go`, retirement-error sentinels (#1476). Legacy bpf2go bindings deleted in #1476. |
| `pkg/dataplane/userspace/` | Go manager for the Rust AF_XDP userspace dataplane |
| `pkg/daemon/` | Daemon lifecycle (TTY detection, signal handling) |
| `pkg/cluster/` | Chassis cluster HA (state machine, session sync, config sync, IPsec SA sync) |
| `pkg/cli/` | Interactive Junos-style CLI |
| `pkg/conntrack/` | Session garbage collection (with HA delete sync callbacks) |
| `pkg/logging/` | Ring buffer reader, event buffer, syslog client |
| `pkg/dhcp/` | DHCPv4/DHCPv6 clients |
| `pkg/frr/` | FRR config generation + managed section in frr.conf |
| `pkg/networkd/` | systemd-networkd .link/.network file generation |
| `pkg/routing/` | GRE tunnels, VRFs, XFRM interfaces, rib-group + next-table route leaking via netlink |
| `pkg/ipsec/` | strongSwan config + SA queries |
| `pkg/api/` | HTTP REST API + Prometheus collector |
| `pkg/grpcapi/` | gRPC server + protobuf bindings |
| `pkg/flowexport/` | NetFlow v9 exporter |
| `pkg/feeds/` | Dynamic address feed fetcher |
| `pkg/dhcpserver/` | Kea DHCP server management |
| `pkg/eventengine/` | Event-driven automation engine |
| `pkg/rpm/` | RPM probe manager |
| `proto/xpf/v1/` | Protobuf service definition |
| `cmd/xpfd/` | Daemon main binary |
| `cmd/cli/` | Remote CLI client binary |
| `pkg/vrrp/` | Native VRRPv3 state machine (30ms RETH advertisements, AF_PACKET, IPv6 NODAD) |
| `pkg/ra/` | Embedded RA sender (replaces radvd) |
| `docs/` | Protocol docs, feature gaps, phase notes, test plans, memory backups |
| `test/incus/` | Test environment (setup.sh, config, systemd unit) |
| `userspace-xdp/` | XDP shim for AF_XDP packet steering |
| `userspace-dp/` | Primary Rust AF_XDP userspace dataplane helper |

## Critical Patterns to Know

### Byte Order
- Use `binary.NativeEndian.Uint32(ip4)` for BPF `__be32` fields — **NOT** `BigEndian`
- cilium/ebpf serializes map values in native endian; IP bytes are already in network order

### C/Go Struct Alignment
- When mirroring C structs in Go for cilium/ebpf, always match `sizeof` in C
- Add trailing `Pad [N]byte` fields to reach C compiler's struct alignment

### Parser Dual AST Shape & Set Syntax Testing
- Hierarchical `family inet { dhcp; }` → `Node{Keys:["family","inet"]}` with children
- Flat `set protocols bgp group g1 neighbor 10.0.0.1 peer-as 65001` → a CHAIN,
  one node per leaf, each nested under the previous leaf's node:
  `[protocols] > [bgp] > [group g1] > [neighbor 10.0.0.1] > [peer-as 65001]`
- Compiler must handle **both** shapes
- **`family inet` is NOT an example of the difference** — do not use it as one.
  `family` is declared `compoundKey: true`, so `SetPath` consumes the sub-key
  into the same node exactly as the hierarchical parser does, and the two trees
  come out **structurally identical** (`Keys=["family","inet"]` either way; they
  differ only in the `Line`/`Column` source positions the hierarchical parser
  records and `SetPath` leaves zero, which nothing reads for shape). This bullet
  previously used `family inet` to illustrate a divergence that does not exist
  there (#8808), which is wrong in the direction that makes people skip a
  measurement: a compiler tested only against `family inet` looks shape-agnostic
  while being blind to every non-compound container. `pkg/config/ast_shape_doc_8808_test.go`
  pins both claims so this cannot rot again.
- **Bracketed lists (`[ a b c ]`) collapse onto ONE leaf's Keys in BOTH shapes (#2419).** The lexer strips `[`/`]`, so `from protocol [ tcp udp icmp ]` becomes a single leaf `Keys=["protocol","tcp","udp","icmp"]` whether parsed hierarchically or via flat-set `SetPath`. A `multi: true` leaf in `setSchema` absorbs every trailing non-sibling token onto its node key. A compiler reading a multi-value leaf MUST read `child.Keys[1:]` AND `child.Children` and accumulate (use `firewallMatchValues`); reading only `Keys[1]` drops all but the first list value (the #2419 bug). See `docs/config-schema.md` "Multi-value leaves and bracketed lists".
- **Testing flat set syntax:** ALWAYS use `ParseSetCommand()` + `tree.SetPath()` loop, NEVER `NewParser()` — the parser treats newlines as whitespace and will merge all set lines into one giant node

### BPF Verifier
- Branch merges lose packet range — re-read `ctx->data`/`ctx->data_end` after branches
- Combined stack limit is 512 bytes across call frames — use `__noinline` and scratch maps
- Variable-offset pkt pointer: verifier refuses range tracking when `var_off` is wide (0xffff) — use constant-offset from validated pointer instead
- **Narrowing meta offsets**: when using `meta->l3_offset` (u16) for packet pointer math, mask with `& 0x3F` to narrow var_off so verifier can track range (`66833c5`)
- `__u16` type causes sign-extension (`smin=-32768`) — fails for pkt pointer math
- `iter.Next(&key, nil)` crashes in cilium/ebpf v0.20 — always use `var val []byte`
- xdp_zone fails verifier on kernel 6.12 (NAT64 complexity) — passes on 6.18+

### TTY Detection
- Use `unix.IoctlGetTermios(fd, TCGETS)` — **not** `os.ModeCharDevice` (`/dev/null` is a CharDevice)

### Interface Management (networkd)
- **xpfd manages ALL interfaces** on the firewall — no external networkd configs needed
- Every interface must be defined in the firewall config and assigned to a security zone
- Interfaces not in the config are brought down and marked `ActivationPolicy=always-down` in networkd
- VRF devices and tunnel interfaces created by the daemon are excluded from unmanaged detection
- **`.link` files**: written per-interface, prefix `10-xpf-`, rename kernel names (enp7s0→ge-0-0-0)
  - Startup naming: `enumerateAndRenameInterfaces()` in `pkg/daemon/linksetup.go` runs at daemon start, assigns vSRX names (fxp0, em0, ge-{FPC}-0-{PORT})
  - Non-RETH interfaces: match by `MACAddress=` (MAC is stable)
  - RETH member interfaces: match by `OriginalName=` (PCI kernel name) — MAC alternates between physical (boot) and virtual (daemon), so `MACAddress=` is unreliable
  - `ensureRethLinkOriginalName()` auto-fixes stale `.link` files that use `MACAddress=` for RETH members
- **`.network` files**: configure addresses (static), DHCP avoidance, RA disable, VLAN parent flags
  - `KeepConfiguration=static` on RETH interfaces preserves VRRP VIPs across `networkctl reload`
- Stale files are auto-removed; `networkctl reload` called only when files actually change
- **DHCP interfaces**: daemon's DHCP client manages the address; address reconciliation is skipped
- **Bootstrap (#1922 lifeline, #7114 appliance gate)**: on a NORMAL boot the
  daemon's `enumerateAndRenameInterfaces()` runs at startup and writes the
  `.link` files. On a BOOTSTRAP boot (nothing ever committed) the full rename
  loop is suppressed: `setupBootstrapLifeline` identifies the mgmt NIC by the
  active default route and, only if that NIC is enumeration index 0, renames
  just it to fxp0 and writes the bootstrap fxp0 DHCP `.network`. With no default
  route it claims NOTHING (console-only) — that guard keeps a foreign host
  reachable on its own config. The appliance image has no such config (the bake
  purges cloud-init/netplan), so `scripts/image/bake.py` writes
  `/etc/xpf/appliance`; with that marker present AND `EverCommitted()` false the
  lifeline falls back to the first enumerated NIC, restoring the image's
  vNIC#1 -> fxp0 factory contract on that artifact only (`isApplianceFactoryBoot`
  / `chooseBootstrapLifeline`, `docs/install-images.md`)
- DHCP-learned default routes get admin distance 200 in FRR (lower priority than static routes). DHCP-learned classless routes are also lower priority: FRR and the management-VRF twin suppress a learned prefix contained by a rendered/operator static route in the same table, with a visible warning. In table 999, only operator routes stamped `RTPROT_STATIC` are authority; xpf-owned `RTPROT_DHCP` and connected/kernel routes are silently ignored, while unexpected other-protocol routes are warned and ignored. An option-121 `/0` follows the normal DHCP-default suppression contract; unusually broad classless `/1` prefixes and non-forwardable martian ranges (`0/8`, `127/8`, `169.254/16`, `224/4`, `240/4`) are refused by default. Set `XPF_DHCP_TRUST_CLASSLESS_OVERRIDE=1` only when deliberately trusting the DHCP server; it restores covered/broad/martian learned classless routes and emits a loud security warning.
- **Device-map mode (#1956, bare metal)**: an opt-in `set chassis device-map`
  stanza replaces positional naming with a STABLE-IDENTITY managed allowlist.
  When `len(chassis device-map entries) > 0`, the daemon renames ONLY the
  mapped NICs (by PCI bus address with permanent-MAC fallback, via
  `enumerateAndRenameMapped` in `pkg/daemon/device_map.go` → `pkg/devicemap`),
  and everything not named is governed by `unmapped-interface-policy`
  (`leave-alone` default = invisible to xpf; `manage-down` = today's
  claim-all). No map = positional mode, bit-identical to pre-#1956.
  Key invariants: BOTH rename sites branch (normal boot + bootstrap-exit);
  the bring-down reconcile (`compiler_iface.go`) SKIPS unmapped NICs under
  leave-alone; topology-change detection REFUSES a binding when PCI matches
  but the permanent MAC differs (card swapped — never silent hijack); RETH
  members stay PCI-keyed + `OriginalName=` (their MAC alternates); collision-
  safe multi-pass rename breaks stale-udev EEXIST; a commit pre-flight rejects
  a map that would strand management on next boot (validating the rollback
  target too for `commit confirmed`); a managed→unmapped teardown runs BEFORE
  `networkd.Apply`. **§9.6: no auto-fxp0 / no bootstrap DHCP in device-map mode**
  — the console is the lifeline on bare metal; `fxp0` is bindable only if the
  operator explicitly maps a NIC to it. `show chassis device-map [candidates]`
  lists NICs to author a map without hand-typing PCI BDFs. Operator doc:
  `docs/bare-metal-device-map.md`.

### XDP on SR-IOV Interfaces
- **iavf (VF driver) has NO native XDP support** — only generic/SKB mode works, which creates a full `sk_buff` per packet (~16% CPU overhead from `memcpy_orig` + `memset_orig`). Performance drops from 25+ Gbps to ~6.8 Gbps
- **i40e/ice (PF driver) has native XDP** — driver-mode XDP processes packets before SKB allocation, much faster
- **`bpf_redirect_map` requires `ndo_xdp_xmit` on target** — you cannot redirect from a native XDP program to an interface that lacks native XDP support. If the target doesn't implement `ndo_xdp_xmit`, the redirect silently fails. This means mixing native+generic interfaces in a redirect set does not work
- **xpf workaround: `redirect_capable` map** — per-interface flag checked in `xdp_forward.c`. Interfaces without native XDP get `XDP_PASS` (kernel forwarding path) instead of `bpf_redirect_map`. This lets native interfaces redirect between each other while non-native interfaces fall back to kernel forwarding
- **XDP on PF does NOT see VF traffic** — SR-IOV hardware switching delivers VF packets directly to VFs, bypassing the PF's XDP program entirely. You cannot use PF XDP to firewall VF traffic. Each VF would need its own XDP program (but iavf doesn't support native XDP, so that's generic-only)
- **Current test env uses PF passthrough (i40e)** — the entire PF (`enp10s0f0np0`) is passed through to the VM via VFIO, not a VF. This gives native XDP on the WAN interface. All interfaces (virtio + i40e PF) run native XDP
- **The loss userspace cluster (`loss:xpf-userspace-fw0/fw1`) is a different env** — its dataplane interfaces (`ge-0-0-1`/`ge-0-0-2`) are **mlx5_core SR-IOV VFs** (`ethtool -i` → `driver: mlx5_core`), not i40e, and these VFs **do** support native XDP and exact/masked ntuple steering (verified in #1649 research plan, commit `36fcd1b8`). Each VF exposes **6 combined RX queues → 6 workers** — the denominator for the per-flow CoV floor in `docs/fairness-regimes.md`. The i40e PF-passthrough note above is the standalone test VM, not this cluster
- **Why not VF passthrough** — VFs use the iavf driver which forces generic mode. Even with the `redirect_capable` workaround, the WAN interface itself runs in generic XDP which is slower for ingress processing. PF passthrough avoids this entirely
- **Gotcha: PF passthrough claims the whole NIC** — no VFs can be used by other VMs when the PF is passed through. For multi-VM setups, VF passthrough with generic XDP + `redirect_capable` fallback is the only option (at a performance cost)

### Chassis Cluster (HA)
- **Failover timing**: ~60ms with 30ms VRRP intervals (masterDownInterval ~97ms); configurable via `set chassis cluster reth-advertise-interval <ms>`
- **Planned shutdown**: burst of 3× priority-0 adverts; peer takes over in ~1ms (immediate takeover on priority-0)
- **Failback timing**: ~130ms (daemon startup + dataplane load + sync hold release)
- **VRRP advertisement**: RETH instances default 30ms; `AdvertiseInterval` is milliseconds internally, centiseconds on wire per RFC 5798
- **Async GARP**: `becomeMaster()` runs GARP in a goroutine — first pair <1ms, remaining at 50ms intervals in background. Critical path: addVIPs → sendAdvert → emitEvent (sync), then go sendGARP(false) (async). `sendGARP` has two suppression gates: a per-epoch dedup (`garpEpoch`/`lastGARPEpoch`) and a 500ms time dampener (`lastGARPTime`/`garpDampened`). `sendGARP(force)` — `force=true` bypasses ONLY the time dampener (keeps the epoch dedup); the routine `becomeMaster`/periodic path passes `force=false` so storm-control survives (#2081)
- **Fabric forwarding**: the userspace dataplane redirects packets for peer-owned synced sessions over the fabric link — `resolve_fabric_redirect()` / `ingress_is_fabric()` in `userspace-dp/src/afxdp/forwarding/fabric.rs` (re-exported through the `forwarding` module; see `docs/fabric-cross-chassis-fwd.md`) — prevents TCP death on VRRP failback. The pre-#1476 eBPF mechanism (`try_fabric_redirect()` in xdp_zone) is historical
- **RETH virtual MAC**: per-node `02:bf:72:CC:RR:NN`; `programRethMAC()` does link DOWN→set MAC→link UP
- **VIP reconciliation**: `ReconcileVIPs()` re-adds VRRP VIPs after `programRethMAC` link DOWN/UP (which removes all kernel addresses). It bumps `garpEpoch` AND calls `sendGARP(true)` (forced) — the MAC just changed, so the post-MAC-change GARP must defeat BOTH gates: the epoch bump clears the dedup, `force=true` clears the time dampener. Before #2081 the dampener still swallowed this burst if any routine GARP fired in the prior 500ms → peers held a stale ARP entry → blackhole until it aged out
- **Sync hold**: VRRP starts with `preempt=false`; released after bulk session sync (or 10s timeout); `preemptNowCh` triggers instant preemption. Sync-hold release preempt is now peer-priority gated (#2082): the non-force `preemptNowCh` shortcut becomes MASTER only on a STRICTLY higher effective priority than the last-observed master (RFC 5798 §6.4.2); `ForceRGMaster` (force=true) and priority-0 takeover (ungated `masterDownTimer` path) bypass the gate — no ~60ms failover regression
- **Heartbeat**: 200ms interval, threshold 5 (1s detection); bind retry loop for simultaneous boot
- **Session sync connect**: immediate first attempt, 1s retry (was 5s)
- **Event debounce**: 500ms for cluster state → VRRP priority updates

### Shutdown
- FRR reloads run `frr-reload.py` DIRECTLY (15s context per leg) — NEVER `systemctl reload frr`: FRR 10.6's ExecReload bounces watchfrr (the unit MainPID), which parks frr.service in a 2-min stop-sigterm and ends in systemd SIGKILLing FRR (#1880)
- systemd unit has `TimeoutStopSec=20` as safety net, `RestartSec=1`

## Feature Coverage
- **Firewall**: Stateful inspection, zone-based policies (including global policies), address books, application matching, multi-term apps, filtered session clearing
- **NAT**: SNAT (interface + pool, address-persistent), DNAT (with hit counters), static 1:1, NAT64
- **IPv4 + IPv6**: Dual-stack, DHCPv4/v6 clients, Router Advertisements
- **Screen/IDS**: 16 checks (land, syn-flood, ping-death, teardrop, winnuke, ip-sweep, port-scan, syn-fin, no-flag, fin-no-ack, syn-frag, source-route-option, icmp-flood, udp-flood, icmp-fragment, limit-session) — each dataplane-enforced; 15 carry a dedicated per-reason drop counter (`SCREEN_REASON_DROP_COUNT`, `screen_reason_drop_index` in userspace-dp/src/screen/mod.rs, session-limit-src/dst folded to one) + icmp-fragment folds to the aggregate `screen_drops`. SYN cookie flood protection (XDP-generated SYN-ACK cookies with source validation) is a separate mechanism; SYN-flood sub-thresholds (#3315: per-source/per-destination caps on a no-eviction count-min sketch + log-only alarm-threshold; `timeout` ENFORCED in #3527 as a per-zone override of the half-open session window `tcp_opening_ns`)
- **Routing**: FRR integration (static, OSPF, BGP, IS-IS, RIP), VRFs, GRE tunnels, export/redistribute, ECMP multipath, next-table + rib-group inter-VRF route leaking, route filtering by protocol/CIDR, probe-driven WAN failover (`services ip-monitoring` preferred-route injection, #1827)
- **VLANs**: 802.1Q tagging, trunk ports
- **IPsec**: strongSwan config generation, IKE proposals, gateway compilation, XFRM interfaces
- **Observability**: Syslog (facility/severity/category filtering, structured RT_FLOW format, TCP/TLS transport, event mode local file), NetFlow v9 (1-in-N sampling), Prometheus, RPM probes, dynamic feeds, SNMP (ifTable MIB), dataplane buffer utilization (`show system buffers`), session aggregation reporting
- **Flow**: TCP MSS clamping (ingress XDP + egress TC on the legacy path, plus userspace handling where admitted), ALG control, allow-dns-reply, allow-embedded-icmp, configurable timeouts (per-application inactivity), configurable SYN-first TCP session-miss guard (SYN-first by default; `no-syn-check` admits non-closing mid-stream transit misses and `strict-syn-check` overrides, while bare RST/FIN always drop, #10703/#4400; host-inbound LocalDelivery still caches only SYN-first sessions and delivers declined packets to the local stack, #4539), firewall filters (port ranges, hit counters, logging, forwarding-class DSCP rewrite, DSCP action)
- **HA**: Chassis cluster state machine (weight-based failover, manual failover/reset, Junos-style show/request commands), native VRRPv3 (Go state machine, AF_PACKET receiver, per-instance sockets, IPv6 NODAD, 30ms RETH advertisements, async GARP burst, ~60ms failover, single-interface tracking — nested `track-interface <if> priority-cost <n>`, effective-priority demotion clamped [1,254] on link-down, owner-255 exempt), bondless RETH (VRRP on physical member interfaces, RethToPhysical resolution, per-node virtual MAC), incremental session sync (1s sweep + ring buffer + GC delete callbacks), config sync (forward + reverse-sync on reconnect, ${node} variable quoting), IPsec SA sync, fabric cross-chassis forwarding, ISSU
- **DHCP**: Relay (Option 82), server (Kea integration with lease display)
- **CLI**: Junos-style prefix matching, "Possible completions:" headers, zone/interface descriptions, session idle time, session brief tabular view, flow statistics, policy descriptions, config validation warnings

## Network Topology (Test VM)

All interfaces are managed by xpfd — renamed via `.link` files, configured via `.network` files.
Startup naming by `enumerateAndRenameInterfaces()` assigns vSRX names based on PCI bus order.

```
Standalone VM (xpf-fw) — no /etc/xpf/node-id, no em0:
  Virtio (PCI bus 05-08):
    enp5s0  → fxp0       DHCP          — mgmt zone (SSH + ping)
    enp6s0  → ge-0-0-0   10.0.1.10     — trust zone
    enp7s0  → ge-0-0-1   10.0.2.10     — untrust zone
    enp8s0  → ge-0-0-2   10.0.30.10    — dmz zone
  i40e PCI passthrough (PCI bus 09+, always higher than virtio):
    enp9s0f0np0   → ge-0-0-3  172.16.50.5  — wan zone (VLAN 50, IPv6)
    enp101s0f1np1 → ge-0-0-4               — loss zone

Test containers:
  trust-host    10.0.1.102  (2001:559:8585:bf01::102)  — xpf-trust bridge
  untrust-host  10.0.2.102  (2001:559:8585:bf02::102)  — xpf-untrust bridge
  dmz-host      10.0.30.101 (2001:559:8585:bf03::101)  — xpf-dmz bridge
```

**HA cluster on `loss:xpf-userspace-fw0/fw1`** — different topology from
the standalone VM above. Do NOT extrapolate the standalone PCI map to
the loss userspace cluster; the WAN interface there is `ge-0-0-2` (node 0
name — node 1 uses FPC 7, i.e. `ge-7-0-2`), not `ge-0-0-3`, and
`ge-0-0-0` is the fabric IPVLAN parent (not WAN). The
per-cluster wiring is canonical in `docs/ha-cluster-userspace.conf` +
`test/incus/loss-userspace-cluster.env`. Summary:

```
loss:xpf-userspace-fw{0,1} — node-id 0 / 1, /etc/xpf/node-id present:
  NOTE: ge-* names below are node 0; node 1 substitutes FPC 7
  (ge-7-0-1 / ge-7-0-2) per pkg/daemon/linksetup.go (fpc=7 for node 1)
  and docs/ha-cluster-userspace.conf (node1: ge-7/0/1, ge-7/0/2).
  Virtio (PCI bus 05-07, lower bus → lower vSRX name):
    enp5s0  → fxp0       DHCP                          — mgmt zone (SSH + ping)
    enp6s0  → em0        10.99.{0..12}.{1,2}           — cluster control plane / heartbeat
    enp7s0  → ge-0-0-0   fab0 IPVLAN parent            — fabric (xdpgeneric — fabric path only)
  mlx5 SR-IOV VF (PCI bus 08-09 — native XDP):
    enp8s0  → ge-0-0-1   reth1.0 (LAN, 10.0.61.1/24)   — LAN-side, mlx5_core xdp native
    enp9s0  → ge-0-0-2   reth0 (WAN; VLAN 50 + 80)     — WAN-side, mlx5_core xdp native
                         reth0.50  172.16.50.8/24      —   transit
                         reth0.80  172.16.80.8/24      —   data path target VLAN

Smoke iperf3 target: 172.16.80.200 / 2001:559:8585:80::200 (on reth0.80
WAN path, AF_XDP zero-copy fast path). Per-class iperf3 servers live on
ports 5200-5211 matching `test/incus/cos-iperf-config.set`. Do NOT use
172.16.100.x — that reaches a different `loss:` uplink path capped at
~9-10 Gb/s and was the misdiagnosed "cluster ceiling" in #1578.
```
