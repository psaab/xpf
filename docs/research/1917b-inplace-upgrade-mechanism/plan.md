# #1917 increment B — in-place cut-over mechanism, HA rolling upgrade, dogfooded test-deploy, first-upgrade compat floor

> Plan-of-action for `/engineer 1917 B`. RESEARCH ONLY — no production
> source is touched here. This doc EXTENDS the converged rev-8 plan
> (`docs/research/1917-deb-inplace-upgrade/plan.md` @ `16317ab61`,
> §6.4 / §6.5 / §6.7) with the concrete increment-B mechanism, the
> STAY-UP HA rolling sequence, the dogfood deploy change, and the
> first-upgrade compatibility floor. Increment A (the `xpf` `.deb`,
> `make deb`, bake-consumes-deb) is MERGED (#1931 + #1932).

## 1. Status

PLAN-DRAFT (v1). Awaiting the 3-way hostile review (Codex + AGY + Claude
SMR). Increment A shipped: `debian/` packaging, `make deb`, dpkg-static
staging at `/usr/local/share/xpf/staged`, live `/usr/local/sbin/*`
symlinks, `needrestart` blacklist, `dh_installsystemd
--no-stop-on-upgrade`, and a postinst that creates the live symlinks on
**first install** and **leaves them untouched on upgrade** (the
deliberate increment-B window). This plan owns the cut-over that closes
that window.

## 2. Issue framing

#1917 asks for an in-place upgrade of xpfd + the dataplane with two
explicit operator demands carried into increment B:

1. **Stay up during upgrades** — an HA rolling upgrade that does not kill
   client TCP connections.
2. **Dogfood it** — the dev/test/CI deploy flow should USE the new
   `.deb`-based in-place upgrade, so every test cycle hardens the real
   path.

Plus the mechanism core (verify-before-cut, atomic flip, rollback,
crash-safety, mgmt-never-stranded) and the **first-upgrade
compatibility floor** (config-envelope reading + fail-closed on parse
error) that makes all future in-place upgrades safe.

OUT: #1930 (OS/kernel + base-OS major upgrades), #1924 (signed/hosted
apt repo), re-doing increment A's packaging.

## 3. Honest scope and value

**Value:** today the only upgrade path is image-replace (bake a new VM,
#1879) or `make cluster-deploy` (a raw `incus file push` + `systemctl
restart` — a hard dataplane cycle that bypasses any verify gate). Neither
is a production in-place upgrade. Increment B delivers:

- `xpf-upgrade` — a verified, atomic, rollback-capable cut-over invoked
  from the `.deb` postinst.
- An HA rolling sequence that keeps the cluster forwarding through an
  upgrade.
- A dogfood switch so the test/CI deploy exercises the same path.
- The compatibility floor that prevents a future config-format change
  from silently wiping config on an old reader.

**Honest non-goals / limits (carried verbatim from rev-8 §6.4):**

- **There is NO true zero-gap xpfd hot restart today.** The helper is an
  `exec.Command` child held in xpfd memory (`process.go:24`/`:76`); a
  fresh xpfd starts `m.proc==nil`, spawns a NEW helper, and CLEARS the
  XSKMAP (`process.go:64-71`), losing all in-process session + CoS state.
  Standalone cut-over is therefore a **bounded, MEASURED multi-second
  dataplane gap**, not milliseconds. The 3s NAPI bootstrap window after a
  fresh helper (`process.go:108-112`) is the structural floor. True
  zero-gap (decoupled-helper re-attach) is scoped as **M-mech-2 (future
  daemon work)** and is NOT in increment B.
- Kernel/OS upgrades are #1930. The §6.7 verify-gated kernel channel is
  NOT re-planned here.

## 4. What is already shipped (A) and reconciliation with rev-8 §6.4/6.5

Shipped in #1931/#1932 (verified against `debian/xpf.postinst`,
`debian/control`, `debian/rules`, `Makefile:310 deb:`):

| Shipped (A) | Increment B builds on it |
|---|---|
| dpkg-static staging `/usr/local/share/xpf/staged/{xpfd,cli,xpf-userspace-dp,xpf-day0-config}` | `xpf-upgrade` copies staging → `/var/lib/xpf/versions/<ver>/` (non-dpkg runtime) |
| live `/usr/local/sbin/*` symlinks, created first-install, untouched on upgrade | `xpf-upgrade` flips them atomically on verify PASS |
| `needrestart` blacklist + `--no-stop-on-upgrade` | preserved; B's postinst hook invokes `xpf-upgrade` explicitly |
| `ExecStartPre` verify-dataplane gate in the packaged unit | B reuses `verify-dataplane` as the cut gate, run against the staged/runtime dir BEFORE flip |
| `/etc/xpf` state never package-owned | B's compat floor + rollback read/write this state |

**Reconcile with rev-8 §6.4:** rev-8 named the mechanism `xpf-upgrade`,
sequenced M-mech-1 (full cycle + HA rolling) vs M-mech-2 (future
zero-gap), and identified the no-re-attach invariant. This plan
CONCRETIZES M-mech-1 into a state machine, layout, and rolling sequence.
**Reconcile with rev-8 §6.5:** the matched-set lockstep (xpfd + helper in
ONE package, cut as one versioned dir) holds; this plan adds the concrete
HA session-sync back-compat gate keyed on `CurrentHAProtocolVersion`
(`pkg/cluster/heartbeat.go:27`).

**Reconcile with rev-8 §6.3b (config fail-closed):** rev-8 identified
that `daemon_run.go` logs-and-proceeds on a config-DB parse error. This
is STILL TRUE on master (verified: `daemon_run.go:190` `slog.Warn("failed
to load config from db")` then `:197` `bootstrapFromFile()`). This plan
owns shipping that fatal-on-parse-error fix as the §4 compatibility floor.

## 5. Multiple path options

### 5A. Cut-over mechanism

**Option A1 — symlink-flip-then-restart (RECOMMENDED).** dpkg installs to
staging; `xpf-upgrade` copies staging → `/var/lib/xpf/versions/<ver>/`,
runs `verify-dataplane` against that dir, and on PASS atomically repoints
`/usr/local/sbin/*` (single `rename(2)` of a symlink via `ln -sfnT` /
`renameat2`) then `systemctl restart xpfd`. Rollback = re-flip to the
previous version dir + restart. Retain N=3 versions; GC oldest.
- Pros: simplest; reuses the increment-A staging+symlink layout exactly;
  the flip is a single atomic syscall; rollback is symmetric; crash
  between copy and flip leaves the OLD version live (safe). Standalone gap
  = the honest multi-second restart.
- Cons: the gap is a full dataplane cycle (no zero-gap).

**Option A2 — systemd-unit-swap (versioned ExecStart).** Instead of
flipping a symlink, rewrite the unit's `ExecStart` to point at
`/var/lib/xpf/versions/<ver>/xpfd` and `daemon-reload` + restart.
- Pros: no symlink ambiguity; the running daemon's binary identity is
  pinned by the unit, so a respawned helper can't resolve a different
  version via PATH (the §6.5 / increment-A respawn footgun).
- Cons: more moving parts (unit templating, daemon-reload ordering);
  rollback rewrites the unit again; `cli`/day-0 still resolve via the
  live symlink so you need BOTH mechanisms. Folded as a HARDENING of A1
  (see §6): A1 flips the symlink AND the recommended design pins
  `ExecStart` to the live symlink path so restart is deterministic, while
  the respawn-mismatch window is closed by the matched-set lockstep
  (helper version == xpfd version always, because they cut together).

**Option A3 — socket-handoff / zero-gap (M-mech-2, OUT).** Decouple the
helper into its own unit that outlives xpfd; xpfd re-attaches over the
control socket without clearing XSKMAP. This is the only path to a true
zero-gap standalone restart, but it does not exist today and is a
substantial daemon change with its own protocol-stability contract.
**Explicitly deferred to M-mech-2 / a future `/research`.** Increment B
documents the gap A1 leaves and scopes A3 as the follow-up.

### 5B. HA rolling sequence

**Option B1 — controlled-drain rolling (RECOMMENDED).** Per node:
`ForceSecondary()` (RG weights→0, VRRP demote, peer primary in ~60ms) →
wait for drain confirm → `xpf-upgrade` the now-passive node (stage copy +
verify + flip + restart) → wait for it to rejoin + bulk session-sync →
`ResetFailover()` to restore weights (or leave passive) → repeat on the
peer. Reuses `cluster.Manager.ForceSecondary()`/`ResetFailover()`
(`pkg/cluster/failover.go:121`/`:148`) and the `make test-failover` path.
- Pros: the upgraded node is verified to FORWARD before the other node
  upgrades; only one node is ever down; client gap is a single ~60ms VRRP
  failover, not a multi-second dataplane cycle.
- Cons: requires session-sync wire back-compat across N/N+1 (else the cut
  drops connections); two controlled failovers per upgrade.

**Option B2 — naive restart-and-let-VRRP-catch (status quo of the
current `deploy_rolling`).** Just restart the passive node and rely on
VRRP. Rejected: no controlled drain means a race where both nodes can be
secondary transiently; no forward-verify gate before the second node
upgrades; this is what the dogfood is meant to REPLACE.

**Option B3 — image-replace both nodes (Path C fallback).** If the
session-sync wire format breaks back-compat in N+1, the release is flagged
NOT rolling-upgradable and goes through image-replace with documented
connection loss. Retained as the fallback, not the default.

### 5C. Dogfood deploy change

**Option C1 — deb-install + xpf-upgrade, with a fast-dev escape
(RECOMMENDED).** `cluster-setup.sh deploy` builds the `.deb` (not raw
binaries), `incus file push`es the `.deb`, `apt install ./xpf_<ver>.deb`,
then drives the rolling cut via `xpf-upgrade --rolling` (cluster) or
`xpf-upgrade` (standalone). A `XPF_DEPLOY_FAST=1` escape keeps the raw
push+restart for tight inner-loop iteration (no full deb rebuild), but CI
and the smoke gate use the deb path so the upgrade mechanism is exercised
every cycle.
- Pros: dogfoods the real path; keeps the verify-dataplane gate; keeps the
  `deploy_rolling` secondary-first ordering (now a CONTROLLED drain, not a
  naive restart).
- Cons: `make deb` adds build time per cycle (mitigated by `XPF_DEPLOY_FAST`).

**Option C2 — always-deb, no escape.** Rejected: forces a multi-minute
deb build on every one-line iteration; the operator explicitly asked for
a fast dev loop.

### 5D. First-upgrade compatibility floor

**Option D1 — fatal-on-parse-error + old-reader-rejecting envelope
(RECOMMENDED, from rev-8 §6.3b + codex-review-010).** Make a config-DB
parse error (non-`IsNotExist`) FATAL at daemon startup, and introduce the
config envelope via an encoding the OLD reader REJECTS (not an object Go
silently empty-loads). Ship this as the FLOOR RELEASE before any release
writes the envelope.
- Pros: closes the silent-wipe hazard proven in rev-8 (Go ignores unknown
  JSON fields → an N+1 `{manifest,tree}` object empty-loads on an N
  reader, wiping config).
- Cons: a parse error now bricks startup instead of degrading — but that
  is the POINT (fail closed); must be paired with the
  mgmt-never-stranded lifeline (#1922) and an actionable error.

## 6. Concrete design (recommended: A1 + B1 + C1 + D1)

### 6.1 `xpf-upgrade` — states and layout

Owned by xpfd (a subcommand or a sibling binary in the same package,
TBD at /engineer — leaning subcommand `xpfd upgrade` to share config-DB
+ cluster client code). Layout:

```
/usr/local/share/xpf/staged/          # dpkg-static (increment A) — write target of apt
/var/lib/xpf/versions/<ver>/          # non-dpkg runtime version dirs (B), retain N=3
/var/lib/xpf/versions/current -> <ver># bookkeeping pointer (the verified-live version)
/usr/local/sbin/{xpfd,cli,xpf-userspace-dp,xpf-day0-config} -> versions/current/<bin>
/var/lib/xpf/upgrade.state            # crash-safe state machine journal (atomic write)
```

(Increment A's symlinks point at `staged/`; B's first run repoints them
through `versions/current/` after the first verified cut. A `version`
field already lives in `heartbeat.go` and the helper status.)

**State machine** (each transition persisted to `upgrade.state` via
temp+fsync+rename so a crash is recoverable and idempotent):

1. `STAGED` — apt has written `staged/`. `xpf-upgrade` reads the staged
   version.
2. `COPIED` — `staged/` copied to `versions/<ver>/` (copy, not move, so
   re-running is idempotent; checksum-verified).
3. `VERIFIED` — `verify-dataplane` run against `versions/<ver>/xpfd`'s
   embedded shim AGAINST THE RUNNING KERNEL (the verifier is kernel-space;
   reuse `pkg/dataplane verify_userspace_shim.go`). On REJECT → abort,
   leave live untouched, exit non-zero. Standalone-only: also a
   config-DB read/write compat check against a COPIED state dir (rev-8
   codex-review-010).
4. `FLIPPED` — repoint `versions/current` → `<ver>` (atomic rename of the
   symlink). `/usr/local/sbin/*` resolve through `current`.
5. `RESTARTED` — `systemctl restart xpfd`; wait for the helper `ping` to
   report the new version + healthy NAPI bootstrap; on failure within a
   deadline → AUTO-ROLLBACK (standalone) = re-flip `current` → previous +
   restart.
6. `COMMITTED` — GC versions beyond N=3 (never GC `current` or its
   immediate predecessor).

**Crash-safety:** a crash in any state re-runs from the journal;
COPY/VERIFY are pure; FLIP is the only mutation of live and is a single
atomic rename; a crash between FLIP and RESTART leaves the new symlink but
the OLD running process (safe — restart completes the cut or rollback
re-flips). Never delete the running OR the rollback version mid-flow.

**mgmt-never-stranded (#1922):** `xpf-upgrade` never touches interface
config; the verify gate runs before any restart; on standalone
auto-rollback failure it leaves the previous (known-good) version live.
Depends on #1922's protected-set for foreign-host installs.

### 6.2 HA rolling sequence (`xpf-upgrade --rolling`)

Driven from EITHER node (or an external driver, as in `deploy_rolling`):

```
for node in [passive, then ex-primary]:
  1. assert peer alive + session-sync established + HA proto compatible
     (CurrentHAProtocolVersion match, heartbeat.go:27) — else ABORT
     (fall back to Path C image-replace, B3).
  2. on the node-to-upgrade: ForceSecondary() — RG weights 0, VRRP demote,
     peer becomes primary (~60ms, async GARP). Wait for drain confirm
     (no primary RGs locally).
  3. xpf-upgrade (single-node A1 flow) on the now-passive node.
  4. wait: helper healthy + NAPI bootstrapped + session-sync re-established
     + bulk sync drained (reuse deploy_rolling's sync-wait, but gated on
     the helper `ping` version == new version).
  5. VERIFY THE UPGRADED NODE FORWARDS while still passive (synthetic
     probe / iperf3 through it as secondary path, or promote-and-check).
  6. ResetFailover() to restore weights (failback) OR leave passive and
     move to peer. Default: leave the just-upgraded node ready, upgrade
     the peer, then let normal election settle.
repeat for the other node.
```

Client-visible gap target: a single ~60ms VRRP failover per node
transition, NO TCP-killing loss (sessions synced + fabric forwarding
covers the FIB-miss window). MUST pass `make test-failover`.

### 6.3 Dogfood test-deploy change (`cluster-setup.sh` + Makefile)

- `cmd_deploy` builds the `.deb` (`make deb`) instead of / in addition to
  raw binaries when `XPF_DEPLOY_FAST` is unset.
- `deploy_vm` pushes the `.deb` and runs `apt install ./xpf_<ver>.deb`
  then `xpf-upgrade` (the postinst invokes it; or the script invokes it
  explicitly for determinism).
- `deploy_rolling` becomes a thin driver over `xpf-upgrade --rolling`
  (controlled drain B1), replacing the naive restart-and-VRRP-catch.
- `XPF_DEPLOY_FAST=1` keeps the current raw-push+restart for inner-loop
  dev (NO deb rebuild, NO verified cut) — explicitly NOT the CI/smoke
  path.
- Interaction with the loss-cluster shared lock: the `make deb` build runs
  OUTSIDE the lock (like the existing `XPF_CLUSTER_SKIP_BUILD` build-outside
  pattern, cluster-setup.sh:619); only the install + cut-over runs under
  the lock.

### 6.4 First-upgrade compatibility floor (D1)

- `daemon_run.go:190`: a `d.store.Load()` error that is NOT `IsNotExist`
  becomes FATAL (return the error from `Run`, do not `slog.Warn` and
  proceed), so `bootstrapFromFile()` can never overwrite an unparseable
  `active.json`. Pair with a clear operator error + the #1922 lifeline so
  mgmt stays reachable.
- Introduce the config envelope via an OLD-READER-REJECTING encoding
  (rev-8 proved a `#`-magic header or a top-level JSON array both error on
  the current `ConfigTree` reader, while a `{manifest,tree}` object
  silently empty-loads). The envelope carries: writer version, AST/schema
  version, MINIMUM reader version, rollback-slot format version. Startup
  validates min-reader before accepting the DB; too-new → fail closed.
- This release is the FLOOR: ship it BEFORE any release that writes the
  envelope, so the first real in-place upgrade has a reader that fails
  closed instead of empty-loading.

## 7. Preserved interfaces (must not change)

- `/usr/local/sbin/*` resolution (xpfd `findBinary` searches
  `dir(os.Args[0])` + PATH, `process.go:38`) — the flip must keep these
  paths valid at all times.
- `ProtocolVersion = 3` (`protocol.go:11`) / `CONFIG_SNAPSHOT_PROTOCOL_VERSION`
  matched-set lockstep — xpfd + helper cut together, never split.
- `CurrentHAProtocolVersion` (`heartbeat.go:27`) session-sync contract.
- `/etc/xpf` state (`.configdb`, `node-id`, `master.key`) — never
  package-owned, never touched by the cut-over except read/write through
  the compat gate.
- `verify-dataplane` gate semantics (anonymous-maps load, no attach, runs
  against the running kernel).
- The `make test-failover` zero-drop contract.

## 8. Hidden invariants

1. **mgmt-never-stranded (#1922)** — the cut-over never reconfigures
   interfaces; a failed verify/restart leaves the previous version live
   and mgmt reachable. Foreign-host installs depend on #1922's
   protected-set.
2. **Matched-set lockstep** — xpfd and helper are ONE package and one
   version dir; a respawned helper can never be a different protocol
   version than its xpfd (closes the increment-A respawn-mismatch window
   structurally).
3. **Session-sync back-compat** — if the sync wire changes in N+1 it MUST
   parse version-N frames for ≥1 release, else the release is flagged
   not-rolling-upgradable (Path C). Gate on `CurrentHAProtocolVersion`.
4. **Config-DB compat** — old-reader-rejecting envelope + fatal-on-parse;
   the floor release must precede any envelope writer.
5. **verify-dataplane gate** — the verifier is kernel-space; verify runs
   against the RUNNING kernel, so the cut-over verifies the version it is
   about to run, on the kernel it will run on.
6. **deploy-wipes-CoS-style gotcha** — a restart loses in-process CoS
   timer-wheel + session state; the HA path masks this with failover +
   session-sync; the standalone path documents the gap. The dogfood
   change must re-apply CoS config post-cut (the deploy-wipes-CoS rule).
7. **loss-cluster shared lock** — `make deb` builds outside the lock; only
   install + cut-over runs under it.
8. **Crash-safe idempotent state machine** — every transition journaled;
   re-run from journal; FLIP is the only live mutation and is atomic.
9. **Never GC the running or rollback version** — N=3 retention, GC only
   beyond predecessor.

## 9. Risk table

| # | Class | Risk | Mitigation |
|---|---|---|---|
| 1 | Correctness | Standalone cut is a multi-second gap (NAPI 3s + ctrl 3s/15s + XSK liveness ≤10s) | MEASURE it; if unacceptable for a use case, that use case uses image-replace or HA |
| 2 | Correctness | N+1 session-sync wire break drops connections on rolling cut | back-compat ≥1 release gate on `CurrentHAProtocolVersion`; else flag not-rolling-upgradable → Path C |
| 3 | Correctness | Config envelope silently empty-loads on old reader (proven) | old-reader-REJECTING encoding + fatal-on-parse floor release first |
| 4 | Data-loss | dpkg/needrestart restarts xpfd onto a half-cut binary | increment-A static staging + needrestart blacklist + `--no-stop-on-upgrade` (shipped); B never relies on dpkg to restart |
| 5 | Data-loss | rollback target deleted by GC or dpkg | non-dpkg `/var/lib/xpf/versions`, retain N=3, never GC running/predecessor |
| 6 | Crash-safety | Crash mid-cut strands the daemon | journaled state machine; FLIP atomic; crash leaves old version live |
| 7 | HA | Both nodes down together during rolling | one-node-at-a-time controlled drain; verify-forward before second node; abort if peer not alive |
| 8 | HA | Auto-rollback mid-rolling un-coordinates the cluster | auto-rollback is STANDALONE-only; HA rollback is operator-driven |
| 9 | Operability | Dogfood deb build slows dev loop | `XPF_DEPLOY_FAST=1` raw escape for inner loop; deb path for CI/smoke |
| 10 | Operability | mgmt stranded by fatal-on-parse | pair with #1922 lifeline + actionable error; rollback to previous version restores a parseable DB |

## 10. Test plan

**Standalone in-place upgrade (end-to-end):**
- Build `.deb` at version N and N+1; install N; run traffic (iperf3 to
  172.16.80.200); `apt install ./xpf_<N+1>.deb` → `xpf-upgrade`; MEASURE
  the dataplane gap (packet loss window) and assert it is bounded +
  reported honestly; assert the new version is live; assert CoS re-applied;
  inject a verify-dataplane REJECT and assert NO flip + previous version
  stays live; inject a post-restart unhealthy helper and assert
  auto-rollback restores N.
- Crash-injection: kill `xpf-upgrade` between each state transition; re-run;
  assert idempotent recovery + live version never half-cut.

**Rolling HA upgrade (gap measurement) — MANDATORY `make test-failover`:**
- On `loss:xpf-userspace-fw0/fw1`: run iperf3 through the cluster; drive
  `xpf-upgrade --rolling` N→N+1; MEASURE client-visible gap per node
  transition; assert NO TCP-killing loss (target single ~60ms VRRP gap,
  0 retransmit storms); assert sessions survive (synced); assert both
  nodes never secondary together; re-apply CoS config post-deploy
  (deploy-wipes-CoS).
- Back-compat case: simulate an N+1 with a bumped `CurrentHAProtocolVersion`
  and assert the rolling driver ABORTS to Path C rather than dropping
  connections.

**Dogfooded test-deploy:**
- `make cluster-deploy` (deb path) deploys + cuts over both nodes via
  `xpf-upgrade --rolling`; smoke (line-rate v4/v6) + `make test-failover`
  green; `XPF_DEPLOY_FAST=1 make cluster-deploy` still works for inner loop.

**Compatibility floor:**
- Old reader (floor release) + an N+1 envelope: assert fail-closed (no
  empty-load, no DB overwrite); assert a corrupt/unparseable `active.json`
  makes startup FATAL (not a blind bootstrap-overwrite); assert mgmt stays
  reachable via the #1922 lifeline.

## 11. Out of scope

- #1930 OS/kernel + base-OS major upgrades (and the §6.7 kernel channel).
- #1924 signed/hosted apt repo.
- M-mech-2 true zero-gap xpfd hot restart (decoupled-helper re-attach) —
  scoped as future daemon work + its own `/research`.
- Re-doing increment A packaging.

## Hostile open questions (each invitable to PLAN-KILL)

1. **Is the standalone multi-second gap acceptable AT ALL, or does it make
   the standalone in-place path pointless vs image-replace?** If every
   standalone upgrade must take a multi-second outage, is `xpf-upgrade`
   standalone just a worse `apt install + reboot`? Defend why the
   verify-gate + atomic-flip + rollback earns its complexity over
   image-replace for standalone. (KILL if it doesn't.)
2. **Does the matched-set lockstep ACTUALLY close the respawn-mismatch
   window, or can a running old xpfd respawn a new helper via the flipped
   symlink mid-cut?** The increment-A postinst comment warns a running
   xpfd "would resolve the NEW helper (protocol mismatch)". If the flip
   happens while old xpfd is alive and it respawns, does it grab the new
   helper before its own restart? Prove the ordering (flip→restart, and
   xpfd doesn't respawn between) or this is a data-corruption KILL.
3. **Is `ForceSecondary()` + `ResetFailover()` a SUFFICIENT controlled
   drain, or does the RG-weight-0 path leave a window where the upgrading
   node still owns RGs / VIPs?** Verify against `failover.go` that weights
   actually demote VRRP and the peer is primary before the cut, with no
   split-brain. (KILL if the drain isn't clean.)
4. **Can `verify-dataplane` run against the COPIED `versions/<ver>/xpfd`
   without disturbing the LIVE dataplane?** It loads anonymous maps (no
   attach) — but does running a second xpfd binary's verify path touch any
   shared pinned map / control socket / state file the live daemon owns?
   If verify perturbs the live dataplane, the gate is unsafe. (KILL if it
   can't be isolated.)
5. **Does the dogfood deb path BREAK the loss-cluster shared-lock
   protocol or the smoke serialization?** If every smoke deploy now does a
   rolling controlled-failover, does that interact badly with the
   single-agent smoke queue, the with-cluster.sh flock, or the build-outside-lock
   assumption? (KILL if dogfooding destabilizes the shared test infra.)
6. **Is fatal-on-parse-error a NET SAFETY WIN or a new brick vector?** A
   parse error now refuses to boot. On a remote foreign host without the
   #1922 lifeline shipped, does this strand mgmt worse than the
   silent-empty-load it replaces? Defend the ordering (floor release
   depends on #1922) or this trades one footgun for a worse one.
7. **N=3 retention — is 3 versions enough, and what happens when
   `/var/lib/xpf/versions` fills the disk** on a small appliance? Does a
   full disk mid-COPY strand the cut-over in a non-idempotent state?
