# #1917 increment B — in-place cut-over mechanism, HA rolling upgrade, dogfooded test-deploy, first-upgrade compat floor

> Plan-of-action for `/engineer 1917 B`. RESEARCH ONLY — no production
> source is touched here. This doc EXTENDS the converged rev-8 plan
> (`docs/research/1917-deb-inplace-upgrade/plan.md` @ `16317ab61`,
> §6.4 / §6.5 / §6.7) with the concrete increment-B mechanism, the
> STAY-UP HA rolling sequence, the dogfood deploy change, and the
> first-upgrade compatibility floor. Increment A (the `xpf` `.deb`,
> `make deb`, bake-consumes-deb) is MERGED (#1931 + #1932).

## 1. Status

PLAN-DRAFT (v2). Round-1 hostile review complete — all three reviewers
PLAN-NEEDS-REVISION (no kill; A1+B1+C1+D1 direction endorsed). v2 folds
every converged round-1 blocker:
- **stop-before-flip** ordering (was flip-before-restart) — closes the
  respawn-mismatch race (Codex#1, AGY#1, SMR);
- a **strong HA drain predicate + peer-takeover-ack BEFORE demote** (was
  "no primary RGs locally") — prevents dual-secondary VIP stranding
  (Codex#2, AGY#2);
- **mandatory DB-restore-from-rollback-slot before booting the old daemon**
  on rollback (was an optional alternative) — closes the envelope-format
  rollback brick (AGY#3, SMR);
- **forward-verify via controlled temporary promotion** (a passive node
  structurally cannot forward) (AGY#4);
- a **postinst HA-mode contract: stage-only / refuse-local-cut on
  clustered nodes** — only `xpf-upgrade --rolling` cuts them (Codex#3);
- **`.partial`-dir + atomic-rename copy + disk preflight** (Codex#4, SMR);
- **mandatory N↔N+1 session-sync frame fixtures** (Codex#5, SMR);
- **#1922 as a HARD release prerequisite** for the fatal-on-parse floor on
  non-appliance hosts (Codex#6).

Increment A shipped: `debian/` packaging, `make deb`, dpkg-static
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

**Round-1 CORRECTION (Codex#1, AGY#1, SMR — confirmed against code).**
Flip-before-restart is UNSAFE and the "matched-set lockstep closes it"
claim was wrong. A LIVE old (version-N) xpfd respawns its helper on two
triggers independent of the cut — helper ping unhealthy
(`process.go:33-35`) and a binding-plan change (`process.go:307-316`) —
and `findBinary` resolves the helper via
`filepath.Join(filepath.Dir(os.Args[0]), "xpf-userspace-dp")`
(`process.go:175`), which for a daemon launched as the live symlink
`/usr/local/sbin/xpfd` resolves the FLIPPED
`/usr/local/sbin/xpf-userspace-dp` → the N+1 helper under an N daemon =
protocol mismatch + XSKMAP churn. Lockstep guarantees they SHIP together,
not that a RUNNING xpfd resolves its OWN version's helper after a shared
flip. **A1 is therefore amended to STOP-BEFORE-FLIP and the design pins
the daemon's binary identity to an absolute versioned path (A2 folded
in):**

**Option A2 — versioned ExecStart (FOLDED INTO THE RECOMMENDED A1).** The
xpfd unit's `ExecStart` points at the **absolute** current-version path
`/var/lib/xpf/versions/current/xpfd` (a symlink resolved AT systemd-exec
time, so `os.Args[0]` is `/var/lib/xpf/versions/<ver>/xpfd` AFTER systemd
resolves it — verify at /engineer that systemd passes the resolved path;
if not, template `ExecStart` to the concrete `<ver>` path and
`daemon-reload`). Then `dir(os.Args[0])` is the version dir and a respawn
resolves the MATCHING-version helper, never the flipped `/usr/local/sbin`
link. The `/usr/local/sbin/*` symlinks then serve ONLY operator tools
(`cli`, day-0), not the running daemon's helper resolution.

**The amended A1 cut ordering is STOP → FLIP → START:**
1. `systemctl stop xpfd` (old daemon + its helper exit cleanly; no live
   process can respawn a helper after this point).
2. flip `versions/current` → `<ver>` (atomic) AND flip the
   `/usr/local/sbin/*` operator-tool links.
3. `systemctl start xpfd` (new daemon, new helper, both version `<ver>`).

This widens the standalone gap slightly (stop happens before the new
binary is live) but it is the ONLY ordering that structurally forecloses
the respawn race. The gap is still the same multi-second class (the
NAPI-bootstrap floor dominates). HA masks it with failover (§6.2).

**Option A3 — socket-handoff / zero-gap (M-mech-2, OUT).** Decouple the
helper into its own unit that outlives xpfd; xpfd re-attaches over the
control socket without clearing XSKMAP. This is the only path to a true
zero-gap standalone restart, but it does not exist today and is a
substantial daemon change with its own protocol-stability contract.
**Explicitly deferred to M-mech-2 / a future `/research`.** Increment B
documents the gap A1 leaves and scopes A3 as the follow-up.

### 5B. HA rolling sequence

**Option B1 — controlled-drain rolling (RECOMMENDED).** Per node:
peer-readiness-precheck → `ForceSecondary()` → wait for a STRONG drain
predicate → `xpf-upgrade` the now-passive node → rejoin + bulk
session-sync → forward-verify via controlled promotion → `ResetFailover()`
(or leave passive) → repeat. Reuses
`cluster.Manager.ForceSecondary()`/`ResetFailover()`
(`failover.go:121`/`:148`) and the `make test-failover` path.

**Round-1 CORRECTIONS (Codex#2, AGY#2, AGY#4 — confirmed against code):**

- **Drain confirm "no primary RGs locally" is TOO WEAK.**
  `ForceSecondary()` only sets local cluster state/weight (`failover.go:121`);
  it does NOT itself prove VRRP backed down or BPF `rg_active==false`. The
  RG state machine keeps forwarding active while VRRP is still MASTER
  (`rg_state.go:13`); demotion calls `ResignRG` (`daemon_ha.go:259/272`)
  but the node only becomes truly inactive after VRRP BACKUP handling
  (`daemon_ha.go:424`). The amended **drain-complete predicate** is ALL of:
  (a) peer owns the RGs (peer reports primary for them), (b) local VRRP is
  BACKUP with no VIPs held, (c) local `rg_active` is false (or
  intentionally fabric-only), (d) session-sync is clean/established.
- **Peer-takeover-ack BEFORE the demoting node drops VIPs.** Demoting
  immediately can strand VIPs if the peer is blocked by a local readiness
  gate (`takeoverHoldTime` / interface-monitor refusal, `election.go:236`)
  → both nodes BACKUP, VIPs stranded. The driver MUST verify the peer is
  takeover-READY (peer health + interface monitors green + no hold) BEFORE
  calling `ForceSecondary()`, and confirm the peer has PROMOTED (owns the
  RGs/VIPs) before declaring drain complete.
- **Forward-verify cannot run while PASSIVE.** A secondary programs
  `rg_active=false` + blackhole/fabric-redirect (`daemon_ha.go:278/601`),
  so it structurally cannot forward transit. The forward-verify step is
  therefore a **controlled temporary promotion**: after the upgraded node
  rejoins and syncs, briefly promote it (or let normal failback promote
  it) and verify forwarding via the `make test-failover` iperf3 path THEN,
  not while passive. Sequencing keeps one node primary at all times.

- Pros: only one node ever down; client gap is a single ~60ms VRRP
  failover, not a multi-second dataplane cycle; the upgraded node is
  forward-verified (post-promotion) before the peer upgrades.
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
temp+fsync+rename so a crash is recoverable and idempotent). The ONLY
live-state mutations are STOP and FLIP-then-START; everything before is
pure/abortable:

1. `STAGED` — apt has written `staged/`. `xpf-upgrade` reads the staged
   version.
2. `PREFLIGHT` — check free space on `/var` ≥ `size(staged)` + margin;
   if a version dir would not fit, GC GC-eligible versions (never the
   running or its predecessor) and re-check; if still short, ABORT here
   (no live mutation). (Codex#4)
3. `COPIED` — copy `staged/` → a `versions/.<ver>.partial/` temp dir,
   fsync, checksum, then **atomic `rename(2)`** to `versions/<ver>/` so a
   crash never leaves an ambiguous half-populated `versions/<ver>`; a
   stray `.partial` dir is always safe to delete on re-run. Copy (not
   move) so apt's staging is untouched and re-run is idempotent. (Codex#4)
4. `VERIFIED` — run `versions/<ver>/xpfd --verify-dataplane` AGAINST THE
   RUNNING KERNEL (the verifier is kernel-space; reuse
   `verify_userspace_shim.go`) **with throwaway
   `--control-socket`/`--state-file`/pin paths so it touches NO live
   resource** (see §8 invariant 5 / OQ#4). On REJECT → abort, live
   untouched, exit non-zero. Standalone-only: also a config-DB read/write
   compat check against a COPIED state dir (codex-review-010).
5. `STOPPED` — `systemctl stop xpfd`. After this, no live process can
   respawn a helper, so the flip is safe (Codex#1/AGY#1). (HA: this node
   is already drained to the peer per §6.2 BEFORE this step.)
6. `FLIPPED` — atomic-rename `versions/current` → `<ver>` AND repoint the
   `/usr/local/sbin/*` operator-tool links. **ALSO template the xpfd unit's
   `ExecStart` + `ExecStartPre verify-dataplane` to the CONCRETE
   `/var/lib/xpf/versions/<ver>/xpfd` path and `systemctl daemon-reload`**
   — systemd does NOT resolve symlinks in `ExecStart`, so `argv[0]` is the
   literal configured path; the current unit `ExecStart=/usr/local/sbin/xpfd`
   (`test/incus/xpfd.service:8`, `debian/rules:56`) would make
   `dir(os.Args[0])` = `/usr/local/sbin` and a respawn resolve the flipped
   helper. Pinning the concrete versioned path makes `dir(os.Args[0])` the
   version dir so even a transient respawn grabs the matching-version
   helper (defense-in-depth atop STOP-before-FLIP). (SMR r2 confirmed this
   against the live unit — it is a HARD step, not an open question.)
7. `STARTED` — `systemctl start xpfd`; wait for the helper `ping` to
   report the new version + healthy NAPI bootstrap within a deadline; on
   failure → AUTO-ROLLBACK (standalone-only): stop → DB-restore (§6.4) →
   re-flip `current` → previous → start. (HA rollback is operator-driven,
   §6.2.)
8. `COMMITTED` — GC versions beyond N=3 (never GC `current` or its
   immediate predecessor).

**Crash-safety:** every transition is journaled and re-runs from the
journal. PREFLIGHT/COPY/VERIFY are pure (abort leaves live untouched).
The COPY uses `.partial`+rename so a crash never yields a half-`<ver>`.
A crash after STOPPED but before STARTED is recovered by re-running:
either complete FLIP→START to the new version, or (if FLIP not yet
journaled) START the OLD version still pointed-to by `current`. Never
delete the running OR the rollback version mid-flow.

**mgmt-never-stranded (#1922):** `xpf-upgrade` never touches interface
config; the verify gate runs before any stop; on standalone auto-rollback
failure it leaves the previous (known-good) version + a parseable DB live.
**#1922 is a HARD prerequisite** for the fatal-on-parse floor (§6.4) on
non-appliance / foreign hosts (Codex#6); on the appliance the day-0 +
protected-set lifeline already covers it.

### 6.2 HA rolling sequence (`xpf-upgrade --rolling`)

Driven from EITHER node (or an external driver, as in `deploy_rolling`):

```
for node in [passive, then ex-primary]:
  1. assert peer alive + session-sync established + HA proto compatible
     (CurrentHAProtocolVersion match, heartbeat.go:27) — else ABORT
     (fall back to Path C image-replace, B3).
  2. PEER-TAKEOVER-READY PRECHECK (AGY#2): verify the PEER is takeover-
     ready BEFORE demoting — peer healthy, peer interface monitors green,
     peer not blocked by takeoverHoldTime/monitor refusal (election.go:236).
     If peer is not ready, DO NOT demote (would strand VIPs) — wait/abort.
  3. on the node-to-upgrade: ForceSecondary() (failover.go:121).
  4. STRONG DRAIN PREDICATE (Codex#2) — wait until ALL hold:
     (a) peer reports PRIMARY for the RGs (peer owns them);
     (b) local VRRP is BACKUP and holds no VIPs;
     (c) local rg_active == false (or intentionally fabric-only)
         — i.e. VRRP-BACKUP-driven inactive state (daemon_ha.go:424),
         NOT merely "weight 0 set" (rg_state.go:13 still forwards while
         VRRP MASTER);
     (d) session-sync established/clean.
  5. xpf-upgrade (single-node STOP→FLIP→START flow, §6.1) on the now-
     fully-drained passive node.
  6. wait: helper healthy + NAPI bootstrapped + session-sync re-established
     + bulk sync drained (reuse deploy_rolling's sync-wait, gated on the
     helper `ping` version == new version).
  7. FORWARD-VERIFY VIA CONTROLLED PROMOTION (AGY#4): a passive node
     CANNOT forward transit (rg_active=false + blackhole/fabric,
     daemon_ha.go:278/601). So briefly promote the upgraded node (or let
     normal failback promote it) and verify forwarding via the
     make test-failover iperf3 path THEN — never "verify while passive".
     Keep exactly one node primary throughout.
  8. ResetFailover() (failover.go:148) to failback, OR leave the upgraded
     node primary and move to the peer. Default: upgraded node becomes
     primary, upgrade the ex-primary (now passive) peer, then let normal
     election settle.
repeat for the other node.
```

If at step 4 the drain predicate cannot be satisfied within a deadline,
ABORT WITHOUT cutting (the node is still forwarding — no harm) and surface
an operator error. HA rollback is OPERATOR-DRIVEN, never auto (an auto
re-flip mid-rolling un-coordinates the cluster — §8 invariant 8).

Client-visible gap target: a single ~60ms VRRP failover per node
transition, NO TCP-killing loss (sessions synced + fabric forwarding
covers the FIB-miss window, `forwarding/mod.rs`). MUST pass
`make test-failover`.

### 6.3 postinst HA-mode contract + dogfood test-deploy change

**postinst HA-mode contract (Codex#3 — resolve the postinst-vs-rolling
contradiction).** The `.deb` postinst must NOT perform a local single-node
cut on a clustered node, or it bypasses the rolling mechanism (one node
down uncoordinated):
- On UPGRADE, the postinst detects cluster membership (presence of
  `/etc/xpf/node-id` + a live cluster) and, if clustered, is **STAGE-ONLY**
  — it refreshes `staged/` and EXITS without invoking the cut. Cutting a
  clustered node is done ONLY by `xpf-upgrade --rolling` (driven by the
  operator or the dogfood driver), which sequences the drain.
- On a STANDALONE node, the postinst MAY invoke `xpf-upgrade` (single-node
  STOP→FLIP→START), or leave it to an explicit operator `xpf-upgrade` —
  TBD at /engineer, but the standalone gap must be documented either way.
- First install is unchanged from increment A (create symlinks, no cut).

**Dogfood test-deploy change (`cluster-setup.sh` + Makefile):**
- `cmd_deploy` builds the `.deb` (`make deb`) instead of raw binaries when
  `XPF_DEPLOY_FAST` is unset.
- `deploy_vm` pushes the `.deb` and runs `apt install ./xpf_<ver>.deb`
  (which, on a clustered node, is STAGE-ONLY per the contract above).
- `deploy_rolling` becomes a thin driver over `xpf-upgrade --rolling`
  (controlled drain B1), replacing the naive restart-and-VRRP-catch — so
  the install (stage) and the cut (rolling) are cleanly separated and the
  rolling mechanism is never bypassed.
- `XPF_DEPLOY_FAST=1` keeps the current raw-push+restart for inner-loop
  dev (NO deb rebuild, NO verified cut) — explicitly NOT the CI/smoke
  path.
- Loss-cluster shared lock: `make deb` runs OUTSIDE the lock (existing
  `XPF_CLUSTER_SKIP_BUILD` build-outside pattern, cluster-setup.sh:619);
  only install + cut-over runs under the lock via `with-cluster.sh`. Smoke
  serialization is unaffected — the single-agent smoke queue still owns the
  cluster for the duration of one rolling cut (OQ#5).

### 6.4 First-upgrade compatibility floor (D1) + rollback DB safety

**Fatal-on-parse (the floor):**
- `daemon_run.go:191`: a `d.store.Load()` error that is NOT `IsNotExist`
  becomes FATAL (return the error from `Run`, do not `slog.Warn` and
  proceed to `:197` `bootstrapFromFile()`), so an unparseable `active.json`
  can never be overwritten/empty-loaded. Pair with a clear operator error.
- **#1922 is a HARD prerequisite** for this on foreign/non-appliance hosts
  (Codex#6): fail-closed without the protected-set lifeline could strand
  mgmt. On the appliance the day-0 + protected-set covers it; gate the
  floor release on #1922 (or scope fatal-on-parse appliance-only until
  #1922 lands).

**Config envelope (EMBEDDED in `active.json`, old-reader-REJECTING):**
- The envelope is **embedded in `active.json`** (rev-8 codex-review-010's
  converged resolution — NOT a sidecar manifest), via an encoding the
  current `readTree` `json.Unmarshal(data, &ConfigTree{})` (`db.go:124`)
  REJECTS: a `#`-magic header line or a top-level JSON array. (rev-8 SMR
  empirically proved both ERROR on the `ConfigTree` reader, while a
  `{manifest,tree}` object SILENTLY empty-loads — the silent-wipe defect.)
- Carries: writer version, AST/schema version, MINIMUM reader version,
  rollback-slot format version. Startup validates min-reader before
  accepting the DB; too-new → fail closed.
- FLOOR ordering: ship the envelope-READER (this release) BEFORE any
  release WRITES the envelope, so the first real in-place upgrade has a
  reader that fails closed instead of empty-loading.

**Rollback DB safety (AGY#3, SMR — mandatory, was optional):** auto-
rollback (standalone, §6.1 step 7) MUST restore the config DB to an
N-readable state BEFORE booting the N (previous) daemon. Concretely:
- The N+1 daemon, on startup with the envelope, writes `active.json` in a
  format N's reader will REJECT (the whole point of the floor). So a bare
  binary re-flip to N would boot an N daemon that fatal-rejects the N+1
  `active.json` → permanent crash (the bricking vector AGY found).
- Therefore on auto-rollback: **first restore `active.json` from the
  pre-upgrade rollback slot / a pre-upgrade DB snapshot taken in step 2
  (PREFLIGHT)**, THEN re-flip the binary, THEN start. The rollback is
  binary+DB atomic, not binary-only.
- Equivalent: gate auto-rollback on "the new version did NOT advance the
  state-format floor" — if it did, refuse silent binary-only rollback and
  require the DB restore. Take a DB snapshot at PREFLIGHT so the restore
  source always exists.

## 7. Preserved interfaces (must not change)

- `findBinary` helper resolution (`process.go:168-191`,
  `dir(os.Args[0])` + PATH) — the daemon's `ExecStart` is pinned to the
  versioned `/var/lib/xpf/versions/current/xpfd` so `dir(os.Args[0])` is
  the version dir; `/usr/local/sbin/*` remain valid for operator tools.
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
2. **Respawn-mismatch closure (STOP-before-FLIP + versioned ExecStart)** —
   matched-set lockstep alone does NOT close the window (a running old
   xpfd resolves the flipped `/usr/local/sbin/xpf-userspace-dp` on a
   helper respawn, `process.go:175`). The closure is structural: (a) the
   cut STOPS xpfd before flipping (no live process to respawn), AND (b)
   `ExecStart` is pinned to the versioned path so even a transient respawn
   resolves the matching-version helper, never the shared `/usr/local/sbin`
   link.
3. **Session-sync back-compat** — if the sync wire changes in N+1 it MUST
   parse version-N frames for ≥1 release, else the release is flagged
   not-rolling-upgradable (Path C). The sync frame header (`sync.go:17`)
   has magic/type/length but NO frame-version field today; either gate on
   `CurrentHAProtocolVersion` (`heartbeat.go:27`) AND add an explicit
   sync-frame version, or commit to never breaking the frame layout
   without a version bump. Mixed-version N↔N+1 fixtures are mandatory
   (§10, Codex#5).
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
   re-run from journal; COPY via `.partial`+rename; live mutations are
   only STOP and FLIP-then-START; HA rollback is operator-driven (auto
   only standalone).
9. **Never GC the running or rollback version** — N=3 retention, GC only
   beyond predecessor; PREFLIGHT disk check + GC-before-copy.
10. **verify isolation** — the verify invocation uses throwaway
    control-socket/state-file/pin paths and never opens a live socket or
    pinned map (OQ#4).
11. **Rollback is binary+DB atomic** — restore the config DB to the
    previous-readable format BEFORE booting the previous binary
    (envelope-format rollback brick, §6.4).
12. **postinst is stage-only on clustered nodes** — never auto-cuts an HA
    node; only `xpf-upgrade --rolling` cuts it (§6.3).

## 9. Risk table

| # | Class | Risk | Mitigation |
|---|---|---|---|
| 1 | Correctness | Standalone cut is a multi-second gap (NAPI 3s + ctrl 3s/15s + XSK liveness ≤10s) | MEASURE it; if unacceptable for a use case, that use case uses image-replace or HA |
| 2 | Correctness | N+1 session-sync wire break drops connections on rolling cut | back-compat ≥1 release gate on `CurrentHAProtocolVersion`; else flag not-rolling-upgradable → Path C |
| 3 | Correctness | Config envelope silently empty-loads on old reader (proven) | old-reader-REJECTING encoding + fatal-on-parse floor release first |
| 4 | Data-loss | dpkg/needrestart restarts xpfd onto a half-cut binary | increment-A static staging + needrestart blacklist + `--no-stop-on-upgrade` (shipped); B never relies on dpkg to restart |
| 5 | Data-loss | rollback target deleted by GC or dpkg | non-dpkg `/var/lib/xpf/versions`, retain N=3, never GC running/predecessor |
| 6 | Crash-safety | Crash mid-cut strands the daemon | journaled state machine; FLIP atomic; crash leaves old version live |
| 7 | HA | Dual-secondary VIP stranding (demote before peer ready) | peer-takeover-ready precheck BEFORE demote; strong drain predicate; abort if peer not ready |
| 8 | HA | Auto-rollback mid-rolling un-coordinates the cluster | auto-rollback is STANDALONE-only; HA rollback is operator-driven |
| 11 | Data-loss | Envelope-format rollback brick (N rejects N+1 DB) | binary+DB atomic rollback: restore DB to previous-readable format before booting previous binary |
| 12 | Correctness | Respawn-mismatch (old xpfd grabs N+1 helper) | STOP-before-FLIP + versioned ExecStart pinned to the version dir |
| 13 | Correctness | postinst auto-cuts a clustered node, bypassing rolling | postinst stage-only on clustered nodes; cut only via `xpf-upgrade --rolling` |
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
- Crash-injection: kill `xpf-upgrade` between each state transition
  (PREFLIGHT/COPIED/VERIFIED/STOPPED/FLIPPED/STARTED); re-run; assert
  idempotent recovery + live version never half-cut + no orphan `.partial`.
- Disk-full: fill `/var` so a version dir won't fit; assert PREFLIGHT
  ABORTS with live untouched (no half-copy, no orphan partial).
- Respawn-race regression: while old xpfd is up, induce a helper respawn
  (binding-plan change / helper kill) AFTER a (hypothetical) flip and
  assert the STOP-before-FLIP ordering + versioned ExecStart prevent the
  old daemon from ever resolving the N+1 helper.

**Rollback DB safety:**
- N+1 writes an envelope `active.json`, then fails its post-start health
  check; assert auto-rollback RESTORES the DB to the N-readable format
  BEFORE booting N, and N boots clean (NOT a fatal-parse brick).

**Rolling HA upgrade (gap measurement) — MANDATORY `make test-failover`:**
- On `loss:xpf-userspace-fw0/fw1`: run iperf3 through the cluster; drive
  `xpf-upgrade --rolling` N→N+1; MEASURE client-visible gap per node
  transition; assert NO TCP-killing loss (target single ~60ms VRRP gap,
  0 retransmit storms); assert sessions survive (synced); assert exactly
  one node primary throughout (never dual-secondary); re-apply CoS config
  post-deploy (deploy-wipes-CoS).
- Drain-predicate test: assert the cut does NOT begin until the strong
  drain predicate holds (peer primary, local VRRP BACKUP, rg_active false,
  sync clean) — not merely "weight 0 set".
- Peer-not-ready test: block the peer's takeover (interface-monitor
  red / hold) and assert the driver REFUSES to demote (no VIP stranding).
- Forward-verify test: assert forwarding is verified via controlled
  promotion, never "while passive".
- Session-sync N↔N+1 fixtures (unit): "N+1 receives N frame", "N receives
  N+1 (or negotiated-down N) frame"; bump the sync-frame version and
  assert the rolling driver ABORTS to Path C rather than dropping
  connections.
- postinst-on-cluster test: `apt install ./xpf_<N+1>.deb` on a clustered
  node is STAGE-ONLY (does NOT cut the dataplane); only
  `xpf-upgrade --rolling` cuts it.

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
2. **[RESOLVED v2 — respawn race]** Round 1 confirmed the race is REAL.
   v2 closes it with STOP-before-FLIP + concrete-versioned `ExecStart`
   (§6.1 step 6). SMR r2 confirmed systemd does NOT symlink-resolve
   `argv[0]`, so the unit MUST template the concrete `versions/<ver>/xpfd`
   path (now a hard FLIP-step, not relying on symlink resolution). Fully
   resolved.
3. **[RESOLVED v2 — drain predicate]** Round 1 confirmed `ForceSecondary()`
   weight-0 alone is insufficient (`rg_state.go:13` forwards while VRRP
   MASTER). v2 mandates the strong drain predicate + peer-ready precheck
   (§6.2). REMAINING question: is the peer-readiness signal the driver
   checks actually authoritative (no TOCTOU between "peer ready" and the
   demote), or can the peer go un-ready in the gap?
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
7. **[PARTIALLY RESOLVED v2]** N=3 retention + PREFLIGHT disk check +
   `.partial`+rename copy (§6.1) make disk-full ABORT cleanly pre-mutation.
   REMAINING question: is N=3 the right number, and does the DB snapshot
   taken at PREFLIGHT (for rollback) itself need disk-space accounting?
8. **Does the controlled-promotion forward-verify (§6.2 step 7) itself
   cause an EXTRA client-visible failover** (promote upgraded node →
   verify → maybe demote again)? If verifying the upgrade costs a second
   ~60ms gap per node, is that acceptable, or should forward-verify be
   folded into the natural failback so there is only one transition?
9. **Stop-before-flip widens the standalone gap** — the daemon is down for
   stop + flip + start + 3s NAPI bootstrap. Is that meaningfully worse than
   flip-then-restart, and does it push standalone past the "just use
   image-replace" threshold (OQ#1)?
