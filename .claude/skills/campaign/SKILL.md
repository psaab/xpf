---
name: campaign
description: Drive ALL open issues and PRs to zero — the single campaign skill. Research keeps filing issues, engineers convert them to PRs, triple hostile review (any 3 of Muse Wonder, Opus 5.5, Codex-6 Astra, GLM-5.3, Kimi K3.1 Pro) plus parallel forwarding/throughput gates on the loss, tcp, and udp clusters land or kill every item, a keeper monitor alerts the parent who alone dispatches to keep lanes full, and it stops only when both queues stay at zero.
user_invocable: true
---

# /campaign — drive-to-zero backlog campaign

Drive **every** open issue to a terminal state — `MERGED` or
`PLAN-KILLED` (all three independent `/research` reviewers converge on
rejecting the final reviewed approach; `plan-deferred-*` is a work queue,
never terminal — see Step 1) — and open new issues for real bugs/gaps
found along the way, then drive those too. Stop only when no
driveable work remains.

## Standing user orders (2026-10-13, reaffirmed repeatedly — do not relitigate)

- **Bands first, lowest number within band**: rank into Step 1 bands,
  then pick lanes from the smallest/lowest open issue number upward
  within the band. Do not cherry-pick interesting work over old debt.
- **PRs landing takes priority**: an open PR is unfinished work, not a queue
  to admire. Before starting NEW engineering, drain the landing queue:
  re-confirm folded heads, rebase, squash message violations, and MERGE.
  New lanes open only after every mergeable PR has landed or been
  dispositioned. A review verdict sitting unactioned for a turn is a
  campaign failure.
- **Zero PRs too**: termination requires zero open PRs as well as zero open
  issues. Drain reviews/merges continuously; an open PR is not delivered work.
- **Agent concurrency cap (user directive 2026-10-26)**: the box-wide
  agent concurrency ceiling is `2 × nproc` concurrent agents. The
  campaign NEVER dispatches into the last 6 slots — they stay free
  for ad-hoc work that comes up mid-campaign — so at most
  `2*nproc - 6` campaign agents (engineers + reviewers + scouts
  combined) may be live at once. The keeper Monitor and the smoke
  watch are standing lanes outside this count (see "The keeper" and
  "Continuous smoke watch"). At the cap, queue new lanes instead of
  dispatching; refill as completions land. On a 16-core box:
  ceiling 32, campaign cap 26. The cap is parent-counted against
  the live task registry (`proc://`): every dispatched task job —
  engineer, reviewer, or scout, whatever its agent type — counts
  as one live campaign agent until it completes. The keeper board
  summary line and the parent's appended lane table both carry the
  live count vs cap (`agents=<n>/<cap>`) so a breach is
  visible at the next keeper tick instead of only in hindsight.
- **Spend cap — the binding limit (2026-10-31)**: the box ceiling
  above was never what stopped a campaign; the spend limit was. On
  2026-10-31 it stopped every agent at once, mid-lane, and the
  salvage cost more than the parallelism had bought. Run at about
  **3 implementor lanes plus about 2 review seats** live at once, and
  use that number as `cap` in every rule below; `2*nproc - 6` is an
  upper bound, not a target, and only the user raises the spend cap.
  A due gate runner (item 9 below) takes the next implementor slot,
  so a merge wave can be 3 gate runners + 2 review seats with no new
  implementor until the gates return. **Resume before you spawn**: a
  fold confirmation, a narrow re-review, or a follow-up question goes
  to the EXISTING seat via `SendMessage` with a narrow delta (Step 3
  item 6), never to a fresh agent that re-reads the whole PR.
- **Keep lanes full, parallelism high (measurable, enforced)**:
  never let engineer or reviewer lanes idle while driveable work
  exists. The invariant is a NUMBER, checked at every parent action
  and every keeper tick: `live campaign agents == min(cap,
  driveable work)` where cap is the spend cap above. If
  live < that number while either queue has unassigned driveable
  work, the campaign is UNDER-FILLED — a campaign failure on the
  same level as an unactioned verdict, recorded in one
  `agents=<live>/<cap> driveable=<n>` line on the tracking task.
  Refill SLA: when a task completes (or is confirmed dead), the
  parent dispatches its replacement in the SAME turn the
  completion is processed — never at the next keeper tick, never
  after a summary.
- **MAXIMUM PARALLELISM — the parent's own turns are the throttle
  (user directive 2026-10-27, repeated)**: the refill SLA above is
  violated most often not by missing work but by the PARENT doing
  serial inline work (folds, rebases, merges, probes) while lanes
  sit empty. Binding rules:
  1. **Fill first, every turn.** Before ANY inline parent work
     beyond a one-command probe, count live agents (`proc://`) and
     dispatch until `live == min(cap, driveable work)`. A parent
     turn that ends with dispatchable work unassigned and
     `live < cap` is a campaign failure — same class as an
     unactioned verdict.
  2. **Batch-dispatch, never drip.** Refills go out as ONE
     `task` call with many `tasks[]` (engineers + reviewers
     mixed), sized to the cap. Serial one-lane-at-a-time dispatch
     across multiple parent turns is the failure mode this rule
     exists to kill.
  3. **Inline work is capped.** Parent inline work is folds and
     merges ONLY, and only while lanes are full or no driveable
     work remains. If a fold/probe will take more than ~2 tool
     calls, it becomes a lane (engineer task with the exact
     worktree + findings), not parent serial work. While waiting
     on verdicts, the parent refills and merges — it never just
     waits with empty lanes.
  4. **Completions are refill triggers, not rest points.** Every
     completion notification (engineer, reviewer, gate) is
     processed as: stamp/merge what it unblocks, THEN immediately
     dispatch the next lowest driveable item into the freed slot,
     in the same response. Summaries and status reports never
     substitute for a dispatch.
  5. **Report the number.** Every parent status surface (tracking
     task line, keeper board read, wave summary) carries
     `agents=<live>/<cap> driveable=<n>`; if `<live> < min(cap,
     driveable)` the same message MUST contain the dispatches that
     fix it.
  6. **HARD GATE — `wait` and yield are the failure, mechanized
     (2026-10-27, third directive; the prose above kept failing).**
     The parent MUST NOT call `wait`, end a turn, or write a
     summary while `live < min(cap, driveable)`. Before any
     `wait` call the parent MUST, IN THE SAME RESPONSE, first emit
     the batch `task` dispatch that fills to the cap — the wait
     then blocks on a FULL board, never an empty one. A response
     whose only actions are wait/status/fold-on-one-PR while
     `live < cap` is a campaign failure regardless of how much
     prose explains it.
  7. **Pre-scoped pipeline (why parents end up serial).** The
     drip-feed happens because unscoped issues can't be dispatched
     blind. FIX THE INPUT, not the discipline: at every reconcile,
     the parent maintains a ready-queue of >= cap PRE-SCOPED items
     (issue + STEP-0 result + exact files + acceptance, scoped by
     scout lanes or prior engineer reports). Refill draws from the
     ready-queue WITHOUT new parent investigation; when the
     ready-queue drops below cap, SCOUT lanes (read-only,
     batch-dispatched like engineers) refill it from the
     lowest-numbered unscoped issues. Scoping is lane work, never
     parent serial work.
  8. **One response = many outcomes.** Each parent response should
     normally contain: all pending stamps/merges, one batch
     dispatch to cap, and only then any inline fold. If a response
     contains zero dispatches while `live < cap` and driveable
     work exists, it is non-compliant by construction.
  9. **Gate slots are standing lanes, not a remembered duty
     (2026-10-27).** Three of the cap's lanes are RESERVED
     gate-runner slots, one per cluster (`loss`, `tcp`, `udp`),
     filled exactly like engineer lanes: at every refill, a free
     gate slot is dispatched BEFORE the next engineer. Each gate
     lane's standing job: deploy current `origin/master` to its
     cluster and run the full measurement (merge-wave gate
     below), append the baseline record, then immediately re-run
     at the then-current master. A gate slot is never converted
     to engineer work while its cluster's baseline is older than
     the validity window.
  10. **Mix at full fill, PR work first**: (1) stamped triple
     reviewers for every PR at a reviewable head, (2) gate runners
     for gated PRs (see the three-cluster cadence below), (3)
     engineers/researchers on the lowest-numbered driveable
     issues in band order. Reserve capacity is not idle capacity:
     the 6 reserved slots are the reserve; inside the cap, all
     lanes work. Reap idle/dead agents (liveness = commit-time +
  live procs, never output-mtime) and refill from the
  lowest-number queue in the same turn. Parent does folds/small
  fixes inline when faster than dispatching. A dedicated
  **keeper/monitor agent** (see "The keeper" below) watches issue
  parallelism AND PR parallelism separately and alerts the parent
  with the `agents=` line; the PARENT alone reaps and refills
  lanes (single dispatch authority — keeper never dispatches).
- **Internal task runners only**: agents via the internal `task` tool only.
  NEVER external CLI model tools (codex/agy/claude CLIs) to run other models.
- **Full engineer + triple hostile reviews**: every PR that changes
  shipped code or behaviour gets **three independent hostile
  domain-expert reviews at the FINAL head** (findings folded, re-review
  after any fold that changes behavior). Docs/test-only PRs with no
  code or behaviour change still get three reviewers, but in short
  form (scope/accuracy verdict, no cluster gate). Reviewer pool — pick
  any 3 distinct models: **Muse Wonder (muse-wonder-1.0), Opus 5.5,
  Codex-6 Astra, GLM-5.3, Kimi K3.1 Pro**. Only 3 verdicts are
  required; the other two are the bench. This is a fail-closed veto,
  not a vote: all three must clear, and any one real finding blocks.
  The same three-reviewer requirement applies to research termination:
  PLAN-KILL requires all three independent reviewers to converge on
  rejecting the final reviewed approach. A single PLAN-KILL is
  substantive dissent to investigate/revise, not a terminal verdict.
  If a model runs out
  of credits / is quota-blocked or unreachable, swap in the next pool
  model immediately and note the swap on the PR — a blocked reviewer
  never waives the gate and never idles a lane.
- **Model seat-swap on quota death (ANY seat, user directive
  2026-10-27)**: the swap rule above covers engineers, gate runners,
  and researchers identically, not just reviewers. On a
  quota/429/rate-limit death (e.g. GLM-5.3 `[1308]`), the parent MUST
  in the SAME turn: (1) salvage the dead lane's worktree in place
  (verify + finish inline or hand the worktree to the replacement
  lane — never re-dispatch over it), and (2) re-staff the seat from
  the bench (Kimi K3.1 Pro, Codex-6 Astra, Opus 5.5, Muse Wonder —
  whichever pool models are live) so lane count never drops for a
  single model's quota. A quota error is a routing event, not a work
  stoppage: never park lanes, reviews, or gates waiting for that
  model's reset time. The pool has five models; no single quota
  blocks the campaign.
  Dispatch mechanics and the auditable verdict stamp are in Step 3.
  Message-shape gate first (see Step 3).
- **Scratch discipline**: ALL temp files, intermediate files, tests, probes,
  and worktrees live in `/var/worktrees/` (NOT `/var/tmp`, NOT `/tmp`, NOT
  inside the repo checkout). `GOCACHE=/var/worktrees/.cache/go-build`,
  `GOTMPDIR=/var/worktrees/.cache/go-tmp`, per-lane `CARGO_TARGET_DIR` under
  `/var/worktrees/.cache/` too. Clean up `/var/worktrees` scratch (reviewer
  worktrees, merged lanes, stale probes) as work completes — prune merged
  worktrees continuously, not in a final sweep. NEVER prune mid-campaign:
  `/var/worktrees/.cache/keeper/`, `/var/worktrees/.cache/tmpdir/` (lock/
  owner/epoch state), or open gate cell scripts — that is the campaign's
  live memory, not scratch. The gate-baselines directory is protected
  except for indexed captures that have expired under the rule below.
- **Host isolation — tests NEVER mutate the workstation (2026-10-26)**:
  the workstation is a long-lived host, not a sacrificial test box.
  Evidence on this host: 32 orphan `eno5v*` VLAN links, fwmark
  rules 5210-5270 + table 220, apt-installed FRR/strongSwan
  (`strongswan-starter` active), `/var/lib/xpf`, host bpffs —
  all from tests/harnesses that flip from SKIP to REAL EFFECT
  the moment they run privileged. Classes: **U** hermetic
  (fakes/fixtures) — workstation + CI, the fast loop. **N**
  netns-kernel (netlink/nft/FIB in a private netns) —
  workstation ONLY unprivileged via `unshare -rn` forcing legs
  (or the repo's self-re-exec parity pattern), NEVER as root.
  **R** init-namespace privileged (BPF load/pin, XFRM, memlock)
  and **F** live-daemon (real bgpd/zebra/charon/kea, named
  netns, `/var/run/frr`) — Incus VM legs ONLY. **V** VM/cluster
  shell harnesses (`test/incus/*.sh`, apt/systemctl/deploy) —
  Incus only, under `with-cluster.sh`; NEVER run them directly
  on the workstation. Rules: (1) no lane runs `go test`/`cargo
  test` as root on the workstation, and `sudo make test-root`
  locally is PROHIBITED (privileged legs run in the standalone
  VM leg); (2) kernel cells assert isolation in-test on a
  LOCKED thread (`runtime.LockOSThread` + netns Get): initial
  netns or host bpffs reach = `t.Fatalf`, NEVER a silent skip —
  NOT-EXAMINED is the honest local outcome; (3) BPF pin paths
  are host-global (`/sys/fs/bpf/xpf` const): class-R cells
  need a private mount ns + sacrificial bpffs or a VM, netns
  alone does NOT isolate them; (4) an env sentinel
  (`XPF_SACRIFICIAL_HOST=1`) is lane INTENT only, set solely by
  make/with-cluster wrappers inside VMs — never by hand on the
  workstation, never as proof overriding a host net+mount
  identity check; (5) every new kernel-reachable test
  (LinkAdd/RuleAdd/nft/ebpf.NewMap/exec of ip|nft|systemctl|
  apt/daemon binaries) declares its class in the same change,
  and reviewers reject undeclared host-reachable tests;
  (6) keeper residue tripwire is REPORT-ONLY (links matching
  `<phys>v[0-9]+`, fwmark 52xx/table-220 rules, `/var/lib/xpf`,
  active frr/strongswan/xpfd host units): alert, never
  auto-clean — residue may be operator state.
- **Running tests MUST NOT touch host interfaces (2026-10-27,
  user directive — the rules above failed in practice)**: declaring
  classes did not stop lanes from running broad suites unprivileged
  on the workstation and mutating host state anyway (residue above:
  32 `eno5v*` links, fwmark 52xx, table 220 — present NOW). The
  failure mechanism: "unprivileged" is not isolation — any test
  that creates links/rules/routes via netlink, execs `ip`/`nft`,
  or binds host interfaces acts on the HOST netns unless it first
  enters a private one, and a suite run inherits whatever reach
  its cells have. Binding execution rules for EVERY lane (parent
  included — no exceptions for "just checking"):
  1. **Default workstation invocation is hermetic-only.** On the
     workstation a lane runs ONLY: named tests (`-run <Exact>` /
     `-- --exact`), or packages proven hermetic (no netlink, no
     `ip`/`nft` exec, no interface mutation anywhere in the
     package's test closure). Broad `go test ./pkg/...`,
     `cargo test` (workspace), and full-package runs of
     network-reachable packages (daemon, routing, nftables,
     networkd, vrrp, ipsec, snmp, userspace-dp, dataplane) are
     PROHIBITED on the workstation — they run in the VM leg or
     not at all; record NOT-EXAMINED with the VM target.
  2. **Kernel-reachable cells run namespaced or not at all.** Any
     cell that can reach the kernel MUST execute under
     `unshare -Urn` (or the repo self-re-exec parity pattern), or
     be guarded by `internal/testisolation` (namespace identity
     vs PID 1, never euid, never an env var alone): host-netns
     reach = hard FAIL in-test, never a skip, never silent
     execution. Before running an unfamiliar cell, the lane
     greps it for `LinkAdd|RuleAdd|AddrAdd|nft|exec.Command("ip"`
     and classifies FIRST.
  3. **Prove no residue.** After any workstation test run that
     touched namespaces, the lane diffs host state before/after
     (`ip -brief link`, `ip rule`, `nft list ruleset` line
     counts) and reports it; new host links/rules = the run was
     a violation — stop, file an issue against the cell, and do
     not re-run it outside a namespace.
  4. **Reviewers enforce execution, not just declarations.** A
     PR whose validation section claims broad-suite runs on the
     workstation, or whose new kernel-reachable cell lacks the
     namespace guard, is MERGE-NEEDS-CHANGES regardless of test
     results. "It passed" is not evidence it was safe to run.
- **Disk guard — `/var/worktrees` must never fill up**: unbounded lanes
  plus Go/Rust caches will fill the volume mid-campaign if nobody owns
  it, so the keeper checks it every tick and the parent reaps. Measure
  cheaply: `df -h /var/worktrees` (percent + free) on EVERY board; the
  expensive `du -sh /var/worktrees/.cache/*` breakdown runs ONLY when
  usage is ≥70% and a reap decision is actually being made (a full
  metadata walk of a TB-scale cache on every tick is itself a disk
  workload). Thresholds on volume usage: **≥70% = flag + breakdown;
  ≥85% — OR growth projecting a full volume within one gate cycle
  (~20 min) at the recent fill rate — = parent reaps the same tick,
  before dispatching new lanes.** At the reap tier the parent FIRST
  stops dispatching and accounts for every live build proc in its
  lane registry: pause or finish-or-kill the youngest build lanes by
  explicit decision, recorded on the tracking task. Only procs the
  parent has not accounted for block cache cleanup — waiting for an
  empty box is waiting for ENOSPC, which is the failure this guard
  exists to preempt. Reap in this order, cheapest/safest first:
  (1) worktrees whose PR is MERGED or CLOSED-with-disposition
  (confirm via `gh` first): `git worktree remove <wt>`; delete the
  lane's per-issue `CARGO_TARGET_DIR` ONLY if the remove succeeded —
  if remove refuses (dirty), keep the target dir and route the
  worktree to salvage; (2) gate cell scripts and smoke logs for
  already-merged PRs; (3) gate baselines outside their validity
  window (decidable from the baselines INDEX below, never by
  guessing file contents under pressure); (4) stale lanes with no
  live procs AND a clean `git -C <wt> status --short` (a dirty
  worktree is salvage, never delete — flag it for Step 0 salvage);
  (5) caches, at the reap tier after the proc accounting above:
  Rust — remove `CARGO_TARGET_DIR`s of merged/dead lanes (per-lane,
  so this is this campaign's own space; never a live lane's).
  Go — the campaign `GOCACHE` (`/var/worktrees/.cache/go-build`) is
  SHARED box infrastructure: `go clean -cache` cold-rebuilds every
  other session on the box too. Treat it as a box-wide action: the
  parent may run `GOCACHE=/var/worktrees/.cache/go-build go clean
  -cache` at the reap tier only after the proc accounting, and must
  log that it did so (path + freed size + collateral note) on the
  tracking task. If the collateral is unacceptable, the alternative
  is dispatching future lanes with a campaign-scoped
  `GOCACHE=/var/worktrees/.cache/go-build-<campaign>` so later
  cleanup is genuinely this campaign's — pick one and record it;
  never pretend the shared cache is private.
  NEVER reap, at any tier: live lane worktrees/target dirs the parent
  has not accounted for, dirty worktrees, the never-prune list above,
  or any lock / owner / epoch file for a cluster with a live holder.
  Log every reap (path + size) on the tracking task so a missing
  worktree is never a mystery. Baselines decidability: each baseline
  capture writes a uniquely named record
  `/var/worktrees/.cache/gate-baselines/<cluster>-<masterSHA>-<capture-epoch>.md`
  and appends a one-line entry to
  `/var/worktrees/.cache/gate-baselines/INDEX` (`<cluster> <masterSHA>
  <capture-epoch> <file>`). Expiry at reap time: expired iff
  `now > capture-epoch + 4h` OR merges since capture
  (`git rev-list --count --merges <masterSHA>..origin/master` —
  merges, not raw commits; merge-commit history makes raw counts
  expire the window ~5× early) exceed 10 — both computed at reap
  time, never guessed. Only those expired, INDEX-listed capture files
  may be pruned; keep INDEX and all current captures.
- **Relative-path edit hazard (recurring)**: lanes editing via relative paths
  have repeatedly spilled changes into the control checkout or lost them.
  Briefs MUST demand absolute paths + `git -C <worktree> status --short`
  proof after edits; parent restores control after confirming the worktree
  copy is complete.
- **Three-cluster gates, in parallel**: we have THREE HA gate systems —
  `loss`, `tcp`, and `udp` (`BPFRX_CLUSTER_ENV=test/incus/<name>-userspace-cluster.env`)
  — so connectivity + transit-forwarding + throughput gates run in
  parallel, never serialized behind one cluster. Parallelism requires
  DISTINCT lock state per physical cluster and the SAME lock/owner/epoch
  tuple for every gate and ordinary command using that cluster:
  `loss` uses the exact `test/incus/cluster-lock.sh` defaults —
  `/var/worktrees/.cache/tmpdir/xpf-cluster.lock`,
  `/var/worktrees/.cache/tmpdir/xpf-cluster.owner`, and
  `/var/worktrees/.cache/tmpdir/xpf-cluster-state/epoch`; ordinary
  commands use these defaults and gates may only export the same tuple.
  `tcp` uses `/var/worktrees/.cache/tmpdir/xpf-cluster-tcp.lock`,
  `/var/worktrees/.cache/tmpdir/xpf-cluster-tcp.owner`, and
  `/var/worktrees/.cache/tmpdir/xpf-cluster-state/epoch-tcp`; `udp`
  uses `/var/worktrees/.cache/tmpdir/xpf-cluster-udp.lock`,
  `/var/worktrees/.cache/tmpdir/xpf-cluster-udp.owner`, and
  `/var/worktrees/.cache/tmpdir/xpf-cluster-state/epoch-udp`.
  EVERY caller of a `tcp`/`udp` cluster — campaign gate, ordinary
  deploy, failover, or smoke — MUST export that cluster's tuple before
  invoking any self-locking command; without these exports the scripts
  fall back to the loss tuple, so gates and ordinary commands could race
  or serialize against the wrong cluster. With these canonical tuples,
  all three clusters can run in parallel (workstation build CPU is still
  shared; only cluster access parallelizes). **Assignment (stated once,
  applies everywhere including Step 3): dataplane, forwarding, or
  throughput changes gate on `loss` — mandatory, never least-busy
  overflow; every other gated PR (or batch) goes to the least-busy
  of `loss`/`tcp`/`udp`.** The clusters are NOT interchangeable
  baselines: `tcp`/`udp` run a bridge-fabric fallback (see their env
  files), so every throughput comparison is against `origin/master`
  measured on the SAME cluster — never quote a loss number for
  `tcp`/`udp`, and never a remembered number for any cluster (the
  measured per-cluster bands are tier 2 of
  `docs/regression-test-matrix.md`). The trust/untrust directional
  matrix does NOT live on these HA clusters; policy-directional PRs
  additionally run
  `/security-matrix` directional cases on their proper topology.
  **Do not regress max throughput**: the decidable rule is Step 3
  item 4 (run 5x per head per family; block if the PR median is >10%
  below the same-cluster master median, or PR multi-stream retransmits
  (summed) exceed master's, or any forwarding failure). Known-external
  failures (e.g. upstream lab IPv6 target dead from the firewall
  itself) are recorded as such, not chased.
- **Don't bail**: no yielding at phase boundaries, todo flips, or partial
  waves. Loop audits until they come back clean; file new issues found on
  the way and drive those too.

This skill is the orchestration layer ABOVE `/research` and `/engineer`.
It does not re-implement them — it ranks the backlog, picks a route
(parallel or serial), fans out agents, and enforces the merge discipline.
It is the SINGLE skill for closing the repo out: research keeps filing
issues (a large, growing open-issue count during research is normal),
engineers convert them to PRs, and this skill lands or kills every one
of both. Do not run a separate PR-closing pass — PR landing and issue
work are fed from the same lane pool here.

## The keeper — dedicated monitor agent (eyes only, no hands)

The keeper is a MECHANISM, not a self-waking agent (background
agents do not tick on timers). At campaign start the parent authors
a small poll script under `/var/worktrees/.cache/keeper/keeper.sh`
(Step 0 commands + lock-holder reads; the parent writes it once and
shows it in the tracking task — there is no pre-existing keeper
script in the repo) and starts it as a `Monitor` loop. The script
polls every ~180s, atomically rewrites the board file
`/var/worktrees/.cache/keeper/board.md` (write temp + `mv`),
appends one `epoch,df-used-pct,df-free` line per tick to
`/var/worktrees/.cache/keeper/df-history.log` (the fill-rate trigger
in the disk guard is computed from this history — slope of the
`df-free` BYTES over the last hour of samples; used-pct is too
coarse at TB scale, 1% ≈ 40G here, and would read zero while tens
of GB/hour are consumed; prune the history with the board
rotation), AND
prints exactly one summary line per tick to stdout (`keeper:
prs=<n> issues=<total> oldest-verdict-age=<dur> stale-lanes=<n>
agents=<n>/<cap>` — the parent supplies the live-agent count
from its task registry; the keeper prints it verbatim)
— Monitor wakes the parent on stdout lines; a silent file rewrite
alerts nobody. The keeper has exactly ONE power: observe and alert.
It NEVER dispatches, reaps, refills, reviews, or merges — the
PARENT is the single dispatch authority. It is the ONLY routine
poller: the parent reads the board on each Monitor wake (and only
re-polls directly to verify before dispatch/merge), so Step 0
never runs twice per tick. Keeper death is DETECTABLE: if
`board.md` is older than 10 min, the keeper is dead — the parent
self-monitors with Step 0 and relaunches the Monitor the same tick.
Every tick the keeper:

1. Polls ground truth with the Step 0 commands (light fields only,
   plus the total-count reconciliation there). Never trusts a
   completion-notification body (they can be cross-wired between
   agents) — verifies via `gh`/`git`.
2. Publishes ONLY what `gh`/`git`/lock/disk state can prove:
   `/var/worktrees` volume usage (`df` percent/free every tick; the
   `.cache` `du` breakdown only at the ≥70% tier, with the disk-guard
   tier from the standing orders), open PR count by merge state
   including draft (from the complete paginated Step 0 scan), open
   issue TOTAL (search `total_count`, authoritative)
   plus per-band counts *where labels support it* and an `unbanded`
   remainder (60-char titles cannot classify semantics — report the
   remainder, never invent bands), per-cluster lock holder (from
   the canonical owner file for that cluster, per the standing
   orders), and the age of the oldest PR whose latest
   reviewer record has no subsequent parent action comment. Cost
   control: that verdict-age scan runs ONLY for PRs awaiting parent
   action (a reviewer record newer than the last parent action),
   using per-PR timestamps cached in
   `/var/worktrees/.cache/keeper/verdict-ages.tsv` (bootstrap: one
   full queue scan at keeper start seeds one row per open PR; each tick
   evicts rows only after a successful complete PR scan confirms they are no
   longer open; scans uncached PRs and re-scans only cached PRs whose
   `updatedAt` changed) — never an
   O(open-PRs) comment scan of the whole queue every tick, which rate-limits
   the keeper exactly when the backlog peaks. Read the paginated PR
   conversation-comment endpoint
   `gh api --paginate repos/$(gh repo view --json nameWithOwner
   -q .nameWithOwner)/issues/<n>/comments`; parent reviewer stamps
   and actions live there, not in `/pulls/<n>/comments` (which
   contains inline review comments). `updatedAt` is requested in the
   Step 0 PR field list and is the cache invalidation key. In-flight
   reviews are invisible until posted. Lane busy/idle state is NOT
   on the keeper board: the agent registry is parent-harness state,
   so the PARENT appends its own lane table to the board each time
   it acts.
3. Flags (does not act on) refill/rebalance/disk needs: disk-guard
   tier (≥70% flag, ≥85% reap-now), UNDER-FILLED lanes
   (`agents=<live>/<cap>` below `min(cap, driveable)` while either
   queue has unassigned driveable work — flagged every tick until
   the parent refills), cluster-cadence staleness (watch/baseline
   ages per "Three-cluster regular testing"), idle capacity
   while either queue has driveable work (queued PRs/issues with no
   linked lane), a gate queued on one cluster while another lock is
   free, a reviewer out of credits, a lane that looks dead
   (unreachable AND no worktree writes AND no live procs for several
   minutes; liveness is commit-time + procs, never output-mtime),
   and dead lanes possibly holding salvageable work. The parent
   verifies against its lane registry and acts the same tick — PR
   work first, then the lowest-numbered issue in band; if PRs drain,
   convert closers to engineers/researchers, and vice-versa if
   research floods in.
4. Runs the ONLINE instruction census once an hour and at keeper
   start: `make instructions-census-online` from a clean checkout at
   `origin/master`. It asks `gh` for the state of every issue an
   expiry marker names (see "Expiry markers" under Standing rules). The
   hermetic half runs in CI and `make selftest`; only the keeper sees
   an issue CLOSE, which is the event that expires those markers. Each
   problem prints one stdout line, `keeper: STALE-INSTRUCTION <tag>
   <file:line>`, so Monitor wakes the parent; the parent retires the
   instruction in the normal queue (a docs PR). A hit in CLAUDE.md is
   reported to the user as an owner action, never edited by a lane.
   Exit 77 (no `gh`) is a SKIP the keeper prints, never a pass.

## Arguments

```
/campaign                       # autonomous: rank the whole backlog, drive it to zero
/campaign <n> <n> ...           # drive a specific set of issues
/campaign serial <n> <n> ...    # force the serial route for a coupled set
/campaign parallel <n> <n> ...  # force the parallel route for a disjoint set
```

No args = full autonomous drive-to-zero over every open issue. With a
cron tick (CronCreate), each firing re-enters this skill and advances the
campaign; `CronDelete` when the backlog is terminal.

## Continuous smoke watch (standing, never blocking)

Run a permanent smoke-feedback lane OUTSIDE the parallel agent lanes
(it does not count against lane limits and never gates a merge). This
watch is a background regression tripwire on `loss` only — it is NOT
the per-PR gate (Step 3 item 4, which runs on the assigned cluster
and DOES gate merges). Never cite a green watch as a passed gate:

- A background service loops every ~15 min against the current master
  tip. "Current" is measured, not assumed: before each run the watch
  fetches and resets its OWN clean checkout to `origin/master` and its
  log line carries `master=<sha>`; a line whose SHA is not the tip is
  a stale watch, not a datapoint (on 2026-10-31 a watcher had run a
  four-day-stale checkout). Each run: (1) `test-connectivity.sh
  cluster`, (2) LIVE node CLI probes on the operator's firewall
  (`incus exec loss:xpf-userspace-fw0 -- cli -c
  "show chassis forwarding"` + flow statistics; FWDD state and
  created==closed session balance are the tripwires). Appends one line
  per run to `/var/worktrees/.cache/smoke-watch/smoke-watch.log`.
- The parent reads the latest lines at every landing-queue check. A NEW
  failure (one not listed under "Known product failures (tracked)" in
  `docs/regression-test-matrix.md`, and not a "Known environment rows"
  cell whose off-path control still fails) or a tip regression
  vs the previous line = a correctness feedback signal: file an issue
  immediately and forward-fix it in the normal queue — do NOT stop or
  slow the landing queue for it, and never hold a PR for the watch.
- The baseline is the deployed master's own latest line. The cells
  expected red, each with its issue, are listed under "Known product
  failures (tracked)" in `docs/regression-test-matrix.md`, each with
  its owner. The 2026-10-13 baseline excused
  "LAN host -> internet IPv6" as environment without a control. Its
  traceroute half was a product defect (ping to a live host worked
  while every hop past the firewall was `???`, #18174); its ping half
  was a dead target, and #18556 retargeted the harness to
  `2001:4860:4860::8888`.
  Deviations from the baseline are the signal; the baseline itself is
  not.
- Perf mistakes ride the same loop: when a perf-relevant merge lands,
  note the tip in the log; a connectivity or throughput datapoint that
  regresses against the prior tip gets an issue + forward-fix, in band.

## Three-cluster regular testing (standing cadence, enforced)

Per-PR gates (Step 3 item 4) prove the PR; this cadence proves the
CLUSTERS and current master continuously, independent of which PR
is in flight. Both duties are mandatory — a campaign that only
gates PRs discovers a dead `tcp`/`udp` cluster weeks later.

**The row-by-row checklist is `docs/regression-test-matrix.md`** (tiers
0–4: build, deploy identity, forwarding and performance, HA, soak). Each
row names the defect it exists to catch. A merge-wave gate runs tiers 2–3
of that matrix on `loss` and `tcp`. A row is dropped only after naming
what else catches its defect.

- **Continuous watch, all three clusters**: the smoke watch (above)
  covers `loss` every ~15 min. Add the same loop for `tcp` and
  `udp`: every ~30 min (offset so the three never collide),
  `test-connectivity.sh cluster` against that cluster's env +
  canonical lock tuple, appending
  `epoch cluster=<C> master=<SHA> result=<pass/fail counts>` to
  `/var/worktrees/.cache/smoke-watch/smoke-watch-<C>.log`.
  Watch lanes never gate merges and never deploy (connectivity
  probes only, under the cluster lock discipline).
- **Merge-wave gate, all three clusters**: after every merge wave
  (and at least hourly while merges are landing), deploy current
  `origin/master` and run the full Step 3 item 4 measurement
  (connectivity + single-stream + 5x multi-stream per family) on
  EACH of `loss`, `tcp`, `udp` — three gate-runner lanes in
  parallel, one per cluster, each inside its own lock cell.
  Results append to that cluster's baseline INDEX as the fresh
  master baseline (Step 3 item 4 validity window). A wave is not
  "landed" until all three cluster records exist at the new
  master SHA or an env failure is recorded per cluster.
  **Trigger is a counter, not a memory (2026-10-27):** the parent
  counts merges since each cluster's last completed gate. At 5
  merges (or 60 min, whichever first) that cluster's gate slot
  MUST be dispatched at the next refill — ahead of new engineer
  work. The count lives on the tracking task line
  (`gates: loss=<n> tcp=<n> udp=<n>` = merges since last gate).
  A cluster whose gate is BLOCKED (env failure, e.g. a deploy
  floor) never excuses the other two: each cluster gates on its
  own slot independently, and a blocked cluster's env failure is
  recorded and re-dispositioned (fix / named-rollback / escalate)
  within one wave — never left as an open deferral while merges
  continue past it.
- **Keeper enforcement**: every keeper tick reads the last line
  of each `smoke-watch-<C>.log` and each cluster's newest baseline
  INDEX row, and prints staleness in the summary line
  (`watch: loss=<age> tcp=<age> udp=<age> base=<ages>`). Loss
  watch older than 30 min, tcp/udp watch older than 45 min, or a
  baseline older than the validity window while gated PRs wait =
  STALE flag; the parent relaunches the watch / dispatches gate
  runners the same tick. **The keeper's `base=` age is a dispatch
  trigger for the parent, not a report:** a parent response that
  reads a STALE baseline and does not dispatch that cluster's
  gate slot in the same response is the same campaign failure as
  an unactioned verdict. A NEW failure (one not tracked in the
  matrix's "Known product failures", and not an environment row whose
  off-path control still fails) on any cluster files an issue immediately
  and enters the normal queue — it never holds the landing queue.
  Downstream skills (`security-matrix`, `failover-test`,
  `perf-test`, `userspace-ha-validation`) run their own topology
  when a PR needs them; this cadence is the floor, not the ceiling.

## The cardinal rule

**You (the PARENT) own review and merge.** Reviewer dispatch capacity
is whatever the internal task runner provides — the three reviewers
may run concurrently or queue; the gate requires three verdicts at
the same final head, NOT simultaneity. Spawned engineer agents
CANNOT dispatch their own sub-reviewers. Therefore:

- **PARENT dispatches THREE independent hostile reviewers for EVERY
  PR** — three distinct models from the pool (Muse Wonder, Opus 5.5,
  Codex-6 Astra, GLM-5.3, Kimi K3.1 Pro), each read-only,
  worktree-scoped, primed as a hostile domain expert, ending with a
  verdict at the FINAL head. All three must clear before merge; any
  real finding from any one blocks. See `/review-pr` for the
  hostile-review shape. Only the declared model pool reviews —
  Copilot is not part of any gate (user directive 2026-10-26).
- **PARENT merges**, never the spawned agent. Agents implement + test +
  open the PR and STOP.

## Step 0: Reconcile ground truth (keeper every tick; parent verifies before dispatch/merge)

```bash
git fetch origin master
git rev-parse --short origin/master
# Light fields only — never fetch full issue bodies for a board poll.
gh issue list --state open --limit 1000 --json number,title,labels \
  --jq '.[] | "#\(.number) [\(.labels|map(.name)|join(","))] \(.title[0:60])"' | sort -n
# Total-count reconciliation: the list above silently caps at 1000.
REPO=$(gh repo view --json nameWithOwner -q .nameWithOwner)
gh api "search/issues?q=repo:${REPO}+state:open+type:issue" \
  --jq '.total_count'
gh api --paginate "repos/${REPO}/pulls?state=open&per_page=100" \
  --jq '.[] | "#\(.number) [\((if .mergeable == null then "unknown" else (.mergeable | tostring) end))] draft=\(.draft) \(.head.ref) updatedAt=\(.updated_at)"'
```

The search `total_count` is authoritative for backlog size. If the
listed issue count != `total_count`, the board is incomplete: say
so on the board and page (`--limit 1000` with label/number filters)
until they reconcile — never report a capped count as the backlog
size.

The PR `--paginate` command follows every linked API page for the open PR
queue. Treat the queue as complete only after that command exits successfully;
derive open-PR counts and cache evictions only from a complete scan. If any
page fails, mark the queue incomplete and preserve all cached PR rows until a
complete scan confirms which PRs are closed.

Then `TaskList` to read the tracking task (the campaign's state-of-record),
and wedge-check any running agents. **Liveness = branch/PR commit-time AND
active cargo/go procs — NOT agent output-mtime** (a 5x-flake-check looks
idle but isn't; don't premature-kill). Do NOT read agent JSONL transcripts
(they overflow context); use the completion notification or a bounded
`grep -ao` of the `.output` file to recover a dropped verdict.

## Step 1: Rank the backlog

Sort every open issue into priority bands, highest first:

1. **Correctness / security bugs** (data-plane drops, fail-open, UAF,
   deadlock, wrong-tuple classification, no-transit).
2. **Features** with a clear spec.
3. **Refactors** (pure code-motion preferred — no architectural premise to
   fail).
4. **Lab/operator-bound** — needs hardware, a live capture, an operator
   secret/URL, or a maintainer decision.

Within each band, prefer issues whose IMPLEMENTATION is driveable now even
if final verification is lab-bound — **ship the code, defer only the
lab-verify** (record the deferral on the issue).

Classify each issue as **disjoint** (touches files no other in-flight issue
touches → parallel route) or **coupled** (shares files / depends on another
issue's merge → serial route). Record the ranking + route on the tracking
task.

### `plan-deferred` is NOT a terminal state — it is a WORK QUEUE

**A `plan-deferred-*` label parks nothing. Drive-to-zero means every open
issue reaches MERGED or a rigorously reviewed PLAN-KILL — not a `plan-deferred`
label that leaves the issue open forever.** Deferring with a reason is a
throughput failure, not a disposition. The correct response to a hard problem
is to `/research` it to a converged plan and `/engineer` it to a merge (or a
PLAN-KILL only when all three independent `/research` reviewers converge on
rejecting the final reviewed approach), NOT to write "defer, revisit on demand"
and move on.

So on every campaign pass, **re-open the `plan-deferred` set and drive it**:

- **`plan-deferred-research`** (design/refactor/needs-a-plan) → this is the
  MAIN queue. `/research` each to a converged plan, then `/engineer` it to a
  MERGE. A refactor whose premise is stale (file already under threshold, target
  already extracted, already-fixed) → CLOSE it as such (that IS terminal). A
  refactor that survives review as genuinely-not-worth-it → PLAN-KILL only
  after all three independent `/research` reviewers converge on rejecting the
  final reviewed approach (label `plan-kill`, close). "Unproven codegen risk"
  is a reason to add an asm-diff gate and DO the extraction, not to defer it
  indefinitely.
- **`plan-deferred-operator` / `plan-deferred-lab`** → **ship the CODE, defer
  only the external verify.** A "needs an operator decision" is a design
  question to resolve in `/research` (pick the safe default, document it) then
  implement; a "needs hardware/a live capture" ships the implementation +
  records the specific lab-verify as the only outstanding item on the issue.
  Do NOT let "operator/lab" block the code.
- The ONLY genuinely-terminal-without-driving case is a maintainer-held issue
  you were explicitly told not to touch → record the hold reason, leave open,
  do NOT touch held code.

Never write a fresh `plan-deferred` label to escape a hard item. If `/research`
converges on PLAN-KILL with all three reviewers rejecting the final reviewed
approach, that is terminal (label `plan-kill`, close). One PLAN-KILL is
substantive dissent: investigate/revise and re-review, never close. If the
reviewers converge PLAN-READY, `/engineer` it to a merge. There is no third
"deferred" outcome except a maintainer hold or a hard external dependency whose
CODE is already shipped.

## Step 2: Pick a route

### Parallel route (default — disjoint issues)

Fan out wide. For each disjoint issue, dispatch a `general-purpose`
engineer agent (or `/research` first if the design needs human judgement).
Run as many concurrently as the box allows, subject to the agent
concurrency caps in the standing orders (the spend cap, bounded by
`2*nproc - 6` live campaign agents; queue beyond it).

- **Unique `CARGO_TARGET_DIR=/var/worktrees/.cache/cargo-<issue>` per Rust
  agent** (scratch rule above — never `/dev/shm` or `/tmp`) — 8 concurrent
  `cargo --release` against one target dir thundering-herds and starves
  them all. Cap concurrency to ~cores.
- Each agent: fresh worktree off CURRENT master
  (`git worktree add -b fix/<n>-campaign-pub /var/worktrees/campaign-pub/wt-<n> origin/master`),
  implement + fail-on-revert tests + build green + open PR ("Closes #<n>")
  + STOP (do not merge, do not dispatch reviewers). Every PR carries its
  own per-change log, `docs/log/<issue>.md` (or `docs/log/<pr>.md` when
  there is no issue), in the same diff — the log
  lands atomically when the PR lands, as has been the practice; there is
  no separate log step and no root `_Log.md` append. The log carries
  the `docs/log/README.md` fields (Timestamp / Action / File(s)) under
  a `# #<issue> — <title>` heading, plus Validation and Risk entries
  matching the PR body's evidence. **Missing log = incomplete PR**: the
  Step 3 gate bounces it back to the lane before any code review,
  exactly like a message-shape violation — the lane adds it (new
  commit or amend, lane's choice), never the parent. A PR classified
  `docs/test-only` still carries the log unless the diff IS the log
  file itself.
- **Commit-message standard (lanes, enforced)** — state verbatim in every dispatch/fold brief (including: the PR TITLE MUST use the same `<area>: <summary> (#NNNN)` subject format — it becomes the merge-commit message); parent bounces non-conforming branches before review (`git log` shape check at PR intake, Step 3 item 1).
  - Subject: `<area>: <imperative summary> (#NNNN)`, ≤72 cols. Area vocabulary: `docs:`, `test:`, `assurance:`, `forwarding:`, `config:`, `daemon:`, `cluster:`, `sessions:`, `audit:`, `show:`, `telemetry:`, `nftables:`, `ha:`, `frr:`, `process:`, `userspace-dp:`, `afxdp:`, `policy:`, `nat:`, `firewall:`, `grpcapi:`, `snmp:`, `ipsec:`, `xdp:`, `shim:`, `ci:`, `build:`, `metrics:` (new areas allowed when none fits, never bare). Summary names the BEHAVIOR change in imperative mood (`gate`, `drop`, `reject`, `refund`, `sync`, `bound`, `fence`), not the file (`update foo.rs`). Parent process commits without an issue cite the ruling (`(user-directive 2026-09-22)`).
  - Body (required, via `git commit -F -` heredoc, wrapped ~72 cols) has four sections:
    1. `Why:` the defect mechanism + consequence — what breaks, who/what is affected, under what config/traffic. 2–5 lines. Cite the path (`poll → session → TX`), not just "fixes bug".
    2. `What:` approach + key files/symbols + deliberate scope cuts (`NOT changed: X because Y`). A reader must know where to look without opening the diff.
    3. `Validation:` exact commands + results — new tests with RED evidence (`fails pre-fix with <assertion>`), suites with totals (`6980 passed, 1 failed (#9894, base-attributed on <sha>)`), BPF verifier headroom for shim changes, lint state.
    4. `Risk:` residuals, follow-ups filed (`#NNNNN`), operator-visible behavior deltas. Omit only when genuinely none — never omit silently on enforcement-path changes.
  - One logical change per commit; each commit builds; squash WIP/scratch before push. Split fix vs test-only vs docs vs generated-artifact regen vs review-fold into separate commits. Review-fold commits describe what review finding they address and why, never `address review`.
  - PROHIBITED: `Issue #NNNN:` prefix form, ref-less subjects (`Fold review hardening`), title-only commits, `wip`/`fix`/`misc` checkpoint messages on pushed branches, backticks in `git commit -m` (heredoc always — messages contain backticked identifiers).
  - Good: `userspace-dp: refund ICMP budget on policy refusal (#10667)` + Why (refused errors exhaust the 64-burst, starving permitted ones) / What (carry budget_key through reversal arms; refund at TTL/CoS/policy terminals) / Validation (3 cells RED pre-fix; full --bins 6952+1 #9894@<sha>) / Risk (post-queue TX drops still unrefunded — rare, pre-existing).
  - Bad: `fix icmp bug`, `Issue #10667: update embedded_icmp.rs`, `Fold review hardening` (no ref, no behavior, no validation).
- **Worktree hygiene is absolute**: agents point at `/var/worktrees/campaign-pub/wt-<n>` (OUTSIDE the repo — never `.claude/worktrees/`, which an in-repo wipe can destroy),
  NEVER the main checkout. Read other branches via `git show <ref>:<path>`,
  never `git checkout` in the main checkout.

**Batch-smoke optimization (disjoint dataplane PRs):** integrate N
disjoint dataplane PRs onto ONE integration branch and run ONE cluster
gate (connectivity + transit throughput, Step 3 item 4) as a
SUPPLEMENT — it never replaces per-PR review stamps or per-PR gate
records at each PR's own head (Step 4 item 0). Record the integration
result on each PR in the batch in addition to its own-head evidence,
then merge them individually. Spread concurrent batches across
`loss`, `tcp`, and `udp` — never queue every batch behind one
cluster. Code in disjoint regions auto-merges; a shared file touched
by two PRs needs an additive merge (keep both — e.g. gre.rs
`outer_ecn_bits` ‖ `inner_dst_ip`). (Per-issue logs are separate
`docs/log/<issue>.md` files and do not conflict; the root `_Log.md`
is closed — never union-resolve it, see CLAUDE.md Logging Rules.)
This amortizes the shared cluster lock without serializing the
campaign on a single gate system.

### Serial route (coupled issues)

When issues share files or one depends on another's merge, chain them: each
agent bases off the PRIOR merge, not stale master. Use this for:

- A multi-increment refactor (each commit/PR builds on the last).
- Issues that touch the same hot file (avoid N-way code conflicts).
- A feature whose pieces have an ordering dependency.

Drive one to MERGED, fetch master, then start the next off the new master.
Slower but conflict-free; the right call when the parallel route would just
manufacture merge conflicts.

## Step 3: Review every PR (PARENT)

For each PR an agent opens:

1. **Message-shape + log gate (BOUNCE before any code review)** — run `git log origin/master..origin/<branch> --format='%h %s%n%b'`, `gh pr view <n> --json title -q .title`, and the diff file list (`gh pr view <n> --json files --jq '.files[].path'`). EVERY branch commit MUST match `<area>: <imperative summary> (#NNNN)` + Why/What/Validation/Risk body (per the commit-message standard); the PR TITLE must match the same subject format (it becomes the merge-commit message). The diff MUST contain the per-change log `docs/log/<issue>.md` (or `docs/log/<pr>.md` when there is no issue) carrying the `docs/log/README.md` fields (Timestamp / Action / File(s)) plus Validation and Risk entries; a missing or stub log (any of those five entries absent) is the same class of violation as a malformed title. Exception, mirroring Step 2: a diff that consists solely of per-change log file(s) is its own log and passes this check. Bounce ANY violation back to the lane (amend + force-push) before reading a line of diff — title-only commits, bare `fix:`, missing refs, missing logs, and malformed PR titles are all merge-blockers. No exceptions, no parent-side repair (the lane owns its history).
2. **Re-verify the FINAL head** — `gh pr view <n> --json headRefOid`.
   Always review and merge the head you just polled, never the head
   you saw when review started — heads move under folds and rebases.
3. **Classify, then dispatch the triple hostile review.** The PARENT
   classifies the PR from the diff (`git diff --stat origin/master...HEAD`),
   never from the author's label: (a) `code/behaviour` — any shipped
   code or behaviour change; (b) `docs/test-only` — diff touches only
   docs, comments, or tests, with no shipped-code change. Test-only
   still gets full test-suite validation; docs/test-only skips only
   item 4, and the parent records the diff stat justifying the class
   on the PR. Code-motion inside the packet/dataplane path is class
   (a) and is gated — "pure move" exempts nothing on the hot path.
   Then dispatch THREE background reviewers via the internal `task`
   tool, each explicitly requesting a distinct model from the pool
   (Muse Wonder, Opus 5.5, Codex-6 Astra, GLM-5.3, Kimi K3.1 Pro),
   worktree-scoped, READ-ONLY (reviewers never write to the PR; they
   **Pool rotation (user directive 2026-10-26): dedicated
   reviewer agent types exist for Astra (`res-camp-astra`), GLM
   (`res-camp-glm`), Opus (`res-camp-opus`), and Kimi
   (`res-camp-kimi`, model `kimi-code/k3.1-pro`). Kimi was
   historically never used: dispatches defaulted to the three
   older dedicated types or generic `task` agents (which silently
   run the parent default, muse-wonder) and nobody named Kimi.
   Every PR's triple MUST rotate: across any 3 consecutive PR
   triples, each pool model serves at least once and no model
   serves all three triples. A generic `task` reviewer counts
   ONLY as Muse Wonder — never relabel it as another pool model;
   the stamp records the ACTUAL runtime model the result reports.
   If a pool model is quota-blocked/unreachable, swap in the next
   pool model the same tick and note the swap on the PR.
   Brief template (fill per
   PR): "You are a hostile domain-expert reviewer (HPC networking /
   OS / CPU / protocols; xpf is an eBPF firewall with a userspace
   AF_XDP Rust dataplane). Review PR #<n> at head <SHA> in
   <worktree>. Presume something is wrong. Verify every claim
   against the code at this SHA and cite file:line; reproduce
   findings where possible. Check: diff vs claimed scope,
   API/caller impact, datastructure/BPF invariants, hot-path
   allocation, concurrency, numerical edges, backward compat,
   tests on real call sites, claimed vs actual smoke. Return
   exactly one verdict line: VERDICT: MERGE-READY /
   MERGE-NEEDS-MINOR / MERGE-NEEDS-MAJOR, preceded by findings."
   **Authoritative channel + audit record:** the task RESULT
   returned to the parent is authoritative in-session; the durable
   record is what the parent — and only the parent — posts to the
   PR: the reviewer's FULL findings text as a PR comment, headed by
   `Reviewer: <model> | Task: <task-id> | Head: <SHA> | Verdict:
   <verdict>`. Posting full text (not just the verdict word) is
   required so a post-merge audit can reconstruct what was reviewed
   after task results are gone. At merge time the parent checks the
   record is PRESENT at the head being merged; resolving `<task-id>`
   to a live task is required only while the session lives (task
   results are ephemeral — never make a merged PR retroactively
   fail its checklist because a task expired). A self-posted
   reviewer comment without the parent header, or a verdict at a
   different SHA, does not count. (This is a record of dispatch, not
   cryptographic proof of model identity — if the runner cannot
   honour the requested model, the result says so and the parent
   records the substitution; never silently relabel.) If a model is out of
   credits/quota, swap in the next pool model the same tick and note
   it on the PR. Depth by risk (count is always three; docs/test-only
   uses the same three records in short form and skips item 4):
   - pure code-motion outside the packet path → triple review + tests
   - hot-path / failover / session / CoS / HA / RA / FRR / WG →
     triple review + cluster gate below (failover PRs add
     `test-failover`; dataplane PRs add iperf throughput)
   - upgrade / correctness / security → triple review, maximal depth
   All three must reach MERGE-READY at the same final head; any real
   finding from any one blocks (fail-closed veto, not majority vote).
   Parent verifies every cited finding against the actual code before
   folding — stale/disproven findings are recorded as such, never
   folded. Reviewer findings are claims, not facts (CLAUDE.md,
   "Working Style"): read the cited line at the REVIEWED SHA, not at
   today's head, because a fold or rebase can move or remove it.
   **Fold-loop cap:** at most 3 review/fold cycles per PR
   (cycles count across rebases/folds for the same PR number; record
   the count on the PR). On the 3rd unresolved cycle, stop folding
   and escalate: parent chooses split-into-smaller-PRs or
   re-`/research`, and LOGS the escalation (cycle count, reason,
   chosen path) on the linked issue AND increments the campaign
   split/escalation count on the tracking task, so a pathological
   issue is visible as such at termination — exhaustion alone never
   closes a PR; "superseded" requires naming the superseding PR.
   **Same root cause two rounds running = remove the mechanism.**
   Do not wait for the cap when two consecutive rounds' findings
   share one root cause: the fold is patching symptoms of a mechanism
   that should not exist. Remove it and close the hole another way.
   #18601's fold for #18606 produced a new HA defect two rounds
   running; removing that mechanism and closing the hole with a
   separate commit-time refusal (#18616) ended the loop.
4. **Gate on forwarding + throughput (three clusters in parallel).**
   The rows a PR must pass, by area, are in
   `docs/regression-test-matrix.md` (tier 0 before any cluster time; HA
   and session PRs add tier-3 H1–H11). H11 is the one-node RG-move soak
   (`make test-rg-move-soak`, #18583): the operator's alternating
   `node 0`/`node 1` loop from ONE node with no clock resync, scored per
   move (`docs/ha-rg-move-correctness.md`). The mechanics below still apply.
   **Test the way the operator does.** The reference is the user's
   own loop: `request chassis cluster failover redundancy-group <N>
   node <0|1>`, alternating, every 5 s, issued from ONE node, with
   nothing between moves; `make test-rg-move-soak` (#18587) is its
   harness. A gate that does what the operator cannot is measuring
   the harness: no clock resync, no silent restore or config reset
   between moves, no retry that hides a refused move. Every
   precondition (NTP sync, target claim, server idle, build identity)
   is MEASURED and scored PASS / VOID / FAIL in the record, never
   silently repaired. The crash gates' clock fix-up (`date -s`,
   removed in #18614) hid the state the operator's loop ran in: on
   2026-10-31 loss's fw1 was 72 s behind, and every operator move to
   node 1 failed fabric-RPC auth (`docs/ha-rg-move-correctness.md`,
   "Measured").
   **Pre-gate environment checklist** (inside the lock cell, before
   the first measured cell; each line goes in the gate record):
   - the iperf target is claim-probed with one holder, the
     `ha_target_claim_check` cell in `make test-connectivity`
     (#18576, #18619); a second holder or a silent control is VOID,
     and no throughput number from that run counts;
   - `chronyc tracking` shows `Leap status: Normal` on BOTH nodes,
     and `show configuration system ntp` shows the `server ...
     routing-instance mgmt` stanza (#18584);
   - the target's iperf3 servers are idle: count ESTABLISHED sockets
     on their ports (`ss -tn state established '( sport = :5211 )'`
     on the target container); if any, restart them, wait for
     LISTEN, and record the count you cleared (#18631). A restart
     the record does not show is a silent repair;
   - each node's build by GIT HASH (`/usr/local/sbin/xpfd version`
     prints `commit <sha>`), never by deb version number: lanes'
     hand-picked versions collided, so a version does not name a
     build;
   - `loadavg` of the orchestrator beside EVERY throughput number
     (the workstation's build load moves loss numbers).
   Skipped only for parent-classified `docs/test-only` PRs (Step 3
   item 3). Otherwise: dataplane/forwarding/throughput PRs MUST gate
   on `loss`; every other gated PR uses the least-busy cluster `<C>`
   (`loss` | `tcp` | `udp`) as defined once in the standing orders.
   BUILD THE PR HEAD outside the lock (never the control checkout —
   `make` in control builds clean master and gates the wrong code),
   then run deploy + ALL measurement inside ONE lock cell. Every
   cluster caller must use that cluster's canonical tuple from the
   standing orders. For `loss`, use the exact `cluster-lock.sh`
   defaults; for `tcp`/`udp`, export their stated tuple before
   invoking `with-cluster.sh` (ordinary commands must do the same).
   Pattern (per `docs/engineering-style.md`; the failover skill's
   single-cell shape):
   ```bash
   WT=/var/worktrees/campaign-pub/wt-<n>          # PR worktree
   export WT
   C=<C>                                          # loss | tcp | udp
   export BPFRX_CLUSTER_ENV="test/incus/${C}-userspace-cluster.env"
   case "$C" in
     loss)
       export XPF_CLUSTER_LOCK=/var/worktrees/.cache/tmpdir/xpf-cluster.lock
       export XPF_CLUSTER_OWNER=/var/worktrees/.cache/tmpdir/xpf-cluster.owner
       export XPF_CLUSTER_EPOCH=/var/worktrees/.cache/tmpdir/xpf-cluster-state/epoch
       ;;
     tcp|udp)
       export XPF_CLUSTER_LOCK="/var/worktrees/.cache/tmpdir/xpf-cluster-${C}.lock"
       export XPF_CLUSTER_OWNER="/var/worktrees/.cache/tmpdir/xpf-cluster-${C}.owner"
       export XPF_CLUSTER_EPOCH="/var/worktrees/.cache/tmpdir/xpf-cluster-state/epoch-${C}"
       ;;
     *) echo "unknown cluster: $C" >&2; exit 2 ;;
   esac
   # Allocate a box-unique, monotonic version, then build it outside
   # the cluster lock. Never hand-pick 0.0.NNNNN: lanes collided, and a
   # number below the deployed one is an apt downgrade that refuses
   # (#18645). The allocator holds a flock on a shared counter and
   # starts above every 0.0.N it can see (debs under /var/worktrees,
   # the PR's and master's commit counts). master's copy runs for a PR
   # based before the script existed.
   DEB_N=$(git -C "$WT" show origin/master:scripts/next-deb-version.sh |
     sh -s -- --git "$WT")
   case "$DEB_N" in 0.0.[0-9]*) ;; *) echo "no deb version" >&2; exit 1 ;; esac
   BUILD_DEB_VERSION="$DEB_N+g$(git -C "$WT" rev-parse --short=12 HEAD)"
   make -C "$WT" deb DEB_VERSION="$BUILD_DEB_VERSION"
   PR_HEAD=$(git -C "$WT" rev-parse HEAD)         # record == PR head
   # Select by explicit Debian version and exact package metadata, never
   # mtime. The numeric xpf_[0-9]* glob excludes xpf-appliance_*; Package
   # and Architecture checks fail closed if the filename is misleading.
   DEB_FILE=
   for candidate in "$WT"/dist-deb/xpf_[0-9]*_amd64.deb; do
     [ -f "$candidate" ] || continue
     [ "$(dpkg-deb -f "$candidate" Package)" = xpf ] || continue
     [ "$(dpkg-deb -f "$candidate" Architecture)" = amd64 ] || continue
     [ "$(dpkg-deb -f "$candidate" Version)" = "$BUILD_DEB_VERSION" ] || continue
     DEB_FILE=$candidate
     break
   done
   test -n "$DEB_FILE" || { echo "built xpf package not found" >&2; exit 1; }
   DEB_VERSION=$(dpkg-deb -f "$DEB_FILE" Version)
   test "$DEB_VERSION" = "$BUILD_DEB_VERSION"
   export DEB_FILE                                  # exact path pin only
   unset DEB_VERSION BUILD_DEB_VERSION             # never into locked make
   # Write the whole gate as ONE cell script, then run it under ONE lock:
   cat > /var/worktrees/.cache/gate-<n>-<C>.sh <<'CELL'
   set -euo pipefail
   cd "$WT"                                       # cell cwd = PR worktree
   source test/incus/deploy-lib.sh
   # deploy_gate_wave preserves the exact checkout fence. Deploy the
   # prebuilt package by path; DO NOT pass DEB_VERSION to make while
   # locked: Makefile prepare-deb treats an explicit version as a
   # request to run make deb again. This bypasses that prerequisite
   # without weakening artifact selection or build attestation.
   deploy_gate_wave "$WT" test-connectivity make \
     env BPFRX_CLUSTER_ENV="$BPFRX_CLUSTER_ENV" \
       XPF_CLUSTER_SKIP_BUILD=1 XPF_DEPLOY_DEB_PATH="$DEB_FILE" \
       "$WT/test/incus/cluster-setup.sh" deploy all
   source test/incus/cluster-env.sh             # cluster host/iperf targets
   source test/incus/cluster-build-identity.sh
   xpf_cluster_rebaseline_build                 # sanctioned deploy in THIS cell
   xpf_assert_cluster_build_unchanged           # fatal if measured != deployed
   # Pre-check (labelled PRECHECK in the record; never a measured cell):
   # target actually serves iperf3, else env failure, not PR failure:
   sg incus-admin -c "incus exec $CLUSTER_LAN_HOST -- timeout 5 iperf3 -c $IPERF_TARGET4 -t 1 -p 5201" >/dev/null
   sg incus-admin -c "incus exec $CLUSTER_LAN_HOST -- iperf3 -c $IPERF_TARGET4    -t 5 -p 5201"
   sg incus-admin -c "incus exec $CLUSTER_LAN_HOST -- iperf3 -c $IPERF_TARGET4 -R -t 5 -p 5201"
   sg incus-admin -c "incus exec $CLUSTER_LAN_HOST -- iperf3 -c $IPERF_TARGET6    -t 5 -p 5201"
   sg incus-admin -c "incus exec $CLUSTER_LAN_HOST -- iperf3 -c $IPERF_TARGET6 -R -t 5 -p 5201"
   # (multi-stream + CoS cells per pass/fail rules below, same cell)
   CELL
   ./test/incus/with-cluster.sh "gate PR #<n> on $C" -- bash /var/worktrees/.cache/gate-<n>-<C>.sh
```
   Deploy from the PR worktree's prebuilt, path-pinned package and run
   `test-connectivity` plus every required measurement in the same cell;
   if deployed-SHA != PR-head-SHA, the gate has not run — record that
   and do not substitute a master run. For CoS cells, apply config to
   the ACTIVE RG primary (resolve it — `./test/incus/active-fw.sh`
   / cluster status — never blindly `$FW0`, which may be secondary
   after a failover), then sweep 5201–5206 in the same cell. HA PRs
   add `test-failover` on the same env in the same cell. Connectivity
   alone is not a passed gate, and never run iperf cells after the cell
   exits — the next lane's deploy would invalidate them. Per-PR gate
   budget: target ≤20 min inside the lock (excluding queue wait); when
   the queue is deep, the baseline cache below is what keeps this
   affordable — never cut reviewer count or skip the PR-head build to
   save gate time.
   Policy-directional changes additionally run `/security-matrix`
   directional cases (trust→untrust ALLOW, untrust→trust BLOCK,
   trust→trust ALLOW + negative control) on the security-matrix
   topology — the HA clusters have no per-zone hosts and do not
   substitute for it. If that topology cannot forward even on
   unmodified master (known standalone black-hole), record
   `directional: INCONCLUSIVE (env)` with the master control result;
   never record it as pass or as a PR failure.
   **Pass/fail per cell (decidable; accepted tradeoff stated):**
   compare against a CACHED baseline per cluster with a VALIDITY
   WINDOW (keying by master SHA alone invalidates on every merge —
   the campaign's main activity — so the window is time/count
   based): the first gate needing a baseline deploys master on that
   cluster (clean master worktree, config reset) and measures. Capture
   the epoch before writing the uniquely named record, then append its
   index row only after the complete record exists:
   ```bash
   MASTER_SHA=$(git -C "$MASTER_WT" rev-parse HEAD)
   CAPTURE_EPOCH=$(date +%s)
   mkdir -p /var/worktrees/.cache/gate-baselines
   BASELINE_FILE="/var/worktrees/.cache/gate-baselines/${C}-${MASTER_SHA}-${CAPTURE_EPOCH}.md"
   # Save the complete measured baseline (SHA and every cell's data) to $BASELINE_FILE.
   printf '%s %s %s %s\n' "$C" "$MASTER_SHA" "$CAPTURE_EPOCH" "$(basename "$BASELINE_FILE")" \
     >> /var/worktrees/.cache/gate-baselines/INDEX
   ```
   `INDEX` rows have the form `<cluster> <masterSHA> <capture-epoch>
   <file>`. It stays valid for 4 hours OR 10 subsequent merges,
   whichever comes first; every PR record names the baseline SHA + its
   age/merge-drift. Accepted drift risk: master content merged inside
   the window is itself gated, so the baseline lags reality by at most
   that window; re-baseline early if gate-relevant config/fixtures
   change or the lab is visibly degraded. Never re-deploy master for
   every PR (that doubles lock hold for zero information). PR
   measurement always follows a config reset so prior-PR state cannot
   leak in.
   - Connectivity + single-stream cells (4: v4/v6 × push/reverse):
     PASS iff traffic flows and PR retransmits ≤ master retransmits
     for the same cell. Single-stream throughput is not rate-gated
     (per-CPU caps make it a connectivity check, not a perf check).
   - Multi-stream throughput cell (`-P 12 -t 10 -R`, v4 and v6):
     run 5× per head per family. For each family, BLOCK if the PR
     five-run median is more than 10% below the same-cluster master's
     five-run median, regardless of how many individual runs are
     below that median; otherwise PASS this rate check only if the
     PR's summed retransmits are ≤ the master's summed retransmits.
     Do not waive a median regression because of run consistency or
     a 10–15% noise/retry clause. The accepted tradeoff is possible
     false-blocking on a degraded-lab day; the 10% median tolerance
     avoids blocking on a single outlier while rejecting sustained
     median regressions. "Line rate" = the same-cluster master median
     just measured, never a remembered figure (the recorded per-cluster
     bands are tier 2 of `docs/regression-test-matrix.md`; `tcp`/`udp`
     baselines are whatever their master medians are — never import
     loss numbers).
   - CoS per-class cells (when applicable): PASS iff every unshaped
     class matches its master-cell behaviour and shaped classes hit
     their shaped rate with no buffer drops beyond master.
   - Forwarding/connectivity failure on any cell that passes on
     master = BLOCK, unconditionally.
   Record on the PR: cluster, PR head SHA (the GATED SHA, which Step 4
   item 0 compares with the head being merged), master SHA, every cell's
   numbers (including all multi-stream runs) each with its `loadavg`,
   each node's build git hash, every line of the pre-gate environment
   checklist above with its PASS / VOID / FAIL, directional result or
   `N/A (not a policy PR)` / `INCONCLUSIVE (env)`, and the verdict.
   "Smoke passed" without numbers is not a gate. Any
   behavior-changing fold re-runs BOTH this gate and the triple
   review at the new head (counts toward the fold-loop cap).
   **A gate's ledger rows are part of the record: never delete them.**
   Every gate run through `test/incus/harness-result.sh` appends one
   row to the TRACKED `test/results/ledger.d/` (`docs/engineering-style.md`,
   "Every gate in this table now leaves a ledger row", #8302), and
   `harness-compare` reads those rows. Lanes deleted the rows their
   runs wrote "by name, uncommitted"; deleting a FAIL row destroys
   the verdict `harness-compare` would have shown. Commit every row
   the gate wrote on the PR branch, as its own ledger-only commit. A
   VOID row (for example, no deploy manifest in that worktree) is
   committed too, with the reason it is VOID in `docs/log/<issue>.md`.
5. **Parent firsthand verification on the final head** as a SEPARATE
   step before merge (supplement to, never a substitute for, the
   triple review): spot-check at least one load-bearing claim
   firsthand (re-run the RED/GREEN pair or a focused test, or
   re-derive the cited invariant), for salvage lanes verify build +
   full affected suite, and record the result on the PR. Reviews use
   only the declared model pool — Copilot is not requested, waited
   for, or evaluated (user directive 2026-10-26).
6. **Fold review findings** by resuming the engineer agent
   (`SendMessage({to: "<agentId>", ...})` — resumes a COMPLETED agent with
   its context intact) OR inline if the agent's worktree is at a stale
   pre-rebase head that would overwrite your rebase. **Seat
   confirmation of a fold** resumes the SAME reviewer seat with a
   narrow brief, "confirm delta `<X>..<Y>` at head `<Z>`": X..Y is the
   fold (X the head that seat last reviewed), Z the head to be merged
   (Y itself, or a merge of master on top of it). The seat answers
   about that delta only, and its record is headed at Z like any other.
   A fresh seat re-reads the whole PR and costs a full review (see the
   spend cap).

Every gate must clear: all three hostile verdicts at the final
head, the cluster gate (or docs/test-only classification), and the
parent firsthand verification.

## Step 4: Merge (PARENT)

Per PR, in order:

0. **Gate checklist (hard stop):** confirm on the PR, all at the head
   you are about to merge — three reviewer records with full
   findings text (Step 3 item 3) all MERGE-READY at this SHA
   (records headed at older SHAs are history and never count
   toward the three),
   cluster-gate record with numbers (Step 3 item 4) or the parent's
   recorded `docs/test-only` classification with diff stat, the
   parent firsthand verification (Step 3 item 5),
   and the Step 3 item 1 log check: `docs/log/<issue>.md` (or
   `docs/log/<pr>.md`) present in the head's diff with Timestamp /
   Action / File(s) / Validation / Risk content.
   If any item is missing or recorded at a different SHA, do NOT
   merge — return to Step 3.
   **The merge record names the gated SHA and classifies the delta.**
   The merge body states the GATED SHA (the head the cluster gate ran
   at) and the class of `git diff --stat <gated>..<head>`:
   `docs-only`, `comments-only` (comment lines in code files, checked
   by reading the diff, not by the file list) or `code`. A `code`
   delta needs a re-gate at the head, or a seat confirmation of that
   exact delta (Step 3 item 6) with the reason a re-gate is not needed
   written in the record. An empty delta says so. Without this line a
   later reader cannot tell a gated merge from a merge of something
   nobody measured. The gate's ledger rows (Step 3 item 4) are in the
   head's diff, or the record says why the gate wrote none.
1. Re-poll `mergeable` THROUGH `UNKNOWN` (GitHub recomputes after every
   push) until `MERGEABLE`/`CLEAN` or `CONFLICTING`.
2. If `CONFLICTING`: in a FRESH worktree off the PR branch,
   `git merge origin/master`, resolve conflicts keeping both sides'
   intent (per-issue `docs/log/<issue>.md` files are separate files
   and should not conflict; the root `_Log.md` is closed — if it
   appears in a conflict, the branch is stale against the logging
   migration, so drop the branch's `_Log.md` change, never union it),
   build-check if a behavior-relevant file conflicted, push the
   rebased branch via `git -C`. NEVER resolve in the main checkout.
3. Set the PR title + body first: `gh pr edit <n> --title "<area>: <summary> (#NNNN)" --body-file /var/worktrees/.cache/pr<n>_body.md` (body with Why/What/Validation + gate evidence). Then merge with an explicit pair: `gh pr merge <n> --merge -t "<area>: <summary> (#NNNN)" -F - <<<"<same body>" --delete-branch`. Both flags REQUIRED together: `-t` alone yields a title-only merge whose body echoes the subject, and bare merge yields GitHub's `Merge pull request #N` template — both are log pollution (ruled 2026-09-22). `git fetch origin` first if the ref may be stale, then verify with `git log --format=%B -1 origin/master` after merging.
4. Verify the issue auto-closed (`Closes #<n>` in the body). If not,
   `gh issue close <n>` with a comment citing the merge SHA + smoke result.
5. Fetch master; the NEXT PR now needs its own rebase vs the new
   master — repeat.
**Control-cleanliness gate (2026-09-22 incident: 24 lane-leaked files sat in the control tree and silently wedged every `merge --ff-only`, leaving control 15 merges behind; 2026-09-24: scratch trees moved out of the repo to `/var/worktrees/` so no in-repo wipe can take them):** before EVERY merge-prep, run `git status --short` in control — it MUST show nothing at all: zero M/A/D/R lines AND zero `??` lines (worktrees no longer live under the repo, so any untracked entry is unexpected). If dirty: STOP; `git stash push -m control-rescue-<date>` (tracked only, NEVER `-u`); confirm with `git stash list` BEFORE resetting; `git fetch origin` then `git reset --hard origin/master`; triage the stash per-file (duplicate-of-branch → drop after lane confirms; unique → rescue to the owning lane); triage unexpected `??` paths individually — `mv` each aside under
`/var/worktrees/.cache/control-rescue-<date>/` (never `rm`), confirm
`git status --short` is empty, and only then proceed with the merge.

**NEVER backticks in `git commit -m`** — use `git commit -F -` heredoc (PR
bodies + commit messages contain backticked identifiers).

## Step 5: File-new during audits

Keep an adversarial-audit lens running. When a review or audit surfaces a
real bug/gap that's out of the current PR's scope, **file a new issue**
(with RFC/spec basis + a concrete fix + provenance) and drive it in a later
round. The campaign isn't done when the initial backlog is empty — it's
done when the backlog STAYS empty after an audit.

## Step 6: Final cross-PR integration audit

After a wave of PRs lands close together, the per-PR reviews each saw only
their ISOLATED diff. Dispatch ONE bounded audit agent over the COMPOSED
master to catch integration bugs the per-PR reviews structurally cannot:

- shared files touched by ≥2 PRs (distinct counters not arg-swapped after a
  shared fn gained a param; gate ordering — suppression BEFORE
  classification; no aliasing in merged data paths)
- wire/protocol fields added by ≥2 PRs all tag-matched on BOTH Rust+Go
  sides (a one-sided field = #1961-class no-transit risk); regenerate +
  diff `protocol_wire_v1.json`
- composed-master build (cargo + go) + the cross-language contract test

If it finds a real bug → file + drive it (defer termination). If CLEAN →
proceed to Step 7.

## Step 7: Terminate

**Termination requires EVERY open issue to be `MERGED` or `PLAN-KILLED`
(all-three-reviewed, labeled `plan-kill`, closed).** A `plan-deferred` label is
NOT a terminal state — see "`plan-deferred` is NOT a terminal state" above. If
any open issue still carries a `plan-deferred-*` label, the campaign is NOT
done: go back and drive it (`/research` → `/engineer` → merge, or `/research`
→ PLAN-KILL). The ONLY exceptions that may remain open at termination are (a) a
maintainer-held issue you were told not to touch, and (b) an issue whose CODE is
already merged and whose ONLY remaining item is a hardware/live-capture verify
you cannot perform — and that must say exactly that on the issue.

Termination additionally requires `gh pr list --state open` to be
empty (except PRs explicitly held by a maintainer with the hold
recorded on the PR). When EVERY open issue (including newly-filed)
is `MERGED` or `PLAN-KILLED` (per the above), every open PR is
merged or closed-with-disposition, and the final integration audit
is clean:

1. Update the tracking task to COMPLETE with the merged list, the
   plan-killed list, and any held/lab-verify-only exceptions (the
   (a)/(b) cases above) — there is no other "deferred set".
2. Write a campaign memory file (`project_campaign<N>_<date>.md`) + a
   one-line `MEMORY.md` index entry capturing the non-obvious lessons.
3. Final disk sweep (termination only — mid-campaign protections no
   longer apply): first ARCHIVE any keeper board + baseline records
   cited by merged PRs into the campaign memory note (Step 7 item 2),
   then remove all campaign worktrees and per-lane
   `CARGO_TARGET_DIR`s, remaining baselines and gate scripts, stop
   the keeper Monitor, and remove stale Rust target dirs (plus
   `go clean -cache` only if the shared-cache collateral was already
   accepted during the campaign) so the next campaign starts
   cold-but-clean. Worktrees for held/lab-verify-only exceptions are
   NOT removed if they hold the only copy of anything — verify clean
   or already-pushed first. Log the final `df -h /var/worktrees` in
   the tracking task.
4. If cron-driven: `CronDelete` the campaign cron.
5. `PushNotification` a one-line outcome (the user may be away).

## Standing rules (apply throughout)

- **Re-verify the FINAL head** before review and before merge — heads move.
- **Liveness = commit-time + active procs**, not output-mtime. Don't
  premature-kill a flake-checking agent. Orphaned test procs from a
  COMPLETED agent ARE safe to kill (zombies, not live work).
- **Cross-wired completion notifications happen** — a task-id from agent A
  can carry a body about agent B's PR, or claim a merged PR is still open.
  VERIFY ground truth via `gh`/`git`, NEVER trust the notification body.
- **Detached smoke** = script-file + no-pipe RC + wait-for-xpfd-solidly-up
  + a `DONE` marker; watch it with `Monitor` (until-grep-marker) or
  `Bash(run_in_background)`. A `cmd | grep; echo $?` returns grep's status
  and can false-pass a failed test.
- **`gofmt -w`** a pre-existing-dirty Go file when your PR touches it.
- **API may 529** — fall back to doing the work inline.
- **Base every PR on CURRENT master** (three-dot diff; a fork-behind
  branch shows false mass-deletions on two-dot — use three-dot to see true
  change + two-dot only as a mass-deletion tripwire).
- **Expiry markers: a temporary instruction says when it stops being
  true (#18645).** Temporary instructions outlived their premise all
  through the 2026-10-31 campaign: a "the loss lab has no NTP" note long
  after the lab had NTP (#18618), and a retired iperf target still named
  as the smoke target. The ones retired on time carried an explicit
  expiry. So an instruction that is true only until something happens
  carries ONE marker line next to the text it expires:

  ```
  <!-- Expires-when: #18576 closed -->      Markdown, also inside a table row
  # Expires-when: #18576 closed             shell, Python, env, Makefile
  # Expires-when: loss's v4 and v6 iperf targets are one host; Review-by: 2026-11-30
  ```

  The issue form is exactly `#NNNN closed` (an issue or a PR number).
  Any other condition is free text and MUST carry a `Review-by:` date,
  because no tool can check prose: the date is the trigger. Never mark a
  permanent rule. `make instructions-census` (hermetic; CI and
  `make selftest`) fails a malformed or near-miss marker, a free-text
  marker without a date, and a date before today (UTC).
  `make instructions-census-online` (the keeper, above) also fails a
  marker whose issue has CLOSED. On a red, retire the instruction
  (delete it, or restate it as permanent), then the marker; moving a
  date needs a reason in the commit. Examples in fenced or inline code
  are not markers.
  Grammar and scope: `scripts/instructions-census.py`.
- **Mirrored text is wrapped, and compared (#18645).** Text deliberately
  copied into several docs (the private-RG peer-loss detection paragraph
  is in six) sits between `<!-- mirror:<id> -->` and
  `<!-- /mirror:<id> -->` markers. `make mirror-census` fails when two
  blocks with one id differ after whitespace normalisation, or a block
  has no partner. Change every copy in the same commit, and let the
  census, not a reviewer, confirm identity. CLAUDE.md is the user's:
  when its copy should join a mirror set, propose the wrapped text in
  the PR body.

## Hard-won operational lessons (from live runs)

- **Verify an issue is not ALREADY FIXED before dispatching.** The open list
  carries stale issues whose fixing PR merged but whose auto-close never
  fired (e.g. #5732 was already fixed by #5733). Before writing a dispatch,
  grep the cited symbol on `origin/master`
  (`git show origin/master:<file> | grep <symbol>`) and/or
  `gh pr list --state merged --search "<keyword> in:title"`. If present,
  `gh issue close <n>` citing the fixing PR + pick another. A "residual"
  follow-up issue may have been closed by its OWN later PR — check. Keep the
  agent's STEP-0 as the backstop, but do the parent check too so lanes are
  not spent on no-ops.

- **Salvage a DEAD engineer's uncommitted work — do not clobber it.** An
  engineer can die mid-task leaving substantial uncommitted work in its
  worktree. First CONFIRM death (not silence): unreachable mailbox AND no
  file/gocache writes AND no live build procs for several minutes — a
  recent-but-static mtime + no procs means it stopped, not that it is
  thinking. Then SALVAGE, do not re-dispatch (a re-dispatch to the same
  worktree/branch clobbers the work): parent verifies it (build + full
  `-race` + a firsthand RED-on-revert on the core guard), commits it, opens
  the PR, and runs it through the SAME gate with EXTRA completeness scrutiny
  in the independent review — a dead agent left no one to defend it, and a
  sweep may be 24/25 correct with one missed site (the #5886 salvage: the
  review caught a panic-site in a package the sweep never touched). NEVER
  `git checkout -- <file>` in a dirty salvage worktree — it discards the
  uncommitted work (recover from the diff if you do).

- **Cross-review when the reviewer pool is thin.** engineer≠reviewer does
  NOT require idle spectator agents: the engineer of PR A may give PR B an
  ADVISORY review and vice-versa. Advisory cross-review never counts
  toward the three stamped records (Step 3 item 3) — those require
  parent-dispatched reviewers who did not implement any PR in the
  current wave. Freeing idle agents for a "small workflow" is fine —
  refill stamped reviewers from the model pool, not from implementers.

- **Declared pool only (2026-10-26).** Copilot was removed from every
  review gate by user directive; do not request, wait for, or evaluate
  it. The load-bearing assurance is the triple hostile review PLUS the
  parent firsthand RED-on-revert / focused re-run (Step 3 item 5).

- **A design fork surfaced mid-`/engineer` → STOP engineering and start
  `/research` now.** If scoping reveals a real design decision (a data-model
  change, a producer→facility mapping, a backward-compat behavior change, a
  multi-PR-sized "full" option vs a bounded one — e.g. #5797), do NOT pick a
  scope blind. Record the scoping analysis on the issue and label it
  `plan-deferred-research` while the issue remains open in the work queue.
  The plan-review gate must resolve the fork; the deferral is explicitly
  non-terminal, not a reason to stop campaign ownership.

## Anti-patterns this skill prevents

- Merging on reviewer verdicts alone without a parent firsthand check of at least one load-bearing claim (the #2285 printed-not-evaluated class).
- Building an integration branch on a stale PR head, then merging it and
  silently reverting the author's later review-fold.
- N-way merge conflicts from running coupled issues on the parallel route.
- Declaring "done" when the initial backlog emptied but an audit would
  surface more — keep the audit lens on until it comes back clean.
- Thundering-herd cargo builds (shared target dir) starving each other.
- Trusting agent output-mtime as liveness and killing a live flake-check.

## When NOT to use this skill

- A single isolated fix → `/engineer <n>` directly.
- A design that needs human judgement before any code → `/research <n>`,
  stop at PLAN-READY, let the user approve.
- An incident/outage → fix directly; don't run a backlog sweep.
