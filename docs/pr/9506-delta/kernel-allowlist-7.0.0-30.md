# Kernel allowlist member review: 7.0.0-30-generic (#9506 P-MECH receive proof)

Review base: research/9506-delta at v11 (plan `docs/pr/9506-delta/plan.md`; recipes `docs/pr/9506-delta/f0f9-recipes.md`).
Purpose: this record is the completed per-member evidence the M1
ENFORCED RECEIVE MODE invariant requires. It binds the exact guest
kernel identity to its source revision, Kconfig posture, and the
per-branch receive-path findings — each finding closed by member-tree
text at the pinned tag plus a machine-checked gate.
STATUS LEGEND: REVIEWED = read in the member tree at the pinned tag
(file:line quoted, §7 transcript); ESTABLISHED = repo code or recorded
Tier-2+ evidence; RECIPE-EXECUTED = the specified gate predicate
executed as a probe this revision (§7) with gap-vs-verdict outputs,
pending P2 landing at the named site; LANDED = P2-executed gate
(FALSE for all gates — the P2-entry bar).

## 0. Member tuple (PINNED — the normative membership predicate)

Membership `is_member(uname, pkg_rows, kconfig)` is the conjunction:

- `uname -r == 7.0.0-30-generic`
- `linux-image-7.0.0-30-generic == 7.0.0-30.30` (SHA256 `6f01659e…8e5c2`)
- `linux-modules-7.0.0-30-generic == 7.0.0-30.30` (SHA256 `d61aa07f…55292`)
- `linux-headers-7.0.0-30-generic == 7.0.0-30.30` (SHA256 `f3be8e8d…f0e14`)
  (full SHAs §1; `-30.30` also pins source `linux 7.0.0-30.30`, §2)
- Kconfig: `CONFIG_4KSTACKS` absent-or-`n`, `CONFIG_BRIDGE=(m|y)`,
  `CONFIG_NF_TABLES_BRIDGE=(m|y)` (§3)
- base digest `9dc7c536…e21be05` (bake/publish legs only —admits the
  image the member ships in, never a kernel by itself)

Coherent-B (`7.0.0-31-*`, or `7.0.0-30` at any other revision) fails
at least one conjunct at EVERY boundary (§5). No boundary uses
nonempty/agreement/version-floor alone anymore.

## 1. Member identity (exact strings, repo- + archive-grounded)

- `uname -r`: `7.0.0-30-generic`
  (`docs/image-validation.md:537`, Tier-2 recorded pass 2026-08-21).
- Base: Ubuntu 26.04 (resolute) cloud image, `9dc7c536…`, Canonical-
  GPG-verified (`docs/image-validation.md:536`; pins
  `scripts/image/bake.py:404`, `:410`, `:433`).
- Image: `xpf-userspace-forwarding-ok-20260402-bfb00432-10859-gf93215641.qcow2`,
  `git_commit: f93215641` (`docs/image-validation.md:534-535`).
- Manifest linkage block (quoted verbatim from the signed sidecar shape,
  `bake.py:1143-1178`): `base_release: 26.04`,
  `base_image_sha256: 9dc7c5363c0146a08ba0c9aa834d82c2c6dfbb1c471ad9a2f0aba1189e21be05`,
  `base_image_pinned: true`, `guest_kernel: 7.0.0-30-generic`.
 - Archive pocket: resolute-security, `main/binary-amd64`
  (`http://archive.ubuntu.com/ubuntu/dists/resolute-security/`,
  queried 2026-09-27, §7). Full binary rows:
  `linux-image-7.0.0-30-generic_7.0.0-30.30_amd64.deb`
  SHA256 `6f01659ea129099601984347b52a498b6e35e86f5716ecf8e2da8a54b3f8e5c2`;
  `linux-modules-7.0.0-30-generic_7.0.0-30.30_amd64.deb`
  SHA256 `d61aa07f5bed438788bbad6c5c95dd15e9bf02cbe949183959abe90107955292`;
  `linux-headers-7.0.0-30-generic_7.0.0-30.30_amd64.deb`
  SHA256 `f3be8e8d73b1f6050c406c04e372f6d556811d548fd12fc4eef32128b11f0e14`.
  ALL FOUR SHAs (image, modules, headers, + buildinfo §3) are
  bytes-verified — each deb downloaded from the archive and
  `sha256sum`-matched against the Packages index (§7); no
  index-only pins remain.
 - Source identity: `linux` source `7.0.0-30.30`, Ubuntu kernel git tag
  `Ubuntu-7.0.0-30.30` → commit `d974a4063f5c03c13b4f241a9ab511750e0b9f12`
  (`git ls-remote` + shallow-clone `git log`, §7). Remote:
  `https://git.launchpad.net/~ubuntu-kernel/ubuntu/+source/linux/+git/resolute`.
  Reviewed-file blob SHAs at the tag (content pins — `git rev-parse
  TAG:path`, §7): `net/core/dev.c` `fab5a0be…8451a`,
  `drivers/net/tun.c` `ca0ae5df…5e8e13`, `net/core/net-sysfs.c`
  `b9740a39…769f4b8`, `net/ipv4/ip_input.c` `19d3141d…583e9256`,
  `net/ipv6/ip6_input.c` `2bcb981c…acde`, `net/core/timestamping.c`
  `a50a7ef4…83af26` (full hashes §8 ledger). (Image binary's
  `Source:` field reads `linux-signed` — the signing wrapper; the tree
  is `linux`, same version.)
Status: ESTABLISHED (repo pins + Tier-2 pass + archive records, all
cited; tag/commit verified live).

## 2. Source revision binding (INSTANTIATED — expected values, not capture)

The expected source revision is `linux 7.0.0-30.30`
(`Ubuntu-7.0.0-30.30` / `d974a4063`). Basis (two archive facts, §7):

- The member binaries record `Version: 7.0.0-30.30`, `Source: linux`
  (modules/headers; image via `linux-signed`, same version).
- Ubuntu kernel binary==source version convention, evidenced live:
  current resolute-security `Sources` shows source `linux 7.0.0-34.34`
  building binaries `7.0.0-34-*` (same suffix both sides).

F0 (fixture, RECIPE-EXECUTED): at bake, `dpkg-query -W
-f='${Package}=${Version}\n'` over installed `linux-image-*` /
`linux-modules-*` (same installed-filter as the `:708-721` hold-verify
fragment) records rows into required manifest key
`kernel-source-revision`; the gate asserts the rows EQUAL the §0 pins
byte-for-byte (a bake recording any other revision FAILS — first
recording is confirmation, never blank enrollment). Gates treat the
value as an opaque exact-match token — agreement-checked, never parsed.
Status: INSTANTIATED + RECIPE-EXECUTED (§7 probe matrix: member
ACCEPT, `-31`, same-uname-revision-skew, `-22` all REJECT).

## 3. Kconfig posture (CAPTURED from the member build)

Source: `linux-buildinfo-7.0.0-30-generic_7.0.0-30.30_amd64.deb`
(SHA256 `24af1791…daa520`, verified §7),
`/usr/lib/linux/7.0.0-30-generic/config` (13339 lines,
`CONFIG_VERSION_SIGNATURE="Ubuntu 7.0.0-30.30-generic 7.0.12"`).
Captured P-MECH posture (grep transcript §7):

- `CONFIG_4KSTACKS`: ABSENT (not set) → v9 assert shape
  (absent-or-`n` passes, `=(m|y)` FATALS) HOLDS on the member.
- `CONFIG_BRIDGE=m`, `CONFIG_NF_TABLES_BRIDGE=m` → floor predicates
  (`bridge_floor_10171.py`, offline `bake.py:676` + live
  `validate.py:1212` snippets) HOLD on the member.
- Context (informative, not gated): `CONFIG_TUN=y`,
  `CONFIG_XDP_SOCKETS=y`, `CONFIG_IPV6=y`, `CONFIG_RPS=y`,
  `CONFIG_RFS_ACCEL=y`, `CONFIG_MLX5_CORE=m`, `CONFIG_NETFILTER=y`,
  `CONFIG_NF_TABLES=m`; `CONFIG_IKCONFIG` not set (live config
  re-read uses `/boot/config-$(uname -r)`, the `_CONFIG_ASSERT`
  shape — never `/proc/config.gz`).

New third predicate (same `_CONFIG_ASSERT` shape, both snippets):
`CONFIG_4KSTACKS` must be absent or `=n`; FATALS on `=(m|y)`.
Rationale: the member `tun.c:1952-1955` `netif_rx` alternative branch
compiles in only when the symbol is set (§4 B4); refusing set builds
removes that branch from the admitted set by construction.
Status: CAPTURED (member config) + RECIPE-EXECUTED (F8 both snippets).

## 4. Per-branch findings (member-tree text at `Ubuntu-7.0.0-30.30`)

All files below are the member tree (`d974a4063`); line numbers are
member-tree lines, quoted in §7.

B1 RPS-map branch. Claim: with a NULL per-queue RPS map AND no flow
table, `get_rps_cpu` returns -1 (no backlog selection). Family: L2.
Basis: REVIEWED — `net/core/dev.c:5128-5133`:
`flow_table = rcu_dereference(rxqueue->rps_flow_table);
map = rcu_dereference(rxqueue->rps_map);
if (!flow_table && !map) goto done;` with `cpu = -1` at entry and
`done: return cpu`. Closing gate: per-queue `rps_cpus==0` readback on
every q0 queue, every audit tick; empty dir set or any nonzero
refuses. Status: REVIEWED + GATE SPECIFIED.

B2 RFS flow-table branch. Claim: with no per-queue flow table, the
`rps_flow_table`/socket-flow branch cannot select a backlog CPU (it
operates with a NULL RPS map — RPS-empty alone does NOT disable RFS).
Family: L2. Basis: REVIEWED — same function: the RFS leg is entered
only `if (flow_table && sock_flow_table)`; with `flow_table == NULL`
execution falls to `try_rps:`, where `if (map)` with NULL map falls
through to `done` (cpu=-1). Closing gate: per-queue
`rps_flow_cnt==0` readback alongside B1; present table refuses even
with all other fields safe. Status: REVIEWED + GATE SPECIFIED (RFS
fixture in P2 entry).

B3 TUN dispatch (non-NAPI path). Claim: `tun_chr_write_iter`
dispatches via `netif_receive_skb` inline (same syscall, no backlog)
when NAPI is off, 4KSTACKS is absent, and `more` is false with an
empty batch queue. Family: L2. Basis: REVIEWED —
`drivers/net/tun.c:1985-2000` (`tun_chr_write_iter` →
`tun_get_user(..., more=false)`); `:1952-1955`
(`} else if (!IS_ENABLED(CONFIG_4KSTACKS)) { tun_rx_batched(...); }`);
`tun_rx_batched` `:1474-1511` (`if (!rx_batched || (!more && empty))
→ netif_receive_skb` inline under `local_bh_disable`); xpf shape
ESTABLISHED — TUN created `IFF_TUN|IFF_NO_PI` (±`MULTI_QUEUE`), no
`IFF_NAPI`, no `IFF_VNET_HDR` (`slowpath.rs:2220,2240`); writes are
`libc::write` (`slowpath.rs:1750`) + uring `opcode::Write`
(`io_uring_write.rs:583`), both → `write_iter` (more=false by
construction). Closing gate: no-`IFF_NAPI` creation flags (zero
in-tree hits) + B1/B2 excluding backlog selection + B8 (more/queue/
rx_batched). Status: REVIEWED + GATE SPECIFIED.

B4 TUN 4KSTACKS alternative. Claim: the `netif_rx` alternative is not
compiled into the member. Family: L2. Basis: REVIEWED — member
`tun.c:1952-1955` (`else { netif_rx(skb); }` under
`IS_ENABLED(CONFIG_4KSTACKS)`) + §3 capture (`CONFIG_4KSTACKS`
absent in the member config). Closing gate: bake + boot assert
FATALS on set. Status: REVIEWED + ENFORCED (F8 both snippets).

B5 GRO hold. Claim: no GRO merging holds q0 skbs across the routing
decision (member GRO runs only in the NAPI leg:
`tun.c:1920-1928` `napi_gro_frags`, unreachable with NAPI off).
Family: L2. Basis: REVIEWED (NAPI-gating) + GRO-off readback
semantics. Closing gate: ethtool `generic-receive-offload` off
readback per tick; on refuses. Status: REVIEWED + GATE SPECIFIED.

B6 XDP redirect. Claim: no XDP program diverts q0 skbs. Family: L2.
Basis: netlink attachment readback. Closing gate: `Info().XDP()`
none-required per tick; attached refuses. Status: GATE SPECIFIED
(XDP program state is runtime, not tree text — no tree claim made).

B7 v4/v6 symmetry. Claim: the inline argument holds identically for
the v4 and v6 forward paths. Family: v4+v6. Basis: REVIEWED —
v4 `ip_rcv` (`net/ipv4/ip_input.c:564`) → `ip_rcv_core` → NF_HOOK →
`ip_rcv_finish` (`:439`) → dst_input → `ip_forward`
(`net/ipv4/ip_forward.c:83`); v6 `ipv6_rcv`
(`net/ipv6/ip6_input.c:304`) → `ip6_rcv_core` (`:148`) → NF_HOOK →
`ip6_rcv_finish` (`:69`) → dst_input → `ip6_forward`
(`net/ipv6/ip6_output.c:497`); every step is a direct synchronous
call within the `netif_receive_skb_internal`
(`net/core/dev.c:6372-6394`: `cpu<0` → `__netif_receive_skb` inline,
no `enqueue_to_backlog`) delivery — no queueing primitive sits
between TUN write and either forward function. (The always-enqueue
shape at `dev.c:5693` is `netif_rx_internal` — the NAPI-poll entry,
NOT the TUN path; conflating them would void the claim.)
RPS/RFS/NAPI/GRO reasoning is L2, pre-family; TC mark program is
family-blind (mark/`queue_mapping` only, `slowpath.rs:188-263`); TUN
`IFF_NO_PI` parses family by nibble. Global-`rps_needed` note: the
jump label only SKIPS the `get_rps_cpu` check when no RPS exists
anywhere; with RPS configured (XDP NICs are), the check runs and
the per-queue predicate (cpu=-1) decides — the gate is
 label-independent by construction. PRE-RPS TIMESTAMP BRANCH
 (concern advisory — the `cpu>=0`-only claim OVERLOOKED it):
 member `netif_receive_skb_internal` (`dev.c:6378`) returns early
 `if (skb_defer_rx_timestamp(skb))`; member
 `net/core/timestamping.c:67-112` defers ONLY with a PHYLIB
 hwtstamp provider (`hwprov` with `source==HWTSTAMP_SOURCE_PHYLIB`
 + `phydev`, or `skb->dev->phydev` with
 `phy_is_default_hwtstamp`) AND a PTP-class skb AND
 `mii_ts->rxtstamp`. TUN CANNOT take this branch: zero
 `phydev`/`phylib`/`hwprov`/`hwtstamp` references in member
 `drivers/net/tun.c` (both pointers NULL by zero-init → the
 first checks return false), and no MDIO/PHYLIB attach path
 exists for TUN (no `phy_connect`, no ethtool-phy ops).
 Closing belt (in addition to the member-text proof):
 per-tick readback asserts no `/sys/class/net/xpf-usp*/phydev`
 + PTP adversarial cell (PTP-class frame through USP still
 routes inline — proves no-defer on the member kernel).
 Closing gate: same predicate both families + TC readback +
 IPv6-parity cells + phydev-absent readback. Status: REVIEWED +
 GATE SPECIFIED.

B8 TUN batching/`more` (NEW — blocker advisory). Claim: no q0 skb is
held across its write's return in `tun_rx_batched`. Basis:
REVIEWED — member `tun.c:1474-1511` (holds iff `rx_batched>0 AND
more`, or NAPI); `:1985-2000` (write path hardcodes `more=false`);
`:2512-2561` (`tun_sendmsg`, the ONLY `more=true` source, via
`MSG_MORE`); `:2802` (`rx_batched = 0` default); `:3553-3598`
(ethtool get/set-coalesce — runtime-tunable, hence gated, not
assumed). xpf side ESTABLISHED + EXECUTED: all USP writes are
char-fd `write`/`OP_Write` (never sendmsg); `sendmsg` on the USP
char fd fails `ENOTSOCK` (errno 88 — executed probe, §7), so a
compile-valid sendmsg mutant fails LOUDLY, never holds silently.
Queue-empty induction: entries enter the batch queue ONLY via the
more-path (`:1496-1498`) or the NAPI path (`:1936`, napi off) —
under all-`!more` writes from a fresh TUN the queue is always
empty, so `(!more && empty)` dispatches inline on every write
 REGARDLESS of `rx_batched`. Closing gates (defense in depth, BOTH):
 (i) structural `!more` + empty-queue proof above (primary — and per
 the corrected advisory, the `more=true` branch is UNREACHABLE from
 q0 writes, so gate (ii) is NOT source-mandated); (ii)
 `rx_batched==0` readback every tick via ethtool coalesce
 (`rx_max_coalesced_frames`) + no-change-while-OPEN + drift →
 revoke+fence+freeze (same cadence/channel as the GRO readback),
 RETAINED SOLELY as belt against future write-path changes +
 operator coalesce drift. The exact call chain pinned:
 `tun_chr_write_iter` (`:1985-2002`, `more=false`) → `tun_get_user`
 (`:1952-53`, non-NAPI + `!4KSTACKS` arm) → `tun_rx_batched`
 (`:1482-87`, `(!more && empty)` → inline `netif_receive_skb`).
 Adversarial fixtures: ENOTSOCK probe (EXECUTED §7, re-executed on
the member kernel by P2); rx_batched-drift fixture (ethtool-set 64
while OPEN → must revoke+freeze); sendmsg-mutant cell (route USP
writes through sendmsg → must fail loud `ENOTSOCK`, never silent
success); kprobe sync-proof (P2 on member kernel: `ip_forward` /
`ip6_forward` entry+exit strictly inside `tun_chr_write_iter`
window for xpf-shape writes — the timing proof no code read can
give). Status: REVIEWED + ENOTSOCK-EXECUTED + GATES SPECIFIED
(kprobe pending P2; the M1 finality claim is RETAINED on (i)+(ii)
plus the ENOTSOCK execution, with the kprobe as the P2-entry
timing bar).

## 5. Boundary enforcement (MEMBERSHIP at every boundary)

Rule: every boundary evaluates the §0 tuple predicate (uname AND
package rows AND Kconfig where the leg can see them — each leg
checks every field it CAN see, and at least uname+revision; no leg
passes coherent-B). Current-code gaps were DEMONSTRATED executed
(§7: current sign SIGNS `-31`/`-22`; current publish PUBLISHES
coherent agreeing `-31`; current floor PASSES `-31`/`-22`); the
specified predicates REJECT all three (executed probe matrix, §7).
P-MECH does not open permits until the LANDED gates (F0–F9) execute
at P2 entry; statuses below are honest per gate.

- Bake output: virt-customize run-command beside `:645-646` /
  `:670-671` / `:676` asserts `ls /lib/modules` equals exactly
  `7.0.0-30-generic` AND installed
  `linux-{image,modules,headers}-7.0.0-30-generic` dpkg rows equal
  the §0 versions (extends the single-kernel assert + hold-verify
  `:708-721` shape); drifted bake emits nothing signable.
  (Current: installs newest `linux-generic`, `:641` — gap
  demonstrated.) Fixture F1 (`7.0.0-31` bake → FATAL; revision-skew
  `7.0.0-30` non-`.30` → FATAL). Status: RECIPE-EXECUTED.
- First recording F0: the P2-evidence bake's `dpkg-query` rows must
  EQUAL the §0 pins (confirmation, never blank enrollment); pins
  land verbatim in repo (Python beside `PINNED_BASE_*` in `bake.py`
  + Go consts beside the LANE-1/validate call sites + agreement
  test). Status: RECIPE-EXECUTED (pins instantiated, §7).
- Signed manifest: `sign.py` `assert_bake_set` (extends `:438-442`)
  requires new `kernel-allowlist` key + `kernel-source-revision`
  key AND tuple membership (replacing nonempty-`guest_kernel`).
  (Current: nonempty only — gap demonstrated, §7.) Fixtures F2
  (non-member `guest_kernel` → bake dies member-mismatch), F3
  (`7.0.0-22` sidecar → SignError; `-31` sidecar → SignError).
  Status: RECIPE-EXECUTED.
- Package inventory: `publish.py` `gate_provenance` requires keys
  present + member package rows present + versions equal to the
  PIN (replacing manifest↔inventory agreement alone; agreement
  remains as tamper-evidence). (Current: agreement only — gap
  demonstrated, §7.) Fixtures F4a/b/c (skew dies + lacks-member-
  package dies + coherent-agreeing-`-31` dies). Status:
  RECIPE-EXECUTED.
- Validate/boot: scenario A (`validate.py:1185-1230` floor block)
  asserts `uname -r` equals the member exactly (before the hold
  assert) + package-row equality via guest `dpkg-query` + Kconfig
  third predicate live. (Current: floor only — gap demonstrated.)
  Fixture F5 (`7.0.0-22` single+held → fail; `-31` → fail).
  Status: RECIPE-EXECUTED.
- Ordinary-boot admission: the supervisor asserts full tuple match
  before OPEN (same gate as the mode predicate — a booted
  non-member runs the system but never opens permits). Fixture F5b
  (booted `7.0.0-22` with a `7.0.0-30` manifest → system runs,
  permits stay shut). Status: RECIPE-EXECUTED.
- Rollback admission: rollback to a non-member known-good proceeds
  as a system function, but P-MECH admission refuses OPEN until a
  member kernel runs again. Fixture F5c (rollback to held
  `7.0.0-22` → system functional, P-MECH deny-only + alarm).
  Status: RECIPE-EXECUTED.
- LANE-1: Arm refuses non-member candidates after
  `ValidateKernelSegment` (new membership check — `ValidateKernelSegment`
  itself is charset/path validation, `version.go:124`, not
  membership); Gate 2 (`kernel_run.go:551-558`) extends
  `running==CandidateVersion` with `running ∈ reviewed tuple`
  (current: candidate-equality only — gap by code read);
  `xpf-kernel-promote` outer gate refuses no-infer AND non-member;
  `promotionMarkerPath`/`lastRollPath`/`ReadChannelStatus`
  (`kernel_status.go:84`, reporting — not enforcement) become
  EVIDENCE INPUTS to the membership check, never the check
  itself. (Current no-infer authenticates the xpfd binary path,
  `kernel_arm_record.go:39` — gap by code read.) Fixtures F6/F7
  (non-member candidate → Arm refuses; non-member running at
  Gate 2 → revert path, never promote). Status: RECIPE-EXECUTED.
- Kconfig: `CONFIG_4KSTACKS` third predicate in both offline (bake)
  and live (validate) snippets. Fixture F8 (set/present → FATAL in
  both; member-absent → PASS — executed against the §3 capture).
  Status: RECIPE-EXECUTED.
- Review linkage: this record quotes member strings verbatim; a
  record quoting any other member is VOID for this member.
  Fixture F9. Status: RECIPE-EXECUTED.

## 6. Limits (explicit, no hand-waving)

- The member tree WAS reviewed textually: tag `Ubuntu-7.0.0-30.30`
(`d974a4063`), files `net/core/dev.c`, `drivers/net/tun.c`,
`net/core/net-sysfs.c`, `net/ipv4/ip_input.c`,
`net/ipv6/ip6_input.c`, `net/core/timestamping.c` (shallow clone
+ sparse checkout, §7).
  Review scope is exactly the receive-path branches cited in §4
  (RPS/RFS dispatch, TUN write/dispatch/batching/coalesce/timestamp, v4/v6
  receive→forward chains) — not a whole-tree audit; whole-tree
  behavior is bounded by exact-version pinning (same bits ⇒ same
  branches) + the runtime predicates, not by broader reading.
- The member config WAS captured: Canonical-signed
  `linux-buildinfo` deb (SHA-verified, §7), not a local guess.
  `/boot/config-$(uname -r)` on the appliance is re-asserted by
  the F8 snippets at bake and boot (config-substitution between
  capture and gate would fail F8).
- P2 still executes on the member kernel: LANDED boundary gates
  (F0–F9 as code), per-tick readbacks (RPS/RFS/GRO/XDP/TC/
  coalesce), the kprobe sync-proof (B8), and IPv6-parity cells.
  Until then every gate above is RECIPE-EXECUTED, honestly
  labeled — never LANDED.
- Adding a member repeats this entire record (new identity +
  source pin + tree review + config capture + boundary fixtures)
  via reviewed commit; non-members deny by default at every
  boundary.

## 7. Executed-evidence transcript (v10–v11, research lane; read-only)

Suite + pocket (2026-09-27):

```text
$ curl -s http://archive.ubuntu.com/ubuntu/dists/ | grep -oE 'href="[a-z]+/"'
… noble/ plucky/ questing/ resolute/ stonking/ …   # 26.04 == resolute
$ curl -s …/dists/resolute-security/main/binary-amd64/Packages.gz
$ zgrep -A14 '^Package: linux-image-7.0.0-30-generic$' …
Package: linux-image-7.0.0-30-generic
Source: linux-signed
Version: 7.0.0-30.30
Filename: pool/main/l/linux-signed/linux-image-7.0.0-30-generic_7.0.0-30.30_amd64.deb
SHA256: 6f01659ea129099601984347b52a498b6e35e86f5716ecf8e2da8a54b3f8e5c2
$ zgrep … '^Package: linux-modules-7.0.0-30-generic$' …
Version: 7.0.0-30.30 / Source: linux
SHA256: d61aa07f5bed438788bbad6c5c95dd15e9bf02cbe949183959abe90107955292
$ zgrep … '^Package: linux-headers-7.0.0-30-generic$' …
Version: 7.0.0-30.30 / Source: linux
SHA256: f3be8e8d73b1f6050c406c04e372f6d556811d548fd12fc4eef32128b11f0e14
$ zgrep -A12 '^Package: linux$' resolute-security …/source/Sources.gz
Version: 7.0.0-34.34 … Binary: … linux-image-7.0.0-34-generic …
  # binary==source version convention, live evidence for the §2 pin
$ git ls-remote https://git.launchpad.net/~ubuntu-kernel/ubuntu/+source/linux/+git/resolute Ubuntu-7.0.0-30.30
399867a77d094ee10790dd9051938ed243954779  refs/tags/Ubuntu-7.0.0-30.30
$ git clone --depth 1 --branch Ubuntu-7.0.0-30.30 … ; git log --oneline -1
d974a4063 UBUNTU: Ubuntu-7.0.0-30.30
$ git rev-parse 'Ubuntu-7.0.0-30.30^{commit}'
d974a4063f5c03c13b4f241a9ab511750e0b9f12
```

Deb verify + config capture:

```text
$ curl -O …/linux-image-7.0.0-30-generic_7.0.0-30.30_amd64.deb
$ sha256sum linux-image-….deb
6f01659ea129099601984347b52a498b6e35e86f5716ecf8e2da8a54b3f8e5c2  (MATCHES Packages)
$ curl -O …/linux-buildinfo-7.0.0-30-generic_7.0.0-30.30_amd64.deb
$ sha256sum linux-buildinfo-….deb
24af1791fba89c89927ebf221d19acb72c044edda2699f68172e116d64daa520  (MATCHES)
$ curl -O …/linux-headers-7.0.0-30-generic_7.0.0-30.30_amd64.deb
$ sha256sum linux-headers-….deb
f3be8e8d73b1f6050c406c04e372f6d556811d548fd12fc4eef32128b11f0e14  (MATCHES)
$ curl -O …/linux-modules-7.0.0-30-generic_7.0.0-30.30_amd64.deb  (169 MB)
$ sha256sum linux-modules-….deb
d61aa07f5bed438788bbad6c5c95dd15e9bf02cbe949183959abe90107955292  (MATCHES)
$ grep -E '^CONFIG_4KSTACKS=|^# CONFIG_4KSTACKS is not set' config || echo ABSENT
ABSENT-FROM-CONFIG
$ grep -E '^CONFIG_BRIDGE=|^CONFIG_NF_TABLES_BRIDGE=' config
CONFIG_BRIDGE=m / CONFIG_NF_TABLES_BRIDGE=m
$ grep CONFIG_VERSION_SIGNATURE config
CONFIG_VERSION_SIGNATURE="Ubuntu 7.0.0-30.30-generic 7.0.12"
```

Member-tree branch lines (tag `Ubuntu-7.0.0-30.30`):

```text
$ grep -n '!flow_table && !map' net/core/dev.c
5131:	if (!flow_table && !map)          # → goto done, cpu=-1 (B1+B2)
$ sed -n '6372,6394p' net/core/dev.c     # netif_receive_skb_internal:
  cpu = get_rps_cpu(…); if (cpu >= 0) { enqueue_to_backlog(…); return; }
  ret = __netif_receive_skb(skb);       # cpu<0 → INLINE (B7 delivery)
$ sed -n '1952,1955p' drivers/net/tun.c  # tun_get_user dispatch:
  } else if (!IS_ENABLED(CONFIG_4KSTACKS)) { tun_rx_batched(…); }
  else { netif_rx(skb); }               # (B3/B4)
$ sed -n '1985,2000p' drivers/net/tun.c  # tun_chr_write_iter:
  result = tun_get_user(tun, tfile, NULL, from, noblock, false);  # more=false (B8)
$ sed -n '2512,2561p' drivers/net/tun.c  # tun_sendmsg: ONLY more=true source
  … m->msg_flags & MSG_MORE …           # (B8)
$ grep -n 'rx_batched = 0' drivers/net/tun.c
2802:	tun->rx_batched = 0;             # default (B8)
$ sed -n '3553,3598p' drivers/net/tun.c  # get/set_coalesce (B8 gate)
$ sed -n '564,575p' net/ipv4/ip_input.c  # ip_rcv → … → ip_rcv_finish (B7)
$ grep -n '^int ip_forward(' net/ipv4/ip_forward.c  → 83
$ sed -n '304,313p' net/ipv6/ip6_input.c # ipv6_rcv → … → ip6_rcv_finish (B7)
$ grep -n 'int ip6_forward(' net/ipv6/ip6_output.c → 497
$ sed -n '6378,6380p' net/core/dev.c     # if (skb_defer_rx_timestamp(skb)) return (B7-ts)
$ sed -n '67,112p' net/core/timestamping.c  # defers ONLY w/ PHYLIB hwprov+phydev+PTP+rxtstamp
$ grep -n 'phydev\|phylib\|hwprov\|hwtstamp' drivers/net/tun.c  # ZERO hits → TUN never defers
```

xpf shape (repo, read-only):

```text
$ grep -n 'IFF_TUN | IFF_NO_PI' userspace-dp/src/slowpath.rs
2220: IfReq::new(&name, IFF_TUN | IFF_NO_PI) / 2240: IFF_TUN|IFF_NO_PI|MULTI?
$ grep -n 'libc::write(fd' userspace-dp/src/slowpath.rs → 1750 (sync arm)
$ grep -n 'opcode::Write' userspace-dp/src/io_uring_write.rs → 583 (uring arm)
$ python3 ENOTSOCK probe (TUN char fd sendmsg):
sendmsg on TUN char fd -> errno=88 (Socket operation on non-socket)
```

Current-code gap probes (repo, read-only — §5 "gap demonstrated"):

```text
$ python3 (scripts/dist/sign.py import; current nonempty-guest_kernel rule):
current-sign guest_kernel=7.0.0-30-generic -> SIGN
current-sign guest_kernel=7.0.0-31-generic -> SIGN     # GAP
current-sign guest_kernel=7.0.0-22-generic -> SIGN     # GAP
$ python3 (current publish agreement leg):
coherent-B 7.0.0-31 manifest+inventory agree -> PUBLISH  # GAP
$ python3 (current validate floor logic):
current-floor 7.0.0-31-generic -> PASS(pending mlx5/single)  # GAP
$ python3 (specified §0 membership predicate):
member (7.0.0-30-generic, 7.0.0-30.30) -> ACCEPT
7.0.0-31-generic -> REJECT / same-uname revision-skew -> REJECT / 7.0.0-22 -> REJECT
```

Scope honesty: this transcript is archive/tree/code evidence +
 recipe probes executed by the research lane. It is NOT landed-gate
 execution (P2) and NOT member-kernel execution (kprobe/readbacks) —
 those remain the P2-entry bar, now with exact expected values.

 ## 8. Artifact retention ledger (v11 — answers the gate artifact question)

 Lane rule permits only `docs/pr/9506-delta/*.md` writes, so durable
 retention is git-pinned .md + content hashes; `/tmp` bytes are
 ephemeral by location but bit-reproducible via the cited commands.
 Per item, exact status (RETAINED = in-branch now; EPHEMERAL =
 present at `/tmp` paths below at v11 time, re-fetchable;
 TRANSCRIPT-ONLY = command+output in §7, no separate bytes):

 - Member tree bytes: EPHEMERAL at `/tmp/u30tree` (shallow clone,
  `--depth 1 --branch Ubuntu-7.0.0-30.30`, sparse: the six files
  below). Identity RETAINED (§1 + here): remote
  `https://git.launchpad.net/~ubuntu-kernel/ubuntu/+source/linux/+git/resolute`,
  tag `Ubuntu-7.0.0-30.30`, tag-obj
  `399867a77d094ee10790dd9051938ed243954779`, commit
  `d974a4063f5c03c13b4f241a9ab511750e0b9f12`. Reviewed-blob SHAs
  RETAINED (verbatim, `git rev-parse TAG:path`):
  `net/core/dev.c` `fab5a0bebd924ee6240dcd57d7b477570218451a`,
  `drivers/net/tun.c` `ca0ae5df73af78a3391841cbb1f115e42a5e8e13`,
  `net/core/net-sysfs.c` `b9740a397f55b8313ec66490be520b050769f4b8`,
  `net/ipv4/ip_input.c` `19d3141dad1f8b031981aea40c311509583e9256`,
  `net/ipv6/ip6_input.c` `2bcb981c91aa83fe08d782c29a185c8559aeacde`,
  `net/core/timestamping.c` `a50a7ef49ae894bfd23462f2a9eb3c762483af26`.
  Reviewed line excerpts RETAINED (§7 branch block).
 - Deb/config bytes: EPHEMERAL at
  `/tmp/linux-image-7.0.0-30-generic_7.0.0-30.30_amd64.deb`,
  `/tmp/linux-modules-7.0.0-30-generic_7.0.0-30.30_amd64.deb`,
  `/tmp/linux-headers-7.0.0-30-generic_7.0.0-30.30_amd64.deb`,
  `/tmp/linux-buildinfo-7.0.0-30-generic_7.0.0-30.30_amd64.deb`
  (+ `/tmp/u30bi/usr/lib/linux/7.0.0-30-generic/config`,
  `/tmp/resolute-*-Packages.gz`, `/tmp/resolute-sec-Sources.gz`).
  SHAs RETAINED (§1: all four debs bytes-verified) + full config
  SHA256 RETAINED:
  `b07d3cb0d53236b021d73038e315018801fa6b843529d53129ad94a2a5233bf6`;
  P-MECH config excerpt RETAINED (§3 + F8 fixture). Re-fetch:
  §7 URLs + `sha256sum -c` against these pins.
 - F0–F9 recipe scripts: RETAINED in-branch at
  `docs/pr/9506-delta/f0f9-recipes.md` (verbatim blocks,
  extraction command + per-file sha256 pins in-file; 15/15
  verified post-extraction at v11).
 - Per-boundary outputs: RETAINED in `f0f9-recipes.md` output
  matrix (member-ACCEPT + revision-skew/coherent-B-REJECT per
  boundary + current-code gap verdicts; `MATRIX: ALL-HERE-OK`,
  exit 0, 2026-09-27). The v10 aggregate probe outputs they
  supersede remain TRANSCRIPT-ONLY (§7 v10 block).
 - ENOTSOCK probe script: RETAINED (`enotsock_probe.py` in
  recipes file); fd/device identity RETAINED (matrix:
  `/dev/net/tun` 10:200, build host `7.0.13+deb14-amd64`,
  char fd O_RDWR); raw output RETAINED in the matrix
  (`socket-op: errno=88 … [OK]`) — no separate raw-output file
  exists (TRANSCRIPT-ONLY beyond the matrix paste). Member-
  kernel/USP-device positive control: NOT executed (P2).
 - rx_batched drift / kprobe sync-proof / PTP cells: scripts
  RETAINED as specified text (recipes file, exit 3 =
  not-run-here); outputs do NOT exist (P2 member-kernel bar).
 - P2-ENTRY EVIDENCE CONTRACT (B8, airtight): permits stay
  CLOSED until ALL of the following exist as LANDED, member-
  kernel-executed evidence: (i) ENOTSOCK positive control on
  the member USP device (same script, `$TUNDEV`, errno 88);
  (ii) rx_batched set/readback/drift/revoke fixture (set 64
  → readback → revoke+fence+freeze within one audit tick);
  (iii) IPv4+IPv6 kprobe timing proof (forward entry+exit
  strictly inside the `tun_chr_write_iter` window per
  xpf-shape write); (iv) every per-tick readback in §4
  executing against the member (RPS/RFS/GRO/XDP/TC/coalesce/
  phydev). ANY missing path, observation, or readback keeps
  permits CLOSED — no partial-credit OPEN. The B8 gates above
  are RECIPE-EXECUTED (i–iv specified + retained); LANDED is
  P2's entry bar.
