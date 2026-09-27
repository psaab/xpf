# Kernel allowlist member review: 7.0.0-30-generic (#9506 P-MECH receive proof)

 Review base: research/9506-delta at v9 (plan `docs/pr/9506-delta/plan.md`).
 Purpose: this record is the completed per-member evidence the M1
 ENFORCED RECEIVE MODE invariant requires. It binds the exact guest
 kernel identity to its source revision, Kconfig posture, and the
 per-branch receive-path findings — each finding closed by a cited
 basis plus a machine-checked gate, never by an unreviewed claim.
 STATUS LEGEND (per-section, honest): ESTABLISHED = repo code or
 recorded Tier-2+ evidence; CITED = reviewer-verified stable read with
 transcript ref, plus a per-member machine confirmation named in the
 closing gate; ENFORCED = machine gate specified in the plan with named
 P2-entry evidence cells (status SPECIFIED until P2 executes them —
 see §5 table statuses).

## 1. Member identity (exact strings, repo-grounded)

- `uname -r`: `7.0.0-30-generic`
  (`docs/image-validation.md:537`, Tier-2 recorded pass 2026-08-21).
- Base: Ubuntu 26.04 cloud image, `9dc7c536…`, Canonical-GPG-verified
  (`docs/image-validation.md:536`; pins `scripts/image/bake.py:404`,
  `:410`, `:433`).
- Image: `xpf-userspace-forwarding-ok-20260402-bfb00432-10859-gf93215641.qcow2`,
  `git_commit: f93215641` (`docs/image-validation.md:534-535`).
- Manifest linkage block (quoted verbatim from the signed sidecar shape,
  `bake.py:1167-1178`): `base_release: 26.04`,
  `base_image_sha256: 9dc7c5363c0146a08ba0c9aa834d82c2c6dfbb1c471ad9a2f0aba1189e21be05`,
  `base_image_pinned: true`, `guest_kernel: 7.0.0-30-generic`.
 Status: ESTABLISHED (repo pins + Tier-2 pass, both cited by line).

## 2. Source revision binding (mechanism + capture rule)

No Ubuntu source-package revision string for this build exists in-tree
(negative census over manifests, inventories, tests, docs — only binary
names like `linux-image-7.0.0-30-generic` occur). The binding is therefore
mechanical, not quoted:

- At bake, `dpkg-query -W -f='${Package}=${Version}\n'` over the installed
  `linux-image-*`/`linux-modules-*` set (same installed-filter as the
  `:708-721` hold-verify fragment) records the full rows into the new
  required manifest key `kernel-source-revision` (beside `guest_kernel`).
- The value is the dpkg-recorded binary version string (Ubuntu kernel
  practice encodes the source revision in it); gates treat it as an
  opaque exact-match token — agreement-checked, never parsed.
- Agreement: `sign.py` `assert_bake_set` and `publish.py`
  `gate_provenance` require the key present; publish additionally requires
  the `linux-image-7.0.0-30-generic` / `linux-modules-7.0.0-30-generic`
  rows present in `xpf-<ver>.pkgs` with versions agreeing with the key.
  Any mismatch refuses (see §5 fixtures F3/F4c).
 - PINNING (defeats a coherent unreviewed B): the FIRST recording at the
   P2-evidence bake is fixture F0 — its exact rows are pinned verbatim
   in repo (Python pins beside `PINNED_BASE_*` in `bake.py` + Go pins
   beside the LANE-1/validate call sites + agreement test asserting both
   sides pin the identical tuple). Every later bake/sign/publish/admit
   boundary compares against the PIN, not merely manifest↔inventory
   agreement (agreement remains as tamper-evidence). B passes only by
   matching the pinned tuple on every field — at which point B IS the
   member. Status: MECHANISM SPECIFIED (capture command + F0 + pins
   named in plan; EXECUTED when P2 runs F0 and lands the pins).

## 3. Kconfig posture (asserted, both snippets)

Floor (existing): `>=6.18`, `-generic` flavor, single-kernel invariant,
mlx5 set (`validate.py` scenario A), `CONFIG_BRIDGE` +
`CONFIG_NF_TABLES_BRIDGE` (`bridge_floor_10171.py:17-24`).

New third predicate (same `_CONFIG_ASSERT` shape, wired into the offline
snippet `bake.py:676` and the live snippet `validate.py:1212`):

- `CONFIG_4KSTACKS` must be absent or `=n`; the assert FATALS on
  `CONFIG_4KSTACKS=(m|y)`. Rationale: the `tun.c:1952-1955` `netif_rx`
  alternative branch compiles in only when the symbol is set; refusing
  set builds removes that branch from the admitted set by construction.
  (The appliance `-generic` x86_64 build carries 16K stacks; the assert
  — not that belief — is the enforcement.)

 ## 4. Per-branch findings (claim / family / basis / closing gate / status)

 B1 RPS-map branch. Claim: with a NULL per-queue RPS map, `get_rps_cpu`
 cannot select a backlog CPU via the map. Family: L2 (pre-family,
 applies identically to v4/v6). Basis: CITED — stable-tree
 `net/core/dev.c` `get_rps_cpu` dual-read structure (reviewer-verified
 read on record in this review process, Plan7Opus verification
 section); per-member confirmation is the readback behavior below
 re-executed ON the member kernel at every boundary (§5). Closing
 gate: per-queue `rps_cpus==0` readback on every q0 queue, every audit
  tick; empty dir set or any nonzero refuses. Status: CITED + GATE
  SPECIFIED (EXECUTED when P2 runs the readback cells + F0–F9).

 B2 RFS flow-table branch. Claim: with no per-queue flow table,
 `get_rps_cpu` cannot select a backlog CPU via the `rps_flow_table` /
 socket-flow branch (which operates with a NULL RPS map). Family: L2.
 Basis: CITED — same stable-tree read (`get_rps_cpu` + `net-sysfs.c`
 `rps_flow_cnt` management). Closing gate: per-queue
 `rps_flow_cnt==0` readback alongside B1; present table refuses even
 with all other fields safe. Status: CITED + GATE SPECIFIED (RFS
 fixture in P2 entry).

 B3 TUN dispatch (non-NAPI path). Claim: `tun_chr_write_iter` dispatches
 via `netif_receive_skb` (inline absent backlog selection). Family: L2.
 Basis: CITED — stable-tree `tun.c` write path (reviewer-verified read
 on record, Synthesis verification). Closing gate: ESTABLISHED
 no-`IFF_NAPI` creation flags (zero in-tree hits) + B1/B2 excluding
 backlog selection. Status: CITED + GATE SPECIFIED.

 B4 TUN 4KSTACKS alternative. Claim: the `netif_rx` alternative under
 `CONFIG_4KSTACKS` is not compiled into admitted builds. Family: L2.
 Basis: §3 Kconfig assert (mechanical). Closing gate: bake + boot assert
 FATALS on set. Status: ENFORCED-SPECIFIED (F8 executes both snippets).

 B5 GRO hold. Claim: no GRO merging holds q0 skbs across the routing
 decision. Family: L2. Basis: GRO-off readback semantics.
 Closing gate: ethtool `generic-receive-offload` off readback per tick;
 on refuses. Status: ENFORCED-SPECIFIED.

 B6 XDP redirect. Claim: no XDP program diverts q0 skbs. Family: L2.
 Basis: netlink attachment readback. Closing gate: `Info().XDP()`
 none-required per tick; attached refuses. Status: ENFORCED-SPECIFIED.

 B7 v4/v6 symmetry. Claim: the inline argument holds identically for
 `ip_rcv → ip_forward` and `ip6_rcv → ip6_forward`. Family: v4+v6
 (the symmetry claim itself). Basis: ESTABLISHED — repo code:
 RPS/RFS/NAPI/GRO reasoning is L2, pre-family; TC mark program is
 family-blind (mark/`queue_mapping` only, `slowpath.rs:188-263`); TUN
 `IFF_NO_PI` parses family by nibble (`gre.rs:710-714`). Closing gate:
 same predicate both families + TC readback + IPv6-parity cells.
 Status: ESTABLISHED + GATE SPECIFIED.

 ## 5. Boundary enforcement (member-as-member, not merely nonempty)

 F-STATUS HONESTY: every fixture below is SPECIFIED (exact command +
 expected verdict named here and in plan §7 P2-entry cells) and becomes
 EXECUTED only when P2 runs it against the member kernel with recorded
 evidence. P-MECH does not open permits until F0–F9 are all EXECUTED.

 - Bake output: virt-customize run-command beside `:645-646`/`:670-671`/
   `:676` asserts `ls /lib/modules` equals exactly the allowlist member;
   drifted bake emits nothing signable. Fixture F1 (7.0.0-31 → FATAL).
   Status: SPECIFIED.
 - First recording: the P2-evidence bake's `dpkg-query` rows are fixture
   F0 — exact rows pinned verbatim in repo (Python + Go pins + agreement
   test). Fixture F0 asserts the rows exist, match the member uname, and
   land byte-identical in both pin sites. Status: SPECIFIED.
 - Signed manifest: new required `kernel-allowlist` key + `sign.py`
   `assert_bake_set` refuses member mismatch (extends `:438-442`).
   Fixture F2 (inventory parse/readback reports non-member
   `guest_kernel` → bake dies member-mismatch). Fixture F3 (7.0.0-22
   sidecar → SignError). Status: SPECIFIED.
 - Package inventory: `publish.py` `gate_provenance` requires key present,
   `linux-image-<member>`/`linux-modules-<member>` rows present, versions
   agreeing with the pinned tuple. Fixtures F4a/b/c (existing skew dies
   + new lacks-member-package die). Status: SPECIFIED.
 - Validate/boot: scenario A asserts `uname -r` equals the member exactly
   (before the hold assert) + Kconfig third predicate live. Fixture F5
   (7.0.0-22 single+held → fail). Status: SPECIFIED.
 - Ordinary-boot admission: the supervisor asserts member match before
   OPEN (same gate as the mode predicate — a booted non-member runs the
   system but never opens permits). Fixture F5b (booted 7.0.0-22 with a
   7.0.0-30 manifest → system runs, permits stay shut). Status:
   SPECIFIED.
 - Rollback admission: rollback to a non-member known-good proceeds as a
   system function, but P-MECH admission refuses OPEN until a member
   kernel runs again. Fixture F5c (rollback to held 7.0.0-22 → system
   functional, P-MECH deny-only + alarm). Status: SPECIFIED.
 - LANE-1: Arm refuses non-member candidates after `ValidateKernelSegment`;
   Gate2 (`kernel_run.go:551-558`) exact equality already member-exact;
   promotionMarker/lastRoll/ReadChannelStatus prove the member;
   `xpf-kernel-promote` outer gate refuses no-infer. Fixtures F6/F7.
   Status: SPECIFIED.
 - Kconfig: `CONFIG_4KSTACKS` third predicate in both offline (bake) and
   live (validate) snippets. Fixture F8 (set/present → FATAL in both).
   Status: SPECIFIED.
 - Review linkage: this record quotes member strings verbatim; a record
   quoting any other member is VOID for this member. Fixture F9.
   Status: SPECIFIED.

## 6. Limits (explicit, no hand-waving)

- No Ubuntu kernel source tree exists in this repository; this record does
  not claim textual review of Ubuntu's 7.0.0-30 tree. Safety rests on
  runtime-verified predicates (read back every tick) + Kconfig asserts +
  exact-version pinning — not on any single human tree read.
- The stable-tree branch structures above are cited from reviewer-verified
  reads on record in this review process (Plan7Opus verification section)
  at the stated files/symbols; per-member confirmation is the Kconfig
  assert + version floor + readback behavior, re-executed at every
  boundary above.
- Adding a member repeats this entire record (new identity + source
  capture + Kconfig + per-branch confirmation + boundary fixtures) via
  reviewed commit; non-members deny by default at every boundary.
