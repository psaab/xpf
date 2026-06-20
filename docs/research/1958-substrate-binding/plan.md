# #1958 — Substrate-agnostic interface binding + bootstrap-reachability contract

RESEARCH-ONLY. Architecture proposal for manual approval. No code in this
branch beyond this doc + reviewer docs. Original base: origin/master @
5d452736e (v1-v3). **v4 re-base: origin/master @ 4e6fc2f2e** (+471 commits) —
see the v4 REFRESH block immediately below.

---

## v5 — r4 review fold (2026-06-20): corrected rationale, disposition stays PLAN-DEFER

**v5 supersedes the v4 block. r4 reviewers (Codex + AGY + Claude SMR all
PLAN-NEEDS-MAJOR) caught two real defects in v4; both are folded here. The
architecture below (v1-v3) is unchanged; the *disposition* (PLAN-DEFER the
net-new B/C work) survives, but the v4 *rationale* was materially wrong and is
rewritten.**

**r4 fold A (Codex — DECISIVE): the "zero container consumer" claim was
FALSE.** A container substrate is named, tooled, and **maintained** in-tree:
- `Makefile:177-178` ships `make test-ct` → `test/incus/setup.sh create-ct`.
- `setup.sh:43` `CT_PROFILE="xpf-container"`; `:296-318` define a privileged
  container with `eth0..eth4` **veth** NICs (kernel names KEPT, unlike the VM
  profile which renames `eth0`→`enp5s0` at `:269`).
- `:511-521` `cmd_create_ct` launches it; `:555-640` `cmd_deploy` pushes
  `xpfd`/`cli`/`xpf-userspace-dp`, installs `xpfd.service`, starts it.
- It is maintained, not stale: hardened in #1943 (kernel-coupled provisioning
  carved to VM-only because "a container shares the HOST kernel") and #1992
  (multi-firewall-on-bridge guard).

So the v4 phrases "no concrete consumer," "purely speculative," and "no CI
substrate to smoke it on" are all WRONG. A container substrate exists and
`test-ct` is a ready-made smoke substrate.

**But xpf-in-container interface bring-up is NON-FUNCTIONAL today — which
sharpens, not softens, the gap.** The deploy pushes `xpf-test.conf`, which
references Junos names `fxp0`/`ge-0/0/0..4` (`xpf-test.conf:1-59`). The
container's NICs are veth `eth0..eth4` with no PCI device symlink, so:
- `enumerateAndRenameInterfaces` (`linksetup.go:66-73`) hits `len(nics)==0`
  → logs "no PCI network interfaces found" → returns, renaming nothing.
- `pkg/devicemap` skips non-PCI interfaces, so #1956 does not cover veths.
- `bootstrap.go:609-625` records the lifeline by PCI only → the #1922
  fail-safe is non-functional on veths.
- `compiler_iface.go` marks unmanaged NICs `always-down` unless device-map
  `leave-alone` is active.
This is **exactly the Slice-B gap** (non-PCI discovery + alias-mode +
non-PCI lifeline), AND `xpf-test.conf` uses Junos names, which is the
**deferred sub-mode (b)** (logical alias, §5.2 — the harder 50-consumer
indirection path). `make test-ct` is therefore a **broken-by-design-today**
xpf-in-container path. No issue tracks it as a bug; it appears used for
dataplane-isolation experiments where full interface management is not
exercised, but the path exists and the gap is latent and un-prioritized — NOT
fictional.

**r4 fold B (AGY): the research branch was on the STALE v3 base.** It was cut
from `df2235787` (base `5d452736e`), so reviewers reading the checked-out tree
saw `pkg/devicemap` absent and the line numbers off — the artifact
contradicted its own text. **Fixed: the branch is now rebased onto
`4e6fc2f2e`**; the source tree matches the v5 code claims.

**Corrected defer rationale (what actually justifies PLAN-DEFER, post-fold):**
1. **No bug is filed.** The container path's interface-management breakage is
   latent and un-prioritized — no operator or issue asks for xpf-in-container
   to be a *supported* path. `test-ct` is a dataplane-test convenience, not a
   shipped product surface.
2. **No remote-reachable non-PCI lockout exists today.** The container's
   reachability is `incus exec` (delegate); there is no remote SSH lifeline to
   lose, so the PCI-keyed-lifeline gap (r2 fold B, still real — confirmed at
   `bootstrap.go:609-625`) is not a *lockout* there. AGY r4 verified no
   Hyper-V/VMBus, Xen/XenBus, AWS, or Azure provisioning exists in-tree
   (deploy/bake target KVM/libvirt + incus VMs on standard-PCI virtio;
   `debian/control:11` amd64-only). So no provisioned remote-reachable non-PCI
   substrate exists to force the fix now.
3. **Slice B/C is large surface on the most fragile bring-up code** — a
   non-PCI enumerator, a non-PCI lifeline resolver, an `eth0`-name consumer
   audit, a substrate detector, and `platform-profile` — for a path nobody has
   prioritized making supported.

**Honest correction to the v4 defer arguments:** DROP "no CI substrate to
smoke it on" — `test-ct` IS one, and that makes Slice B *more* tractable to
build+verify when prioritized (a real plus, not a defer reason). The defer now
rests only on (1) no bug filed + (2) no remote-reachable non-PCI lockout +
(3) large fragile surface.

**Concrete un-defer triggers (refined):**
- **A filed bug: "xpfd interface management must work in `xpf-container` /
  `make test-ct`" — i.e. make the container path SUPPORTED.** This trigger
  already half-exists (the tooling is there); it just needs to become a
  product requirement. Then `/engineer 1958` Slice B from this doc.
- A real remote-reachable non-PCI substrate (a provisioned VMBus/XenBus VM)
  where the PCI-keyed lifeline becomes a live lockout — in which case the
  right first increment is a NARROW "non-PCI discovery + non-PCI lifeline"
  slice, NOT the full container alias-mode + detector + platform-profile
  umbrella.

**Design fork the plan must surface (not bury): the container config naming.**
`xpf-test.conf` uses Junos names, so a *supported* container path needs EITHER
sub-mode (b) (the deferred harder logical-alias path, 50-consumer indirection)
OR `xpf-test.conf` is re-authored with `eth0` kernel names so sub-mode (a)
(nearly-free, §5.3) covers it. The cheap, recommended first move when this is
prioritized is sub-mode (a) + an `eth0`-named container config — explicitly
the §5.2 (a) recommendation. Do not silently assume sub-mode (b).

**Disposition: PLAN-DEFER (net-new Slices B + C), architecture PLAN-READY as
design-of-record, Slice A (#1956) shipped.** Not PLAN-KILL (architecture is
sound and `test-ct` proves the substrate is real, so the design will be
needed). Not PLAN-READY-build-now (no bug filed, no live lockout, large
surface). If the user wants the container path supported now, the un-defer
trigger is met and `/engineer 1958` Slice B (sub-mode (a) + `eth0`-named
container config) is the recommended first increment.

---

## v4 — REFRESH + RE-BASE (2026-06-20) [SUPERSEDED BY v5 ABOVE — retained for history]

**What changed since v3:** master advanced 471 commits (`5d452736e` →
`4e6fc2f2e`). The v1-v3 architecture below was re-verified against current
master and **all load-bearing claims survived**:

- `config.LinuxIfName` is still exactly `strings.ReplaceAll(name, "/", "-")`
  (`pkg/config/types.go:12-14`) — the §5.3 de-risking ("identity transform on
  slash-free names") stands. Consumer count is now **50 files** (was 45); the
  argument is count-independent.
- `enumeratePCINICs` (`linksetup.go:154`), `assignName` (`:227`),
  `enumerateAndRenameInterfaces` (`:66`), `writeBootstrapFxp0Network` (`:316`),
  `extractPCIAddr` (`:209`) — all present, structurally unchanged (line
  numbers drifted by ~15-20; no semantic change).
- `vmHeuristic` (`host_tunables.go:126`) still inspects `/sys/hypervisor/type`
  + cpuinfo `hypervisor` flag behind the mockable `hostTunableFS` (`:46`) —
  §6.2's "extend this exact function" and the ARM64-misclassification fold
  (r2 fold A) both hold.
- `bootstrap.go` lifeline machinery present and **still PCI-keyed**:
  `defaultMgmtInterface = "fxp0"` (`:92`), `lifelineRecord` (`:494`),
  `pciAddrForInterface` builds the record purely from `busAddr` (`:611-621`),
  `protectedInterfacesWith` with the `narrowFxp0` OQ-D escape valve
  (`:683-697`). The r2 fold B finding ("the lifeline record is PCI-keyed and
  must be generalized to `pci → perm-mac → kernel-name`") is **confirmed still
  true** against current code, NOT yet fixed.
- `compiler_iface.go` reconcile still marks unmanaged NICs `Unmanaged` +
  `always-down` (`:1194-1198`) AND now carries the **shipped** #1956
  `leave-alone` skip (`:1132-1163`).

**Materially new fact since v3: Slice A (#1956) SHIPPED.** `pkg/devicemap/`
exists on master (`devicemap.go`, `devicemap_test.go`); the `chassis
device-map` grammar, compiler, schema, `show chassis device-map [candidates]`,
`unmapped-interface-policy leave-alone`, and the PCI-primary + perm-MAC
identity resolver are all merged (commits `1fc18c023`..`d50db21dc`; #1956
issue CLOSED). The v3 recommendation "ship Slice A first, then file B/C as
follow-ups" is therefore **already half-executed**: the foundation is in.

**The decisive finding: Slices B and C have NO concrete consumer.** A current-
master scan found:
- **Zero** container-substrate demand — no open/closed issue names container
  (incus-container / docker / k8s) as a target; no follow-up issue was ever
  filed for Slice B (alias-mode) or Slice C (substrate detector /
  `platform-profile`).
- **Zero** container-targeting code — `grep` over `pkg/**` + `cmd/**` for
  `dockerenv|containerenv|alias-mode|platform-profile|platformProfile` returns
  nothing. The substrate detector and alias enumerator do not exist even in
  skeleton.
- Production image (`scripts/image/bake.py`) targets the VM/appliance base
  only; the only `container`/`docker` hits under `scripts/image/` are the
  **incus VM-guest agent** (`incus-agent.service`), not a container runtime.
- The two substrates xpf actually runs on today — **VM** (positional
  enumeration, status quo, works) and **bare metal** (#1956 device-map,
  shipped) — are **both already covered**. The container axis, which §0/§5
  themselves call "the riskiest unknown" and "the umbrella's net-new burden,"
  is **speculative**: it has no operator, no test substrate, and no issue
  asking for it.

**Revised recommendation: PLAN-DEFER for the net-new umbrella work (Slices
B + C). Keep #1958 OPEN as the architecture record; do NOT `/engineer` it
now.** Rationale (per the project's own "build it when there is a concrete
second substrate" discipline, mirroring the #1760 PLAN-KILL-at-zero-incidence
and #1782 capture-gated-deferral precedents):

1. **The architecture is sound and worth keeping** — the binding/configuration
   split, the three-axis framing, and the de-risked alias-mode blast radius
   are all validated. This doc is the canonical design for when container
   demand appears. PLAN-DEFER, not PLAN-KILL: the design is correct, only the
   *timing* is premature.
2. **Slice B/C are not free** — v3's own honest-scope note flags r2 fold B
   (generalize the lifeline record beyond PCI) as "real work, not a doc
   tweak." Implementing a substrate detector, a non-PCI alias enumerator, an
   `eth0`-name 50-consumer audit, AND a generalized non-PCI lifeline resolver
   — all to serve a substrate **nobody is asking for** and there is **no CI
   substrate to smoke it on** (the project smokes only on the loss userspace
   VM cluster) — is speculative surface area on the single most fragile part
   of bring-up. Untested-because-untestable container bring-up code is a
   liability, not an asset.
3. **The gating prerequisite is concrete container demand.** When a real
   container target lands (an issue: "run xpf in an incus-container / docker /
   k8s pod with veth `eth0`"), `/engineer 1958` can start from this exact doc
   — the design is plan-ready and the blast radius is mapped. Until then the
   marginal value of writing the code is ~zero and the marginal risk
   (untestable bring-up regressions, 50-consumer audit churn) is real.

**Concrete deferral exit criteria (what un-defers this):**
- A filed issue naming a specific container substrate xpf must run in, with a
  reachable test environment (an incus-container or docker profile the smoke
  harness can stand up), OR
- A non-container driver for the generalized non-PCI lifeline (r2 fold B) —
  e.g. a VMBus/XenBus (Hyper-V/Azure/AWS-Xen) VM target actually being
  provisioned, where `enumeratePCINICs` and the PCI-keyed lifeline both fail
  today. **If that VM-substrate need is real and the container need is not,
  the right increment is a narrow "non-PCI VM lifeline + non-PCI discovery"
  slice — NOT the full container alias-mode + detector + platform-profile
  umbrella.** That would be a new, smaller research scope, not this umbrella.

**What is NOT deferred:** Slice A (#1956) is shipped and stays. The v1-v3
architecture below is preserved verbatim as the design-of-record. If the user
disagrees with the defer and wants Slice B/C built speculatively anyway, the
plan below is plan-ready to `/engineer` as-is — the defer is a *judgment about
timing/priority*, not a defect in the design.

---


This is the **umbrella / architecture-level** generalization. **#1956 is its
bare-metal increment** — its v3 plan (`research/1956-bare-metal-device-map`)
is treated as settled foundation here, NOT re-derived. Read #1956 §0-§11
first; this doc builds the cross-substrate model on top of it and pins only
the net-new pieces (container alias-mode, substrate detector,
`platform-profile`, the generalized reachability contract).

**v3 (post-r2 review).** r1: Claude SMR + Codex = PLAN-READY; AGY =
PLAN-NEEDS-MAJOR (2 catches folded). r2: Claude SMR + Codex = PLAN-READY; AGY
= PLAN-NEEDS-MAJOR with three SECOND-ORDER catches that survived only because
the first-order ones were closed — all FOLDED v3:
- **r1 fold A (§6.2):** detector "PCI-empty + veths" tell false-positives on
  Hyper-V/Azure (VMBus) + AWS-Xen (XenBus) VMs (also PCI-less). Fixed:
  positive container signals authoritative; `vmHeuristic` before the demoted
  PCI-empty hint.
- **r1 fold B (§7):** "empty protected set for console-only/delegate" lockout
  regression. Fixed: #1922 boot-recorded lifeline UNCONDITIONALLY protected.
- **r2 fold A (§6.2):** `vmHeuristic` is x86-only — **ARM64 VMs** (Graviton,
  Azure-ARM, Apple-Silicon QEMU) have no cpuinfo `hypervisor` flag and no
  `/sys/hypervisor/type`, so they'd misclassify → lockout. Fixed: add
  `systemd-detect-virt` (bare) as the cross-arch VM-detection fallback.
- **r2 fold B (§7):** the #1922 lifeline record is **PCI-keyed**
  (`bootstrap.go:465` skips persisting when no PCI addr), so the
  "unconditional" fail-safe is NON-FUNCTIONAL on the non-PCI substrates
  (veth/VMBus/XenBus) the umbrella targets. Fixed: generalize the lifeline
  record to a `pci → perm-mac → kernel-name` identity chain. (Codex r2
  independently flagged the same gap.)
- **r2 fold C (§7):** unconditional protection permanently welds a
  bootstrap-DHCP NIC out of the dataplane with no CLI to release it. Fixed:
  explicit `force-release-lifeline` override leaf.
Plus three r1 SMR clarifications (§5.3 audit list, detector-advisory
invariant, §2.1 binding-delivery) and Codex's fxp0-narrowing-vs-lifeline
implementation note (§7).

**Honest scope note:** r2 fold B is the one that crosses from "plan text" into
"this expands Slice B/C implementation surface" — the lifeline record and its
resolver must be generalized beyond PCI. This is consistent with the
binding-identity-chain the umbrella already requires (§3 A1), so it is a fold
not a redesign, but /engineer should size it as real work, not a doc tweak.

---

## 0. TL;DR recommendation

**Recommendation: PLAN-READY for an umbrella with three shippable slices, in
this order:**

1. **Slice A — #1956 bare-metal device-map (already plan-ready).** Ships the
   binding primitive (identity-keyed `host-nic → ge-name`, PCI-primary key,
   `unmapped-interface-policy leave-alone`, console-as-lifeline). This is the
   foundation; everything else reuses its grammar and resolver.
2. **Slice B — container alias-mode (`rename: no`).** The net-new, riskiest
   piece: a binding that uses the kernel name as-is, aliases it logically,
   and performs NO netlink rename and NO bring-down-unmanaged. Generalizes
   the device-map entry with a `rename {yes|no}` axis.
3. **Slice C — substrate detector + `system platform-profile`.** The UX/glue
   layer that auto-selects rename + reachability defaults per substrate, with
   an operator override. Lands LAST because it is pure default-selection over
   primitives A and B — it adds no new mechanism, only chooses among existing
   ones. Until it ships, the operator selects behavior explicitly (device-map
   present ⇒ bare-metal semantics; alias-mode entries ⇒ container semantics).

**The load-bearing abstraction is the binding/configuration split** (§2): a
binding is an *early, declarative, substrate-appropriate* `physical-NIC ↔
logical-name (+ rename axis + identity key)` input resolved BEFORE any
netlink mutation; the Junos config references only logical names and becomes
fully substrate-independent. #1956 already delivers this split for bare
metal; the umbrella's job is to make the **identity key**, the **rename
axis**, and the **reachability contract** pluggable so one primitive covers
VM / bare-metal / container instead of three ad-hoc code paths.

**Key de-risking finding (§5.3):** alias-mode's downstream blast radius is
**small**. `config.LinuxIfName` (`pkg/config/types.go:12`) is the single
Junos→Linux name translation, used by 45 files, and it is `ReplaceAll(name,
"/", "-")` — an *identity* for a name with no slash. So if a container
operator names the interface in config exactly as the kernel device (`eth0`),
`LinuxIfName("eth0") == "eth0"` and the entire downstream machinery (zones,
networkd `.network`, FRR, DHCP, VRRP) already works **unchanged**. The
alias-mode blast radius is concentrated in *bring-up* (the rename loop, the
bootstrap-fxp0 fabrication, the always-down reconcile), NOT in the 45
consumers. This is what makes Slice B tractable.

**Not a PLAN-KILL.** The chicken-and-egg is real, the three-axis framing is
correct, and the increment ordering keeps each slice independently
shippable + smoke-able. PLAN-KILL/scope-cut criteria are in §10.

---

## 1. Problem restatement, grounded in code

The bring-up is built for one substrate (VM/appliance on a DHCP mgmt net) and
hardcodes three assumptions that do not generalize:

1. **Discovery is PCI-only.** `enumeratePCINICs` (`pkg/daemon/linksetup.go:137`)
   walks `/sys/class/net`, and for each entry requires
   `/sys/class/net/<n>/device` to stat (`linksetup.go:150-153`) AND a
   resolvable PCI bus address via `extractPCIAddr` (`linksetup.go:167-170`).
   A pure-veth container interface (`eth0`) has **no `device` symlink and no
   PCI address** → it is silently skipped. **A veth-only container finds zero
   NICs and xpf manages nothing** (issue body, confirmed). Bare metal finds
   *too many* (BMC/IPMI/storage), which is exactly the #1956 F2 hazard.

2. **Naming is positional + rename-mandatory.** `assignName`
   (`linksetup.go:210`) maps enumeration idx → `fxp0`/`em0`/`ge-*`, and
   `enumerateAndRenameInterfaces` (`linksetup.go:65-89`) *renames the kernel
   device* via `.link` + `renameInterface`. In a container the orchestrator
   owns the netns and the veth name; xpf usually **cannot** rename `eth0`
   (and even when CAP_NET_ADMIN permits it, renaming the orchestrator's
   handle breaks the orchestrator's own bookkeeping). There is **no
   "use the kernel name as-is" path** today — rename is unconditional.

3. **Reachability is a fabricated `fxp0` DHCP plane.** `assignName(idx=0)`
   hardcodes `fxp0` (`linksetup.go:211`); `writeBootstrapFxp0Network`
   (`linksetup.go:299`) unconditionally writes a DHCP `.network` for it; and
   `defaultMgmtInterface = "fxp0"` (`bootstrap.go:32`) keeps it in the #1922
   protected set. On bare metal the lifeline is the **console**; in a
   container the lifeline is **`orchestrator exec`**. Neither wants a
   fabricated DHCP mgmt port. #1956 §9.6 already establishes "console IS the
   lifeline, no auto-fxp0" for bare metal; the umbrella generalizes this to a
   declared per-substrate **reachability contract**.

4. **Bring-down-unmanaged claims the whole box.** The compiler reconcile
   (`pkg/dataplane/compiler_iface.go:1132-1188`) enumerates every system
   interface and, for any NIC not in config / not daemon-owned / not
   #1922-protected, marks it `Unmanaged`, strips addresses, and forces
   `always-down` (`networkd.go:406-414`). In a container this would tear down
   the orchestrator's `eth0`; on bare metal it downs BMC/storage NICs. #1956's
   `unmapped-interface-policy leave-alone` fixes this for the device-map case;
   alias-mode must default to the same "leave the rest alone."

### 1.1 What already exists to reuse (do not reinvent)

- **Virt-detection prior art:** `vmHeuristic` (`pkg/daemon/host_tunables.go:126`)
  already inspects `/sys/hypervisor/type` + the `/proc/cpuinfo` hypervisor
  flag, behind a mockable `hostTunableFS` interface, to distinguish VM from
  bare metal. The substrate detector (§6) **extends this exact function and
  interface** — it is not a green-field component.
- **PCI/MAC identity infra:** `extractPCIAddr` (`linksetup.go:192`),
  `pciAddrForInterface` (`bootstrap.go:347`), and the durable lifeline-record
  reader/writer (`bootstrap.go:250-304`). #1956 already commits to the
  PCI-primary + permanent-MAC-fallback resolver discipline built on these.
- **The protected-set / lifeline machinery:** `protectedInterfaces` +
  `protectedInterfacesWith` (`bootstrap.go:408-437`), already config-
  independent and start-of-boot, already tolerant of "no mgmt NIC" on the
  console-only path (`detectLifelineInterface` returns `ok=false` →
  `setupBootstrapLifeline` stays bootstrap with no interface changes,
  `bootstrap.go:455-461`). The reachability contract (§7) parameterizes the
  *default* lifeline source per substrate; the machinery is already there.
- **Single name-translation point:** `config.LinuxIfName`
  (`pkg/config/types.go:12`) — the entire alias-mode tractability argument
  (§5.3) rests on this being the one place Junos↔Linux names are bridged.

---

## 2. The binding/configuration split (the load-bearing abstraction)

**Binding** = `physical-NIC ↔ logical-name`, plus the substrate-specific
*how*: which **identity key** resolves the physical NIC, and whether xpf
**renames** it. **Configuration** = the Junos config (addresses/zones/NAT),
referencing only logical names. The split makes configuration
substrate-independent and isolates all substrate variance into the binding.

A binding entry is the union (superset of #1956's device-map entry):

| Field | Bare metal (#1956) | VM (today, implicit) | Container (net-new) |
|---|---|---|---|
| logical-name | `ge-0/0/3` | `ge-0-0-0` | `lan0` / `ge-0/0/0` |
| identity-key | `pci 0000:09:00.0` (+ perm-MAC fallback) | positional PCI order | `kernel-name eth0` (or perm-MAC) |
| rename | `yes` | `yes` | **`no` (alias)** |
| reachability | console-only | DHCP on a mgmt virtio | delegate-to-orchestrator |

**#1956's device-map entry IS this binding entry with `rename: yes` and a
PCI/MAC key.** The umbrella adds two new cells: the `kernel-name` identity
key and the `rename: no` alias axis. So the umbrella does NOT introduce a new
config object — it generalizes the #1956 `chassis device-map interface`
stanza with a `rename` axis and a `kernel-name` key variant (§8).

### 2.1 The chicken-and-egg break: binding is resolved BEFORE netlink mutation

The chicken-and-egg ("you must reach the box to configure it, but config
defines the interfaces") is broken by making the binding an **early
declarative input that exists before the daemon needs it**, delivered by a
substrate-appropriate channel:

| Substrate | Binding delivery channel | When |
|---|---|---|
| VM / appliance | baked image default (positional) OR a config-drive/cloud-init drop | image-bake / first-boot |
| Bare metal | installer drops the device-map into the seed config; OR operator commits post-install over the console | install-time / console |
| Container | **orchestrator injects** at create — env var, mounted file, or a tiny entrypoint that writes the alias-map before `xpfd` starts | container-create |

The key invariant (already true for #1956 and #1922): the binding +
protected-set are resolved at **start-of-boot, config-independent**, before
the rename loop and before the reconcile. The umbrella keeps that invariant
and only varies the *source* and the *rename axis*. The lifeline/console is
the reachability guarantee that lets the operator fix a wrong binding.

**Container binding-delivery recommendation (Claude SMR r1 fold 3,
resolving OQ-6):** for containers, the binding must exist before the daemon
reads the configstore (it is needed to bring up the interface the operator
would commit config over). Recommended two-phase delivery: (1) **first
boot** — the orchestrator injects the alias-map via a mounted file (e.g.
`/etc/xpf/binding.d/*.conf`) or an entrypoint that writes it before `xpfd`
starts; the daemon reads it start-of-boot like the #1922 lifeline record.
(2) **thereafter** — the binding lives in the configstore as a normal
`chassis device-map` stanza, synced/persisted with the rest of the config.
This is bootstrap-safe in containers specifically because reachability is
`delegate` (orchestrator `exec` is the lifeline), so there is no
chicken-and-egg on the *first* commit — the operator always has
`exec` access. A mounted file is the least-surprise channel for
incus/docker/k8s (k8s `configMap` volume, docker `-v`, incus
`raw.mount`/`devices`).

---

## 3. The three substrate axes (independent, per the issue)

The issue's central claim — *no single mechanism covers all substrates
because three axes vary independently* — is correct. The umbrella's design
makes each axis a pluggable cell, not a fork:

| Axis | Values | Resolved by |
|---|---|---|
| **A1 Identity key** | `positional` / `pci` / `perm-mac` / `kernel-name` | binding entry (§8); priority chain per #1956 §3 |
| **A2 Rename authority** | `yes` (xpf renames via `.link`) / `no` (alias — kernel name as-is) | binding entry `rename` field (§5) |
| **A3 Reachability** | `console-only` / `dhcp <if>` / `delegate-to-orchestrator` | reachability contract (§7); defaulted by platform-profile (§6) |

`platform-profile` (§6) is *only* a convenience that picks sane defaults for
all three axes per detected substrate. The primitives stand alone without it.

---

## 4. Why not a single mechanism — the failure table (grounded)

| Substrate | NIC identity available | Rename feasible? | Current outcome | Required outcome |
|---|---|---|---|---|
| VM (qemu/incus) | virtio PCI addr | yes | works (by luck of ordering) | keep positional default |
| Bare metal | PCI / perm-MAC | yes | claims everything incl. BMC | #1956 device-map + leave-alone |
| Container (veth) | kernel name only (no PCI) | **no** (orchestrator owns netns/name) | **finds 0 NICs, manages nothing** | alias-mode: name-keyed, no rename, leave-alone |

The container row is the umbrella's net-new burden. The other two are #1956 +
status-quo.

---

## 5. Container alias-mode (`rename: no`) — the riskiest unknown, mapped

### 5.1 What alias-mode must do

- **Discovery:** find the veth even though it has no PCI `device` symlink.
  `enumeratePCINICs` cannot — it requires the PCI device path
  (`linksetup.go:150-170`). Alias-mode needs a **name/MAC-based discovery
  path** that enumerates `/sys/class/net` and matches the binding's
  `kernel-name` (or perm-MAC) without demanding a PCI address. This is a new
  enumerator (`enumerateAliasNICs` or a relaxed mode of the existing one),
  NOT a change to the PCI path.
- **No rename:** the binding's logical-name *equals* the kernel name (or is a
  pure-logical alias that maps to it). NO `.link` file, NO `renameInterface`,
  NO `networkctl` rename. The `.link` mechanism (`writeLinkFile`,
  `linksetup.go:270`) is skipped entirely for alias entries.
- **No fabricated fxp0, no bootstrap DHCP:** reachability is
  delegate-to-orchestrator (§7); `writeBootstrapFxp0Network` is skipped.
- **Leave-the-rest-alone:** the reconcile must NOT down/strip the
  orchestrator's other veths. Reuse #1956's `unmapped-interface-policy
  leave-alone` as the alias-mode default (in fact, mandatory — `manage-down`
  in a container would tear down `eth0`).

### 5.2 Two sub-modes of "alias"

- **(a) Identity alias (recommended default):** the operator names the
  interface in config by its **kernel name** (`set interfaces eth0 …`). Then
  `LinuxIfName("eth0") == "eth0"` and there is literally nothing to translate
  — the binding entry only needs to assert "manage eth0, don't rename it,
  don't down the rest." This is the *minimal* alias-mode and the one §5.3
  proves is nearly free downstream.
- **(b) Logical alias (richer, optional):** the operator wants Junos-style
  names (`ge-0/0/0`) bound to `eth0` *without renaming the kernel device*.
  This requires a logical→kernel indirection layer because `LinuxIfName(
  "ge-0/0/0") == "ge-0-0-0" != "eth0"`. Every one of the 45 `LinuxIfName`
  callers (§5.3) would need to consult the binding map instead of the pure
  string transform. **This is materially harder and is explicitly DEFERRED**
  — sub-mode (a) covers the container use case; (b) is a nice-to-have that
  can follow if operators demand vSRX-style names on containers. Recommend
  Slice B ships only (a).

### 5.3 Blast-radius map for alias-mode (the de-risking)

`config.LinuxIfName` (`pkg/config/types.go:12`) is `ReplaceAll(name, "/",
"-")` and is referenced by **45 files** (grep: `pkg/daemon/*`, `pkg/frr`,
`pkg/vrrp`, `pkg/routing`, `pkg/ipsec`, `pkg/grpcapi`, `pkg/api`,
`pkg/cluster`, `pkg/monitoriface`, …). The critical observation:

- For sub-mode (a) (kernel-name in config), `LinuxIfName` is the **identity**
  on a slash-free name, so all 45 consumers already produce the correct
  kernel name with **zero changes**. networkd `.network` generation, FRR
  rendering, VRRP socket binding, DHCP lease keying, zone maps — all keyed by
  `LinuxIfName(configName)` — resolve to `eth0` correctly.
- The ONLY places that must change for sub-mode (a) are the **bring-up**
  sites that assume xpf renamed the NIC:
  1. `enumerateAndRenameInterfaces` / `enumeratePCINICs` — must discover
     non-PCI veths and skip rename for alias entries.
  2. `writeBootstrapFxp0Network` — must be skipped.
  3. The `compiler_iface.go:1132` reconcile — must leave non-bound veths
     alone (already covered by `leave-alone`).
  4. `protectedInterfaces` / `defaultMgmtInterface` — must tolerate "no
     fxp0, no mgmt NIC" (already true on the console-only path per #1956 §9.6
     and `setupBootstrapLifeline` lines 455-461).
  5. RETH-member `OriginalName=` matching — N/A in containers (no RETH).
- **Risk caveat (must verify at /engineer):** some consumers assume a
  *vSRX name shape* for slot/FPC math or for name-prefix classification. The
  audit list (all VERIFIED benign for a literal `eth0`/`lan0` — see below):
  - **Slot/FPC math (all guard `slot >= 0`):** `InterfaceSlot`
    (`types.go:35`), `SlotToNodeID` (`types.go:55`), callers at
    `cluster/monitor.go:258,446`, `grpcapi/server_diag.go:361`,
    `config/compiler.go:347`, `config/types.go:75`. `eth0` → `slot=-1` → the
    branch is skipped (standalone). Safe by construction.
  - **Name-prefix classification (produce absence-of-match for `eth0`,
    which is the CORRECT outcome for a container data port):**
    `daemon_apply.go:308` (`fxp`/`fab`/`em` → mgmt-VRF — `eth0` is not a
    mgmt port, so not placed in vrf-mgmt: correct), `compiler_services.go:493-510`
    (`fxp`/`em`/`fab`/`lo`/`st`/`gr-`/`ip-`/`fti` service-interface filter),
    `compiler_iface.go:954`, `maps_sync.go:1506-1510` (fxp/em/fab
    classification), and all `reth`-prefix HA sites (HA-only; HA-in-container
    is out of scope §10). Codex r1+r2 grepped these exhaustively and found
    **no site that produces wrong/dangerous behavior** for a literal `eth0` —
    only benign absence-of-match.
  - Conclusion: the de-risking claim STANDS (Codex r3 + Claude SMR concur).
    /engineer must still re-confirm the absence-of-match assumption holds
    for each site when implementing, but no counter-example exists today.

  Original caveat retained: auditing these "-1 / no-slot" branches is a
  named Slice-B task, not a blocker — containers are standalone by assumption
  (HA-in-container is out of scope, §10).

**Conclusion:** alias-mode sub-mode (a) is tractable precisely because the
downstream is name-transparent; the work is bounded to ~5 bring-up sites + a
no-slot audit. This is the single most important finding for keeping the
umbrella shippable.

---

## 6. Substrate detector + `system platform-profile`

### 6.1 The setting

```
set system platform-profile auto          # default — detect (§6.2)
set system platform-profile vm            # force positional + dhcp-mgmt
set system platform-profile bare-metal    # force device-map-required + console
set system platform-profile container     # force alias-mode + delegate
```

`platform-profile` selects DEFAULTS for the three axes (§3). It is a `system`
leaf (`schema_system.go` + a typed field on `SystemConfig` + compiler
consumption — the typed-but-ignored-leaf anti-pattern is forbidden per
`docs/config-schema.md`). The operator override is the whole point: detection
can be wrong, and a wrong auto-detect must be correctable with one leaf.

### 6.2 Detection signals, in priority order

Extend `vmHeuristic` (`host_tunables.go:126`) into a `detectSubstrate`
function over the same `hostTunableFS` mock interface:

1. **Container — ONLY positive container signals (highest priority):**
   - `/.dockerenv` exists (Docker), OR
   - `/run/.containerenv` exists (Podman), OR
   - `systemd-detect-virt --container --quiet` exits 0 (catches
     lxc/incus-container/systemd-nspawn).
   These three are *authoritative* — they are true only inside a container.
2. **VM — runs and WINS over the weak container corroborator (AGY r1
   Attack 3 + r2 ARM64 catch):** VM detection is a LADDER, not just
   `vmHeuristic`, because `vmHeuristic`'s signals are x86-centric:
   a. `vmHeuristic` (`host_tunables.go:126` — `/sys/hypervisor/type` +
      `/proc/cpuinfo` `hypervisor` flag). Catches x86 KVM/QEMU/VMware/Hyper-V
      HVM and Xen (PV via `/sys/hypervisor/type=xen`).
   b. **`systemd-detect-virt` (bare form, NOT `--container`) as the
      cross-arch fallback (AGY r2).** The cpuinfo `hypervisor` flag is the
      x86 CPUID.1:ECX.bit31 flag and is **absent on ARM64 guests**
      (`/proc/cpuinfo` has no `flags` section, `Features` lacks it), and
      `/sys/hypervisor/type` is not present on plain KVM/Hyper-V/VMware. So on
      an ARM64 VM (AWS Graviton, Azure ARM64, GCP T2A, Apple-Silicon QEMU)
      `vmHeuristic` returns `""` and would misclassify the VM as bare-metal
      or (via the PCI-empty hint) container → **management lockout on first
      boot**. `systemd-detect-virt` queries DMI/SMBIOS + arch-specific signals
      and reports `kvm`/`qemu`/`microsoft`/`amazon`/`xen` cross-arch, so it is
      the required ARM64 VM tell. The detector MUST consult (a) OR (b) before
      the PCI-empty hint.
   This ladder MUST run before the PCI-empty heuristic below, or a
   Hyper-V/Xen/ARM64 VM (with or without Docker) would be misclassified as a
   container/bare-metal and lose VM provisioning.
3. **Bare metal:** none of the above → physical DMI. Optionally corroborate
   with `/sys/class/dmi/id/sys_vendor` + `product_name` (e.g. not "QEMU"/
   "KVM"/"VMware"/"Bochs"/"Microsoft Corporation"), but default-by-
   elimination is sufficient.

**The "PCI-empty + veths" signal is DEMOTED to a non-authoritative hint
(AGY r1 Attack 3, FOLDED v2).** It may ONLY *corroborate* a container
classification that step 1 already made on a positive signal, or — when NO
positive container signal AND NO VM signal fires — bias the bare-metal
default toward `container` *as a soft default the operator can override*. It
must NEVER override a step-1 or step-2 result. A PCI-less VMBus/XenBus VM is
caught by step 2 (`vmHeuristic`) before this hint is consulted.

**Detector-is-advisory invariant (Claude SMR r1 fold 2):** the detector ONLY
selects DEFAULTS. An explicit binding entry or an explicit `platform-profile`
leaf ALWAYS wins, regardless of detected substrate; the detector never
*gates* or *refuses* a binding. A misdetect is always correctable with one
`set system platform-profile <x>` leaf.

**`systemd-detect-virt` semantics:** `--container` reports only container
techs; the bare form reports VM techs first and falls through to container —
call `--container` explicitly for the container test and the bare form (or
`vmHeuristic`) for the VM test, never conflate them.

### 6.3 Detector → defaults mapping

| Detected | identity-key default | rename default | reachability default | unmapped policy |
|---|---|---|---|---|
| `vm` | positional | yes | `dhcp fxp0` (status quo) | manage-down (status quo) |
| `bare-metal` | device-map required (pci) | yes | `console-only` | leave-alone |
| `container` | kernel-name | **no (alias)** | `delegate-to-orchestrator` | leave-alone |

Detection only *sets defaults*; any explicit binding/leaf overrides. This is
why Slice C lands last: it is pure default-selection over A and B primitives.

---

## 7. The generalized reachability contract

Generalize #1956 §9.6 ("console IS the lifeline") into a declared,
per-substrate contract — reachability is **declared, not assumed**:

```
set system management reachability console-only        # bare metal
set system management reachability dhcp interface fxp0 # VM (status quo)
set system management reachability delegate            # container
```

- **`console-only`:** no *fabricated* fxp0, no bootstrap DHCP `.network`. The
  protected set is NOT forced empty — the boot-recorded default-route
  lifeline (if any) stays protected as the fail-safe (see the CRITICAL
  FAIL-SAFE note below). An empty protected set is valid ONLY on a box with
  no default route at boot (truly console-attached) — the
  `detectLifelineInterface` returns-`ok=false` path (`bootstrap.go:455-461`).
- **`dhcp interface <if>`:** today's behavior, made explicit. The lifeline is
  the named NIC; #1922 protects it and snapshots its addressing.
- **`delegate`:** xpf keeps hands off the management plane entirely — the
  orchestrator's `exec` is the lifeline. No fxp0, no DHCP, no bring-down.
  Equivalent to `console-only` from xpf's perspective (do-nothing), but named
  distinctly so `show` and audit make the operator intent explicit.

**#1922 generalization:** SAFE-BOOTSTRAP's "lifeline" becomes
*profile-driven*, not `fxp0`-hardcoded. `defaultMgmtInterface = "fxp0"`
(`bootstrap.go:32`) stops being an unconditional default and becomes the
`dhcp`-reachability default only. The commit-confirmed rollback +
protected-set machinery is unchanged — it just takes its *configured*
lifeline from the contract instead of a constant.

**CRITICAL FAIL-SAFE — the boot-recorded lifeline is ALWAYS protected,
regardless of the declared contract (AGY r1 Attack 5, FOLDED v2).** The v1
text said "the protected set is empty for console/delegate." That is a
lockout regression and is WRONG. #1922 records the boot-time default-route
NIC (`detectLifelineInterface` → `/etc/xpf/lifeline-interface`,
`bootstrap.go:320,455-475`) precisely so the NIC the operator is *actually
reaching the box on* is never downed/stripped — even by a buggy commit. The
corrected rule:

> The protected set is the UNION of (a) the boot-recorded default-route
> lifeline (always, config-independent — #1922 invariant, unchanged) and
> (b) any mgmt NIC the reachability contract explicitly declares. A
> `console-only`/`delegate` contract MAY decline to *fabricate* an fxp0 and
> MAY skip writing a bootstrap DHCP `.network`, but it can NEVER REMOVE the
> boot-recorded lifeline from protection.

This closes AGY's lockout chain: operator on a remote box over SSH → bad
commit → the reconcile (`compiler_iface.go:1132-1188`) still sees the
lifeline in the skip map (because #1922 recorded it at boot) → the NIC is
NOT downed/stripped → SSH survives → `commit confirmed` rolls back cleanly.
The ONLY case where the protected set is legitimately empty is a genuinely
console-attached box with NO default route at boot — exactly the
`detectLifelineInterface` returns-`ok=false` path
(`bootstrap.go:455-461`), where there is no remote lifeline to lose.

**IMPLEMENTATION GAP — the lifeline record is PCI-keyed and must be
generalized to non-PCI identities (AGY r2 catch 2, FOLDED v3).** As written,
`setupBootstrapLifeline` only persists the lifeline when
`pciAddrForInterface(lifeline)` returns `ok=true` (`bootstrap.go:465`); for a
container `veth` or a VMBus/XenBus VM NIC (no PCI address) the record is
**never written**, so `resolveLifelineCurrentName` returns `("", false)` and
the "unconditionally protected" lifeline is **non-functional on exactly the
non-PCI substrates this umbrella targets.** This is the same PCI-only
assumption that breaks `enumeratePCINICs` (§1.1) surfacing again in the
lifeline path. The fix (a Slice-B/C task, NOT just plan text): extend
`lifelineRecord` + `writeLifelineRecord`/`readLifelineRecord` +
`resolveLifelineCurrentName` to persist and resolve a **MAC-or-kernel-name
identity when no PCI address exists** (priority chain `pci → perm-mac →
kernel-name`, mirroring the device-map identity chain §3 A1). For a container
the kernel name is stable within the netns lifetime, which is the relevant
horizon. Without this fold the §7 fail-safe is bare-metal/VM-PCI only —
unacceptable for the container/non-PCI-VM cases the umbrella exists to serve.

**Lifeline override — repurposing the bootstrap NIC (AGY r2 catch 3,
FOLDED v3).** "Unconditionally protected" creates a new operational trap: a
bare-metal box that booted with a *temporary* DHCP default route on `eth0`
(e.g. PXE/network install) records `eth0` as the lifeline; if the operator
later wants `console-only` and to repurpose `eth0` as a dataplane/revenue
port, the unconditional protection blocks it and there is no CLI to clear
`/etc/xpf/lifeline-interface` (forcing manual root FS surgery). The
resolution: an explicit, auditable override leaf —
`set system management reachability console-only force-release-lifeline`
(or a dedicated `clear system management lifeline` operational command) —
that lets a *deliberate* operator action drop the boot-recorded lifeline from
protection. The default (no override) keeps the unconditional fail-safe; the
override is the escape valve, exactly analogous to #1922's OQ-D
`management-interface` fxp0-narrowing escape valve. This keeps the safe
default safe while not permanently welding the bootstrap NIC out of the
dataplane.

**Implementation note (Codex r2):** the existing #1922 fxp0-narrowing
exception (`narrowFxp0` in `protectedInterfacesWith`, `bootstrap.go:419-436`)
must NOT be applied against the boot-recorded lifeline contribution — the
lifeline is protected on its own merit regardless of the fxp0/mgmt-leaf
narrowing logic. The protected set is `boot-recorded lifeline UNION declared
mgmt contract`, with the lifeline removable ONLY by the explicit override
above.

**Residual guard (from #1956 §9.6):** make the console/delegate intent
explicit and auditable so a typo fails loudly; but safety no longer DEPENDS
on the operator getting the contract right — the boot-recorded lifeline is
the unconditional backstop.

---

## 8. Config grammar (umbrella, building on #1956)

Reuse #1956's `chassis device-map` stanza; add the `rename` axis and the
`kernel-name` key; add the two new `system` leaves.

```
# --- binding (generalizes #1956 device-map entry) ---
set chassis device-map interface ge-0/0/3 pci 0000:09:00.0          # bare metal (#1956)
set chassis device-map interface ge-0/0/3 mac 00:11:22:33:44:55     # fallback (#1956)
set chassis device-map interface lan0     kernel-name eth0          # NET-NEW: container key
set chassis device-map interface lan0     rename no                 # NET-NEW: alias axis
set chassis device-map unmapped-interface-policy leave-alone        # #1956

# --- profile + reachability (Slice C / §6, §7) ---
set system platform-profile auto                                    # NET-NEW
set system management reachability console-only                     # NET-NEW (generalizes #1922)
```

- The `rename` leaf defaults to `yes` when absent (backward-compatible with
  #1956 entries). `kernel-name` is mutually exclusive-ish with `pci` (a
  `kernel-name` key implies a non-PCI substrate; validation should warn if
  both a `pci` and a `kernel-name` are given for one entry).
- Validation reuses #1956's cross-entry collision checks (FATAL on two names
  → one NIC, or two NICs → one name). New checks: `rename no` REQUIRES the
  logical-name be a legal kernel name (no slash) for sub-mode (a) — else it
  is sub-mode (b) which is deferred (§5.2), so FATAL "logical-alias rename:no
  with a Junos-shaped name is not yet supported."
- `show chassis device-map` (from #1956) gains a `rename` and a
  `kernel-name`-resolved column; `show system platform-profile` surfaces the
  detected + effective profile + per-axis defaults.

---

## 9. Relationship to #1956 — what's delivered vs net-new

| Capability | #1956 delivers | Umbrella net-new |
|---|---|---|
| Binding primitive (identity-keyed name pin) | YES (pci/perm-mac) | kernel-name key |
| `unmapped-interface-policy leave-alone` | YES | reused as alias default |
| Console-as-lifeline, no auto-fxp0 (bare metal) | YES (§9.6) | generalized to a declared contract (§7) |
| Rename axis (`rename yes/no`) | NO (always rename) | **YES — alias-mode** |
| Non-PCI / veth discovery | NO (PCI-only) | **YES — alias enumerator** |
| Substrate detector | NO | **YES (extends `vmHeuristic`)** |
| `system platform-profile` | NO | **YES** |
| Declared reachability contract | partial (console for bare metal) | **YES (console/dhcp/delegate)** |

**Increment ordering (§0):** A (#1956) → B (alias-mode + non-PCI discovery +
reachability `delegate`) → C (detector + `platform-profile` defaults). Each
slice is independently committable and smoke-able. B depends on A's grammar +
resolver; C depends on A+B primitives but adds no new mechanism.

---

## 10. PLAN-KILL / scope-cut criteria + out-of-scope

**This stays an umbrella, not a monolith.** If reviewers find the slicing
unsound, the fallbacks:

- If alias-mode sub-mode (b) (logical Junos names on containers) is judged
  necessary for v1: **escalate** — it touches all 45 `LinuxIfName` callers and
  is a much larger change; do NOT fold it into Slice B silently.
- If the substrate detector is judged too magic / risky: **ship A + B with
  explicit operator selection only** (device-map present ⇒ bare metal;
  alias entries ⇒ container; neither ⇒ VM positional). `platform-profile`
  auto becomes a pure UX nicety deferrable indefinitely. The primitives work
  without it.
- **PLAN-KILL the whole umbrella only if** reviewers show the
  binding/configuration split is unsound — but #1956 already validates it for
  bare metal and #1922 already proves the config-independent lifeline, so
  this is unlikely.

**Explicitly out of scope (named, not silently dropped):**
- **HA in containers.** Slice B assumes containers are standalone (no RETH,
  no em0, no FPC slot math). `InterfaceSlot`/`SlotToNodeID` return no-slot
  for `eth0` and callers must tolerate it (§5.3) — but HA-on-container is a
  separate future umbrella.
- **Logical alias sub-mode (b)** — deferred (§5.2).
- **Runtime hot identity-change** — inherited #1956 deferral.
- **Per-substrate AF_XDP/native-XDP feasibility in containers** — veth
  AF_XDP support is a dataplane question orthogonal to binding; the binding
  model does not assume it.

---

## 11. Open questions for reviewers

- **OQ-1 (RESOLVED v2+v3):** the "`enumeratePCINICs` empty + veths" tell DOES
  false-positive on VMBus/XenBus VMs (AGY r1 Attack 3) AND `vmHeuristic` is
  x86-only so ARM64 VMs misclassify (AGY r2). Resolved by the VM-detection
  ladder `vmHeuristic` → `systemd-detect-virt` (bare, cross-arch) before the
  demoted PCI-empty hint (§6.2). Residual: confirm `systemd-detect-virt`
  exit-code/output on the actual target ARM64 + Hyper-V/Xen images at
  /engineer.
- **OQ-7 (NEW, resolved-in-plan):** the #1922 lifeline record is PCI-keyed
  and must be generalized to `pci → perm-mac → kernel-name` for the fail-safe
  to work on non-PCI substrates (§7 implementation gap). Sized as real
  Slice-B/C work, not a doc tweak.
- **OQ-2:** Should `rename no` live on the `chassis device-map` entry, or is
  a container binding conceptually different enough to warrant its own stanza
  (`set system interface-alias …`)? The doc recommends reusing device-map
  (one primitive) — challenge this.
- **OQ-3:** `delegate` vs `console-only` are behaviorally identical (xpf does
  nothing) — is the naming distinction worth two values, or collapse to one
  `external` value with a free-text note?
- **OQ-4:** Does any of the 45 `LinuxIfName` consumers assume Junos-shaped
  names in a way that breaks for a literal `eth0` config name beyond the
  slot-math sites already named (§5.3)? Reviewers should hunt for a counter-
  example that breaks the "sub-mode (a) is nearly free" claim.
- **OQ-5:** Slice ordering — is there a hidden dependency that forces C
  before B (e.g. the reconcile needing to know the profile to pick
  leave-alone)? The doc claims B sets leave-alone explicitly without C; verify.
- **OQ-6:** Container binding delivery — env var vs mounted file vs entrypoint
  writer. Which is the least-surprise for incus/docker/k8s operators, and
  does it interact with the configstore (candidate/active) cleanly given the
  binding must exist *before* the daemon reads config?
