# #1958 — Substrate-agnostic interface binding + bootstrap-reachability contract

RESEARCH-ONLY. Architecture proposal for manual approval. No code in this
branch beyond this doc + reviewer docs. Base: origin/master @ 5d452736e.

This is the **umbrella / architecture-level** generalization. **#1956 is its
bare-metal increment** — its v3 plan (`research/1956-bare-metal-device-map`)
is treated as settled foundation here, NOT re-derived. Read #1956 §0-§11
first; this doc builds the cross-substrate model on top of it and pins only
the net-new pieces (container alias-mode, substrate detector,
`platform-profile`, the generalized reachability contract).

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
- **Risk caveat (must verify at /engineer):** some consumers may assume the
  *Junos* name shape (`ge-N/0/N`) for slot/FPC math — e.g. `InterfaceSlot`
  (`types.go:35`), `SlotToNodeID` (`types.go:55`), RSS indirection's mlx5
  filter (`rss_indirection.go`). A container interface named `eth0` returns
  `InterfaceSlot=-1`, which the callers must treat gracefully (no FPC ⇒ no
  cluster slot ⇒ standalone). Auditing these "-1 / no-slot" branches is a
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

1. **Container (highest priority — most specific):**
   - `/.dockerenv` exists (Docker), OR
   - `/run/.containerenv` exists (Podman), OR
   - `systemd-detect-virt --container --quiet` exits 0 (catches
     lxc/incus-container/systemd-nspawn), OR
   - cgroup-v2 hint + **no PCI NICs at all** (`enumeratePCINICs` returns
     empty) while `/sys/class/net` has non-`lo` entries. The "PCI-empty but
     veths present" signal is the strongest container tell and the one that
     directly explains the "manages nothing" bug.
2. **VM:** `vmHeuristic` non-empty (`/sys/hypervisor/type`, cpuinfo
   hypervisor flag) — reuse verbatim.
3. **Bare metal:** none of the above → physical DMI. Optionally corroborate
   with `/sys/class/dmi/id/sys_vendor` + `product_name` (e.g. not "QEMU"/
   "KVM"/"VMware"/"Bochs"), but the default-by-elimination is sufficient.

**Priority rationale:** container detection MUST outrank VM detection,
because an incus/kvm-backed *VM* and an incus *container* both can show a
hypervisor-ish ancestry; the container-specific signals (`/.dockerenv`,
`detect-virt --container`, PCI-empty+veths) are unambiguous and must win.
`systemd-detect-virt` semantics: `--container` reports only container techs;
bare `systemd-detect-virt` reports VM techs first and falls through to
container — so call `--container` explicitly for the container test and the
bare form (or `vmHeuristic`) for the VM test, never conflate them.

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

- **`console-only`:** no fabricated fxp0, no bootstrap DHCP, empty protected
  set is valid (the console is the lifeline). Already the #1956 §9.6 model;
  the daemon must tolerate zero mgmt NICs (it already does on the
  no-default-route path, `bootstrap.go:455-461`).
- **`dhcp interface <if>`:** today's behavior, made explicit. The lifeline is
  the named NIC; #1922 protects it and snapshots its addressing.
- **`delegate`:** xpf keeps hands off the management plane entirely — the
  orchestrator's `exec` is the lifeline. No fxp0, no DHCP, no bring-down.
  Equivalent to `console-only` from xpf's perspective (do-nothing), but named
  distinctly so `show` and audit make the operator intent explicit.

**#1922 generalization:** SAFE-BOOTSTRAP's "lifeline" becomes
*profile-driven*, not `fxp0`-hardcoded. `defaultMgmtInterface = "fxp0"`
(`bootstrap.go:32`) stops being an unconditional default and becomes the
`dhcp`-reachability default only. The protected set is whatever the
`management` stanza declares (or empty for console/delegate). The
commit-confirmed rollback + protected-set machinery is unchanged — it just
takes its lifeline from the contract instead of a constant. **Safety guard
(from #1956 §9.6):** an empty protected set is only safe when access truly is
console/delegate; if an operator declares `console-only` but actually reaches
the box over a data NIC via SSH, they lose the box on a bad commit. The rule:
*protect the explicitly-declared mgmt NIC(s), or none — never auto-fabricate
fxp0; make the console/delegate intent explicit and auditable so a typo
fails loudly.*

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

- **OQ-1:** Is the container discovery signal "`enumeratePCINICs` empty +
  non-lo veths present" robust enough as the primary container tell, or does
  it false-positive on a diskless/PCI-less appliance? (Mitigant: it only
  *defaults* the profile; explicit `platform-profile` overrides.)
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
