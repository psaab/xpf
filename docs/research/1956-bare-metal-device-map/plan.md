# #1956 — Bare-metal interface handling: device-map / managed-allowlist plan

RESEARCH-ONLY. Plan-of-action for manual approval. No code in this branch
beyond this doc + reviewer docs. Base: origin/master @ 62c1ddc66.

**v3 (post-r2 review).** r1 reviewers both returned PLAN-NEEDS-MAJOR → v2
folded five first-order gaps (§13). r2 reviewers AGAIN returned
PLAN-NEEDS-MAJOR — v2 RESOLVED R-3/R-4/R-7 but they surfaced second-order
blockers visible only after the first-order ones closed: an HA peer-node
lockout via lenient SyncApply (AGY CRITICAL), an unvalidated commit-confirmed
rollback target (Codex), a current-boot udev/EEXIST window, and teardown
ordering. v3 folds all of them (§14). The honest takeaway: this is a
substantial multi-part feature, NOT a quick fix — exactly as the issue
predicted. Read §13 (first-order) then §14 (second-order) for the full
disposition; the section bodies below are updated in place.

## 0. Status / TL;DR recommendation

**Recommendation: implement the stable-identity managed allowlist as a
substantial multi-part feature (the §14 irreducible safe bundle) — NOT a
quick fix, NOT the full positional-replacement device-map.**

- **Primary identity key: PCI bus address (`DDDD:BB:DD.F`), with MAC as an
  explicit per-entry fallback, and an operator-overridable priority chain.**
  PCI address is what the box already trusts for the #1922 lifeline
  (`pkg/daemon/bootstrap.go:231`, keyed by PCI precisely because a
  name-keyed record goes stale the instant the rename runs). It is stable
  across reboots, unaffected by the RETH virtual-MAC alternation that makes
  MAC unreliable for member matching, and it does not move when an
  *unrelated* card is reseated (unlike kernel `enpXsY`, which renumbers).
- **Map vs allowlist: hybrid, but the allowlist semantics are the load-
  bearing half.** The crux for bare metal is "leave everything not named
  here ENTIRELY alone" (never renamed, never `always-down`). The explicit
  `host-nic → ge-name` binding falls out of the same stanza for free.
- **MVP scope (v2, the irreducible set — r1 proved these cannot be
  decoupled):** an opt-in `set chassis device-map` stanza that
  (a) replaces positional enumeration for ONLY the named NICs **on both the
  normal-boot AND bootstrap-exit rename paths**; (b) resolves identity with a
  **dedicated permanent-MAC fallback resolver (NOT the lifeline resolver,
  which stores the running MAC)** and **topology-change detection** that
  rejects an ambiguous/moved binding rather than silently misbinding;
  (c) **excludes RETH members from the MAC-fallback path** (they keep
  `OriginalName=` matching); (d) flips the bring-down-unmanaged reconcile to
  "claim only mapped + #1922-protected" with **explicit managed→unmapped
  stale-`.link` migration semantics** so a NIC moved to `leave-alone` is not
  silently un-renamed by `networkd.Apply`'s stale-file sweep; and (e) the
  `unmapped-interface-policy` knob. Defer runtime hot-identity-change
  detection, `show device-map candidates` (recommended to promote — §13),
  and PCI-topology-path keys to follow-ups.

The full "device-map replaces all positional naming everywhere" is NOT
warranted as a first cut — see §11 PLAN-KILL/scope-cut.

## 1. Problem restatement, grounded in code

`enumerateAndRenameInterfaces()` (`pkg/daemon/linksetup.go:49`) is the
bring-up hazard. On every non-bootstrap boot it:

1. Enumerates ALL PCI NICs via sysfs (`enumeratePCINICs`,
   `linksetup.go:137`), skipping only `lo` and non-PCI devices.
2. Sorts them virtio-first (`sortKey` 0/1) then lexicographically by PCI bus
   address (`linksetup.go:181-186`).
3. Assigns **purely positional** vSRX names (`assignName`,
   `linksetup.go:210`): idx0→`fxp0`; cluster idx1→`em0`, idx2+→
   `ge-{fpc}-0-{idx-2}` (fpc=7 for node1); standalone idx1+→`ge-0-0-{idx-1}`.
4. Writes a `.link` file per NIC (`writeLinkFile`, `linksetup.go:270`) keyed
   by `OriginalName=` (current kernel name) and renames immediately.

Then the dataplane compiler's reconcile
(`pkg/dataplane/compiler_iface.go:1132-1188`) enumerates every system
interface and, for any NIC not in the config and not in the daemon-owned /
#1922-protected set, marks it `Unmanaged: true`, strips its addresses, and
brings it down (`networkd.go:406-414`, `ActivationPolicy=always-down`).

**Two failure modes on real hardware** (issue body, confirmed in code):

- **F1 — positional naming is hardware-unstable.** The sort key is PCI bus
  address; adding a card, a BIOS update that renumbers buses, or onboard +
  add-in + BMC-shared-NIC ordering shifts the idx→name binding. `ge-0-0-3`
  silently becomes a different physical port. There is no durable
  port↔name pin today except the single #1922 lifeline record.
- **F2 — "claim everything + bring-down-unconfigured" is dangerous.** A
  real host has NICs xpf must not touch: BMC/IPMI shared-NIC, storage/
  cluster fabric, the admin's own mgmt path. Today all of them are renamed
  to `ge-*` and, if unconfigured, forced `always-down`
  (`compiler_iface.go:1166-1187`). #1922 protects exactly ONE lifeline NIC
  (`protectedInterfaces`, `bootstrap.go:408`), not the general case.

### 1.1 Correction to the issue framing (must be in the plan)

The issue body says idx1→`em0` unconditionally. The code only assigns `em0`
when `clusterMode` is true (`assignName`, `linksetup.go:214`); standalone
maps idx1→`ge-0-0-0` (`linksetup.go:220`, confirmed by the function doc
comment `linksetup.go:30-37` and CLAUDE.md standalone topology). This
matters: a bare-metal STANDALONE box has no `em0`, so the device-map must
not assume the cluster slot layout.

## 2. Current model — full map (cite-grounded)

| Concern | Where | Behavior today |
|---|---|---|
| NIC discovery | `linksetup.go:137` `enumeratePCINICs` | sysfs walk, virtio-first then PCI-addr sort |
| Name assignment | `linksetup.go:210` `assignName` | positional by enumeration index |
| `.link` write/match | `linksetup.go:270` `writeLinkFile`; `networkd.go:372` `generateLink` | `OriginalName=` for RETH members, `MACAddress=` otherwise |
| RETH member→reth | `set interfaces <if> gigether-options redundant-parent <reth>` → `Interface.RedundantParent`; bondless resolution `RethToPhysical` (`pkg/config/types.go`) | physical iface pinned to reth; local-node FPC preference |
| em0 cluster control | `chassis cluster control-interface` leaf; positional idx1 in cluster mode | name resolved positionally, address from HA state machine not interfaces tree |
| Bring-down-unmanaged | `compiler_iface.go:1132-1188` | every unconfigured non-daemon non-protected NIC → `Unmanaged`, addr-stripped, down |
| #1922 protected set | `bootstrap.go:408` `protectedInterfaces`; record `bootstrap.go:231` keyed by PCI | fxp0 + mgmt-leaf + lifeline NIC never stripped/downed |
| Bootstrap lifeline | `bootstrap.go:454` `setupBootstrapLifeline` | bootstrap mode renames ONLY the default-route NIC (if it would become fxp0); touches no other NIC |
| Mode selection | `daemon_run.go:256,336` | `computeBootClass` → bootstrap suppresses the full rename loop; normal runs `enumerateAndRenameInterfaces` |
| Externally-managed skip | `networkd.go` `findExternallyManaged` | unmanaged NICs that have a non-`10-xpf-` `.network` are left alone |

**Key existing identity infrastructure to reuse, not reinvent:**
`extractPCIAddr` (`linksetup.go:192`) and `pciAddrForInterface`
(`bootstrap.go:347`) for the PCI key, and the durable record reader/writer
pattern (`bootstrap.go:250-304`). NOTE (r1 Codex F2, see §13 R-3):
`resolveLifelineCurrentName` (`bootstrap.go:368`) matches the RUNNING MAC, so
its PCI-first-then-MAC ladder is the right SHAPE but its MAC leg must NOT be
reused verbatim — the device-map's MAC fallback needs a new permanent-MAC
(`PermHWAddr`) resolver to avoid binding RETH virtual MACs.

## 3. Identity-key options + failure modes

| Key | Stable across | Fragile to | Verdict |
|---|---|---|---|
| **PCI bus addr `DDDD:BB:DD.F`** | reboot, kernel-name renumber, RETH virtual-MAC flip, NIC firmware update | reslot of THIS card, BIOS bus renumber on topology change, SR-IOV VF reordering | **PRIMARY.** Already trusted by #1922 lifeline. |
| **MAC** | reslot, bus renumber | MAC spoof/clone, bonding shares a MAC, RETH virtual-MAC alternates (physical↔`02:bf:72:...`), some NICs change MAC on firmware | **Per-entry fallback only.** Must use the *permanent/factory* MAC (`getPermAddr`, `compiler.go:1610`) for RETH members, never the running MAC. |
| **PCI topology path** (`/devices/pci…/…` slot chain) | reslot of OTHER cards in the same chassis | moving the card to a different slot | Future: most robust against "added a card" but heaviest to express; defer (follow-up). |
| **Kernel name `enpXsY` / `eno1`** | nothing reliable on add-card | bus renumber, predictable-name scheme differences across distros/kernels | Reject as a key (it IS the thing that's unstable). Allowed only as a human-readable *hint* in `show`. |
| **driver+index** | — | any reorder | Reject. |

**Decision: priority chain `pci` → `mac` (permanent)**, with the matched
key recorded so `show` can warn when a binding resolved via the fallback
(indicates the PCI address moved — operator should re-pin). This mirrors
`resolveLifelineCurrentName`'s PCI-first-then-MAC ladder
(`bootstrap.go:382-392`) so we have ONE resolution discipline in the
codebase.

## 4. Map vs allowlist vs hybrid (the crux)

Three shapes considered:

- **A — explicit map only** (`pci 0000:09:00.0 → ge-0/0/3`). Solves F1
  (durable pin) but NOT F2 cleanly: what about NICs not in the map? If "down
  them" we still claim-everything; if "leave alone" we've smuggled in an
  allowlist anyway.
- **B — allowlist only** ("manage exactly these PCI addresses, leave the
  rest entirely alone"). Solves F2. Names still positional among the
  allowlisted set → F1 only half-solved.
- **C — hybrid (RECOMMENDED).** The map IS the allowlist: every entry binds
  one host NIC (by identity) to one xpf logical name. NICs with no entry are
  governed by a single explicit policy knob:
  `unmapped-interface-policy { leave-alone | manage-down }`, default
  **`leave-alone`** when a device-map is present. `leave-alone` = never
  renamed, never `always-down`, never address-stripped — invisible to xpf.

Hybrid C solves F1 (durable identity pin) and F2 (explicit "rest is
untouched") in one stanza and is the smallest grammar that does both.

## 5. Mode coexistence

Two modes, selected by **config presence** (no image-bake flag, no separate
mode leaf — least surprise, backward compatible):

- **Positional mode (default, unchanged):** no `chassis device-map` stanza →
  `enumerateAndRenameInterfaces` runs exactly as today. Every shipped
  appliance / VM / the loss cluster keeps working bit-identically. This is
  the zero-config controlled-topology path.
- **Device-map mode (opt-in):** a non-empty `chassis device-map` →
  `enumerateAndRenameInterfaces` branches to `enumerateAndRenameMapped`
  which (1) renames ONLY mapped NICs to their bound names, (2) writes
  `.link` files for ONLY those, (3) records the resolved identity, and (4)
  sets a flag consumed by the compiler reconcile so the bring-down loop
  honors `unmapped-interface-policy`.

Branch point: `daemon_run.go:336-360`. The `if d.inBootstrap()` arm is
unchanged (bootstrap lifeline still runs). The `else` arm gains:

```
if cfg has device-map {
    enumerateAndRenameMapped(deviceMap, clusterMode, nodeID, ...)
} else {
    enumerateAndRenameInterfaces(...)   // today's positional path
}
```

The compiler reconcile (`compiler_iface.go:1132`) gains a guard: when the
active config carries a device-map with `unmapped-interface-policy
leave-alone`, NICs that are neither mapped nor protected are SKIPPED from
the `Unmanaged` append entirely (not marked, not downed).

## 6. Interactions to preserve (each a gate)

### 6.1 #1922 mgmt-lifeline / protected-set
The protected set (`bootstrap.go:408`) MUST remain authoritative and
compose with — never be overridden by — the device-map. Concretely:
the mgmt lifeline NIC is protected even if the operator forgets to add it to
the device-map. The device-map and the protected set are UNIONed in the
"skip the bring-down" decision; an explicit map entry can NAME the mgmt NIC
(e.g. bind it to `fxp0`) but can never *remove* it from protection. The
chicken-and-egg (§7) is exactly why the lifeline is config-independent.

### 6.2 `.link` OriginalName matching + RETH MAC-alternation
Mapped RETH members must still match by `OriginalName=` (their PCI kernel
name), NOT `MACAddress=`, because the MAC alternates physical↔virtual
(`compiler_iface.go:836-843`, CLAUDE.md). The device-map's PCI key resolves
to the current kernel name at rename time; the written `.link` keeps
`OriginalName=` for member interfaces exactly as today. The device-map adds
a pin for WHICH physical NIC is the member; it does not change the `.link`
match-key discipline.

### 6.3 Cluster FPC naming (node1 = FPC 7)
The device-map is **per-node** (hardware differs between nodes). Two
sub-options (§9.3): per-node files, or one shared config with
`groups node0 { chassis device-map … }` / `node1 { … }` Junos apply-groups.
Either way the *resolved* `ge-{fpc}-0-{port}` name must still carry the
right FPC per node so RETH/`RethToPhysical` (`types.go`) and
`SlotToNodeID` keep working. The map binds identity→logical-name; the
operator writes `ge-7/0/2` on node1.

### 6.4 DHCP bootstrap fxp0 `.network`
`writeBootstrapFxp0Network` (`linksetup.go:299`) and the #1922
`writeBootstrapLifelineNetwork` (`bootstrap.go:529`) are untouched in
bootstrap mode. In device-map mode, if `fxp0` is a mapped entry, the same
bootstrap fxp0 `.network` is written for it.

### 6.5 Bring-down-unmanaged reconcile
Becomes policy-driven (§4 C / §5). `leave-alone` is the new bare-metal
default; `manage-down` reproduces today's behavior for operators who DO want
the firewall to own the whole box.

### 6.6 HA — both nodes resolve identically
Each node resolves its OWN local PCI/MAC identities against its OWN per-node
map section. The map content differs per node (different hardware) but the
RESULTING logical names (`ge-0/0/x` on node0, `ge-7/0/x` on node1) are the
cluster-consistent ones the rest of HA already expects. Validation (§8) must
reject a map that would resolve a reth member to a name whose FPC doesn't
match the node-id.

## 7. The chicken-and-egg / failure modes + validation

- **Map references a missing NIC:** commit-time → `commit-check` WARNS (not
  fatal) and the logical name is left unbound (no rename). Rationale: a
  per-node map shared across nodes legitimately references NICs absent on
  the other node; a hard fail would make shared configs impossible. Loud
  `show` diagnostic flags the unbound entry.
- **Two entries collide on one NIC (same PCI/MAC → two names):** commit-time
  FATAL (`SchemaValidate` cross-entry check). Unresolvable at runtime.
- **Two entries map two NICs to the SAME logical name:** FATAL.
- **Mapped NIC identity changes at runtime:** out of MVP scope (follow-up).
  MVP resolves identities once at daemon start (matches today's
  start-time-only `enumerateAndRenameInterfaces`).
- **Partial map (some host NICs unmapped):** governed by
  `unmapped-interface-policy` (operator-selectable, default `leave-alone`).
- **Chicken-and-egg — mgmt NIC must survive before the map applies:** solved
  by #1922 being config-independent and start-of-boot. The lifeline is
  recorded and the NIC protected BEFORE any device-map is read; the
  device-map can only ADD bindings, never strip protection (§6.1).
- **Empty/absent map:** positional mode (§5). Backward compatible.
- **Resolution via fallback key (PCI miss, MAC hit):** bind, but `show`
  warns "resolved via MAC fallback — PCI address moved, re-pin".

## 8. Config grammar

Junos-style, under `chassis` (sibling of `cluster`, so per-node
apply-groups compose):

```
set chassis device-map interface ge-0/0/3 pci 0000:09:00.0
set chassis device-map interface ge-0/0/3 mac 00:11:22:33:44:55   # fallback
set chassis device-map interface fxp0     pci 0000:05:00.0
set chassis device-map unmapped-interface-policy leave-alone       # default
set chassis device-map unmapped-interface-policy manage-down       # legacy claim-all
```

- New subtree in `schema_chassis.go` (`device-map` under `schemaChassis`).
  `interface <name>` is an instance-name slot (like `redundancy-group <id>`)
  with typed `pci` / `mac` value leaves (`valueType: ValueString` + PCI/MAC
  format validators in `schema_validators.go`). Follow the
  `docs/config-schema.md` add-a-leaf steps; the compiler MUST consume the
  leaf (a typed-but-ignored leaf is a documented anti-pattern).
- Typed struct: `Chassis.DeviceMap *DeviceMapConfig` with
  `Entries []DeviceMapEntry{LogicalName, PCIAddr, MAC}` +
  `UnmappedPolicy string`. Compiled in `compiler_chassis*.go`.
- Cross-entry validation (collision checks §7) lives in `SchemaValidate` /
  a `treeValidator` (it needs to see all entries, like the existing
  cross-reference validators noted in `docs/config-schema.md`).

**`show` surface:**
```
show chassis device-map
  Logical    Identity (key)        Resolved kernel   Status
  ge-0/0/3   pci 0000:09:00.0      enp9s0 → ge-0-0-3 bound
  ge-0/0/4   pci 0000:0a:00.0      —                 UNBOUND (no NIC at PCI addr)
  fxp0       pci 0000:05:00.0      enp5s0 → fxp0     bound (protected: lifeline)
```
Add an operational leaf in `pkg/cmdtree/tree.go` + a gRPC RPC. The resolver
reuses `pciAddrForInterface` for the PCI key but uses a NEW dedicated
permanent-MAC resolver (built on `getPermAddr`-style `PermHWAddr` reads), NOT
`resolveLifelineCurrentName` — that function matches the RUNNING MAC and would
mis-resolve RETH virtual MACs (r1 Codex F2). The `Status` column surfaces
`bound` / `UNBOUND` / `bound (via MAC fallback — PCI moved, re-pin)` /
`AMBIGUOUS (topology changed — refused)`.

## 9. Open design sub-questions (call out, don't pre-decide all)

- **9.1** Should `unmapped-interface-policy` default to `leave-alone`
  whenever a map exists (recommended) or require an explicit setting?
  Recommend default-leave-alone — safest for bare metal, and an operator who
  wrote a map clearly wants selective management.
- **9.2** Auto-discovery helper `show chassis device-map candidates`
  (list every PCI NIC + addr + MAC + current name to copy-paste into a map):
  high operator value, low risk, but defer to a fast-follow to keep the MVP
  small.
- **9.3** Per-node map distribution: per-node file vs shared-config
  apply-groups. Recommend apply-groups (`groups node0/node1`) since the
  config-sync machinery already quotes `${node}` and syncs one config.
- **9.4** Should the map also pin `em0`/fabric? Recommend yes (any logical
  name is bindable), but em0's ADDRESS still comes from the cluster stanza.
- **9.5** PCI-topology-path key (robust to reslot-of-others): defer to a
  follow-up; PCI-addr + MAC fallback covers the common bare-metal case.

## 10. Migration / rollout

- Existing appliances: no map → positional mode → bit-identical behavior.
  Zero migration required.
- Operator converts a box: run `show chassis device-map candidates` (9.2) →
  paste entries → `commit confirmed`. The protected lifeline guarantees the
  box stays reachable through the cut-over.
- Bake image: does NOT ship a default map (it has no per-box identities at
  bake time — `bake.py` wipes transient state and naming happens at runtime).
  Bare-metal device-map is a post-install operator action, documented in a
  new operator doc.
- HA: deploy the per-node map sections, commit on primary, config-sync
  carries it; each node resolves locally.

## 11. PLAN-KILL / scope-cut criteria

**Smallest viable version (THE MVP, recommended):**
1. `chassis device-map { interface <name> { pci/mac } unmapped-interface-policy }`
   grammar + typed struct + compiler + cross-entry validation.
2. `enumerateAndRenameMapped` branch in `daemon_run.go` (rename ONLY mapped
   NICs by resolved identity; positional path untouched when no map).
3. Compiler reconcile honors `unmapped-interface-policy leave-alone`
   (the F2 fix — the single most important behavior change).
4. `show chassis device-map`.

**Defer (follow-ups):** runtime identity-change detection; auto-discovery
`candidates`; PCI-topology-path key; `manage-down` partial nuance beyond the
binary policy.

**PLAN-KILL the FULL device-map (positional replacement everywhere) if:**
reviewers find the hybrid allowlist (items 1-4) already closes F1+F2 for the
real bare-metal threat model — in which case the "device-map replaces all
positional naming" framing is over-scoped and items 1-4 ARE the answer. The
MVP is deliberately the allowlist-with-pins, not a from-scratch naming
engine. If even the MVP grammar is judged premature, the absolute floor is
just item 3 (`unmapped-interface-policy` as a `system` leaf) which fixes the
*dangerous* half (F2) without any per-NIC pinning — but that leaves F1
(unstable names) unsolved, so it is the fallback floor, not the
recommendation.

## 12. Files this would touch (implementation preview, NOT in this branch)

- `pkg/config/schema_chassis.go` — `device-map` subtree.
- `pkg/config/types_chassis.go` — `DeviceMapConfig` / `DeviceMapEntry`.
- `pkg/config/compiler_chassis*.go` — compile + cross-entry validation.
- `pkg/config/schema_validators.go` — PCI/MAC format validators.
- `pkg/daemon/linksetup.go` — `enumerateAndRenameMapped`; reuse
  `extractPCIAddr`, share a PCI/MAC→current-name resolver with
  `bootstrap.go`.
- `pkg/daemon/daemon_run.go` — branch at the rename call site.
- `pkg/dataplane/compiler_iface.go` — `unmapped-interface-policy` guard in
  the bring-down loop (~`:1132-1188`).
- `pkg/cmdtree/tree.go` + gRPC — `show chassis device-map`.
- Docs: `docs/config-schema.md`, a new bare-metal operator doc, CLAUDE.md
  interface-management section.

## 13. r1 review convergence + v2 resolutions

Both companion reviewers returned **PLAN-NEEDS-MAJOR**; Claude SMR returned
PLAN-READY-with-minors. The MAJOR verdicts are well-founded — every finding
below was re-verified against code by the planner before folding (the two
load-bearing ones, F3 and F4, were read end-to-end at the cited lines). v2
adopts all of them; none are refuted.

### R-1 (Codex Critical F1 + SMR MINOR-2 + AGY HIGH-3): PCI BDF is not durable on slot/BIOS/VF change
PCI bus address survives a kernel netdev rename only when the PCI topology is
unchanged (`linksetup.go:150-167,192`). It does NOT survive slot migration,
BIOS bus renumber, PCI bridge add/remove, or SR-IOV VF re-creation
(`sriov_numvfs` reorders VF BDFs — directly relevant: the loss cluster
dataplane NICs are mlx5 VFs, CLAUDE.md).
**Resolution.** Keep PCI as the PRIMARY key (it is genuinely durable for
onboard/PF NICs, the dominant bare-metal target) but add **topology-change
detection**: on resolve, if the PCI key matches a NIC whose
permanent-MAC ALSO matches the entry's recorded MAC → bind (high confidence);
if PCI matches but MAC mismatches → **REFUSE the binding, leave the logical
name unbound, and log loudly** (a card was swapped into that slot — silent
hijack, AGY HIGH-3). If PCI misses but the permanent-MAC matches some NIC →
bind via fallback and flag "PCI moved, re-pin" in `show`. For VFs the operator
is steered to MAC-primary via an explicit per-entry key-order override
(`set chassis device-map interface ge-0/0/2 key mac`). The stability table
(§3) is corrected to say PCI is durable for PF/onboard, weaker for VFs.

### R-2 (Codex Critical F1 + AGY HIGH-2/Finding-2): stale `.link` files misbind before the daemon runs
systemd-udev applies `.link` `OriginalName=` matches at uevent time, BEFORE
xpfd runs (`linksetup.go:270`, `networkd.go:372`). A stale `.link` from a prior
topology can rename the wrong NIC before the device-map resolver gets control.
**Resolution.** In device-map mode the daemon MUST, at start (and on every
apply that touches the map): enumerate present NICs, resolve each map entry to
its CURRENT kernel name by PCI/perm-MAC, and **scrub-then-rewrite** every
`10-xpf-*.link` so the on-disk `.link` set exactly matches the resolved
bindings — no orphaned rename rules survive. This is an explicit MVP
deliverable, not prose.

### R-3 (Codex HIGH F2): the lifeline resolver matches the RUNNING MAC — do not reuse it for the MAC fallback
`lifelineRecord` stores `link.Attrs().HardwareAddr` (running MAC,
`bootstrap.go:357`) and `resolveLifelineCurrentName` matches the running MAC
(`bootstrap.go:387`). RETH members run the virtual MAC `02:bf:72:...` when the
daemon is up. A device-map MAC fallback built on this would bind the wrong
entry.
**Resolution.** The device-map MAC fallback uses the **permanent/factory MAC**
(`PermHWAddr`, the basis of `getPermAddr` at `compiler.go:1610`), via a NEW
resolver with explicit empty/duplicate handling (some NICs/VFs return no
`PermHWAddr` → that entry cannot use MAC fallback, flagged at commit). The plan
text that said "reuse the lifeline resolver" is wrong and is struck; the PCI
path still reuses `pciAddrForInterface`.

### R-4 (Codex HIGH F3, verified at daemon_run.go:1557): bootstrap-exit also runs the positional rename
`runBootstrapExitStartup` calls `enumerateAndRenameInterfaces` at
`daemon_run.go:1557` on the FIRST real commit — exactly when a device-map
first appears. v1 only branched the normal-boot site (`daemon_run.go:345`).
**Resolution.** BOTH call sites (`:345` and `:1557`) branch to
`enumerateAndRenameMapped` when the active config carries a device-map. This is
an explicit MVP deliverable. Without it, day-0 bare metal claims every NIC
positionally before the map ever applies.

### R-5 (Codex HIGH F4, verified at networkd.go:133-145): `leave-alone` is not just a compiler guard — `networkd.Apply` sweeps stale `10-xpf-*`
`networkd.Apply` globs `10-xpf-*` and `os.Remove`s any file not in `expected`
(`networkd.go:133-145`), then reloads. A NIC that WAS managed (has a `.link`)
and is later moved to `leave-alone` would have its `.link` removed → reload
un-renames it. "Never renamed/never touched" only holds for never-managed NICs.
**Resolution.** Define explicit **managed→unmapped migration semantics**: when
a previously-managed NIC transitions to `leave-alone`, the daemon performs a
one-shot controlled teardown (remove the `.link`, rename the kernel device back
to a stable predictable name, drop xpf `.network`) and thereafter leaves it
alone — rather than letting `Apply` half-clean it. The plan does NOT promise to
restore the operator's prior addressing on that NIC (it cannot know it); the
contract is "xpf stops managing it cleanly", documented for the operator.

### R-6 (Codex Medium F5): RETH members must stay on `OriginalName=`, excluded from MAC fallback
A RETH member's MAC alternates physical↔virtual; a MAC-fallback binding would
be non-deterministic and silently break HA.
**Resolution.** Device-map entries whose logical name resolves to a RETH member
(`RedundantParent` set / `redundant-ether-options`) are restricted to the PCI
key and keep `.link` `OriginalName=` matching exactly as today
(`compiler_iface.go:836-843`). Commit-check REJECTS a `key mac` override on a
RETH member.

### R-7 (Codex Medium F6 + AGY Medium-5): schema/compiler shape + empty-tree-non-nil
`compileChassis` returns early when there is no `cluster` node
(`compiler_system.go:879`) → a sibling `device-map` is silently dropped;
`schema_chassis.go`/`types_chassis.go` carry only `Cluster`; and an empty
`chassis device-map {}` block compiles to a non-nil `*DeviceMapConfig` (the
empty-tree-compiles-non-nil bug class #1922 hit, AGY Medium-5). Named-instance
identity tokens need `keyValueType/keyValidator`, not leaf `valueType`
(`docs/config-schema.md:116`).
**Resolution.** (a) `compileChassis` must compile the `device-map` subtree
INDEPENDENTLY of `cluster` (restructure the early-return). (b) Device-map mode
is selected on `len(Entries) > 0`, NOT `DeviceMap != nil` — an empty block is
treated as absent (positional mode), closing the silent-all-unconfigured trap.
(c) The `interface <name>` instance slot uses `keyValueType`/`keyValidator` per
the doc. All three are explicit MVP deliverables.

### R-8 (AGY CRITICAL Finding-1 + Codex Medium F7): the deferred-reboot lockout + failure-mode validators
AGY's headline: renames run only at boot/bootstrap-exit, but the compiler
reconcile runs on EVERY commit. An operator who edits/removes the map sees a
clean runtime commit (names don't change live) but a DIFFERENT, possibly
locked-out, interface layout on the NEXT reboot — and `commit confirmed`'s
rollback timer has long expired by then.
**Resolution.** Add a **commit-time pre-flight** for any commit that changes
the device-map: resolve the proposed map against CURRENTLY-present NICs and
**reject (or require an explicit `commit force`) any change that would, on next
boot, leave the management/lifeline NIC or any in-config revenue NIC unbound or
re-bound to a different port**. This converts the latent reboot-time lockout
into a commit-time error while the operator is still connected. Plus the
explicit validators Codex F7 lists: duplicate-PCI/duplicate-name → FATAL;
missing NIC → WARN + unbound (never silent positional fall-through);
RETH `key mac` → FATAL (R-6). The #1922 lifeline remains the independent
backstop (it runs config-independent, before any map — so even a bad map
cannot strand the recorded lifeline NIC).

### R-9 (SMR MINOR-1): policy resolution across empty/rolled-back/bootstrap-exit transients
On a rolled-back/empty active config, `unmapped-interface-policy` is absent.
**Resolution (decision):** the bring-down behavior on an absent device-map is
**positional `manage-down` (today's behavior)** — i.e. losing the map reverts
to claim-all, which is SAFE because (a) the #1922 protected set still shields
mgmt and (b) reverting to positional is the documented "no map = legacy mode"
contract. This is stated explicitly rather than left ambiguous. Combined with
R-8's commit pre-flight, an operator cannot accidentally roll back INTO a
claim-all that downs a revenue NIC they were reachable through without a
commit-time warning.

### Promoted from "defer" to MVP (SMR N2)
`show chassis device-map candidates` (enumerate every PCI NIC + addr +
perm-MAC + current name) is promoted into the MVP. It is cheap (reuses
`enumeratePCINICs`) and it is the operator's only safe way to author a correct
map; without it the "missing NIC" warning becomes the common case.

### Net effect on scope
The MVP is now the **six-part irreducible bundle** (§0 bullet (a)-(e) +
candidates helper + R-8 commit pre-flight). This is larger than v1's framing
but it is the smallest version that is actually SAFE — r1 proved the smaller
cut reproduces the hazard it set out to remove. The PLAN-KILL criterion (§11)
still stands: if reviewers judge even this bundle premature, the floor is the
F2-only fix (`unmapped-interface-policy` as a guard with NO per-NIC pinning),
accepting that F1 (unstable names) stays unsolved.

## 14. r2 review convergence + v3 resolutions

r2 (Codex + AGY, both **PLAN-NEEDS-MAJOR**) confirmed v2 RESOLVED R-3, R-4,
R-7, but surfaced second-order blockers that only became visible once v1's
first-order hazards were closed. All re-verified against code before folding.
v3 adopts all of them. (SMR r2 was PLAN-READY but did not catch the HA-sync
and rollback-target gaps — those are credited to the companions.)

### V-1 (AGY r2 CRITICAL — HA peer-node lockout via lenient SyncApply)
**Verified.** `SyncApply` and `Store.Load` use `compileTreeLenient` /
`CompileConfigForNodeLenient` (compiler.go:159-166, store.go:232,
freetext.go:28) which DOWNGRADE the strict commit-check to a warning. A
commit on node 0 (primary) can only validate node 0's LOCAL hardware (the
R-8 pre-flight queries local sysfs/PCI); it cannot see node 1's NICs, so it
must WARN-not-fail on node 1's section. config-sync then pushes the config to
node 1, whose `SyncApply` (lenient) persists the invalid map → node 1 takes a
deferred-reboot lockout OUTSIDE node 0's commit-confirmed window.
**Resolution (v3).** The pre-flight is **node-local on each node**:
(a) on the active node, the strict commit-check validates ONLY the local
node's resolved device-map section against local hardware; the peer's section
is intentionally NOT failed at commit (cannot be — different box).
(b) On the PASSIVE node, `SyncApply` gains a **device-map admission gate**:
after compiling the synced tree for its OWN node-id, it resolves its local
device-map section against its own present NICs and, if that would strand the
management/lifeline NIC on next boot, it **refuses the sync for the device-map
delta and raises a loud HA-health alarm** rather than silently persisting the
hazard. This is a NARROW exception to lenient-SyncApply, scoped to the exact
class (management-lockout) that lenient ingest must not swallow — analogous to
how #1922 makes the lifeline config-independent. The peer never silently
persists a map that would lock itself out.

### V-2 (Codex r2 STILL-OPEN R-2 + AGY r2 HIGH-3 — current-boot udev window + EEXIST deadlock)
**Verified.** udev applies `.link` rules at uevent time, before xpfd
(rename branch at daemon_run.go:336,345; `.link` matches `OriginalName=` at
linksetup.go:270). The daemon-start scrub only fixes the NEXT boot's disk
state; it does not undo a wrong LIVE rename udev already applied, and a stale
`.link` that renamed NIC-A to `ge-0-0-3` makes the daemon's attempt to rename
NIC-B to `ge-0-0-3` fail with EEXIST.
**Resolution (v3).** `enumerateAndRenameMapped` MUST implement a
**collision-safe multi-pass rename** at daemon start: (1) compute the desired
identity→logical-name binding; (2) detect any present interface whose CURRENT
name equals a desired name but whose identity does NOT match the binding (a
stale-udev misrename); (3) move every such conflicting interface to a unique
temporary name (`xpf-tmp-<n>`) FIRST, breaking the cycle; (4) then rename each
mapped NIC to its final name; (5) scrub+rewrite the `.link` set last so the
NEXT boot's udev is correct. This is the standard rename-cycle break and is
explicitly part of the MVP. The one-boot window is acknowledged and
CONTAINED: the daemon corrects the live state within its start sequence
(before dataplane arm / before the box forwards), and the protected lifeline
(#1922) shields management throughout. We do NOT claim zero live-misrename;
we claim the daemon deterministically converges and never deadlocks on EEXIST.

### V-3 (Codex r2 STILL-OPEN R-8 — rollback target unvalidated)
**Verified.** `executeConfirmedRollback` (daemon_apply.go:222) calls
`PromoteRollback` (store.go) and applies the PREVIOUS config directly under
applySem, WITHOUT re-running the strict commit-check. CLI has no `force` bit
(cli_config.go:176). So the R-8 candidate-only pre-flight does not see the
rollback target; a confirmed-commit timeout that reverts to an absent-map
(positional claim-all) config can silently down a revenue/mgmt NIC.
**Resolution (v3).** (a) At `commit confirmed` time, the pre-flight validates
BOTH the candidate AND the rollback target (the currently-active config that
will be restored on timeout) against present hardware — if EITHER would strand
mgmt on next boot, refuse/force-gate the commit while the operator is still
connected. (b) `executeConfirmedRollback` gains a device-map safety check: if
promoting the rollback target would transition device-map→positional-claim-all
and that would down a currently-up in-config NIC, it logs loudly and (matching
the #1922 first-commit-rollback precedent at daemon_apply.go:232) takes the
conservative path rather than blindly applying. The #1922 protected set
remains the backstop for mgmt specifically.

### V-4 (Codex r2 STILL-OPEN R-5 — teardown ordering vs networkd.Apply)
**Verified.** `networkd.Apply` sweeps stale `10-xpf-*` and reloads
(networkd.go:133-145,185); the compiler still appends unmanaged + strips +
downs (compiler_iface.go:1165,1172). v2 named the teardown but not its order.
**Resolution (v3).** Pin the order explicitly: in the apply path
(daemon_apply.go ~:624, under applySem) the managed→unmapped **teardown hook
runs BEFORE `d.networkd.Apply`** and is the single authority for the
transition — it (1) reads the "previously managed" state from the on-disk
`10-xpf-<name>.link` set (the durable record of what xpf renamed), (2) renames
the device back to its host-predictable name, (3) removes the xpf `.link`/
`.network` for it, so that by the time `networkd.Apply` runs, the interface is
already absent from both the desired set AND the on-disk xpf set — Apply's
sweep then has nothing to half-clean. The "previously managed" state source is
the `10-xpf-*.link` glob, NOT the (now-absent) config.

### V-5 (Codex r2 R-1 blocker — empty-PermHWAddr under PCI cross-check + missing `key` field)
**Verified.** `getPermAddr` returns "" when netlink lacks `PermHWAddr`
(compiler.go:1623). v2 said empty perm-MAC disables MAC fallback but not what
the PCI-primary cross-check does then; and the grammar/struct preview omitted
the `key` order field.
**Resolution (v3).** (a) When perm-MAC is empty (common on some VFs/virtio),
the PCI-primary cross-check **cannot verify identity**, so the binding is
PCI-ONLY and `show` marks it `bound (PCI-only, unverified — no permanent MAC)`;
a `key mac` override on such a NIC is REJECTED at commit (no key to match).
(b) The grammar/types gain the explicit key-order field:
`set chassis device-map interface <name> key [pci|mac|pci-then-mac|mac-then-pci]`
(default `pci-then-mac`), and `DeviceMapEntry` gains `KeyOrder string`. §8
grammar and the §12 types list are updated to include it.

### V-6 (AGY r2 MEDIUM — general FPC/node alignment, not just RETH + predictable-name discovery)
**Verified gap.** v2's FPC validation (R-6/§6.6) only covered RETH members; a
plain revenue/fabric interface mapped to a wrong-FPC name (`ge-7/0/3` on node
0) would pass and silently misattribute to the peer node. And R-5's "rename
back to a stable predictable name" did not say HOW the daemon learns that name.
**Resolution (v3).** (a) Generalize the FPC validator: in cluster mode EVERY
device-map logical name's FPC slot must align with the target node-id
(`SlotToNodeID`, types.go:55) — not just RETH members — else commit FATAL.
(b) The predictable-name teardown (V-4) discovers the host's name via the udev
database (`udevadm info` / `ID_NET_NAME_PATH` / `ID_NET_NAME_ONBOARD` under
`/run/udev/data/`), NOT a hand-computed pattern, so it matches the host's own
naming policy. If discovery fails, leave the device under its current xpf name
but drop xpf management of it (do not guess a name that could collide).

### Net effect on scope (v3)
The MVP bundle grows to the irreducible safe set:
device-map grammar (+`key` order) → independent compile + `len(Entries)>0`
mode → dedicated perm-MAC resolver with empty-MAC PCI-only handling →
topology-change REFUSE → collision-safe multi-pass rename (V-2) → branch both
rename sites → managed→unmapped teardown ordered before networkd.Apply (V-4) →
node-local pre-flight that also validates the rollback target (V-3) + a
passive-node SyncApply admission gate (V-1) → generalized FPC/node validation
(V-6) → `show device-map [candidates]`. This is a substantial feature, not a
quick fix — consistent with the issue's "deserves a thorough pass, not a quick
fix" framing. The PLAN-KILL floor (§11) is unchanged: if even this is judged
too large, ship ONLY the `unmapped-interface-policy` guard (F2 fix) and accept
that F1 + the HA/rollback edges stay unsolved.

## 15. r3 review convergence + open implementation-strategy decisions

After r3, the three reviewers converge on the DESIGN being sound; the residual
items are implementation-strategy choices, not architectural defects:

- **Claude SMR r3: PLAN-READY** (re-verified the HA-sync + rollback gaps it
  missed in r2; confirms v3 closes them).
- **Codex r3 companion: PLAN-NEEDS-MINOR**, per-finding text grades the v3
  designs "directionally sound" and anchored to real code sites. (The Codex
  agent-wrapper re-graded to MAJOR by applying an IMPLEMENTATION rubric —
  "the code isn't written yet" — to a research-only plan; that is a category
  error for a /research plan-review and is recorded but not adopted. See
  codex-plan-r3.md methodology note.)
- **AGY r3: PLAN-NEEDS-MAJOR**, but the three findings are framed as
  "Decision Needed" implementation-strategy tradeoffs, not new architectural
  defects. They are captured below as OQs to resolve at /engineer time.

These do NOT trip the §11 PLAN-KILL criteria (architecture wrong / identity
key fragile / breaks the #1922 lifeline). The plan is therefore PLAN-READY
with the following explicit open implementation-strategy decisions to settle
in the first implementation increment (and re-review there):

### OQ-15.1 (AGY r3 #1) — HA device-map validation: passive-gate vs distributed pre-commit
v3's V-1 passive-node admission gate prevents the peer persisting a self-
lockout map, but AGY notes it can cause node0/node1 config DIVERGENCE (the
peer holds a different effective map; a later peer commit pushes its config
back). **Two implementable options, decide at /engineer:**
(a) **passive gate + health alarm** (v3 as written): simplest, but the peer's
local section is effectively quarantined until fixed — divergence is surfaced
loudly, not silent.
(b) **distributed pre-commit validation**: `commit check` on the active node
RPCs the peer to validate the peer's device-map section against the peer's
local hardware before promoting — keeps both stores identical and safe, at the
cost of a new cross-node commit-time RPC and a peer-unreachable fallback
policy. **Recommendation: (b) is the cleaner end state** (no divergence), but
(a) is an acceptable first increment if the cross-node RPC is deferred —
provided the divergence is alarmed, never silent. The cluster config-sync
machinery (`daemon_ha_sync.go`) already has a peer channel to build (b) on.

### OQ-15.2 (AGY r3 #2) — rollback split-brain: validate-at-commit-confirmed, apply-unconditionally
AGY notes that if `executeConfirmedRollback` (daemon_apply.go:222) ABORTS the
rollback apply for safety, the store (already promoted by `PromoteRollback`)
diverges from the running dataplane → split-brain. **Decision (adopt AGY's own
recommendation): do NOT abort at rollback time.** Instead validate the
rollback target at `commit confirmed` time (v3 V-3(a) already requires this),
so that by the time a timeout fires the target is KNOWN-safe and is applied
UNCONDITIONALLY — no rollback-time abort, no split-brain. The v3 V-3(b)
"conservative branch in executeConfirmedRollback" is therefore narrowed to: it
fires ONLY for the pre-existing #1922 first-commit-rollback case
(prevCfg==nil, daemon_apply.go:232) which already has a defined non-apply
path; for a non-nil validated rollback target it applies unconditionally.
This supersedes the looser V-3(b) wording.

### OQ-15.3 (AGY r3 #3) — temp-rename stranding of unmapped NICs
v3's V-2 multi-pass rename moves a name-conflicting NIC to `xpf-tmp-<n>`; AGY
notes an unmapped NIC left at `xpf-tmp-0` could later confuse the V-4 teardown
name-matching (which keys off the `.link` set). **Decision:** the multi-pass
rename phase MUST, in the SAME pass, rename any temp-stranded NIC that is
unmapped/leave-alone back to its host-predictable name (via the OQ V-6 udev-db
discovery) rather than leaving it as `xpf-tmp-*`. The "previously managed"
state source for teardown (V-4) is the `10-xpf-*.link` glob, and a leave-alone
NIC must have its `.link` removed in this same pass so it is never matched as
"managed". This tightens V-2+V-4 into a single coherent rename/teardown pass.

### Convergence statement
The architecture (hybrid stable-identity managed allowlist; PCI-primary +
permanent-MAC fallback; opt-in stanza; `leave-alone` default flipping the
dangerous bring-down) is endorsed by all three reviewers across three rounds.
The identity key is durable for the primary target (PF/onboard NICs) with
loud, explicit handling of the cases it is not (VFs, slot swaps, empty
perm-MAC). The #1922 lifeline composition is preserved and EXTENDED to the
HA-sync and rollback paths. The three open items above are implementation
sequencing/strategy choices with recommended resolutions, to be locked and
re-reviewed in the first /engineer increment. **PLAN-READY.**
