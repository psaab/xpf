# #1956 — Bare-metal interface handling: device-map / managed-allowlist plan

RESEARCH-ONLY. Plan-of-action for manual approval. No code in this branch
beyond this doc + reviewer docs. Base: origin/master @ 62c1ddc66.

## 0. Status / TL;DR recommendation

**Recommendation: ship the narrow MVP first — a stable-identity managed
allowlist — not the full positional-replacement device-map.**

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
- **MVP scope:** an opt-in `set chassis device-map` stanza that (a) replaces
  positional enumeration for ONLY the named NICs and (b) flips the
  bring-down-unmanaged reconcile from "claim everything" to "claim only
  mapped + protected". Defer runtime-identity-change detection,
  auto-discovery/`show device-map candidates`, and PCI-topology-path keys to
  follow-ups.

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
`extractPCIAddr` (`linksetup.go:192`), `pciAddrForInterface`
(`bootstrap.go:347`), `resolveLifelineCurrentName` (`bootstrap.go:368`,
PCI-first then MAC fallback — exactly the resolution ladder the device-map
needs), and the durable record reader/writer (`bootstrap.go:250-304`).

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
Add an operational leaf in `pkg/cmdtree/tree.go` + a gRPC RPC; the resolver
reuses `pciAddrForInterface` / a generalized `resolveLifelineCurrentName`.

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
