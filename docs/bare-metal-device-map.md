# Bare-metal interface device-map (#1956)

xpf's default interface handling is **positional**: at startup it enumerates
every PCI NIC, sorts virtio-first then by PCI bus address, and assigns vSRX
names by enumeration index (`fxp0`, `em0`, `ge-{fpc}-0-{n}`). Unconfigured
NICs are renamed and brought down. That is correct for the appliance image and
controlled-topology VMs, but it is hazardous on real bare metal:

- **Unstable naming** — adding a card, a BIOS bus renumber, or onboard +
  add-in + BMC-NIC ordering shifts the index→name binding, so `ge-0/0/3`
  silently becomes a different physical port. (Since #4178 the positional
  rename is at least collision-safe — an enumeration shift no longer
  corrupts the `.link` `OriginalName=` chain via `breakNameCollisions`,
  the same phase-1 discipline device-map mode uses — but the index→name
  binding still MOVES on a hardware change. Only the device-map pins it.
  Since #7205 the positional pass also reads the LIVE names back after the
  reload and reports any NIC not wearing its intended name; that catches a
  rename which reported success and did not take effect, but it cannot
  catch the wrong NIC wearing the right name, because in positional mode
  the index IS the identity. The device-map's permanent-MAC check is the
  only thing that closes that.)
- **Claims everything** — a real host has NICs xpf must not touch: a
  BMC/IPMI shared NIC, a storage/cluster fabric, the admin's own management
  path. Positional mode renames them all and, if unconfigured, forces them
  `always-down`.

The **device-map** is an opt-in stanza that fixes both: it binds each xpf
logical name to a NIC by **stable identity** (PCI bus address, with a
permanent-MAC fallback), and leaves everything not named entirely alone.

## Quick start (console / IPMI session)

On bare metal you are on the **console** (serial / IPMI SoL / local KVM).
xpf does NOT fabricate an `fxp0` or grab a NIC for DHCP in device-map mode —
the console is your lifeline.

1. List the NICs (no PCI-address archaeology required):

   ```
   > show chassis device-map candidates
   PCI address      Permanent MAC      Current name   Link
   -----------      -------------      ------------   ----
   0000:05:00.0     a0:36:9f:00:11:22  eno1           up
   0000:09:00.0     a0:36:9f:00:11:30  enp9s0         up
   0000:0a:00.0     a0:36:9f:00:11:31  enp10s0        down
   0000:0b:00.0     (unknown)          enp11s0        unknown

   `(none)` in the Permanent MAC column means the hardware reported no
   permanent MAC; `(unknown)` means its identity could not be read, so a `mac`
   pin for it cannot be verified and would be refused (#6786).

   Example:
     set chassis device-map interface ge-0/0/3 pci 0000:05:00.0
     set chassis device-map unmapped-interface-policy leave-alone
   ```

2. Author the map (copy-paste the PCI addresses):

   ```
   set chassis device-map interface ge-0/0/3 pci 0000:09:00.0
   set chassis device-map interface ge-0/0/4 pci 0000:0a:00.0
   set chassis device-map unmapped-interface-policy leave-alone
   ```

   `leave-alone` (the default when a map exists) means every NIC NOT named
   above — your BMC NIC, storage fabric, etc. — is never renamed, never
   brought down, never touched.

3. Commit with the safety timer, then confirm from a still-reachable session:

   ```
   commit confirmed 5
   ... verify reachability + forwarding ...
   commit              # confirms the pending commit-confirmed
   ```

   Confirm with a plain **`commit`** (Junos semantics: any subsequent
   explicit `commit` confirms a pending `commit confirmed` —
   `pkg/configstore/store_commit.go:106-120`). Do **not** rely on `commit
   check` — it only VALIDATES the candidate and never touches the confirm
   timer (`CommitCheck`, `store_commit.go:26-41`), so the window still
   expires and the daemon auto-rolls-back the just-verified device-map at
   T+5m.

4. Verify the resolved bindings:

   ```
   > show chassis device-map
   Device-map (unmapped-interface-policy: leave-alone):

   Logical      Identity (key)           Resolved kernel   Status
   -------      --------------           ---------------   ------
   ge-0/0/3     0000:09:00.0             enp9s0→ge-0-0-3   bound
   ge-0/0/4     0000:0a:00.0             enp10s0→ge-0-0-4  bound
   ```

The renames take effect at next boot (and persist deterministically via the
written `.link` files). The bring-down reconcile honors `leave-alone`
immediately on commit.

## Identity keys

| Key | Stable across | Use |
|-----|---------------|-----|
| `pci <DDDD:BB:DD.F>` | reboot, kernel-name renumber, RETH virtual-MAC flip, firmware update | **Primary.** Durable for onboard/PF NICs. |
| `mac <xx:xx:xx:xx:xx:xx>` | reslot, bus renumber | **Fallback.** Compared against the *permanent* MAC, never the running MAC. |
| `key <pci-then-mac\|mac-then-pci\|pci\|mac>` | — | Resolution order. Default `pci-then-mac`. |

- **Topology-change refusal.** If the PCI address matches but the present
  NIC's permanent MAC differs from the entry's `mac`, the binding is
  **REFUSED** (a card was swapped into that slot) rather than silently
  hijacking the wrong NIC. Re-pin the entry.
- **PCI moved.** If the PCI address misses but the permanent MAC hits, xpf
  binds via the MAC fallback and flags it in `show` (`bound (via MAC
  fallback — PCI moved, re-pin)`).
- **No permanent MAC** (common on some VFs/virtio): the entry binds PCI-only
  and `show` marks it `(PCI-only, unverified)`; `key mac` is rejected. This is a
  POSITIVE fact — the read succeeded and the hardware reported no permanent-MAC
  attribute — and is distinct from the case below.
- **Unreadable-identity refusal (#6786).** If the NIC at the pinned PCI address
  is present but its identity could not be READ (the per-NIC netlink query
  failed), its permanent MAC is **UNKNOWN**, not absent. An entry that pins a
  `mac` is **REFUSED** — `REFUSED (identity unreadable — cannot verify pinned
  MAC)` — rather than binding it unverified.

  Before this, the enumerator discarded that read error, leaving an empty
  permanent MAC: the same value MAC-less hardware produces. The topology-change
  refusal above is conditioned on the permanent MAC being non-empty, so a failed
  read did not merely lose information — it silently **disabled the card-swap
  check** and downgraded the entry to `bound (PCI-only, unverified)`, whose own
  wording asserts "this hardware has no permanent MAC". A card swapped into the
  pinned slot could then be renamed into the logical name — and the security
  zone — the `mac` pin existed to keep it out of.

  The remedy is the OPPOSITE of the topology-change one, so it is reported
  separately: **retry once the interface is readable**. Nothing is known to be
  wrong with the card, and re-pinning would have you pin against a MAC you
  cannot currently read.

  The refusal is deliberately **narrow — it applies only to entries that pin a
  `mac`.** An entry keyed on PCI alone is unaffected: its identity is the PCI
  address, which comes from sysfs and was read successfully, so the failed
  netlink read cost it nothing it asked for. Widening it to every unreadable NIC
  would let one transient netlink failure refuse every mapped interface on the
  box, management included.

  `show chassis device-map candidates` distinguishes the two states in the
  **Permanent MAC** column: `(none)` means the hardware reported none, while
  `(unknown)` means the read failed. The **Link** column likewise shows
  `unknown` rather than `down`, so an unreadable NIC does not send you hunting a
  cabling fault that does not exist.
- **Non-PCI physical NICs** (USB / platform / SoC ethernet) have no PCI
  address but do carry a factory MAC. They are enumerated (with an empty PCI
  column) so a `key mac` entry binds them; only purely virtual netdevs
  (loopback, bridge, veth, bond, vlan, vrf, tun/tap) are excluded from the
  inventory. Map such a NIC with `key mac` (`pci` is unavailable).
- **RETH members are PCI-only.** A RETH member's MAC alternates
  physical↔virtual, so its entry must be PCI-keyed (`key mac` is rejected at
  commit). It keeps `.link` `OriginalName=` matching as before.
- **Duplicate-logical-name refusal (#6546).** Two entries claiming ONE logical
  name are **REFUSED — both of them**, and `show` marks each `REFUSED (logical
  name claimed by more than one device-map entry)`. Binding either would rename
  a nondeterministically-chosen NIC to that name and persist the choice in a
  `.link` file, so the same config could bind differently across boots — on
  bare metal that can strand management or place a NIC in the wrong zone. The
  resolver already refused the mirror-image case (two entries landing on ONE
  NIC); this is the missing symmetric guard, in the same post-pass.

  It is a **distinct** status from the topology-change refusal because the
  remedy is the opposite one: nothing is wrong with the hardware and re-pinning
  an identity fixes nothing — the map has two entries claiming one interface
  name and one of them must go.

  The refusal counts on the **resolved Linux name**, not the raw spelling. The
  Junos slash form and the kernel dash form are two spellings of one interface
  (`ge-0/0/3` and `ge-0-0-3` both resolve to `ge-0-0-3`), and the strict commit
  gate's raw-string comparison accepted that pair — so the duplicate was
  reachable on the STRICT commit path, not only on the tolerant load /
  peer-sync path where the gate is downgraded to a warning.
  `validateDeviceMapStrict` now canonicalises before comparing and names both
  spellings in its error. Only BOUND entries are counted: a duplicate whose
  second entry matches no present NIC is unambiguous and still binds.

### `OriginalName=` must be a name udev will present (#6678)

Each mapped NIC's `.link` records `OriginalName=` — the NIC's **pre-rename
kernel name** — so systemd can find it again on the next boot and re-apply the
logical name. That key is load-bearing for RETH members in particular: their MAC
alternates between physical (at boot) and virtual (once the daemon programs the
RETH virtual MAC), so `MACAddress=` is unreliable for them and `OriginalName=`
is the only stable match.

xpf derives that name in one of three ways, in order:

1. an existing `.link` chain already records the true original — use it;
2. the NIC still wears its own kernel name (`current != logical`, a fresh first
   map) — that name **is** the original;
3. the NIC already wears its logical name and its `.link` was lost — derive the
   kernel name from sysfs.

If (3) comes back empty, xpf **declines to write a `.link` at all** and reports
it as a rename/reload failure. It does **not** fall back to the NIC's current
name, because in that branch the current name IS the logical name, which udev
will never present — the resulting `.link` could not match, so boot-time
persistence would fail *silently*: the file exists, the name looks plausible,
and nothing matches on the next boot.

Leaving the NIC under its kernel name is the better failure. It is a state the
rest of the daemon already understands and reports, and it surfaces at apply
time rather than hours later on a machine nobody is watching.

## `unmapped-interface-policy`

- **`leave-alone` (default in device-map mode):** NICs with no entry are
  invisible to xpf — never renamed, never `always-down`, never
  address-stripped. This is the bare-metal-safe default.
- **`manage-down`:** reproduces today's claim-all behavior (bring
  unconfigured NICs down). Choose this only if you want xpf to own the whole
  box.

The #1922 management lifeline / protected set is always honored regardless of
the policy — an explicit map can NAME the management NIC but can never remove
it from protection.

### Managed→unmapped teardown (fail-closed, #5309)

When a NIC is REMOVED from the device-map under `leave-alone`, the daemon must
hand it back to the host: it renames the live interface from its xpf logical
name back to the host-predictable name and drops the durable
`10-xpf-<name>.link` / `.network` markers (the record that xpf renamed it), so
by the time `networkd` reconciles the NIC is absent from both the desired set
and the on-disk xpf set.

This teardown is **fail-closed and retains the retry debt on failure**:

- The rename-back is attempted **first**. Only when it **succeeds** (or when no
  live device is still wearing the xpf name — an already-torn-down, idempotent
  no-op) are the durable `.link`/`.network` markers reclaimed.
- If the rename-back **fails** (e.g. `EBUSY` / a name collision), or no
  host-predictable name can be resolved for a device still wearing the xpf
  name, or the `networkctl reload` fails, the durable markers are **RETAINED**
  and the error is surfaced. Deleting the markers on a failed rename-back would
  leave the live interface under the wrong name (stale host routing ownership)
  **and destroy the retry debt** — the markers are the only record that the
  next commit must retry the teardown. Retaining them lets the next `commit`
  converge instead of silently stranding the NIC.
- A genuine teardown failure now **fails the commit closed**: the error is
  aggregated into the commit-error join (alongside the networkd-apply and other
  interface-management errors) rather than being logged and swallowed. The
  operator sees the commit fail, the durable state is intact, and re-running
  `commit` (after clearing the collision) completes the teardown.

A benign no-op — every on-disk `.link` still desired, or the NIC already renamed
back — never triggers a spurious commit failure or a `networkctl reload`. Only a
GENUINE rename-back / reload failure retains-and-errors. This mirrors the #4956
startup rename/reload aggregation and the #4901 retain-on-failed-delete
discipline.

### A collision phase 1 could not break (#7205)

`breakNameCollisions` is phase 1 of the shared two-pass rename, used by BOTH
device-map and positional naming. It moves any NIC that currently wears a
desired final name — but is not that name's intended occupant — to a temporary
`xpf-tmp-N` name, so phase 2 always finds its target free.

If one of those temp renames **fails**, that NIC keeps occupying a desired final
name and phase 2's premise ("collisions are already broken, so no EEXIST here")
no longer holds for that one name. Since #7205 phase 2 **declines** the rename
onto that name and reports:

```
device-map: cannot rename enp9s0 -> ge-0-0-3: the collision break could not free
"ge-0-0-3" (its current occupant failed to temp-rename), so this rename would
EEXIST and phase 2's no-collision premise does not hold for this name (#7205)
```

Before this the rename was attempted and the resulting `EEXIST` was reported —
loud, but pointing at the wrong thing. An operator reading it went looking at
udev or the `.link` file rather than at the collision break that did not happen.

**It is not a rollback.** Un-renaming the NICs that phase 1 moved successfully
would leave the box in a third state neither phase understands. The pass
finishes and reports per name, the same discipline phase 2 itself uses.

Other names are unaffected — only the specific name that could not be freed is
declined.

## Safety: commit pre-flight & rollback

A commit that changes the device-map runs a **node-local pre-flight** against
the present hardware while you are still connected:

- A `REFUSED` entry is rejected, for ANY reason — topology-changed, a logical
  name claimed by more than one entry (#6546), or an identity that could not be
  read (#6786). Each carries a different remedy, so the pre-flight reports them
  separately: "re-pin the entry" for a card swap, "remove the duplicate entry"
  for a duplicate name, and "retry once the interface is readable" for an
  unreadable identity. The check tests `BindStatus.Refused()` rather than one
  sentinel value, so a future refusal reason cannot slip past this hard stop and
  be treated as a clean result.

  Commit is the cheapest place for this to fail: you are still connected,
  nothing on the box has been mutated, and the boot-time re-check (#5490) runs
  the same detector again before any rename, retaining the current interface
  naming if it trips. A refusal therefore never renames a NIC and never writes a
  `.link` file — which matters because a `.link` is durable and udev replays it
  on every subsequent boot, so a mis-binding written during a transient failure
  would outlive the failure itself.
- A map that would move the live management NIC's name onto a different port
  (or steal the management name) is rejected.
- `commit confirmed` validates BOTH the candidate AND the rollback target
  (the config restored on timeout), so a confirmed-commit timeout reverts to
  a known-safe config and applies it unconditionally (no split-brain).
  "Known-safe" is device-map safety here; since #6707 the same pre-flight also
  requires the rollback target to be APPLIABLE (its policy snapshot must not
  carry the #5575 lenient-content poison, which the dataplane refuses whole).
  Both are arm-time decisions for the same reason: the timeout path cannot
  abort without diverging the already-promoted store from the dataplane.
- **The pre-flight fails CLOSED on an unreadable NIC inventory (#5490).** If
  the present-NIC scan (a cold-path sysfs/netlink read) fails, the commit is
  **rejected** — the strand-management safety check cannot run, so the commit
  is refused rather than accepted unvalidated. (Earlier this was a
  skip-with-warning that silently accepted the commit; a candidate that moved
  the live management NIC to a non-management name was then applied verbatim at
  next boot — a durable lockout the confirmed-commit rollback could not undo,
  because its rollback target was never validated either.) Re-commit once the
  hardware inventory is readable. The #1922 lifeline guards the *live* mgmt NIC
  but does not veto an explicit mapped rename, so it is not a substitute for
  this gate. The same fail-closed applies to `bootstrapFromFile`: an unreadable
  inventory leaves the daemon in the lifeline-safe bootstrap state (console +
  fxp0 DHCP) rather than committing an unvalidated map — strictly safer than
  coming up with an unchecked device-map.

The **boot-time mapped rename re-runs the strand detector (#5490)**: before
`enumerateAndRenameMapped` applies any mapped rename it re-validates the active
map against the present hardware and, if the map would strand management,
**refuses to rename** (retaining the current interface naming so management
stays reachable) and logs loudly. This is the backstop for a candidate that was
already committed to the store before this gate existed (or accepted under the
old fail-open commit path): the unsafe binding is caught at the boot where it
would first be applied, not after it has locked the operator out.

The SAME pre-flight now runs on the **day-0 / bootstrap paths** (#4183):

- `xpfd check-config <file>` runs the strand pre-flight after the strict
  parse/schema/compile gate. **On the target hardware** (the mapped NICs are
  present) it **hard-FAILs** (exit 2) a device-map that would strand
  management — so a fat-fingered mgmt PCI BDF is caught before install. **Run
  off-target** — the config-drive is normally built on a build host and
  installed from a deploy host, where none of the target's mapped PCI/MAC
  identities are present — the check is **skipped with a warning** (NOT a
  FAIL): with no mapped identity resolving there is no basis to judge a strand,
  and false-rejecting a valid bare-metal map would break the normal day-0
  pipeline. The on-target `bootstrapFromFile` pre-flight below is the real gate
  in that case. (A NIC-enumeration error is likewise a skip-with-warning.)
- `bootstrapFromFile` (first-boot import of `/etc/xpf/xpf.conf`, which runs ON
  the target) runs the pre-flight before it commits and **refuses to commit** a
  stranding config, leaving the daemon in the lifeline-safe bootstrap state
  instead of coming up console-only from the very first boot. The refusal is
  recorded as a failed bootstrap import (see the bootstrap-import status below).

## Day-0 import visibility

A day-0 / bootstrap status is recorded at boot and surfaced both in the CLI as
`show system bootstrap-import` (#6496) and on `/health` (#4184), so the operator
has an in-band answer beyond a single journald line. `ok` means the text config
was imported and the initial host-credential reconcile completed.
`loaded-from-db` means an active config was already present; `no-config` is the
expected factory/fresh-boot state. `credential-apply-pending` means import
succeeded but the initial account/key/sshd reconciliation has not finished;
`credential-apply-failed` means import succeeded but that reconcile did not
converge. `import-failed` means the file could not be read/parsed/committed or
was rejected by the device-map preflight.

`bootstrap_import_failed` is true for `import-failed` and
`credential-apply-failed`. Neither state forces a 503: the box remains
reachable, and surfacing the cause is the goal. A real import failure emits a
`BOOTSTRAP_IMPORT_FAILED` event; credential-apply detail remains in the
daemon journal.

`show system bootstrap-import` renders the same recorded snapshot through
`pkg/bootstrapshow`, shared by the in-process console CLI and the gRPC
`ShowText` path the remote `cli` uses, so the console, the remote client and
the health probe cannot disagree about whether a day-0 config applied. Unlike
`/health` it prints the error detail: that endpoint is unauthenticated and an
import error quotes the offending config, which can echo a submitted secret
(#5031); the CLI path is authenticated.

A factory boot with NO `/etc/xpf/xpf.conf` is the EXPECTED fresh state and is
logged at Info ("no text config present"), not Warn (#4186) — so an operator
triaging a real day-0 failure is not taught to ignore a benign line. The Warn
is kept for a real read/parse/commit failure.

## HA clusters

The device-map is **per-node** (hardware differs between nodes). Use
apply-groups: `groups node0 { chassis device-map { ... } }` /
`groups node1 { ... }`, which the existing config-sync `${node}` machinery
carries. Each node resolves its own section against its own hardware. In
cluster mode, a logical name's FPC slot must align with the node-id
(`ge-7/0/x` is node 1) — a mismatch is rejected at commit.

**Node identity (`/etc/xpf/node-id` file vs `chassis cluster node` leaf).**
The file drives `${node}` apply-group expansion + boot class; the leaf drives
FPC naming + heartbeat identity. They MUST agree. At commit / `check-config`
(#4185) a config whose compiled `chassis cluster node` leaf disagrees with the
effective node identity (the file value, or the `-node-id` flag) is rejected —
a silent mismatch otherwise yields two half-identities on the wire with no
diagnostic. The correct apply-group form above always agrees after expansion
(node0 group → `node 0`); only a literal-mismatched leaf is rejected. The
daemon's node-id file parser also enforces the same strict `0|1` contract the
other consumers use (a present-but-unparseable/out-of-range file is logged
loudly instead of silently falling back to node0).

When the primary pushes a config whose device-map section would strand the
**passive** node's management on next boot, the passive node raises a loud
HA-config-sync alarm (the config is still applied so the stores stay
consistent and the lifeline keeps it reachable now) — fix the map on the
primary and re-sync before rebooting the passive node. (A distributed
pre-commit validation RPC that prevents this at commit time on the primary is
a planned follow-up.)

## Migration & rollout

- Existing appliances/VMs: no map → positional mode → bit-identical behavior.
  Zero migration.
- The baked image ships NO default map (it has no per-box identities at bake
  time). Authoring a device-map is a post-install operator action.

## Scope (this is bare-metal only)

The device-map binding primitive is forward-compatible with the #1958
substrate-binding umbrella (a pluggable identity key), but THIS feature is
scoped to bare metal: no container alias-mode, no platform-profile.
