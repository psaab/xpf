# xpf appliance image validation runbook (#1879)

How to prove a baked appliance image is shippable. There are **three
tiers**, in increasing fidelity. Tier 1 is automated and gates the bake;
Tiers 2–3 are functional and must be run by hand (they push real traffic
and need test endpoints, so they are not part of the offline bake gate).

> **What each tier proves — read this first.**
> - **Tier 1 (first-boot gate):** the image *boots*, ships exactly one
>   ≥6.18 kernel with the full driver set, the AF_XDP shim passes the
>   in-guest verifier, the factory sshd posture holds, and the day-0
>   loader installs/commits a valid config and rejects an invalid one.
>   It does **NOT** forward a single packet.
> - **Tier 2 (standalone forwarding):** a deployed appliance actually
>   routes + NATs LAN→WAN traffic. This is the "does it work as a
>   firewall/router" proof.
> - **Tier 3 (HA forwarding + failover):** a two-node cluster forwards
>   traffic and survives a node failure with sub-second cutover.
>
> "Boots + verifier-passes" (Tier 1) is necessary but NOT sufficient.
> Do not call an image shippable on Tier 1 alone.

## Prerequisites (build/test host)

- Bake toolchain: `libguestfs-tools`, `qemu-utils`, `xorriso`, Go, cargo.
- KVM access: be in the `kvm` group (or run under `sg kvm`) — otherwise
  libguestfs falls back to TCG (works, ~5× slower). Confirm:
  `sg kvm -c 'test -w /dev/kvm && echo ok'`.
- `incus` with a VM-capable storage pool (e.g. `vm-pool`, btrfs/zfs/lvm;
  `dir` works on recent incus). `incus storage list`.
- Passwordless `sudo` (the bake raises `RLIMIT_MEMLOCK` for qemu io_uring).
- Python 3 + PyYAML for `scripts/deploy/xpf-deploy.py`.

## Bake the image

```bash
sg kvm -c 'python3 scripts/image/bake.py'      # full bake + Tier-1 gate
# or, to iterate the boot test without re-baking:
sg kvm -c 'python3 scripts/image/bake.py --skip-validate'
```

Artifacts land in `dist/`: `xpf-<ver>.qcow2`, `xpf-<ver>.incus-metadata.tar.gz`,
`SHA256SUMS`, `xpf-<ver>.manifest`. Verify: `(cd dist && sha256sum -c SHA256SUMS)`.

**Base-image trust anchor (#4904 B).** The Ubuntu cloud image is fetched from a
mirror and authenticated against a repo-PINNED SHA256 (`PINNED_BASE_SHA256` in
`bake.py`, Canonical-GPG-verified) — NOT just the `SHA256SUMS` fetched from the
same mirror endpoint (which authenticates nothing against a compromised mirror).
A pin mismatch aborts the bake. An UNPINNED release (e.g. an `XPF_BASE_RELEASE`
override or `XPF_UBUNTU_AUTODISCOVER=1` with no matching pin) is refused unless
you set `XPF_ALLOW_UNPINNED_BASE=1` (a non-publishable dev bake) or supply a
reviewed `XPF_BASE_SHA256=<digest>`. The authenticated base digest + source URL
+ `base_image_pinned` flag are bound into the signed `xpf-<ver>.manifest`.

**`--skip-validate` is marked non-publishable (#4904 A).** A `--skip-validate`
bake still signs, but the signed `xpf-<ver>.manifest` records `validated: false`
(a full bake records `validated: true`). `scripts/dist/publish.py` refuses any
image whose provenance is not `validated: true`, so an unvalidated dev/emergency
image can never carry a release signature past the fail-closed publish boundary.
The deploy side reads the same signed field (#9325): `xpf-deploy.py fetch`
refuses to download, and `image-roll` refuses to roll, an image whose sidecar
records `validated: false` unless `--allow-unvalidated` is passed, so a dev
image that reaches a host outside the publish boundary is not installed or
rolled silently.

**An `XPF_ALLOW_UNPINNED_BASE=1` (unpinned) bake is likewise non-publishable
(#5815).** Such a bake signs `base_image_pinned: false` into the same
`xpf-<ver>.manifest` — its own authenticated metadata says the Ubuntu base was
NOT anchored to a reviewed trust-anchor digest. `scripts/dist/publish.py`'s
`gate_provenance` REQUIRES `base_image_pinned: true` symmetrically with
`validated: true`, so a fully signed but unpinned dev image cannot be released
via the normal gate (there is no `--allow-unpinned` override — that is the
point). The check is fail-CLOSED on a MISSING `base_image_pinned` key too: an
old or tampered sidecar that does not assert pinning is refused rather than
default-allowed.

---

## Tier 1 — automated first-boot gate (`validate.py`)

Run automatically by `bake.py` (unless `--skip-validate`), or standalone:

```bash
QCOW=dist/xpf-<ver>.qcow2 ; META=dist/xpf-<ver>.incus-metadata.tar.gz
sg incus-admin -c "XPFD=$PWD/xpfd python3 scripts/image/validate.py \
    --qcow2 $QCOW --metadata $META all"
```

It imports the image into local incus and boots throwaway VMs on a
dedicated NAT network (`xpf-image-net`); none touch the shared cluster,
and all are deleted on exit. The incus alias and every scenario instance
are **namespaced with a per-run ID** (`xpf-image-validate-<run>` /
`xpf-image-<run>-a…e`), and every teardown is **ownership-gated**: the
harness tags each instance it creates with `user.xpf-owner=<run>` and
force-deletes ONLY objects carrying that tag (and only the alias it
imported). So a concurrent bake, or an unrelated same-named VM/image, is
never destroyed — before this the constant `xpf-image-validate` alias and
`xpf-image-a…e` instances were force-deleted at import/launch/cleanup with
no run-ID or ownership check (#4905-D).

`--keep` retains the run's instances, alias, and network for post-mortem
inspection. It now ALSO retains the per-run scratch directory
(`xpf-validate-<rand>`) and prints its path: scenarios attach host-side
day-0 config drives / ISOs from that directory to the VMs, so deleting it
while keeping the VMs would leave each retained instance referencing a
source that can no longer be reopened on restart (codex-182 A10-b03-C01).

Scenarios:

| Scenario | Proves |
|---|---|
| **a** no config drive | factory boot; kernel ≥6.18 + `-generic` flavor; `linux-modules-extra` present (checked via the Mellanox driver dir as the sentinel — the broader mlx5/i40e set rides with it); exactly one kernel; `init_on_alloc=0` on the booted cmdline; **in-guest `xpfd verify-dataplane` PASS**; the `/etc/xpf/appliance` marker present (#7114 — it is what re-enables the factory bootstrap; asserted before the DHCP wait so a bake that stopped writing it fails with its own cause); `fxp0` DHCP; sshd listening with `PermitRootLogin prohibit-password` + `PermitEmptyPasswords no`; no stray `/etc/xpf/xpf.conf` or stamp; **#1930 LANE-1 A/B kernel channel live in-guest** (#6494 — both `xpf-A`/`xpf-B` registered exactly once with their own `\EFI\<slot>\shimx64.efi` loader and reachable in BootOrder, `xpf-uefi-slots.service` and `xpf-kernel-promote.service` both ran with `ExecMainStatus=0`, and the promote gate logged its ordinary-boot path); **both slot ESP dirs fully staged with selectors seeded at the running kernel** and **every installed kernel package still held** (#6498); **guest booted under UEFI Secure Boot** (#6497 — the `SecureBoot` EFI variable, corroborated by `mokutil --sb-state` when present and `/sys/kernel/security/lockdown`) |
| **b** valid day-0 drive | config validated + installed + committed (hostname applied, CLI shows it); reboot does **not** re-apply (stamp honored). *(The loader installs the config `0600` because it may carry credential material; the scenario now asserts that posture — root-owned **regular file**, mode exactly `0600` — #6503.)* |
| **c** invalid day-0 drive | commit-check REJECT logged, nothing installed, no stamp, factory bootstrap still reachable |
| **d** resized disk (#1925) | first-boot root auto-grow fills a 20 GiB root disk — root **partition** + ext4 fs both grow past the 8 GiB bake floor, `/etc/xpf/.root-grown` stamped, idempotent across a reboot, ESP still mounted, `verify-dataplane` still PASS; a control instance at the exact bake size proves the grow is a clean no-op (`growpart` NOCHANGE) |

Before any scenario runs, the harness verifies the **image seal** on the
exported artifact (#6547 — see below). It is a pre-scenario step, not a
scenario, so a single-scenario run is gated by it too.

**Pass:** `Validation complete.` with all selected scenarios PASS. Any
`FAIL:` line blocks the bake.

### The image seal / clone identity (#6547)

The bake seals the image with `virt-sysprep` so **no per-device identity ships
inside the golden artifact**: every appliance must regenerate its own
machine-id, SSH host keys, SNMPv3 EngineID and random-seed on first boot. Until
#6547 this gate — the last thing between a bake and a release signature —
asserted **nothing** about that. `grep -ciE 'ssh_host|machine-id|engine-id|
random-seed|sysprep'` over `validate.py` returned 0 for the identities. A
clone-identity regression therefore shipped **signed** and passed the publish
gate.

The acute risk was bounded: bake's `run()` is `subprocess.run(argv,
check=True)`, so an outright `virt-sysprep` failure raises. The exposure is
**drift**. The `--enable` list was a hand-maintained string literal, and the
identity purge is a `rm -rf … 2>/dev/null || true` whose failure is swallowed by
construction — so a member falling out of either, or the step being refactored
away, produced no signal anywhere. What ships then is fleet-wide shared SSH host
keys (every appliance answers with the same host identity, so an operator's
`known_hosts` cannot distinguish one from an impostor and a stolen key
impersonates the fleet), a shared machine-id, and a shared SNMPv3 EngineID —
from which every clone derives **byte-identical localized USM keys** and will
accept another appliance's authenticated SNMPv3 requests (#5283).

| Identity | Must be | Sealed by |
|---|---|---|
| `/etc/machine-id` | absent or **empty** | `--enable machine-id` |
| `/etc/ssh/ssh_host_*` | absent | `--enable ssh-hostkeys` |
| `/var/lib/xpf/snmp-engine-id` | absent | purge path (#5283) |
| `/var/lib/xpf/snmp-engineboots` | absent | purge path (#5283) |
| `/var/lib/systemd/random-seed` | absent | purge path |

**The assertion is made OFFLINE, against the exported qcow2, and that is not an
implementation convenience — it is the only place the property is observable.**
Inside a booted guest every one of these identities has already been
regenerated by first boot, so an in-guest probe finds a machine-id and host keys
present and cannot tell a freshly-generated identity from a baked-in one. The
shipped bytes are what the operator receives, so the shipped bytes are what is
checked. `machine-id` is checked as *absent or empty* rather than absent because
`virt-sysprep` truncates it rather than deleting it, and systemd's
uninitialized state is a present zero-byte file.

**libguestfs missing is a FAILURE, not a skip.** This runs on the host that just
baked the image (`bake.py` already `require()`s `virt-cat` and the rest of
libguestfs-tools), and a security gate that skips itself when its tool is absent
is exactly the vacuous shape this check exists to remove. A glob the inventory
carries no result for likewise FAILS: an unobserved property is not a satisfied
one, and an unreadable image is when a silent pass costs the most.

**The seal and the gate that verifies it cannot drift apart.** `bake.py` now
carries `SYSPREP_ENABLE_OPS` and `SYSPREP_PURGE_PATHS` as the single source for
the seal (the `virt-sysprep` argv is built from them), and each entry in
`validate.py`'s `_SEAL_IDENTITY_CHECKS` names the seal step that produces its
outcome. `scripts/image/test_validate_image_seal_6547.py` binds the two: remove
one `--enable` member from the bake and it goes RED, with no VM and no real
image. That file also calibrates the verdict on known-bad input for each
identity separately, and pins the unobserved-check-fails rule.

Calibrated end to end on real qcow2 artifacts before being trusted: a
purpose-built **unsealed** image (planted machine-id, host keys, EngineID,
engineBoots, random-seed) is REJECTED naming all five; the same image with those
removed PASSES; an image missing the `/var/lib/xpf` directory entirely PASSES
(no matches, not an unobserved check); and an image shipping only
`snmp-engineboots` is REJECTED naming exactly that one.

**Related — #6503.** Same root shape: a gate that asserts presence rather than
properties. The `/etc/xpf` directory's own mode remains unasserted for the
reason given in that section.

### Secure Boot posture (#6497)

The production appliance posture is UEFI Secure Boot **ON** — `test/incus/setup.sh`
sets `security.secureboot: "true"` "to match the production posture (#1943)".
The gate now proves it rather than inheriting it:

- **incus scenarios launch with an explicit `-c security.secureboot=true`.** It
  is the incus default today, but the gate must not inherit the property it
  exists to assert: a default flip, a profile override, or a host without the MS
  db would silently degrade every scenario to SB-off and still pass.
- **Scenario A asserts the guest actually booted under SB.** Three independent
  readings, so a *missing* reading is distinguished from the property being
  false: byte 4 of the `SecureBoot` EFI variable (authoritative and package-free
  — an efivarfs file is 4 attribute bytes then the value), `mokutil --sb-state`
  when present, and `/sys/kernel/security/lockdown` as corroboration.
  `mokutil` is **not** in `bake.py`'s `RUNTIME_PACKAGES`, so an assertion that
  required it would turn a package-set change into a fake SB regression. An
  active lockdown never *overrides* a definite "off" — lockdown can also be
  forced from the cmdline. **No readable source at all is a FAIL**, not a pass:
  a gate that cannot observe the property has not asserted it, which is exactly
  how SB-off shipped green.
- **The plain-QEMU leg prefers an SB-ENFORCING firmware pair** (a secboot
  `OVMF_CODE` build *and* MS-keyed `OVMF_VARS`, so the Canonical-signed shim
  verifies with no MOK enrollment). Both halves are required: a non-secboot CODE
  build ignores SB even with MS keys present, and a secboot CODE build with
  plain VARS has no db for the shim to verify against. When the host has no
  enforcing pair the leg still runs SB-off for bootability coverage, but says so
  in the log and in its PASS line. The old comment read "plain-QEMU bootability
  is proven fine with SB off" — true, and being counted as something it is not.

Why this is more than "the image is signed": the #1930 A/B substrate makes
lockdown-sensitive design choices nothing automated exercised.
`scripts/image/grub.d/09_xpf` documents that `regexp` may be unavailable under
Secure-Boot lockdown and that the slot selector must therefore be a GRUB
*script* so GRUB can parse it there. Before this, the only SB-on validation of
that chain was a one-time manual probe on a hand-staged stock VM
(`docs/pr/1930-inc1-kernel-channel/live-validation.md`), not the baked artifact.

`_secureboot_verdict` and `_qemu_firmware_choice` are pure functions
(`find` is injected into the latter so the preference order is asserted
independently of the test host's OVMF packages), unit-tested in
`scripts/image/test_validate_secureboot_6497.py` and run by `make selftest`.
### Why scenario A asserts the A/B kernel channel (#6494)

The bake stages `/boot/efi/EFI/{xpf-A,xpf-B}` and enables the two #1930
oneshots, and hard-asserts the signed shim is present. What it cannot assert
offline is the half that only happens in-guest: UEFI `Boot####` variables live
in the target's firmware NVRAM, which `virt-customize` cannot write, so
registration is a first-boot oneshot on the real machine.

That oneshot is deliberately non-fatal on every failure path — a read-only or
no-efivars platform must still boot ("degraded, not bricked") — and until #6494
nothing downstream re-read its outcome. So a regression in the ESP disk/part
parse, the loader-path match, or the `efibootmgr` write shipped a fully
`validated: true` image whose verify-gated kernel channel was silently
unavailable. The operator found out when `xpfd upgrade kernel arm` exited 2
with *"A/B slots not both registered ... the first-boot registration oneshot
must run first"*.

Note what scenario A does **not** assert about the promotion gate: the
`promotion gate: clean` journal line. That line is emitted only once the gate
has exec'd xpfd to run the promote verb. On a factory boot with nothing armed
the script exits 0 much earlier, logging `no armed kernel candidate recorded`,
so requiring the former would fail every good image. The gate asserts
`ExecMainStatus=0` plus that ordinary-boot line, which together prove the unit
**executed** rather than being skipped by a Condition.

The three slot properties are checked separately because they have three
different causes: registered *exactly once* (a duplicate makes `BootNext`
ambiguous — the live #1930 bug, from a label guard anchored at `$`), pointing
at *its own* `\EFI\<slot>\shimx64.efi` (a label-only match would chainload the
wrong loader), and present in *BootOrder* (a slot the firmware never reaches is
not registered in any sense the channel can act on). The verdict functions
mirror `xpf-uefi-slots`' own shell regexes on purpose: a gate that disagreed
with the script about what "registered" means would certify a state the script
would not accept.

Both verdicts are pure functions over captured command output
(`_efibootmgr_slot_verdict`, `_oneshot_clean_verdict`), unit-tested without a
hypervisor in `scripts/image/test_validate_ab_slots_6494.py` (run by `make
selftest`), in the same idiom as `_qemu_img_verdict`.

### The rest of the first-boot substrate (#6498)

Registration is not the whole LANE-1 contract. Two halves of it are invisible
to the #6494 assertions, and scenario A now covers both.

**The slot ESP dirs, and what each selector names.** A slot registers only if
the bake staged its shim: `xpf-uefi-slots`' `register_slot()` returns 1 without
ever calling `efibootmgr` when `/boot/efi/EFI/<slot>/shimx64.efi` is absent. So
an unstaged slot LOOKS like a registration failure, pointing at the wrong half
of the channel — which is why the ESP assertion runs BEFORE the NVRAM one and
is diagnosed separately (a unit test pins that ordering). The selector is the
half nothing else could see at all: a slot whose `xpf.selector` names a
`vmlinuz`/`initrd` pair the image does not ship registers cleanly, boots
cleanly, and exits 0 from both oneshots — and is a dead boot entry discovered
only when the firmware actually falls through to it, i.e. during a rollback,
the one moment the channel exists for. Scenario A asserts each selector names
the RUNNING kernel, which is correct **because it is a factory boot**: the bake
seeds both selectors at the single kernel it leaves in `/lib/modules` and
scenario A re-asserts that count. After a promotion the two selectors
legitimately differ, so this is deliberately a scenario-A assertion and not a
general one.

**The #1930 INC-0 kernel hold, on the booted image.** `bake.py` verifies the
hold per-package — but inside `virt-customize`, before `virt-sysprep`, the
sparsify/export, and the first boot. Nothing re-read it afterwards, so a hold
that did not survive any of those steps shipped in a signed, `validated: true`
image. The consequence is not cosmetic: an unattended apt run that moves the
kernel can leave the appliance booting a kernel the verifier-gated shim `.o`
was never verified against — no dataplane.

> **The enumeration is the KERNEL package set, not the literal `linux-*`.**
> #6498's acceptance criterion reads "every installed `linux-*` package appears
> in `apt-mark showhold`". Asserted literally, that REDS every valid image:
> `linux-base` is a hard dependency of `linux-image-*-generic`, and
> `linux-libc-dev` / `linux-sysctl-defaults` / `linux-perf` are installed
> alongside it. None are kernel packages and `bake.py` deliberately holds none
> of them. The property the criterion reaches for is "the kernel cannot move",
> so the gate enumerates exactly the four globs `bake.py` holds
> (`linux-image-*`, `linux-headers-*`, `linux-modules-*`, `linux-generic`) with
> the same `${db:Status-Status}` installed-only filter. A **drift canary** binds
> the two enumerations: a gate asserting a different set than the bake protects
> would either red on a good image or certify an unprotected one, so the
> agreement itself is the property under test.

An EMPTY enumeration FAILS rather than passing. "All zero of them are held" is
the pass that would argue against anyone re-examining the property — and
`bake.py`'s own hold fragment collapsed to an empty enumeration twice during
#1926 (an unexpanded `${Package}`, then `dpkg-query -W` returning
never-installed names).

`_ab_slot_esp_verdict` and `_kernel_hold_verdict` are pure functions over
captured command output, unit-tested (with the bake-agreement canaries and the
call-site wiring assertions) in
`scripts/image/test_validate_ab_substrate_6498.py`, run by `make selftest`.

### The day-0 config's credential posture (#6503)

The loader installs `/etc/xpf/xpf.conf` with `install -o root -g root -m 0600`
because it "may carry credential material (root-authentication
encrypted-password, IKE PSKs)". Until #6503 the gate asserted the file exists
and is non-empty and **nothing about the mode** — this document said so in as
many words — so a regression to `0644` would ship world-readable IKE PSKs and
password hashes inside a *signed* image and pass Tier 1 green. It is pinned now
for the same reason scenario A pins the sshd posture.

Asserted in **every** scenario that installs a config — B (valid drive), C's
retry leg, and E (node-id drive) — because they all reach the same `install`
call and a regression there would ship from any of them.

Two details a naive version of this check gets wrong:

- **The mode is compared as an octal value, not the string `"600"`** — for
  rendering independence, not because a string compare would let a bad mode
  through. GNU `stat -c %a` emits `600` unpadded, so `!= "600"` rejects `4600`
  exactly as `!= 0o600` does; what the value compare buys is that a zero-padded
  `0600` from a non-GNU `stat` is the same mode and is not a false red.
- **The probe does not pass `stat -L`.** For a symlink, `stat -c '%a %U:%G %F'`
  reports the *link* (`777 … symbolic link`); `stat -L` reports the *target*
  (`644 … regular file`). A check that followed the link would read the
  target's mode while the file an attacker controls is the link — a `0600`
  target behind a world-writable link would PASS on mode alone. The file type
  is therefore part of the verdict, and `_DAY0_CONF_STAT` is asserted to carry
  no `-L`.

**Not** asserted: `/etc/xpf`'s own directory mode. The loader sets it
best-effort (`chmod 0750 … || true`) and the directory comes from the `.deb` on
a real appliance, so it is not the loader's contract to pin here.

`_conf_mode_verdict` is a pure function over the captured `stat` output,
unit-tested (with the call-site wiring assertions) in
`scripts/image/test_validate_day0_perms_6503.py` and run by `make selftest`.

---

## Tier 2 — standalone forwarding + NAT (functional, manual)

Proves a deployed appliance actually routes and SNATs LAN→WAN. Fully
self-contained on one incus host: the appliance is the L3 gateway, the
LAN/WAN segments are pure L2 bridges, and interface SNAT means the WAN
endpoint needs no route back.

> **VENUE NOTE (measured 2026-08-21 from a baked image; #1926).** Plain
> **virtio** in an ordinary incus VM IS a valid venue for the Tier-2
> *functional* forwarding assertions below. The earlier "virtio delivers
> 0 frames to the XSK" warning here is retired — see
> "Recorded Tier-2 result" for the run that replaces it.
>
> The claim it rested on (#1961) was root-caused to a Go↔Rust snapshot
> **wire-type** bug for DSCP/code-point lists, fixed in **PR #1976** plus
> the `NUM_WIDTH` siblings in **#1978**. Its "sustained virtio stall"
> follow-on was retracted by its own author as a test-environment defect:
> three firewall VMs were answering the same gateway IPs on the same
> bridges, so the client's gateway ARP flipped mid-flow. The warning text
> was written one day BEFORE #1976 landed and was never revisited, so it
> outlived its evidence by two months.
>
> What virtio does NOT give you is a **line-rate** number: the ceiling
> below is a few Gbit/s on a single flow, an order of magnitude under a
> real AF_XDP NIC. Performance claims still belong on **mlx5 SR-IOV VFs**
> (the loss userspace cluster) or **i40e PF passthrough** (the standalone
> test VM's WAN). Tier 2 does not ask for one — it asks whether the
> appliance routes and NATs at all.
>
> **The one trap to avoid** is the one that caused the #1961
> misdiagnosis: make sure no other firewall VM answers the same gateway
> IPs on the same bridges. Run `incus list` first. The private
> `10.66.1.0/24` / `10.66.2.0/24` segments below exist precisely to keep
> this run isolated.

### Topology

```
   incus NAT net          xpf appliance VM (from the baked image)
   xpf-rtr-mgmt ──── NIC1 → fxp0      mgmt, DHCP (admin reaches it here)
                     NIC2 → ge-0/0/0  LAN  10.66.1.1/24  fd66:1::1/64
   xpf-rtr-lan ───────────┘
                     NIC3 → ge-0/0/1  WAN  10.66.2.1/24  fd66:2::1/64
   xpf-rtr-wan ───────────┘
     │                              │
   lanhost (ctr)                  wanhost (ctr)
   10.66.1.10/24 gw .1            10.66.2.10/24  (iperf3 -s)
   fd66:1::10/64                  fd66:2::10/64
```

NIC order = interface name (positional contract). Names are shown in
config/CLI slash form (`ge-0/0/0`); the Linux link name is the dash form
(`ge-0-0-0`) that `assignName()` produces — the config layer translates
between them. This topology on plain incus/virtio validates the full
Tier-2 set: control-plane + day-0 + interface bring-up AND transit
forwarding/NAT (measured, #1926 — see "Recorded Tier-2 result"). Only
line-rate numbers need mlx5-VF / i40e-PF.

### Host networks

```bash
incus network create xpf-rtr-mgmt ipv4.address=10.166.0.1/24 ipv4.nat=true ipv6.address=none
incus network create xpf-rtr-lan  ipv4.address=none ipv6.address=none   # L2 only; appliance is gw
incus network create xpf-rtr-wan  ipv4.address=none ipv6.address=none
```

### Router config (`/tmp/router-test.conf`)

Static LAN/WAN (the shipped `standalone.conf` uses WAN-DHCP, awkward for a
closed loop). Validate before use: `xpfd check-config /tmp/router-test.conf`.

```
interfaces {
    fxp0     { unit 0 { family inet { dhcp; } } }
    ge-0/0/0 { unit 0 { family inet { address 10.66.1.1/24; } family inet6 { address fd66:1::1/64; } } }
    ge-0/0/1 { unit 0 { family inet { address 10.66.2.1/24; } family inet6 { address fd66:2::1/64; } } }
}
security {
    zones {
        security-zone mgmt { interfaces { fxp0; } host-inbound-traffic { system-services { ssh; ping; } } }
        security-zone lan  { interfaces { ge-0/0/0.0; } host-inbound-traffic { system-services { ssh; ping; } } }
        security-zone wan  { interfaces { ge-0/0/1.0; } host-inbound-traffic { system-services { ping; } } }
    }
    policies { from-zone lan to-zone wan { policy allow-out {
        match { source-address any; destination-address any; application any; }
        then { permit; } } } }
    nat { source { rule-set lan-to-wan { from zone lan; to zone wan;
        rule snat  { match { source-address 0.0.0.0/0; } then { source-nat { interface; } } }
        rule snat6 { match { source-address ::/0; }      then { source-nat { interface; } } } } } }
}
system { host-name xpf-rtr; dataplane-type userspace; }
```

### Deploy definition (`/tmp/router-test.yaml`)

```yaml
appliance:
  name: xpf-rtr
  mode: standalone
  image: xpf-appliance
  cpu: 4
  memory: 4GiB
  config: /tmp/router-test.conf
  pool: vm-pool
interfaces:
  - {role: fxp0,     backing: net,    source: xpf-rtr-mgmt}
  - {role: ge-0/0/0, backing: bridge, source: xpf-rtr-lan}
  - {role: ge-0/0/1, backing: bridge, source: xpf-rtr-wan}
```

### Run

```bash
incus image import dist/xpf-<ver>.incus-metadata.tar.gz dist/xpf-<ver>.qcow2 --alias xpf-appliance
python3 scripts/deploy/xpf-deploy.py /tmp/router-test.yaml

# Test endpoints (containers; reachable via the incus agent regardless of L3)
incus launch images:debian/13 lanhost --network xpf-rtr-lan
incus launch images:debian/13 wanhost --network xpf-rtr-wan
incus exec lanhost -- ip addr add 10.66.1.10/24 dev eth0
incus exec lanhost -- ip -6 addr add fd66:1::10/64 dev eth0
incus exec lanhost -- ip route add default via 10.66.1.1
incus exec lanhost -- ip -6 route add default via fd66:1::1
incus exec wanhost -- ip addr add 10.66.2.10/24 dev eth0
incus exec wanhost -- ip -6 addr add fd66:2::10/64 dev eth0
# Tools: iperf3 client on lanhost, iperf3 server + tcpdump on wanhost.
incus exec lanhost -- sh -c 'apt-get update -qq && apt-get install -y iperf3 >/dev/null 2>&1'
incus exec wanhost -- sh -c 'apt-get update -qq && apt-get install -y iperf3 tcpdump >/dev/null 2>&1; iperf3 -s -D'

# Wait for the appliance + confirm the interface map
incus exec xpf-rtr -- cli -c "show interfaces terse"   # fxp0 / ge-0/0/0 / ge-0/0/1

# Forwarding + NAT, v4 and v6
incus exec lanhost -- ping  -c3 10.66.2.10
incus exec lanhost -- ping6 -c3 fd66:2::10
incus exec lanhost -- iperf3 -c 10.66.2.10 -t 5
incus exec lanhost -- iperf3 -c fd66:2::10 -t 5

# Prove it ROUTED + NAT'd (not just L2):
incus exec xpf-rtr -- cli -c "show security flow session"      # LAN→WAN sessions w/ translation
incus exec wanhost -- timeout 6 tcpdump -ni eth0 -c3 'src 10.66.2.1'    # v4 SNAT source = appliance WAN
incus exec wanhost -- timeout 6 tcpdump -ni eth0 -c3 'src fd66:2::1'    # v6 SNAT source = appliance WAN
```

### Pass criteria
- v4 + v6 ping succeed; iperf3 moves nonzero throughput both families.
- `show security flow session` shows the forwarded flows with interface SNAT.
- `wanhost` sees traffic sourced from `10.66.2.1` (v4) AND `fd66:2::1` (v6) — SNAT confirmed for both families, not bridged.

### Recorded Tier-2 result (2026-08-21, #1926)

First recorded pass. Run on ordinary **incus/virtio** on a dev host — no
SR-IOV, no PF passthrough, no shared-cluster lock.

| | |
|---|---|
| Image | `xpf-userspace-forwarding-ok-20260402-bfb00432-10859-gf93215641.qcow2` |
| `git_commit` | `f93215641` (master `e344c9df5` + the three bake fixes below) |
| Base | Ubuntu 26.04 cloud image, `9dc7c536…`, Canonical-GPG-verified |
| Guest kernel | `7.0.0-30-generic` |
| Venue | incus VM, 3× virtio NIC, `xpf-rtr-{mgmt,lan,wan}` |

Deployed from the baked qcow2 via `xpf-deploy.py` with the day-0 drive —
**not** pushed binaries. Results:

- **v4 ping** 10.66.1.10 → 10.66.2.10: replies, 0.35–0.43 ms.
- **v6 ping** fd66:1::10 → fd66:2::10: replies, 0.31–0.33 ms.
  (The *first* echo of a cold flow is lost in both families while the
  session installs — `icmp_seq=1` missing, `seq=2,3` fine. A warm flow is
  0% loss; see the discriminator below.)
- **iperf3 v4** 2.98 Gbit/s (5 s), **4.29 Gbit/s** sustained over 30 s.
- **iperf3 v6** 3.94 Gbit/s (5 s), **3.02 Gbit/s** sustained over 30 s.
- **`show security flow session`**: LAN→WAN flows with interface SNAT —
  `In: 10.66.1.10 --> 10.66.2.10;icmp / Out: 10.66.2.10 --> 10.66.2.1;icmp`
  and the `fd66:` equivalent translating to `fd66:2::1`.
- **`show security flow statistics`**: `Packets received: 3033032`,
  `Packets dropped: 0` — the direct refutation of the retired warning's
  `Packets received: 0`.
- **wanhost tcpdump**: ICMP *and* TCP sourced from `10.66.2.1` /
  `fd66:2::1`; the LAN host's own address never appears on the WAN
  segment. SNAT confirmed for both families and both protocols.

**Discriminator — this is the xpf dataplane, not the guest kernel.**
Interface SNAT alone already rules the kernel out (`nft list ruleset`
shows no NAT table — only xpf's own RST-suppression and host-inbound
counters). Made explicit anyway, matching the method that settled #1961:
with `net.ipv4.ip_forward=0` **and** `net.ipv6.conf.all.forwarding=0` set
on the appliance, ping stayed at **0% loss** and iperf3 still moved
**4.29 Gbit/s (v4)** and **3.02 Gbit/s (v6)** over 30 s. Kernel forwarding
disabled, traffic still crossing: the AF_XDP userspace dataplane carried
it.

**Not proven by this run**, and deliberately not claimed:
line rate (virtio ceilings at a few Gbit/s on one flow — use mlx5-VF or
i40e-PF for a performance number), and Tier 3 / HA from an image.

Two defects observed during the run, tracked separately — neither affects
the result above:

- Tier-1 scenario **a** failed on this image (#7114, FIXED): on a factory
  boot with no config drive, nothing brought the NIC up (the bake purges
  cloud-init and netplan), so xpfd's bootstrap lifeline found no default
  route, declined to identify a management NIC, and left the port down and
  unrenamed — no `fxp0`, no DHCP. Tier 2 was unaffected because it supplies
  a day-0 config, which takes xpfd out of bootstrap and into full interface
  takeover. The fix adds the bake-written `/etc/xpf/appliance` marker, which
  (AND-ed with "nothing ever committed") lets the lifeline claim the first
  enumerated NIC on this artifact while keeping the console-only refusal for
  foreign-host installs — see `docs/install-images.md`.
- `show security flow session` lists the ICMP sessions but omits TCP ones,
  while `show security flow statistics` counts them (`Current sessions:
  10` against a rendered `Total sessions: 2`). A display-path gap, not a
  forwarding one — the TCP flows demonstrably forward and SNAT.

### Cleanup
```bash
incus delete -f xpf-rtr lanhost wanhost
incus network delete xpf-rtr-mgmt xpf-rtr-lan xpf-rtr-wan
incus image delete xpf-appliance
rm -f /tmp/router-test.yaml /tmp/router-test.conf /tmp/xpf-rtr-day0.iso
```

---

## Tier 3 — HA pair forwarding + failover (functional, manual)

Proves a two-node cluster forwards and survives a node failure. Same idea
as Tier 2 but two appliances sharing reth interfaces, plus dedicated
`em0` (control) and fabric L2 segments.

### Networks

Create the networks the shipped HA YAMLs actually reference as interface
`source`s — `br-mgmt`, `ha-control`, `ha-fabric`, `br-lan`, `br-wan`
(`examples/deploy/ha-fw0.yaml`/`ha-fw1.yaml`). Use these exact names so the
YAMLs deploy unedited; `br-mgmt` is NAT (admin + fxp0 DHCP), the rest are
L2-only point-to-point/segment bridges:

```bash
incus network create br-mgmt    ipv4.address=10.167.0.1/24 ipv4.nat=true ipv6.address=none
incus network create ha-control ipv4.address=none ipv6.address=none   # em0, point-to-point
incus network create ha-fabric  ipv4.address=none ipv6.address=none   # fabric
incus network create br-lan     ipv4.address=none ipv6.address=none   # reth1 members
incus network create br-wan     ipv4.address=none ipv6.address=none   # reth0 members
```

### Deploy (the shipped HA examples, unedited)
```bash
python3 scripts/deploy/xpf-deploy.py examples/deploy/ha-fw0.yaml examples/deploy/ha-fw1.yaml
# Both nodes attach NICs in the SAME order (mgmt, control, fabric, lan, wan)
# and share ha-pair.conf; only node_id (day-0 drive) + the ge FPC differ.
```

### Verify + failover
```bash
incus exec fw0 -- cli -c "show chassis cluster status"          # RG0/1/2 primary/secondary
# ha-pair.conf gives node 0 priority 200 / node 1 priority 100 for RG1 (WAN)
# and RG2 (LAN), so fw0 is the data-path PRIMARY. To exercise failover you
# must take down the PRIMARY (fw0), not the secondary:
# start a long transfer LAN→WAN through the reth VIP, then:
incus stop fw0               # kill the RG1/RG2 primary; fw1 must take over
# assert: the transfer survives with a sub-second gap; fw1 becomes primary
#         for RG1/RG2; no session loss for the synced flows. Then restart
#         fw0 and confirm failback (preempt) or steady secondary per config.
```

### Pass criteria
- Cluster forms (RGs have a primary/secondary); LAN→WAN forwards through the reth VIP.
- A node failure causes a sub-second cutover; an in-flight TCP transfer survives (session sync + fabric forwarding).
- `make test-failover` on the loss cluster remains the canonical timing gate; this Tier-3 run proves the *image* boots into a working cluster.

### Cleanup
Delete `fw0`/`fw1` and the five `xpf-ha-*` networks.

---

## Honest scope

- **virtio IS a functional forwarding venue; it is not a performance one
  (measured 2026-08-21, #1926).** Tier 2 passes end-to-end on ordinary
  incus/virtio — v4+v6 ping, iperf3 both families, interface SNAT
  confirmed on the wire — from a booted baked image, with the guest's own
  `ip_forward` disabled to prove the AF_XDP dataplane carried it. See
  "Recorded Tier-2 result". What virtio cannot give you is a line-rate
  number: it ceilings at a few Gbit/s on a single flow, so performance
  claims still need the loss cluster's mlx5 SR-IOV VFs or i40e PF
  passthrough.

  This bullet previously asserted the opposite, on #1961's "XSK receives
  0 frames" finding. That finding was a Go↔Rust snapshot wire-type bug
  (fixed in #1976/#1978), and its "sustained stall" follow-on was
  retracted by its author as a gateway-IP/ARP collision between three
  firewall VMs. The text was written the day before the fix landed and
  went unrevisited for two months; treat the dated "re-confirmed" note it
  carried as a caution about re-confirming against a moving tree, not as
  evidence.
- The **image vs. deployed binaries** distinction still matters. The loss
  SR-IOV smoke matrix exercises binaries pushed onto already-running VMs;
  it never boots the baked qcow2. The recorded Tier-2 result above is an
  image-based proof and is the thing that closes that gap — on virtio. An
  image-based proof *on an SR-IOV venue* is still unrun.
- None of these tiers touch the shared `loss` cluster; Tier-1 and the
  functional tiers use dedicated throwaway instances + networks.
