# xpf deployment quickstart

From a baked image (`docs/install-images.md`) to a running firewall —
standalone or HA — with one Python tool, `scripts/deploy/xpf-deploy.py`.
The comprehensive reference (every backing, schema, recipes) is
`examples/deploy/README.md`; this is the fast path.

## The 60-second mental model

xpf names interfaces **by position** (`assignName()` in `linksetup.go`),
exactly like vSRX. (`assignName()` returns the Linux link name in dash
form — `ge-0-0-0`; config and CLI use the slash form — `ge-0/0/0` — and
the config layer translates between them. The tables below use the
slash/CLI form.)

| Position | Standalone | Cluster node 0 | Cluster node 1 |
|---|---|---|---|
| 1 | `fxp0` (mgmt) | `fxp0` | `fxp0` |
| 2 | `ge-0/0/0` | `em0` (HA control) | `em0` |
| 3 | `ge-0/0/1` | `ge-0/0/0` | `ge-7/0/0` |
| N | `ge-0/0/(N-2)` | `ge-0/0/(N-3)` | `ge-7/0/(N-3)` |

So a deployment is one ordered table: each interface gets a **role**
(the name above), a **backing** (`bridge`/`sriov`/`pci`/…), and a
**source** (bridge name, PF name, or PCI address). You write it once as
YAML; the tool validates the role↔position match, builds the day-0
config drive, and launches the VM with the NICs attached in order.

**The virtio-first tiebreaker (get the NIC order right).** The guest
does not name NICs purely by the order the tool attaches them — before
assigning positional names it sorts **virtio-class** backings
(`net`/`bridge`/`macvlan`, which attach as `virtio_net`) *ahead of*
**hardware-class** backings (`sriov`/`physical`/`pci`, which attach as
the real passthrough driver). See `enumeratePCINICs()` in
`pkg/daemon/linksetup.go`. So "position is the contract" holds only when
your interface list already puts **every virtio-class NIC before every
hardware-class NIC**. If you list a virtio-class NIC *after* a
hardware-class one, the guest renames it to an earlier slot and the
firewall zones/policies/NAT land on **swapped ports** (e.g. trust and
untrust inverted). The deploy tool now rejects such a layout at validate
time (`validate_appliance`) and tells you which two interfaces to
reorder — so this is caught before launch, not discovered in production.
Still verify the final map with `show interfaces terse` after boot.

## Prerequisites

```bash
# Import the baked image (see docs/install-images.md):
incus image import dist/xpf-<ver>.incus-metadata.tar.gz \
    dist/xpf-<ver>.qcow2 --alias xpf-appliance
# The deploy tool needs: python3 + PyYAML, xorriso, and (recommended) an
# xpfd binary in PATH/cwd so the day-0 config is validated at build time.
```

## Standalone in two commands

`standalone.yaml` (and the `launch` form below) source three bridges —
`br-mgmt`, `br-lan`, `br-wan`. Create them first so the deploy runs
unedited. `br-mgmt` and `br-wan` are **NAT/DHCP-bearing** so `fxp0`
(mgmt, DHCP) and `ge-0/0/1` (WAN, DHCP-from-upstream) get addresses and
reach the internet; `br-lan` is a plain L2 segment — `ge-0/0/0` is the
static LAN gateway that runs the DHCP server itself:

```bash
incus network create br-mgmt ipv4.address=10.167.0.1/24 ipv4.nat=true ipv6.address=none
incus network create br-wan  ipv4.address=10.168.0.1/24 ipv4.nat=true ipv6.address=none
incus network create br-lan  ipv4.address=none ipv6.address=none
```

```bash
scripts/deploy/xpf-deploy.py inventory                              # see your NICs/VFs/bridges
scripts/deploy/xpf-deploy.py deploy examples/deploy/standalone.yaml # build drive + launch
```

`standalone.yaml` is a working 3-NIC LAN→WAN NAT firewall (mgmt, LAN,
WAN). Edit it for your host, or use a backing-specific sample:
`standalone-sriov.yaml` (VF dataplane) or `standalone-passthrough.yaml`
(PCI passthrough — deploys on incus *and* libvirt). Add `--dry-run` to
print the exact commands first.

First boot: the day-0 loader re-validates the config with the real
commit-check gate, installs it as `/etc/xpf/xpf.conf`, and xpfd commits.
A rejected config logs loudly (`journalctl -u xpf-day0-config`) and
leaves the box factory-default (fxp0 DHCP + console login).

### No YAML? Use `launch`

```bash
scripts/deploy/xpf-deploy.py launch --name fw1 --config examples/deploy/standalone.conf \
    --nic bridge:br-mgmt --nic bridge:br-lan --nic bridge:br-wan
```

## libvirt instead of incus

The same definition, `--hypervisor libvirt` — the tool runs
`virt-install` for you (NIC order = guest PCI-slot order = positional
names):

```bash
scripts/deploy/xpf-deploy.py --hypervisor libvirt deploy examples/deploy/standalone-passthrough.yaml
```

`--import` DEFINES AND BOOTS the domain. Add `--no-start` to define it
without booting (the tool runs `virt-install --print-xml | virsh define`)
so you can pin the guest PCI slots with `virsh edit <name>` before the
first boot:

```bash
scripts/deploy/xpf-deploy.py --hypervisor libvirt --no-start deploy examples/deploy/standalone-passthrough.yaml
virsh -c qemu:///system edit fw1        # pin guest PCI slots, then:
virsh -c qemu:///system start fw1
```

**The libvirt connection URI (#9669).** The tool always names the URI. The golden and overlay
disks live under system-scope `/var/lib/libvirt/images`, so `deploy` runs `virt-install
--connect qemu:///system` and `virsh -c qemu:///system define`. Use the same URI for your own
`virsh edit` / `virsh start`. `destroy`, and the cleanup after a failed deploy, probe BOTH
`qemu:///system` and `qemu:///session`, because libvirt keeps a separate domain namespace per
URI. A domain in either URI is treated as present and is torn down through the URI that holds
it. Disks are removed only when both URIs report the domain missing. An unreachable URI is not
proof of absence.

See `examples/deploy/README.md` for the full incus-vs-libvirt
comparison and the SR-IOV VF-pool / pinned-guest-PCI details.

## Tearing down / re-deploying

`destroy` removes a deployed VM and its per-VM overlay + day-0 drive so a
re-deploy starts clean (incus instance / libvirt domain, whichever
`--hypervisor` selects):

```bash
scripts/deploy/xpf-deploy.py destroy examples/deploy/standalone-passthrough.yaml
scripts/deploy/xpf-deploy.py --hypervisor libvirt destroy examples/deploy/standalone-passthrough.yaml
```

`destroy` removes a disk only after the hypervisor **affirmatively** reports the
VM gone (#8977, #9325). If `virsh`/`incus` cannot be run from the invoking
context, cannot reach its daemon, or still reports the domain after `destroy` and
`undefine` (a running libvirt domain survives `undefine` as a transient domain),
it refuses and names the files it left. Stop the VM, check that
`virsh dominfo <name>` / `incus info <name>` reports it missing, then run
`destroy` again.

The `<name>-day0.iso` drive is written **owner-only (0600)** in the build
directory and lingers there until `destroy` removes it. That ISO embeds
`xpf.conf` verbatim — the most secret-bearing artifact on the box
(root-authentication hash, IKE pre-shared-keys, SNMP community, DDNS
tokens) — so the tool never leaves it world-readable even under a lax
umask (#4586). The standalone builder `scripts/image/make_config_drive.py`
applies the same 0600 (staged copy and finished ISO), so neither day-0
path leaves the secrets world-readable (#4905-C). On a shared
build/CI/jump host, run `destroy` (or delete the ISO) once the VM is up
rather than leaving day-0 secrets on disk.

`name`/`image` are **validated to a single safe path component** before
any path is built from them (#4905-B). They are interpolated into files
the tool writes and removes — the day-0 ISO in the build dir, and the
per-VM overlay + shared golden qcow2 under `/var/lib/libvirt/images`
(sometimes via `sudo rm -f`) — so a value with a path separator, a `..`
component, an absolute path, or a leading dash is rejected, and each path
sink additionally enforces `commonpath` containment. A crafted or
mistyped `name: ../../../../tmp/owned` can no longer redirect a write or
delete outside the managed storage dir.

`deploy` runs a **preflight** before it mutates anything — the image /
golden qcow2, every NIC source (managed network / host bridge / PF / PCI
device), and a free instance name must all exist, or it fails with one
clear message instead of a half-created VM. If a step still fails
mid-deploy, the partially-created instance / overlay is cleaned up so the
re-run does not dead-end on "already exists".

## HA pair

A cluster is two YAML files in one invocation:

```bash
# Create EVERY network the HA YAMLs reference as a source (br-mgmt,
# ha-control, ha-fabric, br-lan, br-wan) so they deploy unedited:
incus network create br-mgmt    ipv4.address=10.167.0.1/24 ipv4.nat=true ipv6.address=none
incus network create ha-control ipv4.address=none ipv6.address=none
incus network create ha-fabric  ipv4.address=none ipv6.address=none
incus network create br-lan     ipv4.address=none ipv6.address=none
incus network create br-wan     ipv4.address=none ipv6.address=none
scripts/deploy/xpf-deploy.py examples/deploy/ha-fw0.yaml examples/deploy/ha-fw1.yaml
incus exec fw0 -- cli -c "show chassis cluster status"
```

Both nodes share `ha-pair.conf`; only `node_id` (stamped on the day-0
drive) and the ge FPC (`0` vs `7`) differ. `ha-fw0-sriov.yaml` /
`ha-fw1-sriov.yaml` are the VF-dataplane variants. Two-host cluster: run
the tool on each host with that node's file and its local PFs.

## Performance: which backing for the dataplane?

The image guarantees the kernel side (≥6.18, verifier-passing AF_XDP
shim). The NIC the VM sees decides the rest:

| Backing | Guest driver | AF_XDP mode | Notes |
|---|---|---|---|
| `pci:` whole PF (i40e/ice/mlx5) | vendor PF | native, fastest | claims the entire NIC |
| `sriov:` / `pci:` mlx5 VF | mlx5_core | **native** | the loss-cluster reference shape |
| `sriov:` / `pci:` Intel VF | iavf | generic only (~3-4× slower) | works, but know it |
| `bridge:` / `net:` | virtio_net | generic-class | fine for labs / modest WANs (`inventory` hints `no (generic)`) |

virtio for mgmt and anything under a few Gb/s; mlx5 VFs or PF
passthrough for line-rate ports.

## Fleet pattern (many sites, few humans)

The YAML + `xpf.conf` are the deployable artifacts — treat them as code:

1. **CI gate**: `xpfd check-config` on every `*.conf` change (the same
   gate runs again at first boot, so a green pipeline can't ship a
   refusable config).
2. **Deploy**: `xpf-deploy.py deploy site-*/appliance.yaml` (one or many).
3. **Upgrade**: replace-image — deploy a new VM from the new image with
   the same YAML + config, swap traffic (HA: replace secondary →
   failover → replace primary). `xpf.conf` + `node_id` are the only
   carried state.
4. **Recover**: cattle. Console for `rollback 1`, redeploy otherwise.

## Troubleshooting

| Symptom | Look at |
|---|---|
| day-0 config not applied | `show system bootstrap-import` from the CLI — the recorded verdict AND the reason (#6496); then `journalctl -u xpf-day0-config` for the verbatim commit-check rejection. Box stays factory-default: fix + reboot. See docs/install-images.md "My day-0 config did not apply" |
| NIC roles shifted | `cli -c "show interfaces terse"` vs your YAML; an interface added between deploys changes order |
| VF dataplane dead after host reboot | unpinned VF MAC rotated — set `mac:` on the interface |
| no mgmt after commit | hypervisor console → `cli` → `rollback 1`, `commit` |
| HA split-brain / no sync | `show chassis cluster status`; confirm the `em0` link is a dedicated L2 carrying nothing else |
