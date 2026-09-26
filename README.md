# xpf

xpf is a high-performance, Junos-style stateful firewall that replicates
Juniper vSRX capabilities. It uses the familiar Junos hierarchical
configuration syntax and a full interactive CLI (tab completion, `?`
help), and forwards packets on a Rust AF_XDP userspace dataplane driven
by a Go control plane.

> Dataplane: the Rust AF_XDP userspace dataplane is the **only** runtime
> forwarding path (eBPF retired in #1373/#1476, DPDK in #1525). See
> [`docs/architecture.md`](docs/architecture.md).

---

## Getting started

There are three ways to get a running firewall. **The prebuilt appliance
image (paths B and C) is the recommended path** — it is the dependency
closure (kernel ≥ 6.18, FRR, strongSwan, Kea, the xpf binaries and units)
baked into one bootable disk, deployable on incus (B) or
libvirt/KVM/QEMU (C). Install the `.deb` (A) on a host you already manage;
build from source for development.

| Path | Use when | Jump to |
|------|----------|---------|
| **(A) Debian package** | You have a Debian/Ubuntu host (kernel ≥ 6.18) and want xpf on it | [below](#a-debian-package-deb) |
| **(B) Incus appliance image** | You run incus and want a VM appliance | [below](#b-incus-appliance-image) |
| **(C) KVM / QEMU / libvirt** | You run libvirt/KVM/QEMU | [below](#c-kvm--qemu--libvirt) |

All paths give you the same firewall. After it boots, the **mgmt
interface `fxp0` comes up on DHCP** and you reach the box over SSH (once
your day-0 config sets credentials) or via the hypervisor console. First
contact is always `cli`.

> **Interface naming is positional, like vSRX.** The first vNIC is `fxp0`
> (out-of-band mgmt); the rest map to `ge-0/0/N` in attach order (cluster
> nodes insert `em0` for HA control at position 2). The order you attach
> NICs is the order they are named, with one wrinkle: enumeration sorts
> virtio NICs ahead of other drivers and then by PCI bus address
> (`enumerateAndRenameInterfaces()` in `pkg/daemon/linksetup.go`), so a
> virtio mgmt NIC stays `fxp0`/`em0` even when dataplane ports are
> SR-IOV/passthrough. In a normal layout this is identical to pure attach
> order; verify with `show interfaces terse`. Full contract in
> [`docs/deploy-quickstart.md`](docs/deploy-quickstart.md).

### (A) Debian package (.deb)

Install xpf onto an existing Debian/Ubuntu host. **Requires kernel ≥
6.18** (the AF_XDP shim's verifier floor; ≥ 6.18 also gives full NAT64).

```bash
# On the build host (Go + cargo toolchain):
make deb                       # builds xpfd + xpf-userspace-dp + cli,
                               # packages them into dist-deb/xpf_<ver>_amd64.deb
                               # (+ the xpf-appliance metapackage)

# Copy dist-deb/xpf_<ver>_amd64.deb to the target host, then there:
sudo apt install ./xpf_<ver>_amd64.deb     # ${shlibs:Depends} pulled in by apt
```

The `xpf` package ships the binary set (`xpfd`, `xpf-userspace-dp`,
`cli`), the day-0 config-drive loader, and the systemd units. The
`postinst` stages the binaries and, on first install, creates the live
`/usr/local/sbin/{xpfd,cli,xpf-userspace-dp}` symlinks and enables
`xpfd`. For the full runtime stack (FRR, strongSwan, Kea, chrony,
networking tooling) in one shot, install the **`xpf-appliance`**
metapackage instead — e.g. `sudo apt install xpf-appliance` from a hosted
apt repo.

Then configure the firewall (see [Configuration](#configuration)) and:

```bash
sudo systemctl status xpfd
cli                            # interactive Junos-style CLI
```

### (B) Incus appliance image

Build (or fetch) the appliance image and deploy an instance from a YAML
definition. The image carries everything xpf needs; there is no
dependency matrix to install.

```bash
# 1. Build the image (or obtain dist/xpf-<ver>.{qcow2,incus-metadata.tar.gz}):
make image                     # = python3 scripts/image/bake.py

# 2. Import it into incus:
incus image import dist/xpf-<ver>.incus-metadata.tar.gz \
    dist/xpf-<ver>.qcow2 --alias xpf-appliance

# 3. See your host NICs, then deploy from a definition:
scripts/deploy/xpf-deploy.py inventory
scripts/deploy/xpf-deploy.py deploy examples/deploy/standalone.yaml
```

`examples/deploy/standalone.yaml` is a working 3-NIC LAN→WAN NAT firewall
(mgmt, LAN, WAN). The deployer validates the role↔position match, builds
the day-0 config drive from the referenced `xpf.conf`, and launches the
VM with the NICs attached in order. Then:

```bash
incus exec <name> -- cli       # reach the CLI immediately (incus-agent loader)
```

For HA pairs, SR-IOV/passthrough backings, the `launch` (no-YAML) form,
and the fleet pattern, see
[`docs/deploy-quickstart.md`](docs/deploy-quickstart.md) and
[`examples/deploy/README.md`](examples/deploy/README.md). The image bake
itself is documented in [`docs/install-images.md`](docs/install-images.md).

### (C) KVM / QEMU / libvirt

The baked qcow2 boots directly under libvirt/KVM or plain QEMU (UEFI or
BIOS). The day-0 config is supplied as a CD-ROM ISO.

```bash
# Build the day-0 config drive from your xpf.conf (optional but recommended;
# the builder runs the real commit-check and refuses an invalid config):
python3 scripts/image/make_config_drive.py [-n 0|1] -o day0.iso my-xpf.conf

# Boot directly with libvirt (NIC order = positional interface names):
virt-install --name xpf1 --memory 4096 --vcpus 4 \
    --import --disk path=dist/xpf-<ver>.qcow2 \
    --disk path=day0.iso,device=cdrom \
    --network bridge=br-mgmt --network bridge=br-trust \
    --osinfo ubuntu26.04 --noautoconsole
```

Plain QEMU works the same way: `-drive file=dist/xpf-<ver>.qcow2`
`-cdrom day0.iso`.

You can also drive libvirt through the same deployer used for incus —
`scripts/deploy/xpf-deploy.py --hypervisor libvirt deploy <file>.yaml`
builds the day-0 drive and runs `virt-install`, including SR-IOV VF-pool
and PCI-passthrough wiring (add `--dry-run` to print the command instead
of running it). **vNIC / SR-IOV mapping:** the order NICs appear on the
guest PCI bus is the order they are named (`fxp0`, then `ge-0/0/N`),
subject to the virtio-first tiebreaker noted above. For line-rate dataplane ports, pass through a whole PF
(i40e/ice/mlx5, native XDP) or an **mlx5** VF (also native XDP); Intel
VFs fall back to generic-mode XDP (~3-4× slower); virtio/bridge is fine
for mgmt and modest WANs. The backing matrix is in
[`docs/deploy-quickstart.md`](docs/deploy-quickstart.md) and the SR-IOV
caveats in [`docs/critical-patterns.md`](docs/critical-patterns.md).

### Day-0 config & first login

Every path uses the same **day-0 config drive**: a volume labeled
`xpf-config` (or any ISO9660 medium) with `xpf.conf` at its root
(`juniper.conf` accepted as an alias), plus an optional `node-id` file
(`0`/`1`) for cluster members. At first boot the loader re-validates it
with the real commit-check gate and installs it as `/etc/xpf/xpf.conf`. A
rejected config logs loudly (`journalctl -u xpf-day0-config`) and leaves
the box factory-default (fxp0 DHCP + console login). Set SSH credentials
via `system root-authentication` / `system login user ...` in that
config. Full first-boot, credentials, upgrade, and recovery contract:
[`docs/install-images.md`](docs/install-images.md).

---

## Configuration

xpf uses Junos-style configuration syntax — both hierarchical `{ }`
blocks and flat `set` commands:

```junos
interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet {
                address 10.0.1.1/24;
            }
        }
    }
}
security {
    zones {
        security-zone trust {
            interfaces {
                ge-0/0/0;
            }
            host-inbound-traffic {
                system-services {
                    ssh;
                    ping;
                }
            }
        }
    }
    policies {
        from-zone trust to-zone untrust {
            policy allow-all {
                match {
                    source-address any;
                    destination-address any;
                    application any;
                }
                then {
                    permit;
                }
            }
        }
    }
}
```

The same thing as flat `set` commands:

```
set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24
set security zones security-zone trust interfaces ge-0/0/0
set security policies from-zone trust to-zone untrust policy allow-all match source-address any destination-address any application any
set security policies from-zone trust to-zone untrust policy allow-all then permit
```

Pre-flight any config on a build host with
`xpfd check-config [-node-id 0|1] my-xpf.conf` (exit 0 PASS / 2 reject).

## Management interfaces

- **Local CLI**: run `cli` on the firewall for the interactive
  Junos-style shell.
- **Remote CLI**: SSH to the firewall and run `cli` there — the daemon's
  gRPC listener is loopback-only with no TLS, so `-addr <host>:50051`
  cannot reach a remote host (#5035). Port-forwarding
  (`ssh -L 50051:127.0.0.1:50051 user@fw`) plus a local `cli` also works;
  either way the daemon authorizes the firewall-local account owning the
  connection (#5278), never anything the client claims.
- **gRPC API**: 48+ RPCs on port 50051 (config, sessions, stats, routes,
  IPsec, DHCP, cluster).
- **REST API**: HTTP on port 8080 (health, Prometheus `/metrics`, config
  endpoints).

---

## Build from source (development)

```bash
make generate           # Rebuild the retained Rust AF_XDP shim — ONLY when
                        # userspace-xdp/ changed (pinned toolchain + kernel
                        # verifier gate, #1864)
make build              # Build xpfd daemon (uses the git-tracked shim object;
                        # does NOT require make generate)
make build-ctl          # Build remote CLI client
make build-userspace-dp # Build the Rust AF_XDP dataplane binary (needs cargo)
make test               # Run BOTH suites: Go (test-go) + Rust userspace-dp
                        # cargo suite (test-rust). A Rust dataplane
                        # regression fails `make test` (#4006). The Rust
                        # leg needs cargo and takes a few minutes.
make test-go            # Go test suite only
make test-rust          # Rust userspace-dp cargo suite only (needs cargo)
make deb                # Package the binaries into a .deb
make image              # Bake the appliance image (qcow2 + incus metadata)
```

Requirements: Linux kernel ≥ 6.18, Go 1.22+, Rust stable, clang/llvm
(only for `make generate`), FRR (routing), strongSwan (IPsec, optional),
Kea (DHCP server, optional).

The full development process (plan → review → code → review → merge) is
in [`docs/development-workflow.md`](docs/development-workflow.md); the
coding/review discipline is in
[`docs/engineering-style.md`](docs/engineering-style.md).

## Test environment

An Incus-based test environment provisions Debian VMs with FRR,
strongSwan, and test containers, plus a two-VM HA cluster.

```bash
make test-env-init      # One-time setup
make test-vm            # Create a standalone VM
make test-deploy        # Build + deploy + restart service

make cluster-init       # HA: create networks + profile
make cluster-create     # HA: launch fw0 + fw1 + LAN host
make cluster-deploy     # HA: rolling deploy (secondary first)
make test-failover      # iperf3 survives fw0 reboot (session sync + VRRP)
```

The test topology (standalone + HA interface maps) is in
[`docs/network-topology.md`](docs/network-topology.md); test categories,
procedures, and userspace validation are in
[`docs/testing-procedures.md`](docs/testing-procedures.md) and
[`docs/userspace-ha-validation.md`](docs/userspace-ha-validation.md).

---

## Where to go next

**Operating xpf**

- [`docs/install-images.md`](docs/install-images.md) — appliance image
  bake, first-boot contract, credentials, upgrades, recovery.
- [`docs/deploy-quickstart.md`](docs/deploy-quickstart.md) +
  [`examples/deploy/README.md`](examples/deploy/README.md) — the
  positional naming contract, the YAML deployer, SR-IOV/passthrough,
  standalone + HA examples, the fleet pattern.
- [`docs/feature-coverage.md`](docs/feature-coverage.md) — the full
  feature matrix (firewall, NAT, routing, HA, observability, management)
  and the userspace dataplane capability/admission boundary.

**Understanding xpf**

- [`docs/architecture.md`](docs/architecture.md) — control plane +
  dataplane architecture, key design patterns, and the code layout.
- [`docs/network-topology.md`](docs/network-topology.md) — test-VM and
  HA-cluster interface maps.
- [`docs/userspace-dataplane-architecture.md`](docs/userspace-dataplane-architecture.md)
  — the comprehensive AF_XDP dataplane design.
- [`docs/sync-protocol.md`](docs/sync-protocol.md) /
  [`docs/fabric-cross-chassis-fwd.md`](docs/fabric-cross-chassis-fwd.md)
  — HA session-sync wire protocol and fabric cross-chassis forwarding.

**Developing xpf**

- [`docs/development-workflow.md`](docs/development-workflow.md) — how
  changes land.
- [`docs/engineering-style.md`](docs/engineering-style.md) +
  [`docs/critical-patterns.md`](docs/critical-patterns.md) — coding/review
  discipline and the project-specific gotchas (byte order, struct
  alignment, BPF verifier, SR-IOV/XDP, interface management).
- [`docs/config-schema.md`](docs/config-schema.md) — how to add a
  config-mode typed leaf.
- [`docs/feature-gaps.md`](docs/feature-gaps.md) — vSRX feature parity
  tracking.

A fuller index of design docs is in
[`docs/README.md`](docs/README.md).
