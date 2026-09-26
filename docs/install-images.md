# xpf appliance images (#1879 Path C)

vSRX-style prebuilt-image distribution: one bootable root disk, built
offline, carrying everything xpf needs — a REVIEWED-PIN Ubuntu base
(`PINNED_BASE_RELEASE` in `bake.py`, 26.04 LTS today; bumping it is a
deliberate, reviewed commit, **not** auto-latest — #1943), a >= 6.18
kernel (the AF_XDP shim's verifier floor; 26.04 ships 7.0), FRR,
strongSwan, Kea, chrony, systemd-networkd, and the xpf
binaries (`xpfd`, `cli`, `xpf-userspace-dp`) with their systemd units.
There is no dependency matrix to install and no kernel hunt: the image
IS the dependency closure.

Two deliverables, same root disk:

| Artifact | Consumer | Deploy command |
|---|---|---|
| `dist/xpf-<ver>.qcow2` | libvirt/KVM, plain QEMU | `virt-install --import --disk path=...` |
| `dist/xpf-<ver>.incus-metadata.tar.gz` + the same qcow2 | incus (VM) | `incus image import <meta> <qcow2> --alias xpf-appliance` |
| `dist/xpf-<ver>.SHA256SUMS` (+ `.minisig`) | both | minisign-verified, per-file (#1924) |

> **Signed distribution (#1924):** the bake emits a per-version, minisign-signed
> checksum manifest. Fetch + verify from a trusted signed source instead of
> copying files by hand — `xpf-deploy.py fetch --version <ver> --image-url
> $XPF_IMAGE_BASE_URL` downloads, verifies the exact bytes against the signed
> manifest, and imports. The one-command `install.sh` + signed apt repo are the
> package path. See `docs/distribution.md`.
>
> `--version` (both `fetch` and `bake.py`) is validated as a path-safe artifact
> segment before it names any `xpf-<ver>.*` file — allow only
> `[A-Za-z0-9][A-Za-z0-9._+~-]*` (git-describe / semver such as
> `1.2.3-5-gabcdef`, `1.0.0+build.7`, `1.0.0~rc1`), and fail closed on a path
> separator, `..`, absolute path, leading dash, `%`, or the Debian epoch `:`
> (never part of an artifact filename) — so a crafted version cannot redirect
> the download/write out of the output directory (#5992). This mirrors the
> systemd-ExecStart version grammar hardened in #5713.
>
> `fetch` also closes the verify/use gap (#5817): the `--out` directory may be
> writable by another local process, so authenticating an artifact at its public
> pathname and then handing that SAME pathname to libvirt (copy-to-golden) or
> `incus image import` would let a dir-writer swap unauthenticated bytes in
> between the check and the consumer's open. Instead the two in-process consumers
> read from a private 0700 staging dir OUTSIDE `--out` — each consumed artifact
> is copied there and re-verified against the signed manifest, so the bytes the
> consumer reads are exactly the bytes that were verified (the same private-copy
> pattern `sign.verify_and_read` uses). Downloads land in an exclusively-created,
> unpredictable temp (`mkstemp`, O_CREAT|O_EXCL) and publish atomically, so a
> concurrent fetch to the same `--out` cannot collide with or clobber an
> in-flight download via a predictable shared `<dst>.tmp`.

## Bake

```bash
make image            # = python3 scripts/image/bake.py
```

Build-host requirements: the normal xpf build toolchain (Go, cargo),
`libguestfs-tools`, `qemu-utils`, `curl`, `xorriso` (for config
drives), and incus for the validation gate. `/dev/kvm` access makes
the bake fast; the script self-raises `RLIMIT_MEMLOCK` via sudo when
needed (qemu's io_uring).

Pipeline (offline — the image is never booted to provision it):

1. `make deb` (#1917 increment A). This runs `make build build-ctl
   build-userspace-dp` via `debian/rules`, so the #1864 pinned-toolchain
   contract holds — `make build` embeds the git-tracked shim object and
   the bake never runs `make generate` — then packages the freshly built
   binaries into the `xpf` Debian package (binary set staged under
   `/usr/local/share/xpf/staged`). The bake installs that `.deb` instead
   of copying raw binaries.
2. Resolve the base release from the **reviewed pin**
   (`PINNED_BASE_RELEASE = "26.04"`, `bake.py`), then fetch the official
   Ubuntu *server cloudimg* and authenticate it against
   `PINNED_BASE_SHA256` — a trust anchor the mirror does not control.
   An unpinned base is **refused**; see "Base-image pin policy" below.
   Upstream owns partitioning and the UEFI/BIOS bootloader.
3. `virt-resize` the root partition into an 8 GiB work disk
   (`XPF_IMAGE_DISK_SIZE` overrides). This is the *floor* size: an
   operator who provisions a larger root disk gets the extra space
   automatically via the first-boot root auto-grow (#1925, see
   "First-boot root auto-grow" below).
4. `virt-customize` offline: runtime package set (the #1879 plan §5
   dependency matrix; no build toolchain), the cloudimg's reduced
   `linux-virtual` kernel replaced by `linux-generic` (full driver set
   — mlx5/i40e for passthrough NICs live in `linux-modules-extra`)
   with in-bake asserts that the kernel meets the >= 6.18 verifier
   floor and the extra-modules tree is present, **the kernel held
   (`apt-mark hold`) + excluded from unattended-upgrades so an apt run
   cannot move the verifier floor out from under the gated shim .o
   (#1930) — kernel bumps go through the verify-gated LANE-1 channel, not
   background apt; a `needrestart` blacklist keeps an apt run from
   restarting xpfd mid-transaction**, purge of cloud-init
   (a competing network manager), snapd, and the virtual-kernel
   metapackages, systemd-networkd + resolved enabled, FRR + chrony
   enabled (default NTP pools neutered; xpfd manages
   `sources.d/xpf.sources`). FRR is installed WITH `frr-pythontools`
   (`RUNTIME_PACKAGES` + the `xpf-appliance` `Depends`, kept in sync):
   it provides `/usr/lib/frr/frr-reload.py`, the daemon's primary FRR
   reload path (`pkg/frr`). It is NOT pulled in transitively by the
   `frr` package, so it is listed explicitly and a bake-time
   `test -x /usr/lib/frr/frr-reload.py` assert (plus a `validate.py`
   presence check) fails the build if it is ever missing — without it
   every reload silently degrades to the additive `vtysh -f` fallback
   and stale-config removal (a deleted route/BGP neighbor) never
   converges (#4172). Then sysctls, `init_on_alloc=0` (via an
   `/etc/default/grub.d` drop-in — Ubuntu cloud images override
   `GRUB_CMDLINE_LINUX_DEFAULT` there), and `apt-get install ./xpf.deb`.
   The package's `postinst` always stages the binary set into
   `/usr/local/share/xpf/staged`, then sets up the live
   `/usr/local/sbin/{xpfd,cli,xpf-userspace-dp,xpf-day0-config}` symlinks
   (normally through `versions/current`; see the fallback below) and
   enables `xpfd` + `xpf-day0-config` (so the bake no longer hand-copies
   binaries/units or runs `systemctl enable xpfd`). This bake is a FIRST
   install, so it takes the seed path. The four postinst behaviors are
   version-dependent (`$2` is the previously-configured version, empty on
   first install) — the full split is:

   - **First install (#1964 seed)** — `postinst` runs `xpfd seed-runtime`
     (`pkg/upgrade/runtime`), which copies `staged/*` into
     `/var/lib/xpf/versions/<ver>/`, points `versions/current -> <ver>`,
     and repoints each `/usr/local/sbin/*` symlink THROUGH
     `versions/current`. This is what a fresh bake gets: a real, immutable
     rollback target before the first in-place upgrade can ever stop the
     daemon. `versions/` is maintainer-script-managed runtime state, never
     in dpkg's file list, so dpkg only ever writes `staged/`.
   - **Direct-staged fallback** — if `seed-runtime` FAILS, `postinst`
     prints a warning and points the sbin symlinks straight at
     `staged/*` so the daemon still launches (degraded: the next upgrade
     takes the legacy-migration `preinst` path). This is the ONLY case
     where the live symlinks point into the staging path.
   - **Clustered upgrade (stage-only)** — on an upgrade where
     `/etc/xpf/node-id` is present, `postinst` STAGES only and does NOT
     cut. A clustered node is cut solely by `xpfd upgrade --rolling`,
     which sequences a controlled per-node drain so the cluster keeps
     forwarding.
   - **Standalone upgrade (verified cut-over)** — on an upgrade with no
     `node-id`, `postinst` publishes the staged generation and invokes
     `xpfd upgrade`, the verified, atomic, rollback-capable
     STOP->FLIP->START cut to the staged version (kernel verify gate, then
     a unit `ExecStart` pinned to the concrete version so a respawn never
     resolves a mismatched helper).

   The incus-agent loader is still copied in and enabled directly. The
   verified in-place cut-over is owned by the package itself; see
   `docs/in-place-upgrade.md` for the full state machine.
5. `virt-sysprep` seal: machine-id, ssh host keys, logs, tmp files,
   bash history, package caches, random seed, the SNMPv3 EngineID +
   engineBoots (#5283); `/etc/xpf` factory-empty. The operations and the
   purged paths come from `SYSPREP_ENABLE_OPS` / `SYSPREP_PURGE_PATHS` in
   `bake.py` — one source, so the validation gate can bind to it. The gate
   VERIFIES the outcome on the exported artifact before signing (#6547); it
   previously asserted nothing about sealing, so a clone-identity regression
   would have shipped signed.
6. Export compressed qcow2 + incus metadata tarball + the per-version
   `xpf-<ver>.SHA256SUMS` checksum manifest. The manifest is NOT signed
   yet — signing is deferred to AFTER the validation gate (step 8, #4017).
7. **Validation gate** (default on): the image is imported into local
   incus and the FULL first-boot matrix runs — factory boot (fxp0
   DHCP, sshd posture via `sshd -T`, -generic kernel flavor + full
   driver set check) with `xpfd verify-dataplane` IN-GUEST against
   the image's own kernel, plus the valid- and invalid-day-0-drive
   scenarios. A failure fails the bake — the image must never ship a
   verifier-failing shim (#1864/#1869 discipline). Use
   `--skip-validate` only for iteration; such artifacts are not
   publishable.
8. **Sign — ONLY after validation passes (#4017):** the SHA256SUMS
   manifest is minisign-signed to `xpf-<ver>.SHA256SUMS.minisig` when
   `XPF_SIGN_SECKEY` (a path) is set (#1924). A signature is a TRUST
   artifact — downstream publish (`scripts/dist/publish.py`) and
   operators read a signed image as a validated one (#1864 secure-boot
   chain) — so signing runs strictly AFTER the gate. A bake that FAILS
   validation exits non-zero at step 7 and leaves NO `.minisig` behind:
   there is never a signed-but-invalid image. An unsigned dev bake warns
   "not publishable"; `make dist-publish` refuses it.

Each bake also writes `dist/xpf-<ver>.manifest` recording the exact
inputs (base image URL + release + verified SHA256, git commit, bake
date/host kernel). Bakes are not bit-reproducible even at a fixed
base release — the mirror's package versions move between bakes — so
the manifest is the traceability record. The manifest ALSO records the
staged binary's compile-time protocol versions (`ha_protocol_version`,
`ha_protocol_min_compat`, `session_sync_protocol_version`,
`configdb_*_version`, from `xpfd protocol-versions`); the #1930 LANE-2
mixed-base HA gate (`xpf-deploy.py image-roll`) reads these to decide —
without booting the image — whether a rolling image-replace can preserve
sessions across the mixed-base window or must replace both nodes at once.
See `docs/in-place-upgrade.md` (Kernel / OS upgrade lanes) for the full
LANE-1/2/3 decision rule and the state-carry contract.

### Base-image pin policy (#1943 / #4904-B)

The base is a **reviewed pin**, not mirror-latest. Two constants in
`scripts/image/bake.py` are the contract:

| Constant | What it pins | How it moves |
|---|---|---|
| `PINNED_BASE_RELEASE` | the Ubuntu release (`"26.04"`) | a reviewed commit (a PR), never automatically |
| `PINNED_BASE_SHA256` | that release's base-image digest | a reviewed commit, after re-verifying Canonical's GPG-signed `SHA256SUMS` against the UEC signing key `D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81` |

The old default scraped `cloud-images.ubuntu.com` and took the
highest-numbered listing, which silently selects whatever the mirror
calls newest — a non-LTS (26.10), or the *previous* release (25.10) when
an LTS image lags publication. That drift is what the pin forbids.

The digest pin is a supply-chain **trust anchor**, not a convenience: the
image and its `SHA256SUMS` come from the same configurable mirror
endpoint, so a same-endpoint checksum authenticates nothing against a
compromised mirror or a TLS/DNS/CA compromise — the mirror can serve
matching malicious bytes *and* hash, and xpf would then sign the result
with its RELEASE key.

**Refusals you can expect** (all `die()`, non-zero exit):

- the downloaded base digest does not match `PINNED_BASE_SHA256` — a
  wrong/compromised mirror, or a stale pin after a Canonical respin
  (re-verify the GPG-signed `SHA256SUMS`, then bump the pin in a
  reviewed commit);
- the resolved release has **no** pin entry and no `XPF_BASE_SHA256` —
  the bake refuses rather than trusting a same-endpoint checksum.

**Opt-in overrides** (all one-off, none of them the default):

| Env var | Effect |
|---|---|
| `XPF_BASE_RELEASE=<rel>` | use `<rel>` instead of `PINNED_BASE_RELEASE` for this run |
| `XPF_BASE_SHA256=<digest>` | supply the trust anchor for this run (e.g. a point respin between reviewed bumps); wins over the repo constant |
| `XPF_UBUNTU_AUTODISCOVER=1` | opt back into mirror-latest discovery — off by default |
| `XPF_ALLOW_UNPINNED_BASE=1` | proceed with an unauthenticated base. The bake warns loudly and the manifest records `base_image_pinned: false` |

An `XPF_ALLOW_UNPINNED_BASE=1` bake is **not publishable**:
`publish.py`'s `gate_provenance` refuses `base_image_pinned != true`
fail-closed (#5815), with no override — a signed unpinned image is not
releasable. The test VM follows the same policy: `test/incus/setup.sh`
tracks whatever release production was last baked at, deliberately,
rather than the newest Ubuntu on the day you run `make test-vm`.
**What the image SHIPS (#6500).** `bake_host_kernel` above is the BUILD
HOST's kernel (`os.uname().release`) and answers a different question
from "what does this image carry". Two additional records close that:

- `guest_kernel:` in the `.manifest` — the kernel the IMAGE runs, i.e.
  the exact artifact the #1930 LANE-1 channel promotes.
- `dist/xpf-<ver>.pkgs` — the full installed package inventory
  (`name=version`, one per line, plus the guest kernel), **covered by the
  signed `xpf-<ver>.SHA256SUMS`** exactly like the `.manifest` sidecar
  (#5042), so it is authenticated the moment the manifest signature
  verifies.

The bake writes the same record INSIDE the image at
`/etc/xpf/image-inventory` and reads it back out **offline with
`virt-cat`** — no boot — so "does release X ship openssl 3.x.y
(CVE-YYYY)?" and "which kernel does image X carry, so I can plan a
LANE-1 arm?" are answered from the dist tree, and the copy that stays in
the image answers them on the box too.

Both are **fail-closed at publish**: `publish.py gate_provenance` refuses
a release whose manifest has no `guest_kernel`, whose `.pkgs` sidecar is
missing or not covered by the signed manifest, whose inventory is HOLLOW
(a present-but-empty record satisfies a presence check and answers
nothing), or whose two authenticated records disagree about the kernel —
alongside the existing `validated` / `base_image_pinned` refusals. The
format lives in `scripts/dist/image_inventory.py`, single-sourced because
bake.py writes it and publish.py reads it and a divergence between those
is always a bug.

Full first-boot matrix (run after a bake, or standalone):

```bash
python3 scripts/image/validate.py --qcow2 dist/xpf-<ver>.qcow2 \
    --metadata dist/xpf-<ver>.incus-metadata.tar.gz all
```

Scenarios (`a|b|c|d|e|q|all`, default `all`):

| key | proves |
|-----|--------|
| `a` | factory bootstrap (no drive): xpfd active, fxp0 DHCP, sshd, in-guest `verify-dataplane` |
| `b` | valid day-0 drive: validated + installed + committed; reboot does NOT re-apply |
| `c` | invalid drive: commit-check REJECT, nothing installed, boot survives; **then** a fixed drive + reboot DOES apply (the fix→reboot→applied retry contract, pairs with the day-0 `active.json` guard) |
| `d` | resized disk: first-boot root auto-grow, idempotent on reboot, ESP intact |
| `e` | cluster node-id drive: `node-id=1` persisted to `/etc/xpf/node-id`, cluster naming (`em0` + node-1 `ge-7/0/N`) |
| `q` | libvirt/plain-QEMU bootability: the qcow2 is a valid, non-corrupt qcow2 ≥ the 8 GiB bake floor (always), and — gated on `qemu-system-x86_64` + `/dev/kvm` + OVMF — actually boots under direct QEMU with the day-0 config on a cdrom |

Scenarios `a`–`e` need local incus; `q`'s boot leg needs qemu + KVM +
OVMF and SKIPs (its config-level qcow2 probe still runs) when they are
absent, like the root-required skips.

Hermetic self-tests (no hypervisor, run in the `make selftest` runner —
see below): `scripts/image/test_validate_scenarios.py` covers the pure
pieces the incus/QEMU scenarios hinge on (the qcow2 bootability verdict,
OVMF discovery order, the scenario registry, and the node-id drive
round-trip).

> **Deploying at scale?** `docs/deploy-quickstart.md` +
> `examples/deploy/README.md` are the operator runbook: the positional
> naming contract, the Python deployer (`scripts/deploy/xpf-deploy.py`
> — YAML-driven, incus/libvirt, builds the day-0 drive in-process),
> validated standalone/HA example definitions, SR-IOV/passthrough, and
> the fleet pattern. The sections below are the raw mechanics it builds
> on. (`scripts/image/make_config_drive.py` shown here is the image
> bakery's config-drive tool; the Python deployer builds drives
> in-process too.)

## Deploy quickstart — incus

```bash
incus image import dist/xpf-<ver>.incus-metadata.tar.gz \
    dist/xpf-<ver>.qcow2 --alias xpf-appliance

# Optional day-0 config drive (see below):
python3 scripts/image/make_config_drive.py -o day0.iso my-xpf.conf

incus init xpf-appliance xpf1 --vm -c limits.cpu=4 -c limits.memory=4GiB
incus config device add xpf1 day0 disk source=$PWD/day0.iso
incus start xpf1
```

The image carries the incus-agent loader (inert outside incus), so
`incus exec xpf1 -- cli` works immediately. Add revenue NICs as extra
devices before start; vNIC order maps to vSRX names (below).

## Deploy quickstart — libvirt/KVM

```bash
virt-install --name xpf1 --memory 4096 --vcpus 4 \
    --import --disk path=xpf-<ver>.qcow2 \
    --disk path=day0.iso,device=cdrom \
    --network bridge=br-mgmt --network bridge=br-trust \
    --osinfo ubuntu26.04 --noautoconsole
```

Plain QEMU works the same way (`-drive file=xpf-<ver>.qcow2`
`-cdrom day0.iso`); the image boots UEFI or BIOS.

The tool-driven path is `xpf-deploy.py --hypervisor libvirt deploy`, which
reads the golden qcow2 from `/var/lib/libvirt/images/<image>.qcow2` and gives
each VM its own copy-on-write overlay. Put the verified image there with
`xpf-deploy.py fetch --version <ver> --qcow2-only --install-libvirt` (see
`docs/distribution.md`) so fetch and deploy use the same path.

## First-boot contract (vSRX parity)

| vSRX | xpf image |
|---|---|
| First vNIC is fxp0 (OOB mgmt), rest map to ge-0/0/N in attach order | Identical: `enumerateAndRenameInterfaces()` assigns fxp0 / em0 (cluster) / ge-X-0-N by PCI bus order |
| Factory default: fxp0 DHCP, root console login, no password | Identical: fxp0 DHCP bootstrap (gated on the `/etc/xpf/appliance` marker — see below); root login on the hypervisor console with empty password; sshd refuses empty/root-password auth |
| Day-0 config: ISO with `juniper.conf` at the root, attached as CD-ROM | ISO (or any volume labeled `xpf-config`) with `xpf.conf` at the root — `juniper.conf` accepted as an alias; optional `node-id` file (`0`/`1`) for cluster members |
| Bad day-0 config: boots factory-default | Identical, but stricter: the config is validated with the REAL commit-check gate (`xpfd check-config`) BEFORE install; a REJECT logs loudly and the system stays factory-default |
| Day-0 applied once | Applied at most once: stamped after success; never clobbers an existing config (a COMMITTED `.configdb/active.json` or a preseeded `xpf.conf`). A REJECTED medium does not stamp — fix the config and reboot to retry while the system is still factory-default |

Day-0 loader specifics (`scripts/image/xpf-day0-config`, oneshot unit
`Before=xpfd.service`):

- Probes volumes labeled `xpf-config` (any filesystem) **first**, then
  any ISO9660 medium. That order is the contract, not an accident:
  a labeled volume is explicit operator intent and the ISO is the
  vSRX-parity fallback, so with two valid-but-different media attached
  the **labeled volume's** config is the one installed and stamped.
  The dedup deliberately preserves first-appearance order
  (`awk 'NF && !seen[$0]++'`) rather than sorting — `| sort -u`
  alphabetized the merged list, so an ISO at `/dev/sda` beat a labeled
  volume at `/dev/sdb`, and any `/dev/sd*` ISO beat a virtio-blk
  `/dev/vd*` volume (#6502). Kernel device-name order is not operator
  intent. A medium that is both labeled and ISO9660 is probed once, in
  its labeled position. Mounted `ro,nosuid,nodev,noexec`; only the two
  fixed filenames at the volume root are considered; 4 MiB size cap;
  validation under timeout. Nothing on the medium is executed.
- On PASS, the optional HA `node-id` is installed durably before
  `/etc/xpf/xpf.conf` becomes visible. The config is installed mode 0600
  (it may carry credential material) via a same-directory temporary file,
  file fsync, atomic rename, and directory fsync. The success stamp is also
  durable and written last. xpfd's normal bootstrap-from-file import commits
  the config at startup, but refuses a zero-length config instead of committing
  an empty tree. No second config ingestion mechanism exists.
- Failures never block the boot: the unit is ordering-only (no
  `Requires=`), the script always exits 0, and `TimeoutStartSec`
  backstops a hung mount. Fallback is always the factory bootstrap.
- The "already configured, skip the probe" guard tests
  `/etc/xpf/.configdb/active.json` (a COMMITTED config), NOT the bare
  `.configdb` directory. xpfd creates that directory on EVERY start
  (`configstore.NewDB` → `MkdirAllDurable`, before any commit), so its
  mere existence is not a "configured" signal — guarding on it would
  make a box that booted once (empty `.configdb` present) permanently
  skip the probe, killing the fix-and-reboot retry above. A box in
  factory bootstrap has no `active.json`, so the loader re-probes.

### "My day-0 config did not apply" — where to look (#4184 / #6496)

The boot-time config-import decision is RECORDED, so this is a question with an
in-band answer rather than a journald hunt. From the CLI on the box (console or
ssh, local `cli` or remote):

```
> show system bootstrap-import
Bootstrap configuration import:
  Status:   import-failed
  Meaning:  a configuration file was present but could NOT be applied — see Error below
  Recorded: 2026-08-21 14:02:11 UTC
  Error:    day-0 config REJECTED by commit-check: ...

  The box is in the lifeline-safe bootstrap state; ...
```

The four statuses are `ok` (imported + committed), `loaded-from-db` (an active
config was already present, so no file import was attempted — the normal
steady-state boot), `no-config` (nothing to import: the expected factory boot),
and `import-failed` (a file was present but could not be read, parsed,
committed, or survived the device-map strand preflight).

`import-failed` is INFORMATIONAL, not a fault state: the box is in the
lifeline-safe bootstrap state and still reachable, so neither this command nor
`/health` treats it as a reason to pull the box. It also emits a
`BOOTSTRAP_IMPORT_FAILED` event.

The same status is on the loopback REST probe for scripted checks:

```
curl -s http://127.0.0.1:8080/health | jq '.data | {bootstrap_import_status, bootstrap_import_failed, bootstrap_import_unix}'
```

Use the CLI when you need the **reason**. `/health` deliberately reports the
status enum, the failed flag and the timestamp but NOT the error text: that
endpoint is unauthenticated, and an import error quotes the offending
configuration, which can echo a submitted secret (#5031). The CLI and gRPC
paths are authenticated, so they are the only surfaces that can tell you why.

### The `/etc/xpf/appliance` marker (#7114)

The bake writes `/etc/xpf/appliance` into the image. It is what makes the
factory `fxp0` DHCP bootstrap above happen at all.

xpfd's #1922 bootstrap lifeline identifies the management NIC by the ACTIVE
DEFAULT ROUTE, and refuses to rename or bring up anything when it cannot find
one — the right call on a **foreign host** where xpf was installed from the
`.deb` and the operator's own network configuration is the lifeline. The
appliance has no such configuration: the bake purges cloud-init and deletes
every netplan / `interfaces.d` file, so a factory boot with no day-0 drive has
no route, no address, and nothing to preserve. Without the marker that boot
leaves every port DOWN and unrenamed — reachable only from the hypervisor
console.

With the marker present AND nothing ever committed on the box, xpfd claims the
first enumerated NIC as `fxp0` and DHCPs it, which is the image's vNIC#1 →
fxp0 contract. Both conditions are required:

- The `.deb` postinst never writes the marker, so a foreign-host install keeps
  the console-only refusal.
- A box that HAS been configured is excluded even when it boots into bootstrap
  mode via the #1960 fail-closed path (a committed config that no longer
  compiles): its intended interface bindings are real and unknown — possibly a
  `chassis device-map` that wants no auto-`fxp0` at all — so claiming NIC 0
  there would be exactly the mis-binding #1960 refuses to perform.

Deleting the marker on a running appliance gives that box the foreign-host
posture. A factory reset does not remove it (the reset erases an exact,
xpf-owned allowlist of config artifacts), so a zeroized appliance comes back up
in the factory `fxp0`-DHCP posture — which is the vSRX behaviour.

The zeroize pending marker uses the reserved basename `.day0-config-applied`;
a configured config file with that basename is rejected before the wipe begins.

Build a config drive:

```bash
python3 scripts/image/make_config_drive.py [-n 0|1] [-o day0.iso] my-xpf.conf
```

When an `xpfd` binary is present, the builder runs the same
commit-check and refuses to build an ISO the appliance would reject.

## First-boot root auto-grow (#1925)

The image ships an 8 GiB root disk (`XPF_IMAGE_DISK_SIZE`). When you
deploy onto a larger disk — `incus init ... -d root,size=40GiB`,
`qemu-img resize`, or a bigger libvirt volume — the extra space is
unallocated GPT free space and `/` cannot use it until the root
partition + filesystem are grown. The appliance does this **once, on
first boot, automatically**:

- `scripts/image/xpf-grow-root.service` (oneshot, `RemainAfterExit`,
  `ConditionPathExists=!/etc/xpf/.root-grown`) runs early — ordered
  `After=systemd-remount-fs.service` and `Before=local-fs.target
  xpfd.service xpf-day0-config.service` — so `/var` is full-size before
  xpf stages its versioned runtime (#1964) or writes the config DB. It
  stamps `/etc/xpf/.root-grown` on success and never runs again.
- `scripts/image/xpf-grow-root` resolves the device backing the live
  root mount from `findmnt /` (bus-agnostic — `vda`/`sda`/`nvme0n1pN`),
  then `growpart <disk> <partnum>` followed by `resize2fs <rootdev>`.
  On an exact-bake-size deploy both are no-ops (`growpart` returns
  `NOCHANGE` when there is no trailing free space; `resize2fs` is a
  no-op when the fs already fills the partition), and the script never
  blocks the boot — every failure path is non-fatal.

This restores exactly what the stock cloudimg's cloud-init
`growpart`/`resizefs` modules did before the bake purged cloud-init —
a known-good, expected-of-every-cloud-image behavior — using `growpart`
(from `cloud-guest-utils`) and `resize2fs` (from `e2fsprogs`). The bake
installs both EXPLICITLY (in `RUNTIME_PACKAGES` and the `xpf-appliance`
metapackage `Depends`): `growpart` is only in the stock cloudimg via
cloud-init, so the cloud-init purge + `apt autoremove` would otherwise
remove it. A bake-time `command -v growpart` assert fails the build if
the provider is ever missing.

**Why `growpart`/`resize2fs` and not `systemd-repart`:** they can only
*grow a partition's end into adjacent free space* and *grow* an ext4
filesystem. They cannot create, reformat, shrink, or move a partition
by construction — there is no `Format=`/`CopyBlocks=` knob to mis-set.
That is the smallest possible data-loss surface, deliberately chosen
over `systemd-repart` (which would also add a runtime package to a
minimized image).

**Why this is safe for the #1930 A/B kernel channel:** the LANE-1 A/B
"slots" are **directories inside the single ESP partition**
(`/boot/efi/EFI/xpf-A`, `xpf-B`) plus the `/etc/grub.d/09_xpf`
`$cmdpath` selector — they are NOT separate GPT partitions, and kernels
live in `/boot`. The root partition is the **physically last partition**
in the canonical Ubuntu cloudimg layout, so growing it into trailing
free space cannot touch the ESP (and the A/B dirs, selectors, and
shim/grub it holds), the BIOS-boot or `/boot` partitions, or any
partition *number* — `growpart` only edits the selected partition's
end and never renumbers. The grow signs nothing and does not alter the
ESP, so the Secure Boot posture and the kernel promote/rollback channel
are untouched. (If a future bake change ever added a trailing partition
*after* root, this "grow the last partition" assumption would need
revisiting.)

Validation: `scripts/image/validate.py d` (also part of `all`) boots a
baked image under local incus with a 20 GiB root disk and asserts the
root partition + filesystem grew past the 8 GiB floor, the grow is
idempotent across a reboot, the ESP stays mounted, and `verify-dataplane`
still passes; a control instance at the exact bake size proves the grow
is a clean no-op.

## Credentials / security posture

- No default password over the network, ever. The root password is
  empty: login works on the hypervisor console only. The image pins
  this explicitly — `/etc/ssh/sshd_config.d/10-xpf-factory.conf` sets
  `PermitRootLogin prohibit-password` + `PermitEmptyPasswords no`
  (not relying on distro defaults), and the validation harness
  asserts the effective `sshd -T` output.
- Headless/SSH access comes from the day-0 config (`system
  root-authentication`, `system login user ...`) — set credentials
  there, or use the console once and `commit` a config.
- The image ships no ssh host keys, no machine-id, no SNMPv3 EngineID and
  no random-seed, and no logs; each is regenerated per-instance at first
  boot, so no per-device identity is shared across clones. This is
  ENFORCED, not merely performed: the pre-sign validation gate reads the
  exported qcow2 offline and refuses to let an unsealed image be signed
  (#6547). Before that it was performed and never verified, so a member
  silently falling out of the seal would have shipped a signed image whose
  every clone answered SSH with the same host key and accepted every other
  clone's authenticated SNMPv3 requests.
- Verify artifacts with their minisign-signed per-version manifest
  (#1924): `xpf-deploy.py fetch` verifies the exact bytes against
  `xpf-<ver>.SHA256SUMS` + `.minisig`, or verify manually with
  `minisign -V -p scripts/dist/xpf-image.pub -m xpf-<ver>.SHA256SUMS
  -x xpf-<ver>.SHA256SUMS.minisig` then check each file's hash. The signed
  apt repo + `install.sh` are the package path — see `docs/distribution.md`.

## Upgrades

The vSRX "replace-image" model: deploy a new VM from the new image. Before
the swap, export the running node's CURRENT committed config from the
config DB to hierarchical day-0 text:

```sh
xpfd export-config /var/tmp/current-xpf.conf
```

Copy that exported file to the replacement image's day-0 drive as `xpf.conf`
(and copy `/etc/xpf/node-id` separately for HA identity), then swap traffic.
The export is the portable artifact; **do not copy the install-time
`/etc/xpf/xpf.conf`**, which stays at its day-0 contents after later commits.
Do not copy `.configdb` or `master.key` to a fresh image: the new image
generates a new key and cannot decrypt the old DB. For HA pairs this is
`deploy_rolling()` at VM granularity: replace the secondary, wait for session
sync, fail over, replace the primary. Kernel + userspace move as one tested
unit. HA config-sync behavior during image replacement is a separate
amplification follow-up and is out of scope here.

In-place binary upgrades inside a running appliance follow the #1869
ordering invariant: copy the new binaries into a versioned runtime dir,
run `xpfd verify-dataplane` against the staged version FIRST, and only on
PASS stop/flip/start. The `xpf` package owns this verified cut path: a
plain `apt install ./xpf.deb` (or `apt upgrade xpf`) stages the new
binaries and then runs the cut itself — `xpfd upgrade` on a standalone
node, or stage-only (cut deferred to `xpfd upgrade --rolling`) on a
clustered node. There is no separate `xpf-upgrade` wrapper. See
`docs/in-place-upgrade.md` for the full state machine and rollback
contract (`test/incus/cluster-setup.sh deploy_vm()` exercises it).

### #7163 — session-sync is a FLAG DAY at wire version 2

**Upgrading to a build carrying #7163 DROPS SYNCED SESSIONS. Both nodes must
move; there is no rolling window.**

#7163 replaced the session-sync authentication handshake with Noise_NNpsk0 to
close the #5078 vector-B proof oracle. A pre-#7163 peer sends the old HELLO,
which is not a valid Noise message, so a mixed pair does not establish a
session-sync connection at all — every frame type on that stream stops, not just
the handshake.

The gate is already wired, and it fails CLOSED rather than letting an operator
discover this as a fabric that will not come up: `cluster.SessionSyncWireVersion`
went 1 → 2, and `upgrade.GateMixedBaseSwap` matches the session-sync protocol
EXACTLY, so a LANE-2 image-replace of the second node returns
`SessionsSurvive=false` with `session-sync protocol differs (peer 1, new image
2)`. `deploy_rolling()` therefore refuses the session-preserving path and tells
you to replace both nodes.

`CurrentHAProtocolVersion` is deliberately NOT bumped. Bumping it would
additionally refuse the peer over heartbeat/failover semantics #7163 does not
touch — a second, unnecessary failure on top of the one the change genuinely
costs. #7925 split the two counters precisely so a session-wire change stops
dragging the HA protocol out from under its own compat floor.

What this means in practice:

- Plan the upgrade as a maintenance window, not a rolling one. Sessions
  established before the swap do not survive it.
- Traffic still fails over: VRRP, the heartbeat and the fabric gRPC listener are
  unaffected. What is lost is the SYNCED SESSION TABLE, so flows crossing the
  failover are re-established rather than preserved.
- Do not key a cluster for the first time during this upgrade. Keying a live
  cluster relies on the established session-sync connection carrying the key to
  a read-only secondary (`pkg/cluster/README.md`, "Rollout"), and there is no
  established connection across a mixed pair.

## Recovery

- Lost mgmt connectivity after a bad commit: use the hypervisor
  console (`incus console xpf1` / `virsh console xpf1`), log in as
  root, run `cli`, `configure`, `rollback 1`, `commit`.
- Unbootable/maimed instance: redeploy from the image and re-apply the current
  export created with `xpfd export-config` via a day-0 drive; never reuse the
  install-time `xpf.conf`.
- Day-0 config rejected at first boot: `journalctl -u xpf-day0-config`
  shows the commit-check error verbatim. Fix the config, rebuild the
  ISO, reboot — the system is still factory-default, so the loader
  retries.
- Pre-flight any config on the build host:
  `xpfd check-config [-node-id 0|1] my-xpf.conf` (exit 0 PASS / 2
  reject).

## Validation

`docs/image-validation.md` is the full validation runbook: Tier 1
(automated first-boot gate via `scripts/image/validate.py` — boot,
single ≥6.18 kernel, in-guest `verify-dataplane`, day-0 valid/invalid),
Tier 2 (standalone forwarding + SNAT, manual), and Tier 3 (HA pair
forwarding + failover, manual). Tier 1 gates the bake; Tiers 2–3 push
real traffic and prove the image actually routes.

### Self-tests — `make selftest`

The day-0/image/dist/deploy tooling has a suite of hermetic self-tests
(no root, no incus, no cluster, no network). `make selftest`
(`scripts/run-selftests.sh`) is the single entry point that discovers and
runs them all in one fast pass — before this they were reachable from no
target and a regression re-introducing sign-before-validate (#4017) or
breaking the grow-root stamp discipline (#2047) merged green. A leg whose
external tool is missing SKIPs rather than fails, so the runner is green
on a minimal host and only goes RED on a genuine regression. It covers:

- shell parse-check (`sh`/`bash -n`) + `shellcheck` over the image/dist
  shell scripts (`xpf-day0-config`, `xpf-grow-root`, `xpf-uefi-slots`,
  `xpf-kernel-promote`, `selftest.sh`, …). That list is a HAND enumeration,
  so `scripts/test_selftest_lint_coverage_6499.py` guards it both ways:
  every shipped `scripts/image/xpf-*` shell script must be listed (a
  shipped production script with no parse check at all — #6499), and
  every listed path must still exist (`run-selftests.sh:103` skips a
  missing path silently, so a rename deletes a lint leg without a word
  in the output);
- `scripts/image/test-grow-root.sh` — grow-root device resolution + stamp
  discipline (#1925);
- `scripts/image/test_uefi_slots_6499.py` — the **boot-firmware**
  registrar's destructive paths (#6499). `xpf-uefi-slots` mutates firmware
  NVRAM on every boot of every shipped appliance — it deletes boot
  entries, dedups them, and rewrites BootOrder — and `sh -n` +
  `shellcheck` cannot see that a logic change wipes a customer box's
  PXE/recovery entries or undoes a promoted kernel slot. The real script
  runs under a real `/bin/sh` with a mock `efibootmgr` modelling NVRAM as
  state files, so regression fixtures cover the classes a reviewer caught
  during #1930 and the non-xpf-front reseed regression: wrong-loader-path
  deletion, duplicate dedup, promoted-slot and operator-selected non-xpf
  BootOrder preservation, and the empty-BootOrder no-write guard (a reseed
  built from an unreadable BootOrder would emit `--bootorder <A>,<B>` and wipe
  everything else). `[ -b "$ESP_DISK" ]` is
  not relaxed by a test hook — the mock names a partition of a real host
  block device — and only two path roots are overridable
  (`XPF_UEFI_SLOTS_EFIVARS`, `XPF_UEFI_SLOTS_ESP`), the same pattern
  `xpf-grow-root` uses;
- `scripts/image/test_kernel_promote_explicit_path.py` — the promotion
  gate's authority model AND its rc contract (`0` → continue, `3` →
  reboot to known-good and still exit 0, `1`/other → infra error, do NOT
  reboot into a bounce loop);
- `scripts/image/test_bake_sign_ordering.py` — VALIDATE-before-SIGN
  ordering (#4017) + frr-pythontools presence;
- `scripts/image/test_validate_scenarios.py` — the `validate.py` scenario
  pure helpers (#4209 H-9);
- `scripts/dist/selftest.sh` — the signed-distribution roundtrip
  (sign → verify → tamper-fails → apt repo → `install.sh --dry-run`,
  throwaway key; SKIPs without minisign/gpg/apt-ftparchive);
- `scripts/deploy/test_xpf_deploy_*.py` — the deployer's pure functions,
  NIC ordering, per-VM disks, and the **mixed-base HA safety gate**
  (`_gate_mixed_base`, the Python mirror of `upgrade.GateMixedBaseSwap`)
  with the same parity vectors as the Go test (#4211 H-24).

The incus/QEMU image boot matrix (`validate.py`) and the loss-cluster
smokes need a hypervisor and are NOT part of `make selftest` — they have
their own entry points (above, and `make test-failover` / `docs/…`).

## What the image does NOT solve

AF_XDP line-rate behavior remains coupled to the NIC driver exposed to
the VM (mlx5/i40e native XDP vs virtio vs iavf-generic) — see
`CLAUDE.md` "XDP on SR-IOV Interfaces". The image guarantees the
kernel side (>= 6.18, verifier-passing shim, `init_on_alloc=0`);
passthrough/VF topology is the operator's hypervisor decision.
