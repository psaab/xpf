#!/usr/bin/env python3
"""xpf appliance image bake (#1879 Path C — vSRX-style prebuilt image), in Python.

Builds ONE bootable root-disk image OFFLINE (libguestfs — never boots the
image to provision it) and exports it for both hypervisors:

  dist/xpf-<ver>.qcow2                  - libvirt/KVM (virt-install)
  dist/xpf-<ver>.incus-metadata.tar.gz  - incus VM image metadata
  dist/xpf-<ver>.manifest               - build + HA/session-sync protocol
                                          metadata (mixed-base image-roll gate);
                                          COVERED by the signed SHA256SUMS (#5042)
  dist/xpf-<ver>.SHA256SUMS             - per-version checksum manifest (#1924),
                                          covering the qcow2, incus metadata, AND
                                          the .manifest sidecar (#5042)
  dist/xpf-<ver>.SHA256SUMS.minisig     - minisign signature over the manifest
                                          (only when XPF_SIGN_SECKEY is set)

Pipeline: build the xpf .deb (`make deb`; no `make generate` — embeds the
#1864 tracked shim) -> discover + fetch the Ubuntu cloud image and
authenticate it against the repo-PINNED SHA256 (a trust anchor NOT under
the mirror's control; #4904 B — a same-endpoint checksum alone is not an
authenticator) -> virt-resize root into a work disk ->
virt-customize (runtime packages, linux-generic >= 6.18 with the full
driver set, purge cloud-init/snapd/stale kernels, HOLD the kernel so apt
cannot move the verifier floor (#1930), networkd, init_on_alloc=0,
`apt-get install ./xpf.deb` which stages the binaries + creates the
/usr/local/sbin symlinks + enables the units via its postinst)
-> virt-sysprep seal -> virt-sparsify+compress export -> checksums +
manifest -> in-guest verify-dataplane validation gate (validate.py) ->
minisign the manifest ONLY after the gate passes (#4017: a signature is a
trust artifact, so a failed bake must never leave a signed image).

Requirements: make/go/cargo, libguestfs-tools, qemu-utils, curl; incus for
the validation gate. /dev/kvm makes libguestfs fast.

Usage:
  bake.py [--version V] [--out DIR] [--skip-build] [--skip-validate] [--keep-work]
"""

import argparse
import os
import re
import resource
import shutil
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))

# Signed-distribution helpers (#1924) live under scripts/dist.
sys.path.insert(0, os.path.join(ROOT, "scripts", "dist"))
import image_inventory  # noqa: E402  (#6500 inventory format)
import sign  # noqa: E402

# Runtime dependency set installed explicitly into the image. This is the
# same set the xpf-appliance metapackage Depends on (debian/control). The
# bake installs the runtime packages explicitly + the xpf BINARY package,
# rather than the metapackage, so apt does not have to resolve the full
# dependency closure against a single local .deb during the offline bake;
# the xpf-appliance metapackage is the operator-facing `apt install`
# entry point (e.g. from a future hosted repo, #1924). Keep this list and
# the metapackage Depends in debian/control in sync.
RUNTIME_PACKAGES = [
    # #4172: frr-pythontools provides /usr/lib/frr/frr-reload.py, the
    # daemon's PRIMARY FRR reload path (pkg/frr/vtysh.go frrReloadScript,
    # invoked from pkg/frr/manager.go). It is NOT pulled in transitively by
    # the `frr` package, so it MUST be listed explicitly here (and in the
    # xpf-appliance Depends, kept in sync per the comment above). Without it
    # every reload silently falls back to the additive `vtysh -f` path and
    # the degraded-retry loop never converges stale-config removal — a
    # deleted route/BGP neighbor keeps forwarding/advertising. A bake-time
    # hard-assert below (`test -x /usr/lib/frr/frr-reload.py`) fails the bake
    # loudly if a future frr package-name drift drops the tool.
    "frr", "frr-pythontools", "strongswan", "strongswan-swanctl",
    "kea-dhcp4-server", "kea-dhcp6-server", "chrony",
    "iproute2", "nftables", "ethtool", "tcpdump", "pciutils",
    "iputils-ping", "traceroute", "openssh-server", "openssh-client",
    "systemd-resolved", "rsyslog", "curl", "ca-certificates",
    # #1925: growpart (cloud-guest-utils) + resize2fs (e2fsprogs) back the
    # first-boot root auto-grow (xpf-grow-root). growpart is in the base
    # cloudimg ONLY transitively via cloud-init, which this bake purges and
    # autoremoves — so it MUST be installed EXPLICITLY here or the
    # autoremove orphans it and the grow silently no-ops on every boot. On
    # Ubuntu 26.04 the package providing /usr/bin/growpart is
    # cloud-guest-utils. e2fsprogs (resize2fs) is a base package, listed
    # belt-and-suspenders so a future base change can't orphan it either.
    "cloud-guest-utils", "e2fsprogs",
]

# #9725: kernel transit forwarding starts CLOSED. xpfd's transit gate opens it
# when the dataplane is armed with a live attached link; a 1 here would forward
# transit, with no program adjudicating it, from boot until then.
SYSCTL_CONF = (
    "net.core.bpf_jit_enable=1\n"
    "net.ipv4.ip_forward=0\n"
    "net.ipv6.conf.all.forwarding=0\n"
    "net.ipv6.conf.all.accept_ra=0\n"
    "net.ipv6.conf.default.accept_ra=0\n"
)

# apt-get update exits 0 even when an index fetch fails; --error-on=any
# makes that fatal, one retry covers a transient blip.
APT_UPDATE = ("apt-get update -qq -o Acquire::Retries=5 --error-on=any || "
              "{ echo 'apt update failed; retrying in 10s' >&2; sleep 10; "
              "apt-get update -qq -o Acquire::Retries=5 --error-on=any; }")

GRUB_DROPIN = (
    '# xpf (#1879): init_on_alloc=0 — CONFIG_INIT_ON_ALLOC_DEFAULT_ON zeroes\n'
    '# every allocated page (~20% CPU in the virtio-net XDP path). A grub.d\n'
    '# drop-in, NOT a sed on /etc/default/grub: Ubuntu cloud images override\n'
    '# GRUB_CMDLINE_LINUX_DEFAULT in /etc/default/grub.d/50-cloudimg-settings.cfg.\n'
    'GRUB_CMDLINE_LINUX_DEFAULT="$GRUB_CMDLINE_LINUX_DEFAULT init_on_alloc=0"\n'
    '# xpf (#1930): flatten the menu so the LANE-1 A/B selector menuentry\n'
    '# (/etc/grub.d/09_xpf) is a stable top-level entry and submenu reordering\n'
    "# by update-grub can't bury a candidate (r2/r5 AGY).\n"
    'GRUB_DISABLE_SUBMENU=y'
)

SSHD_DROPIN = (
    '# xpf factory posture (#1879): root password is EMPTY (console-only\n'
    '# login, vSRX parity). Pin the OpenSSH defaults explicitly.\n'
    'PermitRootLogin prohibit-password\n'
    'PermitEmptyPasswords no'
)


def info(m):
    print(f"==> {m}")


def die(m):
    sys.exit(f"ERROR: {m}")


# #5992: the version is interpolated into artifact WRITE paths — qcow_out /
# meta_out / the SHA256SUMS manifest, all `os.path.join(a.out, "xpf-<ver>.…")`.
# A path separator / `..` / absolute path / leading dash in `--version` would
# escape `--out` or be read as a CLI flag. Validate it against a version-safe
# allowlist BEFORE it names any file (fail closed). Charset MIRRORS
# scripts/deploy/xpf-deploy.py:validate_version and pkg/upgrade.ValidateVersion
# Segment (minus the Debian epoch `:`, never part of an artifact filename).
_SAFE_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+~-]*\Z")


def validate_version(value, field):
    """Reject a version that could escape the artifact output directory when
    substituted into `xpf-<ver>.qcow2` (and siblings). Fail-closed on a path
    separator, `..`, absolute path, leading `.`/`-`, whitespace, `%`, or any
    char outside [A-Za-z0-9._+~-]. Accepts git-describe / semver versions."""
    if not isinstance(value, str) or not value:
        die(f"{field} is required and must be a non-empty string")
    if os.path.isabs(value):
        die(f"{field} '{value}' must not be an absolute path")
    if "/" in value or "\\" in value or os.sep in value \
            or (os.altsep and os.altsep in value):
        die(f"{field} '{value}' must not contain a path separator")
    if value.startswith("-"):
        die(f"{field} '{value}' must not start with '-' (would be read as a CLI flag)")
    if not _SAFE_VERSION.match(value):
        die(f"{field} '{value}' is not a safe version — allow only "
            "[A-Za-z0-9][A-Za-z0-9._+~-]* (no separators, '..', '%', spaces, or "
            "shell metacharacters), so it cannot escape the artifact output "
            "directory (#5992)")
    return value


def require(tool, hint):
    if not shutil.which(tool):
        die(f"{tool} not found — {hint}")


# ── Image seal (#5283, #6547) ────────────────────────────────────────
#
# The seal is what stops the golden image shipping an identical PER-DEVICE
# IDENTITY to every clone. These two tuples are the SINGLE SOURCE for it: the
# virt-sysprep argv below is built from them, and the pre-sign validation gate
# (scripts/image/validate.py) asserts the OUTCOME of each one on the exported
# qcow2 before a signature is ever produced.
#
# #6547: before that gate existed the seal was performed but never verified.
# The `--enable` list was a hand-maintained string literal and the purge was a
# `rm -rf ... 2>/dev/null || true` whose failure is swallowed by construction,
# so a member silently dropping out of either — or the step being refactored
# away — would have shipped a SIGNED image with a fleet-wide shared SSH host
# key, machine-id and SNMPv3 EngineID, and passed the publish gate green.
# `scripts/image/test_validate_image_seal_6547.py` binds these tuples to the
# gate's identity table, so dropping a member from either one reds.
SYSPREP_ENABLE_OPS = (
    "machine-id",
    "ssh-hostkeys",
    "ssh-userdir",
    "logfiles",
    "tmp-files",
    "bash-history",
    "package-manager-cache",
    "backup-files",
    "passwd-backups",
    "utmp",
)

# Paths removed by the seal's --run-command. The xpf state entries make the
# image a factory artifact (no committed config, no day-0 stamp); the SNMPv3
# EngineID component and its engineBoots counter (#5283) and the systemd
# random-seed are per-device identity — every clone must regenerate them on
# first boot, or all of them derive byte-identical localized USM keys and
# accept each other's authenticated SNMPv3 requests.
SYSPREP_PURGE_PATHS = (
    "/etc/xpf/.configdb",
    "/etc/xpf/xpf.conf",
    "/etc/xpf/.day0-config-applied",
    "/etc/xpf/.root-grown",
    "/var/lib/xpf/snmp-engine-id",
    "/var/lib/xpf/snmp-engineboots",
    "/var/lib/systemd/random-seed",
    "/var/lib/apt/lists/*",
)


def run(argv, **kw):
    return subprocess.run(argv, check=True, **kw)


def out_text(argv):
    return subprocess.run(argv, check=True, capture_output=True, text=True).stdout


def git_version():
    try:
        return out_text(["git", "-C", ROOT, "describe", "--tags", "--always", "--dirty"]).strip()
    except Exception:
        return "dev"


def ensure_memlock():
    """qemu io_uring needs locked memory beyond the 8 MiB default."""
    soft, hard = resource.getrlimit(resource.RLIMIT_MEMLOCK)
    if hard == resource.RLIM_INFINITY or hard >= 1048576 * 1024:
        return
    if subprocess.run(["sudo", "-n", "true"], capture_output=True).returncode == 0:
        # The shell original died if this failed; preserve that — a silent
        # drop just relocates the failure into libguestfs/qemu later.
        if subprocess.run(["sudo", "-n", "prlimit", "--memlock=unlimited:unlimited",
                           "--pid", str(os.getpid())]).returncode != 0:
            die("could not raise RLIMIT_MEMLOCK (libguestfs/qemu io_uring needs it)")
    else:
        die("RLIMIT_MEMLOCK too low for libguestfs/qemu io_uring — raise it "
            "(sudo prlimit --memlock=unlimited:unlimited --pid $$) and re-run")


# The production appliance base is pinned to Ubuntu 26.04 LTS (#1943). Bumping
# it is a DELIBERATE, REVIEWED decision — not auto-latest (CLAUDE.md "Ubuntu
# 26.04 parity": "the test VM tracks whatever release production was last baked
# at — a deliberate, reviewed bump, not auto-latest"). The old default scraped
# cloud-images.ubuntu.com and took the highest-numbered listing, which silently
# selects whatever the mirror lists as newest — a non-LTS (e.g. 26.10) or, when
# an LTS image lags publication, the previous release (25.10). That drift is
# exactly what the contract forbids, so the default is the pinned LTS. The
# reviewed bump is a code change to PINNED_BASE_RELEASE below (lands via PR);
# XPF_BASE_RELEASE=<rel> is a one-off runtime override, and
# XPF_UBUNTU_AUTODISCOVER=1 opts back into mirror-latest discovery.
PINNED_BASE_RELEASE = "26.04"

# #4904 B — supply-chain trust anchor for the Ubuntu base image. The image AND
# its SHA256SUMS are fetched from the SAME configurable mirror endpoint
# (base_url), so a same-endpoint checksum authenticates nothing against a
# compromised/custom mirror or a TLS/DNS/CA compromise: the mirror can serve
# matching malicious bytes+hash, and XPF would then sign the result with its
# RELEASE key. The fix pins the expected base-image SHA256 in REVIEWED repo
# metadata — a TRUST ANCHOR the mirror does not control — and verifies the
# downloaded image against it (like the #1943 PINNED_BASE_RELEASE policy).
#
# Provenance of each pin: authored by fetching Canonical's SHA256SUMS +
# SHA256SUMS.gpg from cloud-images.ubuntu.com and verifying the detached GPG
# signature against Canonical's UEC Image Automatic Signing Key
# (fingerprint D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81) — NOT trusting the
# checksum on its own. A Canonical respin (new point image) changes the digest;
# bumping the pin is then a DELIBERATE, REVIEWED commit (re-verify the GPG
# signature first), exactly like a PINNED_BASE_RELEASE bump. Keyed by the same
# release string discover_base_release() returns.
PINNED_BASE_SHA256 = {
    # ubuntu-26.04-server-cloudimg-amd64.img — Canonical-GPG-verified
    # (UEC signing key D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81).
    "26.04": "9dc7c5363c0146a08ba0c9aa834d82c2c6dfbb1c471ad9a2f0aba1189e21be05",
}


def resolve_base_pin(rel):
    """Return the pinned base-image SHA256 (the trust anchor) for release `rel`,
    or None if unpinned. XPF_BASE_SHA256 is a reviewed one-off override (e.g. a
    point respin between reviewed PINNED_BASE_SHA256 bumps, or an
    XPF_BASE_RELEASE override) and wins over the repo constant."""
    env = os.environ.get("XPF_BASE_SHA256")
    if env:
        return env.strip().lower()
    pin = PINNED_BASE_SHA256.get(rel)
    return pin.strip().lower() if pin else None


def authenticate_base_digest(rel, actual):
    """#4904 B: authenticate the downloaded base image against the repo-pinned
    digest (a trust anchor NOT under the mirror's control). Returns True when
    the digest matched a pin (authenticated), False when the base is unpinned
    but the operator explicitly allowed it (XPF_ALLOW_UNPINNED_BASE=1, a
    non-publishable dev bake). Aborts (die -> non-zero) on a pin MISMATCH or on
    an unpinned base without that explicit escape hatch — a same-endpoint
    checksum is never a sufficient authenticator on its own."""
    pin = resolve_base_pin(rel)
    if pin:
        if actual.strip().lower() != pin:
            die(f"base image digest {actual} does NOT match the pinned digest "
                f"{pin} for Ubuntu {rel} — the mirror served bytes a reviewed "
                "trust anchor does not vouch for. Refusing to bake a signed "
                "image from an unauthenticated base (a compromised/wrong mirror, "
                "or a stale pin after a Canonical respin: re-verify Canonical's "
                "GPG-signed SHA256SUMS and bump PINNED_BASE_SHA256 via a "
                "reviewed commit).")
        return True
    if os.environ.get("XPF_ALLOW_UNPINNED_BASE") == "1":
        print(f"WARNING: no pinned SHA256 for Ubuntu {rel} — the base image is "
              "authenticated ONLY by a checksum from the SAME mirror endpoint, "
              "which is NOT a trust anchor. This image is NOT publishable as a "
              f"release. Add PINNED_BASE_SHA256[{rel!r}] (Canonical-GPG-verified) "
              "via a reviewed commit to authenticate it.", file=sys.stderr)
        return False
    die(f"no pinned base-image SHA256 for Ubuntu {rel} (PINNED_BASE_SHA256 has "
        "no entry and XPF_BASE_SHA256 is unset). The base would be authenticated "
        "only by a checksum from the SAME mirror endpoint as the image — not a "
        "trust anchor. Pin it (Canonical-GPG-verified) via a reviewed commit, "
        "set XPF_BASE_SHA256=<digest>, or pass XPF_ALLOW_UNPINNED_BASE=1 for a "
        "non-publishable dev bake.")


def discover_base_release():
    if os.environ.get("XPF_BASE_RELEASE"):
        return os.environ["XPF_BASE_RELEASE"]
    if os.environ.get("XPF_UBUNTU_AUTODISCOVER") != "1":
        return PINNED_BASE_RELEASE
    url = os.environ.get("XPF_UBUNTU_RELEASES_URL",
                         "https://cloud-images.ubuntu.com/releases")
    import re
    html = out_text(["curl", "-fsSL", url + "/"])
    rels = sorted(set(re.findall(r'href="(\d{2}\.\d{2})/"', html)),
                  key=lambda v: tuple(int(x) for x in v.split(".")))
    if not rels:
        die(f"could not discover the latest Ubuntu release from {url}/ "
            "(set XPF_BASE_RELEASE to pin one)")
    return rels[-1]


def sha256(path):
    import hashlib
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def fetch_base(cache_dir, work_dir):
    releases_url = os.environ.get("XPF_UBUNTU_RELEASES_URL",
                                  "https://cloud-images.ubuntu.com/releases")
    rel = discover_base_release()
    base_url = os.environ.get("XPF_BASE_URL", f"{releases_url}/{rel}/release")
    img = f"ubuntu-{rel}-server-cloudimg-amd64.img"
    info(f"fetching Ubuntu {rel} server cloud image base ({base_url})")
    cached = os.path.join(cache_dir, img)
    if not os.path.isfile(cached):
        run(["curl", "-fsSL", "-o", cached + ".tmp", f"{base_url}/{img}"])
        os.replace(cached + ".tmp", cached)
    # Re-verify the cache against the upstream checksum (cache not trusted).
    sums = os.path.join(work_dir, "SHA256SUMS.upstream")
    run(["curl", "-fsSL", "-o", sums, f"{base_url}/SHA256SUMS"])
    expected = None
    with open(sums) as f:
        for line in f:
            parts = line.split()
            if len(parts) == 2 and parts[1].lstrip("*") == img:
                expected = parts[0]
                break
    if not expected:
        die(f"no SHA256 for {img} in upstream SHA256SUMS")
    actual = sha256(cached)
    if expected != actual:
        os.remove(cached)
        die("base image SHA256 mismatch (cache removed — re-run)")
    # The same-endpoint SHA256SUMS above only catches transport corruption — it
    # is fetched from the SAME mirror as the image, so it is NOT an authenticator
    # against a malicious mirror. #4904 B: authenticate the bytes against the
    # repo-pinned digest (a trust anchor the mirror does not control). A mismatch
    # (or an unpinned base without XPF_ALLOW_UNPINNED_BASE=1) aborts BEFORE the
    # image is ever customized/signed.
    pinned = authenticate_base_digest(rel, actual)
    if pinned:
        info("base image checksum verified + matches the pinned digest "
             "(trust anchor).")
    else:
        info("base image checksum verified (UNPINNED base — not publishable).")
    return rel, base_url, img, cached, actual, pinned


def virt_customize(work_qcow, xpf_deb):
    pkgs = " ".join(RUNTIME_PACKAGES)
    deb_name = os.path.basename(xpf_deb)
    argv = [
        "virt-customize", "-a", work_qcow, "--smp", "4", "--memsize", "2048",
        "--hostname", "xpf",
        # #1917 increment A: install xpf via the .deb instead of copying raw
        # binaries. The package stages the binary set under
        # /usr/local/share/xpf/staged, creates the live /usr/local/sbin
        # symlinks, and enables xpfd + xpf-day0-config in its postinst — so
        # the bake no longer hand-copies binaries/units or runs `systemctl
        # enable xpfd`. The git-tracked, kernel-verified shim travels
        # embedded inside the staged xpfd binary (#1864 contract preserved).
        "--copy-in", f"{xpf_deb}:/var/tmp",
        "--copy-in", f"{HERE}/incus-agent.service:/usr/lib/systemd/system",
        "--copy-in", f"{HERE}/incus-agent-setup:/usr/lib/systemd",
        "--copy-in", f"{HERE}/99-incus-agent.rules:/usr/lib/udev/rules.d",
        "--run-command", "chmod 0755 /usr/lib/systemd/incus-agent-setup",
        "--write", f"/etc/sysctl.d/99-xpf.conf:{SYSCTL_CONF}",
        "--run-command", "mkdir -p /etc/xpf && chmod 0750 /etc/xpf",
        # #7114: the appliance-image marker. xpfd's #1922 bootstrap lifeline
        # refuses to rename or bring up ANY NIC when it cannot identify a
        # management interface from an active default route — the right call on
        # a foreign host, where xpf is a guest and the operator's own network
        # configuration is the lifeline. This image has no such configuration:
        # cloud-init is purged and every netplan / interfaces.d file is deleted
        # below, so on a factory boot (no day-0 drive) there is no route, no
        # address, and nothing to preserve. Without this marker that boot leaves
        # every port DOWN and unrenamed — console-only, no fxp0, no DHCP.
        # Its presence, AND-ed in the daemon with "never committed", re-enables
        # the image's vNIC#1 -> fxp0 factory contract on THIS artifact only. The
        # .deb postinst must never write it.
        "--write",
        "/etc/xpf/appliance:"
        "# xpf (#7114) appliance-image marker — written by scripts/image/bake.py.\n"
        "# Presence means: this root filesystem IS the xpf appliance, so xpfd owns\n"
        "# every NIC on it. On a FACTORY boot (nothing ever committed) the daemon\n"
        "# claims the first enumerated NIC as fxp0 and DHCPs it, instead of the\n"
        "# console-only bootstrap refusal it applies to foreign-host installs.\n"
        "# Delete it to get the foreign-host posture on this box.\n",
        "--run-command", f"export DEBIAN_FRONTEND=noninteractive && {APT_UPDATE}",
        "--run-command", f"export DEBIAN_FRONTEND=noninteractive && "
                         f"apt-get install -y -qq -o Acquire::Retries=5 {pkgs}",
        "--run-command", "export DEBIAN_FRONTEND=noninteractive && "
                         "apt-get install -y -qq -o Acquire::Retries=5 linux-generic",
        "--run-command",
        'latest=$(ls /lib/modules | sort -V | tail -1) && case "$latest" in [0-9]*) ;; '
        '*) echo "FATAL: non-kernel entry $latest in /lib/modules" >&2; exit 1 ;; esac && '
        'dpkg --compare-versions "${latest%%-*}" ge 6.18 || '
        '{ echo "FATAL: newest installed kernel $latest < 6.18 (verifier floor)" >&2; exit 1; }',
        "--run-command",
        'test -d "/lib/modules/$(ls /lib/modules | sort -V | tail -1)/kernel/drivers/net/ethernet/mellanox" || '
        '{ echo "FATAL: linux-modules-extra missing (mlx5/i40e)" >&2; exit 1; }',
        "--run-command", "export DEBIAN_FRONTEND=noninteractive && apt-get purge -y -qq "
                         "linux-virtual linux-image-virtual linux-headers-virtual 2>/dev/null || true",
        # Ship EXACTLY ONE kernel. Ubuntu 26.04's cloudimg already runs a
        # -generic kernel, so `apt install linux-generic` pulls a NEWER
        # point release (e.g. 7.0.0-22 over the stock 7.0.0-15) and leaves
        # the original — across packages a narrow name regex misses
        # (linux-main-modules-zfs-<ver>, linux-headers-<ver>, …) AND
        # depmod-generated files dpkg doesn't own. So for every non-newest
        # version: purge ALL its packages via an apt glob, then rm -rf the
        # leftover module dir + its /boot files. update-grub (below)
        # regenerates the menu. Then HARD-ASSERT one kernel remains — the
        # bake must catch this itself, not only the boot validation
        # (this assert caught a real 2-kernel image during #1879 live bake).
        "--run-command",
        'export DEBIAN_FRONTEND=noninteractive; newest=$(ls /lib/modules | sort -V | tail -1); '
        'for v in $(ls /lib/modules | grep -vxF "$newest"); do '
        'apt-get purge -y -qq "linux-*$v*" 2>/dev/null || true; '
        'rm -rf "/lib/modules/$v" /boot/*"$v"*; done; '
        'apt-get autoremove --purge -y -qq 2>/dev/null || true; true',
        "--run-command",
        'n=$(ls /lib/modules | wc -l); [ "$n" -eq 1 ] || '
        '{ echo "FATAL: $n kernels in /lib/modules after purge ($(ls /lib/modules | tr "\\n" " "))" >&2; exit 1; }',
        # #1930 INC-0: HOLD the kernel so an unattended `apt upgrade` cannot move
        # the running kernel out from under the verifier-gated shim .o (#1864).
        # The embedded AF_XDP shim is kernel-space-verifier-gated; a kernel the
        # .o has never been verified against can REJECT it at boot -> no
        # dataplane. A kernel bump must be an explicit, verify-gated operator
        # action (the LANE-1 channel, #1930), never silent apt drift.
        #
        # `apt-mark hold linux-*` MUST NOT be a bare glob: apt-mark does not
        # expand wildcards, and the shell would expand `linux-*` against the cwd
        # (holding nothing). Enumerate the installed kernel package set via
        # dpkg-query instead. `set -e` makes an apt-mark failure fatal, and we
        # then VERIFY every enumerated package is actually in `apt-mark showhold`
        # (per-package, not a count) so neither a partial hold nor a pre-existing
        # unrelated hold can ship an unprotected image.
        #
        # Two things this fragment gets wrong easily, both of which aborted
        # every bake (found by running one, #1926):
        #   1. The `$` in the dpkg-query format must be ESCAPED. This string is
        #      handed to the guest's `sh -c`, so an unescaped `${Package}` is
        #      expanded by that shell as an unset variable, the format collapses
        #      to a bare `\n`, dpkg-query emits one blank line per package, and
        #      `$(...)` strips them all -> `pkgs` empty -> the FATAL below.
        #   2. `dpkg-query -W` matches every package dpkg KNOWS OF, not just the
        #      installed ones -- purged and never-installed names (e.g.
        #      `linux-headers-3.0`, `linux-image-fb-generic`, referenced only as
        #      someone else's dependency) come back too. `apt-mark hold` errors
        #      on those ("Can't select installed nor candidate version"), which
        #      `set -e` turns fatal. Filter on `${db:Status-Status}` so only
        #      genuinely installed packages reach apt-mark.
        "--run-command",
        'set -e; export DEBIAN_FRONTEND=noninteractive; '
        'pkgs=$(dpkg-query -W -f="\\${db:Status-Status} \\${Package}\\n" '
        '"linux-image-*" "linux-headers-*" "linux-modules-*" "linux-generic" '
        '2>/dev/null | awk \'$1=="installed"{print $2}\' | sort -u); '
        '[ -n "$pkgs" ] || { echo "FATAL: no installed linux-* packages found to hold" >&2; exit 1; }; '
        # apt-mark hold failure is fatal (set -e + no output swallow); then
        # verify EACH enumerated package is actually in showhold, so a
        # pre-existing unrelated hold cannot mask a partial/failed hold.
        'apt-mark hold $pkgs; '
        'hold_set=$(apt-mark showhold); '
        'for p in $pkgs; do '
        'printf "%s\\n" "$hold_set" | grep -qxF "$p" || '
        '{ echo "FATAL: $p not held after apt-mark hold (held: $(printf %s "$hold_set" | tr "\\n" " "))" >&2; exit 1; }; '
        'done; '
        'echo "#1930: held $(printf %s "$pkgs" | wc -w) linux-* packages: $(printf %s "$pkgs" | tr "\\n" " ")"',
        # Exclude linux-* from unattended-upgrades too: a hold protects an
        # interactive `apt upgrade`, but unattended-upgrades can be configured to
        # bypass holds for security. Kernel CVEs flow through the verify-gated
        # LANE-1 channel (#1930), NOT unattended-upgrades.
        "--write",
        "/etc/apt/apt.conf.d/99-xpf-kernel-hold:"
        "// xpf (#1930): never let unattended-upgrades move the kernel.\n"
        "// The embedded AF_XDP shim is kernel-verifier-gated (#1864); kernel\n"
        "// bumps go through the verify-gated LANE-1 channel, not background apt.\n"
        'Unattended-Upgrade::Package-Blacklist { "linux-"; "linux-image-"; '
        '"linux-headers-"; "linux-modules-"; "linux-generic"; };\n',
        "--run-command", "export DEBIAN_FRONTEND=noninteractive && apt-get purge -y -qq snapd "
                         "2>/dev/null || true; rm -rf /snap /var/snap /var/lib/snapd /var/cache/snapd",
        "--run-command", 'export DEBIAN_FRONTEND=noninteractive && apt-get purge -y -qq "cloud-init*" '
                         "2>/dev/null || true; rm -rf /etc/cloud /var/lib/cloud",
        "--run-command", "rm -f /etc/network/interfaces.d/* /etc/netplan/*.yaml 2>/dev/null || true",
        "--run-command", f"export DEBIAN_FRONTEND=noninteractive && apt-get autoremove -y -qq && "
                         f"{{ {APT_UPDATE}; }}",
        "--run-command", "systemctl enable systemd-networkd systemd-resolved",
        "--run-command", "systemctl disable systemd-networkd-wait-online.service 2>/dev/null || true",
        "--run-command", "ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf",
        "--run-command", "systemctl enable frr chrony",
        "--run-command", 'sed -i "s/^pool /#pool /; s/^server /#server /" /etc/chrony/chrony.conf '
                         "&& mkdir -p /etc/chrony/sources.d",
        # Install the xpf .deb. apt resolves the package's deps (adduser,
        # present) from the local file. On this FIRST install the postinst
        # runs `xpfd seed-runtime` (#1964): it copies the dpkg-staged binary
        # set into /var/lib/xpf/versions/<v>/, points
        # /var/lib/xpf/versions/current at it, and makes the /usr/local/sbin
        # links resolve THROUGH versions/current — so the baked image ships
        # with a real, immutable rollback target for its first in-place
        # upgrade. The postinst also enables xpfd + xpf-day0-config — so
        # there is no separate `systemctl enable xpfd` here. systemd is not
        # running under virt-customize, so the postinst's deb-systemd-invoke
        # start is a harmless no-op (the units are enabled and start on the
        # real first boot). The xpfd version check below confirms the
        # sbin -> versions/current -> versions/<v> chain resolves.
        "--run-command", "export DEBIAN_FRONTEND=noninteractive && "
                         f"apt-get install -y -qq -o Acquire::Retries=5 /var/tmp/{deb_name} && "
                         f"rm -f /var/tmp/{deb_name}",
        # #1930 INC-0: the needrestart blacklist for xpfd is ALREADY shipped by
        # the package (debian/xpf.needrestart -> /etc/needrestart/conf.d/xpf.conf,
        # installed by the .deb above) using the correct APPEND form
        # ($nrconf{override_rc}{qr(...)} = 0), which preserves needrestart's
        # default override_rc set. We do NOT add a second bake-written file: a
        # whole-hash assignment would wipe those defaults, and writing into
        # /etc/needrestart/conf.d before the .deb creates it would fail the bake.
        # #1930 INC-1: stage the LANE-1 A/B UEFI kernel-slot substrate (A4).
        #   - the $cmdpath branch fragment (re-emitted by every update-grub);
        #   - the SEPARATE non-blocking slot-registration oneshot (shipped here
        #     AND in the .deb for foreign hosts; NVRAM registration is first-boot,
        #     not offline-bake — r4 AGY F2);
        #   - two FIXED A/B ESP slot dirs, each a copy of the signed shim+grub +
        #     a GRUB-script selector SEEDED to the shipped known-good kernel.
        #     Kernels stay in /boot, NEVER on the ESP (r4 AGY F3).
        "--copy-in", f"{HERE}/grub.d/09_xpf:/etc/grub.d",
        "--run-command", "chmod 0755 /etc/grub.d/09_xpf",
        "--copy-in", f"{HERE}/xpf-uefi-slots:/usr/local/sbin",
        # #9725: keep kernel transit closed from boot until xpfd starts; xpfd's
        # transit gate owns it from then on.
        "--copy-in", f"{HERE}/xpf-transit-closed.service:/usr/lib/systemd/system",
        "--run-command", "systemctl enable xpf-transit-closed.service",
        "--copy-in", f"{HERE}/xpf-uefi-slots.service:/usr/lib/systemd/system",
        "--run-command", "chmod 0755 /usr/local/sbin/xpf-uefi-slots",
        "--run-command", "systemctl enable xpf-uefi-slots.service",
        # the promotion gate (r1 Codex Critical-1): runs `xpfd upgrade kernel
        # promote` early on EVERY boot — a fast no-op on an ordinary boot, the
        # gate + reboot-on-revert on a candidate trial boot.
        "--copy-in", f"{HERE}/xpf-kernel-promote:/usr/local/sbin",
        "--copy-in", f"{HERE}/xpf-kernel-promote.service:/usr/lib/systemd/system",
        # OnFailure recovery unit: reboots to known-good if the gate hangs/times
        # out (r2 AGY Finding 3). Triggered via OnFailure= — no enable needed.
        "--copy-in", f"{HERE}/xpf-kernel-promote-failed.service:/usr/lib/systemd/system",
        "--run-command", "chmod 0755 /usr/local/sbin/xpf-kernel-promote",
        "--run-command", "systemctl enable xpf-kernel-promote.service",
        # Stage the A/B slot dirs: copy the signed shim+grub (so each slot boots
        # shim->grub->MOK kernel — Secure-Boot-correct, r4 AGY Hazard C) and seed
        # both selectors at the shipped known-good kernel (the GRUB-script form
        # the 09_xpf branch sources — r5 AGY d).
        "--run-command",
        'set -e; src=/boot/efi/EFI/ubuntu; '
        '[ -f "$src/shimx64.efi" ] || { echo "FATAL: no signed shim at $src" >&2; exit 1; }; '
        'kv=$(ls /lib/modules | sort -V | tail -1); '
        'for slot in xpf-A xpf-B; do '
        'd=/boot/efi/EFI/$slot; mkdir -p "$d"; '
        'cp -f "$src/shimx64.efi" "$src/grubx64.efi" "$src/mmx64.efi" "$d/" 2>/dev/null || '
        'cp -f "$src/shimx64.efi" "$src/grubx64.efi" "$d/"; '
        'printf \'set xpf_slot_kernel="vmlinuz-%s"\\nset xpf_slot_initrd="initrd.img-%s"\\n\' "$kv" "$kv" > "$d/xpf.selector"; '
        'done; '
        'echo "#1930: staged A/B slots seeded at kernel $kv"',
        # Record the watchdog-persistence platform flag (Path Option D). The bake
        # cannot know the deploy platform's watchdog behavior, so default to
        # ABSENT (D2 warn-and-proceed): operators on a platform with a verified
        # warm-reset-surviving HW/hypervisor watchdog drop the marker to enable
        # D1 strict. (The dir + a README; the marker file is intentionally NOT
        # created by the bake.)
        "--run-command", "mkdir -p /etc/xpf/kernel-channel",
        "--write",
        "/etc/xpf/kernel-channel/README:"
        "# xpf (#1930) LANE-1 kernel channel.\n"
        "# Create the file 'watchdog-persistent' in this dir ONLY on a platform\n"
        "# whose watchdog is known to survive a warm reset (firmware/BMC/\n"
        "# hypervisor). Its presence enables Path-D1 strict (fail-closed if the\n"
        "# watchdog is unavailable). Absent = Path-D2 (BootNext still closes the\n"
        "# boot-loop; an EARLY-boot hang needs one external reset to recover).\n",
        # #1925 Item 1: first-boot root auto-grow. Restores the cloud-init
        # growpart/resizefs behavior the bake purged — grows the root
        # partition + ext4 fs to fill an operator-resized disk on first boot
        # only (stamp-gated), then never again. Uses growpart + resize2fs NOT
        # systemd-repart: they cannot create/reformat/shrink/move a partition,
        # the smallest data-loss surface. growpart (cloud-guest-utils) is
        # NOT free in the image — it ships in the base cloudimg only via
        # cloud-init, which the bake purges + autoremoves. It is therefore
        # installed EXPLICITLY via RUNTIME_PACKAGES above (so the autoremove
        # cannot orphan it); resize2fs (e2fsprogs) is base + also listed.
        # Root is the physically LAST partition, so growing it into trailing
        # free space never touches the ESP (the #1930 A/B kernel slots live
        # in ESP dirs, not partitions), /boot, BIOS-boot, or any partition
        # number. See docs/install-images.md.
        "--copy-in", f"{HERE}/xpf-grow-root:/usr/local/sbin",
        "--copy-in", f"{HERE}/xpf-grow-root.service:/usr/lib/systemd/system",
        "--run-command", "chmod 0755 /usr/local/sbin/xpf-grow-root",
        "--run-command", "systemctl enable xpf-grow-root.service",
        # HARD-ASSERT growpart + resize2fs survived the cloud-init purge +
        # autoremove. If a future base/package-name drift removes growpart,
        # FAIL THE BAKE here rather than silently ship an image whose
        # first-boot grow is a permanent no-op (the Codex MAJOR on #2047).
        "--run-command",
        'command -v growpart >/dev/null || { echo "FATAL: growpart missing '
        '(#1925 root auto-grow would no-op; cloud-guest-utils not installed)" >&2; exit 1; }; '
        'command -v resize2fs >/dev/null || { echo "FATAL: resize2fs missing '
        '(#1925; e2fsprogs not installed)" >&2; exit 1; }; '
        'echo "#1925: growpart + resize2fs present ($(command -v growpart), $(command -v resize2fs))"',
        # HARD-ASSERT the FRR reload tool survived the package install. It is
        # provided by frr-pythontools (RUNTIME_PACKAGES above), NOT the base
        # `frr` package. If a future frr package-name drift drops it, FAIL THE
        # BAKE here rather than silently ship an image whose FRR reload is
        # permanently degraded — the additive `vtysh -f` fallback never
        # converges stale-config removal, so a deleted route/BGP neighbor
        # keeps forwarding/advertising (#4172). Mirrors the growpart assert.
        "--run-command",
        'test -x /usr/lib/frr/frr-reload.py || { echo "FATAL: /usr/lib/frr/'
        'frr-reload.py missing (#4172 FRR reload permanently degraded; '
        'frr-pythontools not installed)" >&2; exit 1; }; '
        'echo "#4172: frr-reload.py present (/usr/lib/frr/frr-reload.py)"',
        "--write", f"/etc/default/grub.d/99-xpf.cfg:{GRUB_DROPIN}",
        "--run-command", "update-grub",
        "--write", f"/etc/ssh/sshd_config.d/10-xpf-factory.conf:{SSHD_DROPIN}",
        "--run-command", "passwd -d root",
        # #6500: record what this image actually SHIPS — the guest kernel and
        # the full installed package set — INSIDE the image, as the last step
        # so the enumeration is the final one (after every install, purge and
        # autoremove above). bake.py reads it back out offline with virt-cat
        # and emits it as the signed xpf-<ver>.pkgs sidecar; the in-image copy
        # stays so an operator on the box can answer the same CVE-triage
        # question without the dist tree. The fragment FAILS THE BAKE on an
        # empty enumeration rather than shipping a hollow record.
        "--run-command", image_inventory.WRITE_CMD,
        "--run-command", "/usr/local/sbin/xpfd version",
    ]
    run(argv)


def validation_gate_step(skip_validate, qcow_out, meta_out):
    """Run the in-guest verify-dataplane validation gate (validate.py).

    Aborts the bake (via die(), exit non-zero) if the gate FAILS, so a
    validation failure stops BEFORE signing (#4017). --skip-validate
    downgrades to a loud warning and skips the gate — the resulting
    artifacts are marked non-publishable by the signed `validated: false`
    provenance field in the manifest (#4904 A), which publish.py refuses.
    """
    if skip_validate:
        print("WARNING: --skip-validate — artifacts have NOT passed the in-guest "
              "verify-dataplane gate; do not publish them.", file=sys.stderr)
        return
    info("running validation gate (factory boot + in-guest verify-dataplane + "
         "valid/invalid day-0 drives)...")
    if subprocess.run([sys.executable, os.path.join(HERE, "validate.py"),
                       "--qcow2", qcow_out, "--metadata", meta_out,
                       "all"]).returncode != 0:
        die("validation gate FAILED — artifacts are NOT publishable")


def sign_manifest_step(out_dir, sums, ver):
    """Sign the checksum manifest with minisign (#1924 §5.1).

    #4017: the signature is a TRUST artifact — downstream publish and
    operators read a signed image as a validated one — so this step is
    ordered strictly AFTER the validation gate (see finalize_artifacts). A
    bake that fails validation never reaches this step, so no
    signed-but-invalid image can exist. Fail-OPEN at bake (a dev bake
    without a key still produces artifacts); fail-CLOSED at publish
    (scripts/dist/publish.py refuses unsigned artifacts). XPF_SIGN_SECKEY
    is a PATH to the secret key; the bytes never enter this process. The
    pinned public key is copied into dist/ so the published tree is
    self-describing (its trust root remains the in-repo checked-in copy,
    not this convenience copy).
    """
    seckey = os.environ.get("XPF_SIGN_SECKEY")
    if not seckey:
        print("WARNING: XPF_SIGN_SECKEY unset — manifest NOT signed. This "
              "dev artifact is NOT publishable; `make dist-publish` will "
              "refuse it. Set XPF_SIGN_SECKEY=<path-to-minisign-seckey> to "
              "sign (#1924).", file=sys.stderr)
        return
    try:
        sign.require_minisign()
        sig = sign.sign_manifest(sums, seckey,
                                 comment=f"xpf image {ver} sha256sums")
        info(f"signed manifest: {os.path.basename(sig)}")
        pub_src = sign.DEFAULT_IMAGE_PUBKEY
        if os.path.isfile(pub_src):
            shutil.copyfile(pub_src, os.path.join(out_dir, "xpf-image.pub"))
    except sign.SignError as e:
        die(f"image signing FAILED: {e}")


def finalize_artifacts(*, validate_step, sign_step):
    """#4017 ordering invariant: VALIDATE strictly before SIGN.

    Runs the validation gate first; the manifest signature (a TRUST
    artifact — downstream publish/operators read a signed image as a good
    one, per the #1864 secure-boot chain) is produced ONLY after the gate
    returns success. If validate_step aborts — die()/SystemExit or any
    exception — sign_step is never reached, so a bake that fails validation
    leaves NO signed artifact behind. Extracted as a standalone,
    dependency-free function so the ordering is unit-testable with injected
    steps (scripts/image/test_bake_sign_ordering.py).
    """
    validate_step()
    sign_step()


def build_manifest_text(*, ver, commit, base_url, base_img, rel, base_sha,
                        base_pinned, validated, bake_date, kernel,
                        guest_kernel, proto_lines=""):
    """Assemble the xpf-<ver>.manifest sidecar text (key: value lines).

    Pure + unit-testable so the supply-chain PROVENANCE fields are asserted
    without a full bake:
      - `validated` (#4904 A): true only when the in-guest verify-dataplane gate
        runs (a --skip-validate bake binds false). The publish gate REQUIRES
        validated: true, so a signed-but-unvalidated dev/emergency image is no
        longer indistinguishable from a release.
      - `base_image_pinned` (#4904 B): whether the Ubuntu base was authenticated
        against the repo-pinned trust-anchor digest (bound alongside the base
        digest + source URL already recorded here).
      - `guest_kernel` (#6500): the kernel the IMAGE ships — the exact artifact
        the #1930 LANE-1 channel promotes. `kernel` above is the BUILD HOST's
        (`os.uname().release`, honestly named `bake_host_kernel`) and answers a
        different question entirely. It is a REQUIRED keyword, not a defaulted
        one, so a caller cannot silently omit the field the publish gate
        requires. The full package inventory is too large for this sidecar and
        rides in xpf-<ver>.pkgs, covered by the same signed SHA256SUMS.

    The sidecar is covered by the signed xpf-<ver>.SHA256SUMS (#5042), so these
    fields are authenticated once the manifest signature verifies.
    """
    return (
        f"version: {ver}\n"
        f"git_commit: {commit}\n"
        f"base_image: {base_url}/{base_img}\n"
        f"base_release: {rel}\n"
        f"base_image_sha256: {base_sha}\n"
        f"base_image_pinned: {'true' if base_pinned else 'false'}\n"
        f"validated: {'true' if validated else 'false'}\n"
        f"bake_date: {bake_date}\n"
        f"bake_host_kernel: {kernel}\n"
        f"guest_kernel: {guest_kernel}\n"
        + proto_lines
    )


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--version", default=git_version())
    p.add_argument("--out", default=os.path.join(ROOT, "dist"))
    p.add_argument("--skip-build", action="store_true")
    p.add_argument("--skip-validate", action="store_true")
    p.add_argument("--keep-work", action="store_true")
    a = p.parse_args()
    # #5992: reject a path-escaping / crafted --version before it names any
    # artifact file (xpf-<ver>.qcow2 …). The default is git_version(), already
    # a safe segment; this guards an operator-supplied override.
    validate_version(a.version, "--version")

    for t, hint in [("qemu-img", "apt-get install qemu-utils"),
                    ("virt-customize", "apt-get install libguestfs-tools"),
                    ("virt-resize", "apt-get install libguestfs-tools"),
                    ("virt-sysprep", "apt-get install libguestfs-tools"),
                    ("virt-sparsify", "apt-get install libguestfs-tools"),
                    ("virt-filesystems", "apt-get install libguestfs-tools"),
                    ("virt-cat", "apt-get install libguestfs-tools"),
                    ("curl", "apt-get install curl")]:
        require(t, hint)
    if not (os.access("/dev/kvm", os.R_OK) and os.access("/dev/kvm", os.W_OK)):
        print("WARNING: no /dev/kvm access — libguestfs will use TCG (slow).", file=sys.stderr)
    ensure_memlock()

    cache_dir = os.path.join(os.environ.get("XDG_CACHE_HOME",
                             os.path.expanduser("~/.cache")), "xpf-image-bake")
    os.makedirs(a.out, exist_ok=True)
    os.makedirs(cache_dir, exist_ok=True)
    work = tempfile.mkdtemp(prefix="xpf-bake-", dir=os.environ.get("TMPDIR", "/tmp"))

    import glob
    try:
        # 1. build the xpf .deb (#1917 increment A). `make deb` runs
        #    `make build build-ctl build-userspace-dp` via debian/rules, so
        #    it picks up the embedded #1864 shim and the pinned cargo helper,
        #    then packages the freshly-built binaries. The image consumes the
        #    .deb instead of raw --copy-in binaries.
        # Staging dir for the built .deb — a `dist-deb/` SIBLING of the image
        # publish root `dist/`, NOT under it (HB165 H-5): `make dist-publish`
        # uploads the whole `dist/` tree and publish.py's default-deny sweep
        # refuses any stray file there, so the deb must stage outside `dist/`.
        deb_dir = os.path.join(ROOT, "dist-deb")
        if not a.skip_build:
            info("building xpf .deb (xpfd, cli, xpf-userspace-dp -> staged)...")
            run(["make", "-C", ROOT, "deb"])
        # The git-derived version is computed by the Makefile; glob for the
        # binary package (NOT the xpf-appliance metapackage) and pick the
        # NEWEST by mtime so a stale deb from an earlier (e.g. dirty-tree)
        # build in dist-deb/ is never selected over the one just built.
        debs = sorted((g for g in glob.glob(os.path.join(deb_dir, "xpf_*.deb"))
                       if "xpf-appliance" not in os.path.basename(g)),
                      key=os.path.getmtime)
        if not debs:
            die(f"no xpf_*.deb in {deb_dir} (run without --skip-build, or run `make deb`)")
        xpf_deb = debs[-1]
        info(f"using package: {xpf_deb}")
        # build-host pre-gate (best-effort): verify the embedded shim against
        # the build-host kernel before baking it in (#1864). Verify the xpfd
        # that is ACTUALLY IN THE SELECTED .deb (extracted from the staging
        # path), not ROOT/xpfd — under --skip-build those can diverge (a
        # stale loose ROOT/xpfd next to a newer packaged binary), and the
        # one that ships is the packaged one.
        staged_xpfd = os.path.join(work, "pregate", "usr", "local",
                                   "share", "xpf", "staged", "xpfd")
        run(["dpkg-deb", "-x", xpf_deb, os.path.join(work, "pregate")])
        if not os.access(staged_xpfd, os.X_OK):
            die(f"package {xpf_deb} does not contain an executable staged xpfd")
        if subprocess.run(["sudo", "-n", "true"], capture_output=True).returncode == 0:
            info(f"build-host pre-gate: packaged xpfd verify-dataplane "
                 f"(host kernel {os.uname().release})...")
            if subprocess.run(["sudo", "-n", "nice", "-n", "19",
                               staged_xpfd, "verify-dataplane"]).returncode != 0:
                die("embedded shim REJECTED by the build-host kernel verifier (#1864)")
        else:
            print("NOTE: no passwordless sudo — skipping build-host verify pre-gate "
                  "(in-guest gate still enforces).", file=sys.stderr)

        # 2. base
        rel, base_url, base_img, cached, base_sha, base_pinned = fetch_base(
            cache_dir, work)

        # 3. resize
        disk = os.environ.get("XPF_IMAGE_DISK_SIZE", "8G")
        info(f"creating {disk} work disk + expanding root partition...")
        fs = out_text(["virt-filesystems", "-a", cached, "--filesystems", "--long", "--no-title"])
        root_part = next((ln.split()[0] for ln in fs.splitlines()
                          if len(ln.split()) >= 3 and ln.split()[2] == "ext4"), None)
        if not root_part:
            die("could not locate the ext4 root partition in the base image")
        work_qcow = os.path.join(work, "work.qcow2")
        run(["qemu-img", "create", "-f", "qcow2", "-o", "preallocation=off", work_qcow, disk],
            stdout=subprocess.DEVNULL)
        run(["virt-resize", "--quiet", "--expand", root_part, cached, work_qcow])

        # 4. customize
        info("customizing image offline (packages, kernel >= 6.18, xpf install)...")
        virt_customize(work_qcow, xpf_deb)

        # 4b. read the #6500 inventory back OUT of the image, offline.
        # virt-cat, not a boot: the whole point is that the record is
        # extractable without running the appliance. A parse failure ABORTS the
        # bake — an image whose traceability record is missing or hollow is not
        # publishable anyway (publish.py's gate refuses it), so failing here
        # gives the operator the real cause instead of a refusal three steps
        # later against an artifact that already exists.
        info("reading the image inventory (guest kernel + installed packages)...")
        inventory_text = out_text(
            ["virt-cat", "-a", work_qcow, image_inventory.INVENTORY_GUEST_PATH])
        try:
            guest_kernel, inventory_pkgs = image_inventory.parse(inventory_text)
        except image_inventory.InventoryError as e:
            die(f"the baked image carries no usable inventory at "
                f"{image_inventory.INVENTORY_GUEST_PATH}: {e}")
        info(f"guest kernel {guest_kernel}, {len(inventory_pkgs)} packages recorded")

        # 5. seal
        info("sealing image (virt-sysprep)...")
        run(["virt-sysprep", "-a", work_qcow, "--quiet",
             "--enable", ",".join(SYSPREP_ENABLE_OPS),
             "--run-command",
             "rm -rf " + " ".join(SYSPREP_PURGE_PATHS) + " 2>/dev/null || true"])

        # 6. export
        ver = a.version
        qcow_out = os.path.join(a.out, f"xpf-{ver}.qcow2")
        meta_out = os.path.join(a.out, f"xpf-{ver}.incus-metadata.tar.gz")
        info(f"exporting {qcow_out} (sparsified + compressed qcow2)...")
        run(["virt-sparsify", "--quiet", "--tmp", work, "--compress", work_qcow, qcow_out])

        info(f"exporting {meta_out} (incus VM image metadata)...")
        meta = os.path.join(work, "metadata.yaml")
        with open(meta, "w") as f:
            f.write("architecture: x86_64\n"
                    f"creation_date: {int(time.time())}\n"
                    "properties:\n"
                    f"  description: xpf appliance {ver} (Ubuntu {rel}, kernel >= 6.18, "
                    "AF_XDP userspace dataplane)\n"
                    "  os: Ubuntu\n"
                    f"  release: {rel}\n"
                    "  variant: xpf-appliance\n")
        run(["tar", "-C", work, "-czf", meta_out, "metadata.yaml"])

        # NOTE(#5042): the per-version checksum manifest (xpf-<ver>.SHA256SUMS)
        # is written BELOW — after the xpf-<ver>.manifest protocol sidecar
        # exists — so the sidecar is COVERED by the signed checksum set. The
        # deployer's mixed-base HA session-safety gate decides session survival
        # from that sidecar's ha-protocol / session-sync fields; before #5042
        # those bytes lived outside every signed artifact, so tampering the
        # sidecar alone could spoof a compatible-window / matching-sync decision
        # and bypass the session-safety stop while every signed image byte was
        # untouched. The .minisig over SHA256SUMS is produced only AFTER the
        # validation gate (#4017); see write_manifest below and
        # finalize_artifacts() at the end of the pipeline.

        try:
            commit = out_text(["git", "-C", ROOT, "rev-parse", "HEAD"]).strip()
        except Exception:
            commit = "unknown"

        # #1930 INC-3 LANE-2: record the staged binary's compile-time HA /
        # session-sync / config-DB protocol versions in the manifest so the
        # mixed-base image-replace gate is a FILE READ (no boot, no cross-arch
        # binary run needed). The packaged binary already passed the
        # verify-dataplane pre-gate above, so it is the authoritative source.
        # Best-effort: a parse/run failure leaves the version lines out rather
        # than aborting the bake. The image-roll gate reads ONLY the manifest
        # and FAILS CLOSED on missing protocol fields (it does not re-run the
        # staged binary), so a manifest baked without these lines forces the
        # operator to either re-bake or pass --allow-session-drop.
        proto_lines = ""
        try:
            pv = out_text([staged_xpfd, "protocol-versions"])
            # Re-key into the manifest namespace (manifest uses `key: value`).
            for ln in pv.splitlines():
                if "=" in ln:
                    k, v = ln.split("=", 1)
                    proto_lines += f"{k.strip().replace('-', '_')}: {v.strip()}\n"
        except Exception as e:
            print(f"WARNING: could not read staged xpfd protocol-versions for the "
                  f"manifest ({e}); the manifest will OMIT the protocol-version "
                  f"fields and the mixed-base image-roll gate will FAIL CLOSED "
                  f"(re-bake, or roll with --allow-session-drop).", file=sys.stderr)

        manifest = os.path.join(a.out, f"xpf-{ver}.manifest")
        with open(manifest, "w") as f:
            # #4904 A+B: bind the validated-provenance flag and the base-image
            # pin-provenance flag into the sidecar (covered by the signed
            # SHA256SUMS below). A --skip-validate bake records validated:false,
            # which publish.py's fail-closed gate refuses.
            f.write(build_manifest_text(
                ver=ver, commit=commit, base_url=base_url, base_img=base_img,
                rel=rel, base_sha=base_sha, base_pinned=base_pinned,
                validated=not a.skip_validate,
                bake_date=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                kernel=os.uname().release, guest_kernel=guest_kernel,
                proto_lines=proto_lines))
        info(f"manifest: {manifest}")

        # Per-version, version-named checksum manifest (#1924 §5.1): each bake
        # owns its manifest so retaining v1 next to v2 never orphans v1's
        # checksums. Verification (validate.py / xpf-deploy.py fetch) is
        # PER-FILE against the basenames listed here. #5042: the protocol
        # sidecar xpf-<ver>.manifest is now in the signed set so the deployer's
        # mixed-base HA session-safety gate reads AUTHENTICATED bytes —
        # `xpf-deploy image-roll` verifies it against this SHA256SUMS before
        # parsing the ha-protocol / session-sync fields. The .minisig over this
        # manifest is produced only AFTER the validation gate (finalize_artifacts).
        # #6500: the package inventory sidecar. Its own file rather than more
        # manifest lines — a full dpkg list is hundreds of entries and the
        # .manifest is parsed line-by-line by the deployer's mixed-base gate.
        # It joins the signed SHA256SUMS below, so it is authenticated exactly
        # like the .manifest sidecar is (#5042).
        pkgs_out = os.path.join(a.out, image_inventory.sidecar_name(ver))
        with open(pkgs_out, "w") as f:
            f.write(inventory_text if inventory_text.endswith("\n")
                    else inventory_text + "\n")
        info(f"inventory: {pkgs_out}")

        sums = os.path.join(a.out, f"xpf-{ver}.SHA256SUMS")
        sign.write_manifest(sums, [qcow_out, meta_out, manifest, pkgs_out])
        info("checksums:")
        print(open(sums).read(), end="")

        # 7. validation gate, THEN sign (#4017). The manifest signature is a
        # TRUST artifact — downstream publish (scripts/dist/publish.py) and
        # operators read a signed image as a validated one (#1864 secure-boot
        # chain), so it must never exist for an image that failed the gate.
        # finalize_artifacts enforces validate-before-sign: the gate runs
        # first and signing happens ONLY on success. A gate failure aborts
        # (die(), exit non-zero) BEFORE any .minisig is written.
        finalize_artifacts(
            validate_step=lambda: validation_gate_step(
                a.skip_validate, qcow_out, meta_out),
            sign_step=lambda: sign_manifest_step(a.out, sums, ver),
        )

        info(f"bake complete: {qcow_out}")
        info("deploy quickstarts: docs/install-images.md")
        return 0
    finally:
        if a.keep_work:
            print(f"keeping work dir: {work}")
        else:
            shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
