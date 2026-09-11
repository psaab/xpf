#!/usr/bin/env python3
"""xpf-deploy — set up xpf appliance VMs (incus or libvirt), all in Python.

Subcommands:
  deploy <appliance.yaml> [...]   launch from YAML definition(s); a cluster
                                  is two files. (Default if args are *.yaml.)
                                  Preflights every prerequisite before it
                                  mutates, and cleans up a half-created VM on a
                                  mid-deploy failure so the re-run starts clean.
  destroy <appliance.yaml> [...]  tear down the deployed VM(s) + per-VM overlay
                                  + day-0 drive so a re-deploy is clean.
  launch --name … --nic …         imperative launch without a YAML file.
  inventory                       list host NICs, SR-IOV VFs, bridges → the
                                  values you drop into a definition.
  fetch [--version V] [--image-url] download a signed appliance image from
                                  XPF_IMAGE_BASE_URL. With NO --version, the
                                  version comes from the signed
                                  <channel>/latest.json pointer (#6504); then
                                  VERIFY the exact bytes against the signed
                                  manifest (#1924) and import to a local incus
                                  alias. Verify happens here, not at
                                  deploy/launch.
  kernel-roll --node A --node B   LANE-1 HA kernel roll (#1930 INC-2): drive a
              --version V          verify-gated kernel bump across the HA pair
                                  ONE NODE AT A TIME (drain -> arm+reboot into
                                  the candidate -> poll until promoted -> rejoin,
                                  then the peer). Survives the per-node reboots;
                                  holds a leased lock; STOPS (leaving the peer
                                  primary) if a node reverts. The per-node
                                  arm/verify/promote is `xpfd upgrade kernel`.

Interface naming is POSITIONAL (matches pkg/daemon/linksetup.go assignName):

  standalone:      pos1 -> fxp0   pos2 -> ge-0/0/0   posN -> ge-0/0/(N-2)
  cluster node 0:  pos1 -> fxp0   pos2 -> em0        posN -> ge-0/0/(N-3)
  cluster node 1:  pos1 -> fxp0   pos2 -> em0        posN -> ge-7/0/(N-3)

A NIC's backing (virtio bridge / SR-IOV VF / PCI passthrough) is declared
explicitly per interface — `backing:` in YAML, or the `<backing>:<source>`
spec for --nic. The tool translates each to the right incus device / libvirt
virt-install argument. The day-0 config drive is built and check-config
validated in-process (no shell helpers).

Global options: --dry-run  --hypervisor incus|libvirt  --no-start  --image X

Examples:
  xpf-deploy.py deploy examples/deploy/standalone-sriov.yaml
  xpf-deploy.py deploy --hypervisor libvirt examples/deploy/standalone-passthrough.yaml
  xpf-deploy.py launch --name fw1 --config standalone.conf \\
      --nic bridge:br-mgmt --nic sriov:enp8s0 --nic pci:0000:09:00.0
  xpf-deploy.py inventory
"""

import argparse
import contextlib
import fcntl
import json
import os
import re
import secrets
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile

try:
    import yaml
except ImportError:
    yaml = None

VALID_BACKINGS = {"net", "bridge", "macvlan", "sriov", "physical", "pci"}

# Guest PCI enumeration classes. The guest names interfaces positionally
# (assignName), but ONLY after enumeratePCINICs() sorts NICs with a
# virtio-first tiebreaker: sk=0 for driver "virtio_net", sk=1 for
# everything else, then by PCI bus address (pkg/daemon/linksetup.go). A
# virtio-backed device (net/bridge/macvlan attach as `virtio_net`) always
# sorts ahead of a passthrough device (sriov/physical/pci attach as the
# real hardware driver), regardless of the order the tool attaches them.
# So the config's list position only equals the guest's vSRX name when
# every virtio-class NIC precedes every hardware-class NIC.
VIRTIO_BACKINGS = {"net", "bridge", "macvlan"}
HARDWARE_BACKINGS = {"sriov", "physical", "pci"}
SYS_NET = "/sys/class/net"



@contextlib.contextmanager
def _owner_only_umask():
    """Force a 0077 umask for the duration of the block (#6764).

    The ISO tools create the output file themselves, so its mode comes from the
    process umask at creation time — typically 0022, i.e. 0644 world-readable.
    The chmod that follows the build only narrows it AFTERWARDS, and the file
    already contains xpf.conf from the moment the tool writes it, so every
    co-located UID has the whole build's duration to `isoinfo -x /xpf.conf` the
    day-0 secrets out.

    Setting the umask around the call closes the window at CREATION rather than
    after it, and it survives the tool unlinking and recreating its output —
    which a pre-created 0600 file would not. The chmod afterwards is kept as a
    belt: it also fixes an output file that already existed with a wider mode.

    umask is process-global and not thread-safe; these scripts are
    single-threaded, and the block is a single subprocess call.
    """
    old = os.umask(0o077)
    try:
        yield
    finally:
        os.umask(old)

def backing_sort_key(backing):
    """Guest enumeration sort key for a backing, mirroring the sk=0
    (virtio) / sk=1 (hardware) tiebreaker in enumeratePCINICs()
    (pkg/daemon/linksetup.go). Lower sorts earlier in the guest."""
    return 0 if backing in VIRTIO_BACKINGS else 1


def die(msg):
    sys.exit(f"ERROR: {msg}")


def positive_int(value):
    """argparse ``type=`` callable: parse a STRICTLY-positive integer (> 0).

    Rejects 0 / negative (and non-integer) input at parse time — argparse maps a
    raised ``ArgumentTypeError`` to a usage error with a clear message and exit
    code 2, BEFORE any remote/deploy action runs. We reject rather than silently
    clamp: a bad operator input fails closed.

    This guards ``--lease-ttl`` (#5470). ``_acquire_lease`` renders the roll
    lease deadline as ``expires_at = now + ttl`` and the acquire guard is a
    strict ``now < expires``, so a non-positive TTL yields a lease that is
    already expired the instant it is written. The cross-orchestrator
    kernel/image-roll mutex then never actually holds, and two independent
    drivers could each take a node's flock in turn and drain OPPOSITE HA nodes
    into a no-primary forwarding outage. The TTL must be a positive integer of
    seconds; operators should size it to comfortably exceed the whole roll
    (``--boot-deadline`` plus drain/rejoin margins, default 1800s)."""
    try:
        n = int(value)
    except (TypeError, ValueError):
        raise argparse.ArgumentTypeError(f"'{value}' is not an integer")
    if n <= 0:
        raise argparse.ArgumentTypeError(
            f"must be a positive integer of seconds (> 0), got {n}")
    return n


# ── identifier / path-containment safety (#4905-B) ────────────────────
# The appliance `name` and `image` are interpolated straight into filesystem
# paths that this tool WRITES and REMOVES (often via sudo): the day-0 ISO in
# CWD (`<name>-day0.iso`), and the per-VM overlay + shared golden qcow2 under
# /var/lib/libvirt/images (`<name>.qcow2` / `<image>.qcow2`). A value bearing a
# path separator, a `..` component, an absolute path, or a leading dash would
# redirect those write/delete sinks outside the managed storage dir — e.g.
# `../../../../tmp/owned` resolves to `/tmp/owned.qcow2`, and destroy/cleanup
# would `rm -f` (or `sudo rm -f`) it. Validate every identifier to a single
# safe path component, and enforce commonpath containment at each sink as
# defense-in-depth.
_SAFE_IDENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z")


def validate_identifier(value, field):
    """Reject a name/image identifier that could escape the managed dir.

    Allows only a single safe path component: it must start with an
    alphanumeric and contain only [A-Za-z0-9._-] (so no `/`, `\\`, spaces,
    shell metacharacters, or a leading `.`/`-`). This rules out `..`, absolute
    paths, and any embedded separator. Returns the value on success; die()s
    with a clear message otherwise (#4905-B)."""
    if not isinstance(value, str) or not value:
        die(f"{field} is required and must be a non-empty string")
    if os.path.isabs(value):
        die(f"{field} '{value}' must not be an absolute path")
    if "/" in value or "\\" in value or os.sep in value \
            or (os.altsep and os.altsep in value):
        die(f"{field} '{value}' must not contain a path separator")
    if value.startswith("-"):
        die(f"{field} '{value}' must not start with '-' (would be read as a "
            "CLI flag by the hypervisor tools)")
    if not _SAFE_IDENT.match(value):
        die(f"{field} '{value}' is not a safe identifier — allow only "
            "[A-Za-z0-9][A-Za-z0-9._-]* (no separators, '..', spaces, or "
            "shell metacharacters), so it cannot escape the managed storage "
            "directory (#4905-B)")
    return value


# A version string is interpolated straight into artifact WRITE paths —
# `xpf-<ver>.qcow2` and its `.incus-metadata.tar.gz` / `.SHA256SUMS` /
# `.minisig` siblings — under the fetch/bake out-dir. A path separator, a `..`
# component, an absolute path, or a leading dash would escape the out-dir or be
# read as a CLI flag (the #4905-B / #5713 path-escape class), so `--version
# '../../../etc/cron.d/x'` would write outside `--out`. `_SAFE_IDENT` is too
# strict for a version (it forbids `+`/`~`), so validate the version against a
# version-appropriate allowlist instead (#5992).
_SAFE_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+~-]*\Z")


def validate_version(value, field):
    """Reject a version that could escape the artifact output directory when
    substituted into `xpf-<ver>.qcow2` (and siblings).

    Same fail-closed discipline as validate_identifier, with a
    version-appropriate charset: alnum start, then `[A-Za-z0-9._+~-]` — so no
    `/`, `\\`, `..`, absolute path, leading `.`/`-`, whitespace, `%`, or shell
    metacharacter. Accepts git-describe (`1.2.3-5-gabcdef`) and semver
    (`1.0.0+build.7`, `1.0.0~rc1`).

    The charset MIRRORS pkg/upgrade.ValidateVersionSegment (the #5713
    systemd-ExecStart sink) EXCEPT it drops the Debian epoch `:`: an epoch is
    never part of an artifact FILENAME (dpkg itself encodes `:` as `%3a`), and a
    `:` in `xpf-<ver>.qcow2` would confuse the incus image alias / tooling. This
    is the filename sink's need, which differs from the systemd exec-path sink.

    Returns value on success; die()s with a clear message otherwise (#5992)."""
    if not isinstance(value, str) or not value:
        die(f"{field} is required and must be a non-empty string")
    if os.path.isabs(value):
        die(f"{field} '{value}' must not be an absolute path")
    if "/" in value or "\\" in value or os.sep in value \
            or (os.altsep and os.altsep in value):
        die(f"{field} '{value}' must not contain a path separator")
    if value.startswith("-"):
        die(f"{field} '{value}' must not start with '-' (would be read as a "
            "CLI flag)")
    if not _SAFE_VERSION.match(value):
        die(f"{field} '{value}' is not a safe version — allow only "
            "[A-Za-z0-9][A-Za-z0-9._+~-]* (no separators, '..', '%', spaces, "
            "or shell metacharacters), so it cannot escape the artifact output "
            "directory (#5992)")
    return value


def contained_join(dirpath, basename, field):
    """Join basename onto dirpath and assert the result stays inside dirpath.

    Defense-in-depth beyond validate_identifier: even if a future caller
    forgot to validate, a path that resolves outside `dirpath` is refused
    rather than written/deleted (#4905-B). Returns the safe absolute-joined
    path (not realpath-resolved, so the caller sees the intended location)."""
    full = os.path.join(dirpath, basename)
    real_dir = os.path.realpath(dirpath)
    real_full = os.path.realpath(full)
    if real_full != real_dir and \
            os.path.commonpath([real_dir, real_full]) != real_dir:
        die(f"refusing {field} path {full!r}: it escapes the managed "
            f"directory {dirpath!r} (#4905-B)")
    return full


def day0_iso_path(name):
    """Path of the day-0 ISO for `name`, validated + contained to CWD."""
    validate_identifier(name, "name")
    return contained_join(os.getcwd(), f"{name}-day0.iso", "day-0 ISO")


def run_capture(argv, dry=False):
    """Run argv, capturing stdout+stderr. On a nonzero exit, die() with the
    command, the return code, and the captured stderr — the hypervisor tool's
    REAL message (missing bridge, existing instance, unknown image alias) —
    instead of letting a bare CalledProcessError traceback swallow it
    (fable-165 H-21). In dry-run, print the command and return "" (never
    execute). Returns stdout on success. This is the single capture-and-report
    helper every hypervisor-command call site funnels through."""
    if dry:
        print(" ".join(shlex.quote(a) for a in argv))
        return ""
    r = subprocess.run(argv, capture_output=True, text=True)
    if r.returncode != 0:
        cmd = " ".join(shlex.quote(a) for a in argv)
        detail = (r.stderr or r.stdout or "").strip() or "(no output on stderr)"
        die(f"command failed (rc={r.returncode}): {cmd}\n    {detail}")
    return r.stdout


# ── naming contract ───────────────────────────────────────────────────
def expected_name(idx, mode, node_id):
    """vSRX name the guest assigns to the NIC at position idx (0-based);
    mirrors assignName() in pkg/daemon/linksetup.go."""
    if idx == 0:
        return "fxp0"
    if mode == "cluster":
        if idx == 1:
            return "em0"
        fpc = 7 if node_id == 1 else 0
        return f"ge-{fpc}/0/{idx - 2}"
    return f"ge-0/0/{idx - 1}"


def norm_role(role):
    r = role.strip()
    m = re.fullmatch(r"ge-(\d+)[-/]0[-/](\d+)", r)
    return f"ge-{m.group(1)}/0/{m.group(2)}" if m else r


# ── host introspection ────────────────────────────────────────────────
def _read(path):
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return ""


def is_physical_nic(dev):
    if dev == "lo" or not os.path.isdir(os.path.join(SYS_NET, dev, "device")):
        return False
    return not re.match(r"(veth|tap|br-|virbr|docker|incusbr)", dev)


def driver_of(dev):
    link = os.path.join(SYS_NET, dev, "device", "driver")
    return os.path.basename(os.path.realpath(link)) if os.path.exists(link) else "?"


def pci_of(dev):
    link = os.path.join(SYS_NET, dev, "device")
    return os.path.basename(os.path.realpath(link)) if os.path.exists(link) else "?"


def native_xdp_hint(driver):
    if driver in ("mlx5_core", "i40e", "ice", "ixgbe", "bnxt_en", "nfp"):
        return "native"
    if driver in ("iavf", "ixgbevf", "virtio_net"):
        return "no (generic)"
    return "unknown"


def vf_parent(addr):
    """(PF_netdev, vf_index) for an SR-IOV VF PCI address, or None."""
    if not os.path.isdir(SYS_NET):
        return None
    for pf in os.listdir(SYS_NET):
        devdir = os.path.join(SYS_NET, pf, "device")
        if not os.path.isdir(devdir):
            continue
        for entry in os.listdir(devdir):
            if entry.startswith("virtfn") and \
               os.path.basename(os.path.realpath(os.path.join(devdir, entry))) == addr:
                return pf, entry[len("virtfn"):]
    return None


def cmd_inventory(_args):
    print(f"=== Physical NICs ===")
    print(f"{'NETDEV':<14} {'DRIVER':<10} {'PCI':<14} {'MAC':<18} {'LINK':<6} NATIVE-XDP")
    for dev in sorted(os.listdir(SYS_NET)):
        if not is_physical_nic(dev):
            continue
        drv = driver_of(dev)
        print(f"{dev:<14} {drv:<10} {pci_of(dev):<14} "
              f"{_read(os.path.join(SYS_NET, dev, 'address')):<18} "
              f"{_read(os.path.join(SYS_NET, dev, 'operstate')):<6} {native_xdp_hint(drv)}")
        devdir = os.path.join(SYS_NET, dev, "device")
        total = _read(os.path.join(devdir, "sriov_totalvfs"))
        if total and total != "0":
            num = _read(os.path.join(devdir, "sriov_numvfs")) or "0"
            print(f"    SR-IOV: {num}/{total} VFs. Create N:  "
                  f"echo N | sudo tee {devdir}/sriov_numvfs")
            for entry in sorted(os.listdir(devdir)):
                if entry.startswith("virtfn"):
                    vfpci = os.path.basename(os.path.realpath(os.path.join(devdir, entry)))
                    print(f"      vf{entry[len('virtfn'):]:<3} pci:{vfpci}   "
                          f"(sriov:{dev}  |  pci:{vfpci},mac=02:..)")
    print("\n=== Host bridges (bridge:<name>) ===")
    found = False
    for dev in sorted(os.listdir(SYS_NET)):
        if os.path.isdir(os.path.join(SYS_NET, dev, "bridge")):
            print(f"  bridge:{dev}")
            found = True
    if not found:
        print("  (none — create: sudo ip link add br-lan type bridge; ip link set br-lan up)")
    return 0


# ── appliance model ───────────────────────────────────────────────────
def validate_appliance(ap, where):
    if not ap.get("name"):
        die(f"{where}: name is required")
    # Reject a name/image that could escape the managed storage dir before we
    # ever construct a path from it (#4905-B). The path-building helpers
    # re-validate at each sink, but failing here gives a clear load-time error.
    validate_identifier(ap["name"], f"{where}: name")
    if ap.get("image"):
        validate_identifier(ap["image"], f"{where}: image")
    if ap["mode"] not in ("standalone", "cluster"):
        die(f"{where}: mode must be standalone|cluster")
    if ap["mode"] == "cluster" and ap.get("node_id") not in (0, 1):
        die(f"{where}: cluster needs node_id 0|1")
    if not ap["interfaces"]:
        die(f"{where}: at least one interface (position 1 = fxp0)")
    for i, ic in enumerate(ap["interfaces"]):
        if ic.get("backing") not in VALID_BACKINGS:
            die(f"{where}: interface {i + 1} backing must be one of {sorted(VALID_BACKINGS)}")
        if not ic.get("source"):
            die(f"{where}: interface {i + 1} needs a source")
        want = expected_name(i, ap["mode"], ap.get("node_id"))
        if ic.get("role") and norm_role(ic["role"]) != want:
            die(f"{where}: interface {i + 1} declares role '{ic['role']}' but position {i + 1} "
                f"is '{want}' — reorder or fix; position is the contract.")
        ic["_name"] = want

    # Guest virtio-first tiebreaker (enumeratePCINICs, linksetup.go): the
    # guest sorts virtio-class NICs ahead of hardware-class ones BEFORE it
    # assigns positional vSRX names. "Position is the contract" therefore
    # only holds when the list order already matches that sort — i.e. every
    # virtio-class NIC precedes every hardware-class one. A virtio-class NIC
    # listed AFTER a hardware-class NIC would be renamed to an earlier slot
    # in the guest, silently swapping the zones/policies/NAT bound to those
    # vSRX names (trust/untrust inversion). Fail closed — the deployer holds
    # every backing's class, so it can and must catch this (fable-165 H-22).
    first_hw = None
    for i, ic in enumerate(ap["interfaces"]):
        if backing_sort_key(ic["backing"]) == 1:
            if first_hw is None:
                first_hw = i
        elif first_hw is not None:
            hw = ap["interfaces"][first_hw]
            die(f"{where}: interface {i + 1} ({ic['backing']}:{ic['source']}, "
                f"declared '{ic['_name']}') is a virtio-class NIC listed after "
                f"the hardware-class interface {first_hw + 1} "
                f"({hw['backing']}:{hw['source']}, declared '{hw['_name']}'). "
                f"The guest enumerates virtio before hardware "
                f"(enumeratePCINICs, linksetup.go), so it renames this NIC to "
                f"an earlier slot and SWAPS the zones on '{ic['_name']}' and "
                f"'{hw['_name']}'. Reorder so every virtio-class NIC "
                f"(net/bridge/macvlan) comes before every hardware-class NIC "
                f"(sriov/physical/pci); position is the contract.")


def load_yaml_appliance(path):
    if yaml is None:
        die("PyYAML required for YAML deploy (apt install python3-yaml). "
            "Use the 'launch' subcommand for a no-YAML, no-dependency path.")
    with open(path) as f:
        doc = yaml.safe_load(f)
    if not isinstance(doc, dict):
        die(f"{path}: top level must be a mapping")
    a = doc.get("appliance") or {}
    ap = {
        "name": a.get("name"), "mode": a.get("mode", "standalone"),
        "node_id": a.get("node_id"), "image": a.get("image", "xpf-appliance"),
        "cpu": a.get("cpu", 4), "memory": a.get("memory", "4GiB"),
        "config": a.get("config"), "interfaces": doc.get("interfaces") or [],
        "pool": a.get("pool", "default"),
        "base_dir": os.path.dirname(os.path.abspath(path)),
    }
    validate_appliance(ap, path)
    return ap


# ── day-0 config drive (pure Python; xorriso/genisoimage for the ISO) ──
def find_xpfd():
    for c in (os.environ.get("XPFD"), os.path.join(os.getcwd(), "xpfd"),
              shutil.which("xpfd")):
        if c and os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    return None


def build_config_drive(ap, runner):
    cfg = ap.get("config")
    if not cfg:
        return None
    cfg_path = cfg if os.path.isabs(cfg) else os.path.join(ap["base_dir"], cfg)
    iso = day0_iso_path(ap["name"])
    if runner.dry:
        print(f"==> (dry-run) would build day-0 drive {iso} from {cfg_path} "
              f"(label xpf-config, check-config validated)")
        return iso
    if not os.path.isfile(cfg_path):
        die(f"config not found: {cfg_path}")
    xpfd = find_xpfd()
    if xpfd:
        nodearg = ["-node-id", str(ap["node_id"])] if ap["mode"] == "cluster" else []
        r = subprocess.run([xpfd, "check-config"] + nodearg + [cfg_path],
                           capture_output=True, text=True)
        if r.returncode != 0:
            die(f"day-0 config REJECTED by check-config:\n{r.stdout}{r.stderr}")
        print(f"==> day-0 config validated ({os.path.basename(cfg_path)})")
    else:
        print("WARNING: no xpfd binary found — skipping build-host validation "
              "(the appliance still validates at first boot).")
    mkiso = next((t for t in ("xorriso", "genisoimage", "mkisofs") if shutil.which(t)), None)
    if not mkiso:
        die("need xorriso/genisoimage/mkisofs to build the config drive (apt install xorriso)")
    stage = tempfile.mkdtemp(prefix="xpf-day0-")
    try:
        shutil.copyfile(cfg_path, os.path.join(stage, "xpf.conf"))
        # 0o600, not 0o644: the staged xpf.conf carries every day-0 secret
        # (root-authentication hash, IKE PSK, SNMP community, DDNS tokens).
        # The 0700 mkdtemp already shields it, so this is belt-and-suspenders,
        # but it keeps the staged copy owner-only too (#4586).
        os.chmod(os.path.join(stage, "xpf.conf"), 0o600)
        if ap["mode"] == "cluster":
            with open(os.path.join(stage, "node-id"), "w") as f:
                f.write(f"{ap['node_id']}\n")
        if mkiso == "xorriso":
            argv = ["xorriso", "-as", "mkisofs", "-quiet", "-V", "xpf-config",
                    "-J", "-r", "-o", iso, stage]
        else:
            argv = [mkiso, "-quiet", "-V", "xpf-config", "-J", "-r", "-o", iso, stage]
        with _owner_only_umask():
            run_capture(argv)   # die with the mkiso error, not a bare traceback (H-21)
        # The ISO embeds xpf.conf — the most secret-bearing day-0 artifact
        # (root-authentication hash, IKE PSK, SNMP community, DDNS tokens).
        # xorriso/genisoimage writes it under the process umask (~0022 ->
        # 0644, world-readable) and it lingers in CWD until destroy. Restrict
        # it to owner-only so a co-located UID cannot `isoinfo -x /xpf.conf`
        # the secrets out (#4586). The owner (daemon/VM) still reads it fine.
        os.chmod(iso, 0o600)
        print(f"==> built day-0 drive {iso} (label xpf-config)")
    finally:
        shutil.rmtree(stage, ignore_errors=True)
    return iso


# ── memory / pci helpers ──────────────────────────────────────────────
def memory_mb(val):
    m = re.fullmatch(r"(\d+)\s*([GMgm]i?[Bb]?)?", str(val).strip())
    if not m:
        die(f"unparseable memory '{val}'")
    return int(m.group(1)) * 1024 if (m.group(2) or "M").upper().startswith("G") else int(m.group(1))


def is_pci_addr(s):
    """True if s is a PCI BDF address (DDDD:BB:DD.F), not a netdev name.
    Used to tell a libvirt --hostdev PCI address from an interface name
    (fable-165 H-23)."""
    return bool(re.fullmatch(
        r"[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7]", str(s)))


def pci_parts(addr):
    m = re.fullmatch(r"([0-9a-fA-F]{4}):([0-9a-fA-F]{2}):([0-9a-fA-F]{2})\.([0-7])", addr)
    if not m:
        die(f"pci address '{addr}' is not DDDD:BB:DD.F")
    return {"domain": "0x" + m.group(1), "bus": "0x" + m.group(2),
            "slot": "0x" + m.group(3), "function": "0x" + m.group(4)}


class Runner:
    def __init__(self, dry):
        self.dry = dry

    def run(self, argv):
        # Funnel through run_capture so a failing hypervisor command dies with
        # its real stderr, not a bare CalledProcessError traceback (H-21).
        return run_capture(argv, self.dry)


# ── deploy backends ───────────────────────────────────────────────────
def print_map(ap):
    tag = ap["mode"] + (f" node {ap['node_id']}" if ap["mode"] == "cluster" else "")
    print(f"==> {ap['name']}: {tag}, {len(ap['interfaces'])} NICs")
    for i, ic in enumerate(ap["interfaces"]):
        print(f"      pos {i + 1}: {ic['_name']:<10} <- {ic['backing']}:{ic['source']}")


# ── preflight / existence probes (query-only; never mutate) ────────────
def _incus_exists(kind, name):
    """True if incus AFFIRMATIVELY reports the object. kind in
    {instance,image,network}. Query-only.

    For non-destructive callers, where "could not tell" reading as "not there"
    is harmless. A destructive caller must use `_incus_state`, which keeps the
    two apart (#9325)."""
    return _incus_state(kind, name) == DOMAIN_PRESENT


def _incus_state(kind, name):
    """PRESENT / ABSENT / UNKNOWN for an incus object (query-only, #9325).

    The same three states as `_virsh_domain_state`, for the same reason:
    `incus ... info` exits non-zero both for an object that does not exist and
    for a daemon it could not reach, and an `incus` this process cannot run
    (off PATH, a dangling symlink mid-upgrade) says nothing about what the
    daemon holds. Absence is read from incus's own wording, measured for all
    three kinds:

        instance: Error: Failed to fetch instance "x" in project "default": Instance not found
        image:    Error: Image "x" not found
        network:  Error: Network interface "x" not found
    """
    argv = {"instance": ["incus", "info", name],
            "image": ["incus", "image", "info", name],
            "network": ["incus", "network", "info", name]}[kind]
    try:
        r = subprocess.run(argv, capture_output=True, text=True)
    except OSError:
        return DOMAIN_UNKNOWN
    if r.returncode == 0:
        return DOMAIN_PRESENT
    if "not found" in ((r.stderr or "") + (r.stdout or "")).lower():
        return DOMAIN_ABSENT
    return DOMAIN_UNKNOWN


# #8977: three states, not two. `virsh dominfo` exits non-zero for a domain that
# does not exist AND for a libvirtd that could not be reached, a permissions
# failure, or a timeout. Collapsing those to False made "we could not tell" read
# as "there is nothing there" -- and the callers then removed a running VM's
# backing overlay, in one path with a sudo escalation.
DOMAIN_PRESENT = "present"
DOMAIN_ABSENT = "absent"
DOMAIN_UNKNOWN = "unknown"


# #9669: libvirt keeps a SEPARATE domain namespace per connection URI, and virsh
# / virt-install used to run with no --connect, so they spoke to whichever URI
# the invoking user's default resolved to. The golden and overlay disks are
# hard-wired to system scope (/var/lib/libvirt/images), so the tool now names
# the URI: `deploy` defines the domain at LIBVIRT_SYSTEM_URI. Teardown can no
# longer trust ONE probe: a domain an operator deployed non-root lives in the
# session URI, and a probe against the system URI reports it ABSENT, which is
# exactly the answer that lets teardown delete its disks (#9325). So every
# presence question asks BOTH URIs. A domain present in either is present,
# and it is torn down through the URI that holds it. Absence needs both.
LIBVIRT_SYSTEM_URI = "qemu:///system"
LIBVIRT_SESSION_URI = "qemu:///session"
LIBVIRT_PROBE_URIS = (LIBVIRT_SYSTEM_URI, LIBVIRT_SESSION_URI)


def _virsh_domain_locate(name):
    """(state, uris) for a libvirt domain across LIBVIRT_PROBE_URIS (#9669).

    PRESENT with every URI that holds the domain; otherwise UNKNOWN if ANY URI
    could not answer (an unreachable URI might hold it); otherwise ABSENT.
    """
    states = {uri: _virsh_domain_state_at(name, uri) for uri in LIBVIRT_PROBE_URIS}
    present = [uri for uri in LIBVIRT_PROBE_URIS if states[uri] == DOMAIN_PRESENT]
    if present:
        return DOMAIN_PRESENT, present
    if any(st == DOMAIN_UNKNOWN for st in states.values()):
        return DOMAIN_UNKNOWN, []
    return DOMAIN_ABSENT, []


def _virsh_domain_state(name):
    """PRESENT / ABSENT / UNKNOWN for a libvirt domain across both URIs (#9669)."""
    return _virsh_domain_locate(name)[0]


def _virsh_teardown_domain(name, uris):
    """destroy + undefine the domain through each URI that holds it (#9669)."""
    for uri in uris:
        subprocess.run(["virsh", "-c", uri, "destroy", name], capture_output=True, text=True)
        r = subprocess.run(["virsh", "-c", uri, "undefine", "--nvram", name],
                           capture_output=True, text=True)
        if r.returncode != 0:   # domains without NVRAM reject --nvram
            subprocess.run(["virsh", "-c", uri, "undefine", name],
                           capture_output=True, text=True)


def _virsh_domain_state_at(name, uri):
    """PRESENT / ABSENT / UNKNOWN for a libvirt domain at ONE URI (query-only).

    UNKNOWN is the state that did not exist before #8977, and it is the one the
    destructive callers must refuse on.

    A MISSING BINARY is NOT absence (#9325). virsh is a client: libvirtd and its
    domains exist whether or not this process can exec it, and a restricted
    unit PATH, sudo's secure_path, or a package upgrade that left a dangling
    symlink all raise FileNotFoundError while a domain runs. #8977 exempted
    that one case as "virsh is not installed, so no domain can exist"; it is
    UNKNOWN like every other failure to answer.

    `virsh dominfo` distinguishes them in its stderr: a missing domain says so
    explicitly, while a connection/permission failure names the transport. We
    read that rather than the exit code, which cannot separate them.
    """
    try:
        r = subprocess.run(["virsh", "-c", uri, "dominfo", name],
                           capture_output=True, text=True)
    except OSError:
        # FileNotFoundError included (#9325): a virsh this process cannot run
        # says nothing about whether libvirtd holds the domain.
        return DOMAIN_UNKNOWN
    if r.returncode == 0:
        return DOMAIN_PRESENT
    err = ((r.stderr or "") + (r.stdout or "")).lower()
    # libvirt's own wording for "this domain is not defined".
    if "failed to get domain" in err or "domain not found" in err or "no domain with" in err:
        return DOMAIN_ABSENT
    # Anything else -- cannot connect, permission denied, timeout, an
    # unrecognised failure -- is UNKNOWN. Defaulting the unrecognised case to
    # UNKNOWN rather than ABSENT is deliberate: the cost of a wrong ABSENT is
    # deleting a live VM's disk, and the cost of a wrong UNKNOWN is refusing a
    # teardown that the operator can retry.
    return DOMAIN_UNKNOWN


def _virsh_domain_exists(name):
    """True if a libvirt domain of this name is defined (query-only).

    Retained for the NON-destructive callers (preflight), where treating
    UNKNOWN as "not present" is the pre-#8977 behaviour and is harmless: the
    worst outcome is a name-collision check that passes and a later create that
    fails loudly. Destructive callers must use `_virsh_domain_state`.
    """
    return _virsh_domain_state(name) == DOMAIN_PRESENT


def _netdev_exists(dev):
    return os.path.isdir(os.path.join(SYS_NET, dev))


def preflight_incus(ap, runner):
    """Fail BEFORE mutating (fable-165 H-27): the image alias, every NIC source
    (managed network / host bridge / PF / PCI device), and a free instance name
    must all exist/be-free. A missing prerequisite is the most common first-run
    failure — catching it here turns an opaque mid-deploy error into one clear
    message, and a name that is already taken points at `destroy` instead of a
    bare "already exists". Skipped in dry-run (resources may be created between
    plan and apply)."""
    if runner.dry:
        return
    name = ap["name"]
    problems = []
    if not _incus_exists("image", ap["image"]):
        problems.append(f"image alias '{ap['image']}' not found — "
                        f"fetch/import it first (xpf-deploy.py fetch ...)")
    for i, ic in enumerate(ap["interfaces"]):
        b, src = ic["backing"], str(ic["source"])
        if b == "net":
            if not _incus_exists("network", src):
                problems.append(f"interface {i + 1}: incus network '{src}' not "
                                f"found (incus network create {src})")
        elif b in ("bridge", "macvlan", "sriov", "physical"):
            if not _netdev_exists(src):
                problems.append(f"interface {i + 1}: host netdev '{src}' not "
                                f"present ({b}: parent must exist)")
        elif b == "pci":
            if not os.path.isdir(os.path.join("/sys/bus/pci/devices", src)):
                problems.append(f"interface {i + 1}: PCI device '{src}' not present")
    if _incus_exists("instance", name):
        problems.append(f"instance '{name}' already exists — tear it down first "
                        f"(xpf-deploy.py destroy ...) or it is already deployed")
    if problems:
        die("preflight failed (nothing was changed):\n    - "
            + "\n    - ".join(problems))


def preflight_libvirt(ap, runner):
    """Fail BEFORE mutating (fable-165 H-27): the golden qcow2, every bridge/
    macvlan/physical NIC source, and a free domain name must exist/be-free.
    net/sriov sources (libvirt network / operator-defined VF pool) are left to
    libvirt. Skipped in dry-run."""
    if runner.dry:
        return
    problems = []
    golden = libvirt_golden_path(ap["image"])
    if not os.path.isfile(golden):
        problems.append(f"golden image not found: {golden} — fetch it "
                        f"(xpf-deploy.py fetch --install-libvirt ...)")
    for i, ic in enumerate(ap["interfaces"]):
        b, src = ic["backing"], str(ic["source"])
        if b in ("bridge", "macvlan"):
            if not _netdev_exists(src):
                problems.append(f"interface {i + 1}: host netdev '{src}' not present")
        elif b == "physical":
            # a netdev NAME is resolved to PCI at deploy; a PCI addr passes through.
            if not is_pci_addr(src) and not _netdev_exists(src):
                problems.append(f"interface {i + 1}: physical source '{src}' not "
                                f"present (netdev name or PCI address)")
    if _virsh_domain_exists(ap["name"]):
        problems.append(f"domain '{ap['name']}' already exists — tear it down "
                        f"first (xpf-deploy.py --hypervisor libvirt destroy ...) "
                        f"or it is already deployed")
    if problems:
        die("preflight failed (nothing was changed):\n    - "
            + "\n    - ".join(problems))


def deploy_incus(ap, runner, start):
    name = ap["name"]
    print_map(ap)
    preflight_incus(ap, runner)
    iso = build_config_drive(ap, runner)
    # --no-profiles: the default profile usually carries an `eth0` NIC,
    # which would be an extra virtio device the guest names positionally
    # alongside the declared dev00.. — a phantom interface that pollutes
    # the NIC->name map. Suppress all profile devices and provide the root
    # disk explicitly from the storage pool (default "default", override
    # with `pool:` in YAML) so the device set is EXACTLY the declared NICs.
    pool = ap.get("pool", "default")
    created = False   # True once `incus init` created the instance (ours to clean)
    try:
        # incus -d sets ONE key=value per flag (<device>,<key>=<value>), so the
        # root disk needs three -d flags, not one comma-joined value.
        runner.run(["incus", "init", ap["image"], name, "--vm", "--no-profiles",
                    "-c", f"limits.cpu={ap['cpu']}", "-c", f"limits.memory={ap['memory']}",
                    "-d", "root,type=disk", "-d", f"root,pool={pool}", "-d", "root,path=/"])
        created = True
        pins = []
        for i, ic in enumerate(ap["interfaces"]):
            dev = f"dev{i:02d}"
            b, src, mac = ic["backing"], str(ic["source"]), ic.get("mac")
            if b == "net":
                args = ["nic", f"network={src}"]
            elif b == "bridge":
                args = ["nic", "nictype=bridged", f"parent={src}"]
            elif b == "macvlan":
                args = ["nic", "nictype=macvlan", f"parent={src}"]
            elif b == "sriov":
                args = ["nic", "nictype=sriov", f"parent={src}"]
            elif b == "physical":
                args = ["nic", "nictype=physical", f"parent={src}"]
            elif b == "pci":
                args = ["pci", f"address={src}"]
            if mac and b in ("net", "bridge", "macvlan", "sriov"):
                args.append(f"hwaddr={mac}")
            if mac and b == "pci":
                par = None if runner.dry else vf_parent(src)
                if par:
                    pins.append(["sudo", "ip", "link", "set", "dev", par[0], "vf", par[1], "mac", mac])
                elif runner.dry:
                    print(f"      (dry-run) would pin VF MAC for pci:{src}")
                else:
                    die(f"pci:{src} with mac= is not an SR-IOV VF here (drop mac= for whole-PF)")
            runner.run(["incus", "config", "device", "add", name, dev] + args)
        if iso:
            runner.run(["incus", "config", "device", "add", name, "day0", "disk", f"source={iso}"])
        for pin in pins:
            runner.run(["sudo", "ip", "link", "set", "dev", pin[5], "up"])
            print(f"==> pinning VF MAC: {' '.join(pin)}")
            runner.run(pin)
        if start:
            runner.run(["incus", "start", name])
            print(f"\n{name} launched. Verify the NIC->name map:\n"
                  f"  incus exec {name} -- cli -c \"show interfaces terse\"")
        else:
            print(f"{name} created (not started): incus start {name}")
    except BaseException:
        # Cleanup on partial failure (fable-165 H-27): a mid-deploy die() (a
        # device-add against a missing bridge, a failed VF pin, a start error)
        # otherwise leaves a half-created instance that dead-ends the re-run on
        # "already exists". Delete the instance WE created so the retry is clean,
        # then re-raise the original error (SystemExit keeps its message).
        if created and not runner.dry:
            print(f"==> deploy of '{name}' failed after creating it; cleaning up "
                  f"(incus delete --force {name}) so a re-run starts clean")
            subprocess.run(["incus", "delete", "--force", name],
                           capture_output=True, text=True)
        raise


# Directory libvirt/KVM keeps its qcow2 disks in (the default pool path).
LIBVIRT_IMAGES = "/var/lib/libvirt/images"


def libvirt_golden_path(image):
    """The libvirt golden qcow2 path — the SINGLE source of truth shared by
    `deploy --hypervisor libvirt` (reads it as the read-only overlay backing)
    AND `fetch --install-libvirt` (writes the verified image here). One helper
    so the two halves can't drift (fable-165 H-30). The image identifier is
    validated + contained so a crafted `image:`/`--alias` cannot redirect the
    install/read outside LIBVIRT_IMAGES (#4905-B)."""
    validate_identifier(image, "image")
    return contained_join(LIBVIRT_IMAGES, f"{image}.qcow2", "golden image")


def libvirt_overlay_path(name):
    """The per-VM writable overlay qcow2 path under LIBVIRT_IMAGES, validated +
    contained so a crafted `name:` cannot redirect the overlay create/remove
    (which destroy runs via `sudo rm -f`) outside LIBVIRT_IMAGES (#4905-B)."""
    validate_identifier(name, "name")
    return contained_join(LIBVIRT_IMAGES, f"{name}.qcow2", "per-VM overlay")


class _ProbeIndeterminate(Exception):
    """A qcow2 backing-file probe could not determine the answer (#6760).

    Distinct from "this image has no backing file". The overwrite guard below
    treats the two OPPOSITELY: no-backing means the file is not a dependent
    overlay, while indeterminate means it MIGHT be and must not be assumed
    away."""


def _qcow2_backing_file(path):
    """Absolute (realpath) backing-file of a qcow2 image, or None when the
    image demonstrably has no backing file.

    Raises _ProbeIndeterminate when the answer could not be determined —
    qemu-img exited non-zero (unreadable, locked by a running domain,
    permission denied, corrupt header) or its JSON did not parse.

    #6760: this used to return None for FOUR different outcomes — qemu-img
    absent, qemu-img failed, unparseable JSON, and genuinely no backing file —
    and `_dependent_overlays` read None as "does not back onto the golden". So
    an overlay this tool could not probe was silently classified as NOT
    dependent, and `_install_libvirt_golden` then overwrote the golden and
    corrupted exactly the overlay it had failed to read. A running VM's overlay
    is a realistic instance: qemu-img can fail on an image held by a live
    domain.

    #9325: a qemu-img that cannot be RUN is indeterminate too. #6760 kept it as
    "no backing" on the #5043 argument that this tool cannot have created an
    overlay without qemu-img -- an argument about THIS process's history, not
    about the sibling in front of it. An overlay created before qemu-img left
    PATH (a restricted unit PATH, sudo's secure_path, an upgrade in flight), or
    by another tool, still backs onto the golden, and with qemu-img off PATH the
    old answer let that golden be replaced. Treating it as indeterminate
    changes exactly one state:

        state                                  before     after
        fresh host, no golden yet              PROCEED    PROCEED
        golden present, no sibling .qcow2      PROCEED    PROCEED
        golden present + a sibling overlay     PROCEED    REFUSED
    """
    try:
        r = subprocess.run(["qemu-img", "info", "--output=json", path],
                           capture_output=True, text=True)
    except OSError as exc:
        # Could not ask, which is not "no backing" (#9325; see the docstring).
        raise _ProbeIndeterminate(f"qemu-img could not be run to probe {path}: {exc}")
    if r.returncode != 0:
        raise _ProbeIndeterminate(
            f"qemu-img info failed for {path}: rc={r.returncode} "
            f"{(r.stderr or '').strip()}")
    try:
        info = json.loads(r.stdout)
    except (ValueError, TypeError) as exc:
        raise _ProbeIndeterminate(f"qemu-img info for {path} did not parse: {exc}")
    bf = info.get("full-backing-filename") or info.get("backing-filename")
    return os.path.realpath(bf) if bf else None


def _dependent_overlays(golden):
    """Classify sibling `*.qcow2` files by whether they back onto `golden`.

    Returns `(deps, unknown)` — sorted absolute paths that PROVABLY back onto
    the golden, and those whose backing could not be determined (#6760).

    `libvirt_disk` creates each VM's overlay as `qemu-img create -b <golden>`,
    so the overlay depends on the golden's bytes being IMMUTABLE. Overwriting
    the golden in place shifts the backing bytes under every one of these
    overlays and corrupts them (#5043) — commonly BOTH HA nodes at once, since
    a cluster pair shares one golden.

    `unknown` exists because an unprobeable file is not evidence of safety. It
    is returned separately rather than folded into `deps` so the caller can say
    something true and actionable about each: a known dependant names the VM to
    destroy, an unknown one names a file to investigate."""
    golden_real = os.path.realpath(golden)
    imgdir = os.path.dirname(golden_real)
    deps = []
    unknown = []
    try:
        entries = sorted(os.listdir(imgdir))
    except OSError as exc:
        # #8597 (muse-004 K07): FAIL CLOSED. This used to `return deps, unknown`
        # with both empty, which the caller reads as "nothing backs onto the
        # golden" — the guard passes and the sudo fallback overwrites the golden
        # under live overlays. #5043's HA-pair disk corruption, arrived at
        # through the guard written to prevent it.
        #
        # An unlistable images dir is exactly the state the non-root
        # `fetch --install-libvirt` flow reaches: this process cannot read the
        # directory, and then `_atomic_install_golden` succeeds anyway through
        # `sudo install`. The guard's inputs and the write's privileges are
        # different, so "I could not look" must not mean "there is nothing
        # there".
        #
        # This contradicted the function's OWN docstring three lines up —
        # "`unknown` exists because an unprobeable file is not evidence of
        # safety" — and its sibling `_golden_lock`, which reports its analogous
        # OSError LOUDLY rather than proceeding silently.
        #
        # Reported through the existing `unknown` channel rather than a new die
        # site: the caller already refuses on any unknown, with an actionable
        # message, and one refusal path is easier to keep correct than two.
        unknown.append((imgdir, f"cannot list the images directory: {exc}"))
        return deps, unknown
    for entry in entries:
        if not entry.endswith(".qcow2"):
            continue
        cand = os.path.join(imgdir, entry)
        if os.path.realpath(cand) == golden_real:
            continue  # the golden is not its own overlay
        if not os.path.isfile(cand):
            continue
        try:
            backing = _qcow2_backing_file(cand)
        except _ProbeIndeterminate as exc:
            unknown.append((os.path.abspath(cand), str(exc)))
            continue
        if backing == golden_real:
            deps.append(os.path.abspath(cand))
    return deps, unknown


@contextlib.contextmanager
def _golden_lock(golden):
    """Serialize golden replacement against overlay creation (#6761).

    An exclusive flock on `<images-dir>/.xpf-golden.lock`, held across the
    whole check-then-replace in `_install_libvirt_golden` and across the
    `qemu-img create -b <golden>` in `libvirt_disk`. Without it the dependency
    check and the copy are a plain TOCTOU: an overlay created between them
    backs onto a golden that is about to be replaced, and nothing ever looks
    again.

    The lock file lives beside the golden so both operations on the same host
    agree on it. If the directory is not writable by this user the lock cannot
    be taken; that is not a reason to proceed unserialized, but it is also not
    a reason to fail a first install on a root-owned images dir, so the lock is
    best-effort and its absence is reported rather than silently ignored."""
    lockpath = os.path.join(os.path.dirname(os.path.realpath(golden)),
                            ".xpf-golden.lock")
    fd = None
    try:
        try:
            os.makedirs(os.path.dirname(lockpath), exist_ok=True)
            fd = os.open(lockpath, os.O_CREAT | os.O_RDWR, 0o644)
        except OSError as exc:
            print(f"==> note: golden lock {lockpath} unavailable ({exc}); "
                  f"proceeding WITHOUT serialization against overlay creation "
                  f"(#6761)")
            yield False
            return
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield True
    finally:
        if fd is not None:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)


@contextlib.contextmanager
def _watermark_lock(wm_path):
    """Serialize the anti-rollback watermark read/compare/publish (#9238).

    The watermark is checked twice per fetch — once before the download and
    once after verification — and the publish (incus alias import, or the
    libvirt golden replacement) happens after the second check. Between the
    second read and the publish, a concurrent fetch of a NEWER version can
    advance the watermark and publish, after which this process overwrites the
    alias with the older image. The watermark then names v2 and the thing that
    boots is v1.

    Aborting on the inversion (the `die` at the late check) narrows that window
    but does not close it: the check and the publish are still two steps. This
    lock makes them one, so the losing fetch always observes the winner's
    advance and refuses, rather than observing a stale `prev` and proceeding.

    An exclusive flock beside the watermark file. The watermark is per-user
    state under XDG_STATE_HOME, so per-user is the correct scope — the racing
    parties are two `fetch` runs sharing one watermark, and they necessarily
    share its directory.

    Best-effort in the same sense as `_golden_lock`: if the lock cannot be
    taken the fetch proceeds unserialized and says so, because a state dir that
    is not writable must not turn a first fetch on a fresh workstation into a
    hard failure. The late comparison still runs in that case and still aborts
    on an inversion it can see — a narrower guarantee, reported rather than
    silently assumed."""
    lockpath = os.path.join(os.path.dirname(wm_path), ".image-watermark.lock")
    fd = None
    try:
        try:
            os.makedirs(os.path.dirname(lockpath), exist_ok=True)
            fd = os.open(lockpath, os.O_CREAT | os.O_RDWR, 0o644)
        except OSError as exc:
            print(f"==> note: watermark lock {lockpath} unavailable ({exc}); "
                  f"proceeding WITHOUT serialization against a concurrent "
                  f"fetch (#9238)")
            yield False
            return
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield True
    finally:
        if fd is not None:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)


def _install_libvirt_golden(srcq, image):
    """Install a verified qcow2 to the libvirt golden path deploy reads
    (fable-165 H-30). Returns the destination path.

    Golden-immutability contract (#5043): the golden is a SHARED read-only
    backing store — every per-VM overlay is `qemu-img create -b <golden>` and
    depends on its bytes NEVER changing. Overwriting it in place while overlays
    back onto it shifts the backing bytes under live/created overlays and
    corrupts EVERY one (both HA nodes commonly share one golden — a single
    re-fetch would poison both disks).

    Two holes in that guard are closed here, and they are one path:

    #6760 — an overlay whose backing could not be PROBED was classified as not
    dependent, so the guard passed and the golden was overwritten under exactly
    the file the tool had failed to read. Indeterminate now blocks, separately
    worded from a known dependant.

    #6761 — the check and the copy were an unlocked check-then-act on a live
    file. Two failures, not one: an overlay created between the check and the
    copy is corrupted (TOCTOU), and an INTERRUPTED in-place `copyfile` leaves a
    truncated golden that corrupts every existing overlay even when the check
    was correct. The replacement is now written to a temp file in the same
    directory and moved into place with an atomic rename, under the same lock
    `libvirt_disk` takes to create an overlay."""
    golden = libvirt_golden_path(image)
    with _golden_lock(golden):
        if os.path.isfile(golden):
            deps, unknown = _dependent_overlays(golden)
            if deps:
                listing = "\n    - ".join(deps)
                die(f"refusing to overwrite golden {golden} in place: "
                    f"{len(deps)} per-VM overlay(s) back onto it and would be "
                    f"corrupted (the qcow2 backing bytes would shift under a live "
                    f"disk — HA-pair disk corruption, #5043):\n    - {listing}\n"
                    f"  Fix by EITHER destroying the dependent VM(s) first "
                    f"(xpf-deploy.py --hypervisor libvirt destroy <appliance.yaml> "
                    f"for each), OR installing the new image under a fresh tag so "
                    f"existing overlays keep their immutable backing "
                    f"(fetch --install-libvirt --alias <new-name>, then reference "
                    f"image: <new-name> in the deploy YAML).")
            if unknown:
                listing = "\n    - ".join(f"{p}: {why}" for p, why in unknown)
                die(f"refusing to overwrite golden {golden} in place: "
                    f"{len(unknown)} path(s) could not be probed, so whether they "
                    f"back onto this golden is UNKNOWN — and an unprobeable "
                    f"overlay is not evidence of safety (#6760). A running "
                    f"domain's overlay is a common cause: qemu-img can fail on an "
                    f"image a live VM holds open. An unlistable images DIRECTORY "
                    f"is the other (#8597): this process may not be able to read "
                    f"it while the sudo fallback can still write the golden.\n"
                    f"    - {listing}\n"
                    f"  Fix by EITHER making each path probeable (stop the domain "
                    f"holding it, or correct its permissions) and re-running, OR "
                    f"installing under a fresh tag so existing overlays keep their "
                    f"immutable backing (fetch --install-libvirt --alias <new-name>).")
        print(f"==> installing verified qcow2 -> {golden} (libvirt golden)")
        _atomic_install_golden(srcq, golden)
    return golden


def _atomic_install_golden(srcq, golden):
    """Place `srcq` at `golden` by an ATOMIC RENAME, never an in-place copy
    (#6761).

    An interrupted `shutil.copyfile` onto the live golden leaves it TRUNCATED,
    which shifts the backing bytes under every existing overlay — the same
    corruption the dependency guard exists to prevent, reached without any
    concurrency at all. Writing a sibling temp file and renaming means the
    golden is either wholly the old image or wholly the new one.

    The temp file is created in the golden's own directory so the rename is
    within one filesystem (os.replace across filesystems is not atomic and
    raises). The sudo fallback mirrors the same shape for the root-owned
    /var/lib/libvirt/images case."""
    gdir = os.path.dirname(golden)
    tmp = None
    try:
        os.makedirs(gdir, exist_ok=True)
        # #9325: an unpredictable name created O_CREAT|O_EXCL by mkstemp (as
        # _download_to does, #5817), written through the descriptor mkstemp
        # returned, so no path is resolved after creation. The old predictable
        # `<golden>.xpf-tmp.<pid>` let a pre-planted symlink redirect the copy
        # and then be renamed over the golden itself.
        fd, tmp = tempfile.mkstemp(dir=gdir,
                                   prefix=os.path.basename(golden) + ".xpf-tmp.")
        with os.fdopen(fd, "wb") as dst, open(srcq, "rb") as src:
            shutil.copyfileobj(src, dst, 1 << 20)
            os.fchmod(dst.fileno(), 0o644)
            written = os.fstat(dst.fileno())
        # os.replace renames a PATH: refuse unless it still names the regular
        # file written above.
        now = os.lstat(tmp)
        if (not stat.S_ISREG(now.st_mode)
                or (now.st_dev, now.st_ino) != (written.st_dev, written.st_ino)):
            os.unlink(tmp)
            die(f"refusing to install golden {golden}: its temp file {tmp} was "
                f"replaced while it was being written")
        os.replace(tmp, golden)
        return
    except BaseException as exc:
        # Clean up our partial temp before falling back -- or before an
        # interruption propagates -- so a failed attempt never leaves a stray
        # sibling *.qcow2-adjacent file behind.
        if tmp is not None:
            try:
                os.unlink(tmp)
            except OSError:
                pass
        if not isinstance(exc, OSError):
            raise
    # /var/lib/libvirt/images is normally root-owned; -D creates the dir.
    # install writes the temp, mv -f renames it into place atomically. GNU
    # install unlinks a planted destination symlink and creates the file
    # O_EXCL, so this arm does not write through one (#9325, measured).
    sudo_tmp = f"{golden}.xpf-tmp.{secrets.token_hex(8)}"
    for argv in (["sudo", "install", "-m", "0644", "-D", srcq, sudo_tmp],
                 ["sudo", "mv", "-f", sudo_tmp, golden]):
        r = subprocess.run(argv, capture_output=True, text=True)
        if r.returncode != 0:
            # #9325: remove the root-owned, full-size temp before failing. It does
            # not end in .qcow2, so nothing else would ever notice or reclaim it.
            subprocess.run(["sudo", "rm", "-f", sudo_tmp], capture_output=True, text=True)
            detail = (r.stderr or r.stdout or "").strip() or "(no output on stderr)"
            die(f"command failed (rc={r.returncode}): "
                f"{' '.join(shlex.quote(x) for x in argv)}\n    {detail}")


def libvirt_disk(ap, runner):
    """Return a per-VM writable qcow2 backed READ-ONLY by the golden image.

    The golden image ({image}.qcow2) must NEVER be attached writable:
    qcow2 is not a cluster filesystem, so an HA pair booting two live
    domains off one file corrupts it (concurrent metadata/refcount
    writes), and even a single `virt-install --import` would mutate the
    golden master in place — the day-0 stamp, host keys, and configstore
    DB would get baked into it, and the NEXT VM launched "from the image"
    would inherit the previous VM's identity and skip its own config.

    Each domain gets its OWN copy-on-write overlay instead
    (`qemu-img create -f qcow2 -b <golden> -F qcow2 <overlay>`), so the
    golden stays an immutable shared backing store and each VM writes
    only to its distinct {name}.qcow2. A re-deploy re-creates the overlay
    (a fresh boot from golden); `virt-install --name` still refuses to
    redefine a live domain, so a running VM's overlay is not clobbered
    out from under it.
    """
    golden = libvirt_golden_path(ap['image'])
    overlay = libvirt_overlay_path(ap['name'])
    if os.path.abspath(overlay) == os.path.abspath(golden):
        die(f"VM name '{ap['name']}' collides with the golden image basename "
            f"'{ap['image']}' — the per-VM overlay would overwrite the golden "
            f"image. Rename the appliance (name:) or the image (image:).")
    if not runner.dry and not os.path.isfile(golden):
        die(f"golden image not found: {golden} — fetch/import it first "
            f"(see `xpf-deploy.py fetch`) or set image: in the YAML.")
    # Fresh overlay per deploy so the VM boots clean from golden; the
    # golden is the read-only -b backing store and is never written.
    #
    # #6761: taken under the SAME lock `_install_libvirt_golden` holds across
    # its check-then-replace. Without it the two race: a golden replacement
    # can check for dependent overlays, find none, and then be overtaken by
    # this create — leaving a brand-new overlay backing onto bytes that are
    # about to be swapped, which nothing looks at again. Locking only the
    # replacement side would close nothing; both sides must agree on the lock.
    #
    # A dry run performs no filesystem work, so it takes no lock.
    if runner.dry:
        runner.run(["qemu-img", "create", "-f", "qcow2",
                    "-b", golden, "-F", "qcow2", overlay])
        return overlay
    with _golden_lock(golden):
        runner.run(["qemu-img", "create", "-f", "qcow2",
                    "-b", golden, "-F", "qcow2", overlay])
    return overlay


def _virsh_define(runner, name, xml):
    """Define (persistent, NOT started) a libvirt domain from virt-install's
    generated XML. `virt-install --import` DEFINES AND BOOTS the guest, so the
    only way to honor `--no-start` on libvirt is to generate the domain XML
    (`--print-xml`) and `virsh define` it — the domain is then persistent but
    stopped, so the pinned-guest-PCI workflow (edit slots via `virsh edit`
    BEFORE first boot) works (fable-165 H-26)."""
    if runner.dry:
        runner.run(["virsh", "-c", LIBVIRT_SYSTEM_URI, "define", f"{name}.xml"])
        return
    fd, path = tempfile.mkstemp(suffix=".xml", prefix=f"xpf-{name}-")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(xml)
        runner.run(["virsh", "-c", LIBVIRT_SYSTEM_URI, "define", path])
    finally:
        os.unlink(path)


def deploy_libvirt(ap, runner, start):
    name = ap["name"]
    print_map(ap)
    preflight_libvirt(ap, runner)
    iso = build_config_drive(ap, runner)
    try:
        _deploy_libvirt_inner(ap, runner, start, iso)
    except BaseException:
        # Cleanup on partial failure (fable-165 H-27): a die() partway through
        # (bad hostdev resolve, virt-install/virsh error) otherwise leaves the
        # per-VM overlay (and maybe a defined domain) behind, dead-ending the
        # re-run. Undefine the domain + remove the overlay we created, then
        # re-raise the original error (SystemExit keeps its message).
        if not runner.dry:
            overlay = libvirt_overlay_path(name)
            _cleanup_libvirt(name, overlay)
        raise


def _cleanup_libvirt(name, overlay):
    """Best-effort teardown of a half-created libvirt VM: destroy+undefine the
    domain (if it got defined) and remove the per-VM overlay. Tolerant of a
    missing domain / file (fable-165 H-27)."""
    state, uris = _virsh_domain_locate(name)
    if state == DOMAIN_UNKNOWN:
        # #8977: this is the cleanup path of a FAILED deploy, so it must not
        # itself destroy anything it cannot account for. If libvirtd is
        # unreachable the domain may be running -- possibly a pre-existing one
        # that shares the name -- and removing the overlay deletes its disk.
        # Leaving the files is recoverable; deleting a live VM's backing store
        # is not. Not a SystemExit here: the caller is already handling a
        # failure and re-raising would replace its diagnosis with this one.
        print(f"==> WARNING: cannot determine whether libvirt domain '{name}' "
              f"exists (libvirtd unreachable, permission denied, or timed out)")
        print(f"==> leaving {overlay} in place rather than risk deleting a "
              f"running VM's disk; remove it by hand once libvirtd is reachable")
        return
    if state == DOMAIN_PRESENT:
        print(f"==> deploy of '{name}' failed; cleaning up the libvirt domain "
              f"so a re-run starts clean")
        _virsh_teardown_domain(name, uris)
        after = _virsh_domain_state(name)
        if after != DOMAIN_ABSENT:
            # #9325: neither exit status above is evidence the overlay is free.
            # A running domain survives `undefine` as a transient domain, and a
            # failed `destroy` is also what a stopped domain returns. Only a
            # fresh probe that reports the domain gone permits the unlink.
            print(f"==> WARNING: libvirt domain '{name}' is not confirmed gone "
                  f"after destroy and undefine (probe: {after})")
            print(f"==> leaving {overlay} in place rather than risk deleting a "
                  f"running VM's disk; remove it by hand once the domain is gone")
            return
    if os.path.isfile(overlay):
        try:
            os.remove(overlay)
            print(f"==> removed overlay {overlay}")
        except OSError:
            subprocess.run(["sudo", "rm", "-f", overlay],
                           capture_output=True, text=True)


def _deploy_libvirt_inner(ap, runner, start, iso):
    name = ap["name"]
    disk = libvirt_disk(ap, runner)
    argv = ["virt-install", "--connect", LIBVIRT_SYSTEM_URI, "--name", name, "--memory", str(memory_mb(ap["memory"])),
            "--vcpus", str(ap["cpu"]), "--import",
            "--disk", f"path={disk}",
            "--osinfo", "ubuntu26.04", "--noautoconsole"]
    if iso:
        argv += ["--disk", f"path={iso},device=cdrom"]
    notes = []
    for ic in ap["interfaces"]:
        b, src, mac = ic["backing"], str(ic["source"]), ic.get("mac")
        if b in ("net", "bridge"):
            net = f"{'network' if b == 'net' else 'bridge'}={src},model=virtio"
            argv += ["--network", net + (f",mac.address={mac}" if mac else "")]
        elif b == "macvlan":
            net = f"type=direct,source={src},source_mode=bridge,model=virtio"
            argv += ["--network", net + (f",mac.address={mac}" if mac else "")]
        elif b == "physical":
            # libvirt --hostdev takes a PCI (or USB) address, NOT a netdev
            # name — a bare `--hostdev enp8s0` is an invalid hostdev spec, so
            # the domain fails to define / mis-attaches (fable-165 H-23). The
            # incus backend's `nictype=physical parent=<dev>` DOES take the
            # netdev name (incus resolves it), so translate here for libvirt.
            # Accept a raw PCI address too (physical:0000:08:00.0).
            addr = src if is_pci_addr(src) else pci_of(src)
            if not is_pci_addr(addr):
                if runner.dry:
                    addr = f"pci-of:{src}"   # host may lack the NIC at plan time
                else:
                    die(f"physical:{src}: cannot resolve netdev '{src}' to a "
                        f"PCI address on this host (is it a physical NIC?). "
                        f"libvirt --hostdev requires a PCI address, not an "
                        f"interface name — pass the PCI addr via `pci:` or fix "
                        f"the source.")
            argv += ["--hostdev", addr]
        elif b == "pci":
            if mac:
                p = pci_parts(src)
                argv += ["--network",
                         "type=hostdev,source.address.type=pci,"
                         f"source.address.domain={p['domain']},source.address.bus={p['bus']},"
                         f"source.address.slot={p['slot']},source.address.function={p['function']},"
                         f"mac.address={mac}"]
            else:
                argv += ["--hostdev", src]
        elif b == "sriov":
            pool = f"{src}-vfpool"
            argv += ["--network", f"network={pool}" + (f",mac.address={mac}" if mac else "")]
            notes.append(f"sriov:{src} -> libvirt VF pool '{pool}'. Define once:\n"
                         f"      <network><name>{pool}</name>"
                         f"<forward mode='hostdev' managed='yes'><pf dev='{src}'/></forward></network>\n"
                         f"      virsh net-define <f> && virsh net-start {pool} && virsh net-autostart {pool}")
    print("# virt-install — NIC order = guest PCI-slot order = positional names.")
    for n in notes:
        print(f"# NOTE: {n}")
    if start:
        runner.run(argv)   # --import DEFINES AND BOOTS the domain.
        print(f"\n{name}: verify with `virsh console {name}` then "
              f"`cli -c \"show interfaces terse\"`.")
    else:
        # Honor --no-start: --import would boot the guest, so generate the
        # domain XML and `virsh define` it (defined, persistent, NOT started)
        # — makes the pinned-guest-PCI `virsh edit` before first boot workflow
        # possible (fable-165 H-26).
        xml = runner.run(argv + ["--print-xml"])
        _virsh_define(runner, name, xml)
        print(f"\n{name} defined (not started): start it with `virsh start {name}` "
              f"(edit guest PCI slots first with `virsh edit {name}` if pinning).")


def deploy(ap, args):
    runner = Runner(args.dry_run)
    if args.image:
        ap["image"] = validate_identifier(args.image, "--image")
    (deploy_incus if args.hypervisor == "incus" else deploy_libvirt)(
        ap, runner, not args.no_start)


# ── destroy (teardown for a clean re-deploy, fable-165 H-27) ───────────
def destroy_incus(ap, runner):
    name = ap["name"]
    iso = day0_iso_path(name)
    if runner.dry:
        runner.run(["incus", "delete", "--force", name])
    else:
        # #9325: three states, as for libvirt. The day-0 drive is removed only
        # once incus affirmatively reports the instance gone.
        state = _incus_state("instance", name)
        if state == DOMAIN_PRESENT:
            print(f"==> destroying incus instance '{name}'")
            run_capture(["incus", "delete", "--force", name])
            state = _incus_state("instance", name)
        elif state == DOMAIN_ABSENT:
            print(f"==> incus instance '{name}' not present (nothing to destroy)")
        if state != DOMAIN_ABSENT:
            raise SystemExit(
                f"==> ERROR: cannot confirm incus instance '{name}' is gone "
                f"(probe: {state}; incus not runnable from this context, the "
                f"daemon unreachable, or permission denied).\n"
                f"    REFUSING to remove {iso} -- an instance that still exists may "
                f"have that drive attached.\n"
                f"    Fix incus access and retry.")
    if os.path.isfile(iso) and not runner.dry:
        os.remove(iso)
        print(f"==> removed day-0 drive {iso}")


def destroy_libvirt(ap, runner):
    name = ap["name"]
    overlay = libvirt_overlay_path(name)
    iso = day0_iso_path(name)
    if runner.dry:
        for uri in LIBVIRT_PROBE_URIS:
            runner.run(["virsh", "-c", uri, "destroy", name])
            runner.run(["virsh", "-c", uri, "undefine", "--nvram", name])
        runner.run(["rm", "-f", overlay])
        return
    state, uris = _virsh_domain_locate(name)
    if state == DOMAIN_UNKNOWN:
        # #8977: REFUSE. The probe could not reach libvirtd, so the domain may
        # be RUNNING. The destroy is survivable to skip; the unlink below is
        # not, and it used to run regardless of this branch -- deleting the
        # backing overlay of a live VM, with a sudo escalation if the unlink
        # was refused. The VM then continues on a deleted file until it touches
        # unbacked storage.
        raise SystemExit(
            f"==> ERROR: cannot determine whether libvirt domain '{name}' exists "
            f"(libvirtd unreachable, permission denied, or timed out).\n"
            f"    REFUSING to remove {overlay} -- if the domain is running, that "
            f"deletes a live VM's disk.\n"
            f"    Fix libvirtd access and retry, or remove the files by hand once "
            f"you have confirmed the domain is not running.")
    if state == DOMAIN_PRESENT:
        print(f"==> destroying libvirt domain '{name}'")
        # destroy (power off) is best-effort — the domain may already be stopped.
        print(f"==> via {', '.join(uris)}")
        _virsh_teardown_domain(name, uris)
        after = _virsh_domain_state(name)
        if after != DOMAIN_ABSENT:
            # #9325: as in _cleanup_libvirt, only an affirmative ABSENT frees the
            # disks. A running domain survives undefine as a transient domain.
            raise SystemExit(
                f"==> ERROR: libvirt domain '{name}' is not confirmed gone after "
                f"destroy and undefine (probe: {after}).\n"
                f"    REFUSING to remove {overlay} or {iso} -- a running domain "
                f"survives undefine as a transient domain and still uses them.\n"
                f"    Stop it (virsh -c <uri> destroy {name}), confirm `virsh -c "
                f"{LIBVIRT_SYSTEM_URI} dominfo {name}` and `virsh -c {LIBVIRT_SESSION_URI} "
                f"dominfo {name}` both report it missing, then re-run destroy.")
    else:
        print(f"==> libvirt domain '{name}' not present (nothing to destroy)")
    for f in (overlay, iso):
        if os.path.isfile(f):
            try:
                os.remove(f)
                print(f"==> removed {f}")
            except OSError:
                subprocess.run(["sudo", "rm", "-f", f], capture_output=True, text=True)
                print(f"==> removed {f} (sudo)")


def destroy(ap, args):
    runner = Runner(args.dry_run)
    if args.image:
        ap["image"] = validate_identifier(args.image, "--image")
    (destroy_incus if args.hypervisor == "incus" else destroy_libvirt)(ap, runner)


# ── subcommands ───────────────────────────────────────────────────────
def cmd_deploy(args):
    if not args.yamls:
        die("deploy needs at least one YAML file")
    for path in args.yamls:
        deploy(load_yaml_appliance(path), args)
    return 0


def cmd_destroy(args):
    if not args.yamls:
        die("destroy needs at least one YAML file (the appliance to tear down)")
    for path in args.yamls:
        destroy(load_yaml_appliance(path), args)
    return 0


def cmd_launch(args):
    ifaces = []
    for spec in args.nic:
        kind, _, rest = spec.partition(":")
        if not rest:
            kind, rest = "net", spec
        src, _, tail = rest.partition(",")
        mac = None
        m = re.search(r"mac=([^,]+)", tail)
        if m:
            mac = m.group(1)
        ic = {"backing": kind, "source": src}
        if mac:
            ic["mac"] = mac
        ifaces.append(ic)
    ap = {"name": args.name, "mode": args.mode, "node_id": args.node_id,
          "image": args.image or "xpf-appliance", "cpu": args.cpu,
          "memory": args.mem, "config": args.config, "interfaces": ifaces,
          "base_dir": os.getcwd()}
    validate_appliance(ap, "launch")
    deploy(ap, args)
    return 0


def _suffix_key(suffix):
    """Split a pre-release / git-describe suffix into a comparable tuple of
    alternating text/number runs, coercing the number runs to int so `rc10`
    sorts ABOVE `rc9` and describe-count `10` above `9` (fable-165 H-25 — the
    prior whole-string compare inverted BOTH). Each element is tagged
    (0=number, 1=text) so a number run never string-compares against a text
    run (which would raise TypeError in Python 3)."""
    key = []
    for part in re.split(r"(\d+)", suffix):
        if not part:
            continue
        key.append((0, int(part)) if part.isdigit() else (1, part))
    return tuple(key)


def _ver_key(v):
    """Order key for the fetch anti-rollback watermark. Compare on the
    dotted-numeric RELEASE, then a pre-release rank so a pre-release sorts
    BEFORE its base release (AGY: 1.2.3-rc1 < 1.2.3, so upgrading rc -> final
    is NOT a rollback). git-describe tails like "-N-gHASH[-dirty]" are commits
    AHEAD of the tag -> rank them AFTER the base. WITHIN each rank the suffix is
    numeric-split (`_suffix_key`) so counts / rc numbers compare numerically,
    not lexically (fable-165 H-25). Split on the FIRST '-': left = release,
    right = suffix."""
    s = str(v)
    # #8969: SEMVER BUILD METADATA IS NOT PRECEDENCE. `1.0.0+build.7` is the
    # same release as `1.0.0` (semver 11.4), and the version validator's own
    # docstring advertises that spelling as accepted input. Left in, its `+`
    # made the release component non-numeric and it outranked the base.
    s = s.partition("+")[0]
    # #8969: split on the FIRST `-` OR `~`. Debian spells a pre-release with a
    # tilde and orders it before everything; git-describe spells it with a
    # hyphen. Both mean "before the base release", and only the hyphen was
    # recognised -- so `1.2.3~rc1` had no suffix, parsed as the non-numeric
    # release token `3~rc1`, and passed an anti-rollback watermark set at
    # `1.2.3` that the identical `1.2.3-rc1` was correctly refused by.
    cut = min((i for i in (s.find("-"), s.find("~")) if i >= 0), default=-1)
    if cut >= 0:
        rel, suffix = s[:cut], s[cut + 1:]
    else:
        rel, suffix = s, ""
    rel_key = []
    for tok in rel.split("."):
        # #8969: a non-numeric release token now sorts BELOW every numeric one
        # (-1), where it used to sort ABOVE (1). This is the FAIL-CLOSED
        # direction and it was chosen deliberately rather than inherited: an
        # unparseable version is a candidate we cannot order, and the two
        # outcomes are a refused upgrade (loud, an operator sees it) or a
        # bypassed anti-rollback watermark (silent, an older image replaces a
        # newer one). Measured before the change: `garbage`, `1.2.x` and
        # `1.0.0+build.7` ALL ranked newer than `1.2.3` and passed the
        # watermark, so the fail-open was general and the tilde was one
        # instance of it.
        rel_key.append((0, int(tok)) if tok.isdigit() else (-1, tok))
    if not suffix:
        pre_rank = (1,)                          # base release: after pre-release
    elif suffix[:1].isdigit():
        pre_rank = (2,) + _suffix_key(suffix)    # git-describe "N-gHASH": post-release
    else:
        pre_rank = (0,) + _suffix_key(suffix)    # rc/alpha/beta/...: before the base
    return (rel_key, pre_rank)


# ── #1924 signed channel pointer (#6504) ──────────────────────────────
# publish.py produces, signs and publish-gates a per-channel latest.json
# freshness pointer, and docs/distribution.md named "our scripts" as its
# consumers — but no script read it: `fetch` made --version mandatory, so a
# day-zero operator could not say "give me current stable" without already
# knowing a version string. The signed pointer was a dead letter.
#
# `fetch` with no --version now resolves it from <base>/<channel>/latest.json,
# minisign-verified against the SAME pinned image pubkey that authenticates
# every artifact. The resolved version then flows through the EXISTING path
# unchanged: the #5992 filename-safety validation, the anti-rollback
# watermark, the per-file signature verification, and the import.
#
# A channel name is interpolated into a URL PATH, so it is validated with the
# same fail-closed discipline as a version — `--channel ../../evil` must not
# be able to walk the pointer fetch out of the channel namespace, and the
# channel is also the watermark bucket key.
_CHANNEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


def validate_channel(value, field="--channel"):
    """Reject a channel that could escape its namespace in the pointer URL or
    poison the watermark map. Returns value on success; die()s otherwise."""
    if not isinstance(value, str) or not value:
        die(f"{field} is required and must be a non-empty string")
    if not _CHANNEL_RE.match(value) or ".." in value:
        die(f"{field} '{value}' is not a valid channel name (letters, digits, "
            "'.', '_', '-'; must start alphanumeric and contain no '..')")
    return value


def _resolve_channel_version(base, channel, sign_mod, dry_run=False):
    """Fetch + minisign-verify <base>/<channel>/latest.json and return the
    version it names (#6504).

    The pointer and its signature are downloaded into a PRIVATE 0700 temp dir,
    never into --out: unverified bytes must not land in the operator's
    artifact directory under a predictable name, and nothing but this function
    ever needs them. verify_and_read re-copies and verifies again inside its
    own private dir and returns the VERIFIED bytes, so the JSON parsed here is
    exactly what was signed.

    Fail-CLOSED at every step. A missing pointer, a missing signature, a
    signature that does not verify against the pinned pubkey, unparseable
    JSON, or a version that is not filename-safe all abort — an operator who
    typed no version is trusting this pointer completely, so there is no
    best-effort path where an unverified answer is used anyway.
    """
    url = f"{base}/{channel}/latest.json"
    if dry_run:
        print(f"  (dry-run) curl -fsSL {url} (+ .minisig) -> minisign-verify "
              "against the pinned image pubkey -> take its `version` -> then "
              "fetch + verify + import that version's artifacts as if it had "
              "been passed to --version")
        return None
    tmp = tempfile.mkdtemp(prefix="xpf-latest-")
    os.chmod(tmp, 0o700)
    try:
        latest = os.path.join(tmp, "latest.json")
        sig = latest + ".minisig"
        print(f"==> resolving channel '{channel}': {url}")
        _download_to(url, latest, tmp)
        _download_to(url + ".minisig", sig, tmp)
        try:
            data = sign_mod.verify_and_read(latest, sig)
        except sign_mod.SignError as e:
            die(f"channel pointer {channel}/latest.json FAILED signature "
                f"verification against the pinned image pubkey: {e}. Refusing "
                "to fetch a version named by an unauthenticated pointer.")
        try:
            doc = json.loads(data.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as e:
            die(f"channel pointer {channel}/latest.json verified but is not "
                f"valid JSON: {e}")
        if not isinstance(doc, dict):
            die(f"channel pointer {channel}/latest.json is not a JSON object")
        ver = doc.get("version")
        if not ver:
            die(f"channel pointer {channel}/latest.json names no version "
                f"(got {doc!r})")
        # The pointer's own channel field must agree with the one requested:
        # a stable pointer served at edge/ (a mis-sync, or a swapped object on
        # the host) would otherwise silently deliver the wrong channel while
        # verifying perfectly — both files are signed by the same key.
        got_chan = doc.get("channel")
        if got_chan is not None and got_chan != channel:
            die(f"channel pointer at {channel}/latest.json says it is for "
                f"channel {got_chan!r} — refusing (a mis-synced or swapped "
                "pointer verifies fine; the signature says who wrote it, not "
                "where it belongs).")
        # #5992: this string is about to name artifact FILES. Validate BEFORE
        # it reaches any path, exactly as an operator-supplied --version is.
        ver = validate_version(ver, f"version from {channel}/latest.json")
        print(f"==> channel '{channel}' -> version {ver} (signature OK)")
        return ver
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _download_to(url, dst, workdir):
    """Download `url` to `dst` via an EXCLUSIVELY-created, unpredictable temp in
    `workdir`, then publish atomically with os.replace (#5817).

    mkstemp opens with O_CREAT|O_EXCL and a random name, so a concurrent fetch
    to the same --out, or a pre-planted predictable `<dst>.tmp`, cannot collide
    with or clobber the in-flight download (the old shared `<dst>.tmp` had no
    exclusive create — two fetches raced onto the same path). The temp is
    unlinked on download failure and consumed by the atomic rename on success."""
    fd, tmp = tempfile.mkstemp(
        prefix="." + os.path.basename(dst) + ".", suffix=".tmp", dir=workdir)
    os.close(fd)
    r = subprocess.run(["curl", "-fsSL", "-o", tmp, url])
    if r.returncode != 0:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        die(f"download failed: {url}")
    os.replace(tmp, dst)


@contextlib.contextmanager
def _verified_private_artifacts(sign_mod, out, names, keys, manifest, sig):
    """Yield a {key: path} map of artifacts COPIED into a private 0700 staging
    dir and re-verified there — closing the verify-by-name / use-by-name TOCTOU
    (#5817).

    The public --out dir may be writable by another local process. Verifying a
    file at its public pathname and THEN handing that same pathname to libvirt
    (`_install_libvirt_golden` copy-to-golden) or `incus image import` lets a
    dir-writer swap unauthenticated bytes into the file BETWEEN the checksum
    check and the consumer's open — the verified inode is not retained. Instead
    we copy each artifact into a mkdtemp (0700, owned by us, OUTSIDE --out — the
    same private-copy pattern sign.verify_and_read / verify_listed_artifact_bytes
    use for the directly-signed TOCTOU class) and verify the COPY in place, then
    give the consumer THAT path. Nothing that can write --out can reach the
    staging dir, so the bytes the consumer reads are exactly the bytes that were
    verified. Portable for BOTH consumers: each accepts a pathname and this hands
    them a private one whose bytes cannot be swapped after the check.

    The manifest + its .minisig stay in --out: they are self-authenticating
    (verify_and_read re-checks the signature over the manifest bytes on every
    call, and an attacker without the secret key cannot forge a manifest listing
    a tampered artifact's hash), so only the checksummed artifacts need staging."""
    stage = tempfile.mkdtemp(prefix="xpf-verify-")
    try:
        os.chmod(stage, 0o700)
        staged = {}
        for k in keys:
            name = names[k]
            src = os.path.join(out, name)
            dst = os.path.join(stage, name)
            shutil.copyfile(src, dst)
            try:
                sign_mod.verify_image_artifact(dst, manifest, sig)
            except sign_mod.SignError as e:
                die(f"VERIFICATION FAILED for {name}: {e}")
            staged[k] = dst
        yield staged
    finally:
        shutil.rmtree(stage, ignore_errors=True)


def _validation_verdict(fields):
    """Read a VERIFIED provenance sidecar's `validated` field (#9325).

    Returns (state, reason): "true"; "false" for anything a bake did not write
    as true, a garbled value included; or "absent" for a sidecar from a bake
    that predates #4904 binding the field."""
    if "validated" not in fields:
        return "absent", ("the signed provenance sidecar has no `validated` field "
                          "(a bake that predates #4904), so whether the image passed "
                          "the in-guest verify-dataplane gate cannot be confirmed")
    if fields["validated"].strip().lower() == "true":
        return "true", "validated: true"
    return "false", (f"its signed provenance sidecar records validated: "
                     f"{fields['validated']} -- the in-guest verify-dataplane gate "
                     f"did not pass (a --skip-validate bake)")


def _require_validated_fetch(sign, out, names, ver, fetch_one, allow_unvalidated):
    """#9325: refuse to fetch an image whose SIGNED provenance sidecar says it
    was not validated, before the image itself is downloaded.

    A `--skip-validate` bake signs `validated: false`, and publish.py refuses
    to publish such an image -- but that is one chokepoint, and a signed image
    reaches a host through any mirror or copy. The sidecar is covered by the
    signed SHA256SUMS, so it is read from VERIFIED bytes.

    - listed, `validated: true`: proceed.
    - listed, anything else: refuse unless --allow-unvalidated.
    - listed but not retrievable or not matching: refuse; the override does
      not cover a sidecar the signature lists and the mirror withholds.
    - listed but without the field, or not listed at all: a release that
      predates the sidecar or the field; warn.
    """
    manifest = os.path.join(out, names["manifest"])
    sig = os.path.join(out, names["sig"])
    sidecar = f"xpf-{ver}.manifest"
    try:
        listed = sidecar in sign.verify_manifest_map(manifest, sig)
    except sign.SignError as e:
        die(f"VERIFICATION FAILED for {names['manifest']}: {e}")
    if not listed:
        print(f"==> WARNING: {names['manifest']} lists no provenance sidecar "
              f"({sidecar}), so whether {ver} passed the in-guest verify-dataplane "
              f"gate cannot be confirmed (a release that predates #4904)")
        return
    path = fetch_one(sidecar)
    try:
        data = sign.verify_listed_artifact_bytes(path, manifest, sig)
    except sign.SignError as e:
        die(f"VERIFICATION FAILED for {sidecar}: {e}")
    state, reason = _validation_verdict(
        _parse_image_manifest_versions(data.decode("utf-8", "replace")))
    if state == "true":
        print(f"==> provenance OK: {sidecar} (validated: true)")
    elif state == "absent":
        print(f"==> WARNING: {reason}")
    elif not allow_unvalidated:
        die(f"refusing to fetch {ver}: {reason}.\n"
            f"    An unvalidated image is a dev or emergency build. Pass "
            f"--allow-unvalidated to fetch it anyway.")
    else:
        print(f"==> WARNING: fetching {ver} with --allow-unvalidated: {reason}")


def cmd_fetch(args):
    """Download an appliance image from XPF_IMAGE_BASE_URL, VERIFY the exact
    downloaded bytes against the signed per-version manifest (#1924 §5.2),
    then import it to a local incus alias. Verification happens HERE (at
    fetch/import), not at deploy/launch — the alias-launch path consumes a
    previously-verified alias. This is the only deploy-side place that
    touches raw image bytes, so it is where the signature is bound."""
    HERE_D = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, os.path.join(os.path.dirname(HERE_D), "dist"))
    import sign  # noqa: E402

    base = args.image_url or os.environ.get("XPF_IMAGE_BASE_URL")
    if not base:
        die("fetch needs --image-url or XPF_IMAGE_BASE_URL (the image host).")
    base = base.rstrip("/")
    # The channel is both a URL path segment (the #6504 pointer fetch) and the
    # watermark bucket key, so validate it whether or not a version was given.
    validate_channel(args.channel)
    # #6504: no --version means "give me this channel's current release" —
    # resolve it from the SIGNED latest.json publish.py already produces and
    # gates. The resolved string then takes the identical path an operator's
    # --version takes, validation included.
    if args.version is None:
        resolved = _resolve_channel_version(base, args.channel, sign,
                                            dry_run=args.dry_run)
        if resolved is None:      # dry-run: nothing to name yet
            return 0
        args.version = resolved
    # #5992: the version is interpolated into artifact WRITE paths below
    # (xpf-<ver>.qcow2 …). Reject a path-escaping / crafted version BEFORE it
    # names any file, so `--version '../../etc/x'` cannot redirect the download
    # out of --out. (contained_join at the write is the defense-in-depth belt.)
    ver = validate_version(args.version, "--version")
    out = os.path.abspath(args.out or os.getcwd())
    os.makedirs(out, exist_ok=True)

    # Best-effort monotonic anti-rollback watermark (#1924 §5.6 / NIT-3):
    # remember the highest version fetched per channel so a stale mirror
    # serving an OLDER (still-signed) version is detected. Stateless CLI, so
    # this is best-effort: a fresh workstation has no watermark and trusts the
    # artifact's own signature. Override the channel with --channel; bypass the
    # guard with --allow-rollback (e.g. a deliberate downgrade).
    state_home = os.environ.get("XDG_STATE_HOME") or os.path.expanduser(
        "~/.local/state")
    wm_path = os.path.join(state_home, "xpf", "image-watermark.json")

    # Version ordering for the watermark lives at module scope (`_ver_key`,
    # unit-tested) — numeric-split so rc10 > rc9 and describe-count 10 > 9.

    def read_watermark():
        try:
            with open(wm_path) as f:
                return json.load(f)
        except (OSError, ValueError):
            return {}

    if not args.dry_run and not args.allow_rollback:
        wm = read_watermark()
        prev = wm.get(args.channel)
        if prev and _ver_key(ver) < _ver_key(prev):
            die(f"requested version {ver} is OLDER than the last fetched "
                f"{prev} on channel '{args.channel}' (possible stale mirror / "
                "rollback). Pass --allow-rollback for a deliberate downgrade.")

    names = {
        "qcow2": f"xpf-{ver}.qcow2",
        "metadata": f"xpf-{ver}.incus-metadata.tar.gz",
        "manifest": f"xpf-{ver}.SHA256SUMS",
        "sig": f"xpf-{ver}.SHA256SUMS.minisig",
    }

    def fetch_one(name):
        # #5992 defense-in-depth: even with the validated version above, refuse
        # a write target that resolves outside `out`.
        dst = contained_join(out, name, "artifact")
        url = f"{base}/{name}"
        if args.dry_run:
            print(f"  (dry-run) curl -fsSL {url} -> {dst}")
            return dst
        print(f"==> fetching {url}")
        # #5817: exclusive-create unpredictable temp + atomic publish (no shared
        # predictable `<dst>.tmp` a concurrent fetch could collide/overwrite).
        _download_to(url, dst, out)
        return dst

    # Need at least the manifest + sig + the artifact(s) the operator wants.
    want = ["qcow2"] if args.qcow2_only else ["qcow2", "metadata"]
    fetch_one(names["manifest"])
    fetch_one(names["sig"])
    if not args.dry_run:
        _require_validated_fetch(sign, out, names, ver, fetch_one,
                                 getattr(args, "allow_unvalidated", False))
    for w in want:
        fetch_one(names[w])

    if args.dry_run:
        print("  (dry-run) verify each fetched file against the signed manifest,"
              " then incus image import")
        return 0

    manifest = os.path.join(out, names["manifest"])
    sig = os.path.join(out, names["sig"])
    # #9170: KEEP the digest each verification established. The --no-import
    # branch below prints one for the operator to check at install time, and
    # the only trustworthy source for it is the signed manifest entry this
    # call already compared against — not a later re-read of a public path.
    verified_sha = {}
    for w in want:
        path = os.path.join(out, names[w])
        try:
            verified_sha[w] = sign.verify_image_artifact(path, manifest, sig)
            print(f"==> signature OK: {names[w]}")
        except sign.SignError as e:
            die(f"VERIFICATION FAILED for {names[w]}: {e}")

    # #9238 — the late watermark check is a DECISION, and the whole
    # read-compare-publish is ONE transaction.
    #
    # This block used to re-read `prev`, and when the comparison failed simply
    # not take the branch: no die, no warning, execution falling through to the
    # alias import / golden replacement below. That is the one place in the
    # process holding correct information about the inversion, and it threw it
    # away. Two overlapping fetches could therefore end with the watermark at
    # v2 and the thing that actually boots at v1:
    #
    #   A verifies v1, passes the early check, stalls
    #   B verifies v2, advances the watermark, publishes      wm=v2 alias=v2
    #   A resumes, re-reads prev=v2, skips the write, PUBLISHES     alias=v1
    #
    # Deploy only checks alias/golden existence, so v1 is then consumed as the
    # stable identity with nothing dissenting. No forged signature and no
    # --allow-rollback is involved; both images are legitimately signed and the
    # ordering does all the work.
    #
    # The original comment reasoned only about NOT advancing on a bad fetch
    # ("so a failed/tampered fetch never moves it"), which is correct and is
    # retained below. It never considered the watermark moving underneath a
    # GOOD fetch, which is this case.
    #
    # Half 1: an inversion aborts BEFORE anything is published.
    # Half 2: the lock spans the read, the compare AND the publish, so a second
    # fetch cannot slip between the check and the alias import. Without it half
    # 1 is only a narrower race. Lock ORDER is watermark-then-golden
    # (_install_libvirt_golden takes _golden_lock inside this block); nothing
    # takes them the other way round.
    with _watermark_lock(wm_path):
        # Advance the monotonic watermark only AFTER a successful verify (so a
        # failed/tampered fetch never moves it). Best-effort: a write failure is
        # non-fatal (the signature is the real gate).
        if not args.allow_rollback:
            wm = read_watermark()
            prev = wm.get(args.channel)
            if prev and _ver_key(ver) < _ver_key(prev):
                die(f"channel '{args.channel}' advanced to {prev} while this "
                    f"fetch of {ver} was verifying — refusing to publish {ver} "
                    f"over it. The artifact is validly signed but is no longer "
                    f"the newest version installed on this channel; publishing "
                    f"it would leave the anti-rollback watermark at {prev} and "
                    f"the image that actually boots at {ver}. This is a "
                    f"concurrent-fetch collision: re-run the fetch (it will "
                    f"pick up {prev}), or pass --allow-rollback for a "
                    f"deliberate downgrade.")
            try:
                if not prev or _ver_key(ver) >= _ver_key(prev):
                    wm[args.channel] = ver
                    os.makedirs(os.path.dirname(wm_path), exist_ok=True)
                    tmpw = wm_path + ".tmp"
                    with open(tmpw, "w") as f:
                        json.dump(wm, f, indent=2, sort_keys=True)
                    os.replace(tmpw, wm_path)
            except OSError:
                pass  # best-effort; never block a verified fetch on watermark I/O

        # libvirt golden basename = deploy's `image:` default, so the incus alias
        # and the libvirt golden name AGREE (fable-165 H-30).
        img_name = args.alias or "xpf-appliance"
        # Public path for the non-consuming (--no-import) message only. The two
        # in-process consumers below read from a private staging dir, NOT this
        # re-openable public path (#5817).
        qcow2_pub = os.path.join(out, names["qcow2"])

        # H-30: bridge the fetch -> libvirt gap. `deploy --hypervisor libvirt`
        # reads the golden at libvirt_golden_path(image); --install-libvirt puts
        # the verified qcow2 there (shared path helper — the two can't drift).
        if args.install_libvirt:
            # #5817: install the qcow2 to the golden from the private staging copy,
            # so a post-verify swap in --out cannot poison the golden.
            with _verified_private_artifacts(
                    sign, out, names, ["qcow2"], manifest, sig) as staged:
                _install_libvirt_golden(staged["qcow2"], img_name)
            print(f"==> done. Deploy with: xpf-deploy.py --hypervisor libvirt "
                  f"deploy <appliance.yaml>  (image: {img_name})")
            return 0

        if args.no_import or args.qcow2_only:
            golden = libvirt_golden_path(img_name)
            # #8597 (muse-004 K08): the printed install must be GATED on the digest,
            # not merely preceded by a verification that already happened.
            #
            # The two importing paths above stage into a private directory
            # (_verified_private_artifacts, #5817) and re-verify the staged copy, so
            # "a post-verify swap in --out cannot poison the golden". This path
            # cannot do that — it hands the operator a command to run LATER, so the
            # gap between the verify and the install is unbounded and is exactly the
            # window _verified_private_artifacts' own docstring names: "The public
            # --out dir may be writable by another local process."
            #
            # Printing the expected digest and a verify-then-install one-liner moves
            # the check to the moment of the write. `sha256sum -c` here is bound to
            # THIS path and THIS digest on one line, so it is not the cwd-relative
            # `sha256sum -c` sign.py warns about — the file being hashed is the file
            # being installed.
            # #9170: the digest is the SIGNED one, taken from the verification
            # above — NOT a re-hash of qcow2_pub. A re-hash binds the bytes in
            # --out at print time, which is after the signature check finished,
            # so a dir-writer who wins that window gets its bytes installed AND
            # gets the operator's own `sha256sum -c` to bless them. The gap is
            # not sub-millisecond: a full verify_manifest_map -> verify_and_read
            # -> minisign subprocess, two mkdtemp/rmtree cycles and the
            # watermark os.replace sit inside it.
            expected_sha = verified_sha["qcow2"]
            print(f"==> verified into {out} (not imported). For libvirt/KVM, install "
                  f"it to the golden path deploy reads — RE-VERIFY at install time, "
                  f"because {out} stays writable by any local process after this "
                  f"command exits and the golden is not re-checked downstream:\n"
                  f"      echo '{expected_sha}  {qcow2_pub}' | sha256sum -c - && \\\n"
                  f"        sudo install -m 0644 -D {qcow2_pub} {golden}\n"
                  f"   (or re-run fetch with --install-libvirt, which stages the "
                  f"bytes privately and re-verifies them, #5817), then: "
                  f"xpf-deploy.py --hypervisor libvirt deploy <appliance.yaml> "
                  f"(image: {img_name}). For incus, re-run without "
                  f"--qcow2-only/--no-import.")
            return 0

        alias = img_name
        subprocess.run(["incus", "image", "delete", alias],
                       capture_output=True, text=True)
        print(f"==> importing verified image as incus alias '{alias}'")
        # #5817: import from the private staging dir so a post-verify swap of the
        # public metadata/qcow2 in --out cannot feed unauthenticated bytes to
        # `incus image import`. The dir is rmtree'd once the import returns.
        with _verified_private_artifacts(
                sign, out, names, ["metadata", "qcow2"], manifest, sig) as staged:
            r = subprocess.run(["incus", "image", "import",
                                staged["metadata"], staged["qcow2"], "--alias", alias])
        if r.returncode != 0:
            die("incus image import failed")
        print(f"==> done. Deploy with: xpf-deploy.py deploy <appliance.yaml> "
              f"(image: {alias})")
        return 0


# ── LANE-1 HA kernel-rolling orchestration (#1930 INC-2) ──────────────────
#
# Drive a verify-gated kernel bump across an HA pair ONE NODE AT A TIME so the
# cluster keeps forwarding. Per the converged plan (§3.1-HA): the per-node
# arm/verify/promote/revert is owned by the in-guest `xpfd upgrade kernel`
# (INC-1, merged); this EXTERNAL driver survives the per-node reboots (an
# in-process driver would die at the reboot it triggers) and owns the cross-node
# sequencing + the "never both down" gate.
#
# Sequence per node N (peer P stays primary throughout):
#   1. hold a LEASE naming N (TTL) on BOTH nodes — suppresses N's local
#      self-recovery (INC-2 Go side) so it won't fight the roll, and is the
#      cluster-wide lock (a crashed driver's lease expires, freeing future rolls).
#   2. drain N -> P (xpfd upgrade kernel relies on the node being secondary; we
#      demote via the cluster CLI) and confirm P holds the RGs.
#   3. `xpfd upgrade kernel arm <ver>` on N -> N installs+arms+reboots into the
#      candidate; the in-guest promotion oneshot verifies+promotes or reverts.
#   4. poll N until it is back AND `uname -r == <ver>` AND `xpfd upgrade kernel
#      status` reports `promoted=<ver>` (a REVERTED node boots the OLD kernel and
#      reports promoted!=<ver> -> we STOP and leave P primary, never touch P).
#   5. rejoin N (clear failover) + confirm sync re-established.
#   6. release N's lease, then repeat for P.
#
# If a true cross-node reboot-roll cannot be driven (e.g. --dry-run, or a node
# is unreachable), the driver aborts BEFORE draining the second node, so the
# cluster never ends up with both nodes down.

class NodeExecResult:
    """Structured result of a node command: exit code, stdout, stderr, and an
    `ok` flag (transport + command both succeeded).

    The kernel roll needs to tell an empty-BECAUSE-the-command-succeeded read
    apart from an empty-BECAUSE-the-transport-failed read (SSH/incus drop,
    control-socket contention, a `uname` that never ran). The old wrapper
    returned only stdout, collapsing both to "" — so a single transient status
    failure was misread as a completed reboot and the drained node was left
    ForceSecondary with its leases released (#4905-A). `ok` is the affirmative
    signal that distinguishes the two."""

    __slots__ = ("rc", "out", "err", "ok")

    def __init__(self, rc, out, err, ok):
        self.rc = rc
        self.out = out
        self.err = err
        self.ok = ok


def _node_exec_argv(backend, node, argv):
    """Build the full host argv that runs `argv` inside `node` (incus|ssh)."""
    if backend == "ssh":
        # Non-interactive automation: never hang on a host-key / password prompt
        # or a dead host (Copilot). BatchMode disables all prompts (fail fast
        # instead), ConnectTimeout bounds the TCP connect.
        #
        # ssh space-JOINS its remote-command argv into one string and the
        # REMOTE login shell re-splits it, so a multi-word element (notably
        # `sh -c "<script with spaces>"` used by the lease helpers and the
        # --allow-mixed-ha probe) is shredded — `sh -c echo hi` would run an
        # empty `sh -c` then `hi` as a separate command (r2 AGY HIGH). incus
        # exec passes argv through verbatim, so this only bites the ssh backend.
        # Quote each element so the remote shell reconstructs the exact argv.
        remote = " ".join(shlex.quote(a) for a in argv)
        # No "--" before the remote command: ssh has no option/command
        # separator — getopt stops at the destination (`node`), so everything
        # after it is the remote command. A literal "--" would be sent as the
        # first token of the remote command string, and the remote login shell
        # would try to run `-- <cmd>` → "--: command not found" (Copilot).
        return ["ssh",
                "-o", "BatchMode=yes",
                "-o", "ConnectTimeout=15",
                node, remote]
    return ["incus", "exec", node, "--"] + argv


def _node_exec_result(runner, backend, node, argv):
    """Run argv inside `node`; return a NodeExecResult (never die()s).

    Unlike _node_exec, this preserves the exit code + stderr so callers can
    distinguish a transport/command FAILURE from legitimately-empty output
    (#4905-A reboot detection). In dry-run it prints the command and returns an
    ok result with empty output (nothing executed)."""
    full = _node_exec_argv(backend, node, argv)
    if runner.dry:
        print("   " + " ".join(shlex.quote(a) for a in full))
        return NodeExecResult(0, "", "", True)
    r = subprocess.run(full, capture_output=True, text=True)
    return NodeExecResult(r.returncode, r.stdout, r.stderr, r.returncode == 0)


def _node_exec(runner, backend, node, argv, check=True):
    """Run argv inside `node` via the chosen backend (incus|ssh).

    Returns stdout (string) for the many callers that only need it. Callers
    that must distinguish a transport failure from empty output (kernel-roll
    reboot detection) use _node_exec_result instead (#4905-A)."""
    res = _node_exec_result(runner, backend, node, argv)
    if check and not res.ok and not runner.dry:
        die(f"{node}: command failed ({' '.join(argv)}): "
            f"{res.out.strip()} {res.err.strip()}")
    return res.out


def _acquire_lease(runner, backend, node, target_node_id, holder, ttl_secs):
    """ATOMICALLY acquire the lease on `node`, or die if another holder has an
    unexpired one. The whole read-expired-decide-write is run inside an
    OS-level flock on a dedicated lock file, so the expired-lease RECLAIM is
    serialized too — closing the r3-Codex TOCTOU where a stale-read `rm` could
    delete a racing driver's just-created live lease. (flock is util-linux,
    present on the Debian/Ubuntu appliance base.) expires_at is rendered in the
    NODE's clock (clock-skew safe)."""
    h = holder.replace('"', "")
    # Inner critical section (runs while holding the flock): reclaim ONLY an
    # expired lease, then create the new one. Because the whole section is
    # serialized by flock, no other driver can interleave between the reclaim
    # and the create.
    crit = (
        "f=/var/lib/xpf/kernel-roll.lease; "
        'if [ -f "$f" ]; then '
        'exp=$(sed -n \'s/.*"expires_at": *"\\([^"]*\\)".*/\\1/p\' "$f"); '
        'now=$(date -u +%%s); ee=$(date -u -d "$exp" +%%s 2>/dev/null || echo 0); '
        # live lease held by someone else -> do NOT touch it; fail to acquire.
        'if [ "$now" -lt "$ee" ]; then exit 1; fi; '
        'fi; '
        "exp=$(date -u -d \"+%d seconds\" +%%Y-%%m-%%dT%%H:%%M:%%SZ); "
        "umask 022; "
        # Write to a temp file then atomic-rename, so a reader (the self-recovery
        # loop, which does NOT take the flock) never observes a partial/truncated
        # lease (r2 AGY non-atomic-write). The flock still serializes writers.
        "printf '{\"node_id\": %d, \"holder\": \"%s\", \"expires_at\": \"%%s\"}' "
        "\"$exp\" > \"$f.tmp\" && mv -f \"$f.tmp\" \"$f\""
    ) % (ttl_secs, target_node_id, h)
    # flock -w 30 serializes the critical section across concurrent drivers on
    # this node; -E 9 distinguishes a lock-acquire timeout (exit 9) from the
    # critical section's own exit-1 (live lease held).
    script = (
        "mkdir -p /var/lib/xpf; "
        "flock -w 30 -E 9 /var/lib/xpf/kernel-roll.lock "
        "sh -c " + shlex.quote(crit) + " && echo ACQUIRED"
    )
    out = _node_exec(runner, backend, node, ["sh", "-c", script], check=False)
    # Return whether WE won the lease (the caller releases-what-it-got + aborts
    # on a partial acquisition, rather than die()ing here with a stranded lease).
    return runner.dry or "ACQUIRED" in out


def _clear_lease(runner, backend, node, holder):
    # Release ONLY if WE still hold the lease (holder matches), under the same
    # flock as acquire (r4 Codex: an unconditional rm could delete a SUCCESSOR's
    # live lease if ours had expired and someone else re-acquired). No unlocked
    # fallback — a failure to take the lock means we do NOT delete (safer to
    # leave a lease that will expire than to delete a live successor's).
    h = holder.replace('"', "")
    crit = (
        'f=/var/lib/xpf/kernel-roll.lease; [ -f "$f" ] || exit 0; '
        'cur=$(sed -n \'s/.*"holder": *"\\([^"]*\\)".*/\\1/p\' "$f"); '
        '[ "$cur" = "%s" ] && rm -f "$f"; exit 0'
    ) % h
    _node_exec(runner, backend, node, ["sh", "-c",
               "flock -w 30 /var/lib/xpf/kernel-roll.lock sh -c " + shlex.quote(crit)],
               check=False)


def _renew_lease(runner, backend, node, target_node_id, holder, ttl_secs):
    """RENEW our reservation lease on `node` iff WE still own it (holder
    matches), extending `expires_at = node_now + ttl`. Returns one of:

      "owned"       — we still hold it; the deadline was re-written atomically.
      "lost"        — the node is REACHABLE but the lease is gone / reclaimed by
                      another holder (its `holder` no longer matches ours). We
                      must NOT recreate it — another orchestrator owns the pair.
      "unreachable" — a TRANSPORT/lock failure (SSH/incus drop, control-socket
                      contention, mid-reboot). UNKNOWN, never a loss (#4905-A
                      discipline): the caller retries rather than fencing.

    The whole read-decide-rewrite runs under the SAME flock as acquire/clear so
    a renew can never race a concurrent reclaim, and the new deadline is written
    temp+rename so a reader (the Go self-recovery loop, which does NOT take the
    flock) never sees a torn lease. Crucially the rewrite is holder-guarded:
    a lease another orchestrator has already reclaimed (holder differs) is left
    untouched and reported "lost" — renewal never resurrects a lost lease.

    This is the RENEWAL half of the #5816 fix: a one-shot wall-clock lease with
    no renewal expires while a legitimately-slow roll is still running, letting
    a successor reclaim the pair (split-brain). Renewing while-owned keeps the
    lease valid across the roll's real duration; the `_fence_before_mutate`
    fence uses the "lost" verdict to refuse mutating a pair we no longer own.
    Note: because renewal keeps the lease alive ONLY while this orchestrator is
    live, the Go crashed-roll self-recovery (which fires on an EXPIRED lease)
    still triggers correctly if the orchestrator dies — it just no longer fires
    against a slow-but-alive driver."""
    if runner.dry:
        return "owned"
    h = holder.replace('"', "")
    # Inner critical section (under flock): confirm WE still hold the lease,
    # then rewrite its deadline. A missing file or a holder mismatch prints
    # LOST and does NOT write; a match rewrites expires_at and prints RENEWED.
    crit = (
        'f=/var/lib/xpf/kernel-roll.lease; '
        '[ -f "$f" ] || { echo LOST; exit 0; }; '
        'cur=$(sed -n \'s/.*"holder": *"\\([^"]*\\)".*/\\1/p\' "$f"); '
        'if [ "$cur" != "%s" ]; then echo LOST; exit 0; fi; '
        "exp=$(date -u -d \"+%d seconds\" +%%Y-%%m-%%dT%%H:%%M:%%SZ); "
        "umask 022; "
        "printf '{\"node_id\": %d, \"holder\": \"%s\", \"expires_at\": \"%%s\"}' "
        "\"$exp\" > \"$f.tmp\" && mv -f \"$f.tmp\" \"$f\" && echo RENEWED"
    ) % (h, ttl_secs, target_node_id, h)
    script = (
        "mkdir -p /var/lib/xpf; "
        "flock -w 30 /var/lib/xpf/kernel-roll.lock "
        "sh -c " + shlex.quote(crit)
    )
    # Use the STRUCTURED wrapper so a transport failure (un-ok) is distinguished
    # from a reachable LOST — a mid-reboot node's unreachable read must NEVER be
    # misread as a lost lease (the #4905-A trap). Only a reachable, affirmative
    # LOST is a real loss.
    res = _node_exec_result(runner, backend, node, ["sh", "-c", script])
    if not res.ok:
        return "unreachable"
    if "RENEWED" in res.out:
        return "owned"
    if "LOST" in res.out:
        return "lost"
    # Unexpected output (truncated read, unknown token) — fail safe as unknown,
    # not as a confirmed loss.
    return "unreachable"


def _keepalive_leases(runner, backend, targets, holder, ttl_secs):
    """Renew our lease on each REACHABLE target during a long wait (the boot
    poll), returning the name of any target where we have provably LOST the
    lease (reclaimed by another orchestrator), else None.

    `targets` is a list of (node_name, node_id). A target that is momentarily
    UNREACHABLE (transport blip, or the rolled node mid-reboot) is left for the
    next tick — never misread as a loss. This keeps the still-up PEER's lease
    alive throughout, which is the load-bearing reservation: as long as the peer
    lease is renewed, a successor can never acquire BOTH node leases and start a
    concurrent roll."""
    for name, nid in targets:
        if _renew_lease(runner, backend, name, nid, holder, ttl_secs) == "lost":
            return name
    return None


def _fence_before_mutate(runner, backend, targets, holder, ttl_secs, action,
                         on_lost=None):
    """FENCE: renew-and-verify ownership of EVERY lease in `targets` immediately
    before a pair-mutating action, or die() fail-closed. This is the load-bearing
    invariant of #5816: an orchestrator that has lost (or cannot confirm) its
    lease MUST NOT perform a pair-mutating action (drain / arm+reboot / image
    recreate / rejoin) — otherwise a successor that reclaimed the expired lease
    and a stalled predecessor both mutate the same HA pair (split-brain deploy).

    Each target is renewed (extending the deadline to a fresh full TTL, so the
    common legitimately-slow case never loses the lease at a phase boundary). A
    confirmed LOSS aborts immediately; a transient UNREACHABLE is retried a few
    times, then — still unable to prove ownership — also aborts fail-closed (we
    would rather stop a roll we cannot prove we own than risk mutating a pair a
    peer may now own). `targets` is a list of (node_name, node_id).

    `on_lost`, when supplied, is invoked immediately BEFORE the fail-closed
    die() — on BOTH a confirmed loss AND an unconfirmable (persistently
    unreachable) lease. die() raises SystemExit, so a caller's `finally` block
    still runs while unwinding; a caller whose finally performs a best-effort
    pair mutation (e.g. cmd_kernel_roll's restore-forwarding rejoin) uses this
    hook to record that it no longer safely owns the pair and SUPPRESS that
    mutation. An unconfirmable lease is treated as unsafe-to-mutate exactly like
    a proven loss — the same fail-closed stance the fence itself takes."""
    if runner.dry:
        return
    import time as _time
    for name, nid in targets:
        st = "unreachable"
        for attempt in range(3):
            st = _renew_lease(runner, backend, name, nid, holder, ttl_secs)
            if st in ("owned", "lost"):
                break
            if attempt < 2:
                _time.sleep(1)   # brief retry to ride out a transient blip
        if st == "lost":
            if on_lost is not None:
                on_lost()
            die(f"{name}: LOST the roll lease before {action} — another "
                f"orchestrator has reclaimed the HA-pair reservation. Refusing "
                f"to {action}: an orchestrator that no longer holds the lease "
                f"must NOT mutate the pair (split-brain deploy). Investigate "
                f"the half-rolled cluster before retrying.")
        if st != "owned":
            if on_lost is not None:
                on_lost()
            die(f"{name}: could NOT confirm the roll lease before {action} "
                f"(node unreachable / lock contended after retries). Refusing "
                f"to {action} fail-closed — an orchestrator that cannot prove it "
                f"still holds the pair reservation must not mutate the pair.")


def _kernel_status(runner, backend, node):
    """Return dict parsed from `xpfd upgrade kernel status` (promoted=, armed=)."""
    out = _node_exec(runner, backend, node,
                     ["xpfd", "upgrade", "kernel", "status"], check=False)
    st = {}
    for line in out.splitlines():
        for tok in line.split():
            if "=" in tok:
                k, v = tok.split("=", 1)
                st[k] = v
    return st


def _running_kernel_result(runner, backend, node):
    """(ok, release): `ok` is False on a transport/command failure (SSH/incus
    drop, control-socket contention), True with the stripped `uname -r` output
    otherwise. The roll loop must NOT treat an un-ok read as a reboot (#4905-A)."""
    res = _node_exec_result(runner, backend, node, ["uname", "-r"])
    return res.ok, (res.out.strip() if res.ok else "")


def _boot_id(runner, backend, node):
    """The node's boot_id (/proc/sys/kernel/random/boot_id) — a fresh UUID on
    every boot — or "" if it could not be read. A CHANGED boot_id across the
    arm is the affirmative reboot signal the roll uses; a transport failure
    returns "" (unknown), which is NEVER treated as a reboot (#4905-A)."""
    res = _node_exec_result(runner, backend, node,
                            ["cat", "/proc/sys/kernel/random/boot_id"])
    return res.out.strip() if res.ok else ""


def _reboot_confirmed(pre_boot_id, cur_boot_id, running, version):
    """Affirmative reboot test (#4905-A). A reboot is confirmed ONLY by a
    positive signal — a CHANGED boot_id, or the candidate kernel actually
    running — NEVER by an empty/failed status read. Returns True iff an
    affirmative signal is present.

    This is the crux of the #4905-A fix: the old loop set rebooted=True on ANY
    empty `uname -r` read, so one transient SSH/incus blip made a
    still-drained-and-running node look like a completed revert, and the finally
    skipped its rejoin — leaving the node ForceSecondary with its leases gone."""
    if cur_boot_id and pre_boot_id and cur_boot_id != pre_boot_id:
        return True
    if running and version and running == version:
        return True
    return False


def cmd_kernel_roll(args):
    import time as _time
    runner = Runner(args.dry_run)
    backend = args.backend
    nodes = args.nodes               # ordered [first-to-roll, second]
    # Validate the pair BEFORE indexing nodes[0]/nodes[1] (Copilot: a single
    # --node would otherwise raise IndexError instead of a clear message; two
    # identical --node values would collapse the dict to one key).
    if len(nodes) != 2:
        die("kernel-roll needs exactly two --node arguments (the HA pair)")
    if nodes[0] == nodes[1]:
        die(f"kernel-roll needs two DISTINCT nodes; got {nodes[0]} twice")
    node_ids = {nodes[0]: args.node0_id, nodes[1]: args.node1_id}
    version = args.version
    # Sanitize the holder to a safe token set (r2 AGY): the nodename is
    # interpolated into a shell printf AND a Python %-format, so strip anything
    # that isn't [A-Za-z0-9._-] (drops quotes, %, spaces, shell metachars).
    import re as _re
    _raw_holder = f"{os.uname().nodename}:pid{os.getpid()}"
    holder = _re.sub(r"[^A-Za-z0-9._:-]", "_", _raw_holder)
    lease_ttl = args.lease_ttl
    poll_deadline = args.boot_deadline

    print(f"==> LANE-1 HA kernel roll to {version}: {nodes[0]} then {nodes[1]} "
          f"(one node at a time; peer keeps forwarding)")

    def roll_one(node, peer):
        nid = node_ids[node]
        print(f"\n--- rolling {node} (node-id {nid}); {peer} stays primary ---")
        # 1. ATOMICALLY acquire the lease on BOTH nodes (cross-driver mutex,
        #    flock-serialized + holder-guarded). Acquire in a CANONICAL order
        #    (sorted node name), NOT the roll order, so two drivers rolling in
        #    OPPOSITE order can't each grab one node and deadlock (r5 Codex):
        #    both contend for the same node's lease first. If we get the first
        #    but not the second, RELEASE the first (no stranded lease until TTL)
        #    and abort. Acquiring on `node` also suppresses its self-recovery.
        ordered = sorted([node, peer])
        got = []
        for n in ordered:
            if _acquire_lease(runner, backend, n, nid, holder, lease_ttl):
                got.append(n)
            else:
                for g in got:
                    _clear_lease(runner, backend, g, holder)
                die(f"{n}: could not acquire kernel-roll lease (a live lease is "
                    f"held by another orchestrator, or the lock timed out) — "
                    f"released {got or 'nothing'} and aborting.")
        drained = False        # we issued a confirmed drain (node is ForceSecondary)
        completed = False      # the roll finished (rejoin confirmed) OR the node
                               # rebooted (revert/promote — drain state is gone)
        rebooted = False       # the node actually rebooted into the candidate
        lost_lease = False     # a fence/keepalive proved (or could not disprove)
                               # a successor reclaimed the pair reservation. The
                               # best-effort restore-forwarding rejoin in the
                               # finally MUST be suppressed once this is set: a
                               # die() is a SystemExit, so the finally still runs
                               # after a fence-abort, and an orchestrator that has
                               # lost its lease must NOT mutate (un-drain) a pair a
                               # successor now owns (#5816).

        def _note_lost_lease():
            nonlocal lost_lease
            lost_lease = True
        try:
            # FENCE (#5816): renew-and-verify we still own BOTH node leases
            # immediately before the first pair-mutating action. A one-shot
            # wall-clock lease with no renewal can expire mid-roll (a positive
            # TTL shorter than boot/drain latency); if a successor then reclaims
            # it, draining here would put both drivers on the same pair. Renewing
            # extends the deadline to a fresh TTL; a confirmed LOSS aborts before
            # any mutation (state is untouched, so the finally releases the
            # leases rather than TTL-holding them).
            _fence_before_mutate(runner, backend, [(node, nid), (peer, nid)],
                                 holder, lease_ttl, f"drain {node}",
                                 on_lost=_note_lost_lease)
            # 2. DRAIN node -> peer via the non-interactive in-guest verb, which
            #    CONFIRMS the strong drain predicate (peer holds RGs, sync clean)
            #    before returning — so we never arm an undrained primary (r1
            #    Codex Critical). It also pre-checks peer-takeover-ready + HA
            #    protocol compat and refuses otherwise.
            print(f"   draining {node} -> {peer} (confirmed)...")
            _node_exec(runner, backend, node,
                       ["xpfd", "upgrade", "kernel", "drain"])  # check=True: abort on fail
            drained = True
            # 3. clear any STALE promotion marker so a prior roll to the SAME
            #    version can't false-satisfy this roll's poll (r1 Codex High);
            #    `arm` clears it in-guest too, belt-and-braces here for clarity.
            # 4. arm+install+reboot into the candidate (in-guest verb). `arm`
            #    reboots on success and the exec transport drops — expected, so
            #    check=False. BUT a FAILED arm (UEFI/NVRAM preflight, package
            #    install) also returns nonzero WITHOUT rebooting, which would
            #    leave the node drained-but-running (r1 Codex High). We cannot
            #    distinguish the two by exit code, so the poll below detects a
            #    no-reboot (uname never changes off known-good while armed=none),
            #    and the finally REJOINS a drained node that never rebooted.
            # Record the pre-arm boot_id (#4905-A): a CHANGED boot_id after the
            # arm is the AFFIRMATIVE proof the node actually rebooted. Reading
            # it here — after a confirmed drain, before arm — is on a healthy,
            # reachable node, so it normally succeeds; if it can't be read we
            # fall back to the running==candidate signal (a promote still sets
            # rebooted, and an unconfirmed reboot conservatively rejoins).
            pre_boot_id = _boot_id(runner, backend, node)
            # FENCE (#5816): arm REBOOTS the node — the highest-consequence
            # mutation. Re-verify ownership of both leases (and refresh the
            # deadline) on the still-reachable node before we commit to the
            # reboot. After this the node is down and its lease can't be renewed
            # until it is back; the peer lease keeps the reservation held.
            _fence_before_mutate(runner, backend, [(node, nid), (peer, nid)],
                                 holder, lease_ttl, f"arm+reboot {node}",
                                 on_lost=_note_lost_lease)
            print(f"   arming candidate {version} on {node} (will reboot)...")
            _node_exec(runner, backend, node,
                       ["xpfd", "upgrade", "kernel", "arm", version], check=False)
            if runner.dry:
                print(f"   (dry-run) would poll {node} for promoted={version}, "
                      f"then `xpfd upgrade kernel rejoin`")
                completed = True
                return True
            # 5. poll until back + promoted==version (or STOP on revert/timeout)
            deadline = _time.time() + poll_deadline
            promoted = False
            running = ""   # last observed kernel ("" = never reachable)
            while _time.time() < deadline:
                _time.sleep(10)
                # RENEWAL (#5816): keep the reservation alive across the reboot
                # wait so a legitimately-slow roll never loses it. The rolled
                # node is unreachable while it reboots — its lease can't be
                # renewed yet and that is NOT a loss — but the still-up peer's
                # lease IS renewed every tick, which is the load-bearing
                # reservation (a successor can never acquire BOTH leases while we
                # hold the peer's). A provably LOST lease (reclaimed by a peer
                # roll) is a split-brain signal: stop before rejoin.
                lost = _keepalive_leases(runner, backend,
                                         [(node, nid), (peer, nid)],
                                         holder, lease_ttl)
                if lost:
                    lost_lease = True   # suppress the finally restore-rejoin: a
                                        # reclaimed pair must not be un-drained
                    die(f"{lost}: LOST the roll lease mid-reboot-poll — another "
                        f"orchestrator reclaimed the pair reservation. Stopping "
                        f"the roll of {node}; investigate the half-rolled "
                        f"cluster (a successor may be mutating this pair).")
                st = _kernel_status(runner, backend, node)
                ok, running = _running_kernel_result(runner, backend, node)
                if not ok:
                    # TRANSPORT failure (SSH/incus drop, control-socket
                    # contention) — NOT a reboot. The old code set rebooted=True
                    # on ANY empty read, so one status blip masqueraded as a
                    # completed revert and the finally skipped rejoin, stranding
                    # the node drained + ForceSecondary (#4905-A). Do NOT touch
                    # `rebooted`; just retry.
                    continue
                # Node is reachable. Confirm a reboot ONLY from an affirmative
                # signal: a changed boot_id, or the candidate kernel running.
                cur_boot_id = _boot_id(runner, backend, node)
                if _reboot_confirmed(pre_boot_id, cur_boot_id, running, version):
                    rebooted = True
                if st.get("promoted") == version and running == version:
                    promoted = True
                    break
                # REVERT detection requires an AFFIRMATIVE status read (Copilot):
                # a transient status-command failure yields an EMPTY dict whose
                # `armed` is absent — do NOT treat that as armed=none (it would
                # falsely `die` a revert). Only declare revert when status was
                # actually read (`armed` key present) and explicitly == "none"
                # while running a non-candidate kernel.
                #
                # AND it requires rebooted==True (r2 Codex): a genuine revert
                # means the node REBOOTED to known-good (the reboot cleared the
                # in-memory ForceSecondary drain, so no rejoin is needed). But an
                # `arm` that FAILED its preflight BEFORE rebooting shows the SAME
                # signature (running==known-good, armed=none) while still drained
                # — it must NOT be classified as a revert, or `completed=True`
                # would suppress the finally-rejoin and strand the node drained.
                # With the #4905-A fix, `rebooted` is now set ONLY by a confirmed
                # boot_id change, so a transient blip can no longer forge it.
                if (rebooted and running != version and "armed" in st
                        and st.get("armed") == "none"):
                    # node REBOOTED to a NON-candidate kernel and nothing is armed
                    # -> it REVERTED. drain state is gone via the reboot, the node
                    # self-recovers on its known-good boot — no rejoin needed.
                    # STOP: leave peer primary, do NOT roll peer.
                    completed = True   # drain state gone via the revert reboot
                    die(f"{node} REVERTED (running {running}, not {version}); "
                        f"stopping the roll — {peer} stays primary, {node} is on "
                        f"its known-good kernel. Investigate before retrying.")
                # NOT rebooted + armed=none + running==known-good post-drain ->
                # `arm` failed its preflight without rebooting. Stop polling now;
                # `completed` stays False + `rebooted` stays False, so the finally
                # rejoins the still-drained node and the timeout `die` below
                # reports the arm failure.
                if (not rebooted and "armed" in st
                        and st.get("armed") == "none" and running != version):
                    break
            if not promoted:
                # If the node rebooted (revert/hang) the drain is already gone and
                # the finally must NOT rejoin a possibly-candidate node; if it
                # NEVER rebooted (arm failed pre-reboot) the finally rejoins the
                # still-drained node. `rebooted` distinguishes the two.
                completed = rebooted
                die(f"{node} did not promote {version} within {poll_deadline}s "
                    f"(running={running}, rebooted={rebooted}); stopping — "
                    f"{peer} stays primary"
                    + ("" if rebooted else f"; rejoining {node} (it never rebooted)"))
            print(f"   {node} promoted {version}")
            # 6. REJOIN + CONFIRM sync re-established BEFORE we touch the peer
            #    (the "never both down" gate — r1 Codex Critical). `rejoin`
            #    clears manual failover on ALL RGs and confirms peer-alive +
            #    sync; a failure here STOPS the roll (the peer stays primary).
            # FENCE (#5816): the node is back up and its lease survived the
            # reboot (persistent /var/lib) — re-verify ownership of both leases
            # (and refresh the deadline) before rejoin re-enables its forwarding.
            # If a successor reclaimed while we were rebooting, abort rather than
            # rejoin a pair the peer now owns.
            _fence_before_mutate(runner, backend, [(node, nid), (peer, nid)],
                                 holder, lease_ttl, f"rejoin {node}",
                                 on_lost=_note_lost_lease)
            print(f"   rejoining {node} (confirming sync)...")
            _node_exec(runner, backend, node,
                       ["xpfd", "upgrade", "kernel", "rejoin"])  # check=True: abort on fail
            completed = True
            return True
        finally:
            # 7a. If we drained the node but the roll did not complete AND the
            #     node never rebooted, the node is stuck ForceSecondary-drained
            #     (e.g. `arm` failed its preflight before rebooting). REJOIN it
            #     best-effort so it resumes forwarding — otherwise it sits drained
            #     with no lease and a later retry could drain the peer while this
            #     node is down, opening a no-primary window (r1 Codex High).
            #     (A node that rebooted has already lost the in-memory drain.)
            #     BUT skip this rejoin when we LOST (or could not confirm) the
            #     lease: die() is a SystemExit, so a fence-abort at arm/rejoin — or
            #     a keepalive-detected loss — still reaches this finally, and
            #     rejoining here would UN-DRAIN a pair a successor now owns,
            #     violating the fence's own invariant (a lost orchestrator must not
            #     mutate the pair, #5816). A clean abort where we still hold the
            #     lease (`lost_lease` stays False) keeps rejoining as before.
            if (drained and not completed and not rebooted
                    and not lost_lease and not runner.dry):
                print(f"   roll did not complete and {node} never rebooted; "
                      f"rejoining {node} to restore forwarding...")
                try:
                    _node_exec(runner, backend, node,
                               ["xpfd", "upgrade", "kernel", "rejoin"], check=False)
                except Exception as e:  # best-effort: never mask the original error
                    print(f"   WARNING: best-effort rejoin of {node} failed: {e}")
            # 7b. release this node's lease on both nodes (best-effort)
            _clear_lease(runner, backend, node, holder)
            _clear_lease(runner, backend, peer, holder)

    roll_one(nodes[0], nodes[1])
    print(f"\n==> {nodes[0]} done; rolling the second node")
    roll_one(nodes[1], nodes[0])
    print(f"\n==> LANE-1 HA kernel roll to {version} COMPLETE on both nodes")
    return 0


# ── LANE-2 image-replace rolling driver (#1930 INC-3) ──────────────────────
#
# Recreate each HA node from a NEW baked image, one at a time, so the peer keeps
# forwarding. Built on the existing per-node recreate (`launch` + day-0 re-apply
# of xpf.conf+node-id) — there is NO in-place base-OS swap. Before swapping the
# SECOND node it runs the MIXED-BASE GATE: if the new image's HA/session-sync
# protocol is NOT back-compatible with the still-running first node, it STOPS and
# tells the operator to use the both-nodes-at-once path (sessions drop). Reuses
# the INC-2 drain/rejoin verbs for the never-both-down handoff.

def _node_protocol_versions(runner, backend, node):
    """Read `xpfd protocol-versions` from a RUNNING node into a dict."""
    out = _node_exec(runner, backend, node,
                     ["xpfd", "protocol-versions"], check=False)
    d = {}
    for line in out.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            d[k.strip()] = v.strip()
    return d


def _node_cluster_node_id(runner, backend, node):
    """Read the recreated node's cluster-identity marker /etc/xpf/node-id — the
    SAME file xpfd keys HA identity on (pkg/daemon/daemon.go `nodeIDFile`),
    written by the day-0 config drive during the recreate. Returns the int
    node-id, or None if absent/unreadable/unparsable so the #5075 identity gate
    fails CLOSED. Used to confirm an image-recreated node came back as the
    EXPECTED node, not a wrong-id relaunch (e.g. a --recreate-hook that swapped
    node-id 0 and 1)."""
    out = _node_exec(runner, backend, node,
                     ["cat", "/etc/xpf/node-id"], check=False)
    s = (out or "").strip()
    try:
        return int(s)
    except (TypeError, ValueError):
        return None


def _node_is_primary_for_any_rg(runner, backend, node, node_id):
    """Does `node` currently hold PRIMARY for any redundancy group? (#6759)

    Parses `show chassis cluster status` with the SAME contract the rest of the
    tooling uses: inside a `Redundancy group: N ` block, a node row's FIRST
    field is the node token and the state is a field on that row
    (test/incus/deploy-lib.sh, scripts/userspace-ha-validation.sh). Matching on
    exact FIELDS rather than a substring is deliberate — #4009 was a
    rolling-deploy bug caused by a non-node line being read as a node row, and
    it steered a deploy into restarting the PRIMARY first.

    Returns None when the state cannot be read (xpfd not answering yet, cluster
    not configured, transport blip). None is NOT "not primary": the caller must
    not turn an unreadable state into a pass — it simply has no observation
    this tick and tries again on the next one.
    """
    if node_id is None:
        return None
    out = _node_exec(runner, backend, node,
                     ["cli", "-c", "show chassis cluster status"], check=False)
    if not out or "Redundancy group" not in out:
        return None
    want = f"node{node_id}"
    in_rg = False
    for line in out.splitlines():
        stripped = line.strip()
        if stripped.startswith("Redundancy group"):
            in_rg = True
            continue
        if not in_rg:
            continue
        fields = stripped.split()
        if len(fields) >= 2 and fields[0] == want and "primary" in fields:
            return True
    return False


# ── #7559: the image-roll election window, closed by not starting the elector ──
#
# The recreate DESTROYS the node's disk, so no on-node artifact can carry a
# "hold" across it — that is what #7559 records, and it is why the kernel-roll's
# journal-keyed `holdSecondaryIfKernelCandidateArmed` cannot be reused here (it
# folds a clean ENOENT to "never armed", which is exactly what a wiped disk
# produces).
#
# But the window does not need a signal that survives the wipe. The election is
# run by a DAEMON whose start this driver already controls: the recreated node
# elects inside its own bringup (`daemon_run_bringup.go` calls
# `cluster.UpdateConfig`, which elects on the single-node path). If xpfd never
# starts until the #5075 identity gate has passed, there is no election to hold
# and nothing has to survive anything.
#
# What makes it work is that the gate is evaluable with the daemon DOWN:
# `xpfd protocol-versions` is a pure binary invocation (cmd/xpfd/main.go
# `cmdProtocolVersions` prints compile-time constants and returns before any
# daemon/config/state path is touched), and `/etc/xpf/node-id` is read with
# `cat`. So the driver can prove "the expected node on the expected build"
# BEFORE the node is able to claim a redundancy group — and, unlike every
# design that puts a hold inside xpfd, this works no matter WHICH image the
# hook actually launched, including one that predates the mechanism. That is
# the case #5075 was filed for.
#
# Holding the daemon is an act of the operator-supplied `--recreate-hook`: only
# it can inject state before the guest's first boot. Every hook written before
# this change leaves xpfd auto-starting, so an unheld daemon is REPORTED rather
# than fatal (the #6759 unverified-primary detector still fails closed if the
# node actually went primary). `--require-daemon-hold` turns the report into a
# refusal for operators who want the guarantee enforced.

# xpfd is RUNNING (or on its way to, or on its way down from, running) — in all
# of these the node either can elect or already has. Fail toward "unprotected".
_DAEMON_RUNNING_STATES = ("active", "activating", "reloading", "deactivating")
# The unit was deliberately kept from starting. `systemctl mask` reports
# LoadState=masked; a hook that merely disables the unit reports
# UnitFileState=disabled. Both are holds.
_DAEMON_HELD_UNIT_FILE_STATES = ("masked", "masked-runtime", "disabled")

# Bound on how long the driver waits for a released xpfd to be READY. Separate
# from --boot-deadline (which bounds the node coming BACK at all): by this point
# the node is proven to be the expected build, and all that remains is a cold
# daemon start. Generous on purpose — "ready" here means the gRPC surface is
# answering, which is AFTER config compile+commit, interface rename, the
# networkd apply, the AF_XDP dataplane load and the FRR reload.
_DAEMON_START_DEADLINE = 180
_DAEMON_START_POLL = 5


def _daemon_hold_supported(backend, require_hold):
    """May this roll ask the recreate hook to hold xpfd? (#7559)

    The hold makes the node inert, and on the sealed appliance image that
    includes its MANAGEMENT ADDRESS: `scripts/image/bake.py` purges cloud-init
    and deletes every netplan / interfaces.d file, so the only thing that ever
    addresses fxp0 is xpfd's own bootstrap lifeline. Hold the daemon on that
    image and the node has no IP — which is harmless for a transport that does
    not need one and FATAL for a transport that does:

      - incus: `incus exec` reaches the guest through the incus-agent
        (baked at scripts/image/bake.py, a vsock transport), so the driver can
        still run the identity gate and later release the hold. Supported.
      - ssh:   the driver reaches the node by IP. A held xpfd means no IP, so
        the boot poll would never see the node at all, time out, and leave it
        masked, addressless and console-only — turning a transient integrity
        exposure into a persistent outage. NOT supported by default.

    `--require-daemon-hold` overrides: an operator whose platform supplies the
    management address independently of xpfd (a hypervisor-managed NIC, a
    day-0-written mgmt .network) is asserting that the transport survives the
    hold, and is the only one who can know that.
    """
    return bool(require_hold) or backend == "incus"


def _daemon_cli_ready(status_out):
    """Is the daemon's gRPC surface actually answering? (#7559)

    `systemctl enable --now xpfd` returns as soon as the process forks
    (`Type=simple`), and ActiveState=active means only that. The step that
    follows is `xpfd upgrade kernel rejoin`, whose `RejoinAndConfirm` calls
    `ResetFailover()` OUTSIDE its retry loop (pkg/upgrade/kernel_drain.go) over
    gRPC with a 5s dial timeout — so a single un-retried dial against a daemon
    that is still loading the dataplane fails the whole roll. Readiness must
    therefore be observed on the gRPC path, not from systemd.

    `show chassis cluster status` is the probe because it is exactly that path
    AND requires the cluster manager to be populated; the roll always runs
    against a two-node cluster, so a node that answers with a redundancy-group
    block is past every startup phase the rejoin depends on.
    """
    return bool(status_out) and "Redundancy group" in status_out


def _daemon_hold_state(show_out):
    """Classify `systemctl show xpfd -p LoadState -p UnitFileState -p ActiveState`
    output. Returns one of:

      "running" — xpfd is up (or starting/stopping): the node CAN elect.
      "held"    — the unit is masked or disabled AND not running: the recreate
                  hook honoured the #7559 daemon hold.
      "pending" — the unit is enabled but not (yet) running: the guest is still
                  booting, or xpfd crashed. NOT a hold.
      "unknown" — nothing parseable came back (transport blip, no systemd,
                  dry-run). NOT a hold.

    Pure so the three-way decision is testable without a node, and ordered
    running-first on purpose: a unit that is masked in the unit file but somehow
    RUNNING is running, and reading it as "held" would report protection that
    does not exist.

    `systemctl is-active` alone cannot do this job — it exits non-zero for every
    inactive state, and it cannot tell a masked unit from a node that is merely
    still booting.
    """
    props = {}
    for line in (show_out or "").splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            props[k.strip()] = v.strip()
    active = props.get("ActiveState", "")
    load = props.get("LoadState", "")
    unit_file = props.get("UnitFileState", "")
    if not active and not load and not unit_file:
        return "unknown"
    if active in _DAEMON_RUNNING_STATES:
        return "running"
    if load == "masked" or unit_file in _DAEMON_HELD_UNIT_FILE_STATES:
        return "held"
    if active:
        return "pending"
    return "unknown"


def _node_daemon_hold_state(runner, backend, node):
    """Read the #7559 daemon-hold state of xpfd on `node` in ONE round trip.

    Uses the structured exec result and decides from the OUTPUT, never from the
    exit status: `systemctl show` on a node whose transport is still coming up
    returns nothing, and that is "unknown" — an unreadable state must never be
    read as protection."""
    res = _node_exec_result(runner, backend, node,
                            ["systemctl", "show", "xpfd",
                             "-p", "LoadState",
                             "-p", "UnitFileState",
                             "-p", "ActiveState"])
    return _daemon_hold_state(res.out)


def _release_daemon_hold(runner, backend, node):
    """Start xpfd on a node whose recreate hook held it (#7559).

    Unmask-first and idempotent: the hook holds the daemon by masking the unit
    before the guest's first boot (an `/etc/systemd/system/xpfd.service` ->
    /dev/null symlink), so `enable --now` alone would fail on a masked unit; a
    hook that only disabled the unit is covered by the same two calls. Both legs
    are check=False because the WAIT that follows is the real gate — it reports
    the daemon's actual state rather than a systemctl exit code."""
    _node_exec(runner, backend, node, ["systemctl", "unmask", "xpfd"],
               check=False)
    _node_exec(runner, backend, node, ["systemctl", "enable", "--now", "xpfd"],
               check=False)


def _wait_daemon_ready(runner, backend, node, deadline_secs=None, poll=None):
    """Wait (bounded) for a just-released xpfd to be READY, and report what was
    actually observed: "ready", or the last daemon-hold state seen.

    Never rejoin a daemon that has not answered: `xpfd upgrade kernel rejoin`
    dials gRPC once, un-retried, and without this wait a released-but-still-
    starting xpfd surfaces as an opaque "command failed" from the rejoin rather
    than naming what went wrong. Both conditions are required — the unit must be
    RUNNING and the gRPC surface must ANSWER — because each alone is a false
    ready: a masked unit that never started reports neither, and a Type=simple
    unit reports active the instant it forks."""
    if deadline_secs is None:
        deadline_secs = _DAEMON_START_DEADLINE
    if poll is None:
        poll = _DAEMON_START_POLL
    import time as _time
    deadline = _time.time() + deadline_secs
    state = "unknown"
    while True:
        state = _node_daemon_hold_state(runner, backend, node)
        if state == "running":
            out = _node_exec(runner, backend, node,
                             ["cli", "-c", "show chassis cluster status"],
                             check=False)
            if _daemon_cli_ready(out):
                return "ready"
        if _time.time() >= deadline:
            return state
        _time.sleep(poll)


def _recreated_node_matches(live_versions, want_version, live_node_id, want_node_id):
    """#5075 identity+version gate for a node recreated from the new image.
    Returns (ok: bool, reason: str).

    The post-recreate readiness poll must accept a responding xpfd ONLY when it
    is BOTH the EXPECTED build (its live `xpf-version` equals the AUTHENTICATED
    image manifest's xpf-version) AND the EXPECTED cluster node (its
    /etc/xpf/node-id equals the node-id the deploy assigned). Before #5075 the
    poll accepted ANY xpfd that merely answered with a non-empty xpf-version, so
    a --recreate-hook that relaunched the OLD image, a stale alias, or the WRONG
    node-id satisfied the poll and the roll proceeded to the peer with the pair
    on unintended/mixed software — a silent deploy-integrity failure. This gate
    fails CLOSED on every mismatch.

    - live_versions: dict from `xpfd protocol-versions` on the recreated node.
    - want_version:  xpf-version from the AUTHENTICATED image manifest.
    - live_node_id:  int|None parsed from /etc/xpf/node-id on the node.
    - want_node_id:  the cluster node-id the deploy assigned this node.

    A still-booting node (empty xpf-version) returns (False, ...) too, so the
    caller can simply keep polling until the gate passes or the boot deadline
    elapses, then fail closed with the last reason."""
    live_ver = (live_versions or {}).get("xpf-version", "")
    if not live_ver:
        return False, "xpfd is not answering protocol-versions yet (no xpf-version)"
    if not want_version:
        return (False, "the authenticated image manifest carries no xpf-version — "
                "cannot confirm the node rolled to the expected build (#5075)")
    if live_ver != want_version:
        return (False, f"node is running xpf-version {live_ver!r}, but the "
                f"authenticated manifest expects {want_version!r} — the recreate "
                f"did NOT roll to the requested image (old image / stale alias / "
                f"wrong build)")
    if live_node_id is None:
        return (False, "cannot read /etc/xpf/node-id on the recreated node — "
                f"cannot confirm it is cluster node-id {want_node_id} (#5075)")
    if live_node_id != want_node_id:
        return (False, f"node reports cluster node-id {live_node_id}, not the "
                f"expected {want_node_id} — the recreate launched the WRONG node "
                f"identity (#5075)")
    return (True, f"xpf-version {live_ver} and cluster node-id {live_node_id} "
            f"match the expected new image")


def _node_drain_supports_mixed_ha(runner, backend, node):
    """Feature-detect whether a node's RUNNING xpfd accepts the INC-3
    `--allow-mixed-ha` drain flag. An image rolled FROM a pre-INC-3 release has
    no such flag and would abort on it (AGY CRITICAL); the second image-roll
    drain runs on the still-OLD node, so this MUST be probed before the flag is
    passed. `drain --help` lists flags (on STDERR — Go's flag package writes
    usage there) WITHOUT performing a drain; absence of the token (or any probe
    failure) is treated as unsupported (fail safe: omit the flag, fall back to
    the exact-equality precheck). stderr is merged via `sh -c` so the backend
    captures the usage text (_node_exec returns stdout only). Match the bare
    `allow-mixed-ha` token: Go's flag usage prints it single-dash
    (`-allow-mixed-ha`) even though the flag accepts `--allow-mixed-ha`."""
    if runner.dry:
        return True  # dry-run prints the planned command; assume new image
    out = _node_exec(runner, backend, node,
                     ["sh", "-c",
                      "xpfd upgrade kernel drain --help 2>&1 || true"],
                     check=False)
    return "allow-mixed-ha" in out


def _parse_image_manifest_versions(text):
    """Parse bake `.manifest` TEXT (key: value) into the same key namespace as
    `xpfd protocol-versions` (key=value, hyphenated). Split out from
    `_read_image_manifest_versions` so the #5042 gate can parse the VERIFIED
    bytes of the sidecar (returned by sign.verify_listed_artifact_bytes) rather
    than re-opening the on-disk path after the signature check (TOCTOU)."""
    d = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        k, v = line.split(":", 1)
        d[k.strip().replace("_", "-")] = v.strip()
    return d


def _read_image_manifest_versions(path):
    """Parse the bake `.manifest` FILE (key: value) into the gate key namespace.

    NOTE (#5042): this raw file read is authenticated ONLY when the caller has
    already verified `path` against the signed xpf-<ver>.SHA256SUMS. The
    mixed-base gate in cmd_image_roll now reads VERIFIED bytes via
    `_verified_image_manifest_versions`; do not feed an unverified path
    straight into the session-safety decision."""
    with open(path) as f:
        return _parse_image_manifest_versions(f.read())


def _verified_image_manifest_versions(manifest_path, sums_path, sig_path, pubkey_path=None):
    """#5042: verify the protocol sidecar `manifest_path` against the SIGNED
    checksum manifest (`sums_path` + its `.minisig`) and parse the VERIFIED
    bytes. The mixed-base HA session-safety gate decides whether synchronized
    sessions survive an image roll; before #5042 it read the sidecar RAW, so
    tampering only that unsigned file could spoof a compatible-window /
    matching-session-sync decision and bypass the safety stop while every
    signed image byte was untouched. Reading the bytes verify_listed_artifact_bytes
    returns (hash-checked against the signed manifest, from a private copy)
    closes that trust gap. Fails closed on any missing/mismatched/unsigned input."""
    HERE_D = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, os.path.join(os.path.dirname(HERE_D), "dist"))
    import sign  # noqa: E402
    data = sign.verify_listed_artifact_bytes(manifest_path, sums_path, sig_path, pubkey_path)
    return _parse_image_manifest_versions(data.decode("utf-8", "replace"))


def _default_sums_for_manifest(manifest_path):
    """#5042: convention default for the SIGNED checksum manifest that covers a
    protocol sidecar — the xpf-<ver>.SHA256SUMS sibling of the
    xpf-<ver>.manifest (both land in the same fetch/bake directory). Returns
    None if the manifest name does not fit the `*.manifest` shape, in which
    case the operator must pass --sha256sums explicitly (fail closed)."""
    if manifest_path.endswith(".manifest"):
        return manifest_path[: -len(".manifest")] + ".SHA256SUMS"
    return None


def _u16(s):
    """Parse a uint16 (matches the Go strconv.ParseUint(.,10,16) gate semantics —
    MEDIUM Codex: Python int() would accept -1 / 70000). Returns None on failure
    so the caller fails closed, exactly as the Go gate's `present` map does."""
    try:
        n = int(s)
    except (TypeError, ValueError):
        return None
    if n < 0 or n > 0xFFFF:
        return None
    return n


def _gate_mixed_base(new_img, peer):
    """EXACT Python mirror of upgrade.GateMixedBaseSwap (unit-tested in Go).
    Returns (sessions_survive: bool, reason: str). Fail-closed on any missing or
    out-of-range field, an unknown peer HA, an out-of-window peer, or an unknown
    / mismatched peer session-sync."""
    required = ["ha-protocol-version", "ha-protocol-min-compat",
                "session-sync-protocol-version"]
    for k in required:
        if k not in new_img:
            return False, f"new image manifest missing {k!r} — fail closed (replace both, sessions drop)"
    img_ha = _u16(new_img["ha-protocol-version"])
    img_floor = _u16(new_img["ha-protocol-min-compat"])
    img_sync = _u16(new_img["session-sync-protocol-version"])
    if img_ha is None or img_floor is None or img_sync is None:
        return False, "unparsable/out-of-range new image versions — fail closed"
    peer_ha = _u16(peer.get("ha-protocol-version", "0"))
    peer_sync = _u16(peer.get("session-sync-protocol-version", "0"))
    if peer_ha is None or peer_sync is None:
        return False, "unparsable/out-of-range peer versions — fail closed"
    if peer_ha == 0:
        return False, "peer HA protocol unknown — fail closed"
    if peer_ha < img_floor or peer_ha > img_ha:
        return (False, f"peer HA protocol {peer_ha} outside new image window "
                f"[{img_floor},{img_ha}] — replace BOTH nodes (sessions drop)")
    # An UNKNOWN peer session-sync (0) fails closed — same as the Go gate
    # (r3 Codex HIGH: 0 must NOT be skipped as compatible).
    if peer_sync == 0:
        return False, ("peer session-sync protocol unknown — fail closed "
                       "(replace both nodes, sessions drop)")
    if peer_sync != img_sync:
        return (False, f"session-sync protocol differs (peer {peer_sync}, new image "
                f"{img_sync}) — replace BOTH nodes (sessions drop)")
    return (True, f"new image HA {img_ha} (floor {img_floor}) accepts peer {peer_ha}; "
            f"session-sync {img_sync} matches — mixed-base swap preserves sessions")


def cmd_image_roll(args):
    import time as _time
    import re as _re
    runner = Runner(args.dry_run)
    backend = args.backend
    nodes = args.nodes
    if len(nodes) != 2:
        die("image-roll needs exactly two --node arguments (the HA pair)")
    if nodes[0] == nodes[1]:
        die(f"image-roll needs two DISTINCT nodes; got {nodes[0]} twice")
    node_ids = {nodes[0]: args.node0_id, nodes[1]: args.node1_id}

    # Validate the recreate hook BEFORE any drain (MEDIUM Codex: detecting a
    # missing hook only after node[0] is drained would strand it demoted). The
    # hook is required for the real run; dry-run only prints the plan.
    if not args.dry_run and not args.recreate_hook:
        die("image-roll needs --recreate-hook <script> (the backend-specific "
            "destroy+launch+day-0 recreate step); refusing to drain without it.")

    # The new image's protocol versions come from its manifest. #5042: the
    # sidecar is covered by the SIGNED xpf-<ver>.SHA256SUMS, so verify it
    # against that signed manifest (+ .minisig) and parse the VERIFIED bytes —
    # the mixed-base session-safety gate must decide from signed bytes, never
    # a raw sidecar an attacker could tamper. Fail closed on any
    # missing/mismatched/unsigned input.
    if not args.manifest or not os.path.isfile(args.manifest):
        die("image-roll requires --manifest <xpf-<ver>.manifest> (the new image's "
            "version manifest) for the mixed-base gate; not found")
    sums_path = args.sha256sums or _default_sums_for_manifest(args.manifest)
    if not sums_path or not os.path.isfile(sums_path):
        die("image-roll requires the SIGNED checksum manifest "
            "(xpf-<ver>.SHA256SUMS covering the .manifest) so the mixed-base "
            "session-safety gate reads AUTHENTICATED bytes (#5042). Pass "
            "--sha256sums <path> (default: the .SHA256SUMS sibling of "
            f"--manifest); not found: {sums_path!r}")
    sig_path = args.sig or (sums_path + ".minisig")
    if not os.path.isfile(sig_path):
        die(f"image-roll requires the signature {os.path.basename(sig_path)} "
            "(minisign over the SHA256SUMS) to authenticate the mixed-base gate "
            "input (#5042); not found. Pass --sig <path>.")
    try:
        new_img = _verified_image_manifest_versions(
            args.manifest, sums_path, sig_path, args.pubkey)
    except Exception as e:
        die(f"image-roll: FAILED to verify {os.path.basename(args.manifest)} "
            f"against the signed {os.path.basename(sums_path)} — the mixed-base "
            f"gate must read signed bytes (#5042): {e}")

    # #9325: the same signed sidecar says whether the image passed the in-guest
    # verify-dataplane gate. A --skip-validate bake signs `validated: false`, and
    # this roll is about to replace both nodes' forwarding path with it.
    v_state, v_reason = _validation_verdict(new_img)
    if v_state == "absent":
        print(f"==> WARNING: {v_reason}")
    elif v_state != "true":
        if not getattr(args, "allow_unvalidated", False):
            die(f"image-roll: refusing to roll {os.path.basename(args.manifest)}: "
                f"{v_reason}. Pass --allow-unvalidated to roll an unvalidated "
                f"image anyway.")
        print(f"==> WARNING: image-roll proceeding with --allow-unvalidated: {v_reason}")

    holder = _re.sub(r"[^A-Za-z0-9._:-]", "_",
                     f"{os.uname().nodename}:pid{os.getpid()}")
    lease_ttl = args.lease_ttl
    drain_deadline = args.drain_deadline
    boot_deadline = args.boot_deadline

    print(f"==> LANE-2 HA image roll: {nodes[0]} then {nodes[1]} "
          f"(recreate each from {os.path.basename(args.manifest)}; peer keeps forwarding)")

    # #7559: may this roll ask the hook to hold xpfd, and can the driver then
    # still reach the node? Decided ONCE, from the backend, before anything is
    # mutated — see _daemon_hold_supported.
    hold_supported = _daemon_hold_supported(backend, args.require_daemon_hold)
    if hold_supported:
        print(f"   #7559 daemon hold: REQUESTED of the recreate hook "
              f"({'enforced' if args.require_daemon_hold else 'reported only'})")
    else:
        print(f"   #7559 daemon hold: not requested on the {backend} backend "
              f"(the driver reaches the node by IP, and a held xpfd leaves the "
              f"appliance image with no management address). Pass "
              f"--require-daemon-hold if this platform addresses the node "
              f"independently of xpfd.")

    def roll_one(node, peer, is_second):
        nid = node_ids[node]
        print(f"\n--- rolling {node} (node-id {nid}); {peer} stays primary ---")
        # Cross-orchestrator mutex (HIGH Codex): acquire the SAME kernel-roll
        # lease on BOTH nodes in canonical (sorted) order before draining, so two
        # operators rolling in opposite order can't both drain concurrently
        # (no-primary window). Release-what-we-got + abort on partial acquisition.
        ordered = sorted([node, peer])
        got = []
        for n in ordered:
            if _acquire_lease(runner, backend, n, nid, holder, lease_ttl):
                got.append(n)
            else:
                for g in got:
                    _clear_lease(runner, backend, g, holder)
                die(f"{n}: could not acquire image-roll lease (another orchestrator "
                    f"holds it, or the lock timed out) — released {got or 'nothing'} "
                    f"and aborting.")
        completed = False
        # state_changed flips True at the FIRST mutation (the drain). Until then
        # (lease acquisition + the pre-drain mixed-base gate) nothing on the
        # cluster has moved, so a failure there must RELEASE the leases, not
        # TTL-hold them — otherwise the gate's own suggested remediation (rerun
        # with --allow-session-drop) fails immediately on the caller's stale
        # lease for the full TTL (Codex). TTL-hold is only for a genuine
        # half-rolled cluster (state_changed and not completed).
        state_changed = False
        try:
            # MIXED-BASE GATE: the risk window is the FIRST swap (after it node[0]
            # is NEW while node[1] is still OLD). Gate BEFORE the first swap,
            # reading the still-OLD peer's live protocol. The second swap is into
            # the same already-validated pair, so it is not re-gated.
            allow_mixed = is_second  # second drain runs against the rolled (NEW) peer
            if not is_second:
                peer_v = _node_protocol_versions(runner, backend, peer)
                survive, reason = _gate_mixed_base(new_img, peer_v)
                print(f"   mixed-base gate: {reason}")
                if not survive and not args.allow_session_drop:
                    die(f"mixed-base gate FAILED: {reason}\n"
                        f"   The new image is not session-compatible with the running "
                        f"peer {peer}. Re-image BOTH nodes together (accept the "
                        f"connection drop) or pass --allow-session-drop to proceed "
                        f"node-by-node anyway (sessions WILL drop at the failover).")
                if not survive:
                    # The operator explicitly accepted the drop. The gate may
                    # have failed because the peer's HA protocol is OUT of the
                    # new image's compat WINDOW (not merely a session-sync
                    # mismatch), so relaxing the drain's exact-equality HA check
                    # here can drain into a genuinely mixed-PROTOCOL cluster
                    # (Copilot). That is the documented consequence of
                    # --allow-session-drop: sessions drop AND the cluster runs
                    # split-protocol until the second node is rolled; the
                    # peer-alive / takeover-ready prechecks still guarantee the
                    # peer can serve NEW traffic. Name it loudly. NOTE (Codex):
                    # this relaxes only the exact-equality HA-PROTOCOL precheck;
                    # the drain's transfer-readiness gate still enforces HA
                    # compatibility, so a genuinely HA-skewed peer (Transfer
                    # ready: no) is still refused — not a blanket skew bypass.
                    # Dormant today since HA/session-sync versions are exact.
                    print(f"   --allow-session-drop set: proceeding — sessions "
                          f"WILL drop, AND the drain's HA-protocol-equality "
                          f"precheck is bypassed (the cluster may run "
                          f"split-protocol until {peer} is rolled).")
                    allow_mixed = True  # gate waived -> also relax the drain HA check

            # 1. drain node -> peer (confirmed; never recreate an undrained
            #    primary). --allow-mixed-ha relaxes the drain's exact-equality HA
            #    precheck when the gate already validated window-compat (HIGH
            #    Codex): the second node drains against an already-rolled peer.
            #    FORWARD-COMPAT (AGY CRITICAL): the SECOND node is still on the
            #    OLD image at drain time (recreate is step 2). An image rolled
            #    FROM a pre-INC-3 release has an xpfd that does NOT know
            #    --allow-mixed-ha and would abort on the unknown flag. Append it
            #    only if the node's running binary actually supports it; the old
            #    binary's exact-equality precheck is the safety net otherwise
            #    (and is correct whenever old/new advertise the same HA version,
            #    which is the only in-window case a same-version roll produces).
            drain_cmd = ["xpfd", "upgrade", "kernel", "drain",
                         "--drain-deadline", f"{drain_deadline}s"]
            if allow_mixed:
                if _node_drain_supports_mixed_ha(runner, backend, node):
                    drain_cmd.append("--allow-mixed-ha")
                else:
                    print(f"   note: {node}'s xpfd predates --allow-mixed-ha; "
                          f"draining with the exact-equality HA precheck (safe "
                          f"when old/new advertise the same HA version). If the "
                          f"drain aborts as HA-incompatible, the OLD image cannot "
                          f"relax it — re-image BOTH nodes together.")
            # FENCE (#5816): renew-and-verify we still own BOTH node leases
            # immediately before the first pair-mutating action. The one-shot
            # lease can expire mid-roll (a positive TTL shorter than drain/boot
            # latency or the recreate hook); if a successor reclaimed it,
            # draining here would put both drivers on the same pair. This runs
            # BEFORE state_changed flips, so a confirmed loss aborts while the
            # cluster is still untouched (the finally then releases the leases).
            _fence_before_mutate(runner, backend, [(node, nid), (peer, nid)],
                                 holder, lease_ttl, f"drain {node}")
            print(f"   draining {node} -> {peer} (confirmed)...")
            # First mutation: from here on a failure leaves a half-rolled
            # cluster, so leases must stay TTL-held (never-both-down).
            state_changed = True
            _node_exec(runner, backend, node, drain_cmd)

            # 2. recreate the node from the new image (launch + day-0 re-apply).
            if runner.dry:
                print(f"   (dry-run) would recreate {node} from the new image "
                      f"(launch + day-0), poll boot+verify, then rejoin")
                completed = True  # dry-run: release the leases on the way out
                return
            # FENCE (#5816): recreate DESTROYS+relaunches the node from a fresh
            # image — the single highest-consequence, un-interruptible mutation
            # and the one #5545 flagged as potentially outlasting a short TTL.
            # Renew-and-verify both leases (fresh full TTL) immediately before
            # it. The recreate wipes /var/lib on the node, so the node's own
            # lease is gone afterwards; from here the still-up PEER's lease is
            # the sole reservation (renewed every poll tick below), which is
            # what actually blocks a successor from acquiring both leases.
            _fence_before_mutate(runner, backend, [(node, nid), (peer, nid)],
                                 holder, lease_ttl, f"image-recreate {node}")
            # #6762: keep the PEER lease renewed for the whole duration of the
            # hook, not just up to its start. The peer lease is the sole
            # reservation once the recreate wipes this node's /var/lib.
            recreate_lost = _recreate_node_from_image(
                runner, backend, node, args,
                keepalive=lambda: _keepalive_leases(
                    runner, backend, [(peer, nid)], holder, lease_ttl),
                keepalive_interval=max(5, lease_ttl // 3),
                expect_version=new_img.get("xpf-version", ""),
                expect_node_id=node_ids[node],
                daemon_hold=hold_supported)
            if recreate_lost:
                die(f"{recreate_lost}: LOST the roll lease while the recreate hook "
                    f"for {node} was running — another orchestrator reclaimed the "
                    f"pair reservation. The hook was allowed to finish (interrupting "
                    f"a half-done recreate is worse), but STOPPING before rejoin; "
                    f"investigate the half-rolled cluster.")

            # 3. poll until the node is back AS THE EXPECTED NODE ON THE NEW
            #    IMAGE. #5075: accepting ANY responding xpfd (the pre-fix
            #    `if pv.get("xpf-version")` non-empty check) let a --recreate-hook
            #    that relaunched the OLD image / a stale alias / the WRONG node-id
            #    satisfy the poll — the driver rejoined and proceeded to the peer
            #    with the pair on unintended/mixed software (silent deploy-
            #    integrity failure). Require the live xpf-version to EXACTLY match
            #    the AUTHENTICATED manifest's xpf-version AND /etc/xpf/node-id to
            #    match the assigned cluster node-id before treating the node as
            #    "back". Keep polling until the gate passes or the boot deadline
            #    elapses (existing retry/timeout preserved), then FAIL CLOSED with
            #    the never-both-down leases HELD — a mismatch is not a successful
            #    roll.
            want_ver = new_img.get("xpf-version", "")
            want_nid = node_ids[node]
            deadline = _time.time() + boot_deadline
            back = False
            # #7559 daemon-hold observation. Deliberately THREE outcomes, not a
            # boolean: "the hook held xpfd" and "we could not tell" are
            # different facts and must not collapse into one, or an unreadable
            # state would be reported as protection.
            daemon_held = False    # observed masked/disabled before gate-pass
            daemon_running = False # observed RUNNING before gate-pass
            last_reason = ("did not come back within the boot deadline "
                           "(xpfd never answered protocol-versions)")
            while _time.time() < deadline:
                _time.sleep(10)
                # RENEWAL (#5816): keep the reservation alive across the boot
                # wait. The recreated node has a FRESH disk with no lease file,
                # so ONLY the peer's lease is renewed here — it is the sole
                # remaining reservation and the one that blocks a successor from
                # acquiring both leases. A provably LOST peer lease means a
                # successor reclaimed the pair: stop before rejoin.
                lost = _keepalive_leases(runner, backend, [(peer, nid)],
                                         holder, lease_ttl)
                if lost:
                    die(f"{lost}: LOST the roll lease while waiting for {node} to "
                        f"come back on the new image — another orchestrator "
                        f"reclaimed the pair reservation. Stopping; investigate "
                        f"the half-rolled cluster (a successor may be mutating "
                        f"this pair).")
                # #7559: read the daemon-hold state BEFORE the identity gate.
                # Order is load-bearing: a node that came back with xpfd already
                # RUNNING was never protected, and that stays true on the very
                # tick where the gate happens to pass. Deciding after the gate
                # would let the fastest possible failure — a node that booted,
                # elected, and answered within one poll interval — be recorded
                # as a protected roll.
                hold_state = (_node_daemon_hold_state(runner, backend, node)
                              if hold_supported else "unknown")
                if hold_state == "running":
                    if not daemon_running:
                        daemon_running = True
                        print(f"   NOTE: {node} came back with xpfd ALREADY "
                              f"RUNNING — this roll is NOT protected against "
                              f"the #7559 election window (the recreate hook "
                              f"did not honour XPF_ROLL_DAEMON_HOLD). The node "
                              f"could have won an election before its identity "
                              f"was proven; the unverified-primary check below "
                              f"(#6759) is the remaining net.")
                    if args.require_daemon_hold:
                        die(f"{node} came back with xpfd RUNNING before the "
                            f"image/identity gate passed, and "
                            f"--require-daemon-hold was given. The recreate "
                            f"hook must keep xpfd from auto-starting on the "
                            f"first boot (mask the unit before the guest "
                            f"boots); the driver starts it once the node is "
                            f"proven to be node-id {want_nid} on "
                            f"{want_ver!r}. STOPPING with the never-both-down "
                            f"leases HELD (#7559).")
                elif hold_state == "held":
                    daemon_held = True
                pv = _node_protocol_versions(runner, backend, node)
                # Only read the node-id marker once xpfd is actually answering,
                # to avoid an extra `cat` on every poll while the node is down.
                live_nid = None
                if pv.get("xpf-version"):
                    live_nid = _node_cluster_node_id(runner, backend, node)
                back, last_reason = _recreated_node_matches(
                    pv, want_ver, live_nid, want_nid)
                if back:
                    break
                # #6759: the recreate WIPED this node, which erased the drain
                # that was applied before it — and the identity gate above has
                # NOT passed yet, so we do not know this is the right node
                # running the right image. If it is nevertheless already
                # PRIMARY, an unverified node is carrying traffic. Fail closed
                # with the leases HELD, the same stance this loop already takes
                # for a version/node-id mismatch.
                #
                # THIS DOES NOT CLOSE THE WINDOW, and must not be read as a
                # guard. The election happens during the recreated node's own
                # bringup (daemon_run_bringup.go runs UpdateConfig, which
                # elects on the single-node path) — long before any driver
                # command reaches it. By the time this check can observe
                # anything, the election has already happened. It DETECTS the
                # exposure and stops the roll; it cannot prevent it. Closing it
                # needs a signal that survives the disk wipe, which the
                # kernel-roll's on-node journal cannot provide here — see the
                # successor issue.
                if _node_is_primary_for_any_rg(runner, backend, node, live_nid):
                    die(f"{node} is PRIMARY for a redundancy group but has NOT passed "
                        f"the image/identity gate ({last_reason}). The recreate wiped "
                        f"the drain applied before it, so an UNVERIFIED node is "
                        f"carrying traffic. STOPPING with the never-both-down leases "
                        f"HELD — investigate before rejoining (#6759).")
            if not back:
                die(f"{node} did NOT come back as the expected node on the new "
                    f"image within {boot_deadline}s after image recreate: "
                    f"{last_reason}. STOPPING with the never-both-down leases HELD "
                    f"— {peer} stays primary. Investigate the recreate (#5075).")
            print(f"   {node} back on the new image: {last_reason}")

            # 3b. #7559: the identity gate has PASSED — only NOW may the elector
            #     run. Releasing here, and only here, is the whole mechanism:
            #     while xpfd was held the node could not elect, so there was no
            #     window in which an unverified image could claim a redundancy
            #     group. A node that FAILED the gate never reaches this line —
            #     every failure path above die()s with the leases held — so a
            #     wrong-image / wrong-node-id recreate is left inert rather than
            #     merely detected.
            if daemon_held:
                print(f"   identity gate passed with xpfd held — starting xpfd "
                      f"on {node}...")
                _release_daemon_hold(runner, backend, node)
                state = _wait_daemon_ready(runner, backend, node)
                if state != "ready":
                    die(f"{node} passed the image/identity gate but xpfd was "
                        f"not READY within {_DAEMON_START_DEADLINE}s after the "
                        f"daemon hold was released (last observed: {state}). "
                        f"NOT rejoining a daemon that has not answered — "
                        f"`rejoin` dials gRPC once, un-retried, and would fail "
                        f"the roll with an opaque transport error. STOPPING "
                        f"with the never-both-down leases HELD — {peer} stays "
                        f"primary. On {node}: `systemctl unmask xpfd && "
                        f"systemctl enable --now xpfd`, then check "
                        f"`journalctl -u xpfd` (#7559).")
            elif hold_supported and args.require_daemon_hold:
                # Never observed a hold AND never observed it running: the
                # daemon state was unreadable for the whole poll (no systemd,
                # a transport that only ever answered the version probe). The
                # flag asks for an ENFORCED guarantee, and an unobservable
                # daemon is an unproven one — a distinct reason from
                # "came back running", and it must say so rather than reuse
                # that message.
                die(f"--require-daemon-hold was given but the daemon-hold "
                    f"state of {node} was never readable during the boot poll, "
                    f"so the #7559 election window cannot be shown to have been "
                    f"closed. STOPPING with the never-both-down leases HELD. "
                    f"(`systemctl show xpfd` must be runnable on the node "
                    f"through the {backend} backend for the guarantee to be "
                    f"verifiable.)")

            # 4. rejoin + confirm sync BEFORE touching the peer (never-both-down).
            # FENCE (#5816): re-verify ownership before rejoin re-enables the
            # node's forwarding. Only the PEER's lease is checked — the recreate
            # gave the node a fresh disk with no lease file, so fencing the node
            # would false-abort. The peer lease is the reservation that matters.
            _fence_before_mutate(runner, backend, [(peer, nid)],
                                 holder, lease_ttl, f"rejoin {node}")
            print(f"   rejoining {node} (confirming sync)...")
            _node_exec(runner, backend, node,
                       ["xpfd", "upgrade", "kernel", "rejoin",
                        "--drain-deadline", f"{drain_deadline}s"])
            completed = True
        finally:
            # Release the cross-orchestrator mutex ONLY on a clean roll of THIS
            # node (HIGH Codex never-both-down): on a mid-roll abort the cluster
            # is half-rolled (this node may be drained/down/unrejoined), so the
            # leases stay HELD until their TTL — a second orchestrator is blocked
            # from draining the still-primary peer (which would put both nodes
            # down) and the operator must investigate the half-rolled pair. The
            # drain verb's own peer-alive/takeover-ready precheck is the hard
            # backstop; keeping the lease held is defense-in-depth so recovery is
            # operator-gated, not a TTL race.
            if completed or not state_changed:
                # Clean roll, OR a failure BEFORE any mutation (lease acquire /
                # pre-drain mixed-base gate): nothing is half-rolled, so release
                # the leases — otherwise the operator's own retry (e.g. rerun
                # with --allow-session-drop) would be blocked by this caller's
                # stale lease for the full TTL (Codex).
                _clear_lease(runner, backend, node, holder)
                _clear_lease(runner, backend, peer, holder)
            else:
                print(f"   roll of {node} did NOT complete after the drain "
                      f"began — holding the image-roll lease on {node} and "
                      f"{peer} until TTL ({lease_ttl}s) so no other orchestrator "
                      f"drains the still-primary peer. Investigate the "
                      f"half-rolled cluster.")

    roll_one(nodes[0], nodes[1], is_second=False)
    print(f"\n==> {nodes[0]} done; rolling the second node")
    roll_one(nodes[1], nodes[0], is_second=True)
    print(f"\n==> LANE-2 HA image roll COMPLETE on both nodes")
    return 0


def _recreate_node_from_image(runner, backend, node, args, keepalive=None,
                             keepalive_interval=None, expect_version=None,
                             expect_node_id=None, daemon_hold=True):
    """Recreate ONE node from the new image. Delegates to the operator-supplied
    recreate hook (a script that does the backend-specific destroy+launch+day-0),
    because the recreate mechanics differ per environment (incus launch, libvirt
    redefine, bare-metal re-flash). The hook gets XPF_ROLL_NODE and
    XPF_ROLL_BACKEND in the env, plus (#7559) XPF_ROLL_EXPECT_VERSION,
    XPF_ROLL_EXPECT_NODE_ID and XPF_ROLL_DAEMON_HOLD=1 — the identity this roll
    expects the recreated node to have, and the request that xpfd be kept from
    auto-starting on its first boot so the driver can prove that identity
    BEFORE the node is able to win an election. The extra variables are purely
    additive: a pre-#7559 hook ignores them and behaves exactly as before, so
    the caller VERIFIES the hold instead of assuming it.

    LEASE RENEWAL RUNS *DURING* THE HOOK (#6762). The caller passes `keepalive`,
    a zero-argument callable returning the name of a target whose lease is
    provably LOST (else None); it is invoked every `keepalive_interval` seconds
    while the hook runs.

    Why this is not covered by the fence before it: `_fence_before_mutate`
    extends the leases to ONE fresh TTL and returns. The hook is an ARBITRARY
    operator script doing destroy+launch+day-0 — an image pull, a cloud API
    wait, a bare-metal re-flash — with no bound on its duration, and while it
    ran NOTHING renewed. A hook that outlives the TTL let the still-up peer's
    lease expire, and that peer lease is the SOLE remaining reservation once the
    recreate wipes the node's own /var/lib. A successor could then acquire both
    node leases and begin a concurrent roll on a pair this driver was in the
    middle of recreating. The comment on that fence names the risk — #5545
    flagged the recreate as "potentially outlasting a short TTL" — and a single
    extension answers "the phase boundary", not "the phase".

    A LOSS DETECTED MID-HOOK DOES NOT KILL THE HOOK. The node is already being
    destroyed; interrupting a half-finished recreate is worse than letting it
    finish. The loss is recorded and reported by the caller, which fails closed
    BEFORE rejoining — the same response the boot-poll loop already gives.
    """
    hook = args.recreate_hook
    if not hook:
        die(f"image-roll needs --recreate-hook <script> to recreate {node} from "
            f"the new image (the backend-specific destroy+launch+day-0 step). "
            f"This keeps the never-both-down sequencing here while the recreate "
            f"mechanics stay environment-specific.")
    env = dict(os.environ, XPF_ROLL_NODE=node, XPF_ROLL_BACKEND=backend)
    # #7559: tell the hook what this roll expects of the node it is about to
    # create, and ask it to hold the daemon. Purely ADDITIVE — a hook written
    # before this change ignores the extra variables and behaves exactly as it
    # did — which is why the driver VERIFIES the hold rather than assuming it.
    if expect_version is not None:
        env["XPF_ROLL_EXPECT_VERSION"] = str(expect_version)
    if expect_node_id is not None:
        env["XPF_ROLL_EXPECT_NODE_ID"] = str(expect_node_id)
    if daemon_hold:
        env["XPF_ROLL_DAEMON_HOLD"] = "1"
    print(f"   recreating {node} via {hook}...")
    if keepalive is None:
        # No reservation to keep alive (dry-run / single-node paths).
        r = subprocess.run([hook, node], env=env)
        rc = r.returncode
        lost = None
    else:
        rc, lost = _run_with_lease_keepalive([hook, node], env, keepalive,
                                             keepalive_interval)
    if rc != 0:
        die(f"recreate hook for {node} failed (rc={rc}); STOPPING.")
    return lost


def _run_with_lease_keepalive(argv, env, keepalive, interval):
    """Run `argv` to completion while calling `keepalive()` every `interval`
    seconds. Returns (returncode, lost_target_or_None) (#6762).

    Polling in the FOREGROUND rather than renewing from a background thread:
    the renewal path shells out through the same runner the main flow uses, and
    a second thread driving it concurrently would be a new concurrency surface
    on the one code path whose whole job is to prevent two drivers touching one
    pair. A poll loop has no such surface.

    The first loss is remembered and reporting continues — renewal keeps being
    attempted so a transient blip that later recovers is not mistaken for a
    permanent loss, and the caller decides what a recorded loss means."""
    # The floor guards against a zero/negative interval busy-looping on
    # proc.wait(timeout=0); it is deliberately NOT a whole second. Production
    # passes max(5, lease_ttl // 3), so the floor never binds there — it exists
    # only so a caller cannot spin, and keeping it sub-second lets the unit
    # tests exercise several ticks without sleeping for seconds.
    interval = max(0.05, float(interval or 10))
    proc = subprocess.Popen(argv, env=env)
    lost = None
    while True:
        try:
            rc = proc.wait(timeout=interval)
            break
        except subprocess.TimeoutExpired:
            pass
        if lost is None:
            lost = keepalive()
            if lost:
                print(f"   WARNING: lost the roll lease on {lost} while the recreate "
                      f"hook is still running; letting it finish, then STOPPING "
                      f"before rejoin (#6762)")
    return rc, lost


def main():
    argv = sys.argv[1:]
    if "-h" in argv or "--help" in argv or not argv:
        print(__doc__)
        return 0 if ("-h" in argv or "--help" in argv) else 2

    # Peel the global options from ANYWHERE on the command line with a
    # globals-only pre-parser. parse_known_args picks up --dry-run /
    # --hypervisor / --no-start / --image whether they appear before or
    # after the subcommand, and (critically) it CONSUMES their values, so
    # an option value can never be mistaken for the subcommand token.
    g = argparse.ArgumentParser(add_help=False)
    g.add_argument("--dry-run", action="store_true")
    g.add_argument("--hypervisor", default="incus", choices=["incus", "libvirt"])
    g.add_argument("--no-start", action="store_true")
    g.add_argument("--image")
    gargs, rest = g.parse_known_args(argv)

    # `rest` now holds only the subcommand + its own args. The first token
    # is the subcommand; if it isn't one, treat the whole of `rest` as
    # YAML files for `deploy` (the bare-`xpf-deploy.py foo.yaml` shorthand).
    if rest and rest[0] in ("deploy", "destroy", "launch", "inventory", "fetch",
                            "kernel-roll", "image-roll"):
        cmd, cmd_argv = rest[0], rest[1:]
    else:
        cmd, cmd_argv = "deploy", rest

    if cmd == "fetch":
        sub = argparse.ArgumentParser(prog="xpf-deploy.py fetch", add_help=False)
        # #6504: OPTIONAL. Omitted means "this channel's current release",
        # resolved from the signed <channel>/latest.json pointer.
        sub.add_argument("--version")
        sub.add_argument("--image-url", dest="image_url")
        sub.add_argument("--out")
        sub.add_argument("--alias")
        sub.add_argument("--channel", default="stable",
                         help="watermark channel (anti-rollback bucket)")
        sub.add_argument("--allow-rollback", action="store_true",
                         help="permit fetching an older version than the "
                              "recorded watermark (deliberate downgrade)")
        sub.add_argument("--allow-unvalidated", action="store_true",
                         dest="allow_unvalidated",
                         help="fetch an image whose signed provenance sidecar "
                              "records validated: false (a --skip-validate dev "
                              "or emergency build) instead of refusing (#9325)")
        sub.add_argument("--qcow2-only", action="store_true",
                         help="fetch+verify only the qcow2 (libvirt/KVM path)")
        sub.add_argument("--install-libvirt", action="store_true",
                         dest="install_libvirt",
                         help="after verifying, install the qcow2 to the "
                              "libvirt golden path "
                              "(/var/lib/libvirt/images/<image>.qcow2; basename "
                              "from --alias, default xpf-appliance) that "
                              "`deploy --hypervisor libvirt` reads")
        sub.add_argument("--no-import", action="store_true",
                         help="verify only; do not incus image import")
        args = sub.parse_args(cmd_argv)
    elif cmd == "inventory":
        sub = argparse.ArgumentParser(prog="xpf-deploy.py inventory", add_help=False)
        args = sub.parse_args(cmd_argv)
    elif cmd == "launch":
        sub = argparse.ArgumentParser(prog="xpf-deploy.py launch", add_help=False)
        sub.add_argument("--name", required=True)
        sub.add_argument("--mode", default="standalone", choices=["standalone", "cluster"])
        sub.add_argument("--node-id", type=int, dest="node_id")
        sub.add_argument("--cpu", type=int, default=4)
        sub.add_argument("--mem", default="4GiB")
        sub.add_argument("--config")
        sub.add_argument("--nic", action="append", default=[])
        args = sub.parse_args(cmd_argv)
    elif cmd == "kernel-roll":
        sub = argparse.ArgumentParser(prog="xpf-deploy.py kernel-roll", add_help=False)
        sub.add_argument("--node", dest="nodes", action="append", default=[],
                         required=True,
                         help="HA node (incus name or ssh host); give it TWICE "
                              "in roll order (first-to-roll then second)")
        sub.add_argument("--version", required=True,
                         help="candidate kernel uname -r to roll to")
        sub.add_argument("--backend", default="incus", choices=["incus", "ssh"])
        sub.add_argument("--node0-id", type=int, default=0,
                         help="cluster node-id of the FIRST --node (default 0)")
        sub.add_argument("--node1-id", type=int, default=1,
                         help="cluster node-id of the SECOND --node (default 1)")
        sub.add_argument("--lease-ttl", type=positive_int, default=1800,
                         help="kernel-roll lease TTL seconds (must be > 0; "
                              "suppresses the node's local self-recovery during "
                              "the roll)")
        sub.add_argument("--boot-deadline", type=int, default=600,
                         help="seconds to wait for a node to boot + promote the "
                              "candidate before STOPPING the roll")
        args = sub.parse_args(cmd_argv)
    elif cmd == "image-roll":
        sub = argparse.ArgumentParser(prog="xpf-deploy.py image-roll", add_help=False)
        sub.add_argument("--node", dest="nodes", action="append", default=[],
                         required=True,
                         help="HA node (incus name or ssh host); give it TWICE "
                              "in roll order (first-to-roll then second)")
        sub.add_argument("--manifest", required=True,
                         help="the NEW image's xpf-<ver>.manifest (read for the "
                              "mixed-base HA-protocol gate; VERIFIED against the "
                              "signed SHA256SUMS before use, #5042)")
        sub.add_argument("--sha256sums", default=None,
                         help="the SIGNED xpf-<ver>.SHA256SUMS that covers the "
                              ".manifest (default: the .SHA256SUMS sibling of "
                              "--manifest). The mixed-base gate authenticates the "
                              "manifest against this before reading it (#5042).")
        sub.add_argument("--sig", default=None,
                         help="minisign signature over --sha256sums "
                              "(default: <sha256sums>.minisig)")
        sub.add_argument("--pubkey", default=None,
                         help="image signing public key (default: pinned "
                              "scripts/dist/xpf-image.pub or $XPF_IMAGE_PUBKEY)")
        sub.add_argument("--recreate-hook", dest="recreate_hook",
                         help="script invoked as <hook> <node> to destroy+launch "
                              "the node from the new image + re-apply day-0 "
                              "(backend-specific); receives XPF_ROLL_NODE, "
                              "XPF_ROLL_BACKEND, XPF_ROLL_EXPECT_VERSION, "
                              "XPF_ROLL_EXPECT_NODE_ID and XPF_ROLL_DAEMON_HOLD "
                              "in env")
        sub.add_argument("--allow-unvalidated", action="store_true",
                         dest="allow_unvalidated",
                         help="roll an image whose signed manifest records "
                              "validated: false (a --skip-validate build) instead "
                              "of refusing (#9325)")
        sub.add_argument("--require-daemon-hold", action="store_true",
                         help="REFUSE the roll unless the recreate hook is "
                              "observed to have kept xpfd from auto-starting on "
                              "the recreated node (#7559). Without it an "
                              "unheld daemon is reported and the roll proceeds "
                              "with today's exposure — the recreated node can "
                              "win an election before its identity is proven. "
                              "Also FORCES the hold on --backend ssh, where it "
                              "is otherwise skipped because a held xpfd leaves "
                              "the appliance image with no management address "
                              "for ssh to reach: pass it only if this platform "
                              "addresses the node independently of xpfd.")
        sub.add_argument("--backend", default="incus", choices=["incus", "ssh"])
        sub.add_argument("--node0-id", type=int, default=0,
                         help="cluster node-id of the FIRST --node (default 0)")
        sub.add_argument("--node1-id", type=int, default=1,
                         help="cluster node-id of the SECOND --node (default 1)")
        sub.add_argument("--lease-ttl", type=positive_int, default=1800,
                         help="image-roll lease TTL seconds (must be > 0; "
                              "cross-orchestrator mutex; also suppresses the "
                              "node's self-recovery)")
        sub.add_argument("--drain-deadline", type=int, default=30,
                         help="seconds to confirm the drain/rejoin predicate")
        sub.add_argument("--boot-deadline", type=int, default=600,
                         help="seconds to wait for a recreated node to come back "
                              "before STOPPING the roll")
        sub.add_argument("--allow-session-drop", action="store_true",
                         help="proceed node-by-node even if the mixed-base gate "
                              "fails (sessions WILL drop at the failover)")
        args = sub.parse_args(cmd_argv)
    elif cmd == "destroy":
        sub = argparse.ArgumentParser(prog="xpf-deploy.py destroy", add_help=False)
        sub.add_argument("yamls", nargs="*")
        args = sub.parse_args(cmd_argv)
    else:  # deploy
        sub = argparse.ArgumentParser(prog="xpf-deploy.py deploy", add_help=False)
        sub.add_argument("yamls", nargs="*")
        args = sub.parse_args(cmd_argv)

    # Fold the peeled globals into the namespace the command handlers read.
    args.cmd = cmd
    args.dry_run = gargs.dry_run
    args.hypervisor = gargs.hypervisor
    args.no_start = gargs.no_start
    args.image = gargs.image

    if cmd == "fetch":
        return cmd_fetch(args)
    if cmd == "inventory":
        return cmd_inventory(args)
    if cmd == "launch":
        return cmd_launch(args)
    if cmd == "kernel-roll":
        return cmd_kernel_roll(args)
    if cmd == "image-roll":
        return cmd_image_roll(args)
    if cmd == "destroy":
        return cmd_destroy(args)
    return cmd_deploy(args)


if __name__ == "__main__":
    sys.exit(main())
