#!/usr/bin/env python3
"""Build an xpf day-0 config drive ISO (#1879 Path C), in Python.

The vSRX analog of "ISO with juniper.conf at the root": an ISO9660 volume
labeled `xpf-config` carrying `xpf.conf` and, for HA cluster configs, a
`node-id` file (`0` or `1`). Standalone configs may omit `node-id`. Attach the
ISO to the appliance VM as a CD-ROM (libvirt) or a disk device (incus); the
first-boot loader applies it.

Importable: validate.py and other tooling call build_config_drive().
CLI:
  make_config_drive.py [-n 0|1] [-o out.iso] [--no-validate] <config-file>

Validation: if an xpfd binary is available (./xpfd or $XPFD), the config
is run through the real commit-check gate and the build FAILS on reject.
--no-validate skips it (the appliance still validates at first boot).
"""

import argparse
import contextlib
import os
import shutil
import subprocess
import sys
import tempfile



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

def die(msg):
    sys.exit(f"ERROR: {msg}")


def find_xpfd():
    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.dirname(os.path.dirname(here))
    for c in (os.environ.get("XPFD"), os.path.join(root, "xpfd"), shutil.which("xpfd")):
        if c and os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    return None


def _iso_tool():
    for t in ("xorriso", "genisoimage", "mkisofs"):
        if shutil.which(t):
            return t
    die("need xorriso/genisoimage/mkisofs (apt-get install xorriso)")


def build_config_drive(config, out=None, node_id=None, validate=True):
    """Build the day-0 ISO. Returns the output path."""
    if not os.path.isfile(config):
        die(f"config file not found: {config}")
    if node_id is not None and str(node_id) not in ("0", "1"):
        die("node-id must be 0 or 1")
    out = out or (os.path.splitext(os.path.basename(config))[0] + "-config.iso")

    if validate:
        xpfd = find_xpfd()
        if xpfd:
            print(f"==> validating {config} with check-config ({xpfd})")
            nodearg = ["-node-id", str(node_id)] if node_id is not None else []
            r = subprocess.run([xpfd, "check-config"] + nodearg + [config],
                               capture_output=True, text=True)
            if r.returncode != 0:
                die("config REJECTED by commit-check — fix it or pass "
                    f"--no-validate:\n{r.stdout}{r.stderr}")
        else:
            print("WARNING: no xpfd binary — skipping build-host validation "
                  "(the appliance still validates at first boot).", file=sys.stderr)

    tool = _iso_tool()
    stage = tempfile.mkdtemp(prefix="xpf-day0-")
    try:
        shutil.copyfile(config, os.path.join(stage, "xpf.conf"))
        # 0o600, not 0o644: the staged xpf.conf carries every day-0 secret
        # (root-authentication hash, IKE PSK, SNMP community, DDNS tokens).
        # The 0700 mkdtemp already shields it, but keep the staged copy
        # owner-only too, matching the deploy path (#4905-C / xpf-deploy.py).
        os.chmod(os.path.join(stage, "xpf.conf"), 0o600)
        if node_id is not None:
            with open(os.path.join(stage, "node-id"), "w") as f:
                f.write(f"{node_id}\n")
        print(f"==> building {out} (volume label xpf-config)")
        if tool == "xorriso":
            argv = ["xorriso", "-as", "mkisofs", "-quiet", "-V", "xpf-config",
                    "-J", "-r", "-o", out, stage]
        else:
            argv = [tool, "-quiet", "-V", "xpf-config", "-J", "-r", "-o", out, stage]
        with _owner_only_umask():
            subprocess.run(argv, check=True)
        # The finished ISO embeds xpf.conf — the most secret-bearing day-0
        # artifact. xorriso/genisoimage/mkisofs writes it under the process
        # umask (~0022 -> 0644, world-readable) and it lingers in CWD until an
        # explicit destroy, so any co-located UID could `isoinfo -x /xpf.conf`
        # the secrets out. Restrict it to owner-only immediately after build,
        # matching the deploy implementation (#4905-C). The owner still reads
        # it fine when attaching it to the VM.
        os.chmod(out, 0o600)
    finally:
        shutil.rmtree(stage, ignore_errors=True)
    return out


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("-n", "--node-id", choices=["0", "1"])
    p.add_argument("-o", "--out")
    p.add_argument("--no-validate", action="store_true")
    p.add_argument("config")
    a = p.parse_args()
    out = build_config_drive(a.config, a.out, a.node_id, not a.no_validate)
    print(f"==> done: {out}")
    print(f"    libvirt: virt-install … --disk path={out},device=cdrom")
    print(f"    incus:   incus config device add <vm> day0 disk source={os.path.abspath(out)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
