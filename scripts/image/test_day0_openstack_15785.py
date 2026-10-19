#!/usr/bin/env python3
"""Regression tests for #15785 — OpenStack config-2 / Cloud-Init cidata
config drives and vSRX cloud paths in xpf-day0-config.

On base, probe_devices only queried LABEL=xpf-config + TYPE=iso9660 and
try_device only tried xpf.conf/juniper.conf at the volume root, so an
OpenStack config drive (vfat, LABEL=config-2) carrying
OpenStack/latest/junos-config/configuration.txt, or a Cloud-Init NoCloud
drive (LABEL=cidata) carrying openstack/latest/user_data or user-data
with a #junos-config first line, was undiscoverable and unusable.

These tests drive the real loader through its XPF_DAY0_SOURCE_ONLY=1
hook (6502/9921 pattern) with PATH-stubbed blkid/mount/umount/mktemp/
install and a stub xpfd. The blkid stub models filesystem LABELS only
(no TYPE=iso9660 match for the vfat drives), so the config-2/cidata
cells can only pass if the loader probes those labels without a TYPE
gate. Assertions read the files the real script wrote (installed
xpf.conf, stamp) and the mount order. RED on base: probe returns no
config-2/cidata device, and try_device finds no config at the nested
paths.

Run: python3 -m pytest scripts/image/test_day0_openstack_15785.py
     python3 scripts/image/test_day0_openstack_15785.py
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
LOADER = HERE / "xpf-day0-config"

CONF = "system {{\n    host-name {name};\n}}\n"

MOCK_MOUNT = """#!/usr/bin/env bash
args=()
while (( $# )); do
  case "$1" in
    -o) shift 2 ;;
    *) args+=("$1"); shift ;;
  esac
done
dev="${args[0]}"; mnt="${args[1]}"
src="$MOCK_MEDIA/$(basename "$dev")"
[ -d "$src" ] || exit 1
mkdir -p "$mnt"
cp -a "$src"/. "$mnt"/
echo "$dev" >> "$MOCK_MOUNTLOG"
exit 0
"""

MOCK_UMOUNT = """#!/usr/bin/env bash
mnt="${1:-}"
[ -n "$mnt" ] && rm -rf "${mnt:?}"/* "${mnt:?}"/.[!.]* 2>/dev/null
exit 0
"""

MOCK_INSTALL = """#!/usr/bin/env bash
args=()
while (( $# )); do
  case "$1" in
    -o|-g) shift 2 ;;
    *) args+=("$1"); shift ;;
  esac
done
exec /usr/bin/install "${args[@]}"
"""

MOCK_MKTEMP = """#!/usr/bin/env bash
args=()
for a in "$@"; do args+=("${a/#\\/run\\//$MOCK_RUN/}"); done
exec /usr/bin/mktemp "${args[@]}"
"""


def _blkid(xpf=(), config2=(), cidata=(), isos=()):
    """blkid stub keyed by label/type query. vfat drives match ONLY the
    LABEL queries — no iso9660 TYPE hit — mirroring a real vfat medium."""
    def emit(vals):
        joined = " ".join(vals)
        return f'[ -n "{joined}" ] && printf \'%s\\n\' {joined} ;;'
    return ("#!/bin/sh\n"
            'case "$*" in\n'
            f"*LABEL=xpf-config*) {emit(list(xpf))}\n"
            f"*LABEL=config-2*) {emit(list(config2))}\n"
            f"*LABEL=cidata*) {emit(list(cidata))}\n"
            f"*TYPE=iso9660*) {emit(list(isos))}\n"
            "esac\n"
            "exit 0\n")


@unittest.skipUnless(shutil.which("bash") and shutil.which("perl"),
                     "bash + perl not available")
class _Base(unittest.TestCase):
    def setUp(self):
        self.assertTrue(LOADER.is_file(), f"{LOADER} missing")
        self.tmp = Path(tempfile.mkdtemp(prefix="xpf-day0-15785."))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.bin = self.tmp / "bin"; self.bin.mkdir()
        self.media = self.tmp / "media"; self.media.mkdir()
        self.run = self.tmp / "run"; self.run.mkdir()
        self.xpf_dir = self.tmp / "etc-xpf"
        self.mnt = self.tmp / "mnt"
        self.mountlog = self.tmp / "mount.log"
        for name, body in (("mount", MOCK_MOUNT), ("umount", MOCK_UMOUNT),
                           ("install", MOCK_INSTALL), ("mktemp", MOCK_MKTEMP)):
            f = self.bin / name; f.write_text(body); f.chmod(0o755)
        self.xpfd = self.tmp / "xpfd"
        self.xpfd.write_text("#!/bin/sh\nexit 0\n"); self.xpfd.chmod(0o755)

    def add_blkid(self, **kw):
        f = self.bin / "blkid"; f.write_text(_blkid(**kw)); f.chmod(0o755)

    def add_medium(self, dev, files):
        """files: {relative/path: text} nested paths are created."""
        d = self.media / os.path.basename(dev)
        d.mkdir(parents=True, exist_ok=True)
        for rel, text in files.items():
            p = d / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text)

    def _env(self):
        env = dict(os.environ)
        env.update({
            "PATH": f"{self.bin}:{env.get('PATH', '')}",
            "MOCK_MEDIA": str(self.media),
            "MOCK_RUN": str(self.run),
            "MOCK_MOUNTLOG": str(self.mountlog),
            "XPF_DAY0_SOURCE_ONLY": "1",
        })
        return env

    def _sourced(self, body):
        script = (f'. "{LOADER}"\n'
                  f'XPF_DIR="{self.xpf_dir}"\n'
                  f'STAMP="$XPF_DIR/.day0-config-applied"\n'
                  f'REJECT_MARKER="$XPF_DIR/.day0-config-rejected"\n'
                  f'MNT="{self.mnt}"\n'
                  f'XPFD="{self.xpfd}"\n'
                  'regen_ssh_host_keys() { :; }\n'
                  + body)
        return subprocess.run(["bash", "-c", script], env=self._env(),
                              capture_output=True, text=True)

    def probe(self):
        res = self._sourced("probe_devices\n")
        self.assertEqual(res.returncode, 0, res.stderr)
        return res.stdout.split()

    def run_main(self):
        res = self._sourced("main\n")
        self.assertEqual(res.returncode, 0, res.stderr)
        return res

    def installed(self):
        f = self.xpf_dir / "xpf.conf"
        return f.read_text() if f.is_file() else None

    def installed_hostname(self):
        text = self.installed()
        if text is None:
            return None
        for line in text.splitlines():
            if "host-name" in line:
                return line.split()[-1].rstrip(";")
        return None

    def mounted(self):
        return (self.mountlog.read_text().split()
                if self.mountlog.exists() else [])


class ProbeDevicesTests(_Base):
    def test_config2_label_is_probed(self):
        self.add_blkid(config2=["/dev/vdb"])
        self.assertEqual(self.probe(), ["/dev/vdb"])

    def test_cidata_label_is_probed(self):
        self.add_blkid(cidata=["/dev/vdc"])
        self.assertEqual(self.probe(), ["/dev/vdc"])

    def test_priority_xpf_then_config2_cidata_then_iso(self):
        self.add_blkid(xpf=["/dev/sda"], config2=["/dev/sdb"],
                       cidata=["/dev/sdc"], isos=["/dev/sdd"])
        self.assertEqual(self.probe(),
                         ["/dev/sda", "/dev/sdb", "/dev/sdc", "/dev/sdd"])

    def test_config2_that_is_also_iso_appears_once_at_label_position(self):
        self.add_blkid(config2=["/dev/sr0"], isos=["/dev/sr0", "/dev/sda"])
        self.assertEqual(self.probe(), ["/dev/sr0", "/dev/sda"])

    def test_existing_xpf_and_iso_discovery_unchanged(self):
        self.add_blkid(xpf=["/dev/sdb"], isos=["/dev/sda"])
        self.assertEqual(self.probe(), ["/dev/sdb", "/dev/sda"])


class OpenStackPathTests(_Base):
    def test_config2_junos_configuration_txt_is_installed(self):
        self.add_blkid(config2=["/dev/vdb"])
        self.add_medium("/dev/vdb", {
            "OpenStack/latest/junos-config/configuration.txt":
                CONF.format(name="from-config2-junos")})
        self.run_main()
        self.assertEqual(self.installed_hostname(), "from-config2-junos")
        stamp = (self.xpf_dir / ".day0-config-applied").read_text()
        self.assertIn("/dev/vdb", stamp)

    def test_cidata_openstack_user_data_is_installed(self):
        self.add_blkid(cidata=["/dev/vdc"])
        self.add_medium("/dev/vdc", {
            "openstack/latest/user_data":
                CONF.format(name="from-cidata-userdata")})
        self.run_main()
        self.assertEqual(self.installed_hostname(), "from-cidata-userdata")

    def test_cidata_root_user_data_with_junos_header_is_installed(self):
        self.add_blkid(cidata=["/dev/vdc"])
        self.add_medium("/dev/vdc", {
            "user-data": "#junos-config\n" + CONF.format(name="from-user-data")})
        self.run_main()
        installed = self.installed()
        self.assertIsNotNone(installed)
        self.assertNotIn("#junos-config", installed,
                         "installed config must not retain the header line")
        self.assertEqual(self.installed_hostname(), "from-user-data")

    def test_root_xpf_conf_wins_over_nested_user_data_on_same_medium(self):
        self.add_blkid(cidata=["/dev/vdc"])
        self.add_medium("/dev/vdc", {
            "xpf.conf": CONF.format(name="from-root-xpf"),
            "user-data": "#junos-config\n" + CONF.format(name="from-user-data")})
        self.run_main()
        self.assertEqual(self.installed_hostname(), "from-root-xpf")

    def test_symlink_at_nested_path_is_not_followed(self):
        self.add_blkid(cidata=["/dev/vdc"])
        d = self.media / "vdc"
        (d / "openstack" / "latest").mkdir(parents=True)
        secret = self.tmp / "secret.conf"
        secret.write_text(CONF.format(name="pwned"))
        (d / "openstack" / "latest" / "user_data").symlink_to(secret)
        self.run_main()
        self.assertIsNone(self.installed(),
                          "symlinked nested user_data was installed")

    def test_config2_rejected_config_does_not_stamp(self):
        self.xpfd.write_text('#!/bin/sh\necho "FAIL bad"\nexit 2\n')
        self.xpfd.chmod(0o755)
        self.add_blkid(config2=["/dev/vdb"])
        self.add_medium("/dev/vdb", {
            "OpenStack/latest/junos-config/configuration.txt":
                CONF.format(name="rejected")})
        self.run_main()
        self.assertIsNone(self.installed())
        self.assertFalse((self.xpf_dir / ".day0-config-applied").exists())


class JunosHeaderTests(_Base):
    def _strip(self, data: bytes) -> bytes:
        f = self.tmp / "candidate.conf"
        f.write_bytes(data)
        res = self._sourced(f'strip_junos_config_header "{f}"\n')
        self.assertEqual(res.returncode, 0, res.stderr)
        return f.read_bytes()

    def test_exact_header_line_is_stripped(self):
        out = self._strip(b"#junos-config\nsystem {\n}\n")
        self.assertEqual(out, b"system {\n}\n")

    def test_crlf_header_line_is_stripped(self):
        out = self._strip(b"#junos-config\r\nsystem {\n}\n")
        self.assertEqual(out, b"system {\n}\n")

    def test_header_with_trailing_text_is_not_stripped(self):
        data = b"#junos-config extra\nsystem {\n}\n"
        self.assertEqual(self._strip(data), data)

    def test_header_only_file_becomes_empty(self):
        self.assertEqual(self._strip(b"#junos-config\n"), b"")

    def test_header_only_user_data_is_not_installed(self):
        # Strip leaves an empty copy; the size gate must reject it.
        self.add_blkid(cidata=["/dev/vdc"])
        self.add_medium("/dev/vdc", {"user-data": "#junos-config\n"})
        self.run_main()
        self.assertIsNone(self.installed())
        self.assertFalse((self.xpf_dir / ".day0-config-applied").exists())


if __name__ == "__main__":
    unittest.main()
