#!/usr/bin/env python3
"""Functional self-test: the day-0 loader honours its labeled-first contract
(#6502).

`scripts/image/xpf-day0-config` documents its probe order as "labeled volumes
first (explicit operator intent), then any ISO9660 medium (vSRX cdrom
parity)" — and then piped both blkid passes through `| sort -u`, which merges
and ALPHABETIZES every device path. So an ISO whose /dev node sorts earlier
than the labeled volume's was probed first: an ISO at /dev/sda ahead of a
labeled volume at /dev/sdb, or any /dev/sd* ISO ahead of a virtio-blk /dev/vd*
volume. Kernel enumeration order is not operator intent — incus attaches both
as virtio-scsi sd* in attach order — so with two valid-but-DIFFERENT media
attached the ISO won and stamped, the exact opposite of the documented rule.

(The self-correcting case — ISO invalid, labeled valid — still converged,
because a REJECT does not stamp and the loop moves on. The wrong-winner case
is both-valid-different-content, which is what the end-to-end leg models.)

Two levels, because they fail differently:

  * probe order — the unit-level property, asserted directly against the real
    `probe_devices` with a mocked blkid;
  * which config is INSTALLED and STAMPED — the operator-visible outcome, with
    both media attached and both valid, driving the real `main()`.

The loader is driven through its own `XPF_DAY0_SOURCE_ONLY=1` hook (the one
test/image/day0-configdb-guard-test.sh already uses), with the four absolute
state paths reassigned after sourcing and everything else — blkid, mount,
umount, mktemp, install — shadowed on PATH. Nothing here re-implements the
loader's logic: every assertion reads the files the real script wrote.

Python rather than shell so `run-selftests.sh:139` discovers it by glob; the
shell self-test list at :146-160 is hand-enumerated (#7296), which is why
test/image/day0-configdb-guard-test.sh runs under no target at all.
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

# A config a real commit-check would accept. The two media carry DIFFERENT
# host-names so the installed file names its own winner.
CONF = """system {{
    host-name {name};
}}
"""

# mount: no root, so "mounting" a device copies that device's medium
# directory into $MNT. The device -> medium mapping is a directory named
# after the device's basename.
MOCK_MOUNT = """#!/usr/bin/env bash
# usage (as the loader calls it): mount -o ro,... <dev> <mnt>
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

# install: the loader passes -o root -g root, which a non-root test cannot
# honour. Drop ONLY the ownership flags and forward everything else — the
# mode, the source, the destination — to the real install, so the file the
# assertions read is written by real install with the real -m.
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

# mktemp: the loader writes its private copy under /run, which is not writable
# by a test. Redirect a leading /run/ to the harness's scratch dir and forward.
MOCK_MKTEMP = """#!/usr/bin/env bash
args=()
for a in "$@"; do args+=("${a/#\\/run\\//$MOCK_RUN/}"); done
exec /usr/bin/mktemp "${args[@]}"
"""


def _blkid(labeled, isos):
    lines = "\n".join(labeled) or ""
    isolines = "\n".join(isos) or ""
    return f"""#!/bin/sh
case "$*" in
*LABEL=xpf-config*) [ -n '{lines}' ] && printf '%s\\n' '{lines}' ;;
*TYPE=iso9660*)     [ -n '{isolines}' ] && printf '%s\\n' '{isolines}' ;;
esac
exit 0
"""


@unittest.skipUnless(shutil.which("bash"), "bash not available")
class _LoaderBase(unittest.TestCase):
    def setUp(self):
        self.assertTrue(LOADER.is_file(), f"{LOADER} missing")
        self.tmp = Path(tempfile.mkdtemp(prefix="xpf-day0-6502."))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.bin = self.tmp / "bin"
        self.bin.mkdir()
        self.media = self.tmp / "media"
        self.media.mkdir()
        self.run = self.tmp / "run"
        self.run.mkdir()
        self.xpf_dir = self.tmp / "etc-xpf"
        self.mnt = self.tmp / "mnt"
        self.mountlog = self.tmp / "mount.log"
        for name, body in (("mount", MOCK_MOUNT), ("umount", MOCK_UMOUNT),
                           ("install", MOCK_INSTALL), ("mktemp", MOCK_MKTEMP)):
            f = self.bin / name
            f.write_text(body)
            f.chmod(0o755)
        # A stub xpfd that ACCEPTS every config (`check-config` exit 0), so the
        # only thing deciding the winner is probe ORDER.
        self.xpfd = self.tmp / "xpfd"
        self.xpfd.write_text("#!/bin/sh\nexit 0\n")
        self.xpfd.chmod(0o755)

    def add_blkid(self, labeled=(), isos=()):
        f = self.bin / "blkid"
        f.write_text(_blkid(list(labeled), list(isos)))
        f.chmod(0o755)

    def add_medium(self, dev, name, filename="xpf.conf"):
        """Give device `dev` a medium carrying a config with host-name `name`."""
        d = self.media / os.path.basename(dev)
        d.mkdir(parents=True, exist_ok=True)
        (d / filename).write_text(CONF.format(name=name))

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
                  # regen_ssh_host_keys would try to write /etc/ssh.
                  'regen_ssh_host_keys() { :; }\n'
                  + body)
        return subprocess.run(["bash", "-c", script], env=self._env(),
                              capture_output=True, text=True)

    def probe(self):
        res = self._sourced("probe_devices\n")
        self.assertEqual(res.returncode, 0, res.stderr)
        return res.stdout.split()

    def probe_raw(self):
        """probe_devices' output VERBATIM. `probe()` splits on whitespace,
        which silently discards blank lines — so it cannot see whether the
        blank-line guard is present at all."""
        res = self._sourced("probe_devices\n")
        self.assertEqual(res.returncode, 0, res.stderr)
        return res.stdout

    def run_main(self):
        res = self._sourced("main\n")
        # The loader must NEVER fail the boot.
        self.assertEqual(res.returncode, 0, res.stderr)
        return res

    def installed_hostname(self):
        conf = self.xpf_dir / "xpf.conf"
        if not conf.is_file():
            return None
        for line in conf.read_text().splitlines():
            if "host-name" in line:
                return line.split()[-1].rstrip(";")
        return None

    def mounted(self):
        return (self.mountlog.read_text().split()
                if self.mountlog.exists() else [])


class ProbeOrderTests(_LoaderBase):
    def test_labeled_volume_wins_when_the_iso_sorts_first(self):
        # THE bug, at unit level: an ISO at /dev/sda and a labeled volume at
        # /dev/sdb. `sort -u` puts sda first; the contract says sdb.
        self.add_blkid(labeled=["/dev/sdb"], isos=["/dev/sda"])
        self.assertEqual(self.probe(), ["/dev/sdb", "/dev/sda"])

    def test_virtio_labeled_volume_beats_a_scsi_iso(self):
        # /dev/vdb sorts AFTER /dev/sda in every C-locale sort.
        self.add_blkid(labeled=["/dev/vdb"], isos=["/dev/sda"])
        self.assertEqual(self.probe(), ["/dev/vdb", "/dev/sda"])

    def test_multiple_labeled_volumes_keep_blkids_own_order(self):
        # Within a pass the order is blkid's, not alphabetical.
        self.add_blkid(labeled=["/dev/sdc", "/dev/sdb"], isos=["/dev/sda"])
        self.assertEqual(self.probe(), ["/dev/sdc", "/dev/sdb", "/dev/sda"])

    def test_a_device_that_is_both_labeled_and_iso_appears_once_as_labeled(self):
        # Dedup must span the two passes, which a per-pass dedup would not do,
        # and must keep the LABELED position — explicit intent still wins.
        self.add_blkid(labeled=["/dev/sr0"], isos=["/dev/sr0", "/dev/sda"])
        self.assertEqual(self.probe(), ["/dev/sr0", "/dev/sda"])

    def test_no_media_probes_nothing(self):
        self.add_blkid()
        self.assertEqual(self.probe(), [])

    def test_iso_only_still_probes_the_iso(self):
        # The vSRX cdrom parity path is not regressed by the ordering fix.
        self.add_blkid(isos=["/dev/sr0"])
        self.assertEqual(self.probe(), ["/dev/sr0"])

    def test_never_committed_active_json_does_not_skip_day0_probe(self):
        active = self.xpf_dir / ".configdb" / "active.json"
        active.parent.mkdir(parents=True)
        active.write_text(
            "#xpf-config-envelope v=2 writer=test ast=1 min-reader=1 "
            "rollback-fmt=1 committed=0\n{}\n")
        self.add_blkid(labeled=["/dev/sdb"])
        self.add_medium("/dev/sdb", "from-day0-after-rollback")

        res = self.run_main()

        self.assertEqual(self.installed_hostname(), "from-day0-after-rollback",
                         "committed=0 active.json must allow first-boot retry")
        self.assertEqual(self.mounted(), ["/dev/sdb"])
        self.assertTrue((self.xpf_dir / ".day0-config-applied").is_file())

    def test_committed_active_json_still_skips_day0_probe(self):
        active = self.xpf_dir / ".configdb" / "active.json"
        active.parent.mkdir(parents=True)
        active.write_text(
            "#xpf-config-envelope v=2 writer=test ast=1 min-reader=1 "
            "rollback-fmt=1 committed=1\n{}\n")
        self.add_blkid(labeled=["/dev/sdb"])
        self.add_medium("/dev/sdb", "must-not-replace")

        res = self.run_main()

        self.assertIn("system already configured", res.stdout)
        self.assertEqual(self.mounted(), [])
        self.assertIsNone(self.installed_hostname())


    def test_blank_blkid_output_emits_nothing_at_all(self):
        # Asserted on the RAW output: `probe()` splits on whitespace and would
        # report [] whether or not the blank-line guard exists.
        #
        # Scope, stated honestly: this is HYGIENE, not a behaviour change.
        # main() does `devs=$(probe_devices)`, and command substitution strips
        # trailing newlines, so an all-blank output was already empty; and
        # `for dev in $devs` word-splits, so an interior blank could never
        # become a probed device. The guard keeps probe_devices' own output
        # honest for any reader that does not go through those two steps.
        f = self.bin / "blkid"
        f.write_text("#!/bin/sh\nprintf '\\n\\n'\nexit 0\n")
        f.chmod(0o755)
        self.assertEqual(self.probe_raw(), "")

    def test_a_blank_line_beside_a_real_device_is_dropped(self):
        f = self.bin / "blkid"
        f.write_text("#!/bin/sh\n"
                     'case "$*" in *LABEL=xpf-config*) printf \'/dev/sdb\\n\\n\';; esac\n'
                     "exit 0\n")
        f.chmod(0o755)
        self.assertEqual(self.probe_raw(), "/dev/sdb\n")


class BothMediaAttachedTests(_LoaderBase):
    """The operator-visible outcome: both media attached, both VALID, and
    carrying DIFFERENT configs. Which one is installed and stamped?"""

    def _attach_both(self):
        self.add_blkid(labeled=["/dev/sdb"], isos=["/dev/sda"])
        self.add_medium("/dev/sdb", "from-labeled-volume")
        self.add_medium("/dev/sda", "from-iso-medium")

    def test_the_labeled_volumes_config_is_the_one_installed(self):
        self._attach_both()
        res = self.run_main()
        self.assertEqual(self.installed_hostname(), "from-labeled-volume",
                         "the ISO's config was installed even though a labeled "
                         f"volume was attached: {res.stderr}")

    def test_the_stamp_records_the_labeled_volume(self):
        self._attach_both()
        self.run_main()
        stamp = (self.xpf_dir / ".day0-config-applied").read_text()
        self.assertIn("/dev/sdb", stamp,
                      "the stamp names the wrong medium as the source")

    def test_the_iso_is_never_even_mounted(self):
        # The labeled volume succeeds, so the loop returns before reaching the
        # ISO. Asserting the ISO was not touched pins ORDER, not just outcome:
        # a build that probed both and happened to overwrite in the right
        # sequence would pass the content check and fail this one.
        self._attach_both()
        self.run_main()
        self.assertEqual(self.mounted(), ["/dev/sdb"])

    def test_juniper_conf_alias_on_the_labeled_volume_also_wins(self):
        # vSRX parity: the labeled volume may carry juniper.conf instead.
        self.add_blkid(labeled=["/dev/sdb"], isos=["/dev/sda"])
        self.add_medium("/dev/sdb", "from-labeled-volume", "juniper.conf")
        self.add_medium("/dev/sda", "from-iso-medium")
        self.run_main()
        self.assertEqual(self.installed_hostname(), "from-labeled-volume")

    def test_an_empty_labeled_volume_falls_through_to_the_iso(self):
        # Ordering must not become "labeled or nothing": a labeled volume that
        # carries no config at all still yields to the ISO fallback.
        self.add_blkid(labeled=["/dev/sdb"], isos=["/dev/sda"])
        (self.media / "sdb").mkdir(parents=True)
        self.add_medium("/dev/sda", "from-iso-medium")
        self.run_main()
        self.assertEqual(self.installed_hostname(), "from-iso-medium")
        self.assertEqual(self.mounted(), ["/dev/sdb", "/dev/sda"])

    def test_a_rejected_labeled_volume_falls_through_and_the_iso_stamps(self):
        # The self-correcting case the issue calls out: a REJECT does not
        # stamp, so the loop moves on. Still true after the ordering fix.
        # A check-config that REJECTS (exit 2) only the labeled volume's
        # config, by reading the file it was handed.
        self.xpfd.write_text(
            "#!/bin/sh\n"
            "for a in \"$@\"; do\n"
            "  [ -f \"$a\" ] && grep -q from-labeled-volume \"$a\" && exit 2\n"
            "done\n"
            "exit 0\n")
        self.xpfd.chmod(0o755)
        self._attach_both()
        self.run_main()
        self.assertEqual(self.installed_hostname(), "from-iso-medium")


if __name__ == "__main__":
    unittest.main()
