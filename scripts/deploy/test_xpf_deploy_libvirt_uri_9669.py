"""#9669: libvirt keeps a separate domain namespace per connection URI.

xpf-deploy ran virsh / virt-install with no --connect, and teardown trusted ONE
presence probe. A domain defined at the other URI then read as ABSENT, the one
answer that lets teardown delete a live VM's disks (#9325). Every presence
question now asks qemu:///system AND qemu:///session; a domain is torn down
through the URI that holds it; disks go only when both URIs report it missing.
Deploy names the system URI, where the disks live.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent.parent
_SPEC = importlib.util.spec_from_file_location("xpf_deploy_9669", _HERE / "xpf-deploy.py")
xd = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
_SPEC.loader.exec_module(xd)

PRESENT, ABSENT, UNKNOWN = xd.DOMAIN_PRESENT, xd.DOMAIN_ABSENT, xd.DOMAIN_UNKNOWN
SYS, SES = xd.LIBVIRT_SYSTEM_URI, xd.LIBVIRT_SESSION_URI


def _cp(argv, rc, out="", err=""):
    return subprocess.CompletedProcess(argv, rc, out, err)


class FakeLibvirt:
    """A per-URI domain table ('defined' / 'absent' / 'unreachable') that answers
    virsh the way libvirt does, and records every argv."""

    def __init__(self, domains, survive_undefine=False):
        self.domains = dict(domains)
        self.survive = survive_undefine
        self.calls = []

    def run(self, argv, **_kw):
        argv = list(argv)
        self.calls.append(argv)
        if argv[:2] != ["virsh", "-c"]:
            raise AssertionError(f"virsh invoked without an explicit URI: {argv}")
        uri, verb = argv[2], argv[3]
        state = self.domains.get(uri, "absent")
        if state == "unreachable":
            return _cp(argv, 1, err=f"error: failed to connect to the hypervisor\nerror: authentication unavailable for {uri}")
        if verb == "dominfo":
            return _cp(argv, 0, out="Name: fw1") if state == "defined" else _cp(argv, 1, err="error: failed to get domain 'fw1'")
        if verb == "destroy":
            return _cp(argv, 0 if state == "defined" else 1)
        if verb == "undefine":
            if state == "defined" and not self.survive:
                self.domains[uri] = "absent"
            return _cp(argv, 0 if state == "defined" else 1)
        return _cp(argv, 0)

    def verbs_at(self, uri, verb):
        return [c for c in self.calls if c[2] == uri and c[3] == verb]


def _quiet():
    return contextlib.redirect_stdout(io.StringIO())


class LocateAcrossURIs9669(unittest.TestCase):
    def test_state_per_arrangement(self):
        cases = [
            ({SYS: "defined", SES: "absent"}, PRESENT, [SYS]),
            ({SYS: "absent", SES: "defined"}, PRESENT, [SES]),
            ({SYS: "defined", SES: "defined"}, PRESENT, [SYS, SES]),
            ({SYS: "absent", SES: "absent"}, ABSENT, []),
            ({SYS: "unreachable", SES: "absent"}, UNKNOWN, []),
            ({SYS: "absent", SES: "unreachable"}, UNKNOWN, []),
            ({SYS: "unreachable", SES: "defined"}, PRESENT, [SES]),
        ]
        for domains, want_state, want_uris in cases:
            fake = FakeLibvirt(domains)
            with mock.patch.object(xd.subprocess, "run", side_effect=fake.run):
                self.assertEqual(xd._virsh_domain_locate("fw1"), (want_state, want_uris), repr(domains))
                self.assertEqual(xd._virsh_domain_state("fw1"), want_state, repr(domains))


class TeardownNeverTrustsOneURI9669(unittest.TestCase):
    def _files(self, td):
        overlay, iso = os.path.join(td, "fw1.qcow2"), os.path.join(td, "fw1.iso")
        for f in (overlay, iso):
            open(f, "w").close()
        return overlay, iso

    def _destroy(self, fake, overlay, iso):
        with mock.patch.object(xd, "libvirt_overlay_path", return_value=overlay), \
             mock.patch.object(xd, "day0_iso_path", return_value=iso), \
             mock.patch.object(xd.subprocess, "run", side_effect=fake.run), \
             mock.patch.object(xd, "run_capture", side_effect=lambda argv, *a, **k: fake.run(argv).stdout), \
             _quiet():
            xd.destroy_libvirt({"name": "fw1"}, xd.Runner(dry=False))

    def test_a_session_domain_is_destroyed_through_the_session_uri(self):
        with tempfile.TemporaryDirectory() as td:
            overlay, iso = self._files(td)
            fake = FakeLibvirt({SYS: "absent", SES: "defined"})
            self._destroy(fake, overlay, iso)
            self.assertTrue(fake.verbs_at(SES, "destroy") and fake.verbs_at(SES, "undefine"),
                            f"the session domain was not torn down through the session URI: {fake.calls}")
            self.assertFalse(fake.verbs_at(SYS, "destroy"), "destroy was sent to a URI that does not hold the domain")
            self.assertFalse(os.path.exists(overlay) or os.path.exists(iso), "disks not removed once both URIs report it gone")

    def test_a_domain_in_both_uris_is_torn_down_in_both(self):
        with tempfile.TemporaryDirectory() as td:
            overlay, iso = self._files(td)
            fake = FakeLibvirt({SYS: "defined", SES: "defined"})
            self._destroy(fake, overlay, iso)
            for uri in (SYS, SES):
                self.assertTrue(fake.verbs_at(uri, "undefine"), f"not torn down at {uri}: {fake.calls}")
            self.assertFalse(os.path.exists(overlay) or os.path.exists(iso))

    def test_an_unreachable_uri_is_not_absence(self):
        with tempfile.TemporaryDirectory() as td:
            overlay, iso = self._files(td)
            fake = FakeLibvirt({SYS: "unreachable", SES: "absent"})
            with self.assertRaises(SystemExit):
                self._destroy(fake, overlay, iso)
            self.assertTrue(os.path.exists(overlay) and os.path.exists(iso),
                            "an unreachable system URI read as absence and the disks were removed")

    def test_a_domain_that_survives_undefine_keeps_its_disks(self):
        with tempfile.TemporaryDirectory() as td:
            overlay, iso = self._files(td)
            fake = FakeLibvirt({SYS: "absent", SES: "defined"}, survive_undefine=True)
            with self.assertRaises(SystemExit):
                self._destroy(fake, overlay, iso)
            self.assertTrue(os.path.exists(overlay) and os.path.exists(iso))

    def test_absent_everywhere_is_the_control(self):
        with tempfile.TemporaryDirectory() as td:
            overlay, iso = self._files(td)
            fake = FakeLibvirt({SYS: "absent", SES: "absent"})
            self._destroy(fake, overlay, iso)
            self.assertFalse(os.path.exists(overlay) or os.path.exists(iso))
            self.assertFalse([c for c in fake.calls if c[3] in ("destroy", "undefine")])

    def test_failed_deploy_cleanup_uses_the_holding_uri_and_rechecks_both(self):
        with tempfile.TemporaryDirectory() as td:
            overlay, _ = self._files(td)
            fake = FakeLibvirt({SYS: "absent", SES: "defined"})
            with mock.patch.object(xd.subprocess, "run", side_effect=fake.run), _quiet():
                xd._cleanup_libvirt("fw1", overlay)
            self.assertTrue(fake.verbs_at(SES, "destroy"))
            self.assertFalse(os.path.exists(overlay))
            # Torn down at the system URI, but the session URI then cannot answer:
            # the overlay must stay.
            overlay2 = os.path.join(td, "fw2.qcow2")
            open(overlay2, "w").close()
            fake2 = FakeLibvirt({SYS: "defined", SES: "unreachable"})
            with mock.patch.object(xd.subprocess, "run", side_effect=fake2.run), _quiet():
                xd._cleanup_libvirt("fw1", overlay2)
            self.assertTrue(fake2.verbs_at(SYS, "destroy"))
            self.assertTrue(os.path.exists(overlay2), "an unreachable URI after teardown still removed the overlay")


class DeployNamesTheSystemURI9669(unittest.TestCase):
    def test_define_names_the_system_uri(self):
        seen = []
        with mock.patch.object(xd, "run_capture", side_effect=lambda argv, *a, **k: seen.append(list(argv)) or ""):
            xd._virsh_define(xd.Runner(dry=True), "fw1", "<domain/>")
        self.assertEqual(seen[0][:4], ["virsh", "-c", SYS, "define"], seen)

    def test_every_virsh_and_virt_install_argv_names_a_uri(self):
        src = (_HERE / "xpf-deploy.py").read_text()
        # The lookahead owns the whitespace: `\s*` outside it would backtrack to
        # zero width and let every scoped call match.
        unscoped_virsh = re.findall(r'\["virsh",(?!\s*"-c")', src)
        self.assertEqual(unscoped_virsh, [], "a virsh argv with no -c would speak to whichever URI the default resolves to")
        for m in re.finditer(r'\["virt-install",([^\]]*)', src):
            self.assertIn("--connect", m.group(1), "virt-install argv without --connect")

    def test_the_operator_docs_name_the_uris(self):
        doc = (_ROOT / "docs" / "deploy-quickstart.md").read_text()
        for want in ("qemu:///system", "qemu:///session", "#9669"):
            self.assertIn(want, doc)


if __name__ == "__main__":
    unittest.main()
