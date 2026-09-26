#!/usr/bin/env python3
"""The signed channel pointer has a consumer (#6504).

#1924's distribution mechanism produces, signs and publish-gates a per-channel
`latest.json` freshness pointer, and `docs/distribution.md` named "our scripts
(validate.py, xpf-deploy.py fetch)" as its consumers — but **no script read
it**. `fetch` made `--version` mandatory, so a day-zero operator could not say
"give me current stable" without already knowing a version string, and the
signed pointer was a dead letter.

`fetch` with no `--version` now resolves it from `<base>/<channel>/latest.json`,
minisign-verified against the same pinned image pubkey that authenticates every
artifact. What the tests below pin is the boundary: an operator who typed no
version is trusting that pointer completely, so every step is fail-closed and
the string it yields is treated as UNTRUSTED INPUT even though it arrived
inside a valid signature.

That last point is the one worth stating. A verified signature says WHO wrote
the bytes, not that the bytes are safe to interpolate into a filesystem path,
and not that they belong at the URL they were served from. So a signed pointer
naming `../../etc/cron.d/x` is still refused by the #5992 filename validation,
and a signed `stable` pointer served at `edge/latest.json` is still refused —
both verify perfectly, because the same key signs every channel.

Hermetic: a throwaway minisign keypair, a `file://` base URL, no network.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent.parent
sys.path.insert(0, str(_ROOT / "scripts" / "dist"))

_SPEC = importlib.util.spec_from_file_location(
    "xpf_deploy", _HERE / "xpf-deploy.py")
deploy = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
_SPEC.loader.exec_module(deploy)

import sign  # noqa: E402

VER = "1.2.3-4-gabcdef"


class ValidateChannelTests(unittest.TestCase):
    """The channel is interpolated into a URL PATH and is the watermark bucket
    key, so it gets the same fail-closed treatment as a version."""

    def _rejects(self, value):
        with self.assertRaises(SystemExit, msg=f"accepted {value!r}"):
            deploy.validate_channel(value)

    def test_ordinary_channels_pass(self):
        for ok in ("stable", "edge", "beta-2", "v1.0", "a_b"):
            self.assertEqual(deploy.validate_channel(ok), ok)

    def test_path_traversal_is_refused(self):
        for bad in ("../../evil", "..", "a/../b", "stable/..", "./x"):
            self._rejects(bad)

    def test_a_slash_is_refused(self):
        for bad in ("a/b", "/abs", "a\\b"):
            self._rejects(bad)

    def test_empty_and_non_string_are_refused(self):
        for bad in ("", None, 7):
            self._rejects(bad)

    def test_a_leading_dash_or_dot_is_refused(self):
        for bad in ("-x", ".hidden"):
            self._rejects(bad)


@unittest.skipUnless(shutil.which("minisign") and shutil.which("curl"),
                     "minisign and curl are required")
class ResolveChannelVersionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="xpf-6504."))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.pub = self.tmp / "img.pub"
        self.sec = self.tmp / "img.sec"
        subprocess.run(["minisign", "-G", "-W", "-p", str(self.pub),
                        "-s", str(self.sec)], check=True, capture_output=True)
        self._saved_env = {name: os.environ.get(name) for name in (
            "XPF_IMAGE_PUBKEY", "XDG_STATE_HOME")}
        os.environ["XPF_IMAGE_PUBKEY"] = str(self.pub)
        self.state = self.tmp / "empty-state"
        os.environ["XDG_STATE_HOME"] = str(self.state)
        self.addCleanup(self._restore_env)
        self.host = self.tmp / "host"
        (self.host / "stable").mkdir(parents=True)
        self.base = self.host.as_uri()

    def _restore_env(self):
        for name, value in self._saved_env.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value

    def _publish_pointer(self, channel="stable", body=None, sign_it=True,
                         raw=None):
        d = self.host / channel
        d.mkdir(parents=True, exist_ok=True)
        p = d / "latest.json"
        if raw is not None:
            p.write_text(raw)
        else:
            doc = {"channel": channel, "version": VER,
                   "manifest": f"xpf-{VER}.SHA256SUMS",
                   "date": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
            if body:
                doc.update(body)
            for k, v in list(doc.items()):
                if v is None:
                    del doc[k]
            p.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")
        if sign_it:
            sign.sign_manifest(str(p), str(self.sec), comment="6504 test")
        return p

    def _resolve(self, channel="stable"):
        return deploy._resolve_channel_version(self.base, channel, sign)

    def _refused(self, channel="stable"):
        with self.assertRaises(SystemExit) as ctx:
            self._resolve(channel)
        self.assertNotEqual(ctx.exception.code, 0)
        return str(ctx.exception.code)

    # ── the happy path ──
    def test_a_signed_pointer_yields_its_version(self):
        self._publish_pointer()
        self.assertEqual(self._resolve(), VER)

    def test_each_channel_resolves_its_own_pointer(self):
        self._publish_pointer("stable")
        self._publish_pointer("edge", body={"channel": "edge",
                                            "version": "9.9.9"})
        self.assertEqual(self._resolve("stable"), VER)
        self.assertEqual(self._resolve("edge"), "9.9.9")

    # ── fail-closed ──
    def test_replayed_old_pointer_fails_on_empty_state_home(self):
        self._publish_pointer(body={"date": "1999-01-01T00:00:00Z"})
        args = argparse.Namespace(
            version=None, image_url=self.base, out=str(self.tmp / "out"),
            alias=None, channel="stable", allow_rollback=False,
            allow_unvalidated=False, qcow2_only=True,
            install_libvirt=False, no_import=True, dry_run=False, pubkey=None)
        with self.assertRaises(SystemExit) as caught:
            deploy.cmd_fetch(args)
        self.assertIn("older than the 90-day freshness window",
                      str(caught.exception))
        self.assertFalse(self.state.exists(),
                         "replayed pointer was not rejected before state setup")


    def test_an_absent_pointer_is_refused(self):
        self.assertIn("download failed", self._refused())

    def test_a_pointer_with_no_signature_is_refused(self):
        self._publish_pointer(sign_it=False)
        self.assertIn("download failed", self._refused())

    def test_a_pointer_signed_by_the_WRONG_key_is_refused(self):
        other_pub = self.tmp / "other.pub"
        other_sec = self.tmp / "other.sec"
        subprocess.run(["minisign", "-G", "-W", "-p", str(other_pub),
                        "-s", str(other_sec)], check=True, capture_output=True)
        p = self._publish_pointer(sign_it=False)
        sign.sign_manifest(str(p), str(other_sec), comment="wrong key")
        self.assertIn("FAILED signature verification", self._refused())

    def test_a_tampered_pointer_is_refused(self):
        p = self._publish_pointer()
        # Signature stays; bytes change. This is the stale-mirror / swapped-
        # object case, and it must not resolve.
        p.write_text(p.read_text().replace(VER, "6.6.6"))
        self.assertIn("FAILED signature verification", self._refused())

    def test_tampering_with_the_unused_manifest_field_is_refused(self):
        p = self._publish_pointer()
        p.write_text(p.read_text().replace(
            f"xpf-{VER}.SHA256SUMS", "xpf-tampered.SHA256SUMS"))
        self.assertIn("FAILED signature verification", self._refused())

    def test_a_signed_pointer_that_is_not_json_is_refused(self):
        self._publish_pointer(raw="not json at all\n")
        self.assertIn("not valid JSON", self._refused())

    def test_a_signed_json_ARRAY_is_refused(self):
        self._publish_pointer(raw='["stable", "1.0"]\n')
        self.assertIn("not a JSON object", self._refused())

    def test_a_signed_pointer_with_no_version_is_refused(self):
        self._publish_pointer(body={"version": None})
        self.assertIn("names no version", self._refused())

    def test_a_signed_pointer_with_an_empty_version_is_refused(self):
        self._publish_pointer(body={"version": ""})
        self.assertIn("names no version", self._refused())

    # ── a valid signature is not a safety property ──
    def test_a_SIGNED_path_escaping_version_is_still_refused(self):
        # The signature says WHO wrote the bytes, not that they are safe to
        # interpolate into `xpf-<ver>.qcow2`. #5992's validation runs on the
        # pointer's string exactly as it does on an operator's --version.
        for bad in ("../../etc/cron.d/x", "/abs/path", "a/b", "..",
                    "-leading-dash", "with space"):
            self._publish_pointer(body={"version": bad})
            with self.assertRaises(SystemExit, msg=f"accepted {bad!r}"):
                self._resolve()

    def test_a_pointer_for_ANOTHER_channel_is_refused(self):
        # The same key signs every channel, so a stable pointer served at
        # edge/latest.json verifies perfectly. Only the channel field catches
        # a mis-sync or a swapped object.
        (self.host / "edge").mkdir(parents=True, exist_ok=True)
        self._publish_pointer("edge", body={"channel": "stable"})
        self.assertIn("says it is for channel", self._refused("edge"))

    def test_a_pointer_without_a_channel_field_is_accepted(self):
        # Absence is not disagreement: an older pointer that predates the
        # field must not be refused for lacking it.
        self._publish_pointer(body={"channel": None})
        self.assertEqual(self._resolve(), VER)

    def test_nothing_unverified_is_left_behind_in_the_cwd(self):
        # The pointer and its signature are downloaded into a PRIVATE temp
        # dir, never into --out: unverified bytes must not land in the
        # operator's artifact directory under a predictable name.
        self._publish_pointer()
        before = set(os.listdir(self.tmp))
        self._resolve()
        self.assertEqual(set(os.listdir(self.tmp)), before)


class WiringTests(unittest.TestCase):
    """A resolver nothing calls resolves nothing, and an argparse that still
    demands --version can never reach it."""

    SRC = (_HERE / "xpf-deploy.py").read_text(encoding="utf-8")

    def test_fetch_no_longer_requires_a_version(self):
        self.assertNotIn('sub.add_argument("--version", required=True)', self.SRC)
        self.assertIn('sub.add_argument("--version")', self.SRC)

    def test_cmd_fetch_resolves_the_channel_when_no_version_is_given(self):
        body = self.SRC.split("def cmd_fetch(args):", 1)[1] \
                       .split("\ndef ", 1)[0]
        self.assertIn("if args.version is None:", body)
        self.assertIn("_resolve_channel_version(", body)

    def test_cmd_fetch_validates_the_channel(self):
        body = self.SRC.split("def cmd_fetch(args):", 1)[1] \
                       .split("\ndef ", 1)[0]
        self.assertIn("validate_channel(args.channel)", body)

    def test_the_resolved_version_still_goes_through_validate_version(self):
        # The resolved string must not bypass the #5992 filename gate that an
        # operator-supplied --version passes through.
        body = self.SRC.split("def cmd_fetch(args):", 1)[1] \
                       .split("\ndef ", 1)[0]
        self.assertLess(body.index("_resolve_channel_version("),
                        body.index('validate_version(args.version, "--version")'))


class DocClaimTests(unittest.TestCase):
    """The trust-model table is a set of CLAIMS about which scripts consume
    which signed artifact, and it was wrong in both directions: it named
    `validate.py` as a `latest.json` consumer (it has never read one) while no
    script read the pointer at all.

    Fixing the code makes half the sentence true; the guard is what keeps the
    other half honest. Every script the table names as a consumer of a given
    artifact must actually reference it.
    """

    DOC = (_ROOT / "docs" / "distribution.md").read_text(encoding="utf-8")

    def _row(self, needle):
        rows = [ln for ln in self.DOC.splitlines()
                if ln.startswith("|") and needle in ln]
        self.assertEqual(len(rows), 1,
                         f"expected exactly one trust-model row mentioning "
                         f"{needle!r}, found {len(rows)}")
        return rows[0]

    def test_the_table_has_a_latest_json_row(self):
        # Vacuity guard: every assertion below reads this row.
        self.assertIn("latest.json", self._row("latest.json"))

    def test_validate_py_is_not_claimed_as_a_latest_json_consumer(self):
        # It never was one. The claim survived because nobody re-read it after
        # the mechanism landed.
        self.assertNotIn("validate.py", self._row("latest.json"))
        self.assertNotIn("latest.json",
                         (_ROOT / "scripts" / "image" / "validate.py")
                         .read_text(encoding="utf-8"),
                         "validate.py now references latest.json — the doc row "
                         "that excludes it has gone stale in the other "
                         "direction")

    def test_every_script_named_as_a_latest_json_consumer_reads_one(self):
        row = self._row("latest.json")
        named = {
            "xpf-deploy.py": _ROOT / "scripts" / "deploy" / "xpf-deploy.py",
            "publish.py": _ROOT / "scripts" / "dist" / "publish.py",
        }
        claimed = [n for n in named if n in row]
        self.assertTrue(claimed, "the row names no script consumer — vacuous")
        for n in claimed:
            self.assertIn("latest.json", named[n].read_text(encoding="utf-8"),
                          f"the trust model claims {n} consumes latest.json, "
                          "but it never references one")


if __name__ == "__main__":
    unittest.main()
