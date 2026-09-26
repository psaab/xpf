#!/usr/bin/env python3
"""Regression coverage for bounded image and Ubuntu-base downloads (#10853)."""

from __future__ import annotations

import hashlib
import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent.parent
_DIST = _ROOT / "scripts" / "dist"
_IMAGE = _ROOT / "scripts" / "image"
sys.path.insert(0, str(_DIST))
sys.path.insert(0, str(_IMAGE))

import sign  # noqa: E402

_SPEC = importlib.util.spec_from_file_location(
    "xpf_deploy", _HERE / "xpf-deploy.py")
deploy = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
_SPEC.loader.exec_module(deploy)

_BAKE_SPEC = importlib.util.spec_from_file_location(
    "bake", _ROOT / "scripts" / "image" / "bake.py")
bake = importlib.util.module_from_spec(_BAKE_SPEC)
assert _BAKE_SPEC.loader is not None
_BAKE_SPEC.loader.exec_module(bake)


class FetchURLPolicyTests(unittest.TestCase):
    def test_accepts_https_and_local_fixture_transports(self):
        for url in ("https://images.example/releases",
                    "http://127.0.0.1:8080/images",
                    "http://[::1]:8080/images",
                    "file:///tmp/xpf-images"):
            self.assertEqual(sign.validate_fetch_url(url), url)

    def test_rejects_insecure_or_structurally_ambiguous_bases(self):
        for url in ("http://mirror.example/images", "ftp://mirror.example/images",
                    "https://user@mirror.example/images",
                    "https://mirror.example/images?token=x",
                    "https://mirror.example/images#fragment",
                    "https://mirror.example:99999/images",
                    "file://remote.example/tmp/images", "https://bad host/images"):
            with self.subTest(url=url), self.assertRaises(sign.SignError):
                sign.validate_fetch_url(url)

    def test_curl_argv_has_transport_and_resource_bounds(self):
        argv = sign.curl_fetch_argv(
            "https://images.example/xpf.qcow2", "/tmp/xpf.qcow2",
            max_bytes=12345, max_time=67)
        self.assertIn("--proto", argv)
        self.assertEqual(argv[argv.index("--proto") + 1], "=https")
        self.assertEqual(argv[argv.index("--proto-redir") + 1], "=https")
        self.assertEqual(argv[argv.index("--max-time") + 1], "67")
        self.assertEqual(argv[argv.index("--max-filesize") + 1], "12345")
        self.assertEqual(argv[-1], "https://images.example/xpf.qcow2")

    def test_deploy_rejects_insecure_image_base_before_fetch(self):
        args = SimpleNamespace(
            image_url="http://mirror.example/images", channel="stable",
            dry_run=False)
        with mock.patch.object(deploy, "_download_to") as download, \
                self.assertRaises(SystemExit):
            deploy.cmd_fetch(args)
        download.assert_not_called()


@unittest.skipUnless(shutil.which("minisign"), "minisign is required")
class SignedManifestSizeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="xpf-10853-manifest."))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.pub = self.tmp / "img.pub"
        self.sec = self.tmp / "img.sec"
        subprocess.run(["minisign", "-G", "-W", "-p", str(self.pub),
                        "-s", str(self.sec)], check=True, capture_output=True)
        self.artifact = self.tmp / "xpf-1.2.3.qcow2"
        self.artifact.write_bytes(b"authenticated image bytes")
        self.sums = self.tmp / "xpf-1.2.3.SHA256SUMS"
        digest = hashlib.sha256(self.artifact.read_bytes()).hexdigest()
        sign.write_manifest(
            str(self.sums), [str(self.artifact)],
            recorded_hashes={self.artifact.name: digest},
            recorded_sizes={self.artifact.name: self.artifact.stat().st_size})
        sign.sign_manifest(str(self.sums), str(self.sec))

    def test_signature_authenticates_size_and_sha256sum_stays_compatible(self):
        verified = sign.verify_manifest_map_with_sizes(
            str(self.sums), str(self.sums) + ".minisig", str(self.pub))
        self.assertEqual(verified[self.artifact.name],
                         (hashlib.sha256(self.artifact.read_bytes()).hexdigest(),
                          self.artifact.stat().st_size))
        self.assertEqual(sign.parse_manifest(str(self.sums))[self.artifact.name],
                         verified[self.artifact.name][0])
        checked = subprocess.run(["sha256sum", "-c", self.sums.name],
                                 cwd=self.tmp, capture_output=True, text=True)
        self.assertEqual(checked.returncode, 0, checked.stderr)
        self.assertIn(f"{self.artifact.name}: OK", checked.stdout)

    def test_fetch_uses_authenticated_size_as_preverification_curl_cap(self):
        out = self.tmp / "out"
        state = self.tmp / "state"
        args = SimpleNamespace(
            image_url=self.tmp.as_uri(), version="1.2.3", channel="stable",
            out=str(out), allow_rollback=True, qcow2_only=True,
            dry_run=False, pubkey=[str(self.pub)], allow_unvalidated=False,
            no_import=True, install_libvirt=False, alias="xpf-appliance")
        calls = []
        real_download = deploy._download_to

        def record_download(url, dst, workdir, **kwargs):
            calls.append((os.path.basename(dst), kwargs.get("max_bytes")))
            return real_download(url, dst, workdir, **kwargs)

        with mock.patch.object(deploy, "_download_to",
                               side_effect=record_download), \
                mock.patch.dict(os.environ, {"XDG_STATE_HOME": str(state)}):
            self.assertEqual(deploy.cmd_fetch(args), 0)
        self.assertIn((self.artifact.name, self.artifact.stat().st_size), calls)

    def test_resigning_preserves_signed_size_bounds(self):
        recorded = sign.parse_manifest(str(self.sums))
        sign.write_and_sign_manifest(
            str(self.sums), [str(self.artifact)], str(self.sec),
            recorded_hashes=recorded)
        verified = sign.verify_manifest_map_with_sizes(
            str(self.sums), str(self.sums) + ".minisig", str(self.pub))
        self.assertEqual(verified[self.artifact.name][1],
                         self.artifact.stat().st_size)

    def test_modified_signed_size_field_is_rejected(self):
        original = self.sums.read_text()
        self.sums.write_text(original.replace(
            f"# size {self.artifact.name} {self.artifact.stat().st_size}",
            f"# size {self.artifact.name} {self.artifact.stat().st_size + 1}"))
        with self.assertRaises(sign.SignError):
            sign.verify_manifest_map_with_sizes(
                str(self.sums), str(self.sums) + ".minisig", str(self.pub))


@unittest.skipUnless(shutil.which("curl"), "curl is required")
class DownloadCeilingTests(unittest.TestCase):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            if self.path in ("/oversize", "/chunked",
                             "/base/ubuntu-26.04-server-cloudimg-amd64.img"):
                body = b"x" * 4096
                self.send_response(200)
                if self.path == "/chunked":
                    # Omit Content-Length: curl --max-filesize alone cannot
                    # bound this chunked response; the child file-size limit
                    # must stop it before the temp grows past the cap.
                    self.send_header("Transfer-Encoding", "chunked")
                else:
                    self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                try:
                    if self.path == "/chunked":
                        self.wfile.write(
                            f"{len(body):X}\r\n".encode() + body + b"\r\n0\r\n\r\n")
                    else:
                        self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError):
                    pass
                return
            if self.path == "/redirect":
                self.send_response(302)
                self.send_header("Location", "/oversize")
                self.end_headers()
                return
            if self.path in ("/slow", "/releases/"):
                body = b"slow response"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                time.sleep(2)
                try:
                    self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError):
                    pass
                return
            self.send_error(404)

        def log_message(self, *_args):
            pass

    class QuietThreadingHTTPServer(ThreadingHTTPServer):
        def handle_error(self, _request, _client_address):
            pass

    @classmethod
    def setUpClass(cls):
        cls.server = cls.QuietThreadingHTTPServer(("127.0.0.1", 0), cls.Handler)
        cls.server.daemon_threads = True
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def test_oversized_http_response_is_refused_and_temp_removed(self):
        with tempfile.TemporaryDirectory(prefix="xpf-10853-size.") as temp:
            dst = os.path.join(temp, "xpf-1.2.3.qcow2")
            with self.assertRaises(SystemExit):
                deploy._download_to(self.base + "/oversize", dst, temp,
                                    max_bytes=32, max_time=5)
            self.assertFalse(os.path.exists(dst))
            self.assertEqual(os.listdir(temp), [])

    def test_unknown_length_response_is_hard_capped(self):
        with tempfile.TemporaryDirectory(prefix="xpf-10853-chunked.") as temp:
            dst = os.path.join(temp, "xpf-1.2.3.qcow2")
            with self.assertRaises(SystemExit):
                deploy._download_to(self.base + "/chunked", dst, temp,
                                    max_bytes=32, max_time=5)
            self.assertFalse(os.path.exists(dst))
            self.assertEqual(os.listdir(temp), [])

    def test_http_redirect_cannot_downgrade_protocol(self):
        with tempfile.TemporaryDirectory(prefix="xpf-10853-redirect.") as temp:
            dst = os.path.join(temp, "latest.json")
            with self.assertRaises(SystemExit):
                deploy._download_to(self.base + "/redirect", dst, temp,
                                    max_bytes=1024, max_time=5)
            self.assertFalse(os.path.exists(dst))
            self.assertEqual(os.listdir(temp), [])

    def test_slow_http_response_is_wall_clock_bounded(self):
        with tempfile.TemporaryDirectory(prefix="xpf-10853-time.") as temp:
            dst = os.path.join(temp, "latest.json")
            started = time.monotonic()
            with self.assertRaises(SystemExit):
                deploy._download_to(self.base + "/slow", dst, temp,
                                    max_bytes=1024, max_time=1)
            elapsed = time.monotonic() - started
            self.assertLess(elapsed, 4.0)
            self.assertFalse(os.path.exists(dst))
            self.assertEqual(os.listdir(temp), [])

    def test_bake_release_listing_is_wall_clock_bounded(self):
        env = {
            "XPF_BASE_RELEASE": "",
            "XPF_UBUNTU_AUTODISCOVER": "1",
            "XPF_UBUNTU_RELEASES_URL": self.base + "/releases",
        }
        with mock.patch.dict(os.environ, env), \
                mock.patch.object(sign, "FETCH_MAX_BYTES_SMALL", 1024), \
                mock.patch.object(sign, "FETCH_MAX_TIME_SMALL_S", 1):
            started = time.monotonic()
            with self.assertRaises(subprocess.CalledProcessError):
                bake.discover_base_release()
        self.assertLess(time.monotonic() - started, 4.0)

    def test_bake_base_image_is_capped_and_partial_removed(self):
        env = {
            "XPF_BASE_RELEASE": "26.04",
            "XPF_BASE_URL": self.base + "/base",
            "XPF_UBUNTU_RELEASES_URL":
                "https://cloud-images.ubuntu.com/releases",
        }
        with tempfile.TemporaryDirectory(prefix="xpf-10853-bake.") as temp:
            cache_dir = Path(temp) / "cache"
            work_dir = Path(temp) / "work"
            cache_dir.mkdir()
            work_dir.mkdir()
            with mock.patch.dict(os.environ, env), \
                    mock.patch.object(
                        sign, "FETCH_MAX_BYTES_BASE_IMAGE", 32), \
                    self.assertRaises(subprocess.CalledProcessError):
                bake.fetch_base(str(cache_dir), str(work_dir))
            self.assertEqual(list(cache_dir.iterdir()), [])
            self.assertEqual(list(work_dir.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
