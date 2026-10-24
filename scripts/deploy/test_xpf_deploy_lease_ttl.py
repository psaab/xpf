#!/usr/bin/env python3
"""Unit tests for --lease-ttl positive-value validation (#5470).

The LANE-1/LANE-2 HA roll drivers (`kernel-roll` / `image-roll`) reserve BOTH
nodes with a lease whose deadline is `expires_at = now + --lease-ttl`, and the
acquire guard is a STRICT `now < expires`. Both `--lease-ttl` parsers used an
unconstrained `type=int`, so `--lease-ttl 0` (or negative) was accepted and
produced a lease that is already expired the instant it is written: the
cross-orchestrator mutex never holds, and two independent drivers could each
take a node's flock in turn and drain OPPOSITE HA nodes into a no-primary
forwarding outage.

The fix routes both `--lease-ttl` parsers through the shared `positive_int`
argparse `type=` callable, which rejects 0 / negative BEFORE any remote action
(argparse maps its `ArgumentTypeError` to a usage error + exit code 2). These
tests cover the pure callable and the end-to-end parser wiring for both roll
subcommands.

RED on revert: change either `--lease-ttl` back to `type=int` (or make
`positive_int` accept `n == 0`) and `test_kernel_roll_rejects_zero_ttl` /
`test_image_roll_rejects_zero_ttl` flip — the bad TTL sails past the parser and
dispatches into the roll handler instead of exiting non-zero.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "lib"))
from load_subject import load_subject  # noqa: E402

xpf_deploy = load_subject("xpf_deploy", Path(__file__).with_name("xpf-deploy.py"))


class PositiveIntTests(unittest.TestCase):
    """The pure argparse `type=` callable (#5470 crux)."""

    def test_accepts_positive(self):
        self.assertEqual(xpf_deploy.positive_int("1"), 1)
        self.assertEqual(xpf_deploy.positive_int("1800"), 1800)
        # Already an int (argparse passes strings, but be robust).
        self.assertEqual(xpf_deploy.positive_int(42), 42)

    def test_rejects_zero(self):
        with self.assertRaises(argparse.ArgumentTypeError):
            xpf_deploy.positive_int("0")

    def test_rejects_negative(self):
        with self.assertRaises(argparse.ArgumentTypeError):
            xpf_deploy.positive_int("-1")
        with self.assertRaises(argparse.ArgumentTypeError):
            xpf_deploy.positive_int("-1800")

    def test_rejects_non_integer(self):
        with self.assertRaises(argparse.ArgumentTypeError):
            xpf_deploy.positive_int("notanint")
        with self.assertRaises(argparse.ArgumentTypeError):
            xpf_deploy.positive_int("1.5")


def _run_main(argv):
    """Drive main() with a synthetic argv, swallowing argparse's stderr usage
    text. Returns whatever main() returns (or raises SystemExit on a parse
    error / usage exit)."""
    with mock.patch.object(sys, "argv", ["xpf-deploy.py", *argv]), \
            contextlib.redirect_stderr(io.StringIO()):
        return xpf_deploy.main()


_KERNEL_ROLL_BASE = [
    "kernel-roll", "--node", "fw0", "--node", "fw1", "--version", "6.99.0-cand",
]
_IMAGE_ROLL_BASE = [
    "image-roll", "--node", "fw0", "--node", "fw1", "--manifest", "x.manifest",
]


class LeaseTtlParserWiringTests(unittest.TestCase):
    """End-to-end: the parser rejects a non-positive --lease-ttl BEFORE any
    roll handler runs, and accepts a positive one (both roll subcommands)."""

    def test_kernel_roll_rejects_zero_ttl(self):
        with mock.patch.object(xpf_deploy, "cmd_kernel_roll") as handler:
            with self.assertRaises(SystemExit) as cm:
                _run_main(_KERNEL_ROLL_BASE + ["--lease-ttl", "0"])
        self.assertEqual(cm.exception.code, 2)
        handler.assert_not_called()   # rejected at parse time, no remote action

    def test_kernel_roll_rejects_negative_ttl(self):
        with mock.patch.object(xpf_deploy, "cmd_kernel_roll") as handler:
            with self.assertRaises(SystemExit) as cm:
                _run_main(_KERNEL_ROLL_BASE + ["--lease-ttl", "-5"])
        self.assertEqual(cm.exception.code, 2)
        handler.assert_not_called()

    def test_kernel_roll_accepts_positive_ttl(self):
        with mock.patch.object(xpf_deploy, "cmd_kernel_roll",
                               return_value=0) as handler:
            rc = _run_main(_KERNEL_ROLL_BASE + ["--lease-ttl", "60"])
        self.assertEqual(rc, 0)
        handler.assert_called_once()
        self.assertEqual(handler.call_args.args[0].lease_ttl, 60)

    def test_image_roll_rejects_zero_ttl(self):
        with mock.patch.object(xpf_deploy, "cmd_image_roll") as handler:
            with self.assertRaises(SystemExit) as cm:
                _run_main(_IMAGE_ROLL_BASE + ["--lease-ttl", "0"])
        self.assertEqual(cm.exception.code, 2)
        handler.assert_not_called()

    def test_image_roll_accepts_positive_ttl(self):
        with mock.patch.object(xpf_deploy, "cmd_image_roll",
                               return_value=0) as handler:
            rc = _run_main(_IMAGE_ROLL_BASE + ["--lease-ttl", "900"])
        self.assertEqual(rc, 0)
        handler.assert_called_once()
        self.assertEqual(handler.call_args.args[0].lease_ttl, 900)

    def test_default_ttl_still_accepted(self):
        # No --lease-ttl -> default 1800 flows through unchanged.
        with mock.patch.object(xpf_deploy, "cmd_kernel_roll",
                               return_value=0) as handler:
            _run_main(_KERNEL_ROLL_BASE)
        self.assertEqual(handler.call_args.args[0].lease_ttl, 1800)


if __name__ == "__main__":
    unittest.main()
