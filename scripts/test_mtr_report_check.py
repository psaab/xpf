#!/usr/bin/env python3
"""Unit tests for scripts/mtr_report_check.py.

Pin the classifier's handling of the #1303 silent-external-final-hop
shape (IPv6 warns, does not fail) and the false-pass cases both plan
reviewers flagged ((waiting for reply), %-truncation, integer loss,
unparseable loss). The original #1303 false-fail was a shell-level
`set -e` crash before the classifier ran (fixed by the `2>&1 || true`
capture in run_mtr_report), not a classifier defect; these tests cover
the classifier's target behavior, not that shell-level repro.
"""

from __future__ import annotations

import sys
import textwrap
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "lib"))
from load_subject import load_subject  # noqa: E402

mtr = load_subject("mtr_report_check", Path(__file__).with_name("mtr_report_check.py"))


def report(*lines: str) -> str:
    return textwrap.dedent("\n".join(lines))


# Canonical mtr --report hop line: "  N.|-- HOST   LOSS%  SNT  Last ..."
def hop(idx: int, host: str, loss: str) -> str:
    return f"  {idx}.|-- {host:<24} {loss}     1    0.1   0.1   0.1   0.1   0.0"


HEADER = "Start: 2026-05-29T00:00:00+0000\nHOST: fw0   Loss%   Snt   Last   Avg  Best  Wrst StDev"


class HopParseTests(unittest.TestCase):
    def test_hop_loss_pct_decimal_with_percent(self) -> None:
        self.assertEqual(mtr.hop_loss_pct(hop(1, "rtr.example", "0.0%")), 0.0)

    def test_hop_loss_pct_full_loss_with_percent(self) -> None:
        self.assertEqual(mtr.hop_loss_pct(hop(9, "rtr.example", "100.0%")), 100.0)

    def test_hop_loss_pct_truncated_no_percent_is_none(self) -> None:
        # mtr column-width truncation can drop the '%'. The loss anchor
        # then finds no '%' token -> None -> the classifier fails closed.
        self.assertIsNone(mtr.hop_loss_pct(hop(9, "rtr.example", "100.0")))

    def test_hop_loss_pct_integer_percent(self) -> None:
        self.assertEqual(mtr.hop_loss_pct(hop(9, "rtr.example", "100%")), 100.0)

    def test_hop_loss_pct_none_when_no_percent(self) -> None:
        self.assertIsNone(mtr.hop_loss_pct("  9.|-- (waiting for reply)"))

    def test_hop_loss_pct_ipv6_host_with_colons(self) -> None:
        # An IPv6 address host field must not confuse the loss anchor.
        self.assertEqual(
            mtr.hop_loss_pct(hop(2, "2001:559:8585:80::1", "0.0%")), 0.0
        )

    def test_hop_unresolved_question_marks(self) -> None:
        self.assertTrue(mtr.hop_unresolved(hop(9, "???", "100.0%")))

    def test_hop_unresolved_waiting_for_reply(self) -> None:
        self.assertTrue(mtr.hop_unresolved(hop(9, "(waiting for reply)", "100.0")))

    def test_hop_resolved_host_is_not_unresolved(self) -> None:
        self.assertFalse(mtr.hop_unresolved(hop(1, "rtr.example", "0.0%")))


class ClassifyIPv6Tests(unittest.TestCase):
    """allow_unresolved_destination=1 — public IPv6 trace is observability."""

    def test_silent_external_final_hop_warns_not_fails(self) -> None:
        # The #1303 shape: hops 1-8 resolved, hop 9 is the silent public
        # endpoint. The classifier must WARN (pass), not fail. (The
        # original #1303 false-fail was the SHELL-level `set -e` crash on
        # a non-zero `mtr` exit before the classifier ran; that is fixed
        # by the `2>&1 || true` capture in run_mtr_report, not here. The
        # post-#1301 classifier already warned on this shape — this test
        # pins that the extracted classifier preserves it.)
        lines = [HEADER] + [hop(i, f"rtr{i}.net", "0.0%") for i in range(1, 9)]
        lines.append(hop(9, "???", "100.0%"))
        ok, msg = mtr.classify_mtr_report("ipv6", report(*lines), True)
        self.assertTrue(ok, msg)
        self.assertIn("warning destination unresolved", msg)

    def test_all_upstream_unresolved_passes_with_warning(self) -> None:
        # Healthy path where every upstream rate-limits ICMPv6: this is
        # NOT gated here (the controlled ping/TTL/iperf3 legs gate it).
        lines = [HEADER, hop(1, "fw.lan", "0.0%")]
        lines += [hop(i, "???", "100.0%") for i in range(2, 10)]
        ok, msg = mtr.classify_mtr_report("ipv6", report(*lines), True)
        self.assertTrue(ok, msg)
        self.assertIn("warning", msg)

    def test_first_hop_unresolved_fails(self) -> None:
        lines = [HEADER, hop(1, "???", "100.0%"), hop(2, "rtr.net", "0.0%")]
        ok, msg = mtr.classify_mtr_report("ipv6", report(*lines), True)
        self.assertFalse(ok)
        self.assertIn("first hop unresolved", msg)

    def test_waiting_for_reply_final_hop_passes_with_warning(self) -> None:
        lines = [HEADER, hop(1, "fw.lan", "0.0%"), hop(2, "(waiting for reply)", "100.0")]
        ok, msg = mtr.classify_mtr_report("ipv6", report(*lines), True)
        self.assertTrue(ok, msg)
        self.assertIn("warning", msg)

    def test_no_hop_lines_passes_with_warning(self) -> None:
        ok, msg = mtr.classify_mtr_report("ipv6", report(HEADER), True)
        self.assertTrue(ok, msg)
        self.assertIn("warning produced no hop lines", msg)

    def test_full_healthy_path_passes_clean(self) -> None:
        lines = [HEADER] + [hop(i, f"rtr{i}.net", "0.0%") for i in range(1, 6)]
        ok, msg = mtr.classify_mtr_report("ipv6", report(*lines), True)
        self.assertTrue(ok, msg)
        self.assertEqual(msg, "ipv6 mtr: ok")


class ClassifyIPv4Tests(unittest.TestCase):
    """allow_unresolved_destination=0 — IPv4 final hop is a hard gate."""

    def test_healthy_final_hop_passes(self) -> None:
        lines = [HEADER] + [hop(i, f"rtr{i}.net", "0.0%") for i in range(1, 5)]
        lines.append(hop(5, "1.1.1.1", "0.0%"))
        ok, msg = mtr.classify_mtr_report("ipv4", report(*lines), False)
        self.assertTrue(ok, msg)
        self.assertEqual(msg, "ipv4 mtr: ok")

    def test_question_mark_final_hop_fails(self) -> None:
        lines = [HEADER, hop(1, "fw.lan", "0.0%"), hop(2, "???", "100.0%")]
        ok, msg = mtr.classify_mtr_report("ipv4", report(*lines), False)
        self.assertFalse(ok)
        self.assertIn("destination unresolved", msg)

    def test_waiting_for_reply_final_hop_fails(self) -> None:
        # The reviewers' false-pass: host field has spaces, loss '%' is
        # truncated. Must NOT pass.
        lines = [HEADER, hop(1, "fw.lan", "0.0%"), hop(2, "(waiting for reply)", "100.0")]
        ok, msg = mtr.classify_mtr_report("ipv4", report(*lines), False)
        self.assertFalse(ok)
        self.assertIn("destination unresolved", msg)

    def test_truncated_percent_full_loss_fails(self) -> None:
        # Named host, 100.0 loss without the '%' (column truncation).
        lines = [HEADER, hop(1, "fw.lan", "0.0%"), hop(2, "rtr.example", "100.0")]
        ok, msg = mtr.classify_mtr_report("ipv4", report(*lines), False)
        self.assertFalse(ok)

    def test_integer_full_loss_fails(self) -> None:
        lines = [HEADER, hop(1, "fw.lan", "0.0%"), hop(2, "1.1.1.1", "100%")]
        ok, msg = mtr.classify_mtr_report("ipv4", report(*lines), False)
        self.assertFalse(ok)

    def test_unparseable_loss_column_fails_closed(self) -> None:
        lines = [HEADER, hop(1, "fw.lan", "0.0%"), "  2.|-- 1.1.1.1   (no loss field)"]
        ok, msg = mtr.classify_mtr_report("ipv4", report(*lines), False)
        self.assertFalse(ok)

    def test_no_hop_lines_fails(self) -> None:
        ok, msg = mtr.classify_mtr_report("ipv4", report(HEADER), False)
        self.assertFalse(ok)
        self.assertIn("produced no hop lines", msg)


if __name__ == "__main__":
    unittest.main()
