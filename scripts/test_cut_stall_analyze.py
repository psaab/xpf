#!/usr/bin/env python3
"""Unit tests for scripts/cut_stall_analyze.py.

Covers the #10023 offline cut-characterization analyzer: iperf3 text
(-P4 -i1) and line-delimited JSON, per-stream parsing, zero-gap merging,
cwnd-floor pin windows, SUM-vs-per-stream masking, ping -D gap/loss
analysis, and skew-corrected cut-budget math. Golden values come from the
#9486 loss-cluster evidence (docs/pr/9486/evidence/) and the surviving
Sep-13 journals.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

_SPEC = importlib.util.spec_from_file_location(
    "cut_stall_analyze", Path(__file__).with_name("cut_stall_analyze.py")
)
csa = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
sys.modules[_SPEC.name] = csa
_SPEC.loader.exec_module(csa)


IPERF_EXCERPT = """\
Connecting to host 172.16.80.200, port 5201
[  5] local 10.0.61.102 port 42056 connected to 172.16.80.200 port 5201
[  7] local 10.0.61.102 port 42060 connected to 172.16.80.200 port 5201
[ ID] Interval           Transfer     Bitrate         Retr  Cwnd
[  5]   0.00-1.00   sec  3.50 MBytes  29.3 Mbits/sec    5   91.9 KBytes
[  7]   0.00-1.00   sec  3.50 MBytes  29.3 Mbits/sec    5   93.3 KBytes
[SUM]   0.00-1.00   sec  7.00 MBytes  58.6 Mbits/sec   10
- - - - - - - - - - - - - - - - - - - - - - - - -
[  5]   1.00-2.00   sec  2.75 MBytes  23.1 Mbits/sec    0    112 KBytes
[  7]   1.00-2.00   sec  0.00 Bytes  0.00 bits/sec    1   1.41 KBytes
[SUM]   1.00-2.00   sec  2.75 MBytes  23.1 Mbits/sec    1
- - - - - - - - - - - - - - - - - - - - - - - - -
[  5]   2.00-3.00   sec  0.00 Bytes  0.00 bits/sec    0   1.41 KBytes
[  7]   2.00-3.00   sec  0.00 Bytes  0.00 bits/sec    0   1.41 KBytes
[SUM]   2.00-3.00   sec  0.00 Bytes  0.00 bits/sec    0
"""

PING_EXCERPT = """\
PING 172.16.80.200 (172.16.80.200) 56(84) bytes of data.
[1789329073.215054] 64 bytes from 172.16.80.200: icmp_seq=1 ttl=63 time=1.18 ms
[1789329073.616041] 64 bytes from 172.16.80.200: icmp_seq=3 ttl=63 time=0.365 ms
[1789329111.967961] 64 bytes from 172.16.80.200: icmp_seq=190 ttl=63 time=0.258 ms
[1789329112.591564] 64 bytes from 172.16.80.200: icmp_seq=193 ttl=63 time=11.9 ms
[1789329112.781169] 64 bytes from 172.16.80.200: icmp_seq=194 ttl=63 time=0.344 ms
"""
JSON_STREAM_EXCERPT = """\
{"event":"start","data":{"connected":[{"socket":5,"local_port":42056},{"socket":7,"local_port":42060}]}}
{"event":"interval","data":{"streams":[{"socket":5,"start":0.0,"end":0.1,"seconds":0.1,"bytes":1250000,"bits_per_second":100000000,"retransmits":0,"snd_cwnd":4096},{"socket":7,"start":0.0,"end":0.1,"seconds":0.1,"bytes":1250000,"bits_per_second":100000000,"retransmits":0,"snd_cwnd":4096}],"sum":{"start":0.0,"end":0.1,"seconds":0.1,"bytes":2500000,"bits_per_second":200000000,"retransmits":0}}}
{"event":"interval","data":{"streams":[{"socket":5,"start":0.1,"end":0.2,"seconds":0.1,"bytes":1250000,"bits_per_second":100000000,"retransmits":0,"snd_cwnd":4096},{"socket":7,"start":0.1,"end":0.2,"seconds":0.1,"bytes":0,"bits_per_second":0,"retransmits":1,"snd_cwnd":1443}],"sum":{"start":0.1,"end":0.2,"seconds":0.1,"bytes":1250000,"bits_per_second":100000000,"retransmits":1}}}
{"event":"interval","data":{"streams":[{"socket":5,"start":0.2,"end":0.3,"seconds":0.1,"bytes":0,"bits_per_second":0,"retransmits":0,"snd_cwnd":1443},{"socket":7,"start":0.2,"end":0.3,"seconds":0.1,"bytes":0,"bits_per_second":0,"retransmits":0,"snd_cwnd":1443}],"sum":{"start":0.2,"end":0.3,"seconds":0.1,"bytes":0,"bits_per_second":0,"retransmits":0}}}
"""
TEXT_COMPLETION_EXCERPT = """\
[  5]   0.00-1.00   sec  3.50 MBytes  29.3 Mbits/sec    5   91.9 KBytes
[SUM]   0.00-1.00  sec  3.50 MBytes  29.3 Mbits/sec    5             sender
[SUM]   0.00-1.00  sec  3.50 MBytes  29.3 Mbits/sec                  receiver
"""
SKEWED_JSON_STREAM_EXCERPT = """\
{"event":"interval","data":{"streams":[{"socket":5,"start":0.0,"end":0.1,"bytes":1250000,"bits_per_second":100000000,"retransmits":0,"snd_cwnd":4096},{"socket":7,"start":0.02,"end":0.12,"bytes":0,"bits_per_second":0,"retransmits":1,"snd_cwnd":1443}],"sum":{"start":0.0,"end":0.1,"bytes":1250000,"bits_per_second":100000000,"retransmits":0}}}
"""
PING_CONTIGUOUS_JITTER = """\
[1000.490000] 64 bytes from 172.16.80.200: icmp_seq=1 ttl=63 time=0.2 ms
[1001.010000] 64 bytes from 172.16.80.200: icmp_seq=2 ttl=63 time=0.2 ms
[1001.490000] 64 bytes from 172.16.80.200: icmp_seq=3 ttl=63 time=0.2 ms
[1002.010000] 64 bytes from 172.16.80.200: icmp_seq=4 ttl=63 time=0.2 ms
"""


def _tmp(text: str) -> Path:
    tmp = tempfile.NamedTemporaryFile("w", suffix=".log", delete=False)
    tmp.write(textwrap.dedent(text))
    tmp.close()
    return Path(tmp.name)


class IperfTextTests(unittest.TestCase):
    def test_header_ports(self) -> None:
        parsed = csa.parse_iperf_text(_tmp(IPERF_EXCERPT))
        self.assertEqual(parsed["ports"], {"5": 42056, "7": 42060})

    def test_interval_values_and_units(self) -> None:
        parsed = csa.parse_iperf_text(_tmp(IPERF_EXCERPT))
        first = parsed["streams"]["5"][0]
        self.assertEqual((first.start, first.end), (0.0, 1.0))
        self.assertAlmostEqual(first.bytes, 3.50 * 1024 * 1024)
        self.assertAlmostEqual(first.bps, 29.3e6)
        self.assertEqual(first.retr, 5)
        self.assertAlmostEqual(first.cwnd_bytes, 91.9 * 1024)

    def test_zero_line_parses(self) -> None:
        parsed = csa.parse_iperf_text(_tmp(IPERF_EXCERPT))
        zero = parsed["streams"]["7"][1]
        self.assertEqual(zero.bytes, 0.0)
        self.assertEqual(zero.bps, 0.0)
        self.assertEqual(zero.retr, 1)
        self.assertAlmostEqual(zero.cwnd_bytes, 1.41 * 1024)

    def test_sum_has_no_cwnd(self) -> None:
        parsed = csa.parse_iperf_text(_tmp(IPERF_EXCERPT))
        self.assertEqual(len(parsed["sum"]), 3)
        self.assertIsNone(parsed["sum"][0].cwnd_bytes)
        self.assertEqual(parsed["sum"][2].bps, 0.0)

    def test_gap_merging(self) -> None:
        parsed = csa.parse_iperf_text(_tmp(IPERF_EXCERPT))
        gaps7 = csa.stream_gaps(parsed["streams"]["7"])
        self.assertEqual(len(gaps7), 1)
        self.assertEqual((gaps7[0].start, gaps7[0].end, gaps7[0].duration), (1.0, 3.0, 2.0))
        gaps5 = csa.stream_gaps(parsed["streams"]["5"])
        self.assertEqual(len(gaps5), 1)
        self.assertEqual((gaps5[0].start, gaps5[0].end), (2.0, 3.0))

    def test_cwnd_pin_window(self) -> None:
        parsed = csa.parse_iperf_text(_tmp(IPERF_EXCERPT))
        pins = csa.cwnd_pin_windows(parsed["streams"]["7"], floor_bytes=1.41 * 1024 + 1)
        self.assertEqual(len(pins), 1)
        self.assertEqual((pins[0].start, pins[0].end, pins[0].intervals), (1.0, 3.0, 2))

    def test_sum_masking(self) -> None:
        parsed = csa.parse_iperf_text(_tmp(IPERF_EXCERPT))
        masking = csa.sum_masking(parsed["streams"], parsed["sum"])
        # t=1-2: stream 7 zero while SUM healthy -> masked. t=2-3: all zero.
        self.assertEqual(masking["masked_sec"], 1.0)
        self.assertEqual(masking["sum_zero_sec"], 1.0)
        self.assertEqual(masking["any_stream_zero_sec"], 2.0)


    def test_json_stream_parses_per_socket_fields(self) -> None:
        parsed = csa.parse_iperf_json_stream(_tmp(JSON_STREAM_EXCERPT))
        self.assertEqual(parsed["ports"], {"5": 42056, "7": 42060})
        gap = csa.stream_gaps(parsed["streams"]["7"])[0]
        self.assertAlmostEqual(gap.start, 0.1)
        self.assertAlmostEqual(gap.end, 0.3)
        self.assertEqual(csa.sum_masking(parsed["streams"], parsed["sum"])["masked_sec"], 0.1)

    def test_auto_dispatch_accepts_json_stream(self) -> None:
        parsed = csa.parse_iperf(_tmp(JSON_STREAM_EXCERPT))
        self.assertEqual(len(parsed["sum"]), 3)
        self.assertEqual(parsed["streams"]["7"][1].retr, 1)
    def test_text_completion_summaries_are_ignored(self) -> None:
        parsed = csa.parse_iperf_text(_tmp(TEXT_COMPLETION_EXCERPT))
        self.assertEqual(len(parsed["streams"]["5"]), 1)
        self.assertEqual(len(parsed["sum"]), 0)

    def test_completion_only_headerless_text_dispatches(self) -> None:
        parsed = csa.parse_iperf(_tmp(TEXT_COMPLETION_EXCERPT.splitlines()[1] + "\n"))
        self.assertEqual(parsed["streams"], {})
        self.assertEqual(parsed["sum"], [])

    def test_truncated_final_line_is_reported(self) -> None:
        path = _tmp(IPERF_EXCERPT.rstrip("\n") + "\n[  9] 271.00-272.0")
        parsed = csa.parse_iperf_text(path)
        self.assertEqual(parsed["warnings"], ["truncated_final_line"])

    def test_interior_malformed_interval_still_fails(self) -> None:
        path = _tmp("[  5] 0.00-1.00 sec 3.50 MBytes broken\n")
        with self.assertRaises(ValueError):
            csa.parse_iperf_text(path)

    def test_json_event_index_pairs_skewed_stream_rows(self) -> None:
        parsed = csa.parse_iperf_json_stream(_tmp(SKEWED_JSON_STREAM_EXCERPT))
        self.assertEqual(
            csa.sum_masking(parsed["streams"], parsed["sum"])["masked_sec"], 0.1
        )


class PingDTests(unittest.TestCase):
    def test_parse_replies(self) -> None:
        replies = csa.parse_ping_d(_tmp(PING_EXCERPT))
        self.assertEqual(len(replies), 5)
        self.assertEqual(replies[0].seq, 1)
        self.assertAlmostEqual(replies[0].epoch, 1789329073.215054)
        self.assertAlmostEqual(replies[3].rtt_ms, 11.9)

    def test_gap_detection(self) -> None:
        replies = csa.parse_ping_d(_tmp(PING_EXCERPT))
        replies = [reply for reply in replies if reply.seq >= 190]
        gaps = csa.ping_gaps(replies, gap_thresh_sec=0.5)
        # seq 190->193 is the cut-sized gap; the 0.2s probe schedule
        # makes ordinary one-lost-probe gaps stay below this threshold.
        self.assertEqual(len(gaps), 1)
        gap = gaps[0]
        self.assertEqual((gap.prev_seq, gap.next_seq, gap.missing), (190, 193, 2))
        self.assertAlmostEqual(gap.gap_sec, 0.623603, places=5)

    def test_loss_buckets(self) -> None:
        replies = csa.parse_ping_d(_tmp(PING_EXCERPT))
        buckets = csa.loss_buckets(replies, bucket_sec=1.0, interval_sec=0.2)
        first = buckets[0]
        # t=0-1s: 2 replies of 5 expected -> 60% loss.
        self.assertEqual(first.received, 2)
        self.assertEqual(first.expected, 5)
        self.assertAlmostEqual(first.loss_pct, 60.0)
    def test_sequence_gap_bucketing_avoids_jitter_false_loss(self) -> None:
        replies = csa.parse_ping_d(_tmp(PING_CONTIGUOUS_JITTER))
        buckets = csa.loss_buckets(replies, bucket_sec=1.0, interval_sec=0.1)
        self.assertTrue(buckets)
        self.assertTrue(all(bucket.loss_pct == 0.0 for bucket in buckets))
        self.assertTrue(all(bucket.expected == bucket.received for bucket in buckets))



class BudgetTests(unittest.TestCase):
    def test_skew_correct(self) -> None:
        # fw0 Sep-13 offset: host = fw0 + 125s.
        self.assertAlmostEqual(csa.apply_skew(1789329000.0, 125.0), 1789329125.0)

    def test_fw0_golden_budget(self) -> None:
        # fw0 primary-cut markers, node-local epoch-ms (Sep-13 journal).
        # Milestones: stop_to_proc 2.903 (starting-daemon line) vs 3.000
        # manager-started line elsewhere — distinct raw markers, not a drift.
        base = 1789329000000
        markers = [
            ("drain", base + 46000 + 347),
            ("stop", base + 49000 + 302),
            ("proc", base + 52000 + 205),
            ("armed", base + 54000 + 54),
            ("helper", base + 54000 + 840),
            ("sync_ready", base + 57000 + 211),
        ]
        budget = csa.cut_budget(markers)
        self.assertAlmostEqual(budget["stop_to_proc"], 2.903, places=3)
        self.assertAlmostEqual(budget["proc_to_helper"], 2.635, places=3)
        self.assertAlmostEqual(budget["helper_to_sync"], 2.371, places=3)
        self.assertAlmostEqual(budget["stop_to_sync"], 7.909, places=3)
        self.assertAlmostEqual(budget["drain_to_stop"], 2.955, places=3)
        self.assertAlmostEqual(budget["proc_to_armed"], 1.849, places=3)
        self.assertAlmostEqual(budget["armed_to_helper"], 0.786, places=3)


    def test_budget_requires_order(self) -> None:
        markers = [
            ("drain", 0),
            ("stop", 2),
            ("proc", 1),
            ("armed", 3),
            ("helper", 4),
            ("sync_ready", 5),
        ]
        with self.assertRaisesRegex(ValueError, "out of order"):
            csa.cut_budget(markers)

    def test_budget_requires_armed_marker(self) -> None:
        markers = [
            ("drain", 0),
            ("stop", 2),
            ("proc", 3),
            ("helper", 4),
            ("sync_ready", 5),
        ]
        with self.assertRaisesRegex(ValueError, "missing cut markers: armed"):
            csa.cut_budget(markers)


class CliTests(unittest.TestCase):
    def test_iperf_subcommand_json(self) -> None:
        path = _tmp(IPERF_EXCERPT)
        proc = subprocess.run(
            [sys.executable, str(Path(__file__).with_name("cut_stall_analyze.py")),
             "iperf", "--json", str(path)],
            capture_output=True, text=True, check=True,
        )
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["ports"], {"5": 42056, "7": 42060})
        self.assertEqual(payload["masking"]["masked_sec"], 1.0)
    def test_iperf_subcommand_json_stream(self) -> None:
        path = _tmp(JSON_STREAM_EXCERPT)
        proc = subprocess.run(
            [sys.executable, str(Path(__file__).with_name("cut_stall_analyze.py")),
             "iperf", "--json", str(path)],
            capture_output=True, text=True, check=True,
        )
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["ports"], {"5": 42056, "7": 42060})
        self.assertAlmostEqual(payload["streams"]["7"]["zero_sec"], 0.2)
        self.assertAlmostEqual(payload["masking"]["sum_zero_sec"], 0.1)
    def test_ping_cli_defaults_to_sampler_interval(self) -> None:
        path = _tmp(PING_CONTIGUOUS_JITTER)
        proc = subprocess.run(
            [sys.executable, str(Path(__file__).with_name("cut_stall_analyze.py")),
             "ping", "--json", str(path)],
            capture_output=True, text=True, check=True,
        )
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["replies"], 4)
        self.assertEqual(payload["gaps"], [])
        self.assertEqual(payload["max_loss"], 0.0)


if __name__ == "__main__":
    unittest.main()
