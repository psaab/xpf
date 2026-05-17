import json
import os
import tempfile
import unittest

import mouse_latency_orchestrate as orch


def _write(tmpdir: str, name: str, content: str) -> str:
    path = os.path.join(tmpdir, name)
    with open(path, "w") as f:
        f.write(content)
    return path


class CheckCwndSettleTests(unittest.TestCase):
    def _make_args(self, txt_path: str, shaper: int):
        class A: pass
        a = A()
        a.iperf3_txt = txt_path
        a.shaper_bps = shaper
        a.window_rows = 3
        return a

    def test_settled(self):
        with tempfile.TemporaryDirectory() as t:
            txt = _write(t, "iperf3.txt", """\
[SUM]   1.00-2.00   sec  118 MBytes  990 Mbits/sec
[SUM]   2.00-3.00   sec  118 MBytes  995 Mbits/sec
[SUM]   3.00-4.00   sec  118 MBytes  988 Mbits/sec
""")
            self.assertEqual(orch.cmd_check_cwnd_settle(self._make_args(txt, 1_000_000_000)), 0)

    def test_not_settled_too_low(self):
        with tempfile.TemporaryDirectory() as t:
            txt = _write(t, "iperf3.txt", """\
[SUM]   1.00-2.00   sec  118 MBytes  500 Mbits/sec
[SUM]   2.00-3.00   sec  118 MBytes  600 Mbits/sec
[SUM]   3.00-4.00   sec  118 MBytes  650 Mbits/sec
""")
            self.assertEqual(orch.cmd_check_cwnd_settle(self._make_args(txt, 1_000_000_000)), 1)

    def test_not_settled_unstable(self):
        with tempfile.TemporaryDirectory() as t:
            txt = _write(t, "iperf3.txt", """\
[SUM]   1.00-2.00   sec  118 MBytes  900 Mbits/sec
[SUM]   2.00-3.00   sec  118 MBytes  990 Mbits/sec
[SUM]   3.00-4.00   sec  118 MBytes  700 Mbits/sec
""")
            self.assertEqual(orch.cmd_check_cwnd_settle(self._make_args(txt, 1_000_000_000)), 1)

    def test_no_sum_rows_yet(self):
        with tempfile.TemporaryDirectory() as t:
            txt = _write(t, "iperf3.txt", "Connecting to host 172.16.80.200, port 5201\n")
            self.assertEqual(orch.cmd_check_cwnd_settle(self._make_args(txt, 1_000_000_000)), 1)


class CwndSettleDiagnosticsTests(unittest.TestCase):
    def test_diagnostics_reports_aggregate_and_per_flow_window(self):
        text = """\
[  5]   0.00-1.00   sec  10.0 MBytes  80.0 Mbits/sec    1    100 KBytes
[  7]   0.00-1.00   sec  20.0 MBytes  160.0 Mbits/sec   0    200 KBytes
[SUM]   0.00-1.00   sec  30.0 MBytes  240.0 Mbits/sec
[  5]   1.00-2.00   sec  11.0 MBytes  88.0 Mbits/sec    2    110 KBytes
[  7]   1.00-2.00   sec  19.0 MBytes  152.0 Mbits/sec   0    190 KBytes
[SUM]   1.00-2.00   sec  30.0 MBytes  240.0 Mbits/sec
[  5]   2.00-3.00   sec  10.5 MBytes  84.0 Mbits/sec    3    120 KBytes
[  7]   2.00-3.00   sec  19.5 MBytes  156.0 Mbits/sec   0    180 KBytes
[SUM]   2.00-3.00   sec  30.0 MBytes  240.0 Mbits/sec
"""
        d = orch.build_cwnd_settle_diagnostics(
            text,
            300_000_000,
            elapsed_sec=20,
            sample_index=0,
        )
        self.assertTrue(d["settled"], d["reasons"])
        self.assertEqual(d["elapsed_sec"], 20)
        self.assertEqual(d["aggregate"]["window_bps"], [240_000_000] * 3)
        self.assertEqual(d["per_flow"]["flow_count"], 2)
        self.assertEqual(d["per_flow"]["retransmits_total"], 6)
        self.assertEqual(d["per_flow"]["mean_bps"]["min"], 84_000_000)
        self.assertEqual(d["per_flow"]["mean_bps"]["max"], 156_000_000)
        self.assertEqual(d["per_flow"]["cwnd_bytes"]["min"], 120 * 1024)
        self.assertEqual(d["per_flow"]["cwnd_bytes"]["max"], 180 * 1024)
        self.assertEqual(d["per_flow"]["slowest_streams"][0]["stream_id"], 5)

    def test_settle_diagnostics_writes_json_and_returns_status(self):
        with tempfile.TemporaryDirectory() as t:
            txt = _write(t, "iperf3.txt", """\
[SUM]   0.00-1.00   sec  10.0 MBytes  80.0 Mbits/sec
[SUM]   1.00-2.00   sec  30.0 MBytes  240.0 Mbits/sec
[SUM]   2.00-3.00   sec  10.0 MBytes  80.0 Mbits/sec
""")
            out_path = os.path.join(t, "cwnd-settle.json")

            class SettleArgs: pass
            args = SettleArgs()
            args.iperf3_txt = txt
            args.shaper_bps = 300_000_000
            args.window_rows = 3
            args.elapsed_sec = 20
            args.sample_index = 1
            args.out = out_path

            self.assertEqual(orch.cmd_settle_diagnostics(args), 1)
            with open(out_path) as f:
                payload = json.load(f)
            self.assertFalse(payload["settled"])
            self.assertEqual(payload["elapsed_sec"], 20)
            self.assertEqual(payload["sample_index"], 1)

    def test_diagnostics_explains_failed_thresholds(self):
        text = """\
[SUM]   0.00-1.00   sec  10.0 MBytes  80.0 Mbits/sec
[SUM]   1.00-2.00   sec  30.0 MBytes  240.0 Mbits/sec
[SUM]   2.00-3.00   sec  10.0 MBytes  80.0 Mbits/sec
"""
        d = orch.build_cwnd_settle_diagnostics(text, 300_000_000)
        self.assertFalse(d["settled"])
        self.assertTrue(any("aggregate-window-spread" in r for r in d["reasons"]))
        self.assertTrue(any("aggregate-too-low" in r for r in d["reasons"]))

    def test_diagnostics_requires_enough_sum_rows(self):
        d = orch.build_cwnd_settle_diagnostics(
            "[SUM]   0.00-1.00   sec  10.0 MBytes  80.0 Mbits/sec\n",
            300_000_000,
        )
        self.assertFalse(d["settled"])
        self.assertIn("insufficient-sum-rows", d["reasons"][0])


class CheckCollapseTests(unittest.TestCase):
    def _make_args(self, txt_path: str, shaper: int, n_rows: int = 0, skip_front: int = 0):
        class A: pass
        a = A()
        a.iperf3_txt = txt_path
        a.shaper_bps = shaper
        a.n_rows = n_rows
        a.skip_front = skip_front
        return a

    def test_settle_window_drops_ignored_with_skip_front(self):
        # R5 HIGH: the window must anchor on probe-start (skip_front=20)
        # not "last DURATION rows" (which would lose probe-start
        # collapse and include post-probe slack).
        with tempfile.TemporaryDirectory() as t:
            lines = []
            for i in range(20):
                lines.append(f"[SUM]   {i}.00-{i+1}.00   sec  20 MBytes  100 Mbits/sec")
            for i in range(20, 80):
                lines.append(f"[SUM]   {i}.00-{i+1}.00   sec  118 MBytes  990 Mbits/sec")
            for i in range(80, 90):
                lines.append(f"[SUM]   {i}.00-{i+1}.00   sec  20 MBytes  100 Mbits/sec")
            txt = _write(t, "iperf3.txt", "\n".join(lines) + "\n")
            # skip_front=20, n_rows=60 (probe window only) → no collapse
            self.assertEqual(
                orch.cmd_check_collapse(self._make_args(txt, 1_000_000_000, 60, 20)), 1
            )
            # skip_front=0 (full log) → collapse from warmup
            self.assertEqual(
                orch.cmd_check_collapse(self._make_args(txt, 1_000_000_000, 0, 0)), 0
            )

    def test_collapse_at_probe_start_caught_with_skip_front(self):
        # Settle is steady, but a 3-row dip happens RIGHT at probe start.
        # The R5 fix must not lose this.
        with tempfile.TemporaryDirectory() as t:
            lines = []
            for i in range(20):
                lines.append(f"[SUM]   {i}.00-{i+1}.00   sec  118 MBytes  990 Mbits/sec")
            for i in range(20, 23):
                lines.append(f"[SUM]   {i}.00-{i+1}.00   sec  20 MBytes  100 Mbits/sec")
            for i in range(23, 80):
                lines.append(f"[SUM]   {i}.00-{i+1}.00   sec  118 MBytes  990 Mbits/sec")
            for i in range(80, 90):
                lines.append(f"[SUM]   {i}.00-{i+1}.00   sec  118 MBytes  990 Mbits/sec")
            txt = _write(t, "iperf3.txt", "\n".join(lines) + "\n")
            self.assertEqual(
                orch.cmd_check_collapse(self._make_args(txt, 1_000_000_000, 60, 20)), 0
            )

    def test_steady_no_collapse(self):
        with tempfile.TemporaryDirectory() as t:
            lines = [f"[SUM]   {i}.00-{i+1}.00   sec  118 MBytes  990 Mbits/sec" for i in range(60)]
            txt = _write(t, "iperf3.txt", "\n".join(lines) + "\n")
            # Collapse detection returns 0 IF collapsed; 1 IF not.
            self.assertEqual(orch.cmd_check_collapse(self._make_args(txt, 1_000_000_000)), 1)

    def test_3_consecutive_drops_collapse(self):
        with tempfile.TemporaryDirectory() as t:
            lines = []
            for i in range(60):
                if 30 <= i <= 32:
                    lines.append(f"[SUM]   {i}.00-{i+1}.00   sec  20 MBytes  100 Mbits/sec")
                else:
                    lines.append(f"[SUM]   {i}.00-{i+1}.00   sec  118 MBytes  990 Mbits/sec")
            txt = _write(t, "iperf3.txt", "\n".join(lines) + "\n")
            self.assertEqual(orch.cmd_check_collapse(self._make_args(txt, 1_000_000_000)), 0)

    def test_2_drops_no_collapse(self):
        with tempfile.TemporaryDirectory() as t:
            lines = []
            for i in range(60):
                if 30 <= i <= 31:
                    lines.append(f"[SUM]   {i}.00-{i+1}.00   sec  20 MBytes  100 Mbits/sec")
                else:
                    lines.append(f"[SUM]   {i}.00-{i+1}.00   sec  118 MBytes  990 Mbits/sec")
            txt = _write(t, "iperf3.txt", "\n".join(lines) + "\n")
            self.assertEqual(orch.cmd_check_collapse(self._make_args(txt, 1_000_000_000)), 1)


class RGStateFlappedTests(unittest.TestCase):
    def _make_args(self, path: str):
        class A: pass
        a = A()
        a.poll_file = path
        return a

    def test_stable(self):
        with tempfile.TemporaryDirectory() as t:
            content = "\n".join([
                "1000\trg=1\tnode=0\tstate=primary",
                "1000\trg=1\tnode=1\tstate=secondary",
                "2000\trg=1\tnode=0\tstate=primary",
                "2000\trg=1\tnode=1\tstate=secondary",
                "3000\trg=1\tnode=0\tstate=primary",
                "3000\trg=1\tnode=1\tstate=secondary",
            ]) + "\n"
            poll = _write(t, "rg.txt", content)
            self.assertEqual(orch.cmd_rg_state_flapped(self._make_args(poll)), 1)

    def test_flap_detected(self):
        with tempfile.TemporaryDirectory() as t:
            content = "\n".join([
                "1000\trg=1\tnode=0\tstate=primary",
                "1000\trg=1\tnode=1\tstate=secondary",
                "2000\trg=1\tnode=0\tstate=secondary",
                "2000\trg=1\tnode=1\tstate=primary",
            ]) + "\n"
            poll = _write(t, "rg.txt", content)
            self.assertEqual(orch.cmd_rg_state_flapped(self._make_args(poll)), 0)

    def test_failover_failback_returns_to_initial(self):
        # 3 samples: initial → flapped → back to initial. ANY drift
        # invalidates, even if the end matches the start.
        with tempfile.TemporaryDirectory() as t:
            content = "\n".join([
                "1000\trg=1\tnode=0\tstate=primary",
                "1000\trg=1\tnode=1\tstate=secondary",
                "2000\trg=1\tnode=0\tstate=secondary",
                "2000\trg=1\tnode=1\tstate=primary",
                "3000\trg=1\tnode=0\tstate=primary",
                "3000\trg=1\tnode=1\tstate=secondary",
            ]) + "\n"
            poll = _write(t, "rg.txt", content)
            self.assertEqual(orch.cmd_rg_state_flapped(self._make_args(poll)), 0)

    def test_empty_poll_file_returns_2(self):
        # R1 HIGH 5: empty poll file is "no data", not "stable" — caller
        # must invalidate, not pass.
        with tempfile.TemporaryDirectory() as t:
            poll = _write(t, "rg.txt", "")
            self.assertEqual(orch.cmd_rg_state_flapped(self._make_args(poll)), 2)


if __name__ == "__main__":
    unittest.main()
