import os
import subprocess
import sys
import tempfile
import unittest

from iperf3_sum_parse import (
    failover_interval_verdict,
    failover_stream_verdict,
    parse_interval_line,
    parse_sum_bps,
    parse_sum_line,
)


class ParseSumLineTests(unittest.TestCase):
    def test_per_second_mbits(self):
        line = "[SUM]   3.00-4.00   sec  118 MBytes  990 Mbits/sec                  "
        self.assertEqual(parse_sum_bps(line), 990_000_000)

    def test_per_second_gbits(self):
        line = "[SUM]   0.00-1.00   sec  1.16 GBytes  9.95 Gbits/sec"
        rate_v, rate_bps = parse_sum_line(line)
        self.assertEqual(rate_v, 9.95)
        self.assertEqual(rate_bps, 9_950_000_000)

    def test_per_second_kbits(self):
        line = "[SUM]   1.00-2.00   sec  20.0 KBytes  164 Kbits/sec"
        self.assertEqual(parse_sum_bps(line), 164_000)

    def test_final_summary_receiver(self):
        line = "[SUM]   0.00-60.00  sec  6.96 GBytes   996 Mbits/sec                  receiver"
        self.assertEqual(parse_sum_bps(line), 996_000_000)

    def test_final_summary_sender(self):
        line = "[SUM]   0.00-60.00  sec  6.96 GBytes   996 Mbits/sec    1234             sender"
        self.assertEqual(parse_sum_bps(line), 996_000_000)

    def test_per_stream_does_not_match(self):
        line = "[  5]   3.00-4.00   sec  118 MBytes  990 Mbits/sec"
        self.assertIsNone(parse_sum_bps(line))

    def test_empty_line(self):
        self.assertIsNone(parse_sum_bps(""))

    def test_non_sum_text(self):
        self.assertIsNone(parse_sum_bps("Connecting to host 172.16.80.200, port 5201"))

    def test_partial_sum_line(self):
        # Truncated mid-line should not produce garbage.
        self.assertIsNone(parse_sum_bps("[SUM]   3.00-4.00   sec  118 MBytes"))

    def test_unit_prefix_lowercase(self):
        line = "[SUM]   1.00-2.00   sec  118 mbytes  990 mbits/sec"
        # Regex is case-insensitive on the keyword, but unit prefix
        # is uppercased internally — verify lowercase-m is treated
        # as Mega.
        self.assertEqual(parse_sum_bps(line), 990_000_000)

    def test_bare_bits_per_sec(self):
        # No unit prefix at all (bits/sec exact).
        line = "[SUM]   1.00-2.00   sec  100 Bytes  800 bits/sec"
        self.assertEqual(parse_sum_bps(line), 800)

    def test_fractional_rate_value(self):
        line = "[SUM]   1.00-2.00   sec  118 MBytes  9.95 Gbits/sec"
        self.assertEqual(parse_sum_bps(line), 9_950_000_000)


class FailoverTelemetryTests(unittest.TestCase):
    @staticmethod
    def log(
        streams=range(5, 13),
        dead_after_crash=(),
        delayed_streams=(),
        outage=(),
        duration=32,
    ):
        lines = []
        streams = tuple(streams)
        dead_after_crash = set(dead_after_crash)
        delayed_streams = set(delayed_streams)
        outage = set(outage)
        sum_rates = []
        for second in range(duration):
            live_streams = [
                stream for stream in streams
                if not (stream in dead_after_crash and second >= 10)
                and not (stream in delayed_streams and 12 <= second < 15)
            ]
            interval_dipped = second in outage or second in (10, 11, 20, 21)
            sum_gbps = (
                0.0 if interval_dipped
                else 23.4 * len(live_streams) / 8
            )
            sum_rates.append(sum_gbps)
            sum_rate = (
                "0.00 bits/sec"
                if sum_gbps == 0
                else f"{sum_gbps:.2f} Gbits/sec"
            )
            sum_amount = (
                "0.00 Bytes" if sum_gbps == 0 else f"{sum_gbps / 8:.3f} GBytes"
            )
            lines.append(
                f"[SUM] {second:.2f}-{second + 1:.2f} sec {sum_amount} {sum_rate}"
            )
            for stream in streams:
                live = not interval_dipped
                if stream in dead_after_crash and second >= 10:
                    live = False
                if stream in delayed_streams and 12 <= second < 15:
                    live = False
                rate = "2.925 Gbits/sec" if live else "0.00 bits/sec"
                lines.append(
                    f"[{stream:3d}] {second:.2f}-{second + 1:.2f} sec "
                    f"{'365.625 MBytes' if live else '0.00 Bytes'} {rate}"
                )
        average_gbps = sum(sum_rates) / duration
        lines.append(
            f"[SUM] 0.00-{duration:.2f} sec {average_gbps * duration / 8:.2f} GBytes "
            f"{average_gbps:.2f} Gbits/sec sender"
        )
        return "\n".join(lines)

    def test_interval_parser_reads_aggregate_and_stream_id(self):
        self.assertEqual(
            parse_interval_line("[SUM] 3.00-4.00 sec 118 MBytes 990 Mbits/sec"),
            (None, 3.0, 4.0, 990_000_000),
        )
        self.assertEqual(
            parse_interval_line("[  5] 3.00-4.00 sec 118 MBytes 990 Mbits/sec"),
            (5, 3.0, 4.0, 990_000_000),
        )

    def test_short_failover_interval_dips_are_allowed(self):
        ok, _ = failover_interval_verdict(self.log(outage=(10, 11, 20, 21)))
        self.assertTrue(ok)

    def test_final_aggregate_without_interval_rows_fails_closed(self):
        ok, reason = failover_interval_verdict(
            "[SUM] 0.00-120.00 sec 350 GBytes 23.4 Gbits/sec sender"
        )
        self.assertFalse(ok)
        self.assertIn("no per-second", reason)

    def test_interval_telemetry_gap_fails_closed(self):
        text = (
            "[SUM] 0.00-1.00 sec 2.93 GBytes 23.4 Gbits/sec\n"
            "[SUM] 2.00-3.00 sec 2.93 GBytes 23.4 Gbits/sec"
        )
        ok, reason = failover_interval_verdict(text)
        self.assertFalse(ok)
        self.assertIn("missing [SUM] interval telemetry", reason)

    def test_sixty_second_blackhole_fails_despite_good_run_average(self):
        text = self.log(outage=range(10, 70), duration=120)
        self.assertEqual(parse_sum_bps(text.splitlines()[-1]), 11_700_000_000)
        ok, reason = failover_interval_verdict(text)
        self.assertFalse(ok)
        self.assertIn("60 consecutive", reason)

    def test_each_established_stream_must_resume_after_failover(self):
        self.assertTrue(failover_stream_verdict(self.log(), 10, 8)[0])

    def test_stream_recovery_after_three_seconds_fails(self):
        ok, reason = failover_stream_verdict(self.log(delayed_streams=(5,)), 10, 8)
        self.assertFalse(ok)
        self.assertIn("streams 5", reason)

    def test_lost_streams_fail_even_when_other_streams_survive(self):
        ok, reason = failover_stream_verdict(
            self.log(dead_after_crash=(9, 10, 11, 12)), 10, 8
        )
        self.assertFalse(ok)
        self.assertIn("9, 10, 11, 12", reason)

    def test_insufficient_pre_failover_stream_baseline_fails_closed(self):
        ok, reason = failover_stream_verdict(self.log(streams=range(5, 9)), 10, 8)
        self.assertFalse(ok)
        self.assertIn("expected 8 active streams", reason)

    def test_failover_cli_emits_interval_and_stream_verdicts(self):
        parser = os.path.join(os.path.dirname(__file__), "iperf3_sum_parse.py")
        result = subprocess.run(
            [
                sys.executable,
                parser,
                "--failover-check",
                "--streams",
                "8",
                "--min-throughput-gbps",
                "1.0",
                "--crash-at",
                "10",
            ],
            input=self.log(dead_after_crash=(9, 10, 11, 12)),
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertEqual(len(result.stdout.splitlines()), 2)
        self.assertTrue(result.stdout.splitlines()[0].startswith("PASS "))
        self.assertIn("FAIL streams 9, 10, 11, 12", result.stdout)



class FailoverClientProcessTests(unittest.TestCase):
    def test_pid_tracking_does_not_accept_the_pool_client(self):
        with tempfile.TemporaryDirectory() as tmp:
            bin_dir = os.path.join(tmp, "bin")
            os.makedirs(bin_dir)
            incus = os.path.join(bin_dir, "incus")
            iperf = os.path.join(bin_dir, "iperf3")
            with open(incus, "w", encoding="utf-8") as f:
                f.write(
                    "#!/usr/bin/env bash\n"
                    '[[ "$1" == exec && "$3" == -- ]] || exit 90\n'
                    "shift 3\n"
                    'exec "$@"\n'
                )
            with open(iperf, "w", encoding="utf-8") as f:
                f.write(
                    "#!/usr/bin/env bash\n"
                    "sleep 60 &\n"
                    "child=$!\n"
                    "trap 'kill \"$child\" 2>/dev/null || true' EXIT TERM\n"
                    "wait \"$child\"\n"
                )
            os.chmod(incus, 0o755)
            os.chmod(iperf, 0o755)
            env = os.environ.copy()
            env["PATH"] = bin_dir + os.pathsep + env["PATH"]
            script = r'''
source "$1"
CLUSTER_LAN_HOST=mock-lan
main_pidfile="$2/main.pid"
pool_pidfile="$2/pool.pid"
pids=()
cleanup() {
    for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done
}
trap cleanup EXIT
failover_start_main_iperf 30 192.0.2.1 5211 8 "$2/main.log" "$main_pidfile"
main_pid=$(cat "$main_pidfile")
[[ "$main_pid" =~ ^[0-9]+$ ]] || exit 11
pids+=("$main_pid")
failover_main_iperf_running "$main_pidfile" 192.0.2.1 5211 8 || exit 12
failover_start_main_iperf 30 192.0.2.1 5210 2 "$2/pool.log" "$pool_pidfile"
pool_pid=$(cat "$pool_pidfile")
[[ "$pool_pid" =~ ^[0-9]+$ ]] || exit 13
pids+=("$pool_pid")
if failover_main_iperf_running "$pool_pidfile" 192.0.2.1 5211 8; then exit 14; fi
kill "$main_pid"
for _ in {1..20}; do
    if ! failover_main_iperf_running "$main_pidfile" 192.0.2.1 5211 8; then break; fi
    sleep 0.05
done
if failover_main_iperf_running "$main_pidfile" 192.0.2.1 5211 8; then exit 15; fi
kill -0 "$pool_pid" 2>/dev/null || exit 16
'''
            result = subprocess.run(
                [
                    "bash",
                    "-c",
                    script,
                    "test",
                    os.path.join(os.path.dirname(__file__), "failover-client-lib.sh"),
                    tmp,
                ],
                text=True,
                env=env,
                timeout=10,
            )
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
