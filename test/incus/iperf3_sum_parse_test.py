import json
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
        dead_after_failback=(),
        delayed_streams=(),
        outage=(),
        duration=32,
        failback_at=20,
    ):
        lines = []
        streams = tuple(streams)
        dead_after_crash = set(dead_after_crash)
        delayed_streams = set(delayed_streams)
        outage = set(outage)
        dead_after_failback = set(dead_after_failback)
        sum_rates = []
        for second in range(duration):
            live_streams = [
                stream for stream in streams
                if not (stream in dead_after_crash and second >= 10)
                and not (
                    stream in dead_after_failback
                    and second >= failback_at + 2
                )
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
                if (
                    stream in dead_after_failback
                    and second >= failback_at + 2
                ):
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

    @staticmethod
    def json_stream(text):
        intervals = {}
        for line in text.splitlines():
            row = parse_interval_line(line)
            if row is None:
                continue
            stream, start, end, bps = row
            key = (start, end)
            data = intervals.setdefault(key, {"streams": []})
            entry = {"start": start, "end": end, "bits_per_second": bps}
            if stream is None:
                data["sum"] = entry
            else:
                data["streams"].append({"socket": stream, **entry})
        events = [
            {"event": "interval", "data": intervals[key]}
            for key in sorted(intervals)
        ]
        events.append({"event": "end", "data": {}})
        return "\n".join(json.dumps(event, separators=(",", ":")) for event in events)

    def assert_json_twins(self, text):
        json_text = self.json_stream(text)
        self.assertEqual(
            failover_interval_verdict(json_text, json_stream=True)[0],
            failover_interval_verdict(text)[0],
        )
        self.assertEqual(
            failover_stream_verdict(json_text, 10, 8, json_stream=True)[0],
            failover_stream_verdict(text, 10, 8)[0],
        )

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
        text = self.log(outage=(10, 11, 20, 21))
        ok, _ = failover_interval_verdict(text)
        self.assertTrue(ok)
        self.assert_json_twins(text)

    def test_final_aggregate_without_interval_rows_fails_closed(self):
        text = "[SUM] 0.00-120.00 sec 350 GBytes 23.4 Gbits/sec sender"
        ok, reason = failover_interval_verdict(text)
        self.assertFalse(ok)
        self.assertIn("no per-second", reason)
        self.assert_json_twins(text)

    def test_interval_telemetry_gap_fails_closed(self):
        text = (
            "[SUM] 0.00-1.00 sec 2.93 GBytes 23.4 Gbits/sec\n"
            "[SUM] 2.00-3.00 sec 2.93 GBytes 23.4 Gbits/sec"
        )
        ok, reason = failover_interval_verdict(text)
        self.assertFalse(ok)
        self.assertIn("missing [SUM] interval telemetry", reason)
        self.assert_json_twins(text)

    def test_sixty_second_blackhole_fails_despite_good_run_average(self):
        text = self.log(outage=range(10, 70), duration=120)
        self.assertEqual(parse_sum_bps(text.splitlines()[-1]), 11_700_000_000)
        ok, reason = failover_interval_verdict(text)
        self.assertFalse(ok)
        self.assertIn("60 consecutive", reason)
        self.assert_json_twins(text)

    def test_each_established_stream_must_resume_after_failover(self):
        text = self.log()
        self.assertTrue(failover_stream_verdict(text, 10, 8)[0])
        self.assert_json_twins(text)

    def test_stream_recovery_after_three_seconds_fails(self):
        text = self.log(delayed_streams=(5,))
        ok, reason = failover_stream_verdict(text, 10, 8)
        self.assertFalse(ok)
        self.assertIn("streams 5", reason)
        self.assert_json_twins(text)

    def test_lost_streams_fail_even_when_other_streams_survive(self):
        text = self.log(dead_after_crash=(9, 10, 11, 12))
        ok, reason = failover_stream_verdict(text, 10, 8)
        self.assertFalse(ok)
        self.assertIn("9, 10, 11, 12", reason)
        self.assert_json_twins(text)

    def test_insufficient_pre_failover_stream_baseline_fails_closed(self):
        text = self.log(streams=range(5, 9))
        ok, reason = failover_stream_verdict(text, 10, 8)
        self.assertFalse(ok)
        self.assertIn("expected 8 active streams", reason)
        self.assert_json_twins(text)

    def test_failback_stream_loss_is_detected_after_crash_oracle_passes(self):
        text = self.log(
            dead_after_failback=range(6, 13),
            duration=32,
            failback_at=20,
        )
        self.assertTrue(failover_interval_verdict(text)[0])
        self.assertTrue(failover_stream_verdict(text, 10, 8)[0])

        json_text = self.json_stream(text)
        ok, reason = failover_stream_verdict(
            json_text, 20, 8, json_stream=True, event_label="failback"
        )
        self.assertFalse(ok)
        self.assertIn("streams 6, 7, 8, 9, 10, 11, 12", reason)

        parser = os.path.join(os.path.dirname(__file__), "iperf3_sum_parse.py")
        command = [
            sys.executable,
            parser,
            "--failover-check",
            "--json-stream",
            "--streams",
            "8",
            "--min-throughput-gbps",
            "1.0",
            "--crash-at",
            "10",
            "--failback-at",
            "20",
        ]
        result = subprocess.run(
            command, input=json_text, capture_output=True, text=True, check=True
        )
        self.assertEqual(len(result.stdout.splitlines()), 3)
        self.assertTrue(result.stdout.splitlines()[0].startswith("PASS "))
        self.assertTrue(result.stdout.splitlines()[1].startswith("PASS "))
        self.assertIn("FAIL streams 6, 7, 8, 9, 10, 11, 12", result.stdout)

    def test_client_ending_before_failback_is_void_not_pass(self):
        text = self.json_stream(self.log(duration=32))
        parser = os.path.join(os.path.dirname(__file__), "iperf3_sum_parse.py")
        result = subprocess.run(
            [
                sys.executable,
                parser,
                "--failover-check",
                "--json-stream",
                "--streams",
                "8",
                "--min-throughput-gbps",
                "1.0",
                "--crash-at",
                "10",
                "--failback-at",
                "40",
            ],
            input=text,
            capture_output=True,
            text=True,
            check=True,
        )
        lines = result.stdout.splitlines()
        self.assertEqual(len(lines), 3)
        self.assertEqual(lines[2].split(" ", 1)[0], "VOID")
        self.assertIn("before the failback event", lines[2])


    def test_failover_cli_emits_interval_and_stream_verdicts(self):
        parser = os.path.join(os.path.dirname(__file__), "iperf3_sum_parse.py")
        text = self.log(dead_after_crash=(9, 10, 11, 12))
        command = [
            sys.executable,
            parser,
            "--failover-check",
            "--streams",
            "8",
            "--min-throughput-gbps",
            "1.0",
            "--crash-at",
            "10",
        ]
        result = subprocess.run(
            command, input=text, capture_output=True, text=True, check=True
        )
        json_result = subprocess.run(
            command + ["--json-stream"],
            input=self.json_stream(text),
            capture_output=True,
            text=True,
            check=True,
        )
        auto_json_result = subprocess.run(
            command,
            input=self.json_stream(text),
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertEqual(len(result.stdout.splitlines()), 2)
        self.assertTrue(result.stdout.splitlines()[0].startswith("PASS "))
        self.assertIn("FAIL streams 9, 10, 11, 12", result.stdout)
        expected_statuses = [
            line.split(" ", 1)[0] for line in result.stdout.splitlines()
        ]
        self.assertEqual(
            [line.split(" ", 1)[0] for line in json_result.stdout.splitlines()],
            expected_statuses,
        )
        self.assertEqual(
            [line.split(" ", 1)[0] for line in auto_json_result.stdout.splitlines()],
            expected_statuses,
        )

    def test_json_stream_auto_detection_and_gap_boundary(self):
        contiguous = (
            "[SUM] 0.00-1.00 sec 2.93 GBytes 23.4 Gbits/sec\n"
            "[SUM] 1.25-2.25 sec 2.93 GBytes 23.4 Gbits/sec"
        )
        gap = contiguous.replace("1.25-2.25", "1.251-2.251")
        for text, expected in ((contiguous, True), (gap, False)):
            with self.subTest(text=text):
                json_text = "\n " + self.json_stream(text)
                self.assertEqual(failover_interval_verdict(text)[0], expected)
                self.assertEqual(
                    failover_interval_verdict(json_text)[0],
                    failover_interval_verdict(text)[0],
                )

    def test_json_interval_duration_filter_keeps_half_to_one_and_half_seconds(self):
        events = []
        for start, end in ((0, 0.5), (0.5, 2.0), (2.0, 3.51)):
            events.append({
                "event": "interval",
                "data": {
                    "sum": {
                        "start": start,
                        "end": end,
                        "bits_per_second": 2_000_000_000,
                    },
                },
            })
        text = "\n".join(json.dumps(event) for event in events)
        self.assertTrue(failover_interval_verdict(text)[0])
    def test_json_oracle_uses_per_stream_times_without_aggregate_sum(self):
        events = []
        for second in range(15):
            streams = [
                {
                    "socket": stream,
                    "start": second,
                    "end": second + 1,
                    "bits_per_second": 1_000_000_000,
                }
                for stream in range(1, 9)
            ]
            events.append({"event": "interval", "data": {"streams": streams}})
        text = "\n".join(json.dumps(event) for event in events)
        self.assertTrue(failover_interval_verdict(text, json_stream=True)[0])
        self.assertTrue(failover_stream_verdict(text, 10, 8, json_stream=True)[0])

    def test_json_interval_malformed_evidence_fails_closed(self):
        valid = (
            '{"event":"interval","data":{"sum":{"start":0,"end":1,'
            '"bits_per_second":8000000000}}}'
        )
        valid_stream = (
            '{"start":0,"end":1,"bits_per_second":8000000000,"socket":1}'
        )
        bad_events = {
            "malformed JSON line": '{"event":"interval",',
            "non-object event": "[]",
            "missing event name": "{}",
            "missing interval data": '{"event":"interval"}',
            "non-list streams": (
                '{"event":"interval","data":{"sum":{"start":0,"end":1,'
                '"bits_per_second":8000000000},"streams":{}}}'
            ),
            "non-object stream": (
                '{"event":"interval","data":{"streams":["bad"]}}'
            ),
            "malformed stream fields": (
                '{"event":"interval","data":{"streams":[{"start":0}]}}'
            ),
            "malformed stream id": (
                '{"event":"interval","data":{"streams":[{"start":0,"end":1,'
                '"bits_per_second":8000000000,"socket":"1"}]}}'
            ),
            "boolean rate": (
                '{"event":"interval","data":{"sum":{"start":0,"end":1,'
                '"bits_per_second":true}}}'
            ),
            "string rate": (
                '{"event":"interval","data":{"sum":{"start":0,"end":1,'
                '"bits_per_second":"8000000000"}}}'
            ),
            "non-standard NaN": (
                '{"event":"interval","data":{"sum":{"start":0,"end":1,'
                '"bits_per_second":NaN}}}'
            ),
            "overflowed float": (
                '{"event":"interval","data":{"sum":{"start":0,"end":1,'
                '"bits_per_second":1e999}}}'
            ),
            "overflowed integer": (
                '{"event":"interval","data":{"sum":{"start":0,"end":1,'
                '"bits_per_second":' + "9" * 400 + "}}}"
            ),
            "malformed sum despite stream rows": (
                '{"event":"interval","data":{"sum":null,"streams":['
                + valid_stream
                + "]}}"
            ),
            "reversed sum interval": (
                '{"event":"interval","data":{"sum":{"start":2,"end":1,'
                '"bits_per_second":8000000000}}}'
            ),
            "reversed stream interval": (
                '{"event":"interval","data":{"streams":[{"socket":1,'
                '"start":2,"end":1,"bits_per_second":8000000000}]}}'
            ),
        }
        for label, malformed in bad_events.items():
            with self.subTest(label=label):
                ok, reason = failover_interval_verdict(
                    malformed + "\n" + valid, json_stream=True
                )
                self.assertFalse(ok)
                self.assertIn("invalid JSON-stream interval telemetry", reason)



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
                    '[[ " $* " == *" --json-stream "* && " $* " == *" --forceflush "* && " $* " != *" -i "* ]] || exit 55\n'
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

    def test_timeout_kills_hung_final_exchange_and_cleanup_uses_pidfile(self):
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
                    "#!/usr/bin/env python3\n"
                    "import os, signal, sys, time\n"
                    "args = sys.argv[1:]\n"
                    "if '--json-stream' not in args or '--forceflush' not in args or '-i' in args: sys.exit(55)\n"
                    "port = args[args.index('-p') + 1]\n"
                    "duration = args[args.index('-t') + 1]\n"
                    "with open(os.path.join(os.environ['TEST_CHILD_PID_DIR'], port), 'w') as out:\n"
                    "    out.write(str(os.getpid()))\n"
                    "print('{\"event\":\"interval\",\"data\":{\"sum\":{\"start\":118.0,\"end\":119.0,\"bits_per_second\":8000000000}}}', flush=True)\n"
                    "if port == '5210' or duration != '1':\n"
                    "    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))\n"
                    "else:\n"
                    "    signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
                    "while True:\n"
                    "    time.sleep(1)\n"
                )
            os.chmod(incus, 0o755)
            os.chmod(iperf, 0o755)
            env = os.environ.copy()
            env["PATH"] = bin_dir + os.pathsep + env["PATH"]
            env["TEST_CHILD_PID_DIR"] = tmp
            script = r'''
source "$1"
CLUSTER_LAN_HOST=mock-lan
export FAILOVER_IPERF_TIMEOUT_MARGIN=0
test_dir="$2"
main_pidfile="$test_dir/main.pid"
cleanup_clients() {
    if declare -F failover_stop_main_iperf >/dev/null; then
        failover_stop_main_iperf "$main_pidfile" 192.0.2.1 5211 8
        failover_stop_main_iperf "$test_dir/main-cleanup.pid" 192.0.2.1 5211 8
        failover_stop_main_iperf "$test_dir/pool.pid" 192.0.2.1 5210 2
    else
        for pidfile in "$main_pidfile" "$test_dir/main-cleanup.pid" "$test_dir/pool.pid"; do
            pid=$(cat "$pidfile" 2>/dev/null || true)
            [[ "$pid" =~ ^[0-9]+$ ]] && kill -KILL "$pid" 2>/dev/null || true
        done
    fi
}
trap cleanup_clients EXIT
failover_start_main_iperf 1 192.0.2.1 5211 8 "$2/hung.log" "$main_pidfile"
main_pid=$(cat "$main_pidfile")
[[ "$main_pid" =~ ^[0-9]+$ ]] || exit 31
failover_main_iperf_running "$main_pidfile" 192.0.2.1 5211 8 || exit 32
for _ in {1..100}; do
    if ! failover_main_iperf_running "$main_pidfile" 192.0.2.1 5211 8; then break; fi
    sleep 0.1
done
if failover_main_iperf_running "$main_pidfile" 192.0.2.1 5211 8; then exit 33; fi
grep -q '"start":118.0' "$2/hung.log" || exit 34
if grep -q '"event":"end"' "$2/hung.log"; then exit 35; fi
hung_child=$(cat "$TEST_CHILD_PID_DIR/5211")
if kill -0 "$hung_child" 2>/dev/null; then exit 36; fi

export FAILOVER_IPERF_TIMEOUT_MARGIN=30
main_pidfile="$2/main-cleanup.pid"
pool_pidfile="$2/pool.pid"
failover_start_main_iperf 60 192.0.2.1 5211 8 "$2/main-cleanup.log" "$main_pidfile"
main_pid=$(cat "$main_pidfile")
failover_start_main_iperf 60 192.0.2.1 5210 2 "$2/pool.log" "$pool_pidfile"
pool_pid=$(cat "$pool_pidfile")
failover_main_iperf_running "$main_pidfile" 192.0.2.1 5211 8 || exit 37
failover_main_iperf_running "$pool_pidfile" 192.0.2.1 5210 2 || exit 38
failover_stop_main_iperf "$main_pidfile" 192.0.2.1 5211 8
if failover_main_iperf_running "$main_pidfile" 192.0.2.1 5211 8; then exit 39; fi
failover_main_iperf_running "$pool_pidfile" 192.0.2.1 5210 2 || exit 40
failover_stop_main_iperf "$pool_pidfile" 192.0.2.1 5210 2
if kill -0 "$main_pid" 2>/dev/null || kill -0 "$pool_pid" 2>/dev/null; then exit 41; fi
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
                capture_output=True,
                text=True,
                env=env,
                timeout=20,
            )
        self.assertEqual(result.returncode, 0, result.stderr)





class FailoverClientCompletionTests(unittest.TestCase):
    @staticmethod
    def install_mock_incus(tmp):
        bin_dir = os.path.join(tmp, "bin")
        os.makedirs(bin_dir)
        incus = os.path.join(bin_dir, "incus")
        with open(incus, "w", encoding="utf-8") as f:
            f.write(
                "#!/usr/bin/env bash\n"
                '[[ "$1" == exec && "$3" == -- ]] || exit 90\n'
                "shift 3\n"
                'exec "$@"\n'
            )
        os.chmod(incus, 0o755)
        env = os.environ.copy()
        env["PATH"] = bin_dir + os.pathsep + env["PATH"]
        return env

    def test_stream_without_end_event_does_not_claim_completion(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_path = os.path.join(tmp, "iperf.log")
            with open(log_path, "w", encoding="utf-8") as f:
                f.write(
                    '{"event":"interval","data":{"sum":{"start":0,"end":1,'
                    '"bits_per_second":8000000000}}}\n'
                )
            script = r'''
source "$1"
if failover_json_stream_completed "$2"; then exit 11; fi
'''
            result = subprocess.run(
                [
                    "bash",
                    "-c",
                    script,
                    "test",
                    os.path.join(os.path.dirname(__file__), "failover-client-lib.sh"),
                    log_path,
                ],
                capture_output=True,
                text=True,
                timeout=5,
            )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_wait_polls_for_json_completion_before_sampling(self):
        markers = (
            '{"event":"end","data":{}}',
            '{"completed":true,"observed_end_sec":120}',
        )
        for marker in markers:
            with self.subTest(marker=marker), tempfile.TemporaryDirectory() as tmp:
                env = self.install_mock_incus(tmp)
                log_path = os.path.join(tmp, "iperf.log")
                with open(log_path, "w", encoding="utf-8") as f:
                    f.write(
                        '{"event":"interval","data":{"sum":{"start":118,'
                        '"end":119,"bits_per_second":8000000000}}}\n'
                    )
                writer = subprocess.Popen(
                    [
                        "bash",
                        "-c",
                        'sleep 0.1; printf "%s\\n" "$1" >>"$2"',
                        "test",
                        marker,
                        log_path,
                    ]
                )
                script = r'''
source "$1"
CLUSTER_LAN_HOST=mock-lan
failover_wait_main_iperf_result "$2" 3 || exit 31
grep -Fq "$3" "$2" || exit 32
'''
                try:
                    result = subprocess.run(
                        [
                            "bash",
                            "-c",
                            script,
                            "test",
                            os.path.join(
                                os.path.dirname(__file__), "failover-client-lib.sh"
                            ),
                            log_path,
                            marker,
                        ],
                        capture_output=True,
                        text=True,
                        env=env,
                        timeout=5,
                    )
                finally:
                    writer.wait(timeout=5)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_wait_rejects_malformed_line_even_with_end_text(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = self.install_mock_incus(tmp)
            log_path = os.path.join(tmp, "iperf.log")
            with open(log_path, "w", encoding="utf-8") as f:
                f.write('{"event":"end" broken}\n')
            script = r'''
source "$1"
CLUSTER_LAN_HOST=mock-lan
if failover_wait_main_iperf_result "$2" 0; then exit 41; fi
'''
            result = subprocess.run(
                [
                    "bash",
                    "-c",
                    script,
                    "test",
                    os.path.join(os.path.dirname(__file__), "failover-client-lib.sh"),
                    log_path,
                ],
                capture_output=True,
                text=True,
                env=env,
                timeout=5,
            )
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
