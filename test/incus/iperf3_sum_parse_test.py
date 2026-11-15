import json
import os
import subprocess
import sys
import tempfile
import types
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
        failback_dip=True,
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
            interval_dipped = second in outage or second in (10, 11) or (
                failback_dip and second in (20, 21)
            )
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


    def test_failback_boundary_requires_a_post_event_interval(self):
        for duration, expected in ((21, None), (22, True)):
            text = self.log(duration=duration, failback_dip=False)
            for payload, json_stream in (
                (text, False),
                (self.json_stream(text), True),
            ):
                with self.subTest(duration=duration, json_stream=json_stream):
                    ok, reason = failover_stream_verdict(
                        payload,
                        20,
                        8,
                        json_stream=json_stream,
                        event_label="failback",
                    )
                    self.assertIs(ok, expected)
                    if expected is None:
                        self.assertIn("no per-stream interval", reason)

    def test_client_ending_before_crash_is_fail_not_void(self):
        for duration in (8, 10):
            text = self.log(duration=duration, failback_dip=False)
            for payload, json_stream in (
                (text, False),
                (self.json_stream(text), True),
            ):
                with self.subTest(duration=duration, json_stream=json_stream):
                    ok, reason = failover_stream_verdict(
                        payload,
                        10,
                        8,
                        json_stream=json_stream,
                        event_label="crash",
                    )
                    self.assertIs(ok, False)
                    self.assertIn("before the crash event", reason)

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


_HERE = os.path.dirname(os.path.abspath(__file__))
_PARSER_PATH = os.path.join(_HERE, "iperf3_sum_parse.py")
# Two REAL iperf3 --json-stream logs from loss test-failover crash runs, cut to
# the start event plus the intervals from 10 s before the crash to 20 s after
# it (lines verbatim). Each has one straggler, stream 11:
#   2s91: r-18598/failover-dbg2-025351 (client pid 611806). The aggregate
#         stops at 57.603 s; s11 resumes 2.91 s later, INSIDE the 3 s deadline.
#   4s05: r-18598/failover-master2-012401 (client pid 430760). The aggregate
#         stops at 53.938 s; s11 resumes 4.05 s later, OUTSIDE it.
# The integer anchor mis-scores both: an in-phase 57 FAILs 2s91 and a
# one-late 55 PASSes 4s05 (#18692).
# A third, from the #18703 live run (/var/worktrees/.cache/fwd-goal/r-18692/
# live-133312, 0.0.29546+g8fae8c163179, client pid 3981748): a fast takeover
# in which three streams resumed inside the interval after the crash, so the
# AGGREGATE never emptied (8 % there) while five streams stopped together.
_FAST = os.path.join(_HERE, "failover-crash-fast-takeover.jsonl")
_FAST_EPOCHS = (1793540088.881948012, 1793540103.885568244, 0.005, 0.197)
_INSIDE = os.path.join(_HERE, "failover-crash-straggler-2s91.jsonl")
_OUTSIDE = os.path.join(_HERE, "failover-crash-straggler-4s05.jsonl")


def _read(path):
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def _mutant(anchor, replacement):
    """The parser with ONE exact textual replacement, as a fresh namespace."""
    source = _read(_PARSER_PATH)
    if source.count(anchor) != 1:
        raise AssertionError(f"mutant anchor occurs {source.count(anchor)} times: {anchor!r}")
    namespace = {"__name__": "iperf3_sum_parse_mutant", "__file__": _PARSER_PATH}
    exec(compile(source.replace(anchor, replacement), _PARSER_PATH, "exec"), namespace)
    return namespace


def _with_stream_held(text, stream, start_from, until):
    """``text`` with one stream's bytes zeroed for intervals starting in
    ``[start_from, until)`` (the sum reduced to match): a REAL log made to
    hold that stream down longer. Every other byte is the run's own."""
    out = []
    for line in text.splitlines():
        event = json.loads(line)
        if event.get("event") == "interval":
            data = event["data"]
            for row in data["streams"]:
                if row["socket"] == stream and start_from <= row["start"] < until:
                    data["sum"]["bits_per_second"] -= row["bits_per_second"]
                    data["sum"]["bytes"] -= row["bytes"]
                    row["bits_per_second"] = 0
                    row["bytes"] = 0
            line = json.dumps(event, separators=(",", ":"))
        out.append(line)
    return "\n".join(out) + "\n"


class PreciseCrashAnchorTests(unittest.TestCase):
    """#18692: the crash cell in real seconds, on real straggler logs."""

    INSIDE_STOP = 57.603
    OUTSIDE_STOP = 53.938

    @staticmethod
    def crash_anchor(module, text, before=-0.2, after=10.0, rtt=0.2):
        """The harness's anchor: epochs ``before``/``after`` s from the
        fixture's real stop (the sysrq exec brackets it), offset 0."""
        start = module.json_stream_start_epoch(text)
        stop = module.data_stop_anchor(text, 30.0, 90.0)
        return module.event_anchor(
            text, before=start + stop.seconds + before, after=start + stop.seconds + after,
            offset=0.0, rtt=rtt, label="crash", data_stop=True,
        )

    @staticmethod
    def cell(module, text, anchor):
        return module.precise_stream_cell(text, anchor, 8, json_stream=True)

    @staticmethod
    def fast_takeover_with_late_group_pause(text, pause_start=55, pause_resume=65):
        """Keep only two streams stopped after fast takeover, then pause an
        unrelated three-stream group until ``pause_resume``.
        """
        resumed_fast = {5, 9, 11}
        pre_crash_rates = {}
        events = []
        for line in text.splitlines():
            event = json.loads(line)
            if event.get("event") == "interval":
                data = event["data"]
                second = int(float(data["sum"]["start"]) + 0.05)
                pause_interval = pause_start < second < pause_resume
                for stream in data["streams"]:
                    stream_id = stream["socket"]
                    if second == 53:
                        pre_crash_rates[stream_id] = stream["bits_per_second"]
                    elif second == 54 and stream_id in resumed_fast:
                        stream["bits_per_second"] = pre_crash_rates[stream_id]
                    elif pause_interval and stream_id in resumed_fast:
                        stream["bits_per_second"] = 0
                    if second == 54 and stream_id in resumed_fast:
                        stream["bytes"] = int(
                            stream["bits_per_second"] * (stream["end"] - stream["start"]) / 8
                        )
                    elif pause_interval and stream_id in resumed_fast:
                        stream["bytes"] = 0
                data["sum"]["bits_per_second"] = sum(
                    stream["bits_per_second"] for stream in data["streams"]
                )
                if "bytes" in data["sum"]:
                    data["sum"]["bytes"] = sum(
                        stream.get("bytes", 0) for stream in data["streams"]
                    )
            events.append(json.dumps(event, separators=(",", ":")))
        return "\n".join(events) + "\n"

    def setUp(self):
        import iperf3_sum_parse as module

        self.module = module
        self.inside = _read(_INSIDE)
        self.outside = _read(_OUTSIDE)
        self.fast = _read(_FAST)
        # Stream 11 of the 4s05 log held down past its real resume: through
        # the interval starting 62.0 s (resumes c+9.06 s), through 63.0 s
        # (c+10.06 s), and for the rest of the log (never).
        self.held_9s = _with_stream_held(self.outside, 11, 54.0, 63.0)
        self.held_10s = _with_stream_held(self.outside, 11, 54.0, 64.0)
        self.dead = _with_stream_held(self.outside, 11, 54.0, 1e9)

    def test_start_timestamp_uses_milliseconds(self):
        self.assertEqual(self.module.json_stream_start_epoch(self.outside), 1793496391.493)
        self.assertIsNone(self.module.json_stream_start_epoch('{"event":"start","data":{}}\n'))

    def test_aggregate_stop_inside_the_sysrq_window_is_the_anchor(self):
        for text, expected in ((self.inside, self.INSIDE_STOP), (self.outside, self.OUTSIDE_STOP)):
            anchor = self.crash_anchor(self.module, text)
            self.assertAlmostEqual(anchor.seconds, expected, delta=0.002)
            self.assertAlmostEqual(anchor.uncertainty, 0.05)
            self.assertAlmostEqual(anchor.after_epoch, 0.2, delta=0.002)
            self.assertIn("aggregate stop", anchor.source)

    def fast_anchor(self, module):
        before, after, offset, rtt = _FAST_EPOCHS
        return module.resolve_anchor(
            self.fast, 53, before=before, after=after, offset=offset, rtt=rtt, crash=True
        )

    def test_fast_takeover_anchors_on_the_streams_that_stopped_together(self):
        # The live run's own epochs and clock reading.
        anchor = self.fast_anchor(self.module)
        self.assertAlmostEqual(anchor.seconds, 53.242, delta=0.002)
        self.assertIn("stop of 5 streams together", anchor.source)
        self.assertAlmostEqual(anchor.after_epoch, 0.117, delta=0.002)
        status, reason = self.cell(self.module, self.fast, anchor)
        self.assertEqual(status, "PASS", reason)
        self.assertIn("data max 2.39s", reason)


    def test_delayed_fast_takeover_stop_four_seconds_after_lo_anchors(self):
        # The event is at 53.242 s, more than four seconds after this clock
        # window opens. No delivery-time cap may discard the real stop.
        anchor = self.module.data_stop_anchor(self.fast, 49.0, 65.0)
        self.assertIsNotNone(anchor)
        self.assertAlmostEqual(anchor.seconds, 53.242, delta=0.002)
        status, reason = self.cell(self.module, self.fast, anchor)
        self.assertEqual(status, "PASS", reason)

    def test_partial_group_pause_does_not_replace_fallback_cell_verdict(self):
        text = self.fast_takeover_with_late_group_pause(
            self.fast, pause_start=55, pause_resume=65
        )
        lo = 54.1
        # Candidate k starts at lo+0.9; its stop estimate is lo+1.9, inside
        # the former two-second bound. Aggregate throughput in k+1 stays above
        # half its pre-event rate, so this unrelated group pause cannot anchor.
        self.assertAlmostEqual(55.0 - lo, 0.9, delta=1e-9)
        self.assertAlmostEqual(56.0 - lo, 1.9, delta=1e-9)
        self.assertIsNone(self.module.data_stop_anchor(text, lo, 70.0))

        def judge(module):
            anchor = module.data_stop_anchor(text, lo, 70.0)
            if anchor is not None:
                return module.precise_stream_cell(text, anchor, 8, json_stream=True)
            return module.integer_stream_cell(text, 53, 8, json_stream=True)

        status, reason = judge(self.module)
        self.assertEqual(status, "VOID", reason)
        self.assertIn("52s COST, 53s PASS, 54s PASS", reason)
        # Without aggregate confirmation, the later pause makes a false COST
        # anchor instead of preserving the fallback's conservative VOID.
        self.assert_flips(
            "_STREAMS_STOP_AGGREGATE_FRACTION = 0.5",
            '_STREAMS_STOP_AGGREGATE_FRACTION = float("inf")',
            judge,
            "VOID",
        )


    def test_no_stop_in_a_wide_window_is_no_precise_anchor(self):
        # The window opens after the stop: no stop, and seconds wide.
        self.assertIsNone(self.crash_anchor(self.module, self.inside, before=1.0, after=11.0))
        # A narrow window off the stop stands as a clock anchor.
        anchor = self.crash_anchor(self.module, self.inside, before=1.95, after=2.05, rtt=0.1)
        self.assertTrue(anchor.source.startswith("crash: orchestrator clock"), anchor.source)
        self.assertAlmostEqual(anchor.seconds, self.INSIDE_STOP + 2.0, delta=0.002)
        self.assertAlmostEqual(anchor.uncertainty, 0.1, delta=1e-6)

    def test_resume_inside_three_seconds_passes_and_names_the_straddle(self):
        status, reason = self.cell(self.module, self.inside, self.crash_anchor(self.module, self.inside))
        self.assertEqual(status, "PASS", reason)
        self.assertIn("s11=2.91/", reason)
        # s11's first data interval [60.0, 61.0) holds the 3 s line (60.603).
        self.assertIn("the 3s line falls inside the interval streams 11 resumed in", reason)
        # The defect, on the same bytes: floor(57.603) = 57 FAILs s11.
        ok, reason = failover_stream_verdict(self.inside, 57, 8, json_stream=True)
        self.assertFalse(ok)
        self.assertEqual(reason, "streams 11 carried data before failover but did not resume within 3s")

    def test_resume_at_four_seconds_is_a_cost(self):
        status, reason = self.cell(self.module, self.outside, self.crash_anchor(self.module, self.outside))
        self.assertEqual(status, "COST", reason)
        self.assertTrue(reason.startswith(
            "streams 11 resumed after failover but later than 3s (s11 4.05s): stragglers"), reason)
        self.assertIn("data max 4.05s", reason)
        # The defect: an integer anchor one second late (55) PASSes s11.
        self.assertTrue(failover_stream_verdict(self.outside, 55, 8, json_stream=True)[0])

    def test_ten_second_line_each_side(self):
        status, reason = self.cell(self.module, self.held_9s, self.crash_anchor(self.module, self.held_9s))
        self.assertEqual(status, "COST", reason)
        self.assertRegex(reason, r"s11 9\.\d\ds")
        status, reason = self.cell(self.module, self.held_10s, self.crash_anchor(self.module, self.held_10s))
        self.assertEqual(status, "FAIL", reason)
        self.assertTrue(reason.startswith(
            "streams 11 carried data before failover but did not resume within 10s ["), reason)
        self.assertRegex(reason, r"s11=10\.\d\d/")

    def test_dead_stream_fails(self):
        status, reason = self.cell(self.module, self.dead, self.crash_anchor(self.module, self.dead))
        self.assertEqual(status, "FAIL", reason)
        self.assertIn("did not resume within 10s", reason)
        self.assertIn("s11=never/never", reason)

    def test_late_clock_anchor_reads_inside_the_resume_interval(self):
        # A clock-only anchor 0.1 s late inside its ±0.2 s: s11's first data
        # interval STARTS 2.96 s after it, but its bytes arrive at the very
        # end, 3.95 s after.
        anchor = self.module.EventAnchor(self.OUTSIDE_STOP + 0.1, 0.2, "clock only")
        status, reason = self.cell(self.module, self.outside, anchor)
        self.assertEqual(status, "COST", reason)
        self.assertIn("s11=3.95/", reason)

    def test_fallback_finds_the_stop_within_one_second_of_the_integer_anchor(self):
        # No clock reading: the aggregate's stop within ±1 s of the integer
        # anchor is still on iperf3's own clock.
        for at in (53, 54):
            status, reason = self.module.integer_stream_cell(self.dead, at, 8, json_stream=True)
            self.assertEqual(status, "FAIL", reason)
            self.assertIn("event at 53.938s", reason)
            self.assertIn("the integer anchor", reason)
        status, reason = self.module.integer_stream_cell(self.outside, 54, 8, json_stream=True)
        self.assertEqual(status, "COST", reason)

    def test_three_anchor_fallback_keeps_an_agreed_verdict_and_voids_a_split_one(self):
        # The anchor-53 dead row (#18703 review): the true stop is 53.938, so
        # the 53.0 interval holds it and its PRE-crash bytes must not read as
        # a resume at the 52 s candidate.
        status, reason = self.module.integer_three_anchor_cell(self.dead, 53, 8, json_stream=True)
        self.assertEqual(status, "FAIL", reason)
        self.assertIn("52s FAIL, 53s FAIL, 54s FAIL", reason)
        status, reason = self.module.integer_three_anchor_cell(self.outside, 54, 8, json_stream=True)
        self.assertEqual(status, "VOID", reason)
        self.assertIn("53s COST, 54s COST, 55s PASS", reason)

    def run_cli(self, text, *extra):
        command = [
            sys.executable, _PARSER_PATH, "--failover-check", "--json-stream",
            "--streams", "8", "--min-throughput-gbps", "1", "--crash-at", "54", *extra,
        ]
        return subprocess.run(command, input=text, capture_output=True, text=True)

    def test_cli_precise_cost_and_metrics(self):
        start = self.module.json_stream_start_epoch(self.outside)
        result = self.run_cli(
            self.outside, "--straggler-cost",
            "--crash-epoch", f"{start + self.OUTSIDE_STOP - 0.2:.6f}",
            "--crash-epoch-after", f"{start + self.OUTSIDE_STOP + 10:.6f}",
            "--client-clock-offset", "0", "--client-clock-rtt", "0.2", "--emit-metrics",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        lines = result.stdout.splitlines()
        self.assertTrue(lines[1].startswith("COST streams 11 resumed after failover"), lines[1])
        metrics = dict(line[len("METRIC "):].split("=", 1) for line in lines[2:])
        self.assertEqual(metrics["crash_anchor_precise"], "1")
        self.assertEqual(metrics["crash_at_s"], "53.938")
        self.assertEqual(metrics["crash_stop_after_epoch_s"], "0.200")
        self.assertEqual(metrics["crash_resume_data_max_s"], "4.055")
        self.assertEqual(metrics["crash_resume_straggler_streams"], "1")
        for value in metrics.values():
            float(value)  # harness-result.sh records numeric metrics only

    def test_cli_without_straggler_cost_is_the_old_verdict(self):
        result = self.run_cli(self.outside)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout.splitlines()[1],
            "FAIL " + failover_stream_verdict(self.outside, 54, 8, json_stream=True)[1],
        )
        self.assertEqual(len(result.stdout.splitlines()), 2)
        refused = self.run_cli(self.outside, "--crash-epoch", "1")
        self.assertEqual(refused.returncode, 2)
        self.assertIn("need --straggler-cost", refused.stderr)

    def test_cli_with_no_clock_reading(self):
        # The stop within ±1 s of --crash-at 54 still anchors the cell.
        result = self.run_cli(self.outside, "--straggler-cost", "--emit-metrics")
        lines = result.stdout.splitlines()
        self.assertTrue(lines[1].startswith("COST streams 11 resumed after failover"), lines[1])
        self.assertIn("METRIC crash_anchor_precise=1", lines)
        self.assertFalse(any(line.startswith("METRIC crash_stop_after_epoch_s=") for line in lines))
        # An integer anchor with no stop within ±1 s: the three-anchor cell.
        far = subprocess.run(
            [sys.executable, _PARSER_PATH, "--failover-check", "--json-stream", "--streams", "8",
             "--min-throughput-gbps", "1", "--crash-at", "60", "--straggler-cost", "--emit-metrics"],
            input=self.outside, capture_output=True, text=True,
        ).stdout.splitlines()
        self.assertIn("integer anchor 60s (harness SECONDS) and ±1 s", far[1])
        self.assertIn("METRIC crash_anchor_precise=0", far)

    def test_print_crash_anchor(self):
        def anchor(*extra):
            return subprocess.run(
                [sys.executable, _PARSER_PATH, "--print-crash-anchor", *extra],
                input=self.outside, capture_output=True, text=True, check=True,
            ).stdout.strip()

        start = self.module.json_stream_start_epoch(self.outside)
        self.assertEqual(anchor(
            "--crash-at", "54", "--crash-epoch", f"{start + self.OUTSIDE_STOP - 0.2:.6f}",
            "--crash-epoch-after", f"{start + self.OUTSIDE_STOP + 10:.6f}",
            "--client-clock-offset", "0", "--client-clock-rtt", "0.2",
        ), "53.938 0.050 precise")
        self.assertEqual(anchor("--crash-at", "54"), "53.938 0.050 precise")
        self.assertEqual(anchor("--crash-at", "60"), "60 1 integer")
        # A clock window that opens after the stop rules out a stop before it.
        self.assertEqual(anchor(
            "--crash-at", "54", "--crash-epoch", f"{start + self.OUTSIDE_STOP + 0.5:.6f}",
            "--crash-epoch-after", f"{start + self.OUTSIDE_STOP + 10:.6f}",
            "--client-clock-offset", "0", "--client-clock-rtt", "0.2",
        ), "54 1 integer")

    def test_precise_failback_without_post_event_interval_is_void(self):
        anchor = self.module.EventAnchor(83.0, 0.1, "observed")
        status, reason = self.module.precise_stream_cell(
            self.inside, anchor, 8, json_stream=True, event_label="failback"
        )
        self.assertEqual(status, "VOID", reason)
        self.assertIn("before the failback event", reason)

    # Executable mutants: each removes one piece of the fix and must flip the
    # row it names. A mutant that flips nothing would mean the row cannot see
    # the piece it claims to pin.
    def assert_flips(self, anchor, replacement, judge, expected):
        self.assertEqual(judge(self.module)[0], expected)
        # No-op control through the same exec path: the mechanism alone must
        # not move the row, so a flip below is the replacement's doing.
        control = types.SimpleNamespace(**_mutant(anchor, anchor))
        self.assertEqual(judge(control)[0], expected, "no-op control moved the row")
        mutant = types.SimpleNamespace(**_mutant(anchor, replacement))
        status, reason = judge(mutant)
        self.assertNotEqual(status, expected, f"mutant did not flip the row: {reason}")

    def precise(self, text, **anchor_args):
        return lambda module: self.cell(module, text, self.crash_anchor(module, text, **anchor_args))

    def test_mutant_integer_anchor_flips_the_inside_row(self):
        self.assert_flips(
            "            return EventAnchor(\n                stop,",
            "            return EventAnchor(\n                math.floor(stop),",
            self.precise(self.inside), "PASS",
        )

    def test_mutant_counting_the_crash_interval_flips_the_four_second_row(self):
        self.assert_flips(
            "after = [row for row in intervals if row[0] >= anchor.latest]",
            "after = [row for row in intervals if row[1] > anchor.seconds]",
            self.precise(self.outside), "COST",
        )

    def test_mutant_resume_at_interval_start_flips_the_late_clock_row(self):
        late = lambda module: self.cell(  # noqa: E731
            module, self.outside, module.EventAnchor(self.OUTSIDE_STOP + 0.1, 0.2, "clock only")
        )
        self.assert_flips(
            "resume = end - (end - start) * min(1.0, bps / following)",
            "resume = start",
            late, "COST",
        )

    def test_mutant_resume_at_interval_end_flips_the_inside_row(self):
        self.assert_flips(
            "resume = end - (end - start) * min(1.0, bps / following)",
            "resume = end",
            self.precise(self.inside), "PASS",
        )

    def test_mutant_without_the_stop_refinement_flips_the_early_clock_row(self):
        # A narrow clock window whose midpoint is 0.15 s early: only the
        # aggregate-stop refinement puts s11 back inside 3 s.
        self.assert_flips(
            "    if data_stop:\n", "    if False:\n",
            self.precise(self.inside, before=-0.25, after=-0.05, rtt=0.2), "PASS",
        )

    def test_mutant_aggregate_stop_only_flips_the_fast_takeover_row(self):
        self.assert_flips(
            "    return _streams_stop_anchor(rows, lo, hi)\n", "    return None\n",
            lambda module: ("precise" if self.fast_anchor(module) else "none", ""),
            "precise",
        )

    def test_mutant_no_cost_line_flips_the_four_second_row(self):
        self.assert_flips(
            "RESUME_COST_SECONDS = 3.0", "RESUME_COST_SECONDS = 10.0",
            self.precise(self.outside), "COST",
        )

    def test_mutant_no_fail_line_flips_the_ten_second_row(self):
        self.assert_flips(
            "RESUME_FAIL_SECONDS = 10.0", "RESUME_FAIL_SECONDS = 1e9",
            self.precise(self.held_10s), "FAIL",
        )

    def test_mutant_fallback_trusting_one_anchor_flips_the_split_row(self):
        self.assert_flips(
            "    if len(set(statuses.values())) == 1:\n", "    if True:\n",
            lambda module: module.integer_three_anchor_cell(self.outside, 54, 8, json_stream=True),
            "VOID",
        )

    def test_mutant_crash_interval_as_resume_evidence_flips_the_anchor_53_dead_row(self):
        # Reproduces the review's "52s PASS" for a stream that never resumes.
        self.assert_flips(
            "    lower = max(candidate + 1, at + 1)\n", "    lower = candidate + 1\n",
            lambda module: module.integer_three_anchor_cell(self.dead, 53, 8, json_stream=True),
            "FAIL",
        )

    def test_mutant_fallback_without_the_stop_flips_the_four_second_row(self):
        self.assert_flips(
            "        stop = data_stop_anchor(text, at - 1, at + 1)\n",
            "        stop = None\n",
            lambda module: module.integer_stream_cell(self.outside, 54, 8, json_stream=True),
            "COST",
        )


# #19123: the crash cell over a window with MEASURED edges. The rows below
# are SYNTHETIC runs whose every truth is specified independently of the
# parser: the crash instant on iperf3's interval clock, each stream's resume,
# iperf3's startup gap (start.timestamp -> interval zero), the arrival
# stamps' latency and any clock step, the sysrq dispatch and fw1's peer-lost
# stamp, and both clock offsets. Bytes are the exact overlap of each
# interval with each stream's on-time, so no rate model is assumed.
_STREAMS = (5, 7, 9, 11, 13, 15, 17, 19)


class _SyntheticCrashRun:
    """One test-failover crash run, generated from specified truths."""

    def __init__(self, *, crash=58.4, resumes=None, startup=0.30, lat=0.005,
                 dispatch_latency=0.15, detect_delay=0.8, lan_offset=0.02,
                 lan_rtt=0.15, fw1_offset=-0.01, fw1_rtt=0.15, rate=3e9,
                 factors=None, step=None, duration=75, stamped=None,
                 reported_lan_offset=None):
        self.crash = crash
        self.resumes = {s: crash + 1.0 for s in _STREAMS}
        self.resumes.update(resumes or {})
        self.start_rt = 1800000000.0
        self.zero = self.start_rt + startup          # interval zero, LAN realtime
        dispatch = crash - dispatch_latency          # on the interval clock
        self.at = int(dispatch)                      # harness $SECONDS difference
        self.before = self.zero + dispatch - lan_offset
        self.after = self.before + 15.0
        # A misread offset (the clock mapping reads late) without touching truth.
        self.lan = (lan_offset if reported_lan_offset is None else reported_lan_offset, lan_rtt)
        detected = self.zero + crash + detect_delay - lan_offset   # orchestrator clock
        self.peer = (detected + fw1_offset, fw1_offset, fw1_rtt)
        lines = [json.dumps({"event": "start", "data": {"timestamp": {
            "timemillisecs": int(round(self.start_rt * 1000))}}}, separators=(",", ":"))]
        arrivals = []
        for k in range(duration):
            a, b = float(k), float(k + 1)
            factor = (factors or {}).get(k, 1.0)
            rows = []
            for s in _STREAMS:
                on = max(0.0, min(b, crash) - a)
                resume = self.resumes[s]
                if isinstance(resume, tuple):       # back at resume[0], silent again at resume[1]
                    on += max(0.0, min(b, resume[1]) - max(a, resume[0]))
                elif resume is not None:
                    on += max(0.0, b - max(a, resume))
                bps = int(rate * on * factor)
                rows.append({"socket": s, "start": a, "end": b, "seconds": 1.0,
                             "bytes": bps // 8, "bits_per_second": bps})
            total = sum(r["bits_per_second"] for r in rows)
            line = json.dumps({"event": "interval", "data": {"streams": rows, "sum": {
                "start": a, "end": b, "seconds": 1.0, "bytes": total // 8,
                "bits_per_second": total}}}, separators=(",", ":"))
            lines.append(line)
            stamp = self.zero + b + lat
            if step is not None and b >= step[0]:
                stamp += step[1]
            if stamped is None or stamped(b):
                arrivals.append(f"{stamp:.6f}\t{line}")
        self.text = "\n".join(lines) + "\n"
        self.arrivals = "\n".join(arrivals) + "\n"

    def anchor(self, module, **override):
        args = dict(before=self.before, offset=self.lan[0], rtt=self.lan[1],
                    arrivals=self.arrivals, peer_lost=self.peer[0],
                    peer_offset=self.peer[1], peer_rtt=self.peer[2])
        args.update(override)
        return module.measured_bounded_anchor(self.text, self.at, **args)

    def judge(self, module, **override):
        anchor = self.anchor(module, **override)
        if anchor is None:
            return "no window", ""
        return module.bounded_stream_cell(self.text, anchor, 8)

    def cli(self, tmp):
        path = os.path.join(tmp, "arrivals")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(self.arrivals)
        result = subprocess.run(
            [sys.executable, _PARSER_PATH, "--failover-check", "--json-stream",
             "--streams", "8", "--min-throughput-gbps", "1", "--crash-at", str(self.at),
             "--straggler-cost", "--emit-metrics",
             "--crash-epoch", repr(self.before), "--crash-epoch-after", repr(self.after),
             "--client-clock-offset", repr(self.lan[0]), "--client-clock-rtt", repr(self.lan[1]),
             "--client-arrivals", path, "--peer-lost-epoch", repr(self.peer[0]),
             "--peer-clock-offset", repr(self.peer[1]), "--peer-clock-rtt", repr(self.peer[2])],
            input=self.text, capture_output=True, text=True,
        )
        lines = result.stdout.splitlines()
        return lines[1], [line for line in lines if line.startswith("METRIC ")]


def _assert_flips(test, anchor, replacement, judge, expected):
    """``assert_flips`` above, for a class that is not PreciseCrashAnchorTests."""
    import iperf3_sum_parse as module

    test.assertEqual(judge(module)[0], expected)
    control = types.SimpleNamespace(**_mutant(anchor, anchor))
    test.assertEqual(judge(control)[0], expected, "no-op control moved the row")
    mutant = types.SimpleNamespace(**_mutant(anchor, replacement))
    status, reason = judge(mutant)
    test.assertNotEqual(status, expected, f"mutant did not flip the row: {reason}")


# A REAL fast-takeover crash log (#19034 udp PR H1, g5-19034-logs/pr-udp-h1-1794699622),
# cut like the fixtures above, with its run's integer anchor and epochs. It
# was recorded before the arrival stamper and fw1's peer-lost reading existed,
# so it carries no measured window: its verdict must stay the integer cell's.
_PRE_19123_RUN = ("failover-crash-fast-takeover-udp.jsonl", 58,
                  (1794699715.273589580, 1794699720.459956343, -0.051, 0.155))


class BoundedCrashWindowTests(unittest.TestCase):
    """#19123: a fast takeover leaves no stop; the crash cell is judged at both
    ends of a window whose edges are measured: the sysrq dispatch through the
    client's arrival stamps, and fw1's own peer-lost stamp."""

    def setUp(self):
        import iperf3_sum_parse as module

        self.module = module

    def test_the_window_holds_the_specified_crash(self):
        run = _SyntheticCrashRun()
        anchor = run.anchor(self.module)
        self.assertTrue(anchor.bounded)
        self.assertLessEqual(anchor.seconds, run.crash)
        self.assertGreaterEqual(anchor.latest, run.crash)
        # T_lo = dispatch - rtt/2 - stamp latency, independent of the 0.30 s startup gap.
        self.assertAlmostEqual(anchor.seconds, run.crash - 0.15 - 0.075 - 0.005, delta=1e-6)

    def test_a_true_pass_is_pass(self):
        status, reason = _SyntheticCrashRun().judge(self.module)
        self.assertEqual(status, "PASS", reason)
        self.assertIn("PASS at the earliest, PASS at the latest", reason)

    def test_the_review_counterexample_true_cost_is_never_pass(self):
        # P1-1: iperf3 starts its interval clock 0.30 s after start.timestamp;
        # a stream resumes 3.05 s after the crash. Mapping through
        # start.timestamp read 2.95/2.85 s: PASS/PASS.
        run = _SyntheticCrashRun(startup=0.30, resumes={11: 58.4 + 3.05})
        status, reason = run.judge(self.module)
        self.assertNotEqual(status, "PASS", reason)
        self.assertEqual(status, "VOID", reason)

    def test_a_straggler_past_the_latest_edge_is_cost(self):
        run = _SyntheticCrashRun(resumes={11: 58.4 + 4.8})
        status, reason = run.judge(self.module)
        self.assertEqual(status, "COST", reason)

    def test_a_dead_stream_is_fail(self):
        status, reason = _SyntheticCrashRun(resumes={11: None}).judge(self.module)
        self.assertEqual(status, "FAIL", reason)

    def test_an_unrelated_dip_then_a_delayed_crash_cannot_pass_a_dead_stream(self):
        # P1-2: a 40 % dip in [58,59) unrelated to the crash, the sysrq landing
        # later at 59.10 s, and a stream that carries pre-crash bytes in
        # [59,60) and then dies.
        for factors in ({57: 0.4}, {58: 0.4}):
            with self.subTest(dip=factors):
                run = _SyntheticCrashRun(crash=59.10, factors=factors, resumes={11: None})
                status, reason = run.judge(self.module)
                self.assertEqual(status, "FAIL", reason)

    def test_a_pre_crash_rate_drop_does_not_move_the_window(self):
        # P2-3: traffic at half rate until the crash; the window has no rate model.
        plain = _SyntheticCrashRun().anchor(self.module)
        dropped = _SyntheticCrashRun(factors={58: 0.5}).anchor(self.module)
        self.assertEqual((plain.seconds, plain.latest), (dropped.seconds, dropped.latest))
        status, reason = _SyntheticCrashRun(factors={58: 0.5}).judge(self.module)
        self.assertEqual(status, "PASS", reason)

    def test_a_clock_step_among_the_stamps_takes_no_window(self):
        run = _SyntheticCrashRun(step=(54.0, 0.5))
        self.assertIsNone(run.anchor(self.module))

    def test_a_zero_before_the_start_stamp_takes_no_window(self):
        # A backward step before the window: every stamp 0.5 s early.
        run = _SyntheticCrashRun(step=(0.0, -0.5))
        self.assertIsNone(run.anchor(self.module))

    def test_a_peer_loss_before_the_dispatch_takes_no_window(self):
        run = _SyntheticCrashRun(detect_delay=-1.0)
        self.assertIsNone(run.anchor(self.module))

    def test_a_missing_reading_takes_no_window(self):
        run = _SyntheticCrashRun()
        for missing in ("arrivals", "peer_lost", "peer_offset", "offset"):
            with self.subTest(missing=missing):
                self.assertIsNone(run.anchor(self.module, **{missing: None}))

    def test_the_cli_judges_the_window_and_reports_it(self):
        run = _SyntheticCrashRun()
        with tempfile.TemporaryDirectory() as tmp:
            line, metrics = run.cli(tmp)
        self.assertTrue(line.startswith("PASS "), line)
        self.assertIn("bounded to [", line)
        self.assertIn("METRIC crash_anchor_precise=0", metrics)
        self.assertIn("METRIC crash_anchor_bounded=1", metrics)

    def test_print_crash_anchor_hands_the_producer_the_earliest_edge(self):
        run = _SyntheticCrashRun()
        anchor = run.anchor(self.module)
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "arrivals")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(run.arrivals)
            result = subprocess.run(
                [sys.executable, _PARSER_PATH, "--print-crash-anchor", "--crash-at", str(run.at),
                 "--crash-epoch", repr(run.before), "--crash-epoch-after", repr(run.after),
                 "--client-clock-offset", repr(run.lan[0]), "--client-clock-rtt", repr(run.lan[1]),
                 "--client-arrivals", path, "--peer-lost-epoch", repr(run.peer[0]),
                 "--peer-clock-offset", repr(run.peer[1]), "--peer-clock-rtt", repr(run.peer[2])],
                input=run.text, capture_output=True, text=True, check=True,
            )
        self.assertEqual(
            result.stdout.strip(), f"{anchor.seconds:.3f} {anchor.uncertainty:.3f} bounded"
        )

    def test_a_pre_19123_log_keeps_the_integer_verdict(self):
        path, at, (before, after, offset, rtt) = _PRE_19123_RUN
        text = _read(os.path.join(_HERE, path))
        result = subprocess.run(
            [sys.executable, _PARSER_PATH, "--failover-check", "--json-stream",
             "--streams", "8", "--min-throughput-gbps", "1", "--crash-at", str(at),
             "--straggler-cost", "--emit-metrics",
             "--crash-epoch", repr(before), "--crash-epoch-after", repr(after),
             "--client-clock-offset", repr(offset), "--client-clock-rtt", repr(rtt)],
            input=text, capture_output=True, text=True,
        )
        lines = result.stdout.splitlines()
        self.assertTrue(lines[1].startswith("VOID the integer failover anchor"), lines[1])
        self.assertIn("METRIC crash_anchor_bounded=0", lines)

    def test_the_arrival_stamper_stamps_each_line_and_exits_with_the_client(self):
        with tempfile.TemporaryDirectory() as tmp:
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
            script = r'''
source "$1"
CLUSTER_LAN_HOST=mock-lan
log="$2/client.log"
: >"$log"
sleep 30 & sup=$!
echo "$sup" >"$2/client.pid"
failover_start_arrival_stamper "$log" "$2/client.pid"
sleep 0.5
t0=$EPOCHREALTIME
for i in 1 2 3; do printf '{"event":"interval","n":%d}\n' "$i" >>"$log"; sleep 0.3; done
sleep 0.5
t1=$EPOCHREALTIME
kill "$sup"
for _ in {1..30}; do pgrep -f "tail -s 0.1 --pid=$sup" >/dev/null || break; sleep 0.1; done
pgrep -f "tail -s 0.1 --pid=$sup" >/dev/null && exit 21
echo "$t0 $t1"
'''
            result = subprocess.run(
                ["bash", "-c", script, "test",
                 os.path.join(os.path.dirname(__file__), "failover-client-lib.sh"), tmp],
                capture_output=True, text=True, env=env, timeout=20,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            t0, t1 = map(float, result.stdout.split())
            with open(os.path.join(tmp, "client.log.arrivals"), encoding="utf-8") as handle:
                rows = [line.split("\t", 1) for line in handle.read().splitlines()]
        self.assertEqual([json.loads(raw)["n"] for _, raw in rows], [1, 2, 3])
        stamps = [float(stamp) for stamp, _ in rows]
        self.assertEqual(stamps, sorted(stamps))
        self.assertTrue(all(t0 <= stamp <= t1 for stamp in stamps), (t0, stamps, t1))

    # Executable mutants: each removes one measured edge or guard and must flip
    # its row.
    def test_mutant_mapping_through_the_start_stamp_turns_a_true_cost_into_pass(self):
        run = _SyntheticCrashRun(startup=0.30, resumes={11: 58.4 + 3.05})
        replacement = "    zero_hi, spread, samples = bound\n    zero_hi = start\n"
        _assert_flips(self, "    zero_hi, spread, samples = bound\n", replacement,
                      run.judge, "VOID")
        mutant = types.SimpleNamespace(**_mutant("    zero_hi, spread, samples = bound\n", replacement))
        self.assertEqual(run.judge(mutant)[0], "PASS")

    def test_mutant_judging_at_the_latest_end_turns_a_true_cost_into_pass(self):
        run = _SyntheticCrashRun(startup=0.30, resumes={11: 58.4 + 3.05})
        anchor = "    if status_lo == status_hi:\n        return status_lo, message_lo + note\n"
        replacement = "    if True:\n        return status_hi, message_hi + note\n"
        _assert_flips(self, anchor, replacement, run.judge, "VOID")
        mutant = types.SimpleNamespace(**_mutant(anchor, replacement))
        self.assertEqual(run.judge(mutant)[0], "PASS")

    def test_mutant_resume_evidence_from_the_earliest_edge_flips_a_dead_row(self):
        # The interval starting 59.0 s lies inside [T_lo, crash): stream 11's
        # pre-crash bytes there must not read as a resume.
        run = _SyntheticCrashRun(crash=59.15, resumes={11: None})
        _assert_flips(
            self,
            "    earliest = EventAnchor(anchor.seconds, anchor.uncertainty, anchor.source)\n",
            "    earliest = EventAnchor(anchor.seconds, 0.0, anchor.source)\n",
            run.judge, "FAIL",
        )

    def window(self, run):
        return lambda module: ("window" if run.anchor(module) else "no window", "")

    def test_mutant_without_the_attribution_guard_bounds_an_early_peer_loss(self):
        _assert_flips(
            self,
            "        return None  # fw1 lost its peer before the sysrq was sent: not this crash\n",
            "        pass\n",
            self.window(_SyntheticCrashRun(detect_delay=-1.0)), "no window",
        )

    def test_mutant_without_the_continuity_check_bounds_a_stepped_clock(self):
        _assert_flips(
            self,
            "        return None  # the stamps near the crash disagree: the clock stepped\n",
            "        pass\n",
            self.window(_SyntheticCrashRun(step=(54.0, 0.5))), "no window",
        )

    def test_mutant_without_the_start_stamp_check_bounds_a_zero_before_it(self):
        _assert_flips(
            self,
            "        return None  # a zero before the connect stamp: the clock stepped back\n",
            "        pass\n",
            self.window(_SyntheticCrashRun(step=(0.0, -0.5))), "no window",
        )

    # R24 F1: a stop that the precise path SAW and rejected (it lies before the
    # mapped dispatch, so the mapping reads late) keeps the integer cell. The
    # whole fleet is down for an interval (a stop at 58.4 s); the LAN offset
    # is misread 0.3 s late; a stream truly resumes 3.05 s after the crash.
    def stop_rejected_run(self):
        resumes = {s: 60.2 for s in _STREAMS}
        resumes[11] = 58.4 + 3.05
        return _SyntheticCrashRun(startup=0.01, resumes=resumes, reported_lan_offset=0.32)

    def test_a_rejected_stop_keeps_the_integer_cell(self):
        run = self.stop_rejected_run()
        self.assertIsNone(self.module.resolve_anchor(
            run.text, run.at, before=run.before, after=run.after, offset=run.lan[0],
            rtt=run.lan[1], crash=True,
        ))
        self.assertTrue(self.module.stop_seen(
            run.text, run.at, before=run.before, after=run.after, offset=run.lan[0], rtt=run.lan[1],
        ))
        with tempfile.TemporaryDirectory() as tmp:
            line, metrics = run.cli(tmp)
        self.assertNotIn("bounded to [", line)
        self.assertFalse(line.startswith("PASS "), line)
        self.assertIn("METRIC crash_anchor_bounded=0", metrics)

    def test_mutant_admitting_a_rejected_stop_turns_a_true_cost_into_pass(self):
        run = self.stop_rejected_run()

        def judge(module):
            if module.stop_seen(run.text, run.at, before=run.before, after=run.after,
                                offset=run.lan[0], rtt=run.lan[1]):
                return "integer", ""
            return run.judge(module)

        replacement = "    try:\n        return False and data_stop_anchor(text, lo, hi) is not None\n"
        _assert_flips(
            self, "    try:\n        return data_stop_anchor(text, lo, hi) is not None\n",
            replacement, judge, "integer",
        )
        mutant = types.SimpleNamespace(**_mutant(
            "    try:\n        return data_stop_anchor(text, lo, hi) is not None\n", replacement))
        self.assertEqual(judge(mutant)[0], "PASS")

    # R24 F2: a stream whose read resume is a burst that then goes silent is
    # not a resume. Stream 11 carries data only in [60.0, 60.6) after the crash.
    def test_an_unsustained_resume_is_void(self):
        run = _SyntheticCrashRun(resumes={11: (60.0, 60.6)})
        status, reason = run.judge(self.module)
        self.assertEqual(status, "VOID", reason)
        self.assertIn("not sustained", reason)

    def test_mutant_without_the_stay_up_check_passes_a_burst(self):
        run = _SyntheticCrashRun(resumes={11: (60.0, 60.6)})
        _assert_flips(
            self,
            "        if unsustained:\n",
            "        if False:\n",
            run.judge, "VOID",
        )

    # The arrival stamps: at least three near the crash, and only near it.
    def test_two_stamps_near_the_crash_take_no_window(self):
        run = _SyntheticCrashRun(stamped=lambda end: end < 48.0 or end in (55.0, 56.0))
        self.assertIsNone(run.anchor(self.module))

    def test_mutant_accepting_fewer_than_three_stamps_bounds_it(self):
        run = _SyntheticCrashRun(stamped=lambda end: end < 48.0 or end in (55.0, 56.0))
        _assert_flips(self, "    if len(samples) < 3:\n", "    if len(samples) < 1:\n",
                      self.window(run), "no window")

    def test_stamps_only_far_from_the_crash_take_no_window(self):
        # The stamper stopped well before the crash: no local mapping.
        run = _SyntheticCrashRun(stamped=lambda end: end < 40.0)
        self.assertIsNone(run.anchor(self.module))

    def test_mutant_reaching_far_stamps_bounds_it(self):
        run = _SyntheticCrashRun(stamped=lambda end: end < 40.0)
        _assert_flips(self, "_ARRIVAL_WINDOW = (10.0, 1.0)\n", "_ARRIVAL_WINDOW = (100.0, 1.0)\n",
                      self.window(run), "no window")

    # The old T_hi < T_lo guard is gone: with fw1's stamp after the dispatch,
    # T_hi - T_lo >= fw1 rtt + LAN rtt, so the window always has width.
    def test_the_window_always_has_width(self):
        for startup in (0.0, 0.3, 2.0):
            for delay in (0.001, 0.8, 2.5):
                for rtts in ((0.0, 0.0), (0.15, 0.15)):
                    with self.subTest(startup=startup, delay=delay, rtts=rtts):
                        run = _SyntheticCrashRun(startup=startup, detect_delay=delay,
                                                 lan_rtt=rtts[0], fw1_rtt=rtts[1])
                        anchor = run.anchor(self.module)
                        self.assertIsNotNone(anchor)
                        self.assertGreaterEqual(anchor.uncertainty, 0.0)
                        self.assertLessEqual(anchor.seconds, run.crash)
                        self.assertGreaterEqual(anchor.latest, run.crash)


if __name__ == "__main__":
    unittest.main()
