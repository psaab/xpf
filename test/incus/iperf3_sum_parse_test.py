import io
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


# #19123: the crash cell over a window with MEASURED edges, on CLOCK_MONOTONIC.
# The rows below are SYNTHETIC runs whose every truth is specified
# independently of the parser: the crash instant on iperf3's interval clock,
# each stream's resume, the gap from the client's launch reading to the
# interval zero, the arrival stamps' latency, the sysrq dispatch, fw1's
# peer-lost receipt, both hosts' monotonic offsets and the LAN host's clock
# rate, plus the REALTIME clocks (start.timestamp, the orchestrator's epochs),
# which the window must not read. Bytes are the exact overlap of each
# interval with each stream's on-time, so no rate model is assumed.
_STREAMS = (5, 7, 9, 11, 13, 15, 17, 19)
_ZERO = 5000.0  # the LAN host's CLOCK_MONOTONIC at iperf3's interval zero
_RT_LAN = 1800000000.0 - _ZERO  # the LAN host's CLOCK_REALTIME minus its CLOCK_MONOTONIC


class _SyntheticCrashRun:
    """One test-failover crash run, generated from specified truths."""

    def __init__(self, *, crash=58.4, resumes=None, startup=0.30, lat=0.005,
                 dispatch_latency=0.15, detect_delay=0.8, lan_offset=37.25, lan_rtt=0.15,
                 fw1_offset=-912.5, fw1_rtt=0.15, lan_rate=0.0, pre_lead=1.0, post_lag=60.0,
                 rate=3e9, factors=None, duration=75, stamped=None, missing=None,
                 stale=False, launch_shift=0.0, rt_offset=0.02, reported_rt_offset=None,
                 rt_step=0.0, lan_rt_step=0.0, readings=None):
        self.crash = crash
        self.resumes = {s: crash + 1.0 for s in _STREAMS}
        self.resumes.update(resumes or {})
        launch = _ZERO - startup
        # The LAN host's monotonic clock runs (1 + lan_rate) as fast as the
        # orchestrator's around the dispatch instant o_ref.
        o_ref = _ZERO + crash - dispatch_latency - lan_offset

        def lan(o):
            return o + lan_offset + lan_rate * (o - o_ref)

        def orch(t):
            return o_ref + (t - lan_offset - o_ref) / (1 + lan_rate)

        lost = orch(_ZERO + crash + detect_delay) + fw1_offset
        pre_at, post_at = o_ref - pre_lead, o_ref + post_lag
        lines = {
            "dispatch": f"dispatch {o_ref:.6f}",
            "lan pre": f"lan pre {lan(pre_at) - pre_at:.6f} {lan_rtt:.6f} {pre_at:.6f} "
                       "1111aaaa-0000-0000-0000-00000000000a",
            "lan post": f"lan post {lan(post_at) - post_at:.6f} {lan_rtt:.6f} {post_at:.6f} "
                        "1111aaaa-0000-0000-0000-00000000000a",
            "fw1 pre": f"fw1 pre {fw1_offset:.6f} {fw1_rtt:.6f} {pre_at:.6f} "
                       "2222bbbb-0000-0000-0000-00000000000b",
            "fw1 post": f"fw1 post {fw1_offset:.6f} {fw1_rtt:.6f} {post_at:.6f} "
                        "2222bbbb-0000-0000-0000-00000000000b",
            "fw1 lost": f"fw1 lost {lost:.6f} 2222bbbb00000000000000000000000b",
        }
        lines.update(readings or {})
        self.readings = "\n".join(line for line in lines.values() if line) + "\n"
        # Realtime, for the precise path only: the orchestrator's CLOCK_REALTIME
        # is its CLOCK_MONOTONIC plus rt_orch, stepped by rt_step after the
        # realtime offset reading (which reads rt_offset, or a misread).
        rt_orch = _RT_LAN + lan_offset - rt_offset
        self.at = int(crash - dispatch_latency)
        self.before = o_ref + rt_orch + rt_step
        self.after = self.before + 15.0
        # A LAN realtime step of lan_rt_step after start.timestamp and before the
        # realtime offset reading: the reading carries it, start.timestamp does not.
        reported = rt_offset if reported_rt_offset is None else reported_rt_offset
        self.rt = (reported + lan_rt_step, lan_rtt)
        start_rt = launch + startup / 2 + _RT_LAN       # PARAM_EXCHANGE, between launch and zero
        text = [json.dumps({"event": "start", "data": {"timestamp": {
            "timemillisecs": int(round(start_rt * 1000))}}}, separators=(",", ":"))]
        arrivals = [f"launch\t{launch + launch_shift:.6f}\t1111aaaa-0000-0000-0000-00000000000a"]
        if stale:   # an older run's stamper, still appending its own lines
            arrivals += [f"{launch - 20 + k:.6f}\t" + json.dumps(
                {"event": "interval", "data": {"sum": {"start": k - 1.0, "end": float(k)}}})
                for k in range(1, 6)]
        for k in range(duration):
            a, b = float(k), float(k + 1)
            factor = (factors or {}).get(k, 1.0)
            rows = []
            for s in _STREAMS:
                if k in (missing or {}).get(s, ()):
                    continue
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
            text.append(line)
            if stamped is None or stamped(b):
                arrivals.append(f"{_ZERO + b + lat:.6f}\t{line}")
        self.text = "\n".join(text) + "\n"
        self.arrivals = "\n".join(arrivals) + "\n"

    def anchor(self, module, arrivals=None, readings=None):
        return module.measured_bounded_anchor(
            self.arrivals if arrivals is None else arrivals,
            module.parse_crash_readings(self.readings if readings is None else readings),
        )

    def judge(self, module):
        anchor = self.anchor(module)
        if anchor is None:
            return "no window", ""
        return module.bounded_stream_cell(self.text, anchor, 8)

    def holds(self, module):
        """Whether the window holds the crash: the cardinal edge property."""
        anchor = self.anchor(module)
        if anchor is None:
            return "no window", ""
        inside = anchor.seconds <= self.crash <= anchor.latest
        return ("holds" if inside else "misses"), f"[{anchor.seconds}, {anchor.latest}]"

    def files(self, tmp):
        paths = os.path.join(tmp, "arrivals"), os.path.join(tmp, "readings")
        for path, body in zip(paths, (self.arrivals, self.readings)):
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(body)
        return ["--client-arrivals", paths[0], "--crash-readings", paths[1]]

    def realtime_args(self):
        return ["--crash-at", str(self.at),
                "--crash-epoch", repr(self.before), "--crash-epoch-after", repr(self.after),
                "--client-clock-offset", repr(self.rt[0]), "--client-clock-rtt", repr(self.rt[1])]

    def cli(self, tmp, module=None):
        """The --failover-check crash line and METRIC lines: the parser as a
        subprocess, or ``module.main()`` in-process (for a mutant)."""
        argv = ["--failover-check", "--json-stream", "--streams", "8",
                "--min-throughput-gbps", "1", "--straggler-cost", "--emit-metrics",
                *self.realtime_args(), *self.files(tmp)]
        if module is None:
            stdout = subprocess.run([sys.executable, _PARSER_PATH, *argv], input=self.text,
                                    capture_output=True, text=True).stdout
        else:
            saved = sys.argv, sys.stdin, sys.stdout
            sys.argv, sys.stdin, sys.stdout = [_PARSER_PATH, *argv], io.StringIO(self.text), io.StringIO()
            try:
                module.main()
                stdout = sys.stdout.getvalue()
            finally:
                sys.argv, sys.stdin, sys.stdout = saved
        lines = stdout.splitlines()
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
    return status


# A REAL fast-takeover crash log (#19034 udp PR H1, g5-19034-logs/pr-udp-h1-1794699622),
# cut like the fixtures above, with its run's integer anchor and epochs. It
# was recorded before the arrival stamper and fw1's peer-lost reading existed,
# so it carries no measured window: its verdict must stay the integer cell's.
_PRE_19123_RUN = ("failover-crash-fast-takeover-udp.jsonl", 58,
                  (1794699715.273589580, 1794699720.459956343, -0.051, 0.155))

# The review's counterexamples (#19123 cycles 1 and 2) as runs.
_TRUE_COST = {"resumes": {11: 58.4 + 3.05}}                       # 3.05 s: a straggler
_FAST_BURST_COST = {"resumes": {11: 61.45}, "factors": {61: 2.0}}  # read 61.0, truly 61.45
_FAST_BURST_FAIL = {"resumes": {11: 68.45}, "factors": {68: 2.0}}  # read 68.0, truly 10.05 s


class BoundedCrashWindowTests(unittest.TestCase):
    """#19123: a fast takeover leaves no stop; the crash cell is judged at both
    ends of a window whose edges are measured on CLOCK_MONOTONIC: the sysrq
    dispatch through the client's launch reading and arrival stamps, and fw1's
    peer-lost receipt."""

    def setUp(self):
        import iperf3_sum_parse as module

        self.module = module

    # -- the window's edges ------------------------------------------------
    def test_the_window_holds_the_specified_crash(self):
        run = _SyntheticCrashRun()
        anchor = run.anchor(self.module)
        self.assertTrue(anchor.bounded)
        self.assertEqual(run.holds(self.module)[0], "holds")
        # T_lo = dispatch - rtt/2 - rate budget (1 ms over the 1 s lead) - stamp latency.
        self.assertAlmostEqual(anchor.seconds, run.crash - 0.15 - 0.075 - 0.001 - 0.005, delta=1e-6)

    def test_the_window_always_holds_the_crash(self):
        for startup in (0.0, 0.3, 0.5):
            for delay in (0.001, 0.8, 2.2):
                for rtts in ((0.0, 0.0), (0.15, 0.15)):
                    for rate in (-9e-4, 0.0, 9e-4):
                        with self.subTest(startup=startup, delay=delay, rtts=rtts, rate=rate):
                            run = _SyntheticCrashRun(
                                startup=startup, detect_delay=delay, lan_rtt=rtts[0],
                                fw1_rtt=rtts[1], lan_rate=rate, pre_lead=30.0)
                            self.assertEqual(run.holds(self.module)[0], "holds")

    def test_realtime_steps_do_not_move_the_window(self):
        # Codex cycle 2 P1-1/P1-2: a realtime step between a reading and its
        # use moved an edge across the crash. The window reads no realtime.
        plain = _SyntheticCrashRun().anchor(self.module)
        for step in (-6.0, -0.2, 0.2, 6.0):
            with self.subTest(step=step):
                stepped = _SyntheticCrashRun(rt_step=step).anchor(self.module)
                self.assertEqual((plain.seconds, plain.latest), (stepped.seconds, stepped.latest))

    def test_a_late_sysrq_exec_takes_no_window(self):
        # Codex cycle 2 P1-2's trace: the exec runs 6 s after the dispatch and
        # a stream dies at the crash. fw1's receipt is on its own monotonic
        # clock, so the window would hold the crash, but it is 7 s wide: over
        # the cap, no window, and the CLI never reads PASS.
        run = _SyntheticCrashRun(crash=64.0, dispatch_latency=6.0, resumes={11: None})
        self.assertIsNone(run.anchor(self.module))
        with tempfile.TemporaryDirectory() as tmp:
            line, metrics = run.cli(tmp)
        self.assertFalse(line.startswith("PASS "), line)
        self.assertIn("METRIC crash_anchor_bounded=0", metrics)

    def test_a_far_late_peer_loss_takes_no_window(self):
        # R24 NEW-B: an unrelated peer loss 8 s after the crash.
        self.assertIsNone(_SyntheticCrashRun(detect_delay=8.0).anchor(self.module))

    def test_slow_detection_is_void_but_keeps_an_agreed_integer_verdict(self):
        # R24 NEW-C: 2.0 s detection (the sync-recency guard) widens the window
        # to 2.9 s; the bounded cell cannot confirm a true PASS, and master's
        # integer cell, all three anchors agreeing, decides it as before.
        run = _SyntheticCrashRun(detect_delay=2.0)
        status, reason = run.judge(self.module)
        self.assertEqual(status, "VOID", reason)
        with tempfile.TemporaryDirectory() as tmp:
            line, metrics = run.cli(tmp)
        self.assertTrue(line.startswith("PASS "), line)
        self.assertIn("the three integer anchors agree", line)
        self.assertIn("METRIC crash_anchor_bounded=0", metrics)

    def test_a_pre_crash_rate_drop_does_not_move_the_window(self):
        plain = _SyntheticCrashRun().anchor(self.module)
        dropped = _SyntheticCrashRun(factors={58: 0.5}).anchor(self.module)
        self.assertEqual((plain.seconds, plain.latest), (dropped.seconds, dropped.latest))

    # -- the verdicts --------------------------------------------------------
    def test_a_true_pass_is_pass(self):
        status, reason = _SyntheticCrashRun().judge(self.module)
        self.assertEqual(status, "PASS", reason)
        self.assertIn("PASS at the earliest, PASS at the latest", reason)

    def test_a_true_cost_is_never_pass(self):
        status, reason = _SyntheticCrashRun(**_TRUE_COST).judge(self.module)
        self.assertEqual(status, "VOID", reason)
        # Realtime steps reach no edge: on the orchestrator (Codex cycle 2
        # P1-1), and a 0.2 s LAN step between the start stamp and the offset
        # reading (R24 NEW-A).
        for steps in ({"rt_step": -6.0}, {"rt_step": 6.0}, {"lan_rt_step": 0.2}):
            with self.subTest(**steps), tempfile.TemporaryDirectory() as tmp:
                line, _ = _SyntheticCrashRun(**steps, **_TRUE_COST).cli(tmp)
                self.assertFalse(line.startswith("PASS "), line)

    def test_a_late_resume_with_a_fast_first_burst_is_never_pass(self):
        # Codex cycle 2 P1-3: the in-interval read puts the resume at 61.0
        # (PASS at both ends); the interval's END bounds it at 62.0.
        status, reason = _SyntheticCrashRun(**_FAST_BURST_COST).judge(self.module)
        self.assertEqual(status, "VOID", reason)
        self.assertIn("cannot confirm PASS", reason)

    def test_a_true_fail_with_a_fast_first_burst_is_never_cost(self):
        status, reason = _SyntheticCrashRun(**_FAST_BURST_FAIL).judge(self.module)
        self.assertEqual(status, "VOID", reason)
        self.assertIn("cannot confirm COST", reason)

    def test_a_straggler_past_the_latest_edge_is_cost(self):
        status, reason = _SyntheticCrashRun(resumes={11: 58.4 + 4.8}).judge(self.module)
        self.assertEqual(status, "COST", reason)

    def test_a_dead_stream_is_fail(self):
        status, reason = _SyntheticCrashRun(resumes={11: None}).judge(self.module)
        self.assertEqual(status, "FAIL", reason)

    def test_an_unrelated_dip_then_a_delayed_crash_cannot_pass_a_dead_stream(self):
        for factors in ({57: 0.4}, {58: 0.4}):
            with self.subTest(dip=factors):
                run = _SyntheticCrashRun(crash=59.10, factors=factors, resumes={11: None})
                status, reason = run.judge(self.module)
                self.assertEqual(status, "FAIL", reason)

    # -- coverage after the resume (Codex cycle 2 P2-4, R24 F2) -------------
    def test_a_burst_then_silence_is_void(self):
        status, reason = _SyntheticCrashRun(resumes={11: (60.0, 60.6)}).judge(self.module)
        self.assertEqual(status, "VOID", reason)
        self.assertIn("not sustained", reason)

    def test_telemetry_ending_inside_the_three_seconds_is_void(self):
        run = _SyntheticCrashRun(resumes={11: (60.0, 60.6)}, duration=61)
        status, reason = run.judge(self.module)
        self.assertEqual(status, "VOID", reason)

    def test_a_missing_interval_inside_the_three_seconds_is_void(self):
        status, reason = _SyntheticCrashRun(missing={11: (62,)}).judge(self.module)
        self.assertEqual(status, "VOID", reason)

    def test_silence_only_in_the_third_second_is_void(self):
        status, reason = _SyntheticCrashRun(resumes={11: (59.8, 63.0)}).judge(self.module)
        self.assertEqual(status, "VOID", reason)

    # -- readings that take no window ---------------------------------------
    def test_a_peer_loss_before_the_dispatch_takes_no_window(self):
        self.assertIsNone(_SyntheticCrashRun(detect_delay=-1.0).anchor(self.module))

    def test_an_offset_that_moved_over_the_run_takes_no_window(self):
        for key, line in (
            ("lan post", "lan post 37.75 0.15 5098.0 1111aaaa-0000-0000-0000-00000000000a"),
            ("fw1 post", "fw1 post -906.5 0.15 5098.0 2222bbbb-0000-0000-0000-00000000000b"),
        ):
            with self.subTest(key=key):
                self.assertIsNone(_SyntheticCrashRun(readings={key: line}).anchor(self.module))

    def test_readings_from_another_boot_take_no_window(self):
        run = _SyntheticCrashRun()
        lost_elsewhere = run.readings.replace(" 2222bbbb00000000000000000000000b", " 3333cccc")
        self.assertIsNone(run.anchor(self.module, readings=lost_elsewhere))
        rows = run.readings.splitlines()
        post = next(i for i, row in enumerate(rows) if row.startswith("lan post"))
        rows[post] = rows[post].rsplit(" ", 1)[0] + " 4444dddd"
        self.assertIsNone(run.anchor(self.module, readings="\n".join(rows) + "\n"))
        launch_elsewhere = run.arrivals.replace("1111aaaa-0000-0000-0000-00000000000a", "5555eeee", 1)
        self.assertIsNone(run.anchor(self.module, arrivals=launch_elsewhere))

    def test_a_zero_before_the_launch_reading_takes_no_window(self):
        self.assertIsNone(_SyntheticCrashRun(launch_shift=0.5).anchor(self.module))

    def test_an_older_runs_stamps_are_skipped(self):
        plain = _SyntheticCrashRun().anchor(self.module)
        stale = _SyntheticCrashRun(stale=True).anchor(self.module)
        self.assertEqual((plain.seconds, plain.latest), (stale.seconds, stale.latest))

    def test_a_missing_or_malformed_reading_takes_no_window(self):
        run = _SyntheticCrashRun()
        for key in ("dispatch", "lan pre", "lan post", "fw1 pre", "fw1 post", "fw1 lost"):
            with self.subTest(missing=key):
                self.assertIsNone(_SyntheticCrashRun(readings={key: None}).anchor(self.module))
        rows = run.readings.splitlines()
        for name, bad in (
            ("short", rows[:1] + [rows[1].rsplit(" ", 1)[0]] + rows[2:]),
            ("duplicate", rows + rows[:1]),
            ("nan", [rows[0].split()[0] + " nan"] + rows[1:]),
            ("negative rtt", rows[:1] + [rows[1].replace(" 0.150000 ", " -0.150000 ", 1)] + rows[2:]),
            ("unknown", rows + ["fw0 pre 1 1 1 x"]),
        ):
            with self.subTest(malformed=name):
                self.assertIsNone(run.anchor(self.module, readings="\n".join(bad) + "\n"))
        self.assertIsNone(run.anchor(self.module, arrivals=run.arrivals.split("\n", 1)[1]))
        self.assertIsNone(run.anchor(self.module, arrivals=run.arrivals.split("\n", 1)[0] + "\n"))

    # -- the CLI ---------------------------------------------------------------
    def test_the_cli_judges_the_window_and_reports_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            line, metrics = _SyntheticCrashRun().cli(tmp)
        self.assertTrue(line.startswith("PASS "), line)
        self.assertIn("bounded to [", line)
        self.assertIn("METRIC crash_anchor_precise=0", metrics)
        self.assertIn("METRIC crash_anchor_bounded=1", metrics)

    def test_print_crash_anchor_hands_the_producer_the_earliest_edge(self):
        run = _SyntheticCrashRun()
        anchor = run.anchor(self.module)
        with tempfile.TemporaryDirectory() as tmp:
            result = subprocess.run(
                [sys.executable, _PARSER_PATH, "--print-crash-anchor", *run.realtime_args(),
                 *run.files(tmp)],
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

    # R24 F1: a stop that the precise path SAW and rejected (it lies before the
    # mapped dispatch: the realtime offset is misread 0.3 s late) keeps the
    # integer cell. The whole fleet is down for an interval (a stop at 58.4 s);
    # a stream truly resumes 3.05 s after the crash.
    def stop_rejected_run(self):
        resumes = {s: 60.2 for s in _STREAMS}
        resumes[11] = 58.4 + 3.05
        return _SyntheticCrashRun(startup=0.01, resumes=resumes, reported_rt_offset=0.32)

    def test_a_rejected_stop_keeps_the_integer_cell(self):
        run = self.stop_rejected_run()
        realtime = dict(before=run.before, after=run.after, offset=run.rt[0], rtt=run.rt[1])
        self.assertIsNone(self.module.resolve_anchor(run.text, run.at, crash=True, **realtime))
        self.assertTrue(self.module.stop_seen(run.text, run.at, **realtime))
        with tempfile.TemporaryDirectory() as tmp:
            line, metrics = run.cli(tmp)
        self.assertNotIn("bounded to [", line)
        self.assertFalse(line.startswith("PASS "), line)
        self.assertIn("METRIC crash_anchor_bounded=0", metrics)

    # -- the helpers that take the readings, run against an incus mock -------
    def _lib(self, script, tmp, journal=None):
        bin_dir = os.path.join(tmp, "bin")
        os.makedirs(bin_dir, exist_ok=True)
        with open(os.path.join(bin_dir, "incus"), "w", encoding="utf-8") as f:
            f.write('#!/usr/bin/env bash\n[[ "$1" == exec && "$3" == -- ]] || exit 90\n'
                    'shift 3\nexec "$@"\n')
        if journal is not None:
            with open(os.path.join(bin_dir, "journalctl"), "w", encoding="utf-8") as f:
                f.write(f"#!/usr/bin/env bash\ncat {journal!r}\n")
        for name in os.listdir(bin_dir):
            os.chmod(os.path.join(bin_dir, name), 0o755)
        env = os.environ.copy()
        env["PATH"] = bin_dir + os.pathsep + env["PATH"]
        lib = os.path.join(os.path.dirname(os.path.abspath(__file__)), "failover-client-lib.sh")
        return subprocess.run(["bash", "-c", 'source "$1"; CLUSTER_LAN_HOST=mock-lan\n' + script,
                               "test", lib, tmp], capture_output=True, text=True, env=env,
                              timeout=30)

    @staticmethod
    def _boot():
        with open("/proc/sys/kernel/random/boot_id", encoding="utf-8") as handle:
            return handle.read().strip()

    def test_the_launch_reading_and_the_stamper_write_one_runs_arrival_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = self._lib(r'''
log="$2/client.log"
printf 'launch\t1.0\tstale\nstale line\n' >"$log.arrivals"
t0=$(failover_mono_now)
failover_arrival_launch "$log"
: >"$log"
sleep 30 & sup=$!
echo "$sup" >"$2/client.pid"
failover_start_arrival_stamper "$log" "$2/client.pid"
sleep 0.5
for i in 1 2 3; do printf '{"event":"interval","n":%d}\n' "$i" >>"$log"; sleep 0.3; done
sleep 0.5
t1=$(failover_mono_now)
kill "$sup"
for _ in {1..30}; do pgrep -f "tail -s 0.1 --pid=$sup" >/dev/null || break; sleep 0.1; done
pgrep -f "tail -s 0.1 --pid=$sup" >/dev/null && exit 21
echo "$t0 $t1"
''', tmp)
            self.assertEqual(result.returncode, 0, result.stderr)
            t0, t1 = map(float, result.stdout.split())
            with open(os.path.join(tmp, "client.log.arrivals"), encoding="utf-8") as handle:
                rows = [line.split("\t") for line in handle.read().splitlines()]
        self.assertEqual(rows[0][0], "launch")
        self.assertEqual(rows[0][2], self._boot())
        launch = float(rows[0][1])
        self.assertEqual([json.loads(raw)["n"] for _, raw in rows[1:]], [1, 2, 3])
        stamps = [float(stamp) for stamp, _ in rows[1:]]
        self.assertTrue(t0 <= launch <= stamps[0], (t0, launch, stamps))
        self.assertEqual(stamps, sorted(stamps))
        self.assertLessEqual(stamps[-1], t1)

    def test_a_mono_reading_is_offset_rtt_midpoint_and_boot(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = self._lib("failover_mono_reading mock-fw1 3", tmp)
        self.assertEqual(result.returncode, 0, result.stderr)
        offset, rtt, at, boot = result.stdout.split()
        self.assertLessEqual(abs(float(offset)), float(rtt) / 2 + 1e-6)   # one host, one clock
        self.assertGreater(float(at), 0.0)
        self.assertEqual(boot, self._boot())

    def test_the_peer_lost_read_takes_the_first_matching_entry_on_the_boot(self):
        marker = "cluster: peer heartbeat timeout, marking peer lost"
        entries = [
            {"__MONOTONIC_TIMESTAMP": "990000000", "_BOOT_ID": "aa", "MESSAGE": marker},   # before
            {"__MONOTONIC_TIMESTAMP": "1001000000", "_BOOT_ID": "bb", "MESSAGE": marker},  # other boot
            {"__MONOTONIC_TIMESTAMP": "1001500000", "_BOOT_ID": "aa", "MESSAGE": "other"},
            {"__MONOTONIC_TIMESTAMP": "1002000000", "_BOOT_ID": "aa", "MESSAGE": "x " + marker},
            {"__MONOTONIC_TIMESTAMP": "1003000000", "_BOOT_ID": "aa", "MESSAGE": marker},
        ]
        late = [{"__MONOTONIC_TIMESTAMP": "1005500000", "_BOOT_ID": "aa", "MESSAGE": marker}]
        with tempfile.TemporaryDirectory() as tmp:
            journal = os.path.join(tmp, "journal.json")
            with open(journal, "w", encoding="utf-8") as handle:
                handle.write("not json\n" + "".join(json.dumps(e) + "\n" for e in entries) * 400)
            # dispatch 100 s on this host, fw1 = this host + 900 s: [999, 1005] on fw1.
            result = self._lib("failover_peer_lost_mono mock-fw1 900 a-a 100; echo rc=$?",
                               tmp, journal=journal)
            with open(journal, "w", encoding="utf-8") as handle:
                handle.write("".join(json.dumps(e) + "\n" for e in entries[:3] + late))
            beyond = self._lib("failover_peer_lost_mono mock-fw1 900 a-a 100; echo rc=$?",
                               tmp, journal=journal)
        self.assertEqual(result.stdout.split("\n")[:2], ["1002.000000 aa", "rc=0"], result.stderr)
        self.assertEqual(beyond.stdout.strip(), "rc=0", beyond.stderr)

    # Executable mutants: each removes one measured edge, budget or guard and
    # must flip its row.
    def test_mutant_zero_from_the_launch_reading_moves_the_lower_edge_past_the_crash(self):
        _assert_flips(
            self,
            "    t_lo = dispatch + lan.offset - _mapping_error(lan, dispatch) - zero_hi\n",
            "    t_lo = dispatch + lan.offset - _mapping_error(lan, dispatch) - launch\n",
            _SyntheticCrashRun().holds, "holds",
        )

    def test_mutant_zero_from_the_stamps_moves_the_upper_edge_before_the_crash(self):
        run = _SyntheticCrashRun(detect_delay=0.001, lan_rtt=0.0, fw1_rtt=0.0)
        _assert_flips(
            self,
            "    t_hi = lost_latest + lan.offset + _mapping_error(lan, lost_latest) - launch\n",
            "    t_hi = lost_latest + lan.offset + _mapping_error(lan, lost_latest) - zero_hi\n",
            run.holds, "holds",
        )

    def test_mutant_without_the_rate_budget_moves_the_lower_edge_past_the_crash(self):
        run = _SyntheticCrashRun(lan_rate=-9e-4, pre_lead=30.0, dispatch_latency=0.0, lat=0.0,
                                 lan_rtt=0.0, fw1_rtt=0.0)
        _assert_flips(
            self,
            "    return reading.rtt / 2 + _CLOCK_RATE * abs(at - reading.at)\n",
            "    return reading.rtt / 2\n",
            run.holds, "holds",
        )

    def test_mutant_without_the_agreement_check_bounds_a_moved_offset(self):
        line = "lan post 37.75 0.15 5098.0 1111aaaa-0000-0000-0000-00000000000a"
        run = _SyntheticCrashRun(readings={"lan post": line})
        _assert_flips(
            self,
            "        if abs(post.offset - pre.offset) > (\n",
            "        if False and abs(post.offset - pre.offset) > (\n",
            run.holds, "no window",
        )

    def test_mutant_without_the_boot_check_bounds_another_boots_stamp(self):
        run = _SyntheticCrashRun()
        run.readings = run.readings.replace(" 2222bbbb00000000000000000000000b", " 3333cccc")
        _assert_flips(
            self,
            "        if pre.boot != boot or post.boot != boot:\n",
            "        if False:\n",
            run.holds, "no window",
        )

    def test_mutant_without_the_width_cap_bounds_a_far_late_peer_loss(self):
        _assert_flips(
            self,
            "    if t_hi - t_lo > _MAX_WIDTH:\n",
            "    if False:\n",
            _SyntheticCrashRun(detect_delay=8.0).holds, "no window",
        )

    def test_mutant_without_the_integer_fallback_leaves_slow_detection_void(self):
        run = _SyntheticCrashRun(detect_delay=2.0)

        def cli(module):
            with tempfile.TemporaryDirectory() as tmp:
                line, _ = run.cli(tmp, module)
            return line.split(" ", 1)[0], line

        _assert_flips(self, '                if fallback != "VOID":\n',
                      "                if False:\n", cli, "PASS")

    def test_mutant_without_the_attribution_guard_bounds_an_early_peer_loss(self):
        _assert_flips(
            self,
            '        return None, "fw1 lost its peer before the sysrq was sent: not this crash"\n',
            "        pass\n",
            _SyntheticCrashRun(detect_delay=-1.0).holds, "no window",
        )

    def test_mutant_without_the_launch_check_bounds_a_zero_before_it(self):
        _assert_flips(
            self,
            "    if zero_hi < launch:\n",
            "    if False:\n",
            _SyntheticCrashRun(launch_shift=0.5).holds, "no window",
        )

    def test_mutant_keeping_an_older_runs_stamps_takes_no_window(self):
        _assert_flips(
            self,
            "    zeros = [stamp - end for stamp, end in samples if stamp >= launch]\n",
            "    zeros = [stamp - end for stamp, end in samples]\n",
            _SyntheticCrashRun(stale=True).holds, "holds",
        )

    def test_mutant_reading_pass_in_interval_turns_a_true_cost_into_pass(self):
        status = _assert_flips(
            self,
            "        line = RESUME_COST_SECONDS if status_lo == \"PASS\" else RESUME_FAIL_SECONDS\n",
            "        line = 99.0 if status_lo == \"PASS\" else RESUME_FAIL_SECONDS\n",
            _SyntheticCrashRun(**_FAST_BURST_COST).judge, "VOID",
        )
        self.assertEqual(status, "PASS")

    def test_mutant_reading_cost_in_interval_turns_a_true_fail_into_cost(self):
        status = _assert_flips(
            self,
            "        line = RESUME_COST_SECONDS if status_lo == \"PASS\" else RESUME_FAIL_SECONDS\n",
            "        line = RESUME_COST_SECONDS if status_lo == \"PASS\" else 99.0\n",
            _SyntheticCrashRun(**_FAST_BURST_FAIL).judge, "VOID",
        )
        self.assertEqual(status, "COST")

    def test_mutant_judging_at_the_earliest_end_only_turns_a_true_cost_row_decided(self):
        _assert_flips(
            self,
            "    if status_lo != status_hi:\n",
            "    if False:\n",
            _SyntheticCrashRun(**_TRUE_COST).judge, "VOID",
        )

    def test_mutant_resume_evidence_from_the_earliest_edge_flips_a_dead_row(self):
        # The interval starting 59.0 s lies inside [T_lo, crash): stream 11's
        # pre-crash bytes there must not read as a resume.
        _assert_flips(
            self,
            "    earliest = EventAnchor(anchor.seconds, anchor.uncertainty, anchor.source)\n",
            "    earliest = EventAnchor(anchor.seconds, 0.0, anchor.source)\n",
            _SyntheticCrashRun(crash=59.15, resumes={11: None}).judge, "FAIL",
        )

    def test_mutant_accepting_an_empty_interval_passes_a_burst(self):
        status = _assert_flips(
            self,
            "                break  # an empty one\n",
            "                pass\n",
            _SyntheticCrashRun(resumes={11: (60.0, 60.6)}).judge, "VOID",
        )
        self.assertEqual(status, "PASS")

    def test_mutant_accepting_a_gap_passes_a_missing_interval(self):
        status = _assert_flips(
            self,
            "                break  # a missing interval\n",
            "                pass\n",
            _SyntheticCrashRun(missing={11: (62,)}).judge, "VOID",
        )
        self.assertEqual(status, "PASS")

    def test_mutant_without_the_horizon_passes_telemetry_that_ends(self):
        status = _assert_flips(
            self,
            "        horizon = first[1] + RESUME_COST_SECONDS\n",
            "        horizon = first[1]\n",
            _SyntheticCrashRun(resumes={11: (60.0, 60.6)}, duration=61).judge, "VOID",
        )
        self.assertEqual(status, "PASS")

    def test_mutant_with_a_two_second_horizon_passes_third_second_silence(self):
        status = _assert_flips(
            self,
            "        horizon = first[1] + RESUME_COST_SECONDS\n",
            "        horizon = first[1] + 2.0\n",
            _SyntheticCrashRun(resumes={11: (59.8, 63.0)}).judge, "VOID",
        )
        self.assertEqual(status, "PASS")

    # The window no longer reads the realtime mapping the rejected stop
    # contradicts, so admitting the stop is not unsound by itself; the cell
    # keeps the precise path's integer fallback there all the same.
    def test_mutant_admitting_a_rejected_stop_takes_the_bounded_window(self):
        run = self.stop_rejected_run()
        realtime = dict(before=run.before, after=run.after, offset=run.rt[0], rtt=run.rt[1])

        def judge(module):
            if module.stop_seen(run.text, run.at, **realtime):
                return "integer", ""
            return run.judge(module)

        anchor = "    try:\n        return data_stop_anchor(text, lo, hi) is not None\n"
        replacement = "    try:\n        return False and data_stop_anchor(text, lo, hi) is not None\n"
        status = _assert_flips(self, anchor, replacement, judge, "integer")
        self.assertNotEqual(status, "PASS")


if __name__ == "__main__":
    unittest.main()
