#!/usr/bin/env python3
"""Sequence-numbered UDP continuity probe for HA transition harnesses (#18679).

The sender keeps one UDP socket and monotonically increasing sequence across
all RG moves. The target echoes each sequence with the source address/port it
saw (the NAT identity). A transition is SURVIVED when replies resume with a
higher sequence and the same observed 5-tuple; a changed identity or sequence
reset is RECREATED; no post-window replies is LOST. Sequence gaps and
reordering are recorded per window rather than mistaken for a NAT/session
identity change.
"""

from __future__ import annotations

import argparse
import os
import pathlib
import signal
import socket
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import List, Optional, Set, Tuple

MAGIC = "XPFUDP1"
PORT = 6201
INTERVAL_S = 0.1


@dataclass(frozen=True)
class ProbeLog:
    sent: Set[int]
    replies: List[Tuple[int, str, str]]


def parse_log(text: str) -> ProbeLog:
    sent: Set[int] = set()
    replies: List[Tuple[int, str, str]] = []
    for line_number, raw in enumerate((text or "").splitlines(), 1):
        parts = raw.split()
        if not parts or parts[0] not in ("SENT", "REPLY"):
            continue
        expected_fields = 2 if parts[0] == "SENT" else 4
        if len(parts) != expected_fields or not parts[1].isascii() or not parts[1].isdigit():
            raise ValueError(f"malformed {parts[0]} record at line {line_number}: {raw!r}")
        seq = int(parts[1])
        if parts[0] == "SENT":
            if seq in sent:
                raise ValueError(f"duplicate sent sequence {seq} at line {line_number}")
            sent.add(seq)
        else:
            replies.append((seq, parts[2], parts[3]))
    return ProbeLog(sent, replies)


def classify_snapshots(before_text: str, after_text: str) -> Tuple[str, str, dict]:
    """Classify two cumulative sender-log snapshots; return class, detail, metrics."""
    try:
        before = parse_log(before_text)
        after = parse_log(after_text)
    except ValueError as exc:
        return "VOID", f"UDP probe evidence malformed: {exc}", {}
    if not before.sent or not before.replies:
        return "VOID", "UDP probe has no pre-move sent-and-answered baseline", {}
    before_last = max(before.sent)
    baseline_replies = [record for record in before.replies if record[0] <= before_last]
    if not baseline_replies:
        return "VOID", "UDP probe has no pre-move reply baseline", {}
    baseline_identity = (baseline_replies[-1][1], baseline_replies[-1][2])

    # A restarted client truncates its log and restarts at sequence zero. Do
    # not let that look like an ordinary missing log tail or a quiet window.
    if not before.sent.issubset(after.sent):
        if after.sent and min(after.sent) <= before_last:
            return "RECREATED", (f"UDP probe RECREATED: sender sequence restarted or log was reset; "
                                  f"pre-move last seq was {before_last}, post-move first seq "
                                  f"is {min(after.sent)}"), {"sequence_reset": True}
        return "VOID", "UDP probe cumulative log lost pre-move records", {}
    new_sent = sorted(seq for seq in after.sent if seq > before_last)
    if not new_sent:
        return "VOID", "UDP probe sent no new sequence numbers in the post-move window", {}
    new_replies = [record for record in after.replies if record[0] > before_last]
    if any(seq not in after.sent for seq, _, _ in new_replies):
        return "VOID", "UDP probe reply references a sequence absent from the cumulative send log", {}
    if not new_replies:
        return "LOST", (f"UDP probe LOST: sent {len(new_sent)} post-move datagrams "
                        f"(seq {new_sent[0]}..{new_sent[-1]}) but received no replies"), {
                            "sent": len(new_sent), "received": 0, "lost": len(new_sent), "reordered": 0,
                        }
    for seq, ip, port in new_replies:
        identity = (ip, port)
        if identity != baseline_identity:
            return "RECREATED", (f"UDP probe RECREATED: seq {seq} arrived with translated identity "
                                  f"{ip}:{port}, baseline {baseline_identity[0]}:{baseline_identity[1]}"), {
                                      "sequence_reset": False, "identity_changed": True,
                                      "sent": len(new_sent), "received": len(new_replies),
                                  }
    if min(record[0] for record in new_replies) <= before_last:
        return "RECREATED", (f"UDP probe RECREATED: post-move sequence did not advance beyond {before_last}"), {
            "sequence_reset": True, "sent": len(new_sent), "received": len(new_replies),
        }
    replied = {seq for seq, _, _ in new_replies}
    lost = sum(1 for seq in new_sent if seq not in replied)
    reordered = sum(1 for previous, current in zip(new_replies, new_replies[1:])
                    if current[0] < previous[0])
    last_seq = max(record[0] for record in new_replies)
    metrics = {"sent": len(new_sent), "received": len(new_replies), "lost": lost,
               "reordered": reordered, "last_sequence": last_seq,
               "translated_ip": baseline_identity[0], "translated_port": baseline_identity[1]}
    return "SURVIVED", (f"UDP probe SURVIVED: sequence advanced {before_last}->{last_seq}; "
                         f"translated identity {baseline_identity[0]}:{baseline_identity[1]}; "
                         f"sent={len(new_sent)} received={len(new_replies)} lost={lost} reordered={reordered}"), metrics


def _write_record(fd: int, record: str) -> None:
    os.write(fd, (record + "\n").encode("utf-8"))


def run_sender(target: str, port: int, run_id: str, logfile: str, interval: float) -> int:
    stopping = False

    def stop(_signum, _frame):
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        address = socket.getaddrinfo(target, port, socket.AF_INET, socket.SOCK_DGRAM)[0][4]
    except OSError as exc:
        print(f"UDP probe target lookup failed for {target}:{port}: {exc}", file=sys.stderr)
        return 2
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(("", 0))
        sock.connect(address)
        sock.settimeout(min(interval / 2, 0.05))
    except OSError as exc:
        sock.close()
        print(f"UDP probe socket setup failed: {exc}", file=sys.stderr)
        return 2
    fd = os.open(logfile, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    seq = 0
    due = time.monotonic()
    try:
        while not stopping:
            now = time.monotonic()
            if now >= due:
                payload = f"{MAGIC} {run_id} {seq}".encode("ascii")
                _write_record(fd, f"SENT {seq}")
                try:
                    sock.send(payload)
                except OSError:
                    pass
                seq += 1
                due += interval
                if now - due > interval:
                    due = now + interval
            try:
                response = sock.recv(4096)
            except socket.timeout:
                continue
            except OSError:
                if stopping:
                    break
                continue
            try:
                fields = response.decode("ascii").split()
                if len(fields) != 5 or fields[0] != MAGIC or fields[1] != run_id:
                    continue
                reply_seq = int(fields[2])
                socket.inet_aton(fields[3])
                reply_port = int(fields[4])
                if not 1 <= reply_port <= 65535:
                    continue
            except (UnicodeDecodeError, ValueError, OSError):
                continue
            _write_record(fd, f"REPLY {reply_seq} {fields[3]} {reply_port}")
    finally:
        os.close(fd)
        sock.close()
    return 0


def baseline_file(path: str) -> int:
    try:
        text = pathlib.Path(path).read_text(encoding="utf-8")
        probe = parse_log(text)
    except (OSError, UnicodeError, ValueError) as exc:
        print(f"UDP probe baseline unreadable or malformed: {exc}", file=sys.stderr)
        return 2
    if not probe.sent or not probe.replies:
        print("UDP probe baseline has no sent-and-answered datagrams", file=sys.stderr)
        return 2
    print(f"UDP probe baseline: last sequence {max(probe.sent)}; "
          f"{len(probe.replies)} reply records")
    return 0


def start_sender(args) -> int:
    pidfile = pathlib.Path(args.pidfile)
    logfile = pathlib.Path(args.logfile)
    if pidfile.exists():
        try:
            old_pid = int(pidfile.read_text().strip())
            os.kill(old_pid, 0)
        except (OSError, ValueError):
            pidfile.unlink(missing_ok=True)
        else:
            print(f"UDP probe already running with PID {old_pid}", file=sys.stderr)
            return 2
    logfile.parent.mkdir(parents=True, exist_ok=True)
    log = open(logfile, "wb", buffering=0)
    child = subprocess.Popen([sys.executable, os.path.abspath(__file__), "run",
                              "--target", args.target, "--port", str(args.port),
                              "--run-id", args.run_id, "--logfile", str(logfile),
                              "--interval", str(args.interval)],
                             stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                             start_new_session=True, close_fds=True)
    log.close()
    pidfile.write_text(f"{child.pid}\n", encoding="ascii")
    print(f"UDP probe started pid={child.pid} target={args.target}:{args.port}")
    return 0


def stop_sender(args) -> int:
    pidfile = pathlib.Path(args.pidfile)
    try:
        pid = int(pidfile.read_text(encoding="ascii").strip())
    except (OSError, ValueError):
        print(f"UDP probe pid file {pidfile} is absent or malformed", file=sys.stderr)
        return 2
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        print(f"UDP probe pid {pid} is not running", file=sys.stderr)
        pidfile.unlink(missing_ok=True)
        return 2
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            break
        time.sleep(0.05)
    else:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    pidfile.unlink(missing_ok=True)
    print(f"UDP probe stopped pid={pid}")
    return 0


def classify_files(before: str, after: str) -> int:
    try:
        before_text = pathlib.Path(before).read_text(encoding="utf-8")
        after_text = pathlib.Path(after).read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        print(f"UDP probe evidence unreadable: {exc}", file=sys.stderr)
        return 2
    status, detail, _metrics = classify_snapshots(before_text, after_text)
    stream = sys.stderr if status != "SURVIVED" else sys.stdout
    print(detail, file=stream)
    return {"SURVIVED": 0, "RECREATED": 1, "LOST": 1, "VOID": 2}[status]


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    start = sub.add_parser("start")
    start.add_argument("--target", required=True)
    start.add_argument("--port", type=int, default=PORT)
    start.add_argument("--run-id", required=True)
    start.add_argument("--logfile", required=True)
    start.add_argument("--pidfile", required=True)
    start.add_argument("--interval", type=float, default=INTERVAL_S)
    run = sub.add_parser("run")
    run.add_argument("--target", required=True)
    run.add_argument("--port", type=int, default=PORT)
    run.add_argument("--run-id", required=True)
    run.add_argument("--logfile", required=True)
    run.add_argument("--interval", type=float, default=INTERVAL_S)
    stop = sub.add_parser("stop")
    stop.add_argument("--pidfile", required=True)
    classify = sub.add_parser("classify")
    classify.add_argument("before")
    classify.add_argument("after")
    baseline = sub.add_parser("baseline")
    baseline.add_argument("file")
    args = parser.parse_args(argv)
    if args.command == "start":
        return start_sender(args)
    if args.command == "run":
        return run_sender(args.target, args.port, args.run_id, args.logfile, args.interval)
    if args.command == "stop":
        return stop_sender(args)
    if args.command == "baseline":
        return baseline_file(args.file)
    return classify_files(args.before, args.after)


if __name__ == "__main__":
    raise SystemExit(main())
