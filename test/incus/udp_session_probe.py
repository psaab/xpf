#!/usr/bin/env python3
"""Sequence-numbered UDP continuity probe for HA transition harnesses (#18679).

The sender keeps one UDP socket, boot nonce, and monotonically increasing
sequence across RG moves. The target echoes the post-NAT source identity. A
transition-boundary checkpoint excludes packets emitted before the move was
confirmed: RG1 waits for owner landing, and the directed soak command confirms
its transfer commit. The firewall Session ID on the promoted node is the
primary incarnation test. A changed ID or translated identity is RECREATED,
unanswered confirmed sends are LOST, and stable ID plus post-checkpoint replies
is SURVIVED. Sender restart is VOID.
"""

from __future__ import annotations

import argparse
import os
import pathlib
import re
import secrets
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
BOOT_ID_HEX_LEN = 32


@dataclass(frozen=True)
class ProbeLog:
    sent: Set[int]
    replies: List[Tuple[int, str, str]]
    boot_ids: Tuple[str, ...]
    socket_tuple: Optional[Tuple[str, int, str, int]]


def parse_log(text: str) -> ProbeLog:
    sent: Set[int] = set()
    replies: List[Tuple[int, str, str]] = []
    boot_ids: List[str] = []
    socket_tuple = None
    for line_number, raw in enumerate((text or "").splitlines(), 1):
        parts = raw.split()
        if not parts:
            continue
        kind = parts[0]
        if kind == "BOOT":
            if (len(parts) != 2 or len(parts[1]) != BOOT_ID_HEX_LEN
                    or any(char not in "0123456789abcdef" for char in parts[1])):
                raise ValueError(f"malformed BOOT record at line {line_number}: {raw!r}")
            boot_ids.append(parts[1])
        elif kind == "SOCKET":
            if len(parts) != 5 or socket_tuple is not None:
                raise ValueError(f"malformed or duplicate SOCKET record at line {line_number}: {raw!r}")
            try:
                socket.inet_aton(parts[1])
                source_port = int(parts[2])
                socket.inet_aton(parts[3])
                target_port = int(parts[4])
            except (OSError, ValueError) as exc:
                raise ValueError(f"malformed SOCKET record at line {line_number}: {raw!r}") from exc
            if not 1 <= source_port <= 65535 or not 1 <= target_port <= 65535:
                raise ValueError(f"invalid SOCKET port at line {line_number}: {raw!r}")
            socket_tuple = (parts[1], source_port, parts[3], target_port)
        elif kind in ("SENT", "REPLY"):
            expected_fields = 2 if kind == "SENT" else 4
            if len(parts) != expected_fields or not parts[1].isascii() or not parts[1].isdigit():
                raise ValueError(f"malformed {kind} record at line {line_number}: {raw!r}")
            seq = int(parts[1])
            if kind == "SENT":
                if seq in sent:
                    raise ValueError(f"duplicate sent sequence {seq} at line {line_number}")
                sent.add(seq)
            else:
                replies.append((seq, parts[2], parts[3]))
    if len(boot_ids) > 1:
        raise ValueError("probe log contains more than one boot nonce")
    return ProbeLog(sent, replies, tuple(boot_ids), socket_tuple)

def same_client_identity(before_text: str, after_text: str) -> Tuple[bool, str]:
    """Require the same boot nonce and local tuple across adjacent snapshots."""
    try:
        before = parse_log(before_text)
        after = parse_log(after_text)
    except ValueError as exc:
        return False, f"UDP probe evidence malformed: {exc}"
    if not before.boot_ids or not after.boot_ids:
        return False, "UDP probe snapshot is missing its boot nonce"
    if before.boot_ids != after.boot_ids:
        return False, "UDP probe sender boot nonce changed"
    if before.socket_tuple is None or after.socket_tuple is None:
        return False, "UDP probe snapshot is missing its client socket tuple"
    if before.socket_tuple != after.socket_tuple:
        return False, "UDP probe client socket tuple changed"
    return True, "UDP probe client identity persisted"


# #19038: the remote `cli` lists at most 100 rows per node section unless the
# command passes `limit` (cmd/cli/show_flow.go; the product side is #19039).
# The rows come in BPF hash order, which depends on each node's map seed, so
# on a busy node an unfiltered listing omitted the probe's flow on one node
# and showed it on the other, and that changed with every new probe socket.
# The query therefore names the probe's exact tuple and an explicit limit.
SESSION_QUERY_LIMIT = 10000

_TOTAL_SESSIONS_RE = re.compile(r"^\s*Total sessions(?:\s*\([^)]*\))?:\s*([0-9]+)\s*$")


def session_query_for_probe(probe_text: str) -> str:
    """The `show security flow session` command listing exactly this probe's flow."""
    probe = parse_log(probe_text)
    if probe.socket_tuple is None:
        raise ValueError("probe log has no client SOCKET tuple")
    source_ip, source_port, target_ip, target_port = probe.socket_tuple
    return (f"show security flow session source-prefix {source_ip}/32 source-port {source_port} "
            f"destination-prefix {target_ip}/32 destination-port {target_port} "
            f"protocol udp limit {SESSION_QUERY_LIMIT}")


def session_id_for_probe(probe_text: str, session_text: str) -> Optional[str]:
    """Return the local firewall Session ID for this exact UDP flow tuple.

    None ("absent") comes only from a COMPLETE local section: its
    `Total sessions: N` terminator is present and N equals the rows shown.
    A listing that is truncated or has no terminator cannot prove absence
    (#19038), so it raises ValueError and the caller reports it as
    unreadable, never as "absent on the synced standby".
    """
    probe = parse_log(probe_text)
    if probe.socket_tuple is None:
        raise ValueError("probe log has no client SOCKET tuple")
    source_ip, source_port, target_ip, target_port = probe.socket_tuple
    flow = re.compile(
        rf"\bIn:\s*{re.escape(source_ip)}/{source_port}\s*-->\s*"
        rf"{re.escape(target_ip)}/{target_port};udp(?:,|\s|$)", re.IGNORECASE)
    current_id = None
    matches = []
    node_headers = 0
    rows = 0
    total = None
    for line_number, line in enumerate((session_text or "").splitlines(), 1):
        if re.match(r"^node[0-9]+:", line):
            node_headers += 1
            if node_headers == 2:
                break
            continue
        match = re.match(r"^\s*Session ID:\s*([0-9]+)(?:,|\s|$)", line)
        if match:
            rows += 1
            current_id = match.group(1)
            continue
        total_match = _TOTAL_SESSIONS_RE.match(line)
        if total_match:
            if total is not None:
                raise ValueError(f"local session listing has a second 'Total sessions:' line at line {line_number}")
            total = int(total_match.group(1))
            continue
        if current_id is not None and flow.search(line):
            matches.append(current_id)
            current_id = None
    if len(matches) > 1:
        raise ValueError(f"probe tuple matched multiple local firewall sessions: {matches}")
    if matches:
        return matches[0]
    if total is None:
        raise ValueError("local session listing has no 'Total sessions:' terminator; "
                         "the probe flow's absence is unreadable")
    if total != rows:
        raise ValueError(f"local session listing shows {rows} rows but reports 'Total sessions: {total}' "
                         "(truncated); the probe flow's absence is unreadable")
    return None


def classify_snapshots(before_text: str, checkpoint_text: str, after_text: str,
                       before_session_id: Optional[str],
                       after_session_id: Optional[str]) -> Tuple[str, str, dict]:
    """Classify replies after a transition-boundary checkpoint and Session ID comparison."""
    try:
        before = parse_log(before_text)
        checkpoint = parse_log(checkpoint_text)
        after = parse_log(after_text)
    except ValueError as exc:
        return "VOID", f"UDP probe evidence malformed: {exc}", {}

    # Establish that the probe is one continuous, usable client before using
    # Session IDs to claim recreation. A changed boot/socket or empty baseline is
    # VOID evidence, even if the flow IDs differ.
    if not before_session_id:
        return "VOID", "UDP probe had no matching firewall session in the synced pre-move baseline", {}
    if before.boot_ids != checkpoint.boot_ids or checkpoint.boot_ids != after.boot_ids:
        return "VOID", (f"UDP probe sender restarted (boot nonce "
                        f"{before.boot_ids!r}->{checkpoint.boot_ids!r}->{after.boot_ids!r}); "
                        "sequence continuity is unusable"), {}
    if (not before.boot_ids or before.socket_tuple is None
            or checkpoint.socket_tuple is None or after.socket_tuple is None):
        return "VOID", "UDP probe is missing its boot nonce or client socket tuple", {}
    if before.socket_tuple != checkpoint.socket_tuple or checkpoint.socket_tuple != after.socket_tuple:
        return "VOID", "UDP probe client socket tuple changed across the move", {}
    if not before.sent or not before.replies:
        return "VOID", "UDP probe has no pre-move sent-and-answered baseline", {}
    if not before.sent.issubset(checkpoint.sent) or not checkpoint.sent.issubset(after.sent):
        return "VOID", "UDP probe cumulative log lost confirmed-send records", {}
    for probe in (before, checkpoint, after):
        if any(seq not in probe.sent for seq, _, _ in probe.replies):
            return "VOID", "UDP probe reply references a sequence absent from the confirmed-send log", {}
    baseline_replies = [record for record in before.replies if record[0] <= max(before.sent)]
    if not baseline_replies:
        return "VOID", "UDP probe has no pre-move reply baseline", {}
    baseline_identity = (baseline_replies[-1][1], baseline_replies[-1][2])

    # A session-ID change is meaningful only with a validated, continuous
    # client baseline; otherwise the sender may have created a new flow itself.
    if after_session_id and before_session_id != after_session_id:
        return "RECREATED", (f"UDP probe RECREATED: firewall Session ID changed "
                             f"{before_session_id}->{after_session_id}"), {
                                 "session_id_before": before_session_id,
                                 "session_id_after": after_session_id,
                             }

    # The checkpoint is taken after the move is confirmed: the owner poll for
    # standalone RG1 and the transfer-committed CLI reply for the directed soak.
    # Only later successful sends can prove post-transition forwarding.
    checkpoint_last = max(checkpoint.sent)
    new_sent = sorted(seq for seq in after.sent if seq > checkpoint_last)
    if not new_sent:
        return "VOID", "UDP probe made no confirmed sends after the transition checkpoint", {}
    new_replies = [record for record in after.replies if record[0] > checkpoint_last]
    if not new_replies:
        return "LOST", (f"UDP probe LOST: confirmed {len(new_sent)} post-move datagrams "
                        f"(seq {new_sent[0]}..{new_sent[-1]}) but received no replies"), {
                            "sent": len(new_sent), "received": 0, "lost": len(new_sent), "reordered": 0,
                            "session_id_before": before_session_id,
                        }
    for seq, ip, port in new_replies:
        identity = (ip, port)
        if identity != baseline_identity:
            return "RECREATED", (f"UDP probe RECREATED: seq {seq} arrived with translated identity "
                                  f"{ip}:{port}, baseline {baseline_identity[0]}:{baseline_identity[1]}"), {
                                      "identity_changed": True, "sent": len(new_sent),
                                      "received": len(new_replies),
                                      "session_id_before": before_session_id,
                                      "session_id_after": after_session_id,
                                  }
    if not after_session_id:
        return "VOID", "UDP probe replies arrived but the post-move firewall session identity was unavailable", {}
    replied = {seq for seq, _, _ in new_replies}
    lost = sum(1 for seq in new_sent if seq not in replied)
    reordered = sum(1 for previous, current in zip(new_replies, new_replies[1:])
                    if current[0] < previous[0])
    last_seq = max(record[0] for record in new_replies)
    metrics = {"sent": len(new_sent), "received": len(new_replies), "lost": lost,
               "reordered": reordered, "last_sequence": last_seq,
               "translated_ip": baseline_identity[0], "translated_port": baseline_identity[1],
               "session_id_before": before_session_id, "session_id_after": after_session_id}
    return "SURVIVED", (f"UDP probe SURVIVED: firewall Session ID {before_session_id} persisted; "
                         f"sequence advanced {checkpoint_last}->{last_seq}; translated identity "
                         f"{baseline_identity[0]}:{baseline_identity[1]}; sent={len(new_sent)} "
                         f"received={len(new_replies)} lost={lost} reordered={reordered}"), metrics


def combine_classifications(checks: List[Tuple[str, str, dict]]) -> Tuple[str, str, dict]:
    """Aggregate CLI-window evidence, preserving the most severe measured result."""
    if not checks:
        return "VOID", "UDP probe has no per-move windows", {}
    statuses = [check[0] for check in checks]
    if "RECREATED" in statuses:
        status = "RECREATED"
    elif "LOST" in statuses:
        status = "LOST"
    elif "VOID" in statuses:
        status = "VOID"
    else:
        status = "SURVIVED"
    detail = "; ".join(f"move-{index + 1} {check[0]}: {check[1]}"
                       for index, check in enumerate(checks))
    return status, detail, {"checks": [check[2] for check in checks]}


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
        source_ip, source_port = sock.getsockname()[:2]
    except OSError as exc:
        sock.close()
        print(f"UDP probe socket setup failed: {exc}", file=sys.stderr)
        return 2
    fd = os.open(logfile, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    boot_id = secrets.token_hex(16)
    _write_record(fd, f"BOOT {boot_id}")
    _write_record(fd, f"SOCKET {source_ip} {source_port} {address[0]} {port}")
    seq = 0
    due = time.monotonic()
    try:
        while not stopping:
            now = time.monotonic()
            if now >= due:
                payload = f"{MAGIC} {run_id} {boot_id} {seq}".encode("ascii")
                try:
                    if sock.send(payload) != len(payload):
                        raise OSError("short UDP datagram send")
                except OSError:
                    _write_record(fd, f"SENDERR {seq}")
                else:
                    _write_record(fd, f"SENT {seq}")
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
                if (len(fields) != 6 or fields[0] != MAGIC or fields[1] != run_id
                        or fields[2] != boot_id):
                    continue
                reply_seq = int(fields[3])
                socket.inet_aton(fields[4])
                reply_port = int(fields[5])
                if not 1 <= reply_port <= 65535:
                    continue
            except (UnicodeDecodeError, ValueError, OSError):
                continue
            _write_record(fd, f"REPLY {reply_seq} {fields[4]} {reply_port}")
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
    if not probe.sent or not probe.replies or not probe.boot_ids or not probe.socket_tuple:
        print("UDP probe baseline has no boot nonce, socket tuple, or sent-and-answered datagrams",
              file=sys.stderr)
        return 2
    print(f"UDP probe baseline: last sequence {max(probe.sent)}; "
          f"{len(probe.replies)} reply records; boot={probe.boot_ids[0]}")
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


def session_id_file(probe_path: str, session_path: str) -> int:
    try:
        probe_text = pathlib.Path(probe_path).read_text(encoding="utf-8")
        session_text = pathlib.Path(session_path).read_text(encoding="utf-8")
        session_id = session_id_for_probe(probe_text, session_text)
    except (OSError, UnicodeError, ValueError) as exc:
        print(f"UDP probe session identity unreadable: {exc}", file=sys.stderr)
        return 2
    if session_id is None:
        print("NONE")
        return 0
    print(session_id)
    return 0

def session_query_file(probe_path: str) -> int:
    """Print the tuple-filtered session query for the shell caller (#19038)."""
    try:
        probe_text = pathlib.Path(probe_path).read_text(encoding="utf-8")
        query = session_query_for_probe(probe_text)
    except (OSError, UnicodeError, ValueError) as exc:
        print(f"UDP probe session query unbuildable: {exc}", file=sys.stderr)
        return 2
    print(query)
    return 0


def same_client_files(before: str, after: str) -> int:
    try:
        before_text = pathlib.Path(before).read_text(encoding="utf-8")
        after_text = pathlib.Path(after).read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        print(f"UDP probe identity unreadable: {exc}", file=sys.stderr)
        return 2
    matches, detail = same_client_identity(before_text, after_text)
    stream = sys.stdout if matches else sys.stderr
    print(detail, file=stream)
    return 0 if matches else 2


def classify_files(before: str, checkpoint: str, after: str, before_session_id: str,
                   after_session_id: str) -> int:
    try:
        before_text = pathlib.Path(before).read_text(encoding="utf-8")
        checkpoint_text = pathlib.Path(checkpoint).read_text(encoding="utf-8")
        after_text = pathlib.Path(after).read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        print(f"UDP probe evidence unreadable: {exc}", file=sys.stderr)
        return 2
    before_session_id = None if before_session_id in ("", "NONE") else before_session_id
    after_session_id = None if after_session_id in ("", "NONE") else after_session_id
    status, detail, _metrics = classify_snapshots(
        before_text, checkpoint_text, after_text, before_session_id, after_session_id)
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
    classify.add_argument("checkpoint")
    classify.add_argument("after")
    classify.add_argument("--before-session-id", required=True)
    classify.add_argument("--after-session-id", required=True)
    session_id = sub.add_parser("session-id")
    session_id.add_argument("probe_log")
    session_id.add_argument("session_capture")
    session_query = sub.add_parser("session-query")
    session_query.add_argument("probe_log")
    baseline = sub.add_parser("baseline")
    same_client = sub.add_parser("same-client")
    same_client.add_argument("before")
    same_client.add_argument("after")
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
    if args.command == "session-id":
        return session_id_file(args.probe_log, args.session_capture)
    if args.command == "session-query":
        return session_query_file(args.probe_log)
    if args.command == "same-client":
        return same_client_files(args.before, args.after)
    return classify_files(args.before, args.checkpoint, args.after,
                          args.before_session_id, args.after_session_id)


if __name__ == "__main__":
    raise SystemExit(main())
