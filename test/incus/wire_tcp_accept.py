#!/usr/bin/env python3
"""One-shot TCP acceptor for the #9531 wire-appmatch-twins gate.

Listens on --port for --duration seconds, accepting connections,
reading a little, replying, and closing. Every completed or refused
handshake proves its SYN crossed the firewall; the peer-side capture —
not this script — counts them.

Usage on the sink host (run under `timeout` remotely, killed by the gate):
    python3 wire_tcp_accept.py --port 80 --duration 120
"""

import argparse
import socket
import sys
import time


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--duration", type=float, default=120.0)
    args = ap.parse_args()
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind(("0.0.0.0", args.port))
    except OSError as exc:
        print("bind %d failed: %s" % (args.port, exc), file=sys.stderr)
        return 2
    srv.listen(100)
    print("LISTENING %d" % args.port, flush=True)
    srv.settimeout(1.0)
    accepted = 0
    end = time.time() + args.duration
    while time.time() < end:
        try:
            conn, _ = srv.accept()
        except socket.timeout:
            continue
        except OSError as exc:
            print("accept failed: %s" % exc, file=sys.stderr)
            break
        accepted += 1
        try:
            conn.settimeout(2.0)
            conn.recv(64)
            conn.sendall(b"ok")
        except OSError:
            pass
        try:
            conn.close()
        except OSError:
            pass
    print("ACCEPTED %d" % accepted)
    return 0


if __name__ == "__main__":
    sys.exit(main())
