#!/usr/bin/env python3
"""Counted, tagged UDP bursts for wire_routing_separation (#10136).

The sender runs inside a temporary namespace with one fixed source address
and source port for both phases. The control burst uses the veth while it is
unbound (main-table near miss); the identical probe burst uses that same veth
after it is enslaved to the manager-created empty VRF. A successful ``sendto``
is a frame handed to that ingress veth (the OFFERED side); local errors are
not counted and therefore cannot manufacture a PASS. The tag is carried in
the payload solely to separate the two bursts in one capture window.
"""

from __future__ import annotations

import argparse
import socket
import sys
import time


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", required=True)
    ap.add_argument("--source-port", required=True, type=int)
    ap.add_argument("--dst", required=True)
    ap.add_argument("--port", required=True, type=int)
    ap.add_argument("--count", required=True, type=int)
    ap.add_argument("--tag", required=True, choices=("C", "P"))
    ap.add_argument("--rate", type=float, default=500.0)
    args = ap.parse_args()
    if (
        args.count <= 0
        or args.rate < 0
        or not 1 <= args.source_port <= 65535
        or not 1 <= args.port <= 65535
    ):
        print("invalid count/rate/port", file=sys.stderr)
        return 2
    interval = 1.0 / args.rate if args.rate else 0.0
    sent = 0
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((args.src, args.source_port))
        for seq in range(args.count):
            payload = f"{args.tag}10136:{seq}:".encode() + b"x" * 32
            try:
                sock.sendto(payload, (args.dst, args.port))
            except OSError as exc:
                print(f"sendto {args.tag}{seq} failed: {exc}", file=sys.stderr)
                continue
            sent += 1
            if interval:
                time.sleep(interval)
    finally:
        sock.close()
    print(f"SENT tag={args.tag} count={sent}")
    return 0 if sent == args.count else 1


if __name__ == "__main__":
    raise SystemExit(main())
