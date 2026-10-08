#!/usr/bin/env python3
"""Counted, tagged UDP bursts for the wire_routing_separation gate (#10136).

The harness sender offers an exact-tuple reference burst (tag C) before the
steering term is committed. After commit it offers a near-miss control (tag N)
through the existing main-table route, with only the destination port changed
so the exact-match FBF term does not apply. It then sends the probe (tag P)
with the original tuple into an owned, manager-created empty routing
instance. The peer-side capture spans all three bursts; the post-commit
near-miss control must be observed and the probe must not emerge.

With WIRE_BROKEN_FIXTURE=1, the harness inserts a temporary explicit accept
before the routing-instance term. That intentionally bypasses steering to the
proven main route. It demonstrates capture/verdict liveness, but does not test
fallthrough from an empty selected-VRF table to main.

A successful sendto counts as OFFERED, not proof that the dataplane received
the frame; only peer-side capture counts as observed. Payload tags distinguish
the bursts in the shared capture window.
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
    ap.add_argument("--tag", required=True, choices=("C", "N", "P"))
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
