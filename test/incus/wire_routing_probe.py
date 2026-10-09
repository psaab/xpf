#!/usr/bin/env python3
"""Counted, tagged UDP bursts for the wire_routing_separation gate (#10136).

The harness sender offers an exact-tuple reference burst (tag C) before the
steering term is committed. After commit it offers the near-miss control (tag
N) and probe (tag P) interleaved on one socket. The near miss follows the
existing main-table route; only its destination port differs from the
exact-match FBF-steered probe. The peer-side capture spans all three legs.
The sender emits `control_count - count` control frames after all probes
(500 by default, at least 100); the gate measures the first 100 frames.

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

INTERLEAVE_TAIL_FLOOR = 100


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", required=True)
    ap.add_argument("--source-port", required=True, type=int)
    ap.add_argument("--dst", required=True)
    ap.add_argument("--port", required=True, type=int)
    ap.add_argument("--count", required=True, type=int)
    ap.add_argument("--tag", required=True, choices=("C", "N", "P"))
    ap.add_argument("--rate", type=float, default=500.0)
    ap.add_argument("--interleave", action="store_true",
                    help="interleave control before each probe, then send a control tail after")
    ap.add_argument("--interleave-control-port", type=int)
    ap.add_argument(
        "--interleave-control-count",
        type=int,
        help=f"must exceed --count by at least {INTERLEAVE_TAIL_FLOOR} for a post-probe tail",
    )
    ap.add_argument("--interleave-control-tag", choices=("C", "N", "P"))
    args = ap.parse_args()
    control_args = (
        args.interleave_control_port,
        args.interleave_control_count,
        args.interleave_control_tag,
    )
    if args.interleave != all(value is not None for value in control_args):
        ap.error("--interleave requires control port, count, and tag")
    if not args.interleave and any(value is not None for value in control_args):
        ap.error("interleave control options require --interleave")
    if (
        args.count <= 0
        or args.rate < 0
        or not 1 <= args.source_port <= 65535
        or not 1 <= args.port <= 65535
        or (
            args.interleave
            and (
                args.interleave_control_count < args.count + INTERLEAVE_TAIL_FLOOR
                or not 1 <= args.interleave_control_port <= 65535
                or args.interleave_control_tag == args.tag
            )
        )
    ):
        print("invalid count/rate/port or interleave leg", file=sys.stderr)
        return 2
    interval = 1.0 / args.rate if args.rate else 0.0
    sent = {args.tag: 0}
    if args.interleave:
        sent[args.interleave_control_tag] = 0
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((args.src, args.source_port))

        def send(tag: str, seq: int, port: int) -> None:
            try:
                sock.sendto(
                    f"{tag}10136:{seq}:".encode() + b"x" * 32,
                    (args.dst, port),
                )
            except OSError as exc:
                print(f"sendto {tag}{seq} failed: {exc}", file=sys.stderr)
                return
            sent[tag] += 1

        if args.interleave:
            # The first 100 control packets after the probe burst test
            # liveness at the boundary immediately beyond its final packet.
            for seq in range(args.count):
                send(args.interleave_control_tag, seq, args.interleave_control_port)
                if interval:
                    time.sleep(interval)
                send(args.tag, seq, args.port)
                if interval:
                    time.sleep(interval)
            for seq in range(args.count, args.interleave_control_count):
                send(args.interleave_control_tag, seq, args.interleave_control_port)
                if interval:
                    time.sleep(interval)
        else:
            for seq in range(args.count):
                send(args.tag, seq, args.port)
                if interval:
                    time.sleep(interval)
    finally:
        sock.close()
    print(f"SENT tag={args.tag} count={sent[args.tag]}")
    if args.interleave:
        print(
            f"SENT tag={args.interleave_control_tag} "
            f"count={sent[args.interleave_control_tag]}"
        )
        return 0 if (
            sent[args.tag] == args.count
            and sent[args.interleave_control_tag] == args.interleave_control_count
        ) else 1
    return 0 if sent[args.tag] == args.count else 1


if __name__ == "__main__":
    raise SystemExit(main())
