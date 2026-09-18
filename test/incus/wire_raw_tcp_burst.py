#!/usr/bin/env python3
"""Emit counted IPv4 TCP ACK/PSH segments for wire conntrack tests.

This intentionally does not perform a handshake. Each successful raw send is
an offered mid-stream frame for an existing (or never-created) tuple; a peer
capture, not sendto success, decides whether it leaked through the DUT.
"""
from __future__ import annotations

import argparse
import socket
import struct
import time


def checksum(data: bytes) -> int:
    if len(data) & 1:
        data += b"\0"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def packet(src: str, dst: str, sport: int, dport: int, seq: int, ack: int, payload: bytes) -> bytes:
    tcp = struct.pack("!HHIIHHHH", sport, dport, seq, ack, (5 << 12) | 0x18, 65535, 0, 0) + payload
    pseudo = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack("!BBH", 0, socket.IPPROTO_TCP, len(tcp))
    tcp = bytearray(tcp)
    struct.pack_into("!H", tcp, 16, checksum(pseudo + tcp))
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 0, 0x4000, 64, socket.IPPROTO_TCP, 0, socket.inet_aton(src), socket.inet_aton(dst))
    ip = bytearray(ip)
    struct.pack_into("!H", ip, 10, checksum(ip))
    return bytes(ip) + bytes(tcp)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", required=True)
    ap.add_argument("--dst", required=True)
    ap.add_argument("--sport", type=int, required=True)
    ap.add_argument("--dport", type=int, required=True)
    ap.add_argument("--count", type=int, required=True)
    ap.add_argument("--payload-size", type=int, default=64)
    ap.add_argument("--rate", type=float, default=2000.0)
    args = ap.parse_args()
    if args.count <= 0 or args.payload_size < 1 or args.rate <= 0:
        return 2
    payload = b"W" * args.payload_size
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    interval = 1.0 / args.rate
    sent = 0
    for i in range(args.count):
        try:
            sock.sendto(packet(args.src, args.dst, args.sport, args.dport, i + 1, 1, payload), (args.dst, 0))
            sent += 1
        except OSError:
            break
        time.sleep(interval)
    print(f"SENT raw={sent}", flush=True)
    return 0 if sent == args.count else 1


if __name__ == "__main__":
    raise SystemExit(main())
