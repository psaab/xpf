#!/usr/bin/env python3
"""Small owned TCP listener/client for the conntrack lifecycle gate.

The listener keeps accepted sockets open until its deadline and echoes bytes.
The client sends a heartbeat so the firewall session is observable as live;
the harness terminates it before the idle-expiry phase.
"""
from __future__ import annotations

import argparse
import socket
import threading
import time


def serve(port: int, duration: float) -> None:
    end = time.monotonic() + duration
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", port))
        srv.listen(128)
        srv.settimeout(0.5)
        print(f"LISTEN port={port}", flush=True)
        workers: list[threading.Thread] = []
        while time.monotonic() < end:
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            worker = threading.Thread(target=hold, args=(conn, end), daemon=True)
            worker.start()
            workers.append(worker)
        for worker in workers:
            worker.join(timeout=1.0)


def hold(conn: socket.socket, end: float) -> None:
    with conn:
        conn.settimeout(0.5)
        while time.monotonic() < end:
            try:
                data = conn.recv(4096)
            except socket.timeout:
                continue
            except OSError:
                return
            if not data:
                return
            try:
                conn.sendall(data)
            except OSError:
                return


def recv_exact(conn: socket.socket, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = conn.recv(remaining)
        if not chunk:
            raise RuntimeError("echo listener closed before full response")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def client(
    host: str,
    port: int,
    duration: float,
    heartbeat: float,
    silent_after: float | None,
    post_after: float | None,
    post_count: int,
    source_port: int | None,
) -> None:
    start = time.monotonic()
    end = start + duration
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
        conn.settimeout(5.0)
        if source_port is not None:
            conn.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            conn.bind(("", source_port))
        conn.connect((host, port))
        conn.settimeout(2.0)
        create = b"wire-conntrack-create"
        conn.sendall(create)
        if recv_exact(conn, len(create)) != create:
            raise RuntimeError("echo listener did not acknowledge create payload")
        print(f"CONNECTED host={host} port={port}", flush=True)
        next_post = post_after
        posted = False
        while time.monotonic() < end:
            elapsed = time.monotonic() - start
            if (
                not posted
                and next_post is not None
                and elapsed >= next_post
            ):
                payload = b"wire-conntrack-expired-payload"
                sent = 0
                for _ in range(post_count):
                    try:
                        conn.sendall(payload)
                    except OSError:
                        break
                    sent += 1
                print(f"POST_SENT {sent}", flush=True)
                posted = True
            heartbeat_allowed = silent_after is None or elapsed < silent_after
            if heartbeat_allowed:
                beat = b"heartbeat"
                conn.sendall(beat)
                if recv_exact(conn, len(beat)) != beat:
                    raise RuntimeError("echo listener lost heartbeat")
            time.sleep(max(0.05, heartbeat))


def main() -> None:
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--serve", type=int)
    group.add_argument("--client", nargs=2, metavar=("HOST", "PORT"))
    parser.add_argument("--duration", type=float, default=120.0)
    parser.add_argument("--heartbeat", type=float, default=1.0)
    parser.add_argument("--silent-after", type=float, default=None)
    parser.add_argument("--post-after", type=float, default=None)
    parser.add_argument("--post-count", type=int, default=0)
    parser.add_argument("--source-port", type=int, default=None)
    args = parser.parse_args()
    if args.serve is not None:
        serve(args.serve, args.duration)
    else:
        client(
            args.client[0],
            int(args.client[1]),
            args.duration,
            args.heartbeat,
            args.silent_after,
            args.post_after,
            args.post_count,
            args.source_port,
        )


if __name__ == "__main__":
    main()


