#!/usr/bin/env python3
"""Prove stale N cannot certify a post-outage probe; interleaved N/P must VOID."""
from __future__ import annotations

import collections
import pathlib
import socket
import subprocess
import sys
import threading
import time

HERE = pathlib.Path(__file__).resolve().parent
SENDER = HERE / "wire_routing_probe.py"
VERDICT_LIB = HERE / "wire-gate-lib.sh"


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def sender(*, port: int, count: int, tag: str, extra: tuple[str, ...] = ()) -> str:
    source_port = free_port()
    cmd = [
        sys.executable, str(SENDER), "--src", "127.0.0.1",
        "--source-port", str(source_port), "--dst", "127.0.0.1",
        "--port", str(port), "--count", str(count), "--tag", tag,
        "--rate", "0", *extra,
    ]
    result = subprocess.run(cmd, text=True, capture_output=True, timeout=20)
    if result.returncode != 0:
        raise AssertionError(f"sender failed rc={result.returncode}: {result.stdout}{result.stderr}")
    return result.stdout


def verdict(*, near_observed: int) -> tuple[int, str]:
    result = subprocess.run(
        [
            "bash", "-c",
            'source "$1"; shift; wire_routing_separation_verdict "$@"',
            "bash", str(VERDICT_LIB), "1000", "0", "1500", "1500", "0",
            "1500", str(near_observed),
        ],
        text=True,
        capture_output=True,
        timeout=5,
    )
    return result.returncode, result.stdout.strip()


def main() -> int:
    probe_relay = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    probe_relay.bind(("127.0.0.1", 0))
    probe_relay.settimeout(0.1)
    probe_port = probe_relay.getsockname()[1]
    control_relay = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    control_relay.bind(("127.0.0.1", 0))
    control_relay.settimeout(0.1)
    control_port = control_relay.getsockname()[1]
    if probe_port == control_port:
        raise AssertionError("relay legs unexpectedly share a destination port")
    peer_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    peer_sock.bind(("127.0.0.1", 0))
    peer_sock.settimeout(0.1)
    peer = peer_sock.getsockname()

    condition = threading.Condition()
    forwarded = True
    stopped = False
    relay_counts: collections.Counter[str] = collections.Counter()
    peer_counts: collections.Counter[str] = collections.Counter()
    peer_sequence: list[str] = []

    def relay(sock: socket.socket) -> None:
        nonlocal forwarded, stopped
        while True:
            try:
                payload, _ = sock.recvfrom(2048)
            except socket.timeout:
                with condition:
                    if stopped:
                        return
                continue
            tag = chr(payload[0])
            with condition:
                relay_counts[tag] += 1
                do_forward = forwarded
                condition.notify_all()
            if do_forward:
                sock.sendto(payload, peer)

    def receive_peer() -> None:
        nonlocal stopped
        while True:
            try:
                payload, _ = peer_sock.recvfrom(2048)
            except socket.timeout:
                with condition:
                    if stopped:
                        return
                continue
            tag = chr(payload[0])
            with condition:
                peer_counts[tag] += 1
                peer_sequence.append(tag)
                condition.notify_all()

    relay_threads = [
        threading.Thread(target=relay, args=(sock,), daemon=True)
        for sock in (probe_relay, control_relay)
    ]
    peer_thread = threading.Thread(target=receive_peer, daemon=True)
    for thread in relay_threads:
        thread.start()
    peer_thread.start()

    def wait_for(counter: collections.Counter[str], tag: str, count: int) -> None:
        deadline = time.monotonic() + 5
        with condition:
            while counter[tag] < count:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise AssertionError(f"timed out waiting for {tag}={count}: got {counter[tag]}")
                condition.wait(remaining)

    try:
        # Verify the sender's actual packet order on one receiver socket.
        order_out = sender(
            port=probe_port,
            count=3,
            tag="P",
            extra=(
                "--interleave", "--interleave-control-port", str(probe_port),
                "--interleave-control-count", "3", "--interleave-control-tag", "N",
            ),
        )
        wait_for(peer_counts, "N", 3)
        wait_for(peer_counts, "P", 3)
        with condition:
            order = peer_sequence[:6]
        if order != ["N", "P", "N", "P", "N", "P"]:
            raise AssertionError(f"sender did not interleave N before P: {order}")
        if "SENT tag=P count=3" not in order_out or "SENT tag=N count=3" not in order_out:
            raise AssertionError(f"sender smoke counts were incomplete: {order_out}")

        c_out = sender(port=probe_port, count=1500, tag="C")
        n_out = sender(port=control_port, count=1500, tag="N")
        wait_for(peer_counts, "C", 1500)
        wait_for(peer_counts, "N", 1503)
        if "SENT tag=C count=1500" not in c_out or "SENT tag=N count=1500" not in n_out:
            raise AssertionError("initial C/N sender counts were not complete")
        with condition:
            initial_near_miss_observed = peer_counts["N"] - 3
        if initial_near_miss_observed != 1500:
            raise AssertionError(f"initial near-miss count was {initial_near_miss_observed}, not 1500")

        # Reproduce the reviewed C -> N -> outage -> P sequence. The old
        # aggregate oracle accepts this stale control despite a dead P path.
        with condition:
            forwarded = False
        p_out = sender(port=probe_port, count=1000, tag="P")
        wait_for(relay_counts, "P", 1003)
        with condition:
            if peer_counts["P"] != 3:
                raise AssertionError(f"probe crossed the forwarding outage: {peer_counts['P'] - 3}")
        if "SENT tag=P count=1000" not in p_out:
            raise AssertionError(f"legacy probe sender count was incomplete: {p_out}")
        red_rc, red_out = verdict(near_observed=initial_near_miss_observed)
        if red_rc != 0 or " WIRE_GATE wire_routing_separation PASS " not in f" {red_out} ":
            raise AssertionError(f"RED-before repro did not reproduce false PASS: {red_out} rc={red_rc}")

        # The live gate scores only near-miss packets interleaved with P
        # inside the probe window. Neither tag is forwarded during this outage.
        with condition:
            n_before = peer_counts["N"]
            p_before = peer_counts["P"]
        interleaved = sender(
            port=probe_port,
            count=1000,
            tag="P",
            extra=(
                "--interleave", "--interleave-control-port", str(control_port),
                "--interleave-control-count", "1500", "--interleave-control-tag", "N",
            ),
        )
        wait_for(relay_counts, "N", 3003)
        wait_for(relay_counts, "P", 2003)
        with condition:
            n_window_observed = peer_counts["N"] - n_before
            p_window_observed = peer_counts["P"] - p_before
        if "SENT tag=P count=1000" not in interleaved or "SENT tag=N count=1500" not in interleaved:
            raise AssertionError(f"interleaved sender count mismatch: {interleaved}")
        if n_window_observed != 0 or p_window_observed != 0:
            raise AssertionError(
                f"interleaved traffic crossed outage: N={n_window_observed} P={p_window_observed}"
            )
        green_rc, green_out = verdict(near_observed=n_window_observed)
        if green_rc != 2 or "VOID reason=capture-blind" not in green_out:
            raise AssertionError(f"outage in probe window did not VOID: {green_out} rc={green_rc}")

        print(f"RED-before: C=1500/1500 N=1500/1500 P=1000/0 => {red_out} (exit {red_rc})")
        print(
            f"GREEN-after: interleaved N=1500/{n_window_observed} "
            f"P=1000/{p_window_observed} => {green_out} (exit {green_rc})"
        )
        return 0
    finally:
        with condition:
            stopped = True
            condition.notify_all()
        for thread in relay_threads:
            thread.join(timeout=1)
        peer_thread.join(timeout=1)
        probe_relay.close()
        control_relay.close()
        peer_sock.close()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"temporal regression failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
