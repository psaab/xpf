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


def sender(
    *, port: int, count: int, tag: str, rate: int = 0, extra: tuple[str, ...] = ()
) -> str:
    source_port = free_port()
    cmd = [
        sys.executable, str(SENDER), "--src", "127.0.0.1",
        "--source-port", str(source_port), "--dst", "127.0.0.1",
        "--port", str(port), "--count", str(count), "--tag", tag,
        "--rate", str(rate), *extra,
    ]
    result = subprocess.run(cmd, text=True, capture_output=True, timeout=20)
    if result.returncode != 0:
        raise AssertionError(f"sender failed rc={result.returncode}: {result.stdout}{result.stderr}")
    return result.stdout


def verdict(function: str, *args: int) -> tuple[int, str]:
    result = subprocess.run(
        [
            "bash", "-c",
            'source "$1"; shift; "$@"',
            "bash", str(VERDICT_LIB), function, *map(str, args),
        ],
        text=True,
        capture_output=True,
        timeout=5,
    )
    return result.returncode, result.stdout.strip()


def aggregate_verdict(near_observed: int) -> tuple[int, str]:
    return verdict(
        "wire_routing_separation_verdict",
        1000, 0, 1500, 1500, 0, 1500, near_observed,
    )


def window_verdict(near_observed: int, tail_observed: int) -> tuple[int, str]:
    return verdict(
        "wire_routing_separation_window_verdict",
        tail_observed, 1000, 0, 1500, 1500, 0, 1500, near_observed,
    )


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
    deny_probes = False
    drop_tail_last = False
    late_outage = False
    late_outage_tripped = False
    late_n_baseline = 0
    relay_counts: collections.Counter[str] = collections.Counter()
    peer_counts: collections.Counter[str] = collections.Counter()
    peer_sequence: list[tuple[str, int]] = []

    def relay(sock: socket.socket) -> None:
        nonlocal forwarded, stopped, deny_probes, drop_tail_last, late_outage
        nonlocal late_outage_tripped, late_n_baseline
        while True:
            try:
                payload, _ = sock.recvfrom(2048)
            except socket.timeout:
                with condition:
                    if stopped:
                        return
                continue
            tag = chr(payload[0])
            seq = int(payload.split(b":", 2)[1])
            with condition:
                relay_counts[tag] += 1
                if late_outage and tag == "P" and seq == 999:
                    deadline = time.monotonic() + 5
                    while peer_counts["N"] - late_n_baseline < 1000:
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            break
                        condition.wait(remaining)
                    forwarded = False
                    late_outage = False
                    late_outage_tripped = True
                do_forward = (
                    forwarded
                    and not (deny_probes and tag == "P")
                    and not (
                        late_outage and tag == "N" and seq >= 1000
                    )
                    and not (drop_tail_last and tag == "N" and seq == 1099)
                )
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
            seq = int(payload.split(b":", 2)[1])
            with condition:
                peer_counts[tag] += 1
                peer_sequence.append((tag, seq))
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
                "--interleave-control-count", "103", "--interleave-control-tag", "N",
            ),
        )
        wait_for(peer_counts, "N", 103)
        wait_for(peer_counts, "P", 3)
        with condition:
            order = [tag for tag, _ in peer_sequence[:6]]
        if order != ["N", "P", "N", "P", "N", "P"]:
            raise AssertionError(f"sender did not interleave N before P: {order}")
        if "SENT tag=P count=3" not in order_out or "SENT tag=N count=103" not in order_out:
            raise AssertionError(f"sender smoke counts were incomplete: {order_out}")

        with condition:
            initial_n_before = peer_counts["N"]
        c_out = sender(port=probe_port, count=1500, tag="C", rate=1000)
        n_out = sender(port=control_port, count=1500, tag="N", rate=1000)
        wait_for(peer_counts, "C", 1500)
        wait_for(peer_counts, "N", initial_n_before + 1500)
        if "SENT tag=C count=1500" not in c_out or "SENT tag=N count=1500" not in n_out:
            raise AssertionError("initial C/N sender counts were not complete")
        with condition:
            initial_near_miss_observed = peer_counts["N"] - initial_n_before
        if initial_near_miss_observed != 1500:
            raise AssertionError(f"initial near-miss count was {initial_near_miss_observed}, not 1500")

        # Reproduce the reviewed C -> N -> outage -> P sequence. The aggregate
        # oracle accepts this stale control despite the dead P path.
        with condition:
            forwarded = False
        p_out = sender(port=probe_port, count=1000, tag="P")
        wait_for(relay_counts, "P", 1003)
        with condition:
            if peer_counts["P"] != 3:
                raise AssertionError(f"probe crossed the forwarding outage: {peer_counts['P'] - 3}")
        if "SENT tag=P count=1000" not in p_out:
            raise AssertionError(f"legacy probe sender count was incomplete: {p_out}")
        red_rc, red_out = aggregate_verdict(initial_near_miss_observed)
        if red_rc != 0 or " WIRE_GATE wire_routing_separation PASS " not in f" {red_out} ":
            raise AssertionError(f"RED-before repro did not reproduce false PASS: {red_out} rc={red_rc}")

        # A complete outage inside the scored interleaved window has no liveness.
        with condition:
            n_before = peer_counts["N"]
            p_before = peer_counts["P"]
            sequence_before = len(peer_sequence)
            relay_n_target = relay_counts["N"] + 1500
            relay_p_target = relay_counts["P"] + 1000
        interleaved = sender(
            port=probe_port,
            count=1000,
            tag="P",
            extra=(
                "--interleave", "--interleave-control-port", str(control_port),
                "--interleave-control-count", "1500", "--interleave-control-tag", "N",
            ),
        )
        wait_for(relay_counts, "N", relay_n_target)
        wait_for(relay_counts, "P", relay_p_target)
        with condition:
            n_window_observed = peer_counts["N"] - n_before
            p_window_observed = peer_counts["P"] - p_before
            window_packets = peer_sequence[sequence_before:]
        tail_observed = sum(
            1 for tag, seq in window_packets if tag == "N" and 1000 <= seq <= 1099
        )
        if "SENT tag=P count=1000" not in interleaved or "SENT tag=N count=1500" not in interleaved:
            raise AssertionError(f"interleaved sender count mismatch: {interleaved}")
        if n_window_observed != 0 or p_window_observed != 0 or tail_observed != 0:
            raise AssertionError(
                f"interleaved outage observations: N={n_window_observed} "
                f"P={p_window_observed} tail={tail_observed}"
            )
        green_rc, green_out = window_verdict(n_window_observed, tail_observed)
        if green_rc != 2 or "VOID reason=capture-blind" not in green_out:
            raise AssertionError(f"full outage did not VOID: {green_out} rc={green_rc}")
        # Dropping the final frame in the measured 100-frame tail alone must
        # not VOID a healthy capture; the tail starts just after the probe.
        with condition:
            forwarded = True
            deny_probes = True
            drop_tail_last = True
            healthy_n_before = peer_counts["N"]
            healthy_p_before = peer_counts["P"]
            healthy_sequence_before = len(peer_sequence)
            healthy_relay_n_target = relay_counts["N"] + 1500
            healthy_relay_p_target = relay_counts["P"] + 1000
        healthy_interleaved = sender(
            port=probe_port,
            count=1000,
            tag="P",
            rate=1000,
            extra=(
                "--interleave", "--interleave-control-port", str(control_port),
                "--interleave-control-count", "1500", "--interleave-control-tag", "N",
            ),
        )
        wait_for(relay_counts, "N", healthy_relay_n_target)
        wait_for(relay_counts, "P", healthy_relay_p_target)
        wait_for(peer_counts, "N", healthy_n_before + 1499)
        with condition:
            healthy_n_observed = peer_counts["N"] - healthy_n_before
            healthy_p_observed = peer_counts["P"] - healthy_p_before
            healthy_packets = peer_sequence[healthy_sequence_before:]
            drop_tail_last = False
        healthy_tail_observed = sum(
            1 for tag, seq in healthy_packets if tag == "N" and 1000 <= seq <= 1099
        )
        healthy_last_observed = sum(
            1 for tag, seq in healthy_packets if tag == "N" and seq == 1099
        )
        if (
            healthy_n_observed != 1499
            or healthy_p_observed != 0
            or healthy_tail_observed != 99
            or healthy_last_observed != 0
        ):
            raise AssertionError(
                f"healthy-minus-final-tail mismatch: N={healthy_n_observed} "
                f"P={healthy_p_observed} tail={healthy_tail_observed} "
                f"last={healthy_last_observed}"
            )
        healthy_rc, healthy_out = window_verdict(
            healthy_n_observed, healthy_tail_observed
        )
        if healthy_rc != 0 or " WIRE_GATE wire_routing_separation PASS " not in f" {healthy_out} ":
            raise AssertionError(
                f"healthy capture with only final tail frame lost did not PASS: {healthy_out} "
                f"rc={healthy_rc}"
            )

        # Trip a later outage after N#999 is peer-observed but before P#999.
        # The old aggregate floor reaches 1000; the first 100 controls after
        # the probe burst test liveness immediately beyond its final packet.
        with condition:
            forwarded = True
            deny_probes = True
            late_n_baseline = peer_counts["N"]
            late_n_before = peer_counts["N"]
            late_p_before = peer_counts["P"]
            late_sequence_before = len(peer_sequence)
            late_relay_n_target = relay_counts["N"] + 1500
            late_relay_p_target = relay_counts["P"] + 1000
            late_outage = True
            late_outage_tripped = False
        late_interleaved = sender(
            port=probe_port,
            count=1000,
            tag="P",
            extra=(
                "--interleave", "--interleave-control-port", str(control_port),
                "--interleave-control-count", "1500", "--interleave-control-tag", "N",
            ),
        )
        wait_for(relay_counts, "N", late_relay_n_target)
        wait_for(relay_counts, "P", late_relay_p_target)
        # Wait on the relay's own trip signal before sampling: the peer
        # receiver lags the relay under load, so sampling right after the
        # relay counts arrive reads async state at a fixed point.
        with condition:
            trip_deadline = time.monotonic() + 5
            while not late_outage_tripped:
                remaining = trip_deadline - time.monotonic()
                if remaining <= 0:
                    raise AssertionError(
                        "timed out waiting for the late outage to trip: "
                        f"tripped={late_outage_tripped} "
                        f"N={peer_counts['N'] - late_n_before} "
                        f"P={peer_counts['P'] - late_p_before}"
                    )
                condition.wait(remaining)
        with condition:
            n_late_observed = peer_counts["N"] - late_n_before
            p_late_observed = peer_counts["P"] - late_p_before
            late_packets = peer_sequence[late_sequence_before:]
            outage_tripped = late_outage_tripped
        late_tail_observed = sum(
            1 for tag, seq in late_packets if tag == "N" and 1000 <= seq <= 1099
        )
        if "SENT tag=P count=1000" not in late_interleaved or "SENT tag=N count=1500" not in late_interleaved:
            raise AssertionError(f"late-outage sender counts were incomplete: {late_interleaved}")
        if (
            not outage_tripped
            or n_late_observed != 1000
            or p_late_observed != 0
            or late_tail_observed != 0
        ):
            raise AssertionError(
                f"late-outage shape mismatch: tripped={outage_tripped} "
                f"N={n_late_observed} P={p_late_observed} tail={late_tail_observed}"
            )
        late_red_rc, late_red_out = aggregate_verdict(n_late_observed)
        if late_red_rc != 0 or " WIRE_GATE wire_routing_separation PASS " not in f" {late_red_out} ":
            raise AssertionError(f"late outage did not reproduce aggregate PASS: {late_red_out}")
        late_green_rc, late_green_out = window_verdict(
            n_late_observed, late_tail_observed
        )
        if late_green_rc != 2 or "VOID reason=capture-blind" not in late_green_out:
            raise AssertionError(
                f"tail-aware oracle did not reject late outage: {late_green_out} "
                f"rc={late_green_rc}"
            )

        print(f"RED-before: C=1500/1500 N=1500/1500 P=1000/0 => {red_out} (exit {red_rc})")
        print(
            f"GREEN-after full outage: interleaved N=1500/{n_window_observed} "
            f"P=1000/{p_window_observed} tail={tail_observed} => "
            f"{green_out} (exit {green_rc})"
        )
        print(
            f"Healthy minus final measured tail frame: N={healthy_n_observed}/1500 "
            f"tail={healthy_tail_observed}/100 tail_last={healthy_last_observed} "
            f"=> {healthy_out} (exit {healthy_rc})"
        )
        print(
            f"Late outage after N#999: aggregate={late_red_out} (exit {late_red_rc}); "
            f"tail-aware={late_green_out} (exit {late_green_rc})"
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
