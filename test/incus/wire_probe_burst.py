#!/usr/bin/env python3
"""UDP burst prober for the #9531 wire-deny gates.

Sends counted UDP datagrams, alternating two payload sizes, at a capped
rate, and prints exactly one summary line. Two modes:

    probe/control (wire_policy_deny): --probe-port P --control-port C
        --count N prints `SENT probe=<n> control=<m>`
    legs (wire_appmatch_twins udp legs): --leg PORT:COUNT repeated prints
        `SENT legs=<port>=<n>,...`
    tcp-legs (wire_appmatch_twins tcp legs): --tcp-leg PORT:COUNT repeated
        prints `SENT tcplegs=<port>=<n>,...`. Each attempt is one TCP
        connect; established AND refused both prove the SYN emerged
        peer-side, so both count as offered. Only local errors
        (unreachable net, fd exhaustion) do not.
Nothing else on stdout (diagnostics go to stderr). The peer-side capture —
not this script — is the oracle; these counts are the OFFERED side that the
verdict floors apply to.
"""

import argparse
import socket
import sys
import time


def burst(sock, dst, port, count, sizes, rate, seq_base):
    sent = 0
    interval = 1.0 / rate if rate > 0 else 0.0
    size_count = len(sizes)
    for i in range(count):
        size = sizes[i % size_count]
        # Payload carries the leg identity + sequence so a misdirected
        # datagram is attributable, not just countable. Minimum 8 bytes.
        body = ("P%d:%d:" % (port, seq_base + i)).encode()
        payload = body + b"x" * max(0, size - len(body))
        try:
            sock.sendto(payload, (dst, port))
            sent += 1
        except OSError as exc:
            print("sendto port %d seq %d failed: %s" % (port, i, exc),
                  file=sys.stderr)
        if interval:
            time.sleep(interval)
    return sent


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dst", required=True)
    ap.add_argument("--probe-port", type=int, default=None)
    ap.add_argument("--control-port", type=int, default=None)
    ap.add_argument("--leg", action="append", default=[],
                    metavar="PORT:COUNT",
                    help="repeatable multi-leg burst (twins mode)")
    ap.add_argument("--tcp-leg", action="append", default=[],
                    metavar="PORT:COUNT",
                    help="repeatable TCP-connect burst (twins TCP legs)")
    ap.add_argument("--count", type=int, default=1000)
    ap.add_argument("--sizes", default="64,1400")
    ap.add_argument("--rate", type=float, default=200.0,
                    help="datagrams per second per leg")
    args = ap.parse_args()
    # TCP and UDP leg modes compose: each prints its own SENT line when
    # requested, so one invocation covers a mixed window.
    if args.tcp_leg or args.leg:
        rc = 0
        if args.tcp_leg and tcp_legs_mode(args) != 0:
            rc = 1
        if args.leg:
            sizes = [int(s) for s in args.sizes.split(",") if s.strip()]
            if not sizes:
                print("no sizes requested", file=sys.stderr)
                return 2
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                if legs_mode(sock, args, sizes) != 0:
                    rc = 1
            finally:
                sock.close()
        return rc
    if args.probe_port is None or args.control_port is None:
        print("probe/control mode needs --probe-port and --control-port",
              file=sys.stderr)
        return 2
    if args.count <= 0:
        print("no work requested", file=sys.stderr)
        return 2
    sizes = [int(s) for s in args.sizes.split(",") if s.strip()]
    if not sizes:
        print("no sizes requested", file=sys.stderr)
        return 2
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sent_probe = burst(sock, args.dst, args.probe_port, args.count,
                           sizes, args.rate, 0)
        # Small gap so the two legs do not share identical transmit windows;
        # the capture window covers both regardless.
        time.sleep(0.5)
        sent_control = burst(sock, args.dst, args.control_port, args.count,
                             sizes, args.rate, args.count)
    finally:
        sock.close()
    print("SENT probe=%d control=%d" % (sent_probe, sent_control))
    return 0 if (sent_probe == args.count and
                 sent_control == args.count) else 1


def legs_mode(sock, args, sizes):
    """Run each --leg PORT:COUNT burst in order under one capture window."""
    results = []
    ok = True
    seq = 0
    for spec in args.leg:
        try:
            port_s, count_s = spec.split(":", 1)
            port, count = int(port_s), int(count_s)
        except ValueError:
            print("bad --leg spec (want PORT:COUNT): %r" % spec,
                  file=sys.stderr)
            return 2
        if count <= 0 or not 0 < port < 65536:
            print("bad --leg spec (want PORT:COUNT): %r" % spec,
                  file=sys.stderr)
            return 2
        sent = burst(sock, args.dst, port, count, sizes, args.rate, seq)
        seq += count
        results.append("%d=%d" % (port, sent))
        if sent != count:
            ok = False
        time.sleep(0.5)
    print("SENT legs=%s" % ",".join(results))
    return 0 if ok else 1

def tcp_leg_attempt(dst, port, timeout):
    """One TCP connect attempt. Returns (offered, note).

    Established AND refused both prove at least one SYN emerged peer-side,
    so both count as offered. A timeout also transmitted SYNs (the kernel
    retransmits for the whole timeout) — offered too. Only local failures
    (unreachable network, fd exhaustion, bad address) are not offered.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except OSError as exc:
        return False, "local-socket: %s" % exc
    try:
        s.settimeout(timeout)
        s.connect((dst, port))
        try:
            s.sendall(b"q")
            s.recv(4)
        except OSError:
            pass
        return True, "ok"
    except socket.timeout:
        return True, "timeout"
    except ConnectionRefusedError:
        return True, "refused"
    except OSError as exc:
        import errno
        if exc.errno in (errno.ENETUNREACH, errno.EHOSTUNREACH,
                         errno.EADDRNOTAVAIL, errno.EMFILE, errno.ENFILE,
                         errno.EACCES, errno.EPERM):
            return False, "local: %s" % exc
        # Anything else (reset mid-handshake, etc.) still sent SYNs.
        return True, "reset"
    finally:
        try:
            s.close()
        except OSError:
            pass


def tcp_legs_mode(args):
    """Run each --tcp-leg PORT:COUNT burst via a worker pool."""
    import concurrent.futures
    legs = []
    for spec in args.tcp_leg:
        try:
            port_s, count_s = spec.split(":", 1)
            port, count = int(port_s), int(count_s)
        except ValueError:
            print("bad --tcp-leg spec (want PORT:COUNT): %r" % spec,
                  file=sys.stderr)
            return 2
        if count <= 0 or not 0 < port < 65536:
            print("bad --tcp-leg spec (want PORT:COUNT): %r" % spec,
                  file=sys.stderr)
            return 2
        legs.append((port, count))
    results = []
    ok = True
    for port, count in legs:
        offered = 0
        notes = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as pool:
            futs = [pool.submit(tcp_leg_attempt, args.dst, port, 5.0)
                    for _ in range(count)]
            for f in concurrent.futures.as_completed(futs):
                good, note = f.result()
                if good:
                    offered += 1
                notes[note] = notes.get(note, 0) + 1
        results.append("%d=%d" % (port, offered))
        if offered != count:
            ok = False
        print("tcp-leg %d: offered %d/%d (%s)" % (
            port, offered, count,
            " ".join("%s=%d" % kv for kv in sorted(notes.items()))),
            file=sys.stderr)
    print("SENT tcplegs=%s" % ",".join(results))
    return 0 if ok else 1
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
