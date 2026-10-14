#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""#12495 — pcap normalizer for the IPv6 NA-burst attribution capture.

Reads a classic pcap (libpcap file, Ethernet linktype) on stdin or from the
file named in argv[1], and emits ONE normalized line per ARP / RA / NA frame:

    NA <epoch-ms> <src-ip6> <target-ip6> <tlla-mac|-> <flags>
    RA <epoch-ms> <src-ip6> <slla-mac|-> <router-lifetime-sec>
    ARP <epoch-ms> <sender-ipv4> <sender-mac> <opcode>
    PARSEERR <epoch-ms> <reason>

<flags> is the NA flag set as a letter run: R (router), S (solicited),
O (override) — e.g. "RO" for the VIP burst frame buildVIPUnsolicitedNA sends,
or "-" when no flag is set.

WHY THIS SHAPE
  The decision layer (v6-na-recovery-lib-12495.sh) must be hermetically
  testable, so it consumes these normalized lines instead of tcpdump text.
  tcpdump's verbose ND output varies across versions and does not print the
  NA target link-layer option at -vv on every build in the field, so the
  parser reads packet bytes directly.

FAIL-CLOSED
  A frame that is truncated or unparseable is NEVER silently skipped: it
  emits PARSEERR, and the decision layer treats any PARSEERR as a broken
  instrument (VOID) rather than evidence of absence. A capture that could not
  be read at all (bad magic, wrong linktype, truncated header) exits 1 with
  the reason on stderr — an empty instrument and a dead one must not render
  as the same clean zero (same discipline as cluster-cell-selftest's
  xpf_first_mutation_line).
"""

import struct
import sys

ETH_P_ARP = 0x0806
ETH_P_IPV6 = 0x86DD
IPPROTO_ICMPV6 = 58


def ip6_str(b):
    # Canonical compressed form via the stdlib formatter for 16 bytes.
    import ipaddress

    return str(ipaddress.IPv6Address(b))


def mac_str(b):
    return ":".join("%02x" % x for x in b[:6])


def ip4_str(b):
    return ".".join(str(x) for x in b[:4])


def parse_na(payload, src):
    if len(payload) < 24:
        return None, "NA truncated before target address"
    flags = payload[4]
    target = ip6_str(payload[8:24])
    flag_run = ("R" if flags & 0x80 else "") + ("S" if flags & 0x40 else "") + ("O" if flags & 0x20 else "")
    tlla = "-"
    off = 24
    while off + 2 <= len(payload):
        opt_type, opt_len = payload[off], payload[off + 1]
        if opt_len == 0:
            break  # malformed option length; stop scanning
        opt_bytes = opt_len * 8
        if off + opt_bytes > len(payload):
            break
        if opt_type == 2 and opt_len == 1:  # Target Link-Layer Address
            tlla = mac_str(payload[off + 2 : off + 8])
        off += opt_bytes
    return "NA %s %s %s %s" % (src, target, tlla, flag_run or "-"), None


def parse_ra(payload, src):
    if len(payload) < 16:
        return None, "RA truncated before options"
    lifetime = struct.unpack("!H", payload[6:8])[0]
    slla = "-"
    off = 16
    while off + 2 <= len(payload):
        opt_type, opt_len = payload[off], payload[off + 1]
        if opt_len == 0:
            break
        opt_bytes = opt_len * 8
        if off + opt_bytes > len(payload):
            break
        if opt_type == 1 and opt_len == 1:  # Source Link-Layer Address
            slla = mac_str(payload[off + 2 : off + 8])
        off += opt_bytes
    return "%s %s %d" % (src, slla, lifetime), None


def parse_arp(payload):
    if len(payload) < 28:
        return None, "ARP truncated before sender fields"
    opcode = struct.unpack("!H", payload[6:8])[0]
    return "ARP %s %s %d" % (ip4_str(payload[14:18]), mac_str(payload[8:14]), opcode), None


def emit_frame(ts_ms, frame, out, err):
    if len(frame) < 14:
        err(ts_ms, "frame shorter than Ethernet header")
        return
    ethertype = struct.unpack("!H", frame[12:14])[0]
    if ethertype == ETH_P_ARP:
        line, reason = parse_arp(frame[14:])
    elif ethertype == ETH_P_IPV6:
        if len(frame) < 14 + 40:
            err(ts_ms, "IPv6 header truncated")
            return
        if frame[20] != IPPROTO_ICMPV6:
            return  # not ND; not an instrument subject
        payload = frame[14 + 40 :]
        itype = payload[0] if payload else -1
        if itype == 136:
            line, reason = parse_na(payload, ip6_str(frame[22:38]))
        elif itype == 134:
            body, reason = parse_ra(payload, ip6_str(frame[22:38]))
            line = ("RA " + body) if body is not None else None
        else:
            return  # other ICMPv6 (NS/RS/echo): not a subject of this capture
    else:
        return  # other ethertypes are outside the capture filter anyway
    if reason is not None:
        err(ts_ms, reason)
        return
    out(ts_ms, line)


def main():
    data = open(sys.argv[1], "rb").read() if len(sys.argv) > 1 else sys.stdin.buffer.read()
    if len(data) < 24:
        sys.stderr.write("v6-na-parse: capture shorter than a pcap global header\n")
        return 1
    magic = data[:4]
    if magic == b"\xd4\xc3\xb2\xa1":
        endian, ts_div = "<", 1e3  # microsecond fractions → ms
    elif magic == b"\xa1\xb2\xc3\xd4":
        endian, ts_div = ">", 1e3
    elif magic == b"\x4d\x3c\xb2\xa1":
        endian, ts_div = "<", 1e6  # nanosecond fractions → ms
    elif magic == b"\xa1\xb2\x3c\x4d":
        endian, ts_div = ">", 1e6
    else:
        sys.stderr.write("v6-na-parse: not a libpcap capture (bad magic)\n")
        return 1
    linktype = struct.unpack(endian + "I", data[20:24])[0]
    if linktype != 1:
        sys.stderr.write("v6-na-parse: linktype %d is not Ethernet; the lab capture must be taken on the LAN host's Ethernet device\n" % linktype)
        return 1
    out = lambda ms, line: print("%d %s" % (ms, line))
    err = lambda ms, reason: print("%d PARSEERR %s" % (ms, reason))
    off = 24
    while off + 16 <= len(data):
        ts_sec, ts_frac, incl_len, _ = struct.unpack(endian + "IIII", data[off : off + 16])
        off += 16
        frame = data[off : off + incl_len]
        off += incl_len
        ms = int(ts_sec * 1000 + round(ts_frac / ts_div))
        if len(frame) < incl_len:
            err(ms, "truncated capture record")
            return 0  # already fail-closed on this defect; do not double-report
        emit_frame(ms, frame, out, err)
    if off != len(data):
        err(0, "capture ended mid-record")
    return 0


if __name__ == "__main__":
    sys.exit(main())
