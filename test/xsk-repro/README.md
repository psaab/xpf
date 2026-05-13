# XSK Zero-Copy Rebind Test

Status: Inconclusive — cannot isolate from xpfd daemon.

## What we proved so far:

1. Zero-copy works on initial bind (WAN interface, ifindex 6, rx=228 in helper)
2. Zero-copy fails after link DOWN/UP (LAN interface, ifindex 5, rx=0 after failover)
3. NIC counters: rx_xsk_xdp_redirect increments but rx_xsk_packets does not
4. rx_xsk_congst_umr non-zero on affected interface (UMR congestion)
5. The issue is NOT our NAPI bootstrap (tested with 200ms delay, UMR congestion didn't recur)

## What's still needed:

A standalone test with its own XDP program (not xpfd's XDP shim) to:
- Confirm xdpilone zero-copy works at all on this NIC
- Confirm whether link DOWN/UP breaks the receive path
- Compare xdpilone vs libbpf xsk_socket__create
- Confirm the shared-UMEM owner/secondary bind contract:
  owner sockets may request copy/zero-copy, while secondary sockets must pass
  exactly `XDP_SHARED_UMEM` and verify `XDP_OPTIONS_ZEROCOPY` after bind.

The current test binary coexists with xpfd but the daemon's status
loop overwrites the xskmap and bindings entries, invalidating results.
