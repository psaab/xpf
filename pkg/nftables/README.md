# pkg/nftables

Manages nftables rules via the netlink API (no shell-out to `nft`). Sole
purpose today: install a rule that DROPs outgoing TCP RSTs from NAT SNAT
addresses. This is critical for HA failover correctness — without it
the kernel can generate an RST for a connection it doesn't own at the
moment of takeover, killing the user-visible TCP session.

## Entry points

- `InstallRSTSuppression()` — `rst_suppress.go`. Atomic
  delete-then-create within a single netlink batch, so there is no
  window where the old table is gone but the new one isn't installed.
- `RemoveRSTSuppression()` — `rst_suppress.go`.

## Callers

`pkg/daemon`.

## Dependencies

External: `github.com/google/nftables`. No internal `pkg/*` deps.

## Gotchas

- Issue #450: deleting the table without immediate atomic recreate gives
  the kernel a window to send RSTs for connections owned by the peer
  during HA failover. The atomic delete+add pattern via `Flush()` is the
  fix; preserve it.
- Table name `xpf_dp_rst`, family `INet` (covers both IPv4 and IPv6 in
  one table — don't split it without rethinking the atomic batch).
