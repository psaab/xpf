# #1374 Userspace SYN Cookie Flood Protection Plan

## Goal

Remove the userspace capability fallback for
`security flow syn-flood-protection-mode syn-cookie` by implementing eBPF-parity
SYN cookie behavior in `userspace-dp`.

## Dependencies

- #1381 should land first. Gate removal in
  `pkg/dataplane/userspace/snapshot.go` and capability reporting should happen
  through the standalone userspace manager contract, not the embedded eBPF
  manager.
- The implementation PR may depend on existing TX reply primitives, but must
  profile the actual TX completion cost instead of assuming in-place RX-to-TX
  bounce is required.

## Design

Use SipHash, not HMAC-SHA1/SHA256. Linux SYN cookies and the current kernel
kfunc path use SipHash-class keyed hashing, and the transmitted budget is only
the 32-bit TCP ISN. Per-zone secrets rotate every 64 seconds using a monotonic
epoch. Validation accepts the current and previous epochs.

Cookie ISN layout:

```text
[5 bits epoch] [3 bits MSS index] [24 bits MAC]
```

The MAC covers source/destination IPs, ports, MSS index, zone, and epoch. The
secret is cluster-consistent: either synced as HA state or derived from an
HA-synced master key plus `(zone_id, epoch)`. Local-only secrets are rejected
because failover would invalidate in-flight cookies.

On flood threshold:

1. Check existing `SynProfile` threshold state and set `synproxy_active`.
2. Allocate a cookie-reply frame from a bounded per-binding cookie budget.
3. Build a SYN-ACK with the encoded ISN and transmit it back to the source.
4. If the budget is exhausted, drop the flood SYN and increment a screen-drop
   counter rather than starving normal TX.

On returning ACK:

1. Validate tuple, epoch, MSS index, and MAC.
2. On success, mark the client validated and send RST, matching the current
   eBPF behavior; the client's retransmitted SYN then creates the normal
   policy/NAT/session path.
3. On failure, drop with no session creation and increment invalid-cookie
   counters.

## Hot-Path Invariants

- No heap allocation while deciding SYN cookie mint or ACK validation.
- SipHash key lookup is per-zone and read-only on the published snapshot.
- Cookie reply frame allocation is bounded; normal forwarding frame ownership
  takes priority over diagnostic/flood replies.
- Random ACKs never install sessions.
- Validated-client state uses a bounded LRU or equivalent capped table.

## State and HA Behavior

- Secrets are consistent across active and backup nodes with current+previous
  epoch overlap.
- Epoch uses monotonic time, not wall clock, so NTP rollback does not invalidate
  cookies.
- Failover during an active flood continues accepting cookies minted by the
  former active node for the overlap window.
- `synproxy_active`, sent, valid, invalid, bypass, and budget-drop counters are
  exposed in userspace status.

## Exact Tests

- Cargo: `screen::syn_cookie_mint_validate_roundtrip`.
- Cargo: `screen::syn_cookie_validate_rejects_modified_tuple`.
- Cargo: `screen::syn_cookie_validate_rejects_stale_secret`.
- Cargo: `screen::syn_cookie_mss_index_encoding_parity`.
- Cargo: `screen::syn_cookie_ntp_rollback_monotonic_epoch`.
- Cargo: `screen::syn_cookie_chosen_when_threshold_exceeded`.
- Cargo: `screen::syn_cookie_budget_drop_does_not_starve_tx`.
- Go: remove/update the `SynFloodProtectionMode == "syn-cookie"` capability
  rejection and the manager test that pins it.
- Integration: hping3 SYN flood against the userspace HA cluster with
  `syn-cookie` configured; verify SYN-ACK replies, legitimate retransmitted SYN
  admission after validated ACK/RST, random ACK drops, and failover acceptance
  within the epoch overlap.
- Smoke: existing screen smoke for the other checks still passes.

## Non-Goals

- Do not synthesize a full session directly from the cookie ACK in this PR.
- Do not change policy, NAT, or FIB semantics on the first retransmitted SYN.
- Do not remove eBPF source as part of #1374.
