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

## Current Slice Status (2026-05-18)

- #1393 landed the deterministic userspace cookie codec/layout and codec tests.
- This runtime slice carries `syn_cookie` through Go and Rust screen snapshots,
  adds a fail-closed screen challenge verdict when no HA-safe secret is
  published, uses a fixed-size keyed validated-client table for
  attacker-controlled tuples, and validates returning ACKs only after normal
  session lookup misses.
- The 2026-05-18 closeout slice makes validated-client cache hits visible as an
  explicit single-use `SynCookieBypass`, pins cache expiration at the one-epoch
  TTL boundary, pins current/previous cookie-epoch ACK validation, and wires
  per-binding helper status counters for selected challenges, no-secret
  fail-closed decisions, valid ACKs, invalid ACKs, and bypasses.
- Go helper status renders those counters, and the HA/BPF compatibility counter
  sync mirrors valid ACK, invalid ACK, and bypass deltas. Challenge decisions are
  deliberately not mapped to the legacy sent counter until bounded SYN-ACK TX
  exists.
- The 2026-05-19 construction slice adds pure SYN-cookie SYN-ACK and validated
  ACK RST frame builders. The builders swap Ethernet/IP/TCP identity, preserve
  VLAN headers, emit minimal TCP replies, and recompute IPv4/IPv6 checksums
  from scratch. This intentionally stops before TX-ring integration.
- The userspace capability gate remains in place until bounded SYN-ACK TX,
  bounded ACK RST emission, HA-safe secret publication/cache survivability,
  sent/budget TX counters, and integration/failover validation land.

## Design

Use SipHash, not HMAC-SHA1/SHA256. Linux SYN cookies and the current kernel
kfunc path use SipHash-class keyed hashing, and the transmitted budget is only
the 32-bit TCP ISN. Per-zone secrets rotate every 64 seconds using a monotonic
epoch. Validation accepts the current and previous epochs.

Cookie ISN layout:

```text
[5 bits epoch] [3 bits MSS index] [24 bits MAC]
```

The transmitted epoch field is only `epoch & 0x1f`. The full monotonic epoch is
still part of the MAC input and secret derivation. Validation reconstructs
candidate full epochs from the current and previous full epochs, then accepts
only candidates whose low 5 bits match the transmitted field and whose MAC
validates. A cookie minted 32 epochs ago has the same transmitted low bits as
the current epoch but must reject because the full epoch used for MAC/secret
derivation is outside the current/previous validation window.

The MAC covers source/destination IPs, ports, MSS index, zone, and the full
monotonic epoch. The secret is cluster-consistent: either synced as HA state or
derived from an HA-synced master key plus `(zone_id, full_epoch)`. Local-only
secrets are rejected because failover would invalidate in-flight cookies.

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
- Validated-client state is a fixed-size keyed table; attacker-controlled
  tuples do not enter `FxHashMap` or an unbounded queue.
- Per-zone SYN-cookie active/counter state is config-bound and prepopulated on
  profile updates, so packet processing does not allocate zone strings.
- Cookie reply frame allocation is bounded; normal forwarding frame ownership
  takes priority over diagnostic/flood replies.
- Random ACKs never install sessions.

## State and HA Behavior

- Secrets are consistent across active and backup nodes with current+previous
  epoch overlap.
- Epoch uses monotonic time, not wall clock, so NTP rollback does not invalidate
  cookies.
- Epoch publication must be generation-atomic with the secret snapshot: workers
  must not see a new full epoch with an old per-zone secret or the reverse.
- Failover during an active flood continues accepting cookies minted by the
  former active node for the overlap window.
- `synproxy_active`, sent, valid, invalid, bypass, and budget-drop counters are
  exposed in userspace status.

## Risks

- Replay/wrap: the low 5 transmitted epoch bits wrap every 32 epochs. The
  full-epoch MAC rule above is mandatory to prevent old cookies from becoming
  valid again at low-bit wrap.
- Failover skew: active and backup nodes need bounded monotonic-epoch skew or a
  shared epoch source; otherwise cookies minted immediately before failover can
  be rejected by the new active node.
- Budget starvation: cookie replies are useful only if the bounded reply budget
  cannot drain normal forwarding frames. Drop accounting must distinguish
  invalid-cookie drops from reply-budget drops.
- Validated-client cache pressure: attacker-generated valid-looking ACKs must
  not evict legitimate validated clients without caps and counters.

## Exact Tests

- Cargo: `screen::syn_cookie_mint_validate_roundtrip`.
- Cargo: `screen::syn_cookie_validate_rejects_modified_tuple`.
- Cargo: `screen::syn_cookie_validate_rejects_stale_secret`.
- Cargo: `screen::syn_cookie_mss_index_encoding_parity`.
- Cargo: `screen::syn_cookie_ntp_rollback_monotonic_epoch`.
- Cargo: `screen::syn_cookie_epoch_low_bits_wrap_rejects_32_epoch_old_cookie`.
- Cargo: `screen::syn_cookie_validation_tries_current_and_previous_full_epoch`.
- Cargo: `screen::syn_cookie_chosen_when_threshold_exceeded`.
- Cargo: `screen::syn_cookie_without_published_secret_fails_closed`.
- Cargo: `screen::syn_cookie_ack_validation_marks_next_syn_bypass_without_session_creation`.
- Cargo: `screen::syn_cookie_validated_syn_still_runs_later_screen_checks`.
- Cargo: `screen::syn_cookie_invalid_ack_does_not_validate_client`.
- Cargo: `screen::syn_cookie_ack_fin_is_invalid_while_cookie_mode_is_active`.
- Cargo: `screen::syn_cookie_validated_cache_is_bounded`.
- Cargo: `screen::syn_cookie_validated_cache_index_is_keyed`.
- Cargo: `screen::syn_cookie_validated_cache_expires_on_ttl_boundary`.
- Cargo: `screen::syn_cookie_invalid_ack_flood_does_not_grow_validated_cache`.
- Cargo: `screen::syn_cookie_master_key_rotation_clears_validated_cache`.
- Cargo: `screen::update_profiles_prepopulates_syn_cookie_active_state`.
- Cargo: `screen::syn_cookie_validated_cache_refresh_extends_ttl`.
- Cargo: `screen::syn_cookie_ack_validation_accepts_previous_epoch_after_rotation`.
- Cargo: `afxdp::poll_stages::session_miss_ack_stage_invokes_syn_cookie_runtime_validation`.
- Cargo: `afxdp::frame::tests::syn_cookie_syn_ack_builder_swaps_tuple_and_preserves_vlan`.
- Cargo: `afxdp::frame::tests::syn_cookie_ack_rst_builder_uses_received_ack_as_rst_seq`.
- Cargo: `afxdp::tests::syn_cookie_counters_hot_path_accumulate_in_batch`.
- Cargo: `afxdp::umem::tests::binding_live_snapshot_propagates_710_drop_counters`.
- Cargo: `afxdp::coordinator::tests::refresh_bindings_bridges_v_min_counters_into_binding_status`.
- Cargo: `afxdp::coordinator::tests::refresh_bindings_zeroes_v_min_counters_when_worker_absent`.
- Cargo: `protocol::tests::syn_cookie_counters_binding_status_wire_roundtrip`.
- Go: `TestSumBindingCounters` and `TestFormatStatusSummary` pin helper-side
  aggregation/status rendering for the userspace SYN-cookie counters.
- Go: while the gate remains, keep the `SynFloodProtectionMode == "syn-cookie"`
  capability rejection pinned and verify screen snapshots carry `syn_cookie` for
  the runtime path.
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
