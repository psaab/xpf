# userspace-dp/src/afxdp/forwarding/

The "decide where this packet goes" stage. Validates the parsed
packet metadata against the live `ValidationState` (snapshot
installed, config generation matches, FIB generation matches), then
runs FIB lookup, next-hop selection, VRF / next-table inter-VRF
leaking traversal, and produces a `ForwardingResolution` for the TX
side.

Packets that fail validation never reach FIB lookup — they get a
`PacketDisposition` (`NoSnapshot`, `ConfigGenerationMismatch`,
`FibGenerationMismatch`, `UnsupportedPacket`) and are dropped or
slow-path-injected.

## Files

| File | Purpose |
|------|---------|
| `mod.rs` | `classify_metadata` + the FIB / next-hop traversal entry points. |
| `tests.rs` | Co-located unit tests covering classify, FIB lookup, multi-table next-table leaking. |

## Constants

- `DEFAULT_V4_TABLE = "inet.0"`, `DEFAULT_V6_TABLE = "inet6.0"` —
  the default routing tables a packet starts in when no
  routing-instance scopes it.
- `MAX_NEXT_TABLE_DEPTH = 8` — bounded recursion across `next-table`
  chains to keep a misconfigured loop from running forever.

## Where it sits

- Reads the live snapshot Arcs (FIB, NAT, neighbor table) supplied
  by `worker_loop`.
- Output (`ForwardingResolution`) is consumed by the TX path
  (`tx/dispatch.rs`, `tx/transmit.rs`) to pick the egress binding
  and encode the L2 header.
- Has no cross-binding back-edges — the per-worker hot path stays
  on its own UMEM.
