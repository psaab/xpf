# userspace-dp/src/afxdp/session_glue/

The bridge between an existing session table entry and a forwarding
resolution. Given a session's `SessionDecision` (NAT, drop, or
forward) and the cached `ForwardingResolution` from a prior packet
of the same flow, this module decides whether the cache is still
usable or the resolution must be re-derived.

Also writes the userspace dataplane's view of session state back
into the BPF session map mirror so the CLI / GC / metrics surface
sees the same sessions the userspace path is processing.

## Files

| File | Purpose |
|------|---------|
| `mod.rs` | Cache-validation helpers (`cached_session_resolution`, `resolution_target_for_session`), plus the BPF session-map mirror writers. |
| `tests.rs` | Co-located unit tests for cache validation + mirror semantics. |

## Where it sits

- Called by the worker poll loop after `session::lookup` finds an
  existing session.
- Reads from `forwarding/` for resolution rebuild when the cache is
  stale.
- Writes to the BPF session map (via `coordinator/bpf_maps.rs` FDs)
  so the eBPF data-display surface mirrors the live userspace
  session table.
