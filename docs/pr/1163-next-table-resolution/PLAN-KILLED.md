# #1163 PLAN-KILLED — 2026-05-26

## Final state

Two-round plan review concluded with adversarial deadlock:

- Round 1: Codex PLAN-NEEDS-MAJOR, Gemini PLAN-KILL.
- Round 2: Codex PLAN-READY (with implementation note), Gemini
  PLAN-KILL maintained with sharpened counter-argument.

Per triple-review skill rule "Don't lower the bar — the methodology
only works if the kill verdict is taken seriously," and per
project memory `feedback_difficult_path_pragmatism` ("for 'Refactor:
<Pattern>' issues proposing large rearchitectures, stop and report
rather than ship a wrong-target PR"), Gemini's maintained KILL is
authoritative.

## Why killed

1. **Honest perf framing too thin for LOC**: ~0.05% of one core on
   session-install slow path (only for `next-table` flows, ≤10k/sec
   realistic) does not justify ~250-350 LOC of structural churn
   (per-family interning tables, parallel ID arrays, signature
   churn across the resolution call tree).

2. **The actual value is a 2-line correctness fix, not a refactor**.
   Round-1 Codex review surfaced that `pkg/config/compiler_routing.go:266`
   `parseNextTableInstance` strips the `.inet.0` / `.inet6.0` suffix
   from `next-table` directives, so `RouteSnapshot.NextTable` carries
   the **bare routing-instance name** (e.g. `"Comcast"`).
   `ForwardingState.routes_v4` is keyed by the full table name
   (e.g. `"Comcast.inet.0"`), so today's recursive lookup at
   `userspace-dp/src/afxdp/forwarding/mod.rs:1273` silently misses
   and returns `NoRoute` for all real-config `next-table` flows.

3. **jemalloc-pressure argument is weak**: ~30k allocations/sec on
   a session-install slow path is well below noise floor for a
   per-thread allocator; the structural refactor cannot be justified
   on this axis.

4. **Eager visited-set cycle detection is overengineering** for a
   misconfigured-config slow path.

## What ships instead

A separate, small bug-fix PR (~2 lines + tests) addressing **only**
the bare-RI normalization. Implementation sketch:

```rust
// At forwarding/mod.rs:1273 (v4 case):
let next_table_canonical = if next_table_name.contains(".inet") {
    next_table_name
} else {
    format!("{next_table_name}.inet.0")
};
return lookup_forwarding_resolution_v4(
    state, dynamic_neighbors, ip, &next_table_canonical,
    depth + 1, allow_tunnels,
);

// At forwarding/mod.rs:1421 (v6 case): mirror with .inet6.0.
```

Plus tests:
- `forwarding_resolution_handles_bare_ri_next_table_v4` (fixture
  with `next_table: "blue"`, routes keyed by `"blue.inet.0"`).
- `forwarding_resolution_handles_bare_ri_next_table_v6` (mirror).

Plus release-note entry calling out the behavior change ("operators
relying on `next-table` directives silently dropping traffic must
review their configs — `next-table` now actually routes through the
target instance").

## Issue disposition

#1163 (the perf refactor framing) stays open as a longer-term
"if/when we revisit hot-path next-table" tracker; the bug-fix PR
references it as background but does NOT close it.

## Reviewer transcripts

- Round 1 Codex: task-mpn2x6g6-2zr1d0 — PLAN-NEEDS-MAJOR
- Round 1 Gemini: task-mpn2y7qs-ptdcm8 — PLAN-KILL
- Round 2 Codex: task-mpn3pnbc-p9wom8 — PLAN-READY (caveat note)
- Round 2 Gemini: task-mpn3q9gb-eeb55f — PLAN-KILL (maintained)
