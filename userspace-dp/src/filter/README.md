# userspace-dp/src/filter/

Junos-style firewall filter compiler, evaluation engine, and policer.
Mirrors the BPF firewall-filter pipeline in userspace.

## Files

- `mod.rs` — public surface: `FilterAction` (`Accept` / `Discard` /
  `Reject` only), `FilterTerm` (the matched-and-action carrier),
  `PortMatcher`, `FilterTermCounter`, and three-color policer runtime
  counters. Side-effect actions like counting, logging, policing,
  forwarding-class assignment, and DSCP rewrite are **fields on
  `FilterTerm`** (e.g. `count`, `log`, `policer_name`,
  `three_color_policer`, `forwarding_class`, `dscp_rewrite`), not enum
  variants — the engine applies them around the action verdict.
- `compiler.rs` — parses the typed config's filter terms and lowers
  them to `FilterTerm`s (prefix vectors, protocol bitmap, port
  matcher, DSCP bitmap). Three-color policer snapshots are sorted by
  name and compiled into stable runtime IDs before terms are linked.
- `engine.rs` — per-term evaluation, first-match-wins. It carries the
  matched `then policer ...` name in the filter result. TX-selection
  evaluation meters three-color policers on live forwarding paths and
  cached evaluation returns runtime handles so flow-cache hits can meter
  the same policer before forwarding.
- `policer.rs` — token-bucket implementation plus the #1375 RFC
  2697/2698 three-color meter core. Token math is integer-only:
  the legacy token bucket keeps its bits/sec constructor contract, and
  the three-color core uses byte/sec rates; both refill scaled `u128`
  token buckets from monotonic nanosecond timestamps.
- `tests.rs` — co-located unit tests covering matching ports, prefix
  vectors, TCP flags.

## Conventions

- Prefix matching uses linear scan over `Vec<PrefixV4>` /
  `Vec<PrefixV6>` per term (`source_v4`, `source_v6`, `dest_v4`,
  `dest_v6` on `FilterTerm`). There is no LPM trie in this package
  today — the previous README claim of an "adaptive scan above 8
  entries" was incorrect.
- Hit counters live on each `FilterTerm` (`Arc<FilterTermCounter>`)
  and are surfaced through the status JSON.
- `from-interface` is matched at the binding level (caller sets the
  ingress interface; the term doesn't re-derive it).

## #1375 Three-Color Policer Runtime

Implemented here:

- srTCM (RFC 2697): committed tokens fill at CIR; overflow fills the
  excess bucket only after the committed bucket is full.
- trTCM (RFC 2698): committed and peak buckets refill independently at
  CIR and PIR.
- Color-aware classification never promotes incoming yellow or red
  packets. Color-blind classification ignores inherited color.
- Per-color treatments can carry DSCP rewrite and drop decisions in the
  meter decision.
- The Go snapshot schema, Rust wire DTO, and commit-time structural
  validation are wired for three-color policers. Commit validation
  rejects ambiguous mode declarations (`single-rate` with `two-rate`)
  and ambiguous color declarations (`color-blind` with `color-aware`)
  before they can reach the helper.
- Filter terms link to stable name-sorted runtime handles. The live
  forwarding path meters the handle at packet time, applies red drops,
  and records per-color/drop counters. Flow-cache hits carry the same
  handle in the cached TX-selection descriptor and meter before cached
  forwarding. Packets buffered for missing-neighbor retry carry their
  session key and meter at retry dispatch time before prepared TX.
- Rust status, Go status, CLI status formatting, and Prometheus export
  expose green/yellow/red packet and byte counters plus drop counters.
- `deriveUserspaceCapabilities()` no longer rejects
  `firewall three-color-policer` configs.

Remaining limitations:

- Runtime token state is one `Mutex` per logical policer, not a sharded
  or packed atomic implementation. This preserves correctness and
  stable identity but is not the final high-throughput contention model.
- Counters and token buckets are rebuilt on snapshot replacement; they
  are stable within one compiled runtime but not yet carried across
  config rebuilds.
- Snapshot `then_action` handling currently wires red drop for
  `then discard`. Other actions, such as loss-priority propagation, are
  parsed and admitted but do not yet drive downstream loss-priority
  behavior.
- Traffic-level integration, failover, and performance evidence still
  need to be collected before treating #1375 as fully retired.
