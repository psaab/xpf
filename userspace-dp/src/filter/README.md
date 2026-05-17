# userspace-dp/src/filter/

Junos-style firewall filter compiler, evaluation engine, and policer.
Mirrors the BPF firewall-filter pipeline in userspace.

## Files

- `mod.rs` — public surface: `FilterAction` (`Accept` / `Discard` /
  `Reject` only), `FilterTerm` (the matched-and-action carrier),
  `PortMatcher`, `FilterTermCounter`. Side-effect actions like
  counting, logging, policing, forwarding-class assignment, and DSCP
  rewrite are **fields on `FilterTerm`** (e.g. `count`, `log`,
  `policer_name`, `forwarding_class`, `dscp_rewrite`), not enum
  variants — the engine applies them around the action verdict.
- `compiler.rs` — parses the typed config's filter terms and lowers
  them to `FilterTerm`s (prefix vectors, protocol bitmap, port
  matcher, DSCP bitmap).
- `engine.rs` — per-term evaluation, first-match-wins. It carries the
  matched `then policer ...` name in the filter result; forwarding-path
  enforcement is a separate wiring step.
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

## #1375 Three-Color Policer Foundation

Implemented here:

- srTCM (RFC 2697): committed tokens fill at CIR; overflow fills the
  excess bucket only after the committed bucket is full.
- trTCM (RFC 2698): committed and peak buckets refill independently at
  CIR and PIR.
- Color-aware classification never promotes incoming yellow or red
  packets. Color-blind classification ignores inherited color.
- Per-color treatments can carry DSCP rewrite and drop decisions in the
  meter decision.

Still gated before removing the userspace capability rejection:

- The Go snapshot schema, Rust wire DTO, and commit-time structural
  validation are wired for three-color policers. They are published only
  so the control plane and dataplane agree on the future wire shape.
  Commit validation rejects ambiguous mode declarations (`single-rate`
  with `two-rate`) and ambiguous color declarations (`color-blind` with
  `color-aware`) before they can reach the helper. Duplicate
  hierarchical `firewall three-color-policer <name>` blocks are compiled
  as one logical policer before that validation, so load
  merge/override cannot hide an ambiguity behind last-write-wins map
  assignment.
- Filter terms still carry a policer name in the evaluation result.
  The hot forwarding path must move to stable policer IDs with
  ID-indexed or sharded state before three-color policers are enabled.
- Flow-cache hits do not yet execute policer decisions, because the
  forwarding path does not consume this meter core.
- Forwarding-path application of per-color counters, red drops, DSCP
  rewrites, Rust status, Go status, CLI, and Prometheus export remain
  follow-on wiring.
- Until those runtime pieces land, any config containing
  `firewall three-color-policer` stays fail-closed for userspace
  forwarding through the capability gate.
