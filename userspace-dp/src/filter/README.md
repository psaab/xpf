# userspace-dp/src/filter/

Junos-style firewall filter compiler, evaluation engine, and policer.
Mirrors the BPF firewall-filter pipeline in userspace.

## Files

- `mod.rs` — public surface: `FilterAction` (Accept / Discard / Reject /
  Count / Forward / RateLimit / DSCP / ForwardingClass), per-term
  counters.
- `compiler.rs` — parses the typed config's filter terms and lowers
  them to compiled `FilterTerm` matchers (prefix sets, protocol /
  port / TCP-flag / DSCP matches).
- `engine.rs` — per-term evaluation, first-match-wins. Holds the
  token-bucket policer for `then policer ...` actions.
- `policer.rs` — token-bucket implementation with a `rate_limit_ns`
  refill window.
- `tests.rs` — co-located unit tests covering matching ports, prefix
  sets, TCP flags.

## Conventions

- Prefix sets compile to a small adaptive structure: a linear scan for
  ≤8 entries, an LPM trie above. The threshold is tuned for the
  observed working set in policy lookups.
- Hit counters live on each `FilterTerm` and are surfaced through the
  status JSON.
- `from-interface` is matched at the binding level (caller sets the
  ingress interface; the term doesn't re-derive it).
