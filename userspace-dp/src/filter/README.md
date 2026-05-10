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
- `engine.rs` — per-term evaluation, first-match-wins. Hands off to
  the policer for `then policer ...` actions.
- `policer.rs` — token-bucket implementation; the per-policer field
  is `rate_bytes_per_ns` (rate, not interval).
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
