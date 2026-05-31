PLAN-READY

Round-2 blocker check:
- Re-read the full `docs/research/1715-dns-resolv-ownership/plan.md`.
- Searched for the stale hybrid/resolved-owner forms called out in round 2:
  `enable --now`, resolved drop-in writes, `DNSEnabled`/`system services dns`
  selecting resolved, owner-model selection, and the prior plain-file gotcha.
- The only normative `enable --now` resolved-owner text is inside Option B,
  which is explicitly headed `REJECTED -- documented alternative only` and
  says no normative section selects it at runtime.
- Option D now describes the pure Option A vehicle: `reconcileDNS` always owns
  `/etc/resolv.conf` as a managed plain file, always disables+masks resolved,
  does not pick an owner model from config, and never writes a resolved drop-in.
- Sections 5b, 6, 9, 10, and 11 consistently state no hybrid:
  `DNSEnabled`/`system services dns` is warning-only and does not select a
  resolved-owner runtime branch.

The single round-2 blocker is resolved.
