# Codex hostile plan-review r2 (on plan r4) — verbatim final output

Final output
r4 is not shippable; no code was modified.

### Round-1 flaw matrix

- First-match ordering — **STILL-OPEN:** §5.1 independently gates exact, from-any, and global scopes, while Rust evaluates one effective exact → from-any → global program; an omitted unrepresentable exact permit can expose a later rendered global deny.
- `daddr`/ingress scoping — **STILL-OPEN:** concrete zones use `iifname`, but global-any explicitly has no ingress predicate, allowing denial on lifeline or unzoned ingress contrary to inv-1.
- Coarse-before-fine SSOT — **STILL-OPEN:** a terminal fine `permit→accept` before coarse rules can admit a service that Rust’s coarse gate rejects.
- `SourcePort` — **RESOLVED:** render-or-unrepresentable is explicit.
- Application-set OR — **RESOLVED:** full OR expansion to multiple rules is specified.
- Cross-family excluded addresses — **RESOLVED:** absent-family semantics are explicitly preserved.
- Destination address/exclusion — **RESOLVED:** resolution is constrained to firewall-local destinations.
- Reject pair — **RESOLVED for this slice:** reject-bearing programs are unrendered, and the accepted follow-up names the correct TCP-RST plus ICMPx pair.
- Counter multi-reference — **RESOLVED:** declaration deduplication with multiple references is specified.
- Warning suppression — **RESOLVED:** suppression requires an actually rendered rule.
- Established parity — **STILL-OPEN overall:** fine-deny re-evaluation is fixed, but the remaining original-direction established accept still bypasses Rust’s per-hit coarse recheck; nft `drop` also does not literally delete conntrack state.
- Hit-counter honesty — **RESOLVED:** aggregate nft telemetry is explicitly distinguished from policy counters and RT_FLOW attribution.
- Feed taint — **RESOLVED:** recursive and same-name static/feed contamination is covered.
- Scheduler hazards — **RESOLVED:** scheduler-bound programs are wholly unrepresentable.

### §6.4 placement

No, the combined placement is not faithful.

- **(a) Mixed:** raw ESP/AH may correctly bypass fine policy. ND/PMTUD/ICMP-error are only coarse admissions in [host_inbound.rs](/home/ps/git/bpfrx/.claude/worktrees/4146-research-junos-host-direct-deny/userspace-dp/src/afxdp/forwarding/host_inbound.rs:484); fine policy still runs afterward in [mod.rs](/home/ps/git/bpfrx/.claude/worktrees/4146-research-junos-host-direct-deny/userspace-dp/src/afxdp/poll_descriptor/mod.rs:2285). r4 therefore under-enforces a representable `application any` deny.
- **(b) Faithful narrowly:** accepting established reply-direction traffic preserves returns for firewall-originated flows.
- **(c) Not faithful:** fine `permit→accept` before coarse service admission violates Rust’s explicit rule that fine permit cannot re-admit a coarse rejection ([mod.rs](/home/ps/git/bpfrx/.claude/worktrees/4146-research-junos-host-direct-deny/userspace-dp/src/afxdp/poll_descriptor/mod.rs:138)). The residual established accept also skips coarse re-evaluation.

The remaining unsafe defects are the coarse-bypass exposure, independently gated policy tiers, unrestricted global-any ingress, and missing handling of plain `deny` in a zone with `tcp-rst`; explicit reject and source-restricted permit remain acceptable follow-ups.

Replace §§5.1/6.4 with one per-concrete-ingress/family effective program—exact → from-any → global—whole-program gated and entered only after coarse admission, with PMTUD/ND and original-direction established traffic traversing coarse then fine. That single rewrite must exclude lifelines and either faithfully model verdict-affecting `tcp-rst`/IPsec cases or mark those programs unrepresentable.

PLAN-REVISE

