# #9909 follow-up — commit-gate hardening

- **Issue**: [#9909](https://github.com/psaab/xpf/issues/9909)
- **Branch**: `fix/9909-gate-harden`
- **Disposition**: follow-up hardening only; this PR references #9909 and does not close it. The VRF-bind implementation is separately owned and is not changed here.

## What and why

The merged #9909 gate correctly refuses or quarantines WireGuard tunnels whose inner device is assigned to a routing-instance while the userspace outer UDP socket remains unbound. This follow-up restores the hardening that was lost with the earlier worktree:

- `TunnelNameMap` is initialized lazily through `tunMapReady`, `getTunMap`, and `scopeFor`. Explicit tunnel scope and configs without routing-instance membership do not build the map; membership expansion builds it at most once per validation.
- Bare-member quarantine expands to resolved `{ref, device}` pairs and preserves authored explicit members. Generated survivor refs are deduplicated by resolved device in input order, so aliases and explicit spellings cannot create duplicate membership records.
- Unit-0 survivor generation validates the candidate spelling against the resolved device. With a VLAN-ID unit 0, `Base.0` is retained only for the ref that resolves to that same VLAN child; a mismatched synthetic base-device candidate is rejected, preventing duplicate or misbound membership.
- Regression coverage expands undeclared-member controls to both `wg0.99` and `wg0.999`, and asserts the unscoped WireGuard endpoint remains present. New cells cover explicit-survivor deduplication and VLAN-ID unit-0 narrowing with endpoint quarantine.

These changes are limited to the #9909 compiler gate, its regression suite, and this follow-up log. The merged `docs/log/9909.md` history is unchanged.

## RED → GREEN proof

- Reverting the survivor-device deduplication made `TestWireguardBareMemberNarrowingDeduplicatesExplicit9909` fail with two copies of `gr-0/0/0.1`.
- Reverting candidate device validation made `TestWireguardBareMemberVLANUnitZeroNarrowing9909` fail with two copies of `gr-0/0/9.0`; the guard rejects the mismatched synthetic base-device candidate and leaves the single VLAN-unit survivor plus its endpoint state intact.
- The restored implementation passes both cells and the expanded undeclared-member table. The lazy map path retains the existing strict, tolerant, alias, forwarding, shared-device, and clean-control behavior.

## Validation counts

- `go test ./pkg/config -run 'TestWireguard.*9909' -count=1 -json`: **25** passing test actions, 0 skipped, 0 failed, 1 package.
- `go test ./pkg/config -run 'TestWireGuard|TestWireguard' -count=1 -json`: **96** passing test actions, 0 skipped, 0 failed, 1 package.
- `go test ./pkg/config -count=1 -json`: **10,467** passing test actions, 0 failed, 8 skipped, 1 package.
