# Issue #12525 closeout

## Disposition

The compiler-gate implementation and comprehensive regression coverage landed on
master through PR #12540 (merged 2026-10-10). The issue remained open solely for
the #12085 lab ICMP frag-needed capture. That capture was owned by #12085 / PR
#12333, not #12525; docs/log/12085.md records it was not run. #12085 has since
closed COMPLETED via PR #12333. The capture remains unrun but no longer blocks
this compiler-gate issue; the lab proof is tracked separately in #12809 (plan-deferred-lab), which owns the capture.

## Evidence

- PR #12540 contains the non-zone scope acceptance, per-side scope provenance,
present-empty fail-closed validation, and interface-mode counter handling.
- `docs/log/12525.md` records the implementation, tests, and known limitations.
- Reverified on the source containing PR #12540: `go test ./pkg/dataplane -run 'TestCompileNAT.*12525|TestCompileNAT12085' -count=1` and `go test ./pkg/config -run 'NAT|Nat' -count=1` passed.
- No live cluster was available; no lab capture is claimed.
**Independent acceptance remains outstanding:** the lab ICMP frag-needed capture was not run; it is owned by #12809. The closeout here is limited to the compiler-gate scope of #12525; it is not forwarding/lab sign-off for #12085.

## Risk

This PR records the issue disposition only. It does not change dataplane code or
claim live forwarding validation.
