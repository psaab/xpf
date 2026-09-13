## NEEDS-MAJOR

The test-only lane remains worthwhile, but this plan contains an inaccessible helper dependency, a false general invariant, and an ECMP entry-point mismatch.

Reviewed checkout source read-only; I could not independently verify the supplied commit/base or run tests with the available tools. Paths below are relative to `userspace-dp/src/afxdp/` unless stated otherwise.

### Blocking findings

1. **The proposed construction helpers cannot call the claimed APIs.**
   `docs/pr/9522-phase0/plan.md:45-46,60-62,96-98` says `sort_routes` and `populate_routes` are accessible from the new forwarding test module. They are `pub(super)` inside private `forwarding_build::fib` (`forwarding_build/fib.rs:37,161`), and neither is re-exported (`forwarding_build/mod.rs:32,44-48`). A glob import does not bypass privacy.

   **Required:** construct relevant fixtures through the existing accessible builder (`forwarding_build/mod.rs:196,209`), or revise the test placement. Do not copy the comparator into a test helper: that would stop testing production sorting. No production visibility changes are necessary.

2. **“Same SET, different insertion orders ⇒ identical resolutions” is false without qualifications.**
   Plan lines 73-74 contradict lines 72: equal-prefix/equal-preference competing routes retain insertion order. Production explicitly uses stable sorting (`forwarding_build/fib.rs:162-183`) and first matching entry (`forwarding/fib.rs:427-430,657-660`).

   **Required:** remove the chunk-reassembly claim. Restrict permutation invariance to fixtures with an unambiguous winner—no competing ties—or preserve relative order within ties. Include an explicit reversed-tie case showing that the winner changes.

3. **The ECMP cell cannot exercise its advertised flow hashes through the chosen entry point.**
   Plan lines 81-83 promise fixed-flow-hash sweeps. `lookup_forwarding_resolution_in_table_with_dynamic` passes through the non-ECMP wrapper, which supplies `None` (`forwarding/fib.rs:183-200`); selection therefore uses destination hashing (`forwarding/fib.rs:533,764`).

   **Required:** either call the existing `lookup_forwarding_resolution_inner_ecmp` with explicit hashes for this cell, documenting the exception, or describe it honestly as destination-hash coverage.

   Moreover, repeatability plus “winner belongs to slice” does **not** establish order preservation: an implementation always selecting the first member passes those assertions. For a semantic-preserving LPM cutover, exact member selection at a supplied hash and fixed liveness is legitimate—not bitmask over-pinning. Specify small expected selections and a reordered-slice case. The observable contract is authored-order modulo selection over live members, with full-slice fallback when none are live (`forwarding/fib.rs:1098-1129`). The bitmask itself is not the contract.

### Semantic checks and scope decisions

- **MissingNeighbor attribution: yes, with fixture constraints.** Positive, non-tunnel static next hops retain the selected member’s ifindex (`forwarding/fib.rs:575-613,803-840`); connected routes do likewise (`:455-474,684-703`). `session_glue/mod.rs:46-65` only enriches transmit/MAC/VLAN fields, not egress attribution. Require positive distinct ifindices, tunnel IDs zero, empty static **and** dynamic neighbor maps, and no local-address membership. An unresolved *interface* yielding ifindex zero instead produces `NoRoute`; “unresolved next-hop always means MissingNeighbor” is too broad.

- **Cells 1–3 and connected comparisons are correct.** Longest prefix precedes ascending preference; ties preserve insertion order. Connected wins equal or longer prefix regardless of static preference (`forwarding/fib.rs:863-899`). `single()` supplies exactly one member with the passed fields (`types/forwarding.rs:955-1006`).

- **Discard and NoRoute expectations are correct.** Discard returns `(DiscardRoute, 0)` after route selection (`forwarding/fib.rs:478-491`); no match returns `(NoRoute, 0)` (`:843-855`). Empty-table coverage alone does not test misses in a populated table: add an outside-prefix destination.

- **Keep next-table coverage, but make it LPM-specific.** Use a selected more-specific next-table route over a usable ancestor, checking successful recursion and terminal failure without ancestor fallback. A missing target table yields `NoRoute`, not `NextTableUnsupported`; cycles and depth exhaustion produce the latter (`forwarding/fib.rs:413-426,493-529`). A cycle test cannot prove early cycle detection: depth exhaustion produces the same asserted pair. Do not claim that mutation coverage.

- **Snapshot coverage is needed; duplication is not.** Builder-driven fixtures also solve finding 1. Direct state cannot test declared-family validation or next-hop inference (`forwarding_build/fib.rs:56-125`). Retain existing #6568 ingest coverage (`forwarding_build/tests.rs:3315,3367`) rather than duplicating it under a “every cell performs lookup” invariant. Its expected typed error is correct, but it is a build contract, not a lookup disposition. Existing table-scoped gateway inference tests start at `forwarding_build/tests.rs:3525`; cite these complementary gates. Add a builder-to-lookup IPv6 canonical-table case where it contributes distinct coverage.

### Q6: do not kill the salvage

A bounded regression corpus has value without a committed trie implementation. However, label it **selected lookup-semantic coverage**, not proof of complete equivalence or remediation of #9522.

No cluster smoke or full Go suite is warranted for this scope; the proposed package-level Go check is sufficient. Replace “5× determinism proof” with “repeat-run check,” and enforce the no-production-delta rule using the actual scoped diff, not merely `git status`.
