# Codex hostile plan review r4 — #1918 — task 019ed443-ac07-7eb2-bae0-2f37d239beea

Verdict: PLAN-NEEDS-WORK

NF1 VERIFIED (§5c). NF2 + r3 LinkSet-error blocker VERIFIED (commit-after-success). NF4 VERIFIED
(UNRECOGNIZED -> TRANSIENT). NF3 textually verified but generates new blocking defect F7.

F7 (HIGH) — gen-guard TOCTOU: the gen check (step 4) is under t.mu but LinkSet* (step 5) fires
outside any lock. A concurrent Apply can recreate the tunnel (bump gen) between the gen check and
the LinkSetDown syscall; if the kernel reuses the old ifindex, the stale runner passes the guard
and LinkSetDown's the replacement link, committing stale state. Fix: gen re-check atomic with /
after the LinkSet*, e.g. hold t.mu across check AND LinkSet*, or post-op gen re-verify.

[r5 resolution: drain-before-recreate. Apply reordered to cancel+drain the old runner before
LinkDel/LinkAdd, so no stale runner exists during recreate. linkGen kept as defense-in-depth.
Codex's "hold t.mu across LinkSet*" rejected — reintroduces lock-across-netlink, the exact #1918
bug.]
