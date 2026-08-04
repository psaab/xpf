# AGY plan review — round 18 — #6749 armed-state plan v8.13 (92fb722e1)

**Reviewer:** AGY (hostile, zero-tool-call inline-evidence constraint; prompt /tmp/agy-6749-r18-prompt.txt assembled at 120,619 bytes: boilerplate + transport-trimmed plan + evidence excerpts store_persist.go:389-465, process_control.go:145-170, process.go:225-250, daemon_apply_commit.go:420-470). Raw output: /tmp/agy-6749-r18.out. Background bash `b4wkeltmj` (direct `agy --print-timeout 9m --print`).

**Verdict: DEMAND-REVISION** (4 BLOCKER + 4 MAJOR + 1 MINOR + 1 NIT).

---

1. **[BLOCKER] Direct contradiction in checked-quiescence post-quiescence try-lock handling** (§5-C/Delta 7; process.go:225-250): the v8.13 text says a post-quiescence try-lock skip routes through the restore finalizer, while the standing text says a contended per-mutation re-read "skips the mutation to the next backoff tick with the work item still claimed" — read together, workers can be left stopped for a 5-60s backoff tick. (= SMR18-4; resolution: the standing rule's scope is pinned PRE-QUIESCENCE; post-`Valid` skips route through the restore finalizer.)
2. **[BLOCKER] Incomplete Go control-response contract for `error_code` survival** (process_control.go:145-170; §6 item 12): today the OK=false path returns a zero-valued `ControlResponse{}` plus `errors.New(resp.Error)`; any caller doing `if err != nil { return err }` drops the response and the code. (= SMR18-7.1: the amended form returns the decoded response alongside the typed error; callers branch on `error_code` first.)
3. **[BLOCKER] Unbounded `m.mu` hold during blocking OS network I/O in `map_generation`** (§5-C/Delta 11): building the payload requires peer-MAC resolution (daemon_ha_fabric.go:484-490) — ARP/NDP inspection and netlink syscalls inside `m.mu`. (= SMR18-5; resolution: the resolution reads the manager's neighbor CACHE under the lock; a cache miss carries the existing unresolved-posture marker and the cache's regen drives the next attempt.)
4. **[BLOCKER] Input capture snapshots mutable state references rather than deep copies** (§5-C/Delta 2(i)): refs to mutable feed/overlay structures allow in-place mutation while the builder dereferences them outside `m.mu` — lazy read drift and data races. (= SMR18-2; resolution: the validation is the content HASH at send (mismatch → abandon); buildSeq supplies only the wire ordering.)
5. **[MAJOR] Unspecified outcome fold matrix for predecessor chain replays** (§5-C/Delta 6): outcome application is non-commutative; the plan lacks the explicit state-transition matrix for all outcome pairs. (= SMR18-3: restores-first-chronological, intents-after, head's own outcome terminal; §6 gains the matrix.)
6. **[MAJOR] Missing wire warning field and CLI delivery mechanism for exposure-gated commits** (§1/Delta 1(i); §6): ControlResponse carries no warnings field and §6 keeps CLI output byte-identical — the operator sees plain success. (= SMR18-7.2: the warning rides the COMMIT's result surface (the apply RPC's existing warning list), not a wire field; the exposure debt is visible in `show`.)
7. **[MAJOR] Unbounded factory-MAC blackhole for late-arriving members with backed-off retry clocks** (§5-C/Delta 9): the text says "(5s initial backoff)" but a member with prior failures sits at the 60s floor. (= SMR18-8: the bound is the member's current backoff + FIFO queueing + the transaction.)
8. **[MINOR] Polling `PersistDegraded()` does not accelerate disk write recovery** (store_persist.go:389-465; §1/Delta 1(ii)): the store's retry sleeps with doubling backoff; the poll only observes. (= SMR18-6: inherent; the bound is the store's maxBackoff, stated in the budget.)
9. **[NIT] `requestDetailedLocked` error-handling specification omitted** (§6 item 12): the explicit Go struct/error types returned when `!resp.OK && error_code != ""` are unspecified. (= SMR18-7.1.)

Evidence wishes (informational): daemon_ha_fabric.go:484-490 (peer-MAC resolution locking); handlers/mod.rs:255-267 (verb registration); manager_compile.go:177-228 (feed/overlay capture structure).

DEMAND-REVISION
