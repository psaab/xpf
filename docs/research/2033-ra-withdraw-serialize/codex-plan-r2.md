VERDICT: NEEDS-REVISION

1. MAJOR: r2 still overclaims the startup/normal-send guarantee.
`burstInterruptible()` only checks `draining()` before `sendRA()` and `stopCh` during the inter-send sleep (`docs/research/2033-ra-withdraw-serialize/plan.md:262-270`). A graceful withdraw can still land after the check and before the write, so a normal RA can be emitted after `withdrawAndStop()` begins. The same check-to-send gap exists after `advTimer.C` and after RS sleep before `s.sendRA()` (`plan.md:237-248`). This does not necessarily violate “goodbye is last,” because the owner later exits through `finishShutdown()`, but it violates the stronger invariant stated at `plan.md:186-189` and the user-facing r2 claim at `plan.md:297-299`. Either weaken the invariant/test language to “no lifetime>0 RA after the first goodbye / goodbye is last,” or add a real send-vs-shutdown exclusion.

2. MAJOR: `WithdrawOnce` claim is still underspecified in a way that can lose a legitimate `Apply`.
r2 says the claim should make concurrent `Apply` “skips/serializes” (`plan.md:416-418`). “Skip” is not acceptable: if boot-as-secondary `WithdrawOnce` wins the claim and a MASTER `Apply` arrives, dropping that `Apply` leaves no RA sender after the claim releases. T4b’s desired assertion is right (`plan.md:549-555`), but the design must explicitly require `Apply` to wait/retry after the claim, not skip. Current source shows why this matters: `WithdrawOnce` drops `m.mu` between guard and temporary sender (`pkg/ra/ra.go:150-173`), while `Apply` starts the real sender under the same manager lifecycle (`pkg/ra/ra.go:31-90`).

3. MODERATE: moving `conn.Close()` after join for hard `stop()` is an unnecessary regression risk.
Graceful withdraw needs the conn alive for owner-emitted goodbye, but hard stop does not. r2 moves close-after-join for both hard and graceful paths (`plan.md:275-287`, `plan.md:439-448`), whereas current `stop()` closes before waiting (`pkg/ra/sender.go:120-125`). That removes the current ability to unblock a stuck packet operation during `Clear` / `Apply` removal. Keep old close-before-join behavior for `modeHard`, or add a clear justification/write-deadline strategy.

Resolved r1 checks:

- W2 is now materially accurate: the real RS exposure is the goodbye-burst window plus the tiny pre-`stopCh` close gap, not 500ms after goodbye (`plan.md:79-101`; current source `pkg/ra/ra.go:106-107`, `pkg/ra/sender.go:161-169`, `pkg/ra/sender.go:230-239`).
- W3/T2 is corrected: concurrent `WriteTo` is an ordering issue, not itself a Go data race; `-race` belongs on `lastRA`/`ResendBurst` coverage (`plan.md:103-114`, `plan.md:538-542`).
- The single `stopCh` + atomic mode design fixes the r1 two-channel select skip. The memory-model argument is acceptable: mode is published before the close observed by the owner, including the CAS-loser-close case via atomic synchronization; `select` can no longer choose a separate hard-stop channel and bypass goodbye (`plan.md:213-219`, `plan.md:231-248`).
- `finishShutdown()` is reached on all sketched owner exits (`plan.md:221-248`). On hard stop it is called but does not send because mode is not graceful (`plan.md:254-259`).
- I12 is a real constraint, not hand-waving: the current `start()` path calls `ensureLinkLocal()` (`pkg/ra/sender.go:68-71`), and that can toggle the link (`pkg/ra/sender.go:386-400`). The standalone goodbye path must avoid it (`plan.md:469-474`).
- I10’s `rsReceiver` sequencing has no deadlock: owner exits on `stopCh`, caller closes conn after `<-stopped`, and detached `ReadFrom` unblocks (`plan.md:450-461`).

Codex session ID: 019ee26e-22a1-7e11-bbce-3c20062088d7
Resume in Codex: codex resume 019ee26e-22a1-7e11-bbce-3c20062088d7
