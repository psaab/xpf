// Package memlockcensus gates the set of tests that go INERT without the
// privilege to raise the memlock rlimit (#8371).
//
// THE DEFECT. 42 test sites across 19 files call `rlimit.RemoveMemlock()` and
// `t.Skipf` when it fails. Without CAP_SYS_RESOURCE the tests SKIP, the package
// still reports `ok`, and the guards they encode provide no protection. A
// reviewer greps, finds `TestApplyHelperStatusRejectsQueueIDBeyondStride`, and
// reasonably concludes the #4894 aliasing defect is guarded — and whether it is
// depends entirely on where the suite ran.
//
// This is the codebase's recurring failure shape — a check that fails to a
// value indistinguishable from healthy — applied to the checks themselves.
//
// MEASURED, because #8371 asks for the measurement before the fix and names it
// the first task. On the development host these guards do NOT run:
//
//	$ id -u        -> 1000        (not root)
//	$ ulimit -l    -> 8192        (8 MiB, cannot be raised unprivileged)
//	$ go test ./pkg/dataplane/userspace/ -run QueueIDBeyondStride -count=1 -v
//	    RemoveMemlock: failed to set memlock rlimit: operation not permitted
//	  --- SKIP: TestApplyHelperStatusRejectsQueueIDBeyondStride (0.00s)
//	  ok  github.com/psaab/xpf/pkg/dataplane/userspace  0.005s
//
// So this is not a CI-only concern deferred to a machine nobody watches. It is
// the primary development environment, where `make test-go` runs and where
// every change is first validated. All 42 are inert here, today.
//
// WHAT THIS PACKAGE DOES, and what it deliberately does not.
//
// It does NOT make the suite red when memlock is unavailable. That would turn
// every developer's `make test-go` red for an environment property they cannot
// change, and a gate everyone learns to ignore is worse than the silence it
// replaced.
//
// It makes the SET a gated quantity instead. The census below is a registry:
// a new memlock-gated guard cannot be added without appearing here, and a
// removed one cannot linger. That closes the reviewer-grep harm, because the
// registry names every guard whose protection is conditional, in one place, and
// the count cannot drift silently.
//
// And it makes the inertness LOUD where it matters: when the privilege is
// unavailable, TestMemlockGuardsAreInertHere reports exactly which guards did
// not run, by name. Under XPF_REQUIRE_MEMLOCK_GUARDS=1 — for the privileged leg
// — it FAILS instead, so an environment that is supposed to execute them cannot
// silently stop.
//
// #9337, TWO CORRECTIONS.
//
// The leg it deferred to did not exist. At the time, `.github/` held only
// `instructions/`; there were no workflow files and no CI in this repository
// at all, and nothing anywhere set XPF_REQUIRE_MEMLOCK_GUARDS. 42 guards were
// deferring to a name. (The repository has since gained pull-request
// workflows under `.github/workflows/`; the privileged leg still runs only
// locally — GitHub-hosted runners have no CAP_BPF.)
// `make test-memlock-guards` is now that leg (and a prerequisite of
// `make test-root`): it derives the package set FROM the registry, runs it
// under the required privilege, and verifies BY NAME that every registered
// Test... function actually produced a `=== RUN` line — a `-run` predicate is
// a claim about names and fails silently in the only direction that matters.
//
// And the capability named here was the WRONG ONE. This package used to advise
// "Run as root or with CAP_SYS_RESOURCE", and its readiness predicate was
// `rlimit.RemoveMemlock()` succeeding. Neither is the capability the guards
// consume. Measured, by raising only the memlock rlimit and dropping straight
// back to the unprivileged user:
//
//	uid=1000  memlock cur=18446744073709551615
//	RemoveMemlock: OK        <- the old predicate: "all 42 guards execute"
//	ebpf.NewMap:   FAILED (map create: operation not permitted)
//
// Following the old advice exactly produces an environment the census calls
// READY and the guards cannot run in: they stop skipping and start FAILING, at
// map creation, with an error that looks nothing like the defects they exist to
// catch. A gate that measures one dimension and reads as validation of another.
// probeGuardReadiness therefore performs the first operation every guard
// performs — a trivial BPF map create — and the report distinguishes the three
// states rather than two.
package memlockcensus
