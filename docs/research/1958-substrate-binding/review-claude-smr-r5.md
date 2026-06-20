# Claude SMR — plan-review round 5 (v5 fold verification)

Reviewing: `plan.md` v5 block @ `1406f13f3`, branch `research/1958-refresh`
rebased onto origin/master `4e6fc2f2e`.

r4 was 3-way PLAN-NEEDS-MAJOR (Codex container-substrate defect; AGY stale-base
defect; SMR concur both real, rationale wrong). r5 verifies the v5 fold closes
both without introducing a new defect.

## Fold A (Codex — container substrate is real) — CLOSED

v5 fully and accurately folds it:
- The v5 block names `make test-ct` (`Makefile:177-178`), the `xpf-container`
  profile with `eth0..eth4` veth NICs (`setup.sh:296-318`), and the deploy
  path — matching Codex's r4 evidence.
- It correctly states xpf-in-container bring-up is non-functional today
  (`enumerateAndRenameInterfaces` early-returns on `len(nics)==0`,
  `linksetup.go:66-73`, verified) and that `xpf-test.conf` uses Junos names
  (`:1-59`, verified) = the deferred sub-mode (b).
- It DROPS the three false v4 phrases ("zero consumer," "purely speculative,"
  "no CI substrate to smoke it on") and rebuilds the defer rationale on three
  defensible legs: no bug filed, no remote-reachable non-PCI lockout, large
  fragile surface.
- It adds the design fork (container config naming: sub-mode (a) + `eth0`-named
  config is the cheap first move) instead of burying it — a genuine
  improvement over v4.
Not overstated: "broken-by-design-today, latent, no bug filed" is precisely
right — no issue tracks it, and the path is plausibly used for
dataplane-isolation experiments, not interface-management.

## Fold B (AGY — stale base) — CLOSED

`git merge-base --is-ancestor 4e6fc2f2e 1406f13f3` → true (rebased). The
worktree source now matches the v5 claims (`pkg/devicemap/devicemap.go`
present; `LinuxIfName` body confirmed; line numbers align). The artifact no
longer contradicts its own text.

## Did the corrected rationale survive my hostile re-test?

The single strongest attack on PLAN-DEFER is: "a broken `test-ct` in master is
debt; the smoke harness is non-functional for interface management — fix it."
Rebuttal holds: there is no filed requirement that `test-ct` exercise xpf
interface management (it predates and is orthogonal to it), and Slice B/C is
real surface on the most fragile bring-up path. Speculatively building it for a
convenience target nobody has prioritized trades regression risk for ~zero
current value. Defer, with a clean un-defer trigger (file the "make test-ct
supported" bug → `/engineer 1958` Slice B from this doc), is the disciplined
call. This matches the project's PLAN-KILL-at-zero-incidence (#1760) and
capture-gated-deferral (#1782) precedents.

The r2-fold-B PCI-keyed-lifeline gap (`bootstrap.go:609-625`) is real and still
unfixed, but it is not a *lockout* on any provisioned remote-reachable
substrate today (container = delegate/incus-exec; no VMBus/XenBus/cloud
in-tree). So it does not force "build now"; it is correctly captured as an
un-defer trigger.

No new defect introduced by the v5 edit.

**VERDICT: PLAN-READY** — both r4 folds closed; defer disposition sound on the
corrected rationale; architecture (v1-v3) unchanged and validated; Slice A
(#1956) shipped. The architecture is the design-of-record; the net-new Slices
B+C are deferred pending a filed "make the container path supported" bug or a
real remote-reachable non-PCI substrate.
