# Claude SMR hostile plan-review — #1956 r2

Reviewing plan.md v2 (with §13 r1 disposition) as domain SMR adversary.

## Verdict: PLAN-READY

v2 folds every r1 blocker with a code-grounded resolution, and I
independently re-verified the two load-bearing claims:
- `runBootstrapExitStartup` does call `enumerateAndRenameInterfaces` at
  `daemon_run.go:1557` (R-4 is real; v2 branches both `:345` and `:1557`). ✔
- `networkd.Apply` globs `10-xpf-*` and removes any file not in `expected`
  at `networkd.go:133-145` (R-5 is real; v2 adds explicit managed→unmapped
  migration semantics). ✔

## Per-finding check of v2 resolutions

- **R-1 (PCI durability / VF / slot-swap hijack):** RESOLVED. The
  topology-change detection (PCI-match-but-MAC-mismatch → REFUSE, not silent
  bind) is the correct answer to AGY's slot-hijack and Codex's VF instability.
  Keeping PCI primary for PF/onboard while steering VFs to a `key mac`
  override is the right pragmatic split. The corrected §3 stability table no
  longer overstates VFs.
- **R-2 (stale `.link` misbind pre-daemon):** RESOLVED. Scrub-then-rewrite of
  the full `10-xpf-*.link` set against resolved bindings, as an explicit MVP
  deliverable, closes the udev-before-daemon window.
- **R-3 (lifeline resolver = running MAC):** RESOLVED. v2 strikes the "reuse"
  language (both in §8 and §2), specifies a new `PermHWAddr` resolver with
  empty/duplicate handling. Correct.
- **R-4 (bootstrap-exit path):** RESOLVED. Both rename call sites branch.
- **R-5 (networkd stale-file sweep un-renames leave-alone):** RESOLVED with
  honest scope — v2 explicitly does NOT promise to restore the operator's
  prior addressing, only a clean stop-managing. That is the right contract.
- **R-6 (RETH MAC-fallback exclusion):** RESOLVED. PCI-only + commit-reject of
  `key mac` on RETH members preserves the `OriginalName=` invariant.
- **R-7 (compileChassis early-return / empty-tree-non-nil / keyValueType):**
  RESOLVED. Mode selection on `len(Entries)>0` (not `!= nil`) closes the
  empty-block trap; independent compile of the device-map subtree; correct
  named-instance slot typing per docs/config-schema.md.
- **R-8 (deferred-reboot lockout — AGY's headline Critical):** RESOLVED by the
  commit-time pre-flight that resolves the proposed map against present NICs
  and rejects (or force-gates) a change that would strand the mgmt/lifeline or
  a revenue NIC on next boot. This is the single most important addition — it
  converts a latent reboot-time lockout (past the commit-confirmed window)
  into a commit-time error while the operator is still connected. The #1922
  lifeline remains the independent backstop.
- **R-9 (empty/rolled-back policy resolution):** RESOLVED by an explicit
  decision (absent map → positional manage-down, safe because the protected
  set still shields mgmt + R-8 pre-flight catches the rollback-into-claim-all
  case). No longer ambiguous.

## Residual notes (non-blocking)

- The R-8 commit pre-flight is the highest-risk part to implement correctly
  (it must resolve identities at commit time, which the daemon already does
  for the lifeline, so the machinery exists). Flag for careful review on the
  implementation PR, but the DESIGN is sound.
- `show chassis device-map candidates` promotion to MVP is correct; without
  it map authoring is error-prone.

## Why PLAN-READY now

v2 is the smallest version that is actually safe. r1 proved the smaller cut
reproduced the hazard; v2's six-part bundle is irreducible and each part is
tied to a verified code site. No architectural defect remains; the identity
key is durable for the primary target with explicit, loud handling of the
cases where it isn't. The #1922 lifeline composition is preserved and
strengthened (R-8). Ready for manual approval → /engineer.
