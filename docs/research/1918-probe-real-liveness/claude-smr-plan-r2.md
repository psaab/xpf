# Claude SMR — HOSTILE plan review r2 — #1918

Reviewer: Claude SMR. Posture: hostile re-review of r2 against my r1 findings + hunt for new
defects introduced by the r2 edits.

## Verdict: PLAN-READY

r2 resolves all four of my r1 findings and absorbs AGY's decisive overlay/underlay correction
and Codex's runner-identity/TOCTOU findings. The architecture is now sound and the remaining
choices are implementation-grade, appropriate for the /engineer phase. I checked the r2 edits
for newly-introduced defects and found only one MINOR worth recording (does not block READY).

## My r1 findings — disposition in r2

- **F1 (match predicate contradiction) — RESOLVED.** §5a now states a single authoritative
  predicate: Seq + Data-nonce, ID ignored on datagram / advisory on raw (plan §5a, §7.1, R3 all
  agree now). The kernel `id = inet->inet_sport` rewrite is cited correctly. The implementer can
  no longer ship the always-Dead bug.
- **F2 (exactly-one-LinkSet invariant unstated) — RESOLVED.** Axis D now states the invariant
  explicitly: decision + `Up` write in one locked section, netlink keyed to `changed` after
  unlock, edge guards preserved. It additionally handles the two cases I only gestured at —
  LinkByName error (revert) and link replacement (ifindex guard). Stronger than I asked for.
- **F3 (Dead→Unsupported→recovery stranding) — RESOLVED in substance.** This was my concern that
  a link left admin-down by a real failure, then entering sustained-Unsupported, never recovers.
  r2's C1 holds the prior `Up` (= the real value) and never `LinkSetUp`s under Unsupported — so
  the link stays in whatever admin state the last *real* probe set. That is the defensible
  choice IF the operator is alarmed; r2's transient-escalation (loud status + slog.Error) and
  the structural one-shot Warn provide that alarm. I withdraw the r1 demand that we
  auto-restore-up on sustained-Unsupported — on reflection auto-`LinkSetUp` under "we cannot
  probe" would itself be a route-existence-style false-up, exactly the class of bug #1918 fixes.
  Hold + alarm is correct. (One residual, see N1.)
- **F4 (per-tick socket reopen cost) — RESOLVED by §5b collapse.** Since r2 drops VRF binding,
  the "reopen per probe to pick up a late VRF" pressure is gone; a per-keepalive cached socket
  is now viable and §7/R4 imply it. Not a blocker either way at 1 Hz.

## New-defect hunt over the r2 edits

- **N1 (MINOR, non-blocking) — the "hold prior Up" value can be stale-up across a daemon
  restart.** C1 holds the *in-memory* prior `Up`, which `startKeepalive` initializes to `true`
  (`tunnel.go:955` `Up: true`). So a daemon restart in a structurally-Unsupported environment
  (no `ping_group_range`) starts every keepalive at `Up=true` and holds it there — reporting
  `KeepaliveUp=nil`/"unknown" in status (good) but with the kernel link left up by the apply
  path. This is acceptable (it matches the pre-fix availability posture and status now tells the
  truth), but the plan should note it explicitly so /engineer doesn't "fix" it into a
  start-down-when-unprobeable behavior that would black-hole tunnels on every privilege-less
  boot. Recommend one sentence in §6 C1 / R1: "On startup under structural-Unsupported, the link
  retains the apply-time admin state (up); status reads 'unknown', not 'up'." Not a blocker.
- **Underlay-table probe (AGY #2 fix) — verified correct.** GRE/IPIP outer encapsulation
  resolves the tunnel `Destination` via the FIB in the device's L3 domain; for the standard case
  (tunnel device's underlay in the global table) an unbound probe socket resolves the same dst
  the same way. r2 correctly scopes underlay-in-a-VRF as out-of-scope. This is the right call.
- **Transient/structural errno split — plausible, refine at /engineer.** Structural = EPERM
  (cap/ping_group_range), EACCES, EAFNOSUPPORT, EPROTONOSUPPORT. Transient = EMFILE, ENFILE,
  ENOBUFS, ENOMEM. The plan correctly says "classify errno at ListenPacket time" and defers the
  exact table to implementation. Acceptable for a plan; the test plan covers both arms.
- **Axis D revert-under-mu — no new race.** Re-acquiring `mu` to revert `state.Up` after a
  LinkByName error is safe because this goroutine is the only writer of `state.Up`; the revert
  cannot race a concurrent writer (AGY #5 established this), and `GetStatus`/`Apply` only read
  under the lock. The brief window where `Up` is the flipped value (between step-1 unlock and the
  step-3 revert) is observable by a `GetStatus` racing in — it would momentarily report the
  not-yet-effected state — but that is a sub-second status blip with no netlink consequence,
  strictly better than r1's lock-across-netlink hazard. Acceptable.

## Conclusion

PLAN-READY. The one residual (N1) is a documentation sentence, not a design change. Recommend
shipping the recommended combination (A1 + auto-A2 + B1 + C1-with-transient-escalation + D + 5a
+ 5b). The follow-ups (monitor.go 5a, C3 knob, underlay-in-VRF, package split) are correctly
scoped out.
