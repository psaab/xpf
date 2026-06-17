# #1958 plan v1 — Claude SMR hostile review (round 1)

Reviewer: Claude (domain SMR + SW-design). Plan @ 33a1d9de4. Base
origin/master @ 5d452736e. Reviewed as ARCHITECTURE/umbrella, treating #1956
v3 as settled foundation.

## Verdict: PLAN-READY (with three folded clarifications + one OQ promotion)

The proposal is sound: the three-axis framing is correct, the increment
ordering is genuinely free of hidden dependencies, and the central de-risking
claim survives my hostile check with one addition. It is not a PLAN-KILL or
NEEDS-MAJOR — the remaining items are clarifications, not redesigns.

## Claim 1 — binding/configuration split is load-bearing (CONFIRMED)

Not hand-waving. #1956 already implements exactly this split for bare metal
(identity-keyed binding resolved start-of-boot, config references logical
names), and #1922 already proves the binding/protected-set is resolved
*config-independent before netlink mutation* (`bootstrap.go:408-437`,
start-of-boot). The umbrella's contribution is making the three cells (key /
rename / reachability) pluggable, which is a generalization of a proven
primitive, not a new bet. PASS.

## Claim 2 — §5.3 alias-mode de-risking (CONFIRMED, with one addition)

I hunted for a `LinuxIfName` consumer that breaks on a literal `eth0` config
name. Findings:

- **Slot-math sites are all guarded.** Every `InterfaceSlot` caller checks
  `slot >= 0` before using it: `cluster/monitor.go:258-259,446-447`,
  `grpcapi/server_diag.go:361-362`, `config/types.go:75-77`,
  `config/compiler.go:347-348`. A literal `eth0` → `InterfaceSlot=-1` → those
  branches are skipped (treated as standalone/no-FPC). The plan's §5.3
  caveat is accurate; these are safe-by-construction, not blockers.
- **NEW site the plan must name: name-prefix-keyed mgmt-VRF.**
  `daemon_apply.go:308` keys management-VRF membership on
  `HasPrefix(name,"fxp"|"fab"|"em")`. A container interface (`eth0`/`lan0`)
  does NOT match → not placed in vrf-mgmt. For a container *data* interface
  that is **correct** (it is not a mgmt port). So this does not break the
  claim, but it is a second name-prefix assumption beyond pure slot-math and
  belongs in the §5.3 audit list so /engineer doesn't trip on it.
- **No counter-example found** where a downstream consumer (networkd/FRR/
  VRRP/DHCP/zones) mis-handles a literal `eth0`. `LinuxIfName("eth0")=="eth0"`
  holds and all those keyed lookups resolve. The "nearly free for sub-mode
  (a)" claim STANDS.

FOLD: add `daemon_apply.go:308` (fxp/fab/em prefix → vrf-mgmt) to the §5.3
audit list with the note "absence-of-match is correct for container data
ports; confirm no mgmt-VRF is expected."

## Claim 3 — substrate detector priority + container tell (SOUND, one guard)

Container-outranks-VM is correct: an incus/kvm-backed container can show
hypervisor ancestry, so the container-specific signals must win. The plan
already calls `systemd-detect-virt --container` explicitly (the right
semantic — `--container` reports only container techs). The
"`enumeratePCINICs` empty + veths present" tell is the strongest signal AND
is the one that directly explains the original bug, but it is a *corroborating*
signal, not the sole one — the plan correctly lists `/.dockerenv`,
`/run/.containerenv`, and `detect-virt --container` ahead of it. False-
positive risk (a diskless PCI-less appliance) is mitigated because detection
only *defaults* the profile and `platform-profile` overrides. PASS. Minor:
the plan should state the detector is **advisory** (sets defaults) and never
*gates* a binding — an explicit binding always wins regardless of detected
substrate. (It implies this in §6.3 but should say it as an invariant.)

## Claim 4 — A→B→C ordering (CONFIRMED free of hidden dependency)

The risk is "does the reconcile need `platform-profile` (C) before B can set
`leave-alone`?" It does not: #1956's `unmapped-interface-policy` is an
explicit per-stanza leaf consumed by the reconcile (compiler_iface.go path),
independent of any profile. Slice B's alias entries set `leave-alone`
explicitly via that same #1956 leaf. C only *defaults* the leaf when unset.
So B is fully functional with explicit selection and C is pure sugar. The
ordering holds. PASS.

## Claim 5 — generalizing #1922 lifeline (SOUND, guard already carried)

Generalizing `defaultMgmtInterface="fxp0"` into a declared reachability
contract does NOT break SAFE-BOOTSTRAP *provided* the §7 safety guard is
honored: "protect the explicitly-declared mgmt NIC(s), or none — never auto-
fabricate fxp0; make console/delegate explicit so a typo fails loudly." The
machinery already tolerates an empty protected set on the no-default-route
path (`setupBootstrapLifeline` 455-461). The genuine hazard — operator
declares `console-only` but actually SSHes over a data NIC — is already named
in §7 (inherited from #1956 §9.6). The one thing I'd sharpen: the contract
must make `console-only`/`delegate` an *assertion the operator made*, so the
daemon can refuse to silently strand a box whose only route is over a data
NIC it's about to leave unprotected. The plan says this; keep it as a hard
/engineer gate. PASS.

## Additional SMR observations (non-blocking)

- **OQ-3 (delegate vs console-only):** I agree they are behaviorally
  identical from xpf's view. Recommend KEEPING both names anyway — the audit/
  `show` value of explicit operator intent is real and cheap. Not a collapse.
- **OQ-6 (container binding delivery):** the binding-before-config ordering
  constraint is the subtle one. An env var or a mounted file read at daemon
  *start* (before configstore load) is cleanest; a candidate/active config
  leaf for the binding has a bootstrap-ordering smell (the binding must exist
  to bring up the interface you'd commit the config over). For containers
  this is fine because reachability is `delegate` (orchestrator exec), so the
  binding can legitimately come from the active config on a later commit — but
  the FIRST bring-up needs the injected binding. Recommend Slice B settle
  this as: injected file/env for first-boot, configstore leaf thereafter.
- **Scope discipline is good:** HA-in-container and logical-alias sub-mode (b)
  are explicitly out-of-scope and named, not silently dropped. This is the
  right umbrella hygiene.

## Required folds for v2 (all clarifications, not redesign)

1. Add `daemon_apply.go:308` (fxp/fab/em prefix → vrf-mgmt) to the §5.3 audit
   list (Claim 2).
2. State the detector-is-advisory invariant explicitly in §6 (Claim 3).
3. Promote the OQ-6 binding-delivery answer into §2.1 as a recommendation
   (injected-for-first-boot, configstore-thereafter) rather than leaving it
   purely an open question.

These are doc edits; the architecture is approved.
