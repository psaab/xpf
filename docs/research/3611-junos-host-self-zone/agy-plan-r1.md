# AGY adversarial plan review r1 (#3611)

Job: adversarial-review-mr1vqaze-dg80s0 (succeeded). Read against current
source (policy.rs:2868, compiler_validate_strict.go:2715-2733, daemon_nft.go).

## Verdict (split)

- **Piece A — from-zone junos-host (host-originated), kernel nft output chain:
  PLAN-KILL / document-only.**
- **Piece B — to-zone junos-host GLOBAL policy (host-inbound, userspace-dp):
  PLAN-READY.**

Single most important reason: the split-enforcement model breaks logging + ALG
state tracking, and the mandatory fail-closed commit gate (needed to avoid the
partial-fidelity footgun) would reject the vast majority of real-world Junos
application-catalog configs — a highly complex, brittle feature with an
unacceptably high self-DoS blast radius.

## Findings (attack vectors)

1. **KILL vs DEFER.** A fail-closed commit gate on nft-representable matches is
   mathematically correct but operationally untenable: nft cannot represent
   dynamic-port application sets or Junos ALGs (e.g. junos-ftp), so almost all
   outbound self-traffic policies would fail commit. A feature that rejects ~90%
   of standard configs is worse than a documented limitation.
2. **oifname classification UNSOUND at output for VRF (l3mdev).** At the output
   hook, packets bound to a VRF master report the VRF device name as oifname, not
   the final physical interface. Moving to postrouting to recover the physical
   iface LOSES the synchronous `reject` socket error → host sockets hang / time
   out silently. This is a concrete correctness blocker for the nft-output
   mechanism.
3. **Split-enforcement hazard.** One policy family across two runtimes (Rust
   dataplane + kernel Netfilter) = maintenance tax, no RT_FLOW logging parity for
   outbound rejects, and no shared conntrack helpers/ALGs.
4. **Lifeline insufficient.** Low-level lifelines (fxp0/em0/fab*, ESP/AH, ICMP)
   do NOT protect logical dependencies: blocking a zone carrying outbound DNS,
   NTP, RADIUS, or cloud-metadata causes delayed but catastrophic control-plane
   failure.
5. **Piece B cleanly READY.** `to-zone junos-host` globals can be enforced
   entirely in userspace-dp on the LocalDelivery path — low-risk, high-fidelity,
   no split-conntrack, no self-DoS.

## Impact on the plan

AGY's #2 (oifname/VRF unsound) and #1 (fail-closed gate rejects most app configs)
materially weaken the plan's "a real, usable mechanism exists" pillar for Piece
A. Combined with the split-engine + logging-parity + logical-lifeline findings,
the convergent disposition for Piece A moves from DEFER to **document-only**
(build not recommended). Piece B (to-zone-global) is endorsed as the buildable,
low-risk slice.
