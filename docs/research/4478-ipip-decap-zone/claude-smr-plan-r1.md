# Claude SMR hostile plan-review — #4478 r1

**Verdict: PLAN-REVISE** (not READY). The crux is correctly diagnosed and the
GRE contrast is accurate, but the recommendation ships a partial fix whose
security value is weaker than the plan admits, and the plan under-weights the
one genuinely fail-closed *interim* (refuse the unsafe config). Four required
changes below before I move to PLAN-READY.

## What the plan gets right (verified independently)

- **Crux confirmed.** `is_local_destination` (`lib.rs` L1363-1380) returns true
  for the IPIP outer dst (tunnel-source is an interface address published to
  `USERSPACE_LOCAL` by `buildLocalAddressEntries`, `maps_sync.go` L1400-1436) →
  `cpumap_or_pass` → kernel `Iptun` decap → inner kernel-forwarded. XDP is an
  ingress-only hook, so the decapped inner packet does NOT re-ingress an XDP
  program on egress. **The inner packet is kernel-forwarded raw** — the parent's
  crux question #1 answer is correct, and it is fail-OPEN (not merely wrong-zone).
- **GRE contrast accurate.** GRE uses a `netlink.Tuntap` anchor (no kernel GRE
  device), and the shim `native_gre` branch (L646-668) skips `is_local_destination`
  and redirects to XSK; enforcement is the re-zone (`gre.rs` L750-763), not the
  `GRE_DECAP_INGRESS_FLAG` (which only picks the `tcp-mss gre-in` clamp,
  `forwarding/mod.rs` L1241). Correct.
- **OQ-1 resolution correct.** `parse_l4` default arm (`lib.rs` L1526) → ports=0
  for proto-4. The static key is deterministic. Path B is mechanically viable.
- **The degraded-residual finding (§4-3/HI-2) is the strongest part of the plan**
  and is correct: the degraded short-circuits (L465-533) precede both the session
  lookup (L585) and the native branch (L584/646), so neither Path B nor Path C
  closes the residual — only removing the kernel `Iptun` (Path E) does.

## Required change 1 — the degraded residual is attacker-INDUCIBLE; say so

The plan frames the residual as a "sub-second window an attacker cannot force on
demand" (§3). That is too generous. The degraded state is entered on
heartbeat-stale / binding-not-ready (`lib.rs` L465-533). A determined attacker
who can **degrade or crash the userspace helper** (resource exhaustion, a helper
panic, a bulk-sync stall — the control socket is explicitly contention-sensitive
per CLAUDE.md) can *re-open the fail-open* and then inject. Path B's guarantee is
therefore "fail-closed while the helper is healthy," and helper health is itself
an attack surface. This does NOT kill Path B (steady-state closure is still a
real improvement over 24/7-open), but the plan must state the residual is
adversarially reachable, not merely incidental, and must carry that into the
Path E follow-up priority. **Revise §3 and HI-2.**

## Required change 2 — add Path F: commit-time fail-closed refusal as the interim

The plan enumerates B/C/E (+ rejected A/D) but misses the cheapest genuinely
fail-CLOSED interim: **reject `mode "ipip"` at commit** (or reject it on a tunnel
whose unit is placed in a security zone reachable from an untrusted zone) with a
clear error pointing at #4478, UNTIL enforcement exists. xpf already hard-rejects
unsupported/unsafe config (e.g. `ErrEBPFDataplaneRetired`). If the security
posture is "no fail-open," the principled move when the fix is blocked is to
refuse the feature, not to ship a partial steering hack that is open during
helper-degraded windows. Path F is fail-closed, needs no dataplane change, no
#1864 dependency, and is trivially correct. Its cost is breaking any existing
IPIP user — which is exactly the tradeoff the security owner should weigh against
Path B. **Add Path F to §5 and to the §11 decision criteria.** The honest
framing is a three-way choice: B (partial, open-when-degraded), F (fail-closed,
feature removed), or DEFER→E (fail-closed, feature kept, blocked on #1864).

## Required change 3 — prove the synthetic key cannot collide with a real session

Path B makes Go a writer of `userspace_sessions`. The plan's persistence story
(B2 note) argues userspace-dp's per-session deletes are keyed on its own
`SessionTable` so they won't evict the synthetic key. Strengthen this with the
COLLISION direction the plan omits: a **transit** IPIP flow (proto-4 passing
THROUGH the firewall, outer dst NOT local) would get a userspace-dp session with
key `(proto=4, ports=0, src, dst_non_local)` — distinct from the synthetic
`(proto=4, ports=0, remote, local_source)` because `dst` differs, so no
collision. But the plan must also rule out userspace-dp OVERWRITING the synthetic
entry when it processes the decapped inner flow (it installs a session on the
INNER 5-tuple, a different key — no overwrite) and must confirm there is no
userspace-dp code path that enumerates+rewrites the whole map on resync
(`shared_ops.rs` republish ADDs; `session_glue` deletes per-key — spot-checked,
but the plan should name this as a MUST-verify at /engineer time, not assert it).
**Add to §7 as HI-7 and to §11 as an /engineer-time verification gate.**

## Required change 4 — commit to resolving OQ-6 (real exposure) BEFORE code

OQ-6 (does the kernel FIB actually forward a decapped inner packet into a
protected zone in a realistic config?) is left fully open, yet it gates whether
this is M-1 or lower and whether Path B's complexity is justified. This is a
30-minute runtime check on the loss cluster (the §9 baseline test literally
proves it). The plan should COMMIT that the /engineer phase runs the §9 baseline
FIRST — proving the gap is open with a real captured inner packet on the LAN host
— before any code is written. If the baseline can't reproduce the injection
(e.g. RPF or absent inter-zone route silently closes it), that is a PLAN-KILL
signal. **Make §9 step 3 a gating precondition, not just a test.**

## Non-blocking nits

- §4-4: good precision on proto-4-only. Also note the Ip6tnl 4in6 case means the
  OUTER family can be IPv6 while the inner is IPv4 — the static key's
  `addr_family` is the OUTER family; make sure B2 keys the outer family, not the
  inner. (The plan implies this but should be explicit.)
- HI-3: define zone-0 (unzoned tunnel) semantics — in xpf does ingress_zone==0
  mean "drop" or "default permissive"? If permissive, an unzoned ipip tunnel is
  itself a latent fail-open even after Path B. Resolve in OQ-4.
- The §8 risk table should add a Path F column once Path F is added.

## Severity opinion

M-1 is defensible pending OQ-6. Requires source-spoofing a specific configured
remote and a one-way injection (return hits policy). Not High absent a
demonstrated bidirectional or unauthenticated-any-source decap. Agree with M-1.

## Bottom line

The architecture analysis is sound and the crux is right. But a first-pass
PLAN-READY here would be the soft-pass anti-pattern: the plan currently
under-sells the residual's reachability, omits the fail-closed interim (Path F),
and asserts (rather than gates) the collision-safety and real-exposure checks.
Address changes 1-4 → I expect PLAN-READY on r2.
