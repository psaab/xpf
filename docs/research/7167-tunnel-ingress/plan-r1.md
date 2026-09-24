# #7167 — bounded logical-tunnel-ingress: research plan r1

Scope: adjudicating decapped WireGuard and IPsec plaintext through the AF_XDP
zone-policy pipeline. Written after reading the surrounding code, at
`ec4a1569c`, before any implementation.

**Status: this plan does not propose a design. It records what is true at head,
retracts three claims the issue makes that no longer hold, and names the one
measurement that must come first because it decides which plan we are writing.**

---

## 0. Why this is a plan and not a patch

The issue reads as "two protocols bypass policy; hand the decapped frame back
into the pipeline". Both halves are real. But the two protocols' capture
mechanisms are asymmetric in cost, and — this is the part that was wrong in the
first split proposal, mine — **neither is an unblocking of an existing
mechanism**. Both require new packet-path code. Establishing that took reading;
it is not visible from the issue.

---

## 1. Corrections to the issue's own citations

These are all "the premise moved" findings. None weakens the defect; all three
will mislead a fresh reader who runs the stated checks.

### 1.1 `grep -rn "hook forward"` no longer returns zero

The issue's evidence that the kernel forwards unadjudicated is a zero-hit grep.
At head it returns **6**. All six are comments *asserting the absence*
(`daemon_transit_gate.go`, `daemon_run_bringup.go`, `routes.go`,
`metrics_descriptors_binding.go`, and a test).

The substance holds — there is still no forward hook — but the stated check no
longer produces the stated result. This is the source-scanning trap in mirror
image: the count is nonzero **because the codebase documents the absence**. Any
future gate built on this grep must strip comments.

### 1.2 `wg_control.rs` no longer exists

Split by #6438/#6570 into `wg_control/{mtu,sock,attempt,dispatch}.rs`. The defect
is intact at `dispatch.rs:215` — `slowpath::write_packet_nonblocking(tun_fd,
plaintext)` — with the only policy mention being the comment at `:202` stating
that the kernel, not the AF_XDP engine, handles it. Nothing between
authentication and the write.

### 1.3 The two "config-shape naming bugs" are largely stale

The issue lists two reasons the xfrmi is invisible. One is fixed; the other is
real but **inert**, and that distinction matters because these were briefly
considered as separable groundwork.

**Shape A (`st0` vs the real `st0.0` netdev) is FIXED.** `snapshotLinuxName`
(`pkg/dataplane/userspace/interfaces.go:832`) handles it explicitly and
delegates the rule to the shared `config.SecureTunnelUnitNetdev` (#5619, #6691).
Its own comment describes the old behaviour in the past tense: the unit-0
collapse "yielded `st0` for `bind-interface st0.0`, a name that exists on no
box".

**Shape B (`bind-interface st0.0` with no `set interfaces st0`) is REAL but
currently unobservable.** `buildInterfaceSnapshots` iterates only
`cfg.Interfaces.Interfaces`, and `pkg/dataplane` contains **zero** production
references to `BindInterface` — it is read only under `pkg/config/` and
`pkg/cli/`. So no snapshot row exists for that shape. Confirmed authorable:
`compiler_ipsec_plaintext_warn.go` records that #4515 accepts
`set security zones security-zone vpn interfaces st0.0` with no explicit
interface stanza.

`liveXfrmNetdevs` does **not** close it. That input feeds `snapshotSecureTunnel`,
which *classifies existing rows*; it does not create a row for a config-absent
xfrmi.

**But fixing Shape B alone changes nothing observable.** The xfrmi is excluded
from the ingress-adjudication set either way, and `syncInterfaceAttachments`
calls `DetachXDP` on every ifindex outside the allowed set — so "absent from the
snapshot" and "present but excluded" produce identical behaviour today. A test
for it could only assert an internal snapshot property. It becomes load-bearing
the moment a capture mechanism exists, and not before, so it belongs to whichever
mechanism wins rather than ahead of it.

---

## 2. What is actually true at head

### 2.1 The IPsec exclusion is deliberated, not incidental

It is a named class table, `netdevExclusionClasses`
(`pkg/dataplane/userspace/ingress_exclusions.go`), with six classes. Two are
relevant: a generic `Tunnel` arm and a dedicated `SecureTunnel` arm whose doc
states outright — *"#5619: an IPsec secure tunnel is NOT adjudicated by the
userspace dataplane, and this arm says so out loud."*

It is keyed on **ownership and kernel link kind**, never on name shape, after
nine #6691 review rounds (round 5 stopped it calling `IsSecureTunnelIfName`; the
Rust mirror `is_secure_tunnel_ifname` was deleted rather than re-derived).

Anyone proposing to invert this is not deleting an oversight. They are reversing
a decision with a written rationale, and they inherit the keying discipline that
took nine rounds to get right.

### 2.2 The exclusion's stated reason is an EGRESS problem

From `compiler_ipsec_plaintext_warn.go`: the xfrmi is excluded *"because there is
no path to hand a plaintext frame back INTO an xfrmi for the egress direction."*
AF_XDP cannot transmit on an xfrmi.

**Any ingress-only proposal must answer this rather than route around it
silently.** The argument that it can be answered: the inbound direction does not
need xfrmi TX, because a decapped packet adjudicated on xfrmi ingress egresses
via an ordinary LAN NIC. That argument is plausible and **unverified** — see §3.

### 2.3 There is no raw-L3 framing support anywhere in the pipeline

An xfrm interface is `ARPHRD_NONE`: a frame arriving there has no Ethernet
header. The AF_XDP path assumes Ethernet framing end to end — parse, CoS, NAT,
checksum, TX.

The evidence is a **systematic near-miss**, which is stronger than a null grep:
every occurrence of "L3-only" in this codebase means *no L4 header* (non-first
fragments — `frame/mod.rs:275`, `frame/mod.rs:313`, `nat64.rs:4120`,
`nat64.rs:4201`, `inspect.rs:663`), and **never** *no Ethernet header*. A null
result is ambiguous; a consistent near-miss is an answer.

So requirement 7's "raw-L3→synthetic-Ethernet normalization" names a mechanism
that must be **built**, not one that can be selected. The issue presents
requirement 7 as a choice between two available options, and that framing is what
made the first (retracted) split proposal read it as available.

### 2.4 The WireGuard side needs a new primitive, and #7937 says why it must not block

`WorkerCommand` carries session and CoS commands only. There is **no bounded
logical-ingress packet command** the control thread could use, so this half needs
a new packet-handoff primitive with an ownership and buffer-recycling model.

The issue requires the handoff be "bounded" without saying why. **PR #7937
supplies the reason and it should be quoted in any design:** the WireGuard
control loop is *not control-only* — it blocks in `poll(2)` over
`{UDP socket, TUN}` and carries the tunnel's data path. Anything that blocks
there turns a policy decision into a forwarding stall for the entire tunnel.
Without that sentence, "bounded" reads as a style preference.

### 2.5 #5619 already ships an operator-visible warning

`compiler_ipsec_plaintext_warn.go` emits one aggregated commit-time advisory
naming the affected tunnels. Deliberately a **warning, not a rejection**, under
the #1960 no-brick posture: #3114 rejects only the unsupported `then permit
tunnel` policy action, not an IPsec VPN object. A missing bind-interface is a
separate strict-commit error (#10638); a valid route-based VPN remains supported,
so rejecting it would be feature removal rather than a guard. The function has
no error return and takes no `lenient` flag, so the no-brick property is
structural.

This changes how the eventual change is described to operators: it is
**enforcement of something they are already told**, not the discovery of a new
gap.

---

## 3. THE MEASUREMENT THAT MUST COME FIRST

**Is the outbound (LAN → tunnel) direction already adjudicated?**

This is the hinge, and it is unresolved. It decides whether requirement 9
("route-based IPsec egress must retain xpf policy evaluation before kernel XFRM
encryption") is *already satisfied* or *owed*:

- **If already satisfied** — a LAN-ingress packet destined for a tunnel prefix is
  policy-evaluated at its LAN ingress with the correct to-zone, then reaches XFRM
  through the kernel — then ingress-only xfrmi capture covers both directions and
  §2.2's egress objection is answered on the merits.
- **If not** — the packet reaches the kernel before or without policy — then the
  egress mechanism is back in scope, and this is a materially different and much
  larger plan.

What makes it non-obvious: `NoRoute` is a **drop** disposition
(`disposition.rs:865` — bumps `route_miss`, records an exception), yet route-based
IPsec demonstrably works, so LAN→tunnel traffic is not resolving `NoRoute`.
Something else is happening and the plan must say what. `routes.go:387` describes
a *different* case in which a packet "resolves NoRoute and is REINJECTED to the
kernel unadjudicated", so both dispositions exist in the codebase's own prose and
they have to be told apart.

**Method:** drive a LAN→tunnel packet through the forwarding resolver in the Rust
unit harness with a route whose egress is a tunnel ifindex, and record (a) the
disposition, (b) whether `evaluate_policy` ran, and (c) which to-zone it used.
Do this before any design work.

---

## 4. Open design questions, in the order they must be answered

1. **§3's measurement.** Everything downstream depends on it.
2. **Does the evaluation contract survive being written protocol-agnostically?**
   What a decapped packet must be adjudicated against, and what a capability
   failure does, should be expressible without reference to xfrmi or to a TUN
   write. If a parameter appears that only makes sense for netdev-based capture,
   the seam is in the wrong place.
3. **Capture mechanism per protocol** (requirement 7 concedes they may differ):
   ingress-only xfrmi binding + normalization, versus a bounded kernel→userspace
   capture bridge that could serve both.
4. **Fail-closed at bring-up.** Requirement 7 says a capability failure must fail
   the dataplane **closed** and be operator-visible, never a silent fallback to
   Linux forwarding — because that fallback *is* the defect. This is the
   acceptance criterion the rest hangs off, not a trailing item.
5. **HA.** An inactive RG must not locally forward inner traffic because the WG
   control thread still holds a live socket.

## 5. What this plan explicitly does NOT conclude

- That the split into "IPsec now, WG later" is right. That proposal was mine and
  I retracted it: it rested on IPsec being an unblocking, and §2.3 says it is not.
- That ingress-only capture is viable. It is plausible pending §3.
- That the exclusion should be inverted. §2.1 and §2.2 are the case that must be
  answered first.

## 6. Adversarial review should attack, specifically

- §2.3's near-miss argument. If raw-L3 handling exists somewhere this search
  missed, the cost estimate collapses and the plan changes.
- §3's framing. If outbound is adjudicated somewhere other than LAN ingress, both
  branches of the hinge are wrong.
- The claim that Shape B is unobservable (§1.3). If any consumer of
  `snapshot.Interfaces` other than the ingress map and `syncInterfaceAttachments`
  reads xfrmi rows, it is observable and separable after all.
