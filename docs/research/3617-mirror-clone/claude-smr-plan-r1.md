# Claude SMR — hostile plan review r1 (#3617)

Posture: adversarial. Goal is to break the PLAN-KILL, not confirm it.

## Attacks attempted

### A1. "Junos transit-only is an MX/EX claim; SRX flow reject differs."
Checked. The Juniper *Configuring Port Mirroring* guide states plainly "Only
transit data is supported," and the analyzer docs add "Layer 2 local data
(packets destined for or sent by the Routing Engine ...) are not mirrored" and
"CPU-generated packets (ARP, ICMP, BPDU, LACP) cannot be mirrored on egress."
SRX-specific text confirms "only transit data can be mirrored" and SRX mirrors
ingress+egress together on physical interfaces. No source says host-generated
reject RST/ICMP is mirrored. Attack fails — the transit-only rule holds across
platforms, including SRX. **Verdict stands.**

Caveat surfaced (not a defeat): SRX operators DO capture host-generated packets
— but via `monitor traffic` / packet-capture / flow traceoptions, which are
distinct from `forwarding-options port-mirroring`/`analyzer`. #3617 is scoped to
port-mirroring/analyzer, so this is out of scope and does not change the verdict.

### A2. "The field-semantics argument is a strawman; the real fix is to CALL the
mirror-clone machinery for the reply (Option B), so don't KILL a real feature."
Partly fair. Option B is a genuine mechanism (call `enqueue_sampled_mirror_clone`
keyed on the reply's egress ifindex). But it is a **Junos divergence** by A1, so
it is a net-new non-Junos feature, not a bug fix. Killing the *audit item* while
pointing any future demand at a separately-scoped opt-in issue is the correct
disposition for a parity-driven project. The plan already says this (Option B →
new issue). **Verdict stands**, provided the plan does not overclaim that
Option B is worthless — it says "only worthwhile on explicit user demand," which
is accurate.

### A3. "L10 is a cheap, real improvement — that alone justifies DEFER not KILL."
Investigated to ground truth. The reject reply (`reject_reply.rs:394`) and the
SYN-cookie reply (`cookie_reply.rs:504`) already assert `!req.mirror_clone`, so
L10 is DONE for those. HOWEVER: the forward-path generated ICMP errors — PTB /
Frag-Needed (`tx/dispatch/mod.rs:438`) and time-exceeded (`:204`) — set
`mirror_clone: false` but have **no** test asserting it. So L10 "assert ALL
egress metadata incl. mirror_clone for EVERY generated reply" is **not fully
covered** for the ICMP-error family.

This is a real, if tiny, residual. It does NOT change the core verdict (the
value is correct; this is a pin, not a behaviour change). Disposition options:
(a) fold a 2-line `assert!(!req.mirror_clone)` pin into the next test-sweep and
KILL the issue; (b) keep a micro-DEFER solely for that pin. I lean (a): the
issue's headline ask (mirror the replies) is works-as-intended; a missing
one-line test pin does not warrant holding an audit issue open. The plan should
name this residual explicitly rather than claim L10 is fully done. **Minor plan
correction requested** (see below).

### A4. "Premise-refutation (§2.4) is overreach — maybe the trigger IS mirrored."
Verified. The only three live mirror-clone sites are on the admitted-forward
path (`flow_cache_hit.rs`, `neighbor_dispatch.rs`, `tx/dispatch/mod.rs`). A
policy/filter reject drops the trigger on the cold deny arm before any forward,
so it is not mirrored. §2.4 is correct. **No defeat.**

### A5. "Does classify_generated_reply already give operators enough visibility?"
Yes — replies are counted (policy/filter_reject_sent, SYN-cookie counters,
generated-error counters) and are subject to output filters + CoS. The operator
is not blind; they simply do not get an analyzer copy, matching Junos. Weakens
the forensics motivation further. **Reinforces KILL.**

## Required plan change (r1 → r2 if pursued)

- §5 Option A and §6: soften "the L10 test already exists" to "L10 is covered
  for the reject and SYN-cookie replies but NOT the PTB/time-exceeded generated
  ICMP errors (`tx/dispatch/mod.rs:204,438` have no `mirror_clone` pin)."
  Recommend folding that one-line pin into a future test-sweep rather than
  holding #3617 open. This is the only inaccuracy in the plan.

## Verdict

**PLAN-KILL (works-as-intended)** — CONCUR, with the §5/§6 accuracy correction
above. The core ask (mirror host-generated replies) diverges from Junos
transit-only mirroring; the proposed `mirror_clone` mechanism is a misreading;
observability already exists via counters + output-filter classification. The
sole real residual is a missing one-line test pin on the ICMP-error family,
which is a test-sweep item, not a reason to keep the issue open.
