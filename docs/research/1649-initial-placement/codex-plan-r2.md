# Codex hostile plan-review — #1649 r2 (confirmation)

Task: codex exec read-only confirmation of r2 revisions.

## Findings (verbatim)

The r1 counter-example is now correctly handled. Lines 200-219 explicitly
acknowledge the verified masked source-port-residue ntuple mechanism, and lines
221-223 move the kill from "no mechanism exists" to "relocates the multinomial
draw without flattening it."

On §7.0: the core multinomial argument is correct. For uncontrolled ephemeral
ports, any static mapping `f(tuple) -> queue` produces iid queue draws with some
fixed queue probability vector. A balanced layout gives the RSS floor; an
imbalanced layout is worse. More residue classes, wider port hashing, or
RSS-context indirection can only choose that static probability vector. They
cannot create the negative dependence needed to make N<=M flows avoid occupied
queues.

One precision note: lines 236-238 quote `src_port mod 8` bucket CoV 1.05 versus
RSS queue CoV 0.87. That 1.05 is correct for eight residue buckets, but if
residues 6/7 fall through to uniform RSS, the actual six RX-queue distribution
is the same multinomial as RSS, not necessarily worse. This is not a hole in the
kill, because the kill only needs "does not beat the floor," and that remains
true. Read "same/worse" as the production claim, not depend on "worse."
[ADOPTED in r2-final §7.0.]

The acknowledgement-plus-multinomial kill leaves no mechanism hole. Success is
correctly limited to deliberately assigned residues; the Phase-0 3.8% result is
correctly classified as a controlled-harness artifact. That knob is useful as a
lab demonstration, but not worth shipping as a production dataplane feature.

## VERDICT: PLAN-READY (kill correct)

Independently re-derived the mixture model: residues 6/7 → RSS gives the 6-queue
CoV ≈ 0.874 (= RSS); pure 8-bucket CoV ≈ 1.05; P(perfect spread) = 6!/6⁶ ≈
1.54% for both RSS and the balanced static map.
