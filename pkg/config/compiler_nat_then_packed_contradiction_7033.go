package config

import "strings"

// compiler_nat_then_packed_contradiction_7033.go — #7033.
//
// A `then` block carrying two mutually-exclusive translation actions is meant to
// be rejected at strict commit (#5628). When the two are PACKED as tokens on one
// run rather than lowered as two fields, only one is lowered, the cardinality
// counter — which counts RESOLVED fields — sees `n == 1`, and the contradiction
// commits under STRICT with no diagnostic:
//
//	then { source-nat pool P off; }      -> {PoolName:"P"}   `off` DROPPED
//	then { source-nat off pool P; }      -> {Off:true}       `pool P` dropped
//	then { source-nat { pool P off; } }  -> {PoolName:"P"}   `off` DROPPED
//	set … then source-nat pool P off     -> {PoolName:"P"}   `off` DROPPED
//
// The rows where `off` is the casualty are the severe ones: the operator
// authored a no-NAT EXEMPTION and the compiler publishes a TRANSLATION in its
// place — the inverse of the authored action, which is the outcome the #5628
// rejection text says it prevents.
//
// WHY THIS IS A DETECTION FIX AND NOT AN ACCUMULATING LOWERING FIX. Two rounds
// of #6820 tried to make the lowering read every packed token, and each
// introduced a commit-reachable regression in the ACCEPTING direction — round 5
// made `then { destination-nat interface pool PD; }` newly resolve as a pool
// translation, round 6 fabricated an exemption out of
// `then { source-nat { frobnicate { off; } } }`. Both were reverted. Nothing
// here changes what a rule RESOLVES to: the authored actions are recorded
// alongside the resolved NATThen (the #7013 record, extended with modes) and the
// gate reads that. A config that commits today either commits unchanged or is
// rejected; none resolves differently.
//
// ORDERING: a block that LOWERS two actions is already rejected by the
// resolved-field count, with a message this project has iterated on across
// #6820, #7034 and #7035, and a block that lowers none is rejected there too.
// Neither must start reporting a packed contradiction instead, so this check
// applies to the n == 1 class ONLY — the configs that count cannot see.
//
// TWO THINGS ENFORCE THAT, AND EITHER ALONE WOULD DO IT, which is worth stating
// because it means a mutation of one is invisible: the call site sits after the
// count's switch, whose n == 0 and n >= 2 arms both return, AND
// natThenPackedContradictionModes refuses any rule whose resolved count is not
// exactly one. The redundancy is deliberate rather than accidental — the
// predicate is also called by natTerminalActionCardinalityOffenders, which has
// no such switch around it, so the guard has to live in the predicate for it to
// be correct standalone. Proving the property is guarded therefore takes a
// COMPOUND mutation (move the call AND drop the guard); a single-site mutation
// is masked by the other site, which is what redundancy means, not a gap.
//
// WHAT STAYS ACCEPTED, each pinned by a test:
//
//   - `pool off` — a pool legitimately NAMED `off`. `pool` consumes exactly one
//     value token, so this is one pool, not a pool plus an exemption.
//   - `pool P persistent-nat permit any-remote-host` — #4313's trailing
//     grammar (modeled since #14626). The scan stops at the first unrecognised
//     token instead of reading the tail as actions.
//   - `then { source-nat { frobnicate { off; } } }` — still rejected, but as the
//     ZERO-action rule it is. The walk does not descend past an unrecognised
//     container, so this never becomes a fabricated `off`.

// natThenPackedContradictionModes returns the distinct terminal action MODES one
// `then` container authored, when there are two or more of them AND the rule
// resolved to exactly one action — that is, precisely the contradiction the
// resolved-field count cannot see. It returns nil in every other case.
//
// ONE PREDICATE, TWO CALLERS. The strict gate rejects on it and
// natTerminalActionCardinalityOffenders enumerates on it, for the same reason
// #7640 gave for the field count: a gauge that counted rules a commit would
// accept, or missed ones it would refuse, is worse than no gauge.
// TestLenientNATOffendersMatchThePackedGate_7033 binds the agreement for this
// class rather than trusting it.
func natThenPackedContradictionModes(rule *NATRule) []string {
	if rule == nil {
		return nil
	}
	// Only the n == 1 class. n == 0 and n >= 2 belong to the resolved-field
	// count, which reports them with its own text. This guard is what makes the
	// predicate correct for natTerminalActionCardinalityOffenders too, which
	// calls it without the count's switch around it.
	if natThenTerminalActionCount(rule.Then) != 1 {
		return nil
	}
	modes := rule.thenAuthored.distinctModes()
	if len(modes) < 2 {
		return nil
	}
	return modes
}

// natPackedContradictionDetail renders the operator-facing explanation for a
// packed contradiction: which mode takes effect, which are discarded, and — when
// `off` is among the casualties — that the published behaviour is the INVERSE of
// what was authored.
func natPackedContradictionDetail(modes []string) string {
	survivor := modes[0]
	dropped := modes[1:]
	var b strings.Builder
	b.WriteString("`" + survivor + "` is the one that takes effect and ")
	b.WriteString("`" + strings.Join(dropped, "`, `") + "` ")
	if len(dropped) == 1 {
		b.WriteString("is silently discarded")
	} else {
		b.WriteString("are silently discarded")
	}
	for _, d := range dropped {
		if d == "off" {
			b.WriteString(". `off` is an EXEMPTION from translation, so what the " +
				"dataplane enforces here is the INVERSE of what was authored: a " +
				"translation where the configuration asks for none")
			break
		}
	}
	return b.String()
}
