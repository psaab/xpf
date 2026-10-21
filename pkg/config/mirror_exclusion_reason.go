package config

import "math"

// PortMirroringInstanceExcludedReason reports why the userspace snapshot
// builder drops a `forwarding-options port-mirroring` instance outright, or ""
// when the instance is published.
//
// #6534. The lie this closes is unusually sharp: both renderers print
// `Input rate: all packets` whenever InputRate is not > 0 — so an instance with
// a NEGATIVE rate, which the builder drops entirely (a negative would wrap the
// uint32 cast), reads on screen as the most permissive possible mirror while
// mirroring nothing at all.
//
// SCOPE — read this before assuming the predicate is complete. It covers only
// the conditions decidable from the CONFIG. buildMirrorSnapshots drops an
// instance for two further reasons that depend on the runtime INTERFACE TABLE,
// not on config: an output interface that does not resolve to an ifindex, and
// an ingress interface already claimed by a lower-sorted instance (one output
// per ingress ifindex). A renderer holding only *config.Config cannot reach
// those, so annotating them needs the resolved ifindex map threaded to the
// surface — the one place in this audit where the "give the renderer applied
// state" instinct has real force, rather than the predicate being enough.
//
// Callers: buildMirrorSnapshots (pkg/dataplane/userspace/mirrors.go), and all
// THREE show surfaces — cli.showPortMirroring,
// Server.showForwardingOptionsPortMirroring, and cli.showForwardingOptions.
//
// This comment said TWO until #6534's closure, and the miscount was the bug:
// the first two are byte-identical copies of each other and were annotated
// together, while `show forwarding-options` in cli_show_routing.go — a third
// copy with its own layout, printing MORE per-instance detail than the gRPC
// command of the same name — was not, and kept rendering a dropped instance as
// armed with the suite green. An enumeration in a comment is a claim about a
// population nobody measured; pkg/showaudit measures it now
// (TestSurfaceAnnotationCensusIsExact6534), so a fourth renderer cannot appear
// unannotated and cannot make this sentence wrong again without a red test.
//
// Until these copies are single-sourced the way pkg/natshow and
// pkg/dataplane/userspace/format already are, every one of them must consult
// this predicate: annotating some leaves the rest lying.
func PortMirroringInstanceExcludedReason(inst *PortMirrorInstance) string {
	if inst == nil {
		return ""
	}
	if inst.Output == "" {
		return "no output interface configured"
	}
	if inst.InputRate < 0 {
		return "negative input rate"
	}
	// #8597 (muse-004 K68): the same wrap, at the other end.
	//
	// `Rate: uint32(inst.InputRate)` is the wire field, at TWO sites
	// (pkg/dataplane/userspace/mirrors.go and pkg/dataplane/compiler.go). A
	// value above math.MaxUint32 wraps, and `rate 4294967296` wraps to exactly
	// ZERO — which in this field means MIRROR EVERY PACKET. An operator asking
	// for the sparsest possible sample gets a full traffic duplicate onto the
	// output interface.
	//
	// That is worse than the negative case this predicate was written for. A
	// negative rate at least mirrors nothing while the screen lies; a wrapped
	// zero makes the screen and the behaviour AGREE, and both are the opposite
	// of what was asked for.
	//
	// The sibling knob already has this bound: `forwarding-options sampling`
	// caps its own InputRate at math.MaxUint32 in pkg/dataplane/userspace/
	// flow.go with a slog.Warn (#1977). Port mirroring was left out of that
	// sweep.
	//
	// EXCLUDING rather than capping, unlike the sampling sibling, and for two
	// reasons. It matches the negative case three lines up, so one knob does
	// not have two different out-of-range behaviours. And a value this far out
	// of range is a typo or a hostile config, not an operator asking for the
	// sparsest mirror the wire can encode — capping would invent an intent, the
	// #6769 argument. The exclusion is annotated on all three show surfaces,
	// so the operator is told rather than left to infer it from traffic.
	if int64(inst.InputRate) > math.MaxUint32 {
		return "input rate above the 32-bit wire field"
	}
	return ""
}

// TunnelUnitSharedIfindexMirrorReason is the #16063 refusal text for a
// port-mirroring input naming one tunnel unit whose netdev is shared
// with sibling units at the same VID (wg0.0/wg0.1 on ifindex 42, both
// VID 0). The packet metadata at every mirror callsite is (ifindex,
// VID) only — tunnel decap rebinds inner packets to the tunnel's single
// logical ifindex — so no per-packet unit identity exists; installing
// the row would mirror every sibling unit to the analyzer. The builder
// refuses the input (shared-ifindex refusal) and records this reason.
func TunnelUnitSharedIfindexMirrorReason(input string) string {
	return "input interface " + input + " shares its tunnel ifindex with sibling units; per-unit mirroring of one unit would mirror them all"
}
