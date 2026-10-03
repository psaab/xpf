package config

// Class-of-service: forwarding classes, DSCP/IEEE-802.1p classifiers and
// rewrite rules, queue schedulers, scheduler-maps, per-interface shaping,
// and fairness expectations.

// ClassOfServiceConfig holds CoS forwarding classes, schedulers,
// scheduler-maps, and per-interface shaping configuration.
type ClassOfServiceConfig struct {
	ForwardingClasses   map[string]*CoSForwardingClass
	DSCPClassifiers     map[string]*CoSDSCPClassifier
	IEEE8021Classifiers map[string]*CoSIEEE8021Classifier
	// INetPrecedenceClassifierDefs holds `class-of-service classifiers
	// inet-precedence <name>` with its code-point entries (#6847). Before
	// #6847 only the NAMES were recorded (INetPrecedenceClassifiers, below)
	// because nothing consumed the map and the unit-level schema had no
	// `inet-precedence` binding site at all -- the classifier was
	// definable but not bindable. It is now compiled and ENFORCED.
	INetPrecedenceClassifierDefs map[string]*CoSINetPrecedenceClassifier
	DSCPRewriteRules             map[string]*CoSDSCPRewriteRule
	// IEEE8021RewriteRules holds `class-of-service rewrite-rules ieee-802.1
	// <name>` — the 802.1p PCP egress rewrite (#4228 Gap 4). It fully mirrors
	// DSCPRewriteRules (forwarding-class -> loss-priority -> code-point 0..7)
	// so the mapping is modeled and validated at commit, but it is currently
	// ACCEPTED-BUT-INERT: the userspace dataplane rewrites only DSCP on egress
	// (cos_classify.rs) and does not yet own the 802.1Q tag write, so the
	// configured PCP rewrite has no runtime effect. A commit advisory surfaces
	// the inertness. The classifier side (IEEE8021Classifiers) IS enforced;
	// this rewrite half awaits egress 802.1Q tag ownership in the AF_XDP TX
	// path (the Rust follow-up). Modeled here so imported vSRX configs commit
	// clean instead of being rejected as an unknown leaf.
	IEEE8021RewriteRules map[string]*CoSIEEE8021RewriteRule
	Schedulers           map[string]*CoSScheduler
	SchedulerMaps        map[string]*CoSSchedulerMap
	Interfaces           map[string]*CoSInterface
	FairnessExpectations []*CoSFairnessExpectation
	// INetPrecedenceClassifiers / INetPrecedenceRewriteRules / EXPRewriteRules
	// retain the configured NAMES for advisories and the name-only show surface.
	// The two inert rewrite families' inner entries are also parsed into
	// validation-only rule definitions below; no code point is sent to the
	// dataplane or exposed in the compiled config's JSON form.
	INetPrecedenceClassifiers     []string
	INetPrecedenceRewriteRules    []string
	EXPRewriteRules               []string
	INetPrecedenceRewriteRuleDefs map[string]*CoSINetPrecedenceRewriteRule `json:"-"`
	EXPRewriteRuleDefs            map[string]*CoSEXPRewriteRule            `json:"-"`
	// TrafficControlProfiles holds the Junos hierarchical shaping profiles
	// (`class-of-service traffic-control-profiles <name>`). A profile is
	// bound to a logical interface's egress by
	// `interfaces <if> unit N output-traffic-control-profile <name>`;
	// resolveCoSTrafficControlProfiles folds the bounded knobs
	// (shaping-rate, scheduler-map) into the referencing CoSInterfaceUnit so
	// the existing per-unit shaper enforces them. Before this modeling the
	// whole binding was silently dropped — a clean commit with ZERO shaping
	// (fable-167 F-2, #4315).
	TrafficControlProfiles map[string]*CoSTrafficControlProfile
}

// CoSTrafficControlProfile models one Junos traffic-control-profile
// (`class-of-service traffic-control-profiles <name>`). The BOUNDED knobs
// map onto xpf's existing per-unit shaper: ShapingRateBytes becomes the
// unit root shaper and SchedulerMap the unit scheduler-map when the profile
// is bound via output-traffic-control-profile
// (resolveCoSTrafficControlProfiles). GuaranteedRateBytes and
// DelayBufferRateBytes are captured for `show configuration` fidelity and a
// commit advisory but have NO per-unit dataplane consumer yet
// (accepted-but-not-enforced) — there is no absolute per-unit guaranteed-rate
// or delay-buffer reservation in the userspace shaper (the #1614 A1
// guarantee-rate is a proportional FRACTION, a distinct mechanism).
type CoSTrafficControlProfile struct {
	Name             string
	ShapingRateBytes uint64 // bytes/sec; 0 = unset
	// ShapingRatePercent (#4228 Gap 2) carries the Junos `shaping-rate percent
	// <n>` form: a share (0,100] of the bound interface's speed. Accepted for
	// vSRX-config import parity but ACCEPTED-BUT-INERT — the dataplane folds an
	// absolute ShapingRateBytes into the bound unit's root shaper and xpf does
	// not yet resolve the percent against the interface speed (commit
	// advisory). Mutually exclusive with ShapingRateBytes.
	ShapingRatePercent   float64
	GuaranteedRateBytes  uint64 // bytes/sec; 0 = unset (accepted-but-inert)
	DelayBufferRateBytes uint64 // bytes/sec; 0 = unset (accepted-but-inert)
	SchedulerMap         string
}

// CoSForwardingClass maps a forwarding-class name to a queue number.
type CoSForwardingClass struct {
	Name  string
	Queue int
}

// CoSDSCPClassifier maps DSCP code points into forwarding classes.
type CoSDSCPClassifier struct {
	Name    string
	Entries []*CoSDSCPClassifierEntry
}

// CoSDSCPClassifierEntry assigns one or more DSCP values to a forwarding class.
type CoSDSCPClassifierEntry struct {
	ForwardingClass string
	LossPriority    string
	DSCPValues      []uint8
}

// CoSINetPrecedenceClassifier maps IP-precedence code points (0..7) into
// forwarding classes (#6847).
//
// IP precedence is the top 3 bits of the same IPv4 TOS byte the DSCP classifier
// reads, which is why a unit may bind AT MOST ONE of `dscp` and
// `inet-precedence`: they are alternative interpretations of one field, not
// composable classifiers. That mutual exclusion is enforced at commit
// (validateCoSUnitClassifierConflict) rather than resolved by a silent
// precedence order.
type CoSINetPrecedenceClassifier struct {
	Name    string
	Entries []*CoSINetPrecedenceClassifierEntry
}

// CoSINetPrecedenceClassifierEntry assigns one or more IP-precedence code
// points (0..7) to a forwarding class.
type CoSINetPrecedenceClassifierEntry struct {
	ForwardingClass string
	LossPriority    string
	Precedences     []uint8
}

// CoSIEEE8021Classifier maps 802.1p PCP values into forwarding classes.
type CoSIEEE8021Classifier struct {
	Name    string
	Entries []*CoSIEEE8021ClassifierEntry
}

// CoSIEEE8021ClassifierEntry assigns one or more PCP values to a forwarding class.
type CoSIEEE8021ClassifierEntry struct {
	ForwardingClass string
	LossPriority    string
	CodePoints      []uint8
}

// CoSDSCPRewriteRule maps forwarding classes to egress DSCP rewrite values.
type CoSDSCPRewriteRule struct {
	Name    string
	Entries []*CoSDSCPRewriteRuleEntry
}

// CoSDSCPRewriteRuleEntry assigns a DSCP rewrite code point to a forwarding class.
type CoSDSCPRewriteRuleEntry struct {
	ForwardingClass string
	LossPriority    string
	DSCPValue       uint8
}

// CoSIEEE8021RewriteRule maps forwarding classes to egress 802.1p PCP rewrite
// values (#4228 Gap 4). Accepted-but-inert — see ClassOfServiceConfig.
type CoSIEEE8021RewriteRule struct {
	Name    string
	Entries []*CoSIEEE8021RewriteRuleEntry
}

// CoSIEEE8021RewriteRuleEntry assigns an 802.1p PCP rewrite code point (0..7)
// to a forwarding class.
type CoSIEEE8021RewriteRuleEntry struct {
	ForwardingClass string
	LossPriority    string
	PCPValue        uint8
}

// CoSInertRewriteRuleEntry is the validation-only mapping captured for the
// currently unsupported 3-bit egress rewrite families. It is deliberately not
// published to the wire; the configured names continue to drive the inert
// advisory and name-only show output.
type CoSInertRewriteRuleEntry struct {
	ForwardingClass string
	LossPriority    string
	CodePoint       uint8
}

// CoSINetPrecedenceRewriteRule holds the inner entries of an inert
// IP-precedence rewrite rule so commit validation can check the same loss
// priority and 0..7 code-point contract as the 802.1p sibling.
type CoSINetPrecedenceRewriteRule struct {
	Name    string
	Entries []*CoSInertRewriteRuleEntry
}

// CoSEXPRewriteRule holds the inner entries of an inert MPLS EXP rewrite rule
// for strict commit validation. The definition remains Go-only until a
// dataplane consumer exists.
type CoSEXPRewriteRule struct {
	Name    string
	Entries []*CoSInertRewriteRuleEntry
}

// CoSScheduler defines the Phase 1 class scheduler knobs.
type CoSScheduler struct {
	Name              string
	TransmitRateBytes uint64
	TransmitRateExact bool
	// TransmitRatePercent (#4228 Gap 2) carries the Junos `transmit-rate
	// percent <n>` form: a share (0,100] of the bound interface's rate.
	// Mutually exclusive with TransmitRateBytes and TransmitRateRemainder
	// (validateClassOfServiceStrict).
	//
	// #6565 row 4 / #7422: this comment said ACCEPTED-BUT-INERT and that "xpf
	// does not yet resolve the percent against the interface's shaping-rate".
	// That was true when written and is NOT true now — the dataplane resolves
	// it live in cos_effective_transmit_rate_bytes
	// (userspace-dp/src/afxdp/forwarding_build/cos.rs), and the field is on the
	// wire as transmit_rate_percent. A rationale outlives the fix that
	// invalidates it unless something re-reads it, and this one had gone on to
	// justify a renderer printing "-" for a queue that is in fact shaped.
	TransmitRatePercent float64
	// TransmitRateRemainder (#4228 Gap 2) carries the Junos `transmit-rate
	// remainder` form (a share of the leftover bandwidth).
	//
	// Also resolved live, but by a different mechanism and later (#6846):
	// percent is a function of the scheduler and its interface, so it resolves
	// per-scheduler; remainder means "whatever the interface's shaping rate has
	// left after every SIBLING queue resolves", so it needs a pre-pass over the
	// sibling set. Recorded because the two are easy to assume share an
	// implementation and they do not.
	TransmitRateRemainder bool
	Priority              string
	// BufferSizeBytes preserves the legacy explicit byte-size path.
	BufferSizeBytes uint64
	// BufferSizePercent is the Junos percent form. A value > 0 means
	// userspace resolves the scheduler buffer against the interface CoS
	// burst pool when the scheduler is bound to a queue.
	BufferSizePercent float64
	// BufferSizeTemporalUS (#4228 Gap 2 follow-up) carries the Junos
	// `buffer-size temporal <microseconds>` form: size the queue buffer by a
	// target queue delay rather than an absolute byte-size or percent. It is
	// accepted for vSRX-config import parity but ACCEPTED-BUT-INERT — resolving
	// microseconds to bytes needs the queue's transmit rate (which itself may
	// be a percent resolved per bound interface), so xpf does not yet
	// materialize a byte-size from it (a commit advisory surfaces the
	// inertness). Mutually exclusive with BufferSizeBytes / BufferSizePercent.
	BufferSizeTemporalUS uint64
	// SurplusSharing (#915) lifts the surplus-phase skip on
	// transmit-rate exact queues so they can draw from the root
	// shaper's surplus tokens once their own bucket is empty.
	// Only meaningful when TransmitRateExact == true; cleared
	// by ValidateConfig otherwise (warn-and-strip).
	SurplusSharing bool
	// EqualFlowEnforcement opts a positive transmit-rate exact
	// scheduler into shared v8 queue-lease equal-flow suppression.
	// Validation fails closed unless the scheduler has transmit-rate
	// exact with a positive rate and does not also opt into
	// SurplusSharing, whose surplus phase intentionally bypasses the
	// per-queue lease cap.
	EqualFlowEnforcement bool
	// EqualFlowTargetPolicy (#1746) selects the per-flow target the
	// equal-flow publisher enforces: "slowest" (clip to the slowest
	// sampled per-flow rate — the byte-unchanged default; "" maps
	// here), "mean" (clip toward the aggregate-weighted mean achieved
	// per-flow rate), or "ideal-share" (literal scheduler_rate /
	// total_active_flows nominal share; a documented no-op in
	// capacity-limited regimes). Only meaningful with
	// EqualFlowEnforcement; warned (not stripped) otherwise. NO policy
	// lifts slow-worker flows — the cap is one-directional; the
	// work-conserving fix is cross-worker rebalance (#1748).
	EqualFlowTargetPolicy string
	// CodelTargetNS (#1614 A3) is the per-queue CoDel sojourn-time
	// AQM target in nanoseconds. 0 (default) disables CoDel for the
	// queue. Recommended >= 1.5x post-shaper RTT (~5-7 ms on the
	// loss userspace cluster, so 7.5-10 ms = 7_500_000-10_000_000 ns).
	// RFC 8290 baseline is 5 ms; on this cluster 5 ms collides with
	// RTT and may oscillate (see docs/cos-traffic-shaping.md).
	CodelTargetNS uint64
}

// CoSSchedulerMap binds forwarding classes to named schedulers.
type CoSSchedulerMap struct {
	Name    string
	Entries map[string]*CoSSchedulerMapEntry
}

// CoSSchedulerMapEntry is a single forwarding-class -> scheduler binding.
type CoSSchedulerMapEntry struct {
	ForwardingClass string
	Scheduler       string
}

// CoSInterface holds unit-level CoS configuration for an interface.
type CoSInterface struct {
	Name  string
	Units map[int]*CoSInterfaceUnit
	// Level holds a CoS binding applied at the physical interface level
	// (`class-of-service interfaces geX { scheduler-map M; ... }` with no
	// `unit`). In Junos an interface-level binding applies to every
	// logical unit on the port; a unit-level binding overrides it per
	// knob. The compiler folds Level into each configured logical unit
	// after the interface stanza is known (applyCoSInterfaceLevelBindings),
	// so the dataplane snapshot and `show class-of-service` — which both
	// iterate Units — need no interface-level awareness. Nil when the
	// operator configured only per-unit bindings.
	Level *CoSInterfaceUnit
}

// CoSInterfaceUnit defines the Phase 1 root shaper attached to a logical unit.
type CoSInterfaceUnit struct {
	Unit               int
	ShapingRateBytes   uint64
	BurstSizeBytes     uint64
	SchedulerMap       string
	DSCPClassifier     string
	IEEE8021Classifier string
	// INetPrecedenceClassifier is the `classifiers inet-precedence <name>`
	// ingress binding on this unit (#6847). Mutually exclusive with
	// DSCPClassifier: both read the same IPv4 TOS byte, so binding both is a
	// contradiction rather than a composition and is rejected at commit.
	INetPrecedenceClassifier string
	DSCPRewriteRule          string
	// IEEE8021RewriteRule is the `rewrite-rules ieee-802.1 <name>` egress
	// binding on this unit (#4228 Gap 4). Accepted-but-inert: retained for
	// `show configuration` fidelity and the undefined-reference advisory, but
	// the dataplane rewrites only DSCP on egress today.
	IEEE8021RewriteRule string
	// OutputTrafficControlProfile is the raw
	// `output-traffic-control-profile <name>` reference bound to this unit's
	// egress (fable-167 F-2, #4315). resolveCoSTrafficControlProfiles (run
	// after applyCoSInterfaceLevelBindings) looks up the named profile and
	// folds its shaping-rate + scheduler-map into ShapingRateBytes /
	// SchedulerMap when those are not already set directly on the unit
	// (a direct unit-level knob wins). Retained on the unit for
	// `show configuration` fidelity and the undefined-reference advisory.
	OutputTrafficControlProfile string
	// OversubscriptionPolicy (#1614 A1) is the operator-selectable
	// behaviour when sum of exact-class transmit-rates exceeds the
	// interface's shaping-rate. Empty or "proportional" (default)
	// preserves current scheduler bit-for-bit (when
	// PriorityLowMinShareBytes is also 0). "guarantee-rate"
	// activates the v5 two-phase waterfill allocator.
	OversubscriptionPolicy string
	// OversubscriptionGuaranteeFraction (#1614 A1) is the Phase 1
	// budget fraction (0.0..1.0). Only meaningful when
	// OversubscriptionPolicy == "guarantee-rate". 0.0 makes the
	// allocator a no-op even if the policy is set.
	OversubscriptionGuaranteeFraction float64
	// PriorityLowMinShareBytes (#1614 A2) is the priority-low
	// minimum share in bytes per second. Subtracted from effective
	// scheduler cap before the A1 allocator runs (orthogonal to A1
	// policy choice). Default 0 (no min-share).
	PriorityLowMinShareBytes uint64
}

// CoSFairnessExpectation declares an opt-in RSS/workload expectation for
// one egress CoS queue. Interface is the STABLE xpf interface name (e.g.
// ge-0-0-2); the kernel ifindex it maps to is transient across
// re-enumeration, so the name is resolved to the current ifindex at
// evaluate time from the live status snapshot (#hb166 G-9).
type CoSFairnessExpectation struct {
	Interface      string
	QueueID        uint8
	RSSExpectation string
}
