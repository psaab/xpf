package config

// Class-of-service: forwarding classes, DSCP/IEEE-802.1p classifiers and
// rewrite rules, queue schedulers, scheduler-maps, per-interface shaping,
// and fairness expectations.

// ClassOfServiceConfig holds CoS forwarding classes, schedulers,
// scheduler-maps, and per-interface shaping configuration.
type ClassOfServiceConfig struct {
	ForwardingClasses    map[string]*CoSForwardingClass
	DSCPClassifiers      map[string]*CoSDSCPClassifier
	IEEE8021Classifiers  map[string]*CoSIEEE8021Classifier
	DSCPRewriteRules     map[string]*CoSDSCPRewriteRule
	Schedulers           map[string]*CoSScheduler
	SchedulerMaps        map[string]*CoSSchedulerMap
	Interfaces           map[string]*CoSInterface
	FairnessExpectations []*CoSFairnessExpectation
	// FlowRebalance is the #1748 opt-in reactive ntuple rebalance knob.
	// nil => disabled (the userspace-dp controller is never constructed and
	// the default forwarding path is byte-identical).
	FlowRebalance *CoSFlowRebalance
}

// CoSFlowRebalance holds the #1748/#1751 reactive cross-worker ntuple
// rebalance controller knobs. Presence of the block (even with all defaults)
// enables the controller; absence keeps it off.
type CoSFlowRebalance struct {
	// ImbalanceThresholdPercent: #1748 byte-rate threshold, RETAINED for
	// config back-compat but IGNORED by the #1751 count-balancing decision.
	ImbalanceThresholdPercent uint32
	// CountDelta: #1751 count-delta threshold K — the controller moves a flow
	// from the highest-flow-count worker to the lowest only when
	// max_count - min_count >= K. 0 => controller default (2); the selector
	// floors it at 2 (a smaller K cannot admit a move under the overshoot
	// guard).
	CountDelta uint32
	// RebalanceIntervalSecs: minimum seconds between rule installs. 0 =>
	// controller default (1).
	RebalanceIntervalSecs uint32
	// MaxRules: hard cap on concurrently-installed ntuple rules per
	// interface. 0 => controller default (64).
	MaxRules uint32
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

// CoSScheduler defines the Phase 1 class scheduler knobs.
type CoSScheduler struct {
	Name              string
	TransmitRateBytes uint64
	TransmitRateExact bool
	Priority          string
	// BufferSizeBytes preserves the legacy explicit byte-size path.
	BufferSizeBytes uint64
	// BufferSizePercent is the Junos percent form. A value > 0 means
	// userspace resolves the scheduler buffer against the interface CoS
	// burst pool when the scheduler is bound to a queue.
	BufferSizePercent float64
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
}

// CoSInterfaceUnit defines the Phase 1 root shaper attached to a logical unit.
type CoSInterfaceUnit struct {
	Unit               int
	ShapingRateBytes   uint64
	BurstSizeBytes     uint64
	SchedulerMap       string
	DSCPClassifier     string
	IEEE8021Classifier string
	DSCPRewriteRule    string
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
// one egress CoS queue. Ifindex is used intentionally because the
// userspace status snapshot reports the same kernel identity.
type CoSFairnessExpectation struct {
	Ifindex        int
	QueueID        uint8
	RSSExpectation string
}
