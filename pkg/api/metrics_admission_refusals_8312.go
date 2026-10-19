package api

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/psaab/xpf/pkg/diagcmd"
)

// #8312: export the admission limiters' refusal counts.
//
// THE NUMBER THIS EXISTS TO PROVIDE. #7294 item 2 asks for a WEIGHTED cost
// model on diagcmd.SessionWalkLimiter — charge a full table walk more slots
// than a cursor page — with the acceptance criterion that the model be "stated
// with a measurement, not asserted". Two attempts measured the wrong quantity:
// a cluster REST sweep whose ~80ms of HTTP + JSON fixed cost buried the walk
// and produced five NEGATIVE per-session slopes, and a proposed Go benchmark
// that needs BPF_MAP_CREATE and could not be run.
//
// A weighting is only observable if some request is refused today that a
// weighted budget would admit. Nothing counted refusals, so no per-item cost —
// however precisely measured — could have decided it. This is the instrument
// that can: if these stay at 0 on real deployments the weighting buys nothing
// and the issue is answered; if they climb, the labels say which budget and
// the case is made from a running box rather than from a benchmark.
//
// ALWAYS EMITTED, INCLUDING AT ZERO, per the #3464 convention: a counter that
// appears only once it fires cannot be alerted on and cannot distinguish
// "never refused" from "not scraped". Zero is the answer this issue most needs
// to be able to see.
//
// Cumulative and process-lifetime, so a restart resets it — which is the
// ordinary Prometheus counter contract and is handled by rate() at query time.
func (c *xpfCollector) describeAdmissionRefusals(ch chan<- *prometheus.Desc) {
	ch <- c.admissionRefusalsTotal
}

// admissionLimiters is the set sampled, with the label each carries.
//
// #9143 moved the LIST to diagcmd.AllLimiters, beside the limiters themselves,
// and this is now a thin pass-through. The list being a function here was meant
// to stop "a second list of the same fact" from drifting — but the list still
// lived in a different package from the `var`s it had to contain, and it had
// already drifted: SnapshotReadLimiter (#8151) was added to
// pkg/diagcmd/limiter.go and never reached this list, so its refusals were
// exported as a permanent 0. That is the worst possible direction for #8312,
// whose whole argument rests on a 0 being trustworthy ("if these stay at 0 in
// the field the weighting changes nothing that can be observed") — an
// unregistered limiter is indistinguishable from one that never refuses.
//
// Keeping the registry three lines from the declarations removes the decision
// rather than adding a step to remember, and
// TestAllLimitersIsExhaustive9143 (pkg/diagcmd) fails when a limiter is
// declared without being registered. snapshot_read and vtysh are both exported
// now.
func admissionLimiters() []diagcmd.NamedLimiter {
	return diagcmd.AllLimiters()
}

func (c *xpfCollector) emitAdmissionRefusals(ch chan<- prometheus.Metric) {
	for _, l := range admissionLimiters() {
		if l.Limiter == nil {
			continue
		}
		c.emitConstMetric(ch, c.admissionRefusalsTotal,
			prometheus.CounterValue, float64(l.Limiter.Refusals()), l.Name)
	}
}
