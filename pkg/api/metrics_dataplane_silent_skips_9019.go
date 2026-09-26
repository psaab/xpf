package api

import (
	"sort"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/psaab/xpf/pkg/dataplane/userspace"
)

var learnedRouteCapGroupShedsTotalDesc = prometheus.NewDesc(
	"xpf_learned_route_cap_group_sheds_total",
	"Total learned-route cap group sheds, by kernel route protocol.",
	[]string{"protocol"}, nil,
)

// #9019: export the two userspace-dataplane counters that record work the box
// DECLINED to do.
//
// Both already existed and both were unreadable. `NAPIProbeTargetSkips` and
// `LearnedRouteCapHits` had no consumer anywhere outside their own file and
// their own unit test -- the only other mention of `LearnedRouteCapHits` in the
// tree was a comment in the file that copied its shape. So each fix satisfied
// the letter of "make the skip observable" by incrementing something, and left
// nothing able to observe it.
//
// That is a worse position than no counter at all, because the counter reads as
// the remedy: #9019's acceptance asked for a counter AND a status surface, and
// the counter alone closes the visible half while the box stays exactly as
// silent as before.
//
// WHAT THEY MEAN, since neither is an error:
//
//   - napi_probe_target_skips_total: an interface the NAPI bootstrap could not
//     derive a probe target for, so its queues got no synthetic hardware RX
//     event. Nothing else covers this -- the binding wedge recovery keys on a
//     bind FAILURE and its own give-up message records that "binding readiness
//     cannot see a queue that is bound-but-dead". (That clause used to continue
//     "and the XSK liveness gate is box-wide, so one live queue sets
//     xskLivenessProven for the whole box and masks a cold one"; #9331 removed
//     that masking. The conclusion is unchanged: a queue with no NAPI probe
//     target BINDS successfully and is merely never woken, so it is not a wedge
//     the predicate can see at all.) A non-zero value here is the only signal that a segment
//     may be silently dropping redirected traffic on a path the shim believes
//     is healthy.
//
//   - binding_wedge_giveups_total: bounded auto-rebind exhausted its budget
//     and stopped trying to recover a wedged XSK binding (#9043). Its own
//     give-up message records that "the affected queues will not forward and
//     no readiness signal reports them" -- so before this counter, a single
//     once-per-wedge log line was the entire signal, and a log line that fires
//     once is the hardest kind to alert on. Non-zero means a box is forwarding
//     with queues nobody is trying to repair any more.
//
//   - learned_route_cap_hits_total: a snapshot build that declined learned
//     routes at the cap. Steady non-zero means the helper route set is known
//     incomplete; capped NoRoute frames are adjudicated, with denied results
//     counted as policy denials and Permit results retaining ordinary
//     delegation (#9522).
//
//   - learned_route_cap_group_sheds_total{protocol}: complete table/protocol
//     route groups shed to stay within the publish budget (#10824). The fixed
//     protocol set is emitted at zero; unknown observed protocols are included.
//
// ALWAYS EMITTED, INCLUDING AT ZERO, per the #3464 convention and for the
// reason #8312 and #9042 both give: a counter that appears only once it fires
// cannot be alerted on, and cannot distinguish "never skipped" from "not
// scraped". Zero is the normal state, which makes every reading one an
// operator can trust; any departure from zero IS the event.
//
// EMITTED BEFORE THE DATAPLANE GATE, like the admission-refusal and
// authz-denial counters above them, and here the reason is sharper than
// convention: these describe a dataplane that came up INCOMPLETELY. Emitting
// them behind a gate that requires a healthy dataplane would hide them in
// exactly the case they exist to report.
//
// Cumulative and process-lifetime; a restart resets them, the ordinary
// Prometheus counter contract, handled by rate() at query time.
func (c *xpfCollector) describeDataplaneSilentSkips(ch chan<- *prometheus.Desc) {
	ch <- c.napiProbeTargetSkipsTotal
	ch <- c.bindingWedgeGiveupsTotal
	ch <- c.learnedRouteCapHitsTotal
	ch <- learnedRouteCapGroupShedsTotalDesc
}

func (c *xpfCollector) emitDataplaneSilentSkips(ch chan<- prometheus.Metric) {
	ch <- prometheus.MustNewConstMetric(c.napiProbeTargetSkipsTotal,
		prometheus.CounterValue, float64(userspace.NAPIProbeTargetSkips()))
	ch <- prometheus.MustNewConstMetric(c.bindingWedgeGiveupsTotal,
		prometheus.CounterValue, float64(userspace.BindingWedgeGiveups()))
	ch <- prometheus.MustNewConstMetric(c.learnedRouteCapHitsTotal,
		prometheus.CounterValue, float64(userspace.LearnedRouteCapHits()))
	protocolHits := userspace.LearnedRouteCapHitsByProtocol()
	protocols := make([]string, 0, len(protocolHits))
	for protocol := range protocolHits {
		protocols = append(protocols, protocol)
	}
	sort.Strings(protocols)
	for _, protocol := range protocols {
		ch <- prometheus.MustNewConstMetric(learnedRouteCapGroupShedsTotalDesc,
			prometheus.CounterValue, float64(protocolHits[protocol]), protocol)
	}
}
