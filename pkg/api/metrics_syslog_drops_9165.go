package api

import (
	"github.com/prometheus/client_golang/prometheus"
)

// initSyslogDropDescriptors declares the remote-syslog drop family (#9165).
func (c *xpfCollector) initSyslogDropDescriptors() {
	c.syslogMessagesDropped = prometheus.NewDesc(
		"xpf_syslog_messages_dropped_total",
		// The `reason` label carries the same three values the package's
		// internal warning does (write / dial / cooldown), so a scrape and a
		// journald line describe the same event in the same vocabulary.
		//
		// `protocol` is not decoration. Only stream transports can report
		// dial/cooldown drops, so a series that is UDP and non-zero on `write`
		// alone is the expected shape, not a gap — and #9165 was precisely a
		// UDP-only silence.
		"Remote syslog messages dropped, by collector and reason.",
		[]string{"addr", "protocol", "reason"}, nil,
	)
}

// collectSyslogDrops emits the remote-syslog drop counters.
//
// This is a CONTROL-PLANE signal — the syslog clients run whether or not the
// dataplane is loaded — so the caller emits it BEFORE the dataplane gate. A box
// that failed to load its dataplane is exactly the box whose logs an operator
// most needs, and gating this behind the dataplane would hide a dead collector
// on it.
func (c *xpfCollector) collectSyslogDrops(ch chan<- prometheus.Metric) {
	if c.srv == nil || c.srv.syslogDropsFn == nil {
		return
	}
	for _, st := range c.srv.syslogDropsFn() {
		// All three reasons are emitted for every collector, including at
		// zero. A counter that appears only once it becomes non-zero cannot
		// be alerted on with `increase()` — the series has no prior sample to
		// compare against — and its absence is indistinguishable from a
		// scrape that never reached this code.
		for _, r := range []struct {
			name string
			v    uint64
		}{
			{"write", st.Writes},
			{"dial", st.Dials},
			{"cooldown", st.Cooldown},
		} {
			c.emitConstMetric(ch, c.syslogMessagesDropped,
				prometheus.CounterValue, float64(r.v),
				st.RemoteAddr, st.Protocol, r.name)
		}
	}
}
