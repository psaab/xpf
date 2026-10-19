package api

import (
	"strings"
	"unicode/utf8"

	"github.com/prometheus/client_golang/prometheus"
)

// #15086 (A44-01): a non-UTF-8 byte in a committed config identifier
// (policy, zone, pool, filter, ... name) used to reach
// prometheus.MustNewConstMetric as a label value. client_golang rejects
// invalid UTF-8 label values, Must* panics, and Registry.Gather runs
// collectors in its own goroutine, so the panic killed the whole daemon
// on the next /metrics scrape — net/http recovery never applies.
//
// emitConstMetric is the single choke point every const-metric emit in
// this package now goes through. It sanitizes the label values (the only
// panic class reachable from config-controlled data) and then uses the
// error-returning NewConstMetric: any residual error (arity, invalid
// descriptor) skips the sample and bumps counterReadErrors instead of
// panicking. Legitimate values pass through byte-identical — the fast
// path is a utf8.ValidString check per value, with no allocation and no
// behaviour change for healthy config.
//
// Descriptor validity is a programmer invariant: NewDesc panics at
// construction for an invalid name/help/variadic-label set, so a bad
// descriptor fails at collector construction, never here.

// sanitizeMetricLabelValue returns s unchanged when it is valid UTF-8,
// and s with each invalid byte folded to U+FFFD otherwise. ok reports
// whether s was already valid.
func sanitizeMetricLabelValue(s string) (out string, ok bool) {
	if utf8.ValidString(s) {
		return s, true
	}
	return strings.ToValidUTF8(s, "�"), false
}

// sanitizeMetricLabelValues sanitizes values in place when the collector
// can count replacements, and reports how many values were invalid. It
// allocates only when at least one value is invalid: the common scrape
// reuses the caller's slice untouched.
func (c *xpfCollector) sanitizeMetricLabelValues(values []string) {
	invalid := 0
	for i, v := range values {
		if s, ok := sanitizeMetricLabelValue(v); !ok {
			values[i] = s
			invalid++
		}
	}
	if invalid > 0 && c != nil {
		c.invalidLabelValues.Add(uint64(invalid))
	}
}

// newConstMetric builds one const metric with sanitized label values.
// Nil-collector safe: standalone helpers (emitHistogram) call it without
// a collector; sanitization still applies, only the counting is skipped.
func newConstMetric(c *xpfCollector, desc *prometheus.Desc, valueType prometheus.ValueType, value float64, labelValues ...string) (prometheus.Metric, error) {
	if c != nil {
		c.sanitizeMetricLabelValues(labelValues)
	} else {
		for i, v := range labelValues {
			if s, ok := sanitizeMetricLabelValue(v); !ok {
				labelValues[i] = s
			}
		}
	}
	return prometheus.NewConstMetric(desc, valueType, value, labelValues...)
}

// emitConstMetric sends the metric built by newConstMetric on ch. On
// any construction error the sample is skipped and counterReadErrors is
// bumped (the #3345 omit-plus-error contract), never panicked.
func (c *xpfCollector) emitConstMetric(ch chan<- prometheus.Metric, desc *prometheus.Desc, valueType prometheus.ValueType, value float64, labelValues ...string) {
	m, err := newConstMetric(c, desc, valueType, value, labelValues...)
	if err != nil {
		if c != nil {
			c.counterReadErrors.Add(1)
		}
		return
	}
	ch <- m
}

// emitInvalidLabelValues publishes the cumulative sanitized-label count.
// Nil-Desc safe: literal-constructed test collectors that never ran
// initGlobalDescriptors skip the sample (the atomic still accumulates).
func (c *xpfCollector) emitInvalidLabelValues(ch chan<- prometheus.Metric) {
	if c == nil || c.invalidLabelValuesTotal == nil {
		return
	}
	c.emitConstMetric(ch, c.invalidLabelValuesTotal, prometheus.CounterValue,
		float64(c.invalidLabelValues.Load()))
}

// emitCollectorPanics publishes the cumulative lane-recovered panic
// count. Nil-Desc safe, mirroring emitInvalidLabelValues.
func (c *xpfCollector) emitCollectorPanics(ch chan<- prometheus.Metric) {
	if c == nil || c.collectorPanicsTotal == nil {
		return
	}
	c.emitConstMetric(ch, c.collectorPanicsTotal, prometheus.CounterValue,
		float64(c.collectorPanics.Load()))
}
