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
// panicking. Label values without backslashes or invalid bytes retain the
// byte-identical, allocation-free fast path.
//
// Descriptor validity is a programmer invariant: NewDesc panics at
// construction for an invalid name/help/variadic-label set, so a bad
// descriptor fails at collector construction, never here.
//
// #16707: strings.ToValidUTF8(s, "�") is many-to-one — web\xffallow and
// web\xfeallow both folded to web�allow. Two such identifiers in the
// same scope then emitted duplicate series and Registry.Gather failed
// the whole scrape (promhttp HTTPErrorOnError -> 500, zero samples).
// sanitizeMetricLabelValue escapes each invalid byte as \xNN (lowercase
// hex) and each literal backslash as \x5c. This reserves the escape
// introducer, so distinct raw values—including a raw invalid byte and a
// valid literal \xNN spelling—keep distinct sanitized spellings. Healthy
// values without backslashes are unchanged. Any residual duplicate-series
// source (the Y49-03 class) is covered by the systemic ContinueOnError
// backstop in metrics_handler.go, which drops the duplicate and counts it
// instead of 500ing the whole scrape.

// sanitizeMetricLabelValue returns s unchanged when it is valid UTF-8 and
// contains no backslash. It escapes each invalid byte as \xNN and each
// backslash as \x5c, so the mapping from raw byte strings to sanitized
// values is injective and reversible. ok reports whether s was valid UTF-8.
func sanitizeMetricLabelValue(s string) (out string, ok bool) {
	var b strings.Builder
	escaped := false
	valid := true
	start := 0
	for i := 0; i < len(s); {
		if s[i] == '\\' {
			if !escaped {
				b.Grow(len(s) + 8)
				b.WriteString(s[:i])
				escaped = true
			} else {
				b.WriteString(s[start:i])
			}
			b.WriteString(`\x5c`)
			i++
			start = i
			continue
		}
		_, size := utf8.DecodeRuneInString(s[i:])
		if size == 1 && s[i] >= utf8.RuneSelf {
			// Invalid byte (including a truncated/invalid sequence head).
			valid = false
			if !escaped {
				b.Grow(len(s) + 8)
				b.WriteString(s[:i])
				escaped = true
			} else {
				b.WriteString(s[start:i])
			}
			const hex = "0123456789abcdef"
			b.WriteString(`\x`)
			b.WriteByte(hex[s[i]>>4])
			b.WriteByte(hex[s[i]&0x0f])
			i++
			start = i
			continue
		}
		i += size
	}
	if !escaped {
		return s, true
	}
	b.WriteString(s[start:])
	return b.String(), valid
}

// sanitizeMetricLabelValues sanitizes values in place when the collector
// can count invalid UTF-8 values. It allocates only when a value contains
// a backslash or invalid byte; clean values reuse the caller's slice.
func (c *xpfCollector) sanitizeMetricLabelValues(values []string) {
	invalid := 0
	for i, v := range values {
		s, ok := sanitizeMetricLabelValue(v)
		if s != v {
			values[i] = s
		}
		if !ok {
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
			s, _ := sanitizeMetricLabelValue(v)
			if s != v {
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

// emitGatherErrors publishes the cumulative count of scrapes whose
// Registry.Gather returned duplicate-series (or other) errors that
// promhttp's ContinueOnError salvaged (#16707). Nil-Desc safe.
func (c *xpfCollector) emitGatherErrors(ch chan<- prometheus.Metric) {
	if c == nil || c.gatherErrorsTotal == nil {
		return
	}
	c.emitConstMetric(ch, c.gatherErrorsTotal, prometheus.CounterValue,
		float64(c.gatherErrors.Load()))
}
