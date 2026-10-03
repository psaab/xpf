package frr

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #11823: renderer belt for configs that bypass strict schema/compiler gates.
// Negative or wider-than-24-bit metrics are omitted instead of emitting a
// vtysh-rejected line that fails the whole managed-section reload (#1880/#2223).
func TestISISFRRNeverEmitsInvalidMetric11823(t *testing.T) {
	for _, tc := range []struct {
		name     string
		metric   int
		wantLine string
		wantWarn bool
	}{
		{name: "unset-default", metric: 0},
		{name: "negative", metric: -5, wantWarn: true},
		{name: "parse-failure-sentinel", metric: -1, wantWarn: true},
		{name: "over-wide-max", metric: 16777216, wantWarn: true},
		{name: "far-over-wide-max", metric: 99999999, wantWarn: true},
		{name: "minimum", metric: 1, wantLine: "isis metric 1"},
		{name: "typical", metric: 10, wantLine: "isis metric 10"},
		{name: "maximum", metric: config.MaxISISMetric, wantLine: "isis metric 16777215"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var logs bytes.Buffer
			previous := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
			defer slog.SetDefault(previous)

			isis := &config.ISISConfig{
				NET: "49.0001.0100.0000.0001.00",
				Interfaces: []*config.ISISInterface{{
					Name: "eth0", Metric: tc.metric,
				}},
			}
			got := New().generateProtocols(nil, nil, nil, nil, isis, "", 0, nil, nil)
			if tc.wantLine != "" {
				if !strings.Contains(got, tc.wantLine) {
					t.Fatalf("valid metric %d did not render %q:\n%s", tc.metric, tc.wantLine, got)
				}
			} else if strings.Contains(got, "isis metric") {
				t.Fatalf("invalid/default metric %d unexpectedly rendered:\n%s", tc.metric, got)
			}
			if tc.wantWarn {
				if !strings.Contains(logs.String(), "invalid IS-IS interface metric") || !strings.Contains(logs.String(), "interface=eth0") {
					t.Fatalf("invalid metric %d did not produce a scoped warning: %s", tc.metric, logs.String())
				}
			} else if strings.Contains(logs.String(), "invalid IS-IS interface metric") {
				t.Fatalf("valid/default metric %d unexpectedly warned: %s", tc.metric, logs.String())
			}
		})
	}
}
