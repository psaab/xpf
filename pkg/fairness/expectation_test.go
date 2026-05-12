package fairness

import (
	"strings"
	"testing"
)

func TestParseRSSExpectation(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{name: "any empty", raw: "", want: "any"},
		{name: "balanced", raw: "balanced", want: "balanced"},
		{name: "active workers", raw: "active-workers:4", want: "at-least-active-workers:4"},
		{name: "max share percent", raw: "max-worker-flow-share:50%", want: "max-worker-flow-share:0.5"},
		{name: "cstruct operator", raw: "cstruct <= 25%", want: "cstruct-max:0.25"},
		{name: "cstruct unicode whitespace", raw: "cstruct\u00a0<=\u00a025%", want: "cstruct-max:0.25"},
		{name: "cstruct above one", raw: "cstruct-max:1.2", want: "cstruct-max:1.2"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseRSSExpectation(tt.raw)
			if err != nil {
				t.Fatalf("ParseRSSExpectation(%q) error = %v", tt.raw, err)
			}
			if got.Canonical() != tt.want {
				t.Fatalf("ParseRSSExpectation(%q) canonical = %q, want %q", tt.raw, got.Canonical(), tt.want)
			}
		})
	}
}

func TestParseRSSExpectationRejectsInvalidValues(t *testing.T) {
	for _, raw := range []string{
		"bogus",
		"at-least-active-workers:not-a-number",
		"max-worker-flow-share:150%",
		"max-worker-flow-share:-1",
		"cstruct-max:-0.1",
		"cstruct-max:NaN",
	} {
		t.Run(raw, func(t *testing.T) {
			if _, err := ParseRSSExpectation(raw); err == nil {
				t.Fatalf("ParseRSSExpectation(%q) succeeded, want error", raw)
			}
		})
	}
}

func TestRSSExpectationMetricShape(t *testing.T) {
	tests := []struct {
		raw      string
		wantKind string
		wantVal  float64
		wantHas  bool
	}{
		{raw: "balanced", wantKind: "balanced"},
		{raw: "at-least-active-workers:3", wantKind: "at-least-active-workers", wantVal: 3, wantHas: true},
		{raw: "max-worker-flow-share:50%", wantKind: "max-worker-flow-share", wantVal: 0.5, wantHas: true},
		{raw: "cstruct-max:0.25", wantKind: "cstruct-max", wantVal: 0.25, wantHas: true},
	}
	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			got, err := ParseRSSExpectation(tt.raw)
			if err != nil {
				t.Fatalf("ParseRSSExpectation(%q): %v", tt.raw, err)
			}
			if got.MetricKind() != tt.wantKind {
				t.Fatalf("MetricKind() = %q, want %q", got.MetricKind(), tt.wantKind)
			}
			value, ok := got.MetricValue()
			if ok != tt.wantHas || value != tt.wantVal {
				t.Fatalf("MetricValue() = (%v, %t), want (%v, %t)", value, ok, tt.wantVal, tt.wantHas)
			}
		})
	}
}

func TestEvaluateRSSExpectation(t *testing.T) {
	tests := []struct {
		name       string
		raw        string
		dist       []uint32
		cstruct    float64
		workers    uint32
		wantPass   bool
		wantReason string
	}{
		{
			name:       "balanced pass",
			raw:        "balanced",
			dist:       []uint32{2, 2, 2, 2},
			workers:    4,
			wantPass:   true,
			wantReason: "balanced: active_workers=4, min=2, max=2",
		},
		{
			name:       "balanced skew fail",
			raw:        "balanced",
			dist:       []uint32{9, 1, 1, 0},
			workers:    4,
			wantPass:   false,
			wantReason: "balanced: active_workers=3 expected 4, min=1, max=9",
		},
		{
			name:       "active workers pass",
			raw:        "at-least-active-workers:3",
			dist:       []uint32{2, 0, 1, 1},
			workers:    4,
			wantPass:   true,
			wantReason: "active_workers=3 >= expected 3",
		},
		{
			name:       "max share fail",
			raw:        "max-worker-flow-share:50%",
			dist:       []uint32{3, 1},
			workers:    2,
			wantPass:   false,
			wantReason: "max_worker_flow_share=0.7500 > expected 0.5000",
		},
		{
			name:       "cstruct pass",
			raw:        "cstruct-max:0.6",
			dist:       []uint32{3, 1},
			cstruct:    0.577350269,
			workers:    2,
			wantPass:   true,
			wantReason: "cstruct=0.5774 <= expected 0.6000",
		},
		{
			name:       "max share no traffic fails",
			raw:        "max-worker-flow-share:50%",
			dist:       []uint32{0, 0, 0, 0},
			workers:    4,
			wantPass:   false,
			wantReason: "max-worker-flow-share: no active flows observed",
		},
		{
			name:       "cstruct no traffic fails",
			raw:        "cstruct-max:0.25",
			dist:       []uint32{0, 0, 0, 0},
			workers:    4,
			wantPass:   false,
			wantReason: "cstruct-max: no active flows observed",
		},
		{
			name:       "balanced no traffic fails",
			raw:        "balanced",
			dist:       []uint32{0, 0, 0, 0},
			workers:    4,
			wantPass:   false,
			wantReason: "balanced: no active flows observed",
		},
		{
			name:       "active workers no traffic fails",
			raw:        "at-least-active-workers:0",
			dist:       []uint32{0, 0, 0, 0},
			workers:    4,
			wantPass:   false,
			wantReason: "at-least-active-workers: no active flows observed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expectation, err := ParseRSSExpectation(tt.raw)
			if err != nil {
				t.Fatalf("ParseRSSExpectation(%q): %v", tt.raw, err)
			}
			got := EvaluateRSSExpectation(expectation, tt.dist, tt.cstruct, tt.workers)
			if got.Pass != tt.wantPass {
				t.Fatalf("EvaluateRSSExpectation pass = %t, want %t; reason=%s", got.Pass, tt.wantPass, got.Reason)
			}
			if !strings.Contains(got.Reason, tt.wantReason) {
				t.Fatalf("EvaluateRSSExpectation reason = %q, want substring %q", got.Reason, tt.wantReason)
			}
		})
	}
}

func TestEvaluateRSSExpectationRejectsUnknownKindBeforeNoTraffic(t *testing.T) {
	got := EvaluateRSSExpectation(RSSExpectation{Kind: "bogus"}, []uint32{0, 0}, 0, 2)
	if got.Pass {
		t.Fatalf("EvaluateRSSExpectation passed unknown kind: %+v", got)
	}
	if !strings.Contains(got.Reason, `unknown RSS expectation kind "bogus"`) {
		t.Fatalf("EvaluateRSSExpectation reason = %q, want unknown-kind error", got.Reason)
	}
}
