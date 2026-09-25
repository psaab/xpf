package userspace

import (
	"encoding/json"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// The two TCP SYN selectors must cross the Go/Rust snapshot boundary together
// so the dataplane can apply no-syn-check while preserving strict-mode override.
func TestTCPSynCheckSelectorsReachTheWire10703(t *testing.T) {
	cases := []struct {
		name           string
		noSynCheck     bool
		strictSynCheck bool
	}{
		{name: "unset"},
		{name: "no-syn-check", noSynCheck: true},
		{name: "strict-syn-check", strictSynCheck: true},
		{name: "strict overrides opt-out", noSynCheck: true, strictSynCheck: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{}
			cfg.Security.Flow.TCPSession = &config.TCPSessionConfig{
				NoSynCheck:     tc.noSynCheck,
				StrictSynCheck: tc.strictSynCheck,
			}
			b, err := json.Marshal(buildFlowSnapshot(cfg))
			if err != nil {
				t.Fatalf("marshal flow snapshot: %v", err)
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(b, &fields); err != nil {
				t.Fatalf("decode flow snapshot: %v", err)
			}
			for _, want := range []struct {
				name  string
				field string
				value bool
			}{
				{name: "no-syn-check", field: "tcp_no_syn_check", value: tc.noSynCheck},
				{name: "strict-syn-check", field: "tcp_strict_syn_check", value: tc.strictSynCheck},
			} {
				raw, present := fields[want.field]
				if !want.value {
					if present {
						t.Errorf("unset %s was emitted: %s", want.name, raw)
					}
					continue
				}
				if !present {
					t.Errorf("configured %s missing from flow snapshot: %s", want.name, b)
					continue
				}
				var got bool
				if err := json.Unmarshal(raw, &got); err != nil || !got {
					t.Errorf("%s = %s (decode error %v), want true", want.name, raw, err)
				}
			}
		})
	}
}
