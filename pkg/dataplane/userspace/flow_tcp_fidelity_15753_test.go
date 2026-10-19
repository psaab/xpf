package userspace

import (
	"encoding/json"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestTCPFidelityKnobsReachWire15753(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Flow.TCPSession = &config.TCPSessionConfig{
		NoSynCheckInTunnel: true, RstInvalidateSession: true,
		NoSequenceCheck: true, RstSequenceCheck: true, MaximumWindow: 32768,
	}
	b, err := json.Marshal(buildFlowSnapshot(cfg))
	if err != nil { t.Fatalf("marshal: %v", err) }
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil { t.Fatalf("decode: %v", err) }
	for k, want := range map[string]string{
		"tcp_no_syn_check_in_tunnel": "true", "tcp_rst_invalidate_session": "true",
		"tcp_no_sequence_check": "true", "tcp_rst_sequence_check": "true", "tcp_maximum_window": "32768",
	} {
		if string(m[k]) != want { t.Errorf("%s = %s, want %s (wire %s)", k, m[k], want, b) }
	}
	// Unset must omit (omitempty) so old helpers see nothing.
	b2, _ := json.Marshal(buildFlowSnapshot(&config.Config{}))
	var m2 map[string]json.RawMessage
	_ = json.Unmarshal(b2, &m2)
	for k := range map[string]string{"tcp_no_syn_check_in_tunnel": "", "tcp_rst_invalidate_session": ""} {
		if _, ok := m2[k]; ok { t.Errorf("unset %s emitted: %s", k, b2) }
	}
}
