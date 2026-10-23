package userspace

import (
	"encoding/json"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15946 H14-02: time-wait-state flags must reach the wire.
func TestTimeWaitStateFlagsReachWire15946(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Flow.TCPSession = &config.TCPSessionConfig{
		TimeWaitTimeout: 30, TimeWaitStateSessionTimeout: 99,
		TimeWaitStateSessionAgeout: true, TimeWaitStateApplyToHalfClosed: true,
	}
	b, err := json.Marshal(buildFlowSnapshot(cfg))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	for k, want := range map[string]string{
		"tcp_time_wait_timeout":              "99",
		"tcp_time_wait_session_ageout":       "true",
		"tcp_time_wait_apply_to_half_closed": "true",
	} {
		if string(m[k]) != want {
			t.Errorf("%s=%s want %s (%s)", k, m[k], want, b)
		}
	}
	b2, _ := json.Marshal(buildFlowSnapshot(&config.Config{}))
	var m2 map[string]json.RawMessage
	_ = json.Unmarshal(b2, &m2)
	for _, k := range []string{"tcp_time_wait_session_ageout", "tcp_time_wait_apply_to_half_closed"} {
		if _, ok := m2[k]; ok {
			t.Errorf("unset %s emitted", k)
		}
	}
}
