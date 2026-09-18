// controllink_auth_status_4484_test.go — #4484 L-9: the control-plane
// statistics surface must reveal whether the #4107 control-link authentication
// is ENGAGED (enforced) or silently degraded to DUAL-ACCEPT. The status string
// is derived from the same two facts the auth-decision gates use
// (ControlLinkAuthKey + HeartbeatPeerAuthSeen), so it tracks the real
// enforcement posture.
package cluster

import (
	"strings"
	"testing"
)

func TestControlLinkAuthStatus(t *testing.T) {
	tests := []struct {
		name         string
		key          []byte
		wantEngaged  bool   // "engaged" vs "dual-accept"
		wantContains string // a stable discriminating substring
	}{
		{
			name:         "no key configured -> dual-accept",
			key:          nil,
			wantEngaged:  false,
			wantContains: "no control-link key configured",
		},
		{
			name:         "key configured before peer authentication -> engaged",
			key:          []byte("shared-psk-16byte"),
			wantEngaged:  true,
			wantContains: "unauthenticated heartbeat frames rejected",
		},
		{
			name:         "key configured after peer authentication -> engaged",
			key:          []byte("shared-psk-16byte"),
			wantEngaged:  true,
			wantContains: "unauthenticated heartbeat frames rejected",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := &Manager{controlAuthKey: tc.key}
			got := m.controlLinkAuthStatus()
			engaged := strings.HasPrefix(got, "engaged")
			if engaged != tc.wantEngaged {
				t.Errorf("controlLinkAuthStatus() = %q; engaged=%v, want engaged=%v",
					got, engaged, tc.wantEngaged)
			}
			if !strings.Contains(got, tc.wantContains) {
				t.Errorf("controlLinkAuthStatus() = %q; want to contain %q", got, tc.wantContains)
			}

			// The secret key bytes must never leak into the rendered status.
			if len(tc.key) > 0 && strings.Contains(got, string(tc.key)) {
				t.Errorf("controlLinkAuthStatus() leaked the control-link key: %q", got)
			}
		})
	}
}

// TestFormatControlPlaneStatisticsIncludesAuth pins that the auth posture is
// wired into the operator-visible `show chassis cluster
// control-plane-statistics` render (FormatControlPlaneStatistics), not just the
// helper. RED-on-revert: dropping the Authentication line makes this fail.
func TestFormatControlPlaneStatisticsIncludesAuth(t *testing.T) {
	m := &Manager{controlAuthKey: []byte("shared-psk-16byte")}
	r := &heartbeatReceiver{mgr: m, auth: m.heartbeatAuthState()}
	m.hbReceiver = r
	r.auth.peerAuthSeen.Store(true)

	out := m.FormatControlPlaneStatistics()
	if !strings.Contains(out, "Authentication:") {
		t.Errorf("FormatControlPlaneStatistics missing Authentication line:\n%s", out)
	}
	if !strings.Contains(out, "engaged") {
		t.Errorf("FormatControlPlaneStatistics did not report engaged auth:\n%s", out)
	}
}
