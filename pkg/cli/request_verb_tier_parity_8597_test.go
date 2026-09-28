package cli

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #8597 K47, the console half of the tier agreement. The gRPC half is
// TestPoliciesCheckTopicCostsWhatTheConsoleCharges_8597 /
// TestRescueVerbsCostWhatTheConsoleCharges_8597 in pkg/grpcapi, which cannot
// import this package.
//
// The two verbs the remote `cli` gained must keep costing what they cost here.
// If a later change elevates one of these to maintenance, this cell reds and
// names the gRPC table that has to move with it.
func TestRequestVerbTiersMatchTheRemoteSurface_8597(t *testing.T) {
	for _, tc := range []struct {
		cmd  []string
		want config.LoginClassPermission
	}{
		{[]string{"request", "security", "policies", "check"}, config.PermControl},
		{[]string{"request", "system", "configuration", "rescue", "save"}, config.PermControl},
		{[]string{"request", "system", "configuration", "rescue", "delete"}, config.PermControl},
		// The contrast, so "PermControl" is a measurement rather than the only
		// answer this resolver gives for `request`.
		{[]string{"request", "system", "zeroize"}, config.PermMaint},
		{[]string{"request", "system", "reboot"}, config.PermMaint},
	} {
		t.Run(tc.cmd[1]+" "+tc.cmd[2], func(t *testing.T) {
			if got := requiredPermission(tc.cmd); got != tc.want {
				t.Errorf("%v costs %v, want %v. The gRPC surface prices the same "+
					"command from showTextElevatedTopics / systemActionPermissions; "+
					"a change here must move that table too (#8597 K47)",
					tc.cmd, got, tc.want)
			}
		})
	}
}

func TestDynamicAddressShrinkAcknowledgementRequiresConfigurePermission(t *testing.T) {
	command := []string{
		"request", "security", "dynamic-address", "acknowledge-shrink",
		"threats", "candidate-id", "41", "candidate-hash",
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"old-count", "100", "new-count", "5", "reason", "upstream", "change", "reviewed",
	}
	if got := requiredPermission(command); got != config.PermConfig {
		t.Fatalf("dynamic-address shrink acknowledgement costs %v, want %v", got, config.PermConfig)
	}
}
