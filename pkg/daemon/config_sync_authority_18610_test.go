package daemon

import (
	"errors"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
)

// #18610: the daemon's RG0-primary refusal must be the cluster sentinel, or
// configApplyLoop treats it as a failed apply: it arms CF on the primary and
// leaves the primary reading "standby config stale", which blocks a rolling
// upgrade started there. RED if errConfigSyncRejectedPrimary goes back to a
// daemon-local errors.New.
func TestRG0PrimaryRefusalIsTheClusterAuthoritySentinel18610(t *testing.T) {
	if !errors.Is(errConfigSyncRejectedPrimary, cluster.ErrConfigSyncRejectedAuthority) {
		t.Fatal("errConfigSyncRejectedPrimary is not cluster.ErrConfigSyncRejectedAuthority")
	}
}
