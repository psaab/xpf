package daemon

import (
	"errors"

	"github.com/psaab/xpf/pkg/cluster"
)

// heartbeatRestarter is the part of *cluster.Manager the VRF-rebind apply step
// uses to restart the heartbeat.
type heartbeatRestarter interface {
	RestartHeartbeat() bool
	HeartbeatRestartOwed() bool
}

var _ heartbeatRestarter = (*cluster.Manager)(nil)

// errHeartbeatRestartFailed is joined into the apply's networkd error when the
// heartbeat restart after a management VRF rebind fails (#9751).
var errHeartbeatRestartFailed = errors.New("cluster heartbeat restart after the management VRF rebind failed: " +
	"the heartbeat is stopped, so this node sends no heartbeats and cannot see the peer; " +
	"the next apply retries the restart (#9751)")

// restartHeartbeatAfterRebind restarts the heartbeat after the management VRF
// rebind and reports a failure instead of discarding it (#9751).
//
// RestartHeartbeat returns false in two unrelated cases. Either the heartbeat
// was never running, so there is nothing to restart (before comms start), or a
// restart exhausted its bind retries and left the heartbeat STOPPED. The second
// used to be dropped here: the commit reported success while this node sent no
// heartbeats and the peer declared it lost. HeartbeatRestartOwed tells the two
// apart.
func restartHeartbeatAfterRebind(c heartbeatRestarter) error {
	if c.RestartHeartbeat() || !c.HeartbeatRestartOwed() {
		return nil
	}
	return errHeartbeatRestartFailed
}
