package daemon

import (
	"log/slog"

	"github.com/psaab/xpf/pkg/config"
)

// controlLinkMoveMark is the last control-link VRF master-move count the
// apply path acted on (#18597).
type controlLinkMoveMark struct {
	link string
	seq  uint64
}

// clusterControlLinkName is the kernel name of the configured cluster control
// link, the link the heartbeat sockets are bound through, or "" when the
// config has no cluster control interface.
func clusterControlLinkName(cfg *config.Config) string {
	if cfg == nil || cfg.Chassis.Cluster == nil || cfg.Chassis.Cluster.ControlInterface == "" {
		return ""
	}
	return cfg.ResolveKernelIfName(cfg.Chassis.Cluster.ControlInterface)
}

// controlLinkMovedSinceLastCheck reports whether the daemon changed the
// control link's VRF master since the previous call, and records the current
// count. A link the daemon never moved has count 0, so the first check after
// a warm restart (em0 already in vrf-mgmt) is not a move; the first check
// after the boot apply bound em0 is. A renamed control link compares against
// 0 for the same reason. Called only under applySem.
func (d *Daemon) controlLinkMovedSinceLastCheck(cfg *config.Config) bool {
	if d.routing == nil {
		return false
	}
	link := clusterControlLinkName(cfg)
	if link == "" {
		return false
	}
	seq := d.routing.VRFMasterMoveSeq(link)
	prev := uint64(0)
	if d.hbControlLinkMoves.link == link {
		prev = d.hbControlLinkMoves.seq
	}
	d.hbControlLinkMoves = controlLinkMoveMark{link: link, seq: seq}
	return seq != prev
}

// restartHeartbeatIfControlLinkMoved restarts the cluster heartbeat after a
// management-VRF bind pass only when that pass, or anything since the last
// pass, actually moved the control link into or out of a VRF, or when a
// failed restart is still owed (#9751).
//
// #18597: the restart used to run after EVERY apply that had a management VRF.
// On master that was paired with networkd detaching em0 from vrf-mgmt on every
// reconfigure, so each commit took em0 down and up twice, removed its
// addresses, and rebuilt the heartbeat sockets while the address was
// mid-move ("bind: cannot assign requested address"). In a 20-commit soak that
// ended in both nodes declaring the other lost and a full RG takeover.
// networkd now renders KeepMaster=yes and leaves the binding alone, so a
// commit that does not change the control link's VRF membership leaves the
// sockets that are already bound through it untouched. A restart that is
// genuinely needed (the link was moved, for example after vrf-mgmt was
// recreated) still runs, and RestartHeartbeat's own peer keepalive and
// restart grace cover it.
//
// Callers run it right after each management bind pass, so the restart
// follows the move instead of waiting for the end of the apply. retryOwed is
// set only by the post-networkd pass, so one apply retries an owed restart
// (and its up-to-5s bind retries) once, as before, not twice.
func (d *Daemon) restartHeartbeatIfControlLinkMoved(cfg *config.Config, retryOwed bool) error {
	if d.cluster == nil {
		return nil
	}
	moved := d.controlLinkMovedSinceLastCheck(cfg)
	if !moved && !(retryOwed && d.cluster.HeartbeatRestartOwed()) {
		slog.Debug("cluster: control link VRF membership unchanged; heartbeat not restarted",
			"interface", clusterControlLinkName(cfg))
		return nil
	}
	return d.restartHeartbeatAfterRebindForCurrentCommsEpoch()
}
