package config

import "fmt"

// NTPAcquisitionInstance decides which routing instance chrony's NTP client
// sockets are bound to (#18584).
//
// Why it exists: on a chassis cluster the only off-box route a node is
// guaranteed to have is in the management VRF (fxp0's DHCP default). The
// default instance's default route leaves through a RETH, which only the node
// that owns that redundancy group has; the other node's default is a
// blackhole. chronyd in the default instance therefore reaches its servers on
// at most one node, and a failover moves that reachability to the other node.
// On loss (2026-10-31) both nodes had no source and fw1 was 71 s behind,
// which broke every cross-node fabric RPC (30 s token window).
//
// chrony has exactly one acquisition-socket device (`bindacqdevice`), not a
// per-source one, so the per-server `routing-instance` modifier can only be
// honoured when every server agrees. Returns:
//
//   - ("", true, "") — no server names an instance: chrony stays in the
//     default instance, exactly as before.
//   - (ri, true, "") — every server names the same instance ri, and ri is the
//     management VRF (which the daemon creates only when a management-class
//     interface — fxp*, em*, fab* — is configured) or a configured
//     VRF-backed instance: bind to VRFDeviceName(ri).
//   - ("", false, reason) — the servers disagree, or name an instance that
//     has no VRF device (unknown, or instance-type forwarding). Nothing is
//     bound and the commit warns with `reason`.
//
// Peers (`system ntp peer`) are not covered: chrony sends peer traffic from
// its NTP server socket (`binddevice`), not the acquisition sockets, so their
// routing-instance stays advisory (#15709).
func NTPAcquisitionInstance(cfg *Config) (string, bool, string) {
	if cfg == nil {
		return "", true, ""
	}
	sys := &cfg.System
	if len(sys.NTPServers) == 0 {
		return "", true, ""
	}
	var ri string
	for i, server := range sys.NTPServers {
		got := sys.NTPServerOptions[server].RoutingInstance
		if i == 0 {
			ri = got
			continue
		}
		if got != ri {
			return "", false, fmt.Sprintf("servers name different routing-instances (%s, %s) and chrony binds every NTP client socket to one device; none is bound",
				ntpInstanceLabel(ri), ntpInstanceLabel(got))
		}
	}
	if ri == "" {
		return "", true, ""
	}
	if ri == ManagementVRFInstanceName {
		// The daemon creates vrf-mgmt only for a configured management-class
		// interface (pkg/daemon managementVRFIfaceSet). Binding chrony to a
		// device that does not exist would leave it with no source at all.
		for name := range cfg.Interfaces.Interfaces {
			if IsManagementIfName(name) {
				return ri, true, ""
			}
		}
		return "", false, fmt.Sprintf("routing-instance %q is the management VRF, which exists only when a management interface (fxp*, em*, fab*) is configured, and none is", ri)
	}
	for _, inst := range cfg.RoutingInstances {
		if inst == nil || inst.Name != ri {
			continue
		}
		if inst.InstanceType == "forwarding" {
			return "", false, fmt.Sprintf("routing-instance %q is instance-type forwarding and has no VRF device to bind to", ri)
		}
		return ri, true, ""
	}
	return "", false, fmt.Sprintf("routing-instance %q is not configured", ri)
}

func ntpInstanceLabel(ri string) string {
	if ri == "" {
		return "default"
	}
	return ri
}

// clusterNTPDefaultInstanceAdvisory is the commit advisory for a chassis
// cluster whose NTP servers are all reached through the default instance
// (#18584). The secondary has no default-instance egress, so chrony there has
// no reachable source; the remedy names the management VRF.
const clusterNTPDefaultInstanceAdvisory = "chassis cluster NTP servers are reached through the default " +
	"routing instance: only the node that owns the WAN redundancy group has a default-instance route " +
	"off the box, so the other node never syncs and its clock drifts until cross-node fabric RPC " +
	"(30-second token window) fails. Reach them through the management VRF: " +
	"`set system ntp server <address> routing-instance " + ManagementVRFInstanceName + "` (#18584)."

// appendClusterNTPInstanceAdvisoryLocked adds the #18584 advisory. It shares
// the #8357 advisory's suppression on the tolerant (boot / peer-sync) compile
// paths for the same reason: a warning repeated on every boot for a decision
// already made is one an operator learns to skip.
func appendClusterNTPInstanceAdvisoryLocked(cfg *Config, opts compileOpts) {
	if cfg == nil || opts.suppressClusterNTPAdvisory || cfg.Chassis.Cluster == nil {
		return
	}
	if len(cfg.System.NTPServers) == 0 {
		return // #8357's advisory covers "no source at all"
	}
	ri, ok, _ := NTPAcquisitionInstance(cfg)
	if ok && ri == "" {
		cfg.Warnings = append(cfg.Warnings, clusterNTPDefaultInstanceAdvisory)
	}
}

// appendNTPRoutingInstanceAdvisoryLocked keeps the #11444 accepted-but-inert
// advisory for the routing-instance shapes chrony cannot express (#18584):
// servers that disagree, or an instance with no VRF device. Like the advisory
// it replaces it fires on every compile path, strict and tolerant: the knob is
// inert on all of them.
func appendNTPRoutingInstanceAdvisoryLocked(cfg *Config) {
	if cfg == nil {
		return
	}
	named := false
	for _, server := range cfg.System.NTPServers {
		if cfg.System.NTPServerOptions[server].RoutingInstance != "" {
			named = true
			break
		}
	}
	if !named {
		return
	}
	if _, ok, reason := NTPAcquisitionInstance(cfg); !ok {
		cfg.Warnings = append(cfg.Warnings, "system ntp server routing-instance: accepted but NOT enforced ("+
			reason+"; NTP sources are queried through the default instance) (#18584)")
	}
}
