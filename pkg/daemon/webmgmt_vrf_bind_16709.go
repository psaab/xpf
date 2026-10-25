package daemon

import (
	"github.com/psaab/xpf/pkg/config"
)

// webmgmt_vrf_bind_16709.go — #16709: resolve the SO_BINDTODEVICE scope
// for a web-management interface.
//
// An interface enslaved to a VRF has its addresses only in that VRF's
// local table, so an unscoped bind to them is refused EADDRNOTAVAIL.
// The daemon enslaves in exactly two ways, and this resolver mirrors
// both (management first, mirroring bindRoutingInstanceMembers'
// management-wins ownership):
//
//   - management-class interfaces (fxp*/fab*/em*, config.IsManagementIfName
//     — the same class managementVRFIfaceSet binds) -> vrf-mgmt
//     (config.ManagementVRFDeviceName);
//   - a non-forwarding routing-instance `interface` member (tenant
//     virtual-router) -> "vrf-"+instance, the device pkg/routing
//     creates for that instance.
//
// Everything else (default-VRF data interfaces, loopback, unknown
// refs) resolves to "" — the unscoped pre-#16709 bind. The resolver is
// a pure function of the committed config so resolveAPIBinds, the
// management reconciler's fingerprint, and unit tests all derive the
// same scope without a kernel lookup: config is the source of truth
// for enslavement (the apply path binds exactly what this function
// reads), and a scope named for a VRF device that does not exist yet
// fails the bind visibly (ENODEV-class) and is retried by the #6803
// re-assert owner instead of silently serving unscoped.

// webMgmtBindDevice returns the VRF device a web-management bind on
// the authored Junos interface ref (e.g. "fxp0.0", "ge-0/0/0.0") must
// be scoped to, or "" for an unscoped bind.
func webMgmtBindDevice(cfg *config.Config, ifname string) string {
	if cfg == nil || ifname == "" {
		return ""
	}
	kernelName := cfg.ResolveKernelIfName(ifname)
	// Management class wins: the daemon refuses tenant ownership of
	// management-class devices (#11392), so a config that lists fxp0
	// under a routing-instance still enslaves it to vrf-mgmt.
	if mgmt := managementVRFIfaceSet(cfg); mgmt[kernelName] {
		return config.ManagementVRFDeviceName
	}
	// Also honour the bare authored name's class (covers configs whose
	// interface table spells the device differently from the resolved
	// kernel name, e.g. unit/VLAN forms managementVRFIfaceSet keys by
	// LogicalUnitDeviceKey).
	if config.IsManagementIfName(ifname) {
		// Only claim vrf-mgmt when the daemon will actually create it:
		// at least one management interface must be configured.
		if len(managementVRFIfaceSet(cfg)) > 0 {
			return config.ManagementVRFDeviceName
		}
	}
	owners := config.RoutingInstanceMemberLinuxNameOwners(cfg)
	if inst, ok := owners[kernelName]; ok && inst != "" {
		return "vrf-" + inst
	}
	return ""
}

// bindDevicesForInterface renders the api.Config BindDevices entries
// for one plane: every resolved bind address of iface scoped to dev.
// An empty dev yields nil (fully unscoped plane).
func bindDevicesForInterface(addrs []string, dev string) map[string]string {
	if dev == "" || len(addrs) == 0 {
		return nil
	}
	out := make(map[string]string, len(addrs))
	for _, a := range addrs {
		out[a] = dev
	}
	return out
}

// mergeBindDevices folds src into dst (allocating dst when needed) and
// returns the result. Later planes never collide with earlier ones on
// a key in practice (HTTP :80 vs HTTPS :443), but a collision would
// keep the last writer — the two planes resolve the same device for a
// shared interface anyway.
func mergeBindDevices(dst, src map[string]string) map[string]string {
	if len(src) == 0 {
		return dst
	}
	if dst == nil {
		dst = make(map[string]string, len(src))
	}
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

// rebuildBindDevicesAfterClamp drops scope entries whose address was
// rewritten by the #4047/#5127 loopback clamp. A clamped leg serves on
// loopback in the main table; keeping its VRF scope would scope the
// loopback socket to the VRF (harmless for 127.0.0.1, wrong in
// principle and confusing in the fingerprint). Entries for surviving
// addresses are kept verbatim.
func rebuildBindDevicesAfterClamp(devices map[string]string, liveAddrs ...[]string) map[string]string {
	if len(devices) == 0 {
		return nil
	}
	live := make(map[string]bool)
	for _, set := range liveAddrs {
		for _, a := range set {
			live[a] = true
		}
	}
	out := make(map[string]string, len(devices))
	for addr, dev := range devices {
		if live[addr] {
			out[addr] = dev
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
