package daemon

import (
	"log/slog"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

// #9813: a fabric overlay (fab0/fab1) carries the session-sync address, and it
// is a member of the management VRF because session sync binds its sockets to
// that VRF. Only the apply path bound it: step 0b before networkd, and the
// authoritative re-bind at step 2.7 after it. An overlay created outside an
// apply stayed outside vrf-mgmt, and session sync over that fabric stayed down
// until the next apply of any kind. Two paths create one outside an apply: the
// #6791 re-assert loop and the deferred OnXSKBound closure. An overlay can also
// lose its master without being re-created, for example through an
// out-of-band `ip link set nomaster`.

// mgmtVRFDeviceName is the management VRF's kernel device, named the way
// routing.BindInterfaceToVRF names it.
const mgmtVRFDeviceName = "vrf-" + config.ManagementVRFInstanceName

// fabricOverlayOutsideMgmtVRF reports whether overlay name belongs to the
// management VRF and is not in it. It is false when name is not in the
// published management-VRF set (the last apply did not manage vrf-mgmt), when
// the overlay or the VRF device is absent, and when the overlay's master is
// already the VRF.
func (d *Daemon) fabricOverlayOutsideMgmtVRF(name string) bool {
	if !d.mgmtVRFIfaceSet()[name] {
		return false
	}
	link, err := d.fabricLinkByName(name)
	if err != nil || link == nil || link.Attrs() == nil {
		return false
	}
	vrf, err := d.fabricLinkByName(mgmtVRFDeviceName)
	if err != nil || vrf == nil || vrf.Attrs() == nil {
		return false
	}
	return link.Attrs().MasterIndex != vrf.Attrs().Index
}

// bindFabricOverlayToMgmtVRF binds overlay name to the management VRF when
// fabricOverlayOutsideMgmtVRF says it belongs there and is not. It reports
// whether it attempted a bind.
func (d *Daemon) bindFabricOverlayToMgmtVRF(name string) (bool, error) {
	if d.routing == nil || !d.fabricOverlayOutsideMgmtVRF(name) {
		return false, nil
	}
	return true, d.routing.BindInterfaceToVRF(name, config.ManagementVRFInstanceName)
}

// fabricOverlaysOutsideMgmtVRF returns the configured fabric overlays that
// exist outside the management VRF they belong to. With no published
// management-VRF set it does no lookups at all; otherwise it costs, like
// missingFabricOverlays, a name lookup per configured fab device, plus one for
// the VRF device.
func (d *Daemon) fabricOverlaysOutsideMgmtVRF(cfg *config.Config) []string {
	var out []string
	config.RangeInterfaces(cfg, func(ifName string, ifCfg *config.InterfaceConfig) {
		if ifCfg.LocalFabricMember == "" || !strings.HasPrefix(ifName, "fab") {
			return
		}
		if name := config.LinuxIfName(ifName); d.fabricOverlayOutsideMgmtVRF(name) {
			out = append(out, name)
		}
	})
	return out
}

// rebindFabricOverlaysToMgmtVRF binds every configured fabric overlay that sits
// outside the management VRF. A failure is logged, and the next tick retries.
func (d *Daemon) rebindFabricOverlaysToMgmtVRF(cfg *config.Config) {
	for _, name := range d.fabricOverlaysOutsideMgmtVRF(cfg) {
		slog.Warn("fabric IPVLAN outside the management VRF — re-binding", "name", name)
		if _, err := d.bindFabricOverlayToMgmtVRF(name); err != nil {
			slog.Error("fabric IPVLAN management-VRF bind failed; will retry",
				"name", name, "err", err)
			continue
		}
		slog.Info("fabric IPVLAN bound to the management VRF", "name", name)
	}
}

// createDeferredFabricOverlays is the OnXSKBound callback applyFabricIPVLAN
// registers. It creates the overlays whose creation was deferred past the XSK
// bind. It can run after the apply's step-2.7 management-VRF re-bind, so it
// binds each overlay it creates itself (#9813). A bind failure is left to the
// #6791 re-assert loop, which retries it.
func (d *Daemon) createDeferredFabricOverlays(overlays []deferredIPVLAN) {
	for _, ov := range overlays {
		slog.Info("XSK bound — creating deferred fabric IPVLAN",
			"parent", ov.parent, "name", ov.name)
		if err := fabricEnsureFn(ov.parent, ov.name, ov.addrs); err != nil {
			slog.Error("deferred fabric IPVLAN creation failed",
				"parent", ov.parent, "name", ov.name, "err", err)
			continue
		}
		if _, err := d.bindFabricOverlayToMgmtVRF(ov.name); err != nil {
			slog.Warn("deferred fabric IPVLAN management-VRF bind failed; the re-assert loop retries",
				"name", ov.name, "err", err)
		}
	}
}
