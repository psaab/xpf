package daemon

import (
	"log/slog"

	"github.com/psaab/xpf/pkg/routing"
	"github.com/vishvananda/netlink"
)

// #15223 (A38-02): a desired VRF device (vrf-mgmt or a tenant vrf-*) deleted
// out of band between applies had no re-assert owner. Every #11448/#9813
// loop skipped when the device lookup failed, so its members fell into the
// default VRF until the next apply. The helpers below let those existing
// 30s owners re-create ONLY a device that is still desired — management
// membership comes from the last apply's published set, tenant membership
// from the active config's routing instances — and then run their normal
// bind pass in the same tick. A same-name foreign (non-VRF) link is never
// adopted or deleted: CreateVRF refuses it, matching ReconcileVRFs (#12062).

// vrfDeviceMissing reports whether the named kernel VRF device is absent.
// A present link, even a foreign non-VRF one, is not missing.
func (d *Daemon) vrfDeviceMissing(device string) bool {
	link, err := d.fabricLinkByName(device)
	return err != nil || link == nil || link.Attrs() == nil
}

// ensureVRFDeviceForReassert re-creates one desired VRF device that is
// absent. It reports whether a usable VRF device exists afterwards; a
// foreign occupant or a create failure leaves the tick to retry in 30s
// rather than binding members into a device that is not there. It uses
// the single-VRF CreateVRF, never a full ReconcileVRFs, so it cannot reap
// or otherwise touch any other VRF device.
func (d *Daemon) ensureVRFDeviceForReassert(spec routing.VRFSpec) bool {
	if d.routing == nil {
		return false
	}
	device := "vrf-" + spec.Name
	link, err := d.fabricLinkByName(device)
	if err == nil && link != nil && link.Attrs() != nil {
		if _, ok := link.(*netlink.Vrf); !ok {
			slog.Error("desired VRF device name is occupied by a non-VRF link; refusing to adopt it",
				"device", device, "instance", spec.Name, "issue", "#15223")
			return false
		}
		return true // present (e.g. re-created by a racing owner under applySem)
	}
	slog.Warn("desired VRF device absent — re-creating",
		"device", device, "instance", spec.Name, "table", spec.TableID, "issue", "#15223")
	if err := d.routing.CreateVRF(spec.Name, spec.TableID); err != nil {
		slog.Error("VRF device re-create failed; will retry",
			"device", device, "err", err, "issue", "#15223")
		return false
	}
	link, err = d.fabricLinkByName(device)
	if err != nil || link == nil || link.Attrs() == nil {
		slog.Error("VRF device still absent after re-create; will retry",
			"device", device, "err", err, "issue", "#15223")
		return false
	}
	if _, ok := link.(*netlink.Vrf); !ok {
		slog.Error("re-created VRF device is not a VRF link; will retry",
			"device", device, "issue", "#15223")
		return false
	}
	slog.Info("VRF device re-created", "device", device, "instance", spec.Name, "issue", "#15223")
	return true
}
