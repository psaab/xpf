package daemon

import (
	xnft "github.com/psaab/xpf/pkg/nftables"
)

// setHostInputFenceOverlay publishes an immutable candidate. Callers must keep
// the old overlay installed until replacement install/readback ACK have
// completed. A nil value is intentionally ignored: detach must use
// clearHostInputFenceOverlayAfterAck only after old-set conntrack ACK and
// empty-candidate nft readback.
func (d *Daemon) setHostInputFenceOverlay(overlay *xnft.HostInputFenceOverlay) {
	if d == nil || overlay == nil {
		return
	}
	copyOverlay := xnft.CanonicalHostInputFenceOverlay(*overlay)
	d.ipsecOverlayAcked.Store(nil)
	d.ipsecOverlay.Store(&copyOverlay)
}

func (d *Daemon) clearHostInputFenceOverlayAfterAck() {
	if d != nil {
		d.ipsecOverlay.Store(nil)
		d.ipsecOverlayAcked.Store(nil)
		d.hostInputFenceConntrackActive.Store(nil)
	}
}

func (d *Daemon) activeHostInputFenceOverlay() *xnft.HostInputFenceOverlay {
	if d == nil {
		return nil
	}
	o := d.ipsecOverlay.Load()
	if o == nil {
		return nil
	}
	copyOverlay := *o
	copyOverlay.MasterSet = append([]string(nil), o.MasterSet...)
	return &copyOverlay
}
