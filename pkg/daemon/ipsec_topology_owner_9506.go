package daemon

import (
	"context"
	"sync"
	"time"

	"github.com/psaab/xpf/pkg/config"
	xnft "github.com/psaab/xpf/pkg/nftables"
	"github.com/vishvananda/netlink"
)

var ipsecTopologyLinkList = netlink.LinkList

const ipsecTopologyPollInterval = time.Second

// startIpsecTopologyLinkWatch joins the RTNL subscription to daemon shutdown.
// A link event revokes immediately; the periodic census remains the recovery
// path after dropped notifications or a subscription restart.
func (d *Daemon) startIpsecTopologyLinkWatch(ctx context.Context, wg *sync.WaitGroup) {
	if d == nil || ctx == nil || wg == nil {
		return
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		d.ipsecTopologyLinkWatch(ctx)
	}()
}

func (d *Daemon) ipsecTopologyLinkWatch(ctx context.Context) {
	for {
		if !d.runIpsecTopologyLinkSubscription(ctx) {
			return
		}
		timer := time.NewTimer(linkStateResubBackoffDefault)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return
		case <-timer.C:
		}
	}
}

func (d *Daemon) runIpsecTopologyLinkSubscription(ctx context.Context) bool {
	updates := make(chan netlink.LinkUpdate, 64)
	done := make(chan struct{})
	if err := netlink.LinkSubscribe(updates, done); err != nil {
		d.ipsecTopologySubscribed.Store(false)
		close(done)
		d.pollIpsecTopology()
		d.noteIpsecTopologyLinkTransition()
		d.pollIpsecTopology()
		return true
	}
	d.ipsecTopologySubscribed.Store(false)
	defer func() {
		d.ipsecTopologySubscribed.Store(false)
		close(done)
	}()
	// Establish the initial census before receiving events. This first pass is
	// intentionally UNKNOWN because subscription health is not established yet.
	d.pollIpsecTopology()
	d.ipsecTopologySubscribed.Store(true)
	d.pollIpsecTopology()
	for {
		select {
		case <-ctx.Done():
			return false
		case update, ok := <-updates:
			if !ok {
				d.ipsecTopologySubscribed.Store(false)
				d.noteIpsecTopologyLinkTransition()
				d.pollIpsecTopology()
				return true
			}
			if d.ipsecTopologyLinkEventRelevant(update) {
				d.noteIpsecTopologyLinkTransition()
			}
			// Every event still drives a census. Proven-irrelevant noise must
			// leave the immutable permit record untouched when the census is
			// unchanged, while a missed/reordered relevant event is recovered
			// by the authoritative snapshot.
			d.pollIpsecTopology()
		}
	}
}

func (d *Daemon) ipsecTopologyLinkEventRelevant(update netlink.LinkUpdate) bool {
	if d == nil || d.ipsecS4 == nil || update.Link == nil {
		return true
	}
	attrs := update.Link.Attrs()
	if attrs == nil {
		return true
	}
	if attrs.Name == xnft.HostInboundDelegatedIfname {
		return true
	}
	snapshot := d.ipsecS4.watch.Load()
	snapshotCurrent := false
	if snapshot != nil {
		permit := d.ipsecS4.loadPermit()
		snapshotCurrent = permit != nil && permit.watchGeneration == snapshot.Generation
		for _, tuple := range snapshot.Tuples {
			if attrs.Index == tuple.Ifindex || attrs.Index == tuple.MasterIndex ||
				attrs.Name == tuple.Name || attrs.MasterIndex == tuple.Ifindex {
				return true
			}
		}
	}
	// A relevant-kind update without an authoritative current snapshot is
	// conservative: it may be a newly-created xfrmi or its bridge/VRF master.
	// Once the snapshot generation is current for the permit, unmatched
	// bridge/VRF IDs are proven-irrelevant noise and take census-only.
	switch update.Link.Type() {
	case "xfrm":
		return true
	case "bridge", "vrf":
		return !snapshotCurrent
	default:
		return false
	}
}

// noteIpsecTopologyLinkTransition is the immediate fail-closed path for every
// relevant link event. The subsequent census establishes the new immutable
// tuple, but a transient delete/recreate or master detach must revoke even
// when the final census happens to equal the previous one.
func (d *Daemon) noteIpsecTopologyLinkTransition() {
	if d == nil || d.ipsecS4 == nil {
		return
	}
	d.ipsecTopologyDirty.Store(true)
	permit := d.ipsecS4.loadPermit()
	if permit == nil || permit.state == ipsecPermitClosed {
		return
	}
	key := permit.closeRequestKey
	key.Ready = ipsecReadyUnknown
	key.Tuples = append([]ipsecTopologyTuple(nil), key.Tuples...)
	seq := d.ipsecS4.allocCloseEventSeqAfter(permit.closeRequestSeq)
	d.ipsecS4.revokeTransitPermitNonblocking(ipsecTopologyEvent{Seq: seq, Key: key})
}

// pollIpsecTopology is the Go-side owner for the permit/watch publication. It
// converts the current kernel xfrmi census into the immutable tuple used by
// the permit record; unknown netlink state is conservative and never opens a
// permit. A changed census publishes a new generation, which pre-revokes an
// OPEN permit before the host-fence reconciler sees it.
func (d *Daemon) pollIpsecTopology() {
	if d == nil || d.ipsecS4 == nil {
		return
	}
	ready := ipsecReadyUnknown
	if d.ipsecTopologySubscribed.Load() {
		ready = ipsecReadySafe
	}
	var tuples []ipsecTopologyTuple
	links, err := ipsecTopologyLinkList()
	if err != nil {
		ready = ipsecReadyUnknown
	} else {
		d.ipsecCaptureMu.Lock()
		installed := d.ipsecCapture
		d.ipsecCaptureMu.Unlock()
		tuples, ready = classifyIpsecTopologyLinksWithInstalled(links, ready, installed)
	}
	current := d.ipsecS4.watch.Load()
	dirty := d.ipsecTopologyDirty.Load()
	generation := uint64(1)
	if current != nil {
		generation = current.Generation
		if !dirty && current.Ready == ready &&
			makeCloseRequestKey(current.Ready, current.Generation, tuples).equal(current.closeKey()) {
			return
		}
		generation++
	}
	snapshot := &TransitWatchSnapshot{Generation: generation, Ready: ready, Tuples: tuples}
	if d.ipsecS4.publishWatchSnapshot(snapshot) {
		d.ipsecTopologyDirty.Store(false)
	}
}

// classifyIpsecTopologyLinksWithInstalled is classifyIpsecTopologyLinks
// plus the #16420 installed-divert comparison: when an installed divert
// runtime is supplied, a VRF-enslaved xfrmi whose live master differs from
// the divert's Master for that tunnel (including an iifname-only divert
// with Master=="") is UNSAFE, so the permit cannot OPEN on a stale divert
// that will never match enslaved traffic. A nil installed runtime keeps
// the legacy behaviour (no comparison possible).
func classifyIpsecTopologyLinksWithInstalled(links []netlink.Link, ready ipsecReadyResult, installed *ipsecCaptureRuntime) ([]ipsecTopologyTuple, ipsecReadyResult) {
	tuples, ready := classifyIpsecTopologyLinks(links, ready)
	if installed == nil {
		return tuples, ready
	}
	for _, tuple := range tuples {
		if tuple.Kind != "xfrmi" || tuple.MasterIndex == 0 {
			continue
		}
		masterLink, err := ipsecFenceLinkByIndex(tuple.MasterIndex)
		if err != nil || masterLink == nil || masterLink.Attrs() == nil || masterLink.Attrs().Name == "" {
			continue // classify already marked this UNKNOWN
		}
		liveMaster := masterLink.Attrs().Name
		installedMaster, found := installedMasterForTunnel(installed, tuple.Name)
		if !found {
			continue
		}
		if installedMaster != liveMaster {
			ready = ipsecReadyUnsafe
		}
	}
	return tuples, ready
}

// installedMasterForTunnel returns the Master carried by the installed
// divert for the tunnel whose xfrmi device is tunnelName. STN is the
// authored bind ref (st0.0 or st0); the census Name is the device name,
// which XFRMIfNameAndID derives from the bind.
func installedMasterForTunnel(rt *ipsecCaptureRuntime, tunnelName string) (string, bool) {
	if rt == nil {
		return "", false
	}
	for _, h := range rt.handles {
		dev, _ := config.XFRMIfNameAndID(h.Key.STN)
		if dev == tunnelName {
			return h.Key.Master, true
		}
	}
	return "", false
}

func classifyIpsecTopologyLinks(links []netlink.Link, ready ipsecReadyResult) ([]ipsecTopologyTuple, ipsecReadyResult) {
	var tuples []ipsecTopologyTuple
	outletFound := false
	outletUnsafe := false
	for _, link := range links {
		attrs := link.Attrs()
		if attrs == nil {
			ready = ipsecReadyUnknown
			continue
		}
		if attrs.Name == xnft.HostInboundDelegatedIfname {
			outletFound = true
			tuples = append(tuples, ipsecTopologyTuple{
				Kind:        "outlet",
				Ifindex:     attrs.Index,
				MasterIndex: attrs.MasterIndex,
				Name:        attrs.Name,
				Owner:       "kernel",
			})
			if link.Type() != "tuntap" {
				ready = ipsecReadyUnknown
			}
			if attrs.MasterIndex != 0 {
				outletUnsafe = true
			}
		}
		if link.Type() != "xfrm" {
			continue
		}
		tuple := ipsecTopologyTuple{
			Kind:        "xfrmi",
			Ifindex:     attrs.Index,
			MasterIndex: attrs.MasterIndex,
			Name:        attrs.Name,
			Owner:       "kernel",
		}
		tuples = append(tuples, tuple)
		if attrs.MasterIndex == 0 {
			continue
		}
		master, err := ipsecFenceLinkByIndex(attrs.MasterIndex)
		if err != nil || master == nil || master.Attrs() == nil || master.Type() == "" {
			ready = ipsecReadyUnknown
			continue
		}
		switch master.Type() {
		case "vrf":
			// #15067 (A35-02): a VRF-enslaved xfrmi is a supported
			// topology. The divert matches it by iifname=master +
			// sdifname=tunnel and the host-input fence drops only
			// that (master, slave) pair (#14974), so co-members such
			// as ge-0-0-3 keep their host-inbound path. Marking it
			// UNSAFE kept the permit from ever OPENing, and the
			// fence (retired only on the OPEN path) then dropped
			// tunnel-arriving host traffic forever. Leave ready
			// unchanged (SAFE when subscribed).
		case "bridge":
			ready = ipsecReadyUnsafe
		default:
			// A supported xfrmi is masterless or VRF-enslaved. Any
			// other resolved master is an unsupported route domain
			// and must not reach OPEN.
			ready = ipsecReadyUnsafe
		}
	}
	if !outletFound {
		ready = ipsecReadyUnknown
	} else if outletUnsafe {
		ready = ipsecReadyUnsafe
	}
	return tuples, ready
}
