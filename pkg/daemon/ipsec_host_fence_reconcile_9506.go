package daemon

import (
	"context"
	"fmt"
	"sort"
	"time"

	xnft "github.com/psaab/xpf/pkg/nftables"
	"github.com/vishvananda/netlink"
)

var ipsecFenceLinkByIndex = netlink.LinkByIndex

// ipsecHostInputFenceOverlay derives the iifname-only candidate from the
// immutable permit record. MasterIndex is resolved at reconciliation time so
// route/master renames cannot leave an overlay attached to an old name.
func (d *Daemon) ipsecHostInputFenceOverlay() (*xnft.HostInputFenceOverlay, error) {
	if d == nil || d.ipsecS4 == nil {
		return nil, nil
	}
	return d.ipsecHostInputFenceOverlayForPermit(d.ipsecS4.loadPermit())
}

func (d *Daemon) ipsecHostInputFenceOverlayForPermit(permit *permitRecord) (*xnft.HostInputFenceOverlay, error) {
	if permit == nil {
		return nil, nil
	}
	masters := make([]string, 0, len(permit.closeRequestKey.Tuples))
	seenIndex := map[int]string{}
	for _, tuple := range permit.closeRequestKey.Tuples {
		if tuple.Kind != "xfrmi" {
			continue
		}
		name := tuple.Name
		if tuple.MasterIndex > 0 {
			link, err := ipsecFenceLinkByIndex(tuple.MasterIndex)
			if err != nil || link == nil || link.Attrs() == nil || link.Attrs().Name == "" {
				if err == nil {
					err = fmt.Errorf("link missing")
				}
				return nil, fmt.Errorf("resolve xfrmi master index %d: %w", tuple.MasterIndex, err)
			}
			name = link.Attrs().Name
			if prior, ok := seenIndex[tuple.MasterIndex]; ok && prior != name {
				return nil, fmt.Errorf("master index %d resolved ambiguously as %q and %q", tuple.MasterIndex, prior, name)
			}
			seenIndex[tuple.MasterIndex] = name
		}
		if name == "" {
			return nil, fmt.Errorf("xfrmi tuple has no interface name")
		}
		masters = append(masters, name)
	}
	sort.Strings(masters)
	uniq := masters[:0]
	for _, name := range masters {
		if len(uniq) == 0 || uniq[len(uniq)-1] != name {
			uniq = append(uniq, name)
		}
	}
	return &xnft.HostInputFenceOverlay{
		MasterSet:       uniq,
		Generation:      permit.watchGeneration,
		PermitEpoch:     permit.permitEpoch,
		CloseRequestSeq: permit.closeRequestSeq,
		CloseRequestKey: fmt.Sprintf("%d/%d/%v", permit.closeRequestKey.Ready, permit.closeRequestKey.WatchGeneration, permit.closeRequestKey.Tuples),
		WatchGeneration: permit.watchGeneration,
		State:           permit.state.String(),
	}, nil
}

func sameHostInputFenceOverlay(a, b *xnft.HostInputFenceOverlay) bool {
	if a == nil || b == nil {
		return a == b
	}
	a = func() *xnft.HostInputFenceOverlay {
		v := xnft.CanonicalHostInputFenceOverlay(*a)
		return &v
	}()
	b = func() *xnft.HostInputFenceOverlay {
		v := xnft.CanonicalHostInputFenceOverlay(*b)
		return &v
	}()
	if a.Generation != b.Generation || a.PermitEpoch != b.PermitEpoch ||
		a.CloseRequestSeq != b.CloseRequestSeq || a.CloseRequestKey != b.CloseRequestKey ||
		a.WatchGeneration != b.WatchGeneration || a.State != b.State ||
		len(a.MasterSet) != len(b.MasterSet) {
		return false
	}
	for i := range a.MasterSet {
		if a.MasterSet[i] != b.MasterSet[i] {
			return false
		}
	}
	return true
}
func hostInputFenceOverlayAuthorityMatches(o *xnft.HostInputFenceOverlay, permit *permitRecord) bool {
	if o == nil || permit == nil {
		return false
	}
	return o.Generation == permit.watchGeneration &&
		o.PermitEpoch == permit.permitEpoch &&
		o.CloseRequestSeq == permit.closeRequestSeq &&
		o.WatchGeneration == permit.watchGeneration &&
		o.State == permit.state.String() &&
		o.CloseRequestKey == fmt.Sprintf("%d/%d/%v", permit.closeRequestKey.Ready, permit.closeRequestKey.WatchGeneration, permit.closeRequestKey.Tuples)
}
func (d *Daemon) tryOpenIpsecPermitAfterFenceAck(permit *permitRecord) {
	if d == nil || d.ipsecS4 == nil || permit == nil ||
		permit.state != ipsecPermitClosing || permit.closeRequestKey.Ready != ipsecReadySafe ||
		d.HostInputFenceConntrackRevocationOwed() {
		return
	}
	if d.ipsecCaptureRemovalPending.Load() {
		return
	}
	d.ipsecCaptureMu.Lock()
	divertActive := d.ipsecCapture != nil
	d.ipsecCaptureMu.Unlock()
	if !divertActive {
		return
	}
	_ = d.ipsecS4.tryOpenPermit(permit, permit.closeRequestKey, permit.watchGeneration)
}

// ipsecDivertSpecMasters9506 collects the xfrmi ifnames from a divert spec's
// four hook classes. The fence hold unions these with the live census so a
// census lag cannot leave a configured tunnel unfenced across a transition.
func ipsecDivertSpecMasters9506(spec xnft.IpsecDivertSpec) []string {
	var out []string
	for _, rules := range [][]xnft.IpsecDivertRule{spec.InetForward, spec.InetInput, spec.BridgeForward, spec.BridgeInput} {
		for _, r := range rules {
			if r.Ifname != "" {
				out = append(out, r.Ifname)
			}
		}
	}
	return out
}

// holdIpsecHostInputFenceForDivertTransition installs and acknowledges a DROP
// covering the live xfrmi plus every ifname in the divert being removed.
// Removing the divert while its permit is OPEN and the overlay has retired
// leaves neither authority. The hold revokes to CLOSING before any nft mutation
// and publishes the overlay only after host-inbound install/readback succeeds.
//
// Callers serialize against the reconciler: commit paths hold applySem and
// shutdown runs after the supervisor loop joins. This helper does not acquire
// applySem itself.
func (d *Daemon) holdIpsecHostInputFenceForDivertTransition(extraMasters []string) error {
	if d == nil || nftInstaller == nil {
		return fmt.Errorf("host-input fence hold requires daemon and nftables installer")
	}
	if d.ipsecS4 == nil {
		if len(extraMasters) == 0 {
			return nil
		}
		return fmt.Errorf("host-input fence hold requires IPsec supervisor")
	}
	permit := d.ipsecS4.loadPermit()
	if permit == nil {
		if len(extraMasters) == 0 {
			return nil
		}
		return fmt.Errorf("host-input fence hold requires permit authority")
	}
	if permit.state == ipsecPermitOpen {
		// Retain the exact OPEN authority sampled above. If a watcher CAS wins
		// first, leave the divert in place and let the next serialized pass
		// reconcile that newer generation instead of fencing a stale census.
		expected := permit
		revoked, prior := d.ipsecS4.revokeTransitPermitNonblocking(ipsecTopologyEvent{
			Key: expected.closeRequestKey,
		})
		if prior != expected {
			return fmt.Errorf("host-input fence hold permit changed before OPEN-to-CLOSING transition")
		}
		permit = revoked
	}
	if permit == nil || permit.state != ipsecPermitClosing {
		state := ipsecPermitClosed
		if permit != nil {
			state = permit.state
		}
		return fmt.Errorf("host-input fence hold requires CLOSING permit, got %v", state)
	}
	if d.ipsecS4.loadPermit() != permit {
		return fmt.Errorf("host-input fence hold permit changed before overlay derivation")
	}
	desired, err := d.ipsecHostInputFenceOverlayForPermit(permit)
	if err != nil {
		return fmt.Errorf("derive host-input fence overlay: %w", err)
	}
	if desired == nil {
		return nil
	}
	if len(extraMasters) > 0 {
		desired.MasterSet = append(append([]string(nil), desired.MasterSet...), extraMasters...)
		canon := xnft.CanonicalHostInputFenceOverlay(*desired)
		desired = &canon
	}
	if len(desired.MasterSet) == 0 {
		return nil
	}
	if sameHostInputFenceOverlay(d.activeHostInputFenceOverlay(), desired) &&
		hostInputFenceOverlayAuthorityMatches(d.ipsecOverlayAcked.Load(), permit) {
		// A prior ACK is not enough after a destructive operation can fail
		// ambiguously. Read the exact live marker/rule again before reusing it.
		if d.ipsecS4.loadPermit() != permit {
			return fmt.Errorf("host-input fence hold permit changed before overlay readback")
		}
		if err := nftInstaller.VerifyHostInboundOverlay(*desired); err == nil {
			if d.ipsecS4.loadPermit() != permit {
				return fmt.Errorf("host-input fence hold permit changed during overlay readback")
			}
			return nil
		}
		// Re-install below; an old ACK cannot authorize divert removal when
		// live kernel readback no longer proves this exact generation.
	}
	if d.store == nil {
		return fmt.Errorf("host-input fence hold requires config store")
	}
	cfg := d.store.ActiveConfig()
	if cfg == nil {
		return fmt.Errorf("host-input fence hold requires active config")
	}
	d.ipsecS4.drainCommitLeases()
	if err := d.applyHostInboundFilterWithOverlay(cfg, desired); err != nil {
		return fmt.Errorf("install host-input fence before divert transition: %w", err)
	}
	if d.ipsecS4.loadPermit() != permit {
		return fmt.Errorf("host-input fence hold permit changed during overlay install/readback")
	}
	d.ipsecOverlay.Store(desired)
	d.ipsecOverlayAcked.Store(desired)
	d.ipsecOverlayRetryGeneration.Store(0)
	d.ipsecOverlayRetrySequence.Store(0)
	d.ipsecOverlayRetryUntil.Store(0)
	return nil
}

// reconcileIpsecHostInputFence is the production owner that turns permit
// transitions into the kernel overlay. It is called by the joined S4
// supervisor loop and serializes nft install/retire through applySem.
func (d *Daemon) reconcileIpsecHostInputFence(ctx context.Context) {
	if d == nil || d.ipsecS4 == nil || d.store == nil || d.applySem == nil {
		return
	}
	permit := d.ipsecS4.loadPermit()
	if permit == nil {
		return
	}
	if permit.state == ipsecPermitClosing &&
		hostInputFenceOverlayAuthorityMatches(d.ipsecOverlayAcked.Load(), permit) &&
		(permit.closeRequestKey.Ready != ipsecReadySafe || d.HostInputFenceConntrackRevocationOwed()) {
		return
	}
	if permit.state == ipsecPermitOpen && d.ipsecOverlay.Load() == nil {
		return
	}
	if err := d.applySem.Acquire(ctx, 1); err != nil {
		return
	}
	defer d.applySem.Release(1)

	permit = d.ipsecS4.loadPermit()
	if permit == nil {
		return
	}
	now := time.Now()
	if d.ipsecOverlayRetryGeneration.Load() == permit.watchGeneration &&
		d.ipsecOverlayRetrySequence.Load() == permit.closeRequestSeq &&
		d.ipsecOverlayRetryUntil.Load() > now.UnixNano() {
		return
	}
	active := d.activeHostInputFenceOverlay()
	if permit.state == ipsecPermitClosing &&
		hostInputFenceOverlayAuthorityMatches(d.ipsecOverlayAcked.Load(), permit) {
		d.tryOpenIpsecPermitAfterFenceAck(permit)
		return
	}
	restore := func(old *xnft.HostInputFenceOverlay) {
		if old == nil {
			d.ipsecOverlay.Store(nil)
			d.ipsecOverlayAcked.Store(nil)
			return
		}
		d.setHostInputFenceOverlay(old)
	}
	markRetry := func() {
		d.ipsecOverlayRetryGeneration.Store(permit.watchGeneration)
		d.ipsecOverlayRetrySequence.Store(permit.closeRequestSeq)
		d.ipsecOverlayRetryUntil.Store(time.Now().Add(250 * time.Millisecond).UnixNano())
	}
	clearRetry := func() {
		d.ipsecOverlayRetryGeneration.Store(0)
		d.ipsecOverlayRetrySequence.Store(0)
		d.ipsecOverlayRetryUntil.Store(0)
	}

	if permit.state == ipsecPermitOpen {
		if active == nil {
			return
		}
		if cfg := d.store.ActiveConfig(); cfg != nil {
			if err := d.retireHostInputFenceOverlay(cfg, permit); err != nil {
				markRetry()
				return
			}
		}
		clearRetry()
		return
	}
	if permit.state != ipsecPermitClosing {
		return
	}
	d.ipsecS4.drainCommitLeases()
	desired, err := d.ipsecHostInputFenceOverlayForPermit(permit)
	if err != nil {
		markRetry()
		return
	}
	if desired == nil {
		return
	}
	if len(desired.MasterSet) == 0 {
		// No xfrmi master is resolvable in this authority record. Retain any
		// previously installed fence (overfence) and ACK only the empty
		// authority; the OPEN retire path is the sole detach owner.
		d.ipsecOverlayAcked.Store(desired)
		clearRetry()
		d.tryOpenIpsecPermitAfterFenceAck(permit)
		return
	}
	if sameHostInputFenceOverlay(active, desired) &&
		hostInputFenceOverlayAuthorityMatches(d.ipsecOverlayAcked.Load(), permit) {
		d.tryOpenIpsecPermitAfterFenceAck(permit)
		return
	}
	// Keep the candidate private until install and exact readback succeed.
	cfg := d.store.ActiveConfig()
	if cfg == nil {
		restore(active)
		return
	}
	if err := d.applyHostInboundFilterWithOverlay(cfg, desired); err != nil {
		// Candidate verification failures can happen after an atomic table
		// replacement. With no prior verified overlay, retain the candidate
		// fence and retry it; never fall back to the ordinary un-fenced table.
		fallback := active
		if fallback == nil {
			fallback = desired
		}
		restore(fallback)
		if restoreErr := d.applyHostInboundFilter(cfg); restoreErr != nil {
			markRetry()
			return
		}
		d.ipsecOverlayAcked.Store(fallback)
		markRetry()
		return
	}
	d.ipsecOverlay.Store(desired)
	d.ipsecOverlayAcked.Store(desired)
	clearRetry()
	d.tryOpenIpsecPermitAfterFenceAck(permit)
}
