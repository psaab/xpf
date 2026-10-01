package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

var rxVlanAuditInterval = 10 * time.Second

var (
	rxVlanAuditLinkByName    = netlink.LinkByName
	rxVlanAuditLinkSetDown   = netlink.LinkSetDown
	rxVlanAuditLinkSubscribe = defaultLinkStateSubscribe
)

type rxVlanAuditState struct {
	quarantined           map[string]bool
	forcedDown            map[string]bool
	transitSuppressed     bool
	restoreDataplaneArmed bool
}

func newRxVlanAuditState() *rxVlanAuditState {
	return &rxVlanAuditState{
		quarantined: make(map[string]bool),
		forcedDown:  make(map[string]bool),
	}
}

func (d *Daemon) startRxVlanAuditLoop(ctx context.Context, wg *sync.WaitGroup) {
	if d == nil || ctx == nil || wg == nil {
		return
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		d.rxVlanAuditLoop(ctx)
	}()
}

func (d *Daemon) rxVlanAuditLoop(ctx context.Context) {
	state := newRxVlanAuditState()
	for {
		if !d.runRxVlanAuditLinkSubscription(ctx, state) {
			return
		}
		timer := time.NewTimer(linkStateResubBackoffDefault)
		select {
		case <-ctx.Done():
			_ = timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func (d *Daemon) runRxVlanAuditLinkSubscription(ctx context.Context, state *rxVlanAuditState) bool {
	if state == nil {
		state = newRxVlanAuditState()
	}
	updates := make(chan netlink.LinkUpdate, 64)
	done := make(chan struct{})
	onErr := func(err error) {
		slog.Warn("rxvlan audit: netlink receive error, resubscribing", "err", err)
	}
	subscribe := rxVlanAuditLinkSubscribe
	if subscribe == nil {
		subscribe = defaultLinkStateSubscribe
	}
	if err := subscribe(updates, done, onErr); err != nil {
		slog.Warn("rxvlan audit: link subscription failed", "err", err)
		close(done)
		_ = d.rxVlanAuditOnce(ctx, "", state)
		return true
	}
	defer close(done)

	_ = d.rxVlanAuditOnce(ctx, "", state)
	ticker := time.NewTicker(rxVlanAuditInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return false
		case <-ticker.C:
			_ = d.rxVlanAuditOnce(ctx, "", state)
		case update, ok := <-updates:
			if !ok {
				_ = d.rxVlanAuditOnce(ctx, "", state)
				return true
			}
			if update.Header.Type != unix.RTM_NEWLINK {
				continue
			}
			attrs := update.Attrs()
			if attrs == nil || attrs.Name == "" || attrs.Flags&net.FlagUp == 0 {
				continue
			}
			name := attrs.Name
			if state.transitSuppressed {
				name = ""
			}
			_ = d.rxVlanAuditOnce(ctx, name, state)
		}
	}
}

// rxVlanParentNames mirrors the compiler's physical-parent selection: a
// VLAN-bearing RETH maps to this node's selected physical member, and a
// physical member uses the RETH's effective VLAN units. Standalone VLAN trunks
// remain their own parents.
func rxVlanParentNames(cfg *config.Config) []string {
	if cfg == nil || cfg.Interfaces.Interfaces == nil {
		return nil
	}
	rethToPhysical := cfg.RethToPhysical()
	parents := make(map[string]struct{})
	add := func(name string) {
		if name != "" {
			parents[config.LinuxIfName(name)] = struct{}{}
		}
	}
	for name, iface := range cfg.Interfaces.Interfaces {
		if iface == nil {
			continue
		}
		if physical, isReth := rethToPhysical[name]; isReth {
			if config.InterfaceHasVlanSubinterface(iface) {
				add(physical)
			}
			continue
		}
		if iface.RedundantParent != "" {
			physical, local := rethToPhysical[iface.RedundantParent]
			if !local || physical != name {
				continue
			}
			reth := cfg.Interfaces.Interfaces[iface.RedundantParent]
			if config.InterfaceHasVlanSubinterface(reth) {
				add(name)
			}
			continue
		}
		if iface.RedundancyGroup != 0 || strings.HasPrefix(name, "reth") {
			continue
		}
		if config.InterfaceHasVlanSubinterface(iface) {
			add(name)
		}
	}
	out := make([]string, 0, len(parents))
	for name := range parents {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func (d *Daemon) rxVlanAuditParents(ctx context.Context) ([]string, error) {
	if d == nil || d.store == nil || d.applySem == nil {
		return nil, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := d.applySem.Acquire(ctx, 1); err != nil {
		return nil, err
	}
	defer d.applySem.Release(1)

	parents := d.rxVlanAuditParentsLocked()
	out := make([]string, 0, len(parents))
	for name := range parents {
		out = append(out, name)
	}
	sort.Strings(out)
	return out, nil
}

func (d *Daemon) rxVlanAuditOnce(ctx context.Context, onlyName string, state *rxVlanAuditState) error {
	if d == nil || d.store == nil || d.applySem == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if state == nil {
		state = newRxVlanAuditState()
	}
	parents, err := d.rxVlanAuditParents(ctx)
	if err != nil {
		return err
	}
	var auditErr error
	allSafe := true
	for _, parent := range parents {
		if onlyName != "" && onlyName != parent {
			continue
		}
		link, err := rxVlanAuditLinkByName(parent)
		if err != nil {
			slog.Warn("rxvlan audit: configured VLAN parent is not present", "iface", parent, "err", err)
			if state.transitSuppressed {
				allSafe = false
			}
			continue
		}
		attrs := link.Attrs()
		if attrs == nil || attrs.Index <= 0 {
			auditErr = errors.Join(auditErr,
				fmt.Errorf("rxvlan audit: %s has no valid link index", parent))
			allSafe = false
			continue
		}
		if state.transitSuppressed && attrs.Flags&net.FlagUp == 0 {
			allSafe = false
		}

		attached, attachmentKnown := rxVlanXDPAttached(d.dataplane(), attrs.Index)
		alreadyQuarantined := state.quarantined[parent] && attachmentKnown && !attached && !state.forcedDown[parent]
		if attached {
			delete(state.quarantined, parent)
		}

		out, queryErr := runCommandTimeout("ethtool", "-k", parent)
		offloadState := dataplane.ClassifyRxVlanOffload(out, queryErr)
		if offloadState == dataplane.RxVlanOffloadOff || offloadState == dataplane.RxVlanOffloadAbsent {
			if state.forcedDown[parent] {
				if attrs.Flags&net.FlagUp != 0 {
					delete(state.forcedDown, parent)
				} else {
					allSafe = false
				}
			}
			continue
		}

		_, disableErr := runCommandTimeout("ethtool", "-K", parent, "rxvlan", "off")
		if disableErr == nil {
			if state.forcedDown[parent] {
				if attrs.Flags&net.FlagUp != 0 {
					delete(state.forcedDown, parent)
				} else {
					allSafe = false
				}
			}
			continue
		}

		if alreadyQuarantined {
			allSafe = false
			slog.Error("rxvlan offload remains enabled on an already quarantined VLAN parent",
				"iface", parent, "query_err", queryErr, "disable_err", disableErr)
			auditErr = errors.Join(auditErr,
				fmt.Errorf("rxvlan parent %s: disable failed: %w", parent, disableErr))
			continue
		}

		quarantined, quarantineErr := d.quarantineRxVlanBinding(ctx, parent, state)
		if quarantined {
			if !state.forcedDown[parent] {
				state.quarantined[parent] = true
			}
			if state.transitSuppressed {
				allSafe = false
			}
			slog.Error("rxvlan offload could not be disabled; VLAN parent bind quarantined",
				"iface", parent, "query_err", queryErr, "disable_err", disableErr,
				"quarantine_err", quarantineErr)
		} else {
			allSafe = false
			slog.Error("rxvlan offload could not be disabled and VLAN parent bind is not quarantined",
				"iface", parent, "query_err", queryErr, "disable_err", disableErr,
				"quarantine_err", quarantineErr)
		}
		auditErr = errors.Join(auditErr,
			fmt.Errorf("rxvlan parent %s: disable failed: %w", parent, disableErr))
		if quarantineErr != nil {
			auditErr = errors.Join(auditErr, quarantineErr)
		}
	}
	if onlyName == "" && state.transitSuppressed && allSafe {
		state.transitSuppressed = false
		state.forcedDown = make(map[string]bool)
		if state.restoreDataplaneArmed {
			d.markDataplaneArmed("rxvlan-audit-recovery")
		}
		state.restoreDataplaneArmed = false
	}
	return auditErr
}

func (d *Daemon) quarantineRxVlanBinding(ctx context.Context, parent string, state *rxVlanAuditState) (bool, error) {
	if d == nil || d.applySem == nil {
		return false, errors.New("rxvlan quarantine: apply semaphore unavailable")
	}
	if state == nil {
		state = newRxVlanAuditState()
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := d.applySem.Acquire(ctx, 1); err != nil {
		return false, fmt.Errorf("rxvlan quarantine: acquire apply semaphore: %w", err)
	}
	defer d.applySem.Release(1)

	current := d.rxVlanAuditParentsLocked()
	if !current[parent] {
		return false, nil
	}
	link, err := rxVlanAuditLinkByName(parent)
	if err != nil {
		return false, fmt.Errorf("rxvlan quarantine: lookup %s: %w", parent, err)
	}
	attrs := link.Attrs()
	if attrs == nil || attrs.Index <= 0 {
		return false, fmt.Errorf("rxvlan quarantine: %s has no valid link index", parent)
	}
	if !d.shouldManageTransitGate() {
		return false, errors.New("rxvlan quarantine: daemon does not own the transit gate")
	}

	if !state.transitSuppressed {
		state.restoreDataplaneArmed = d.dataplaneArmed.Load()
	}

	d.transitGateMu.Lock()
	defer d.transitGateMu.Unlock()
	var barrierErr error
	if nftInstaller == nil {
		barrierErr = errors.New("nft transit barrier installer unavailable")
	} else {
		barrierErr = d.applyTransitBarrier(false)
	}
	writeTransitForwardSysctls(false)
	if barrierErr != nil {
		// The old allowlist may still contain this ifname. Never detach before
		// the unconditional barrier is installed; isolate the physical parent
		// and keep the daemon unarmed if that closeout cannot be established.
		d.dataplaneArmed.Store(false)
		d.applyDataplaneReadyTrack(false)
		state.transitSuppressed = true
		downErr := rxVlanAuditLinkSetDown(link)
		if downErr == nil {
			state.forcedDown[parent] = true
			return true, fmt.Errorf("rxvlan quarantine: barrier install failed; %s administratively down: %w", parent, barrierErr)
		}
		return false, errors.Join(fmt.Errorf("rxvlan quarantine: barrier install failed: %w", barrierErr),
			fmt.Errorf("rxvlan quarantine: LinkSetDown(%s): %w", parent, downErr))
	}
	d.applyDataplaneReadyTrack(false)

	backend := dataplane.Unwrap(d.dataplane())
	detacher, ok := backend.(interface{ DetachXDP(int) error })
	if !ok {
		d.dataplaneArmed.Store(false)
		d.applyDataplaneReadyTrack(false)
		state.transitSuppressed = true
		return true, errors.New("rxvlan quarantine: dataplane has no XDP detach capability; transit remains closed")
	}
	detachErr := detacher.DetachXDP(attrs.Index)
	attached, known := rxVlanXDPAttached(backend, attrs.Index)
	if detachErr != nil && (!known || attached) {
		d.dataplaneArmed.Store(false)
		d.applyDataplaneReadyTrack(false)
		state.transitSuppressed = true
		return true, fmt.Errorf("rxvlan quarantine: detach %s failed and transit remains closed: %w", parent, detachErr)
	}
	if detachErr == nil && known && attached {
		d.dataplaneArmed.Store(false)
		d.applyDataplaneReadyTrack(false)
		state.transitSuppressed = true
		return true, fmt.Errorf("rxvlan quarantine: detach %s returned success but the XDP census still includes ifindex %d; transit remains closed",
			parent, attrs.Index)
	}

	ready := d.dataplaneArmed.Load() && d.attachedXDPLinks() > 0
	opened := d.writeTransitGateLocked("rxvlan-audit", ready)
	d.applyDataplaneReadyTrack(opened)
	if detachErr != nil {
		return true, fmt.Errorf("rxvlan quarantine: %s removed from XDP census despite detach error: %w", parent, detachErr)
	}
	if ready && !opened {
		return true, fmt.Errorf("rxvlan quarantine: %s detached; transit remains closed while the remaining fence is retried", parent)
	}
	return true, nil
}

// rxVlanAuditParentsLocked requires d.applySem and includes both the promoted
// config and the last successfully applied parent set. A failed replacement
// can leave the prior dataplane snapshot live (#5679).
func (d *Daemon) rxVlanAuditParentsLocked() map[string]bool {
	if d == nil || d.store == nil {
		return nil
	}
	parents := make(map[string]bool)
	for _, name := range rxVlanParentNames(d.store.ActiveConfig()) {
		parents[name] = true
	}
	appliedParents := d.rxVlanAppliedParents
	if provider, ok := dataplane.Unwrap(d.dataplane()).(interface {
		AppliedConfig() *config.Config
	}); ok {
		if applied := provider.AppliedConfig(); applied != nil {
			// The helper may finish a deferred snapshot outside ApplyConfig;
			// its applied config is authoritative when available.
			appliedParents = make(map[string]struct{})
			for _, name := range rxVlanParentNames(applied) {
				appliedParents[name] = struct{}{}
			}
		}
	}
	for name := range appliedParents {
		parents[name] = true
	}
	return parents
}

func rxVlanXDPAttached(provider any, ifindex int) (bool, bool) {
	backend := dataplane.Unwrap(provider)
	census, ok := backend.(interface{ AttachedXDPIfindexes() []int })
	if !ok {
		return false, false
	}
	for _, attached := range census.AttachedXDPIfindexes() {
		if attached == ifindex {
			return true, true
		}
	}
	return false, true
}

// retainRxVlanAppliedParents records which physical VLAN parents can still be
// governed by the dataplane. Failed/deferred replacements retain both sides;
// only a complete apply drops parents from the previous accepted snapshot.
func (d *Daemon) retainRxVlanAppliedParents(cfg *config.Config, complete bool) {
	rt := d.dataplane()
	if rt == nil || cfg == nil {
		return
	}
	next := make(map[string]struct{})
	if !complete {
		for parent := range d.rxVlanAppliedParents {
			next[parent] = struct{}{}
		}
	}
	for _, parent := range rxVlanParentNames(cfg) {
		next[parent] = struct{}{}
	}
	d.rxVlanAppliedParents = next
}
