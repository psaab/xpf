package daemon

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	xnft "github.com/psaab/xpf/pkg/nftables"
)

// hostInputFenceConntrackFilter is deliberately separate from the ordinary
// denied-service reconcile. An input-fence overlay revokes every direct-host
// flow to the captured local destinations, including services the ordinary
// host-inbound policy would otherwise permit.
type hostInputFenceConntrackFilter struct {
	destinations map[netip.Addr]struct{}
}

func (f *hostInputFenceConntrackFilter) MatchConntrackFlow(flow *netlink.ConntrackFlow) bool {
	if f == nil || flow == nil {
		return false
	}
	dst, ok := netip.AddrFromSlice(flow.Forward.DstIP)
	if !ok {
		return false
	}
	_, ok = f.destinations[dst.Unmap()]
	return ok
}

// hostInputFenceAllLocalAddrs is the complete kernel-local address census,
// including dynamic addresses and lifeline interfaces omitted by the ordinary
// host-inbound view builders. Tests replace it with a deterministic snapshot.
var hostInputFenceAllLocalAddrs = func() ([]string, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, err
	}
	var out []string
	for _, link := range links {
		for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
			addrs, err := netlink.AddrList(link, family)
			if err != nil {
				return nil, err
			}
			for _, addr := range addrs {
				if addr.IP != nil {
					out = append(out, addr.IP.String())
				}
			}
		}
	}
	return out, nil
}

// hostInputFenceConntrackRequest is the immutable revocation identity. The
// authority fields make retry debt auditable and prevent a retry from silently
// applying a newer overlay's destination set.
type hostInputFenceConntrackRequest struct {
	destinations    []string
	generation      uint64
	permitEpoch     uint64
	closeRequestSeq uint64
	closeRequestKey string
	watchGeneration uint64
	state           string
}

// A separate seam is required: overlay revocation must never be accidentally
// replaced by the narrower ordinary host-inbound reconcile filter.
var hostInputFenceConntrackDeleteFilters = func(family netlink.InetFamily, filters ...netlink.CustomConntrackFilter) (uint, error) {
	return netlink.ConntrackDeleteFilters(netlink.ConntrackTable, family, filters...)
}

func canonicalHostInputFenceDestinations(addrs []string) []string {
	seen := make(map[string]struct{}, len(addrs))
	out := make([]string, 0, len(addrs))
	for _, raw := range addrs {
		addr, err := netip.ParseAddr(raw)
		if err != nil {
			continue
		}
		key := addr.Unmap().String()
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

func buildHostInputFenceConntrackFilter(destinations []string) *hostInputFenceConntrackFilter {
	parsed := make(map[netip.Addr]struct{}, len(destinations))
	for _, raw := range destinations {
		addr, err := netip.ParseAddr(raw)
		if err != nil {
			continue
		}
		parsed[addr.Unmap()] = struct{}{}
	}
	if len(parsed) == 0 {
		return nil
	}
	return &hostInputFenceConntrackFilter{destinations: parsed}
}

func hostInputFenceConntrackDestinations(cfg *config.Config, views []dpuserspace.ZoneHostInboundView, unzonedV4, unzonedV6 []string) ([]string, error) {
	addrs := make([]string, 0, len(unzonedV4)+len(unzonedV6))
	addrs = append(addrs, unzonedV4...)
	addrs = append(addrs, unzonedV6...)
	for _, view := range views {
		addrs = append(addrs, view.V4Addrs...)
		addrs = append(addrs, view.V6Addrs...)
	}
	if cfg != nil {
		for _, iface := range cfg.Interfaces.Interfaces {
			if iface == nil {
				continue
			}
			for _, unit := range iface.Units {
				if unit == nil {
					continue
				}
				for _, raw := range unit.Addresses {
					if prefix, err := netip.ParsePrefix(raw); err == nil {
						addrs = append(addrs, prefix.Addr().String())
						continue
					}
					if addr, err := netip.ParseAddr(raw); err == nil {
						addrs = append(addrs, addr.String())
					}
				}
			}
		}
	}
	kernelAddrs, err := hostInputFenceAllLocalAddrs()
	if err != nil {
		return nil, fmt.Errorf("local address census: %w", err)
	}
	addrs = append(addrs, kernelAddrs...)
	return canonicalHostInputFenceDestinations(addrs), nil
}

func hostInputFenceConntrackRequestForOverlay(overlay xnft.HostInputFenceOverlay, destinations []string) hostInputFenceConntrackRequest {
	overlay = xnft.CanonicalHostInputFenceOverlay(overlay)
	return hostInputFenceConntrackRequest{
		destinations:    canonicalHostInputFenceDestinations(destinations),
		generation:      overlay.Generation,
		permitEpoch:     overlay.PermitEpoch,
		closeRequestSeq: overlay.CloseRequestSeq,
		closeRequestKey: overlay.CloseRequestKey,
		watchGeneration: overlay.WatchGeneration,
		state:           overlay.State,
	}
}
func hostInputFenceConntrackRequestEqual(a, b hostInputFenceConntrackRequest) bool {
	if a.generation != b.generation ||
		a.permitEpoch != b.permitEpoch ||
		a.closeRequestSeq != b.closeRequestSeq ||
		a.closeRequestKey != b.closeRequestKey ||
		a.watchGeneration != b.watchGeneration ||
		a.state != b.state ||
		len(a.destinations) != len(b.destinations) {
		return false
	}
	for i := range a.destinations {
		if a.destinations[i] != b.destinations[i] {
			return false
		}
	}
	return true
}

func flushHostInputFenceConntrack(req hostInputFenceConntrackRequest) error {
	filter := buildHostInputFenceConntrackFilter(req.destinations)
	if filter == nil {
		return nil
	}
	var errs []error
	for _, family := range []netlink.InetFamily{unix.AF_INET, unix.AF_INET6} {
		if _, err := hostInputFenceConntrackDeleteFilters(family, filter); err != nil {
			errs = append(errs, fmt.Errorf("family %d: %w", family, err))
		}
	}
	return errors.Join(errs...)
}

func (d *Daemon) noteHostInputFenceConntrack(req hostInputFenceConntrackRequest, err error) {
	if d == nil {
		return
	}
	if err == nil {
		d.hostInputFenceConntrackDebt.Store(nil)
		return
	}
	r := req
	r.destinations = append([]string(nil), req.destinations...)
	d.hostInputFenceConntrackFailures.Add(1)
	d.hostInputFenceConntrackDebt.Store(&r)
}

func (d *Daemon) retryHostInputFenceConntrackFlushOnce(ctx context.Context) {
	if d == nil || d.hostInputFenceConntrackDebt.Load() == nil || d.applySem == nil {
		return
	}
	if err := d.applySem.Acquire(ctx, 1); err != nil {
		return
	}
	defer d.applySem.Release(1)
	req := d.hostInputFenceConntrackDebt.Load()
	if req == nil {
		return
	}
	d.noteHostInputFenceConntrack(*req, flushHostInputFenceConntrack(*req))
}

func (d *Daemon) HostInputFenceConntrackFailures() uint64 {
	if d == nil {
		return 0
	}
	return d.hostInputFenceConntrackFailures.Load()
}

func (d *Daemon) HostInputFenceConntrackRevocationOwed() bool {
	return d != nil && d.hostInputFenceConntrackDebt.Load() != nil
}

// retireHostInputFenceOverlay performs the close protocol: old-set conntrack
// ACK first, then install/read back an empty candidate, then clear the pointer.
// A failed old-set ACK leaves the old overlay published and retry debt armed.
// expected is the OPEN permit record that authorized this retirement. A
// concurrent topology revoke invalidates it before the empty install.
func (d *Daemon) retireHostInputFenceOverlay(cfg *config.Config, expected *permitRecord) error {
	if d == nil || cfg == nil {
		return nil
	}
	old := d.activeHostInputFenceOverlay()
	if old == nil {
		return nil
	}
	req := d.hostInputFenceConntrackActive.Load()
	if req == nil {
		views := dpuserspace.BuildZoneHostInboundViews(cfg)
		v4, v6 := dpuserspace.BuildUnzonedHostInboundAddrs(cfg)
		destinations, err := hostInputFenceConntrackDestinations(cfg, views, v4, v6)
		if err != nil {
			return fmt.Errorf("capture host-input fence destinations: %w", err)
		}
		fallback := hostInputFenceConntrackRequestForOverlay(*old, destinations)
		req = &fallback
	}
	if err := flushHostInputFenceConntrack(*req); err != nil {
		d.noteHostInputFenceConntrack(*req, err)
		return fmt.Errorf("retire host-input fence conntrack: %w", err)
	}
	d.noteHostInputFenceConntrack(*req, nil)
	if expected != nil &&
		(d.ipsecS4 == nil || d.ipsecS4.loadPermit() != expected || expected.state != ipsecPermitOpen) {
		return fmt.Errorf("host-input fence retire authority changed before empty install")
	}
	empty := *old
	empty.MasterSet = nil
	empty.State = "RETIRING"
	if err := d.applyHostInboundFilterWithOverlay(cfg, &empty); err != nil {
		d.setHostInputFenceOverlay(old)
		if restoreErr := d.applyHostInboundFilter(cfg); restoreErr != nil {
			return errors.Join(err, fmt.Errorf("restore old host-input fence: %w", restoreErr))
		}
		return err
	}
	d.clearHostInputFenceOverlayAfterAck()
	d.hostInputFenceConntrackActive.Store(nil)
	return nil
}
