package cluster

import (
	"log/slog"
	"net"
	"sort"

	"github.com/psaab/xpf/pkg/config"
)

// AnnounceKind classifies one failover announcement target (#17052).
type AnnounceKind int

const (
	AnnounceVIP AnnounceKind = iota
	AnnounceRouterLL
	AnnouncePoolV4
	AnnouncePoolV6
)

func (k AnnounceKind) String() string {
	switch k {
	case AnnounceVIP:
		return "vip"
	case AnnounceRouterLL:
		return "router-ll"
	case AnnouncePoolV4:
		return "pool-v4"
	case AnnouncePoolV6:
		return "pool-v6"
	default:
		return "unknown"
	}
}

// AnnounceTarget is one (iface, IP, kind) announcement. Burst is the
// per-target frame count AFTER the single clamp in SendAnnounceTargets:
// VIP and router-LL targets carry the clamped per-RG burst count; pool
// targets carry 1 (breadth, not depth — #8405).
type AnnounceTarget struct {
	Iface   string
	IP      net.IP
	Kind    AnnounceKind
	Burst   int
	ProbeIP net.IP // VIP v4 only: gateway probe target (network+1), nil to skip; derivation lives in pkg/vrrp
}

// AnnounceBurstCount resolves the per-RG gratuitous-ARP count (default 3)
// and applies the single #5695 runtime clamp for the announce path.
// clamped reports whether the clamp fired so the caller can warn once
// (per-RG in the daemon, per-instance in pkg/vrrp). This is the ONE
// ClampGratuitousARPCount call on the announce path (#17052 acceptance);
// the two engines must not re-clamp.
func AnnounceBurstCount(cfg *config.Config, rgID int) (count int, configured int, clamped bool) {
	configured = 3
	if cfg != nil {
		if cc := cfg.Chassis.Cluster; cc != nil {
			for _, rg := range cc.RedundancyGroups {
				if rg.ID == rgID && rg.GratuitousARPCount > 0 {
					configured = rg.GratuitousARPCount
					break
				}
			}
		}
	}
	count, clamped = EffectiveAnnounceBurstCount(configured)
	return count, configured, clamped
}

// EffectiveAnnounceBurstCount applies the same resolution+clamp to a
// caller-supplied configured count (pkg/vrrp reads its per-instance
// GARPCount, which CollectRethInstances already copied from the same
// per-RG config). <=0 yields the default 3, matching both engines'
// historic behaviour. clamped reports whether the #5695 clamp fired.
func EffectiveAnnounceBurstCount(configured int) (count int, clamped bool) {
	if configured <= 0 {
		return 3, false
	}
	if c, was := config.ClampGratuitousARPCount(configured); was {
		return c, true
	}
	return configured, false
}

// AnnounceTargets builds the FULL ordered target set for rgID in cfg:
// VIPs (via the #17140 single walk Config.RethVIPsForRG), then the
// per-unit router link-locals (#17049 Config.RouterLinkLocalPlacements),
// then the proxy-ARP/NDP pool addresses (RG via Config.RefRG — the
// #17086 SSOT behind daemon's proxyARPRedundancyGroupFor). Order is
// deterministic: interfaces sorted, addresses in walk order, router-LL
// in placement order, pool in configured order. Pool breadth is NOT
// truncated here; SendAnnounceTargets enforces PoolAnnounceMaxAddresses
// so a parity test sees the identical full set both modes would attempt.
func AnnounceTargets(cfg *config.Config, rgID int, probeDerive func(*net.IPNet) (net.IP, bool)) []AnnounceTarget {
	if cfg == nil || rgID <= 0 {
		return nil
	}
	burst, _, _ := AnnounceBurstCount(cfg, rgID)
	var targets []AnnounceTarget
	targets = append(targets, AnnounceTargetsFromVIPMap(cfg.RethVIPsForRG(rgID), burst, probeDerive)...)
	for _, p := range cfg.RouterLinkLocalPlacements(rgID) {
		targets = append(targets, AnnounceTarget{Iface: p.Netdev, IP: p.Addr, Kind: AnnounceRouterLL, Burst: burst})
	}
	targets = append(targets, PoolAnnounceTargets(cfg, rgID)...)
	return targets
}

// AnnounceTargetsFromVIPMap builds VIP targets from an explicit
// iface->CIDRs map (pkg/vrrp's per-instance snapshot shape), filling
// ProbeIP via derive. Burst is the caller's already-clamped count.
func AnnounceTargetsFromVIPMap(vipMap map[string][]string, burst int, derive func(*net.IPNet) (net.IP, bool)) []AnnounceTarget {
	ifNames := make([]string, 0, len(vipMap))
	for n := range vipMap {
		ifNames = append(ifNames, n)
	}
	sort.Strings(ifNames)
	var targets []AnnounceTarget
	for _, ifName := range ifNames {
		for _, cidr := range vipMap[ifName] {
			ip, ipNet, err := net.ParseCIDR(cidr)
			if err != nil {
				continue
			}
			t := AnnounceTarget{Iface: ifName, IP: ip, Kind: AnnounceVIP, Burst: burst}
			if derive != nil && ip.To4() != nil {
				if gw, ok := derive(ipNet); ok && !gw.Equal(ip.To4()) {
					t.ProbeIP = gw
				}
			}
			targets = append(targets, t)
		}
	}
	return targets
}

// NonVIPAnnounceTargets returns AnnounceTargets minus the VIP kind: the
// set legacy VRRP mode must send from the daemon on RG activation,
// because pkg/vrrp already announces the VIPs itself (#17052).
func NonVIPAnnounceTargets(cfg *config.Config, rgID int) []AnnounceTarget {
	all := AnnounceTargets(cfg, rgID, nil)
	out := all[:0]
	for _, t := range all {
		if t.Kind != AnnounceVIP {
			out = append(out, t)
		}
	}
	return out
}

// PoolAnnounceMaxAddresses bounds how many pool addresses one RG
// ownership change announces (#8405; see daemon_ha_vip.go history).
// Attempted sends count, not only successes.
const PoolAnnounceMaxAddresses = 64

// PoolAnnounceTargets returns the pool targets for rgID (untruncated,
// configured order). Split out so the parity test and the sender share
// one derivation.
func PoolAnnounceTargets(cfg *config.Config, rgID int) []AnnounceTarget {
	if cfg == nil || rgID <= 0 {
		return nil
	}
	var targets []AnnounceTarget
	for _, entry := range cfg.Security.NAT.ProxyARP {
		if cfg.RefRG(entry.Interface) != rgID {
			continue
		}
		ifName := cfg.ResolveKernelIfName(entry.Interface)
		if ifName == "" {
			continue
		}
		for _, cidr := range entry.Addresses {
			ip, _, err := net.ParseCIDR(cidr)
			if err != nil {
				if ip = net.ParseIP(cidr); ip == nil {
					continue
				}
			}
			kind := AnnouncePoolV6
			if ip.To4() != nil {
				kind = AnnouncePoolV4
			}
			targets = append(targets, AnnounceTarget{Iface: ifName, IP: ip, Kind: kind, Burst: 1})
		}
	}
	return targets
}

// Sender seams so daemon/vrrp tests and the parity test can capture the
// frame sequence without AF_PACKET I/O. Production wiring is the gated
// burst senders in garp.go (same file package).
var (
	announceGARPBurstFn    = SendGratuitousARPBurstGated
	announceNABurstFn      = SendGratuitousIPv6BurstGated
	announceProxyNABurstFn = SendProxyGratuitousIPv6BurstGated
	announceARPProbeFn     = SendARPProbe
)

// AnnounceSender captures the send seams SendAnnounceTargets uses, so
// callers that already own seams (pkg/daemon's direct*Fn, pkg/vrrp's
// garpBurstFn) can inject THEIR captured senders and keep their existing
// tests observing the shared engine. A nil field falls back to the
// package default above.
type AnnounceSender struct {
	GARP    func(iface string, ip net.IP, count int, stillValid BurstStillValid) error
	NA      func(iface string, ip net.IP, count int, stillValid BurstStillValid) error
	ProxyNA func(iface string, ip net.IP, count int, stillValid BurstStillValid) error
	Probe   func(iface string, senderIP, targetIP net.IP) error
}

func (s AnnounceSender) garp() func(string, net.IP, int, BurstStillValid) error {
	if s.GARP != nil {
		return s.GARP
	}
	return announceGARPBurstFn
}
func (s AnnounceSender) na() func(string, net.IP, int, BurstStillValid) error {
	if s.NA != nil {
		return s.NA
	}
	return announceNABurstFn
}
func (s AnnounceSender) proxyNA() func(string, net.IP, int, BurstStillValid) error {
	if s.ProxyNA != nil {
		return s.ProxyNA
	}
	return announceProxyNABurstFn
}
func (s AnnounceSender) probe() func(string, net.IP, net.IP) error {
	if s.Probe != nil {
		return s.Probe
	}
	return announceARPProbeFn
}

// AnnounceResult reports what SendAnnounceTargets did, for caller logging.
type AnnounceResult struct {
	Sent          int // targets whose first frame succeeded
	PoolAttempted int
	PoolTruncated bool
	FirstErr      error
}

// SendAnnounceTargets emits the frame sequence for targets in order:
// VIP v4 = GARP burst + gateway probe, VIP v6 / router-LL = NA burst,
// pool v4 = single GARP, pool v6 = single proxy NA. stillValid gates
// follow-up frames (inside the gated senders) and, for pool targets, is
// consulted before each send so a mid-announce abdication stops rather
// than lies (#8405). Pool breadth is truncated at
// PoolAnnounceMaxAddresses attempted sends. Per-target failures are
// logged once per target (never per frame) and do not stop the sweep,
// matching both engines' historic behaviour.
func SendAnnounceTargets(targets []AnnounceTarget, stillValid BurstStillValid, sender AnnounceSender) AnnounceResult {
	var res AnnounceResult
	poolAttempted := 0
	for _, t := range targets {
		switch t.Kind {
		case AnnounceVIP:
			if t.IP.To4() != nil {
				// Probe fires even when the GARP burst errors (both
				// historic engines did this): the probe is an
				// independent rebind path for routers that ignore
				// broadcast GARP. It does not count as announced.
				if err := sender.garp()(t.Iface, t.IP, t.Burst, stillValid); err != nil {
					slog.Warn("announce: GARP failed", "iface", t.Iface, "ip", t.IP, "kind", t.Kind.String(), "err", err)
					res.noteErr(err)
				} else {
					res.Sent++
				}
				if t.ProbeIP != nil {
					if err := sender.probe()(t.Iface, t.IP.To4(), t.ProbeIP); err != nil {
						slog.Warn("announce: ARP probe failed", "iface", t.Iface, "gw", t.ProbeIP, "err", err)
					}
				}
			} else {
				if err := sender.na()(t.Iface, t.IP, t.Burst, stillValid); err != nil {
					slog.Warn("announce: IPv6 NA failed", "iface", t.Iface, "ip", t.IP, "kind", t.Kind.String(), "err", err)
					res.noteErr(err)
					continue
				}
				res.Sent++
			}
		case AnnounceRouterLL:
			if err := sender.na()(t.Iface, t.IP, t.Burst, stillValid); err != nil {
				slog.Warn("announce: router link-local NA failed", "iface", t.Iface, "ip", t.IP, "err", err)
				res.noteErr(err)
				continue
			}
			res.Sent++
		case AnnouncePoolV4, AnnouncePoolV6:
			if stillValid != nil && !stillValid() {
				return res
			}
			if poolAttempted >= PoolAnnounceMaxAddresses {
				res.PoolAttempted = poolAttempted
				res.PoolTruncated = true
				return res
			}
			poolAttempted++
			var err error
			if t.Kind == AnnouncePoolV4 {
				err = sender.garp()(t.Iface, t.IP, 1, stillValid)
			} else {
				err = sender.proxyNA()(t.Iface, t.IP, 1, stillValid)
			}
			if err != nil {
				slog.Warn("announce: pool announce failed", "iface", t.Iface, "ip", t.IP, "kind", t.Kind.String(), "err", err)
				res.noteErr(err)
				continue
			}
			res.Sent++
		}
	}
	res.PoolAttempted = poolAttempted
	return res
}

func (r *AnnounceResult) noteErr(err error) {
	if r.FirstErr == nil {
		r.FirstErr = err
	}
}
