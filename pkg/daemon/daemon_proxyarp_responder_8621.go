package daemon

import (
	"context"
	"log/slog"
	"net"
	"sort"
	"strings"
	"sync"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"golang.org/x/sys/unix"
)

// #8621: the userspace half of proxy-ARP for source-NAT pool addresses.
//
// reconcileProxyARP installs NTF_PROXY entries and sets the per-interface
// `proxy_arp` sysctl. For a pool address inside the connected subnet of its own
// egress interface — the configuration this product ships and #8280 chose
// deliberately — BOTH ARE INERT, because every arm of `arp_process`'s proxy
// branch is gated on the route to the target egressing a different device than
// the request arrived on. The full derivation, the measurement, and why
// `proxy_arp_pvlan` is refused are in the header of
// `pkg/cluster/arp_responder_8621.go`.
//
// The consequence before this change: nothing ever answered an ARP request for
// a pool address, so an upstream could only learn it from #8405's gratuitous
// announce — which fires on redundancy-group ownership change and nothing else.
// Between announces the binding ages out and pool-mode return traffic
// blackholes silently. That also means #8297's suppression of the standby's
// "responder" was suppressing something that never answered.
//
// This file supplies the responder those two changes already assume exists.
//
// THE SPLIT BETWEEN WHAT IS CACHED AND WHAT IS LIVE is the load-bearing design
// decision here:
//
//   - the ADDRESS SET, REDUNDANCY-GROUP ID, interface identity, and current
//     interface MAC are snapshotted at reconcile. The address/config values
//     change only on commit; the MAC is re-read on every reconcile because a
//     live virtual-MAC update keeps the socket running.
//   - OWNERSHIP OF THAT GROUP is read per request. It changes on failover,
//     between reconciles, and answering from a stale snapshot is precisely the
//     failure #8405 measured: the RETH virtual MAC is PER NODE, so a standby
//     that answers draws the traffic to itself.
//
// Caching ownership would reintroduce the bug this responder exists to help
// fix, from the other direction. Snapshotting the config/address/MAC state is
// what keeps the per-frame work bounded while still tracking live failover.

// proxyARPResponders owns one goroutine per interface that has proxy-ARP pool
// addresses configured on it.
type proxyARPResponders struct {
	mu      sync.Mutex
	running map[string]*proxyARPResponder // kernel netdev name -> responder
}

type proxyARPResponder struct {
	cancel   context.CancelFunc
	done     chan struct{}

	// addrsMu guards the reconcile snapshot: addresses, interface identity,
	// redundancy-group ownership input, and the current interface MAC. A
	// responder stays alive across reconcile, so all of these fields can
	// change while its receive goroutine is answering requests.
	addrsMu  sync.RWMutex
	junosRef string
	// rgID is the redundancy group of the interface, resolved from config at
	// reconcile. 0 means the interface belongs to no group, which answers
	// unconditionally — there is no ownership question to ask.
	rgID int
	addrs map[string]struct{} // canonical IPv4 string -> present
	mac   net.HardwareAddr    // current interface MAC, refreshed on reconcile
	// macSet distinguishes "reconcile deliberately cleared the MAC after a
	// failed lookup" from a responder that has not opened its socket yet.
	macSet bool
}

func newProxyARPResponders() *proxyARPResponders {
	return &proxyARPResponders{running: map[string]*proxyARPResponder{}}
}
// proxyARPInterfaceByName is a seam for the reconcile-time MAC lookup. The
// production function reads the live kernel interface so a virtual-MAC live
// set is observed even though the AF_PACKET socket remains open.
var proxyARPInterfaceByName = net.InterfaceByName

func proxyARPCurrentMAC(ifName string) (net.HardwareAddr, error) {
	iface, err := proxyARPInterfaceByName(ifName)
	if err != nil {
		return nil, err
	}
	return append(net.HardwareAddr(nil), iface.HardwareAddr...), nil
}

func (r *proxyARPResponder) currentMAC() net.HardwareAddr {
	r.addrsMu.RLock()
	defer r.addrsMu.RUnlock()
	return append(net.HardwareAddr(nil), r.mac...)
}
// snapshot returns one coherent reconcile view. In particular, junosRef and
// rgID are read under the same lock that publishes them; the receive goroutine
// must never pair a new address set with an old ownership identity.
func (r *proxyARPResponder) snapshot(target string) (proxied bool, junosRef string, rgID int) {
	r.addrsMu.RLock()
	defer r.addrsMu.RUnlock()
	_, proxied = r.addrs[target]
	return proxied, r.junosRef, r.rgID
}

// proxyARPPoolAddressesByInterface derives, from config alone, the IPv4
// proxy-ARP addresses per Junos interface ref.
//
// IPv4 only, and deliberately: IPv6 proxy NDP has no equivalent defect —
// `ndisc_recv_ns` gates on forwarding + proxy_ndp + a bare `pneigh_lookup` with
// NO route lookup, so the kernel answers v6 for a same-subnet target correctly
// and `reconcileProxyARP` already installs those entries. A v6 responder here
// would duplicate a working kernel path, and two responders for one family can
// disagree while only one is gated by ownership.
func proxyARPPoolAddressesByInterface(cfg *config.Config) map[string]map[string]struct{} {
	if cfg == nil || len(cfg.Security.NAT.ProxyARP) == 0 {
		return nil
	}
	out := map[string]map[string]struct{}{}
	for _, entry := range cfg.Security.NAT.ProxyARP {
		for _, cidr := range entry.Addresses {
			ip, _, err := net.ParseCIDR(cidr)
			if err != nil {
				if ip = net.ParseIP(cidr); ip == nil {
					continue
				}
			}
			v4 := ip.To4()
			if v4 == nil {
				continue // see the IPv6 note above
			}
			set, ok := out[entry.Interface]
			if !ok {
				set = map[string]struct{}{}
				out[entry.Interface] = set
			}
			set[v4.String()] = struct{}{}
		}
	}
	return out
}

// answerPolicyFor builds the per-request decision for one interface. The
// address set is read from the responder's snapshot; ownership is read live.
func (d *Daemon) answerPolicyFor(r *proxyARPResponder) cluster.ARPAnswerPolicy {
	return func(_ string, target net.IP) bool {
		v4 := target.To4()
		if v4 == nil {
			return false
		}
		proxied, _, rgID := r.snapshot(v4.String())
		if !proxied {
			return false
		}
		// LIVE ownership read — the only thing not snapshotted. A cached
		// verdict here answers with this node's per-node RETH virtual MAC after
		// the group has moved, which is the #8405 misdelivery.
		//
		// proxyARPSuppressedForRG keeps its three-state default: it suppresses
		// only on an AFFIRMATIVE not-owner, so unknown ownership answers. That
		// is the right direction here for the reason rg_ownership_8297.go:32
		// gives — answering twice is a defect, answering zero times is a bigger
		// one — and a double answer is corrected by the next announce, whereas
		// a silent non-answer is the bug this responder exists to fix.
		return !d.proxyARPSuppressedForRG(rgID)
	}
}

// runProxyARPResponder is the receive loop for one interface.
func (d *Daemon) runProxyARPResponder(ctx context.Context, ifName string, r *proxyARPResponder) {
	defer close(r.done)

	fd, ifIndex, mac, err := cluster.OpenARPSocket(ifName)
	if err != nil {
		slog.Warn("proxy-arp responder: cannot open ARP socket; pool addresses on "+
			"this interface will not be answered and return traffic depends on the "+
			"failover announce alone (#8621)",
			"iface", ifName, "err", err)
		return
	}
	// Publish the MAC returned with the socket only when reconcile has not
	// already published a newer snapshot. Without this conditional, the
	// interleaving "socket opens with M1; reconcile stores M2; socket-open path
	// stores M1" would leave stale answers until a later reconcile.
	r.addrsMu.Lock()
	if !r.macSet {
		r.mac = append(net.HardwareAddr(nil), mac...)
		r.macSet = true
	}
	r.addrsMu.Unlock()
	// The fd is closed EXACTLY ONCE, by whichever of the two paths gets there
	// first: the watcher goroutine below (to unblock a parked Recvfrom on
	// shutdown) or this function's own exit. A plain `defer unix.Close(fd)`
	// alongside the watcher is a DOUBLE CLOSE — and a double close is not
	// harmless here, because the kernel reuses the lowest free descriptor
	// number: between the two closes another goroutine can open a socket or a
	// file that lands on this number and have it closed underneath it. That
	// failure is silent, remote from its cause, and load-dependent.
	var closeOnce sync.Once
	closeFD := func() { closeOnce.Do(func() { unix.Close(fd) }) }
	defer closeFD()

	// Unblock a blocking Recvfrom on shutdown; the read then returns EBADF and
	// the loop exits.
	go func() {
		<-ctx.Done()
		closeFD()
	}()

	policy := d.answerPolicyFor(r)
	buf := make([]byte, 2048)
	for {
		if ctx.Err() != nil {
			return
		}
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			if ctx.Err() != nil {
				return // shutdown closed the fd
			}
			if err == unix.EINTR {
				continue
			}
			slog.Debug("proxy-arp responder: recv", "iface", ifName, "err", err)
			return
		}
		if err := respondToARPFrame(fd, ifIndex, ifName, r, policy, buf[:n]); err != nil {
			slog.Debug("proxy-arp responder: send reply", "iface", ifName, "err", err)
		}
	}
}

// arpReplySend is a package var so a test can observe what actually reaches the
// wire without a raw socket. Production is unix.Sendto.
var arpReplySend = func(fd int, pkt []byte, addr unix.Sockaddr) error {
	return unix.Sendto(fd, pkt, 0, addr)
}

// respondToARPFrame is the last mile: decide, and if the answer is yes, address
// the reply to the asker and put it on the wire.
//
// Extracted from the receive loop so the SEND is reachable from a test. The
// decision being right and the frame never leaving the box are indistinguishable
// from inside the loop, and the link-layer destination is set here rather than
// by the frame builder — a reply with correct contents sent to the wrong
// link-layer address teaches nobody anything.
func respondToARPFrame(fd, ifIndex int, ifName string, r *proxyARPResponder, policy cluster.ARPAnswerPolicy, frame []byte) error {
	mac := r.currentMAC()
	reply, req, verdict := cluster.HandleARPFrame(frame, mac, ifName, policy)
	if verdict != cluster.ARPReplyAnswer || reply == nil || req == nil {
		return nil
	}
	addr := &unix.SockaddrLinklayer{Ifindex: ifIndex, Halen: 6}
	copy(addr.Addr[:], req.SenderMAC)
	return arpReplySend(fd, reply, addr)
}

// syncProxyARPResponders starts, updates and stops per-interface responders to
// match the reconcile's view.
//
// want maps kernel netdev name -> Junos interface ref, and is exactly the set
// reconcileProxyARP just installed entries for. Interfaces that dropped out get
// their responder stopped: leaving one running would answer for an address this
// node no longer proxies, which is the same class of error as the #4001 stale
// re-install the reassert loop was fixed for.
func (d *Daemon) syncProxyARPResponders(cfg *config.Config, want map[string]string) {
	if d.arpResponders == nil {
		return
	}
	byIface := proxyARPPoolAddressesByInterface(cfg)

	d.arpResponders.mu.Lock()
	defer d.arpResponders.mu.Unlock()

	// #9237: EVICT RESPONDERS THAT ARE NO LONGER RUNNING, before anything below
	// consults the map.
	//
	// The entry is published BEFORE the goroutine opens its socket, so an open
	// or bind failure leaves a `running` member that owns nothing. The branch
	// below then takes the running path -- swapping the address snapshot rather
	// than restarting, on the correct reasoning that a restart would drop
	// requests during a socket rebuild -- and the map cannot distinguish a
	// responder that is answering from one that never opened. So recovery was
	// not merely missing, it was suppressed by an optimisation whose
	// precondition was unchecked, and neither the apply path nor the 30s
	// reassert owner could recover it: config removal or a daemon restart was
	// the only exit.
	//
	// The signal was already being produced. runProxyARPResponder does
	// `defer close(r.done)` and nothing in production read it; this is that
	// consumer. A non-blocking check once per reconcile is enough, because the
	// close is permanent.
	//
	// GENERATION-SCOPED ON THE EXACT POINTER, and honestly labelled: the
	// identity comparison below is DEFENSIVE and is NOT reachable as written.
	// The sweep re-reads the same map it is iterating, under the mutex it
	// already holds, so `cur` cannot differ from `r`. A mutation test dropping
	// the comparison therefore survives, and that is correct rather than a gap
	// in the cells.
	//
	// It stays because the invariant is what matters and the locking that
	// currently provides it is incidental: if eviction ever moves off this
	// path -- into the responder goroutine itself, or behind a shorter critical
	// section -- a dead responder deleting a REPLACEMENT installed under the
	// same name becomes reachable immediately, and it is the kind of race that
	// presents as an intermittently missing responder rather than as a crash.
	//
	// An INTENTIONAL teardown never reaches this sweep: both the !keep branch
	// below and the empty-address branch delete the entry synchronously when
	// they cancel it. So a `done` observed here is always an unintended death,
	// and treating it as retry debt cannot re-arm a responder the config no
	// longer wants -- the want-loop decides that, one pass later.
	var died []string
	for name, r := range d.arpResponders.running {
		select {
		case <-r.done:
			if cur, ok := d.arpResponders.running[name]; ok && cur == r {
				delete(d.arpResponders.running, name)
				died = append(died, name)
			}
		default:
		}
	}
	if len(died) > 0 {
		// AGGREGATE, not per-responder: this runs every 30s from the reassert
		// owner, and a persistently unopenable interface would otherwise log on
		// every tick. The count is what an operator needs; the per-interface
		// reason was already logged once by the responder itself.
		sort.Strings(died)
		slog.Warn("proxy-arp responder: evicting responders that exited without being "+
			"stopped; they owned no socket and answered nothing. Restarting them below "+
			"(#9237)", "count", len(died), "ifaces", strings.Join(died, ","))
	}

	for name, r := range d.arpResponders.running {
		if _, keep := want[name]; !keep {
			r.cancel()
			delete(d.arpResponders.running, name)
			slog.Info("proxy-arp responder: stopped", "iface", name)
		}
	}

	for name, junosRef := range want {
		addrs := byIface[junosRef]
		rgID := proxyARPRedundancyGroupFor(cfg, junosRef)
		if len(addrs) == 0 {
			// Configured on this interface but with no IPv4 address to answer
			// for. Do not start a socket that can never answer.
			if r, ok := d.arpResponders.running[name]; ok {
				r.cancel()
				delete(d.arpResponders.running, name)
			}
			continue
		}
		if r, ok := d.arpResponders.running[name]; ok {
			// Running: swap the snapshot rather than restart. A restart would
			// drop requests during the socket rebuild for no reason — the
			// address set is the only thing that changed.
			mac, err := proxyARPCurrentMAC(name)
			if err != nil {
				slog.Warn("proxy-arp responder: cannot refresh interface MAC; "+
					"pausing answers until the next successful reconcile",
					"iface", name, "err", err, "issue", "#10316")
			}
			r.addrsMu.Lock()
			r.addrs = addrs
			r.junosRef = junosRef
			r.rgID = rgID
			// Do not retain an old MAC after a failed lookup: answering with a
			// stale virtual MAC is worse than suppressing one reconcile's
			// request. The next reconcile retries the live lookup.
			r.mac = append(net.HardwareAddr(nil), mac...)
			r.macSet = true
			r.addrsMu.Unlock()
			continue
		}
		ctx, cancel := context.WithCancel(d.proxyARPResponderCtx())
		r := &proxyARPResponder{
			cancel:   cancel,
			done:     make(chan struct{}),
			junosRef: junosRef,
			rgID:     rgID,
			addrs:    addrs,
		}
		d.arpResponders.running[name] = r
		go d.runProxyARPResponder(ctx, name, r)
		slog.Info("proxy-arp responder: started", "iface", name, "addresses", len(addrs))
	}
}

// stopProxyARPResponders tears every responder down on shutdown.
func (d *Daemon) stopProxyARPResponders() {
	if d.arpResponders == nil {
		return
	}
	d.arpResponders.mu.Lock()
	defer d.arpResponders.mu.Unlock()
	for name, r := range d.arpResponders.running {
		r.cancel()
		delete(d.arpResponders.running, name)
	}
}

// proxyARPResponderCtx is the parent for responder goroutines.
//
// d.daemonCtx is the RAW parent Run stores, deliberately kept separate from the
// shutdown-signal context (#5807) so subsystems stay live during teardown. That
// is the right parent here: responders must be stopped EXPLICITLY and early in
// the shutdown sequence — a node on its way down should stop claiming pool
// addresses before it tears the dataplane down, not after — which is what
// stopProxyARPResponders does. Before Run has stored one, Background: a
// responder started that early is still stopped by that same call.
func (d *Daemon) proxyARPResponderCtx() context.Context {
	if d.daemonCtx != nil {
		return d.daemonCtx
	}
	return context.Background()
}
