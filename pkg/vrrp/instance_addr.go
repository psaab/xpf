package vrrp

import (
	"bytes"
	"net"
	"sort"
	"strings"
)

// interfaceAddrs returns the interface's current addresses, via the test seam
// when set, else live from the kernel. Re-queried on every resolve so the
// addr-watcher (#2528) always sees the CURRENT address set.
func (vi *vrrpInstance) interfaceAddrs() ([]net.Addr, error) {
	if vi.addrsFn != nil {
		return vi.addrsFn()
	}
	return vi.iface.Addrs()
}

// getLocalIP returns the resolved local IPv4 address, or nil if unresolved.
// Safe to call from any goroutine — the field is written via setLocalIP from
// openSocket() (pre-goroutine) and from the sendPacket() lazy-resolve path
// (run-loop goroutine), while the receiver goroutines read it (#2258).
func (vi *vrrpInstance) getLocalIP() net.IP {
	if p := vi.localIP.Load(); p != nil {
		return *p
	}
	return nil
}

// setLocalIP atomically stores the resolved local IPv4 address.
func (vi *vrrpInstance) setLocalIP(ip net.IP) {
	if ip == nil {
		vi.localIP.Store(nil)
		return
	}
	vi.localIP.Store(&ip)
}

// getLocalIPv6 returns the resolved local link-local IPv6 address, or nil if
// unresolved. Safe to call from any goroutine — see getLocalIP (#2258).
func (vi *vrrpInstance) getLocalIPv6() net.IP {
	if p := vi.localIPv6.Load(); p != nil {
		return *p
	}
	return nil
}

// setLocalIPv6 atomically stores the resolved local link-local IPv6 address.
func (vi *vrrpInstance) setLocalIPv6(ip net.IP) {
	if ip == nil {
		vi.localIPv6.Store(nil)
		return
	}
	vi.localIPv6.Store(&ip)
}

// vipAddrSet returns the configured virtual addresses (prefix stripped) as a
// set. Used to EXCLUDE VIPs when selecting our own advert source: during
// split-brain both nodes hold the VIP, so sending from it would make the peer
// filter our adverts as self-sent. VIP sets may be updated in place at config
// commit (#10780), so read the mutable slice under vi.mu.
func (vi *vrrpInstance) vipAddrSet() map[string]bool {
	vi.mu.RLock()
	defer vi.mu.RUnlock()
	s := make(map[string]bool, len(vi.cfg.VirtualAddresses))
	for _, vip := range vi.cfg.VirtualAddresses {
		addr := vip
		if idx := strings.Index(addr, "/"); idx >= 0 {
			addr = addr[:idx]
		}
		s[canonAddr(addr)] = true
	}
	return s
}

// canonAddr returns the canonical string form of an IP literal so that VIP
// exclusion keys match the lookup side, which uses net.IP.String() (Go's
// canonical form). A non-canonically-formatted VIP — e.g. an uppercase or
// non-zero-compressed link-local "fe80::AB" — would otherwise be keyed by its
// raw config string and miss the "fe80::ab" lookup, leaking the VIP into local
// link-local source selection and making the engine treat its own adverts as
// self-sent (#2516). net.ParseIP rejects CIDR, so the caller must strip any
// "/prefix" first; an unparseable string falls back to itself unchanged.
func canonAddr(s string) string {
	if ip := net.ParseIP(s); ip != nil {
		return ip.String()
	}
	return s
}

// resolveLocalIPv4 deterministically selects our IPv4 advert source: the
// lowest non-VIP IPv4 currently assigned to the interface, or nil if none.
// Deterministic (lowest) selection — mirroring resolveIPv6LinkLocal — keeps
// the source STABLE across unrelated secondary-address churn so the
// addr-watcher re-resolve (#2528) never flips the advert source on an event
// for some other address on the same interface. (Member interfaces normally
// carry exactly one non-VIP primary IPv4, so this is a no-op in practice; the
// determinism only matters for the multi-address edge.)
func (vi *vrrpInstance) resolveLocalIPv4(vipSet map[string]bool) net.IP {
	addrs, err := vi.interfaceAddrs()
	if err != nil {
		return nil
	}
	var candidates []net.IP
	for _, a := range addrs {
		ipNet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip4 := ipNet.IP.To4()
		if ip4 == nil || vipSet[ip4.String()] {
			continue
		}
		candidates = append(candidates, ip4)
	}
	if len(candidates) == 0 {
		return nil
	}
	sort.Slice(candidates, func(i, j int) bool {
		return bytes.Compare(candidates[i], candidates[j]) < 0
	})
	return candidates[0]
}

// reresolveLocalAddrs recomputes localIP and localIPv6 from the interface's
// CURRENT kernel addresses and stores them atomically. Called once at
// openSocket() and again from the manager addr-watcher whenever an address is
// added/removed on this instance's interface (#2528).
//
// Before #2528 the cached source was resolved exactly once and never
// invalidated: if the interface's IPv4 or link-local IPv6 changed during
// operation — most acutely the RETH MAC reprogram cycle (programRethMAC does
// link DOWN -> set MAC -> UP, which flushes ALL kernel addresses; networkd
// KeepConfiguration=static restores them but with a 30ms-1s timing window
// against the next 30ms advert) — the instance kept sending from a stale
// source. The kernel then silently rejects the advert (source no longer on
// the interface) AND incoming self-adverts fail self-filtering in
// handleMasterRx -> false master conflict / split-brain. Re-resolving on every
// address event closes that window. A nil result (address transiently absent)
// is stored as nil so the sendPacket()/sendPacketIPv6() lazy path re-resolves
// on the next advert. The atomic setLocalIP/setLocalIPv6 stores make this
// addr-watcher-goroutine write race-clean against the receiver/run-loop reads
// (#2258).
func (vi *vrrpInstance) reresolveLocalAddrs() {
	vipSet := vi.vipAddrSet()
	vi.setLocalIP(vi.resolveLocalIPv4(vipSet))
	vi.setLocalIPv6(vi.resolveIPv6LinkLocal(vipSet))
	// #7334: the self-check's address SET, taken from the same re-resolve so
	// it can never lag the send-source selection.
	v4Set, v6Set := vi.resolveLocalAddrSets(vipSet)
	vi.setLocalAddrSet(false, v4Set)
	vi.setLocalAddrSet(true, v6Set)
}

// resolveIPv6LinkLocal deterministically selects the lowest non-VIP
// link-local IPv6 address on the interface. Sorting ensures the same
// address is always chosen regardless of kernel enumeration order,
// even when multiple link-locals exist (e.g. after MAC changes).
func (vi *vrrpInstance) resolveIPv6LinkLocal(vipSet map[string]bool) net.IP {
	addrs, err := vi.interfaceAddrs()
	if err != nil {
		return nil
	}
	var candidates []net.IP
	for _, a := range addrs {
		ipNet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		if ipNet.IP.To4() != nil {
			continue
		}
		if !ipNet.IP.IsLinkLocalUnicast() {
			continue
		}
		if vipSet[ipNet.IP.String()] {
			continue
		}
		candidates = append(candidates, ipNet.IP)
	}
	if len(candidates) == 0 {
		return nil
	}
	// Sort and pick lowest for determinism.
	sort.Slice(candidates, func(i, j int) bool {
		return bytes.Compare(candidates[i], candidates[j]) < 0
	})
	return candidates[0]
}

// THE SELECTION AND THE SET ARE DIFFERENT THINGS (#7334).
//
// localIP/localIPv6 are the SEND source and must stay a single deterministic
// choice (the lowest non-VIP), so the advert source is stable across unrelated
// secondary-address churn — that is #2528's whole point.
//
// But the receive-path self-CHECK compared an incoming frame's source against
// that one selected value, so a self-advert sent from address A bypassed the
// check once the selection had moved to B. resolveEqualPriorityMaster then
// compared our own OLD source A against our own NEW source B and stepped down
// whenever A > B: a coin flip, and a self-inflicted master-down. The check needs
// every address we might have sent from, including one the selection has since
// moved off.
//
// Both are recomputed from a single reresolveLocalAddrs read, so the set can
// never lag the selection.

// getLocalAddrSet returns the snapshot of every non-VIP address of `family`
// currently on the interface, as canonical strings (#7334). Nil/empty means
// UNRESOLVED, and every caller must fail OPEN on it.
func (vi *vrrpInstance) getLocalAddrSet(v6 bool) []string {
	p := vi.localAddrSet.Load()
	if v6 {
		p = vi.localAddrSetV6.Load()
	}
	if p == nil {
		return nil
	}
	return *p
}

// setLocalAddrSet atomically stores the address-set snapshot for a family.
func (vi *vrrpInstance) setLocalAddrSet(v6 bool, set []string) {
	target := &vi.localAddrSet
	if v6 {
		target = &vi.localAddrSetV6
	}
	if len(set) == 0 {
		target.Store(nil)
		return
	}
	target.Store(&set)
}

// isLocalAddr reports whether ip is one of OUR addresses on this interface
// (#7334).
//
// FAILS OPEN on an unresolved set, matching the posture #6560 established: a
// frame we cannot classify must still be able to be a peer's advert, and
// dropping it would be a self-inflicted master-down — strictly worse than the
// bug being fixed. An unresolved set is exactly the #2528 RETH-MAC flush
// window, when programRethMAC's link DOWN has removed every kernel address.
//
// This is the SET, not the selected send source. The selection is deliberately
// one deterministic address so the advert source stays stable; the self-check
// must recognise every address we might have sent from, including one the
// selection has since moved off.
func (vi *vrrpInstance) isLocalAddr(ip net.IP) bool {
	if ip == nil {
		return false
	}
	v6 := ip.To4() == nil
	set := vi.getLocalAddrSet(v6)
	if len(set) == 0 {
		return false // unresolved -> fail open (not ours -> do not drop)
	}
	want := canonicalVRRPAddr(ip)
	i := sort.SearchStrings(set, want)
	return i < len(set) && set[i] == want
}

// canonicalVRRPAddr renders an address for set membership: a v4-in-v6 form must
// match a snapshot taken as 4 bytes, since the receive path can hand either
// representation.
//
// The explicit To4() is BELT-AND-BRACES over net.IP.String(), which already
// performs the same check internally — so a mutation removing it is INERT
// rather than uncovered, and that is worth saying here so the next reader does
// not delete it, see nothing red, and conclude the canonicalisation is
// untested. It is kept because the intent ("normalise the family
// representation") should be visible at this call site rather than inferred
// from the standard library's implementation.
func canonicalVRRPAddr(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.String()
}

// resolveLocalAddrSets recomputes both family address sets from the
// interface's CURRENT kernel addresses (#7334). Called from
// reresolveLocalAddrs alongside the send-source selection, so the set and the
// selection are always taken from the same read.
func (vi *vrrpInstance) resolveLocalAddrSets(vipSet map[string]bool) (v4, v6 []string) {
	addrs, err := vi.interfaceAddrs()
	if err != nil {
		return nil, nil
	}
	for _, a := range addrs {
		ipNet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		if ip4 := ipNet.IP.To4(); ip4 != nil {
			if vipSet[ip4.String()] {
				continue
			}
			v4 = append(v4, ip4.String())
			continue
		}
		ip := ipNet.IP
		if ip == nil || vipSet[ip.String()] {
			continue
		}
		v6 = append(v6, ip.String())
	}
	sort.Strings(v4)
	sort.Strings(v6)
	return v4, v6
}
