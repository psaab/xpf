package vrrp

import (
	"fmt"
	"log/slog"
	"net"
	"strings"
)

// splitVIPsByFamily parses a configured virtual-address list (CIDR or bare
// literals) into the per-family net.IP slices a VRRPv3 advertisement carries.
// Unparseable entries are skipped, exactly as the send path has always done.
//
// This is the SINGLE source of the per-family address counts. sendAdvert uses
// it to build the packets and checkAdvertCapacity uses it to decide whether those
// packets can legally be built, so the guard and the builder can never disagree
// about how many addresses a config yields — the counting rule is shared code,
// not two copies of the same loop (#6779).
func splitVIPsByFamily(vips []string) (v4Addrs, v6Addrs []net.IP) {
	for _, vip := range vips {
		addr := vip
		if idx := strings.Index(addr, "/"); idx >= 0 {
			addr = addr[:idx]
		}
		ip := net.ParseIP(addr)
		if ip == nil {
			continue
		}
		if ip.To4() != nil {
			v4Addrs = append(v4Addrs, ip.To4())
		} else {
			v6Addrs = append(v6Addrs, ip.To16())
		}
	}
	return v4Addrs, v6Addrs
}

// checkAdvertCapacity reports why the given configured virtual-address set cannot
// produce a legal VRRPv3 advertisement, or nil if it can (#6779).
//
// It checks the UPPER bound only: more addresses of one family than the advert
// can express. Marshal range-checks len(IPAddresses) against
// MinAdvertAddrCount..MaxAdvertAddrCount and returns an error rather than
// truncating the u8 Count byte (#5090), so an oversized family makes every
// Marshal call for that family fail. The per-family ceiling is
// MaxConfiguredVIPs, which is one lower for IPv6 because sendPacketIPv6
// prepends the mandatory link-local before Marshal.
//
// Deliberately NOT checked here: an EMPTY (or entirely unparseable) VIP list.
// sendAdvert emits a per-family advert only when that family has at least one
// address, so a VIP-less instance also holds its group without ever
// advertising — but it claims no addresses, so there is nothing for a
// second master to collide over, and it is a distinct defect from the
// oversized set this guard exists for. Folding it in here would also change
// the behaviour of every VIP-less instance in one step; that belongs in its
// own change rather than riding along with this fix.
//
// Why this is fatal rather than degraded: sendAdvert discards the Marshal error
// at slog.Debug, so the failure is silent on a default log level. A node that
// has claimed ownership and cannot advertise holds the VIPs while emitting
// nothing — the peer's masterDownTimer expires and it promotes too, so both
// nodes answer ARP for the same VIP (dual-master), or, if the peer shares the
// same unsendable config, the VIP is stranded with no advertising owner.
//
// The check is per-family and ANY failing configured family fails the whole
// instance: the families share one VRID and one ownership claim, so a family
// that cannot advertise is a family whose peer will elect a second master for
// addresses this node is already answering for. That mirrors the #5082
// "required VIP set" rule, where a partially-actuated VIP set is also refused
// rather than partially claimed.
//
// The predicate is pure for a given VIP list. It is evaluated at construction
// and again when updateVIPs changes the live configuration (#10780).
func checkAdvertCapacity(vips []string) error {
	v4Addrs, v6Addrs := splitVIPsByFamily(vips)

	if n := len(v4Addrs); n > MaxConfiguredVIPs(false) {
		return fmt.Errorf("%d IPv4 virtual addresses exceed the %d that fit in a "+
			"VRRPv3 advertisement (RFC 5798 §5.2.4 Count IPvX Addr is one byte); "+
			"every IPv4 advert would fail to build", n, MaxConfiguredVIPs(false))
	}
	if n := len(v6Addrs); n > MaxConfiguredVIPs(true) {
		return fmt.Errorf("%d IPv6 virtual addresses exceed the %d that fit in a "+
			"VRRPv3 advertisement (RFC 5798 §5.2.4 Count IPvX Addr is one byte, and "+
			"§6.1 reserves the first slot for the mandatory link-local prepend); "+
			"every IPv6 advert would fail to build", n, MaxConfiguredVIPs(true))
	}
	return nil
}

// instanceAdvertCapacityErr evaluates checkAdvertCapacity for a new instance's
// configured VIP set and emits the single operator-facing Error for it (#6779).
//
// VIP-set changes are applied in place, so updateVIPs re-evaluates this
// predicate and emits the same Error for a newly invalid set. becomeMaster
// consults the stored result on every promotion attempt without re-parsing the
// list — and, more importantly, without re-logging: that path retries every
// masterDownInterval (~97ms for a RETH instance), so an Error there would put
// ~10 lines/second into the journal for as long as the bad config is loaded,
// exactly the flooding CLAUDE.md's logging rules forbid.
func instanceAdvertCapacityErr(cfg Instance) error {
	err := checkAdvertCapacity(cfg.VirtualAddresses)
	if err != nil {
		slog.Error("vrrp: configured virtual addresses cannot produce a legal "+
			"advertisement; this instance will never claim MASTER (fail-closed)",
			"key", StateKey(cfg.Interface, cfg.GroupID, cfg.Family),
			"vip_count", len(cfg.VirtualAddresses), "err", err)
	}
	return err
}
