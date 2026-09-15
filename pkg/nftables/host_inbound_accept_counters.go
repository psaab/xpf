package nftables

import (
	"errors"
	"fmt"
	"strings"

	"github.com/google/nftables"
	"golang.org/x/sys/unix"
)

// hostInboundAcceptCounterPrefix tags every named counter object attached to a
// GLOBAL host-inbound ICMP-error / ND accept rule (#4759) so the metric scraper
// can pick our accept counters out of the `inet xpf_hostinbound` table and
// ignore anything else (including the `xpfhi_` deny counters, which use a
// distinct prefix). The two prefixes never collide: `xpfhi_` is immediately
// followed by an underscore-terminated family token, while `xpfhia_` has an 'a'
// in that position, so ParseHostInboundDenyCounterName rejects an accept name
// and this parser rejects a deny name.
const hostInboundAcceptCounterPrefix = "xpfhia_"

// Host-inbound ICMP-error / ND accept counter TYPE-class keys (#4759). The
// global accept rules in pkg/daemon/daemon_nft.go accept a set of ICMP/ICMPv6
// control-message types regardless of any per-zone host-inbound service set (so
// enforcement never black-holes core L3 operation). Before #4759 those accepts
// were UNCOUNTED; each rule now carries the named counter for its type-class,
// giving aggregate per-class visibility into how many such packets the
// host-inbound path admits.
//
// These are AGGREGATE (the accept rules are GLOBAL, not per-zone) — there is no
// per-zone breakdown; a per-zone split would require per-zone rule duplication
// (a larger ruleset change, #4759 caveat).
const (
	// HostInboundAcceptICMP6ND counts ICMPv6 Neighbor Discovery accepts
	// (types 133-137: router/neighbor solicit+advert, redirect).
	HostInboundAcceptICMP6ND = "icmp6_nd"
	// HostInboundAcceptICMP6Error counts ICMPv6 error / PMTUD accepts
	// (types 1-4: destination-unreachable, packet-too-big, time-exceeded,
	// parameter-problem).
	HostInboundAcceptICMP6Error = "icmp6_error"
	// HostInboundAcceptICMP4Error counts ICMPv4 error / PMTUD accepts
	// (destination-unreachable, time-exceeded, parameter-problem).
	HostInboundAcceptICMP4Error = "icmp4_error"
)

// HostInboundAcceptCounterTypes is the ordered, fixed set of accept type-class
// keys. The daemon declares one counter object per entry and references it on
// the matching accept rule; the Prometheus collector iterates the same set.
var HostInboundAcceptCounterTypes = []string{
	HostInboundAcceptICMP6ND,
	HostInboundAcceptICMP6Error,
	HostInboundAcceptICMP4Error,
}

// HostInboundAcceptCounterName returns the nft named-counter object name for a
// host-inbound accept type-class. The result is a BARE nft identifier
// (prefix + fixed key, all in [a-z0-9_]), so it is valid both in the UNQUOTED
// counter DECLARATION (`counter <n> { }`, which nft v1.1.6 requires unquoted,
// #3578) and in the QUOTED reference (`counter name "<n>"`) — the two match
// byte-for-byte.
func HostInboundAcceptCounterName(typ string) string {
	return hostInboundAcceptCounterPrefix + typ
}

// ParseHostInboundAcceptCounterName reverses HostInboundAcceptCounterName. It
// returns ok=false for any object name that is not one of our host-inbound
// accept counters (wrong prefix or unknown type-class), so the scraper silently
// skips foreign / malformed / deny-counter objects that share the table.
func ParseHostInboundAcceptCounterName(name string) (typ string, ok bool) {
	rest, found := strings.CutPrefix(name, hostInboundAcceptCounterPrefix)
	if !found || rest == "" {
		return "", false
	}
	switch rest {
	case HostInboundAcceptICMP6ND, HostInboundAcceptICMP6Error, HostInboundAcceptICMP4Error, HostInboundAcceptReinject:
		return rest, true
	}
	return "", false
}

// HostInboundAcceptCount is one global host-inbound ICMP-error / ND accept
// counter read from the `inet xpf_hostinbound` table.
type HostInboundAcceptCount struct {
	Type    string // one of the HostInboundAccept* type-class keys
	Packets uint64
	Bytes   uint64
}

// ReadHostInboundAcceptCounters reads the global ICMP-error / ND accept counters
// from the kernel `inet xpf_hostinbound` table via netlink (no nft shell-out).
// It returns one entry per xpf-managed accept counter currently installed. The
// accept counters live in the SAME table as the per-zone DROP counters
// (ReadHostInboundDenyCounters); the two are separated purely by object-name
// prefix, so this scraper skips the deny counters and vice versa.
//
// When the table is absent (no host-inbound-traffic enforcement is installed, so
// the daemon removed it) the function returns (nil, nil): no table means no
// counts, not an error. A genuine netlink failure is returned so the caller can
// surface "counter unavailable" rather than a misleading zero (the #3345
// missing-sample contract the Prometheus collector applies to nft counters).
//
// Counters reset to zero whenever the daemon rebuilds the table (every commit
// and every DHCP/DHCPv6 address change on a dataplane interface, which delete +
// recreate the table); this matches the table lifecycle and is handled by
// Prometheus rate() reset detection, exactly like ReadHostInboundDenyCounters.
func ReadHostInboundAcceptCounters() ([]HostInboundAcceptCount, error) {
	c, err := nftables.New()
	if err != nil {
		return nil, fmt.Errorf("nftables conn: %w", err)
	}
	tables, err := c.ListTablesOfFamily(nftables.TableFamilyINet)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil, nil
		}
		return nil, fmt.Errorf("nftables list tables: %w", err)
	}
	var table *nftables.Table
	for _, t := range tables {
		if t != nil && t.Name == HostInboundTableName {
			table = t
			break
		}
	}
	if table == nil {
		// No host-inbound enforcement installed -> no accepts counted.
		return nil, nil
	}
	objs, err := c.GetObjects(table)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil, nil
		}
		return nil, fmt.Errorf("nftables list objects %s: %w", HostInboundTableName, err)
	}
	var out []HostInboundAcceptCount
	for _, o := range objs {
		co, ok := o.(*nftables.CounterObj)
		if !ok {
			continue
		}
		typ, ok := ParseHostInboundAcceptCounterName(co.Name)
		if !ok {
			continue
		}
		out = append(out, HostInboundAcceptCount{
			Type:    typ,
			Packets: co.Packets,
			Bytes:   co.Bytes,
		})
	}
	return out, nil
}
