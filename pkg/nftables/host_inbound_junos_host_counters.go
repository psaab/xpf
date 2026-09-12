package nftables

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/google/nftables"
	"golang.org/x/sys/unix"
)

// host_inbound_junos_host_counters.go owns the named nft counters attached to
// the #4146 `to-zone junos-host` DENY drop rules in the kernel `xpf_hostinbound`
// chain. These live in the SAME table as the coarse per-zone deny counters
// (host_inbound_counters.go) and the ICMP/ND accept counters
// (host_inbound_accept_counters.go), separated by object-name PREFIX so each
// scraper reads back only its own objects. They are DISTINCT from the coarse
// per-zone deny counters: a coarse deny is "no host-inbound-traffic service
// opened this", a junos-host deny is "a `to-zone junos-host` security policy
// denied this source/application" — the two must not merge.

// hostInboundJunosHostDenyCounterPrefix tags every named counter attached to a
// junos-host DENY drop rule. Distinct from hostInboundDenyCounterPrefix
// ("xpfhi_") and the accept prefix so the metric collectors never cross-count.
const hostInboundJunosHostDenyCounterPrefix = "xpfjh_"

// HostInboundJunosHostDenyCounterName returns the deterministic nft named-counter
// object name for the junos-host DENY drop rules of a given scope (the ingress
// zone name) and family ("ip" or "ip6"). Encoding mirrors
// HostInboundDenyCounterName: xpfjh_<family>_<len>_<scope>, length-prefixed so
// the scope is unambiguously reversible even when it contains '_'/'-'. The scope
// is passed through sanitizeNftIdent (shared with the coarse counters) so the
// bare (unquoted) declaration parses on nft v1.1.6.
func HostInboundJunosHostDenyCounterName(scope, family string) string {
	s := sanitizeNftIdent(scope)
	return fmt.Sprintf("%s%s_%d_%s", hostInboundJunosHostDenyCounterPrefix, family, len(s), s)
}

// HostInboundJunosHostChainName names the regular chain holding one ingress
// zone's first-match junos-host rules (#9504). The index is the program's
// position in the rendered program list, which keeps the name unique when two
// zone names sanitize to the same identifier; the sanitized zone keeps
// `nft list` readable.
func HostInboundJunosHostChainName(index int, zone string) string {
	return fmt.Sprintf("junos_host_%d_%s", index, sanitizeNftIdent(zone))
}

// ParseHostInboundJunosHostDenyCounterName reverses
// HostInboundJunosHostDenyCounterName, returning ok=false for any name that is
// not one of our junos-host deny counters so the scraper skips foreign objects.
func ParseHostInboundJunosHostDenyCounterName(name string) (scope, family string, ok bool) {
	rest, found := strings.CutPrefix(name, hostInboundJunosHostDenyCounterPrefix)
	if !found {
		return "", "", false
	}
	fam, afterFam, found := strings.Cut(rest, "_")
	if !found || (fam != "ip" && fam != "ip6") {
		return "", "", false
	}
	lenTok, scopeTok, found := strings.Cut(afterFam, "_")
	if !found {
		return "", "", false
	}
	n, err := strconv.Atoi(lenTok)
	if err != nil || n != len(scopeTok) {
		return "", "", false
	}
	return scopeTok, fam, true
}

// HostInboundJunosHostDenyCount is one scope/family junos-host kernel-drop
// counter read from the `inet xpf_hostinbound` table.
type HostInboundJunosHostDenyCount struct {
	Scope   string // ingress zone name
	Family  string // "ip" or "ip6"
	Packets uint64
	Bytes   uint64
}

// ReadHostInboundJunosHostDenyCounters reads the per-scope/family named
// junos-host DENY counters from the kernel `inet xpf_hostinbound` table via
// netlink. It returns (nil, nil) when the table is absent (no enforcement -> no
// denies) and a wrapped error on a genuine netlink failure, matching
// ReadHostInboundDenyCounters (the #3345 missing-sample contract). Counters
// reset to zero whenever the daemon rebuilds the table, handled by Prometheus
// rate() reset detection.
func ReadHostInboundJunosHostDenyCounters() ([]HostInboundJunosHostDenyCount, error) {
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
		return nil, nil
	}
	objs, err := c.GetObjects(table)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil, nil
		}
		return nil, fmt.Errorf("nftables list objects %s: %w", HostInboundTableName, err)
	}
	var out []HostInboundJunosHostDenyCount
	for _, o := range objs {
		co, ok := o.(*nftables.CounterObj)
		if !ok {
			continue
		}
		scope, family, ok := ParseHostInboundJunosHostDenyCounterName(co.Name)
		if !ok {
			continue
		}
		out = append(out, HostInboundJunosHostDenyCount{
			Scope:   scope,
			Family:  family,
			Packets: co.Packets,
			Bytes:   co.Bytes,
		})
	}
	return out, nil
}
