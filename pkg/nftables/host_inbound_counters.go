package nftables

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/google/nftables"
	"golang.org/x/sys/unix"
)

// HostInboundTableName is the kernel nftables table that enforces
// `security zones <z> host-inbound-traffic` (#3070). The Go control plane
// (pkg/daemon/daemon_nft.go) renders it via `nft -f -`; this package reads its
// named DROP counters back via netlink for the observability surface (#3361).
const HostInboundTableName = "xpf_hostinbound"

// hostInboundDenyCounterPrefix tags every named counter object attached to a
// host-inbound catch-all DROP rule so the metric scraper can pick our counters
// out of the table and ignore anything else.
const hostInboundDenyCounterPrefix = "xpfhi_"

// HostInboundDenyCounterName returns the deterministic nft named-counter object
// name attached to a host-inbound catch-all DROP for a zone and family ("ip" or
// "ip6"). These counters expose drops that were previously uncounted (#3361).
// Callers use the reserved "junos-host" label when no unique source zone can be
// attributed (currently unzoned and ambiguous-ingress catch-all drops).
//
// Encoding is xpfhi_<family>_<len>_<zone> where <zone> is the zone name passed
// through sanitizeNftIdent and <len> is its byte length. The length prefix
// makes the name unambiguously reversible by ParseHostInboundDenyCounterName
// even when the zone name itself contains '_' or '-' (both legal in a Junos zone
// name AND in a bare nft identifier), so the Prometheus collector recovers the
// zone/family labels straight from the kernel object name without re-deriving
// them from config. family is one of the two fixed tokens "ip"/"ip6" so the
// family/length boundary is never ambiguous.
//
// Sanitization (#3578): this name is emitted both as an nft counter REFERENCE
// (`counter name "<n>"`, which nft accepts quoted) AND as a counter DECLARATION
// (`counter <n> { }`, which nft v1.1.6 requires UNQUOTED — a quoted declaration
// is a hard syntax error). A bare nft identifier accepts only [A-Za-z0-9_.-];
// the Junos lexer additionally permits ':','+','*','%','=',',','<','>' (and '/',
// already rejected for zone names at commit) in a zone name, any of which would
// make the bare declaration fail to parse. sanitizeNftIdent maps every byte
// outside the bare-safe set to '_'. The mapping is length-preserving so the
// <len> prefix stays a valid reverse key, and it is the identity for the common
// zone-name set [A-Za-z0-9_.-] (so existing names/labels are unchanged).
//
// Tradeoff for an exotic zone name (bytes outside [A-Za-z0-9_.-]; only '/' is
// commit-blocked, while ':;+*%=,<>' commit fine): the recovered Prometheus zone
// LABEL is the lossy sanitized form, and two such zones differing only in their
// unsafe bytes (e.g. "a:b" and "a+b") COLLIDE onto one counter object. This is a
// metric-aggregation artifact ONLY — the catch-all DROP rules are per
// (zone, daddr), so there is no security, forwarding, or counter-dedup
// mis-routing: the kernel still drops each zone's host-bound traffic correctly;
// only the two zones' deny COUNTS merge under one label. A hash suffix was
// deliberately NOT used so the object name stays human-readable and the reverse
// lookup stays simple; the collision is operator-self-inflicted via exotic
// naming and bounded to the metric. Without sanitization the zone's ruleset
// would fail to apply at all (no metric whatsoever), so the lossy label is
// strictly better.
func HostInboundDenyCounterName(zone, family string) string {
	z := sanitizeNftIdent(zone)
	return fmt.Sprintf("%s%s_%d_%s", hostInboundDenyCounterPrefix, family, len(z), z)
}

// sanitizeNftIdent maps a string to the byte set nft v1.1.6 accepts in a BARE
// identifier ([A-Za-z0-9_.-]), replacing every other byte with '_'. It is
// length-preserving and allocation-free when the input is already bare-safe.
// See HostInboundDenyCounterName for why declarations cannot be quoted (#3578).
func sanitizeNftIdent(s string) string {
	var b []byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '_', c == '-', c == '.':
			// safe in a bare nft identifier; leave as-is.
		default:
			if b == nil {
				b = []byte(s)
			}
			b[i] = '_'
		}
	}
	if b == nil {
		return s
	}
	return string(b)
}

// ParseHostInboundDenyCounterName reverses HostInboundDenyCounterName. It returns
// ok=false for any name that is not one of our host-inbound deny counters (wrong
// prefix, unknown family, or a length field that does not match the trailing
// zone), so the scraper silently skips foreign / malformed counter objects.
func ParseHostInboundDenyCounterName(name string) (zone, family string, ok bool) {
	rest, found := strings.CutPrefix(name, hostInboundDenyCounterPrefix)
	if !found {
		return "", "", false
	}
	fam, afterFam, found := strings.Cut(rest, "_")
	if !found || (fam != "ip" && fam != "ip6") {
		return "", "", false
	}
	lenTok, zoneTok, found := strings.Cut(afterFam, "_")
	if !found {
		return "", "", false
	}
	n, err := strconv.Atoi(lenTok)
	if err != nil || n != len(zoneTok) {
		return "", "", false
	}
	return zoneTok, fam, true
}

// HostInboundDenyCount is one zone/family host-inbound kernel-drop counter read
// from the `inet xpf_hostinbound` table.
type HostInboundDenyCount struct {
	Zone    string
	Family  string // "ip" or "ip6"
	Packets uint64
	Bytes   uint64
}

// HostInboundTableState reports what the netlink read observed about the
// `inet xpf_hostinbound` TABLE itself, so a caller can tell a CERTIFIED zero
// from an uncertifiable one (#5719). The deny-counter slice alone cannot: an
// empty slice is produced by three distinct kernel states, and only two of them
// make "0 host-inbound kernel denies" a true statement about enforcement.
type HostInboundTableState int

const (
	// HostInboundTableAbsent: no xpf_hostinbound table is installed — the daemon
	// tore it down because nothing is enforceable, or none was ever loaded. No
	// enforcement means no denies, so an aggregate 0 IS authoritative. This is
	// also the zero value returned alongside a non-nil error, where it carries no
	// meaning: callers MUST check the error first.
	HostInboundTableAbsent HostInboundTableState = iota
	// HostInboundTableCounterless: the table is INSTALLED but carries no named
	// counter object at all. That is the signature of the #5644 M37 cold-boot
	// fail-closed FENCE — buildHostInboundFencePayload (and its netlink twin
	// buildHostInboundFenceNetlink) render the mandatory admits plus catch-all
	// DROPs with "NO per-service accepts, NO named counters" — and of a zero-drop
	// fence shell. The kernel can be ACTIVELY DROPPING host-bound traffic while
	// exposing no counter to attribute those drops to, so an aggregate 0 is NOT
	// authoritative: the caller must mark it unavailable (the #3345 /
	// #3681-H05 "counter unavailable != zero" contract) rather than publish it.
	//
	// A REAL host-inbound generation is distinguishable and does NOT land here:
	// it declares the three #4759 global ICMP/ND ACCEPT counters
	// UNCONDITIONALLY (both buildHostInboundFilterPayload and the netlink
	// buildHostInboundNetlink iterate HostInboundAcceptCounterTypes up front), so
	// a real table always carries >=1 named counter object even in the one
	// generation that installs no per-zone catch-all DROP (a junos-host
	// program-only ruleset). That is precisely why the discriminator is "no
	// counter OBJECTS in the table", not "no DENY counters" — the latter would
	// false-alarm on that legitimate, fully-enforcing generation.
	HostInboundTableCounterless
	// HostInboundTableCounted: the table is installed and carries >=1 named
	// counter object, so what the walk returned reflects real kernel objects.
	// Deny counters that merely happen to read zero land HERE — the objects
	// exist and come back with Packets: 0 — so their aggregate 0 IS
	// authoritative and must stay so.
	HostInboundTableCounted
)

// ReadHostInboundDenyCounters reads the per-zone/family named catch-all DROP
// counters from the kernel `inet xpf_hostinbound` table via netlink (no nft
// shell-out). It returns one entry per host-inbound deny counter currently
// installed, plus the HostInboundTableState the entries were read from.
//
// When the table is absent (no host-inbound-traffic stanza is enforced, so the
// daemon removed it) the function returns (nil, HostInboundTableAbsent, nil): no
// enforcement means no denies, not an error. When the table is PRESENT but
// carries no named counter objects it returns (nil, HostInboundTableCounterless,
// nil) — enforcement may well be live and uncounted (the #5644 cold-boot fence),
// so the caller must NOT publish that 0 as authoritative (#5719). A genuine
// netlink failure is returned so the caller can surface "counter unavailable"
// rather than a misleading zero (the #3345 missing-sample contract the
// Prometheus collector applies to dataplane counters); the state accompanying a
// non-nil error is the zero value and is meaningless.
//
// Counters reset to zero whenever the daemon rebuilds the table (every commit
// and every DHCP/DHCPv6 address change on a dataplane interface, which delete +
// recreate the table); this matches the table lifecycle and is handled by
// Prometheus rate() reset detection.
func ReadHostInboundDenyCounters() ([]HostInboundDenyCount, HostInboundTableState, error) {
	c, err := nftables.New()
	if err != nil {
		return nil, HostInboundTableAbsent, fmt.Errorf("nftables conn: %w", err)
	}
	tables, err := c.ListTablesOfFamily(nftables.TableFamilyINet)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil, HostInboundTableAbsent, nil
		}
		return nil, HostInboundTableAbsent, fmt.Errorf("nftables list tables: %w", err)
	}
	var table *nftables.Table
	for _, t := range tables {
		if t != nil && t.Name == HostInboundTableName {
			table = t
			break
		}
	}
	if table == nil {
		// No host-inbound enforcement installed -> no denies.
		return nil, HostInboundTableAbsent, nil
	}
	objs, err := c.GetObjects(table)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			// The table went away between the list and the object walk: same as
			// never having been there.
			return nil, HostInboundTableAbsent, nil
		}
		return nil, HostInboundTableAbsent, fmt.Errorf("nftables list objects %s: %w", HostInboundTableName, err)
	}
	counts, state := classifyHostInboundDenyObjects(objs)
	return counts, state, nil
}

// classifyHostInboundDenyObjects walks one table's objects into the deny-counter
// slice and the present-table half of HostInboundTableState. It is split out of
// the netlink read so the counterless-vs-counted discrimination — the #5719
// property — is unit-testable without a live kernel or CAP_NET_ADMIN (the
// absent-table half is decided by the caller before this runs).
//
// The state is keyed on whether the table carries ANY named counter object, not
// on whether the returned deny slice is empty: see HostInboundTableCounterless
// for why a real generation always carries the #4759 accept counters and so can
// never be mistaken for a fence.
func classifyHostInboundDenyObjects(objs []nftables.Obj) ([]HostInboundDenyCount, HostInboundTableState) {
	var out []HostInboundDenyCount
	namedCounters := 0
	for _, o := range objs {
		co, ok := o.(*nftables.CounterObj)
		if !ok {
			continue
		}
		namedCounters++
		zone, family, ok := ParseHostInboundDenyCounterName(co.Name)
		if !ok {
			continue
		}
		out = append(out, HostInboundDenyCount{
			Zone:    zone,
			Family:  family,
			Packets: co.Packets,
			Bytes:   co.Bytes,
		})
	}
	if namedCounters == 0 {
		return out, HostInboundTableCounterless
	}
	return out, HostInboundTableCounted
}
