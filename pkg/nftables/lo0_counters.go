package nftables

import (
	"errors"
	"fmt"
	"strings"

	"github.com/google/nftables"
	"golang.org/x/sys/unix"
)

// Lo0TableName is the kernel nftables table that enforces the lo0 loopback
// input firewall filter (`interfaces lo0 unit 0 family inet[6] filter input`,
// #3445). The Go control plane (pkg/daemon/daemon_nft.go) renders it via
// `nft -f -`; this package reads its named `then count` counters back via
// netlink for the observability surface (#4422).
const Lo0TableName = "xpf_lo0"

// lo0CounterPrefix namespaces every named counter object attached to a kernel
// lo0 input-filter rule (the `inet xpf_lo0` table) so the object is recognizably
// xpf-managed and always begins with a letter. A bare nft identifier may not
// start with a digit, but a Junos firewall-filter `then count <name>` may, so
// the prefix also guarantees the declaration parses (#3445).
const lo0CounterPrefix = "xpflo0_"

// Lo0CounterName returns the nft named-counter object name that mirrors a
// firewall-filter term's `then count <name>` modifier onto the kernel lo0 input
// chain (#3445). The Junos counter name is passed through sanitizeNftIdent so
// the result is a valid BARE nft identifier — the counter DECLARATION
// (`counter <n> { }`) must be unquoted, which nft v1.1.6 requires (a quoted
// declaration is a hard syntax error, #3578) — and prefixed so it can never
// begin with a digit. The same string is referenced (quoted, `counter name
// "<n>"`) on the rule, so declaration and reference match byte-for-byte.
//
// Two Junos count names that differ only in bytes outside [A-Za-z0-9_.-] (rare;
// Junos count names are normally bare) sanitize to the same object and their
// kernel counts merge. That is a counting artifact ONLY: the lo0 verdict rules
// are independent of the counter object, so no forwarding or verdict effect can
// change. Without sanitization an exotic name would make the whole atomic lo0
// table fail to load, so the lossy name is strictly better than no mirror.
func Lo0CounterName(name string) string {
	return lo0CounterPrefix + sanitizeNftIdent(name)
}

// ParseLo0CounterName reverses Lo0CounterName: it strips the fixed prefix and
// returns the counter label, or ok=false for any object name that is not one of
// our lo0 `then count` counters (wrong prefix), so the scraper silently skips
// foreign / malformed counter objects in the table.
//
// Unlike ParseHostInboundDenyCounterName there is no length-encoding to reverse:
// the object name is just the sanitized Junos count name. A Junos `then count`
// name is normally a bare identifier, so the returned label equals the operator
// name; only an exotic name with bytes outside [A-Za-z0-9_.-] is the lossy
// sanitized form (see Lo0CounterName), which is the same aggregation artifact the
// declaration side already documents.
func ParseLo0CounterName(name string) (counter string, ok bool) {
	rest, found := strings.CutPrefix(name, lo0CounterPrefix)
	if !found || rest == "" {
		return "", false
	}
	return rest, true
}

// lo0ImplicitDiscardCounterPrefix namespaces the per-family counter of the
// lo0 mirror's implicit final discard (#18728). It is deliberately NOT under
// lo0CounterPrefix: every byte string after that prefix is a possible
// operator `then count` name, so an implicit counter there could merge with
// (or, in the Prometheus series, duplicate) an authored one.
const lo0ImplicitDiscardCounterPrefix = "xpflo0implicit_"

// Lo0ImplicitDiscardCounterName returns the counter object of the lo0
// implicit final discard for family "inet" or "inet6" (#18728).
func Lo0ImplicitDiscardCounterName(family string) string {
	return lo0ImplicitDiscardCounterPrefix + family
}

// ParseLo0ImplicitDiscardCounterName reverses Lo0ImplicitDiscardCounterName,
// returning the family ("inet" / "inet6") or ok=false.
func ParseLo0ImplicitDiscardCounterName(name string) (family string, ok bool) {
	rest, found := strings.CutPrefix(name, lo0ImplicitDiscardCounterPrefix)
	if !found || (rest != "inet" && rest != "inet6") {
		return "", false
	}
	return rest, true
}

// Lo0Count is one lo0 input-filter counter read from the `inet xpf_lo0`
// table: a `then count` counter (Counter set) or the per-family implicit
// final discard counter (#18728; ImplicitDiscardFamily set, Counter empty).
type Lo0Count struct {
	Counter string // the (sanitized) Junos `then count <name>`
	// ImplicitDiscardFamily is "inet" or "inet6" for the implicit-discard
	// counter of that family's lo0 filter, "" for a `then count` counter.
	ImplicitDiscardFamily string
	Packets               uint64
	Bytes                 uint64
}

// ReadLo0Counters reads the named `then count` counters from the kernel
// `inet xpf_lo0` lo0 input-filter table via netlink (no nft shell-out). It
// returns one entry per xpf-managed lo0 counter currently installed.
//
// When the table is absent (no lo0 input filter is attached, so the daemon
// removed it) the function returns (nil, nil): no filter means no counts, not an
// error. A genuine netlink failure is returned so the caller can surface
// "counter unavailable" rather than a misleading zero (the #3345 missing-sample
// contract the Prometheus collector applies to dataplane counters).
//
// Counters reset to zero whenever the daemon rebuilds the table (every commit and
// every DHCP/DHCPv6 re-render, which delete + recreate the table, #3445); this
// matches the table lifecycle and is handled by Prometheus rate() reset
// detection, exactly like ReadHostInboundDenyCounters.
func ReadLo0Counters() ([]Lo0Count, error) {
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
		if t != nil && t.Name == Lo0TableName {
			table = t
			break
		}
	}
	if table == nil {
		// No lo0 input filter installed -> no counts.
		return nil, nil
	}
	objs, err := c.GetObjects(table)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil, nil
		}
		return nil, fmt.Errorf("nftables list objects %s: %w", Lo0TableName, err)
	}
	var out []Lo0Count
	for _, o := range objs {
		co, ok := o.(*nftables.CounterObj)
		if !ok {
			continue
		}
		if family, ok := ParseLo0ImplicitDiscardCounterName(co.Name); ok {
			out = append(out, Lo0Count{
				ImplicitDiscardFamily: family,
				Packets:               co.Packets,
				Bytes:                 co.Bytes,
			})
			continue
		}
		counter, ok := ParseLo0CounterName(co.Name)
		if !ok {
			continue
		}
		out = append(out, Lo0Count{
			Counter: counter,
			Packets: co.Packets,
			Bytes:   co.Bytes,
		})
	}
	return out, nil
}

// ResetLo0Counters zeroes the named `then count` counters in the kernel
// `inet xpf_lo0` lo0 input-filter table via netlink, so `clear firewall all`
// resets them together with the helper/dataplane filter counters (#16457).
// Previously they reset only on table rebuild (every commit / DHCP
// re-render), so a clear left the kernel counts — and the
// xpf_lo0_counter_hits_total series — running.
//
// When the table is absent (no lo0 input filter is attached) it returns nil:
// no filter means no counters to reset, mirroring ReadLo0Counters. A genuine
// netlink failure is returned so the clear surfaces it rather than printing
// an unqualified success.
func ResetLo0Counters() error {
	c, err := nftables.New()
	if err != nil {
		return fmt.Errorf("nftables conn: %w", err)
	}
	tables, err := c.ListTablesOfFamily(nftables.TableFamilyINet)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return fmt.Errorf("nftables list tables: %w", err)
	}
	var table *nftables.Table
	for _, t := range tables {
		if t != nil && t.Name == Lo0TableName {
			table = t
			break
		}
	}
	if table == nil {
		return nil
	}
	if _, err := c.ResetObjects(table); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return fmt.Errorf("nftables reset objects %s: %w", Lo0TableName, err)
	}
	return nil
}
