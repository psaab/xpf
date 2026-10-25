package natshow

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"time"

	"github.com/psaab/xpf/pkg/appid"
	"github.com/psaab/xpf/pkg/dataplane"
)

// persistentNATTable resolves the persistent-NAT table ONCE.
//
// #2114/#6743-F2: the daemon hands these renderers a live indirection
// whose GetPersistentNAT() performs a fresh cell load per call, so the
// old `dp.GetPersistentNAT() == nil` check followed by a second
// `dp.GetPersistentNAT().All()` was a check-then-use across two distinct
// resolutions — a setDataplane(nil) in between nil-dereferenced. One
// resolution bound to a local removes the window; the pointer is then
// live for the render, bounded by the #6741 lifetime gap.
func persistentNATTable(dp Reader) *dataplane.PersistentNATTable {
	if dp == nil {
		return nil
	}
	return dp.GetPersistentNAT()
}

// RenderPersistent renders the persistent-NAT bindings table with
// remaining timeout per binding.
//
// It takes NO context because it drives NO conntrack walk. #7315's premise
// listed it among the four walking ShowText topics, citing persistent.go:85
// and :102 — but both of those lines are inside RenderPersistentDetail
// below. This renderer's only dataplane read is PersistentNATTable.All(),
// an O(bindings) snapshot copy of an in-process map taken under that
// table's own RWMutex (#4811); it touches no conntrack bucket and holds no
// session-store lock. A ctx parameter here would be a cancellation
// guarantee with nothing to cancel.
func RenderPersistent(w io.Writer, dp Reader) {
	// #2114/#6743-F2: single resolution — see persistentNATTable.
	table := persistentNATTable(dp)
	if table == nil {
		io.WriteString(w, "Persistent NAT table not available\n")
		return
	}
	bindings := table.All()
	if len(bindings) == 0 {
		io.WriteString(w, "No persistent NAT bindings\n")
		return
	}
	fmt.Fprintf(w, "Total persistent NAT bindings: %d\n\n", len(bindings))
	fmt.Fprintf(w, "%-20s %-8s %-20s %-8s %-15s %-10s\n",
		"Source IP", "SrcPort", "NAT IP", "NATPort", "Pool", "Timeout")
	for _, b := range bindings {
		remaining := time.Until(b.LastSeen.Add(b.Timeout))
		if remaining < 0 {
			remaining = 0
		}
		fmt.Fprintf(w, "%-20s %-8d %-20s %-8d %-15s %-10s\n",
			b.SrcIP, b.SrcPort, b.NatIP, b.NatPort, b.PoolName,
			remaining.Truncate(time.Second))
	}
}

// RenderPersistentDetail renders per-binding detail for persistent-NAT
// bindings, including current session counts per (NAT IP, NAT port).
// ctx is the admission-lease context (#7315); the v4+v6 session tally below
// stops on cancellation via the shared walkSessionValues authority.
func RenderPersistentDetail(ctx context.Context, w io.Writer, dp Reader) {
	// #2114/#6743-F2: single resolution — see persistentNATTable.
	table := persistentNATTable(dp)
	if table == nil {
		io.WriteString(w, "Persistent NAT table not available\n")
		return
	}
	bindings := table.All()
	if len(bindings) == 0 {
		io.WriteString(w, "No persistent NAT bindings\n")
		return
	}
	// natKey uses a unified `netip.Addr` so v4 and v6 NAT IPs share
	// one map. v4 sessions are stored via `netip.AddrFrom4` and v6
	// sessions via `netip.AddrFrom16` — matching the producer side
	// in conntrack/gc.go (Save calls). Persistent-NAT bindings store
	// `netip.Addr` directly so the lookup matches without
	// family-specific shimming (was: hardcoded `b.NatIP.As4()` which
	// panicked on v6 bindings).
	type natKey struct {
		addr netip.Addr
		port uint16
	}
	sessionCounts := make(map[natKey]int)
	scanErr := walkSessionValues(ctx, dp,
		func(val dataplane.SessionValue) {
			if val.IsReverse == 0 && val.Flags&dataplane.SessFlagSNAT != 0 {
				// SessionValue.NATSrcIP is a `uint32` holding the IP's
				// network-order bytes in native-endian word form (the
				// BPF `__be32` is serialized as native-endian uint32 by
				// cilium/ebpf; see CLAUDE.md "Byte Order"). Recover the
				// original 4 bytes via NativeEndian.PutUint32 to match
				// conntrack/gc.go:277-279's storage path. Do NOT use
				// BigEndian here — that would re-swap the bytes.
				var ip4 [4]byte
				binary.NativeEndian.PutUint32(ip4[:], val.NATSrcIP)
				sessionCounts[natKey{netip.AddrFrom4(ip4), val.NATSrcPort}]++
			}
		},
		func(val dataplane.SessionValueV6) {
			if val.IsReverse == 0 && val.Flags&dataplane.SessFlagSNAT != 0 {
				// Match conntrack/gc.go:397 — no Unmap, the binding
				// stores the 16-byte form for v6 NAT.
				sessionCounts[natKey{netip.AddrFrom16(val.NATSrcIP), val.NATSrcPort}]++
			}
		})

	noteSessionScanError(w, scanErr)
	fmt.Fprintf(w, "Total persistent NAT bindings: %d\n\n", len(bindings))
	for i, b := range bindings {
		if i > 0 {
			io.WriteString(w, "\n")
		}
		remaining := time.Until(b.LastSeen.Add(b.Timeout))
		if remaining < 0 {
			remaining = 0
		}
		sessions := sessionCounts[natKey{b.NatIP, b.NatPort}]

		fmt.Fprintf(w, "Persistent NAT binding:\n")
		fmt.Fprintf(w, "  Internal IP:        %s\n", b.SrcIP)
		fmt.Fprintf(w, "  Internal port:      %d\n", b.SrcPort)
		fmt.Fprintf(w, "  Reflexive IP:       %s\n", b.NatIP)
		fmt.Fprintf(w, "  Reflexive port:     %d\n", b.NatPort)
		fmt.Fprintf(w, "  Pool:               %s\n", b.PoolName)
		if b.Protocol != 0 {
			fmt.Fprintf(w, "  Protocol:           %s\n", persistentProtocolName(b.Protocol))
		}
		fmt.Fprintf(w, "  Routing scope:      %d\n", b.RoutingScope)
		// #3193: render the full three-way persistent-NAT permit mode
		// (any-remote-host / target-host / target-host-port), not the
		// pre-#3193 binary any-remote-host flag — an operator could not
		// otherwise tell target-host from target-host-port.
		fmt.Fprintf(w, "  Permit:             %s\n", b.PermitMode())
		for _, remote := range b.PermittedRemotes {
			if remote.Port == 0 {
				fmt.Fprintf(w, "  Permitted remote:   %s (any port)\n", remote.IP)
			} else {
				fmt.Fprintf(w, "  Permitted remote:   %s:%d\n", remote.IP, remote.Port)
			}
		}
		fmt.Fprintf(w, "  Current sessions:   %d\n", sessions)
		fmt.Fprintf(w, "  Left time:          %s\n", remaining.Truncate(time.Second))
		fmt.Fprintf(w, "  Configured timeout: %ds\n", int(b.Timeout.Seconds()))
	}
}

// persistentProtocolName renders a lease protocol number, falling back to
// the decimal number for protocols appid does not name.
func persistentProtocolName(protocol uint8) string {
	if name := appid.ProtocolName(protocol); name != "" {
		return name
	}
	return strconv.Itoa(int(protocol))
}
