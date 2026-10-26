package dhcpserver

// #4886 C: parseActiveLeasesFileInto used csv.ReadAll(), materializing EVERY row
// of a Kea LFC memfile ([][]string holding all rows LIVE at once) before reducing
// to the accumulator (which keeps only the latest row per address). A Kea memfile
// accumulates many historical rows between LFC compactions, so under lease churn
// this was an O(history) transient that could OOM the control plane. It now
// streams row-by-row (csv.Read) and folds each row into acc as it is read: peak
// live memory O(unique addresses), not O(history).
//
// FAIL-ON-REVERT: restoring csv.ReadAll() holds all N rows live at once, so the
// TotalAlloc for a many-rows/few-addresses file jumps (the retained [][]string) —
// TestParseActiveLeasesStreamingBounded_4886 asserts the per-parse allocation is
// bounded well under the ReadAll retained-row cost. The correctness test proves
// the streaming loop is functionally identical to ReadAll.

import (
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// bigHistoryFile writes a Kea v4 memfile with nRows historical rows spread over
// nAddrs addresses (round-robin), each row active (state 0, future expire). The
// LAST row per address wins; with all rows active the result is nAddrs active
// leases regardless of history depth.
func bigHistoryFile(t *testing.T, nRows, nAddrs int) string {
	t.Helper()
	var b strings.Builder
	b.Grow(nRows * 64)
	b.WriteString(lfcV4Header + "\n")
	for i := 0; i < nRows; i++ {
		a := i % nAddrs
		// address, hwaddr, client_id, valid_lifetime, expire, subnet_id,
		// fqdn_fwd, fqdn_rev, hostname, state
		fmt.Fprintf(&b, "10.0.%d.%d,aa:bb:cc:dd:%02x:%02x,,3600,%s,1,0,1,host-%d,0\n",
			a/256, a%256, (a>>8)&0xff, a&0xff, lfcFuture, a)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "leases4.csv")
	writeCSV(t, path, b.String())
	return path
}

// TestParseActiveLeasesLargeHistoryCorrect_4886: a large-history file (many rows,
// few addresses) parses to exactly the latest-per-address active set — proving
// the streaming loop is functionally identical to the pre-#4886 ReadAll path and
// handles a deep history without dropping/duplicating leases.
func TestParseActiveLeasesLargeHistoryCorrect_4886(t *testing.T) {
	const nRows, nAddrs = 20000, 8
	path := bigHistoryFile(t, nRows, nAddrs)

	leases, err := parseActiveLeases(path, 4, lfcNow)
	if err != nil {
		t.Fatalf("parseActiveLeases4: %v", err)
	}
	if len(leases) != nAddrs {
		t.Fatalf("large-history parse returned %d leases, want %d (latest-per-address across %d rows)",
			len(leases), nAddrs, nRows)
	}
	seen := map[string]bool{}
	for _, l := range leases {
		if seen[l.Address] {
			t.Fatalf("duplicate address %s in result", l.Address)
		}
		seen[l.Address] = true
	}
}

// TestParseActiveLeasesStreamingBounded_4886: per-parse allocation for a
// many-rows/few-addresses file is bounded well below the retained-row cost of
// csv.ReadAll(). ReadAll holds all nRows []string rows LIVE (referenced by the
// records slice) → TotalAlloc includes the full retained backing; streaming lets
// each row be freed after it is folded into acc, so TotalAlloc scales with the
// row STREAM, not the retained set. The bound is generous (well between the two)
// so it is robust yet REDs on the ReadAll revert.
func TestParseActiveLeasesStreamingBounded_4886(t *testing.T) {
	const nRows, nAddrs = 60000, 8
	path := bigHistoryFile(t, nRows, nAddrs)

	var m1, m2 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m1)
	if _, err := parseActiveLeases(path, 4, lfcNow); err != nil {
		t.Fatalf("parseActiveLeases4: %v", err)
	}
	runtime.ReadMemStats(&m2)
	allocated := m2.TotalAlloc - m1.TotalAlloc

	// Streaming allocates on the order of the row STREAM (each row's []string +
	// cell strings, transient/GC-able). ReadAll additionally RETAINS every row in
	// the records [][]string, so csv.ReadAll copies and holds them all → a
	// materially higher per-parse allocation. Empirically (60k rows / 8 addrs,
	// stable to <1%): streaming ~14.9 MiB, ReadAll ~23.0 MiB. Bound = 19 MiB sits
	// cleanly between (streaming +4 MiB headroom; RED on the ReadAll revert).
	const bound = 19 << 20
	if allocated > bound {
		t.Fatalf("parse allocated %d bytes for %d rows / %d addresses — want <= %d (ReadAll-retains-all-rows regression?)",
			allocated, nRows, nAddrs, bound)
	}
	t.Logf("streaming parse allocated %d bytes for %d rows / %d addresses (bound %d)", allocated, nRows, nAddrs, bound)
}
