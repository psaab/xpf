package dhcpserver

import (
	"path/filepath"
	"testing"
	"time"
)

// #5796: xpf treated the current Kea memfile (kea-leases{4,6}.csv) as the
// COMPLETE lease DB, but after Lease File Cleanup (LFC) begins that file is only
// the new append log — the active set spans Kea's LFC file set: PREVIOUS
// (<f>.2, the compacted result of the last cleanup) and INPUT (<f>.1, the
// current file moved aside at the start of a cleanup). Reading only the current
// file LOSES leases that live in .2/.1, and a header-only current file then
// falsely authorized the DESTRUCTIVE DDNS trusted-empty delete (fail-open).
//
// Suffix mapping is authoritative from Kea src
// (memfile_lease_mgr.cc appendSuffix): .1 = INPUT, .2 = PREVIOUS. Chronological
// read order (oldest → newest, last-row-wins) is therefore .2 → .1 → current.
//
// FAIL-ON-REVERT: restore the single-current-file read in parseActiveLeases /
// parseLeaseCSVDegradable (drop the keaLFCLeaseFilePaths loop, open only `path`) → the
// leases that live in .2/.1 vanish → TestLFC5796_* below go RED (union tests
// return 0 leases; the order test resurrects a released lease; the display test
// shows nothing).

const (
	lfcV4Header = "address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state"
	lfcFuture   = "1900000000" // > now
	lfcPast     = "1600000000" // < now
)

var lfcNow = time.Unix(1_700_000_000, 0)

// TestLFC5796_UnionAcrossFileSet: active leases living ONLY in the previous
// (.2) and input (.1) files are returned even when the current file is a fresh
// header-only append log. This is the core lease-loss bug AND the destructive
// header-only-authorizes-mass-delete bug (invariant 5): a header-only current
// with leases in .2/.1 must NOT be trusted-empty.
func TestLFC5796_UnionAcrossFileSet(t *testing.T) {
	dir := t.TempDir()
	cur := filepath.Join(dir, "leases4.csv")

	// PREVIOUS (.2): the compacted set from the last LFC — lease A + B active.
	writeCSV(t, cur+".2", lfcV4Header+"\n"+
		"10.0.0.10,aa:bb:cc:dd:ee:10,,3600,"+lfcFuture+",1,0,1,host-a,0\n"+
		"10.0.0.11,aa:bb:cc:dd:ee:11,,3600,"+lfcFuture+",1,0,1,host-b,0\n")
	// INPUT (.1): the pre-cleanup current file moved aside — lease C active.
	writeCSV(t, cur+".1", lfcV4Header+"\n"+
		"10.0.0.12,aa:bb:cc:dd:ee:12,,3600,"+lfcFuture+",1,0,1,host-c,0\n")
	// CURRENT: freshly rotated header-only append log (no data rows yet).
	writeCSV(t, cur, lfcV4Header+"\n")

	leases, err := parseActiveLeases4(cur, lfcNow)
	if err != nil {
		t.Fatalf("parseActiveLeases4: %v", err)
	}
	// Destructive safety: header-only current + leases in .2/.1 is NOT
	// trusted-empty. Pre-fix this returned nil (→ DDNS mass-delete).
	if len(leases) != 3 {
		t.Fatalf("want 3 active leases across the LFC set (A/.2 B/.2 C/.1); got %d: %+v", len(leases), leases)
	}
	got := map[string]bool{}
	for _, l := range leases {
		got[l.Address] = true
	}
	for _, want := range []string{"10.0.0.10", "10.0.0.11", "10.0.0.12"} {
		if !got[want] {
			t.Fatalf("lease %s from the previous/input file was LOST (single-file read regression): %+v", want, leases)
		}
	}
}

// TestLFC5796_ChronologicalOrderLastRowWins: a lease active in PREVIOUS (.2)
// but RELEASED/expired in the current file must be dropped (current supersedes
// previous), and a renewal in the current file must win its newer attributes.
// If the merge order were reversed (current before previous), the stale .2 row
// would resurrect a released lease — a correctness inversion.
func TestLFC5796_ChronologicalOrderLastRowWins(t *testing.T) {
	dir := t.TempDir()
	cur := filepath.Join(dir, "leases4.csv")

	// PREVIOUS (.2): A active with an OLD hostname; D active.
	writeCSV(t, cur+".2", lfcV4Header+"\n"+
		"10.0.0.10,aa:bb:cc:dd:ee:10,,3600,"+lfcFuture+",1,0,1,prev-name,0\n"+
		"10.0.0.40,aa:bb:cc:dd:ee:40,,3600,"+lfcFuture+",1,0,1,host-d,0\n")
	// CURRENT: A RENEWED with a NEW hostname (supersede); D EXPIRED (past
	// expire → tombstone; a released/expired lease must not be resurrected).
	writeCSV(t, cur, lfcV4Header+"\n"+
		"10.0.0.10,aa:bb:cc:dd:ee:10,,3600,"+lfcFuture+",1,0,1,curr-name,0\n"+
		"10.0.0.40,aa:bb:cc:dd:ee:40,,3600,"+lfcPast+",1,0,1,host-d,0\n")

	leases, err := parseActiveLeases4(cur, lfcNow)
	if err != nil {
		t.Fatalf("parseActiveLeases4: %v", err)
	}
	if len(leases) != 1 {
		t.Fatalf("want exactly 1 active lease (A renewed; D released); got %d: %+v", len(leases), leases)
	}
	if leases[0].Address != "10.0.0.10" {
		t.Fatalf("released lease D=10.0.0.40 was resurrected (wrong merge order): %+v", leases)
	}
	if leases[0].HostName != "curr-name" {
		t.Fatalf("current-file renewal did not supersede the previous row: hostname=%q want curr-name", leases[0].HostName)
	}
}

// TestLFC5796_NoLFCUnchanged: with no .1/.2 present (the common steady state),
// the set collapses to exactly the current file — behavior byte-identical to
// the pre-#5796 single-file read.
func TestLFC5796_NoLFCUnchanged(t *testing.T) {
	dir := t.TempDir()
	cur := filepath.Join(dir, "leases4.csv")
	writeCSV(t, cur, lfcV4Header+"\n"+
		"10.0.0.99,aa:bb:cc:dd:ee:99,,3600,"+lfcFuture+",1,0,1,host-z,0\n")

	leases, err := parseActiveLeases4(cur, lfcNow)
	if err != nil {
		t.Fatalf("parseActiveLeases4: %v", err)
	}
	if len(leases) != 1 || leases[0].Address != "10.0.0.99" {
		t.Fatalf("no-LFC single-file read changed: %+v", leases)
	}
}

// TestLFC5796_ExistingMangledSiblingFailsClosed: a PRESENT-but-anomalous
// previous/input file (headerless — mid-write/corrupt) makes the WHOLE family
// untrusted (error), so the DDNS reconciler skips the destructive diff across
// the set rather than trusting a partial union (invariant 4, fail-closed).
func TestLFC5796_ExistingMangledSiblingFailsClosed(t *testing.T) {
	dir := t.TempDir()
	cur := filepath.Join(dir, "leases4.csv")
	// Current is a healthy header-only file (would be trusted-empty alone)...
	writeCSV(t, cur, lfcV4Header+"\n")
	// ...but the PREVIOUS file exists and is headerless (0 records) — anomalous.
	writeCSV(t, cur+".2", "")

	if _, err := parseActiveLeases4(cur, lfcNow); err == nil {
		t.Fatal("an existing headerless .2 (previous) must make the family untrusted (error), not partial-trusted")
	}
}

// TestLFC5796_DisplayUnionAcrossFileSet: the lenient display parser
// (parseLeaseCSVDegradable) must ALSO union the LFC set so `show dhcp server leases` does
// not omit the compacted active set right after an LFC rotation.
func TestLFC5796_DisplayUnionAcrossFileSet(t *testing.T) {
	dir := t.TempDir()
	cur := filepath.Join(dir, "leases4.csv")
	writeCSV(t, cur+".2", lfcV4Header+"\n"+
		"10.0.0.10,aa:bb:cc:dd:ee:10,,3600,"+lfcFuture+",1,0,1,host-a,0\n")
	writeCSV(t, cur, lfcV4Header+"\n") // header-only current

	leases, skipped := parseLeaseCSVDegradable(cur, lfcNow)
	if len(skipped) != 0 {
		t.Fatalf("unreadable files = %v, want none", skipped)
	}
	if len(leases) != 1 || leases[0].Address != "10.0.0.10" {
		t.Fatalf("display omitted the compacted previous-file lease (single-file read regression): %+v", leases)
	}
}

// TestLFC5796_FileSetOrder pins the chronological order the merge relies on:
// previous (.2) → input (.1) → current. A reorder here silently inverts
// last-row-wins.
func TestLFC5796_FileSetOrder(t *testing.T) {
	got := keaLFCLeaseFilePaths("/var/lib/kea/kea-leases4.csv")
	want := []string{
		"/var/lib/kea/kea-leases4.csv.2", // PREVIOUS (oldest / compacted)
		"/var/lib/kea/kea-leases4.csv.1", // INPUT
		"/var/lib/kea/kea-leases4.csv",   // CURRENT (newest)
	}
	if len(got) != len(want) {
		t.Fatalf("keaLFCLeaseFilePaths returned %d paths, want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("keaLFCLeaseFilePaths[%d] = %q, want %q (chronological .2 -> .1 -> current)", i, got[i], want[i])
		}
	}
}
