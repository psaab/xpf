package dhcpserver

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// lease_source_5938_test.go pins the three Kea LFC lease-source behaviors
// carried forward from #5796/#5936:
//   - Invariant 2: the DISPLAY path PREFERS the live lease_cmds socket over the
//     memfile snapshot when the hook is expected (getDisplayLeases).
//   - Invariant 3: the current reader ignores .output/.completed when .2/.1
//     remain; an orphaned lease-bearing .completed remains a reader gap.
//   - Invariant 8: a DEGRADED source (socket-unavailable fallback, or an
//     unreadable sibling) raises a banner on the show path.

// ---- Invariant 2: live lease_cmds socket preference -----------------------

// TestDisplayLeases_PrefersLiveSocket_5938 asserts that when the lease_cmds hook
// is expected (lease-sync enabled) the display reads the LIVE lease DB, not the
// memfile — proven by seeding the socket and the memfile with DIFFERENT leases
// and requiring the socket's lease.
//
// FAIL-ON-REVERT: remove the socket-preference branch in getDisplayLeases (always
// parse the memfile) → the memfile lease is returned instead of the socket lease
// → the "socket lease present / memfile lease absent" assertions go RED.
func TestDisplayLeases_PrefersLiveSocket_5938(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	sock := tmpSocket(t, "k4.sock")
	stub := &stubKea{handler: func(cmd keaCommand) keaResponse {
		if cmd.Command != "lease4-get-all" {
			t.Errorf("unexpected command %q (want lease4-get-all — the live query)", cmd.Command)
		}
		return leaseGetAllResponse([]keaLeaseJSON{
			{IPAddress: "10.0.0.50", HWAddress: "aa:bb:cc:dd:ee:50", SubnetID: 1,
				ValidLft: 3600, CLTT: now.Unix() - 600, State: keaStateDefault, Hostname: "live-host"},
		})
	}}
	dial, stop := startStubKea(t, sock, stub)
	defer stop()

	// The memfile holds a DIFFERENT lease so a memfile read is distinguishable.
	dir := t.TempDir()
	memfile := filepath.Join(dir, "leases4.csv")
	writeCSV(t, memfile, lfcV4Header+"\n"+
		"10.0.0.99,aa:bb:cc:dd:ee:99,,3600,"+lfcFuture+",1,0,1,memfile-host,0\n")

	m := New()
	m.SetLeaseSyncSeamsForTesting(dial, sock, "", memfile, "")
	m.SetLeaseSyncEnabled(true) // the hook is expected

	leases, src := m.getDisplayLeases(4, now)
	if src.Degraded {
		t.Errorf("live socket read must NOT be degraded: %+v", src)
	}
	if src.Origin != leaseSourceLiveSocket {
		t.Errorf("source origin = %q, want %q", src.Origin, leaseSourceLiveSocket)
	}
	if len(leases) != 1 || leases[0].Address != "10.0.0.50" {
		t.Fatalf("want the LIVE socket lease 10.0.0.50, got %+v (a memfile lease 10.0.0.99 means the socket preference was skipped)", leases)
	}
	// The live query was actually issued.
	if got := stub.seen(); len(got) != 1 || got[0].Command != "lease4-get-all" {
		t.Fatalf("live lease4-get-all not issued: %+v", got)
	}
}

// TestDisplayLeases_SocketUnavailableFallsBackDegraded_5938 covers the Invariant 2
// fallback AND the Invariant 8 banner: the hook is expected but the socket is
// unreachable, so the display falls back to the memfile and flags DEGRADED.
//
// FAIL-ON-REVERT (Invariant 8): drop the Degraded flag on the fallback source →
// the banner is empty → the assertions below go RED.
func TestDisplayLeases_SocketUnavailableFallsBackDegraded_5938(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	dir := t.TempDir()
	memfile := filepath.Join(dir, "leases4.csv")
	writeCSV(t, memfile, lfcV4Header+"\n"+
		"10.0.0.99,aa:bb:cc:dd:ee:99,,3600,"+lfcFuture+",1,0,1,memfile-host,0\n")

	m := New()
	// ctrlSocket4 points at a path with no server → dial fails → fallback.
	m.SetLeaseSyncSeamsForTesting(nil, filepath.Join(dir, "missing.sock"), "", memfile, "")
	m.SetLeaseSyncEnabled(true) // the hook is EXPECTED, so the failure is a degradation

	leases, src := m.getDisplayLeases(4, now)
	if !src.Degraded {
		t.Fatalf("an EXPECTED-but-unreachable socket must degrade the source: %+v", src)
	}
	if src.Banner() == "" {
		t.Fatalf("degraded source must produce a non-empty banner")
	}
	// The memfile fallback still returns its leases (display not blanked).
	if len(leases) != 1 || leases[0].Address != "10.0.0.99" {
		t.Fatalf("fallback must return the memfile lease 10.0.0.99, got %+v", leases)
	}
}

// TestDisplayLeases_NoHookNotDegraded_5938 guards against a FALSE degraded banner:
// on a box WITHOUT the lease_cmds hook (lease-sync disabled) the memfile is the
// normal authoritative source, so the read must NOT be degraded.
func TestDisplayLeases_NoHookNotDegraded_5938(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	dir := t.TempDir()
	memfile := filepath.Join(dir, "leases4.csv")
	writeCSV(t, memfile, lfcV4Header+"\n"+
		"10.0.0.99,aa:bb:cc:dd:ee:99,,3600,"+lfcFuture+",1,0,1,memfile-host,0\n")

	m := New()
	m.SetLeaseSyncSeamsForTesting(nil, "", "", memfile, "")
	// leaseSyncEnabled defaults false — the hook is NOT expected.

	leases, src := m.getDisplayLeases(4, now)
	if src.Degraded {
		t.Fatalf("a memfile read on a box without the hook must NOT be degraded: %+v", src)
	}
	if src.Banner() != "" {
		t.Fatalf("healthy source must produce no banner, got %q", src.Banner())
	}
	if len(leases) != 1 || leases[0].Address != "10.0.0.99" {
		t.Fatalf("want the memfile lease 10.0.0.99, got %+v", leases)
	}
}

// TestDisplayLeases_UnreadableSiblingDegraded_5938 is the Invariant 8
// mangled-sibling half: an unreadable LFC sibling (present but EACCES) is SKIPPED
// (not aborted) and the source is flagged degraded, so the remaining leases still
// display with a banner rather than blanking the show.
//
// FAIL-ON-REVERT: revert parseLeaseCSVDegradable to abort on the first file error
// (the parseLeaseCSV behavior) → the show is blanked / errored instead of a
// partial+banner; or drop the Degraded flag → banner empty. Either goes RED.
func TestDisplayLeases_UnreadableSiblingDegraded_5938(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("chmod-000 unreadable-file test is meaningless as root (permission bypass)")
	}
	now := time.Unix(1_700_000_000, 0)
	dir := t.TempDir()
	cur := filepath.Join(dir, "leases4.csv")

	// CURRENT is readable with one active lease.
	writeCSV(t, cur, lfcV4Header+"\n"+
		"10.0.0.10,aa:bb:cc:dd:ee:10,,3600,"+lfcFuture+",1,0,1,host-a,0\n")
	// PREVIOUS (.2) is PRESENT but UNREADABLE (EACCES on open, not IsNotExist).
	unreadable := cur + ".2"
	writeCSV(t, unreadable, lfcV4Header+"\n")
	if err := os.Chmod(unreadable, 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(unreadable, 0o644) })

	m := New()
	m.SetLeaseSyncSeamsForTesting(nil, "", "", cur, "")

	leases, src := m.getDisplayLeases(4, now)
	if !src.Degraded {
		t.Fatalf("an unreadable sibling must degrade the source: %+v", src)
	}
	if src.Banner() == "" {
		t.Fatalf("degraded source must produce a non-empty banner")
	}
	// The readable current file's lease still displays (not blanked by the skip).
	if len(leases) != 1 || leases[0].Address != "10.0.0.10" {
		t.Fatalf("want the readable current lease 10.0.0.10 (skip must not blank the display), got %+v", leases)
	}
}

// ---- Invariant 3: reader handling of intermediates -------------------------

// TestKeaLFCIntermediatesIgnored_5938 proves the display/DDNS reader ignores
// kea-lfc's `.output`, while honoring a lease-bearing `.completed` with Kea's
// startup precedence when it exists. `.output` is redundant because it is
// built from `.1`/.2; `.completed` is authoritative over those older files.
func TestKeaLFCIntermediatesIgnored_5938(t *testing.T) {
	now := lfcNow
	dir := t.TempDir()
	cur := filepath.Join(dir, "leases4.csv")

	// The canonical LFC set the reader DOES ingest (.2 → .1 → current).
	writeCSV(t, cur+".2", lfcV4Header+"\n"+ // PREVIOUS: lease B
		"10.0.0.11,aa:bb:cc:dd:ee:11,,3600,"+lfcFuture+",1,0,1,host-b,0\n")
	writeCSV(t, cur+".1", lfcV4Header+"\n"+ // INPUT: lease A
		"10.0.0.10,aa:bb:cc:dd:ee:10,,3600,"+lfcFuture+",1,0,1,host-a,0\n")
	writeCSV(t, cur, lfcV4Header+"\n") // CURRENT: fresh header-only append log

	// Baseline: resolve WITHOUT any intermediates present.
	base, err := parseLeaseCSV(cur, now)
	if err != nil {
		t.Fatalf("parseLeaseCSV baseline: %v", err)
	}
	baseSet := addrSet(base)
	if !baseSet["10.0.0.10"] || !baseSet["10.0.0.11"] {
		t.Fatalf("baseline must resolve A(.1) + B(.2): %+v", base)
	}

	// Now drop kea-lfc's crash-interrupted intermediates alongside the set.
	// `.output` is kea-lfc's in-progress merge of (.1,.2) — here we also add a
	// BOGUS unique lease C that lives ONLY in .output, to PROVE the reader never
	// opens it (in reality .output ⊆ .1∪.2, so C could not exist; the bogus row
	// makes the skip observable). `.completed` contains the authoritative
	// compacted set Kea would load instead of `.1`/.2.
	writeCSV(t, cur+".output", lfcV4Header+"\n"+
		"10.0.0.10,aa:bb:cc:dd:ee:10,,3600,"+lfcFuture+",1,0,1,host-a,0\n"+
		"10.0.0.77,aa:bb:cc:dd:ee:77,,3600,"+lfcFuture+",1,0,1,ONLY-in-output,0\n")
	writeCSV(t, cur+".completed", lfcV4Header+"\n"+
		"10.0.0.11,aa:bb:cc:dd:ee:11,,3600,"+lfcFuture+",1,0,1,host-b,0\n"+
		"10.0.0.10,aa:bb:cc:dd:ee:10,,3600,"+lfcFuture+",1,0,1,host-a,0\n")

	after, err := parseLeaseCSV(cur, now)
	if err != nil {
		t.Fatalf("parseLeaseCSV with intermediates: %v", err)
	}
	afterSet := addrSet(after)

	// (1) The output intermediate does NOT change the resolved set.
	if len(after) != len(base) || !sameSet(baseSet, afterSet) {
		t.Fatalf(".output changed the resolved set: base=%+v after=%+v", base, after)
	}
	// (2) The lease living ONLY in .output is NOT present — .output is ignored.
	if afterSet["10.0.0.77"] {
		t.Fatalf(".output was READ (lease 10.0.0.77 leaked into the display) — must be ignored")
	}
	// (3) A lease reachable through .output (A) is still covered by .1.
	if !afterSet["10.0.0.10"] {
		t.Fatalf("lease A must remain covered by .1 independent of .output: %+v", after)
	}
}

func addrSet(ls []Lease) map[string]bool {
	m := make(map[string]bool, len(ls))
	for _, l := range ls {
		m[l.Address] = true
	}
	return m
}

func sameSet(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}
