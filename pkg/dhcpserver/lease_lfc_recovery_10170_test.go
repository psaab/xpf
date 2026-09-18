package dhcpserver

import (
	"path/filepath"
	"testing"
)

// #10170 (residual 2): the in-tree memfile reader must recover an orphaned
// lease-bearing `.completed`.
//
// Upstream Kea startup loads `<file>.completed` INSTEAD of `.2`/`.1` when it
// exists (memfile_lease_mgr.cc loadLeasesFromFiles, verified for #10148 M1);
// Kea's startup source selection is the contract: when `.completed` exists it
// is loaded INSTEAD of `.2`/`.1`, with the current append log applied after
// it. When `.completed` is absent, the reader falls back to `.2 → .1 →
// current`. `.output` stays ignored: Kea never loads it.

const lfcV6Header10170 = "address,duid,valid_lifetime,expire,subnet_id,pref_lifetime,lease_type,iaid,prefix_len,fqdn_fwd,fqdn_rev,hostname,hwaddr,state"

// TestParseActiveLeasesRecoversOrphanedCompleted10170 is the RED core: with
// `.2`/`.1` removed by a torn rotation and leases only in `.completed`, the
// destructive reader must return them instead of trusted-empty.
func TestParseActiveLeasesRecoversOrphanedCompleted10170(t *testing.T) {
	t.Run("v4", func(t *testing.T) {
		dir := t.TempDir()
		cur := filepath.Join(dir, "leases4.csv")
		// Torn rotation: .2 and .1 removed, rename of .completed → .2 never ran.
		writeCSV(t, cur+".completed", lfcV4Header+"\n"+
			"10.0.0.50,aa:bb:cc:dd:ee:50,,3600,"+lfcFuture+",1,0,1,host-orphan,0\n")
		writeCSV(t, cur, lfcV4Header+"\n") // fresh header-only append log

		leases, err := parseActiveLeases4(cur, lfcNow)
		if err != nil {
			t.Fatalf("parseActiveLeases4 with orphaned .completed: %v", err)
		}
		if len(leases) != 1 || leases[0].Address != "10.0.0.50" {
			t.Fatalf("orphaned .completed lease lost: got %+v, want [10.0.0.50] "+
				"(trusted-empty on a torn rotation reaps every DDNS record)", leases)
		}
	})
	t.Run("v6", func(t *testing.T) {
		dir := t.TempDir()
		cur := filepath.Join(dir, "leases6.csv")
		writeCSV(t, cur+".completed", lfcV6Header10170+"\n"+
			"2001:db8::50,00:01:00:01:de:ad,3600,"+lfcFuture+",1,1800,0,7,128,1,1,host-orphan,aa:bb,0\n")
		writeCSV(t, cur, lfcV6Header10170+"\n")

		leases, err := parseActiveLeases6(cur, lfcNow)
		if err != nil {
			t.Fatalf("parseActiveLeases6 with orphaned .completed: %v", err)
		}
		if len(leases) != 1 || leases[0].Address != "2001:db8::50" {
			t.Fatalf("orphaned v6 .completed lease lost: got %+v", leases)
		}
	})
	t.Run("v4/completed-suppresses-older-generation-files", func(t *testing.T) {
		dir := t.TempDir()
		cur := filepath.Join(dir, "leases4.csv")
		// `.completed` is authoritative over the old `.1` generation. A row
		// present only in `.1` must not leak into the reader's result.
		writeCSV(t, cur+".completed", lfcV4Header+"\n"+
			"10.0.0.10,aa:bb:cc:dd:ee:10,,3600,"+lfcFuture+",1,0,1,host-a,0\n"+
			"10.0.0.11,aa:bb:cc:dd:ee:11,,3600,"+lfcFuture+",1,0,1,host-b,0\n")
		writeCSV(t, cur+".1", lfcV4Header+"\n"+
			"10.0.0.12,aa:bb:cc:dd:ee:12,,3600,"+lfcFuture+",1,0,1,stale-generation,0\n")
		writeCSV(t, cur, lfcV4Header+"\n")

		leases, err := parseActiveLeases4(cur, lfcNow)
		if err != nil {
			t.Fatalf("parseActiveLeases4 with completed precedence: %v", err)
		}
		got := map[string]bool{}
		for _, l := range leases {
			got[l.Address] = true
		}
		if len(leases) != 2 || !got["10.0.0.10"] || !got["10.0.0.11"] {
			t.Fatalf("older .1 generation leaked or completed rows lost: got %+v", leases)
		}
		if got["10.0.0.12"] {
			t.Fatalf("older .1 row survived Kea completed precedence: %+v", leases)
		}
	})
}

// TestParseLeaseCSVRecoversOrphanedCompleted10170 is the display twin: `show`
// must not blank a lease the promoted Kea itself would load.
func TestParseLeaseCSVRecoversOrphanedCompleted10170(t *testing.T) {
	dir := t.TempDir()
	cur := filepath.Join(dir, "leases4.csv")
	writeCSV(t, cur+".completed", lfcV4Header+"\n"+
		"10.0.0.50,aa:bb:cc:dd:ee:50,,3600,"+lfcFuture+",1,0,1,host-orphan,0\n")
	writeCSV(t, cur, lfcV4Header+"\n")

	leases, err := parseLeaseCSV(cur, lfcNow)
	if err != nil {
		t.Fatalf("parseLeaseCSV with orphaned .completed: %v", err)
	}
	if len(leases) != 1 || leases[0].Address != "10.0.0.50" {
		t.Fatalf("display lost the orphaned .completed lease: got %+v", leases)
	}
}

// TestCompletedNeverOverridesNewerCanonical10170 pins the read order:
// `.completed` is authoritative over `.2`/`.1`, while a current append row
// remains newer and may override it.
func TestCompletedNeverOverridesNewerCanonical10170(t *testing.T) {
	t.Run("renewal-in-current-wins", func(t *testing.T) {
		dir := t.TempDir()
		cur := filepath.Join(dir, "leases4.csv")
		writeCSV(t, cur+".completed", lfcV4Header+"\n"+
			"10.0.0.10,aa:bb:cc:dd:ee:10,,3600,1750000000,1,0,1,host-old,0\n")
		writeCSV(t, cur+".2", lfcV4Header+"\n"+
			"10.0.0.10,aa:bb:cc:dd:ee:10,,3600,1750000000,1,0,1,stale-generation,0\n")
		writeCSV(t, cur, lfcV4Header+"\n"+
			"10.0.0.10,aa:bb:cc:dd:ee:10,,3600,"+lfcFuture+",1,0,1,host-new,0\n")

		leases, err := parseActiveLeases4(cur, lfcNow)
		if err != nil {
			t.Fatalf("parseActiveLeases4: %v", err)
		}
		if len(leases) != 1 || leases[0].HostName != "host-new" {
			t.Fatalf("current renewal did not override completed: %+v", leases)
		}
	})
	t.Run("older-generation-release-is-ignored", func(t *testing.T) {
		dir := t.TempDir()
		cur := filepath.Join(dir, "leases4.csv")
		// `.completed` remains authoritative even when a stale `.1` carries a
		// contradictory tombstone; current is the only newer source.
		writeCSV(t, cur+".completed", lfcV4Header+"\n"+
			"10.0.0.10,aa:bb:cc:dd:ee:10,,3600,"+lfcFuture+",1,0,1,host-a,0\n")
		writeCSV(t, cur+".1", lfcV4Header+"\n"+
			"10.0.0.10,aa:bb:cc:dd:ee:10,,3600,"+lfcFuture+",1,0,1,host-a,2\n")
		writeCSV(t, cur, lfcV4Header+"\n")

		leases, err := parseActiveLeases4(cur, lfcNow)
		if err != nil {
			t.Fatalf("parseActiveLeases4: %v", err)
		}
		if len(leases) != 1 || leases[0].Address != "10.0.0.10" {
			t.Fatalf("stale .1 tombstone overrode completed: %+v", leases)
		}
	})
	t.Run("release-in-current-tombstones", func(t *testing.T) {
		dir := t.TempDir()
		cur := filepath.Join(dir, "leases4.csv")
		writeCSV(t, cur+".completed", lfcV4Header+"\n"+
			"10.0.0.10,aa:bb:cc:dd:ee:10,,3600,"+lfcFuture+",1,0,1,host-a,0\n")
		writeCSV(t, cur, lfcV4Header+"\n"+
			"10.0.0.10,aa:bb:cc:dd:ee:10,,3600,"+lfcFuture+",1,0,1,host-a,2\n")

		leases, err := parseActiveLeases4(cur, lfcNow)
		if err != nil {
			t.Fatalf("parseActiveLeases4: %v", err)
		}
		if len(leases) != 0 {
			t.Fatalf("current tombstone did not remove completed row: %+v", leases)
		}
	})
}

// TestOrphanedCompletedAnomalyFailsClosed pins the fail-safe: an existing
// but headerless `.completed` that the reader depends on (canonical files gone)
// must veto the destructive read, not read as trusted-empty.
func TestOrphanedCompletedAnomalyFailsClosed10170(t *testing.T) {
	dir := t.TempDir()
	cur := filepath.Join(dir, "leases4.csv")
	writeCSV(t, cur+".completed", "") // exists, no header: anomalous
	writeCSV(t, cur, lfcV4Header+"\n")

	if _, err := parseActiveLeases4(cur, lfcNow); err == nil {
		t.Fatal("headerless orphaned .completed read as trusted-empty; " +
			"the destructive diff would reap every record on a corrupt file")
	}
}
