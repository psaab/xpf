package dhcpserver

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// ddns_leases_test.go: the state-aware Kea-memfile lease parser tests. These
// stayed in pkg/dhcpserver in #2691 P1a (the parser — ddns_leases.go — stays
// here because it is entangled with the lease-sync memfile fallback); the
// reconcile-engine / state-store / hostname / rfc2136 tests moved to pkg/ddns.

// ---- state-aware lease parser ----

func writeCSV(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestParseActiveLeases4FiltersStateAndExpiry(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "leases4.csv")
	// expire epoch far in the future for active rows; a past epoch for the
	// stale row. now = 1_700_000_000.
	writeCSV(t, path, `address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state
10.0.0.10,aa:bb:cc:dd:ee:01,,3600,1900000000,1,0,1,host-a,0
10.0.0.11,aa:bb:cc:dd:ee:02,,3600,1900000000,1,0,1,host-b,1
10.0.0.12,aa:bb:cc:dd:ee:03,,3600,1900000000,1,0,1,host-c,2
10.0.0.13,aa:bb:cc:dd:ee:04,,3600,1600000000,1,0,1,host-d,0
`)
	now := time.Unix(1_700_000_000, 0)
	leases, err := parseActiveLeases(path, 4, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(leases) != 1 {
		t.Fatalf("want 1 active lease, got %d: %+v", len(leases), leases)
	}
	if leases[0].Address != "10.0.0.10" || leases[0].HostName != "host-a" {
		t.Fatalf("wrong active lease: %+v", leases[0])
	}
	if leases[0].Identity != "mac:aa:bb:cc:dd:ee:01" {
		t.Fatalf("identity = %q", leases[0].Identity)
	}
}

func TestParseActiveLeases4ClientIDPreferred(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "leases4.csv")
	writeCSV(t, path, `address,hwaddr,client_id,valid_lifetime,expire,subnet_id,hostname,state
10.0.0.10,aa:bb:cc:dd:ee:01,01aabbcc,3600,1900000000,1,host-a,0
`)
	leases, err := parseActiveLeases(path, 4, time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(leases) != 1 || leases[0].Identity != "cid:01aabbcc" {
		t.Fatalf("client-id not preferred: %+v", leases)
	}
}

func TestParseActiveLeases4FQDNForwardFlagSplitsNameSource(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "leases4.csv")
	writeCSV(t, path, `address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,hostname,state
10.0.0.10,aa:bb:cc:dd:ee:01,,3600,1900000000,1,0,host-a,0
10.0.0.11,aa:bb:cc:dd:ee:02,,3600,1900000000,1,1,client.example.com,0
`)
	leases, err := parseActiveLeases(path, 4, time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(leases) != 2 {
		t.Fatalf("want 2 active leases, got %d: %+v", len(leases), leases)
	}
	if leases[0].HostName != "host-a" || leases[0].ClientFQDN != "" {
		t.Fatalf("hostname row parsed wrong: %+v", leases[0])
	}
	if leases[1].HostName != "" || leases[1].ClientFQDN != "client.example.com" {
		t.Fatalf("fqdn row parsed wrong: %+v", leases[1])
	}
}

func TestParseActiveLeases6DUIDIAID(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "leases6.csv")
	writeCSV(t, path, `address,duid,valid_lifetime,expire,subnet_id,pref_lifetime,lease_type,iaid,prefix_len,fqdn_fwd,fqdn_rev,hostname,hwaddr,state
2001:db8::5,00:01:00:01:de:ad,3600,1900000000,1,1800,0,7,128,1,1,host-6,aa:bb,0
2001:db8::6,00:01:00:01:be:ef,3600,1900000000,1,1800,0,8,128,1,1,host-7,aa:cc,2
`)
	leases, err := parseActiveLeases(path, 6, time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(leases) != 1 {
		t.Fatalf("want 1 active v6 lease, got %d: %+v", len(leases), leases)
	}
	if leases[0].Identity != "duid:00:01:00:01:de:ad/7" {
		t.Fatalf("v6 identity = %q", leases[0].Identity)
	}
	if leases[0].Family != 6 {
		t.Fatalf("family = %d", leases[0].Family)
	}
}

func TestParseActiveLeasesLastRowWins(t *testing.T) {
	// A renewal appends a new row; the later row supersedes. An address
	// whose final row is declined/expired must drop out entirely.
	dir := t.TempDir()
	path := filepath.Join(dir, "leases4.csv")
	writeCSV(t, path, `address,hwaddr,client_id,valid_lifetime,expire,subnet_id,hostname,state
10.0.0.10,aa,,3600,1900000000,1,old-name,0
10.0.0.10,aa,,3600,1900000000,1,new-name,0
10.0.0.20,bb,,3600,1900000000,1,host-x,0
10.0.0.20,bb,,3600,1900000000,1,host-x,1
`)
	leases, err := parseActiveLeases(path, 4, time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(leases) != 1 {
		t.Fatalf("want 1 lease (10.0.0.10 with new-name), got %d: %+v", len(leases), leases)
	}
	if leases[0].Address != "10.0.0.10" || leases[0].HostName != "new-name" {
		t.Fatalf("last-row-wins failed: %+v", leases[0])
	}
}

// TestParseActiveLeasesInactiveThenActiveReclaim proves the #1387 MAJOR-3
// boundary: an inactive (declined/expired-reclaimed) row that PRECEDES a
// later active row for the SAME address must NOT suppress that active row.
// Last-row-wins means the final active allocation reclaims the address and
// it appears in the output. Against the pre-fix parser (which tombstoned the
// address out of the output order and never re-added it when a later active
// row arrived) the reclaimed address is silently OMITTED, so this test fails
// pre-fix.
func TestParseActiveLeasesInactiveThenActiveReclaim(t *testing.T) {
	dir := t.TempDir()
	now := time.Unix(1_700_000_000, 0)

	t.Run("inactive then active", func(t *testing.T) {
		path := filepath.Join(dir, "leases-ia.csv")
		// 10.0.0.10: declined (state=1) THEN a fresh active allocation.
		writeCSV(t, path, `address,hwaddr,client_id,valid_lifetime,expire,subnet_id,hostname,state
10.0.0.10,aa,,3600,1900000000,1,old-decl,1
10.0.0.10,bb,,3600,1900000000,1,new-active,0
`)
		leases, err := parseActiveLeases(path, 4, now)
		if err != nil {
			t.Fatal(err)
		}
		if len(leases) != 1 {
			t.Fatalf("reclaimed active lease omitted: got %d leases %+v", len(leases), leases)
		}
		if leases[0].Address != "10.0.0.10" || leases[0].HostName != "new-active" {
			t.Fatalf("wrong reclaimed lease: %+v", leases[0])
		}
	})

	t.Run("active inactive active", func(t *testing.T) {
		path := filepath.Join(dir, "leases-aia.csv")
		// 10.0.0.20: active, then expired-reclaimed (state=2), then active
		// again — the FINAL active row must win.
		writeCSV(t, path, `address,hwaddr,client_id,valid_lifetime,expire,subnet_id,hostname,state
10.0.0.20,aa,,3600,1900000000,1,first,0
10.0.0.20,aa,,3600,1900000000,1,gone,2
10.0.0.20,cc,,3600,1900000000,1,final,0
`)
		leases, err := parseActiveLeases(path, 4, now)
		if err != nil {
			t.Fatal(err)
		}
		if len(leases) != 1 {
			t.Fatalf("final active row omitted: got %d leases %+v", len(leases), leases)
		}
		if leases[0].HostName != "final" {
			t.Fatalf("active->inactive->active did not keep final: %+v", leases[0])
		}
	})

	t.Run("inactive last row still drops", func(t *testing.T) {
		path := filepath.Join(dir, "leases-final-inactive.csv")
		// 10.0.0.30: active then declined — final row inactive => dropped.
		writeCSV(t, path, `address,hwaddr,client_id,valid_lifetime,expire,subnet_id,hostname,state
10.0.0.30,aa,,3600,1900000000,1,was-active,0
10.0.0.30,aa,,3600,1900000000,1,now-declined,1
`)
		leases, err := parseActiveLeases(path, 4, now)
		if err != nil {
			t.Fatal(err)
		}
		if len(leases) != 0 {
			t.Fatalf("address with final inactive row should drop: %+v", leases)
		}
	})
}

// TestParseActiveLeasesMangledHeaderErrors proves the AGY MINOR-1 / MAJOR-4
// re-open fix: a Kea memfile whose header is MANGLED (a required column
// missing or renamed) must return a parse ERROR — not a silent empty lease
// set — so the reconciler marks the family untrusted and SKIPS the
// destructive delete pass. Otherwise every owned record of that family
// looks expired and is mass-deleted, the exact failure MAJOR-4 prevents,
// reached through the header-validation gap. The two sub-cases exercise the
// header-mangle path end to end through Reconcile (owned records preserved)
// and the direct-parser path (error returned). Against the pre-fix code the
// parser returns 0 leases with no error, so the owned record is deleted and
// these assertions fail.
func TestParseActiveLeasesMangledHeaderErrors(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)

	t.Run("missing address column errors", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "leases-noaddr.csv")
		// Header lacks "address"; the body row still carries a value where
		// address would be. Pre-fix: every addr reads "" -> all rows skipped
		// -> 0 leases, no error.
		writeCSV(t, path, `hwaddr,client_id,valid_lifetime,expire,subnet_id,hostname,state
aa:bb:cc:dd:ee:01,,3600,1900000000,1,host-a,0
`)
		if _, err := parseActiveLeases(path, 4, now); err == nil {
			t.Fatal("missing 'address' column must produce a parse error")
		}
	})

	t.Run("missing state column errors", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "leases-nostate.csv")
		writeCSV(t, path, `address,hwaddr,client_id,valid_lifetime,expire,subnet_id,hostname
10.0.0.10,aa:bb:cc:dd:ee:01,,3600,1900000000,1,host-a
`)
		if _, err := parseActiveLeases(path, 4, now); err == nil {
			t.Fatal("missing 'state' column must produce a parse error")
		}
	})

	t.Run("mangled header does not mass-delete via Reconcile", func(t *testing.T) {
		// End-to-end of the keaLeaseParser → pkg/ddns engine wiring (#2691 P1a):
		// a mangled v4 header makes the real Kea parser error, and the engine
		// must surface that error AND preserve the owned record (the
		// untrusted-family fail-safe). Driven through the exported test seam +
		// OwnedForTesting accessor — no pkg/ddns internals.
		up := newFakeUpdater()
		m := testDDNS(t, up)
		p4, _ := m.DDNSLeasePaths()
		cfg := &config.DHCPServerConfig{
			DynamicDNS: &config.DHCPDynamicDNSConfig{
				Enabled:    true,
				Domain:     "example.com",
				TTLSeconds: 300,
			},
		}
		// Cycle 1: a valid header -> the v4 lease is published and owned.
		writeCSV(t, p4, `address,hwaddr,client_id,valid_lifetime,expire,subnet_id,hostname,state
10.0.0.10,aa,,3600,1900000000,1,host-a,0
`)
		if err := m.Reconcile(context.Background(), cfg); err != nil {
			t.Fatalf("cycle 1 reconcile: %v", err)
		}
		if !m.OwnedForTesting("mac:aa", "10.0.0.10") {
			t.Fatal("cycle 1 did not record the owned v4 record")
		}
		// Cycle 2: the v4 header is now mangled (no "state" column). The
		// reconcile must surface an error and NOT delete the owned record.
		up.deletes = nil
		writeCSV(t, p4, `address,hwaddr,client_id,valid_lifetime,expire,subnet_id,hostname
10.0.0.10,aa,,3600,1900000000,1,host-a
`)
		err := m.Reconcile(context.Background(), cfg)
		if err == nil {
			t.Fatal("mangled header must surface a parse error from Reconcile")
		}
		for _, d := range up.deletes {
			if d.Addr.Is4() {
				t.Fatalf("v4 record deleted on a mangled header: %s", d.FQDN)
			}
		}
		if !m.OwnedForTesting("mac:aa", "10.0.0.10") {
			t.Fatal("v4 owned record mass-deleted on a mangled header (MAJOR-4 re-opened)")
		}
	})
}

// TestParseActiveLeasesCaseInsensitiveHeader proves AGY MINOR-2: header
// column names are matched case-insensitively, so a memfile written with
// mixed-case headers ("Address","State", ...) still resolves its columns
// and parses leases correctly. Against the pre-fix case-sensitive cols map
// the columns are not found, every row is skipped, and the parser returns 0
// leases — so this test fails pre-fix.
func TestParseActiveLeasesCaseInsensitiveHeader(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "leases-mixedcase.csv")
	writeCSV(t, path, `Address,HwAddr,Client_ID,Valid_Lifetime,Expire,Subnet_ID,Hostname,State
10.0.0.10,aa:bb:cc:dd:ee:01,,3600,1900000000,1,host-a,0
10.0.0.11,aa:bb:cc:dd:ee:02,,3600,1900000000,1,host-b,1
`)
	leases, err := parseActiveLeases(path, 4, time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatalf("mixed-case header should parse, got error: %v", err)
	}
	if len(leases) != 1 {
		t.Fatalf("want 1 active lease from mixed-case header, got %d: %+v", len(leases), leases)
	}
	if leases[0].Address != "10.0.0.10" || leases[0].HostName != "host-a" {
		t.Fatalf("mixed-case columns resolved wrong: %+v", leases[0])
	}
	if leases[0].Identity != "mac:aa:bb:cc:dd:ee:01" {
		t.Fatalf("identity from mixed-case header = %q", leases[0].Identity)
	}
}

// reconcileWithLeaseHeaders is a helper: seed an owned record from a healthy
// lease file, then re-run Reconcile with a (possibly mangled) header and
// assert the owned record is preserved + the reconcile surfaces an error.
// Used by the Codex-r3 MAJOR-A (naming) and MAJOR-B (identity) tests.
func assertReconcilePreservesOwned(t *testing.T, family int, healthyHeader, healthyRow, mangledHeader, mangledRow, ownIdentity, ownAddr string) {
	t.Helper()
	up := newFakeUpdater()
	m := testDDNS(t, up)
	cfg := &config.DHCPServerConfig{
		DynamicDNS: &config.DHCPDynamicDNSConfig{
			Enabled:    true,
			Domain:     "example.com",
			TTLSeconds: 300,
		},
	}
	p4, p6 := m.DDNSLeasePaths()
	leasePath := p4
	if family == 6 {
		leasePath = p6
	}
	// Cycle 1: healthy header -> the lease is published and owned.
	writeCSV(t, leasePath, healthyHeader+"\n"+healthyRow+"\n")
	if err := m.Reconcile(context.Background(), cfg); err != nil {
		t.Fatalf("cycle 1 reconcile: %v", err)
	}
	if !m.OwnedForTesting(ownIdentity, ownAddr) {
		t.Fatalf("cycle 1 did not record owned record %s|%s; ownedKeys=%v", ownIdentity, ownAddr, m.OwnedKeysForTesting())
	}
	// Cycle 2: mangled header -> must error, must not delete the owned record.
	up.deletes = nil
	writeCSV(t, leasePath, mangledHeader+"\n"+mangledRow+"\n")
	if err := m.Reconcile(context.Background(), cfg); err == nil {
		t.Fatal("mangled header must surface a parse error from Reconcile")
	}
	if len(up.deletes) != 0 {
		t.Fatalf("records deleted on a mangled header (record loss): %v", up.deleteNames())
	}
	if !m.OwnedForTesting(ownIdentity, ownAddr) {
		t.Fatalf("owned record %s|%s lost on a mangled header", ownIdentity, ownAddr)
	}
}

// assertReconcilePreservesOwnedRow is like assertReconcilePreservesOwned but
// writes the mangled cycle-2 file as header-only when mangledRow is empty
// (the Codex-r4 header-only trigger), avoiding an ambiguous trailing blank
// line. A non-empty mangledRow is appended as a normal data row.
func assertReconcilePreservesOwnedRow(t *testing.T, family int, healthyHeader, healthyRow, mangledHeader, mangledRow, ownIdentity, ownAddr string) {
	t.Helper()
	up := newFakeUpdater()
	m := testDDNS(t, up)
	cfg := &config.DHCPServerConfig{
		DynamicDNS: &config.DHCPDynamicDNSConfig{
			Enabled: true, Domain: "example.com", TTLSeconds: 300,
		},
	}
	p4, p6 := m.DDNSLeasePaths()
	leasePath := p4
	if family == 6 {
		leasePath = p6
	}
	writeCSV(t, leasePath, healthyHeader+"\n"+healthyRow+"\n")
	if err := m.Reconcile(context.Background(), cfg); err != nil {
		t.Fatalf("cycle 1 reconcile: %v", err)
	}
	if !m.OwnedForTesting(ownIdentity, ownAddr) {
		t.Fatalf("cycle 1 did not record owned record %s|%s; ownedKeys=%v", ownIdentity, ownAddr, m.OwnedKeysForTesting())
	}
	up.deletes = nil
	mangled := mangledHeader + "\n"
	if mangledRow != "" {
		mangled += mangledRow + "\n"
	}
	writeCSV(t, leasePath, mangled)
	if err := m.Reconcile(context.Background(), cfg); err == nil {
		t.Fatal("mangled header must surface a parse error from Reconcile")
	}
	if len(up.deletes) != 0 {
		t.Fatalf("records deleted on a mangled header-only file (record loss): %v", up.deleteNames())
	}
	if !m.OwnedForTesting(ownIdentity, ownAddr) {
		t.Fatalf("owned record %s|%s lost on a mangled header-only file", ownIdentity, ownAddr)
	}
}

// TestParseActiveLeasesNamingColumnRequired proves Codex-r3 MAJOR-A: if the
// naming column ("hostname") is missing while address+state remain, the
// pre-fix parser SUCCEEDS with empty names, Reconcile skips every lease as
// unnamed (empty desired set), and the destructive pass mass-deletes all
// owned records. The naming column is now REQUIRED, so a header without it
// errors and Reconcile marks the family untrusted. Against pre-fix code the
// parser returns named=0 with no error -> the owned record is mass-deleted ->
// this fails.
func TestParseActiveLeasesNamingColumnRequired(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	// Direct parser: missing hostname errors (v4 and v6).
	t.Run("v4 missing hostname errors", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "l4.csv")
		writeCSV(t, path, `address,hwaddr,client_id,valid_lifetime,expire,subnet_id,state
10.0.0.10,aa,,3600,1900000000,1,0
`)
		if _, err := parseActiveLeases(path, 4, now); err == nil {
			t.Fatal("v4 header missing 'hostname' must error")
		}
	})
	t.Run("v6 missing hostname errors", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "l6.csv")
		writeCSV(t, path, `address,duid,valid_lifetime,expire,subnet_id,iaid,state
2001:db8::5,00:01,3600,1900000000,1,7,0
`)
		if _, err := parseActiveLeases(path, 6, now); err == nil {
			t.Fatal("v6 header missing 'hostname' must error")
		}
	})
	// End-to-end: a missing hostname must not mass-delete owned records.
	t.Run("v4 missing hostname does not mass-delete", func(t *testing.T) {
		assertReconcilePreservesOwned(t, 4,
			"address,hwaddr,client_id,valid_lifetime,expire,subnet_id,hostname,state",
			"10.0.0.10,aa,,3600,1900000000,1,host-a,0",
			"address,hwaddr,client_id,valid_lifetime,expire,subnet_id,state",
			"10.0.0.10,aa,,3600,1900000000,1,0",
			"mac:aa", "10.0.0.10")
	})
}

// TestParseActiveLeasesIdentityColumnRequired proves Codex-r3 MAJOR-B: if the
// per-family identity columns disappear (v4: client_id+hwaddr; v6: duid+iaid)
// while address/state/hostname remain, the pre-fix parser SUCCEEDS but the
// identity collapses to the address fallback, so the owned record keyed by the
// PRIOR real identity no longer matches desired -> delete + re-add churn (and
// record loss if the re-add upsert fails). The identity columns are now
// REQUIRED per family, so a header without them errors and Reconcile marks the
// family untrusted. Against pre-fix code the parser succeeds and the owned
// record is deleted+rekeyed -> this fails.
func TestParseActiveLeasesIdentityColumnRequired(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	t.Run("v4 missing client_id+hwaddr errors", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "l4.csv")
		writeCSV(t, path, `address,valid_lifetime,expire,subnet_id,hostname,state
10.0.0.10,3600,1900000000,1,host-a,0
`)
		if _, err := parseActiveLeases(path, 4, now); err == nil {
			t.Fatal("v4 header missing identity columns must error")
		}
	})
	t.Run("v6 missing duid+iaid errors", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "l6.csv")
		writeCSV(t, path, `address,valid_lifetime,expire,subnet_id,hostname,state
2001:db8::5,3600,1900000000,1,host-6,0
`)
		if _, err := parseActiveLeases(path, 6, now); err == nil {
			t.Fatal("v6 header missing identity columns must error")
		}
	})
	// End-to-end: a v4 header losing its identity columns must not delete the
	// record keyed by the prior real identity.
	t.Run("v4 missing identity does not churn owned record", func(t *testing.T) {
		assertReconcilePreservesOwned(t, 4,
			"address,hwaddr,client_id,valid_lifetime,expire,subnet_id,hostname,state",
			"10.0.0.10,aa,,3600,1900000000,1,host-a,0",
			"address,valid_lifetime,expire,subnet_id,hostname,state",
			"10.0.0.10,3600,1900000000,1,host-a,0",
			"mac:aa", "10.0.0.10")
	})
	// End-to-end: a v6 header losing its identity columns must not churn.
	t.Run("v6 missing identity does not churn owned record", func(t *testing.T) {
		assertReconcilePreservesOwned(t, 6,
			"address,duid,valid_lifetime,expire,subnet_id,iaid,hostname,state",
			"2001:db8::5,00:01,3600,1900000000,1,7,host-6,0",
			"address,valid_lifetime,expire,subnet_id,hostname,state",
			"2001:db8::5,3600,1900000000,1,host-6,0",
			"duid:00:01/7", "2001:db8::5")
	})
}

// TestParseActiveLeasesOptionalColumnsDegradeSafely proves the columns kept
// OPTIONAL (fqdn_fwd, expire, subnet_id) do not error and degrade safely: a
// healthy header without them still parses the lease (named, active). This
// documents the deliberate boundary — only columns whose absence is
// destructive are required.
func TestParseActiveLeasesOptionalColumnsDegradeSafely(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "l4.csv")
	// No fqdn_fwd, no expire, no subnet_id — all the required columns present.
	writeCSV(t, path, `address,hwaddr,client_id,hostname,state
10.0.0.10,aa,,host-a,0
`)
	leases, err := parseActiveLeases(path, 4, time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatalf("optional columns absent should still parse, got error: %v", err)
	}
	if len(leases) != 1 || leases[0].HostName != "host-a" || leases[0].Identity != "mac:aa" {
		t.Fatalf("optional-absent lease parsed wrong: %+v", leases)
	}
}

// TestLeaseColumnValueLowerCasesLookupName proves the Codex-r3 MINOR: the
// column lookup lower-cases its NAME argument so the case-insensitivity
// invariant holds at the call site, not merely because every caller passes a
// lower-case literal. The cols map (built lower-cased) is queried with a
// MIXED-case lookup name; it must still resolve. Against the pre-fix lookup
// (cols[name], no lower-casing of name) a mixed-case lookup name misses and
// returns "" — so this test fails pre-fix. This is the direct guard the
// documented invariant requires.
func TestLeaseColumnValueLowerCasesLookupName(t *testing.T) {
	// cols keys are lower-case (as built from the header). Look them up with
	// mixed/upper-case names — they must resolve.
	cols := map[string]int{"address": 0, "client_id": 1, "hostname": 2}
	fields := []string{"10.0.0.10", "01deadbeef", "host-a"}
	cases := []struct{ name, want string }{
		{"Address", "10.0.0.10"},
		{"ADDRESS", "10.0.0.10"},
		{"Client_ID", "01deadbeef"},
		{"HostName", "host-a"},
		{"absent", ""},
	}
	for _, tc := range cases {
		if got := leaseColumnValue(cols, fields, tc.name); got != tc.want {
			t.Fatalf("leaseColumnValue(%q) = %q, want %q (lookup name not lower-cased)", tc.name, got, tc.want)
		}
	}
}

// TestParseActiveLeasesHeaderOnlyValidatesBeforeEmptyReturn proves the
// Codex-r4 MAJOR: the required-column validation must run BEFORE the
// zero-data-row trusted-empty return, so a header-only file (1 record =
// header, no data rows) with a MANGLED header still ERRORS instead of
// short-circuiting to a trusted (nil, nil) empty result. Against the pre-fix
// code the `len(records) < 2` early return fired first, returning trusted
// empty for a mangled header-only file → Reconcile ran the destructive pass →
// mass-delete. These sub-cases assert the parser errors and (end to end) no
// owned record is deleted.
func TestParseActiveLeasesHeaderOnlyValidatesBeforeEmptyReturn(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)

	// Direct parser: a header-only file with a mangled header errors.
	t.Run("v4 header-only missing hostname errors", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "l4.csv")
		// Header line only (no data rows), missing the required "hostname".
		writeCSV(t, path, "address,hwaddr,client_id,valid_lifetime,expire,subnet_id,state\n")
		if _, err := parseActiveLeases(path, 4, now); err == nil {
			t.Fatal("header-only file with a mangled header must error (not trusted-empty)")
		}
	})
	t.Run("v4 header-only missing identity errors", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "l4.csv")
		writeCSV(t, path, "address,valid_lifetime,expire,subnet_id,hostname,state\n")
		if _, err := parseActiveLeases(path, 4, now); err == nil {
			t.Fatal("header-only file missing identity columns must error")
		}
	})
	t.Run("v6 header-only missing identity errors", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "l6.csv")
		writeCSV(t, path, "address,valid_lifetime,expire,subnet_id,hostname,state\n")
		if _, err := parseActiveLeases(path, 6, now); err == nil {
			t.Fatal("v6 header-only file missing identity columns must error")
		}
	})

	// End to end: a header-only mangled file must NOT mass-delete owned
	// records (the same destructive vector reached through the header-only
	// trigger). assertReconcilePreservesOwned seeds via a healthy header then
	// re-runs with the mangled (here: header-only) header.
	t.Run("v4 header-only mangled does not mass-delete via Reconcile", func(t *testing.T) {
		assertReconcilePreservesOwnedRow(t, 4,
			"address,hwaddr,client_id,valid_lifetime,expire,subnet_id,hostname,state",
			"10.0.0.10,aa,,3600,1900000000,1,host-a,0",
			"address,hwaddr,client_id,valid_lifetime,expire,subnet_id,state", // header-only, missing hostname
			"", // no data row
			"mac:aa", "10.0.0.10")
	})
}

// TestParseActiveLeasesHeaderOnlyValidGoodIsTrustedEmpty proves the legitimate
// case stays correct: a file with a VALID header and ZERO data rows is a
// trusted zero-lease (nil, nil) — a genuinely-empty Kea, so clearing owned DNS
// records is correct. End to end, an owned record IS removed when the lease
// file becomes header-only-valid.
func TestParseActiveLeasesHeaderOnlyValidGoodIsTrustedEmpty(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	t.Run("v4 valid header-only is trusted empty", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "l4.csv")
		writeCSV(t, path, "address,hwaddr,client_id,valid_lifetime,expire,subnet_id,hostname,state\n")
		leases, err := parseActiveLeases(path, 4, now)
		if err != nil {
			t.Fatalf("valid header-only file must be trusted-empty, got error: %v", err)
		}
		if len(leases) != 0 {
			t.Fatalf("valid header-only file should yield 0 leases, got %d", len(leases))
		}
	})
	t.Run("v4 valid header-only clears owned record via Reconcile", func(t *testing.T) {
		up := newFakeUpdater()
		m := testDDNS(t, up)
		cfg := &config.DHCPServerConfig{
			DynamicDNS: &config.DHCPDynamicDNSConfig{
				Enabled: true, Domain: "example.com", TTLSeconds: 300,
			},
		}
		// Cycle 1: one active lease -> owned.
		writeCSV(t, mustP4(m), "address,hwaddr,client_id,valid_lifetime,expire,subnet_id,hostname,state\n"+
			"10.0.0.10,aa,,3600,1900000000,1,host-a,0\n")
		if err := m.Reconcile(context.Background(), cfg); err != nil {
			t.Fatalf("cycle 1 reconcile: %v", err)
		}
		if !m.OwnedForTesting("mac:aa", "10.0.0.10") {
			t.Fatal("cycle 1 did not record owned record")
		}
		// Cycle 2: the lease genuinely drains -> valid header, no data rows.
		// The owned record must be cleaned (trusted-empty permits deletion).
		writeCSV(t, mustP4(m), "address,hwaddr,client_id,valid_lifetime,expire,subnet_id,hostname,state\n")
		if err := m.Reconcile(context.Background(), cfg); err != nil {
			t.Fatalf("cycle 2 reconcile: %v", err)
		}
		if m.OwnedForTesting("mac:aa", "10.0.0.10") {
			t.Fatal("valid header-only (genuinely empty) did not clear the owned record")
		}
	})
}

// TestParseActiveLeasesEmptyFileIsUntrusted proves a 0-record EXISTING file
// (no header at all — anomalous, e.g. mid-write/truncated) fails SAFE: it
// errors rather than returning a trusted-empty result, so Reconcile does not
// mass-delete on an unvalidatable file. A genuinely MISSING file stays a
// trusted-empty (handled by os.IsNotExist, asserted separately).
func TestParseActiveLeasesEmptyFileIsUntrusted(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)

	t.Run("zero-byte existing file errors", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "l4.csv")
		writeCSV(t, path, "") // exists, zero records
		if _, err := parseActiveLeases(path, 4, now); err == nil {
			t.Fatal("a 0-record existing lease file must error (fail-safe untrusted), not trusted-empty")
		}
	})

	t.Run("missing file stays trusted-empty", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "does-not-exist.csv")
		leases, err := parseActiveLeases(path, 4, now)
		if err != nil {
			t.Fatalf("a genuinely missing file must be trusted-empty, got error: %v", err)
		}
		if leases != nil {
			t.Fatalf("missing file should yield nil leases, got %+v", leases)
		}
	})
}

// TestParseActiveLeasesDuplicateColumnErrors proves the Codex-r5 MAJOR: a
// header with a DUPLICATED column name is AMBIGUOUS — building cols would
// overwrite the earlier index with the last occurrence, so cols[name] could
// point at the wrong/empty column → leases read empty/wrong → wrong desired
// set → the destructive pass deletes owned records. A healthy Kea header has
// all-unique column names, so the parser rejects ANY duplicate column (not
// just duplicate required columns) BEFORE any lookup. Against the pre-fix code
// the duplicate silently overwrites and parsing proceeds (no error), so these
// assertions fail.
func TestParseActiveLeasesDuplicateColumnErrors(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)

	t.Run("duplicate required column (two address) errors", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "l4.csv")
		// Two "address" columns; the second (empty) would win under overwrite.
		writeCSV(t, path, `address,hwaddr,client_id,valid_lifetime,expire,subnet_id,hostname,state,address
10.0.0.10,aa,,3600,1900000000,1,host-a,0,
`)
		if _, err := parseActiveLeases(path, 4, now); err == nil {
			t.Fatal("duplicate 'address' column must error (ambiguous header)")
		}
	})

	t.Run("duplicate required column (two state) errors", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "l4.csv")
		writeCSV(t, path, `address,hwaddr,client_id,valid_lifetime,expire,subnet_id,hostname,state,state
10.0.0.10,aa,,3600,1900000000,1,host-a,0,2
`)
		if _, err := parseActiveLeases(path, 4, now); err == nil {
			t.Fatal("duplicate 'state' column must error (ambiguous header)")
		}
	})

	t.Run("duplicate case-insensitive (Address + address) errors", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "l4.csv")
		writeCSV(t, path, `Address,hwaddr,client_id,valid_lifetime,expire,subnet_id,hostname,state,ADDRESS
10.0.0.10,aa,,3600,1900000000,1,host-a,0,
`)
		if _, err := parseActiveLeases(path, 4, now); err == nil {
			t.Fatal("case-insensitive duplicate 'address' columns must error")
		}
	})

	t.Run("duplicate optional column also errors (reject ANY duplicate)", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "l4.csv")
		// subnet_id is OPTIONAL, but a duplicate makes the header ambiguous,
		// so we reject ANY duplicate column name (not just required ones).
		writeCSV(t, path, `address,hwaddr,client_id,valid_lifetime,expire,subnet_id,hostname,state,subnet_id
10.0.0.10,aa,,3600,1900000000,1,host-a,0,2
`)
		if _, err := parseActiveLeases(path, 4, now); err == nil {
			t.Fatal("duplicate optional column must error (any duplicate => ambiguous)")
		}
	})

	t.Run("v6 duplicate identity column errors", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "l6.csv")
		writeCSV(t, path, `address,duid,valid_lifetime,expire,subnet_id,iaid,hostname,state,duid
2001:db8::5,00:01,3600,1900000000,1,7,host-6,0,bad
`)
		if _, err := parseActiveLeases(path, 6, now); err == nil {
			t.Fatal("v6 duplicate 'duid' column must error")
		}
	})

	// End to end: a duplicated required column must NOT mass-delete owned
	// records (the same destructive vector, duplicate-column trigger).
	t.Run("duplicate column does not mass-delete via Reconcile", func(t *testing.T) {
		assertReconcilePreservesOwnedRow(t, 4,
			"address,hwaddr,client_id,valid_lifetime,expire,subnet_id,hostname,state",
			"10.0.0.10,aa,,3600,1900000000,1,host-a,0",
			"address,hwaddr,client_id,valid_lifetime,expire,subnet_id,hostname,state,address", // dup address
			"10.0.0.10,aa,,3600,1900000000,1,host-a,0,",
			"mac:aa", "10.0.0.10")
	})
}

// TestParseActiveLeasesExtraAndReorderedColumnsTolerated proves the deliberate
// boundary: extra/unknown columns and a reordered header are TOLERATED (parse
// succeeds) because lookups are by name, not position. Only ambiguity
// (duplicate) and missing required columns are errors. This documents that the
// duplicate rejection does not over-broadly reject healthy-but-unusual headers.
func TestParseActiveLeasesExtraAndReorderedColumnsTolerated(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)

	t.Run("extra unknown column tolerated", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "l4.csv")
		writeCSV(t, path, `address,hwaddr,client_id,valid_lifetime,expire,subnet_id,hostname,state,user_context,pool_id
10.0.0.10,aa,,3600,1900000000,1,host-a,0,{},5
`)
		leases, err := parseActiveLeases(path, 4, now)
		if err != nil {
			t.Fatalf("extra columns should be tolerated, got error: %v", err)
		}
		if len(leases) != 1 || leases[0].HostName != "host-a" {
			t.Fatalf("extra-column lease parsed wrong: %+v", leases)
		}
	})

	t.Run("reordered columns tolerated", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "l4.csv")
		// Columns in a non-standard order; resolved by name.
		writeCSV(t, path, `state,hostname,address,client_id,hwaddr,expire,subnet_id
0,host-a,10.0.0.10,01cafe,aa,1900000000,1
`)
		leases, err := parseActiveLeases(path, 4, now)
		if err != nil {
			t.Fatalf("reordered columns should be tolerated, got error: %v", err)
		}
		if len(leases) != 1 || leases[0].Address != "10.0.0.10" ||
			leases[0].HostName != "host-a" || leases[0].Identity != "cid:01cafe" {
			t.Fatalf("reordered-column lease parsed wrong: %+v", leases)
		}
	})
}

// TestParseActiveLeasesRaggedRowUntrusted proves the Codex-r6 MAJOR: a data
// row too SHORT to supply a required column makes the source unreliable, so
// the parser errors (untrusted → Reconcile skips the destructive diff) rather
// than silently mis-reading the row and dropping its lease. A torn/truncated
// Kea memfile append leaves a ragged row; reading a required column past the
// row's length returns "" (bounds-safe but NOT delete-safe), which would drop
// the lease and delete its owned DNS record. Against the pre-fix code the
// ragged row reads "" for the missing fields → lease dropped → record deleted.
func TestParseActiveLeasesRaggedRowUntrusted(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)

	t.Run("v4 row too short for a required column errors", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "l4.csv")
		// Valid header; the data row is truncated before reaching hostname
		// and state (a torn append). It contains address but not the later
		// required columns.
		writeCSV(t, path, `address,hwaddr,client_id,valid_lifetime,expire,subnet_id,hostname,state
10.0.0.10,aa,,3600
`)
		if _, err := parseActiveLeases(path, 4, now); err == nil {
			t.Fatal("a ragged v4 row (too short for required columns) must error (untrusted)")
		}
	})

	t.Run("v4 row reaches address but not state/hostname errors", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "l4.csv")
		// Required v4 columns include hostname (idx 6) and state (idx 7); a
		// row of 7 fields (idx 0..6) reaches hostname but not state.
		writeCSV(t, path, `address,hwaddr,client_id,valid_lifetime,expire,subnet_id,hostname,state
10.0.0.10,aa,,3600,1900000000,1,host-a
`)
		if _, err := parseActiveLeases(path, 4, now); err == nil {
			t.Fatal("a row missing the trailing required 'state' column must error")
		}
	})

	t.Run("v6 ragged row errors", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "l6.csv")
		writeCSV(t, path, `address,duid,valid_lifetime,expire,subnet_id,iaid,hostname,state
2001:db8::5,00:01,3600
`)
		if _, err := parseActiveLeases(path, 6, now); err == nil {
			t.Fatal("a ragged v6 row must error (untrusted)")
		}
	})

	// End to end: a ragged row must NOT mass-delete owned records.
	t.Run("ragged row does not mass-delete via Reconcile", func(t *testing.T) {
		assertReconcilePreservesOwnedRow(t, 4,
			"address,hwaddr,client_id,valid_lifetime,expire,subnet_id,hostname,state",
			"10.0.0.10,aa,,3600,1900000000,1,host-a,0",
			"address,hwaddr,client_id,valid_lifetime,expire,subnet_id,hostname,state", // valid header
			"10.0.0.10,aa,,3600", // ragged data row
			"mac:aa", "10.0.0.10")
	})
}

// TestParseActiveLeasesExtraFieldRowTolerated proves the boundary is not
// over-broad: a data row with MORE fields than the header (extra trailing
// fields) is TOLERATED — only too-SHORT-for-a-required-column rows trigger
// untrust. Lookups are by name/index, so trailing extras are ignored.
func TestParseActiveLeasesExtraFieldRowTolerated(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "l4.csv")
	// The data row has two extra trailing fields beyond the header width.
	writeCSV(t, path, `address,hwaddr,client_id,valid_lifetime,expire,subnet_id,hostname,state
10.0.0.10,aa,,3600,1900000000,1,host-a,0,extra1,extra2
`)
	leases, err := parseActiveLeases(path, 4, time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatalf("a row with extra trailing fields should be tolerated, got error: %v", err)
	}
	if len(leases) != 1 || leases[0].Address != "10.0.0.10" || leases[0].HostName != "host-a" {
		t.Fatalf("extra-field row parsed wrong: %+v", leases)
	}
}
