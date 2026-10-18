package dhcpserver

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Issue 14730: merged pre-seed must not resurrect tombstoned leases via stale
// LFC generations, and csvField must not emit a bare CR.

func writeRawMemfile14730(t *testing.T, path, header, row string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(header+"\n"+row), 0644); err != nil {
		t.Fatal(err)
	}
}

func TestPreSeed14730_StillMasteringDropsTombstonedViaLFC(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	expire := now.Unix() + 3600
	// .1 active for 10.0.147.10, current tombstone state=1 for same addr.
	for _, fam := range []int{4, 6} {
		dir := t.TempDir()
		var memfile, header, activeRow, tombRow string
		var peer []SyncLease
		m := New()
		m.unitActive = func(string) (bool, error) { return false, nil }
		if fam == 4 {
			memfile = filepath.Join(dir, "kea-leases4.csv")
			header = keaMemfileHeader4
			activeRow = "10.0.147.10,aa:bb:cc:dd:ee:10,01:aa:bb:cc:dd:ee:10,3600," + itoa14730(expire) + ",1,0,0,old-host,0,,0\n"
			tombRow = "10.0.147.10,aa:bb:cc:dd:ee:10,01:aa:bb:cc:dd:ee:10,3600," + itoa14730(expire) + ",1,0,0,old-host,1,,0\n"
			m.SetLeaseSyncSeamsForTesting(nil, filepath.Join(dir, "no4.sock"), "", memfile, "")
			peer = []SyncLease{{Family: 4, Address: "10.0.147.99", HWAddress: "aa:bb:cc:dd:ee:99", SubnetID: 1, Remaining: 3600, State: keaStateDefault}}
		} else {
			memfile = filepath.Join(dir, "kea-leases6.csv")
			header = keaMemfileHeader6
			activeRow = "2001:db8:147::10,00:03:00:01:aa:bb:cc:dd:ee:10,3600," + itoa14730(expire) + ",1,3600,0,10,128,0,0,old-host,aa:bb:cc:dd:ee:10,0,,0,0,0\n"
			tombRow = "2001:db8:147::10,00:03:00:01:aa:bb:cc:dd:ee:10,3600," + itoa14730(expire) + ",1,3600,0,10,128,0,0,old-host,aa:bb:cc:dd:ee:10,1,,0,0,0\n"
			m.SetLeaseSyncSeamsForTesting(nil, "", filepath.Join(dir, "no6.sock"), "", memfile)
			peer = []SyncLease{{Family: 6, Address: "2001:db8:147::99", DUID: "00:03:00:01:aa:bb:cc:dd:ee:99", IAID: 99, LeaseType: "IA_NA", SubnetID: 1, Remaining: 3600, PreferredRemaining: 3600, State: keaStateDefault}}
		}
		m.SetKeaOwnerLookupForTesting(func() (int, int, bool) { return os.Getuid(), os.Getgid(), true })
		writeRawMemfile14730(t, memfile+".1", header, activeRow)
		// also .2 and .completed variants in separate sub-scenarios would share same mechanism; test .1 here plus check removal of others seeded below
		writeRawMemfile14730(t, memfile+".2", header, activeRow)
		writeRawMemfile14730(t, memfile+".completed", header, activeRow)
		writeRawMemfile14730(t, memfile, header, tombRow)

		var err error
		if fam == 4 {
			err = m.PreSeedMemfileMerged4(context.Background(), peer, now, true)
		} else {
			err = m.PreSeedMemfileMerged6(context.Background(), peer, now, true)
		}
		if err != nil {
			t.Fatalf("fam%d pre-seed: %v", fam, err)
		}
		var got []ddnsLease
		if fam == 4 {
			got, err = parseActiveLeases4(memfile, now)
		} else {
			got, err = parseActiveLeases6(memfile, now)
		}
		if err != nil {
			t.Fatalf("fam%d parse: %v", fam, err)
		}
		for _, g := range got {
			if g.Address == "10.0.147.10" || g.Address == "2001:db8:147::10" {
				t.Fatalf("fam%d tombstoned lease resurrected: %+v", fam, got)
			}
		}
		for _, suf := range []string{".1", ".2", ".completed"} {
			if _, err := os.Stat(memfile + suf); !os.IsNotExist(err) {
				t.Fatalf("fam%d stale generation %s survived (err=%v)", fam, suf, err)
			}
		}
		// control: peer present
		foundPeer := false
		for _, g := range got {
			if strings.HasSuffix(g.Address, ".99") || strings.HasSuffix(g.Address, "::99") {
				foundPeer = true
			}
		}
		if !foundPeer {
			t.Fatalf("fam%d peer lease missing: %+v", fam, got)
		}
	}
}
func TestCSVField14730_EscapesCR(t *testing.T) {
	if got := csvField("host\rname"); got != "hostname" {
		t.Fatalf("csvField CR: got %q, want stripped %q", got, "hostname")
	}
	if got := csvField("a,b"); got != "\"a,b\"" {
		t.Fatalf("csvField comma: got %q", got)
	}
}

func TestPreSeed14730_LiveSocketDropsTombstonedViaLFC(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	expire := now.Unix() + 3600
	dir := t.TempDir()
	memfile := filepath.Join(dir, "kea-leases4.csv")
	sock := tmpSocket(t, "k4live14730.sock")
	stub := &stubKea{handler: func(cmd keaCommand) keaResponse {
		switch cmd.Command {
		case "dhcp-disable":
			return keaResponse{Result: keaResultSuccess, Text: "ok"}
		case "lease4-get-all":
			return leaseGetAllResponse([]keaLeaseJSON{{IPAddress: "10.0.147.50", HWAddress: "aa:bb:cc:dd:ee:50", ClientID: "01:aa:bb:cc:dd:ee:50", SubnetID: 1, ValidLft: 3600, CLTT: now.Unix() - 100, State: keaStateDefault, Hostname: "live-host"}})
		default:
			return keaResponse{Result: keaResultError, Text: "unexpected"}
		}
	}}
	dial, stop := startStubKea(t, sock, stub)
	defer stop()
	m := New()
	m.unitActive = func(string) (bool, error) { return true, nil }
	m.SetLeaseSyncSeamsForTesting(dial, sock, "", memfile, "")
	m.SetKeaOwnerLookupForTesting(func() (int, int, bool) { return os.Getuid(), os.Getgid(), true })
	activeRow := "10.0.147.10,aa:bb:cc:dd:ee:10,01:aa:bb:cc:dd:ee:10,3600," + itoa14730(expire) + ",1,0,0,old-host,0,,0\n"
	tombRow := "10.0.147.10,aa:bb:cc:dd:ee:10,01:aa:bb:cc:dd:ee:10,3600," + itoa14730(expire) + ",1,0,0,old-host,1,,0\n"
	writeRawMemfile14730(t, memfile+".1", keaMemfileHeader4, activeRow)
	writeRawMemfile14730(t, memfile, keaMemfileHeader4, tombRow)
	peer := []SyncLease{{Family: 4, Address: "10.0.147.99", HWAddress: "aa:bb:cc:dd:ee:99", SubnetID: 1, Remaining: 3600, State: keaStateDefault}}
	if err := m.PreSeedMemfileMerged4(context.Background(), peer, now, false); err != nil {
		t.Fatalf("live pre-seed: %v", err)
	}
	got, err := parseActiveLeases4(memfile, now)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	seen := map[string]bool{}
	for _, g := range got {
		seen[g.Address] = true
	}
	if seen["10.0.147.10"] {
		t.Fatalf("live tombstoned lease resurrected: %+v", got)
	}
	if !seen["10.0.147.50"] || !seen["10.0.147.99"] {
		t.Fatalf("live merged set missing local/peer: %+v", got)
	}
	if _, err := os.Stat(memfile + ".1"); !os.IsNotExist(err) {
		t.Fatalf("live stale .1 survived: %v", err)
	}
	// WithAuthority live twin.
	if err := m.PreSeedMemfileMerged4WithAuthority(context.Background(), LeaseSyncSnapshot{Leases: peer, Received: true}, now, false, LeaseSyncAuthority{}); err != nil {
		t.Fatalf("live WithAuthority pre-seed: %v", err)
	}
}

func TestPreSeed14730_CRHostnameRoundTrip(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	dir := t.TempDir()
	memfile := filepath.Join(dir, "kea-leases4.csv")
	m := New()
	m.unitActive = func(string) (bool, error) { return false, nil }
	m.SetLeaseSyncSeamsForTesting(nil, filepath.Join(dir, "no.sock"), "", memfile, "")
	m.SetKeaOwnerLookupForTesting(func() (int, int, bool) { return os.Getuid(), os.Getgid(), true })
	leases := []SyncLease{{Family: 4, Address: "10.0.147.20", HWAddress: "aa:bb:cc:dd:ee:20", SubnetID: 1, Remaining: 3600, Hostname: "host\rname", State: keaStateDefault}}
	if err := m.PreSeedMemfile4(leases, now); err != nil {
		t.Fatalf("PreSeed: %v", err)
	}
	raw, _ := os.ReadFile(memfile)
	got, err := parseActiveLeases4(memfile, now)
	if err != nil {
		t.Fatalf("parse with CR hostname failed (DDNS would halt): %v raw=%q", err, string(raw))
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 lease, got %+v raw=%q", got, string(raw))
	}
	if strings.Contains(got[0].HostName, "\r") || strings.Contains(got[0].HostName, "\n") {
		t.Fatalf("hostname retained control char: %q", got[0].HostName)
	}
}

func itoa14730(v int64) string { return strconv.FormatInt(v, 10) }
