package dhcpserver

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/ddns"
)

// #17009: the HA lease-sync memfile fallback must build its SyncLease from
// authoritative Kea lease fields rather than projecting the DDNS view model.
// The former ddnsLease conversion lost FQDNRev for both families and v6
// HWAddress. Explicit expected values plus full equality pin the remaining
// identity, DNS, family-specific, and lifetime fields as well. The fixture
// compares Kea's real socket representation (no IA_NA prefix_len) with the
// memfile writer's /128; a synthetic socket case pins defensive normalization.

func fallbackLeases17009(t *testing.T, memfile string, family int, now time.Time) []SyncLease {
	t.Helper()
	m := New()
	missing := filepath.Join(t.TempDir(), "missing.sock")
	if family == 4 {
		m.SetLeaseSyncSeamsForTesting(nil, missing, "", memfile, "")
		leases, err := m.GetSyncLeases4(context.Background(), now)
		if err != nil {
			t.Fatalf("GetSyncLeases4 (fallback): %v", err)
		}
		return leases
	}
	m.SetLeaseSyncSeamsForTesting(nil, "", missing, "", memfile)
	leases, err := m.GetSyncLeases6(context.Background(), now)
	if err != nil {
		t.Fatalf("GetSyncLeases6 (fallback): %v", err)
	}
	return leases
}

func socketLeases17009(t *testing.T, family int, rows []keaLeaseJSON, now time.Time) []SyncLease {
	t.Helper()
	sock := tmpSocket(t, "k-17009.sock")
	stub := &stubKea{handler: func(cmd keaCommand) keaResponse {
		return leaseGetAllResponse(rows)
	}}
	dial, stop := startStubKea(t, sock, stub)
	defer stop()
	m := New()
	if family == 4 {
		m.SetLeaseSyncSeamsForTesting(dial, sock, "", "", "")
		leases, err := m.GetSyncLeases4(context.Background(), now)
		if err != nil {
			t.Fatalf("GetSyncLeases4 (socket): %v", err)
		}
		return leases
	}
	m.SetLeaseSyncSeamsForTesting(dial, "", sock, "", "")
	leases, err := m.GetSyncLeases6(context.Background(), now)
	if err != nil {
		t.Fatalf("GetSyncLeases6 (socket): %v", err)
	}
	return leases
}

func writeMemfile17009(t *testing.T, memfile, header string, rows ...string) {
	t.Helper()
	var b []byte
	b = append(b, header...)
	for _, r := range rows {
		b = append(b, r...)
	}
	if err := os.WriteFile(memfile, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestMemfileFallbackMatchesSocketPrimary17009V4(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	expire := now.Unix() + 1800

	dir := t.TempDir()
	memfile := filepath.Join(dir, "kea-leases4.csv")
	// fqdn_fwd=1, fqdn_rev=1: hostname is the client FQDN.
	writeMemfile17009(t, memfile, v4MemfileHeader10428,
		"10.0.170.80,aa:bb:cc:dd:ee:80,01:aa:bb:cc:dd:ee:80,3600,"+
			strconv.FormatInt(expire, 10)+",2,1,1,host-opt61.example,0\n")

	fallback := fallbackLeases17009(t, memfile, 4, now)
	if len(fallback) != 1 {
		t.Fatalf("expected 1 fallback lease, got %d: %+v", len(fallback), fallback)
	}
	wantV4 := SyncLease{
		Family: 4, Address: "10.0.170.80", SubnetID: 2,
		HWAddress: "aa:bb:cc:dd:ee:80", ClientID: "01:aa:bb:cc:dd:ee:80",
		Hostname: "host-opt61.example", FQDNFwd: true, FQDNRev: true,
		ValidLife: 3600, Remaining: 1800, PreferredRemaining: 1800,
		State: keaStateDefault,
	}
	if !reflect.DeepEqual(fallback[0], wantV4) {
		t.Errorf("v4 fallback lost authoritative fields\n got:  %+v\n want: %+v", fallback[0], wantV4)
	}

	primary := socketLeases17009(t, 4, []keaLeaseJSON{{
		IPAddress: "10.0.170.80", HWAddress: "aa:bb:cc:dd:ee:80",
		ClientID: "01:aa:bb:cc:dd:ee:80", SubnetID: 2,
		ValidLft: 3600, CLTT: now.Unix() - 1800, State: keaStateDefault,
		Hostname: "host-opt61.example", FQDNFwd: true, FQDNRev: true,
	}}, now)
	if len(primary) != 1 {
		t.Fatalf("expected 1 socket lease, got %d: %+v", len(primary), primary)
	}
	if !reflect.DeepEqual(fallback[0], primary[0]) {
		t.Errorf("v4 memfile fallback != socket primary\n fallback: %+v\n primary:  %+v", fallback[0], primary[0])
	}
}

func TestMemfileFallbackMatchesSocketPrimary17009V6(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	expire := now.Unix() + 2700

	dir := t.TempDir()
	memfile := filepath.Join(dir, "kea-leases6.csv")
	writeMemfile17009(t, memfile, keaMemfileHeader6+"\n",
		// IA_NA: writer emits prefix_len=128; Kea's socket omits it for non-PD.
		"2001:db8::80,00:03:00:01:aa:bb:cc:dd:ee:80,3600,"+strconv.FormatInt(expire, 10)+",3,2700,0,4242,128,1,1,host6.example,aa:bb:cc:dd:ee:80,0,,0,,0\n",
		// IA_PD: lease_type=2, prefix_len=56, deprecated (pref_lifetime=0).
		"2001:db8:100::,00:03:00:01:aa:bb:cc:dd:ee:81,3600,"+strconv.FormatInt(expire, 10)+",3,0,2,5150,56,0,1,pd6.example,aa:bb:cc:dd:ee:81,0,,0,,0\n")

	fallback := fallbackLeases17009(t, memfile, 6, now)
	if len(fallback) != 2 {
		t.Fatalf("expected 2 fallback leases, got %d: %+v", len(fallback), fallback)
	}
	wantByAddr := map[string]SyncLease{
		"2001:db8::80": {
			Family: 6, Address: "2001:db8::80", SubnetID: 3,
			HWAddress: "aa:bb:cc:dd:ee:80", DUID: "00:03:00:01:aa:bb:cc:dd:ee:80",
			IAID: 4242, LeaseType: "IA_NA", PrefixLen: 0,
			Hostname: "host6.example", FQDNFwd: true, FQDNRev: true,
			ValidLife: 3600, Remaining: 2700, PreferredRemaining: 1800,
			State: keaStateDefault,
		},
		"2001:db8:100::": {
			Family: 6, Address: "2001:db8:100::", SubnetID: 3,
			HWAddress: "aa:bb:cc:dd:ee:81", DUID: "00:03:00:01:aa:bb:cc:dd:ee:81",
			IAID: 5150, LeaseType: "IA_PD", PrefixLen: 56,
			Hostname: "pd6.example", FQDNRev: true,
			ValidLife: 3600, Remaining: 2700, PreferredRemaining: 0,
			State: keaStateDefault,
		},
	}

	pref2700 := 2700
	pref0 := 0
	primary := socketLeases17009(t, 6, []keaLeaseJSON{
		{
			IPAddress: "2001:db8::80", DUID: "00:03:00:01:aa:bb:cc:dd:ee:80",
			IAID: iaidPtr16855(4242), Type: "IA_NA",
			HWAddress: "aa:bb:cc:dd:ee:80", SubnetID: 3,
			ValidLft: 3600, PreferredLft: &pref2700,
			CLTT: now.Unix() - 900, State: keaStateDefault,
			Hostname: "host6.example", FQDNFwd: true, FQDNRev: true,
		},
		{
			IPAddress: "2001:db8:100::", DUID: "00:03:00:01:aa:bb:cc:dd:ee:81",
			IAID: iaidPtr16855(5150), Type: "IA_PD", PrefixLen: 56,
			HWAddress: "aa:bb:cc:dd:ee:81", SubnetID: 3,
			ValidLft: 3600, PreferredLft: &pref0,
			CLTT: now.Unix() - 900, State: keaStateDefault,
			Hostname: "pd6.example", FQDNFwd: false, FQDNRev: true,
		},
	}, now)
	if len(primary) != 2 {
		t.Fatalf("expected 2 socket leases, got %d: %+v", len(primary), primary)
	}
	byAddr := map[string]SyncLease{}
	for _, l := range primary {
		byAddr[l.Address] = l
	}
	for _, fb := range fallback {
		want, ok := wantByAddr[fb.Address]
		if !ok {
			t.Errorf("unexpected fallback lease %s", fb.Address)
			continue
		}
		if !reflect.DeepEqual(fb, want) {
			t.Errorf("v6 fallback lost authoritative fields for %s\n got:  %+v\n want: %+v", fb.Address, fb, want)
		}
		pr, ok := byAddr[fb.Address]
		if !ok {
			t.Errorf("fallback lease %s has no socket counterpart", fb.Address)
			continue
		}
		if !reflect.DeepEqual(fb, pr) {
			t.Errorf("v6 memfile fallback != socket primary for %s\n fallback: %+v\n primary:  %+v", fb.Address, fb, pr)
		}
	}

	for _, leaseType := range []string{"IA_NA", "IA_TA"} {
		synthetic := keaLeaseRowFromSocket(keaLeaseJSON{
			Type: leaseType, PrefixLen: 128,
		}, 6).toSync(now)
		if synthetic.PrefixLen != 0 {
			t.Errorf("synthetic socket %s PrefixLen = %d, want normalized 0",
				leaseType, synthetic.PrefixLen)
		}
	}
}

func TestMemfileWhitespaceLeaseTypeFailsClosed17009(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	expire := strconv.FormatInt(now.Unix()+1800, 10)
	memfile := filepath.Join(t.TempDir(), "kea-leases6.csv")
	writeMemfile17009(t, memfile, keaMemfileHeader6+"\n",
		"2001:db8:170::1,00:03:00:01:aa:bb:cc:dd:ee:91,3600,"+expire+",3,1800, ,4243,56,0,1,ws.example,aa:bb:cc:dd:ee:91,0,,0,,0\n")

	leases := fallbackLeases17009(t, memfile, 6, now)
	if len(leases) != 0 {
		t.Errorf("whitespace lease_type fallback leases = %d, want 0: %+v", len(leases), leases)
	}
	ddnsLeases, err := keaLeaseParser(memfile, 6, now)
	if err != nil {
		t.Fatalf("keaLeaseParser whitespace lease_type: %v", err)
	}
	if len(ddnsLeases) != 1 || ddnsLeases[0].LeaseType != ddns.LeaseTypeUnknown {
		t.Errorf("whitespace lease_type DDNS lease = %+v, want LeaseTypeUnknown", ddnsLeases)
	}
}

func TestMemfileLeaseTypeControls17009(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	expire := strconv.FormatInt(now.Unix()+1800, 10)
	dir := t.TempDir()

	pdMemfile := filepath.Join(dir, "pd.csv")
	writeMemfile17009(t, pdMemfile, keaMemfileHeader6+"\n",
		"2001:db8:170::2,00:03:00:01:aa:bb:cc:dd:ee:92,3600,"+expire+",3,1800,2,4244,56,0,1,pd.example,aa:bb:cc:dd:ee:92,0,,0,,0\n")
	pd := fallbackLeases17009(t, pdMemfile, 6, now)
	if len(pd) != 1 || pd[0].LeaseType != "IA_PD" || pd[0].PrefixLen != 56 {
		t.Fatalf("IA_PD control = %+v, want IA_PD/56", pd)
	}
	pdDDNS, err := keaLeaseParser(pdMemfile, 6, now)
	if err != nil || len(pdDDNS) != 1 || pdDDNS[0].LeaseType != ddns.LeaseTypeIAPD {
		t.Fatalf("IA_PD DDNS control = %+v err=%v, want LeaseTypeIAPD", pdDDNS, err)
	}

	absentMemfile := filepath.Join(dir, "absent.csv")
	header := "address,duid,valid_lifetime,expire,subnet_id,pref_lifetime,iaid,prefix_len,fqdn_fwd,fqdn_rev,hostname,hwaddr,state,user_context,hwtype,hwaddr_source,pool_id\n"
	writeMemfile17009(t, absentMemfile, header,
		"2001:db8:170::3,00:03:00:01:aa:bb:cc:dd:ee:93,3600,"+expire+",3,1800,4245,128,0,1,absent.example,aa:bb:cc:dd:ee:93,0,,0,,0\n")
	absent := fallbackLeases17009(t, absentMemfile, 6, now)
	if len(absent) != 1 || absent[0].LeaseType != "IA_NA" {
		t.Fatalf("absent lease_type control = %+v, want IA_NA", absent)
	}
	absentDDNS, err := keaLeaseParser(absentMemfile, 6, now)
	if err != nil || len(absentDDNS) != 1 || absentDDNS[0].LeaseType != ddns.LeaseTypeIANA {
		t.Fatalf("absent lease_type DDNS control = %+v err=%v, want LeaseTypeIANA", absentDDNS, err)
	}
}

func TestMemfileFallbackSkipsMalformedIAID17009(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	expire := strconv.FormatInt(now.Unix()+1800, 10)
	for _, iaid := range []string{"not-a-number", "-1", "4294967296"} {
		t.Run(iaid, func(t *testing.T) {
			memfile := filepath.Join(t.TempDir(), "kea-leases6.csv")
			writeMemfile17009(t, memfile, keaMemfileHeader6+"\n",
				"2001:db8:170::10,00:03:00:01:aa:bb:cc:dd:ee:a0,3600,"+expire+",3,1800,0,"+iaid+",128,0,1,bad.example,aa:bb:cc:dd:ee:a0,0,,0,,0\n",
				"2001:db8:170::11,00:03:00:01:aa:bb:cc:dd:ee:a1,3600,"+expire+",3,1800,0,42,128,0,1,good.example,aa:bb:cc:dd:ee:a1,0,,0,,0\n")

			leases := fallbackLeases17009(t, memfile, 6, now)
			if len(leases) != 1 || leases[0].Address != "2001:db8:170::11" || leases[0].IAID != 42 {
				t.Fatalf("fallback leases = %+v, want only valid IAID 42 row", leases)
			}
		})
	}
}
