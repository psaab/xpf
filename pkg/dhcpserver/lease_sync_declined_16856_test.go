package dhcpserver

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// #16856: declined (state=1) leases must survive HA sync and live pre-seed.

func TestDeclined16856_SocketAndMemfileCarry(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	sock := tmpSocket(t, "k4decl16856.sock")
	stub := &stubKea{handler: func(cmd keaCommand) keaResponse {
		if cmd.Command == "lease4-get-all" {
			return leaseGetAllResponse([]keaLeaseJSON{
				{IPAddress: "10.0.61.10", HWAddress: "aa:bb:cc:dd:ee:10", SubnetID: 1, ValidLft: 3600, CLTT: now.Unix() - 100, State: keaStateDefault, Hostname: "active"},
				{IPAddress: "10.0.61.66", HWAddress: "aa:bb:cc:dd:ee:66", SubnetID: 1, ValidLft: 3600, CLTT: now.Unix(), State: keaStateDeclined},
				{IPAddress: "10.0.61.67", HWAddress: "aa:bb:cc:dd:ee:67", SubnetID: 1, ValidLft: 3600, CLTT: now.Unix(), State: keaStateExpired},
			})
		}
		if cmd.Command == "dhcp-disable" {
			return keaResponse{Result: keaResultSuccess}
		}
		return keaResponse{Result: keaResultError, Text: "unexpected"}
	}}
	dial, stop := startStubKea(t, sock, stub)
	defer stop()
	m := New()
	dir := t.TempDir()
	memfile := filepath.Join(dir, "kea-leases4.csv")
	m.SetLeaseSyncSeamsForTesting(dial, sock, "", memfile, "")
	m.SetKeaOwnerLookupForTesting(func() (int, int, bool) { return os.Getuid(), os.Getgid(), true })
	m.unitActive = func(string) (bool, error) { return true, nil }

	leases, err := m.GetSyncLeases4(context.Background(), now)
	if err != nil {
		t.Fatalf("GetSyncLeases4: %v", err)
	}
	var declined *SyncLease
	for i := range leases {
		if leases[i].Address == "10.0.61.66" {
			declined = &leases[i]
		}
		if leases[i].Address == "10.0.61.67" {
			t.Fatalf("state=2 must be dropped: %+v", leases)
		}
	}
	if declined == nil || declined.State != keaStateDeclined || declined.Remaining != 3600 {
		t.Fatalf("declined not carried via socket: %+v", leases)
	}

	// Live pre-seed: local snapshot (socket) contains declined; peer empty.
	if err := m.PreSeedMemfileMerged4(context.Background(), nil, now, false); err != nil {
		t.Fatalf("PreSeedMemfileMerged4: %v", err)
	}
	raw, _ := os.ReadFile(memfile)
	if !strings.Contains(string(raw), "10.0.61.66") || !strings.Contains(string(raw), ",1,,0") {
		t.Fatalf("memfile must retain declined 10.0.61.66 state=1, got:\n%s", raw)
	}
	if !strings.Contains(string(raw), "10.0.61.10") {
		t.Fatalf("active control missing: %s", raw)
	}
	// parseSyncLeases sees declined; parseActiveLeases (DDNS) must not.
	syncLeases, err := parseSyncLeases4(memfile, now)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, l := range syncLeases {
		if l.Address == "10.0.61.66" && l.State == StateDeclined {
			found = true
		}
	}
	if !found {
		t.Fatalf("parseSyncLeases4 missing declined: %+v", syncLeases)
	}
	active, err := parseActiveLeases4(memfile, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range active {
		if l.Address == "10.0.61.66" {
			t.Fatalf("DDNS parseActiveLeases must not publish declined: %+v", active)
		}
	}
}

func TestDeclined16856_MemfileFallbackAndPreSeed(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	expire := now.Unix() + 3600
	dir := t.TempDir()
	memfile := filepath.Join(dir, "kea-leases4.csv")
	csv := keaMemfileHeader4 + "\n" +
		"10.0.61.10,aa:bb:cc:dd:ee:10,01:aa:bb:cc:dd:ee:10,3600," + strconv.FormatInt(expire, 10) + ",1,0,0,active,0,,0\n" +
		"10.0.61.66,aa:bb:cc:dd:ee:66,01:aa:bb:cc:dd:ee:66,3600," + strconv.FormatInt(expire, 10) + ",1,0,0,,1,,0\n" +
		"10.0.61.67,aa:bb:cc:dd:ee:67,01:aa:bb:cc:dd:ee:67,3600," + strconv.FormatInt(expire, 10) + ",1,0,0,,2,,0\n"
	if err := os.WriteFile(memfile, []byte(csv), 0644); err != nil {
		t.Fatal(err)
	}
	m := New()
	m.SetLeaseSyncSeamsForTesting(nil, filepath.Join(dir, "missing.sock"), "", memfile, "")
	leases, err := m.GetSyncLeases4(context.Background(), now)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]int{}
	for _, l := range leases {
		seen[l.Address] = l.State
	}
	if seen["10.0.61.66"] != keaStateDeclined {
		t.Fatalf("memfile fallback declined missing: %+v", leases)
	}
	if _, ok := seen["10.0.61.67"]; ok {
		t.Fatalf("state=2 leaked via memfile: %+v", leases)
	}
	// PreSeed plain with declined peer row.
	m2 := New()
	out := filepath.Join(dir, "out.csv")
	m2.SetLeaseSyncSeamsForTesting(nil, "", "", out, "")
	peer := []SyncLease{{Family: 4, Address: "10.0.61.66", SubnetID: 1, Remaining: 1800, ValidLife: 3600, State: keaStateDeclined}}
	if err := m2.PreSeedMemfile4(peer, now); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(out)
	if !strings.Contains(string(raw), "10.0.61.66") || !strings.Contains(string(raw), ",1,,0") {
		t.Fatalf("peer declined not seeded as state=1: %s", raw)
	}
}

func TestDeclined16856_SeedSocketAndSanitize(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	sock := tmpSocket(t, "k4declseed.sock")
	var got []keaLeaseJSON
	stub := &stubKea{handler: func(cmd keaCommand) keaResponse {
		if cmd.Command == "lease4-add" {
			var kl keaLeaseJSON
			b, _ := json.Marshal(cmd.Arguments)
			_ = json.Unmarshal(b, &kl)
			got = append(got, kl)
			return keaResponse{Result: keaResultSuccess}
		}
		return keaResponse{Result: keaResultError, Text: "unexpected"}
	}}
	dial, stop := startStubKea(t, sock, stub)
	defer stop()
	m := New()
	m.SetLeaseSyncSeamsForTesting(dial, sock, "", "", "")
	in := []SyncLease{
		{Family: 4, Address: "10.0.61.66", SubnetID: 1, Remaining: 1800, State: keaStateDeclined},
		{Family: 4, Address: "10.0.61.67", SubnetID: 1, Remaining: 1800, State: keaStateExpired, HWAddress: "aa"},
	}
	n, err := m.SeedSyncLeases4(context.Background(), in, now)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 || len(got) != 1 || got[0].State != keaStateDeclined || got[0].IPAddress != "10.0.61.66" {
		t.Fatalf("seed declined: n=%d got=%+v", n, got)
	}
	if _, ok := SanitizeSyncLeaseForFamily(4, SyncLease{Family: 4, Address: "10.0.0.1", State: 99}); ok {
		t.Fatal("unknown state 99 must be dropped by Sanitize")
	}
	if _, ok := SanitizeSyncLeaseForFamily(4, SyncLease{Family: 4, Address: "10.0.0.1", State: keaStateDeclined}); !ok {
		t.Fatal("declined must pass Sanitize without identity")
	}
}

func TestDeclined16856_MergeArbitration(t *testing.T) {
	activeOld := SyncLease{Family: 4, Address: "10.0.0.9", HWAddress: "aa", Remaining: 100, ValidLife: 3600, State: keaStateDefault}
	declined := SyncLease{Family: 4, Address: "10.0.0.9", Remaining: 3500, ValidLife: 3600, State: keaStateDeclined}
	out := mergeLeasesByIdentity([]SyncLease{activeOld}, []SyncLease{declined}, 4)
	if len(out) != 1 || !out[0].IsDeclined() {
		t.Fatalf("declined should beat older active: %+v", out)
	}
	activeNew := SyncLease{Family: 4, Address: "10.0.0.9", HWAddress: "bb", Remaining: 3500, ValidLife: 3600, State: keaStateDefault}
	out = mergeLeasesByIdentity([]SyncLease{declined}, []SyncLease{activeNew}, 4)
	// declined grant age=100, active grant age=100 tie -> declined wins (first is local declined, candidate active cannot beat)
	// Provably newer active: ValidLife 3600 Remaining 3599 age 1 < declined age 100
	activeNewer := SyncLease{Family: 4, Address: "10.0.0.9", HWAddress: "bb", Remaining: 3599, ValidLife: 3600, State: keaStateDefault}
	declinedOld := SyncLease{Family: 4, Address: "10.0.0.9", Remaining: 3400, ValidLife: 3600, State: keaStateDeclined}
	out = mergeLeasesByIdentity([]SyncLease{declinedOld}, []SyncLease{activeNewer}, 4)
	if len(out) != 1 || out[0].IsDeclined() {
		t.Fatalf("provably newer active should beat declined: %+v", out)
	}
	_ = activeNew
}
