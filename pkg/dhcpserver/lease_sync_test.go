package dhcpserver

import (
	"context"
	"encoding/json"
	"math"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// stubKea is an in-test Kea control-socket server: it accepts one connection
// per dial, decodes a single keaCommand, hands it to a handler, and writes the
// JSON response. It captures every command for assertions.
type stubKea struct {
	mu       sync.Mutex
	commands []keaCommand
	handler  func(cmd keaCommand) keaResponse
}

func (s *stubKea) record(cmd keaCommand) {
	s.mu.Lock()
	s.commands = append(s.commands, cmd)
	s.mu.Unlock()
}

func (s *stubKea) seen() []keaCommand {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]keaCommand, len(s.commands))
	copy(out, s.commands)
	return out
}

// startStubKea spins a unix-socket server at path serving the stub handler. It
// returns a dialer suitable for SetLeaseSyncSeamsForTesting and a stop func.
func startStubKea(t *testing.T, path string, s *stubKea) (keaSocketDialer, func()) {
	t.Helper()
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen unix %s: %v", path, err)
	}
	done := make(chan struct{})
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				select {
				case <-done:
					return
				default:
					return
				}
			}
			go func(c net.Conn) {
				defer c.Close()
				dec := json.NewDecoder(c)
				var cmd keaCommand
				if err := dec.Decode(&cmd); err != nil {
					return
				}
				s.record(cmd)
				resp := s.handler(cmd)
				b, _ := json.Marshal(resp)
				_, _ = c.Write(b)
			}(conn)
		}
	}()
	dial := func(ctx context.Context, socketPath string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", socketPath)
	}
	return dial, func() { close(done); ln.Close() }
}

func tmpSocket(t *testing.T, name string) string {
	t.Helper()
	// unix socket paths are length-limited (~108); use a short tmp dir.
	dir, err := os.MkdirTemp("", "ks")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return filepath.Join(dir, name)
}

func leaseGetAllResponse(leases []keaLeaseJSON) keaResponse {
	args, _ := json.Marshal(keaLeaseGetAllArgs{Leases: leases})
	return keaResponse{Result: keaResultSuccess, Text: "ok", Arguments: args}
}

// Test (a): read leases via the control socket (lease4-get-all).
func TestGetSyncLeases4_ViaSocket(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	sock := tmpSocket(t, "k4.sock")
	stub := &stubKea{handler: func(cmd keaCommand) keaResponse {
		if cmd.Command != "lease4-get-all" {
			t.Errorf("unexpected command %q", cmd.Command)
		}
		return leaseGetAllResponse([]keaLeaseJSON{
			{
				IPAddress: "10.0.61.50", HWAddress: "aa:bb:cc:dd:ee:01",
				ClientID: "01:aa:bb:cc:dd:ee:01", SubnetID: 1,
				ValidLft: 3600, CLTT: now.Unix() - 600, State: keaStateDefault,
				Hostname: "host-a",
			},
			// An expired lease (cltt+valid-lft in the past) must be dropped.
			{
				IPAddress: "10.0.61.51", HWAddress: "aa:bb:cc:dd:ee:02",
				SubnetID: 1, ValidLft: 100, CLTT: now.Unix() - 1000, State: keaStateDefault,
			},
			// A declined lease (non-default state) must be dropped.
			{
				IPAddress: "10.0.61.52", HWAddress: "aa:bb:cc:dd:ee:03",
				SubnetID: 1, ValidLft: 3600, CLTT: now.Unix(), State: keaStateDeclined,
			},
		})
	}}
	dial, stop := startStubKea(t, sock, stub)
	defer stop()

	m := New()
	m.SetLeaseSyncSeamsForTesting(dial, sock, "", "", "")

	leases, err := m.GetSyncLeases4(context.Background(), now)
	if err != nil {
		t.Fatalf("GetSyncLeases4: %v", err)
	}
	if len(leases) != 1 {
		t.Fatalf("expected 1 active lease, got %d: %+v", len(leases), leases)
	}
	l := leases[0]
	if l.Address != "10.0.61.50" {
		t.Errorf("address = %q", l.Address)
	}
	// Remaining = (cltt+valid-lft) - now = (now-600+3600) - now = 3000.
	if l.Remaining != 3000 {
		t.Errorf("remaining = %d, want 3000", l.Remaining)
	}
	if l.Hostname != "host-a" {
		t.Errorf("hostname = %q", l.Hostname)
	}
}

// Test (a) fallback: socket absent → memfile parser.
func TestGetSyncLeases4_MemfileFallback(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	dir := t.TempDir()
	memfile := filepath.Join(dir, "kea-leases4.csv")
	expire := now.Unix() + 1800
	csv := "address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state\n" +
		"10.0.61.70,aa:bb:cc:dd:ee:70,01:aa:bb:cc:dd:ee:70,3600," +
		strconv.FormatInt(expire, 10) + ",2,0,0,host-mem,0\n"
	if err := os.WriteFile(memfile, []byte(csv), 0644); err != nil {
		t.Fatal(err)
	}

	m := New()
	// Point the control socket at a non-existent path so the socket read
	// errors and the memfile fallback is taken.
	m.SetLeaseSyncSeamsForTesting(nil, filepath.Join(dir, "missing.sock"), "", memfile, "")

	leases, err := m.GetSyncLeases4(context.Background(), now)
	if err != nil {
		t.Fatalf("GetSyncLeases4 (fallback): %v", err)
	}
	if len(leases) != 1 {
		t.Fatalf("expected 1 lease from memfile, got %d", len(leases))
	}
	if leases[0].Address != "10.0.61.70" || leases[0].Remaining != 1800 {
		t.Errorf("memfile lease = %+v", leases[0])
	}
	if leases[0].ClientID != "01:aa:bb:cc:dd:ee:70" {
		t.Errorf("client-id not recovered: %q", leases[0].ClientID)
	}
}

// TestGetSyncLeases4_MemfileFallback_SubnetIDBounds pins #6218 item 11: the
// memfile fallback parsed subnet_id with a bare strconv.Atoi, whose bitSize=0
// parses at the PLATFORM int width — 64-bit on amd64/arm64, but only 32-bit
// on a 32-bit target — rather than the fixed uint32 width Kea's subnet-id
// space actually uses (keaSubnetIDMax = 0xFFFFFFFE, dhcpserver.go).
// strconv.ParseUint(s, 10, 32) is exact and portable: it accepts every value
// up to keaSubnetIDMax regardless of host int width, AND (unlike the bare
// 64-bit-native Atoi) correctly REJECTS a value outside Kea's real uint32
// subnet-id space rather than silently accepting it as a garbage subnet id.
//
// The at-boundary case (keaSubnetIDMax itself) round-trips under both the
// old and new parse, so it alone would not catch a reverted fix on this
// (64-bit) test host. The out-of-range case is the one that does: on a bare
// strconv.Atoi (64-bit here) a subnet_id ABOVE math.MaxUint32 still parses
// successfully and is silently accepted as SubnetID — a garbage value Kea's
// real uint32 subnet-id space could never produce. ParseUint(...,32) refuses
// it, leaving SubnetID at its zero/unset value.
//
// RED on revert: restoring the bare strconv.Atoi accepts the out-of-range
// subnet_id below and sets SubnetID to a huge garbage int instead of leaving
// it 0, failing the second assertion.
func TestGetSyncLeases4_MemfileFallback_SubnetIDBounds(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	expire := now.Unix() + 1800
	header := "address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state\n"

	t.Run("at-boundary-accepted", func(t *testing.T) {
		dir := t.TempDir()
		memfile := filepath.Join(dir, "kea-leases4.csv")
		const boundarySubnetID = 4294967294 // 0xFFFFFFFE == keaSubnetIDMax
		csv := header + "10.0.61.71,aa:bb:cc:dd:ee:71,01:aa:bb:cc:dd:ee:71,3600," +
			strconv.FormatInt(expire, 10) + "," + strconv.Itoa(boundarySubnetID) + ",0,0,host-big,0\n"
		if err := os.WriteFile(memfile, []byte(csv), 0644); err != nil {
			t.Fatal(err)
		}
		m := New()
		m.SetLeaseSyncSeamsForTesting(nil, filepath.Join(dir, "missing.sock"), "", memfile, "")
		leases, err := m.GetSyncLeases4(context.Background(), now)
		if err != nil {
			t.Fatalf("GetSyncLeases4 (fallback): %v", err)
		}
		if len(leases) != 1 {
			t.Fatalf("expected 1 lease from memfile, got %d", len(leases))
		}
		if leases[0].SubnetID != boundarySubnetID {
			t.Errorf("boundary subnet-id not recovered: got %d, want %d", leases[0].SubnetID, boundarySubnetID)
		}
	})

	t.Run("above-uint32-rejected", func(t *testing.T) {
		dir := t.TempDir()
		memfile := filepath.Join(dir, "kea-leases4.csv")
		const overRangeSubnetID = "5000000000" // > math.MaxUint32 (4294967295)
		csv := header + "10.0.61.72,aa:bb:cc:dd:ee:72,01:aa:bb:cc:dd:ee:72,3600," +
			strconv.FormatInt(expire, 10) + "," + overRangeSubnetID + ",0,0,host-huge,0\n"
		if err := os.WriteFile(memfile, []byte(csv), 0644); err != nil {
			t.Fatal(err)
		}
		m := New()
		m.SetLeaseSyncSeamsForTesting(nil, filepath.Join(dir, "missing.sock"), "", memfile, "")
		leases, err := m.GetSyncLeases4(context.Background(), now)
		if err != nil {
			t.Fatalf("GetSyncLeases4 (fallback): %v", err)
		}
		if len(leases) != 1 {
			t.Fatalf("expected 1 lease from memfile, got %d", len(leases))
		}
		if leases[0].SubnetID != 0 {
			t.Errorf("out-of-uint32-range subnet_id %q must leave SubnetID unset (0), got %d",
				overRangeSubnetID, leases[0].SubnetID)
		}
	})
}

// Test (a) v6 fallback (#2262): the memfile-fallback read path must PRESERVE
// the v6 lease kind (IA_NA vs IA_PD) and the PD prefix length from the Kea v6
// memfile, not hardcode IA_NA. A memfile holding BOTH an IA_NA and an IA_PD row
// must round-trip each lease's type (and the PD prefix-len) — mirroring the
// faithful control-socket path (TestSeedSyncLeases6_IdentityAndPD). Fail-on-
// revert: re-hardcoding LeaseType="IA_NA" makes the IA_PD assertions fail.
func TestGetSyncLeases6_MemfileFallback_PreservesType(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	dir := t.TempDir()
	memfile := filepath.Join(dir, "kea-leases6.csv")
	expire := strconv.FormatInt(now.Unix()+1800, 10)
	// Canonical Kea v6 memfile header + one IA_NA (lease_type 0, prefix_len 128)
	// and one IA_PD (lease_type 2, prefix_len 56) row.
	//   address,duid,valid_lifetime,expire,subnet_id,pref_lifetime,
	//   lease_type,iaid,prefix_len,fqdn_fwd,fqdn_rev,hostname,hwaddr,
	//   state,user_context,hwtype,hwaddr_source,pool_id
	csv := keaMemfileHeader6 + "\n" +
		"2001:db8::100,00:01:00:01,3600," + expire + ",1,3600,0,42,128,0,0,host-na,,0,,,,0\n" +
		"2001:db8:abcd::,00:01:00:02,3600," + expire + ",1,3600,2,7,56,0,0,host-pd,,0,,,,0\n"
	if err := os.WriteFile(memfile, []byte(csv), 0644); err != nil {
		t.Fatal(err)
	}

	m := New()
	// Missing socket → memfile fallback; leaseFile6 = our fixture.
	m.SetLeaseSyncSeamsForTesting(nil, "", filepath.Join(dir, "missing.sock"), "", memfile)

	leases, err := m.GetSyncLeases6(context.Background(), now)
	if err != nil {
		t.Fatalf("GetSyncLeases6 (fallback): %v", err)
	}
	if len(leases) != 2 {
		t.Fatalf("expected 2 leases from v6 memfile, got %d: %+v", len(leases), leases)
	}

	byAddr := map[string]SyncLease{}
	for _, l := range leases {
		byAddr[l.Address] = l
	}

	na, ok := byAddr["2001:db8::100"]
	if !ok {
		t.Fatalf("IA_NA lease missing from fallback result: %+v", leases)
	}
	if na.LeaseType != "IA_NA" {
		t.Errorf("IA_NA lease type = %q, want IA_NA", na.LeaseType)
	}
	if na.PrefixLen != 0 {
		t.Errorf("IA_NA lease PrefixLen = %d, want 0", na.PrefixLen)
	}
	if na.DUID != "00:01:00:01" || na.IAID != 42 {
		t.Errorf("IA_NA identity wrong: DUID=%q IAID=%d", na.DUID, na.IAID)
	}

	pd, ok := byAddr["2001:db8:abcd::"]
	if !ok {
		t.Fatalf("IA_PD lease missing from fallback result: %+v", leases)
	}
	// This is the #2262 regression guard: pre-fix the fallback hardcoded
	// LeaseType="IA_NA" and dropped the prefix length, so a PD lease arrived as
	// an address lease on the peer.
	if pd.LeaseType != "IA_PD" {
		t.Errorf("IA_PD lease mis-typed as %q (want IA_PD) — #2262 regression", pd.LeaseType)
	}
	if pd.PrefixLen != 56 {
		t.Errorf("IA_PD lease PrefixLen = %d, want 56 — #2262 regression", pd.PrefixLen)
	}
	if pd.DUID != "00:01:00:02" || pd.IAID != 7 {
		t.Errorf("IA_PD identity wrong: DUID=%q IAID=%d", pd.DUID, pd.IAID)
	}
}

// Test (a) v6 fallback skip-malformed (#2262): a PRESENT-but-unparseable
// lease_type column must cause the row to be SKIPPED (fail-closed), not
// defaulted to IA_NA, so a corrupt row can never silently mis-seed an address
// lease on the peer. A well-formed IA_PD row in the same file still parses.
func TestGetSyncLeases6_MemfileFallback_SkipMalformedType(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	dir := t.TempDir()
	memfile := filepath.Join(dir, "kea-leases6.csv")
	expire := strconv.FormatInt(now.Unix()+1800, 10)
	// First row: lease_type column is garbage ("PD") → unparseable → skipped.
	// Second row: a valid IA_PD lease that must still survive.
	csv := keaMemfileHeader6 + "\n" +
		"2001:db8::bad,00:01:00:09,3600," + expire + ",1,3600,PD,9,64,0,0,host-bad,,0,,,,0\n" +
		"2001:db8:cafe::,00:01:00:0a,3600," + expire + ",1,3600,2,10,60,0,0,host-good,,0,,,,0\n"
	if err := os.WriteFile(memfile, []byte(csv), 0644); err != nil {
		t.Fatal(err)
	}

	m := New()
	m.SetLeaseSyncSeamsForTesting(nil, "", filepath.Join(dir, "missing.sock"), "", memfile)

	leases, err := m.GetSyncLeases6(context.Background(), now)
	if err != nil {
		t.Fatalf("GetSyncLeases6 (fallback): %v", err)
	}
	if len(leases) != 1 {
		t.Fatalf("expected 1 lease (malformed-type row skipped), got %d: %+v", len(leases), leases)
	}
	if leases[0].Address != "2001:db8:cafe::" {
		t.Errorf("surviving lease = %q, want the valid IA_PD row", leases[0].Address)
	}
	if leases[0].LeaseType != "IA_PD" || leases[0].PrefixLen != 60 {
		t.Errorf("surviving IA_PD lease wrong: %+v", leases[0])
	}
}

// Test (b): seed re-anchors Remaining to the LOCAL clock — a skewed peer "now"
// must NOT influence the seeded expiry (clock-skew immunity).
func TestSeedSyncLeases4_ClockSkewImmune(t *testing.T) {
	localNow := time.Unix(1_700_000_000, 0)
	sock := tmpSocket(t, "k4add.sock")
	var addArgs keaLeaseJSON
	stub := &stubKea{handler: func(cmd keaCommand) keaResponse {
		if cmd.Command == "lease4-add" {
			b, _ := json.Marshal(cmd.Arguments)
			_ = json.Unmarshal(b, &addArgs)
			return keaResponse{Result: keaResultSuccess, Text: "added"}
		}
		return keaResponse{Result: keaResultError, Text: "unexpected"}
	}}
	dial, stop := startStubKea(t, sock, stub)
	defer stop()

	m := New()
	m.SetLeaseSyncSeamsForTesting(dial, sock, "", "", "")

	// The lease was synced from a peer whose clock was 1 HOUR ahead, but the
	// SyncLease only carries Remaining (1800s) — never the peer's absolute
	// expiry. The seeded expire must be localNow+1800, ignoring peer skew.
	in := []SyncLease{{
		Family: 4, Address: "10.0.61.90", HWAddress: "aa:bb:cc:dd:ee:90",
		SubnetID: 1, ValidLife: 3600, Remaining: 1800, State: keaStateDefault,
	}}
	n, err := m.SeedSyncLeases4(context.Background(), in, localNow)
	if err != nil {
		t.Fatalf("SeedSyncLeases4: %v", err)
	}
	if n != 1 {
		t.Fatalf("seeded = %d, want 1", n)
	}
	wantExpire := localNow.Unix() + 1800
	if addArgs.Expire != wantExpire {
		t.Errorf("seeded expire = %d, want %d (local-clock re-anchor)", addArgs.Expire, wantExpire)
	}
	if addArgs.ValidLft != 1800 {
		t.Errorf("seeded valid-lft = %d, want 1800 (remaining)", addArgs.ValidLft)
	}
	if addArgs.IPAddress != "10.0.61.90" {
		t.Errorf("seeded address = %q", addArgs.IPAddress)
	}
}

// Test (b) v6: seed carries DUID/IAID/type/prefix-len faithfully (Q5).
func TestSeedSyncLeases6_IdentityAndPD(t *testing.T) {
	localNow := time.Unix(1_700_000_000, 0)
	sock := tmpSocket(t, "k6add.sock")
	var got []keaLeaseJSON
	stub := &stubKea{handler: func(cmd keaCommand) keaResponse {
		if cmd.Command == "lease6-add" {
			b, _ := json.Marshal(cmd.Arguments)
			var kl keaLeaseJSON
			_ = json.Unmarshal(b, &kl)
			got = append(got, kl)
			return keaResponse{Result: keaResultSuccess}
		}
		return keaResponse{Result: keaResultError, Text: "unexpected"}
	}}
	dial, stop := startStubKea(t, sock, stub)
	defer stop()

	m := New()
	m.SetLeaseSyncSeamsForTesting(dial, "", sock, "", "")

	in := []SyncLease{
		{Family: 6, Address: "2001:db8::100", DUID: "00:01:00:01", IAID: 42,
			LeaseType: "IA_NA", SubnetID: 1, Remaining: 1200, State: keaStateDefault},
		{Family: 6, Address: "2001:db8:abcd::", DUID: "00:01:00:02", IAID: 7,
			LeaseType: "IA_PD", PrefixLen: 56, SubnetID: 1, Remaining: 2400, State: keaStateDefault},
	}
	n, err := m.SeedSyncLeases6(context.Background(), in, localNow)
	if err != nil {
		t.Fatalf("SeedSyncLeases6: %v", err)
	}
	if n != 2 {
		t.Fatalf("seeded = %d, want 2", n)
	}
	if len(got) != 2 {
		t.Fatalf("captured %d lease6-add", len(got))
	}
	if got[0].DUID != "00:01:00:01" || got[0].IAID != 42 || got[0].Type != "IA_NA" {
		t.Errorf("NA lease wrong: %+v", got[0])
	}
	if got[1].Type != "IA_PD" || got[1].PrefixLen != 56 {
		t.Errorf("PD lease wrong: %+v", got[1])
	}
}

// Test (b) collision → update fallback (idempotent seed).
func TestSeedSyncLeases4_ConflictUpdates(t *testing.T) {
	sock := tmpSocket(t, "kconf.sock")
	var sawUpdate bool
	stub := &stubKea{handler: func(cmd keaCommand) keaResponse {
		switch cmd.Command {
		case "lease4-add":
			return keaResponse{Result: keaResultConflict, Text: "lease already exists"}
		case "lease4-update":
			sawUpdate = true
			return keaResponse{Result: keaResultSuccess}
		}
		return keaResponse{Result: keaResultError}
	}}
	dial, stop := startStubKea(t, sock, stub)
	defer stop()

	m := New()
	m.SetLeaseSyncSeamsForTesting(dial, sock, "", "", "")
	n, err := m.SeedSyncLeases4(context.Background(),
		[]SyncLease{{Family: 4, Address: "10.0.61.5", HWAddress: "a", SubnetID: 1, Remaining: 60}},
		time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	if n != 1 || !sawUpdate {
		t.Fatalf("expected conflict→update path: n=%d sawUpdate=%v", n, sawUpdate)
	}
}

// Test (c): the Kea config gains control-socket + lease_cmds hook ONLY when
// lease sync is enabled (the config knob gate).
func TestKeaConfig_LeaseSyncStanza_Gated(t *testing.T) {
	dir := t.TempDir()
	conf4 := filepath.Join(dir, "kea4.conf")
	conf6 := filepath.Join(dir, "kea6.conf")
	m := NewManagerForTesting(conf4, conf6,
		func(...string) error { return nil },
		func(string) bool { return false })

	cfg := &config.DHCPServerConfig{
		DHCPLocalServer: &config.DHCPLocalServerConfig{
			Groups: map[string]*config.DHCPServerGroup{
				"g0": {Interfaces: []string{"eth0"}, Pools: []*config.DHCPPool{
					{Subnet: "10.0.61.0/24", RangeLow: "10.0.61.10", RangeHigh: "10.0.61.200"},
				}},
			},
		},
	}

	// Disabled → no stanza.
	if err := m.generateKea4Config(cfg); err != nil {
		t.Fatal(err)
	}
	off, _ := os.ReadFile(conf4)
	if strings.Contains(string(off), "control-socket") || strings.Contains(string(off), "lease_cmds") {
		t.Errorf("disabled config must not contain control-socket/lease_cmds:\n%s", off)
	}

	// Enabled → stanza present.
	m.SetLeaseSyncEnabled(true)
	if err := m.generateKea4Config(cfg); err != nil {
		t.Fatal(err)
	}
	on, _ := os.ReadFile(conf4)
	if !strings.Contains(string(on), "control-socket") {
		t.Errorf("enabled config missing control-socket:\n%s", on)
	}
	if !strings.Contains(string(on), "libdhcp_lease_cmds.so") {
		t.Errorf("enabled config missing lease_cmds hook:\n%s", on)
	}
	// Validate it is still well-formed JSON.
	var parsed map[string]any
	if err := json.Unmarshal(on, &parsed); err != nil {
		t.Errorf("enabled config not valid JSON: %v", err)
	}
}

// Test (d): the memfile pre-seed round-trips through the destructive-safe
// parser (so a starting Kea will load it), and re-anchors to the local clock.
func TestPreSeedMemfile4_RoundTrip(t *testing.T) {
	localNow := time.Unix(1_700_000_000, 0)
	dir := t.TempDir()
	memfile := filepath.Join(dir, "kea-leases4.csv")
	m := New()
	m.SetLeaseSyncSeamsForTesting(nil, "", "", memfile, "")

	in := []SyncLease{
		{Family: 4, Address: "10.0.61.42", HWAddress: "aa:bb:cc:dd:ee:42",
			ClientID: "01:aa:bb:cc:dd:ee:42", SubnetID: 3, Remaining: 900,
			Hostname: "pre-seeded", State: keaStateDefault},
	}
	if err := m.PreSeedMemfile4(in, localNow); err != nil {
		t.Fatalf("PreSeedMemfile4: %v", err)
	}
	// Re-read via the destructive-safe parser → must see the lease.
	got, err := parseActiveLeases4(memfile, localNow)
	if err != nil {
		t.Fatalf("parseActiveLeases4 on pre-seeded file: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("pre-seeded memfile parsed %d leases, want 1", len(got))
	}
	if got[0].Address != "10.0.61.42" {
		t.Errorf("address = %q", got[0].Address)
	}
	if got[0].Expire != localNow.Unix()+900 {
		t.Errorf("expire = %d, want %d (local re-anchor)", got[0].Expire, localNow.Unix()+900)
	}
}

// TestSeedAndPreSeed_DropExpiredLeases is the #4871 dhcpserver-side guard: an
// aged-out lease (Remaining <= 0) must be DROPPED by both seed paths, never
// floored to 1s and re-anchored to now_local (which would resurrect a lease
// past its true expiry -> duplicate allocation). A still-valid lease in the
// same set proves the drop is selective.
//
// Fail-on-revert: restoring the `if rem < 1 { rem = 1 }` floor (removing the
// `Remaining <= 0` drops) makes the expired lease seed/write, failing the
// count assertions.
func TestSeedAndPreSeed_DropExpiredLeases(t *testing.T) {
	localNow := time.Unix(1_700_000_000, 0)

	t.Run("control-socket seed", func(t *testing.T) {
		sock := tmpSocket(t, "k4exp.sock")
		var added []keaLeaseJSON
		stub := &stubKea{handler: func(cmd keaCommand) keaResponse {
			if cmd.Command == "lease4-add" {
				var kl keaLeaseJSON
				b, _ := json.Marshal(cmd.Arguments)
				_ = json.Unmarshal(b, &kl)
				added = append(added, kl)
				return keaResponse{Result: keaResultSuccess, Text: "added"}
			}
			return keaResponse{Result: keaResultError, Text: "unexpected"}
		}}
		dial, stop := startStubKea(t, sock, stub)
		defer stop()
		m := New()
		m.SetLeaseSyncSeamsForTesting(dial, sock, "", "", "")

		in := []SyncLease{
			{Family: 4, Address: "10.0.0.5", HWAddress: "aa", SubnetID: 1, Remaining: 600, State: keaStateDefault},
			{Family: 4, Address: "10.0.0.6", HWAddress: "bb", SubnetID: 1, Remaining: 0, State: keaStateDefault},
			{Family: 4, Address: "10.0.0.7", HWAddress: "cc", SubnetID: 1, Remaining: -5, State: keaStateDefault},
		}
		n, err := m.SeedSyncLeases4(context.Background(), in, localNow)
		if err != nil {
			t.Fatalf("SeedSyncLeases4: %v", err)
		}
		if n != 1 {
			t.Fatalf("seeded = %d, want 1 (only the valid lease)", n)
		}
		if len(added) != 1 || added[0].IPAddress != "10.0.0.5" {
			t.Fatalf("expired lease was seeded (resurrection): %+v", added)
		}
	})

	t.Run("memfile pre-seed", func(t *testing.T) {
		dir := t.TempDir()
		memfile := filepath.Join(dir, "kea-leases4.csv")
		m := New()
		m.SetLeaseSyncSeamsForTesting(nil, "", "", memfile, "")
		in := []SyncLease{
			{Family: 4, Address: "10.0.0.5", HWAddress: "aa", SubnetID: 1, Remaining: 600, State: keaStateDefault},
			{Family: 4, Address: "10.0.0.6", HWAddress: "bb", SubnetID: 1, Remaining: 0, State: keaStateDefault},
		}
		if err := m.PreSeedMemfile4(in, localNow); err != nil {
			t.Fatalf("PreSeedMemfile4: %v", err)
		}
		got, err := parseActiveLeases4(memfile, localNow)
		if err != nil {
			t.Fatalf("parseActiveLeases4: %v", err)
		}
		if len(got) != 1 || got[0].Address != "10.0.0.5" {
			t.Fatalf("expired lease written to memfile (resurrection): %+v", got)
		}
	})
}

// #10893: the socket and memfile sinks independently validate direct callers,
// not just rows that passed the cluster decoder. Invalid family/address/scope
// and zero-length IA_PD rows never reach Kea; extreme lifetimes are capped.
func TestSeedAndPreSeedRejectInvalidSyncLeases10893(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	sock4 := tmpSocket(t, "k4semantic.sock")
	var added4, added6 []keaLeaseJSON
	stub := &stubKea{handler: func(cmd keaCommand) keaResponse {
		var lease keaLeaseJSON
		b, _ := json.Marshal(cmd.Arguments)
		_ = json.Unmarshal(b, &lease)
		switch cmd.Command {
		case "lease4-add":
			added4 = append(added4, lease)
		case "lease6-add":
			added6 = append(added6, lease)
		default:
			return keaResponse{Result: keaResultError, Text: "unexpected"}
		}
		return keaResponse{Result: keaResultSuccess}
	}}
	dial, stop := startStubKea(t, sock4, stub)
	defer stop()
	m := New()
	file4 := filepath.Join(t.TempDir(), "kea-leases4.csv")
	file6 := filepath.Join(t.TempDir(), "kea-leases6.csv")
	m.SetLeaseSyncSeamsForTesting(dial, sock4, sock4, file4, file6)

	v4 := []SyncLease{
		{Family: 4, Address: "10.0.0.5", HWAddress: "aa", ValidLife: 3600, Remaining: 600},
		{Family: 4, Address: "2001:db8::5", HWAddress: "bb", ValidLife: 3600, Remaining: 600},
		{Family: 4, Address: "127.0.0.1", HWAddress: "cc", ValidLife: 3600, Remaining: 600},
		{Family: 6, Address: "2001:db8::6", DUID: "00:01:06", LeaseType: "IA_NA", Remaining: 600},
		{Family: 4, Address: "10.0.0.10", HWAddress: "dd", ValidLife: math.MaxUint32, Remaining: math.MaxUint32},
	}
	n, err := m.SeedSyncLeases4(context.Background(), v4, now)
	if err != nil || n != 2 || len(added4) != 2 {
		t.Fatalf("v4 seed = (%d, %d adds, %v), want 2 valid rows", n, len(added4), err)
	}
	if added4[0].IPAddress != "10.0.0.5" || added4[1].IPAddress != "10.0.0.10" ||
		added4[1].ValidLft != maxSyncLeaseLifetime {
		t.Fatalf("v4 seed admitted invalid data or failed to cap lifetime: %+v", added4)
	}

	v6 := []SyncLease{
		{Family: 6, Address: "2001:db8::6", DUID: "00:01:06", LeaseType: "IA_NA", ValidLife: 3600, Remaining: 600},
		{Family: 6, Address: "2001:db8:1::", DUID: "00:01:07", LeaseType: "IA_PD", PrefixLen: 0, Remaining: 600},
		{Family: 6, Address: "fe80::1", DUID: "00:01:08", LeaseType: "IA_NA", Remaining: 600},
		{Family: 4, Address: "10.0.0.9", HWAddress: "ee", Remaining: 600},
		{Family: 6, Address: "2001:db8::10", DUID: "00:01:10", LeaseType: "IA_NA", ValidLife: math.MaxUint32, Remaining: math.MaxUint32},
	}
	n, err = m.SeedSyncLeases6(context.Background(), v6, now)
	if err != nil || n != 2 || len(added6) != 2 {
		t.Fatalf("v6 seed = (%d, %d adds, %v), want 2 valid rows", n, len(added6), err)
	}
	if added6[0].IPAddress != "2001:db8::6" || added6[1].IPAddress != "2001:db8::10" ||
		added6[1].ValidLft != maxSyncLeaseLifetime {
		t.Fatalf("v6 seed admitted invalid data or failed to cap lifetime: %+v", added6)
	}

	if err := m.PreSeedMemfile4(v4, now); err != nil {
		t.Fatalf("PreSeedMemfile4: %v", err)
	}
	got4, err := parseActiveLeases4(file4, now)
	if err != nil || len(got4) != 2 || got4[0].Address != "10.0.0.5" ||
		got4[1].Address != "10.0.0.10" || got4[1].Expire != now.Unix()+int64(maxSyncLeaseLifetime) {
		t.Fatalf("v4 memfile retained invalid row or uncapped lifetime: %+v (err=%v)", got4, err)
	}
	if err := m.PreSeedMemfile6(v6, now); err != nil {
		t.Fatalf("PreSeedMemfile6: %v", err)
	}
	got6, err := parseActiveLeases6(file6, now)
	if err != nil || len(got6) != 2 || got6[0].Address != "2001:db8::6" ||
		got6[1].Address != "2001:db8::10" || got6[1].Expire != now.Unix()+int64(maxSyncLeaseLifetime) {
		t.Fatalf("v6 memfile retained invalid row or uncapped lifetime: %+v (err=%v)", got6, err)
	}
}

// TestPreSeedMemfileMerged4_PreservesLocalLeases is the #5040 regression guard.
// On active-active takeover this node is ALREADY MASTER for one RG (its lease is
// live in local Kea) and takes over a second RG (the peer's lease). The pre-seed
// must write the UNION so the restarting Kea keeps the still-mastered RG's
// in-use bindings. The pre-#5040 peer-only overwrite wiped them.
//
// Fail-on-revert: reverting PreSeedMemfileMerged4 to a peer-only write (or the
// merge to peer-wins/local-drop) drops 10.0.1.50 from the memfile, failing the
// still-mastered assertion.
func TestPreSeedMemfileMerged4_PreservesLocalLeases(t *testing.T) {
	localNow := time.Unix(1_700_000_000, 0)
	sock := tmpSocket(t, "k4merge.sock")
	// Local Kea (already mastering RG-A) reports one live lease via lease4-get-all.
	stub := &stubKea{handler: func(cmd keaCommand) keaResponse {
		switch cmd.Command {
		case "dhcp-disable":
			return keaResponse{Result: keaResultSuccess, Text: "disabled"}
		case "lease4-get-all":
			return leaseGetAllResponse([]keaLeaseJSON{{
				IPAddress: "10.0.1.50", HWAddress: "aa:aa:aa:aa:aa:aa",
				SubnetID: 1, ValidLft: 3600, CLTT: localNow.Unix() - 100,
				State: keaStateDefault,
			}})
		default:
			return keaResponse{Result: keaResultError, Text: "unexpected"}
		}
	}}
	dial, stop := startStubKea(t, sock, stub)
	defer stop()

	dir := t.TempDir()
	memfile := filepath.Join(dir, "kea-leases4.csv")
	m := New()
	m.SetLeaseSyncSeamsForTesting(dial, sock, "", memfile, "")

	// Peer set (the newly-taken RG-B): a different address/subnet.
	peer := []SyncLease{{
		Family: 4, Address: "10.0.2.80", HWAddress: "bb:bb:bb:bb:bb:bb",
		SubnetID: 2, ValidLife: 3600, Remaining: 1800, State: keaStateDefault,
	}}
	if err := m.PreSeedMemfileMerged4(context.Background(), peer, localNow, false); err != nil {
		t.Fatalf("PreSeedMemfileMerged4: %v", err)
	}
	got, err := parseActiveLeases4(memfile, localNow)
	if err != nil {
		t.Fatalf("parseActiveLeases4 on pre-seeded file: %v", err)
	}
	addrs := make(map[string]bool, len(got))
	for _, l := range got {
		addrs[l.Address] = true
	}
	if !addrs["10.0.1.50"] {
		t.Errorf("still-mastered local lease 10.0.1.50 was wiped by the pre-seed (duplicate-allocation bug #5040); memfile has %v", addrs)
	}
	if !addrs["10.0.2.80"] {
		t.Errorf("newly-taken peer lease 10.0.2.80 missing from pre-seed; memfile has %v", addrs)
	}
}

// TestPreSeedMemfileMerged6_PreservesLocalLeases is the v6 counterpart of the
// #5040 live-socket guard. A live local RG-X binding must survive while a peer
// RG-Y binding is added to the same pre-seed.
func TestPreSeedMemfileMerged6_PreservesLocalLeases(t *testing.T) {
	localNow := time.Unix(1_700_000_000, 0)
	sock := tmpSocket(t, "k6merge.sock")
	stub := &stubKea{handler: func(cmd keaCommand) keaResponse {
		switch cmd.Command {
		case "dhcp-disable":
			return keaResponse{Result: keaResultSuccess, Text: "disabled"}
		case "lease6-get-all":
			return leaseGetAllResponse([]keaLeaseJSON{{
				IPAddress: "2001:db8:1::50", DUID: "00:03:00:01:aa:aa",
				IAID: 50, Type: "IA_NA", SubnetID: 1, ValidLft: 3600,
				CLTT: localNow.Unix() - 100, State: keaStateDefault,
			}})
		default:
			return keaResponse{Result: keaResultError, Text: "unexpected"}
		}
	}}
	dial, stop := startStubKea(t, sock, stub)
	defer stop()

	dir := t.TempDir()
	memfile := filepath.Join(dir, "kea-leases6.csv")
	m := New()
	m.SetLeaseSyncSeamsForTesting(dial, "", sock, "", memfile)

	peer := []SyncLease{{
		Family: 6, Address: "2001:db8:2::80", DUID: "00:03:00:01:bb:bb",
		IAID: 80, LeaseType: "IA_NA", SubnetID: 2, ValidLife: 3600,
		Remaining: 1800, PreferredRemaining: 1800, State: keaStateDefault,
	}}
	if err := m.PreSeedMemfileMerged6(context.Background(), peer, localNow, false); err != nil {
		t.Fatalf("PreSeedMemfileMerged6: %v", err)
	}
	got, err := parseActiveLeases6(memfile, localNow)
	if err != nil {
		t.Fatalf("parseActiveLeases6 on pre-seeded file: %v", err)
	}
	addrs := make(map[string]bool, len(got))
	for _, l := range got {
		addrs[l.Address] = true
	}
	if !addrs["2001:db8:1::50"] {
		t.Errorf("still-mastered local v6 lease was wiped by the pre-seed; memfile has %v", addrs)
	}
	if !addrs["2001:db8:2::80"] {
		t.Errorf("newly-taken peer v6 lease missing from pre-seed; memfile has %v", addrs)
	}
}

// TestPreSeedMemfileMerged4_QuiescesWindowGrants10895 is the #10895 regression
// guard: active Kea is quiesced before the lease snapshot and remains disabled
// through the atomic replacement and takeover restart. A grant completed just
// before quiescing must be in the snapshot; no further grant can slip into the
// snapshot-to-install window and disappear from the installed file.
//
// The fake publishes a second lease when it processes dhcp-disable, modeling a
// grant that completed just before the command took effect. The following
// lease4-get-all must see both leases. Fail-on-revert: without quiescing, the
// socket snapshot contains only the original lease.
func TestPreSeedMemfileMerged4_QuiescesWindowGrants10895(t *testing.T) {
	localNow := time.Unix(1_700_000_000, 0)
	sock := tmpSocket(t, "k4reread.sock")
	base := keaLeaseJSON{
		IPAddress: "10.0.1.50", HWAddress: "aa:aa:aa:aa:aa:aa",
		SubnetID: 1, ValidLft: 3600, CLTT: localNow.Unix() - 100,
		State: keaStateDefault,
	}
	window := keaLeaseJSON{
		IPAddress: "10.0.1.51", HWAddress: "bb:bb:bb:bb:bb:bb",
		SubnetID: 1, ValidLft: 3600, CLTT: localNow.Unix(),
		State: keaStateDefault,
	}
	var mu sync.Mutex
	disabled := false
	stub := &stubKea{handler: func(cmd keaCommand) keaResponse {
		mu.Lock()
		defer mu.Unlock()
		switch cmd.Command {
		case "dhcp-disable":
			disabled = true
			return keaResponse{Result: keaResultSuccess, Text: "disabled"}
		case "lease4-get-all":
			if disabled {
				return leaseGetAllResponse([]keaLeaseJSON{base, window})
			}
			return leaseGetAllResponse([]keaLeaseJSON{base})
		default:
			return keaResponse{Result: keaResultError, Text: "unexpected"}
		}
	}}
	dial, stop := startStubKea(t, sock, stub)
	defer stop()

	dir := t.TempDir()
	memfile := filepath.Join(dir, "kea-leases4.csv")
	m := New()
	m.SetLeaseSyncSeamsForTesting(dial, sock, "", memfile, "")

	if err := m.PreSeedMemfileMerged4WithAuthority(
		context.Background(), LeaseSyncSnapshot{}, localNow, false, LeaseSyncAuthority{}); err != nil {
		t.Fatalf("PreSeedMemfileMerged4WithAuthority: %v", err)
	}
	got, err := parseActiveLeases4(memfile, localNow)
	if err != nil {
		t.Fatalf("parseActiveLeases4 on pre-seeded file: %v", err)
	}
	addrs := make(map[string]bool, len(got))
	for _, l := range got {
		addrs[l.Address] = true
	}
	if !addrs["10.0.1.50"] || !addrs["10.0.1.51"] {
		t.Errorf("pre-seed did not preserve both snapshot leases; memfile has %v", addrs)
	}
	commands := stub.seen()
	if len(commands) != 2 || commands[0].Command != "dhcp-disable" || commands[1].Command != "lease4-get-all" {
		t.Errorf("control commands = %+v, want dhcp-disable before lease4-get-all", commands)
	}
	mu.Lock()
	remainedDisabled := disabled
	mu.Unlock()
	if !remainedDisabled {
		t.Error("DHCP was re-enabled before the takeover restart")
	}
}

// TestPreSeedMemfileMerged6_QuiescesWindowGrants10895 is the v6 twin of the
// #10895 quiesce-and-snapshot guard.
func TestPreSeedMemfileMerged6_QuiescesWindowGrants10895(t *testing.T) {
	localNow := time.Unix(1_700_000_000, 0)
	sock := tmpSocket(t, "k6reread.sock")
	base := keaLeaseJSON{
		IPAddress: "2001:db8:1::50", DUID: "00:03:00:01:aa:aa",
		IAID: 50, Type: "IA_NA", SubnetID: 1, ValidLft: 3600,
		CLTT: localNow.Unix() - 100, State: keaStateDefault,
	}
	window := keaLeaseJSON{
		IPAddress: "2001:db8:1::51", DUID: "00:03:00:01:bb:bb",
		IAID: 51, Type: "IA_NA", SubnetID: 1, ValidLft: 3600,
		CLTT: localNow.Unix(), State: keaStateDefault,
	}
	var mu sync.Mutex
	disabled := false
	stub := &stubKea{handler: func(cmd keaCommand) keaResponse {
		mu.Lock()
		defer mu.Unlock()
		switch cmd.Command {
		case "dhcp-disable":
			disabled = true
			return keaResponse{Result: keaResultSuccess, Text: "disabled"}
		case "lease6-get-all":
			if disabled {
				return leaseGetAllResponse([]keaLeaseJSON{base, window})
			}
			return leaseGetAllResponse([]keaLeaseJSON{base})
		default:
			return keaResponse{Result: keaResultError, Text: "unexpected"}
		}
	}}
	dial, stop := startStubKea(t, sock, stub)
	defer stop()

	dir := t.TempDir()
	memfile := filepath.Join(dir, "kea-leases6.csv")
	m := New()
	m.SetLeaseSyncSeamsForTesting(dial, "", sock, "", memfile)

	if err := m.PreSeedMemfileMerged6WithAuthority(
		context.Background(), LeaseSyncSnapshot{}, localNow, false, LeaseSyncAuthority{}); err != nil {
		t.Fatalf("PreSeedMemfileMerged6WithAuthority: %v", err)
	}
	got, err := parseActiveLeases6(memfile, localNow)
	if err != nil {
		t.Fatalf("parseActiveLeases6 on pre-seeded file: %v", err)
	}
	addrs := make(map[string]bool, len(got))
	for _, l := range got {
		addrs[l.Address] = true
	}
	if !addrs["2001:db8:1::50"] || !addrs["2001:db8:1::51"] {
		t.Errorf("pre-seed did not preserve both snapshot leases; memfile has %v", addrs)
	}
	commands := stub.seen()
	if len(commands) != 2 || commands[0].Command != "dhcp-disable" || commands[1].Command != "lease6-get-all" {
		t.Errorf("control commands = %+v, want dhcp-disable before lease6-get-all", commands)
	}
	mu.Lock()
	remainedDisabled := disabled
	mu.Unlock()
	if !remainedDisabled {
		t.Error("DHCPv6 was re-enabled before the takeover restart")
	}
}

func TestPreSeedMemfileMerged4_FailsClosedWhenKeaCannotQuiesce10895(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	sock := tmpSocket(t, "k4disablefail.sock")
	stub := &stubKea{handler: func(cmd keaCommand) keaResponse {
		if cmd.Command == "dhcp-disable" {
			return keaResponse{Result: keaResultError, Text: "disable rejected"}
		}
		return keaResponse{Result: keaResultError, Text: "unexpected"}
	}}
	dial, stop := startStubKea(t, sock, stub)
	defer stop()

	dir := t.TempDir()
	memfile := filepath.Join(dir, "kea-leases4.csv")
	original := []byte(keaMemfileHeader4 + "\n")
	if err := os.WriteFile(memfile, original, 0640); err != nil {
		t.Fatalf("write original memfile: %v", err)
	}
	m := New()
	m.SetLeaseSyncSeamsForTesting(dial, sock, "", memfile, "")
	m.unitActive = func(unit string) (bool, error) {
		if unit != kea4Svc {
			t.Errorf("unitActive checked %q, want %q", unit, kea4Svc)
		}
		return true, nil
	}

	err := m.PreSeedMemfileMerged4WithAuthority(
		context.Background(), LeaseSyncSnapshot{}, now, false, LeaseSyncAuthority{})
	if err == nil {
		t.Fatal("pre-seed succeeded after active Kea rejected dhcp-disable")
	}
	got, readErr := os.ReadFile(memfile)
	if readErr != nil {
		t.Fatalf("read memfile after rejected quiesce: %v", readErr)
	}
	if string(got) != string(original) {
		t.Fatalf("pre-seed replaced memfile while Kea remained active:\n%s", got)
	}
	commands := stub.seen()
	if len(commands) != 1 || commands[0].Command != "dhcp-disable" {
		t.Fatalf("commands after failed quiesce = %+v, want only dhcp-disable", commands)
	}
}

// TestPreSeedForcesRestartWhenConfigIsUnchanged10895 proves the memfile install
// cannot be followed by #10896's unchanged-config restart elision. Kea must
// reload the atomically replaced lease file before DHCP is enabled again.
func TestPreSeedForcesRestartWhenConfigIsUnchanged10895(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	sock := tmpSocket(t, "k4restart.sock")
	stub := &stubKea{handler: func(cmd keaCommand) keaResponse {
		switch cmd.Command {
		case "dhcp-disable":
			return keaResponse{Result: keaResultSuccess, Text: "disabled"}
		case "lease4-get-all":
			return leaseGetAllResponse(nil)
		default:
			return keaResponse{Result: keaResultError, Text: "unexpected"}
		}
	}}
	dial, stop := startStubKea(t, sock, stub)
	defer stop()

	m, calls := testManager(t, map[string]bool{kea4Svc: true}, "")
	memfile := filepath.Join(t.TempDir(), "kea-leases4.csv")
	m.SetLeaseSyncSeamsForTesting(dial, sock, "", memfile, "")
	m.SetKeaOwnerLookupForTesting(func() (int, int, bool) {
		return os.Getuid(), os.Getgid(), true
	})
	cfg := v4Config("reth0.0")
	if err := m.Apply(cfg); err != nil {
		t.Fatalf("initial Apply: %v", err)
	}
	if len(m.appliedConfig4) == 0 {
		t.Fatal("initial Apply did not record the loaded v4 config")
	}

	if err := m.PreSeedMemfileMerged4WithAuthority(
		context.Background(), LeaseSyncSnapshot{}, now, false, LeaseSyncAuthority{}); err != nil {
		t.Fatalf("PreSeedMemfileMerged4WithAuthority: %v", err)
	}
	if m.appliedConfig4 != nil {
		t.Fatal("pre-seed retained the applied-config cache for the old memfile")
	}
	if err := m.Apply(cfg); err != nil {
		t.Fatalf("Apply after pre-seed: %v", err)
	}

	restarts := 0
	for _, call := range *calls {
		if call == "restart "+kea4Svc {
			restarts++
		}
	}
	if restarts != 2 {
		t.Fatalf("identical-config Apply restarted v4 %d times, want 2 (initial load + memfile reload); calls=%v", restarts, *calls)
	}
}

// TestPreSeedMemfileMerged_DropsFallbackMemfileLeases9853 guards the pure
// backup takeover path. When Kea is stopped, getSyncLeases must parse the
// memfile to retain fail-closed validation, but those persisted rows are not
// current local authority and must not be merged back into the promoted
// memfile. A valid peer row still seeds.
//
// The stale row is placed in each LFC generation in turn, including
// `.completed`. Fail-on-revert: restoring the unconditional local+peer merge
// writes the stale row from `.1`/`.2`, while omitting pre-seed generation
// replacement leaves a stale generation in the effective set or leaves
// `.completed` on disk after a peer-only current write.
func TestPreSeedMemfileMerged_DropsFallbackMemfileLeases9853(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	tests := []struct {
		name   string
		family int
		stale  SyncLease
		peer   SyncLease
		header string
	}{
		{
			name:   "v4",
			family: 4,
			stale: SyncLease{
				Family: 4, Address: "10.0.61.103", HWAddress: "02:00:00:00:98:53",
				SubnetID: 1, ValidLife: 86400, Remaining: 72000, State: keaStateDefault,
			},
			peer: SyncLease{
				Family: 4, Address: "10.0.61.101", HWAddress: "02:00:00:00:98:51",
				SubnetID: 1, ValidLife: 86400, Remaining: 3600, State: keaStateDefault,
			},
			header: keaMemfileHeader4,
		},
		{
			name:   "v6",
			family: 6,
			stale: SyncLease{
				Family: 6, Address: "2001:db8:61::103",
				DUID: "00:03:00:01:02:00:00:00:98:53", IAID: 53, LeaseType: "IA_NA",
				SubnetID: 1, ValidLife: 86400, Remaining: 72000, PreferredRemaining: 72000,
				State: keaStateDefault,
			},
			peer: SyncLease{
				Family: 6, Address: "2001:db8:61::101",
				DUID: "00:03:00:01:02:00:00:00:98:51", IAID: 51, LeaseType: "IA_NA",
				SubnetID: 1, ValidLife: 86400, Remaining: 3600, PreferredRemaining: 3600,
				State: keaStateDefault,
			},
			header: keaMemfileHeader6,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for _, suffix := range []string{".1", ".2", ".completed"} {
				t.Run("stale-in"+suffix, func(t *testing.T) {
					dir := t.TempDir()
					memfile := filepath.Join(dir, "kea-leases.csv")
					ctrl4, ctrl6, file4, file6 := "", "", "", ""
					if tc.family == 4 {
						ctrl4, file4 = filepath.Join(dir, "missing4.sock"), memfile
					} else {
						ctrl6, file6 = filepath.Join(dir, "missing6.sock"), memfile
					}
					m := New()
					m.unitActive = func(string) (bool, error) { return false, nil }
					m.SetLeaseSyncSeamsForTesting(nil, ctrl4, ctrl6, file4, file6)
					m.SetKeaOwnerLookupForTesting(func() (int, int, bool) {
						return os.Getuid(), os.Getgid(), true
					})
					if tc.family == 4 {
						if err := m.PreSeedMemfile4([]SyncLease{tc.stale}, now); err != nil {
							t.Fatalf("write stale v4 fixture: %v", err)
						}
					} else {
						if err := m.PreSeedMemfile6([]SyncLease{tc.stale}, now); err != nil {
							t.Fatalf("write stale v6 fixture: %v", err)
						}
					}
					if err := os.Rename(memfile, memfile+suffix); err != nil {
						t.Fatalf("move stale fixture to %s: %v", suffix, err)
					}
					if err := os.WriteFile(memfile, []byte(tc.header+"\n"), 0644); err != nil {
						t.Fatalf("write current header: %v", err)
					}

					var err error
					if tc.family == 4 {
						err = m.PreSeedMemfileMerged4(context.Background(), []SyncLease{tc.peer}, now, false)
					} else {
						err = m.PreSeedMemfileMerged6(context.Background(), []SyncLease{tc.peer}, now, false)
					}
					if err != nil {
						t.Fatalf("merged pre-seed: %v", err)
					}

					var got []ddnsLease
					if tc.family == 4 {
						got, err = parseActiveLeases4(memfile, now)
					} else {
						got, err = parseActiveLeases6(memfile, now)
					}
					if err != nil {
						t.Fatalf("read effective pre-seeded set: %v", err)
					}
					seen := make(map[string]bool, len(got))
					for _, lease := range got {
						seen[lease.Address] = true
					}
					if seen[tc.stale.Address] {
						t.Fatalf("released fallback row %s was re-injected from %s: %+v",
							tc.stale.Address, suffix, got)
					}
					if !seen[tc.peer.Address] {
						t.Fatalf("valid peer row %s was not seeded: %+v", tc.peer.Address, got)
					}
					if _, statErr := os.Stat(memfile + suffix); !os.IsNotExist(statErr) {
						t.Fatalf("stale LFC generation %s survived replacement (stat=%v)", suffix, statErr)
					}
				})
			}
		})
	}
}

// TestPreSeedMemfileMerged_StaggeredFailoverPreservesStillMastered9853 covers
// the hostile-review race: RG-X is already MASTER, its Kea restart is still in
// flight, and RG-Y's synchronous pre-seed runs while the control socket is
// down. The fallback union must preserve RG-X's binding and leave its LFC
// generation intact while adding RG-Y's peer binding.
//
// Fail-on-revert: making stillMastering take the peer-only replacement branch
// drops the RG-X assertion and removes the generation, reproducing the
// duplicate-allocation wipe.
func TestPreSeedMemfileMerged_StaggeredFailoverPreservesStillMastered9853(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	tests := []struct {
		name   string
		family int
		local  SyncLease
		peer   SyncLease
		header string
	}{
		{
			name:   "v4",
			family: 4,
			local: SyncLease{
				Family: 4, Address: "10.0.71.50", HWAddress: "02:00:00:00:71:50",
				SubnetID: 1, ValidLife: 86400, Remaining: 72000, State: keaStateDefault,
			},
			peer: SyncLease{
				Family: 4, Address: "10.0.72.80", HWAddress: "02:00:00:00:72:80",
				SubnetID: 2, ValidLife: 86400, Remaining: 3600, State: keaStateDefault,
			},
			header: keaMemfileHeader4,
		},
		{
			name:   "v6",
			family: 6,
			local: SyncLease{
				Family: 6, Address: "2001:db8:71::50",
				DUID: "00:03:00:01:02:00:00:00:71:50", IAID: 50, LeaseType: "IA_NA",
				SubnetID: 1, ValidLife: 86400, Remaining: 72000, PreferredRemaining: 72000,
				State: keaStateDefault,
			},
			peer: SyncLease{
				Family: 6, Address: "2001:db8:72::80",
				DUID: "00:03:00:01:02:00:00:00:72:80", IAID: 80, LeaseType: "IA_NA",
				SubnetID: 2, ValidLife: 86400, Remaining: 3600, PreferredRemaining: 3600,
				State: keaStateDefault,
			},
			header: keaMemfileHeader6,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			memfile := filepath.Join(dir, "kea-leases.csv")
			ctrl4, ctrl6, file4, file6 := "", "", "", ""
			if tc.family == 4 {
				ctrl4, file4 = filepath.Join(dir, "missing4.sock"), memfile
			} else {
				ctrl6, file6 = filepath.Join(dir, "missing6.sock"), memfile
			}
			m := New()
			m.unitActive = func(string) (bool, error) { return false, nil }
			m.SetLeaseSyncSeamsForTesting(nil, ctrl4, ctrl6, file4, file6)
			m.SetKeaOwnerLookupForTesting(func() (int, int, bool) {
				return os.Getuid(), os.Getgid(), true
			})
			if tc.family == 4 {
				if err := m.PreSeedMemfile4([]SyncLease{tc.local}, now); err != nil {
					t.Fatalf("write local v4 fixture: %v", err)
				}
			} else {
				if err := m.PreSeedMemfile6([]SyncLease{tc.local}, now); err != nil {
					t.Fatalf("write local v6 fixture: %v", err)
				}
			}
			generation := memfile + ".1"
			if err := os.Rename(memfile, generation); err != nil {
				t.Fatalf("move local fixture to LFC generation: %v", err)
			}
			if err := os.WriteFile(memfile, []byte(tc.header+"\n"), 0644); err != nil {
				t.Fatalf("write current header: %v", err)
			}

			var err error
			if tc.family == 4 {
				err = m.PreSeedMemfileMerged4(context.Background(), []SyncLease{tc.peer}, now, true)
			} else {
				err = m.PreSeedMemfileMerged6(context.Background(), []SyncLease{tc.peer}, now, true)
			}
			if err != nil {
				t.Fatalf("staggered-failover pre-seed: %v", err)
			}

			var got []ddnsLease
			if tc.family == 4 {
				got, err = parseActiveLeases4(memfile, now)
			} else {
				got, err = parseActiveLeases6(memfile, now)
			}
			if err != nil {
				t.Fatalf("read effective staggered-failover set: %v", err)
			}
			seen := make(map[string]bool, len(got))
			for _, lease := range got {
				seen[lease.Address] = true
			}
			if !seen[tc.local.Address] || !seen[tc.peer.Address] {
				t.Fatalf("still-mastered fallback union lost a binding: got %v, want %s and %s",
					seen, tc.local.Address, tc.peer.Address)
			}
			if _, statErr := os.Stat(generation); statErr != nil {
				t.Fatalf("still-mastered LFC generation was removed: %v", statErr)
			}
		})
	}
}

// TestRemoveLFCGenerationsAttemptsBoth verifies cleanup attempts every
// lease-bearing generation even when removal fails. A non-empty directory is
// not removable with os.Remove; all generation names must appear in the joined
// error, proving one failure cannot prevent later attempts.
func TestRemoveLFCGenerationsAttemptsBoth(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "kea-leases.csv")
	for _, suffix := range []string{".2", ".1", ".completed"} {
		generation := path + suffix
		if err := os.Mkdir(generation, 0750); err != nil {
			t.Fatalf("mkdir %s: %v", generation, err)
		}
		if err := os.WriteFile(filepath.Join(generation, "keep"), []byte("x"), 0600); err != nil {
			t.Fatalf("write %s: %v", generation, err)
		}
	}
	err := removeLFCGenerations(path)
	if err == nil {
		t.Fatal("removeLFCGenerations returned nil when generation unlinks failed")
	}
	for _, suffix := range []string{".2", ".1", ".completed"} {
		generation := path + suffix
		if !strings.Contains(err.Error(), generation) {
			t.Errorf("joined cleanup error omitted %s: %v", generation, err)
		}
		if _, statErr := os.Stat(generation); statErr != nil {
			t.Errorf("failed-removal fixture %s unexpectedly disappeared: %v", generation, statErr)
		}
	}
}

// TestRemoveLFCGenerationsRemovesCompleted9853 proves a pure-backup
// replacement removes an orphaned, lease-bearing .completed file. Kea loads
// that file in preference to .2/.1 at startup, so leaving it would resurrect
// stale leases after the peer-only current-file write.
func TestRemoveLFCGenerationsRemovesCompleted9853(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "kea-leases.csv")
	completed := path + ".completed"
	if err := os.WriteFile(completed, []byte(keaMemfileHeader4+"\n"), 0600); err != nil {
		t.Fatalf("write completed fixture: %v", err)
	}
	if err := removeLFCGenerations(path); err != nil {
		t.Fatalf("removeLFCGenerations: %v", err)
	}
	if _, err := os.Stat(completed); !os.IsNotExist(err) {
		t.Fatalf("orphaned completed file survived cleanup (stat=%v)", err)
	}
}

// TestPreSeedMemfileMerged4_FailsClosedOnUntrustedLocal proves the #5040
// fail-closed posture: when the local lease source cannot be read (socket down
// AND an existing memfile is corrupt/untrusted), the pre-seed must NOT replace
// the memfile with peer-only rows — it returns an error and leaves the file
// intact so the restarting Kea reloads its own persisted leases (the post-start
// lease-add seed still adds the peer set).
func TestPreSeedMemfileMerged4_FailsClosedOnUntrustedLocal(t *testing.T) {
	localNow := time.Unix(1_700_000_000, 0)
	dir := t.TempDir()
	memfile := filepath.Join(dir, "kea-leases4.csv")
	// A present-but-headerless/mangled memfile is an untrusted local source.
	corrupt := "garbage,not,a,valid,header,at,all\n"
	if err := os.WriteFile(memfile, []byte(corrupt), 0644); err != nil {
		t.Fatal(err)
	}
	m := New()
	m.unitActive = func(string) (bool, error) { return false, nil }
	// nil dialer + a bogus socket path → socket read fails → memfile fallback →
	// corrupt memfile → local read errors.
	m.SetLeaseSyncSeamsForTesting(nil, filepath.Join(dir, "nope.sock"), "", memfile, "")

	peer := []SyncLease{{
		Family: 4, Address: "10.0.2.80", HWAddress: "bb", SubnetID: 2,
		Remaining: 1800, State: keaStateDefault,
	}}
	if err := m.PreSeedMemfileMerged4(context.Background(), peer, localNow, false); err == nil {
		t.Fatalf("expected fail-closed error on untrusted local source, got nil")
	}
	after, rerr := os.ReadFile(memfile)
	if rerr != nil {
		t.Fatal(rerr)
	}
	if string(after) != corrupt {
		t.Errorf("fail-closed must leave the memfile intact, got:\n%s", after)
	}
}

// Test (#2268): the v6 memfile pre-seed must round-trip the lease KIND
// symmetrically with the read path — an IA_TA (temporary-address) lease read
// and held as IA_TA must be written back as lease_type=1 (IA_TA), never silently
// downgraded to lease_type=0 (IA_NA). Before the fix writeMemfile6 only encoded
// IA_PD vs "everything-else as IA_NA", so an IA_TA lease lost its kind across a
// failover. IA_NA and IA_PD rows in the same file prove no regression.
//
// Fail-on-revert: reverting writeMemfile6 to the IA_PD-vs-IA_NA-only writer
// makes the IA_TA assertions fail (the row would read back as IA_NA with
// prefix_len=128, never IA_TA).
func TestPreSeedMemfile6_RoundTrip_PreservesIATA(t *testing.T) {
	localNow := time.Unix(1_700_000_000, 0)
	dir := t.TempDir()
	memfile := filepath.Join(dir, "kea-leases6.csv")
	m := New()
	// Pre-seed writes to memfile6; the read-back fallback (no socket) reads it.
	m.SetLeaseSyncSeamsForTesting(nil, "", filepath.Join(dir, "missing.sock"), "", memfile)

	in := []SyncLease{
		{Family: 6, Address: "2001:db8::1", DUID: "00:01:00:01", IAID: 10,
			LeaseType: "IA_NA", SubnetID: 1, Remaining: 1200, State: keaStateDefault},
		{Family: 6, Address: "2001:db8::2a", DUID: "00:01:00:02", IAID: 20,
			LeaseType: "IA_TA", SubnetID: 1, Remaining: 1800, State: keaStateDefault},
		{Family: 6, Address: "2001:db8:abcd::", DUID: "00:01:00:03", IAID: 30,
			LeaseType: "IA_PD", PrefixLen: 56, SubnetID: 1, Remaining: 2400, State: keaStateDefault},
	}
	if err := m.PreSeedMemfile6(in, localNow); err != nil {
		t.Fatalf("PreSeedMemfile6: %v", err)
	}

	// Direct byte-level assertion: the IA_TA row must carry lease_type=1. This is
	// the tightest fail-on-revert guard — an IA_PD-vs-IA_NA-only writer would
	// emit lease_type=0 for the IA_TA address. The Kea v6 memfile lease_type is
	// the 7th column (index 6).
	raw, err := os.ReadFile(memfile)
	if err != nil {
		t.Fatalf("read pre-seeded memfile: %v", err)
	}
	var sawTAColumn bool
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if !strings.HasPrefix(line, "2001:db8::2a,") {
			continue
		}
		cols := strings.Split(line, ",")
		if len(cols) < 9 {
			t.Fatalf("IA_TA row has too few columns: %q", line)
		}
		if cols[6] != "1" {
			t.Errorf("IA_TA row lease_type column = %q, want 1 (#2268 downgrade regression): %q", cols[6], line)
		}
		// IA_TA is a full /128 address binding, not a delegated prefix.
		if cols[8] != "128" {
			t.Errorf("IA_TA row prefix_len column = %q, want 128: %q", cols[8], line)
		}
		sawTAColumn = true
	}
	if !sawTAColumn {
		t.Fatalf("IA_TA row not found in pre-seeded memfile:\n%s", raw)
	}

	// Full round trip: read the pre-seeded memfile back through the production
	// read path (socket missing → memfile fallback) and assert each kind survives.
	got, err := m.GetSyncLeases6(context.Background(), localNow)
	if err != nil {
		t.Fatalf("GetSyncLeases6 (read-back): %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("read back %d leases, want 3: %+v", len(got), got)
	}
	byAddr := map[string]SyncLease{}
	for _, l := range got {
		byAddr[l.Address] = l
	}

	ta, ok := byAddr["2001:db8::2a"]
	if !ok {
		t.Fatalf("IA_TA lease missing after round trip: %+v", got)
	}
	if ta.LeaseType != "IA_TA" {
		t.Errorf("IA_TA lease round-tripped as %q, want IA_TA (#2268 downgrade)", ta.LeaseType)
	}
	if ta.PrefixLen != 0 {
		t.Errorf("IA_TA lease PrefixLen = %d, want 0 (address, not prefix)", ta.PrefixLen)
	}
	if ta.DUID != "00:01:00:02" || ta.IAID != 20 {
		t.Errorf("IA_TA identity wrong: DUID=%q IAID=%d", ta.DUID, ta.IAID)
	}

	// No regression: IA_NA and IA_PD still round-trip.
	if na := byAddr["2001:db8::1"]; na.LeaseType != "IA_NA" || na.PrefixLen != 0 {
		t.Errorf("IA_NA lease regressed: %+v", na)
	}
	if pd := byAddr["2001:db8:abcd::"]; pd.LeaseType != "IA_PD" || pd.PrefixLen != 56 {
		t.Errorf("IA_PD lease regressed: %+v", pd)
	}
}

// Test (#2386): the v6 memfile pre-seed must emit the lease hardware address in
// the canonical Kea `hwaddr` column. SyncLease.HWAddress is populated for v6
// leases read from the active peer (keaLeaseToSync sets it for both families),
// but writeMemfile6 previously hardcoded the hwaddr column empty, so standby
// takeover stripped the MAC from every IPv6 lease (lost hwaddr-based logging,
// reservation matching, and operator visibility — DHCPv6 keys on DUID so the
// lease itself still worked).
//
// The Kea v6 memfile CSV is POSITIONAL; the hwaddr column is field 13 (1-based)
// in keaMemfileHeader6. This test asserts (a) the per-lease column count matches
// the header exactly so the fix cannot shift any column, and (b) the populated
// HWAddress lands in the hwaddr slot.
//
// Fail-on-revert: reverting writeMemfile6 to the empty-hwaddr writer makes the
// hwaddr-column assertion fail (the field would read back empty).
func TestPreSeedMemfile6_EmitsHWAddress(t *testing.T) {
	localNow := time.Unix(1_700_000_000, 0)
	dir := t.TempDir()
	memfile := filepath.Join(dir, "kea-leases6.csv")
	m := New()
	m.SetLeaseSyncSeamsForTesting(nil, "", filepath.Join(dir, "missing.sock"), "", memfile)

	const wantHW = "aa:bb:cc:dd:ee:f6"
	in := []SyncLease{
		{Family: 6, Address: "2001:db8::abc", DUID: "00:01:00:0a", IAID: 7,
			LeaseType: "IA_NA", HWAddress: wantHW, SubnetID: 1, Remaining: 1200,
			State: keaStateDefault},
	}
	if err := m.PreSeedMemfile6(in, localNow); err != nil {
		t.Fatalf("PreSeedMemfile6: %v", err)
	}

	raw, err := os.ReadFile(memfile)
	if err != nil {
		t.Fatalf("read pre-seeded memfile: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) < 2 {
		t.Fatalf("pre-seeded memfile has no lease row:\n%s", raw)
	}

	// Positional integrity: the lease row must have exactly as many columns as
	// the header, so the inserted hwaddr field cannot off-by-one any column.
	headerCols := strings.Split(keaMemfileHeader6, ",")
	hwIdx := -1
	for i, name := range headerCols {
		if name == "hwaddr" {
			hwIdx = i
			break
		}
	}
	if hwIdx < 0 {
		t.Fatalf("hwaddr column not found in header %q", keaMemfileHeader6)
	}
	// hwaddr is field 13 (1-based) per the canonical Kea v6 header.
	if hwIdx != 12 {
		t.Fatalf("hwaddr column index = %d, want 12 (field 13); header drifted: %q", hwIdx, keaMemfileHeader6)
	}

	var sawRow bool
	for _, line := range lines[1:] {
		if !strings.HasPrefix(line, "2001:db8::abc,") {
			continue
		}
		cols := strings.Split(line, ",")
		if len(cols) != len(headerCols) {
			t.Fatalf("lease row column count = %d, header has %d (positional drift): %q",
				len(cols), len(headerCols), line)
		}
		if cols[hwIdx] != wantHW {
			t.Errorf("hwaddr column (field %d) = %q, want %q (#2386 strip regression): %q",
				hwIdx+1, cols[hwIdx], wantHW, line)
		}
		sawRow = true
	}
	if !sawRow {
		t.Fatalf("lease row not found in pre-seeded memfile:\n%s", raw)
	}
}

// Test (#2268): the lease-type read↔write mapping is a single total inverse —
// keaLeaseTypeToString and stringToKeaLeaseType must agree on every value so the
// pair can never drift to re-introduce an asymmetric downgrade. Every numeric
// type the reader produces must invert back to the same number, and every string
// the writer accepts must come from the reader. The empty string (unknown kind)
// defaults to IA_NA on the write side.
func TestKeaLeaseTypeInverseTotality(t *testing.T) {
	for _, n := range []int{keaLeaseTypeIANA, keaLeaseTypeIATA, keaLeaseTypeIAPD} {
		s, ok := keaLeaseTypeToString(n)
		if !ok {
			t.Fatalf("keaLeaseTypeToString(%d) not ok", n)
		}
		back, ok := stringToKeaLeaseType(s)
		if !ok {
			t.Fatalf("stringToKeaLeaseType(%q) not ok", s)
		}
		if back != n {
			t.Errorf("inverse drift: %d -> %q -> %d", n, s, back)
		}
	}
	// Empty string is the write-side default (unknown kind) → IA_NA.
	if v, ok := stringToKeaLeaseType(""); !ok || v != keaLeaseTypeIANA {
		t.Errorf(`stringToKeaLeaseType("") = %d ok=%v, want %d true`, v, ok, keaLeaseTypeIANA)
	}
	// An unknown non-empty string is rejected (ok=false) and falls back to IA_NA.
	if v, ok := stringToKeaLeaseType("IA_BOGUS"); ok || v != keaLeaseTypeIANA {
		t.Errorf(`stringToKeaLeaseType("IA_BOGUS") = %d ok=%v, want %d false`, v, ok, keaLeaseTypeIANA)
	}
	// An unknown numeric type is rejected (mirrors the read side fail-closed).
	if _, ok := keaLeaseTypeToString(99); ok {
		t.Errorf("keaLeaseTypeToString(99) ok=true, want false")
	}
}

// ownerCall records one writeMemfileFile invocation so the chown-on-pre-seed
// tests (#2450) can assert the resolved Kea owner reached the writer with the
// correct final path — without needing root to perform a real fchown.
type ownerCall struct {
	path       string
	uid, gid   int
	applyOwner bool
}

// installMemfileRecorder swaps the package writeMemfileFile var for a recorder
// that captures the owner decision AND still writes the file (plainly, no
// chown) so any read-back in the test works. It returns the captured calls
// slice (append-only) and a restore func.
func installMemfileRecorder(t *testing.T) (*[]ownerCall, func()) {
	t.Helper()
	var calls []ownerCall
	prev := writeMemfileFile
	writeMemfileFile = func(path string, data []byte, perm os.FileMode, uid, gid int, applyOwner bool) error {
		calls = append(calls, ownerCall{path: path, uid: uid, gid: gid, applyOwner: applyOwner})
		// Write without a chown so the recorder works unprivileged; the
		// production install path's atomic-owner behavior is exercised by
		// fsatomic's own WithOwner tests.
		return os.WriteFile(path, data, perm)
	}
	return &calls, func() { writeMemfileFile = prev }
}

// Test (#2450, HIGH): the memfile pre-seed must chown the file to the resolved
// Kea runtime user so unprivileged Kea can open it RW on takeover; otherwise
// Kea fails to start (EACCES) and DHCP goes dark at failover. The fake resolver
// returns a known uid/gid (no real _kea user needed) and the recorder asserts
// WithOwner was requested with exactly that uid/gid on the FINAL memfile path,
// for BOTH families.
//
// Fail-on-revert: deleting the chown in writeMemfileAtomic (so it writes
// without the resolved owner) makes applyOwner=false / uid/gid=0 here, failing
// the assertions.
func TestPreSeedMemfile_ChownsToKeaUser(t *testing.T) {
	const wantUID, wantGID = 14242, 14243
	localNow := time.Unix(1_700_000_000, 0)
	dir := t.TempDir()
	memfile4 := filepath.Join(dir, "kea-leases4.csv")
	memfile6 := filepath.Join(dir, "kea-leases6.csv")

	calls, restore := installMemfileRecorder(t)
	defer restore()

	m := New()
	m.SetLeaseSyncSeamsForTesting(nil, "", "", memfile4, memfile6)
	m.SetKeaOwnerLookupForTesting(func() (int, int, bool) { return wantUID, wantGID, true })

	if err := m.PreSeedMemfile4([]SyncLease{
		{Family: 4, Address: "10.0.61.42", HWAddress: "aa:bb:cc:dd:ee:42",
			SubnetID: 3, Remaining: 900, State: keaStateDefault},
	}, localNow); err != nil {
		t.Fatalf("PreSeedMemfile4: %v", err)
	}
	if err := m.PreSeedMemfile6([]SyncLease{
		{Family: 6, Address: "2001:db8::1", DUID: "00:01", IAID: 7,
			LeaseType: "IA_NA", SubnetID: 1, Remaining: 1200, State: keaStateDefault},
	}, localNow); err != nil {
		t.Fatalf("PreSeedMemfile6: %v", err)
	}

	if len(*calls) != 2 {
		t.Fatalf("writeMemfileFile called %d times, want 2 (v4+v6)", len(*calls))
	}
	wantPaths := map[string]bool{memfile4: false, memfile6: false}
	for _, c := range *calls {
		if !c.applyOwner {
			t.Errorf("path %s: applyOwner=false, want chown to Kea user", c.path)
		}
		if c.uid != wantUID || c.gid != wantGID {
			t.Errorf("path %s: owner = %d:%d, want %d:%d", c.path, c.uid, c.gid, wantUID, wantGID)
		}
		if _, ok := wantPaths[c.path]; !ok {
			t.Errorf("unexpected pre-seed path %q", c.path)
			continue
		}
		wantPaths[c.path] = true
	}
	for p, seen := range wantPaths {
		if !seen {
			t.Errorf("no pre-seed write to %s", p)
		}
	}
}

// Test (#2450 robustness): when NEITHER Kea user resolves (dev host / Kea not
// installed), the pre-seed must NOT abort the takeover — it writes the file
// without an owner override and returns nil. Aborting here would turn a
// missing-package condition into a failed failover.
//
// The warning is emitted ONCE PER PROCESS from the cached owner resolution,
// NOT per pre-seed: this test pre-seeds BOTH families and asserts exactly one
// warning across the two pre-seeds (a stronger assertion than per-call — if
// the warning regresses back into writeMemfileAtomic it fires twice here and
// this fails).
func TestPreSeedMemfile_NoKeaUser_WarnsAndSucceeds(t *testing.T) {
	localNow := time.Unix(1_700_000_000, 0)
	dir := t.TempDir()
	memfile4 := filepath.Join(dir, "kea-leases4.csv")
	memfile6 := filepath.Join(dir, "kea-leases6.csv")

	calls, restore := installMemfileRecorder(t)
	defer restore()

	var warnings []string
	m := New()
	m.SetLeaseSyncSeamsForTesting(nil, "", "", memfile4, memfile6)
	m.SetWarnForTesting(func(msg string, _ ...any) { warnings = append(warnings, msg) })
	m.SetKeaOwnerLookupForTesting(func() (int, int, bool) { return 0, 0, false })

	if err := m.PreSeedMemfile4([]SyncLease{
		{Family: 4, Address: "10.0.61.7", HWAddress: "aa:bb:cc:dd:ee:07",
			SubnetID: 3, Remaining: 600, State: keaStateDefault},
	}, localNow); err != nil {
		t.Fatalf("PreSeedMemfile4 must not abort when Kea user absent: %v", err)
	}
	if err := m.PreSeedMemfile6([]SyncLease{
		{Family: 6, Address: "2001:db8::7", DUID: "00:09", IAID: 9,
			LeaseType: "IA_NA", SubnetID: 1, Remaining: 600, State: keaStateDefault},
	}, localNow); err != nil {
		t.Fatalf("PreSeedMemfile6 must not abort when Kea user absent: %v", err)
	}

	// The v4 file was still written (takeover not aborted) and is parseable.
	got, err := parseActiveLeases4(memfile4, localNow)
	if err != nil {
		t.Fatalf("parseActiveLeases4 on pre-seeded file: %v", err)
	}
	if len(got) != 1 || got[0].Address != "10.0.61.7" {
		t.Fatalf("pre-seeded memfile = %+v, want the one lease", got)
	}
	// Both families written, neither with an owner override.
	if len(*calls) != 2 {
		t.Fatalf("writeMemfileFile called %d times, want 2 (v4+v6)", len(*calls))
	}
	for _, c := range *calls {
		if c.applyOwner {
			t.Errorf("path %s: applyOwner=true, want no owner override when Kea user absent", c.path)
		}
	}
	// Exactly ONE warning across both pre-seeds (once per process).
	if len(warnings) != 1 || !strings.Contains(warnings[0], "_kea") {
		t.Errorf("warnings = %v, want exactly one mentioning the missing Kea user", warnings)
	}
}

// Test (#2450): the Kea owner resolution is cached behind sync.Once — the
// takeover path may pre-seed both families (and re-seed on retry) without
// re-reading the user database each time.
func TestResolveKeaOwner_CachedOnce(t *testing.T) {
	m := New()
	var lookups int
	m.SetKeaOwnerLookupForTesting(func() (int, int, bool) {
		lookups++
		return 991, 992, true
	})
	for i := 0; i < 3; i++ {
		uid, gid, ok := m.resolveKeaOwner()
		if !ok || uid != 991 || gid != 992 {
			t.Fatalf("resolveKeaOwner() = %d:%d ok=%v, want 991:992 true", uid, gid, ok)
		}
	}
	if lookups != 1 {
		t.Errorf("user lookup ran %d times, want 1 (cached)", lookups)
	}
}

// TestSplitV6Identity verifies the IAID parse contract from #2379: a present
// but unparseable IAID now surfaces an error (so the takeover-seed loop can
// log+skip the lease) instead of silently swallowing to iaid=0, while a
// legitimate decimal IAID parses and the no-slash form stays a clean iaid=0
// with no error.
//
// fail-on-revert: reverting splitV6Identity to the silent err==nil swallow
// makes the malformed cases below (which require err != nil) go red.
func TestSplitV6Identity(t *testing.T) {
	tests := []struct {
		name     string
		identity string
		wantDUID string
		wantIAID uint32
		wantErr  bool
	}{
		{"valid", "duid:0011223344556677/42", "0011223344556677", 42, false},
		{"valid zero iaid", "duid:0011223344556677/0", "0011223344556677", 0, false},
		{"no slash no iaid", "duid:0011223344556677", "0011223344556677", 0, false},
		{"no prefix no slash", "0011223344556677", "0011223344556677", 0, false},
		{"malformed iaid", "duid:0011223344556677/notanumber", "0011223344556677", 0, true},
		{"empty iaid", "duid:0011223344556677/", "0011223344556677", 0, true},
		{"oversized iaid", "duid:0011223344556677/4294967296", "0011223344556677", 0, true},
		{"negative iaid", "duid:0011223344556677/-1", "0011223344556677", 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			duid, iaid, err := splitV6Identity(tt.identity)
			if (err != nil) != tt.wantErr {
				t.Fatalf("splitV6Identity(%q) err=%v, wantErr=%v", tt.identity, err, tt.wantErr)
			}
			if duid != tt.wantDUID {
				t.Errorf("splitV6Identity(%q) duid=%q, want %q", tt.identity, duid, tt.wantDUID)
			}
			if iaid != tt.wantIAID {
				t.Errorf("splitV6Identity(%q) iaid=%d, want %d", tt.identity, iaid, tt.wantIAID)
			}
		})
	}
}

// TestKeaMemfileHeadersMatchKea30xSchema pins the Kea 3.0.x memfile CSV schema
// (the appliance ships kea-common live-verified at 3.0.3, per dhcpserver.go) as
// EXTERNAL ground truth and asserts the production keaMemfileHeader{4,6} consts
// match it byte-for-byte (#2261).
//
// Why this test exists — the byte-exactness risk it closes:
// The other memfile tests are self-referential. TestPreSeedMemfile6_EmitsHWAddress
// derives its expected column layout from keaMemfileHeader6 itself
// (strings.Split(keaMemfileHeader6, ",")), and the writer emits that same const,
// so a CO-DRIFT of the const AND the writer still passes them — yet a reordered
// or renamed column silently breaks the LIVE Kea loader when the promoted node
// reads the standby's pre-seeded memfile on failover (the memfile CSV is
// positional). The live "client keeps its lease across a real failover" smoke is
// the only other witness for that drift, and it is lab-gated (plan-deferred-lab).
//
// This test hard-codes the exact Kea 3.0.x lease4/lease6 header column order as a
// LITERAL string, transcribed from the Kea source of truth (CSVLeaseFile4 /
// CSVLeaseFile6 schemas), NOT derived from the production const. Mutating the
// production const — or the writer — by even one column therefore FAILS here
// (RED-on-revert), catching the drift without a lab window.
//
// Column order source of truth (Kea 3.0.x):
//
//	lease4 (12 cols): address,hwaddr,client_id,valid_lifetime,expire,subnet_id,
//	                  fqdn_fwd,fqdn_rev,hostname,state,user_context,pool_id
//	lease6 (18 cols): address,duid,valid_lifetime,expire,subnet_id,pref_lifetime,
//	                  lease_type,iaid,prefix_len,fqdn_fwd,fqdn_rev,hostname,hwaddr,
//	                  state,user_context,hwtype,hwaddr_source,pool_id
//	                  (hwaddr is field 13 / index 12 — see
//	                  TestPreSeedMemfile6_EmitsHWAddress).
func TestKeaMemfileHeadersMatchKea30xSchema(t *testing.T) {
	// Literal Kea 3.0.x DHCPv4 memfile CSV header (12 columns). Hand-transcribed
	// from the Kea schema — deliberately NOT built from keaMemfileHeader4, so this
	// is external ground truth and not a self-referential tautology.
	const goldenKea30xHeader4 = "address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state,user_context,pool_id"
	// Literal Kea 3.0.x DHCPv6 memfile CSV header (18 columns). Hand-transcribed
	// from the Kea schema — NOT derived from keaMemfileHeader6.
	const goldenKea30xHeader6 = "address,duid,valid_lifetime,expire,subnet_id,pref_lifetime,lease_type,iaid,prefix_len,fqdn_fwd,fqdn_rev,hostname,hwaddr,state,user_context,hwtype,hwaddr_source,pool_id"

	// (1) The production consts must equal the golden literals byte-for-byte. This
	// is the core external-ground-truth assertion: reorder/rename/add/drop a
	// column in keaMemfileHeader{4,6} and this fails, even if the writer moved with
	// it.
	if keaMemfileHeader4 != goldenKea30xHeader4 {
		t.Errorf("keaMemfileHeader4 drifted from the Kea 3.0.x lease4 schema:\n  got:  %q\n  want: %q",
			keaMemfileHeader4, goldenKea30xHeader4)
	}
	if keaMemfileHeader6 != goldenKea30xHeader6 {
		t.Errorf("keaMemfileHeader6 drifted from the Kea 3.0.x lease6 schema:\n  got:  %q\n  want: %q",
			keaMemfileHeader6, goldenKea30xHeader6)
	}

	// (2) Independent column-count guard on the golden literals themselves (a live
	// Kea loader keys every field positionally, so the count must be exact). This
	// also fails loudly if a future editor mangles the golden string in this test.
	if n := len(strings.Split(goldenKea30xHeader4, ",")); n != 12 {
		t.Errorf("golden lease4 header has %d columns, want 12", n)
	}
	if n := len(strings.Split(goldenKea30xHeader6, ",")); n != 18 {
		t.Errorf("golden lease6 header has %d columns, want 18", n)
	}

	// (3) The WRITERS must emit exactly the golden column count. Encode one lease
	// per family and count the emitted fields against the golden headers (not the
	// production const). This is what catches the #2261 co-drift the self-
	// referential tests miss: if BOTH the header const and the writer format string
	// gain/lose a column together, (1) still passes for the writer's own const but
	// this fails against the external golden count.
	localNow := time.Unix(1_700_000_000, 0)
	dir := t.TempDir()
	memfile4 := filepath.Join(dir, "kea-leases4.csv")
	memfile6 := filepath.Join(dir, "kea-leases6.csv")
	m := New()
	m.SetLeaseSyncSeamsForTesting(nil, "", "", memfile4, memfile6)

	if err := m.PreSeedMemfile4([]SyncLease{
		{Family: 4, Address: "10.0.61.42", HWAddress: "aa:bb:cc:dd:ee:42",
			ClientID: "01:aa:bb:cc:dd:ee:42", SubnetID: 3, Remaining: 900,
			Hostname: "golden4", State: keaStateDefault},
	}, localNow); err != nil {
		t.Fatalf("PreSeedMemfile4: %v", err)
	}
	if err := m.PreSeedMemfile6([]SyncLease{
		{Family: 6, Address: "2001:db8::42", DUID: "00:01:00:0a", IAID: 7,
			LeaseType: "IA_NA", HWAddress: "aa:bb:cc:dd:ee:f6", SubnetID: 1,
			Remaining: 1200, State: keaStateDefault},
	}, localNow); err != nil {
		t.Fatalf("PreSeedMemfile6: %v", err)
	}

	wantCols := map[int]struct {
		path   string
		golden string
		want   int
	}{
		4: {memfile4, goldenKea30xHeader4, 12},
		6: {memfile6, goldenKea30xHeader6, 18},
	}
	for family, tc := range wantCols {
		raw, err := os.ReadFile(tc.path)
		if err != nil {
			t.Fatalf("read pre-seeded v%d memfile: %v", family, err)
		}
		lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
		if len(lines) < 2 {
			t.Fatalf("pre-seeded v%d memfile has no lease row:\n%s", family, raw)
		}
		// Header line must itself be byte-exact against the golden.
		if lines[0] != tc.golden {
			t.Errorf("v%d memfile header line drifted:\n  got:  %q\n  want: %q",
				family, lines[0], tc.golden)
		}
		// The lease data row must have exactly the golden column count.
		if n := len(strings.Split(lines[1], ",")); n != tc.want {
			t.Errorf("v%d lease row emitted %d columns, want %d (writer/header drift): %q",
				family, n, tc.want, lines[1])
		}
	}
}

// TestKeaLeaseToSync_PreferredRemaining is the #5073 socket-reader guard. Kea's
// lease6-get-all reports valid-lft AND preferred-lft; both count from cltt, so
// the preferred remaining is anchored to the same expire as the valid remaining:
//
//	preferred_remaining = valid_remaining - (valid-lft - preferred-lft)
//
// A DEPRECATED binding (preferred-lft=0) must read PreferredRemaining=0, NOT the
// valid remaining — reading valid revives it on takeover. When Kea omits
// preferred-lft (nil), default preferred==valid.
//
// FAIL-ON-REVERT: drop the preferred-lft handling in keaLeaseToSync and the
// deprecated case reads PreferredRemaining=Remaining (revival) → RED.
func TestKeaLeaseToSync_PreferredRemaining(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	intp := func(n int) *int { return &n }
	// cltt+valid-lft-now = (now-600+3600)-now = 3000 valid remaining.
	base := keaLeaseJSON{
		IPAddress: "2001:db8::1", DUID: "00:01:00:01", IAID: 7, Type: "IA_NA",
		SubnetID: 1, ValidLft: 3600, CLTT: now.Unix() - 600, State: keaStateDefault,
	}
	cases := []struct {
		name    string
		prefLft *int
		want    int
	}{
		{"deprecated", intp(0), 0},           // 3000 - (3600-0) = -600 -> clamp 0
		{"partial", intp(1200), 600},         // 3000 - (3600-1200) = 600
		{"healthy", intp(3600), 3000},        // 3000 - 0 = 3000 == Remaining
		{"absent-defaults-valid", nil, 3000}, // no preferred-lft -> preferred==valid
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			kl := base
			kl.PreferredLft = tc.prefLft
			l := keaLeaseToSync(kl, 6, now)
			if l.Remaining != 3000 {
				t.Fatalf("Remaining = %d, want 3000", l.Remaining)
			}
			if l.PreferredRemaining != tc.want {
				t.Errorf("PreferredRemaining = %d, want %d", l.PreferredRemaining, tc.want)
			}
			if l.PreferredRemaining < 0 || l.PreferredRemaining > l.Remaining {
				t.Errorf("invariant 0 <= PreferredRemaining(%d) <= Remaining(%d) violated",
					l.PreferredRemaining, l.Remaining)
			}
		})
	}
}

// TestGetSyncLeases6_MemfileFallback_PreferredRemaining is the #5073 memfile-
// reader guard. The v6 memfile carries distinct valid_lifetime and pref_lifetime
// columns; the fallback read must recover a preferred remaining that does NOT
// revive a deprecated (pref_lifetime=0) binding. valid_lifetime=3600 with
// expire=now+1800 means the lease aged 1800s (Remaining=1800), so:
//   - pref_lifetime=0    -> PreferredRemaining=0    (deprecated, not revived)
//   - pref_lifetime=2400 -> PreferredRemaining=600  (1800-(3600-2400))
//   - pref_lifetime=3600 -> PreferredRemaining=1800 (== Remaining, healthy)
//
// FAIL-ON-REVERT: drop the pref_lifetime handling and every lease reads
// PreferredRemaining=Remaining, so the deprecated row's want-0 assertion goes RED.
func TestGetSyncLeases6_MemfileFallback_PreferredRemaining(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	dir := t.TempDir()
	memfile := filepath.Join(dir, "kea-leases6.csv")
	expire := strconv.FormatInt(now.Unix()+1800, 10) // Remaining = 1800 for all rows
	csv := keaMemfileHeader6 + "\n" +
		// address,duid,valid_lifetime,expire,subnet_id,pref_lifetime,lease_type,iaid,prefix_len,...
		"2001:db8::dep,00:01:00:01,3600," + expire + ",1,0,0,1,128,0,0,dep,,0,,,,0\n" +
		"2001:db8::par,00:01:00:02,3600," + expire + ",1,2400,0,2,128,0,0,par,,0,,,,0\n" +
		"2001:db8::ok,00:01:00:03,3600," + expire + ",1,3600,0,3,128,0,0,ok,,0,,,,0\n"
	if err := os.WriteFile(memfile, []byte(csv), 0644); err != nil {
		t.Fatal(err)
	}
	m := New()
	m.SetLeaseSyncSeamsForTesting(nil, "", filepath.Join(dir, "missing.sock"), "", memfile)

	leases, err := m.GetSyncLeases6(context.Background(), now)
	if err != nil {
		t.Fatalf("GetSyncLeases6 (fallback): %v", err)
	}
	byAddr := map[string]SyncLease{}
	for _, l := range leases {
		byAddr[l.Address] = l
	}
	want := map[string]int{"2001:db8::dep": 0, "2001:db8::par": 600, "2001:db8::ok": 1800}
	for addr, wantPref := range want {
		l, ok := byAddr[addr]
		if !ok {
			t.Fatalf("lease %s missing from fallback read: %+v", addr, leases)
		}
		if l.Remaining != 1800 {
			t.Errorf("%s Remaining = %d, want 1800", addr, l.Remaining)
		}
		if l.PreferredRemaining != wantPref {
			t.Errorf("%s PreferredRemaining = %d, want %d", addr, l.PreferredRemaining, wantPref)
		}
	}
}

// TestGetSyncLeases6_MemfileFallback_AbsentPrefColumnDefaultsValid confirms an
// OLD v6 memfile that lacks the pref_lifetime column defaults preferred==valid
// (PreferredRemaining=Remaining), never 0 — an absent column must not deprecate.
func TestGetSyncLeases6_MemfileFallback_AbsentPrefColumnDefaultsValid(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	dir := t.TempDir()
	memfile := filepath.Join(dir, "kea-leases6.csv")
	expire := strconv.FormatInt(now.Unix()+1800, 10)
	// A minimal header WITHOUT pref_lifetime / valid_lifetime (only the required
	// columns + expire). PreferredRemaining must default to Remaining.
	csv := "address,duid,expire,subnet_id,lease_type,iaid,prefix_len,fqdn_fwd,fqdn_rev,hostname,state\n" +
		"2001:db8::old,00:01:00:09," + expire + ",1,0,9,128,0,0,old,0\n"
	if err := os.WriteFile(memfile, []byte(csv), 0644); err != nil {
		t.Fatal(err)
	}
	m := New()
	m.SetLeaseSyncSeamsForTesting(nil, "", filepath.Join(dir, "missing.sock"), "", memfile)

	leases, err := m.GetSyncLeases6(context.Background(), now)
	if err != nil {
		t.Fatalf("GetSyncLeases6 (fallback): %v", err)
	}
	if len(leases) != 1 {
		t.Fatalf("want 1 lease, got %d: %+v", len(leases), leases)
	}
	if leases[0].Remaining != 1800 || leases[0].PreferredRemaining != 1800 {
		t.Errorf("absent pref_lifetime column: Remaining=%d PreferredRemaining=%d, want 1800/1800",
			leases[0].Remaining, leases[0].PreferredRemaining)
	}
}

// TestPreSeedMemfile6_PreferredLifetime is the #5073 pre-seed-writer guard. The
// v6 memfile pref_lifetime column (index 5) must carry PreferredRemaining, while
// valid_lifetime (index 2) carries the valid remaining — the two lifetimes are
// written INDEPENDENTLY. A deprecated binding (PreferredRemaining=0, Remaining=
// 1800) must emit pref_lifetime=0 with valid_lifetime=1800; before #5073 the
// writer substituted the valid remaining into pref_lifetime, reviving it.
//
// FAIL-ON-REVERT: restore `rem` (the valid remaining) in the pref_lifetime slot
// and the deprecated row emits pref_lifetime=1800 → the want-"0" assertion RED.
func TestPreSeedMemfile6_PreferredLifetime(t *testing.T) {
	localNow := time.Unix(1_700_000_000, 0)
	dir := t.TempDir()
	memfile6 := filepath.Join(dir, "kea-leases6.csv")
	m := New()
	m.SetLeaseSyncSeamsForTesting(nil, "", "", "", memfile6)

	if err := m.PreSeedMemfile6([]SyncLease{
		{Family: 6, Address: "2001:db8::d", DUID: "00:01:00:01", IAID: 1,
			LeaseType: "IA_NA", SubnetID: 1, Remaining: 1800, PreferredRemaining: 0,
			State: keaStateDefault}, // deprecated
		{Family: 6, Address: "2001:db8::a", DUID: "00:01:00:02", IAID: 2,
			LeaseType: "IA_NA", SubnetID: 1, Remaining: 1800, PreferredRemaining: 600,
			State: keaStateDefault}, // partially deprecated
		{Family: 6, Address: "2001:db8::b", DUID: "00:01:00:03", IAID: 3,
			LeaseType: "IA_NA", SubnetID: 1, Remaining: 1800, PreferredRemaining: 1800,
			State: keaStateDefault}, // healthy
	}, localNow); err != nil {
		t.Fatalf("PreSeedMemfile6: %v", err)
	}

	raw, err := os.ReadFile(memfile6)
	if err != nil {
		t.Fatalf("read pre-seeded memfile: %v", err)
	}
	rows := map[string][]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n")[1:] {
		f := strings.Split(line, ",")
		rows[f[0]] = f // key by address column
	}
	// v6 column order: address(0),duid(1),valid_lifetime(2),expire(3),
	// subnet_id(4),pref_lifetime(5),lease_type(6),...
	want := map[string]struct{ valid, pref string }{
		"2001:db8::d": {"1800", "0"},
		"2001:db8::a": {"1800", "600"},
		"2001:db8::b": {"1800", "1800"},
	}
	for addr, w := range want {
		f, ok := rows[addr]
		if !ok {
			t.Fatalf("row for %s missing:\n%s", addr, raw)
		}
		if f[2] != w.valid {
			t.Errorf("%s valid_lifetime(col2) = %q, want %q", addr, f[2], w.valid)
		}
		if f[5] != w.pref {
			t.Errorf("%s pref_lifetime(col5) = %q, want %q (independent of valid_lifetime)",
				addr, f[5], w.pref)
		}
	}
}
