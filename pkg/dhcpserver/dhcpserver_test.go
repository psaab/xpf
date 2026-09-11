package dhcpserver

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// testManager builds a Manager with recording seams. activeUnits maps
// unit name → is-active answer; calls records every runSystemctl
// invocation as a joined string ("restart kea-dhcp4-server").
func testManager(t *testing.T, activeUnits map[string]bool, failCmd string) (*Manager, *[]string) {
	t.Helper()
	dir := t.TempDir()
	calls := &[]string{}
	m := NewManagerForTesting(
		filepath.Join(dir, "kea-dhcp4.conf"),
		filepath.Join(dir, "kea-dhcp6.conf"),
		func(args ...string) error {
			c := strings.Join(args, " ")
			*calls = append(*calls, c)
			if failCmd != "" && c == failCmd {
				return fmt.Errorf("systemctl %s: exit status 1", c)
			}
			return nil
		},
		func(unit string) bool { return activeUnits[unit] },
	)
	return m, calls
}

func v4Config(ifaces ...string) *config.DHCPServerConfig {
	return &config.DHCPServerConfig{
		DHCPLocalServer: &config.DHCPLocalServerConfig{
			Groups: map[string]*config.DHCPServerGroup{
				"g0": {
					Name:       "g0",
					Interfaces: ifaces,
					Pools: []*config.DHCPPool{{
						Name:     "p0",
						Subnet:   "10.0.1.0/24",
						RangeLow: "10.0.1.100", RangeHigh: "10.0.1.200",
					}},
				},
			},
		},
	}
}

func calledWith(calls []string, want string) bool {
	for _, c := range calls {
		if c == want {
			return true
		}
	}
	return false
}

// A stale Kea from a PREVIOUS daemon must be stopped when the new
// config has no dhcp-server stanza, even though this Manager never
// started it (#1778: reconcile against systemd state, not booleans).
func TestApplyNilStopsStaleActiveUnits(t *testing.T) {
	m, calls := testManager(t, map[string]bool{kea4Svc: true, kea6Svc: true}, "")
	for _, p := range []string{m.confPath4, m.confPath6} {
		if err := os.WriteFile(p, []byte("{}"), 0644); err != nil {
			t.Fatal(err)
		}
	}

	if err := m.Apply(nil); err != nil {
		t.Fatalf("Apply(nil): %v", err)
	}
	if !calledWith(*calls, "stop "+kea4Svc) || !calledWith(*calls, "stop "+kea6Svc) {
		t.Errorf("expected stop of both active units, got calls %v", *calls)
	}
	for _, p := range []string{m.confPath4, m.confPath6} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("config %s not removed", p)
		}
	}
}

// Removing one family from config stops that family's active unit
// while the other family restarts normally.
func TestApplyConfigRemovedFamilyStopsActiveUnit(t *testing.T) {
	m, calls := testManager(t, map[string]bool{kea6Svc: true}, "")

	if err := m.Apply(v4Config("ge-0-0-0")); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !calledWith(*calls, "restart "+kea4Svc) {
		t.Errorf("expected restart of %s, got %v", kea4Svc, *calls)
	}
	if !calledWith(*calls, "stop "+kea6Svc) {
		t.Errorf("expected stop of active %s, got %v", kea6Svc, *calls)
	}
}

// Inactive units are not stopped — no systemctl churn on the common
// no-DHCP-config commit path.
func TestApplyClearSkipsInactiveUnits(t *testing.T) {
	m, calls := testManager(t, map[string]bool{}, "")
	if err := m.Apply(nil); err != nil {
		t.Fatalf("Apply(nil): %v", err)
	}
	if len(*calls) != 0 {
		t.Errorf("expected no systemctl calls for inactive units, got %v", *calls)
	}
}

// Fail-closed (#1778): a Kea restart failure must fail Apply so the
// commit surfaces it, instead of logging Warn and returning nil.
func TestApplyRestartFailureFailsApply(t *testing.T) {
	m, _ := testManager(t, map[string]bool{}, "restart "+kea4Svc)
	err := m.Apply(v4Config("ge-0-0-0"))
	if err == nil {
		t.Fatal("expected error from failed restart, got nil")
	}
	if !strings.Contains(err.Error(), kea4Svc) {
		t.Errorf("error should name the unit: %v", err)
	}
}

// Failing to stop an active unit that is no longer configured is also
// surfaced (the stale server would keep handing out old leases).
func TestApplyStopFailureFailsApply(t *testing.T) {
	m, _ := testManager(t, map[string]bool{kea4Svc: true}, "stop "+kea4Svc)
	err := m.Apply(nil)
	if err == nil {
		t.Fatal("expected error from failed stop, got nil")
	}
	if !strings.Contains(err.Error(), kea4Svc) {
		t.Errorf("error should name the unit: %v", err)
	}
}

// Clear is authoritative too: stops units systemd reports active even
// when this process never started them.
func TestClearStopsStaleActiveUnits(t *testing.T) {
	m, calls := testManager(t, map[string]bool{kea4Svc: true, kea6Svc: true}, "")
	m.Clear()
	if !calledWith(*calls, "stop "+kea4Svc) || !calledWith(*calls, "stop "+kea6Svc) {
		t.Errorf("expected stop of both active units, got %v", *calls)
	}
}

// IsRunning reflects systemd state, surviving daemon restarts.
func TestIsRunningQueriesSystemd(t *testing.T) {
	m, _ := testManager(t, map[string]bool{kea6Svc: true}, "")
	if !m.IsRunning() {
		t.Error("IsRunning should be true when a unit is active")
	}
	m2, _ := testManager(t, map[string]bool{}, "")
	if m2.IsRunning() {
		t.Error("IsRunning should be false when no unit is active")
	}
}

// Multi-interface groups: the per-subnet interface binding (which Kea
// limits to ONE interface) is omitted so address-based subnet
// selection serves every interface; single-interface groups keep the
// explicit binding. interfaces-config always lists all interfaces.
func TestGroupBindingAllInterfaces(t *testing.T) {
	type subnet struct {
		Subnet    string `json:"subnet"`
		Interface string `json:"interface"`
	}
	type dhcp4 struct {
		InterfacesConfig struct {
			Interfaces []string `json:"interfaces"`
		} `json:"interfaces-config"`
		Subnet4 []subnet `json:"subnet4"`
	}

	readConf := func(t *testing.T, m *Manager) dhcp4 {
		t.Helper()
		data, err := os.ReadFile(m.confPath4)
		if err != nil {
			t.Fatal(err)
		}
		var out struct {
			Dhcp4 dhcp4 `json:"Dhcp4"`
		}
		if err := json.Unmarshal(data, &out); err != nil {
			t.Fatal(err)
		}
		return out.Dhcp4
	}

	t.Run("multi-interface group omits subnet binding", func(t *testing.T) {
		m, _ := testManager(t, map[string]bool{}, "")
		if err := m.Apply(v4Config("ge-0-0-0", "ge-0-0-1")); err != nil {
			t.Fatalf("Apply: %v", err)
		}
		conf := readConf(t, m)
		if got := conf.InterfacesConfig.Interfaces; len(got) != 2 {
			t.Errorf("interfaces-config should list all group interfaces, got %v", got)
		}
		if len(conf.Subnet4) != 1 {
			t.Fatalf("want 1 subnet, got %d", len(conf.Subnet4))
		}
		if conf.Subnet4[0].Interface != "" {
			t.Errorf("multi-interface group must not bind subnet to %q (silent first-interface drop)",
				conf.Subnet4[0].Interface)
		}
	})

	t.Run("single-interface group binds explicitly", func(t *testing.T) {
		m, _ := testManager(t, map[string]bool{}, "")
		if err := m.Apply(v4Config("ge-0-0-0")); err != nil {
			t.Fatalf("Apply: %v", err)
		}
		conf := readConf(t, m)
		if len(conf.Subnet4) != 1 || conf.Subnet4[0].Interface != "ge-0-0-0" {
			t.Errorf("single-interface group should bind subnet, got %+v", conf.Subnet4)
		}
	})
}

// Apply must report a generate failure (unwritable config dir) for
// the broken family without masking it.
func TestApplyGenerateFailureFailsApply(t *testing.T) {
	m, calls := testManager(t, map[string]bool{}, "")
	// Point confPath4 inside a path that cannot be created (a file in
	// the way of the directory component).
	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, nil, 0644); err != nil {
		t.Fatal(err)
	}
	m.confPath4 = filepath.Join(blocker, "sub", "kea-dhcp4.conf")

	err := m.Apply(v4Config("ge-0-0-0"))
	if err == nil {
		t.Fatal("expected generate error, got nil")
	}
	if calledWith(*calls, "restart "+kea4Svc) {
		t.Errorf("must not restart kea4 after generate failure: %v", *calls)
	}
	var pe *os.PathError
	if !errors.As(err, &pe) {
		t.Errorf("expected wrapped path error, got %v", err)
	}
}

// leaseTestNow is a fixed reference time BEFORE the 2024-02 expire
// epochs used by the legacy fixtures (1707868800 / 1707955200), so the
// expire filter added in #2085 keeps those (state=0) rows live and the
// pre-existing assertions still hold. New #2085 tests use their own now.
var leaseTestNow = time.Unix(1707800000, 0) // 2024-02-13 03:33:20 UTC

func TestParseLeaseCSV(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "kea-leases4.csv")
	csv := `address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state,user_context,pool_id
10.0.1.100,aa:bb:cc:dd:ee:01,,86400,1707868800,1,0,0,client1,0,,0
10.0.1.101,aa:bb:cc:dd:ee:02,,86400,1707955200,1,0,0,client2,0,,0
`
	if err := os.WriteFile(path, []byte(csv), 0644); err != nil {
		t.Fatal(err)
	}

	leases, err := parseLeaseCSV(path, leaseTestNow)
	if err != nil {
		t.Fatal(err)
	}
	if len(leases) != 2 {
		t.Fatalf("got %d leases, want 2", len(leases))
	}

	l := leases[0]
	if l.Address != "10.0.1.100" {
		t.Errorf("address: got %q", l.Address)
	}
	if l.HWAddress != "aa:bb:cc:dd:ee:01" {
		t.Errorf("hwaddr: got %q", l.HWAddress)
	}
	if l.Hostname != "client1" {
		t.Errorf("hostname: got %q", l.Hostname)
	}
	if l.ValidLife != "86400" {
		t.Errorf("valid_lifetime: got %q", l.ValidLife)
	}
	if l.SubnetID != "1" {
		t.Errorf("subnet_id: got %q", l.SubnetID)
	}
}

func TestParseLeaseCSV_NoFile(t *testing.T) {
	leases, err := parseLeaseCSV("/nonexistent/path", leaseTestNow)
	if err != nil {
		t.Fatal(err)
	}
	if leases != nil {
		t.Errorf("expected nil for nonexistent file, got %v", leases)
	}
}

func TestParseLeaseCSV_Empty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "kea-leases4.csv")
	if err := os.WriteFile(path, []byte("address,hwaddr\n"), 0644); err != nil {
		t.Fatal(err)
	}

	leases, err := parseLeaseCSV(path, leaseTestNow)
	if err != nil {
		t.Fatal(err)
	}
	if len(leases) != 0 {
		t.Errorf("expected no leases, got %d", len(leases))
	}
}

// Quoted fields containing commas must not shift columns (#1778:
// encoding/csv instead of strings.Split).
func TestParseLeaseCSV_QuotedHostname(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "kea-leases4.csv")
	csvData := `address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state,user_context,pool_id
10.0.1.100,aa:bb:cc:dd:ee:01,,86400,1707868800,1,0,0,"host, with comma",0,,0
`
	if err := os.WriteFile(path, []byte(csvData), 0644); err != nil {
		t.Fatal(err)
	}

	leases, err := parseLeaseCSV(path, leaseTestNow)
	if err != nil {
		t.Fatal(err)
	}
	if len(leases) != 1 {
		t.Fatalf("got %d leases, want 1", len(leases))
	}
	if leases[0].Hostname != "host, with comma" {
		t.Errorf("hostname: got %q", leases[0].Hostname)
	}
	if leases[0].SubnetID != "1" {
		t.Errorf("subnet_id shifted: got %q", leases[0].SubnetID)
	}
}

// indexLeasesByAddr collapses a lease slice to an address→Lease map so
// the #2085 tests can assert per-address presence and field values; the
// expected lease count is asserted separately via len(leases).
func indexLeasesByAddr(leases []Lease) map[string]Lease {
	m := make(map[string]Lease, len(leases))
	for _, l := range leases {
		m[l.Address] = l
	}
	return m
}

// TestParseLeaseCSV_ExpiredAndDuplicate pins the core of #2085: Kea's
// memfile is append-only, so the SAME address appears multiple times
// (renewals) and lapsed leases linger until LFC. The display parser
// must collapse to one row per address (newest wins) and drop expired
// rows. Non-tautological: against the pre-#2085 parser this fixture
// returns FOUR rows (the duplicate twice + the expired one + the live
// one); the fix returns TWO (deduped live + the other live).
func TestParseLeaseCSV_ExpiredAndDuplicate(t *testing.T) {
	now := time.Unix(1707900000, 0) // 2024-02-14 06:40:00 UTC
	past := now.Unix() - 3600       // expired an hour ago
	future := now.Unix() + 3600     // valid for another hour
	dir := t.TempDir()
	path := filepath.Join(dir, "kea-leases4.csv")
	// Append order is chronological: the second 10.0.1.50 row (client1b,
	// newer expire) supersedes the first. 10.0.1.99 is expired. 10.0.1.60
	// is a normal single live lease.
	csv := fmt.Sprintf(`address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state,user_context,pool_id
10.0.1.50,aa:bb:cc:dd:ee:01,,86400,%d,1,0,0,client1a,0,,0
10.0.1.99,aa:bb:cc:dd:ee:99,,86400,%d,1,0,0,stale,0,,0
10.0.1.50,aa:bb:cc:dd:ee:01,,86400,%d,1,0,0,client1b,0,,0
10.0.1.60,aa:bb:cc:dd:ee:60,,86400,%d,1,0,0,client2,0,,0
`, future, past, future, future)
	if err := os.WriteFile(path, []byte(csv), 0644); err != nil {
		t.Fatal(err)
	}

	leases, err := parseLeaseCSV(path, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(leases) != 2 {
		t.Fatalf("got %d leases, want 2 (deduped + non-expired); pre-#2085 returned 4", len(leases))
	}
	byAddr := indexLeasesByAddr(leases)
	dup, ok := byAddr["10.0.1.50"]
	if !ok {
		t.Fatalf("deduped address 10.0.1.50 missing; got %+v", leases)
	}
	if dup.Hostname != "client1b" {
		t.Errorf("dedup must keep the NEWEST row: hostname got %q, want client1b", dup.Hostname)
	}
	if _, ok := byAddr["10.0.1.99"]; ok {
		t.Errorf("expired lease 10.0.1.99 must be dropped; got %+v", leases)
	}
	if _, ok := byAddr["10.0.1.60"]; !ok {
		t.Errorf("live lease 10.0.1.60 must be present; got %+v", leases)
	}
	// Order is stable (first-appearance): 10.0.1.50 before 10.0.1.60.
	if leases[0].Address != "10.0.1.50" || leases[1].Address != "10.0.1.60" {
		t.Errorf("display order not stable first-appearance: %q, %q", leases[0].Address, leases[1].Address)
	}
}

// TestParseLeaseCSV_StateFiltered pins the second half of #2085: a
// released (state=2 expired-reclaimed) or declined (state=1) Kea lease
// is written with a non-default state but often a FUTURE expire epoch,
// so an expire-only filter would still show it as live. The display
// must drop non-default-state rows too, BEFORE the expire check. A
// later active (state=0) append must still reclaim the address.
// Non-tautological against an expire-only half-fix (which would emit the
// declined and reclaimed rows because their expire is in the future).
func TestParseLeaseCSV_StateFiltered(t *testing.T) {
	now := time.Unix(1707900000, 0)
	future := now.Unix() + 3600
	dir := t.TempDir()
	path := filepath.Join(dir, "kea-leases4.csv")
	// 10.0.1.10 declined (state=1, future expire) — must be hidden.
	// 10.0.1.11 expired-reclaimed (state=2, future expire) — must be hidden.
	// 10.0.1.12 reclaimed (state=2) then re-allocated live (state=0) —
	//   the later live append must reclaim the address.
	// 10.0.1.13 plain active — present.
	csv := fmt.Sprintf(`address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state,user_context,pool_id
10.0.1.10,aa:bb:cc:dd:ee:10,,86400,%d,1,0,0,declined,1,,0
10.0.1.11,aa:bb:cc:dd:ee:11,,86400,%d,1,0,0,reclaimed,2,,0
10.0.1.12,aa:bb:cc:dd:ee:12,,86400,%d,1,0,0,old,2,,0
10.0.1.12,aa:bb:cc:dd:ee:12,,86400,%d,1,0,0,reallocated,0,,0
10.0.1.13,aa:bb:cc:dd:ee:13,,86400,%d,1,0,0,active,0,,0
`, future, future, future, future, future)
	if err := os.WriteFile(path, []byte(csv), 0644); err != nil {
		t.Fatal(err)
	}

	leases, err := parseLeaseCSV(path, now)
	if err != nil {
		t.Fatal(err)
	}
	byAddr := indexLeasesByAddr(leases)
	if _, ok := byAddr["10.0.1.10"]; ok {
		t.Errorf("declined lease (state=1, future expire) must be dropped; got %+v", leases)
	}
	if _, ok := byAddr["10.0.1.11"]; ok {
		t.Errorf("expired-reclaimed lease (state=2, future expire) must be dropped; got %+v", leases)
	}
	reclaimed, ok := byAddr["10.0.1.12"]
	if !ok {
		t.Errorf("re-allocated address 10.0.1.12 must be shown live; got %+v", leases)
	} else if reclaimed.Hostname != "reallocated" {
		t.Errorf("reclaim must keep the live row: hostname got %q, want reallocated", reclaimed.Hostname)
	}
	if _, ok := byAddr["10.0.1.13"]; !ok {
		t.Errorf("plain active lease 10.0.1.13 must be present; got %+v", leases)
	}
	if len(leases) != 2 {
		t.Fatalf("got %d leases, want 2 (reallocated + active); pre-fix/expire-only returns more", len(leases))
	}
}

// TestParseLeaseCSV_Lenient pins the display path's leniency: absent or
// unparseable state/expire columns must NOT hide a lease, and a header
// missing the state column entirely must degrade to today's behaviour
// (all addressed rows shown), never abort the show. This is what keeps
// the fix safe for older Kea / exotic headers.
func TestParseLeaseCSV_Lenient(t *testing.T) {
	now := time.Unix(1707900000, 0)
	dir := t.TempDir()

	// Garbage state + blank/garbage expire ⇒ rows kept.
	path := filepath.Join(dir, "garbage.csv")
	csv := `address,hwaddr,expire,state,hostname
10.0.2.10,aa:bb:cc:dd:ee:10,notanumber,xyz,a
10.0.2.11,aa:bb:cc:dd:ee:11,,,b
`
	if err := os.WriteFile(path, []byte(csv), 0644); err != nil {
		t.Fatal(err)
	}
	leases, err := parseLeaseCSV(path, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(leases) != 2 {
		t.Errorf("lenient: garbage/blank state+expire must keep rows; got %d, want 2 (%+v)", len(leases), leases)
	}

	// Header with NO state and NO expire column ⇒ all addressed rows shown.
	path2 := filepath.Join(dir, "nostate.csv")
	csv2 := `address,hwaddr,hostname
10.0.3.10,aa:bb:cc:dd:ee:10,a
10.0.3.11,aa:bb:cc:dd:ee:11,b
`
	if err := os.WriteFile(path2, []byte(csv2), 0644); err != nil {
		t.Fatal(err)
	}
	leases2, err := parseLeaseCSV(path2, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(leases2) != 2 {
		t.Errorf("lenient: missing state/expire columns must keep rows; got %d, want 2 (%+v)", len(leases2), leases2)
	}
}

// TestParseLeaseCSV_SkipsMalformedLine pins #2154: the READ layer must be
// row-robust, not all-or-nothing. Kea appends to its memfile concurrently
// with our read, so the file can end on a torn line (a partially-written
// row, e.g. an unterminated quoted field). The pre-#2154 ReadAll() aborted
// the WHOLE parse on the first such record and returned (nil, err), so
// `show dhcp server leases` blanked even though most rows were valid —
// worst exactly when the network is busy. The fix reads record-by-record,
// logs+skips a malformed row, and keeps every valid lease around it.
//
// Non-tautological: against the ReadAll() code this fixture returns
// (nil, err) and the valid leases are LOST. It also exercises the #2085
// dedup/expire/state body on the surviving rows to prove that logic is
// preserved on top of the robust read.
func TestParseLeaseCSV_SkipsMalformedLine(t *testing.T) {
	now := time.Unix(1707900000, 0)
	future := now.Unix() + 3600
	past := now.Unix() - 3600
	dir := t.TempDir()

	// A self-contained malformed row in the MIDDLE — a bare quote in a
	// non-quoted field — produces a *csv.ParseError that csv.Read RECOVERS
	// from on the next call (verified: the following record reads cleanly),
	// so the valid rows AFTER it survive too. (An UNTERMINATED quote is a
	// different shape: it opens a field that spans to EOF and is covered by
	// the torn-tail case below — that matches ReadAll and is unavoidable.)
	// Surrounding rows include a #2085 duplicate (newest wins), an expired
	// row (dropped), and a declined row (state=1, dropped) so the read fix
	// is proven to compose with #2085's per-record semantics.
	path := filepath.Join(dir, "kea-leases4.csv")
	csvData := fmt.Sprintf(`address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state,user_context,pool_id
10.0.4.10,aa:bb:cc:dd:ee:10,,86400,%d,1,0,0,first,0,,0
10.0.4.20,aa:bb:cc:dd:ee:20,,86400,%d,1,0,0,ba"req,0,,0
10.0.4.30,aa:bb:cc:dd:ee:30,,86400,%d,1,0,0,dupA,0,,0
10.0.4.30,aa:bb:cc:dd:ee:30,,86400,%d,1,0,0,dupB,0,,0
10.0.4.40,aa:bb:cc:dd:ee:40,,86400,%d,1,0,0,expired,0,,0
10.0.4.50,aa:bb:cc:dd:ee:50,,86400,%d,1,0,0,declined,1,,0
10.0.4.60,aa:bb:cc:dd:ee:60,,86400,%d,1,0,0,last,0,,0
`, future, future, future, future, past, future, future)
	if err := os.WriteFile(path, []byte(csvData), 0644); err != nil {
		t.Fatal(err)
	}

	leases, err := parseLeaseCSV(path, now)
	if err != nil {
		t.Fatalf("malformed line must not abort the whole read; got err %v", err)
	}
	byAddr := indexLeasesByAddr(leases)

	// The valid rows surrounding the malformed line survive. The bad row
	// (10.0.4.20) is skipped; what matters is that the read did not abort
	// and every row it could parse is returned.
	if _, ok := byAddr["10.0.4.10"]; !ok {
		t.Errorf("valid row before malformed line lost; got %+v", leases)
	}
	if _, ok := byAddr["10.0.4.20"]; ok {
		t.Errorf("malformed row 10.0.4.20 must be skipped; got %+v", leases)
	}
	if _, ok := byAddr["10.0.4.60"]; !ok {
		t.Errorf("valid row after malformed line lost; got %+v", leases)
	}
	// #2085 logic preserved on the surviving rows:
	if dup, ok := byAddr["10.0.4.30"]; !ok {
		t.Errorf("deduped row 10.0.4.30 missing; got %+v", leases)
	} else if dup.Hostname != "dupB" {
		t.Errorf("dedup must keep newest row: hostname got %q, want dupB", dup.Hostname)
	}
	if _, ok := byAddr["10.0.4.40"]; ok {
		t.Errorf("expired row 10.0.4.40 must be dropped; got %+v", leases)
	}
	if _, ok := byAddr["10.0.4.50"]; ok {
		t.Errorf("declined row 10.0.4.50 (state=1) must be dropped; got %+v", leases)
	}

	// Canonical Kea case: the torn line is the VERY LAST line (an append in
	// progress). The leading valid rows must still render. Against ReadAll
	// this returns (nil, err) and shows nothing.
	path2 := filepath.Join(dir, "torn-tail.csv")
	csv2 := fmt.Sprintf(`address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state,user_context,pool_id
10.0.5.10,aa:bb:cc:dd:ee:10,,86400,%d,1,0,0,good1,0,,0
10.0.5.11,aa:bb:cc:dd:ee:11,,86400,%d,1,0,0,good2,0,,0
10.0.5.12,aa:bb:cc:dd:ee:12,,86400,%d,1,0,0,"torn-mid-append`, future, future, future)
	if err := os.WriteFile(path2, []byte(csv2), 0644); err != nil {
		t.Fatal(err)
	}
	leases2, err := parseLeaseCSV(path2, now)
	if err != nil {
		t.Fatalf("torn last line must not abort the read; got err %v", err)
	}
	by2 := indexLeasesByAddr(leases2)
	if _, ok := by2["10.0.5.10"]; !ok {
		t.Errorf("leading valid row lost to torn tail; got %+v", leases2)
	}
	if _, ok := by2["10.0.5.11"]; !ok {
		t.Errorf("leading valid row lost to torn tail; got %+v", leases2)
	}

	// A short concurrent line (fewer fields) must also be tolerated, not
	// fatal. With FieldsPerRecord = -1 it is not even an error; the field()
	// helper bounds-checks the column index.
	path3 := filepath.Join(dir, "short.csv")
	csv3 := fmt.Sprintf(`address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state,user_context,pool_id
10.0.6.10,aa:bb:cc:dd:ee:10,,86400,%d,1,0,0,full,0,,0
10.0.6.11,aa:bb:cc:dd:ee:11
10.0.6.12,aa:bb:cc:dd:ee:12,,86400,%d,1,0,0,after,0,,0
`, future, future)
	if err := os.WriteFile(path3, []byte(csv3), 0644); err != nil {
		t.Fatal(err)
	}
	leases3, err := parseLeaseCSV(path3, now)
	if err != nil {
		t.Fatalf("short line must not abort the read; got err %v", err)
	}
	by3 := indexLeasesByAddr(leases3)
	if _, ok := by3["10.0.6.10"]; !ok {
		t.Errorf("row before short line lost; got %+v", leases3)
	}
	if _, ok := by3["10.0.6.12"]; !ok {
		t.Errorf("row after short line lost; got %+v", leases3)
	}
}

// TestApplyStopsDeactivatingUnit pins the Codex finding on PR #1835:
// a unit reported "deactivating" can have a queued start behind it, so
// the reconcile must treat it as active-for-stop (unitIsActive returns
// true for it; here the seam simulates that directly).
func TestApplyStopsDeactivatingUnit(t *testing.T) {
	dir := t.TempDir()
	var stopped []string
	m := NewManagerForTesting(
		dir+"/kea4.conf", dir+"/kea6.conf",
		func(args ...string) error {
			if len(args) > 0 && args[0] == "stop" {
				stopped = append(stopped, args[len(args)-1])
			}
			return nil
		},
		func(unit string) bool { return true },
	)
	if err := m.Apply(nil); err != nil {
		t.Fatalf("Apply(nil): %v", err)
	}
	if len(stopped) != 2 {
		t.Fatalf("stopped = %v, want both kea units", stopped)
	}
}

// TestGenerateKea6RejectsMultiInterfaceGroup pins the second Codex
// finding on PR #1835: Kea v6 subnet selection cannot fall back to
// address matching (clients use link-local sources), so a
// multi-interface v6 group must be rejected loudly rather than
// silently losing its subnet6 interface selector.
func TestGenerateKea6RejectsMultiInterfaceGroup(t *testing.T) {
	dir := t.TempDir()
	m := NewManagerForTesting(
		dir+"/kea4.conf", dir+"/kea6.conf",
		func(...string) error { return nil },
		func(string) bool { return false },
	)
	cfg := &config.DHCPServerConfig{
		DHCPv6LocalServer: &config.DHCPLocalServerConfig{},
	}
	cfg.DHCPv6LocalServer.Groups = map[string]*config.DHCPServerGroup{"lan": {
		Name:       "lan",
		Interfaces: []string{"ge-0/0/1", "ge-0/0/2"},
		Pools: []*config.DHCPPool{{
			Subnet: "2001:db8::/64", RangeLow: "2001:db8::100", RangeHigh: "2001:db8::200",
		}},
	}}
	err := m.Apply(cfg)
	if err == nil || !strings.Contains(err.Error(), "single interface selector") {
		t.Fatalf("want multi-interface v6 rejection, got %v", err)
	}
}

// TestWarnAmbiguousSubnetSelection pins #1835 F1: two groups whose
// pools share/overlap a subnet while at least one involved group emits
// no per-subnet interface selector (multi-interface group) must fire a
// warning at generate time — Kea's subnet selection is ambiguous. It
// must stay a warning, not an error (pre-existing accepted configs).
func TestWarnAmbiguousSubnetSelection(t *testing.T) {
	mkCfg := func(subnetA, subnetB string, ifacesA, ifacesB []string) *config.DHCPServerConfig {
		return &config.DHCPServerConfig{
			DHCPLocalServer: &config.DHCPLocalServerConfig{
				Groups: map[string]*config.DHCPServerGroup{
					"ga": {Name: "ga", Interfaces: ifacesA,
						Pools: []*config.DHCPPool{{Subnet: subnetA,
							RangeLow: "10.0.1.100", RangeHigh: "10.0.1.200"}}},
					"gb": {Name: "gb", Interfaces: ifacesB,
						Pools: []*config.DHCPPool{{Subnet: subnetB,
							RangeLow: "10.0.1.100", RangeHigh: "10.0.1.200"}}},
				},
			},
		}
	}

	run := func(t *testing.T, cfg *config.DHCPServerConfig) []string {
		t.Helper()
		m, _ := testManager(t, map[string]bool{}, "")
		var warned []string
		m.SetWarnForTesting(func(msg string, args ...any) {
			s := msg
			for _, a := range args {
				s += fmt.Sprintf(" %v", a)
			}
			warned = append(warned, s)
		})
		if err := m.Apply(cfg); err != nil {
			t.Fatalf("Apply must not error on ambiguous subnets: %v", err)
		}
		return warned
	}

	t.Run("same subnet, one multi-interface group warns", func(t *testing.T) {
		warned := run(t, mkCfg("10.0.1.0/24", "10.0.1.0/24",
			[]string{"ge-0-0-0", "ge-0-0-1"}, []string{"ge-0-0-2"}))
		// #9785: an identical prefix also draws the renderer's skip warning,
		// because Kea refuses a second subnet with the same prefix. This row
		// is about the ambiguity warning, so it counts those and pins the skip
		// warning separately.
		ambiguous, skipped := splitWarnings9785(warned)
		if len(ambiguous) != 1 || len(skipped) != 1 || len(warned) != 2 {
			t.Fatalf("want 1 ambiguity and 1 #9785 skip warning, got %d: %v", len(warned), warned)
		}
		if !strings.Contains(ambiguous[0], "ga") || !strings.Contains(ambiguous[0], "gb") {
			t.Errorf("warning should name both groups: %q", ambiguous[0])
		}
	})

	t.Run("overlapping subnets warn too", func(t *testing.T) {
		warned := run(t, mkCfg("10.0.0.0/16", "10.0.1.0/24",
			[]string{"ge-0-0-0", "ge-0-0-1"}, []string{"ge-0-0-2"}))
		if len(warned) != 1 {
			t.Fatalf("want 1 warning for overlapping prefixes, got %d: %v", len(warned), warned)
		}
	})

	t.Run("disjoint subnets do not warn", func(t *testing.T) {
		warned := run(t, mkCfg("10.0.1.0/24", "10.0.2.0/24",
			[]string{"ge-0-0-0", "ge-0-0-1"}, []string{"ge-0-0-2"}))
		if len(warned) != 0 {
			t.Errorf("unexpected warning: %v", warned)
		}
	})

	t.Run("both groups with selectors do not warn", func(t *testing.T) {
		warned := run(t, mkCfg("10.0.1.0/24", "10.0.1.0/24",
			[]string{"ge-0-0-0"}, []string{"ge-0-0-2"}))
		// #9785: selectors do not make an identical prefix loadable. Kea
		// refused the second subnet with both groups on one interface, and its
		// message names only the prefix, so the renderer skips it and says so.
		// There is still no ambiguity warning.
		ambiguous, skipped := splitWarnings9785(warned)
		if len(ambiguous) != 0 || len(skipped) != 1 || len(warned) != 1 {
			t.Errorf("want no ambiguity warning and 1 #9785 skip warning when both subnets carry selectors, got %v", warned)
		}
	})
}

// asyncTestManager builds a Manager whose fake systemctl reports which
// v4 config was on disk when each restart ran (the worker writes the
// config before restarting, so this observes exactly which desired
// state the worker applied), and blocks until released.
func asyncTestManager(t *testing.T) (m *Manager, applied chan string, release chan struct{}) {
	t.Helper()
	dir := t.TempDir()
	applied = make(chan string, 16)
	release = make(chan struct{}, 16)
	m = NewManagerForTesting(
		filepath.Join(dir, "kea-dhcp4.conf"),
		filepath.Join(dir, "kea-dhcp6.conf"),
		nil, // set below; needs m for confPath4
		func(unit string) bool { return false },
	)
	m.runSystemctl = func(args ...string) error {
		data, _ := os.ReadFile(m.confPath4)
		applied <- string(data)
		<-release
		return nil
	}
	return m, applied, release
}

// TestApplyAsyncNeverBlocks pins #1835 F2: the VRRP event loop must
// never wait behind a (15s-bounded) systemctl — ApplyAsync returns
// immediately even while the worker is stuck inside a shell-out.
func TestApplyAsyncNeverBlocks(t *testing.T) {
	m, applied, release := asyncTestManager(t)
	defer close(release)

	m.ApplyAsync(v4Config("ge-0-0-0"), "test")
	<-applied // worker is now blocked inside the fake systemctl

	done := make(chan struct{})
	go func() {
		m.ApplyAsync(v4Config("ge-0-0-1"), "test")
		m.ApplyAsync(nil, "test")
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("ApplyAsync blocked while the worker held systemctl")
	}
}

// TestApplyAsyncLatestWins pins the mailbox coalescing contract: with
// the worker busy, enqueueing B then C must apply only C — B is
// discarded, and the LAST desired state is the last one applied.
// Correct because Apply is an idempotent reconcile to desired state.
func TestApplyAsyncLatestWins(t *testing.T) {
	m, applied, release := asyncTestManager(t)

	m.ApplyAsync(v4Config("iface-A"), "a")
	gotA := <-applied // worker is executing A and blocked
	if !strings.Contains(gotA, "iface-A") {
		t.Fatalf("first apply should be A, got %q", gotA)
	}

	// Worker still blocked: B fills the slot, C overwrites B.
	m.ApplyAsync(v4Config("iface-B"), "b")
	m.ApplyAsync(v4Config("iface-C"), "c")

	release <- struct{}{} // finish A; worker picks up the slot
	gotNext := <-applied
	if !strings.Contains(gotNext, "iface-C") {
		t.Fatalf("expected latest state C applied next, got %q", gotNext)
	}
	release <- struct{}{} // finish C

	// B must have been coalesced away — no further applies.
	select {
	case extra := <-applied:
		t.Fatalf("unexpected extra apply (B not coalesced): %q", extra)
	case <-time.After(200 * time.Millisecond):
	}
}

// TestApplyAsyncSingleWorker pins the singleton contract: repeated
// ApplyAsync bursts start exactly one worker goroutine.
func TestApplyAsyncSingleWorker(t *testing.T) {
	m, _ := testManager(t, map[string]bool{}, "")
	for burst := 0; burst < 2; burst++ {
		for i := 0; i < 25; i++ {
			m.ApplyAsync(nil, "burst")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if n := m.asyncWorkerStarts.Load(); n != 1 {
		t.Fatalf("worker goroutine starts = %d, want 1", n)
	}
}

// TestApplyClusterCommit pins #1835 F3: a cluster-mode commit must
// always regenerate the Kea config and restart ONLY units that are
// currently active (active == this node is serving as VRRP MASTER);
// inactive units get the fresh config on disk for the next MASTER
// transition, with no restart.
func TestApplyClusterCommit(t *testing.T) {
	t.Run("active unit restarted with rewritten config", func(t *testing.T) {
		m, calls := testManager(t, map[string]bool{kea4Svc: true}, "")
		if err := m.ApplyClusterCommit(v4Config("ge-0-0-0")); err != nil {
			t.Fatalf("ApplyClusterCommit: %v", err)
		}
		if _, err := os.Stat(m.confPath4); err != nil {
			t.Errorf("config not regenerated: %v", err)
		}
		if !calledWith(*calls, "restart "+kea4Svc) {
			t.Errorf("active unit must restart on cluster commit, got %v", *calls)
		}
	})

	t.Run("inactive unit gets config only, no restart", func(t *testing.T) {
		m, calls := testManager(t, map[string]bool{}, "")
		if err := m.ApplyClusterCommit(v4Config("ge-0-0-0")); err != nil {
			t.Fatalf("ApplyClusterCommit: %v", err)
		}
		if _, err := os.Stat(m.confPath4); err != nil {
			t.Errorf("config not regenerated: %v", err)
		}
		if len(*calls) != 0 {
			t.Errorf("inactive unit must not restart on cluster commit, got %v", *calls)
		}
	})

	t.Run("restart failure on active unit fails the commit", func(t *testing.T) {
		m, _ := testManager(t, map[string]bool{kea4Svc: true}, "restart "+kea4Svc)
		err := m.ApplyClusterCommit(v4Config("ge-0-0-0"))
		if err == nil || !strings.Contains(err.Error(), kea4Svc) {
			t.Fatalf("want fail-closed restart error naming the unit, got %v", err)
		}
	})

	t.Run("nil config clears active units", func(t *testing.T) {
		m, calls := testManager(t, map[string]bool{kea4Svc: true}, "")
		if err := m.ApplyClusterCommit(nil); err != nil {
			t.Fatalf("ApplyClusterCommit(nil): %v", err)
		}
		if !calledWith(*calls, "stop "+kea4Svc) {
			t.Errorf("active unit must stop when config removed, got %v", *calls)
		}
	})
}

// waitForCondition polls cond until true or fails the test. Used for
// observing the async worker's gen-checked outcomes (skip counters,
// lastAppliedGen) without timing assumptions on the assertion itself.
func waitForCondition(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// TestSyncSupersedesQueuedAsync pins Codex hole 2 on PR #1835: a
// queued async request must NOT be applied over a newer synchronous
// ApplyClusterCommit. Choreographed deterministically via gens: the
// async producer allocates its gen at call entry, then "stalls" before
// reaching the mailbox (the worst-case interleaving), the sync commit
// lands with a higher gen, and the stale async — delivered through the
// real mailbox + worker — must be skipped by the shared apply body.
func TestSyncSupersedesQueuedAsync(t *testing.T) {
	m, calls := testManager(t, map[string]bool{kea4Svc: true}, "")

	// Async producer at call entry: gen allocated, enqueue delayed.
	oldGen := m.applyGen.Add(1)
	oldReq := &asyncApplyReq{gen: oldGen, cfg: v4Config("iface-OLD"), reason: "stale-vrrp"}

	// Sync cluster commit with a newer gen applies (unit active →
	// regenerates config and restarts).
	if err := m.ApplyClusterCommit(v4Config("iface-NEW")); err != nil {
		t.Fatalf("ApplyClusterCommit: %v", err)
	}

	// The stalled producer finally lands its stale request.
	m.enqueueAsync(oldReq)
	waitForCondition(t, "stale async skip", func() bool {
		return m.staleApplySkips.Load() == 1
	})

	data, err := os.ReadFile(m.confPath4)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "iface-NEW") || strings.Contains(string(data), "iface-OLD") {
		t.Errorf("stale async overwrote the sync commit's config: %s", data)
	}
	restarts := 0
	for _, c := range *calls {
		if c == "restart "+kea4Svc {
			restarts++
		}
	}
	if restarts != 1 {
		t.Errorf("apply count: want exactly the sync commit's restart, got %d (%v)", restarts, *calls)
	}
}

// TestAsyncSupersedesOlderSync pins the other direction of the gen
// ordering: an async request allocated AFTER a sync apply lands over
// it (final state = async's), while a sync applier holding a stale gen
// skips and returns nil — being superseded is not a failure.
func TestAsyncSupersedesOlderSync(t *testing.T) {
	m, calls := testManager(t, map[string]bool{}, "")

	if err := m.Apply(v4Config("iface-SYNC")); err != nil { // gen 1
		t.Fatalf("Apply: %v", err)
	}
	m.ApplyAsync(v4Config("iface-ASYNC"), "newer") // gen 2 > 1 → applies
	waitForCondition(t, "async apply over older sync", func() bool {
		m.mu.Lock()
		defer m.mu.Unlock()
		return m.lastAppliedGen == 2
	})
	data, _ := os.ReadFile(m.confPath4)
	if !strings.Contains(string(data), "iface-ASYNC") {
		t.Errorf("newer async must win, config: %s", data)
	}
	if got := len(*calls); got != 2 {
		t.Errorf("want 2 restarts (sync + newer async), got %d: %v", got, *calls)
	}

	// Inverse stale case: a sync applier whose gen lost the race to a
	// newer applier must skip, returning nil with no systemctl calls.
	if err := m.apply(1, v4Config("iface-STALE"), true); err != nil {
		t.Fatalf("superseded sync apply must return nil, got %v", err)
	}
	if m.staleApplySkips.Load() != 1 {
		t.Errorf("stale sync apply not skipped (skips=%d)", m.staleApplySkips.Load())
	}
	data, _ = os.ReadFile(m.confPath4)
	if strings.Contains(string(data), "iface-STALE") {
		t.Errorf("stale sync apply regenerated config: %s", data)
	}
	if got := len(*calls); got != 2 {
		t.Errorf("stale sync apply issued systemctl calls: %v", *calls)
	}
}

// TestApplyAsyncConcurrentProducersHighestGenWins pins Codex hole 1 on
// PR #1835 (ABA in the old send-after-drain loop): with the worker
// blocked, 10 concurrent producers race the mailbox; the pending slot
// must end up holding exactly the highest allocated gen (asserted via
// gens, not timing), and after release exactly that state is applied.
func TestApplyAsyncConcurrentProducersHighestGenWins(t *testing.T) {
	m, applied, release := asyncTestManager(t)

	m.ApplyAsync(v4Config("iface-prime"), "prime") // gen 1
	<-applied                                      // worker blocked in prime's restart

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			m.ApplyAsync(v4Config(fmt.Sprintf("iface-%d", i)), "racer")
		}(i)
	}
	wg.Wait()

	// All producers returned: the slot must hold the highest gen.
	m.asyncMu.Lock()
	pend := m.pendingAsync
	m.asyncMu.Unlock()
	if pend == nil {
		t.Fatal("no pending request after concurrent producers")
	}
	if want := m.applyGen.Load(); pend.gen != want {
		t.Fatalf("pending gen = %d, want highest allocated %d (ABA: an older producer overwrote a newer request)", pend.gen, want)
	}
	winner := pend.cfg.DHCPLocalServer.Groups["g0"].Interfaces[0]

	release <- struct{}{} // finish prime
	got := <-applied      // exactly one coalesced apply
	if !strings.Contains(got, winner) {
		t.Fatalf("applied %q, want highest-gen state %q", got, winner)
	}
	release <- struct{}{}

	select {
	case extra := <-applied:
		t.Fatalf("unexpected extra apply: %q", extra)
	case <-time.After(200 * time.Millisecond):
	}

	m.mu.Lock()
	last := m.lastAppliedGen
	m.mu.Unlock()
	if last != pend.gen {
		t.Fatalf("lastAppliedGen = %d, want %d", last, pend.gen)
	}
}

// multiGroupV4Config builds a 3-group / multi-pool DHCPv4 config whose
// stable (sorted) subnet_id assignment is known. Group names are chosen so
// lexical order (alpha, mid, zeta) differs from any natural map-insert order.
func multiGroupV4Config() *config.DHCPServerConfig {
	return &config.DHCPServerConfig{
		DHCPLocalServer: &config.DHCPLocalServerConfig{
			Groups: map[string]*config.DHCPServerGroup{
				"zeta": {Name: "zeta", Interfaces: []string{"ge-0-0-2"}, Pools: []*config.DHCPPool{
					{Name: "z0", Subnet: "10.0.3.0/24", RangeLow: "10.0.3.10", RangeHigh: "10.0.3.20"},
				}},
				"alpha": {Name: "alpha", Interfaces: []string{"ge-0-0-0"}, Pools: []*config.DHCPPool{
					// Declared out of subnet order to exercise stablePools.
					{Name: "a1", Subnet: "10.0.1.128/25", RangeLow: "10.0.1.130", RangeHigh: "10.0.1.140"},
					{Name: "a0", Subnet: "10.0.1.0/25", RangeLow: "10.0.1.10", RangeHigh: "10.0.1.20"},
				}},
				"mid": {Name: "mid", Interfaces: []string{"ge-0-0-1"}, Pools: []*config.DHCPPool{
					{Name: "m0", Subnet: "10.0.2.0/24", RangeLow: "10.0.2.10", RangeHigh: "10.0.2.20"},
				}},
			},
		},
	}
}

func multiGroupV6Config() *config.DHCPServerConfig {
	return &config.DHCPServerConfig{
		DHCPv6LocalServer: &config.DHCPLocalServerConfig{
			Groups: map[string]*config.DHCPServerGroup{
				"zeta": {Name: "zeta", Interfaces: []string{"ge-0-0-2"}, Pools: []*config.DHCPPool{
					{Name: "z0", Subnet: "2001:db8:3::/64", RangeLow: "2001:db8:3::10", RangeHigh: "2001:db8:3::20"},
				}},
				"alpha": {Name: "alpha", Interfaces: []string{"ge-0-0-0"}, Pools: []*config.DHCPPool{
					{Name: "a1", Subnet: "2001:db8:1:8000::/65", RangeLow: "2001:db8:1:8000::10", RangeHigh: "2001:db8:1:8000::20"},
					{Name: "a0", Subnet: "2001:db8:1::/65", RangeLow: "2001:db8:1::10", RangeHigh: "2001:db8:1::20"},
				}},
				"mid": {Name: "mid", Interfaces: []string{"ge-0-0-1"}, Pools: []*config.DHCPPool{
					{Name: "m0", Subnet: "2001:db8:2::/64", RangeLow: "2001:db8:2::10", RangeHigh: "2001:db8:2::20"},
				}},
			},
		},
	}
}

// subnetIDMap reads the rendered Kea conf and returns subnet -> id.
func subnetIDMap(t *testing.T, path, family string) map[string]int {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	type sub struct {
		ID     int    `json:"id"`
		Subnet string `json:"subnet"`
	}
	var out map[string]json.RawMessage
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	var inner struct {
		Subnet4 []sub `json:"subnet4"`
		Subnet6 []sub `json:"subnet6"`
	}
	if err := json.Unmarshal(out["Dhcp"+family], &inner); err != nil {
		t.Fatal(err)
	}
	subs := inner.Subnet4
	if family == "6" {
		subs = inner.Subnet6
	}
	res := make(map[string]int, len(subs))
	for _, s := range subs {
		if prev, dup := res[s.Subnet]; dup {
			t.Fatalf("duplicate subnet %s (ids %d and %d)", s.Subnet, prev, s.ID)
		}
		res[s.Subnet] = s.ID
	}
	return res
}

// TestKeaSubnetIDStableAcrossRegenerations is the #2668 regression guard.
// Kea binds memfile leases to subnets by the subnet_id column, so the SAME
// subnet MUST receive the SAME subnet_id on every config regeneration. The
// assignment used to range the randomized Groups map, so reverting to that
// makes this test flaky (a wrong mapping eventually appears across the N
// regenerations). Since #5041 the id is a stable hash of the subnet CIDR
// rather than a positional counter, so we no longer pin golden positional
// values — we capture the first regeneration's mapping and assert every
// subsequent regeneration reproduces it exactly.
func TestKeaSubnetIDStableAcrossRegenerations(t *testing.T) {
	var wantV4, wantV6 map[string]int

	const regens = 50 // enough to surface map-order randomization on revert
	for i := 0; i < regens; i++ {
		mv4, _ := testManager(t, map[string]bool{}, "")
		if err := mv4.generateKea4Config(multiGroupV4Config()); err != nil {
			t.Fatalf("generateKea4Config[%d]: %v", i, err)
		}
		got := subnetIDMap(t, mv4.confPath4, "4")
		if i == 0 {
			wantV4 = got
		} else if !mapsEqualSI(got, wantV4) {
			t.Fatalf("v4 regen %d: subnet_id mapping %v != first-regen %v", i, got, wantV4)
		}

		mv6, _ := testManager(t, map[string]bool{}, "")
		if err := mv6.generateKea6Config(multiGroupV6Config()); err != nil {
			t.Fatalf("generateKea6Config[%d]: %v", i, err)
		}
		got6 := subnetIDMap(t, mv6.confPath6, "6")
		if i == 0 {
			wantV6 = got6
		} else if !mapsEqualSI(got6, wantV6) {
			t.Fatalf("v6 regen %d: subnet_id mapping %v != first-regen %v", i, got6, wantV6)
		}
	}
}

// TestKeaSubnetIDStableAcrossFilteredSubsets is the #5041 regression guard.
// In an HA cluster each node renders only its MASTER-filtered subset of
// subnets, so the SAME logical subnet lands at a DIFFERENT position on the two
// nodes. The old positional counter therefore gave that subnet a DIFFERENT
// subnet_id per node, and a synced lease (which carries subnet_id verbatim)
// misbound on the receiver. The stable-hash id must be IDENTICAL for a subnet
// whether it is rendered in the full config or in a filtered subset where its
// position shifts.
//
// Fail-on-revert: reverting stableSubnetID to the positional counter makes the
// filtered subset renumber the shared subnets (position 3/4 in full become
// 1/2 in the {mid,zeta} subset), so this test fails.
func TestKeaSubnetIDStableAcrossFilteredSubsets(t *testing.T) {
	check := func(t *testing.T, family string,
		gen func(m *Manager, cfg *config.DHCPServerConfig) error,
		full *config.DHCPServerConfig,
		subsetGroups map[string]*config.DHCPServerGroup,
		sharedSubnets []string,
	) {
		t.Helper()
		mFull, _ := testManager(t, map[string]bool{}, "")
		if err := gen(mFull, full); err != nil {
			t.Fatalf("generate full: %v", err)
		}
		confPath := mFull.confPath4
		if family == "6" {
			confPath = mFull.confPath6
		}
		idsFull := subnetIDMap(t, confPath, family)

		// Render only a subset of the groups (as a node mastering a subset of
		// RGs would), which shifts the surviving subnets' positions.
		subset := &config.DHCPServerConfig{}
		if family == "6" {
			subset.DHCPv6LocalServer = &config.DHCPLocalServerConfig{Groups: subsetGroups}
		} else {
			subset.DHCPLocalServer = &config.DHCPLocalServerConfig{Groups: subsetGroups}
		}
		mSub, _ := testManager(t, map[string]bool{}, "")
		if err := gen(mSub, subset); err != nil {
			t.Fatalf("generate subset: %v", err)
		}
		confPathSub := mSub.confPath4
		if family == "6" {
			confPathSub = mSub.confPath6
		}
		idsSub := subnetIDMap(t, confPathSub, family)

		for _, sn := range sharedSubnets {
			if idsFull[sn] == 0 || idsSub[sn] == 0 {
				t.Fatalf("subnet %s missing (full=%d subset=%d)", sn, idsFull[sn], idsSub[sn])
			}
			if idsFull[sn] != idsSub[sn] {
				t.Errorf("subnet %s subnet_id shifted between full (%d) and filtered subset (%d) — synced leases would misbind on the peer",
					sn, idsFull[sn], idsSub[sn])
			}
		}
	}

	v4Full := multiGroupV4Config()
	check(t, "4",
		func(m *Manager, cfg *config.DHCPServerConfig) error { return m.generateKea4Config(cfg) },
		v4Full,
		map[string]*config.DHCPServerGroup{
			"mid":  v4Full.DHCPLocalServer.Groups["mid"],
			"zeta": v4Full.DHCPLocalServer.Groups["zeta"],
		},
		[]string{"10.0.2.0/24", "10.0.3.0/24"},
	)

	v6Full := multiGroupV6Config()
	check(t, "6",
		func(m *Manager, cfg *config.DHCPServerConfig) error { return m.generateKea6Config(cfg) },
		v6Full,
		map[string]*config.DHCPServerGroup{
			"mid":  v6Full.DHCPv6LocalServer.Groups["mid"],
			"zeta": v6Full.DHCPv6LocalServer.Groups["zeta"],
		},
		[]string{"2001:db8:2::/64", "2001:db8:3::/64"},
	)
}

func mapsEqualSI(a, b map[string]int) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// cloneIDSet copies an id-occupancy set so a probe run does not mutate the
// caller's map.
func cloneIDSet(m map[int]bool) map[int]bool {
	out := make(map[int]bool, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// oldLinearProbe reproduces the pre-#5203 collision probe: a +1 linear walk
// through whatever ids the node's rendered set already occupies. Its result is
// therefore a function of the SURROUNDING subnets, which is exactly the
// node-dependence #5203 removes. Kept in the test only, to prove the scenario
// below actually discriminates the old behavior from the new.
func oldLinearProbe(base int, used map[int]bool) int {
	id := base
	for used[id] {
		if id >= keaSubnetIDMax {
			id = 1
		} else {
			id++
		}
	}
	return id
}

// TestKeaSubnetIDCollisionProbeIsNodeIndependent is the #5203 completeness
// guard for #5041. stableSubnetID makes the common (non-colliding) subnet_id a
// pure function of the CIDR, so both HA nodes agree. On a genuine FNV-1a
// COLLISION the loser must PROBE for a free id. The old probe stepped +1
// through the node's render order, so the free id it landed on depended on
// which OTHER subnets were in THAT node's MASTER-filtered subset — under
// asymmetric mastering the two nodes could disagree, reintroducing the #5041
// cross-node lease misbind for the colliding pair. resolveSubnetID now walks a
// CIDR-DERIVED sequence, so a colliding subnet resolves to the SAME id on both
// nodes regardless of the surrounding subnets.
//
// The two `used` maps model the exact asymmetry: both nodes see `cidr`
// colliding at `base` (its stableSubnetID, already claimed by the collision's
// winning partner), but node A additionally masters subnets that happen to sit
// on the LINEAR probe path base+1, base+2 while node B does not. The old +1
// probe walks past those on node A only, so it diverges; the CIDR-derived
// probe ignores set position and converges.
func TestKeaSubnetIDCollisionProbeIsNodeIndependent(t *testing.T) {
	const cidr = "10.55.0.0/24"
	base := stableSubnetID(cidr)

	// The CIDR-derived step must not itself land on base+1/base+2 for this
	// fixture, or node A's extra occupancy would perturb the new probe too and
	// mask the property under test. It never does (the step is a large hash),
	// but assert it so the fixture stays honest if the hash salt changes.
	step := int(subnetProbeStep(cidr))
	if step == 1 || step == 2 {
		t.Fatalf("fixture invalid: CIDR-derived step %d collides with the linear-path occupancy", step)
	}

	nodeA := map[int]bool{base: true, base + 1: true, base + 2: true}
	nodeB := map[int]bool{base: true}

	idA := resolveSubnetID(cidr, cloneIDSet(nodeA))
	idB := resolveSubnetID(cidr, cloneIDSet(nodeB))

	if idA != idB {
		t.Fatalf("resolveSubnetID gave id %d on node A but %d on node B for the same colliding CIDR %s — a synced lease would misbind on the peer (#5203)", idA, idB, cidr)
	}
	if idA == base {
		t.Fatalf("collision left unresolved: id stayed at the occupied base %d", base)
	}
	if idA < 1 || idA > keaSubnetIDMax {
		t.Fatalf("resolved id %d outside the valid Kea range [1,%d]", idA, keaSubnetIDMax)
	}

	// Fail-on-revert: prove the scenario actually distinguishes the fix. The
	// old linear +1 probe DID depend on the node's subset, so it MUST disagree
	// across nodeA/nodeB here. If it agreed, the fixture would not be
	// exercising the divergence resolveSubnetID removes.
	oldA := oldLinearProbe(base, cloneIDSet(nodeA))
	oldB := oldLinearProbe(base, cloneIDSet(nodeB))
	if oldA == oldB {
		t.Fatalf("fixture does not discriminate the fix: the old linear probe agreed (%d) across both node subsets", oldA)
	}
}

// TestResolveSubnetIDNonColliding asserts the common path is unchanged: with no
// occupied ids every subnet resolves to its stableSubnetID direct hit, no id is
// 0 (Kea's SUBNET_ID_UNUSED sentinel) or out of range, and a rendered set never
// contains a duplicate id.
func TestResolveSubnetIDNonColliding(t *testing.T) {
	cidrs := []string{
		"10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24",
		"192.168.0.0/23", "172.16.5.0/24",
		"2001:db8:1::/64", "2001:db8:2::/64",
	}
	used := make(map[int]bool)
	for _, c := range cidrs {
		want := stableSubnetID(c)
		got := resolveSubnetID(c, used)
		if got != want {
			t.Errorf("resolveSubnetID(%s) = %d, want stableSubnetID direct hit %d", c, got, want)
		}
		if got < 1 || got > keaSubnetIDMax {
			t.Errorf("resolveSubnetID(%s) = %d outside valid Kea range [1,%d]", c, got, keaSubnetIDMax)
		}
		if used[got] {
			t.Errorf("resolveSubnetID(%s) = %d duplicates an already-assigned id", c, got)
		}
		used[got] = true
	}
}
