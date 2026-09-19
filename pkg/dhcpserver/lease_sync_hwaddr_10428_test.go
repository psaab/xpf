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

// #10428 (GEMINI-049-093): the DHCP HA memfile fallback dropped the IPv4
// hardware address for every lease carrying Option 61 (client-id).
//
// parseActiveLeasesFileInto packed BOTH memfile columns into one DDNS owner
// key (l.Identity = identity4(client_id, hwaddr)), and identity4 prefers the
// client-id ("cid:..."), discarding the MAC. readSyncLeasesViaMemfile then
// unpacked with splitV4Identity, which returns hwaddr="" for any "cid:..."
// identity. syncLeaseToKea renders HWAddress with `json:"hw-address,omitempty"`,
// so the seeded lease4-add omitted hw-address — which Kea documents as "a
// mandatory parameter for an IPv4 lease". Every Option-61-bearing v4 lease was
// therefore rejected on takeover seeding, exactly when the fallback exists to
// save us (control socket down).
//
// Fix shape (per the issue's acceptance option 1): ddnsLease carries ClientID
// and HWAddress as separate fields for the sync path, while Identity stays the
// client-id-preferred DDNS owner key (changing it would churn DDNS ownership —
// see the delete + re-add MAJOR-B warning in ddns_leases.go).
//
// Fail-on-revert: dropping the separate fields (parsing HWAddress back out of
// the packed Identity) empties HWAddress on the Option-61 row → the
// PreservesHWAddress and RendersHWAddress tests below go RED.

const v4MemfileHeader10428 = "address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state\n"

// writeV4Memfile10428 writes a v4 memfile with the given data rows.
func writeV4Memfile10428(t *testing.T, memfile string, rows ...string) {
	t.Helper()
	var b strings.Builder
	b.WriteString(v4MemfileHeader10428)
	for _, r := range rows {
		b.WriteString(r)
	}
	if err := os.WriteFile(memfile, []byte(b.String()), 0644); err != nil {
		t.Fatal(err)
	}
}

// fallbackLeases10428 reads v4 leases through the memfile fallback (control
// socket pointed at a missing path so the socket read errors).
func fallbackLeases10428(t *testing.T, memfile string, now time.Time) []SyncLease {
	t.Helper()
	m := New()
	m.SetLeaseSyncSeamsForTesting(nil, filepath.Join(t.TempDir(), "missing.sock"), "", memfile, "")
	leases, err := m.GetSyncLeases4(context.Background(), now)
	if err != nil {
		t.Fatalf("GetSyncLeases4 (fallback): %v", err)
	}
	return leases
}

func leaseByAddr10428(t *testing.T, leases []SyncLease, addr string) SyncLease {
	t.Helper()
	for _, l := range leases {
		if l.Address == addr {
			return l
		}
	}
	t.Fatalf("no lease for %s in %+v", addr, leases)
	return SyncLease{}
}

// Cell A: a memfile row carrying BOTH client_id and hwaddr must yield a
// SyncLease carrying both — the fallback path must be equivalent to the
// primary (control-socket) path, which copies both fields verbatim
// (keaLeaseToSync). The hwaddr-only row pins the "mac:" branch against
// regression in the other direction.
func TestGetSyncLeases4_MemfileFallback_PreservesHWAddress10428(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	expire := strconv.FormatInt(now.Unix()+1800, 10)
	dir := t.TempDir()
	memfile := filepath.Join(dir, "kea-leases4.csv")
	writeV4Memfile10428(t, memfile,
		"10.0.61.80,aa:bb:cc:dd:ee:80,01:aa:bb:cc:dd:ee:80,3600,"+expire+",2,0,0,host-opt61,0\n",
		"10.0.61.81,aa:bb:cc:dd:ee:81,,3600,"+expire+",2,0,0,host-nocid,0\n",
	)

	leases := fallbackLeases10428(t, memfile, now)
	if len(leases) != 2 {
		t.Fatalf("expected 2 leases from memfile, got %d: %+v", len(leases), leases)
	}

	opt61 := leaseByAddr10428(t, leases, "10.0.61.80")
	if opt61.HWAddress != "aa:bb:cc:dd:ee:80" {
		t.Errorf("Option-61 lease HWAddress = %q, want %q (MAC dropped by packed Identity)",
			opt61.HWAddress, "aa:bb:cc:dd:ee:80")
	}
	if opt61.ClientID != "01:aa:bb:cc:dd:ee:80" {
		t.Errorf("Option-61 lease ClientID = %q, want %q", opt61.ClientID, "01:aa:bb:cc:dd:ee:80")
	}

	noCID := leaseByAddr10428(t, leases, "10.0.61.81")
	if noCID.HWAddress != "aa:bb:cc:dd:ee:81" {
		t.Errorf("hwaddr-only lease HWAddress = %q, want %q", noCID.HWAddress, "aa:bb:cc:dd:ee:81")
	}
	if noCID.ClientID != "" {
		t.Errorf("hwaddr-only lease ClientID = %q, want empty", noCID.ClientID)
	}
}

// Cell A (equivalence half): the same binding read via the live control
// socket (primary) and via the memfile (fallback) must agree on every
// identity-carrying field. ValidLife is intentionally excluded: the memfile
// fallback does not consume the valid_lifetime column for v4 (Remaining is
// derived from the absolute expire epoch), while the socket path reports
// Kea's configured valid-lft — a pre-existing, out-of-scope difference.
func TestMemfileFallbackMatchesSocketPrimary10428(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	expire := now.Unix() + 1800

	dir := t.TempDir()
	memfile := filepath.Join(dir, "kea-leases4.csv")
	writeV4Memfile10428(t, memfile,
		"10.0.61.80,aa:bb:cc:dd:ee:80,01:aa:bb:cc:dd:ee:80,3600,"+
			strconv.FormatInt(expire, 10)+",2,0,0,host-opt61,0\n",
	)
	fallback := fallbackLeases10428(t, memfile, now)
	if len(fallback) != 1 {
		t.Fatalf("expected 1 fallback lease, got %d: %+v", len(fallback), fallback)
	}

	sock := tmpSocket(t, "k4-10428.sock")
	stub := &stubKea{handler: func(cmd keaCommand) keaResponse {
		return leaseGetAllResponse([]keaLeaseJSON{{
			IPAddress: "10.0.61.80", HWAddress: "aa:bb:cc:dd:ee:80",
			ClientID: "01:aa:bb:cc:dd:ee:80", SubnetID: 2,
			ValidLft: 3600, CLTT: now.Unix() - 1800, State: keaStateDefault,
			Hostname: "host-opt61",
		}})
	}}
	dial, stop := startStubKea(t, sock, stub)
	defer stop()
	m := New()
	m.SetLeaseSyncSeamsForTesting(dial, sock, "", "", "")
	primary, err := m.GetSyncLeases4(context.Background(), now)
	if err != nil {
		t.Fatalf("GetSyncLeases4 (socket): %v", err)
	}
	if len(primary) != 1 {
		t.Fatalf("expected 1 socket lease, got %d: %+v", len(primary), primary)
	}

	fb, pr := fallback[0], primary[0]
	if fb.Address != pr.Address || fb.HWAddress != pr.HWAddress || fb.ClientID != pr.ClientID {
		t.Errorf("fallback identity %+v != primary identity %+v", fb, pr)
	}
	if fb.SubnetID != pr.SubnetID || fb.Hostname != pr.Hostname || fb.Remaining != pr.Remaining {
		t.Errorf("fallback meta %+v != primary meta %+v", fb, pr)
	}
}

// Cell B (issue acceptance): a memfile row with Option 61 seeds a lease4-add
// whose arguments carry hw-address. End-to-end: memfile → fallback SyncLease
// → syncLeaseToKea → lease4-add JSON.
func TestSyncLeaseToKea4_Option61RendersHWAddress10428(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	expire := strconv.FormatInt(now.Unix()+1800, 10)
	dir := t.TempDir()
	memfile := filepath.Join(dir, "kea-leases4.csv")
	writeV4Memfile10428(t, memfile,
		"10.0.61.80,aa:bb:cc:dd:ee:80,01:aa:bb:cc:dd:ee:80,3600,"+expire+",2,0,0,host-opt61,0\n",
	)
	leases := fallbackLeases10428(t, memfile, now)
	if len(leases) != 1 {
		t.Fatalf("expected 1 fallback lease, got %d: %+v", len(leases), leases)
	}
	raw, err := json.Marshal(syncLeaseToKea(leases[0], now))
	if err != nil {
		t.Fatalf("marshal lease4-add args: %v", err)
	}
	args := string(raw)
	if !strings.Contains(args, `"hw-address":"aa:bb:cc:dd:ee:80"`) {
		t.Errorf("lease4-add args missing hw-address: %s", args)
	}
	if !strings.Contains(args, `"client-id":"01:aa:bb:cc:dd:ee:80"`) {
		t.Errorf("lease4-add args missing client-id: %s", args)
	}
}

// Cell C (issue acceptance, characterization): Kea documents hw-address as "a
// mandatory parameter for an IPv4 lease" (lease4-add; client-id is optional).
// Exercise the actual seed path with that rejection response and pin the
// rendered arguments that caused it: an empty HWAddress is omitted by
// `json:"hw-address,omitempty"`, while the client-id remains present. This
// keeps the failure mode visible in the same command/error flow as takeover
// seeding. GREEN both before and after the fix by design.
func TestSeedSyncLeases4_EmptyHWAddressReportsKeaRejection10428(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	const rejection = "hw-address is mandatory for IPv4 lease"
	sock := tmpSocket(t, "k4reject.sock")
	stub := &stubKea{handler: func(cmd keaCommand) keaResponse {
		if cmd.Command != "lease4-add" {
			t.Errorf("unexpected command %q", cmd.Command)
		}
		return keaResponse{Result: keaResultError, Text: rejection}
	}}
	dial, stop := startStubKea(t, sock, stub)
	defer stop()

	m := New()
	m.SetLeaseSyncSeamsForTesting(dial, sock, "", "", "")
	n, err := m.SeedSyncLeases4(context.Background(), []SyncLease{{
		Family: 4, Address: "10.0.61.90", ClientID: "01:aa:bb:cc:dd:ee:90",
		SubnetID: 2, Remaining: 100,
	}}, now)
	if err == nil || !strings.Contains(err.Error(), rejection) {
		t.Fatalf("SeedSyncLeases4 error = %v, want Kea rejection %q", err, rejection)
	}
	if n != 0 {
		t.Fatalf("seeded = %d, want 0 after Kea rejection", n)
	}

	commands := stub.seen()
	if len(commands) != 1 {
		t.Fatalf("captured %d commands, want one lease4-add: %+v", len(commands), commands)
	}
	raw, err := json.Marshal(commands[0].Arguments)
	if err != nil {
		t.Fatalf("marshal captured lease4-add args: %v", err)
	}
	args := string(raw)
	if strings.Contains(args, "hw-address") {
		t.Errorf("empty HWAddress must omit hw-address in rejected args: %s", args)
	}
	if !strings.Contains(args, `"client-id":"01:aa:bb:cc:dd:ee:90"`) {
		t.Errorf("client-id must still render in rejected args: %s", args)
	}
}
