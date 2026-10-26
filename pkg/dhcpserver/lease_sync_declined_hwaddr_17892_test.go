package dhcpserver

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// #17892: identity-free declined (state=1) v4 leases omit the mandatory
// hw-address argument on lease4-add, so the real Kea socket backstop rejects
// the rows that the #16856 stub test accepts.
//
// #16856 deliberately exempted declined rows from the HW/ClientID identity
// requirement (cluster validLeaseIdentityForFamily, SanitizeSyncLeaseForFamily,
// IdentityKey address-only). syncLeaseToKea rendered HWAddress with
// `json:"hw-address,omitempty"`, so an identity-free declined row marshaled
// to lease4-add arguments with NO hw-address key. Kea 3.0.3's
// lease_parser.cc Lease4Parser::parse calls getString(lease_info,
// "hw-address") before it inspects state, so the real parser rejects the
// missing argument.
//
// The socket backstop is distinct from the memfile pre-seed path: the v4
// memfile row can carry an empty hwaddr column, and Kea's declined lease uses
// an empty HWAddr internally. `syncLeaseToKea` keeps that empty string, while
// the lease4-add/update wrapper ensures the required JSON member is present.
// ClientID-only declined rows need the same argument because Kea's parser
// requires hw-address even when client-id is present.
//
// Fail-on-revert: removing the declined lease4 argument wrapper makes the
// in-process Kea parser stub reject identity-free and ClientID-only declined
// lease4-add/update commands; both the seed and conflict-update tests go RED.
// The stub mirrors the pinned parser's required-key check, not a live daemon.

// keaLease4AddMandatory17892 mirrors Kea 3.0.3 Lease4Parser::parse's
// mandatory-argument behavior. Raw JSON keys distinguish "absent" from an
// explicitly empty value.
func keaLease4AddMandatory17892(cmd keaCommand) (map[string]json.RawMessage, keaResponse, bool) {
	if cmd.Command != "lease4-add" && cmd.Command != "lease4-update" {
		return nil, keaResponse{Result: keaResultError, Text: "unexpected"}, false
	}
	raw, err := json.Marshal(cmd.Arguments)
	if err != nil {
		return nil, keaResponse{Result: keaResultError, Text: "marshal"}, false
	}
	var args map[string]json.RawMessage
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, keaResponse{Result: keaResultError, Text: "unmarshal"}, false
	}
	if _, ok := args["ip-address"]; !ok {
		return args, keaResponse{Result: keaResultError, Text: "Kea: ip-address missing"}, true
	}
	if _, ok := args["hw-address"]; !ok {
		return args, keaResponse{Result: keaResultError, Text: "Kea: hw-address missing"}, true
	}
	return args, keaResponse{Result: keaResultSuccess}, true
}

func TestDeclined17892_IdentityFreeSeedCarriesMandatoryHWAddress(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	sock := tmpSocket(t, "k4decl17892.sock")
	var got []map[string]json.RawMessage
	stub := &stubKea{handler: func(cmd keaCommand) keaResponse {
		args, resp, isAdd := keaLease4AddMandatory17892(cmd)
		if isAdd && resp.Result == keaResultSuccess {
			got = append(got, args)
		}
		return resp
	}}
	dial, stop := startStubKea(t, sock, stub)
	defer stop()
	m := New()
	m.SetLeaseSyncSeamsForTesting(dial, sock, "", "", "")

	in := []SyncLease{
		// Target: identity-free declined row, the #16856 carve-out shape.
		{Family: 4, Address: "10.0.61.66", SubnetID: 1, Remaining: 1800, State: keaStateDeclined},
		// ClientID-only declined rows also need Kea's mandatory hw-address.
		{Family: 4, Address: "10.0.61.67", SubnetID: 1, Remaining: 1800, State: keaStateDeclined, ClientID: "01:aa:bb:cc:dd:ee:67"},
		// Controls: declined with HWAddress and active with identity are unchanged.
		{Family: 4, Address: "10.0.61.68", SubnetID: 1, Remaining: 1800, State: keaStateDeclined, HWAddress: "aa:bb:cc:dd:ee:68"},
		{Family: 4, Address: "10.0.61.10", SubnetID: 1, Remaining: 1800, State: keaStateDefault, HWAddress: "aa:bb:cc:dd:ee:10", ClientID: "01:aa:bb:cc:dd:ee:10"},
	}
	n, err := m.SeedSyncLeases4(context.Background(), in, now)
	if err != nil {
		t.Fatalf("SeedSyncLeases4 (real Kea would reject identity-free declined add): %v", err)
	}
	if n != len(in) || len(got) != len(in) {
		t.Fatalf("seeded n=%d captured=%d, want %d each", n, len(got), len(in))
	}
	byAddr := map[string]map[string]json.RawMessage{}
	for _, args := range got {
		var ip string
		if err := json.Unmarshal(args["ip-address"], &ip); err != nil {
			t.Fatalf("decode ip-address: %v", err)
		}
		byAddr[ip] = args
	}
	hwOf := func(addr string) string {
		t.Helper()
		args, ok := byAddr[addr]
		if !ok {
			t.Fatalf("no lease4-add captured for %s", addr)
		}
		rawHW, ok := args["hw-address"]
		if !ok {
			t.Fatalf("lease4-add for %s omits mandatory hw-address: %s", addr, mustJSON17892(args))
		}
		var hw string
		if err := json.Unmarshal(rawHW, &hw); err != nil {
			t.Fatalf("decode hw-address for %s: %v", addr, err)
		}
		return hw
	}
	for _, addr := range []string{"10.0.61.66", "10.0.61.67"} {
		if hw := hwOf(addr); hw != "" {
			t.Errorf("declined row %s hw-address = %q, want present empty value", addr, hw)
		}
	}
	for _, addr := range []string{"10.0.61.66", "10.0.61.67"} {
		if got := string(byAddr[addr]["hw-address"]); got != `""` {
			t.Errorf("declined row %s hw-address JSON = %s, want an explicit empty string", addr, got)
		}
	}
	if cid := byAddr["10.0.61.67"]["client-id"]; !strings.Contains(string(cid), "01:aa:bb:cc:dd:ee:67") {
		t.Errorf("client-id-only declined lost its client-id: %s", mustJSON17892(byAddr["10.0.61.67"]))
	}
	if hw := hwOf("10.0.61.68"); hw != "aa:bb:cc:dd:ee:68" {
		t.Errorf("declined-with-hwaddr hw-address = %q, want verbatim aa:bb:cc:dd:ee:68", hw)
	}
	if hw := hwOf("10.0.61.10"); hw != "aa:bb:cc:dd:ee:10" {
		t.Errorf("active control hw-address = %q, want verbatim aa:bb:cc:dd:ee:10", hw)
	}
	var st int
	if err := json.Unmarshal(byAddr["10.0.61.66"]["state"], &st); err != nil || st != keaStateDeclined {
		t.Errorf("identity-free row state = %d (err %v), want %d", st, err, keaStateDeclined)
	}
}

// Conflict-then-update leg (#17892 fold): lease4-add reports already-exists,
// so seedOneLease retries lease4-update. The update must carry the SAME
// explicitly-empty hw-address as the add — reverting the update command to
// the unwrapped keaLeaseJSON (lease_sync.go Arguments: kl) drops the key and
// this test goes RED: the parser stub rejects the update.
func TestDeclined17892_ConflictThenUpdateCarriesEmptyHWAddress(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	sock := tmpSocket(t, "k4declupd17892.sock")
	var seen []keaCommand
	var seenArgs []map[string]json.RawMessage
	stub := &stubKea{handler: func(cmd keaCommand) keaResponse {
		args, resp, isLeaseCmd := keaLease4AddMandatory17892(cmd)
		if !isLeaseCmd {
			return resp
		}
		if resp.Result != keaResultSuccess {
			return resp // parser rejects malformed args before any add/update logic
		}
		seen = append(seen, cmd)
		seenArgs = append(seenArgs, args)
		if cmd.Command == "lease4-add" {
			return keaResponse{Result: keaResultConflict, Text: "lease already exists"}
		}
		return keaResponse{Result: keaResultSuccess}
	}}
	dial, stop := startStubKea(t, sock, stub)
	defer stop()
	m := New()
	m.SetLeaseSyncSeamsForTesting(dial, sock, "", "", "")
	n, err := m.SeedSyncLeases4(context.Background(), []SyncLease{
		{Family: 4, Address: "10.0.61.66", SubnetID: 1, Remaining: 1800, State: keaStateDeclined},
	}, now)
	if err != nil {
		t.Fatalf("SeedSyncLeases4 conflict-then-update: %v", err)
	}
	if n != 1 {
		t.Fatalf("seeded n=%d, want 1 via update", n)
	}
	if len(seen) != 2 || seen[0].Command != "lease4-add" || seen[1].Command != "lease4-update" {
		t.Fatalf("commands = %v, want [lease4-add lease4-update]", seen)
	}
	for i, args := range seenArgs {
		if got := string(args["hw-address"]); got != `""` {
			t.Errorf("%s hw-address JSON = %s, want explicit empty string", seen[i].Command, got)
		}
		var ip string
		if err := json.Unmarshal(args["ip-address"], &ip); err != nil || ip != "10.0.61.66" {
			t.Errorf("%s ip-address = %q (err %v), want 10.0.61.66", seen[i].Command, ip, err)
		}
		var st int
		if err := json.Unmarshal(args["state"], &st); err != nil || st != keaStateDeclined {
			t.Errorf("%s state = %d (err %v), want %d", seen[i].Command, st, err, keaStateDeclined)
		}
	}
}

func mustJSON17892(args map[string]json.RawMessage) string {
	b, _ := json.Marshal(args)
	return string(b)
}

func TestDeclined17892_SeedV6LeavesHWAddressOptional(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	sock := tmpSocket(t, "k6decl17892.sock")
	var raw []byte
	stub := &stubKea{handler: func(cmd keaCommand) keaResponse {
		if cmd.Command != "lease6-add" {
			return keaResponse{Result: keaResultError, Text: "unexpected command"}
		}
		raw, _ = json.Marshal(cmd.Arguments)
		return keaResponse{Result: keaResultSuccess}
	}}
	dial, stop := startStubKea(t, sock, stub)
	defer stop()
	m := New()
	m.SetLeaseSyncSeamsForTesting(dial, "", sock, "", "")

	n, err := m.SeedSyncLeases6(context.Background(), []SyncLease{{
		Family: 6, Address: "2001:db8::66", SubnetID: 1,
		DUID: "00:01:00:01:aa:bb:cc:dd:ee:66", IAID: 1, LeaseType: "IA_NA",
		Remaining: 1800, State: keaStateDeclined,
	}}, now)
	if err != nil || n != 1 {
		t.Fatalf("SeedSyncLeases6: n=%d err=%v", n, err)
	}
	var args map[string]json.RawMessage
	if err := json.Unmarshal(raw, &args); err != nil {
		t.Fatalf("decode lease6-add args: %v", err)
	}
	if _, ok := args["hw-address"]; ok {
		t.Errorf("v6 lease6-add unexpectedly has hw-address: %s", raw)
	}
}
