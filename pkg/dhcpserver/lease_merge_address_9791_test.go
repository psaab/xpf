package dhcpserver

import (
	"reflect"
	"testing"
)

func v4Lease9791(addr, mac string, valid, remaining int) SyncLease {
	return SyncLease{Family: 4, Address: addr, HWAddress: mac, ValidLife: valid, Remaining: remaining}
}

func owners9791(rows []SyncLease) map[string][]string {
	out := map[string][]string{}
	for _, l := range rows {
		id := l.HWAddress
		if l.Family == 6 {
			id = l.DUID
		}
		out[leaseAddressKey9791(l)] = append(out[leaseAddressKey9791(l)], id)
	}
	return out
}

// TestPreSeedKeepsOneOwnerPerAddress9791 is #9791's shape. The promoted node's
// local memfile still held an older grant of 10.0.61.100 to the client that
// released it, while the peer held the current grant to client A. Both rows
// used to be written, local first, and client A's renewal was refused.
func TestPreSeedKeepsOneOwnerPerAddress9791(t *testing.T) {
	local := []SyncLease{v4Lease9791("10.0.61.100", "42:52:86:7e:4e:37", 86400, 80000)} // granted 6400s ago
	peer := []SyncLease{v4Lease9791("10.0.61.100", "f6:c2:10:d9:73:69", 86400, 86390)}  // granted 10s ago
	got := owners9791(mergeLeasesByIdentity(local, peer, 4))
	if want := []string{"f6:c2:10:d9:73:69"}; !reflect.DeepEqual(got["4|10.0.61.100"], want) {
		t.Fatalf("10.0.61.100 owners %v, want only the most recent grant %v", got["4|10.0.61.100"], want)
	}
}

// TestPreSeedAddressConflictCases9791 pins the rest of the rule.
func TestPreSeedAddressConflictCases9791(t *testing.T) {
	cases := []struct {
		name        string
		local, peer []SyncLease
		family      int
		want        map[string][]string
	}{
		{
			name:   "a live local binding beats an older peer copy for another client",
			local:  []SyncLease{v4Lease9791("10.0.61.101", "aa:aa:aa:aa:aa:01", 86400, 86390)},
			peer:   []SyncLease{v4Lease9791("10.0.61.101", "bb:bb:bb:bb:bb:01", 86400, 50000)},
			family: 4,
			want:   map[string][]string{"4|10.0.61.101": {"aa:aa:aa:aa:aa:01"}},
		},
		{
			name:   "the same binding on both sides keeps the local copy even when the peer's is newer",
			local:  []SyncLease{v4Lease9791("10.0.61.102", "cc:cc:cc:cc:cc:01", 86400, 70000)},
			peer:   []SyncLease{v4Lease9791("10.0.61.102", "cc:cc:cc:cc:cc:01", 86400, 86399)},
			family: 4,
			want:   map[string][]string{"4|10.0.61.102": {"cc:cc:cc:cc:cc:01"}},
		},
		{
			name:   "control: distinct addresses both survive",
			local:  []SyncLease{v4Lease9791("10.0.61.103", "dd:dd:dd:dd:dd:01", 86400, 80000)},
			peer:   []SyncLease{v4Lease9791("10.0.61.104", "ee:ee:ee:ee:ee:01", 86400, 86000)},
			family: 4,
			want:   map[string][]string{"4|10.0.61.103": {"dd:dd:dd:dd:dd:01"}, "4|10.0.61.104": {"ee:ee:ee:ee:ee:01"}},
		},
		{
			name:   "a tie keeps the local row",
			local:  []SyncLease{v4Lease9791("10.0.61.105", "11:11:11:11:11:01", 86400, 86000)},
			peer:   []SyncLease{v4Lease9791("10.0.61.105", "22:22:22:22:22:01", 86400, 86000)},
			family: 4,
			want:   map[string][]string{"4|10.0.61.105": {"11:11:11:11:11:01"}},
		},
		{
			name:   "a row without its valid lifetime is compared by remaining lifetime",
			local:  []SyncLease{v4Lease9791("10.0.61.106", "33:33:33:33:33:01", 0, 1000)},
			peer:   []SyncLease{v4Lease9791("10.0.61.106", "44:44:44:44:44:01", 86400, 86000)},
			family: 4,
			want:   map[string][]string{"4|10.0.61.106": {"44:44:44:44:44:01"}},
		},
		{
			name: "v6 IA_NA resolves one owner by recency",
			local: []SyncLease{{Family: 6, Address: "2001:db8:61::100", DUID: "00:01:aa", IAID: 1, LeaseType: "IA_NA",
				ValidLife: 7200, Remaining: 1000}},
			peer: []SyncLease{{Family: 6, Address: "2001:db8:61::100", DUID: "00:01:bb", IAID: 1, LeaseType: "IA_NA",
				ValidLife: 7200, Remaining: 7190}},
			family: 6,
			want:   map[string][]string{"6|2001:db8:61::100|IA_NA|0": {"00:01:bb"}},
		},
		{
			name: "control: v6 prefixes of different length on one base are different occupancies",
			local: []SyncLease{{Family: 6, Address: "2001:db8:ff00::", DUID: "00:01:cc", IAID: 2, LeaseType: "IA_PD",
				PrefixLen: 56, ValidLife: 7200, Remaining: 7000}},
			peer: []SyncLease{{Family: 6, Address: "2001:db8:ff00::", DUID: "00:01:dd", IAID: 2, LeaseType: "IA_PD",
				PrefixLen: 60, ValidLife: 7200, Remaining: 7100}},
			family: 6,
			want: map[string][]string{
				"6|2001:db8:ff00::|IA_PD|56": {"00:01:cc"},
				"6|2001:db8:ff00::|IA_PD|60": {"00:01:dd"},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := owners9791(mergeLeasesByIdentity(tc.local, tc.peer, tc.family)); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("owners %v, want %v", got, tc.want)
			}
		})
	}
}

// TestPreSeedIdentityConflictKeepsTheLocalCopy9791: pass 1 is unchanged. The
// same binding on both sides keeps the LOCAL row, even though pass 2 would call
// the peer's copy the more recent grant.
func TestPreSeedIdentityConflictKeepsTheLocalCopy9791(t *testing.T) {
	local := []SyncLease{v4Lease9791("10.0.61.102", "cc:cc:cc:cc:cc:01", 86400, 70000)}
	peer := []SyncLease{v4Lease9791("10.0.61.102", "cc:cc:cc:cc:cc:01", 86400, 86399)}
	got := mergeLeasesByIdentity(local, peer, 4)
	if len(got) != 1 || got[0].Remaining != 70000 {
		t.Fatalf("want the local copy (remaining 70000) alone, got %+v", got)
	}
}
