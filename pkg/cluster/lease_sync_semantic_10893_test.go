package cluster

import (
	"context"
	"encoding/json"
	"math"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/dhcpserver"
)

const expectedMaxSyncLeaseLifetime10893 = 5 * 365 * 24 * 60 * 60

type leaseSeedRequest10893 struct {
	Command   string `json:"command"`
	Arguments struct {
		IPAddress string `json:"ip-address"`
		ValidLft  int    `json:"valid-lft"`
		Type      string `json:"type"`
		PrefixLen int    `json:"prefix-len"`
	} `json:"arguments"`
}

type leaseValidationStats10893 struct {
	MalformedRecordsDropped     uint64
	DHCPLeasesDroppedNoIdentity uint64
}

// deliverDHCPLeasesToSeed10893 drives the real wire encoder, receiver decode / semantic
// filter, callback, and Kea socket seed with an in-memory control-socket peer.
func deliverDHCPLeasesToSeed10893(t *testing.T, family int, leases []dhcpserver.SyncLease) ([]leaseSeedRequest10893, int, error, leaseValidationStats10893) {
	t.Helper()
	var mu sync.Mutex
	var requests []leaseSeedRequest10893
	dial := func(_ context.Context, _ string) (net.Conn, error) {
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			var request leaseSeedRequest10893
			if err := json.NewDecoder(server).Decode(&request); err != nil {
				t.Errorf("decode seed command: %v", err)
				return
			}
			mu.Lock()
			requests = append(requests, request)
			mu.Unlock()
			if err := json.NewEncoder(server).Encode(struct {
				Result int `json:"result"`
			}{Result: 0}); err != nil {
				t.Errorf("write seed response: %v", err)
			}
		}()
		return client, nil
	}
	manager := dhcpserver.New()
	manager.SetLeaseSyncSeamsForTesting(dial, "test4", "test6", "", "")
	now := time.Unix(1_700_000_000, 0)
	var seeded int
	var seedErr error
	syncer := NewSessionSync(":0", "10.0.0.2:4785", nil)
	syncer.OnDHCPLeasesReceived = func(receivedFamily int, got []dhcpserver.SyncLease) {
		if receivedFamily != family {
			t.Errorf("callback family = %d, want %d", receivedFamily, family)
			return
		}
		if family == 4 {
			seeded, seedErr = manager.SeedSyncLeases4(context.Background(), got, now)
		} else {
			seeded, seedErr = manager.SeedSyncLeases6(context.Background(), got, now)
		}
	}
	msgType := uint8(syncMsgDHCPLeaseV4)
	if family == 6 {
		msgType = syncMsgDHCPLeaseV6
	}
	syncer.handleMessage(nil, msgType, encodeDHCPLeasePayload(leases))
	mu.Lock()
	gotRequests := append([]leaseSeedRequest10893(nil), requests...)
	mu.Unlock()
	return gotRequests, seeded, seedErr, leaseValidationStats10893{
		MalformedRecordsDropped:     syncer.stats.MalformedRecordsDropped.Load(),
		DHCPLeasesDroppedNoIdentity: syncer.stats.DHCPLeasesDroppedNoIdentity.Load(),
	}
}

func TestDHCPLeaseSyncSemanticValidation10893(t *testing.T) {
	v4 := []dhcpserver.SyncLease{
		{Family: 4, Address: "10.0.0.5", HWAddress: "aa:bb:cc:dd:ee:05", ValidLife: 3600, Remaining: 1800},
		{Family: 4, Address: "2001:db8::5", HWAddress: "aa:bb:cc:dd:ee:06", ValidLife: 3600, Remaining: 1800},                   // wrong address family
		{Family: 4, Address: "127.0.0.1", HWAddress: "aa:bb:cc:dd:ee:07", ValidLife: 3600, Remaining: 1800},                     // loopback scope
		{Family: 4, Address: "169.254.1.1", HWAddress: "aa:bb:cc:dd:ee:08", ValidLife: 3600, Remaining: 1800},                   // link-local scope
		{Family: 6, Address: "2001:db8::9", DUID: "00:01:09", LeaseType: "IA_NA", Remaining: 1800},                              // wrong row family
		{Family: 4, Address: "10.0.0.10", HWAddress: "aa:bb:cc:dd:ee:10", ValidLife: math.MaxUint32, Remaining: math.MaxUint32}, // extreme lifetime
	}
	requests, seeded, err, stats := deliverDHCPLeasesToSeed10893(t, 4, v4)
	if err != nil || seeded != 2 || len(requests) != 2 {
		t.Fatalf("v4 seed = (%d, %d requests, %v), want two valid rows", seeded, len(requests), err)
	}
	if requests[0].Arguments.IPAddress != "10.0.0.5" || requests[0].Arguments.ValidLft != 1800 {
		t.Fatalf("valid v4 lease seed = %+v", requests[0])
	}
	if requests[1].Arguments.IPAddress != "10.0.0.10" || requests[1].Arguments.ValidLft != expectedMaxSyncLeaseLifetime10893 {
		t.Fatalf("extreme v4 lease was not capped before seed: %+v", requests[1])
	}
	if stats.MalformedRecordsDropped != 3 || stats.DHCPLeasesDroppedNoIdentity != 1 {
		t.Fatalf("v4 drop stats = malformed:%d identity:%d, want 3 and 1", stats.MalformedRecordsDropped, stats.DHCPLeasesDroppedNoIdentity)
	}

	v6 := []dhcpserver.SyncLease{
		{Family: 6, Address: "2001:db8::6", DUID: "00:01:06", LeaseType: "IA_NA", ValidLife: 3600, Remaining: 1800},
		{Family: 6, Address: "2001:db8:1::", DUID: "00:01:07", LeaseType: "IA_PD", PrefixLen: 0, ValidLife: 3600, Remaining: 1800},       // empty prefix
		{Family: 6, Address: "fe80::1", DUID: "00:01:08", LeaseType: "IA_NA", ValidLife: 3600, Remaining: 1800},                          // link-local scope
		{Family: 4, Address: "10.0.0.9", HWAddress: "aa:bb:cc:dd:ee:09", Remaining: 1800},                                                // wrong row family
		{Family: 6, Address: "2001:db8::10", DUID: "00:01:10", LeaseType: "IA_NA", ValidLife: math.MaxUint32, Remaining: math.MaxUint32}, // extreme lifetime
	}
	requests, seeded, err, stats = deliverDHCPLeasesToSeed10893(t, 6, v6)
	if err != nil || seeded != 2 || len(requests) != 2 {
		t.Fatalf("v6 seed = (%d, %d requests, %v), want two valid rows", seeded, len(requests), err)
	}
	if requests[0].Arguments.IPAddress != "2001:db8::6" || requests[0].Arguments.Type != "IA_NA" {
		t.Fatalf("valid v6 lease seed = %+v", requests[0])
	}
	if requests[1].Arguments.IPAddress != "2001:db8::10" || requests[1].Arguments.ValidLft != expectedMaxSyncLeaseLifetime10893 {
		t.Fatalf("extreme v6 lease was not capped before seed: %+v", requests[1])
	}
	if stats.MalformedRecordsDropped != 2 || stats.DHCPLeasesDroppedNoIdentity != 1 {
		t.Fatalf("v6 drop stats = malformed:%d identity:%d, want 2 and 1", stats.MalformedRecordsDropped, stats.DHCPLeasesDroppedNoIdentity)
	}
}

func FuzzDHCPLeaseDecodeToSeed10893(f *testing.F) {
	// Flags bit 0 selects the message family (0=v4, 1=v6); bit 1 changes
	// the row family, covering a validly framed cross-family record.
	f.Add(uint8(0), "2001:db8::1", "IA_NA", int32(0), uint32(3600))        // v4 frame, v6 address
	f.Add(uint8(0), "127.0.0.1", "IA_NA", int32(0), uint32(3600))          // wrong address scope
	f.Add(uint8(1), "2001:db8:1::", "IA_PD", int32(0), uint32(3600))       // zero-length delegated prefix
	f.Add(uint8(0), "10.0.0.1", "IA_NA", int32(0), uint32(math.MaxUint32)) // extreme Remaining
	f.Add(uint8(2), "10.0.0.1", "IA_NA", int32(0), uint32(3600))           // wrong row family
	f.Add(uint8(0), "0.1.2.3", "IA_NA", int32(0), uint32(3600))            // reserved v4 scope
	f.Add(uint8(0), "240.0.0.1", "IA_NA", int32(0), uint32(3600))          // reserved v4 scope
	f.Add(uint8(1), "fe80::1", "IA_NA", int32(0), uint32(3600))            // v6 link-local scope

	f.Fuzz(func(t *testing.T, flags uint8, address, leaseType string, prefixLen int32, remaining uint32) {
		family := 4
		if flags&1 != 0 {
			family = 6
		}
		rowFamily := family
		if flags&2 != 0 {
			if family == 4 {
				rowFamily = 6
			} else {
				rowFamily = 4
			}
		}
		lease := dhcpserver.SyncLease{
			Family: rowFamily, Address: address, SubnetID: 1, HWAddress: "aa:bb:cc:dd:ee:01",
			ClientID: "01:aa:bb:cc:dd:ee:01", DUID: "00:01:01", LeaseType: leaseType,
			PrefixLen: int(prefixLen), ValidLife: math.MaxUint32, Remaining: int(remaining),
			PreferredRemaining: int(remaining),
		}
		requests, seeded, err, _ := deliverDHCPLeasesToSeed10893(t, family, []dhcpserver.SyncLease{lease})
		if err != nil {
			t.Fatalf("seed error: %v", err)
		}
		if len(requests) > 1 || seeded != len(requests) {
			t.Fatalf("seeded=%d requests=%d; one wire row cannot seed more than once", seeded, len(requests))
		}
		wantSeed := lease.Family == family && validSemanticAddress10893(family, address) && remaining > 0 &&
			(family != 6 || leaseType != "IA_PD" || (prefixLen >= 1 && prefixLen <= 128)) &&
			len(address) <= math.MaxUint16 && len(leaseType) <= math.MaxUint16
		if wantSeed != (len(requests) == 1) {
			t.Fatalf("family=%d row=%+v: seeded=%v, want %v", family, lease, len(requests) == 1, wantSeed)
		}
		if len(requests) == 1 {
			request := requests[0]
			if request.Command != map[int]string{4: "lease4-add", 6: "lease6-add"}[family] || request.Arguments.IPAddress != address {
				t.Fatalf("seed request does not preserve the validated lease: %+v", request)
			}
			if request.Arguments.ValidLft <= 0 || request.Arguments.ValidLft > expectedMaxSyncLeaseLifetime10893 {
				t.Fatalf("seed valid-lft escaped semantic lifetime bounds: %d", request.Arguments.ValidLft)
			}
			if family == 6 && leaseType == "IA_PD" && request.Arguments.PrefixLen != int(prefixLen) {
				t.Fatalf("seeded IA_PD prefix length %d, want %d", request.Arguments.PrefixLen, prefixLen)
			}
		}
	})
}

func validSemanticAddress10893(family int, address string) bool {
	ip := net.ParseIP(address)
	if ip == nil || ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}
	switch family {
	case 4:
		v4 := ip.To4()
		return v4 != nil && !strings.Contains(address, ":") && v4[0] != 0 && v4[0] < 240
	case 6:
		return ip.To4() == nil && strings.Contains(address, ":")
	default:
		return false
	}
}
