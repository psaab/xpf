package userspace

import (
	"encoding/binary"
	"testing"
)

// This test intentionally inspects map ABI sizes so the same test runs against
// the address-only master object and the domain-scoped fixed object. On master,
// the foreign-local destination is seeded into the address-only map and wrongly
// XDP_PASSes; with the fix, it is seeded only in its owner domain and redirects.
func TestUserspaceXDPDoesNotPassForeignDomainLocalAddress13929(t *testing.T) {
	const redDomain = uint32(100042)
	dst := [4]byte{10, 0, 0, 1}
	for _, tc := range []struct {
		name          string
		owner         uint32
		ingressDomain uint32
		wantAction    uint32
		wantRedirect  bool
	}{
		{name: "foreign owner does not pass through default ingress", owner: redDomain, wantAction: xdpActionDrop, wantRedirect: true},
		{name: "default owner passes through default ingress", wantAction: xdpActionPass},
		{name: "red owner passes through red ingress", owner: redDomain, ingressDomain: redDomain, wantAction: xdpActionPass},
	} {
		t.Run(tc.name, func(t *testing.T) {
			coll := loadUserspaceXDPTestCollection(t)
			if coll.Maps["userspace_ingress_domains"] == nil && tc.ingressDomain != 0 {
				t.Skip("master ingress has no routing-domain map")
			}
			updateUserspaceXDPTestIngressDomain(t, coll, userspaceXDPTestRunIfindex(t), tc.ingressDomain)
			updateUserspaceXDPTestCtrl(t, coll, userspaceCtrlValue{
				Enabled: 1, MetadataVersion: userspaceMetadataVersion, Workers: 1, QueueCount: 1,
				HeartbeatTimeoutMS: userspaceHeartbeatTimeoutMS,
			})
			updateUserspaceXDPTestBinding(t, coll, userspaceXDPTestRunBindingIndex(t, 0), userspaceBindingValue{Slot: 0, Flags: userspaceBindingReady})
			updateUserspaceXDPTestHeartbeat(t, coll, 0)

			local := coll.Maps[mapNameUserspaceLocalV4]
			localInfo, err := local.Info()
			if err != nil {
				t.Fatalf("local map info: %v", err)
			}
			addr := binary.BigEndian.Uint32(dst[:])
			if localInfo.KeySize == 4 {
				updateUserspaceXDPTestMap(t, coll, mapNameUserspaceLocalV4, addr, uint8(1))
			} else {
				updateUserspaceXDPTestMap(t, coll, mapNameUserspaceLocalV4, struct {
					Domain uint32
					Addr   uint32
				}{Domain: tc.owner, Addr: addr}, uint8(1))
			}

			got := runUserspaceXDPTestPacket(t, coll, udpIPv4TestPacket([4]byte{198, 51, 100, 9}, dst))
			if got != tc.wantAction {
				t.Fatalf("XDP action = %d, want %d", got, tc.wantAction)
			}
			redirectErrors := userspaceXDPDegradedPathStat(t, coll, "redirect_err")
			if tc.wantRedirect && redirectErrors == 0 {
				t.Fatal("foreign-domain local destination did not reach the worker redirect attempt")
			}
			if !tc.wantRedirect && redirectErrors != 0 {
				t.Fatalf("local destination reached worker redirect %d times", redirectErrors)
			}
		})
	}
}
