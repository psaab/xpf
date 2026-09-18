package daemon

import (
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

func TestSessionOriginDeltaConversionPreservesPeerOrigin10227(t *testing.T) {
	base := dpuserspace.SessionDeltaInfo{
		AddrFamily:    dataplane.AFInet,
		Protocol:      6,
		SrcIP:         "10.0.0.1",
		DstIP:         "10.0.0.2",
		SrcPort:       1000,
		DstPort:       80,
		IngressZoneID: 1,
		EgressZoneID:  2,
	}
	for _, tc := range []struct {
		origin string
		want   bool
	}{
		{origin: "sync_import", want: true},
		{origin: "shared_materialize", want: true},
		{origin: "worker_local_import", want: false},
		{origin: "forward_flow", want: false},
		{origin: "", want: false},
	} {
		t.Run(tc.origin, func(t *testing.T) {
			delta := base
			delta.Origin = tc.origin
			_, val, ok := userspaceSessionFromDeltaV4(delta, nil)
			if !ok {
				t.Fatal("delta conversion rejected a complete fixture")
			}
			got := val.Flags&dataplane.SessFlagClusterSynced != 0
			if got != tc.want {
				t.Fatalf("origin %q converted to cluster-synced=%v, want %v (flags=%#x)", tc.origin, got, tc.want, val.Flags)
			}
		})
	}
}

func TestSessionOriginDeltaConversionPreservesPeerOriginV6_10227(t *testing.T) {
	base := dpuserspace.SessionDeltaInfo{
		AddrFamily:    dataplane.AFInet6,
		Protocol:      6,
		SrcIP:         "2001:db8::1",
		DstIP:         "2001:db8::2",
		SrcPort:       1000,
		DstPort:       80,
		IngressZoneID: 1,
		EgressZoneID:  2,
	}
	for _, tc := range []struct {
		origin string
		want   bool
	}{
		{origin: "sync_import", want: true},
		{origin: "shared_materialize", want: true},
		{origin: "worker_local_import", want: false},
		{origin: "forward_flow", want: false},
		{origin: "", want: false},
	} {
		t.Run(tc.origin, func(t *testing.T) {
			delta := base
			delta.Origin = tc.origin
			_, val, ok := userspaceSessionFromDeltaV6(delta, nil)
			if !ok {
				t.Fatal("delta conversion rejected a complete IPv6 fixture")
			}
			got := val.Flags&dataplane.SessFlagClusterSynced != 0
			if got != tc.want {
				t.Fatalf("origin %q converted to cluster-synced=%v, want %v (flags=%#x)", tc.origin, got, tc.want, val.Flags)
			}
		})
	}
}
