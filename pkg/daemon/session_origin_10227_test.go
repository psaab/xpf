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

func TestSessionDeltaConversionCarriesSourceNatProvenance12187(t *testing.T) {
	cases := []struct {
		name       string
		provenance uint8
		want       uint8
	}{
		{name: "legacy unknown", provenance: dataplane.SourceNatProvenanceUnknown, want: dataplane.SourceNatProvenanceUnknown},
		{name: "dynamic", provenance: dataplane.SourceNatProvenanceDynamic, want: dataplane.SourceNatProvenanceDynamic},
		{name: "static", provenance: dataplane.SourceNatProvenanceStatic, want: dataplane.SourceNatProvenanceStatic},
	}
	for _, family := range []struct {
		name    string
		addrFam uint8
		srcIP   string
		dstIP   string
		natSrc  string
	}{
		{name: "v4", addrFam: dataplane.AFInet, srcIP: "10.0.0.1", dstIP: "10.0.0.2", natSrc: "203.0.113.10"},
		{name: "v6", addrFam: dataplane.AFInet6, srcIP: "2001:db8::1", dstIP: "2001:db8::2", natSrc: "2001:db8::10"},
	} {
		t.Run(family.name, func(t *testing.T) {
			base := dpuserspace.SessionDeltaInfo{
				AddrFamily:    family.addrFam,
				Protocol:      6,
				SrcIP:         family.srcIP,
				DstIP:         family.dstIP,
				SrcPort:       1000,
				DstPort:       80,
				IngressZoneID: 1,
				EgressZoneID:  2,
				NATSrcIP:      family.natSrc,
				NATSrcPort:    40000,
			}
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					delta := base
					delta.SourceNatProvenance = tc.provenance
					delta.Origin = "sync_import"
					var flags uint16
					if family.addrFam == dataplane.AFInet {
						_, val, ok := userspaceSessionFromDeltaV4(delta, nil)
						if !ok {
							t.Fatal("IPv4 source-NAT delta conversion failed")
						}
						flags = val.Flags
					} else {
						_, val, ok := userspaceSessionFromDeltaV6(delta, nil)
						if !ok {
							t.Fatal("IPv6 source-NAT delta conversion failed")
						}
						flags = val.Flags
					}
					if got := dataplane.SourceNatProvenanceFromFlags(flags); got != tc.want {
						t.Fatalf("converted flags=%#x provenance=%d, want %d", flags, got, tc.want)
					}
					if flags&dataplane.SessFlagSNAT == 0 || flags&dataplane.SessFlagClusterSynced == 0 {
						t.Fatalf("conversion dropped SNAT/origin flags: %#x", flags)
					}
				})
			}
		})
	}
}
