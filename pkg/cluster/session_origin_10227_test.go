package cluster

import (
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

func TestSessionOriginFlagsCrossSessionWire10227(t *testing.T) {
	v4Key := dataplane.SessionKey{Protocol: 6, SrcPort: 1000, DstPort: 80}
	v4 := dataplane.SessionValue{Flags: dataplane.SessFlagClusterSynced}
	_, got4, ok := decodeSessionV4Payload(encodeSessionV4Payload(v4Key, v4))
	if !ok {
		t.Fatal("v4 origin payload did not decode")
	}
	if got4.Flags&dataplane.SessFlagClusterSynced == 0 {
		t.Fatalf("v4 decoded flags=%#x, origin bit was lost", got4.Flags)
	}

	v6Key := dataplane.SessionKeyV6{Protocol: 6, SrcPort: 1000, DstPort: 80}
	v6 := dataplane.SessionValueV6{Flags: dataplane.SessFlagClusterSynced}
	_, got6, ok := decodeSessionV6Payload(encodeSessionV6Payload(v6Key, v6))
	if !ok {
		t.Fatal("v6 origin payload did not decode")
	}
	if got6.Flags&dataplane.SessFlagClusterSynced == 0 {
		t.Fatalf("v6 decoded flags=%#x, origin bit was lost", got6.Flags)
	}
}

func TestLegacySessionOriginDefaultsClear10227(t *testing.T) {
	v4Key := dataplane.SessionKey{Protocol: 6, SrcPort: 1000, DstPort: 80}
	v4Payload := encodeSessionV4Payload(v4Key, dataplane.SessionValue{Flags: dataplane.SessFlagClusterSynced})
	_, got4, ok := decodeSessionV4Payload(v4Payload[:len(v4Payload)-1])
	if !ok {
		t.Fatal("legacy v4 payload did not decode")
	}
	if got4.Flags&dataplane.SessFlagClusterSynced != 0 {
		t.Fatalf("legacy v4 decoded flags=%#x, want origin clear", got4.Flags)
	}

	v6Key := dataplane.SessionKeyV6{Protocol: 6, SrcPort: 1000, DstPort: 80}
	v6Payload := encodeSessionV6Payload(v6Key, dataplane.SessionValueV6{Flags: dataplane.SessFlagClusterSynced})
	_, got6, ok := decodeSessionV6Payload(v6Payload[:len(v6Payload)-1])
	if !ok {
		t.Fatal("legacy v6 payload did not decode")
	}
	if got6.Flags&dataplane.SessFlagClusterSynced != 0 {
		t.Fatalf("legacy v6 decoded flags=%#x, want origin clear", got6.Flags)
	}
}

func TestPartialInstallTableTailDoesNotBecomeOriginFlags10227(t *testing.T) {
	v4Key := dataplane.SessionKey{Protocol: 6, SrcPort: 1000, DstPort: 80}
	v4Payload := encodeSessionV4Payload(v4Key, dataplane.SessionValue{
		Flags:              dataplane.SessFlagClusterSynced,
		InstallTableDomain: 2,
	})
	_, got4, ok := decodeSessionV4Payload(v4Payload[:len(v4Payload)-2])
	if !ok {
		t.Fatal("partial v4 payload did not decode")
	}
	if got4.Flags&dataplane.SessFlagClusterSynced != 0 {
		t.Fatalf("partial v4 decoded flags=%#x, want origin clear", got4.Flags)
	}

	v6Key := dataplane.SessionKeyV6{Protocol: 6, SrcPort: 1000, DstPort: 80}
	v6Payload := encodeSessionV6Payload(v6Key, dataplane.SessionValueV6{
		InstallTableDomain: 2,
		Flags:              dataplane.SessFlagClusterSynced,
	})
	_, got6, ok := decodeSessionV6Payload(v6Payload[:len(v6Payload)-2])
	if !ok {
		t.Fatal("partial v6 payload did not decode")
	}
	if got6.Flags&dataplane.SessFlagClusterSynced != 0 {
		t.Fatalf("partial v6 decoded flags=%#x, want origin clear", got6.Flags)
	}
}
