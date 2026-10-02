package cluster

import (
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

func TestALGSyncUsesDirectionAwareServicePort11672(t *testing.T) {
	for _, tc := range []struct {
		name     string
		protocol uint8
		src      uint16
		dst      uint16
		reverse  uint8
		alg      uint8
		want     uint8
	}{
		{name: "forward DNS client source port is untagged", protocol: 17, src: 53, dst: 9999, alg: 3},
		{name: "forward FTP client source port is untagged", protocol: 6, src: 21, dst: 9999, alg: 1},
		{name: "forward UDP SIP client source port is untagged", protocol: 17, src: 5060, dst: 9999, alg: 2},
		{name: "forward TCP SIP client source port is untagged", protocol: 6, src: 5060, dst: 9999, alg: 2},
		{name: "forward DNS destination service port remains tagged", protocol: 17, src: 40000, dst: 53, alg: 3, want: 3},
		{name: "forward FTP destination service port remains tagged", protocol: 6, src: 40000, dst: 21, alg: 1, want: 1},
		{name: "forward UDP SIP destination service port remains tagged", protocol: 17, src: 40000, dst: 5060, alg: 2, want: 2},
		{name: "forward TCP SIP destination service port remains tagged", protocol: 6, src: 40000, dst: 5060, alg: 2, want: 2},
		{name: "reverse DNS source service port remains tagged", protocol: 17, src: 53, dst: 40000, reverse: 1, alg: 3, want: 3},
		{name: "reverse FTP source service port remains tagged", protocol: 6, src: 21, dst: 40000, reverse: 1, alg: 1, want: 1},
		{name: "reverse UDP SIP source service port remains tagged", protocol: 17, src: 5060, dst: 40000, reverse: 1, alg: 2, want: 2},
		{name: "reverse TCP SIP source service port remains tagged", protocol: 6, src: 5060, dst: 40000, reverse: 1, alg: 2, want: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key := dataplane.SessionKey{
				SrcIP: [4]byte{192, 0, 2, 1}, DstIP: [4]byte{198, 51, 100, 2},
				SrcPort: tc.src, DstPort: tc.dst, Protocol: tc.protocol,
			}
			val := dataplane.SessionValue{
				State: dataplane.SessStateEstablished, IsReverse: tc.reverse, ALGType: tc.alg,
			}
			gotKey, gotVal, ok := decodeSessionV4Payload(encodeSessionV4Payload(key, val))
			if !ok {
				t.Fatal("v4 session failed to decode")
			}
			if gotKey != key || gotVal.ALGType != tc.want {
				t.Fatalf("v4 sync tuple=(%d -> %d, protocol=%d, reverse=%d) ALGType=%d, want %d",
					gotKey.SrcPort, gotKey.DstPort, gotKey.Protocol, gotVal.IsReverse, gotVal.ALGType, tc.want)
			}
			// Model standby re-publication: the decoded value must survive the
			// next HA encode/decode without restoring a source-port-only tag.
			_, republished, ok := decodeSessionV4Payload(encodeSessionV4Payload(gotKey, gotVal))
			if !ok || republished.ALGType != tc.want {
				t.Fatalf("v4 HA re-publish ALGType=%d ok=%v, want %d", republished.ALGType, ok, tc.want)
			}

			key6 := dataplane.SessionKeyV6{
				SrcIP:   [16]byte{0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
				DstIP:   [16]byte{0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2},
				SrcPort: tc.src, DstPort: tc.dst, Protocol: tc.protocol,
			}
			val6 := dataplane.SessionValueV6{
				State: dataplane.SessStateEstablished, IsReverse: tc.reverse, ALGType: tc.alg,
			}
			gotKey6, gotVal6, ok := decodeSessionV6Payload(encodeSessionV6Payload(key6, val6))
			if !ok || gotKey6 != key6 || gotVal6.ALGType != tc.want {
				t.Fatalf("v6 sync tuple=(%d -> %d, protocol=%d, reverse=%d) ALGType=%d ok=%v, want %d",
					gotKey6.SrcPort, gotKey6.DstPort, gotKey6.Protocol, gotVal6.IsReverse, gotVal6.ALGType, ok, tc.want)
			}
			_, republished6, ok := decodeSessionV6Payload(encodeSessionV6Payload(gotKey6, gotVal6))
			if !ok || republished6.ALGType != tc.want {
				t.Fatalf("v6 HA re-publish ALGType=%d ok=%v, want %d", republished6.ALGType, ok, tc.want)
			}
		})
	}
}
