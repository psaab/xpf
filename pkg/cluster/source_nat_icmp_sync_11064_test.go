package cluster

import (
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

func TestSourceNatICMPIdentityCrossesClusterWire11064(t *testing.T) {
	for _, tc := range []struct {
		name  string
		valid bool
		typ   uint8
		code  uint8
	}{
		{name: "valid zero pair", valid: true, typ: 0, code: 0},
		{name: "typed source NAT", valid: true, typ: 13, code: 0},
	} {
		t.Run("v4/"+tc.name, func(t *testing.T) {
			key := dataplane.SessionKey{Protocol: 1}
			val := dataplane.SessionValue{
				SessionID: 77, SourceNatICMPValid: tc.valid,
				SourceNatICMPType: tc.typ, SourceNatICMPCode: tc.code,
			}
			payload := encodeSessionV4Payload(key, val)
			_, got, ok := decodeSessionV4Payload(payload)
			if !ok {
				t.Fatal("decodeSessionV4Payload rejected the encoded session")
			}
			assertSourceNatICMP11064(t, got.SourceNatICMPValid, got.SourceNatICMPType, got.SourceNatICMPCode, tc.valid, tc.typ, tc.code)

			// A peer before #11064 stops at the existing high-flags byte.
			_, legacy, ok := decodeSessionV4Payload(payload[:len(payload)-3])
			if !ok {
				t.Fatal("decodeSessionV4Payload rejected the legacy-length session")
			}
			assertSourceNatICMP11064(t, legacy.SourceNatICMPValid, legacy.SourceNatICMPType, legacy.SourceNatICMPCode, false, 0, 0)
		})

		t.Run("v6/"+tc.name, func(t *testing.T) {
			key := dataplane.SessionKeyV6{Protocol: 1}
			val := dataplane.SessionValueV6{
				SessionID: 77, SourceNatICMPValid: tc.valid,
				SourceNatICMPType: tc.typ, SourceNatICMPCode: tc.code,
			}
			payload := encodeSessionV6Payload(key, val)
			_, got, ok := decodeSessionV6Payload(payload)
			if !ok {
				t.Fatal("decodeSessionV6Payload rejected the encoded session")
			}
			assertSourceNatICMP11064(t, got.SourceNatICMPValid, got.SourceNatICMPType, got.SourceNatICMPCode, tc.valid, tc.typ, tc.code)

			_, legacy, ok := decodeSessionV6Payload(payload[:len(payload)-3])
			if !ok {
				t.Fatal("decodeSessionV6Payload rejected the legacy-length session")
			}
			assertSourceNatICMP11064(t, legacy.SourceNatICMPValid, legacy.SourceNatICMPType, legacy.SourceNatICMPCode, false, 0, 0)
		})
	}
}

func assertSourceNatICMP11064(t *testing.T, gotValid bool, gotType, gotCode uint8, wantValid bool, wantType, wantCode uint8) {
	t.Helper()
	if gotValid != wantValid || gotType != wantType || gotCode != wantCode {
		t.Fatalf("source_nat_icmp=(%t,%d,%d), want (%t,%d,%d)", gotValid, gotType, gotCode, wantValid, wantType, wantCode)
	}
}

func TestSourceNatICMPIdentitySurvivesMirrorResends11064(t *testing.T) {
	s := &SessionSync{}
	s.initGenState()

	key4 := dataplane.SessionKey{Protocol: 1}
	active4 := dataplane.SessionValue{
		SessionID: 77, SourceNatICMPValid: true, SourceNatICMPType: 13,
	}
	s.stampInstallGenV4(key4, &active4)
	mirror4 := dataplane.SessionValue{SessionID: 77}
	s.stampInstallGenV4(key4, &mirror4)
	assertSourceNatICMP11064(t, mirror4.SourceNatICMPValid, mirror4.SourceNatICMPType, mirror4.SourceNatICMPCode, true, 13, 0)
	reused4 := dataplane.SessionValue{SessionID: 78}
	s.stampInstallGenV4(key4, &reused4)
	assertSourceNatICMP11064(t, reused4.SourceNatICMPValid, reused4.SourceNatICMPType, reused4.SourceNatICMPCode, false, 0, 0)

	key6 := dataplane.SessionKeyV6{Protocol: 1}
	active6 := dataplane.SessionValueV6{
		SessionID: 88, SourceNatICMPValid: true, SourceNatICMPType: 13,
	}
	s.stampInstallGenV6(key6, &active6)
	mirror6 := dataplane.SessionValueV6{SessionID: 88}
	s.stampInstallGenV6(key6, &mirror6)
	assertSourceNatICMP11064(t, mirror6.SourceNatICMPValid, mirror6.SourceNatICMPType, mirror6.SourceNatICMPCode, true, 13, 0)
	reused6 := dataplane.SessionValueV6{SessionID: 89}
	s.stampInstallGenV6(key6, &reused6)
	assertSourceNatICMP11064(t, reused6.SourceNatICMPValid, reused6.SourceNatICMPType, reused6.SourceNatICMPCode, false, 0, 0)
}
