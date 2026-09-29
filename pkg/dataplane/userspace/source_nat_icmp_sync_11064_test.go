package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

func TestSourceNatICMPIdentityReachesHelperRequest11064(t *testing.T) {
	const (
		typ  = uint8(13)
		code = uint8(0)
	)
	m := New()
	v4 := dataplane.SessionValue{
		Flags: dataplane.SessFlagSNAT, SourceNatICMPValid: true,
		SourceNatICMPType: typ, SourceNatICMPCode: code,
	}
	req4 := m.buildSessionSyncRequestV4("upsert", dataplane.SessionKey{Protocol: 1}, &v4)
	assertSourceNatICMPRequest11064(t, req4.SourceNatICMPValid, req4.SourceNatICMPType, req4.SourceNatICMPCode, typ, code)

	v6 := dataplane.SessionValueV6{
		Flags: dataplane.SessFlagSNAT, SourceNatICMPValid: true,
		SourceNatICMPType: typ, SourceNatICMPCode: code,
	}
	req6 := m.buildSessionSyncRequestV6("upsert", dataplane.SessionKeyV6{Protocol: 1}, &v6)
	assertSourceNatICMPRequest11064(t, req6.SourceNatICMPValid, req6.SourceNatICMPType, req6.SourceNatICMPCode, typ, code)
}

func assertSourceNatICMPRequest11064(t *testing.T, gotValid bool, gotType, gotCode, wantType, wantCode uint8) {
	t.Helper()
	if !gotValid || gotType != wantType || gotCode != wantCode {
		t.Fatalf("request source_nat_icmp=(%t,%d,%d), want (true,%d,%d)", gotValid, gotType, gotCode, wantType, wantCode)
	}
}
