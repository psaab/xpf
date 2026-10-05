package api

import (
	"encoding/binary"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/psaab/xpf/pkg/logging"
)

// paritySessionDP yields one forward IPv4 session that exercises every
// REST-vs-gRPC parity gap from #3419: a long-lived but recently-active
// session (H1 age-vs-idle), both SNAT and DNAT set (H2 twice-NAT), and a
// companion reverse entry carrying counters (H3 reverse-merge). It also
// supplies an ApplyResult so policy/zone names resolve (M6).
type paritySessionDP struct {
	*dataplane.Manager
	apply  *dataplane.ApplyResult
	fwdKey dataplane.SessionKey
	fwdVal dataplane.SessionValue
	revKey dataplane.SessionKey
	revVal dataplane.SessionValue
}

func (d *paritySessionDP) IsLoaded() bool { return true }

func (d *paritySessionDP) LastApplyResult() *dataplane.ApplyResult { return d.apply }

func (d *paritySessionDP) IterateSessions(fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	fn(d.fwdKey, d.fwdVal)
	return nil
}

func (d *paritySessionDP) IterateSessionsV6(func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	return nil
}

func (d *paritySessionDP) GetSessionV4(key dataplane.SessionKey) (dataplane.SessionValue, error) {
	if key == d.revKey {
		return d.revVal, nil
	}
	return dataplane.SessionValue{}, errors.New("not found")
}

func (d *paritySessionDP) GetSessionV6(dataplane.SessionKeyV6) (dataplane.SessionValueV6, error) {
	return dataplane.SessionValueV6{}, errors.New("not found")
}

// TestRESTSessionParityWithGRPC asserts the #3419 REST session contract:
//   - age_seconds is wall age (now-Created), idle_seconds is time since the
//     last packet (now-LastSeen) — NOT idle reported as age (H1).
//   - a session with BOTH SNAT and DNAT exposes both text parts and the
//     structured nat_src/nat_dst fields — the DNAT branch no longer
//     overwrites the SNAT branch (H2).
//   - the companion reverse entry's counters are merged into the forward
//     entry (H3).
//   - policy_name / ingress_zone_name / egress_zone_name / session_id /
//     ha_active are surfaced (M6).
//
// FAIL-ON-REVERT: reverting sessionEntryV4 to set Age from LastSeen flips
// the age/idle assertions; dropping the reverse-counter merge in the
// handler flips rev_packets; restoring the single-NAT-string overwrite
// flips the SNAT-present assertion; removing the enrichment maps flips the
// name assertions.
func TestRESTSessionParityWithGRPC(t *testing.T) {
	base := monotonicSeconds()
	created := uint64(1)
	if base > 1000 {
		created = base - 1000
	}
	lastSeen := uint64(1)
	if base > 2 {
		lastSeen = base - 2
	}
	dp := &paritySessionDP{
		Manager: dataplane.New(),
		apply: &dataplane.ApplyResult{
			ZoneIDs:     map[string]uint16{"trust": 2, "untrust": 3},
			PolicyNames: map[uint32]string{5: "allow-web"},
		},
		fwdKey: dataplane.SessionKey{
			SrcIP:    [4]byte{10, 0, 1, 5},
			DstIP:    [4]byte{10, 0, 2, 7},
			SrcPort:  ntohs(12345),
			DstPort:  ntohs(443),
			Protocol: 6,
		},
		revKey: dataplane.SessionKey{
			SrcIP:    [4]byte{10, 0, 2, 7},
			DstIP:    [4]byte{10, 0, 1, 5},
			SrcPort:  ntohs(443),
			DstPort:  ntohs(12345),
			Protocol: 6,
		},
	}
	dp.fwdVal = dataplane.SessionValue{
		State:       dataplane.SessStateEstablished,
		IsReverse:   0,
		PolicyID:    5,
		IngressZone: 2,
		EgressZone:  3,
		FwdPackets:  10,
		FwdBytes:    1000,
		RevPackets:  0,
		RevBytes:    0,
		SessionID:   0xABCD,
		Created:     created,  // as old as boot permits on a fresh runner
		LastSeen:    lastSeen, // refreshed 2s ago when boot uptime permits
		Flags:       dataplane.SessFlagSNAT | dataplane.SessFlagDNAT,
		NATSrcIP:    natIPv4(192, 0, 2, 1),
		NATSrcPort:  ntohs(50000),
		NATDstIP:    natIPv4(198, 51, 100, 9),
		NATDstPort:  ntohs(8443),
		ReverseKey: dataplane.SessionKey{
			SrcIP:    [4]byte{10, 0, 2, 7},
			DstIP:    [4]byte{10, 0, 1, 5},
			SrcPort:  ntohs(443),
			DstPort:  ntohs(12345),
			Protocol: 6,
		},
	}
	dp.revVal = dataplane.SessionValue{
		IsReverse:  1,
		FwdPackets: 3,
		FwdBytes:   300,
		RevPackets: 7,
		RevBytes:   700,
	}

	s := &Server{
		dp:         dp,
		eventBuf:   logging.NewEventBuffer(8),
		haActiveFn: func() bool { return false },
	}

	rr := httptest.NewRecorder()
	s.sessionsHandler(rr, httptest.NewRequest("GET", "/api/v1/security/sessions", nil))
	if rr.Code != 200 {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	resp := decodeSessions(t, rr.Body.Bytes())
	if len(resp.Sessions) != 1 {
		t.Fatalf("got %d sessions, want 1", len(resp.Sessions))
	}
	se := resp.Sessions[0]

	// H1: age is wall age from Created (~1000s, or as old as this host's
	// monotonic clock permits on a fresh runner), while idle remains small.
	minAge := uint64(500)
	if base <= 500 {
		minAge = 0
		if base > 0 {
			minAge = base - 1
		}
	}
	if se.Age < int64(minAge) {
		t.Errorf("H1: age_seconds = %d, want >=%d (computed from Created)", se.Age, minAge)
	}
	if se.Idle <= 0 || se.Idle > 60 {
		t.Errorf("H1: idle_seconds = %d, want a small positive value (from LastSeen)", se.Idle)
	}
	if se.Age <= se.Idle {
		t.Errorf("H1: age (%d) must exceed idle (%d) for a long-lived active session", se.Age, se.Idle)
	}

	// H2: both SNAT and DNAT surfaced; neither overwrites the other.
	if !strings.Contains(se.NAT, "SNAT") || !strings.Contains(se.NAT, "DNAT") {
		t.Errorf("H2: nat = %q, want both SNAT and DNAT parts", se.NAT)
	}
	if se.NATSrcAddr == "" || se.NATDstAddr == "" {
		t.Errorf("H2: structured nat fields lost: src=%q dst=%q", se.NATSrcAddr, se.NATDstAddr)
	}

	// H3: reverse entry's counters merged into the forward entry.
	if se.RevPackets != 7 {
		t.Errorf("H3: rev_packets = %d, want 7 (merged from reverse entry)", se.RevPackets)
	}
	if se.FwdPackets != 13 {
		t.Errorf("H3: fwd_packets = %d, want 13 (10 fwd + 3 from reverse entry)", se.FwdPackets)
	}

	// M6: names, session id, ha-active surfaced.
	if se.PolicyName != "allow-web" {
		t.Errorf("M6: policy_name = %q, want allow-web", se.PolicyName)
	}
	if se.IngressZoneName != "trust" || se.EgressZoneName != "untrust" {
		t.Errorf("M6: zone names = %q/%q, want trust/untrust", se.IngressZoneName, se.EgressZoneName)
	}
	if se.SessionID != 0xABCD {
		t.Errorf("M6: session_id = %#x, want 0xABCD", se.SessionID)
	}
	if se.HAActive != false {
		t.Errorf("M6: ha_active = %v, want false (haActiveFn wired)", se.HAActive)
	}
}

// TestRESTSessionFiltersFailClosed asserts the new #3419 filters
// (nat_only, application, interface, source_nat_pool) parse and that an
// unresolved source_nat_pool fails closed with HTTP 400 rather than
// silently matching every session.
func TestRESTSessionFiltersFailClosed(t *testing.T) {
	s := &Server{
		dp:       &oneSessionDP{Manager: dataplane.New()},
		eventBuf: logging.NewEventBuffer(8),
	}

	cases := []struct {
		name string
		url  string
		want int
	}{
		{"nat_only true", "/api/v1/security/sessions?nat_only=true", 200},
		{"nat_only bad", "/api/v1/security/sessions?nat_only=maybe", 400},
		{"application filter", "/api/v1/security/sessions?application=http", 200},
		{"interface filter", "/api/v1/security/sessions?interface=ge-0-0-0", 200},
		// No active config -> the pool cannot resolve -> fail closed.
		{"source_nat_pool unknown", "/api/v1/security/sessions?source_nat_pool=nope", 400},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			s.sessionsHandler(rr, httptest.NewRequest("GET", tc.url, nil))
			if rr.Code != tc.want {
				t.Errorf("status = %d, want %d; body=%s", rr.Code, tc.want, rr.Body.String())
			}
		})
	}
}

// natIPv4 builds the native-endian u32 the dataplane stores for an IPv4
// NAT address (octets read as u32::from_ne_bytes), matching uint32ToIP.
func natIPv4(a, b, c, d byte) uint32 {
	return binary.NativeEndian.Uint32([]byte{a, b, c, d})
}
