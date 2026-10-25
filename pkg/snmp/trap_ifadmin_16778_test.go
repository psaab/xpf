package snmp

import (
	"testing"
	"time"
)

// trapVB16778 is one decoded trap varbind: OID, value tag, and the decoded
// value (ival for INTEGER/TimeTicks, sval for OCTET STRING / OID rendering).
type trapVB16778 struct {
	oid  []int
	tag  byte
	ival int
	sval string
}

// decodeTrapVarbinds16778 decodes every varbind of a v1 or v2c link trap
// using the package's own BER decoder (#16778 acceptance harness).
func decodeTrapVarbinds16778(t *testing.T, pkt []byte, v1 bool) []trapVB16778 {
	t.Helper()
	_, body, err := berDecodeHeader(pkt)
	if err != nil {
		t.Fatalf("outer SEQUENCE: %v", err)
	}
	_, rest, err := berDecodeInteger(body)
	if err != nil {
		t.Fatalf("version: %v", err)
	}
	_, rest, err = berDecodeOctetString(rest)
	if err != nil {
		t.Fatalf("community: %v", err)
	}
	_, pduBody, err := berDecodeHeader(rest)
	if err != nil {
		t.Fatalf("PDU: %v", err)
	}
	b := pduBody
	if v1 {
		// enterprise, agent-addr, generic-trap, specific-trap, time-stamp.
		for i := range 5 {
			n := berEncodedLen(b)
			if n <= 0 || n > len(b) {
				t.Fatalf("v1 PDU field %d: bad encoded len %d", i, n)
			}
			b = b[n:]
		}
	} else {
		// request-id, error-status, error-index.
		for i := range 3 {
			_, nb, err := berDecodeInteger(b)
			if err != nil {
				t.Fatalf("v2c PDU integer %d: %v", i, err)
			}
			b = nb
		}
	}
	_, vbList, err := berDecodeHeader(b)
	if err != nil {
		t.Fatalf("varbind list: %v", err)
	}
	var out []trapVB16778
	for len(vbList) > 0 {
		_, vbBody, err := berDecodeHeader(vbList)
		if err != nil {
			t.Fatalf("varbind: %v", err)
		}
		n := berEncodedLen(vbList)
		if n <= 0 || n > len(vbList) {
			t.Fatalf("varbind encoded len %d", n)
		}
		vbList = vbList[n:]
		oid := extractVarbindOID(t, vbBody)
		valTLV := vbBody[berEncodedLen(vbBody):]
		vtag, vval, err := berDecodeHeader(valTLV)
		if err != nil {
			t.Fatalf("varbind value: %v", err)
		}
		vb := trapVB16778{oid: oid, tag: vtag}
		switch vtag {
		case tagInteger:
			v, _, err := berDecodeInteger(valTLV)
			if err != nil {
				t.Fatalf("integer value: %v", err)
			}
			vb.ival = v
		case tagOctetString:
			vb.sval = string(vval)
		case tagObjectIdentifier:
			decoded, err := berDecodeOID(vval)
			if err != nil {
				t.Fatalf("OID value: %v", err)
			}
			// Keep the decoded OID in ival-free form via sval for messages.
			vb.sval = oidString16778(decoded)
		case tagTimeTicks:
			if len(vval) > 0 {
				v := 0
				for _, c := range vval {
					v = v<<8 | int(c)
				}
				vb.ival = v
			}
		}
		out = append(out, vb)
	}
	return out
}

func oidString16778(oid []int) string {
	s := ""
	for i, n := range oid {
		if i > 0 {
			s += "."
		}
		s += itoa16778(n)
	}
	return s
}

func itoa16778(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

func oidWithIndex16778(base []int, idx int) []int {
	out := append([]int{}, base...)
	return append(out, idx)
}

// TestLinkTrapIfAdminStatus16778 is the #16778 acceptance cell. RFC 2863:
// linkDown/linkUp NOTIFICATION-TYPE OBJECTS { ifIndex, ifAdminStatus,
// ifOperStatus } — in that order. RFC 3416 §4.2.6 copies them, in order,
// after sysUpTime.0/snmpTrapOID.0 in v2c; ifDescr is only a trailing
// additional varbind. An admin-down (Flags&net.FlagUp clear) MUST encode
// ifAdminStatus=2 so a receiver can suppress the "ignore admin-down" page.
//
// RED pre-fix: varbind 4 (v2c) / varbind 2 (v1) is ifDescr, and no
// ifAdminStatus varbind exists at all, so every subtest below fails.
func TestLinkTrapIfAdminStatus16778(t *testing.T) {
	cases := []struct {
		name      string
		linkUp    bool
		adminUp   bool
		wantAdmin int
		wantOper  int
	}{
		{"admin-down linkDown", false, false, 2, 2},
		{"admin-up carrier-down linkDown", false, true, 1, 2},
		{"admin-up linkUp", true, true, 1, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name+"/v2c", func(t *testing.T) {
			a := &Agent{startTime: time.Now().Add(-10 * time.Second)}
			pkt := a.buildLinkTrap("public", tc.linkUp, 5, "ge-0-0-0", tc.adminUp)
			vbs := decodeTrapVarbinds16778(t, pkt, false)
			if len(vbs) != 6 {
				t.Fatalf("v2c varbind count = %d, want 6 (sysUpTime, snmpTrapOID, ifIndex, ifAdminStatus, ifOperStatus, ifDescr): %+v", len(vbs), vbs)
			}
			if !oidEqual(vbs[0].oid, oidSysUpTime) {
				t.Fatalf("v2c vb1 OID = %v, want sysUpTime.0 %v", vbs[0].oid, oidSysUpTime)
			}
			if !oidEqual(vbs[1].oid, oidSnmpTrapOID) {
				t.Fatalf("v2c vb2 OID = %v, want snmpTrapOID.0 %v", vbs[1].oid, oidSnmpTrapOID)
			}
			// OBJECTS clause order: columns 1, 7, 8.
			if !oidEqual(vbs[2].oid, oidWithIndex16778(oidIfIndex, 5)) || vbs[2].tag != tagInteger || vbs[2].ival != 5 {
				t.Fatalf("v2c vb3 = %+v, want ifIndex.5 INTEGER 5", vbs[2])
			}
			if !oidEqual(vbs[3].oid, oidWithIndex16778(oidIfAdminStatus, 5)) || vbs[3].tag != tagInteger || vbs[3].ival != tc.wantAdmin {
				t.Fatalf("v2c vb4 = %+v, want ifAdminStatus.5 INTEGER %d", vbs[3], tc.wantAdmin)
			}
			if !oidEqual(vbs[4].oid, oidWithIndex16778(oidIfOperStatus, 5)) || vbs[4].tag != tagInteger || vbs[4].ival != tc.wantOper {
				t.Fatalf("v2c vb5 = %+v, want ifOperStatus.5 INTEGER %d", vbs[4], tc.wantOper)
			}
			// ifDescr only as trailing additional varbind.
			if !oidEqual(vbs[5].oid, oidWithIndex16778(oidIfDescr, 5)) || vbs[5].tag != tagOctetString || vbs[5].sval != "ge-0-0-0" {
				t.Fatalf("v2c vb6 = %+v, want trailing ifDescr.5 OctetString %q", vbs[5], "ge-0-0-0")
			}
		})
		t.Run(tc.name+"/v1", func(t *testing.T) {
			a := &Agent{startTime: time.Now().Add(-10 * time.Second)}
			pkt := a.buildLinkTrapV1("public", "", tc.linkUp, 5, "ge-0-0-0", tc.adminUp)
			vbs := decodeTrapVarbinds16778(t, pkt, true)
			if len(vbs) != 4 {
				t.Fatalf("v1 varbind count = %d, want 4 (ifIndex, ifAdminStatus, ifOperStatus, ifDescr): %+v", len(vbs), vbs)
			}
			if !oidEqual(vbs[0].oid, oidWithIndex16778(oidIfIndex, 5)) || vbs[0].tag != tagInteger || vbs[0].ival != 5 {
				t.Fatalf("v1 vb1 = %+v, want ifIndex.5 INTEGER 5", vbs[0])
			}
			if !oidEqual(vbs[1].oid, oidWithIndex16778(oidIfAdminStatus, 5)) || vbs[1].tag != tagInteger || vbs[1].ival != tc.wantAdmin {
				t.Fatalf("v1 vb2 = %+v, want ifAdminStatus.5 INTEGER %d", vbs[1], tc.wantAdmin)
			}
			if !oidEqual(vbs[2].oid, oidWithIndex16778(oidIfOperStatus, 5)) || vbs[2].tag != tagInteger || vbs[2].ival != tc.wantOper {
				t.Fatalf("v1 vb3 = %+v, want ifOperStatus.5 INTEGER %d", vbs[2], tc.wantOper)
			}
			if !oidEqual(vbs[3].oid, oidWithIndex16778(oidIfDescr, 5)) || vbs[3].tag != tagOctetString || vbs[3].sval != "ge-0-0-0" {
				t.Fatalf("v1 vb4 = %+v, want trailing ifDescr.5 OctetString %q", vbs[3], "ge-0-0-0")
			}
		})
	}
}

// TestLinkTrapAdminStatusThreadsDeferredV1_16778 pins that the admin state
// captured at event time survives the deferred v1 trapJob (#9917) instead
// of being dropped between sendLinkTraps and the worker build.
func TestLinkTrapAdminStatusThreadsDeferredV1_16778(t *testing.T) {
	agent := v1TrapAgent9917("v1")
	agent.NotifyLinkDown(7, "ge-0/0/0", false)
	jobs := drainTrapQueue9917(agent)
	if len(jobs) != 1 {
		t.Fatalf("queued %d jobs, want 1", len(jobs))
	}
	if !jobs[0].deferredV1 {
		t.Fatal("v1 job is not deferred")
	}
	if jobs[0].adminUp {
		t.Fatal("deferred v1 job lost admin-down state (adminUp=true, want false)")
	}
	// And the worker-built packet carries ifAdminStatus=2 at vb2.
	pkt := agent.buildLinkTrapV1WithUptime(jobs[0].community, jobs[0].target, jobs[0].linkUp, jobs[0].ifindex, jobs[0].iface, jobs[0].uptime, jobs[0].adminUp)
	vbs := decodeTrapVarbinds16778(t, pkt, true)
	if len(vbs) < 2 || !oidEqual(vbs[1].oid, oidWithIndex16778(oidIfAdminStatus, 7)) || vbs[1].ival != 2 {
		t.Fatalf("worker-built v1 varbinds = %+v, want vb2 ifAdminStatus.7=2", vbs)
	}
}
