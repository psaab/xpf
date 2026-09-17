package snmp

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #10017: GET of an unknown-class OID must return noSuchObject (0x80), while a
// missing instance of a known object returns noSuchInstance (0x81) — per RFC
// 3416 §4.2.1, on both v2c and v3. The shared lookup collapsed both absences
// into nil and both renderers emitted one tag (v2c's comment even said
// "noSuchObject" while the code emitted noSuchInstance).
//
// Each case below guards a distinct classification path, so a blind tag swap
// (fixing one class by breaking the other) fails exactly the opposite class:
//   - unknown enterprise / sys OIDs → noSuchObject (final lookup miss)
//   - scalar wrong-instance / bare base → noSuchInstance (known scalar base)
//   - table known-column unknown-index → noSuchInstance (iface miss)
//   - table unknown-column (with an ALSO-unknown index, so column/object
//     precedence over instance is exercised) → noSuchObject
type absenceCase10017 struct {
	name string
	oid  []int
	want byte
}

func absenceCases10017() []absenceCase10017 {
	ifDescrUnknownIdx := append(append([]int{}, oidIfTablePrefix...), 2, 9999)
	ifTableUnknownCol := append(append([]int{}, oidIfTablePrefix...), 99, 9999)
	ifXUnknownIdx := append(append([]int{}, oidIfXTablePrefix...), 1, 9999)
	ifXUnknownCol := append(append([]int{}, oidIfXTablePrefix...), 99, 9999)
	return []absenceCase10017{
		{"unknown enterprise OID", []int{1, 3, 6, 1, 4, 1, 99999, 42, 0}, tagNoSuchObject},
		{"unknown sys field", []int{1, 3, 6, 1, 2, 1, 1, 99, 0}, tagNoSuchObject},
		{"sysDescr wrong instance", []int{1, 3, 6, 1, 2, 1, 1, 1, 1}, tagNoSuchInstance},
		{"sysDescr bare base", []int{1, 3, 6, 1, 2, 1, 1, 1}, tagNoSuchInstance},
		{"ifTable known col unknown idx", ifDescrUnknownIdx, tagNoSuchInstance},
		{"ifTable unknown col", ifTableUnknownCol, tagNoSuchObject},
		{"ifXTable known col unknown idx", ifXUnknownIdx, tagNoSuchInstance},
		{"ifXTable unknown col", ifXUnknownCol, tagNoSuchObject},
	}
}

func absenceTagName10017(tag byte) string {
	switch tag {
	case tagNoSuchObject:
		return "noSuchObject"
	case tagNoSuchInstance:
		return "noSuchInstance"
	default:
		return "unknown"
	}
}

func TestV2cAbsenceTags_10017(t *testing.T) {
	a := NewAgent(&config.SNMPConfig{
		Communities: map[string]*config.SNMPCommunity{
			"public": {Name: "public", Authorization: "read-only"},
		},
	})
	a.SetIfDataFn(oneIfData)

	// Positive controls: served OIDs still return values, so a dead agent
	// cannot masquerade as correct exceptions.
	for _, pc := range []struct {
		name string
		oid  []int
		want byte
	}{
		{"sysDescr", oidSysDescr, tagOctetString},
		{"ifDescr.1", append(append([]int{}, oidIfTablePrefix...), 2, 1), tagOctetString},
	} {
		req := buildV2cGetRequest("public", 1, pc.oid)
		resp := a.handlePacket(req)
		if resp == nil {
			t.Fatalf("CONTROL v2c GET %s: nil response", pc.name)
		}
		_, vbList := v2cResponseVBList(t, resp)
		vbs := decodeVarbindsFull(t, vbList)
		if len(vbs) != 1 {
			t.Fatalf("CONTROL v2c GET %s: got %d varbinds, want 1", pc.name, len(vbs))
		}
		if vbs[0].valTag != pc.want {
			t.Fatalf("CONTROL v2c GET %s: valTag = 0x%02x, want 0x%02x", pc.name, vbs[0].valTag, pc.want)
		}
	}

	for i, tc := range absenceCases10017() {
		t.Run(tc.name, func(t *testing.T) {
			req := buildV2cGetRequest("public", 100+i, tc.oid)
			resp := a.handlePacket(req)
			if resp == nil {
				t.Fatalf("v2c GET %v: nil response", tc.oid)
			}
			errStatus, vbList := v2cResponseVBList(t, resp)
			if errStatus != errNoError {
				t.Fatalf("v2c GET %v: error-status = %d, want noError (exceptions are per-varbind)", tc.oid, errStatus)
			}
			vbs := decodeVarbindsFull(t, vbList)
			if len(vbs) != 1 {
				t.Fatalf("v2c GET %v: got %d varbinds, want 1", tc.oid, len(vbs))
			}
			if !oidsEqual(vbs[0].oid, tc.oid) {
				t.Fatalf("v2c GET %v: response OID = %v, want echo", tc.oid, vbs[0].oid)
			}
			if vbs[0].valTag != tc.want {
				t.Fatalf("v2c GET %v: exception = %s (0x%02x), want %s (0x%02x)",
					tc.oid, absenceTagName10017(vbs[0].valTag), vbs[0].valTag,
					absenceTagName10017(tc.want), tc.want)
			}
		})
	}
}

func TestV3AbsenceTags_DefaultContext_10017(t *testing.T) {
	a, engineID, authKey := newTimelinessAgent(t, 5, 1000)
	a.SetIfDataFn(oneIfData)

	// Positive control: sysDescr in the default context still returns a value.
	pkt := buildV3ContextRequest(t, "sha", "tuser", engineID, authKey, 5, 1000, nil, oidSysDescr)
	a.lastPacket = pkt
	resp := driveV3(t, a, pkt)
	if resp == nil {
		t.Fatal("CONTROL v3 GET sysDescr: nil response")
	}
	_, vbList := v3ResponseVBList(t, resp)
	vbs := decodeVarbindsFull(t, vbList)
	if len(vbs) != 1 {
		t.Fatalf("CONTROL v3 GET sysDescr: got %d varbinds, want 1", len(vbs))
	}
	if vbs[0].valTag != tagOctetString {
		t.Fatalf("CONTROL v3 GET sysDescr: valTag = 0x%02x, want OctetString", vbs[0].valTag)
	}

	for i, tc := range absenceCases10017() {
		t.Run(tc.name, func(t *testing.T) {
			pkt := buildV3ContextRequest(t, "sha", "tuser", engineID, authKey, 5, 1000+i, nil, tc.oid)
			a.lastPacket = pkt
			resp := driveV3(t, a, pkt)
			if resp == nil {
				t.Fatalf("v3 GET %v: nil response", tc.oid)
			}
			errStatus, vbList := v3ResponseVBList(t, resp)
			if errStatus != errNoError {
				t.Fatalf("v3 GET %v: error-status = %d, want noError", tc.oid, errStatus)
			}
			vbs := decodeVarbindsFull(t, vbList)
			if len(vbs) != 1 {
				t.Fatalf("v3 GET %v: got %d varbinds, want 1", tc.oid, len(vbs))
			}
			if !oidsEqual(vbs[0].oid, tc.oid) {
				t.Fatalf("v3 GET %v: response OID = %v, want echo", tc.oid, vbs[0].oid)
			}
			if vbs[0].valTag != tc.want {
				t.Fatalf("v3 GET %v: exception = %s (0x%02x), want %s (0x%02x)",
					tc.oid, absenceTagName10017(vbs[0].valTag), vbs[0].valTag,
					absenceTagName10017(tc.want), tc.want)
			}
		})
	}
}

// TestV3NonDefaultContextUnknownObject_10017: in a non-default context the MIB
// view is empty, so an unknown-class OID is still rendered as noSuchObject
// rather than noSuchInstance. Known objects use noSuchInstance for a missing
// instance, and no default-context data is ever returned.
func TestV3NonDefaultContextUnknownObject_10017(t *testing.T) {
	a, engineID, authKey := newTimelinessAgent(t, 5, 1000)
	ctx := []byte("vrf-red")
	unknown := []int{1, 3, 6, 1, 4, 1, 99999, 42, 0}
	pkt := buildV3ContextRequest(t, "sha", "tuser", engineID, authKey, 5, 1000, ctx, unknown)
	a.lastPacket = pkt

	resp := driveV3(t, a, pkt)
	if resp == nil {
		t.Fatal("non-default-context GET unknown OID: nil response (should be empty-view, not dropped)")
	}
	errStatus, vbList := v3ResponseVBList(t, resp)
	if errStatus != errNoError {
		t.Fatalf("non-default-context GET unknown OID: error-status = %d, want noError", errStatus)
	}
	vbs := decodeVarbindsFull(t, vbList)
	if len(vbs) != 1 {
		t.Fatalf("non-default-context GET unknown OID: got %d varbinds, want 1", len(vbs))
	}
	if vbs[0].valTag != tagNoSuchObject {
		t.Fatalf("non-default-context GET unknown OID: exception = %s (0x%02x), want noSuchObject (0x80)",
			absenceTagName10017(vbs[0].valTag), vbs[0].valTag)
	}
	if got := scopedContextName(t, resp); string(got) != string(ctx) {
		t.Fatalf("non-default-context GET unknown OID: contextName = %q, want %q", got, ctx)
	}
}
