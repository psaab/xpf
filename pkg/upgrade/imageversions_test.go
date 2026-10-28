package upgrade

import "testing"

const sampleProtoVersions = `xpf-version=1.2.3
ha-protocol-version=2
ha-protocol-min-compat=1
session-sync-protocol-version=3
configdb-envelope-version=1
configdb-min-reader-version=1
`

const sampleManifest = `version: 1.2.3
git_commit: abcdef
base_release: 26.04
ha_protocol_version: 2
ha_protocol_min_compat: 1
session_sync_protocol_version: 3
configdb_envelope_version: 1
configdb_min_reader_version: 1
`

func TestParseImageVersions_BothSeparators(t *testing.T) {
	for name, txt := range map[string]string{"equals": sampleProtoVersions, "colon": sampleManifest} {
		iv, err := parseImageVersions(txt)
		if err != nil {
			t.Fatalf("%s: parse: %v", name, err)
		}
		if iv.HAProtocol != 2 || iv.HAProtocolMinCompat != 1 || iv.SessionSyncProtocol != 3 {
			t.Fatalf("%s: parsed %+v", name, iv)
		}
		for _, k := range requiredKeys {
			if !iv.has(k) {
				t.Fatalf("%s: missing required key %q", name, k)
			}
		}
	}
}

// The gate vector table lives in the shared cross-language fixture
// (scripts/deploy/mixed_base_gate_fixture.json, #17091) — see
// TestMixedBaseGateFixture17091. The cells below keep the parse-level
// parity pins that a uint16-typed Go fixture row cannot express.

func TestGateProtocolCompat_PeerInWindow_Survives(t *testing.T) {
	iv, _ := parseImageVersions(sampleProtoVersions) // speaks 2, floor 1, sync 3
	v := GateProtocolCompat(iv, 1, 3, RefuseUnknownWire)
	if v.Err != nil || !v.Compatible {
		t.Fatalf("peer HA 1 in window [1,2] + sync match must survive: err=%v %s", v.Err, v.Reason)
	}
	if v2 := GateProtocolCompat(iv, 2, 3, RefuseUnknownWire); v2.Err != nil || !v2.Compatible {
		t.Fatalf("same-version peer must survive: err=%v %s", v2.Err, v2.Reason)
	}
}

// TestParseImageVersions_NegativeSessionSync_FailsClosed locks the r4 Codex
// HIGH Go/Python parity fix: a negative (or out-of-uint16-range)
// session-sync-protocol-version must be REJECTED at parse (not stored), so the
// required key is absent and the gate fails closed — matching the Python
// _u16() rejection. A signed strconv.Atoi would have stored -1 and let a peer
// also reporting -1 falsely pass the exact-match.
func TestParseImageVersions_NegativeSessionSync_FailsClosed(t *testing.T) {
	const txt = `ha-protocol-version=2
ha-protocol-min-compat=1
session-sync-protocol-version=-1
`
	iv, err := parseImageVersions(txt)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if iv.has("session-sync-protocol-version") {
		t.Fatal("negative session-sync must be rejected at parse (key absent)")
	}
	// The gate must fail closed on the absent required key (as a target
	// error), never judge the pair compatible.
	if v := GateProtocolCompat(iv, 1, 3, RefuseUnknownWire); v.Err == nil || v.Compatible {
		t.Fatalf("missing required key must fail closed as error: %+v", v)
	}
	// Out-of-uint16-range is likewise rejected.
	iv2, _ := parseImageVersions("ha-protocol-version=2\nha-protocol-min-compat=1\nsession-sync-protocol-version=70000\n")
	if iv2.has("session-sync-protocol-version") {
		t.Fatal("out-of-uint16-range session-sync must be rejected at parse")
	}
}

func TestGateProtocolCompat_MissingFields_DropsClosed(t *testing.T) {
	iv, _ := parseImageVersions("xpf-version=1.2.3\n") // no protocol fields
	if v := GateProtocolCompat(iv, 1, 3, RefuseUnknownWire); v.Err == nil || v.Compatible {
		t.Fatalf("missing required protocol fields must fail closed: %+v", v)
	}
	if v := GateProtocolCompat(nil, 1, 3, RefuseUnknownWire); v.Err == nil || v.Compatible {
		t.Fatal("nil image versions must fail closed")
	}
}
