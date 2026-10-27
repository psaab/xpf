// Copyright 2026 PSAAB. All rights reserved. This file is part of
// XPF. It is subject to the license terms in the LICENSE file found
// in the top-level directory of this distribution.

package snmp

import (
	"bytes"
	"encoding/hex"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// #17055: byte-identical golden pins for every site re-pointed at the
// consolidated encodeVarbind / encodeVarbindList / encodePDU. The hex was
// captured from the pre-consolidation encoders (three loop copies plus the
// unrolled trap wraps) under deterministic seams — fixed trap entropy,
// a fixed engineTime, and a fixed v1 uptime — and verified unchanged after
// the consolidation (the v2c trap uptime is wall-clock-derived, so the v2c
// leg pins every byte except the TimeTicks value bytes, which are checked
// separately as a well-formed TimeTicks of the captured uptime).

func mustHex17055(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("golden hex: %v", err)
	}
	return b
}

func goldenAgent17055(t *testing.T) *Agent {
	t.Helper()
	oldRead := trapRandRead
	trapRandRead = func(p []byte) (int, error) {
		copy(p, []byte{0x11, 0x22, 0x33, 0x44})
		return len(p), nil
	}
	t.Cleanup(func() { trapRandRead = oldRead })
	saved := engineTimeNow
	engineTimeNow = func(a *Agent) int { return 1000 }
	t.Cleanup(func() { engineTimeNow = saved })
	return &Agent{
		cfg: &config.SNMPConfig{Communities: map[string]*config.SNMPCommunity{
			"public": {Name: "public", Authorization: "read-only"},
		}},
		startTime:   time.Now().Add(-10000 * time.Millisecond),
		engineID:    []byte{0x80, 0x00, 0x1f, 0x88, 0x80, 0x17, 0x05, 0x05},
		engineBoots: 1,
		v3Users:     map[string]*usmUser{},
	}
}

func TestTrapGoldenBytesUnchanged17055(t *testing.T) {
	a := goldenAgent17055(t)

	// SNMPv1 trap: fully deterministic (fixed uptime parameter).
	wantV1 := mustHex17055(t, "307202010004067075626c6963a46506082b06010603010105400400000000020102020100430203e83049300f060a2b060102010202010105020105300f060a2b060102010202010705020101300f060a2b0601020102020108050201023014060a2b0601020102020102050406747275737430")
	if got := a.buildLinkTrapV1WithUptime("public", "", false, 5, "trust0", 1000, true); !bytes.Equal(got, wantV1) {
		t.Fatalf("v1 trap bytes changed:\n got %x\nwant %x", got, wantV1)
	}

	// SNMPv2c trap: deterministic except the sysUpTime TimeTicks value,
	// which derives from wall-clock time since startTime (~1000 hundredths
	// here). Pin the prefix up to the TimeTicks value and the suffix after
	// it; assert the value itself is the 3-byte TimeTicks 0x03e8 ± a few
	// hundredths of execution jitter by re-encoding the captured uptime
	// window [990, 1010].
	got := a.buildLinkTrap("public", false, 5, "trust0", true)
	prefix := mustHex17055(t, "30818e02010104067075626c6963a781800204112233440201000201003072300e06082b0601020101030043")
	suffix := mustHex17055(t, "3017060a2b06010603010104010006092b0601060301010503300f060a2b060102010202010105020105300f060a2b060102010202010705020101300f060a2b0601020102020108050201023014060a2b0601020102020102050406747275737430")
	if !bytes.HasPrefix(got, prefix) {
		t.Fatalf("v2c trap prefix changed:\n got %x\nwant prefix %x", got, prefix)
	}
	rest := got[len(prefix):]
	if len(rest) < 1 {
		t.Fatal("v2c trap truncated after TimeTicks header")
	}
	ticksLen := int(rest[0])
	ticks := rest[1 : 1+ticksLen]
	found := false
	for up := 990; up <= 1010; up++ {
		if bytes.Equal(ticks, berEncodeTimeTicks(up)) {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("v2c trap TimeTicks value %x not in captured uptime window", ticks)
	}
	if !bytes.Equal(rest[1+ticksLen:], suffix) {
		t.Fatalf("v2c trap suffix changed:\n got %x\nwant %x", rest[1+ticksLen:], suffix)
	}
}

func TestResponseGoldenBytesUnchanged17055(t *testing.T) {
	a := goldenAgent17055(t)

	wantV2 := mustHex17055(t, "303702010104067075626c6963a22a02012a020100020100301f300f06082b060102010101000403787066300c06082b060102010105008100")
	gotV2 := a.buildResponse([]byte("public"), 42, errNoError, 0, []varbind{
		{oid: oidSysDescr, tag: tagOctetString, value: []byte("xpf")},
		{oid: oidSysName, tag: tagNoSuchInstance},
	})
	if !bytes.Equal(gotV2, wantV2) {
		t.Fatalf("v2c response bytes changed:\n got %x\nwant %x", gotV2, wantV2)
	}

	wantV3 := mustHex17055(t, "305f020103300d02010702021000040100020103041f301d040880001f8880170505020101020203e804066e6f626f647904000400302a040880001f88801705050400a21c02012a0201000201003011300f06082b060102010101000403787066")
	gotV3 := a.buildV3Response(7, 0, &usmUser{name: "nobody"}, nil, 42, errNoError, 0, []varbind{
		{oid: oidSysDescr, tag: tagOctetString, value: []byte("xpf")},
	})
	if !bytes.Equal(gotV3, wantV3) {
		t.Fatalf("v3 response bytes changed:\n got %x\nwant %x", gotV3, wantV3)
	}

	wantDisc := mustHex17055(t, "3059020103300d0201070202100004010002010304193017040880001f8880170505020101020203e8040004000400302a040880001f88801705050400a81c0201000201000201003011300f060a2b060106030f01010400410100")
	if got := a.buildV3Discovery(7); !bytes.Equal(got, wantDisc) {
		t.Fatalf("v3 discovery bytes changed:\n got %x\nwant %x", got, wantDisc)
	}

	wantReport := mustHex17055(t, "a81c0201000201000201003011300f060a2b060106030f01010200410100")
	if got := a.buildReportPDU(usmStatsNotInTimeWindows); !bytes.Equal(got, wantReport) {
		t.Fatalf("report PDU bytes changed:\n got %x\nwant %x", got, wantReport)
	}
}

// TestEncodeVarbindExceptionNil17055 pins the defensive exception-tag nil:
// an exception varbind carrying a stray value still encodes the value as
// the empty exception TLV, exactly as the three pre-consolidation copies did.
func TestEncodeVarbindExceptionNil17055(t *testing.T) {
	for _, tag := range []byte{tagNoSuchObject, tagNoSuchInstance, tagEndOfMibView} {
		got := encodeVarbind(nil, varbind{oid: oidSysName, tag: tag, value: []byte("stray")})
		want := encodeVarbind(nil, varbind{oid: oidSysName, tag: tag})
		if !bytes.Equal(got, want) {
			t.Fatalf("tag 0x%02x: stray value leaked into exception varbind: %x vs %x", tag, got, want)
		}
		if n := varbindEncodedLen(varbind{oid: oidSysName, tag: tag, value: []byte("stray")}); n != len(want) {
			t.Fatalf("tag 0x%02x: varbindEncodedLen = %d, encoder emitted %d", tag, n, len(want))
		}
	}
}
