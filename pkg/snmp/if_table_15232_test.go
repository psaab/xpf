package snmp

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// Counter32 and ifLastChange columns. Pre-fix ifTableColumns is
// {1,2,3,4,5,7,8,10,16} and IfData carries no such fields, so every
// GET below returns nil (noSuchObject) and the walk skips the columns.

func ifTableOID15232(col, idx int) []int {
	return append(append([]int{}, oidIfTablePrefix...), col, idx)
}

func TestIfTableServesErrorDiscardUcastLastChange15232(t *testing.T) {
	a := NewAgent(&config.SNMPConfig{})
	a.SetIfDataFn(func() []IfData {
		return []IfData{{
			IfIndex: 7, IfDescr: "ge-0-0-0", IfType: 6, IfMtu: 1500,
			AdminStatus: 1, OperStatus: 1,
			InUcastPkts: 111, InNonUcastPkts: 22,
			InErrors: 3, InDiscards: 4, InUnknownProtos: 5,
			OutUcastPkts: 222, OutNonUcastPkts: 33,
			OutErrors: 6, OutDiscards: 7,
			LastChange: 12345,
		}}
	})
	cases := []struct {
		col  int
		want uint32
		tag  byte
		name string
	}{
		{9, 12345, tagTimeTicks, "ifLastChange"},
		{11, 111, tagCounter32, "ifInUcastPkts"},
		{12, 22, tagCounter32, "ifInNUcastPkts"},
		{13, 3, tagCounter32, "ifInErrors"},
		{14, 4, tagCounter32, "ifInDiscards"},
		{15, 5, tagCounter32, "ifInUnknownProtos"},
		{17, 222, tagCounter32, "ifOutUcastPkts"},
		{18, 33, tagCounter32, "ifOutNUcastPkts"},
		{19, 6, tagCounter32, "ifOutErrors"},
		{20, 7, tagCounter32, "ifOutDiscards"},
	}
	for _, tc := range cases {
		val, tag := a.getOIDValue(ifTableOID15232(tc.col, 7))
		if val == nil {
			t.Errorf("%s (col %d): no value served", tc.name, tc.col)
			continue
		}
		if tag != tc.tag {
			t.Errorf("%s: tag=0x%02x want 0x%02x", tc.name, tag, tc.tag)
		}
		// Decode unsigned application value (Counter32/TimeTicks content).
		var got uint32
		for _, b := range val {
			got = got<<8 | uint32(b)
		}
		if got != tc.want {
			t.Errorf("%s: decoded=%d want %d (raw %v)", tc.name, got, tc.want, val)
		}
	}
	// Existing columns unchanged (control).
	val, tag := a.getOIDValue(ifTableOID15232(2, 7))
	if tag != tagOctetString || string(val) != "ge-0-0-0" {
		t.Errorf("ifDescr control: %q tag 0x%02x", val, tag)
	}
	// Walk order stays sorted and includes the new columns.
	prev := ifTableOID15232(8, 7)
	next := a.findNextOID(prev)
	if !oidEqual(next, ifTableOID15232(9, 7)) {
		t.Errorf("GETNEXT after ifOperStatus.7 = %v, want ifLastChange.7 %v", next, ifTableOID15232(9, 7))
	}
	// Full walk must be strictly increasing.
	cur := []int{1, 3, 6, 1, 2, 1, 2, 2, 1}
	for range 200 {
		nxt := a.findNextOID(cur)
		if nxt == nil {
			break
		}
		if oidCompare(nxt, cur) <= 0 {
			t.Fatalf("walk not strictly increasing at %v -> %v", cur, nxt)
		}
		cur = nxt
	}
}
