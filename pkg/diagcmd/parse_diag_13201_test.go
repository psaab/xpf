// #13201 D10-05 regression: strict parser in shared diagcmd must reject
// unknown/duplicate/missing/delimiter values (RED pre-fix: symbols missing).
package diagcmd

import "testing"

func TestParsePingTracerouteStrict13201(t *testing.T) {
	if _, err := ParsePingOptions([]string{"192.0.2.1", "sourcce", "10.0.0.1"}); err == nil {
		t.Fatal("want unknown-option error")
	}
	if _, err := ParsePingOptions([]string{"192.0.2.1", "count"}); err == nil {
		t.Fatal("want missing-value error")
	}
	if _, err := ParsePingOptions([]string{"192.0.2.1", "count", "abc"}); err == nil {
		t.Fatal("want invalid count error")
	}
	if _, err := ParsePingOptions([]string{"192.0.2.1", "source", "a", "source", "b"}); err == nil {
		t.Fatal("want duplicate error")
	}
	p, err := ParsePingOptions([]string{"192.0.2.1", "count", "3", "source", "10.0.0.1", "size", "64", "routing-instance", "vr1"})
	if err != nil || p.Count != 3 || p.Size != 64 || p.Source != "10.0.0.1" || p.RoutingInstance != "vr1" || p.Target != "192.0.2.1" {
		t.Fatalf("valid ping: %+v err=%v", p, err)
	}
	if _, err := ParseTracerouteOptions([]string{"192.0.2.1", "routing-instance"}); err == nil {
		t.Fatal("want missing routing-instance error")
	}
	if _, err := ParseTracerouteOptions([]string{"192.0.2.1", "source", "a", "source", "b"}); err == nil {
		t.Fatal("want duplicate source error")
	}
	tr, err := ParseTracerouteOptions([]string{"192.0.2.1", "source", "10.0.0.1"})
	if err != nil || tr.Source != "10.0.0.1" {
		t.Fatalf("valid traceroute: %+v err=%v", tr, err)
	}
}

func TestParseTestInterfaceStrict13201(t *testing.T) {
	for _, a := range [][]string{
		{"interface", "ge-0/0/0,injected=1"},
		{"interface", "a", "bogus"},
		{"interface"},
		{"interface", "a", "interface", "b"},
		{"bogus", "a"},
		{"interface", ""},
	} {
		if _, _, err := ParseTestInterface(a); err == nil {
			t.Fatalf("ParseTestInterface(%v) want error", a)
		}
	}
	v, present, err := ParseTestInterface([]string{"interface", "ge-0/0/0.0"})
	if err != nil || !present || v != "ge-0/0/0.0" {
		t.Fatalf("valid: %q %v %v", v, present, err)
	}
	if _, present, err := ParseTestInterface(nil); err != nil || present {
		t.Fatalf("empty: present=%v err=%v want usage path", present, err)
	}
}
