package diagcmd

import "testing"

// TestParsePingOptionsClampsBeforeNarrowing15235 is the A51-03
// regression: values that overflow int32 (4294967297 wraps to 1) must be
// clamped in ParsePingOptions before cmd/cli casts to int32, matching
// the local console which clamps to 100 / MaxPingSize.
func TestParsePingOptionsClampsBeforeNarrowing15235(t *testing.T) {
	p, err := ParsePingOptions([]string{"192.0.2.1", "count", "4294967297"})
	if err != nil {
		t.Fatalf("count overflow: %v", err)
	}
	if p.Count != MaxPingCount {
		t.Fatalf("Count = %d, want %d (pre-fix int32 cast gave 1)", p.Count, MaxPingCount)
	}
	if int32(p.Count) != 100 {
		t.Fatalf("int32(Count) = %d, want 100", int32(p.Count))
	}
	p, err = ParsePingOptions([]string{"192.0.2.1", "size", "4294967297"})
	if err != nil {
		t.Fatalf("size overflow: %v", err)
	}
	if p.Size != MaxPingSize || int32(p.Size) != MaxPingSize {
		t.Fatalf("Size = %d, want %d", p.Size, MaxPingSize)
	}
	for _, tc := range []struct {
		in   string
		want int
	}{
		{"3", 3}, {"100", 100}, {"500", 100}, {"0", DefaultPingCount}, {"-3", DefaultPingCount},
	} {
		p, err := ParsePingOptions([]string{"192.0.2.1", "count", tc.in})
		if err != nil || p.Count != tc.want {
			t.Fatalf("count %q = %d err=%v, want %d", tc.in, p.Count, err, tc.want)
		}
	}
	p, err = ParsePingOptions([]string{"192.0.2.1", "count", "99999999999999999999"})
	if err != nil || p.Count != MaxPingCount {
		t.Fatalf("huge count = %d err=%v, want %d", p.Count, err, MaxPingCount)
	}
	if _, err := ParsePingOptions([]string{"192.0.2.1", "count", "-99999999999999999999"}); err == nil {
		t.Fatal("negative overflow count accepted, want error")
	}
}
