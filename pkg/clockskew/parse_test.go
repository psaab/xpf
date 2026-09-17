package clockskew

import (
	"testing"
)

// TestParseChronyTracking10025 pins the `chronyc tracking` reference sampler:
// synced-ness from Leap status/Stratum, and the exact signed system-minus-true
// offset from the "System time" line ("slow of" = behind = negative).
func TestParseChronyTracking10025(t *testing.T) {
	synced := `Reference ID    : 0A000001 (ntp1.example.net)
Stratum         : 3
Ref time (UTC)  : Thu Jul 10 12:34:56 2026
System time     : 0.000123456 seconds slow of NTP time
Last offset     : -0.000012345 seconds
RMS offset      : 0.000034567 seconds
Frequency       : 12.345 ppm slow
Root delay      : 0.001234 seconds
Root dispersion : 0.000567 seconds
Update interval : 64.2 seconds
Leap status     : Normal
`
	fast := `Reference ID    : 0A000002 (ntp2.example.net)
Stratum         : 2
Ref time (UTC)  : Thu Jul 10 12:34:56 2026
System time     : 5.123456789 seconds fast of NTP time
Leap status     : Normal
`
	unsync := `Reference ID    : 00000000 ()
Stratum         : 0
Ref time (UTC)  : Thu Jan 01 00:00:00 1970
System time     : 0.000000000 seconds fast of NTP time
Last offset     : +0.000000000 seconds
RMS offset      : 0.000000000 seconds
Frequency       : 10.000 ppm slow
Root delay      : 1.000000000 seconds
Root dispersion : 1.000000000 seconds
Update interval : 0.0 seconds
Leap status     : Not synchronised
`
	cases := []struct {
		name       string
		output     string
		wantOK     bool
		wantSynced bool
		wantHave   bool
		wantOffset float64
		why        string
	}{
		{"synced_millisecond_slow", synced, true, true, true, -0.000123456, "slow of NTP time = behind = negative"},
		{"synced_seconds_fast", fast, true, true, true, 5.123456789, "fast of NTP time = ahead = positive"},
		{"stratum_zero_unsync", unsync, true, false, false, 0, "the #10025 shape: no source, stratum 0, Not synchronised"},
		{"leap_alone_marks_unsync", "Leap status     : Not synchronised\n", true, false, false, 0, "unsync needs no other field"},
		{"stratum_alone_marks_unsync", "Stratum         : 0\n", true, false, false, 0, "stratum 0 is never synchronized"},
		{"unparseable_offset_keeps_sync", "Stratum         : 3\nLeap status     : Normal\nSystem time     : garbage\n", true, true, false, 0, "a mangled offset line must not fake an unsync"},
		{"empty_is_unknown", "", false, false, false, 0, "no fields at all: unknown, the monitor HOLDs"},
		{"unrelated_is_unknown", "chronyc: command not found\n", false, false, false, 0, "stderr passthrough must not parse as a state"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st, ok := ParseChronyTracking(tc.output)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v — %s", ok, tc.wantOK, tc.why)
			}
			if !ok {
				return
			}
			if !st.Known {
				t.Fatalf("Known = false on a parsed output — %s", tc.why)
			}
			if st.Synced != tc.wantSynced {
				t.Fatalf("Synced = %v, want %v — %s", st.Synced, tc.wantSynced, tc.why)
			}
			if st.HaveOffset != tc.wantHave {
				t.Fatalf("HaveOffset = %v, want %v — %s", st.HaveOffset, tc.wantHave, tc.why)
			}
			if tc.wantHave && st.OffsetSecs != tc.wantOffset {
				t.Fatalf("OffsetSecs = %v, want %v — %s", st.OffsetSecs, tc.wantOffset, tc.why)
			}
		})
	}
}

// TestParseTimedatectlSync10025 pins the fallback boolean sampler:
// `timedatectl show --property=NTPSynchronized --value` prints "yes"/"no".
func TestParseTimedatectlSync10025(t *testing.T) {
	cases := []struct {
		output     string
		wantSynced bool
		wantOK     bool
	}{
		{"yes\n", true, true},
		{"yes", true, true},
		{"no\n", false, true},
		{"no", false, true},
		{"", false, false},
		{"maybe", false, false},
	}
	for _, tc := range cases {
		synced, ok := ParseTimedatectlSync(tc.output)
		if synced != tc.wantSynced || ok != tc.wantOK {
			t.Errorf("output %q: synced=%v ok=%v, want synced=%v ok=%v",
				tc.output, synced, ok, tc.wantSynced, tc.wantOK)
		}
	}
}
