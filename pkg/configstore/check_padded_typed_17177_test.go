package configstore

import (
	"strings"
	"testing"
)

// #17177: the three traced live instances of "validator trims,
// consumer reads raw" must be rejected by the production commit gate
// (CheckText), with the one shared padding message, while the bare
// controls still commit. Before the central checkToken gate:
//   - a padded RDNSS address committed and was dropped by the RA sender;
//   - a padded device-map pci committed and never bound;
//   - a padded scheduler start-time committed and the scheduler stayed
//     inactive all day, so a scheduled deny was skipped.

func TestCheckTextPaddedRDNSSRejected17177(t *testing.T) {
	for _, addr := range []string{`" 2001:db8::53"`, `"2001:db8::53 "`, `" 2001:db8::53 "`} {
		text := `protocols { router-advertisement { interface ge-0-0-0 { dns-server-address ` + addr + `; } } }`
		if _, err := CheckText(text, -1); err == nil {
			t.Errorf("CheckText ACCEPTED padded RDNSS %s", addr)
		} else if !strings.Contains(err.Error(), "must not have leading or trailing whitespace") {
			t.Errorf("padded RDNSS %s: want shared padding message, got %v", addr, err)
		}
	}
	bare := `protocols { router-advertisement { interface ge-0-0-0 { dns-server-address 2001:db8::53; } } }`
	cfg, err := CheckText(bare, -1)
	if err != nil {
		t.Fatalf("bare RDNSS control must pass CheckText: %v", err)
	}
	if cfg == nil {
		t.Fatal("bare RDNSS control returned nil config")
	}
	// Bracket-list spelling: every element is gated.
	paddedList := `protocols { router-advertisement { interface ge-0-0-0 { dns-server-address [ 2001:db8::53 " 2001:db8::54" ]; } } }`
	if _, err := CheckText(paddedList, -1); err == nil {
		t.Errorf("CheckText ACCEPTED padded RDNSS inside bracket list")
	}
}

func TestCheckTextPaddedDeviceMapPCIRejected17177(t *testing.T) {
	for _, pci := range []string{`" 0000:09:00.0"`, `"0000:09:00.0 "`} {
		text := `chassis { device-map { interface ge-0/0/3 { pci ` + pci + `; } } }`
		if _, err := CheckText(text, -1); err == nil {
			t.Errorf("CheckText ACCEPTED padded device-map pci %s", pci)
		} else if !strings.Contains(err.Error(), "must not have leading or trailing whitespace") {
			t.Errorf("padded pci %s: want shared padding message, got %v", pci, err)
		}
	}
	bare := `chassis { device-map { interface ge-0/0/3 { pci 0000:09:00.0; } } }`
	if _, err := CheckText(bare, -1); err != nil {
		t.Fatalf("bare device-map pci control must pass CheckText: %v", err)
	}
}

func TestCheckTextPaddedSchedulerBoundsRejected17177(t *testing.T) {
	cases := []struct{ name, text string }{
		{"padded-start", `schedulers { scheduler biz { daily { start-time " 09:00"; stop-time 17:00; } } }`},
		{"padded-stop", `schedulers { scheduler biz { daily { start-time 09:00; stop-time "17:00 "; } } }`},
		{"padded-direct-start", `schedulers { scheduler biz { start-time " 09:00"; stop-time 17:00; } }`},
		{"padded-direct-stop", `schedulers { scheduler biz { start-time 09:00; stop-time "17:00 "; } }`},
	}
	for _, tc := range cases {
		if _, err := CheckText(tc.text, -1); err == nil {
			t.Errorf("%s: CheckText ACCEPTED padded scheduler bound: %s", tc.name, tc.text)
		} else if !strings.Contains(err.Error(), "must not have leading or trailing whitespace") {
			t.Errorf("%s: want shared padding message, got %v", tc.name, err)
		}
	}
	bare := `schedulers { scheduler biz { daily { start-time 09:00; stop-time 17:00; } } }`
	if _, err := CheckText(bare, -1); err != nil {
		t.Fatalf("bare scheduler control must pass CheckText: %v", err)
	}
}
