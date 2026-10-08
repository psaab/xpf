package config

import (
	"strings"
	"testing"
)

func TestTimeRangeSchedulerRejectsUnknownDaysAndLeaves12239(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  string
		bad  string
	}{
		{
			name: "misspelled weekday",
			set:  "set schedulers scheduler deny-test modnay start-time 09:00:00",
			bad:  "modnay",
		},
		{
			name: "unknown day leaf",
			set:  "set schedulers scheduler deny-test monday star-time 09:00:00",
			bad:  "star-time",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildTree(t, []string{tc.set})
			err := SchemaValidate(tree, nil)
			if err == nil {
				t.Fatalf("strict schema validation accepted %q", tc.bad)
			}
			for _, want := range []string{"deny-test", tc.bad, "closed-world"} {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("error = %q, want scheduler name, unknown keyword, and closed-world diagnostic (%q)", err, want)
				}
			}
		})
	}
}

func TestMisspelledWeekdayOnScheduledDenyRejected12239(t *testing.T) {
	tree := buildTree(t, []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.2.1/24",
		"set schedulers scheduler deny-test modnay start-time 09:00:00",
		"set schedulers scheduler deny-test modnay stop-time 17:00:00",
		"set security zones security-zone trust interfaces ge-0/0/0.0",
		"set security zones security-zone untrust interfaces ge-0/0/1.0",
		"set security policies from-zone trust to-zone untrust policy p1 match source-address any",
		"set security policies from-zone trust to-zone untrust policy p1 match destination-address any",
		"set security policies from-zone trust to-zone untrust policy p1 match application any",
		"set security policies from-zone trust to-zone untrust policy p1 then deny",
		"set security policies from-zone trust to-zone untrust policy p1 scheduler-name deny-test",
	})
	err := SchemaValidate(tree, nil)
	if err == nil {
		t.Fatal("strict schema validation accepted a scheduled deny whose only weekday is misspelled")
	}
	for _, want := range []string{"deny-test", "modnay"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error = %q, want scheduler name and typo %q", err, want)
		}
	}
}

func TestTimeRangeSchedulerNoWindowSchemaControl12239(t *testing.T) {
	tree := buildTree(t, []string{"set schedulers scheduler empty"})
	if err := SchemaValidate(tree, nil); err != nil {
		t.Fatalf("an empty scheduler remains schema-valid: %v", err)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("an empty scheduler remains compilable: %v", err)
	}
	s := cfg.Schedulers["empty"]
	if s == nil {
		t.Fatal("compiled config is missing the empty scheduler")
	}
	if s.StartTime != "" || s.StopTime != "" || s.AllDay || len(s.Days) != 0 {
		t.Fatalf("empty scheduler unexpectedly acquired a window: %+v", s)
	}
}
