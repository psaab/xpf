package config_test

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestSchedulerEquivalentRepeatedTimeSpellingsAccepted11681(t *testing.T) {
	for _, tc := range []struct {
		name  string
		first string
		last  string
	}{
		{name: "omitted seconds", first: "09:00", last: "09:00:00"},
		{name: "one-digit hour", first: "9:00:00", last: "09:00:00"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			text := "schedulers { scheduler S { sunday { start-time " + tc.first +
				"; start-time " + tc.last + "; stop-time 12:00; } } }"
			tree, errs := config.NewParser(text).Parse()
			if len(errs) > 0 {
				t.Fatalf("parse errors: %v", errs)
			}
			if _, err := config.CompileConfig(tree); err != nil {
				t.Fatalf("semantically identical repeated boundaries %q and %q should compile: %v", tc.first, tc.last, err)
			}
		})
	}
}

func TestSchedulerDistinctRepeatedTimeSpellingsStillConflict11681(t *testing.T) {
	const text = "schedulers { scheduler S { sunday { start-time 09:00; start-time 09:00:01; stop-time 12:00; } } }"
	tree, errs := config.NewParser(text).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	if _, err := config.CompileConfig(tree); err == nil || !strings.Contains(err.Error(), "#11358") {
		t.Fatalf("distinct repeated boundaries should remain rejected by #11358, got %v", err)
	}
}
