package config_test

// #4228 Gap 2 follow-up: CoS scheduler `buffer-size` accepts the Junos
// `temporal <microseconds>` form in addition to an absolute byte-size (16m)
// and a percent (10%). temporal is ACCEPTED-BUT-INERT — xpf stores the
// microsecond target but does not yet resolve it to a byte-size (that needs
// the queue's transmit rate), so a commit advisory surfaces the inertness.
//
// FAIL-ON-REVERT: with the tailValidator + temporal child removed and the
// plain ValueByteSizeOrPercent validator restored, `buffer-size temporal
// 50000` is rejected at SchemaValidate (the value token "temporal" is not a
// byte-size), and the compiled BufferSizeTemporalUS field disappears.

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestCoSBufferSizeTemporal_AcceptsAndCompiles(t *testing.T) {
	cfg := mustCompileSet4228(t,
		"set class-of-service schedulers be buffer-size temporal 50000",
	)
	sched := cfg.ClassOfService.Schedulers["be"]
	if sched == nil {
		t.Fatal("expected be scheduler")
	}
	if sched.BufferSizeTemporalUS != 50000 {
		t.Fatalf("BufferSizeTemporalUS = %d, want 50000", sched.BufferSizeTemporalUS)
	}
	if sched.BufferSizeBytes != 0 || sched.BufferSizePercent != 0 {
		t.Fatalf("temporal form must not set bytes/percent (bytes=%d percent=%v)",
			sched.BufferSizeBytes, sched.BufferSizePercent)
	}
}

// TestTemporalAdvisoryNarrowsToUnresolvable6846 replaces the #4228 blanket
// inert-advisory assertion. #6846 makes `buffer-size temporal` RESOLVE against
// the queue's transmit rate, so the advisory must narrow to the case that still
// cannot: a queue with no resolvable rate has no drain speed.
//
// BOTH DIRECTIONS ARE ASSERTED, and the second is the one that matters. An
// advisory that keeps firing for configurations that now work is as much a
// defect as one that stops firing for configurations that do not — it teaches
// the operator to ignore it. A cell that only checked "it still warns" would
// pass against a change that never narrowed anything.
func TestTemporalAdvisoryNarrowsToUnresolvable6846(t *testing.T) {
	hasTemporalAdvisory := func(t *testing.T, lines ...string) bool {
		t.Helper()
		for _, w := range config.ValidateConfig(mustCompileSet4228(t, lines...)) {
			if strings.Contains(w, "buffer-size temporal") {
				return true
			}
		}
		return false
	}

	t.Run("no resolvable rate still warns", func(t *testing.T) {
		// A bare scheduler: no absolute rate, and not bound via a
		// scheduler-map to a shaped interface. Nothing to convert against.
		if !hasTemporalAdvisory(t,
			"set class-of-service schedulers be buffer-size temporal 50000",
		) {
			t.Fatal("a temporal target on a queue with no resolvable transmit-rate " +
				"must still warn — there is no drain speed to convert it against")
		}
	})

	t.Run("remainder with a shaping base resolves, so it must NOT warn", func(t *testing.T) {
		// A `remainder` queue bound via a scheduler-map to a shaped interface
		// HAS a resolvable rate, so temporal converts against it. Found by the
		// mutation matrix: making cosSchedulerRateResolves ignore
		// TransmitRateRemainder escaped GREEN against the whole Go suite,
		// because every other fixture reaches a resolvable rate by the
		// ABSOLUTE route and cannot tell the two apart.
		if hasTemporalAdvisory(t,
			"set class-of-service schedulers be transmit-rate remainder",
			"set class-of-service schedulers be buffer-size temporal 50000",
			"set class-of-service scheduler-maps sm forwarding-class best-effort scheduler be",
			"set class-of-service interfaces ge-0/0/0 scheduler-map sm",
			"set class-of-service interfaces ge-0/0/0 shaping-rate 100m",
		) {
			t.Fatal("#6846: a `remainder` queue with a shaping base resolves, so " +
				"temporal converts against it and the advisory must not fire")
		}
	})

	t.Run("remainder with a ZERO leftover: the RATE is inert, temporal is NOT", func(t *testing.T) {
		// The subtest above binds a lone remainder queue to a 100m shape, so
		// the leftover is the whole 100m — it varies the right axis and samples
		// only the passing point.
		//
		// Here siblings claim the entire shaping-rate, so the leftover is zero
		// and the dataplane declines the share. The `remainder` form IS inert
		// and TestRemainderAdvisoryTracksTheLeftover6846 asserts the remainder
		// advisory fires for exactly this shape.
		//
		// TEMPORAL is not. The queue keeps the no-guarantee fallback, which is
		// the interface shaping-rate, so it still drains at 100m and the
		// microsecond target still has a byte value. An earlier revision
		// asserted a warning here on the reasoning that "the queue has no
		// rate"; the queue has no GUARANTEE, which is a different thing, and
		// build_cos_state_temporal_converts_against_the_fallback_drain_rate
		// measures the difference.
		if hasTemporalAdvisory(t,
			"set class-of-service schedulers full transmit-rate percent 100",
			"set class-of-service schedulers be transmit-rate remainder",
			"set class-of-service schedulers be buffer-size temporal 50000",
			"set class-of-service scheduler-maps sm forwarding-class assured-forwarding scheduler full",
			"set class-of-service scheduler-maps sm forwarding-class best-effort scheduler be",
			"set class-of-service interfaces ge-0/0/0 scheduler-map sm",
			"set class-of-service interfaces ge-0/0/0 shaping-rate 100m",
		) {
			t.Fatal("#6846: an unresolved `remainder` does not make TEMPORAL inert — " +
				"the queue still drains at the interface shaping-rate, so the " +
				"microsecond target still has a byte value. Warning here tells the " +
				"operator a knob does nothing when it does")
		}
	})

	t.Run("bound to an UNSHAPED interface still warns", func(t *testing.T) {
		// The case that keeps the predicate honest. A scheduler-map binding is
		// not enough on its own: with no root shaping-rate the queue's
		// effective rate is zero, cos_temporal_buffer_bytes declines it, and
		// the buffer really does fall back to default sizing.
		//
		// Without this row the predicate could be weakened all the way to "is
		// it bound to anything" and every other row would still pass.
		if !hasTemporalAdvisory(t,
			"set class-of-service schedulers be buffer-size temporal 50000",
			"set class-of-service scheduler-maps sm forwarding-class best-effort scheduler be",
			"set class-of-service interfaces ge-0/0/0 scheduler-map sm",
		) {
			t.Fatal("#6846: an interface with no root shaping-rate gives the queue an " +
				"effective rate of zero, so temporal has nothing to convert against " +
				"and the advisory must still fire")
		}
	})

	t.Run("absolute rate resolves, so it must NOT warn", func(t *testing.T) {
		// An explicit transmit-rate needs no shaping base, so temporal
		// converts and the advisory must be gone.
		if hasTemporalAdvisory(t,
			"set class-of-service schedulers be transmit-rate 10m",
			"set class-of-service schedulers be buffer-size temporal 50000",
		) {
			t.Fatal("#6846: temporal RESOLVES against an explicit transmit-rate, so " +
				"the advisory must not fire. An advisory that keeps firing for a " +
				"configuration that now works teaches the operator to ignore it")
		}
	})
}

// The byte-size and percent forms must keep working after the tailValidator
// conversion (regression guard for the leaf-shape change).
func TestCoSBufferSizeBytesAndPercent_StillCompile(t *testing.T) {
	cfg := mustCompileSet4228(t,
		"set class-of-service schedulers b1 buffer-size 16m",
		"set class-of-service schedulers b2 buffer-size 10%",
	)
	if got := cfg.ClassOfService.Schedulers["b1"].BufferSizeBytes; got == 0 {
		t.Fatalf("buffer-size 16m should compile to bytes, got %d", got)
	}
	if got := cfg.ClassOfService.Schedulers["b2"].BufferSizePercent; got != 10 {
		t.Fatalf("buffer-size 10%% should compile to percent 10, got %v", got)
	}
}

func TestCoSBufferSizeTemporalZero_Rejected(t *testing.T) {
	err := flatSchemaCheck(t, "set class-of-service schedulers be buffer-size temporal 0")
	if err == nil {
		t.Fatal("expected error for `buffer-size temporal 0`")
	}
	if !strings.Contains(err.Error(), "temporal") {
		t.Fatalf("error should reference temporal: %v", err)
	}
}

func TestCoSBufferSizeTemporalGarbage_Rejected(t *testing.T) {
	err := flatSchemaCheck(t, "set class-of-service schedulers be buffer-size temporal abc")
	if err == nil {
		t.Fatal("expected error for `buffer-size temporal abc`")
	}
}

func TestCoSBufferSizeTemporalMissingValue_Rejected(t *testing.T) {
	err := flatSchemaCheck(t, "set class-of-service schedulers be buffer-size temporal")
	if err == nil {
		t.Fatal("expected error for `buffer-size temporal` with no value")
	}
}

func TestCoSBufferSizeMixedSiblingFormsRejected11789(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name: "bytes and temporal",
			input: `class-of-service {
    schedulers {
        be {
            buffer-size 16m;
            buffer-size temporal 50000;
        }
    }
}`,
		},
		{
			name: "percent and temporal",
			input: `class-of-service {
    schedulers {
        be {
            buffer-size 10%;
            buffer-size temporal 50000;
        }
    }
}`,
		},
		{
			name: "bytes and percent",
			input: `class-of-service {
    schedulers {
        be {
            buffer-size 16m;
            buffer-size 10%;
        }
    }
}`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tree, parseErrs := config.NewParser(tc.input).Parse()
			if len(parseErrs) != 0 {
				t.Fatalf("parse error: %v", parseErrs[0])
			}
			err := config.SchemaValidate(tree, nil)
			if err == nil {
				t.Fatal("SchemaValidate accepted sibling buffer-size forms")
			}
			for _, want := range []string{"buffer-size", "mutually exclusive"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("schema error %q does not name %q", err, want)
				}
			}
		})
	}
}

func TestCoSBufferSizeSameSiblingFormRemainsAllowed11789(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input string
	}{
		{
			name: "byte sizes",
			input: `class-of-service {
    schedulers { be { buffer-size 16m; buffer-size 32m; } }
}`,
		},
		{
			name: "percentages",
			input: `class-of-service {
    schedulers { be { buffer-size 10%; buffer-size 20%; } }
}`,
		},
		{
			name: "temporal values",
			input: `class-of-service {
    schedulers { be { buffer-size temporal 50000; buffer-size temporal 100000; } }
}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree, parseErrs := config.NewParser(tc.input).Parse()
			if len(parseErrs) != 0 {
				t.Fatalf("parse error: %v", parseErrs[0])
			}
			if err := config.SchemaValidate(tree, nil); err != nil {
				t.Fatalf("same-arm sibling buffer-size values must remain accepted: %v", err)
			}
		})
	}
}

func TestCoSBufferSizeLaterHierarchicalFormReplacesEarlier11789(t *testing.T) {
	tests := []struct {
		name           string
		first, second  string
		wantBytes      bool
		wantPercent    float64
		wantTemporalUS uint64
	}{
		{name: "bytes replace temporal", first: "temporal 50000", second: "16m", wantBytes: true},
		{name: "percent replaces temporal", first: "temporal 50000", second: "10%", wantPercent: 10},
		{name: "temporal replaces bytes", first: "16m", second: "temporal 50000", wantTemporalUS: 50_000},
		{name: "temporal replaces percent", first: "10%", second: "temporal 50000", wantTemporalUS: 50_000},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			input := `class-of-service {
    schedulers {
        be { buffer-size ` + tc.first + `; }
    }
    schedulers {
        be { buffer-size ` + tc.second + `; }
    }
}`
			tree, parseErrs := config.NewParser(input).Parse()
			if len(parseErrs) != 0 {
				t.Fatalf("parse error: %v", parseErrs[0])
			}
			cfg, err := config.CompileConfig(tree)
			if err != nil {
				t.Fatalf("CompileConfig: %v", err)
			}
			sched := cfg.ClassOfService.Schedulers["be"]
			if sched == nil {
				t.Fatal("expected be scheduler")
			}
			if gotBytes := sched.BufferSizeBytes > 0; gotBytes != tc.wantBytes {
				t.Errorf("BufferSizeBytes present = %t, want %t (value=%d)", gotBytes, tc.wantBytes, sched.BufferSizeBytes)
			}
			if sched.BufferSizePercent != tc.wantPercent {
				t.Errorf("BufferSizePercent = %v, want %v", sched.BufferSizePercent, tc.wantPercent)
			}
			if sched.BufferSizeTemporalUS != tc.wantTemporalUS {
				t.Errorf("BufferSizeTemporalUS = %d, want %d", sched.BufferSizeTemporalUS, tc.wantTemporalUS)
			}
		})
	}
}
