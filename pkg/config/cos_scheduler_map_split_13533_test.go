package config

import (
	"strings"
	"testing"
)

// #13533 (1): split scheduler-map blocks overwrite. The scheduler-maps loop
// was the only map-keyed CoS container left on fresh-construct (#8436 fixed
// schedulers/traffic-control-profiles/interfaces): a second block naming the
// same scheduler-map discarded the first block's entries.
func TestSplitSchedulerMapBlocksMerge13533(t *testing.T) {
	cfg := mustCompile8436(t, `
class-of-service {
    scheduler-maps {
        SM-A {
            forwarding-class best-effort scheduler SCHED-A;
        }
        SM-A {
            forwarding-class expedited-forwarding scheduler SCHED-B;
        }
    }
    schedulers {
        SCHED-A {
            transmit-rate 100m;
        }
        SCHED-B {
            transmit-rate 100m;
        }
    }
}
`)
	sm := cfg.ClassOfService.SchedulerMaps["SM-A"]
	if sm == nil {
		t.Fatal("SM-A did not compile")
	}
	if len(sm.Entries) != 2 {
		t.Fatalf("split SM-A blocks retained %d entries, want 2: %v", len(sm.Entries), sm.Entries)
	}
	if e := sm.Entries["best-effort"]; e == nil || e.Scheduler != "SCHED-A" {
		t.Errorf("best-effort entry = %v, want SCHED-A (first block lost)", e)
	}
	if e := sm.Entries["expedited-forwarding"]; e == nil || e.Scheduler != "SCHED-B" {
		t.Errorf("expedited-forwarding entry = %v, want SCHED-B (second block lost)", e)
	}
}

// #13533 (1): same merge across two class-of-service ROOTS (compileSections
// iterates roots in author order; the map is shared).
func TestSplitSchedulerMapAcrossRootsMerge13533(t *testing.T) {
	cfg := mustCompile8436(t, `
class-of-service {
    scheduler-maps {
        SM-A {
            forwarding-class best-effort scheduler SCHED-A;
        }
    }
    schedulers {
        SCHED-A {
            transmit-rate 100m;
        }
    }
}
class-of-service {
    scheduler-maps {
        SM-A {
            forwarding-class expedited-forwarding scheduler SCHED-B;
        }
    }
    schedulers {
        SCHED-B {
            transmit-rate 100m;
        }
    }
}
`)
	sm := cfg.ClassOfService.SchedulerMaps["SM-A"]
	if sm == nil {
		t.Fatal("SM-A did not compile")
	}
	if len(sm.Entries) != 2 {
		t.Fatalf("cross-root SM-A retained %d entries, want 2: %v", len(sm.Entries), sm.Entries)
	}
}

// THE CONTROL: different scheduler-map names stay distinct.
func TestDistinctSchedulerMapsStayDistinct13533(t *testing.T) {
	cfg := mustCompile8436(t, `
class-of-service {
    scheduler-maps {
        SM-A {
            forwarding-class best-effort scheduler SCHED-A;
        }
        SM-B {
            forwarding-class expedited-forwarding scheduler SCHED-B;
        }
    }
    schedulers {
        SCHED-A {
            transmit-rate 100m;
        }
        SCHED-B {
            transmit-rate 100m;
        }
    }
}
`)
	if len(cfg.ClassOfService.SchedulerMaps) != 2 {
		t.Fatalf("got %d scheduler-maps, want 2", len(cfg.ClassOfService.SchedulerMaps))
	}
	if e := cfg.ClassOfService.SchedulerMaps["SM-A"].Entries["best-effort"]; e == nil || e.Scheduler != "SCHED-A" {
		t.Errorf("SM-A entry = %v", e)
	}
	if e := cfg.ClassOfService.SchedulerMaps["SM-B"].Entries["expedited-forwarding"]; e == nil || e.Scheduler != "SCHED-B" {
		t.Errorf("SM-B entry = %v", e)
	}
}

// #13533 (2): queue bijection must hold across CoS roots. The registry was
// local to one compileClassOfService invocation, so a second root could
// bind queue 0 to a different FC (and an FC to a second queue).
func compileErr13533(t *testing.T, text string) error {
	t.Helper()
	tree, perrs := NewParser(text).Parse()
	if len(perrs) != 0 {
		t.Fatalf("parse: %v", perrs)
	}
	_, err := CompileConfig(tree)
	return err
}

func TestCrossRootQueueOwnerConflict13533(t *testing.T) {
	err := compileErr13533(t, `
class-of-service {
    forwarding-classes {
        queue 0 be;
    }
}
class-of-service {
    forwarding-classes {
        queue 0 ef2;
    }
}
`)
	if err == nil {
		t.Fatal("two CoS roots both binding queue 0 accepted; want bijection error")
	}
	if !strings.Contains(err.Error(), "queue 0") {
		t.Fatalf("error should name queue 0: %v", err)
	}
}

func TestCrossRootFCQueueConflict13533(t *testing.T) {
	err := compileErr13533(t, `
class-of-service {
    forwarding-classes {
        queue 0 be;
    }
}
class-of-service {
    forwarding-classes {
        queue 1 be;
    }
}
`)
	if err == nil {
		t.Fatal("FC be bound to queues 0 and 1 across roots accepted; want bijection error")
	}
}

func TestCrossRootDisjointQueuesAndIdempotentReapplyAccepted13533(t *testing.T) {
	cfg := mustCompile8436(t, `
class-of-service {
    forwarding-classes {
        queue 0 be;
        queue 1 ef;
    }
}
class-of-service {
    forwarding-classes {
        queue 0 be;
        queue 2 af;
    }
}
`)
	if len(cfg.ClassOfService.ForwardingClasses) != 3 {
		t.Fatalf("got %d FCs, want 3: %v", len(cfg.ClassOfService.ForwardingClasses), cfg.ClassOfService.ForwardingClasses)
	}
	if cfg.ClassOfService.ForwardingClasses["be"].Queue != 0 {
		t.Errorf("be queue = %d, want 0", cfg.ClassOfService.ForwardingClasses["be"].Queue)
	}
}
