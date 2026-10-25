package config

import "testing"

// #8436 batch: `class-of-service` interfaces / schedulers /
// traffic-control-profiles, and `protocols isis interface`.
//
// All four had the shape the census names: a second hierarchical block
// constructed a fresh object and either overwrote the first under one map key
// or appended a second entry with the same name. The flat-set spelling merges,
// so the two spellings of one config disagreed.
//
// EVERY MERGE CELL HERE IS PAIRED WITH A DIFFERENT-NAMES CONTROL, and the
// control is the load-bearing half. Find-or-create is keyed on the NAME, so two
// blocks naming different things still produce two entries — but a merge that
// matched ANY entry rather than the same-named one would pass every merge cell
// while silently configuring one interface where the operator wrote two. That
// over-broad merge is the mirror of the defect and only the control can see it.
//
// The leaf spellings below were verified with single-block compiles before the
// assertions were written (`metric 42` -> Metric=42, `transmit-rate 100m` ->
// 12500000 bytes, `shaping-rate 1g` -> 125000000, `unit 0 shaping-rate 500m` ->
// 62500000). #8587 shipped a fixture whose nested spelling set nothing and
// nearly reported the innocent merge as a second defect; the tell there was
// that the CONTROL failed too.

const cosSchedulerMapDef8436 = `
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
`

// ---------- protocols isis interface ----------

// ISIS.Interfaces is a SLICE, so the defect appended a SECOND entry with the
// same name rather than overwriting — it looks like a merge until the entries
// are counted, which is why the count is asserted before the fields.
func TestDuplicateISISInterfaceBlocksMerge8436(t *testing.T) {
	cfg := mustCompile8436(t, `
protocols {
    isis {
        net 49.0001.0100.0000.0001.00;
        interface ge-0/0/0.0 {
            metric 42;
        }
        interface ge-0/0/0.0 {
            passive;
        }
    }
}
`)
	ifaces := cfg.Protocols.ISIS.Interfaces
	if len(ifaces) != 1 {
		t.Fatalf("two blocks naming ONE interface produced %d entries, want 1. A slice-backed "+
			"container appends rather than overwrites, so a duplicate looks merged until the "+
			"entries are counted; whichever consumer reads first wins and the other block's "+
			"settings are unreachable (#8436)", len(ifaces))
	}
	if got := ifaces[0].Metric; got != 42 {
		t.Errorf("Metric = %d, want 42 — the first block's setting was lost", got)
	}
	if !ifaces[0].Passive {
		t.Errorf("Passive = false, want true — the second block's setting was lost")
	}
}

// THE CONTROL. Two DIFFERENT interfaces must still produce two entries, each
// keeping its own settings.
//
// MUTATION: match any entry instead of the same-named one (drop the
// `existing.Name == child.Keys[1]` test) and this reds — one interface, both
// settings, where the operator wrote two.
func TestDistinctISISInterfaceBlocksStillAppend8436(t *testing.T) {
	cfg := mustCompile8436(t, `
protocols {
    isis {
        net 49.0001.0100.0000.0001.00;
        interface ge-0/0/0.0 {
            metric 42;
        }
        interface ge-0/0/1.0 {
            metric 43;
        }
    }
}
`)
	ifaces := cfg.Protocols.ISIS.Interfaces
	if len(ifaces) != 2 {
		t.Fatalf("two DIFFERENT interfaces produced %d entries, want 2. The merge is "+
			"over-broad: it matched an entry with a different name, so one interface now "+
			"carries both blocks' settings and the other is gone entirely (#8436)", len(ifaces))
	}
	byName := map[string]int{}
	for _, i := range ifaces {
		byName[i.Name] = i.Metric
	}
	if byName["ge-0/0/0.0"] != 42 || byName["ge-0/0/1.0"] != 43 {
		t.Errorf("the two interfaces did not keep their own settings: %v", byName)
	}
}

// ---------- class-of-service schedulers ----------

func TestDuplicateCoSSchedulerBlocksMerge8436(t *testing.T) {
	cfg := mustCompile8436(t, `
class-of-service {
    schedulers {
        SCHED-A {
            transmit-rate 100m;
        }
        SCHED-A {
            priority high;
        }
    }
}
`)
	sched := cfg.ClassOfService.Schedulers["SCHED-A"]
	if sched == nil {
		t.Fatal("SCHED-A did not compile")
	}
	if got := sched.TransmitRateBytes; got != 12500000 {
		t.Errorf("TransmitRateBytes = %d, want 12500000 — the first block's rate was "+
			"discarded when the second block overwrote the map entry (#8436)", got)
	}
	if got := sched.Priority; got != "high" {
		t.Errorf("Priority = %q, want \"high\" — the second block's setting was lost", got)
	}
}

// THE CONTROL for the map-keyed containers. Two different names must remain two
// entries with their own values. A map key is a weaker way to get this wrong
// than a slice, but a merge written against the wrong key would collapse them.
func TestDistinctCoSSchedulerBlocksStayDistinct8436(t *testing.T) {
	cfg := mustCompile8436(t, `
class-of-service {
    schedulers {
        SCHED-A {
            transmit-rate 100m;
        }
        SCHED-B {
            transmit-rate 200m;
        }
    }
}
`)
	if n := len(cfg.ClassOfService.Schedulers); n != 2 {
		t.Fatalf("two DIFFERENT schedulers produced %d entries, want 2 (#8436)", n)
	}
	if got := cfg.ClassOfService.Schedulers["SCHED-A"].TransmitRateBytes; got != 12500000 {
		t.Errorf("SCHED-A rate = %d, want 12500000", got)
	}
	if got := cfg.ClassOfService.Schedulers["SCHED-B"].TransmitRateBytes; got != 25000000 {
		t.Errorf("SCHED-B rate = %d, want 25000000", got)
	}
}

// ---------- class-of-service traffic-control-profiles ----------

func TestDuplicateCoSTrafficControlProfileBlocksMerge8436(t *testing.T) {
	cfg := mustCompile8436(t, `
class-of-service {`+cosSchedulerMapDef8436+`
    traffic-control-profiles {
        TCP-A {
            shaping-rate 1g;
        }
        TCP-A {
            scheduler-map SM-A;
        }
    }
}
`)
	tcp := cfg.ClassOfService.TrafficControlProfiles["TCP-A"]
	if tcp == nil {
		t.Fatal("TCP-A did not compile")
	}
	if got := tcp.ShapingRateBytes; got != 125000000 {
		t.Errorf("ShapingRateBytes = %d, want 125000000 — the first block's shaping rate "+
			"was discarded (#8436)", got)
	}
	if got := tcp.SchedulerMap; got != "SM-A" {
		t.Errorf("SchedulerMap = %q, want \"SM-A\" — the second block's binding was lost", got)
	}
}

func TestDistinctCoSTrafficControlProfileBlocksStayDistinct8436(t *testing.T) {
	cfg := mustCompile8436(t, `
class-of-service {
    traffic-control-profiles {
        TCP-A {
            shaping-rate 1g;
        }
        TCP-B {
            shaping-rate 500m;
        }
    }
}
`)
	if n := len(cfg.ClassOfService.TrafficControlProfiles); n != 2 {
		t.Fatalf("two DIFFERENT profiles produced %d entries, want 2 (#8436)", n)
	}
	if got := cfg.ClassOfService.TrafficControlProfiles["TCP-A"].ShapingRateBytes; got != 125000000 {
		t.Errorf("TCP-A shaping = %d, want 125000000", got)
	}
	if got := cfg.ClassOfService.TrafficControlProfiles["TCP-B"].ShapingRateBytes; got != 62500000 {
		t.Errorf("TCP-B shaping = %d, want 62500000", got)
	}
}

// ---------- class-of-service interfaces ----------

// This one has TWO levels to conserve, and they fail differently. The interface
// entry is the map value; the per-unit bodies and the interface-LEVEL body are
// objects inside it that a fresh-construct would wipe wholesale even after the
// entry itself was shared. #8587 records that a shared object is only half a
// fix — the addresses survive and the port range still goes — so the two halves
// are asserted separately.
func TestDuplicateCoSInterfaceBlocksMerge8436(t *testing.T) {
	cfg := mustCompile8436(t, `
class-of-service {`+cosSchedulerMapDef8436+`
    interfaces {
        ge-0/0/0 {
            unit 0 {
                shaping-rate 500m;
            }
        }
        ge-0/0/0 {
            unit 1 {
                shaping-rate 250m;
            }
        }
    }
}
`)
	iface := cfg.ClassOfService.Interfaces["ge-0/0/0"]
	if iface == nil {
		t.Fatal("ge-0/0/0 did not compile")
	}
	if n := len(iface.Units); n != 2 {
		t.Fatalf("two blocks for ONE interface produced %d units, want 2 — the second "+
			"block replaced the whole interface entry and unit 0 is gone (#8436)", n)
	}
	if got := iface.Units[0].ShapingRateBytes; got != 62500000 {
		t.Errorf("unit 0 shaping = %d, want 62500000", got)
	}
	if got := iface.Units[1].ShapingRateBytes; got != 31250000 {
		t.Errorf("unit 1 shaping = %d, want 31250000", got)
	}
}

// The SAME unit in both blocks: the per-unit body must merge rather than the
// second block's fresh object wiping the first's leaves. This is the per-field
// half, and it fails differently from the entry half above — an entry-level fix
// alone leaves it broken.
func TestDuplicateCoSInterfaceSameUnitMergesFields8436(t *testing.T) {
	cfg := mustCompile8436(t, `
class-of-service {`+cosSchedulerMapDef8436+`
    interfaces {
        ge-0/0/0 {
            unit 0 {
                shaping-rate 500m;
            }
        }
        ge-0/0/0 {
            unit 0 {
                scheduler-map SM-A;
            }
        }
    }
}
`)
	iface := cfg.ClassOfService.Interfaces["ge-0/0/0"]
	if iface == nil || iface.Units[0] == nil {
		t.Fatal("ge-0/0/0 unit 0 did not compile")
	}
	if got := iface.Units[0].ShapingRateBytes; got != 62500000 {
		t.Errorf("unit 0 shaping = %d, want 62500000 — the second block's fresh unit "+
			"object wiped the first block's leaf (#8436, the #8433 per-field-wipe "+
			"disposition reached through a container fix)", got)
	}
	if got := iface.Units[0].SchedulerMap; got != "SM-A" {
		t.Errorf("unit 0 scheduler-map = %q, want \"SM-A\"", got)
	}
}

func TestDistinctCoSInterfaceBlocksStayDistinct8436(t *testing.T) {
	cfg := mustCompile8436(t, `
class-of-service {
    interfaces {
        ge-0/0/0 {
            unit 0 {
                shaping-rate 500m;
            }
        }
        ge-0/0/1 {
            unit 0 {
                shaping-rate 250m;
            }
        }
    }
}
`)
	if n := len(cfg.ClassOfService.Interfaces); n != 2 {
		t.Fatalf("two DIFFERENT interfaces produced %d entries, want 2. An over-broad "+
			"merge would silently configure one interface where the operator wrote two "+
			"(#8436)", n)
	}
	if got := cfg.ClassOfService.Interfaces["ge-0/0/0"].Units[0].ShapingRateBytes; got != 62500000 {
		t.Errorf("ge-0/0/0 unit 0 shaping = %d, want 62500000", got)
	}
	if got := cfg.ClassOfService.Interfaces["ge-0/0/1"].Units[0].ShapingRateBytes; got != 31250000 {
		t.Errorf("ge-0/0/1 unit 0 shaping = %d, want 31250000", got)
	}
}
