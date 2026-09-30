package config

import (
	"fmt"
	"sort"
)

type schedulerWindowKey11358 struct {
	scheduler string
	day       string
}

type schedulerWindowBoundaryValues11358 struct {
	start          string
	stop           string
	repeatedStart  bool
	repeatedStop   bool
}

// validateSchedulerWindowPairs11358 catches distinct repeated time boundaries
// before schedulerWindowFromNode compiles its single scalar start/stop pair.
// The gate runs after group expansion, so inherited window statements receive
// the same strict rejection / tolerant warning as inline statements.
func validateSchedulerWindowPairs11358(tree *ConfigTree, lenient bool) ([]string, error) {
	if tree == nil {
		return nil, nil
	}

	var windows map[schedulerWindowKey11358]*schedulerWindowBoundaryValues11358
	record := func(scheduler, day, boundary, value string) {
		if value == "" {
			return
		}
		key := schedulerWindowKey11358{scheduler: scheduler, day: day}
		if windows == nil {
			windows = make(map[schedulerWindowKey11358]*schedulerWindowBoundaryValues11358)
		}
		values := windows[key]
		if values == nil {
			values = &schedulerWindowBoundaryValues11358{}
			windows[key] = values
		}
		switch boundary {
		case "start-time":
			if values.start == "" {
				values.start = value
			} else if values.start != value {
				values.repeatedStart = true
			}
		case "stop-time":
			if values.stop == "" {
				values.stop = value
			} else if values.stop != value {
				values.repeatedStop = true
			}
		}
	}

	for _, root := range tree.Children {
		if root == nil || root.Name() != "schedulers" {
			continue
		}
		for _, inst := range namedInstances(root.FindChildren("scheduler")) {
			if inst.node == nil {
				continue
			}
			// Match compileSchedulers' flat-run expansion so packed scheduler
			// statements are inspected at the same semantic level as the compiler.
			for _, prop := range expandRunChildren9235(inst.node.Children, schedulerSchema9235()) {
				if prop == nil {
					continue
				}
				switch prop.Name() {
				case "start-time", "stop-time":
					// Legacy direct scheduler leaves are the daily scalar window.
					record(inst.name, "daily", prop.Name(), nodeVal(prop))
				case "daily", "monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday":
					for _, leaf := range expandFlatRun(prop.Children, schedulerDayLeafSchema8939()) {
						if leaf == nil {
							continue
						}
						if boundary := leaf.Name(); boundary == "start-time" || boundary == "stop-time" {
							record(inst.name, prop.Name(), boundary, nodeVal(leaf))
						}
					}
				}
			}
		}
	}

	if len(windows) == 0 {
		return nil, nil
	}
	keys := make([]schedulerWindowKey11358, 0, len(windows))
	for key, values := range windows {
		if values.repeatedStart || values.repeatedStop {
			keys = append(keys, key)
		}
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].scheduler != keys[j].scheduler {
			return keys[i].scheduler < keys[j].scheduler
		}
		return keys[i].day < keys[j].day
	})

	if len(keys) == 0 {
		return nil, nil
	}
	warnings := make([]string, 0, len(keys))
	for _, key := range keys {
		values := windows[key]
		var repeated []string
		if values.repeatedStart {
			repeated = append(repeated, "start-time")
		}
		if values.repeatedStop {
			repeated = append(repeated, "stop-time")
		}
		what := repeated[0]
		if len(repeated) == 2 {
			what = "start-time and stop-time"
		}
		message := fmt.Sprintf(
			"scheduler %q %s has conflicting repeated %s values; xpf stores one window per day and compiles the last value for each boundary, so earlier window boundaries would be lost (#11358)",
			key.scheduler, key.day, what)
		if !lenient {
			return nil, fmt.Errorf("%s", message)
		}
		warnings = append(warnings, message)
	}
	return warnings, nil
}
