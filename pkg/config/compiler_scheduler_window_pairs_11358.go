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
	start         string
	stop          string
	repeatedStart bool
	repeatedStop  bool
}

// validateSchedulerWindowPairs11358 checks each effective cluster-node view
// before node-local expansion can hide a peer-only group. The scheduler model
// stores one scalar time pair per day, so conflicting repeats cannot be
// represented without losing a boundary.
func validateSchedulerWindowPairs11358(tree *ConfigTree, lenient bool) ([]string, error) {
	if tree == nil {
		return nil, nil
	}
	if !hasSchedulerWindowCandidate11358(tree) {
		return nil, nil
	}
	findings := make(map[schedulerWindowKey11358]struct{})
	for _, nodeID := range []int{0, 1} {
		view := tree.Clone()
		vars := map[string]string{"node": fmt.Sprintf("node%d", nodeID)}
		if err := view.ExpandGroupsWithVarsTagged(vars); err != nil {
			continue
		}
		collectSchedulerWindowPairFindings11358(view, findings)
	}
	if len(findings) == 0 {
		return nil, nil
	}

	keys := make([]schedulerWindowKey11358, 0, len(findings))
	for key := range findings {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].scheduler != keys[j].scheduler {
			return keys[i].scheduler < keys[j].scheduler
		}
		return keys[i].day < keys[j].day
	})

	warnings := make([]string, 0, len(keys))
	for _, key := range keys {
		message := fmt.Sprintf(
			"scheduler %q %s has conflicting repeated time boundaries; xpf stores one window per day, so conflicting repeats do not define a supported multiple-window representation and later definitions may replace earlier boundary values or whole windows (#11358)",
			key.scheduler, key.day)
		if !lenient {
			return nil, fmt.Errorf("%s", message)
		}
		warnings = append(warnings, message)
	}
	return warnings, nil
}

// hasSchedulerWindowCandidate11358 avoids cloning and expanding unrelated
// configs while still noticing schedulers that exist only inside a group.
func hasSchedulerWindowCandidate11358(tree *ConfigTree) bool {
	for _, root := range tree.Children {
		if root == nil {
			continue
		}
		if root.Name() == "schedulers" ||
			(root.Name() == "groups" && containsSchedulerSection11358(root.Children)) {
			return true
		}
	}
	return false
}

func containsSchedulerSection11358(nodes []*Node) bool {
	for _, node := range nodes {
		if node == nil {
			continue
		}
		if node.Name() == "schedulers" || containsSchedulerSection11358(node.Children) {
			return true
		}
	}
	return false
}

// collectSchedulerWindowPairFindings11358 scans one already-expanded view.
// Findings are unioned by scheduler/day across node0 and node1; boundary
// values are intentionally compared only within one view so legitimate
// node-specific windows are not mistaken for duplicate statements.
func collectSchedulerWindowPairFindings11358(tree *ConfigTree, findings map[schedulerWindowKey11358]struct{}) {
	var windows map[schedulerWindowKey11358]*schedulerWindowBoundaryValues11358
	record := func(scheduler, day, boundary, value string) {
		if value == "" {
			return
		}
		// Compare semantic times, not spelling (omitted seconds and a
		// one-digit hour in HH:MM:SS are accepted by the scheduler parser).
		if parsed, err := parseSchedulerTimeOfDay(value); err == nil {
			value = parsed.Format("15:04:05")
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

	for key, values := range windows {
		if values.repeatedStart || values.repeatedStop {
			findings[key] = struct{}{}
		}
	}
}
