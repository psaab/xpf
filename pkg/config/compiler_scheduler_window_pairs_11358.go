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

type schedulerWindowFinding11358 uint8

const (
	schedulerWindowFindingRepeatedBoundary11358 schedulerWindowFinding11358 = 1 << iota
	schedulerWindowFindingAllDayExclude12238
	schedulerWindowFindingFlagWindow12238
	schedulerWindowFindingAllDayWindow12643
	schedulerWindowFindingDailyAllDayWindow12745
)

// schedulerWeekdayContribution12238 is what one weekday statement (one
// `monday ...` node after flat-run expansion) declares for its day.
// Contributors are keyed per statement: splits between statements are
// diagnosed as #12238, and an all-day flag combined with a complete window
// is diagnosed even when the effective tree composes them into one statement
// (#12643).
type schedulerWeekdayContribution12238 struct {
	allDay  bool
	exclude bool
	start   bool
	stop    bool
}

type schedulerWeekdayContributors12238 struct {
	allDay  map[*Node]struct{}
	exclude map[*Node]struct{}
	start   map[*Node]struct{}
	stop    map[*Node]struct{}
}

func (c *schedulerWeekdayContributors12238) add(statement *Node, contribution schedulerWeekdayContribution12238) {
	if contribution.allDay {
		if c.allDay == nil {
			c.allDay = make(map[*Node]struct{})
		}
		c.allDay[statement] = struct{}{}
	}
	if contribution.exclude {
		if c.exclude == nil {
			c.exclude = make(map[*Node]struct{})
		}
		c.exclude[statement] = struct{}{}
	}
	if contribution.start {
		if c.start == nil {
			c.start = make(map[*Node]struct{})
		}
		c.start[statement] = struct{}{}
	}
	if contribution.stop {
		if c.stop == nil {
			c.stop = make(map[*Node]struct{})
		}
		c.stop[statement] = struct{}{}
	}
}

// splitAllDayExclude reports all-day and exclude declared by different
// statements for the same day.
func (c *schedulerWeekdayContributors12238) splitAllDayExclude() bool {
	for allDayStatement := range c.allDay {
		for excludeStatement := range c.exclude {
			if allDayStatement != excludeStatement {
				return true
			}
		}
	}
	return false
}

// splitFlagWindow reports an all-day or exclude statement that does not itself
// carry the complete start/stop pair the day's statements supply. A flag next
// to only a partial start/stop preserves complementary-fragment behavior
// (#11641).
func (c *schedulerWeekdayContributors12238) splitFlagWindow() bool {
	if len(c.start) == 0 || len(c.stop) == 0 {
		return false
	}
	lacksOwnWindow := func(flags map[*Node]struct{}) bool {
		for flagStatement := range flags {
			_, hasStart := c.start[flagStatement]
			_, hasStop := c.stop[flagStatement]
			if !hasStart || !hasStop {
				return true
			}
		}
		return false
	}
	return lacksOwnWindow(c.allDay) || lacksOwnWindow(c.exclude)
}

// validateSchedulerWindowPairs11358 checks effective cluster-node views before
// node-local expansion can hide a peer-only group. It rejects conflicting
// boundary repeats (#11358), split weekday all-day/exclude/time-window meanings
// (#12238), weekday all-day with a complete time window (#12643), and daily
// all-day with a complete time window (#12745), because the scheduler runtime
// evaluates all-day before time bounds.
func validateSchedulerWindowPairs11358(tree *ConfigTree, lenient bool) ([]string, error) {
	if tree == nil {
		return nil, nil
	}
	if !hasSchedulerWindowCandidate11358(tree) {
		return nil, nil
	}
	findings := make(map[schedulerWindowKey11358]schedulerWindowFinding11358)
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
		var message string
		addMessage := func(part string) {
			if message != "" {
				message += "; "
			}
			message += part
		}
		if findings[key]&schedulerWindowFindingRepeatedBoundary11358 != 0 {
			addMessage(fmt.Sprintf(
				"scheduler %q %s has conflicting repeated time boundaries; xpf stores one window per day, so conflicting repeats do not define a supported multiple-window representation and later definitions may replace earlier boundary values or whole windows (#11358)",
				key.scheduler, key.day))
		}
		if findings[key]&schedulerWindowFindingAllDayExclude12238 != 0 {
			addMessage(fmt.Sprintf(
				"scheduler %q %s combines all-day and exclude from separate weekday statements; xpf stores one window per day and cannot represent both meanings (#12238)",
				key.scheduler, key.day))
		}
		if findings[key]&schedulerWindowFindingFlagWindow12238 != 0 {
			addMessage(fmt.Sprintf(
				"scheduler %q %s combines an all-day or exclude flag with start-time/stop-time bounds from a separate weekday statement; xpf stores one window per day and cannot represent both meanings (#12238)",
				key.scheduler, key.day))
		}
		if findings[key]&schedulerWindowFindingAllDayWindow12643 != 0 {
			addMessage(fmt.Sprintf(
				"scheduler %q %s combines all-day with a complete start-time/stop-time window; runtime enforces all-day before time bounds, so xpf cannot represent both meanings (#12643)",
				key.scheduler, key.day))
		}
		if findings[key]&schedulerWindowFindingDailyAllDayWindow12745 != 0 {
			addMessage(fmt.Sprintf(
				"scheduler %q daily combines all-day with a complete start-time/stop-time window; runtime enforces all-day before time bounds, so xpf cannot represent both meanings (#12745)",
				key.scheduler))
		}
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
// Findings are unioned by scheduler/day across node0 and node1. Boundary
// repeats and weekday contributors are compared only within one view so
// legitimate node-specific windows are not mistaken for repeated statements.
func collectSchedulerWindowPairFindings11358(tree *ConfigTree, findings map[schedulerWindowKey11358]schedulerWindowFinding11358) {
	var windows map[schedulerWindowKey11358]*schedulerWindowBoundaryValues11358
	var weekdayContributors map[schedulerWindowKey11358]*schedulerWeekdayContributors12238
	dailyWindows := make(map[string]SchedulerDayWindow)
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
					daily := dailyWindows[inst.name]
					if prop.Name() == "start-time" {
						daily.StartTime = nodeVal(prop)
					} else {
						daily.StopTime = nodeVal(prop)
					}
					dailyWindows[inst.name] = daily
					record(inst.name, "daily", prop.Name(), nodeVal(prop))
				case "daily":
					if win, ok := schedulerWindowFromNode(prop); ok {
						daily := dailyWindows[inst.name]
						if win.StartTime != "" {
							daily.StartTime = win.StartTime
						}
						if win.StopTime != "" {
							daily.StopTime = win.StopTime
						}
						daily.AllDay = win.AllDay
						dailyWindows[inst.name] = daily
					}
					for _, leaf := range expandFlatRun(prop.Children, schedulerDayLeafSchema8939()) {
						if leaf == nil {
							continue
						}
						if boundary := leaf.Name(); boundary == "start-time" || boundary == "stop-time" {
							record(inst.name, "daily", boundary, nodeVal(leaf))
						}
					}
				case "monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday":
					if win, ok := schedulerWindowFromNode(prop); ok {
						if weekdayContributors == nil {
							weekdayContributors = make(map[schedulerWindowKey11358]*schedulerWeekdayContributors12238)
						}
						key := schedulerWindowKey11358{scheduler: inst.name, day: prop.Name()}
						contributors := weekdayContributors[key]
						if contributors == nil {
							contributors = &schedulerWeekdayContributors12238{}
							weekdayContributors[key] = contributors
						}
						contributors.add(prop, schedulerWeekdayContribution12238{
							allDay:  win.AllDay,
							exclude: win.Exclude,
							start:   win.StartTime != "",
							stop:    win.StopTime != "",
						})
					}
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

	for key, contributors := range weekdayContributors {
		if contributors.splitAllDayExclude() {
			findings[key] |= schedulerWindowFindingAllDayExclude12238
		}
		if contributors.splitFlagWindow() {
			findings[key] |= schedulerWindowFindingFlagWindow12238
		}
		if len(contributors.allDay) > 0 && len(contributors.start) > 0 && len(contributors.stop) > 0 {
			findings[key] |= schedulerWindowFindingAllDayWindow12643
		}
	}
	for key, values := range windows {
		if values.repeatedStart || values.repeatedStop {
			findings[key] |= schedulerWindowFindingRepeatedBoundary11358
		}
	}
	for scheduler, daily := range dailyWindows {
		if daily.AllDay && daily.StartTime != "" && daily.StopTime != "" {
			findings[schedulerWindowKey11358{scheduler: scheduler, day: "daily"}] |= schedulerWindowFindingDailyAllDayWindow12745
		}
	}
}
