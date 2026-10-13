package config

import "fmt"

// schemaSchedulers models the top-level `[edit schedulers]` policy
// time-range stanza (F-013 — previously absent from setSchema, so flat-set
// `set schedulers scheduler X daily start-time ...` packed the whole line
// onto ONE leaf node and the compiler dropped it). Adding it here makes
// SetPath group flat-set scheduler config into the same nested AST the
// hierarchical parser produces, so compileSchedulers descends into the
// `daily {}`/weekday containers for both shapes.
//
// The time/date value slots are typed (ValueTimeOfDay/ValueDate) so a
// malformed window is rejected at commit — the fail-closed half of #3849.
var schemaSchedulerDay = &schemaNode{
	desc: "Time window for this day (start-time/stop-time, all-day, or exclude)",
	// #12239: use the same SetPath flat-run expansion as the compiler's
	// schedulerWindowFromNode. Without it, the inherited closed-world arm
	// rejects supported #8939 chains such as `monday all-day exclude`.
	packedFlatRun: true,
	nodeValidator: validateSchedulerDayPackedTail12239,
	children: map[string]*schemaNode{
		"start-time": {
			desc:          "Window start time (24-hour HH:MM or HH:MM:SS)",
			args:          1,
			placeholder:   "<HH:MM[:SS]>",
			valueType:     ValueTimeOfDay,
			valueDesc:     "Time of day the window opens (seconds default to zero)",
			valueExamples: []string{"09:00", "09:00:00", "17:30:00", "22:00:00"},
			validator:     ValidateTimeOfDay,
			children:      nil,
		},
		"stop-time": {
			desc:          "Window stop time (24-hour HH:MM or HH:MM:SS; exclusive)",
			args:          1,
			placeholder:   "<HH:MM[:SS]>",
			valueType:     ValueTimeOfDay,
			valueDesc:     "Time of day the window closes (seconds default to zero)",
			valueExamples: []string{"17:00", "17:00:00", "06:00"},
			validator:     ValidateTimeOfDay,
			children:      nil,
		},
		"all-day": {desc: "Active for the entire day", children: nil},
		"exclude": {desc: "Never active on this day", children: nil},
	},
}

var schemaSchedulers = &schemaNode{
	desc: "Policy time-range schedulers ([edit schedulers])",
	children: map[string]*schemaNode{
		"scheduler": {
			desc:          "Named scheduler bound to a policy via scheduler-name",
			args:          1,
			multi:         true,
			placeholder:   "<scheduler-name>",
			closedWorld:   true,
			nodeValidator: validateSchedulerPackedWeekday12636,
			children: map[string]*schemaNode{
				// Junos `scheduler (Security Policies)` syntax includes
				// `description text;` directly under `scheduler <name>`.
				// Modeled (unwired, like the address-set description at
				// schema_security.go) so the closed-world arm keeps its
				// LEAF-COMPLETE precondition and does not reject valid
				// Junos. SchedulerConfig has no Description field and
				// compileSchedulers reads no description child, so the
				// value is accepted and inert by construction.
				"description": {desc: "Scheduler description", args: 1, placeholder: "<text>", children: nil},
				// Legacy simplified shape: start-time/stop-time as direct
				// children of the scheduler (the daily window).
				"start-time": {
					desc:          "Daily window start time (24-hour HH:MM or HH:MM:SS)",
					args:          1,
					placeholder:   "<HH:MM[:SS]>",
					valueType:     ValueTimeOfDay,
					valueDesc:     "Time of day the daily window opens (seconds default to zero)",
					valueExamples: []string{"09:00", "09:00:00", "17:30:00"},
					// Validate the canonical inline pair as one typed tail
					// without adding artificial scheduler child paths.
					validator:     nil,
					tailValidator: validateSchedulerTimePair12637,
					children:      nil,
				},
				"stop-time": {
					desc:          "Daily window stop time (24-hour HH:MM or HH:MM:SS; exclusive)",
					args:          1,
					placeholder:   "<HH:MM[:SS]>",
					valueType:     ValueTimeOfDay,
					valueDesc:     "Time of day the daily window closes (seconds default to zero)",
					valueExamples: []string{"17:00", "17:00:00", "06:00"},
					validator:     ValidateTimeOfDay,
					children:      nil,
				},
				"start-date": {
					desc:          "Scheduler start date or local date-time (inclusive)",
					args:          1,
					placeholder:   "<YYYY-MM-DD[.HH:MM]>",
					valueType:     ValueDate,
					valueDesc:     "First active date or local date-time",
					valueExamples: []string{"2026-03-01", "2026-03-01.08:30"},
					// Keep the inline range in this leaf's grammar without
					// changing scheduler child paths used by other schema scans.
					validator:     nil,
					tailValidator: validateSchedulerDatePair12637,
					children:      nil,
				},
				"stop-date": {
					desc:          "Scheduler stop date or local date-time (date inclusive; date-time exclusive)",
					args:          1,
					placeholder:   "<YYYY-MM-DD[.HH:MM]>",
					valueType:     ValueDate,
					valueDesc:     "Last active date, or exclusive local date-time bound",
					valueExamples: []string{"2026-03-31", "2026-03-31.17:00"},
					validator:     ValidateDate,
					children:      nil,
				},
				// Junos day containers. `daily` applies to every weekday with
				// no specific override; a weekday container overrides `daily`
				// for that day. All share the same window sub-schema.
				"daily":     schemaSchedulerDay,
				"monday":    schemaSchedulerDay,
				"tuesday":   schemaSchedulerDay,
				"wednesday": schemaSchedulerDay,
				"thursday":  schemaSchedulerDay,
				"friday":    schemaSchedulerDay,
				"saturday":  schemaSchedulerDay,
				"sunday":    schemaSchedulerDay,
			},
		},
	},
}

func validateSchedulerTimePair12637(tokens []string, _ [][]string) error {
	if len(tokens) == 1 {
		return ValidateTimeOfDay(tokens[0], nil)
	}
	if len(tokens) < 2 || tokens[1] != "stop-time" {
		if len(tokens) > 1 {
			return fmt.Errorf("unknown modifier %q", tokens[1])
		}
		return fmt.Errorf("missing value")
	}
	if len(tokens) == 2 {
		return fmt.Errorf("stop-time: missing value")
	}
	if err := ValidateTimeOfDay(tokens[0], nil); err != nil {
		return err
	}
	if err := ValidateTimeOfDay(tokens[2], nil); err != nil {
		return fmt.Errorf("stop-time: %w", err)
	}
	if len(tokens) > 3 {
		return fmt.Errorf("unknown modifier %q", tokens[3])
	}
	return nil
}

func validateSchedulerDatePair12637(tokens []string, _ [][]string) error {
	if len(tokens) == 1 {
		return ValidateDate(tokens[0], nil)
	}
	if len(tokens) < 2 || tokens[1] != "stop-date" {
		if len(tokens) > 1 {
			return fmt.Errorf("unknown modifier %q", tokens[1])
		}
		return fmt.Errorf("missing value")
	}
	if len(tokens) == 2 {
		return fmt.Errorf("stop-date: missing value")
	}
	if err := ValidateDate(tokens[0], nil); err != nil {
		return err
	}
	if err := ValidateDate(tokens[2], nil); err != nil {
		return fmt.Errorf("stop-date: %w", err)
	}
	if len(tokens) > 3 {
		return fmt.Errorf("unknown modifier %q", tokens[3])
	}
	return nil
}

// validateSchedulerPackedWeekday12636 rejects a weekday packed onto the
// named scheduler line. The compiler reads scheduler properties only from
// children, so both a recognized day and a typo in this position were dropped.
func validateSchedulerPackedWeekday12636(node *Node, _ *schemaNode) error {
	if node == nil || len(node.Keys) <= 2 {
		return nil
	}
	return fmt.Errorf("unexpected %q after scheduler name %q: put weekday windows inside the scheduler block", node.Keys[2], node.Keys[1])
}

// validateSchedulerDayPackedTail12239 gates the packed day-leaf tail
// (#12239 F3): hierarchical `daily all-day;` parses to Keys=[daily,
// all-day], and schedulerWindowFromNode reads exactly Keys[1] ==
// all-day|exclude there (compiler_system.go). A misspelled tail never
// becomes a child node, so the closed-world child walk cannot see it;
// without this gate `daily all-dya;` commits clean and the scheduled
// policy silently loses its window. Tokens after Keys[1] are never read
// either (`monday all-day exclude;` compiled as all-day alone), so the
// error names the first token the compiler would drop. A packed
// `<day> start-time X stop-time Y;` never reaches this check: the #8662
// compact normalizer moves it into the day's braces first. Runs only on
// exact schema-key match, so it fires for day containers under
// `scheduler <name>` and nowhere else. Lenient load/boot is untouched:
// SchemaValidate is the strict gate, and Store.Load/SyncApply downgrade
// it to a warning.
func validateSchedulerDayPackedTail12239(node *Node, _ *schemaNode) error {
	if node == nil || len(node.Keys) <= 1 {
		return nil
	}
	day, tail := node.Keys[0], node.Keys[1]
	if tail != "all-day" && tail != "exclude" {
		return fmt.Errorf("unexpected %q after %q: a day window takes all-day, exclude, or start-time/stop-time", tail, day)
	}
	if len(node.Keys) > 2 {
		return fmt.Errorf("unexpected %q after %q %q: a packed day line carries one statement; put the others inside the day's braces", node.Keys[2], day, tail)
	}
	return nil
}
