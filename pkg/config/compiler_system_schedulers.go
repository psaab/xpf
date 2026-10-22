package config

// compiler_system_schedulers.go holds the `schedulers` compiler
// evicted from compiler_system.go (#16146): pure in-package code
// motion, unchanged call graph.

var schedulerWeekdays = map[string]struct{}{
	"monday": {}, "tuesday": {}, "wednesday": {}, "thursday": {},
	"friday": {}, "saturday": {}, "sunday": {},
}

func compileSchedulers(node *Node, cfg *Config) error {
	if cfg.Schedulers == nil {
		cfg.Schedulers = make(map[string]*SchedulerConfig)
	}

	for _, inst := range namedInstances(node.FindChildren("scheduler")) {
		// #5825: REUSE the existing map entry instead of allocating a fresh
		// SchedulerConfig per named AST instance. compileSchedulers runs once PER
		// top-level `schedulers` root (compiler_dispatch.go) and once per named
		// instance within a root; the pre-fix code built a fresh sched each time
		// then unconditionally `cfg.Schedulers[name] = sched`, so a later same-name
		// block/root REPLACED the first — every day/window authored earlier
		// vanished. A policy time-gated by the scheduler then became active/inactive
		// on the WRONG days with a clean commit. Flat `set` composes into ONE path,
		// so hierarchical diverged from flat. Reusing the persisted entry composes
		// every fragment: the weekday Days map (below) UNIONS distinct days across
		// blocks/roots (no window lost), and the daily/date scalars follow
		// flat-set / Junos load-merge last-wins (a repeated leaf replaces — no
		// "conflict" arises in flat-set, so hierarchical must match). Mirrors the
		// #5824 policy-statement block-merge.
		sched := cfg.Schedulers[inst.name]
		if sched == nil {
			sched = &SchedulerConfig{Name: inst.name}
			cfg.Schedulers[inst.name] = sched
		}

		// #9235: `scheduler s1 start-date D start-time T stop-date E` is ONE
		// command nested into a chain, so this loop read `start-date` and left
		// the window empty -- and an empty window makes isWithinWindow fall OPEN
		// (always-active), so a scheduled policy that should have been inactive
		// enforced around the clock. Lenient path only.
		for _, prop := range expandRunChildren9235(inst.node.Children, schedulerSchema9235()) {
			name := prop.Name()
			switch {
			case name == "start-time":
				// Legacy simplified shape: start-time/stop-time as direct
				// children of the scheduler. Junos also packs that canonical
				// pair onto the start-time statement itself.
				sched.StartTime = nodeVal(prop)
				if stop, ok := schedulerInlineModifierValue12637(prop, "stop-time"); ok {
					sched.StopTime = stop
				}
			case name == "stop-time":
				sched.StopTime = nodeVal(prop)
			case name == "start-date":
				sched.StartDate = nodeVal(prop)
				if stop, ok := schedulerInlineModifierValue12637(prop, "stop-date"); ok {
					sched.StopDate = stop
				}
			case name == "stop-date":
				sched.StopDate = nodeVal(prop)
			case name == "daily":
				sched.Daily = true
				// Junos hierarchical shape:
				//   daily { start-time X; stop-time Y; }
				//   daily all-day;  /  daily { exclude; }
				// A bare `daily;` leaf carries no window and only flips the
				// recurrence flag. Descend to read the daily window (#3849 —
				// previously this branch ignored the block, leaving the
				// window empty so isWithinWindow fell open to always-active).
				if win, ok := schedulerWindowFromNode(prop); ok {
					if win.StartTime != "" {
						sched.StartTime = win.StartTime
					}
					if win.StopTime != "" {
						sched.StopTime = win.StopTime
					}
					sched.AllDay = sched.AllDay || win.AllDay
					// #14396: OR, not assign — a duplicate `daily` stanza
					// (second stanza in one block, duplicate scheduler
					// instance, or group-expanded fragment) carrying only
					// a window must not clear an exclude an earlier stanza
					// declared, or a never-active scheduler goes active.
					// Mirrors the weekday arm's `w.Exclude || win.Exclude`.
					sched.DailyExclude = sched.DailyExclude || win.Exclude
				}
			default:
				if _, ok := schedulerWeekdays[name]; ok {
					if win, ok := schedulerWindowFromNode(prop); ok {
						if sched.Days == nil {
							sched.Days = make(map[string]*SchedulerDayWindow)
						}
						w := SchedulerDayWindow{}
						if previous := sched.Days[name]; previous != nil {
							w = *previous
						}
						if win.StartTime != "" {
							w.StartTime = win.StartTime
						}
						if win.StopTime != "" {
							w.StopTime = win.StopTime
						}
						w.AllDay = w.AllDay || win.AllDay
						w.Exclude = w.Exclude || win.Exclude
						sched.Days[name] = &w
					}
				}
			}
		}
		// #5825: NO unconditional overwrite here — sched IS the shared map entry,
		// so this instance's fragments are already composed into any earlier
		// same-name block/root's days and scalars.
	}
	return nil
}

// schedulerInlineModifierValue12637 reads the Junos one-line scheduler
// boundary that may follow a typed start-time/start-date leaf. It accepts
// both parser representations: a packed Keys tail and a child modifier node.
func schedulerInlineModifierValue12637(n *Node, keyword string) (string, bool) {
	if n == nil {
		return "", false
	}
	for i := 2; i+1 < len(n.Keys); i++ {
		if n.Keys[i] == keyword {
			return n.Keys[i+1], true
		}
	}
	for _, child := range n.Children {
		if child != nil && child.Name() == keyword {
			return nodeVal(child), true
		}
	}
	return "", false
}

// schedulerWindowFromNode extracts a time window from a `daily` or weekday
// container node inside a scheduler. It handles both AST shapes and returns
// ok=false when the node is a bare flag with no recognized window statement
// (e.g. a plain `daily;`), so the caller can leave the window unset.
func schedulerWindowFromNode(n *Node) (SchedulerDayWindow, bool) {
	var win SchedulerDayWindow
	found := false

	// #8939: a flat `set` command naming several window leaves is ONE command,
	// and SetPath nests them instead of making them siblings:
	//
	//	set schedulers scheduler s1 monday all-day exclude start-time 08:00:00
	//	  [monday]
	//	    [all-day]
	//	      [exclude start-time 08:00:00]     <- ONE node, a FLAT RUN
	//
	// The Children loop below sees `all-day` and nothing else, so `exclude` and
	// the window were silently dropped. Flattening here rather than at the two
	// call sites covers `daily` AND all seven weekdays in one place, because
	// this is the single extractor they share -- measured before relying on it.
	children := expandFlatRun(n.Children, schedulerDayLeafSchema8939())

	// Flat leaf shape where the keyword rides on the node's own Keys, e.g.
	// hierarchical `daily all-day;` parses to Keys=["daily","all-day"].
	if len(n.Keys) >= 2 {
		switch n.Keys[1] {
		case "all-day":
			win.AllDay = true
			found = true
		case "exclude":
			win.Exclude = true
			found = true
		}
	}

	for _, c := range children {
		switch c.Name() {
		case "start-time":
			win.StartTime = nodeVal(c)
			found = true
		case "stop-time":
			win.StopTime = nodeVal(c)
			found = true
		case "all-day":
			win.AllDay = true
			found = true
		case "exclude":
			win.Exclude = true
			found = true
		}
	}
	return win, found
}

// schedulerDayLeafSchema8939 resolves the leaf set a scheduler day window
// declares. `daily` and every weekday share it, which is why one lookup serves
// both call sites of schedulerWindowFromNode.
func schedulerDayLeafSchema8939() *schemaNode {
	sch := resolveSchemaChild(setSchema, "schedulers")
	inst := resolveSchemaChild(sch, "scheduler")
	if inst == nil {
		return nil
	}
	if inst.wildcard != nil {
		inst = inst.wildcard
	}
	return resolveSchemaChild(inst, "daily")
}
