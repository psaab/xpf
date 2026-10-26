package cli

import (
	"strconv"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

// #14707 (on-box CLI twin): `show` in config mode rendered the candidate
// subtree with neither regex pair consulted — dispatchConfig's
// checkConfigRegex declines non-mutation verbs and the operational gate
// runs only in dispatchOperational. `show configuration …` in
// operational mode already reaches checkCommandRegex with the full
// path+format, so only the config-mode arm and the operational
// whole-tree/configuration-regex interaction needed the shared
// pkg/config read decision (AuthorizeConfigShow*).
//
// checkConfigShowRegex adjudicates a config-mode `show [path…]`
// (parts after "show"). The rendered path is the edit path plus the
// typed remainder, mirroring how the mutation verbs resolve; a bare
// `show` at the top renders the whole candidate. A trailing
// `| display …` pipe is format, not path. Fail closed on an invalid
// regex via the shared decision; an unrestricted class pays nothing.
func (c *CLI) checkConfigShowRegex(args []string) error {
	if c.UserClass() == "" {
		return nil
	}
	var cfg *config.Config
	if c.store != nil {
		cfg = c.store.ActiveConfig()
	}
	// #14987: `show | compare [rollback <N>]` renders a candidate diff
	// (against active, or against rollback slot N). #15272 B24-03: a
	// compare with an explicit/edit path renders only that subtree, so
	// it is adjudicated as a path read; a bare compare is a whole-tree
	// render (AuthorizeConfigShowCompare).
	// #15995: a scoped compare discloses rendered descendants on both
	// arms, so price them against the candidate/active (or rollback
	// slot/candidate) trees the handler will diff.
	for i, a := range args {
		if a == "|" && i+1 < len(args) && args[i+1] == "compare" {
			var comparePath []string
			if c.store != nil {
				comparePath = append(comparePath, c.store.GetEditPath()...)
			}
			comparePath = append(comparePath, args[:i]...)
			var trees []*config.ConfigTree
			priceCfg := cfg
			if c.store != nil {
				rest := args[i+1:]
				if len(rest) == 3 && rest[1] == "rollback" {
					if n, err := strconv.Atoi(rest[2]); err == nil && n >= 0 {
						scfg, slot, other, _, _, slotErr := c.store.RollbackCompareSnapshot(n, false)
						if scfg != nil {
							priceCfg = scfg
						}
						trees = []*config.ConfigTree{slot, other}
						c.setRenderSnapshots16613(slotErr, slot, other)
						if slotErr != nil {
							return slotErr
						}
					}
				} else {
					scfg, active, candidate, _ := c.store.CompareSnapshot()
					if scfg != nil {
						priceCfg = scfg
					}
					trees = []*config.ConfigTree{active, candidate}
					c.setCompareSnapshots15995(active, candidate)
				}
			}
			// Fold 3 PATH-TOCTOU: carry the priced compare path.
			c.renderComparePath15995 = append([]string(nil), comparePath...)
			return config.AuthorizeConfigShowCompareAtPathRendered(priceCfg, c.UserClass(), comparePath, trees...)
		}
		if a != "|" {
			continue
		}
		break
	}
	// Strip a display pipe: `| display set` etc. are format selectors.
	path := args
	suffix := ""
	for i, a := range args {
		if a == "|" {
			if i+2 < len(args) && args[i+1] == "display" {
				suffix = "display " + args[i+2]
			}
			path = args[:i]
			break
		}
		if strings.HasPrefix(a, "|") {
			path = args[:i]
			break
		}
	}
	var editPath []string
	if c.store != nil {
		editPath = c.store.GetEditPath()
	}
	full := append(append([]string(nil), editPath...), path...)
	if len(full) == 0 {
		// Whole candidate render: contained+expanded pricing over
		// the priced candidate snapshot; op verdict carried by the
		// helper (fold B1 — display set etc. must still deny).
		var trees []*config.ConfigTree
		priceCfg := cfg
		if c.store != nil {
			scfg, tree, _, _ := c.store.ShowConfigSnapshot("candidate")
			if scfg != nil {
				priceCfg = scfg
			}
			if tree != nil {
				trees = []*config.ConfigTree{tree}
			}
			c.setCandidateSnapshot15995(tree)
		}
		return config.AuthorizeConfigShowWholeAtTree(priceCfg, c.UserClass(), displaySuffix14707(suffix), trees...)
	}
	// #15995: config-mode show renders the candidate subtree;
	// | display inheritance renders its apply-groups expansion
	// (cli_config.go RenderShowInheritance* on the candidate
	// snapshot), so price the EXPANDED candidate — the operational
	// helper's twin branch (checkShowConfigurationRead).
	// Fold 3: stash under the "candidate" key the handler reads, and
	// carry the priced path (edit cursor folded in) to the handler.
	var trees []*config.ConfigTree
	nodeID := -1
	priceCfg := cfg
	if c.store != nil {
		scfg, tree, nid, _ := c.store.ShowConfigSnapshot("candidate")
		if scfg != nil {
			priceCfg = scfg
		}
		nodeID = nid
		if tree != nil {
			trees = []*config.ConfigTree{tree}
		}
		c.setCandidateSnapshot15995(tree)
	}
	c.renderPath15995 = append([]string(nil), full...)
	if displaySuffix14707(suffix) == "inheritance" {
		return config.AuthorizeExpandedConfigShowPathRendered(priceCfg, c.UserClass(), full, displaySuffix14707(suffix), nodeID, trees...)
	}
	return config.AuthorizeConfigShowPathRendered(priceCfg, c.UserClass(), full, displaySuffix14707(suffix), trees...)
}

// checkShowSystemConfigRead adjudicates operational config renders
// reached through `show system …` (#14987): rollback slots and their
// candidate compares, login / root-authentication subtrees, and the
// rescue text. checkCommandRegex in dispatchOperational already
// charged *-commands on the real spelling (`show system rollback 1`,
// `show system login`, …); what was missing was the *-configuration
// pair and the anchored `^show configuration$` alternate form — both
// lived only on the `show configuration` arm, so a class with
// deny-configuration "^security" (or an anchored show deny) read the
// whole denied tree through the rollback slot. args are the words
// after "show" (parts[1:]); the handler's own token-exact parsing
// decides malformed shapes, and this gate mirrors it: a bare
// `show system rollback` lists timestamps only (no config content)
// and is not gated here; a `| display set` pipe wins over a compare
// token exactly as in handleShowSystem.
func (c *CLI) checkShowSystemConfigRead(args []string) error {
	if c.UserClass() == "" || len(args) < 2 {
		return nil
	}
	var cfg *config.Config
	if c.store != nil {
		cfg = c.store.ActiveConfig()
	}
	switch args[1] {
	case "rollback":
		if len(args) < 3 {
			return nil // timestamp list only
		}
		if args[2] == "compare" {
			if len(args) != 4 {
				return nil // handler usage error; renders nothing
			}
			n, err := strconv.Atoi(args[3])
			if err != nil || n < 0 {
				return nil
			}
			// #15657 V45-03: operational compare diffs against
			// ACTIVE — a whole committed-tree diff, adjudicated
			// like ShowRollback, not the candidate compare.
			// #15995 fold: stash the priced arms for the handler.
			priceCfg := cfg
			if c.store != nil {
				scfg, slot, other, _, _, slotErr := c.store.RollbackCompareSnapshot(n, true)
				if scfg != nil {
					priceCfg = scfg
				}
				c.setRenderSnapshots16613(slotErr, slot, other)
				if slotErr != nil {
					return slotErr
				}
			}
			return c.priceRollbackWholeCompareCaptured15994(priceCfg, cfg)
		}
		n, err := strconv.Atoi(args[2])
		if err != nil || n < 0 {
			return nil // handler usage error
		}
		rest := args[3:]
		rbPath, format, pipe, piped, pipeErr := splitDisplayPipe(rest)
		if pipeErr != nil {
			return nil // handler prints the syntax error; renders nothing
		}
		if piped && format != displayPipeNone {
			// #15657 V48-02: display formats carry an optional
			// pre-pipe subtree path; a path render is priced as a
			// path read, a whole render as a rollback read.
			// #15995: price the slot's rendered descendants;
			// display inheritance prices the expanded slot tree.
			suffix := config.ConfigShowDisplaySuffix(displaySuffix14707("display " + displayFormatName(format)))
			if len(rbPath) > 0 {
				var trees []*config.ConfigTree
				nodeID := -1
				priceCfg := cfg
				if c.store != nil {
					scfg, tree, nid, _, slotErr := c.store.RollbackSnapshot(n)
					if scfg != nil {
						priceCfg = scfg
					}
					nodeID = nid
					if tree != nil {
						trees = []*config.ConfigTree{tree}
					}
					c.setRenderSnapshots16613(slotErr, tree, nil)
					if slotErr != nil {
						return slotErr
					}
				}
				if format == displayPipeInheritance {
					return config.AuthorizeExpandedConfigShowPathRendered(priceCfg, c.UserClass(), rbPath, suffix, nodeID, trees...)
				}
				return config.AuthorizeConfigShowPathRendered(priceCfg, c.UserClass(), rbPath, suffix, trees...)
			}
			priceCfg := cfg
			if c.store != nil {
				scfg, tree, _, _, slotErr := c.store.RollbackSnapshot(n)
				if scfg != nil {
					priceCfg = scfg
				}
				c.setRenderSnapshots16613(slotErr, tree, nil)
				if slotErr != nil {
					return slotErr
				}
			}
			return c.priceRollbackWholeCaptured15994(priceCfg, cfg, suffix)
		}
		if piped {
			if len(pipe) == 1 && pipe[0] == "compare" {
				// #15942 H2-04: `N <path> | compare` diffs only that
				// subtree against active; price the path, not the
				// whole-tree rollback. #15995: price rendered
				// descendants on both arms (slot + active).
				var trees []*config.ConfigTree
				priceCfg := cfg
				if c.store != nil {
					scfg, slot, other, _, _, slotErr := c.store.RollbackCompareSnapshot(n, true)
					if scfg != nil {
						priceCfg = scfg
					}
					trees = []*config.ConfigTree{slot, other}
					c.setRenderSnapshots16613(slotErr, slot, other)
					if slotErr != nil {
						return slotErr
					}
				}
				return config.AuthorizeConfigShowRollbackAtPathRendered(priceCfg, c.UserClass(), rbPath, "", trees...)
			}
			return nil // handler syntax error; renders nothing
		}
		for _, a := range rest {
			if a == "compare" {
				priceCfg := cfg
				if c.store != nil {
					scfg, slot, other, _, _, slotErr := c.store.RollbackCompareSnapshot(n, true)
					if scfg != nil {
						priceCfg = scfg
					}
					c.setRenderSnapshots16613(slotErr, slot, other)
					if slotErr != nil {
						return slotErr
					}
				}
				return c.priceRollbackWholeCompareCaptured15994(priceCfg, cfg)
			}
		}
		// #15942 H2-04: a bare pre-pipe subtree path (`rollback 1
		// interfaces`) renders that subtree — price it as one. Other
		// stray tokens are the handler's syntax error and render
		// nothing, so they need no adjudication here (splitDisplayPipe
		// already separated them as rbPath; the handler validates).
		if len(rbPath) > 0 {
			var trees []*config.ConfigTree
			priceCfg := cfg
			if c.store != nil {
				scfg, tree, _, _, slotErr := c.store.RollbackSnapshot(n)
				if scfg != nil {
					priceCfg = scfg
				}
				if tree != nil {
					trees = []*config.ConfigTree{tree}
				}
				c.setRenderSnapshots16613(slotErr, tree, nil)
				if slotErr != nil {
					return slotErr
				}
			}
			return config.AuthorizeConfigShowPathRendered(priceCfg, c.UserClass(), rbPath, "", trees...)
		}
		priceCfg := cfg
		if c.store != nil {
			scfg, tree, _, _, slotErr := c.store.RollbackSnapshot(n)
			if scfg != nil {
				priceCfg = scfg
			}
			c.setRenderSnapshots16613(slotErr, tree, nil)
			if slotErr != nil {
				return slotErr
			}
		}
		return c.priceRollbackWholeCaptured15994(priceCfg, cfg, "")
	case "login":
		// #15995 fold: `show system login` prints the whole
		// system login subtree — price its rendered descendants
		// in the active tree, not just the `system login` root.
		var trees []*config.ConfigTree
		priceCfg := cfg
		if c.store != nil {
			scfg, tree, _, _ := c.store.ShowConfigSnapshot("active")
			if scfg != nil {
				priceCfg = scfg
			}
			if tree != nil {
				trees = []*config.ConfigTree{tree}
			}
			c.setRenderSnapshots15995(tree, nil)
		}
		return config.AuthorizeConfigShowSystemPathRendered(priceCfg, c.UserClass(),
			[]string{"system", "login"}, "show system login", trees...)
	case "internet-options":
		return config.AuthorizeConfigShowSystemPath(cfg, c.UserClass(),
			[]string{"system", "internet-options"}, "show system internet-options")
	case "root-authentication":
		// #15995 fold: same whole-subtree render at
		// system root-authentication.
		var trees []*config.ConfigTree
		priceCfg := cfg
		if c.store != nil {
			scfg, tree, _, _ := c.store.ShowConfigSnapshot("active")
			if scfg != nil {
				priceCfg = scfg
			}
			if tree != nil {
				trees = []*config.ConfigTree{tree}
			}
			c.setRenderSnapshots15995(tree, nil)
		}
		return config.AuthorizeConfigShowSystemPathRendered(priceCfg, c.UserClass(),
			[]string{"system", "root-authentication"}, "show system root-authentication", trees...)
	case "configuration":
		if len(args) >= 3 && args[2] == "rescue" {
			return config.AuthorizeConfigShowRescue(cfg, c.UserClass())
		}
		return nil
	}
	return nil
}

// displayFormatName maps a displayPipeFormat to its spelling.
func displayFormatName(f displayPipeFormat) string {
	switch f {
	case displayPipeSet:
		return "set"
	case displayPipeJSON:
		return "json"
	case displayPipeXML:
		return "xml"
	case displayPipeInheritance:
		return "inheritance"
	}
	return ""
}

// checkShowConfigurationRead adjudicates operational
// `show configuration [path…]` against the *-configuration pair only
// (the operational pair was already charged by checkCommandRegex on
// the full canonical line, pipe included). args are the words after
// "configuration"; a `| display …` pipe is format, not path.
func (c *CLI) checkShowConfigurationRead(args []string) error {
	if c.UserClass() == "" {
		return nil
	}
	var cfg *config.Config
	if c.store != nil {
		cfg = c.store.ActiveConfig()
	}
	path := args
	display := ""
	for i, a := range args {
		if a == "|" {
			if i+2 < len(args) && args[i+1] == "display" {
				display = "display " + args[i+2]
			}
			path = args[:i]
			break
		}
	}
	if len(path) == 0 {
		var trees []*config.ConfigTree
		priceCfg := cfg
		if c.store != nil {
			scfg, tree, _, _ := c.store.ShowConfigSnapshot("active")
			if scfg != nil {
				priceCfg = scfg
			}
			if tree != nil {
				trees = []*config.ConfigTree{tree}
			}
			c.setRenderSnapshots15995(tree, nil)
		}
		return config.AuthorizeConfigShowWholeAtTree(priceCfg, c.UserClass(), displaySuffix14707(display), trees...)
	}
	// Operational arm already charged *-commands on the LITERAL line
	// (checkCommandRegex); the effective (group-unwrapped) command
	// was never charged — charge it here (#15994 fold 1), on every
	// effective spelling, without weakening the literal verdict.
	// #15995: price rendered descendants of the active tree too;
	// | display inheritance prices the expanded active tree.
	var trees []*config.ConfigTree
	nodeID := -1
	priceCfg := cfg
	if c.store != nil {
		scfg, tree, nid, _ := c.store.ShowConfigSnapshot("active")
		if scfg != nil {
			priceCfg = scfg
		}
		nodeID = nid
		if tree != nil {
			trees = []*config.ConfigTree{tree}
		}
		c.setRenderSnapshots15995(tree, nil)
	}
	if displaySuffix14707(display) == "inheritance" {
		return config.AuthorizeExpandedConfigPathOnlyRenderedWithOp15994(priceCfg, c.UserClass(), path, displaySuffix14707(display), nodeID, trees...)
	}
	return config.AuthorizeConfigPathOnlyRenderedWithOp15994(priceCfg, c.UserClass(), path, displaySuffix14707(display), trees...)
}

// displaySuffix14707 converts "display set" to the format spelling the
// shared gate consumes ("set"); "" stays "".
func displaySuffix14707(display string) string {
	return strings.TrimPrefix(display, "display ")
}

// setRenderSnapshots15995 records the priced snapshots for the handler
// of the in-flight dispatch: slotOrActive is the primary rendered tree
// (active for show configuration / show system, the rollback slot for
// rollback renders), other is the second compare arm when present.
// Fold 3: the map is created even when both trees are nil — map
// presence is the "snapshot captured" bit, and a nil entry is a priced
// absence the handler renders instead of re-resolving the live store.
func (c *CLI) setRenderSnapshots15995(slotOrActive, other *config.ConfigTree) {
	if c.renderSnapshots15995 == nil {
		c.renderSnapshots15995 = map[string]*config.ConfigTree{}
	}
	c.renderSnapshots15995["active"] = slotOrActive
	c.renderSnapshots15995["slot"] = slotOrActive
	c.renderSnapshots15995["other"] = other
}

// setCompareSnapshots15995 records both candidate-compare arms (same
// presence contract as setRenderSnapshots15995).
func (c *CLI) setCompareSnapshots15995(active, candidate *config.ConfigTree) {
	if c.renderSnapshots15995 == nil {
		c.renderSnapshots15995 = map[string]*config.ConfigTree{}
	}
	c.renderSnapshots15995["active"] = active
	c.renderSnapshots15995["candidate"] = candidate
}

// setCandidateSnapshot15995 records the priced candidate tree for a
// config-mode show dispatch, under the "candidate" key the handler
// actually reads (fold 3: previously stashed as "other", so the
// handler missed it and rendered the LIVE candidate).
func (c *CLI) setCandidateSnapshot15995(candidate *config.ConfigTree) {
	if c.renderSnapshots15995 == nil {
		c.renderSnapshots15995 = map[string]*config.ConfigTree{}
	}
	c.renderSnapshots15995["candidate"] = candidate
}

// setRenderSnapshots16613 records the priced snapshots together with
// the rollback slot error (#16613): gates price a nil snapshot as
// "renders nothing", so a missing slot must still surface as an error
// at the handler (the snapshot_render_15995.go contract). A nil
// slotErr leaves renderSlotErr16613 unset.
func (c *CLI) setRenderSnapshots16613(slotErr error, slotOrActive, other *config.ConfigTree) {
	c.setRenderSnapshots15995(slotOrActive, other)
	// Assign unconditionally: a later capture in the same dispatch
	// frame (or a direct gate call) must clear a previous slot error.
	c.renderSlotErr16613 = slotErr
}

// renderSlotErr returns the rollback slot error stashed with the
// priced snapshots for this dispatch, or nil when the slot resolved.
func (c *CLI) renderSlotErr() error {
	return c.renderSlotErr16613
}

// snapshotsCaptured15995 reports whether the gate captured snapshots
// for this dispatch (renderSnapshots15995 non-nil), distinguishing a
// priced absence (nil tree) from no gate at all.
func (c *CLI) snapshotsCaptured15995() bool {
	return c.renderSnapshots15995 != nil
}

// renderSnapshot15995 returns the priced snapshot for key, or nil when
// this dispatch was not gated with snapshots (ungated/superuser path —
// handlers then use the store renderers as before) or when the priced
// tree was absent.
func (c *CLI) renderSnapshot15995(key string) *config.ConfigTree {
	if c.renderSnapshots15995 == nil {
		return nil
	}
	return c.renderSnapshots15995[key]
}

// priceRollbackWholeCompareCaptured15994 prices an unscoped
// operational rollback-vs-active compare against the arms ALREADY
// captured+stashed by the caller's RollbackCompareSnapshot(n, true)
// (#15994 fold2-3: price and stash must be the SAME capture — the
// helper never takes a second one).
func (c *CLI) priceRollbackWholeCompareCaptured15994(priceCfg, cfg *config.Config) error {
	if priceCfg == nil {
		priceCfg = cfg
	}
	if c.store == nil {
		return config.AuthorizeConfigShowRollback(priceCfg, c.UserClass(), "")
	}
	return config.AuthorizeConfigShowCompareAtTree(priceCfg, c.UserClass(),
		c.renderSnapshot15995("slot"), c.renderSnapshot15995("other"))
}

// priceRollbackWholeCaptured15994 prices an unscoped operational
// rollback render against the slot tree ALREADY captured+stashed
// by the caller's RollbackSnapshot(n) (fold2-3).
func (c *CLI) priceRollbackWholeCaptured15994(priceCfg, cfg *config.Config, suffix string) error {
	if priceCfg == nil {
		priceCfg = cfg
	}
	if c.store == nil {
		return config.AuthorizeConfigShowRollback(priceCfg, c.UserClass(), suffix)
	}
	return config.AuthorizeConfigShowRollbackAtTree(priceCfg, c.UserClass(),
		c.renderSnapshot15995("slot"), suffix)
}
