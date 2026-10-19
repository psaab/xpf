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
	if c.userClass == "" {
		return nil
	}
	var cfg *config.Config
	if c.store != nil {
		cfg = c.store.ActiveConfig()
	}
	// #14987: `show | compare [rollback <N>]` renders a candidate diff
	// (against active, or against rollback slot N). It is not a path
	// render: checkConfigShowRegex used to strip only display pipes, so
	// the compare pipe fell through to the per-path arm and a
	// *-configuration-restricted class was adjudicated on the edit
	// path alone rather than as the whole-tree compare it is.
	// Adjudicate it as AuthorizeConfigShowCompare: refused for a
	// *-configuration-restricted class, operationally the bare
	// `show configuration` command.
	for i, a := range args {
		if a == "|" && i+1 < len(args) && args[i+1] == "compare" {
			return config.AuthorizeConfigShowCompare(cfg, c.userClass)
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
		return config.AuthorizeConfigShowWhole(cfg, c.userClass, displaySuffix14707(suffix))
	}
	return config.AuthorizeConfigShowPath(cfg, c.userClass, full, displaySuffix14707(suffix))
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
	if c.userClass == "" || len(args) < 2 {
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
			if len(args) < 4 {
				return nil // handler usage error; renders nothing
			}
			if n, err := strconv.Atoi(args[3]); err != nil || n < 1 {
				return nil
			}
			return config.AuthorizeConfigShowCompare(cfg, c.userClass)
		}
		n, err := strconv.Atoi(args[2])
		if err != nil || n < 1 {
			return nil // handler usage error
		}
		rest := args[3:]
		_, format, _, piped, pipeErr := splitDisplayPipe(rest)
		if pipeErr != nil {
			return nil // handler prints the syntax error; renders nothing
		}
		if piped && format == displayPipeSet {
			return config.AuthorizeConfigShowRollback(cfg, c.userClass, displaySuffix14707("display set"))
		}
		if piped {
			return nil // handler syntax error; renders nothing
		}
		for _, a := range rest {
			if a == "compare" {
				return config.AuthorizeConfigShowCompare(cfg, c.userClass)
			}
		}
		return config.AuthorizeConfigShowRollback(cfg, c.userClass, "")
	case "login":
		return config.AuthorizeConfigShowSystemPath(cfg, c.userClass,
			[]string{"system", "login"}, "show system login")
	case "internet-options":
		return config.AuthorizeConfigShowSystemPath(cfg, c.userClass,
			[]string{"system", "internet-options"}, "show system internet-options")
	case "root-authentication":
		return config.AuthorizeConfigShowSystemPath(cfg, c.userClass,
			[]string{"system", "root-authentication"}, "show system root-authentication")
	case "configuration":
		if len(args) >= 3 && args[2] == "rescue" {
			return config.AuthorizeConfigShowRescue(cfg, c.userClass)
		}
		return nil
	}
	return nil
}

// checkShowConfigurationRead adjudicates operational
// `show configuration [path…]` against the *-configuration pair only
// (the operational pair was already charged by checkCommandRegex on
// the full canonical line, pipe included). args are the words after
// "configuration"; a `| display …` pipe is format, not path.
func (c *CLI) checkShowConfigurationRead(args []string) error {
	if c.userClass == "" {
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
		return config.AuthorizeConfigShowWhole(cfg, c.userClass, displaySuffix14707(display))
	}
	// Operational arm already charged *-commands; re-checking it here
	// would double-charge with a shorter command string. Evaluate only
	// the configuration pair by passing a class whose operational
	// verdict the caller already took: AuthorizeConfigShowPath checks
	// both, so call the path arm via the config-only helper below.
	return config.AuthorizeConfigPathOnly(cfg, c.userClass, path)
}

// displaySuffix14707 converts "display set" to the format spelling the
// shared gate consumes ("set"); "" stays "".
func displaySuffix14707(display string) string {
	return strings.TrimPrefix(display, "display ")
}
