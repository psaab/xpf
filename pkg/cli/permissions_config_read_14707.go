package cli

import (
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
	// A display suffix typed as separate fields after the pipe was
	// stripped above; re-derive the shared suffix spelling.
	display := ""
	if suffix != "" {
		display = suffix
	}
	if len(full) == 0 {
		return config.AuthorizeConfigShowWhole(cfg, c.userClass, displaySuffix14707(display))
	}
	return config.AuthorizeConfigShowPath(cfg, c.userClass, full, displaySuffix14707(display))
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
