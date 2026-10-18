package config

import (
	"fmt"
	"strings"
)

// #14707: configuration READS were never adjudicated against the
// *-configuration regexes or the path/format-scoped *-commands regexes.
//
// ShowConfig / ShowCompare / ShowRollback (and their REST twins) rendered
// the full secret-redacted tree for any class the coarse permission bits
// admitted. deny-configuration "^security" denied `set security …` on
// every surface yet concealed nothing on read, and deny-commands
// "^show configuration security" or "display set" never fired because
// the gRPC gate flattened the RPC to the bare "show configuration".
// #14144 fixed Complete by reference to what "ShowConfig/Set conceal" —
// ShowConfig did not, in fact, conceal it. This file is the shared read
// decision so gRPC and REST cannot drift on it.
//
// Semantics, deliberately mirroring the surfaces operators already know:
//
//   - An explicit subtree path is adjudicated exactly as the CLI
//     adjudicates `show configuration <path>`: the configuration regexes
//     on the joined path (the same string checkConfigRegex /
//     AuthorizeConfigMutation evaluate, minus the verb) AND the
//     operational regexes on "show configuration <path>" with the bare
//     "show configuration" as an alternate form (EvaluateForms), so an
//     anchored `^show configuration$` still covers sub-paths and a
//     path-scoped `^show configuration security` fires.
//   - A whole-tree render, a candidate diff, and a rollback render have
//     no single path: like AuthorizeConfigLoad's override arm and
//     AuthorizeConfigRollback, they are REFUSED for a class with
//     configuration regexes, because the subtrees they would disclose
//     cannot be enumerated from the request. For the operational pair
//     the whole render is the bare `show configuration` command; a
//     path-scoped deny does not refuse it, a bare deny does.
//   - A class with no regexes in a family is untouched by that family.
//     An invalid regex denies (fail closed, as every sibling gate).
//   - Format is part of the operational command: `| display set` (and
//     json/xml/inheritance) reformats what a deny may withhold, exactly
//     as the CLI counts the pipe as part of the command (#7172). The
//     hierarchical form carries no suffix.

// AuthorizeConfigShowPath adjudicates an explicit `show configuration
// <path>` subtree read. path is the resolved config path the handler
// will render (nil/empty is NOT this function — see
// AuthorizeConfigShowWhole). displaySuffix is "display set" /
// "display json" / "display xml" / "display inheritance", or "" for the
// hierarchical form.
func AuthorizeConfigShowPath(cfg *Config, class string, path []string, displaySuffix string) error {
	if class == "" {
		return nil
	}
	joined := strings.Join(path, " ")
	if err := authorizeConfigReadPath(cfg, class, joined); err != nil {
		return err
	}
	return authorizeShowCommand(cfg, class, "show configuration "+joined, displaySuffix)
}

// AuthorizeConfigShowWhole adjudicates a whole-tree configuration read
// (ShowConfig with no path, in any target/format). A class with
// configuration regexes is refused: the render includes subtrees the
// request cannot enumerate. The operational pair is evaluated against
// the bare command (plus format suffix).
func AuthorizeConfigShowWhole(cfg *Config, class string, displaySuffix string) error {
	if class == "" {
		return nil
	}
	if err := authorizeConfigWhole(cfg, class, "show configuration"); err != nil {
		return err
	}
	return authorizeShowCommand(cfg, class, "show configuration", displaySuffix)
}

// AuthorizeConfigShowCompare adjudicates a candidate diff render
// (ShowCompare, both arms). The diff discloses candidate content under
// arbitrary paths, so a configuration-restricted class is refused, as
// with load override. Operationally it is the bare `show configuration`.
func AuthorizeConfigShowCompare(cfg *Config, class string) error {
	if class == "" {
		return nil
	}
	if err := authorizeConfigWhole(cfg, class, "show configuration"); err != nil {
		return err
	}
	return authorizeShowCommand(cfg, class, "show configuration", "")
}

// AuthorizeConfigShowRollback adjudicates a rollback-slot render
// (ShowRollback). Same whole-tree shape as AuthorizeConfigShowWhole.
func AuthorizeConfigShowRollback(cfg *Config, class string, displaySuffix string) error {
	if class == "" {
		return nil
	}
	if err := authorizeConfigWhole(cfg, class, "show system rollback"); err != nil {
		return err
	}
	return authorizeShowCommand(cfg, class, "show configuration", displaySuffix)
}

func authorizeConfigReadPath(cfg *Config, class, joined string) error {
	rules, ok, err := ConfigurationLoginRegexesFor(cfg, class)
	if err != nil {
		return fmt.Errorf("permission denied: login class %q has an invalid configuration regex: %w", class, err)
	}
	if !ok {
		return nil
	}
	if decision := rules.Evaluate(joined); !decision.Allowed {
		return fmt.Errorf("permission denied: login class %q denies configuration under %q (%s)",
			class, configAuditRoot(joined), decision.Reason)
	}
	return nil
}

func authorizeConfigWhole(cfg *Config, class, what string) error {
	_, restricted, err := ConfigurationLoginRegexesFor(cfg, class)
	if err != nil {
		return fmt.Errorf("permission denied: login class %q has an invalid configuration regex: %w", class, err)
	}
	if !restricted {
		return nil
	}
	return fmt.Errorf("permission denied: login class %q restricts configuration paths, and "+
		"%s renders the whole configuration, so the subtrees it discloses cannot be "+
		"adjudicated one by one; request an allowed subtree instead (#14707)", class, what)
}

// AuthorizeConfigPathOnly adjudicates one config path against the
// *-configuration pair alone. For surfaces that already charged the
// operational pair on the full command line (the on-box CLI's
// checkCommandRegex) and must not double-charge it against a shorter
// string.
func AuthorizeConfigPathOnly(cfg *Config, class string, path []string) error {
	if class == "" {
		return nil
	}
	return authorizeConfigReadPath(cfg, class, strings.Join(path, " "))
}

// authorizeShowCommand evaluates the operational pair against the
// canonical show command. The bare "show configuration" is measured as
// an alternate form so an anchored deny on it covers sub-paths
// (EvaluateForms max-per-side, #9022 shape), and the display suffix is
// part of the matched string so "display set" fires.
func authorizeShowCommand(cfg *Config, class, command, displaySuffix string) error {
	rules, ok, err := OperationalLoginRegexesFor(cfg, class)
	if err != nil {
		return fmt.Errorf("permission denied: login class %q has an invalid command regex: %w", class, err)
	}
	if !ok {
		return nil
	}
	full := command
	if displaySuffix != "" {
		full = command + " | " + displaySuffix
	}
	if decision := rules.EvaluateForms(full, "show configuration"); !decision.Allowed {
		return fmt.Errorf("permission denied: login class %q denies %q (%s)", class, command, decision.Reason)
	}
	return nil
}

// ConfigShowDisplaySuffix renders a display-format selector as the CLI
// pipe suffix operators write ("display set", …). format is the
// caller-surface spelling: "set", "json", "xml", "inheritance", or ""
// (hierarchical). Unknown spellings yield "" — the caller's own format
// validation rejects them; authorization must not invent a form.
func ConfigShowDisplaySuffix(format string) string {
	switch format {
	case "set", "json", "xml", "inheritance":
		return "display " + format
	}
	return ""
}
